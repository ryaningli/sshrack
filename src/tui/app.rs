//! TUI application state, key handling, and event loop.
//!
//! The loop is the only place with side effects. [`App::on_key`] is pure (no
//! I/O): it inspects a [`KeyEvent`] and returns an [`Outcome`] describing what
//! the loop should do next. This keeps key logic unit-testable without a
//! terminal or event source.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent};
use ratatui::Frame;
use sshrack_core::config::schema::SshrackConfig;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency::Frecency;
use std::path::PathBuf;
use ulid::Ulid;

use super::ConnectRequest;
use super::CredentialNames;
use super::connect::connect_host;
use super::cred_panel::CredPanel;
use super::dialog::draw_dialog;
use super::help::draw_help_dialog;
use super::intent::{Outcome, Overlay, Status};
use super::launcher::Launcher;
use super::persist::{
    StoreSwitchTarget, fulfill_save_cred, persist_cred_delete, persist_host_delete,
    persist_host_save, persist_store_switch,
};
use super::prompt::TuiPassphrase;
use super::settings::SettingsPanel;
use super::shell::draw_shell;
use super::store::StoreView;
use super::tab::{Tab, TabKey, tab_key_decision};
use super::term::{TerminalHandle, Tui};
use super::wizard::{CredForm, HostForm};
use sshrack_core::secret::PassphraseProvider;

/// TUI application state. The shell (brand + tab bar + footer) is always on
/// screen; [`App::active_tab`] selects which panel fills the middle band, and
/// [`App::overlay`] layers a dialog (help / host wizard / cred wizard / store
/// picker / delete confirm) on top when set.
///
/// `App` owns the data (config, frecency, credential-name lookup) loaded once
/// at startup from core, and the on-disk config path so the wizard save path
/// can persist + reload without re-resolving. The [`Launcher`] / [`HostForm`] /
/// [`CredForm`] inside it own their respective view states. The config is kept
/// here (not just its derived slices) because connect orchestration needs the
/// credential table and vault meta, which live on the full [`SshrackConfig`].
pub struct App {
    /// Set by [`App::on_key`] when the user presses a quit binding. The loop
    /// checks this as a secondary exit (the primary exit is [`Outcome::Quit`]).
    pub should_quit: bool,
    /// The full config, loaded from core. Owned here so connect orchestration
    /// can resolve auth, unlock the vault, and look up hosts by id. The host
    /// list and credential table are borrowed out of this via `&self.config`.
    pub(super) config: SshrackConfig,
    /// The on-disk path the config was loaded from. `None` when no path was
    /// resolved (e.g. a fresh install with no home dir); the wizard save path
    /// treats that as best-effort (build the new config but skip the persist).
    pub(super) config_path: Option<PathBuf>,
    /// Machine-local frecency table, loaded from core's data dir.
    frecency: Frecency,
    /// Reverse lookup from a credential ULID to its display name, so the
    /// launcher can show `Auth::Ref` targets by name without re-scanning.
    credential_names: CredentialNames,
    /// The active shell tab. Drives which panel fills the middle band and
    /// which footer hints show. Switched by Tab / Shift-Tab / Ctrl-1/2/3.
    active_tab: Tab,
    /// The overlay layered on top of the shell, if any. At most one at a time.
    /// The wizard forms live inside their variants so their state survives
    /// across keystrokes without separate `Option<…>` fields.
    pub(super) overlay: Option<Overlay>,
    /// The interactive launcher (the Hosts panel: query + selection + ranked
    /// list). Public so the existing tests can drive its state machine directly
    /// and the loop can read `pending_connect`.
    pub launcher: Launcher,
    /// The credential panel (the Credentials tab: query + selection + ranked
    /// list). Public so the loop can read `pending_delete_cred`.
    cred_panel: CredPanel,
    /// The settings panel (the Settings tab: one row for the storage mode).
    /// Owns its cursor + the OpenStorePicker intent on Enter.
    settings_panel: SettingsPanel,
    /// The store-mode switch view, used by the Settings tab. Present only while
    /// a [`Overlay::StorePicker`] flow or its Task 8 successor is active; kept
    /// on `App` so its state survives across the loop's popup-driven switch.
    pub(super) store_view: Option<StoreView>,
    /// The consolidated status-bar message. Every action sets it; the footer
    /// rendered in [`App::draw`] shows it. Errors tint red. This is the user's
    /// single feedback channel across all views.
    status: Status,
    /// The pending-connect host id set by Enter on the launcher. The loop reads
    /// (and clears) this to run connect orchestration. Mirrors `pending_delete`.
    pending_connect: Option<Ulid>,
    /// Set by `on_key` when the user presses `^d` on a host. The event loop
    /// reads this (clearing it on cancel), drives the confirm popup, and runs
    /// the I/O-heavy delete. `on_key` does NO I/O, so this is the pure bridge
    /// to the loop.
    pub(super) pending_delete: Option<Ulid>,
    /// Set by `on_key` when the user presses `^d` on a credential. The loop
    /// reads (clearing it on cancel), drives the confirm popup, and runs the
    /// I/O-heavy delete via `credential::delete_credential_with_secret`. The
    /// credential's name is captured here (not its id) because the core delete
    /// fn is name-keyed and the panel's cursor already resolved to a name.
    pub(super) pending_delete_cred: Option<String>,
}

impl App {
    /// Construct a fresh app from loaded core data. Builds the launcher with
    /// its initial frecency-ordered ranking. `config_path` is the on-disk path
    /// the config was loaded from, used by the wizard save path to persist +
    /// reload.
    pub fn new(
        config: SshrackConfig,
        config_path: Option<PathBuf>,
        frecency: Frecency,
        credential_names: CredentialNames,
    ) -> Self {
        let launcher = Launcher::new(&config.hosts, &frecency);
        let mut cred_panel = CredPanel::new();
        cred_panel.recompute(&config.credentials);
        Self {
            should_quit: false,
            config,
            config_path,
            frecency,
            credential_names,
            active_tab: Tab::Hosts,
            overlay: None,
            launcher,
            cred_panel,
            settings_panel: SettingsPanel::new(),
            store_view: None,
            status: Status::empty(),
            pending_connect: None,
            pending_delete: None,
            pending_delete_cred: None,
        }
    }

    /// Borrow the loaded config. Used by connect orchestration to resolve auth
    /// and unlock the vault.
    pub fn config(&self) -> &SshrackConfig {
        &self.config
    }

    /// Borrow the on-disk config path. Used by the wizard save path to persist.
    pub fn config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }

    /// Borrow the frecency table mutably. Connect orchestration records + saves
    /// it before returning a [`ConnectRequest`].
    pub fn frecency_mut(&mut self) -> &mut Frecency {
        &mut self.frecency
    }

    /// The active shell tab. Test accessor for assertions on tab routing; the
    /// production loop reads `self.active_tab` directly.
    #[cfg(test)]
    pub fn active_tab(&self) -> Tab {
        self.active_tab
    }

    /// The current overlay, if any. Test accessor for assertions on overlay
    /// routing (`matches!(app.overlay(), Some(Overlay::HostWizard(_)))`); the
    /// production loop reads the overlay field directly.
    #[cfg(test)]
    pub fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }

    /// Borrow the active host wizard, if a [`Overlay::HostWizard`] is open. Test
    /// accessor: the production loop reads the overlay field directly.
    #[cfg(test)]
    pub fn wizard(&self) -> Option<&HostForm> {
        match &self.overlay {
            Some(Overlay::HostWizard(f)) => Some(f),
            _ => None,
        }
    }

    /// Borrow the active cred wizard, if a [`Overlay::CredWizard`] is open. Test
    /// accessor: the production loop reads the overlay field directly.
    #[cfg(test)]
    pub fn cred_wizard(&self) -> Option<&CredForm> {
        match &self.overlay {
            Some(Overlay::CredWizard(f)) => Some(f),
            _ => None,
        }
    }

    /// Open the host wizard overlay in add mode with a blank form. Discards any
    /// overlay already open (there should be none when the launcher is showing).
    /// The form lives inside the [`Overlay::HostWizard`] variant.
    pub fn open_host_wizard_add(&mut self) {
        let names: Vec<String> = self
            .config
            .credentials
            .iter()
            .map(|c| c.name.clone())
            .collect();
        self.overlay = Some(Overlay::HostWizard(HostForm::new_add(names)));
    }

    /// Open the host wizard overlay in edit mode, prefilled from the host with
    /// the given id. No-op (returns false) when the id is not in the config.
    /// When the host's auth is a credential reference, the referenced
    /// credential's current name is resolved from the config so the chooser can
    /// prefill the correct index (the wizard works in names; it cannot map
    /// id→name alone).
    pub fn open_host_wizard_edit(&mut self, host_id: Ulid) -> bool {
        let Some(host) = self.config.find_host_by_id(&host_id).cloned() else {
            return false;
        };
        let names: Vec<String> = self
            .config
            .credentials
            .iter()
            .map(|c| c.name.clone())
            .collect();
        // Resolve the referenced credential id → its current name (if any) so
        // new_edit can prefill the chooser at the right index. None covers both
        // non-Ref auth and a dangling ref (credential deleted between sessions).
        let referenced_credential_name = host.auth.credential_id().and_then(|id| {
            self.config
                .find_credential_by_id(&id)
                .map(|c| c.name.clone())
        });
        self.overlay = Some(Overlay::HostWizard(HostForm::new_edit(
            &host,
            names,
            referenced_credential_name.as_deref(),
        )));
        true
    }

    /// Leave the host wizard overlay and return to the launcher, reloading the
    /// host ranking so a freshly added/edited host shows up. Used by the loop
    /// after a save or a cancel.
    pub fn close_host_wizard(&mut self) {
        self.overlay = None;
        // Re-rank so the launcher reflects the (possibly) updated host list.
        self.recompute_panels();
    }

    /// Re-rank both panels (Hosts by frecency, Credentials alphabetically) from
    /// the current config. Called after every config reload / cancel so the
    /// visible tab reflects any change. Centralized so a new panel never gets
    /// forgotten on a reload path.
    pub(super) fn recompute_panels(&mut self) {
        self.launcher.recompute(&self.config.hosts, &self.frecency);
        self.cred_panel.recompute(&self.config.credentials);
    }

    /// Open the credential wizard overlay in add mode with a blank form.
    /// Discards any overlay already open.
    pub fn open_cred_wizard_add(&mut self) {
        self.overlay = Some(Overlay::CredWizard(CredForm::new_add()));
    }

    /// Open the credential wizard overlay in edit mode, prefilled from the
    /// credential with the given name. No-op (returns false) when the name is
    /// not in the config.
    pub fn open_cred_wizard_edit(&mut self, name: &str) -> bool {
        let Some(cred) = self.config.find_credential_by_name(name).cloned() else {
            return false;
        };
        self.overlay = Some(Overlay::CredWizard(CredForm::new_edit(&cred)));
        true
    }

    /// Leave the cred wizard overlay and return to the launcher. Used by the
    /// loop after a save or a cancel. Re-ranks both panels: the host ranking
    /// reflects any inline-user change, and the credential panel reflects the
    /// added/edited credential.
    pub fn close_cred_wizard(&mut self) {
        self.overlay = None;
        self.recompute_panels();
    }

    /// Close whatever overlay is open. The loop calls this after a save, a
    /// cancel, or a switch intent resolved. Re-ranks both panels so any tab
    /// reflects a config change.
    pub fn close_overlay(&mut self) {
        self.overlay = None;
        self.recompute_panels();
    }

    /// Open the host wizard overlay in edit mode, prefilled from the host named
    /// `name`. No-op (returns false) when the name is not in the config. Used by
    /// the entry-routing path (`host edit <name>` → TUI) where the host is
    /// identified by name, not by the launcher cursor.
    pub fn open_host_wizard_edit_by_name(&mut self, name: &str) -> bool {
        let Some(host) = self.config.find_host_by_name(name).cloned() else {
            return false;
        };
        // open_host_wizard_edit takes an id; resolve the name → id here.
        self.open_host_wizard_edit(host.id)
    }

    /// The human-readable label for the currently active storage mode, or
    /// `"undecided"` when `cfg.store` is `None`. Used by the settings panel and
    /// the store view to mark the `(active)` row.
    fn current_store_mode_label(&self) -> &'static str {
        use sshrack_core::config::schema::SecretStore;
        match &self.config.store {
            Some(SecretStore::Keyring) => "keyring",
            Some(SecretStore::Vault { .. }) => "vault",
            Some(SecretStore::Plaintext) => "plaintext",
            None => "undecided",
        }
    }

    /// Open the store-mode switch view, snapshotting the active mode for the
    /// `(active)` marker. Used by the Settings tab and the legacy store-pick
    /// recovery path.
    pub fn open_store_view(&mut self) {
        self.store_view = Some(StoreView::new(Some(self.current_store_mode_label())));
    }

    /// Open the store-mode picker as the `StorePicker` overlay (the Settings
    /// tab's Enter action). Builds a fresh [`StoreView`] snapshotting the active
    /// mode, stashes it on `self.store_view`, sets the overlay, and returns the
    /// `OpenOverlay` intent so the loop re-renders. The picker's cursor + switch
    /// intents are driven by [`App::route_overlay`] delegating to the stashed
    /// view's `on_key`.
    fn open_store_picker(&mut self) -> Outcome {
        self.open_store_view();
        self.overlay = Some(Overlay::StorePicker);
        Outcome::OpenOverlay(Overlay::StorePicker)
    }

    /// Leave the store view. The host ranking is unaffected by a mode switch,
    /// but re-running `recompute` is cheap and keeps both panels in sync.
    pub fn close_store_view(&mut self) {
        self.store_view = None;
        self.recompute_panels();
    }

    /// Apply the entry-routing decision (derived from `cli.cmd` in
    /// [`super::entry_mode_from_cmd`]) before the first frame. Called once from
    /// [`super::run`] after the config is loaded and before the alternate
    /// screen is entered.
    ///
    /// **Tab first, then overlay** (Task 11 routing contract): the shell's
    /// `active_tab` is set to [`EntryMode::target_tab`] BEFORE the overlay opens
    /// so the panel behind the wizard already matches user intent (e.g.
    /// `sshrack cred add` lands on the Credentials tab, not the Hosts tab). For
    /// a named edit, the matching panel selection is also moved onto that name
    /// so the cursor is on it when the overlay closes. A missing edit target
    /// (name not in the config) falls back to the panel on that tab rather than
    /// erroring — the user lands in the list with a status hint and can fix the
    /// typo, mirroring how the in-TUI edit path degrades.
    ///
    /// [`EntryMode::target_tab`]: super::EntryMode::target_tab
    pub fn apply_entry_mode(&mut self, mode: super::EntryMode) {
        // Tab first: every entry mode carries its target tab. Set it before
        // opening any overlay so the panel behind the wizard is already right.
        self.active_tab = mode.target_tab();
        match mode {
            super::EntryMode::Launcher => {}
            super::EntryMode::HostWizard { edit_name: None } => self.open_host_wizard_add(),
            super::EntryMode::HostWizard {
                edit_name: Some(name),
            } => {
                if !self.open_host_wizard_edit_by_name(&name) {
                    self.status = Status::error(format!("host '{name}' not found"));
                } else {
                    self.select_host_by_name(&name);
                }
            }
            super::EntryMode::CredWizard { edit_name: None } => self.open_cred_wizard_add(),
            super::EntryMode::CredWizard {
                edit_name: Some(name),
            } => {
                if !self.open_cred_wizard_edit(&name) {
                    self.status = Status::error(format!("credential '{name}' not found"));
                } else {
                    self.select_cred_by_name(&name);
                }
            }
        }
    }

    /// Best-effort move the launcher selection onto the host named `name`, so
    /// the cursor is on it when an entry-routed edit overlay closes. Finds the
    /// host's index in the current ranking and sets `selected`; a missing name
    /// leaves the selection untouched (the wizard still opened).
    fn select_host_by_name(&mut self, name: &str) {
        if let Some(idx) = self.launcher.ranked.iter().position(|r| {
            self.config
                .hosts
                .get(r.host_idx)
                .is_some_and(|h| h.name == name)
        }) {
            self.launcher.selected = idx;
        }
    }

    /// Best-effort move the credential panel selection onto the credential named
    /// `name`, so the cursor is on it when an entry-routed edit overlay closes.
    /// Finds the credential's index in the current ranking and sets `selected`;
    /// a missing name leaves the selection untouched.
    fn select_cred_by_name(&mut self, name: &str) {
        if let Some(idx) = self.cred_panel.ranked.iter().position(|i| {
            self.config
                .credentials
                .get(*i)
                .is_some_and(|c| c.name == name)
        }) {
            self.cred_panel.selected = idx;
        }
    }

    /// Replace the in-memory config (after a wizard save) and rebuild the
    /// credential-name lookup the launcher renders. The caller persists + (re)
    /// loads first, then hands the new config here.
    pub fn set_config(&mut self, config: SshrackConfig) {
        self.credential_names = config
            .credentials
            .iter()
            .map(|c| (c.id, c.name.clone()))
            .collect();
        self.config = config;
    }

    /// Set an informational status (normal color). The footer shows it on the
    /// next render.
    pub fn set_status(&mut self, message: String) {
        self.status = Status::info(message);
    }

    /// Set an error status (red). Used when an action fails (connect failed,
    /// switch failed, delete failed).
    pub fn set_status_error(&mut self, message: String) {
        self.status = Status::error(message);
    }

    /// The consolidated status, for the footer to render. Exposed for tests
    /// that assert the status an action set.
    #[cfg(test)]
    pub fn status(&self) -> &Status {
        &self.status
    }

    /// The pending-delete host id set by `^d` on the launcher. The loop reads
    /// (and clears) this to drive the delete confirm popup. Exposed for tests
    /// that drive the delete intent directly.
    #[cfg(test)]
    pub fn pending_delete(&self) -> Option<Ulid> {
        self.pending_delete
    }

    /// The pending-delete credential name set by `^d` on the credential panel.
    /// The loop reads (and clears) this to drive the delete confirm popup.
    /// Exposed for tests that drive the delete intent directly.
    #[cfg(test)]
    pub fn pending_delete_cred(&self) -> Option<&str> {
        self.pending_delete_cred.as_deref()
    }

    /// Borrow the credential panel mutably. Exposed for tests that drive the
    /// panel state machine directly.
    #[cfg(test)]
    pub fn cred_panel(&mut self) -> &mut CredPanel {
        &mut self.cred_panel
    }

    /// Pure: decide what should happen next for a given key. Performs **no**
    /// I/O — no reads, no writes, no terminal access — so it is safe to call
    /// from a unit test without an event source.
    ///
    /// Three layers, evaluated in order:
    /// 1. **Global** — `Ctrl-C` quits, `F1` toggles the Help overlay. These win
    ///    over everything (so the user can always quit / read help, even
    ///    mid-wizard).
    /// 2. **Overlay** — when an overlay is open it owns the key. Help dismisses
    ///    on `F1`/`Esc`/`q`; a wizard's `on_key` returns `SaveHost`/`SaveCred`/
    ///    `Cancel`/`Continue`; the store picker delegates to the stashed
    ///    `StoreView::on_key` (Up/Down/Enter/Esc); DeleteHost/DeleteCred close
    ///    on `Esc`.
    /// 3. **Panel/tab** — when no overlay is open: `tab_key_decision` switches
    ///    tabs (Tab / Shift-Tab / Ctrl-1/2/3), then `Ctrl-A/E/D` + `Enter` +
    ///    `Esc`, then the active panel consumes printable chars / arrows.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

        // Layer 1 — global keys (work with or without an overlay).
        // Ctrl-C must be EXACTLY Control+c — `contains` would wrongly treat
        // Ctrl-Shift-C (terminal paste) as quit. Same invariant the launcher
        // held before the rewrite.
        if key.kind == KeyEventKind::Press
            && key.modifiers == KeyModifiers::CONTROL
            && key.code == KeyCode::Char('c')
        {
            self.should_quit = true;
            return Outcome::Quit;
        }
        if key.kind == KeyEventKind::Press && key.modifiers.is_empty() && key.code == KeyCode::F(1)
        {
            // Toggle help: open if none, close if Help is already up.
            if matches!(self.overlay, Some(Overlay::Help)) {
                self.overlay = None;
                return Outcome::CloseOverlay;
            }
            self.overlay = Some(Overlay::Help);
            return Outcome::OpenOverlay(Overlay::Help);
        }

        // Layer 2 — an open overlay owns the key. take() it so we can borrow
        // `self` mutably inside route_overlay without a borrow conflict, then
        // route_overlay stashes it back unless the outcome is terminal.
        if let Some(ov) = self.overlay.take() {
            return self.route_overlay(key, ov);
        }

        // Layer 3 — panel/tab layer (no overlay).
        self.route_panel(key)
    }

    /// Layer 2: route a key into the active overlay. The overlay was `take()`n
    /// by [`on_key`]; this stashes it back unless the outcome is terminal
    /// (`Cancel`/`CloseOverlay`), so the form state survives across keystrokes.
    fn route_overlay(&mut self, key: KeyEvent, ov: Overlay) -> Outcome {
        use crossterm::event::{KeyCode, KeyEventKind};
        match ov {
            Overlay::Help => {
                if key.kind == KeyEventKind::Press
                    && matches!(key.code, KeyCode::Esc | KeyCode::F(1) | KeyCode::Char('q'))
                {
                    return Outcome::CloseOverlay;
                }
                self.overlay = Some(Overlay::Help);
                Outcome::Continue
            }
            Overlay::HostWizard(mut form) => {
                let out = form.on_key(key);
                // SaveHost/Continue need the form stashed back so the loop can
                // read it (on save) or the user can keep editing (on continue).
                // Cancel/CloseOverlay are terminal — drop the form.
                let terminal = matches!(out, Outcome::Cancel | Outcome::CloseOverlay);
                if !terminal {
                    self.overlay = Some(Overlay::HostWizard(form));
                }
                out
            }
            Overlay::CredWizard(mut form) => {
                let out = form.on_key(key);
                let terminal = matches!(out, Outcome::Cancel | Outcome::CloseOverlay);
                if !terminal {
                    self.overlay = Some(Overlay::CredWizard(form));
                }
                out
            }
            Overlay::StorePicker => {
                // Delegate to the stashed store view's on_key (Up/Down move the
                // cursor; Enter signals SwitchTo{Keyring,Vault,Plaintext}; Esc
                // signals Cancel). on_key is pure — the loop runs the I/O-heavy
                // migration + persist on the switch outcomes. Cancel / switch
                // outcomes are terminal for the overlay (the view is dropped /
                // closed by the loop); Continue keeps the picker open.
                let Some(view) = self.store_view.as_mut() else {
                    // Defensive: open_store_picker always stashes the view. If it
                    // is missing, close the overlay rather than panic.
                    return Outcome::CloseOverlay;
                };
                let out = view.on_key(key);
                let terminal = matches!(
                    out,
                    Outcome::SwitchToKeyring
                        | Outcome::SwitchToVault
                        | Outcome::SwitchToPlaintext
                        | Outcome::Cancel
                        | Outcome::CloseOverlay
                );
                if !terminal {
                    self.overlay = Some(Overlay::StorePicker);
                }
                out
            }
        }
    }

    /// Layer 3: route a key to the active panel/tab. No overlay is open when
    /// this runs (the caller checked). Tab switching is decided first so a
    /// `Tab`/`Ctrl-1/2/3` never reaches a panel's search box.
    fn route_panel(&mut self, key: KeyEvent) -> Outcome {
        use crossterm::event::{KeyCode, KeyModifiers};

        if key.kind != crossterm::event::KeyEventKind::Press {
            return Outcome::Continue;
        }

        // Tab switching first (Tab / BackTab / Ctrl-1/2/3).
        match tab_key_decision(key) {
            TabKey::To(t) => {
                self.active_tab = t;
                return Outcome::SwitchTab(t);
            }
            TabKey::Cycle(d) => {
                let new = if d > 0 {
                    self.active_tab.next()
                } else {
                    self.active_tab.prev()
                };
                self.active_tab = new;
                return Outcome::SwitchTab(new);
            }
            TabKey::None => {}
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        // Ctrl-A/E/D act on the current tab's selected row.
        if ctrl && key.code == KeyCode::Char('a') {
            return self.open_add_overlay();
        }
        if ctrl && key.code == KeyCode::Char('e') {
            return self.open_edit_overlay();
        }
        if ctrl && key.code == KeyCode::Char('d') {
            return self.begin_delete();
        }
        // Esc: clear the active panel's query, or (if empty) quit.
        if key.code == KeyCode::Esc && key.modifiers.is_empty() {
            if self.active_panel_query().is_empty() {
                self.should_quit = true;
                return Outcome::Quit;
            }
            self.clear_active_panel_query();
            return Outcome::Continue;
        }
        // Enter: tab-specific primary action.
        if key.code == KeyCode::Enter && key.modifiers.is_empty() {
            return self.primary_action();
        }
        // Otherwise the active panel consumes it (printable chars → query,
        // arrows → move).
        self.route_active_panel_key(key)
    }

    /// Open the add overlay for the active tab. Hosts opens the host wizard;
    /// Credentials opens the cred wizard; Settings is Task 8.
    fn open_add_overlay(&mut self) -> Outcome {
        match self.active_tab {
            Tab::Hosts => {
                let names: Vec<String> = self
                    .config
                    .credentials
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                let ov = Overlay::HostWizard(HostForm::new_add(names));
                self.overlay = Some(ov.clone());
                Outcome::OpenOverlay(ov)
            }
            Tab::Credentials => {
                let ov = Overlay::CredWizard(CredForm::new_add());
                self.overlay = Some(ov.clone());
                Outcome::OpenOverlay(ov)
            }
            Tab::Settings => Outcome::Continue,
        }
    }

    /// Open the edit overlay for the active tab, prefilled from the selected
    /// row. Hosts edits the host under the launcher cursor; Credentials edits
    /// the credential under the cred panel cursor; Settings is Task 8.
    fn open_edit_overlay(&mut self) -> Outcome {
        match self.active_tab {
            Tab::Hosts => {
                if let Some(h) = self.launcher.selected_host(&self.config.hosts) {
                    let id = h.id;
                    self.open_host_wizard_edit(id);
                    // open_host_wizard_edit set self.overlay; mirror it into the
                    // returned outcome (it is Some when the edit succeeded).
                    match self.overlay.clone() {
                        Some(ov) => Outcome::OpenOverlay(ov),
                        None => Outcome::Continue,
                    }
                } else {
                    self.status = Status::error("no host selected to edit".to_string());
                    Outcome::Continue
                }
            }
            Tab::Credentials => {
                // Resolve the cursor → the credential's name, then open the
                // edit wizard prefilled from it. The name lookup is done from
                // the config (not the panel) so a missing credential surfaces
                // cleanly rather than indexing nothing.
                let Some(name) = self
                    .cred_panel
                    .selected_credential(&self.config.credentials)
                    .map(|c| c.name.clone())
                else {
                    self.status = Status::error("no credential selected to edit".to_string());
                    return Outcome::Continue;
                };
                self.open_cred_wizard_edit(&name);
                match self.overlay.clone() {
                    Some(ov) => Outcome::OpenOverlay(ov),
                    None => Outcome::Continue,
                }
            }
            Tab::Settings => Outcome::Continue,
        }
    }

    /// Begin a delete on the selected row. Hosts sets `pending_delete` and
    /// returns [`Outcome::DeleteHost`] (the loop drives the confirm popup);
    /// Credentials sets `pending_delete_cred` and returns
    /// [`Outcome::DeleteCred`]; Settings is Task 8.
    fn begin_delete(&mut self) -> Outcome {
        match self.active_tab {
            Tab::Hosts => match self.launcher.selected_host(&self.config.hosts) {
                Some(h) => {
                    self.pending_delete = Some(h.id);
                    Outcome::DeleteHost
                }
                None => {
                    self.status = Status::error("no host selected to delete".to_string());
                    Outcome::Continue
                }
            },
            Tab::Credentials => {
                let Some(name) = self
                    .cred_panel
                    .selected_credential(&self.config.credentials)
                    .map(|c| c.name.clone())
                else {
                    self.status = Status::error("no credential selected to delete".to_string());
                    return Outcome::Continue;
                };
                self.pending_delete_cred = Some(name);
                Outcome::DeleteCred
            }
            Tab::Settings => Outcome::Continue,
        }
    }

    /// The tab-specific primary action on Enter. Hosts delegates to the
    /// launcher's `on_key` (which sets `pending_connect` and returns
    /// `ConnectRequested`); Credentials opens the edit wizard for the selected
    /// credential (Enter = edit on this tab); Settings opens the store-mode
    /// picker overlay.
    fn primary_action(&mut self) -> Outcome {
        match self.active_tab {
            Tab::Hosts => {
                let out = self
                    .launcher
                    .on_key(enter_press(), &self.config.hosts, &self.frecency);
                self.pending_connect = self.launcher.pending_connect;
                // When Enter hit no host (empty list / filtered out), the
                // launcher returns Continue with pending_connect still None.
                // Surface that as a status so the single footer gives feedback
                // instead of silently no-op'ing. (Restores the hint lost when
                // Launcher::status was removed; the Credentials tab's edit path
                // already sets its own status.)
                if matches!(out, Outcome::Continue) && self.pending_connect.is_none() {
                    self.status = Status::info("no host selected".to_string());
                }
                out
            }
            Tab::Credentials => self.open_edit_overlay(),
            Tab::Settings => self.open_store_picker(),
        }
    }

    /// Forward a panel-level key to the active panel. Hosts → the launcher's
    /// `on_key` (query/selection); Credentials → the cred panel's `on_key`;
    /// Settings → the settings panel's `on_key` (Up/Down/Enter only — printable
    /// chars are ignored, Settings has no query).
    fn route_active_panel_key(&mut self, key: KeyEvent) -> Outcome {
        match self.active_tab {
            Tab::Hosts => {
                let out = self
                    .launcher
                    .on_key(key, &self.config.hosts, &self.frecency);
                if matches!(out, Outcome::Quit) {
                    self.should_quit = true;
                }
                out
            }
            Tab::Credentials => self.cred_panel.on_key(key, &self.config.credentials),
            Tab::Settings => self.settings_panel.on_key(key),
        }
    }

    /// The active panel's query string (for Esc-clears-query). Hosts → the
    /// launcher query; Credentials → the cred panel query; Settings has an
    /// empty "query".
    fn active_panel_query(&self) -> &str {
        match self.active_tab {
            Tab::Hosts => &self.launcher.query,
            Tab::Credentials => &self.cred_panel.query,
            Tab::Settings => "",
        }
    }

    /// Clear the active panel's query (Esc on a non-empty query). Hosts clears
    /// the launcher query and re-ranks; Credentials clears the cred panel query
    /// and re-ranks.
    fn clear_active_panel_query(&mut self) {
        match self.active_tab {
            Tab::Hosts => {
                self.launcher.query.clear();
                self.launcher.recompute(&self.config.hosts, &self.frecency);
            }
            Tab::Credentials => {
                self.cred_panel.query.clear();
                self.cred_panel.recompute(&self.config.credentials);
            }
            Tab::Settings => {}
        }
    }

    /// Render current state to the frame. Only writes to the frame (no stdout
    /// access of its own). Draws the three-band shell, the active panel into the
    /// middle band, and the overlay (if any) on top.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let footer = self.footer_hints();
        let panel_area = draw_shell(frame, area, self.active_tab, &footer, &self.status);
        match self.active_tab {
            Tab::Hosts => self.launcher.draw_in_shell(
                frame,
                panel_area,
                &self.config.hosts,
                &self.frecency,
                &self.config.credentials,
            ),
            Tab::Credentials => {
                self.cred_panel
                    .draw_in_shell(frame, panel_area, &self.config.credentials)
            }
            Tab::Settings => self.settings_panel.draw_in_shell(
                frame,
                panel_area,
                self.current_store_mode_label(),
            ),
        }
        if let Some(ov) = &self.overlay {
            self.draw_overlay(frame, ov);
        }
    }

    /// The footer hint pairs for the active surface. Overlays show their own
    /// field/save/cancel hints; the panel footer reflects the active tab's
    /// bindings.
    fn footer_hints(&self) -> Vec<(&'static str, &'static str)> {
        if self.overlay.is_some() {
            return vec![("Tab", "field"), ("^S", "save"), ("Esc", "cancel")];
        }
        match self.active_tab {
            Tab::Hosts => vec![
                ("Enter", "connect"),
                ("^A", "add"),
                ("^E", "edit"),
                ("^D", "delete"),
                ("F1", "help"),
            ],
            Tab::Credentials => vec![
                ("Enter", "edit"),
                ("^A", "add"),
                ("^E", "edit"),
                ("^D", "delete"),
                ("F1", "help"),
            ],
            Tab::Settings => vec![("Enter", "edit"), ("F1", "help")],
        }
    }

    /// Render the active overlay on top of the shell. Wizards draw their field
    /// rows into the body rect [`draw_dialog`] hands them; Help is the static
    /// keymap reference; StorePicker draws the three-mode list into the dialog
    /// body via [`StoreView::draw_in_dialog`]; DeleteHost/DeleteCred render an
    /// empty dialog (the loop drives their confirm popups).
    fn draw_overlay(&self, frame: &mut Frame, ov: &Overlay) {
        match ov {
            Overlay::Help => draw_help_dialog(frame),
            Overlay::HostWizard(form) => {
                let body = draw_dialog(
                    frame,
                    &form.title(),
                    0,
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                form.draw_in_dialog(frame, body);
            }
            Overlay::CredWizard(form) => {
                let body = draw_dialog(
                    frame,
                    &form.title(),
                    0,
                    &[("Tab", "field"), ("^S", "save"), ("Esc", "cancel")],
                );
                form.draw_in_dialog(frame, body);
            }
            Overlay::StorePicker => {
                let body = draw_dialog(
                    frame,
                    " storage mode ",
                    0,
                    &[("↑↓", "select"), ("Enter", "switch"), ("Esc", "cancel")],
                );
                self.store_view
                    .as_ref()
                    .expect("invariant: store_view stashed while StorePicker overlay is open")
                    .draw_in_dialog(frame, body);
            }
        }
    }
}

/// A synthetic `Enter` Press event, used by [`App::primary_action`] to drive
/// the launcher's `on_key` (which already owns the Enter→`pending_connect`→
/// `ConnectRequested` logic) without re-implementing it.
fn enter_press() -> KeyEvent {
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Press)
}

/// Blocking event loop. Renders `app`, polls crossterm for key events, and
/// dispatches each key through [`App::on_key`]. Returns `Some(req)` when the
/// user connects (the loop exits and `main` execs ssh after terminal restore),
/// or `None` when the user quits.
///
/// When `on_key` returns [`Outcome::ConnectRequested`], the launcher has set
/// `pending_connect` to a host id (pure intent, no I/O). The loop then runs
/// [`connect_host`] — vault unlock popup, host-key confirm popup, argv build,
/// frecency record+save — which is the connect orchestration mirroring
/// `cli::cmd::connect::run`. A user cancel inside a popup (Esc/Ctrl-C)
/// surfaces as [`SshrackError::Interrupted`] and returns the user to the
/// launcher rather than exiting: `pending_connect` is cleared and the loop
/// keeps running. Any other orchestration error is shown in the status line
/// and also returns to the launcher.
///
/// Event-read errors are tolerated (treated as "no event this tick") rather
/// than aborting the TUI: a transient read failure should not strand the user
/// in an unrecoverable state. The terminal is still restored on return because
/// the caller owns the [`TerminalGuard`].
///
/// # Reentrancy-safe borrow (Critical #1)
///
/// `terminal` is the shared `Rc<RefCell<Tui>>` (cloned from
/// [`TerminalGuard::terminal`]). The loop borrows it mutably ONLY for the
/// duration of each `draw(...)` call — the `RefMut` is dropped the instant the
/// draw closure returns, BEFORE the loop reads a key or runs a side effect.
/// The popup paths (`connect_host`, `TuiPassphrase::confirm`, the
/// store-switch popups) borrow the terminal themselves by upgrading the weak
/// `handle`; because the loop's `RefMut` is already released, their
/// `borrow_mut()` succeeds instead of panicking. Holding a long-lived
/// `RefMut` across this whole loop re-introduces the panic on every popup.
pub fn run_loop(
    terminal: &Rc<RefCell<Tui>>,
    app: &mut App,
    handle: TerminalHandle,
    data_dir: Option<&std::path::Path>,
) -> Option<ConnectRequest> {
    loop {
        // Borrow ONLY for the draw, then release before any key read or side
        // effect. A popup re-borrows via the weak handle and must not collide.
        {
            let mut t = terminal.borrow_mut();
            if t.draw(|f| app.draw(f)).is_err() {
                // A draw failure (e.g. suspended tty) is not fatal; try again
                // next tick. The RefMut is released at the end of this block
                // before the loop reads a key or runs a popup.
            }
        }

        if !event::poll(Duration::from_millis(250)).unwrap_or(false) {
            // No event within the poll window, or poll itself failed: re-render
            // and poll again. Unwrap_or(false) keeps the loop alive on a
            // transient poll error instead of unwinding the TUI.
            continue;
        }

        let event = match event::read() {
            Ok(ev) => ev,
            Err(_) => continue,
        };

        if let Event::Key(key) = event {
            // Only react to key presses, not releases/repeats (crossterm 0.28
            // emits Release/Repeat on some platforms).
            match app.on_key(key) {
                Outcome::Quit => return None,
                Outcome::ConnectRequested => {
                    // Read the pure intent the launcher set on Enter. Clear it
                    // so a subsequent keystroke does not re-fire a stale id.
                    let Some(host_id) = app.launcher.pending_connect.take() else {
                        // No id: defensive — treat as if Enter hit no host.
                        continue;
                    };
                    match connect_host(host_id, app, handle.clone(), data_dir) {
                        Ok(req) => return Some(req),
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a popup (Esc/Ctrl-C). Return to the
                            // launcher, NOT an exit. No status write — the popup
                            // dismissing is the feedback.
                        }
                        Err(e) => {
                            // A real error (vault unlock fail, host-key reject,
                            // dangling credential, frecency save fail). Surface
                            // it in the status line (red) and return to the
                            // launcher so the user can read it.
                            app.set_status_error(format!("connect failed: {e}"));
                        }
                    }
                }
                Outcome::SaveHost => {
                    // The wizard signaled save after its pure validate() passed.
                    // Persist: build the host, resolve the credential name→id,
                    // add or apply-patch, write config, reload, close the wizard
                    // overlay. on_key's route_overlay stashed the form back on
                    // SaveHost (non-terminal), so the overlay is still open here.
                    match persist_host_save(app, &handle) {
                        Ok(()) => {
                            app.set_status("host saved".to_string());
                            app.close_host_wizard();
                        }
                        Err(e) => {
                            // Persist failed (duplicate name, write error,
                            // dangling credential). Surface in the wizard's
                            // core-error line and stay in the overlay so the
                            // user can fix it.
                            if let Some(Overlay::HostWizard(w)) = app.overlay.as_mut() {
                                w.set_core_error(e.to_string());
                            }
                        }
                    }
                }
                Outcome::SaveCred => {
                    // The cred wizard signaled save after its pure validate()
                    // passed. Persist + recover from a store-undecided state in
                    // place (popup + switch + retry) without leaving the wizard.
                    fulfill_save_cred(app, &handle);
                }
                Outcome::Cancel => {
                    // A wizard's Esc / Ctrl-C: on_key's route_overlay already
                    // dropped the form (terminal outcome) and left the overlay
                    // clear. No status write — the overlay closing is the
                    // feedback; re-rank so the Hosts tab reflects any state.
                    app.close_overlay();
                }
                Outcome::CloseOverlay => {
                    // Esc / Ctrl-C inside a non-wizard overlay (Help /
                    // StorePicker / DeleteHost). on_key already cleared it; the
                    // overlay closing is the feedback, so no status write.
                }
                Outcome::SwitchTab(_) | Outcome::OpenOverlay(_) | Outcome::Continue => {
                    // Pure state changes already applied inside on_key; the next
                    // draw reflects them. Nothing for the loop to do.
                }
                Outcome::SwitchToKeyring => {
                    match persist_store_switch(app, StoreSwitchTarget::Keyring, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to keyring mode".to_string());
                        }
                        Ok(false) => {
                            // Keyring unavailable or a transient error surfaced in
                            // the store view's status line; stay in the view.
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a vault-unlock popup (vault→keyring
                            // needs the source key). Stay in the store view. No
                            // status write — the popup dismissing is the feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::SwitchToVault => {
                    match persist_store_switch(app, StoreSwitchTarget::Vault, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to vault mode".to_string());
                        }
                        Ok(false) => {}
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the passphrase popup. Stay in the
                            // view. No status write — the popup dismissing is the
                            // feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::SwitchToPlaintext => {
                    match persist_store_switch(app, StoreSwitchTarget::Plaintext, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to plaintext mode".to_string());
                        }
                        Ok(false) => {}
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the confirm popup (or a vault-unlock
                            // popup, when leaving vault). Stay in the store view.
                            // No status write — the popup dismissing is the
                            // feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::DeleteHost => {
                    // Pure intent: ^d on a host set pending_delete. Drive the
                    // confirm popup, then (on Yes) core delete + keyring cleanup
                    // + persist + reload. A cancel (Esc/Ctrl-C in the popup, or
                    // a No) closes the overlay with NO status write — the popup
                    // dismissing is the feedback — and is NOT an exit.
                    let Some(host_id) = app.pending_delete.take() else {
                        continue;
                    };
                    // Resolve id → name for the confirm message BEFORE deleting
                    // (the host is gone after delete). None is defensive (the
                    // launcher only hands out ids from the loaded config).
                    let name = app
                        .config
                        .find_host_by_id(&host_id)
                        .map(|h| h.name.clone())
                        .unwrap_or_else(|| host_id.to_string());
                    let provider = TuiPassphrase::new(handle.clone());
                    let prompt = format!("Remove host '{name}'?");
                    match provider.confirm(&prompt) {
                        Ok(true) => match persist_host_delete(app, &name) {
                            Ok(()) => {
                                app.overlay = None;
                                app.set_status(format!("removed '{name}'"));
                            }
                            Err(e) => {
                                app.set_status_error(format!("delete failed: {e}"));
                            }
                        },
                        Ok(false) => {
                            // User declined (No). The confirm popup closing is
                            // the feedback; no status write.
                            app.overlay = None;
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the popup (Esc/Ctrl-C). No status
                            // write — the popup dismissing is the feedback.
                            app.overlay = None;
                        }
                        Err(e) => {
                            app.set_status_error(format!("delete failed: {e}"));
                        }
                    }
                }
                Outcome::DeleteCred => {
                    // Pure intent: ^d on a credential set pending_delete_cred.
                    // Drive the confirm popup, then (on Yes) core delete +
                    // keyring cleanup + persist + reload. A cancel (Esc/Ctrl-C
                    // in the popup, or a No) closes the overlay with NO status
                    // write — the popup dismissing is the feedback — and is NOT
                    // an exit.
                    let Some(name) = app.pending_delete_cred.take() else {
                        continue;
                    };
                    let provider = TuiPassphrase::new(handle.clone());
                    let prompt = format!("Remove credential '{name}'?");
                    match provider.confirm(&prompt) {
                        Ok(true) => match persist_cred_delete(app, &name) {
                            Ok(()) => {
                                app.overlay = None;
                                app.set_status(format!("removed '{name}'"));
                            }
                            Err(e) => {
                                app.set_status_error(format!("delete failed: {e}"));
                            }
                        },
                        Ok(false) => {
                            // User declined (No). The confirm popup closing is
                            // the feedback; no status write.
                            app.overlay = None;
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the popup (Esc/Ctrl-C). No status
                            // write — the popup dismissing is the feedback.
                            app.overlay = None;
                        }
                        Err(e) => {
                            app.set_status_error(format!("delete failed: {e}"));
                        }
                    }
                }
            }
        }

        if app.should_quit {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    //! Purity tests for `App::on_key`. The contract: `on_key` takes a key and
    //! returns an outcome with **no I/O**. These tests call it directly (no
    //! terminal, no event source) to pin both the behavior and the purity.

    use super::*;
    use crate::tui::persist::persist_cred_save;
    use crate::tui::test_support::{
        app_with_credential, app_with_host, app_with_named_cred, dead_handle, press, stdout_tui,
    };
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use std::collections::HashMap;
    use ulid::Ulid;

    #[test]
    fn esc_with_empty_query_yields_quit() {
        // The launcher starts with an empty query, so the first Esc quits.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Quit));
        assert!(app.should_quit, "Esc should set should_quit");
    }

    #[test]
    fn esc_after_typing_clears_query_then_second_esc_quits() {
        let mut app = app_with_host("web");
        // Type 'w' (query now non-empty), so the first Esc clears, not quits.
        app.on_key(press(KeyCode::Char('w'), KeyModifiers::NONE));
        assert!(!app.should_quit);
        assert_eq!(app.launcher.query, "w");
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(app.launcher.query.is_empty(), "Esc should clear the query");
        assert!(
            !app.should_quit,
            "first Esc must not quit when query had text"
        );
        // Second Esc now that the query is empty → quit.
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Quit));
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_c_yields_quit() {
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Quit));
        assert!(app.should_quit, "Ctrl-C should set should_quit");
    }

    #[test]
    fn neutral_key_yields_continue_and_appends_to_query() {
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit, "a neutral key must not flip should_quit");
        assert_eq!(app.launcher.query, "a");
    }

    #[test]
    fn key_release_is_ignored() {
        // Release events must not be treated as a quit even for Esc.
        let mut app = app_with_host("web");
        let release =
            KeyEvent::new_with_kind(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release);
        let outcome = app.on_key(release);
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
    }

    #[test]
    fn bare_ctrl_c_modifier_combo_only() {
        // Ctrl-Shift-C or Ctrl-Alt-C are NOT quit bindings — only plain Ctrl-C.
        // (Terminal paste, e.g. Ctrl-Shift-C, must not accidentally quit.) The
        // global key check requires `modifiers == CONTROL` (not `contains`) so
        // an extra Shift/Alt modifier exempts the key.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
    }

    #[test]
    fn enter_signals_connect_intent_without_quitting() {
        // Task 15: Enter is now the pure ConnectRequested intent. on_key does
        // NO I/O; it sets pending_connect and returns ConnectRequested. The
        // loop runs connect orchestration. This pins the pure half.
        let mut app = app_with_host("web");
        let expected_id = app.config.hosts[0].id;
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::ConnectRequested));
        assert!(!app.should_quit, "Enter must not set should_quit");
        assert_eq!(app.launcher.pending_connect, Some(expected_id));
    }

    #[test]
    fn enter_with_no_host_surfaces_no_host_selected_status() {
        // When Enter hits no host (empty host list), primary_action must surface
        // a "no host selected" status so the single footer gives feedback
        // instead of silently no-op'ing. Restores the hint lost when
        // Launcher::status was removed; mirrors the Credentials edit path.
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        assert!(app.config().hosts.is_empty());
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(
            app.launcher.pending_connect.is_none(),
            "no host → no pending_connect"
        );
        assert_eq!(
            app.status().message.as_deref(),
            Some("no host selected"),
            "Enter on no host must surface a status, not silently no-op"
        );
        assert!(!app.status().is_error, "the hint is informational, not red");
    }

    #[test]
    fn down_then_up_moves_selection() {
        // Build a two-host app so ↑↓ has somewhere to go.
        let h1 = Host {
            id: Ulid::new(),
            name: "alpha".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        };
        let h2 = Host {
            id: Ulid::new(),
            name: "bravo".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        };
        let cfg = SshrackConfig {
            hosts: vec![h1, h2],
            ..SshrackConfig::default()
        };
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        assert_eq!(app.launcher.selected, 0);
        app.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(
            app.launcher.selected, 1,
            "Down should move to the second host"
        );
        app.on_key(press(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(
            app.launcher.selected, 0,
            "Up should move back to the first host"
        );
    }

    #[test]
    fn ctrl_a_opens_add_host_wizard() {
        // Task 16: ^a opens the host wizard overlay in add mode (blank form).
        // In the new model it returns OpenOverlay(Overlay::HostWizard(_)) and
        // stashes the overlay on App::overlay.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::HostWizard(_))
        ));
        assert!(!app.should_quit);
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "^a should open the host wizard overlay"
        );
        let w = app.wizard().expect("wizard open");
        assert!(!w.editing, "add mode must be non-editing");
        assert!(w.name.is_empty(), "add form must start blank");
    }

    #[test]
    fn ctrl_e_opens_edit_host_wizard_prefilled() {
        // Task 16: ^e on the selected host opens the wizard overlay in edit
        // mode, prefilled from that host, and returns OpenOverlay(...).
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::HostWizard(_))
        ));
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "^e should open the host wizard overlay"
        );
        let w = app.wizard().expect("wizard open");
        assert!(w.editing, "edit mode must be editing");
        assert_eq!(w.name, "web", "edit form must be prefilled");
    }

    #[test]
    fn ctrl_e_with_no_host_sets_status_and_stays_in_launcher() {
        // ^e with an empty host list cannot pick a host to edit: it sets the
        // consolidated status and returns Continue (no overlay).
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(app.overlay().is_none(), "no overlay when there is no host");
        assert_eq!(
            app.status().message.as_deref(),
            Some("no host selected to edit")
        );
    }

    #[test]
    fn wizard_esc_closes_back_to_launcher() {
        // Esc inside the wizard signals Cancel; route_overlay treats Cancel as
        // terminal, so the overlay is dropped and the app is back at the panel.
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "wizard opened"
        );
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Cancel));
        assert!(
            app.overlay().is_none(),
            "Cancel must drop the wizard overlay (back to launcher)"
        );
        assert!(app.wizard().is_none());
    }

    // ---- end-to-end add→save→launcher-reflects, driven via on_key + loop actions ----

    #[test]
    fn add_flow_via_on_key_then_save_reflects_in_launcher() {
        // Mirrors the smoke: ^a opens add wizard, type name+host, ^s saves,
        // launcher re-ranks and shows the new host. Uses on_key for the key half
        // and the loop's actions (persist_host_save + close_host_wizard) for the
        // I/O half — exactly the loop's wiring.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());
        assert!(app.config().hosts.is_empty());

        // ^a → opens wizard overlay.
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host wizard overlay open"
        );

        // Type "web" into the Name field, Tab to Host, type address, ^s.
        for ch in "web".chars() {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        app.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        for ch in "10.0.0.5".chars() {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        let outcome = app.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::SaveHost));

        // Loop actions.
        persist_host_save(&mut app, &dead_handle()).expect("save");
        app.close_host_wizard();
        assert!(app.overlay().is_none(), "overlay closed back to launcher");
        // The launcher now sees the new host (re-ranked on close).
        assert_eq!(app.config().hosts.len(), 1);
        assert_eq!(app.launcher.ranked.len(), 1);
        assert_eq!(app.config().hosts[0].name, "web");
    }

    #[test]
    fn edit_flow_via_on_key_prefilled_then_change_port_saves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: orig_id,
                name: "web".into(),
                host: "10.0.0.5".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("ops")),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        // ^e on the selected (only) host → wizard overlay prefilled.
        app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host wizard overlay open"
        );
        let w = app.wizard().expect("wizard open");
        assert_eq!(w.name, "web");
        assert_eq!(w.host_addr, "10.0.0.5");
        assert_eq!(w.port, "22");

        // Move focus to Port (Tab x2: Name→Host→Port) and clear+retype.
        app.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        app.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        // Clear the "22" and type "2200".
        for _ in 0..2 {
            app.on_key(press(KeyCode::Backspace, KeyModifiers::NONE));
        }
        for ch in "2200".chars() {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        let outcome = app.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::SaveHost));

        persist_host_save(&mut app, &dead_handle()).expect("save");
        app.close_host_wizard();
        assert_eq!(app.config().hosts.len(), 1);
        assert_eq!(app.config().hosts[0].port, 2200);
        assert_eq!(app.config().hosts[0].id, orig_id);
    }

    #[test]
    fn add_flow_esc_cancels_and_persists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        // Type a partial name, then Esc.
        app.on_key(press(KeyCode::Char('w'), KeyModifiers::NONE));
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Cancel));

        assert!(
            app.overlay().is_none(),
            "Cancel drops the wizard overlay (back to launcher)"
        );
        // Nothing persisted.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.hosts.is_empty());
    }

    // ===============================================================
    // Credential wizard: entry routing + on_key-driven flow.
    // (The persist_cred_save I/O tests live in persist.rs.)
    // ===============================================================

    use sshrack_core::config::schema::{Credential, SecretStore};

    // ---- entry routing ----

    #[test]
    fn entry_mode_cred_add_opens_cred_wizard_directly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        app.apply_entry_mode(super::super::EntryMode::CredWizard { edit_name: None });
        assert!(
            matches!(app.overlay(), Some(Overlay::CredWizard(_))),
            "cred entry opens the cred wizard overlay"
        );
        assert!(
            !app.cred_wizard().unwrap().editing,
            "add entry must open the add (non-editing) form"
        );
    }

    #[test]
    fn entry_mode_cred_edit_prefills_from_named_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: Ulid::new(),
                name: "ops".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        app.apply_entry_mode(super::super::EntryMode::CredWizard {
            edit_name: Some("ops".into()),
        });
        assert!(
            matches!(app.overlay(), Some(Overlay::CredWizard(_))),
            "cred edit entry opens the cred wizard overlay"
        );
        let w = app.cred_wizard().expect("cred wizard open");
        assert!(w.editing);
        assert_eq!(w.name, "ops");
        assert_eq!(w.user, "deploy");
    }

    #[test]
    fn entry_mode_cred_edit_unknown_name_falls_back_to_launcher_with_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        app.apply_entry_mode(super::super::EntryMode::CredWizard {
            edit_name: Some("ghost".into()),
        });
        assert!(app.overlay().is_none(), "unknown name opens no overlay");
        assert!(app.cred_wizard().is_none());
        assert!(
            app.status()
                .message
                .as_deref()
                .unwrap_or("")
                .contains("not found")
        );
    }

    #[test]
    fn entry_mode_host_add_opens_host_wizard() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        app.apply_entry_mode(super::super::EntryMode::HostWizard { edit_name: None });
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host entry opens the host wizard overlay"
        );
        assert!(app.wizard().is_some());
    }

    #[test]
    fn cred_wizard_esc_cancels_back_to_launcher() {
        let mut app = app_with_host("web");
        app.open_cred_wizard_add();
        assert!(
            matches!(app.overlay(), Some(Overlay::CredWizard(_))),
            "cred wizard overlay open"
        );
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Cancel));
        assert!(
            app.overlay().is_none(),
            "Cancel drops the cred wizard overlay (back to launcher)"
        );
        assert!(app.cred_wizard().is_none());
    }

    #[test]
    fn cred_add_flow_via_on_key_then_save_persists() {
        // End-to-end via on_key (key half) + persist_cred_save (I/O half),
        // mirroring the host add-flow test. Drives: c opens add wizard, type
        // name+user, ^s saves.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        // Open the cred wizard directly (bare `c` is now a query char, not the
        // cred-add binding).
        app.open_cred_wizard_add();
        assert!(
            matches!(app.overlay(), Some(Overlay::CredWizard(_))),
            "cred wizard overlay open"
        );
        // Type "ops" into Name, Tab to User, type "deploy", ^s.
        for ch in "ops".chars() {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        app.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
        for ch in "deploy".chars() {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        let outcome = app.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::SaveCred));

        persist_cred_save(&mut app, &dead_handle()).expect("save");
        app.close_cred_wizard();
        assert!(app.overlay().is_none(), "overlay closed back to launcher");
        assert_eq!(app.config().credentials.len(), 1);
        assert_eq!(app.config().credentials[0].name, "ops");
    }

    // ===============================================================
    // Task 19: delete flow (^d → confirm → core delete).
    // ===============================================================

    #[test]
    fn ctrl_d_on_selected_host_signals_delete_intent_pure() {
        // ^d sets pending_delete to the host under the cursor and returns
        // DeleteHost. on_key does NO I/O; the loop drives the popup + core
        // delete. This pins the pure half.
        let mut app = app_with_host("web");
        let expected_id = app.config.hosts[0].id;
        let outcome = app.on_key(press(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::DeleteHost));
        assert_eq!(app.pending_delete(), Some(expected_id));
    }

    #[test]
    fn ctrl_d_with_no_host_sets_launcher_status_and_stays() {
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        let outcome = app.on_key(press(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(app.overlay().is_none(), "no overlay when there is no host");
        assert!(
            app.status()
                .message
                .as_deref()
                .unwrap_or("")
                .contains("no host selected to delete")
        );
    }

    // ===============================================================
    // New-model bindings: tab switching, conflict-fix query chars,
    // overlay-open intents, and Esc-closes-overlay purity.
    // ===============================================================

    #[test]
    fn ctrl_digits_and_tab_switch_tab() {
        let mut app = app_with_host("web");
        assert!(matches!(
            app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)),
            Outcome::SwitchTab(Tab::Credentials)
        ));
        assert!(matches!(
            app.on_key(press(KeyCode::Tab, KeyModifiers::NONE)),
            Outcome::SwitchTab(Tab::Settings)
        ));
    }

    #[test]
    fn bare_chars_c_and_question_and_digit_reach_query() {
        // The conflict fix: these used to be hotkeys (c cred-add, ? help). No more.
        let mut app = app_with_host("web");
        for ch in ['c', '?', '1', 'a'] {
            app.on_key(press(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(app.launcher.query, "c?1a");
    }

    #[test]
    fn ctrl_a_opens_host_wizard_overlay() {
        let mut app = app_with_host("web");
        let out = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(out, Outcome::OpenOverlay(Overlay::HostWizard(_))));
        assert!(app.overlay().is_some());
    }

    #[test]
    fn esc_inside_overlay_closes_it_and_does_not_touch_query() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL)); // open host wizard
        let q_before = app.launcher.query.clone();
        let out = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(out, Outcome::Cancel) || matches!(out, Outcome::CloseOverlay));
        assert_eq!(app.launcher.query, q_before);
    }

    // ===============================================================
    // Task 20: help overlay (F1 only) + consolidated status.
    // ===============================================================

    #[test]
    fn f1_in_launcher_opens_help_overlay_then_esc_closes_it() {
        let mut app = app_with_host("web");
        // F1 opens the Help overlay; both the outcome and the stashed overlay agree.
        let outcome = app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::OpenOverlay(Overlay::Help)));
        assert!(matches!(app.overlay(), Some(Overlay::Help)));
        // Esc closes it and clears the overlay.
        let after = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(after, Outcome::CloseOverlay));
        assert!(app.overlay().is_none());
    }

    #[test]
    fn question_mark_in_wizard_text_field_inserts_char_not_help() {
        // Regression: `?` is a printable char in a wizard text field. It must
        // fall through to the wizard's on_key and be appended to the focused
        // field — NOT open the help overlay. (`?` no longer opens Help
        // anywhere; this still pins the wizard insertion path.)
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL)); // -> HostWizard overlay
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host wizard overlay open"
        );
        // Name field is focused by default; type "a?b".
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::NONE));
        app.on_key(press(KeyCode::Char('?'), KeyModifiers::NONE));
        app.on_key(press(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "? must not switch the overlay away from HostWizard"
        );
        let form = app
            .wizard()
            .expect("invariant: wizard is open in HostWizard overlay");
        assert_eq!(form.name, "a?b", "? must be inserted into the text field");
    }

    #[test]
    fn f1_opens_help_from_inside_wizard_then_esc_closes_overlay() {
        // Help is reachable mid-wizard (you should not have to back out to read
        // a binding). In the new single-overlay model F1 REPLACES the
        // HostWizard overlay with Help; Esc closes Help, leaving no overlay
        // (back at the launcher, not the wizard — there is no overlay stacking).
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL)); // -> HostWizard overlay
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host wizard overlay open"
        );
        let outcome = app.on_key(press(KeyCode::F(1), KeyModifiers::NONE)); // -> Help
        assert!(matches!(outcome, Outcome::OpenOverlay(Overlay::Help)));
        assert!(matches!(app.overlay(), Some(Overlay::Help)));
        // Esc dismisses the Help overlay.
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::CloseOverlay));
        assert!(app.overlay().is_none(), "Esc closed the help overlay");
    }

    #[test]
    fn help_dismiss_keys_are_f1_esc_and_q() {
        for key in [
            press(KeyCode::F(1), KeyModifiers::NONE),
            press(KeyCode::Esc, KeyModifiers::NONE),
            press(KeyCode::Char('q'), KeyModifiers::NONE),
        ] {
            let mut app = app_with_host("web");
            app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
            assert!(matches!(app.overlay(), Some(Overlay::Help)));
            let outcome = app.on_key(key);
            assert!(
                matches!(outcome, Outcome::CloseOverlay),
                "dismiss key must close the help overlay"
            );
            assert!(app.overlay().is_none(), "overlay cleared after dismiss");
        }
    }

    #[test]
    fn f1_inside_help_dismisses_does_not_stack() {
        // A second F1 toggles Help off rather than nesting a second overlay.
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(matches!(app.overlay(), Some(Overlay::Help)));
        let outcome = app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::CloseOverlay));
        assert!(app.overlay().is_none());
    }

    #[test]
    fn help_other_keys_continue_without_dismissing() {
        // Random keys inside the help overlay must NOT dismiss or change it.
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        let outcome = app.on_key(press(KeyCode::Char('x'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(
            matches!(app.overlay(), Some(Overlay::Help)),
            "x must not dismiss help"
        );
    }

    #[test]
    fn help_release_events_are_ignored() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::F(1), KeyModifiers::NONE));
        let release =
            KeyEvent::new_with_kind(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release);
        app.on_key(release);
        assert!(
            matches!(app.overlay(), Some(Overlay::Help)),
            "release must not dismiss help"
        );
    }

    #[test]
    fn set_status_and_set_status_error_round_trip() {
        let mut app = app_with_host("web");
        assert!(app.status().message.is_none());
        app.set_status("host saved".to_string());
        assert_eq!(app.status().message.as_deref(), Some("host saved"));
        assert!(!app.status().is_error);
        app.set_status_error("connect failed: timeout".to_string());
        assert_eq!(
            app.status().message.as_deref(),
            Some("connect failed: timeout")
        );
        assert!(app.status().is_error);
    }

    // ===============================================================
    // Critical #1 regression: the popup borrow path must not collide with
    // run_loop's draw borrow. The panic scenario (final-review Critical #1)
    // was: run_loop held a long-lived RefMut across the whole iteration, and
    // a popup upgraded the weak handle and called borrow_mut() AGAIN →
    // "already borrowed" panic. The fix narrows the draw borrow to a single
    // block so the RefMut is released before any popup runs. These tests pin
    // both that (a) the fixed narrow-borrow-then-popup pattern does NOT panic,
    // and (b) the old wide-borrow pattern DID panic — proving the test would
    // catch a regression that re-introduced a long-lived RefMut across run_loop.
    // ===============================================================

    use std::rc::Rc;

    use super::super::prompt::TuiPassphrase;

    #[test]
    fn popup_borrow_after_narrow_draw_borrow_does_not_panic() {
        // Mirror run_loop's fixed pattern exactly: borrow_mut in a block for
        // the draw (released at block end), THEN upgrade the weak handle and
        // borrow_mut again inside the popup path. Under the bug, an outer
        // long-lived RefMut across the whole iteration made the popup's
        // borrow_mut panic; under the fix the popup borrow is the only live
        // borrow and succeeds.
        //
        // We cannot drive `event::read` here (no key is piped in a unit test),
        // so we stop just short of the popup's blocking read: we prove the
        // RefCell does not reject the popup's borrow_mut, which is the exact
        // failure mode the bug caused. `TuiPassphrase::confirm` borrows in its
        // own draw loop before reading; we replicate that single borrow.
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        let provider = TuiPassphrase::new(handle.clone());

        // run_loop's draw borrow: scoped, released before the side effect.
        {
            let _t = rc.borrow_mut();
            // (draw would run here; the borrow scope is what matters.)
        }
        // Popup path: upgrade the SAME live handle and borrow_mut. Under the
        // bug this panicked; under the fix it is the only live borrow.
        let upgraded = handle.upgrade().expect("live strong ref");
        let _popup_borrow = upgraded.borrow_mut();
        // `provider` carries the same live handle the popup layer would use;
        // its existence with a live strong ref proves the upgrade path resolves
        // (the bug dead-locked here with a RefMut panic).
        let _ = &provider;
    }

    #[test]
    #[should_panic(expected = "already borrowed")]
    fn wide_outer_borrow_then_popup_borrow_panics_regression_pin() {
        // Inverse pin: the OLD pattern (a long-lived outer RefMut across the
        // whole iteration, which is what `with_terminal(|t| run_loop(t, ...))`
        // produced) DOES panic when a popup borrow_mut runs inside it. This
        // test asserts that panic so a future refactor that re-introduces a
        // wide outer borrow across run_loop is caught by tests immediately,
        // not only at runtime against a real host.
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Simulate the OLD buggy pattern: outer RefMut held across the popup.
        let _outer = rc.borrow_mut();
        let upgraded = handle.upgrade().expect("live strong ref");
        // This borrow_mut panics because `_outer` is still live — exactly the
        // "already borrowed" the user saw on every popup before the fix.
        let _ = upgraded.borrow_mut();
    }

    // ---- Credentials panel routing (Task 7) ----
    // These drive App::on_key directly to pin the new panel routing: tab
    // switching to Credentials, Ctrl-A/E/D/Enter, query/arrows, and the
    // delete-confirm → persist_cred_delete round-trip. No terminal is touched.
    // (`Credential` and `CredentialBody` are already in scope from the earlier
    // `use` statements at the top of `mod tests`.)

    #[test]
    fn ctrl_2_switches_to_credentials_tab() {
        let mut app = app_with_credential("ops", "deploy");
        assert_eq!(app.active_tab(), Tab::Hosts);
        let outcome = app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::SwitchTab(Tab::Credentials)));
        assert_eq!(app.active_tab(), Tab::Credentials);
    }

    #[test]
    fn credentials_printable_enters_query_not_hotkey() {
        // On the Credentials tab a plain char enters the panel query (no
        // single-char hotkeys).
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // switch
        let outcome = app.on_key(press(KeyCode::Char('o'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(app.cred_panel().query, "o");
    }

    #[test]
    fn credentials_ctrl_a_opens_cred_wizard_add() {
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::CredWizard(_))
        ));
        let w = app.cred_wizard().expect("cred wizard open");
        assert!(!w.editing, "add mode must be non-editing");
        assert!(w.name.is_empty(), "add form must start blank");
    }

    #[test]
    fn credentials_ctrl_e_opens_cred_wizard_edit_prefilled() {
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::CredWizard(_))
        ));
        let w = app.cred_wizard().expect("cred wizard open");
        assert!(w.editing, "edit mode must be editing");
        assert_eq!(w.name, "ops", "edit form must be prefilled with the name");
        assert_eq!(w.user, "deploy");
    }

    #[test]
    fn credentials_enter_opens_cred_wizard_edit() {
        // Enter on the Credentials tab = edit the selected credential (primary
        // action). Same outcome as Ctrl-E here.
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::CredWizard(_))
        ));
        let w = app.cred_wizard().expect("cred wizard open");
        assert!(w.editing);
        assert_eq!(w.name, "ops");
    }

    #[test]
    fn credentials_ctrl_e_with_no_selection_sets_status() {
        // No credentials → no selection → status hint, no overlay.
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(app.overlay().is_none());
        assert_eq!(
            app.status().message.as_deref(),
            Some("no credential selected to edit")
        );
    }

    #[test]
    fn credentials_ctrl_d_sets_pending_delete_cred_and_emits_delete_cred() {
        // Ctrl-D on a credential captures its name and returns the DeleteCred
        // intent (pure; the loop drives the confirm popup). The captured name
        // is the credential under the cursor.
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::DeleteCred));
        assert_eq!(app.pending_delete_cred(), Some("ops"));
    }

    #[test]
    fn credentials_ctrl_d_with_no_selection_sets_status() {
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        let outcome = app.on_key(press(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(app.pending_delete_cred().is_none());
        assert_eq!(
            app.status().message.as_deref(),
            Some("no credential selected to delete")
        );
    }

    #[test]
    fn credentials_esc_clears_query_then_second_esc_is_handled() {
        // On the Credentials tab: typing then Esc clears the query (Continue);
        // the second Esc (empty query) signals Quit at the App layer.
        let mut app = app_with_credential("ops", "deploy");
        app.on_key(press(KeyCode::Char('2'), KeyModifiers::CONTROL)); // → Credentials
        app.on_key(press(KeyCode::Char('o'), KeyModifiers::NONE));
        assert_eq!(app.cred_panel().query, "o");
        let first = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(first, Outcome::Continue));
        assert!(app.cred_panel().query.is_empty());
        let second = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(second, Outcome::Quit));
    }

    // ---- Settings panel routing (Task 8) ----
    // Drive App::on_key directly to pin: Ctrl-3 lands on Settings, Enter opens
    // the StorePicker overlay (and stashes a store_view), arrow keys are no-ops,
    // and Esc inside the picker returns Cancel + clears the overlay.

    #[test]
    fn ctrl_3_switches_to_settings_tab() {
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('3'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::SwitchTab(Tab::Settings)));
        assert_eq!(app.active_tab(), Tab::Settings);
    }

    #[test]
    fn settings_enter_opens_store_picker_overlay() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('3'), KeyModifiers::CONTROL)); // -> Settings
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            outcome,
            Outcome::OpenOverlay(Overlay::StorePicker)
        ));
        assert!(
            matches!(app.overlay(), Some(Overlay::StorePicker)),
            "StorePicker overlay should be open"
        );
        // open_store_picker stashes a view so draw_overlay + route_overlay can
        // drive it across keystrokes.
        assert!(
            app.store_view.is_some(),
            "store_view must be stashed while the picker is open"
        );
    }

    #[test]
    fn settings_arrows_are_noops() {
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('3'), KeyModifiers::CONTROL)); // -> Settings
        let outcome = app.on_key(press(KeyCode::Down, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        // No overlay opened.
        assert!(app.overlay().is_none());
    }

    #[test]
    fn store_picker_esc_returns_cancel_and_drops_overlay() {
        // Open the picker, then Esc: store_view::on_key signals Cancel, which
        // is terminal for the overlay → route_overlay drops it. The loop's
        // Cancel arm clears the overlay + re-renders; here we pin the pure half
        // (the outcome + the overlay state after on_key).
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('3'), KeyModifiers::CONTROL)); // -> Settings
        app.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open picker
        assert!(matches!(app.overlay(), Some(Overlay::StorePicker)));
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(
            matches!(outcome, Outcome::Cancel),
            "Esc in the picker must signal Cancel"
        );
        assert!(
            app.overlay().is_none(),
            "Cancel must drop the StorePicker overlay"
        );
    }

    #[test]
    fn store_picker_down_then_enter_signals_switch_to_vault() {
        // Cursor starts on keyring (index 0); Down → vault; Enter signals
        // SwitchToVault. The loop's SwitchToVault arm runs the I/O; here we pin
        // the pure routing through the stashed store_view.
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('3'), KeyModifiers::CONTROL)); // -> Settings
        app.on_key(press(KeyCode::Enter, KeyModifiers::NONE)); // open picker
        app.on_key(press(KeyCode::Down, KeyModifiers::NONE)); // -> vault
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::SwitchToVault));
    }

    #[test]
    fn current_store_mode_label_reflects_configured_mode() {
        // Sanity: the label the settings panel renders comes from the config's
        // store field. Undecided → "undecided".
        let mut app = app_with_host("web");
        assert_eq!(app.current_store_mode_label(), "undecided");

        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        app.set_config(cfg);
        assert_eq!(app.current_store_mode_label(), "plaintext");
    }

    #[test]
    fn host_add_entry_lands_on_hosts_tab_with_overlay() {
        let mut app = app_with_host("web");
        app.apply_entry_mode(super::super::EntryMode::HostWizard { edit_name: None });
        assert_eq!(app.active_tab(), super::super::tab::Tab::Hosts);
        assert!(
            matches!(app.overlay(), Some(Overlay::HostWizard(_))),
            "host add entry should open the HostWizard overlay"
        );
    }

    #[test]
    fn host_edit_entry_lands_on_hosts_tab_with_edit_overlay_and_selection() {
        let mut app = app_with_host("web");
        app.apply_entry_mode(super::super::EntryMode::HostWizard {
            edit_name: Some("web".into()),
        });
        assert_eq!(app.active_tab(), super::super::tab::Tab::Hosts);
        // Selection landed on the named host (assert before borrowing overlay).
        assert_eq!(app.launcher.selected, 0);
        // Edit overlay is a HostWizard in edit mode (form.editing == true).
        let Some(Overlay::HostWizard(form)) = app.overlay() else {
            panic!("host edit entry should open the HostWizard overlay");
        };
        assert!(
            form.editing,
            "edit entry should prefill the form in edit mode"
        );
    }

    #[test]
    fn host_edit_entry_missing_name_lands_on_hosts_tab_no_overlay_with_status() {
        let mut app = app_with_host("web");
        app.apply_entry_mode(super::super::EntryMode::HostWizard {
            edit_name: Some("ghost".into()),
        });
        assert_eq!(app.active_tab(), super::super::tab::Tab::Hosts);
        assert!(
            app.overlay().is_none(),
            "missing edit target should not open an overlay"
        );
        assert!(
            app.status().is_error,
            "missing target should set an error status"
        );
    }

    #[test]
    fn cred_add_entry_lands_on_credentials_tab_with_overlay() {
        let mut app = app_with_named_cred("ops");
        app.apply_entry_mode(super::super::EntryMode::CredWizard { edit_name: None });
        assert_eq!(
            app.active_tab(),
            super::super::tab::Tab::Credentials,
            "`cred add` must land on the Credentials tab"
        );
        assert!(
            matches!(app.overlay(), Some(Overlay::CredWizard(_))),
            "cred add entry should open the CredWizard overlay"
        );
    }

    #[test]
    fn cred_edit_entry_lands_on_credentials_tab_with_edit_overlay_and_selection() {
        let mut app = app_with_named_cred("ops");
        app.apply_entry_mode(super::super::EntryMode::CredWizard {
            edit_name: Some("ops".into()),
        });
        assert_eq!(app.active_tab(), super::super::tab::Tab::Credentials);
        // Selection landed on the named credential (assert before borrowing
        // overlay — both are shared borrows of `app`, but cred_panel() is
        // &mut, so do it while no &ref is alive).
        assert_eq!(app.cred_panel().selected, 0);
        let Some(Overlay::CredWizard(form)) = app.overlay() else {
            panic!("cred edit entry should open the CredWizard overlay");
        };
        assert!(
            form.editing,
            "cred edit entry should prefill the form in edit mode"
        );
    }

    #[test]
    fn cred_edit_entry_missing_name_lands_on_credentials_tab_no_overlay_with_status() {
        let mut app = app_with_named_cred("ops");
        app.apply_entry_mode(super::super::EntryMode::CredWizard {
            edit_name: Some("ghost".into()),
        });
        assert_eq!(app.active_tab(), super::super::tab::Tab::Credentials);
        assert!(
            app.overlay().is_none(),
            "missing edit target should not open an overlay"
        );
        assert!(
            app.status().is_error,
            "missing target should set an error status"
        );
    }

    #[test]
    fn bare_entry_lands_on_hosts_tab_no_overlay() {
        let mut app = app_with_host("web");
        app.apply_entry_mode(super::super::EntryMode::Launcher);
        assert_eq!(app.active_tab(), super::super::tab::Tab::Hosts);
        assert!(app.overlay().is_none(), "bare entry should open no overlay");
    }
}
