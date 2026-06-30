//! TUI application state, key handling, terminal guard, and event loop.
//!
//! The loop is the only place with side effects. [`App::on_key`] is pure (no
//! I/O): it inspects a [`KeyEvent`] and returns an [`Outcome`] describing what
//! the loop should do next. This keeps key logic unit-testable without a
//! terminal or event source.
//!
//! [`TerminalGuard`] is RAII: it enters raw mode + the alternate screen on
//! construction and restores the terminal in [`Drop`]. Because `Drop` always
//! runs, the terminal is restored even when the loop returns early (e.g. on a
//! connect request that later errors in `main`).

use std::cell::RefCell;
use std::io::{self, Stdout};
use std::rc::{Rc, Weak};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend};
use sshrack_core::config::schema::SshrackConfig;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency::Frecency;
use std::path::PathBuf;
use ulid::Ulid;

use super::ConnectRequest;
use super::CredentialNames;
use super::connect::connect_host;
use super::launcher::Launcher;
use super::prompt::TuiPassphrase;
use super::wizard::{CredForm, HostForm};

/// ratatui backend bound to stdout via crossterm.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Weak, interior-mutable handle to the terminal. The [`TerminalGuard`] owns
/// the only strong reference (`Rc<RefCell<Tui>>`) while the TUI is running; it
/// hands out a weak clone ([`TerminalHandle`]) to the prompt layer so a `&self`
/// [`sshrack_core::secret::PassphraseProvider`] impl can borrow the terminal
/// `&mut` to render a popup. The weak handle goes dead when the guard drops, so
/// a stray reference (e.g. a `TuiPassphrase` or host-key closure that outlives
/// `tui::run`) can never keep the `Tui` alive past the terminal restore.
/// Callers [`Weak::upgrade`] at use time; `None` means the guard is gone and the
/// operation is treated as a silent cancellation.
pub type TerminalHandle = Weak<RefCell<Tui>>;

/// RAII terminal guard. On construction it enables raw mode and enters the
/// alternate screen; on drop it leaves the alternate screen and disables raw
/// mode. The guard owns the [`Tui`] behind an [`Rc<RefCell<…>>`] so both the
/// event loop (via [`with_terminal`]) and the prompt layer (which receives a
/// [`TerminalHandle`] via [`handle`](Self::handle)) can borrow it. The terminal
/// lives exactly as long as raw mode is on.
///
/// Drop swallows restore errors: there is no meaningful recovery at drop time,
/// and a partially-restored terminal is strictly worse than a best-effort one.
/// The user can `reset` if ever needed.
///
/// [`with_terminal`]: TerminalGuard::with_terminal
pub struct TerminalGuard {
    terminal: Rc<RefCell<Tui>>,
}

impl TerminalGuard {
    /// Enter raw mode + alternate screen and return a terminal backed by
    /// stdout. On any setup failure the half-applied state is rolled back
    /// (raw mode disabled) before propagating the error.
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        // If entering the alternate screen fails, undo raw mode so the user's
        // terminal isn't left in raw mode without a guard to restore it.
        if let Err(e) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(e);
        }
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(Self {
            terminal: Rc::new(RefCell::new(terminal)),
        })
    }

    /// Borrow the terminal `&mut` for the duration of this call. Panics only
    /// if the terminal is already borrowed — which cannot happen on the event
    /// loop's single-threaded, non-reentrant path.
    pub fn with_terminal<R>(&self, f: impl FnOnce(&mut Tui) -> R) -> R {
        f(&mut self.terminal.borrow_mut())
    }

    /// A weak handle the prompt layer can store inside a `&self`
    /// [`sshrack_core::secret::PassphraseProvider`] impl. [`Weak::upgrade`]
    /// returns `Some` only while this guard is alive; once the guard drops, the
    /// handle goes dead and consumers treat the `None` as a silent
    /// cancellation ([`SshrackError::Interrupted`]).
    #[allow(dead_code)]
    pub fn handle(&self) -> TerminalHandle {
        Rc::downgrade(&self.terminal)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore. Drop has no error channel; ignore failures.
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

/// The pure result of handling one key. Side effects happen in the loop, not
/// in [`App::on_key`], so key logic stays unit-testable without a terminal.
///
/// Later tasks grow this enum (EditHost, AddHost, AddCred, RemoveHost, ...).
pub enum Outcome {
    /// User asked to quit; the loop returns `None` (no connect).
    Quit,
    /// Nothing of interest happened; keep rendering and reading events.
    Continue,
    /// Pure intent: the user pressed Enter on a host. `on_key` sets the
    /// launcher's `pending_connect` field to the host's id and returns this.
    /// The event loop reads the id, runs the I/O-heavy connect orchestration
    /// ([`crate::tui::connect_host`]), and either returns the resulting
    /// [`ConnectRequest`] to `main` or — on user cancel — returns to the
    /// launcher. This variant carries no data because the id lives on the
    /// launcher (single source of truth, clearable on cancel).
    ConnectRequested,
    /// Pure intent: the host wizard wants to persist its form. The wizard's
    /// `on_key` validated the fields already; the loop resolves the credential
    /// name→id, builds a [`Host`], calls [`host::add_host`]/applies the patch,
    /// persists the config, reloads hosts, and returns to the launcher. The
    /// intent carries no data because the form lives on the wizard (single
    /// source of truth, clearable on cancel).
    ///
    /// [`host::add_host`]: sshrack_core::host::add_host
    SaveHost,
    /// Pure intent: the credential wizard wants to persist its form. The
    /// wizard's `on_key` validated the fields already; the loop builds a
    /// [`sshrack_core::config::schema::CredentialBody`], seals any password
    /// per the configured store mode (keyring / vault / plaintext) via core's
    /// [`sshrack_core::secret::vault::seal_body`], calls
    /// `credential::add_credential` (add) or splices in place preserving the
    /// original id (edit), persists the config, reloads, and returns to the
    /// launcher.
    SaveCred,
    /// Pure intent: the user pressed Esc / Ctrl-C inside the wizard. The loop
    /// discards the wizard and returns to the launcher.
    Cancel,
}

/// Which view the TUI is showing. The launcher is the default; the host wizard
/// is entered via `^a` (add) / `^e` (edit), and the credential wizard via `c`
/// (add) / the in-TUI edit key, or directly via entry routing when the user
/// runs `sshrack cred add|edit`. Keeping this on [`App`] (not the launcher)
/// means the launcher's own state machine never has to know about non-launcher
/// keys — routing happens here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The host launcher (query + ranked list + connect).
    Launcher,
    /// The host add/edit wizard.
    HostWizard,
    /// The credential add/edit wizard.
    CredWizard,
}

/// TUI application state. The launcher is the primary mode; the host wizard is
/// the secondary. Later tasks grow [`Mode`] with store/help views.
///
/// `App` owns the data (config, hosts, frecency, credential-name lookup)
/// loaded once at startup from core, and the on-disk config path so the wizard
/// save path can persist + reload without re-resolving. The [`Launcher`] /
/// [`HostForm`] inside it own their respective view states. The config is kept
/// here (not just its derived slices) because connect orchestration needs the
/// credential table and vault meta, which live on the full [`SshrackConfig`].
pub struct App {
    /// Set by [`App::on_key`] when the user presses a quit binding. The loop
    /// checks this as a secondary exit (the primary exit is [`Outcome::Quit`]).
    pub should_quit: bool,
    /// The full config, loaded from core. Owned here so connect orchestration
    /// can resolve auth, unlock the vault, and look up hosts by id. The host
    /// list and credential table are borrowed out of this via `&self.config`.
    config: SshrackConfig,
    /// The on-disk path the config was loaded from. `None` when no path was
    /// resolved (e.g. a fresh install with no home dir); the wizard save path
    /// treats that as best-effort (build the new config but skip the persist).
    config_path: Option<PathBuf>,
    /// Machine-local frecency table, loaded from core's data dir.
    frecency: Frecency,
    /// Reverse lookup from a credential ULID to its display name, so the
    /// launcher can show `Auth::Ref` targets by name without re-scanning.
    credential_names: CredentialNames,
    /// The interactive launcher (query + selection + ranked list).
    launcher: Launcher,
    /// The active view. Routes `on_key`/`draw` to the launcher or the wizard.
    mode: Mode,
    /// The host wizard, present only when [`Mode::HostWizard`] is active. Kept
    /// on `App` (not created on demand each frame) so its state survives across
    /// keystrokes.
    wizard: Option<HostForm>,
    /// The credential wizard, present only when [`Mode::CredWizard`] is active.
    cred_wizard: Option<CredForm>,
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
        Self {
            should_quit: false,
            config,
            config_path,
            frecency,
            credential_names,
            launcher,
            mode: Mode::Launcher,
            wizard: None,
            cred_wizard: None,
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

    /// Borrow the launcher mutably. Exposed for tests that drive the launcher
    /// state machine directly and for the loop's `pending_connect` read.
    #[allow(dead_code)]
    pub fn launcher(&mut self) -> &mut Launcher {
        &mut self.launcher
    }

    /// The current view mode. Exposed for tests asserting mode routing.
    #[allow(dead_code)]
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// Borrow the active host wizard, if any. The loop uses this to read the
    /// form fields when fulfilling a [`Outcome::SaveHost`] intent.
    #[allow(dead_code)]
    pub fn wizard(&self) -> Option<&HostForm> {
        self.wizard.as_ref()
    }

    /// Open the host wizard in add mode with a blank form. Discards any wizard
    /// already open (there should be none when the launcher is showing).
    pub fn open_host_wizard_add(&mut self) {
        let names: Vec<String> = self
            .config
            .credentials
            .iter()
            .map(|c| c.name.clone())
            .collect();
        self.wizard = Some(HostForm::new_add(names));
        self.mode = Mode::HostWizard;
    }

    /// Open the host wizard in edit mode, prefilled from the host with the
    /// given id. No-op (returns false) when the id is not in the config. When
    /// the host's auth is a credential reference, the referenced credential's
    /// current name is resolved from the config so the chooser can prefill the
    /// correct index (the wizard works in names; it cannot map id→name alone).
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
        self.wizard = Some(HostForm::new_edit(
            &host,
            names,
            referenced_credential_name.as_deref(),
        ));
        self.mode = Mode::HostWizard;
        true
    }

    /// Leave the wizard and return to the launcher, reloading the host ranking
    /// so a freshly added/edited host shows up. Used by the loop after a save
    /// or a cancel.
    pub fn close_host_wizard(&mut self) {
        self.wizard = None;
        self.mode = Mode::Launcher;
        // Re-rank so the launcher reflects the (possibly) updated host list.
        self.launcher.recompute(&self.config.hosts, &self.frecency);
    }

    /// Open the credential wizard in add mode with a blank form. Discards any
    /// cred wizard already open.
    pub fn open_cred_wizard_add(&mut self) {
        self.cred_wizard = Some(CredForm::new_add());
        self.mode = Mode::CredWizard;
    }

    /// Open the credential wizard in edit mode, prefilled from the credential
    /// with the given name. No-op (returns false) when the name is not in the
    /// config.
    pub fn open_cred_wizard_edit(&mut self, name: &str) -> bool {
        let Some(cred) = self.config.find_credential_by_name(name).cloned() else {
            return false;
        };
        self.cred_wizard = Some(CredForm::new_edit(&cred));
        self.mode = Mode::CredWizard;
        true
    }

    /// Leave the cred wizard and return to the launcher. Used by the loop after
    /// a save or a cancel. The host ranking is unchanged (crediting does not
    /// move hosts), but re-running `recompute` is cheap and keeps the launcher
    /// in sync if a credential rename affected a host's display label.
    pub fn close_cred_wizard(&mut self) {
        self.cred_wizard = None;
        self.mode = Mode::Launcher;
        self.launcher.recompute(&self.config.hosts, &self.frecency);
    }

    /// Open the host wizard in edit mode, prefilled from the host named `name`.
    /// No-op (returns false) when the name is not in the config. Used by the
    /// entry-routing path (`host edit <name>` → TUI) where the host is
    /// identified by name, not by the launcher cursor.
    pub fn open_host_wizard_edit_by_name(&mut self, name: &str) -> bool {
        let Some(host) = self.config.find_host_by_name(name).cloned() else {
            return false;
        };
        // open_host_wizard_edit takes an id; resolve the name → id here.
        self.open_host_wizard_edit(host.id)
    }

    /// Apply the entry-routing decision (derived from `cli.cmd` in
    /// [`super::entry_mode_from_cmd`]) before the first frame. Called once from
    /// [`super::run`] after the config is loaded and before the alternate
    /// screen is entered. A missing edit target (name not in the config) falls
    /// back to the launcher rather than erroring — the user lands in the host
    /// list and can fix the typo, mirroring how the in-TUI edit path degrades.
    pub fn apply_entry_mode(&mut self, mode: super::EntryMode) {
        match mode {
            super::EntryMode::Launcher => {}
            super::EntryMode::HostWizard { edit_name: None } => self.open_host_wizard_add(),
            super::EntryMode::HostWizard {
                edit_name: Some(name),
            } => {
                if !self.open_host_wizard_edit_by_name(&name) {
                    self.launcher.status = Some(format!("host '{name}' not found"));
                }
            }
            super::EntryMode::CredWizard { edit_name: None } => self.open_cred_wizard_add(),
            super::EntryMode::CredWizard {
                edit_name: Some(name),
            } => {
                if !self.open_cred_wizard_edit(&name) {
                    self.launcher.status = Some(format!("credential '{name}' not found"));
                }
            }
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

    /// Pure: decide what should happen next for a given key. Performs **no**
    /// I/O — no reads, no writes, no terminal access — so it is safe to call
    /// from a unit test without an event source.
    ///
    /// Routes the key by [`Mode`]:
    /// - Launcher → the launcher's `on_key`. `^a`/`^e` open the wizard (pure:
    ///   they only flip mode + build the form, no persist). Quit sets
    ///   `should_quit`.
    /// - HostWizard → the wizard's `on_key`. `SaveHost`/`Cancel` are returned
    ///   to the loop, which does the persist + reload.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        match self.mode {
            Mode::Launcher => {
                // Intercept ^a / ^e before the launcher so they open the wizard
                // (the launcher used to set a "not yet implemented" status for
                // them; that is now handled by mode routing).
                if key.kind == crossterm::event::KeyEventKind::Press {
                    let ctrl = key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL);
                    if ctrl && key.code == crossterm::event::KeyCode::Char('a') {
                        self.open_host_wizard_add();
                        return Outcome::Continue;
                    }
                    if ctrl && key.code == crossterm::event::KeyCode::Char('e') {
                        // Edit uses the host currently under the launcher cursor.
                        if let Some(h) = self.launcher.selected_host(&self.config.hosts) {
                            let id = h.id;
                            self.open_host_wizard_edit(id);
                        } else {
                            self.launcher.status = Some("no host selected to edit".into());
                        }
                        return Outcome::Continue;
                    }
                    // `c` opens the credential add wizard; `C` (Shift-C) opens
                    // the credential edit wizard for the credential referenced
                    // by the host under the launcher cursor (intuitive entry:
                    // the host you are looking at uses that credential). A host
                    // without a credential reference sets a status hint.
                    if !ctrl
                        && key.code == crossterm::event::KeyCode::Char('c')
                        && key.modifiers.is_empty()
                    {
                        self.open_cred_wizard_add();
                        return Outcome::Continue;
                    }
                    if key.modifiers == crossterm::event::KeyModifiers::SHIFT
                        && key.code == crossterm::event::KeyCode::Char('C')
                    {
                        match self
                            .launcher
                            .selected_host(&self.config.hosts)
                            .and_then(|h| h.auth.credential_id())
                            .and_then(|id| {
                                self.config
                                    .find_credential_by_id(&id)
                                    .map(|c| c.name.clone())
                            }) {
                            Some(name) => {
                                self.open_cred_wizard_edit(&name);
                            }
                            None => {
                                self.launcher.status =
                                    Some("selected host has no credential to edit".into());
                            }
                        }
                        return Outcome::Continue;
                    }
                }
                let outcome = self
                    .launcher
                    .on_key(key, &self.config.hosts, &self.frecency);
                if matches!(outcome, Outcome::Quit) {
                    self.should_quit = true;
                }
                outcome
            }
            Mode::HostWizard => {
                let outcome = match self.wizard.as_mut() {
                    Some(w) => w.on_key(key),
                    None => Outcome::Continue,
                };
                // The loop also treats Cancel like a return-to-launcher.
                outcome
            }
            Mode::CredWizard => match self.cred_wizard.as_mut() {
                Some(w) => w.on_key(key),
                None => Outcome::Continue,
            },
        }
    }

    /// Render current state to the frame. Only writes to the frame (no stdout
    /// access of its own). Routes by [`Mode`] to the active view's render.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        match self.mode {
            Mode::Launcher => self.launcher.draw(
                frame,
                area,
                &self.config.hosts,
                &self.frecency,
                &self.credential_names,
            ),
            Mode::HostWizard => {
                if let Some(w) = &self.wizard {
                    w.draw(frame, area);
                }
            }
            Mode::CredWizard => {
                if let Some(w) = &self.cred_wizard {
                    w.draw(frame, area);
                }
            }
        }
    }
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
pub fn run_loop(
    terminal: &mut Tui,
    app: &mut App,
    handle: TerminalHandle,
    data_dir: Option<&std::path::Path>,
) -> Option<ConnectRequest> {
    loop {
        if terminal.draw(|f| app.draw(f)).is_err() {
            // A draw failure (e.g. suspended tty) is not fatal; try again next
            // tick. If the terminal is truly gone, poll/read will spin idle.
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
                            // launcher, NOT an exit.
                            app.launcher.status = Some("connect cancelled".into());
                        }
                        Err(e) => {
                            // A real error (vault unlock fail, host-key reject,
                            // dangling credential, frecency save fail). Surface
                            // it in the status line and return to the launcher
                            // so the user can read it.
                            app.launcher.status = Some(format!("connect failed: {e}"));
                        }
                    }
                }
                Outcome::SaveHost => {
                    // The wizard signaled save after its pure validate() passed.
                    // Persist: build the host, resolve the credential name→id,
                    // add or apply-patch, write config, reload, close the wizard.
                    match persist_host_save(app) {
                        Ok(()) => {
                            app.launcher.status = Some("host saved".into());
                            app.close_host_wizard();
                        }
                        Err(e) => {
                            // Persist failed (duplicate name, write error,
                            // dangling credential). Surface in the wizard's
                            // core-error line and stay in the wizard so the
                            // user can fix it.
                            if let Some(w) = app.wizard.as_mut() {
                                w.set_core_error(e.to_string());
                            }
                        }
                    }
                }
                Outcome::SaveCred => {
                    // The cred wizard signaled save after its pure validate()
                    // passed. Persist: build the body, seal any password per
                    // the configured store mode via core, add or splice-in-
                    // place preserving the original id, write config, reload,
                    // close the wizard.
                    match persist_cred_save(app, &handle) {
                        Ok(()) => {
                            app.launcher.status = Some("credential saved".into());
                            app.close_cred_wizard();
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a vault-unlock popup (Esc/Ctrl-C).
                            // Stay in the wizard; surface a status so they know
                            // why nothing was saved.
                            if let Some(w) = app.cred_wizard.as_mut() {
                                w.set_core_error("vault unlock cancelled".into());
                            }
                        }
                        Err(e) => {
                            // Persist failed (duplicate name, store mode
                            // undecided, write error). Surface in the wizard's
                            // core-error line and stay so the user can fix it.
                            if let Some(w) = app.cred_wizard.as_mut() {
                                w.set_core_error(e.to_string());
                            }
                        }
                    }
                }
                Outcome::Cancel => {
                    // Wizard Esc / Ctrl-C: discard the active wizard and return
                    // to the launcher. Which wizard to close depends on mode.
                    app.launcher.status = Some("cancelled".into());
                    match app.mode {
                        Mode::HostWizard => app.close_host_wizard(),
                        Mode::CredWizard => app.close_cred_wizard(),
                        _ => {}
                    }
                }
                Outcome::Continue => {}
            }
        }

        if app.should_quit {
            return None;
        }
    }
}

/// Fulfill a [`Outcome::SaveHost`] intent: resolve the form to a [`Host`],
/// persist via core, reload, and update the app's config. Pure validation
/// already passed inside the wizard; this is the I/O half — duplicate-name /
/// config-write failures surface as [`SshrackError`] so the loop can show them
/// in the wizard's error line.
///
/// Add mode: `host::add_host` with a fresh id. Edit mode: `host::apply_patch`
/// preserving the original id (so the keyring entry is not orphaned). For a
/// Credential auth choice, the referenced credential name is resolved to its
/// stable [`Ulid`] here (the wizard only ever holds the name).
fn persist_host_save(app: &mut App) -> Result<(), SshrackError> {
    // Take the form out of the app so we can borrow `app.config` for the
    // credential-name → id resolution without a borrow conflict. Put it back
    // (cleared of core_error) on the error paths so the loop's error handler
    // can still see it.
    let Some(form) = app.wizard.clone() else {
        return Ok(());
    };

    // Resolve credential name → id (only when the user picked Credential).
    let resolved_credential = match form.selected_credential_name() {
        Some(name) => Some(
            app.config
                .find_credential_by_name(name)
                .map(|c| c.id)
                .ok_or(SshrackError::CredentialNotFound {
                    name: name.to_string(),
                    hint: sshrack_core::error::DidYouMean::none(),
                })?,
        ),
        None => None,
    };

    let auth = form.build_auth(resolved_credential);
    let name = form.name.trim().to_string();
    let host_addr = form.host_addr.trim().to_string();
    let port = form.parsed_port();

    let new_cfg = if form.editing {
        // Edit: preserve the original id (keyring-keyed). The form already holds
        // every field, so stamp the original id onto the freshly built host and
        // splice it in place of the original. A rename to another host's name
        // is rejected by validate_rename (excluding the current name).
        let orig_id = form.orig_id.ok_or(SshrackError::MissingRequiredField {
            field: "orig_id (edit mode)",
        })?;
        let orig = app
            .config
            .find_host_by_id(&orig_id)
            .ok_or(SshrackError::HostNotFound {
                name: orig_id.to_string(),
                hint: sshrack_core::error::DidYouMean::none(),
            })?;
        if orig.name != name {
            sshrack_core::host::validate_rename(&app.config, &orig.name, &name)?;
        }
        let edited = sshrack_core::host::finalize_body(orig_id, &name, &host_addr, port, auth);
        let mut next = app.config.clone();
        if let Some(slot) = next.hosts.iter_mut().find(|h| h.id == orig_id) {
            *slot = edited;
        }
        next
    } else {
        // Add: fresh id, append. host::add_host validates the name chars and
        // appends. The duplicate-name check is host::validate_no_duplicate; we
        // run it here so the error surfaces before the append (add_host itself
        // only checks forbidden chars).
        sshrack_core::host::validate_no_duplicate(&app.config, &name, false)?;
        sshrack_core::host::add_host(&app.config, Ulid::new(), &name, &host_addr, port, auth)?
    };

    // Persist + reload (so the on-disk file is the source of truth and the
    // in-memory config round-trips through TOML).
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        // No path resolved (fresh install, no home dir): keep the new config in
        // memory only. The launcher will still show the host this session.
        app.set_config(new_cfg);
    }
    Ok(())
}

/// Fulfill a [`Outcome::SaveCred`] intent: build the credential body, seal any
/// password per the configured store mode via core
/// ([`sshrack_core::secret::vault::seal_body`]), add (fresh id) or splice in
/// place (preserving the original id — keyring-keyed), persist, reload. Pure
/// validation already passed inside the wizard; this is the I/O half.
///
/// **Store-mode-undecided guard.** When the user picked a Password but
/// `cfg.store` is `None` (no mode chosen yet), the wizard surfaces a clear
/// "run `sshrack store use <mode>` first" error instead of silently picking a
/// mode. Core's `seal_body` treats `None` as plaintext, which would store the
/// password in the clear without the user ever choosing that — the wizard
/// refuses to make that choice for them. Vault unlock happens here via
/// [`TuiPassphrase`] (mirroring [`connect_host`]); a popup cancel surfaces as
/// [`SshrackError::Interrupted`], which the loop maps to "stay in the wizard".
///
/// [`connect_host`]: super::connect::connect_host
fn persist_cred_save(app: &mut App, handle: &TerminalHandle) -> Result<(), SshrackError> {
    // Take the form out so we can borrow app.config/launcher without a conflict.
    let Some(form) = app.cred_wizard.clone() else {
        return Ok(());
    };

    use sshrack_core::config::schema::Credential;
    use sshrack_core::credential as cred_core;
    use sshrack_core::id::OwnerKind;
    use sshrack_core::secret::{OsKeyring, vault};

    let name = form.name.trim().to_string();

    // ── Decide the id and the pre-seal body. ────────────────────────────────
    // Edit mode preserves the original id (the keyring entry + every host
    // Auth::Ref are keyed by it). When the edit leaves the password field
    // blank under the Password choice, keep the existing body's password so a
    // user editing only the user/name does not silently drop the password.
    let (id, mut body) = if form.editing {
        let orig_id = form.orig_id.ok_or(SshrackError::MissingRequiredField {
            field: "orig_id (cred edit mode)",
        })?;
        let orig = app
            .config
            .find_credential_by_id(&orig_id)
            .ok_or_else(|| cred_core::credential_not_found(&app.config, &orig_id.to_string()))?;
        let mut body = form.build_body();
        if form.secret_kind == super::wizard::SecretChoice::Password
            && form.password.is_empty()
            && body.password.is_none()
        {
            // Preserve the existing password: re-attach it as plaintext (it is
            // re-sealed below per the current store mode, so an encrypted body
            // round-trips through encrypt again cleanly).
            body.password = orig.body.password.clone();
        }
        if orig.name != name {
            cred_core::validate_rename_credential(&app.config, &orig.name, &name)?;
        }
        (orig_id, body)
    } else {
        // Add: fresh id. Duplicate-name check runs before the append.
        cred_core::validate_no_duplicate_credential(&app.config, &name, false)?;
        (Ulid::new(), form.build_body())
    };

    // ── Seal the password per the configured store mode. ────────────────────
    // Only seal when there is a freshly collected plaintext password to re-host
    // (a key / none body passes through unchanged). And only when a store mode
    // is decided; a Password choice with no mode decided is a user-facing
    // error, NOT a silent plaintext fallback.
    let has_plaintext_password = matches!(
        body.password,
        Some(sshrack_core::config::schema::Secret::Plain(_))
    );
    if has_plaintext_password {
        if app.config.store.is_none() {
            return Err(SshrackError::StoreModeNotDecided);
        }
        // Vault unlock (no-op unless vault mode). TuiPassphrase drives a masked
        // popup; under SSHRACK_PASSPHRASE the env value shadows it. A popup
        // cancel surfaces as Interrupted, which the loop maps to "stay in the
        // wizard" rather than an exit.
        let passphrase_provider = TuiPassphrase::new(handle.clone());
        let env_pw = vault::passphrase_from_env();
        let vault_key =
            vault::ensure_unlocked_vault_key(&app.config, env_pw.as_ref(), &passphrase_provider)?;
        let backend = OsKeyring;
        body = vault::seal_body(
            body,
            OwnerKind::Credential,
            &id,
            &app.config,
            vault_key.as_ref(),
            &backend,
        )?;
    }

    // ── Build the credential and splice / append. ───────────────────────────
    let credential = Credential {
        id,
        name: name.clone(),
        body,
    };
    let new_cfg = if form.editing {
        let mut next = app.config.clone();
        if let Some(slot) = next.credentials.iter_mut().find(|c| c.id == id) {
            *slot = credential;
        }
        next
    } else {
        // add_credential validates name chars + body and appends.
        cred_core::add_credential(&app.config, id, &name, credential.body)?
    };

    // Persist + reload (the on-disk file is the source of truth).
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        app.set_config(new_cfg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Purity tests for `App::on_key`. The contract: `on_key` takes a key and
    //! returns an outcome with **no I/O**. These tests call it directly (no
    //! terminal, no event source) to pin both the behavior and the purity.

    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use std::collections::HashMap;
    use ulid::Ulid;

    /// A one-host app with no frecency and no named credentials. Enough to
    /// drive the launcher's quit/navigation branches without a config file.
    fn app_with_host(name: &str) -> App {
        let host = Host {
            id: Ulid::new(),
            name: name.into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        };
        let cfg = SshrackConfig {
            hosts: vec![host],
            ..SshrackConfig::default()
        };
        App::new(cfg, None, Frecency::default(), HashMap::new())
    }

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        // crossterm distinguishes Press/Release/Repeat; the app only acts on
        // Press, so tests construct Press keys to exercise the binding.
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

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
        // (Terminal paste, e.g. Ctrl-Shift-C, must not accidentally quit.)
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
    }

    #[test]
    fn plain_c_without_ctrl_is_continue() {
        // 'c' without Ctrl is now the credential-add-wizard entry key (it used
        // to be a query character; the in-TUI cred entry now shadows that). The
        // original invariant — plain 'c' is not a quit — still holds, and the
        // query is NOT advanced. The wizard-open behavior is pinned by
        // `launcher_c_key_opens_cred_add_wizard`.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
        assert!(
            app.launcher.query.is_empty(),
            "plain 'c' must not enter the query"
        );
        assert_eq!(
            *app.mode(),
            Mode::CredWizard,
            "plain 'c' opens the cred wizard"
        );
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
        // Task 16: ^a now opens the host wizard in add mode (blank form),
        // routing the app from Launcher to HostWizard mode.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
        assert_eq!(*app.mode(), Mode::HostWizard);
        assert!(app.wizard().is_some(), "^a should open the wizard");
        let w = app.wizard().unwrap();
        assert!(!w.editing, "add mode must be non-editing");
        assert!(w.name.is_empty(), "add form must start blank");
    }

    #[test]
    fn ctrl_e_opens_edit_host_wizard_prefilled() {
        // Task 16: ^e on the selected host opens the wizard in edit mode,
        // prefilled from that host.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(*app.mode(), Mode::HostWizard);
        let w = app.wizard().expect("wizard open");
        assert!(w.editing, "edit mode must be editing");
        assert_eq!(w.name, "web", "edit form must be prefilled");
    }

    #[test]
    fn ctrl_e_with_no_host_sets_status_and_stays_in_launcher() {
        // ^e with an empty host list cannot pick a host to edit.
        let cfg = SshrackConfig::default();
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        let outcome = app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(*app.mode(), Mode::Launcher);
        assert_eq!(
            app.launcher.status.as_deref(),
            Some("no host selected to edit")
        );
    }

    #[test]
    fn wizard_esc_closes_back_to_launcher() {
        // Esc inside the wizard signals Cancel; the loop closes the wizard.
        // Here we drive on_key and then simulate the loop's close.
        let mut app = app_with_host("web");
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert_eq!(*app.mode(), Mode::HostWizard);
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Cancel));
        // Loop action: close the wizard.
        app.close_host_wizard();
        assert_eq!(*app.mode(), Mode::Launcher);
        assert!(app.wizard().is_none());
    }

    // ---- persist_host_save: add + edit round-trips through a real temp file ----
    // These exercise the I/O half the wizard's pure on_key deliberately leaves
    // to the loop: name→id resolution, host::add_host / finalize_body, config
    // save+reload, and the launcher re-ranking afterwards.

    #[test]
    fn persist_host_save_add_appends_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Start from an empty config persisted to disk (so the reload reads the
        // file the save wrote).
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        // Open the add wizard and fill the form.
        app.open_host_wizard_add();
        let w = app.wizard.as_mut().unwrap();
        w.name = "web-prod".into();
        w.host_addr = "10.0.0.5".into();
        w.port = "2222".into();
        w.user = "deploy".into();

        persist_host_save(&mut app).expect("add save should succeed");

        // Wizard is NOT auto-closed by persist (the loop does that); but the
        // config has been reloaded with the new host.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        assert_eq!(reloaded.hosts[0].name, "web-prod");
        assert_eq!(reloaded.hosts[0].host, "10.0.0.5");
        assert_eq!(reloaded.hosts[0].port, 2222);
        assert_eq!(reloaded.hosts[0].auth.inline_body().unwrap().user, "deploy");
    }

    #[test]
    fn persist_host_save_edit_preserves_id_and_persists() {
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
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        // Open the edit wizard for that host and change the port + name.
        assert!(app.open_host_wizard_edit(orig_id));
        let w = app.wizard.as_mut().unwrap();
        w.port = "2200".into();
        w.name = "web-renamed".into();

        persist_host_save(&mut app).expect("edit save should succeed");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        let h = &reloaded.hosts[0];
        assert_eq!(h.id, orig_id, "edit must preserve the original id");
        assert_eq!(h.name, "web-renamed");
        assert_eq!(h.port, 2200);
    }

    #[test]
    fn persist_host_save_add_rejects_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let w = app.wizard.as_mut().unwrap();
        w.name = "web".into(); // duplicate
        w.host_addr = "h2".into();

        let err = persist_host_save(&mut app).unwrap_err();
        assert!(matches!(err, SshrackError::HostAlreadyExists { .. }));
        // The duplicate host was NOT written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
    }

    #[test]
    fn persist_host_save_credential_choice_resolves_name_to_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cid = Ulid::new();
        let cfg = SshrackConfig {
            credentials: vec![sshrack_core::config::schema::Credential {
                id: cid,
                name: "ops-key".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add(); // seeds credential_names from config
        let w = app.wizard.as_mut().unwrap();
        w.name = "web".into();
        w.host_addr = "10.0.0.5".into();
        w.auth_choice = super::super::wizard::AuthChoice::Credential { idx: 0 };

        persist_host_save(&mut app).unwrap();

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let h = &reloaded.hosts[0];
        assert_eq!(
            h.auth.credential_id(),
            Some(cid),
            "credential name must resolve to id"
        );
    }

    #[test]
    fn persist_host_save_credential_choice_unknown_name_errors() {
        // A dangling credential (name not in config) must surface as
        // CredentialNotFound, not silently fall back to inline default.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        // No credentials defined; force a Credential choice with idx 0 (which
        // names nothing). build_auth falls back to inline, but the loop's
        // selected_credential_name() returns None when the list is empty, so
        // this path actually skips the resolution. To exercise the unknown-name
        // branch, inject a credential name that does not exist.
        let w = app.wizard.as_mut().unwrap();
        w.name = "web".into();
        w.host_addr = "10.0.0.5".into();
        w.credential_names = vec!["ghost".into()]; // not in config
        w.auth_choice = super::super::wizard::AuthChoice::Credential { idx: 0 };

        let err = persist_host_save(&mut app).unwrap_err();
        assert!(matches!(err, SshrackError::CredentialNotFound { .. }));
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

        // ^a → opens wizard.
        app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert_eq!(*app.mode(), Mode::HostWizard);

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
        persist_host_save(&mut app).expect("save");
        app.close_host_wizard();
        assert_eq!(*app.mode(), Mode::Launcher);
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

        // ^e on the selected (only) host → wizard prefilled.
        app.on_key(press(KeyCode::Char('e'), KeyModifiers::CONTROL));
        assert_eq!(*app.mode(), Mode::HostWizard);
        let w = app.wizard.as_ref().unwrap();
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

        persist_host_save(&mut app).expect("save");
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
        app.close_host_wizard();

        assert_eq!(*app.mode(), Mode::Launcher);
        // Nothing persisted.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.hosts.is_empty());
    }

    // ===============================================================
    // Credential wizard: persist_cred_save + entry routing.
    // ===============================================================

    use sshrack_core::config::schema::{Credential, SecretKind, SecretStore};

    /// A `TerminalHandle` whose [`Weak::upgrade`] always returns `None`. Used
    /// in tests that exercise the plaintext store-mode path (no vault unlock
    /// popup, so the handle is never upgraded). Vault-mode tests would need a
    /// live terminal; the plaintext path is the unit-testable surface here.
    fn dead_handle() -> TerminalHandle {
        std::rc::Weak::new()
    }

    #[test]
    fn cred_add_none_kind_persists_user_only_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let w = app.cred_wizard.as_mut().unwrap();
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::None;

        persist_cred_save(&mut app, &dead_handle()).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.credentials.len(), 1);
        assert_eq!(reloaded.credentials[0].name, "ops");
        assert_eq!(reloaded.credentials[0].body.user, "deploy");
        assert_eq!(
            reloaded.credentials[0].body.secret_kind(),
            SecretKind::Default
        );
    }

    #[test]
    fn cred_add_identity_kind_persists_key_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Plaintext store mode so no sealing/vault path is exercised.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let w = app.cred_wizard.as_mut().unwrap();
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::IdentityKey;
        w.identity = "/home/me/.ssh/id_ed25519".into();

        persist_cred_save(&mut app, &dead_handle()).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.body.secret_kind(), SecretKind::Key);
        assert_eq!(
            c.body.key.as_deref(),
            Some(std::path::Path::new("/home/me/.ssh/id_ed25519"))
        );
    }

    #[test]
    fn cred_add_password_with_store_mode_plaintext_persists_plain_secret() {
        // Password + a decided store mode (Plaintext) → seal_body writes
        // Secret::Plain inline. The password must be sealed, not stored raw in
        // argv, and must survive the reload.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let w = app.cred_wizard.as_mut().unwrap();
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::Password;
        *w.password = "hunter2".into();

        persist_cred_save(&mut app, &dead_handle()).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.body.secret_kind(), SecretKind::Password);
        assert_eq!(c.body.password_plain(), Some("hunter2"));
    }

    #[test]
    fn cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext() {
        // The crux of the "do not auto-pick a mode" rule: a Password choice
        // with cfg.store == None must surface StoreModeNotDecided, NOT silently
        // fall through to plaintext (which core's seal would otherwise do).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let w = app.cred_wizard.as_mut().unwrap();
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::Password;
        *w.password = "hunter2".into();

        let err = persist_cred_save(&mut app, &dead_handle()).unwrap_err();
        assert!(
            matches!(err, SshrackError::StoreModeNotDecided),
            "undecided store mode must error, not silently pick plaintext: {err}"
        );
        // Nothing was written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.credentials.is_empty());
    }

    #[test]
    fn cred_add_duplicate_name_errors() {
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
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let w = app.cred_wizard.as_mut().unwrap();
        w.name = "ops".into(); // duplicate
        w.user = "deploy".into();

        let err = persist_cred_save(&mut app, &dead_handle()).unwrap_err();
        assert!(matches!(err, SshrackError::CredentialAlreadyExists { .. }));
    }

    #[test]
    fn cred_edit_preserves_original_id_and_password_when_password_blank() {
        // Editing only the user/name with the password field left blank MUST
        // keep the existing password (and the original id). The original body is
        // a plaintext-password credential under Plaintext store mode.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            credentials: vec![Credential {
                id: orig_id,
                name: "ops".into(),
                body: CredentialBody::new("deploy").with_password("topsecret"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        assert!(app.open_cred_wizard_edit("ops"));
        let w = app.cred_wizard.as_mut().unwrap();
        // The chooser opens on Password (the original kind). Leave the password
        // field blank and rename.
        assert_eq!(w.secret_kind, super::super::wizard::SecretChoice::Password);
        assert!(w.password.is_empty(), "edit form must not echo plaintext");
        w.name = "ops2".into();
        w.user = "ops".into();

        persist_cred_save(&mut app, &dead_handle()).expect("edit save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.credentials.len(), 1);
        let c = &reloaded.credentials[0];
        assert_eq!(c.id, orig_id, "edit must preserve the original id");
        assert_eq!(c.name, "ops2");
        assert_eq!(
            c.body.password_plain(),
            Some("topsecret"),
            "blank password field must keep the existing password"
        );
    }

    #[test]
    fn cred_edit_changing_user_keeps_id_and_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            credentials: vec![Credential {
                id: orig_id,
                name: "ops".into(),
                body: CredentialBody::new("deploy").with_password("topsecret"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        assert!(app.open_cred_wizard_edit("ops"));
        let w = app.cred_wizard.as_mut().unwrap();
        w.user = "root".into();
        // password left blank → preserved.

        persist_cred_save(&mut app, &dead_handle()).expect("edit save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.id, orig_id);
        assert_eq!(c.body.user, "root");
        assert_eq!(c.body.password_plain(), Some("topsecret"));
    }

    // ---- entry routing ----

    #[test]
    fn entry_mode_cred_add_opens_cred_wizard_directly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        app.apply_entry_mode(super::super::EntryMode::CredWizard { edit_name: None });
        assert_eq!(*app.mode(), Mode::CredWizard);
        assert!(app.cred_wizard.is_some());
        assert!(
            !app.cred_wizard.as_ref().unwrap().editing,
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
        assert_eq!(*app.mode(), Mode::CredWizard);
        let w = app.cred_wizard.as_ref().unwrap();
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
        assert_eq!(*app.mode(), Mode::Launcher);
        assert!(app.cred_wizard.is_none());
        assert!(
            app.launcher
                .status
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
        assert_eq!(*app.mode(), Mode::HostWizard);
        assert!(app.wizard.is_some());
    }

    #[test]
    fn launcher_c_key_opens_cred_add_wizard() {
        // The in-TUI entry key: bare `c` opens the cred add wizard from the
        // launcher.
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..SshrackConfig::default()
        };
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(*app.mode(), Mode::CredWizard);
        assert!(app.cred_wizard.is_some());
    }

    #[test]
    fn launcher_shift_c_edits_selected_hosts_credential() {
        // Shift-C opens the cred edit wizard for the credential referenced by
        // the host under the launcher cursor.
        let cid = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::reference(cid),
            }],
            credentials: vec![Credential {
                id: cid,
                name: "ops".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        let outcome = app.on_key(press(KeyCode::Char('C'), KeyModifiers::SHIFT));
        assert!(matches!(outcome, Outcome::Continue));
        assert_eq!(*app.mode(), Mode::CredWizard);
        let w = app.cred_wizard.as_ref().unwrap();
        assert!(w.editing);
        assert_eq!(w.name, "ops");
    }

    #[test]
    fn launcher_shift_c_with_no_credential_ref_sets_status() {
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..SshrackConfig::default()
        };
        let mut app = App::new(cfg, None, Frecency::default(), HashMap::new());
        app.on_key(press(KeyCode::Char('C'), KeyModifiers::SHIFT));
        assert_eq!(*app.mode(), Mode::Launcher);
        assert!(
            app.launcher
                .status
                .as_deref()
                .unwrap_or("")
                .contains("no credential")
        );
    }

    #[test]
    fn cred_wizard_esc_cancels_back_to_launcher() {
        let mut app = app_with_host("web");
        app.open_cred_wizard_add();
        assert_eq!(*app.mode(), Mode::CredWizard);
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Cancel));
        app.close_cred_wizard();
        assert_eq!(*app.mode(), Mode::Launcher);
        assert!(app.cred_wizard.is_none());
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

        // c → opens cred wizard.
        app.on_key(press(KeyCode::Char('c'), KeyModifiers::NONE));
        assert_eq!(*app.mode(), Mode::CredWizard);
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
        assert_eq!(*app.mode(), Mode::Launcher);
        assert_eq!(app.config().credentials.len(), 1);
        assert_eq!(app.config().credentials[0].name, "ops");
    }
}
