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
use super::wizard::HostForm;

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
    /// Pure intent: the user pressed Esc / Ctrl-C inside the wizard. The loop
    /// discards the wizard and returns to the launcher.
    Cancel,
}

/// Which view the TUI is showing. The launcher is the default; the host wizard
/// is entered via `^a` (add) / `^e` (edit) and left via save / cancel. Keeping
/// this on [`App`] (not the launcher) means the launcher's own state machine
/// never has to know about non-launcher keys — routing happens here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The host launcher (query + ranked list + connect).
    Launcher,
    /// The host add/edit wizard.
    HostWizard,
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
    /// given id. No-op (returns false) when the id is not in the config.
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
        self.wizard = Some(HostForm::new_edit(&host, names));
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
                Outcome::Cancel => {
                    // Wizard Esc / Ctrl-C: discard and return to the launcher.
                    app.launcher.status = Some("cancelled".into());
                    app.close_host_wizard();
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
        // 'c' without Ctrl is just a character, not a quit.
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
        assert_eq!(app.launcher.query, "c");
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
}
