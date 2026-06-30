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
use sshrack_core::config::schema::Host;
use sshrack_core::frecency::Frecency;

use super::ConnectRequest;
use super::CredentialNames;
use super::launcher::Launcher;

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
    /// User picked a host to connect to. The loop returns `Some(req)`; `main`
    /// execs ssh after the terminal is restored.
    ///
    /// Constructed by the launcher in Task 15; Task 11 only matches on it.
    #[allow(dead_code)]
    Connect(ConnectRequest),
}

/// TUI application state. The launcher is the primary mode; later tasks grow
/// this with wizard/store/help modes via a `mode` enum.
///
/// `App` owns the data (hosts, frecency, credential-name lookup) loaded once
/// at startup from core. The [`Launcher`] inside it owns the query/selection
/// view state and is the only mode wired up here.
pub struct App {
    /// Set by [`App::on_key`] when the user presses a quit binding. The loop
    /// checks this as a secondary exit (the primary exit is [`Outcome::Quit`]).
    pub should_quit: bool,
    /// The full host list, loaded from core config. The launcher borrows into
    /// this by index; no data path lives in the view.
    hosts: Vec<Host>,
    /// Machine-local frecency table, loaded from core's data dir.
    frecency: Frecency,
    /// Reverse lookup from a credential ULID to its display name, so the
    /// launcher can show `Auth::Ref` targets by name without re-scanning.
    credential_names: CredentialNames,
    /// The interactive launcher (query + selection + ranked list).
    launcher: Launcher,
}

impl App {
    /// Construct a fresh app from loaded core data. Builds the launcher with
    /// its initial frecency-ordered ranking.
    pub fn new(hosts: Vec<Host>, frecency: Frecency, credential_names: CredentialNames) -> Self {
        let launcher = Launcher::new(&hosts, &frecency);
        Self {
            should_quit: false,
            hosts,
            frecency,
            credential_names,
            launcher,
        }
    }

    /// Pure: decide what should happen next for a given key. Performs **no**
    /// I/O — no reads, no writes, no terminal access — so it is safe to call
    /// from a unit test without an event source.
    ///
    /// Routes the key to the launcher. Quit is handled inside the launcher
    /// (`Esc` with empty query, or `Ctrl-C`); this method sets `should_quit`
    /// for the loop's secondary exit check.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        let outcome = self.launcher.on_key(key, &self.hosts, &self.frecency);
        if matches!(outcome, Outcome::Quit) {
            self.should_quit = true;
        }
        outcome
    }

    /// Render current state to the frame. Only writes to the frame (no stdout
    /// access of its own). Routes to the launcher's render.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        self.launcher.draw(
            frame,
            area,
            &self.hosts,
            &self.frecency,
            &self.credential_names,
        );
    }
}

/// Blocking event loop. Renders `app`, polls crossterm for key events, and
/// dispatches each key through [`App::on_key`]. Returns `Some(req)` when the
/// app signals a connect (the loop exits and `main` execs ssh after terminal
/// restore), or `None` when the user quits.
///
/// Event-read errors are tolerated (treated as "no event this tick") rather
/// than aborting the TUI: a transient read failure should not strand the user
/// in an unrecoverable state. The terminal is still restored on return because
/// the caller owns the [`TerminalGuard`].
pub fn run_loop(terminal: &mut Tui, app: &mut App) -> Option<ConnectRequest> {
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
                Outcome::Connect(req) => return Some(req),
                Outcome::Continue => {}
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
    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
    use sshrack_core::config::schema::{Auth, CredentialBody};
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
        App::new(vec![host], Frecency::default(), HashMap::new())
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
    fn enter_sets_connect_pending_status_without_quitting() {
        // Task 14: Enter is a Continue placeholder (Task 15 wires connect).
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
        assert!(
            app.launcher
                .status
                .as_deref()
                .unwrap_or("")
                .contains("pending")
        );
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
        let mut app = App::new(vec![h1, h2], Frecency::default(), HashMap::new());
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
    fn ctrl_a_sets_not_yet_implemented_status() {
        let mut app = app_with_host("web");
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
        assert!(
            app.launcher
                .status
                .as_deref()
                .unwrap_or("")
                .contains("not yet implemented")
        );
    }
}
