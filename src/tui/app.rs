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
use std::rc::Rc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout},
    style::{Style, Stylize},
    text::Line,
    widgets::Paragraph,
};

use super::ConnectRequest;

/// ratatui backend bound to stdout via crossterm.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Shared, interior-mutable handle to the terminal. The [`TerminalGuard`] owns
/// the only strong reference while the TUI is running; it hands out a **weak**
/// clone ([`TerminalHandle`]) to the prompt layer so a `&self`
/// [`sshrack_core::secret::PassphraseProvider`] impl can borrow the terminal
/// `&mut` to render a popup. The weak handle goes dead when the guard drops, so
/// a stray reference can never outlive the terminal restore.
pub type TerminalHandle = Rc<RefCell<Tui>>;

/// RAII terminal guard. On construction it enables raw mode and enters the
/// alternate screen; on drop it leaves the alternate screen and disables raw
/// mode. The guard owns the [`Tui`] behind an [`Rc<RefCell<…>>`] so both the
/// event loop and the prompt layer (which receives a [`TerminalHandle`]) can
/// borrow it. The terminal lives exactly as long as raw mode is on.
///
/// Drop swallows restore errors: there is no meaningful recovery at drop time,
/// and a partially-restored terminal is strictly worse than a best-effort one.
/// The user can `reset` if ever needed.
pub struct TerminalGuard {
    terminal: TerminalHandle,
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
    /// [`sshrack_core::secret::PassphraseProvider`] impl. Upgrades to
    /// `Some(handle)` only while this guard is alive.
    #[allow(dead_code)]
    pub fn handle(&self) -> TerminalHandle {
        Rc::clone(&self.terminal)
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

/// TUI application state. Task 11 ships only the quit flag; later tasks add
/// the host list, query, selection, mode, and popup state.
pub struct App {
    /// Set by [`App::on_key`] when the user presses a quit binding. The loop
    /// checks this as a secondary exit (the primary exit is [`Outcome::Quit`]).
    pub should_quit: bool,
}

impl App {
    /// Construct a fresh app with default state.
    pub fn new() -> Self {
        Self { should_quit: false }
    }

    /// Pure: decide what should happen next for a given key. Performs **no**
    /// I/O — no reads, no writes, no terminal access — so it is safe to call
    /// from a unit test without an event source.
    ///
    /// Quit bindings: `Esc` or `Ctrl-C`. Everything else is [`Outcome::Continue`]
    /// for now; later tasks add navigation, search, and selection.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        // Ctrl-C must be EXACTLY Control+c — `contains` would wrongly treat
        // Ctrl-Shift-C (terminal paste) as quit. Esc needs no modifier guard
        // (Shift-Esc and friends are rare and still intent to quit).
        let is_quit = key.kind == KeyEventKind::Press
            && (key.code == KeyCode::Esc
                || (key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c')));
        if is_quit {
            self.should_quit = true;
            return Outcome::Quit;
        }
        Outcome::Continue
    }

    /// Render current state to the frame. Only writes to the frame (no stdout
    /// access of its own). Task 11 renders a centered placeholder so the
    /// screen is never blank; later tasks replace this with the launcher.
    pub fn draw(&self, frame: &mut Frame) {
        let area = frame.area();

        // One vertical region; we center the text within it. `areas` returns
        // exactly one rect for a single-constraint vertical layout, so the
        // destructuring cannot fail.
        let [body] = Layout::vertical([Constraint::Fill(1)]).areas(area);

        let lines = vec![
            Line::from("sshrack TUI").bold().centered(),
            Line::from("press Esc (or Ctrl-C) to quit")
                .style(Style::new().dim())
                .centered(),
        ];
        let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
        frame.render_widget(paragraph, body);
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
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

    fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        // crossterm distinguishes Press/Release/Repeat; the app only acts on
        // Press, so tests construct Press keys to exercise the binding.
        KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
    }

    #[test]
    fn esc_yields_quit() {
        let mut app = App::new();
        let outcome = app.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Quit));
        assert!(app.should_quit, "Esc should set should_quit");
    }

    #[test]
    fn ctrl_c_yields_quit() {
        let mut app = App::new();
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(matches!(outcome, Outcome::Quit));
        assert!(app.should_quit, "Ctrl-C should set should_quit");
    }

    #[test]
    fn neutral_key_yields_continue() {
        let mut app = App::new();
        let outcome = app.on_key(press(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit, "a neutral key must not flip should_quit");
    }

    #[test]
    fn key_release_is_ignored() {
        // Release events must not be treated as a quit even for Esc.
        let mut app = App::new();
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
        let mut app = App::new();
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
        let mut app = App::new();
        let outcome = app.on_key(press(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(matches!(outcome, Outcome::Continue));
        assert!(!app.should_quit);
    }
}
