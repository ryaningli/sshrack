//! Terminal ownership for the TUI.
//!
//! [`TerminalGuard`] is RAII: it enters raw mode + the alternate screen on
//! construction and restores the terminal in [`Drop`]. Because `Drop` always
//! runs, the terminal is restored even when the event loop returns early (e.g.
//! on a connect request that later errors in `main`).
//!
//! The guard owns the [`Tui`] behind an `Rc<RefCell<…>>` and hands out two
//! ways to reach it: [`TerminalGuard::terminal`] returns the `Rc` (the loop
//! `borrow_mut()`s it for one narrow draw at a time), and
//! [`TerminalGuard::handle`] returns a weak [`TerminalHandle`] the prompt layer
//! upgrades at popup time. The reentrancy contract (narrow borrows only) is
//! documented on [`TerminalGuard`].

use std::cell::RefCell;
use std::io::{self, Stdout};
use std::rc::{Rc, Weak};

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

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
/// mode. The guard owns the [`Tui`] behind an [`Rc<RefCell<…>>`] and hands out
/// two ways to reach it: [`terminal`](Self::terminal) returns the `Rc` so the
/// event loop can `borrow_mut()` it for narrow scopes (a draw, a popup), and
/// [`handle`](Self::handle) returns a weak handle the prompt layer upgrades at
/// popup time. The terminal lives exactly as long as raw mode is on.
///
/// # Reentrancy contract (load-bearing)
///
/// The event loop MUST NOT hold a `RefMut` across code that itself borrows the
/// terminal via the weak handle (vault-unlock popup, host-key popup). The
/// pattern is: `borrow_mut()` only around a single `terminal.draw(...)` (or a
/// single popup's own draw loop), drop the `RefMut`, THEN run the side effect.
/// Holding a long-lived `RefMut` across `run_loop` re-introduces the
/// "already borrowed" panic on every popup path (Critical #1 final-review fix).
///
/// Drop swallows restore errors: there is no meaningful recovery at drop time,
/// and a partially-restored terminal is strictly worse than a best-effort one.
/// The user can `reset` if ever needed.
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

    /// The shared `Rc<RefCell<Tui>>` the event loop uses to draw frames and the
    /// prompt layer upgrades (via the weak [`handle`](Self::handle)) to render
    /// popups. The loop MUST `borrow_mut()` only for a narrow scope (one draw,
    /// or a popup's own draw loop) and drop the `RefMut` before running any
    /// side effect that re-borrows via the handle — otherwise the popup's
    /// `borrow_mut()` panics with "already borrowed". The [`Rc`] is returned
    /// (not a `RefMut`) so the caller controls the borrow lifetime.
    pub fn terminal(&self) -> Rc<RefCell<Tui>> {
        Rc::clone(&self.terminal)
    }

    /// A weak handle the prompt layer can store inside a `&self`
    /// [`sshrack_core::secret::PassphraseProvider`] impl. [`Weak::upgrade`]
    /// returns `Some` only while this guard is alive; once the guard drops, the
    /// handle goes dead and consumers treat the `None` as a silent
    /// cancellation ([`SshrackError::Interrupted`]). The handle is the
    /// reentrancy seam: popups upgrade it and `borrow_mut()` the terminal
    /// inside their own draw loop — the loop must NOT hold a `RefMut` at that
    /// point (see the type-level reentrancy contract).
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
