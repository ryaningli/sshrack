//! Interactive TUI front end. Thin view over sshrack-core; all data paths go
//! through core, never reimplemented here.
//!
//! Task 11 ships only the foundation: [`App`] state, a pure
//! [`App::on_key`] -> [`Outcome`] decision, a blocking event loop, an RAII
//! [`TerminalGuard`] that restores the terminal on drop, and the delayed-exec
//! [`ConnectRequest`] contract. The launcher, connect orchestration, wizards,
//! and popups land in later tasks.
//!
//! Architectural red line: the TUI holds no data path. [`App::on_key`] is pure
//! (no I/O) so it is unit-testable without a terminal. Side effects (persist,
//! exec) happen in the loop *after* `on_key`, never inside it. The terminal is
//! fully restored via [`TerminalGuard`]'s drop *before* `main` calls
//! [`sshrack_core::connect::launch`], so ssh never writes into the alternate
//! screen.

use crate::cli::Cli;
use sshrack_core::error::SshrackError;

pub mod app;
pub mod help;
pub mod launcher;
pub mod popup;
pub mod prompt;
pub mod wizard;

pub use app::{App, TerminalGuard, run_loop};

/// What `main` needs to spawn ssh after the TUI exits. All pre-exec side
/// effects (resolve, vault unlock, host-key confirm, frecency save) have
/// already happened inside the TUI before this is returned.
///
/// `main` consumes this *after* the [`TerminalGuard`] has been dropped and the
/// terminal restored, so ssh inherits a normal terminal, not the alternate
/// screen.
pub struct ConnectRequest {
    /// Fully-resolved ssh/scp argv (program + args). `main` passes it straight
    /// to [`sshrack_core::connect::launch`].
    pub argv: Vec<String>,
    /// Where the password (if any) comes from at exec time. Carried by value
    /// because [`sshrack_core::credential::PasswordSource`] owns a
    /// `Zeroizing<String>` for the inline case.
    pub source: sshrack_core::credential::PasswordSource,
}

/// TUI entry point. Returns `Ok(None)` when the user quits without connecting,
/// `Ok(Some(req))` when the TUI wants `main` to exec ssh after terminal
/// restore, or `Err` if terminal setup failed.
///
/// The [`TerminalGuard`] owns the terminal and is dropped at the end of this
/// function (raw mode off, alternate screen left), so by the time the
/// `Option<ConnectRequest>` reaches `main` the terminal is fully restored.
pub fn run(_cli: &Cli) -> Result<Option<ConnectRequest>, SshrackError> {
    let mut guard = TerminalGuard::enter()?;
    let mut app = App::new();
    // run_loop borrows the terminal through the guard; the guard itself stays
    // alive here, so the screen stays in alternate/raw mode for the duration.
    let request = run_loop(&mut guard, &mut app);
    // `guard` drops at function return: disable_raw_mode +
    // LeaveAlternateScreen. The terminal is restored on every path — plain
    // quit, connect, or early return from run_loop — because Drop always runs.
    Ok(request)
}
