//! Interactive TUI front end. Thin view over sshrack-core; all data paths go
//! through core, never reimplemented here.
//!
//! Block 4 ships only this stub: `run` reports the TUI as not-yet-implemented
//! and returns success. The real launcher lands in Block 5 (ratatui + crossterm
//! + nucleo-matcher, already declared as dependencies on the root crate).

use crate::cli::Cli;
use crate::shared::exit_code;

/// Entry point for TUI routes. Replaced by the real launcher in Block 5.
///
/// Routed here by `main::route_is_tui` for a bare `sshrack`, or for
/// `host`/`cred` `add`/`edit` invocations that carry no content flags (the
/// interactive wizards). The stub prints a notice and exits success so the
/// routing fork is exercised end-to-end before any rendering code lands.
pub fn run(_cli: &Cli) -> Result<i32, sshrack_core::error::SshrackError> {
    eprintln!("sshrack TUI (not yet implemented)");
    Ok(exit_code::SUCCESS)
}
