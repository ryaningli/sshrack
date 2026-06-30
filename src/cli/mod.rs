//! Non-interactive command surface. All handlers are flags-only; missing
//! required fields error instead of prompting. Interaction lives in `tui`.
use clap::CommandFactory;

pub mod args;
pub mod cmd;
pub mod prompt; // deleted in Block 3
pub mod table;

use crate::shared::exit_code;

pub use args::Cli;

/// Dispatch the parsed CLI. Returns the process exit code.
pub fn run(cli: &Cli) -> i32 {
    use args::Command;
    match &cli.cmd {
        None => {
            // Routed to TUI in Block 4; placeholder keeps behavior for now.
            Cli::command().print_help().ok();
            exit_code::SUCCESS
        }
        Some(Command::Ssh { .. }) | Some(Command::Connect(_)) => cmd::connect::run(cli),
        Some(Command::Scp { .. }) => cmd::scp::run(cli),
        Some(Command::Host { action }) => cmd::host::run(cli, action),
        Some(Command::Cred { action }) => cmd::cred::run(cli, action),
        Some(Command::Store { action }) => cmd::store::run(cli, action),
    }
}
