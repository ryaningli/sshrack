//! Non-interactive command surface. The CLI is fail-closed: every required
//! field must come from a flag (missing `--host`/`--user`/`<name>` errors with
//! `VALIDATION`/`USAGE`), the vault passphrase comes only from the
//! `SSHRACK_PASSPHRASE` env var, destructive actions (`host rm`, `cred rm`,
//! `store use plaintext`) require `--yes`, and a first-seen host key is only
//! accepted with `--accept-new`. There is no `--no-input` toggle and no TTY
//! prompting anywhere in this layer — the interactive wizard lives in `tui`.
use clap::CommandFactory;

pub mod args;
pub mod cmd;
// Foundation for the CLI's default-interactive mode (tasks T2-T7 wire the
// consumers). `dead_code` is allowed at the module until the last consumer
// lands, so this task can ship the focused interaction module on its own.
#[allow(dead_code)]
pub(crate) mod prompt;
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
        // Unreachable: `route_is_tui` routes every Sftp arm to the TUI before
        // this function is called. Surface a clean internal error rather than
        // silently dropping on the floor if that invariant ever breaks.
        Some(Command::Sftp { .. }) => {
            eprintln!("sshrack: internal error: sftp arm reached the CLI dispatcher");
            exit_code::USAGE
        }
        Some(Command::Host { action }) => cmd::host::run(cli, action),
        Some(Command::Cred { action }) => cmd::cred::run(cli, action),
        Some(Command::Store { action }) => cmd::store::run(cli, action),
    }
}
