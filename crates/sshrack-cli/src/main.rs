//! sshrack binary entry. Dispatches between the SSH_ASKPASS helper role and
//! the CLI based on environment variables set by the launcher.
//!
//! When the launcher (or ssh) forks this binary with `SSHRACK_ASKPASS_FILE`
//! or `SSHRACK_KEYRING_KEY` set, we run the askpass helper: it reads the
//! staged password (file or keyring) and writes it to stdout for ssh. In any
//! other invocation we parse the CLI and dispatch.

use clap::{CommandFactory, Parser};
use sshrack_core::askpass;

mod cli;
mod cmd;
mod exit_code;
mod format;
mod prompt;

fn main() {
    // Askpass role: the launcher (or ssh) forks us with one of these set.
    if std::env::var_os(askpass::ASKPASS_FILE_ENV).is_some()
        || std::env::var_os(sshrack_core::secret::keyring::KEYRING_KEY_ENV).is_some()
    {
        match askpass::run() {
            Ok(()) => std::process::exit(exit_code::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(exit_code::CONNECT);
            }
        }
    }

    let code = run_cli();
    std::process::exit(code);
}

/// Parse the CLI and dispatch on the parsed subcommand.
///
/// The `Ssh` and `Connect` arms run the connect path (Task 19). Other arms
/// print a stub message until Task 20 wires them up.
fn run_cli() -> i32 {
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap handles `--help`/`--version` (exit code 0) and usage errors
            // (exit code 2) here, printing to stdout/stderr as appropriate.
            e.print().ok();
            return e.exit_code();
        }
    };

    match &cli.cmd {
        None => {
            // No subcommand: print --help (no TUI in this phase).
            cli::Cli::command().print_help().ok();
            exit_code::SUCCESS
        }
        Some(cli::Command::Ssh { .. }) | Some(cli::Command::Connect(_)) => cmd::connect::run(&cli),
        Some(_) => {
            // TODO(Task 20): dispatch on cli.cmd to the cmd:: handlers.
            eprintln!("sshrack CLI dispatch not yet implemented for this subcommand");
            exit_code::SUCCESS
        }
    }
}
