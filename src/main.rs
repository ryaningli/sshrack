//! sshrack binary entry. Dispatches the SSH_ASKPASS helper role vs the CLI/TUI.
use clap::Parser;
use sshrack_core::askpass;

mod cli;
mod shared;

fn main() {
    // Askpass role: the launcher (or ssh) forks us with one of these set.
    if std::env::var_os(askpass::ASKPASS_FILE_ENV).is_some()
        || std::env::var_os(sshrack_core::secret::keyring::KEYRING_KEY_ENV).is_some()
    {
        match askpass::run() {
            Ok(()) => std::process::exit(shared::exit_code::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(shared::exit_code::CONNECT);
            }
        }
    }

    let code = run_main();
    std::process::exit(code);
}

/// Parse the CLI and dispatch on the parsed subcommand.
///
/// `Ssh`/`Connect` run the connect path; `Host`/`Cred` run the resource-group
/// handlers; `Scp`/`Store` are stubbed (Part C). Handlers return their own
/// exit codes; domain-error → exit-code mapping lives inside each handler.
fn run_main() -> i32 {
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap handles `--help`/`--version` (exit code 0) and usage errors
            // (exit code 2) here, printing to stdout/stderr as appropriate.
            e.print().ok();
            return e.exit_code();
        }
    };

    cli::run(&cli)
}
