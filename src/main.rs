//! sshrack binary entry. Dispatches the SSH_ASKPASS helper role vs the CLI/TUI.
use clap::Parser;
use sshrack_core::askpass;

mod cli;
mod shared;
mod tui;

use cli::args::{Command, CredAction, HostAction};
use shared::exit_code;

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
/// A bare `sshrack`, or `host`/`cred` `add`/`edit` carrying no content flags,
/// routes to the TUI (the interactive wizards); everything else — connect,
/// scp, ls, show, rm, cp, store — runs the non-interactive CLI. `--help`/
/// `--version` and usage errors are still owned by clap.
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

    // `host edit` and `cred edit` REQUIRE a name (Finding #3): without one the
    // user picked the edit verb but named nothing to edit. Surfacing this as a
    // usage error here — rather than silently opening the ADD wizard (the old
    // behavior, because `route_is_tui` ignored `name` for Edit) — keeps the
    // edit/add verbs distinct. The user can still run the bare `sshrack` (which
    // routes to the launcher) or `host add` (add wizard) explicitly.
    if let Some(msg) = edit_requires_name_error(&cli) {
        eprintln!("{msg}");
        return exit_code::USAGE;
    }

    if route_is_tui(&cli) {
        // The TUI returns None (user quit, no connect) or a ConnectRequest for
        // main to exec. The TerminalGuard is dropped inside tui::run before
        // this match sees the value, so ssh inherits a restored terminal.
        return match tui::run(&cli) {
            Ok(None) => exit_code::SUCCESS,
            Ok(Some(req)) => {
                // Unreachable in Task 11 (the App never produces a Connect),
                // but compiles and is correct for Task 15. Resolve our own exe
                // without `?` (run_main returns i32, not Result); a resolution
                // failure is a connect-time error.
                let exe = match sshrack_core::connect::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return exit_code::CONNECT;
                    }
                };
                match sshrack_core::connect::launch(req.argv, req.source, &exe) {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("{e}");
                        exit_code::CONNECT
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                exit_code::CONNECT
            }
        };
    }

    cli::run(&cli)
}

/// A bare `sshrack`, or `host`/`cred add|edit` with no content flags, routes
/// to the TUI. Everything else (connect, scp, ls, show, rm, cp, store) is CLI.
///
/// `host edit <name>` with no edit flags returns true → TUI edit wizard;
/// `host edit <name> --port 22` returns false → CLI patch (the hard rule:
/// a flagged field is a patch, never a wizard).
///
/// # `--format json` with no subcommand (Finding #9)
///
/// A bare `sshrack --format json` does NOT route to the TUI: there is nothing
/// to format, and silently ignoring the flag while opening the alternate
/// screen would surprise scripts. It falls through to the CLI (clap prints
/// help; the flag is a no-op there). Only a TRULY bare `sshrack` (no
/// subcommand AND default text format) opens the launcher.
///
/// # `host/cred edit` without a name (Finding #3)
///
/// `host edit` / `cred edit` with no name returns false here so it never
/// reaches the TUI; [`edit_requires_name_error`] surfaces a usage error before
/// any routing decision runs. (Edit needs a target; add does not.)
fn route_is_tui(cli: &cli::Cli) -> bool {
    match &cli.cmd {
        // Finding #9: a bare `sshrack` opens the TUI ONLY under the default
        // text format. `--format json` with no subcommand falls through to the
        // CLI (help), never the alternate screen.
        None => matches!(cli.format, cli::args::OutputFormat::Text),
        Some(Command::Host { action }) => host_add_or_edit_is_empty(action),
        Some(Command::Cred { action }) => cred_add_or_edit_is_empty(action),
        _ => false,
    }
}

/// If the CLI is a `host edit` / `cred edit` with no name, return a usage error
/// message (Finding #3). `None` otherwise. This runs BEFORE [`route_is_tui`] so
/// the user gets a clear "edit needs <name>" message instead of the add wizard
/// or a confusing launcher. The launcher is still reachable via bare `sshrack`
/// (the user can pick a host there and press `^e`), and add is unaffected.
fn edit_requires_name_error(cli: &cli::Cli) -> Option<String> {
    let needs_name = matches!(
        &cli.cmd,
        Some(Command::Host {
            action: HostAction::Edit { name: None, .. },
        }) | Some(Command::Cred {
            action: CredAction::Edit { name: None, .. },
        })
    );
    if needs_name {
        Some(
            "edit requires <name>: run `sshrack host edit <name>` or `sshrack cred edit <name>`, or run a bare `sshrack` to open the launcher and pick one.".into(),
        )
    } else {
        None
    }
}

/// `host add` with no content fields → TUI add wizard; `host edit <name>` with
/// no edit flags → TUI edit wizard. Any other `host` sub-action is CLI.
/// `host edit` with NO name returns false ([`edit_requires_name_error`] handles
/// the usage error before routing).
fn host_add_or_edit_is_empty(action: &HostAction) -> bool {
    match action {
        HostAction::Add {
            name,
            host,
            user,
            port,
            identity,
            credential,
            force,
        } => {
            // A name positional alone does NOT leave add empty — `host add x`
            // is still a partial add that the CLI rejects (missing --host); the
            // wizard is for a truly flag-less `host add`. Every content field
            // (flags AND the name positional) must be unset.
            name.is_none()
                && host.is_none()
                && user.is_none()
                && port.is_none()
                && identity.is_none()
                && credential.is_none()
                && !*force
        }
        HostAction::Edit {
            name,
            host,
            user,
            port,
            identity,
            rename,
            credential,
            clear_identity,
            clear_password,
            clear_credential,
        } => {
            // Finding #3: edit REQUIRES a name — without one it is a usage
            // error (handled by edit_requires_name_error), not the TUI.
            name.is_some()
                && host.is_none()
                && user.is_none()
                && port.is_none()
                && identity.is_none()
                && rename.is_none()
                && credential.is_none()
                && !*clear_identity
                && !*clear_password
                && !*clear_credential
        }
        _ => false,
    }
}

/// `cred add` with no content fields → TUI add wizard; `cred edit <name>` with
/// no edit flags → TUI edit wizard. Any other `cred` sub-action is CLI.
/// `cred edit` with NO name returns false ([`edit_requires_name_error`] handles
/// the usage error before routing).
fn cred_add_or_edit_is_empty(action: &CredAction) -> bool {
    match action {
        CredAction::Add {
            name,
            user,
            identity,
            force,
        } => name.is_none() && user.is_none() && identity.is_none() && !*force,
        CredAction::Edit {
            name,
            user,
            identity,
            clear_identity,
            rename,
        } => {
            // Finding #3: edit REQUIRES a name — without one it is a usage
            // error, not the TUI.
            name.is_some()
                && user.is_none()
                && identity.is_none()
                && !*clear_identity
                && rename.is_none()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Decision-table tests for the routing predicate. The table is the
    //! contract: bare / empty-add / empty-edit → TUI; everything else → CLI.
    use super::*;
    use crate::cli::args::{
        Cli, Command, ConfigAction, CredAction, HostAction, OutputFormat, SortMode, StoreAction,
    };
    use clap::Parser;

    fn cli_with_cmd(cmd: Option<Command>) -> Cli {
        // A minimal parseable Cli. Fields not relevant to routing are defaulted.
        let args: Vec<&str> = vec![];
        let mut base = Cli::try_parse_from(["sshrack"].iter().chain(args.iter())).unwrap();
        base.cmd = cmd;
        base
    }

    #[test]
    fn bare_routes_to_tui() {
        assert!(route_is_tui(&cli_with_cmd(None)));
    }

    #[test]
    fn bare_with_format_json_does_not_route_to_tui() {
        // Finding #9: `sshrack --format json` (no subcommand) must NOT open the
        // alternate screen; the flag is silently ignored by the TUI otherwise.
        // It falls through to the CLI (clap prints help). Only a TRULY bare
        // `sshrack` (default text format) opens the launcher.
        let mut cli = cli_with_cmd(None);
        cli.format = OutputFormat::Json;
        assert!(
            !route_is_tui(&cli),
            "--format json + no subcommand = not TUI"
        );
    }

    #[test]
    fn host_edit_no_name_does_not_route_to_tui() {
        // Finding #3: `host edit` with no name is a usage error, not the TUI
        // (and not the add wizard, which the old routing silently opened).
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: None,
                host: None,
                user: None,
                port: None,
                identity: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_credential: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_edit_no_name_surfaces_usage_error() {
        // Finding #3: edit_requires_name_error fires for nameless host edit.
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: None,
                host: None,
                user: None,
                port: None,
                identity: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_credential: false,
            },
        };
        let cli = cli_with_cmd(Some(cmd));
        assert!(edit_requires_name_error(&cli).is_some());
    }

    #[test]
    fn cred_edit_no_name_does_not_route_to_tui() {
        // Finding #3: `cred edit` with no name is a usage error, not the TUI.
        let mk = || Command::Cred {
            action: CredAction::Edit {
                name: None,
                user: None,
                identity: None,
                clear_identity: false,
                rename: None,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(mk()))));
        assert!(edit_requires_name_error(&cli_with_cmd(Some(mk()))).is_some());
    }

    #[test]
    fn host_edit_named_still_routes_to_tui() {
        // Regression guard for Finding #3: the fix must NOT break the named
        // `host edit <name>` → TUI edit-wizard route. Only nameless edit errors.
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: Some("h".into()),
                host: None,
                user: None,
                port: None,
                identity: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_credential: false,
            },
        };
        let cli = cli_with_cmd(Some(cmd));
        assert!(route_is_tui(&cli));
        assert!(edit_requires_name_error(&cli).is_none());
    }

    #[test]
    fn host_add_empty_routes_to_tui() {
        let cmd = Command::Host {
            action: HostAction::Add {
                name: None,
                host: None,
                user: None,
                port: None,
                identity: None,
                credential: None,
                force: false,
            },
        };
        assert!(route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_add_with_name_only_is_cli() {
        // A name positional alone does not open the wizard — it's a partial
        // add the CLI rejects (missing --host). Wizard is for flag-less add.
        let cmd = Command::Host {
            action: HostAction::Add {
                name: Some("x".into()),
                host: None,
                user: None,
                port: None,
                identity: None,
                credential: None,
                force: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_add_with_host_flag_is_cli() {
        let cmd = Command::Host {
            action: HostAction::Add {
                name: Some("x".into()),
                host: Some("1.2.3.4".into()),
                user: None,
                port: None,
                identity: None,
                credential: None,
                force: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_add_force_alone_is_cli() {
        // --force without other fields still isn't a wizard; it's a CLI error
        // (missing --host). Only a truly flag-less add routes to the TUI.
        let cmd = Command::Host {
            action: HostAction::Add {
                name: None,
                host: None,
                user: None,
                port: None,
                identity: None,
                credential: None,
                force: true,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_edit_no_flags_routes_to_tui() {
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: Some("somehost".into()),
                host: None,
                user: None,
                port: None,
                identity: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_credential: false,
            },
        };
        assert!(route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_edit_with_port_is_cli_patch() {
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: Some("somehost".into()),
                host: None,
                user: None,
                port: Some(22),
                identity: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_credential: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_edit_clear_identity_is_cli() {
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: Some("h".into()),
                host: None,
                user: None,
                port: None,
                identity: None,
                rename: None,
                credential: None,
                clear_identity: true,
                clear_password: false,
                clear_credential: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn host_ls_is_cli() {
        let cmd = Command::Host {
            action: HostAction::Ls {
                fields: None,
                sort: Some(SortMode::Name),
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn cred_add_empty_routes_to_tui() {
        let cmd = Command::Cred {
            action: CredAction::Add {
                name: None,
                user: None,
                identity: None,
                force: false,
            },
        };
        assert!(route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn cred_add_with_user_is_cli() {
        let cmd = Command::Cred {
            action: CredAction::Add {
                name: None,
                user: Some("root".into()),
                identity: None,
                force: false,
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn cred_edit_no_flags_routes_to_tui() {
        let cmd = Command::Cred {
            action: CredAction::Edit {
                name: Some("c".into()),
                user: None,
                identity: None,
                clear_identity: false,
                rename: None,
            },
        };
        assert!(route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn cred_edit_rename_is_cli() {
        let cmd = Command::Cred {
            action: CredAction::Edit {
                name: Some("c".into()),
                user: None,
                identity: None,
                clear_identity: false,
                rename: Some("d".into()),
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn store_status_is_cli() {
        let cmd = Command::Store {
            action: StoreAction::Status,
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn store_config_none_is_cli() {
        let cmd = Command::Store {
            action: StoreAction::Config {
                action: Some(ConfigAction::Show),
            },
        };
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }

    #[test]
    fn connect_shorthand_is_cli() {
        let cmd = Command::Connect(vec!["web1".into(), "echo".into(), "hi".into()]);
        assert!(!route_is_tui(&cli_with_cmd(Some(cmd))));
    }
}
