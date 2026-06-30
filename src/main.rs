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

    if route_is_tui(&cli) {
        return match tui::run(&cli) {
            Ok(code) => code,
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
fn route_is_tui(cli: &cli::Cli) -> bool {
    match &cli.cmd {
        None => true,
        Some(Command::Host { action }) => host_add_or_edit_is_empty(action),
        Some(Command::Cred { action }) => cred_add_or_edit_is_empty(action),
        _ => false,
    }
}

/// `host add` with no content fields → TUI add wizard; `host edit <name>` with
/// no edit flags → TUI edit wizard. Any other `host` sub-action is CLI.
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
            host,
            user,
            port,
            identity,
            rename,
            credential,
            clear_identity,
            clear_password,
            clear_credential,
            ..
        } => {
            // name may be set (`host edit <name>`); what matters is that NO
            // edit flag is set — that is the patch vs wizard line.
            host.is_none()
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
fn cred_add_or_edit_is_empty(action: &CredAction) -> bool {
    match action {
        CredAction::Add {
            name,
            user,
            identity,
            force,
        } => name.is_none() && user.is_none() && identity.is_none() && !*force,
        CredAction::Edit {
            user,
            identity,
            clear_identity,
            rename,
            ..
        } => user.is_none() && identity.is_none() && !*clear_identity && rename.is_none(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Decision-table tests for the routing predicate. The table is the
    //! contract: bare / empty-add / empty-edit → TUI; everything else → CLI.
    use super::*;
    use crate::cli::args::{
        Cli, Command, ConfigAction, CredAction, HostAction, SortMode, StoreAction,
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
