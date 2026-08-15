//! Interactive TUI front end. Thin view over sshrack-core; all data paths go
//! through core, never reimplemented here.
//!
//! Task 11 shipped the foundation (App, event loop, RAII terminal guard,
//! delayed-exec ConnectRequest). Task 14 wires the launcher: [`App`] now owns
//! the host list, frecency table, and credential-name lookup loaded from core
//! at startup, and routes `on_key`/`draw` to the launcher view.
//!
//! Architectural red line: the TUI holds no data path. [`App::on_key`] is pure
//! (no I/O) so it is unit-testable without a terminal. Side effects (persist,
//! exec) happen in the loop *after* `on_key`, never inside it. The terminal is
//! fully restored via [`TerminalGuard`]'s drop *before* `main` calls
//! [`sshrack_core::connect::launch`], so ssh never writes into the alternate
//! screen.

use std::collections::HashMap;

use crate::cli::Cli;
use crate::cli::args::{Command, ConnectOptions, CredAction, HostAction};
use sshrack_core::config::path as config_path;
use sshrack_core::config::schema::{Host, SecretStore, SshrackConfig};
use sshrack_core::config::store as config_store;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::host;
use sshrack_core::secret::{OsKeyring, SecretBackend};
use ulid::Ulid;

pub mod app;
pub(crate) mod browser_core;
pub mod connect;
pub mod cred_panel;
pub mod dialog;
pub mod file_picker;
pub mod fit;
pub mod help;
pub mod intent;
pub mod launcher;
pub mod panel;
pub mod parts;
pub mod persist;
pub mod popup;
pub mod prompt;
pub mod run_loop;
pub mod settings;
pub mod shell;
pub mod store;
pub mod tab;
pub mod term;
pub mod theme;
pub mod transfer;
pub mod wizard;

#[cfg(test)]
mod test_support;

pub use app::App;
pub use intent::{Outcome, Overlay, Status};
pub use run_loop::run_loop;
pub use term::{TerminalGuard, TerminalHandle, Tui};

/// Reverse lookup from a credential ULID to its display name, built once at
/// startup from the loaded config. Lets the launcher show `Auth::Ref` targets
/// by name without re-scanning the credential table on every render.
pub type CredentialNames = HashMap<Ulid, String>;

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
    /// Temp files holding a pasted inline identity key, when the resolved
    /// auth's key was inline material. `main` MUST hold this across
    /// [`sshrack_core::connect::launch`] — its `Drop` removes the temp files so
    /// the plaintext does not outlive ssh. `None` for path-key / no-key hosts.
    pub key_artifact: Option<sshrack_core::connect::KeyArtifact>,
}

/// The default store mode to apply when a freshly-loaded config has not chosen
/// one yet (`store` is `None`). Returns `Keyring` when the OS keyring is
/// available, so a desktop user lands in the safest mode with zero prompts;
/// returns `None` when the keyring is absent (headless / no D-Bus), leaving the
/// config undecided so the existing first-password-save prompt handles it.
///
/// Pure: the caller performs the keyring probe and passes the boolean.
fn auto_default_store_mode(undecided: bool, keyring_available: bool) -> Option<SecretStore> {
    (undecided && keyring_available).then_some(SecretStore::Keyring)
}

/// TUI entry point. Returns `Ok(None)` when the user quits without connecting,
/// `Ok(Some(req))` when the TUI wants `main` to exec ssh after terminal
/// restore, or `Err` if terminal setup failed.
///
/// Loads the config (hosts + named credentials) and the frecency table from
/// core *before* entering the alternate screen, so the launcher has data ready
/// to render on the first frame. A missing config or frecency file is treated
/// as empty (a fresh install shows an empty-state message, not an error).
///
/// The [`TerminalGuard`] owns the terminal and is dropped at the end of this
/// function (raw mode off, alternate screen left), so by the time the
/// `Option<ConnectRequest>` reaches `main` the terminal is fully restored.
pub fn run(cli: &Cli) -> Result<Option<ConnectRequest>, SshrackError> {
    // Load core data before touching the terminal: a load error should reach
    // the user on their normal terminal, not the alternate screen.
    let config_path = config_path::resolve(cli.config.as_deref());
    let mut cfg = config_path
        .as_ref()
        .map(|p| config_store::load(p))
        .transpose()?
        .unwrap_or_default();

    // Auto-default the store mode: if the loaded config is undecided and the
    // OS keyring is available, adopt keyring silently so a desktop user never
    // sees the store-undecided state. When the keyring is absent the config
    // stays undecided and the first password save will prompt (existing path).
    // Best-effort persist: a write failure is non-fatal — the in-memory mode
    // is correct for this session and the next credential/host save rewrites
    // the whole config anyway.
    if let Some(mode) = auto_default_store_mode(cfg.store.is_none(), OsKeyring.available()) {
        cfg.store = Some(mode);
        if let Some(p) = config_path.as_ref() {
            let _ = config_store::save(p, &cfg);
        }
    }

    // Best-effort frecency load: a missing/corrupt file is an empty table,
    // never a reason to strand the user.
    let data_dir = config_path::default_data_dir();
    let frecency = data_dir
        .as_ref()
        .map(|d| frecency::store::load(d).unwrap_or_default())
        .unwrap_or_default();

    let credential_names: CredentialNames = cfg
        .credentials
        .iter()
        .map(|c| (c.id, c.name.clone()))
        .collect();

    // Entry routing: which view opens first depends on the subcommand that
    // routed us here. `entry_mode` only signals the tab landing now — the
    // transfer target (if any) is resolved below.
    let entry_mode = entry_mode_from_cmd(cli.cmd.as_ref());
    // Resolve the sftp entry target (saved name OR address literal) BEFORE the
    // alternate screen: an unknown name / dangling --credential /
    // address-without-identity errors here, on the normal terminal, mapped to
    // exit NOT_FOUND by
    // main (mirroring the CLI connect path). Non-sftp commands resolve to None.
    let pending_transfer_host = resolve_transfer_target(cli.cmd.as_ref(), &cfg, &cli.connect_opts)?;

    let app = App::new(cfg, config_path, frecency, credential_names);

    let guard = TerminalGuard::enter()?;
    let mut app = app;
    // Hand off the entry-routed transfer id (if any). The first tick of
    // run_loop drains this and opens the transfer screen directly, mirroring
    // an `Outcome::OpenTransfer` without polluting `App::on_key` with a
    // phantom outcome.
    if let Some(h) = pending_transfer_host {
        app.pending_transfer_host = Some(h);
    }
    // Entry routing: which view opens first depends on the subcommand that
    // routed us here. `route_is_tui` already guaranteed one of: bare, empty
    // `host add|edit`, empty `cred add|edit`, or `sftp <name>`. Mirror that
    // user intent by opening the matching wizard up front (otherwise the
    // launcher opens, the user has to press ^a/^e/c, and `sshrack cred add`
    // would surprise them by landing on the host list). For `Transfer` the
    // tab landing is applied here; the actual screen open happens via
    // `pending_transfer_host` in run_loop.
    app.apply_entry_mode(entry_mode);
    // A weak handle the prompt layer (vault popup, host-key popup) upgrades to
    // borrow the terminal for rendering. Cloned from the guard so it goes dead
    // the moment the guard drops (RAII restore), never keeping the Tui alive.
    let handle = guard.handle();
    // run_loop draws frames by borrowing the shared Rc<RefCell<Tui>> for ONE
    // draw at a time (the RefMut is dropped before any key read or side
    // effect). That narrow borrow is load-bearing: the popup paths re-borrow
    // the terminal by upgrading `handle`, and a long-lived outer RefMut would
    // panic on "already borrowed" (Critical #1). The guard still owns the
    // strong Rc, so RAII restore (LeaveAlternateScreen + disable_raw_mode)
    // still runs when `guard` drops at function return — on every path: plain
    // quit, connect return, or early return from run_loop.
    let terminal = guard.terminal();
    let request = run_loop(&terminal, &mut app, handle, data_dir.as_deref());
    Ok(request)
}

/// Which view the TUI should open first, derived from the subcommand that
/// routed it here. `route_is_tui` already filtered to bare / empty-add /
/// empty-edit / `sftp <name>`, so this only needs to distinguish those. Each
/// variant also carries the tab the shell should land on so
/// [`App::apply_entry_mode`] can set `active_tab` before opening the overlay
/// (Task 11 routing contract).
///
/// - `None` (bare `sshrack`) → Hosts tab, no overlay.
/// - `host add` (empty) → Hosts tab + host add wizard; `host edit <name>`
///   (empty) → Hosts tab + host edit wizard.
/// - `cred add` (empty) → Credentials tab + cred add wizard; `cred edit <name>`
///   (empty) → Credentials tab + cred edit wizard.
/// - `sftp <name>` → Hosts tab; the transfer screen opens on the first
///   `run_loop` tick via `App::pending_transfer_host` (resolved to a Host in
///   [`run`] before the alternate screen, so an unknown name errors out on the
///   normal terminal with `exit_code::NOT_FOUND`).
pub(super) enum EntryMode {
    /// Bare `sshrack` — open the host launcher.
    Launcher,
    /// Empty `host add` (add wizard) or `host edit <name>` (edit wizard). Lands
    /// on the Hosts tab.
    HostWizard { edit_name: Option<String> },
    /// Empty `cred add` (add wizard) or `cred edit <name>` (edit wizard). Lands
    /// on the Credentials tab.
    CredWizard { edit_name: Option<String> },
    /// `sshrack sftp <name>` — open the transfer screen for the named host on
    /// the first `run_loop` tick. The target (saved name or address literal) is
    /// resolved to a Host in [`run`] by [`resolve_transfer_target`] (reading
    /// the name from `cli.cmd`) before the alternate screen, so this variant
    /// only signals the tab landing — the Host itself lives on
    /// `App::pending_transfer_host`.
    Transfer,
}

impl EntryMode {
    /// The shell tab this entry mode should land on. Read by
    /// [`App::apply_entry_mode`] before the overlay opens, so the panel behind
    /// the overlay already matches the user's intent (e.g. `sshrack cred add`
    /// does not flash the Hosts tab).
    pub(super) fn target_tab(&self) -> tab::Tab {
        use tab::Tab;
        match self {
            EntryMode::Launcher | EntryMode::HostWizard { .. } | EntryMode::Transfer => Tab::Hosts,
            EntryMode::CredWizard { .. } => Tab::Credentials,
        }
    }
}

/// Resolve the `sshrack sftp` entry target into a concrete [`Host`], honoring
/// the merged `--credential`/`--user`/`--port`/`--identity` flags exactly like
/// the ssh/scp connect path — a thin wrapper over
/// [`host::resolve_target`]. Returns `Ok(None)` when the CLI is not an `sftp`
/// command. The returned user is the effective login-user override for the
/// worker (`user@` > `-l`).
///
/// Pure: no I/O, no terminal. The sftp entry path in [`run`] calls this BEFORE
/// the alternate screen so an unknown name, a dangling `--credential`, or an
/// address target without an identity errors out on the normal terminal
/// (mirroring the CLI connect path's fail-fast-before-network rule). The
/// credential name is resolved to an id here (and only here) for the same
/// reason — a dangling `-c` errors before any popup or connection.
fn resolve_transfer_target(
    cmd: Option<&Command>,
    cfg: &SshrackConfig,
    top: &ConnectOptions,
) -> Result<Option<(Host, Option<String>)>, SshrackError> {
    let Some(Command::Sftp { opts, name }) = cmd else {
        return Ok(None);
    };
    let merged = opts.clone().overlay(top);
    let cred_ulid = match merged.credential.as_deref() {
        None => None,
        Some(cname) => Some(
            cfg.find_credential_by_name(cname)
                .map(|c| c.id)
                .ok_or_else(|| credential::credential_not_found(cfg, cname))?,
        ),
    };
    let overrides = host::ResolveOverrides {
        credential: cred_ulid,
        port: merged.port,
        user: merged.user.as_deref(),
        identity: merged.identity.as_deref(),
    };
    let resolved = host::resolve_target(cfg, name, &overrides)?;
    let user_override = resolved.target_user.or_else(|| merged.user.clone());
    Ok(Some((resolved.host, user_override)))
}

/// Map the parsed CLI command to an [`EntryMode`]. Only the
/// [`route_is_tui`]-true shapes reach here, so the default is the launcher and
/// every other arm is one of the empty add/edit shapes or `sftp <name>`.
///
/// [`route_is_tui`]: crate::route_is_tui
fn entry_mode_from_cmd(cmd: Option<&Command>) -> EntryMode {
    let Some(cmd) = cmd else {
        return EntryMode::Launcher;
    };
    match cmd {
        Command::Host { action } => match action {
            HostAction::Add { .. } => EntryMode::HostWizard { edit_name: None },
            HostAction::Edit { name, .. } => EntryMode::HostWizard {
                edit_name: name.clone(),
            },
            _ => EntryMode::Launcher,
        },
        Command::Cred { action } => match action {
            CredAction::Add { .. } => EntryMode::CredWizard { edit_name: None },
            CredAction::Edit { name, .. } => EntryMode::CredWizard {
                edit_name: name.clone(),
            },
            _ => EntryMode::Launcher,
        },
        Command::Sftp { .. } => EntryMode::Transfer,
        _ => EntryMode::Launcher,
    }
}

#[cfg(test)]
mod tests {
    //! Decision-table tests for [`entry_mode_from_cmd`]: each `route_is_tui`-
    //! true shape maps to the wizard that matches user intent AND carries the
    //! tab the shell should land on (Task 11 routing contract).
    use super::*;
    use crate::cli::args::{Command, CredAction, HostAction};
    use crate::tui::tab::Tab;
    use sshrack_core::config::schema::{Auth, CredentialBody};
    use ulid::Ulid;

    #[test]
    fn bare_maps_to_launcher() {
        let mode = entry_mode_from_cmd(None);
        assert!(matches!(mode, EntryMode::Launcher));
        assert_eq!(mode.target_tab(), Tab::Hosts, "bare lands on Hosts tab");
    }

    #[test]
    fn host_add_empty_maps_to_host_add_wizard() {
        let cmd = Command::Host {
            action: HostAction::Add {
                name: None,
                host: None,
                user: None,
                port: None,
                ssh_args: None,
                identity: None,
                identity_stdin: false,
                identity_file: None,
                certificate_stdin: false,
                certificate_file: None,
                credential: None,
                force: false,
            },
        };
        let mode = entry_mode_from_cmd(Some(&cmd));
        assert!(matches!(mode, EntryMode::HostWizard { edit_name: None }));
        assert_eq!(mode.target_tab(), Tab::Hosts);
    }

    #[test]
    fn host_edit_named_maps_to_host_edit_wizard() {
        let cmd = Command::Host {
            action: HostAction::Edit {
                name: Some("web".into()),
                host: None,
                user: None,
                port: None,
                ssh_args: None,
                identity: None,
                identity_stdin: false,
                identity_file: None,
                certificate_stdin: false,
                certificate_file: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
                clear_ssh_args: false,
                clear_credential: false,
            },
        };
        let mode = entry_mode_from_cmd(Some(&cmd));
        assert!(matches!(
            &mode,
            EntryMode::HostWizard { edit_name: Some(n) } if n == "web"
        ));
        assert_eq!(mode.target_tab(), Tab::Hosts);
    }

    #[test]
    fn cred_add_empty_maps_to_cred_add_wizard() {
        let cmd = Command::Cred {
            action: CredAction::Add {
                name: None,
                user: None,
                identity: None,
                identity_stdin: false,
                identity_file: None,
                certificate_stdin: false,
                certificate_file: None,
                force: false,
            },
        };
        let mode = entry_mode_from_cmd(Some(&cmd));
        assert!(matches!(mode, EntryMode::CredWizard { edit_name: None }));
        assert_eq!(
            mode.target_tab(),
            Tab::Credentials,
            "`cred add` lands on Credentials tab"
        );
    }

    #[test]
    fn cred_edit_named_maps_to_cred_edit_wizard() {
        let cmd = Command::Cred {
            action: CredAction::Edit {
                name: Some("ops".into()),
                user: None,
                identity: None,
                identity_stdin: false,
                identity_file: None,
                certificate_stdin: false,
                certificate_file: None,
                clear_identity: false,
                rename: None,
            },
        };
        let mode = entry_mode_from_cmd(Some(&cmd));
        assert!(matches!(
            &mode,
            EntryMode::CredWizard { edit_name: Some(n) } if n == "ops"
        ));
        assert_eq!(mode.target_tab(), Tab::Credentials);
    }

    #[test]
    fn auto_default_picks_keyring_when_undecided_and_available() {
        assert_eq!(
            auto_default_store_mode(true, true),
            Some(SecretStore::Keyring)
        );
    }

    // `sshrack sftp <name>` maps to EntryMode::Transfer, which lands on the
    // Hosts tab. The host name is resolved in `run` (via
    // `resolve_transfer_target`, reading it from `cli.cmd`) before the
    // alternate screen; the variant no longer carries the name.

    #[test]
    fn sftp_maps_to_transfer_entry_mode_on_hosts_tab() {
        let cmd = Command::Sftp {
            opts: crate::cli::args::ConnectOptions::default(),
            name: "web1".into(),
        };
        let mode = entry_mode_from_cmd(Some(&cmd));
        assert!(matches!(mode, EntryMode::Transfer));
        assert_eq!(
            mode.target_tab(),
            Tab::Hosts,
            "sftp entry lands on the Hosts tab (transfer opens over it)"
        );
    }

    // ---- resolve_transfer_target: the `sshrack sftp` entry honors
    // the per-connection overrides exactly like the ssh/scp connect path
    // (host::resolve_target). Pure; no terminal, no I/O. ----

    fn named_host_cfg() -> SshrackConfig {
        // One saved host named "web1"; an address like "10.0.0.4" is NOT a name.
        SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web1".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                ssh_args: None,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..Default::default()
        }
    }

    fn sftp_cmd(name: &str, opts: ConnectOptions) -> Command {
        Command::Sftp {
            opts,
            name: name.into(),
        }
    }

    #[test]
    fn resolve_transfer_target_none_for_non_sftp() {
        // A bare `sshrack` (no subcommand) has no sftp target to resolve.
        let cfg = SshrackConfig::default();
        assert!(
            resolve_transfer_target(None, &cfg, &ConnectOptions::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn resolve_transfer_target_named_host_returns_the_entry() {
        // `sshrack sftp web1` (no overrides) resolves to the saved host as-is
        // with NO user override (the credential user applies).
        let cfg = named_host_cfg();
        let (host, user) = resolve_transfer_target(
            Some(&sftp_cmd("web1", ConnectOptions::default())),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap()
        .expect("named host resolves");
        assert_eq!(host.name, "web1");
        assert_eq!(host.host, "10.0.0.5");
        assert_eq!(host.port, 2222);
        assert_eq!(user, None);
    }

    #[test]
    fn resolve_transfer_target_address_with_credential_builds_ephemeral_ref() {
        // `sshrack -c yushi sftp 192.168.20.18`: address is not a name; the
        // address target builds an ephemeral host whose auth references the
        // credential.
        let cfg = named_host_cfg(); // "192.168.20.18" is not a name here
        // Inject a saved credential named "yushi" so -c resolves to its id.
        let mut cfg = cfg;
        let cred_id = Ulid::new();
        cfg.credentials
            .push(sshrack_core::config::schema::Credential {
                id: cred_id,
                name: "yushi".into(),
                body: CredentialBody::new("deploy"),
            });
        let top = ConnectOptions {
            credential: Some("yushi".into()),
            ..Default::default()
        };
        let (host, user) =
            resolve_transfer_target(Some(&sftp_cmd("192.168.20.18", top.clone())), &cfg, &top)
                .unwrap()
                .expect("address target resolves");
        assert_eq!(host.host, "192.168.20.18");
        assert_eq!(host.port, 22);
        assert_eq!(host.auth.credential_id(), Some(cred_id));
        assert_eq!(user, None, "-c contributes no user override");
    }

    #[test]
    fn resolve_transfer_target_address_with_user_builds_inline_body() {
        // `sshrack --user ryan -p 2222 sftp 10.9.9.9`: an address
        // target with -l builds an ephemeral inline-auth host (a bare word is
        // never an address — the new decision table).
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions {
            user: Some("ryan".into()),
            port: Some(2222),
            ..Default::default()
        };
        let (host, user) =
            resolve_transfer_target(Some(&sftp_cmd("10.9.9.9", opts.clone())), &cfg, &opts)
                .unwrap()
                .expect("address target resolves");
        assert_eq!(host.host, "10.9.9.9");
        assert_eq!(host.port, 2222);
        let body = host.auth.inline_body().expect("inline auth");
        assert_eq!(body.user, "ryan");
        assert_eq!(user, Some("ryan".into()), "-l also flows as the override");
    }

    #[test]
    fn resolve_transfer_target_address_without_identity_errors() {
        // An address target with neither --credential nor --user cannot log
        // in; fail fast (AddressNeedsUser) before the alternate screen.
        let cfg = SshrackConfig::default();
        let err = resolve_transfer_target(
            Some(&sftp_cmd("10.0.0.4", ConnectOptions::default())),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::AddressNeedsUser { .. }
        ));
    }

    #[test]
    fn resolve_transfer_target_dangling_credential_errors() {
        // `-c nope` naming an unknown credential must fail fast (credential
        // not found), NOT fall through to host-not-found.
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions {
            credential: Some("nope".into()),
            ..Default::default()
        };
        let err = resolve_transfer_target(
            Some(&sftp_cmd("web1", opts)),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::CredentialNotFound { .. }
        ));
    }

    #[test]
    fn resolve_transfer_target_named_miss_is_host_not_found() {
        // `sshrack sftp ghost`: unknown name → HostNotFound (the existing
        // pre-Task-2 behavior preserved).
        let cfg = named_host_cfg();
        let err = resolve_transfer_target(
            Some(&sftp_cmd("ghost", ConnectOptions::default())),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::HostNotFound { ref name, .. } if name == "ghost"
        ));
    }

    #[test]
    fn resolve_transfer_target_overlays_top_level_opts() {
        // Top-level flags (`sshrack --user ryan sftp ...`) merge with
        // subcommand flags. Mirrors ConnectOptions::overlay.
        let cfg = SshrackConfig::default();
        let top = ConnectOptions {
            user: Some("ryan".into()),
            ..Default::default()
        };
        // Subcommand opts empty; top-level carries --user.
        let (host, user) = resolve_transfer_target(
            Some(&sftp_cmd("10.0.0.4", ConnectOptions::default())),
            &cfg,
            &top,
        )
        .unwrap()
        .expect("top-level --user applies");
        assert_eq!(host.host, "10.0.0.4");
        assert_eq!(host.auth.inline_body().unwrap().user, "ryan");
        assert_eq!(user, Some("ryan".into()));
    }

    #[test]
    fn resolve_transfer_target_user_at_address_carries_user() {
        // `sshrack sftp root@10.0.0.9`: the @user must reach the worker as the
        // user override (a bare IP without one cannot log in).
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions::default();
        let (host, user) =
            resolve_transfer_target(Some(&sftp_cmd("root@10.0.0.9", opts.clone())), &cfg, &opts)
                .unwrap()
                .expect("sftp command resolves");
        assert_eq!(host.host, "10.0.0.9");
        assert_eq!(
            user,
            Some("root".into()),
            "user@ must reach the worker as the user override"
        );
    }

    #[test]
    fn resolve_transfer_target_dash_l_flows_as_user_override() {
        // -l applies to the sftp entry too now (previously silently ignored
        // on the TUI path).
        let cfg = SshrackConfig::default();
        let top = ConnectOptions::default();
        let opts = ConnectOptions {
            user: Some("admin".into()),
            ..Default::default()
        };
        let (host, user) = resolve_transfer_target(Some(&sftp_cmd("10.0.0.9", opts)), &cfg, &top)
            .unwrap()
            .expect("resolves");
        assert_eq!(host.host, "10.0.0.9");
        assert_eq!(user, Some("admin".into()));
    }

    #[test]
    fn auto_default_never_overrides_a_decided_config() {
        // A user who explicitly chose plaintext or vault must not be silently
        // flipped to keyring on the next launch.
        assert_eq!(auto_default_store_mode(false, true), None);
    }

    #[test]
    fn auto_default_none_when_keyring_absent() {
        // Headless / no D-Bus: stay undecided so the first password save
        // triggers the existing store-pick prompt.
        assert_eq!(auto_default_store_mode(true, false), None);
    }
}
