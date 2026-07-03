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
use crate::cli::args::{Command, CredAction, HostAction};
use sshrack_core::config::path as config_path;
use sshrack_core::config::schema::SecretStore;
use sshrack_core::config::store as config_store;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::secret::{OsKeyring, SecretBackend};
use ulid::Ulid;

pub mod app;
pub mod connect;
pub mod cred_panel;
pub mod dialog;
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

    let app = App::new(cfg, config_path, frecency, credential_names);

    let guard = TerminalGuard::enter()?;
    let mut app = app;
    // Entry routing: which view opens first depends on the subcommand that
    // routed us here. `route_is_tui` already guaranteed one of: bare, empty
    // `host add|edit`, or empty `cred add|edit`. Mirror that user intent by
    // opening the matching wizard up front (otherwise the launcher opens, the
    // user has to press ^a/^e/c, and `sshrack cred add` would surprise them by
    // landing on the host list).
    app.apply_entry_mode(entry_mode_from_cmd(cli.cmd.as_ref()));
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
/// empty-edit, so this only needs to distinguish those. Each variant also
/// carries the tab the shell should land on so [`App::apply_entry_mode`] can
/// set `active_tab` before opening the overlay (Task 11 routing contract).
///
/// - `None` (bare `sshrack`) → Hosts tab, no overlay.
/// - `host add` (empty) → Hosts tab + host add wizard; `host edit <name>`
///   (empty) → Hosts tab + host edit wizard.
/// - `cred add` (empty) → Credentials tab + cred add wizard; `cred edit <name>`
///   (empty) → Credentials tab + cred edit wizard.
pub(super) enum EntryMode {
    /// Bare `sshrack` — open the host launcher.
    Launcher,
    /// Empty `host add` (add wizard) or `host edit <name>` (edit wizard). Lands
    /// on the Hosts tab.
    HostWizard { edit_name: Option<String> },
    /// Empty `cred add` (add wizard) or `cred edit <name>` (edit wizard). Lands
    /// on the Credentials tab.
    CredWizard { edit_name: Option<String> },
}

impl EntryMode {
    /// The shell tab this entry mode should land on. Read by
    /// [`App::apply_entry_mode`] before the overlay opens, so the panel behind
    /// the overlay already matches the user's intent (e.g. `sshrack cred add`
    /// does not flash the Hosts tab).
    pub(super) fn target_tab(&self) -> tab::Tab {
        use tab::Tab;
        match self {
            EntryMode::Launcher | EntryMode::HostWizard { .. } => Tab::Hosts,
            EntryMode::CredWizard { .. } => Tab::Credentials,
        }
    }
}

/// Map the parsed CLI command to an [`EntryMode`]. Only the
/// [`route_is_tui`]-true shapes reach here, so the default is the launcher and
/// every other arm is one of the empty add/edit shapes.
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
                identity: None,
                identity_stdin: false,
                identity_file: None,
                certificate_stdin: false,
                certificate_file: None,
                rename: None,
                credential: None,
                clear_identity: false,
                clear_password: false,
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
