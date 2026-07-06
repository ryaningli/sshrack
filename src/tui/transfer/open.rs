//! `open_transfer` — the sftp-screen analogue of
//! [`crate::tui::connect::connect_host`]. Mirrors `connect_host`'s auth +
//! vault-unlock + host-key pre-flight, then (instead of building an ssh argv)
//! spawns the [`SftpWorker`] and seeds a fresh [`TransferScreen`].
//!
//! ## Cancel vs error
//!
//! A user cancel inside the vault or host-key popup (Esc / Ctrl-C) surfaces as
//! [`SshrackError::Interrupted`]; [`crate::tui::run_loop`] maps that to "return
//! to the launcher" — NOT an exit and NOT a status write. Any other error
//! (vault unlock failed, host key rejected, dangling credential, worker spawn
//! failed) is shown in the status line and also returns to the launcher.
//!
//! ## Inline-key lifetime (load-bearing)
//!
//! [`materialize_inline_key`][sshrack_core::connect::materialize_inline_key]
//! writes a pasted private key to a `0600` temp file and returns a
//! [`KeyArtifact`][sshrack_core::connect::KeyArtifact] whose `Drop` deletes it.
//! For an interactive `ssh` call the artifact only needs to outlive
//! [`connect::launch`]; for the transfer screen the master `ssh -N` it points
//! at lives for the whole sftp session, so the artifact CANNOT drop at the end
//! of `open_transfer`. It is stored on [`App::transfer_key_artifact`] and
//! dropped when the screen closes (which also drops the worker → `ssh -O
//! exit` + kill). For a path-key or no-key host the artifact is `None`.

use std::path::Path;

use sshrack_core::config::schema::SshrackConfig;
use sshrack_core::connect::sftp::SftpWorker;
use sshrack_core::connect::ssh::Overrides;
use sshrack_core::connect::{self, KeyArtifact};
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::hostkey;
use sshrack_core::secret::vault;

use ulid::Ulid;

use crate::tui::TerminalHandle;
use crate::tui::app::App;
use crate::tui::prompt::{TuiPassphrase, host_key_confirm};
use crate::tui::transfer::screen::TransferScreen;

use sshrack_core::error::DidYouMean;

/// Run all pre-open side effects for an sftp session on `host_id` and seed a
/// fresh [`TransferScreen`] on [`App::transfer`] with the [`SftpWorker`] on
/// [`App::transfer_worker`]. Mirrors [`connect_host`]'s steps 1–4
/// (auth/hostkey), then opens the worker and seeds the remote pane.
///
/// Side effects, in order:
/// 1. Look up the host by id (no name to resolve — the launcher picked it).
/// 2. Vault unlock via [`TuiPassphrase`] (no-op unless vault mode).
/// 3. Resolve auth → [`credential::PasswordSource`] (dangling ref fails here).
/// 4. Materialize an inline (pasted) key to a temp file so `ssh -i` can read
///    it. The [`KeyArtifact`] is stored on [`App::transfer_key_artifact`] so
///    its `Drop` runs only when the screen closes (the master `ssh -N` needs
///    the temp file for its whole lifetime).
/// 5. Host-key pre-flight via the TUI confirm closure (popup for new keys).
/// 6. Spawn the [`SftpWorker`] (master `ssh -N` + worker thread).
/// 7. Build a [`TransferScreen`] seeded with cwd = local `current_dir`, remote
///    = the worker's reported home, and send `WorkerCmd::List(home)` so the
///    remote pane populates once the worker drains the command.
///
/// `data_dir` is accepted for symmetry with [`connect_host`] but unused: an
/// sftp session does not record frecency (frecency tracks interactive connect
/// targets, not transfer sessions). Kept in the signature so the loop's
/// `Outcome::OpenTransfer` arm parallels the `ConnectRequested` arm and a
/// future change (e.g. frecency-ranking recently-transferred-to hosts) needs
/// no plumbing change.
///
/// [`connect_host`]: crate::tui::connect::connect_host
pub fn open_transfer(
    host_id: Ulid,
    app: &mut App,
    handle: TerminalHandle,
    _data_dir: Option<&Path>,
) -> Result<(), SshrackError> {
    let cfg: &SshrackConfig = app.config();

    // ── Step 1: Look up the host by id (launcher already chose it). ──────────
    let host = cfg
        .find_host_by_id(&host_id)
        .ok_or(SshrackError::HostNotFound {
            name: host_id.to_string(),
            // See connect_host for the rationale: the id is internal, no
            // did-you-mean over a bare ULID is useful, and this branch is
            // unreachable in normal use (the launcher only hands out ids from
            // the loaded config). An empty hint keeps the message clean.
            hint: DidYouMean::none(),
        })?;
    let port = host.port;
    let resolved_host = host.clone();

    // ── Step 2: Vault unlock (no-op unless vault mode). ──────────────────────
    let passphrase_provider = TuiPassphrase::new(handle.clone());
    let env_pw = vault::passphrase_from_env();
    let vault_key = vault::ensure_unlocked_vault_key(cfg, env_pw.as_ref(), &passphrase_provider)?;

    // ── Step 3: Resolve auth → PasswordSource (dangling ref fails here). ─────
    let mut resolved_auth = credential::resolve(&resolved_host, cfg, vault_key.as_ref())?;

    // ── Step 4: Materialize an inline (pasted) key to a temp file so the
    // master `ssh -N` can read it with `ssh -i`. The artifact's Drop MUST out-
    // live the master, so it is carried onto App for the screen's lifetime
    // (dropped when the screen closes alongside the worker). ──────────────────
    let key_artifact: Option<KeyArtifact> = connect::materialize_inline_key(&mut resolved_auth)?;

    // ── Step 5: Host-key pre-flight via the TUI confirm closure. ─────────────
    // A cancel inside the popup (Ctrl-C/Esc) flips the shared flag; we re-
    // surface that as Interrupted so run_loop returns the user to the launcher
    // (no status write), NOT the HostKeyNotConfirmed "sftp open failed" path.
    let host_str = resolved_host.host.as_str();
    // Capture the remote pane title before `resolved_auth` / `resolved_host`
    // are moved into SftpWorker::open below. Prefer the host's friendly name;
    // fall back to "<user>@<host>" for an unnamed (e.g. ad-hoc) host.
    let remote_title = remote_title(
        &resolved_host.name,
        &resolved_auth.user,
        &resolved_host.host,
    );
    let (confirm, interrupted) = host_key_confirm(handle);
    hostkey::run_host_key_flow(host_str, port, confirm)?;
    if interrupted.get() {
        return Err(SshrackError::Interrupted);
    }

    // ── Step 6: Spawn the SftpWorker (master + worker thread). ───────────────
    // resolved_auth.password is moved into SftpWorker::open; clone it first so
    // we can hand an owned PasswordSource in (it carries a Zeroizing<String>
    // for the inline case which cannot be shared by reference).
    let self_exe = connect::current_exe()?;
    let pw_source = resolved_auth.password.clone();
    let (worker, home) = SftpWorker::open(
        resolved_auth,
        resolved_host,
        Overrides::default(),
        &self_exe,
        pw_source,
    )
    .map_err(|detail| SshrackError::SftpOpenFailed { detail })?;

    // ── Step 7: Build the screen, seed the remote pane, store on App. ────────
    // local cwd = the user's actual cwd when they invoked the TUI; remote cwd
    // = the worker's reported home (falls back to `/` when sftp `pwd` failed
    // inside worker::open, so the screen still renders). Send an initial
    // `List(home)` so the remote pane populates as soon as the worker drains
    // its command queue.
    let local_cwd = std::env::current_dir()?;
    let mut screen = TransferScreen::new(local_cwd.clone(), home.clone());
    screen.remote_title = remote_title;
    worker.send(sshrack_core::connect::sftp::proto::WorkerCmd::List(home));

    // Seed the local pane now (the local fs is fast and synchronous) so it is
    // not blank until the first keypress. Mirrors what drain_transfer_events
    // does on navigation; a failure here is non-fatal — the status row surfaces
    // it and the pane just stays empty until the user navigates.
    {
        use sshrack_core::dirsource::{DirSource, LocalDirSource};
        match LocalDirSource::new().list(&local_cwd) {
            Ok(entries) => screen.local_mut().set_entries(entries),
            Err(msg) => screen.set_status(crate::tui::intent::Status::error(format!(
                "local list failed: {msg}"
            ))),
        }
    }

    app.transfer = Some(screen);
    app.transfer_worker = Some(worker);
    app.transfer_key_artifact = key_artifact;
    Ok(())
}

/// Build the remote pane's title: prefer the host's friendly `name`; fall back
/// to `<user>@<host>` when the host is unnamed (e.g. an ad-hoc host) so the
/// bordered block never shows an empty title. Pure.
fn remote_title(name: &str, user: &str, host: &str) -> String {
    if name.is_empty() {
        format!("{user}@{host}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for `open_transfer`'s master argv shape. The full open
    //! path (vault popup, host-key popup, real `ssh -N` spawn, worker thread)
    //! is integration-level: it needs a live terminal handle (the weak ref
    //! upgrades to nothing here) and a real sshd. What IS pure is the argv the
    //! worker's master carries — it reuses `master_argv` on a default host
    //! (no-secret, default port), which we pin here the same way `connect.rs`
    //! pins `connect::ssh::build`. No real ssh is spawned in unit tests.

    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Host};
    use sshrack_core::connect::sftp::master_argv;
    use sshrack_core::connect::ssh::Overrides;
    use sshrack_core::credential;
    use std::path::Path;

    fn host_with_inline_user(name: &str) -> Host {
        Host {
            id: Ulid::new(),
            name: name.into(),
            host: "h.example".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        }
    }

    #[test]
    fn remote_title_prefers_the_host_name() {
        // A saved host is always named — the title is the friendly name, not
        // the user@ip form.
        assert_eq!(remote_title("web1", "ryan", "10.0.0.4"), "web1");
    }

    #[test]
    fn remote_title_falls_back_to_user_at_host_when_unnamed() {
        // An ad-hoc / unnamed host falls back to <user>@<host> so the title is
        // never empty.
        assert_eq!(remote_title("", "ryan", "10.0.0.4"), "ryan@10.0.0.4");
    }

    #[test]
    fn master_argv_shape_for_default_host() {
        // open_transfer calls SftpWorker::open which builds the master via
        // `master_argv(&resolved, &host, &Overrides::default(), sock)`. Pin the
        // shape: it carries the user, the port, the host, ControlMaster=yes,
        // ControlPath=<sock>, and `-N` (no remote command — the master just
        // holds the connection open). No real ssh is spawned here.
        let host = host_with_inline_user("web");
        let cfg = SshrackConfig::default();
        let auth = credential::resolve(&host, &cfg, None).unwrap();
        let sock = Path::new("/tmp/sshrack-mux-test.sock");
        let argv = master_argv(&auth, &host, &Overrides::default(), sock);
        // Master: ssh -N -o ControlMaster=yes ... <user/port via connect_opts> <host>
        assert_eq!(argv[0], "ssh");
        assert!(
            argv.contains(&"-N".to_string()),
            "master must carry -N: {argv:?}"
        );
        let has_cm = argv
            .windows(2)
            .any(|w| w[0] == "-o" && w[1] == "ControlMaster=yes");
        assert!(has_cm, "master must carry ControlMaster=yes: {argv:?}");
        let has_cp = argv.iter().any(|a| a.starts_with("ControlPath="));
        assert!(has_cp, "master must carry a ControlPath option: {argv:?}");
        // User + port + host reach the argv via connect_opts.
        let has_user = argv.windows(2).any(|w| w[0] == "-l" && w[1] == "u");
        assert!(has_user, "master must carry -l u: {argv:?}");
        let has_port = argv.windows(2).any(|w| w[0] == "-p" && w[1] == "22");
        assert!(has_port, "master must carry -p 22: {argv:?}");
        assert!(
            argv.contains(&"h.example".to_string()),
            "master must carry the host token: {argv:?}"
        );
        // The last token is the host (the master carries NO remote command).
        assert_eq!(argv.last().map(String::as_str), Some("h.example"));
    }
}
