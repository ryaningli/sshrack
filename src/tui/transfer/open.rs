//! `open_transfer` — the sftp-screen analogue of
//! [`crate::tui::connect::connect_host`]. Mirrors `connect_host`'s auth +
//! vault-unlock, then (instead of building an ssh argv) spawns the
//! [`SftpWorker`] and seeds a fresh [`TransferScreen`]. The host-key
//! pre-flight (was step 5 here, synchronous on the UI thread) moved onto the
//! worker thread in Task 2 — it surfaces via `WorkerEvent::HostKeyNeedsConfirm`
//! and an in-screen overlay, so `open_transfer` is now purely local work
//! (vault/auth/inline-key) + `spawn` + screen seed and never touches the
//! network.
//!
//! ## Cancel vs error
//!
//! A user cancel inside the vault popup (Esc / Ctrl-C) surfaces as
//! [`SshrackError::Interrupted`]; [`crate::tui::run_loop`] maps that to "return
//! to the launcher" — NOT an exit and NOT a status write. Any other error
//! (vault unlock failed, dangling credential, no-password-no-key, worker spawn
//! failed) is surfaced in the status bar via `App::report_failure` and returns
//! to the launcher. Host-key reject / cancel is owned by the worker thread now
//! and arrives as `WorkerEvent::ConnectFailed`.
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

use std::path::{Path, PathBuf};

use sshrack_core::config::schema::{Host, SshrackConfig};
use sshrack_core::connect::sftp::SftpWorker;
use sshrack_core::connect::ssh::Overrides;
use sshrack_core::connect::{self, KeyArtifact};
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::vault;

use crate::tui::TerminalHandle;
use crate::tui::app::App;
use crate::tui::prompt::TuiPassphrase;
use crate::tui::transfer::screen::TransferScreen;

/// Run all pre-open side effects for an sftp session on `host` and seed a
/// fresh [`TransferScreen`] on [`App::transfer`] with the [`SftpWorker`] on
/// [`App::transfer_worker`]. Mirrors [`connect_host`]'s steps 1–4
/// (auth/hostkey), then opens the worker and seeds the remote pane.
///
/// Side effects, in order:
/// 1. Carry the resolved `host` + `user_override` — the caller (launcher
///    `Ctrl-T`, or the `sshrack sftp` entry) already resolved the target (a
///    saved name OR an ad-hoc literal built by `host::resolve_target`), so
///    there is no id→host re-lookup here. An ad-hoc host is never in the
///    config. The override carries the entry target's embedded `user@`/`-l`
///    (previously the sftp entry ignored `-l` entirely — fixed here);
///    `None` for the launcher Ctrl-T path.
/// 2. Vault unlock via [`TuiPassphrase`] (no-op unless vault mode).
/// 3. Resolve auth → [`credential::PasswordSource`] (dangling ref fails here).
/// 4. Materialize an inline (pasted) key to a temp file so `ssh -i` can read
///    it. The [`KeyArtifact`] is stored on [`App::transfer_key_artifact`] so
///    its `Drop` runs only when the screen closes (the master `ssh -N` needs
///    the temp file for its whole lifetime).
/// 5. Spawn the [`SftpWorker`] (master `ssh -N` + worker thread). The host-key
///    pre-flight (ssh-keyscan + fingerprint confirm) runs ON the worker thread
///    and surfaces via `WorkerEvent::HostKeyNeedsConfirm` for an unknown host.
/// 6. Build a [`TransferScreen`] seeded with cwd = local `current_dir`, remote
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
    host: Host,
    user_override: Option<String>,
    app: &mut App,
    handle: TerminalHandle,
    _data_dir: Option<&Path>,
) -> Result<(), SshrackError> {
    let cfg: &SshrackConfig = app.config();

    // ── Step 1: Carry the resolved host. The caller already resolved it (saved
    // name or ad-hoc literal), so there is no id→host lookup to redo. ─────────
    let resolved_host = host;

    // ── Step 2: Vault unlock (no-op unless vault mode). ──────────────────────
    let passphrase_provider = TuiPassphrase::new(handle.clone());
    let env_pw = vault::passphrase_from_env();
    let vault_key = vault::ensure_unlocked_vault_key(cfg, env_pw.as_ref(), &passphrase_provider)?;

    // ── Step 3: Resolve auth → PasswordSource (dangling ref fails here). ─────
    let backend = OsKeyring;
    let mut resolved_auth = credential::resolve(&resolved_host, cfg, vault_key.as_ref(), &backend)?;

    // ── Step 4: Materialize an inline (pasted) key to a temp file so the
    // master `ssh -N` can read it with `ssh -i`. The artifact's Drop MUST out-
    // live the master, so it is carried onto App for the screen's lifetime
    // (dropped when the screen closes alongside the worker). ──────────────────
    let key_artifact: Option<KeyArtifact> = connect::materialize_inline_key(&mut resolved_auth)?;

    // No up-front rejection for password-less, key-less hosts: system ssh
    // falls back to ~/.ssh/id_* and ssh-agent just like the SSH connect path
    // (see `connect_opts`: "ssh-agent handles the rest"). A host that truly
    // has no credential fails inside the master and is reported by the
    // tty-safe deny path — mirroring SSH, not pre-empting it.

    // Capture the remote pane title before `resolved_auth` / `resolved_host`
    // are moved into SftpWorker::spawn below. Prefer the host's friendly name;
    // fall back to "<user>@<host>" for an unnamed (e.g. ad-hoc) host.
    let remote_title = remote_title(
        &resolved_host.name,
        &resolved_auth.user,
        &resolved_host.host,
    );

    // ── Step 5: Spawn the SftpWorker (non-blocking). ────────────────────────
    // The host-key pre-flight + master handshake + `sftp pwd` ALL run ON the
    // worker thread and surface later as WorkerEvent::HostKeyNeedsConfirm /
    // Connected / ConnectFailed. The screen is shown immediately in a
    // Connecting state; the run-loop drain surfaces the host-key overlay for
    // an unknown host, flips to Connected (building the RemotePathSearch +
    // sending the first List there), or surfaces ConnectFailed.
    //
    // resolved_auth.password is moved into SftpWorker::spawn; clone it first so
    // we can hand an owned PasswordSource in (it carries a Zeroizing<String>
    // for the inline case which cannot be shared by reference). config_path is
    // forwarded so the plaintext-mode config channel reads the same file the
    // parent loaded.
    let self_exe = connect::current_exe()?;
    let pw_source = resolved_auth.password.clone();
    let worker = SftpWorker::spawn(
        resolved_auth,
        resolved_host,
        Overrides {
            user: user_override,
            ..Default::default()
        },
        &self_exe,
        pw_source,
        app.config_path(),
        sshrack_core::connect::sftp::SftpBin::default(),
    )
    .map_err(|detail| SshrackError::SftpOpenFailed { detail })?;

    // ── Step 6: Build the screen (Connecting), seed local pane, store on App. ─
    // local cwd = the user's actual cwd; remote cwd = `/` placeholder
    // (corrected on Connected when the worker reports home). The remote
    // path-aware searcher + the first `List(home)` are NOT built here — they
    // move to the Connected drain arm (target/sock are live only post-connect,
    // and the worker handle exposes neither, so they ride the Connected event).
    let local_cwd = std::env::current_dir()?;
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/"));
    screen.remote_title = remote_title;
    // `connect` defaults to Connecting (the handshake is in flight on the
    // worker thread). `remote.loading` stays true so the pane shows its
    // loading indicator until Connected lands + the first Listing arrives.
    screen.remote.loading = true;

    // Seed the local pane now (the local fs is fast and synchronous) so it is
    // not blank until the first keypress. Mirrors what drain_transfer_events
    // does on navigation; a failure here is non-fatal — the status row surfaces
    // it and the pane just stays empty until the user navigates.
    {
        use sshrack_core::dirsource::{DirSource, LocalDirSource};
        screen.local.loading = true;
        match LocalDirSource::new().list(&local_cwd) {
            Ok(entries) => {
                screen.local_mut().set_entries(entries);
                screen.local.loading = false;
            }
            Err(msg) => {
                screen.local.loading = false;
                screen.set_status(crate::tui::intent::Status::error(format!(
                    "local list failed: {msg}"
                )));
            }
        }
    }

    app.transfer = Some(screen);
    app.transfer_worker = Some(worker);
    app.transfer_key_artifact = key_artifact;
    Ok(())
}

/// Build the remote pane's title: prefer the host's friendly `name`; fall back
/// to `<user>@<host>` when there is no real name. A saved host carries a name
/// distinct from its address; an ad-hoc host (built by `host::resolve_target`'s
/// `address_host`) has `name == address` — no real name — so it shows
/// `<user>@<host>` to surface the login identity. Pure.
fn remote_title(name: &str, user: &str, host: &str) -> String {
    if name.is_empty() || name == host {
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
    use ulid::Ulid;

    fn host_with_inline_user(name: &str) -> Host {
        Host {
            id: Ulid::new(),
            name: name.into(),
            host: "h.example".into(),
            port: 22,
            ssh_args: None,
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
    fn remote_title_shows_user_at_host_for_an_ad_hoc_address_name() {
        // An ad-hoc host built by host::resolve_target carries name == address;
        // the title surfaces the login user (user@ip), not the bare address.
        assert_eq!(
            remote_title("192.168.20.18", "yushi", "192.168.20.18"),
            "yushi@192.168.20.18"
        );
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
        let auth = credential::resolve(&host, &cfg, None, &OsKeyring).unwrap();
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

    #[test]
    fn master_argv_carries_the_user_override_as_dash_l() {
        // REGRESSION: the sftp entry used to pass `Overrides::default()` to
        // SftpWorker::spawn, so `-l` (and the target's embedded `user@`) was
        // silently ignored on the TUI path — the worker logged in as the
        // credential user instead. open_transfer now threads the resolved
        // user override into the Overrides; pin that it lands as `-l <user>`,
        // beating the resolved auth user.
        let host = host_with_inline_user("web"); // inline user "u"
        let cfg = SshrackConfig::default();
        let auth = credential::resolve(&host, &cfg, None, &OsKeyring).unwrap();
        let sock = Path::new("/tmp/sshrack-mux-test.sock");
        let argv = master_argv(
            &auth,
            &host,
            &Overrides {
                user: Some("admin".into()),
                ..Default::default()
            },
            sock,
        );
        let has_override = argv.windows(2).any(|w| w[0] == "-l" && w[1] == "admin");
        assert!(
            has_override,
            "the user override must beat the credential user in the master argv: {argv:?}"
        );
        assert!(
            !argv.windows(2).any(|w| w[0] == "-l" && w[1] == "u"),
            "the credential user must NOT also appear as -l: {argv:?}"
        );
    }
}
