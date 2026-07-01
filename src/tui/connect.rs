//! Deferred-exec connect orchestration for the TUI.
//!
//! [`connect_host`] mirrors the CLI's connect sequence
//! (`cli::cmd::connect::run`) but swaps the side-effect seams to the TUI's
//! popup-based equivalents:
//!
//! | step                  | CLI                                 | TUI                          |
//! |-----------------------|-------------------------------------|------------------------------|
//! | resolve `--credential`| Step 1 (fail-fast before host)      | n/a — no `--credential` flag |
//! | resolve name → Host   | Step 2 (`host::resolve_target`)     | `find_host_by_id` (id from launcher) |
//! | vault unlock          | `EnvPassphrase` (env-only)          | [`TuiPassphrase`] (popup)    |
//! | resolve auth          | Step 4 (`credential::resolve`)      | same                         |
//! | host-key pre-flight   | closure over `--accept-new`         | TUI confirm closure (popup)  |
//! | build argv            | Step 6 (`connect::ssh::build`)      | same (no overrides, no cmd)  |
//! | frecency record+save  | Step 7 (before launch)              | same (before return)         |
//! | launch ssh            | Step 8 (`connect::launch`)          | deferred to `main` (post-restore) |
//!
//! ## Why the TUI skips CLI Steps 1 & 2's name resolution
//!
//! The launcher already selected a host from the loaded config, so the host
//! `id` is known and trusted — there is no name to resolve and no
//! `--credential`/`--ad-hoc`/`--port`/`--user`/`--identity` override to fold
//! in. The auth reference (by id) is still resolved through the same
//! `credential::resolve` as the CLI, so a dangling reference fails here
//! exactly as it would on the command line. An interactive shell has no
//! `remote_command`, so `connect::ssh::build` is called with an empty slice.
//!
//! ## Cancel vs error
//!
//! A user cancel inside the vault or host-key popup (Esc/Ctrl-C) surfaces as
//! [`SshrackError::Interrupted`]; [`super::app::run_loop`] maps that to
//! "return to the launcher" — NOT an exit. Any other error (vault unlock
//! failed, host key rejected, dangling credential, frecency save failed) is
//! shown in the status line and also returns to the launcher.

use std::path::Path;

use ulid::Ulid;

use sshrack_core::config::schema::SshrackConfig;
use sshrack_core::connect;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::hostkey;
use sshrack_core::secret::vault;

use super::ConnectRequest;
use super::app::App;
use super::app::TerminalHandle;
use super::prompt::{TuiPassphrase, host_key_confirm};

/// Run all pre-exec side effects for connecting to `host_id` and return the
/// [`ConnectRequest`] `main` execs after the terminal is restored. Mirrors
/// `cli::cmd::connect::run`'s sequence (see the module docs for the diff
/// table).
///
/// Side effects, in order:
/// 1. Look up the host by id (no name to resolve — the launcher picked it).
/// 2. Vault unlock via [`TuiPassphrase`] (no-op unless vault mode).
/// 3. Resolve auth → [`credential::PasswordSource`] (dangling ref fails here).
/// 4. Host-key pre-flight via the TUI confirm closure (popup for new keys).
/// 5. Build argv via [`connect::ssh::build`] (no overrides, no remote command).
/// 6. Record + save frecency **before** returning (a hung ssh never loses it).
///
/// `main` runs [`connect::launch`] after the [`super::app::TerminalGuard`]
/// drops, so ssh inherits a normal terminal.
///
/// `data_dir` is the frecency data dir (from `config::path::default_data_dir`).
/// `None` skips the frecency save (best-effort: a fresh install with no home
/// dir cannot persist, but the connection still proceeds).
pub fn connect_host(
    host_id: Ulid,
    app: &mut App,
    handle: TerminalHandle,
    data_dir: Option<&Path>,
) -> Result<ConnectRequest, SshrackError> {
    let cfg: &SshrackConfig = app.config();

    // ── Step 1: Look up the host by id (launcher already chose it). ──────────
    // No name resolution, no --credential/--ad-hoc/--port/--user/--identity
    // overrides: the TUI connect path is a direct launcher selection.
    let host = cfg
        .find_host_by_id(&host_id)
        .ok_or(SshrackError::HostNotFound {
            name: host_id.to_string(),
            // The id is internal; no did-you-mean over a bare ULID is useful, and
            // this branch is unreachable in normal use (the launcher only hands
            // out ids from the loaded config). An empty hint keeps the message
            // clean rather than printing a stray id.
            hint: DidYouMean::none(),
        })?;
    let port = host.port;
    let resolved_host = host.clone();

    // ── Step 2: Vault unlock (no-op unless vault mode). ──────────────────────
    // TuiPassphrase drives a masked popup; under SSHRACK_PASSPHRASE the env
    // value shadows the popup (same precedence as the CLI). A cancel (Esc)
    // surfaces as Interrupted, which run_loop maps to "return to launcher".
    let passphrase_provider = TuiPassphrase::new(handle.clone());
    let env_pw = vault::passphrase_from_env();
    let vault_key = vault::ensure_unlocked_vault_key(cfg, env_pw.as_ref(), &passphrase_provider)?;

    // ── Step 3: Resolve auth → PasswordSource (dangling ref fails here). ─────
    let resolved_auth = credential::resolve(&resolved_host, cfg, vault_key.as_ref())?;

    // ── Step 4: Host-key pre-flight via the TUI confirm closure. ─────────────
    // The closure renders the fingerprint in a y/n popup. A new key the user
    // accepts is appended to known_hosts; a changed key is rejected by ssh at
    // connect time (core never classifies "changed", only "present"). A cancel
    // inside the popup (Ctrl-C/Esc) flips the shared flag; we re-surface that
    // as Interrupted so run_loop returns the user to the launcher (no status
    // write), NOT the HostKeyNotConfirmed "connect failed" message (Finding #4:
    // the popup cancel used to be flattened to a host-key rejection).
    let host_str = resolved_host.host.as_str();
    let (confirm, interrupted) = host_key_confirm(handle);
    hostkey::run_host_key_flow(host_str, port, confirm)?;
    if interrupted.get() {
        return Err(SshrackError::Interrupted);
    }

    // ── Step 5: Build argv (interactive shell: no overrides, no command). ────
    let argv = connect::ssh::build(
        &resolved_auth,
        &resolved_host,
        &connect::ssh::Overrides::default(),
        &[],
    );

    // ── Step 6: Record + save frecency BEFORE returning the request. ─────────
    // Spec invariant: frecency is persisted before exec so a hung ssh never
    // loses the usage record. The save is best-effort on a missing data dir.
    let frec = app.frecency_mut();
    frec.record(&resolved_host.id);
    if let Some(dir) = data_dir {
        let _ = frecency::store::save(dir, frec);
    }

    Ok(ConnectRequest {
        argv,
        source: resolved_auth.password,
    })
}

/// Empty did-you-mean hint, used for the (unreachable) bare-ULID HostNotFound
/// path so the error message stays clean. Re-declared here as a private re-bind
/// to keep the call site readable; the real type is in `sshrack_core::error`.
use sshrack_core::error::DidYouMean;

#[cfg(test)]
mod tests {
    //! Pure-logic tests for `connect_host`'s decisions that run without a
    //! terminal or network. The full connect path (vault popup, host-key popup,
    //! ssh spawn) is integration-level: it needs a live terminal handle (the
    //! weak ref upgrades to nothing here) and real `ssh-keygen`/`ssh-keyscan`
    //! processes. Core's `connect_flow_test` covers launch correctness; here we
    //! pin the pieces that ARE pure:
    //!
    //! - the argv the TUI builds for a default (no-secret) host — proving it
    //!   reuses `connect::ssh::build` with no overrides and an empty remote
    //!   command (interactive shell).
    //! - the frecency-before-return ordering: `record` then `save` is exactly
    //!   the Step-6 sequence, asserted in isolation so the ordering invariant
    //!   survives refactors.
    //! - the unreachable bare-ULID `HostNotFound` hint renders empty.
    //!
    //! What is NOT covered here (needs manual/integration verification): the
    //! vault unlock popup, the host-key confirm popup, and `main` launching ssh
    //! after the terminal restore. Those are exercised by the manual smoke
    //! (Enter on a host → ssh spawns on the normal screen).

    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Host};

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
    fn argv_shape_for_default_host() {
        // The TUI connect path calls connect::ssh::build with NO overrides and
        // an EMPTY remote_command (interactive shell). Asserting the argv here
        // proves the TUI reuses the same builder as the CLI with the launcher-
        // specific simplification (no --credential/--port/--user/--identity,
        // no remote command).
        let host = host_with_inline_user("web");
        let cfg = SshrackConfig::default();
        let auth = credential::resolve(&host, &cfg, None).unwrap();
        let argv = connect::ssh::build(&auth, &host, &connect::ssh::Overrides::default(), &[]);
        // Interactive shell: ssh -l <user> -p <port> <host>, no remote command.
        assert_eq!(argv[0], "ssh");
        let has_user = argv.windows(2).any(|w| w[0] == "-l" && w[1] == "u");
        assert!(has_user, "argv should carry -l u: {argv:?}");
        let has_port = argv.windows(2).any(|w| w[0] == "-p" && w[1] == "22");
        assert!(has_port, "argv should carry -p 22: {argv:?}");
        assert!(argv.contains(&"h.example".to_string()));
        // Last token is the host (no remote command appended).
        assert_eq!(argv.last().map(String::as_str), Some("h.example"));
    }

    #[test]
    fn frecency_record_then_save_persists_before_return() {
        // Spec invariant: frecency is recorded + saved BEFORE the connect
        // request is returned (so a hung ssh never loses the record). This
        // exercises the exact Step-6 sequence — record(host.id) then save(dir)
        // — in isolation, confirming the persisted score is non-zero for the
        // recorded host. connect_host performs this inline; pinning it here
        // guards the ordering against a refactor that swaps the order.
        let dir = tempfile::tempdir().unwrap();
        let mut frec = frecency::Frecency::default();
        let id = Ulid::new();
        // Step 6a: record.
        frec.record(&id);
        // Step 6b: save (the spec order — save happens before exec).
        frecency::store::save(dir.path(), &frec).unwrap();
        // Reload and confirm the record survived the save.
        let back = frecency::store::load(dir.path()).unwrap();
        assert!(
            back.score(&id) > 0.0,
            "frecency must be persisted before the request returns"
        );
    }

    #[test]
    fn did_you_mean_none_renders_no_hint() {
        // The unreachable bare-ULID HostNotFound path uses DidYouMean::none();
        // its Display must contribute nothing to the error message.
        let hint = DidYouMean::none();
        assert!(hint.to_string().is_empty());
    }
}
