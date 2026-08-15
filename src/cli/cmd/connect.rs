//! Connect-path command handler: resolves a name and launches `ssh`.
//!
//! This module implements the 8-step connect flow that backs both
//! `sshrack ssh <name>` and the `sshrack <name>` shorthand. The steps,
//! in the order the code actually runs them:
//!
//! 1. Resolve `--credential <name>` → `Ulid` (fail-fast if unknown).
//! 2. Resolve the name → [`Host`] (fail-fast: `HostNotFound` + did-you-mean
//!    before any network I/O).
//! 3. If vault mode active: unlock vault via `SSHRACK_PASSPHRASE` (errors if
//!    unset).
//! 4. [`credential::resolve`] → [`ResolvedAuth`].
//! 5. [`hostkey::run_host_key_flow`] — host-key pre-flight (new keys accepted
//!    only with `--accept-new`; changed keys rejected by ssh upstream).
//! 6. [`connect::ssh::build`] → argv.
//! 7. [`frecency::record`] + [`frecency::store::save`] **before** launch
//!    (ephemeral address targets never record — their fresh ULID per call
//!    could never rank).
//! 8. [`connect::launch`].
//!
//! ## Why credential before host (Steps 1 → 2)
//!
//! The credential name must be resolved to a `Ulid` *before* [`Host`]
//! resolution because `host::resolve_target` consumes that `Ulid` inside
//! [`host::ResolveOverrides`]. Resolving the credential first also gives the
//! earlier fail-fast: a dangling `--credential` errors out before any
//! network-touching host-key work runs (consistent with the project rule that
//! local validation precedes network I/O).

use sshrack_core::config::path as config_path;
use sshrack_core::config::store;
use sshrack_core::connect;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::host;
use sshrack_core::hostkey;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::vault;

use crate::cli::args::{Cli, Command};
use crate::shared::exit_code;

/// Dispatch for the `Ssh`/`Connect` arms of the CLI.
///
/// Merges the top-level `--port`/`--user`/`--identity`/`--credential`/
/// `--ad-hoc`/`--accept-new` flags with any subcommand-level flags, then runs
/// the 8-step connect flow. Returns the ssh exit code, or an [`exit_code`]
/// constant on a local error.
pub fn run(cli: &Cli) -> i32 {
    // Extract tokens and per-connection options from the matched arm.
    let (tokens, opts) = match &cli.cmd {
        Some(Command::Ssh { opts, args }) => {
            let merged = opts.clone().overlay(&cli.connect_opts);
            (args.as_slice(), merged)
        }
        Some(Command::Connect(args)) => (args.as_slice(), cli.connect_opts.clone()),
        _ => {
            eprintln!("sshrack: internal error: connect::run called on wrong arm");
            return exit_code::USAGE;
        }
    };

    if tokens.is_empty() {
        eprintln!("sshrack: no host name given");
        return exit_code::USAGE;
    }

    let target = &tokens[0];
    let remote_command = tokens[1..].to_vec();

    // Load config (empty config on a fresh install is OK).
    let config_path = config_path::resolve(cli.config.as_deref());
    let cfg = match config_path.as_ref().map(|p| store::load(p)).transpose() {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => {
            eprintln!("sshrack: config error: {e}");
            return exit_code::USAGE;
        }
    };

    // ── Step 1: Resolve credential name → Ulid BEFORE resolving host. This
    // order is required because host::resolve_target consumes the Ulid via
    // ResolveOverrides (Step 2); it also fails fast on a dangling
    // --credential before any network I/O. ────────────────────────────────────
    let cred_ulid = match opts.credential.as_deref() {
        None => None,
        Some(name) => match cfg.find_credential_by_name(name) {
            Some(c) => Some(c.id),
            None => {
                let err = credential::credential_not_found(&cfg, name);
                eprintln!("sshrack: {err}");
                return exit_code::NOT_FOUND;
            }
        },
    };

    // ── Step 2: Resolve name → Host (fail-fast, no network I/O). ─────────────
    let resolve_overrides = host::ResolveOverrides {
        ad_hoc: opts.ad_hoc,
        credential: cred_ulid,
        port: opts.port,
        user: opts.user.as_deref(),
        identity: opts.identity.as_deref(),
    };
    let resolved = match host::resolve_target(&cfg, target, &resolve_overrides) {
        Ok(r) => r,
        Err(SshrackError::HostNotFound { name, hint }) => {
            eprintln!("sshrack: host not found: {name}{hint}");
            if let Some(hint_line) = crate::cli::cmd::shared::unregistered_host_hint(&name) {
                eprintln!("sshrack: {hint_line}");
            }
            return exit_code::NOT_FOUND;
        }
        Err(e) => {
            eprintln!("sshrack: {e}");
            return exit_code::VALIDATION;
        }
    };
    let resolved_host = resolved.host;
    let port = opts.port.unwrap_or(resolved_host.port);

    // ── Step 3: Vault unlock (no-op when not in vault mode). ─────────────────
    // TtyPassphrase prompts when a human is present; EnvPassphrase reads
    // SSHRACK_PASSPHRASE (errors Interrupted if unset). The env var still wins
    // — ensure_unlocked_vault_key consults it before the provider.
    let passphrase_provider = crate::cli::prompt::passphrase_provider();
    let env_pw = vault::passphrase_from_env();
    let vault_key =
        match vault::ensure_unlocked_vault_key(&cfg, env_pw.as_ref(), &*passphrase_provider) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("sshrack: vault unlock failed: {e}");
                return exit_code::STORE;
            }
        };

    // ── Step 4: Resolve auth (dangling credential errors here). ──────────────
    let backend = OsKeyring;
    let mut resolved_auth =
        match credential::resolve(&resolved_host, &cfg, vault_key.as_ref(), &backend) {
            Ok(a) => a,
            Err(SshrackError::CredentialNotFound { name, hint }) => {
                // The ref-by-id path surfaces a bare ULID as `name` (the host
                // references the credential by id; the credential is missing so no
                // name exists to show). Reword to name the originating host so the
                // message reads like a host problem, not a stray id. CLI-layer
                // concern only — core's `credential::resolve` is unchanged.
                eprintln!(
                    "sshrack: host '{}' references an unknown credential{hint}",
                    resolved_host.name
                );
                let _ = name; // the bare ULID is intentionally not surfaced
                return exit_code::NOT_FOUND;
            }
            Err(SshrackError::VaultLocked) => {
                eprintln!(
                    "sshrack: vault is locked; run `sshrack store unlock` or set SSHRACK_PASSPHRASE"
                );
                return exit_code::STORE;
            }
            Err(e) => {
                eprintln!("sshrack: auth error: {e}");
                return exit_code::CONNECT;
            }
        };

    // ── Step 4b: Materialize an inline (pasted) key to a temp file so ssh -i
    // can read it. The artifact MUST outlive launch — its Drop deletes the
    // temp files. build_argv reads resolved_auth.key_path (now pointing at the
    // temp private path) unchanged; it never sees the key text. ─────────────
    let _key_artifact = match connect::materialize_inline_key(&mut resolved_auth) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sshrack: failed to stage inline identity: {e}");
            return exit_code::CONNECT;
        }
    };

    // ── Step 5: Host-key pre-flight. ─────────────────────────────────────────
    // `--accept-new` takes the Accept path: a first-seen key is auto-accepted
    // (the confirm closure is never called). Without it on a tty, core calls
    // the closure with the full fingerprint and we ask yes/no; without a tty
    // the new key is rejected. Changed keys are always rejected upstream by ssh.
    let host_str = resolved_host.host.as_str();
    let accept_new = opts.accept_new;
    let has_tty = crate::cli::prompt::has_tty();
    let confirm = |fingerprint_text: &str| crate::cli::prompt::prompt_host_key(fingerprint_text);
    if let Err(e) = hostkey::run_host_key_flow(host_str, port, has_tty, accept_new, confirm) {
        eprintln!("sshrack: host key: {e}");
        return exit_code::CONNECT;
    }

    // ── Step 6: Build argv. ───────────────────────────────────────────────────
    // User precedence: `user@` (target_user) > `-l`. The resolved target
    // already stripped the @user, so it must be re-applied here — otherwise a
    // `user@registered-name` connect would silently log in as the credential
    // user.
    let ssh_overrides = connect::ssh::Overrides {
        user: resolved.target_user.clone().or_else(|| opts.user.clone()),
        port: opts.port,
        identity: opts.identity.clone(),
        credential: cred_ulid,
        ad_hoc: opts.ad_hoc,
    };
    let argv = connect::ssh::build(
        &resolved_auth,
        &resolved_host,
        &ssh_overrides,
        &remote_command,
    );

    // ── Step 7: Record frecency BEFORE launch (ephemeral address targets
    // never record — a fresh ULID per call could never rank, only bloat). ──
    if !resolved.ephemeral
        && let Some(dir) = sshrack_core::config::path::default_data_dir()
    {
        let mut frec = frecency::store::load(&dir).unwrap_or_default();
        frec.record(&resolved_host.id);
        let _ = frecency::store::save(&dir, &frec);
    }

    // ── Step 8: Launch ssh. ───────────────────────────────────────────────────
    let self_exe = match connect::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sshrack: cannot determine self path: {e}");
            return exit_code::CONNECT;
        }
    };
    match connect::launch(
        argv,
        resolved_auth.password,
        &self_exe,
        config_path.as_deref(),
    ) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshrack: launch failed: {e}");
            exit_code::CONNECT
        }
    }
}
