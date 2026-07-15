//! scp transfer handler: resolves `name:path` operands and launches `scp`.
//!
//! Mirrors the connect path ([`super::connect`]) but for file transfer. The
//! steps, in the order the code actually runs them:
//!
//! 1. Resolve `--credential <name>` → `Ulid` (fail-fast if unknown).
//! 2. Load config (a missing file is an empty config).
//! 3. Vault unlock if needed (env-passphrase from `SSHRACK_PASSPHRASE`).
//! 4. [`connect::scp::build`] — resolves every `name:path` operand to
//!    `user@host:path`, assembles the argv, and resolves the first remote's
//!    [`PasswordSource`] once (carried in [`ScpPlan`]) so the launch path does
//!    not re-resolve after the host-key check.
//! 5. [`hostkey::run_host_key_flow`] for each deduplicated remote endpoint
//!    (new keys accepted only with `--accept-new`).
//! 6. [`connect::launch`].
//!
//! ## Validation order
//!
//! The credential name resolves (Step 1) before [`connect::scp::build`]
//! consumes it via [`Overrides`] (Step 4). `build` itself fails fast on a
//! typo'd `name:path` operand ([`HostNotFound`]) and a dangling credential
//! reference ([`CredentialNotFound`]) before any network I/O runs in Step 5.
//!
//! ## Frecency
//!
//! scp does NOT record frecency: it is a file transfer, not a connect. Only the
//! `ssh`/`<name>` connect paths bump the frecency table (see [`super::connect`]).
//!
//! [`ScpPlan`]: sshrack_core::connect::scp::ScpPlan
//! [`Overrides`]: sshrack_core::connect::ssh::Overrides

use sshrack_core::config::path as config_path;
use sshrack_core::config::store;
use sshrack_core::connect;
use sshrack_core::error::SshrackError;
use sshrack_core::hostkey;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::vault;

use crate::cli::args::{Cli, Command};
use crate::cli::prompt::EnvPassphrase;
use crate::shared::exit_code;

/// Dispatch for the `Scp` arm of the CLI.
///
/// Merges the top-level per-connection flags with those given after the `scp`
/// token, then runs the 6-step scp flow. Returns the scp exit code, or an
/// [`exit_code`] constant on a local error.
pub fn run(cli: &Cli) -> i32 {
    let (args, opts) = match &cli.cmd {
        Some(Command::Scp { opts, args }) => {
            let merged = opts.clone().overlay(&cli.connect_opts);
            (args.as_slice(), merged)
        }
        _ => {
            eprintln!("sshrack: internal error: scp::run called on wrong arm");
            return exit_code::USAGE;
        }
    };

    if args.is_empty() {
        eprintln!("sshrack: scp: no operands given (expected `name:path` or local paths)");
        return exit_code::USAGE;
    }

    // Load config (a fresh install with an empty config is OK for scp's
    // local-to-local and `user@host:path` pass-through operands).
    let config_path = config_path::resolve(cli.config.as_deref());
    let cfg = match config_path.as_ref().map(|p| store::load(p)).transpose() {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => {
            eprintln!("sshrack: config error: {e}");
            return exit_code::USAGE;
        }
    };

    // ── Step 1: Resolve credential name → Ulid BEFORE build (fail-fast). ──────
    // A dangling --credential must error before any network I/O; resolving it
    // here also gives build the Ulid its Overrides expect.
    let cred_ulid = match opts.credential.as_deref() {
        None => None,
        Some(name) => match cfg.find_credential_by_name(name) {
            Some(c) => Some(c.id),
            None => {
                let err = sshrack_core::credential::credential_not_found(&cfg, name);
                eprintln!("sshrack: {err}");
                return exit_code::NOT_FOUND;
            }
        },
    };

    // ── Step 2: config loaded above. ──────────────────────────────────────────

    // ── Step 3: Vault unlock (no-op when not in vault mode). ─────────────────
    let passphrase_provider = EnvPassphrase;
    let env_pw = vault::passphrase_from_env();
    let vault_key =
        match vault::ensure_unlocked_vault_key(&cfg, env_pw.as_ref(), &passphrase_provider) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("sshrack: vault unlock failed: {e}");
                return exit_code::STORE;
            }
        };

    // ── Step 4: Build the scp argv (resolves operands, fails fast on typos /
    //    dangling refs, before any network I/O). ────────────────────────────────
    let overrides = connect::ssh::Overrides {
        user: opts.user.clone(),
        port: opts.port,
        identity: opts.identity.clone(),
        credential: cred_ulid,
        ad_hoc: opts.ad_hoc,
    };
    let backend = OsKeyring;
    let plan = match connect::scp::build(args, &cfg, &overrides, vault_key.as_ref(), &backend) {
        Ok(p) => p,
        Err(SshrackError::HostNotFound { name, hint }) => {
            eprintln!("sshrack: host not found: {name}{hint}");
            return exit_code::NOT_FOUND;
        }
        Err(SshrackError::CredentialNotFound { name, hint }) => {
            // The ref-by-id path surfaces a bare ULID as `name` (the host
            // references the credential by id; the credential is missing so no
            // name exists to show). Reword to point at the originating host so
            // the message reads like a host problem, not a stray id.
            let msg = credential_msg(&name, &hint, plan_host_name(&cfg, args));
            eprintln!("sshrack: {msg}");
            return exit_code::NOT_FOUND;
        }
        Err(SshrackError::MissingRequiredField { field }) => {
            eprintln!("sshrack: missing {field} (use --credential, --user, or user@host:path)");
            return exit_code::VALIDATION;
        }
        Err(SshrackError::VaultLocked) => {
            eprintln!(
                "sshrack: vault is locked; run `sshrack store unlock` or set SSHRACK_PASSPHRASE"
            );
            return exit_code::STORE;
        }
        Err(e) => {
            eprintln!("sshrack: {e}");
            return exit_code::VALIDATION;
        }
    };

    // ── Step 5: Host-key pre-flight for every remote endpoint. ────────────────
    // run_host_key_flow only calls confirm for NEW keys; changed keys are
    // rejected upstream by ssh. `accept_new` (OR'd across top-level + scp)
    // accepts a first-seen key iff --accept-new was given. The closure is
    // FnOnce, so rebuild it per iteration. `has_tty` is a per-process fact, so
    // compute it once before the loop.
    let accept_new = opts.accept_new;
    let has_tty = crate::cli::prompt::has_tty();
    for (host_str, port) in &plan.remote_hosts {
        // On the Prompt path (has_tty && !accept_new) core hands us the full
        // fingerprint text; show it and ask yes/no. The Accept path (accept_new)
        // never calls this closure.
        let confirm = |fingerprint_text: &str| crate::cli::prompt::prompt_yes_no(fingerprint_text);
        if let Err(e) = hostkey::run_host_key_flow(host_str, *port, has_tty, accept_new, confirm) {
            eprintln!("sshrack: host key: {e}");
            return exit_code::CONNECT;
        }
    }

    // ── Step 6: Launch scp. ───────────────────────────────────────────────────
    let self_exe = match connect::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sshrack: cannot determine self path: {e}");
            return exit_code::CONNECT;
        }
    };
    match connect::launch(plan.argv, plan.password, &self_exe, config_path.as_deref()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshrack: launch failed: {e}");
            exit_code::CONNECT
        }
    }
}

/// Build the human-facing message for a dangling-credential error surfaced by
/// the scp build path. When the originating host name is known (`Some`), the
/// message points at the host ("host 'web1' references an unknown credential");
/// otherwise it falls back to the bare string core produced (a ULID).
///
/// `hint` is core's [`DidYouMean`](sshrack_core::error::DidYouMean) rendered
/// via `Display` (already includes a leading space when non-empty).
///
/// CLI-layer concern only — core's `credential::resolve` is unchanged.
fn credential_msg(
    name: &str,
    hint: &sshrack_core::error::DidYouMean,
    host_name: Option<&str>,
) -> String {
    match host_name {
        Some(h) => format!("host '{h}' references an unknown credential{hint}"),
        None => format!("credential not found: {name}{hint}"),
    }
}

/// Best-effort reverse-lookup of the host name whose `name:path` operand
/// triggered a dangling-credential error. Returns `None` for an ad-hoc operand
/// (no registered name) or when the operand was not in `name:path` form.
///
/// Used only to improve the dangling-credential error message (Task-8
/// follow-up); never affects control flow.
fn plan_host_name<'a>(
    cfg: &'a sshrack_core::config::schema::SshrackConfig,
    args: &[String],
) -> Option<&'a str> {
    for arg in args {
        let Some((left, _rest)) = arg.split_once(':') else {
            continue;
        };
        // `user@host:path` and ad-hoc literals have no registered name.
        if left.contains('@') {
            continue;
        }
        if let Some(h) = cfg.find_host_by_name(left) {
            return Some(&h.name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    //! Unit tests for the two pure helpers that shape scp's error messages and
    //! operand resolution: `credential_msg` (dangling-credential wording) and
    //! `plan_host_name` (reverse-lookup of the `name:path` operand that triggered
    //! the error). Pure: feeds fixtures, asserts strings/`Option`.
    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use sshrack_core::error::DidYouMean;
    use ulid::Ulid;

    /// Build a config registering the named hosts (each with an inline default
    /// body; only `name` matters for `plan_host_name`).
    fn cfg_with_hosts(names: &[&str]) -> SshrackConfig {
        SshrackConfig {
            hosts: names
                .iter()
                .map(|n| Host {
                    id: Ulid::new(),
                    name: (*n).into(),
                    host: format!("{n}.internal"),
                    port: 22,
                    auth: Auth::Inline(CredentialBody::new("u")),
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Convenience to build owned argv slices from `&str` literals.
    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    // ---- credential_msg ----

    #[test]
    fn credential_msg_with_host_name_points_at_host() {
        let msg = credential_msg("ghost", &DidYouMean::none(), Some("web1"));
        assert!(
            msg.contains("host 'web1' references an unknown credential"),
            "got: {msg}"
        );
        // Must not fall through to the bare credential-not-found wording.
        assert!(!msg.contains("credential not found"), "got: {msg}");
    }

    #[test]
    fn credential_msg_without_host_name_falls_back_to_credential_not_found() {
        let msg = credential_msg("ghost", &DidYouMean::none(), None);
        assert!(msg.contains("credential not found: ghost"), "got: {msg}");
        // Must not misattribute to a host.
        assert!(!msg.contains("host '"), "got: {msg}");
    }

    #[test]
    fn credential_msg_without_host_name_appends_hint() {
        let hint = DidYouMean::from_option(Some("ops"));
        let msg = credential_msg("ghost", &hint, None);
        assert!(msg.contains("credential not found: ghost"), "got: {msg}");
        assert!(
            msg.contains("(did you mean 'ops'?)"),
            "expected the suggestion rendered, got: {msg}"
        );
    }

    #[test]
    fn credential_msg_with_host_name_appends_hint() {
        let hint = DidYouMean::from_option(Some("team"));
        let msg = credential_msg("ghost", &hint, Some("web1"));
        assert!(
            msg.contains("host 'web1' references an unknown credential"),
            "got: {msg}"
        );
        assert!(
            msg.contains("(did you mean 'team'?)"),
            "expected the suggestion rendered, got: {msg}"
        );
    }

    // ---- plan_host_name ----

    #[test]
    fn plan_host_name_registered_name_path_returns_name() {
        let cfg = cfg_with_hosts(&["web1"]);
        assert_eq!(
            plan_host_name(&cfg, &args(&["web1:/tmp/file"])),
            Some("web1")
        );
    }

    #[test]
    fn plan_host_name_first_match_wins_when_multiple_registered() {
        let cfg = cfg_with_hosts(&["web1", "web2"]);
        assert_eq!(
            plan_host_name(&cfg, &args(&["web1:/a", "web2:/b"])),
            Some("web1")
        );
    }

    #[test]
    fn plan_host_name_no_colon_is_skipped() {
        // A bare operand with no colon (local path or a stray name) is skipped.
        let cfg = cfg_with_hosts(&["web1"]);
        assert_eq!(plan_host_name(&cfg, &args(&["web1"])), None);
    }

    #[test]
    fn plan_host_name_user_at_host_is_skipped() {
        // `user@host:path` is an ad-hoc literal, never a registered name.
        let cfg = cfg_with_hosts(&["web1"]);
        assert_eq!(plan_host_name(&cfg, &args(&["user@host:/tmp"])), None);
    }

    #[test]
    fn plan_host_name_unregistered_name_returns_none() {
        let cfg = cfg_with_hosts(&["web1"]);
        // A name:path whose left side is not a registered host → None.
        assert_eq!(plan_host_name(&cfg, &args(&["ghost:/a"])), None);
    }

    #[test]
    fn plan_host_name_skipped_operands_fall_through_to_registered_match() {
        // Ad-hoc (user@host) and colon-less operands are skipped, then a later
        // registered name:path operand still resolves.
        let cfg = cfg_with_hosts(&["web1"]);
        assert_eq!(
            plan_host_name(&cfg, &args(&["user@host:/a", "./local", "web1:/b"]),),
            Some("web1")
        );
    }

    #[test]
    fn plan_host_name_empty_args_returns_none() {
        let cfg = cfg_with_hosts(&["web1"]);
        assert_eq!(plan_host_name(&cfg, &args(&[])), None);
    }
}
