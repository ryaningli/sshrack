//! Assemble the `scp` argv from raw scp arguments, resolving every remote
//! operand (`name:path`, `user@host:path`, `[v6]:path`) through the shared
//! connect-target table (following credential references for user/key).
//! Mirrors the system `scp` calling convention; the caller hands the result to
//! `connect::launch`.

use std::path::PathBuf;

use super::KeyArtifact;
use super::ssh::Overrides;
use crate::config::schema::{Host, SshrackConfig};
use crate::credential::{self, PasswordSource};
use crate::error::SshrackError;
use crate::host::{ResolveOverrides, resolve_target};
use crate::secret::SecretBackend;

/// The assembled scp invocation plus the resolved remote host (if any), so the
/// caller can resolve a password without re-parsing.
#[derive(Debug)]
pub struct ScpPlan {
    /// Full scp argv, starting with `"scp"`.
    pub argv: Vec<String>,
    /// The first host config matched in `args`. `None` when every operand is a
    /// local path.
    pub host: Option<Host>,
    /// Password source for the first remote host, resolved once here (during
    /// build) so the launch path does not re-resolve — and re-validate — after
    /// the network host-key check. [`PasswordSource::None`] for key/default-auth
    /// remotes or all-local operands; [`PasswordSource::Inline`] for plaintext
    /// / vault bodies; [`PasswordSource::Keyring`] for keyring-marker bodies
    /// (the helper fetches — no plaintext in the main process).
    pub password: PasswordSource,
    /// Every remote `(host, port)` endpoint referenced by the operands
    /// (deduplicated, first-appearance order), for host-key confirmation.
    pub remote_hosts: Vec<(String, u16)>,
    /// Temp files holding a pasted inline identity key, when the first remote's
    /// resolved key was inline material. The caller MUST hold the plan across
    /// `connect::launch` — its `Drop` removes the temp files so the plaintext
    /// does not outlive scp. `None` for path-key / no-key remotes and all-local
    /// operands. Acquired via [`super::materialize_inline_key`] inside `build`.
    pub key_artifact: Option<KeyArtifact>,
}

/// Build the scp argv from raw arguments. Every remote operand (`x:path`,
/// `user@x:path`, `[v6]:path`) resolves through [`crate::host::resolve_target`]
/// — a config name, a `user@host` literal (explicit user; a config-name host
/// part keeps the config's address/port), or a bare IP literal (needs
/// `-c`/`-l`). A bare word that matches nothing errors with
/// [`SshrackError::HostNotFound`] instead of reaching scp as a hostname.
/// The first resolved remote also contributes `-P <port>` and `-i <identity>`
/// (from override or the resolved key).
///
/// An operand with no `:` is a local path and passes through untouched.
/// Returns `CredentialNotFound` for a dangling credential reference, and
/// `AddressNeedsUser` for a bare-IP operand with neither `--credential` nor
/// `--user`.
///
/// `vault` is the unlocked master key (from [`crate::secret::vault`]) used to
/// decrypt any stored password; `None` means the config is not in encrypted
/// mode (or the caller is a unit test). `backend` is where keyring-stored
/// inline key text is read from when a host carries a keyring-marker inline
/// key (`ik.keyring = true`).
pub fn build(
    args: &[String],
    cfg: &SshrackConfig,
    overrides: &Overrides,
    vault: Option<&crate::secret::vault::VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<ScpPlan, SshrackError> {
    let mut out_args: Vec<String> = Vec::with_capacity(args.len());
    let mut host: Option<Host> = None;
    let mut first_port: Option<u16> = None;
    let mut identity: Option<PathBuf> = None;
    let mut remote_hosts: Vec<(String, u16)> = Vec::new();
    let mut password: PasswordSource = PasswordSource::None;
    let mut key_artifact: Option<KeyArtifact> = None;

    let resolve_overrides = ResolveOverrides {
        ad_hoc: overrides.ad_hoc,
        credential: overrides.credential,
        port: overrides.port,
        user: overrides.user.as_deref(),
        identity: overrides.identity.as_deref(),
    };

    for arg in args {
        // `[v6]:path` — scp's own IPv6 operand form. Split inside the
        // brackets so a v6 literal's colons don't cut the address apart.
        // Anything else splits at the first ':' (a bare operand is local).
        let pair = if let Some(stripped) = arg.strip_prefix('[') {
            stripped
                .split_once(']')
                .and_then(|(addr, after)| after.strip_prefix(':').map(|rest| (addr, rest)))
        } else {
            arg.split_once(':')
        };
        let Some((left, rest)) = pair else {
            out_args.push(arg.clone());
            continue;
        };

        // Every remote operand resolves through the same table: a config
        // name, `user@host` (explicit user; the host part may itself be a
        // config name = address + user overlay), or a bare IP literal with
        // -c/-l. A bare word that matches nothing is a typo'd name —
        // HostNotFound beats a misleading DNS error out of scp.
        let resolved =
            resolve_target(cfg, left, &resolve_overrides).map_err(|e| operand_err(e, left, arg))?;
        let host_cfg = resolved.host;
        let mut auth = credential::resolve(&host_cfg, cfg, vault, backend)?;
        // User precedence: user@ (target) > -l (flag) > resolved auth user.
        let user = resolved
            .target_user
            .as_deref()
            .or(overrides.user.as_deref())
            .unwrap_or(&auth.user);
        out_args.push(format!("{user}@{}:{rest}", host_cfg.host));
        let port = overrides.port.unwrap_or(host_cfg.port);
        if host.is_none() {
            host = Some(host_cfg.clone());
            first_port = Some(port);
            // Materialize an inline (pasted) key to a temp file before reading
            // auth.key_path — the inline branch leaves key_path None and the
            // temp path must reach argv via the same -i slot. The artifact
            // lives in the plan so it survives across connect::launch.
            key_artifact = super::materialize_inline_key(&mut auth)?;
            identity = overrides.identity.clone().or_else(|| auth.key_path.clone());
            // Carry the first remote's PasswordSource out so the launch path
            // does not re-resolve after the network host-key check. The source
            // decides delivery: Inline → temp file, Keyring → helper fetches,
            // None → no askpass payload.
            password = auth.password;
        }
        let entry = (host_cfg.host.clone(), port);
        if !remote_hosts.contains(&entry) {
            remote_hosts.push(entry);
        }
    }

    let mut argv: Vec<String> = vec!["scp".into()];
    if let Some(p) = first_port {
        argv.push("-P".into());
        argv.push(p.to_string());
    }
    if let Some(k) = identity {
        argv.push("-i".into());
        argv.push(k.to_string_lossy().into_owned());
    }
    // scp accepts ssh's `-o` options but not its flags (`-X`, `-L`, …), so
    // only the `-o Key=Value` subset of the host's ssh_args is forwarded.
    if let Some(h) = &host
        && let Some(raw) = &h.ssh_args
    {
        argv.extend(crate::sshargs::o_option_tokens(raw));
    }
    argv.extend(out_args);

    Ok(ScpPlan {
        argv,
        host,
        password,
        remote_hosts,
        key_artifact,
    })
}

/// Upgrade a `HostNotFound` on an operand that looks like an unbracketed
/// IPv6 literal (`fe80::1:/tmp` — scp splits at the first colon, so the
/// mangled host segment is all-hex) into a targeted hint instead of a
/// confusing "host not found: fe80". Other errors pass through unchanged.
fn operand_err(e: SshrackError, left: &str, arg: &str) -> SshrackError {
    if matches!(e, SshrackError::HostNotFound { .. })
        && !arg.starts_with('[')
        && arg.contains("::")
        && !left.is_empty()
        && left.chars().all(|c| c.is_ascii_hexdigit())
    {
        return SshrackError::InvalidTarget {
            target: arg.into(),
            reason: "this looks like an IPv6 address; write it bracketed as [addr]:path".into(),
        };
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
    use crate::secret::test_doubles::FakeBackend;
    use ulid::Ulid;

    fn cfg_with_key_host(name: &str) -> SshrackConfig {
        SshrackConfig {
            hosts: vec![Host {
                id: crate::id::new_id(),
                name: name.into(),
                host: "10.0.0.5".into(),
                port: 2222,
                ssh_args: None,
                auth: Auth::inline(
                    CredentialBody::new("deploy").with_key("/home/u/.ssh/id_ed25519"),
                ),
            }],
            credentials: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn resolves_name_colon_path_with_port_and_identity() {
        let plan = build(
            &["local.txt".into(), "web1:/srv/app".into()],
            &cfg_with_key_host("web1"),
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert_eq!(plan.argv[0], "scp");
        assert!(plan.argv.contains(&"-P".to_string()));
        assert!(plan.argv.contains(&"2222".to_string()));
        assert!(plan.argv.contains(&"-i".to_string()));
        assert!(plan.argv.iter().any(|a| a == "deploy@10.0.0.5:/srv/app"));
        assert_eq!(plan.host.unwrap().name, "web1");
    }

    #[test]
    fn leaves_local_to_local_untouched() {
        let plan = build(
            &["a.txt".into(), "b.txt".into()],
            &SshrackConfig::default(),
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert_eq!(plan.argv, vec!["scp", "a.txt", "b.txt"]);
        assert!(plan.host.is_none());
    }

    #[test]
    fn override_user_replaces_resolved_user() {
        let o = Overrides {
            user: Some("root".into()),
            ..Default::default()
        };
        let plan = build(
            &["web1:/x".into()],
            &cfg_with_key_host("web1"),
            &o,
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.iter().any(|a| a == "root@10.0.0.5:/x"));
    }

    #[test]
    fn override_port_replaces_resolved_port() {
        let o = Overrides {
            port: Some(22000),
            ..Default::default()
        };
        let plan = build(
            &["web1:/x".into()],
            &cfg_with_key_host("web1"),
            &o,
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.contains(&"22000".to_string()));
        assert!(!plan.argv.contains(&"2222".to_string()));
    }

    #[test]
    fn unknown_name_token_errors() {
        // `name:path` (no @) that is not a known name is a typo, not a host:
        // refuse with HostNotFound rather than letting scp treat it as a
        // hostname and surface a misleading DNS resolution error.
        let err = build(
            &["weird:path".into()],
            &cfg_with_key_host("web1"),
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SshrackError::HostNotFound { name, .. } if name == "weird"
        ));
    }

    #[test]
    fn dangling_credential_reference_is_hard_error() {
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: crate::id::new_id(),
                name: "web1".into(),
                host: "10.0.0.5".into(),
                port: 22,
                ssh_args: None,
                auth: Auth::reference(crate::id::new_id()),
            }],
            credentials: vec![],
            ..Default::default()
        };
        let err = build(
            &["web1:/x".into()],
            &cfg,
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap_err();
        // The dangling id surfaces as CredentialNotFound (the looked-for string
        // is the ULID, per the ref-by-id resolution path).
        assert!(matches!(err, SshrackError::CredentialNotFound { .. }));
    }

    /// A config with one reusable key credential named `name` (user `deploy`,
    /// key at `key_path`) and no hosts — the fixture for operand-level
    /// `-c`-injection tests.
    fn cfg_with_credential(name: &str, key_path: &str) -> SshrackConfig {
        SshrackConfig {
            credentials: vec![Credential {
                id: crate::id::new_id(),
                name: name.into(),
                body: CredentialBody::new("deploy").with_key(key_path),
            }],
            ..Default::default()
        }
    }

    /// The ULID of the named fixture credential (mirrors how the production
    /// CLI resolves a `--credential <name>` before calling `build`).
    fn cred_id(cfg: &SshrackConfig, name: &str) -> Ulid {
        cfg.credentials
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.id)
            .unwrap_or_else(|| panic!("invariant: fixture credential '{name}' exists"))
    }

    fn cfg_with_password_credential() -> (SshrackConfig, Ulid) {
        let cid = crate::id::new_id();
        let cfg = SshrackConfig {
            hosts: vec![],
            credentials: vec![Credential {
                id: cid,
                name: "team-dev".into(),
                body: CredentialBody::new("deploy").with_password("s3cret"),
            }],
            ..Default::default()
        };
        (cfg, cid)
    }

    #[test]
    fn password_carried_through_for_first_remote() {
        // The first remote's password is resolved once during build and carried
        // in ScpPlan as a PasswordSource, so the launch path never re-resolves
        // (and re-validates) after the network host-key check.
        let (cfg, cid) = cfg_with_password_credential();
        let o = Overrides {
            ad_hoc: true,
            credential: Some(cid),
            ..Default::default()
        };
        let plan = build(
            &["file.txt".into(), "1.2.3.4:/tmp/".into()],
            &cfg,
            &o,
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        match plan.password {
            PasswordSource::Inline(p) => assert_eq!(p.as_str(), "s3cret"),
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn user_at_operand_resolves_and_injects_credential() {
        // user@host:path used to pass through verbatim (no -i/-P injection, so
        // -c was silently ignored). It now resolves through the same table.
        let cfg = cfg_with_credential("ops", "/keys/ops_ed25519");
        let plan = build(
            &["f.txt".into(), "root@10.0.0.9:/tmp".into()],
            &cfg,
            &Overrides {
                credential: Some(cred_id(&cfg, "ops")),
                ..Default::default()
            },
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.iter().any(|a| a == "root@10.0.0.9:/tmp"));
        assert!(plan.argv.contains(&"-i".to_string()));
        assert!(plan.argv.iter().any(|a| a.contains("ops_ed25519")));
        assert!(
            plan.host.is_some(),
            "the operand contributed a host for auth"
        );
    }

    #[test]
    fn bare_ip_operand_with_credential_injected() {
        // A bare-IP operand with -c: the credential supplies user + key, so
        // the operand rewrites to <cred-user>@<ip>:<path> with -i injected.
        let cfg = cfg_with_credential("ops", "/keys/ops_ed25519");
        let plan = build(
            &["file.txt".into(), "10.0.0.9:/tmp/".into()],
            &cfg,
            &Overrides {
                credential: Some(cred_id(&cfg, "ops")),
                ..Default::default()
            },
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.iter().any(|a| a == "deploy@10.0.0.9:/tmp/"));
        assert!(plan.argv.contains(&"-i".to_string()));
        assert!(plan.argv.iter().any(|a| a.contains("ops_ed25519")));
        assert_eq!(
            plan.host.expect("operand contributed a host").host,
            "10.0.0.9"
        );
    }

    #[test]
    fn bare_ip_operand_without_identity_errors_with_fix() {
        // A bare-IP operand with neither -c nor -l has no login user; the
        // error states the fix instead of a bare "not found".
        let err = build(
            &["10.0.0.9:/tmp".into()],
            &SshrackConfig::default(),
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SshrackError::AddressNeedsUser { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("pass -c/-l or use user@10.0.0.9"),
            "got: {msg}"
        );
    }

    #[test]
    fn bracketed_ipv6_operand_resolves() {
        // scp's `[v6]:path` operand form: split inside the brackets so the
        // address's colons do not cut it apart.
        let cfg = cfg_with_credential("ops", "/keys/ops_ed25519");
        let plan = build(
            &["[fe80::1]:/tmp".into()],
            &cfg,
            &Overrides {
                credential: Some(cred_id(&cfg, "ops")),
                ..Default::default()
            },
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.iter().any(|a| a == "deploy@fe80::1:/tmp"));
    }

    #[test]
    fn unbracketed_ipv6_operand_gets_bracket_hint() {
        // `fe80::1:/tmp` splits at the first colon (host segment `fe80`), so
        // the HostNotFound is upgraded to a bracket-hint InvalidTarget.
        let cfg = cfg_with_credential("ops", "/keys/ops_ed25519");
        let err = build(
            &["fe80::1:/tmp".into()],
            &cfg,
            &Overrides {
                credential: Some(cred_id(&cfg, "ops")),
                ..Default::default()
            },
            None,
            &FakeBackend::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SshrackError::InvalidTarget { .. }));
        let msg = err.to_string();
        assert!(msg.contains("bracketed as [addr]:path"), "got: {msg}");
    }

    #[test]
    fn ghost_name_operand_still_host_not_found() {
        // Typo protection unchanged: a bare word that matches nothing errors
        // with HostNotFound. `ghost:/tmp/a::b` contains `::` but `ghost` is
        // not all-hex, so it must NOT hit the IPv6 hint.
        for operand in ["ghost:/tmp", "ghost:/tmp/a::b"] {
            let err = build(
                &[operand.into()],
                &SshrackConfig::default(),
                &Overrides::default(),
                None,
                &FakeBackend::new(),
            )
            .unwrap_err();
            assert!(
                matches!(err, SshrackError::HostNotFound { ref name, .. } if name == "ghost"),
                "{operand}: got {err:?}"
            );
        }
    }

    #[test]
    fn user_at_config_name_rewrites_with_explicit_user() {
        // `root@web1:/srv`: the host part hits the config, so the config's
        // address is used with the explicit user — NOT the config's user.
        let plan = build(
            &["root@web1:/srv".into()],
            &cfg_with_key_host("web1"),
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert!(plan.argv.iter().any(|a| a == "root@10.0.0.5:/srv"));
    }

    #[test]
    fn build_forwards_only_dash_o_subset_to_scp() {
        let mut cfg = cfg_with_key_host("web1");
        cfg.hosts[0].ssh_args = Some("-o ServerAliveInterval=30 -X -L 8080:x:80".into());
        let plan = build(
            &["web1:/tmp/x".into(), ".".into()],
            &cfg,
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap_or_else(|e| panic!("invariant: valid build: {e}"));
        assert!(plan.argv.contains(&"ServerAliveInterval=30".to_string()));
        assert!(!plan.argv.iter().any(|a| a == "-X"));
        assert!(!plan.argv.iter().any(|a| a.starts_with("-L")));
    }
}
