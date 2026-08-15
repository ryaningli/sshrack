//! Assemble the `scp` argv from raw scp arguments, resolving any `name:path`
//! token against the config (following credential references for user/key).
//! Mirrors the system `scp` calling convention; the caller hands the result to
//! `connect::launch`.

use std::path::PathBuf;

use super::KeyArtifact;
use super::ssh::Overrides;
use crate::config::schema::{Host, SshrackConfig};
use crate::credential::{self, PasswordSource};
use crate::error::SshrackError;
use crate::host::{ResolveOverrides, host_not_found, resolve_target};
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

/// Build the scp argv from raw arguments. A `left:rest` operand is rewritten
/// to `user@host:rest` (user/key resolved through the host's auth, following
/// credential references) when `left` is a known name — or, with `--ad-hoc`,
/// a literal address. The first rewritten operand also contributes `-P <port>`
/// and `-i <identity>` (from override or the resolved key).
///
/// Operands with no `:`, or in scp's `user@host:path` form (`left` has `@`),
/// pass through verbatim — the escape hatch for reaching a host with no
/// registered name. A `name:path` whose `name` is neither a known name nor
/// (under `--ad-hoc`) an address is a typo'd name: it errors with
/// [`SshrackError::HostNotFound`] instead of being forwarded to scp as a
/// hostname.
///
/// Returns `CredentialNotFound` for a dangling credential reference, and
/// `MissingRequiredField` for an ad-hoc operand with neither `--credential`
/// nor `--user`.
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
        let Some((left, rest)) = arg.split_once(':') else {
            out_args.push(arg.clone());
            continue;
        };
        // `user@host:path` (left contains @) is an explicit host in scp's
        // native syntax, not a name — pass it through so scp can still reach
        // any host without a registered name.
        if left.contains('@') {
            out_args.push(arg.clone());
            continue;
        }
        // `name:path` (no @): a known name, or (with --ad-hoc) a literal
        // address. Anything else is a typo'd name — refuse with HostNotFound
        // + did-you-mean rather than letting scp treat it as a hostname and
        // surface a misleading DNS error.
        let host_cfg = match cfg.find_host_by_name(left) {
            Some(h) => h.clone(),
            None if overrides.ad_hoc => resolve_target(cfg, left, &resolve_overrides)?.host,
            None => return Err(host_not_found(cfg, left)),
        };
        let mut auth = credential::resolve(&host_cfg, cfg, vault, backend)?;
        let user = overrides.user.as_deref().unwrap_or(&auth.user);
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

    fn cfg_with_key_credential() -> (SshrackConfig, Ulid) {
        let cid = crate::id::new_id();
        let cfg = SshrackConfig {
            hosts: vec![],
            credentials: vec![Credential {
                id: cid,
                name: "team-dev".into(),
                body: CredentialBody::new("deploy").with_key("/team_ed25519"),
            }],
            ..Default::default()
        };
        (cfg, cid)
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
    fn ad_hoc_operand_with_credential_is_injected() {
        let (cfg, cid) = cfg_with_key_credential();
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
        assert!(plan.argv.iter().any(|a| a == "deploy@1.2.3.4:/tmp/"));
        assert!(plan.argv.contains(&"-P".to_string()));
        assert!(plan.argv.contains(&"22".to_string()));
        assert!(plan.argv.contains(&"-i".to_string()));
        assert_eq!(plan.host.unwrap().host, "1.2.3.4");
        assert!(plan.remote_hosts.contains(&("1.2.3.4".to_string(), 22)));
        // A key credential carries no password.
        assert!(matches!(plan.password, PasswordSource::None));
    }

    #[test]
    fn bare_address_without_ad_hoc_errors() {
        // A `host:path` operand with no @ and no --ad-hoc is treated as a
        // typo'd name and refused. Use --ad-hoc (or `user@host:path`) to
        // reach a host that is not a registered name.
        let (cfg, cid) = cfg_with_key_credential();
        let o = Overrides {
            ad_hoc: false,
            credential: Some(cid),
            ..Default::default()
        };
        let err = build(&["1.2.3.4:/x".into()], &cfg, &o, None, &FakeBackend::new()).unwrap_err();
        assert!(matches!(err, SshrackError::HostNotFound { .. }));
    }

    #[test]
    fn user_at_host_token_passes_through() {
        // `user@host:path` is scp's native explicit-host syntax, not a name,
        // so it passes through verbatim — the escape hatch for reaching a host
        // that has no registered name.
        let (cfg, _cid) = cfg_with_key_credential();
        let plan = build(
            &["root@1.2.3.4:/x".into()],
            &cfg,
            &Overrides::default(),
            None,
            &FakeBackend::new(),
        )
        .unwrap();
        assert_eq!(plan.argv, vec!["scp", "root@1.2.3.4:/x"]);
        assert!(plan.host.is_none());
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

    #[test]
    fn ad_hoc_operand_without_identity_errors() {
        let o = Overrides {
            ad_hoc: true,
            ..Default::default()
        };
        let err = build(
            &["1.2.3.4:/x".into()],
            &SshrackConfig::default(),
            &o,
            None,
            &FakeBackend::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SshrackError::AddressNeedsUser { .. }));
    }
}
