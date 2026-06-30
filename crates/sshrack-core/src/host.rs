//! Host CRUD pure logic: alias validation, immutable config transforms, and
//! connect-time target resolution.
//!
//! Everything here is decision logic lifted out of the (forthcoming) CLI's
//! `cmd/host/{add,edit,rm,cp}` modules. There is no I/O and no interactive
//! prompting: `AddOptions` / `EditOptions` are plain flag-bag structs the CLI
//! fills in; the keyring side effects (`delete_host_with_secret`,
//! `copy_keyring_entry`) take an injected [`SecretBackend`](crate::secret::SecretBackend)
//! so they stay unit-testable without a daemon.
//!
//! Ref-by-id invariant ([`crate::credential`]): a host holds an [`Auth::Ref`]
//! pointing at a credential's stable [`Ulid`], never its alias. None of the
//! transforms here rewrite that id on rename — the host keeps referencing the
//! same credential regardless of alias edits.

use std::path::PathBuf;

use ulid::Ulid;

use crate::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
use crate::error::{DidYouMean, SshrackError};
use crate::id::{OwnerKind, new_id};
use crate::secret::{self, SecretBackend};
use crate::suggest;

/// Characters forbidden in a host alias: they break sshrack's own syntax (`:` is
/// the scp `alias:path` separator; `@` is reserved for the future `user@alias`
/// form) or argv/token splitting (whitespace). `add` rejects these up front;
/// the soft warning pass in the CLI surfaces them when they appear in a
/// hand-edited config. Hosts and credentials share the same rule.
pub const FORBIDDEN_ALIAS_CHARS: &[char] = &[':', '@', ' ', '\t', '\n', '\r'];

/// The first forbidden character in `alias`, if any. Shared by the hard
/// rejection in `add` and the soft warning pass.
pub fn forbidden_char_in(alias: &str) -> Option<char> {
    alias.chars().find(|c| FORBIDDEN_ALIAS_CHARS.contains(c))
}

/// Reject `alias` if it contains a [`FORBIDDEN_ALIAS_CHARS`] character.
pub fn validate_alias_chars(alias: &str) -> Result<(), SshrackError> {
    if let Some(ch) = forbidden_char_in(alias) {
        return Err(SshrackError::InvalidAliasChar {
            alias: alias.to_string(),
            ch,
        });
    }
    Ok(())
}

/// Build a [`SshrackError::HostNotFound`] with a "did you mean" hint computed
/// from the config's host aliases. Shared by every host lookup that fails:
/// resolve, show, rm, cp, edit.
pub fn host_not_found(cfg: &SshrackConfig, alias: &str) -> SshrackError {
    let candidates: Vec<&str> = cfg.hosts.iter().map(|h| h.alias.as_str()).collect();
    SshrackError::HostNotFound {
        alias: alias.into(),
        hint: DidYouMean::from_option(suggest::closest(&candidates, alias)),
    }
}

/// Reject a duplicate alias unless `force` is set.
pub fn validate_no_duplicate(
    cfg: &SshrackConfig,
    alias: &str,
    force: bool,
) -> Result<(), SshrackError> {
    if cfg.find_host_by_alias(alias).is_some() && !force {
        return Err(SshrackError::HostAlreadyExists {
            alias: alias.into(),
        });
    }
    Ok(())
}

/// Validate a rename target against the config (excludes the current alias).
pub fn validate_rename(
    cfg: &SshrackConfig,
    current_alias: &str,
    new_alias: &str,
) -> Result<(), SshrackError> {
    validate_alias_chars(new_alias)?;
    let taken_by_other = cfg
        .hosts
        .iter()
        .any(|h| h.alias == new_alias && h.alias != current_alias);
    if taken_by_other {
        return Err(SshrackError::AliasTaken {
            alias: new_alias.to_string(),
        });
    }
    Ok(())
}

/// Validate the destination alias for a copy: legal characters and global
/// uniqueness. `cp` never overwrites, so this always rejects an existing alias
/// (including the source's own name — a host cannot be copied onto itself).
pub fn validate_dst(cfg: &SshrackConfig, dst: &str) -> Result<(), SshrackError> {
    validate_alias_chars(dst)?;
    validate_no_duplicate(cfg, dst, false)
}

/// Return a new config with a fresh host appended, or `Err` on a forbidden
/// alias character. Pure: does not mutate `cfg`, does not touch the filesystem.
/// The caller supplies the stable `id` (generated via [`new_id`]).
pub fn add_host(
    cfg: &SshrackConfig,
    id: Ulid,
    alias: &str,
    host: &str,
    port: u16,
    auth: Auth,
) -> Result<SshrackConfig, SshrackError> {
    validate_alias_chars(alias)?;
    let mut next = cfg.clone();
    next.hosts.push(Host {
        id,
        alias: alias.into(),
        host: host.into(),
        port,
        auth,
    });
    Ok(next)
}

/// Return a new config with `alias` removed, or `None` if it was not present.
///
/// Pure transform: does not mutate `cfg`, does not touch the filesystem or the
/// keyring. The caller is responsible for persisting the returned config and
/// (via [`delete_host_with_secret`]) forgetting any keyring entry.
pub fn remove_host(cfg: &SshrackConfig, alias: &str) -> Option<SshrackConfig> {
    if !cfg.hosts.iter().any(|h| h.alias == alias) {
        return None;
    }
    let mut next = cfg.clone();
    next.hosts.retain(|h| h.alias != alias);
    Some(next)
}

/// Clone `src` into a fresh [`Host`] that shares every field except `alias` and
/// `id`. The copy gets a **fresh id** so it is an independent keyring identity
/// (a shared id would make the two hosts alias one keyring entry and diverge
/// confusingly). The keyring entry itself is best-effort copied by the caller
/// via [`copy_keyring_entry`].
///
/// A credential reference is copied as a shared id string — the copy references
/// the same credential, the credential itself is never duplicated. An inline
/// body is duplicated verbatim (its secret travels with the body).
pub fn clone_host_as(src: &Host, dst_id: Ulid, dst_alias: &str) -> Host {
    Host {
        id: dst_id,
        alias: dst_alias.to_string(),
        host: src.host.clone(),
        port: src.port,
        auth: src.auth.clone(),
    }
}

/// Connection-time overrides that influence how a connect target is resolved.
/// Borrows from the CLI layer so this core module stays free of CLI coupling.
///
/// `credential` is a [`Ulid`] (the CLI resolves `--credential <alias>` to an id
/// before constructing this), matching [`crate::connect::ssh::Overrides::credential`].
#[derive(Debug, Clone, Copy)]
pub struct ResolveOverrides<'a> {
    /// `--ad-hoc`: treat an unknown target as a literal address, not an alias.
    pub ad_hoc: bool,
    /// `--credential <id>`: reuse a `[[credentials]]` entry's identity.
    pub credential: Option<Ulid>,
    /// `--port <n>`: override the resolved port.
    pub port: Option<u16>,
    /// `--user <name>`: override the resolved login user.
    pub user: Option<&'a str>,
    /// `--identity <path>`: override the resolved key file.
    pub identity: Option<&'a std::path::Path>,
}

/// ssh default port, used for ad-hoc targets that have no config entry.
const DEFAULT_PORT: u16 = 22;

/// Resolve a connect `target` into a concrete [`Host`], whether it names a
/// configured alias or an ad-hoc address. Decision table:
///
/// | alias hit | `--ad-hoc` | result |
/// |-----------|------------|--------|
/// | yes       | any        | the host entry; `--credential` overrides its auth |
/// | no        | yes        | an ephemeral host `{ host = target, … }` |
/// | no        | no         | [`SshrackError::HostNotFound`] (+ did-you-mean) |
///
/// An ad-hoc target must carry an identity — either `--credential` or `--user`
/// — since sshrack has no implicit login user. `--credential` is not checked
/// for existence here; a dangling reference surfaces as
/// [`SshrackError::CredentialNotFound`] when the caller runs
/// [`crate::credential::resolve`].
pub fn resolve_target(
    cfg: &SshrackConfig,
    target: &str,
    overrides: &ResolveOverrides<'_>,
) -> Result<Host, SshrackError> {
    if let Some(found) = cfg.find_host_by_alias(target) {
        let mut host = found.clone();
        if let Some(cred) = overrides.credential {
            host.auth = Auth::reference(cred);
        }
        return Ok(host);
    }

    if !overrides.ad_hoc {
        return Err(host_not_found(cfg, target));
    }

    let auth = ad_hoc_auth(overrides)?;
    Ok(ad_hoc_host(
        target,
        overrides.port.unwrap_or(DEFAULT_PORT),
        auth,
    ))
}

/// Build the auth for an ad-hoc target from the overrides: `--credential`
/// wins; otherwise inline `--user` (with optional `--identity`); otherwise
/// reject — an ad-hoc connection needs an explicit identity.
fn ad_hoc_auth(overrides: &ResolveOverrides<'_>) -> Result<Auth, SshrackError> {
    if let Some(cred) = overrides.credential {
        return Ok(Auth::reference(cred));
    }
    let Some(user) = overrides.user else {
        return Err(SshrackError::MissingRequiredField {
            field: "--credential or --user (required for --ad-hoc)",
        });
    };
    let mut body = CredentialBody::new(user);
    if let Some(key) = overrides.identity {
        body = body.with_key(key);
    }
    Ok(Auth::inline(body))
}

/// Build an ephemeral [`Host`] for an ad-hoc address + auth. Never persisted:
/// `alias` mirrors the address (cosmetic — ad-hoc hosts are never looked up by
/// alias after construction). The `id` is fresh so a keyring password (if any)
/// keys off a stable identity.
fn ad_hoc_host(address: &str, port: u16, auth: Auth) -> Host {
    Host {
        id: new_id(),
        alias: address.to_string(),
        host: address.to_string(),
        port,
        auth,
    }
}

// ===========================================================================
// add / edit pure helpers (lifted from sshrack-old's cmd/host/{add,edit}.rs)
// ===========================================================================

/// Field values supplied via CLI flags for `add`. `None` means "not provided"
/// (interactive mode prompts; `--no-input` mode errors for required `host`).
/// The CLI fills this struct; core never reads the TTY.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AddOptions {
    /// Remote hostname or IP. Required in `--no-input` mode.
    pub host: Option<String>,
    pub port: Option<u16>,
    /// Reference a `[[credentials]]` entry by alias. The CLI resolves this to a
    /// stable [`Ulid`] before building the host. When set alongside `user` or
    /// `identity`, the interactive `prompt_auth` menu is skipped.
    pub credential: Option<Ulid>,
    /// Inline login user (defaults to `root`).
    pub user: Option<String>,
    /// Inline private key path.
    pub identity: Option<PathBuf>,
    /// Non-interactive: all required fields must come from flags (a password
    /// host cannot be created in this mode — passwords never enter argv).
    pub no_input: bool,
    /// Overwrite an existing alias.
    pub force: bool,
}

/// Build the inline/reference auth from add options. A `credential` wins;
/// otherwise an inline body is built from user/identity. A password is never
/// set here — passwords never enter argv, so a password host requires
/// interactive entry.
pub fn build_auth(opts: &AddOptions) -> Auth {
    if let Some(cred) = opts.credential {
        return Auth::reference(cred);
    }
    let user = opts.user.clone().unwrap_or_else(|| "root".into());
    let mut body = CredentialBody::new(user);
    if let Some(k) = &opts.identity {
        body = body.with_key(k.clone());
    }
    Auth::inline(body)
}

/// True when the caller supplied any auth-determining flag, so the interactive
/// `prompt_auth` menu is skipped.
pub fn auth_supplied_by_flags(opts: &AddOptions) -> bool {
    opts.credential.is_some() || opts.user.is_some() || opts.identity.is_some()
}

/// Build a [`Host`] from alias + options + a caller-supplied id, applying
/// defaults and the required-`host` check. The body's password is attached by
/// the CLI (interactive only — never via flags). Pure: validates the alias and
/// assembles the struct, no config mutation.
pub fn merge_fields(id: Ulid, alias: &str, opts: &AddOptions) -> Result<Host, SshrackError> {
    validate_alias_chars(alias)?;
    let host_addr = opts
        .host
        .clone()
        .ok_or(SshrackError::MissingRequiredField { field: "host" })?;
    Ok(Host {
        id,
        alias: alias.into(),
        host: host_addr,
        port: opts.port.unwrap_or(DEFAULT_PORT),
        auth: build_auth(opts),
    })
}

/// Field updates supplied via CLI flags for `edit`. `None` keeps the existing
/// value; `Some` overwrites.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EditOptions {
    pub host: Option<String>,
    pub port: Option<u16>,
    /// Reference a `[[credentials]]` entry by id (the CLI resolves the alias).
    /// Setting this implies switching the host's auth to [`Auth::Ref`] — the
    /// host's inline user/identity fields are not patched in this case.
    /// Mutually exclusive with `clear_credential`.
    pub credential: Option<Ulid>,
    pub user: Option<String>,
    pub identity: Option<PathBuf>,
    pub rename: Option<String>,
    pub clear_identity: bool,
    pub clear_password: bool,
    /// Drop any credential reference, falling back to inline default user.
    pub clear_credential: bool,
}

/// Pure transform: build a new [`Host`] from `orig` by applying `opts`,
/// preserving `orig.id` so a patch (including `--rename`) never orphans the
/// keyring entry keyed by that id.
///
/// `--credential <X>` (alone) switches auth to [`Auth::Ref`] pointing at `X` —
/// it implies the switch, so callers never need a separate "use credential"
/// flag. `--clear-credential` drops a reference and falls back to an inline
/// default body. Otherwise the existing auth is preserved: a reference is left
/// untouched by user/identity flags, and only an inline body is patched
/// field-by-field.
pub fn apply_patch(orig: &Host, opts: &EditOptions) -> Result<Host, SshrackError> {
    let alias = opts.rename.clone().unwrap_or_else(|| orig.alias.clone());
    let host = opts.host.clone().unwrap_or_else(|| orig.host.clone());
    let port = opts.port.unwrap_or(orig.port);

    let auth = if let Some(cred) = opts.credential {
        Auth::reference(cred)
    } else if opts.clear_credential {
        Auth::inline(CredentialBody::new(
            opts.user.clone().unwrap_or_else(|| "root".into()),
        ))
    } else {
        match &orig.auth {
            // A reference is left untouched by user/identity flags; switch it
            // explicitly with --credential / --clear-credential.
            Auth::Ref { .. } => orig.auth.clone(),
            Auth::Inline(body) => Auth::inline(patch_body(body, opts)?),
        }
    };

    Ok(Host {
        id: orig.id,
        alias,
        host,
        port,
        auth,
    })
}

/// Patch an inline body's fields: user/identity/password keep their existing
/// values when the corresponding flag is absent; `clear_*` drops them. The
/// body's `keyring` marker is preserved verbatim so a patch (including
/// `--rename`) never orphans the keyring entry keyed by the host's id.
fn patch_body(body: &CredentialBody, opts: &EditOptions) -> Result<CredentialBody, SshrackError> {
    let user = opts.user.clone().unwrap_or_else(|| body.user.clone());
    let key = if opts.clear_identity {
        None
    } else {
        opts.identity.clone().or(body.key.clone())
    };
    let (password, keyring) = if opts.clear_password {
        (None, false)
    } else {
        // Preserve the existing secret slot and keyring marker verbatim: an
        // inline password keeps its Secret, a keyring body keeps its marker.
        (body.password.clone(), body.keyring)
    };
    let mut new_body = CredentialBody {
        user,
        password,
        key: None,
        keyring,
    };
    if let Some(k) = key {
        new_body = new_body.with_key(k); // with_key clears password (mutual exclusion)
    }
    new_body.validate()?;
    Ok(new_body)
}

/// Preserve the original host's id across an interactive auth rebuild. The old
/// `edit.rs` did this via `new_body.retain_id(orig_body)`; with the id now on
/// the host (not the body), the equivalent is to stamp the original id onto the
/// freshly prompted host. Returns a [`Host`] with `orig_id` and the new fields.
pub fn finalize_body(orig_id: Ulid, alias: &str, host: &str, port: u16, auth: Auth) -> Host {
    Host {
        id: orig_id,
        alias: alias.into(),
        host: host.into(),
        port,
        auth,
    }
}

/// True when `opts` carries any field-setting flag (used by `edit` to decide
/// between the patch path and the full-prompt path).
pub fn edit_has_any_flag(opts: &EditOptions) -> bool {
    opts.host.is_some()
        || opts.port.is_some()
        || opts.credential.is_some()
        || opts.user.is_some()
        || opts.identity.is_some()
        || opts.rename.is_some()
        || opts.clear_identity
        || opts.clear_password
        || opts.clear_credential
}

// ===========================================================================
// rm / cp keyring-aware helpers (backend-injected; no direct I/O)
// ===========================================================================

/// Remove the host named `alias` from `cfg` and best-effort forget its keyring
/// entry when the host's inline body was keyring-marked. Returns the new config
/// (keyring already cleaned), or `Err(HostNotFound)` if absent.
///
/// The keyring cleanup goes through [`secret::forget_keyring_secret`] with
/// [`OwnerKind::Host`] and the host's stable id (the body no longer carries an
/// id — the owner does). Pure w.r.t. the filesystem: the caller persists the
/// returned config.
pub fn delete_host_with_secret(
    cfg: &SshrackConfig,
    alias: &str,
    backend: &dyn SecretBackend,
) -> Result<SshrackConfig, SshrackError> {
    let Some(host) = cfg.find_host_by_alias(alias) else {
        return Err(host_not_found(cfg, alias));
    };
    // Snapshot the keyring-relevant fields before the (cloned) remove, so the
    // forget decision reflects the host as it stood at call time.
    let (host_id, keyring) = (host.id, host.auth.inline_body().is_some_and(|b| b.keyring));
    let next = remove_host(cfg, alias).expect("invariant: host present (checked above)");
    secret::forget_keyring_secret(backend, OwnerKind::Host, &host_id, keyring);
    Ok(next)
}

/// Best-effort forget the keyring entry of the host currently at `alias`, when
/// that host is about to be overwritten in place (e.g. `host add --force` on an
/// existing alias, which generates a fresh id). If the existing host's inline
/// body was keyring-marked, its keyring entry — keyed by the *old* id — is
/// deleted so no orphaned secret is left behind, mirroring [`delete_host_with_secret`].
///
/// No-op when `alias` is absent (nothing to overwrite) or when the existing
/// host was not keyring-marked. Pure w.r.t. the filesystem; the caller persists
/// the replacement config separately. Never returns an error (best-effort, like
/// the rm path).
pub fn forget_keyring_on_overwrite(cfg: &SshrackConfig, alias: &str, backend: &dyn SecretBackend) {
    let Some(old) = cfg.find_host_by_alias(alias) else {
        return;
    };
    let keyring = old.auth.inline_body().is_some_and(|b| b.keyring);
    secret::forget_keyring_secret(backend, OwnerKind::Host, &old.id, keyring);
}

/// Best-effort: if `src` is a keyring-password host, copy its keyring entry from
/// the source's id to `dst`'s fresh id so the copy connects immediately. A
/// missing/unreachable entry is reported via the returned `Err` (carrying no
/// secret); the caller logs-and-continues. Never materializes the password
/// outside the backend round-trip.
pub fn copy_keyring_entry(
    src: &Host,
    dst: &Host,
    backend: &dyn SecretBackend,
) -> Result<(), SshrackError> {
    let (Some(src_body), Some(_dst_body)) = (src.auth.inline_body(), dst.auth.inline_body()) else {
        return Ok(());
    };
    if !src_body.keyring {
        return Ok(());
    }
    match backend.get(&crate::id::keyring_key(OwnerKind::Host, &src.id))? {
        Some(pw) => backend.set(OwnerKind::Host, &dst.id, &pw),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use crate::secret::test_doubles::FakeBackend;

    fn cfg_with(alias: &str) -> SshrackConfig {
        SshrackConfig {
            hosts: vec![Host {
                id: new_id(),
                alias: alias.into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..Default::default()
        }
    }

    fn cfg_with_aliases(aliases: &[&str]) -> SshrackConfig {
        SshrackConfig {
            hosts: aliases
                .iter()
                .map(|&a| Host {
                    id: new_id(),
                    alias: a.into(),
                    host: "h".into(),
                    port: 22,
                    auth: Auth::inline(CredentialBody::new("u")),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn cfg_with_hosts(hosts: Vec<Host>) -> SshrackConfig {
        SshrackConfig {
            hosts,
            ..Default::default()
        }
    }

    fn inline_host(alias: &str, body: CredentialBody) -> Host {
        Host {
            id: new_id(),
            alias: alias.into(),
            host: format!("{alias}.example.com"),
            port: 2222,
            auth: Auth::inline(body),
        }
    }

    // --- forbidden_char_in / validate_alias_chars ---

    #[test]
    fn forbidden_char_in_detects_colon_at_whitespace() {
        assert_eq!(forbidden_char_in("a:b"), Some(':'));
        assert_eq!(forbidden_char_in("x@y"), Some('@'));
        assert_eq!(forbidden_char_in("a b"), Some(' '));
        assert_eq!(forbidden_char_in("a\tb"), Some('\t'));
        assert_eq!(forbidden_char_in("clean-name"), None);
    }

    #[test]
    fn validate_alias_chars_accepts_clean_alias() {
        assert!(validate_alias_chars("web-1.db_2").is_ok());
    }

    #[test]
    fn validate_alias_chars_reports_offending_char() {
        let err = validate_alias_chars("a:b").unwrap_err();
        assert!(matches!(
            err,
            SshrackError::InvalidAliasChar { ref alias, ch: ':' } if alias == "a:b"
        ));
    }

    // --- host_not_found ---

    #[test]
    fn host_not_found_carries_closest_hint() {
        let cfg = cfg_with("ets-pc");
        let e = host_not_found(&cfg, "ets-pcc");
        let SshrackError::HostNotFound { hint, .. } = e else {
            panic!("expected HostNotFound");
        };
        assert_eq!(hint.to_string(), " (did you mean 'ets-pc'?)");
    }

    #[test]
    fn host_not_found_omits_hint_when_unrelated() {
        let cfg = cfg_with("web1");
        let e = host_not_found(&cfg, "totally-different");
        let SshrackError::HostNotFound { hint, .. } = e else {
            panic!("expected HostNotFound");
        };
        assert_eq!(hint.to_string(), "");
    }

    // --- validate_no_duplicate ---

    #[test]
    fn duplicate_rejected_without_force() {
        let cfg = cfg_with("web1");
        assert!(matches!(
            validate_no_duplicate(&cfg, "web1", false),
            Err(SshrackError::HostAlreadyExists { .. })
        ));
    }

    #[test]
    fn duplicate_allowed_with_force() {
        let cfg = cfg_with("web1");
        assert!(validate_no_duplicate(&cfg, "web1", true).is_ok());
    }

    // --- validate_rename ---

    #[test]
    fn rename_taken_by_other_rejected() {
        let cfg = cfg_with_aliases(&["web1", "web2"]);
        let err = validate_rename(&cfg, "web1", "web2").unwrap_err();
        assert!(matches!(err, SshrackError::AliasTaken { alias } if alias == "web2"));
    }

    // --- add_host ---

    #[test]
    fn add_host_appends_with_supplied_id_and_returns_new_config() {
        let cfg = SshrackConfig::default();
        let id = new_id();
        let next = add_host(
            &cfg,
            id,
            "web1",
            "10.0.0.5",
            2222,
            Auth::inline(CredentialBody::new("deploy")),
        )
        .unwrap();
        assert_eq!(next.hosts.len(), 1);
        let h = &next.hosts[0];
        assert_eq!(h.id, id);
        assert_eq!(h.alias, "web1");
        assert_eq!(h.host, "10.0.0.5");
        assert_eq!(h.port, 2222);
        // The input config is untouched (immutable transform).
        assert!(cfg.hosts.is_empty());
    }

    #[test]
    fn add_host_rejects_forbidden_char() {
        let err = add_host(
            &SshrackConfig::default(),
            new_id(),
            "a:b",
            "h",
            22,
            Auth::inline(CredentialBody::new("u")),
        )
        .unwrap_err();
        assert!(matches!(err, SshrackError::InvalidAliasChar { .. }));
    }

    // --- remove_host ---

    #[test]
    fn removes_existing_host() {
        let cfg = cfg_with("web1");
        let next = remove_host(&cfg, "web1").expect("present host should be removed");
        assert!(next.hosts.is_empty());
    }

    #[test]
    fn missing_host_returns_none() {
        let cfg = cfg_with("web1");
        assert!(remove_host(&cfg, "ghost").is_none());
    }

    #[test]
    fn other_hosts_preserved() {
        let cfg = cfg_with_aliases(&["a", "b"]);
        let next = remove_host(&cfg, "a").expect("present host should be removed");
        assert_eq!(next.hosts.len(), 1);
        assert_eq!(next.hosts[0].alias, "b");
    }

    #[test]
    fn input_is_not_mutated() {
        let cfg = cfg_with("web1");
        let _ = remove_host(&cfg, "web1");
        assert_eq!(cfg.hosts.len(), 1, "remove_host must not mutate its input");
    }

    #[test]
    fn remove_host_preserves_credentials() {
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: new_id(),
                alias: "web1".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            credentials: vec![crate::config::schema::Credential {
                id: new_id(),
                alias: "team-dev".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..Default::default()
        };
        let next = remove_host(&cfg, "web1").unwrap();
        assert!(next.hosts.is_empty());
        assert_eq!(next.credentials.len(), 1, "credentials must be preserved");
    }

    // --- clone_host_as / validate_dst ---

    #[test]
    fn clone_replaces_alias_and_id_keeps_fields() {
        let src = inline_host("web1", CredentialBody::new("deploy").with_key("/k"));
        let dst_id = new_id();
        let cloned = clone_host_as(&src, dst_id, "web2");
        assert_eq!(cloned.id, dst_id);
        assert_eq!(cloned.alias, "web2");
        assert_eq!(cloned.host, src.host);
        assert_eq!(cloned.port, src.port);
        let body = cloned.auth.inline_body().unwrap();
        assert_eq!(body.user, "deploy");
        assert_eq!(body.key.as_deref(), Some(std::path::Path::new("/k")));
        assert_eq!(src.alias, "web1");
    }

    #[test]
    fn clone_preserves_inline_password() {
        let src = inline_host("db", CredentialBody::new("pg").with_password("s3cret"));
        let cloned = clone_host_as(&src, new_id(), "db2");
        assert_eq!(
            cloned.auth.inline_body().unwrap().password_plain(),
            Some("s3cret")
        );
    }

    #[test]
    fn clone_preserves_credential_reference() {
        let cid = new_id();
        let src = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::reference(cid),
        };
        let cloned = clone_host_as(&src, new_id(), "web2");
        assert_eq!(cloned.auth.credential_id(), Some(cid));
    }

    #[test]
    fn clone_gives_copy_a_fresh_id() {
        let src = inline_host("web1", CredentialBody::new("deploy"));
        let cloned = clone_host_as(&src, new_id(), "web2");
        assert_ne!(src.id, cloned.id, "copy must get a fresh id");
    }

    #[test]
    fn validate_dst_rejects_existing_alias() {
        let cfg = cfg_with_hosts(vec![inline_host("web1", CredentialBody::new("u"))]);
        assert!(matches!(
            validate_dst(&cfg, "web1"),
            Err(SshrackError::HostAlreadyExists { .. })
        ));
    }

    #[test]
    fn validate_dst_rejects_forbidden_char() {
        let cfg = cfg_with_hosts(vec![]);
        assert!(matches!(
            validate_dst(&cfg, "a:b"),
            Err(SshrackError::InvalidAliasChar { .. })
        ));
    }

    #[test]
    fn validate_dst_accepts_fresh_alias() {
        let cfg = cfg_with_hosts(vec![inline_host("web1", CredentialBody::new("u"))]);
        assert!(validate_dst(&cfg, "web2").is_ok());
    }

    // --- resolve_target / ad_hoc_host ---

    fn ro_none() -> ResolveOverrides<'static> {
        ResolveOverrides {
            ad_hoc: false,
            credential: None,
            port: None,
            user: None,
            identity: None,
        }
    }

    #[test]
    fn resolve_target_alias_hit_returns_entry_unchanged() {
        let cfg = cfg_with("web1");
        let host = resolve_target(&cfg, "web1", &ro_none()).unwrap();
        assert_eq!(host.alias, "web1");
        assert_eq!(host.host, "h");
        assert_eq!(host.port, 22);
        assert!(host.auth.inline_body().is_some());
    }

    #[test]
    fn resolve_target_alias_hit_with_credential_overrides_auth() {
        let cfg = cfg_with("web1");
        let cid = new_id();
        let mut o = ro_none();
        o.credential = Some(cid);
        let host = resolve_target(&cfg, "web1", &o).unwrap();
        assert_eq!(host.host, "h");
        assert_eq!(host.port, 22);
        assert_eq!(host.auth.credential_id(), Some(cid));
    }

    #[test]
    fn resolve_target_ad_hoc_with_credential_builds_ephemeral_ref() {
        let cfg = cfg_with("web1"); // "1.2.3.4" is not an alias here
        let cid = new_id();
        let mut o = ro_none();
        o.ad_hoc = true;
        o.credential = Some(cid);
        let host = resolve_target(&cfg, "1.2.3.4", &o).unwrap();
        assert_eq!(host.host, "1.2.3.4");
        assert_eq!(host.port, 22);
        assert_eq!(host.auth.credential_id(), Some(cid));
    }

    #[test]
    fn resolve_target_ad_hoc_with_user_builds_inline_body() {
        let cfg = SshrackConfig::default();
        let mut o = ro_none();
        o.ad_hoc = true;
        o.user = Some("deploy");
        o.identity = Some(std::path::Path::new("/k"));
        o.port = Some(2222);
        let host = resolve_target(&cfg, "host.example.com", &o).unwrap();
        assert_eq!(host.host, "host.example.com");
        assert_eq!(host.port, 2222);
        let body = host.auth.inline_body().unwrap();
        assert_eq!(body.user, "deploy");
        assert_eq!(body.key.as_deref(), Some(std::path::Path::new("/k")));
    }

    #[test]
    fn resolve_target_ad_hoc_without_identity_errors() {
        let cfg = SshrackConfig::default();
        let mut o = ro_none();
        o.ad_hoc = true;
        let err = resolve_target(&cfg, "1.2.3.4", &o).unwrap_err();
        assert!(matches!(err, SshrackError::MissingRequiredField { .. }));
    }

    #[test]
    fn resolve_target_miss_without_ad_hoc_is_host_not_found() {
        let cfg = cfg_with("web1");
        let err = resolve_target(&cfg, "web2", &ro_none()).unwrap_err();
        assert!(matches!(
            err,
            SshrackError::HostNotFound { alias, .. } if alias == "web2"
        ));
    }

    #[test]
    fn ad_hoc_host_mirrors_address_and_carries_auth() {
        let cid = new_id();
        let host = ad_hoc_host("10.0.0.5", 2222, Auth::reference(cid));
        assert_eq!(host.alias, "10.0.0.5");
        assert_eq!(host.host, "10.0.0.5");
        assert_eq!(host.port, 2222);
        assert_eq!(host.auth.credential_id(), Some(cid));
    }

    // --- add helpers (build_auth / auth_supplied_by_flags / merge_fields) ---

    fn opts_host(host: Option<&str>) -> AddOptions {
        AddOptions {
            host: host.map(Into::into),
            ..Default::default()
        }
    }

    #[test]
    fn auth_supplied_by_flags_detects_any_auth_flag() {
        assert!(!auth_supplied_by_flags(&AddOptions::default()));
        assert!(auth_supplied_by_flags(&AddOptions {
            credential: Some(new_id()),
            ..Default::default()
        }));
        assert!(auth_supplied_by_flags(&AddOptions {
            user: Some("ops".into()),
            ..Default::default()
        }));
        assert!(auth_supplied_by_flags(&AddOptions {
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        }));
    }

    #[test]
    fn build_auth_reference_wins_over_inline_flags() {
        let opts = AddOptions {
            credential: Some(new_id()),
            user: Some("ignored".into()),
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        };
        let auth = build_auth(&opts);
        assert!(auth.credential_id().is_some());
        assert!(auth.inline_body().is_none());
    }

    #[test]
    fn build_auth_inline_default_user() {
        let opts = AddOptions::default();
        let auth = build_auth(&opts);
        let body = auth.inline_body().unwrap();
        assert_eq!(body.user, "root");
    }

    #[test]
    fn build_auth_inline_key() {
        let opts = AddOptions {
            user: Some("ops".into()),
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        };
        let auth = build_auth(&opts);
        let body = auth.inline_body().unwrap();
        assert_eq!(body.user, "ops");
        assert!(body.key.is_some());
    }

    #[test]
    fn merge_applies_port_default_and_auth() {
        let h = merge_fields(new_id(), "web1", &opts_host(Some("10.0.0.5"))).unwrap();
        assert_eq!(h.host, "10.0.0.5");
        assert_eq!(h.port, 22);
        assert!(h.auth.inline_body().is_some());
    }

    #[test]
    fn merge_requires_host() {
        let err = merge_fields(new_id(), "web1", &opts_host(None)).unwrap_err();
        assert!(matches!(
            err,
            SshrackError::MissingRequiredField { field: "host" }
        ));
    }

    #[test]
    fn merge_rejects_forbidden_char() {
        let err = merge_fields(new_id(), "a:b", &opts_host(Some("h"))).unwrap_err();
        assert!(matches!(err, SshrackError::InvalidAliasChar { .. }));
    }

    // --- apply_patch / patch_body / finalize_body / edit_has_any_flag ---

    #[test]
    fn apply_all_none_keeps_original() {
        let orig = inline_host("web1", CredentialBody::new("deploy").with_key("/k"));
        let out = apply_patch(&orig, &EditOptions::default()).unwrap();
        assert_eq!(out.id, orig.id);
        assert_eq!(out.alias, "web1");
        assert_eq!(out.host, orig.host);
        assert_eq!(out.port, 2222);
        let body = out.auth.inline_body().unwrap();
        assert_eq!(body.user, "deploy");
        assert_eq!(body.key.as_deref(), Some(std::path::Path::new("/k")));
    }

    #[test]
    fn apply_overwrites_host_and_port() {
        let orig = inline_host("web1", CredentialBody::new("deploy"));
        let opts = EditOptions {
            host: Some("10.0.0.9".into()),
            port: Some(22000),
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert_eq!(out.host, "10.0.0.9");
        assert_eq!(out.port, 22000);
    }

    #[test]
    fn apply_credential_flag_switches_to_reference() {
        let orig = inline_host("web1", CredentialBody::new("deploy"));
        let cid = new_id();
        let opts = EditOptions {
            credential: Some(cid),
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert_eq!(out.auth.credential_id(), Some(cid));
    }

    #[test]
    fn apply_credential_flag_switches_reference_to_new_id() {
        let old_cid = new_id();
        let orig = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::reference(old_cid),
        };
        let new_cid = new_id();
        let opts = EditOptions {
            credential: Some(new_cid),
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert_eq!(out.auth.credential_id(), Some(new_cid));
    }

    #[test]
    fn apply_clear_identity_drops_key() {
        let orig = inline_host("web1", CredentialBody::new("deploy").with_key("/k"));
        let opts = EditOptions {
            clear_identity: true,
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert!(out.auth.inline_body().unwrap().key.is_none());
    }

    #[test]
    fn apply_rename_preserves_id() {
        // rename/user edits must keep the host's id so the keyring entry
        // (keyed by id) is not orphaned.
        let orig = inline_host("web1", CredentialBody::new("deploy"));
        let opts = EditOptions {
            rename: Some("web2".into()),
            user: Some("ops".into()),
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert_eq!(out.alias, "web2");
        assert_eq!(out.id, orig.id, "id must survive a patch");
    }

    #[test]
    fn patch_body_preserves_keyring_marker() {
        // A keyring-password body edited for user/rename must stay keyring-marked.
        let orig = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "deploy".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        };
        let opts = EditOptions {
            user: Some("ops".into()),
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        assert!(
            out.auth.inline_body().unwrap().keyring,
            "keyring marker must survive a patch"
        );
    }

    #[test]
    fn patch_body_clear_password_drops_keyring_marker() {
        let orig = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "deploy".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        };
        let opts = EditOptions {
            clear_password: true,
            ..Default::default()
        };
        let out = apply_patch(&orig, &opts).unwrap();
        let body = out.auth.inline_body().unwrap();
        assert!(
            !body.keyring,
            "keyring marker must be dropped on --clear-password"
        );
        assert!(body.password.is_none());
    }

    #[test]
    fn finalize_body_stamps_orig_id() {
        let id = new_id();
        let h = finalize_body(
            id,
            "web1",
            "10.0.0.5",
            2222,
            Auth::inline(CredentialBody::new("deploy")),
        );
        assert_eq!(h.id, id);
        assert_eq!(h.alias, "web1");
    }

    #[test]
    fn edit_has_any_flag_detects_any_flag() {
        assert!(!edit_has_any_flag(&EditOptions::default()));
        assert!(edit_has_any_flag(&EditOptions {
            rename: Some("x".into()),
            ..Default::default()
        }));
        assert!(edit_has_any_flag(&EditOptions {
            clear_credential: true,
            ..Default::default()
        }));
    }

    // --- delete_host_with_secret / copy_keyring_entry ---

    #[test]
    fn delete_host_with_secret_removes_and_forgets_keyring_entry() {
        let backend = FakeBackend::new();
        let id = new_id();
        backend.set(OwnerKind::Host, &id, "topsecret").unwrap();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id,
                alias: "kr-rm".into(),
                host: "10.0.0.99".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "root".into(),
                    password: None,
                    key: None,
                    keyring: true,
                }),
            }],
            ..Default::default()
        };
        let next = delete_host_with_secret(&cfg, "kr-rm", &backend).unwrap();
        assert!(next.hosts.is_empty());
        assert!(
            backend
                .get(&crate::id::keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .is_none(),
            "keyring entry must be deleted"
        );
    }

    #[test]
    fn delete_host_with_secret_leaves_non_keyring_entry_untouched() {
        // A non-keyring (plaintext/key/default) host has no keyring entry to
        // forget; delete still removes the host.
        let backend = FakeBackend::new();
        let cfg = cfg_with("web1");
        let next = delete_host_with_secret(&cfg, "web1", &backend).unwrap();
        assert!(next.hosts.is_empty());
    }

    #[test]
    fn delete_host_with_secret_missing_errors() {
        let backend = FakeBackend::new();
        let cfg = cfg_with("web1");
        let err = delete_host_with_secret(&cfg, "ghost", &backend).unwrap_err();
        assert!(matches!(err, SshrackError::HostNotFound { .. }));
    }

    // ---- forget_keyring_on_overwrite (host add --force cleanup) ----

    #[test]
    fn forget_keyring_on_overwrite_deletes_old_entry_when_marked() {
        // `host add --force` overwrites by generating a fresh id; the old
        // keyring entry (keyed by the OLD id) must be cleaned up so no orphaned
        // secret remains.
        let backend = FakeBackend::new();
        let old_id = new_id();
        backend.set(OwnerKind::Host, &old_id, "topsecret").unwrap();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: old_id,
                alias: "kr-overwrite".into(),
                host: "10.0.0.99".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "root".into(),
                    password: None,
                    key: None,
                    keyring: true,
                }),
            }],
            ..Default::default()
        };

        forget_keyring_on_overwrite(&cfg, "kr-overwrite", &backend);

        assert!(
            backend
                .get(&crate::id::keyring_key(OwnerKind::Host, &old_id))
                .unwrap()
                .is_none(),
            "old keyring entry must be deleted on --force overwrite"
        );
    }

    #[test]
    fn forget_keyring_on_overwrite_leaves_non_keyring_host_alone() {
        // A plaintext/key/default host has no keyring entry to forget; the
        // helper is a no-op (and must not touch any unrelated entry).
        let backend = FakeBackend::new();
        let cfg = cfg_with("web1"); // plaintext-style host, no keyring marking
        forget_keyring_on_overwrite(&cfg, "web1", &backend);
        // Nothing was ever set; nothing should appear. A non-keyring host must
        // not spuriously delete an unrelated entry.
        assert!(backend.entries.borrow().is_empty());
    }

    #[test]
    fn forget_keyring_on_overwrite_is_noop_when_alias_absent() {
        // Overwriting a non-existent alias is a no-op (there is nothing to clean).
        let backend = FakeBackend::new();
        let id = new_id();
        backend.set(OwnerKind::Host, &id, "unrelated").unwrap();
        let cfg = SshrackConfig::default(); // no hosts
        forget_keyring_on_overwrite(&cfg, "ghost", &backend);
        // The unrelated entry is untouched.
        assert_eq!(
            backend
                .get(&crate::id::keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("unrelated")
        );
    }

    #[test]
    fn copy_keyring_entry_copies_when_source_marked() {
        let backend = FakeBackend::new();
        let src_id = new_id();
        backend.set(OwnerKind::Host, &src_id, "topsecret").unwrap();
        let src = Host {
            id: src_id,
            alias: "web1".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "root".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        };
        let dst_id = new_id();
        let dst = clone_host_as(&src, dst_id, "web2");
        copy_keyring_entry(&src, &dst, &backend).unwrap();
        let copied = backend
            .get(&crate::id::keyring_key(OwnerKind::Host, &dst_id))
            .unwrap();
        assert_eq!(copied.as_deref().map(String::as_str), Some("topsecret"));
    }

    #[test]
    fn copy_keyring_entry_noop_when_source_not_marked() {
        // A plaintext / key / default source has no keyring entry to copy.
        let backend = FakeBackend::new();
        let src = inline_host("web1", CredentialBody::new("deploy").with_password("p"));
        let dst = clone_host_as(&src, new_id(), "web2");
        copy_keyring_entry(&src, &dst, &backend).unwrap();
        // No entries created.
        assert!(backend.entries.borrow().is_empty());
    }

    #[test]
    fn copy_keyring_entry_noop_when_source_unavailable() {
        // A keyring-marked source whose entry is missing/empty is a silent
        // no-op (the caller surfaces a re-enter hint); never an error here.
        let backend = FakeBackend::new();
        let src = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "root".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        };
        let dst = clone_host_as(&src, new_id(), "web2");
        assert!(copy_keyring_entry(&src, &dst, &backend).is_ok());
    }

    #[test]
    fn copy_keyring_entry_noop_when_either_side_is_reference() {
        // A credential-reference source has no inline body to read a marker from.
        let backend = FakeBackend::new();
        let cid = new_id();
        let src = Host {
            id: new_id(),
            alias: "web1".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::reference(cid),
        };
        let dst = clone_host_as(&src, new_id(), "web2");
        copy_keyring_entry(&src, &dst, &backend).unwrap();
    }
}
