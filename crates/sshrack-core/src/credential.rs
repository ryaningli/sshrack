//! Credential resolution for a host.
//!
//! A host's [`Auth`](crate::config::schema::Auth) is resolved into a concrete
//! identity: a reference is followed — by id — through the `[[credentials]]`
//! table, an inline body is used directly. The result feeds ssh/scp argv
//! assembly; the password (if any) flows through the SSH_ASKPASS hook in
//! [`crate::connect`] (the connect layer lands in a later task).
//!
//! Ref-by-id is the core guarantee of the redesigned schema: a host holds a
//! `[[credentials]]` entry's stable [`Ulid`], never its alias, so renaming a
//! credential never dangles a host's reference. [`find_referrers`] is keyed on
//! the same id so delete warnings stay accurate across renames too.

use std::path::PathBuf;

use ulid::Ulid;
use zeroize::Zeroizing;

use crate::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
use crate::error::{DidYouMean, SshrackError};
use crate::host::validate_alias_chars;
use crate::id::{OwnerKind, keyring_key};
use crate::secret::{self, SecretBackend};
use crate::suggest;

/// Where a resolved password lives, if any.
///
/// - [`PasswordSource::None`] — no password (key-only or default-ssh hosts).
/// - [`PasswordSource::Inline`] — plaintext password carried inline (plaintext
///   or decrypted-vault body); delivered to ssh via the askpass temp file.
/// - [`PasswordSource::Keyring`] — plaintext lives in the OS keyring under
///   `key`; the main process never materializes it. The askpass helper fetches
///   it directly via [`crate::secret::keyring::get`].
#[derive(Clone, Default)]
pub enum PasswordSource {
    /// No password for this identity.
    #[default]
    None,
    /// Plaintext password, wiped on drop. Redacted in `Debug`.
    Inline(Zeroizing<String>),
    /// The password is in the OS keyring under the derived account `key`
    /// (see [`keyring_key`]).
    Keyring {
        /// The keyring account key (`host:<ulid>` or `cred:<ulid>`).
        key: String,
    },
}

impl std::fmt::Debug for PasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f
                .debug_struct("PasswordSource")
                .field("variant", &"None")
                .finish(),
            Self::Inline(_) => f
                .debug_struct("PasswordSource")
                .field("variant", &"Inline")
                .field("password", &"<redacted>")
                .finish(),
            Self::Keyring { key } => f
                .debug_struct("PasswordSource")
                .field("variant", &"Keyring")
                .field("key", &key)
                .finish(),
        }
    }
}

/// The fully resolved identity for a connection: login user, optional key path,
/// and the password's source (inline plaintext, keyring, or none).
#[derive(Debug, Clone, Default)]
pub struct ResolvedAuth {
    /// Login user delivered to ssh (`-l`) / scp (`user@`).
    pub user: String,
    /// Optional identity key path delivered to ssh (`-i`).
    pub key_path: Option<PathBuf>,
    /// Where the password lives, if any.
    pub password: PasswordSource,
}

impl ResolvedAuth {
    /// Build a resolved identity from already-resolved fields, enforcing the
    /// mutual-exclusion invariant. Callers decrypt any [`crate::config::schema::Secret::Encrypted`]
    /// password first (see [`resolve`]).
    pub fn from_plain(
        user: String,
        key_path: Option<PathBuf>,
        password: PasswordSource,
    ) -> Result<Self, SshrackError> {
        // Mutual exclusion: a body with both a key and a password is malformed.
        if key_path.is_some() && !matches!(password, PasswordSource::None) {
            return Err(SshrackError::InvalidCredentialBody { user });
        }
        Ok(Self {
            user,
            key_path,
            password,
        })
    }
}

/// Build a [`SshrackError::CredentialNotFound`] with a "did you mean" hint
/// computed from the config's credential aliases. Shared by credential lookup
/// failures in resolve, cred show, cred rm, and cred edit. (scp reaches this
/// through `credential::resolve`, so it gains the hint for free.)
///
/// `looked_for` is the alias (or alias-like string) the user typed; the hint is
/// purely cosmetic since [`resolve`] looks credentials up by id, not alias.
pub fn credential_not_found(cfg: &SshrackConfig, looked_for: &str) -> SshrackError {
    let candidates: Vec<&str> = cfg.credentials.iter().map(|c| c.alias.as_str()).collect();
    SshrackError::CredentialNotFound {
        alias: looked_for.into(),
        hint: DidYouMean::from_option(suggest::closest(&candidates, looked_for)),
    }
}

/// Build a credential, validating the alias and body. The caller supplies the
/// stable `id` (the owner owns the id; the body does not).
pub fn merge_credential(
    id: Ulid,
    alias: &str,
    body: CredentialBody,
) -> Result<Credential, SshrackError> {
    validate_alias_chars(alias)?;
    body.validate()?;
    Ok(Credential {
        id,
        alias: alias.into(),
        body,
    })
}

/// Reject a duplicate credential alias unless `force` is set.
pub fn validate_no_duplicate_credential(
    cfg: &SshrackConfig,
    alias: &str,
    force: bool,
) -> Result<(), SshrackError> {
    if cfg.find_credential_by_alias(alias).is_some() && !force {
        return Err(SshrackError::CredentialAlreadyExists {
            alias: alias.into(),
        });
    }
    Ok(())
}

/// Validate renaming to `new_alias`, excluding the current alias.
pub fn validate_rename_credential(
    cfg: &SshrackConfig,
    current_alias: &str,
    new_alias: &str,
) -> Result<(), SshrackError> {
    validate_alias_chars(new_alias)?;
    let taken_by_other = cfg
        .credentials
        .iter()
        .any(|c| c.alias == new_alias && c.alias != current_alias);
    if taken_by_other {
        return Err(SshrackError::AliasTaken {
            alias: new_alias.to_string(),
        });
    }
    Ok(())
}

/// Return a new config with `alias` removed from credentials (hosts preserved),
/// or `None` if it was absent.
///
/// Hosts referencing the removed credential by id are NOT rewritten here — the
/// caller surfaces [`find_referrers`] as a delete warning and decides. Leaving
/// a dangling id is intentional: the display layer maps ids to aliases, and
/// rewriting auth refs is a separate concern.
pub fn remove_credential(cfg: &SshrackConfig, alias: &str) -> Option<SshrackConfig> {
    if !cfg.credentials.iter().any(|c| c.alias == alias) {
        return None;
    }
    let mut next = cfg.clone();
    next.credentials.retain(|c| c.alias != alias);
    Some(next)
}

/// Host ids whose auth references this credential (for delete warnings).
///
/// Keyed by the credential's stable [`Ulid`], not its alias, so a rename never
/// silently drops a referrer from the warning. The display layer maps each id
/// back to a host alias when rendering.
pub fn find_referrers(cfg: &SshrackConfig, cred_id: &Ulid) -> Vec<Ulid> {
    cfg.hosts
        .iter()
        .filter_map(|h| match &h.auth {
            Auth::Ref { credential } if credential == cred_id => Some(h.id),
            _ => None,
        })
        .collect()
}

// ===========================================================================
// add / edit / rm pure helpers (lifted from sshrack-old's cmd/cred/{add,edit,rm}.rs)
// ===========================================================================

/// Field values supplied via CLI flags for `cred add`. `None` means "not
/// provided" (interactive mode prompts; `--no-input` mode errors for required
/// `user`). The CLI fills this struct; core never reads the TTY. A password is
/// never a flag (passwords never enter argv) — it is attached by the CLI's
/// interactive path and sealed via the (forthcoming) vault orchestration.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AddOptions {
    /// Login user. Required in `--no-input` mode.
    pub user: Option<String>,
    /// Inline private key path.
    pub identity: Option<PathBuf>,
    /// Non-interactive: all required fields must come from flags.
    pub no_input: bool,
    /// Overwrite an existing alias.
    pub force: bool,
}

/// Field updates supplied via CLI flags for `cred edit`. `None` keeps the
/// existing value; `Some` overwrites; `clear_*` drops it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EditOptions {
    pub user: Option<String>,
    pub identity: Option<PathBuf>,
    /// Drop an existing identity key (mutually exclusive with `identity`).
    pub clear_identity: bool,
    /// Rename to a new alias. The caller validates the new name against the
    /// config via [`validate_rename_credential`] before applying.
    pub rename: Option<String>,
    /// Non-interactive mode (does not change patch behaviour itself; the CLI
    /// uses it to decide between the patch path and the full-prompt path).
    pub no_input: bool,
}

/// Build a body from add flags (`--no-input` mode). The password is never set
/// here — it cannot come from a flag. [`AddOptions::user`] is required in this
/// mode.
pub fn build_body(opts: &AddOptions) -> Result<CredentialBody, SshrackError> {
    let user = opts
        .user
        .clone()
        .ok_or(SshrackError::MissingRequiredField { field: "user" })?;
    let mut body = CredentialBody::new(user);
    if let Some(k) = &opts.identity {
        body = body.with_key(k.clone());
    }
    body.validate()?;
    Ok(body)
}

/// True when the caller supplied any field-setting flag, so the interactive
/// `prompt_credential_body` path is skipped in favour of the patch path.
pub fn edit_has_any_flag(opts: &EditOptions) -> bool {
    opts.user.is_some() || opts.identity.is_some() || opts.clear_identity || opts.rename.is_some()
}

/// Return a new config with a credential appended, or `Err` on a forbidden
/// alias character. Pure: does not mutate `cfg`, does not touch the filesystem.
/// The caller supplies the stable `id` (generated via [`crate::id::new_id`]);
/// the body's password is sealed by the CLI's interactive path before this is
/// called.
///
/// Does NOT check for duplicate aliases — the caller runs
/// [`validate_no_duplicate_credential`] first (the `--force` flag belongs there,
/// not on the pure append).
pub fn add_credential(
    cfg: &SshrackConfig,
    id: Ulid,
    alias: &str,
    body: CredentialBody,
) -> Result<SshrackConfig, SshrackError> {
    validate_alias_chars(alias)?;
    body.validate()?;
    let mut next = cfg.clone();
    next.credentials.push(Credential {
        id,
        alias: alias.into(),
        body,
    });
    Ok(next)
}

/// Insert or replace the credential keyed by alias, preserving insertion order
/// on replace (an existing alias is overwritten in place; a new alias is
/// appended). Pure: returns a new config. Shared by `add --force` and `edit`.
pub fn upsert_credential(cfg: &SshrackConfig, cred: Credential) -> SshrackConfig {
    let mut next = cfg.clone();
    if let Some(existing) = next
        .credentials
        .iter_mut()
        .find(|c| c.alias == cred.alias.as_str())
    {
        *existing = cred;
    } else {
        next.credentials.push(cred);
    }
    next
}

/// Pure transform: apply edit flags to a credential. The original password is
/// preserved only when no new key is being set: a credential carries at most
/// one secret, so once `--identity` (or a preserved key) is in play the password
/// must be dropped rather than silently re-attached (`with_password` would
/// otherwise clear the key). The password itself is only ever changed
/// interactively (the CLI re-seals via the vault path after this).
///
/// The credential's `id` is preserved verbatim so a patch (including
/// `--rename`) never orphans the keyring entry keyed by that id. The body's
/// `keyring` marker is cleared when switching to/clearing an identity (the old
/// keyring entry is then orphaned, which is the caller's concern).
pub fn apply_credential_patch(
    orig: &Credential,
    opts: &EditOptions,
) -> Result<Credential, SshrackError> {
    let alias = opts.rename.clone().unwrap_or_else(|| orig.alias.clone());
    validate_alias_chars(&alias)?;
    let user = opts.user.clone().unwrap_or_else(|| orig.body.user.clone());
    let key = if opts.clear_identity {
        None
    } else {
        opts.identity.clone().or(orig.body.key.clone())
    };
    let (password, keyring) = if opts.identity.is_some() || opts.clear_identity {
        // Switching to / clearing a key drops any password/marker.
        (None, false)
    } else {
        (orig.body.password.clone(), orig.body.keyring)
    };
    let mut body = CredentialBody {
        user,
        password,
        key: None,
        keyring,
    };
    if let Some(k) = key {
        body = body.with_key(k);
    }
    body.validate()?;
    Ok(Credential {
        // Preserve the original stable id: the keyring entry and every host
        // Auth::Ref are keyed by it; a patch must never mint a new identity.
        id: orig.id,
        alias,
        body,
    })
}

/// Remove the credential named `alias` from `cfg` and best-effort forget its
/// keyring entry when the credential's body was keyring-marked. Returns the new
/// config (keyring already cleaned), or `Err(CredentialNotFound)` if absent.
///
/// The keyring cleanup goes through [`secret::forget_keyring_secret`] with
/// [`OwnerKind::Credential`] and the credential's stable id (the body no longer
/// carries an id — the owner does). Pure w.r.t. the filesystem: the caller
/// persists the returned config.
pub fn delete_credential_with_secret(
    cfg: &SshrackConfig,
    alias: &str,
    backend: &dyn SecretBackend,
) -> Result<SshrackConfig, SshrackError> {
    let Some(cred) = cfg.find_credential_by_alias(alias) else {
        return Err(credential_not_found(cfg, alias));
    };
    // Snapshot the keyring-relevant fields before the (cloned) remove, so the
    // forget decision reflects the credential as it stood at call time.
    let (cred_id, keyring) = (cred.id, cred.body.keyring);
    let next = remove_credential(cfg, alias)
        // remove_credential returns None only when the alias is absent, which
        // the find_credential_by_alias above already ruled out.
        .expect("invariant: credential present (checked above)");
    secret::forget_keyring_secret(backend, OwnerKind::Credential, &cred_id, keyring);
    Ok(next)
}

/// Best-effort: if `src` is a keyring-password credential, copy its keyring
/// entry from the source's id to `dst`'s fresh id so the copy connects
/// immediately. A missing/unreachable entry is reported via the returned `Err`
/// (carrying no secret); the caller logs-and-continues. Never materializes the
/// password outside the backend round-trip.
///
/// Used by `cred cp`: the copy gets a fresh id (it is an independent keyring
/// identity), and this helper re-keys the entry onto it.
pub fn copy_keyring_entry(
    src: &Credential,
    dst: &Credential,
    backend: &dyn SecretBackend,
) -> Result<(), SshrackError> {
    if !src.body.keyring {
        return Ok(());
    }
    match backend.get(&keyring_key(OwnerKind::Credential, &src.id))? {
        Some(pw) => backend.set(OwnerKind::Credential, &dst.id, &pw),
        None => Ok(()),
    }
}

/// Decrypt a stored password secret into plaintext, given an optional master
/// key. `None`/`Plain` need no key; `Encrypted` without a key is `VaultLocked`.
///
/// `alias_label` is the owner's display label (host or credential alias) used
/// only in the [`SshrackError::DecryptionFailed`] message — never the secret.
pub(crate) fn decrypt_secret(
    secret: Option<&crate::config::schema::Secret>,
    vault: Option<&crate::secret::vault::VaultKey>,
    alias_label: &str,
) -> Result<Option<Zeroizing<String>>, SshrackError> {
    use crate::config::schema::Secret;
    use crate::secret::vault::crypto;
    match secret {
        None => Ok(None),
        // `p.clone()` copies the plaintext into a wiped wrapper; the source
        // inside `Secret::Plain(String)` is not zeroized (the String-typed
        // Secret definition does not allow it). Only the returned value is
        // wiped on drop; a zeroizing Secret::Plain is a follow-up.
        Some(Secret::Plain(p)) => Ok(Some(Zeroizing::new(p.clone()))),
        Some(Secret::Encrypted(enc)) => match vault {
            // `VaultKey` is `Zeroizing<[u8; 32]>`; passing `key` borrows it as
            // `&Zeroizing<[u8; 32]>`, which auto-derefs to the `&[u8; 32]`
            // that `crypto::decrypt` expects.
            // crypto::decrypt fails with a fieldless DecryptError; attach the
            // alias label and discard crypto detail (no decryption oracle).
            Some(key) => Ok(Some(crypto::decrypt(enc, key).map_err(|_| {
                SshrackError::DecryptionFailed {
                    alias: alias_label.to_string(),
                }
            })?)),
            None => Err(SshrackError::VaultLocked),
        },
    }
}

/// Resolve `host`'s auth into a concrete identity, decrypting any encrypted
/// password with `vault`. Pure (no I/O); the master key is an input. Returns
/// `CredentialNotFound` for a dangling reference (with a did-you-mean hint
/// computed from credential aliases), `VaultLocked` when an encrypted password
/// is seen without a key.
///
/// The reference arm follows [`Auth::Ref`] by the credential's stable [`Ulid`]
/// (via [`SshrackConfig::find_credential_by_id`]) — never its alias — so
/// renaming the credential leaves this resolution intact.
///
/// The resulting [`ResolvedAuth::password`] is a [`PasswordSource`]:
/// [`PasswordSource::Inline`] for plaintext/vault bodies (decrypted here),
/// [`PasswordSource::Keyring`] for keyring-marker bodies (keyed off the owner's
/// stable id — `host:<id>` for inline auth, `cred:<id>` for a referenced
/// credential), and [`PasswordSource::None`] otherwise.
pub fn resolve(
    host: &Host,
    cfg: &SshrackConfig,
    vault: Option<&crate::secret::vault::VaultKey>,
) -> Result<ResolvedAuth, SshrackError> {
    // owner_kind + owner_id select the keyring account; alias_label is the
    // display name attached to a decryption failure (never the secret).
    let (user, key_path, password_secret, keyring, owner_kind, owner_id, alias_label) =
        match &host.auth {
            Auth::Ref { credential } => {
                let cred = cfg.find_credential_by_id(credential).ok_or_else(|| {
                    // The user typed a host alias, not a credential alias; surface a
                    // did-you-mean over credential aliases anyway — it is the only
                    // hint we can compute without a stable "looked-for" string, and
                    // a dangling id almost always means a deleted credential the
                    // user might re-add by alias.
                    credential_not_found(cfg, &credential.to_string())
                })?;
                (
                    cred.body.user.clone(),
                    cred.body.key.clone(),
                    cred.body.password.clone(),
                    cred.body.keyring,
                    OwnerKind::Credential,
                    cred.id,
                    cred.alias.as_str(),
                )
            }
            Auth::Inline(body) => {
                // Validate mutual exclusion on the raw body before decrypting.
                body.validate()?;
                (
                    body.user.clone(),
                    body.key.clone(),
                    body.password.clone(),
                    body.keyring,
                    OwnerKind::Host,
                    host.id,
                    host.alias.as_str(),
                )
            }
        };
    let password = if keyring {
        // Keyring body: plaintext lives in the OS keyring under the owner's
        // stable id. The alias is NOT in the key, so renames are safe.
        PasswordSource::Keyring {
            key: keyring_key(owner_kind, &owner_id),
        }
    } else {
        // Plaintext or vault body: decrypt to inline plaintext (None if absent).
        match decrypt_secret(password_secret.as_ref(), vault, alias_label)? {
            Some(p) => PasswordSource::Inline(p),
            None => PasswordSource::None,
        }
    };
    ResolvedAuth::from_plain(user, key_path, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
    use std::path::PathBuf;
    use ulid::Ulid;

    #[test]
    fn password_source_debug_redacts_inline_plaintext() {
        // The plaintext must never survive {:?} formatting — this guards
        // against re-introducing #[derive(Debug)] on PasswordSource.
        let p = PasswordSource::Inline(Zeroizing::new("hunter2".into()));
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("hunter2"), "Debug leaked plaintext: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }

    #[test]
    fn password_source_debug_keyring_shows_non_sensitive_key() {
        // The keyring route label is not a secret; it must remain visible so
        // error/debug output stays useful for diagnosis.
        let p = PasswordSource::Keyring {
            key: "host:web1".into(),
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("host:web1"), "key redacted: {dbg}");
    }

    #[test]
    fn resolved_auth_debug_transitively_redacts_inline_password() {
        // ResolvedAuth #[derive(Debug)] and embeds PasswordSource; the custom
        // Debug must reach it transitively.
        let r = ResolvedAuth {
            user: "root".into(),
            key_path: None,
            password: PasswordSource::Inline(Zeroizing::new("hunter2".into())),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("hunter2"), "ResolvedAuth Debug leaked: {dbg}");
    }

    fn body(user: &str) -> CredentialBody {
        CredentialBody::new(user)
    }

    fn cfg_with_cred(alias: &str) -> SshrackConfig {
        SshrackConfig {
            credentials: vec![Credential {
                id: Ulid::new(),
                alias: alias.into(),
                body: body("u"),
            }],
            ..Default::default()
        }
    }

    fn inline_host(b: CredentialBody) -> Host {
        Host {
            id: Ulid::new(),
            alias: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(b),
        }
    }

    fn ref_host(cred_id: Ulid) -> Host {
        Host {
            id: Ulid::new(),
            alias: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::reference(cred_id),
        }
    }

    #[test]
    fn inline_password_resolves() {
        let h = inline_host(CredentialBody::new("root").with_password("secret"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        assert_eq!(r.user, "root");
        assert!(r.key_path.is_none());
        match &r.password {
            PasswordSource::Inline(p) => assert_eq!(p.as_str(), "secret"),
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn inline_key_resolves() {
        let h = inline_host(CredentialBody::new("ops").with_key("/k"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        assert_eq!(r.user, "ops");
        assert_eq!(r.key_path.as_deref(), Some(PathBuf::from("/k").as_path()));
        assert!(matches!(r.password, PasswordSource::None));
    }

    #[test]
    fn inline_default_resolves_no_secret() {
        let h = inline_host(CredentialBody::new("ec2-user"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        assert_eq!(r.user, "ec2-user");
        assert!(r.key_path.is_none());
        assert!(matches!(r.password, PasswordSource::None));
    }

    #[test]
    fn reference_resolves_through_credential_table_by_id() {
        let cid = Ulid::new();
        let h = ref_host(cid);
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                alias: "team-dev".into(),
                body: CredentialBody::new("deploy").with_key("/team"),
            }],
            ..Default::default()
        };
        let r = resolve(&h, &cfg, None).unwrap();
        assert_eq!(r.user, "deploy");
        assert_eq!(
            r.key_path.as_deref(),
            Some(PathBuf::from("/team").as_path())
        );
    }

    #[test]
    fn dangling_reference_errors() {
        // A host whose auth refs a credential id that is not in the table.
        let h = ref_host(Ulid::new());
        let err = resolve(&h, &SshrackConfig::default(), None).unwrap_err();
        assert!(matches!(err, SshrackError::CredentialNotFound { .. }));
    }

    #[test]
    fn mutual_exclusion_violation_errors() {
        let b = CredentialBody {
            user: "u".into(),
            password: Some(crate::config::schema::Secret::Plain("p".into())),
            key: Some(PathBuf::from("/k")),
            keyring: false,
        };
        let h = inline_host(b);
        assert!(matches!(
            resolve(&h, &SshrackConfig::default(), None),
            Err(SshrackError::InvalidCredentialBody { .. })
        ));
    }

    #[test]
    fn credential_not_found_carries_closest_hint() {
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: Ulid::new(),
                alias: "team-dev".into(),
                body: crate::config::schema::CredentialBody::new("deploy"),
            }],
            ..Default::default()
        };
        let e = credential_not_found(&cfg, "team-devv");
        let SshrackError::CredentialNotFound { hint, .. } = e else {
            panic!("expected CredentialNotFound");
        };
        assert_eq!(hint.to_string(), " (did you mean 'team-dev'?)");
    }

    #[test]
    fn merge_credential_accepts_reserved_word_alias() {
        // Reserved words are legal aliases now (reachable via `sshrack ssh <name>`).
        let c = merge_credential(Ulid::new(), "cred", body("u")).unwrap();
        assert_eq!(c.alias, "cred");
    }

    #[test]
    fn merge_credential_rejects_forbidden_char() {
        let err = merge_credential(Ulid::new(), "a:b", body("u")).unwrap_err();
        assert!(matches!(err, SshrackError::InvalidAliasChar { .. }));
    }

    #[test]
    fn merge_credential_carries_supplied_id() {
        // The id is the caller's, not generated inside merge_credential.
        let id = Ulid::new();
        let c = merge_credential(id, "team", body("u")).unwrap();
        assert_eq!(c.id, id);
    }

    #[test]
    fn duplicate_credential_rejected_without_force() {
        let cfg = cfg_with_cred("team-dev");
        assert!(matches!(
            validate_no_duplicate_credential(&cfg, "team-dev", false),
            Err(SshrackError::CredentialAlreadyExists { .. })
        ));
    }

    #[test]
    fn duplicate_credential_allowed_with_force() {
        let cfg = cfg_with_cred("team-dev");
        assert!(validate_no_duplicate_credential(&cfg, "team-dev", true).is_ok());
    }

    #[test]
    fn rename_credential_taken_rejected() {
        let cfg = SshrackConfig {
            credentials: vec![
                Credential {
                    id: Ulid::new(),
                    alias: "a".into(),
                    body: body("u"),
                },
                Credential {
                    id: Ulid::new(),
                    alias: "b".into(),
                    body: body("u"),
                },
            ],
            ..Default::default()
        };
        assert!(matches!(
            validate_rename_credential(&cfg, "a", "b"),
            Err(SshrackError::AliasTaken { alias }) if alias == "b"
        ));
    }

    #[test]
    fn rename_credential_to_self_ok() {
        let cfg = cfg_with_cred("a");
        assert!(validate_rename_credential(&cfg, "a", "a").is_ok());
    }

    #[test]
    fn remove_credential_preserves_hosts() {
        let cid = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                alias: "web1".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::reference(cid),
            }],
            credentials: vec![Credential {
                id: cid,
                alias: "team-dev".into(),
                body: body("u"),
            }],
            ..Default::default()
        };
        let next = remove_credential(&cfg, "team-dev").unwrap();
        assert!(next.credentials.is_empty());
        assert_eq!(next.hosts.len(), 1, "hosts must be preserved");
    }

    #[test]
    fn remove_credential_missing_returns_none() {
        let cfg = cfg_with_cred("a");
        assert!(remove_credential(&cfg, "ghost").is_none());
    }

    #[test]
    fn find_referrers_lists_host_ids() {
        let cid = Ulid::new();
        let web1_id = Ulid::new();
        let web2_id = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![
                Host {
                    id: web1_id,
                    alias: "web1".into(),
                    host: "h".into(),
                    port: 22,
                    auth: Auth::reference(cid),
                },
                Host {
                    id: web2_id,
                    alias: "web2".into(),
                    host: "h".into(),
                    port: 22,
                    auth: Auth::reference(cid),
                },
                Host {
                    id: Ulid::new(),
                    alias: "db".into(),
                    host: "h".into(),
                    port: 22,
                    auth: Auth::inline(body("pg")),
                },
            ],
            credentials: vec![Credential {
                id: cid,
                alias: "team-dev".into(),
                body: body("u"),
            }],
            ..Default::default()
        };
        assert_eq!(find_referrers(&cfg, &cid), vec![web1_id, web2_id]);
    }

    #[test]
    fn find_referrers_empty_when_no_match() {
        let cid = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                alias: "web1".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(body("u")),
            }],
            credentials: vec![],
            ..Default::default()
        };
        assert!(find_referrers(&cfg, &cid).is_empty());
    }

    #[test]
    fn resolve_keyring_inline_body_emits_keyring_source() {
        // A keyring-marker inline body resolves to PasswordSource::Keyring whose
        // key is host:<host-id> (the alias is NOT in the key).
        let host_id = Ulid::new();
        let h = Host {
            id: host_id,
            alias: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "root".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        };
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        match r.password {
            PasswordSource::Keyring { key } => {
                assert_eq!(key, format!("host:{host_id}"));
                assert_ne!(key, "host:h", "alias must not appear in the key");
            }
            other => panic!("expected Keyring, got {other:?}"),
        }
    }

    #[test]
    fn resolve_keyring_credential_emits_keyring_source() {
        let cid = Ulid::new();
        let h = ref_host(cid);
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                alias: "team-dev".into(),
                body: CredentialBody {
                    user: "deploy".into(),
                    password: None,
                    key: None,
                    keyring: true,
                },
            }],
            ..Default::default()
        };
        let r = resolve(&h, &cfg, None).unwrap();
        match r.password {
            PasswordSource::Keyring { key } => {
                assert_eq!(key, format!("cred:{cid}"));
            }
            other => panic!("expected Keyring, got {other:?}"),
        }
    }

    #[test]
    fn resolve_key_body_emits_no_password() {
        // A key body has no password of any kind.
        let h = inline_host(CredentialBody::new("ops").with_key("/k"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        assert!(matches!(r.password, PasswordSource::None));
    }

    #[test]
    fn resolve_default_body_emits_no_password() {
        let h = inline_host(CredentialBody::new("ec2-user"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        assert!(matches!(r.password, PasswordSource::None));
    }

    #[test]
    fn resolve_plaintext_body_emits_inline_source() {
        let h = inline_host(CredentialBody::new("root").with_password("secret"));
        let r = resolve(&h, &SshrackConfig::default(), None).unwrap();
        match r.password {
            PasswordSource::Inline(p) => {
                assert_eq!(p.as_str(), "secret");
            }
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn resolve_decrypts_encrypted_password_with_key() {
        use crate::config::schema::{CredentialBody, Secret};
        use crate::secret::vault::{VaultKey, crypto};
        let key: VaultKey = crypto::derive_key(
            "x",
            &crate::secret::vault::fast_meta("AAAAAAAAAAAAAAAAAAAAAA=="),
        )
        .unwrap();
        let enc = crypto::encrypt(b"secret", &key).unwrap();
        let h = inline_host(CredentialBody {
            user: "root".into(),
            password: Some(Secret::Encrypted(enc)),
            key: None,
            keyring: false,
        });
        let r = resolve(&h, &SshrackConfig::default(), Some(&key)).unwrap();
        match &r.password {
            PasswordSource::Inline(p) => assert_eq!(p.as_str(), "secret"),
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn resolve_errors_when_encrypted_but_locked() {
        use crate::config::schema::{CredentialBody, EncryptedSecret, Secret};
        let h = inline_host(CredentialBody {
            user: "root".into(),
            password: Some(Secret::Encrypted(EncryptedSecret {
                nonce: "n".into(),
                cipher: "c".into(),
            })),
            key: None,
            keyring: false,
        });
        assert!(matches!(
            resolve(&h, &SshrackConfig::default(), None),
            Err(SshrackError::VaultLocked)
        ));
    }

    #[test]
    fn resolve_decrypt_failure_names_alias() {
        use crate::config::schema::{Auth, CredentialBody, Host, Secret};
        use crate::secret::vault::crypto;
        let enc = crypto::encrypt(b"secret", &[1u8; 32]).unwrap();
        let h = Host {
            id: Ulid::new(),
            alias: "web1".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "root".into(),
                password: Some(Secret::Encrypted(enc)),
                key: None,
                keyring: false,
            }),
        };
        let err = resolve(
            &h,
            &SshrackConfig::default(),
            Some(
                &crypto::derive_key(
                    "x",
                    &crate::secret::vault::fast_meta("AAAAAAAAAAAAAAAAAAAAAA=="),
                )
                .unwrap(),
            ),
        )
        .unwrap_err();
        assert!(matches!(err, SshrackError::DecryptionFailed { alias } if alias == "web1"));
    }

    /// Regression for the core ref-by-id guarantee: a host references a
    /// credential by id; renaming that credential's ALIAS (the user-facing
    /// name) must not break `resolve`, because the host holds the id, not the
    /// alias. Pre-ref-by-id (alias-keyed) this would have dangled.
    #[test]
    fn renaming_credential_alias_keeps_reference_resolvable() {
        let cid = Ulid::new();
        let host_id = Ulid::new();
        // Host references the credential by its stable id and lives in the
        // config so find_referrers can see it.
        let h = Host {
            id: host_id,
            alias: "web1".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::reference(cid),
        };
        // Credential exists under alias "team-dev".
        let mut cfg = SshrackConfig {
            hosts: vec![h.clone()],
            credentials: vec![Credential {
                id: cid,
                alias: "team-dev".into(),
                body: CredentialBody::new("deploy").with_password("p"),
            }],
            ..Default::default()
        };
        // Resolve works before the rename.
        let before = resolve(&h, &cfg, None).unwrap();
        assert_eq!(before.user, "deploy");
        // find_referrers lists the host before the rename.
        assert_eq!(find_referrers(&cfg, &cid), vec![host_id]);

        // Rename the credential alias in place (id unchanged). A rename through
        // the CLI would re-run merge_credential with the same id; here we edit
        // the alias directly to exercise the resolution invariant alone.
        cfg.credentials[0].alias = "prod-team".into();
        assert!(
            validate_rename_credential(&cfg, "prod-team", "prod-team").is_ok(),
            "rename to self should validate"
        );

        // Resolve still works after the rename — the host's id reference is
        // intact. This is the central promise of ref-by-id.
        let after = resolve(&h, &cfg, None).unwrap();
        assert_eq!(after.user, "deploy");
        match after.password {
            PasswordSource::Inline(p) => assert_eq!(p.as_str(), "p"),
            other => panic!("expected Inline after rename, got {other:?}"),
        }

        // find_referrers is keyed by id, so it still lists the host after the
        // alias rename — delete warnings stay accurate across renames.
        assert_eq!(find_referrers(&cfg, &cid), vec![host_id]);
    }

    // ---- add / edit / rm pure helpers ----

    use crate::config::schema::SecretKind;
    use crate::id::new_id;
    use crate::secret::SecretBackend;
    use crate::secret::test_doubles::FakeBackend;

    #[test]
    fn build_body_requires_user_in_no_input_mode() {
        let err = build_body(&AddOptions::default()).unwrap_err();
        assert!(matches!(
            err,
            SshrackError::MissingRequiredField { field: "user" }
        ));
    }

    #[test]
    fn build_body_user_and_key() {
        let opts = AddOptions {
            user: Some("ops".into()),
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        };
        let b = build_body(&opts).unwrap();
        assert_eq!(b.user, "ops");
        assert_eq!(b.secret_kind(), SecretKind::Key);
    }

    #[test]
    fn edit_has_any_flag_detects_each_flag() {
        assert!(!edit_has_any_flag(&EditOptions::default()));
        assert!(edit_has_any_flag(&EditOptions {
            user: Some("u".into()),
            ..Default::default()
        }));
        assert!(edit_has_any_flag(&EditOptions {
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        }));
        assert!(edit_has_any_flag(&EditOptions {
            clear_identity: true,
            ..Default::default()
        }));
        assert!(edit_has_any_flag(&EditOptions {
            rename: Some("d".into()),
            ..Default::default()
        }));
    }

    #[test]
    fn add_credential_appends_to_config() {
        let cfg = SshrackConfig::default();
        let id = new_id();
        let next = add_credential(&cfg, id, "team", body("deploy")).unwrap();
        assert_eq!(next.credentials.len(), 1);
        assert_eq!(next.credentials[0].id, id);
        assert_eq!(next.credentials[0].alias, "team");
        // Original config is untouched (immutable).
        assert!(cfg.credentials.is_empty());
    }

    #[test]
    fn add_credential_rejects_forbidden_alias_char() {
        let cfg = SshrackConfig::default();
        assert!(matches!(
            add_credential(&cfg, new_id(), "a:b", body("u")),
            Err(SshrackError::InvalidAliasChar { .. })
        ));
    }

    #[test]
    fn add_credential_rejects_invalid_body() {
        // Mutual-exclusion violation surfaces via body.validate().
        let bad = CredentialBody {
            user: "u".into(),
            password: Some(crate::config::schema::Secret::Plain("p".into())),
            key: Some(PathBuf::from("/k")),
            keyring: false,
        };
        assert!(matches!(
            add_credential(&SshrackConfig::default(), new_id(), "a", bad),
            Err(SshrackError::InvalidCredentialBody { .. })
        ));
    }

    #[test]
    fn upsert_replaces_in_place_on_alias_match() {
        let cfg = cfg_with_cred("team");
        let original_id = cfg.credentials[0].id;
        // Clone-then-build so we can hand ownership into upsert.
        let next = cfg.clone();
        let replacement = Credential {
            id: original_id,
            alias: "team".into(),
            body: body("new-user"),
        };
        let out = upsert_credential(&next, replacement);
        assert_eq!(
            out.credentials.len(),
            1,
            "must not duplicate on alias match"
        );
        assert_eq!(out.credentials[0].body.user, "new-user");
    }

    #[test]
    fn upsert_appends_when_alias_is_new() {
        let cfg = cfg_with_cred("a");
        let added = Credential {
            id: new_id(),
            alias: "b".into(),
            body: body("u"),
        };
        let out = upsert_credential(&cfg, added);
        assert_eq!(out.credentials.len(), 2);
    }

    #[test]
    fn apply_patch_overwrites_user_and_key() {
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: CredentialBody::new("u").with_key("/k"),
        };
        let opts = EditOptions {
            user: Some("new".into()),
            identity: Some(PathBuf::from("/k2")),
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert_eq!(out.body.user, "new");
        assert_eq!(out.body.key.as_deref(), Some(std::path::Path::new("/k2")));
    }

    #[test]
    fn apply_patch_clear_identity_drops_key() {
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: CredentialBody::new("u").with_key("/k"),
        };
        let opts = EditOptions {
            clear_identity: true,
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert!(out.body.key.is_none());
    }

    #[test]
    fn apply_patch_identity_on_password_credential_drops_password() {
        // C1 regression: `cred edit <pw-cred> --identity /k` must convert the
        // body to a Key-kind body with password == None. Re-attaching the
        // original password via `with_password` after setting the key would
        // silently clear the key.
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: CredentialBody::new("u").with_password("topsecret"),
        };
        let opts = EditOptions {
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert_eq!(out.body.secret_kind(), SecretKind::Key);
        assert_eq!(out.body.key.as_deref(), Some(std::path::Path::new("/k")));
        assert!(
            out.body.password.is_none(),
            "password must be dropped when switching to a key"
        );
    }

    #[test]
    fn apply_patch_preserves_password_when_no_key_in_play() {
        // Password-only credential edited for user/rename keeps its password.
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: CredentialBody::new("u").with_password("topsecret"),
        };
        let opts = EditOptions {
            user: Some("ops".into()),
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert_eq!(out.body.user, "ops");
        assert_eq!(out.body.password_plain(), Some("topsecret"));
        assert!(out.body.key.is_none());
    }

    #[test]
    fn apply_patch_rename_updates_alias() {
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: body("u"),
        };
        let opts = EditOptions {
            rename: Some("d".into()),
            ..Default::default()
        };
        assert_eq!(apply_credential_patch(&orig, &opts).unwrap().alias, "d");
    }

    #[test]
    fn apply_patch_rename_rejects_forbidden_char() {
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: body("u"),
        };
        let opts = EditOptions {
            rename: Some("a:b".into()),
            ..Default::default()
        };
        assert!(matches!(
            apply_credential_patch(&orig, &opts),
            Err(SshrackError::InvalidAliasChar { .. })
        ));
    }

    #[test]
    fn apply_patch_preserves_original_id() {
        // The id is on the owner; a patch must carry it through unchanged so
        // the keyring entry (keyed by id) and every host Auth::Ref survive.
        let id = new_id();
        let orig = Credential {
            id,
            alias: "c".into(),
            body: body("u"),
        };
        let opts = EditOptions {
            rename: Some("d".into()),
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert_eq!(out.id, id, "credential id must survive a patch");
    }

    #[test]
    fn apply_patch_identity_drops_keyring_marker() {
        // Switching a keyring-marker credential to an identity must clear the
        // marker: the body now carries a key, so `keyring = true` would
        // misreport the auth kind (and resolve to a stale Keyring source).
        let orig = Credential {
            id: new_id(),
            alias: "c".into(),
            body: CredentialBody {
                user: "u".into(),
                password: None,
                key: None,
                keyring: true,
            },
        };
        let opts = EditOptions {
            identity: Some(PathBuf::from("/k")),
            ..Default::default()
        };
        let out = apply_credential_patch(&orig, &opts).unwrap();
        assert_eq!(out.body.secret_kind(), SecretKind::Key);
        assert!(
            !out.body.keyring,
            "keyring marker must be dropped when switching to an identity"
        );
    }

    #[test]
    fn delete_credential_with_secret_forgets_keyring_entry() {
        // A keyring-password credential's entry must be deleted on rm so it does
        // not leak. Seeded into a FakeBackend (no daemon dependency); asserted
        // by observing the entry vanish.
        let backend = FakeBackend::new();
        let id = new_id();
        backend
            .set(OwnerKind::Credential, &id, "topsecret")
            .unwrap();
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id,
                alias: "kr-cred-rm".into(),
                body: CredentialBody {
                    user: "root".into(),
                    password: None,
                    key: None,
                    keyring: true,
                },
            }],
            ..Default::default()
        };
        let next = delete_credential_with_secret(&cfg, "kr-cred-rm", &backend).unwrap();
        assert!(next.credentials.is_empty());
        assert!(
            backend
                .get(&keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .is_none(),
            "keyring entry must be deleted on rm"
        );
    }

    #[test]
    fn delete_credential_with_secret_leaves_unmarked_entry_alone() {
        // A plaintext/password credential has no keyring entry; rm must not
        // touch the backend (forget is delete-if-marked).
        let backend = FakeBackend::new();
        let id = new_id();
        backend
            .set(OwnerKind::Credential, &id, "unrelated")
            .unwrap();
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id,
                alias: "plain-cred".into(),
                body: CredentialBody::new("u").with_password("p"),
            }],
            ..Default::default()
        };
        let next = delete_credential_with_secret(&cfg, "plain-cred", &backend).unwrap();
        assert!(next.credentials.is_empty());
        // The unrelated entry is untouched (body was not keyring-marked).
        assert!(
            backend
                .get(&keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .is_some(),
            "unmarked credential's entry must survive rm"
        );
    }

    #[test]
    fn delete_credential_with_secret_errors_when_absent() {
        let cfg = SshrackConfig::default();
        let backend = FakeBackend::new();
        assert!(matches!(
            delete_credential_with_secret(&cfg, "ghost", &backend),
            Err(SshrackError::CredentialNotFound { .. })
        ));
    }

    #[test]
    fn copy_keyring_entry_copies_when_source_marked() {
        let backend = FakeBackend::new();
        let src = Credential {
            id: new_id(),
            alias: "s".into(),
            body: CredentialBody {
                user: "u".into(),
                password: None,
                key: None,
                keyring: true,
            },
        };
        let dst = Credential {
            id: new_id(),
            alias: "d".into(),
            body: CredentialBody {
                user: "u".into(),
                password: None,
                key: None,
                keyring: true,
            },
        };
        backend
            .set(OwnerKind::Credential, &src.id, "hunter2")
            .unwrap();
        copy_keyring_entry(&src, &dst, &backend).unwrap();
        assert_eq!(
            backend
                .get(&keyring_key(OwnerKind::Credential, &dst.id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
        // Source entry survives (copy, not move).
        assert_eq!(
            backend
                .get(&keyring_key(OwnerKind::Credential, &src.id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
    }

    #[test]
    fn copy_keyring_entry_noop_when_source_unmarked() {
        // A non-keyring credential has nothing to copy; the helper returns Ok
        // without touching the backend.
        let backend = FakeBackend::new();
        let src = Credential {
            id: new_id(),
            alias: "s".into(),
            body: CredentialBody::new("u").with_key("/k"),
        };
        let dst = Credential {
            id: new_id(),
            alias: "d".into(),
            body: CredentialBody::new("u"),
        };
        copy_keyring_entry(&src, &dst, &backend).unwrap();
        // Nothing was written for dst.
        assert!(
            backend
                .get(&keyring_key(OwnerKind::Credential, &dst.id))
                .unwrap()
                .is_none()
        );
    }
}
