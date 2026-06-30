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
}
