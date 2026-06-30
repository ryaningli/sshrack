//! Pure transforms over [`CredentialBody`]/[`SshrackConfig`] that apply or
//! remove vault encryption, plus the unified mode-switch ([`migrate`]). No I/O
//! except inside [`crypto::encrypt`] (a fresh nonce) and the injected
//! [`SecretBackend`](crate::secret::SecretBackend) (the OS keyring or a test
//! double); the master key is always an input, never derived here.
//!
//! These are the unit-testable core of `store use`/rekey and of the
//! representation-driven re-host that flips a stored password between
//! plaintext / encrypted / keyring-marker depending on the active
//! `[store] mode`. The per-write `seal_password`/`seal_body` orchestration
//! (which also resolves the first-use mode and unlocks the vault) is deferred
//! to a later task — it depends on unlock/enable/rekey orchestration that has
//! not been ported yet.

use zeroize::Zeroizing;

use crate::config::schema::{CredentialBody, Secret, SecretStore, SshrackConfig};
use crate::error::SshrackError;
use crate::id::{OwnerKind, keyring_key};
use crate::secret::SecretBackend;
use crate::secret::vault::VaultKey;
use crate::secret::vault::crypto;

/// Decide how a freshly collected plaintext password is stored under the active
/// mode, given an optional derived master key:
/// - vault mode + key    → [`Secret::Encrypted`]
/// - vault mode, no key  → [`SshrackError::VaultLocked`] (never silently store
///   plaintext in vault mode)
/// - plaintext mode (or undecided) → [`Secret::Plain`]
///
/// Keyring mode is NOT handled here — it is the caller's responsibility: it
/// stores the plaintext via [`SecretBackend::set`] and flips the body's
/// `keyring = true` marker (no inline `Secret` is produced). This pure helper
/// only finalizes an inline secret representation.
pub fn finalize_password(
    plain: &str,
    cfg: &SshrackConfig,
    key: Option<&VaultKey>,
) -> Result<Secret, SshrackError> {
    match (&cfg.store, key) {
        (Some(SecretStore::Vault { .. }), Some(k)) => {
            Ok(Secret::Encrypted(crypto::encrypt(plain.as_bytes(), k)?))
        }
        (Some(SecretStore::Vault { .. }), None) => Err(SshrackError::VaultLocked),
        // Plaintext or undecided (`None`): store as bare plaintext. First-use
        // resolution is the orchestration layer's job; this helper only reflects
        // the current cfg.
        _ => Ok(Secret::Plain(plain.to_string())),
    }
}

/// Count stored password secrets across credentials and inline host auth.
/// Returns `(encrypted_count, plaintext_count, keyring_count)`. A body counts
/// once, by its own representation (`Encrypted` / `Plain` / `keyring == true`);
/// passwordless and key-only bodies are skipped.
pub fn count_secrets(cfg: &SshrackConfig) -> (usize, usize, usize) {
    let bodies = cfg
        .credentials
        .iter()
        .map(|c| &c.body)
        .chain(cfg.hosts.iter().filter_map(|h| h.auth.inline_body()));
    let (mut enc, mut plain, mut keyring) = (0usize, 0usize, 0usize);
    for b in bodies {
        if b.keyring {
            keyring += 1;
        } else {
            match &b.password {
                Some(Secret::Encrypted(_)) => enc += 1,
                Some(Secret::Plain(_)) => plain += 1,
                None => {}
            }
        }
    }
    (enc, plain, keyring)
}

/// A copy of `body` with an encrypted password (if any) decrypted under `key`,
/// tagged with `name_label` on failure. Plaintext/key/default bodies pass
/// through. The body's `user`/`key`/`keyring` are preserved verbatim.
///
/// `name_label` is the owner's display label (host or credential name) used
/// only in the [`SshrackError::DecryptionFailed`] message — never the secret.
pub(crate) fn decrypt_body(
    body: &CredentialBody,
    key: &VaultKey,
    name_label: &str,
) -> Result<CredentialBody, SshrackError> {
    let password = match &body.password {
        Some(Secret::Encrypted(enc)) => {
            // crypto::decrypt fails with a fieldless DecryptError; attach the
            // name here, intentionally discarding crypto detail (no oracle).
            let plain = crypto::decrypt(enc, key).map_err(|_| SshrackError::DecryptionFailed {
                name: name_label.to_string(),
            })?;
            // `plain.to_string()` moves the decrypted text into a plain
            // `Secret::Plain(String)` that is not zeroized (the String-typed
            // Secret does not allow it); only `plain` itself is wiped. This
            // path serves enable/disable/rekey, not the connect path.
            Some(Secret::Plain(plain.to_string()))
        }
        other => other.clone(),
    };
    Ok(CredentialBody {
        user: body.user.clone(),
        password,
        key: body.key.clone(),
        keyring: body.keyring,
    })
}

/// Decrypt every encrypted password under `key`. Returns the count converted.
/// Used by rekey (decrypt-all before re-encrypting under a new key).
pub fn decrypt_all(cfg: &mut SshrackConfig, key: &VaultKey) -> Result<usize, SshrackError> {
    let mut n = 0usize;
    for c in &mut cfg.credentials {
        if matches!(c.body.password, Some(Secret::Encrypted(_))) {
            let name = c.name.clone();
            c.body = decrypt_body(&c.body, key, &name)?;
            n += 1;
        }
    }
    for h in &mut cfg.hosts {
        if let Some(body) = h.auth.inline_body_mut()
            && matches!(body.password, Some(Secret::Encrypted(_)))
        {
            let name = h.name.clone();
            let next = decrypt_body(body, key, &name)?;
            *body = next;
            n += 1;
        }
    }
    Ok(n)
}

/// The routing identity for a stored secret during a transform: which owner
/// kind (host vs credential), the stable id that keys the keyring entry, and
/// the name label attached to a decryption failure (never the secret). Packs
/// the three values the old crate carried in its `SecretOwner` enum into one
/// borrowable handle so the transform helpers stay under clippy's arg limit.
struct SecretOwner<'a> {
    kind: OwnerKind,
    id: ulid::Ulid,
    name_label: &'a str,
}

impl<'a> SecretOwner<'a> {
    /// A credential owner: the keyring account is `cred:<id>`.
    fn credential(id: ulid::Ulid, name_label: &'a str) -> Self {
        Self {
            kind: OwnerKind::Credential,
            id,
            name_label,
        }
    }

    /// A host owner: the keyring account is `host:<id>`.
    fn host(id: ulid::Ulid, name_label: &'a str) -> Self {
        Self {
            kind: OwnerKind::Host,
            id,
            name_label,
        }
    }
}

/// Re-host every stored password into `target`. For each body that carries a
/// password, extract its plaintext — inline plaintext, an inline `Encrypted`
/// secret decrypted with `source_vault_key`, or a `keyring = true` marker body
/// fetched from the OS keyring — then re-seal it for the target mode and clean
/// up the source representation (deleting the keyring entry when leaving
/// keyring mode). Bodies without a password are skipped. Returns the count
/// migrated.
///
/// Representation-driven (reads each body's `password`/`keyring`), not
/// mode-driven, so it is self-healing across mixed states and handles every
/// source→target edge uniformly. `source_vault_key` decrypts Encrypted source
/// bodies; `target_vault_key` encrypts when the target is vault. An Encrypted
/// body with no source key errors as [`SshrackError::VaultLocked`] rather than
/// being silently dropped.
///
/// The id used to key each keyring entry is the owner's stable [`ulid::Ulid`]
/// (`cred.id` for credentials, `host.id` for inline host auth) — never the
/// name — so renames never move a keyring entry.
pub fn migrate(
    cfg: &mut SshrackConfig,
    target: &SecretStore,
    source_vault_key: Option<&VaultKey>,
    target_vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<usize, SshrackError> {
    let mut n = 0usize;
    for c in &mut cfg.credentials {
        // Snapshot the owner identity so it does not borrow `*c` while we also
        // pass `&mut c.body`. The id is the keyring account key; the name is
        // only the decryption-failure label.
        let owner = SecretOwner::credential(c.id, &c.name);
        if migrate_body(
            &mut c.body,
            &owner,
            target,
            source_vault_key,
            target_vault_key,
            backend,
        )? {
            n += 1;
        }
    }
    for h in &mut cfg.hosts {
        if let Some(body) = h.auth.inline_body_mut() {
            let owner = SecretOwner::host(h.id, &h.name);
            if migrate_body(
                body,
                &owner,
                target,
                source_vault_key,
                target_vault_key,
                backend,
            )? {
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Migrate one body's password into `target`. Returns `true` if the body had a
/// password (counted), `false` if it was skipped. See [`migrate`].
///
/// `owner` selects the keyring account (kind + id) and carries the name label
/// attached to a decryption failure (never the secret).
fn migrate_body(
    body: &mut CredentialBody,
    owner: &SecretOwner<'_>,
    target: &SecretStore,
    source_vault_key: Option<&VaultKey>,
    target_vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<bool, SshrackError> {
    let Some(plain) = extract_plain(body, owner, source_vault_key, backend)? else {
        return Ok(false);
    };
    // Leaving keyring mode? Remember to delete the old entry AFTER the re-seal
    // succeeds, so a re-seal failure (e.g. crypto::encrypt RNG failure) cannot
    // lose the password — the old keyring entry stays intact until the body is
    // safely re-sealed. (keyring→keyring is rejected at the command layer and
    // the guard below skips it regardless.)
    let leaving_keyring = body.keyring && !matches!(target, SecretStore::Keyring);
    match target {
        SecretStore::Plaintext => {
            // `plain.to_string()` copies into a non-zeroizing `Secret::Plain`;
            // only `plain` itself is wiped on drop. Matches the existing
            // decrypt_body/resolve limitation (zeroizing Secret is a follow-up).
            body.password = Some(Secret::Plain(plain.to_string()));
            body.keyring = false;
        }
        SecretStore::Vault { .. } => {
            let key = target_vault_key.ok_or(SshrackError::VaultLocked)?;
            body.password = Some(Secret::Encrypted(crypto::encrypt(plain.as_bytes(), key)?));
            body.keyring = false;
        }
        SecretStore::Keyring => {
            backend.set(owner.kind, &owner.id, plain.as_str())?;
            body.password = None;
            body.keyring = true;
        }
    }
    if leaving_keyring {
        // Best-effort delete of the now-superseded entry; a missing entry is
        // already gone.
        let _ = backend.delete(owner.kind, &owner.id);
    }
    Ok(true)
}

/// Extract a body's password as wiped plaintext, from whichever representation
/// holds it. `None` when the body has no password.
///
/// `owner` derives the keyring account key for a marker body and carries the
/// name label attached to a decryption failure (never the secret).
fn extract_plain(
    body: &CredentialBody,
    owner: &SecretOwner<'_>,
    source_vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<Option<Zeroizing<String>>, SshrackError> {
    if body.keyring {
        let key = keyring_key(owner.kind, &owner.id);
        let plain = backend
            .get(&key)?
            .ok_or(SshrackError::KeyringNoEntry { key })?;
        return Ok(Some(plain));
    }
    match &body.password {
        None => Ok(None),
        Some(Secret::Plain(p)) => Ok(Some(Zeroizing::new(p.clone()))),
        Some(Secret::Encrypted(enc)) => {
            // crypto::decrypt fails with a fieldless DecryptError; attach the
            // name and discard crypto detail (no decryption oracle).
            let key = source_vault_key.ok_or(SshrackError::VaultLocked)?;
            Ok(Some(crypto::decrypt(enc, key).map_err(|_| {
                SshrackError::DecryptionFailed {
                    name: owner.name_label.to_string(),
                }
            })?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, Credential, EncryptedSecret, Host, VaultMeta};
    use crate::id::keyring_key as derive_keyring_key;

    const KEY: [u8; 32] = [9u8; 32];

    fn plain_body(user: &str, pw: &str) -> CredentialBody {
        CredentialBody::new(user).with_password(pw)
    }

    fn vault_target() -> SecretStore {
        SecretStore::Vault {
            meta: VaultMeta::default_argon2id("AA=="),
        }
    }

    /// Build a vault cfg (vault mode) with the fast Argon2id meta used by tests.
    fn vault_cfg() -> SshrackConfig {
        SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: crate::secret::vault::fast_meta("AA=="),
            }),
            ..SshrackConfig::default()
        }
    }

    #[test]
    fn decrypt_body_round_trips_and_tags_name() {
        let enc = crypto::encrypt(b"hunter2", &KEY).unwrap();
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Encrypted(enc)),
            key: None,
            keyring: false,
        };
        let back = decrypt_body(&body, &KEY.into(), "team").unwrap();
        assert_eq!(back.password_plain(), Some("hunter2"));
        // Wrong key surfaces a name-tagged DecryptionFailed.
        let err = decrypt_body(&body, &[0u8; 32].into(), "team").unwrap_err();
        assert!(matches!(err, SshrackError::DecryptionFailed { name } if name == "team"));
    }

    #[test]
    fn finalize_password_encrypted_mode_with_key() {
        let cfg = vault_cfg();
        let s = finalize_password("hunter2", &cfg, Some(&KEY.into())).unwrap();
        assert!(matches!(s, Secret::Encrypted(_)));
    }

    #[test]
    fn finalize_password_encrypted_mode_without_key_is_locked() {
        let cfg = vault_cfg();
        assert!(matches!(
            finalize_password("hunter2", &cfg, None),
            Err(SshrackError::VaultLocked)
        ));
    }

    #[test]
    fn finalize_password_plaintext_mode() {
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        let s = finalize_password("hunter2", &cfg, None).unwrap();
        assert_eq!(s.as_plain(), Some("hunter2"));
    }

    #[test]
    fn finalize_password_undecided_mode_is_plaintext() {
        // A fresh config with no chosen mode finalizes as plaintext; the caller
        // (seal orchestration) is responsible for resolving the first-use mode.
        let cfg = SshrackConfig::default();
        let s = finalize_password("hunter2", &cfg, None).unwrap();
        assert_eq!(s.as_plain(), Some("hunter2"));
    }

    #[test]
    fn count_secrets_tallies_all_three_kinds() {
        let cfg = SshrackConfig {
            credentials: vec![
                Credential {
                    id: ulid::Ulid::new(),
                    name: "a".into(),
                    body: plain_body("u", "p1"),
                },
                Credential {
                    id: ulid::Ulid::new(),
                    name: "b".into(),
                    body: CredentialBody {
                        user: "u".into(),
                        password: Some(Secret::Encrypted(EncryptedSecret {
                            nonce: "n".into(),
                            cipher: "c".into(),
                        })),
                        key: None,
                        keyring: false,
                    },
                },
                Credential {
                    id: ulid::Ulid::new(),
                    name: "c".into(),
                    body: CredentialBody {
                        user: "u".into(),
                        password: None,
                        key: None,
                        keyring: true,
                    },
                },
            ],
            hosts: vec![],
            ..SshrackConfig::default()
        };
        assert_eq!(count_secrets(&cfg), (1, 1, 1)); // 1 encrypted, 1 plaintext, 1 keyring
    }

    #[test]
    fn decrypt_all_round_trips_after_migrate_to_vault_with_counts() {
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "a".into(),
                body: plain_body("u", "p1"),
            }],
            hosts: vec![Host {
                id: ulid::Ulid::new(),
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(plain_body("u", "p2")),
            }],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        assert_eq!(n, 2);
        assert_eq!(count_secrets(&cfg), (2, 0, 0));
        let n = decrypt_all(&mut cfg, &KEY.into()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(count_secrets(&cfg), (0, 2, 0));
    }

    // ---- migrate: the unified mode-switch ----

    fn keyring_cfg_one_plain(cred_name: &str) -> SshrackConfig {
        SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: cred_name.into(),
                body: plain_body("deploy", "hunter2"),
            }],
            hosts: vec![],
            ..SshrackConfig::default()
        }
    }

    #[test]
    fn migrate_plaintext_to_vault_encrypts_every_body() {
        let mut cfg = keyring_cfg_one_plain("m-p2v");
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Target is a vault store; provide the target key. No source key needed
        // (no Encrypted bodies).
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        assert_eq!(n, 1);
        assert!(matches!(
            cfg.credentials[0].body.password,
            Some(Secret::Encrypted(_))
        ));
        // Round-trips back to plaintext under the same key.
        let _ = migrate(
            &mut cfg,
            &SecretStore::Plaintext,
            Some(&KEY.into()),
            None,
            &backend,
        )
        .unwrap();
        assert_eq!(cfg.credentials[0].body.password_plain(), Some("hunter2"));
    }

    #[test]
    fn migrate_skips_key_default_and_passwordless_bodies() {
        let mut cfg = SshrackConfig {
            credentials: vec![
                Credential {
                    id: ulid::Ulid::new(),
                    name: "key-only".into(),
                    body: CredentialBody::new("u").with_key("/k"),
                },
                Credential {
                    id: ulid::Ulid::new(),
                    name: "default".into(),
                    body: CredentialBody::new("u"),
                },
            ],
            hosts: vec![],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        assert_eq!(
            migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap(),
            0
        );
    }

    #[test]
    fn migrate_encrypted_source_without_key_is_locked() {
        let mut cfg = keyring_cfg_one_plain("m-locked");
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Make the body encrypted first.
        let _ = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        // Re-migrating to plaintext WITHOUT a source key must fail as VaultLocked
        // rather than silently skip the stranded encrypted secret.
        let err = migrate(&mut cfg, &SecretStore::Plaintext, None, None, &backend).unwrap_err();
        assert!(matches!(err, SshrackError::VaultLocked));
    }

    #[test]
    fn migrate_keyring_to_vault_moves_secret_off_keyring() {
        // THE BUG FIX: keyring -> vault previously stranded the password in the
        // keyring because encrypt_all skipped keyring-marker bodies. The
        // FakeBackend stands in for the OS keyring, so this runs everywhere —
        // no Secret Service daemon required.
        let cred_name = "sshrack-test-mig-kr2v";
        let mut cfg = keyring_cfg_one_plain(cred_name);
        let id = cfg.credentials[0].id;
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Start in keyring mode: move the plaintext into the backend. `migrate`
        // to the Keyring target is the only producer of keyring-marker bodies.
        let _ = migrate(&mut cfg, &SecretStore::Keyring, None, None, &backend).unwrap();
        assert!(cfg.credentials[0].body.keyring);
        assert!(cfg.credentials[0].body.password.is_none());
        // The plaintext now lives in the fake backend.
        assert_eq!(
            backend
                .get(&derive_keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );

        // Now migrate keyring -> vault. The secret must be fetched from the
        // backend, the entry deleted, and the body re-sealed as Encrypted.
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        assert_eq!(n, 1);
        assert!(
            !cfg.credentials[0].body.keyring,
            "keyring marker must clear"
        );
        assert!(matches!(
            cfg.credentials[0].body.password,
            Some(Secret::Encrypted(_))
        ));
        // The backend entry must be gone (no orphan).
        let gone = backend
            .get(&derive_keyring_key(OwnerKind::Credential, &id))
            .unwrap();
        assert!(
            gone.is_none(),
            "keyring entry must be deleted on leaving keyring"
        );
        // And the ciphertext round-trips to the original plaintext.
        let _ = migrate(
            &mut cfg,
            &SecretStore::Plaintext,
            Some(&KEY.into()),
            None,
            &backend,
        )
        .unwrap();
        assert_eq!(cfg.credentials[0].body.password_plain(), Some("hunter2"));
    }

    #[test]
    fn migrate_keyring_uses_owner_id_not_name_for_account_key() {
        // Renaming a credential must not change its keyring account key — the
        // key is owner_kind + id, not the name. Verify by migrating a renamed
        // credential's keyring body: the entry keyed by the original id is the
        // one fetched.
        let mut cfg = keyring_cfg_one_plain("kr-rename");
        let id = cfg.credentials[0].id;
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Seed keyring mode.
        let _ = migrate(&mut cfg, &SecretStore::Keyring, None, None, &backend).unwrap();
        // Rename the credential in place (id unchanged) — the keyring entry is
        // still keyed by the id, so this rename is invisible to the backend.
        cfg.credentials[0].name = "kr-renamed".into();
        // Leaving keyring must read the entry by id (not name) and delete it.
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        assert_eq!(n, 1);
        assert!(
            backend
                .get(&derive_keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .is_none(),
            "entry keyed by id must be gone after leaving keyring"
        );
    }
}
