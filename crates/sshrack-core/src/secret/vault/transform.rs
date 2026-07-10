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

use crate::config::schema::{
    CredentialBody, EncryptedSecret, KeySource, Secret, SecretStore, SshrackConfig,
};
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

/// Finalize one inline **key/cert** secret the same way [`finalize_password`]
/// finalizes a password: encrypt under vault when a key is present, else keep
/// plaintext. Separate name from `finalize_password` so call sites read as
/// "key material", not "password". Keyring mode is handled by `seal_inline_key`
/// before this helper runs, so only vault/plaintext reach here.
pub fn finalize_secret(
    plain: &str,
    cfg: &SshrackConfig,
    key: Option<&VaultKey>,
) -> Result<Secret, SshrackError> {
    // Identical logic to finalize_password; the duplication is intentional and
    // small, and avoids passing a "kind" flag that would couple these two
    // unrelated concerns.
    match (&cfg.store, key) {
        (Some(SecretStore::Vault { .. }), Some(k)) => {
            Ok(Secret::Encrypted(crypto::encrypt(plain.as_bytes(), k)?))
        }
        (Some(SecretStore::Vault { .. }), None) => Err(SshrackError::VaultLocked),
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
            // Inline key material counts each secret it carries (private key +
            // optional certificate), so store-mode switches / rekeys see them.
            // A keyring-marker inline body (ik.keyring) counts toward the
            // keyring total, mirroring the body-level marker.
            if let Some(KeySource::Inline(ik)) = &b.key {
                if ik.keyring {
                    keyring += 1;
                } else {
                    if let Some(s) = &ik.private_key {
                        count_one_secret(s, &mut enc, &mut plain);
                    }
                    if let Some(s) = &ik.certificate {
                        count_one_secret(s, &mut enc, &mut plain);
                    }
                }
            }
        }
    }
    (enc, plain, keyring)
}

/// Tally one [`Secret`] into the encrypted/plaintext counters. A local helper
/// so the inline-key arms in [`count_secrets`] read the same shape as the
/// password match without duplicating the `Encrypted`/`Plain` dispatch.
fn count_one_secret(s: &Secret, enc: &mut usize, plain: &mut usize) {
    match s {
        Secret::Encrypted(_) => *enc += 1,
        Secret::Plain(_) => *plain += 1,
    }
}

/// A copy of `body` with its encrypted secret material — password and/or an
/// inline key's `private_key`/`certificate` — decrypted under `key`, tagged
/// with `name_label` on failure. Plaintext/key/default bodies pass through. The
/// body's `user`/`keyring` and any path key are preserved verbatim.
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
            Some(Secret::Plain(decrypt_to_plain(enc, key, name_label)?))
        }
        other => other.clone(),
    };
    // Decrypt inline-key material when present, so rekey (decrypt-all before
    // re-encrypting under a new key) does not strand private-key/certificate
    // ciphertext on the old vault key. Path keys carry no secret material and
    // pass through untouched.
    let mut body_key = body.key.clone();
    if let Some(KeySource::Inline(ik)) = &mut body_key {
        if let Some(Secret::Encrypted(enc)) = ik.private_key.take() {
            ik.private_key = Some(Secret::Plain(decrypt_to_plain(&enc, key, name_label)?));
        }
        if let Some(Secret::Encrypted(enc)) = ik.certificate.take() {
            ik.certificate = Some(Secret::Plain(decrypt_to_plain(&enc, key, name_label)?));
        }
    }
    Ok(CredentialBody {
        user: body.user.clone(),
        password,
        key: body_key,
        keyring: body.keyring,
    })
}

/// Decrypt one [`EncryptedSecret`] to an owned plaintext `String`, attaching
/// `name_label` on the (fieldless) [`crypto::DecryptError`] so the caller sees
/// [`SshrackError::DecryptionFailed`] without leaking crypto detail (no oracle).
/// The returned `String` is not `Zeroizing` (the `Secret::Plain` variant is a
/// plain `String`); the wipe lives in [`crypto::decrypt`]'s `Zeroizing<String>`
/// intermediate. Shared by the password and inline-key arms of [`decrypt_body`].
fn decrypt_to_plain(
    enc: &EncryptedSecret,
    key: &VaultKey,
    name_label: &str,
) -> Result<String, SshrackError> {
    crypto::decrypt(enc, key)
        .map(|plain| plain.to_string())
        .map_err(|_| SshrackError::DecryptionFailed {
            name: name_label.to_string(),
        })
}

/// True if `body` carries any [`Secret::Encrypted`] material — a password or an
/// inline key's `private_key`/`certificate` — that [`decrypt_body`] would
/// convert. Used by [`decrypt_all`] to decide which bodies to visit, so an
/// inline-key-only encrypted body is not skipped (which would strand its
/// ciphertext on the old vault key during rekey).
fn body_has_encrypted(body: &CredentialBody) -> bool {
    if matches!(body.password, Some(Secret::Encrypted(_))) {
        return true;
    }
    if let Some(KeySource::Inline(ik)) = &body.key {
        ik.private_key.as_ref().is_some_and(Secret::is_encrypted)
            || ik.certificate.as_ref().is_some_and(Secret::is_encrypted)
    } else {
        false
    }
}

/// Decrypt every encrypted secret — passwords and inline-key material — under
/// `key`. Returns the count of bodies converted. Used by rekey (decrypt-all
/// before re-encrypting under a new key). A body counts once if it carries any
/// [`Secret::Encrypted`] material; see [`body_has_encrypted`].
pub fn decrypt_all(cfg: &mut SshrackConfig, key: &VaultKey) -> Result<usize, SshrackError> {
    let mut n = 0usize;
    for c in &mut cfg.credentials {
        if body_has_encrypted(&c.body) {
            let name = c.name.clone();
            c.body = decrypt_body(&c.body, key, &name)?;
            n += 1;
        }
    }
    for h in &mut cfg.hosts {
        if let Some(body) = h.auth.inline_body_mut()
            && body_has_encrypted(body)
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

/// Re-host every stored secret into `target`. For each body that carries a
/// secret, extract its plaintext — inline plaintext, an inline `Encrypted`
/// secret decrypted with `source_vault_key`, or a `keyring = true` marker body
/// fetched from the OS keyring — then re-seal it for the target mode and clean
/// up the source representation (deleting the keyring entry when leaving
/// keyring mode). Both `body.password` and the inline key's `private_key` /
/// `certificate` are re-sealed; path keys and default bodies are skipped.
/// Returns the count of bodies migrated (a body counts once if any of its
/// secrets was re-sealed).
///
/// Representation-driven (reads each body's `password`/`key`/`keyring`), not
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

/// Migrate one body's secrets (password and/or inline key) into `target`.
/// Returns `true` if the body carried any re-sealable secret (counted once),
/// `false` if it was skipped (path key, default body). See [`migrate`].
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
    // Re-seal the password (if any) and the inline key (if any) independently.
    // A body counts once if either path actually re-sealed a secret: per
    // CredentialBody::validate password and key are mutually exclusive, so at
    // most one arm returns true in a valid config.
    let pw = migrate_body_password(
        body,
        owner,
        target,
        source_vault_key,
        target_vault_key,
        backend,
    )?;
    let key = migrate_body_inline_key(
        body,
        owner,
        target,
        source_vault_key,
        target_vault_key,
        backend,
    )?;
    Ok(pw || key)
}

/// Re-host the body's `password` (or keyring-marker password) into `target`.
/// Returns `true` if the body had a password (counted), `false` if not. See
/// [`migrate_body`].
fn migrate_body_password(
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

/// Re-host an inline key's `private_key` and `certificate` into `target`,
/// mirroring [`migrate_body_password`]'s per-target re-sealing. Returns `true`
/// if the body carried an inline key (counted), `false` for path keys / no key.
///
/// Path keys ([`KeySource::Path`]) are filesystem locations, not secret
/// material — they pass through untouched. Inline-key text is re-hosted across
/// every mode switch: extracted from the in-body `Secret` (or the OS keyring
/// slots when this is a keyring-marker body), then re-sealed per `target`
/// (plaintext → `Plain`; vault → `Encrypted` under `target_vault_key`; keyring
/// → written to the inline slots with a marker body). Leaving keyring mode
/// deletes the source slots via [`delete_inline_slots`] so none are orphaned.
fn migrate_body_inline_key(
    body: &mut CredentialBody,
    owner: &SecretOwner<'_>,
    target: &SecretStore,
    source_vault_key: Option<&VaultKey>,
    target_vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<bool, SshrackError> {
    let Some(KeySource::Inline(ik)) = &mut body.key else {
        // Path key or no key: not secret material to migrate.
        return Ok(false);
    };
    // Extract the current plaintext (from the in-body Secret, or from the
    // keyring slots when this is a keyring-marker body), then re-seal per target.
    let priv_plain = extract_inline_text(
        ik.private_key.take(),
        owner,
        source_vault_key,
        InlineSlot::Private,
        backend,
    )?;
    let cert_plain = extract_inline_text(
        ik.certificate.take(),
        owner,
        source_vault_key,
        InlineSlot::Certificate,
        backend,
    )?;
    match target {
        SecretStore::Keyring => {
            if let Some(p) = &priv_plain {
                backend.set_at(
                    &crate::id::keyring_key_inline_priv(owner.kind, &owner.id),
                    p,
                )?;
            } else {
                let _ =
                    backend.delete_at(&crate::id::keyring_key_inline_priv(owner.kind, &owner.id));
            }
            if let Some(c) = &cert_plain {
                backend.set_at(
                    &crate::id::keyring_key_inline_cert(owner.kind, &owner.id),
                    c,
                )?;
            } else {
                let _ =
                    backend.delete_at(&crate::id::keyring_key_inline_cert(owner.kind, &owner.id));
            }
            ik.keyring = true;
        }
        SecretStore::Plaintext => {
            ik.private_key = priv_plain.map(|p| Secret::Plain(p.to_string()));
            ik.certificate = cert_plain.map(|c| Secret::Plain(c.to_string()));
            ik.keyring = false;
            delete_inline_slots(backend, owner);
        }
        SecretStore::Vault { .. } => {
            ik.private_key = priv_plain
                .as_ref()
                .map(|p| {
                    let k = target_vault_key.ok_or(SshrackError::VaultLocked)?;
                    Ok::<_, SshrackError>(Secret::Encrypted(crypto::encrypt(p.as_bytes(), k)?))
                })
                .transpose()?;
            ik.certificate = cert_plain
                .as_ref()
                .map(|c| {
                    let k = target_vault_key.ok_or(SshrackError::VaultLocked)?;
                    Ok::<_, SshrackError>(Secret::Encrypted(crypto::encrypt(c.as_bytes(), k)?))
                })
                .transpose()?;
            ik.keyring = false;
            delete_inline_slots(backend, owner);
        }
    }
    Ok(true)
}

/// Which inline-key slot a text belongs to.
enum InlineSlot {
    Private,
    Certificate,
}

/// Extract an inline-key text as wiped plaintext, whether it currently lives
/// in-body (`Plain`/`Encrypted`) or in the OS keyring (keyring-marker body).
/// `None` when there is no private/cert text at all. `owner.name_label` tags a
/// decryption failure (never the secret).
fn extract_inline_text(
    secret: Option<Secret>,
    owner: &SecretOwner<'_>,
    source_vault_key: Option<&VaultKey>,
    slot: InlineSlot,
    backend: &dyn SecretBackend,
) -> Result<Option<Zeroizing<String>>, SshrackError> {
    match secret {
        None => {
            // A keyring-marker body keeps its text in the slot.
            let key = match slot {
                InlineSlot::Private => crate::id::keyring_key_inline_priv(owner.kind, &owner.id),
                InlineSlot::Certificate => {
                    crate::id::keyring_key_inline_cert(owner.kind, &owner.id)
                }
            };
            Ok(backend.get(&key)?)
        }
        Some(Secret::Plain(p)) => Ok(Some(Zeroizing::new(p))),
        Some(Secret::Encrypted(enc)) => {
            let key = source_vault_key.ok_or(SshrackError::VaultLocked)?;
            Ok(Some(crypto::decrypt(&enc, key).map_err(|_| {
                SshrackError::DecryptionFailed {
                    name: owner.name_label.to_string(),
                }
            })?))
        }
    }
}

/// Delete both inline-keyring slots for an owner (best-effort, no orphans on
/// leaving keyring mode). A missing slot is success.
fn delete_inline_slots(backend: &dyn SecretBackend, owner: &SecretOwner<'_>) {
    let _ = backend.delete_at(&crate::id::keyring_key_inline_priv(owner.kind, &owner.id));
    let _ = backend.delete_at(&crate::id::keyring_key_inline_cert(owner.kind, &owner.id));
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
    use crate::config::schema::{Auth, Credential, EncryptedSecret, Host, InlineKey, VaultMeta};
    use crate::id::keyring_key as derive_keyring_key;
    use crate::secret::test_doubles::FakeBackend;

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
    fn count_secrets_counts_inline_key_secrets() {
        // An inline key contributes both its private_key and its certificate to
        // the secret tally, so store-mode switches / rekeys see them.
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "ops".into(),
                body: CredentialBody::new("u")
                    .with_inline_key(Secret::Plain("k".into()), Some(Secret::Plain("c".into()))),
            }],
            ..SshrackConfig::default()
        };
        let (enc, plain, _keyring) = count_secrets(&cfg);
        // private_key + certificate = 2 plaintext secrets.
        assert_eq!((enc, plain), (0, 2));
    }

    #[test]
    fn count_secrets_counts_keyring_marker_inline_body() {
        // A keyring-marker inline body (ik.keyring = true) must count toward the
        // keyring total so `store status` and `store use` show accurate counts.
        use crate::config::schema::{InlineKey, KeySource};
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: ulid::Ulid::new(),
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: Some(KeySource::Inline(InlineKey {
                        private_key: None,
                        certificate: None,
                        keyring: true,
                    })),
                    keyring: false,
                }),
            }],
            ..Default::default()
        };
        let (_enc, _plain, keyring) = count_secrets(&cfg);
        assert!(keyring >= 1, "keyring-marker inline body must be counted");
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

    // ---- migrate: inline identity keys are re-sealed across mode switches ----
    //
    // A pre-existing gap: migrate_body re-sealed only body.password, so an
    // inline key saved earlier under plaintext mode was NOT encrypted when the
    // user later ran `store use vault` / `store rekey`. These tests lock the
    // fix: both private_key and certificate re-seal across plaintext <-> vault.

    /// Build a credential body that carries an inline key with plaintext
    /// private_key + certificate. Mirrors `plain_body` for the inline-key path.
    fn inline_plain_body(user: &str, priv_text: &str, cert_text: Option<&str>) -> CredentialBody {
        let cert = cert_text.map(|c| Secret::Plain(c.to_string()));
        CredentialBody::new(user).with_inline_key(Secret::Plain(priv_text.to_string()), cert)
    }

    #[test]
    fn migrate_plaintext_to_vault_encrypts_inline_key() {
        // plaintext cfg + an inline-key body (private_key + certificate both
        // Plain); migrate to vault with a target key; assert BOTH become
        // Encrypted and the plaintext strings are absent from the body's TOML.
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "ik-p2v".into(),
                body: inline_plain_body("u", "PRIVATE-KEY-TEXT", Some("CERTIFICATE-TEXT")),
            }],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        assert_eq!(n, 1, "inline-key body must count as migrated once");
        let ik = match &cfg.credentials[0].body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert!(
            ik.private_key.as_ref().is_some_and(Secret::is_encrypted),
            "private_key must be Encrypted after migrate to vault"
        );
        assert!(
            ik.certificate.as_ref().is_some_and(Secret::is_encrypted),
            "certificate must be Encrypted after migrate to vault"
        );
        // Belt-and-suspenders: the plaintext must not appear in the serialized
        // body (the on-disk shape under vault mode).
        let body_toml = toml::to_string(&cfg.credentials[0].body).unwrap();
        assert!(
            !body_toml.contains("PRIVATE-KEY-TEXT"),
            "private key plaintext leaked into TOML: {body_toml}"
        );
        assert!(
            !body_toml.contains("CERTIFICATE-TEXT"),
            "certificate plaintext leaked into TOML: {body_toml}"
        );
    }

    #[test]
    fn migrate_vault_to_plaintext_decrypts_inline_key() {
        // vault cfg with an Encrypted inline key + source key; migrate to
        // plaintext; assert BOTH become Plain and round-trip to the originals.
        // Build the encrypted form by first migrating from plaintext, so the
        // source representation matches what `store use vault` would produce.
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "ik-v2p".into(),
                body: inline_plain_body("u", "ORIG-PRIVATE", Some("ORIG-CERT")),
            }],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Seal into vault first.
        migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        // Sanity: it is now encrypted (the bug being fixed would have left it Plain).
        if let Some(KeySource::Inline(ik)) = &cfg.credentials[0].body.key {
            assert!(
                ik.private_key.as_ref().is_some_and(Secret::is_encrypted),
                "precondition: private_key must be encrypted after seal"
            );
        } else {
            panic!("expected Inline after seal");
        }
        // Now migrate back to plaintext with the source key.
        let n = migrate(
            &mut cfg,
            &SecretStore::Plaintext,
            Some(&KEY.into()),
            None,
            &backend,
        )
        .unwrap();
        assert_eq!(n, 1, "inline-key body must count as migrated once");
        let ik = match &cfg.credentials[0].body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("ORIG-PRIVATE"),
            "private_key must round-trip to the original plaintext"
        );
        assert_eq!(
            ik.certificate.as_ref().and_then(Secret::as_plain),
            Some("ORIG-CERT"),
            "certificate must round-trip to the original plaintext"
        );
    }

    #[test]
    fn migrate_vault_to_vault_rekeys_inline_key_under_new_key() {
        // `store rekey` migrates vault -> vault under a new key. Inline key
        // material must be decrypted with the source key and re-encrypted under
        // the target key, mirroring the password path. Verifies that BOTH
        // secrets follow the source-key -> target-key rewrap.
        let source_key: VaultKey = Zeroizing::new(KEY);
        let target_key: VaultKey = Zeroizing::new([7u8; 32]);
        // Seed: plaintext inline key.
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "ik-rekey".into(),
                body: inline_plain_body("u", "REKEY-PRIVATE", Some("REKEY-CERT")),
            }],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Seal under the source key.
        migrate(&mut cfg, &vault_target(), None, Some(&source_key), &backend).unwrap();
        // Rekey: vault -> vault with source -> target.
        let n = migrate(
            &mut cfg,
            &vault_target(),
            Some(&source_key),
            Some(&target_key),
            &backend,
        )
        .unwrap();
        assert_eq!(n, 1, "inline-key body must count as rekeyed");
        let ik = match &cfg.credentials[0].body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        // Decrypt with the TARGET key proves the rewrap landed under the new key.
        if let Some(Secret::Encrypted(enc)) = &ik.private_key {
            let plain = crypto::decrypt(enc, &target_key).unwrap();
            assert_eq!(plain.as_str(), "REKEY-PRIVATE");
        } else {
            panic!("private_key must remain Encrypted after rekey");
        }
        if let Some(Secret::Encrypted(enc)) = &ik.certificate {
            let plain = crypto::decrypt(enc, &target_key).unwrap();
            assert_eq!(plain.as_str(), "REKEY-CERT");
        } else {
            panic!("certificate must remain Encrypted after rekey");
        }
    }

    #[test]
    fn decrypt_all_then_enable_rekeys_inline_key_under_new_key() {
        // `store rekey` flow: decrypt_all under the old key, then enable under
        // a fresh passphrase. Inline-key material must be decrypted by
        // decrypt_all (the gap: previously only passwords were decrypted) and
        // re-encrypted by enable. Mirrors
        // migrate_vault_to_vault_rekeys_inline_key_under_new_key but exercises
        // the decrypt_all -> enable path actually used by `store rekey`.
        use crate::secret::vault::enable;

        let old_key: VaultKey = Zeroizing::new(KEY);
        // Seed: plaintext inline key in a vault-mode cfg.
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "ik-rekey-da".into(),
                body: inline_plain_body("u", "REKEY-PRIVATE", Some("REKEY-CERT")),
            }],
            ..vault_cfg()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        // Seal the inline key under the old key (simulates a prior `store use
        // vault`). The seed store is already vault, but migrate re-seals each
        // body's secret under the provided target key regardless of cfg.store.
        migrate(&mut cfg, &vault_target(), None, Some(&old_key), &backend).unwrap();
        // Sanity: the inline key is now Encrypted under the old key.
        if let Some(KeySource::Inline(ik)) = &cfg.credentials[0].body.key {
            assert!(
                ik.private_key.as_ref().is_some_and(Secret::is_encrypted),
                "precondition: private_key must be encrypted after seal"
            );
        } else {
            panic!("expected Inline after seal");
        }

        // rekey step 1: decrypt_all under the old key. THIS IS THE GAP —
        // previously decrypt_all left inline-key Encrypted ciphertext stranded
        // on the old vault key, so the subsequent enable would re-encrypt still-
        // encrypted bytes under the new key (double-wrap) or skip them.
        let n = decrypt_all(&mut cfg, &old_key).unwrap();
        assert_eq!(n, 1, "decrypt_all must count the inline-key body");
        let ik = match &cfg.credentials[0].body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("REKEY-PRIVATE"),
            "decrypt_all must decrypt the inline private_key to plaintext"
        );
        assert_eq!(
            ik.certificate.as_ref().and_then(Secret::as_plain),
            Some("REKEY-CERT"),
            "decrypt_all must decrypt the inline certificate to plaintext"
        );

        // rekey step 2: drop store + enable under a fresh passphrase (new key).
        cfg.store = None;
        let new_key = enable(&mut cfg, "new-passphrase", None, &backend).unwrap();
        assert!(cfg.is_vault(), "enable must flip cfg.store back to vault");
        // The inline key must be re-encrypted under the NEW key and round-trip
        // to the original plaintext. Proves the rekey rewrap landed correctly.
        let ik = match &cfg.credentials[0].body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline after enable, got {other:?}"),
        };
        if let Some(Secret::Encrypted(enc)) = &ik.private_key {
            let plain = crypto::decrypt(enc, &new_key).unwrap();
            assert_eq!(plain.as_str(), "REKEY-PRIVATE");
        } else {
            panic!("private_key must be Encrypted under the new key after enable");
        }
        if let Some(Secret::Encrypted(enc)) = &ik.certificate {
            let plain = crypto::decrypt(enc, &new_key).unwrap();
            assert_eq!(plain.as_str(), "REKEY-CERT");
        } else {
            panic!("certificate must be Encrypted under the new key after enable");
        }
        // The old key can no longer decrypt the rewrapped private_key.
        if let Some(Secret::Encrypted(enc)) = &ik.private_key {
            assert!(
                crypto::decrypt(enc, &old_key).is_err(),
                "old key must not decrypt the rewrapped private_key"
            );
        }
    }

    #[test]
    fn migrate_vault_to_keyring_moves_inline_key_to_keyring_slots() {
        // THE RESIDUAL ROOT CAUSE: vault -> keyring migration must decrypt the
        // inline key and store its plaintext in the keyring slots, leaving a
        // marker body (ik.keyring = true, no in-body text). Previously this
        // short-circuited and left the Encrypted ciphertext stranded under
        // keyring mode — which then misreported as `vault is locked` at connect.
        use crate::config::schema::{InlineKey, KeySource, Secret, SecretStore};
        use crate::secret::test_doubles::FakeBackend;
        use crate::secret::vault::crypto;

        let key = [9u8; 32];
        let enc_priv = crypto::encrypt(b"PRIV", &key).unwrap();
        let id = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: VaultMeta::default_argon2id("c2FsdA=="),
            }),
            hosts: vec![Host {
                id,
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: Some(KeySource::Inline(InlineKey {
                        private_key: Some(Secret::Encrypted(enc_priv)),
                        certificate: None,
                        keyring: false,
                    })),
                    keyring: false,
                }),
            }],
            ..Default::default()
        };
        let backend = FakeBackend::new();
        let vkey = VaultKey::from(key);
        migrate(&mut cfg, &SecretStore::Keyring, Some(&vkey), None, &backend).unwrap();
        let body = cfg.hosts[0].auth.inline_body().unwrap();
        let ik = match &body.key {
            Some(KeySource::Inline(ik)) => ik,
            _ => panic!("expected Inline"),
        };
        assert!(ik.keyring, "marker must be set");
        assert!(ik.private_key.is_none(), "in-body text must be cleared");
        let stored = backend
            .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
            .unwrap()
            .expect("priv slot written");
        assert_eq!(stored.as_str(), "PRIV");
    }

    #[test]
    fn migrate_keyring_to_vault_encrypts_inline_key_from_keyring_slots() {
        // Reverse direction: a keyring-marker inline key is read from the slots and
        // re-encrypted under the target vault key; the marker is cleared and the
        // source slots are deleted (no orphans).
        use crate::config::schema::{InlineKey, KeySource, Secret, SecretStore};
        use crate::secret::test_doubles::FakeBackend;

        let id = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            hosts: vec![Host {
                id,
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: Some(KeySource::Inline(InlineKey {
                        private_key: None,
                        certificate: None,
                        keyring: true,
                    })),
                    keyring: false,
                }),
            }],
            ..Default::default()
        };
        let backend = FakeBackend::new();
        backend
            .set_at(
                &crate::id::keyring_key_inline_priv(OwnerKind::Host, &id),
                "PRIV",
            )
            .unwrap();
        let target = SecretStore::Vault {
            meta: VaultMeta::default_argon2id("c2FsdA=="),
        };
        let target_key = VaultKey::from([9u8; 32]);
        migrate(&mut cfg, &target, None, Some(&target_key), &backend).unwrap();
        let ik = match &cfg.hosts[0].auth.inline_body().unwrap().key {
            Some(KeySource::Inline(ik)) => ik,
            _ => panic!("expected Inline"),
        };
        assert!(!ik.keyring, "marker cleared after leaving keyring");
        assert!(
            matches!(ik.private_key, Some(Secret::Encrypted(_))),
            "re-encrypted under target key"
        );
        assert!(
            backend
                .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .is_none(),
            "priv slot must be deleted after leaving keyring"
        );
    }

    #[test]
    fn migrate_skips_path_key_body_without_touching_the_path() {
        // A path-key body (key = "/k") is not secret material — migrate must
        // skip it (count 0) and leave the path verbatim. Guards against an
        // over-eager fix that re-seals path keys.
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "path-only".into(),
                body: CredentialBody::new("u").with_key("/k"),
            }],
            ..SshrackConfig::default()
        };
        let backend = crate::secret::test_doubles::FakeBackend::new();
        assert_eq!(
            migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap(),
            0,
            "path-key body must not count as migrated"
        );
        assert_eq!(
            cfg.credentials[0]
                .body
                .key
                .as_ref()
                .and_then(KeySource::as_path),
            Some(std::path::Path::new("/k")),
            "path key must be unchanged"
        );
    }

    // ---- audit-driven safety / correctness backfill (Task 1.1) ----
    //
    // Migration atomicity, idempotency, inline-key two-slot decrypt, the
    // finalize_secret/finalize_password contract parity, the migrate mode matrix
    // (vault<->keyring<->plaintext, rekey), and a no-leak assertion that no
    // vault/keyring error string ever carries the secret.

    #[test]
    fn decrypt_all_partial_failure_reports_only_failing_name_and_leaves_prior_body_half_migrated() {
        // Two encrypted credentials: cred[0] under the correct key, cred[1] under
        // a wrong key. `decrypt_all` uses `?` short-circuit: cred[1] fails and the
        // loop stops, leaving cred[0] already mutated to Plain (non-atomic). This
        // test PINS the current behavior so a later atomicity change must update
        // it; it also asserts the failing name is cred[1]'s and the plaintext
        // never enters the error.
        let good_key: [u8; 32] = KEY;
        let wrong_key: [u8; 32] = [7u8; 32];
        let enc0 = crypto::encrypt(b"pw-zero", &good_key).unwrap();
        // cred[1]'s secret is the leak-canary plaintext "hunter2".
        let enc1 = crypto::encrypt(b"hunter2", &wrong_key).unwrap();
        let cred0_name = "zero";
        let cred1_name = "one";
        let mut cfg = SshrackConfig {
            credentials: vec![
                Credential {
                    id: ulid::Ulid::new(),
                    name: cred0_name.into(),
                    body: CredentialBody {
                        user: "u".into(),
                        password: Some(Secret::Encrypted(enc0)),
                        key: None,
                        keyring: false,
                    },
                },
                Credential {
                    id: ulid::Ulid::new(),
                    name: cred1_name.into(),
                    body: CredentialBody {
                        user: "u".into(),
                        password: Some(Secret::Encrypted(enc1)),
                        key: None,
                        keyring: false,
                    },
                },
            ],
            ..SshrackConfig::default()
        };
        let err = decrypt_all(&mut cfg, &good_key.into()).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("hunter2"),
            "error must not contain plaintext: {msg}"
        );
        match err {
            SshrackError::DecryptionFailed { name } => {
                assert_eq!(name, cred1_name, "error must name the failing credential");
            }
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
        // Non-atomic `?` short-circuit: cred[0] was already decrypted to Plain
        // before cred[1] aborted. If a maintainer later makes decrypt_all atomic
        // (e.g. decrypt into a scratch cfg then swap), this assertion must flip.
        assert_eq!(
            cfg.credentials[0].body.password_plain(),
            Some("pw-zero"),
            "cred[0] must already be Plain — pins the non-atomic short-circuit"
        );
    }

    #[test]
    fn decrypt_all_already_plaintext_is_noop_idempotent() {
        // No Encrypted material anywhere → decrypt_all counts 0 and leaves every
        // body unchanged (no spurious mutation of Plain bodies).
        let mut cfg = SshrackConfig {
            credentials: vec![
                Credential {
                    id: ulid::Ulid::new(),
                    name: "a".into(),
                    body: plain_body("u", "p1"),
                },
                Credential {
                    id: ulid::Ulid::new(),
                    name: "b".into(),
                    body: plain_body("u", "p2"),
                },
            ],
            hosts: vec![Host {
                id: ulid::Ulid::new(),
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(plain_body("u", "p3")),
            }],
            ..SshrackConfig::default()
        };
        let n = decrypt_all(&mut cfg, &KEY.into()).unwrap();
        assert_eq!(n, 0, "no encrypted bodies should be counted");
        assert_eq!(cfg.credentials[0].body.password_plain(), Some("p1"));
        assert_eq!(cfg.credentials[1].body.password_plain(), Some("p2"));
        assert_eq!(
            cfg.hosts[0].auth.inline_body().unwrap().password_plain(),
            Some("p3")
        );
    }

    #[test]
    fn migrate_vault_to_vault_same_key_is_idempotent() {
        // Re-sealing vault->vault under the SAME key is a no-op on the plaintext:
        // the ciphertext is freshly re-encrypted (new nonce) but still decrypts
        // to the original. Idempotent in the value sense, not the byte sense.
        let mut cfg = keyring_cfg_one_plain("idem-v2v");
        let backend = FakeBackend::new();
        migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        // Now Encrypted under KEY.
        assert!(matches!(
            cfg.credentials[0].body.password,
            Some(Secret::Encrypted(_))
        ));
        let n = migrate(
            &mut cfg,
            &vault_target(),
            Some(&KEY.into()),
            Some(&KEY.into()),
            &backend,
        )
        .unwrap();
        assert_eq!(n, 1, "vault->vault same key still counts as a re-seal pass");
        // Round-trips under the same key after the re-seal.
        decrypt_all(&mut cfg, &KEY.into()).unwrap();
        assert_eq!(
            cfg.credentials[0].body.password_plain(),
            Some("hunter2"),
            "value must survive vault->vault same-key re-seal"
        );
    }

    #[test]
    fn migrate_mixed_inline_and_ref_hosts_migrates_creds_once_skips_ref_hosts() {
        // A Ref-auth host borrows its credential's secret — migrate must NOT
        // double-count it (the cred is migrated once, the Ref host skipped). An
        // inline host in the same config is migrated independently.
        let cid = ulid::Ulid::new();
        let ref_host_id = ulid::Ulid::new();
        let inline_host_id = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                name: "C".into(),
                body: plain_body("deploy", "hunter2"),
            }],
            hosts: vec![
                Host {
                    id: ref_host_id,
                    name: "ref-host".into(),
                    host: "x".into(),
                    port: 22,
                    auth: Auth::reference(cid),
                },
                Host {
                    id: inline_host_id,
                    name: "inline-host".into(),
                    host: "y".into(),
                    port: 22,
                    auth: Auth::inline(plain_body("u", "inline-pw")),
                },
            ],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let n = migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap();
        // cred C + inline host = 2; the Ref host contributes nothing.
        assert_eq!(n, 2, "count = cred C + inline host (Ref host skipped)");
        // C migrated exactly once → Encrypted.
        assert!(matches!(
            cfg.credentials[0].body.password,
            Some(Secret::Encrypted(_))
        ));
        // Ref host's auth is untouched (still a Ref at the same id).
        assert_eq!(cfg.hosts[0].auth.credential_id(), Some(cid));
        // Inline host migrated → Encrypted.
        assert!(matches!(
            cfg.hosts[1].auth.inline_body().unwrap().password,
            Some(Secret::Encrypted(_))
        ));
    }

    #[test]
    fn decrypt_body_inline_key_two_slots_round_trips_and_tags_name_on_wrong_key() {
        // Both inline-key slots Encrypted: decrypt_body must decrypt BOTH to Plain
        // and round-trip the originals. A wrong key surfaces a name-tagged
        // DecryptionFailed carrying only the label, never the key material.
        let priv_enc = crypto::encrypt(b"PRIV-TEXT", &KEY).unwrap();
        let cert_enc = crypto::encrypt(b"CERT-TEXT", &KEY).unwrap();
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: Some(Secret::Encrypted(priv_enc)),
                certificate: Some(Secret::Encrypted(cert_enc)),
                keyring: false,
            })),
            keyring: false,
        };
        let back = decrypt_body(&body, &KEY.into(), "ik-owner").unwrap();
        let ik = match &back.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("PRIV-TEXT"),
            "private_key must round-trip"
        );
        assert_eq!(
            ik.certificate.as_ref().and_then(Secret::as_plain),
            Some("CERT-TEXT"),
            "certificate must round-trip"
        );

        // Wrong key: name-tagged failure, no key material in the message.
        let err = decrypt_body(&body, &[0u8; 32].into(), "ik-owner").unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("PRIV-TEXT") && !msg.contains("CERT-TEXT"),
            "error leaked key material: {msg}"
        );
        match err {
            SshrackError::DecryptionFailed { name } => assert_eq!(name, "ik-owner"),
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    #[test]
    fn extract_plain_keyring_marker_body_without_backend_entry_is_keyring_no_entry() {
        // A keyring-marker password body with no backend entry must surface
        // KeyringNoEntry carrying the owner's account key (a non-sensitive label),
        // never the plaintext. Driven through the public `migrate` so the whole
        // extract_plain path is exercised.
        let cid = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                name: "kr-missing".into(),
                body: CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: None,
                    keyring: true,
                },
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new(); // empty — no entry for `cid`
        let err =
            migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("hunter2"),
            "error must not contain plaintext: {msg}"
        );
        match err {
            SshrackError::KeyringNoEntry { key } => {
                assert_eq!(
                    key,
                    derive_keyring_key(OwnerKind::Credential, &cid),
                    "key must be the owner's account key"
                );
            }
            other => panic!("expected KeyringNoEntry, got {other:?}"),
        }
    }

    #[test]
    fn finalize_secret_matches_finalize_password_contract() {
        // The two helpers must agree across the four (store, key) combinations.
        // For vault+key both produce Encrypted ciphertexts that decrypt to the
        // same plaintext (nonces differ, value does not).
        let plain = "hunter2";
        // (1) vault + key → both Encrypted, decrypt to `plain`.
        let cfg_v = vault_cfg();
        let sp = finalize_secret(plain, &cfg_v, Some(&KEY.into())).unwrap();
        let pp = finalize_password(plain, &cfg_v, Some(&KEY.into())).unwrap();
        match (&sp, &pp) {
            (Secret::Encrypted(es), Secret::Encrypted(ep)) => {
                assert_eq!(crypto::decrypt(es, &KEY).unwrap().as_str(), plain);
                assert_eq!(crypto::decrypt(ep, &KEY).unwrap().as_str(), plain);
            }
            _ => panic!("both must be Encrypted, got sp={sp:?} pp={pp:?}"),
        }
        // (2) vault, no key → both VaultLocked.
        assert!(matches!(
            finalize_secret(plain, &cfg_v, None),
            Err(SshrackError::VaultLocked)
        ));
        assert!(matches!(
            finalize_password(plain, &cfg_v, None),
            Err(SshrackError::VaultLocked)
        ));
        // (3) plaintext → both Plain with the same value.
        let cfg_p = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        assert_eq!(
            finalize_secret(plain, &cfg_p, None).unwrap().as_plain(),
            Some(plain)
        );
        assert_eq!(
            finalize_password(plain, &cfg_p, None).unwrap().as_plain(),
            Some(plain)
        );
        // (4) undecided store → both Plain (caller resolves first-use mode).
        let cfg_u = SshrackConfig::default();
        assert_eq!(
            finalize_secret(plain, &cfg_u, None).unwrap().as_plain(),
            Some(plain)
        );
        assert_eq!(
            finalize_password(plain, &cfg_u, None).unwrap().as_plain(),
            Some(plain)
        );
    }

    #[test]
    fn migrate_password_vault_to_keyring() {
        // An Encrypted (vault-representation) password body migrated to Keyring:
        // decrypted with the source key, written to the backend under the owner's
        // account key, the in-body password cleared, and the marker set.
        let cid = ulid::Ulid::new();
        let enc = crypto::encrypt(b"hunter2", &KEY).unwrap();
        let mut cfg = SshrackConfig {
            store: Some(vault_target()),
            credentials: vec![Credential {
                id: cid,
                name: "vk".into(),
                body: CredentialBody {
                    user: "u".into(),
                    password: Some(Secret::Encrypted(enc)),
                    key: None,
                    keyring: false,
                },
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let n = migrate(
            &mut cfg,
            &SecretStore::Keyring,
            Some(&KEY.into()),
            None,
            &backend,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(
            cfg.credentials[0].body.keyring,
            "marker must be set after entering keyring mode"
        );
        assert!(
            cfg.credentials[0].body.password.is_none(),
            "in-body password must be cleared"
        );
        // The plaintext now lives in the backend under the owner's account key.
        assert_eq!(
            backend
                .get(&derive_keyring_key(OwnerKind::Credential, &cid))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
    }

    #[test]
    fn migrate_password_keyring_to_plaintext() {
        // A keyring-marker password body + seeded backend entry, migrated to
        // Plaintext: the plaintext is read from the backend, written into the
        // body as Plain, the marker clears, and the backend entry is deleted
        // (no orphan on leaving keyring mode).
        let cid = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                name: "kp".into(),
                body: CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: None,
                    keyring: true,
                },
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        backend.set(OwnerKind::Credential, &cid, "hunter2").unwrap();
        let n = migrate(&mut cfg, &SecretStore::Plaintext, None, None, &backend).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            cfg.credentials[0].body.password_plain(),
            Some("hunter2"),
            "plaintext must be restored into the body"
        );
        assert!(
            !cfg.credentials[0].body.keyring,
            "marker must clear on leaving keyring"
        );
        assert!(
            backend
                .get(&derive_keyring_key(OwnerKind::Credential, &cid))
                .unwrap()
                .is_none(),
            "backend entry must be deleted on leaving keyring (no orphan)"
        );
    }

    #[test]
    fn migrate_body_inline_key_keyring_to_plaintext_and_back() {
        // Round-trip an inline key between keyring and plaintext in both
        // directions: keyring → plaintext (slot read into body, slot deleted,
        // marker cleared) then plaintext → keyring (in-body text cleared,
        // marker set, slot re-populated).
        let id = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            hosts: vec![Host {
                id,
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: Some(KeySource::Inline(InlineKey {
                        private_key: None,
                        certificate: None,
                        keyring: true,
                    })),
                    keyring: false,
                }),
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        backend
            .set_at(
                &crate::id::keyring_key_inline_priv(OwnerKind::Host, &id),
                "PRIV",
            )
            .unwrap();

        // keyring → plaintext: slot read into the body, marker cleared, slot deleted.
        migrate(&mut cfg, &SecretStore::Plaintext, None, None, &backend).unwrap();
        let ik = match &cfg.hosts[0].auth.inline_body().unwrap().key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert!(!ik.keyring, "marker must clear after leaving keyring");
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("PRIV"),
            "private_key text must be restored into the body"
        );
        assert!(
            backend
                .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .is_none(),
            "priv slot must be deleted after leaving keyring"
        );

        // plaintext → keyring: in-body text cleared, marker set, slot re-populated.
        migrate(&mut cfg, &SecretStore::Keyring, None, None, &backend).unwrap();
        let ik = match &cfg.hosts[0].auth.inline_body().unwrap().key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline, got {other:?}"),
        };
        assert!(ik.keyring, "marker must be set after entering keyring");
        assert!(
            ik.private_key.is_none(),
            "in-body text must be cleared when entering keyring"
        );
        assert_eq!(
            backend
                .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("PRIV"),
            "priv slot must be re-populated when entering keyring"
        );
    }

    #[test]
    fn migrate_password_vault_to_vault_rekey() {
        // Rekey: an Encrypted password under source key A is decrypted and
        // re-encrypted under target key B. The result must decrypt under B and
        // NOT under A.
        let source_key: [u8; 32] = KEY;
        let target_key: [u8; 32] = [7u8; 32];
        let enc = crypto::encrypt(b"hunter2", &source_key).unwrap();
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "rekey-pw".into(),
                body: CredentialBody {
                    user: "u".into(),
                    password: Some(Secret::Encrypted(enc)),
                    key: None,
                    keyring: false,
                },
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let n = migrate(
            &mut cfg,
            &vault_target(),
            Some(&source_key.into()),
            Some(&target_key.into()),
            &backend,
        )
        .unwrap();
        assert_eq!(n, 1);
        let enc = match &cfg.credentials[0].body.password {
            Some(Secret::Encrypted(e)) => e,
            other => panic!("expected Encrypted after rekey, got {other:?}"),
        };
        assert_eq!(
            crypto::decrypt(enc, &target_key).unwrap().as_str(),
            "hunter2",
            "must decrypt under the TARGET key after rekey"
        );
        assert!(
            crypto::decrypt(enc, &source_key).is_err(),
            "must NOT decrypt under the SOURCE key after rekey"
        );
    }

    #[test]
    fn extract_inline_text_encrypted_without_source_key_is_vault_locked() {
        // An Encrypted inline-key slot migrated with no source_vault_key must
        // error VaultLocked rather than silently dropping the stranded ciphertext.
        // Driven through `migrate` so the full extract_inline_text path runs.
        let priv_enc = crypto::encrypt(b"PRIV", &KEY).unwrap();
        let mut cfg = SshrackConfig {
            store: Some(vault_target()),
            hosts: vec![Host {
                id: ulid::Ulid::new(),
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: Some(KeySource::Inline(InlineKey {
                        private_key: Some(Secret::Encrypted(priv_enc)),
                        certificate: None,
                        keyring: false,
                    })),
                    keyring: false,
                }),
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let err = migrate(&mut cfg, &SecretStore::Plaintext, None, None, &backend).unwrap_err();
        assert!(
            matches!(err, SshrackError::VaultLocked),
            "expected VaultLocked, got {err:?}"
        );
    }

    #[test]
    fn decryption_failure_and_keyring_no_entry_errors_never_contain_secret() {
        // The two transform error variants that could surface during a migrate
        // must never embed the plaintext. Feed "hunter2" as the secret and assert
        // the rendered error string is free of it for both variants.
        // (1) DecryptionFailed: encrypt hunter2, decrypt with the wrong key.
        let enc = crypto::encrypt(b"hunter2", &KEY).unwrap();
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Encrypted(enc)),
            key: None,
            keyring: false,
        };
        let err = decrypt_body(&body, &[0u8; 32].into(), "owner-label").unwrap_err();
        assert!(
            !err.to_string().contains("hunter2"),
            "DecryptionFailed leaked plaintext: {err}"
        );
        // (2) KeyringNoEntry: a keyring-marker body whose plaintext WAS hunter2
        // before it was moved; the missing-entry error must name only the key.
        let cid = ulid::Ulid::new();
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cid,
                name: "kr-leak".into(),
                body: CredentialBody {
                    user: "u".into(),
                    password: None,
                    key: None,
                    keyring: true,
                },
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let err =
            migrate(&mut cfg, &vault_target(), None, Some(&KEY.into()), &backend).unwrap_err();
        assert!(
            !err.to_string().contains("hunter2"),
            "KeyringNoEntry leaked plaintext: {err}"
        );
    }
}
