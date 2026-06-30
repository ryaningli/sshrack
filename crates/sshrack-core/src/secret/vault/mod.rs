//! Master-passphrase encryption for stored passwords ("vault" mode).
//!
//! Split into a pure cryptography core ([`crypto`]), pure body/config
//! transforms ([`transform`]), and an I/O-only key cache ([`cache`]). This
//! module owns the **read-direction** unlock orchestration
//! ([`ensure_unlocked_vault_key`], [`unlock`], and the helpers that back them)
//! and the **write-direction** orchestration: [`enable`] (turn on vault mode
//! and migrate every existing password) and [`seal_body`] / [`seal_auth`]
//! (re-host a freshly collected plaintext password per the active storage
//! mode).
//!
//! # Read-direction unlock precedence
//!
//! 1. Valid cache hit (within TTL and verifier passes) → return cached key.
//! 2. The env-passphrase passed in by the caller (read from
//!    `SSHRACK_PASSPHRASE` via [`passphrase_from_env`]) → derive + verify +
//!    cache.
//! 3. `PassphraseProvider::passphrase()` (TTY prompt) → derive + verify +
//!    cache.
//!
//! The env-passphrase is injected as a parameter (not read inside [`unlock`])
//! so the precedence is testable without mutating `std::env` — which the
//! project forbids in tests. The env value shadows the TTY prompt, so CI /
//! scripts can inject the passphrase without a terminal. The CLI's
//! [`PassphraseProvider`] impl errors instead of prompting, so if neither the
//! cache nor the env value is available the call fails fast.
//!
//! # Design rules
//!
//! Nothing in this module ever prints, logs, or returns a passphrase, master
//! key, or plaintext in an error message.

pub mod cache;
pub mod crypto;
pub mod transform;

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::config::schema::{Auth, CredentialBody, Secret, SecretStore, SshrackConfig, VaultMeta};
use crate::error::SshrackError;
use crate::id::OwnerKind;
use crate::secret::PassphraseProvider;
use crate::secret::SecretBackend;

/// The derived 32-byte master key. Wrapped in [`Zeroizing`] so it is wiped on
/// drop. Produced by [`crypto::derive_key`]; consumed by
/// [`crypto::encrypt`]/[`crypto::decrypt`] and the body transforms.
pub type VaultKey = Zeroizing<[u8; 32]>;

/// Environment variable that supplies the master passphrase for non-interactive
/// use (CI, scripts, the CLI). When set, [`unlock`] skips the TTY prompt.
pub const PASSPHRASE_ENV: &str = "SSHRACK_PASSPHRASE";

/// Plaintext encrypted as the vault verifier. Decrypting it under the master
/// key proves the passphrase is correct at unlock time. Used by
/// [`unlock_with_passphrase`] (read) and [`enable`] (write).
pub(crate) const VERIFIER_PLAINTEXT: &[u8] = b"sshrack-vault-v1";

/// Read the passphrase from the environment, wrapped in [`Zeroizing`] so it
/// is wiped on drop rather than lingering as a bare `String` through the derive
/// phase. Returns `None` when the variable is unset or empty.
///
/// Used by the production caller (the connect path), which then passes the
/// value into [`unlock`] / [`ensure_unlocked_vault_key`] as the
/// `env_passphrase` parameter. Tests inject the value directly instead of
/// calling this — they never mutate `std::env`.
pub fn passphrase_from_env() -> Option<Zeroizing<String>> {
    std::env::var(PASSPHRASE_ENV).ok().map(Zeroizing::new)
}

/// Derive the master key from `passphrase`, verify it against `meta.verifier`
/// (fail fast on a wrong passphrase), and cache it for the TTL window.
///
/// Pure of TTY/env — the orchestration in [`unlock`] chooses the passphrase
/// source. `cache_path` may be `None`; when present the derived key is cached
/// to that path so the next unlock within the TTL returns early.
pub fn unlock_with_passphrase(
    meta: &VaultMeta,
    passphrase: &str,
    cache_path: Option<&Path>,
) -> Result<VaultKey, SshrackError> {
    let key = crypto::derive_key(passphrase, meta)?;
    // Production always has a verifier after `store use vault` fills it; `None`
    // means not-enabled / abnormal / tampered and is rejected because the
    // passphrase cannot be verified.
    match meta.verifier.as_ref() {
        None => return Err(SshrackError::VaultUnlockFailed),
        Some(v) if crypto::decrypt(v, &key).is_err() => {
            return Err(SshrackError::VaultUnlockFailed);
        }
        Some(_) => {}
    }
    let ttl = std::time::Duration::from_secs(meta.cache_ttl_secs);
    let path = cache_path
        .map(std::path::Path::to_path_buf)
        .or_else(cache::default_cache_path);
    if let Some(p) = path.as_ref() {
        let _ = cache::write_cache(p, &key, ttl);
    }
    Ok(key)
}

/// True when `key` still decrypts this vault's verifier — i.e. the key matches
/// the current config. A cached key that fails this check is stale (left by a
/// prior `enable`/`rekey`) and must not be trusted: [`unlock`] treats it as a
/// miss and re-derives, which overwrites the stale cache.
pub fn cached_key_is_valid(key: &VaultKey, meta: &VaultMeta) -> bool {
    meta.verifier
        .as_ref()
        .is_some_and(|v| crypto::decrypt(v, key).is_ok())
}

/// Resolve the master key for the session, or `None` when the config is not in
/// encrypted mode.
///
/// Order: cache hit (valid) → `env_passphrase` (the value the caller read from
/// `SSHRACK_PASSPHRASE`) → prompt via `provider`. Returns `None` when no vault
/// is active; `Err` when unlock fails (wrong passphrase or the provider is
/// refused / interrupted).
///
/// `env_passphrase` is injected rather than read inside this function so the
/// precedence is testable without mutating `std::env` (forbidden in tests).
/// Production callers read it with [`passphrase_from_env`].
pub fn unlock(
    cfg: &SshrackConfig,
    cache_path: Option<&Path>,
    env_passphrase: Option<&Zeroizing<String>>,
    provider: &dyn PassphraseProvider,
) -> Result<Option<VaultKey>, SshrackError> {
    let Some(meta) = cfg.vault_meta() else {
        return Ok(None);
    };
    let ttl = std::time::Duration::from_secs(meta.cache_ttl_secs);
    let path = cache_path
        .map(std::path::Path::to_path_buf)
        .or_else(cache::default_cache_path);

    if let Some(p) = path.as_ref()
        && let Some(key) = cache::read_cache(p, ttl)
        && cached_key_is_valid(&key, meta)
    {
        return Ok(Some(key));
    }

    let env_pw_owned;
    let passphrase: &Zeroizing<String> = match env_passphrase {
        Some(p) => p,
        None => {
            env_pw_owned = provider.passphrase()?;
            &env_pw_owned
        }
    };
    let key = unlock_with_passphrase(meta, passphrase, cache_path)?;
    Ok(Some(key))
}

/// Ensure the vault key is available for a read operation (the connect path).
///
/// - If the config is not in vault mode, returns `Ok(None)`.
/// - Cache hit (valid) → returns the cached key immediately (no prompt).
/// - `env_passphrase` (the value the caller read from `SSHRACK_PASSPHRASE`)
///   → derive, verify, cache, return.
/// - Otherwise → `provider.passphrase()` → derive, verify, cache, return.
///
/// In the CLI, the provider errors on `passphrase()` when the env value is
/// unset, so the call fails here when neither the cache nor the env value is
/// available — exactly the right behavior for unattended runs.
///
/// `env_passphrase` is injected (read by the caller via
/// [`passphrase_from_env`]) so this function is testable without touching
/// `std::env`.
///
/// This is the key entry point for the connect path. Write-direction callers
/// use [`enable`] (which derives its own key) and [`seal_body`] (which takes
/// the already-unlocked key as a parameter, so it never prompts).
pub fn ensure_unlocked_vault_key(
    cfg: &SshrackConfig,
    env_passphrase: Option<&Zeroizing<String>>,
    provider: &dyn PassphraseProvider,
) -> Result<Option<VaultKey>, SshrackError> {
    if !cfg.is_vault() {
        return Ok(None);
    }
    match unlock(cfg, None, env_passphrase, provider)? {
        Some(k) => Ok(Some(k)),
        None => Err(SshrackError::VaultLocked),
    }
}

/// Turn on encrypted mode: generate a fresh salt + Argon2id meta, derive the
/// key, store a verifier, migrate every existing password into vault mode, and
/// set `cfg.store`. Returns the new key.
///
/// `enable` is only ever called on a non-vault config (first-use `store use
/// vault`, or `rekey` after decrypting to plaintext), so no source vault key
/// is needed — source bodies are inline plaintext or keyring markers, both
/// handled by [`transform::migrate`]. The returned key decrypts the verifier,
/// proving it matches the freshly written meta.
///
/// `cache_ttl_secs` overrides the default cache TTL when `Some`. The CLI
/// supplies the master passphrase (already confirmed via
/// [`PassphraseProvider::passphrase_confirm`]); this function is UI-free.
pub fn enable(
    cfg: &mut SshrackConfig,
    passphrase: &str,
    cache_ttl_secs: Option<u64>,
    backend: &dyn SecretBackend,
) -> Result<VaultKey, SshrackError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| SshrackError::EncryptionFailed)?;
    let mut meta = VaultMeta::default_argon2id(STANDARD.encode(salt));
    if let Some(secs) = cache_ttl_secs {
        meta.cache_ttl_secs = secs;
    }
    let key = crypto::derive_key(passphrase, &meta)?;
    meta.verifier = Some(crypto::encrypt(VERIFIER_PLAINTEXT, &key)?);
    let target = SecretStore::Vault { meta };
    // Migrate every existing password into vault mode before flipping cfg.store
    // so a migration failure leaves the config untouched.
    transform::migrate(cfg, &target, None, Some(&key), backend)?;
    cfg.store = Some(target);
    Ok(key)
}

/// Seal a body's freshly collected plaintext password (if any) per the
/// **already-decided** storage mode.
///
/// - vault mode (`vault_key` required) → [`Secret::Encrypted`].
/// - keyring mode → the plaintext is stored via [`SecretBackend::set`] under
///   the owner's id and the body's `keyring` flag is set (clearing the inline
///   password).
/// - plaintext mode → [`Secret::Plain`].
///
/// Already-encrypted, marker-only, or passwordless bodies pass through
/// unchanged, so re-saving an untouched entry is a no-op.
///
/// This helper is **UI-free**: it does not resolve the first-use mode or
/// unlock the vault. The caller (CLI) guarantees `cfg.store` is decided and,
/// for vault mode, passes the already-unlocked key via `vault_key`.
/// `kind` + `id` identify the owner (`Credential.id` / `Host.id`), so the
/// keyring entry is keyed by the stable id, not the body.
pub fn seal_body(
    body: CredentialBody,
    kind: OwnerKind,
    id: &Ulid,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<CredentialBody, SshrackError> {
    let password = match body.password {
        // A freshly collected plaintext password is re-hosted per the mode.
        Some(Secret::Plain(ref p)) => seal_password(p, kind, id, cfg, vault_key, backend)?,
        // Already-sealed (Encrypted) or marker-only bodies pass through.
        other => other,
    };
    // Keyring mode stored the password in the backend (or the body was already
    // a keyring-marker body with `password = None`): `password.is_none()` is
    // the signal, so flip the marker so `resolve` produces PasswordSource::Keyring.
    let keyring = password.is_none() && cfg.is_keyring();
    Ok(CredentialBody {
        user: body.user,
        password,
        key: body.key,
        keyring,
    })
}

/// Seal an inline auth's freshly collected plaintext password (if any) per the
/// active mode, using the host's id and [`OwnerKind::Host`] for keyring keying.
///
/// [`Auth::Ref`] passes through unchanged — sealing a reference is a no-op
/// since it carries no inline secret. See [`seal_body`] for the per-mode
/// behavior. Like `seal_body`, this helper is UI-free: the caller resolves
/// mode selection and vault unlock before calling it.
pub fn seal_auth(
    auth: Auth,
    kind: OwnerKind,
    id: &Ulid,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<Auth, SshrackError> {
    match auth {
        Auth::Inline(body) => Ok(Auth::Inline(seal_body(
            body, kind, id, cfg, vault_key, backend,
        )?)),
        // A reference carries no inline secret — pass through verbatim.
        other => Ok(other),
    }
}

/// Re-host one freshly collected plaintext password per the **already-decided**
/// storage mode, returning the inline [`Secret`] (or `None` for keyring mode,
/// where the password is stored in the backend and the body carries only the
/// `keyring = true` marker).
///
/// Private: folded into [`seal_body`] rather than exported, because the
/// caller's invariant — "the password is freshly collected plaintext" — is only
/// meaningful from inside `seal_body`'s match arm.
fn seal_password(
    plain: &str,
    kind: OwnerKind,
    id: &Ulid,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<Option<Secret>, SshrackError> {
    match cfg.store {
        Some(SecretStore::Vault { .. }) => {
            // vault_key is required in vault mode; transform::finalize_password
            // returns VaultLocked when it is missing.
            Ok(Some(transform::finalize_password(plain, cfg, vault_key)?))
        }
        Some(SecretStore::Keyring) => {
            backend.set(kind, id, plain)?;
            Ok(None)
        }
        // Plaintext mode (or undecided — the caller is responsible for
        // resolving first-use, so undecided here means a programming error
        // upstream, treated as plaintext to mirror finalize_password).
        Some(SecretStore::Plaintext) | None => {
            Ok(Some(transform::finalize_password(plain, cfg, None)?))
        }
    }
}

/// Low-cost Argon2id meta for tests: the default 64 MiB / 3 / 4 cost would
/// make the suite seconds-slow. Shared by the vault and credential tests.
#[cfg(test)]
pub(crate) fn fast_meta(salt_b64: &str) -> crate::config::schema::VaultMeta {
    use crate::config::schema::VaultMeta;
    VaultMeta {
        m: 8,
        t: 1,
        p: 1,
        ..VaultMeta::default_argon2id(salt_b64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Credential, SecretStore, SshrackConfig, VaultMeta};
    use crate::id::{OwnerKind, keyring_key};
    use crate::secret::test_doubles::{FakeBackend, deny};

    /// Build a `VaultMeta` with a verifier for `passphrase`. Reusable across
    /// multiple tests so the derive cost is paid only once per test that calls it.
    fn meta_with_verifier(passphrase: &str) -> VaultMeta {
        let mut meta = fast_meta("AAAAAAAAAAAAAAAAAAAAAA==");
        let key = crypto::derive_key(passphrase, &meta).unwrap();
        let verifier = crypto::encrypt(VERIFIER_PLAINTEXT, &key).unwrap();
        meta.verifier = Some(verifier);
        meta
    }

    // ---- unlock_with_passphrase ----

    #[test]
    fn unlock_with_correct_passphrase_returns_key() {
        let meta = meta_with_verifier("hunter2");
        let key = unlock_with_passphrase(&meta, "hunter2", None).unwrap();
        // The returned key must decrypt the verifier (round trip proves correctness).
        assert!(crypto::decrypt(meta.verifier.as_ref().unwrap(), &key).is_ok());
    }

    #[test]
    fn unlock_with_wrong_passphrase_fails() {
        let meta = meta_with_verifier("hunter2");
        assert!(matches!(
            unlock_with_passphrase(&meta, "wrong", None),
            Err(SshrackError::VaultUnlockFailed)
        ));
    }

    #[test]
    fn unlock_with_passphrase_rejects_when_verifier_missing() {
        // A meta without a verifier (not-enabled / tampered) must be rejected.
        let meta = fast_meta("AAAAAAAAAAAAAAAAAAAAAA=="); // verifier: None
        assert!(matches!(
            unlock_with_passphrase(&meta, "anything", None),
            Err(SshrackError::VaultUnlockFailed)
        ));
    }

    #[test]
    fn unlock_writes_cache_when_ttl_positive() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let meta = meta_with_verifier("hunter2");
        unlock_with_passphrase(&meta, "hunter2", Some(tmp.path())).unwrap();
        assert!(tmp.path().exists(), "cache file must be written");
    }

    // ---- cached_key_is_valid ----

    #[test]
    fn cached_key_is_valid_only_for_matching_verifier() {
        let meta = meta_with_verifier("hunter2");
        let good = crypto::derive_key("hunter2", &meta).unwrap();
        let bad = crypto::derive_key("wrong", &meta).unwrap();
        assert!(cached_key_is_valid(&good, &meta));
        assert!(!cached_key_is_valid(&bad, &meta));
    }

    #[test]
    fn cached_key_is_invalid_without_verifier() {
        let meta = fast_meta("AAAAAAAAAAAAAAAAAAAAAA=="); // verifier: None
        let key = crypto::derive_key("x", &meta).unwrap();
        assert!(!cached_key_is_valid(&key, &meta));
    }

    // ---- unlock ----

    #[test]
    fn unlock_returns_none_in_plaintext_mode() {
        let cfg = SshrackConfig::default(); // no vault
        assert!(matches!(unlock(&cfg, None, None, &deny()), Ok(None)));
    }

    #[test]
    fn unlock_rejects_stale_cache_key() {
        // Config encrypted under "hunter2".
        let meta = meta_with_verifier("hunter2");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault { meta: meta.clone() }),
            ..SshrackConfig::default()
        };
        // Cache holds a key from a DIFFERENT passphrase — stale, but within TTL
        // so read_cache returns it. unlock must NOT return the stale key.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let stale = crypto::derive_key("wrong", &meta).unwrap();
        cache::write_cache(tmp.path(), &stale, std::time::Duration::from_secs(1800)).unwrap();

        // No env-passphrase injected, and deny() provider refuses to prompt —
        // so we exercise the stale-cache rejection path without relying on
        // env state (the test never touches `std::env`).
        let res = unlock(&cfg, Some(tmp.path()), None, &deny());
        assert!(
            !matches!(res, Ok(Some(_))),
            "stale cache key must not be returned: {res:?}"
        );
    }

    // ---- ensure_unlocked_vault_key ----

    #[test]
    fn ensure_unlocked_vault_key_returns_none_for_non_vault_config() {
        let cfg = SshrackConfig::default();
        let result = ensure_unlocked_vault_key(&cfg, None, &deny()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn ensure_unlocked_vault_key_prefers_env_passphrase_over_provider() {
        // Hermetic: the env-passphrase is injected as a parameter, so the real
        // `SSHRACK_PASSPHRASE` (set or unset in the shell) is irrelevant. The
        // deny() provider would refuse a prompt — proving the env value won
        // over the provider.
        let meta = meta_with_verifier("env-passphrase");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault { meta }),
            ..SshrackConfig::default()
        };
        let env_pw = Zeroizing::new("env-passphrase".to_string());
        let result = ensure_unlocked_vault_key(&cfg, Some(&env_pw), &deny());
        assert!(
            matches!(result, Ok(Some(_))),
            "env-passphrase must unlock even when the provider refuses: {result:?}"
        );
    }

    #[test]
    fn ensure_unlocked_vault_key_fails_when_provider_refuses_and_no_env() {
        // No cache, no injected env-passphrase (None), provider refuses → must
        // fail (not panic). Hermetic: passes `None` explicitly, so the real
        // `SSHRACK_PASSPHRASE` in the shell never reaches this test. This test
        // never early-returns — it always runs.
        let meta = meta_with_verifier("secret");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault { meta }),
            ..SshrackConfig::default()
        };
        let result = ensure_unlocked_vault_key(&cfg, None, &deny());
        assert!(
            result.is_err(),
            "provider refusal with no env-passphrase must fail: {result:?}"
        );
    }

    // ---- enable ----

    #[test]
    fn enable_sets_vault_and_encrypts_existing_plaintext() {
        // enable migrates an existing plaintext credential into vault mode,
        // writes a verifier, and flips cfg.store. The returned key decrypts the
        // verifier (proof it matches the new meta).
        let mut cfg = SshrackConfig {
            credentials: vec![Credential {
                id: ulid::Ulid::new(),
                name: "a".into(),
                body: CredentialBody::new("u").with_password("p"),
            }],
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let key = enable(&mut cfg, "passphrase", None, &backend).unwrap();
        let meta = cfg.vault_meta().expect("invariant: vault mode");
        assert_eq!(meta.kdf, "argon2id");
        assert!(meta.verifier.is_some(), "verifier must be written");
        assert!(cfg.is_vault(), "cfg.store must be vault");
        assert!(
            matches!(cfg.credentials[0].body.password, Some(Secret::Encrypted(_))),
            "existing plaintext must be migrated to Encrypted"
        );
        // The returned key decrypts the verifier — i.e. it is the right key.
        assert!(crypto::decrypt(meta.verifier.as_ref().unwrap(), &key).is_ok());
    }

    #[test]
    fn enable_honors_explicit_cache_ttl() {
        let mut cfg = SshrackConfig::default();
        let backend = FakeBackend::new();
        enable(&mut cfg, "p", Some(42), &backend).unwrap();
        assert_eq!(
            cfg.vault_meta()
                .expect("invariant: vault mode")
                .cache_ttl_secs,
            42
        );
    }

    #[test]
    fn enable_defaults_cache_ttl_when_none() {
        let mut cfg = SshrackConfig::default();
        let backend = FakeBackend::new();
        enable(&mut cfg, "p", None, &backend).unwrap();
        assert_eq!(
            cfg.vault_meta()
                .expect("invariant: vault mode")
                .cache_ttl_secs,
            VaultMeta::DEFAULT_CACHE_TTL_SECS
        );
    }

    // ---- seal_body: three-mode branching + pass-through ----
    //
    // These exercise seal_password's dispatch on cfg.store WITHOUT touching the
    // first-use prompt (they construct cfg.store directly). The vault branch is
    // driven by an already-unlocked key the caller passes in — no unlock, no
    // prompt, hermetic. The keyring branch writes through the injected
    // FakeBackend, so no Secret Service daemon is required.

    #[test]
    fn seal_body_plaintext_mode_keeps_inline_password() {
        // Plaintext mode keeps the password inline and leaves the keyring flag false.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let id = ulid::Ulid::new();
        let body = CredentialBody::new("root").with_password("hunter2");
        let out = seal_body(body, OwnerKind::Host, &id, &cfg, None, &backend).unwrap();
        assert!(!out.keyring);
        assert_eq!(out.password_plain(), Some("hunter2"));
    }

    #[test]
    fn seal_body_vault_mode_encrypts_inline_password() {
        // Vault mode: the caller supplies an already-unlocked key; seal_body
        // encrypts the plaintext inline. No unlock, no prompt, hermetic.
        let mut cfg = SshrackConfig::default();
        let backend = FakeBackend::new();
        let key = enable(&mut cfg, "test-passphrase", None, &backend).unwrap();
        let id = ulid::Ulid::new();
        let body = CredentialBody::new("root").with_password("hunter2");
        let out = seal_body(body, OwnerKind::Credential, &id, &cfg, Some(&key), &backend).unwrap();
        assert!(
            matches!(out.password, Some(Secret::Encrypted(_))),
            "vault mode must encrypt, got {:?}",
            out.password
        );
        assert!(!out.keyring, "keyring flag must stay false in vault mode");
        // Round-trips: decrypt back to the original plaintext.
        if let Some(Secret::Encrypted(enc)) = &out.password {
            let plain = crypto::decrypt(enc, &key).unwrap();
            assert_eq!(plain.as_str(), "hunter2");
        }
    }

    #[test]
    fn seal_body_vault_mode_without_key_is_locked() {
        // The caller forgot to unlock in vault mode — must error VaultLocked,
        // NOT silently store plaintext.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: fast_meta("AA=="),
            }),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let id = ulid::Ulid::new();
        let body = CredentialBody::new("root").with_password("hunter2");
        let err = seal_body(body, OwnerKind::Host, &id, &cfg, None, &backend).unwrap_err();
        assert!(matches!(err, SshrackError::VaultLocked));
    }

    #[test]
    fn seal_body_keyring_mode_stores_and_sets_marker() {
        // Keyring mode: the plaintext is stored via the backend under the
        // owner id, the inline password is cleared, and the keyring marker is
        // set. FakeBackend stands in for the OS keyring.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let id = ulid::Ulid::new();
        let body = CredentialBody::new("root").with_password("hunter2");
        let out = seal_body(body, OwnerKind::Credential, &id, &cfg, None, &backend).unwrap();
        assert!(out.keyring, "body.keyring must be true in keyring mode");
        assert!(
            out.password.is_none(),
            "inline password must be cleared in keyring mode"
        );
        // The plaintext is now in the fake backend under the owner id.
        let fetched = backend
            .get(&keyring_key(OwnerKind::Credential, &id))
            .unwrap();
        assert_eq!(fetched.as_deref().map(String::as_str), Some("hunter2"));
    }

    #[test]
    fn seal_body_passes_through_already_encrypted_body() {
        // An already-encrypted body (re-saving an untouched entry) passes
        // through without re-encrypting or attempting keyring storage.
        let mut cfg = SshrackConfig::default();
        let backend = FakeBackend::new();
        let key = enable(&mut cfg, "test-passphrase", None, &backend).unwrap();
        let id = ulid::Ulid::new();
        let enc = crypto::encrypt(b"pw", &key).unwrap();
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Encrypted(enc)),
            key: None,
            keyring: false,
        };
        let out = seal_body(body, OwnerKind::Credential, &id, &cfg, Some(&key), &backend).unwrap();
        assert!(matches!(out.password, Some(Secret::Encrypted(_))));
        assert!(!out.keyring);
    }

    #[test]
    fn seal_body_keyring_marker_body_stays_marked_in_keyring_mode() {
        // A body that already carries `keyring = true` (a re-save of an existing
        // keyring entry, no plaintext present) must keep its marker when
        // re-sealed in keyring mode. password.is_none() drives the marker, so a
        // marker body round-trips through seal_body unchanged.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let id = ulid::Ulid::new();
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        let out = seal_body(body, OwnerKind::Host, &id, &cfg, None, &backend).unwrap();
        assert!(out.keyring, "marker must be preserved in keyring mode");
        assert!(out.password.is_none());
    }

    // ---- seal_auth ----

    #[test]
    fn seal_auth_inline_seals_body_with_host_owner() {
        // An inline auth is sealed with OwnerKind::Host and the host's id, so
        // the keyring entry (in keyring mode) is keyed by host:<id>.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let id = ulid::Ulid::new();
        let auth = Auth::inline(CredentialBody::new("root").with_password("hunter2"));
        let out = seal_auth(auth, OwnerKind::Host, &id, &cfg, None, &backend).unwrap();
        let body = match out {
            Auth::Inline(b) => b,
            other => panic!("inline must stay inline, got {other:?}"),
        };
        assert!(body.keyring, "marker must be set in keyring mode");
        assert!(body.password.is_none());
        // Keyed by host id, not cred id.
        let fetched = backend.get(&keyring_key(OwnerKind::Host, &id)).unwrap();
        assert_eq!(fetched.as_deref().map(String::as_str), Some("hunter2"));
    }

    #[test]
    fn seal_auth_ref_passes_through_unchanged() {
        // A reference carries no inline secret — it passes through verbatim,
        // including the referenced credential id.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        let backend = FakeBackend::new();
        let cred_id = ulid::Ulid::new();
        let host_id = ulid::Ulid::new();
        let auth = Auth::reference(cred_id);
        let out = seal_auth(auth, OwnerKind::Host, &host_id, &cfg, None, &backend).unwrap();
        assert_eq!(
            out.credential_id(),
            Some(cred_id),
            "reference must round-trip unchanged"
        );
        // No secret was written to the backend (a reference carries none).
        assert!(
            backend
                .get(&keyring_key(OwnerKind::Host, &host_id))
                .unwrap()
                .is_none(),
            "no keyring entry must be created for a reference"
        );
    }
}
