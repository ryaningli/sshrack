//! Master-passphrase encryption for stored passwords ("vault" mode).
//!
//! Split into a pure cryptography core ([`crypto`]), pure body/config
//! transforms ([`transform`]), and an I/O-only key cache ([`cache`]). This
//! module owns the **read-direction** unlock orchestration:
//! [`ensure_unlocked_vault_key`], [`unlock`], and the helpers that back them.
//! The write-direction helpers (`enable`, `seal_body`, `seal_auth`) land in a
//! later task.
//!
//! # Unlock precedence
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
//! `--no-input` callers can inject the passphrase without a terminal. The
//! connect path passes `--no-input` through to the provider; under `--no-input`
//! the CLI's [`PassphraseProvider`] impl errors instead of prompting, so if
//! neither the cache nor the env value is available the call fails fast.
//!
//! # Design rules
//!
//! Nothing in this module ever prints, logs, or returns a passphrase, master
//! key, or plaintext in an error message.

pub mod cache;
pub mod crypto;
pub mod transform;

use std::path::Path;

use zeroize::Zeroizing;

use crate::config::schema::{SshrackConfig, VaultMeta};
use crate::error::SshrackError;
use crate::secret::PassphraseProvider;

/// The derived 32-byte master key. Wrapped in [`Zeroizing`] so it is wiped on
/// drop. Produced by [`crypto::derive_key`]; consumed by
/// [`crypto::encrypt`]/[`crypto::decrypt`] and the body transforms.
pub type VaultKey = Zeroizing<[u8; 32]>;

/// Environment variable that supplies the master passphrase for non-interactive
/// use (CI, scripts, `--no-input`). When set, [`unlock`] skips the TTY prompt.
pub const PASSPHRASE_ENV: &str = "SSHRACK_PASSPHRASE";

/// Plaintext encrypted as the vault verifier. Decrypting it under the master
/// key proves the passphrase is correct at unlock time. Used by
/// [`unlock_with_passphrase`] and the test helpers that build a
/// verifier-bearing [`VaultMeta`]. The write-direction callers (`enable`,
/// `rekey`) that also encrypt this plaintext land in Task 20.
#[allow(dead_code)]
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
/// Under `--no-input`, the CLI's provider errors on `passphrase()`, so the
/// call fails here when neither the cache nor the env value is available —
/// exactly the right behavior for unattended runs.
///
/// `env_passphrase` is injected (read by the caller via
/// [`passphrase_from_env`]) so this function is testable without touching
/// `std::env`.
///
/// This is the key entry point for the connect path. Write-direction callers
/// (`enable`, `seal_body`) are Task 20.
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
    use crate::config::schema::{SecretStore, SshrackConfig, VaultMeta};
    use crate::secret::test_doubles::deny;

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
}
