//! OS keyring password storage (keyring mode), behind the [`SecretBackend`] trait.
//!
//! Passwords live in the OS credential store (macOS Keychain / Linux Secret
//! Service), keyed by a stable account derived from the owning body's ULID id
//! (not the alias), so renaming a host or credential never moves its entry.
//! `config.toml` holds only a `keyring = true` marker — the plaintext never
//! touches disk. The askpass helper reads entries directly via [`get`], so the
//! main sshrack process never materializes a keyring password.
//!
//! Keying goes through [`crate::id::keyring_key`] (`<kind>:<ulid>`); this module
//! is purely the OS I/O layer over raw account keys. The trait seam itself lives
//! in [`super`] (`SecretBackend` / `OsKeyring`).

use zeroize::Zeroizing;

use crate::error::SshrackError;

/// Constant keyring service name. All sshrack entries share this service; the
/// per-owner account key (built via [`crate::id::keyring_key`]) disambiguates
/// them.
pub const SERVICE: &str = "sshrack";

/// Env var naming the keyring account the askpass helper fetches. Set by the
/// connect path for keyring-mode connections instead of a temp password file.
/// Read by the helper to call [`get`] directly.
pub const KEYRING_KEY_ENV: &str = "SSHRACK_KEYRING_KEY";

/// Open the keyring entry for a raw account key. A failure to construct the
/// entry means the backend is unreachable.
fn entry_for(key: &str) -> Result<keyring::Entry, SshrackError> {
    keyring::Entry::new(SERVICE, key).map_err(|_| SshrackError::KeyringUnavailable)
}

/// Store `password` under the raw account `key` (overwrites any existing
/// entry). I/O. Used by [`super::OsKeyring::set`] (which derives the key from
/// `OwnerKind + Ulid`) and by keyring-mode migrations.
pub(crate) fn set_by_key(key: &str, password: &str) -> Result<(), SshrackError> {
    let entry = entry_for(key)?;
    entry
        .set_password(password)
        .map_err(|_| SshrackError::KeyringIo { detail: "write" })
}

/// Fetch the password for a raw account key; `Ok(None)` when no entry exists.
/// Used by the askpass helper — the only place a keyring password's plaintext
/// is materialized, and it lives in the short-lived helper process.
pub fn get(key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
    let entry = entry_for(key)?;
    match entry.get_password() {
        Ok(p) => Ok(Some(Zeroizing::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(SshrackError::KeyringIo { detail: "read" }),
    }
}

/// Delete the entry for a raw account key if present. A missing entry is
/// success. Used by [`super::OsKeyring::delete`] and the rm/cp keyring cleanup.
pub fn delete_by_key(key: &str) -> Result<(), SshrackError> {
    let entry = entry_for(key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(SshrackError::KeyringIo { detail: "delete" }),
    }
}

/// True when the OS keyring backend is reachable (a Secret Service daemon is
/// running / the keychain is unlocked). Probes by writing + deleting a
/// throwaway entry. Used by `store use keyring` to fail fast before migrating
/// any passwords.
pub fn daemon_available() -> bool {
    let probe = match keyring::Entry::new(SERVICE, "__sshrack_probe__") {
        Ok(e) => e,
        Err(_) => return false,
    };
    let reachable = probe.set_password("").is_ok();
    // Best-effort cleanup so the probe entry does not accumulate in the user's
    // keyring on every call. A failure to delete is not a signal about daemon
    // availability — the write above already answered that.
    if reachable {
        let _ = probe.delete_credential();
    }
    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_constants_match_contract() {
        assert_eq!(SERVICE, "sshrack");
        assert_eq!(KEYRING_KEY_ENV, "SSHRACK_KEYRING_KEY");
    }
}
