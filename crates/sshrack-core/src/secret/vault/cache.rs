//! Master-key cache: a 0600 file holding the derived key + a timestamp, so a
//! passphrase is entered at most once per TTL window instead of once per
//! connection. Lives under `$XDG_RUNTIME_DIR` (tmpfs) when available, else the
//! per-user cache dir. I/O only — no cryptography here.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::error::SshrackError;
use crate::secret::vault::VaultKey;

/// 32-byte key + 8-byte LE timestamp.
const KEY_LEN: usize = 32;
const TS_LEN: usize = 8;
const RECORD_LEN: usize = KEY_LEN + TS_LEN;

/// Default cache location: runtime dir (tmpfs) if present, else per-user
/// cache dir. Both are per-user, so no uid juggling is needed. Returns
/// `None` if no per-user directory can be resolved.
pub fn default_cache_path() -> Option<PathBuf> {
    let pd = directories::ProjectDirs::from("dev", "sshrack", "sshrack")?;
    let dir = pd.runtime_dir().or_else(|| Some(pd.cache_dir()))?;
    Some(dir.join("vault.key"))
}

/// Read a non-expired master key from the cache, or `None` if absent, corrupt,
/// or older than `ttl`. A `ttl` of zero disables caching and always returns
/// `None`. Any read or timestamp error degrades to `None` so a damaged cache
/// is self-healing — the caller simply re-derives and re-prompts.
pub fn read_cache(path: &Path, ttl: Duration) -> Option<VaultKey> {
    if ttl.is_zero() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() != RECORD_LEN {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes[..KEY_LEN]);
    let ts = u64::from_le_bytes(bytes[KEY_LEN..].try_into().ok()?);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now.saturating_sub(ts) >= ttl.as_secs() {
        return None;
    }
    Some(Zeroizing::new(key))
}

/// Write the master key + current timestamp, mode 0600 on Unix. A no-op when
/// `ttl` is zero, so caching can be disabled purely by config without special
/// casing at call sites. Never leaks the key in the returned error.
pub fn write_cache(path: &Path, key: &VaultKey, ttl: Duration) -> Result<(), SshrackError> {
    if ttl.is_zero() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent); // best-effort
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut record = [0u8; RECORD_LEN];
    record[..KEY_LEN].copy_from_slice(key.as_ref());
    record[KEY_LEN..].copy_from_slice(&now.to_le_bytes());
    // Created at 0600 (no umask window) via the shared helper.
    crate::fsutil::write_private(path, &record).map_err(|source| SshrackError::CacheIo {
        path: path.to_path_buf(),
        source,
    })
}

/// Remove the cache file so the next unlock re-prompts. No error if the file
/// is already absent — clearing is idempotent.
pub fn clear_cache(path: &Path) -> Result<(), SshrackError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SshrackError::CacheIo {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Clear the master-key cache at its default location (best-effort, no-op if
/// absent). Used by `store use`/`rekey`/`lock`/`enable` so each does not
/// re-derive the path and swallow the result inline.
pub fn clear_default_cache() {
    if let Some(p) = default_cache_path() {
        let _ = clear_cache(&p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> VaultKey {
        Zeroizing::new([fill; KEY_LEN])
    }

    #[test]
    fn write_then_read_round_trips_within_ttl() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_cache(tmp.path(), &key(7), Duration::from_secs(1800)).unwrap();
        let got = read_cache(tmp.path(), Duration::from_secs(1800));
        assert_eq!(got.as_ref().map(|k| k.as_ref()), Some(&[7u8; 32][..]));
    }

    #[test]
    fn zero_ttl_disables_both_directions() {
        // Use a path that does not exist yet — `NamedTempFile::new()` would
        // pre-create the file and mask the no-op assertion below.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        write_cache(&path, &key(7), Duration::ZERO).unwrap();
        assert!(!path.exists(), "zero TTL must not write a cache");
        assert!(read_cache(&path, Duration::ZERO).is_none());
    }

    #[test]
    fn expired_record_reads_as_none() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Build a record whose timestamp is 1 hour in the past.
        let old = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(3600);
        let mut record = [0u8; RECORD_LEN];
        record[..KEY_LEN].copy_from_slice(&[7u8; KEY_LEN]);
        record[KEY_LEN..].copy_from_slice(&old.to_le_bytes());
        std::fs::write(tmp.path(), record).unwrap();
        assert!(read_cache(tmp.path(), Duration::from_secs(60)).is_none());
    }

    #[test]
    fn clear_is_idempotent() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_cache(tmp.path(), &key(1), Duration::from_secs(60)).unwrap();
        clear_cache(tmp.path()).unwrap();
        assert!(!tmp.path().exists());
        // Clearing a missing file is not an error.
        clear_cache(tmp.path()).unwrap();
    }

    #[test]
    fn short_or_corrupt_file_reads_as_none() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"garbage").unwrap();
        assert!(read_cache(tmp.path(), Duration::from_secs(60)).is_none());
    }
}
