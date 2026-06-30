//! Machine-local persistence for [`Frecency`](super::Frecency) as an atomic
//! 0600 TOML file under the data dir.
//!
//! [`load`] of a missing file returns an empty [`Frecency`] (a fresh install
//! has no usage history). [`save`] serializes the table to `<dir>/frecency.toml`
//! via an atomic write (temp file at 0600, then rename), mirroring
//! [`crate::config::store::save`].
//!
//! TOML cannot serialize [`std::time::SystemTime`] directly, so the on-disk
//! representation stores `last_used` as seconds-since-epoch (`i64`) via the
//! [`StoredEntry`] mirror struct. A `None` `last_used` (never-recorded entry) is
//! stored as an absent `last_used_secs` field rather than a sentinel, so a
//! default entry round-trips cleanly.

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::SshrackError;
use crate::frecency::{Entry, Frecency};

/// The frecency file name, written inside the caller-supplied data dir.
const FILENAME: &str = "frecency.toml";

/// On-disk entry: a TOML-friendly mirror of [`Entry`]. `last_used_secs` is the
/// `last_used` [`SystemTime`] as seconds-since-epoch, or `None` when the entry
/// has never been recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_secs: Option<i64>,
}

/// On-disk frecency table: a TOML-friendly mirror of [`Frecency`]. The map key
/// is the host [`ulid::Ulid`] rendered as its 26-char string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredFrecency {
    #[serde(default)]
    entries: HashMap<String, StoredEntry>,
}

/// Load the frecency table from `<dir>/frecency.toml`. A missing file returns
/// an empty [`Frecency`] (no error) so a fresh install works without one.
pub fn load(dir: &Path) -> Result<Frecency, SshrackError> {
    let path = dir.join(FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let stored: StoredFrecency =
                toml::from_str(&contents).map_err(|source| SshrackError::ConfigParse {
                    path: path.clone(),
                    source,
                })?;
            Ok(from_stored(stored))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Frecency::default()),
        Err(source) => Err(SshrackError::ConfigRead { path, source }),
    }
}

/// Serialize `frec` to TOML and write it to `<dir>/frecency.toml` atomically
/// with owner-only permissions. Parent directories are created on demand.
/// Mirrors [`crate::config::store::save`].
pub fn save(dir: &Path, frec: &Frecency) -> Result<(), SshrackError> {
    let path = dir.join(FILENAME);
    let stored = to_stored(frec);
    let serialized =
        toml::to_string_pretty(&stored).map_err(|source| SshrackError::ConfigSerialize {
            path: path.clone(),
            source,
        })?;
    std::fs::create_dir_all(dir).map_err(|e| SshrackError::ConfigWrite {
        path: dir.to_path_buf(),
        source: e,
    })?;
    crate::fsutil::atomic_write_private(&path, serialized.as_bytes()).map_err(|source| {
        SshrackError::ConfigWrite {
            path: path.clone(),
            source,
        }
    })
}

/// Convert the in-memory [`Frecency`] to its TOML-friendly mirror.
fn to_stored(frec: &Frecency) -> StoredFrecency {
    let mut entries = HashMap::with_capacity(frec.map.len());
    for (id, entry) in &frec.map {
        let last_used_secs = entry.last_used.and_then(system_time_to_secs);
        entries.insert(
            id.to_string(),
            StoredEntry {
                score: entry.score,
                last_used_secs,
            },
        );
    }
    StoredFrecency { entries }
}

/// Convert the TOML-friendly mirror back to in-memory [`Frecency`]. Unknown or
/// malformed keys are skipped (forward-compat with future fields).
fn from_stored(stored: StoredFrecency) -> Frecency {
    let mut map = HashMap::with_capacity(stored.entries.len());
    for (id_str, entry) in stored.entries {
        let Ok(id) = ulid::Ulid::from_string(&id_str) else {
            tracing::warn!(key = %id_str, "skipping malformed frecency entry");
            continue;
        };
        let last_used = entry.last_used_secs.and_then(secs_to_system_time);
        map.insert(
            id,
            Entry {
                score: entry.score,
                last_used,
            },
        );
    }
    Frecency { map }
}

/// Render a [`SystemTime`] as seconds-since-epoch. Returns `None` for times
/// before the epoch (which cannot happen for a real `now`).
fn system_time_to_secs(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// Parse seconds-since-epoch back into a [`SystemTime`].
fn secs_to_system_time(secs: i64) -> Option<SystemTime> {
    if secs < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frecency::Frecency;
    use ulid::Ulid;

    /// A fixed `SystemTime` well after the epoch for deterministic round-trips.
    fn fixed_time() -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let frec = load(dir.path()).unwrap();
        assert!(frec.map.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_scores_and_last_used() {
        let dir = tempfile::tempdir().unwrap();
        let mut frec = Frecency::default();
        let a = Ulid::new();
        let b = Ulid::new();
        let t = fixed_time();
        frec.record_at(&a, t);
        frec.record_at(&a, t + std::time::Duration::from_secs(60)); // 1.0*4+1 = 5.0
        frec.record_at(&b, t); // 1.0

        save(dir.path(), &frec).unwrap();
        let back = load(dir.path()).unwrap();

        assert_eq!(back.map.len(), 2);
        assert_eq!(back.score(&a), 5.0);
        assert_eq!(back.score(&b), 1.0);
        assert_eq!(
            back.map.get(&a).unwrap().last_used,
            Some(t + std::time::Duration::from_secs(60))
        );
        assert_eq!(back.map.get(&b).unwrap().last_used, Some(t));
    }

    #[test]
    fn save_then_load_preserves_never_recorded_entry() {
        // An entry whose last_used is None (manually inserted) round-trips with
        // last_used still None — stored as an absent last_used_secs field.
        let dir = tempfile::tempdir().unwrap();
        let mut frec = Frecency::default();
        let id = Ulid::new();
        frec.map.insert(
            id,
            Entry {
                score: 2.5,
                last_used: None,
            },
        );

        save(dir.path(), &frec).unwrap();
        let back = load(dir.path()).unwrap();
        assert_eq!(back.score(&id), 2.5);
        assert_eq!(back.map.get(&id).unwrap().last_used, None);
    }

    #[test]
    fn save_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("deeper");
        let mut frec = Frecency::default();
        frec.record_at(&Ulid::new(), fixed_time());

        save(&nested, &frec).unwrap();
        assert!(nested.join(FILENAME).exists());
    }

    #[test]
    fn load_skips_malformed_ulid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILENAME);
        std::fs::write(
            &path,
            "[entries]\n\"not-a-ulid\" = { score = 1.0 }\n\"01H8ZG7WBCNVK1VPX9J8KQ3Y5Z\" = { score = 2.0 }\n",
        )
        .unwrap();
        let frec = load(dir.path()).unwrap();
        // Malformed key skipped; valid ULID kept.
        assert_eq!(frec.map.len(), 1);
        assert_eq!(
            frec.score(&Ulid::from_string("01H8ZG7WBCNVK1VPX9J8KQ3Y5Z").unwrap()),
            2.0
        );
    }

    #[test]
    fn load_skips_negative_last_used() {
        // A negative last_used_secs is before the epoch and unrepresentable;
        // it must not panic, and the entry keeps its score with last_used None.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILENAME);
        std::fs::write(
            &path,
            "[entries]\n\"01H8ZG7WBCNVK1VPX9J8KQ3Y5Z\" = { score = 1.5, last_used_secs = -100 }\n",
        )
        .unwrap();
        let frec = load(dir.path()).unwrap();
        let id = Ulid::from_string("01H8ZG7WBCNVK1VPX9J8KQ3Y5Z").unwrap();
        assert_eq!(frec.score(&id), 1.5);
        assert_eq!(frec.map.get(&id).unwrap().last_used, None);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut frec = Frecency::default();
        frec.record_at(&Ulid::new(), fixed_time());

        save(dir.path(), &frec).unwrap();
        let path = dir.path().join(FILENAME);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "frecency file must be 0600");
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let mut frec = Frecency::default();
        frec.record_at(&Ulid::new(), fixed_time());

        save(dir.path(), &frec).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "only the target file should remain");
        assert_eq!(leftovers[0].to_string_lossy(), FILENAME);
    }

    #[test]
    fn empty_frecency_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &Frecency::default()).unwrap();
        let back = load(dir.path()).unwrap();
        assert!(back.map.is_empty());
    }

    #[test]
    fn system_time_to_secs_round_trip() {
        let t = fixed_time();
        let secs = system_time_to_secs(t).unwrap();
        assert_eq!(secs_to_system_time(secs), Some(t));
    }

    #[test]
    fn system_time_to_secs_none_before_epoch() {
        let before = UNIX_EPOCH - std::time::Duration::from_secs(10);
        assert_eq!(system_time_to_secs(before), None);
    }
}
