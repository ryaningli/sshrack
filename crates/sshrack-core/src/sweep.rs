//! Best-effort cleanup of sshrack temp files left behind by a crashed prior
//! run. The connect path's `Drop` / child-exit removals are best-effort and
//! skip on Ctrl-C / SIGKILL; this sweep runs once at startup to collect the
//! orphans (`sshrack-askpass-*.pw`, `sshrack-key-*.pem`, plus the matching
//! `*-cert.pub`). Files newer than the staleness threshold are left alone so a
//! concurrent live connection's freshly-written file is never deleted.
//!
//! The threshold is kept short (5 minutes): `ssh` reads the `-i` IdentityFile
//! once, early, at connect time, so a `sshrack-key-*.pem` older than a few
//! minutes is residue from a crashed prior run, not a live connection's file
//! (a connection whose ssh still hasn't opened the key after that long has
//! hung). This bounds the on-disk secret leak window from SIGKILL/crash to the
//! next sshrack launch.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// Patterns owned by sshrack that the connect path creates and is responsible
/// for removing. Anything else in the temp dir is left untouched.
const STALE_PREFIXES: &[&str] = &["sshrack-askpass-", "sshrack-key-"];

/// SIGKILL/crash leak window: a temp file older than this at startup is
/// reclaimed. `ssh` reads the `-i` IdentityFile once at connect time, so a
/// file more than a few minutes old is residue from a crashed prior run, not a
/// live connection's file (a live connection whose ssh hasn't opened the key
/// after this long has hung). Kept small to bound the on-disk secret window.
const STALE_THRESHOLD: Duration = Duration::from_secs(300);

/// Exposed so the threshold can be pinned by a unit test (a future bump should
/// be a conscious decision, since it bounds how long a leaked key sits on disk).
/// Test-only: nothing in production reads this (production uses `STALE_THRESHOLD`
/// directly via `sweep_default`), hence the `#[cfg(test)]` gate.
#[cfg(test)]
pub(crate) fn stale_threshold() -> Duration {
    STALE_THRESHOLD
}

/// Remove sshrack temp files under `dir` whose mtime is older than `max_age`
/// (relative to `now`). Returns the count removed. Best-effort: unreadable
/// entries, permission errors, and a missing `dir` all resolve to `0` (a sweep
/// failure must never block a connect). `now` is injected so the staleness
/// check is unit-testable without backdating file mtimes.
pub fn sweep_stale_tempfiles(dir: &Path, now: SystemTime, max_age: Duration) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_sshrack_tempfile(&path) {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|mtime| {
                now.duration_since(mtime)
                    .map(|age| age > max_age)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if stale && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Whether `path`'s file name matches a sshrack-owned temp-file pattern. Covers
/// `sshrack-askpass-*.pw`, `sshrack-key-*.pem`, and the `sshrack-key-*-cert.pub`
/// sibling that `KeyArtifact` writes beside the private key.
fn is_sshrack_tempfile(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    STALE_PREFIXES.iter().any(|pfx| name.starts_with(pfx))
}

/// Default startup sweep: the std temp dir, "now", and the staleness threshold
/// ([`STALE_THRESHOLD`]). A normal connection closes its temp files within
/// seconds; `ssh` reads the `-i` IdentityFile once at connect, so a file older
/// than the 5-minute threshold is residue from a crashed prior run (or a hung
/// connection). Best-effort; all errors are swallowed.
pub fn sweep_default() {
    let _ = sweep_stale_tempfiles(&std::env::temp_dir(), SystemTime::now(), STALE_THRESHOLD);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// Write a file at real-now. Staleness is controlled purely by the `now`
    /// passed to `sweep_stale_tempfiles` (injected `now` design — no `filetime`
    /// mtime backdating needed, keeps the tests hermetic and dev-dep-free beyond
    /// `tempfile`).
    fn touch(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn removes_stale_askpass_and_key_files() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "sshrack-askpass-111-222.pw");
        touch(dir.path(), "sshrack-key-333-444.pem");
        touch(dir.path(), "sshrack-key-333-444.pem-cert.pub");
        // Injected `now` pushed 2h into the future so the freshly-written files
        // read as older than the 1h threshold.
        let now = SystemTime::now() + Duration::from_secs(7200);
        let removed = sweep_stale_tempfiles(dir.path(), now, Duration::from_secs(3600));
        assert_eq!(removed, 3);
        assert!(dir.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn preserves_fresh_files_under_threshold() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "sshrack-askpass-111-222.pw");
        // `now` ~= real-now: the file is brand new, well under the threshold.
        let now = SystemTime::now();
        let removed = sweep_stale_tempfiles(dir.path(), now, Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert!(dir.path().join("sshrack-askpass-111-222.pw").exists());
    }

    #[test]
    fn ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sshrack-msg.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("unrelated.log"), b"x").unwrap();
        // Far-future `now` would make any sshrack file stale; these two are not
        // sshrack-owned, so none are removed.
        let now = SystemTime::now() + Duration::from_secs(99999);
        let removed = sweep_stale_tempfiles(dir.path(), now, Duration::from_secs(3600));
        assert_eq!(removed, 0);
    }

    #[test]
    fn missing_dir_is_silent_zero() {
        let removed = sweep_stale_tempfiles(
            std::path::Path::new("/no/such/dir/here"),
            SystemTime::now(),
            Duration::from_secs(3600),
        );
        assert_eq!(removed, 0);
    }

    #[test]
    fn sweep_default_threshold_is_short() {
        // The SIGKILL/crash leak window = the sweep threshold. ssh reads the -i
        // IdentityFile once at connect, so files older than a few minutes are safe
        // to reclaim. Pin the constant so a future bump is a conscious decision.
        assert!(
            super::stale_threshold() <= std::time::Duration::from_secs(600),
            "sweep threshold must stay <= 10 min to bound the on-disk secret window"
        );
    }
}
