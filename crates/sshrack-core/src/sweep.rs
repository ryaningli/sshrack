//! Best-effort cleanup of sshrack temp files left behind by a crashed prior
//! run. The connect path's `Drop` / child-exit removals are best-effort and
//! skip on Ctrl-C / SIGKILL; this sweep runs once at startup to collect the
//! orphans (`sshrack-askpass-*.pw`, `sshrack-key-*.pem`, plus the matching
//! `*-cert.pub`). Files newer than the staleness threshold are left alone so a
//! concurrent live connection's freshly-written file is never deleted.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// Patterns owned by sshrack that the connect path creates and is responsible
/// for removing. Anything else in the temp dir is left untouched.
const STALE_PREFIXES: &[&str] = &["sshrack-askpass-", "sshrack-key-"];

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

/// Default startup sweep: the std temp dir, "now", and a 1-hour staleness
/// threshold. A normal connection closes its temp files within seconds, so a
/// file older than an hour is residue from a crashed prior run (or a zombie
/// connection). Best-effort; all errors are swallowed.
pub fn sweep_default() {
    let _ = sweep_stale_tempfiles(
        &std::env::temp_dir(),
        SystemTime::now(),
        Duration::from_secs(3600),
    );
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
}
