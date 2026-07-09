//! Process-global registry of sshrack temp files held by a live connection
//! (inline-key `.pem` / cert, askpass `.pw`). `KeyArtifact` and
//! `write_password_file` register on create and unregister on Drop/exit; a
//! signal-time cleaner (`cleanup_all`) wipes whatever is still registered so a
//! Ctrl-C / SIGTERM mid-connection does not leave secrets on disk — `Drop` is
//! skipped when the process is killed by a signal.
//!
//! Lock-guarded, best-effort: a fs error or lock-poison during cleanup never
//! propagates (a cleanup failure must not mask the signal).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LIVE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Test-only serializer so tests touching the global `LIVE` registry (here AND
/// in `connect::tests`) cannot interleave. Acquired at the start of each such
/// test. A separate process-wide lock (rather than a per-module one) is required
/// because the registry itself is process-global: a `connect::tests` entry
/// registered mid-flight would be drained by a registry test's `cleanup_all`,
/// breaking count assertions and poisoning this lock's sibling tests.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Record a temp file path as currently live so a signal-time cleanup can
/// remove it if the process is killed before its owner `Drop`s.
pub fn register(path: PathBuf) {
    if let Ok(mut v) = LIVE.lock() {
        v.push(path);
    }
}

/// Remove a path from the registry (its owner `Drop` ran normally).
pub fn unregister(path: &Path) {
    if let Ok(mut v) = LIVE.lock() {
        v.retain(|p| p != path);
    }
}

/// Delete every registered temp file from disk and clear the registry. Returns
/// the count removed. Best-effort: fs errors and a poisoned lock are swallowed.
/// Called by the binary's SIGINT/SIGTERM handler.
pub fn cleanup_all() -> usize {
    let paths = LIVE
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default();
    paths
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    // `LIVE` is a process global, so tests touching it (here AND in
    // `connect::tests`) serialize on `super::TEST_LOCK` to avoid racing: one
    // test's `cleanup_all` could otherwise drain another's entries mid-flight.
    // Lock is held for the whole test body.

    #[test]
    fn cleanup_all_removes_registered_files() {
        let _g = super::TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("sshrack-key-a.pem");
        let b = dir.path().join("sshrack-askpass-b.pw");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        register(a.clone());
        register(b.clone());
        let removed = cleanup_all();
        assert_eq!(removed, 2);
        assert!(!a.exists());
        assert!(!b.exists());
    }

    #[test]
    fn unregister_keeps_a_file_registered_as_live() {
        let _g = super::TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("sshrack-key-keep.pem");
        let gone = dir.path().join("sshrack-key-gone.pem");
        std::fs::write(&keep, b"x").unwrap();
        std::fs::write(&gone, b"x").unwrap();
        register(keep.clone());
        register(gone.clone());
        unregister(&gone); // its Drop ran
        let removed = cleanup_all();
        assert_eq!(removed, 1);
        assert!(!keep.exists()); // keep was still registered → removed
        assert!(gone.exists()); // unregistered → left alone
    }

    #[test]
    fn cleanup_all_is_noop_when_empty() {
        let _g = super::TEST_LOCK.lock().unwrap();
        // Drain any leftovers from other tests so this is deterministic.
        let _ = cleanup_all();
        assert_eq!(cleanup_all(), 0);
    }

    #[test]
    fn cleanup_all_swallows_missing_file() {
        let _g = super::TEST_LOCK.lock().unwrap();
        // A registered path that no longer exists (owner already removed it)
        // must not panic or be counted.
        register(PathBuf::from("/tmp/sshrack-definitely-not-here-xyz.pem"));
        let removed = cleanup_all();
        assert_eq!(removed, 0);
    }
}
