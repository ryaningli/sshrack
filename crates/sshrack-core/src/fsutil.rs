//! Filesystem helpers for secret-bearing files: write owner-only (0600 on
//! Unix) with no umask window. Shared by the config store, the frecency store,
//! and the vault key cache so all of them create-or-overwrite at 0600 and
//! persist via the same atomic write path.

use std::path::{Path, PathBuf};

/// Write `contents` to `path`, creating the file owner-only (mode 0600 on
/// Unix) at open time, or truncating it in place if it already exists.
///
/// On Unix the mode is applied via `OpenOptions::mode(0o600)` at create time,
/// so the file never exists with umask-permitted (often 0644) permissions; an
/// already-present file keeps its existing mode (the program only ever writes
/// these files at 0600). The raw [`std::io::Error`] is returned so each caller
/// can attach its own path-bearing variant
/// ([`crate::error::SshrackError::ConfigWrite`] vs
/// [`crate::error::SshrackError::CacheIo`]). Non-Unix targets fall back to a
/// plain write (Windows ACL hardening is out of scope for phase 1).
pub(crate) fn write_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    #[cfg(target_family = "unix")]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents).inspect_err(|_| {
            // Best-effort: do not leave a partial file behind on write failure.
            let _ = std::fs::remove_file(path);
        })?;
        Ok(())
    }
    #[cfg(not(target_family = "unix"))]
    {
        std::fs::write(path, contents)
    }
}

/// Write `contents` to a sibling temp file at 0600 (via [`write_private`]),
/// then atomically `rename` it over `path`. Removes the temp file on rename
/// failure so no `.tmp` leftovers remain after a failed save. The temp path
/// embeds pid + nanos, so collisions are effectively impossible.
///
/// Shared by [`crate::config::store::save`] and [`crate::frecency::store::save`]
/// so both persist atomically at 0600 through one path. The raw
/// [`std::io::Error`] is returned (each caller attaches its own path-bearing
/// error variant).
pub(crate) fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let tmp = atomic_temp_path(path);
    write_private(&tmp, contents)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Best-effort: clean up the temp file so a failed save leaves no trace.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// A unique sibling temp path: `.<file>.tmp.<pid>.<nanos>`. Falls back to
/// `file` when `path` has no file name component (which never happens for the
/// real callers — config/frecency/cache files always have names).
fn atomic_temp_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "file".into());
    let mut name = std::ffi::OsString::from(".");
    name.push(base);
    name.push(format!(".tmp.{pid}.{nanos}"));
    path.with_file_name(name)
}
