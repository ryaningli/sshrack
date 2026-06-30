//! Filesystem helpers for secret-bearing files: write owner-only (0600 on
//! Unix) with no umask window. Shared by the config store (atomic save) and
//! the vault key cache so both create-or-overwrite at 0600 through one path.

use std::path::Path;

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
