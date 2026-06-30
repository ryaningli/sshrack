//! The askpass role: ssh forks this binary (via `$SSH_ASKPASS`) to hand over
//! a password. We ignore ssh's prompt argument and emit the password for the
//! host sshrack is connecting to. There are two delivery modes, selected by
//! which environment variable the parent sshrack process set in
//! [`crate::connect::launch`]:
//!
//! - [`KEYRING_KEY_ENV`][crate::secret::keyring::KEYRING_KEY_ENV] — fetch the password
//!   from the OS keyring via [`crate::secret::keyring::get`]. No temp file, and no
//!   plaintext ever lives in the parent process. Used for keyring-mode hosts.
//! - [`ASKPASS_FILE_ENV`] — read the password from a 0600 temp file written by
//!   the parent. Used for plaintext/vault-mode hosts (the parent decrypted it).

use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::SshrackError;
use crate::secret::keyring;

/// Environment variable carrying the path to the 0600 password file written
/// by the parent sshrack process (`connect`) for the plaintext/vault path.
pub const ASKPASS_FILE_ENV: &str = "SSHRACK_ASKPASS_FILE";

/// Read the password from `path` (a 0600 file written by the parent), then
/// best-effort delete the file so the plaintext does not outlive the
/// handshake. The parent also deletes it after the child exits; this is
/// defense in depth.
pub fn materialize(path: &Path) -> Result<Zeroizing<String>, SshrackError> {
    let bytes = std::fs::read(path).map_err(|source| SshrackError::AskpassRead {
        path: path.to_path_buf(),
        source,
    })?;
    // Best-effort: ignore the rare race where the parent already removed it.
    let _ = std::fs::remove_file(path);
    let s = String::from_utf8(bytes).map_err(|_e| SshrackError::AskpassEncoding)?;
    Ok(Zeroizing::new(s))
}

/// Askpass role entry point. Branches on which env the parent set:
///
/// - [`keyring::KEYRING_KEY_ENV`] set → fetch via [`keyring::get`]; error
///   [`SshrackError::KeyringNoEntry`] when the entry is absent.
/// - otherwise → read the password file named by [`ASKPASS_FILE_ENV`].
///
/// In both cases the password is written to stdout (where ssh reads it) and
/// flushed before returning.
pub fn run() -> Result<(), SshrackError> {
    if let Some(key) = std::env::var_os(keyring::KEYRING_KEY_ENV) {
        let key = key.to_string_lossy();
        let pw = keyring::get(&key)?.ok_or_else(|| SshrackError::KeyringNoEntry {
            key: key.into_owned(),
        })?;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(pw.as_bytes()).map_err(SshrackError::from)?;
        lock.flush().map_err(SshrackError::from)?;
        return Ok(());
    }
    let path = std::env::var_os(ASKPASS_FILE_ENV).ok_or(SshrackError::AskpassNoFile {
        env: ASKPASS_FILE_ENV,
    })?;
    let pw = materialize(&PathBuf::from(path))?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(pw.as_bytes()).map_err(SshrackError::from)?;
    lock.flush().map_err(SshrackError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(contents: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sshrack-askpass-test-{}-{}.pw",
            std::process::id(),
            contents.len(), // stable-ish unique suffix without rand
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    fn write_tmp_bytes(contents: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "sshrack-askpass-test-{}-{}.pw",
            std::process::id(),
            contents.len(),
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        f.write_all(contents).unwrap();
        path
    }

    #[test]
    fn materialize_reads_password() {
        let path = write_tmp("hunter2");
        let pw = materialize(&path).unwrap();
        assert_eq!(pw.as_str(), "hunter2");
        // materialize deletes the file best-effort.
        assert!(!path.exists(), "password file should be deleted after read");
    }

    #[test]
    fn materialize_missing_file_is_error() {
        let path = std::env::temp_dir().join("sshrack-askpass-nonexistent.pw");
        let _ = std::fs::remove_file(&path);
        let err = materialize(&path).unwrap_err();
        assert!(matches!(err, SshrackError::AskpassRead { .. }));
    }

    #[test]
    fn materialize_rejects_non_utf8() {
        // 0xff 0xfe is not valid UTF-8 in any continuation pattern.
        let path = write_tmp_bytes(&[0xff, 0xfe]);
        let err = materialize(&path).unwrap_err();
        assert!(matches!(err, SshrackError::AskpassEncoding));
        let _ = std::fs::remove_file(&path);
    }
}
