//! Connection: ssh/scp argv assembly and the zero-copy launcher.
//!
//! The launcher itself (spawn + inherited stdio + askpass env wiring) is added
//! in Task 11.

pub mod scp;
pub mod ssh;

use std::path::{Path, PathBuf};
use std::process::Command;

use zeroize::Zeroizing;

use crate::askpass::ASKPASS_FILE_ENV;
use crate::credential::PasswordSource;
use crate::error::SshrackError;
use crate::secret::keyring::KEYRING_KEY_ENV;

/// Absolute path to this binary. `SSH_ASKPASS` must be absolute so older ssh
/// builds do not search PATH for it.
pub fn current_exe() -> Result<PathBuf, SshrackError> {
    std::env::current_exe().map_err(|source| SshrackError::SelfExe { source })
}

/// Assemble the environment that makes ssh call our askpass role.
///
/// Pure (no I/O) so the exact keys/values are unit-testable. `pw_file` is the
/// temp-file path for [`PasswordSource::Inline`] (the caller materializes it);
/// `None` for the keyring path (no temp file, no plaintext in this process) and
/// the none path (no askpass payload at all).
///
/// Always sets the `SSH_ASKPASS` triplet so ssh knows to fork the helper; the
/// payload env (`SSHRACK_ASKPASS_FILE` vs `SSHRACK_KEYRING_KEY`) is what tells
/// the helper which branch to take.
fn askpass_env_for(
    self_exe: &Path,
    source: &PasswordSource,
    pw_file: Option<&Path>,
) -> Vec<(&'static str, String)> {
    let mut env: Vec<(&'static str, String)> = vec![
        ("SSH_ASKPASS", self_exe.to_string_lossy().into_owned()),
        ("SSH_ASKPASS_REQUIRE", "force".to_string()),
        // Some older ssh builds only honor SSH_ASKPASS when DISPLAY is set.
        ("DISPLAY", ":0".to_string()),
    ];
    match source {
        PasswordSource::Inline(_) => {
            if let Some(p) = pw_file {
                env.push((ASKPASS_FILE_ENV, p.to_string_lossy().into_owned()));
            }
        }
        PasswordSource::Keyring { key } => {
            env.push((KEYRING_KEY_ENV, key.clone()));
        }
        PasswordSource::None => {}
    }
    env
}

/// Test seam over [`askpass_env_for`] with a fixed `self_exe` and no `pw_file`
/// (the keyring/none paths carry no file). Exposed so unit and integration
/// tests can assert the env shape for each [`PasswordSource`] variant without
/// touching I/O. Not used by production code paths.
pub fn env_for(source: &PasswordSource) -> Vec<(&'static str, String)> {
    let exe = Path::new("/sshrack");
    askpass_env_for(exe, source, None)
}

/// Write `pw` to a fresh 0600 temp file and return its path. The caller is
/// responsible for removing it after the child exits.
///
/// The path mixes the pid with a nanosecond timestamp so that repeated calls
/// within one process (e.g. concurrent tests, or future reconnect loops) do
/// not stomp on each other's file.
fn write_password_file(pw: &Zeroizing<String>) -> Result<PathBuf, SshrackError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "sshrack-askpass-{}-{}.pw",
        std::process::id(),
        nanos,
    ));
    let write_err = |source: std::io::Error| SshrackError::AskpassWrite {
        path: path.clone(),
        source,
    };
    // Atomic creation with mode 0600: there is never a window where the file
    // exists with default (umask-permitted) permissions. `create_new` also
    // defends against clobbering an existing file at the same path.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(write_err)?;
    f.write_all(pw.as_bytes()).map_err(|e| {
        // Best-effort cleanup: don't leave an orphaned/partial password file.
        let _ = std::fs::remove_file(&path);
        write_err(e)
    })?;
    Ok(path)
}

/// Run `argv` to completion. stdio is INHERITED — ssh talks straight to the
/// user's terminal; we are not in the data path. Password delivery depends on
/// `source` (see the [module docs](self)): `Inline` writes a 0600 temp file,
/// `Keyring` sets only `SSHRACK_KEYRING_KEY` (no temp file, no plaintext here),
/// `None` carries no askpass payload. Returns the child's exit code.
pub fn launch(
    argv: Vec<String>,
    source: PasswordSource,
    self_exe: &Path,
) -> Result<i32, SshrackError> {
    // Only Inline materializes a plaintext temp file. Keyring/None do not.
    let pw_file = match source {
        PasswordSource::Inline(ref p) => Some(write_password_file(p)?),
        _ => None,
    };

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in askpass_env_for(self_exe, &source, pw_file.as_deref()) {
        cmd.env(k, v);
    }

    let status = cmd.status().map_err(SshrackError::from)?;

    if let Some(p) = pw_file {
        // Defense in depth: the askpass role already deleted it on read.
        let _ = std::fs::remove_file(p);
    }
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_for_none_has_required_keys_and_no_secret_env() {
        // None (key/default-auth): SSH_ASKPASS triplet set, but neither the
        // askpass file nor the keyring key — ssh uses the key/agent and the
        // askpass role is never invoked.
        let env = env_for(&PasswordSource::None);
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map.get("SSH_ASKPASS").copied(), Some("/sshrack"));
        assert_eq!(map.get("SSH_ASKPASS_REQUIRE").copied(), Some("force"));
        assert_eq!(map.get("DISPLAY").copied(), Some(":0"));
        assert!(!map.contains_key(ASKPASS_FILE_ENV));
        assert!(!map.contains_key(KEYRING_KEY_ENV));
    }

    #[test]
    fn env_for_inline_includes_file_when_pw_file_given() {
        // Inline path: caller passes the temp-file path; env carries
        // SSHRACK_ASKPASS_FILE (and never the keyring key).
        let env = askpass_env_for(
            Path::new("/sshrack"),
            &PasswordSource::Inline(Zeroizing::new("x".into())),
            Some(Path::new("/tmp/x.pw")),
        );
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map.get(ASKPASS_FILE_ENV).copied(), Some("/tmp/x.pw"));
        assert!(!map.contains_key(KEYRING_KEY_ENV));
    }

    #[test]
    fn env_for_keyring_sets_keyring_env_not_file() {
        // Pure helper: given a keyring source, the env must carry KEYRING_KEY
        // and NOT SSHRACK_ASKPASS_FILE. No plaintext exists in this process.
        let env = env_for(&PasswordSource::Keyring {
            key: "host:web1".into(),
        });
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map.get(KEYRING_KEY_ENV).copied(), Some("host:web1"));
        assert!(!map.contains_key(ASKPASS_FILE_ENV));
    }

    #[test]
    fn env_for_inline_omits_file_when_pw_file_none() {
        // Defensive: an Inline source without a pw_file must not set the file
        // env (the caller failed to materialize the file). Normal callers always
        // pass Some for Inline; this just locks the contract.
        let env = askpass_env_for(
            Path::new("/sshrack"),
            &PasswordSource::Inline(Zeroizing::new("x".into())),
            None,
        );
        assert!(
            env.iter()
                .all(|(k, _)| *k != ASKPASS_FILE_ENV && *k != KEYRING_KEY_ENV)
        );
    }

    #[test]
    fn write_password_file_is_0600_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let pw = Zeroizing::new("s3cret".into());
        let path = write_password_file(&pw).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = std::fs::read_to_string(&path).unwrap();
        assert_eq!(back, "s3cret");
        let _ = std::fs::remove_file(&path);
    }
}
