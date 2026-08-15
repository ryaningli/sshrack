//! The askpass role: ssh forks this binary (via `$SSH_ASKPASS`) to hand over
//! a password. We ignore ssh's prompt argument and emit the password for the
//! host sshrack is connecting to. There are three delivery modes, selected by
//! which environment variable the parent sshrack process set in
//! [`crate::connect::launch`]:
//!
//! - [`HOST_ID_ENV`] — plaintext storage mode: the password already lives at
//!   0600 in `config.toml`, so the parent sets `SSHRACK_HOST_ID` (plus optional
//!   [`CONFIG_ENV`] when a `--config` override is in play) and the helper reads
//!   the password straight back from the config via [`run_config`]. No temp
//!   file, no new exposure.
//! - [`KEYRING_KEY_ENV`][crate::secret::keyring::KEYRING_KEY_ENV] — fetch the password
//!   from the OS keyring via [`crate::secret::keyring::get`]. No temp file, and no
//!   plaintext ever lives in the parent process. Used for keyring-mode hosts.
//! - [`ASKPASS_FILE_ENV`] — read the password from a 0600 temp file written by
//!   the parent. Used for vault-mode hosts (the parent decrypted it; the vault
//!   master key never reaches the helper).

use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::SshrackError;
use crate::secret::keyring;

/// Environment variable carrying the path to the 0600 password file written
/// by the parent sshrack process (`connect`) for the vault path.
pub const ASKPASS_FILE_ENV: &str = "SSHRACK_ASKPASS_FILE";

/// Env var carrying the host ULID whose plaintext password the helper must
/// supply (plaintext storage mode — the password is read from the config, not
/// a temp file, so plaintext mode writes no askpass temp file at all). The
/// parent sets this in [`PasswordSource::Config`][crate::credential::PasswordSource::Config]
/// via [`crate::connect::askpass_env_for`].
pub const HOST_ID_ENV: &str = "SSHRACK_HOST_ID";

/// Env var naming the config file the helper must read in plaintext mode.
/// Optional: when unset the helper falls back to the XDG default
/// ([`crate::config::path::default_config_path`]), so the common case needs no
/// extra wiring. The connect layer sets it when a `--config` override is in
/// play so the helper always reads the same file the parent loaded.
pub const CONFIG_ENV: &str = "SSHRACK_CONFIG";

/// Env var set by the SFTP launcher when the master must NEVER fall back to
/// `/dev/tty`. The helper sees it, prints a fixed error, and exits non-zero so
/// ssh treats the auth as failed (no `/dev/tty` prompt, because the master also
/// sets `SSH_ASKPASS_REQUIRE=force`). Used for SFTP hosts whose resolved
/// password source is `None` — there is no payload to deliver, and the TUI
/// still owns the terminal the master would otherwise prompt on.
pub const ASKPASS_DENY_ENV: &str = "SSHRACK_ASKPASS_DENY";

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

/// Read the host's plaintext password from `config_path` and write it to `out`
/// (ssh reads the helper's stdout). Used in plaintext storage mode, where the
/// password already lives at 0600 in the config and the parent pointed the
/// helper at the host via [`HOST_ID_ENV`] (no temp file).
///
/// Pure except for the single config read; no env access, so it is hermetic
/// and unit-testable (tests inject a [`tempfile`] path and a `&mut Vec<u8>`).
/// [`run`] is the thin shell that reads the env, locks stdout, and delegates
/// here.
pub fn run_config<W: Write>(
    config_path: &Path,
    host_id: &str,
    out: &mut W,
) -> Result<(), SshrackError> {
    let cfg = crate::config::store::load(config_path)?;
    let ulid = ulid::Ulid::from_string(host_id).map_err(|_| SshrackError::AskpassBadHostId {
        raw: host_id.into(),
    })?;
    let host = cfg
        .find_host_by_id(&ulid)
        .ok_or_else(|| SshrackError::AskpassHostMissing { id: host_id.into() })?;
    let pw = crate::credential::plaintext_password(host, &cfg)
        .ok_or(SshrackError::AskpassNoPlaintextPassword { id: host_id.into() })?;
    out.write_all(pw.as_bytes()).map_err(SshrackError::from)?;
    out.flush().map_err(SshrackError::from)?;
    Ok(())
}

/// Askpass role entry point. Branches on which env the parent set:
///
/// - [`HOST_ID_ENV`] set → read the password from the config ([`run_config`]).
///   `CONFIG_ENV` overrides the config path; otherwise the XDG default is used.
/// - [`keyring::KEYRING_KEY_ENV`] set → fetch via [`keyring::get`]; error
///   [`SshrackError::KeyringNoEntry`] when the entry is absent.
/// - otherwise → read the password file named by [`ASKPASS_FILE_ENV`].
///
/// In every case the password is written to stdout (where ssh reads it) and
/// flushed before returning.
pub fn run() -> Result<(), SshrackError> {
    // SFTP deny: the TUI owns the tty; refuse to prompt. ssh reads this non-zero
    // exit as an auth failure — and because the master sets
    // SSH_ASKPASS_REQUIRE=force, ssh never falls back to /dev/tty. Nothing is
    // written to stdout (no secret, no empty password).
    if std::env::var_os(ASKPASS_DENY_ENV).is_some() {
        eprintln!("sshrack: no password configured for this SFTP session");
        return Err(SshrackError::AskpassDenied);
    }
    if let Some(host_id) = std::env::var_os(HOST_ID_ENV) {
        let host_id = host_id.to_string_lossy();
        let config_path = std::env::var_os(CONFIG_ENV)
            .map(PathBuf::from)
            .or_else(crate::config::path::default_config_path)
            .ok_or(SshrackError::AskpassNoConfigPath)?;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        return run_config(&config_path, &host_id, &mut lock);
    }
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

    // ---- run_config: the plaintext-mode config channel (pure-ish) ----

    /// Build a single-host config (inline plaintext password) and write it to a
    /// temp path. Returns the path + the host's ULID string so tests can hand
    /// them straight to [`run_config`].
    fn write_config_with_inline_password(
        password: &str,
    ) -> (std::path::PathBuf, String, tempfile::TempDir) {
        use crate::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
        use crate::config::store;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let host_id = ulid::Ulid::new();
        let host = Host {
            id: host_id,
            name: "h".into(),
            host: "x".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("u").with_password(password)),
        };
        let cfg = SshrackConfig {
            hosts: vec![host],
            ..Default::default()
        };
        store::save(&path, &cfg).unwrap();
        (path, host_id.to_string(), dir)
    }

    #[test]
    fn run_config_reads_plaintext_password_from_config() {
        let (path, host_id, _dir) = write_config_with_inline_password("s3cret");
        let mut out = Vec::new();
        run_config(&path, &host_id, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "s3cret");
    }

    #[test]
    fn run_config_errors_when_host_missing() {
        // A valid ULID not present in the config → AskpassHostMissing (no panic).
        use crate::config::schema::SshrackConfig;
        use crate::config::store;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        store::save(&path, &SshrackConfig::default()).unwrap();
        let other = ulid::Ulid::new().to_string();
        let mut out = Vec::new();
        let err = run_config(&path, &other, &mut out).unwrap_err();
        assert!(
            matches!(err, SshrackError::AskpassHostMissing { .. }),
            "expected AskpassHostMissing, got {err:?}"
        );
    }

    #[test]
    fn run_config_errors_when_host_has_no_plaintext_password() {
        // A key-only host has no password → AskpassNoPlaintextPassword.
        use crate::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
        use crate::config::store;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let host_id = ulid::Ulid::new();
        let host = Host {
            id: host_id,
            name: "h".into(),
            host: "x".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::inline(CredentialBody::new("u").with_key("/k")),
        };
        let cfg = SshrackConfig {
            hosts: vec![host],
            ..Default::default()
        };
        store::save(&path, &cfg).unwrap();
        let mut out = Vec::new();
        let err = run_config(&path, &host_id.to_string(), &mut out).unwrap_err();
        assert!(
            matches!(err, SshrackError::AskpassNoPlaintextPassword { .. }),
            "expected AskpassNoPlaintextPassword, got {err:?}"
        );
    }

    #[test]
    fn run_config_errors_on_malformed_host_id() {
        // A non-ULID host_id → AskpassBadHostId (no panic, no config look-up).
        let (path, _host_id, _dir) = write_config_with_inline_password("s3cret");
        let mut out = Vec::new();
        let err = run_config(&path, "not-a-ulid", &mut out).unwrap_err();
        assert!(
            matches!(err, SshrackError::AskpassBadHostId { .. }),
            "expected AskpassBadHostId, got {err:?}"
        );
    }

    #[test]
    fn run_config_reads_referenced_credential_password() {
        // A host auth = Ref { credential } pointing at a cred whose body has a
        // plaintext password resolves through the credential table.
        use crate::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
        use crate::config::store;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let host_id = ulid::Ulid::new();
        let cid = ulid::Ulid::new();
        let host = Host {
            id: host_id,
            name: "h".into(),
            host: "x".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::reference(cid),
        };
        let cfg = SshrackConfig {
            hosts: vec![host],
            credentials: vec![Credential {
                id: cid,
                name: "team".into(),
                body: CredentialBody::new("deploy").with_password("team-pw"),
            }],
            ..Default::default()
        };
        store::save(&path, &cfg).unwrap();
        let mut out = Vec::new();
        run_config(&path, &host_id.to_string(), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "team-pw");
    }
}
