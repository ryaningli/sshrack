//! Connection: ssh/scp argv assembly and the zero-copy launcher.
//!
//! The launcher itself (spawn + inherited stdio + askpass env wiring) is added
//! in Task 11.

pub mod scp;
pub mod sftp;
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
/// For `Inline` and `Keyring` the `SSH_ASKPASS` triplet is set so ssh forks the
/// helper, plus the payload env (`SSHRACK_ASKPASS_FILE` vs `SSHRACK_KEYRING_KEY`)
/// that tells the helper which branch to take. For [`PasswordSource::None`] no
/// env is set at all: a key-only connection has no account password to inject,
/// and leaving askpass unset lets ssh prompt at `/dev/tty` for an encrypted
/// private key's passphrase instead of calling this payload-less helper.
pub fn askpass_env_for(
    self_exe: &Path,
    source: &PasswordSource,
    pw_file: Option<&Path>,
) -> Vec<(&'static str, String)> {
    // Key-only / default-auth connection: nothing to inject. Leaving askpass
    // unset lets ssh prompt at /dev/tty for an encrypted key's passphrase
    // (otherwise ssh would call this payload-less helper and fail).
    if matches!(source, PasswordSource::None) {
        return Vec::new();
    }
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
pub fn write_password_file(pw: &Zeroizing<String>) -> Result<PathBuf, SshrackError> {
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

/// Temp files holding a pasted identity key, written so `ssh -i` can read them.
/// `Drop` best-effort deletes both files so the plaintext does not outlive the
/// ssh process. The private key is `0600`; the certificate sits beside it as
/// `<private>-cert.pub` (the OpenSSH auto-load convention). The paths embed the
/// pid + nanos so concurrent connections never collide.
///
/// Built by the connect orchestration from [`crate::credential::InlineKeyMaterial`]
/// when a host's key source is inline (pasted). The caller fills
/// [`crate::credential::ResolvedAuth::key_path`] with [`KeyArtifact::private_path`]
/// so argv assembly points `ssh -i` at the temp file, then holds the artifact
/// across `launch` so `Drop` runs only after ssh exits.
///
/// `Debug` surfaces the temp file paths (filesystem locations, not key text);
/// the key material itself lives only in the file, never on this struct.
pub struct KeyArtifact {
    private: PathBuf,
    cert: Option<PathBuf>,
}

impl std::fmt::Debug for KeyArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyArtifact")
            .field("private", &self.private)
            .field("cert", &self.cert)
            .finish()
    }
}

impl KeyArtifact {
    /// Write `private` (and an optional `certificate`) to fresh `0600` temp
    /// files in the std temp dir. Returns the artifact; dropping it removes the
    /// files. The private path is what the caller passes to `ssh -i`.
    pub fn write(
        private: &Zeroizing<String>,
        certificate: Option<&Zeroizing<String>>,
    ) -> Result<Self, SshrackError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let private_path =
            std::env::temp_dir().join(format!("sshrack-key-{}-{}.pem", std::process::id(), nanos,));
        let private_err = |source: std::io::Error| SshrackError::AskpassWrite {
            path: private_path.clone(),
            source,
        };
        // Atomic create_new + 0600: no window where the file exists with
        // umask-permitted perms, and no clobbering an existing file.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&private_path)
            .map_err(private_err)?;
        f.write_all(private.as_bytes()).map_err(|e| {
            // Best-effort cleanup so a partial private file never survives.
            let _ = std::fs::remove_file(&private_path);
            private_err(e)
        })?;

        // Certificate, if any: write beside the private key as <name>-cert.pub
        // so `ssh -i <private>` auto-loads it. Same 0600 perms — the cert is
        // sensitive (it identifies the holder) even though it is public-signed.
        let cert_path = if let Some(cert) = certificate {
            let cert_name = private_path
                .file_name()
                .map(std::ffi::OsStr::to_string_lossy)
                .map(|s| format!("{s}-cert.pub"))
                .unwrap_or_else(|| "sshrack-key-cert.pub".to_string());
            let cp = private_path.with_file_name(cert_name);
            let cert_err = |source: std::io::Error| SshrackError::AskpassWrite {
                path: cp.clone(),
                source,
            };
            let mut cf = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&cp)
                .map_err(|e| {
                    // Roll back the private file so a cert-open failure does not
                    // leave an orphaned private key on disk.
                    let _ = std::fs::remove_file(&private_path);
                    SshrackError::AskpassWrite {
                        path: cp.clone(),
                        source: e,
                    }
                })?;
            cf.write_all(cert.as_bytes()).map_err(|e| {
                let _ = std::fs::remove_file(&private_path);
                let _ = std::fs::remove_file(&cp);
                cert_err(e)
            })?;
            Some(cp)
        } else {
            None
        };

        Ok(Self {
            private: private_path,
            cert: cert_path,
        })
    }

    /// The path to pass to `ssh -i`. The certificate (if any) lives beside it
    /// as `<private>-cert.pub` and is auto-loaded by ssh.
    pub fn private_path(&self) -> &Path {
        &self.private
    }
}

impl Drop for KeyArtifact {
    fn drop(&mut self) {
        // Best-effort: a failed removal (e.g. tmp cleared mid-flight) is
        // swallowed so Drop never panics. Both files are wiped so neither the
        // private key nor the certificate outlives the connection.
        let _ = std::fs::remove_file(&self.private);
        if let Some(c) = &self.cert {
            let _ = std::fs::remove_file(c);
        }
    }
}

/// Materialize a resolved identity's inline key (if any) to a `0600` temp file
/// and point [`ResolvedAuth::key_path`] at it so argv assembly (`ssh -i`)
/// picks up the temp path. Returns the [`KeyArtifact`] whose `Drop` removes the
/// temp files — the caller MUST hold it across [`launch`] so the plaintext does
/// not outlive the ssh process.
///
/// No-op (returns `None`) when the resolved auth carries no inline material
/// (the path-key and no-key cases). Mutates `resolved` in place: takes
/// `inline_key` (so it cannot be materialized twice) and, when present, fills
/// `key_path` with the temp private path (overwriting any prior value — the
/// inline branch leaves `key_path` `None` on resolve, so there is no clobber).
///
/// Pure seam over [`KeyArtifact::write`]: no shared state, no argv mutation.
/// The caller still owns the resolved auth and the artifact's lifetime.
pub fn materialize_inline_key(
    resolved: &mut crate::credential::ResolvedAuth,
) -> Result<Option<KeyArtifact>, SshrackError> {
    let inline_key = resolved.inline_key.take();
    match inline_key {
        Some(mat) => {
            let artifact = KeyArtifact::write(&mat.private, mat.certificate.as_ref())?;
            resolved.key_path = Some(artifact.private_path().to_path_buf());
            Ok(Some(artifact))
        }
        None => Ok(None),
    }
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
    fn env_for_none_sets_no_askpass_so_ssh_asks_passphrase_at_tty() {
        // A key-only (or default) connection has no account password to inject, so
        // ssh must NOT be pointed at our askpass helper: if the private key is
        // encrypted, ssh would call askpass (which has no payload for a key-only
        // connection) and fail. Leaving SSH_ASKPASS unset lets ssh fall back to
        // /dev/tty and prompt the user for the key passphrase itself.
        let env = env_for(&PasswordSource::None);
        assert!(
            env.is_empty(),
            "key-only connections set no askpass env, got {env:?}"
        );
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

    // ---- Task 3: KeyArtifact materialization for inline identity keys ----

    #[test]
    fn key_artifact_writes_private_and_cert_siblings_then_cleanup_removes_both() {
        // ssh -i <private> auto-loads <private>-cert.pub, so the cert must sit
        // beside the private key with that exact suffix. Drop must remove both
        // temp files so the plaintext does not outlive the connection.
        use std::cell::RefCell;
        let priv_text = Zeroizing::new("PRIVATE-KEY-TEXT".into());
        let cert_text = Zeroizing::new("CERTIFICATE-TEXT".into());
        let paths: RefCell<Vec<std::path::PathBuf>> = RefCell::new(vec![]);
        {
            let a = KeyArtifact::write(&priv_text, Some(&cert_text)).unwrap();
            let p = a.private_path().to_path_buf();
            assert!(p.exists(), "private key temp file must exist at {p:?}");
            let cert_sibling = p.with_file_name(format!(
                "{}-cert.pub",
                p.file_name()
                    .expect("invariant: temp path always has a file name")
                    .to_string_lossy()
            ));
            assert!(
                cert_sibling.exists(),
                "cert sibling must exist at {cert_sibling:?}"
            );
            *paths.borrow_mut() = vec![p, cert_sibling];
            // Files carry the material exactly.
            assert_eq!(
                std::fs::read_to_string(&paths.borrow()[0]).unwrap(),
                "PRIVATE-KEY-TEXT"
            );
            assert_eq!(
                std::fs::read_to_string(&paths.borrow()[1]).unwrap(),
                "CERTIFICATE-TEXT"
            );
        }
        // After Drop (scope exit), both temp files are gone.
        for p in paths.borrow().iter() {
            assert!(!p.exists(), "temp file {p:?} should be removed after drop");
        }
    }

    #[test]
    fn key_artifact_private_only_when_no_certificate() {
        // No certificate: only the private temp file is created, and Drop
        // removes just that one.
        let priv_text = Zeroizing::new("ONLY-KEY".into());
        let path = {
            let a = KeyArtifact::write(&priv_text, None).unwrap();
            a.private_path().to_path_buf()
        };
        assert!(
            !path.exists(),
            "private temp file should be removed after drop"
        );
    }

    #[test]
    fn key_artifact_private_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let priv_text = Zeroizing::new("K".into());
        let a = KeyArtifact::write(&priv_text, None).unwrap();
        let mode = std::fs::metadata(a.private_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ---- materialize_inline_key: the connect-side seam every launch site uses ----

    fn resolved_with_inline(private: &str, cert: Option<&str>) -> crate::credential::ResolvedAuth {
        use crate::credential::{InlineKeyMaterial, ResolvedAuth};
        ResolvedAuth {
            user: "u".into(),
            key_path: None,
            password: PasswordSource::None,
            inline_key: Some(InlineKeyMaterial {
                private: Zeroizing::new(private.into()),
                certificate: cert.map(|c| Zeroizing::new(c.into())),
            }),
        }
    }

    #[test]
    fn materialize_inline_key_writes_temp_and_fills_key_path() {
        // An inline-key body: materialize_inline_key must write the private key
        // to a 0600 temp file, fill key_path with that path, and return the
        // artifact (so the caller can hold it across launch). Drop of the
        // artifact removes the temp file.
        let mut resolved = resolved_with_inline("PRIVATE-MATERIAL", None);
        let path = {
            let _artifact = materialize_inline_key(&mut resolved).unwrap().unwrap();
            let p = resolved
                .key_path
                .as_deref()
                .expect("materialize fills key_path")
                .to_path_buf();
            assert!(
                p.exists(),
                "temp private key must exist at {p:?} while artifact is live"
            );
            assert_eq!(
                std::fs::read_to_string(&p).unwrap(),
                "PRIVATE-MATERIAL",
                "temp file must hold the private key text exactly"
            );
            p
        };
        // Drop removed the temp file (artifact released at the block end).
        assert!(
            !path.exists(),
            "temp private key must be removed after artifact drops"
        );
        // inline_key is taken — a second materialization is a no-op (returns None).
        let again = materialize_inline_key(&mut resolved).unwrap();
        assert!(again.is_none(), "inline_key must be taken on first call");
    }

    #[test]
    fn materialize_inline_key_writes_cert_sibling_alongside_private() {
        // With a certificate: the cert lands beside the private key as
        // <private>-cert.pub so ssh -i auto-loads it. Both temp files share the
        // artifact's lifetime.
        let mut resolved = resolved_with_inline("PRIV", Some("CERT-MATERIAL"));
        let artifact = materialize_inline_key(&mut resolved).unwrap().unwrap();
        let p = resolved.key_path.as_deref().unwrap().to_path_buf();
        let cert_sibling = p.with_file_name(format!(
            "{}-cert.pub",
            p.file_name()
                .expect("invariant: temp path has a file name")
                .to_string_lossy()
        ));
        assert!(
            cert_sibling.exists(),
            "cert sibling must exist at {cert_sibling:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&cert_sibling).unwrap(),
            "CERT-MATERIAL"
        );
        // Both files removed when the artifact drops.
        drop(artifact);
        assert!(!p.exists(), "private must be removed after artifact drops");
        assert!(
            !cert_sibling.exists(),
            "cert must be removed after artifact drops"
        );
    }

    #[test]
    fn materialize_inline_key_is_noop_for_path_key_body() {
        // A path-key (or no-key) body has inline_key = None: materialize must be
        // a no-op, returning None and leaving key_path untouched.
        use crate::credential::ResolvedAuth;
        let mut resolved = ResolvedAuth {
            user: "u".into(),
            key_path: Some(PathBuf::from("/home/u/.ssh/id_ed25519")),
            password: PasswordSource::None,
            inline_key: None,
        };
        let artifact = materialize_inline_key(&mut resolved).unwrap();
        assert!(artifact.is_none(), "no inline key → no artifact");
        assert_eq!(
            resolved.key_path,
            Some(PathBuf::from("/home/u/.ssh/id_ed25519")),
            "existing key_path must be preserved"
        );
    }
}
