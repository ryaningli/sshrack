//! Loading and saving [`SshrackConfig`] from/to TOML files.

use std::path::Path;

use crate::config::schema::SshrackConfig;
use crate::error::SshrackError;

/// Load config from `path`. A missing file is treated as an empty config
/// (so a fresh install works without a config file).
pub fn load(path: &Path) -> Result<SshrackConfig, SshrackError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents).map_err(|source| SshrackError::ConfigParse {
            path: path.to_path_buf(),
            source,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SshrackConfig::default()),
        Err(source) => Err(SshrackError::ConfigRead {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Serialize `cfg` to TOML and write it to `path` atomically with owner-only
/// permissions. Parent directories are created on demand. Writes go to a
/// sibling temp file, mode 0600 is set on Unix, then the temp file is
/// `rename`d over the target so a crash mid-write cannot corrupt the config.
pub fn save(path: &Path, cfg: &SshrackConfig) -> Result<(), SshrackError> {
    let serialized =
        toml::to_string_pretty(cfg).map_err(|source| SshrackError::ConfigSerialize {
            path: path.to_path_buf(),
            source,
        })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SshrackError::ConfigWrite {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    crate::fsutil::atomic_write_private(path, serialized.as_bytes()).map_err(|source| {
        SshrackError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, CredentialBody, Host};
    use tempfile::NamedTempFile;

    #[test]
    fn missing_file_returns_empty_config() {
        let path = Path::new("/nonexistent/sshrack/nope.toml");
        let cfg = load(path).unwrap();
        assert!(cfg.hosts.is_empty());
    }

    #[test]
    fn save_then_load_round_trip() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: crate::id::new_id(),
                alias: "round".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u").with_password("pw")),
            }],
            credentials: vec![],
            ..Default::default()
        };
        save(tmp.path(), &cfg).unwrap();
        let back = load(tmp.path()).unwrap();
        assert_eq!(back.hosts.len(), 1);
        assert_eq!(back.hosts[0].alias, "round");
        assert_eq!(
            back.hosts[0].auth.inline_body().unwrap().password_plain(),
            Some("pw")
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        // Use a fresh path inside a tempdir: NamedTempFile::new() itself
        // creates a 0600 file, which would mask a `save` that merely honored
        // umask. A non-preexisting path forces `save` to create the file, so
        // the test only passes when `save` explicitly sets 0600.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: crate::id::new_id(),
                alias: "x".into(),
                host: "h".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u").with_password("secret")),
            }],
            ..SshrackConfig::default()
        };
        save(&path, &cfg).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "config with a password must be 0600");
    }

    #[test]
    fn save_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig::default();
        save(&path, &cfg).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "only the target file should remain");
        assert_eq!(leftovers[0].to_string_lossy(), "config.toml");
    }
}
