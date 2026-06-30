//! Resolution of the config file location (XDG default + `--config` override)
//! and the machine-local data directory.

use std::path::{Path, PathBuf};

/// Compute the default config path under the user's XDG config dir.
///
/// Returns `None` if the user's home/config directory cannot be determined.
pub fn default_config_path() -> Option<PathBuf> {
    let proj = directories::ProjectDirs::from("dev", "sshrack", "sshrack")?;
    // directories::ProjectDirs::config_dir() -> Linux: ~/.config/sshrack
    Some(proj.config_dir().join("config.toml"))
}

/// The default data directory (XDG data dir / sshrack), for machine-local
/// state such as frecency. Created lazily by callers.
pub fn default_data_dir() -> Option<PathBuf> {
    let proj = directories::ProjectDirs::from("dev", "sshrack", "sshrack")?;
    Some(proj.data_dir().to_path_buf())
}

/// Resolve the effective config path: an explicit override wins, else the XDG default.
pub fn resolve(override_path: Option<&Path>) -> Option<PathBuf> {
    override_path
        .map(|p| p.to_path_buf())
        .or_else(default_config_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_over_default() {
        let override_path = Path::new("/tmp/custom.toml");
        let resolved = resolve(Some(override_path));
        assert_eq!(resolved.as_deref(), Some(Path::new("/tmp/custom.toml")));
    }

    #[test]
    fn default_is_under_config_dir() {
        // We cannot assert the exact path (depends on HOME), but it must end
        // with sshrack/config.toml.
        if let Some(p) = default_config_path() {
            assert!(p.ends_with("sshrack/config.toml"));
        }
    }

    #[test]
    fn default_data_dir_is_under_sshrack() {
        // We cannot assert the exact path (depends on HOME), but it must end
        // with sshrack (the data dir itself, not a file inside it).
        if let Some(p) = default_data_dir() {
            assert!(p.ends_with("sshrack"));
        }
    }

    #[test]
    fn resolve_none_falls_back_to_default() {
        // Either both are None (no home dir) or both are Some and equal.
        let resolved = resolve(None);
        let default = default_config_path();
        assert_eq!(resolved, default);
    }
}
