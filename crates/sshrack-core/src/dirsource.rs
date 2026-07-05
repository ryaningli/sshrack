//! Directory-listing capability for the file picker, behind a trait so the
//! picker is testable without a filesystem and so a future `SftpDirSource`
//! (sshrack sftp) can reuse the whole `FilePicker` component unchanged. The
//! real listing (`std::fs::read_dir`, symlink-aware) lives in
//! [`LocalDirSource`]; tests use `tempdir` for it and a hand-written fake in
//! the TUI layer. Pure entry sorting is split into [`build_entries`] so it is
//! unit-testable with no fs.

use std::path::{Path, PathBuf};

use crate::pathutil::{ResolvedPath, expand_tilde};

/// Filesystem classification of one path. `Symlink` is reported independently
/// of whether its target is a dir or file (the picker annotates with `@`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symbolic link (target type resolved separately by the picker).
    Symlink,
    /// The path does not exist on the source.
    NotFound,
}

/// One row in the picker list. `name` carries a trailing `/` for directories
/// and `@` for symlinks (display-ready); `path` is the absolute path to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Display-ready name with a trailing `/` (dir) or `@` (symlink).
    pub name: String,
    /// Absolute filesystem path that this row points at.
    pub path: PathBuf,
    /// Whether the entry is a directory (follows symlinks).
    pub is_dir: bool,
    /// Whether the entry itself is a symbolic link.
    pub is_symlink: bool,
}

/// Directory-listing + path-classification capability. Implementations: real
/// local fs ([`LocalDirSource`]), fake (TUI tests), future sftp.
pub trait DirSource {
    /// List `cwd`'s entries, with a `../` entry prepended at index 0 when `cwd`
    /// has a parent. IO errors become `Err(message)`.
    fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String>;
    /// Classify a single path (dir / file / symlink / not-found). Used by
    /// [`Self::resolve`] and by the picker's start-directory probe.
    fn classify(&self, path: &Path) -> PathKind;
    /// The user's home directory, if known. `None` disables `~`-expansion.
    fn home(&self) -> Option<PathBuf>;
    /// Resolve a path-like filter string against `cwd` (`~`-expanded). Pure-ish:
    /// touches fs via [`Self::classify`].
    fn resolve(&self, raw: &str, cwd: &Path) -> ResolvedPath {
        let home = self.home();
        let abs = match raw {
            s if s.starts_with('~') => home
                .as_ref()
                .map(|h| expand_tilde(s, h))
                .unwrap_or_else(|| PathBuf::from(s)),
            s if Path::new(s).is_absolute() => PathBuf::from(s),
            s => cwd.join(s),
        };
        match self.classify(&abs) {
            PathKind::Dir | PathKind::Symlink => {
                // A symlink may point at a dir; treat Symlink as selectable but
                // let the picker step into it on Enter (re-list resolves it).
                ResolvedPath::Dir(abs)
            }
            PathKind::File => ResolvedPath::File(abs),
            PathKind::NotFound => ResolvedPath::NotFound,
        }
    }
    /// Pick the first candidate (a literal, possibly `~`-bearing string) that
    /// resolves to an existing directory. Returns the absolute PathBuf, or `None`
    /// when nothing resolves (the picker falls back to `/`). Default uses
    /// [`Self::classify`].
    fn resolve_start(&self, candidates: &[String]) -> Option<PathBuf> {
        let home = self.home();
        for c in candidates {
            let p = if c.starts_with('~') {
                home.as_ref().map(|h| expand_tilde(c, h))
            } else {
                Some(PathBuf::from(c))
            };
            if let Some(p) = p {
                if matches!(self.classify(&p), PathKind::Dir) {
                    return Some(p);
                }
            }
        }
        None
    }
}

/// Local filesystem listing. Zero state — all work goes through `std::fs`.
#[derive(Debug, Clone, Default)]
pub struct LocalDirSource;

impl LocalDirSource {
    /// Construct a `LocalDirSource` (zero state).
    pub fn new() -> Self {
        Self
    }
}

impl DirSource for LocalDirSource {
    fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
        let rd = std::fs::read_dir(cwd).map_err(|e| format!("{cwd:?}: {e}"))?;
        let mut items: Vec<(String, PathBuf, bool, bool)> = Vec::new();
        for entry in rd.flatten() {
            let path = entry.path();
            let lmeta = std::fs::symlink_metadata(&path).ok();
            let fameta = std::fs::metadata(&path).ok();
            let is_symlink = lmeta
                .as_ref()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            let is_dir = fameta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let raw_name = entry.file_name().to_string_lossy().into_owned();
            items.push((raw_name, path, is_dir, is_symlink));
        }
        let mut entries = build_entries(items);
        // Prepend `../` when cwd has a parent so the user can always step up.
        if cwd.parent().is_some() {
            entries.insert(
                0,
                DirEntry {
                    name: "../".into(),
                    path: cwd.parent().unwrap_or(cwd).to_path_buf(),
                    is_dir: true,
                    is_symlink: false,
                },
            );
        }
        Ok(entries)
    }

    fn classify(&self, path: &Path) -> PathKind {
        let lmeta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => return PathKind::NotFound,
        };
        if lmeta.file_type().is_symlink() {
            return PathKind::Symlink;
        }
        if lmeta.is_dir() {
            PathKind::Dir
        } else {
            PathKind::File
        }
    }

    fn home(&self) -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

/// Decorate a raw entry name: dirs get a trailing `/`, symlinks a trailing
/// `@` (a symlink-to-dir gets `/`). Pure.
fn decorate(raw: &str, is_dir: bool, is_symlink: bool) -> String {
    if is_dir {
        format!("{raw}/")
    } else if is_symlink {
        format!("{raw}@")
    } else {
        raw.to_string()
    }
}

/// Sort raw `(name, path, is_dir, is_symlink)` items into display order:
/// directories first, then files; within each group, case-insensitive name asc.
/// Names are decorated on the way out (dirs get a trailing `/`, symlinks `@`).
/// Pure (no fs, no cwd knowledge). `LocalDirSource::list` calls this and then
/// prepends the `../` row.
pub(crate) fn build_entries(items: Vec<(String, PathBuf, bool, bool)>) -> Vec<DirEntry> {
    let mut items = items;
    items.sort_by(|a, b| {
        b.2.cmp(&a.2) // is_dir: true (1) before false (0)
            .then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase()))
    });
    items
        .into_iter()
        .map(|(raw_name, path, is_dir, is_symlink)| DirEntry {
            name: decorate(&raw_name, is_dir, is_symlink),
            path,
            is_dir,
            is_symlink,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn build_entries_dirs_first_then_files_case_insensitive() {
        let items = vec![
            (
                "zfile.txt".into(),
                PathBuf::from("/d/zfile.txt"),
                false,
                false,
            ),
            ("Adir".into(), PathBuf::from("/d/Adir"), true, false),
            (
                "afile.txt".into(),
                PathBuf::from("/d/afile.txt"),
                false,
                false,
            ),
            ("Bdir".into(), PathBuf::from("/d/Bdir"), true, false),
        ];
        let e = build_entries(items);
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["Adir/", "Bdir/", "afile.txt", "zfile.txt"]);
    }

    #[test]
    fn build_entries_empty_is_empty() {
        assert!(build_entries(Vec::new()).is_empty());
    }

    #[test]
    fn local_list_prepends_parent_and_decorates() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(
            root.join("id_ed25519"),
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        std::fs::write(root.join("readme.txt"), b"hi").unwrap();
        let entries = LocalDirSource::new().list(root).unwrap();
        assert_eq!(entries[0].name, "../");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"sub/"));
        assert!(names.contains(&"id_ed25519"));
        assert!(names.contains(&"readme.txt"));
        let sub_i = names.iter().position(|n| *n == "sub/").unwrap();
        let id_i = names.iter().position(|n| *n == "id_ed25519").unwrap();
        assert!(sub_i < id_i);
    }

    #[test]
    fn local_list_shows_hidden_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".hidden"), b"x").unwrap();
        let entries = LocalDirSource::new().list(tmp.path()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&".hidden"),
            "hidden file must be shown: {names:?}"
        );
    }

    #[test]
    fn local_classify_dir_file_symlink_notfound() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        let file = tmp.path().join("f");
        let link = tmp.path().join("l");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let s = LocalDirSource::new();
        assert_eq!(s.classify(&dir), PathKind::Dir);
        assert_eq!(s.classify(&file), PathKind::File);
        #[cfg(unix)]
        assert_eq!(s.classify(&link), PathKind::Symlink);
        assert_eq!(s.classify(&tmp.path().join("nope")), PathKind::NotFound);
    }

    #[test]
    fn local_list_io_error_is_err_string() {
        let s = LocalDirSource::new();
        assert!(s.list(Path::new("/definitely/not/here/xyz")).is_err());
    }

    #[test]
    fn resolve_relative_file_against_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("key.pem");
        std::fs::write(&f, b"x").unwrap();
        struct L(LocalDirSource);
        impl DirSource for L {
            fn list(&self, _: &Path) -> Result<Vec<DirEntry>, String> {
                self.0.list(Path::new("/"))
            }
            fn classify(&self, p: &Path) -> PathKind {
                self.0.classify(p)
            }
            fn home(&self) -> Option<PathBuf> {
                self.0.home()
            }
        }
        let s = L(LocalDirSource::new());
        assert_eq!(s.resolve("key.pem", tmp.path()), ResolvedPath::File(f));
    }

    #[test]
    fn resolve_notfound_is_notfound() {
        let tmp = tempfile::tempdir().unwrap();
        let s = LocalDirSource::new();
        assert_eq!(s.resolve("nope", tmp.path()), ResolvedPath::NotFound);
    }

    #[test]
    fn resolve_start_picks_first_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let s = LocalDirSource::new();
        let cands = vec!["/no/such".to_string(), sub.to_string_lossy().into_owned()];
        assert_eq!(s.resolve_start(&cands), Some(sub));
    }

    #[test]
    fn resolve_start_none_when_all_missing() {
        let s = LocalDirSource::new();
        assert_eq!(
            s.resolve_start(&["/no/such/a".into(), "/no/such/b".into()]),
            None
        );
    }
}
