//! Shared per-directory cursor-memory restore for directory browsers.
//!
//! Both the form file picker (`file_picker::FilePicker::load`) and the SFTP
//! transfer `Pane` remember, per visited directory, which entry was selected
//! when the user left it (ranger-style directory history). The restore step —
//! locate the remembered entry path in the current ranked view — is identical
//! pure logic, so it lives here once. The snapshot step is a one-line insert
//! each caller does inline (it knows its own `cwd` + `selected_entry`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sshrack_core::dirsource::DirEntry;

/// Return the ranked-list index of the entry `history` remembers for `cwd`,
/// or `0` when nothing is remembered or the remembered path is no longer in
/// the listing. Pure.
///
/// - `history`: visited-cwd → that dir's last-selected entry path.
/// - `ranked`: indices into `entries`, fuzzy-ordered for display (the cursor
///   indexes `ranked`, not `entries`).
/// - `entries`: the current listing the ranked indices point into.
///
/// Reachability: `file_picker::FilePicker::load` + `transfer::Pane::set_entries`.
#[must_use]
pub(crate) fn remembered_cursor_index(
    history: &HashMap<PathBuf, PathBuf>,
    cwd: &Path,
    ranked: &[usize],
    entries: &[DirEntry],
) -> usize {
    history
        .get(cwd)
        .and_then(|p| {
            ranked
                .iter()
                .position(|&i| entries.get(i).is_some_and(|e| &e.path == p))
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::dirsource::DirEntry;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn entry(name: &str, path: &str, is_dir: bool) -> DirEntry {
        DirEntry {
            name: name.into(),
            path: PathBuf::from(path),
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    #[test]
    fn empty_history_returns_zero() {
        let history = HashMap::new();
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0, 1], &entries),
            0
        );
    }

    #[test]
    fn remembered_path_present_returns_its_ranked_index() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/b"));
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0, 1], &entries),
            1
        );
    }

    #[test]
    fn ranked_reorder_is_respected() {
        // dirs-first decoration may rank b before a; the restore follows the
        // ranked order, not the entries order.
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/a"));
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[1, 0], &entries),
            1
        );
    }

    #[test]
    fn remembered_path_missing_falls_back_to_zero() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/gone"));
        let entries = vec![entry("a/", "/x/a", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0], &entries),
            0
        );
    }

    #[test]
    fn cwd_not_in_history_returns_zero() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/other"), PathBuf::from("/other/a"));
        let entries = vec![entry("a/", "/x/a", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0], &entries),
            0
        );
    }
}
