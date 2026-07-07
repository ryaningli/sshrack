//! Shared, business-decoupled directory-browser core. Both the modal
//! [`crate::tui::file_picker::FilePicker`] (single-select) and the SFTP
//! [`crate::tui::transfer::pane::Pane`] (dual-pane, multi-select) hold one
//! `BrowserCore` and delegate navigation, fuzzy filter, mark, and
//! per-directory cursor-memory logic to it. The core is pure — no I/O, no
//! rendering, no outcome type — so the two surfaces stay in sync by
//! construction and a behavior drift (like the Backspace-as-step-up vs
//! pure-edit split that once crept in) cannot recur.
//!
//! The two consumers' real differences are honored, not papered over:
//! - `FilePicker` owns its `DirSource` and lists synchronously; it switches
//!   atomically via [`BrowserCore::commit_switch`] (Task 2).
//! - `Pane` is a passive state machine fed by the transfer screen/worker; it
//!   switches in two phases around an async listing via
//!   [`BrowserCore::begin_switch`] + [`BrowserCore::finish_switch`] (Task 2).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use sshrack_core::dirsource::DirEntry;

/// Pure per-directory browser state: a cwd, its current listing, a fuzzy
/// filter query, a cursor, a per-directory mark set, and a per-directory
/// cursor memory. All methods are pure (no I/O, no rendering); the component
/// owns I/O (`DirSource`) and rendering.
///
/// Field visibility: every field is `pub(crate)` so the file picker, the
/// transfer pane, and their tests reach in directly — one source of truth,
/// no accessor boilerplate. The module itself is `pub(crate)`, so external
/// crates cannot see any of this.
///
/// Reachability: `Pane` consumes this in Task 3 and `FilePicker` in Task 4.
/// Until then no `main` call site reaches it, so `cargo clippy --all-targets`
/// (which lints the non-test binary target separately from the test target)
/// flags it dead. The scoped `#[allow(dead_code)]` below is removed in Task 4
/// once both consumers are wired (the Task-5 sweep verifies it is gone).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct BrowserCore {
    /// Absolute current directory.
    pub(crate) cwd: PathBuf,
    /// Current listing (real children only — dirs first, then files).
    pub(crate) entries: Vec<DirEntry>,
    /// Filter-box text. Drives fuzzy ranking via [`Self::recompute`].
    pub(crate) query: String,
    /// Indices into `entries`, fuzzy-ordered for display. Derived from
    /// `entries` + `query`.
    pub(crate) ranked: Vec<usize>,
    /// Cursor position: index into `ranked`.
    pub(crate) selected: usize,
    /// Marked paths in the CURRENT directory only. Cleared on a dir switch.
    /// Both files and directories can be marked.
    pub(crate) marked: HashSet<PathBuf>,
    /// Per-directory cursor memory (ranger-style): visited cwd → that dir's
    /// last-selected entry path.
    history: HashMap<PathBuf, PathBuf>,
    /// Set by `begin_switch` so the next `finish_switch` restores the NEW
    /// cwd's remembered cursor instead of resetting to 0. Separates a
    /// dir-switch from an in-place refresh.
    pending_restore: bool,
}

#[allow(dead_code)] // consumers land in Tasks 3–4; see the struct allow note.
impl BrowserCore {
    /// New core at `initial_cwd` with an empty listing. The component feeds
    /// the first listing via `commit_switch` / `finish_switch` (Task 2).
    #[must_use]
    pub(crate) fn new(initial_cwd: PathBuf) -> Self {
        Self {
            cwd: initial_cwd,
            entries: Vec::new(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            marked: HashSet::new(),
            history: HashMap::new(),
            pending_restore: false,
        }
    }

    /// Re-rank `entries` for the current `query` via the shared nucleo helper
    /// (one-field rows, all-zero scores). Empty query yields every entry in
    /// its sorted order. Pure.
    pub(crate) fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    /// Clamp the cursor into `ranked` bounds (no-op when empty). Pure.
    pub(crate) fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the cursor by `delta` with wrap-around. No-op when ranked empty.
    pub(crate) fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// The entry under the cursor, or `None` when the ranked list is empty.
    #[must_use]
    pub(crate) fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked
            .get(self.selected)
            .and_then(|&i| self.entries.get(i))
    }

    /// The entry at display position `ranked_idx`, or `None` when out of range.
    #[must_use]
    pub(crate) fn entry_at_rank(&self, ranked_idx: usize) -> Option<&DirEntry> {
        self.ranked
            .get(ranked_idx)
            .and_then(|&i| self.entries.get(i))
    }

    /// Number of entries surviving the filter (`ranked.len()`).
    #[must_use]
    pub(crate) fn matched_count(&self) -> usize {
        self.ranked.len()
    }

    /// Range of `ranked` indices to render for a viewport of `rows` rows.
    #[must_use]
    pub(crate) fn visible_window(&self, rows: usize) -> std::ops::Range<usize> {
        crate::tui::fit::focus_window(self.ranked.len(), self.selected, rows)
    }

    /// Toggle the mark on the cursor entry. Returns `Some(path)` when a mark
    /// changed, `None` when the cursor is empty. Mutates `marked`.
    pub(crate) fn toggle_mark_selected(&mut self) -> Option<PathBuf> {
        let entry = self.selected_entry()?;
        let path = entry.path.clone();
        if !self.marked.insert(path.clone()) {
            self.marked.remove(&path);
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn entry(name: &str, parent: &Path, is_dir: bool) -> DirEntry {
        let decorated = if is_dir {
            format!("{name}/")
        } else {
            name.to_string()
        };
        DirEntry {
            name: decorated,
            path: parent.join(name),
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    fn core_with(cwd: &str, names: &[(&str, bool)]) -> BrowserCore {
        let cwd = PathBuf::from(cwd);
        let entries: Vec<DirEntry> = names.iter().map(|(n, d)| entry(n, &cwd, *d)).collect();
        let mut c = BrowserCore::new(cwd);
        c.entries = entries;
        c.recompute();
        c
    }

    #[test]
    fn recompute_empty_query_keeps_all_in_entries_order() {
        let c = core_with("/x", &[("a", false), ("b", false)]);
        assert_eq!(c.matched_count(), 2);
        assert_eq!(c.entry_at_rank(0).map(|e| e.name.as_str()), Some("a"));
        assert_eq!(c.entry_at_rank(1).map(|e| e.name.as_str()), Some("b"));
    }

    #[test]
    fn recompute_query_filters_to_matches() {
        let mut c = core_with(
            "/x",
            &[("id_ed25519", false), ("id_rsa", false), ("notes", false)],
        );
        c.query = "id".to_string();
        c.recompute();
        assert_eq!(c.matched_count(), 2, "only the two id_* entries match");
    }

    #[test]
    fn move_cursor_wraps_around() {
        let mut c = core_with("/x", &[("a", false), ("b", false), ("c", false)]);
        assert_eq!(c.selected, 0);
        c.move_cursor(-1); // wrap top -> bottom
        assert_eq!(c.selected, 2);
        c.move_cursor(1); // wrap bottom -> top
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn move_cursor_noop_on_empty_ranked() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        c.move_cursor(5); // no panic, no change
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn clamp_selected_drops_back_into_bounds() {
        let mut c = core_with("/x", &[("a", false)]);
        c.selected = 99;
        c.clamp_selected();
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn clamp_selected_empty_resets_to_zero() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        c.selected = 5;
        c.clamp_selected();
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn toggle_mark_selected_round_trips() {
        let mut c = core_with("/x", &[("a", false)]);
        let p = c.toggle_mark_selected().expect("cursor on an entry");
        assert!(c.marked.contains(&p), "first toggle marks");
        let _ = c.toggle_mark_selected();
        assert!(c.marked.is_empty(), "second toggle unmarks");
    }

    #[test]
    fn toggle_mark_selected_none_on_empty_listing() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        assert!(c.toggle_mark_selected().is_none());
    }

    #[test]
    fn visible_window_delegates_to_focus_window() {
        let c = core_with("/x", &[("a", false), ("b", false), ("c", false)]);
        let win = c.visible_window(2);
        assert!(win.end - win.start <= 2);
    }
}
