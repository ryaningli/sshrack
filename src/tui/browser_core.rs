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

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use sshrack_core::dirsource::DirEntry;

/// Neutral result of [`BrowserCore::apply_nav_key`] for the unambiguous
/// navigation/edit keys (arrows, Ctrl-P/N, Left, Backspace, printable chars
/// incl. Space). The component translates it into its own outcome. Keys NOT
/// owned here — `Enter`/`Right` (activation, component-specific), `Space`
/// (`Pane` marks vs `FilePicker` query char — `Pane` intercepts it earlier),
/// `Esc`/`Ctrl-C` (cancel) — yield `None` so the component keeps full control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NavDecision {
    /// Up/Down/Ctrl-P/N moved the cursor (`selected` already mutated).
    CursorMoved,
    /// A printable char was appended or Backspace popped one (`query` + rank
    /// already mutated).
    QueryChanged,
    /// `Left` requested the parent directory. Core did NOT move; the component
    /// decides (and may no-op at `/`).
    StepUp,
    /// Backspace on an empty query — a deliberate no-op (pure-edit semantics).
    Noop,
}

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

    /// Phase 1 of the async two-phase switch (e.g. remote SFTP): snapshot the
    /// OUTGOING cwd's cursor into history, clear marks/query/selected, and arm
    /// `pending_restore`. The caller then sets `cwd` to the new path, fetches
    /// the listing, and calls [`Self::finish_switch`]. Pure.
    pub(crate) fn begin_switch(&mut self) {
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.marked.clear();
        self.query.clear();
        self.selected = 0;
        self.pending_restore = true;
    }

    /// Phase 2 of the async switch: adopt `entries` for the CURRENT `cwd` (set
    /// by the caller between phase 1 and here), re-rank, and restore the
    /// remembered cursor (dir switch — `pending_restore`) or reset to 0
    /// (in-place refresh). Also records the parent's cursor as this cwd so
    /// going back up lands on the child. Pure.
    pub(crate) fn finish_switch(&mut self, entries: Vec<DirEntry>) {
        self.entries = entries;
        self.recompute();
        if self.pending_restore {
            self.selected = crate::tui::cursor_history::remembered_cursor_index(
                &self.history,
                &self.cwd,
                &self.ranked,
                &self.entries,
            );
            if let Some(parent) = self.cwd.parent() {
                self.history.insert(parent.to_path_buf(), self.cwd.clone());
            }
            self.pending_restore = false;
        } else {
            self.selected = 0;
        }
    }

    /// Atomic switch for synchronous sources (e.g. local fs): snapshot
    /// outgoing, set `new_cwd` + entries, restore incoming — all in one call.
    /// A listing failure can simply skip this call and leave the previous
    /// view intact (snapshot happens before `entries` are replaced). Pure.
    pub(crate) fn commit_switch(&mut self, new_cwd: PathBuf, entries: Vec<DirEntry>) {
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.cwd = new_cwd;
        self.entries = entries;
        self.query.clear();
        self.marked.clear();
        self.recompute();
        self.selected = crate::tui::cursor_history::remembered_cursor_index(
            &self.history,
            &self.cwd,
            &self.ranked,
            &self.entries,
        );
        if let Some(parent) = self.cwd.parent() {
            self.history.insert(parent.to_path_buf(), self.cwd.clone());
        }
    }

    /// Apply one unambiguous navigation/edit key and return the decision for
    /// the component to translate. Returns `None` for keys it does NOT own
    /// (`Enter`, `Right`, `Esc`, `Ctrl-C`, non-Press) so the component keeps
    /// full control over activation/cancel semantics. `Space` IS appended to
    /// the query here — `Pane` intercepts it earlier for mark-toggle.
    pub(crate) fn apply_nav_key(&mut self, key: KeyEvent) -> Option<NavDecision> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Up => {
                self.move_cursor(-1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Down => {
                self.move_cursor(1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Char('p') if ctrl => {
                self.move_cursor(-1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Char('n') if ctrl => {
                self.move_cursor(1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Left => Some(NavDecision::StepUp),
            KeyCode::Backspace => {
                // Pure edit: pop a query char, or no-op when empty. NEVER
                // step up — going up uses Left. Keeps both browsers identical
                // (fixes the drift where FilePicker stepped up on empty
                // Backspace).
                if self.query.is_empty() {
                    Some(NavDecision::Noop)
                } else {
                    self.query.pop();
                    self.recompute();
                    self.clamp_selected();
                    Some(NavDecision::QueryChanged)
                }
            }
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                self.selected = 0;
                Some(NavDecision::QueryChanged)
            }
            _ => None,
        }
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

    // ---- dir-switch protocol ----

    #[test]
    fn commit_switch_first_visit_lands_on_zero() {
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/x"),
            vec![
                entry("a", Path::new("/x"), false),
                entry("b", Path::new("/x"), false),
            ],
        );
        assert_eq!(c.cwd, PathBuf::from("/x"));
        assert_eq!(c.selected, 0, "first visit → cursor 0");
        assert_eq!(c.matched_count(), 2);
    }

    #[test]
    fn begin_then_finish_restores_remembered_cursor() {
        // Enter /x, move to "b", leave; come back — cursor should land on "b".
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/x"),
            vec![
                entry("a", Path::new("/x"), false),
                entry("b", Path::new("/x"), false),
            ],
        );
        c.move_cursor(1); // cursor on "b"
        // leave /x for /y
        c.begin_switch();
        c.cwd = PathBuf::from("/y");
        c.finish_switch(vec![entry("c", Path::new("/y"), false)]);
        // come back to /x
        c.begin_switch();
        c.cwd = PathBuf::from("/x");
        c.finish_switch(vec![
            entry("a", Path::new("/x"), false),
            entry("b", Path::new("/x"), false),
        ]);
        assert_eq!(
            c.selected_entry().map(|e| e.name.as_str()),
            Some("b"),
            "remembered cursor restored on re-entry"
        );
    }

    #[test]
    fn begin_switch_clears_marks_query_and_selected() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        c.move_cursor(1);
        let _ = c.toggle_mark_selected();
        c.query = "abc".to_string();
        c.begin_switch();
        assert!(c.marked.is_empty(), "marks cleared on switch");
        assert!(c.query.is_empty(), "query cleared on switch");
        assert_eq!(c.selected, 0, "selected reset on switch");
    }

    #[test]
    fn commit_switch_records_parent_cursor_so_going_up_lands_on_child() {
        // Commit into /tmp/sftp-test; then begin+finish back into /tmp should
        // land the cursor on sftp-test (the child we just entered).
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/tmp"),
            vec![
                entry("aaa", Path::new("/tmp"), true),
                entry("sftp-test", Path::new("/tmp"), true),
                entry("zzz", Path::new("/tmp"), false),
            ],
        );
        c.commit_switch(
            PathBuf::from("/tmp/sftp-test"),
            vec![entry("file", Path::new("/tmp/sftp-test"), false)],
        );
        // go back up to /tmp
        c.begin_switch();
        c.cwd = PathBuf::from("/tmp");
        c.finish_switch(vec![
            entry("aaa", Path::new("/tmp"), true),
            entry("sftp-test", Path::new("/tmp"), true),
            entry("zzz", Path::new("/tmp"), false),
        ]);
        assert_eq!(
            c.selected_entry().map(|e| e.path.as_path()),
            Some(std::path::Path::new("/tmp/sftp-test")),
            "going back up lands on the dir we just entered"
        );
    }

    #[test]
    fn finish_switch_in_place_refresh_resets_cursor_when_not_pending() {
        // finish_switch without a preceding begin_switch is an in-place refresh:
        // cursor resets to 0.
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        c.move_cursor(1);
        assert!(!c.pending_restore);
        c.finish_switch(vec![
            entry("a", Path::new("/x"), false),
            entry("b", Path::new("/x"), false),
        ]);
        assert_eq!(c.selected, 0, "in-place refresh resets cursor");
    }

    // ---- apply_nav_key ----

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn nav_backspace_on_empty_query_is_noop_never_step_up() {
        // The drift fix: empty-query Backspace must NOT be StepUp. It is Noop.
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Backspace)).expect("handled");
        assert_eq!(d, super::NavDecision::Noop);
        assert_eq!(c.cwd, PathBuf::from("/x"), "cwd unchanged by Backspace");
    }

    #[test]
    fn nav_backspace_pops_query_char() {
        let mut c = core_with("/x", &[("a", false)]);
        c.query = "ab".to_string();
        let d = c.apply_nav_key(key(KeyCode::Backspace)).expect("handled");
        assert_eq!(d, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "a");
    }

    #[test]
    fn nav_left_requests_step_up_without_moving_cwd() {
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Left)).expect("handled");
        assert_eq!(d, super::NavDecision::StepUp);
        assert_eq!(c.cwd, PathBuf::from("/x"), "Left does not move cwd itself");
    }

    #[test]
    fn nav_arrows_move_cursor() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        let d = c.apply_nav_key(key(KeyCode::Down)).expect("handled");
        assert_eq!(d, super::NavDecision::CursorMoved);
        assert_eq!(c.selected, 1);
    }

    #[test]
    fn nav_ctrl_p_n_move_cursor() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        let pn = KeyEvent::new_with_kind(
            KeyCode::Char('n'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let d = c.apply_nav_key(pn).expect("handled");
        assert_eq!(d, super::NavDecision::CursorMoved);
        assert_eq!(c.selected, 1);
    }

    #[test]
    fn nav_printable_char_appends_to_query_including_space() {
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Char('z'))).expect("handled");
        assert_eq!(d, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "z");
        // Space is a query char here; Pane intercepts it earlier for marks.
        let d2 = c.apply_nav_key(key(KeyCode::Char(' '))).expect("handled");
        assert_eq!(d2, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "z ");
    }

    #[test]
    fn nav_enter_right_escape_are_not_handled() {
        let mut c = core_with("/x", &[("a", false)]);
        assert!(c.apply_nav_key(key(KeyCode::Enter)).is_none());
        assert!(c.apply_nav_key(key(KeyCode::Right)).is_none());
        assert!(c.apply_nav_key(key(KeyCode::Esc)).is_none());
    }
}
