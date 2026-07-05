//! Pure per-side navigation/filter/mark state for the dual-pane transfer screen
//! (`sshrack sftp`). Each side of the screen owns one [`Pane`]; the screen
//! feeds entries via [`Pane::set_entries`] (the local side lists inline via
//! `LocalDirSource`, the remote side is fed by the SFTP worker). All key
//! handling, fuzzy filter, focus-window math, and mark set live here and are
//! pure — no I/O — so a pane is unit-testable without a terminal, a
//! filesystem, or a worker.
//!
//! Navigation mirrors [`crate::tui::file_picker`] so the two surfaces feel
//! identical: arrows + Ctrl-P/N move the cursor with wrap, Left/empty-Backspace
//! step up, Right/Enter on a dir steps in (and on a file activates it),
//! printable chars append to the query and re-rank, Backspace pops the query,
//! Space toggles the mark on the cursor entry (file or dir — both transfer).
//!
//! Mark scope: marks belong to the CURRENT directory only. The screen calls
//! [`Pane::on_step`] right before [`Pane::set_entries`] when stepping into or
//! out of a directory, which clears marks (and the query and cursor) so a
//! stale mark never survives a directory change.
//!
//! This module is staged ahead of the transfer screen (a later task wires
//! `Pane` into the dual-pane UI). Until that screen lands nothing in the binary
//! references `Pane`, so module-local `dead_code` silencing is needed for the
//! private helpers. It is scoped to this file so newly-dead code anywhere else
//! still flags.

// Scoped silence: see the module doc — `Pane` is consumed by a later task.
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use sshrack_core::dirsource::DirEntry;
use sshrack_core::pathutil::{FilterIntent, expand_tilde, parse_filter_intent};

/// Which side of the transfer screen a [`Pane`] drives. Pure label — the pane
/// does not branch on it, but the screen renders each side differently and
/// routes side effects (local: inline list; remote: worker List) by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The local filesystem side.
    Local,
    /// The remote (SFTP) side.
    Remote,
}

/// Pure intent returned by [`Pane::on_key`]. The pane mutates only its own
/// query/cursor/marked state; this intent tells the screen what side effect to
/// perform (worker List, transfer enqueue, focus switch). Kept enum-shaped (not
/// `Option<PaneOutcome>`) so the screen's match is exhaustive over the action
/// vocabulary — adding a new action is a compile error everywhere it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneOutcome {
    /// The key was consumed (or ignored) but no side effect is needed — the
    /// pane's own state already reflects the result (e.g. cursor move).
    None,
    /// The filter query changed — re-render the search box. The pane already
    /// re-ranked and reset the cursor.
    QueryChanged,
    /// The cursor entry is a directory; the screen lists it. The screen calls
    /// [`Pane::on_step`] + [`Pane::set_entries`] once the listing resolves
    /// (local: sync; remote: worker event). Carries the absolute dir path.
    StepInto(PathBuf),
    /// The user asked to go to the parent directory. Same screen flow as
    /// [`StepInto`](Self::StepInto). Emitted only when `cwd` has a parent
    /// (no-op at `/`).
    StepUp,
    /// A file (or directory) was activated with `Enter`/`Right`. Reserved for
    /// transfer enqueue at screen level — `ActivateSelected` itself only
    /// signals intent; the screen decides whether to enqueue.
    ActivateSelected,
    /// The user toggled the mark on `path` (file or dir). The pane has already
    /// updated its `marked` set; this intent lets the screen re-render the row
    /// and update any selection/counter UI.
    ToggleMark(PathBuf),
    /// A path-like query (per [`parse_filter_intent`]) was resolved to an
    /// absolute directory path; the screen lists it. Same screen flow as
    /// [`StepInto`](Self::StepInto). Resolution: a leading `~` expands via
    /// `HOME`; a relative path joins onto `cwd`; an absolute path is used
    /// verbatim. `~` with no `HOME` emits [`None`](Self::None).
    RequestList(PathBuf),
}

/// One side of the dual-pane transfer screen: a cwd, its current listing, a
/// fuzzy filter query, a cursor, and a per-directory mark set. Pure — no I/O.
/// The screen feeds entries via [`Pane::set_entries`]; the pane never lists on
/// its own.
///
/// Field visibility: `ranked` is private (it is a derived index buffer that
/// tests in this module read but external code only consumes via
/// [`selected_entry`](Self::selected_entry) /
/// [`visible_window`](Self::visible_window)); every other field is public so
/// the screen and its tests can drive the pane directly.
#[derive(Debug, Clone)]
pub struct Pane {
    /// Which side this pane drives. Pure label; the pane does not branch on it.
    pub side: Side,
    /// Absolute current directory. The screen updates this when it acts on a
    /// [`StepInto`](PaneOutcome::StepInto) / [`StepUp`](PaneOutcome::StepUp) /
    /// [`RequestList`](PaneOutcome::RequestList) intent.
    pub cwd: PathBuf,
    /// Current listing. Worker-fed for the remote side, `LocalDirSource`-fed
    /// for the local side.
    pub entries: Vec<DirEntry>,
    /// Filter-box text. Drives fuzzy ranking via [`recompute`](Self::recompute).
    pub query: String,
    /// Indices into `entries`, fuzzy-ordered for display. Private: derived from
    /// `entries` + `query`; reset by [`set_entries`](Self::set_entries) and
    /// [`recompute`](Self::recompute).
    ranked: Vec<usize>,
    /// Cursor position: an index into `ranked` (not `entries`).
    pub selected: usize,
    /// Marked paths in the CURRENT directory only. Cleared by
    /// [`on_step`](Self::on_step). Both files and directories can be marked —
    /// both are transferable (dirs recurse).
    pub marked: HashSet<PathBuf>,
    /// Pending-list indicator the screen toggles around `set_entries`. The pane
    /// never mutates this; it is render-only state colocated here so the screen
    /// does not carry a parallel `Side` → bool map.
    pub loading: bool,
}

impl Pane {
    /// Open a pane at `cwd` with an empty listing. The screen feeds the first
    /// listing via [`set_entries`](Self::set_entries) once it resolves (sync
    /// for local, worker event for remote). Pure: no I/O.
    #[must_use]
    pub fn new(side: Side, cwd: PathBuf) -> Self {
        Self {
            side,
            cwd,
            entries: Vec::new(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            marked: HashSet::new(),
            loading: false,
        }
    }

    /// Replace the listing and re-rank against the current query. Resets the
    /// cursor to 0. Pure: no I/O. The screen calls
    /// [`on_step`](Self::on_step) first when the new listing is for a different
    /// directory (clears marks + query); for an in-place refresh (same dir,
    /// new entries) the screen calls this directly and the query survives.
    pub fn set_entries(&mut self, entries: Vec<DirEntry>) {
        self.entries = entries;
        self.selected = 0;
        self.recompute();
    }

    /// Reset per-directory state for an upcoming directory change. Clears
    /// `marked`, `query`, and `selected`. The screen calls this right before
    /// [`set_entries`](Self::set_entries) when stepping into/up or fulfilling a
    /// [`RequestList`](PaneOutcome::RequestList) — marks do not carry across
    /// directories.
    pub fn on_step(&mut self) {
        self.marked.clear();
        self.query.clear();
        self.selected = 0;
    }

    /// Pure key handler. Mutates only `query` / `selected` / `marked` and
    /// returns the side effect the screen should perform. Performs no I/O and
    /// reads no env except `HOME` (for `~`-expansion of a path-like `Enter`).
    ///
    /// Key map mirrors [`crate::tui::file_picker::FilePicker::on_key`] so
    /// navigation feels identical across the app:
    /// - `Up`/`Down` + `Ctrl-P`/`Ctrl-N` move `selected` with wrap.
    /// - `Left` → [`StepUp`](PaneOutcome::StepUp) (no-op at `/`).
    /// - `Right`/`Enter` on a dir → [`StepInto`](PaneOutcome::StepInto); on a
    ///   file → [`ActivateSelected`](PaneOutcome::ActivateSelected). `Enter`
    ///   on a path-like query → [`RequestList`](PaneOutcome::RequestList).
    /// - `Backspace` pops the query; empty query → [`StepUp`](PaneOutcome::StepUp).
    /// - `Space` toggles the mark on the cursor entry (file or dir).
    /// - Printable char → append to `query`, re-rank, reset cursor →
    ///   [`QueryChanged`](PaneOutcome::QueryChanged).
    ///
    /// Only reacts to [`KeyEventKind::Press`] (matches every other TUI surface).
    pub fn on_key(&mut self, key: KeyEvent) -> PaneOutcome {
        if key.kind != KeyEventKind::Press {
            return PaneOutcome::None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Up => {
                self.move_cursor(-1);
                PaneOutcome::None
            }
            KeyCode::Down => {
                self.move_cursor(1);
                PaneOutcome::None
            }
            KeyCode::Char('p') if ctrl => {
                self.move_cursor(-1);
                PaneOutcome::None
            }
            KeyCode::Char('n') if ctrl => {
                self.move_cursor(1);
                PaneOutcome::None
            }
            KeyCode::Left => self.step_up_intent(),
            KeyCode::Backspace => {
                if self.query.is_empty() {
                    self.step_up_intent()
                } else {
                    self.query.pop();
                    self.recompute();
                    self.clamp_selected();
                    PaneOutcome::QueryChanged
                }
            }
            // `Right` is a pure navigation key: enter the dir under the cursor,
            // or activate a file. It never resolves a path-like query (only
            // `Enter` does — keeps the file_picker's split between Right-as-nav
            // and Enter-as-activate-or-resolve).
            KeyCode::Right => self.activate_or_step(),
            KeyCode::Enter => self.on_enter(),
            // Space toggles the mark on the cursor entry (file or dir — both
            // transfer, dirs recursively). Must precede the generic Char arm.
            KeyCode::Char(' ') if !ctrl => self.toggle_mark_selected(),
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                self.selected = 0;
                PaneOutcome::QueryChanged
            }
            _ => PaneOutcome::None,
        }
    }

    /// Range of `ranked` indices to render for a viewport of `rows` rows.
    /// Delegates to [`crate::tui::fit::focus_window`] so the pane scrolls
    /// exactly like the launcher / wizards / picker. Pure.
    #[must_use]
    pub fn visible_window(&self, rows: usize) -> std::ops::Range<usize> {
        crate::tui::fit::focus_window(self.ranked.len(), self.selected, rows)
    }

    /// The entry under the cursor, or `None` when the ranked list is empty.
    /// Pure. Pub so the screen can read the activate/transfer target without
    /// re-deriving the ranked → entry mapping.
    #[must_use]
    pub fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked
            .get(self.selected)
            .and_then(|&i| self.entries.get(i))
    }

    /// Re-rank `entries` for the current `query` via the shared nucleo helper
    /// (one-field rows, all-zero scores). Empty query yields every entry in its
    /// sorted order. Pure: no I/O. Mirrors [`file_picker`]'s `recompute`.
    ///
    /// [`file_picker`]: crate::tui::file_picker::FilePicker
    fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    /// Clamp the cursor into `ranked` bounds (no-op when empty). Pure.
    fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the cursor by `delta` with wrap-around. No-op when ranked is empty.
    /// Pure.
    fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// `Right` / `Enter`-on-fuzzy activation: dirs return
    /// [`StepInto`](PaneOutcome::StepInto), files return
    /// [`ActivateSelected`](PaneOutcome::ActivateSelected). Empty cursor →
    /// [`None`](PaneOutcome::None). Pure.
    fn activate_or_step(&mut self) -> PaneOutcome {
        if let Some(entry) = self.selected_entry() {
            if entry.is_dir {
                return PaneOutcome::StepInto(entry.path.clone());
            }
            return PaneOutcome::ActivateSelected;
        }
        PaneOutcome::None
    }

    /// `Enter`: a path-like query resolves via [`resolve_path_like`] →
    /// [`RequestList`](PaneOutcome::RequestList); a fuzzy query activates the
    /// cursor entry (dir → [`StepInto`](PaneOutcome::StepInto), file →
    /// [`ActivateSelected`](PaneOutcome::ActivateSelected)). Pure except `HOME`
    /// lookup for `~`.
    fn on_enter(&mut self) -> PaneOutcome {
        match parse_filter_intent(&self.query) {
            FilterIntent::PathLike(raw) => match resolve_path_like(&raw, &self.cwd) {
                Some(abs) => PaneOutcome::RequestList(abs),
                None => PaneOutcome::None,
            },
            FilterIntent::Fuzzy(_) => self.activate_or_step(),
        }
    }

    /// `Left` / empty-`Backspace`: emit [`StepUp`](PaneOutcome::StepUp) when
    /// `cwd` has a parent, [`None`](PaneOutcome::None) at `/` (no parent —
    /// stepping up from root is a no-op). Pure.
    fn step_up_intent(&self) -> PaneOutcome {
        if self.cwd.parent().is_some() {
            PaneOutcome::StepUp
        } else {
            PaneOutcome::None
        }
    }

    /// `Space`: toggle the mark on the cursor entry (file or dir). Returns
    /// [`ToggleMark(path)`](PaneOutcome::ToggleMark) and updates `marked`
    /// in-place; [`None`](PaneOutcome::None) when the cursor is empty. Pure.
    fn toggle_mark_selected(&mut self) -> PaneOutcome {
        let Some(entry) = self.selected_entry() else {
            return PaneOutcome::None;
        };
        let path = entry.path.clone();
        if !self.marked.insert(path.clone()) {
            self.marked.remove(&path);
        }
        PaneOutcome::ToggleMark(path)
    }
}

/// Resolve a path-like filter string against `cwd` to an absolute path. Pure
/// except for the `HOME` lookup, which only runs for `~`-prefixed inputs.
///
/// - `~` alone or `~/x` → `HOME` joined with the rest. Returns `None` when
///   `HOME` is unset (the caller emits `PaneOutcome::None` — `~` cannot be
///   resolved without a home).
/// - An absolute path → used verbatim.
/// - A relative path → joined onto `cwd`.
fn resolve_path_like(raw: &str, cwd: &Path) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.starts_with('~') {
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        Some(expand_tilde(trimmed, &home))
    } else if Path::new(trimmed).is_absolute() {
        Some(PathBuf::from(trimmed))
    } else {
        Some(cwd.join(trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use sshrack_core::dirsource::DirEntry;
    use std::path::PathBuf;

    /// Build a `DirEntry` test fixture: `name` is decorated with a trailing
    /// `/` for dirs (matches `LocalDirSource::list`'s decoration); `path` is
    /// `parent.join(name)`. `size`/`modified` are `None` (Task-1 fields).
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

    /// A `KeyEvent::Press` with no modifiers for `code`.
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    /// A pane at `/x` with three file entries: apple, banana, cherry.
    fn pane_with_fruits() -> Pane {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![
            entry("apple", &cwd, false),
            entry("banana", &cwd, false),
            entry("cherry", &cwd, false),
        ]);
        p
    }

    // ---- new() ----

    #[test]
    fn new_starts_empty_with_no_query_no_marks() {
        let p = Pane::new(Side::Local, PathBuf::from("/x"));
        assert_eq!(p.side, Side::Local);
        assert_eq!(p.cwd, PathBuf::from("/x"));
        assert!(p.entries.is_empty());
        assert!(p.query.is_empty());
        assert!(p.ranked.is_empty());
        assert_eq!(p.selected, 0);
        assert!(p.marked.is_empty());
        assert!(!p.loading);
        assert!(p.selected_entry().is_none());
    }

    // ---- set_entries: resets cursor + re-ranks (empty query → all entries) ----

    #[test]
    fn set_entries_resets_cursor_to_zero_and_ranks_all() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.selected = 7; // pretend a stale cursor
        p.set_entries(vec![
            entry("apple", &cwd, false),
            entry("banana", &cwd, false),
        ]);
        assert_eq!(p.selected, 0, "cursor reset to 0");
        assert_eq!(p.ranked.len(), 2, "both entries ranked");
        assert_eq!(p.ranked, vec![0, 1], "empty query keeps entry order");
    }

    #[test]
    fn set_entries_preserves_query_for_in_place_refresh() {
        // A refresh of the SAME dir should not wipe the user's filter — only
        // on_step (called for a NEW dir) clears the query.
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![
            entry("apple", &cwd, false),
            entry("banana", &cwd, false),
            entry("cherry", &cwd, false),
        ]);
        // Simulate the user typing "an" (matches "banana" only).
        let _ = p.on_key(press(KeyCode::Char('a')));
        let _ = p.on_key(press(KeyCode::Char('n')));
        assert_eq!(p.query, "an");
        // Now the worker refreshes the same dir's entries (e.g. a file appeared
        // server-side). The query must survive.
        p.set_entries(vec![
            entry("apple", &cwd, false),
            entry("avocado", &cwd, false),
            entry("banana", &cwd, false),
            entry("cherry", &cwd, false),
        ]);
        assert_eq!(p.query, "an", "query preserved on in-place refresh");
        // "an" still matches banana only; the new avocado does not match.
        let names: Vec<&str> = p
            .ranked
            .iter()
            .map(|&i| p.entries[i].name.as_str())
            .collect();
        assert_eq!(names, vec!["banana"]);
        assert_eq!(p.selected, 0, "cursor reset on refresh");
    }

    // ---- on_step: clears marks + query + cursor for a new dir ----

    #[test]
    fn on_step_clears_marks_query_and_cursor() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("apple", &cwd, false)]);
        // Mark the entry, type a query, move the cursor.
        let _ = p.on_key(press(KeyCode::Char(' '))); // ToggleMark(/x/apple)
        let _ = p.on_key(press(KeyCode::Char('q'))); // query = "q"
        let _ = p.on_key(press(KeyCode::Down)); // selected = 0 still (1 entry)
        assert!(p.marked.contains(&cwd.join("apple")));
        assert_eq!(p.query, "q");
        // Act: the screen is about to load a new dir.
        p.on_step();
        assert!(p.marked.is_empty(), "marks cleared");
        assert!(p.query.is_empty(), "query cleared");
        assert_eq!(p.selected, 0, "cursor reset");
    }

    // ---- query filters + re-ranks ----

    #[test]
    fn typing_a_char_appends_to_query_and_filters() {
        let mut p = pane_with_fruits();
        let out = p.on_key(press(KeyCode::Char('c')));
        assert_eq!(out, PaneOutcome::QueryChanged);
        assert_eq!(p.query, "c");
        let names: Vec<&str> = p
            .ranked
            .iter()
            .map(|&i| p.entries[i].name.as_str())
            .collect();
        assert_eq!(names, vec!["cherry"], "only cherry matches 'c'");
        assert_eq!(p.selected, 0, "cursor reset to 0 on query change");
    }

    #[test]
    fn backspace_pops_a_query_char_and_reranks() {
        let mut p = pane_with_fruits();
        let _ = p.on_key(press(KeyCode::Char('c')));
        let _ = p.on_key(press(KeyCode::Char('h')));
        assert_eq!(p.query, "ch");
        let out = p.on_key(press(KeyCode::Backspace));
        assert_eq!(out, PaneOutcome::QueryChanged);
        assert_eq!(p.query, "c");
    }

    // ---- Down/Up move selected with wrap ----

    #[test]
    fn down_then_up_moves_cursor_and_wraps() {
        let mut p = pane_with_fruits();
        assert_eq!(p.selected, 0);
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 1);
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 2);
        // wrap bottom → top
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(p.selected, 0);
        // wrap top → bottom
        let _ = p.on_key(press(KeyCode::Up));
        assert_eq!(p.selected, 2);
    }

    #[test]
    fn ctrl_p_and_ctrl_n_move_cursor() {
        let mut p = pane_with_fruits();
        let ctrl_p = KeyEvent::new_with_kind(
            KeyCode::Char('p'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let ctrl_n = KeyEvent::new_with_kind(
            KeyCode::Char('n'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        let _ = p.on_key(ctrl_n);
        assert_eq!(p.selected, 1);
        let _ = p.on_key(ctrl_p);
        assert_eq!(p.selected, 0);
    }

    // ---- Left / Backspace-empty → StepUp ----

    #[test]
    fn left_emits_step_up_when_cwd_has_parent() {
        let mut p = pane_with_fruits(); // cwd = /x
        assert_eq!(p.on_key(press(KeyCode::Left)), PaneOutcome::StepUp);
        // Backspace on empty query is the same intent.
        assert_eq!(p.on_key(press(KeyCode::Backspace)), PaneOutcome::StepUp);
    }

    #[test]
    fn left_is_noop_at_root() {
        let mut p = Pane::new(Side::Local, PathBuf::from("/"));
        assert_eq!(p.on_key(press(KeyCode::Left)), PaneOutcome::None);
        assert_eq!(p.on_key(press(KeyCode::Backspace)), PaneOutcome::None);
    }

    // ---- Right/Enter on a dir → StepInto; on a file → ActivateSelected ----

    #[test]
    fn right_on_dir_emits_step_into() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        // Single dir entry, so the cursor lands on it unambiguously. (With a
        // file alongside, rank_by_fields would order by name asc and "file"
        // sorts before "subdir/" — the cursor would land on the file.)
        p.set_entries(vec![entry("subdir", &cwd, true)]);
        let out = p.on_key(press(KeyCode::Right));
        assert_eq!(out, PaneOutcome::StepInto(cwd.join("subdir")));
    }

    #[test]
    fn right_on_file_emits_activate_selected() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("file", &cwd, false)]);
        let out = p.on_key(press(KeyCode::Right));
        assert_eq!(out, PaneOutcome::ActivateSelected);
    }

    #[test]
    fn enter_on_dir_emits_step_into() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("subdir", &cwd, true)]);
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(out, PaneOutcome::StepInto(cwd.join("subdir")));
    }

    #[test]
    fn enter_on_file_emits_activate_selected() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("file", &cwd, false)]);
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(out, PaneOutcome::ActivateSelected);
    }

    #[test]
    fn enter_on_empty_cursor_is_none() {
        let mut p = Pane::new(Side::Local, PathBuf::from("/x"));
        p.set_entries(vec![]);
        assert_eq!(p.on_key(press(KeyCode::Enter)), PaneOutcome::None);
        assert_eq!(p.on_key(press(KeyCode::Right)), PaneOutcome::None);
    }

    // ---- Space toggles a mark (file or dir) and updates `marked` ----

    #[test]
    fn space_on_file_toggles_mark_and_path_appears_in_marked() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("apple", &cwd, false)]);
        let target = cwd.join("apple");
        let out = p.on_key(press(KeyCode::Char(' ')));
        assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
        assert!(p.marked.contains(&target), "marked after first Space");
        // Second Space untoggles.
        let out = p.on_key(press(KeyCode::Char(' ')));
        assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
        assert!(!p.marked.contains(&target), "unmarked after second Space");
    }

    #[test]
    fn space_on_dir_toggles_mark() {
        // Dirs are transferable recursively, so Space toggles their mark too.
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("subdir", &cwd, true)]);
        let target = cwd.join("subdir");
        let out = p.on_key(press(KeyCode::Char(' ')));
        assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
        assert!(p.marked.contains(&target));
    }

    #[test]
    fn space_on_empty_cursor_is_none() {
        let mut p = Pane::new(Side::Local, PathBuf::from("/x"));
        p.set_entries(vec![]);
        assert_eq!(p.on_key(press(KeyCode::Char(' '))), PaneOutcome::None);
    }

    // ---- path-like query + Enter → RequestList ----

    #[test]
    fn enter_on_absolute_path_query_emits_request_list() {
        let mut p = Pane::new(Side::Local, PathBuf::from("/start"));
        p.set_entries(vec![]);
        for c in "/foo/bar".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Enter)),
            PaneOutcome::RequestList(PathBuf::from("/foo/bar"))
        );
    }

    #[test]
    fn enter_on_relative_path_query_joins_cwd() {
        let mut p = Pane::new(Side::Local, PathBuf::from("/parent"));
        p.set_entries(vec![]);
        for c in "sub/dir".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Enter)),
            PaneOutcome::RequestList(PathBuf::from("/parent/sub/dir"))
        );
    }

    #[test]
    fn enter_on_tilde_path_query_expands_home_when_set() {
        // `~`-expansion depends on HOME; skip the assertion when the test
        // environment has none (the production behavior is to emit None).
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            eprintln!("skip: HOME unset; cannot exercise ~ expansion");
            return;
        };
        let mut p = Pane::new(Side::Local, PathBuf::from("/start"));
        p.set_entries(vec![]);
        for c in "~/baz".chars() {
            let _ = p.on_key(press(KeyCode::Char(c)));
        }
        assert_eq!(
            p.on_key(press(KeyCode::Enter)),
            PaneOutcome::RequestList(home.join("baz"))
        );
    }

    #[test]
    fn enter_on_fuzzy_query_activates_cursor_not_request_list() {
        // A plain-word query (no `/`, no `~`) is fuzzy, not path-like: Enter
        // activates the cursor entry rather than emitting RequestList.
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![entry("cherry", &cwd, false)]);
        let _ = p.on_key(press(KeyCode::Char('c'))); // fuzzy "c" → cherry
        let out = p.on_key(press(KeyCode::Enter));
        assert_eq!(out, PaneOutcome::ActivateSelected);
    }

    // ---- visible_window keeps the cursor in view ----

    #[test]
    fn visible_window_keeps_cursor_centered_then_clamps_to_tail() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        let entries: Vec<DirEntry> = (0..20)
            .map(|i| entry(&format!("f{i:02}"), &cwd, false))
            .collect();
        p.set_entries(entries);
        assert_eq!(p.ranked.len(), 20);
        // Move cursor to 15; window of 5 → focus_window(20, 15, 5) = 13..18.
        for _ in 0..15 {
            let _ = p.on_key(press(KeyCode::Down));
        }
        assert_eq!(p.selected, 15);
        let win = p.visible_window(5);
        assert!(
            win.contains(&p.selected),
            "{}..{} excludes {}",
            win.start,
            win.end,
            p.selected
        );
        assert_eq!(win, 13..18);
        // Clamp to tail: cursor at 19, window 5 → 15..20.
        for _ in 0..4 {
            let _ = p.on_key(press(KeyCode::Down));
        }
        assert_eq!(p.selected, 19);
        let win = p.visible_window(5);
        assert!(win.contains(&p.selected));
        assert_eq!(win, 15..20);
    }

    #[test]
    fn visible_window_empty_entries_is_empty_range() {
        let p = Pane::new(Side::Local, PathBuf::from("/x"));
        assert_eq!(p.visible_window(10), 0..0);
    }

    // ---- non-Press events are ignored ----

    #[test]
    fn non_press_events_emit_none_and_do_not_mutate() {
        let mut p = pane_with_fruits();
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('a'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert_eq!(p.on_key(release), PaneOutcome::None);
        assert!(p.query.is_empty(), "release did not append to query");
    }

    // ---- selected_entry follows the cursor ----

    #[test]
    fn selected_entry_tracks_cursor_after_move() {
        let cwd = PathBuf::from("/x");
        let mut p = Pane::new(Side::Local, cwd.clone());
        p.set_entries(vec![
            entry("a", &cwd, false),
            entry("b", &cwd, false),
            entry("c", &cwd, false),
        ]);
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("a")
        );
        let _ = p.on_key(press(KeyCode::Down));
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("b")
        );
    }
}
