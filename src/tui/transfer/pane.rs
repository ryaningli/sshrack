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
///
/// Staging note: [`Pane::on_key`] (Task 9) is the sole producer of these
/// variants. The Task-8 transfer screen ships render-only, so until Task 9
/// lands the variants are constructed only inside `on_key` itself (and its
/// helpers) — none of which the prod binary reaches yet. The scoped allow on
/// the enum drops automatically once Task 9 wires `on_key` into the screen.
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
///
/// `Side` is NOT carried on the pane: the screen's `focus: Side` field already
/// tracks which pane is which, and the pane itself never branches on side
/// (local-vs-remote differences live in how entries are fed in, not in pane
/// behavior). Carrying a redundant `side` label here would just be dead state.
#[derive(Debug, Clone)]
pub struct Pane {
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
    /// Per-directory cursor memory (ranger-style history): visited cwd → that
    /// dir's last-selected entry path. Snapshot in [`on_step`](Self::on_step)
    /// (the only "leaving this cwd" point), restored in
    /// [`set_entries`](Self::set_entries) via [`cursor_history`]. Per-pane
    /// private, so local and remote remember independently.
    history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
    /// Set by [`on_step`](Self::on_step) so the next
    /// [`set_entries`](Self::set_entries) restores the NEW cwd's remembered
    /// cursor instead of resetting to 0. Consumed (cleared) by `set_entries`.
    /// Separates a dir-switch from an in-place refresh (which must NOT move
    /// the cursor).
    pending_restore: bool,
    /// Pending-list indicator the screen toggles around `set_entries`. The pane
    /// never mutates this; it is render-only state colocated here so the screen
    /// does not carry a parallel `Side` → bool map.
    pub loading: bool,
}

impl Pane {
    /// Open a pane at `cwd` with an empty listing. The screen feeds the first
    /// listing via [`set_entries`](Self::set_entries) once it resolves (sync
    /// for local, worker event for remote). Pure: no I/O.
    ///
    /// Reachability: Task-8 render path + tests construct panes; the prod
    /// binary reaches `Pane` only via the Task-9 screen wiring
    /// ([`TransferScreen::new`](super::screen::TransferScreen::new)).
    #[must_use]
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            entries: Vec::new(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            marked: HashSet::new(),
            history: std::collections::HashMap::new(),
            pending_restore: false,
            loading: false,
        }
    }

    /// Replace the listing and re-rank against the current query. On a
    /// directory switch (the screen called [`on_step`](Self::on_step) first)
    /// restore the NEW cwd's remembered cursor via
    /// [`cursor_history::remembered_cursor_index`]; on an in-place refresh
    /// (same dir, new entries — no `on_step`) reset the cursor to 0 and the
    /// query survives. Pure: no I/O.
    ///
    /// Reachability: Task-9 screen key routing calls this; the Task-8 render
    /// path does not (only the marker + tests reach it).
    /// Live root is Task 10's sftp event loop (calls this after each List
    /// resolves). The Task-9 `TransferScreen::on_key` consumes `Pane::on_key`
    /// but is itself awaiting Task-10 wiring, so the allow is still required.
    pub fn set_entries(&mut self, entries: Vec<DirEntry>) {
        self.entries = entries;
        self.recompute();
        if self.pending_restore {
            // Dir switch (on_step ran first): restore the NEW cwd's remembered
            // cursor by locating it in the just-recomputed `ranked`. First
            // visit, or a remembered path gone from the listing, falls back to 0.
            self.selected = crate::tui::cursor_history::remembered_cursor_index(
                &self.history,
                &self.cwd,
                &self.ranked,
                &self.entries,
            );
            // Record the parent's cursor as this new cwd, so navigating back
            // up (Left → StepUp) lands on the directory we just entered —
            // matches ranger. Fixes a path-like Enter ("/tmp/sftp-test") where
            // the parent was never visited, so its cursor was never on the
            // child; without this, going back up restored cursor to index 0.
            if let Some(parent) = self.cwd.parent() {
                self.history.insert(parent.to_path_buf(), self.cwd.clone());
            }
            self.pending_restore = false;
        } else {
            // In-place refresh (same dir, new entries): reset to 0 like before.
            self.selected = 0;
        }
    }

    /// Reset per-directory state for an upcoming directory change. Clears
    /// `marked`, `query`, and `selected`. The screen calls this right before
    /// [`set_entries`](Self::set_entries) when stepping into/up or fulfilling a
    /// [`RequestList`](PaneOutcome::RequestList) — marks do not carry across
    /// directories.
    ///
    /// Reachability: Task-9 screen key routing calls this.
    /// Live root is Task 10's sftp event loop (calls this before set_entries
    /// when stepping into/up or fulfilling a RequestList).
    pub fn on_step(&mut self) {
        // Snapshot the OUTGOING cwd's cursor before clearing it, so re-entering
        // this dir restores it (ranger-style directory history). `cwd` is still
        // the old one here — the screen updates cwd between on_step and
        // set_entries.
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.marked.clear();
        self.query.clear();
        self.selected = 0;
        self.pending_restore = true;
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
    ///
    /// Reachability: the Task-9 screen event loop routes keys here; the Task-8
    /// render-only path never calls it. The scoped allow drops once Task 9
    /// wires the screen's `on_key`.
    /// Live root is Task 10's sftp event loop, which calls
    /// `TransferScreen::on_key` (Task 9) → this method.
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
                // Backspace is a pure edit key: it deletes from the query and
                // is a no-op when the query is empty — it never steps up to
                // the parent dir. Going up uses `Left` (the arm above). This
                // removes the ambiguity where emptying the query and pressing
                // Backspace once more would jump directories (expensive on a
                // remote listing). Matches ranger / lf.
                if self.query.is_empty() {
                    PaneOutcome::None
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
    ///
    /// Reachability: read by the Task-9/10 activate + transfer paths; the
    /// Task-8 render-only path uses [`Self::entry_at_rank`] instead.
    /// Live root is Task 10's loop via `TransferScreen::on_key`'s enqueue path.
    #[must_use]
    pub fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked
            .get(self.selected)
            .and_then(|&i| self.entries.get(i))
    }

    /// The number of entries currently surviving the filter (`ranked.len()`).
    /// The search box renders this as the `matched` half of `matched/total`.
    /// Pure.
    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.ranked.len()
    }

    /// The entry at display position `ranked_idx` (0-based), or `None` when the
    /// index is out of the ranked list. The screen uses this to render each
    /// visible row without re-deriving the ranked → entry mapping. Pure.
    #[must_use]
    pub fn entry_at_rank(&self, ranked_idx: usize) -> Option<&DirEntry> {
        self.ranked
            .get(ranked_idx)
            .and_then(|&i| self.entries.get(i))
    }

    /// Re-rank `entries` for the current `query` via the shared nucleo helper
    /// (one-field rows, all-zero scores). Empty query yields every entry in its
    /// sorted order. Pure: no I/O. Mirrors [`file_picker`]'s `recompute`.
    ///
    /// Reachability: called by `set_entries` + `on_key`. Both are Task-9 paths.
    ///
    /// [`file_picker`]: crate::tui::file_picker::FilePicker
    /// Live root: `on_key`/`set_entries` → Task 10's loop.
    fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    /// Clamp the cursor into `ranked` bounds (no-op when empty). Pure.
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key` → Task 10's loop.
    fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the cursor by `delta` with wrap-around. No-op when ranked is empty.
    /// Pure.
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key` → Task 10's loop.
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
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key`/`on_enter` → Task 10's loop.
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
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key` → Task 10's loop.
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
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key` → Task 10's loop.
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
    ///
    /// Reachability: called by `on_key`. Task-9 path.
    /// Live root: `on_key` → Task 10's loop.
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
///
/// Reachability: called by `on_enter` (Task-9 path).
/// Live root: `on_enter` → `on_key` → Task 10's loop.
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

// Per-pane navigation/filter/mark unit tests live in a sibling file via
// `#[path]` so this module stays under the 800-line guideline. The split is
// mechanical — the tests are inline-equivalent (they reach into `super::*`
// private items the same way an inline `mod tests` would). Mirrors the
// screen.rs / screen_tests.rs split.
#[cfg(test)]
#[path = "pane_tests.rs"]
mod tests;
