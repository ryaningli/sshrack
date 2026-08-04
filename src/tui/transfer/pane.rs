//! One side of the dual-pane transfer screen (`sshrack sftp`). A [`Pane`] is
//! now a thin shell over [`crate::tui::browser_core::BrowserCore`]: it owns
//! the SFTP-specific `loading` flag and the transfer-specific outcome
//! semantics, and delegates all navigation / fuzzy filter / mark /
//! cursor-memory logic to the core it shares with [`crate::tui::file_picker`].
//! That shared core is what keeps the two browsers' navigation identical.
//!
//! Mark scope: marks belong to the CURRENT directory only. The screen calls
//! [`Pane::on_step`] right before [`Pane::set_entries`] when stepping into or
//! out of a directory; the core clears marks (and the query and cursor) on
//! `begin_switch` so a stale mark never survives a directory change.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use sshrack_core::dirsource::DirEntry;
use sshrack_core::pathutil::{FilterIntent, expand_tilde, parse_filter_intent};

use crate::tui::browser_core::{BrowserCore, NavDecision};
use crate::tui::transfer::search::PaneSearch;

/// Which side of the transfer screen a [`Pane`] drives. Pure label — the pane
/// does not branch on it; the screen renders each side differently and routes
/// side effects (local: inline list; remote: worker List) by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The local filesystem side.
    Local,
    /// The remote (SFTP) side.
    Remote,
}

/// Pure intent returned by [`Pane::on_key`]. The pane mutates only its own
/// core state; this intent tells the screen what side effect to perform
/// (worker List, transfer enqueue, focus switch). Kept enum-shaped (not
/// `Option<PaneOutcome>`) so the screen's match is exhaustive over the action
/// vocabulary — adding a new action is a compile error everywhere it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneOutcome {
    /// The key was consumed but no side effect is needed.
    None,
    /// The filter query changed — re-render the search box.
    QueryChanged,
    /// The cursor entry is a directory; the screen lists it. Carries the
    /// absolute dir path.
    StepInto(PathBuf),
    /// The user asked to go to the parent directory. Emitted only when `cwd`
    /// has a parent.
    StepUp,
    /// A file (or directory) was activated with `Enter`/`Right` — reserved
    /// for transfer enqueue at screen level.
    ActivateSelected,
    /// The user toggled the mark on `path` (file or dir).
    ToggleMark(PathBuf),
    /// A path-like query was resolved to an absolute directory path; the
    /// screen lists it. `~` with no `HOME` emits `None`.
    RequestList(PathBuf),
}

/// One side of the dual-pane transfer screen: a [`BrowserCore`] plus the
/// SFTP-specific `loading` flag. Pure — no I/O. The screen feeds entries via
/// [`Pane::set_entries`]; the pane never lists on its own.
#[derive(Debug, Clone)]
pub struct Pane {
    /// Shared browser state (cwd, entries, query, cursor, marks, history).
    pub(crate) core: BrowserCore,
    /// Pending-list indicator the screen toggles around `set_entries`.
    /// Render-only; the pane never mutates it.
    pub loading: bool,
    /// Active cross-directory find state. `None` in filter mode (≤1 query
    /// segment); `Some` in find mode (>1 segment). The screen sets/clears
    /// this from `parse_query(core.query)`; the pane only reads it to route
    /// keys (arrows move the SEARCH cursor, not the dir-list cursor) and to
    /// report `QueryChanged` when the query text changes.
    pub(crate) search: Option<PaneSearch>,
}

impl Pane {
    /// Open a pane at `cwd` with an empty listing. The screen feeds the first
    /// listing via [`Pane::set_entries`]. Pure: no I/O.
    #[must_use]
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            core: BrowserCore::new(cwd),
            loading: false,
            search: None,
        }
    }

    /// Replace the listing and finish a dir-switch (the screen called
    /// [`Pane::on_step`] first) or an in-place refresh. Delegates to
    /// [`BrowserCore::finish_switch`]. Pure: no I/O.
    pub fn set_entries(&mut self, entries: Vec<DirEntry>) {
        self.core.finish_switch(entries);
    }

    /// Begin a directory switch: snapshot the outgoing cursor, clear
    /// marks/query/selected. The screen calls this right before it updates
    /// `core.cwd` and fetches the new listing. Pure.
    pub fn on_step(&mut self) {
        self.core.begin_switch();
    }

    /// Revert a switch whose listing failed: restore `core.cwd` to the
    /// pre-switch directory, keep that directory's entries, and restore the
    /// remembered cursor — as if the navigation never happened. The run loop
    /// calls this when a `pending_list` resolves to a list error (local fs or
    /// remote worker) so the pane cannot sit on an unreachable path while still
    /// showing the previous listing (the "wrong directory" transfer bug).
    /// Delegates to [`BrowserCore::revert_switch`]. Pure.
    pub fn revert_switch(&mut self) {
        self.core.revert_switch();
    }

    /// Pure key handler. Mutates only the core and returns the side effect the
    /// screen should perform. Performs no I/O and reads no env except `HOME`
    /// (for `~`-expansion of a path-like `Enter`). `Space` is intercepted here
    /// for mark-toggle (before the core, which would otherwise append it to
    /// the query).
    pub fn on_key(&mut self, key: KeyEvent) -> PaneOutcome {
        if key.kind != KeyEventKind::Press {
            return PaneOutcome::None;
        }
        // Find mode: when a cross-directory search is active on this pane,
        // route keys to the search-result handler instead of the dir-list one.
        // Arrows move the SEARCH cursor; query edits still go to core.query.
        // Tab/Esc/Ctrl-S/Ctrl-Q/Ctrl-C never reach here — the screen
        // intercepts them before delegating.
        if self.search.is_some() {
            return self.on_search_key(key);
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Space → toggle mark (Pane-specific). Must precede apply_nav_key,
        // which treats Space as a query char.
        if key.code == KeyCode::Char(' ') && !ctrl {
            return match self.core.toggle_mark_selected() {
                Some(path) => PaneOutcome::ToggleMark(path),
                None => PaneOutcome::None,
            };
        }
        if let Some(decision) = self.core.apply_nav_key(key) {
            return match decision {
                NavDecision::CursorMoved | NavDecision::Noop => PaneOutcome::None,
                NavDecision::QueryChanged => PaneOutcome::QueryChanged,
                NavDecision::StepUp => self.step_up_intent(),
            };
        }
        // Unhandled by the core: Enter / Right (activation, component-specific).
        match key.code {
            KeyCode::Right => self.activate_or_step(),
            KeyCode::Enter => self.on_enter(),
            _ => PaneOutcome::None,
        }
    }

    /// Key handling while a cross-directory search is active on this pane.
    /// Arrows (and Ctrl-P/N) move the SEARCH result cursor; query-edit keys
    /// delegate to [`BrowserCore::apply_nav_key`] (which edits `core.query`)
    /// and surface [`PaneOutcome::QueryChanged`] when the text changed;
    /// `Space`/`Enter`/`Right` return [`PaneOutcome::None`] so the screen
    /// acts on the selected result. `Tab`/`Esc`/`Ctrl-S`/`Ctrl-Q`/`Ctrl-C`
    /// never reach here — the screen intercepts them first.
    ///
    /// The query stays unified in `core.query`: this method does NOT carry a
    /// second query field on `PaneSearch`. Both filter mode (≤1 segment) and
    /// find mode (>1 segment) edit the same `core.query`.
    fn on_search_key(&mut self, key: KeyEvent) -> PaneOutcome {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Bare arrows always move the search cursor; Ctrl-P/N are the same
            // motion. Kept as separate arms (not `Up | Char('p') if ctrl`)
            // because a guard on a `|`-pattern applies to BOTH alternatives —
            // collapsing them would require Ctrl for a bare Up.
            KeyCode::Up => {
                self.move_search_cursor(-1);
                PaneOutcome::None
            }
            KeyCode::Down => {
                self.move_search_cursor(1);
                PaneOutcome::None
            }
            KeyCode::Char('p') if ctrl => {
                self.move_search_cursor(-1);
                PaneOutcome::None
            }
            KeyCode::Char('n') if ctrl => {
                self.move_search_cursor(1);
                PaneOutcome::None
            }
            // Space marks the selected result; Enter/Right jump — the screen
            // handles both. Returning None lets the screen read
            // `pane.search.as_ref().and_then(|s| s.selected())`.
            KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Right => PaneOutcome::None,
            // Query edit (printable, Backspace, Left-for-parent): delegate to
            // core, which edits core.query and returns QueryChanged when the
            // text changed. The screen re-runs parse_query on QueryChanged
            // and may flip this pane back to filter mode (search = None).
            _ => match self.core.apply_nav_key(key) {
                Some(NavDecision::QueryChanged) => PaneOutcome::QueryChanged,
                Some(_) => PaneOutcome::None,
                None => PaneOutcome::None,
            },
        }
    }

    /// Move the find-result cursor by `delta` (wraps). No-op if the search
    /// state is gone (defensive — the `on_key` guard keeps it `Some` for the
    /// duration of a search-key call).
    fn move_search_cursor(&mut self, delta: i32) {
        if let Some(srch) = self.search.as_mut() {
            srch.move_cursor(delta);
        }
    }

    /// Range of `ranked` indices to render for a viewport of `rows` rows.
    #[must_use]
    pub fn visible_window(&self, rows: usize) -> std::ops::Range<usize> {
        self.core.visible_window(rows)
    }

    /// The entry under the cursor, or `None`.
    #[must_use]
    pub fn selected_entry(&self) -> Option<&DirEntry> {
        self.core.selected_entry()
    }

    /// The number of entries currently surviving the filter.
    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.core.matched_count()
    }

    /// The entry at display position `ranked_idx`.
    #[must_use]
    pub fn entry_at_rank(&self, ranked_idx: usize) -> Option<&DirEntry> {
        self.core.entry_at_rank(ranked_idx)
    }

    /// `Right` / `Enter`-on-fuzzy activation: dirs → [`StepInto`](PaneOutcome::StepInto),
    /// files → [`ActivateSelected`](PaneOutcome::ActivateSelected). Empty cursor → `None`.
    fn activate_or_step(&mut self) -> PaneOutcome {
        match self.core.selected_entry() {
            Some(e) if e.is_dir => PaneOutcome::StepInto(e.path.clone()),
            Some(_) => PaneOutcome::ActivateSelected,
            None => PaneOutcome::None,
        }
    }

    /// `Enter`: a path-like query resolves via [`resolve_path_like`] →
    /// [`RequestList`](PaneOutcome::RequestList); a fuzzy query activates the
    /// cursor entry. Pure except `HOME` lookup for `~`.
    fn on_enter(&mut self) -> PaneOutcome {
        match parse_filter_intent(&self.core.query) {
            FilterIntent::PathLike(raw) => match resolve_path_like(&raw, &self.core.cwd) {
                Some(abs) => PaneOutcome::RequestList(abs),
                None => PaneOutcome::None,
            },
            FilterIntent::Fuzzy(_) => self.activate_or_step(),
        }
    }

    /// `Left`: emit [`StepUp`](PaneOutcome::StepUp) when `cwd` has a parent,
    /// [`None`](PaneOutcome::None) at `/`.
    fn step_up_intent(&self) -> PaneOutcome {
        if self.core.cwd.parent().is_some() {
            PaneOutcome::StepUp
        } else {
            PaneOutcome::None
        }
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

// Per-pane unit tests live in a sibling file via `#[path]` so this module
// stays under the 800-line guideline.
#[cfg(test)]
#[path = "pane_tests.rs"]
mod tests;
