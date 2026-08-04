//! Cross-directory find dispatch for [`TransferScreen`]: streamed
//! search-event handling, filter↔find mode switching, and search-result
//! actions (jump / mark / enqueue / cancel). Extracted mechanically from
//! `screen.rs` so that module stays under the 800-line guideline; behavior is
//! unchanged — this is a second `impl TransferScreen` block, not a new type.
//!
//! Methods kept private to this block (`pane_mut`, `enqueue_from_search`) are
//! called only by other methods here. The `pub(crate)` methods are called from
//! `screen.rs` (`on_key` / `route_to_focused`); `pub` methods (`apply_search_event`,
//! `jump_to_search_result`) are the run-loop / external entry points.

use std::path::PathBuf;

use sshrack_core::connect::sftp::proto::{Direction, TransferJob};
use sshrack_core::dirsource::{DirSource, LocalDirSource};
use sshrack_core::pathfind::{SearchEvent, SearchEventKind, parse_query, rank_matches};

use crate::tui::transfer::pane::{Pane, Side};
use crate::tui::transfer::screen::{ScreenOutcome, TransferScreen};
use crate::tui::transfer::search::PaneSearch;

impl TransferScreen {
    /// Mutable accessor by side (focus-agnostic). Returns `Some` for both
    /// `Side::Local` and `Side::Remote` — both panes always exist; the `Option`
    /// lets callers defensive-match rather than `expect` at every site.
    fn pane_mut(&mut self, side: Side) -> Option<&mut Pane> {
        match side {
            Side::Local => Some(&mut self.local),
            Side::Remote => Some(&mut self.remote),
        }
    }

    /// Apply one streamed search event to the named pane's search state. The
    /// run loop (Task 9) calls this for each event drained from
    /// [`search_rx`](Self::search_rx). Stale events (`ev.gen ≠ search_gen`) are
    /// dropped so results from a superseded query never reach the pane. Pure:
    /// no I/O.
    #[allow(dead_code)] // Task 9 run-loop drain is the production caller.
    pub fn apply_search_event(&mut self, side: Side, ev: SearchEvent) {
        if ev.r#gen != self.search_gen {
            return;
        }
        let Some(pane) = self.pane_mut(side) else {
            return;
        };
        let Some(srch) = pane.search.as_mut() else {
            return;
        };
        match ev.kind {
            SearchEventKind::Match(m) => {
                srch.results.push(m);
                rank_matches(&mut srch.results);
                // Re-clamp the cursor into bounds after append + re-rank.
                srch.set_results(srch.results.clone());
            }
            SearchEventKind::Done { .. } => srch.searching = false,
            SearchEventKind::Error(msg) => {
                srch.searching = false;
                srch.error = Some(msg);
            }
        }
    }

    /// Re-evaluate filter-vs-find mode after the focused pane's query changed.
    /// Single-segment-or-empty queries with `base == cwd` stay in filter mode
    /// (the synchronous `core.recompute` already handles them); multi-segment
    /// or out-of-cwd queries enter find mode (set `pane.search`, clear its
    /// results, and stash `pending_search` for the run loop to launch). Pure:
    /// no I/O.
    pub(crate) fn search_request(&mut self, side: Side, query: String) {
        if query.is_empty() {
            self.pane_mut(side)
                .expect("invariant: side is a valid pane")
                .search = None;
            return;
        }
        let (cwd, home) = match side {
            Side::Local => (self.local.core.cwd.clone(), LocalDirSource::new().home()),
            Side::Remote => (self.remote.core.cwd.clone(), self.remote_home.clone()),
        };
        let parsed = parse_query(&query, &cwd, home.as_deref());
        let is_filter = parsed.segments.len() <= 1 && parsed.base == cwd;
        let launch = if is_filter {
            None
        } else {
            Some((side, parsed))
        };
        {
            let pane = self
                .pane_mut(side)
                .expect("invariant: side is a valid pane");
            if is_filter {
                pane.search = None;
            } else {
                let srch = pane.search.get_or_insert_with(PaneSearch::empty);
                srch.searching = true;
                srch.error = None;
                srch.results.clear();
                srch.cursor = 0;
            }
        }
        self.pending_search = launch;
    }

    /// `Enter` on a search result: jump to its directory (the match itself for
    /// a dir, the parent for a file), clear the search + query, and set
    /// [`pending_list`](Self::pending_list) so the run loop lists the target.
    /// MVP: the cursor lands on the directory's remembered position (not
    /// auto-located on the match file — a future enhancement).
    pub fn jump_to_search_result(&mut self) -> ScreenOutcome {
        let focus = self.focus;
        let Some(target) = self
            .pane_mut(focus)
            .expect("invariant: focus is a valid pane")
            .search
            .as_ref()
            .and_then(|s| s.selected().map(|m| (m.path.clone(), m.is_dir)))
        else {
            return ScreenOutcome::Continue;
        };
        let dir = if target.1 {
            target.0.clone()
        } else {
            target
                .0
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| target.0.clone())
        };
        {
            let pane = self
                .pane_mut(focus)
                .expect("invariant: focus is a valid pane");
            pane.search = None;
            pane.core.query.clear();
            pane.core.recompute();
        }
        self.pending_list = Some((focus, dir));
        ScreenOutcome::Continue
    }

    /// `Space` on a search result: mark its path (reuses `Pane.core.marked` so
    /// the existing mark-rendering + enqueue-from-marks path works unchanged).
    pub(crate) fn search_mark_focused(&mut self) {
        let focus = self.focus;
        let Some(path) = self
            .pane_mut(focus)
            .expect("invariant: focus is a valid pane")
            .search
            .as_ref()
            .and_then(|s| s.selected().map(|m| m.path.clone()))
        else {
            return;
        };
        self.focused_pane_mut().core.marked.insert(path);
    }

    /// `Ctrl-S` / `Ctrl-Enter` on search results: enqueue marked (or selected)
    /// matches. Mirrors [`enqueue_from_focused`](Self::enqueue_from_focused)
    /// but sources its specs from the search results instead of the dir
    /// listing. `size_total` is `None` because `PathMatch` does not carry
    /// size. Marks are single-shot (cleared after enqueue).
    fn enqueue_from_search(&mut self) -> ScreenOutcome {
        let focus = self.focus;
        let direction = match focus {
            Side::Local => Direction::Upload,
            Side::Remote => Direction::Download,
        };
        let dst_cwd = match focus {
            Side::Local => self.remote.core.cwd.clone(),
            Side::Remote => self.local.core.cwd.clone(),
        };
        let mut specs: Vec<(PathBuf, bool)> = Vec::new();
        {
            let pane = self.focused_pane();
            let Some(srch) = pane.search.as_ref() else {
                return ScreenOutcome::Continue;
            };
            if !pane.core.marked.is_empty() {
                for m in &srch.results {
                    if pane.core.marked.contains(&m.path) {
                        specs.push((m.path.clone(), m.is_dir));
                    }
                }
            } else if let Some(m) = srch.selected() {
                specs.push((m.path.clone(), m.is_dir));
            }
        }
        if specs.is_empty() {
            return ScreenOutcome::Continue;
        }
        self.focused_pane_mut().core.marked.clear();
        for (path, is_dir) in specs {
            let name = path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.clone());
            let dst = dst_cwd.join(&name);
            self.ledger.enqueue(TransferJob {
                direction,
                src: path,
                dst,
                name: name.to_string_lossy().into_owned(),
                size_total: None,
                recursive: is_dir,
            });
        }
        ScreenOutcome::Enqueue
    }

    /// `Esc` in find mode: cancel the in-flight search (flip the cancel flag
    /// the run loop installed) and drop back to filter mode. The query text is
    /// left intact so the user can edit and re-trigger.
    pub(crate) fn cancel_search(&mut self) {
        if let Some(cancel) = &self.search_cancel {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.search_rx = None;
        self.search_cancel = None;
        let focus = self.focus;
        if let Some(pane) = self.pane_mut(focus) {
            pane.search = None;
        }
    }

    /// Unified enqueue entry: search results when a search is active on the
    /// focused pane, else the dir-listing path. Keeps `on_key` agnostic of the
    /// current mode.
    pub(crate) fn enqueue_focused(&mut self) -> ScreenOutcome {
        if self.focused_pane().search.is_some() {
            self.enqueue_from_search()
        } else {
            self.enqueue_from_focused()
        }
    }
}
