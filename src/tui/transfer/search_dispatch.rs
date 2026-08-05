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
    /// run loop calls this for each event drained from
    /// [`search_rx`](Self::search_rx). Stale events (`ev.gen ≠ search_gen`) are
    /// dropped so results from a superseded query never reach the pane. Pure:
    /// no I/O.
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
        // First event of a generation different from the one that produced the
        // current results: drop the stale results before applying. Gated on
        // the EVENT's generation (== search_gen), not a boolean — so a stale
        // event from the previous generation that drains after search_request
        // (but before the new search launches and bumps search_gen) cannot
        // flip the gate and let the new generation's first hit append to
        // (instead of replace) the old results.
        let first_of_gen = srch.results_gen != Some(ev.r#gen);
        match ev.kind {
            SearchEventKind::Match(m) => {
                if first_of_gen {
                    srch.results.clear();
                    srch.cursor = 0;
                }
                srch.results.push(m);
                rank_matches(&mut srch.results);
                // Re-clamp the cursor into bounds after append + re-rank,
                // in place — no full-results clone per Match event.
                let len = srch.results.len();
                if srch.cursor >= len {
                    srch.cursor = len.saturating_sub(1);
                }
                srch.results_gen = Some(ev.r#gen);
            }
            SearchEventKind::Done => {
                // A search that produced no Match reaches Done as the first
                // event of its generation: clear the stale results so the
                // renderer shows "no matches" instead of the previous query's
                // hits.
                if first_of_gen {
                    srch.results.clear();
                    srch.cursor = 0;
                }
                srch.searching = false;
                srch.results_gen = Some(ev.r#gen);
            }
            SearchEventKind::Error(msg) => {
                srch.searching = false;
                srch.error = Some(msg);
                // Surface the error (the renderer only shows it when results
                // are empty), so drop any stale hits.
                srch.results.clear();
                srch.cursor = 0;
                srch.results_gen = Some(ev.r#gen);
            }
            SearchEventKind::Drilled(_) => {
                // `Drilled` carries the directory a trailing-slash find entered;
                // a later task wires it to `srch.current_dir` (the synthetic "."
                // row). Accepted here only so the match stays exhaustive now
                // that core emits the event.
            }
        }
    }

    /// Re-evaluate filter-vs-find mode after the focused pane's query changed.
    /// A plain single name (no slash) with `base == cwd` stays in filter mode
    /// (the synchronous `core.recompute` already handles it); a trailing slash,
    /// any multi-segment, or an out-of-cwd query enters find mode (set
    /// `pane.search`, mark it `searching`, and stash `pending_search` for the
    /// run loop to launch). Pure: no I/O.
    ///
    /// Stale-while-revalidate: the previous query's `results` AND `results_gen`
    /// are deliberately kept here (not cleared) so the list does not flash to
    /// "search…" on every keystroke. [`apply_search_event`](Self::apply_search_event)
    /// clears the results on the first event whose generation differs from
    /// `results_gen` — gated on the event's generation, not a reset boolean, so
    /// a stale previous-generation event draining in the debounce window
    /// cannot flip the gate ahead of the new generation's first hit.
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
        // Filter mode = a plain single name in the current directory (no slash at all).
        // A trailing slash ("a/") or any multi-segment / out-of-cwd query is find mode.
        let is_filter = !parsed.trailing_slash && parsed.segments.len() == 1 && parsed.base == cwd;
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
                // NOTE: results AND results_gen are intentionally kept (not
                // cleared). The previous query's hits stay visible until the
                // new search's first event lands — stale-while-revalidate, so
                // the list does not flash empty on every keystroke.
                // apply_search_event clears them when an event of a NEW
                // generation (results_gen != Some(ev.gen)) arrives.
            }
        }
        self.pending_search = launch;
    }

    /// `Tab`: complete the focused pane's query from its highlighted
    /// candidate. Returns `true` when a completion was applied (the query was
    /// updated and the find re-launched); `false` when there was nothing to
    /// complete — an empty query or no candidate under the cursor — so the
    /// caller falls back to flipping focus. Pure: no I/O (it mutates only
    /// pane state and stashes `pending_search`, exactly what typing a key does
    /// via `search_request`).
    pub(crate) fn complete_focused(&mut self) -> bool {
        let focus = self.focus;
        let Some(completion) = self.completion_for_focused() else {
            return false;
        };
        {
            let pane = self.focused_pane_mut();
            pane.core.query = completion.clone();
            pane.core.recompute();
        }
        self.search_request(focus, completion);
        true
    }

    /// Compute the query string that completes the focused pane's current
    /// candidate, or `None` when completion does not apply (empty query, a find
    /// search still in flight, or no candidate under the cursor). The single
    /// source of the candidate → query mapping for both pane modes.
    ///
    /// Only the FINAL segment is completed. The prefix the user already typed —
    /// up to and including the last `/` — is preserved verbatim, so the base
    /// syntax survives: `/ho` → `/home/`, `~/do` → `~/documents/`, `../sib` →
    /// `../sibling/`, and a relative drill `aaa/bb` → `aaa/bbb/`. Completing
    /// off `seg_matches` instead would drop the base, since `seg_matches` holds
    /// only the path relative to the query base. The completed segment is the
    /// candidate's last path component, with a trailing `/` appended for a
    /// directory so the completion re-enters find mode and lists that
    /// directory's contents (the exact-drill trailing-slash trigger).
    fn completion_for_focused(&self) -> Option<String> {
        let pane = self.focused_pane();
        let query: &str = &pane.core.query;
        if query.is_empty() {
            return None;
        }
        // Preserve the typed prefix (base syntax + any drilled segments)
        // verbatim; complete only the final segment from the candidate.
        let prefix = query.rfind('/').map(|i| &query[..=i]).unwrap_or("");
        let (last_seg, is_dir) = if let Some(srch) = pane.search.as_ref() {
            // A search is in flight: the visible results are the PREVIOUS
            // query's, kept only to avoid a flash (stale-while-revalidate), so
            // the candidate under the cursor does not belong to the current
            // query. Do not complete off it — return None so Tab is swallowed
            // until the new search yields fresh results.
            if srch.searching {
                return None;
            }
            let pm = srch.selected()?;
            let name = pm.path.file_name()?.to_string_lossy().into_owned();
            (name, pm.is_dir)
        } else {
            let e = pane.selected_entry()?;
            let name = e.name.trim_end_matches('/').to_string();
            (name, e.is_dir)
        };
        Some(if is_dir {
            format!("{prefix}{last_seg}/")
        } else {
            format!("{prefix}{last_seg}")
        })
    }

    /// `Enter` on a DIRECTORY search result: jump into it, clear the search +
    /// query, and set [`pending_list`](Self::pending_list) so the run loop
    /// lists the target. The cursor lands on the target's remembered position.
    /// A FILE result is a no-op here — `on_key` routes file results to
    /// [`enqueue_focused`](Self::enqueue_focused) (Enter on a file transfers,
    /// parity with filter mode), so a file only reaches here via a direct call,
    /// where the safe contract is "do nothing" rather than jump to its parent
    /// (which would discard the user's selected file and force a re-find).
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
        // Only a directory result jumps (into itself). A file result is owned
        // by enqueue; if one reaches here anyway, no-op — never jump to its
        // parent.
        if !target.1 {
            return ScreenOutcome::Continue;
        }
        let dir = target.0;
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

    /// `Ctrl-S` / `Ctrl-Enter` on search results: enqueue the selected match.
    /// Find mode has no marking (the cross-dir `marked` set is a current-dir
    /// concept), so this transfers the cursor result only — a file, or a dir
    /// (recursive). `size_total` is `None` because `PathMatch` does not carry
    /// size. Mirrors [`enqueue_from_focused`](Self::enqueue_from_focused) but
    /// sources its single spec from the search results.
    fn enqueue_from_search(&mut self) -> ScreenOutcome {
        let focus = self.focus;
        let Some((path, is_dir)) = self
            .focused_pane()
            .search
            .as_ref()
            .and_then(|s| s.selected().map(|m| (m.path.clone(), m.is_dir)))
        else {
            return ScreenOutcome::Continue;
        };
        let direction = match focus {
            Side::Local => Direction::Upload,
            Side::Remote => Direction::Download,
        };
        let dst_cwd = match focus {
            Side::Local => self.remote.core.cwd.clone(),
            Side::Remote => self.local.core.cwd.clone(),
        };
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
        ScreenOutcome::Enqueue
    }

    /// Record that `side` now owns the in-flight search. Called by the run
    /// loop once it has bumped `search_gen` and cancelled the previous
    /// worker, just before installing the fresh `search_rx` / `search_cancel`
    /// pair. When a DIFFERENT pane's search is being displaced, that pane's
    /// `searching` flag is cleared here: the displaced worker was just
    /// cancelled and will never emit `Done`, so without this its pane would
    /// spin forever. The displaced pane's stale `results` stay visible
    /// (stale-while-revalidate). Pure: no I/O.
    pub(crate) fn begin_search(&mut self, side: Side) {
        if let Some(prev) = self.search_side
            && prev != side
            && let Some(pane) = self.pane_mut(prev)
            && let Some(srch) = pane.search.as_mut()
        {
            srch.searching = false;
        }
        self.search_side = Some(side);
    }

    /// `Esc` in find mode: cancel the in-flight search (flip the cancel flag
    /// the run loop installed), drop the pane out of find mode, AND clear the
    /// query so the listing returns to the full current directory. filter and
    /// find share `core.query`, and find typing recomputes `core.ranked`
    /// against the cross-dir query (which matches no current-dir name) —
    /// leaving the query intact would render a stale empty list on drop-back.
    /// Esc abandons the search entirely; to retry with edits, type in find
    /// mode (Backspace re-triggers) rather than relying on Esc to keep text.
    pub(crate) fn cancel_search(&mut self) {
        if let Some(cancel) = &self.search_cancel {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        self.search_rx = None;
        self.search_cancel = None;
        // Esc inside the debounce window must not let a stale pending_search
        // fire a background search after the user explicitly cancelled.
        self.pending_search = None;
        // Clear the IN-FLIGHT search's pane (the one whose worker we just
        // stopped), not merely the focused pane — after a Shift-Tab these can
        // differ, and clearing the wrong one would leave the cancelled
        // search's pane stuck in find mode with a dead worker. Fall back to
        // focus when nothing is in flight (defensive; an Esc that takes this
        // path implies a search was active).
        let target = self.search_side.unwrap_or(self.focus);
        if let Some(pane) = self.pane_mut(target) {
            pane.search = None;
        }
        // Clear the find query and recompute so the pane returns to the full
        // current-dir listing (shared with filter-mode Esc via
        // [`clear_query`]). filter/find share core.query, and find typing left
        // core.ranked computed against the cross-dir query (matches no
        // current-dir name); without this, dropping back to filter mode would
        // show that stale empty list until the user Backspaced the query away.
        self.clear_query(target);
        self.search_side = None;
    }

    /// Clear the query on `side`'s pane and recompute so the listing returns
    /// to the full current directory (cursor clamped into range). Shared by
    /// find-mode `Esc` ([`cancel_search`]) and filter-mode `Esc`
    /// ([`TransferScreen::on_key`]) so neither leaves a stale filtered list
    /// behind — both abandon the typed query entirely.
    pub(crate) fn clear_query(&mut self, side: Side) {
        if let Some(pane) = self.pane_mut(side) {
            pane.core.query.clear();
            pane.core.recompute();
            pane.core.clamp_selected();
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
