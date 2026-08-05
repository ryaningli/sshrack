//! TUI-side glue for cross-directory find: the `nucleo-matcher`-backed
//! [`SegmentMatcher`] (core stays nucleo-free), plus the per-pane search
//! result state ([`PaneSearch`]) that the transfer pane overlays on top of
//! `BrowserCore` while a find query is active. Matching mirrors
//! `crate::tui::panel::match_indices` — same `Pattern::parse` + `indices`
//! call — but applied per path segment.
//!
//! [`SegmentMatcher`]: sshrack_core::pathfind::SegmentMatcher

use std::ops::Range;

use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};

use crate::tui::fit::focus_window;
use sshrack_core::pathfind::{PathMatch, SegmentMatcher, SegmentScore};

/// `SegmentMatcher` backed by `nucleo-matcher`. One fresh `Matcher` per call
/// (state is cheap; `Matcher::new` is a small allocation).
///
/// Constructed once in `App::new` and shared via `Arc` across search launches
/// (Task 9 run loop calls `PathSearch::launch` with a clone of it).
pub(crate) struct NucleoSegmentMatcher;

impl SegmentMatcher for NucleoSegmentMatcher {
    fn match_segment(&self, name: &str, seg: &str) -> Option<SegmentScore> {
        if seg.is_empty() {
            return Some(SegmentScore {
                score: 0,
                indices: vec![],
            });
        }
        let mut matcher = Matcher::new(Config::DEFAULT);
        let pattern = Pattern::parse(seg, CaseMatching::Smart, Normalization::Smart);
        let mut indices: Vec<u32> = Vec::new();
        let score =
            pattern.indices(Utf32Str::Ascii(name.as_bytes()), &mut matcher, &mut indices)?;
        // nucleo appends per-atom indices without sort/dedup (see panel.rs).
        indices.sort_unstable();
        indices.dedup();
        Some(SegmentScore { score, indices })
    }
}

/// Per-pane search result state, overlaid on a [`crate::tui::browser_core::BrowserCore`]
/// while a cross-directory find query is active. The query itself lives in the
/// core's unified `query` field — this struct holds only the result side: the
/// ranked matches, the cursor over them, and the pending/error flags the
/// renderer reads.
///
/// Mode switching is the screen's job, not the pane's: the screen reads
/// `core.query`, runs `parse_query`, and sets `pane.search = Some(...)` for
/// find mode (a trailing slash, any multi-segment query, or any out-of-cwd
/// base) or `None` for filter mode (a plain single name in the cwd). The pane
/// just reports `PaneOutcome::QueryChanged` when the query text changes and
/// routes arrows to the SEARCH cursor while `search` is `Some`.
#[derive(Debug, Clone)]
pub(crate) struct PaneSearch {
    /// Ranked find results across directories (one `PathMatch` per hit).
    pub results: Vec<PathMatch>,
    /// Cursor over `results` (wraps on move). Rendered highlighted.
    pub cursor: usize,
    /// True while a search is in flight (debounce window or worker drain
    /// pending). Render-only signal; the pane never mutates it.
    pub searching: bool,
    /// The generation that produced the `results` currently held, or `None`
    /// when no results are held. The first event of a NEW generation
    /// (`results_gen != Some(ev.gen)`) clears `results` before applying — so a
    /// stale event from the PREVIOUS generation that drains after the user
    /// retypes (but before the new search launches and bumps `search_gen`) can
    /// never concatenate with the new generation's hits. Until that first new
    /// event lands the previous query's results stay visible
    /// (stale-while-revalidate), so the list does not flash to "searching…" on
    /// every keystroke.
    pub results_gen: Option<u32>,
    /// Last search error, if any (e.g. unreadable directory). Render-only.
    pub error: Option<String>,
    /// The synthetic "." (current-directory) row, set when a trailing-slash
    /// find drilled successfully into a directory (a `Drilled` event arrived).
    /// `Some` ⇒ the rendered list has "." pinned at index 0: `selected()`
    /// returns this `PathMatch` for cursor 0, so Enter/enqueue treat "." as a
    /// normal directory (Enter navigates into the drilled dir). `None` ⇒ no
    /// "." row (leaf search, drill failure, or before the first event).
    pub current_dir: Option<PathMatch>,
}

impl PaneSearch {
    /// Fresh search state: no results yet, cursor at 0, `searching` true (a
    /// search is about to start or is in flight), `results_gen` `None` (no
    /// generation has produced results yet).
    pub(crate) fn empty() -> Self {
        Self {
            results: vec![],
            cursor: 0,
            searching: true,
            results_gen: None,
            error: None,
            current_dir: None,
        }
    }

    /// Number of rendered rows: the results plus the synthetic "." row when
    /// present. The cursor, `visible_window`, and render loop all key off this.
    #[must_use]
    pub(crate) fn display_len(&self) -> usize {
        self.results.len() + usize::from(self.current_dir.is_some())
    }

    /// True when the cursor sits on the synthetic "." row (cursor 0 with a
    /// current-dir entry present). Used to suppress Tab completion on ".".
    //
    // `allow(dead_code)`: no production caller yet — wired in a later task
    // (Tab-completion suppression on the "." row). Tests exercise it today, so
    // `#[expect(dead_code)]` would be unfulfilled under `--all-targets`; remove
    // this attribute when the first production caller lands.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn on_dot(&self) -> bool {
        self.cursor == 0 && self.current_dir.is_some()
    }

    /// The match under the cursor, or `None` when the list is empty. Cursor 0
    /// returns the synthetic "." `PathMatch` when `current_dir` is set; the
    /// dot shifts result indices by one.
    #[must_use]
    pub(crate) fn selected(&self) -> Option<&PathMatch> {
        let has_dot = self.current_dir.is_some();
        if has_dot && self.cursor == 0 {
            return self.current_dir.as_ref();
        }
        let idx = self.cursor.saturating_sub(usize::from(has_dot));
        self.results.get(idx)
    }

    /// Move the cursor by `delta`, wrapping around the full display list
    /// (results + the "." row when present). An empty list pins the cursor at 0.
    pub(crate) fn move_cursor(&mut self, delta: i32) {
        let n = self.display_len();
        if n == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = ((self.cursor as i32 + delta).rem_euclid(n as i32)) as usize;
    }

    /// Range of display indices to render for a viewport of `rows` rows, using
    /// the same focus-following window as the directory browser so scroll
    /// behavior stays identical between filter and find modes.
    #[must_use]
    pub(crate) fn visible_window(&self, rows: usize) -> Range<usize> {
        focus_window(self.display_len(), self.cursor, rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::pathfind::SegmentMatcher;

    #[test]
    fn matches_subsequence_and_returns_indices() {
        let m = NucleoSegmentMatcher;
        let s = m.match_segment("apath", "ap").expect("ap matches apath");
        assert!(s.score > 0);
        assert!(s.indices.contains(&0), "first matched char is at index 0");
    }

    #[test]
    fn no_match_returns_none() {
        let m = NucleoSegmentMatcher;
        assert!(m.match_segment("xyz", "abc").is_none());
    }

    #[test]
    fn empty_segment_matches_all_zero_score() {
        let m = NucleoSegmentMatcher;
        let s = m.match_segment("anything", "").expect("empty seg matches");
        assert_eq!(s.score, 0);
        assert!(s.indices.is_empty());
    }

    // ---- PaneSearch ----

    use sshrack_core::pathfind::PathMatch;
    use std::path::PathBuf;

    #[test]
    fn pane_search_move_cursor_wraps() {
        let mut s = super::PaneSearch::empty();
        s.results = vec![
            PathMatch {
                path: PathBuf::from("/x/a"),
                is_dir: false,
                seg_matches: vec![],
            },
            PathMatch {
                path: PathBuf::from("/x/b"),
                is_dir: false,
                seg_matches: vec![],
            },
        ];
        assert_eq!(s.cursor, 0);
        s.move_cursor(1);
        assert_eq!(s.cursor, 1);
        s.move_cursor(1); // wrap
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn pane_search_visible_window_bounds_cursor() {
        let mut s = super::PaneSearch::empty();
        s.results = (0..50)
            .map(|i| PathMatch {
                path: PathBuf::from(format!("/x/{i}")),
                is_dir: false,
                seg_matches: vec![],
            })
            .collect();
        s.cursor = 40;
        let win = s.visible_window(10);
        assert!(win.start <= 40 && 40 < win.end);
    }

    fn dot_match(path: &str) -> PathMatch {
        PathMatch {
            path: PathBuf::from(path),
            is_dir: true,
            seg_matches: vec![],
        }
    }

    #[test]
    fn display_len_counts_the_dot_row() {
        let mut s = super::PaneSearch::empty();
        assert_eq!(s.display_len(), 0, "no results, no dot");
        s.current_dir = Some(dot_match("/srv/a"));
        assert_eq!(s.display_len(), 1, "dot only, no results");
        s.results = vec![
            PathMatch {
                path: PathBuf::from("/srv/a/x"),
                is_dir: false,
                seg_matches: vec![],
            },
            PathMatch {
                path: PathBuf::from("/srv/a/y"),
                is_dir: false,
                seg_matches: vec![],
            },
        ];
        assert_eq!(s.display_len(), 3, "dot + 2 results");
    }

    #[test]
    fn selected_returns_dot_at_cursor_zero_then_results() {
        let mut s = super::PaneSearch::empty();
        s.current_dir = Some(dot_match("/srv/a"));
        s.results = vec![PathMatch {
            path: PathBuf::from("/srv/a/x"),
            is_dir: false,
            seg_matches: vec![],
        }];
        // cursor 0 → the dot row (the drilled dir).
        assert_eq!(s.selected().unwrap().path, PathBuf::from("/srv/a"));
        assert!(s.selected().unwrap().is_dir);
        // cursor 1 → results[0].
        s.cursor = 1;
        assert_eq!(s.selected().unwrap().path, PathBuf::from("/srv/a/x"));
        assert!(!s.selected().unwrap().is_dir);
    }

    #[test]
    fn selected_without_dot_behaves_unchanged() {
        let mut s = super::PaneSearch::empty();
        s.results = vec![PathMatch {
            path: PathBuf::from("/x/a"),
            is_dir: false,
            seg_matches: vec![],
        }];
        // No dot: cursor 0 maps straight to results[0] (pre-existing behavior).
        assert_eq!(s.selected().unwrap().path, PathBuf::from("/x/a"));
    }

    #[test]
    fn move_cursor_wraps_over_dot_plus_results() {
        let mut s = super::PaneSearch::empty();
        s.current_dir = Some(dot_match("/srv/a"));
        s.results = vec![
            PathMatch {
                path: PathBuf::from("/srv/a/x"),
                is_dir: false,
                seg_matches: vec![],
            },
            PathMatch {
                path: PathBuf::from("/srv/a/y"),
                is_dir: false,
                seg_matches: vec![],
            },
        ];
        // display_len = 3 (dot + x + y). cursor 0 → 1 → 2 → wrap → 0.
        assert_eq!(s.cursor, 0);
        s.move_cursor(1);
        assert_eq!(s.cursor, 1);
        s.move_cursor(1);
        assert_eq!(s.cursor, 2);
        s.move_cursor(1); // wrap
        assert_eq!(s.cursor, 0, "wraps past the last result back to the dot");
    }

    #[test]
    fn move_cursor_empty_with_dot_stays_on_dot() {
        let mut s = super::PaneSearch::empty();
        s.current_dir = Some(dot_match("/srv/a")); // empty existing dir
        s.move_cursor(1);
        assert_eq!(s.cursor, 0, "display_len=1 → cursor pinned to the dot");
        s.move_cursor(-1);
        assert_eq!(s.cursor, 0);
    }

    #[test]
    fn on_dot_only_when_cursor_zero_and_dot_present() {
        let mut s = super::PaneSearch::empty();
        assert!(!s.on_dot());
        s.current_dir = Some(dot_match("/srv/a"));
        assert!(s.on_dot(), "cursor 0 + dot → on_dot");
        s.cursor = 1;
        assert!(!s.on_dot(), "moved off the dot");
    }
}
