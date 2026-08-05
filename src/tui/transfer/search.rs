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
    /// Last search error, if any (e.g. unreadable directory). Render-only.
    pub error: Option<String>,
}

impl PaneSearch {
    /// Fresh search state: no results yet, cursor at 0, `searching` true (a
    /// search is about to start or is in flight).
    pub(crate) fn empty() -> Self {
        Self {
            results: vec![],
            cursor: 0,
            searching: true,
            error: None,
        }
    }

    /// The match under the cursor, or `None` when there are no results.
    #[must_use]
    pub(crate) fn selected(&self) -> Option<&PathMatch> {
        self.results.get(self.cursor)
    }

    /// Move the result cursor by `delta`, wrapping around the result list.
    /// An empty result list pins the cursor at 0.
    pub(crate) fn move_cursor(&mut self, delta: i32) {
        if self.results.is_empty() {
            self.cursor = 0;
            return;
        }
        let n = self.results.len() as i32;
        self.cursor = ((self.cursor as i32 + delta).rem_euclid(n)) as usize;
    }

    /// Range of result indices to render for a viewport of `rows` rows, using
    /// the same focus-following window as the directory browser so scroll
    /// behavior stays identical between filter and find modes.
    #[must_use]
    pub(crate) fn visible_window(&self, rows: usize) -> Range<usize> {
        focus_window(self.results.len(), self.cursor, rows)
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
}
