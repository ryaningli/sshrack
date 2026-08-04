//! TUI-side glue for cross-directory find: the `nucleo-matcher`-backed
//! [`SegmentMatcher`] (core stays nucleo-free), plus the per-pane search state
//! added in later tasks. Matching mirrors `crate::tui::panel::match_indices` —
//! same `Pattern::parse` + `indices` call — but applied per path segment.
//!
//! [`SegmentMatcher`]: sshrack_core::pathfind::SegmentMatcher

use nucleo_matcher::{
    Config, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};

use sshrack_core::pathfind::{SegmentMatcher, SegmentScore};

/// `SegmentMatcher` backed by `nucleo-matcher`. One fresh `Matcher` per call
/// (state is cheap; `Matcher::new` is a small allocation).
///
/// Constructed for the first time in Task 9's run loop (`PathSearch::launch`
/// injection); until then `dead_code` would fire under `--all-targets`.
#[allow(dead_code)]
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
}
