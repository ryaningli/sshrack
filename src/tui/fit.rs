//! Pure geometry helpers for overlay content-fitting: a focus-following
//! viewport ([`focus_window`]) and display-width-aware ellipsis truncation
//! ([`truncate_cells`]). Both are pure and unit-tested; renderers consume
//! them so the small-terminal behavior is pinned independently of ratatui.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// The focus-following viewport over `total` items: returns the `[start, end)`
/// range of items to render so that `selected` is always visible and roughly
/// centered, with the window clamped to the `[0, total)` bounds.
///
/// Pure. Renderers (forms, help, picker) consume this so the small-terminal
/// scroll behavior is pinned by tests independent of ratatui.
///
/// - `total == 0` or `visible == 0` → empty range (`0..0`).
/// - `visible >= total` → the full range (`0..total`); everything fits.
/// - `selected` is clamped into `[0, total)` defensively.
// Foundation helpers produced before their callers: the dialog/picker/help
// renderers in later tasks (forms, help overlay, credential picker) consume
// these. `allow` (not `expect`) because the unit tests already call them, so
// `expect` would be flagged "unfulfilled" in the test build; revisit once the
// renderer consumers land.
#[allow(dead_code)]
pub fn focus_window(total: usize, selected: usize, visible: usize) -> std::ops::Range<usize> {
    if total == 0 || visible == 0 {
        return 0..0;
    }
    if visible >= total {
        return 0..total;
    }
    let sel = selected.min(total - 1);
    let half = visible / 2;
    let start = sel.saturating_sub(half).min(total - visible);
    start..start + visible
}

/// Truncate `s` to at most `max` display cells, appending a single `…`
/// (width 1) when anything was dropped. Display width follows Unicode East
/// Asian Width (so CJK glyphs count as 2) via the `unicode-width` crate.
///
/// Pure. `max == 0` → `""`. Input already within budget → returned unchanged.
#[allow(dead_code)]
pub fn truncate_cells(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.width() <= max {
        return s.to_string();
    }
    // Reserve one cell for the ellipsis; fill with as many leading chars as fit.
    let budget = max - 1;
    let mut out = String::new();
    let mut w = 0usize;
    for ch in s.chars() {
        let cw = ch.width().unwrap_or(0);
        if w + cw > budget {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- focus_window ----

    #[test]
    fn focus_window_empty_total_is_empty_range() {
        assert_eq!(focus_window(0, 0, 5), 0..0);
    }

    #[test]
    fn focus_window_visible_ge_total_returns_everything() {
        assert_eq!(focus_window(5, 2, 10), 0..5);
        assert_eq!(focus_window(5, 0, 5), 0..5);
    }

    #[test]
    fn focus_window_keeps_selected_centered_when_room_on_both_sides() {
        // 10 items, window 4, selected 5 → centered start = 5-2 = 3 → 3..7.
        assert_eq!(focus_window(10, 5, 4), 3..7);
    }

    #[test]
    fn focus_window_clamps_to_top_when_selected_near_head() {
        // selected 0 must stay in-window without a negative start.
        assert_eq!(focus_window(10, 0, 4), 0..4);
        assert_eq!(focus_window(10, 1, 4), 0..4);
    }

    #[test]
    fn focus_window_clamps_to_bottom_when_selected_near_tail() {
        // selected at last item → window hugs the tail.
        assert_eq!(focus_window(10, 9, 4), 6..10);
        assert_eq!(focus_window(10, 8, 4), 6..10);
    }

    #[test]
    fn focus_window_clamps_selected_that_exceeds_total() {
        // Defensive: an out-of-range selected is pulled back to the last item.
        assert_eq!(focus_window(10, 99, 4), 6..10);
    }

    #[test]
    fn focus_window_zero_visible_is_empty() {
        assert_eq!(focus_window(10, 5, 0), 0..0);
    }

    // ---- truncate_cells ----

    #[test]
    fn truncate_cells_zero_max_is_empty() {
        assert_eq!(truncate_cells("abc", 0), "");
    }

    #[test]
    fn truncate_cells_under_max_returns_input_unchanged() {
        assert_eq!(truncate_cells("abc", 10), "abc");
        assert_eq!(truncate_cells("abc", 3), "abc");
    }

    #[test]
    fn truncate_cells_over_max_appends_ellipsis() {
        assert_eq!(truncate_cells("abcdef", 4), "abc…");
    }

    #[test]
    fn truncate_cells_max_one_yields_just_ellipsis_when_first_char_fits() {
        // width budget 1 → can't show any payload char + ellipsis, so just …
        assert_eq!(truncate_cells("abc", 1), "…");
    }

    #[test]
    fn truncate_cells_counts_wide_chars_as_two_cells() {
        // 中/文 are width 2 each. Budget 3 → one wide char (2) + … = "中…".
        assert_eq!(truncate_cells("中文", 3), "中…");
    }

    #[test]
    fn truncate_cells_wide_char_fitting_exactly_is_kept() {
        assert_eq!(truncate_cells("中", 2), "中");
    }
}
