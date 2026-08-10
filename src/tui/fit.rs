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

/// Display width of `s` in terminal cells, following Unicode East Asian Width
/// (via the `unicode-width` crate). Pure. Use to budget text against a
/// `Rect::width` before passing it to [`truncate_cells`] / [`truncate_cells_head`].
pub fn cells(s: &str) -> usize {
    s.width()
}

/// Left-truncate `s` to at most `max` display cells, prepending a single `…`
/// (width 1) when anything was dropped — the **tail** is preserved, the head is
/// the part that gets cut. Use this when the trailing characters are the ones
/// that carry meaning (e.g. a directory path: `…/.ssh`, not `/home/ry…`).
/// Display width follows Unicode East Asian Width (so CJK glyphs count as 2)
/// via the `unicode-width` crate.
///
/// Pure. `max == 0` → `""`. Input already within budget → returned unchanged.
/// A trailing glyph that does not fit in the remaining budget is dropped
/// (never split), so a CJK glyph is shown whole or not at all.
pub fn truncate_cells_head(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.width() <= max {
        return s.to_string();
    }
    // Reserve one cell for the ellipsis; fill from the end with as many trailing
    // chars as fit. A glyph whose width exceeds the remaining budget is skipped
    // (no half-width rendering of a wide glyph).
    let budget = max - 1;
    let mut kept: Vec<char> = Vec::new();
    let mut w = 0usize;
    for ch in s.chars().rev() {
        let cw = ch.width().unwrap_or(0);
        if w + cw > budget {
            break;
        }
        kept.push(ch);
        w += cw;
    }
    kept.reverse();
    let mut out = String::with_capacity(kept.len() + 1);
    out.push('…');
    out.extend(kept);
    out
}

/// Truncate `s` to at most `max` display cells, appending a single `…`
/// (width 1) when anything was dropped. Display width follows Unicode East
/// Asian Width (so CJK glyphs count as 2) via the `unicode-width` crate.
///
/// Pure. `max == 0` → `""`. Input already within budget → returned unchanged.
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

/// Split `avail` cells between two elastic columns whose ideal widths are
/// `a_need` and `b_need`. Column `a` is the primary label (a host/credential
/// name), `b` the denser payload (an address, a user).
///
/// When both fit (`a_need + b_need <= avail`), `a` takes its need and `b` gets
/// the remainder. When they contend, `a` is capped at `a_share` percent of
/// `avail` so the denser `b` keeps the majority; if that would squeeze `b`
/// below `b_min`, `a` shrinks to defend `b_min`, down to `a_min`. Returns
/// `(a_width, b_width)` with `a_width + b_width == avail` (and `(0, 0)` when
/// `avail == 0`).
///
/// Pure. The host list (a = name, b = address) and the credential list
/// (a = name, b = user) share it so both adapt to the terminal width the
/// same way — no hard-coded column cap.
pub fn column_widths(
    avail: usize,
    a_need: usize,
    b_need: usize,
    a_share: usize,
    a_min: usize,
    b_min: usize,
) -> (usize, usize) {
    if avail == 0 {
        return (0, 0);
    }
    let a_w = if a_need + b_need <= avail {
        a_need
    } else {
        let cap = avail * a_share / 100;
        let mut a = a_need.min(cap);
        if avail - a < b_min {
            // `b` would drop below its floor: hand cells back from `a`, down
            // to `a_min` (if `avail < a_min + b_min`, `a` still holds `a_min`
            // and `b` gets whatever remains — the degenerate narrow case).
            let target = avail.saturating_sub(b_min);
            a = a_min.max(target.min(a_need));
        }
        a
    };
    (a_w, avail - a_w)
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

    // ---- truncate_cells_head ----

    #[test]
    fn truncate_cells_head_zero_max_is_empty() {
        assert_eq!(truncate_cells_head("abc", 0), "");
    }

    #[test]
    fn truncate_cells_head_under_max_returns_input_unchanged() {
        assert_eq!(truncate_cells_head("abc", 10), "abc");
        assert_eq!(truncate_cells_head("abc", 3), "abc");
    }

    #[test]
    fn truncate_cells_head_over_max_prepends_ellipsis_keeping_tail() {
        // "abcdef" budget 4 → "…" + trailing 3 cells "def" = "…def".
        assert_eq!(truncate_cells_head("abcdef", 4), "…def");
    }

    #[test]
    fn truncate_cells_head_max_one_yields_just_ellipsis_when_last_char_fits() {
        // width budget 1 → only the ellipsis fits (no payload char).
        assert_eq!(truncate_cells_head("abc", 1), "…");
    }

    #[test]
    fn truncate_cells_head_keeps_directory_tail_not_head() {
        // The motivating case: a long cwd should show the trailing dir name,
        // not the leading "/home/ry…".
        let cwd = "/home/ryan/.ssh";
        assert_eq!(truncate_cells_head(cwd, 8), "…an/.ssh");
        // The tail-only form ".ssh" stays intact when it fits exactly.
        assert_eq!(truncate_cells_head("/short/.ssh", 12), "/short/.ssh");
    }

    #[test]
    fn truncate_cells_head_counts_wide_chars_as_two_cells() {
        // 中/文 are width 2 each. Budget 3 → "文" (2) + "…" = "…文".
        assert_eq!(truncate_cells_head("中文", 3), "…文");
    }

    #[test]
    fn truncate_cells_head_budget_splitting_wide_glyph_does_not_panic() {
        // Budget 2 leaves only 1 payload cell after the ellipsis, which cannot
        // hold a width-2 glyph — the glyph is dropped (no panic, no half glyph).
        assert_eq!(truncate_cells_head("中文", 2), "…");
        // Budget 3 → ellipsis (1) + one width-2 glyph "文" (fits exactly) = "…文".
        assert_eq!(truncate_cells_head("中文", 3), "…文");
    }

    // ---- cells ----

    #[test]
    fn cells_counts_one_per_ascii_char() {
        assert_eq!(cells("abc"), 3);
        assert_eq!(cells(""), 0);
    }

    #[test]
    fn cells_counts_wide_chars_as_two() {
        assert_eq!(cells("中文"), 4);
        assert_eq!(cells("a中"), 3);
    }

    // ---- column_widths ----

    #[test]
    fn column_widths_roomy_gives_a_its_need_and_b_the_rest() {
        // 10 + 20 = 30 <= 80: a takes its need, b gets the remainder.
        assert_eq!(column_widths(80, 10, 20, 40, 6, 12), (10, 70));
    }

    #[test]
    fn column_widths_contended_caps_a_at_share_percent() {
        // 30 avail, a wants 20, b wants 20 (40 > 30). a capped at 30*40% = 12; b=18 >= b_min.
        assert_eq!(column_widths(30, 20, 20, 40, 6, 12), (12, 18));
    }

    #[test]
    fn column_widths_contended_a_need_below_cap_keeps_a_need() {
        // a only needs 8 (< cap 12) → a gets 8, not padded up to the cap.
        assert_eq!(column_widths(30, 8, 25, 40, 6, 12), (8, 22));
    }

    #[test]
    fn column_widths_floor_keeps_b_min_by_shrinking_a() {
        // 18 avail: cap=7 → b_w=11 < b_min 12 → a shrinks to 6 so b keeps 12.
        assert_eq!(column_widths(18, 20, 20, 40, 6, 12), (6, 12));
    }

    #[test]
    fn column_widths_zero_avail_is_zero_zero() {
        assert_eq!(column_widths(0, 10, 20, 40, 6, 12), (0, 0));
    }

    #[test]
    fn column_widths_zero_a_need_gives_all_to_b() {
        assert_eq!(column_widths(30, 0, 20, 40, 6, 12), (0, 30));
    }

    #[test]
    fn column_widths_extreme_avail_below_mins_holds_a_min() {
        // 10 avail < a_min(6)+b_min(12): can't satisfy both. a holds a_min, b gets the rest.
        assert_eq!(column_widths(10, 20, 20, 40, 6, 12), (6, 4));
    }
}
