//! Cross-directory find result rendering for the transfer panes. Pure render
//! — no I/O. [`draw_search_list`] paints the flat ranked [`PathMatch`] list a
//! focused/unfocused pane overlays on top of its directory listing while a
//! find query is active (`pane.search.is_some()`). It mirrors [`draw_pane_row`]
//! / [`draw_pane_list`] in [`super::render`]: same 4-cell leading prefix (mark
//! glyph + focus marker) so columns align with the directory listing, same
//! accent+bold cursor-row highlight, same dim-the-non-focused-pane language.
//! The only difference is the cell body — a joined path with per-segment fuzzy
//! highlight (one highlight run per `SegMatch.indices`) instead of a single
//! name column + size/mtime meta.
//!
//! [`draw_pane_row`]: super::render::draw_pane_row
//! [`draw_pane_list`]: super::render::draw_pane_list

use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use sshrack_core::pathfind::PathMatch;

use crate::tui::parts;
use crate::tui::theme;
use crate::tui::transfer::pane::Pane;

/// Render the focused/unfocused pane's flat search-result list into `area`
/// (the list body — same area [`draw_pane_list`] paints). Shape:
/// - Empty state: a dim centered line — `searching…` while the search is in
///   flight, `no matches` when the search terminated with zero hits, or the
///   error string's first line when a listing error terminated the search.
/// - Otherwise: window via [`PaneSearch::visible_window`], and for each visible
///   [`PathMatch`] a row that mirrors [`draw_pane_row`]'s prefix (2-cell mark
///   glyph + 2-cell focus marker) so columns line up with the directory
///   listing. The body is the joined path: each `SegMatch.name` rendered with
///   its own per-segment highlight (matched chars in `theme::MATCH` + bold,
///   unmatched chars in the row's base style), names joined by a dim `/`, with
///   a trailing dim `/` when `is_dir`. The cursor row is accent + bold whole.
///
/// [`draw_pane_list`]: super::render::draw_pane_list
/// [`draw_pane_row`]: super::render::draw_pane_row
/// [`PaneSearch::visible_window`]: super::search::PaneSearch::visible_window
pub(crate) fn draw_search_list(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool) {
    let Some(srch) = pane.search.as_ref() else {
        return;
    };

    if srch.results.is_empty() {
        let msg = if srch.searching {
            "searching…"
        } else if let Some(err) = &srch.error {
            // A listing error can span multiple lines (a wrapped path + cause);
            // surface only the first line so the empty-state stays one row.
            err.lines().next().unwrap_or("no matches")
        } else {
            "no matches"
        };
        frame.render_widget(
            Paragraph::new(msg)
                .style(Style::new().dim())
                .alignment(Alignment::Center),
            parts::vertical_center(area, 1),
        );
        return;
    }

    let rows = area.height as usize;
    let win = srch.visible_window(rows);

    // Highlight style applied to every matched char regardless of row state —
    // same `base.add_modifier(BOLD).fg(MATCH)` panel::highlighted_spans uses,
    // so a find result highlights the same way a directory filter does.
    let hi = Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD);
    let sep = Style::new().dim();

    let mut lines: Vec<Line> = Vec::with_capacity(win.end.saturating_sub(win.start));
    for i in win {
        let Some(pm) = srch.results.get(i) else {
            continue;
        };
        lines.push(draw_search_row(
            pm,
            pane,
            i == srch.cursor,
            focused,
            hi,
            sep,
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Build one search-result row: 2-cell mark glyph + 2-cell focus marker +
/// joined path with per-segment highlight + trailing dim `/` for directories.
/// Pure: returns a `Line` the caller renders. Mirrors [`draw_pane_row`]'s
/// prefix and cursor/mark styling so the two list surfaces (directory listing
/// and find results) align column-for-column.
///
/// [`draw_pane_row`]: super::render::draw_pane_row
fn draw_search_row(
    pm: &PathMatch,
    pane: &Pane,
    is_cursor: bool,
    focused: bool,
    hi: Style,
    sep: Style,
) -> Line<'static> {
    // Base style mirrors draw_pane_row: focused cursor = accent + bold, focused
    // non-cursor = plain, non-focused pane = dim overall.
    let base = if focused && is_cursor {
        theme::accent().add_modifier(Modifier::BOLD)
    } else if focused {
        Style::new()
    } else {
        Style::new().dim()
    };

    let mut spans: Vec<Span> = Vec::with_capacity(8);

    // Leading mark glyph: `● ` accented when marked + focused, dimly accented
    // when marked + non-focused, two spaces when unmarked. Same 2-cell prefix
    // as draw_pane_row so columns line up with the directory listing.
    let is_marked = pane.core.marked.contains(&pm.path);
    if is_marked {
        let mark_style = if focused {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme::ACCENT).dim()
        };
        spans.push(Span::styled("● ", mark_style));
    } else {
        spans.push(Span::raw("  "));
    }

    spans.push(theme::focus_marker(focused && is_cursor));

    // Path body: join each SegMatch.name with a dim `/`, highlight the matched
    // chars within each name (per its own `indices`), and append a trailing
    // dim `/` for directories.
    for (s_idx, seg) in pm.seg_matches.iter().enumerate() {
        if s_idx > 0 {
            spans.push(Span::styled("/", sep));
        }
        spans.extend(seg_spans(&seg.name, &seg.indices, base, hi));
    }
    if pm.is_dir {
        spans.push(Span::styled("/", sep));
    }

    Line::from(spans)
}

/// Render one segment's name as styled spans, splitting it into matched and
/// unmatched runs by precomputed `indices` (char positions into `name`).
/// Mirrors [`panel::highlighted_spans`] but reads the matcher's verdict
/// verbatim instead of re-running nucleo — the leaf matcher produced these
/// indices, so the renderer treats them as opaque. Empty `indices` (an
/// exact-drill ancestor segment, or a trailing-slash "list all" leaf) yields a
/// single base-styled span.
///
/// [`panel::highlighted_spans`]: crate::tui::panel::highlighted_spans
fn seg_spans(name: &str, indices: &[u32], base: Style, hi: Style) -> Vec<Span<'static>> {
    if indices.is_empty() {
        return vec![Span::styled(name.to_string(), base)];
    }
    // Collect matched char positions for O(1) lookup. Indices arrive sorted +
    // deduplicated from NucleoSegmentMatcher, but the renderer is match-source
    // agnostic, so a defensive HashSet keeps this correct regardless of order.
    let matched: std::collections::HashSet<u32> = indices.iter().copied().collect();

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(indices.len() + 1);
    let mut prev_byte = 0usize;
    for (char_pos, (byte_offset, ch)) in name.char_indices().enumerate() {
        if matched.contains(&(char_pos as u32)) {
            // Flush the preceding unmatched run (if any) in base style.
            if byte_offset > prev_byte {
                spans.push(Span::styled(name[prev_byte..byte_offset].to_string(), base));
            }
            // The matched char itself, in highlight style.
            let next_byte = byte_offset + ch.len_utf8();
            spans.push(Span::styled(name[byte_offset..next_byte].to_string(), hi));
            prev_byte = next_byte;
        }
    }
    if prev_byte < name.len() {
        spans.push(Span::styled(name[prev_byte..].to_string(), base));
    }
    spans
}

#[cfg(test)]
mod tests {
    //! Render-shape tests for the search-result list. The per-segment highlight
    //! helper is exercised directly (matched vs unmatched runs), and the full
    //! `draw_search_list` is pinned with an `insta` snapshot so the row layout
    //! (mark glyph + focus marker + joined path + trailing `/` for dirs) stays
    //! aligned with the directory listing.

    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    use sshrack_core::pathfind::{PathMatch, SegMatch};

    use crate::tui::transfer::pane::Pane;
    use crate::tui::transfer::search::PaneSearch;

    /// Build a canned `PathMatch` with two segments and hand-picked highlight
    /// indices, so the snapshot shows per-segment highlight visibly (the
    /// snapshot is text-only — colors do not appear, but the structure does).
    fn seg(name: &str, indices: &[u32]) -> SegMatch {
        SegMatch {
            name: name.to_string(),
            score: 1,
            indices: indices.to_vec(),
        }
    }

    fn build_pane() -> Pane {
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        let mut srch = PaneSearch::empty();
        srch.searching = false;
        srch.results = vec![
            PathMatch {
                path: std::path::PathBuf::from("/srv/apath/bfile"),
                is_dir: false,
                seg_matches: vec![seg("apath", &[0]), seg("bfile", &[0])],
            },
            PathMatch {
                path: std::path::PathBuf::from("/srv/apath/bdir"),
                is_dir: true,
                seg_matches: vec![seg("apath", &[0]), seg("bdir", &[0])],
            },
            PathMatch {
                path: std::path::PathBuf::from("/srv/xdir/yfile"),
                is_dir: false,
                seg_matches: vec![seg("xdir", &[0]), seg("yfile", &[0])],
            },
        ];
        // Cursor on index 1, mark the directory result (index 1) so the marked
        // + cursor + dir glyphs all appear in the same snapshot row.
        srch.cursor = 1;
        pane.core
            .marked
            .insert(std::path::PathBuf::from("/srv/apath/bdir"));
        pane.search = Some(srch);
        pane
    }

    #[test]
    fn draw_search_list_renders_results_cursor_mark_and_dir_suffix_snapshot() {
        let pane = build_pane();
        let backend = TestBackend::new(40, 6);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_search_list(f, f.area(), &pane, true))
            .unwrap();
        insta::assert_snapshot!(term.backend());
    }

    // ---- seg_spans: pure per-segment highlight ----

    /// Production highlight style: MATCH (yellow) + bold. Used by tests that
    /// verify style on matched spans.
    fn hi_style() -> Style {
        Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD)
    }

    #[test]
    fn seg_spans_empty_indices_returns_single_base_span() {
        let spans = seg_spans("abc", &[], Style::new(), hi_style());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "abc");
    }

    #[test]
    fn seg_spans_emits_one_span_per_matched_char_like_panel() {
        // "web-prod" with indices [0,1,2] (matched "web"). Like
        // panel::highlighted_spans, each matched char is its own span (no run
        // coalescing) → "w","e","b" hi then "-prod" base. The first span is
        // the first matched char (no leading plain span).
        let spans = seg_spans("web-prod", &[0, 1, 2], Style::new(), hi_style());
        assert_eq!(spans.len(), 4, "got {} spans", spans.len());
        assert_eq!(spans[0].content.as_ref(), "w");
        assert_eq!(spans[1].content.as_ref(), "e");
        assert_eq!(spans[2].content.as_ref(), "b");
        assert_eq!(spans[3].content.as_ref(), "-prod");
        // Every matched-char span carries MATCH + bold.
        for s in &spans[0..3] {
            assert_eq!(s.style.fg, Some(theme::MATCH));
            assert!(s.style.add_modifier.contains(Modifier::BOLD));
        }
        // The trailing unmatched run is plain base.
        assert_eq!(spans[3].style.fg, None);
    }

    #[test]
    fn seg_spans_leading_unmatched_run_is_its_own_span() {
        // Indices [4] on "web-prod" → "web-" base, "p" hi, "rod" base.
        let spans = seg_spans("web-prod", &[4], Style::new(), hi_style());
        let joined: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, "web-prod");
        // The matched 'p' is one span on its own.
        let p = spans.iter().find(|s| s.content.as_ref() == "p").expect("p");
        assert_eq!(p.style.fg, Some(theme::MATCH));
    }

    #[test]
    fn seg_spans_trailing_unmatched_run_appended() {
        // Index [0] only on "abc" → "a" hi, "bc" base.
        let spans = seg_spans("abc", &[0], Style::new(), hi_style());
        assert_eq!(spans[0].content.as_ref(), "a");
        assert_eq!(spans[1].content.as_ref(), "bc");
    }

    #[test]
    fn seg_spans_handles_non_contiguous_indices() {
        // Indices [0,2] on "abc" → "a" hi, "b" base, "c" hi.
        let spans = seg_spans("abc", &[0, 2], Style::new(), hi_style());
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].content.as_ref(), "a");
        assert_eq!(spans[1].content.as_ref(), "b");
        assert_eq!(spans[2].content.as_ref(), "c");
    }

    #[test]
    fn seg_spans_handles_multibyte_chars_by_char_position() {
        // "中文.txt" — char positions: 中=0, 文=1, .=2, t=3, x=4, t=5.
        // Highlight [0, 1] → "中" hi, "文" hi, ".txt" base. CJK chars are 3
        // bytes in UTF-8; byte-offset accounting must advance by char len, not
        // 1, else the slice boundaries land mid-codepoint and panic.
        let spans = seg_spans("中文.txt", &[0, 1], Style::new(), hi_style());
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0].content.as_ref(), "中");
        assert_eq!(spans[1].content.as_ref(), "文");
        assert_eq!(spans[2].content.as_ref(), ".txt");
    }

    #[test]
    fn seg_spans_out_of_range_index_ignored_gracefully() {
        // Index 99 on "abc" — past the end. Defensive: no panic; just one base
        // span (no char ever matched).
        let spans = seg_spans("abc", &[99], Style::new(), hi_style());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content.as_ref(), "abc");
    }
}
