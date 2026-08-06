//! Cross-directory find result rendering for the transfer panes. Pure render
//! — no I/O. [`draw_search_list`] paints the flat ranked [`PathMatch`] list a
//! focused/unfocused pane overlays on top of its directory listing while a
//! find query is active (`pane.search.is_some()`). It mirrors [`draw_pane_row`]
//! / [`draw_pane_list`] in [`super::render`]: same 4-cell leading prefix (a
//! 2-cell spacer where the listing puts its mark glyph, + focus marker) so
//! columns align with the directory listing, same accent+bold cursor-row
//! highlight, same dim-the-non-focused-pane language.
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

use sshrack_core::pathfind::{PathMatch, base_display_prefix};

use crate::tui::parts;
use crate::tui::theme;
use crate::tui::transfer::pane::Pane;

/// Render the focused/unfocused pane's flat search-result list into `area`
/// (the list body — same area [`draw_pane_list`] paints). Shape:
/// - Empty state: a dim centered line — `searching…` while the search is in
///   flight, `no matches` when the search terminated with zero hits, or the
///   error string's first line when a listing error terminated the search.
/// - Otherwise: window via [`PaneSearch::visible_window`], and for each visible
///   [`PathMatch`] a row that mirrors [`draw_pane_row`]'s prefix width (2-cell
///   spacer + 2-cell focus marker) so columns line up with the directory
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

    if srch.results.is_empty() && srch.current_dir.is_none() {
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
    let has_dot = srch.current_dir.is_some();

    // Highlight style applied to every matched char regardless of row state —
    // same `base.add_modifier(BOLD).fg(MATCH)` panel::highlighted_spans uses,
    // so a find result highlights the same way a directory filter does.
    let hi = Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD);
    let sep = Style::new().dim();
    // The base-syntax prefix the user typed (`/`, `~/`, `../` chain) — the path
    // component NOT carried by `seg_matches` (they hold only the path relative
    // to the base). Prepended to every row so an absolute query renders
    // `/home/ryan/` instead of `home/ryan/`. Empty for a relative query.
    let prefix = base_display_prefix(&pane.core.query);

    let mut lines: Vec<Line> = Vec::with_capacity(win.end.saturating_sub(win.start));
    for i in win {
        if has_dot && i == 0 {
            lines.push(draw_dot_row(i == srch.cursor, focused));
            continue;
        }
        let idx = i - usize::from(has_dot);
        let Some(pm) = srch.results.get(idx) else {
            continue;
        };
        lines.push(draw_search_row(
            pm,
            i == srch.cursor,
            focused,
            hi,
            sep,
            &prefix,
            area.width,
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Build the synthetic "." (current-directory) row that tops a trailing-slash
/// find listing. Same leading 4-cell prefix (2-cell spacer + focus marker) as
/// [`draw_search_row`] so columns line up with the directory listing and the
/// other find rows; the body is a literal "." in the row's base style (cursor
/// row = accent + bold when focused). Pure: returns a `Line` the caller renders.
///
/// [`draw_search_row`]: draw_search_row
fn draw_dot_row(is_cursor: bool, focused: bool) -> Line<'static> {
    let base = if focused && is_cursor {
        theme::accent().add_modifier(Modifier::BOLD)
    } else if focused {
        Style::new()
    } else {
        Style::new().dim()
    };
    let spans: Vec<Span> = vec![
        Span::raw("  "),
        theme::focus_marker(focused && is_cursor),
        Span::styled(".", base),
    ];
    Line::from(spans)
}

/// Build one search-result row: 2-cell spacer + 2-cell focus marker +
/// base-syntax prefix + joined path with per-segment highlight + trailing dim
/// `/` for directories, tail-truncated to `row_width` so a long cross-directory
/// path shows `…/<leaf>` instead of silently clipping. Pure: returns a `Line`
/// the caller renders. Mirrors [`draw_pane_row`]'s prefix and cursor styling so
/// the two list surfaces (directory listing and find results) align
/// column-for-column.
///
/// Truncation is segment-aware (see [`fit_units_tail`]): the row is built as
/// atomic units — each segment name plus its trailing `/`, with the base prefix
/// folded into the first unit — then kept from the right until the next would
/// overflow. Segment boundaries are never split, so each segment's per-char
/// highlight `indices` stay valid. `row_width` is the full list-area width; the
/// 4-cell leading prefix (spacer + focus marker) is reserved first.
///
/// `prefix` is the query's base syntax (`/`, `~/`, `../`, or `""` for a
/// relative query). Rendered in the dim separator style (structural).
///
/// [`draw_pane_row`]: super::render::draw_pane_row
fn draw_search_row(
    pm: &PathMatch,
    is_cursor: bool,
    focused: bool,
    hi: Style,
    sep: Style,
    prefix: &str,
    row_width: u16,
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

    let seg_len = pm.seg_matches.len();

    // Build atomic units (segment name + its trailing "/"), folding the base
    // prefix into the first unit so the prefix never strands alone when the
    // head is dropped. The trailing "/" after a segment is either the inter-
    // segment separator (not-last segment) or the directory's trailing slash
    // (last segment when is_dir). The last segment of a file gets no slash.
    let mut units: Vec<Vec<Span<'static>>> = Vec::with_capacity(seg_len);
    for (i, seg) in pm.seg_matches.iter().enumerate() {
        let mut unit: Vec<Span<'static>> = Vec::new();
        if i == 0 && !prefix.is_empty() {
            unit.push(Span::styled(prefix.to_string(), sep));
        }
        unit.extend(seg_spans(&seg.name, &seg.indices, base, hi));
        let is_last = i + 1 == seg_len;
        if !is_last || pm.is_dir {
            unit.push(Span::styled("/", sep));
        }
        units.push(unit);
    }

    let avail = (row_width as usize).saturating_sub(4); // spacer(2) + focus_marker(2)
    let body = fit_units_tail(units, avail);

    let mut spans: Vec<Span<'static>> = Vec::with_capacity(2 + body.len());
    // Leading 2-space prefix (the mark-glyph column from draw_pane_row, kept so
    // columns line up). Find mode has no marking, so this is always blank.
    spans.push(Span::raw("  "));
    spans.push(theme::focus_marker(focused && is_cursor));
    spans.extend(body);
    Line::from(spans)
}

/// Tail-preserving truncation for an ordered list of span "units". Each inner
/// `Vec<Span>` is an atomic group (a path segment name plus its trailing `/`,
/// with the base prefix folded into the first group) — truncation never splits
/// a group, so each segment's per-char fuzzy-highlight indices stay valid.
///
/// When everything fits within `avail`, all units are concatenated unchanged.
/// Otherwise units are kept from the RIGHT until the next would overflow
/// `avail - 1` (1 cell reserved for a leading `…`), and a dim `…` span is
/// prepended. If even the last unit alone overflows the budget, that lone unit
/// is flattened to a string and left-truncated via [`truncate_cells_head`] so
/// the tail (a filename's extension, or a dir's trailing `/`) survives —
/// consistent with this helper's tail-preserving strategy. Its highlight
/// degrades to the unit's first-span style (a rare case where a single segment
/// name is wider than the whole row). `avail == 0` or no units → empty. Pure.
fn fit_units_tail(units: Vec<Vec<Span<'static>>>, avail: usize) -> Vec<Span<'static>> {
    use crate::tui::fit::{cells, truncate_cells_head};

    let n = units.len();
    if avail == 0 || n == 0 {
        return Vec::new();
    }
    // Width of one unit = sum of its spans' display widths (CJK-aware).
    let widths: Vec<usize> = units
        .iter()
        .map(|u| u.iter().map(|s| cells(s.content.as_ref())).sum())
        .collect();
    let total: usize = widths.iter().sum();
    if total <= avail {
        return units.into_iter().flatten().collect();
    }

    // Reserve 1 cell for the leading ellipsis; greedily keep trailing units.
    let budget = avail.saturating_sub(1);
    let mut kept_from_right = 0usize;
    let mut w = 0usize;
    for i in (0..n).rev() {
        if w + widths[i] > budget {
            break;
        }
        w += widths[i];
        kept_from_right += 1;
    }

    let mut out: Vec<Span<'static>> = Vec::new();
    if kept_from_right == 0 {
        // The last unit alone overflows: flatten + left-truncate it (keep the
        // tail — a filename extension or a dir's trailing `/`).
        let last = units.last().expect("invariant: n > 0 checked above");
        let flat: String = last.iter().map(|s| s.content.as_ref()).collect();
        let style = last.first().map(|s| s.style).unwrap_or_default();
        out.push(Span::styled(truncate_cells_head(&flat, avail), style));
        return out;
    }

    out.push(Span::styled("…", Style::new().dim()));
    let start = n - kept_from_right;
    for unit in units.into_iter().skip(start) {
        out.extend(unit);
    }
    out
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
        // Cursor on index 1 (the directory result) so the cursor + dir
        // glyphs appear in the same snapshot row.
        srch.cursor = 1;
        pane.search = Some(srch);
        pane
    }

    #[test]
    fn draw_search_list_renders_results_cursor_and_dir_suffix_snapshot() {
        let pane = build_pane();
        let backend = TestBackend::new(40, 6);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_search_list(f, f.area(), &pane, true))
            .unwrap();
        insta::assert_snapshot!(term.backend());
    }

    #[test]
    fn draw_search_list_long_path_truncates_tail_with_ellipsis_snapshot() {
        // A deeply-nested absolute path that overflows a 28-cell-wide pane.
        // Base prefix "/" is folded into unit 0; seg_matches are the path parts.
        // The leaf "main.rs" must survive at the tail; ancestors drop behind "…".
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        pane.core.query = "/home/ryan/projects/alpha/src".into();
        let mut srch = PaneSearch::empty();
        srch.searching = false;
        srch.results = vec![PathMatch {
            path: std::path::PathBuf::from("/home/ryan/projects/alpha/src/main.rs"),
            is_dir: false,
            seg_matches: vec![
                seg("home", &[]),
                seg("ryan", &[]),
                seg("projects", &[]),
                seg("alpha", &[]),
                seg("src", &[]),
                seg("main.rs", &[0, 1]),
            ],
        }];
        srch.cursor = 0;
        pane.search = Some(srch);
        let backend = TestBackend::new(28, 3);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_search_list(f, f.area(), &pane, true))
            .unwrap();
        insta::assert_snapshot!(term.backend());
    }

    fn dot_pane(cursor: usize) -> Pane {
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        let mut srch = PaneSearch::empty();
        srch.searching = false;
        srch.current_dir = Some(PathMatch {
            path: std::path::PathBuf::from("/srv/apath"),
            is_dir: true,
            seg_matches: vec![],
        });
        srch.results = vec![
            PathMatch {
                path: std::path::PathBuf::from("/srv/apath/bfile"),
                is_dir: false,
                seg_matches: vec![seg("apath", &[]), seg("bfile", &[0])],
            },
            PathMatch {
                path: std::path::PathBuf::from("/srv/apath/bdir"),
                is_dir: true,
                seg_matches: vec![seg("apath", &[]), seg("bdir", &[0])],
            },
        ];
        srch.cursor = cursor;
        pane.search = Some(srch);
        pane
    }

    #[test]
    fn draw_search_list_renders_dot_row_at_top_snapshot() {
        // Cursor on "." (index 0): the top row is the synthetic current-dir
        // entry, then the drilled dir's children below it.
        let pane = dot_pane(0);
        let backend = TestBackend::new(40, 6);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_search_list(f, f.area(), &pane, true))
            .unwrap();
        insta::assert_snapshot!(term.backend());
    }

    #[test]
    fn draw_search_list_empty_dir_shows_dot_not_no_matches_snapshot() {
        // A drilled directory that exists but is empty: the "." row renders
        // (NOT the "no matches" empty state), so the user can Enter into it.
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        let mut srch = PaneSearch::empty();
        srch.searching = false;
        srch.current_dir = Some(PathMatch {
            path: std::path::PathBuf::from("/srv/empty"),
            is_dir: true,
            seg_matches: vec![],
        });
        pane.search = Some(srch);
        let backend = TestBackend::new(40, 3);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_search_list(f, f.area(), &pane, true))
            .unwrap();
        insta::assert_snapshot!(term.backend());
    }

    // ---- base prefix (Bug 1): absolute/tilde/parent queries must show their
    // leading base syntax, which seg_matches does not carry. ----

    fn join_spans(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn draw_search_row_prepends_root_slash_for_absolute_query() {
        // Query "/home/ryan" → base "/", seg_matches [home, ryan]. Without the
        // prefix the row read "home/ryan/"; it must read "/home/ryan/".
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        pane.core.query = "/home/ryan".into();
        let pm = PathMatch {
            path: std::path::PathBuf::from("/home/ryan"),
            is_dir: true,
            seg_matches: vec![seg("home", &[]), seg("ryan", &[0, 1])],
        };
        let hi = Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD);
        let sep = Style::new().dim();
        let line = draw_search_row(&pm, true, true, hi, sep, "/", 80);
        let joined = join_spans(&line);
        assert!(
            joined.contains("/home/ryan/"),
            "absolute query must render with leading slash: {joined:?}"
        );
    }

    #[test]
    fn draw_search_row_prepends_tilde_for_home_query() {
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        pane.core.query = "~/proj".into();
        let pm = PathMatch {
            path: std::path::PathBuf::from("/home/u/proj"),
            is_dir: true,
            seg_matches: vec![seg("proj", &[0])],
        };
        let hi = Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD);
        let sep = Style::new().dim();
        let line = draw_search_row(&pm, false, true, hi, sep, "~/", 80);
        let joined = join_spans(&line);
        assert!(
            joined.contains("~/proj/"),
            "tilde query must render with ~/: {joined:?}"
        );
    }

    #[test]
    fn draw_search_row_no_prefix_for_relative_query() {
        // A relative query renders segments as-typed — no leading slash. The
        // cwd base is intentionally not shown.
        let mut pane = Pane::new(std::path::PathBuf::from("/srv"));
        pane.core.query = "a/bdir".into();
        let pm = PathMatch {
            path: std::path::PathBuf::from("/srv/a/bdir"),
            is_dir: true,
            seg_matches: vec![seg("a", &[]), seg("bdir", &[0])],
        };
        let hi = Style::new().fg(theme::MATCH).add_modifier(Modifier::BOLD);
        let sep = Style::new().dim();
        let line = draw_search_row(&pm, false, true, hi, sep, "", 80);
        let joined = join_spans(&line);
        assert!(
            joined.contains("a/bdir/") && !joined.contains("/a/bdir/"),
            "relative query renders segments without a leading slash: {joined:?}"
        );
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

    // ---- fit_units_tail: segment-aware tail-preserving truncation ----
    // (Span / Style / Modifier arrive via `use super::*` at the top of the test
    //  module — render_search already imports them. Do not re-import here.)

    /// Join a unit list into the displayed string (style is irrelevant here).
    fn join_units(units: &[Vec<Span<'static>>]) -> String {
        units.iter().flatten().map(|s| s.content.as_ref()).collect()
    }

    /// Join a produced span vec back to its display string.
    fn join_spans_owned(spans: &[Span<'static>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn unit(s: &str) -> Vec<Span<'static>> {
        vec![Span::raw(s.to_string())]
    }

    #[test]
    fn fit_units_tail_avail_zero_returns_empty() {
        let out = fit_units_tail(vec![unit("abc")], 0);
        assert!(out.is_empty());
    }

    #[test]
    fn fit_units_tail_empty_units_returns_empty() {
        let out = fit_units_tail(vec![], 10);
        assert!(out.is_empty());
    }

    #[test]
    fn fit_units_tail_everything_fits_returns_all_flattened_no_ellipsis() {
        // Two units, total 11 cells, avail 20 → everything kept, no "…".
        let units = vec![unit("/home/"), unit("ryan/")];
        let out = fit_units_tail(units.clone(), 20);
        assert_eq!(join_spans_owned(&out), join_units(&units));
        assert!(!out.iter().any(|s| s.content.as_ref() == "…"));
    }

    #[test]
    fn fit_units_tail_drops_leading_unit_prepends_ellipsis_keeping_tail() {
        // units: "/home/" (6) + "ryan/" (5) = 11. avail 8 → budget 7.
        // From right: "ryan/" (5) ≤ 7 keep; "/home/" (6): 5+6=11 > 7 stop.
        // Result: "…" + "ryan/" = "…ryan/".
        let units = vec![unit("/home/"), unit("ryan/")];
        let out = fit_units_tail(units, 8);
        assert_eq!(join_spans_owned(&out), "…ryan/");
    }

    #[test]
    fn fit_units_tail_keeps_multiple_trailing_units_drops_head() {
        // units: "aaa/" (4) + "bbb/" (4) + "ccc" (3) = 11. avail 9 → budget 8.
        // From right: "ccc" (3) keep; "bbb/" (4): 3+4=7 ≤ 8 keep;
        // "aaa/" (4): 7+4=11 > 8 stop. Result: "…" + "bbb/ccc" = "…bbb/ccc".
        let units = vec![unit("aaa/"), unit("bbb/"), unit("ccc")];
        let out = fit_units_tail(units, 9);
        assert_eq!(join_spans_owned(&out), "…bbb/ccc");
    }

    #[test]
    fn fit_units_tail_degenerates_to_truncate_when_last_unit_alone_overflows() {
        // Single unit wider than avail: flatten + left-truncate with "…", keeping
        // the tail (a filename's extension) — consistent with this helper's
        // tail-preserving strategy.
        // "abcdefghi.txt" = 13 cells, avail 8 → truncate_cells_head(_, 8) = "…ghi.txt".
        let units = vec![unit("abcdefghi.txt")];
        let out = fit_units_tail(units, 8);
        assert_eq!(join_spans_owned(&out), "…ghi.txt");
    }

    #[test]
    fn fit_units_tail_ellipsis_span_is_dim_styled() {
        let units = vec![unit("/home/"), unit("ryan/")];
        let out = fit_units_tail(units, 8);
        let ell = out
            .iter()
            .find(|s| s.content.as_ref() == "…")
            .expect("ellipsis present");
        assert!(
            ell.style.add_modifier.contains(Modifier::DIM) || ell.style == Style::new().dim(),
            "ellipsis must be dim-styled, got {ell:?}"
        );
    }
}
