//! Pane-row rendering helpers + format functions for the dual-pane transfer
//! screen. Pure render — no I/O. [`draw_pane`] paints one side (cwd row, filter
//! row, windowed list with marked/cursor glyphs and a right-aligned size+mtime
//! column); the format helpers (`fmt_size`, `fmt_rate`, `fmt_eta`, `fmt_mtime`)
//! are the unit-testable pure cores of the progress panel's text.
//!
//! Style mirror: [`draw_pane`] follows [`crate::tui::launcher::Launcher`] and
//! [`crate::tui::cred_panel::CredPanel`] — same `theme::focus_marker` selection
//! and fuzzy-highlight via `panel::highlighted_spans` — so the transfer screen
//! reads as one more panel of the app, not a separate surface. Unlike those
//! panels, each transfer pane is wrapped in a titled bordered block with its
//! own borderless 1-row filter prompt (`draw_filter_row`). The non-focused
//! pane is dimmed overall by applying [`Style::dim`] to every span it paints.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
};
use sshrack_core::connect::sftp::parse::strip_control_chars;
use sshrack_core::connect::sftp::proto::{Direction, Progress};
use sshrack_core::dirsource::DirEntry;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tui::fit::truncate_cells_head;
use crate::tui::panel;
use crate::tui::parts;
use crate::tui::theme;
use crate::tui::transfer::pane::Pane;

/// Cap on the name column. Names longer than this overflow gracefully into the
/// gap rather than squeezing the meta column off the row. Mirrors the launcher
/// / credential panel cap so all three list surfaces line up.
const NAME_COL_CAP: usize = 24;

/// Paint one pane into `area` as a titled bordered block: focus = accent
/// border + bold title, non-focus = dim border + dim title (mirrors sshelf and
/// keeps sshrack's dim-the-non-focused-pane language). Inside the block: a
/// 1-row cwd line, a borderless 1-row filter prompt ([`draw_filter_row`]), and
/// a Fill list windowed by [`Pane::visible_window`].
///
/// The filter is a 1-row prompt rather than the shared 3-row bordered
/// [`parts::draw_search_box`] so the pane has exactly one border (no box-in-box)
/// and the list loses no vertical room (the border costs 2 rows, the filter
/// shrinks 3→1, net zero).
pub fn draw_pane(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool, title: &str) {
    let border_style = if focused {
        theme::accent()
    } else {
        Style::new().dim()
    };
    let title_style = if focused {
        theme::accent().add_modifier(Modifier::BOLD)
    } else {
        Style::new().dim()
    };
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(format!(" {title} "), title_style));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [cwd_area, filter_area, list_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(inner);

    draw_cwd_row(frame, cwd_area, pane, focused);
    draw_filter_row(
        frame,
        filter_area,
        &pane.query,
        pane.matched_count(),
        pane.entries.len(),
        focused,
    );

    if pane.loading {
        frame.render_widget(
            Paragraph::new("loading…")
                .style(Style::new().dim())
                .alignment(Alignment::Center),
            parts::vertical_center(list_area, 1),
        );
        return;
    }

    draw_pane_list(frame, list_area, pane, focused);
}

/// Render the cwd row: the cwd path (accent when focused, dim when not),
/// left-truncated so the trailing dir name survives. No prompt prefix — the
/// pane's bordered title already identifies the side (`local` / remote name).
fn draw_cwd_row(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool) {
    let cwd_str = pane.cwd.to_string_lossy();
    let shown = truncate_cells_head(&cwd_str, area.width as usize);
    let style = if focused {
        theme::accent()
    } else {
        Style::new().dim()
    };
    frame.render_widget(Paragraph::new(Span::styled(shown, style)), area);
}

/// Render the filter row (interior of the bordered pane): a dim `❯ ` prefix +
/// the query on the left, the right-aligned `matched/total` [`count_label`] on
/// the right, and — only when `focused` — the terminal cursor right after the
/// query. Borderless (the pane `Block` already draws the surrounding border).
fn draw_filter_row(
    frame: &mut Frame,
    area: Rect,
    query: &str,
    matched: usize,
    total: usize,
    focused: bool,
) {
    let label = parts::count_label(matched, total);
    let label_w = label.chars().count() as u16;
    let [prompt_area, count_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(label_w)]).areas(area);

    let query_style = if focused {
        Style::new()
    } else {
        Style::new().dim()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::styled(query.to_string(), query_style),
        ])),
        prompt_area,
    );
    frame.render_widget(
        Paragraph::new(label)
            .alignment(Alignment::Right)
            .style(Style::new().dim()),
        count_area,
    );

    // Place the terminal cursor right after the 2-cell `❯ ` prefix, only on the
    // focused pane (the non-focused pane must not fight the focused pane's
    // cursor). Clamp to the row's last cell.
    if focused {
        let cursor_x = area.x + 2 + query.chars().count() as u16;
        let max_x = area.x + area.width.saturating_sub(1);
        frame.set_cursor_position((cursor_x.min(max_x), area.y));
    }
}

/// Render the windowed list: rank-order entries, slice the visible window via
/// [`Pane::visible_window`], and paint each row via [`draw_pane_row`]. The
/// focused pane's cursor row gets `theme::focus_marker(true)`; every other row
/// gets the two-space marker so the name column lines up. Empty listing → a
/// dim empty-state line.
fn draw_pane_list(frame: &mut Frame, area: Rect, pane: &Pane, focused: bool) {
    let total = pane.matched_count();
    if total == 0 {
        let msg = if pane.entries.is_empty() {
            "(empty)"
        } else {
            "(no matches)"
        };
        frame.render_widget(
            Paragraph::new(msg)
                .style(Style::new().dim())
                .alignment(Alignment::Center),
            parts::vertical_center(area, 1),
        );
        return;
    }

    // Window the visible rows to the viewport height. `area.height` is the
    // actual list body height; focus_window never selects an out-of-window row.
    let rows = area.height as usize;
    let win = pane.visible_window(rows);

    // Adaptive name column width across the VISIBLE rows (not the whole
    // listing) so a very long off-screen name cannot squeeze the meta column.
    let name_w = win
        .clone()
        .filter_map(|i| pane.entry_at_rank(i))
        .map(|e| strip_control_chars(&e.name).chars().count())
        .max()
        .unwrap_or(0)
        .min(NAME_COL_CAP);

    let mut lines: Vec<Line> = Vec::with_capacity(win.end.saturating_sub(win.start));
    for i in win {
        let Some(entry) = pane.entry_at_rank(i) else {
            continue;
        };
        let is_cursor = i == pane.selected;
        let is_marked = pane.marked.contains(&entry.path);
        lines.push(draw_pane_row(
            entry,
            &pane.query,
            is_cursor,
            is_marked,
            focused,
            name_w,
            area.width,
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Build one list row: `[●|  ]` mark glyph + `theme::focus_marker(cursor)` +
/// fuzzy-highlighted name padded to `name_w` + right-aligned dim
/// `<size>  <mtime>`. The mark glyph and the focus marker together are the
/// 4-cell leading prefix that every row aligns under. Pure: returns a `Line`
/// the caller renders.
fn draw_pane_row(
    entry: &DirEntry,
    query: &str,
    is_cursor: bool,
    is_marked: bool,
    focused_pane: bool,
    name_w: usize,
    width: u16,
) -> Line<'static> {
    // The focused pane's cursor row highlights the WHOLE row (accent + bold),
    // matching the identity-key picker — name, size, and mtime read as one
    // selected row, not just a leading arrow. Other rows stay plain; the
    // non-focused pane dims everything so it never competes with the highlight.
    let base = if focused_pane && is_cursor {
        theme::accent().add_modifier(Modifier::BOLD)
    } else if focused_pane {
        Style::new()
    } else {
        Style::new().dim()
    };

    let mut spans: Vec<Span> = Vec::with_capacity(8);

    // Leading mark glyph: `● ` accented when marked, two spaces otherwise. The
    // accent is dimmed on the non-focused pane so it does not out-shout the
    // focused pane's marks.
    if is_marked {
        let mark_style = if focused_pane {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(theme::ACCENT).dim()
        };
        spans.push(Span::styled("● ", mark_style));
    } else {
        spans.push(Span::raw("  "));
    }

    // Focus marker (2 cells either way) keeps the name column aligned across
    // selected and unselected rows. Pass `focused_pane && is_cursor` so the
    // non-focused pane never paints an accented arrow that competes with the
    // focused pane's.
    spans.push(theme::focus_marker(focused_pane && is_cursor));

    // Name: control-char-stripped + fuzzy-highlighted against the query.
    let cleaned = strip_control_chars(&entry.name);
    spans.extend(panel::highlighted_spans(&cleaned, query, base));
    spans.push(Span::raw(
        " ".repeat(name_w.saturating_sub(cleaned.chars().count())),
    ));

    // Right-aligned dim `<size>  <mtime>` meta column. The leading gap is the
    // remaining fill so the meta sticks to the right edge.
    let size_str = fmt_size_opt(entry.size);
    let mtime_str = fmt_mtime(entry.modified);
    let meta = format!("{size_str}  {mtime_str}");
    let used = 2 + 2 + name_w;
    let fill = (width as usize).saturating_sub(used + meta.chars().count());
    // Meta (size + mtime): dim on plain rows, but on the focused cursor row it
    // inherits the accent+bold highlight so the whole row reads as one.
    let meta_style = if focused_pane && is_cursor {
        base
    } else {
        Style::new().dim()
    };
    spans.push(Span::raw(" ".repeat(fill)));
    spans.push(Span::styled(meta, meta_style));

    Line::from(spans)
}

/// Render row 1 of the progress panel: the active transfer's text summary plus
/// a `Gauge`, or `"<name> <dir> <done> transferred…"` (no gauge) when
/// `bytes_total` is `None`, or the dim "no transfer in flight" placeholder
/// when `active` is `None`. The row is split horizontally — text on the left,
/// gauge on the right — so a long name cannot push the gauge off the row.
pub fn draw_active_transfer(frame: &mut Frame, area: Rect, active: Option<&Progress>) {
    let Some(prog) = active else {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no transfer in flight",
                Style::new().dim(),
            ))),
            area,
        );
        return;
    };

    let dir_glyph = match prog.direction {
        Direction::Upload => "↑",
        Direction::Download => "↓",
    };

    match prog.bytes_total {
        Some(total) if total > 0 => {
            let percent = u16::try_from(prog.bytes_done.saturating_mul(100) / total)
                .unwrap_or(100)
                .min(100);
            let text = format!(
                "{} {} {}% {}/{} {}/s eta:{}",
                prog.name,
                dir_glyph,
                percent,
                fmt_size(prog.bytes_done),
                fmt_size(total),
                fmt_rate(prog.rate_bps),
                fmt_eta(prog.eta_secs),
            );
            // Split: text on the left (clamped to leave at least 10 cells for
            // the gauge), gauge on the right. A tiny area just renders text.
            let text_w = text.chars().count() as u16;
            let avail = area.width;
            let want_gauge_w = avail.saturating_sub(text_w.min(avail / 2));
            if want_gauge_w < 5 {
                frame.render_widget(Paragraph::new(text), area);
                return;
            }
            let [text_area, gauge_area] =
                Layout::horizontal([Constraint::Min(0), Constraint::Length(want_gauge_w)])
                    .areas(area);
            frame.render_widget(Paragraph::new(text), text_area);
            frame.render_widget(
                Gauge::default()
                    .gauge_style(theme::accent())
                    .percent(percent)
                    .label(format!("{percent}%")),
                gauge_area,
            );
        }
        _ => {
            // Unknown total: render the indeterminate form with no gauge.
            let text = format!(
                "{} {} {} transferred…",
                prog.name,
                dir_glyph,
                fmt_size(prog.bytes_done),
            );
            frame.render_widget(Paragraph::new(text), area);
        }
    }
}

/// Build the 2-row status band's summary line: `done X/Y · fail Z [· paused]`
/// on the left, and — when present — the transient status message on the right.
/// Pure. `width` bounds the message so it can not push the counts off the row.
///
/// `done` counts successfully completed tasks only (`Done(Ok)`); failed and
/// cancelled tasks count toward `total` (and `failed`, for failures only) but
/// NOT toward `done`. This keeps the convention universal: `done` = success,
/// `fail` = failure, disjoint — and matches the Task-4 queue-overlay header's
/// `ledger.done_count()`. So a single failed task reads `done 0/1 · fail 1`.
pub fn summary_line(
    ledger: &crate::tui::transfer::ledger::TransferLedger,
    status: &crate::tui::intent::Status,
    width: u16,
) -> Line<'static> {
    let total = ledger.total();
    let done = ledger.done_count();
    let failed = ledger.failed_count();
    let counts = format!("done {done}/{total} · fail {failed}");
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        counts,
        if failed > 0 {
            Style::new().fg(crate::tui::theme::DANGER)
        } else {
            Style::new()
        },
    ));
    if ledger.is_paused() {
        spans.push(Span::styled(" · ", Style::new().dim()));
        spans.push(Span::styled("paused", crate::tui::theme::accent()));
    }
    if let Some(msg) = &status.message {
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        let budget = (width as usize).saturating_sub(used + 3); // " · "
        let trimmed = truncate_cells_head(msg, budget);
        spans.push(Span::styled(" · ", Style::new().dim()));
        let style = if status.is_error {
            Style::new().fg(crate::tui::theme::DANGER)
        } else {
            Style::new()
        };
        spans.push(Span::styled(trimmed, style));
    }
    Line::from(spans)
}

// ---- format helpers (pure) ----

/// Format a byte count `ls -lh`-style: plain digits under 1K, then `K` / `M`
/// / `G` (single uppercase letter, 1024-based) with one decimal place. Pure.
fn fmt_size_opt(opt: Option<u64>) -> String {
    match opt {
        Some(b) => fmt_size(b),
        None => "—".to_string(),
    }
}

/// Format a known byte count. Pure.
fn fmt_size(bytes: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    const KB: u64 = 1 << 10;
    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}")
    }
}

/// Format a transfer rate (bytes/sec) as `<fmt_size>/s`, or `—` when unknown.
/// Pure.
fn fmt_rate(bps: Option<u64>) -> String {
    match bps {
        Some(b) => format!("{}/s", fmt_size(b)),
        None => "—".to_string(),
    }
}

/// Format an ETA (seconds) as `Ns` or `NmNs`, or `—` when unknown. Pure.
fn fmt_eta(secs: Option<u64>) -> String {
    match secs {
        Some(s) => {
            if s < 60 {
                format!("{s}s")
            } else {
                format!("{}m{}s", s / 60, s % 60)
            }
        }
        None => "—".to_string(),
    }
}

/// Format a modification time as `YYYY-MM-DD` (UTC, civil-from-days), or `?`
/// when unknown. UTC is intentional — sftp listings carry server-local time
/// without a timezone, so a stable UTC label is honest and avoids the
/// tz-database dependency. Pure.
fn fmt_mtime(t: Option<SystemTime>) -> String {
    let Some(t) = t else {
        return "?".to_string();
    };
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return "?".to_string(),
    };
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant's `civil_from_days`: convert days since 1970-01-01 to a
/// `(year, month, day)` triple. Pure. Input can be negative (pre-epoch).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    //! Pure-function tests for the format helpers, plus a pane-row render
    //! regression that does not depend on ratatui's buffer internals (it
    //! format-checks the returned `Line`).
    use super::*;
    use std::time::Duration;

    // ---- fmt_size ----

    #[test]
    fn fmt_size_bytes_under_1k_is_plain_digits() {
        // ls -lh style: byte counts carry no unit.
        assert_eq!(fmt_size(0), "0");
        assert_eq!(fmt_size(512), "512");
        assert_eq!(fmt_size(1023), "1023");
    }

    #[test]
    fn fmt_size_kmg_one_decimal_ls_lh_style() {
        // ls -lh style: K/M/G (single uppercase letter), 1024-based, 1 decimal.
        assert_eq!(fmt_size(1024), "1.0K");
        assert_eq!(fmt_size(1536), "1.5K");
        assert_eq!(fmt_size(1_048_576), "1.0M");
        assert_eq!(fmt_size(1_073_741_824), "1.0G");
        assert_eq!(fmt_size(1_500_000_000), "1.4G");
    }

    // ---- fmt_rate ----

    #[test]
    fn fmt_rate_none_is_dash() {
        assert_eq!(fmt_rate(None), "—");
    }

    #[test]
    fn fmt_rate_some_appends_per_sec() {
        assert_eq!(fmt_rate(Some(1024)), "1.0K/s");
        assert_eq!(fmt_rate(Some(0)), "0/s");
    }

    // ---- fmt_eta ----

    #[test]
    fn fmt_eta_none_is_dash() {
        assert_eq!(fmt_eta(None), "—");
    }

    #[test]
    fn fmt_eta_under_minute_is_seconds() {
        assert_eq!(fmt_eta(Some(0)), "0s");
        assert_eq!(fmt_eta(Some(45)), "45s");
    }

    #[test]
    fn fmt_eta_minute_or_more_is_m_s() {
        assert_eq!(fmt_eta(Some(60)), "1m0s");
        assert_eq!(fmt_eta(Some(125)), "2m5s");
    }

    // ---- fmt_mtime ----

    #[test]
    fn fmt_mtime_none_is_question_mark() {
        assert_eq!(fmt_mtime(None), "?");
    }

    #[test]
    fn fmt_mtime_epoch_is_1970_01_01() {
        assert_eq!(fmt_mtime(Some(UNIX_EPOCH)), "1970-01-01");
    }

    #[test]
    fn fmt_mtime_known_timestamp_is_yyyy_mm_dd() {
        // 2020-01-01 = 18262 days since epoch.
        let t = UNIX_EPOCH + Duration::from_secs(86_400 * 18_262);
        assert_eq!(fmt_mtime(Some(t)), "2020-01-01");
    }

    // ---- civil_from_days (a few leap-year / month-boundary cases) ----

    #[test]
    fn civil_from_days_handles_pre_epoch_dates() {
        // 1969-12-31 = -1 day.
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn civil_from_days_handles_leap_day() {
        // 2000-02-29 = 11016 days since epoch (a leap day on a leap year —
        // 2000-01-01 is day 10957; Jan fills 31, then 28 more lands on Feb 29).
        let t = UNIX_EPOCH + Duration::from_secs(86_400 * 11_016);
        let (y, m, d) = civil_from_days(11_016);
        assert_eq!((y, m, d), (2000, 2, 29));
        // Round-trip via fmt_mtime so the format->days path stays covered too.
        assert_eq!(fmt_mtime(Some(t)), "2000-02-29");
    }

    // ---- draw_pane_row: render-alignment regression ----

    /// Build a fixture `DirEntry` with the given name.
    fn entry(name: &str, is_dir: bool, size: Option<u64>) -> DirEntry {
        let decorated = if is_dir {
            format!("{name}/")
        } else {
            name.to_string()
        };
        DirEntry {
            name: decorated,
            path: std::path::PathBuf::from("/x").join(name),
            is_dir,
            is_symlink: false,
            size,
            modified: None,
        }
    }

    #[test]
    fn draw_pane_row_marked_leads_with_accented_dot() {
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, true, true, 12, 50);
        let s = format!("{line}");
        assert!(s.starts_with('●'), "marked row must lead with ●: {s}");
    }

    #[test]
    fn draw_pane_row_unmarked_leads_with_spaces() {
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, true, 12, 50);
        let s = format!("{line}");
        assert!(
            s.starts_with("  "),
            "unmarked row must lead with two spaces: {s}"
        );
    }

    #[test]
    fn draw_pane_row_cursor_on_focused_pane_paints_focus_arrow() {
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, true, 12, 50);
        let s = format!("{line}");
        assert!(s.contains('▶'), "focused cursor must show ▶: {s}");
    }

    #[test]
    fn draw_pane_row_cursor_on_dimmed_pane_does_not_paint_arrow() {
        // Non-focused pane: no accented arrow (the cursor is shown only by the
        // absence of the arrow on the dim row, matching the launcher pattern).
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, false, 12, 50);
        let s = format!("{line}");
        assert!(!s.contains('▶'), "dim cursor must not show ▶: {s}");
    }

    #[test]
    fn draw_pane_row_strips_fake_control_chars_from_name() {
        let mut e = entry("evil", false, None);
        e.name = "foo\x1b[2Jbar".into();
        let line = draw_pane_row(&e, "", false, false, true, 12, 50);
        let s = format!("{line}");
        assert!(!s.contains('\u{1b}'), "ESC leaked into row: {s}");
        assert!(s.contains("foo?"), "control char not replaced: {s}");
    }

    #[test]
    fn draw_pane_row_renders_size_and_mtime_column() {
        let e = DirEntry {
            name: "alpha.txt".into(),
            path: std::path::PathBuf::from("/x/alpha.txt"),
            is_dir: false,
            is_symlink: false,
            size: Some(2048),
            modified: Some(UNIX_EPOCH + Duration::from_secs(86_400 * 18_262)),
        };
        let line = draw_pane_row(&e, "", false, false, true, 12, 50);
        let s = format!("{line}");
        assert!(s.contains("2.0K"), "size column missing: {s}");
        assert!(s.contains("2020-01-01"), "mtime column missing: {s}");
    }

    #[test]
    fn draw_pane_row_cursor_highlights_the_whole_row_including_meta() {
        // Focused + cursor: the whole row is accent+bold — the meta (size+mtime)
        // span carries BOLD + the accent fg, matching the identity-key picker.
        // (highlighted_spans preserves the base style on the name spans too.)
        let e = DirEntry {
            name: "alpha.txt".into(),
            path: std::path::PathBuf::from("/x/alpha.txt"),
            is_dir: false,
            is_symlink: false,
            size: Some(2048),
            modified: Some(UNIX_EPOCH + Duration::from_secs(86_400 * 18_262)),
        };
        let line = draw_pane_row(&e, "", true, false, true, 12, 50);
        let meta_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("2.0K"))
            .expect("meta span carrying the size");
        assert!(
            meta_span.style.add_modifier.contains(Modifier::BOLD),
            "cursor row meta must be bold (highlighted): {:?}",
            meta_span.style
        );
        assert_eq!(
            meta_span.style.fg,
            Some(theme::ACCENT),
            "cursor row meta must be accent-colored"
        );
    }

    #[test]
    fn draw_pane_row_non_cursor_meta_is_not_bold() {
        // A non-cursor row's meta stays dim — the highlight is cursor-only.
        let e = DirEntry {
            name: "alpha.txt".into(),
            path: std::path::PathBuf::from("/x/alpha.txt"),
            is_dir: false,
            is_symlink: false,
            size: Some(2048),
            modified: None,
        };
        let line = draw_pane_row(&e, "", false, false, true, 12, 50);
        let meta_span = line
            .spans
            .iter()
            .find(|s| s.content.contains("2.0K"))
            .expect("meta span carrying the size");
        assert!(
            !meta_span.style.add_modifier.contains(Modifier::BOLD),
            "non-cursor meta must not be bold: {:?}",
            meta_span.style
        );
    }

    // ---- draw_pane: titled bordered block, no panic on a short terminal ----

    #[test]
    fn draw_pane_focused_renders_without_panic_and_keeps_cursor_on_screen() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut pane = Pane::new(std::path::PathBuf::from("/x"));
        pane.set_entries(vec![
            entry("alpha.txt", false, Some(1024)),
            entry("betadir", true, None),
        ]);
        let backend = TestBackend::new(40, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, true, "local"))
            .expect("focused titled pane must render without panic");
        let pos = term.backend().cursor_position();
        assert!(
            pos.x < 40 && pos.y < 12,
            "focused filter cursor must stay on-screen (got ({},{}))",
            pos.x,
            pos.y,
        );
    }

    #[test]
    fn draw_pane_unfocused_renders_without_panic() {
        use ratatui::{Terminal, backend::TestBackend};
        let mut pane = Pane::new(std::path::PathBuf::from("/x"));
        pane.set_entries(vec![entry("alpha.txt", false, Some(1024))]);
        let backend = TestBackend::new(40, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, false, "u@h"))
            .expect("unfocused titled pane must render without panic");
    }
}

#[cfg(test)]
mod summary_tests {
    use super::*;
    use crate::tui::intent::Status;
    use crate::tui::transfer::ledger::TransferLedger;
    use sshrack_core::connect::sftp::proto::{Direction, TransferJob, TransferOutcome};

    fn job(name: &str, dir: Direction) -> TransferJob {
        TransferJob {
            direction: dir,
            src: format!("/s/{name}").into(),
            dst: format!("/d/{name}").into(),
            name: name.into(),
            size_total: Some(1024),
            recursive: false,
        }
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn summary_line_shows_done_over_total_and_fail() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.enqueue(job("b", Direction::Upload));
        l.enqueue(job("c", Direction::Upload));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok); // a done
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        assert!(s.contains("done"), "label present: {s}");
        assert!(s.contains("1/3"), "done/total: {s}");
        assert!(s.contains("fail"), "fail label present: {s}");
        assert!(s.contains("0"), "fail count: {s}");
    }

    #[test]
    fn summary_line_shows_failed_count() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("x".into()));
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        // A failed task is NOT done — done counts Done(Ok) only.
        assert!(s.contains("0/1"), "a failed task is not 'done': {s}");
        assert!(s.contains("fail 1"), "fail count rendered: {s}");
    }

    #[test]
    fn summary_line_appends_paused_when_paused() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.set_paused(true);
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        assert!(s.contains("paused"), "paused marker: {s}");
    }

    #[test]
    fn summary_line_appends_status_message_when_present() {
        let l = TransferLedger::new();
        let line = summary_line(&l, &Status::error("transfer failed: boom"), 80);
        let s = line_to_string(&line);
        assert!(
            s.contains("transfer failed: boom"),
            "status message rendered: {s}"
        );
    }
}
