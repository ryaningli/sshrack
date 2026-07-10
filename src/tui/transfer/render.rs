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
    widgets::{Block, Borders, Paragraph},
};
use sshrack_core::connect::sftp::parse::strip_control_chars;
use sshrack_core::connect::sftp::proto::{Direction, Progress};
use sshrack_core::dirsource::DirEntry;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::tui::fit::{cells, truncate_cells, truncate_cells_head};
use crate::tui::panel;
use crate::tui::parts;
use crate::tui::theme;
use crate::tui::transfer::pane::Pane;
use crate::tui::transfer::queue_overlay::QueueView;

/// Cap on the name column. Names longer than this overflow gracefully into the
/// gap rather than squeezing the meta column off the row. Mirrors the launcher
/// / credential panel cap so all three list surfaces line up.
const NAME_COL_CAP: usize = 24;

/// Minimum name column width kept before numeric segments are dropped. Below
/// this the name is starved and we degrade the row instead of rendering a
/// 2-character sliver.
const NAME_MIN: usize = 6;
/// Gauge width bounds: ~1/3 of the row, never narrower than this (else the
/// `██░░ N%` label is unreadable) nor wider than this (else it dominates).
const GAUGE_MIN: u16 = 10;
const GAUGE_MAX: u16 = 30;

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
        &pane.core.query,
        pane.matched_count(),
        pane.core.entries.len(),
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
    let cwd_str = pane.core.cwd.to_string_lossy();
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
        let msg = if pane.core.entries.is_empty() {
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

    // Plan the name column from the VISIBLE rows' display widths (not the whole
    // listing, so an off-screen giant name can't squeeze the meta column). Meta
    // width is the widest visible "<size>  <mtime>" so the plan accounts for
    // the row that needs the most room.
    let visible: Vec<&DirEntry> = win.clone().filter_map(|i| pane.entry_at_rank(i)).collect();
    let visible_max = visible
        .iter()
        .map(|e| cells(&strip_control_chars(&e.name)))
        .max()
        .unwrap_or(0);
    let meta_w = visible
        .iter()
        .map(|e| {
            cells(&format!(
                "{}  {}",
                fmt_size_opt(e.size),
                fmt_mtime(e.modified)
            ))
        })
        .max()
        .unwrap_or(0);
    let plan = plan_name_col(visible_max, meta_w, area.width);

    let mut lines: Vec<Line> = Vec::with_capacity(win.end.saturating_sub(win.start));
    for i in win {
        let Some(entry) = pane.entry_at_rank(i) else {
            continue;
        };
        let is_cursor = i == pane.core.selected;
        let is_marked = pane.core.marked.contains(&entry.path);
        lines.push(draw_pane_row(
            entry,
            &pane.core.query,
            is_cursor,
            is_marked,
            focused,
            plan.name_w,
            area.width,
            plan.show_meta,
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Build one list row: `[●|  ]` mark glyph + `theme::focus_marker(cursor)` +
/// fuzzy-highlighted name truncated/padded to `name_w` (display cells) +, when
/// `show_meta`, a right-aligned dim `<size>  <mtime>`. The mark glyph and the
/// focus marker together are the 4-cell leading prefix every row aligns under.
/// Pure: returns a `Line` the caller renders.
#[allow(clippy::too_many_arguments)]
fn draw_pane_row(
    entry: &DirEntry,
    query: &str,
    is_cursor: bool,
    is_marked: bool,
    focused_pane: bool,
    name_w: usize,
    width: u16,
    show_meta: bool,
) -> Line<'static> {
    // The focused pane's cursor row highlights the WHOLE row (accent + bold),
    // matching the identity-key picker. Other rows stay plain; the non-focused
    // pane dims everything so it never competes with the highlight.
    let base = if focused_pane && is_cursor {
        theme::accent().add_modifier(Modifier::BOLD)
    } else if focused_pane {
        Style::new()
    } else {
        Style::new().dim()
    };

    let mut spans: Vec<Span> = Vec::with_capacity(8);

    // Leading mark glyph: `● ` accented when marked, two spaces otherwise.
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

    spans.push(theme::focus_marker(focused_pane && is_cursor));

    // Name: control-char-stripped, truncated to name_w cells (with `…`), then
    // fuzzy-highlighted against the query, then padded by DISPLAY width so CJK
    // and ASCII rows align under the same meta column.
    let cleaned = strip_control_chars(&entry.name);
    let truncated = if cells(&cleaned) > name_w {
        truncate_cells(&cleaned, name_w)
    } else {
        cleaned.clone()
    };
    spans.extend(panel::highlighted_spans(&truncated, query, base));
    let pad = name_w.saturating_sub(cells(&truncated));
    spans.push(Span::raw(" ".repeat(pad)));

    if show_meta {
        let size_str = fmt_size_opt(entry.size);
        let mtime_str = fmt_mtime(entry.modified);
        let meta = format!("{size_str}  {mtime_str}");
        let used = 2 + 2 + name_w;
        let fill = (width as usize).saturating_sub(used + cells(&meta));
        let meta_style = if focused_pane && is_cursor {
            base
        } else {
            Style::new().dim()
        };
        spans.push(Span::raw(" ".repeat(fill)));
        spans.push(Span::styled(meta, meta_style));
    }

    Line::from(spans)
}

/// Render row 1 of the progress panel: the active transfer as a three-column
/// row — `[name ↑/↓]` left, the surviving numeric segments (`size rate eta`)
/// right-aligned against the gauge, and a visible-track bar hard against the right edge.
/// An unknown total renders no gauge (just name + bytes-done + rate). `None`
/// paints the dim "no transfer in flight" placeholder.
///
/// Width handling is delegated to [`plan_active_row`]: the name is truncated
/// with `…` (never silently clipped), numeric segments drop in priority order
/// (eta → rate → size) as the row narrows, and the gauge is dropped only when
/// even a minimal name + gauge no longer fit. The percent appears once, in the
/// gauge label. The right edge is always the gauge (or the last segment) — no
/// wasted trailing space.
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

    let plan = plan_active_row(
        &prog.name,
        prog.bytes_done,
        prog.bytes_total,
        prog.rate_bps,
        prog.eta_secs,
        area.width,
    );

    let dir_glyph = match prog.direction {
        Direction::Upload => "↑",
        Direction::Download => "↓",
    };

    // Name column: truncated name + a spaced direction glyph, left-aligned.
    let name_line = Line::from(vec![
        Span::raw(plan.name_shown.clone()),
        Span::styled(format!(" {dir_glyph}"), theme::accent()),
    ]);

    // Segments column: surviving segments right-aligned so they hug the gauge.
    let mut seg_spans: Vec<Span> = Vec::new();
    if plan.show_size {
        seg_spans.push(Span::raw(format!(" {}", plan.size_seg)));
    }
    if plan.show_rate {
        seg_spans.push(Span::raw(format!(" {}", plan.rate_seg)));
    }
    if plan.show_eta {
        seg_spans.push(Span::raw(format!(" {}", plan.eta_seg)));
    }

    if plan.gauge_w == 0 {
        // No gauge: name fills the row, segments trail it. Still no silent
        // clip — the plan already truncated the name to fit `area.width`.
        let [name_area, segs_area] =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(plan.segs_w)]).areas(area);
        frame.render_widget(Paragraph::new(name_line), name_area);
        if plan.segs_w > 0 {
            frame.render_widget(
                Paragraph::new(Line::from(seg_spans)).alignment(Alignment::Right),
                segs_area,
            );
        }
        return;
    }

    let [name_area, segs_area, gauge_area] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(plan.segs_w),
        Constraint::Length(plan.gauge_w),
    ])
    .areas(area);

    frame.render_widget(Paragraph::new(name_line), name_area);
    if plan.segs_w > 0 {
        frame.render_widget(
            Paragraph::new(Line::from(seg_spans)).alignment(Alignment::Right),
            segs_area,
        );
    }
    // Manual bar render: a visible `█`/`░` track filling gauge_w exactly, with
    // the percent overlaid centered. ratatui's `Gauge` widget leaves the
    // unfilled portion as blank space (invisible endpoint + trailing waste);
    // rendering the track ourselves fixes both. See `plan_gauge`.
    let label_str = plan.gauge_label.as_deref().unwrap_or("");
    let bar_spans: Vec<Span> = plan_gauge(plan.gauge_w, plan.percent, label_str)
        .into_iter()
        .map(|cell| match cell {
            GaugeCell::Filled => Span::styled("█", theme::accent()),
            GaugeCell::Track => Span::styled("░", Style::new().dim()),
            GaugeCell::Label(ch) => {
                Span::styled(ch.to_string(), Style::new().add_modifier(Modifier::BOLD))
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(Line::from(bar_spans)), gauge_area);
}

/// Build the 2-row status band's summary line: `done X/Y · fail Z [· paused]`
/// on the left, and — when present — the transient status message on the right.
/// Pure. `width` bounds the message so it can not push the counts off the row.
///
/// `done` counts successfully completed tasks only (`Done(Ok)`); failed and
/// cancelled tasks count toward `total` (and `failed`, for failures only) but
/// NOT toward `done`. This keeps the convention universal: `done` = success,
/// `fail` = failure, disjoint — and matches the queue-overlay header's
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

/// Render one task as a single popup row: direction glyph + name (left) and a
/// state/progress label (right). `selected` bolds the name (the popup applies
/// its own accent to the whole row via the selected row's style). Pure.
///
/// The label collapses each [`TaskState`] to a compact suffix: `queued` /
/// `folder · indeterminate` (queued folders), `<pct>%` or `transferring…`
/// (in-flight), `done` / `cancelled` / `failed: <excerpt>` (terminal). The
/// fill between name and label right-aligns the label against `width`.
pub fn queue_row(
    task: &crate::tui::transfer::ledger::Task,
    width: u16,
    selected: bool,
) -> Line<'static> {
    use crate::tui::transfer::ledger::TaskState;
    use sshrack_core::connect::sftp::proto::TransferOutcome;

    let glyph = match task.job.direction {
        sshrack_core::connect::sftp::proto::Direction::Upload => "↑",
        sshrack_core::connect::sftp::proto::Direction::Download => "↓",
    };
    let name_style = if selected {
        Style::new().add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };

    // Build the right-aligned state/progress label FIRST: the name budget is
    // what remains after the prefix and the label.
    let label = match &task.state {
        TaskState::Queued => {
            if matches!(task.kind, crate::tui::transfer::ledger::TaskKind::Folder) {
                "folder · indeterminate".to_string()
            } else {
                "queued".to_string()
            }
        }
        TaskState::InFlight => match &task.progress {
            Some(p) => match p.bytes_total {
                Some(total) if total > 0 => {
                    let pct = u16::try_from(p.bytes_done.saturating_mul(100) / total)
                        .unwrap_or(100)
                        .min(100);
                    format!("{pct}%")
                }
                _ => "transferring…".to_string(),
            },
            None => "starting…".to_string(),
        },
        TaskState::Done(TransferOutcome::Ok) => "done".to_string(),
        TaskState::Done(TransferOutcome::Cancelled) => "cancelled".to_string(),
        TaskState::Done(TransferOutcome::Failed(msg)) => {
            format!("failed: {}", truncate_cells_head(msg, 20))
        }
    };
    let label_cells = cells(&label);

    // Prefix " <glyph> " is 3 cells; reserve ≥1 cell gap before the label.
    let prefix_cells = 3usize;
    let name_budget = (width as usize).saturating_sub(prefix_cells + 1 + label_cells);
    let shown = truncate_cells(&task.job.name, name_budget);
    let name_cells = cells(&shown);

    let fill = (width as usize).saturating_sub(prefix_cells + name_cells + label_cells + 1);
    let label_style = match &task.state {
        TaskState::Done(TransferOutcome::Failed(_)) => Style::new().fg(crate::tui::theme::DANGER),
        TaskState::Done(TransferOutcome::Ok) => Style::new().dim(),
        TaskState::Queued => Style::new().dim(),
        _ => Style::new(),
    };

    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, name_style),
        Span::raw(" "),
        Span::styled(shown, name_style),
        Span::raw(" ".repeat(fill)),
        Span::styled(label, label_style),
    ])
}

/// The view-switcher tab strip: `Active (n)   Failed (n)   Completed (n)`,
/// separated by a 3-space gutter. The current view is rendered accented +
/// underlined; the others dimmed. `tabs` carries per-view counts (computed by
/// the caller via `task_indices_for`), so this function stays free of ledger
/// internals. Pure: returns a [`Line`] for the overlay's tab row.
pub fn queue_tab_bar(
    current: QueueView,
    tabs: &[(QueueView, usize); 3],
    _width: u16,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    for (i, (view, count)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        let label = match view {
            QueueView::Active => "Active",
            QueueView::Failed => "Failed",
            QueueView::Completed => "Completed",
        };
        let style = if *view == current {
            crate::tui::theme::accent().add_modifier(Modifier::UNDERLINED)
        } else {
            Style::new().dim()
        };
        spans.push(Span::styled(format!("{label} ({count})"), style));
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

/// Laid-out active-transfer row, produced by [`plan_active_row`]. Pure —
/// [`draw_active_transfer`] consumes these fields verbatim. Centralizing the
/// width-driven degradation here keeps every rung of the ladder (drop eta →
/// rate → size → gauge; truncate the name) unit-testable without ratatui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveRowPlan {
    /// Name truncated to its cell budget (with `…` when cut).
    pub name_shown: String,
    /// `"<done>/<total>"` when the total is known, else `"<done>"` (bytes moved).
    pub size_seg: String,
    /// `"<rate>/s"` or `—`.
    pub rate_seg: String,
    /// `"<n>s"` / `"<m>n s"` / `—`.
    pub eta_seg: String,
    pub show_size: bool,
    pub show_rate: bool,
    pub show_eta: bool,
    /// Total cell width of the shown numeric segments, each including its one
    /// leading space. 0 when none are shown. Used to size the right-aligned
    /// segment column so it hugs the gauge with no gap.
    pub segs_w: u16,
    /// Gauge width in cells. 0 ⇒ no gauge (indeterminate total, or row too
    /// narrow even for `GAUGE_MIN` + `NAME_MIN`).
    pub gauge_w: u16,
    /// `Some("N%")` when a gauge is shown, else `None`.
    pub gauge_label: Option<String>,
    /// Integer percent 0..=100 for the gauge bar. 0 when indeterminate.
    pub percent: u16,
}

/// Plan the active-transfer row for a `avail`-wide area. Pure.
///
/// Layout (left → right): `[name][ ↑/↓][ <size>][ <rate>][ <eta>]` left/center,
/// `[gauge N%]` hard against the right edge. The name is the most compressible
/// field: it is truncated to whatever budget remains after the surviving
/// numeric segments and the gauge. As `avail` shrinks, segments are dropped in
/// priority order — eta first (it depends on a known total anyway), then rate,
/// then size — and only when even a bare `NAME_MIN` name + `GAUGE_MIN` gauge no
/// longer fit is the gauge dropped. An unknown total means no gauge, no
/// percent, and no eta, but size + rate remain.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_active_row(
    name: &str,
    done: u64,
    total: Option<u64>,
    rate: Option<u64>,
    eta: Option<u64>,
    avail: u16,
) -> ActiveRowPlan {
    let avail = avail as usize;
    let glyph_w = 2usize; // " ↑" / " ↓" — a space + the arrow, for legibility

    let total_known = total.filter(|t| *t > 0);
    let (percent, gauge_label) = match total_known {
        Some(t) => {
            let pct = u16::try_from(done.saturating_mul(100) / t)
                .unwrap_or(100)
                .min(100);
            (pct, Some(format!("{pct}%")))
        }
        None => (0u16, None),
    };

    let size_seg = match total_known {
        Some(t) => format!("{}/{}", fmt_size(done), fmt_size(t)),
        None => fmt_size(done),
    };
    let rate_seg = fmt_rate(rate);
    let eta_seg = fmt_eta(eta);

    let size_w = cells(&size_seg) + 1; // +1 leading space
    let rate_w = cells(&rate_seg) + 1;
    let eta_w = cells(&eta_seg) + 1;

    // Gauge only when the total is known AND the row can hold gauge + NAME_MIN.
    let mut gauge_w: usize = if total_known.is_some() {
        let g = (avail / 3).clamp(GAUGE_MIN as usize, GAUGE_MAX as usize);
        if avail >= GAUGE_MIN as usize + NAME_MIN + 2 {
            g
        } else {
            0
        }
    } else {
        0
    };
    let mut gauge_used = if gauge_w > 0 { gauge_w + 1 } else { 0 }; // +1 sep before gauge

    // eta is only meaningful with a known total.
    let mut show_eta = total_known.is_some();
    let mut show_size = true;
    let mut show_rate = true;

    let mut segs_w = size_w + if show_rate { rate_w } else { 0 } + if show_eta { eta_w } else { 0 };
    let mut name_budget = avail.saturating_sub(glyph_w + segs_w + gauge_used);

    // Degrade: eta → rate → size → gauge, until the name keeps NAME_MIN.
    if name_budget < NAME_MIN && show_eta {
        show_eta = false;
        segs_w = size_w + if show_rate { rate_w } else { 0 };
        name_budget = avail.saturating_sub(glyph_w + segs_w + gauge_used);
    }
    if name_budget < NAME_MIN && show_rate {
        show_rate = false;
        segs_w = size_w;
        name_budget = avail.saturating_sub(glyph_w + segs_w + gauge_used);
    }
    if name_budget < NAME_MIN && show_size {
        show_size = false;
        segs_w = 0;
        name_budget = avail.saturating_sub(glyph_w + segs_w + gauge_used);
    }
    if name_budget < NAME_MIN && gauge_w > 0 {
        gauge_w = 0;
        gauge_used = 0;
        name_budget = avail.saturating_sub(glyph_w + segs_w + gauge_used);
    }

    let name_shown = truncate_cells(name, name_budget.max(1));

    ActiveRowPlan {
        name_shown,
        size_seg,
        rate_seg,
        eta_seg,
        show_size,
        show_rate,
        show_eta,
        segs_w: segs_w as u16,
        gauge_w: gauge_w as u16,
        gauge_label: gauge_label.filter(|_| gauge_w > 0),
        percent,
    }
}

/// One cell of the active-transfer gauge bar. Pure — [`plan_gauge`] produces a
/// `Vec<GaugeCell>` and [`draw_active_transfer`] maps each to a styled span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GaugeCell {
    /// Filled portion: `█` in the accent color.
    Filled,
    /// Unfilled track: `░` dimmed. Makes the bar's full width (and thus its
    /// 100% endpoint) visible, instead of the blank-space track ratatui's
    /// `Gauge` widget leaves.
    Track,
    /// A label char (from the centered `N%` overlay), replacing the bar char
    /// that would otherwise sit beneath it.
    Label(char),
}

/// Lay out a `gauge_w`-cell progress bar at `percent` (clamped to 0..=100) with
/// `label` (e.g. `"7%"`) overlaid centered. Pure — the renderer maps each
/// [`GaugeCell`] to a styled span. The first `filled = percent*gauge_w/100`
/// cells are [`GaugeCell::Filled`], the rest are [`GaugeCell::Track`], and the
/// label chars sit centered (left-biased), replacing the bar chars beneath
/// them. When the label is empty or at least as wide as the bar, no overlay is
/// applied (the bar is just filled + track) so a too-wide label never overflows.
pub(crate) fn plan_gauge(gauge_w: u16, percent: u16, label: &str) -> Vec<GaugeCell> {
    let w = gauge_w as usize;
    let filled = (percent.min(100) as usize * w / 100).min(w);
    let chars: Vec<char> = label.chars().collect();
    let lc = chars.len();
    let overlay = lc > 0 && lc < w;
    let start = if overlay { (w - lc) / 2 } else { 0 };
    let end = if overlay { start + lc } else { 0 };
    (0..w)
        .map(|i| {
            if overlay && (start..end).contains(&i) {
                GaugeCell::Label(chars[i - start])
            } else if i < filled {
                GaugeCell::Filled
            } else {
                GaugeCell::Track
            }
        })
        .collect()
}

/// Pane-row column plan: the name-column width and whether the meta column
/// survives the width budget. Pure — produced by [`plan_name_col`], consumed
/// by [`draw_pane_list`] / [`draw_pane_row`]. Centralizing this keeps the
/// "shrink name before dropping meta, never silently clip" rule unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameColPlan {
    pub name_w: usize,
    pub show_meta: bool,
}

/// Decide the name-column width and meta visibility for a pane row of `width`
/// inner cells, given the widest visible name (`visible_max`, in display cells)
/// and the meta string's width (`meta_w`, in display cells). Pure.
///
/// The 4-cell leading prefix (mark glyph + focus marker) is reserved first.
/// The name column is capped at [`NAME_COL_CAP`] and, when the row is narrow,
/// shrunk before meta is dropped — down to [`NAME_MIN`]. Only when even
/// `NAME_MIN` + meta won't fit is meta dropped and the name given the full
/// remaining width (capped). This guarantees a long name truncates with `…`
/// instead of overflowing into / silently clipping the meta column.
pub(crate) fn plan_name_col(visible_max: usize, meta_w: usize, width: u16) -> NameColPlan {
    const PREFIX: usize = 4; // mark glyph (2) + focus_marker (2)
    let width = width as usize;
    if width <= PREFIX {
        // Degenerate: not even room for the prefix. Give the name whatever is
        // left; meta cannot survive.
        return NameColPlan {
            name_w: width.max(1),
            show_meta: false,
        };
    }
    let avail = width - PREFIX;
    let cap = NAME_COL_CAP.min(avail);
    let mut name_w = visible_max.min(cap);
    let mut show_meta = true;

    let meta_with_gap = meta_w + 1; // 1-cell gap before the right-aligned meta
    if name_w + meta_with_gap > avail {
        let shrunk = avail.saturating_sub(meta_with_gap);
        if shrunk >= NAME_MIN {
            name_w = shrunk;
        } else {
            // Can't keep meta alongside a usable name: drop meta, give the name
            // the full avail (still capped).
            show_meta = false;
            name_w = avail.min(NAME_COL_CAP);
        }
    }
    NameColPlan { name_w, show_meta }
}

/// How many of `hints` (in order) fit a `width`-wide row when rendered as
/// `"<key> <label>"` joined by `" · "`. Pure. The renderer draws exactly this
/// many leading hints and appends a `…` when fewer than the total fit, so the
/// footer degrades by dropping the least-important (trailing) hints instead of
/// being silently clipped. Always keeps at least the first hint (unless there
/// are none) so the footer is never blank on a narrow terminal.
pub(crate) fn fit_hint_count(hints: &[(&str, &str)], width: u16) -> usize {
    let width = width as usize;
    let mut w = 0usize;
    let mut count = 0usize;
    for (i, (k, label)) in hints.iter().enumerate() {
        // First hint: "key label"; later hints add a " · " separator prefix.
        let seg = if i == 0 {
            format!("{k} {label}")
        } else {
            format!(" · {k} {label}")
        };
        let seg_w = cells(&seg);
        if w + seg_w > width {
            break;
        }
        w += seg_w;
        count += 1;
    }
    count.max(if hints.is_empty() { 0 } else { 1 })
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

    // ---- plan_active_row (width-driven degradation ladder) ----

    #[test]
    fn plan_active_row_wide_shows_all_segments_and_gauge() {
        // avail=100 is plenty: name uncut, all three numeric segments shown,
        // gauge ~1/3 of the row clamped to [10,30] => 30, percent label present.
        let p = plan_active_row("file.bin", 1024, Some(4096), Some(1024), Some(3), 100);
        assert_eq!(p.name_shown, "file.bin", "name fits uncut");
        assert!(
            p.show_size && p.show_rate && p.show_eta,
            "all segments shown"
        );
        assert_eq!(p.gauge_w, 30, "gauge clamps to GAUGE_MAX");
        assert_eq!(p.gauge_label.as_deref(), Some("25%"), "1024/4096 = 25%");
        assert_eq!(p.percent, 25);
        // segs_w = ("1.0K/4.0K"+1) + ("1.0K/s"+1) + ("3s"+1) = 10 + 7 + 3 = 20
        assert_eq!(p.segs_w, 20);
    }

    #[test]
    fn plan_active_row_narrow_drops_eta_before_rate_and_size() {
        // avail=42: name_budget drops below NAME_MIN with all segs, so eta
        // (lowest priority) is dropped first; size + rate + gauge survive.
        let p = plan_active_row("file.bin", 1024, Some(4096), Some(1024), Some(3), 42);
        assert!(!p.show_eta, "eta dropped first");
        assert!(p.show_size && p.show_rate, "size + rate kept");
        assert!(p.gauge_w > 0, "gauge kept");
        assert_eq!(
            p.name_shown, "file.bin",
            "name still fits after dropping eta"
        );
    }

    #[test]
    fn plan_active_row_very_narrow_drops_everything_then_gauge() {
        // avail=15: cannot hold gauge + NAME_MIN, so gauge goes; then all segs
        // go; only a truncated name remains. No percent label without a gauge.
        let p = plan_active_row("file.bin", 1024, Some(4096), Some(1024), Some(3), 15);
        assert!(
            !p.show_size && !p.show_rate && !p.show_eta,
            "all segs dropped"
        );
        assert_eq!(p.gauge_w, 0, "gauge dropped");
        assert!(p.gauge_label.is_none(), "no label without gauge");
        assert_eq!(p.name_shown, "file.bin", "name fits in the freed space");
    }

    #[test]
    fn plan_active_row_long_name_truncates_with_ellipsis() {
        // A 34-cell name in a 50-wide row: name must be cut to its budget and
        // carry `…`. The numeric segments that fit stay; gauge stays.
        let p = plan_active_row(
            "funasr_encoder_adaptor_dynamic.onnx",
            100,
            Some(1000),
            Some(10),
            Some(5),
            50,
        );
        assert!(
            p.name_shown.ends_with('…'),
            "truncated name ends with …: {}",
            p.name_shown
        );
        assert!(
            p.name_shown.starts_with("funasr"),
            "keeps the prefix: {}",
            p.name_shown
        );
        assert!(crate::tui::fit::cells(&p.name_shown) <= 50, "fits the row");
        assert!(p.gauge_w > 0, "gauge still shown");
    }

    #[test]
    fn plan_active_row_indeterminate_has_no_gauge_or_eta() {
        // Unknown total: no gauge, no percent, no eta. Size (bytes done) and
        // rate still carry information, so they stay when width allows.
        let p = plan_active_row("file.bin", 1024, None, Some(1024), None, 80);
        assert_eq!(p.gauge_w, 0, "no gauge when total unknown");
        assert!(
            p.gauge_label.is_none(),
            "no percent label when total unknown"
        );
        assert!(!p.show_eta, "eta meaningless without a total");
        assert!(p.show_size && p.show_rate, "size + rate still shown");
        // size_seg is just bytes done (no /total) when total is unknown
        assert_eq!(p.size_seg, "1.0K");
    }

    #[test]
    fn plan_active_row_indeterminate_shows_no_percent_in_label() {
        // Belt-and-suspenders: an indeterminate transfer must never synthesize
        // a percent label, even on a wide row.
        let p = plan_active_row("big.bin", 9_999_999_999, None, None, None, 120);
        assert!(p.gauge_label.is_none());
        assert_eq!(p.gauge_w, 0);
    }

    // ---- plan_gauge: pure bar-layout helper ----

    #[test]
    fn plan_gauge_half_width_10_label_50pct() {
        // 50% of 10 = 5 filled; label "50%" (3 chars) centered at start=3.
        // Cells: [0,3) Filled, [3,6) Label, [6,10) Track.
        use super::{GaugeCell, plan_gauge};
        let cells = plan_gauge(10, 50, "50%");
        assert_eq!(
            cells,
            vec![
                GaugeCell::Filled,
                GaugeCell::Filled,
                GaugeCell::Filled,
                GaugeCell::Label('5'),
                GaugeCell::Label('0'),
                GaugeCell::Label('%'),
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Track,
            ]
        );
    }

    #[test]
    fn plan_gauge_zero_pct_all_track_with_centered_label() {
        // 0% → no filled; "0%" centered in width 8 (start=3).
        use super::{GaugeCell, plan_gauge};
        let cells = plan_gauge(8, 0, "0%");
        assert_eq!(
            cells,
            vec![
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Label('0'),
                GaugeCell::Label('%'),
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Track,
            ]
        );
    }

    #[test]
    fn plan_gauge_full_pct_all_filled_with_centered_label() {
        // 100% → all filled; "100%" (4 chars) centered in width 8 (start=2).
        use super::{GaugeCell, plan_gauge};
        let cells = plan_gauge(8, 100, "100%");
        assert_eq!(
            cells,
            vec![
                GaugeCell::Filled,
                GaugeCell::Filled,
                GaugeCell::Label('1'),
                GaugeCell::Label('0'),
                GaugeCell::Label('0'),
                GaugeCell::Label('%'),
                GaugeCell::Filled,
                GaugeCell::Filled,
            ]
        );
    }

    #[test]
    fn plan_gauge_seven_pct_width_30_counts() {
        // The screenshot case: 7% of 30 = 2 filled; "7%" centered at start=14.
        let cells = super::plan_gauge(30, 7, "7%");
        let filled = cells
            .iter()
            .filter(|c| matches!(c, super::GaugeCell::Filled))
            .count();
        let track = cells
            .iter()
            .filter(|c| matches!(c, super::GaugeCell::Track))
            .count();
        let label = cells
            .iter()
            .filter(|c| matches!(c, super::GaugeCell::Label(_)))
            .count();
        assert_eq!(filled, 2, "7% of 30 = 2 filled cells");
        assert_eq!(label, 2, "\"7%\" = 2 label cells");
        assert_eq!(track, 26, "remainder is track");
        assert_eq!(cells.len(), 30, "fills gauge_w exactly");
        // Label sits centered (start 14): cells 14 and 15.
        assert!(matches!(cells[14], super::GaugeCell::Label('7')));
        assert!(matches!(cells[15], super::GaugeCell::Label('%')));
    }

    #[test]
    fn plan_gauge_empty_label_no_overlay() {
        // Empty label → no overlay, just filled + track.
        use super::{GaugeCell, plan_gauge};
        let cells = plan_gauge(6, 50, "");
        assert_eq!(
            cells,
            vec![
                GaugeCell::Filled,
                GaugeCell::Filled,
                GaugeCell::Filled,
                GaugeCell::Track,
                GaugeCell::Track,
                GaugeCell::Track,
            ]
        );
    }

    #[test]
    fn plan_gauge_label_wider_than_bar_no_overlay() {
        // Label "100%" (4) >= width 3 → drop overlay; 50% of 3 = 1 filled.
        use super::{GaugeCell, plan_gauge};
        let cells = plan_gauge(3, 50, "100%");
        assert_eq!(
            cells,
            vec![GaugeCell::Filled, GaugeCell::Track, GaugeCell::Track]
        );
    }

    #[test]
    fn plan_gauge_zero_width_empty() {
        // Degenerate: zero-width gauge yields no cells (caller skips rendering).
        assert!(super::plan_gauge(0, 50, "50%").is_empty());
    }

    #[test]
    fn plan_gauge_clamps_percent_above_100() {
        // Defensive: percent > 100 must not overflow or over-fill.
        let cells = super::plan_gauge(10, 150, "100%");
        let filled = cells
            .iter()
            .filter(|c| matches!(c, super::GaugeCell::Filled))
            .count();
        assert_eq!(cells.len(), 10);
        // 150 clamped to 100 → 10 filled minus the 4 label cells overlapping = 6 Filled.
        assert_eq!(filled, 6);
    }

    // ---- draw_active_transfer: render-alignment regression ----

    /// Read row 0 of a TestBackend buffer as a trimmed String.
    fn row_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buf = term.backend().buffer();
        let s: String = (0..buf.area.width)
            .map(|col| {
                buf.cell((col, 0u16))
                    .map(|c| c.symbol())
                    .unwrap_or(" ")
                    .to_string()
            })
            .collect();
        s.trim_end().to_string()
    }

    #[test]
    fn draw_active_transfer_renders_rate_with_one_per_sec() {
        // `fmt_rate` already returns `<size>/s`; the active-transfer text must
        // not append another `/s` (the `13.4M/s/s` regression that surfaced
        // once upload progress actually started updating).
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};

        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 1_024,
            bytes_total: Some(4_096),
            rate_bps: Some(1_024),
            eta_secs: Some(3),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains("1.0K/s"), "rate should appear once: {text:?}");
        assert!(
            !text.contains("/s/s"),
            "rate must not double the /s suffix: {text:?}"
        );
    }

    #[test]
    fn draw_active_transfer_wide_shows_name_segments_and_gauge() {
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 1_024,
            bytes_total: Some(4_096),
            rate_bps: Some(1_024),
            eta_secs: Some(3),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains("file.bin"), "name shown: {text:?}");
        assert!(text.contains("1.0K/4.0K"), "size shown: {text:?}");
        assert!(text.contains("1.0K/s"), "rate shown: {text:?}");
        assert!(text.contains("3s"), "eta shown: {text:?}");
        assert!(text.contains("25%"), "gauge percent shown: {text:?}");
        // The bar fills the gauge width to the right edge: the last cell is a
        // bar cell (`█` filled or `░` track), never blank — no trailing waste.
        let last = text.chars().last().expect("non-empty row");
        assert!(
            last == '█' || last == '░',
            "right edge is a bar cell (no trailing waste): {text:?}"
        );
        // The unfilled track is visible — the 100% endpoint is no longer blank.
        assert!(text.contains('░'), "visible track below 100%: {text:?}");
    }

    #[test]
    fn draw_active_transfer_narrow_truncates_name_and_keeps_gauge_at_right() {
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "funasr_encoder_adaptor_dynamic.onnx".into(),
            direction: Direction::Upload,
            bytes_done: 2_000_000_000,
            bytes_total: Some(10_000_000_000),
            rate_bps: Some(14_000_000),
            eta_secs: Some(55),
        };
        let mut term = Terminal::new(TestBackend::new(30, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains('…'), "long name truncated with …: {text:?}");
        // No silent clipping past the right edge: row never exceeds 30 cells.
        assert!(
            crate::tui::fit::cells(&text) <= 30,
            "row fits the area: {text:?}"
        );
        // Percent still present (gauge survives at width 30).
        assert!(text.contains('%'), "gauge label present: {text:?}");
    }

    #[test]
    fn draw_active_transfer_indeterminate_has_no_gauge_or_percent() {
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "stream.bin".into(),
            direction: Direction::Download,
            bytes_done: 5_000_000,
            bytes_total: None,
            rate_bps: Some(2_000_000),
            eta_secs: None,
        };
        let mut term = Terminal::new(TestBackend::new(80, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains("stream.bin"), "name shown: {text:?}");
        assert!(
            !text.contains('%'),
            "no percent when total unknown: {text:?}"
        );
        assert!(text.contains("1.9M/s"), "rate shown: {text:?}");
    }

    #[test]
    fn draw_active_transfer_percent_appears_exactly_once() {
        // The percent must live in the gauge label only — never also printed in
        // the text segment (the old `{}% ... {}/{} ...` format doubled it).
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 1_024,
            bytes_total: Some(4_096),
            rate_bps: Some(1_024),
            eta_secs: Some(3),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        let pct_count = text.matches('%').count();
        assert_eq!(pct_count, 1, "percent appears exactly once: {text:?}");
    }

    #[test]
    fn draw_active_transfer_bar_shows_visible_track_below_100pct() {
        // The whole point: below 100% the unfilled portion is a visible `░`
        // track, not blank space, so the bar's endpoint is visible.
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 1_024,
            bytes_total: Some(4_096),
            rate_bps: Some(1_048_576),
            eta_secs: Some(3),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains('█'), "filled portion present: {text:?}");
        assert!(text.contains('░'), "visible track present: {text:?}");
        assert!(text.contains("25%"), "percent overlaid: {text:?}");
    }

    #[test]
    fn draw_active_transfer_full_pct_has_no_track() {
        // At 100% the bar is entirely filled — no `░` track remains.
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 4_096,
            bytes_total: Some(4_096),
            rate_bps: Some(1_048_576),
            eta_secs: Some(0),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let text = row_text(&term);
        assert!(text.contains('█'), "filled bar present: {text:?}");
        assert!(!text.contains('░'), "no track at 100%: {text:?}");
        assert!(text.contains("100%"), "percent overlaid: {text:?}");
    }

    #[test]
    fn draw_active_transfer_bar_fills_to_right_edge_no_trailing_waste() {
        // The bar must reach the right edge of the area — the rightmost buffer
        // cell is a bar/label cell, never a space. This is the "no wasted
        // right-side space" guarantee (row_text trims trailing spaces, so check
        // the raw buffer cell at the last column directly).
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::connect::sftp::proto::{Direction, Progress};
        let prog = Progress {
            name: "file.bin".into(),
            direction: Direction::Upload,
            bytes_done: 1_024,
            bytes_total: Some(4_096),
            rate_bps: Some(1_024),
            eta_secs: Some(3),
        };
        let mut term = Terminal::new(TestBackend::new(100, 1)).unwrap();
        term.draw(|f| draw_active_transfer(f, f.area(), Some(&prog)))
            .unwrap();
        let buf = term.backend().buffer();
        let last = buf
            .cell((99u16, 0u16))
            .expect("rightmost cell")
            .symbol()
            .to_string();
        assert!(
            last == "█" || last == "░" || last == "%" || last.chars().all(|c| c.is_ascii_digit()),
            "rightmost cell is a bar/label cell, not blank: {last:?}"
        );
        assert_ne!(last, " ", "no trailing blank at the right edge");
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
        let line = draw_pane_row(&e, "", true, true, true, 12, 50, true);
        let s = format!("{line}");
        assert!(s.starts_with('●'), "marked row must lead with ●: {s}");
    }

    #[test]
    fn draw_pane_row_unmarked_leads_with_spaces() {
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, true, 12, 50, true);
        let s = format!("{line}");
        assert!(
            s.starts_with("  "),
            "unmarked row must lead with two spaces: {s}"
        );
    }

    #[test]
    fn draw_pane_row_cursor_on_focused_pane_paints_focus_arrow() {
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, true, 12, 50, true);
        let s = format!("{line}");
        assert!(s.contains('▶'), "focused cursor must show ▶: {s}");
    }

    #[test]
    fn draw_pane_row_cursor_on_dimmed_pane_does_not_paint_arrow() {
        // Non-focused pane: no accented arrow (the cursor is shown only by the
        // absence of the arrow on the dim row, matching the launcher pattern).
        let e = entry("alpha.txt", false, Some(1024));
        let line = draw_pane_row(&e, "", true, false, false, 12, 50, true);
        let s = format!("{line}");
        assert!(!s.contains('▶'), "dim cursor must not show ▶: {s}");
    }

    #[test]
    fn draw_pane_row_strips_fake_control_chars_from_name() {
        let mut e = entry("evil", false, None);
        e.name = "foo\x1b[2Jbar".into();
        let line = draw_pane_row(&e, "", false, false, true, 12, 50, true);
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
        let line = draw_pane_row(&e, "", false, false, true, 12, 50, true);
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
        let line = draw_pane_row(&e, "", true, false, true, 12, 50, true);
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
        let line = draw_pane_row(&e, "", false, false, true, 12, 50, true);
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

    // ---- plan_name_col (pane row width planning) ----

    #[test]
    fn plan_name_col_wide_keeps_full_name_and_meta() {
        // visible_max 12, meta 19, width 50: plenty — name_w = min(12, CAP=24) = 12, meta shown.
        let p = plan_name_col(12, 19, 50);
        assert_eq!(p.name_w, 12);
        assert!(p.show_meta);
    }

    #[test]
    fn plan_name_col_caps_at_name_col_cap() {
        // A 40-cell visible name is capped at NAME_COL_CAP (24), not 40.
        let p = plan_name_col(40, 19, 80);
        assert_eq!(p.name_w, NAME_COL_CAP);
        assert!(p.show_meta);
    }

    #[test]
    fn plan_name_col_narrow_shrinks_name_to_keep_meta() {
        // width 30, prefix 4, meta 19+1 gap = 20: name_w would be 30-4-20 = 6 == NAME_MIN, meta kept.
        let p = plan_name_col(12, 19, 30);
        assert!(p.show_meta, "meta kept when name can shrink to NAME_MIN");
        assert_eq!(p.name_w, 6);
    }

    #[test]
    fn plan_name_col_too_narrow_drops_meta() {
        // width 20, prefix 4 → avail 16. meta 20 won't fit alongside NAME_MIN:
        // meta dropped, name gets the full avail (capped).
        let p = plan_name_col(12, 19, 20);
        assert!(!p.show_meta, "meta dropped when it can't share the row");
        assert_eq!(p.name_w, 16, "name takes the full avail");
    }

    // ---- fit_hint_count (footer hint budget) ----

    #[test]
    fn fit_hint_count_wide_keeps_all_hints() {
        let hints: &[(&str, &str)] = &[("Tab", "switch"), ("↑↓", "move"), ("F1", "help")];
        // Each hint renders as "<key> <label>", joined by " · ".
        // "Tab switch" = 10, " · ↑↓ move" = 10, " · F1 help" = 10 → 30 cells.
        assert_eq!(fit_hint_count(hints, 40), 3);
        assert_eq!(fit_hint_count(hints, 30), 3);
    }

    #[test]
    fn fit_hint_count_narrow_drops_trailing_hints() {
        let hints: &[(&str, &str)] = &[("Tab", "switch"), ("↑↓", "move"), ("F1", "help")];
        // Only room for the first hint (10 cells) + the `…` sentinel is drawn
        // by the renderer, not counted here. width=15 fits hint 0 + part of
        // the gap but not hint 1 fully → count = 1.
        assert_eq!(fit_hint_count(hints, 15), 1);
    }

    #[test]
    fn fit_hint_count_always_keeps_at_least_one() {
        let hints: &[(&str, &str)] = &[("Tab", "switch"), ("F1", "help")];
        // Even on a tiny row, the first hint survives so the footer is never
        // blank.
        assert_eq!(fit_hint_count(hints, 5), 1);
    }

    #[test]
    fn fit_hint_count_empty_hints_returns_zero() {
        let hints: &[(&str, &str)] = &[];
        assert_eq!(fit_hint_count(hints, 80), 0);
    }

    #[test]
    fn draw_pane_row_long_name_truncates_with_ellipsis() {
        // A name longer than name_w is truncated to name_w cells with `…`, and
        // does NOT overflow into the meta column.
        let e = entry(
            "a_really_long_filename_that_exceeds_the_column.onnx",
            false,
            Some(1024),
        );
        let line = draw_pane_row(&e, "", false, false, true, 12, 60, true);
        let s = format!("{line}");
        assert!(s.contains('…'), "long name truncated: {s}");
        assert!(
            crate::tui::fit::cells(&s) <= 60,
            "row never exceeds width: {s:?}"
        );
    }

    #[test]
    fn draw_pane_row_no_meta_when_plan_says_so() {
        // show_meta=false: the size/mtime column is omitted entirely (the row
        // is just marker + focus + name, padded out).
        let e = entry("alpha.txt", false, Some(2048));
        let line = draw_pane_row(&e, "", false, false, true, 12, 20, false);
        let s = format!("{line}");
        assert!(
            !s.contains("2.0K"),
            "size column hidden when show_meta=false: {s}"
        );
    }

    #[test]
    fn draw_pane_row_cjk_name_aligns_by_display_width() {
        // A CJK glyph is 2 cells. "中文" is 4 display cells; with name_w=8 the
        // name must pad by 4 (display width) so the meta column starts at the
        // same offset as an ASCII row of the same cell width. With the old
        // char-count pad, "中文" (2 chars) would pad 6, yielding 10 cells !=
        // name_w=8 — this assertion catches that regression.
        let name_w = 8usize;
        let width = 40u16;
        let e_cjk = entry("中文", false, Some(1024));
        let line = draw_pane_row(&e_cjk, "", false, false, true, name_w, width, true);
        // Span layout: [mark, focus, name..., pad, fill, meta]. The fill span
        // (pure spaces) sits right before meta; name+pad is spans[2..fill_idx).
        let meta_idx = line
            .spans
            .iter()
            .position(|s| s.content.contains("1.0K"))
            .expect("meta span carrying the size");
        let name_pad: String = line.spans[2..meta_idx - 1]
            .iter()
            .map(|s| &*s.content)
            .collect();
        assert_eq!(
            crate::tui::fit::cells(&name_pad),
            name_w,
            "name+pad must be exactly name_w display cells; got {:?} ({} cells)",
            name_pad,
            crate::tui::fit::cells(&name_pad),
        );
        // Whole row still fits the allotted width.
        let s = format!("{line}");
        assert!(
            crate::tui::fit::cells(&s) <= width as usize,
            "cjk row fits width: {s:?}"
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

    #[test]
    fn draw_pane_truncates_a_very_long_filename_snapshot() {
        // Snapshot a focused pane carrying one entry whose filename is far
        // wider than the pane. Locks the truncation behavior: the name is cut
        // to fit, and the marker/cursor glyphs are not pushed off the row.
        // Hermetic: modified: None (no real time), fixed name/path/size,
        // in-memory TestBackend — identical output on any machine.
        use ratatui::{Terminal, backend::TestBackend};
        use sshrack_core::dirsource::DirEntry;

        use crate::tui::transfer::pane::Pane;

        let long = "this-is-an-extremely-long-filename-that-overflows-the-pane-width.tar.gz";
        let mut pane = Pane::new(std::path::PathBuf::from("/home/u/project"));
        pane.set_entries(vec![DirEntry {
            name: long.to_string(),
            path: std::path::PathBuf::from(format!("/home/u/project/{long}")),
            is_dir: false,
            is_symlink: false,
            size: Some(1024),
            modified: None,
        }]);
        let backend = TestBackend::new(40, 10);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| draw_pane(f, f.area(), &pane, true, "local"))
            .unwrap();
        insta::assert_snapshot!(term.backend());
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

#[cfg(test)]
mod queue_row_tests {
    use super::*;
    use crate::tui::transfer::ledger::{Task, TaskId, TaskKind, TaskState};
    use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob, TransferOutcome};

    fn task(name: &str, state: TaskState, recursive: bool) -> Task {
        Task {
            id: TaskId(0),
            kind: if recursive {
                TaskKind::Folder
            } else {
                TaskKind::File
            },
            job: TransferJob {
                direction: Direction::Upload,
                src: format!("/s/{name}").into(),
                dst: format!("/d/{name}").into(),
                name: name.into(),
                size_total: Some(100),
                recursive,
            },
            progress: None,
            state,
        }
    }

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn queue_row_queued_shows_name_and_queued_label() {
        let t = task("photo.jpg", TaskState::Queued, false);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("photo.jpg"), "{s}");
        assert!(s.contains("queued"), "{s}");
    }

    #[test]
    fn queue_row_failed_shows_error_excerpt() {
        let t = task(
            "old.log",
            TaskState::Done(TransferOutcome::Failed("no such file".into())),
            false,
        );
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("old.log"), "{s}");
        assert!(s.contains("failed"), "{s}");
        assert!(s.contains("no such file"), "{s}");
    }

    #[test]
    fn queue_row_inflight_shows_progress_percent() {
        let mut t = task("big.tar", TaskState::InFlight, false);
        t.progress = Some(Progress {
            name: "big.tar".into(),
            direction: Direction::Upload,
            bytes_done: 40,
            bytes_total: Some(100),
            rate_bps: Some(5),
            eta_secs: Some(12),
        });
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("big.tar"), "{s}");
        assert!(s.contains("40%"), "{s}");
    }

    #[test]
    fn queue_row_inflight_percent_grows_across_snapshots() {
        // The queue row's percent must track the progress snapshot as it
        // advances — the "queue refreshes" guarantee. Two snapshots of the
        // same job at 40% and 70% must render their respective percents, so a
        // stuck-at-0% queue row regressions is caught.
        let mut t40 = task("big.tar", TaskState::InFlight, false);
        t40.progress = Some(Progress {
            name: "big.tar".into(),
            direction: Direction::Upload,
            bytes_done: 40,
            bytes_total: Some(100),
            rate_bps: Some(5),
            eta_secs: Some(12),
        });
        let s40 = text(&queue_row(&t40, 60, false));
        assert!(s40.contains("40%"), "40% snapshot: {s40}");

        let mut t70 = task("big.tar", TaskState::InFlight, false);
        t70.progress = Some(Progress {
            name: "big.tar".into(),
            direction: Direction::Upload,
            bytes_done: 70,
            bytes_total: Some(100),
            rate_bps: Some(8),
            eta_secs: Some(6),
        });
        let s70 = text(&queue_row(&t70, 60, false));
        assert!(s70.contains("70%"), "70% snapshot: {s70}");
    }

    #[test]
    fn queue_row_folder_shows_folder_label_when_indeterminate() {
        let t = task("src/", TaskState::Queued, true);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("folder"), "folder label: {s}");
    }

    #[test]
    fn queue_row_truncates_a_long_name_and_keeps_label_visible() {
        let long = "x".repeat(80);
        let t = task(&long, TaskState::Queued, false);
        let s = text(&queue_row(&t, 20, false));
        assert!(s.contains('…'), "long name is truncated: {s}");
        assert!(
            s.contains("queued"),
            "label still visible after truncation: {s}"
        );
    }

    #[test]
    fn queue_row_leaves_a_short_name_intact_at_wide_width() {
        let t = task("photo.jpg", TaskState::Queued, false);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("photo.jpg"), "{s}");
        assert!(!s.contains('…'), "no truncation when the name fits: {s}");
    }
}

#[cfg(test)]
mod queue_tab_bar_tests {
    use super::*;
    use crate::tui::transfer::queue_overlay::QueueView;

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn tab_bar_lists_all_three_views_with_counts() {
        let tabs = [
            (QueueView::Active, 2),
            (QueueView::Failed, 1),
            (QueueView::Completed, 5),
        ];
        let line = queue_tab_bar(QueueView::Active, &tabs, 80);
        let s = line_to_string(&line);
        assert!(s.contains("Active (2)"), "{s}");
        assert!(s.contains("Failed (1)"), "{s}");
        assert!(s.contains("Completed (5)"), "{s}");
    }

    #[test]
    fn tab_bar_underlines_only_the_current_view() {
        let tabs = [
            (QueueView::Active, 0),
            (QueueView::Failed, 0),
            (QueueView::Completed, 0),
        ];
        let line = queue_tab_bar(QueueView::Failed, &tabs, 80);
        // The span for "Failed (0)" is the only one flagged UNDERLINED.
        let labeled: Vec<(&str, bool)> = line
            .spans
            .iter()
            .map(|s| {
                (
                    s.content.as_ref(),
                    s.style
                        .add_modifier
                        .contains(ratatui::style::Modifier::UNDERLINED),
                )
            })
            .collect();
        let current = labeled
            .iter()
            .find(|(t, _)| t.contains("Failed"))
            .map(|(_, u)| *u);
        assert_eq!(current, Some(true), "current view underlined");
        let others_underlined = labeled
            .iter()
            .filter(|(t, u)| (t.contains("Active") || t.contains("Completed")) && *u)
            .count();
        assert_eq!(others_underlined, 0, "non-current views not underlined");
    }
}
