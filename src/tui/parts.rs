//! Shared render parts for the Hosts / Credentials panels: a vertical-center
//! helper, plus the status row rendered at the bottom of each panel's own
//! area. Pure layout/render — no I/O, no state. Kept separate from `panel.rs`
//! (which stays pure ranking data) so the data module is not pulled into
//! rendering.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph},
};

use super::intent::Status;
use super::theme;

/// A sub-rect of `area` with height `h`, vertically centered (horizontal span
/// unchanged). Used to place the empty-state line in the middle of the list
/// area instead of pinned to the top row.
pub fn vertical_center(area: Rect, h: u16) -> Rect {
    Rect {
        y: area.y + area.height.saturating_sub(h) / 2,
        height: h,
        ..area
    }
}

/// `matched/total` — always this form, even when unfiltered (then
/// `matched == total`, e.g. `50/50`). Extracted so the count format is pure and
/// unit-testable independent of rendering.
pub fn count_label(matched: usize, total: usize) -> String {
    format!("{matched}/{total}")
}

/// Render the search input as a bordered box: `❯ <query>` on the left, the
/// [`count_label`] right-aligned, both inside a 3-row bordered band (top border,
/// one content row, bottom border). The terminal cursor is placed right after
/// the query. `matched` is the filtered (post-query) list length, `total` the
/// full list length. Callers give this a `Length(3)` band.
pub fn draw_search_box(frame: &mut Frame, area: Rect, query: &str, matched: usize, total: usize) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().dim())
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let label = count_label(matched, total);
    let label_w = label.chars().count() as u16;
    let [prompt_area, count_area] =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(label_w)]).areas(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("❯ ", Style::new().dim()),
            Span::raw(query),
        ])),
        prompt_area,
    );
    frame.render_widget(
        Paragraph::new(label)
            .alignment(Alignment::Right)
            .style(Style::new().dim()),
        count_area,
    );

    // The terminal cursor sits right after the 2-cell `❯ ` prefix, inside the
    // box's content row. `inner` is already inset by border + padding.
    let cursor_x = inner.x + 2 + query.chars().count() as u16;
    let max_x = inner.x + inner.width.saturating_sub(1);
    frame.set_cursor_position((cursor_x.min(max_x), inner.y));
}

/// Render the consolidated status as the bottom row of a panel's area: a dim
/// `› ` prefix + the message (red on [`Status::is_error`]). A `Status::empty`
/// renders just the dim prefix so the row's height stays stable. This replaces
/// the old shell-footer status branch — the shell footer is now hotkey-only.
pub fn draw_status_row(frame: &mut Frame, area: Rect, status: &Status) {
    let line = match &status.message {
        Some(msg) => {
            let style = if status.is_error {
                Style::new().fg(theme::DANGER)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::styled("› ", Style::new().dim()),
                Span::styled(msg.clone(), style),
            ])
        }
        None => Line::from(vec![Span::styled("› ", Style::new().dim())]),
    };
    frame.render_widget(Paragraph::new(line), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_label_is_matched_slash_total_for_filtered_query() {
        // A filtered query shows the matched count over the total.
        assert_eq!(count_label(12, 50), "12/50");
    }

    #[test]
    fn count_label_shows_full_count_when_unfiltered() {
        // Unfiltered: matched == total, still the same `{matched}/{total}` form.
        assert_eq!(count_label(50, 50), "50/50");
    }

    #[test]
    fn count_label_shows_zero_when_nothing_matches() {
        // A query that matches nothing still shows 0 over the total.
        assert_eq!(count_label(0, 3), "0/3");
    }
}
