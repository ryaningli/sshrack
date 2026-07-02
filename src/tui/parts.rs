//! Shared render parts for the Hosts / Credentials panels: a vertical-center
//! helper, plus the status row rendered at the bottom of each panel's own
//! area. Pure layout/render — no I/O, no state. Kept separate from `panel.rs`
//! (which stays pure ranking data) so the data module is not pulled into
//! rendering.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
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
