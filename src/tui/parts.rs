//! Shared render parts for the Hosts / Credentials panels: a vertical-center
//! helper (this task), plus the status row and boxed search input added later.
//! Pure layout/render — no I/O, no state. Kept separate from `panel.rs` (which
//! stays pure ranking data) so the data module is not pulled into rendering.

use ratatui::layout::Rect;

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
