//! Centered popup primitive: a `Clear`-backed bordered area on the screen.
//!
//! Two helpers:
//! - [`centered_rect`] — the standard ratatui recipe, pure and unit-testable.
//! - [`render_popup`] — draw a bordered, clear-backed area with a title and the
//!   given body widget inside it. Used by `prompt`'s password and confirm
//!   popups; kept here so both share one chrome.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, Borders, Clear, Widget},
};

/// The fixed size of a popup. Centralized so password and confirm popups share
/// the same footprint.
const POPUP_WIDTH: u16 = 60;
const POPUP_HEIGHT: u16 = 20;

/// Standard ratatui centered-rect recipe. Returns a rect of `POPUP_WIDTH` x
/// `POPUP_HEIGHT` centered inside `r`. Pure (no I/O), so the geometry is
/// unit-testable. When the terminal is too small, returns `r` clamped so we
/// still render top-left aligned instead of panicking on a zero-size rect.
pub fn centered_rect(r: Rect) -> Rect {
    let popup = Rect::new(0, 0, POPUP_WIDTH, POPUP_HEIGHT);
    if r.width < popup.width || r.height < popup.height {
        return r;
    }
    // Three-segment layouts with the popup in the middle, flanked by Fill
    // spacers, center it both horizontally and vertically.
    let [_, vert_mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(popup.height),
        Constraint::Fill(1),
    ])
    .areas(r);
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(popup.width),
        Constraint::Fill(1),
    ])
    .areas(vert_mid);
    area
}

/// Render a clear-backed bordered popup titled `title`, then render `body`
/// inside it. The caller drives input by reading keys separately; this fn only
/// paints the chrome + body widget.
pub fn render_popup<W: Widget>(frame: &mut Frame, title: &str, body: W) {
    let area = centered_rect(frame.area());
    // Clear the background so previous frame content doesn't bleed through.
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "));
    frame.render_widget(&block, area);
    let [content] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
    frame.render_widget(body, content);
}

#[cfg(test)]
mod tests {
    //! Geometry tests for the centered popup rect (clamping against tiny
    //! viewports) and the paragraph layout. Rendering itself is ratatui's
    //! job; these pin our `centered_rect` math.
    use super::*;

    #[test]
    fn centered_rect_is_centered_when_screen_large_enough() {
        let screen = Rect::new(0, 0, 100, 40);
        let popup = centered_rect(screen);
        assert_eq!(popup.width, 60);
        assert_eq!(popup.height, 20);
        // Horizontal center: left margin == right margin == 20.
        assert_eq!(popup.x, 20);
        // Vertical center: top margin == bottom margin == 10.
        assert_eq!(popup.y, 10);
    }

    #[test]
    fn centered_rect_clamps_to_screen_when_too_small() {
        // A terminal smaller than the popup returns the whole screen (top-left
        // aligned, no panic, no zero-size rect).
        let tiny = Rect::new(0, 0, 10, 5);
        let popup = centered_rect(tiny);
        assert_eq!(popup, tiny);
    }

    #[test]
    fn centered_rect_exactly_popup_sized_returns_full_screen() {
        let exact = Rect::new(0, 0, POPUP_WIDTH, POPUP_HEIGHT);
        let popup = centered_rect(exact);
        assert_eq!(popup, exact);
    }
}
