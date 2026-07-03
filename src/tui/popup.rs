//! Centered popup primitive: a `Clear`-backed bordered area on the screen.
//!
//! Two helpers:
//! - [`centered_rect`] — the standard ratatui recipe, pure and unit-testable.
//!   Sizes to the caller's requested `(w, h)` so a popup hugs its content
//!   instead of always occupying a fixed 60x20 box.
//! - [`render_popup`] — draw a bordered, clear-backed area with a title and the
//!   given body widget inside it, then return the inner content rect. Used by
//!   `prompt`'s password / confirm / store-pick popups and the credential
//!   picker; kept here so all share one chrome.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    widgets::{Block, Borders, Clear, Widget},
};

/// Default upper bound on popup width. Callers asking for the classic cap
/// (e.g. the credential picker, which renders a long list) pass this rather
/// than computing their own content width.
pub const POPUP_WIDTH: u16 = 60;

/// Default upper bound on popup height. See [`POPUP_WIDTH`] for the rationale.
pub const POPUP_HEIGHT: u16 = 20;

/// Standard ratatui centered-rect recipe: returns a rect of `w` x `h` centered
/// inside `r`, clamped down to `r`'s dimensions when the terminal is too small
/// (so we still render top-left aligned instead of panicking on a zero-size
/// rect). Pure (no I/O), so the geometry is unit-testable.
pub fn centered_rect(r: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(r.width);
    let h = h.min(r.height);
    // Three-segment layouts with the popup in the middle, flanked by Fill
    // spacers, center it both horizontally and vertically.
    let [_, vert_mid, _] = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(h),
        Constraint::Fill(1),
    ])
    .areas(r);
    let [_, area, _] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(w),
        Constraint::Fill(1),
    ])
    .areas(vert_mid);
    area
}

/// Render a clear-backed bordered popup titled `title` at a centered `(w, h)`
/// footprint, then render `body` inside it, and return the inner content rect
/// (so callers that need to place a terminal cursor — e.g. the password popup's
/// masked input or the credential picker's query box — know where the content
/// area landed). Callers that ignore the return value are unaffected.
pub fn render_popup<W: Widget>(frame: &mut Frame, title: &str, body: W, w: u16, h: u16) -> Rect {
    let area = centered_rect(frame.area(), w, h);
    // Clear the background so previous frame content doesn't bleed through.
    frame.render_widget(Clear, area);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {title} "));
    frame.render_widget(&block, area);
    let [content] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
    frame.render_widget(body, content);
    content
}

#[cfg(test)]
mod tests {
    //! Geometry tests for the centered popup rect (clamping against tiny
    //! viewports) and the paragraph layout. Rendering itself is ratatui's
    //! job; these pin our `centered_rect` math against the `(w, h)` signature.
    use super::*;

    #[test]
    fn centered_rect_uses_given_size_and_centers() {
        let screen = Rect::new(0, 0, 100, 40);
        let r = centered_rect(screen, 40, 6);
        assert_eq!((r.width, r.height), (40, 6));
        assert_eq!(r.x, 30); // centered horizontally
        assert_eq!(r.y, 17); // centered vertically
    }

    #[test]
    fn centered_rect_clamps_to_screen_when_too_small() {
        let tiny = Rect::new(0, 0, 10, 5);
        let r = centered_rect(tiny, 40, 6);
        assert_eq!((r.width, r.height), (10, 5), "clamps down, never overflows");
    }

    #[test]
    fn centered_rect_clamps_only_width_when_height_fits() {
        // Asymmetric clamp: width too wide but height fits — width clamps, height
        // keeps the requested value and centers within the un-clamped axis.
        let screen = Rect::new(0, 0, 30, 40);
        let r = centered_rect(screen, 40, 6);
        assert_eq!((r.width, r.height), (30, 6));
    }

    #[test]
    fn render_popup_returns_inner_content_rect() {
        use ratatui::{Terminal, backend::TestBackend, widgets::Paragraph};
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        let mut captured = None;
        let _ = term.draw(|f| {
            captured = Some(render_popup(f, "Title", Paragraph::new("body"), 40, 6));
        });
        let rect = captured.unwrap();
        // The content rect sits inside the bordered popup (border = 1 cell each
        // side), so it is strictly smaller than the centered 40x6 popup rect
        // and offset inward by one row/column.
        let popup = centered_rect(Rect::new(0, 0, 100, 40), 40, 6);
        assert!(rect.x >= popup.x);
        assert!(rect.x + rect.width <= popup.x + popup.width);
        assert!(rect.y >= popup.y);
        assert!(rect.y + rect.height <= popup.y + popup.height);
        assert_eq!(rect.width, 38, "content loses 2 columns to the border");
        assert_eq!(rect.height, 4, "content loses 2 rows to the border");
    }
}
