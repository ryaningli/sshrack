//! The persistent three-band shell: brand + tab bar on top, the active panel's
//! area in the middle (returned to the caller, wrapped in a thin dim border),
//! and a contextual hotkey footer on the bottom. Pure render — no I/O.
//!
//! The shell is the only fixed chrome on screen; the active panel fills the
//! `Rect` this function returns. Brand on the left, the [`Tabs`] bar next to
//! it running to near the right edge; the footer is a dot-separated
//! `(key, label)` row where keys take the accent color. The `F1` help hint
//! lives in the footer (passed in by the caller), not the header.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};

use crate::tui::app::Status;
use crate::tui::{tab, tab::Tab, theme};

/// Render the brand + tab bar (band 1), the bordered middle band (band 2, whose
/// inner `Rect` is returned for the active panel to draw into), and the status
/// footer (band 3) — the **single** status surface. Band 3 shows the status
/// message when [`Status::message`] is `Some` (red on [`Status::is_error`],
/// else normal), preceded by a dim `"status: "` label; otherwise it shows the
/// hotkey hints (`footer` is a slice of `(key, label)` pairs joined by ` · `
/// with keys accented). Centralizing band 3 here is what removes the per-panel
/// status row that previously duplicated the hotkey hint.
pub fn draw_shell(
    frame: &mut Frame,
    area: Rect,
    active: Tab,
    footer: &[(&str, &str)],
    status: &Status,
) -> Rect {
    let [top, middle, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // ── Band 1: brand · tabs ────────────────────────────────────────────────
    let titles: Vec<Line> = tab::TAB_ORDER
        .iter()
        .map(|t| Line::from(t.label()))
        .collect();
    let tabs_index = active.idx();
    let brand_len: u16 = theme::BRAND.chars().count() as u16;
    let tabs_area = Rect {
        x: top.x + brand_len + 2,
        width: top.width.saturating_sub(brand_len + 2 + 1), // +1 right padding
        y: top.y,
        height: 1,
    };
    let tabs = Tabs::new(titles)
        .select(tabs_index)
        .divider(" ")
        .style(Style::new().dim())
        .highlight_style(theme::accent().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    frame.render_widget(tabs, tabs_area);
    // Brand on the left.
    frame.render_widget(
        Paragraph::new(Line::from(theme::brand_span())),
        Rect {
            x: top.x,
            width: brand_len,
            y: top.y,
            height: 1,
        },
    );

    // ── Band 2: bordered middle panel (caller draws inside `panel_area`) ────
    let panel_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().dim());
    let panel_area = panel_block.inner(middle);
    frame.render_widget(panel_block, middle);

    // ── Band 3: status message when present, else the hotkey hints ──────────
    // The footer is the single status surface: a set status message takes
    // precedence (red on error), otherwise the `(key, label)` hint pairs show.
    let line = if let Some(msg) = &status.message {
        let style = if status.is_error {
            Style::new().fg(theme::DANGER)
        } else {
            Style::new()
        };
        Line::from(vec![
            Span::styled("status: ", Style::new().dim()),
            Span::styled(msg.clone(), style),
        ])
    } else {
        let mut spans: Vec<Span> = Vec::new();
        for (i, (k, label)) in footer.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" · ", Style::new().dim()));
            }
            spans.push(Span::styled(
                *k,
                theme::accent().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
        }
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), bottom);

    panel_area
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn draw_shell_returns_inner_panel_area_and_never_panics() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        let status = Status::empty();
        for active in [Tab::Hosts, Tab::Credentials, Tab::Settings] {
            let mut got = Rect::default();
            term.draw(|f| {
                got = draw_shell(
                    f,
                    f.area(),
                    active,
                    &[("Enter", "connect"), ("^A", "add"), ("F1", "help")],
                    &status,
                );
            })
            .unwrap();
            // Inner area is the middle band inset by the 1-cell border on every
            // side: x shifts in by 1, y shifts in by 1 below the top band,
            // width loses 2, height is (screen - top - bottom - 2 borders).
            assert_eq!(got.x, 1);
            assert_eq!(got.y, 1 + 1);
            assert_eq!(got.width, 100 - 2);
            assert_eq!(got.height, (30 - 2) - 2);
        }
    }

    #[test]
    fn draw_shell_clamps_on_tiny_terminal() {
        let backend = TestBackend::new(20, 3);
        let mut term = Terminal::new(backend).unwrap();
        let status = Status::empty();
        term.draw(|f| {
            let _ = draw_shell(f, f.area(), Tab::Hosts, &[], &status);
        })
        .unwrap();
    }

    #[test]
    fn draw_shell_borders_middle_and_drops_f1_help() {
        let backend = TestBackend::new(60, 12);
        let mut term = Terminal::new(backend).unwrap();
        let status = Status::empty();
        let mut got = Rect::default();
        term.draw(|f| {
            got = draw_shell(
                f,
                f.area(),
                Tab::Hosts,
                &[("Enter", "connect"), ("F1", "help")],
                &status,
            );
        })
        .unwrap();
        // Inner rect is inset by the 1-cell border on every side of the middle
        // band. Middle band y = 1 (after the 1-row top band), so the inset
        // inner sits at y = 2; height = (12 - 2 top/bottom) - 2 borders.
        assert_eq!(got.x, 1);
        assert_eq!(got.y, 1 + 1);
        assert_eq!(got.width, 60 - 2);
        assert_eq!(got.height, 10 - 2);
        // F1 help text no longer appears in the top band (band 1, row 0). The
        // footer (band 3) legitimately may carry an `F1 help` hint, so scope the
        // check to the header row only.
        let buf = term.backend().buffer();
        let header: String = (0..buf.area.width)
            .map(|col| {
                buf.cell((col, 0u16))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_else(|| " ".to_string())
            })
            .collect();
        let header_trim: String = header.trim().to_string();
        assert!(
            !header_trim.contains("F1") && !header_trim.contains("help"),
            "F1 help should be removed from the header row, got header: {header_trim:?}"
        );
        // Specifically the top-right corner is not the `F`/`h` of "F1 help".
        let top_right = buf
            .cell((buf.area.width - 1, 0))
            .map(|c| c.symbol().to_string())
            .unwrap_or_default();
        assert!(
            top_right != "F" && top_right != "h",
            "top-right corner should not hold leftover F1-help text, got: {top_right:?}"
        );
    }

    /// The footer (band 3) is the single status surface: with an empty status it
    /// renders the hotkey hints; with a status message it renders that message
    /// (preceded by a dim `status: ` label) and the hints disappear. This is the
    /// contract that lets the panels drop their own status row without losing
    /// either feedback or hints.
    #[test]
    fn draw_shell_footer_shows_hints_when_empty_and_message_when_set() {
        let backend = TestBackend::new(80, 12);
        let mut term = Terminal::new(backend).unwrap();
        let hints = [("Enter", "connect"), ("F1", "help")];

        // Empty status → hints render in band 3 (the bottom row).
        let empty = Status::empty();
        term.draw(|f| {
            let _ = draw_shell(f, f.area(), Tab::Hosts, &hints, &empty);
        })
        .unwrap();
        let bottom_row: String = (0..term.backend().buffer().area.width)
            .map(|col| {
                term.backend()
                    .buffer()
                    .cell((col, term.backend().buffer().area.height - 1))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_else(|| " ".to_string())
            })
            .collect();
        let bottom_trim = bottom_row.trim().to_string();
        assert!(
            bottom_trim.contains("Enter") && bottom_trim.contains("connect"),
            "empty status should show the hotkey hints in band 3, got: {bottom_trim:?}"
        );
        assert!(
            !bottom_trim.contains("status:"),
            "empty status should not show a status label, got: {bottom_trim:?}"
        );

        // Set status → the message renders in band 3, and the hints are gone.
        let msg = Status::info("host saved");
        term.draw(|f| {
            let _ = draw_shell(f, f.area(), Tab::Hosts, &hints, &msg);
        })
        .unwrap();
        let bottom_row: String = (0..term.backend().buffer().area.width)
            .map(|col| {
                term.backend()
                    .buffer()
                    .cell((col, term.backend().buffer().area.height - 1))
                    .map(|c| c.symbol().to_string())
                    .unwrap_or_else(|| " ".to_string())
            })
            .collect();
        let bottom_trim = bottom_row.trim().to_string();
        assert!(
            bottom_trim.contains("status:") && bottom_trim.contains("host saved"),
            "set status should render the message in band 3, got: {bottom_trim:?}"
        );
        assert!(
            !bottom_trim.contains("connect"),
            "set status should suppress the hotkey hints, got: {bottom_trim:?}"
        );
    }
}
