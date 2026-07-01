//! The persistent three-band shell: brand + tab bar on top, the active panel's
//! area in the middle (returned to the caller), and a contextual hotkey footer
//! on the bottom. Pure render — no I/O.
//!
//! The shell is the only fixed chrome on screen; the active panel fills the
//! `Rect` this function returns. Brand on the left, the [`Tabs`] bar next to
//! it, `F1 help` flush right on the same row; the footer is a dot-separated
//! `(key, label)` row where keys take the accent color.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Tabs},
};

use crate::tui::{tab, tab::Tab, theme};

/// Render the brand + tab bar (band 1) and the hotkey footer (band 3), and
/// return the band-2 `Rect` for the active panel to draw into. `footer` is a
/// slice of `(key, label)` pairs joined by ` · ` with keys accented.
///
/// `#[allow(dead_code)]`: the keystone App rewrite (Task 9) is the first
/// production caller; unit tests already exercise this path. Same pre-wired
/// convention as `theme.rs` / `tab.rs`.
#[allow(dead_code)]
pub fn draw_shell(frame: &mut Frame, area: Rect, active: Tab, footer: &[(&str, &str)]) -> Rect {
    let [top, middle, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // ── Band 1: brand · tabs · F1 help ──────────────────────────────────────
    let titles: Vec<Line> = tab::TAB_ORDER
        .iter()
        .map(|t| Line::from(t.label()))
        .collect();
    let tabs_index = active.idx();
    let brand_len: u16 = 7; // "sshrack"
    let help_text = "F1 help";
    let tabs_area = Rect {
        x: top.x + brand_len + 2,
        width: top
            .width
            .saturating_sub((brand_len + 2) + help_text.len() as u16 + 2),
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
    // Help on the right.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(help_text, Style::new().dim())))
            .alignment(Alignment::Right),
        Rect {
            x: top.x,
            width: top.width,
            y: top.y,
            height: 1,
        },
    );

    // ── Band 3: contextual footer ───────────────────────────────────────────
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
    frame.render_widget(Paragraph::new(Line::from(spans)), bottom);

    middle
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn draw_shell_returns_inner_panel_area_and_never_panics() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        for active in [Tab::Hosts, Tab::Credentials, Tab::Settings] {
            let mut got = Rect::default();
            term.draw(|f| {
                got = draw_shell(
                    f,
                    f.area(),
                    active,
                    &[("Enter", "connect"), ("^A", "add"), ("F1", "help")],
                );
            })
            .unwrap();
            // Inner area is the screen minus the top band (1) and bottom band (1).
            assert_eq!(got.x, 0);
            assert_eq!(got.width, 100);
            assert_eq!(got.height, 30 - 2);
        }
    }

    #[test]
    fn draw_shell_clamps_on_tiny_terminal() {
        let backend = TestBackend::new(20, 3);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let _ = draw_shell(f, f.area(), Tab::Hosts, &[]);
        })
        .unwrap();
    }
}
