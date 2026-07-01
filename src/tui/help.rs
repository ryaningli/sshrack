//! Full-screen help overlay (`F1`). Renders a static keybinding reference for
//! every TUI surface (launcher, host wizard, credential wizard, store view) and
//! dismisses on `F1` / `Esc` / `q` (handled in [`super::app::App::on_key`]).
//!
//! The text is static (no live state), so this module is pure render: it takes
//! a frame and an area and writes the reference. There is nothing to unit-test
//! beyond the constant existing, so the test module just pins the title.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

/// The title shown in the overlay's border. Centralized so the App-level F1
/// intercept and the render stay in sync. Exposed (`pub`) because the App
/// references it in a doc-link.
pub const HELP_TITLE: &str = " Help ";

/// The static keybinding reference, one section per surface. Newlines between
/// sections give visual breathing room; the trailing dismiss hint reminds the
/// user how to leave the overlay.
fn help_lines() -> Vec<Line<'static>> {
    let section = |heading: &'static str| {
        Line::from(vec![Span::styled(
            heading,
            Style::new().add_modifier(Modifier::BOLD),
        )])
    };
    let binding = |k: &'static str, desc: &'static str| {
        Line::from(vec![
            Span::styled(format!("  {k:<14}"), Style::new()),
            Span::raw(desc),
        ])
    };

    vec![
        section("Hosts tab"),
        binding("Enter", "connect to the selected host"),
        binding("Up / Down", "move selection (wraps)"),
        binding("Ctrl-N / Ctrl-P", "move selection (wraps)"),
        binding("type", "fuzzy-filter hosts by name"),
        binding("Backspace", "edit the query"),
        binding("Ctrl-A", "add a new host"),
        binding("Ctrl-E", "edit the selected host"),
        binding("Ctrl-D", "delete the selected host (confirm)"),
        binding("Esc", "clear query, or quit when query is empty"),
        binding("Ctrl-C", "quit"),
        Line::from(""),
        section("Tabs"),
        binding(
            "Tab / Shift-Tab",
            "cycle tabs (Hosts / Credentials / Settings)",
        ),
        binding("Ctrl-1 / 2 / 3", "jump to a tab"),
        Line::from(""),
        section("Host & credential wizards"),
        binding("Tab", "next field"),
        binding("Shift-Tab", "previous field"),
        binding("Up / Down", "cycle a chooser field's options"),
        binding("Enter", "cycle a chooser field's options"),
        binding("type", "edit the focused text field"),
        binding("Backspace", "edit the focused text field"),
        binding("Ctrl-S", "save (validates first)"),
        binding("Esc / Ctrl-C", "cancel, return to the tab"),
        Line::from(""),
        section("Everywhere"),
        binding("F1", "open / close this help overlay"),
        binding("Esc / q", "(in help) dismiss the overlay"),
        Line::from(""),
        Line::from(Span::styled(
            "Press F1, Esc, or q to close this overlay.",
            Style::new(),
        )),
    ]
}

/// Render the help overlay: a bordered block titled [`HELP_TITLE`] filling
/// `area`, with the keybinding reference left-aligned inside. Pure render — no
/// I/O, no key handling.
pub fn draw_help(frame: &mut Frame, area: ratatui::layout::Rect) {
    let block = Block::new().borders(Borders::ALL).title(HELP_TITLE);
    frame.render_widget(&block, area);
    let [inner] = Layout::vertical([Constraint::Fill(1)]).areas(block.inner(area));
    let body = Paragraph::new(help_lines()).alignment(Alignment::Left);
    frame.render_widget(body, inner);
}

#[cfg(test)]
mod tests {
    //! The overlay is pure render; only the title constant is worth pinning so
    //! the F1 intercept and the border title cannot drift apart.

    use super::*;

    #[test]
    fn help_title_is_nonempty_and_trimmed() {
        assert!(!HELP_TITLE.is_empty());
        // It is framed with spaces for the border title; assert both edges.
        assert!(HELP_TITLE.starts_with(' '));
        assert!(HELP_TITLE.ends_with(' '));
    }

    #[test]
    fn help_lines_cover_every_surface_and_dismiss_hint() {
        let lines = help_lines();
        let joined: String = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // Each surface has at least one binding documented.
        assert!(joined.contains("connect to the selected host"), "hosts tab");
        assert!(joined.contains("save (validates first)"), "wizards");
        assert!(joined.contains("cycle tabs"), "tabs section");
        assert!(
            joined.contains("open / close this help overlay"),
            "F1 entry"
        );
        assert!(joined.contains("dismiss the overlay"), "dismiss hint");
    }
}
