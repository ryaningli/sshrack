//! Help overlay (`F1`): a centered dialog with the static keybinding reference
//! for the three-band shell + tabs + overlays. Dismisses on `F1` / `Esc` / `q`
//! (handled in [`super::app::App::route_overlay`]).
//!
//! The text is static (no live state), so this module is pure render: it takes
//! a frame and writes the reference inside the dialog body that
//! [`draw_dialog`](super::dialog::draw_dialog) returns. The only logic worth
//! unit-testing is that `help_lines()` documents every surface and drops the
//! removed bindings (`c` / `Shift-C` / `F2` / `?`).

use ratatui::{
    Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::dialog::draw_dialog;

/// The static keybinding reference, grouped by surface. Bare letters and digits
/// never appear as bindings here: they reach the active panel's search box, so
/// the keymap deliberately has no single-char hotkeys (the conflict fix). Newlines
/// between sections give visual breathing room.
///
/// `on_key` uses the line count as the theoretical maximum scroll offset (the
/// largest value [`max_scroll`] can return across all body sizes) so the tail is
/// reachable even on short terminals; the renderer then re-clamps to the real
/// body height each frame.
pub fn help_lines() -> Vec<Line<'static>> {
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
        section("Tabs"),
        binding(
            "Tab / Shift-Tab",
            "cycle tabs (Hosts / Credentials / Settings)",
        ),
        binding("type", "filter the active panel's search box"),
        binding("Up / Down", "move selection (wraps)"),
        binding("Ctrl-N / Ctrl-P", "move selection (wraps)"),
        Line::from(""),
        section("Hosts panel"),
        binding("Enter", "connect to the selected host"),
        binding("Ctrl-A", "add (current tab)"),
        binding("Ctrl-E", "edit the selected host"),
        binding("Ctrl-D", "delete the selected host (confirm)"),
        Line::from(""),
        section("Credentials panel"),
        binding("Enter", "edit the selected credential"),
        binding("Ctrl-A", "add (current tab)"),
        binding("Ctrl-E", "edit the selected credential"),
        binding("Ctrl-D", "delete the selected credential (confirm)"),
        Line::from(""),
        section("Settings panel"),
        binding("Enter", "edit the storage-mode row"),
        Line::from(""),
        section("Overlays (wizards / store-picker)"),
        binding("Tab / Shift-Tab", "next / previous field"),
        binding("Up / Down", "cycle a chooser field's options"),
        binding("Ctrl-S", "save (validates first)"),
        binding("Esc / Ctrl-C", "cancel, return to the tab"),
        Line::from(""),
        section("Everywhere"),
        binding("F1", "open / close this help overlay"),
        binding("Esc", "clear query / close overlay / quit"),
        binding("Ctrl-C", "quit"),
    ]
}

/// Max scroll offset that still shows the last help line, given the body
/// height the dialog actually got. Returns 0 when the body fits every line;
/// otherwise the number of lines hidden past the bottom. Pure: consumed by
/// [`App::on_key`][super::app::App::on_key] to clamp `help_scroll`, and by
/// [`draw_help_dialog`] to clamp the render-side scroll.
pub fn max_scroll(body_height: u16) -> u16 {
    let lines = help_lines().len() as u16;
    lines.saturating_sub(body_height)
}

/// Render the help overlay as a centered dialog: a titled bordered area with a
/// `↑↓ · scroll` + `F1/Esc · close` hotkey footer, and the keymap reference
/// left-aligned in the body. The body is scrolled by `scroll` rows (clamped to
/// [`max_scroll`] of the rendered body height so it never scrolls past the last
/// line). Pure render — no I/O, no key handling.
pub fn draw_help_dialog(frame: &mut Frame, scroll: u16) {
    let body = draw_dialog(
        frame,
        " help ",
        help_lines().len() as u16,
        &[("↑↓", "scroll"), ("F1/Esc", "close")],
    );
    let lines = help_lines();
    let clamped = scroll.min(max_scroll(body.height));
    frame.render_widget(Paragraph::new(lines).scroll((clamped, 0)), body);
}

#[cfg(test)]
mod tests {
    //! The overlay is pure render; the only logic worth pinning is that
    //! `help_lines()` documents every surface, keeps the dismiss hint, drops
    //! the removed bindings (`c` / `Shift-C` / `F2` / `?`), and that
    //! `max_scroll` + `draw_help_dialog` clamp scroll without panicking.

    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn help_lines_cover_every_surface_and_dismiss_hint() {
        let lines = help_lines();
        let joined: String = lines
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        // Every surface has at least one binding documented.
        assert!(joined.contains("cycle tabs"), "tabs section");
        assert!(
            joined.contains("connect to the selected host"),
            "hosts panel"
        );
        assert!(
            joined.contains("edit the selected credential"),
            "credentials panel"
        );
        assert!(
            joined.contains("edit the storage-mode row"),
            "settings panel"
        );
        assert!(joined.contains("save (validates first)"), "wizards");
        assert!(
            joined.contains("open / close this help overlay"),
            "F1 entry"
        );
        // The new keymap is tab/add/edit/delete driven — these removed bindings
        // must NOT be documented (they now reach the query or are gone entirely).
        assert!(!joined.contains("switch storage mode"), "F2 is gone");
        assert!(
            !joined.contains("add credential") && !joined.contains("Shift-C"),
            "c / Shift-C are gone"
        );
        assert!(
            !joined.contains("(in help) dismiss the overlay"),
            "old q-only dismiss hint reworded"
        );
    }

    #[test]
    fn help_lines_keep_bare_chars_out_of_bindings() {
        // Conflict-fix invariant: no single-char hotkeys. The keymap must not
        // document a bare `c`, `?`, `F2`, or `Shift-C` as a binding.
        let joined: String = help_lines()
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!joined.contains("Shift-C"), "Shift-C removed");
        assert!(!joined.contains("F2"), "F2 removed");
        // Bare `c` and `?` only ever appear as part of "Ctrl-C" / punctuation,
        // never as standalone bindings — assert the old `c` add-credential entry
        // is gone.
        assert!(
            !joined.contains("\n  c             "),
            "bare c add-credential binding removed"
        );
    }

    #[test]
    fn max_scroll_is_zero_when_body_fits_all_lines() {
        // 31 help lines fit in a 40-row body → no scroll needed.
        assert_eq!(max_scroll(40), 0);
    }

    #[test]
    fn max_scroll_is_excess_lines_when_body_too_short() {
        // 31 lines in a 21-row body → 10 lines hidden, scroll 10 to reveal the
        // last one.
        assert_eq!(max_scroll(21), 10);
    }

    #[test]
    fn max_scroll_is_zero_when_body_exceeds_line_count() {
        // Body taller than the line list → still 0 (never scroll past the end).
        assert_eq!(max_scroll(100), 0);
    }

    #[test]
    fn draw_help_dialog_renders_without_panic_and_clamps_scroll() {
        // Render at a typical terminal size. A `scroll` value larger than the
        // body's max (10 for a 21-row body) must be silently clamped by
        // `draw_help_dialog` — no panic, no overflow.
        let backend = TestBackend::new(100, 40);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            draw_help_dialog(f, 999);
        })
        .unwrap();
    }

    #[test]
    fn draw_help_dialog_renders_without_panic_on_short_screen() {
        // A short terminal shrinks the dialog body, which changes max_scroll.
        // The renderer must still not panic for any scroll value.
        let backend = TestBackend::new(80, 12);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            draw_help_dialog(f, 0);
            draw_help_dialog(f, 50);
        })
        .unwrap();
    }
}
