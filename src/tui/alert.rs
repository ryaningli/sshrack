//! Modal error alert overlay chrome. Reuses [`super::dialog`]'s titled bordered
//! area + footer; the body is the error message wrapped to the dialog width.

use ratatui::{
    Frame,
    layout::Alignment,
    widgets::{Paragraph, Wrap},
};

use crate::tui::dialog::draw_dialog;

/// Draw a modal alert: a titled bordered dialog whose body is `body` (wrapped)
/// and whose footer advertises `Esc` / `Ctrl-C` to close. The caller has
/// already chosen `Overlay::Alert { title, body }`; this only renders it.
pub fn draw_alert(frame: &mut Frame, title: &str, body: &str) {
    // Size the dialog to the wrapped content so a short error yields a small
    // box and a long one (e.g. captured ssh stderr) grows up to MAX_H.
    let max_chars = 76usize;
    let body_rows: u16 = body
        .split('\n')
        .map(|line| line.chars().count().div_ceil(max_chars).max(1) as u16)
        .sum::<u16>()
        .max(1);
    let body_area = draw_dialog(
        frame,
        title,
        body_rows,
        &[("Esc", "close"), ("^C", "close")],
    );
    frame.render_widget(
        Paragraph::new(body.to_string())
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left),
        body_area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn draw_alert_renders_without_panic_short_body() {
        // A short error message yields a small dialog; must not panic on a
        // normal terminal.
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| {
            draw_alert(
                f,
                " SFTP connection failed ",
                "host 'web1' has no password configured",
            )
        })
        .expect("draw");
    }

    #[test]
    fn draw_alert_renders_without_panic_long_body() {
        // A long captured-stderr body wraps and grows the dialog up to MAX_H;
        // must not panic or overflow.
        let long = "Permission denied (publickey,password).\n".repeat(40);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| draw_alert(f, " SFTP connection failed ", &long))
            .expect("draw");
    }

    #[test]
    fn draw_alert_renders_without_panic_tiny_terminal() {
        // A too-small screen still must not panic (dialog_area clamps).
        let backend = TestBackend::new(10, 5);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| draw_alert(f, " err ", "x")).expect("draw");
    }
}
