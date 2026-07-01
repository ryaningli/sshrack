//! The Settings panel. Today it exposes a single row — the password storage
//! mode — which opens the store-picker overlay on Enter.
//!
//! Pure view layer: [`SettingsPanel::on_key`] is a pure decision function (no
//! I/O — the event loop in [`super::app`] applies its [`Outcome`]), and
//! [`SettingsPanel::draw_in_shell`] renders into the shell's panel area.
//!
//! Unlike the Hosts/Credentials panels, Settings has **no search box**: there is
//! nothing to filter (one row today). `on_key` honors only `Up`/`Down` (no-ops
//! with a single row) and `Enter` (opens [`Overlay::StorePicker`]); every
//! printable char is ignored. The current-mode label comes from
//! [`App::current_store_mode_label`].
//!
//! [`App::current_store_mode_label`]: super::app::App::current_store_mode_label

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::app::{Outcome, Status};
use super::theme;

/// The Settings panel state. Today it holds a single row (the storage-mode
/// entry), so `selected` is always `0`; the field exists so future rows land
/// without reshaping the type.
#[derive(Debug, Clone)]
pub struct SettingsPanel {
    /// The selected row index. Always `0` while there is one row. Read by tests
    /// to pin the no-op Up/Down behavior; production callers do not yet read it
    /// because there is only one row.
    #[allow(dead_code)]
    pub selected: usize,
}

impl SettingsPanel {
    /// Construct a fresh panel with the first (only) row selected.
    pub fn new() -> Self {
        Self { selected: 0 }
    }

    /// Pure key decision: inspect `key`, return what the loop should do next.
    /// Performs **no I/O**.
    ///
    /// Bindings:
    /// - `Up` / `Down` — move the cursor. A no-op with one row today, but kept
    ///   so adding rows later needs no routing change.
    /// - `Enter` — open the store-mode picker overlay.
    /// - everything else (including printable chars) — [`Outcome::Continue`]:
    ///   Settings has no query.
    pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }
        match key.code {
            // With a single row Up/Down have nowhere to go; ignore gracefully.
            KeyCode::Up | KeyCode::Down => Outcome::Continue,
            KeyCode::Enter => Outcome::OpenOverlay(super::app::Overlay::StorePicker),
            _ => Outcome::Continue,
        }
    }

    /// Render the panel into the shell's panel area (no outer border — the
    /// shell supplies the brand/tab/footer bands around it). Splits `area` into
    /// `[row(2), spacer(Fill), status(1)]` and renders the single storage-mode
    /// row plus the status footer. There is no search row for Settings.
    ///
    /// `current_mode` is the human-readable label for the active store mode
    /// (`"keyring"` / `"vault"` / `"plaintext"` / `"undecided"`), used to tint
    /// the value red when no mode is chosen yet.
    pub fn draw_in_shell(
        &self,
        frame: &mut Frame,
        area: Rect,
        current_mode: &str,
        status: &Status,
    ) {
        // No search row for Settings: a 2-row band for the single entry, a fill
        // spacer, and a 1-row status footer.
        let [row_area, _, status_area] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Fill(1),
            Constraint::Length(1),
        ])
        .areas(area);

        let value_span = if current_mode == "undecided" {
            Span::styled(format!("{current_mode} ▸"), Style::new().fg(theme::DANGER))
        } else {
            Span::styled(
                format!("{current_mode} ▸"),
                theme::accent().add_modifier(Modifier::BOLD),
            )
        };
        let row = Line::from(vec![
            theme::selected_gutter(),
            Span::raw(" Storage mode"),
            Span::raw("    "),
            value_span,
        ]);
        frame.render_widget(Paragraph::new(row), row_area);

        let status_line = match &status.message {
            Some(msg) => Line::from(vec![
                Span::styled("status: ", Style::new().dim()),
                Span::styled(
                    msg.clone(),
                    if status.is_error {
                        Style::new().fg(theme::DANGER)
                    } else {
                        Style::new()
                    },
                ),
            ]),
            None => Line::from(Span::styled(
                "Enter to change a setting",
                Style::new().dim(),
            )),
        };
        frame.render_widget(Paragraph::new(status_line), status_area);
    }
}

impl Default for SettingsPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    //! Purity tests for `SettingsPanel::on_key`. The contract: `on_key` takes a
    //! key and returns an outcome with **no I/O**.

    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn enter_opens_store_picker_overlay() {
        let mut p = SettingsPanel::new();
        let out = p.on_key(key(KeyCode::Enter));
        assert!(matches!(
            out,
            Outcome::OpenOverlay(super::super::app::Overlay::StorePicker)
        ));
    }

    #[test]
    fn arrows_do_not_crash_single_row() {
        let mut p = SettingsPanel::new();
        p.on_key(key(KeyCode::Down));
        p.on_key(key(KeyCode::Up));
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn printable_chars_are_ignored() {
        // Settings has no query box; a printable char must not open anything.
        let mut p = SettingsPanel::new();
        for ch in ['s', '1', '?', ' '] {
            let out = p.on_key(key(KeyCode::Char(ch)));
            assert!(
                matches!(out, Outcome::Continue),
                "printable {ch:?} must be a no-op"
            );
        }
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn release_events_are_ignored() {
        let mut p = SettingsPanel::new();
        let release =
            KeyEvent::new_with_kind(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Release);
        let out = p.on_key(release);
        assert!(matches!(out, Outcome::Continue));
    }
}
