//! The quit-SFTP confirmation overlay. When the user asks to leave the
//! transfer screen while a transfer is in flight, [`TransferScreen`] opens
//! this modal so the exit does not silently discard the in-flight task (the
//! worker's `Drop` would kill it and `remove_partial_dst` would delete the
//! partial destination). Lives inside
//! [`crate::tui::transfer::screen::TransferScreen`] — the transfer screen
//! owns its own overlays the way [`super::queue_overlay::QueueOverlay`] does.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{Frame, widgets::Paragraph};
use sshrack_core::connect::sftp::proto::Direction;

use crate::tui::dialog;
use crate::tui::transfer::screen::ScreenOutcome;

/// The quit-SFTP confirmation modal. Snapshots the in-flight task's
/// direction + display name when it opens, so the message stays stable even
/// if the transfer finishes while the dialog is up. `closed` is set by the
/// cancel keys (`n` / `Esc`); the owning screen reads [`Self::closed`] to
/// drop the overlay without quitting. A confirm key returns
/// [`ScreenOutcome::CloseTransfer`] directly.
///
/// Reachability: the owning `TransferScreen` (Task 2 of the quit-confirm
/// plan) opens this overlay. Until that wiring lands, no `main` call site
/// reaches `draw` (or the `direction`/`name` fields it reads), so
/// `cargo clippy --all-targets` (which lints the non-test binary target
/// separately from the test target) flags it dead. The scoped
/// `#[allow(dead_code)]` annotations below are removed once Task 2 wires
/// the screen to construct + pump + draw this overlay.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct CloseConfirm {
    direction: Direction,
    name: String,
    closed: bool,
}

#[allow(dead_code)] // screen wiring lands in Task 2; see the struct note.
impl CloseConfirm {
    /// Snapshot the in-flight task's display info.
    pub(crate) fn new(direction: Direction, name: String) -> Self {
        Self {
            direction,
            name,
            closed: false,
        }
    }

    /// Handle a key. `Enter`/`y`/`Y` confirms the quit
    /// (→ [`ScreenOutcome::CloseTransfer`]); `n`/`N`/`Esc` cancels (sets
    /// `closed`, → [`ScreenOutcome::Continue`]); any other key — and any
    /// non-`Press` event — is swallowed (`Continue`).
    pub(crate) fn on_key(&mut self, key: KeyEvent) -> ScreenOutcome {
        if key.kind != KeyEventKind::Press {
            return ScreenOutcome::Continue;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                ScreenOutcome::CloseTransfer
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.closed = true;
                ScreenOutcome::Continue
            }
            _ => ScreenOutcome::Continue,
        }
    }

    /// Render the centered confirmation dialog above the transfer screen.
    /// Uses [`dialog::draw_dialog`] for the bordered box + hotkey footer; the
    /// body names the in-flight task so the user sees exactly what they would
    /// discard.
    pub(crate) fn draw(&self, frame: &mut Frame) {
        let (glyph, label) = direction_display(self.direction);
        let name = &self.name;
        let body = format!(
            "A transfer is in progress:\n  {glyph} {label}: {name}\n\
             Quitting cancels it and deletes the partial file.",
        );
        // 3 text rows. draw_dialog adds the border, a blank separator, and the
        // hotkey footer on top of this count.
        let body_area = dialog::draw_dialog(
            frame,
            "Quit SFTP?",
            3,
            &[("Enter/y", "quit"), ("n/Esc", "stay")],
        );
        frame.render_widget(Paragraph::new(body), body_area);
    }

    /// Whether the user cancelled (the owning screen drops the overlay).
    pub(crate) fn closed(&self) -> bool {
        self.closed
    }
}

/// Direction → (glyph, word) for the in-flight summary line.
#[allow(dead_code)] // only called from `draw`, whose screen wiring lands in Task 2.
fn direction_display(d: Direction) -> (&'static str, &'static str) {
    match d {
        Direction::Upload => ("↑", "upload"),
        Direction::Download => ("↓", "download"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn confirm_keys_quit() {
        for key in [KeyCode::Enter, KeyCode::Char('y'), KeyCode::Char('Y')] {
            let mut ov = CloseConfirm::new(Direction::Upload, "x.tar".into());
            assert_eq!(ov.on_key(press(key)), ScreenOutcome::CloseTransfer);
            assert!(!ov.closed(), "confirm does not set closed: {key:?}");
        }
    }

    #[test]
    fn cancel_keys_stay_and_mark_closed() {
        for key in [KeyCode::Esc, KeyCode::Char('n'), KeyCode::Char('N')] {
            let mut ov = CloseConfirm::new(Direction::Download, "y.bin".into());
            assert_eq!(ov.on_key(press(key)), ScreenOutcome::Continue);
            assert!(ov.closed(), "cancel must set closed: {key:?}");
        }
    }

    #[test]
    fn neutral_keys_are_swallowed() {
        for key in [
            KeyCode::Up,
            KeyCode::Char('a'),
            KeyCode::Char(' '),
            KeyCode::Tab,
            KeyCode::Backspace,
        ] {
            let mut ov = CloseConfirm::new(Direction::Upload, "z".into());
            assert_eq!(ov.on_key(press(key)), ScreenOutcome::Continue);
            assert!(!ov.closed(), "neutral key must not close: {key:?}");
        }
    }

    #[test]
    fn non_press_events_are_ignored() {
        let mut ov = CloseConfirm::new(Direction::Upload, "z".into());
        let release = KeyEvent::new_with_kind(
            KeyCode::Enter,
            KeyModifiers::NONE,
            crossterm::event::KeyEventKind::Release,
        );
        assert_eq!(ov.on_key(release), ScreenOutcome::Continue);
        assert!(!ov.closed());
    }
}
