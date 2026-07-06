//! The `^Q` queue-manager overlay: a modal list of every transfer task with
//! per-task progress/status. Lives inside [`crate::tui::transfer::screen::TransferScreen`]
//! (the transfer screen bypasses `App::overlay` — see `app.rs` Layer-0 — so it
//! owns its own overlay the way the wizards own their inner popups).
//!
//! Task 4 ships view + navigation (open `^Q`, close `Esc`, move `↑↓`/`jk`).
//! Task 5 adds the operations (retry / remove / cancel / pause).

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{Frame, layout::Rect, widgets::Paragraph};

use crate::tui::dialog;
use crate::tui::transfer::ledger::{TaskState, TransferLedger};
use crate::tui::transfer::render;

use super::screen::ScreenOutcome;

/// The selectable task rows in display order: in-flight first, then queued
/// (FIFO), then failed/cancelled (retryable). Completed (`Done(Ok)`) tasks are
/// folded into a single non-selectable "> N completed" row.
///
/// Returns indices into `ledger.tasks` (not ids) so the renderer can index
/// `ledger.tasks[ti]` directly after a single O(n) pass.
fn selectable(ledger: &TransferLedger) -> Vec<usize> {
    let mut idx = Vec::new();
    // In-flight first.
    for (i, t) in ledger.tasks.iter().enumerate() {
        if matches!(t.state, TaskState::InFlight) {
            idx.push(i);
        }
    }
    for (i, t) in ledger.tasks.iter().enumerate() {
        if matches!(t.state, TaskState::Queued) {
            idx.push(i);
        }
    }
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    for (i, t) in ledger.tasks.iter().enumerate() {
        if matches!(
            t.state,
            TaskState::Done(TransferOutcome::Failed(_))
                | TaskState::Done(TransferOutcome::Cancelled)
        ) {
            idx.push(i);
        }
    }
    idx
}

/// The modal. `selected` is an index into the [`selectable`] list; `closed` is
/// set by `Esc` so the screen drops the overlay.
#[derive(Debug, Clone, Default)]
pub struct QueueOverlay {
    selected: usize,
    pub closed: bool,
}

impl QueueOverlay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clamp the selection to the selectable range (call after the ledger
    /// mutates so a removed row can not leave the cursor out of bounds).
    /// Task 4 has no mutations, but every `on_key` calls this so Task 5's
    /// operation arms inherit a always-in-range cursor for free.
    fn clamp(&mut self, ledger: &TransferLedger) {
        let n = selectable(ledger).len();
        if n == 0 {
            self.selected = 0;
        } else if self.selected >= n {
            self.selected = n - 1;
        }
    }

    /// Modal key router. Returns a [`ScreenOutcome`] for the loop side-effects;
    /// `Continue` for pure view/nav. Task 4 takes the ledger by shared
    /// reference (no mutations yet); Task 5 widens it to `&mut` for the
    /// operation arms.
    pub fn on_key(&mut self, key: KeyEvent, ledger: &TransferLedger) -> ScreenOutcome {
        if key.kind != KeyEventKind::Press {
            return ScreenOutcome::Continue;
        }
        self.clamp(ledger);
        let n = selectable(ledger).len();
        match key.code {
            KeyCode::Esc => {
                self.closed = true;
                ScreenOutcome::Continue
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
                ScreenOutcome::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                ScreenOutcome::Continue
            }
            _ => ScreenOutcome::Continue,
        }
    }

    /// Render the overlay as a centered dialog. The selectable rows are
    /// windowed around `selected` so the cursor stays visible on long queues;
    /// a final `> N completed` row summarizes the folded `Done(Ok)` history.
    pub fn draw(&self, frame: &mut Frame, ledger: &TransferLedger) {
        let sel = selectable(ledger);
        let completed = ledger
            .tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.state,
                    TaskState::Done(sshrack_core::connect::sftp::proto::TransferOutcome::Ok)
                )
            })
            .count();
        // Body rows = selectable rows + (1 if any completed) — capped by the
        // dialog chrome (MAX_H minus border + blank + footer = 4).
        let body_rows = (sel.len() + usize::from(completed > 0))
            .min(usize::from(dialog::MAX_H).saturating_sub(4));
        let body_rows = body_rows.max(1) as u16;

        let header = format!(
            "transfer queue  ·  done {}/{} · fail {}{}",
            ledger.done_count(),
            ledger.total(),
            ledger.failed_count(),
            if ledger.is_paused() { " · paused" } else { "" }
        );
        let body = dialog::draw_dialog(
            frame,
            &header,
            body_rows,
            &[("↑↓", "select"), ("Esc", "close")],
        );

        // Window: keep `selected` in view within `body.height` rows over the
        // selectable list, then append the completed-count row.
        let max_rows = body.height as usize;
        let sel_len = sel.len();
        let half = max_rows.div_ceil(2).saturating_sub(1);
        let start = self
            .selected
            .saturating_sub(half)
            .min(sel_len.saturating_sub(1));
        let window: Vec<usize> = sel.iter().copied().skip(start).take(max_rows).collect();
        let mut rows: Vec<(usize, bool)> = window
            .into_iter()
            .enumerate()
            .map(|(i, ti)| (ti, start + i == self.selected))
            .collect();

        let mut y = body.y;
        let row_w = body.width;
        for (ti, is_sel) in rows.drain(..) {
            let line = render::queue_row(&ledger.tasks[ti], row_w, is_sel);
            let style = if is_sel {
                crate::tui::theme::accent()
            } else {
                ratatui::style::Style::new()
            };
            let area = Rect::new(body.x, y, body.width, 1);
            frame.render_widget(Paragraph::new(line).style(style), area);
            y += 1;
            if ((y - body.y) as u16) >= body.height {
                break;
            }
        }
        if completed > 0 && ((y - body.y) as u16) < body.height {
            let area = Rect::new(body.x, y, body.width, 1);
            frame.render_widget(
                Paragraph::new(format!("> {completed} completed"))
                    .style(ratatui::style::Style::new().dim()),
                area,
            );
        }
    }
}
