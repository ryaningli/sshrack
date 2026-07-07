//! The `^Q` queue-manager overlay: a modal view over the transfer ledger,
//! split into three tabs cycled by `Tab` / `Shift-Tab`:
//! - **Active** — in-flight + queued tasks (the default; what you watch while
//!   transferring).
//! - **Failed** — `Done(Failed)` + `Done(Cancelled)` tasks, which are retryable.
//! - **Completed** — `Done(Ok)` tasks, read-only confirmation history.
//!
//! Each view keeps its own cursor, so a long completed history never floods
//! the active view, and every finished task stays inspectable on its tab. The
//! view is pure projection over [`TransferLedger`]; retry/remove/cancel/pause
//! semantics are unchanged (they route through the selected task of the
//! current view). Lives inside [`crate::tui::transfer::screen::TransferScreen`]
//! — the transfer screen owns its own overlay the way the wizards own their
//! inner popups.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{Frame, layout::Rect, widgets::Paragraph};

use crate::tui::dialog;
use crate::tui::theme;
use crate::tui::transfer::ledger::{TaskState, TransferLedger};
use crate::tui::transfer::render;

use super::screen::ScreenOutcome;

/// One slice of the ledger the overlay can show. `Tab` cycles forward through
/// [`Self::all`]; `Shift-Tab` backward. `#[repr(usize)]` so a `[usize; 3]`
/// cursor array can be indexed by `self.view as usize`.
#[repr(usize)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum QueueView {
    /// The default: in-flight + queued.
    #[default]
    Active = 0,
    /// `Done(Failed)` + `Done(Cancelled)` — retryable.
    Failed = 1,
    /// `Done(Ok)` — completed history.
    Completed = 2,
}

impl QueueView {
    /// Next view in `Tab` order: Active → Failed → Completed → Active.
    fn next(self) -> Self {
        match self {
            Self::Active => Self::Failed,
            Self::Failed => Self::Completed,
            Self::Completed => Self::Active,
        }
    }

    /// Previous view in `Shift-Tab` order (the inverse of [`Self::next`]).
    fn prev(self) -> Self {
        match self {
            Self::Active => Self::Completed,
            Self::Failed => Self::Active,
            Self::Completed => Self::Failed,
        }
    }
}

/// The ledger indices a `view` shows, in display order. Pure projection — does
/// not mutate the ledger.
///
/// - `Active`: `InFlight` first, then `Queued` (FIFO dispatch order).
/// - `Failed`: `Done(Failed)` then `Done(Cancelled)`, in insertion order.
/// - `Completed`: `Done(Ok)`, in insertion order.
fn task_indices_for(ledger: &TransferLedger, view: QueueView) -> Vec<usize> {
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let mut idx = Vec::new();
    match view {
        QueueView::Active => {
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
        }
        QueueView::Failed => {
            for (i, t) in ledger.tasks.iter().enumerate() {
                if matches!(t.state, TaskState::Done(TransferOutcome::Failed(_))) {
                    idx.push(i);
                }
            }
            for (i, t) in ledger.tasks.iter().enumerate() {
                if matches!(t.state, TaskState::Done(TransferOutcome::Cancelled)) {
                    idx.push(i);
                }
            }
        }
        QueueView::Completed => {
            for (i, t) in ledger.tasks.iter().enumerate() {
                if matches!(t.state, TaskState::Done(TransferOutcome::Ok)) {
                    idx.push(i);
                }
            }
        }
    }
    idx
}

/// The modal. `view` is the active tab; `cursors` holds one cursor per view so
/// leaving and returning lands where you left off. `closed` is set by `Esc`.
#[derive(Debug, Clone, Default)]
pub struct QueueOverlay {
    view: QueueView,
    cursors: [usize; 3],
    pub closed: bool,
}

impl QueueOverlay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The cursor index within the current view.
    fn current_cursor(&self) -> usize {
        self.cursors[self.view as usize]
    }

    /// Set the cursor within the current view.
    fn set_current_cursor(&mut self, v: usize) {
        self.cursors[self.view as usize] = v;
    }

    /// Clamp the current view's cursor to its list length (call after the
    /// ledger mutates so a removed row can not leave the cursor out of bounds).
    fn clamp(&mut self, ledger: &TransferLedger) {
        let n = task_indices_for(ledger, self.view).len();
        let c = self.current_cursor();
        let clamped = if n == 0 {
            0
        } else if c >= n {
            n - 1
        } else {
            c
        };
        self.set_current_cursor(clamped);
    }

    /// Resolve the selected row of the current view to its index into
    /// `ledger.tasks` (`None` when the view is empty). Operations route through
    /// this so a mutation + re-render can not mis-target a row that shifted.
    fn selected_task_index(&self, ledger: &TransferLedger) -> Option<usize> {
        task_indices_for(ledger, self.view)
            .get(self.current_cursor())
            .copied()
    }

    /// Modal key router. Returns a [`ScreenOutcome`] for the loop side-effects:
    /// `Enqueue` (retry / resume-after-pause) and `CancelActive` (cancel the
    /// in-flight task) drive the existing `route_transfer` mapping; `Continue`
    /// for pure view/nav and no-op operations.
    pub fn on_key(&mut self, key: KeyEvent, ledger: &mut TransferLedger) -> ScreenOutcome {
        if key.kind != KeyEventKind::Press {
            return ScreenOutcome::Continue;
        }
        self.clamp(ledger);
        let n = task_indices_for(ledger, self.view).len();
        match key.code {
            KeyCode::Esc => {
                self.closed = true;
                ScreenOutcome::Continue
            }
            // Cycle view tabs. Each view keeps its own cursor; clamp on entry
            // so a shrunken list can not leave the cursor out of bounds.
            KeyCode::Tab => {
                self.view = self.view.next();
                self.clamp(ledger);
                ScreenOutcome::Continue
            }
            KeyCode::BackTab => {
                self.view = self.view.prev();
                self.clamp(ledger);
                ScreenOutcome::Continue
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let c = self.current_cursor();
                if c > 0 {
                    self.set_current_cursor(c - 1);
                }
                ScreenOutcome::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let c = self.current_cursor();
                if c + 1 < n {
                    self.set_current_cursor(c + 1);
                }
                ScreenOutcome::Continue
            }
            // Retry the selected failed/cancelled task (re-queue in place).
            KeyCode::Enter | KeyCode::Char('r') => {
                if let Some(ti) = self.selected_task_index(ledger) {
                    let id = ledger.tasks[ti].id;
                    if ledger.retry(id) {
                        return ScreenOutcome::Enqueue;
                    }
                }
                ScreenOutcome::Continue
            }
            // Remove the selected task. An in-flight task is deferred to the
            // worker-cancel path: the loop kills the worker, and the ledger
            // task moves to Done(Cancelled) when the `Done` event arrives.
            KeyCode::Delete | KeyCode::Char('d') => {
                if let Some(ti) = self.selected_task_index(ledger) {
                    if matches!(ledger.tasks[ti].state, TaskState::InFlight) {
                        return ScreenOutcome::CancelActive;
                    }
                    let id = ledger.tasks[ti].id;
                    ledger.remove(id);
                    self.clamp(ledger);
                }
                ScreenOutcome::Continue
            }
            // Cancel: only meaningful on the in-flight task. On a queued/done
            // task it falls through to a plain remove.
            KeyCode::Char('c') => {
                if let Some(ti) = self.selected_task_index(ledger) {
                    if matches!(ledger.tasks[ti].state, TaskState::InFlight) {
                        return ScreenOutcome::CancelActive;
                    }
                    let id = ledger.tasks[ti].id;
                    ledger.remove(id);
                    self.clamp(ledger);
                }
                ScreenOutcome::Continue
            }
            // Toggle the queue-level pause. Resuming a paused queue that has
            // pending work and nothing in flight must restart dispatch, so
            // signal Enqueue.
            KeyCode::Char('p') => {
                ledger.toggle_paused();
                if !ledger.is_paused() && ledger.pending_count() > 0 && !ledger.has_inflight() {
                    ScreenOutcome::Enqueue
                } else {
                    ScreenOutcome::Continue
                }
            }
            _ => ScreenOutcome::Continue,
        }
    }

    /// Render the overlay as a centered dialog. The current view's rows are
    /// windowed around the cursor so it stays visible on long queues.
    ///
    /// (Task 3 adds the tab strip + empty-state placeholder here; for now the
    /// active view name is shown in the header so the state is observable.)
    pub fn draw(&self, frame: &mut Frame, ledger: &TransferLedger) {
        let sel = task_indices_for(ledger, self.view);
        let max_body = usize::from(dialog::MAX_H).saturating_sub(4);
        let body_rows = sel.len().max(1).min(max_body) as u16;

        let view_name = match self.view {
            QueueView::Active => "active",
            QueueView::Failed => "failed",
            QueueView::Completed => "completed",
        };
        let header = format!(
            "transfer queue  ·  {view_name}{}",
            if ledger.is_paused() { " · paused" } else { "" }
        );
        let body = dialog::draw_dialog(
            frame,
            &header,
            body_rows,
            &[
                ("↑↓", "select"),
                ("⏎", "retry"),
                ("Del", "remove"),
                ("c", "cancel"),
                ("p", "pause"),
                ("Esc", "close"),
            ],
        );

        let total = sel.len();
        let cursor = self.current_cursor().min(total.saturating_sub(1));
        let max_rows = body.height as usize;
        let half = max_rows.div_ceil(2).saturating_sub(1);
        let start = cursor.saturating_sub(half).min(total.saturating_sub(1));
        for (y, (i, ti)) in (body.y..).zip(sel.iter().enumerate().skip(start).take(max_rows)) {
            let is_sel = i == cursor;
            let line = render::queue_row(&ledger.tasks[*ti], body.width, is_sel);
            let style = if is_sel {
                theme::accent()
            } else {
                ratatui::style::Style::new()
            };
            let area = Rect::new(body.x, y, body.width, 1);
            frame.render_widget(Paragraph::new(line).style(style), area);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::transfer::ledger::TransferLedger;
    use sshrack_core::connect::sftp::proto::{Direction, TransferJob, TransferOutcome};

    fn job(name: &str) -> TransferJob {
        TransferJob {
            direction: Direction::Upload,
            src: format!("/s/{name}").into(),
            dst: format!("/d/{name}").into(),
            name: name.into(),
            size_total: Some(1),
            recursive: false,
        }
    }

    #[test]
    fn task_indices_active_is_inflight_then_queued() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a")); // idx 0
        l.enqueue(job("b")); // idx 1
        l.next_to_dispatch(); // a -> InFlight, b stays Queued
        assert_eq!(
            task_indices_for(&l, QueueView::Active),
            vec![0, 1],
            "Active = InFlight(a) then Queued(b)"
        );
    }

    #[test]
    fn task_indices_failed_is_failed_then_cancelled() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("x".into())); // a Failed (idx 0)
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Cancelled); // b Cancelled (idx 1)
        assert_eq!(task_indices_for(&l, QueueView::Failed), vec![0, 1]);
    }

    #[test]
    fn task_indices_completed_is_ok_only() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok); // a Done(Ok) (idx 0)
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("x".into())); // b Failed
        assert_eq!(task_indices_for(&l, QueueView::Completed), vec![0]);
    }

    #[test]
    fn task_indices_views_partition_every_task_once() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a")); // idx 0
        l.enqueue(job("b")); // idx 1
        l.enqueue(job("c")); // idx 2
        l.enqueue(job("d")); // idx 3
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok); // a Completed
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("e".into())); // b Failed
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Cancelled); // c Cancelled
        // d stays Queued (concurrency=1, never dispatched)
        let active = task_indices_for(&l, QueueView::Active);
        let failed = task_indices_for(&l, QueueView::Failed);
        let completed = task_indices_for(&l, QueueView::Completed);
        assert!(active.contains(&3), "queued d is in Active: {active:?}");
        assert_eq!(failed, vec![1, 2]);
        assert_eq!(completed, vec![0]);
        let mut all = active.clone();
        all.extend(failed.iter().copied());
        all.extend(completed.iter().copied());
        all.sort_unstable();
        assert_eq!(
            all,
            vec![0, 1, 2, 3],
            "views partition each task exactly once"
        );
    }

    #[test]
    fn view_next_cycles_active_failed_completed() {
        assert_eq!(QueueView::Active.next(), QueueView::Failed);
        assert_eq!(QueueView::Failed.next(), QueueView::Completed);
        assert_eq!(QueueView::Completed.next(), QueueView::Active);
    }

    #[test]
    fn view_prev_is_the_inverse_of_next() {
        assert_eq!(QueueView::Failed.prev(), QueueView::Active);
        assert_eq!(QueueView::Completed.prev(), QueueView::Failed);
        assert_eq!(QueueView::Active.prev(), QueueView::Completed);
    }

    #[test]
    fn each_view_keeps_its_own_cursor() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b")); // Active has 2 items
        let mut ov = QueueOverlay::new();
        ov.cursors[QueueView::Active as usize] = 1;
        // Switch away to Failed, then back to Active.
        ov.view = QueueView::Failed;
        ov.view = QueueView::Active;
        assert_eq!(
            ov.current_cursor(),
            1,
            "returning to Active restores the cursor we left at"
        );
    }

    #[test]
    fn clamp_pulls_an_out_of_bounds_cursor_into_the_current_view() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a")); // Active: 1 item
        let mut ov = QueueOverlay::new();
        ov.cursors[QueueView::Active as usize] = 9;
        ov.clamp(&l);
        assert_eq!(ov.current_cursor(), 0, "clamped to last index");
        // An empty view clamps to 0.
        ov.view = QueueView::Failed;
        ov.clamp(&l);
        assert_eq!(ov.current_cursor(), 0, "empty view -> cursor 0");
    }
}
