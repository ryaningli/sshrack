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
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::{Frame, widgets::Paragraph};

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

    /// All views in `Tab` order. Used to render the tab strip and to compute
    /// per-view counts.
    fn all() -> [Self; 3] {
        [Self::Active, Self::Failed, Self::Completed]
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

    /// Render the overlay: a tab strip across the top (per-view counts, the
    /// current view accented + underlined), then the current view's task rows
    /// windowed around the cursor. An empty view shows a `no tasks` row.
    pub fn draw(&self, frame: &mut Frame, ledger: &TransferLedger) {
        let sel = task_indices_for(ledger, self.view);
        // body = tab strip (1) + list (rest). Cap so the dialog fits MAX_H.
        let max_list = usize::from(dialog::MAX_H).saturating_sub(5); // border(2)+blank(1)+footer(1)+tab(1)
        let list_rows = sel.len().min(max_list).max(1);
        let body_rows = (1 + list_rows) as u16;

        let header = format!(
            "transfer queue{}",
            if ledger.is_paused() { " · paused" } else { "" }
        );
        let body = dialog::draw_dialog(
            frame,
            &header,
            body_rows,
            &[
                ("Tab", "view"),
                ("↑↓", "select"),
                ("⏎", "retry"),
                ("Del", "remove"),
                ("c", "cancel"),
                ("p", "pause"),
                ("Esc", "close"),
            ],
        );

        let [tab_area, list_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(body);

        // Tab strip with per-view counts.
        let tabs = QueueView::all().map(|v| (v, task_indices_for(ledger, v).len()));
        let tab_line = render::queue_tab_bar(self.view, &tabs, tab_area.width);
        frame.render_widget(Paragraph::new(tab_line), tab_area);

        // List body (or empty placeholder).
        let total = sel.len();
        if total == 0 {
            frame.render_widget(
                Paragraph::new("  no tasks").style(ratatui::style::Style::new().dim()),
                list_area,
            );
            return;
        }
        let cursor = self.current_cursor().min(total - 1);
        let win = crate::tui::fit::focus_window(total, cursor, list_area.height as usize);
        let mut y = list_area.y;
        for display_i in win {
            let ti = sel[display_i];
            let is_sel = display_i == cursor;
            let line = render::queue_row(&ledger.tasks[ti], list_area.width, is_sel);
            let style = if is_sel {
                theme::accent()
            } else {
                ratatui::style::Style::new()
            };
            let area = Rect::new(list_area.x, y, list_area.width, 1);
            frame.render_widget(Paragraph::new(line).style(style), area);
            y += 1;
            if y - list_area.y >= list_area.height {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::transfer::ledger::{TaskState, TransferLedger};
    use crossterm::event::KeyModifiers;
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

    // ---- on_key: direct drive across views and actions ----
    //
    // The preceding tests cover the pure helpers (`task_indices_for`, view
    // cycling, cursor, `clamp`). These feed real `KeyEvent`s into `on_key`
    // directly (not via `TransferScreen`) so the key→action routing is pinned
    // at the source, mirroring `screen_tests`'s overlay tests but without the
    // screen layer in between.

    /// A `KeyEvent::Press` with `code`, no modifiers (matches the overlay's
    /// Press-only gate and the documented keymap).
    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    #[test]
    fn on_key_tab_cycles_active_failed_completed_and_back() {
        let mut l = TransferLedger::new();
        let mut ov = QueueOverlay::new();
        assert_eq!(ov.view, QueueView::Active);
        let _ = ov.on_key(press(KeyCode::Tab), &mut l);
        assert_eq!(ov.view, QueueView::Failed);
        let _ = ov.on_key(press(KeyCode::Tab), &mut l);
        assert_eq!(ov.view, QueueView::Completed);
        let _ = ov.on_key(press(KeyCode::Tab), &mut l);
        assert_eq!(ov.view, QueueView::Active, "wraps back to Active");
    }

    #[test]
    fn on_key_backtab_cycles_backward() {
        let mut l = TransferLedger::new();
        let mut ov = QueueOverlay::new();
        let _ = ov.on_key(press(KeyCode::BackTab), &mut l);
        assert_eq!(
            ov.view,
            QueueView::Completed,
            "BackTab: Active -> Completed"
        );
        let _ = ov.on_key(press(KeyCode::BackTab), &mut l);
        assert_eq!(ov.view, QueueView::Failed);
        let _ = ov.on_key(press(KeyCode::BackTab), &mut l);
        assert_eq!(ov.view, QueueView::Active);
    }

    #[test]
    fn on_key_down_moves_cursor_and_clamps_at_end() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        l.enqueue(job("c"));
        let mut ov = QueueOverlay::new();
        assert_eq!(ov.current_cursor(), 0);
        let out = ov.on_key(press(KeyCode::Down), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(ov.current_cursor(), 1);
        let _ = ov.on_key(press(KeyCode::Down), &mut l);
        assert_eq!(ov.current_cursor(), 2);
        // Past the end: clamps (no overflow, stays at last index).
        let out = ov.on_key(press(KeyCode::Down), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(ov.current_cursor(), 2, "clamped at last index");
    }

    #[test]
    fn on_key_up_moves_cursor_and_clamps_at_zero() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        let mut ov = QueueOverlay::new();
        ov.set_current_cursor(1);
        let out = ov.on_key(press(KeyCode::Up), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(ov.current_cursor(), 0);
        // At 0: stays 0 (no underflow).
        let _ = ov.on_key(press(KeyCode::Up), &mut l);
        assert_eq!(ov.current_cursor(), 0, "clamped at 0");
    }

    #[test]
    fn on_key_j_and_k_mirror_down_and_up() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        let mut ov = QueueOverlay::new();
        // j moves down.
        let _ = ov.on_key(press(KeyCode::Char('j')), &mut l);
        assert_eq!(ov.current_cursor(), 1, "j moves down");
        // k moves up.
        let _ = ov.on_key(press(KeyCode::Char('k')), &mut l);
        assert_eq!(ov.current_cursor(), 0, "k moves up");
    }

    #[test]
    fn on_key_d_on_inflight_returns_cancel_active_and_keeps_task() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch(); // a -> InFlight
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Char('d')), &mut l);
        assert_eq!(out, ScreenOutcome::CancelActive);
        // The in-flight task is NOT removed by `d` (the worker-cancel path
        // owns the lifecycle; `remove` refuses InFlight).
        assert_eq!(l.total(), 1, "inflight task not removed by 'd'");
    }

    #[test]
    fn on_key_delete_on_inflight_also_returns_cancel_active() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch();
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Delete), &mut l);
        assert_eq!(out, ScreenOutcome::CancelActive);
    }

    #[test]
    fn on_key_d_on_queued_removes_from_ledger() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        let mut ov = QueueOverlay::new();
        let before = l.total();
        let out = ov.on_key(press(KeyCode::Char('d')), &mut l);
        assert_eq!(out, ScreenOutcome::Continue, "queued 'd' is a pure remove");
        assert_eq!(l.total(), before - 1, "queued task removed");
    }

    #[test]
    fn on_key_c_on_inflight_returns_cancel_active() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch();
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Char('c')), &mut l);
        assert_eq!(out, ScreenOutcome::CancelActive);
    }

    #[test]
    fn on_key_c_on_queued_falls_through_to_remove() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Char('c')), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(l.total(), 0, "queued task removed via 'c'");
    }

    #[test]
    fn on_key_enter_retries_failed_task_and_signals_enqueue() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("boom".into())); // a Done(Failed)
        let mut ov = QueueOverlay::new();
        // a is now in the Failed view; switch to it.
        let _ = ov.on_key(press(KeyCode::Tab), &mut l); // Active -> Failed
        let out = ov.on_key(press(KeyCode::Enter), &mut l);
        assert_eq!(out, ScreenOutcome::Enqueue, "retry signals advance");
        assert!(
            matches!(l.tasks[0].state, TaskState::Queued),
            "failed task re-queued"
        );
    }

    #[test]
    fn on_key_r_retries_cancelled_task() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Cancelled);
        let mut ov = QueueOverlay::new();
        let _ = ov.on_key(press(KeyCode::Tab), &mut l); // -> Failed
        let out = ov.on_key(press(KeyCode::Char('r')), &mut l);
        assert_eq!(out, ScreenOutcome::Enqueue);
        assert!(matches!(l.tasks[0].state, TaskState::Queued));
    }

    #[test]
    fn on_key_enter_on_empty_view_is_a_continue_noop() {
        let mut l = TransferLedger::new();
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Enter), &mut l);
        assert_eq!(out, ScreenOutcome::Continue, "nothing selected -> no-op");
    }

    #[test]
    fn on_key_p_pause_then_resume_with_pending_idle_signals_enqueue() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a")); // Queued: pending=1, no inflight
        let mut ov = QueueOverlay::new();
        // First 'p': pause. Now paused → Continue (not Enqueue).
        let out = ov.on_key(press(KeyCode::Char('p')), &mut l);
        assert_eq!(out, ScreenOutcome::Continue, "pausing -> Continue");
        assert!(l.is_paused());
        // Second 'p': resume. pending>0, no inflight → Enqueue.
        let out = ov.on_key(press(KeyCode::Char('p')), &mut l);
        assert_eq!(
            out,
            ScreenOutcome::Enqueue,
            "resume with pending+idle -> Enqueue"
        );
        assert!(!l.is_paused());
    }

    #[test]
    fn on_key_p_resume_with_inflight_does_not_signal_enqueue() {
        // When an inflight task is active, resuming must not signal Enqueue
        // (the loop is already busy; a second dispatch would double-start).
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.next_to_dispatch(); // a InFlight
        let mut ov = QueueOverlay::new();
        let _ = ov.on_key(press(KeyCode::Char('p')), &mut l); // pause
        assert!(l.is_paused());
        let out = ov.on_key(press(KeyCode::Char('p')), &mut l); // resume, but inflight
        assert_eq!(
            out,
            ScreenOutcome::Continue,
            "resume while inflight -> Continue (no double-dispatch)"
        );
    }

    #[test]
    fn on_key_p_resume_with_no_pending_is_continue() {
        let mut l = TransferLedger::new();
        l.set_paused(true);
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Char('p')), &mut l);
        assert_eq!(
            out,
            ScreenOutcome::Continue,
            "resume with no pending -> Continue"
        );
        assert!(!l.is_paused());
    }

    #[test]
    fn on_key_esc_sets_closed_and_returns_continue() {
        let mut l = TransferLedger::new();
        let mut ov = QueueOverlay::new();
        assert!(!ov.closed);
        let out = ov.on_key(press(KeyCode::Esc), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert!(ov.closed, "Esc marks the overlay closed");
    }

    #[test]
    fn on_key_non_press_event_is_ignored() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        let mut ov = QueueOverlay::new();
        let release =
            KeyEvent::new_with_kind(KeyCode::Tab, KeyModifiers::NONE, KeyEventKind::Release);
        let out = ov.on_key(release, &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(ov.view, QueueView::Active, "release did not cycle view");
    }

    #[test]
    fn on_key_neutral_key_is_continue_and_does_not_mutate() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        let mut ov = QueueOverlay::new();
        let out = ov.on_key(press(KeyCode::Char('x')), &mut l);
        assert_eq!(out, ScreenOutcome::Continue);
        assert_eq!(l.total(), 1, "neutral key does not remove anything");
        assert!(!ov.closed, "neutral key does not close");
    }

    #[test]
    fn on_key_tab_into_smaller_view_clamps_cursor() {
        // Cursor in Active (2 items) at index 1; switching to Failed (empty)
        // clamps the cursor to 0 so a later selection can not read OOB.
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        let mut ov = QueueOverlay::new();
        ov.set_current_cursor(1);
        let _ = ov.on_key(press(KeyCode::Tab), &mut l); // Active -> Failed (empty)
        assert_eq!(
            ov.current_cursor(),
            0,
            "Tab into an empty view clamps the cursor to 0"
        );
    }

    #[test]
    fn on_key_d_removes_cursor_stays_in_bounds() {
        // Remove the selected queued task; the cursor must clamp to the new
        // last index (not point past the end on the next keypress).
        let mut l = TransferLedger::new();
        l.enqueue(job("a"));
        l.enqueue(job("b"));
        let mut ov = QueueOverlay::new();
        ov.set_current_cursor(1); // on b
        let _ = ov.on_key(press(KeyCode::Char('d')), &mut l); // remove b
        assert_eq!(l.total(), 1);
        assert_eq!(
            ov.current_cursor(),
            0,
            "cursor clamped after removing the last row"
        );
    }
    // ---- draw: smoke (no panic) + snapshot ----

    /// A ledger seeded with one task per terminal state so the overlay has
    /// rows to render in every tab. Built one-at-a-time (dispatch → finish)
    /// so the ledger's concurrency=1 invariant holds — never two inflight.
    /// Final layout: Completed(1), Failed(2: one Failed + one Cancelled),
    /// Active(2: one InFlight + one Queued).
    fn canned_ledger() -> TransferLedger {
        let mut l = TransferLedger::new();
        // Completed tab.
        l.enqueue(job("done-ok"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok);
        // Failed tab: one Failed + one Cancelled.
        l.enqueue(job("failed-task"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("boom".into()));
        l.enqueue(job("cancelled-task"));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Cancelled);
        // Active tab: one InFlight + one Queued (the queued one waits since
        // concurrency=1 and the inflight slot is occupied).
        l.enqueue(job("inflight-task"));
        l.next_to_dispatch();
        l.enqueue(job("queued-task"));
        l
    }

    #[test]
    fn draw_active_view_renders_without_panic_80x24_and_narrow() {
        let l = canned_ledger();
        let ov = QueueOverlay::new(); // Active view
        // 80x24.
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        let res = term.draw(|f| ov.draw(f, &l));
        assert!(res.is_ok(), "80x24 draw returned error: {:?}", res.err());
        // Narrow 40x8 (dialog clamps down; must not panic or overflow).
        let backend = ratatui::backend::TestBackend::new(40, 8);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        let res = term.draw(|f| ov.draw(f, &l));
        assert!(res.is_ok(), "40x8 draw returned error: {:?}", res.err());
    }

    #[test]
    fn draw_failed_view_renders_without_panic() {
        let l = canned_ledger();
        let mut ov = QueueOverlay::new();
        ov.view = QueueView::Failed;
        let backend = ratatui::backend::TestBackend::new(40, 8);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        let res = term.draw(|f| ov.draw(f, &l));
        assert!(res.is_ok(), "Failed view 40x8 draw: {:?}", res.err());
    }

    #[test]
    fn draw_completed_view_renders_without_panic() {
        let l = canned_ledger();
        let mut ov = QueueOverlay::new();
        ov.view = QueueView::Completed;
        let backend = ratatui::backend::TestBackend::new(40, 8);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        let res = term.draw(|f| ov.draw(f, &l));
        assert!(res.is_ok(), "Completed view 40x8 draw: {:?}", res.err());
    }

    #[test]
    fn draw_empty_view_renders_the_no_tasks_placeholder_without_panic() {
        let l = TransferLedger::new(); // empty
        let ov = QueueOverlay::new();
        let backend = ratatui::backend::TestBackend::new(40, 8);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        let res = term.draw(|f| ov.draw(f, &l));
        assert!(res.is_ok(), "empty view draw: {:?}", res.err());
    }

    #[test]
    fn draw_active_view_snapshot_80x24() {
        // Snapshot the default (Active) view at 80x24 with a seeded ledger so
        // the tab strip, row layout, and focus styling stay stable. Hermetic:
        // TestBackend in memory, fixed names, no timestamps.
        let l = canned_ledger();
        let ov = QueueOverlay::new(); // Active view
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut term = ratatui::Terminal::new(backend).expect("test backend");
        term.draw(|f| ov.draw(f, &l)).expect("draw");
        insta::assert_snapshot!(term.backend());
    }
}
