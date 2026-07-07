# Queue Overlay View-Tabs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the `^Q` queue-manager overlay into three view-tabs — **Active** (in-flight + queued), **Failed** (failed + cancelled, retryable), **Completed** (done-ok) — cycled by `Tab`/`Shift-Tab`, each with its own cursor, so a long completed history never floods the active view and every finished task stays inspectable.

**Architecture:** A new `QueueView` enum + a pure `task_indices_for(ledger, view)` partition replace the old single `selectable()` list (which folded `Done(Ok)` into a non-inspectable `> N completed` counter row). `QueueOverlay` gains a per-view cursor array. Rendering adds a tab strip with per-view counts (current view accented + underlined), an empty-view placeholder, and `focus_window`-based list scrolling. Long filenames are truncated via the existing `fit::truncate_cells`, with a new `fit::cells()` helper to budget the name against the row width. All view logic is pure projection over the unchanged `TransferLedger`; retry/remove/cancel/pause semantics are untouched.

**Tech Stack:** Rust 2024 (MSRV 1.86), ratatui 0.30, crossterm 0.28, unicode-width (already a dep via `fit.rs`).

## Global Constraints

- **English only** — all source, comments, doc comments, errors, commit messages.
- **Zero `unsafe`** (including tests). **Zero `unwrap()`/`expect()`** in production; tests may `.unwrap()`.
- **clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit. **Format** — `cargo fmt` green before every commit.
- **TDD for pure logic** — RED → GREEN → REFACTOR for the pure view-partition / truncation / tab-bar functions.
- **No bare-char hotkeys** — `Tab`/`Shift-Tab` are control keys (`KeyCode::Tab`/`KeyCode::BackTab`), allowed. Do not introduce bare printable-char hotkeys in the overlay.
- **No compat / dead code** — the old `selectable()` function and the `> N completed` folded-row logic are deleted, not kept behind a flag. Every new item is consumed by the end of the task that introduces it (no leftover `#[allow(dead_code)]`).
- **Tests hermetic** — `cargo test --workspace` must pass with `SSHRACK_PASSPHRASE` already set in the real shell; do not use `env -u`.
- **Conventional Commits** — `<type>(<scope>): <desc>`, no `Co-Authored-By` trailer. Use `git add <explicit paths>` (never `git add -A`).

---

## File Structure

| File | Responsibility | Touched by |
|---|---|---|
| `src/tui/transfer/queue_overlay.rs` | The `QueueOverlay` modal: `QueueView` enum, `task_indices_for` pure partition, per-view cursor state, key router (`Tab`/`Shift-Tab`/nav/ops), `draw` (tab strip + list + empty state). | T1, T3, T4 |
| `src/tui/transfer/render.rs` | Pure renderers: `queue_row` (with name truncation), `queue_tab_bar` (new — tab strip). | T2, T3 |
| `src/tui/fit.rs` | Pure geometry helpers: add `cells()` (display width); reuse `truncate_cells`, `truncate_cells_head`, `focus_window`. | T2 |
| `src/tui/transfer/screen_tests.rs` | Behavior-level overlay tests (open `^Q`, `Tab`, assert via `TestBackend` buffer). | T1, T3 |
| `docs/sftp.md` | Key reference for the queue overlay. | T4 |

**No changes** to `ledger.rs` (the partition is projection-only — counts come from `task_indices_for`), `screen.rs` (the modal routing at `screen.rs:199` already gives the overlay every key), or any core crate.

---

## Interfaces (cross-task contract)

These exact signatures are produced by their defining task and consumed by later tasks. An implementer sees only their own task; this block is the shared vocabulary.

- `pub(crate) enum QueueView { Active, Failed, Completed }` (T1) — `#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]` with `#[default]` on `Active`; `#[repr(usize)]` with `Active = 0, Failed = 1, Completed = 2` (so `cursors[self.view as usize]` indexes). Methods `fn next(self) -> Self`, `fn prev(self) -> Self` (T1, consumed by `on_key`). `fn all() -> [Self; 3]` (Tab order: Active, Failed, Completed) is added in **T3**, where `draw` is its first non-test consumer — it is NOT defined in T1 because T1 has no non-`#[cfg(test)]` caller and `cargo clippy --all-targets` would flag it dead on the non-test binary target.
- `fn task_indices_for(ledger: &TransferLedger, view: QueueView) -> Vec<usize>` (T1) — private to `queue_overlay.rs`. Returns `ledger.tasks` indices for the view, in display order.
- `pub fn cells(s: &str) -> usize` (T2, in `fit.rs`) — display width via `unicode-width`.
- `pub fn queue_tab_bar(current: QueueView, tabs: &[(QueueView, usize); 3], width: u16) -> Line<'static>` (T3, in `render.rs`) — renders the tab strip; counts are passed in (the overlay computes them via `task_indices_for`), so `render` does not import `ledger` counting.

---

## Task 1: View partition + per-view cursor + Tab/Shift-Tab navigation

**Files:**
- Modify: `src/tui/transfer/queue_overlay.rs` (whole file — replace `selectable`, the `QueueOverlay` struct/impl, `on_key`, `draw`)
- Test: `src/tui/transfer/queue_overlay.rs` (new `#[cfg(test)] mod tests`) and `src/tui/transfer/screen_tests.rs` (append behavior tests)

**Interfaces:**
- Produces: `QueueView` enum + `task_indices_for` (see Interfaces block).
- Consumes: nothing from later tasks.

This task ends with a compilable overlay where `Tab`/`Shift-Tab` cycle three views, each view keeps its own cursor, retry/remove/cancel/pause still work (they already route through `selected_task_index`, which now reads the current view), and the `> N completed` folded row is gone. The tab strip and empty-state placeholder land in Task 3; for now the current view name is shown in the dialog header so the state is observable.

- [ ] **Step 1: Add the failing pure-logic tests**

Append this module to the **end** of `src/tui/transfer/queue_overlay.rs` (the file currently has no `#[cfg(test)]` module):

```rust
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
        assert_eq!(all, vec![0, 1, 2, 3], "views partition each task exactly once");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib queue_overlay:: 2>&1 | tail -20`
Expected: FAIL — `cannot find type QueueView`, `cannot find function task_indices_for`, etc. (the types do not exist yet).

- [ ] **Step 3: Replace the overlay implementation**

Replace the **entire body of `src/tui/transfer/queue_overlay.rs`** (from the first `use` line through the end of the existing `impl QueueOverlay { ... }` block — i.e. everything **except** the new `#[cfg(test)] mod tests` you just appended) with:

```rust
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
        let clamped = if n == 0 { 0 } else if c >= n { n - 1 } else { c };
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
        let mut y = body.y;
        for (i, ti) in sel.iter().enumerate().skip(start).take(max_rows) {
            let is_sel = i == cursor;
            let line = render::queue_row(&ledger.tasks[*ti], body.width, is_sel);
            let style = if is_sel {
                theme::accent()
            } else {
                ratatui::style::Style::new()
            };
            let area = Rect::new(body.x, y, body.width, 1);
            frame.render_widget(Paragraph::new(line).style(style), area);
            y += 1;
        }
    }
}
```

- [ ] **Step 4: Run the pure-logic tests to verify they pass**

Run: `cargo test --lib queue_overlay::tests 2>&1 | tail -20`
Expected: PASS — all 8 new tests green.

- [ ] **Step 5: Add behavior tests for Tab / Shift-Tab routing**

Append to `src/tui/transfer/screen_tests.rs` (after the existing `overlay_resume_with_pending_and_idle_signals_advance` test at the end of the overlay section):

```rust
// ---- ^Q queue-manager overlay: view tabs (Tab / Shift-Tab) ----

#[test]
fn tab_switches_to_failed_view_and_lists_the_failed_task() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/queued-one"),
        dst: local_cwd.join("queued-one"),
        name: "queued-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/failed-one"),
        dst: local_cwd.join("failed-one"),
        name: "failed-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen
        .ledger
        .finish_inflight(TransferOutcome::Failed("boom".into())); // failed-one now in Failed view
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty())); // -> Failed
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "draw must not panic: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("failed-one"),
        "Failed view lists the failed task: {view}"
    );
    assert!(
        !view.contains("queued-one"),
        "queued task is not in the Failed view: {view}"
    );
}

#[test]
fn shift_tab_cycles_back_to_completed_view() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/done-one"),
        dst: local_cwd.join("done-one"),
        name: "done-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.finish_inflight(TransferOutcome::Ok); // done-one in Completed view
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty())); // Active -> Completed (prev)
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("done-one"),
        "Shift-Tab from Active lands on Completed: {view}"
    );
}
```

- [ ] **Step 6: Run the full workspace test suite + clippy + fmt**

Run:
```bash
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15
cargo fmt
```
Expected: all tests pass (existing overlay tests still green — they use `Enter`/`Delete`/`c`/`p` which now operate on the current Active view, unchanged behavior); clippy green; fmt clean.

- [ ] **Step 7: Commit**

```bash
git add src/tui/transfer/queue_overlay.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(tui): split queue overlay into active/failed/completed views"
```

---

## Task 2: Truncate long filenames in queue rows

**Files:**
- Modify: `src/tui/fit.rs` (add `cells`)
- Modify: `src/tui/transfer/render.rs` (rewrite `queue_row` to budget + truncate the name; update the `fit` import)
- Test: `src/tui/fit.rs` (`cells` tests) and `src/tui/transfer/render.rs` (`queue_row` truncation tests in `queue_row_tests`)

**Interfaces:**
- Produces: `pub fn cells(s: &str) -> usize` (see Interfaces block).
- Consumes: nothing.

Today `queue_row` (`render.rs:413`) pushes `task.job.name` verbatim and only right-aligns the label via a `fill` computed with `chars().count()` (not display width). A long name drives `fill` to 0, so the label collides with / overflows past the name. This task truncates the name to a width-derived budget and fixes the budget math to use display cells.

- [ ] **Step 1: Add the failing `cells` tests**

In `src/tui/fit.rs`, inside the existing `#[cfg(test)] mod tests` (after the `truncate_cells_head` tests, before the closing `}`), add:

```rust
    // ---- cells ----

    #[test]
    fn cells_counts_one_per_ascii_char() {
        assert_eq!(cells("abc"), 3);
        assert_eq!(cells(""), 0);
    }

    #[test]
    fn cells_counts_wide_chars_as_two() {
        assert_eq!(cells("中文"), 4);
        assert_eq!(cells("a中"), 3);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib fit::tests::cells 2>&1 | tail -15`
Expected: FAIL — `cannot find function cells`.

- [ ] **Step 3: Implement `cells`**

In `src/tui/fit.rs`, add immediately **above** the existing `truncate_cells_head` function (i.e. after `focus_window` and its doc, before `truncate_cells_head`):

```rust
/// Display width of `s` in terminal cells, following Unicode East Asian Width
/// (via the `unicode-width` crate). Pure. Use to budget text against a
/// `Rect::width` before passing it to [`truncate_cells`] / [`truncate_cells_head`].
pub fn cells(s: &str) -> usize {
    s.width()
}
```

(`use unicode_width::UnicodeWidthStr;` is already at `fit.rs:6`, so `s.width()` resolves.)

- [ ] **Step 4: Run to verify `cells` passes**

Run: `cargo test --lib fit::tests::cells 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Add the failing `queue_row` truncation tests**

In `src/tui/transfer/render.rs`, inside `mod queue_row_tests` (after `queue_row_folder_shows_folder_label_when_indeterminate`, before the closing `}`), add:

```rust
    #[test]
    fn queue_row_truncates_a_long_name_and_keeps_label_visible() {
        let long = "x".repeat(80);
        let t = task(&long, TaskState::Queued, false);
        let s = text(&queue_row(&t, 20, false));
        assert!(s.contains('…'), "long name is truncated: {s}");
        assert!(s.contains("queued"), "label still visible after truncation: {s}");
    }

    #[test]
    fn queue_row_leaves_a_short_name_intact_at_wide_width() {
        let t = task("photo.jpg", TaskState::Queued, false);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("photo.jpg"), "{s}");
        assert!(!s.contains('…'), "no truncation when the name fits: {s}");
    }
```

- [ ] **Step 6: Run to verify the row tests fail**

Run: `cargo test --lib queue_row_truncates 2>&1 | tail -15`
Expected: FAIL — the long-name test fails (no `…` today; label may be pushed off).

- [ ] **Step 7: Update the `fit` import in `render.rs`**

Change the import at `render.rs:27`:

```rust
use crate::tui::fit::truncate_cells_head;
```
to:
```rust
use crate::tui::fit::{cells, truncate_cells, truncate_cells_head};
```

- [ ] **Step 8: Rewrite `queue_row`**

Replace the **entire** `queue_row` function (`render.rs:413-475`, from `pub fn queue_row(` through its closing `}`) with:

```rust
pub fn queue_row(
    task: &crate::tui::transfer::ledger::Task,
    width: u16,
    selected: bool,
) -> Line<'static> {
    use crate::tui::transfer::ledger::TaskState;
    use sshrack_core::connect::sftp::proto::TransferOutcome;

    let glyph = match task.job.direction {
        sshrack_core::connect::sftp::proto::Direction::Upload => "↑",
        sshrack_core::connect::sftp::proto::Direction::Download => "↓",
    };
    let name_style = if selected {
        Style::new().add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };

    // Build the right-aligned state/progress label FIRST: the name budget is
    // what remains after the prefix and the label.
    let label = match &task.state {
        TaskState::Queued => {
            if matches!(task.kind, crate::tui::transfer::ledger::TaskKind::Folder) {
                "folder · indeterminate".to_string()
            } else {
                "queued".to_string()
            }
        }
        TaskState::InFlight => match &task.progress {
            Some(p) => match p.bytes_total {
                Some(total) if total > 0 => {
                    let pct = u16::try_from(p.bytes_done.saturating_mul(100) / total)
                        .unwrap_or(100)
                        .min(100);
                    format!("{pct}%")
                }
                _ => "transferring…".to_string(),
            },
            None => "starting…".to_string(),
        },
        TaskState::Done(TransferOutcome::Ok) => "done".to_string(),
        TaskState::Done(TransferOutcome::Cancelled) => "cancelled".to_string(),
        TaskState::Done(TransferOutcome::Failed(msg)) => {
            format!("failed: {}", truncate_cells_head(msg, 20))
        }
    };
    let label_cells = cells(&label);

    // Prefix " <glyph> " is 3 cells; reserve ≥1 cell gap before the label.
    let prefix_cells = 3usize;
    let name_budget = (width as usize).saturating_sub(prefix_cells + 1 + label_cells);
    let shown = truncate_cells(&task.job.name, name_budget);
    let name_cells = cells(&shown);

    let fill = (width as usize).saturating_sub(prefix_cells + name_cells + label_cells + 1);
    let label_style = match &task.state {
        TaskState::Done(TransferOutcome::Failed(_)) => Style::new().fg(crate::tui::theme::DANGER),
        TaskState::Done(TransferOutcome::Ok) => Style::new().dim(),
        TaskState::Queued => Style::new().dim(),
        _ => Style::new(),
    };

    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, name_style),
        Span::raw(" "),
        Span::styled(shown, name_style),
        Span::raw(" ".repeat(fill)),
        Span::styled(label, label_style),
    ])
}
```

- [ ] **Step 9: Run the row tests + regression**

Run:
```bash
cargo test --lib queue_row 2>&1 | tail -15
```
Expected: PASS — both new tests plus the four pre-existing `queue_row_*` tests (the existing `task()` helper uses short names that fit, so they are unaffected).

- [ ] **Step 10: Run workspace tests + clippy + fmt; commit**

```bash
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15
cargo fmt
git add src/tui/fit.rs src/tui/transfer/render.rs
git commit -m "fix(tui): truncate long filenames in queue rows"
```

---

## Task 3: Tab strip with per-view counts + empty-view placeholder

**Files:**
- Modify: `src/tui/transfer/render.rs` (add `queue_tab_bar`)
- Modify: `src/tui/transfer/queue_overlay.rs` (rewrite `draw` to render the tab strip + `focus_window` list + empty state; add `Tab`/view to footer hints)
- Test: `src/tui/transfer/render.rs` (`queue_tab_bar` tests) and `src/tui/transfer/screen_tests.rs` (behavior)

**Interfaces:**
- Produces: `pub fn queue_tab_bar(current: QueueView, tabs: &[(QueueView, usize); 3], width: u16) -> Line<'static>` (see Interfaces block).
- Consumes: `QueueView` (T1), `cells` (T2, only if a future truncation is added — not required now).

The current view's name currently sits in the header (a Task 1 placeholder). Now it moves into a proper tab strip above the list, each tab carrying its count, the active tab accented + underlined. Empty views show `no tasks`. The list uses `fit::focus_window` instead of the hand-rolled window math.

- [ ] **Step 1: Add the `QueueView` import to `render.rs`**

At the top of `src/tui/transfer/render.rs`, add this alongside the other `use crate::tui::transfer::...` lines:

```rust
use crate::tui::transfer::queue_overlay::QueueView;
```

- [ ] **Step 2: Add the failing `queue_tab_bar` tests**

In `src/tui/transfer/render.rs`, add a new test module at the **end** of the file (after `mod queue_row_tests`):

```rust
#[cfg(test)]
mod queue_tab_bar_tests {
    use super::*;
    use crate::tui::transfer::queue_overlay::QueueView;

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn tab_bar_lists_all_three_views_with_counts() {
        let tabs = [
            (QueueView::Active, 2),
            (QueueView::Failed, 1),
            (QueueView::Completed, 5),
        ];
        let line = queue_tab_bar(QueueView::Active, &tabs, 80);
        let s = line_to_string(&line);
        assert!(s.contains("Active (2)"), "{s}");
        assert!(s.contains("Failed (1)"), "{s}");
        assert!(s.contains("Completed (5)"), "{s}");
    }

    #[test]
    fn tab_bar_underlines_only_the_current_view() {
        let tabs = [(QueueView::Active, 0), (QueueView::Failed, 0), (QueueView::Completed, 0)];
        let line = queue_tab_bar(QueueView::Failed, &tabs, 80);
        // The span for "Failed (0)" is the only one flagged UNDERLINED.
        let labeled: Vec<(&str, bool)> = line
            .spans
            .iter()
            .map(|s| {
                (
                    s.content.as_ref(),
                    s.style
                        .add_modifier
                        .contains(ratatui::style::Modifier::UNDERLINED),
                )
            })
            .collect();
        let current = labeled
            .iter()
            .find(|(t, _)| t.contains("Failed"))
            .map(|(_, u)| *u);
        assert_eq!(current, Some(true), "current view underlined");
        let others_underlined = labeled
            .iter()
            .filter(|(t, u)| (t.contains("Active") || t.contains("Completed")) && *u)
            .count();
        assert_eq!(others_underlined, 0, "non-current views not underlined");
    }
}
```

(If `line_to_string` is not in scope at the file's top-level test scope, mirror the `text()` helper already in `queue_row_tests` — copy it into this module as `fn line_to_string(line: &Line<'_>) -> String` using the same span-join body.)

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test --lib queue_tab_bar 2>&1 | tail -15`
Expected: FAIL — `cannot find function queue_tab_bar`.

- [ ] **Step 4: Implement `queue_tab_bar`**

In `src/tui/transfer/render.rs`, add this function immediately **after** the `queue_row` function (after Task 2 it ends with its closing `}`):

```rust
/// The view-switcher tab strip: `Active (n)   Failed (n)   Completed (n)`,
/// separated by a 3-space gutter. The current view is rendered accented +
/// underlined; the others dimmed. `tabs` carries per-view counts (computed by
/// the caller via `task_indices_for`), so this function stays free of ledger
/// internals. Pure: returns a [`Line`] for the overlay's tab row.
pub fn queue_tab_bar(current: QueueView, tabs: &[(QueueView, usize); 3], _width: u16) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();
    for (i, (view, count)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        let label = match view {
            QueueView::Active => "Active",
            QueueView::Failed => "Failed",
            QueueView::Completed => "Completed",
        };
        let style = if *view == current {
            crate::tui::theme::accent().add_modifier(Modifier::UNDERLINED)
        } else {
            Style::new().dim()
        };
        spans.push(Span::styled(format!("{label} ({count})"), style));
    }
    Line::from(spans)
}
```

- [ ] **Step 5: Run to verify `queue_tab_bar` passes**

Run: `cargo test --lib queue_tab_bar 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 6: Add the failing empty-view behavior test**

Append to `src/tui/transfer/screen_tests.rs`:

```rust
#[test]
fn empty_view_shows_the_no_tasks_placeholder() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    // No tasks at all — every view is empty.
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty())); // -> Failed (empty)
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("no tasks"),
        "empty view shows placeholder: {view}"
    );
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `cargo test --lib empty_view_shows 2>&1 | tail -15`
Expected: FAIL — "no tasks" not rendered yet (Task 1 `draw` has no placeholder).

- [ ] **Step 8: Add `QueueView::all()` and rewrite `draw` in `queue_overlay.rs`**

First, add the `all()` method to `QueueView` in `src/tui/transfer/queue_overlay.rs` — inside `impl QueueView`, immediately after the `prev` method and before the closing `}`. (It is introduced here, not in Task 1, because `draw` below is its first non-test consumer; defining it earlier would trip `cargo clippy --all-targets` dead-code on the non-test binary target.)

```rust
    /// All views in `Tab` order. Used to render the tab strip and to compute
    /// per-view counts.
    fn all() -> [Self; 3] {
        [Self::Active, Self::Failed, Self::Completed]
    }
```

Then, still in `src/tui/transfer/queue_overlay.rs`, update the `ratatui` import (line ~12) from:

```rust
use ratatui::{Frame, layout::Rect, widgets::Paragraph};
```
to:
```rust
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::{Frame, widgets::Paragraph};
```

Then replace the **entire** `draw` method (the Task 1 version, from `pub fn draw(` through its closing `}`) with:

```rust
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
            if (y - list_area.y) as u16 >= list_area.height {
                break;
            }
        }
    }
```

- [ ] **Step 9: Run all overlay + render tests**

Run:
```bash
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15
cargo fmt
```
Expected: all pass. The `tab_switches_to_failed_view_and_lists_the_failed_task` / `shift_tab_cycles_back_to_completed_view` tests from Task 1 still pass (they assert view contents, not the header). The Task 1 header showed the view name; that is now replaced by the tab strip — verify no Task 1 test asserted the header word `active`/`failed`/`completed` (none do; they assert task names).

- [ ] **Step 10: Commit**

```bash
git add src/tui/transfer/render.rs src/tui/transfer/queue_overlay.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(tui): add view tabs and empty-state to queue overlay"
```

---

## Task 4: Docs + key reference + final verification

**Files:**
- Modify: `docs/sftp.md` (document the queue-overlay keys incl. `Tab`)
- Verify: `src/tui/transfer/queue_overlay.rs` (module doc already updated in Task 1 — re-read to confirm it no longer references removed concepts)

**Interfaces:** n/a (cleanup + docs).

- [ ] **Step 1: Locate the queue-overlay key reference**

Run: `rg -n 'queue|^\| `?\^Q|Tab .{0,20}pane' docs/sftp.md`
Inspect the section that lists the `^Q` queue overlay keys. (If `docs/sftp.md` has no dedicated queue-overlay key table, add a short subsection under the transfer-keys section mirroring the existing format.)

- [ ] **Step 2: Document the queue-overlay keys**

Update the queue-overlay key reference to reflect the final key set. Use this exact table content (adapt surrounding prose to the file's existing style):

```markdown
| Key | Action (queue overlay) |
|---|---|
| `Tab` / `Shift-Tab` | cycle view: Active / Failed / Completed |
| `↑`/`↓` or `k`/`j` | move selection (current view) |
| `Enter` / `r` | retry the selected failed/cancelled task |
| `Del` / `d` | remove the selected task (cancel if in-flight) |
| `c` | cancel the in-flight task |
| `p` | pause / resume the queue |
| `Esc` | close the overlay |
```

Add one line of prose: "Active lists in-flight + queued tasks; Failed lists failed + cancelled (retryable); Completed lists finished tasks. Each view keeps its own cursor."

- [ ] **Step 3: Confirm no stale references**

Run:
```bash
rg -n 'selectable\(|> .*completed|N completed|Task 4|Task 5' src/tui/transfer/
```
Expected: no matches in `queue_overlay.rs` for `selectable(`, `completed` folded-row, or `Task 4`/`Task 5` doc text. (The word "completed" may still appear in `QueueView::Completed` / `task_indices_for` comments — that is fine; this check targets the removed `selectable` function and the removed folded-row string.)

- [ ] **Step 4: Final full verification**

Run:
```bash
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -15
cargo fmt --check
```
Expected: all tests pass; clippy green; fmt clean.

- [ ] **Step 5: Commit**

```bash
git add docs/sftp.md
git commit -m "docs(sftp): document queue-overlay view tabs and keys"
```

---

## Self-Review (run after writing; recorded here for the implementer)

**Spec coverage:**
- Three views (Active / Failed / Completed), no "All" → Task 1 (`QueueView`, `task_indices_for`). ✓
- `Tab` / `Shift-Tab` cycle, no conflict (overlay owns the key; `Tab` is a control key) → Task 1 (`on_key`). ✓
- Per-view cursor (leave & return) → Task 1 (`cursors`, `each_view_keeps_its_own_cursor`). ✓
- Per-view counts on the tabs → Task 3 (`queue_tab_bar`, counts from `task_indices_for`). ✓
- Empty-view placeholder → Task 3 (`no tasks`). ✓
- Long filename display → Task 2 (`queue_row` truncation + `cells`). ✓
- Remove the non-inspectable `> N completed` folded row → Task 1 (`draw` no longer renders it; `selectable` removed). ✓
- UX-friendly rendering (tab strip, current-view highlight, `focus_window` scrolling) → Task 3. ✓
- Key reference updated → Task 4. ✓

**Placeholder scan:** none — every step has exact code or an exact command.

**Type consistency:** `QueueView` is `#[repr(usize)]` with `Active=0/Failed=1/Completed=2` so `cursors[self.view as usize]` is valid in T1 tests and `draw`. `task_indices_for(&TransferLedger, QueueView) -> Vec<usize>` matches every call site. `queue_tab_bar(QueueView, &[(QueueView, usize); 3], u16) -> Line<'static>` matches the T3 `draw` call (`QueueView::all().map(|v| (v, task_indices_for(ledger, v).len()))` yields `[(QueueView, usize); 3]`). `cells(&str) -> usize` used in T2 `queue_row`. `focus_window(total, cursor, height) -> Range<usize>` matches the T3 loop.
