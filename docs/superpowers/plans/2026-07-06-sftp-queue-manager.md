# SFTP Queue Manager (MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a transfer-ledger data model, collapse the transfer screen's status panel from 4 rows to 2 (active transfer + `done/total · fail` summary), and add a `^Q` queue-manager popup that lists every task with per-task progress/status and supports retry / remove / cancel / queue-level pause.

**Architecture:** Introduce `TransferLedger` (pure, in `src/tui/transfer/ledger.rs`) as the single source of truth for transfer tasks, replacing `TransferScreen`'s `queue`/`active`/`last_direction` fields. The worker protocol (`WorkerCmd`/`WorkerEvent`/`TransferJob`/`Progress`/`TransferOutcome`) is unchanged — the ledger is a UI-side projection that the run-loop mutates from drained worker events. A new `QueueOverlay` (modal, lives inside `TransferScreen` because the transfer screen bypasses `App::overlay` — see `app.rs` Layer-0) renders the ledger and routes `retry`/`remove`/`cancel`/`pause` keys to ledger mutations, reusing the existing `ScreenOutcome::{Enqueue, CancelActive}` for the loop side-effects.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30 + crossterm 0.28. Pure-logic TDD for the ledger; render-smoke + on_key routing tests for the screen/overlay.

## Global Constraints

- **English only** — all source, comments, doc comments, errors, help text, log output, commit messages.
- **Zero `unsafe`** (incl. tests); **zero `unwrap()`/`expect()`** in production (only `#[cfg(test)]` or unreachable `expect("invariant: …")`).
- **TDD for pure logic** (ledger, summary_line, queue_row) — RED → GREEN → REFACTOR.
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Never reimplement SSH** — no `russh`/`ssh2`/`russh-sftp`; this plan touches only TUI state + the existing system-sftp worker drain.
- **sshrack-core is zero-UI** — never add a UI dep to `crates/sshrack-core/`. The ledger is TUI-side.
- **Errors** — library errors `thiserror`, app errors `anyhow` + `.context()`; all fallible ops propagate `?`.
- **Conventional Commits** — `<type>(<scope>): <desc>`, **NO `Co-Authored-By` trailer**. Scope e.g. `tui`, `transfer`.
- **Stage explicitly** — `git add <paths>`, NEVER `git add -A`.
- **Tests hermetic** — `cargo test` must stay green with `SSHRACK_PASSPHRASE` already set in the real shell; no `env -u` workarounds.
- **Dev-stage: no compat code** — the ledger becomes the single source of truth; the old `queue`/`active`/`last_direction` fields are DELETED, not dual-written. Per-task `#[allow(dead_code)]` is allowed ONLY with a "Task-N consumer" doc comment (the established SFTP staging convention); remove it once the consumer lands.
- **Key-binding invariant** — bare printable chars reach the pane search box; new hotkeys MUST be Ctrl-combos. The queue popup is opened with `Ctrl-Q` (`^Q`), never bare `q`/`Q`.

**Locked design decisions (D1–D4):** D1 = keep the 1-row active-transfer line on the main screen; D2 = folders stay one indeterminate task in the MVP (per-file expansion is Phase 2); D3 = `^Q` opens the popup; D4 = no `cancel-all` in the MVP.

---

## File Structure

- **Create** `src/tui/transfer/ledger.rs` — pure `TransferLedger` model (Task 1). No UI deps.
- **Create** `src/tui/transfer/queue_overlay.rs` — `QueueOverlay` modal state + `on_key` + `draw` (Tasks 4–5).
- **Modify** `src/tui/transfer/mod.rs` — declare the two new modules.
- **Modify** `src/tui/transfer/screen.rs` — replace `queue`/`active`/`last_direction` with `ledger: TransferLedger`; add `queue_overlay: Option<QueueOverlay>`; intercept `^Q` + overlay routing in `on_key`; draw overlay in `draw`; collapse status panel 4→2 rows; add `^Q` to footer.
- **Modify** `src/tui/transfer/render.rs` — add `summary_line` + `queue_row` pure helpers (with tests); delete `queue_summary_line` + `queue_second_line` + their tests.
- **Modify** `src/tui/transfer/screen_tests.rs` — port fixtures/assertions to the ledger API; add overlay + summary tests.
- **Modify** `src/tui/run_loop.rs` — drain `Done` arm snapshots direction then calls `finish_inflight(outcome)`; `dispatch_next_job` popup-Cancel path calls `abort_inflight` + `clear_queued`.
- **Modify** `src/tui/app.rs` — `route_transfer` reads `screen.has_inflight()` instead of `screen.active.is_none()`.
- **Modify** `docs/sftp.md` + `CLAUDE.md` — document the queue manager + `^Q` (Task 6).

---

## Task 1: Pure `TransferLedger` model

**Files:**
- Create: `src/tui/transfer/ledger.rs`
- Modify: `src/tui/transfer/mod.rs` — add `pub mod ledger;`

**Interfaces:**
- Consumes: `sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob, TransferOutcome}` (all already `Clone`; `TransferOutcome` is `Clone`).
- Produces: `TaskId`, `TaskKind`, `TaskState`, `Task`, `TransferLedger` — the API every later task reads. **Do not rename these in later tasks.**

- [ ] **Step 1: Write the failing tests**

Create `src/tui/transfer/ledger.rs` with ONLY the test module first (the types it references do not exist yet → compile fails = RED):

```rust
//! Pure transfer-task ledger: the single source of truth for the queue-manager
//! popup and the status-bar counters. UI-side projection of the worker's
//! `TransferJob` / `Progress` / `TransferOutcome` stream — no I/O, no worker
//! dependency. Mutated by the run-loop from drained `WorkerEvent`s.
//!
//! Reachability: Task 2 wires `TransferScreen` onto this struct. Until then
//! every public item is test-only, so each carries a scoped
//! `#[allow(dead_code)]` naming the Task-2 consumer (the established SFTP
//! staging convention — no blanket module-level allow).

use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob, TransferOutcome};

/// Stable id for a task. The popup selects by display index but operations
/// resolve through this id so a mutation + re-render can not mis-target a row
/// that shifted.
#[allow(dead_code)] // Task 2: TransferScreen wiring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub usize);

/// Display flavor of a task. `Folder` tasks are indeterminate in the MVP
/// (Phase 2 expands them to per-file tasks).
#[allow(dead_code)] // Task 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    File,
    Folder,
}

/// Lifecycle of a task. Concurrency is 1, so at most one task is `InFlight`.
#[allow(dead_code)] // Task 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Queued,
    InFlight,
    Done(TransferOutcome),
}

/// One tracked transfer. `progress` is `Some` only while `InFlight`.
#[allow(dead_code)] // Task 2
#[derive(Debug, Clone)]
pub struct Task {
    pub id: TaskId,
    pub kind: TaskKind,
    pub job: TransferJob,
    pub progress: Option<Progress>,
    pub state: TaskState,
}

/// The transfer ledger. Owns every task (queued + in-flight + recent history)
/// and the queue-level pause flag. Counters are derived, never stored.
#[allow(dead_code)] // Task 2
#[derive(Debug, Clone, Default)]
pub struct TransferLedger {
    /// Insertion-ordered. FIFO dispatch walks this for the head `Queued` task.
    pub tasks: Vec<Task>,
    next_id: usize,
    paused: bool,
}
```

Then append the test module (this is the RED suite — it calls methods that do not exist yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn job(name: &str, dir: Direction, recursive: bool) -> TransferJob {
        TransferJob {
            direction: dir,
            src: format!("/s/{name}").into(),
            dst: format!("/d/{name}").into(),
            name: name.into(),
            size_total: Some(1024),
            recursive,
        }
    }

    fn prog(name: &str) -> Progress {
        Progress {
            name: name.into(),
            direction: Direction::Upload,
            bytes_done: 10,
            bytes_total: Some(100),
            rate_bps: Some(5),
            eta_secs: Some(18),
        }
    }

    #[test]
    fn enqueue_assigns_increasing_ids_and_queued_state() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        let b = l.enqueue(job("b", Direction::Download, false));
        assert_ne!(a, b, "ids must be distinct");
        assert_eq!(l.total(), 2);
        assert_eq!(l.pending_count(), 2);
        assert!(matches!(l.tasks[0].state, TaskState::Queued));
    }

    #[test]
    fn enqueue_kind_tracks_recursive() {
        let mut l = TransferLedger::new();
        let f = l.enqueue(job("f", Direction::Upload, false));
        let d = l.enqueue(job("d", Direction::Upload, true));
        assert_eq!(l.tasks.iter().find(|t| t.id == f).unwrap().kind, TaskKind::File);
        assert_eq!(l.tasks.iter().find(|t| t.id == d).unwrap().kind, TaskKind::Folder);
    }

    #[test]
    fn next_to_dispatch_marks_head_queued_inflight() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        l.enqueue(job("b", Direction::Upload, false));
        assert_eq!(l.next_to_dispatch(), Some(a));
        assert!(l.has_inflight());
        assert_eq!(l.pending_count(), 1, "only one queued remains");
    }

    #[test]
    fn next_to_dispatch_returns_none_when_empty() {
        let mut l = TransferLedger::new();
        assert_eq!(l.next_to_dispatch(), None);
    }

    #[test]
    fn next_to_dispatch_returns_none_when_paused_and_does_not_mark() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload, false));
        l.set_paused(true);
        assert_eq!(l.next_to_dispatch(), None);
        assert!(!l.has_inflight(), "paused must not start a task");
        assert_eq!(l.pending_count(), 1);
    }

    #[test]
    fn next_to_dispatch_skips_done_tasks() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        let b = l.enqueue(job("b", Direction::Upload, false));
        l.next_to_dispatch(); // a -> InFlight
        l.finish_inflight(TransferOutcome::Ok); // a -> Done(Ok)
        assert_eq!(l.next_to_dispatch(), Some(b), "dispatch walks past Done");
    }

    #[test]
    fn set_inflight_progress_updates_the_inflight_task() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload, false));
        l.next_to_dispatch();
        l.set_inflight_progress(prog("a"));
        assert_eq!(l.active_progress().map(|p| p.bytes_done), Some(10));
    }

    #[test]
    fn active_progress_is_none_when_idle() {
        let mut l = TransferLedger::new();
        assert!(l.active_progress().is_none());
        l.enqueue(job("a", Direction::Upload, false));
        l.next_to_dispatch();
        assert!(l.active_progress().is_none(), "no Progress yet");
    }

    #[test]
    fn finish_inflight_marks_done_and_clears_progress() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload, false));
        l.next_to_dispatch();
        l.set_inflight_progress(prog("a"));
        l.finish_inflight(TransferOutcome::Failed("boom".into()));
        assert!(!l.has_inflight());
        assert!(l.active_progress().is_none());
        assert_eq!(l.failed_count(), 1);
        assert_eq!(l.done_count(), 0, "Failed is not a success");
    }

    #[test]
    fn done_count_counts_ok_only() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload, false));
        l.enqueue(job("b", Direction::Upload, false));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok); // a done
        assert_eq!(l.done_count(), 1);
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Cancelled); // b cancelled
        assert_eq!(l.done_count(), 1, "Cancelled is not a success");
        assert_eq!(l.failed_count(), 0);
    }

    #[test]
    fn retry_requeues_failed_or_cancelled_only() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        let b = l.enqueue(job("b", Direction::Upload, false));
        l.next_to_dispatch(); // a -> InFlight
        l.finish_inflight(TransferOutcome::Failed("x".into())); // a -> Done(Failed)
        assert!(l.retry(a), "failed task is retryable");
        assert!(matches!(l.tasks.iter().find(|t| t.id == a).unwrap().state, TaskState::Queued));
        assert_eq!(l.pending_count(), 2, "a (retried) + b both queued");

        // A Queued task is NOT retryable.
        assert!(!l.retry(b));

        // A Done(Ok) task is NOT retryable.
        l.next_to_dispatch(); // dispatch a (head Queued again)
        l.finish_inflight(TransferOutcome::Ok);
        assert!(!l.retry(a));
    }

    #[test]
    fn remove_drops_queued_or_done_but_not_inflight() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        let b = l.enqueue(job("b", Direction::Upload, false));
        assert!(l.remove(b), "queued task removable");
        assert_eq!(l.total(), 1);
        l.next_to_dispatch(); // a InFlight
        assert!(!l.remove(a), "inflight task not removable here (worker-cancel path)");
        l.finish_inflight(TransferOutcome::Ok);
        assert!(l.remove(a), "done task removable");
        assert_eq!(l.total(), 0);
    }

    #[test]
    fn clear_queued_removes_only_queued() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        l.enqueue(job("b", Direction::Upload, false));
        l.next_to_dispatch(); // a InFlight
        l.clear_queued();
        assert_eq!(l.pending_count(), 0);
        assert!(l.has_inflight(), "InFlight survives clear_queued");
        assert!(l.tasks.iter().any(|t| t.id == a));
    }

    #[test]
    fn abort_inflight_removes_the_inflight_task() {
        let mut l = TransferLedger::new();
        let a = l.enqueue(job("a", Direction::Upload, false));
        l.next_to_dispatch(); // a InFlight
        l.abort_inflight();
        assert!(!l.has_inflight());
        assert!(l.tasks.iter().all(|t| t.id != a), "InFlight task gone");
    }

    #[test]
    fn pause_toggle_flips_flag() {
        let mut l = TransferLedger::new();
        assert!(!l.is_paused());
        l.toggle_paused();
        assert!(l.is_paused());
        l.toggle_paused();
        assert!(!l.is_paused());
    }

    #[test]
    fn last_direction_prefers_inflight_then_most_recent_done() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload, false));
        l.next_to_dispatch();
        assert_eq!(l.last_direction(), Some(Direction::Upload));
        l.finish_inflight(TransferOutcome::Ok);
        assert_eq!(l.last_direction(), Some(Direction::Upload), "falls back to most-recent Done");
        assert_eq!(TransferLedger::new().last_direction(), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test transfer::ledger::tests --no-run`
Expected: COMPILE ERROR — the methods (`new`, `enqueue`, `next_to_dispatch`, `has_inflight`, `pending_count`, `set_inflight_progress`, `active_progress`, `finish_inflight`, `done_count`, `failed_count`, `retry`, `remove`, `clear_queued`, `abort_inflight`, `total`, `set_paused`, `toggle_paused`, `is_paused`, `last_direction`) do not exist yet.

- [ ] **Step 3: Implement the methods**

Append to `src/tui/transfer/ledger.rs` (above the `#[cfg(test)]` block):

```rust
#[allow(dead_code)] // Task 2
impl TransferLedger {
    /// Empty ledger, not paused.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a job as a new `Queued` task; returns its id.
    pub fn enqueue(&mut self, job: TransferJob) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;
        let kind = if job.recursive { TaskKind::Folder } else { TaskKind::File };
        self.tasks.push(Task {
            id,
            kind,
            job,
            progress: None,
            state: TaskState::Queued,
        });
        id
    }

    /// Mark the head `Queued` task `InFlight` and return its id — unless the
    /// queue is paused (then no task starts; returns `None`). Returns `None`
    /// when no `Queued` task exists. The caller reads [`Self::job_for`] to send
    /// `WorkerCmd::Transfer`.
    pub fn next_to_dispatch(&mut self) -> Option<TaskId> {
        if self.paused {
            return None;
        }
        let task = self
            .tasks
            .iter_mut()
            .find(|t| matches!(t.state, TaskState::Queued))?;
        task.state = TaskState::InFlight;
        Some(task.id)
    }

    /// Clone out the job for a task id (to hand the worker).
    pub fn job_for(&self, id: TaskId) -> Option<TransferJob> {
        self.tasks.iter().find(|t| t.id == id).map(|t| t.job.clone())
    }

    /// The single `InFlight` task's id, if any (concurrency = 1).
    pub fn inflight_id(&self) -> Option<TaskId> {
        self.tasks
            .iter()
            .find(|t| matches!(t.state, TaskState::InFlight))
            .map(|t| t.id)
    }

    /// Whether any task is currently in flight.
    pub fn has_inflight(&self) -> bool {
        self.inflight_id().is_some()
    }

    /// Update the `InFlight` task's progress snapshot (from `WorkerEvent::Progress`).
    pub fn set_inflight_progress(&mut self, p: Progress) {
        if let Some(id) = self.inflight_id() {
            if let Some(t) = self.tasks.iter_mut().find(|t| t.id == id) {
                t.progress = Some(p);
            }
        }
    }

    /// The `InFlight` task's progress snapshot (for the status-bar active row).
    pub fn active_progress(&self) -> Option<&Progress> {
        self.tasks
            .iter()
            .find(|t| matches!(t.state, TaskState::InFlight))
            .and_then(|t| t.progress.as_ref())
    }

    /// Mark the `InFlight` task `Done(outcome)` and clear its progress snapshot.
    /// Called from the `WorkerEvent::Done` drain arm.
    pub fn finish_inflight(&mut self, outcome: TransferOutcome) {
        if let Some(t) = self
            .tasks
            .iter_mut()
            .find(|t| matches!(t.state, TaskState::InFlight))
        {
            t.state = TaskState::Done(outcome);
            t.progress = None;
        }
    }

    /// Re-queue a `Done(Failed|Cancelled)` task in place. Returns `true` if the
    /// task was retryable and is now `Queued`. `Done(Ok)` and non-`Done` tasks
    /// are not retryable.
    pub fn retry(&mut self, id: TaskId) -> bool {
        let Some(t) = self.tasks.iter_mut().find(|t| t.id == id) else {
            return false;
        };
        let retryable = matches!(
            &t.state,
            TaskState::Done(TransferOutcome::Failed(_)) | TaskState::Done(TransferOutcome::Cancelled)
        );
        if retryable {
            t.state = TaskState::Queued;
            t.progress = None;
        }
        retryable
    }

    /// Remove a non-`InFlight` task (Queued or Done). `InFlight` tasks are
    /// removed via [`Self::abort_inflight`] (the worker-cancel path), not here.
    /// Returns `true` if a task was removed.
    pub fn remove(&mut self, id: TaskId) -> bool {
        if self
            .tasks
            .iter()
            .any(|t| t.id == id && matches!(t.state, TaskState::InFlight))
        {
            return false;
        }
        let before = self.tasks.len();
        self.tasks.retain(|t| t.id != id);
        self.tasks.len() < before
    }

    /// Remove every `Queued` task (overwrite-popup Cancel drops the batch).
    pub fn clear_queued(&mut self) {
        self.tasks.retain(|t| !matches!(t.state, TaskState::Queued));
    }

    /// Remove the `InFlight` task entirely (used when dispatch is aborted
    /// before the job is sent — i.e. overwrite-popup Cancel).
    pub fn abort_inflight(&mut self) {
        self.tasks.retain(|t| !matches!(t.state, TaskState::InFlight));
    }

    /// Queue-level pause flag.
    pub fn is_paused(&self) -> bool {
        self.paused
    }
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }
    pub fn toggle_paused(&mut self) {
        self.paused = !self.paused;
    }

    // ---- derived counters ----

    /// Total tasks tracked (queued + in-flight + history).
    pub fn total(&self) -> usize {
        self.tasks.len()
    }
    /// Successfully completed tasks (`Done(Ok)` — the worker short-circuits
    /// overwrite `Skip` to `Ok`, so this covers skipped files too).
    pub fn done_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Done(TransferOutcome::Ok)))
            .count()
    }
    /// Failed tasks (`Done(Failed)`).
    pub fn failed_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Done(TransferOutcome::Failed(_))))
            .count()
    }
    /// Tasks waiting to run (`Queued`).
    pub fn pending_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Queued))
            .count()
    }
    /// True when no `Queued` task remains (the post-Done refresh gate).
    pub fn queue_empty(&self) -> bool {
        self.pending_count() == 0
    }
    /// Direction for the post-Done pane-refresh decision: the `InFlight`
    /// task's direction, else the most recently finished task's direction.
    pub fn last_direction(&self) -> Option<Direction> {
        if let Some(t) = self
            .tasks
            .iter()
            .find(|t| matches!(t.state, TaskState::InFlight))
        {
            return Some(t.job.direction);
        }
        self.tasks
            .iter()
            .rev()
            .find(|t| matches!(t.state, TaskState::Done(_)))
            .map(|t| t.job.direction)
    }
}
```

- [ ] **Step 4: Register the module**

In `src/tui/transfer/mod.rs`, add (after `pub mod open;`):

```rust
pub mod ledger;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test transfer::ledger::tests`
Expected: PASS — all ledger tests green.

- [ ] **Step 6: Commit**

```bash
git add src/tui/transfer/ledger.rs src/tui/transfer/mod.rs
git commit -m "feat(transfer): add pure TransferLedger model for queue management"
```

---

## Task 2: Wire `TransferScreen` + `run_loop` onto the ledger (behavior-preserving)

**Goal:** `TransferLedger` becomes the single source of truth. The 4-row status panel and drain/dispatch semantics are UNCHANGED after this task — only the backing store changes. The existing `screen_tests` + `run_loop` tests must stay green (ported to the ledger API).

**Files:**
- Modify: `src/tui/transfer/screen.rs`
- Modify: `src/tui/run_loop.rs`
- Modify: `src/tui/app.rs`
- Modify: `src/tui/transfer/screen_tests.rs`

**Interfaces:**
- Consumes: `TransferLedger` (Task 1).
- Produces: `TransferScreen` now exposes `ledger: TransferLedger` (pub(crate)) + thin accessors `has_inflight()`, `queue_empty()`, `last_direction()`, `finish_inflight(outcome)`, `abort_inflight()`, `clear_queued()`, and keeps `next_job() -> Option<TransferJob>`, `set_active(Option<Progress>)`. The old fields `queue`/`active`/`last_direction` are DELETED.

**Transformation rule for test sites (apply mechanically; the compiler enumerates them after field deletion):**
- `screen.queue.push(job)` → `screen.ledger.enqueue(job);` (return value ignored).
- `screen.active = Some(p)` (a Progress) → enqueue a job for it, dispatch it, set progress. In practice only `canned_screen()` does this — port it per Step 4 below.
- `screen.active` (read) / `screen.active.is_some()` → `screen.ledger.active_progress()` / `screen.has_inflight()`.
- `screen.queue` (read) → `screen.ledger.tasks` or the relevant accessor.
- `screen.last_direction` → `screen.ledger.last_direction()`.

- [ ] **Step 1: Update the struct + constructors**

In `src/tui/transfer/screen.rs`:

Replace the three fields
```rust
    pub active: Option<Progress>,
    ...
    pub queue: Vec<TransferJob>,
    ...
    pub last_direction: Option<Direction>,
```
with a single
```rust
    /// The transfer ledger: single source of truth for queued / in-flight /
    /// recently-finished tasks + the queue-level pause flag. Drives both the
    /// status-bar counters and the queue-manager popup. Mutated by the run-loop
    /// from drained `WorkerEvent`s.
    pub ledger: crate::tui::transfer::ledger::TransferLedger,
```

Update the imports at the top of `screen.rs`: remove now-unused `Progress`, `TransferJob`, `Direction` IF they become unused (check after the edits; `TransferJob` is still used by `enqueue_from_focused` and `next_job`, `Direction` by `enqueue_from_focused`/`route_to_focused`, `Progress` by `set_active`). Keep `OverwritePolicy` (still a field). Add:
```rust
use crate::tui::transfer::ledger::TransferLedger;
use sshrack_core::connect::sftp::proto::TransferOutcome;
```

In `TransferScreen::new`, replace
```rust
            active: None,
            queue: Vec::new(),
            ...
            last_direction: None,
```
with
```rust
            ledger: TransferLedger::new(),
```

- [ ] **Step 2: Rewrite the queue helpers**

Replace `enqueue_from_focused`'s per-spec push (the `self.queue.push(TransferJob { … })` line inside the `for (path, name, is_dir, size) in specs` loop) with:
```rust
            self.ledger.enqueue(TransferJob {
                direction,
                src: path,
                dst,
                name: display_name,
                size_total: size,
                recursive: is_dir,
            });
```
(Keep the surrounding `specs` gathering + mark-clear unchanged.)

Replace `next_job` entirely:
```rust
    /// Mark the head queued task in-flight and return its job (cloned) so the
    /// loop can send `WorkerCmd::Transfer`. Returns `None` when the queue is
    /// empty or paused. Pure mutator: no I/O.
    pub fn next_job(&mut self) -> Option<TransferJob> {
        let id = self.ledger.next_to_dispatch()?;
        self.ledger.job_for(id)
    }
```

Replace `set_active`:
```rust
    /// Update the in-flight task's progress snapshot (from
    /// `WorkerEvent::Progress`). `None` is a no-op (the `Done` arm calls
    /// [`finish_inflight`](Self::finish_inflight) to clear it).
    pub fn set_active(&mut self, progress: Option<Progress>) {
        if let Some(p) = progress {
            self.ledger.set_inflight_progress(p);
        }
    }
```

Replace `clear_active` with three accessors:
```rust
    /// Mark the in-flight task `Done(outcome)` and clear its progress snapshot.
    /// Called from the run-loop's `WorkerEvent::Done` arm (replaces the old
    /// `clear_active` — the outcome is now retained as history).
    pub fn finish_inflight(&mut self, outcome: TransferOutcome) {
        self.ledger.finish_inflight(outcome);
    }

    /// Drop the in-flight task entirely (dispatch aborted before the job was
    /// sent — the overwrite-popup Cancel path).
    pub fn abort_inflight(&mut self) {
        self.ledger.abort_inflight();
    }

    /// Drop every queued task (overwrite-popup Cancel clears the batch).
    pub fn clear_queued(&mut self) {
        self.ledger.clear_queued();
    }

    /// Whether a transfer is currently in flight.
    pub fn has_inflight(&self) -> bool {
        self.ledger.has_inflight()
    }

    /// Whether any queued task remains (the post-Done refresh gate).
    pub fn queue_empty(&self) -> bool {
        self.ledger.queue_empty()
    }

    /// Direction of the in-flight task, else the most-recently-finished one.
    pub fn last_direction(&self) -> Option<Direction> {
        self.ledger.last_direction()
    }
```

- [ ] **Step 3: Update `draw_progress_panel`'s reads**

In `draw_progress_panel`, change:
```rust
        render::draw_active_transfer(frame, row1, self.active.as_ref());

        let q2 = render::queue_summary_line(self.queue.len(), self.queue.first(), area.width);
        frame.render_widget(Paragraph::new(q2), row2);

        let q3 = render::queue_second_line(self.queue.get(1), area.width);
```
to read pending jobs from the ledger (behavior-identical output):
```rust
        render::draw_active_transfer(frame, row1, self.ledger.active_progress());

        // Pending jobs in FIFO order, for the unchanged 4-row panel (Task 3
        // replaces this with the 2-row summary).
        let pending: Vec<&sshrack_core::connect::sftp::proto::TransferJob> = self
            .ledger
            .tasks
            .iter()
            .filter(|t| matches!(t.state, crate::tui::transfer::ledger::TaskState::Queued))
            .map(|t| &t.job)
            .collect();
        let q2 = render::queue_summary_line(pending.len(), pending.first().copied(), area.width);
        frame.render_widget(Paragraph::new(q2), row2);

        let q3 = render::queue_second_line(pending.get(1).copied(), area.width);
```

- [ ] **Step 4: Port `screen_tests.rs` fixtures**

In `src/tui/transfer/screen_tests.rs`, replace the body of `canned_screen()` (the `screen.active = Some(Progress { … });` + `screen.queue.push(TransferJob { … });` block) with ledger calls:
```rust
    // Active upload: enqueue + dispatch (InFlight) + progress snapshot.
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: local_cwd.join("alpha.txt"),
        dst: remote_cwd.join("alpha.txt"),
        name: "alpha.txt".into(),
        size_total: Some(1024),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.set_inflight_progress(Progress {
        name: "alpha.txt".into(),
        direction: Direction::Upload,
        bytes_done: 256,
        bytes_total: Some(1024),
        rate_bps: Some(128),
        eta_secs: Some(6),
    });
    // One queued download.
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: remote_cwd.join("server.log"),
        dst: local_cwd.join("server.log"),
        name: "server.log".into(),
        size_total: Some(2048),
        recursive: false,
    });
```

Then fix every other compile error the field deletion surfaces (run `cargo test transfer --no-run` and apply the transformation rule from the task header to each site). Common sites in `screen_tests.rs`:
- `screen.active = None;` → `screen.ledger.abort_inflight();` (drops the in-flight task) — used by `draw_shows_no_transfer_in_flight_when_idle`. NOTE: that test enqueues a download AFTER the upload is in-flight; to make the screen idle, also clear the queued download: `screen.ledger.abort_inflight(); screen.ledger.clear_queued();`.
- `screen.active = Some(Progress { … });` (other tests constructing an active transfer) → enqueue a job, `next_to_dispatch()`, `set_inflight_progress(Progress { … })`.
- Any direct `screen.queue` reads → `screen.ledger.tasks` filtered by state.

- [ ] **Step 5: Update `run_loop.rs` drain**

In `src/tui/run_loop.rs` `drain_transfer_events`:

In the `WorkerEvent::Done(outcome)` arm, replace
```rust
            WorkerEvent::Done(outcome) => {
                if let Some(screen) = app.transfer.as_mut() {
                    screen.clear_active();
                }
                let last_direction = app.transfer.as_ref().and_then(|s| s.last_direction);
                let queue_empty = app.transfer.as_ref().is_none_or(|s| s.queue.is_empty());
```
with (snapshot direction BEFORE finishing, then finish with the cloned outcome):
```rust
            WorkerEvent::Done(outcome) => {
                // Snapshot the just-finished direction BEFORE finish_inflight
                // flips the task to Done (it is still InFlight here).
                let last_direction = app.transfer.as_ref().and_then(|s| s.last_direction());
                if let Some(screen) = app.transfer.as_mut() {
                    screen.finish_inflight(outcome.clone());
                }
                let queue_empty = app.transfer.as_ref().is_none_or(|s| s.queue_empty());
```
(`TransferOutcome` is `Clone`.) The rest of the arm (`decide_post_done_refresh` + the `match outcome` for advance/failed) is unchanged.

In `dispatch_next_job`, replace the overwrite-popup `Cancel` arm's
```rust
                    screen.queue.clear();
```
with
```rust
                    screen.abort_inflight();
                    screen.clear_queued();
```
(`next_job` already marked the job in-flight; `abort_inflight` reverts that never-sent task and `clear_queued` drops the rest — matching the old "whole batch gone" behavior.)

- [ ] **Step 6: Update `app.rs`**

In `src/tui/app.rs` `route_transfer`, change the `ScreenOutcome::Enqueue` arm's
```rust
                if screen.active.is_none() {
```
to
```rust
                if !screen.has_inflight() {
```

- [ ] **Step 7: Run the full transfer + run_loop test suites**

Run: `cargo test transfer && cargo test run_loop::tests`
Expected: PASS — all existing tests green (4-row panel output identical; drain/dispatch semantics identical). No new tests in this task (behavior preserved).

- [ ] **Step 8: Clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: green. Remove any now-unused imports the field deletion left behind.

- [ ] **Step 9: Commit**

```bash
git add src/tui/transfer/screen.rs src/tui/transfer/screen_tests.rs src/tui/run_loop.rs src/tui/app.rs
git commit -m "refactor(transfer): back TransferScreen with TransferLedger"
```

---

## Task 3: Collapse the status panel 4 → 2 rows

**Goal:** Replace the 4-row progress panel with a 2-row band: row 1 = active transfer (existing `draw_active_transfer`), row 2 = `done X/Y · fail Z [· paused]` summary + the transient status message. Delete the now-dead `queue_summary_line` / `queue_second_line` helpers.

**Files:**
- Modify: `src/tui/transfer/render.rs`
- Modify: `src/tui/transfer/screen.rs`
- Modify: `src/tui/transfer/screen_tests.rs`

**Interfaces:**
- Produces: `render::summary_line(ledger, status, width) -> Line<'static>` (pure). Deletes `render::queue_summary_line` + `render::queue_second_line`.

- [ ] **Step 1: Write the failing test for `summary_line`**

In `src/tui/transfer/render.rs`, add a test (RED — `summary_line` does not exist yet):

```rust
#[cfg(test)]
mod summary_tests {
    use super::*;
    use crate::tui::intent::Status;
    use crate::tui::transfer::ledger::{TaskState, TransferLedger};
    use sshrack_core::connect::sftp::proto::{Direction, TransferJob, TransferOutcome};

    fn job(name: &str, dir: Direction) -> TransferJob {
        TransferJob {
            direction: dir,
            src: format!("/s/{name}").into(),
            dst: format!("/d/{name}").into(),
            name: name.into(),
            size_total: Some(1024),
            recursive: false,
        }
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect::<Vec<_>>().join("")
    }

    #[test]
    fn summary_line_shows_done_over_total_and_fail() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.enqueue(job("b", Direction::Upload));
        l.enqueue(job("c", Direction::Upload));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Ok); // a done
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        assert!(s.contains("done"), "label present: {s}");
        assert!(s.contains("1/3"), "done/total: {s}");
        assert!(s.contains("fail"), "fail label present: {s}");
        assert!(s.contains("0"), "fail count: {s}");
    }

    #[test]
    fn summary_line_shows_failed_count() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.next_to_dispatch();
        l.finish_inflight(TransferOutcome::Failed("x".into()));
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        assert!(s.contains("1/1"), "{s}");
        assert!(s.contains("fail 1"), "fail count rendered: {s}");
    }

    #[test]
    fn summary_line_appends_paused_when_paused() {
        let mut l = TransferLedger::new();
        l.enqueue(job("a", Direction::Upload));
        l.set_paused(true);
        let line = summary_line(&l, &Status::empty(), 60);
        let s = line_to_string(&line);
        assert!(s.contains("paused"), "paused marker: {s}");
    }

    #[test]
    fn summary_line_appends_status_message_when_present() {
        let mut l = TransferLedger::new();
        let line = summary_line(&l, &Status::error("transfer failed: boom"), 80);
        let s = line_to_string(&line);
        assert!(s.contains("transfer failed: boom"), "status message rendered: {s}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test transfer::render::summary_tests --no-run`
Expected: COMPILE ERROR — `summary_line` undefined.

- [ ] **Step 3: Implement `summary_line`**

In `src/tui/transfer/render.rs`, add (the import `use crate::tui::transfer::ledger::TransferLedger;` may be needed at the top — add it if not present):

```rust
/// Build the 2-row status band's summary line: `done X/Y · fail Z [· paused]`
/// on the left, and — when present — the transient status message on the right.
/// Pure. `width` bounds the message so it can not push the counts off the row.
pub fn summary_line(
    ledger: &crate::tui::transfer::ledger::TransferLedger,
    status: &crate::tui::intent::Status,
    width: u16,
) -> Line<'static> {
    let done = ledger.done_count();
    let total = ledger.total();
    let failed = ledger.failed_count();
    let counts = format!("done {done}/{total} · fail {failed}");
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled(
        counts,
        if failed > 0 {
            Style::new().fg(crate::tui::theme::DANGER)
        } else {
            Style::new()
        },
    ));
    if ledger.is_paused() {
        spans.push(Span::styled(" · ", Style::new().dim()));
        spans.push(Span::styled("paused", crate::tui::theme::accent()));
    }
    if let Some(msg) = &status.message {
        let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
        let budget = (width as usize).saturating_sub(used + 3); // " · "
        let trimmed = truncate_cells_head(msg, budget);
        spans.push(Span::styled(" · ", Style::new().dim()));
        let style = if status.is_error {
            Style::new().fg(crate::tui::theme::DANGER)
        } else {
            Style::new()
        };
        spans.push(Span::styled(trimmed, style));
    }
    Line::from(spans)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test transfer::render::summary_tests`
Expected: PASS.

- [ ] **Step 5: Delete the dead helpers + their tests**

In `src/tui/transfer/render.rs`, delete the functions `queue_summary_line` and `queue_second_line`, and delete any tests in `render.rs`'s test module that reference them (search for `queue_summary` / `queue_second`). `draw_active_transfer` stays.

- [ ] **Step 6: Rewrite `draw_progress_panel` to 2 rows**

In `src/tui/transfer/screen.rs`, replace the body of `draw_progress_panel` with:
```rust
    fn draw_progress_panel(&self, frame: &mut Frame, area: Rect) {
        let [row1, row2] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

        // Row 1: the active transfer (blank-looking when idle — draw_active_transfer
        // paints nothing useful without a progress snapshot). Keeps the live
        // progress visible without opening the queue popup.
        render::draw_active_transfer(frame, row1, self.ledger.active_progress());

        // Row 2: done/total + fail (+ paused) summary, with any transient status
        // message appended.
        let line = render::summary_line(&self.ledger, &self.status, area.width);
        frame.render_widget(Paragraph::new(line), row2);
    }
```

And in `draw`, change the panel height from `Constraint::Length(4)` to `Constraint::Length(2)`:
```rust
        let [title_area, panes_area, panel_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .areas(area);
```

Update the `draw_progress_panel` doc comment to describe the 2-row band (row 1 active transfer, row 2 summary + status).

- [ ] **Step 7: Update `screen_tests.rs` render assertions**

The 4-row-specific assertions change. In `src/tui/transfer/screen_tests.rs`:
- In `draw_paints_title_panes_progress_and_footer`, replace the queue assertion `assert!(view.contains("queue"), …)` with a summary assertion:
  ```rust
    assert!(view.contains("done"), "summary label missing: {view}");
  ```
- `draw_shows_no_transfer_in_flight_when_idle`: this asserted the literal `no transfer in flight` text. After Task 3 the idle row-1 paints nothing (no progress snapshot). Repurpose the test to assert the summary still renders and the screen does not panic when idle:
  ```rust
  #[test]
  fn draw_renders_summary_when_idle() {
      let backend = TestBackend::new(70, 20);
      let mut term = Terminal::new(backend).expect("test backend");
      let mut screen = canned_screen();
      screen.ledger.abort_inflight();
      screen.ledger.clear_queued();
      let res = term.draw(|f| screen.draw(f, f.area()));
      assert!(res.is_ok(), "idle draw must not panic: {:?}", res.err());
      let view = buffer_view(term.backend().buffer());
      assert!(view.contains("done"), "summary present when idle: {view}");
  }
  ```
  (Delete the old `draw_shows_no_transfer_in_flight_when_idle`.)
- Any other test asserting `queue:` / `no transfer in flight` text — update or remove similarly.

- [ ] **Step 8: Run the full transfer suite + clippy + fmt**

Run: `cargo test transfer && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: PASS + green.

- [ ] **Step 9: Commit**

```bash
git add src/tui/transfer/render.rs src/tui/transfer/screen.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(transfer): collapse status panel to a 2-row active+summary band"
```

---

## Task 4: Queue-manager popup — view, open `^Q`, close `Esc`, navigate

**Goal:** A modal `QueueOverlay` listing every task (in-flight first, then queued, then failed/cancelled, then a collapsed `> N completed` row). Opens with `^Q`, closes with `Esc`, navigates with `↑↓`/`jk`. No operations yet (Task 5 adds retry/remove/cancel/pause).

**Files:**
- Create: `src/tui/transfer/queue_overlay.rs`
- Modify: `src/tui/transfer/mod.rs` — add `pub mod queue_overlay;`
- Modify: `src/tui/transfer/screen.rs` — add `queue_overlay: Option<QueueOverlay>` field; intercept overlay routing + `^Q` in `on_key`; draw overlay in `draw`.
- Modify: `src/tui/transfer/render.rs` — add `queue_row(task, width, selected) -> Line<'static>` pure helper + tests.
- Modify: `src/tui/transfer/screen_tests.rs` — open/close/nav tests + render smoke.

**Interfaces:**
- Consumes: `TransferLedger`, `Task`, `TaskState`, `dialog::draw_dialog`, `ScreenOutcome`.
- Produces: `QueueOverlay { selected: usize, closed: bool }` with `new()`, `on_key(key, &mut ledger) -> ScreenOutcome`, `draw(&self, frame, &ledger)`. The screen stores `queue_overlay: Option<QueueOverlay>`.

- [ ] **Step 1: Write the failing test for `queue_row`**

In `src/tui/transfer/render.rs`, add (RED):

```rust
#[cfg(test)]
mod queue_row_tests {
    use super::*;
    use crate::tui::transfer::ledger::{Task, TaskId, TaskKind, TaskState};
    use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob, TransferOutcome};

    fn task(name: &str, state: TaskState, recursive: bool) -> Task {
        Task {
            id: TaskId(0),
            kind: if recursive { TaskKind::Folder } else { TaskKind::File },
            job: TransferJob {
                direction: Direction::Upload,
                src: format!("/s/{name}").into(),
                dst: format!("/d/{name}").into(),
                name: name.into(),
                size_total: Some(100),
                recursive,
            },
            progress: None,
            state,
        }
    }

    fn text(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect::<Vec<_>>().join("")
    }

    #[test]
    fn queue_row_queued_shows_name_and_queued_label() {
        let t = task("photo.jpg", TaskState::Queued, false);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("photo.jpg"), "{s}");
        assert!(s.contains("queued"), "{s}");
    }

    #[test]
    fn queue_row_failed_shows_error_excerpt() {
        let t = task("old.log", TaskState::Done(TransferOutcome::Failed("no such file".into())), false);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("old.log"), "{s}");
        assert!(s.contains("failed"), "{s}");
        assert!(s.contains("no such file"), "{s}");
    }

    #[test]
    fn queue_row_inflight_shows_progress_percent() {
        let mut t = task("big.tar", TaskState::InFlight, false);
        t.progress = Some(Progress {
            name: "big.tar".into(),
            direction: Direction::Upload,
            bytes_done: 40,
            bytes_total: Some(100),
            rate_bps: Some(5),
            eta_secs: Some(12),
        });
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("big.tar"), "{s}");
        assert!(s.contains("40%"), "{s}");
    }

    #[test]
    fn queue_row_folder_shows_folder_label_when_indeterminate() {
        let t = task("src/", TaskState::Queued, true);
        let s = text(&queue_row(&t, 60, false));
        assert!(s.contains("folder"), "folder label: {s}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test transfer::render::queue_row_tests --no-run`
Expected: COMPILE ERROR — `queue_row` undefined.

- [ ] **Step 3: Implement `queue_row`**

In `src/tui/transfer/render.rs`, add (add `use crate::tui::transfer::ledger::{Task, TaskState};` at the top if not present):

```rust
/// Render one task as a single popup row: direction glyph + name (left) and a
/// state/progress label (right). `selected` bolds the name (the popup applies
/// its own accent to the whole row via the selected row's style). Pure.
pub fn queue_row(task: &crate::tui::transfer::ledger::Task, width: u16, selected: bool) -> Line<'static> {
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
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(glyph, name_style),
        Span::raw(" "),
        Span::styled(task.job.name.clone(), name_style),
    ];

    // Right-aligned state/progress label.
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
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let fill = (width as usize).saturating_sub(used + label.chars().count() + 1);
    let label_style = match &task.state {
        TaskState::Done(TransferOutcome::Failed(_)) => Style::new().fg(crate::tui::theme::DANGER),
        TaskState::Done(TransferOutcome::Ok) => Style::new().dim(),
        TaskState::Queued => Style::new().dim(),
        _ => Style::new(),
    };
    spans.push(Span::raw(" ".repeat(fill)));
    spans.push(Span::styled(label, label_style));
    Line::from(spans)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test transfer::render::queue_row_tests`
Expected: PASS.

- [ ] **Step 5: Create `QueueOverlay` (view + nav only)**

Create `src/tui/transfer/queue_overlay.rs`:

```rust
//! The `^Q` queue-manager overlay: a modal list of every transfer task with
//! per-task progress/status. Lives inside [`TransferScreen`] (the transfer
//! screen bypasses `App::overlay` — see `app.rs` Layer-0 — so it owns its own
//! overlay the way the wizards own their inner popups).
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
            TaskState::Done(TransferOutcome::Failed(_)) | TaskState::Done(TransferOutcome::Cancelled)
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
    fn clamp(&mut self, ledger: &TransferLedger) {
        let n = selectable(ledger).len();
        if n == 0 {
            self.selected = 0;
        } else if self.selected >= n {
            self.selected = n - 1;
        }
    }

    /// Modal key router. Returns a [`ScreenOutcome`] for the loop side-effects;
    /// `Continue` for pure view/nav. Task 5 adds the operation arms.
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
    /// windowed around `selected` so the cursor stays visible on long queues.
    pub fn draw(&self, frame: &mut Frame, ledger: &TransferLedger) {
        let sel = selectable(ledger);
        let completed = ledger
            .tasks
            .iter()
            .filter(|t| matches!(t.state, TaskState::Done(sshrack_core::connect::sftp::proto::TransferOutcome::Ok)))
            .count();
        // Body rows = selectable rows + (1 if any completed) — capped by the
        // dialog chrome (MAX_H minus border+blank+footer).
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
        let body = dialog::draw_dialog(frame, &header, body_rows, &[
            ("↑↓", "select"),
            ("Esc", "close"),
        ]);

        // Window: keep `selected` in view within `body.height` rows over the
        // selectable list, then append the completed-count row.
        let max_rows = body.height as usize;
        let sel_len = sel.len();
        let half = max_rows.div_ceil(2).saturating_sub(1);
        let start = self.selected.saturating_sub(half).min(sel_len.saturating_sub(1));
        let window: Vec<usize> = sel.iter().copied().skip(start).take(max_rows).collect();
        let mut rows: Vec<(usize, bool)> =
            window.into_iter().enumerate().map(|(i, ti)| (ti, start + i == self.selected)).collect();

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
            if (y - body.y) as u16 >= body.height {
                break;
            }
        }
        if completed > 0 && (y - body.y) as u16 < body.height {
            let area = Rect::new(body.x, y, body.width, 1);
            frame.render_widget(
                Paragraph::new(format!("> {completed} completed")).style(ratatui::style::Style::new().dim()),
                area,
            );
        }
    }
}
```

- [ ] **Step 6: Register the module + add the field + wire `on_key` + draw**

In `src/tui/transfer/mod.rs`, add:
```rust
pub mod queue_overlay;
```

In `src/tui/transfer/screen.rs`:
- Add the import `use crate::tui::transfer::queue_overlay::QueueOverlay;`.
- Add a field to `TransferScreen`:
  ```rust
    /// The `^Q` queue-manager modal. `None` when closed. Owned here (not as an
    /// `App::overlay`) because the transfer screen bypasses the overlay stack.
    pub queue_overlay: Option<QueueOverlay>,
  ```
  and init `queue_overlay: None,` in `new`.
- At the TOP of `on_key` (right after the `if key.kind != KeyEventKind::Press` early return), add overlay routing:
  ```rust
        // The queue-manager overlay is modal: when open it owns every key.
        if let Some(mut ov) = self.queue_overlay.take() {
            let out = ov.on_key(key, &self.ledger);
            if !ov.closed {
                self.queue_overlay = Some(ov);
            }
            return out;
        }
  ```
- In the `match key.code` body, add a `^Q` arm BEFORE the `_ => self.route_to_focused(key)` arm:
  ```rust
            // Ctrl-Q toggles the queue-manager overlay. (Bare `q`/`Q` stay
            // bound to the pane search box per the no-bare-hotkey invariant.)
            KeyCode::Char('q') if ctrl => {
                self.queue_overlay.get_or_insert(QueueOverlay::new());
                ScreenOutcome::Continue
            }
  ```
- At the END of `draw` (after `self.draw_footer(...)`), add:
  ```rust
        if let Some(ov) = &self.queue_overlay {
            ov.draw(frame, &self.ledger);
        }
  ```

- [ ] **Step 7: Write open/close/nav + render tests**

In `src/tui/transfer/screen_tests.rs`, add:
```rust
#[test]
fn ctrl_q_opens_the_queue_overlay() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    assert!(screen.queue_overlay.is_none());
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(screen.queue_overlay.is_some(), "^Q must open the overlay");
}

#[test]
fn bare_q_does_not_open_the_overlay_it_feeds_the_query() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()));
    assert!(screen.queue_overlay.is_none(), "bare q must reach the search box");
}

#[test]
fn esc_closes_the_overlay_instead_of_the_screen() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    // Open, then Esc.
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(out, ScreenOutcome::Continue, "Esc inside the overlay must NOT CloseTransfer");
    assert!(screen.queue_overlay.is_none(), "Esc must close the overlay");
}

#[test]
fn arrow_keys_move_the_overlay_selection() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/b"),
        dst: local_cwd.join("b"),
        name: "b".into(),
        size_total: Some(1),
        recursive: false,
    });
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    // selected moved 0 -> 1; pressing Up returns to 0 (no observable field is
    // pub, so assert via a render smoke that both names appear and nothing
    // panics).
    let _ = screen.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "overlay draw must not panic: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(view.contains("transfer queue"), "overlay title missing: {view}");
}
```

- [ ] **Step 8: Run the transfer suite + clippy + fmt**

Run: `cargo test transfer && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: PASS + green.

- [ ] **Step 9: Commit**

```bash
git add src/tui/transfer/queue_overlay.rs src/tui/transfer/mod.rs src/tui/transfer/render.rs src/tui/transfer/screen.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(transfer): add ^Q queue-manager overlay (view + navigation)"
```

---

## Task 5: Queue-manager operations — retry / remove / cancel / pause

**Goal:** Wire the overlay's operation keys to ledger mutations + loop side-effects. `r`/`Enter` retries a failed/cancelled task; `Del`/`d` removes a task (queued/done) or cancels the in-flight one; `c` cancels the in-flight task; `p` toggles the queue-level pause.

**Files:**
- Modify: `src/tui/transfer/queue_overlay.rs` — add operation arms to `on_key`; widen the footer hints.
- Modify: `src/tui/transfer/screen_tests.rs` — operation tests.

**Interfaces:**
- Consumes: `TransferLedger::{retry, remove, toggle_paused, is_paused, pending_count, has_inflight}`, `ScreenOutcome::{Enqueue, CancelActive, Continue}`, `TaskId`.
- Produces: no new public API — `on_key` now returns `Enqueue` (retry / resume-after-pause) and `CancelActive` (cancel in-flight) so the existing `route_transfer` mapping drives the loop. **No `run_loop` change needed** (verify in Step 5).

- [ ] **Step 1: Write the failing operation tests**

In `src/tui/transfer/screen_tests.rs`, add:
```rust
#[test]
fn overlay_retry_requeues_a_failed_task_and_signals_advance() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    let id = screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.finish_inflight(sshrack_core::connect::sftp::proto::TransferOutcome::Failed("boom".into()));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open
    let out = screen.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty())); // retry selected
    assert_eq!(out, ScreenOutcome::Enqueue, "retry must signal advance-if-idle");
    assert!(matches!(screen.ledger.tasks.iter().find(|t| t.id == id).unwrap().state,
        crate::tui::transfer::ledger::TaskState::Queued),
        "failed task is queued again");
}

#[test]
fn overlay_remove_drops_a_queued_task() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    let before = screen.ledger.total();
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::empty()));
    assert_eq!(out, ScreenOutcome::Continue, "remove is a pure ledger mutation");
    assert_eq!(screen.ledger.total(), before - 1, "task removed");
}

#[test]
fn overlay_cancel_on_inflight_signals_cancel_active() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch(); // InFlight
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()));
    assert_eq!(out, ScreenOutcome::CancelActive, "cancel on in-flight must kill the worker");
}

#[test]
fn overlay_pause_toggles_the_ledger_flag() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(screen.ledger.is_paused());
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(!screen.ledger.is_paused());
}

#[test]
fn overlay_resume_with_pending_and_idle_signals_advance() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.set_paused(true);
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty())); // resume
    assert_eq!(out, ScreenOutcome::Enqueue, "resume with pending + idle must advance");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test transfer::screen::tests::overlay --no-run` (or `cargo test transfer --no-run`)
Expected: failures — `Enter`/`Delete`/`c`/`p` currently return `Continue` and do nothing.

- [ ] **Step 3: Add the operation arms + a TaskId resolution helper**

In `src/tui/transfer/queue_overlay.rs`, add a helper that resolves `selected` → the `TaskId` (and the task index) it points at:
```rust
    /// Resolve the selected row to its task index in `ledger.tasks` (None when
    /// the selectable list is empty).
    fn selected_task_index(&self, ledger: &TransferLedger) -> Option<usize> {
        selectable(ledger).get(self.selected).copied()
    }
```

Extend `on_key`'s `match` with the operation arms (the helper now takes `&mut ledger`, so change the signature to `pub fn on_key(&mut self, key: KeyEvent, ledger: &mut TransferLedger) -> ScreenOutcome`). Replace the `_ => ScreenOutcome::Continue` with the operation arms BEFORE it:

```rust
            KeyCode::Enter | KeyCode::Char('r') => {
                // Retry the selected failed/cancelled task.
                if let Some(ti) = self.selected_task_index(ledger) {
                    let id = ledger.tasks[ti].id;
                    if ledger.retry(id) {
                        return ScreenOutcome::Enqueue;
                    }
                }
                ScreenOutcome::Continue
            }
            KeyCode::Delete | KeyCode::Char('d') => {
                // Remove the selected task. If it is in-flight, defer to the
                // worker-cancel path (the loop kills the worker; the ledger
                // task moves to Done(Cancelled) when Done arrives).
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
            KeyCode::Char('c') => {
                // Cancel: only meaningful on the in-flight task.
                if let Some(ti) = self.selected_task_index(ledger) {
                    if matches!(ledger.tasks[ti].state, TaskState::InFlight) {
                        return ScreenOutcome::CancelActive;
                    }
                    // On a queued/done task, fall through to remove.
                    let id = ledger.tasks[ti].id;
                    ledger.remove(id);
                    self.clamp(ledger);
                }
                ScreenOutcome::Continue
            }
            KeyCode::Char('p') => {
                ledger.toggle_paused();
                // Resuming a paused queue with pending work and nothing in
                // flight must restart dispatch — signal Enqueue (advance-if-idle).
                if !ledger.is_paused() && ledger.pending_count() > 0 && !ledger.has_inflight() {
                    ScreenOutcome::Enqueue
                } else {
                    ScreenOutcome::Continue
                }
            }
            _ => ScreenOutcome::Continue,
```

Update the footer hints in `draw` to advertise the operations:
```rust
        let body = dialog::draw_dialog(frame, &header, body_rows, &[
            ("↑↓", "select"),
            ("⏎", "retry"),
            ("Del", "remove"),
            ("c", "cancel"),
            ("p", "pause"),
            ("Esc", "close"),
        ]);
```

Finally, update the `on_key` call site in `screen.rs` — the overlay now mutably borrows the ledger. Replace the Task-4 overlay block (`if let Some(mut ov) = self.queue_overlay.take() { … }`) with a panic-free form (no `unwrap()` — `Option::is_some` + `take` + a dead-but-safe `None` arm):
```rust
        if self.queue_overlay.is_some() {
            let mut ov = match self.queue_overlay.take() {
                Some(ov) => ov,
                None => return ScreenOutcome::Continue,
            };
            let out = ov.on_key(key, &mut self.ledger);
            if !ov.closed {
                self.queue_overlay = Some(ov);
            }
            return out;
        }
```
(The `None` arm is unreachable — the `is_some` gate just proved `Some` — but the compiler can not prove it, so the arm stays panic-free rather than `unwrap()`.)

- [ ] **Step 4: Run the operation tests**

Run: `cargo test transfer::screen::tests::overlay`
Expected: PASS — all five operation tests green.

- [ ] **Step 5: Verify no `run_loop` change is needed**

The overlay returns only existing `ScreenOutcome` variants (`Continue` / `Enqueue` / `CancelActive`), all already mapped by `route_transfer` in `app.rs`:
- `Enqueue` → `if !screen.has_inflight() { pending_advance = true }` → `dispatch_next_job` → `screen.next_job()` → `ledger.next_to_dispatch()` (respects `paused`, skips `Done`) → dispatches the retried / resumed task. ✓
- `CancelActive` → `pending_cancel = true` → drain sends `WorkerCmd::Cancel` → worker kills → `WorkerEvent::Done(Cancelled)` → `finish_inflight(Cancelled)`. ✓
- `Continue` → no side effect (retry-of-non-retryable, remove, pause-stay-paused). ✓

Run: `cargo test transfer && cargo test run_loop::tests`
Expected: PASS. If any `run_loop` test breaks, fix it (none expected — the drain path is unchanged from Task 2).

- [ ] **Step 6: Clippy + fmt**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: green. Remove the now-unused `Rect`/`Paragraph` import in `queue_overlay.rs` if the operation arms made them unused (they are still used by `draw`, so likely retained — verify).

- [ ] **Step 7: Commit**

```bash
git add src/tui/transfer/queue_overlay.rs src/tui/transfer/screen.rs src/tui/transfer/screen_tests.rs
git commit -m "feat(transfer): wire queue-overlay retry/remove/cancel/pause operations"
```

---

## Task 6: Docs + footer `^Q` hint + final polish

**Goal:** Document the queue manager in `docs/sftp.md` + `CLAUDE.md`, add `^Q` to the main-screen footer, and run the whole-workspace gate.

**Files:**
- Modify: `src/tui/transfer/screen.rs` — add `^Q` to the footer `hints`.
- Modify: `docs/sftp.md` — queue-manager section.
- Modify: `CLAUDE.md` — `^Q` in the SFTP transfer keys table.

- [ ] **Step 1: Add `^Q` to the main-screen footer**

In `src/tui/transfer/screen.rs` `draw_footer`, add the hint to the `hints` slice (after `("^S", "transfer")`):
```rust
            ("^Q", "queue"),
```

- [ ] **Step 2: Document in `docs/sftp.md`**

Append a "## Queue manager (`^Q`)" section to `docs/sftp.md` describing: the 2-row status band (`done X/Y · fail Z [· paused]` + active transfer row); `^Q` opens the modal; the row states (in-flight / queued / failed / cancelled / completed); the operations (`⏎`/`r` retry, `Del`/`d` remove, `c` cancel, `p` pause) and the honest scope notes: pause is queue-level (the current file finishes first); retry re-transfers from byte 0 (no resume); folders are indeterminate in the MVP.

- [ ] **Step 3: Update `CLAUDE.md`**

In `CLAUDE.md`'s "SFTP Transfer Keys" table, add a row:
```
| `^Q` | open the queue-manager overlay (retry / remove / cancel / pause) |
```

- [ ] **Step 4: Whole-workspace gate**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add src/tui/transfer/screen.rs docs/sftp.md CLAUDE.md
git commit -m "docs(transfer): document the ^Q queue manager + add footer hint"
```

---

## Notes for the executor (controller-side)

- **Branch:** create `feat/sftp-queue-manager` from `main` before Task 1 (do not implement on `main`).
- **Per-task gate:** implementer runs the task's tests + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt` before reporting DONE.
- **No `Co-Authored-By`** trailer on any commit. **Explicit `git add <paths>`**, never `git add -A`.
- **Task 2 is the load-bearing refactor.** Its safety net is the existing `screen_tests` + `run_loop` tests; behavior must be byte-identical (same panel output, same drain/dispatch semantics) except where this plan says otherwise.
- **`#[allow(dead_code)]` discipline:** Task 1's ledger items carry scoped allows naming "Task 2" — Task 2 MUST remove them once the screen consumes the API (clippy will flag any remaining as unused once consumed elsewhere; verify none linger).
