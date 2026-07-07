//! Pure transfer-task ledger: the single source of truth for the queue-manager
//! popup and the status-bar counters. UI-side projection of the worker's
//! `TransferJob` / `Progress` / `TransferOutcome` stream — no I/O, no worker
//! dependency. Mutated by the run-loop from drained `WorkerEvent`s.

use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob, TransferOutcome};

/// Stable id for a task. The popup selects by display index but operations
/// resolve through this id so a mutation + re-render can not mis-target a row
/// that shifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub usize);

/// Display flavor of a task. `Folder` tasks are indeterminate in the MVP
/// (Phase 2 expands them to per-file tasks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    File,
    Folder,
}

/// Lifecycle of a task. Concurrency is 1, so at most one task is `InFlight`.
//
// `TransferOutcome` (in `sshrack-core`) is only `Debug + Clone` (no
// `PartialEq`/`Eq`), so deriving either trait here fails to compile. No call
// site compares `TaskState` with `==` — every site uses `matches!` — so
// dropping both derives is the minimal behavior-preserving fix.
#[derive(Debug, Clone)]
pub enum TaskState {
    Queued,
    InFlight,
    Done(TransferOutcome),
}

/// One tracked transfer. `progress` is `Some` only while `InFlight`.
#[derive(Debug, Clone)]
pub struct Task {
    pub id: TaskId,
    /// Display flavor (File/Folder). Read by `render::queue_row` to label
    /// indeterminate folder tasks in the queue overlay.
    pub kind: TaskKind,
    pub job: TransferJob,
    pub progress: Option<Progress>,
    pub state: TaskState,
}

/// The transfer ledger. Owns every task (queued + in-flight + recent history)
/// and the queue-level pause flag. Counters are derived, never stored.
#[derive(Debug, Clone, Default)]
pub struct TransferLedger {
    /// Insertion-ordered. FIFO dispatch walks this for the head `Queued` task.
    pub tasks: Vec<Task>,
    next_id: usize,
    paused: bool,
}

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
        let kind = if job.recursive {
            TaskKind::Folder
        } else {
            TaskKind::File
        };
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
        self.tasks
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.job.clone())
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
        if let Some(id) = self.inflight_id()
            && let Some(t) = self.tasks.iter_mut().find(|t| t.id == id)
        {
            t.progress = Some(p);
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
            TaskState::Done(TransferOutcome::Failed(_))
                | TaskState::Done(TransferOutcome::Cancelled)
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
        self.tasks
            .retain(|t| !matches!(t.state, TaskState::InFlight));
    }

    /// Queue-level pause flag.
    pub fn is_paused(&self) -> bool {
        self.paused
    }
    #[allow(dead_code)] // test-only setter; production toggles via toggle_paused
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
        assert_eq!(
            l.tasks.iter().find(|t| t.id == f).unwrap().kind,
            TaskKind::File
        );
        assert_eq!(
            l.tasks.iter().find(|t| t.id == d).unwrap().kind,
            TaskKind::Folder
        );
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
        l.enqueue(job("a", Direction::Upload, false));
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
        assert!(matches!(
            l.tasks.iter().find(|t| t.id == a).unwrap().state,
            TaskState::Queued
        ));
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
        assert!(
            !l.remove(a),
            "inflight task not removable here (worker-cancel path)"
        );
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
        assert_eq!(
            l.last_direction(),
            Some(Direction::Upload),
            "falls back to most-recent Done"
        );
        assert_eq!(TransferLedger::new().last_direction(), None);
    }
}
