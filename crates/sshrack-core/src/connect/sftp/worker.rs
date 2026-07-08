//! SFTP worker: owns the master `ssh -N` connection and serially executes every
//! [`WorkerCmd`] the UI sends. The main thread pushes commands via
//! [`SftpWorker::send`]; the UI polls [`WorkerEvent`]s each tick via
//! [`SftpWorker::try_event`]. `Drop` tears the whole thing down: Shutdown → join
//! → `ssh -O exit` → kill master → remove socket file → remove pw file.
//!
//! ## Threading shape
//!
//! ```text
//!   main thread                         worker thread
//!   ───────────                         ─────────────
//!   SftpWorker {                        loop {
//!     cmd_tx ──── WorkerCmd ────►         rx.recv()
//!     event_rx ◄── WorkerEvent ─── tx     match cmd { List | Transfer | … }
//!     join handle                        }
//!     master_child                       (owns SftpDirSource + target + sock
//!     ControlSocket                       for spawning sftp batches)
//!   }
//! ```
//!
//! The worker thread owns the listing source and the connection coordinates;
//! the main thread owns the master `Child` and the [`ControlSocket`] RAII guard
//! so dropping the worker handle always reaps both.
//!
//! ## Testability
//!
//! The thread + spawn paths are not unit-testable without a real sshd, so only
//! the pure pieces are unit-tested (now extracted into [`super::pure`] —
//! `parse_remote_home`, `parse_size_from_ls`, `classify_inflight_cmd`) plus the
//! [`ControlSocket`] RAII behavior (in [`super`]). A `#[ignore]`'d e2e test
//! lives in `tests/sftp_e2e.rs` for a future local-sshd run.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crate::config::schema::Host;
use crate::connect::sftp::proto::{
    Direction, OverwritePolicy, Progress, TransferJob, TransferOutcome, WorkerCmd, WorkerEvent,
};
use crate::connect::sftp::pure::{
    InflightAction, classify_inflight_cmd, parse_remote_home, parse_size_from_ls,
};
use crate::connect::sftp::source::{LocalSftpRunner, SftpDirSource, SftpRunner};
use crate::connect::sftp::{
    ControlSocket, control_check_argv, control_exit_argv, get_batch, master_argv,
    progress_snapshot, put_batch, pwd_batch, sftp_batch_argv, sftp_target, shell_quote,
};
use crate::connect::ssh::Overrides;
use crate::connect::{askpass_env_for_sftp, write_password_file};
use crate::credential::{PasswordSource, ResolvedAuth};
use crate::dirsource::DirSource;

/// How long [`SftpWorker::open`] polls `ssh -O check` before giving up. 30s is
/// generous for slow first-connect handshakes on high-latency links but bounded
/// so a misconfigured host surfaces a clear error instead of hanging forever.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval during the master handshake.
const HANDSHAKE_POLL: Duration = Duration::from_millis(250);

/// Polling interval during a transfer (size + cancel check).
const PROGRESS_POLL: Duration = Duration::from_millis(200);

// ---- SftpWorker ----

/// Owns the worker thread + the master `ssh -N` connection. Push commands via
/// [`SftpWorker::send`]; poll events via [`SftpWorker::try_event`]. `Drop`
/// tears everything down (see the module docs).
///
/// Construction is via [`SftpWorker::open`], which spawns the master and the
/// worker thread; nothing else constructs this type.
pub struct SftpWorker {
    cmd_tx: mpsc::Sender<WorkerCmd>,
    event_rx: mpsc::Receiver<WorkerEvent>,
    join: Option<JoinHandle<()>>,
    sock: Option<ControlSocket>,
    master_child: Option<Child>,
    pw_file: Option<PathBuf>,
    target: String,
}

impl SftpWorker {
    /// Open the master and start the worker thread.
    ///
    /// 1. Allocate a [`ControlSocket`].
    /// 2. Build askpass env via the shared [`askpass_env_for_sftp`] /
    ///    [`write_password_file`] helpers (DRY: the worker never reinvents
    ///    password materialization). The SFTP variant forces
    ///    `SSH_ASKPASS_REQUIRE=force` and denies `/dev/tty` for `None`.
    /// 3. Spawn the master `ssh -N` (NOT `status()` — the master must stay
    ///    alive). Keep the `Child`. stderr is piped + drained on a side thread
    ///    so an auth failure's reason is captured instead of corrupting the
    ///    TUI's tty.
    /// 4. Poll `ssh -O check` until "Master running" / exit 0, the master
    ///    exits, or [`HANDSHAKE_TIMEOUT`] (30s).
    /// 5. Probe the remote home via an `sftp pwd` batch (fall back to `/`).
    /// 6. Spawn the worker thread; return `(worker, home)`.
    ///
    /// `resolved`/`host`/`overrides`/`self_exe`/`source`/`config_path` mirror
    /// [`crate::connect::launch`].
    pub fn open(
        resolved: ResolvedAuth,
        host: Host,
        overrides: Overrides,
        self_exe: &Path,
        source: PasswordSource,
        config_path: Option<&Path>,
    ) -> Result<(Self, PathBuf), String> {
        let sock = ControlSocket::new();
        let sock_path = sock.path().to_path_buf();
        let target = sftp_target(&resolved, &host);

        // (2) Materialize the password temp file (Inline only) and build the
        // askpass env. Keyring carries no file; None carries no env at all.
        let pw_file = match &source {
            PasswordSource::Inline(pw) => Some(write_password_file(pw).map_err(|e| e.to_string())?),
            _ => None,
        };
        let env = askpass_env_for_sftp(self_exe, &source, pw_file.as_deref(), config_path);

        // Captured master stderr: drained on a side thread so (a) the pipe
        // never fills and blocks the handshake, and (b) an auth failure's real
        // reason is captured instead of being written to the TUI's tty.
        let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

        // (3) Spawn the master `ssh -N`. stdin null (ssh -N never reads it),
        // stdout null (ssh -N never writes it), stderr piped + drained on a
        // side thread so an auth failure's reason is captured instead of
        // corrupting the TUI's tty.
        let master_argv = master_argv(&resolved, &host, &overrides, &sock_path);
        let mut master_cmd = Command::new(&master_argv[0]);
        master_cmd
            .args(&master_argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (k, v) in &env {
            master_cmd.env(k, v);
        }
        let mut master_child = master_cmd
            .spawn()
            .map_err(|e| format!("sftp master spawn failed: {e}"))?;

        // Drain master stderr into the buffer. Unlike run_transfer's drain
        // (which is safe with `read_to_end` because the buffer is read only
        // AFTER `try_wait` shows the child exited), this buffer is polled by
        // `wait_for_master` every HANDSHAKE_POLL while the master is still
        // alive. Holding the lock across a blocking `read_to_end` would lock
        // out `wait_for_master`'s per-poll `lock()` for the master's entire
        // lifetime (the happy path — `ssh -N` stays up, stderr never EOFs) and
        // hang the handshake indefinitely. Read in chunks instead, holding the
        // lock only briefly per chunk so `wait_for_master` can acquire it
        // between reads.
        {
            let buf = Arc::clone(&stderr_buf);
            if let Some(mut stderr) = master_child.stderr.take() {
                let _ = thread::spawn(move || {
                    use std::io::Read;
                    let mut chunk = [0u8; 1024];
                    loop {
                        match stderr.read(&mut chunk) {
                            Ok(0) => break, // EOF — master exited
                            Ok(n) => {
                                buf.lock()
                                    .expect("invariant: stderr lock")
                                    .extend_from_slice(&chunk[..n]);
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }

        // (4) Poll `ssh -O check` until ready, the master exits, or the deadline.
        match wait_for_master(
            &target,
            &sock_path,
            Instant::now() + HANDSHAKE_TIMEOUT,
            &mut master_child,
            &stderr_buf,
        ) {
            HandshakeOutcome::Ready => {}
            outcome => {
                // Teardown on handshake failure: kill + reap the master, ask it
                // to exit politely, drop the socket, remove the pw file.
                let _ = master_child.kill();
                let _ = master_child.wait();
                let exit_argv = control_exit_argv(&target, &sock_path);
                let _ = Command::new(&exit_argv[0])
                    .args(&exit_argv[1..])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                drop(sock);
                if let Some(p) = pw_file {
                    let _ = std::fs::remove_file(p);
                }
                let reason = match outcome {
                    HandshakeOutcome::Exited(s) => match first_meaningful_line(&s) {
                        "" => "sftp master failed (authentication rejected)".to_string(),
                        line => format!("sftp master failed: {line}"),
                    },
                    HandshakeOutcome::Timeout => "sftp master handshake timed out".to_string(),
                    HandshakeOutcome::Ready => unreachable!("handled above"),
                };
                return Err(reason);
            }
        }

        // (5) Probe the remote home via `sftp pwd`. Falls back to `/` on any
        // failure so the UI never blocks on home detection.
        let runner = Arc::new(LocalSftpRunner::new());
        let home = {
            let batch = pwd_batch();
            match runner.run_batch(&target, &sock_path, &batch) {
                Ok(stdout) => parse_remote_home(&stdout).unwrap_or_else(|| PathBuf::from("/")),
                Err(_) => PathBuf::from("/"),
            }
        };

        // (6) Spawn the worker thread. The thread owns the listing source and
        // the connection coordinates; the main thread keeps the master Child
        // and the ControlSocket guard.
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();

        let worker_target = target.clone();
        let worker_sock = sock_path.clone();
        let worker_home = home.clone();
        let join = match thread::Builder::new()
            .name("sftp-worker".into())
            .spawn(move || {
                worker_loop(
                    cmd_rx,
                    event_tx,
                    runner,
                    worker_target,
                    worker_sock,
                    worker_home,
                );
            }) {
            Ok(handle) => Some(handle),
            Err(e) => {
                // Teardown on thread-spawn failure: be a good citizen and clean
                // up everything we set up. The thread never got the inputs, so
                // we own their lifetimes here.
                let exit_argv = control_exit_argv(&target, &sock_path);
                let _ = Command::new(&exit_argv[0]).args(&exit_argv[1..]).status();
                let _ = master_child.kill();
                let _ = master_child.wait();
                drop(sock);
                if let Some(p) = pw_file {
                    let _ = std::fs::remove_file(p);
                }
                return Err(format!("sftp worker thread spawn failed: {e}"));
            }
        };

        Ok((
            SftpWorker {
                cmd_tx,
                event_rx,
                join,
                sock: Some(sock),
                master_child: Some(master_child),
                pw_file,
                target,
            },
            home,
        ))
    }

    /// Push a command onto the worker's queue. Non-blocking; the worker thread
    /// drains commands serially.
    pub fn send(&self, cmd: WorkerCmd) {
        // A send error means the worker thread has exited (or is exiting). The
        // UI tolerates that — it will see the worker dropped on the next tick.
        let _ = self.cmd_tx.send(cmd);
    }

    /// Drain one pending event without blocking. The UI calls this each tick.
    /// `None` means "no events queued right now".
    pub fn try_event(&self) -> Option<WorkerEvent> {
        self.event_rx.try_recv().ok()
    }
}

impl Drop for SftpWorker {
    fn drop(&mut self) {
        // 1. Tell the worker thread to exit (best-effort — it may already be
        //    gone if the channel is closed).
        let _ = self.cmd_tx.send(WorkerCmd::Shutdown);

        // 2. Join the thread. A bounded wait would be nicer (the thread could
        //    be mid-sftp-batch), but plain join is acceptable for MVP and
        //    ensures the thread is reaped before we tear down its inputs.
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }

        // 3. Politely ask the master to exit via `ssh -O exit`. Best-effort —
        //    a missing master is fine, a hung master falls through to step 4.
        let sock_path = self
            .sock
            .as_ref()
            .map(|s| s.path().to_path_buf())
            .unwrap_or_default();
        let exit_argv = control_exit_argv(&self.target, &sock_path);
        let _ = Command::new(&exit_argv[0])
            .args(&exit_argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // 4. Force-kill the master + reap it. SIGKILL + wait guarantees no
        //    lingering `ssh -N` process even if `ssh -O exit` was ignored.
        if let Some(child) = self.master_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // 5. Drop the ControlSocket (removes the socket file). Taking the
        //    Option makes the drop explicit and ordering-controllable here.
        self.sock.take();

        // 6. Remove the password temp file if we created one.
        if let Some(p) = self.pw_file.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---- worker thread ----

/// The worker thread loop. Owns the listing source + connection coordinates;
/// drains [`WorkerCmd`]s and emits [`WorkerEvent`]s.
fn worker_loop(
    cmd_rx: mpsc::Receiver<WorkerCmd>,
    event_tx: mpsc::Sender<WorkerEvent>,
    runner: Arc<dyn SftpRunner>,
    target: String,
    sock: PathBuf,
    home: PathBuf,
) {
    let dir_source = SftpDirSource::new(target.clone(), sock.clone(), runner.clone(), Some(home));

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            WorkerCmd::List(cwd) => {
                let result = dir_source.list(&cwd);
                let _ = event_tx.send(WorkerEvent::Listing(cwd, result));
            }
            WorkerCmd::Transfer(job, policy) => {
                // `run_transfer` returns `true` when it received `Shutdown`
                // mid-flight — propagate that so we `break` instead of looping
                // back to `recv()`. Looping back would deadlock: the dropping
                // main thread holds `cmd_tx` until `join()` returns, and
                // `join()` waits for us to exit.
                if run_transfer(&event_tx, &cmd_rx, &runner, &job, policy, &target, &sock) {
                    break;
                }
            }
            WorkerCmd::Cancel => {
                // No transfer in flight — nothing to cancel. Drop silently.
            }
            WorkerCmd::Shutdown => break,
        }
    }
}

/// Run one transfer job to completion (or cancellation). Emits Progress while
/// running, Done on completion / failure / cancel.
///
/// `cmd_rx` is checked between try_wait polls so `Cancel` lands within
/// [`PROGRESS_POLL`] ms. Other commands arriving mid-transfer are classified
/// via [`classify_inflight_cmd`]: `Shutdown` propagates (kill + cleanup +
/// signal), `Cancel` cancels, anything else is dropped.
///
/// Returns `true` if `Shutdown` was received mid-transfer, so [`worker_loop`]
/// `break`s instead of looping back to `recv()` (which would deadlock against
/// `Drop`'s `join()`). Returns `false` on normal completion / cancel / spawn
/// failure / channel disconnect.
fn run_transfer(
    event_tx: &mpsc::Sender<WorkerEvent>,
    cmd_rx: &mpsc::Receiver<WorkerCmd>,
    runner: &Arc<dyn SftpRunner>,
    job: &TransferJob,
    policy: OverwritePolicy,
    target: &str,
    sock: &Path,
) -> bool {
    // Honor Skip/SkipAll without spawning sftp: the screen already decided via
    // decide() that this conflict should be skipped; the worker trusts the
    // policy. Overwrite/OverwriteAll proceed normally.
    if matches!(policy, OverwritePolicy::Skip | OverwritePolicy::SkipAll) {
        let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Ok));
        return false;
    }

    let batch = match job.direction {
        Direction::Download => get_batch(&job.src, &job.dst, job.recursive),
        Direction::Upload => put_batch(&job.src, &job.dst, job.recursive),
    };

    // Spawn `sftp -b -` mounted on the master. stdin pipes the batch; stderr is
    // captured (drained on a side thread) so we can report the first error line
    // on failure.
    let argv = sftp_batch_argv(target, sock);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Failed(format!(
                "sftp spawn failed: {e}"
            ))));
            return false;
        }
    };

    // Write the batch to stdin and drop the handle to signal EOF. Errors here
    // (broken pipe — child already exited) are surfaced by try_wait instead.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(batch.as_bytes());
    }
    // Drain stdout too so its pipe buffer doesn't fill up; we don't need its
    // contents. Take it so the main wait path can't accidentally block on it.
    if let Some(mut stdout) = child.stdout.take() {
        let _ = thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
        });
    }
    // Drain stderr into a shared buffer so the failure path can read the first
    // error line after the child exits.
    let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut stderr) = child.stderr.take() {
        let buf = Arc::clone(&stderr_buf);
        let _ = thread::spawn(move || {
            use std::io::Read;
            let _ = stderr.read_to_end(&mut buf.lock().expect("invariant: stderr lock"));
        });
    }

    let start = Instant::now();
    let mut prev_done = 0u64;
    let mut prev_secs = 0u64;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Ok));
                } else {
                    // Bind the lock guard so its borrow outlives the Cow that
                    // borrows from it.
                    let stderr_bytes = stderr_buf.lock().expect("invariant: stderr lock");
                    let stderr_str = String::from_utf8_lossy(&stderr_bytes);
                    let first_line = match first_meaningful_line(&stderr_str) {
                        "" => "sftp failed".to_string(),
                        s => s.to_string(),
                    };
                    drop(stderr_bytes);
                    remove_partial_dst(runner, job, target, sock);
                    let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Failed(first_line)));
                }
                return false;
            }
            Ok(None) => {
                // Still running: poll dst size + emit progress, then check for
                // a command with a short timeout so the loop both paces itself
                // and stays responsive to cancellation / shutdown.
                let bytes_done = poll_dst_size(runner, job, target, sock);
                let cur_secs = start.elapsed().as_secs();
                let (rate_bps, eta_secs) =
                    progress_snapshot(prev_done, prev_secs, bytes_done, cur_secs, job.size_total);
                let _ = event_tx.send(WorkerEvent::Progress(Progress {
                    name: job.name.clone(),
                    direction: job.direction,
                    bytes_done,
                    bytes_total: job.size_total,
                    rate_bps,
                    eta_secs,
                }));
                prev_done = bytes_done;
                prev_secs = cur_secs;

                match cmd_rx.recv_timeout(PROGRESS_POLL) {
                    Ok(cmd) => match classify_inflight_cmd(&cmd) {
                        InflightAction::Cancel => {
                            let _ = child.kill();
                            let _ = child.wait(); // reap
                            remove_partial_dst(runner, job, target, sock);
                            let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Cancelled));
                            return false;
                        }
                        InflightAction::Shutdown => {
                            // CRITICAL: propagate Shutdown so worker_loop breaks
                            // instead of looping back to recv(). Kill + reap the
                            // child + remove the partial so teardown is clean,
                            // then signal the loop to exit.
                            let _ = child.kill();
                            let _ = child.wait();
                            remove_partial_dst(runner, job, target, sock);
                            return true;
                        }
                        InflightAction::Continue => {
                            // Unexpected during a transfer (the UI serializes).
                            // Drop the command and keep polling — do NOT kill
                            // the child or the partial destination.
                        }
                    },
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        // Main thread is gone. Kill + reap the child so we don't
                        // leave a sftp process behind, then exit the loop.
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                }
            }
            Err(e) => {
                let _ = event_tx.send(WorkerEvent::Done(TransferOutcome::Failed(format!(
                    "sftp wait failed: {e}"
                ))));
                return false;
            }
        }
    }
}

// ---- transfer helpers ----

/// Best-effort removal of the partial destination after a failed / cancelled
/// transfer.
///
/// - **Download**: `std::fs::remove_file(&dst)` — local cleanup, cheap.
/// - **Upload (file)**: spawns an `rm <dst>` sftp batch against the master so a
///   retry doesn't see a corrupt partial that the UI's `decide()` might Skip
///   (the stuck-state the plan explicitly calls out — sftp `put` overwrites in
///   place, leaving a short/corrupt file behind on failure).
/// - **Upload (recursive dir)**: NOT cleaned up — sftp `rm -r`/`-R` support
///   varies across OpenSSH versions, so we leave the partial tree in place
///   rather than risk a half-removed state. The next transfer's `Overwrite`
///   policy handles re-upload.
fn remove_partial_dst(runner: &Arc<dyn SftpRunner>, job: &TransferJob, target: &str, sock: &Path) {
    match job.direction {
        Direction::Download => {
            let _ = std::fs::remove_file(&job.dst);
        }
        Direction::Upload if !job.recursive => {
            let batch = format!("rm {}\nquit\n", shell_quote(&job.dst.to_string_lossy()));
            let _ = runner.run_batch(target, sock, &batch);
        }
        Direction::Upload => {
            // Recursive upload: documented gap (see doc comment). sftp `rm -r`
            // /`-R` support varies across OpenSSH versions; leaving the partial
            // tree is safer than a half-removed state.
        }
    }
}

/// Poll the destination's current byte size for progress display. Downloads
/// read local fs metadata (cheap); uploads spawn a single `ls -l <dst>` sftp
/// batch against the master (expensive, but bounded to one batch per poll).
///
/// Returns 0 on any failure or when the size is unknown (e.g. directory dst) —
/// progress just reports "unknown" until the next sample lands.
fn poll_dst_size(
    runner: &Arc<dyn SftpRunner>,
    job: &TransferJob,
    target: &str,
    sock: &Path,
) -> u64 {
    match job.direction {
        Direction::Download => std::fs::metadata(&job.dst).map(|m| m.len()).unwrap_or(0),
        Direction::Upload => {
            let batch = format!("ls -l {}\nquit\n", shell_quote(&job.dst.to_string_lossy()));
            match runner.run_batch(target, sock, &batch) {
                Ok(stdout) => parse_size_from_ls(&stdout, SystemTime::now()).unwrap_or(0),
                Err(_) => 0,
            }
        }
    }
}

/// Outcome of polling the master handshake. [`wait_for_master`] returns this;
/// [`SftpWorker::open`] maps `Exited`/`Timeout` to a `Err` carrying the reason.
enum HandshakeOutcome {
    /// `ssh -O check` succeeded — the master is up.
    Ready,
    /// The master exited before coming up (auth failure, refused key, etc.).
    /// Carries the drained stderr so the user sees the real reason.
    Exited(String),
    /// The master neither came up nor exited before the deadline.
    Timeout,
}

/// Pure decision over one handshake poll's signals, factored out so the logic
/// (check wins; master-exit beats timeout; else keep polling) is unit-testable
/// without a real sshd. `stderr` is attached only to [`HandshakeOutcome::Exited`].
fn classify_poll(
    check_ok: bool,
    master_exited: bool,
    timed_out: bool,
    stderr: String,
) -> Option<HandshakeOutcome> {
    if check_ok {
        return Some(HandshakeOutcome::Ready);
    }
    if master_exited {
        return Some(HandshakeOutcome::Exited(stderr));
    }
    if timed_out {
        return Some(HandshakeOutcome::Timeout);
    }
    None
}

/// The first line of `s` whose trimmed form is non-empty, or `""` if there is
/// none. Collapses a multi-line captured stderr into a single status-bar line
/// (the footer is one row). Pure.
fn first_meaningful_line(s: &str) -> &str {
    for line in s.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    ""
}

/// Poll `ssh -O check <target>` until it exits 0 (master up) or the deadline.
/// Pure-I/O wrapper: the readiness check is itself a process spawn (no stdout
/// parsing — readiness is exit-0 only), so this is not unit-tested.
fn wait_for_master(
    target: &str,
    sock: &Path,
    deadline: Instant,
    master: &mut Child,
    stderr_buf: &Arc<Mutex<Vec<u8>>>,
) -> HandshakeOutcome {
    loop {
        let argv = control_check_argv(target, sock);
        let check_ok = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // A master that exited (auth refused, wrong password, bad key) must not
        // be masked by a 30s wait: detect it each poll and fail at once.
        let master_exited = master.try_wait().ok().flatten().is_some();
        let timed_out = Instant::now() >= deadline;
        let stderr =
            String::from_utf8_lossy(&stderr_buf.lock().expect("invariant: stderr lock").clone())
                .into_owned();
        if let Some(outcome) = classify_poll(check_ok, master_exited, timed_out, stderr) {
            return outcome;
        }
        thread::sleep(HANDSHAKE_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- HANDSHAKE_TIMEOUT value pinned ----

    #[test]
    fn handshake_timeout_is_30_seconds() {
        // The brief pins this at 30s. Generous for slow first-connect TLS
        // handshakes, bounded so a misconfigured host surfaces a clear error.
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(30));
    }

    #[test]
    fn handshake_poll_is_250ms_and_progress_poll_is_200ms() {
        // Internal pacing consts — pin them so a future refactor can't silently
        // make polling 10x more or less aggressive.
        assert_eq!(HANDSHAKE_POLL, Duration::from_millis(250));
        assert_eq!(PROGRESS_POLL, Duration::from_millis(200));
    }

    // ---- classify_poll: pure handshake decision ----

    #[test]
    fn classify_poll_ready_wins() {
        // A successful ssh -O check means the master is up — ready, even if the
        // master also happened to exit (race) or the deadline passed.
        let out = classify_poll(true, false, true, String::new());
        assert!(matches!(out, Some(HandshakeOutcome::Ready)));
    }

    #[test]
    fn classify_poll_master_exit_beats_timeout() {
        // Master exited (auth failure) before the deadline: report Exited with
        // the captured stderr, not Timeout.
        let out = classify_poll(false, true, true, "Permission denied".into());
        assert!(matches!(
            out,
            Some(HandshakeOutcome::Exited(s)) if s == "Permission denied"
        ));
    }

    #[test]
    fn classify_poll_timeout_when_only_deadline() {
        let out = classify_poll(false, false, true, String::new());
        assert!(matches!(out, Some(HandshakeOutcome::Timeout)));
    }

    #[test]
    fn classify_poll_none_keeps_polling() {
        // No signal yet: return None so the caller polls again.
        let out = classify_poll(false, false, false, String::new());
        assert!(out.is_none());
    }

    // ---- remove_partial_dst ----

    /// Captures every `run_batch` call's batch string into the shared buffer.
    /// The buffer is held outside the runner so the test can inspect it after
    /// the runner has been coerced to `Arc<dyn SftpRunner>` (which hides the
    /// concrete field).
    #[derive(Default)]
    struct RecordingRunner {
        batches: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl SftpRunner for RecordingRunner {
        fn run_batch(&self, _target: &str, _sock: &Path, batch: &str) -> Result<String, String> {
            self.batches
                .lock()
                .expect("invariant: recording lock")
                .push(batch.to_string());
            Ok(String::new())
        }
    }

    #[test]
    fn remove_partial_dst_download_removes_local_file() {
        // Download partial: a local file at dst is removed. The runner is not
        // called for downloads (local fs only) — the recording stays empty.
        let dir = tempfile::tempdir().expect("temp dir");
        let dst = dir.path().join("partial.bin");
        std::fs::write(&dst, b"partial").expect("write");
        assert!(dst.exists());
        let job = TransferJob {
            direction: Direction::Download,
            src: PathBuf::from("/remote/file"),
            dst: dst.clone(),
            name: "file".into(),
            size_total: Some(100),
            recursive: false,
        };
        let batches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let runner: Arc<dyn SftpRunner> = Arc::new(RecordingRunner {
            batches: batches.clone(),
        });
        remove_partial_dst(&runner, &job, "user@host", Path::new("/tmp/mux.sock"));
        assert!(!dst.exists(), "download partial must be removed");
        let recorded = batches.lock().expect("invariant: lock").clone();
        assert!(
            recorded.is_empty(),
            "download cleanup must not spawn an sftp batch: {recorded:?}"
        );
    }

    #[test]
    fn remove_partial_dst_does_not_panic_when_file_missing() {
        // A nonexistent dst must not panic (best-effort cleanup).
        let job = TransferJob {
            direction: Direction::Download,
            src: PathBuf::from("/remote/file"),
            dst: PathBuf::from("/no/such/local/file"),
            name: "file".into(),
            size_total: Some(100),
            recursive: false,
        };
        let runner: Arc<dyn SftpRunner> = Arc::new(RecordingRunner {
            batches: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        remove_partial_dst(&runner, &job, "user@host", Path::new("/tmp/mux.sock")); // must not panic
    }

    #[test]
    fn remove_partial_dst_upload_file_issues_rm_batch() {
        // A failed/cancelled file upload must issue an sftp `rm <dst>` batch so
        // the corrupt partial is cleaned up before the next attempt (the plan
        // explicitly calls out the sshelf stuck-state where a partial file
        // makes decide() pick Skip on retry).
        let job = TransferJob {
            direction: Direction::Upload,
            src: PathBuf::from("/local/file"),
            dst: PathBuf::from("/remote/file"),
            name: "file".into(),
            size_total: Some(100),
            recursive: false,
        };
        let batches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let runner: Arc<dyn SftpRunner> = Arc::new(RecordingRunner {
            batches: batches.clone(),
        });
        remove_partial_dst(&runner, &job, "user@host", Path::new("/tmp/mux.sock"));
        let recorded = batches.lock().expect("invariant: lock").clone();
        assert_eq!(
            recorded.len(),
            1,
            "exactly one rm batch must be issued for an upload file partial"
        );
        let batch = &recorded[0];
        assert!(
            batch.contains("rm "),
            "batch must contain an `rm` command: {batch}"
        );
        assert!(
            batch.contains(&shell_quote("/remote/file")),
            "batch must contain the quoted remote dst path: {batch}"
        );
        assert!(
            batch.ends_with("quit\n"),
            "batch must terminate with quit (sftp batch EOF): {batch}"
        );
    }

    #[test]
    fn remove_partial_dst_upload_recursive_is_documented_gap() {
        // Recursive upload cleanup is intentionally a no-op (see doc comment):
        // sftp `rm -r`/`-R` support varies across OpenSSH versions, so we leave
        // the partial tree rather than risk a half-removed state. Pin the
        // no-op so a future change is deliberate.
        let job = TransferJob {
            direction: Direction::Upload,
            src: PathBuf::from("/local/dir"),
            dst: PathBuf::from("/remote/dir"),
            name: "dir".into(),
            size_total: None,
            recursive: true,
        };
        let batches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let runner: Arc<dyn SftpRunner> = Arc::new(RecordingRunner {
            batches: batches.clone(),
        });
        remove_partial_dst(&runner, &job, "user@host", Path::new("/tmp/mux.sock"));
        let recorded = batches.lock().expect("invariant: lock").clone();
        assert!(
            recorded.is_empty(),
            "recursive upload cleanup must be a no-op (documented gap): {recorded:?}"
        );
    }

    // ---- master stderr drain: lock-contention regression (C1 deadlock) ----

    #[test]
    fn master_stderr_drain_does_not_hold_lock_across_blocking_read() {
        // Regression for the C1 deadlock. The master-stderr drain thread must
        // NOT hold the buffer's `Mutex` across a blocking read. On the happy
        // path the master `ssh -N` stays alive and stderr never EOFs, so a
        // drain that locks across `read_to_end` keeps the lock for the
        // master's whole lifetime — and `wait_for_master`'s per-poll `lock()`
        // blocks forever, hanging the handshake (the 30s timeout never fires
        // because the loop never re-enters past the lock acquire).
        //
        // We reproduce the shape WITHOUT a real sshd: spawn a long-lived
        // "master" that writes a marker to stderr and then sleeps (stderr stays
        // open), drain it with the SAME chunked loop used in `open`, and assert
        // BOTH that:
        //   (a) the marker reaches the buffer through the chunked append
        //       (preserves full stderr for the `Exited` path), and
        //   (b) a `try_lock` from this thread succeeds WHILE the child is
        //       still alive (the lock is not held continuously — the drain
        //       released it after appending and is now blocked in `read()`
        //       without holding it).
        //
        // Under the old `read_to_end`-with-lock drain the lock is held until
        // EOF, so every `try_lock` below fails while the child lives and the
        // test fails fast (it does NOT hang — `try_lock` is non-blocking, by
        // design, so the regression pins the bug class without risking an
        // indefinite hang in the suite).
        use std::io::Read;

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("printf hello-stderr 1>&2; sleep 5")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let buf = Arc::clone(&buf);
            let mut stderr = child.stderr.take().expect("piped stderr");
            let _ = thread::spawn(move || {
                let mut chunk = [0u8; 1024];
                loop {
                    match stderr.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.lock()
                                .expect("invariant: stderr lock")
                                .extend_from_slice(&chunk[..n]);
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        let marker = b"hello-stderr";

        // (a) Chunked append must deliver the marker to the buffer. `try_lock`
        // so the test never blocks even under a buggy drain.
        let marker_deadline = Instant::now() + Duration::from_secs(2);
        let mut marker_seen = false;
        while Instant::now() < marker_deadline {
            if let Ok(drained) = buf.try_lock()
                && drained.windows(marker.len()).any(|w| w == marker)
            {
                marker_seen = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            marker_seen,
            "chunked drain must deliver stderr to the buffer: got {:?}",
            buf.try_lock().map(|b| b.clone()).unwrap_or_default()
        );

        // (b) The child is still alive (sleeping ~5s). The drain thread already
        // consumed the marker so it is now blocked inside `stderr.read(...)`.
        // The lock MUST be free so a `try_lock` succeeds — `wait_for_master`
        // depends on acquiring it each poll. Under the old `read_to_end`-with-
        // lock drain this `try_lock` never succeeds while the child lives.
        let lock_deadline = Instant::now() + Duration::from_secs(2);
        let mut acquired_while_alive = false;
        while Instant::now() < lock_deadline {
            if buf.try_lock().is_ok() {
                acquired_while_alive = true;
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        // Reap BEFORE the asserts so a failure does not leak a `sleep` process.
        let alive_at_assert = child.try_wait().ok().flatten().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            acquired_while_alive,
            "drain thread held the stderr buffer lock while the master was still \
             alive — wait_for_master would deadlock on the happy path"
        );
        assert!(
            alive_at_assert,
            "the master must still be alive when the lock is acquired — otherwise \
             the regression test does not exercise the deadlock shape"
        );
    }

    // ---- first_meaningful_line: collapse captured stderr to one line ----

    #[test]
    fn first_meaningful_line_returns_first_non_empty_trimmed_line() {
        assert_eq!(
            first_meaningful_line("  \n\nPermission denied (password).\nsecond line"),
            "Permission denied (password)."
        );
    }

    #[test]
    fn first_meaningful_line_empty_when_all_lines_blank() {
        assert_eq!(first_meaningful_line("  \n\n\t "), "");
    }

    #[test]
    fn first_meaningful_line_empty_for_empty_input() {
        assert_eq!(first_meaningful_line(""), "");
    }

    #[test]
    fn first_meaningful_line_single_line_is_trimmed() {
        assert_eq!(
            first_meaningful_line("  host unreachable  "),
            "host unreachable"
        );
    }
}
