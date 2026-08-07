//! SFTP worker: spawns the master `ssh -N` connection on a worker thread and
//! serially executes every [`WorkerCmd`] the UI sends. The main thread pushes
//! commands via [`SftpWorker::send`]; the UI polls [`WorkerEvent`]s each tick via
//! [`SftpWorker::try_event`]. [`SftpWorker::spawn`] returns immediately — the
//! master handshake + `sftp pwd` run on the worker thread, surfacing via
//! [`WorkerEvent::Connected`] / [`WorkerEvent::ConnectFailed`]. Dropping the
//! handle sends `Shutdown` and joins; the worker thread owns the master/socket/
//! pw-file via a [`MasterSession`] guard whose `Drop` is the single teardown
//! path (so a dropped-while-Connecting handshake aborts within one poll).
//!
//! ## Threading shape
//!
//! ```text
//!   main thread                         worker thread
//!   ───────────                         ─────────────
//!   SftpWorker {                        connect_phase (master + pwd)
//!     cmd_tx ──── WorkerCmd ────►         │  drains cmd_rx (Shutdown = cancel)
//!     event_rx ◄── WorkerEvent ─── tx     ▼
//!     join handle                        service_loop {
//!   }                                      recv() → match { List | Transfer | … }
//!                                         }
//!                                         (MasterSession owned here → Drop on
//!                                          any exit path tears the master down)
//! ```
//!
//! The worker thread owns the master `Child`, the [`ControlSocket`] RAII guard,
//! the password temp file, and the listing source + connection coordinates;
//! the handle keeps only channel endpoints + the join handle. Teardown is
//! entirely on the worker thread, so the UI thread does zero synchronous
//! network I/O on close.
//!
//! ## Testability
//!
//! The thread + spawn paths are not unit-testable without a real sshd, so only
//! the pure pieces are unit-tested (now extracted into [`super::pure`] —
//! `parse_remote_home`, `parse_size_from_ls`, `classify_inflight_cmd`) plus the
//! [`ControlSocket`] RAII behavior (in [`super`]). The spawn / connect / cancel
//! shape is exercised against a mock-ssh shim in `tests/sftp_seam_test.rs`. A
//! `#[ignore]`'d e2e test lives in `tests/sftp_e2e.rs` for a future local-sshd
//! run.

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
    ControlSocket, SftpBin, control_check_argv, control_exit_argv, get_batch, master_argv,
    progress_snapshot, put_batch, pwd_batch, sftp_batch_argv, sftp_target, shell_quote,
};
use crate::connect::ssh::Overrides;
use crate::connect::{askpass_env_for_sftp, write_password_file};
use crate::credential::{PasswordSource, ResolvedAuth};
use crate::dirsource::DirSource;
use crate::hostkey::{self, HostKeyAction};

/// How long [`connect_phase`] polls `ssh -O check` before giving up. 30s is
/// generous for slow first-connect handshakes on high-latency links but bounded
/// so a misconfigured host surfaces a clear error instead of hanging forever.
/// The UI may `Esc`-cancel a slow handshake within one [`HANDSHAKE_POLL`]
/// (≤250ms) regardless of this deadline.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval during the master handshake.
const HANDSHAKE_POLL: Duration = Duration::from_millis(250);

/// Polling interval during a transfer (size + cancel check).
const PROGRESS_POLL: Duration = Duration::from_millis(200);

// ---- MasterSession: worker-thread teardown owner ----

/// Owned by the worker thread once the master is up. `Drop` tears the session
/// down: kill + reap the master, detach `ssh -O exit`, drop the
/// [`ControlSocket`] (removes the socket file), and remove + unregister the
/// password temp file. Living on the worker thread means teardown runs on every
/// exit path — normal `Shutdown`, connect failure, cancel, or the thread simply
/// ending — without the UI thread doing any synchronous network I/O.
struct MasterSession {
    master_child: Option<Child>,
    sock: Option<ControlSocket>,
    pw_file: Option<PathBuf>,
    target: String,
    bin: SftpBin,
}

impl MasterSession {
    /// Detach `ssh -O exit` (fire-and-forget, like the close path) and
    /// force-kill + reap the master. Idempotent.
    fn teardown(&mut self) {
        let sock_path = self
            .sock
            .as_ref()
            .map(|s| s.path().to_path_buf())
            .unwrap_or_default();
        let exit_argv = control_exit_argv(&self.target, &sock_path);
        let _ = Command::new(&self.bin.ssh)
            .args(&exit_argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn(); // detached — see sftp-detach-control-exit memory
        if let Some(child) = self.master_child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.sock.take(); // ControlSocket::drop removes the socket file
        if let Some(p) = self.pw_file.take() {
            crate::tempfile_registry::unregister(&p);
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for MasterSession {
    fn drop(&mut self) {
        self.teardown();
    }
}

// ---- SftpWorker ----

/// Handle to the worker thread. Push commands via [`SftpWorker::send`]; poll
/// events via [`SftpWorker::try_event`]. `Drop` sends `Shutdown` and joins —
/// the worker thread owns the master/socket/pw-file ([`MasterSession`]) and
/// tears them down on any exit path.
///
/// Construction is via [`SftpWorker::spawn`], which returns immediately — the
/// master handshake runs on the worker thread. `target()` / `sock_path()` are
/// NOT exposed: the worker thread owns those coordinates, and they only go live
/// once the master is up, so they ride the [`WorkerEvent::Connected`] event
/// instead.
pub struct SftpWorker {
    cmd_tx: mpsc::Sender<WorkerCmd>,
    event_rx: mpsc::Receiver<WorkerEvent>,
    join: Option<JoinHandle<()>>,
}

impl SftpWorker {
    /// Spawn the worker thread. Returns immediately — the master handshake and
    /// `sftp pwd` happen ON the worker thread, surfaced later as
    /// [`WorkerEvent::Connected`] / [`WorkerEvent::ConnectFailed`]. The UI
    /// shows a `Connecting…` screen while these run and may `Esc`-cancel (the
    /// handle's `Drop` sends `Shutdown`; the connect phase drains `cmd_rx` and
    /// aborts).
    ///
    /// `resolved`/`host`/`overrides`/`self_exe`/`source`/`config_path` mirror
    /// the old `open`. The host-key pre-flight (Task 2) runs at the top of the
    /// connect phase on the worker thread.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        resolved: ResolvedAuth,
        host: Host,
        overrides: Overrides,
        self_exe: &Path,
        source: PasswordSource,
        config_path: Option<&Path>,
        bin: SftpBin,
    ) -> Result<Self, String> {
        Self::spawn_inner(
            resolved,
            host,
            overrides,
            self_exe,
            source,
            config_path,
            bin,
            /* host_key_preflight */ true,
        )
    }

    /// Test-only spawn: like [`SftpWorker::spawn`] but skips the host-key
    /// pre-flight. The shim-based seam tests use unresolvable hosts (e.g.
    /// `sftp-shim.invalid`) that would fail `ssh-keyscan` before the master
    /// handshake is reached; skipping the pre-flight lets those tests keep
    /// exercising the master handshake + transfer path against the ssh/sftp
    /// shims. Not part of the stable API.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_for_test(
        resolved: ResolvedAuth,
        host: Host,
        overrides: Overrides,
        self_exe: &Path,
        source: PasswordSource,
        config_path: Option<&Path>,
        bin: SftpBin,
    ) -> Result<Self, String> {
        Self::spawn_inner(
            resolved,
            host,
            overrides,
            self_exe,
            source,
            config_path,
            bin,
            /* host_key_preflight */ false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_inner(
        resolved: ResolvedAuth,
        host: Host,
        overrides: Overrides,
        self_exe: &Path,
        source: PasswordSource,
        config_path: Option<&Path>,
        bin: SftpBin,
        host_key_preflight: bool,
    ) -> Result<Self, String> {
        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
        let runner = Arc::new(LocalSftpRunner::with_bin(bin.sftp.clone()));
        // Convert borrowed inputs to owned BEFORE the closure: the thread is
        // 'static, so neither &Path nor Option<&Path> can be captured.
        let self_exe_owned = self_exe.to_path_buf();
        let config_path_owned = config_path.map(|p| p.to_path_buf());
        let join = thread::Builder::new()
            .name("sftp-worker".into())
            .spawn(move || {
                run_worker_thread(
                    cmd_rx,
                    event_tx,
                    resolved,
                    host,
                    overrides,
                    self_exe_owned,
                    source,
                    config_path_owned,
                    bin,
                    runner,
                    host_key_preflight,
                )
            })
            .map_err(|e| format!("sftp worker thread spawn failed: {e}"))?;
        Ok(Self {
            cmd_tx,
            event_rx,
            join: Some(join),
        })
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

    /// Test-only constructor: build a handle around pre-seeded channel ends
    /// WITHOUT spawning a worker thread. The drain reads events from
    /// `event_rx` and (on `HostKeyConfirm`) writes commands to `cmd_tx`;
    /// `Drop` sends `Shutdown` and skips the join (`join: None` → no thread to
    /// reap). Used by `run_loop` drain tests that need to exercise the
    /// event-routing logic without a real master handshake. Not part of the
    /// stable API.
    #[doc(hidden)]
    pub fn new_for_test(
        cmd_tx: mpsc::Sender<WorkerCmd>,
        event_rx: mpsc::Receiver<WorkerEvent>,
    ) -> Self {
        Self {
            cmd_tx,
            event_rx,
            join: None,
        }
    }
}

impl Drop for SftpWorker {
    fn drop(&mut self) {
        // Ask the worker to exit, then join. The connect phase and service loop
        // both watch cmd_rx, so this returns within ~HANDSHAKE_POLL (250ms)
        // once the worker reaches a recv point. On join, the worker thread's
        // MasterSession has already torn the master down.
        let _ = self.cmd_tx.send(WorkerCmd::Shutdown);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

// ---- worker thread ----

/// Worker thread entry point. Runs [`connect_phase`] (master handshake + pwd,
/// cancellable) then [`service_loop`] (the Listing/Transfer/Cancel/Shutdown
/// loop). `session` moves into `service_loop` so its [`MasterSession::drop`]
/// runs when that function returns — i.e. on every exit path. On a connect
/// failure / cancel [`connect_phase`] already cleaned up and returned `Err`.
/// `host_key_preflight` toggles the Task 2 host-key step (prod runs it; the
/// shim seam tests skip it because their hosts are unresolvable).
#[allow(clippy::too_many_arguments)]
fn run_worker_thread(
    cmd_rx: mpsc::Receiver<WorkerCmd>,
    event_tx: mpsc::Sender<WorkerEvent>,
    resolved: ResolvedAuth,
    host: Host,
    overrides: Overrides,
    self_exe: PathBuf,
    source: PasswordSource,
    config_path: Option<PathBuf>,
    bin: SftpBin,
    runner: Arc<LocalSftpRunner>,
    host_key_preflight: bool,
) {
    // Task 1: connect = master handshake + pwd. Task 2 prepends the host-key
    // pre-flight (ssh-keyscan + fingerprint confirm) here, so `host_str`/`port`
    // are read from `host` BEFORE the borrow and forwarded into connect_phase.
    // `connect_phase` reports + cleans up on Err, so only the Ok arm does work.
    let host_str = host.host.as_str();
    let port = host.port;
    if let Ok((session, home)) = connect_phase(
        &cmd_rx,
        &event_tx,
        &resolved,
        &host,
        &overrides,
        &self_exe,
        &source,
        config_path.as_deref(),
        &bin,
        &runner,
        host_str,
        port,
        host_key_preflight,
    ) {
        // service_loop takes ownership of the session; when it returns,
        // session drops and tears the master down.
        let target = session.target.clone();
        let sock_path = session
            .sock
            .as_ref()
            .map(|s| s.path().to_path_buf())
            .expect("invariant: socket alive after connect");
        let sftp_bin = bin.sftp.clone();
        // Coercion Arc<LocalSftpRunner> → Arc<dyn SftpRunner> happens here.
        let runner_dyn: Arc<dyn SftpRunner> = runner;
        service_loop(
            cmd_rx, event_tx, session, runner_dyn, target, sock_path, home, sftp_bin,
        );
    }
}

/// Host-key pre-flight (Task 2). Runs on the worker thread BEFORE the master
/// handshake. For a known host it is instant (`is_known` → launch); for an
/// unknown host it scans, asks the UI via [`WorkerEvent::HostKeyNeedsConfirm`],
/// and blocks on `cmd_rx` for the reply — all cancellable via `Shutdown` (Esc
/// while the overlay is up lands here as a reject).
///
/// `host_str`/`port` thread from [`run_worker_thread`] (which owns `host`).
/// Returns `Ok(())` to proceed to the master handshake; `Err(())` after
/// emitting `ConnectFailed` (or silently on a channel disconnect = UI gone).
///
/// Known limitation: `ssh-keyscan` (unknown-host path only) runs via
/// `Command::output` and is NOT cancellable mid-scan. If the user `Esc`s while
/// the worker is inside the scan, `Drop`'s `join` waits up to the scan's 5s
/// `-T` timeout before returning. The high-frequency paths (known host: no
/// scan; master handshake: cancellable poll) are unaffected.
fn host_key_check(
    cmd_rx: &mpsc::Receiver<WorkerCmd>,
    event_tx: &mpsc::Sender<WorkerEvent>,
    host_str: &str,
    port: u16,
) -> Result<(), ()> {
    // The TUI always runs on a tty and has no --accept-new flag, so `classify`
    // returns Launch for known hosts and Prompt for unknown hosts. Reject is
    // unreachable (no-tty + no-flag) but fail-safe.
    let known_hosts = match hostkey::known_hosts_path() {
        Some(p) => p,
        None => {
            let _ = event_tx.send(WorkerEvent::ConnectFailed("no known_hosts path".into()));
            return Err(());
        }
    };
    let known = hostkey::is_known(host_str, port, &known_hosts).unwrap_or(false);
    match hostkey::classify(known, /*has_tty*/ true, /*accept_new*/ false) {
        HostKeyAction::Launch => {} // known — proceed to master handshake
        HostKeyAction::Accept | HostKeyAction::Prompt => {
            // Unknown: scan (≤5s `-T`), ask, wait. `classify` returns Accept
            // only with --accept-new, which the TUI never sets, so this is the
            // Prompt path in practice — but Accept handles a future flag too.
            let fps = match hostkey::scan_fingerprints(host_str, port) {
                Ok(fps) if !fps.is_empty() => fps,
                _ => {
                    let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                        "host key scan failed for {host_str}"
                    )));
                    return Err(());
                }
            };
            let primary = match hostkey::pick_primary(&fps) {
                Some(p) => p,
                None => {
                    let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                        "host key scan returned no keys for {host_str}"
                    )));
                    return Err(());
                }
            };
            let fingerprint = hostkey::confirm_text(host_str, primary);
            let _ = event_tx.send(WorkerEvent::HostKeyNeedsConfirm {
                host: host_str.to_string(),
                fingerprint,
            });
            // Wait for the UI's reply. Esc/drop → Shutdown/Disconnect → reject.
            // A channel disconnect (UI gone) is a silent cancel — no
            // ConnectFailed, the user already chose to leave.
            let accepted = match cmd_rx.recv() {
                Ok(WorkerCmd::HostKeyConfirm(true)) => true,
                Ok(WorkerCmd::HostKeyConfirm(false)) | Ok(WorkerCmd::Shutdown) => false,
                Ok(_) => false,           // unexpected; treat as reject
                Err(_) => return Err(()), // UI gone — silent cancel
            };
            if !accepted {
                let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                    "host key not confirmed for {host_str}"
                )));
                return Err(());
            }
            if let Err(e) = hostkey::append_to_known_hosts(host_str, port, &known_hosts) {
                let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                    "known_hosts write failed: {e}"
                )));
                return Err(());
            }
        }
        HostKeyAction::Reject => {
            // classify returns Reject only without a tty AND without
            // accept_new; the TUI always has a tty, so this is unreachable —
            // but fail safe.
            let _ = event_tx.send(WorkerEvent::ConnectFailed("host key rejected".into()));
            return Err(());
        }
    }
    Ok(())
}

/// Spawn the master, poll until up (cancellable), probe home via `pwd`.
/// Sends [`WorkerEvent::Connected`] on success; [`WorkerEvent::ConnectFailed`]
/// on Exited/Timeout; nothing on Cancelled. Returns `Err(())` whenever the
/// master did NOT come up (the partial [`MasterSession`] cleans itself up via
/// `Drop`).
///
/// Task 2 prepends [`host_key_check`] (was `open_transfer` step 5 on the UI
/// thread) when `host_key_preflight` is true; the shim-based seam tests pass
/// `false` so their unresolvable hosts do not fail at `ssh-keyscan` before the
/// master handshake is reached. `host_str`/`port` thread from
/// [`run_worker_thread`] (which owns `host`).
#[allow(clippy::too_many_arguments)]
fn connect_phase(
    cmd_rx: &mpsc::Receiver<WorkerCmd>,
    event_tx: &mpsc::Sender<WorkerEvent>,
    resolved: &ResolvedAuth,
    host: &Host,
    overrides: &Overrides,
    self_exe: &Path,
    source: &PasswordSource,
    config_path: Option<&Path>,
    bin: &SftpBin,
    runner: &Arc<LocalSftpRunner>,
    host_str: &str,
    port: u16,
    host_key_preflight: bool,
) -> Result<(MasterSession, PathBuf), ()> {
    if host_key_preflight {
        host_key_check(cmd_rx, event_tx, host_str, port)?;
    }

    let sock = ControlSocket::new();
    let sock_path = sock.path().to_path_buf();
    let target = sftp_target(resolved, host);

    // Materialize the password temp file (Inline only) and build the askpass
    // env. Keyring carries no file; None carries no env at all. The SFTP
    // variant forces SSH_ASKPASS_REQUIRE=force and denies /dev/tty for None.
    let pw_file = match source {
        PasswordSource::Inline(pw) => match write_password_file(pw) {
            Ok(p) => Some(p),
            Err(e) => {
                let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                    "sftp password file failed: {e}"
                )));
                return Err(());
            }
        },
        _ => None,
    };
    let env = askpass_env_for_sftp(self_exe, source, pw_file.as_deref(), config_path);

    // Captured master stderr: drained on a side thread so (a) the pipe never
    // fills and blocks the handshake, and (b) an auth failure's real reason is
    // captured instead of being written to the TUI's tty.
    let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    // Spawn the master `ssh -N`. stdin null (ssh -N never reads it), stdout
    // null, stderr piped + drained on a side thread.
    let master_argv = master_argv(resolved, host, overrides, &sock_path);
    let mut master_cmd = Command::new(&bin.ssh);
    master_cmd
        .args(&master_argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (k, v) in &env {
        master_cmd.env(k, v);
    }
    let mut master_child = match master_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = event_tx.send(WorkerEvent::ConnectFailed(format!(
                "sftp master spawn failed: {e}"
            )));
            // Partial session: Drop removes pw_file + socket.
            let partial = MasterSession {
                master_child: None,
                sock: Some(sock),
                pw_file,
                target,
                bin: bin.clone(),
            };
            drop(partial);
            return Err(());
        }
    };

    // Drain master stderr into the buffer in chunks (see wait_for_master's
    // per-poll lock): holding the lock across a blocking read would lock out
    // the per-poll `lock()` for the master's whole lifetime and hang the
    // handshake. Read in chunks so the poll can acquire the lock between reads.
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

    let outcome = wait_for_master_cancellable(
        cmd_rx,
        &target,
        &sock_path,
        &bin.ssh,
        Instant::now() + HANDSHAKE_TIMEOUT,
        &mut master_child,
        &stderr_buf,
    );
    let session = MasterSession {
        master_child: Some(master_child),
        sock: Some(sock),
        pw_file,
        target: target.clone(),
        bin: bin.clone(),
    };
    match outcome {
        HandshakeOutcome::Ready => {}
        HandshakeOutcome::Cancelled => {
            // Silent: user cancelled. session.drop cleans up.
            return Err(());
        }
        HandshakeOutcome::Exited(s) => {
            let reason = match first_meaningful_line(&s) {
                "" => "sftp master failed (authentication rejected)".to_string(),
                line => format!("sftp master failed: {line}"),
            };
            let _ = event_tx.send(WorkerEvent::ConnectFailed(reason));
            return Err(());
        }
        HandshakeOutcome::Timeout => {
            let _ = event_tx.send(WorkerEvent::ConnectFailed(
                "sftp master handshake timed out".to_string(),
            ));
            return Err(());
        }
    }

    // Probe home via `pwd` (falls back to `/`). Failing to detect home is NOT
    // a connect failure — the screen still works with cwd `/`.
    let home = {
        let batch = pwd_batch();
        match runner.run_batch(&target, &sock_path, &batch) {
            Ok(stdout) => parse_remote_home(&stdout).unwrap_or_else(|| PathBuf::from("/")),
            Err(_) => PathBuf::from("/"),
        }
    };
    let _ = event_tx.send(WorkerEvent::Connected {
        home: home.clone(),
        target: target.clone(),
        sock: sock_path.clone(),
    });
    Ok((session, home))
}

/// The worker thread service loop. Owns the [`MasterSession`] (so its `Drop`
/// tears the master down on return), the listing source, and the connection
/// coordinates; drains [`WorkerCmd`]s and emits [`WorkerEvent`]s. The body is
/// unchanged from the old `worker_loop` — only the name and the added `session`
/// parameter (so its teardown runs on every exit path) differ.
#[allow(clippy::too_many_arguments)]
fn service_loop(
    cmd_rx: mpsc::Receiver<WorkerCmd>,
    event_tx: mpsc::Sender<WorkerEvent>,
    session: MasterSession,
    runner: Arc<dyn SftpRunner>,
    target: String,
    sock: PathBuf,
    home: PathBuf,
    sftp_bin: PathBuf,
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
                if run_transfer(
                    &event_tx, &cmd_rx, &runner, &job, policy, &target, &sock, &sftp_bin,
                ) {
                    break;
                }
            }
            WorkerCmd::Cancel => {
                // No transfer in flight — nothing to cancel. Drop silently.
            }
            WorkerCmd::HostKeyConfirm(_) => {
                // Connect-phase reply that arrived after the master was already
                // up (impossible in normal flow — the connect phase owns
                // cmd_rx until Connected). Drop silently rather than risk a
                // mid-session state change.
            }
            WorkerCmd::Shutdown => break,
        }
    }
    // session drops here → MasterSession::teardown (kill + reap master,
    // detached ssh -O exit, drop socket, remove pw file).
    drop(session);
}

/// Run one transfer job to completion (or cancellation). Emits Progress while
/// running, Done on completion / failure / cancel.
///
/// `cmd_rx` is checked between try_wait polls so `Cancel` lands within
/// [`PROGRESS_POLL`] ms. Other commands arriving mid-transfer are classified
/// via [`classify_inflight_cmd`]: `Shutdown` propagates (kill + cleanup +
/// signal), `Cancel` cancels, anything else is dropped.
///
/// Returns `true` if `Shutdown` was received mid-transfer, so [`service_loop`]
/// `break`s instead of looping back to `recv()` (which would deadlock against
/// `Drop`'s `join()`). Returns `false` on normal completion / cancel / spawn
/// failure / channel disconnect.
#[allow(clippy::too_many_arguments)]
fn run_transfer(
    event_tx: &mpsc::Sender<WorkerEvent>,
    cmd_rx: &mpsc::Receiver<WorkerCmd>,
    runner: &Arc<dyn SftpRunner>,
    job: &TransferJob,
    policy: OverwritePolicy,
    target: &str,
    sock: &Path,
    sftp_bin: &Path,
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
    let mut cmd = Command::new(sftp_bin);
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
                            // CRITICAL: propagate Shutdown so service_loop breaks
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

/// Outcome of polling the master handshake. [`wait_for_master_cancellable`]
/// returns this; [`connect_phase`] maps `Exited`/`Timeout` to a
/// `WorkerEvent::ConnectFailed`, drops the partial session on `Cancelled`, and
/// proceeds on `Ready`.
enum HandshakeOutcome {
    /// `ssh -O check` succeeded — the master is up.
    Ready,
    /// The master exited before coming up (auth failure, refused key, etc.).
    /// Carries the drained stderr so the user sees the real reason.
    Exited(String),
    /// The master neither came up nor exited before the deadline.
    Timeout,
    /// The UI dropped the worker mid-handshake (Esc while Connecting) — stop
    /// polling, clean up, and exit silently (no `ConnectFailed`: the user chose
    /// to cancel, so a red error would be noise).
    Cancelled,
}

/// Pure decision over one handshake poll's signals. `cancelled` (a Shutdown /
/// channel disconnect observed by the polling loop) beats everything: there is
/// no point waiting once the UI is gone.
///
/// Precedence: `cancelled` > `check_ok` (Ready) > `master_exited` (Exited) >
/// `timed_out` (Timeout). `stderr` is attached only to `Exited`.
fn classify_poll(
    check_ok: bool,
    master_exited: bool,
    timed_out: bool,
    stderr: String,
    cancelled: bool,
) -> Option<HandshakeOutcome> {
    if cancelled {
        return Some(HandshakeOutcome::Cancelled);
    }
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

/// Poll `ssh -O check <target>` until it exits 0 (master up), the master
/// exits, the deadline elapses, or the UI sends `Shutdown` (cancel). Pure-I/O
/// wrapper: the readiness check is itself a process spawn (no stdout parsing —
/// readiness is exit-0 only), so this is not unit-tested.
///
/// Between polls the function drains `cmd_rx` with a `recv_timeout(HANDSHAKE_POLL)`
/// so the cancel lands within one poll window (≤250ms) instead of waiting for
/// the deadline. A channel disconnect (UI gone) also cancels. Other commands
/// arriving pre-`Connected` are dropped — the connect phase owns the thread
/// until the master is up, and the UI holds `List`/`Transfer` until
/// [`WorkerEvent::Connected`] lands.
fn wait_for_master_cancellable(
    cmd_rx: &mpsc::Receiver<WorkerCmd>,
    target: &str,
    sock: &Path,
    ssh_bin: &Path,
    deadline: Instant,
    master: &mut Child,
    stderr_buf: &Arc<Mutex<Vec<u8>>>,
) -> HandshakeOutcome {
    loop {
        let argv = control_check_argv(target, sock);
        let check_ok = Command::new(ssh_bin)
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
        // Drain ANY command the UI sent during the handshake. Only `Shutdown`
        // matters (cancel); `List`/`Transfer` arriving early are impossible
        // (the UI holds them until `Connected`), but if one does arrive, drop
        // it — the connect phase owns the thread until the master is up.
        let cancelled = match cmd_rx.recv_timeout(HANDSHAKE_POLL) {
            Ok(WorkerCmd::Shutdown) => true,
            Ok(_) => false, // unexpected pre-Connected; ignore
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true, // UI gone
        };
        if let Some(outcome) = classify_poll(check_ok, master_exited, timed_out, stderr, cancelled)
        {
            return outcome;
        }
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
        let out = classify_poll(true, false, true, String::new(), false);
        assert!(matches!(out, Some(HandshakeOutcome::Ready)));
    }

    #[test]
    fn classify_poll_master_exit_beats_timeout() {
        // Master exited (auth failure) before the deadline: report Exited with
        // the captured stderr, not Timeout.
        let out = classify_poll(false, true, true, "Permission denied".into(), false);
        assert!(matches!(
            out,
            Some(HandshakeOutcome::Exited(s)) if s == "Permission denied"
        ));
    }

    #[test]
    fn classify_poll_cancelled_wins_over_timeout() {
        // A Shutdown arrived mid-handshake (user hit Esc while Connecting): cancel
        // immediately, even if the deadline also passed. The UI dropped the worker;
        // there is nothing to wait for.
        let out = classify_poll(false, false, true, String::new(), true);
        assert!(matches!(out, Some(HandshakeOutcome::Cancelled)));
    }

    #[test]
    fn classify_poll_timeout_when_only_deadline() {
        let out = classify_poll(false, false, true, String::new(), false);
        assert!(matches!(out, Some(HandshakeOutcome::Timeout)));
    }

    #[test]
    fn classify_poll_none_keeps_polling() {
        // No signal yet: return None so the caller polls again.
        let out = classify_poll(false, false, false, String::new(), false);
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
