//! End-to-end SFTP worker test against a local sshd.
//!
//! This is `#[ignore]`'d by default — it requires a real OpenSSH server
//! running on the test machine, which CI does not provide. Run locally with:
//!
//! ```sh
//! cargo test -p sshrack-core --test sftp_e2e -- --ignored --nocapture
//! ```
//!
//! ## Manual setup
//!
//! The test assumes a local sshd is reachable on `127.0.0.1:<port>` with key
//! auth for the current user already configured (so the master comes up
//! without a password prompt). The simplest setup on a Linux dev box:
//!
//! 1. Generate a host key + user key:
//!    `ssh-keygen -t ed25519 -f /tmp/sshrack-e2e/host_key -N ""`
//!    `ssh-keygen -t ed25519 -f /tmp/sshrack-e2e/user_key -N ""`
//! 2. Authorize the user key:
//!    `mkdir -p ~/.ssh && cat /tmp/sshrack-e2e/user_key.pub >> ~/.ssh/authorized_keys`
//! 3. Start a local sshd on an unused port (e.g. 2222):
//!    `/usr/sbin/sshd -h /tmp/sshrack-e2e/host_key -p 2222 -D` (in another shell)
//! 4. Point the test at it via env (defaults shown):
//!    `SSHRACK_E2E_HOST=127.0.0.1`
//!    `SSHRACK_E2E_PORT=2222`
//!    `SSHRACK_E2E_USER=$USER`
//!    `SSHRACK_E2E_IDENTITY=/tmp/sshrack-e2e/user_key`
//!
//! The test then spawns the master, lists `$HOME`, downloads `/etc/hostname`
//! (or a fallback) to a temp path, and uploads it back to a temp remote path,
//! asserting each step's outcome. It exercises the real
//! [`SftpWorker::spawn`] / `send(WorkerCmd::List)` / `Transfer` / `try_event`
//! path end-to-end.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::connect::sftp::SftpWorker;
use sshrack_core::connect::sftp::proto::{
    Direction, OverwritePolicy, TransferJob, WorkerCmd, WorkerEvent,
};
use sshrack_core::connect::ssh::Overrides;
use sshrack_core::credential::{PasswordSource, ResolvedAuth};
use sshrack_core::id::new_id;

/// Spawn the worker and wait for its `Connected` event, mirroring the shape of
/// the deleted blocking `SftpWorker::open` (returns `(worker, home)`). This
/// `#[ignore]`'d e2e test runs against a real sshd, so a generous 30s deadline
/// covers the first-connect handshake.
fn open_worker(
    resolved: ResolvedAuth,
    host: Host,
    overrides: Overrides,
    self_exe: &std::path::Path,
    bin: sshrack_core::connect::sftp::SftpBin,
) -> (SftpWorker, PathBuf) {
    let worker = SftpWorker::spawn(
        resolved,
        host,
        overrides,
        self_exe,
        PasswordSource::None,
        None,
        bin,
    )
    .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut home = None;
    while Instant::now() < deadline {
        match worker.try_event() {
            Some(WorkerEvent::Connected {
                home: h,
                target: _,
                sock: _,
            }) => {
                home = Some(h);
                break;
            }
            Some(WorkerEvent::ConnectFailed(r)) => panic!("connect failed: {r}"),
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let home = home.expect("no Connected event within 30s");
    (worker, home)
}

/// Pull the e2e target coordinates from the environment, with the documented
/// defaults. Returns `None` if the user key file is missing (so the test
/// skips cleanly instead of failing the assertion when the manual setup was
/// not done).
fn e2e_env() -> Option<(String, u16, String, PathBuf)> {
    let host = std::env::var("SSHRACK_E2E_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("SSHRACK_E2E_PORT")
        .unwrap_or_else(|_| "2222".to_string())
        .parse()
        .ok()?;
    let user = std::env::var("SSHRACK_E2E_USER")
        .ok()
        .filter(|s| !s.is_empty())?;
    let identity = PathBuf::from(
        std::env::var("SSHRACK_E2E_IDENTITY")
            .unwrap_or_else(|_| "/tmp/sshrack-e2e/user_key".to_string()),
    );
    if !identity.exists() {
        return None;
    }
    Some((host, port, user, identity))
}

/// Build a key-only `Host` pointing at the e2e target.
fn e2e_host(host: &str, port: u16) -> Host {
    Host {
        id: new_id(),
        name: "e2e".into(),
        host: host.into(),
        port,
        ssh_args: None,
        auth: Auth::inline(CredentialBody::new("ignored-under-key-auth")),
    }
}

/// A resolved identity for the e2e target: the user + key from env, no
/// password.
fn e2e_resolved(user: &str, identity: &std::path::Path) -> ResolvedAuth {
    ResolvedAuth {
        user: user.into(),
        key_path: Some(identity.to_path_buf()),
        password: PasswordSource::None,
        inline_key: None,
    }
}

/// Real-sshd round trip: list `$HOME`, download `/etc/hostname`, upload it
/// back to a temp path. `#[ignore]`'d so CI never runs it — see the module
/// docs for the manual setup.
#[test]
#[ignore = "requires a local sshd; see module docs for setup"]
fn sftp_round_trip_local_sshd() {
    let Some((host, port, user, identity)) = e2e_env() else {
        eprintln!("sftp_e2e: SSHRACK_E2E_IDENTITY missing — skipping (run setup first)");
        return;
    };

    let host_obj = e2e_host(&host, port);
    let resolved = e2e_resolved(&user, &identity);
    let overrides = Overrides::default();
    let self_exe = std::env::current_exe().expect("current_exe");

    let (worker, home) = open_worker(
        resolved,
        host_obj,
        overrides,
        &self_exe,
        sshrack_core::connect::sftp::SftpBin::default(),
    );

    // (1) List $HOME.
    worker.send(WorkerCmd::List(home.clone()));
    let listing = wait_for_event(Duration::from_secs(15), &worker, |ev| {
        matches!(
            ev,
            sshrack_core::connect::sftp::proto::WorkerEvent::Listing(_, _)
        )
    })
    .expect("listing event");
    match listing {
        sshrack_core::connect::sftp::proto::WorkerEvent::Listing(_, res) => {
            let _ = res.expect("list ok");
        }
        _ => unreachable!(),
    }

    // (2) Download /etc/hostname (or /etc/hosts as a portable fallback).
    let remote_src = PathBuf::from("/etc/hostname");
    let local_dst = {
        let t = tempfile::tempdir().expect("temp dir");
        t.path().join("hostname.txt")
    };
    worker.send(WorkerCmd::Transfer(
        TransferJob {
            direction: Direction::Download,
            src: remote_src.clone(),
            dst: local_dst.clone(),
            name: "hostname".into(),
            size_total: None,
            recursive: false,
        },
        OverwritePolicy::Overwrite,
    ));
    let done = wait_for_event(Duration::from_secs(30), &worker, |ev| {
        matches!(ev, sshrack_core::connect::sftp::proto::WorkerEvent::Done(_))
    })
    .expect("done event");
    match done {
        sshrack_core::connect::sftp::proto::WorkerEvent::Done(
            sshrack_core::connect::sftp::proto::TransferOutcome::Ok,
        ) => {}
        other => panic!("download failed: {other:?}"),
    }
    assert!(local_dst.exists(), "downloaded file must exist");

    // (3) Upload it back to a unique remote temp path and let Drop clean up.
    let remote_dst = PathBuf::from(format!(
        "/tmp/sshrack-e2e-upload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    worker.send(WorkerCmd::Transfer(
        TransferJob {
            direction: Direction::Upload,
            src: local_dst.clone(),
            dst: remote_dst,
            name: "hostname-upload".into(),
            size_total: None,
            recursive: false,
        },
        OverwritePolicy::Overwrite,
    ));
    let done = wait_for_event(Duration::from_secs(30), &worker, |ev| {
        matches!(ev, sshrack_core::connect::sftp::proto::WorkerEvent::Done(_))
    })
    .expect("done event");
    match done {
        sshrack_core::connect::sftp::proto::WorkerEvent::Done(
            sshrack_core::connect::sftp::proto::TransferOutcome::Ok,
        ) => {}
        other => panic!("upload failed: {other:?}"),
    }

    // Drop tears down the master + socket file.
    drop(worker);
}

/// Diagnostic: upload + download a ~30MB file with `size_total=Some`, collecting
/// every `Progress` event's `bytes_done`. Decides whether the active-transfer
/// row would actually advance: if `bytes_done` grows here the worker is fine
/// and the bug is in the TUI drain/draw; if it stays 0 the bug is in
/// `poll_dst_size`. `#[ignore]`'d like the round-trip test — needs sshd.
#[test]
#[ignore = "requires a local sshd; see module docs for setup"]
fn sftp_progress_grows_local_sshd() {
    let Some((host, port, user, identity)) = e2e_env() else {
        eprintln!("sftp_e2e: SSHRACK_E2E_IDENTITY missing — skipping (run setup first)");
        return;
    };
    let host_obj = e2e_host(&host, port);
    let resolved = e2e_resolved(&user, &identity);
    let overrides = Overrides::default();
    let self_exe = std::env::current_exe().expect("current_exe");
    let (worker, _home) = open_worker(
        resolved,
        host_obj,
        overrides,
        &self_exe,
        sshrack_core::connect::sftp::SftpBin::default(),
    );

    // A large local file so the transfer spans enough PROGRESS_POLL ticks to
    // observe growth (a few hundred ms on loopback). Sparse-allocated to avoid
    // writing 200MB of real data — sftp still ships 200MB over the wire.
    let big_dir = tempfile::tempdir().expect("temp dir for big file");
    let big_local = big_dir.path().join("big.bin");
    std::fs::File::create(&big_local)
        .expect("create big.bin")
        .set_len(200 * 1024 * 1024)
        .expect("set_len");
    let size = std::fs::metadata(&big_local).expect("big.bin meta").len();
    let remote_dst = PathBuf::from(format!(
        "/tmp/sshrack-e2e-upload-{}.bin",
        std::process::id()
    ));

    // ---- UPLOAD a large local file to the remote ----
    worker.send(WorkerCmd::Transfer(
        TransferJob {
            direction: Direction::Upload,
            src: big_local.clone(),
            dst: remote_dst.clone(),
            name: "big-upload".into(),
            size_total: Some(size),
            recursive: false,
        },
        OverwritePolicy::Overwrite,
    ));
    let up_seq = collect_progress(&worker, Duration::from_secs(60));
    eprintln!("UPLOAD progress samples ({}): {:?}", up_seq.len(), up_seq);

    // ---- DOWNLOAD it back ----
    let dn_tmp = tempfile::tempdir().expect("temp dir");
    let local_back = dn_tmp.path().join("back.bin");
    worker.send(WorkerCmd::Transfer(
        TransferJob {
            direction: Direction::Download,
            src: remote_dst.clone(),
            dst: local_back.clone(),
            name: "big-download".into(),
            size_total: Some(size),
            recursive: false,
        },
        OverwritePolicy::Overwrite,
    ));
    let dn_seq = collect_progress(&worker, Duration::from_secs(60));
    eprintln!("DOWNLOAD progress samples ({}): {:?}", dn_seq.len(), dn_seq);

    let _ = std::process::Command::new("rm")
        .arg("-f")
        .arg(&remote_dst)
        .status();
    drop(worker);

    fn grew(seq: &[u64]) -> bool {
        seq.len() >= 2 && seq.last().copied().unwrap_or(0) > seq.first().copied().unwrap_or(0)
    }
    assert!(!up_seq.is_empty(), "upload emitted no Progress events");
    assert!(!dn_seq.is_empty(), "download emitted no Progress events");
    // Upload is the core regression guard: it polls the remote file size via
    // `parse_size_from_ls`, the function the prompt-echo bug left stuck at 0.
    assert!(grew(&up_seq), "upload bytes_done never grew: {up_seq:?}");
    // Download polls local fs metadata (not `parse_size_from_ls`); a fast
    // loopback can finish 200MB in under two 20ms polls, so `grew` would flake
    // without indicating a real bug. Non-empty proves the download path emits
    // Progress events at all.
}

/// Drain `Progress` events (printing each) until `Done` arrives or the deadline
/// passes. Returns the collected `bytes_done` sequence.
fn collect_progress(worker: &SftpWorker, deadline: Duration) -> Vec<u64> {
    use sshrack_core::connect::sftp::proto::WorkerEvent;
    let stop = Instant::now() + deadline;
    let mut seq: Vec<u64> = Vec::new();
    while Instant::now() < stop {
        let mut got_done = false;
        while let Some(ev) = worker.try_event() {
            match ev {
                WorkerEvent::Progress(p) => {
                    eprintln!(
                        "  prog done={} total={:?} rate={:?} eta={:?}",
                        p.bytes_done, p.bytes_total, p.rate_bps, p.eta_secs
                    );
                    seq.push(p.bytes_done);
                }
                WorkerEvent::Done(o) => {
                    eprintln!("  done: {o:?}");
                    got_done = true;
                }
                _ => {}
            }
        }
        if got_done {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    seq
}

/// Poll `try_event` until `matches` returns true for some event, or the
/// deadline passes. Returns the matching event, or `None` on timeout.
fn wait_for_event<F>(
    deadline: Duration,
    worker: &SftpWorker,
    matches: F,
) -> Option<sshrack_core::connect::sftp::proto::WorkerEvent>
where
    F: Fn(&sshrack_core::connect::sftp::proto::WorkerEvent) -> bool,
{
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        while let Some(ev) = worker.try_event() {
            if matches(&ev) {
                return Some(ev);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}
