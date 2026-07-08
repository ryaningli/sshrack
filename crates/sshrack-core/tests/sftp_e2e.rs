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
//! The test then opens the master, lists `$HOME`, downloads `/etc/hostname`
//! (or a fallback) to a temp path, and uploads it back to a temp remote path,
//! asserting each step's outcome. It exercises the real
//! [`SftpWorker::open`] / `send(WorkerCmd::List)` / `Transfer` / `try_event`
//! path end-to-end.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::connect::sftp::SftpWorker;
use sshrack_core::connect::sftp::proto::{Direction, OverwritePolicy, TransferJob, WorkerCmd};
use sshrack_core::connect::ssh::Overrides;
use sshrack_core::credential::{PasswordSource, ResolvedAuth};
use sshrack_core::id::new_id;

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

    let (worker, home) = SftpWorker::open(
        resolved,
        host_obj,
        overrides,
        &self_exe,
        PasswordSource::None,
        None,
    )
    .expect("master open");

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
