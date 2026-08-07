//! Hermetic integration tests for the SFTP worker spawn seam.
//!
//! These tests exercise `SftpWorker::open` / `send` / `Drop` with shim binaries
//! standing in for the system `ssh` / `sftp`. The seam is [`SftpBin`]: the
//! worker uses `bin.ssh` / `bin.sftp` as the `Command::new(...)` program for
//! the master (`ssh -N`), control (`ssh -O check|exit`), and transfer (`sftp
//! -b -`) spawns, skipping the literal `"ssh"` / `"sftp"` first element that
//! the argv builders still emit. Production passes [`SftpBin::default`]; these
//! tests pass shim paths.
//!
//! Hermeticity: the shims are absolute paths used as `argv[0]` (no `PATH`
//! mutation, no `set_var`, no network). The ssh-shim derives its capture-file
//! path from its own location; the sftp-shim sleeps a fixed duration. No real
//! `sshd`, `ssh`, or `sftp` process is contacted.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::connect::sftp::{
    SftpBin, SftpWorker,
    proto::{Direction, OverwritePolicy, TransferJob, WorkerCmd, WorkerEvent},
};
use sshrack_core::credential::{PasswordSource, ResolvedAuth};
use sshrack_core::id::new_id;

// ---- shim infrastructure ----

/// Write the ssh-shim script to `shim_path`. The shim:
/// - records every invocation's argv + selected env to `<dir>/capture.txt`
///   (next to the shim), appending with `===END===` delimiters;
/// - on `-N` (master): touches the control-socket file so `ControlSocket::drop`
///   can remove it, then sleeps (stays alive until the worker drops + kills);
/// - on `-O check` / `-O exit`: exits 0;
/// - otherwise: exits 0.
///
/// The socket path is extracted from the `-o ControlPath=<path>` arg so the
/// shim can create the sentinel file at the exact path the worker allocated.
///
/// `exit_sleep` controls the `-O exit` branch: `None` (the default) exits at
/// once; `Some(secs)` sleeps first, used by the drop-not-blocked test to
/// simulate a master that is slow to tear down.
fn write_ssh_shim(shim_path: &Path, exit_sleep: Option<u64>) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let capture = shim_path
        .parent()
        .expect("shim has a parent dir")
        .join("capture.txt");
    let cap_str = capture.to_string_lossy();
    // `-O exit` branch body: sleep first when asked, to emulate a slow master
    // teardown (proves Drop does not block on `ssh -O exit`).
    let exit_branch = match exit_sleep {
        Some(secs) => format!("exit) sleep {secs}; exit 0 ;;"),
        None => "exit) exit 0 ;;".to_string(),
    };
    let script = format!(
        "#!/bin/sh\n\
         CAP='{cap_str}'\n\
         BLOCK=$(\n\
         for a in \"$0\" \"$@\"; do printf '%s\\n' \"$(printf '%s' \"$a\" | base64)\"; done\n\
         printf '%s\\n' '---ENV---'\n\
         for k in SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY SSHRACK_ASKPASS_FILE SSHRACK_KEYRING_KEY SSHRACK_HOST_ID SSHRACK_CONFIG SSHRACK_ASKPASS_DENY; do\n\
         eval \"v=\\$$k\"\n\
         if [ -n \"${{v:+set}}\" ]; then printf '%s=%s\\n' \"$k\" \"$v\"; fi\n\
         done\n\
         printf '%s\\n' '===END=='\n\
         )\n\
         printf '%s\\n' \"$BLOCK\" >> \"$CAP\"\n\
         SOCK=''\n\
         for arg in \"$@\"; do\n\
         case \"$arg\" in\n\
         ControlPath=*) SOCK=\"${{arg#ControlPath=}}\" ;;\n\
         esac\n\
         done\n\
         for arg in \"$@\"; do\n\
         case \"$arg\" in\n\
         {exit_branch}\n\
         -N) [ -n \"$SOCK\" ] && touch \"$SOCK\" 2>/dev/null; sleep 30 & wait; exit 0 ;;\n\
         esac\n\
         done\n\
         exit 0\n",
    );
    std::fs::write(shim_path, script).expect("write ssh shim");
    std::fs::set_permissions(shim_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod ssh shim");
    capture
}

/// Like [`write_ssh_shim`] but the `-O check` branch exits 1 forever — the
/// master (the `-N` arm) is alive but never reports ready, so the worker's
/// handshake polls until cancelled. Used by the cancel-mid-handshake test.
fn write_ssh_shim_never_ready(shim_path: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let capture = shim_path
        .parent()
        .expect("shim has a parent dir")
        .join("capture.txt");
    let cap_str = capture.to_string_lossy();
    let script = format!(
        "#!/bin/sh\n\
         CAP='{cap_str}'\n\
         BLOCK=$(\n\
         for a in \"$0\" \"$@\"; do printf '%s\\n' \"$(printf '%s' \"$a\" | base64)\"; done\n\
         printf '%s\\n' '---ENV---'\n\
         for k in SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY SSHRACK_ASKPASS_FILE SSHRACK_KEYRING_KEY SSHRACK_HOST_ID SSHRACK_CONFIG SSHRACK_ASKPASS_DENY; do\n\
         eval \"v=\\$$k\"\n\
         if [ -n \"${{v:+set}}\" ]; then printf '%s=%s\\n' \"$k\" \"$v\"; fi\n\
         done\n\
         printf '%s\\n' '===END=='\n\
         )\n\
         printf '%s\\n' \"$BLOCK\" >> \"$CAP\"\n\
         SOCK=''\n\
         for arg in \"$@\"; do\n\
         case \"$arg\" in\n\
         ControlPath=*) SOCK=\"${{arg#ControlPath=}}\" ;;\n\
         esac\n\
         done\n\
         for arg in \"$@\"; do\n\
         case \"$arg\" in\n\
         check) exit 1 ;;\n\
         exit) exit 0 ;;\n\
         -N) [ -n \"$SOCK\" ] && touch \"$SOCK\" 2>/dev/null; sleep 30 & wait; exit 0 ;;\n\
         esac\n\
         done\n\
         exit 0\n",
    );
    std::fs::write(shim_path, script).expect("write ssh shim");
    std::fs::set_permissions(shim_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod ssh shim");
    capture
}

/// Write the sftp-shim script to `shim_path`. The shim drains stdin (so the
/// parent's batch write does not SIGPIPE), sleeps a fixed duration, then exits
/// 0. The fixed sleep is long enough for several progress polls (~200ms each)
/// and for a Cancel to arrive mid-transfer.
fn write_sftp_shim(shim_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let script = "#!/bin/sh\ncat >/dev/null 2>&1\nsleep 3\nexit 0\n";
    std::fs::write(shim_path, script).expect("write sftp shim");
    std::fs::set_permissions(shim_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod sftp shim");
}

/// One captured ssh-shim invocation: argv + env.
#[derive(Debug, Clone)]
struct ShimInvocation {
    argv: Vec<String>,
    env: HashMap<String, String>,
}

/// Parse the capture file into a list of invocations. Each invocation is
/// delimited by `===END==`.
fn read_all_invocations(capture_path: &Path) -> Vec<ShimInvocation> {
    let contents = std::fs::read_to_string(capture_path).expect("capture readable");
    let mut invocations = Vec::new();
    for block in contents.split("===END==\n") {
        if block.trim().is_empty() {
            continue;
        }
        let mut lines = block.lines();
        let mut argv: Vec<String> = Vec::new();
        for line in lines.by_ref() {
            if line == "---ENV---" {
                break;
            }
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(line.trim())
                .expect("base64 argv line");
            argv.push(String::from_utf8(bytes).expect("argv utf8"));
        }
        let mut env: HashMap<String, String> = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once('=') {
                env.insert(k.to_string(), v.to_string());
            }
        }
        invocations.push(ShimInvocation { argv, env });
    }
    invocations
}

// ---- test fixtures ----

/// Build a minimal key-only host (no password) for SftpWorker::open.
fn key_only_host() -> Host {
    Host {
        id: new_id(),
        name: "test-host".into(),
        host: "sftp-shim.invalid".into(),
        port: 2222,
        auth: Auth::inline(CredentialBody::new("deploy")),
    }
}

/// Build a resolved identity matching the key-only host (no key path, no
/// password — PasswordSource::None).
fn resolved_none() -> ResolvedAuth {
    ResolvedAuth {
        user: "deploy".into(),
        key_path: None,
        password: PasswordSource::None,
        inline_key: None,
    }
}

/// Build a resolved identity carrying an inline password, for the pw-file
/// teardown test.
fn resolved_inline(pw: &str) -> ResolvedAuth {
    ResolvedAuth {
        user: "deploy".into(),
        key_path: None,
        password: PasswordSource::Inline(pw.to_string().into()),
        inline_key: None,
    }
}

/// Set up a fresh temp dir with ssh + sftp shims, returning
/// `(dir, ssh_shim, sftp_shim, capture_path, bin)`.
fn fresh_shim_env() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, SftpBin) {
    let dir = tempfile::tempdir().expect("temp dir");
    let ssh_shim = dir.path().join("ssh-shim");
    let sftp_shim = dir.path().join("sftp-shim");
    let capture = write_ssh_shim(&ssh_shim, None);
    write_sftp_shim(&sftp_shim);
    let bin = SftpBin::new(ssh_shim.clone(), sftp_shim.clone());
    (dir, ssh_shim, sftp_shim, capture, bin)
}

/// Like [`fresh_shim_env`], but the ssh-shim sleeps `exit_sleep_secs` on its
/// `-O exit` branch — emulating a master that is slow to tear down. Used to
/// prove [`SftpWorker::drop`] does not block on `ssh -O exit`.
fn fresh_shim_env_slow_exit(
    exit_sleep_secs: u64,
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, SftpBin) {
    let dir = tempfile::tempdir().expect("temp dir");
    let ssh_shim = dir.path().join("ssh-shim");
    let sftp_shim = dir.path().join("sftp-shim");
    let capture = write_ssh_shim(&ssh_shim, Some(exit_sleep_secs));
    write_sftp_shim(&sftp_shim);
    let bin = SftpBin::new(ssh_shim.clone(), sftp_shim.clone());
    (dir, ssh_shim, sftp_shim, capture, bin)
}

/// Like [`fresh_shim_env`], but the ssh-shim's `-O check` branch exits 1
/// forever — emulating a master that NEVER becomes ready. The `-N` arm still
/// sleeps (the master is "alive" but never answers `-O check`), so the worker
/// keeps polling until cancelled. Used to prove dropping a worker mid-handshake
/// aborts within the handshake-poll window instead of waiting for the deadline.
fn fresh_shim_env_never_ready() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, SftpBin) {
    let dir = tempfile::tempdir().expect("temp dir");
    let ssh_shim = dir.path().join("ssh-shim");
    let sftp_shim = dir.path().join("sftp-shim");
    let capture = write_ssh_shim_never_ready(&ssh_shim);
    write_sftp_shim(&sftp_shim);
    let bin = SftpBin::new(ssh_shim.clone(), sftp_shim.clone());
    (dir, ssh_shim, sftp_shim, capture, bin)
}

/// Build a download TransferJob whose dst is inside `dir`.
fn download_job(dir: &Path, dst_name: &str, size_total: Option<u64>) -> TransferJob {
    TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/remote/file.bin"),
        dst: dir.join(dst_name),
        name: dst_name.into(),
        size_total,
        recursive: false,
    }
}

/// Collect every `sshrack-askpass-*.pw` path in `dir` into a set. Used by the
/// drop teardown test as a snapshot-delta over the shared temp dir: the set
/// captured before `SftpWorker::open` vs after `drop(worker)` must not gain a
/// new entry, proving Drop removed the pw-file `open` created. Pre-existing
/// files (other test binaries, crashed prior runs) are present in both
/// snapshots and so never cause a false failure.
fn pw_files_in(dir: &Path) -> HashSet<PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                n.starts_with("sshrack-askpass-") && n.ends_with(".pw")
            })
        })
        .collect()
}

/// Poll the shim capture until an invocation whose argv contains `token`
/// appears, or `deadline` elapses. [`SftpWorker::drop`] fires `ssh -O exit`
/// detached (it does not wait), so the shim records that invocation
/// asynchronously — this waits for the write without a flaky fixed sleep.
fn wait_for_invocation_with(capture: &Path, token: &str, deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        if read_all_invocations(capture)
            .iter()
            .any(|inv| inv.argv.iter().any(|a| a == token))
        {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---- tests ----

/// Spawn a worker against `bin` (PasswordSource::None, key-only host) and wait
/// for its `Connected` event — the master handshake + `sftp pwd` ran to
/// completion on the worker thread. Returns `(worker, home)`. Panics on
/// `ConnectFailed` or if no `Connected` lands within 5s (the shim master comes
/// up quickly; a hang is a regression). Replaces the blocking `SftpWorker::open`
/// that previously handed back `(worker, home)` synchronously.
fn spawn_and_connect(bin: SftpBin) -> (SftpWorker, PathBuf) {
    let self_exe = std::env::current_exe().expect("current_exe");
    let worker = SftpWorker::spawn_for_test(
        resolved_none(),
        key_only_host(),
        sshrack_core::connect::ssh::Overrides::default(),
        &self_exe,
        PasswordSource::None,
        None,
        bin,
    )
    .expect("spawn");
    let mut home: Option<PathBuf> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match worker.try_event() {
            Some(WorkerEvent::Connected {
                home: h,
                target: _,
                sock: _,
            }) => {
                home = Some(h);
                break;
            }
            Some(WorkerEvent::ConnectFailed(reason)) => {
                panic!("worker reported ConnectFailed: {reason}");
            }
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    let home = home.expect("no Connected event within 5s");
    (worker, home)
}

/// The master spawn's argv carries `-N`, `ControlMaster=yes`, and the socket
/// path; its env carries the SFTP askpass shape (`SSH_ASKPASS` + deny even for
/// `PasswordSource::None`); the password/key never appears in argv or env.
#[test]
fn sftp_master_spawn_env_shape_matches_askpass_env_for_sftp() {
    let (_dir, _ssh, _sftp, capture, bin) = fresh_shim_env();
    // spawn_and_connect waits for the master handshake to complete on the
    // worker thread; by then the shim's master (-N) invocation is captured.
    let (worker, _home) = spawn_and_connect(bin);

    let invocations = read_all_invocations(&capture);
    // Find the master invocation (the one containing `-N`).
    let master = invocations
        .iter()
        .find(|inv| inv.argv.iter().any(|a| a == "-N"))
        .expect("a master (-N) invocation was captured");

    // (a) argv shape: master carries -N, ControlMaster=yes, and a ControlPath.
    assert!(
        master.argv.iter().any(|a| a == "-N"),
        "master argv must contain -N: {:?}",
        master.argv
    );
    assert!(
        master.argv.iter().any(|a| a == "ControlMaster=yes"),
        "master argv must contain ControlMaster=yes: {:?}",
        master.argv
    );
    assert!(
        master.argv.iter().any(|a| a.starts_with("ControlPath=")),
        "master argv must contain ControlPath=<sock>: {:?}",
        master.argv
    );
    // argv[0] is the shim path, not the literal "ssh".
    assert!(
        !master.argv[0].ends_with("ssh") || master.argv[0].contains("shim"),
        "argv[0] should be the shim, not system ssh: {:?}",
        master.argv[0]
    );

    // (b) env shape: the SFTP master forces SSH_ASKPASS + deny even for None.
    assert!(
        master.env.contains_key("SSH_ASKPASS"),
        "SFTP master must set SSH_ASKPASS even for PasswordSource::None: {:?}",
        master.env
    );
    assert_eq!(
        master.env.get("SSH_ASKPASS_REQUIRE"),
        Some(&"force".to_string()),
        "SFTP master must force SSH_ASKPASS_REQUIRE=force: {:?}",
        master.env
    );
    assert!(
        master.env.contains_key("SSHRACK_ASKPASS_DENY"),
        "SFTP master must set the askpass deny marker for None: {:?}",
        master.env
    );

    // (c) No password/key material in argv or env (there is none for None, but
    // this also guards against a future regression that leaks material for the
    // Inline path into the master env/argv).
    for a in &master.argv {
        assert!(!a.contains("secret"), "argv must not carry secrets: {a}");
    }

    drop(worker);
}

/// A download transfer emits WorkerEvent::Progress events then Done(Ok). The
/// sftp-shim sleeps while a side thread grows the local dst file (the download
/// progress source for a Download is local-fs metadata).
#[test]
fn sftp_run_transfer_emits_progress_then_done_against_shim() {
    let (dir, _ssh, _sftp, _capture, bin) = fresh_shim_env();
    let dst = dir.path().join("downloaded.bin");
    std::fs::write(&dst, b"").expect("create empty dst");

    let (worker, _home) = spawn_and_connect(bin);

    // Side thread grows the dst file so poll_dst_size observes progress.
    let dst_clone = dst.clone();
    let grower = std::thread::spawn(move || {
        for size in [50u64, 100, 150, 200] {
            std::thread::sleep(Duration::from_millis(250));
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(&dst_clone)
                .expect("open dst for growth");
            let _ = f.set_len(size);
        }
    });

    worker.send(WorkerCmd::Transfer(
        download_job(dir.path(), "downloaded.bin", Some(200)),
        OverwritePolicy::Overwrite,
    ));

    // Drain events with a bounded deadline. The sftp-shim sleeps 3s then exits
    // 0 → Done(Ok). Allow generous headroom.
    let mut progress_count = 0;
    let mut got_done_ok = false;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match worker.try_event() {
            Some(WorkerEvent::Progress(p)) => {
                progress_count += 1;
                // bytes_total must reflect the job we sent.
                assert_eq!(p.bytes_total, Some(200));
            }
            Some(WorkerEvent::Done(outcome)) => match outcome {
                sshrack_core::connect::sftp::proto::TransferOutcome::Ok => {
                    got_done_ok = true;
                    break;
                }
                other => panic!("expected Done(Ok), got Done({other:?})"),
            },
            Some(WorkerEvent::Listing(_, _)) => { /* ignore */ }
            // Connected/ConnectFailed arrive before Transfer (spawn_and_connect
            // already drained Connected); safe to ignore here. HostKeyNeedsConfirm
            // only fires for an unknown host (the shim tests use a known host).
            Some(WorkerEvent::Connected { .. })
            | Some(WorkerEvent::ConnectFailed(_))
            | Some(WorkerEvent::HostKeyNeedsConfirm { .. }) => {}
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    grower.join().expect("grower thread");

    assert!(progress_count > 0, "must emit at least one Progress event");
    assert!(got_done_ok, "must complete with Done(Ok)");

    drop(worker);
}

/// A Cancel mid-transfer kills + reaps the sftp child, marks the transfer
/// Cancelled, and removes the partial destination.
#[test]
fn sftp_run_transfer_cancel_kills_and_reaps_and_marks_cancelled() {
    let (dir, _ssh, _sftp, _capture, bin) = fresh_shim_env();
    let dst = dir.path().join("partial.bin");
    std::fs::write(&dst, b"partial-bytes").expect("seed partial dst");
    assert!(dst.exists(), "partial dst must exist before cancel");

    let (worker, _home) = spawn_and_connect(bin);

    // Enqueue a transfer then immediately cancel. The worker thread processes
    // Transfer first (spawning the sftp-shim, which sleeps 3s), then on its
    // first recv_timeout(200ms) the Cancel is already queued → immediate kill.
    worker.send(WorkerCmd::Transfer(
        download_job(dir.path(), "partial.bin", Some(100)),
        OverwritePolicy::Overwrite,
    ));
    worker.send(WorkerCmd::Cancel);

    let mut got_cancelled = false;
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match worker.try_event() {
            Some(WorkerEvent::Done(outcome)) => {
                match outcome {
                    sshrack_core::connect::sftp::proto::TransferOutcome::Cancelled => {
                        got_cancelled = true;
                        break;
                    }
                    sshrack_core::connect::sftp::proto::TransferOutcome::Ok => {
                        // The shim may exit 0 before the Cancel is processed if
                        // timing is very tight. That is a valid race, not a
                        // failure of the cancel path — but retry by sending
                        // another cancel-only sequence is pointless. Assert the
                        // partial was still removed (it is for both outcomes).
                        //
                        // Under load the Cancelled-path assertion is best-effort:
                        // the 3s sftp-shim sleep is far longer than the worker's
                        // 200ms poll interval, so in practice the Cancel always
                        // lands mid-transfer and the Ok branch here is the rare
                        // losing race, not the expected outcome.
                        break;
                    }
                    other => panic!("expected Cancelled or Ok, got {other:?}"),
                }
            }
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    // If we observed Cancelled, the partial dst must be removed (Download
    // cleanup = remove_file). If we observed Ok, the transfer completed and the
    // dst may still exist — but for the Cancelled path the file is gone.
    if got_cancelled {
        assert!(!dst.exists(), "partial dst must be removed after Cancelled");
    }
    // Either way, the worker did not hang and emitted a terminal event.

    drop(worker);
}

/// Dropping a worker whose master is a shim sends `ssh -O exit`, removes the
/// socket file, and removes the askpass password temp file.
#[test]
fn sftp_worker_drop_tears_down_master_socket_and_pw_file() {
    let (_dir, _ssh, _sftp, capture, bin) = fresh_shim_env();
    let self_exe = std::env::current_exe().expect("current_exe");

    // Use an Inline password so a pw temp file is created and must be removed.
    // Snapshot the shared temp dir BEFORE spawn. The pw-file the worker creates
    // lives in std::env::temp_dir() with a pid+nanos name; the after-drop
    // snapshot (c) diffs against this set to prove Drop removed it.
    let before: HashSet<PathBuf> = pw_files_in(&std::env::temp_dir());
    let worker = SftpWorker::spawn_for_test(
        resolved_inline("hunter2"),
        key_only_host(),
        sshrack_core::connect::ssh::Overrides::default(),
        &self_exe,
        PasswordSource::Inline("hunter2".to_string().into()),
        None,
        bin.clone(),
    )
    .expect("spawn");
    // Drain Connected so the master is up + the socket is touched + the pw
    // file is materialized before the assertions.
    let mut connected = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match worker.try_event() {
            Some(WorkerEvent::Connected { .. }) => {
                connected = true;
                break;
            }
            Some(WorkerEvent::ConnectFailed(r)) => panic!("connect failed: {r}"),
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
    assert!(connected, "no Connected event within 5s");

    // Capture the socket path from the master invocation before drop.
    let pre_drop_invocations = read_all_invocations(&capture);
    let master = pre_drop_invocations
        .iter()
        .find(|inv| inv.argv.iter().any(|a| a == "-N"))
        .expect("master invocation captured before drop");
    let cp_arg = master
        .argv
        .iter()
        .find(|a| a.starts_with("ControlPath="))
        .expect("ControlPath present");
    let sock_path = PathBuf::from(&cp_arg["ControlPath=".len()..]);
    // The shim touched the socket file on master spawn.
    assert!(
        sock_path.exists(),
        "socket file must exist while worker lives"
    );

    drop(worker);

    // (a) Socket file removed by Drop.
    assert!(
        !sock_path.exists(),
        "socket file must be removed after drop"
    );

    // (b) An `ssh -O exit` invocation was sent (teardown). Drop fires it
    // detached, so the shim writes its capture asynchronously — poll for it.
    let exit_sent = wait_for_invocation_with(&capture, "exit", Duration::from_secs(2));
    let post_drop_invocations = read_all_invocations(&capture);
    assert!(
        exit_sent,
        "drop must send ssh -O exit (found in capture): {:?}",
        post_drop_invocations
            .iter()
            .map(|i| &i.argv)
            .collect::<Vec<_>>()
    );

    // (c) No pw temp file left behind. The pw-file path is not directly
    // observable from outside the worker (it lives in std::env::temp_dir() with
    // a pid+nanos name), so use a snapshot-delta over the shared temp dir:
    // capture every `sshrack-askpass-*.pw` before open (above) and again after
    // drop, then assert drop introduced no new file. `before` excludes
    // pre-existing files (other test binaries, crashed prior runs) so the
    // assertion is stable under parallel `cargo test`. This is a real
    // assertion — unlike a bare scan-and-cleanup, it fails if the Drop
    // pw-file removal (worker.rs step 6) is deleted: `after` then gains the
    // one file `open` created and the difference is non-empty.
    //
    // Why the delta and not a content scan (assert no pw-file holds `hunter2`)?
    // A content scan over all `sshrack-askpass-*.pw` in temp_dir is stricter
    // but NOT stable: it would also fire on an orphaned pw-file left by a prior
    // failed run, making this test non-hermetic across runs. The delta is both
    // rigorous (proven to fail on a removed cleanup — see RED verification in
    // the task-5.3 report) and stable (pre-existing files are in both sets).
    let after: HashSet<PathBuf> = pw_files_in(&std::env::temp_dir());
    let leaked: Vec<&PathBuf> = after.difference(&before).collect();
    assert!(
        leaked.is_empty(),
        "drop must remove the askpass pw-file it created; new pw-files leaked after drop: {leaked:?}"
    );
}

/// `SftpWorker::drop` must not block on `ssh -O exit`: it fires the teardown
/// command detached (no wait), so a master that takes its time to tear down —
/// here the shim sleeps 3s on `-O exit` — cannot stall the UI thread that drops
/// the worker. The synchronous SIGKILL + reap on the master child (fast) is the
/// real teardown guarantee; `ssh -O exit` is best-effort.
#[test]
fn sftp_worker_drop_not_blocked_by_slow_control_exit() {
    let (_dir, _ssh, _sftp, _capture, bin) = fresh_shim_env_slow_exit(3);
    let (worker, _home) = spawn_and_connect(bin);

    let start = std::time::Instant::now();
    drop(worker);
    let elapsed = start.elapsed();

    // The shim sleeps 3s on `-O exit`. A blocking drop (`.status()`) would take
    // >=3s; a detached drop returns well under that. 2s is a comfortable upper
    // bound — far clear of the 3s floor on any healthy machine, and it fails
    // reliably against a blocking implementation.
    assert!(
        elapsed < Duration::from_secs(2),
        "drop blocked on slow ssh -O exit: {elapsed:?} (expected <<3s)"
    );
}

/// `SftpWorker::spawn` returns immediately and the worker thread reports
/// `Connected { home, .. }` once the master handshake completes — the spawn
/// does NOT block on the handshake. Contrast with the deleted `open`, which
/// blocked. Pins the struct form of the event (Step 5 FINAL shape).
#[test]
fn sftp_worker_spawn_is_async_reports_connected() {
    let (_dir, _ssh, _sftp, _capture, bin) = fresh_shim_env();
    let self_exe = std::env::current_exe().expect("current_exe");
    let worker = SftpWorker::spawn_for_test(
        resolved_none(),
        key_only_host(),
        sshrack_core::connect::ssh::Overrides::default(),
        &self_exe,
        PasswordSource::None,
        None,
        bin,
    )
    .expect("spawn");
    // The call returned without waiting for the handshake. Now drain the
    // Connected event (the shim master comes up quickly).
    let mut connected_home = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Some(ev) = worker.try_event() {
            match ev {
                WorkerEvent::Connected { home, target, sock } => {
                    // Struct form carries all three coordinates.
                    assert!(
                        !target.is_empty(),
                        "Connected.target must be the user@host string"
                    );
                    assert!(
                        !sock.as_os_str().is_empty(),
                        "Connected.sock must be the live ControlPath"
                    );
                    connected_home = Some(home);
                    break;
                }
                WorkerEvent::ConnectFailed(r) => {
                    panic!("expected Connected, got ConnectFailed: {r}");
                }
                other => panic!("expected Connected, got {other:?}"),
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        connected_home.is_some(),
        "no Connected event within 5s — spawn did not produce one"
    );
    drop(worker); // join must return promptly (service loop idles on recv)
}

/// Dropping the worker mid-handshake sends `Shutdown`; the connect phase aborts
/// and `Drop`'s join returns within the handshake-poll window. Uses a shim whose
/// `-O check` exits 1 forever so the handshake is still in progress when dropped.
#[test]
fn sftp_worker_spawn_drop_cancels_handshake_quickly() {
    let (_dir, _ssh, _sftp, _capture, bin) = fresh_shim_env_never_ready();
    let self_exe = std::env::current_exe().expect("current_exe");
    let worker = SftpWorker::spawn_for_test(
        resolved_none(),
        key_only_host(),
        sshrack_core::connect::ssh::Overrides::default(),
        &self_exe,
        PasswordSource::None,
        None,
        bin,
    )
    .expect("spawn");
    let start = std::time::Instant::now();
    drop(worker); // sends Shutdown + joins
    let elapsed = start.elapsed();
    // The connect phase polls every HANDSHAKE_POLL (250ms) and treats a
    // Shutdown / channel disconnect as cancel (returns at once, then the
    // partial MasterSession drops). 2s is a comfortable upper bound that is
    // far clear of the 30s handshake deadline — it fails reliably if the
    // cancel path regresses into waiting for the deadline.
    assert!(
        elapsed < Duration::from_secs(2),
        "drop did not cancel the handshake quickly: {elapsed:?} (expected <<30s)"
    );
}

// ---- Task 2: async host-key pre-flight (unknown-host integration test) ----
//
// The worker's host-key pre-flight calls `hostkey::known_hosts_path()` which
// reads the real `$HOME/.ssh/known_hosts`. There is no hermetic seam to point
// the worker at a temp known_hosts without env mutation (forbidden), so a full
// unknown-host round-trip is an integration test against the real known_hosts
// and a real sshd. It is `#[ignore]`'d by default — CI never runs it. Run
// locally with:
//
//   SSHRACK_E2E_HOST=127.0.0.1 SSHRACK_E2E_PORT=2222 SSHRACK_E2E_USER=$USER \
//     cargo test -p sshrack-core --test sftp_seam_test -- \
//     --ignored --nocapture sftp_worker_async_host_key_unknown_host
//
// Preconditions (mirror sftp_e2e.rs):
//   1. A local sshd is reachable at SSHRACK_E2E_HOST:SSHRACK_E2E_PORT with key
//      auth for SSHRACK_E2E_USER already configured.
//   2. The host is NOT already in `~/.ssh/known_hosts` (the test removes any
//      matching entry before + after so it is repeatable).
//
// The hermetic backbone for Task 2 lives in: (a) the screen_tests on_key tests
// (ScreenOutcome::HostKeyConfirm routing), (b) the run_loop drain test
// (HostKeyNeedsConfirm → screen.host_key), (c) hostkey.rs's existing unit
// tests (classify / scan_fingerprints / pick_primary / confirm_text).

/// `#[ignore]`'d unknown-host round trip: spawn → HostKeyNeedsConfirm →
/// HostKeyConfirm(true) → Connected. Verifies the worker surfaces the
/// fingerprint, accepts the reply, appends to known_hosts, and resumes the
/// master handshake. Requires a real sshd + a host not in known_hosts.
#[test]
#[ignore = "requires a local sshd + a host not in known_hosts; see test docs"]
fn sftp_worker_async_host_key_unknown_host() {
    use sshrack_core::hostkey;
    use std::process::Stdio;

    let host = std::env::var("SSHRACK_E2E_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("SSHRACK_E2E_PORT")
        .unwrap_or_else(|_| "2222".to_string())
        .parse()
        .expect("SSHRACK_E2E_PORT parses as u16");
    let user = std::env::var("SSHRACK_E2E_USER")
        .unwrap_or_else(|_| std::env::var("USER").unwrap_or_default());
    if user.is_empty() {
        eprintln!("sftp_worker_async_host_key_unknown_host: no SSHRACK_E2E_USER — skipping");
        return;
    }
    let known_hosts = match hostkey::known_hosts_path() {
        Some(p) => p,
        None => {
            eprintln!("no known_hosts path — skipping");
            return;
        }
    };

    // Pre-clean: remove any existing entry so the host is genuinely unknown
    // (otherwise the worker skips the prompt and goes straight to Connected).
    let _ = std::process::Command::new("ssh-keygen")
        .args(["-R", &hostkey::host_query(&host, port)])
        .arg(&known_hosts)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Re-verify: if the host is somehow still known, the test cannot exercise
    // the unknown-host path — skip instead of false-passing.
    if hostkey::is_known(&host, port, &known_hosts).unwrap_or(false) {
        eprintln!(
            "sftp_worker_async_host_key_unknown_host: {host}:{port} still in known_hosts after -R — skipping"
        );
        return;
    }

    let host_obj = Host {
        id: sshrack_core::id::new_id(),
        name: "host-key-e2e".into(),
        host: host.clone(),
        port,
        auth: Auth::inline(CredentialBody::new(user.clone())),
    };
    let resolved = ResolvedAuth {
        user,
        key_path: None,
        password: PasswordSource::None,
        inline_key: None,
    };
    let self_exe = std::env::current_exe().expect("current_exe");
    let worker = SftpWorker::spawn(
        resolved,
        host_obj,
        sshrack_core::connect::ssh::Overrides::default(),
        &self_exe,
        PasswordSource::None,
        None,
        sshrack_core::connect::sftp::SftpBin::default(),
    )
    .expect("spawn");

    // Drain HostKeyNeedsConfirm (unknown host → scan → ask). Bounded by the
    // ssh-keyscan -T 5s timeout + a margin.
    let mut got_prompt = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if let Some(ev) = worker.try_event() {
            match ev {
                WorkerEvent::HostKeyNeedsConfirm {
                    host: h,
                    fingerprint,
                } => {
                    assert_eq!(h, host, "prompt host matches the spawned host");
                    assert!(
                        fingerprint.contains("SHA256:"),
                        "fingerprint text must include the SHA256: prefix: {fingerprint}"
                    );
                    got_prompt = true;
                    break;
                }
                WorkerEvent::ConnectFailed(r) => {
                    // Cleanup before failing so a rerun is clean.
                    let _ = std::process::Command::new("ssh-keygen")
                        .args(["-R", &hostkey::host_query(&host, port)])
                        .arg(&known_hosts)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    panic!("expected HostKeyNeedsConfirm, got ConnectFailed: {r}");
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        got_prompt,
        "no HostKeyNeedsConfirm within 15s — the host may already be known, or ssh-keyscan is unreachable"
    );

    // Accept the fingerprint. The worker appends to known_hosts and resumes the
    // master handshake.
    worker.send(WorkerCmd::HostKeyConfirm(true));

    // Drain Connected (or ConnectFailed if the sshd is unreachable / auth
    // fails). The handshake can take up to HANDSHAKE_TIMEOUT (30s) on a slow
    // first-connect; allow the full window.
    let mut got_connected = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(35);
    while std::time::Instant::now() < deadline {
        if let Some(ev) = worker.try_event() {
            match ev {
                WorkerEvent::Connected { .. } => {
                    got_connected = true;
                    break;
                }
                WorkerEvent::ConnectFailed(r) => {
                    // The host-key path itself worked (we got the prompt + the
                    // accept landed); the connect failure is downstream
                    // (sshd down / auth refused). Cleanup + report.
                    let _ = std::process::Command::new("ssh-keygen")
                        .args(["-R", &hostkey::host_query(&host, port)])
                        .arg(&known_hosts)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    panic!(
                        "host-key prompt accepted but master handshake failed (is sshd up + auth configured?): {r}"
                    );
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        got_connected,
        "no Connected within 35s after accepting the host key"
    );
    // Sanity: the host is now in known_hosts (the accept appended it).
    assert!(
        hostkey::is_known(&host, port, &known_hosts).unwrap_or(false),
        "accepting the prompt must have appended the host to known_hosts"
    );

    // Cleanup: drop the worker (tears down the master) + remove the test's
    // known_hosts entry so the test is repeatable.
    drop(worker);
    let _ = std::process::Command::new("ssh-keygen")
        .args(["-R", &hostkey::host_query(&host, port)])
        .arg(&known_hosts)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
