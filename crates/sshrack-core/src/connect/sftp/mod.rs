//! SFTP-over-ControlMaster argv builders.
//!
//! SFTP transfer reuses the system `ssh` + `sftp` binaries over a single
//! shared [`ControlMaster`] connection — no SSH protocol reimplementation
//! (sshrack never sits in the data stream). This module assembles the argv for
//! the three processes that cooperate:
//!
//! 1. **Master** (`[`argv::master_argv`]`) — `ssh -N` with `ControlMaster=yes`
//!    plus the same connection options (`-l/-p/-i`) as an interactive `ssh`,
//!    holding the muxed connection open in the background.
//! 2. **sftp client** (`[`argv::sftp_batch_argv`]`) — `sftp -b -` mounting the
//!    master via `ControlPath` only. It carries NO `-P/-i/-J`: the master
//!    already negotiated port and identity, and this sidesteps the ssh `-p` vs
//!    sftp `-P` flag clash.
//! 3. **Control messages** (`[`argv::control_check_argv`]` / `[`argv::control_exit_argv`]`)
//!    — `ssh -O check|exit` for readiness poll and teardown.
//!
//! The control socket lives under `$XDG_RUNTIME_DIR` (falling back to the std
//! temp dir), never `/tmp`, and is unique per process/session via a pid + an
//! in-process counter so concurrent sshrack sftp sessions never collide.
//!
//! [`ControlMaster`]: https://www.openssh.com/cgi-bin/man.cgi?q=ssh_config#ControlMaster

pub mod argv;
pub use argv::{
    control_check_argv, control_exit_argv, control_socket_path, master_argv, runtime_dir,
    sftp_batch_argv, sftp_target, shell_quote,
};

pub mod parse;
pub use parse::{RawLsEntry, parse_ls_line, parse_ls_listing, strip_control_chars, to_dir_entries};

pub mod proto;
pub use proto::{
    Direction, OverwritePolicy, Progress, TransferJob, TransferOutcome, WorkerCmd, WorkerEvent,
    get_batch, list_batch, progress_snapshot, put_batch, pwd_batch,
};

pub mod source;
pub use source::{LocalSftpRunner, SftpDirSource, SftpRunner};

pub mod pure;
pub use pure::parse_remote_home;

pub mod worker;
pub use worker::{HANDSHAKE_TIMEOUT, SftpWorker};

use std::path::{Path, PathBuf};

/// RAII over the control socket path. [`ControlSocket::new`] allocates a unique
/// path under [`control_socket_path`]; `Drop` removes the file (best-effort —
/// the master may not have created it yet, and a stale removal must never
/// panic). The master `ssh -O exit` is issued by [`SftpWorker`]'s `Drop`
/// BEFORE the socket file removal so the background `ssh -N` exits cleanly.
///
/// The socket file is the rendezvous point between the master `ssh -N` process
/// and the `sftp`/`ssh -O check` mounts; owning its path here keeps cleanup
/// tied to the worker's lifetime even on a panic.
#[derive(Debug)]
pub struct ControlSocket {
    path: PathBuf,
}

impl ControlSocket {
    /// Allocate a fresh, unique control socket path. The path is not created —
    /// the master `ssh -N` creates the socket itself once it connects. Two
    /// consecutive calls yield distinct paths (via the in-process counter in
    /// [`control_socket_path`]).
    pub fn new() -> Self {
        Self {
            path: control_socket_path(),
        }
    }

    /// The allocated socket path. Pass to `ssh -o ControlPath=...` /
    /// `sftp -o ControlPath=...`.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for ControlSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        // Best-effort: the master may have created the socket, may not have, or
        // the runtime dir may have been cleared. Never panic on cleanup.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod control_socket_tests {
    use super::*;

    #[test]
    fn new_returns_path_under_runtime_dir() {
        let sock = ControlSocket::new();
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let dir = runtime_dir(xdg.as_deref());
        assert!(
            sock.path().starts_with(&dir),
            "socket {:?} must live under runtime dir {:?}",
            sock.path(),
            dir
        );
    }

    #[test]
    fn two_new_calls_yield_distinct_paths() {
        // The in-process counter must keep concurrent sshrack sftp sessions from
        // colliding on one socket file.
        let a = ControlSocket::new();
        let b = ControlSocket::new();
        assert_ne!(
            a.path(),
            b.path(),
            "consecutive ControlSocket::new() calls must yield distinct paths"
        );
    }

    #[test]
    fn drop_removes_a_file_placed_at_the_path() {
        // The path is allocated but never created by ControlSocket itself; the
        // master creates it. Simulate that by placing a sentinel file at the
        // path, then dropping the socket — Drop must remove it.
        let sock = ControlSocket::new();
        let path = sock.path().to_path_buf();
        // Ensure the parent dir exists (XDG_RUNTIME_DIR may not be set in CI).
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&path, b"sentinel").expect("write sentinel");
        assert!(path.exists(), "sentinel must exist before drop");
        drop(sock);
        assert!(
            !path.exists(),
            "Drop must remove the file at the socket path"
        );
    }

    #[test]
    fn drop_does_not_panic_when_file_missing() {
        // The master may not have created the socket yet (handshake failed).
        // Drop must swallow the not-found error, not panic.
        let sock = ControlSocket::new();
        // No file at sock.path() — Drop runs remove_file and discards the err.
        drop(sock);
    }
}
