//! Pure helpers extracted from [`super::worker`] — the thread/spawn-free,
//! I/O-free pieces that can be unit-tested without a real sshd. Kept here so
//! `worker.rs` stays under the 800-line file-size guideline while the pure
//! logic (the load-bearing `Shutdown` classification in particular) stays
//! visible and pinned by tests. These helpers do NOT touch the OS process
//! tree, the master socket, or any `SftpRunner` — they are pure transforms
//! of stdout text and `WorkerCmd` values.

use std::path::PathBuf;
use std::time::SystemTime;

use crate::connect::sftp::parse::parse_ls_line;
use crate::connect::sftp::proto::WorkerCmd;

/// Parse sftp `pwd` stdout to extract the remote working directory. sftp emits
/// `Remote working directory: <path>`; this returns the first matching line's
/// path, trimmed. Pure (no I/O).
pub fn parse_remote_home(stdout: &str) -> Option<PathBuf> {
    stdout.lines().find_map(|line| {
        line.strip_prefix("Remote working directory: ")
            .map(|s| PathBuf::from(s.trim()))
    })
}

/// Parse the size field out of the first parseable `ls -l` file row in
/// `stdout`. Used by upload progress polling to read the partial remote file
/// size. Skips non-file lines — critically the `sftp> <command>` prompt echo
/// that `sftp -b -` writes to stdout before the result, which would otherwise
/// be the first non-blank line and parse as `None`, leaving upload progress
/// stuck at 0% for the whole transfer. Returns `None` when no file row is
/// found. Pure (the `now` is only used for year inference inside
/// [`parse_ls_line`]; size does not depend on it).
pub(crate) fn parse_size_from_ls(stdout: &str, now: SystemTime) -> Option<u64> {
    stdout
        .lines()
        .find_map(|line| parse_ls_line(line, now)?.size)
}

/// What [`run_transfer`] should do with a command that arrived mid-transfer.
/// Pure (no I/O) — unit-tested directly via [`classify_inflight_cmd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InflightAction {
    /// Keep polling: the command is not meaningful mid-transfer (e.g. an
    /// unexpected `Transfer` or `List` the UI shouldn't have sent while a
    /// transfer is in flight).
    Continue,
    /// Cancel the in-flight transfer: kill child, reap, remove partial.
    Cancel,
    /// Propagate teardown: kill child, reap, remove partial, and tell
    /// [`worker_loop`] to `break` instead of looping back to `recv()`.
    Shutdown,
}

/// Classify a command that arrived while a transfer is in flight. Pure (no
/// I/O) — the caller ([`run_transfer`]) applies the resulting [`InflightAction`].
///
/// `Cancel` cancels the in-flight transfer. `Shutdown` propagates teardown —
/// this is load-bearing: swallowing `Shutdown` deadlocks `Drop`, which is
/// `join`-blocked waiting for the worker to exit while still holding `cmd_tx`
/// (the worker would loop back to `recv()` and block forever on a channel
/// whose sender is never dropped). Any other command (`Transfer` / `List`
/// arriving mid-flight) is dropped → [`InflightAction::Continue`].
pub(crate) fn classify_inflight_cmd(cmd: &WorkerCmd) -> InflightAction {
    match cmd {
        WorkerCmd::Cancel => InflightAction::Cancel,
        WorkerCmd::Shutdown => InflightAction::Shutdown,
        WorkerCmd::List(_) | WorkerCmd::Transfer(_, _) => InflightAction::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::sftp::proto::{Direction, OverwritePolicy, TransferJob};

    // ---- classify_inflight_cmd (the load-bearing Shutdown propagation) ----

    #[test]
    fn classify_inflight_cmd_shutdown_propagates() {
        // CRITICAL: Shutdown must map to InflightAction::Shutdown so run_transfer
        // can break worker_loop instead of looping back to recv(). Swallowing it
        // (the prior Ok(_) arm) deadlocks Drop: the dropping main thread holds
        // cmd_tx until join() returns, and join() waits for the worker — which
        // would block forever in recv() on a sender that is never dropped.
        assert_eq!(
            classify_inflight_cmd(&WorkerCmd::Shutdown),
            InflightAction::Shutdown
        );
    }

    #[test]
    fn classify_inflight_cmd_cancel_cancels() {
        assert_eq!(
            classify_inflight_cmd(&WorkerCmd::Cancel),
            InflightAction::Cancel
        );
    }

    #[test]
    fn classify_inflight_cmd_unexpected_commands_continue() {
        // Transfer / List arriving mid-transfer are dropped → Continue (the UI
        // serializes commands and waits for Done before sending the next; an
        // unexpected mid-flight cmd must NOT kill the child or the partial).
        assert_eq!(
            classify_inflight_cmd(&WorkerCmd::List(PathBuf::from("/srv"))),
            InflightAction::Continue
        );
        let job = TransferJob {
            direction: Direction::Download,
            src: PathBuf::from("/remote/x"),
            dst: PathBuf::from("/local/x"),
            name: "x".into(),
            size_total: None,
            recursive: false,
        };
        assert_eq!(
            classify_inflight_cmd(&WorkerCmd::Transfer(job, OverwritePolicy::Overwrite)),
            InflightAction::Continue
        );
    }

    // ---- parse_remote_home ----

    #[test]
    fn parse_remote_home_extracts_path_from_pwd_line() {
        let stdout = "Remote working directory: /home/deploy\n";
        assert_eq!(
            parse_remote_home(stdout),
            Some(PathBuf::from("/home/deploy"))
        );
    }

    #[test]
    fn parse_remote_home_handles_trailing_whitespace() {
        // sftp output on some platforms carries a trailing CR; trim handles it.
        let stdout = "Remote working directory: /home/u  \r\n";
        assert_eq!(parse_remote_home(stdout), Some(PathBuf::from("/home/u")));
    }

    #[test]
    fn parse_remote_home_finds_first_match_among_other_lines() {
        // sftp may print other lines (prompt echo, etc.); the parser picks the
        // one bearing the prefix.
        let stdout = "sftp> pwd\nRemote working directory: /root\nsftp> quit\n";
        assert_eq!(parse_remote_home(stdout), Some(PathBuf::from("/root")));
    }

    #[test]
    fn parse_remote_home_none_when_no_match() {
        assert_eq!(parse_remote_home(""), None);
        assert_eq!(parse_remote_home("some unrelated text\n"), None);
    }

    // ---- parse_size_from_ls ----

    #[test]
    fn parse_size_from_ls_extracts_file_size() {
        let stdout = "-rw-r--r-- 1 user group 1234 Jan 2 03:04 /tmp/file\n";
        assert_eq!(parse_size_from_ls(stdout, SystemTime::now()), Some(1234));
    }

    #[test]
    fn parse_size_from_ls_none_for_directory_row() {
        // Dirs report None — size polling for a recursive upload dst reports
        // "unknown" and progress just shows indeterminate.
        let stdout = "drwxr-xr-x 2 user group 4096 Jan 2 03:04 /tmp/dir\n";
        assert_eq!(parse_size_from_ls(stdout, SystemTime::now()), None);
    }

    #[test]
    fn parse_size_from_ls_none_on_empty_or_unparseable() {
        assert_eq!(parse_size_from_ls("", SystemTime::now()), None);
        assert_eq!(parse_size_from_ls("total 8\n", SystemTime::now()), None);
    }

    #[test]
    fn parse_size_from_ls_skips_sftp_prompt_echo() {
        // `sftp -b -` echoes the `sftp> <command>` prompt line to stdout
        // before the result row. The FIRST non-blank line is the prompt echo,
        // not the ls row — parse must skip it and read the file row's size, or
        // upload progress polling reads 0 for the whole transfer (the
        // "active-transfer row stays at 0% until done" bug).
        let stdout = "sftp> ls -l \"/tmp/foo.bin\"\n\
                      -rw-r--r--    ? ryan     ryan     81469440 Jul 10 11:25 /tmp/foo.bin\n\
                      sftp> quit\n";
        assert_eq!(
            parse_size_from_ls(stdout, SystemTime::now()),
            Some(81469440)
        );
    }

    #[test]
    fn parse_size_from_ls_skips_total_line_then_file() {
        // `ls -l` emits a `total N` summary header before the file rows. The
        // parser must skip it (total parses as None) and read the file row's
        // size — existing tests only cover `total 8\n` alone (→ None), not the
        // header-followed-by-file shape that real upload polling sees.
        let stdout = "total 8\n-rw-r--r-- 1 u g 1234 Jan 2 03:04 /a\n";
        assert_eq!(parse_size_from_ls(stdout, SystemTime::now()), Some(1234));
    }

    #[test]
    fn parse_size_from_ls_uses_first_non_blank_line() {
        // A multi-line stdout: the first non-blank row's size wins.
        let stdout = "\n-rw-r--r-- 1 u g 99 Jan 2 03:04 /a\n-rw-r--r-- 1 u g 1 Jan 2 03:04 /b\n";
        assert_eq!(parse_size_from_ls(stdout, SystemTime::now()), Some(99));
    }
}
