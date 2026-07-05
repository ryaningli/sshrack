//! SFTP worker protocol types, batch builders, and progress math.
//!
//! Pure helpers that assemble sftp batch scripts and compute rate/ETA from
//! polled byte offsets. No I/O.

use std::path::{Path, PathBuf};

use crate::connect::sftp::shell_quote;

// ---- Direction ----

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    Upload,
    #[default]
    Download,
}

// ---- TransferJob ----

/// One transfer the worker runs. `size_total` is the source file's size
/// (best-effort; used for the percentage + ETA when known).
#[derive(Debug, Clone)]
pub struct TransferJob {
    pub direction: Direction,
    pub src: PathBuf, // local for Upload, remote for Download
    pub dst: PathBuf,
    pub name: String, // display name
    pub size_total: Option<u64>,
    pub recursive: bool,
}

// ---- OverwritePolicy ----

/// User's answer to a same-name conflict. `OverwriteAll`/`SkipAll` apply to
/// the rest of the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    Overwrite,
    Skip,
    OverwriteAll,
    SkipAll,
}

// ---- WorkerCmd ----

/// Command sent from the main thread to the SFTP worker.
#[derive(Debug, Clone)]
pub enum WorkerCmd {
    List(PathBuf), // remote cwd to list
    Transfer(TransferJob, OverwritePolicy),
    Cancel,   // kill the in-flight transfer + delete partial
    Shutdown, // teardown master + exit thread
}

// ---- WorkerEvent ----

/// Event sent from the SFTP worker to the main thread.
#[derive(Debug, Clone)]
pub enum WorkerEvent {
    Ready(Result<PathBuf, String>), // master up; home path (or error)
    Listing(PathBuf, Result<Vec<DirEntry>, String>), // entries for cwd (or error msg)
    Progress(Progress),
    Done(TransferOutcome),
}

// ---- Progress ----

/// Transfer progress snapshot. Updated on each tick.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub name: String,
    pub direction: Direction,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub rate_bps: Option<u64>,
    pub eta_secs: Option<u64>,
}

// ---- TransferOutcome ----

/// Final result of a transfer job.
#[derive(Debug, Clone)]
pub enum TransferOutcome {
    Ok,
    Cancelled,
    Failed(String),
}

// ---- DirEntry ----

/// A single directory entry returned by `sftp ls -l`.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<String>,
}

// ---- batch builders ----

/// Build an `ls -l` batch script for listing a remote directory.
pub fn list_batch(path: &Path) -> String {
    format!("ls -l {}\nquit\n", shell_quote(&path.to_string_lossy()))
}

/// Build a `pwd` batch script for printing the current remote directory.
pub fn pwd_batch() -> String {
    "pwd\nquit\n".to_string()
}

/// Build a `get` batch script for downloading a file/directory.
pub fn get_batch(src: &Path, dst: &Path, recursive: bool) -> String {
    let flag = if recursive { "-r " } else { "" };
    format!(
        "{}get {} {}\nquit\n",
        flag,
        shell_quote(&src.to_string_lossy()),
        shell_quote(&dst.to_string_lossy())
    )
}

/// Build a `put` batch script for uploading a file/directory.
pub fn put_batch(src: &Path, dst: &Path, recursive: bool) -> String {
    let flag = if recursive { "-r " } else { "" };
    format!(
        "{}put {} {}\nquit\n",
        flag,
        shell_quote(&src.to_string_lossy()),
        shell_quote(&dst.to_string_lossy())
    )
}

// ---- progress math ----

/// Compute rate + ETA from the delta between samples.
///
/// # Arguments
/// * `prev_done` - previous bytes done
/// * `prev_secs` - previous time (seconds since epoch)
/// * `cur_done` - current bytes done
/// * `cur_secs` - current time (seconds since epoch)
/// * `total` - total bytes (for ETA computation)
///
/// # Returns
/// * `(rate_bps, eta_secs)` - rate in bytes/sec, ETA in seconds (both optional)
///
/// # Behavior
/// * Returns `(None, None)` when elapsed time is zero.
/// * Returns `(None, None)` when `cur_done < prev_done` (non-monotonic, e.g. fresh file).
/// * Returns rate when elapsed > 0 and monotonic.
/// * Returns ETA only when total is Some, bytes remain, rate > 0.
pub fn progress_snapshot(
    prev_done: u64,
    prev_secs: u64,
    cur_done: u64,
    cur_secs: u64,
    total: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    let elapsed = cur_secs.saturating_sub(prev_secs);
    if elapsed == 0 {
        return (None, None);
    }
    if cur_done < prev_done {
        // Non-monotonic: counter reset or fresh file.
        return (None, None);
    }

    let transferred = cur_done - prev_done;
    let rate = transferred / elapsed;

    let eta = match total {
        Some(t) if t > cur_done && rate > 0 => Some((t - cur_done) / rate),
        _ => None,
    };

    (Some(rate), eta)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Direction::default ----

    #[test]
    fn direction_default_is_download() {
        assert_eq!(Direction::default(), Direction::Download);
    }

    // ---- list_batch ----

    #[test]
    fn list_batch_contains_ls_and_quit() {
        let batch = list_batch(Path::new("/remote/path"));
        assert!(batch.contains("ls -l"), "batch must contain 'ls -l'");
        assert!(batch.contains("quit"), "batch must end with 'quit'");
    }

    #[test]
    fn list_batch_quotes_path() {
        let batch = list_batch(Path::new("/path with spaces"));
        assert!(
            batch.contains("\"/path with spaces\""),
            "path must be shell-quoted"
        );
    }

    // ---- pwd_batch ----

    #[test]
    fn pwd_batch_is_pwd_and_quit() {
        let batch = pwd_batch();
        assert_eq!(batch, "pwd\nquit\n");
    }

    // ---- get_batch ----

    #[test]
    fn get_batch_non_recursive() {
        let batch = get_batch(
            Path::new("/remote/file.txt"),
            Path::new("/local/file.txt"),
            false,
        );
        assert!(batch.contains("get "), "batch must contain 'get'");
        assert!(
            !batch.contains("-r"),
            "non-recursive batch must not contain '-r'"
        );
        assert!(batch.contains("quit"), "batch must end with 'quit'");
    }

    #[test]
    fn get_batch_recursive() {
        let batch = get_batch(Path::new("/remote/dir"), Path::new("/local/dir"), true);
        assert!(batch.contains("get "), "batch must contain 'get'");
        assert!(batch.contains("-r"), "recursive batch must contain '-r'");
        assert!(batch.contains("quit"), "batch must end with 'quit'");
    }

    #[test]
    fn get_batch_quotes_both_paths() {
        let batch = get_batch(
            Path::new("/path with spaces"),
            Path::new("/local path"),
            false,
        );
        assert!(
            batch.contains("\"/path with spaces\""),
            "src must be shell-quoted"
        );
        assert!(
            batch.contains("\"/local path\""),
            "dst must be shell-quoted"
        );
    }

    // ---- put_batch ----

    #[test]
    fn put_batch_non_recursive() {
        let batch = put_batch(
            Path::new("/local/file.txt"),
            Path::new("/remote/file.txt"),
            false,
        );
        assert!(batch.contains("put "), "batch must contain 'put'");
        assert!(
            !batch.contains("-r"),
            "non-recursive batch must not contain '-r'"
        );
        assert!(batch.contains("quit"), "batch must end with 'quit'");
    }

    #[test]
    fn put_batch_recursive() {
        let batch = put_batch(Path::new("/local/dir"), Path::new("/remote/dir"), true);
        assert!(batch.contains("put "), "batch must contain 'put'");
        assert!(batch.contains("-r"), "recursive batch must contain '-r'");
        assert!(batch.contains("quit"), "batch must end with 'quit'");
    }

    #[test]
    fn put_batch_quotes_both_paths() {
        let batch = put_batch(Path::new("/local path"), Path::new("/remote path"), false);
        assert!(
            batch.contains("\"/local path\""),
            "src must be shell-quoted"
        );
        assert!(
            batch.contains("\"/remote path\""),
            "dst must be shell-quoted"
        );
    }

    // ---- progress_snapshot ----

    #[test]
    fn progress_snapshot_basic_rate_and_eta() {
        // 100 bytes transferred in 1 second, total 200 bytes
        let (rate, eta) = progress_snapshot(0, 0, 100, 1, Some(200));
        assert_eq!(rate, Some(100), "rate must be 100 bytes/sec");
        assert_eq!(eta, Some(1), "ETA must be 1 second");
    }

    #[test]
    fn progress_snapshot_no_rate_when_elapsed_zero() {
        // No time elapsed
        let (rate, eta) = progress_snapshot(0, 0, 100, 0, Some(200));
        assert_eq!(rate, None, "rate must be None when elapsed is zero");
        assert_eq!(eta, None, "ETA must be None when rate is None");
    }

    #[test]
    fn progress_snapshot_no_rate_when_non_monotonic() {
        // cur_done < prev_done (counter reset)
        let (rate, eta) = progress_snapshot(100, 0, 50, 1, Some(200));
        assert_eq!(rate, None, "rate must be None when non-monotonic");
        assert_eq!(eta, None, "ETA must be None when rate is None");
    }

    #[test]
    fn progress_snapshot_no_eta_when_total_none() {
        // Rate is known but total is not
        let (rate, eta) = progress_snapshot(0, 0, 100, 1, None);
        assert_eq!(rate, Some(100), "rate must be Some");
        assert_eq!(eta, None, "ETA must be None when total is None");
    }

    #[test]
    fn progress_snapshot_no_eta_when_complete() {
        // Transfer complete (cur_done >= total)
        let (rate, eta) = progress_snapshot(0, 0, 200, 2, Some(200));
        assert_eq!(rate, Some(100), "rate must be Some");
        assert_eq!(eta, None, "ETA must be None when transfer complete");
    }

    #[test]
    fn progress_snapshot_no_eta_when_rate_zero() {
        // Rate is zero (no progress)
        let (rate, eta) = progress_snapshot(0, 0, 0, 1, Some(200));
        assert_eq!(rate, Some(0), "rate must be 0");
        assert_eq!(eta, None, "ETA must be None when rate is 0");
    }

    #[test]
    fn progress_snapshot_handles_saturating_sub() {
        // cur_secs < prev_secs (clock skew or monotonic assumption violated)
        let (rate, eta) = progress_snapshot(100, 10, 150, 5, Some(300));
        // saturating_sub makes elapsed = 0
        assert_eq!(rate, None, "rate must be None when elapsed is 0");
        assert_eq!(eta, None, "ETA must be None when rate is None");
    }
}
