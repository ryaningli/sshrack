//! `SftpDirSource` — a `DirSource` backed by an SFTP-over-ControlMaster link.
//!
//! The file picker is generic over [`crate::dirsource::DirSource`]; this module
//! is the remote-listing implementation, used by the (future) SFTP worker.
//! Listing a remote directory runs an `ls -l <cwd>` batch through an injectable
//! [`SftpRunner`] seam; classifying one path runs `ls -ld <path>`. Parsing is
//! the same [`parse_ls_listing`] / [`parse_ls_line`] pipeline the local picker
//! uses, so display ordering (dirs-first, control-char stripping, decoration)
//! is identical between local and remote listings.
//!
//! The runner seam is what keeps `cargo test` hermetic: tests inject a
//! [`FakeRunner`] (canned stdout / canned `Err`); production uses
//! [`LocalSftpRunner`], which spawns `sftp -b -` mounted on the master socket.
//! The master already authenticated, so the sftp mount carries only
//! `ControlPath` + target — no askpass env, no port/identity flags.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use crate::connect::sftp::{
    list_batch, parse_ls_line, parse_ls_listing, sftp_batch_argv, shell_quote, to_dir_entries,
};
use crate::dirsource::{DirEntry, DirSource, PathKind};

/// Runs one sftp batch against a mounted master socket. The worker calls this
/// from its own thread; tests inject a fake that returns canned stdout.
///
/// `target` is the `user@host` sftp target string; `sock` is the
/// already-established `ControlPath`; `batch` is the full sftp script body,
/// which the caller is expected to terminate with a trailing `quit` line (every
/// batch builder in [`super::proto`] — `pwd_batch`, `list_batch`, `get_batch`,
/// `put_batch` — and the one-off `ls -l`/`rm` batches in `worker.rs` already
/// include it). Dropping the stdin handle after the write also signals
/// end-of-batch. Returns the captured stdout on success, or
/// `Err(first_useful_stderr_line)` on non-zero exit.
pub trait SftpRunner: Send + Sync {
    /// Run `batch` against the master at `sock`. Returns stdout on success,
    /// `Err("sftp failed: <first non-blank stderr line>")` on non-zero exit.
    fn run_batch(&self, target: &str, sock: &Path, batch: &str) -> Result<String, String>;
}

/// Production runner: spawns `sftp -b - <argv>` via [`sftp_batch_argv`], writes
/// `batch` to stdin, reads stdout + stderr, returns stdout on success /
/// `Err("sftp failed: <first non-blank stderr line>")` on non-zero exit.
///
/// Carries the `sftp` binary path so tests can inject a shim (via
/// [`LocalSftpRunner::with_bin`]) and keep every sftp spawn hermetic — the pwd
/// probe in `SftpWorker::open`, the listing/classify polls in `SftpDirSource`,
/// and the progress/removal batches in `run_transfer` all flow through here in
/// tests. Production constructs via [`LocalSftpRunner::new`] (literal
/// `"sftp"`). The argv builder still emits `"sftp"` as its first element; this
/// runner skips it and uses the stored path for `Command::new(...)`.
#[derive(Debug, Clone)]
pub struct LocalSftpRunner {
    sftp_bin: PathBuf,
}

impl Default for LocalSftpRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalSftpRunner {
    /// Construct a `LocalSftpRunner` backed by the system `sftp` binary.
    pub fn new() -> Self {
        Self {
            sftp_bin: PathBuf::from("sftp"),
        }
    }

    /// Construct a `LocalSftpRunner` backed by an explicit `sftp` binary path.
    /// Tests pass a shim path so the sftp spawns never contact a real sshd.
    pub fn with_bin(sftp_bin: PathBuf) -> Self {
        Self { sftp_bin }
    }
}

impl SftpRunner for LocalSftpRunner {
    fn run_batch(&self, target: &str, sock: &Path, batch: &str) -> Result<String, String> {
        let argv = sftp_batch_argv(target, sock);
        let mut cmd = Command::new(&self.sftp_bin);
        cmd.args(&argv[1..]);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| format!("sftp spawn failed: {e}"))?;

        // Write the batch to stdin, then drop the handle to close stdin and
        // signal EOF — sftp processes batch commands to EOF.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(batch.as_bytes())
                .map_err(|e| format!("sftp stdin write failed: {e}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("sftp wait failed: {e}"))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
            Err(format!("sftp failed: {first}"))
        }
    }
}

/// `DirSource` whose `list` runs `ls -l <cwd>` via the injected runner and
/// parses the output. Built by the SFTP worker once the master is up (so `sock`
/// exists). `home` is the remote `$HOME` (captured by the worker's `pwd` probe
/// on master-ready); it makes `~`-expansion resolve against the right place.
pub struct SftpDirSource {
    target: String,
    sock: PathBuf,
    runner: Arc<dyn SftpRunner>,
    home: Option<PathBuf>,
}

impl SftpDirSource {
    /// Construct an `SftpDirSource`. The caller (SFTP worker) supplies the
    /// master socket path and the remote home directory (already probed), plus
    /// the runner to use (production: [`LocalSftpRunner::new`]; tests: a fake).
    pub fn new(
        target: String,
        sock: PathBuf,
        runner: Arc<dyn SftpRunner>,
        home: Option<PathBuf>,
    ) -> Self {
        Self {
            target,
            sock,
            runner,
            home,
        }
    }
}

impl DirSource for SftpDirSource {
    fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
        let batch = list_batch(cwd);
        let stdout = self.runner.run_batch(&self.target, &self.sock, &batch)?;
        let rows = parse_ls_listing(&stdout, SystemTime::now());
        Ok(to_dir_entries(rows, cwd))
    }

    fn classify(&self, path: &Path) -> PathKind {
        // `ls -ld <quoted-path>` returns one row describing the path itself
        // (no recursion). On a missing path sftp emits an error to stderr and
        // an empty stdout; either way the parse produces no row → NotFound.
        let batch = format!("ls -ld {}\nquit\n", shell_quote(&path.to_string_lossy()));
        let stdout = match self.runner.run_batch(&self.target, &self.sock, &batch) {
            Ok(s) => s,
            Err(_) => return PathKind::NotFound,
        };
        let Some(line) = stdout.lines().find(|l| !l.trim().is_empty()) else {
            return PathKind::NotFound;
        };
        match parse_ls_line(line, SystemTime::now()) {
            Some(row) if row.is_dir => PathKind::Dir,
            Some(row) if row.is_symlink => PathKind::Symlink,
            Some(_) => PathKind::File,
            None => PathKind::NotFound,
        }
    }

    fn home(&self) -> Option<PathBuf> {
        self.home.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Test fake for [`SftpRunner`]: holds one canned stdout string and returns
    /// it verbatim from `run_batch`, OR returns `Err(rest)` when the canned
    /// string starts with `ERR:` (the `rest` after the prefix is the error
    /// message). The `target`/`sock`/`batch` args are ignored — the fake is
    /// only meant to feed one canned answer per test.
    #[derive(Debug, Clone)]
    struct FakeRunner(String);

    impl SftpRunner for FakeRunner {
        fn run_batch(&self, _target: &str, _sock: &Path, _batch: &str) -> Result<String, String> {
            if let Some(msg) = self.0.strip_prefix("ERR:") {
                Err(msg.to_string())
            } else {
                Ok(self.0.clone())
            }
        }
    }

    /// Build an `SftpDirSource` over a [`FakeRunner`] with the given canned
    /// stdout (or error string). The target/sock/home are placeholders — the
    /// fake ignores them.
    fn source_with(canned: &str) -> SftpDirSource {
        SftpDirSource::new(
            "user@host".to_string(),
            PathBuf::from("/tmp/mux.sock"),
            Arc::new(FakeRunner(canned.to_string())),
            Some(PathBuf::from("/home/user")),
        )
    }

    // ---- list: parses canned ls -l into display-ready entries ----

    #[test]
    fn list_parses_rows_into_sorted_decorated_entries() {
        // Canned `ls -l` output covering a dir, a file, and a symlink. The
        // source must hand back the same shape `LocalDirSource::list` would:
        // dirs first, then files, with `/` / `@` decoration, and absolute
        // paths under `cwd`.
        let canned = "\
drwxr-xr-x 2 u g 4096 Jan 2 03:04 /srv/zdir
-rw-r--r-- 1 u g 1234 Jan 2 03:04 /srv/afile.txt
lrwxrwxrwx 1 u g 4 Jan 2 03:04 /srv/link -> tgt
";
        let src = source_with(canned);
        let cwd = Path::new("/srv");
        let entries = src.list(cwd).expect("list must parse the canned output");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["zdir/", "afile.txt", "link@"],
            "dirs first, then files, then symlinks — each decorated"
        );
        // File row carries size; dir does not (mirrors LocalDirSource).
        let afile = entries
            .iter()
            .find(|e| e.name == "afile.txt")
            .expect("file entry present");
        assert_eq!(afile.size, Some(1234));
        assert_eq!(afile.path, PathBuf::from("/srv/afile.txt"));
        let zdir = entries
            .iter()
            .find(|e| e.name == "zdir/")
            .expect("dir entry present");
        assert!(zdir.is_dir);
        assert_eq!(zdir.path, PathBuf::from("/srv/zdir"));
        let link = entries
            .iter()
            .find(|e| e.name == "link@")
            .expect("symlink entry present");
        assert!(link.is_symlink);
        assert_eq!(link.path, PathBuf::from("/srv/link"));
    }

    #[test]
    fn list_empty_stdout_yields_empty_entries() {
        // An empty remote directory → sftp emits no rows → list returns Ok([]).
        let src = source_with("");
        let entries = src
            .list(Path::new("/srv"))
            .expect("empty stdout is not an error");
        assert!(entries.is_empty(), "empty listing must produce no entries");
    }

    #[test]
    fn list_runner_error_surfaces_as_err() {
        // The brief: a runner error must propagate as `Err(String)` from list.
        let src = source_with("ERR:connection lost");
        let res = src.list(Path::new("/srv"));
        let err = res.expect_err("runner error must surface as Err");
        assert!(
            err.contains("connection lost"),
            "error message must be the canned stderr text: {err}"
        );
    }

    #[test]
    fn list_strips_total_summary_and_dot_entries() {
        // Real sftp `ls -l` prepends a `total N` summary and `.`/`..` rows;
        // the parser drops all three, and the source returns only the real
        // children.
        let canned = "\
total 8
drwxr-xr-x 2 u g 4096 Jan 2 03:04 .
drwxr-xr-x 3 u g 4096 Jan 2 03:04 ..
-rw-r--r-- 1 u g 5 Jan 2 03:04 keep.txt
";
        let src = source_with(canned);
        let entries = src.list(Path::new("/srv")).expect("parse ok");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["keep.txt"]);
    }

    #[test]
    fn list_keeps_hidden_dotfiles_but_drops_dot_and_dotdot() {
        // `list_batch` now emits `ls -la`, so the listing includes dotfiles
        // alongside `.` / `..` and the `total N` summary. The parser must KEEP
        // real dotfiles (so hidden dirs/files are selectable in the pane) while
        // still dropping `.`, `..`, and the summary line. Guards against a
        // regression that re-hides dotfiles or fails to filter `.`/`..`.
        let canned = "\
total 12
drwxr-xr-x 2 u g 4096 Jan 2 03:04 .
drwxr-xr-x 3 u g 4096 Jan 2 03:04 ..
drwxr-xr-x 2 u g 4096 Jan 2 03:04 /srv/.config
-rw-r--r-- 1 u g 256 Jan 2 03:04 /srv/.bashrc
-rw-r--r-- 1 u g 10 Jan 2 03:04 /srv/keep.txt
";
        let src = source_with(canned);
        let entries = src.list(Path::new("/srv")).expect("parse ok");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec![".config/", ".bashrc", "keep.txt"],
            "hidden dir + hidden file kept; dirs first then files; ./.. gone"
        );
        // The hidden file keeps its size and absolute path; the hidden dir is a dir.
        let bashrc = entries
            .iter()
            .find(|e| e.name == ".bashrc")
            .expect("hidden file present");
        assert_eq!(bashrc.size, Some(256));
        assert_eq!(bashrc.path, PathBuf::from("/srv/.bashrc"));
        let config = entries
            .iter()
            .find(|e| e.name == ".config/")
            .expect("hidden dir present");
        assert!(config.is_dir);
        assert_eq!(config.path, PathBuf::from("/srv/.config"));
    }

    #[test]
    fn list_drops_absolute_path_dot_and_dotdot_self_refs() {
        // REAL OpenSSH sftp `ls -la <abspath>` shape: the `.` and `..` rows
        // carry ABSOLUTE-path names (`<cwd>` for `.` and `<cwd>/..` for `..`),
        // NOT the literal `.`/`..` the fixture above uses. The literal filter
        // in `parse_ls_listing` misses these, so `to_dir_entries` must drop
        // them by normalized path identity (== cwd / cwd.parent()). Regression
        // for the bug where a dir's `.`/`..` showed in the pane as `sftp-test/`
        // and `/tmp/sftp-test/../`.
        let canned = "\
total 12
drwxr-xr-x 3 u g 4096 Jan 2 03:04 /tmp/sftp-test
drwxr-xr-x 3 u g 4096 Jan 2 03:04 /tmp/sftp-test/..
drwxr-xr-x 2 u g 4096 Jan 2 03:04 /tmp/sftp-test/.superpowers
-rw-r--r-- 1 u g 123 Jan 2 03:04 /tmp/sftp-test/host_auth_modes_test.rs
-rw-r--r-- 1 u g 456 Jan 2 03:04 /tmp/sftp-test/json_output_test.rs
-rw-r--r-- 1 u g 789 Jan 2 03:04 /tmp/sftp-test/tab.rs
";
        let src = source_with(canned);
        let entries = src.list(Path::new("/tmp/sftp-test")).expect("parse ok");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                ".superpowers/",
                "host_auth_modes_test.rs",
                "json_output_test.rs",
                "tab.rs",
            ],
            "absolute-path `.`/`..` self-refs dropped; hidden dir + files kept"
        );
    }

    // ---- classify: maps the first ls -ld row to a PathKind ----

    #[test]
    fn classify_dir_row_is_dir() {
        let canned = "drwxr-xr-x 2 u g 4096 Jan 2 03:04 /srv/sub\n";
        let src = source_with(canned);
        assert_eq!(src.classify(&PathBuf::from("/srv/sub")), PathKind::Dir);
    }

    #[test]
    fn classify_file_row_is_file() {
        let canned = "-rw-r--r-- 1 u g 1234 Jan 2 03:04 /srv/note.txt\n";
        let src = source_with(canned);
        assert_eq!(
            src.classify(&PathBuf::from("/srv/note.txt")),
            PathKind::File
        );
    }

    #[test]
    fn classify_symlink_row_is_symlink() {
        // A symlink-to-anything is reported as Symlink regardless of target
        // type — the picker annotates with `@` and steps in on Enter.
        let canned = "lrwxrwxrwx 1 u g 4 Jan 2 03:04 /srv/link -> tgt\n";
        let src = source_with(canned);
        assert_eq!(src.classify(&PathBuf::from("/srv/link")), PathKind::Symlink);
    }

    #[test]
    fn classify_empty_stdout_is_not_found() {
        // A missing path → sftp writes "not found" to stderr, stdout empty.
        let src = source_with("");
        assert_eq!(src.classify(&PathBuf::from("/no/such")), PathKind::NotFound);
    }

    #[test]
    fn classify_runner_error_is_not_found() {
        // The brief: a runner error OR an empty parse → NotFound. classify
        // never propagates Err (DirSource::classify returns PathKind, not
        // Result), so the runner error must collapse to NotFound.
        let src = source_with("ERR:sftp exploded");
        assert_eq!(
            src.classify(&PathBuf::from("/anywhere")),
            PathKind::NotFound
        );
    }

    // ---- home: passed through unchanged ----

    #[test]
    fn home_returns_stored_home() {
        // The worker captures home via a `pwd` probe on master-ready; the
        // source just hands it back so `~`-expansion resolves against the
        // remote $HOME.
        let src = SftpDirSource::new(
            "user@host".into(),
            PathBuf::from("/tmp/x.sock"),
            Arc::new(FakeRunner("".into())),
            Some(PathBuf::from("/home/user")),
        );
        assert_eq!(src.home(), Some(PathBuf::from("/home/user")));
    }

    #[test]
    fn home_none_when_worker_passed_none() {
        let src = SftpDirSource::new(
            "user@host".into(),
            PathBuf::from("/tmp/x.sock"),
            Arc::new(FakeRunner("".into())),
            None,
        );
        assert_eq!(src.home(), None);
    }

    // ---- runner args: target/sock are forwarded ----

    #[test]
    fn list_forwards_target_and_sock_to_runner() {
        // A fake that records the args it was called with proves the source
        // threads `target`/`sock` through (not, say, hardcoding them).
        #[derive(Default)]
        struct RecordingRunner {
            seen: std::sync::Mutex<Option<(String, PathBuf)>>,
        }
        impl SftpRunner for RecordingRunner {
            fn run_batch(&self, target: &str, sock: &Path, _batch: &str) -> Result<String, String> {
                *self.seen.lock().unwrap() = Some((target.to_string(), sock.to_path_buf()));
                Ok(String::new())
            }
        }
        let runner = Arc::new(RecordingRunner::default());
        let src = SftpDirSource::new(
            "deploy@1.2.3.4".into(),
            PathBuf::from("/run/mux.sock"),
            runner.clone(),
            None,
        );
        let _ = src.list(Path::new("/srv")).expect("empty stdout → Ok");
        let captured = runner
            .seen
            .lock()
            .unwrap()
            .clone()
            .expect("run_batch was called");
        assert_eq!(captured.0, "deploy@1.2.3.4", "target forwarded verbatim");
        assert_eq!(
            captured.1,
            PathBuf::from("/run/mux.sock"),
            "sock forwarded verbatim"
        );
    }

    // ---- LocalSftpRunner is constructible + zero-state ----

    #[test]
    fn local_runner_new_is_zero_state() {
        // Smoke check that the production runner constructs cleanly. The
        // `Default` derive on a unit struct is trivial and clippy-flagged if
        // spelled `LocalSftpRunner::default()`, so we only exercise `new()`
        // (which is what production code calls).
        let _ = LocalSftpRunner::new();
    }
}
