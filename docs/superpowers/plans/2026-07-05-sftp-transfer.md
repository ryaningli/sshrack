# SFTP Dual-Pane Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Ship `sshrack sftp` — a dual-pane interactive SFTP transfer screen (local | remote) with multi-select + queue, overwrite prompts, and rate/ETA progress, driven entirely by the system `ssh`/`sftp` binaries over a ControlMaster-multiplexed connection (zero SSH protocol libraries).

**Architecture:** A background `ssh -N -o ControlMaster=yes` owns one authenticated connection (built via the existing connect orchestration — host/cred resolve, vault, hostkey, askpass, inline-key materialize); every `sftp -b -` operation mounts it via `-o ControlPath=<sock>`. A dedicated worker thread owns the master socket + runs sftp batches serially, communicating with the UI through `std::mpsc` (`WorkerCmd` in, `WorkerEvent` out) and tearing everything down in `Drop` (RAII). The TUI is a new full-screen `TransferScreen` (not an `Overlay`) holding two `Pane`s; local entries come from the existing `LocalDirSource` (sync, fast), remote entries from a new `SftpDirSource` that the worker drives (so the UI thread never blocks on remote I/O). `DirSource` and the pure navigation/filter/window helpers are reused from the file picker; the file-picker component itself is left untouched.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, nucleo-matcher, `std::sync::mpsc` + `std::thread` (no tokio, no async). No new dependencies.

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **Zero SSH protocol libraries** — `russh`, `ssh2`, `russh-sftp`, `suppaftp`, `openssh-sftp-client`, `age`, `ssh2-config` are all BANNED. Spawn the system `ssh`/`sftp` binaries. SFTP-over-library is explicitly forbidden (CLAUDE.md:240, 369).
- **`sshrack-core` zero-UI invariant** — never list `ratatui`/`crossterm`/`nucleo-matcher`/`console` in `crates/sshrack-core/Cargo.toml`. All UI lives in the root binary `src/`.
- **Connect path never sits in the data stream** — `ssh`/`sftp` are spawned with inherited stdio. SFTP `get`/`put` happen inside the child `sftp` process; sshrack reads at most the child's stdout/stderr for `ls -l` parsing and error surfacing, never the file payload itself.
- **Passwords are `Zeroizing<String>`** — never logged/printed/embedded in errors/argv. The master `ssh -N` reuses the exact askpass env wiring as the connect path (`askpass_env_for`), so passwords/keyring keys never appear in argv or `ps`.
- **TDD for pure logic** — RED → GREEN → REFACTOR for `ls` parsing, argv assembly, batch construction, progress math, overwrite decisions, Pane navigation/filter. Process/thread/real-ssh behavior is covered by `#[ignore]` e2e (needs a local sshd) + manual smoke, never by hermetic unit tests.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace/add outright; no parallel old paths.
- **Files ≤ 800 lines** — split into focused modules (see File Structure). The SFTP surface is large; it MUST be split, not one file.
- **Clippy strict + fmt** — `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt` green before every commit.
- **Commit style** — `<type>(<scope>): <desc>` (Conventional Commits, English). SFTP work uses scope `sftp` (e.g. `feat(sftp): ...`). No `Co-Authored-By`.

**Verification-boundary rule (read this before every task):** Pure logic is unit-tested and MUST pass in `cargo test`. Real-`ssh`/real-`sftp` behavior (master open, batch run, transfer bytes) is `#[ignore]` e2e against a local sshd when feasible, plus manual smoke at the end. An implementer subagent CANNOT run a real sshd — it ships the pure unit tests + a `#[ignore]` e2e stub and reports `DONE` when `cargo build --workspace` + the pure tests + clippy + fmt are green. The controller does the final manual smoke.

---

## File Structure (target)

```
crates/sshrack-core/src/
├── dirsource.rs            # MODIFY (Task 1): DirEntry += size/modified; LocalDirSource fills them
└── connect/
    ├── mod.rs              # MODIFY (Task 2): `pub mod sftp;` + expose askpass env helper
    ├── ssh.rs              # MODIFY (Task 2): extract `connect_opts(...)` (DRY for ssh + master)
    └── sftp/               # NEW directory
        ├── mod.rs          #   re-exports + ControlSocket (RAII socket path)
        ├── argv.rs         #   master_argv / sftp_batch_argv / control_{check,exit}_argv / control_socket_path / shell_quote
        ├── parse.rs        #   parse_ls_line / parse_ls_listing / to_dir_entries / strip_control_chars
        ├── proto.rs        #   WorkerCmd / WorkerEvent / TransferJob / Direction / Progress / OverwritePolicy / TransferOutcome + batch builders + ProgressTracker
        ├── source.rs       #   SftpRunner trait + LocalSftpRunner + SftpDirSource (impl DirSource)
        └── worker.rs       #   SftpWorker (thread + mpsc + RAII teardown)

src/
├── cli/args.rs             # MODIFY (Task 11): Command::Sftp { opts, name }
├── main.rs                 # MODIFY (Task 11): route_is_tui arms Sftp → true
└── tui/
    ├── mod.rs              # MODIFY (Task 11): EntryMode::Transfer + entry_mode_from_cmd arm
    ├── intent.rs           # MODIFY (Task 10): Outcome::OpenTransfer
    ├── app.rs              # MODIFY (Task 10): App.transfer + pending_transfer + on_key/draw routing for transfer
    ├── run_loop.rs         # MODIFY (Task 10): Outcome::OpenTransfer dispatch + drain worker events each tick
    ├── launcher.rs         # MODIFY (Task 11): Ctrl-T → OpenTransfer (sets pending_transfer)
    └── transfer/           # NEW directory
        ├── mod.rs          #   re-exports
        ├── pane.rs         #   Pane state + pure navigation/filter/mark logic (reuses fit/panel/pathutil)
        ├── screen.rs       #   TransferScreen state + dual-pane render + progress/queue panel + footer
        └── overwrite.rs    #   OverwriteChoice + decide_overwrite (pure) + render the prompt
```

**CLAUDE.md** is updated in the final task (move `sftp` out of "Later phase (still deferred)"; add a TUI sub-section describing keys/entry).

---

## Inventory — what is reused vs newly built

**Reused unchanged:**
- `connect::ssh::build` argv shape (Task 2 extracts `connect_opts` from it — the extraction is the only change).
- `connect::materialize_inline_key` + `KeyArtifact` (the master `ssh -N` needs an inline key materialized exactly as connect does).
- `hostkey::run_host_key_flow` + the TUI confirm closure (the master open runs the SAME host-key preflight as connect).
- `credential::resolve`, `vault::ensure_unlocked_vault_key`, `askpass_env_for` (auth + askpass wiring reused verbatim).
- `DirSource` trait + `LocalDirSource` (the local pane uses `LocalDirSource` directly; `SftpDirSource` implements the same trait).
- `fit::{focus_window, truncate_cells, truncate_cells_head}`, `panel::{rank_by_fields, highlighted_spans}`, `pathutil::parse_filter_intent` (Pane navigation/filter/window reuse these pure helpers).
- `theme`, `popup::centered_rect`, `parts::{draw_search_box, draw_status_row}` (render chrome reused).
- `Frecency` (opening the transfer screen records the host, like connect).

**Newly built:** the `connect/sftp/` module (argv/parse/proto/source/worker), the `tui/transfer/` module (pane/screen/overwrite), `Outcome::OpenTransfer`, `Command::Sftp`, `EntryMode::Transfer`, `App.transfer`.

---

## Task 1: Extend `DirEntry` with `size` + `modified`

The SFTP list pane shows size + mtime columns; the local pane fills the same fields so both panes render identically. `DirEntry` is the shared shape.

**Files:**
- Modify: `crates/sshrack-core/src/dirsource.rs`
- Audit (fix construction sites): `src/tui/file_picker.rs` (test fakes), anywhere `DirEntry { ... }` is constructed literally.

**Interfaces:**
- Produces: `DirEntry` gains two fields:
  ```rust
  pub struct DirEntry {
      pub name: String,
      pub path: PathBuf,
      pub is_dir: bool,
      pub is_symlink: bool,
      pub size: Option<u64>,            // NEW; None when unknown (e.g. dirs, or a source that can't report)
      pub modified: Option<std::time::SystemTime>, // NEW; None when unknown
  }
  ```
  and `build_entries` takes a richer input tuple:
  ```rust
  pub(crate) fn build_entries(
      items: Vec<(String, PathBuf, bool, bool, Option<u64>, Option<std::time::SystemTime>)>,
  ) -> Vec<DirEntry>
  ```

- [ ] **Step 1: Update the unit tests first (RED).** In `dirsource.rs` `#[cfg(test)] mod tests`:
  - Extend the `build_entries` tests to pass `None, None` for the two new fields on every existing call site (the sort order assertions stay identical — size/modified do not affect ordering).
  - Add a new test asserting `LocalDirSource::list` reports `size` for a file and `None` for a dir's size is acceptable (a dir's `size` MAY be `Some(dir_size)` or `None` — pin only that a regular file's size is `Some` and equals the written byte count):
    ```rust
    #[test]
    fn local_list_reports_file_size() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"hello").unwrap();
        let e = LocalDirSource::new().list(tmp.path()).unwrap();
        let f = e.iter().find(|e| e.name == "f").unwrap();
        assert_eq!(f.size, Some(5));
        assert!(f.modified.is_some(), "mtime should be known for a local file");
    }
    ```
  - `cargo test -p sshrack-core dirsource` → fails to compile (struct field missing).

- [ ] **Step 2: Add the fields + fill them (GREEN).**
  - Add `size`/`modified` to `DirEntry`. Update `build_entries` signature + its final `DirEntry { ... }` literal to forward them.
  - In `LocalDirSource::list`, capture `fameta.len()` and `fameta.modified()` (when present) into the items tuple. Dirs: report `is_dir`-derived size as `None` (a dir's byte size is meaningless in a listing).
  - Fix every other `DirEntry { ... }` literal (grep `DirEntry {`) to add `size: None, modified: None` (test fakes in `file_picker.rs`). `LocalDirSource::list` is the only production filler for now; `SftpDirSource` (Task 5) fills them from `ls -l`.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(core): extend DirEntry with size and modified for sftp listing"
  ```

---

## Task 2: Extract `connect_opts` + build the ControlMaster/sftp argv layer

The master/sftp argv is built from the SAME connection options as `ssh` (user/port/identity) plus ControlMaster options. Extract a shared `connect_opts` so the master path is DRY with `ssh::build`, and add the sftp-specific argv builders + the control-socket path (in `$XDG_RUNTIME_DIR`, never `/tmp`).

**Files:**
- Modify: `crates/sshrack-core/src/connect/ssh.rs` (extract `connect_opts`)
- Modify: `crates/sshrack-core/src/connect/mod.rs` (`pub mod sftp;` + expose `askpass_env_for` as `pub(crate)`)
- Create: `crates/sshrack-core/src/connect/sftp/mod.rs`, `argv.rs`

**Interfaces:**
- `ssh.rs` produces:
  ```rust
  /// The ssh connection options shared by the interactive `ssh` argv and the
  /// SFTP master/sftp argv: `-l <user> -p <port> (-i <key>)?`. Pure.
  pub fn connect_opts(resolved: &ResolvedAuth, host: &Host, overrides: &Overrides) -> Vec<String>
  ```
  `build` becomes `["ssh"] + connect_opts(...) + [host] + remote_command`.
- `connect/sftp/argv.rs` produces:
  ```rust
  /// Control socket path under $XDG_RUNTIME_DIR (falls back to std::env::temp_dir).
  /// Per-process, per-session unique so concurrent sshrack sftp sessions never collide.
  pub fn control_socket_path() -> std::path::PathBuf

  /// `ssh -N -o ControlMaster=yes -o ControlPath=<sock> -o ConnectTimeout=10
  ///   -o ServerAliveInterval=15  <connect_opts> <host>` — owns the muxed connection.
  pub fn master_argv(resolved: &ResolvedAuth, host: &Host, overrides: &Overrides, sock: &Path) -> Vec<String>

  /// `sftp -b - -o ControlPath=<sock> <user@host>` — mounts the master. No -P/-i/-J:
  /// the master already carries port/identity; this avoids the ssh -p vs sftp -P flag clash.
  pub fn sftp_batch_argv(target: &str, sock: &Path) -> Vec<String>

  /// `ssh -o ControlPath=<sock> -O check <target>` / `-O exit` — readiness poll + teardown.
  pub fn control_check_argv(target: &str, sock: &Path) -> Vec<String>
  pub fn control_exit_argv(target: &str, sock: &Path) -> Vec<String>

  /// The sftp target string `<user>@<host>` used as sftp's last argv token.
  pub fn sftp_target(resolved: &ResolvedAuth, host: &Host) -> String

  /// Shell-quote a path for an sftp batch line (`get`/`put` operands). Uses sftp's own
  /// quoting rules so filenames with spaces survive (the scp→sftp lesson).
  pub fn shell_quote(path: &str) -> String
  ```

- [ ] **Step 1: Write failing tests (RED).** In `ssh.rs` tests, add `connect_opts_returns_user_port_identity` asserting it yields `["-l","u","-p","22","-i","/k"]` for the existing `host()`/`resolved()` helpers. In `sftp/argv.rs` tests (new), pin the exact argv for master/sftp/control_*/socket path: e.g. `master_argv` contains `"-N"`, `"ControlMaster=yes"`, `"ConnectTimeout=10"`, `"ServerAliveInterval=15"`, the connect_opts tokens, and the host; `sftp_batch_argv` is exactly `["sftp","-b","-","-o",format!("ControlPath={}",sock.display()),target]`; `control_socket_path()` is rooted under `$XDG_RUNTIME_DIR` when set (test via a `root: &Path` parameter — see Step 2, the fn is split for testability). `cargo test -p sshrack-core connect::sftp` → RED.

- [ ] **Step 2: Implement.**
  - In `ssh.rs`: extract `connect_opts` (pure — same user/port/identity extraction `build` already does), rewrite `build` in terms of it. Existing `ssh.rs` tests must still pass unchanged.
  - `connect/sftp/mod.rs`: `pub mod argv; pub mod argv::*;` re-exports + a short module doc.
  - `connect/sftp/argv.rs`: implement the builders. For `control_socket_path`, factor the dir choice into a pure `runtime_dir(env_xdg: Option<&Path>) -> PathBuf` (testable) and let `control_socket_path()` read `std::env::var_os("XDG_RUNTIME_DIR")` + `std::process::id()` for the unique name (`sshrack-mux-{pid}-{counter}.sock`). Use an `AtomicU64` counter for uniqueness within one process. `shell_quote` wraps the path in double quotes and backslash-escapes `"`, `\`, and `$` — minimal but correct for sftp operands.
  - `connect/mod.rs`: add `pub mod sftp;` and change `fn askpass_env_for` to `pub(crate) fn askpass_env_for` (Task 6's worker needs it to spawn the master with the same askpass env as connect).

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): connection-option reuse + ControlMaster/sftp argv builders"
  ```

---

## Task 3: `ls -l` parser + control-character stripping

Remote listings come from `sftp -b -` running `ls -l <path>`; the output is parsed into `DirEntry` rows. This is the brittle core — it must handle spaces in names, filter junk rows (`.`/`..`, `total N`, device/socket/pipe entries), and strip C0 control characters from names so a malicious filename (`foo\x1b[2Jbar`) cannot reorder the layout. Port sshelf's robust `parse_ls_line` logic; generalize to fill `size`/`modified`.

**Files:**
- Create: `crates/sshrack-core/src/connect/sftp/parse.rs`
- Modify: `crates/sshrack-core/src/connect/sftp/mod.rs` (`pub mod parse;`)

**Interfaces:**
- ```rust
  /// One parsed `ls -l` row. `name` is the raw basename (no decoration); `kind`
  /// distinguishes dir/file/symlink from the mode column's first byte.
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct RawLsEntry {
      pub name: String,
      pub is_dir: bool,
      pub is_symlink: bool,
      pub size: Option<u64>,
      pub modified: Option<std::time::SystemTime>,
  }

  /// Parse one `ls -l` line. Returns `None` for blank lines, `total N` summaries,
  /// rows with fewer than 9 whitespace fields, and device/socket/pipe entries
  /// (mode first byte not in `-dl`). Names containing spaces are recovered by
  /// taking everything after the 9th field. A trailing ` -> target` on symlinks
  /// is dropped (only the link name is kept). Pure.
  pub fn parse_ls_line(line: &str) -> Option<RawLsEntry>

  /// Parse a full `ls -l` listing into entries, skipping `.`, `..`, and
  /// unparseable lines. Pure.
  pub fn parse_ls_listing(output: &str) -> Vec<RawLsEntry>

  /// Convert parsed rows into display-ready `DirEntry` (decorate names, sort
  /// dirs-first via `dirsource::build_entries`, attach paths under `cwd`).
  /// `strip_control_chars` is applied to each name first. Pure.
  pub fn to_dir_entries(rows: Vec<RawLsEntry>, cwd: &Path) -> Vec<DirEntry>

  /// Replace C0 control chars (except tab/newline, which never appear in a name
  /// here) with `?` so a malicious name cannot inject ANSI/control sequences
  /// that reorder or blank the layout. Pure.
  pub fn strip_control_chars(s: &str) -> String
  ```
  Note: `to_dir_entries` needs `dirsource::build_entries`. Since `build_entries` is `pub(crate)`, `parse.rs` (same crate) can call it. Adapt its input tuple to carry the parsed `size`/`modified` through.

- [ ] **Step 1: Write failing tests (RED).** Cover, in `parse.rs` tests:
  - A regular file row: `-rw-r--r-- 1 u g 1234 Jan 2 03:04 hello.txt` → name `hello.txt`, `is_dir=false`, `size=Some(1234)`, `modified.is_some()`.
  - A directory row: `drwxr-xr-x 2 u g 4096 Jan 2 03:04 sub` → `is_dir=true`.
  - A symlink row: `lrwxrwxrwx 1 u g 4 Jan 2 03:04 link -> tgt` → `is_symlink=true`, name `link` (target dropped).
  - **Spaces in a name**: `-rw-r--r-- 1 u g 5 Jan 2 03:04 a name with spaces.txt` → name preserved verbatim.
  - **Control chars**: feeding a name containing `\x1b` through `strip_control_chars` yields `?` in its place; `to_dir_entries` applies it so the resulting `DirEntry.name` has no C0 controls.
  - Filtered-out rows: `total 12`, blank line, `crw-rw-rw- 1 u g 1,3 Jan 2 03:04 null` (device, mode `c`) → all produce `None`/are dropped; `.` and `..` rows are dropped by `parse_ls_listing`.
  - `to_dir_entries` sorts dirs first, then files case-insensitively, and the `path` is `cwd.join(name)`.

- [ ] **Step 2: Implement** the four fns per the doc + tests. For `modified`, parse `Mmm DD HH:MM` (or `Mmm DD  YYYY`) loosely into a `SystemTime` — a best-effort parse is fine (sshelf does not even do this); on any ambiguity return `None` (the column is informational, never load-bearing). Reuse `parse_ls_listing` = line split + `parse_ls_line` + filter `.`/`..`.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): robust ls -l parser with control-char stripping"
  ```

---

## Task 4: Worker protocol types + batch builders + progress math

Define the worker's `mpsc` vocabulary and the pure helpers that build sftp batch scripts and compute rate/ETA from polled byte offsets. All pure, heavily unit-tested.

**Files:**
- Create: `crates/sshrack-core/src/connect/sftp/proto.rs`
- Modify: `crates/sshrack-core/src/connect/sftp/mod.rs` (`pub mod proto;`)

**Interfaces:**
- ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Direction { Upload, Download }

  /// One transfer the worker runs. `size_total` is the source file's size
  /// (best-effort; used for the percentage + ETA when known).
  #[derive(Debug, Clone)]
  pub struct TransferJob {
      pub direction: Direction,
      pub src: PathBuf,   // local for Upload, remote for Download
      pub dst: PathBuf,
      pub name: String,   // display name
      pub size_total: Option<u64>,
      pub recursive: bool,
  }

  /// User's answer to a same-name conflict. `OverwriteAll`/`SkipAll` apply to
  /// the rest of the batch.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum OverwritePolicy { Overwrite, Skip, OverwriteAll, SkipAll }

  #[derive(Debug, Clone)]
  pub enum WorkerCmd {
      List(PathBuf),                                   // remote cwd to list
      Transfer(TransferJob, OverwritePolicy),
      Cancel,                                          // kill the in-flight transfer + delete partial
      Shutdown,                                        // teardown master + exit thread
  }

  #[derive(Debug, Clone)]
  pub enum WorkerEvent {
      Ready(Result<PathBuf, String>),                  // master up; home path (or error)
      Listing(PathBuf, Result<Vec<DirEntry>, String>), // entries for cwd (or error msg)
      Progress(Progress),
      Done(TransferOutcome),
  }

  #[derive(Debug, Clone, Default)]
  pub struct Progress {
      pub name: String,
      pub direction: Direction,
      pub bytes_done: u64,
      pub bytes_total: Option<u64>,
      pub rate_bps: Option<u64>,
      pub eta_secs: Option<u64>,
  }

  #[derive(Debug, Clone)]
  pub enum TransferOutcome { Ok, Cancelled, Failed(String) }

  // ---- batch builders (produce the sftp `-b -` stdin script) ----
  pub fn list_batch(path: &Path) -> String        // "ls -l <q(path)>\nquit\n"
  pub fn pwd_batch() -> String                    // "pwd\nquit\n"
  pub fn get_batch(src: &Path, dst: &Path, recursive: bool) -> String
  pub fn put_batch(src: &Path, dst: &Path, recursive: bool) -> String

  // ---- progress math ----
  /// Tracks the last sample (bytes_done + instant) and computes rate + ETA from
  /// the delta between samples. Pure given (prev_done, prev_secs, cur_done, cur_secs, total).
  pub fn progress_snapshot(
      prev_done: u64, prev_secs: u64, cur_done: u64, cur_secs: u64, total: Option<u64>,
  ) -> (Option<u64>, Option<u64>) // (rate_bps, eta_secs)
  ```

- [ ] **Step 1: Write failing tests (RED).** Pin the EXACT batch string for each variant (use `assert_eq!`, not `contains`, so command structure is locked): `list_batch` == `"ls -l <q(path)>\nquit\n"`; `pwd_batch` == `"pwd\nquit\n"`; `get_batch(false)` == `"get <q(src)> <q(dst)>\nquit\n"`; `get_batch(true)` == `"get -R <q(src)> <q(dst)>\nquit\n"` — the recursive flag is **`-R` (uppercase), AFTER the command** (OpenSSH sftp's form; NOT `-r`, and never before the command, which sftp batch mode rejects). `put_batch` mirrors `get_batch`. Verify `shell_quote` is applied to both operands. Progress: `(0,0,  100,1s, Some(200))` → rate `100`, eta `1`; a non-monotonic sample (cur_done < prev_done) yields rate `None`; `total=None` → eta `None` even with a rate.

- [ ] **Step 2: Implement.** Batch builders use `argv::shell_quote` on operands. `progress_snapshot` guards division-by-zero and clamps. `Progress` is `Default` for convenience.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): worker protocol, batch builders, progress math"
  ```

---

## Task 5: `SftpDirSource` + the `SftpRunner` execution seam

`SftpDirSource` implements `DirSource` by running an `ls -l` batch through an injected runner — keeping the IO out of the unit tests (a `FakeRunner` returns canned `ls -l` output) and the real `LocalSftpRunner` spawns `sftp -b -` over the master socket. This is the seam that lets `cargo test` cover remote-listing parsing end-to-end without a real sshd.

**Files:**
- Create: `crates/sshrack-core/src/connect/sftp/source.rs`
- Modify: `crates/sshrack-core/src/connect/sftp/mod.rs` (`pub mod source;`)

**Interfaces:**
- ```rust
  /// Runs one sftp batch against a mounted master socket. The worker calls this
  /// from its own thread; tests inject a fake that returns canned stdout.
  pub trait SftpRunner: Send + Sync {
      fn run_batch(&self, target: &str, sock: &Path, batch: &str) -> Result<String, String>;
  }

  /// Production runner: spawns `sftp -b - <argv>`, writes `batch` to stdin,
  /// reads stdout (stderr folded into the error on non-zero exit), waits. Uses
  /// the same askpass env wiring path as connect (env passed in by the worker).
  pub struct LocalSftpRunner { /* env: Vec<(String,String)> carried from the master open */ }

  /// `DirSource` whose `list` runs `ls -l <cwd>` via the runner and parses it.
  /// Built by the worker once the master is up (so `sock` exists).
  pub struct SftpDirSource {
      target: String,
      sock: PathBuf,
      runner: std::sync::Arc<dyn SftpRunner>,
      home: Option<PathBuf>,
  }
  impl SftpDirSource {
      pub fn new(target: String, sock: PathBuf, runner: std::sync::Arc<dyn SftpRunner>, home: Option<PathBuf>) -> Self;
  }
  impl DirSource for SftpDirSource { /* list/classify/home/resolve */ }
  ```
  `classify` runs `ls -ld <path>` and inspects the first row's mode byte; `home` returns the stored home (captured by the worker's `Ready` probe).

- [ ] **Step 1: Write failing tests (RED).** With a `FakeRunner` returning a canned multi-line `ls -l`, assert `SftpDirSource::list(cwd)` returns `DirEntry`s with the right names/order/sizes, that a runner error surfaces as `Err(String)`, and that `classify` on a dir/file/notfound path returns the right `PathKind`. The fake is a small `struct FakeRunner(&str)` returning `Ok` with its canned string (or `Err` when the canned string starts with `ERR:`).

- [ ] **Step 2: Implement.** `LocalSftpRunner::run_batch` spawns the `sftp_batch_argv`, writes `batch`, captures stdout/stderr, returns stdout on success / `format!("sftp failed: {stderr_first_line}")` on non-zero exit. `SftpDirSource::list` = build `list_batch(cwd)`, run, `parse_ls_listing`, `to_dir_entries(rows, cwd)`. `classify` builds a `ls -ld <q(path)>` batch, runs, parses one row.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): SftpDirSource over an injectable SftpRunner seam"
  ```

---

## Task 6: `ControlSocket` RAII + `SftpWorker` thread

The worker owns the master connection's lifecycle and serially executes every command. This is the one task where most behavior is process/thread-level and therefore only partially unit-testable; the pure pieces (ControlSocket path + Drop cleanup ordering, command→event routing in isolation) are unit-tested, and a `#[ignore]` e2e stub is provided for a future local-sshd run.

**Files:**
- Create: `crates/sshrack-core/src/connect/sftp/mod.rs` (`ControlSocket`), `worker.rs`
- Modify: `crates/sshrack-core/src/connect/sftp/mod.rs` (`pub mod worker;`, hold `ControlSocket` here)

**Interfaces:**
- ```rust
  /// RAII over the control socket path. `new()` allocates a unique path under
  /// `control_socket_path()`; `Drop` removes the file (best-effort). The master
  /// `ssh -O exit` is issued by the worker's Drop BEFORE the socket file removal.
  pub struct ControlSocket { /* path: PathBuf */ }
  impl ControlSocket {
      pub fn new() -> Self;
      pub fn path(&self) -> &Path;
  }

  /// Owns the worker thread + the master connection. `send` pushes a command;
  /// `try_event` drains one pending event (the UI polls this each tick). `Drop`
  /// sends Shutdown, joins the thread, runs `ssh -O exit`, and the `ControlSocket`
  /// removes the socket file — so a panic still cleans up.
  pub struct SftpWorker { /* cmd_tx, event_rx, join, sock */ }
  impl SftpWorker {
      /// Opens the master (`ssh -N` via `master_argv`, with `askpass_env_for` env
      /// so password/keyring hosts authenticate), polls `control_check_argv` until
      /// ready or `HANDSHAKE_TIMEOUT` (30s), then returns the worker handle.
      /// `resolved`/`host`/`overrides`/`self_exe`/`source` mirror connect_host.
      pub fn open(
          resolved: ResolvedAuth, host: Host, overrides: Overrides,
          self_exe: &Path, source: PasswordSource,
      ) -> Result<(Self, PathBuf /* remote home */), String>;

      pub fn send(&self, cmd: WorkerCmd);
      pub fn try_event(&self) -> Option<WorkerEvent>;
  }
  ```

- [ ] **Step 1: Write failing tests (RED) — pure pieces only.**
  - `ControlSocket::new()` yields a path rooted under `runtime_dir(...)` and unique across two consecutive `new()` calls; its `Drop` removes a file placed at that path (create a sentinel file at the path, drop, assert gone).
  - A pure `route_cmd(cmd, state) -> Vec<WorkerEvent>` helper (extracted from the thread loop) returns the right event sequence for `List` (one `Listing`), `Shutdown` (thread-exit signal), and an unknown-no-op. (This extraction is what makes the routing testable; the thread loop calls it.)
  - Add `tests/sftp_e2e.rs` (integration test) with a single `#[ignore] fn sftp_round_trip_local_sshd()` stub that documents the manual setup (start a local sshd, point `SSHRACK_*` at it, assert list+get+put) but `#[ignore]`'d so CI never runs it. It MUST compile.

- [ ] **Step 2: Implement.**
  - `ControlSocket` in `sftp/mod.rs`: wraps `control_socket_path()`; `Drop` does `let _ = std::fs::remove_file(&self.path);`.
  - `worker.rs`: `SftpWorker::open` — allocate `ControlSocket`, build `master_argv`, `Command::new("ssh").args(...).envs(askpass_env_for(...))`, `spawn()` (NOT `status` — the master must stay alive), loop `control_check_argv` + `Command::status` until stdout contains "Master running" or 30s elapse (→ `Err("sftp master handshake timed out")`). On ready, spawn the worker thread; the thread `loop { match rx.recv() }`: `List(cwd)` → `SftpDirSource::list` (built once with the live `LocalSftpRunner` + sock + home) → `Listing` event; `Transfer(job, policy)` → spawn `sftp -b -` with `get`/`put` batch, poll the destination file size every ~200ms emitting `Progress` (use `progress_snapshot`), on completion emit `Done(Ok)`; on `Cancel` kill the child + remove the partial destination + emit `Done(Cancelled)`; on a non-zero exit remove the partial destination + emit `Done(Failed(..))`; `Shutdown` → break. `Drop` sends `Shutdown`, `join()`s, runs `control_exit_argv` via `Command::status`, then drops the `ControlSocket`.
  - The worker thread must own the master `Child` so dropping it kills the master if the thread dies.

- [ ] **Step 3: Build + test (pure only) + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): ControlSocket RAII + SftpWorker thread with multiplexed master"
  ```

---

## Task 7: TUI `Pane` — pure navigation/filter/mark logic

Each side of the transfer screen is a `Pane`. Its key handling, fuzzy filter, focus-window, and mark set are pure (no I/O) — the local pane calls `LocalDirSource::list` inline (fast), the remote pane is fed entries by the worker via the screen. This task delivers the pure state + logic, reused by both panes symmetrically.

**Files:**
- Create: `src/tui/transfer/mod.rs`, `pane.rs`

**Interfaces:**
- ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Side { Local, Remote }

  /// Pure intent returned by `Pane::on_key` — the screen decides side effects
  /// (worker List, transfer enqueue, focus switch).
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum PaneOutcome {
      None,
      QueryChanged,                       // re-render the filter box
      StepInto(PathBuf),                  // cursor entry is a dir → list it (local: sync; remote: worker)
      StepUp,                             // go to parent
      ActivateSelected,                   // a file is selected (reserved; transfer is Ctrl-Enter at screen level)
      ToggleMark(PathBuf),                // space on a file toggles its mark
      RequestList(PathBuf),               // path-like filter resolved to a dir → list it
  }

  pub struct Pane {
      pub side: Side,
      pub cwd: PathBuf,
      pub entries: Vec<DirEntry>,         // current listing (worker-fed for remote)
      pub query: String,
      ranked: Vec<usize>,                 // indices into `entries`, fuzzy-ranked
      pub selected: usize,                // cursor into `ranked`
      pub marked: std::collections::HashSet<PathBuf>,
      pub loading: bool,
  }
  impl Pane {
      pub fn new(side: Side, cwd: PathBuf) -> Self;
      pub fn set_entries(&mut self, entries: Vec<DirEntry>);  // re-ranks
      pub fn on_key(&mut self, key: KeyEvent) -> PaneOutcome; // pure
      pub fn visible_window(&self, rows: usize) -> std::ops::Range<usize>; // focus_window over ranked
      pub fn selected_entry(&self) -> Option<&DirEntry>;
  }
  ```

- [ ] **Step 1: Write failing tests (RED).** Pin: a printable char pushes the query and re-ranks (a pane with entries `[apple, banana, cherry]`, query `c` → ranked `[cherry]`, cursor 0); `Down`/`Up` move `selected` with wrap; `Left`/`Backspace`(empty query) → `StepUp`; `Right`/`Enter` on a dir entry → `StepInto(<path>)`, on a file → `ActivateSelected`; `Space` on a file → `ToggleMark(<path>)` and the path is in `marked` after; a path-like query (`/x` or `~/y`) + `Enter` → `RequestList(<resolved>)`. Reuse `parse_filter_intent` to classify the query (fuzzy vs path-like) so behavior matches the file picker.

- [ ] **Step 2: Implement.** `set_entries` resets the cursor to 0 and re-ranks via `panel::rank_by_fields` over `(name,)`. `on_key` matches the file-picker key map (so navigation feels identical across the app): arrows + Ctrl-P/N, Left=up, Right/Enter=activate, Backspace=pop query or up, Space=toggle mark, printable=append query. `visible_window` delegates to `fit::focus_window`. `Pane` holds no `DirSource` — the screen feeds entries.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --bin sshrack tui::transfer && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): pure Pane navigation/filter/mark for dual-pane transfer"
  ```

---

## Task 8: `TransferScreen` state + dual-pane render + progress/queue panel

The full-screen transfer view. Renders two panes side by side, a bottom progress/queue panel, and a hotkey footer. Pure-ish rendering (no I/O); the screen reads its own state + the latest drained worker events.

**Files:**
- Create: `src/tui/transfer/screen.rs`

**Interfaces:**
- ```rust
  pub struct TransferScreen {
      pub local: Pane,
      pub remote: Pane,
      pub focus: Side,
      pub active: Option<Progress>,        // in-flight transfer
      pub queue: Vec<TransferJob>,         // pending
      pub status: Status,
      // worker handle + overwrite policy live here too (Task 10 wires them)
  }
  impl TransferScreen {
      /// Render the full screen: title band + two panes (each cwd row / filter box /
      /// windowed list with size+mtime columns, marked-glyph, control-char-stripped)
      /// + a progress/queue panel + a hotkey footer.
      pub fn draw(&self, frame: &mut Frame, area: Rect);
  }
  ```

- [ ] **Step 1: Write a no-panic render smoke (RED-ish).** A `TestBackend` test that constructs a `TransferScreen` with a handful of canned entries on each side, a marked file, an active `Progress`, and one queued job, then `terminal.draw(|f| screen.draw(f, f.area()))` — assert it returns `Ok(())` (no panic, no layout overflow). A second test on a 60×12 terminal asserts the focused pane's list window scrolled the cursor into view (cursor y within the area) — mirroring the wizard's small-terminal test.

- [ ] **Step 2: Implement.** Layout: `Layout::vertical([title(1), panes(Fill), progress_panel(4), footer(1)])`; panes = `Layout::horizontal([50%, 50%])`. Each pane renders a cwd row (truncated head via `fit::truncate_cells_head`), a filter box (`parts::draw_search_box`), and the windowed list. Each list row: focus marker (`theme::focus_marker`) + name (control-char-stripped + fuzzy-highlight via `panel::highlighted_spans`) + a right-aligned `<size>  <mtime>` column (dim). Marked files carry a leading `●` (accent). The non-focused pane is dimmed. Progress panel: the active transfer (name + direction glyph ↑/↓ + percent Gauge + `<done>/<total> <rate> eta:<s>`) or "no transfer"; below it, the queue count + the next 1–2 names. Footer: the hotkey hints (`Tab switch · ↑↓ move · → open · Space mark · ^⏎ transfer · Esc cancel · ^C close`). All text English.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --bin sshrack tui::transfer && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): TransferScreen dual-pane render with progress and queue"
  ```

---

## Task 9: TransferScreen `on_key` + overwrite prompt + queue logic

The screen's key routing (focus switch, mark, transfer-enqueue, cancel, close), the same-name overwrite decision (pure), and the queue-advance state machine. The worker is driven from here (send `List`/`Transfer`/`Cancel`); events are drained by the loop (Task 10) and fed back here.

**Files:**
- Create: `src/tui/transfer/overwrite.rs`
- Modify: `src/tui/transfer/screen.rs` (`on_key`, enqueue/advance)

**Interfaces:**
- ```rust
  // overwrite.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum OverwriteChoice { Overwrite, Skip, OverwriteAll, SkipAll, Cancel }

  /// Decide what to do for one conflicting destination. Pure given the user's
  /// batch-level policy + whether this destination already exists.
  pub fn decide(policy: OverwritePolicy, dest_exists: bool) -> OverwriteChoice
  ```
- `TransferScreen::on_key(key) -> TransferOutcome { Continue, Quit, CloseTransfer, StatusUpdate } }` (pure; the loop performs the worker send + popup).

- [ ] **Step 1: Write failing tests (RED).** `decide` table: `(OverwriteAll, true)→Overwrite`, `(SkipAll,true)→Skip`, `(Overwrite, true)→Overwrite`, `(Overwrite, false)→Overwrite` (no conflict → just go), `(Skip, false)→Skip`-meaning-noop, etc. `on_key`: `Tab` flips `focus`; `Space` on the focused pane's selected file toggles a mark and returns `Continue`; `Ctrl-Enter` with ≥1 marked (or the selected file) returns an outcome carrying the enqueue list with the right `Direction` (Upload when `focus==Local`, Download when `focus==Remote`) and `recursive=true` for a dir; `Esc` with an active transfer returns `Cancel`-intent, with no transfer returns `CloseTransfer`; `Ctrl-C` returns `CloseTransfer`.

- [ ] **Step 2: Implement.** `on_key` routes to the focused pane (`Pane::on_key`) for navigation/query/space, handles `Tab`/`Shift-Tab` for focus, `Ctrl-Enter` for enqueue, `Esc`/`Ctrl-C` for close. Enqueue: gather marked paths (or just the selected file if none marked), build `TransferJob`s, append to `queue`. The first job is sent to the worker when no `active` transfer exists; on `Done` the next queue item advances (the loop calls `screen.advance_queue(&worker)` after draining a `Done` event). The overwrite prompt is rendered as a popup (Task 10 wires the popup via `TuiPassphrase`-style centered render); `decide` is the pure core tested here.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --bin sshrack tui::transfer && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): transfer on_key, overwrite decision, queue advance"
  ```

---

## Task 10: Wire `TransferScreen` into `App` + `run_loop` event drain

The transfer screen is a full-screen view owned by `App` (not an `Overlay`). `App::on_key`/`App::draw` route to it when active; `run_loop` opens it on `Outcome::OpenTransfer` (spawns the worker via a new `open_transfer` orchestrator mirroring `connect_host`), drains worker events each 250ms tick, and closes it on user close (dropping the worker = RAII teardown).

**Files:**
- Modify: `src/tui/intent.rs` (`Outcome::OpenTransfer`)
- Modify: `src/tui/app.rs` (`App.transfer: Option<TransferScreen>`, `pending_transfer: Option<Ulid>`, `on_key`/`draw` routing, `open_transfer` helper)
- Modify: `src/tui/run_loop.rs` (`Outcome::OpenTransfer` arm + per-tick `drain_transfer_events`)
- Create: `src/tui/transfer/open.rs` (`open_transfer` orchestrator — mirrors `connect_host` steps 1–4 then `SftpWorker::open`)

**Interfaces:**
- ```rust
  // intent.rs
  pub enum Outcome { /* ...existing... */ OpenTransfer }

  // app.rs
  impl App {
      pub fn transfer(&self) -> Option<&TransferScreen>;
      pub fn transfer_mut(&mut self) -> Option<&mut TransferScreen>;
  }

  // transfer/open.rs
  /// Mirrors connect_host's auth/hostkey steps, then opens the SFTP worker and
  /// builds a TransferScreen seeded with cwd = local current_dir, remote = the
  /// worker's reported home. Returns Err(Interrupted) on a popup cancel.
  pub fn open_transfer(
      host_id: Ulid, app: &mut App, handle: TerminalHandle,
  ) -> Result<(), SshrackError>;
  ```

- [ ] **Step 1: Write failing tests (RED).**
  - `intent`/`app`: `App::on_key` with a live `transfer` routes a key to `TransferScreen::on_key` and returns its outcome (test with a hand-built `TransferScreen` and a `Tab` keystroke → focus flips). With no transfer, the existing routing is unchanged.
  - `app::on_key` intercepts `Ctrl-T` only on the Hosts tab with a selected host → sets `pending_transfer` and returns `OpenTransfer` (no transfer open already; if one is open, `Ctrl-T` is a no-op). Assert via `matches!(out, Outcome::OpenTransfer)` + `app.pending_transfer.is_some()`.
  - `open_transfer`: a pure seam test — with a host whose auth resolves but no real network, assert it builds the right `master_argv` tokens (reuse the `connect_host` test pattern: call `connect::ssh::build`-equivalent on a default host and check the user/port/host tokens reach `master_argv`). The real spawn is `#[ignore]`/manual.

- [ ] **Step 2: Implement.**
  - `intent.rs`: add `OpenTransfer` (no payload — `pending_transfer` lives on `App`, like `ConnectRequested`).
  - `app.rs`: add `transfer: Option<TransferScreen>` + `pending_transfer: Option<Ulid>` to `App`; in `on_key`, BEFORE the panel layer, if `self.transfer.is_some()`, route the key to the transfer screen and map its outcome; also intercept `Ctrl-T` at the global layer (Layer 1) when `transfer.is_none()` and `active_tab == Hosts` and a host is selected. In `draw`, if `self.transfer.is_some()`, render `TransferScreen::draw` full-screen instead of the shell.
  - `transfer/open.rs`: `open_transfer` runs the `connect_host` steps (find host by id, vault unlock via `TuiPassphrase`, `credential::resolve`, `materialize_inline_key`, `hostkey::run_host_key_flow`), then `SftpWorker::open(...)`, builds `TransferScreen { local: Pane::new(Local, std::env::current_dir()), remote: Pane::new(Remote, home), … }`, sends an initial `List(home)` to populate the remote pane, and assigns `app.transfer`.
  - `run_loop.rs`: add `Outcome::OpenTransfer` arm → `open_transfer(host_id, app, handle.clone())`; on `Err(Interrupted)` return to launcher (no status), on other `Err` set a status error. Add a per-tick `if let Some(t) = app.transfer_mut() { drain events → feed to screen.advance / status }` right after the `event::poll` window (the existing 250ms poll already paces this). Closing the transfer (`CloseTransfer` outcome) sets `app.transfer = None` (drop → worker RAII teardown).

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): wire TransferScreen into App with worker event drain"
  ```

---

## Task 11: `sshrack sftp <name>` CLI + `Ctrl-T` entry + routing

The CLI entry point and the launcher hotkey. `sshrack sftp <name>` parses, routes to the TUI, and opens the transfer screen for that host directly (mirroring how `sshrack host add` opens the wizard). `Ctrl-T` in the launcher does the same for the selected host.

**Files:**
- Modify: `src/cli/args.rs` (`Command::Sftp`)
- Modify: `src/main.rs` (`route_is_tui` arms `Sftp` → true)
- Modify: `src/tui/mod.rs` (`EntryMode::Transfer { name }` + `entry_mode_from_cmd` arm + `apply_entry_mode` opens transfer)
- Modify: `src/tui/launcher.rs` (`Ctrl-T` → `Outcome::OpenTransfer` setting `pending_transfer`)

**Interfaces:**
- ```rust
  // args.rs
  pub enum Command {
      // ...
      /// Interactive SFTP transfer screen for <name>: `sshrack sftp <name>`.
      /// Opens the dual-pane transfer view (system sftp over ControlMaster).
      /// Non-interactive transfer remains `sshrack scp`.
      Sftp {
          #[command(flatten)]
          opts: ConnectOptions,
          /// Host name to open the transfer screen for.
          name: String,
      },
  }
  ```
- `EntryMode::Transfer { name: String }` with `target_tab() => Tab::Hosts`. `apply_entry_mode` for `Transfer` looks up the host by name, sets `pending_transfer`, and the loop's first tick opens it (or `open_transfer` is called directly from `run` if the host exists; a missing name surfaces a clean error before the alternate screen).

- [ ] **Step 1: Write failing tests (RED).**
  - `args.rs`: `Cli::try_parse_from(["sshrack","sftp","web1"])` parses to `Command::Sftp { name: "web1", .. }`; `sshrack sftp` (no name) is a clap usage error.
  - `main.rs` `route_is_tui`: `Command::Sftp{..}` → true (extend the existing `route_is_tui` tests).
  - `mod.rs` `entry_mode_from_cmd`: `Command::Sftp{ name, .. }` → `EntryMode::Transfer { name }`, `target_tab() == Hosts`.

- [ ] **Step 2: Implement.**
  - `args.rs`: add the `Sftp` variant after `Scp`. Add a clap conflict test that `sftp` requires a name (clap does this by making `name: String` non-optional).
  - `main.rs`: in `route_is_tui`, add `Some(Command::Sftp { .. }) => true`. (No `edit_requires_name_error` change — sftp always has a name.)
  - `mod.rs`: add `EntryMode::Transfer { name }` + its `target_tab` arm + the `entry_mode_from_cmd` arm. Extend `apply_entry_mode` so that on `EntryMode::Transfer` it resolves the name → host id (error to stderr + `exit_code::USAGE`/`NOT_FOUND` before the alternate screen if missing) and sets `app.pending_transfer = Some(id)`; the first `run_loop` tick drains `OpenTransfer` (the launcher's first key is synthetic — see Step 2b).
  - **Step 2b (synthetic first event):** the cleanest hook is: after `apply_entry_mode(Transfer)`, `run_loop` checks `app.pending_transfer` on its FIRST iteration and treats it as if `OpenTransfer` had been returned (call `open_transfer` directly). Add a `bool first_tick` guard in `run_loop`. This avoids polluting `on_key` with a phantom outcome.
  - `launcher.rs`: in `on_key`, add `KeyCode::Char('t') if ctrl =>` → if a host is selected set `pending_transfer` + return `Outcome::OpenTransfer` (mirror the `Enter` → `ConnectRequested` shape). Keep `Ctrl-C` exact-match precedence.

- [ ] **Step 3: Build + test + clippy + fmt + commit.**
  ```bash
  cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
  git add -A && git commit -m "feat(sftp): sshrack sftp <name> CLI + Ctrl-T launcher entry"
  ```

---

## Task 12: Docs + full gate + manual smoke

Update the project doc to reflect that SFTP is shipped, then run the full quality gate and a manual smoke against a real host.

**Files:**
- Modify: `CLAUDE.md` (move `sshrack sftp` out of "Later phase (still deferred)"; add a `## SFTP transfer (sshrack sftp)` sub-section under TUI describing the dual-pane, keys, ControlMaster model, and the file-picker-vs-TransferScreen relationship).

- [ ] **Step 1: Update CLAUDE.md.**
  - Remove `sshrack sftp` from the "Later phase (still deferred)" bullet (CLAUDE.md:265).
  - Add a new TUI sub-section: entry (`sshrack sftp <name>` and `Ctrl-T` from the launcher), the dual-pane layout, the keymap table (Tab/↑↓/←→/Space/Ctrl-Enter/Esc/Ctrl-C), the "transfer screen is a full-screen App view, not an Overlay" note, the ControlMaster+`sftp -b -` model + `XDG_RUNTIME_DIR` socket, and a line stating `DirSource` is shared with the file picker while the `FilePicker` component itself is unchanged (the decoupling decision).
  - Add `sftp/` to the module tree under `connect/` and `transfer/` under `src/tui/`.

- [ ] **Step 2: Full gate.**
  ```bash
  cargo build --workspace --release
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo fmt --check
  ```

- [ ] **Step 3: Manual smoke (controller does this — not the subagent).** Against a real configured host with a key:
  - `sshrack sftp <name>` opens the transfer screen, remote pane populates with the home listing, local pane shows the current dir.
  - `Tab` switches focus; `↑↓` moves; `→` enters a dir; `←` goes up; a path-like query (`/tmp`) + `Enter` jumps; a fuzzy query filters.
  - `Space` marks a file; `Ctrl-Enter` enqueues a download (remote focus) and the progress panel shows rate/ETA; a second file queues.
  - A same-name destination triggers the overwrite prompt; `s` skips, `a` overwrites-all for the batch.
  - `Esc` cancels the in-flight transfer (partial file is removed); a network drop also removes the partial file (no `Done(Failed)` leaves a stub).
  - `Ctrl-T` from the launcher opens the screen for the selected host.
  - `Ctrl-C` closes the screen and the control socket file is gone from `$XDG_RUNTIME_DIR`.
  - A password/keyring host authenticates via the askpass helper (no prompt in the transfer screen).

- [ ] **Step 4: Commit + final review handoff.**
  ```bash
  git add -A && git commit -m "docs(sftp): document the dual-pane SFTP transfer screen"
  ```
  Then the controller dispatches the final whole-branch reviewer (`scripts/review-package MERGE_BASE HEAD`) and uses `superpowers:finishing-a-development-branch` to merge after fixes.

---

## Self-Review

**1. Spec coverage.**
- ControlMaster + `sftp -b -`, `$XDG_RUNTIME_DIR` socket, `ConnectTimeout`/`ServerAliveInterval` → Task 2 (argv) + Task 6 (worker). ✅
- Reuse connect orchestration (host/cred/vault/hostkey/askpass/inline-key) → Task 10 (`open_transfer` mirrors `connect_host`). ✅
- Worker thread + mpsc + RAII teardown → Task 6. ✅
- `ls -l` parse + control-char strip + spaces-in-name + filter `./..`/devices → Task 3. ✅
- Dual-pane, symmetric nav/filter/window, `Tab` focus, marks, `Ctrl-Enter` enqueue, direction-by-focus, recursive dirs → Tasks 7/8/9. ✅
- Multi-select + queue (serial), queue panel → Tasks 7/8/9. ✅
- Overwrite prompt (overwrite/skip/rename* + overwrite-all/skip-all), failed-transfer cleans partial → Task 9 (`decide`) + Task 6 (worker removes partial on failure/cancel). (*`rename` is deferred to a follow-up — see note below; the prompt ships overwrite/skip/all for MVP. The spec's "rename" option is intentionally deferred to keep MVP scoped; `decide` covers the shipped set.) ⚠️ adjusted: see note.
- Rate/ETA/byte-count progress via destination polling, 200ms → Task 4 (`progress_snapshot`) + Task 6 (poll loop). ✅
- `sshrack sftp <name>` CLI + `Ctrl-T` launcher entry + `route_is_tui` → Task 11. ✅
- `DirSource` reuse, `FilePicker` unchanged → Task 5 (`SftpDirSource`) + File Structure note. ✅
- Deferred: file management (delete/mkdir/rename/chmod), resume, dir cache, global shared master, concurrency, symlink, history → explicitly out of MVP (Global Constraints + per-task scope). ✅

**Note on "rename" in the overwrite prompt.** The discussion listed overwrite/skip/rename. MVP ships overwrite/skip/overwrite-all/skip-all; `rename` is deferred (it needs a free-text input popup, which is extra surface). The plan's `OverwriteChoice`/`decide` cover the shipped set; a `Rename` variant can be added later without touching `decide`'s existing arms. Flagging here so it is a conscious cut, not an omission.

**2. Placeholder scan.** No TBD/TODO. Each task gives exact file paths, signatures, test cases, and commands. Where a step says "mirror the existing X pattern", the referenced code is named (e.g. `connect_host`, the wizard's small-terminal test) so the implementer can read it.

**3. Type consistency.**
- `DirEntry` (Task 1) is consumed unchanged by Task 3 (`to_dir_entries`), Task 5 (`SftpDirSource::list` returns `Vec<DirEntry>`), Task 7 (`Pane.entries`), Task 8 (render).
- `WorkerCmd`/`WorkerEvent`/`TransferJob`/`Progress`/`OverwritePolicy` (Task 4) are used verbatim in Task 5 (runner is unaware of these — it only runs batches), Task 6 (worker), Task 9 (enqueue), Task 10 (drain).
- `Pane`/`Side`/`PaneOutcome` (Task 7) consumed by Task 8 (render) and Task 9 (on_key).
- `TransferScreen` (Task 8) + its `on_key` (Task 9) + `open_transfer` (Task 10) + `Command::Sftp`/`EntryMode::Transfer` (Task 11) chain consistently: `App.transfer: Option<TransferScreen>`, `pending_transfer: Option<Ulid>`, `Outcome::OpenTransfer`.
- `connect_opts` (Task 2) is the single source of user/port/identity tokens for both `ssh::build` and `master_argv`.
