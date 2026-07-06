# SFTP Transfer (`sshrack sftp`)

Dual-pane interactive SFTP over the system `ssh`/`sftp` binaries (zero protocol
libraries; the "Never Reimplement SSH" invariant holds). The high-frequency
transfer keymap lives in `CLAUDE.md`; this file holds the architecture and
failure-hygiene design.

## Connection Model

A background `ssh -N -o ControlMaster=yes` owns one authenticated connection (built via the connect orchestration: host/cred resolve, vault, hostkey, askpass, inline-key materialize); every `sftp -b -` operation mounts it via `-o ControlPath=<sock>` (socket under `$XDG_RUNTIME_DIR`, with `ConnectTimeout` + `ServerAliveInterval`). A dedicated worker thread (`connect/sftp/worker.rs`) owns the master + runs sftp batches serially, talks to the UI via `std::mpsc` (`WorkerCmd`/`WorkerEvent`), and tears down in `Drop` (RAII: kill child + `ssh -O exit` + socket removal). Progress is polled by sampling the destination file size every ~200ms (rate/ETA derived) — sftp's progressmeter is tty-only and silent under batch mode, so sshrack never taps the byte stream (the connect-path "never in the data stream" invariant holds).

## Entry

- `sshrack sftp <name>` (CLI — opens the TUI straight into the transfer screen for that host; a missing host fails `HostNotFound` BEFORE the alternate screen, exit 4).
- `Ctrl-T` on a host in the launcher.

## Screen (`tui/transfer/`)

A full-screen `App` view (not an `Overlay`) — two `Pane`s (local | remote), a progress/queue panel, a hotkey footer. Same-name conflicts prompt overwrite/skip/overwrite-all/skip-all (downloads check the local target; uploads overwrite in place — remote-exists check deferred to a later phase).

## Decoupling

`DirSource` is shared with the file picker, but the `FilePicker` component is NOT reused (single-select modal vs dual-pane). `SftpDirSource` implements `DirSource` and runs in the worker thread; the local pane uses `LocalDirSource` inline. Pure navigation/filter/window helpers are shared.

## Failure Hygiene

A failed or cancelled transfer removes the partial destination (download: local `remove_file`; upload: `rm` sftp batch via the runner — recursive-dir upload cleanup is a documented gap), avoiding the stub-file-then-skip-on-retry stuck state observed in the predecessor.

## Later Phase (still deferred)

- Port forwarding, `~/.ssh/config` read-only import, 2FA, `print-command` + clipboard.
- SFTP file-management (delete/mkdir/rename/chmod), resume (`reget`/`reput`), directory cache, global shared ControlMaster (connect/scp reuse), concurrent transfers, recursive-dir upload partial cleanup, upload remote-exists overwrite check.

The CLI scripttable-transfer moat (`sshrack scp`) and non-interactive command execution (`sshrack <name> <cmd>`) remain first-class.
