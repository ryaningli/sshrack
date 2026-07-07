# SFTP Transfer (`sshrack sftp`)

Dual-pane interactive SFTP over the system `ssh`/`sftp` binaries (zero protocol
libraries; the "Never Reimplement SSH" invariant holds). The high-frequency
transfer keymap lives in `CLAUDE.md`; this file holds the architecture and
failure-hygiene design.

## Connection Model

A background `ssh -N -o ControlMaster=yes` owns one authenticated connection (built via the connect orchestration: host/cred resolve, vault, hostkey, askpass, inline-key materialize); every `sftp -b -` operation mounts it via `-o ControlPath=<sock>` (socket under `$XDG_RUNTIME_DIR`, with `ConnectTimeout` + `ServerAliveInterval`). A dedicated worker thread (`connect/sftp/worker.rs`) owns the master + runs sftp batches serially, talks to the UI via `std::mpsc` (`WorkerCmd`/`WorkerEvent`), and tears down in `Drop` (RAII: kill child + `ssh -O exit` + socket removal). Progress is polled by sampling the destination file size every ~200ms (rate/ETA derived) — sftp's progressmeter is tty-only and silent under batch mode, so sshrack never taps the byte stream (the connect-path "never in the data stream" invariant holds).

## Entry

- `sshrack sftp <name>` (CLI — opens the TUI straight into the transfer screen for that host; a missing host fails `HostNotFound` BEFORE the alternate screen, exit 4). Honors the same per-connection flags as `ssh`/`scp` — `--ad-hoc`, `-c/--credential`, `-l/--user`, `-p/--port`, `-i/--identity` — so `sshrack --ad-hoc -c yushi sftp 192.168.20.18` opens the screen for an unsaved host (remote pane title = the address). `--accept-new` is a no-op here: a first-seen host key is confirmed via the interactive popup, same as `Ctrl-T`.
- `Ctrl-T` on a host in the launcher.

## Screen (`tui/transfer/`)

A full-screen `App` view (not an `Overlay`) — two `Pane`s (local | remote), a progress/queue panel, a hotkey footer. Each pane is a titled bordered block — `local` / `<user>@<host>` (the remote title is set in `open_transfer` once auth resolves); the focused pane gets an accent border + bold title, the unfocused pane is dimmed. Same-name conflicts prompt overwrite/skip/overwrite-all/skip-all (downloads check the local target; uploads overwrite in place — remote-exists check deferred to a later phase).

## Decoupling

`DirSource` is shared with the file picker, but the `FilePicker` component is NOT reused (single-select modal vs dual-pane). `SftpDirSource` implements `DirSource` and runs in the worker thread; the local pane uses `LocalDirSource` inline. Pure navigation/filter/window helpers are shared.

## Failure Hygiene

A failed or cancelled transfer removes the partial destination (download: local `remove_file`; upload: `rm` sftp batch via the runner — recursive-dir upload cleanup is a documented gap), avoiding the stub-file-then-skip-on-retry stuck state observed in the predecessor.

## Later Phase (still deferred)

- Port forwarding, `~/.ssh/config` read-only import, 2FA, `print-command` + clipboard.
- SFTP file-management (delete/mkdir/rename/chmod), resume (`reget`/`reput`), directory cache, global shared ControlMaster (connect/scp reuse), concurrent transfers, recursive-dir upload partial cleanup, upload remote-exists overwrite check.

The CLI scripttable-transfer moat (`sshrack scp`) and non-interactive command execution (`sshrack <name> <cmd>`) remain first-class.

## Queue Manager (`^Q`)

The transfer screen is backed by a `TransferLedger` (in `tui/transfer/ledger.rs`) — the single source of truth for every transfer task (queued + in-flight + recent history) and the queue-level pause flag. Concurrency is 1: at most one task is `InFlight` at a time.

**Status band (main screen, 2 rows).** Row 1 is the active transfer (`path  P%  rate  ETA` over a `Gauge`; a dim "no transfer in flight" placeholder when idle). Row 2 is the summary line: `done X/Y · fail Z` tinted danger-red when `Z > 0`, followed by `· paused` (accent) when the queue is paused, followed by any transient status message (truncated to fit). `done` counts `Done(Ok)` only — failed and cancelled tasks count toward `Y` (and `Z` for failures) but never toward `X`, so the two counters stay disjoint.

**Opening the modal.** `Ctrl-Q` (`^Q`) opens the queue-manager overlay (footer-advertised; bare `q`/`Q` stay in the pane search box per the key-binding invariant). The overlay splits tasks into three view-tabs cycled by `Tab` / `Shift-Tab`: Active lists in-flight + queued tasks; Failed lists failed + cancelled (retryable); Completed lists finished tasks. Each view keeps its own cursor, so a long completed history never floods the active view. The overlay's header mirrors the summary band (`done X/Y · fail Z [· paused]`); `Esc` closes it.

**Row states.** `InFlight` (the active task), `Queued` (waiting — dispatch is FIFO, head first), `Done(Ok)` (completed — Completed tab), `Done(Failed)` (failed — Failed tab), `Done(Cancelled)` (cancelled — Failed tab, retryable). Retry targets `Failed` and `Cancelled` only; `Done(Ok)` and non-`Done` tasks are not retryable.

**Operations.**

| Key | Action (queue overlay) |
|---|---|
| `Tab` / `Shift-Tab` | cycle view: Active / Failed / Completed |
| `↑`/`↓` or `k`/`j` | move selection (current view) |
| `Enter` / `r` | retry the selected failed/cancelled task |
| `Del` / `d` | remove the selected task (cancel if in-flight) |
| `c` | cancel the in-flight task |
| `p` | pause / resume the queue |
| `Esc` | close the overlay |

**Honest scope notes (MVP).**

- **Pause is queue-level, not per-task.** The current file runs to completion (or failure); only subsequent dispatch is gated. Resuming a paused queue with pending work and nothing in flight re-signals dispatch via the loop's idle gate.
- **Retry re-transfers from byte 0.** sshrack has no `reget`/`reput` (system `sftp` batch mode is append-unaware here), so retry is a fresh transfer, not a resume. The failure-hygiene cleanup already removed the partial destination, so there is no stub to collide with.
- **Folders are indeterminate.** A recursive folder transfer (`get -R` / `put -R`) is one ledger task with no per-file progress — the gauge reads the whole dir as a single indeterminate unit. Per-file expansion (splitting a folder task into per-file children with real byte progress) is a future phase.

