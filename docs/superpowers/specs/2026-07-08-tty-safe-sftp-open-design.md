# TTY-safe SFTP open + unified error display

> Companion plan: `docs/superpowers/plans/2026-07-08-tty-safe-sftp-open.md`.

## Problem

When a host requires password auth but no password is configured (or the
password is wrong, or an encrypted key has no passphrase source), opening the
SFTP screen (`Ctrl-T` / `sshrack sftp <name>`) corrupts the TUI: ssh's password
prompt writes to `/dev/tty` while ratatui still owns the terminal in raw +
alternate-screen mode, and raw-mode input/echo is garbled. The prompt overlaps
the TUI and "the whole page becomes messy".

## Root cause

The two connect paths treat the TTY oppositely.

- **Regular connect (`Enter`):** `connect_host` returns a `ConnectRequest`;
  `TerminalGuard` drops (terminal restored) BEFORE `main` calls
  `connect::launch`. ssh inherits a normal TTY. Correct.
- **SFTP (`Ctrl-T`):** `open_transfer` → `SftpWorker::open` spawns the
  long-lived `ssh -N` master WHILE the TUI still owns alt screen + raw mode.
  The master runs with `stdin(null)`, `stdout(null)`, `stderr(inherit)`.

For a password-missing host, `resolve` returns `PasswordSource::None`;
`askpass_env_for(None)` sets no `SSH_ASKPASS`; the master ssh falls back to
`open("/dev/tty")` to prompt + read the password. That `/dev/tty` is the very
terminal the TUI holds in raw mode → the prompt overlaps the TUI and input is
garbled. There is **no fail-fast gate** before spawn. `wait_for_master` only
detects a 30s timeout, not a master that exited at once, so the user waits 30s
for a misleading "handshake timed out" while the inherited stderr already
polluted the screen. Errors are shown only as a one-line status line.

The SFTP master is long-lived and the UI runs on top of it, so it CANNOT use
the regular connect's "drop guard → let ssh own the TTY → restore" pattern.
The only correct policy is: **the master must never need TTY interaction.**

> Piping stderr does NOT stop ssh reading `/dev/tty` — ssh opens the
> controlling tty directly, independent of stdin/stderr. Only
> `SSH_ASKPASS_REQUIRE=force` prevents it. This is why two defense lines are
> required (one for `/dev/tty`, one for stderr), not one.

## Solution

Three defense lines + a fail-fast overlay.

### Defense 1 — structurally forbid `/dev/tty` (askpass force)

The SFTP master sets `SSH_ASKPASS=<self_exe>` + `SSH_ASKPASS_REQUIRE=force`
(+ `DISPLAY=:0`) for **all** password sources.

- `Inline` / `Config` / `Keyring`: unchanged (the helper has a payload).
- `None`: the helper is invoked with no payload → it writes a clear error and
  exits non-zero, so ssh fails immediately instead of opening `/dev/tty`.

Effect: any auth need (password or encrypted-key passphrase) goes through
askpass — success or fast failure; `open("/dev/tty")` never happens.

### Defense 2 — capture stderr + detect real failure

Master `stderr` changes from `inherit` to `piped`, drained to a buffer during
the handshake (no TTY pollution). `wait_for_master` gains a third terminator:
`master_child.try_wait() == Exited` → fail at once with the captured stderr
appended. The timeout branch stays (network-unreachable etc.), also with
stderr.

Effect: wrong password / no password / host refused → second-scale failure
with the real message (not a 30s "timed out").

### Defense 3 — unified Alert overlay

A new modal `Overlay::Alert { title, body }` (multi-line, centered,
`Esc`/`Ctrl-C` closes → return to launcher) replaces the one-line status line
for ALL `open_transfer` failures: vault locked, dangling credential, resolve
failure, master auth failure, handshake timeout.

### Fail-fast overlay (friendlier)

Conditions determinable at resolve time (`VaultLocked` / `CredentialNotFound` /
no-password-and-no-key) short-circuit to the Alert before spawn, with a
precise message (e.g. *"host 'web1' has no password configured"*). Composes
with the structural defenses: predictable cases get a clear message;
unpredictable ones (wrong password, network) are caught by the structural net.

## Scope

- **In:** SFTP `Ctrl-T` + `sshrack sftp <name>` (both route through
  `open_transfer`).
- **Out:** regular connect (`Enter`) — it drops the guard, ssh legitimately
  reads `/dev/tty` for password/passphrase; no corruption. Untouched.
- **Out:** in-TUI password entry ("补输入"); scp-from-TUI (none exists);
  vault-mode temp-file elimination (known follow-up).

## Components

- `crates/sshrack-core/src/connect/mod.rs` — `askpass_env_for` SFTP arm (force
  for all sources; `None` carries a deny marker so the helper fails clearly).
- `crates/sshrack-core/src/connect/sftp/worker.rs` — stderr piped + drain;
  `wait_for_master` exit detection; the error carries captured stderr.
- `crates/sshrack-core/src/askpass.rs` + `src/main.rs` — helper returns failure
  with a clear message when invoked with no payload (SFTP deny semantics).
- `src/tui/intent.rs` — `Overlay::Alert { title, body }` + close outcome.
- `src/tui/transfer/open.rs` — map all failures to an Alert payload; fail-fast
  before spawn.
- `src/tui/dialog.rs` (or a new alert render) — Alert chrome (reuse the
  existing dialog chrome).

## Testing

- **Unit (pure):** `askpass_env_for` SFTP arm; the `wait_for_master` failure
  decision extracted as a pure function (mock the master exit status).
- **Render:** `Alert` overlay via `TestBackend` + `insta` snapshot.
- **Integration:** mock-ssh shim — the master exits non-zero at once → `open`
  returns an error carrying the captured stderr, leaves no residual spawn, and
  produces the correct Alert payload.
