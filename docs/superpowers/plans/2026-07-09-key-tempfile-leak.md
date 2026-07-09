# Inline-Key Temp-File Leak on Interrupt — Fix (a)+(b)+(c)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the inline-key (and askpass) temp files from leaking when a connection is interrupted — a Ctrl-C on a stuck/failing connection currently leaves the `0600` private-key text sitting in `/tmp` because `KeyArtifact::drop` is skipped when the process is killed by a signal.

**Architecture:**
- **(c) Fail-fast argv** — a key-only host (identity present, no password) gets `-o IdentitiesOnly=yes -o PasswordAuthentication=no` so a bad/unreadable key fails immediately with "Permission denied (publickey)" instead of silently degrading to an interactive password prompt (the exact prompt users Ctrl-C out of, leaking the temp file). Pure argv change in the shared `connect::ssh::connect_opts`.
- **(b) Tighten the sweep backstop** — the existing startup sweep (`sweep::sweep_default`) is correct but uses a 1-hour staleness threshold, so a leaked file lingers up to an hour. Since `ssh` reads the IdentityFile once at connect time, a file more than a few minutes old is no longer needed by any live connection — lower the threshold to shrink the SIGKILL/crash leak window.
- **(a) Signal-aware immediate cleanup** — a process-global registry (`core::tempfile_registry`) records every live sshrack temp file; `KeyArtifact` and `write_password_file` register/unregister around their existing lifetimes. The binary installs a `signal-hook` SIGINT/SIGTERM handler (once, at startup) whose action is `cleanup_all()` then exit. `signal-hook`'s deferred (self-pipe) model runs the cleanup in normal thread context (safe to call `std::fs`), and the registry is the gate — when empty (no temp files live), cleanup is a no-op, so normal Ctrl-C behavior outside a connection is unchanged. This handles the common Ctrl-C/SIGTERM case immediately; (b) remains the backstop for SIGKILL/OOM where no handler can run.

**Tech Stack:** Rust 2024, MSRV 1.88; `sshrack-core` (zero-UI, thiserror); binary `sshrack` (ratatui/crossterm/anyhow). New direct dep: `signal-hook` 0.3 (already a transitive dep via crossterm/mio — `Cargo.lock` confirms `signal-hook` 0.3.18). **No `unsafe`** (sshrack hard rule) — `signal-hook`'s safe API is the whole reason it's chosen over raw `libc::sigaction`.

## Global Constraints

- English only — all source, comments, errors, commit messages.
- Zero `unsafe`. Zero `unwrap()`/`expect()` in prod (`#[cfg(test)]` ok). Secrets (`Zeroizing<String>`) never logged/printed/in errors/in argv.
- **Never reimplement SSH** — drive system `ssh`/`sftp`. (c) only adds ssh `-o` options.
- clippy strict: `cargo clippy --workspace --all-targets -- -D warnings` green before every commit. `cargo fmt` green before every commit.
- TDD for pure logic (the registry, the argv condition). Match the layer (unit for pure; manual smoke for the signal-delivery path — see each task).
- Hermetic tests: `cargo test --workspace` under `script -qec "cargo test --workspace" /dev/null` (pty) must pass; tests never mutate the real env or rely on real `/tmp` state (use `tempfile`).
- Conventional Commits `<type>(<scope>): <desc>`, no `Co-Authored-By`, explicit `git add <paths>`.
- Dev stage — no compat/dead code. No `#[allow(dead_code)]` left behind.

## File Structure

| File | Responsibility | Touched by |
|---|---|---|
| `crates/sshrack-core/src/connect/ssh.rs` | `connect_opts` argv builder (shared by ssh + SFTP master) | Task 1 (c) |
| `crates/sshrack-core/src/sweep.rs` | startup orphan sweep + threshold | Task 2 (b) |
| `crates/sshrack-core/src/tempfile_registry.rs` (**NEW**) | process-global live-tempfile registry: `register`/`unregister`/`cleanup_all` | Task 3 (a) |
| `crates/sshrack-core/src/connect/mod.rs` | `KeyArtifact` (write/drop) + `write_password_file` + `launch` — wire registry | Task 3 (a) |
| `crates/sshrack-core/src/lib.rs` | `pub mod tempfile_registry;` | Task 3 (a) |
| `src/signal_cleanup.rs` (**NEW**) | install SIGINT/SIGTERM handler → `cleanup_all` + exit | Task 3 (a) |
| `src/main.rs` | call `signal_cleanup::install()` once after the askpass-role check | Task 3 (a) |
| `Cargo.toml` (binary `sshrack`) | add `signal-hook` 0.3 | Task 3 (a) |

---

## Task 1: (c) Fail-fast argv for key-only-no-password hosts

**Files:**
- Modify: `crates/sshrack-core/src/connect/ssh.rs` (`connect_opts` :34-53; update existing tests :99-202)

**Interfaces:**
- Consumes: `crate::credential::PasswordSource` (the `None` variant discriminates "no account password").
- Produces: no signature change. `connect_opts` now appends `-o IdentitiesOnly=yes -o PasswordAuthentication=no` when an identity is present and no password is configured.

**Rationale (put in the code comment):** an inline-key host with a bad/corrupt key currently lets ssh fall through to `password` auth and prompt `root@host's password:` — confusing, and the prompt is exactly what users Ctrl-C out of (leaking the temp file). `PasswordAuthentication=no` kills that fallback so a bad key fails fast with "Permission denied (publickey)". It is chosen over `PreferredAuthentications=publickey` deliberately: it leaves `keyboard-interactive` enabled, so key-then-2FA flows still work; only the `password` method (which the host has no secret for anyway) is disabled. `IdentitiesOnly=yes` additionally stops ssh dragging in unrelated agent keys.

- [ ] **Step 1: Write the failing test (RED)** — add to `connect/ssh.rs` test module:

```rust
#[test]
fn connect_opts_key_only_no_password_restricts_to_publickey() {
    // A key-only host (identity present, PasswordSource::None) must restrict
    // ssh so a bad/unreadable key fails fast instead of degrading to a
    // password prompt. IdentitiesOnly=yes + PasswordAuthentication=no.
    let opts = connect_opts(&resolved(), &host(), &Overrides::default());
    assert!(
        opts.windows(2)
            .any(|w| w == ["-o".to_string(), "IdentitiesOnly=yes".to_string()]),
        "key-only host must set IdentitiesOnly=yes, got {opts:?}"
    );
    assert!(
        opts.windows(2).any(|w| w == ["-o".to_string(), "PasswordAuthentication=no".to_string()]),
        "key-only host must set PasswordAuthentication=no, got {opts:?}"
    );
}

#[test]
fn connect_opts_key_plus_password_does_not_restrict() {
    // A host with BOTH a key and a password keeps password fallback — do not
    // add the publickey-only restrictions.
    use crate::credential::PasswordSource;
    let mut r = resolved();
    r.password = PasswordSource::Inline(zeroize::Zeroizing::new("pw".into()));
    let opts = connect_opts(&r, &host(), &Overrides::default());
    assert!(!opts.iter().any(|a| a == "PasswordAuthentication=no"));
    assert!(!opts.iter().any(|a| a == "IdentitiesOnly=yes"));
}

#[test]
fn connect_opts_no_key_no_password_no_restrictions() {
    // No identity at all (agent / password-less) → no -i and no restrictions.
    let mut r = resolved();
    r.key_path = None;
    let opts = connect_opts(&r, &host(), &Overrides::default());
    assert!(!opts.contains(&"-i".to_string()));
    assert!(!opts.iter().any(|a| a == "PasswordAuthentication=no"));
}
```

(`zeroize` is already a sshrack-core dep; if `PasswordSource::Inline` is constructed differently in this codebase, mirror the existing `resolved()` fixture's idiom — check `PasswordSource` variants in `crates/sshrack-core/src/credential.rs`.)

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p sshrack-core --lib connect::ssh`
Expected: `connect_opts_key_only_no_password_restricts_to_publickey` FAILS (options absent).

- [ ] **Step 3: Implement (GREEN)** — in `connect_opts`, after the identity block (`:47-50`), before the closing `opts`, add:

```rust
    // Key-only host (identity present, no account password): restrict ssh so a
    // bad/unreadable key fails fast with "Permission denied (publickey)" rather
    // than silently degrading to an interactive password prompt — which is the
    // prompt users Ctrl-C out of, leaking the inline-key temp file. We disable
    // the `password` method only (not keyboard-interactive), so key-then-2FA
    // flows still work; the host has no password secret anyway. IdentitiesOnly
    // additionally stops ssh dragging in unrelated ssh-agent keys.
    let has_identity = identity.is_some();
    let no_password = matches!(resolved.password, crate::credential::PasswordSource::None);
    if has_identity && no_password {
        opts.push("-o".into());
        opts.push("IdentitiesOnly=yes".into());
        opts.push("-o".into());
        opts.push("PasswordAuthentication=no".into());
    }
```

- [ ] **Step 4: Update the existing snapshot tests that now gain the two `-o` pairs**

The fixture `resolved()` (`:90-97`) is key + `PasswordSource::None`, so every test asserting an exact `connect_opts`/`build` argv for that fixture now must include the two new `-o` pairs after `-i <key>`. Update (append the four tokens in the expected `vec!` / add `.contains` checks):
- `connect_opts_returns_user_port_identity` (`:146-162`) — exact-equality assertion; append the four tokens.
- `connect_opts_overrides_win_over_resolved` (`:182-202`) — the override supplies an identity and `resolved.password` is still `None`, so restrictions apply; append the four tokens.
- `interactive_shell_argv` (`:99-110`) — uses `.contains`, add two `.contains` checks or leave (it uses `.contains`, not exact — verify it still passes; it asserts presence of specific tokens, so it stays green; confirm).
- Tests using a no-key fixture (`connect_opts_drops_identity_when_neither_override_nor_resolved_key` `:165`) must NOT gain the restrictions — verify they stay green (the `has_identity` guard).

Run `cargo test -p sshrack-core --lib connect::ssh` and fix every assertion failure by adding the four tokens where the fixture is key+no-password. Do NOT change behavior to satisfy a test — only update expectations to match the new (correct) argv.

- [ ] **Step 5: Check SFTP-side ripple** — `connect_opts` is shared by the SFTP master argv (`connect/sftp/argv.rs` / `connect/sftp/source.rs`). Run `cargo test -p sshrack-core --lib connect::sftp` and `cargo test -p sshrack-core --lib transfer`; update any snapshot test whose fixture is key+no-password. SFTP master is non-interactive (no tty), so the restrictions are harmless there and only make a bad key fail faster.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/connect/ssh.rs
git commit -m "fix(connect): fail fast on bad key for key-only hosts, no password fallback"
```

---

## Task 2: (b) Lower the startup sweep threshold

**Files:**
- Modify: `crates/sshrack-core/src/sweep.rs` (`sweep_default` :58-68 + module/doc comments :1-6)

**Interfaces:** none (policy constant only).

**Rationale:** `ssh` reads the `-i` IdentityFile once, early, at the start of a connection; after that the temp file is never re-read. So a `sshrack-key-*.pem` more than a few minutes old is residue, not a live connection's file. The current 1-hour threshold leaves a leaked private key on disk for up to an hour (and only clears on the *next* sshrack launch). Lower to 5 minutes — a 12× shrink of the SIGKILL/crash leak window, while still tolerating any real connection whose ssh hasn't yet opened the key (a multi-minute stall there means ssh itself hung).

- [ ] **Step 1: Write the pinning test (RED)** — add to `sweep.rs` test module:

```rust
#[test]
fn sweep_default_threshold_is_short() {
    // The SIGKILL/crash leak window = the sweep threshold. ssh reads the -i
    // IdentityFile once at connect, so files older than a few minutes are safe
    // to reclaim. Pin the constant so a future bump is a conscious decision.
    assert!(
        super::stale_threshold() <= std::time::Duration::from_secs(600),
        "sweep threshold must stay <= 10 min to bound the on-disk secret window"
    );
}
```

- [ ] **Step 2: Run — expect failure** (`stale_threshold` undefined).

- [ ] **Step 3: Implement** — replace the `sweep_default` body and add the named constant + accessor:

```rust
/// SIGKILL/crash leak window: a temp file older than this at startup is
/// reclaimed. `ssh` reads the `-i` IdentityFile once at connect time, so a
/// file more than a few minutes old is residue from a crashed prior run, not a
/// live connection's file (a live connection whose ssh hasn't opened the key
/// after this long has hung). Kept small to bound the on-disk secret window.
const STALE_THRESHOLD: Duration = Duration::from_secs(300);

/// Exposed so the threshold can be pinned by a unit test (a future bump should
/// be a conscious decision, since it bounds how long a leaked key sits on disk).
pub fn stale_threshold() -> Duration {
    STALE_THRESHOLD
}

/// Default startup sweep: the std temp dir, "now", and the staleness threshold.
/// Best-effort; all errors are swallowed.
pub fn sweep_default() {
    let _ = sweep_stale_tempfiles(&std::env::temp_dir(), SystemTime::now(), STALE_THRESHOLD);
}
```

Update the module doc comment (`:1-6`) and the `sweep_default` doc (`:58-61`) that currently say "1-hour": change to "5-minute" and add the ssh-reads-once rationale.

- [ ] **Step 4: Run — expect green**

Run: `cargo test -p sshrack-core --lib sweep`
Expected: all PASS (the parameterized `sweep_stale_tempfiles` tests pass injected `max_age`, unaffected by the constant).

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/sweep.rs
git commit -m "fix(sweep): shrink temp-file leak window from 1h to 5min"
```

---

## Task 3: (a) Registry + signal-aware cleanup

**Files:**
- Create: `crates/sshrack-core/src/tempfile_registry.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (declare module)
- Modify: `crates/sshrack-core/src/connect/mod.rs` (wire KeyArtifact + write_password_file + launch)
- Create: `src/signal_cleanup.rs`
- Modify: `src/main.rs` (call `install()`)
- Modify: `Cargo.toml` (binary) — add `signal-hook`

**Interfaces:**
- Produces (core): `tempfile_registry::register(PathBuf)`, `tempfile_registry::unregister(&Path)`, `tempfile_registry::cleanup_all() -> usize`.
- Produces (binary): `signal_cleanup::install()` — idempotent, call once from `main`.

**Architecture:** the registry is a `Mutex<Vec<PathBuf>>` in core (same precedent as `sweep` doing direct fs cleanup in core). The invasive signal wiring stays in the binary (keeps `signal-hook` out of core, keeps core "capability + bookkeeping"). `signal-hook`'s `Signals::forever()` runs a normal thread (self-pipe deferral) — safe to call `std::fs::remove_file` there. The handler unconditionally calls `cleanup_all()` (no-op when the registry is empty) then `exit(128 + signo)`, so behavior outside a connection is unchanged.

### Step 1: core registry — write failing tests

Create `crates/sshrack-core/src/tempfile_registry.rs` with the test module first:

```rust
//! Process-global registry of sshrack temp files held by a live connection
//! (inline-key `.pem` / cert, askpass `.pw`). `KeyArtifact` and
//! `write_password_file` register on create and unregister on Drop/exit; a
//! signal-time cleaner (`cleanup_all`) wipes whatever is still registered so a
//! Ctrl-C / SIGTERM mid-connection does not leave secrets on disk — `Drop` is
//! skipped when the process is killed by a signal.
//!
//! Lock-guarded, best-effort: a fs error or lock-poison during cleanup never
//! propagates (a cleanup failure must not mask the signal).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LIVE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Record a temp file path as currently live so a signal-time cleanup can
/// remove it if the process is killed before its owner `Drop`s.
pub fn register(path: PathBuf) {
    if let Ok(mut v) = LIVE.lock() {
        v.push(path);
    }
}

/// Remove a path from the registry (its owner `Drop` ran normally).
pub fn unregister(path: &Path) {
    if let Ok(mut v) = LIVE.lock() {
        v.retain(|p| p != path);
    }
}

/// Delete every registered temp file from disk and clear the registry. Returns
/// the count removed. Best-effort: fs errors and a poisoned lock are swallowed.
/// Called by the binary's SIGINT/SIGTERM handler.
pub fn cleanup_all() -> usize {
    let paths = LIVE
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default();
    paths
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_all_removes_registered_files() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("sshrack-key-a.pem");
        let b = dir.path().join("sshrack-askpass-b.pw");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        register(a.clone());
        register(b.clone());
        let removed = cleanup_all();
        assert_eq!(removed, 2);
        assert!(!a.exists());
        assert!(!b.exists());
    }

    #[test]
    fn unregister_keeps_a_file_registered_as_live() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("sshrack-key-keep.pem");
        let gone = dir.path().join("sshrack-key-gone.pem");
        std::fs::write(&keep, b"x").unwrap();
        std::fs::write(&gone, b"x").unwrap();
        register(keep.clone());
        register(gone.clone());
        unregister(&gone); // its Drop ran
        let removed = cleanup_all();
        assert_eq!(removed, 1);
        assert!(!keep.exists()); // keep was still registered → removed
        assert!(gone.exists()); // unregistered → left alone
    }

    #[test]
    fn cleanup_all_is_noop_when_empty() {
        // Drain any leftovers from other tests so this is deterministic.
        let _ = cleanup_all();
        assert_eq!(cleanup_all(), 0);
    }

    #[test]
    fn cleanup_all_swallows_missing_file() {
        // A registered path that no longer exists (owner already removed it)
        // must not panic or be counted.
        register(PathBuf::from("/tmp/sshrack-definitely-not-here-xyz.pem"));
        let removed = cleanup_all();
        assert_eq!(removed, 0);
    }
}
```

NOTE on test isolation: the registry is a process global, so tests share it. The tests above are ordered/defensive (`cleanup_all_is_noop_when_empty` drains first; others register fresh paths and clean up after). If the test runner parallelizes and they clash, serialize with a `Mutex` fixture or run with `--test-threads=1` for this module — prefer making each test self-contained (register unique paths, assert, cleanup_all at end) so order doesn't matter. The bodies above already `cleanup_all` at the end of each nontrivial test.

- [ ] **Step 2: Run — expect failure** (`tempfile_registry` not declared in lib.rs).

### Step 3: Declare the module

In `crates/sshrack-core/src/lib.rs`, add alongside the existing module declarations:

```rust
pub mod tempfile_registry;
```

Run `cargo test -p sshrack-core --lib tempfile_registry` → PASS.

### Step 4: Wire KeyArtifact

In `crates/sshrack-core/src/connect/mod.rs`:

- In `KeyArtifact::write`, after the private file is written and the cert path resolved (just before `Ok(Self { ... })` at `:265`), register both paths:

```rust
    crate::tempfile_registry::register(private_path.clone());
    if let Some(cp) = &cert_path {
        crate::tempfile_registry::register(cp.clone());
    }
```

- In `impl Drop for KeyArtifact` (`:278-288`), unregister before the existing `remove_file` calls (so the registry and disk stay in sync — a `cleanup_all` racing the Drop won't double-remove):

```rust
impl Drop for KeyArtifact {
    fn drop(&mut self) {
        crate::tempfile_registry::unregister(&self.private);
        if let Some(c) = &self.cert {
            crate::tempfile_registry::unregister(c);
        }
        let _ = std::fs::remove_file(&self.private);
        if let Some(c) = &self.cert {
            let _ = std::fs::remove_file(c);
        }
    }
}
```

### Step 5: Wire the askpass password file

In `write_password_file` (`:130-161`), register on success (just before `Ok(path)`):

```rust
    crate::tempfile_registry::register(path.clone());
    Ok(path)
```

In `launch` (`:326-351`), after `cmd.status()` returns and the existing `remove_file(p)` block (`:346-349`), unregister:

```rust
    if let Some(p) = pw_file {
        crate::tempfile_registry::unregister(&p);
        let _ = std::fs::remove_file(p);
    }
```

### Step 6: Add the dependency

```bash
cargo add signal-hook@0.3 -p sshrack
```

(Confirm the binary package name is `sshrack` — `cargo add` will error clearly if not; the dependency-policy doc uses `-p sshrack`.)

### Step 7: Binary signal handler

Create `src/signal_cleanup.rs`:

```rust
//! Install a SIGINT/SIGTERM handler that wipes any live sshrack temp files
//! (registered in `sshrack_core::tempfile_registry`) before the process exits.
//! `Drop` is skipped when the process is killed by a signal; this closes that
//! leak for the common Ctrl-C / SIGTERM case (SIGKILL/OOM still falls to the
//! startup `sweep`). Uses signal-hook's deferred (self-pipe) model so cleanup
//! runs in normal thread context — safe to call `std::fs`.
//!
//! The handler calls `cleanup_all` (a no-op when nothing is registered) then
//! exits with the conventional 128 + signo code, so Ctrl-C outside a
//! connection behaves as before.

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::sync::Once;

/// Install the SIGINT/SIGTERM handler. Idempotent; intended to be called once
/// from `main` after the askpass-role early-return (the askpass helper fork is
/// short-lived and owns no temp files).
pub fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // If Signals::new fails, best-effort: skip — the startup `sweep` stays
        // the backstop. signal-hook's self-pipe deferral means `signals.forever`
        // runs in normal thread context, so calling `std::fs` there is safe.
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = std::thread::Builder::new()
            .name("sshrack-signal-cleanup".into())
            .spawn(move || {
                for sig in signals.forever() {
                    let _ = sshrack_core::tempfile_registry::cleanup_all();
                    // 128 + signo is the shell convention for a signal exit.
                    std::process::exit(128 + (sig as i32));
                }
            });
    });
}
```

If `TERM_SIGNALS`/`USR1` imports warn unused, simplify to exactly `use signal_hook::consts::{SIGINT, SIGTERM};` and `Signals::new([SIGINT, SIGTERM])`. Keep it minimal — the goal is SIGINT + SIGTERM only. Remove the `USR1` line entirely if unused (no dead imports — dev-stage rule).

### Step 8: Wire install() into main

In `src/main.rs`, after the askpass-role block (`:12-24`, the `if std::env::var_os(...)` early-return) and before `let code = run_main();`:

```rust
    // Install before any connection can run: a Ctrl-C / SIGTERM mid-connection
    // must wipe live temp files (Drop is skipped on signal-kill). No-op outside
    // a connection. Not installed for the askpass helper fork (above early
    // return) — it owns no temp files.
    signal_cleanup::install();
```

And declare the module near `mod cli;`:

```rust
mod signal_cleanup;
```

### Step 9: clippy + fmt + test + commit

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
script -qec "cargo test --workspace" /dev/null
git add crates/sshrack-core/src/tempfile_registry.rs crates/sshrack-core/src/lib.rs crates/sshrack-core/src/connect/mod.rs src/signal_cleanup.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "fix(connect): wipe temp files on SIGINT/SIGTERM so a Ctrl-C does not leak keys"
```

### Step 10: Manual smoke (signal delivery cannot be unit-tested hermetically)

Report these in the task report (not automated):
1. Inline-key host whose key makes ssh hang or fail (e.g., point at a non-responsive port, or a deliberately-corrupt key now that (c) fails fast): launch `sshrack <host>`, hit Ctrl-C while ssh is running. Confirm no `sshrack-key-*.pem` remains in `/tmp` (`ls /tmp/sshrack-key-*.pem` → none).
2. TUI: open the launcher, confirm Ctrl-C still cancels the overlay / quits as before (raw-mode key event, not SIGINT — the handler must not change TUI Ctrl-C behavior).
3. Clean connection (good key): connect and exit normally; confirm no temp file remains (Drop path still works) and the registry didn't grow.

---

## Self-Review

**Spec coverage:**
- (a) signal-aware immediate cleanup → Task 3 (registry + handler + wiring). ✓
- (b) startup sweep backstop → Task 2 (lower threshold; module already exists and is wired in `main.rs:run_main`). ✓ (verified: `sweep_default()` is already called at `src/main.rs` start of `run_main`.)
- (c) fail-fast argv → Task 1 (`connect_opts` condition). ✓
- The compounding trigger (bad key → password prompt → Ctrl-C → leak) is addressed two ways: (c) removes the prompt, (a) catches the Ctrl-C if it still happens. ✓

**Placeholder scan:** none — all steps carry verbatim code and exact paths.

**Type consistency:** `register(PathBuf)` / `unregister(&Path)` / `cleanup_all() -> usize` consistent across registry def + all 4 wiring points (KeyArtifact write/drop, write_password_file, launch). `PasswordSource::None` discriminates consistently in Task 1 test + impl.

**Ripple risks flagged for implementers:**
- Task 1 changes the shared `connect_opts` argv → existing snapshot tests in `connect/ssh.rs` AND possibly `connect/sftp/*` gain two `-o` pairs for key+no-password fixtures. Step 4 + Step 5 enumerate this; do not "fix" tests by weakening behavior.
- Task 3's registry is a process global → tests must be self-contained (unique paths, `cleanup_all` at end). Step 1 calls this out.
- Task 3's handler is global; verify TUI Ctrl-C is unchanged (raw mode → key event, not SIGINT) — Step 10 smoke #2.
- `signal-hook` must be a binary dep only (not core) — Step 6 + Step 7 keep core free of it.

**Out of scope (deliberate):** switching inline keys to an ssh-agent model (option (d) from the design discussion) — that eliminates temp files entirely but is a separate, larger feature. This plan keeps the temp-file model and plugs its leak vectors.
