# TTY-safe SFTP open Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SFTP open path (`Ctrl-T` / `sshrack sftp <name>`) structurally incapable of corrupting the TUI when auth needs interaction, and route every open failure through a unified modal Alert.

**Architecture:** Three defense lines + a fail-fast overlay. (1) The SFTP master forces `SSH_ASKPASS_REQUIRE=force` for every password source, and a new `SSHRACK_ASKPASS_DENY` marker makes the helper fail clearly for `None` instead of letting ssh read `/dev/tty`. (2) The master's stderr is captured (not inherited) and `wait_for_master` detects a master that exited at once, so failure is second-scale with the real message. (3) All `open_transfer` failures surface in a new `Overlay::Alert` instead of a one-line status. Resolve-time failures (vault locked, dangling cred, no-password-no-key) short-circuit to the Alert before spawn.

**Tech Stack:** Rust 2024, sshrack-core (zero-UI), ratatui 0.30 + crossterm, thiserror (core) / anyhow (app).

**Spec:** `docs/superpowers/specs/2026-07-08-tty-safe-sftp-open-design.md`.

## Global Constraints

Copied verbatim from `CLAUDE.md` — every task implicitly includes these:

- **English only** — all source, comments, doc comments, errors, help text, log output, commit messages.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()` / `expect()`** in production — only `#[cfg(test)]` or genuinely unreachable states with `expect("invariant: ...")`.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged, printed, in errors, or in argv/`ps`. The deny path writes a fixed string, never a secret.
- **Never Reimplement SSH** — spawn/drive the system `ssh`/`sftp`; no protocol libraries.
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Errors** — core uses `thiserror`; app uses `anyhow` with `.context()`. All fallible ops propagate via `?`.
- **Hermetic tests** — `cargo test --workspace` green with no env vars; inject via params/traits/tempfiles; never mutate the real env. Tests run under a pty: `script -qec "cargo test --workspace" /dev/null`.
- **Snapshots** — commit the `.snap`, never the `.snap.new`. Seed with `INSTA_UPDATE=always`.
- **Commits** — Conventional Commits `<type>(<scope>): <desc>`, no `Co-Authored-By` trailer. Explicit `git add <paths>`, never `git add -A`.
- **MSRV 1.88**, edition 2024. `usize::div_ceil` is stable (1.73+) — OK to use.

**Task dependency:** Task 1 (Alert) and Task 2 (askpass deny) are independent. Task 3 (worker) consumes Task 2's `askpass_env_for_sftp`. Task 4 (integration) consumes Tasks 1+2+3. Execute in order 1 → 2 → 3 → 4.

---

## Task 1: `Overlay::Alert` chrome + render

**Files:**
- Modify: `src/tui/intent.rs` (add `Overlay::Alert` variant)
- Create: `src/tui/alert.rs` (`draw_alert`)
- Modify: `src/tui/mod.rs` (re-export `draw_alert` if the overlay render dispatch imports from `mod`)
- Modify: the overlay **render dispatch** (the `match Overlay { … }` that calls each overlay's draw — locate with `grep -rn "Overlay::Help" src/tui` and find the draw site it shares) to add an `Alert` arm
- Test: `src/tui/alert.rs` (`#[cfg(test)]`) + an insta snapshot

**Interfaces:**
- Produces: `Overlay::Alert { title: String, body: String }`; `draw_alert(frame, title, body)`.
- Consumes: the existing `draw_dialog(frame, title, body_rows, footer_hints)` chrome (`src/tui/dialog.rs`) and the existing overlay close path (`Outcome::CloseOverlay`, already wired for `Esc`/`Ctrl-C` on any overlay — `Alert` rides it for free, no key handling needed).

- [ ] **Step 1: Add the `Alert` variant to `Overlay`**

In `src/tui/intent.rs`, inside `pub enum Overlay { … }` (after the `StorePicker` variant):

```rust
    /// A modal error alert (e.g. a failed SFTP open). `body` is the multi-line
    /// message; `Esc` / `Ctrl-C` close it via the standard overlay close path
    /// (`Outcome::CloseOverlay`) — the shell renders behind it. Set by the
    /// `OpenTransfer` arm for every `open_transfer` failure.
    Alert { title: String, body: String },
```

- [ ] **Step 2: Write the failing render test**

Create `src/tui/alert.rs` with the test first:

```rust
//! Modal error alert overlay chrome. Reuses [`super::dialog`]'s titled bordered
//! area + footer; the body is the error message wrapped to the dialog width.

use ratatui::{Frame, layout::Alignment, widgets::{Paragraph, Wrap}};

use crate::tui::dialog::draw_dialog;

/// Draw a modal alert: a titled bordered dialog whose body is `body` (wrapped)
/// and whose footer advertises `Esc` / `Ctrl-C` to close. The caller has
/// already chosen `Overlay::Alert { title, body }`; this only renders it.
pub fn draw_alert(frame: &mut Frame, title: &str, body: &str) {
    // Size the dialog to the wrapped content so a short error yields a small
    // box and a long one (e.g. captured ssh stderr) grows up to MAX_H.
    let max_chars = 76usize;
    let body_rows: u16 = body
        .split('\n')
        .map(|line| line.chars().count().div_ceil(max_chars).max(1) as u16)
        .sum::<u16>()
        .max(1);
    let body_area = draw_dialog(frame, title, body_rows, &[("Esc", "close"), ("^C", "close")]);
    frame.render_widget(
        Paragraph::new(body.to_string())
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left),
        body_area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn draw_alert_renders_without_panic_short_body() {
        // A short error message yields a small dialog; must not panic on a
        // normal terminal.
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| draw_alert(f, " SFTP connection failed ", "host 'web1' has no password configured"))
            .expect("draw");
    }

    #[test]
    fn draw_alert_renders_without_panic_long_body() {
        // A long captured-stderr body wraps and grows the dialog up to MAX_H;
        // must not panic or overflow.
        let long = "Permission denied (publickey,password).\n".repeat(40);
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| draw_alert(f, " SFTP connection failed ", &long))
            .expect("draw");
    }

    #[test]
    fn draw_alert_renders_without_panic_tiny_terminal() {
        // A too-small screen still must not panic (dialog_area clamps).
        let backend = TestBackend::new(10, 5);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| draw_alert(f, " err ", "x"))
            .expect("draw");
    }
}
```

- [ ] **Step 3: Register the module + run tests to confirm they fail to compile (RED)**

In `src/tui/mod.rs` add `pub mod alert;` next to the other `pub mod` declarations (and `pub use alert::draw_alert;` if the render dispatch reaches it via `crate::tui::…`). Then run:

```bash
cargo test -p sshrack --lib alert
```

Expected: the new tests run once the module compiles; the overlay dispatch does not yet render `Alert` (covered in Step 4), so assert only that `draw_alert` itself passes. If `draw_alert` tests pass, the chrome is correct.

- [ ] **Step 4: Wire the `Alert` arm into the overlay render dispatch**

Locate the single `match` over `Overlay` that routes each variant to its draw call:

```bash
grep -rn "Overlay::Help\|Overlay::HostWizard\|Overlay::StorePicker" src/tui | grep -v intent.rs
```

In that `match` (the render path, not `on_key`), add an arm:

```rust
            Overlay::Alert { title, body } => {
                crate::tui::alert::draw_alert(frame, title, body);
            }
```

(Adjust the path prefix to match how the sibling arms refer to their draw fns — e.g. `super::alert::draw_alert` or `crate::tui::help::draw_help_dialog`.)

- [ ] **Step 5: Confirm `on_key` closes `Alert` via the existing overlay path**

The overlay close path already maps `Esc`/`Ctrl-C` (with an overlay open) to `Outcome::CloseOverlay` for every variant. Verify with:

```bash
grep -n "CloseOverlay\|overlay.is_some" src/tui/app.rs
```

No code change should be needed — `Alert` is an `Overlay` variant, so it inherits the close. If the close dispatch instead matches variants exhaustively, add `Overlay::Alert { .. }` to the same arm as the other non-interactive overlays (`Help`/`StorePicker`).

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
script -qec "cargo test --workspace" /dev/null
```

Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add src/tui/intent.rs src/tui/alert.rs src/tui/mod.rs
# plus the render-dispatch file edited in Step 4
git commit -m "feat(tui): add Overlay::Alert modal error dialog"
```

---

## Task 2: askpass deny — structurally forbid `/dev/tty` for the SFTP master

**Files:**
- Modify: `crates/sshrack-core/src/askpass.rs` (deny env const + `run()` branch)
- Modify: `crates/sshrack-core/src/error.rs` (new `AskpassDenied` variant)
- Modify: `src/main.rs` (dispatch recognizes the deny env)
- Modify: `crates/sshrack-core/src/connect/mod.rs` (new `askpass_env_for_sftp`)
- Test: `askpass.rs` `#[cfg(test)]`; `connect/mod.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `askpass::ASKPASS_DENY_ENV`; `SshrackError::AskpassDenied`; `connect::askpass_env_for_sftp(self_exe, source, pw_file, config_path)`.
- Consumes: existing `askpass_env_for` (delegates to it), existing `run()` dispatch order.

- [ ] **Step 1: Add the `AskpassDenied` error variant**

In `crates/sshrack-core/src/error.rs`, add to `SshrackError` (near the other `Askpass*` variants):

```rust
    /// The SFTP master pointed the helper here with `SSHRACK_ASKPASS_DENY` set:
    /// the TUI owns the tty, so the helper refuses to prompt and ssh must fail
    /// the auth immediately. Carries no secret.
    #[error("askpass denied: SFTP session has no password configured")]
    AskpassDenied,
```

- [ ] **Step 2: Add the deny env + `run()` branch**

In `crates/sshrack-core/src/askpass.rs`, add the const near the other env consts (after `CONFIG_ENV`):

```rust
/// Env var set by the SFTP launcher when the master must NEVER fall back to
/// `/dev/tty`. The helper sees it, prints a fixed error, and exits non-zero so
/// ssh treats the auth as failed (no `/dev/tty` prompt, because the master also
/// sets `SSH_ASKPASS_REQUIRE=force`). Used for SFTP hosts whose resolved
/// password source is `None` — there is no payload to deliver, and the TUI
/// still owns the terminal the master would otherwise prompt on.
pub const ASKPASS_DENY_ENV: &str = "SSHRACK_ASKPASS_DENY";
```

At the very top of `pub fn run() -> Result<(), SshrackError>` (before the `HOST_ID_ENV` check), add:

```rust
    // SFTP deny: the TUI owns the tty; refuse to prompt. ssh reads this non-zero
    // exit as an auth failure — and because the master sets
    // SSH_ASKPASS_REQUIRE=force, ssh never falls back to /dev/tty. Nothing is
    // written to stdout (no secret, no empty password).
    if std::env::var_os(ASKPASS_DENY_ENV).is_some() {
        eprintln!("sshrack: no password configured for this SFTP session");
        return Err(SshrackError::AskpassDenied);
    }
```

- [ ] **Step 3: Make `main.rs` dispatch recognize the deny env**

In `src/main.rs`, extend the askpass-role guard (lines 15-18) to include the deny env:

```rust
    if std::env::var_os(askpass::HOST_ID_ENV).is_some()
        || std::env::var_os(askpass::ASKPASS_FILE_ENV).is_some()
        || std::env::var_os(sshrack_core::secret::keyring::KEYRING_KEY_ENV).is_some()
        || std::env::var_os(askpass::ASKPASS_DENY_ENV).is_some()
    {
```

- [ ] **Step 4: Write the failing test for `askpass_env_for_sftp`**

In `crates/sshrack-core/src/connect/mod.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn sftp_none_source_sets_force_triplet_and_deny() {
        // The SFTP master must never read /dev/tty. A None source still gets
        // the SSH_ASKPASS triplet (force) PLUS the deny marker, so the helper
        // fails clearly instead of ssh prompting on the TUI's tty.
        let env = askpass_env_for_sftp(
            Path::new("/sshrack"),
            &PasswordSource::None,
            None,
            None,
        );
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map.get("SSH_ASKPASS").copied(), Some("/sshrack"));
        assert_eq!(map.get("SSH_ASKPASS_REQUIRE").copied(), Some("force"));
        assert_eq!(map.get(crate::askpass::ASKPASS_DENY_ENV).copied(), Some("1"));
    }

    #[test]
    fn sftp_inline_source_keeps_payload_and_no_deny() {
        // A source WITH a payload keeps the file env and never sets deny.
        let env = askpass_env_for_sftp(
            Path::new("/sshrack"),
            &PasswordSource::Inline(Zeroizing::new("x".into())),
            Some(Path::new("/tmp/x.pw")),
            None,
        );
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map.get(ASKPASS_FILE_ENV).copied(), Some("/tmp/x.pw"));
        assert!(
            !map.contains_key(crate::askpass::ASKPASS_DENY_ENV),
            "Inline must not set deny"
        );
    }

    #[test]
    fn sftp_keyring_source_no_deny() {
        // Keyring has a payload; deny stays unset.
        let env = askpass_env_for_sftp(
            Path::new("/sshrack"),
            &PasswordSource::Keyring { key: "host:01J".into() },
            None,
            None,
        );
        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert!(!map.contains_key(crate::askpass::ASKPASS_DENY_ENV));
    }
```

- [ ] **Step 5: Implement `askpass_env_for_sftp` (GREEN)**

In `crates/sshrack-core/src/connect/mod.rs`, add the import `ASKPASS_DENY_ENV` to the existing `use crate::askpass::{…}` line, then add the function just after `askpass_env_for`:

```rust
/// Like [`askpass_env_for`] but for the SFTP master, which runs under the TUI
/// and must NEVER read `/dev/tty`. Every source gets the `SSH_ASKPASS` triplet
/// (`SSH_ASKPASS_REQUIRE=force`); [`PasswordSource::None`] additionally sets
/// [`ASKPASS_DENY_ENV`] so the helper fails clearly instead of letting ssh
/// prompt on the terminal the TUI still owns. This is the structural guarantee
/// that a master needing auth interaction cannot corrupt the TUI.
pub fn askpass_env_for_sftp(
    self_exe: &Path,
    source: &PasswordSource,
    pw_file: Option<&Path>,
    config_path: Option<&Path>,
) -> Vec<(&'static str, String)> {
    let mut env = askpass_env_for(self_exe, source, pw_file, config_path);
    if matches!(source, PasswordSource::None) {
        // No payload to deliver. askpass_env_for returned empty for None, so add
        // the triplet ourselves: SSH_ASKPASS_REQUIRE=force makes ssh call the
        // helper (never /dev/tty), and the deny marker makes the helper fail.
        if env.is_empty() {
            env.push(("SSH_ASKPASS", self_exe.to_string_lossy().into_owned()));
            env.push(("SSH_ASKPASS_REQUIRE", "force".to_string()));
            env.push(("DISPLAY", ":0".to_string()));
        }
        env.push((ASKPASS_DENY_ENV, "1".to_string()));
    }
    env
}
```

- [ ] **Step 6: Confirm deny coverage (no extra unit test needed)**

The deny behavior is covered by composition: `askpass_env_for_sftp` (Step 5)
asserts the `None` source sets `ASKPASS_DENY_ENV`; Task 3 wires the SFTP master
to `askpass_env_for_sftp`; the Verification smoke test exercises the real forked
helper end-to-end (no password configured → Alert). `run()`'s deny branch is a
2-line env check + fixed `eprintln` + `Err(AskpassDenied)` — a non-hermetic
env-reading unit test would add coupling without signal, so skip it.

- [ ] **Step 7: Run the gate**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
script -qec "cargo test --workspace" /dev/null
```

- [ ] **Step 8: Commit**

```bash
git add crates/sshrack-core/src/askpass.rs crates/sshrack-core/src/error.rs crates/sshrack-core/src/connect/mod.rs src/main.rs
git commit -m "feat(core): add SSHRACK_ASKPASS_DENY so SFTP master never reads /dev/tty"
```

---

## Task 3: capture master stderr + detect real failure in `wait_for_master`

**Files:**
- Modify: `crates/sshrack-core/src/connect/sftp/worker.rs` (`open`, `wait_for_master`, new `HandshakeOutcome` + `classify_poll`)
- Test: `worker.rs` `#[cfg(test)]` (pure `classify_poll`)

**Interfaces:**
- Consumes: Task 2's `askpass_env_for_sftp` (replaces the `askpass_env_for` call at `worker.rs:120`).
- Produces: `wait_for_master` returns `HandshakeOutcome` (was `bool`); `open`'s error string carries the captured stderr.

- [ ] **Step 1: Write the failing test for the pure decision**

In `worker.rs` `#[cfg(test)] mod tests`, add:

```rust
    // ---- classify_poll: pure handshake decision ----

    #[test]
    fn classify_poll_ready_wins() {
        // A successful ssh -O check means the master is up — ready, even if the
        // master also happened to exit (race) or the deadline passed.
        let out = classify_poll(true, false, true, String::new());
        assert!(matches!(out, Some(HandshakeOutcome::Ready)));
    }

    #[test]
    fn classify_poll_master_exit_beats_timeout() {
        // Master exited (auth failure) before the deadline: report Exited with
        // the captured stderr, not Timeout.
        let out = classify_poll(false, true, true, "Permission denied".into());
        assert!(matches!(
            out,
            Some(HandshakeOutcome::Exited(s)) if s == "Permission denied"
        ));
    }

    #[test]
    fn classify_poll_timeout_when_only_deadline() {
        let out = classify_poll(false, false, true, String::new());
        assert!(matches!(out, Some(HandshakeOutcome::Timeout)));
    }

    #[test]
    fn classify_poll_none_keeps_polling() {
        // No signal yet: return None so the caller polls again.
        let out = classify_poll(false, false, false, String::new());
        assert!(out.is_none());
    }
```

- [ ] **Step 2: Add `HandshakeOutcome` + `classify_poll` (GREEN for the test)**

Near the other free functions in `worker.rs` (before `wait_for_master`):

```rust
/// Outcome of polling the master handshake. [`wait_for_master`] returns this;
/// [`SftpWorker::open`] maps `Exited`/`Timeout` to a `Err` carrying the reason.
enum HandshakeOutcome {
    /// `ssh -O check` succeeded — the master is up.
    Ready,
    /// The master exited before coming up (auth failure, refused key, etc.).
    /// Carries the drained stderr so the user sees the real reason.
    Exited(String),
    /// The master neither came up nor exited before the deadline.
    Timeout,
}

/// Pure decision over one handshake poll's signals, factored out so the logic
/// (check wins; master-exit beats timeout; else keep polling) is unit-testable
/// without a real sshd. `stderr` is attached only to [`HandshakeOutcome::Exited`].
fn classify_poll(
    check_ok: bool,
    master_exited: bool,
    timed_out: bool,
    stderr: String,
) -> Option<HandshakeOutcome> {
    if check_ok {
        return Some(HandshakeOutcome::Ready);
    }
    if master_exited {
        return Some(HandshakeOutcome::Exited(stderr));
    }
    if timed_out {
        return Some(HandshakeOutcome::Timeout);
    }
    None
}
```

- [ ] **Step 3: Rewrite `wait_for_master` to take the master child + stderr**

Replace the existing `wait_for_master` (lines 541-560):

```rust
fn wait_for_master(
    target: &str,
    sock: &Path,
    deadline: Instant,
    master: &mut Child,
    stderr_buf: &Arc<Mutex<Vec<u8>>>,
) -> HandshakeOutcome {
    loop {
        let argv = control_check_argv(target, sock);
        let check_ok = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // A master that exited (auth refused, wrong password, bad key) must not
        // be masked by a 30s wait: detect it each poll and fail at once.
        let master_exited = master.try_wait().ok().flatten().is_some();
        let timed_out = Instant::now() >= deadline;
        let stderr = String::from_utf8_lossy(
            &stderr_buf.lock().expect("invariant: stderr lock").clone(),
        )
        .into_owned();
        if let Some(outcome) = classify_poll(check_ok, master_exited, timed_out, stderr) {
            return outcome;
        }
        thread::sleep(HANDSHAKE_POLL);
    }
}
```

- [ ] **Step 4: Capture master stderr + drain thread + wire the new env in `open`**

In `SftpWorker::open`, make four changes.

(a) Switch the env builder to the SFTP variant (replaces `askpass_env_for`):

```rust
        let env = askpass_env_for_sftp(self_exe, &source, pw_file.as_deref(), config_path);
```

and update the import at the top of the file:

```rust
use crate::connect::{askpass_env_for_sftp, write_password_file};
```

(b) Add a stderr buffer before the master spawn, and pipe stderr:

```rust
        // Captured master stderr: drained on a side thread so (a) the pipe
        // never fills and blocks the handshake, and (b) an auth failure's real
        // reason is captured instead of being written to the TUI's tty.
        let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
```

(c) On the `master_cmd` builder, change `.stdout(Stdio::null())` to also set stderr piped:

```rust
        master_cmd
            .args(&master_argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
```

(d) After `master_child.spawn()` and BEFORE the `wait_for_master` call, take + drain stderr, then call the new `wait_for_master` and map the outcome. Replace the existing `if !wait_for_master(...) { … }` block (lines 138-151) with:

```rust
        // Drain master stderr into the buffer (see run_transfer for the shape).
        {
            let buf = Arc::clone(&stderr_buf);
            if let Some(stderr) = master_child.stderr.take() {
                let _ = thread::spawn(move || {
                    use std::io::Read;
                    let _ = stderr.read_to_end(&mut buf.lock().expect("invariant: stderr lock"));
                });
            }
        }

        // (4) Poll `ssh -O check` until ready, the master exits, or the deadline.
        match wait_for_master(
            &target,
            &sock_path,
            Instant::now() + HANDSHAKE_TIMEOUT,
            &mut master_child,
            &stderr_buf,
        ) {
            HandshakeOutcome::Ready => {}
            outcome => {
                // Teardown on handshake failure: kill + reap the master, ask it
                // to exit politely, drop the socket, remove the pw file.
                let _ = master_child.kill();
                let _ = master_child.wait();
                let exit_argv = control_exit_argv(&target, &sock_path);
                let _ = Command::new(&exit_argv[0])
                    .args(&exit_argv[1..])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                drop(sock);
                if let Some(p) = pw_file {
                    let _ = std::fs::remove_file(p);
                }
                let reason = match outcome {
                    HandshakeOutcome::Exited(s) if !s.trim().is_empty() => {
                        format!("sftp master failed: {s}")
                    }
                    HandshakeOutcome::Exited(_) => {
                        "sftp master failed (authentication rejected)".to_string()
                    }
                    HandshakeOutcome::Timeout => "sftp master handshake timed out".to_string(),
                    HandshakeOutcome::Ready => unreachable!("handled above"),
                };
                return Err(reason);
            }
        }
```

- [ ] **Step 5: Run the gate**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
script -qec "cargo test --workspace" /dev/null
```

Expected: the `classify_poll` unit tests pass; the existing `handshake_timeout_is_30_seconds` still passes; the sftp e2e `#[ignore]` test is unchanged.

- [ ] **Step 6: Commit**

```bash
git add crates/sshrack-core/src/connect/sftp/worker.rs
git commit -m "fix(sftp): capture master stderr and fail fast when it exits"
```

---

## Task 4: route `open_transfer` failures through the Alert + fail-fast

**Files:**
- Modify: `src/tui/transfer/open.rs` (fail-fast before spawn)
- Modify: `src/tui/run_loop.rs` (`OpenTransfer` arm: `Err(e)` → `Overlay::Alert`)
- Test: `open.rs` `#[cfg(test)]` (pure fail-fast predicate)

**Interfaces:**
- Consumes: Task 1's `Overlay::Alert`; Tasks 2+3's improved `SftpOpenFailed { detail }` (now carries captured stderr).
- Produces: `open::host_unconfigured(resolved) -> bool` (pure fail-fast predicate).

- [ ] **Step 1: Write the failing test for the pure fail-fast predicate**

In `src/tui/transfer/open.rs` `#[cfg(test)] mod tests`, add:

```rust
    #[test]
    fn host_unconfigured_true_for_no_password_no_key() {
        // A user-only host (no password, no key) cannot authenticate without TTY
        // interaction — the SFTP master must reject it up front.
        use sshrack_core::credential::{PasswordSource, ResolvedAuth};
        let r = ResolvedAuth {
            user: "u".into(),
            key_path: None,
            password: PasswordSource::None,
            inline_key: None,
        };
        assert!(host_unconfigured(&r));
    }

    #[test]
    fn host_unconfigured_false_when_key_present() {
        // A key-only host (encrypted or not) is NOT unconfigured: it may still
        // auth via the key. If the key is encrypted and no passphrase source
        // exists, the deny path (Task 2) handles it — not this predicate.
        use sshrack_core::credential::{PasswordSource, ResolvedAuth};
        let r = ResolvedAuth {
            user: "u".into(),
            key_path: Some("/k/id".into()),
            password: PasswordSource::None,
            inline_key: None,
        };
        assert!(!host_unconfigured(&r));
    }

    #[test]
    fn host_unconfigured_false_when_password_present() {
        use sshrack_core::credential::{PasswordSource, ResolvedAuth};
        use zeroize::Zeroizing;
        let r = ResolvedAuth {
            user: "u".into(),
            key_path: None,
            password: PasswordSource::Inline(Zeroizing::new("p".into())),
            inline_key: None,
        };
        assert!(!host_unconfigured(&r));
    }
```

- [ ] **Step 2: Implement the predicate (GREEN)**

In `src/tui/transfer/open.rs`, add:

```rust
/// True when the resolved identity has neither a password nor an identity key:
/// such a host cannot authenticate without TTY interaction, and the SFTP master
/// must never read `/dev/tty`, so `open_transfer` rejects it before spawn with a
/// precise message. A key-only host returns `false` (it may still auth via the
/// key; an encrypted key with no passphrase source is caught by the deny path).
fn host_unconfigured(resolved: &sshrack_core::credential::ResolvedAuth) -> bool {
    use sshrack_core::credential::PasswordSource;
    matches!(resolved.password, PasswordSource::None) && resolved.key_path.is_none()
}
```

- [ ] **Step 3: Add the fail-fast check in `open_transfer`**

In `open_transfer`, after Step 4 (`let key_artifact = connect::materialize_inline_key(&mut resolved_auth)?;`) and before Step 5 (host-key pre-flight), add:

```rust
    // ── Fail-fast: a host with no password AND no key cannot authenticate
    // without TTY interaction. The SFTP master must never read /dev/tty, so
    // reject now with a precise message instead of spawning a master that
    // fails via the deny path with a vaguer error. ─────────────────────────────
    if host_unconfigured(&resolved_auth) {
        return Err(SshrackError::SftpOpenFailed {
            detail: format!(
                "host '{}' has no password and no identity key configured",
                resolved_host.name
            ),
        });
    }
```

(`materialize_inline_key` already moved an inline key into `key_path`, so checking `key_path.is_none()` covers both path-key and inline-key hosts.)

- [ ] **Step 4: Route `OpenTransfer` failures to the Alert overlay**

In `src/tui/run_loop.rs`, the `Outcome::OpenTransfer` arm (lines 370-392) currently does `app.set_status_error(format!("sftp open failed: {e}"))` on the catch-all `Err(e)`. Replace ONLY that catch-all arm (leave the `Interrupted` arm untouched) with:

```rust
                        Err(e) => {
                            // Surface every open failure (vault locked, dangling
                            // credential, no-password-no-key, master auth
                            // failure, handshake timeout) as a modal Alert. The
                            // body carries the real reason — captured stderr for
                            // master failures (Task 3), a precise message for
                            // the fail-fast cases. Esc/^C closes → launcher.
                            app.overlay = Some(Overlay::Alert {
                                title: " SFTP connection failed ".into(),
                                body: e.to_string(),
                            });
                        }
```

(`Overlay` is already imported at `run_loop.rs:31`.)

- [ ] **Step 5: Run the gate**

```bash
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
script -qec "cargo test --workspace" /dev/null
```

- [ ] **Step 6: Commit**

```bash
git add src/tui/transfer/open.rs src/tui/run_loop.rs
git commit -m "feat(tui): route sftp open failures through the Alert overlay"
```

---

## Verification (after all 4 tasks)

- `cargo fmt` + `cargo clippy --workspace --all-targets -- -D warnings` green.
- `script -qec "cargo test --workspace" /dev/null` green.
- **Manual smoke (the original bug):** configure a host that needs a password but has none set; launch `sshrack`; select the host; `Ctrl-T`. Expected: a centered "SFTP connection failed" Alert with *"host 'X' has no password and no identity key configured"*; the TUI behind it is intact (no overlapping prompt, no garbled input); `Esc` closes the Alert and returns to the launcher. No `/tmp/sshrack-askpass-*` leak from this path; the master left no lingering `ssh -N`.
- **Wrong-password smoke:** configure a host with a wrong password; `Ctrl-T`. Expected: a second-scale Alert whose body includes ssh's captured *"Permission denied"* line (no 30s hang, no stderr pollution of the TUI).

## Out of scope (documented follow-ups)

- Regular connect (`Enter`) fail-fast — it drops the guard and ssh legitimately reads `/dev/tty`; no corruption. Untouched.
- In-TUI password entry ("补输入").
- Vault-mode temp-file elimination (separate plan).
- An `SSH_ASKPASS_REQUIRE=force` compatibility fallback for OpenSSH < 8.4 (sshrack targets modern Linux/macOS where `force` is universal); if an older ssh is ever supported, add a runtime probe then.
