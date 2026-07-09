# Transfer Status Auto-Clear Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the transfer screen's footer status line auto-clear on the next keypress, so a stale list/transfer error stops lingering while the user searches, moves the cursor, or navigates.

**Architecture:** The launcher already clears its status on every panel keypress (`App::route_panel` sets `self.status = Status::empty()` at the top of Layer 3 — "the status is a transient per-action hint, not a persistent banner"). The transfer screen bypasses Layer 3 (its keys route through Layer 0, `App::route_transfer`, which returns before `route_panel` runs), so it never gets that clear. The fix is to mirror the same one-line clear at the top of `route_transfer`, Press-gated, before `screen.on_key(key)`. A new status produced during the same keypress's drain (a list error, queue feedback) is written AFTER this clear, so it still surfaces.

**Tech Stack:** Rust 2024 (MSRV 1.88), ratatui 0.30 / crossterm, sshrack-core. Tests use the existing `app_with_host` + `TransferScreen::new` + `drain_transfer_events` harness in `src/tui/run_loop.rs`.

## Global Constraints

- **English only** — all source, comments, doc comments, errors, and commit messages.
- **Zero `unsafe`**; **zero `unwrap()`/`expect()` in production** (test-only is fine; the harness's `.expect("temp dir")` etc. are inside `#[test]`).
- **Clippy strict**: `cargo clippy --workspace --all-targets -- -D warnings` green before commit.
- **Format**: `cargo fmt` green before commit.
- **TDD**: write the failing test first, watch it RED, implement, watch it GREEN.
- **Hermetic tests**: no env mutation. CI runs tests under a pty (`script -qec "cargo test --workspace" /dev/null`); the harness's `stdout_tui()` needs it, so reproduce locally under a pty if a tty-backed test misbehaves.
- **Test layer**: this is a state bug — use the `on_key` chain + state-assert layer (drive `app.on_key(...)`, then assert `app.transfer.as_ref().unwrap().status`), the lightest layer that reaches it.
- **Conventional Commits**: `fix(<scope>): <description>`, **no `Co-Authored-By` trailer**. Scope here is `tui` (or `sftp` to match the recent transfer-screen fix commits — pick `tui`).
- **Do not touch `drain_transfer_events`** — the clear lives at the keypress entry only; the drain layer must keep writing statuses (list errors, queue feedback) so they survive between keypresses.

---

## Task 1: Auto-clear transfer status on each keypress

**Files:**
- Modify: `src/tui/app.rs` — `App::route_transfer` (starts at line 786). Add the clear as the FIRST thing in the function body, before `let out = screen.on_key(key);`.
- Test: `src/tui/run_loop.rs` — add two tests in the existing `tests` module, next to `drain_local_list_failure_reverts_cwd_and_keeps_entries` (line ~1020).

**Interfaces:**
- Consumes:
  - `TransferScreen::set_status(&mut self, Status)` — pure setter (defined in `src/tui/transfer/screen.rs:150`).
  - `Status::empty()` — `{ message: None, is_error: false }` (defined in `src/tui/intent.rs:212`). `Status` is already imported in `app.rs` (line 24: `use super::intent::{Outcome, Overlay, Status};`).
  - `crossterm::event::KeyEventKind::Press` — `key.kind` is a `KeyEventKind` on every `KeyEvent`.
- Produces: nothing (internal behavior change; no new public item).

**Current code at the edit site** (`src/tui/app.rs:786-788`):

```rust
    fn route_transfer(&mut self, key: KeyEvent, mut screen: TransferScreen) -> Outcome {
        let out = screen.on_key(key);
        match out {
```

- [ ] **Step 1: Write the failing test (the driver)**

Add this test to the `tests` module in `src/tui/run_loop.rs`, right after `drain_local_list_failure_reverts_cwd_and_keeps_entries` (after its closing brace at line ~1071). It reuses the exact harness pattern of that test.

```rust
    // ===============================================================
    // The transfer screen's status line must auto-clear on the next
    // keypress, mirroring the launcher's panel layer (route_panel clears
    // self.status before every panel key). The transfer screen routes
    // through Layer 0 (route_transfer), which never reaches route_panel,
    // so without an explicit clear a list/transfer error lingers on the
    // footer while the user searches, moves the cursor, or navigates.
    // ===============================================================
    #[test]
    fn transfer_status_auto_clears_on_next_keypress() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        use std::fs;
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("alpha.txt"), b"").expect("write file");
        let origin = dir.path().to_path_buf();

        let mut app = app_with_host("web");
        let screen = TransferScreen::new(origin.clone(), PathBuf::from("/remote"));
        app.transfer = Some(screen);
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Seed the local pane, then navigate to a nonexistent path so the
        // local list fails and surfaces an error status (the user's scenario).
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, origin.clone()));
        drain_transfer_events(&mut app, &handle);
        let bad = PathBuf::from("/nonexistent/sshrack-auto-clear-7781");
        assert!(!bad.exists(), "fixture: the bad path must not exist");
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, bad));
        drain_transfer_events(&mut app, &handle);
        assert!(
            app.transfer.as_ref().unwrap().status.is_error,
            "fixture: the failed list must seed an error status first"
        );

        // Any subsequent keypress (cursor-down on the local pane here) must
        // clear the stale error — status is a per-action hint, not a banner.
        let down = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Press);
        app.on_key(down);

        let status = &app.transfer.as_ref().unwrap().status;
        assert!(
            !status.is_error && status.message.is_none(),
            "stale error status must clear on the next keypress, got: {:?}",
            status.message
        );
    }
```

- [ ] **Step 2: Run the test to verify it FAILS (RED)**

Run: `cargo test --workspace transfer_status_auto_clears_on_next_keypress`
Expected: FAIL. The assertion `!status.is_error && status.message.is_none()` fails because `status` is still the seeded error (`local list failed: ...`) — there is no clear yet. This confirms the test actually catches the bug (not a false green).

- [ ] **Step 3: Write the guard test (Press-only semantics)**

Add this test right after the one above. It locks in that the clear is **Press-gated** (a `Release` event must NOT clear) — so a future edit that drops the `Press` condition is caught. Note: this test passes trivially before the implementation exists (no clear code → Release changes nothing); it exists to guard the implementation shape, not to drive RED.

```rust
    // The clear is Press-gated, matching the launcher's Press-only key
    // handling. A Release event must leave the status untouched.
    #[test]
    fn transfer_status_clear_is_press_only_not_release() {
        use super::intent::Status;
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        screen.set_status(Status::error("seeded error"));
        app.transfer = Some(screen);

        let release = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        app.on_key(release);

        let status = &app.transfer.as_ref().unwrap().status;
        assert!(
            status.is_error && status.message.as_deref() == Some("seeded error"),
            "Release must not clear the status, got: {:?}",
            status.message
        );
    }
```

- [ ] **Step 4: Implement the Press-gated clear**

Edit `src/tui/app.rs` `route_transfer` (line 786). Insert the clear as the first statements, before `let out = screen.on_key(key);`. `Status` is already imported at the top of the file.

```rust
    fn route_transfer(&mut self, key: KeyEvent, mut screen: TransferScreen) -> Outcome {
        // Auto-clear stale status on each transfer keypress, mirroring the
        // launcher's panel layer (`route_panel` clears `self.status` before
        // every panel key): a status line is a transient per-action hint, not
        // a persistent banner. The transfer screen routes through Layer 0 and
        // never reaches `route_panel`, so without this a list/transfer error
        // lingers on the footer until some later action overwrites it. A new
        // status set during THIS keypress's drain (a list error, queue
        // feedback) is written AFTER this clear, so it still surfaces.
        if key.kind == crossterm::event::KeyEventKind::Press {
            screen.set_status(Status::empty());
        }
        let out = screen.on_key(key);
        match out {
```

Leave the rest of the match arms unchanged.

- [ ] **Step 5: Run both new tests to verify they PASS (GREEN)**

Run: `cargo test --workspace transfer_status_auto_clear transfer_status_clear_is_press_only`
Expected: PASS (2 passed).

Then run the neighboring regression to confirm the clear did NOT break the "same-keypress error still surfaces" path (the clear runs before `on_key`, the error is set later in the drain, so it survives):

Run: `cargo test --workspace drain_local_list_failure_reverts enqueue_dst_uses_reverted`
Expected: PASS.

- [ ] **Step 6: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: no warnings.

Run: `cargo fmt`
Expected: no diff (or apply it).

- [ ] **Step 7: Full workspace test**

Run under a pty (the `stdout_tui()`-backed tests need it): `script -qec "cargo test --workspace" /dev/null`
Expected: all pass (the sftp e2e test that needs a live sshd is the one pre-existing ignore — unchanged).

- [ ] **Step 8: Commit**

```bash
git add src/tui/app.rs src/tui/run_loop.rs
git commit -m "fix(tui): auto-clear transfer status on each keypress

The transfer screen routes keys through Layer 0 (route_transfer), which
returns before the launcher's Layer 3 (route_panel) — and the per-keypress
status clear that lives at the top of route_panel never runs for transfer
keys. A list/transfer error written to the footer status therefore lingered
until some later action happened to overwrite it, so the user kept seeing a
stale 'local list failed: ...' while searching, moving the cursor, or
navigating.

Mirror route_panel's clear at the top of route_transfer, Press-gated, before
screen.on_key. A status produced during the same keypress's drain (list
error, queue feedback) is written after the clear, so it still surfaces; the
drain layer is untouched."
```

---

## Notes for the implementer

- The edit is intentionally tiny (one `if` + setter + comment). Do NOT also add a clear inside `drain_transfer_events` — that would wipe the async remote `Listing Err` / queue feedback the instant it is written.
- Do NOT special-case `queue_overlay`: the user-chosen semantics is "any keypress clears", and queue-overlay feedback (e.g. the batch-cancel notice) is itself a transient per-action hint that the next keypress should clear too. A uniform clear at the entry is simpler and matches the choice.
- The launcher's Layer 3 clear is at `src/tui/app.rs:700` (`self.status = Status::empty();`); the comment there is the canonical phrasing — this plan's comment mirrors it.
- The persistent "transfer failed" signal is NOT the status line — it is `ledger.failed_count()`, rendered as the red `fail N` counter in `summary_line` (`src/tui/transfer/render.rs:369`). Clearing the status does not hide transfer failures; it only retires the transient per-action message.
