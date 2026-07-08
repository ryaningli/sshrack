# Unified Error Feedback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse every action-failure surface in the TUI onto a single self-describing status-bar line, and delete the modal `Alert` overlay (it carried no interaction value — every trigger was a read-only "dismiss me"), so failure feedback is uniform across connect / SFTP-open / delete.

**Architecture:** A new `App::report_failure(e)` writes the error's own `Display` verbatim as a red `Status::error` one-liner — no per-action `"<action> failed:"` prefix (those duplicated the error's wording and even produced a double prefix at the `sshrack sftp` first-tick entry). All six existing status-bar failure sites plus the one `Alert` site route through it. `SftpOpenFailed` details are flattened to one line (captured master stderr → first meaningful line) so the single-row footer never overflows. The `Overlay::Alert` variant, `alert.rs`, its route/draw branches, and its registration are removed in one atomic commit (clippy `dead_code` forces atomicity).

**Tech Stack:** Rust 2024, MSRV 1.88. `sshrack-core` (thiserror) + binary TUI (ratatui 0.30 + crossterm). Pure-logic TDD in `#[cfg(test)]`; TestBackend for render; hermetic by default.

## Global Constraints

**Design principle (the point of this refactor).**
- **A modal Alert is justified only when it collects a user response that drives a follow-up action** (re-entry, retry, re-input). A read-only "dismiss me" alert has no interaction value — it is a blocking status bar. Today *no* failure site offers an inline response, so the Alert is removed entirely. When a future feature adds a real interaction (e.g. re-input password → re-spawn master), a *new* interactive overlay is introduced then — not this one.
- **No-interaction failures unify on the status bar** (`Status::error`, the red one-row footer).
- **Failure wording has one source: the error's `Display`.** `report_failure(app, e)` writes `e.to_string()` with **no** `"<action> failed: "` prefix. Every `SshrackError` variant already renders a full self-describing sentence via thiserror; a second prefix duplicates it (and `SftpOpenFailed` already begins `"sftp open failed: …"`, so the old `format!("sftp open failed: {e}")` at the first-tick entry printed the prefix twice).
- **The status bar is one row:** every failure detail must be single-line. Multi-line captured stderr is collapsed to its first non-empty trimmed line.

**Project hard rules (from CLAUDE.md).**
- English only — all source, comments, doc comments, errors, help text, log output, commit messages.
- Zero `unsafe`. Zero `unwrap()`/`expect()` in production (only `#[cfg(test)]` or `expect("invariant: …")` on genuinely unreachable states).
- Clippy strict: `cargo clippy --workspace --all-targets -- -D warnings` green before every commit. `cargo fmt` green before every commit.
- TDD for pure logic (RED → GREEN → REFACTOR). Write enough tests; no hard coverage gate.
- Library errors use `thiserror`; application errors use `anyhow` with `.context()`. Propagate via `?`.
- `sshrack-core` is zero-UI (never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`).
- Hermetic tests: `cargo test --workspace` passes with no env vars; tests never mutate the real environment. Insta: commit the `.snap`, never the `.snap.new`.
- Dev-stage rule: no compatibility/scaffold residue. Removing `Alert` means removing it **cleanly** — no `#[allow(dead_code)]` bridge.
- Conventional Commits: `<type>(<scope>): <description>`. **No `Co-Authored-By` trailer.** Explicit `git add <paths>`; never `git add -A`.
- CI runs tests under a pty: `script -qec "cargo test --workspace" /dev/null`.

---

## File Structure

- **`crates/sshrack-core/src/connect/sftp/worker.rs`** (Task 1) — new private pure fn `first_meaningful_line(&str) -> &str`; two stderr→detail sites collapse through it (the master-handshake failure `reason`, and the transfer-run failure `first_line`). DRY: the inline logic at `worker.rs:473-477` is replaced by the helper.
- **`src/tui/app.rs`** (Task 2 + Task 3) — new `App::report_failure(&SshrackError)` method; removal of the `draw_alert` import, the `Overlay::Alert` route branch (`route_overlay`), and the `Overlay::Alert` draw branch (`draw_overlay`).
- **`src/tui/run_loop.rs`** (Task 2 + Task 3) — the six status-bar failure sites (first-tick `:114`, connect `:177`, delete-host `:315`/`:329`, delete-cred `:352`/`:366`) and the one Alert site (OpenTransfer arm `:388-399`) all call `app.report_failure(&e)`.
- **`src/tui/intent.rs`** (Task 3) — remove the `Overlay::Alert { title, body }` variant + its doc comment.
- **`src/tui/alert.rs`** (Task 3) — **delete the entire file** (`draw_alert` + its 3 render tests).
- **`src/tui/mod.rs`** (Task 3) — remove `pub mod alert;`.
- **`src/tui/transfer/open.rs`** (Task 3) — update the module doc (Alert mention → status bar).
- **`docs/tui.md`** (Task 3) — update any error-presentation / Alert mention to "failures show in the status bar".

---

## Task 1: Collapse multi-line master stderr to one status line

**Files:**
- Modify: `crates/sshrack-core/src/connect/sftp/worker.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: private pure fn `fn first_meaningful_line(s: &str) -> &str` — returns the first line of `s` whose `trim()` is non-empty, or `""` if none. Used by two sites in this same file (no cross-file consumer).

**Why:** `wait_for_master` builds the failure detail as `format!("sftp master failed: {s}")` where `s` is the **entire** captured master stderr (`HandshakeOutcome::Exited(String)` at `worker.rs:204-213`) — potentially many lines. After Task 3 routes SFTP-open failures to the one-row status bar, that multi-line detail must collapse to one line. `run_transfer` already has the same logic inline (`worker.rs:473-477`); extracting a shared helper removes the duplication.

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)]` module in `worker.rs`:

```rust
    #[test]
    fn first_meaningful_line_returns_first_non_empty_trimmed_line() {
        // Leading blank/whitespace lines are skipped; the first content line is
        // returned trimmed.
        assert_eq!(
            first_meaningful_line("  \n\nPermission denied (password).\nsecond line"),
            "Permission denied (password)."
        );
    }

    #[test]
    fn first_meaningful_line_empty_when_all_lines_blank() {
        assert_eq!(first_meaningful_line("  \n\n\t "), "");
    }

    #[test]
    fn first_meaningful_line_empty_for_empty_input() {
        assert_eq!(first_meaningful_line(""), "");
    }

    #[test]
    fn first_meaningful_line_single_line_is_trimmed() {
        assert_eq!(first_meaningful_line("  host unreachable  "), "host unreachable");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sshrack-core first_meaningful_line`
Expected: FAIL — `cannot find function first_meaningful_line`.

- [ ] **Step 3: Add the pure helper**

Add this private fn near `classify_poll` / `wait_for_master` (it is peer pure logic for the failure path):

```rust
/// The first line of `s` whose trimmed form is non-empty, or `""` if there is
/// none. Collapses a multi-line captured stderr into a single status-bar line
/// (the footer is one row). Pure.
fn first_meaningful_line(s: &str) -> &str {
    for line in s.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    ""
}
```

- [ ] **Step 4: Route the master-handshake failure through it**

In `SftpWorker::open`, replace the `reason` match (the block currently reading `HandshakeOutcome::Exited(s) if !s.trim().is_empty() => format!("sftp master failed: {s}")`, `HandshakeOutcome::Exited(_) => "sftp master failed (authentication rejected)"`, …) with:

```rust
                let reason = match outcome {
                    HandshakeOutcome::Exited(s) => match first_meaningful_line(&s) {
                        "" => "sftp master failed (authentication rejected)".to_string(),
                        line => format!("sftp master failed: {line}"),
                    },
                    HandshakeOutcome::Timeout => "sftp master handshake timed out".to_string(),
                    HandshakeOutcome::Ready => unreachable!("handled above"),
                };
```

- [ ] **Step 5: Route the transfer-run failure through it (DRY)**

In `run_transfer` (the `else` branch of `if status.success()`), replace the inline extraction:

```rust
                    let first_line = stderr_str
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("sftp failed")
                        .to_string();
```

with:

```rust
                    let first_line = match first_meaningful_line(&stderr_str) {
                        "" => "sftp failed".to_string(),
                        s => s.to_string(),
                    };
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p sshrack-core first_meaningful_line`
Expected: PASS (4/4).

Run: `cargo test -p sshrack-core`
Expected: PASS (no regressions in the sftp worker tests, incl. the `classify_poll` and drain-deadlock regression).

- [ ] **Step 7: Lint + format**

Run: `cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt`
Expected: green.

- [ ] **Step 8: Commit**

```bash
git add crates/sshrack-core/src/connect/sftp/worker.rs
git commit -m "refactor(sftp): collapse multi-line master stderr to one status line"
```

---

## Task 2: Route action failures through one status helper

**Files:**
- Modify: `src/tui/app.rs` (add `report_failure`)
- Modify: `src/tui/run_loop.rs` (six failure sites)

**Interfaces:**
- Consumes: `Status::error` (existing, `intent.rs`); `SshrackError` Display (existing).
- Produces: `pub fn App::report_failure(&mut self, e: &sshrack_core::error::SshrackError)` — sets `self.status = Status::error(e.to_string())`. Consumed by Task 3's Alert site as well.

**Why:** Six failure sites each hand-wrote `app.set_status_error(format!("<action> failed: {e}"))`, producing four different prefixes and a double prefix at the first-tick entry (`"sftp open failed: " + SftpOpenFailed.to_string()` which itself begins `"sftp open failed: …"`). One helper, fed the error's own `Display`, makes wording single-source and removes the duplication.

- [ ] **Step 1: Write the failing test**

In `src/tui/app.rs`'s `#[cfg(test)]` module (mirror the existing `set_status_and_set_status_error_round_trip` test at `app.rs:2126` — reuse whatever `App` constructor that test uses):

```rust
    #[test]
    fn report_failure_shows_error_display_with_no_prefix() {
        // report_failure writes the error's own Display as a red status, with
        // NO "<action> failed:" prefix — the wording comes from the error type
        // alone (single source of truth). HostKeyScanFailed already renders a
        // full sentence, so the status is exactly that sentence.
        let mut app = App::default(); // <-- match the constructor used at app.rs:2126
        let e = SshrackError::HostKeyScanFailed {
            host: "x.example".into(),
        };
        app.report_failure(&e);
        let status = app.status();
        assert!(status.is_error);
        assert_eq!(
            status.message.as_deref(),
            Some("ssh-keyscan failed for 'x.example' (is the host reachable on that port?)"),
        );
    }
```

> If `App::default()` is not the constructor used at `app.rs:2126`, copy the exact constructor call from that test instead. If `SshrackError` is not yet imported in the test module, add `use sshrack_core::error::SshrackError;`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin sshrack report_failure_shows_error_display_with_no_prefix`
Expected: FAIL — `no method named report_failure found`.

- [ ] **Step 3: Add `App::report_failure`**

In `src/tui/app.rs`, immediately after `set_status_error` (around `app.rs:498`), add:

```rust
    /// Report an action failure via the status bar: the error's own `Display`
    /// (self-describing — every `SshrackError` variant renders a full sentence)
    /// is shown verbatim as a red one-liner. No `"<action> failed: "` prefix is
    /// added: it would duplicate the error's own wording (e.g. `SftpOpenFailed`
    /// already renders `"sftp open failed: …"`) and the action the user just
    /// took supplies the context. This is the single call site for failure
    /// wording — connect, SFTP-open, and delete all route through it.
    pub fn report_failure(&mut self, e: &sshrack_core::error::SshrackError) {
        self.status = Status::error(e.to_string());
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin sshrack report_failure_shows_error_display_with_no_prefix`
Expected: PASS.

- [ ] **Step 5: Rewire the six status-bar failure sites in `run_loop.rs`**

Replace each of the six `app.set_status_error(format!("<action> failed: {e}"));` lines with `app.report_failure(&e);`. The six sites (verify line numbers; they drift):

1. First-tick SFTP entry — currently `app.set_status_error(format!("sftp open failed: {e}"));` (around `run_loop.rs:114`):
   ```rust
                       Err(e) => {
                           app.report_failure(&e);
                       }
   ```
2. Regular connect — currently `format!("connect failed: {e}")` (around `:177`):
   ```rust
                           Err(e) => {
                               // A real error (vault unlock fail, host-key reject,
                               // dangling credential, frecency save fail). Surface
                               // it as a red one-liner via the error's own wording
                               // and return to the launcher so the user can read it.
                               app.report_failure(&e);
                           }
   ```
3. Delete-host persist error — currently `format!("delete failed: {e}")` (around `:315`):
   ```rust
                               Err(e) => {
                                   app.report_failure(&e);
                               }
   ```
4. Delete-host confirm-popup error — currently `format!("delete failed: {e}")` (around `:329`): same replacement → `app.report_failure(&e);`
5. Delete-cred persist error — currently `format!("delete failed: {e}")` (around `:352`): same replacement → `app.report_failure(&e);`
6. Delete-cred confirm-popup error — currently `format!("delete failed: {e}")` (around `:366`): same replacement → `app.report_failure(&e);`

Leave the `Ok` arms, the `Interrupted` arms, and the `Ok(false)` arms untouched.

- [ ] **Step 6: Run the TUI test suite**

Run: `cargo test --bin sshrack`
Expected: PASS. (The first-tick double-prefix is now gone — `report_failure(&e)` emits exactly `e.to_string()`, which for `SftpOpenFailed` is `"sftp open failed: …"` once.)

- [ ] **Step 7: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: green.

- [ ] **Step 8: Commit**

```bash
git add src/tui/app.rs src/tui/run_loop.rs
git commit -m "refactor(tui): route action failures through a single status helper"
```

---

## Task 3: Remove the modal Alert; unify the SFTP-open failure to the status bar

**Files:**
- Modify: `src/tui/run_loop.rs` (OpenTransfer arm)
- Modify: `src/tui/app.rs` (drop import + route/draw branches)
- Modify: `src/tui/intent.rs` (drop `Overlay::Alert` variant)
- Modify: `src/tui/mod.rs` (drop `pub mod alert;`)
- Modify: `src/tui/transfer/open.rs` (module doc)
- Modify: `docs/tui.md` (error-presentation mention, if any)
- Delete: `src/tui/alert.rs`

**Interfaces:**
- Consumes: `App::report_failure` from Task 2.
- Produces: `Overlay` no longer has an `Alert` variant; `draw_alert` and `alert.rs` are gone. After this task there is **no** modal error surface in the TUI — every failure is a status-bar line.

**Why:** The `Alert` is the inconsistency the user reported: the `Ctrl-T` SFTP-open path popped a modal while every other failure (connect, delete, `sshrack sftp` first-tick) wrote a status line. Per the design principle, a modal is warranted only by an inline user response — the Alert offered only `Esc`/`Ctrl-C` (dismiss), so it was a blocking status bar. Removing it unifies all failures onto `report_failure`. This task is **atomic**: once the OpenTransfer arm stops constructing `Overlay::Alert`, the variant + `draw_alert` become `dead_code`, which clippy `-D warnings` rejects — so every removal lands in one commit.

- [ ] **Step 1: Rewire the OpenTransfer arm off the Alert**

In `src/tui/run_loop.rs`, the `Outcome::OpenTransfer` arm's error branch currently builds `app.overlay = Some(Overlay::Alert { title: " SFTP connection failed ".into(), body: e.to_string() });` (around `:388-399`). Replace the whole `Err(e) => { … }` body with:

```rust
                        Err(e) => {
                            // Surface every open failure (vault locked, dangling
                            // credential, no-password-no-key, master auth failure,
                            // handshake timeout) as a red status-bar line via the
                            // error's own wording. A modal Alert offered no
                            // interaction value here (only dismiss), so the status
                            // bar — uniform with connect/delete failures — is the
                            // right surface. Esc/^C in any popup still returns to
                            // the launcher via the Interrupted arm above.
                            app.report_failure(&e);
                        }
```

- [ ] **Step 2: Drop the `Overlay::Alert` variant**

In `src/tui/intent.rs`, remove the variant and its doc comment (the block currently reading):

```rust
    /// A modal error alert (e.g. a failed SFTP open). `body` is the multi-line
    /// message; `Esc` / `Ctrl-C` close it via the standard overlay close path
    /// (`Outcome::CloseOverlay`) — the shell renders behind it. Set by the
    /// `OpenTransfer` arm for every `open_transfer` failure.
    Alert { title: String, body: String },
```

- [ ] **Step 3: Drop the route + draw branches and the import in `app.rs`**

In `src/tui/app.rs`:
- Remove the import line `use super::alert::draw_alert;` (around `:21`).
- In `route_overlay`, remove the entire `Overlay::Alert { title, body } => { … }` branch (around `:768-780`). The surrounding `match self.overlay.clone()` remains exhaustive over the remaining variants.
- In `draw_overlay`, remove the entire `Overlay::Alert { title, body } => { draw_alert(frame, title, body); }` branch (around `:1176-1178`).

- [ ] **Step 4: Delete `alert.rs` and unregister it**

- Delete the file `src/tui/alert.rs`.
- In `src/tui/mod.rs`, remove the line `pub mod alert;` (around `:30`).

- [ ] **Step 5: Update the `open.rs` module doc**

In `src/tui/transfer/open.rs`, the "Cancel vs error" doc block currently ends (around lines 10-13):

```rust
//! A user cancel inside the vault or host-key popup (Esc / Ctrl-C) surfaces as
//! [`SshrackError::Interrupted`]; [`crate::tui::run_loop`] maps that to "return
//! to the launcher" — NOT an exit and NOT a status write. Any other error
//! (vault unlock failed, host key rejected, dangling credential,
//! no-password-no-key, worker spawn failed) is surfaced as a modal
//! [`Overlay::Alert`] and returns to the launcher once the user dismisses it.
```

Replace the last sentence so it reads:

```rust
//! A user cancel inside the vault or host-key popup (Esc / Ctrl-C) surfaces as
//! [`SshrackError::Interrupted`]; [`crate::tui::run_loop`] maps that to "return
//! to the launcher" — NOT an exit and NOT a status write. Any other error
//! (vault unlock failed, host key rejected, dangling credential,
//! no-password-no-key, worker spawn failed) is surfaced in the status bar via
//! [`App::report_failure`] and returns to the launcher.
```

- [ ] **Step 6: Update `docs/tui.md`**

Run: `grep -n -i "alert" docs/tui.md`
For each hit, rewrite the surrounding sentence so failure feedback is described as a red status-bar line (no modal Alert). If the doc has an "error display" / "Alert" subsection, replace its body with: *Action failures (connect, SFTP open, delete) are shown as a red one-line status message at the foot of the screen, using the error's own wording; there is no modal error dialog.*

If `grep` returns no hits, skip this step.

- [ ] **Step 7: Build + lint (atomicity check)**

Run: `cargo build --workspace`
Expected: succeeds — no remaining reference to `Overlay::Alert`, `draw_alert`, or `alert::`.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: green — confirms no `dead_code` bridge survived (the variant, the file, and every branch are gone together).

- [ ] **Step 8: Run the full test suite under a pty**

Run: `script -qec "cargo test --workspace" /dev/null`
Expected: PASS (0 failed). The three `alert.rs` tests are gone with the file; no snapshot referenced `Overlay::Alert` (verified pre-plan), so no `.snap` churn.

- [ ] **Step 9: Format**

Run: `cargo fmt`
Expected: green.

- [ ] **Step 10: Commit**

```bash
git add src/tui/run_loop.rs src/tui/app.rs src/tui/intent.rs src/tui/mod.rs \
        src/tui/transfer/open.rs docs/tui.md
git rm src/tui/alert.rs
git commit -m "refactor(tui): drop the modal Alert; unify all failures to the status bar"
```

> If `git rm` is unavailable in the dispatch environment, `git add` the deletion (`git add -u src/tui/alert.rs` after deleting the file) — the explicit-paths discipline still holds; do **not** use `git add -A`.

---

## Self-Review (run by the plan author, recorded here)

**1. Spec coverage** (the agreed principle: *Alert only when an inline response is collected; otherwise status bar; one wording source*):
- "No-interaction failures → status bar" → Task 2 (six sites) + Task 3 (the one Alert site) route through `report_failure`. ✓
- "Drop the no-interaction Alert" → Task 3 removes variant + file + branches atomically. ✓
- "One wording source (error Display, no prefix)" → `report_failure` body is `Status::error(e.to_string())`; the per-site `format!("<action> failed: …")` prefixes are deleted in Task 2 Step 5. ✓
- "Status bar is one row → flatten multi-line detail" → Task 1 `first_meaningful_line` at the one multi-line source (master stderr); the transfer-run site is de-duplicated to the same helper. ✓
- First-tick double-prefix bug → fixed for free by removing the `"sftp open failed: "` prefix (Task 2 Step 5 site 1). ✓

**2. Placeholder scan:** every step shows the actual code or the exact grep/edit. The two "mirror the existing constructor at app.rs:2126" / "verify line numbers; they drift" notes point at concrete existing code rather than inventing a signature. No TBD/TODO. ✓

**3. Type consistency:** `first_meaningful_line(&str) -> &str` (Task 1) matches both call sites' usage (`match first_meaningful_line(&s) { "" => …, line => … }` and `match first_meaningful_line(&stderr_str) { "" => …, s => … }`). `App::report_failure(&mut self, e: &sshrack_core::error::SshrackError)` (Task 2) matches the Task 3 call `app.report_failure(&e)` where `e: SshrackError`. `Overlay::Alert` removal in Task 3 is the only variant touched; the two `match` arms in `app.rs` become exhaustive over the remaining variants without further edits. ✓
