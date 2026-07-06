# Transfer Screen Fixes: Empty Panes / Cursor History / Remote Basename

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Fix three SFTP transfer-screen problems reported together: (1) both panes show empty on screen open even though the directories have files; (2) the panes have no per-directory cursor memory (the form file picker has it — navigating `A → B2 → back to A` should land back on `B2`, not the first entry); (3) the remote pane shows absolute paths instead of basenames (local shows basenames).

**Architecture:** Three independent fixes, one per task (plus a fourth DRY task). (1) Empty-on-open has **two root causes**: the local pane is never sent an initial listing (`open_transfer` only sends `WorkerCmd::List` for the remote side), and the remote pane's first `WorkerEvent::Listing` is gated behind an input event because `run_loop`'s no-event `continue` skips `drain_transfer_events`. Fix both: seed the local pane synchronously in `open_transfer`, and drain worker events in the no-event branch too. (2) Cursor history: extract the **identical** pure restore logic already in `file_picker::load` into a shared `tui::cursor_history::remembered_cursor_index`, then add a `history` map + `pending_restore` flag to `Pane` (snapshot in `on_step`, restore in `set_entries` — the flag separates dir-switch from in-place refresh). (3) Remote basename: `to_dir_entries` currently keeps the absolute path sftp emits in the name column; take `Path::file_name()` for display while keeping the absolute path for navigation.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28. **No new dependencies.**

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`. Prefer `unwrap_or` / `is_some_and` / `position`.
- **TDD for pure logic** — RED → GREEN → REFACTOR for pure-logic modules. Process/event-loop behavior is covered by regression + manual smoke (CLAUDE.md: "Process/PTY-dependent behavior is covered by integration tests").
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the old behavior outright; no parallel path.
- **No duplicate logic** — shared helpers belong in one place. Task 2 introduces the shared helper; Task 3 is the DRY move that makes `file_picker` use it.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`. Staging is explicit (`git add <paths>`), never `git add -A`.

**Scope invariant:** Tasks 1–3 are TUI-only (`src/tui/`). Task 4 touches `crates/sshrack-core/src/connect/sftp/parse.rs` (pure parse logic, no UI import — the zero-UI invariant holds).

---

## File Structure (target)

```
src/tui/
├── cursor_history.rs        # NEW (Task 2) — pure remembered_cursor_index + tests
├── mod.rs                   # MODIFY (Task 2) — declare pub(crate) mod cursor_history;
├── file_picker.rs           # MODIFY (Task 3) — load() restore → call shared helper
├── run_loop.rs              # MODIFY (Task 1) — drain worker events in the no-event branch
└── transfer/
    ├── open.rs              # MODIFY (Task 1) — seed local pane on open
    ├── pane.rs              # MODIFY (Task 2) — history field + on_step snapshot + set_entries restore
    └── pane_tests.rs        # MODIFY (Task 2) — 3 cursor-history tests
crates/sshrack-core/src/connect/sftp/
├── parse.rs                 # MODIFY (Task 4) — to_dir_entries takes basename for abs paths
└── source.rs                # MODIFY (Task 4) — tighten list fixture to real absolute-path form
```

---

## Inventory (the contract this plan must satisfy)

- `open_transfer` at `src/tui/transfer/open.rs:135-151` builds the screen and sends exactly ONE initial list — `WorkerCmd::List(home)` at `:146` — for the remote side only. The local pane is never seeded.
- `run_loop` at `src/tui/run_loop.rs:122-127`: `if !event::poll(...).unwrap_or(false) { continue; }` — the `continue` skips the per-tick `drain_transfer_events(app, &handle)` call at `:391-393`, so a remote `WorkerEvent::Listing` that arrives before the first keypress sits in the mpsc channel until the user presses a key.
- `drain_transfer_events` (`src/tui/run_loop.rs:430`) is the single consumer: it resolves `pending_list` (Local inline via `LocalDirSource::list`, Remote via `WorkerCmd::List`) and feeds `WorkerEvent::Listing` into `screen.remote_mut().set_entries(...)` at `:515`. It is a no-op when there is no `pending_list` and no worker event, so calling it in the no-event branch is safe.
- `Pane::set_entries` (`src/tui/transfer/pane.rs:156-160`) unconditionally resets `self.selected = 0`. `Pane::on_step` (`:171-175`) clears marks/query/selected — it is the single "leaving this cwd" point and runs before the screen updates `pane.cwd` (`run_loop.rs:459` local / `:490` remote) and then calls `set_entries`. So `on_step` (snapshot the OLD cwd) → cwd update → `set_entries` (restore for the NEW cwd) is the wiring point.
- `file_picker.rs:123-156` `load()` already does cursor history: `history: HashMap<PathBuf, PathBuf>` field at `:61-65`, snapshot at `:129-131`, restore at `:139-147` (locate remembered path in `ranked`, fallback 0). The restore block at `:139-147` is the exact logic Task 2 extracts and Task 3 swaps for a call.
- `DirEntry` (`crates/sshrack-core/src/dirsource.rs:40-53`): `name` = display-ready (trailing `/` or `@`), `path` = absolute. `LocalDirSource::list` sets `name = entry.file_name()` (basename). `SftpDirSource::list` → `parse_ls_listing` → `to_dir_entries` (`parse.rs:131-141`): sftp `ls -l <abs>` (see `proto.rs:94-96` `list_batch`) emits ABSOLUTE paths in the name column, and `to_dir_entries` keeps `clean` as-is for the name → remote shows absolute paths. The render layer uses `entry.name` only (`render.rs:209`, `pane.rs:301`), so the fix belongs in `to_dir_entries`.
- `pane_tests.rs` (`src/tui/transfer/pane_tests.rs`) is `#[path]`-included from `pane.rs`, reaches `super::*` private fields, and already has `entry(name, parent, is_dir)` (`:21`) + `press()` (`:38`) helpers.
- `parse.rs` test module has a `raw(name, is_dir, is_symlink)` helper and `RawLsEntry { ... }` literal construction (see `parse.rs:626`).

---

## Task 1: Populate both panes on transfer screen open

**Files:**
- Modify: `src/tui/transfer/open.rs:135-151`
- Modify: `src/tui/run_loop.rs:122-127`

**Interfaces:**
- Consumes: `sshrack_core::dirsource::{DirSource, LocalDirSource}` (already used in `run_loop.rs:431`), `TransferScreen::local_mut` (`screen.rs:148`), `Status::error` (`intent::Status`).
- Produces: no signature changes. Behavior: both panes are populated immediately on screen open.

**Note on testing:** This task fixes I/O timing + event-loop control flow, NOT pure logic (CLAUDE.md: process/PTY-dependent behavior → integration/smoke). There is no new pure function to TDD. Verification = full workspace regression (no existing test breaks) + the manual smoke at the end. Do not fabricate a unit test for the event loop.

- [ ] **Step 1: Seed the local pane synchronously in `open_transfer`**

In `src/tui/transfer/open.rs`, the block at `:135-151` ends with:

```rust
    worker.send(sshrack_core::connect::sftp::proto::WorkerCmd::List(home));

    app.transfer = Some(screen);
```

Insert the local-pane seed BETWEEN those two lines (after the remote `List` send, before storing the screen on `app`):

```rust
    worker.send(sshrack_core::connect::sftp::proto::WorkerCmd::List(home));

    // Seed the local pane now (the local fs is fast and synchronous) so it is
    // not blank until the first keypress. Mirrors what drain_transfer_events
    // does on navigation; a failure here is non-fatal — the status row surfaces
    // it and the pane just stays empty until the user navigates.
    {
        use sshrack_core::dirsource::{DirSource, LocalDirSource};
        match LocalDirSource::new().list(&local_cwd) {
            Ok(entries) => screen.local_mut().set_entries(entries),
            Err(msg) => screen.set_status(crate::tui::intent::Status::error(format!(
                "local list failed: {msg}"
            ))),
        }
    }

    app.transfer = Some(screen);
```

- [ ] **Step 2: Drain worker events in the no-event branch of the run loop**

In `src/tui/run_loop.rs:122-127`, the no-event branch currently is:

```rust
        if !event::poll(Duration::from_millis(250)).unwrap_or(false) {
            // No event within the poll window, or poll itself failed: re-render
            // and poll again. Unwrap_or(false) keeps the loop alive on a
            // transient poll error instead of unwinding the TUI.
            continue;
        }
```

Replace it so an open transfer session still drains worker events before `continue` (so an async remote listing or transfer-progress event lands without waiting for a keypress):

```rust
        if !event::poll(Duration::from_millis(250)).unwrap_or(false) {
            // No key within the poll window — still drain worker events so an
            // async remote listing (or transfer progress) lands without waiting
            // for a keypress. drain_transfer_events is a no-op for pending_list
            // when on_key set none, so this only flushes WorkerEvent traffic.
            if app.transfer_worker.is_some() {
                drain_transfer_events(app, &handle);
            }
            if app.should_quit {
                return None;
            }
            continue;
        }
```

(Keep the existing post-key `drain_transfer_events` call at `:391-393` unchanged — it handles `pending_list` set by `on_key` on the same tick. The two call sites are idempotent together: `pending_list` is `take`n once, and worker events drain to empty.)

- [ ] **Step 3: Build + full workspace regression**

```bash
cargo build --workspace
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
```

Expected: every `test result:` line is `ok` with `0 failed`. (The fix changes I/O timing + control flow; existing tests assert pure pane/screen logic and must stay green.)

- [ ] **Step 4: clippy + fmt**

```bash
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: clippy clean; `FMT_OK`.

- [ ] **Step 5: Commit**

```bash
git add src/tui/transfer/open.rs src/tui/run_loop.rs
git commit -m "fix(tui): populate both transfer panes on screen open" -m "open_transfer sent the initial WorkerCmd::List for the remote side only, so the local pane was blank until the first navigation; and run_loop's no-event continue skipped drain_transfer_events, so the remote pane's first WorkerEvent::Listing sat in the mpsc channel until the first keypress. Seed the local pane synchronously in open_transfer (LocalDirSource::list, same path navigation uses) and drain worker events in the no-event branch too. The two drain call sites are idempotent together (pending_list is taken once; worker events drain to empty)."
```

---

## Task 2: Per-directory cursor history in the transfer pane (+ shared helper)

**Files:**
- Create: `src/tui/cursor_history.rs`
- Modify: `src/tui/mod.rs` (declare the module)
- Modify: `src/tui/transfer/pane.rs` (`Pane` struct + `new` + `on_step` + `set_entries`)
- Test: `src/tui/cursor_history.rs` (unit), `src/tui/transfer/pane_tests.rs` (3 tests)

**Interfaces:**
- Produces: `pub(crate) fn remembered_cursor_index(history: &HashMap<PathBuf, PathBuf>, cwd: &Path, ranked: &[usize], entries: &[DirEntry]) -> usize` in `crate::tui::cursor_history`. Two new private fields on `Pane`: `history: HashMap<PathBuf, PathBuf>`, `pending_restore: bool`.
- Consumes (Task 3): `file_picker::load` will call the same helper.

- [ ] **Step 1: Write the failing unit tests for the shared helper (RED)**

Create `src/tui/cursor_history.rs` with ONLY the test module (no impl yet — the `remembered_cursor_index` reference will fail to compile, which is the RED signal):

```rust
//! Shared per-directory cursor-memory restore for directory browsers.
//!
//! Both the form file picker (`file_picker::FilePicker::load`) and the SFTP
//! transfer `Pane` remember, per visited directory, which entry was selected
//! when the user left it (ranger-style directory history). The restore step —
//! locate the remembered entry path in the current ranked view — is identical
//! pure logic, so it lives here once. The snapshot step is a one-line insert
//! each caller does inline (it knows its own `cwd` + `selected_entry`).

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::dirsource::DirEntry;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn entry(name: &str, path: &str, is_dir: bool) -> DirEntry {
        DirEntry {
            name: name.into(),
            path: PathBuf::from(path),
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    #[test]
    fn empty_history_returns_zero() {
        let history = HashMap::new();
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0, 1], &entries),
            0
        );
    }

    #[test]
    fn remembered_path_present_returns_its_ranked_index() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/b"));
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0, 1], &entries),
            1
        );
    }

    #[test]
    fn ranked_reorder_is_respected() {
        // dirs-first decoration may rank b before a; the restore follows the
        // ranked order, not the entries order.
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/a"));
        let entries = vec![entry("a/", "/x/a", true), entry("b/", "/x/b", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[1, 0], &entries),
            1
        );
    }

    #[test]
    fn remembered_path_missing_falls_back_to_zero() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/x"), PathBuf::from("/x/gone"));
        let entries = vec![entry("a/", "/x/a", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0], &entries),
            0
        );
    }

    #[test]
    fn cwd_not_in_history_returns_zero() {
        let mut history = HashMap::new();
        history.insert(PathBuf::from("/other"), PathBuf::from("/other/a"));
        let entries = vec![entry("a/", "/x/a", true)];
        assert_eq!(
            remembered_cursor_index(&history, Path::new("/x"), &[0], &entries),
            0
        );
    }
}
```

- [ ] **Step 2: Run — expect compile failure (RED)**

```bash
cargo test --bin sshrack tui::cursor_history 2>&1 | tail -15
```

Expected: fails to compile (`cannot find function remembered_cursor_index`).

- [ ] **Step 3: Declare the module**

In `src/tui/mod.rs`, next to the sibling module declarations (e.g. beside `pub mod file_picker;`), add:

```rust
pub(crate) mod cursor_history;
```

- [ ] **Step 4: Implement the helper (GREEN)**

Add above the test module in `src/tui/cursor_history.rs`:

```rust
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sshrack_core::dirsource::DirEntry;

/// Return the ranked-list index of the entry `history` remembers for `cwd`,
/// or `0` when nothing is remembered or the remembered path is no longer in
/// the listing. Pure.
///
/// - `history`: visited-cwd → that dir's last-selected entry path.
/// - `ranked`: indices into `entries`, fuzzy-ordered for display (the cursor
///   indexes `ranked`, not `entries`).
/// - `entries`: the current listing the ranked indices point into.
///
/// Reachability: `file_picker::FilePicker::load` + `transfer::Pane::set_entries`.
#[must_use]
pub(crate) fn remembered_cursor_index(
    history: &HashMap<PathBuf, PathBuf>,
    cwd: &Path,
    ranked: &[usize],
    entries: &[DirEntry],
) -> usize {
    history
        .get(cwd)
        .and_then(|p| {
            ranked
                .iter()
                .position(|&i| entries.get(i).is_some_and(|e| &e.path == p))
        })
        .unwrap_or(0)
}
```

- [ ] **Step 5: Run — GREEN**

```bash
cargo test --bin sshrack tui::cursor_history 2>&1 | tail -15
```

Expected: all 5 `cursor_history` tests pass.

- [ ] **Step 6: Write the 3 failing pane tests (RED)**

In `src/tui/transfer/pane_tests.rs`, append (the existing `entry(name, parent, is_dir)` helper at `:21` is reused):

```rust
// ---- cursor history: re-entering a dir restores the cursor ----

#[test]
fn set_entries_without_on_step_resets_cursor_to_zero() {
    // An in-place refresh (no on_step) must NOT move the cursor based on
    // history — it resets to 0 like before.
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("banana", &cwd, false),
    ]);
    p.selected = 1; // cursor on banana
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("banana", &cwd, false),
        entry("cherry", &cwd, false),
    ]);
    assert_eq!(p.selected, 0, "in-place refresh resets cursor to 0");
}

#[test]
fn step_into_and_back_restores_cursor() {
    let a = PathBuf::from("/A");
    let mut p = Pane::new(a.clone());
    p.set_entries(vec![
        entry("B1", &a, true),
        entry("B2", &a, true),
        entry("B3", &a, true),
    ]);
    // 3 dirs, empty query → ranked = [0,1,2] (B1,B2,B3); land on B2.
    p.selected = 1;
    assert_eq!(
        p.selected_entry().map(|e| e.name.clone()).as_deref(),
        Some("B2/"),
        "sanity: cursor on B2 before entering"
    );
    // step into B2: snapshot /A → /A/B2, then load /A/B2.
    p.on_step();
    let b2 = PathBuf::from("/A/B2");
    p.cwd = b2.clone();
    p.set_entries(vec![entry("f1", &b2, false)]);
    assert_eq!(p.selected, 0, "first visit to /A/B2 lands at 0");
    // step back to /A: snapshot /A/B2 → f1, then reload /A.
    p.on_step();
    p.cwd = a.clone();
    p.set_entries(vec![
        entry("B1", &a, true),
        entry("B2", &a, true),
        entry("B3", &a, true),
    ]);
    assert_eq!(
        p.selected, 1,
        "re-entering /A restores the cursor on B2 (directory history)"
    );
    assert_eq!(
        p.selected_entry().map(|e| e.name.clone()).as_deref(),
        Some("B2/")
    );
}

#[test]
fn remembered_cursor_missing_falls_back_to_zero() {
    let a = PathBuf::from("/A");
    let mut p = Pane::new(a.clone());
    p.set_entries(vec![entry("B2", &a, true)]);
    p.on_step(); // remember /A → /A/B2
    let b2 = PathBuf::from("/A/B2");
    p.cwd = b2.clone();
    p.set_entries(vec![entry("f1", &b2, false)]);
    // back to /A, but the new listing no longer contains B2.
    p.on_step();
    p.cwd = a.clone();
    p.set_entries(vec![entry("B9", &a, true)]);
    assert_eq!(
        p.selected, 0,
        "remembered path missing from new listing falls back to 0"
    );
    assert_eq!(
        p.selected_entry().map(|e| e.name.clone()).as_deref(),
        Some("B9/")
    );
}
```

- [ ] **Step 7: Run — expect RED**

```bash
cargo test --bin sshrack transfer::pane_tests::step_into_and_back_restores_cursor 2>&1 | tail -20
```

Expected: `step_into_and_back_restores_cursor` FAILs (current `set_entries` always sets `selected = 0`, so after going back the cursor is on `B1/`, not `B2/`). `set_entries_without_on_step_resets_cursor_zero` and `remembered_cursor_missing_falls_back_to_zero` PASS already (current behavior) — they are regression guards.

- [ ] **Step 8: Add the `history` + `pending_restore` fields to `Pane`**

In `src/tui/transfer/pane.rs`, add two private fields to the `Pane` struct right after `pub marked: HashSet<PathBuf>,` (`:117`):

```rust
    /// Per-directory cursor memory (ranger-style history): visited cwd → that
    /// dir's last-selected entry path. Snapshot in [`on_step`](Self::on_step)
    /// (the only "leaving this cwd" point), restored in
    /// [`set_entries`](Self::set_entries) via [`cursor_history`]. Per-pane
    /// private, so local and remote remember independently.
    history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
    /// Set by [`on_step`](Self::on_step) so the next
    /// [`set_entries`](Self::set_entries) restores the NEW cwd's remembered
    /// cursor instead of resetting to 0. Consumed (cleared) by `set_entries`.
    /// Separates a dir-switch from an in-place refresh (which must NOT move
    /// the cursor).
    pending_restore: bool,
```

Initialize both in `Pane::new` (`:133-143`), next to `loading: false,`:

```rust
            history: std::collections::HashMap::new(),
            pending_restore: false,
```

- [ ] **Step 9: Snapshot in `on_step`**

Replace `Pane::on_step` (`:171-175`):

```rust
    pub fn on_step(&mut self) {
        // Snapshot the OUTGOING cwd's cursor before clearing it, so re-entering
        // this dir restores it (ranger-style directory history). `cwd` is still
        // the old one here — the screen updates cwd between on_step and
        // set_entries.
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.marked.clear();
        self.query.clear();
        self.selected = 0;
        self.pending_restore = true;
    }
```

- [ ] **Step 10: Restore in `set_entries`**

Replace `Pane::set_entries` (`:156-160`):

```rust
    pub fn set_entries(&mut self, entries: Vec<DirEntry>) {
        self.entries = entries;
        self.recompute();
        if self.pending_restore {
            // Dir switch (on_step ran first): restore the NEW cwd's remembered
            // cursor by locating it in the just-recomputed `ranked`. First
            // visit, or a remembered path gone from the listing, falls back to 0.
            self.selected = crate::tui::cursor_history::remembered_cursor_index(
                &self.history,
                &self.cwd,
                &self.ranked,
                &self.entries,
            );
            self.pending_restore = false;
        } else {
            // In-place refresh (same dir, new entries): reset to 0 like before.
            self.selected = 0;
        }
    }
```

(`recompute` runs first so `ranked` reflects the new entries + the cleared query; the restore then searches `ranked`. `self.cwd` is already the NEW cwd — the screen updates it between `on_step` and `set_entries` at `run_loop.rs:459` / `:490`.)

- [ ] **Step 11: Run — GREEN**

```bash
cargo test --bin sshrack transfer::pane 2>&1 | tail -15
cargo test --bin sshrack tui::cursor_history 2>&1 | tail -10
```

Expected: all pane + cursor_history tests pass, including the 3 new ones.

- [ ] **Step 12: Full workspace regression + clippy + fmt**

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: every `test result:` ok / `0 failed`; clippy clean; `FMT_OK`.

- [ ] **Step 13: Commit**

```bash
git add src/tui/cursor_history.rs src/tui/mod.rs src/tui/transfer/pane.rs src/tui/transfer/pane_tests.rs
git commit -m "feat(tui): remember per-directory cursor in the transfer pane" -m "Pane.reset selected=0 on every set_entries, so navigating A -> B2 -> back to A landed on B1 instead of B2. Extract the restore logic file_picker already had into tui::cursor_history::remembered_cursor_index (pure: locate a remembered entry path in the current ranked view, fallback 0), add a history map + pending_restore flag to Pane, snapshot the outgoing cwd's cursor in on_step, and restore the incoming cwd's cursor in set_entries. pending_restore separates a dir-switch (restore) from an in-place refresh (reset to 0). Per-pane private, so local and remote remember independently. file_picker switches to the same helper in the next commit."
```

---

## Task 3: file_picker reuses the shared cursor-history helper (DRY)

**Files:**
- Modify: `src/tui/file_picker.rs:139-147`

**Interfaces:**
- Consumes: `crate::tui::cursor_history::remembered_cursor_index` (Task 2).
- Produces: no signature changes. `file_picker`'s `history` field type is already `HashMap<PathBuf, PathBuf>` (`:61-65`).

- [ ] **Step 1: Replace the inline restore with a call to the shared helper**

In `src/tui/file_picker.rs`, inside `load()` (`:123-156`), replace the restore block at `:139-147`:

```rust
                self.selected = self
                    .history
                    .get(&cwd)
                    .and_then(|p| {
                        self.ranked
                            .iter()
                            .position(|&i| self.entries.get(i).is_some_and(|e| &e.path == p))
                    })
                    .unwrap_or(0);
```

with:

```rust
                // Restore the incoming dir's remembered cursor (first visit →
                // 0). Shared with transfer::Pane so both browsers stay in sync.
                self.selected = crate::tui::cursor_history::remembered_cursor_index(
                    &self.history,
                    &cwd,
                    &self.ranked,
                    &self.entries,
                );
```

Leave the snapshot at `:129-131` (`self.history.insert(prev, cursor)`) and everything else in `load` unchanged.

- [ ] **Step 2: Run file_picker's existing cursor-history tests (regression)**

```bash
cargo test --bin sshrack tui::file_picker 2>&1 | tail -15
```

Expected: all file_picker tests pass — in particular the 3 cursor-history tests (`step_into_and_back_restores_cursor`, `first_visit_lands_on_first_entry`, `remembered_cursor_missing_falls_back_to_zero`). They pin the same behavior the shared helper now provides, so they must stay green unchanged.

- [ ] **Step 3: Full workspace regression + clippy + fmt**

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: every `test result:` ok / `0 failed`; clippy clean; `FMT_OK`.

- [ ] **Step 4: Commit**

```bash
git add src/tui/file_picker.rs
git commit -m "refactor(tui): reuse shared cursor-history helper in file picker" -m "file_picker::load had the same ranked-path restore logic the transfer pane now needs. Drop the inline copy and call tui::cursor_history::remembered_cursor_index instead (extracted in the previous commit). Behavior unchanged — the 3 existing cursor-history tests in file_picker stay green."
```

---

## Task 4: Remote entries show basename, not absolute path

**Files:**
- Modify: `crates/sshrack-core/src/connect/sftp/parse.rs:131-141` (`to_dir_entries`)
- Test: `crates/sshrack-core/src/connect/sftp/parse.rs` (2 new tests)
- Modify: `crates/sshrack-core/src/connect/sftp/source.rs:202-206` (tighten the list fixture to the real absolute-path form)

**Interfaces:**
- Produces: no signature changes. `to_dir_entries` behavior: when the parsed name is an absolute path (real sftp `ls -l <abs>` form), the `DirEntry.name` becomes the basename and `DirEntry.path` stays absolute; relative names still join under `cwd` (legacy form).

- [ ] **Step 1: Write the 2 failing tests (RED)**

In the `#[cfg(test)] mod tests` block of `crates/sshrack-core/src/connect/sftp/parse.rs`, in the `---- to_dir_entries ----` section (after `to_dir_entries_empty_is_empty` at `:638-641`), add:

```rust
    #[test]
    fn to_dir_entries_strips_absolute_prefix_to_basename() {
        // sftp `ls -l /srv` emits rows with ABSOLUTE paths in the name column
        // (because the argument is absolute). The display name must be the
        // basename; the navigation path stays absolute.
        let rows = vec![
            RawLsEntry {
                name: "/srv/sub".into(),
                is_dir: true,
                is_symlink: false,
                size: None,
                modified: None,
            },
            RawLsEntry {
                name: "/srv/afile.txt".into(),
                is_dir: false,
                is_symlink: false,
                size: Some(1234),
                modified: None,
            },
        ];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["sub/", "afile.txt"], "dirs first, decorated; basename only");
        assert_eq!(entries[0].path, PathBuf::from("/srv/sub"), "dir path stays absolute");
        let afile = entries
            .iter()
            .find(|e| e.name == "afile.txt")
            .expect("file entry present");
        assert_eq!(afile.path, PathBuf::from("/srv/afile.txt"), "file path stays absolute");
    }

    #[test]
    fn to_dir_entries_relative_name_still_joins_cwd() {
        // A relative (basename) name — e.g. a server that lists relatively —
        // still joins under cwd (the legacy behavior), so both forms work.
        let rows = vec![RawLsEntry {
            name: "rel.txt".into(),
            is_dir: false,
            is_symlink: false,
            size: None,
            modified: None,
        }];
        let entries = to_dir_entries(rows, Path::new("/srv"));
        assert_eq!(entries[0].name, "rel.txt");
        assert_eq!(entries[0].path, PathBuf::from("/srv/rel.txt"));
    }
```

- [ ] **Step 2: Run — expect RED**

```bash
cargo test -p sshrack-core connect::sftp::parse::tests::to_dir_entries_strips_absolute_prefix_to_basename 2>&1 | tail -20
```

Expected: `to_dir_entries_strips_absolute_prefix_to_basename` FAILs — current `to_dir_entries` keeps `/srv/sub` as the name (so `entries[0].name` is `"/srv/sub/"` after decoration, not `"sub/"`). `to_dir_entries_relative_name_still_joins_cwd` PASSes already (legacy path) — regression guard.

- [ ] **Step 3: Implement — basename for absolute names**

Replace `to_dir_entries` (`crates/sshrack-core/src/connect/sftp/parse.rs:131-141`):

```rust
/// Convert parsed rows into display-ready [`DirEntry`] rows: strip control
/// chars from each name, attach paths, decorate + sort dirs-first via
/// [`build_entries`]. Pure (takes already-parsed rows; any clock reference
/// was supplied to [`parse_ls_line`] before rows reached here).
///
/// Name shape: `sftp ls -l <abs>` emits ABSOLUTE paths in the name column, so
/// when the cleaned name is absolute we take its basename for display and
/// keep the absolute path for navigation. A relative name still joins under
/// `cwd` (servers that list relatively, or future sources).
pub fn to_dir_entries(rows: Vec<RawLsEntry>, cwd: &Path) -> Vec<DirEntry> {
    let items: Vec<RawEntry> = rows
        .into_iter()
        .map(|r| {
            let clean = strip_control_chars(&r.name);
            let (display, path) = if std::path::Path::new(&clean).is_absolute() {
                let abs = std::path::PathBuf::from(&clean);
                let base = abs
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or(clean.clone());
                (base, abs)
            } else {
                (clean.clone(), cwd.join(&clean))
            };
            (display, path, r.is_dir, r.is_symlink, r.size, r.modified)
        })
        .collect();
    build_entries(items)
}
```

- [ ] **Step 4: Run — GREEN**

```bash
cargo test -p sshrack-core connect::sftp::parse 2>&1 | tail -15
```

Expected: all parse tests pass, including the 2 new ones. (The existing basename tests pass unchanged: a relative name like `"Adir"` takes the `else` branch, exactly the old `cwd.join` behavior.)

- [ ] **Step 5: Tighten the source-level list fixture to the real absolute-path form**

In `crates/sshrack-core/src/connect/sftp/source.rs`, the `list_parses_rows_into_sorted_decorated_entries` test (`:197-227`) feeds a canned `ls -l` whose name column is basenames (`zdir`, `afile.txt`, `link -> tgt`) — that is not what sftp actually emits for `ls -l /srv`. Change the canned names to absolute paths so the end-to-end path reflects reality and guards the Task-4 fix:

```rust
        let canned = "\
drwxr-xr-x 2 u g 4096 Jan 2 03:04 /srv/zdir
-rw-r--r-- 1 u g 1234 Jan 2 03:04 /srv/afile.txt
lrwxrwxrwx 1 u g 4 Jan 2 03:04 /srv/link -> tgt
";
```

The existing assertions (`names == ["zdir/", "afile.txt", "link@"]`, `afile.path == /srv/afile.txt`, `zdir.is_dir`) now exercise the basename extraction end-to-end and stay green after Step 3. Do not change the assertions — only the canned input.

- [ ] **Step 6: Full workspace regression + clippy + fmt**

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: every `test result:` ok / `0 failed`; clippy clean; `FMT_OK`.

- [ ] **Step 7: Commit**

```bash
git add crates/sshrack-core/src/connect/sftp/parse.rs crates/sshrack-core/src/connect/sftp/source.rs
git commit -m "fix(sftp): show remote entries by basename, not absolute path" -m "sftp ls -l <abs> emits absolute paths in the name column, and to_dir_entries kept them verbatim as DirEntry.name, so the remote transfer pane showed absolute paths while the local pane showed basenames. When the cleaned name is absolute, take Path::file_name() for display and keep the absolute path for navigation; relative names still join under cwd. Tighten the source-level list fixture to the real absolute-path form so the end-to-end path guards this. Display layer already uses entry.name only, so no render change needed."
```

---

## Final smoke test (after all four tasks land)

Build a release binary and exercise all three fixes against a real host:

```bash
cargo build --release
# Run from a directory that has files (so the local pane has something to show):
./target/release/sshrack <host>   # launcher
# Press Ctrl-T on the host to enter the transfers screen.
```

Verify:
1. **Empty fix:** both panes show their current-directory contents IMMEDIATELY on open — no keypress needed.
2. **Cursor history:** navigate local `A → <subdir> → Left back to A`; the cursor lands on the entry you left, not the first one. Repeat on the remote pane. Confirm local and remote remember independently.
3. **Remote basename:** the remote pane's entries show plain filenames (e.g. `file.txt`, `subdir/`), matching the local pane — no `/home/user/...` prefixes.

If a host is not available, at minimum run the full gate one more time:

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -15
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt --check && echo FMT_OK
```

---

## Self-Review

**1. Spec coverage (each reported problem → task):**
- "Ctrl-T 进入 transfers 后，双方当前目录的内容都是 empty" → Task 1 (local seed in `open_transfer` + drain worker events in the no-event branch). ✅
- "transfers 页面切换目录缺少 history 能力（表单文件选择器上有）" → Task 2 (`Pane` history + shared helper) + Task 3 (`file_picker` DRY move so the two stay unified). ✅
- "远程目录显示绝对路径，期望显示文件名，和 local 一致" → Task 4 (`to_dir_entries` basename for absolute names). ✅

**2. Placeholder scan:** No TBD/TODO. Every step has runnable code or an exact command. The one non-TDD task (Task 1) states why (I/O timing, not pure logic) and gives the smoke verification instead of fabricating a unit test.

**3. Type consistency:**
- `remembered_cursor_index(history: &HashMap<PathBuf, PathBuf>, cwd: &Path, ranked: &[usize], entries: &[DirEntry]) -> usize` — matches: Task 2 helper tests, `Pane::set_entries` call (Task 2 Step 10: `&self.history` is `HashMap<PathBuf, PathBuf>`, `&self.cwd` is `&PathBuf` → deref-coerces to `&Path`, `&self.ranked` is `&Vec<usize>` → `&[usize]`, `&self.entries` is `&Vec<DirEntry>` → `&[DirEntry]`), and the `file_picker::load` call (Task 3: `&self.history`, `&cwd` where `cwd: PathBuf`, `&self.ranked`, `&self.entries`). ✅
- `Pane.history: HashMap<PathBuf, PathBuf>` + `pending_restore: bool` (Task 2 Step 8) — matches init in `new` (Step 8), snapshot in `on_step` (Step 9: `self.history.insert(self.cwd.clone(), cursor)` where `cursor` is `PathBuf` from `selected_entry().map(|e| e.path.clone())`), and restore+clear in `set_entries` (Step 10). ✅
- `to_dir_entries` returns `(display, path, is_dir, is_symlink, size, modified)` matching the existing `RawEntry` tuple `build_entries` consumes; `display` is the undecorated basename (decoration is `build_entries`'s job, same as before). ✅
- `selected_entry()` already exists on `Pane` (used in `pane_tests.rs:66` and by the new tests) and on `FilePicker`. ✅

**4. Purity / invariants:**
- `cursor_history::remembered_cursor_index` is pure (HashMap read + `position`); its tests are hermetic. ✅
- `to_dir_entries` is pure (path ops on already-parsed rows); new tests are hermetic. ✅
- `Pane` changes stay pure (no I/O added; `on_step`/`set_entries` were already pure). ✅
- No new `unsafe` / `unwrap` / `expect` in prod code (`unwrap_or`, `is_some_and`, `and_then` only). ✅
- Task 4 touches `sshrack-core` but adds NO UI import (path parsing only) — the zero-UI invariant holds. ✅
- The two `drain_transfer_events` call sites in Task 1 are idempotent together (`pending_list` is `take`n; worker events drain to empty) — no double-feed. ✅
