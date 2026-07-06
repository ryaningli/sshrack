# File-Picker Directory Cursor History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Make the file picker remember, per directory, which entry was under the cursor when the user left it — so navigating `A → B2 → back to A` lands on `B2` again (ranger-style directory history) instead of resetting to the first entry.

**Architecture:** Add a private `history: HashMap<PathBuf, PathBuf>` (visited cwd → that dir's last-selected entry path) to `FilePicker`. The **single** touch point is `load()` — the only directory-switching path (`step_into`, `step_up`, and the PathLike-Dir branch of `activate_selected` all go through it). `load` snapshots the outgoing cwd's cursor *before* `list` swaps `entries`, and restores the incoming cwd's cursor *after* `recompute`. Because `selected` is a **ranked-list index** (not an `entries` index), the restore searches `ranked` for the remembered entry path. Query is still cleared on every `load` (out of scope). Window scroll follows `selected` via the existing `focus_window`, so cursor restore implies scroll restore for free — no separate scroll memory.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28. **No new dependencies.**

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`. Prefer `unwrap_or` / `is_some_and` / `position`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. This change is pure (no fs in the new logic; the `FakeSource` test seam already exists).
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace the unconditional `selected = 0` outright; do not keep a parallel old path.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`. Likely `fix(tui)` or `feat(tui)` here — `feat(tui)` fits (new navigational capability).

**Scope invariant:** Only `src/tui/file_picker.rs` changes. `sshrack-core` is untouched.

---

## File Structure

```
src/tui/file_picker.rs   # MODIFY — the only file
  ├── struct FilePicker        + field `history`
  ├── new()                    + init `history: HashMap::new()`
  ├── load()                   snapshot outgoing cursor + restore incoming cursor
  └── #[cfg(test)] mod tests   + `multi_dir_tree()` fixture + 3 tests
```

No new modules, no new deps, no public-API change (the field is private).

---

## Inventory (the contract this plan must satisfy)

- `load()` at `src/tui/file_picker.rs:111-127` sets `self.selected = 0` unconditionally on the `Ok` branch — this is the line that erases memory and the one this plan replaces.
- `selected` is a **ranked-list index**: `selected_entry()` maps `ranked[selected] → entries[i]`. So the restore must locate the remembered path in `ranked`, not in `entries`.
- `load` is the **sole** directory-switching entry point:
  - `step_into(child)` → `load(child.path)` (`:164-166`)
  - `step_up()` → `load(parent)` (`:169-174`)
  - `activate_selected()` PathLike-Dir → `load(abs)` (`:248-251`)
  - first-ever load via `ensure_started()` → `load(cwd)` (`:92-104`)
  Putting the snapshot/restore in `load` covers all four navigation shapes at once.
- `focus_window` already centers the viewport on `selected` (`draw_overlay`), so restoring `selected` automatically restores scroll — no extra state.
- The test module already has `FakeSource` (in-memory `DirSource`), `tree()`, and `press()` helpers (`:412-491`) — reused, plus one new fixture and one stateful source.

---

## Task 1: directory cursor history in `load`

**Files:**
- Modify: `src/tui/file_picker.rs`

**Interfaces:**
- Produces: one new private struct field `history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>`; behavior change inside `load()`. No new public items, no signature changes.

- [ ] **Step 1: Add the `multi_dir_tree()` test fixture**

Add this fixture inside the existing `#[cfg(test)] mod tests` block (next to `tree()`), so the new tests can build a multi-level dir layout:

```rust
    /// Multi-level fixture: `/A/{B1/, B2/, B3/}` (subdirs), `/A/B2/{f1, f2}`
    /// (files inside B2), `/A/B1` and `/A/B3` empty. `home` = `/A` so a
    /// no-hint picker starts in `/A`.
    fn multi_dir_tree() -> FakeSource {
        let mut f = FakeSource {
            home: Some(PathBuf::from("/A")),
            ..Default::default()
        };
        let a = PathBuf::from("/A");
        let b2 = PathBuf::from("/A/B2");
        f.dirs.insert(
            a.clone(),
            vec![
                FakeSource::entry("B1", &a, true),
                FakeSource::entry("B2", &a, true),
                FakeSource::entry("B3", &a, true),
            ],
        );
        f.dirs.insert(
            b2.clone(),
            vec![
                FakeSource::entry("f1", &b2, false),
                FakeSource::entry("f2", &b2, false),
            ],
        );
        f.dirs.insert(PathBuf::from("/A/B1"), vec![]);
        f.dirs.insert(PathBuf::from("/A/B3"), vec![]);
        f
    }
```

- [ ] **Step 2: Write the 3 failing tests (RED)**

Add these three tests in the same test module (e.g. after `enter_on_dir_steps_into_it`):

```rust
    // ---- directory cursor history: re-entering a dir restores the cursor ----

    #[test]
    fn step_into_and_back_restores_cursor() {
        let mut p = FilePicker::new("pick", None, multi_dir_tree());
        p.ensure_started(); // lands in /A
        // land the cursor on B2 by name (order-agnostic vs the ranker)
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B2/"),
            "sanity: cursor on B2 before entering"
        );
        let _ = p.on_key(press(KeyCode::Right)); // enter B2
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A/B2")));
        let _ = p.on_key(press(KeyCode::Left)); // back to /A
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A")));
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B2/"),
            "re-entering a dir must restore the previous cursor (directory history)"
        );
    }

    #[test]
    fn first_visit_lands_on_first_entry() {
        let mut p = FilePicker::new("pick", None, multi_dir_tree());
        p.ensure_started(); // /A, cursor at index 0
        assert_eq!(p.selected, 0, "initial dir → index 0");
        // navigate to B2 and enter it (never visited, non-empty).
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        let _ = p.on_key(press(KeyCode::Right)); // enter B2 — first visit
        assert_eq!(p.cwd.as_deref(), Some(std::path::Path::new("/A/B2")));
        assert_eq!(p.selected, 0, "first visit to a dir → index 0 (no history yet)");
    }

    #[test]
    fn remembered_cursor_missing_falls_back_to_zero() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        // Stateful source: the FIRST list of /A returns [B1,B2,B3]; after we
        // enter B2 and come back, the SECOND list of /A returns [B9] only.
        // The remembered B2 path is now gone → the cursor must fall back to 0.
        #[derive(Clone)]
        struct Mutating {
            a_calls: Arc<AtomicUsize>,
        }
        impl DirSource for Mutating {
            fn list(&self, cwd: &Path) -> Result<Vec<DirEntry>, String> {
                if cwd == std::path::Path::new("/A") {
                    let n = self.a_calls.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Ok(vec![
                            DirEntry {
                                name: "B1/".into(),
                                path: std::path::PathBuf::from("/A/B1"),
                                is_dir: true,
                                is_symlink: false,
                            },
                            DirEntry {
                                name: "B2/".into(),
                                path: std::path::PathBuf::from("/A/B2"),
                                is_dir: true,
                                is_symlink: false,
                            },
                            DirEntry {
                                name: "B3/".into(),
                                path: std::path::PathBuf::from("/A/B3"),
                                is_dir: true,
                                is_symlink: false,
                            },
                        ])
                    } else {
                        Ok(vec![DirEntry {
                            name: "B9/".into(),
                            path: std::path::PathBuf::from("/A/B9"),
                            is_dir: true,
                            is_symlink: false,
                        }])
                    }
                } else if cwd == std::path::Path::new("/A/B2") {
                    Ok(vec![DirEntry {
                        name: "f1".into(),
                        path: std::path::PathBuf::from("/A/B2/f1"),
                        is_dir: false,
                        is_symlink: false,
                    }])
                } else {
                    Ok(vec![])
                }
            }
            fn classify(&self, p: &Path) -> PathKind {
                match p.to_string_lossy().as_ref() {
                    "/A" | "/A/B2" => PathKind::Dir,
                    _ => PathKind::NotFound,
                }
            }
            fn home(&self) -> Option<PathBuf> {
                Some(std::path::PathBuf::from("/A"))
            }
        }
        let mut p = FilePicker::new(
            "pick",
            None,
            Mutating {
                a_calls: Arc::new(AtomicUsize::new(0)),
            },
        );
        p.ensure_started(); // /A list #0 → [B1,B2,B3]
        // move to B2
        for _ in 0..p.ranked.len() {
            if p.selected_entry().is_some_and(|e| e.name == "B2/") {
                break;
            }
            let _ = p.on_key(press(KeyCode::Down));
        }
        let _ = p.on_key(press(KeyCode::Right)); // enter B2
        let _ = p.on_key(press(KeyCode::Left)); // back to /A → list #1 → [B9]
        assert_eq!(
            p.selected, 0,
            "remembered cursor gone from new listing → fall back to index 0"
        );
        assert_eq!(
            p.selected_entry().map(|e| e.name.clone()).as_deref(),
            Some("B9/")
        );
    }
```

- [ ] **Step 3: Run the new tests — expect RED**

```bash
cargo test --bin sshrack tui::file_picker::tests::step_into_and_back_restores_cursor 2>&1 | tail -20
cargo test --bin sshrack tui::file_picker::tests::first_visit_lands_on_first_entry 2>&1 | tail -10
```

Expected:
- `step_into_and_back_restores_cursor` → **FAIL** (current `load` resets `selected = 0`, so after going back the cursor is on `B1/`, not `B2/`). This is the load-bearing RED.
- `first_visit_lands_on_first_entry` → **PASS** already (current behavior lands first-visit at 0 too). That's fine — it pins the behavior so the restore logic can't regress it.
- `remembered_cursor_missing_falls_back_to_zero` → **PASS** already (current `selected = 0` trivially). Also a regression guard.

If the compile fails because the test name still has the space, fix the name first, then re-run.

- [ ] **Step 4: Add the `history` field + init**

Add the private field to the `FilePicker` struct (next to `started`):

```rust
    /// Per-directory cursor memory (ranger-style directory history): maps a
    /// visited dir's absolute path to the absolute path of the entry that was
    /// selected when we last left it. Snapshot/restored only inside [`load`];
    /// never persisted, discarded when the picker closes.
    history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
```

Initialize it in `new()` (next to `started: false,`):

```rust
            history: std::collections::HashMap::new(),
```

(Fully-qualified `std::collections::HashMap` matches the existing fully-qualified `std::path::PathBuf` style — no new top-level `use`.)

- [ ] **Step 5: Implement snapshot + restore inside `load()`**

Replace the body of `load()` (`src/tui/file_picker.rs:111-127`). The change is: capture the outgoing cwd + its cursor **before** `list`, remember them on the `Ok` branch, and replace the unconditional `self.selected = 0;` with a ranked-path restore:

```rust
    /// (Re)list `cwd`, reset ranking + query on success, and remember/restore
    /// the per-directory cursor (ranger-style history). Returns `true` on the
    /// `Ok` branch, `false` on `Err`. On error, leaves `cwd`/`entries`/`ranked`
    /// untouched and only sets `status`. Fs via `source`.
    ///
    /// Cursor memory: snapshots the OUTGOING dir's selected-entry path before
    /// `list` swaps `entries`, then on entry to the INCOMING dir restores the
    /// remembered cursor by locating that path in `ranked` (first visit → 0).
    /// `selected` is a ranked index, so the search is over `ranked`, not
    /// `entries`. A remembered path that no longer exists (dir changed) falls
    /// back to 0.
    fn load(&mut self, cwd: std::path::PathBuf) -> bool {
        // Snapshot against the OLD `ranked`/`entries` (before `list` swaps them).
        let prev_cwd = self.cwd.clone();
        let prev_cursor = self.selected_entry().map(|e| e.path.clone());
        match self.source.list(&cwd) {
            Ok(entries) => {
                if let (Some(prev), Some(cursor)) = (prev_cwd, prev_cursor) {
                    self.history.insert(prev, cursor);
                }
                self.cwd = Some(cwd.clone());
                self.entries = entries;
                self.query.clear();
                self.recompute();
                // Restore the incoming dir's remembered cursor by locating the
                // remembered entry path in `ranked`; first visit → 0. `selected`
                // is a ranked index, so search `ranked`, not `entries`.
                self.selected = self
                    .history
                    .get(&cwd)
                    .and_then(|p| {
                        self.ranked
                            .iter()
                            .position(|&i| self.entries.get(i).is_some_and(|e| &e.path == p))
                    })
                    .unwrap_or(0);
                self.status = None;
                true
            }
            Err(msg) => {
                self.status = Some(format!("cannot list: {msg}"));
                false
            }
        }
    }
```

Key points the implementer must preserve:
- `prev_cwd` / `prev_cursor` are captured **before** `self.source.list(...)` mutates nothing yet — they read the still-old `self.cwd` / `self.entries` / `self.ranked` / `self.selected`. Correct, because `list` only reads the fs; the swap into `self.entries` happens inside the `Ok` arm, after the capture.
- On `Err`, **do not** remember anything (we never actually left the old dir). The snapshot vars are simply dropped. Correct.
- The `self.history.insert` uses the **old** `self.cwd` (via `prev_cwd`), captured before reassignment — correct.
- The restore searches `ranked` (`self.ranked.iter().position(...)`), not `entries`, because `self.selected` indexes into `ranked`.

- [ ] **Step 6: Run — expect GREEN**

```bash
cargo test --bin sshrack tui::file_picker 2>&1 | tail -15
```

Expected: all file_picker tests pass (existing 19 + the 3 new = 22). In particular:
- `step_into_and_back_restores_cursor` → **PASS** (cursor back on `B2/`).
- `first_visit_lands_on_first_entry` → **PASS**.
- `remembered_cursor_missing_falls_back_to_zero` → **PASS**.

- [ ] **Step 7: Full workspace regression + clippy + fmt**

```bash
cargo test --workspace 2>&1 | grep -E "^test result:" | tail -10
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cargo fmt && cargo fmt --check && echo FMT_OK
```

Expected: every `test result:` line is `ok` with `0 failed`; clippy clean; `FMT_OK`.

- [ ] **Step 8: Commit**

```bash
git add src/tui/file_picker.rs
git commit -m "feat(tui): remember per-directory cursor in the file picker" -m "load() used to reset selected=0 on every directory switch, so navigating A -> B2 -> back to A landed on B1 instead of B2. Add a history: HashMap<cwd, selected-entry-path> and make load snapshot the outgoing dir's cursor before listing and restore the incoming dir's remembered cursor (by path, via ranked) after recompute. First visit still lands at 0; a remembered path missing from a changed listing falls back to 0. Query is still cleared on each load (out of scope). Adds multi_dir_tree fixture and three tests."
```

(`feat(tui)` — this is a new navigational capability, not a bug fix. No `Co-Authored-By`.)

---

## Self-Review

**1. Spec coverage:**
- "只记忆 cursor，不记忆 query" → `load` still calls `self.query.clear()`; only `selected` is remembered/restored. ✅
- "添加单元测试" → 3 tests: core restore, first-visit guard, missing-path fallback. ✅
- A → B2 → back to A lands on B2 → `step_into_and_back_restores_cursor`. ✅

**2. Placeholder scan:** No TBD/TODO. Every step has runnable code or an exact command.

**3. Type consistency:**
- Field `history: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>` (Step 4) matches the `HashMap::new()` init (Step 4) and the `self.history.insert(prev, cursor)` / `self.history.get(&cwd)` usage (Step 5). `prev` and `cursor` are both `PathBuf` (from `self.cwd.clone()` and `selected_entry().map(|e| e.path.clone())`). ✅
- Restore returns `usize` (from `position`) or `0` via `unwrap_or(0)` — matches `self.selected: usize`. ✅
- `cwd.clone()` passed to `history.get(&cwd)` after `self.cwd = Some(cwd.clone())` — `cwd` is still in scope (`PathBuf` arg, moved via `clone`). ✅

**4. Purity / invariants:**
- New logic is pure (HashMap ops + `position`); the only fs call is the pre-existing `self.source.list`. The wizard-`on_key`-is-fs-free contract is untouched (`load` was already fs-touching). ✅
- No new `unsafe` / `unwrap` / `expect` in prod code (`unwrap_or`, `is_some_and`, `and_then` only). ✅
- `sshrack-core` untouched (TUI-only). ✅
