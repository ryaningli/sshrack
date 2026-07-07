# Browser Core Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the directory-browser logic shared by `FilePicker` (single-select modal) and `Pane` (SFTP dual-pane, multi-select) into one pure `BrowserCore`, eliminating the 4 byte-identical duplicated methods (`recompute` / `clamp_selected` / `move_cursor` / `selected_entry`), the duplicated switch/history plumbing, and the `Backspace` behavior drift between the two surfaces.

**Architecture:** A new `tui::browser_core::BrowserCore` owns all per-directory browser state (cwd, entries, query, ranked, selected, marked, history) and exposes pure methods for filter/cursor/mark/dir-switch + a shared `apply_nav_key` that forces identical navigation semantics. `FilePicker` and `Pane` become thin shells that each hold a `BrowserCore`, keep their own outcome types and rendering, and delegate all shared logic. `FilePicker` switches directories atomically (`commit_switch`, sync source); `Pane` switches in two phases around an async listing (`begin_switch` + `finish_switch`). The standalone `cursor_history` module folds into `BrowserCore` (its only consumer). No compatibility shims, no dual-writes — the duplicated code is deleted, not retained.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, nucleo-matcher (via `tui::panel`/`tui::fit`), sshrack-core (`DirEntry`, `pathutil`).

## Global Constraints

Copied verbatim from the project's hard rules — every task implicitly inherits these:

- **English only** — all source, comments, doc comments, errors, help text, commit messages.
- **Zero `unsafe`** — never, including in tests.
- **Zero `unwrap()` / `expect()` in production** — only `#[cfg(test)]` or genuinely-unreachable `expect("invariant: ...")`. (Tests may use `.unwrap()`.)
- **`sshrack-core` stays zero-UI** — `BrowserCore` lives in the binary crate (`src/tui/`), NOT in core. It may use `crossterm::event::KeyEvent` (already a TUI-layer type); it must NOT pull in `ratatui`/`nucleo-matcher` directly — it calls `crate::tui::panel::rank_by_fields` / `crate::tui::fit::focus_window` (existing `pub fn`s).
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Tests are hermetic** — `cargo test --workspace` passes with `SSHRACK_PASSPHRASE` already set in the shell; never use `env -u` workarounds. `BrowserCore` methods read no env (pure); the `~`-expansion path in `Pane::on_enter` still reads `HOME` via the existing `resolve_path_like` helper, unchanged.
- **Conventional Commits** — `<type>(<scope>): <desc>`, scope `tui`. **No `Co-Authored-By` trailer.**
- **Explicit `git add <paths>`** — never `git add -A` (it sweeps in unrelated files).
- **No compat / dual-write code (dev-stage rule)** — the duplicated methods in `FilePicker` and `Pane` are DELETED, not kept beside the core. No `#[allow(dead_code)]` staging (this work connects to `main` immediately). No alias/re-export shims for the old `cursor_history` path.
- **Immutability / `&str` over `String`** at boundaries; `pub(crate)` visibility by default; domain-based module organization.

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/tui/browser_core.rs` | Pure directory-browser core: state + filter/cursor/mark/switch/nav-key | **Create** |
| `src/tui/mod.rs` | Module registration | Modify (add `browser_core`, remove `cursor_history`) |
| `src/tui/cursor_history.rs` | Standalone `remembered_cursor_index` | **Delete** (folds into `browser_core`) |
| `src/tui/transfer/pane.rs` | SFTP pane shell over `BrowserCore` | Modify (struct + delegate) |
| `src/tui/transfer/pane_tests.rs` | Pane unit tests | Modify (field-access migration) |
| `src/tui/transfer/screen.rs` | Pane consumer | Modify (field-access migration) |
| `src/tui/transfer/screen_tests.rs` | Screen tests (if they touch pane fields) | Modify (field-access migration) |
| `src/tui/run_loop.rs` | Drives pane switch (`on_step` + `cwd =` + `set_entries`) + its tests | Modify (field-access migration) |
| `src/tui/file_picker.rs` | Identity picker shell over `BrowserCore` + Backspace fix | Modify (struct + delegate + test re-anchor) |

Each file keeps one clear responsibility. `browser_core.rs` is the single source of truth for browser state; the two consumers are intentionally NOT merged (different control-flow paradigms — see Architecture).

---

## Task 1: BrowserCore base — state + shared listing operations

**Goal:** Create `BrowserCore` with its fields and the 4 currently-duplicated pure methods (plus the read-only accessors `Pane` exposes). No dir-switch or nav-key logic yet (Task 2). Nothing consumes it yet, so the binary is unchanged.

**Files:**
- Create: `src/tui/browser_core.rs`
- Modify: `src/tui/mod.rs` (add `pub(crate) mod browser_core;` in alphabetical order, after `app`/before `cred_panel` — actually between `app` and `connect`; place it as `pub(crate) mod browser_core;` immediately after `pub mod app;`)

**Interfaces:**
- Consumes: `sshrack_core::dirsource::DirEntry`; `crate::tui::panel::rank_by_fields(rows: &[Vec<String>], scores: &[f64], query: &str) -> Vec<usize>`; `crate::tui::fit::focus_window(total: usize, selected: usize, visible: usize) -> std::ops::Range<usize>`.
- Produces: `pub(crate) struct BrowserCore { cwd, entries, query, ranked, selected, marked, history, pending_restore }` and methods `new`, `recompute`, `clamp_selected`, `move_cursor`, `selected_entry`, `entry_at_rank`, `matched_count`, `visible_window`, `toggle_mark_selected`. Later tasks add `begin_switch`/`finish_switch`/`commit_switch`/`apply_nav_key`/`NavDecision`.

- [ ] **Step 1: Write the failing test for the pure operations**

Append to `src/tui/browser_core.rs` (full file content — Step 3 creates the production code; the test goes in the same file's `#[cfg(test)] mod tests`). Write the WHOLE file now with both production code and tests so the module is self-contained; the test is what we run first to drive compilation.

Write the complete file `src/tui/browser_core.rs`:

```rust
//! Shared, business-decoupled directory-browser core. Both the modal
//! [`crate::tui::file_picker::FilePicker`] (single-select) and the SFTP
//! [`crate::tui::transfer::pane::Pane`] (dual-pane, multi-select) hold one
//! `BrowserCore` and delegate navigation, fuzzy filter, mark, and
//! per-directory cursor-memory logic to it. The core is pure — no I/O, no
//! rendering, no outcome type — so the two surfaces stay in sync by
//! construction and a behavior drift (like the Backspace-as-step-up vs
//! pure-edit split that once crept in) cannot recur.
//!
//! The two consumers' real differences are honored, not papered over:
//! - `FilePicker` owns its `DirSource` and lists synchronously; it switches
//!   atomically via [`BrowserCore::commit_switch`] (Task 2).
//! - `Pane` is a passive state machine fed by the transfer screen/worker; it
//!   switches in two phases around an async listing via
//!   [`BrowserCore::begin_switch`] + [`BrowserCore::finish_switch`] (Task 2).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use sshrack_core::dirsource::DirEntry;

/// A visited-cwd → that dir's last-selected entry path (ranger-style memory).
type CursorHistory = HashMap<PathBuf, PathBuf>;

/// Pure per-directory browser state: a cwd, its current listing, a fuzzy
/// filter query, a cursor, a per-directory mark set, and a per-directory
/// cursor memory. All methods are pure (no I/O, no rendering); the component
/// owns I/O (`DirSource`) and rendering.
///
/// Field visibility: every field is `pub(crate)` so the file picker, the
/// transfer pane, and their tests reach in directly — one source of truth,
/// no accessor boilerplate. The module itself is `pub(crate)`, so external
/// crates cannot see any of this.
#[derive(Debug, Clone)]
pub(crate) struct BrowserCore {
    /// Absolute current directory.
    pub(crate) cwd: PathBuf,
    /// Current listing (real children only — dirs first, then files).
    pub(crate) entries: Vec<DirEntry>,
    /// Filter-box text. Drives fuzzy ranking via [`Self::recompute`].
    pub(crate) query: String,
    /// Indices into `entries`, fuzzy-ordered for display. Derived from
    /// `entries` + `query`.
    pub(crate) ranked: Vec<usize>,
    /// Cursor position: index into `ranked`.
    pub(crate) selected: usize,
    /// Marked paths in the CURRENT directory only. Cleared on a dir switch.
    /// Both files and directories can be marked.
    pub(crate) marked: HashSet<PathBuf>,
    /// Per-directory cursor memory (ranger-style): visited cwd → that dir's
    /// last-selected entry path.
    history: CursorHistory,
    /// Set by `begin_switch` so the next `finish_switch` restores the NEW
    /// cwd's remembered cursor instead of resetting to 0. Separates a
    /// dir-switch from an in-place refresh.
    pending_restore: bool,
}

impl BrowserCore {
    /// New core at `initial_cwd` with an empty listing. The component feeds
    /// the first listing via `commit_switch` / `finish_switch` (Task 2).
    #[must_use]
    pub(crate) fn new(initial_cwd: PathBuf) -> Self {
        Self {
            cwd: initial_cwd,
            entries: Vec::new(),
            query: String::new(),
            ranked: Vec::new(),
            selected: 0,
            marked: HashSet::new(),
            history: HashMap::new(),
            pending_restore: false,
        }
    }

    /// Re-rank `entries` for the current `query` via the shared nucleo helper
    /// (one-field rows, all-zero scores). Empty query yields every entry in
    /// its sorted order. Pure.
    pub(crate) fn recompute(&mut self) {
        let rows: Vec<Vec<String>> = self.entries.iter().map(|e| vec![e.name.clone()]).collect();
        let scores = vec![0.0f64; self.entries.len()];
        self.ranked = crate::tui::panel::rank_by_fields(&rows, &scores, &self.query);
    }

    /// Clamp the cursor into `ranked` bounds (no-op when empty). Pure.
    pub(crate) fn clamp_selected(&mut self) {
        if self.ranked.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.ranked.len() {
            self.selected = self.ranked.len() - 1;
        }
    }

    /// Move the cursor by `delta` with wrap-around. No-op when ranked empty.
    pub(crate) fn move_cursor(&mut self, delta: i32) {
        if self.ranked.is_empty() {
            return;
        }
        let n = self.ranked.len() as i32;
        self.selected = ((self.selected as i32 + delta).rem_euclid(n)) as usize;
    }

    /// The entry under the cursor, or `None` when the ranked list is empty.
    #[must_use]
    pub(crate) fn selected_entry(&self) -> Option<&DirEntry> {
        self.ranked
            .get(self.selected)
            .and_then(|&i| self.entries.get(i))
    }

    /// The entry at display position `ranked_idx`, or `None` when out of range.
    #[must_use]
    pub(crate) fn entry_at_rank(&self, ranked_idx: usize) -> Option<&DirEntry> {
        self.ranked
            .get(ranked_idx)
            .and_then(|&i| self.entries.get(i))
    }

    /// Number of entries surviving the filter (`ranked.len()`).
    #[must_use]
    pub(crate) fn matched_count(&self) -> usize {
        self.ranked.len()
    }

    /// Range of `ranked` indices to render for a viewport of `rows` rows.
    #[must_use]
    pub(crate) fn visible_window(&self, rows: usize) -> std::ops::Range<usize> {
        crate::tui::fit::focus_window(self.ranked.len(), self.selected, rows)
    }

    /// Toggle the mark on the cursor entry. Returns `Some(path)` when a mark
    /// changed, `None` when the cursor is empty. Mutates `marked`.
    pub(crate) fn toggle_mark_selected(&mut self) -> Option<PathBuf> {
        let entry = self.selected_entry()?;
        let path = entry.path.clone();
        if !self.marked.insert(path.clone()) {
            self.marked.remove(&path);
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn entry(name: &str, parent: &Path, is_dir: bool) -> DirEntry {
        let decorated = if is_dir { format!("{name}/") } else { name.to_string() };
        DirEntry {
            name: decorated,
            path: parent.join(name),
            is_dir,
            is_symlink: false,
            size: None,
            modified: None,
        }
    }

    fn core_with(cwd: &str, names: &[(&str, bool)]) -> BrowserCore {
        let cwd = PathBuf::from(cwd);
        let entries: Vec<DirEntry> = names
            .iter()
            .map(|(n, d)| entry(n, &cwd, *d))
            .collect();
        let mut c = BrowserCore::new(cwd);
        c.entries = entries;
        c.recompute();
        c
    }

    #[test]
    fn recompute_empty_query_keeps_all_in_entries_order() {
        let c = core_with("/x", &[("a", false), ("b", false)]);
        assert_eq!(c.matched_count(), 2);
        assert_eq!(c.entry_at_rank(0).map(|e| e.name.as_str()), Some("a"));
        assert_eq!(c.entry_at_rank(1).map(|e| e.name.as_str()), Some("b"));
    }

    #[test]
    fn recompute_query_filters_to_matches() {
        let mut c = core_with("/x", &[("id_ed25519", false), ("id_rsa", false), ("notes", false)]);
        c.query = "id".to_string();
        c.recompute();
        assert_eq!(c.matched_count(), 2, "only the two id_* entries match");
    }

    #[test]
    fn move_cursor_wraps_around() {
        let mut c = core_with("/x", &[("a", false), ("b", false), ("c", false)]);
        assert_eq!(c.selected, 0);
        c.move_cursor(-1); // wrap top -> bottom
        assert_eq!(c.selected, 2);
        c.move_cursor(1); // wrap bottom -> top
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn move_cursor_noop_on_empty_ranked() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        c.move_cursor(5); // no panic, no change
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn clamp_selected_drops_back_into_bounds() {
        let mut c = core_with("/x", &[("a", false)]);
        c.selected = 99;
        c.clamp_selected();
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn clamp_selected_empty_resets_to_zero() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        c.selected = 5;
        c.clamp_selected();
        assert_eq!(c.selected, 0);
    }

    #[test]
    fn toggle_mark_selected_round_trips() {
        let mut c = core_with("/x", &[("a", false)]);
        let p = c.toggle_mark_selected().expect("cursor on an entry");
        assert!(c.marked.contains(&p), "first toggle marks");
        let _ = c.toggle_mark_selected();
        assert!(c.marked.is_empty(), "second toggle unmarks");
    }

    #[test]
    fn toggle_mark_selected_none_on_empty_listing() {
        let mut c = BrowserCore::new(PathBuf::from("/x"));
        assert!(c.toggle_mark_selected().is_none());
    }

    #[test]
    fn visible_window_delegates_to_focus_window() {
        let c = core_with("/x", &[("a", false), ("b", false), ("c", false)]);
        let win = c.visible_window(2);
        assert_eq!(win.end - win.start <= 2, true);
    }
}
```

- [ ] **Step 2: Register the module and run the test to confirm it fails (module missing → compile error)**

In `src/tui/mod.rs`, add (alphabetical: after `pub mod app;`):

```rust
pub(crate) mod browser_core;
```

Run: `cargo test browser_core --no-run`
Expected: FAILS to compile until the file from Step 1 exists. After creating it: `cargo test browser_core`

- [ ] **Step 3: Verify the production code compiles and tests pass**

Run: `cargo test browser_core`
Expected: 9 tests pass (`recompute_empty_query_keeps_all_in_entries_order`, …, `visible_window_delegates_to_focus_window`).

- [ ] **Step 4: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Run: `cargo fmt`
Expected: both green. (The new module is unused by the binary yet, but it is `#[cfg(test)]`-exercised, so clippy will not flag it dead — the test fns reach every method.)

- [ ] **Step 5: Commit**

```bash
git add src/tui/browser_core.rs src/tui/mod.rs
git commit -m "refactor(tui): extract BrowserCore base with shared listing ops"
```

---

## Task 2: BrowserCore dir-switch protocol + nav-key decision (fold in cursor_history)

**Goal:** Add the directory-switch protocol (`begin_switch`/`finish_switch`/`commit_switch`) and the shared `apply_nav_key` + `NavDecision`, and fold the standalone `cursor_history::remembered_cursor_index` into `browser_core` (its only consumer after this task). `Backspace` is forced to pure-edit (noop on empty query) for BOTH future consumers — this is the drift fix.

**Files:**
- Modify: `src/tui/browser_core.rs` (add switch methods, `apply_nav_key`, `NavDecision`, the migrated `remembered_cursor_index`)
- Modify: `src/tui/mod.rs` (remove `pub(crate) mod cursor_history;`)
- Delete: `src/tui/cursor_history.rs`

**Interfaces:**
- Consumes: `crossterm::event::{KeyCode, KeyEvent, KeyModifiers}`; the `BrowserCore` from Task 1.
- Produces:
  - `pub(crate) enum NavDecision { CursorMoved, QueryChanged, StepUp, Noop }`
  - `BrowserCore::begin_switch(&mut self)`, `finish_switch(&mut self, entries: Vec<DirEntry>)`, `commit_switch(&mut self, new_cwd: PathBuf, entries: Vec<DirEntry>)`
  - `BrowserCore::apply_nav_key(&mut self, key: KeyEvent) -> Option<NavDecision>`
  - private `fn remembered_cursor_index(history, cwd, ranked, entries) -> usize` (migrated)

- [ ] **Step 1: Write the failing tests for switch protocol + nav decisions**

Add these tests to the `#[cfg(test)] mod tests` block in `src/tui/browser_core.rs`:

```rust
    // ---- dir-switch protocol ----

    #[test]
    fn commit_switch_first_visit_lands_on_zero() {
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/x"),
            vec![entry("a", Path::new("/x"), false), entry("b", Path::new("/x"), false)],
        );
        assert_eq!(c.cwd, PathBuf::from("/x"));
        assert_eq!(c.selected, 0, "first visit → cursor 0");
        assert_eq!(c.matched_count(), 2);
    }

    #[test]
    fn begin_then_finish_restores_remembered_cursor() {
        // Enter /x, move to "b", leave; come back — cursor should land on "b".
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/x"),
            vec![entry("a", Path::new("/x"), false), entry("b", Path::new("/x"), false)],
        );
        c.move_cursor(1); // cursor on "b"
        // leave /x for /y
        c.begin_switch();
        c.cwd = PathBuf::from("/y");
        c.finish_switch(vec![entry("c", Path::new("/y"), false)]);
        // come back to /x
        c.begin_switch();
        c.cwd = PathBuf::from("/x");
        c.finish_switch(vec![entry("a", Path::new("/x"), false), entry("b", Path::new("/x"), false)]);
        assert_eq!(
            c.selected_entry().map(|e| e.name.as_str()),
            Some("b"),
            "remembered cursor restored on re-entry"
        );
    }

    #[test]
    fn begin_switch_clears_marks_query_and_selected() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        c.move_cursor(1);
        let _ = c.toggle_mark_selected();
        c.query = "abc".to_string();
        c.begin_switch();
        assert!(c.marked.is_empty(), "marks cleared on switch");
        assert!(c.query.is_empty(), "query cleared on switch");
        assert_eq!(c.selected, 0, "selected reset on switch");
    }

    #[test]
    fn commit_switch_records_parent_cursor_so_going_up_lands_on_child() {
        // Commit into /tmp/sftp-test; then begin+finish back into /tmp should
        // land the cursor on sftp-test (the child we just entered).
        let mut c = BrowserCore::new(PathBuf::from("/"));
        c.commit_switch(
            PathBuf::from("/tmp"),
            vec![
                entry("aaa", Path::new("/tmp"), true),
                entry("sftp-test", Path::new("/tmp"), true),
                entry("zzz", Path::new("/tmp"), false),
            ],
        );
        c.commit_switch(
            PathBuf::from("/tmp/sftp-test"),
            vec![entry("file", Path::new("/tmp/sftp-test"), false)],
        );
        // go back up to /tmp
        c.begin_switch();
        c.cwd = PathBuf::from("/tmp");
        c.finish_switch(vec![
            entry("aaa", Path::new("/tmp"), true),
            entry("sftp-test", Path::new("/tmp"), true),
            entry("zzz", Path::new("/tmp"), false),
        ]);
        assert_eq!(
            c.selected_entry().map(|e| e.path.as_path()),
            Some(std::path::Path::new("/tmp/sftp-test")),
            "going back up lands on the dir we just entered"
        );
    }

    #[test]
    fn finish_switch_in_place_refresh_resets_cursor_when_not_pending() {
        // finish_switch without a preceding begin_switch is an in-place refresh:
        // cursor resets to 0.
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        c.move_cursor(1);
        assert_eq!(c.pending_restore, false);
        c.finish_switch(vec![
            entry("a", Path::new("/x"), false),
            entry("b", Path::new("/x"), false),
        ]);
        assert_eq!(c.selected, 0, "in-place refresh resets cursor");
    }

    // ---- apply_nav_key ----

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::EMPTY,
        }
    }

    #[test]
    fn nav_backspace_on_empty_query_is_noop_never_step_up() {
        // The drift fix: empty-query Backspace must NOT be StepUp. It is Noop.
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Backspace)).expect("handled");
        assert_eq!(d, super::NavDecision::Noop);
        assert_eq!(c.cwd, PathBuf::from("/x"), "cwd unchanged by Backspace");
    }

    #[test]
    fn nav_backspace_pops_query_char() {
        let mut c = core_with("/x", &[("a", false)]);
        c.query = "ab".to_string();
        let d = c.apply_nav_key(key(KeyCode::Backspace)).expect("handled");
        assert_eq!(d, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "a");
    }

    #[test]
    fn nav_left_requests_step_up_without_moving_cwd() {
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Left)).expect("handled");
        assert_eq!(d, super::NavDecision::StepUp);
        assert_eq!(c.cwd, PathBuf::from("/x"), "Left does not move cwd itself");
    }

    #[test]
    fn nav_arrows_move_cursor() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        let d = c.apply_nav_key(key(KeyCode::Down)).expect("handled");
        assert_eq!(d, super::NavDecision::CursorMoved);
        assert_eq!(c.selected, 1);
    }

    #[test]
    fn nav_ctrl_p_n_move_cursor() {
        let mut c = core_with("/x", &[("a", false), ("b", false)]);
        let pn = KeyEvent {
            code: KeyCode::Char('n'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::EMPTY,
        };
        let d = c.apply_nav_key(pn).expect("handled");
        assert_eq!(d, super::NavDecision::CursorMoved);
        assert_eq!(c.selected, 1);
    }

    #[test]
    fn nav_printable_char_appends_to_query_including_space() {
        let mut c = core_with("/x", &[("a", false)]);
        let d = c.apply_nav_key(key(KeyCode::Char('z'))).expect("handled");
        assert_eq!(d, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "z");
        // Space is a query char here; Pane intercepts it earlier for marks.
        let d2 = c.apply_nav_key(key(KeyCode::Char(' '))).expect("handled");
        assert_eq!(d2, super::NavDecision::QueryChanged);
        assert_eq!(c.query, "z ");
    }

    #[test]
    fn nav_enter_right_escape_are_not_handled() {
        let mut c = core_with("/x", &[("a", false)]);
        assert!(c.apply_nav_key(key(KeyCode::Enter)).is_none());
        assert!(c.apply_nav_key(key(KeyCode::Right)).is_none());
        assert!(c.apply_nav_key(key(KeyCode::Esc)).is_none());
    }
```

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `cargo test browser_core`
Expected: FAIL — `NavDecision` / `begin_switch` / `commit_switch` / `apply_nav_key` not defined.

- [ ] **Step 3: Implement the switch protocol + nav decision + migrate cursor_history**

In `src/tui/browser_core.rs`:

(a) Add to the imports at the top:
```rust
use std::path::{Path, PathBuf};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
```
(merge into the existing `use std::path::PathBuf;` → `use std::path::{Path, PathBuf};`, and add the crossterm import)

(b) Add the `NavDecision` enum above `BrowserCore`:
```rust
/// Neutral result of [`BrowserCore::apply_nav_key`] for the unambiguous
/// navigation/edit keys (arrows, Ctrl-P/N, Left, Backspace, printable chars
/// incl. Space). The component translates it into its own outcome. Keys NOT
/// owned here — `Enter`/`Right` (activation, component-specific), `Space`
/// (`Pane` marks vs `FilePicker` query char — `Pane` intercepts it earlier),
/// `Esc`/`Ctrl-C` (cancel) — yield `None` so the component keeps full control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NavDecision {
    /// Up/Down/Ctrl-P/N moved the cursor (`selected` already mutated).
    CursorMoved,
    /// A printable char was appended or Backspace popped one (`query` + rank
    /// already mutated).
    QueryChanged,
    /// `Left` requested the parent directory. Core did NOT move; the component
    /// decides (and may no-op at `/`).
    StepUp,
    /// Backspace on an empty query — a deliberate no-op (pure-edit semantics).
    Noop,
}
```

(c) Add these methods inside `impl BrowserCore` (after `toggle_mark_selected`):
```rust
    /// Phase 1 of the async two-phase switch (e.g. remote SFTP): snapshot the
    /// OUTGOING cwd's cursor into history, clear marks/query/selected, and arm
    /// `pending_restore`. The caller then sets `cwd` to the new path, fetches
    /// the listing, and calls [`Self::finish_switch`]. Pure.
    pub(crate) fn begin_switch(&mut self) {
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.marked.clear();
        self.query.clear();
        self.selected = 0;
        self.pending_restore = true;
    }

    /// Phase 2 of the async switch: adopt `entries` for the CURRENT `cwd` (set
    /// by the caller between phase 1 and here), re-rank, and restore the
    /// remembered cursor (dir switch — `pending_restore`) or reset to 0
    /// (in-place refresh). Also records the parent's cursor as this cwd so
    /// going back up lands on the child. Pure.
    pub(crate) fn finish_switch(&mut self, entries: Vec<DirEntry>) {
        self.entries = entries;
        self.recompute();
        if self.pending_restore {
            self.selected = remembered_cursor_index(
                &self.history,
                &self.cwd,
                &self.ranked,
                &self.entries,
            );
            if let Some(parent) = self.cwd.parent() {
                self.history.insert(parent.to_path_buf(), self.cwd.clone());
            }
            self.pending_restore = false;
        } else {
            self.selected = 0;
        }
    }

    /// Atomic switch for synchronous sources (e.g. local fs): snapshot
    /// outgoing, set `new_cwd` + entries, restore incoming — all in one call.
    /// A listing failure can simply skip this call and leave the previous
    /// view intact (snapshot happens before `entries` are replaced). Pure.
    pub(crate) fn commit_switch(&mut self, new_cwd: PathBuf, entries: Vec<DirEntry>) {
        if let Some(cursor) = self.selected_entry().map(|e| e.path.clone()) {
            self.history.insert(self.cwd.clone(), cursor);
        }
        self.cwd = new_cwd;
        self.entries = entries;
        self.query.clear();
        self.marked.clear();
        self.recompute();
        self.selected =
            remembered_cursor_index(&self.history, &self.cwd, &self.ranked, &self.entries);
        if let Some(parent) = self.cwd.parent() {
            self.history.insert(parent.to_path_buf(), self.cwd.clone());
        }
    }

    /// Apply one unambiguous navigation/edit key and return the decision for
    /// the component to translate. Returns `None` for keys it does NOT own
    /// (`Enter`, `Right`, `Esc`, `Ctrl-C`, non-Press) so the component keeps
    /// full control over activation/cancel semantics. `Space` IS appended to
    /// the query here — `Pane` intercepts it earlier for mark-toggle.
    pub(crate) fn apply_nav_key(&mut self, key: KeyEvent) -> Option<NavDecision> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Up => {
                self.move_cursor(-1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Down => {
                self.move_cursor(1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Char('p') if ctrl => {
                self.move_cursor(-1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Char('n') if ctrl => {
                self.move_cursor(1);
                Some(NavDecision::CursorMoved)
            }
            KeyCode::Left => Some(NavDecision::StepUp),
            KeyCode::Backspace => {
                // Pure edit: pop a query char, or no-op when empty. NEVER
                // step up — going up uses Left. Keeps both browsers identical
                // (fixes the drift where FilePicker stepped up on empty
                // Backspace).
                if self.query.is_empty() {
                    Some(NavDecision::Noop)
                } else {
                    self.query.pop();
                    self.recompute();
                    self.clamp_selected();
                    Some(NavDecision::QueryChanged)
                }
            }
            KeyCode::Char(c) if !ctrl => {
                self.query.push(c);
                self.recompute();
                self.selected = 0;
                Some(NavDecision::QueryChanged)
            }
            _ => None,
        }
    }
```

(d) Add the migrated free function at the bottom of the file (above `#[cfg(test)]`):
```rust
/// Return the ranked-list index of the entry `history` remembers for `cwd`,
/// or `0` when nothing is remembered or the remembered path is gone from the
/// listing. Pure. (Migrated from the former standalone `cursor_history`
/// module — `BrowserCore` is now its only consumer.)
#[must_use]
fn remembered_cursor_index(
    history: &CursorHistory,
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

- [ ] **Step 4: Delete `cursor_history` and drop its registration**

Delete the file: `src/tui/cursor_history.rs`
In `src/tui/mod.rs` remove the line `pub(crate) mod cursor_history;`.

(The two call sites `crate::tui::cursor_history::remembered_cursor_index(...)` in `file_picker.rs` and `transfer/pane.rs` are rewritten in Tasks 3 and 4 — but until then the crate will not compile. That is expected; Task 3 lands next and restores compilation. Do NOT add a temporary re-export.)

- [ ] **Step 5: Run the core tests**

Run: `cargo test browser_core`
Expected: all Task-1 tests + the new switch/nav tests pass (18 total).

- [ ] **Step 6: Commit (crate does not yet build end-to-end — that is intentional; Task 3 reconnects the consumers)**

```bash
git add src/tui/browser_core.rs src/tui/mod.rs src/tui/cursor_history.rs
git commit -m "refactor(tui): unify dir-switch + nav decisions in BrowserCore"
```

(Note: `git add src/tui/cursor_history.rs` stages the deletion.)

---

## Task 3: Reduce `Pane` to a `BrowserCore` shell

**Goal:** `Pane` becomes `{ core: BrowserCore, loading: bool }`. Its public API (`new`/`on_key`/`on_step`/`set_entries`/`selected_entry`/`entry_at_rank`/`matched_count`/`visible_window` and the `PaneOutcome` enum) is UNCHANGED so `screen.rs`/`run_loop.rs` keep working modulo field-access migration. The duplicated `recompute`/`clamp_selected`/`move_cursor`/`selected_entry`/`resolve_path_like`-internal + the `history`/`pending_restore` fields are DELETED.

**Files:**
- Modify: `src/tui/transfer/pane.rs`
- Modify: `src/tui/transfer/pane_tests.rs`
- Modify: `src/tui/transfer/screen.rs`
- Modify: `src/tui/transfer/screen_tests.rs` (only if it touches `pane.{cwd,entries,query,selected,marked}` — grep first)
- Modify: `src/tui/run_loop.rs`

**Interfaces:**
- Consumes: `BrowserCore`, `NavDecision` from Task 2.
- Produces: `Pane { pub(crate) core: BrowserCore, pub loading: bool }` with the same public method set + `PaneOutcome` unchanged.

- [ ] **Step 1: Rewrite `src/tui/transfer/pane.rs`**

Replace the entire file body. Keep the module doc comment (update it to say the pane delegates to `BrowserCore`). The new file:

```rust
//! One side of the dual-pane transfer screen (`sshrack sftp`). A [`Pane`] is
//! now a thin shell over [`crate::tui::browser_core::BrowserCore`]: it owns
//! the SFTP-specific `loading` flag and the transfer-specific outcome
//! semantics, and delegates all navigation / fuzzy filter / mark /
//! cursor-memory logic to the core it shares with [`crate::tui::file_picker`].
//! That shared core is what keeps the two browsers' navigation identical.
//!
//! Mark scope: marks belong to the CURRENT directory only. The screen calls
//! [`Pane::on_step`] right before [`Pane::set_entries`] when stepping into or
//! out of a directory; the core clears marks (and the query and cursor) on
//! `begin_switch` so a stale mark never survives a directory change.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use sshrack_core::dirsource::DirEntry;
use sshrack_core::pathutil::{expand_tilde, parse_filter_intent, FilterIntent};

use crate::tui::browser_core::{BrowserCore, NavDecision};

/// Which side of the transfer screen a [`Pane`] drives. Pure label — the pane
/// does not branch on it; the screen renders each side differently and routes
/// side effects (local: inline list; remote: worker List) by side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

/// Pure intent returned by [`Pane::on_key`]. The pane mutates only its own
/// core state; this intent tells the screen what side effect to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneOutcome {
    /// The key was consumed but no side effect is needed.
    None,
    /// The filter query changed — re-render the search box.
    QueryChanged,
    /// The cursor entry is a directory; the screen lists it. Carries the
    /// absolute dir path.
    StepInto(PathBuf),
    /// The user asked to go to the parent directory. Emitted only when `cwd`
    /// has a parent.
    StepUp,
    /// A file (or directory) was activated with `Enter`/`Right` — reserved
    /// for transfer enqueue at screen level.
    ActivateSelected,
    /// The user toggled the mark on `path` (file or dir).
    ToggleMark(PathBuf),
    /// A path-like query was resolved to an absolute directory path; the
    /// screen lists it. `~` with no `HOME` emits `None`.
    RequestList(PathBuf),
}

/// One side of the dual-pane transfer screen: a [`BrowserCore`] plus the
/// SFTP-specific `loading` flag. Pure — no I/O. The screen feeds entries via
/// [`Pane::set_entries`]; the pane never lists on its own.
#[derive(Debug, Clone)]
pub struct Pane {
    /// Shared browser state (cwd, entries, query, cursor, marks, history).
    pub(crate) core: BrowserCore,
    /// Pending-list indicator the screen toggles around `set_entries`.
    /// Render-only; the pane never mutates it.
    pub loading: bool,
}

impl Pane {
    /// Open a pane at `cwd` with an empty listing. The screen feeds the first
    /// listing via [`Pane::set_entries`]. Pure: no I/O.
    #[must_use]
    pub fn new(cwd: PathBuf) -> Self {
        Self {
            core: BrowserCore::new(cwd),
            loading: false,
        }
    }

    /// Replace the listing and finish a dir-switch (the screen called
    /// [`Pane::on_step`] first) or an in-place refresh. Delegates to
    /// [`BrowserCore::finish_switch`]. Pure: no I/O.
    pub fn set_entries(&mut self, entries: Vec<DirEntry>) {
        self.core.finish_switch(entries);
    }

    /// Begin a directory switch: snapshot the outgoing cursor, clear
    /// marks/query/selected. The screen calls this right before it updates
    /// `core.cwd` and fetches the new listing. Pure.
    pub fn on_step(&mut self) {
        self.core.begin_switch();
    }

    /// Pure key handler. Mutates only the core and returns the side effect the
    /// screen should perform. Performs no I/O and reads no env except `HOME`
    /// (for `~`-expansion of a path-like `Enter`). `Space` is intercepted here
    /// for mark-toggle (before the core, which would otherwise append it to
    /// the query).
    pub fn on_key(&mut self, key: KeyEvent) -> PaneOutcome {
        if key.kind != KeyEventKind::Press {
            return PaneOutcome::None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Space → toggle mark (Pane-specific). Must precede apply_nav_key,
        // which treats Space as a query char.
        if key.code == KeyCode::Char(' ') && !ctrl {
            return match self.core.toggle_mark_selected() {
                Some(path) => PaneOutcome::ToggleMark(path),
                None => PaneOutcome::None,
            };
        }
        if let Some(decision) = self.core.apply_nav_key(key) {
            return match decision {
                NavDecision::CursorMoved | NavDecision::Noop => PaneOutcome::None,
                NavDecision::QueryChanged => PaneOutcome::QueryChanged,
                NavDecision::StepUp => self.step_up_intent(),
            };
        }
        // Unhandled by the core: Enter / Right (activation, component-specific).
        match key.code {
            KeyCode::Right => self.activate_or_step(),
            KeyCode::Enter => self.on_enter(),
            _ => PaneOutcome::None,
        }
    }

    /// Range of `ranked` indices to render for a viewport of `rows` rows.
    #[must_use]
    pub fn visible_window(&self, rows: usize) -> std::ops::Range<usize> {
        self.core.visible_window(rows)
    }

    /// The entry under the cursor, or `None`.
    #[must_use]
    pub fn selected_entry(&self) -> Option<&DirEntry> {
        self.core.selected_entry()
    }

    /// The number of entries currently surviving the filter.
    #[must_use]
    pub fn matched_count(&self) -> usize {
        self.core.matched_count()
    }

    /// The entry at display position `ranked_idx`.
    #[must_use]
    pub fn entry_at_rank(&self, ranked_idx: usize) -> Option<&DirEntry> {
        self.core.entry_at_rank(ranked_idx)
    }

    /// `Right` / `Enter`-on-fuzzy activation: dirs → [`StepInto`](PaneOutcome::StepInto),
    /// files → [`ActivateSelected`](PaneOutcome::ActivateSelected). Empty cursor → `None`.
    fn activate_or_step(&mut self) -> PaneOutcome {
        match self.core.selected_entry() {
            Some(e) if e.is_dir => PaneOutcome::StepInto(e.path.clone()),
            Some(_) => PaneOutcome::ActivateSelected,
            None => PaneOutcome::None,
        }
    }

    /// `Enter`: a path-like query resolves via [`resolve_path_like`] →
    /// [`RequestList`](PaneOutcome::RequestList); a fuzzy query activates the
    /// cursor entry. Pure except `HOME` lookup for `~`.
    fn on_enter(&mut self) -> PaneOutcome {
        match parse_filter_intent(&self.core.query) {
            FilterIntent::PathLike(raw) => match resolve_path_like(&raw, &self.core.cwd) {
                Some(abs) => PaneOutcome::RequestList(abs),
                None => PaneOutcome::None,
            },
            FilterIntent::Fuzzy(_) => self.activate_or_step(),
        }
    }

    /// `Left`: emit [`StepUp`](PaneOutcome::StepUp) when `cwd` has a parent,
    /// [`None`](PaneOutcome::None) at `/`.
    fn step_up_intent(&self) -> PaneOutcome {
        if self.core.cwd.parent().is_some() {
            PaneOutcome::StepUp
        } else {
            PaneOutcome::None
        }
    }
}

/// Resolve a path-like filter string against `cwd` to an absolute path. Pure
/// except for the `HOME` lookup, which only runs for `~`-prefixed inputs.
fn resolve_path_like(raw: &str, cwd: &Path) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.starts_with('~') {
        let home = std::env::var_os("HOME").map(PathBuf::from)?;
        Some(expand_tilde(trimmed, &home))
    } else if Path::new(trimmed).is_absolute() {
        Some(PathBuf::from(trimmed))
    } else {
        Some(cwd.join(trimmed))
    }
}

// Per-pane unit tests live in a sibling file via `#[path]` so this module
// stays under the 800-line guideline.
#[cfg(test)]
#[path = "pane_tests.rs"]
mod tests;
```

- [ ] **Step 2: Migrate field access in `src/tui/transfer/pane_tests.rs`**

The tests reach Pane fields directly. Apply these mechanical replacements (the test bodies are otherwise unchanged — same assertions, same behavior):

- `p.cwd` → `p.core.cwd` (incl. `p.cwd = x` → `p.core.cwd = x` and `p.cwd.clone()` → `p.core.cwd.clone()`)
- `p.entries` → `p.core.entries`
- `p.query` → `p.core.query` (incl. `p.query = "..."` → `p.core.query = "..."`)
- `p.selected` → `p.core.selected`
- `p.marked` → `p.core.marked`
- `p.ranked` → `p.core.ranked`
- `p.history` → `p.core.history`

Method calls (`p.on_key(...)`, `p.set_entries(...)`, `p.on_step()`, `p.selected_entry()`, `p.matched_count()`) stay unchanged. The helper `entry(name, parent, is_dir)` and `Pane::new(...)` calls stay unchanged.

Then run: `cargo test --test '' 2>/dev/null; cargo test transfer::pane`
Expected: all existing pane tests pass (behavior is preserved — this is a pure refactor). If a test referenced the old private `pending_restore`/`history` by a now-different path, fix it to `p.core.pending_restore` / `p.core.history` (both are `pub(crate)`).

- [ ] **Step 3: Migrate field access in `src/tui/transfer/screen.rs`**

Apply:
- `self.local.cwd` → `self.local.core.cwd` (lines ~288, ~322)
- `self.remote.cwd` → `self.remote.core.cwd` (lines ~289, ~321)
- `src.marked` → `src.core.marked` (lines ~331, ~333)
- `src.entries` → `src.core.entries` (line ~332)
- `self.focused_pane_mut().marked.clear()` → `self.focused_pane_mut().core.marked.clear()` (line ~355)

Method calls (`src.selected_entry()`, `self.focused_pane()`, `self.focused_pane_mut()`, `self.local.on_key(...)`) stay unchanged. The `Side`/`Pane`/`PaneOutcome` imports stay unchanged.

- [ ] **Step 4: Migrate field access in `src/tui/transfer/screen_tests.rs` (if any) and `src/tui/run_loop.rs`**

First grep to find every remaining site:
```bash
rg -n "screen\.(local|remote)\.(cwd|entries|query|selected|marked)\b|\.local\.(cwd|entries|query|selected|marked)\b|\.remote\.(cwd|entries|query|selected|marked)\b" src/tui/transfer/screen_tests.rs src/tui/run_loop.rs
```
For each hit, insert `.core` before the field name. Known sites in `run_loop.rs`:
- `screen.local.cwd = path.clone();` → `screen.local.core.cwd = path.clone();` (~477)
- `screen.remote.cwd = path.clone();` → `screen.remote.core.cwd = path.clone();` (~498)
- `screen.remote.cwd == cwd` → `screen.remote.core.cwd == cwd` (~525)
- `s.local.cwd.clone()` → `s.local.core.cwd.clone()` (~603)
- `s.remote.cwd.clone()` → `s.remote.core.cwd.clone()` (~617)
- Test (~886–916): `screen.remote.query = "stale"` → `screen.remote.core.query = "stale"`; `.marked` → `.core.marked`; `.query.is_empty()` → `.core.query.is_empty()`; `.marked.len()`/`.marked.is_empty()` → `.core.marked...`; `.cwd` → `.core.cwd`.

The `on_step()` / `set_entries()` / `on_key()` / `local_mut()` / `remote_mut()` method calls stay unchanged.

- [ ] **Step 5: Build + run the full transfer test suite**

Run: `cargo test transfer`
Expected: all transfer tests (pane + screen + queue_overlay) pass. The crate now compiles end-to-end again (Task 2's broken intermediate state is resolved).

- [ ] **Step 6: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add src/tui/transfer/pane.rs src/tui/transfer/pane_tests.rs src/tui/transfer/screen.rs src/tui/transfer/screen_tests.rs src/tui/run_loop.rs
git commit -m "refactor(tui): reduce Pane to a BrowserCore shell"
```

---

## Task 4: Reduce `FilePicker` to a `BrowserCore` shell + align Backspace

**Goal:** `FilePicker` becomes a thin shell over `BrowserCore`. It keeps its own `DirSource`, `FilePickerOutcome`, popup rendering, and `started`/`status` lifecycle. The duplicated `recompute`/`clamp_selected`/`move_cursor`/`selected_entry` + the `history` field + the `cwd: Option<PathBuf>` are DELETED. `Backspace` now matches `Pane` (pure edit — noop on empty query) via the shared `apply_nav_key`. This is the user-visible drift fix.

**Files:**
- Modify: `src/tui/file_picker.rs`
- (No change to `src/tui/wizard/host.rs` or `src/tui/wizard/cred.rs`: they consume only `FilePicker::new` / `on_key` / `draw_overlay` / `FilePickerOutcome`, never fields.)

**Interfaces:**
- Consumes: `BrowserCore`, `NavDecision` from Task 2; `DirSource`, `LocalDirSource`, `DirEntry`; `pathutil::{FilterIntent, parse_filter_intent, ResolvedPath, start_candidates}`.
- Produces: `FilePicker<S> { title, source, candidates, core: BrowserCore, status: Option<String>, started: bool }` with the same public API (`new`, `ensure_started`, `on_key`, `draw_overlay`, `VISIBLE_ROWS`, `FilePickerOutcome`).

- [ ] **Step 1: Re-anchor the Backspace test (the drift fix)**

In `src/tui/file_picker.rs` test module, REPLACE the test `backspace_on_empty_query_steps_up` (which asserted Backspace steps up) with its inverted counterpart:

```rust
    #[test]
    fn backspace_on_empty_query_is_a_noop_never_step_up() {
        // Drift fix: empty-query Backspace is a pure no-op. It must NOT step
        // up to the parent (going up uses Left). Matches the transfer Pane
        // via the shared BrowserCore::apply_nav_key.
        let mut p = FilePicker::new("pick", Some("/h/.ssh/k"), tree());
        p.ensure_started();
        let cwd_before = p.core.cwd.clone();
        let _ = p.on_key(press(KeyCode::Backspace));
        assert_eq!(p.core.cwd, cwd_before, "Backspace did not change cwd");
        assert!(p.core.query.is_empty(), "query still empty");
    }
```

Keep `backspace_on_query_pops_a_char` as-is (it asserts `p.query == "i"` — migrate the field read to `p.core.query`).

- [ ] **Step 2: Re-anchor the failure-retry test to the new `started` semantics**

In `ensure_started_retries_after_initial_list_failure`, the assertions `p.cwd.is_none()` / `p.cwd.is_some()` no longer apply (core always has a cwd). Replace those TWO lines with the `started` flag (which the test already checks). Concretely, remove:
```rust
        assert!(p.cwd.is_none(), "cwd stays None on failure");
```
and
```rust
        assert!(p.cwd.is_some(), "cwd populated on retry");
```
Keep the `!p.started` / `p.started` / `p.status.is_some()` / `p.entries.iter().any(...)` assertions (migrating `p.entries` → `p.core.entries`).

- [ ] **Step 3: Rewrite the `FilePicker` production code**

Replace the `FilePicker` struct + its `impl` block (lines ~32–446 of the current file) with the shell. Keep the module doc comment (update it to mention delegation to `BrowserCore`). The new struct + impl:

```rust
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use std::path::PathBuf;

use sshrack_core::dirsource::{DirSource, LocalDirSource};
use sshrack_core::pathutil::{
    parse_filter_intent, start_candidates, FilterIntent, ResolvedPath,
};

use crate::tui::browser_core::{BrowserCore, NavDecision};

/// The pure result of [`FilePicker::on_key`]. `Pick` carries an absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePickerOutcome {
    Pick(std::path::PathBuf),
    Cancel,
    Pending,
}

/// Modal file picker, generic over [`DirSource`]. A thin shell over
/// [`BrowserCore`]: it owns the `DirSource`, the popup rendering, and the
/// `started`/`status` lifecycle, and delegates navigation/filter/cursor
/// memory to the core it shares with the transfer `Pane`.
#[derive(Clone)]
pub struct FilePicker<S: DirSource + Clone = LocalDirSource> {
    title: &'static str,
    source: S,
    candidates: Vec<String>,
    core: BrowserCore,
    status: Option<String>,
    started: bool,
}

impl<S: DirSource + Clone> FilePicker<S> {
    pub const VISIBLE_ROWS: usize = 16;

    /// Open a picker. `identity_hint` seeds the start-directory candidates. NO
    /// filesystem access — the first listing is lazy ([`ensure_started`]). The
    /// core starts as an empty shell at `/` until the first successful list.
    #[must_use]
    pub fn new(title: &'static str, identity_hint: Option<&str>, source: S) -> Self {
        Self {
            title,
            source,
            candidates: start_candidates(identity_hint),
            core: BrowserCore::new(PathBuf::from("/")),
            status: None,
            started: false,
        }
    }

    /// Lazily resolve the start directory and list it. Idempotent once it
    /// succeeds. On an initial list failure `started` stays `false` so the
    /// next call retries.
    pub fn ensure_started(&mut self) {
        if self.started {
            return;
        }
        let cwd = self
            .source
            .resolve_start(&self.candidates)
            .unwrap_or_else(|| PathBuf::from("/"));
        if self.load(cwd) {
            self.started = true;
        }
    }

    /// (Re)list `cwd` and commit it atomically. On success the core switches
    /// (snapshotting the outgoing cursor, restoring the incoming one); on
    /// error the previous view is left intact and only `status` is set.
    fn load(&mut self, cwd: PathBuf) -> bool {
        match self.source.list(&cwd) {
            Ok(entries) => {
                self.core.commit_switch(cwd, entries);
                self.status = None;
                true
            }
            Err(msg) => {
                self.status = Some(format!("cannot list: {msg}"));
                false
            }
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> FilePickerOutcome {
        if key.kind != KeyEventKind::Press {
            return FilePickerOutcome::Pending;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Esc {
            return FilePickerOutcome::Cancel;
        }
        if ctrl && key.code == KeyCode::Char('c') {
            return FilePickerOutcome::Cancel;
        }
        self.ensure_started();
        if let Some(decision) = self.core.apply_nav_key(key) {
            return match decision {
                NavDecision::CursorMoved
                | NavDecision::QueryChanged
                | NavDecision::Noop => FilePickerOutcome::Pending,
                NavDecision::StepUp => {
                    self.step_up();
                    FilePickerOutcome::Pending
                }
            };
        }
        // Unhandled by the core: Enter / Right (activation). Space was already
        // appended to the query by apply_nav_key (FilePicker treats Space as a
        // query char, unlike the Pane which intercepts it for marks).
        match key.code {
            KeyCode::Enter => self.activate_selected(),
            KeyCode::Right => self.step_into_selected(),
            _ => FilePickerOutcome::Pending,
        }
    }

    /// Step up to the parent of `cwd`. No-op at `/`.
    fn step_up(&mut self) {
        if let Some(parent) = self.core.cwd.parent() {
            self.load(parent.to_path_buf());
        }
    }

    /// `Right`: enter the dir under the cursor, or do nothing on a file. Always
    /// `Pending`.
    fn step_into_selected(&mut self) -> FilePickerOutcome {
        let target = self
            .core
            .selected_entry()
            .filter(|e| e.is_dir)
            .map(|e| e.path.clone());
        if let Some(path) = target {
            self.load(path);
        }
        FilePickerOutcome::Pending
    }

    /// `Enter`: a path-like query resolves via the source (File → Pick, Dir →
    /// load, NotFound → status); a fuzzy query activates the cursor entry
    /// (dir → load, file → Pick).
    fn activate_selected(&mut self) -> FilePickerOutcome {
        match parse_filter_intent(&self.core.query) {
            FilterIntent::PathLike(raw) => match self.source.resolve(&raw, &self.core.cwd) {
                ResolvedPath::File(abs) => FilePickerOutcome::Pick(abs),
                ResolvedPath::Dir(abs) => {
                    self.load(abs);
                    FilePickerOutcome::Pending
                }
                ResolvedPath::NotFound => {
                    self.status = Some(format!("no such path: {raw}"));
                    FilePickerOutcome::Pending
                }
            },
            FilterIntent::Fuzzy(_) => {
                let picked = self
                    .core
                    .selected_entry()
                    .map(|e| (e.is_dir, e.path.clone()));
                match picked {
                    Some((true, path)) => {
                        self.load(path);
                        FilePickerOutcome::Pending
                    }
                    Some((false, path)) => FilePickerOutcome::Pick(path),
                    None => FilePickerOutcome::Pending,
                }
            }
        }
    }

    /// Paint the picker as a centered popup. Rendering only — mutates nothing.
    pub fn draw_overlay(&self, frame: &mut Frame) {
        use ratatui::layout::{Alignment, Constraint, Layout};
        use ratatui::style::{Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};
        use std::io::{BufRead, BufReader};

        let area = crate::tui::popup::centered_rect(
            frame.area(),
            crate::tui::popup::POPUP_WIDTH,
            crate::tui::popup::POPUP_HEIGHT,
        );
        frame.render_widget(Clear, area);
        let block = Block::new()
            .borders(Borders::ALL)
            .title(format!(" {} ", self.title))
            .title_style(crate::tui::theme::accent().add_modifier(Modifier::BOLD));
        frame.render_widget(&block, area);
        let inner = block.inner(area);

        let [cwd_area, list_area, query_area, status_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(inner);

        // cwd line, left-truncated (tail wins).
        let cwd_str = self.core.cwd.to_string_lossy().into_owned();
        let avail = inner.width as usize;
        let shown = crate::tui::fit::truncate_cells_head(&format!(" {cwd_str}"), avail);
        frame.render_widget(
            Paragraph::new(shown).style(crate::tui::theme::accent()),
            cwd_area,
        );

        // windowed, highlighted list.
        let total = self.core.ranked.len();
        let win = crate::tui::fit::focus_window(total, self.core.selected, Self::VISIBLE_ROWS);
        let mut lines: Vec<Line> = Vec::new();
        if self.core.ranked.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (empty — type a path with Enter to jump, or Esc to cancel)",
                Style::new().dim(),
            )));
        } else {
            for i in win.start..win.end {
                let Some(entry) = self.core.entry_at_rank(i) else {
                    continue;
                };
                let is_sel = i == self.core.selected;
                let marker = if is_sel { "▶ " } else { "  " };
                let base = if is_sel {
                    crate::tui::theme::accent().add_modifier(Modifier::BOLD)
                } else if entry.is_dir {
                    Style::new().add_modifier(Modifier::BOLD)
                } else {
                    Style::new()
                };
                let keyish = sshrack_core::keydetect::looks_like_key_filename(
                    entry.name.trim_end_matches(['/', '@']),
                ) || {
                    !entry.is_dir && {
                        std::fs::File::open(&entry.path)
                            .ok()
                            .and_then(|f| BufReader::new(f).lines().next().and_then(Result::ok))
                            .map(|l| sshrack_core::keydetect::looks_like_private_key_header(&l))
                            .unwrap_or(false)
                    }
                };
                let value_style = if keyish {
                    base.fg(crate::tui::theme::MATCH)
                } else {
                    base
                };
                let mut spans = vec![Span::styled(marker, base)];
                spans.extend(crate::tui::panel::highlighted_spans(
                    &entry.name,
                    &self.core.query,
                    value_style,
                ));
                lines.push(Line::from(spans).alignment(Alignment::Left));
            }
        }
        frame.render_widget(Paragraph::new(lines), list_area);

        // query box.
        let q = Line::from(vec![
            Span::styled(
                "> ",
                crate::tui::theme::accent().add_modifier(Modifier::BOLD),
            ),
            Span::raw(self.core.query.clone()),
            Span::styled("_", Style::new().dim()),
        ]);
        frame.render_widget(q, query_area);
        let qx = query_area.x + 2 + self.core.query.chars().count() as u16;
        let max_x = query_area.x + query_area.width.saturating_sub(1);
        frame.set_cursor_position((qx.min(max_x), query_area.y));

        // status / hint line.
        let line = match &self.status {
            Some(msg) => Line::from(vec![
                Span::styled("  ! ", Style::new().fg(crate::tui::theme::DANGER).bold()),
                Span::styled(msg.clone(), Style::new().fg(crate::tui::theme::DANGER)),
            ]),
            None => Line::from(Span::styled(
                " type: filter · ↑↓ move · ↵ open/select · ← up · esc clear/cancel",
                Style::new().dim(),
            )),
        };
        frame.render_widget(line, status_area);
    }
}
```

- [ ] **Step 4: Migrate the remaining field reads in the `file_picker.rs` test module**

Apply throughout the test module:
- `p.cwd` → `p.core.cwd` (note: `p.cwd.as_deref()` / `p.cwd.is_none()` / `p.cwd.is_some()` are GONE — see Step 2 for the failure test; other tests reading `p.cwd` as a path now read `p.core.cwd` directly, e.g. `assert_eq!(p.core.cwd, Path::new("/h"))`)
- `p.entries` → `p.core.entries`
- `p.query` → `p.core.query`
- `p.selected` → `p.core.selected`
- `p.ranked` → `p.core.ranked`
- `p.history` → `p.core.history`

Method calls (`p.on_key`, `p.ensure_started`, `p.draw_overlay`, `FilePicker::new`) stay unchanged. The `FakeSource`/`tree()`/`multi_dir_tree()`/`press()` helpers stay unchanged.

- [ ] **Step 5: Run the file-picker tests**

Run: `cargo test file_picker`
Expected: all tests pass, including the inverted `backspace_on_empty_query_is_a_noop_never_step_up` and the re-anchored `ensure_started_retries_after_initial_list_failure`.

- [ ] **Step 6: Run the wizard tests (consumers) to confirm zero breakage**

Run: `cargo test wizard`
Expected: pass (host/cred wizards construct `FilePicker` and consume `FilePickerOutcome` — unchanged surface).

- [ ] **Step 7: Lint + format**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt`
Expected: green.

- [ ] **Step 8: Commit**

```bash
git add src/tui/file_picker.rs
git commit -m "refactor(tui): reduce FilePicker to BrowserCore shell, align Backspace"
```

---

## Task 5: Finalize — full gate, dead-code sweep, doc references

**Goal:** Whole-workspace green; no leftover dead code; no stale doc references to the deleted `cursor_history` module.

**Files:**
- Audit (modify only if needed): `src/tui/browser_core.rs`, `src/tui/file_picker.rs`, `src/tui/transfer/pane.rs`, any doc comment still mentioning `cursor_history`.

- [ ] **Step 1: Full test gate**

Run: `cargo test --workspace`
Expected: all pass. (sshrack binary ~740+ tests, sshrack-core ~469+ tests.)

- [ ] **Step 2: Clippy + fmt gate**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: green.

- [ ] **Step 3: Dead-code + stale-reference sweep**

Run each; every hit must be resolved (delete or update):
```bash
rg -n "cursor_history" src/                         # expect ZERO hits
rg -n "remembered_cursor_index" src/                # expect only browser_core.rs (def + tests)
rg -n "#\[allow\(dead_code\)\]" src/tui/            # expect ZERO hits in the touched modules
rg -n "Mirrors .*file_picker|Mirrors .*Pane|mirrors \[.file_picker.\]" src/  # stale cross-refs gone
```
If `cursor_history` appears in any doc comment, rewrite it to reference `BrowserCore`. If any `#[allow(dead_code)]` lingers in `browser_core.rs`/`pane.rs`/`file_picker.rs`, remove it (all items are now reachable from `main` via the consumers).

- [ ] **Step 4: Confirm no duplicated logic remains**

Run:
```bash
rg -n "fn recompute|fn clamp_selected|fn move_cursor" src/tui/file_picker.rs src/tui/transfer/pane.rs
# expect ZERO hits — these now live once, in browser_core.rs
```
Expected: no matches in the two consumer files.

- [ ] **Step 5: Commit (only if Steps 3–4 changed anything)**

```bash
git add -u
git commit -m "refactor(tui): finalize browser-core extraction cleanup"
```
(If nothing changed, skip the commit — the refactor is already complete and clean.)

---

## Self-Review

**1. Spec coverage (the user's requirements):**
- "抽离能力组件" → Tasks 1–2 create `BrowserCore`; Tasks 3–4 migrate both consumers. ✓
- "完全的重构，不要兼容写法" → duplicated methods are DELETED in the consumers (Task 3 Step 1, Task 4 Step 3); `cursor_history` is DELETED (Task 2 Step 4); no re-export shims. Task 5 Step 3 verifies. ✓
- "不要有任何的 dead code" → Task 5 Step 3 sweeps `#[allow(dead_code)]` + stale refs. ✓
- "该删除的就删除，该复用的就提取" → 4 duplicated methods + `remembered_cursor_index` extracted once; consumer copies deleted. ✓
- "解耦、优雅、可复用、灵活易用" → core is pure, both consumers are thin shells; the two control-flow paradigms are honored via `commit_switch` (sync) vs `begin/finish_switch` (async). ✓
- "足够的测试用例保证，不引入 bug" → Task 1 (9 tests) + Task 2 (12 tests) drive the core; Tasks 3–4 preserve all existing consumer tests (mechanical migration only) + the Backspace drift test is inverted to lock the fix. Task 5 runs the full gate. ✓
- "cursor history 能力、筛选能力、多选能力" → all three live in `BrowserCore` (`history`, `recompute`+`rank_by_fields`, `marked`+`toggle_mark_selected`); "multi-select on/off" is expressed by the component choosing whether to call `toggle_mark_selected` (Pane yes, FilePicker no) — no runtime flag. ✓

**2. Placeholder scan:** No "TBD"/"TODO"/"handle edge cases"/"similar to". Every code step shows complete code; every migration step shows the exact `rg` + replacement. ✓

**3. Type consistency:**
- `NavDecision::CursorMoved | QueryChanged | StepUp | Noop` — used identically in Task 2 def, Task 3 `Pane::on_key`, Task 4 `FilePicker::on_key`. ✓
- `BrowserCore` fields `cwd/entries/query/ranked/selected/marked` are `pub(crate)` — accessible from `pane_tests.rs`, `screen.rs`, `run_loop.rs`, `file_picker.rs` test mod (all same crate). ✓
- `commit_switch(PathBuf, Vec<DirEntry>)` (Task 2) vs call in `FilePicker::load` (Task 4 Step 3) — signature matches. ✓
- `finish_switch(Vec<DirEntry>)` (Task 2) vs call in `Pane::set_entries` (Task 3 Step 1) — matches. ✓
- `begin_switch()` (Task 2) vs call in `Pane::on_step` (Task 3 Step 1) — matches. ✓
- `apply_nav_key(KeyEvent) -> Option<NavDecision>` (Task 2) vs calls in both consumers — matches. ✓
