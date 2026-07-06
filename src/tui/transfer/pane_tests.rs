//! Per-pane navigation/filter/mark unit tests for [`super::pane`].
//!
//! Covers `new`/`set_entries`/`on_step`/`on_key` (query filter, cursor
//! wrap, StepUp/StepInto/ActivateSelected, mark toggle, path-like Enter →
//! RequestList), `visible_window`, and non-Press event filtering. The pane
//! is pure — no I/O — so every test runs without a terminal, filesystem, or
//! worker.
//!
//! Extracted from `pane.rs` via `#[path]` so the module file stays under
//! the 800-line guideline (mirrors the inline-test convention used elsewhere
//! in the TUI; the split is purely mechanical — the tests reach into
//! `super::*` private items the same way an inline `mod tests` would).
use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use sshrack_core::dirsource::DirEntry;
use std::path::PathBuf;

/// Build a `DirEntry` test fixture: `name` is decorated with a trailing
/// `/` for dirs (matches `LocalDirSource::list`'s decoration); `path` is
/// `parent.join(name)`. `size`/`modified` are `None` (Task-1 fields).
fn entry(name: &str, parent: &Path, is_dir: bool) -> DirEntry {
    let decorated = if is_dir {
        format!("{name}/")
    } else {
        name.to_string()
    };
    DirEntry {
        name: decorated,
        path: parent.join(name),
        is_dir,
        is_symlink: false,
        size: None,
        modified: None,
    }
}

/// A `KeyEvent::Press` with no modifiers for `code`.
fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
}

/// A pane at `/x` with three file entries: apple, banana, cherry.
fn pane_with_fruits() -> Pane {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("banana", &cwd, false),
        entry("cherry", &cwd, false),
    ]);
    p
}

// ---- new() ----

#[test]
fn new_starts_empty_with_no_query_no_marks() {
    let p = Pane::new(PathBuf::from("/x"));
    assert_eq!(p.cwd, PathBuf::from("/x"));
    assert!(p.entries.is_empty());
    assert!(p.query.is_empty());
    assert!(p.ranked.is_empty());
    assert_eq!(p.selected, 0);
    assert!(p.marked.is_empty());
    assert!(!p.loading);
    assert!(p.selected_entry().is_none());
}

// ---- set_entries: resets cursor + re-ranks (empty query → all entries) ----

#[test]
fn set_entries_resets_cursor_to_zero_and_ranks_all() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.selected = 7; // pretend a stale cursor
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("banana", &cwd, false),
    ]);
    assert_eq!(p.selected, 0, "cursor reset to 0");
    assert_eq!(p.ranked.len(), 2, "both entries ranked");
    assert_eq!(p.ranked, vec![0, 1], "empty query keeps entry order");
}

#[test]
fn set_entries_preserves_query_for_in_place_refresh() {
    // A refresh of the SAME dir should not wipe the user's filter — only
    // on_step (called for a NEW dir) clears the query.
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("banana", &cwd, false),
        entry("cherry", &cwd, false),
    ]);
    // Simulate the user typing "an" (matches "banana" only).
    let _ = p.on_key(press(KeyCode::Char('a')));
    let _ = p.on_key(press(KeyCode::Char('n')));
    assert_eq!(p.query, "an");
    // Now the worker refreshes the same dir's entries (e.g. a file appeared
    // server-side). The query must survive.
    p.set_entries(vec![
        entry("apple", &cwd, false),
        entry("avocado", &cwd, false),
        entry("banana", &cwd, false),
        entry("cherry", &cwd, false),
    ]);
    assert_eq!(p.query, "an", "query preserved on in-place refresh");
    // "an" still matches banana only; the new avocado does not match.
    let names: Vec<&str> = p
        .ranked
        .iter()
        .map(|&i| p.entries[i].name.as_str())
        .collect();
    assert_eq!(names, vec!["banana"]);
    assert_eq!(p.selected, 0, "cursor reset on refresh");
}

// ---- on_step: clears marks + query + cursor for a new dir ----

#[test]
fn on_step_clears_marks_query_and_cursor() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("apple", &cwd, false)]);
    // Mark the entry, type a query, move the cursor.
    let _ = p.on_key(press(KeyCode::Char(' '))); // ToggleMark(/x/apple)
    let _ = p.on_key(press(KeyCode::Char('q'))); // query = "q"
    let _ = p.on_key(press(KeyCode::Down)); // selected = 0 still (1 entry)
    assert!(p.marked.contains(&cwd.join("apple")));
    assert_eq!(p.query, "q");
    // Act: the screen is about to load a new dir.
    p.on_step();
    assert!(p.marked.is_empty(), "marks cleared");
    assert!(p.query.is_empty(), "query cleared");
    assert_eq!(p.selected, 0, "cursor reset");
}

// ---- query filters + re-ranks ----

#[test]
fn typing_a_char_appends_to_query_and_filters() {
    let mut p = pane_with_fruits();
    let out = p.on_key(press(KeyCode::Char('c')));
    assert_eq!(out, PaneOutcome::QueryChanged);
    assert_eq!(p.query, "c");
    let names: Vec<&str> = p
        .ranked
        .iter()
        .map(|&i| p.entries[i].name.as_str())
        .collect();
    assert_eq!(names, vec!["cherry"], "only cherry matches 'c'");
    assert_eq!(p.selected, 0, "cursor reset to 0 on query change");
}

#[test]
fn backspace_pops_a_query_char_and_reranks() {
    let mut p = pane_with_fruits();
    let _ = p.on_key(press(KeyCode::Char('c')));
    let _ = p.on_key(press(KeyCode::Char('h')));
    assert_eq!(p.query, "ch");
    let out = p.on_key(press(KeyCode::Backspace));
    assert_eq!(out, PaneOutcome::QueryChanged);
    assert_eq!(p.query, "c");
}

// ---- Down/Up move selected with wrap ----

#[test]
fn down_then_up_moves_cursor_and_wraps() {
    let mut p = pane_with_fruits();
    assert_eq!(p.selected, 0);
    let _ = p.on_key(press(KeyCode::Down));
    assert_eq!(p.selected, 1);
    let _ = p.on_key(press(KeyCode::Down));
    assert_eq!(p.selected, 2);
    // wrap bottom → top
    let _ = p.on_key(press(KeyCode::Down));
    assert_eq!(p.selected, 0);
    // wrap top → bottom
    let _ = p.on_key(press(KeyCode::Up));
    assert_eq!(p.selected, 2);
}

#[test]
fn ctrl_p_and_ctrl_n_move_cursor() {
    let mut p = pane_with_fruits();
    let ctrl_p = KeyEvent::new_with_kind(
        KeyCode::Char('p'),
        KeyModifiers::CONTROL,
        KeyEventKind::Press,
    );
    let ctrl_n = KeyEvent::new_with_kind(
        KeyCode::Char('n'),
        KeyModifiers::CONTROL,
        KeyEventKind::Press,
    );
    let _ = p.on_key(ctrl_n);
    assert_eq!(p.selected, 1);
    let _ = p.on_key(ctrl_p);
    assert_eq!(p.selected, 0);
}

// ---- Left / Backspace-empty → StepUp ----

#[test]
fn left_emits_step_up_when_cwd_has_parent() {
    let mut p = pane_with_fruits(); // cwd = /x
    assert_eq!(p.on_key(press(KeyCode::Left)), PaneOutcome::StepUp);
    // Backspace on empty query is the same intent.
    assert_eq!(p.on_key(press(KeyCode::Backspace)), PaneOutcome::StepUp);
}

#[test]
fn left_is_noop_at_root() {
    let mut p = Pane::new(PathBuf::from("/"));
    assert_eq!(p.on_key(press(KeyCode::Left)), PaneOutcome::None);
    assert_eq!(p.on_key(press(KeyCode::Backspace)), PaneOutcome::None);
}

// ---- Right/Enter on a dir → StepInto; on a file → ActivateSelected ----

#[test]
fn right_on_dir_emits_step_into() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    // Single dir entry, so the cursor lands on it unambiguously. (With a
    // file alongside, rank_by_fields would order by name asc and "file"
    // sorts before "subdir/" — the cursor would land on the file.)
    p.set_entries(vec![entry("subdir", &cwd, true)]);
    let out = p.on_key(press(KeyCode::Right));
    assert_eq!(out, PaneOutcome::StepInto(cwd.join("subdir")));
}

#[test]
fn right_on_file_emits_activate_selected() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("file", &cwd, false)]);
    let out = p.on_key(press(KeyCode::Right));
    assert_eq!(out, PaneOutcome::ActivateSelected);
}

#[test]
fn enter_on_dir_emits_step_into() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("subdir", &cwd, true)]);
    let out = p.on_key(press(KeyCode::Enter));
    assert_eq!(out, PaneOutcome::StepInto(cwd.join("subdir")));
}

#[test]
fn enter_on_file_emits_activate_selected() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("file", &cwd, false)]);
    let out = p.on_key(press(KeyCode::Enter));
    assert_eq!(out, PaneOutcome::ActivateSelected);
}

#[test]
fn enter_on_empty_cursor_is_none() {
    let mut p = Pane::new(PathBuf::from("/x"));
    p.set_entries(vec![]);
    assert_eq!(p.on_key(press(KeyCode::Enter)), PaneOutcome::None);
    assert_eq!(p.on_key(press(KeyCode::Right)), PaneOutcome::None);
}

// ---- Space toggles a mark (file or dir) and updates `marked` ----

#[test]
fn space_on_file_toggles_mark_and_path_appears_in_marked() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("apple", &cwd, false)]);
    let target = cwd.join("apple");
    let out = p.on_key(press(KeyCode::Char(' ')));
    assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
    assert!(p.marked.contains(&target), "marked after first Space");
    // Second Space untoggles.
    let out = p.on_key(press(KeyCode::Char(' ')));
    assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
    assert!(!p.marked.contains(&target), "unmarked after second Space");
}

#[test]
fn space_on_dir_toggles_mark() {
    // Dirs are transferable recursively, so Space toggles their mark too.
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("subdir", &cwd, true)]);
    let target = cwd.join("subdir");
    let out = p.on_key(press(KeyCode::Char(' ')));
    assert_eq!(out, PaneOutcome::ToggleMark(target.clone()));
    assert!(p.marked.contains(&target));
}

#[test]
fn space_on_empty_cursor_is_none() {
    let mut p = Pane::new(PathBuf::from("/x"));
    p.set_entries(vec![]);
    assert_eq!(p.on_key(press(KeyCode::Char(' '))), PaneOutcome::None);
}

// ---- path-like query + Enter → RequestList ----

#[test]
fn enter_on_absolute_path_query_emits_request_list() {
    let mut p = Pane::new(PathBuf::from("/start"));
    p.set_entries(vec![]);
    for c in "/foo/bar".chars() {
        let _ = p.on_key(press(KeyCode::Char(c)));
    }
    assert_eq!(
        p.on_key(press(KeyCode::Enter)),
        PaneOutcome::RequestList(PathBuf::from("/foo/bar"))
    );
}

#[test]
fn enter_on_relative_path_query_joins_cwd() {
    let mut p = Pane::new(PathBuf::from("/parent"));
    p.set_entries(vec![]);
    for c in "sub/dir".chars() {
        let _ = p.on_key(press(KeyCode::Char(c)));
    }
    assert_eq!(
        p.on_key(press(KeyCode::Enter)),
        PaneOutcome::RequestList(PathBuf::from("/parent/sub/dir"))
    );
}

#[test]
fn enter_on_tilde_path_query_expands_home_when_set() {
    // `~`-expansion depends on HOME; skip the assertion when the test
    // environment has none (the production behavior is to emit None).
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("skip: HOME unset; cannot exercise ~ expansion");
        return;
    };
    let mut p = Pane::new(PathBuf::from("/start"));
    p.set_entries(vec![]);
    for c in "~/baz".chars() {
        let _ = p.on_key(press(KeyCode::Char(c)));
    }
    assert_eq!(
        p.on_key(press(KeyCode::Enter)),
        PaneOutcome::RequestList(home.join("baz"))
    );
}

#[test]
fn enter_on_fuzzy_query_activates_cursor_not_request_list() {
    // A plain-word query (no `/`, no `~`) is fuzzy, not path-like: Enter
    // activates the cursor entry rather than emitting RequestList.
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![entry("cherry", &cwd, false)]);
    let _ = p.on_key(press(KeyCode::Char('c'))); // fuzzy "c" → cherry
    let out = p.on_key(press(KeyCode::Enter));
    assert_eq!(out, PaneOutcome::ActivateSelected);
}

// ---- visible_window keeps the cursor in view ----

#[test]
fn visible_window_keeps_cursor_centered_then_clamps_to_tail() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    let entries: Vec<DirEntry> = (0..20)
        .map(|i| entry(&format!("f{i:02}"), &cwd, false))
        .collect();
    p.set_entries(entries);
    assert_eq!(p.ranked.len(), 20);
    // Move cursor to 15; window of 5 → focus_window(20, 15, 5) = 13..18.
    for _ in 0..15 {
        let _ = p.on_key(press(KeyCode::Down));
    }
    assert_eq!(p.selected, 15);
    let win = p.visible_window(5);
    assert!(
        win.contains(&p.selected),
        "{}..{} excludes {}",
        win.start,
        win.end,
        p.selected
    );
    assert_eq!(win, 13..18);
    // Clamp to tail: cursor at 19, window 5 → 15..20.
    for _ in 0..4 {
        let _ = p.on_key(press(KeyCode::Down));
    }
    assert_eq!(p.selected, 19);
    let win = p.visible_window(5);
    assert!(win.contains(&p.selected));
    assert_eq!(win, 15..20);
}

#[test]
fn visible_window_empty_entries_is_empty_range() {
    let p = Pane::new(PathBuf::from("/x"));
    assert_eq!(p.visible_window(10), 0..0);
}

// ---- non-Press events are ignored ----

#[test]
fn non_press_events_emit_none_and_do_not_mutate() {
    let mut p = pane_with_fruits();
    let release = KeyEvent::new_with_kind(
        KeyCode::Char('a'),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert_eq!(p.on_key(release), PaneOutcome::None);
    assert!(p.query.is_empty(), "release did not append to query");
}

// ---- selected_entry follows the cursor ----

#[test]
fn selected_entry_tracks_cursor_after_move() {
    let cwd = PathBuf::from("/x");
    let mut p = Pane::new(cwd.clone());
    p.set_entries(vec![
        entry("a", &cwd, false),
        entry("b", &cwd, false),
        entry("c", &cwd, false),
    ]);
    assert_eq!(
        p.selected_entry().map(|e| e.name.clone()).as_deref(),
        Some("a")
    );
    let _ = p.on_key(press(KeyCode::Down));
    assert_eq!(
        p.selected_entry().map(|e| e.name.clone()).as_deref(),
        Some("b")
    );
}

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
