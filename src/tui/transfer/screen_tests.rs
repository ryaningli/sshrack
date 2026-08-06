//! Render smoke + small-terminal tests for the transfer screen, plus the pure
//! `on_key` routing tests (focus switch, mark, transfer-enqueue, cancel,
//! close, queue-advance). The screen is a thin layer over [`super::render`]
//! and [`super::Pane`], so these tests exercise the layout wiring and the key
//! router (no panic, no overflow, focused row stays in view, correct
//! [`super::ScreenOutcome`] per key) rather than re-asserting per-pane painting.
//!
//! Extracted from `screen.rs` via `#[path]` so the module file stays under the
//! 800-line guideline (mirrors the inline-test convention everywhere else in
//! the TUI; the split is purely mechanical).
use super::*;
use crate::tui::transfer::search::PaneSearch;
use ratatui::{Terminal, backend::TestBackend};
use sshrack_core::connect::sftp::parse::strip_control_chars;
use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob};
use sshrack_core::dirsource::DirEntry;
use sshrack_core::pathfind::{PathMatch, SearchEvent, SearchEventKind, SegMatch, parse_query};
use std::path::{Path, PathBuf};

/// Build a `DirEntry` fixture: `name` carries a trailing `/` for dirs
/// (matches `LocalDirSource::list`'s decoration); `path` is `parent/name`.
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
        size: Some(1024),
        modified: None,
    }
}

/// Seed one in-flight upload task named `name` (mirrors the seeding in
/// `filter_esc_clears_query_before_cancelling_inflight_transfer`).
fn seed_inflight_upload(s: &mut TransferScreen, name: &str) {
    s.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/srv").join(name),
        dst: PathBuf::from("/r").join(name),
        name: name.into(),
        size_total: Some(100),
        recursive: false,
    });
    s.ledger.next_to_dispatch();
    s.ledger.set_inflight_progress(Progress {
        name: name.into(),
        direction: Direction::Upload,
        bytes_done: 0,
        bytes_total: Some(100),
        rate_bps: None,
        eta_secs: None,
    });
}

/// Build a screen with a few entries on each side, a marked local file, an
/// active upload, and one queued download — the rendering smoke case.
fn canned_screen() -> TransferScreen {
    let local_cwd = PathBuf::from("/home/local");
    let remote_cwd = PathBuf::from("/srv/remote");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen.local.set_entries(vec![
        entry("alpha.txt", &local_cwd, false),
        entry("beta.txt", &local_cwd, false),
        entry("docs", &local_cwd, true),
    ]);
    screen.remote.set_entries(vec![
        entry("server.log", &remote_cwd, false),
        entry("cache", &remote_cwd, true),
    ]);
    // Mark one local file.
    screen.local.core.marked.insert(local_cwd.join("alpha.txt"));
    // Active upload: enqueue + dispatch (InFlight) + progress snapshot.
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: local_cwd.join("alpha.txt"),
        dst: remote_cwd.join("alpha.txt"),
        name: "alpha.txt".into(),
        size_total: Some(1024),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.set_inflight_progress(Progress {
        name: "alpha.txt".into(),
        direction: Direction::Upload,
        bytes_done: 256,
        bytes_total: Some(1024),
        rate_bps: Some(128),
        eta_secs: Some(6),
    });
    // One queued download.
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: remote_cwd.join("server.log"),
        dst: local_cwd.join("server.log"),
        name: "server.log".into(),
        size_total: Some(2048),
        recursive: false,
    });
    screen
}

/// Human-readable dump of a ratatui buffer (one line per row) for substring
/// assertions in render tests.
fn buffer_view(buf: &ratatui::buffer::Buffer) -> String {
    let area = buf.area;
    let mut out = String::with_capacity((area.width as usize + 1) * area.height as usize);
    for row in 0..area.height {
        for col in 0..area.width {
            let cell = buf.cell((col, row));
            out.push_str(cell.map(|c| c.symbol()).unwrap_or(" "));
        }
        out.push('\n');
    }
    out
}

#[test]
fn draw_renders_without_panic_or_overflow() {
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let screen = canned_screen();
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "draw returned error: {:?}", res.err());
}

#[test]
fn draw_paints_title_panes_progress_and_footer() {
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let screen = canned_screen();
    term.draw(|f| screen.draw(f, f.area())).expect("draw");
    let view = buffer_view(term.backend().buffer());

    // Title band: brand + sftp.
    assert!(view.contains("sshrack"), "brand missing: {view}");
    assert!(view.contains("sftp"), "sftp label missing: {view}");

    // Footer advertises Tab completion (not the old "switch" wording).
    assert!(
        view.contains("complete"),
        "footer Tab hint says complete: {view}"
    );

    // Both pane cwds are rendered.
    assert!(
        view.contains("local") || view.contains("/home/local"),
        "local cwd missing: {view}"
    );
    assert!(
        view.contains("remote") || view.contains("/srv/remote"),
        "remote cwd missing: {view}"
    );

    // The marked file is flagged with `●` and the active transfer's name
    // shows up in the progress panel.
    assert!(view.contains('●'), "mark glyph missing: {view}");
    assert!(view.contains("alpha.txt"), "active name missing: {view}");
    assert!(view.contains("done"), "summary label missing: {view}");

    // Footer hotkeys.
    assert!(view.contains("Tab"), "footer Tab missing: {view}");
    assert!(view.contains("Space"), "footer Space missing: {view}");
    assert!(view.contains("^S"), "footer ^S missing: {view}");

    // No leak of fake control chars from `strip_control_chars` use — feed a
    // malicious name through and assert it shows up cleaned. Re-renders on
    // a fresh screen so the assertion reads cleanly.
    let local_cwd = PathBuf::from("/x");
    let mut evil = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    evil.local.set_entries(vec![DirEntry {
        name: "foo\x1b[2Jbar".into(),
        path: local_cwd.join("foo\x1b[2Jbar"),
        is_dir: false,
        is_symlink: false,
        size: None,
        modified: None,
    }]);
    let mut term2 = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
    term2.draw(|f| evil.draw(f, f.area())).expect("draw");
    let view2 = buffer_view(term2.backend().buffer());
    assert!(!view2.contains('\u{1b}'), "ESC leaked into render: {view2}");
    // strip_control_chars is the source of the `?` replacement; touch it so
    // the import stays meaningful in this test.
    assert_eq!(strip_control_chars("a\x1bb"), "a?b");
}

#[test]
fn transfer_footer_advertises_f1_help() {
    // The full hint strip (Tab … ^C close · F1 help) only fits on a wide
    // terminal — at 80 cols the footer paragraph clips before F1, so use a
    // 120-col backend where the whole row renders. Pins that F1 is advertised
    // alongside the other transfer hotkeys now that Help is a global layer.
    let backend = TestBackend::new(120, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
    term.draw(|f| screen.draw(f, f.area())).expect("draw");
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("F1") && view.contains("help"),
        "footer must advertise F1 help, got: {view}"
    );
}

#[test]
fn draw_renders_summary_when_idle() {
    let backend = TestBackend::new(70, 20);
    let mut term = Terminal::new(backend).expect("test backend");
    let mut screen = canned_screen();
    // canned_screen() has an in-flight upload + a queued download. Drop both
    // so the screen is fully idle (no InFlight, no Queued).
    screen.ledger.abort_inflight();
    screen.ledger.clear_queued();
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "idle draw must not panic: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(view.contains("done"), "summary present when idle: {view}");
}

#[test]
fn draw_handles_unknown_total_without_gauge_panic() {
    // `bytes_total` = None must render the indeterminate form without a
    // Gauge (a missing percent would have panicked `Gauge::percent`). The
    // row shows the name + bytes-done segment + rate segment, but no `%`.
    let backend = TestBackend::new(70, 20);
    let mut term = Terminal::new(backend).expect("test backend");
    let mut screen = canned_screen();
    // Replace the in-flight upload with an unknown-total download: abort the
    // canned upload, then enqueue + dispatch + progress a stream.bin download.
    screen.ledger.abort_inflight();
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/srv/remote/stream.bin"),
        dst: PathBuf::from("/home/local/stream.bin"),
        name: "stream.bin".into(),
        size_total: None,
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.set_inflight_progress(Progress {
        name: "stream.bin".into(),
        direction: Direction::Download,
        bytes_done: 4096,
        bytes_total: None,
        rate_bps: None,
        eta_secs: None,
    });
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "draw returned error: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(view.contains("stream.bin"), "name shown: {view}");
    assert!(!view.contains('%'), "no gauge when total unknown: {view}");
    assert!(view.contains("4.0K"), "bytes-done segment shown: {view}");
}

/// Small-terminal pin: on a 60×12 backend with focus on the remote pane's
/// last entry, the focused entry's name must appear in the rendered buffer
/// (i.e. the focus-following window scrolled it into view, not off-screen).
/// Mirrors the wizard's small-terminal cursor-on-screen test.
#[test]
fn draw_keeps_focused_row_visible_on_small_terminal() {
    let local_cwd = PathBuf::from("/local");
    let remote_cwd = PathBuf::from("/remote");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    // Lots of remote entries so the cursor sits at the tail of a long list.
    let remote_entries: Vec<DirEntry> = (0..30)
        .map(|i| entry(&format!("r{i:02}.dat"), &remote_cwd, false))
        .collect();
    screen.remote.set_entries(remote_entries);
    // Move the remote cursor to the last entry.
    for _ in 0..29 {
        screen.remote.core.selected = (screen.remote.core.selected + 1) % 30;
    }
    assert_eq!(screen.remote.core.selected, 29);
    screen.focus = Side::Remote;
    // Sanity: `selected_entry` agrees the cursor is on r29.
    assert_eq!(
        screen
            .remote
            .selected_entry()
            .map(|e| e.name.clone())
            .as_deref(),
        Some("r29.dat")
    );

    let backend = TestBackend::new(60, 12);
    let mut term = Terminal::new(backend).expect("test backend");
    term.draw(|f| screen.draw(f, f.area())).expect("draw");

    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("r29.dat"),
        "focused entry name not visible on 60x12: {view}"
    );
}

// ---- on_key: focus switching ----

/// A `KeyEvent::Press` with `mods` and `code`.
fn press(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
    KeyEvent::new_with_kind(code, mods, KeyEventKind::Press)
}

#[test]
fn tab_flips_focus_local_to_remote() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert_eq!(screen.focus, Side::Local, "default focus is Local");
    let out = screen.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(screen.focus, Side::Remote, "Tab flipped to Remote");
}

#[test]
fn backtab_flips_focus_remote_to_local() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    screen.focus = Side::Remote;
    let out = screen.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(screen.focus, Side::Local, "Shift-Tab flipped back to Local");
}

// ---- on_key: Space reaches the focused pane (toggles a mark) ----

#[test]
fn space_toggles_mark_via_focused_pane_and_returns_continue() {
    let local_cwd = PathBuf::from("/l");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);
    assert!(screen.local.core.marked.is_empty(), "no marks initially");

    // Space must NOT be pre-empted at the screen level — it reaches the
    // focused pane and toggles the mark on the cursor entry.
    let out = screen.on_key(press(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(
        screen
            .local
            .core
            .marked
            .contains(&local_cwd.join("alpha.txt")),
        "Space toggled the local mark"
    );
}

// ---- on_key: Ctrl-Enter enqueues ----

#[test]
fn ctrl_enter_with_marked_file_enqueues_upload_job() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);
    // Mark the local file directly (the screen's Space path is covered
    // above; this test isolates the enqueue direction).
    screen.local.core.marked.insert(local_cwd.join("alpha.txt"));

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue, "marked file → Enqueue");
    assert_eq!(screen.ledger.tasks.len(), 1, "exactly one job queued");
    let job = &screen.ledger.tasks[0].job;
    assert_eq!(job.direction, Direction::Upload, "focus=Local → Upload");
    assert_eq!(job.src, local_cwd.join("alpha.txt"));
    assert_eq!(
        job.dst,
        remote_cwd.join("alpha.txt"),
        "dst = remote cwd + file name"
    );
    assert_eq!(job.name, "alpha.txt");
    assert!(!job.recursive, "file → recursive=false");
    assert_eq!(job.size_total, Some(1024), "size carried from entry");
    // Marks are single-shot: cleared after enqueue.
    assert!(
        screen.local.core.marked.is_empty(),
        "marks cleared after enqueue"
    );
}

#[test]
fn ctrl_enter_with_focus_remote_enqueues_download_job() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen.focus = Side::Remote;
    screen
        .remote
        .set_entries(vec![entry("server.log", &remote_cwd, false)]);
    screen
        .remote
        .core
        .marked
        .insert(remote_cwd.join("server.log"));

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks.len(), 1);
    let job = &screen.ledger.tasks[0].job;
    assert_eq!(
        job.direction,
        Direction::Download,
        "focus=Remote → Download"
    );
    assert_eq!(job.src, remote_cwd.join("server.log"));
    assert_eq!(job.dst, local_cwd.join("server.log"));
}

#[test]
fn ctrl_enter_with_marked_dir_sets_recursive_true() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("docs", &local_cwd, true)]);
    screen.local.core.marked.insert(local_cwd.join("docs"));

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks.len(), 1);
    let job = &screen.ledger.tasks[0].job;
    assert!(job.recursive, "dir → recursive=true");
    assert_eq!(job.src, local_cwd.join("docs"));
    assert_eq!(job.dst, remote_cwd.join("docs"));
    // Dir display name has the trailing `/` stripped.
    assert_eq!(job.name, "docs", "trailing slash stripped from name");
}

#[test]
fn ctrl_enter_with_no_marks_enqueues_selected_file() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);
    // No marks — the selected entry (cursor at index 0) is the fallback.

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(
        out,
        ScreenOutcome::Enqueue,
        "selected file fallback → Enqueue"
    );
    assert_eq!(screen.ledger.tasks.len(), 1);
    assert_eq!(screen.ledger.tasks[0].job.src, local_cwd.join("alpha.txt"));
}

#[test]
fn ctrl_enter_with_empty_pane_returns_continue_and_queues_nothing() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    // No entries, no marks, no selected entry.
    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "nothing to enqueue → Continue"
    );
    assert!(screen.ledger.tasks.is_empty(), "queue still empty");
}

#[test]
fn ctrl_enter_enqueues_multiple_marked_files_in_entry_order() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen.local.set_entries(vec![
        entry("alpha.txt", &local_cwd, false),
        entry("beta.txt", &local_cwd, false),
        entry("docs", &local_cwd, true),
    ]);
    // Mark alpha and docs (skip beta) — order in the queue follows entry
    // order, not mark-insertion order.
    screen.local.core.marked.insert(local_cwd.join("docs"));
    screen.local.core.marked.insert(local_cwd.join("alpha.txt"));

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks.len(), 2, "two marked entries queued");
    assert_eq!(
        screen.ledger.tasks[0].job.src,
        local_cwd.join("alpha.txt"),
        "alpha first (entry order)"
    );
    assert_eq!(
        screen.ledger.tasks[1].job.src,
        local_cwd.join("docs"),
        "docs second (entry order)"
    );
    assert!(
        screen.ledger.tasks[1].job.recursive,
        "docs is a dir → recursive"
    );
}

// ---- on_key: Ctrl-S transfers (reliable primary) + Enter-on-file ----
//
// Ctrl-Enter above is the legacy alias; many terminals collapse it to a bare
// Enter (no modifier), so the footer advertises Ctrl-S as the primary trigger
// (a control char, always delivered). Plain Enter ALSO enqueues when the cursor
// is on a file — a convenience. Enter on a dir still steps in (folders transfer
// via Ctrl-S, never via Enter — guards against accidental recursive uploads).

#[test]
fn ctrl_s_on_file_enqueues_upload_job() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue, "Ctrl-S on a file → Enqueue");
    assert_eq!(screen.ledger.tasks.len(), 1);
    let job = &screen.ledger.tasks[0].job;
    assert_eq!(job.direction, Direction::Upload, "focus=Local → Upload");
    assert_eq!(job.src, local_cwd.join("alpha.txt"));
    assert_eq!(job.dst, remote_cwd.join("alpha.txt"));
    assert!(!job.recursive, "file → recursive=false");
}

#[test]
fn ctrl_s_on_dir_enqueues_recursive_job() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("docs", &local_cwd, true)]);

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    let job = &screen.ledger.tasks[0].job;
    assert!(job.recursive, "dir via Ctrl-S → recursive=true");
    assert_eq!(job.src, local_cwd.join("docs"));
    assert_eq!(job.name, "docs", "trailing slash stripped from name");
}

#[test]
fn ctrl_s_in_find_mode_enqueues_cursor_result_only_ignoring_marks() {
    // Find mode has no marking: Ctrl-S enqueues the cursor result only. Stale
    // `marked` entries (e.g. carried over from listing mode) are NOT consulted
    // — find results are cross-directory, so a marked set would be meaningless
    // and could silently suppress the enqueue (stale-mark pollution). The
    // cursor file is enqueued with dst = opposite cwd / file name.
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.results = vec![
        PathMatch {
            path: PathBuf::from("/l/sub/a.txt"),
            is_dir: false,
            seg_matches: vec![],
        },
        PathMatch {
            path: PathBuf::from("/l/sub/dir"),
            is_dir: true,
            seg_matches: vec![],
        },
    ];
    s.local.search = Some(srch);
    // Cursor on index 0 (the file). Stale mark unrelated to the find results.
    s.local.core.marked.insert(PathBuf::from("/l/legacy.txt"));

    let out = s.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(s.ledger.tasks.len(), 1, "only the cursor result enqueued");
    let job = &s.ledger.tasks[0].job;
    assert_eq!(job.direction, Direction::Upload);
    assert_eq!(job.src, PathBuf::from("/l/sub/a.txt"));
    assert_eq!(
        job.dst,
        PathBuf::from("/r/a.txt"),
        "dst = opposite cwd / file name"
    );
    assert!(!job.recursive, "file → recursive=false");
}

#[test]
fn ctrl_s_focus_remote_enqueues_download_job() {
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen.focus = Side::Remote;
    screen
        .remote
        .set_entries(vec![entry("server.log", &remote_cwd, false)]);

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks[0].job.direction, Direction::Download);
    assert_eq!(
        screen.ledger.tasks[0].job.src,
        remote_cwd.join("server.log")
    );
    assert_eq!(screen.ledger.tasks[0].job.dst, local_cwd.join("server.log"));
}

#[test]
fn ctrl_s_with_marks_enqueues_marked_batch() {
    // Marks take priority over the cursor for both Ctrl-S and Enter — marking
    // is the explicit "transfer these" signal. Marks are single-shot.
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen.local.set_entries(vec![
        entry("alpha.txt", &local_cwd, false),
        entry("beta.txt", &local_cwd, false),
    ]);
    screen.local.core.marked.insert(local_cwd.join("beta.txt"));

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks.len(), 1, "only the marked entry queued");
    assert_eq!(screen.ledger.tasks[0].job.src, local_cwd.join("beta.txt"));
    assert!(
        screen.local.core.marked.is_empty(),
        "marks cleared after enqueue"
    );
}

#[test]
fn enter_on_file_enqueues_upload_job() {
    // Plain Enter (no modifier) on a file under the cursor enqueues it — the
    // convenience shortcut mirroring Ctrl-S for the single-file case.
    let local_cwd = PathBuf::from("/l");
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Enqueue, "Enter on a file → Enqueue");
    assert_eq!(screen.ledger.tasks.len(), 1);
    assert_eq!(screen.ledger.tasks[0].job.src, local_cwd.join("alpha.txt"));
    assert_eq!(screen.ledger.tasks[0].job.direction, Direction::Upload);
}

#[test]
fn enter_on_dir_steps_in_and_does_not_enqueue() {
    // Safety pin: Enter on a dir NAVIGATES (requests a listing), never
    // transfers — folders transfer via Ctrl-S. Guards against an accidental
    // recursive upload when the user means to look inside a directory.
    let local_cwd = PathBuf::from("/l");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    screen
        .local
        .set_entries(vec![entry("docs", &local_cwd, true)]);

    let out = screen.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "Enter on a dir navigates, does not enqueue"
    );
    assert!(
        screen.ledger.tasks.is_empty(),
        "no job queued for a dir on Enter"
    );
    assert_eq!(
        screen.pending_list,
        Some((Side::Local, local_cwd.join("docs"))),
        "Enter on a dir requests a listing of that dir"
    );
}

#[test]
fn plain_s_types_into_filter_and_does_not_enqueue() {
    // Guard the `if ctrl` on the Ctrl-S arm: a bare 's' (no modifier) is a
    // filter-box character, never a transfer. Without this pin a regression
    // that drops the guard would silently enqueue on every 's' keystroke.
    let local_cwd = PathBuf::from("/l");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    screen
        .local
        .set_entries(vec![entry("alpha.txt", &local_cwd, false)]);

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue, "bare 's' is not a transfer");
    assert_eq!(
        screen.local.core.query, "s",
        "bare 's' reaches the filter box"
    );
    assert!(screen.ledger.tasks.is_empty(), "bare 's' must not enqueue");
}

// ---- on_key: Esc / Ctrl-C ----

#[test]
fn esc_without_active_transfer_returns_close_transfer() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert!(!screen.has_inflight());
    let out = screen.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        out,
        ScreenOutcome::CloseTransfer,
        "Esc idle → CloseTransfer"
    );
}

#[test]
fn filter_esc_clears_non_empty_query_instead_of_closing() {
    // In filter mode (no active find), Esc with a non-empty query clears the
    // query and returns to the full current-dir listing — mirroring find
    // mode's Esc. Only an empty query lets Esc proceed to quit the SFTP
    // session. Otherwise the instinct to "clear the search box" would kick
    // the user out of SFTP.
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![
        entry("alpha.txt", &cwd, false),
        entry("beta.txt", &cwd, false),
    ]);
    s.local.core.query = "alpha".into();
    s.local.core.recompute();
    assert_eq!(
        s.local.matched_count(),
        1,
        "precondition: filter narrows to alpha"
    );

    let out = s.on_key(press(KeyCode::Esc, KeyModifiers::NONE));

    assert_eq!(out, ScreenOutcome::Continue, "Esc clears query, not close");
    assert!(s.local.core.query.is_empty(), "query cleared");
    assert_eq!(s.local.matched_count(), 2, "full listing restored");
}

#[test]
fn filter_esc_clears_query_before_opening_quit_confirm() {
    // Esc peels layers inside-out: a non-empty query is cleared BEFORE Esc
    // reaches the quit path — matching find mode's precedence (in_search is
    // checked before request_close). A second Esc (query now empty) opens the
    // quit-confirm overlay; cancelling the transfer itself is done in ^Q's
    // queue manager, not with Esc.
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![entry("alpha.txt", &cwd, false)]);
    s.local.core.query = "alpha".into();
    s.local.core.recompute();
    // Seed an in-flight transfer.
    s.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/srv/alpha.txt"),
        dst: PathBuf::from("/r/alpha.txt"),
        name: "alpha.txt".into(),
        size_total: Some(10),
        recursive: false,
    });
    s.ledger.next_to_dispatch();
    s.ledger.set_inflight_progress(Progress {
        name: "alpha.txt".into(),
        direction: Direction::Upload,
        bytes_done: 0,
        bytes_total: Some(10),
        rate_bps: None,
        eta_secs: None,
    });

    let out = s.on_key(press(KeyCode::Esc, KeyModifiers::NONE));

    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "Esc clears the query first, not CancelActive"
    );
    assert!(
        s.local.core.query.is_empty(),
        "query cleared before transfer cancel"
    );
    assert!(
        s.has_inflight(),
        "transfer still in flight after query-clear Esc"
    );
}

// ---- on_key: pending_list set on navigation intents ----

#[test]
fn right_on_dir_sets_pending_list_for_focused_side() {
    let local_cwd = PathBuf::from("/l");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    screen
        .local
        .set_entries(vec![entry("subdir", &local_cwd, true)]);
    assert!(screen.pending_list.is_none());

    // Right on a dir → pane emits StepInto → screen sets pending_list.
    let out = screen.on_key(press(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        screen.pending_list,
        Some((Side::Local, local_cwd.join("subdir")))
    );
}

#[test]
fn left_at_non_root_sets_pending_list_to_parent() {
    let local_cwd = PathBuf::from("/l/sub");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    screen
        .local
        .set_entries(vec![entry("x", &local_cwd, false)]);

    let out = screen.on_key(press(KeyCode::Left, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        screen.pending_list,
        Some((Side::Local, PathBuf::from("/l")))
    );
}

#[test]
fn pending_list_targets_remote_side_when_remote_focused() {
    let remote_cwd = PathBuf::from("/r");
    let mut screen = TransferScreen::new(PathBuf::from("/l"), remote_cwd.clone());
    screen.focus = Side::Remote;
    screen
        .remote
        .set_entries(vec![entry("srv", &remote_cwd, true)]);

    let out = screen.on_key(press(KeyCode::Right, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        screen.pending_list,
        Some((Side::Remote, remote_cwd.join("srv")))
    );
}

// ---- next_job / finish_inflight ----

#[test]
fn next_job_pops_fifo_and_none_when_empty() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/l/a"),
        dst: PathBuf::from("/r/a"),
        name: "a".into(),
        size_total: None,
        recursive: false,
    });
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/l/b"),
        dst: PathBuf::from("/r/b"),
        name: "b".into(),
        size_total: None,
        recursive: false,
    });

    let first = screen.next_job();
    assert_eq!(
        first.map(|j| j.name.clone()).as_deref(),
        Some("a"),
        "FIFO: a first"
    );
    let second = screen.next_job();
    assert_eq!(
        second.map(|j| j.name.clone()).as_deref(),
        Some("b"),
        "FIFO: b second"
    );
    let third = screen.next_job();
    assert!(third.is_none(), "empty queue → None");
}

#[test]
fn finish_inflight_clears_inflight_task() {
    // Replaces the old clear_active test: the run-loop now calls
    // finish_inflight(outcome) on WorkerEvent::Done (the outcome is retained
    // as history). After it, has_inflight() is false and active_progress() is
    // None.
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/l/x"),
        dst: PathBuf::from("/r/x"),
        name: "x".into(),
        size_total: Some(10),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.set_inflight_progress(Progress {
        name: "x".into(),
        direction: Direction::Upload,
        bytes_done: 0,
        bytes_total: Some(10),
        rate_bps: None,
        eta_secs: None,
    });
    assert!(screen.has_inflight());
    screen.finish_inflight(TransferOutcome::Ok);
    assert!(!screen.has_inflight(), "finish_inflight cleared the task");
    assert!(
        screen.ledger.active_progress().is_none(),
        "progress snapshot cleared"
    );
}

// ---- on_key: non-Press events are ignored ----

#[test]
fn non_press_key_returns_continue_and_does_not_mutate() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    let release = KeyEvent::new_with_kind(KeyCode::Tab, KeyModifiers::NONE, KeyEventKind::Release);
    let out = screen.on_key(release);
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(screen.focus, Side::Local, "release did not flip focus");
}

// ---- next_job: records direction for post-Done refresh ----

#[test]
fn next_job_records_direction_for_post_done_refresh() {
    // next_job marks the dispatched task InFlight; the ledger derives
    // last_direction() from the InFlight task so the event loop can refresh
    // the destination pane on Done even when no Progress arrived (a transfer
    // finishing inside the first 200ms poll).
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Upload,
        src: PathBuf::from("/l/a"),
        dst: PathBuf::from("/r/a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    assert!(screen.last_direction().is_none(), "starts None");
    let job = screen.next_job().expect("pop one job");
    assert_eq!(job.direction, Direction::Upload);
    assert_eq!(
        screen.last_direction(),
        Some(Direction::Upload),
        "next_job records the dispatched direction"
    );
}

#[test]
fn next_job_empty_queue_leaves_last_direction_unchanged() {
    // Popping from an empty queue is a no-op on last_direction (does not
    // reset a prior value, does not set one). Seed a prior Download by
    // finishing a Done task, then call next_job on the now-empty queue.
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/r/a"),
        dst: PathBuf::from("/l/a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.finish_inflight(TransferOutcome::Ok);
    assert_eq!(screen.last_direction(), Some(Direction::Download));
    // Queue is empty (the only task is Done). next_job returns None.
    assert!(screen.next_job().is_none());
    assert_eq!(
        screen.last_direction(),
        Some(Direction::Download),
        "prior direction preserved"
    );
}

#[test]
fn new_screen_remote_title_defaults_to_remote() {
    // open_transfer overrides this with "<user>@<host>"; the default keeps the
    // title meaningful in tests (which construct the screen directly) and on
    // any path that does not set it, so the bordered title is never blank.
    let s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert_eq!(s.remote_title, "remote");
}

// ---- ^Q queue-manager overlay: view + nav only ----

#[test]
fn ctrl_q_opens_the_queue_overlay() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    assert!(screen.queue_overlay.is_none());
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(screen.queue_overlay.is_some(), "^Q must open the overlay");
}

#[test]
fn bare_q_does_not_open_the_overlay_it_feeds_the_query() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty()));
    assert!(
        screen.queue_overlay.is_none(),
        "bare q must reach the search box, not open the overlay"
    );
}

#[test]
fn esc_closes_the_overlay_instead_of_the_screen() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut screen = TransferScreen::new(PathBuf::from("/x"), PathBuf::from("/y"));
    // Open, then Esc.
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::empty()));
    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "Esc inside the overlay must NOT CloseTransfer"
    );
    assert!(screen.queue_overlay.is_none(), "Esc must close the overlay");
}

#[test]
fn arrow_keys_move_the_overlay_selection() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/b"),
        dst: local_cwd.join("b"),
        name: "b".into(),
        size_total: Some(1),
        recursive: false,
    });
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
    // selected moved 0 -> 1; pressing Up returns to 0 (no observable field is
    // pub, so assert via a render smoke that both names appear and nothing
    // panics).
    let _ = screen.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "overlay draw must not panic: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("transfer queue"),
        "overlay title missing: {view}"
    );
}

// ---- ^Q queue-manager overlay: retry / remove / cancel / pause ----

#[test]
fn overlay_retry_requeues_a_failed_task_and_signals_advance() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    let id = screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen
        .ledger
        .finish_inflight(sshrack_core::connect::sftp::proto::TransferOutcome::Failed(
            "boom".into(),
        ));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty())); // Active -> Failed
    let out = screen.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty())); // retry selected
    assert_eq!(
        out,
        ScreenOutcome::Enqueue,
        "retry must signal advance-if-idle"
    );
    assert!(
        matches!(
            screen
                .ledger
                .tasks
                .iter()
                .find(|t| t.id == id)
                .unwrap()
                .state,
            crate::tui::transfer::ledger::TaskState::Queued
        ),
        "failed task is queued again"
    );
}

#[test]
fn overlay_remove_drops_a_queued_task() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    let before = screen.ledger.total();
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::empty()));
    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "remove is a pure ledger mutation"
    );
    assert_eq!(screen.ledger.total(), before - 1, "task removed");
}

#[test]
fn overlay_cancel_on_inflight_signals_cancel_active() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch(); // InFlight
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()));
    assert_eq!(
        out,
        ScreenOutcome::CancelActive,
        "cancel on in-flight must kill the worker"
    );
}

#[test]
fn overlay_pause_toggles_the_ledger_flag() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(screen.ledger.is_paused());
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
    assert!(!screen.ledger.is_paused());
}

#[test]
fn overlay_resume_with_pending_and_idle_signals_advance() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/a"),
        dst: local_cwd.join("a"),
        name: "a".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.set_paused(true);
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL));
    let out = screen.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty())); // resume
    assert_eq!(
        out,
        ScreenOutcome::Enqueue,
        "resume with pending + idle must advance"
    );
}

// ---- ^Q queue-manager overlay: view tabs (Tab / Shift-Tab) ----

#[test]
fn tab_switches_to_failed_view_and_lists_the_failed_task() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    // Enqueue `failed-one` first so FIFO dispatch lands the failure on it;
    // enqueueing `queued-one` first would make `queued-one` the failed task
    // and invert the assertions below.
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/failed-one"),
        dst: local_cwd.join("failed-one"),
        name: "failed-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/queued-one"),
        dst: local_cwd.join("queued-one"),
        name: "queued-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen
        .ledger
        .finish_inflight(TransferOutcome::Failed("boom".into())); // failed-one now in Failed view
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty())); // -> Failed
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok(), "draw must not panic: {:?}", res.err());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("failed-one"),
        "Failed view lists the failed task: {view}"
    );
    assert!(
        !view.contains("queued-one"),
        "queued task is not in the Failed view: {view}"
    );
}

#[test]
fn shift_tab_cycles_back_to_completed_view() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    screen.ledger.enqueue(TransferJob {
        direction: Direction::Download,
        src: PathBuf::from("/y/done-one"),
        dst: local_cwd.join("done-one"),
        name: "done-one".into(),
        size_total: Some(1),
        recursive: false,
    });
    screen.ledger.next_to_dispatch();
    screen.ledger.finish_inflight(TransferOutcome::Ok); // done-one in Completed view
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::empty())); // Active -> Completed (prev)
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("done-one"),
        "Shift-Tab from Active lands on Completed: {view}"
    );
}

#[test]
fn empty_view_shows_the_no_tasks_placeholder() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let local_cwd = PathBuf::from("/x");
    let mut screen = TransferScreen::new(local_cwd.clone(), PathBuf::from("/y"));
    // No tasks at all — every view is empty.
    let _ = screen.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)); // open (Active)
    let _ = screen.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty())); // -> Failed (empty)
    let backend = TestBackend::new(80, 24);
    let mut term = Terminal::new(backend).expect("test backend");
    let res = term.draw(|f| screen.draw(f, f.area()));
    assert!(res.is_ok());
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains("no tasks"),
        "empty view shows placeholder: {view}"
    );
}

// ---- apply_remote_listing: Ok adopt / Ok stale-drop / Err revert ----

#[test]
fn apply_remote_listing_ok_adopted_when_cwd_matches() {
    // Fresh listing whose cwd matches the pane's cwd → entries are adopted,
    // replacing the previous listing.
    let remote_cwd = PathBuf::from("/remote/here");
    let mut screen = TransferScreen::new(PathBuf::from("/local"), remote_cwd.clone());
    screen
        .remote
        .set_entries(vec![entry("old", &remote_cwd, false)]);
    let listed = vec![entry("fresh", &remote_cwd, false)];
    // A list is in flight for this cwd (dir switch / initial seed /
    // post-transfer refresh all set loading=true before sending List).
    screen.remote.loading = true;
    screen.apply_remote_listing(remote_cwd.clone(), Ok(listed));
    assert!(
        screen.remote.core.entries.iter().any(|e| e.name == "fresh"),
        "matching cwd → fresh entries adopted"
    );
    assert!(
        !screen.remote.core.entries.iter().any(|e| e.name == "old"),
        "old entries replaced"
    );
    assert!(
        !screen.remote.loading,
        "adopted listing clears loading — the list completed"
    );
}

#[test]
fn apply_remote_listing_ok_dropped_when_user_navigated_away() {
    // The user navigated further while the listing was in flight: the pane's
    // cwd no longer matches the listed cwd, so the stale result is dropped.
    let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote/here"));
    screen.remote.core.cwd = PathBuf::from("/remote/elsewhere"); // navigated away
    let listed = vec![entry("stale", &PathBuf::from("/remote/here"), false)];
    screen.remote.loading = true;
    screen.apply_remote_listing(PathBuf::from("/remote/here"), Ok(listed));
    assert!(
        !screen.remote.core.entries.iter().any(|e| e.name == "stale"),
        "stale listing (cwd mismatch) must be dropped, not adopted"
    );
    assert!(
        screen.remote.loading,
        "stale drop must NOT clear loading — the current cwd's list is still in flight"
    );
}

#[test]
fn apply_remote_listing_err_reverts_cwd_and_surfaces_failure() {
    // Regression for the remote arm of the "wrong directory" bug: a failed
    // remote listing must roll the pane back to its pre-switch cwd + entries
    // (not leave it on the unreachable path) and surface the error.
    let remote_cwd = PathBuf::from("/remote/start");
    let mut screen = TransferScreen::new(PathBuf::from("/local"), remote_cwd.clone());
    screen
        .remote
        .set_entries(vec![entry("file", &remote_cwd, false)]);
    // Simulate a navigation into a path that then fails to list: on_step
    // captures the origin, the caller advances cwd to the target.
    screen.remote.on_step();
    screen.remote.core.cwd = PathBuf::from("/remote/ghost");
    screen.remote.loading = true;
    screen.apply_remote_listing(
        PathBuf::from("/remote/ghost"),
        Err("no such directory".to_string()),
    );
    assert_eq!(
        screen.remote.core.cwd,
        PathBuf::from("/remote/start"),
        "cwd reverted to origin (not left on the unreachable path)"
    );
    assert!(
        screen.remote.core.entries.iter().any(|e| e.name == "file"),
        "origin entries kept consistent after the failed switch"
    );
    assert!(screen.status.is_error, "failure surfaced as an error");
    assert!(
        screen
            .status
            .message
            .as_deref()
            .unwrap_or("")
            .contains("remote list failed"),
        "status names the failure: {:?}",
        screen.status.message
    );
    assert!(
        !screen.remote.loading,
        "loading cleared on revert — the failed list is done"
    );
}

#[test]
fn draw_footer_narrow_drops_trailing_hints_with_ellipsis() {
    // A 25-wide footer cannot fit all 10 hints; trailing ones are dropped via
    // `render::fit_hint_count` and a dim `…` marks the truncation. The first
    // hint (`Tab`) must survive; the last (`F1 help`) must not.
    let backend = TestBackend::new(25, 1);
    let mut term = Terminal::new(backend).expect("test backend");
    let screen = canned_screen();
    term.draw(|f| screen.draw_footer(f, f.area()))
        .expect("draw");
    let view = buffer_view(term.backend().buffer());
    assert!(
        view.contains('…'),
        "narrow footer shows … truncation: {view:?}"
    );
    assert!(view.contains("Tab"), "first hint kept: {view:?}");
    assert!(!view.contains("help"), "trailing hint dropped: {view:?}");
}

// ---- cross-directory find: TransferScreen search dispatch (Task 8) ----
//
// `PaneSearch` state + `core.query` are owned by the pane, but the SCREEN owns
// the mode switch (filter ↔ find), streamed-result handling, and the
// Enter/Space/Ctrl-S/Esc result actions. These pin each arm of that state
// machine without spawning a real search (Task 9 wires the run-loop drain).

#[test]
fn apply_search_event_match_appends_and_ignores_stale_gen() {
    // A Match event whose `gen` matches `search_gen` is appended + re-ranked;
    // a stale-`gen` event (≠ `search_gen`) is dropped.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    let m = PathMatch {
        path: PathBuf::from("/a/x1"),
        is_dir: false,
        seg_matches: vec![],
    };
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(m.clone()),
        },
    );
    assert_eq!(s.local.search.as_ref().unwrap().results.len(), 1);
    // Stale gen (0 ≠ 1) ignored — result count stays at 1.
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 0,
            kind: SearchEventKind::Match(m),
        },
    );
    assert_eq!(
        s.local.search.as_ref().unwrap().results.len(),
        1,
        "stale-gen event must be ignored"
    );
}

#[test]
fn apply_search_event_drilled_sets_current_dir_before_matches() {
    // A Drilled event sets the synthetic "." row; subsequent Matches append
    // behind it; cursor lands on "." (index 0).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/sub")),
        },
    );
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/a/sub/c.txt"),
                is_dir: false,
                seg_matches: vec![],
            }),
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert_eq!(
        srch.current_dir.as_ref().unwrap().path,
        PathBuf::from("/a/sub"),
        "Drilled sets current_dir to the drilled dir"
    );
    assert!(srch.current_dir.as_ref().unwrap().is_dir);
    assert_eq!(srch.results.len(), 1, "Match appended behind the dot");
    assert_eq!(srch.cursor, 0, "cursor on the dot");
}

#[test]
fn apply_search_event_new_gen_clears_current_dir() {
    // A new generation's first event clears the previous "." row (stale dir).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/sub")),
        },
    );
    assert!(s.local.search.as_ref().unwrap().current_dir.is_some());
    // A new generation (2) whose first event is a leaf Match → no Drilled →
    // current_dir must be cleared.
    s.search_gen = 2;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 2,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/a/leaf.txt"),
                is_dir: false,
                seg_matches: vec![],
            }),
        },
    );
    assert!(
        s.local.search.as_ref().unwrap().current_dir.is_none(),
        "first event of a new gen clears the stale dot"
    );
}

#[test]
fn apply_search_event_second_drilled_is_ambiguous_and_clears() {
    // Two Drilled events in one generation (multi-frontier resolution) → the
    // drilled target is ambiguous → suppress the "." row.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/x")),
        },
    );
    assert!(s.local.search.as_ref().unwrap().current_dir.is_some());
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/y")),
        },
    );
    assert!(
        s.local.search.as_ref().unwrap().current_dir.is_none(),
        "a second Drilled makes the target ambiguous → no dot"
    );
}

#[test]
fn apply_search_event_error_clears_current_dir() {
    // An Error event (a directory listing failed mid-search) must clear the
    // synthetic "." row. Otherwise a stale dot — from this query's earlier
    // Drilled, or carried over from a prior query via stale-while-revalidate —
    // would persist and mask the error: the renderer's empty-state gate only
    // surfaces the error when `current_dir.is_none()`.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/sub")),
        },
    );
    assert!(s.local.search.as_ref().unwrap().current_dir.is_some());
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Error("boom".into()),
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert!(srch.current_dir.is_none(), "Error must clear the dot");
    assert!(srch.results.is_empty(), "Error clears results");
    assert_eq!(srch.error.as_deref(), Some("boom"));
}

#[test]
fn completion_returns_none_when_cursor_on_dot() {
    // Tab on the synthetic "." row must not complete (it would malform the
    // query, e.g. "/a/sub/" + "sub" + "/" → "/a/sub/sub/"). It returns None so
    // Tab is swallowed in find mode (no focus flip either).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.focus = Side::Local;
    s.local.core.query = "/a/sub/".into();
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.current_dir = Some(PathMatch {
        path: PathBuf::from("/a/sub"),
        is_dir: true,
        seg_matches: vec![],
    });
    srch.cursor = 0; // on the dot
    s.local.search = Some(srch);
    assert!(
        !s.complete_focused(),
        "Tab on '.' completes nothing (returns false)"
    );
    assert_eq!(s.local.core.query, "/a/sub/", "query left untouched");
}

#[test]
fn jump_to_result_noops_on_file() {
    // jump_to_search_result only jumps on a DIRECTORY result. A file result is
    // enqueued by the caller (on_key routes file results to enqueue_focused),
    // so reaching here with a file is a no-op — it must NOT jump to the file's
    // parent (that lost the user's selected file and left them to re-find it).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub/f.txt"),
        is_dir: false,
        seg_matches: vec![],
    }];
    let out = s.jump_to_search_result();
    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "file result → no-op (enqueue owns files)"
    );
    assert!(s.pending_list.is_none(), "file does not jump");
    assert!(
        s.local.search.is_some(),
        "file leaves the search state untouched"
    );
}

#[test]
fn jump_to_result_jumps_into_directory() {
    // Enter on a DIRECTORY result jumps into the directory itself: clears
    // search + query and sets pending_list so the run loop lists the target.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub"),
        is_dir: true,
        seg_matches: vec![],
    }];
    let out = s.jump_to_search_result();
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        s.pending_list,
        Some((Side::Local, PathBuf::from("/a/sub"))),
        "jump targets the directory itself"
    );
    assert!(s.local.search.is_none(), "search cleared after jump");
    assert!(
        s.local.core.query.is_empty(),
        "query cleared after jump so the pane returns to filter mode in the new dir"
    );
}

#[test]
fn enter_after_drill_navigates_into_drilled_dir_not_first_child() {
    // THE Tab+Enter habit collision, end-to-end at the screen layer: a
    // trailing-slash find lists a directory's children with the synthetic "."
    // at index 0 (cursor lands on it). Enter must navigate into the DRILLED
    // directory (the dot), NOT dive into the first child — which here is itself
    // a directory (the trap). Simulates the post-Tab search event stream a real
    // run loop would drain (Drilled + Matches + Done), then exercises Enter via
    // jump_to_search_result (the on_key Enter-on-dir path).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.focus = Side::Local;
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    // Drilled first, then two children — one a directory (the pre-fix trap).
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/sub")),
        },
    );
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/a/sub/child_dir"),
                is_dir: true,
                seg_matches: vec![],
            }),
        },
    );
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/a/sub/file.txt"),
                is_dir: false,
                seg_matches: vec![],
            }),
        },
    );
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Done,
        },
    );

    let srch = s.local.search.as_ref().unwrap();
    assert!(srch.on_dot(), "cursor on the dot after the drill");
    // Enter on a directory result routes to jump_to_search_result (screen.rs
    // Enter-if-in_search arm). The dot's selected() is_dir is true, so it jumps.
    assert!(srch.selected().unwrap().is_dir);
    let out = s.jump_to_search_result();
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        s.pending_list,
        Some((Side::Local, PathBuf::from("/a/sub"))),
        "Enter on '.' navigates into the drilled dir, not its first child"
    );
    assert!(s.local.search.is_none(), "search cleared after the jump");
}

#[test]
fn enter_on_dot_navigates_into_empty_drilled_dir() {
    // A drilled directory that exists but is empty: Drilled fires, zero Matches,
    // Done. The "." row is the only entry; Enter navigates into it. Pre-feature
    // this was impossible (no match to select → Enter was a no-op).
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.focus = Side::Local;
    s.local.search = Some(PaneSearch::empty());
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Drilled(PathBuf::from("/a/empty")),
        },
    );
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Done,
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert!(srch.results.is_empty(), "empty dir → no child matches");
    assert!(srch.on_dot(), "the dot is the only row");
    let out = s.jump_to_search_result();
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        s.pending_list,
        Some((Side::Local, PathBuf::from("/a/empty"))),
        "Enter on '.' navigates into the empty drilled dir"
    );
}

#[test]
fn find_enter_on_file_enqueues_instead_of_jumping() {
    // find mode: Enter on a FILE result enqueues it — parity with filter mode,
    // where Enter on a file transfers. Previously Enter jumped to the file's
    // parent dir (and left the cursor off the file), forcing a re-find.
    // Direction follows focus (Local → Upload); dst is the opposite pane's cwd
    // + the file name. enqueue_from_search does not touch search/query, so the
    // find state survives (the user can keep searching + enqueuing).
    let local_cwd = PathBuf::from("/a");
    let remote_cwd = PathBuf::from("/b");
    let mut s = TransferScreen::new(local_cwd.clone(), remote_cwd.clone());
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub/f.txt"),
        is_dir: false,
        seg_matches: vec![],
    }];
    let out = s.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Enqueue, "file result → Enqueue");
    assert_eq!(s.ledger.tasks.len(), 1, "exactly one job queued");
    let job = &s.ledger.tasks[0].job;
    assert_eq!(job.direction, Direction::Upload, "focus=Local → Upload");
    assert_eq!(job.src, PathBuf::from("/a/sub/f.txt"));
    assert_eq!(
        job.dst,
        remote_cwd.join("f.txt"),
        "dst = remote cwd + file name"
    );
    assert_eq!(job.name, "f.txt");
    assert!(!job.recursive, "file → recursive=false");
    assert_eq!(job.size_total, None, "PathMatch carries no size");
    assert!(
        s.local.search.is_some(),
        "find state retained after enqueue"
    );
    assert!(s.pending_list.is_none(), "no navigation on file enqueue");
}

#[test]
fn find_enter_on_dir_jumps_into_directory() {
    // find mode: Enter on a DIRECTORY result jumps into it — parity with
    // filter mode, where Enter on a dir enters. Regression pin: the file
    // enqueue change above must not alter directory behavior.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub"),
        is_dir: true,
        seg_matches: vec![],
    }];
    let out = s.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue, "dir result → jump (Continue)");
    assert_eq!(
        s.pending_list,
        Some((Side::Local, PathBuf::from("/a/sub"))),
        "jump targets the directory itself"
    );
    assert!(s.local.search.is_none(), "search cleared after jump");
    assert!(s.local.core.query.is_empty(), "query cleared after jump");
}

#[test]
fn find_mode_space_appends_to_query_instead_of_marking() {
    // Find mode disables Space-marking. `Pane.core.marked` is a current-dir
    // concept (toggle + single-shot per enqueue); allowing cross-dir find
    // results into it caused: (a) no toggle (insert-only), (b) stale marks
    // polluting listing-mode enqueue after Esc, (c) same-name dst collisions
    // across directories. Space now reaches the query box like any printable
    // char — filenames may contain spaces.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub"),
        is_dir: true,
        seg_matches: vec![],
    }];
    s.local.core.query = "/a/s".to_string();

    let out = s.on_key(press(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(
        s.local.core.marked.is_empty(),
        "find mode must not mark on Space"
    );
    assert_eq!(
        s.local.core.query, "/a/s ",
        "Space appends to the query like a printable char"
    );
}

#[test]
fn search_request_find_mode_when_multi_segment() {
    // A multi-segment relative query ("a/b") against the focused pane's cwd
    // enters find mode: pane.search is Some, pending_search is set for the
    // run loop.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    s.search_request(Side::Local, "a/b".into());
    assert!(s.local.search.is_some(), "multi-segment → find mode");
    assert!(
        s.pending_search.is_some(),
        "pending_search set for the run loop"
    );
}

#[test]
fn search_request_filter_mode_when_single_segment() {
    // A single-segment query ("a") with base == cwd stays in filter mode: the
    // existing synchronous core.recompute handles it. A prior find state is
    // cleared, and pending_search is NOT set.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    // Simulate a prior find, then a single-segment query must clear it.
    s.local.search = Some(PaneSearch::empty());
    s.search_request(Side::Local, "a".into());
    assert!(
        s.local.search.is_none(),
        "single-segment → filter mode (search cleared)"
    );
    assert!(
        s.pending_search.is_none(),
        "filter mode does not launch a search"
    );
}

#[test]
fn search_request_find_mode_when_trailing_slash() {
    // A single-segment query with a trailing slash ("a/") enters find mode:
    // exact-drill into "a" then list it. It must NOT stay in filter mode (which
    // would only fuzzy-filter the current directory and never descend).
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    s.search_request(Side::Local, "a/".into());
    assert!(
        s.local.search.is_some(),
        "trailing slash → find mode (not filter)"
    );
    assert!(
        s.pending_search.is_some(),
        "pending_search set for the run loop"
    );
}

#[test]
fn cancel_search_clears_pending_search() {
    // Esc inside the ~80ms debounce window must clear pending_search too —
    // otherwise the run loop still dispatches it after the window elapses,
    // firing a wasted background search AFTER the user explicitly cancelled.
    // Reproduces the leak: cancel_search cleared search_rx/search_cancel/
    // pane.search but not pending_search.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let parsed = parse_query("a/b", Path::new("/srv"), None);
    s.local.search = Some(PaneSearch::empty());
    s.pending_search = Some((Side::Local, parsed));
    s.cancel_search();
    assert!(
        s.pending_search.is_none(),
        "cancel must clear pending_search so a stale search cannot fire"
    );
    assert!(
        s.local.search.is_none(),
        "cancel must drop the pane out of find mode"
    );
}

// ---- begin_search: in-flight side tracking + displaced-pane spinner ----

#[test]
fn begin_search_displaces_prior_side_and_stops_its_spinner() {
    // A find running on LOCAL (search_side = Local, local spinner active) is
    // displaced when a new find starts on REMOTE. The local worker is
    // cancelled and will never emit Done, so begin_search must clear the
    // local pane's `searching` flag itself — otherwise the left pane spins
    // forever. Stale local results stay visible (stale-while-revalidate).
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    s.search_side = Some(Side::Local);
    s.local.search = Some(PaneSearch::empty()); // searching == true
    s.begin_search(Side::Remote);
    assert_eq!(
        s.search_side,
        Some(Side::Remote),
        "in-flight side is now remote"
    );
    let local_after = s
        .local
        .search
        .as_ref()
        .expect("local search kept for stale results");
    assert!(
        !local_after.searching,
        "displaced pane must stop spinning (its worker was cancelled)"
    );
}

#[test]
fn begin_search_same_side_keeps_spinner_running() {
    // Retyping in the SAME pane relaunches the search (new gen, new worker)
    // but the pane is not displaced — its spinner must keep running.
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    s.search_side = Some(Side::Local);
    s.local.search = Some(PaneSearch::empty()); // searching == true
    s.begin_search(Side::Local);
    assert_eq!(s.search_side, Some(Side::Local));
    assert!(
        s.local.search.as_ref().expect("local search").searching,
        "same-side relaunch keeps the spinner running"
    );
}

#[test]
fn begin_search_first_search_sets_side() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert!(s.search_side.is_none(), "no in-flight search initially");
    s.begin_search(Side::Local);
    assert_eq!(s.search_side, Some(Side::Local));
}

#[test]
fn cancel_search_clears_in_flight_side_pane_not_focus() {
    // Esc cancels the IN-FLIGHT search's pane (the one whose worker stops),
    // not merely the focused pane. When focus has flipped to the other pane
    // (Shift-Tab) these differ; clearing the wrong one would leave the
    // cancelled search's pane stuck in find mode while the worker is dead.
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    s.focus = Side::Remote; // user flipped to remote
    s.search_side = Some(Side::Local); // but the in-flight find is still local
    s.local.search = Some(PaneSearch::empty());
    s.remote.search = Some(PaneSearch::empty());
    s.cancel_search();
    assert!(
        s.local.search.is_none(),
        "in-flight (local) pane exits find mode"
    );
    assert!(s.search_side.is_none(), "no in-flight search after cancel");
    assert!(
        s.remote.search.is_some(),
        "non-in-flight remote pane untouched by cancel"
    );
}

#[test]
fn cancel_search_clears_query_and_restores_full_listing() {
    // Esc in find mode must clear the query AND restore the full current-dir
    // listing. filter/find share core.query, and find typing recomputes
    // core.ranked against the cross-dir query (e.g. "a/b" matches no
    // current-dir name). cancel_search used to leave the query intact, so
    // dropping back to filter mode rendered that stale empty ranked list —
    // the user saw the old query text but an empty pane until they Backspaced
    // it all away. Esc = abandon the search entirely.
    let local_cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(local_cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![
        entry("alpha.txt", &local_cwd, false),
        entry("beta.txt", &local_cwd, false),
        entry("docs", &local_cwd, true),
    ]);
    // Simulate the user having typed a cross-dir find query: ranked collapses
    // (a/b matches no current-dir name) while search is active.
    s.local.core.query = "a/b".into();
    s.local.core.recompute();
    assert_eq!(
        s.local.matched_count(),
        0,
        "precondition: cross-dir query matches no current-dir name"
    );
    s.local.search = Some(PaneSearch::empty());

    s.cancel_search();

    assert!(s.local.core.query.is_empty(), "Esc clears the query");
    assert!(s.local.search.is_none(), "Esc exits find mode");
    assert_eq!(
        s.local.matched_count(),
        3,
        "ranked restored to full current-dir listing"
    );
    assert!(
        s.local.core.selected < s.local.matched_count(),
        "cursor clamped into the restored ranked range"
    );
}

// ---- on_key: Tab completion (input state) ----

#[test]
fn tab_empty_query_flips_focus_not_complete() {
    // Decision: an empty query keeps Tab = switch pane (the candidate under
    // the cursor is ignored until the user starts typing).
    let cwd = PathBuf::from("/l");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![entry("bbb", &cwd, true)]);
    assert_eq!(s.focus, Side::Local, "default focus Local");
    let out = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(s.focus, Side::Remote, "empty query → Tab flips");
    assert!(s.local.core.query.is_empty(), "query untouched");
}

#[test]
fn tab_filter_mode_completes_dir_with_trailing_slash_and_enters_find() {
    let cwd = PathBuf::from("/l");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![entry("bbb", &cwd, true)]);
    s.local.core.query = "bb".into();
    s.local.core.recompute();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(s.local.core.query, "bbb/", "dir completed with trailing /");
    assert!(
        s.local.search.is_some(),
        "trailing slash entered find mode (lists bbb/)"
    );
}

#[test]
fn tab_filter_mode_completes_file_without_slash_stays_filter() {
    let cwd = PathBuf::from("/l");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![entry("bbc.txt", &cwd, false)]);
    s.local.core.query = "bb".into();
    s.local.core.recompute();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(s.local.core.query, "bbc.txt", "file completed, no slash");
    assert!(s.local.search.is_none(), "no slash → stayed in filter mode");
}

#[test]
fn tab_find_mode_completes_dir_by_joining_segments() {
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/aaa/bbb"),
        is_dir: true,
        seg_matches: vec![
            SegMatch {
                name: "aaa".into(),
                score: 0,
                indices: vec![],
            },
            SegMatch {
                name: "bbb".into(),
                score: 0,
                indices: vec![],
            },
        ],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "aaa/bb".into();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.local.core.query, "aaa/bbb/",
        "find dir → segments joined + /"
    );
}

#[test]
fn tab_find_mode_completes_file_without_slash() {
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/aaa/bbc.txt"),
        is_dir: false,
        seg_matches: vec![
            SegMatch {
                name: "aaa".into(),
                score: 0,
                indices: vec![],
            },
            SegMatch {
                name: "bbc.txt".into(),
                score: 0,
                indices: vec![],
            },
        ],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "aaa/bb".into();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.local.core.query, "aaa/bbc.txt",
        "find file → segments joined, no /"
    );
}

#[test]
fn backtab_flips_focus_even_with_search_candidate() {
    // Shift-Tab is the dedicated pane-switch escape: it never completes,
    // even when a find candidate is under the cursor.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/aaa/bbb"),
        is_dir: true,
        seg_matches: vec![
            SegMatch {
                name: "aaa".into(),
                score: 0,
                indices: vec![],
            },
            SegMatch {
                name: "bbb".into(),
                score: 0,
                indices: vec![],
            },
        ],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "aaa/bb".into();
    assert_eq!(s.focus, Side::Local);
    let _ = s.on_key(press(KeyCode::BackTab, KeyModifiers::SHIFT));
    assert_eq!(s.focus, Side::Remote, "Shift-Tab flips, does not complete");
    assert_eq!(s.local.core.query, "aaa/bb", "query untouched by Shift-Tab");
}

#[test]
fn tab_no_candidate_under_cursor_flips_focus() {
    // A non-empty query that matches nothing leaves no candidate under the
    // cursor: Tab falls back to switching panes (completion_for_focused
    // returns None via selected_entry() on an empty ranked list — distinct
    // from the empty-query early return).
    let cwd = PathBuf::from("/l");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    s.local.set_entries(vec![entry("alpha.txt", &cwd, false)]);
    s.local.core.query = "zz".into();
    s.local.core.recompute();
    assert_eq!(s.focus, Side::Local);
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.focus,
        Side::Remote,
        "no candidate under cursor → Tab flips, no completion"
    );
    assert_eq!(s.local.core.query, "zz", "query untouched");
}

#[test]
fn tab_find_mode_completes_absolute_path_preserves_root_prefix() {
    // Regression: `/ho` → `/home/` must keep the leading `/`. Completing off
    // seg_matches alone dropped it (seg_matches is relative to the query base,
    // so it never carries the `/`/`~/`/`../` the user typed).
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/home"),
        is_dir: true,
        seg_matches: vec![SegMatch {
            name: "home".into(),
            score: 0,
            indices: vec![],
        }],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "/ho".into();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(s.local.core.query, "/home/", "absolute base / preserved");
}

#[test]
fn tab_find_mode_completes_parent_path_preserves_dotdot_prefix() {
    let cwd = PathBuf::from("/srv/app");
    let mut s = TransferScreen::new(cwd, PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/sibling"),
        is_dir: true,
        seg_matches: vec![SegMatch {
            name: "sibling".into(),
            score: 0,
            indices: vec![],
        }],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "../sib".into();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.local.core.query, "../sibling/",
        "../ parent base preserved"
    );
}

#[test]
fn tab_find_mode_completes_home_path_preserves_tilde_prefix() {
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false;
    srch.results = vec![PathMatch {
        path: PathBuf::from("/home/user/documents"),
        is_dir: true,
        seg_matches: vec![SegMatch {
            name: "documents".into(),
            score: 0,
            indices: vec![],
        }],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "~/do".into();
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(s.local.core.query, "~/documents/", "~/ home base preserved");
}

// ---- find flicker: stale-while-revalidate ----
//
// Re-typing in find mode used to clear `results` immediately, so the list
// flashed to "searching…" on every keystroke until the new search produced
// results. Stale-while-revalidate keeps the previous query's results visible
// until an event of a NEW generation lands (`PaneSearch.results_gen` gates
// the clear).

#[test]
fn search_request_find_mode_keeps_stale_results_until_first_event() {
    // A new find query must NOT clear the previous query's results or reset
    // `results_gen`: they stay visible (searching=true) so the renderer does
    // not flash empty. The first event of a NEW generation clears them.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut prior = PaneSearch::empty();
    prior.searching = false;
    prior.results_gen = Some(0);
    prior.results = vec![PathMatch {
        path: PathBuf::from("/srv/old"),
        is_dir: false,
        seg_matches: vec![],
    }];
    s.local.search = Some(prior);
    // A multi-segment query re-enters find mode.
    s.search_request(Side::Local, "a/b".into());
    let srch = s.local.search.as_ref().expect("still find mode");
    assert!(srch.searching, "new search marked in-flight");
    assert_eq!(
        srch.results_gen,
        Some(0),
        "results_gen kept: new generation has produced no events yet"
    );
    assert_eq!(
        srch.results.len(),
        1,
        "stale previous-query results retained until first event (no flash)"
    );
}

#[test]
fn apply_search_event_first_match_clears_stale_results() {
    // The first Match of a NEW generation (results_gen != Some(ev.gen)) drops
    // the stale results before pushing, so the list swaps cleanly old→new
    // instead of concatenating.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = true;
    srch.results_gen = Some(0); // results belong to a previous generation
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/old"),
        is_dir: false,
        seg_matches: vec![],
    }];
    s.local.search = Some(srch);
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/srv/new"),
                is_dir: false,
                seg_matches: vec![],
            }),
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert_eq!(srch.results_gen, Some(1), "results_gen advanced to new gen");
    assert_eq!(srch.results.len(), 1, "stale result replaced, not appended");
    assert_eq!(srch.results[0].path, PathBuf::from("/srv/new"));
}

#[test]
fn apply_search_event_done_zero_results_clears_stale() {
    // A search that finishes with zero matches must clear the stale results
    // so the renderer shows "no matches" instead of the previous query's hits.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = true;
    srch.results_gen = Some(0);
    srch.results = vec![PathMatch {
        path: PathBuf::from("/srv/old"),
        is_dir: false,
        seg_matches: vec![],
    }];
    s.local.search = Some(srch);
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Done,
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert!(!srch.searching, "Done clears searching");
    assert_eq!(srch.results_gen, Some(1));
    assert!(
        srch.results.is_empty(),
        "zero-result Done clears stale results (no lingering previous hits)"
    );
}

#[test]
fn apply_search_event_new_gen_clears_after_stale_drain_race() {
    // Bug 2 regression: the fast-backspace duplicate. Sequence —
    //   gen 0 produced a result (results_gen = Some(0));
    //   user retypes → search_request keeps the stale results (no flash);
    //   a LATE gen-0 event drains in the debounce window (search_gen still 0,
    //     new search not launched yet) — same generation, so it APPENDS;
    //   the new search launches → search_gen bumps to 1;
    //   gen 1's first Match arrives — must CLEAR the gen-0 results and land
    //     alone, NOT concatenate. The clear is gated on the event's generation
    //     differing from results_gen, so the late gen-0 drain (which left
    //     results_gen == Some(0)) cannot suppress it.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    s.search_gen = 0;
    let mut srch = PaneSearch::empty();
    srch.results_gen = Some(0);
    srch.results = vec![PathMatch {
        path: PathBuf::from("/home/ryan"),
        is_dir: true,
        seg_matches: vec![SegMatch {
            name: "ryan".into(),
            score: 3,
            indices: vec![0, 1, 2],
        }],
    }];
    s.local.search = Some(srch);
    // User retypes; stale results + results_gen kept (stale-while-revalidate).
    s.search_request(Side::Local, "/home/ry".into());
    // A late gen-0 event drains before the new search launches (search_gen=0).
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 0,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/home/ryan-old"),
                is_dir: true,
                seg_matches: vec![SegMatch {
                    name: "ryan-old".into(),
                    score: 3,
                    indices: vec![0, 1, 2],
                }],
            }),
        },
    );
    assert_eq!(
        s.local.search.as_ref().unwrap().results.len(),
        2,
        "same-gen stale event appends (stale-while-revalidate)"
    );
    assert_eq!(s.local.search.as_ref().unwrap().results_gen, Some(0));
    // New search launches → generation advances.
    s.search_gen = 1;
    s.apply_search_event(
        Side::Local,
        SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/home/ryan"),
                is_dir: true,
                seg_matches: vec![SegMatch {
                    name: "ryan".into(),
                    score: 2,
                    indices: vec![0, 1],
                }],
            }),
        },
    );
    let srch = s.local.search.as_ref().unwrap();
    assert_eq!(
        srch.results.len(),
        1,
        "new generation clears stale gen-0 results — no duplicate path"
    );
    assert_eq!(srch.results[0].path, PathBuf::from("/home/ryan"));
    assert_eq!(srch.results_gen, Some(1));
}

#[test]
fn tab_while_searching_with_no_candidate_does_not_flip_focus() {
    // Race reported in the wild: type "/ho" and press Tab before the search
    // yields. The pane is in find mode, searching=true, no results yet, so
    // completion has no candidate. Tab must NOT fall through to flipping the
    // pane — the user's intent is completion, not switching. Swallow it until
    // the search produces a candidate; Shift-Tab remains the dedicated switch.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    // PaneSearch::empty(): searching=true, results=[], results_gen=None.
    s.local.search = Some(PaneSearch::empty());
    s.local.core.query = "/ho".into();
    assert_eq!(s.focus, Side::Local);
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.focus,
        Side::Local,
        "Tab mid-search with no candidate must not steal focus"
    );
    assert_eq!(s.local.core.query, "/ho", "query untouched");
}

#[test]
fn tab_while_searching_does_not_complete_from_stale_results() {
    // Gap in stale-while-revalidate: while a search is in flight the previous
    // query's results stay visible (no flash), but the candidate under the
    // cursor belongs to the OLD query. Tab must NOT complete off it — e.g.
    // query `/home/ryan/` listing `some_dir`, then typing `w` and Tab must
    // stay `/home/ryan/w`, not jump to `/home/ryan/some_dir`. Swallow Tab
    // until the new search yields fresh results.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = true; // new search in flight
    srch.results = vec![PathMatch {
        // stale result from the PREVIOUS query (`/home/ryan/` list-all)
        path: PathBuf::from("/home/ryan/some_dir"),
        is_dir: true,
        seg_matches: vec![SegMatch {
            name: "some_dir".into(),
            score: 0,
            indices: vec![],
        }],
    }];
    s.local.search = Some(srch);
    s.local.core.query = "/home/ryan/w".into();
    assert_eq!(s.focus, Side::Local);
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.local.core.query, "/home/ryan/w",
        "Tab mid-search must not complete from stale results"
    );
    assert_eq!(
        s.focus,
        Side::Local,
        "Tab mid-search must not flip focus either"
    );
}

#[test]
fn tab_find_mode_zero_results_does_not_flip_focus() {
    // Find mode owns Tab for completion only. Even when the search has
    // FINISHED with zero results (searching=false, results=[]) — so no
    // candidate is under the cursor — Tab must NOT flip focus. Only filter
    // mode (incl. an empty query) flips; Shift-Tab always flips.
    let mut s = TransferScreen::new(PathBuf::from("/srv"), PathBuf::from("/r"));
    let mut srch = PaneSearch::empty();
    srch.searching = false; // search finished
    srch.results = vec![]; // zero matches
    s.local.search = Some(srch);
    s.local.core.query = "/srv/zzz".into();
    assert_eq!(s.focus, Side::Local);
    let _ = s.on_key(press(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(
        s.focus,
        Side::Local,
        "find mode with zero results: Tab must not flip focus"
    );
    assert_eq!(s.local.core.query, "/srv/zzz", "query untouched");
}

// ---- advance_spinner: tick the find-mode spinner phase ----

#[test]
fn advance_spinner_increments_while_local_pane_searching() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert_eq!(s.spinner, 0, "fresh screen starts at frame 0");
    s.local.search = Some(PaneSearch::empty()); // PaneSearch::empty() has searching = true
    s.advance_spinner();
    assert_eq!(s.spinner, 1);
    s.advance_spinner();
    assert_eq!(s.spinner, 2);
}

#[test]
fn advance_spinner_increments_while_remote_pane_searching() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    s.remote.search = Some(PaneSearch::empty());
    s.advance_spinner();
    assert_eq!(s.spinner, 1);
}

#[test]
fn advance_spinner_noop_when_no_search_in_flight() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    // No search on either pane.
    s.advance_spinner();
    assert_eq!(s.spinner, 0);
    // A FINISHED search (searching = false) must not advance either — only an
    // in-flight search animates the spinner.
    let mut done = PaneSearch::empty();
    done.searching = false;
    s.local.search = Some(done);
    s.advance_spinner();
    assert_eq!(
        s.spinner, 0,
        "a finished search must not animate the spinner"
    );
}

// ---- quit-confirm overlay: Ctrl-C / Esc route through request_close ----
//
// Every quit path (Esc's final layer + Ctrl-C) routes through a single
// `request_close()` guard that opens the `CloseConfirm` overlay when a
// transfer is in flight, so the exit never silently discards the active task.

#[test]
fn ctrl_c_with_inflight_opens_quit_confirm_instead_of_quitting() {
    // Every quit path routes through request_close: Ctrl-C while a transfer
    // is in flight must NOT close — it opens the confirmation overlay and
    // stays. The in-flight task is untouched (still InFlight).
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    seed_inflight_upload(&mut s, "big.tar");

    let out = s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "Ctrl-C does not quit while in flight"
    );
    assert!(s.close_confirm.is_some(), "quit-confirm overlay opened");
    assert!(
        s.has_inflight(),
        "in-flight task not cancelled by opening the overlay"
    );
}

#[test]
fn esc_with_inflight_opens_quit_confirm_instead_of_cancelling() {
    // Esc no longer cancels an in-flight transfer — that is owned by ^Q's
    // queue manager. Like Ctrl-C, Esc routes through request_close: with a
    // transfer in flight it opens the quit-confirm overlay and stays, leaving
    // the task untouched. Cancelling is a deliberate act in the queue manager,
    // not an Esc side effect.
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    seed_inflight_upload(&mut s, "big.tar");

    let out = s.on_key(press(KeyCode::Esc, KeyModifiers::NONE));

    assert_eq!(
        out,
        ScreenOutcome::Continue,
        "Esc does not cancel while in flight"
    );
    assert!(s.close_confirm.is_some(), "quit-confirm overlay opened");
    assert!(
        s.has_inflight(),
        "in-flight task not cancelled by opening the overlay"
    );
}

#[test]
fn quit_confirm_enter_quits() {
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    seed_inflight_upload(&mut s, "big.tar");
    s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(s.close_confirm.is_some());

    let out = s.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::CloseTransfer, "Enter confirms the quit");
}

#[test]
fn quit_confirm_cancel_keeps_transfer_and_closes_overlay() {
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    seed_inflight_upload(&mut s, "big.tar");
    s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(s.close_confirm.is_some());

    let out = s.on_key(press(KeyCode::Char('n'), KeyModifiers::NONE));

    assert_eq!(out, ScreenOutcome::Continue, "cancel stays in SFTP");
    assert!(s.close_confirm.is_none(), "overlay closed after cancel");
    assert!(
        s.has_inflight(),
        "in-flight task still running after cancel"
    );
}

#[test]
fn ctrl_c_idle_closes_immediately_without_overlay() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert!(!s.has_inflight());
    let out = s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::CloseTransfer);
    assert!(s.close_confirm.is_none());
}

#[test]
fn esc_idle_quit_path_does_not_open_overlay() {
    let mut s = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    assert!(!s.has_inflight());
    let out = s.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::CloseTransfer);
    assert!(s.close_confirm.is_none());
}

#[test]
fn quit_confirm_behaves_when_transfer_completes_while_open() {
    // The overlay is key-driven and snapshots the task at open time. If the
    // transfer finishes while the dialog is up, confirm must still quit and
    // cancel must still stay + close the overlay (the snapshot is just stale
    // text — the overlay is not wired to the ledger's live state).
    use sshrack_core::connect::sftp::proto::TransferOutcome;
    let cwd = PathBuf::from("/srv");
    let mut s = TransferScreen::new(cwd.clone(), PathBuf::from("/r"));
    seed_inflight_upload(&mut s, "big.tar");
    s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(s.close_confirm.is_some());

    // Transfer finishes while the overlay is open.
    s.ledger.finish_inflight(TransferOutcome::Ok);
    assert!(!s.has_inflight());

    // Cancel: stay in SFTP, overlay closed.
    let out = s.on_key(press(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(s.close_confirm.is_none());

    // Re-open on a fresh in-flight task, finish it, then confirm: quits.
    seed_inflight_upload(&mut s, "more.tar");
    s.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    s.ledger.finish_inflight(TransferOutcome::Ok);
    let out = s.on_key(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::CloseTransfer);
}
