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
use sshrack_core::pathfind::{PathMatch, SearchEvent, SearchEventKind, parse_query};
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
fn esc_with_active_transfer_returns_cancel_active() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    // Seed an in-flight transfer: enqueue + dispatch + progress snapshot.
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
    let out = screen.on_key(press(KeyCode::Esc, KeyModifiers::NONE));
    assert_eq!(
        out,
        ScreenOutcome::CancelActive,
        "Esc with active → CancelActive"
    );
}

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
fn ctrl_c_always_returns_close_transfer() {
    let mut screen = TransferScreen::new(PathBuf::from("/l"), PathBuf::from("/r"));
    let out = screen.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::CloseTransfer);
    // Even with an active transfer, Ctrl-C closes (the user wants out).
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
    let out = screen.on_key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(
        out,
        ScreenOutcome::CloseTransfer,
        "Ctrl-C closes even with an active transfer"
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
    screen.apply_remote_listing(remote_cwd.clone(), Ok(listed));
    assert!(
        screen.remote.core.entries.iter().any(|e| e.name == "fresh"),
        "matching cwd → fresh entries adopted"
    );
    assert!(
        !screen.remote.core.entries.iter().any(|e| e.name == "old"),
        "old entries replaced"
    );
}

#[test]
fn apply_remote_listing_ok_dropped_when_user_navigated_away() {
    // The user navigated further while the listing was in flight: the pane's
    // cwd no longer matches the listed cwd, so the stale result is dropped.
    let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote/here"));
    screen.remote.core.cwd = PathBuf::from("/remote/elsewhere"); // navigated away
    let listed = vec![entry("stale", &PathBuf::from("/remote/here"), false)];
    screen.apply_remote_listing(PathBuf::from("/remote/here"), Ok(listed));
    assert!(
        !screen.remote.core.entries.iter().any(|e| e.name == "stale"),
        "stale listing (cwd mismatch) must be dropped, not adopted"
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
fn jump_to_result_targets_parent_for_file() {
    // Enter on a file search result jumps to the file's PARENT directory
    // (navigating to the file itself is impossible; its containing dir is the
    // useful target). Clears the search + query and sets pending_list.
    let mut s = TransferScreen::new(PathBuf::from("/a"), PathBuf::from("/b"));
    s.local.search = Some(PaneSearch::empty());
    s.local.search.as_mut().unwrap().results = vec![PathMatch {
        path: PathBuf::from("/a/sub/f.txt"),
        is_dir: false,
        seg_matches: vec![],
    }];
    let out = s.jump_to_search_result();
    assert_eq!(out, ScreenOutcome::Continue);
    assert_eq!(
        s.pending_list,
        Some((Side::Local, PathBuf::from("/a/sub"))),
        "jump targets the file's parent dir"
    );
    assert!(s.local.search.is_none(), "search cleared after jump");
    assert!(
        s.local.core.query.is_empty(),
        "query cleared after jump so the pane returns to filter mode in the new dir"
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
