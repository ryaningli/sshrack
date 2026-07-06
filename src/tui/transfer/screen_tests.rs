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
use ratatui::{Terminal, backend::TestBackend};
use sshrack_core::connect::sftp::parse::strip_control_chars;
use sshrack_core::connect::sftp::proto::{Direction, Progress, TransferJob};
use sshrack_core::dirsource::DirEntry;
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
    screen.local.marked.insert(local_cwd.join("alpha.txt"));
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
    // Summary row (Task 3 collapsed the 4-row panel into a 2-row band).
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
    // `bytes_total` = None must render the "transferred…" form without a
    // Gauge (a missing percent would have panicked `Gauge::percent`).
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
    assert!(
        view.contains("stream.bin") && view.contains("transferred"),
        "unknown-total row missing: {view}"
    );
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
        screen.remote.selected = (screen.remote.selected + 1) % 30;
    }
    assert_eq!(screen.remote.selected, 29);
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
    assert!(screen.local.marked.is_empty(), "no marks initially");

    // Space must NOT be pre-empted at the screen level — it reaches the
    // focused pane and toggles the mark on the cursor entry.
    let out = screen.on_key(press(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(out, ScreenOutcome::Continue);
    assert!(
        screen.local.marked.contains(&local_cwd.join("alpha.txt")),
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
    screen.local.marked.insert(local_cwd.join("alpha.txt"));

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
        screen.local.marked.is_empty(),
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
    screen.remote.marked.insert(remote_cwd.join("server.log"));

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
    screen.local.marked.insert(local_cwd.join("docs"));

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
    screen.local.marked.insert(local_cwd.join("docs"));
    screen.local.marked.insert(local_cwd.join("alpha.txt"));

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
    screen.local.marked.insert(local_cwd.join("beta.txt"));

    let out = screen.on_key(press(KeyCode::Char('s'), KeyModifiers::CONTROL));
    assert_eq!(out, ScreenOutcome::Enqueue);
    assert_eq!(screen.ledger.tasks.len(), 1, "only the marked entry queued");
    assert_eq!(screen.ledger.tasks[0].job.src, local_cwd.join("beta.txt"));
    assert!(
        screen.local.marked.is_empty(),
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
    assert_eq!(screen.local.query, "s", "bare 's' reaches the filter box");
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
