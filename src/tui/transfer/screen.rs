//! Full-screen dual-pane transfer view for `sshrack sftp`: state + layout.
//!
//! [`TransferScreen`] owns the two [`Pane`]s (local + remote), the focus side,
//! the in-flight [`Progress`], the pending [`TransferJob`] queue, and the
//! consolidated [`Status`] line. [`TransferScreen::draw`] lays the screen out
//! as four vertical bands — title (1) / panes (Fill) / progress+queue panel
//! (4) / hotkey footer (1) — and delegates the pane-row painting to
//! [`super::render`].
//!
//! Architectural red line (shared with [`super::pane`]): `draw` performs no
//! I/O. The screen reads its own state plus the latest worker snapshots
//! (`active`, `queue`) the loop drained onto it; it never reads the network or
//! the filesystem. Key handling lands in Task 9 (`on_key`); this is render +
//! state only.

use std::path::PathBuf;

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use sshrack_core::connect::sftp::proto::{Progress, TransferJob};

use crate::tui::intent::Status;
use crate::tui::theme;
use crate::tui::transfer::pane::{Pane, Side};
use crate::tui::transfer::render;

/// The full-screen transfer view. Pure state plus a render entry point —
/// [`TransferScreen::draw`] lays out the screen and delegates pane painting to
/// [`render::draw_pane`]. Task 9 wires `on_key`; Task 10 wires the worker
/// handle + overwrite policy onto this struct.
///
/// Reachability note: Task 8 ships the state + pure render path; Task 9 wires
/// `on_key` and the `sshrack sftp` event loop, Task 10 wires the worker. Until
/// those land the screen is constructed only by tests + the
/// `transfer::touch_for_reachability` symbol mention, so methods that have no
/// test caller (the setters + private draw helpers) carry scoped
/// `#[allow(dead_code)]` rather than a blanket module-level allow. Each allow
/// drops automatically once Task 9/10 starts driving it.
#[derive(Debug, Clone)]
pub struct TransferScreen {
    /// The local-filesystem pane. Owns its cwd, entries, query, cursor, marks.
    pub local: Pane,
    /// The remote (SFTP) pane. Same shape as `local`; entries are worker-fed.
    pub remote: Pane,
    /// Which pane receives navigation keys. The other pane is rendered dim.
    pub focus: Side,
    /// The in-flight transfer snapshot, or `None` when nothing is running.
    pub active: Option<Progress>,
    /// Pending transfers, in take-order. The progress panel renders the count
    /// and the next 1–2 job names.
    pub queue: Vec<TransferJob>,
    /// The consolidated status line (rendered at the bottom of the progress
    /// panel). Carries the same transient one-liner feedback the rest of the
    /// app surfaces via [`Status`].
    pub status: Status,
}

impl TransferScreen {
    /// Construct a fresh screen with two empty panes at the given cwds, focus
    /// on Local, no active transfer, an empty queue, and an empty status.
    /// Pure: no I/O.
    ///
    /// Reachability: Task-9 sftp dispatch will construct the live screen; the
    /// Task-8 render path is exercised by tests only.
    #[allow(dead_code)]
    #[must_use]
    pub fn new(local_cwd: PathBuf, remote_cwd: PathBuf) -> Self {
        Self {
            local: Pane::new(Side::Local, local_cwd),
            remote: Pane::new(Side::Remote, remote_cwd),
            focus: Side::Local,
            active: None,
            queue: Vec::new(),
            status: Status::empty(),
        }
    }

    /// Set the focused side. Pure setter — Task 9 drives it off `Tab`.
    #[allow(dead_code)]
    pub fn set_focus(&mut self, side: Side) {
        self.focus = side;
    }

    /// Replace the in-flight transfer snapshot (or clear it with `None`).
    /// Pure setter — Task 10 drives it from drained worker events.
    #[allow(dead_code)]
    pub fn set_active(&mut self, progress: Option<Progress>) {
        self.active = progress;
    }

    /// Replace the consolidated status. Pure setter.
    #[allow(dead_code)]
    pub fn set_status(&mut self, status: Status) {
        self.status = status;
    }

    /// Append a transfer job to the queue. Pure mutator — Task 10 enqueues.
    #[allow(dead_code)]
    pub fn push_queue(&mut self, job: TransferJob) {
        self.queue.push(job);
    }

    /// Mutable accessor for the local pane. The screen never hands out `&mut`
    /// fields directly in `draw` (which takes `&self`); Task 9's `on_key` uses
    /// this to route per-pane key handling.
    #[allow(dead_code)]
    pub fn local_mut(&mut self) -> &mut Pane {
        &mut self.local
    }

    /// Mutable accessor for the remote pane. See [`Self::local_mut`].
    #[allow(dead_code)]
    pub fn remote_mut(&mut self) -> &mut Pane {
        &mut self.remote
    }

    /// Render the full screen into `area`: title band (1) / panes (Fill) /
    /// progress+queue panel (4) / hotkey footer (1). The panes split
    /// horizontally 50/50; each pane renders its own cwd row, filter box, and
    /// windowed list via [`render::draw_pane`]. The non-focused pane is dimmed
    /// overall. Pure: no I/O, no env access.
    ///
    /// Reachability: Task-9 sftp dispatch + event loop drives this; the Task-8
    /// render path is exercised by the screen tests.
    #[allow(dead_code)]
    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let [title_area, panes_area, panel_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .areas(area);

        self.draw_title(frame, title_area);

        let [local_area, remote_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes_area);

        render::draw_pane(frame, local_area, &self.local, self.focus == Side::Local);
        render::draw_pane(frame, remote_area, &self.remote, self.focus == Side::Remote);

        self.draw_progress_panel(frame, panel_area);
        self.draw_footer(frame, footer_area);
    }

    /// Title band: `sshrack sftp` accented on the left. The brand word goes
    /// through [`theme::brand_span`] so it stays in lockstep with the shell.
    fn draw_title(&self, frame: &mut Frame, area: Rect) {
        let line = Line::from(vec![
            theme::brand_span(),
            Span::styled(" sftp", theme::accent()),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    /// Progress + queue panel: a 4-row band. Row 1 holds the active transfer
    /// text plus a `Gauge`, or "no transfer in flight" when idle. Rows 2 and 3
    /// hold the queue count plus the next 1–2 job names (truncated to the panel
    /// width). Row 4 holds the consolidated status, or a default hotkey hint
    /// when empty.
    fn draw_progress_panel(&self, frame: &mut Frame, area: Rect) {
        let [row1, row2, row3, row4] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);

        render::draw_active_transfer(frame, row1, self.active.as_ref());

        // Row 2: queue count + first queued name (truncated). Empty queue →
        // a dim "queue: 0 items" so the row stays stable.
        let q2 = render::queue_summary_line(self.queue.len(), self.queue.first(), area.width);
        frame.render_widget(Paragraph::new(q2), row2);

        // Row 3: second queued name when present, otherwise blank.
        let q3 = render::queue_second_line(self.queue.get(1), area.width);
        frame.render_widget(Paragraph::new(q3), row3);

        // Row 4: status message or the default hotkey hint.
        let status_line = match &self.status.message {
            Some(msg) => {
                let style = if self.status.is_error {
                    Style::new().fg(theme::DANGER)
                } else {
                    Style::new()
                };
                Line::from(vec![
                    Span::styled("› ", Style::new().dim()),
                    Span::styled(msg.clone(), style),
                ])
            }
            None => Line::from(vec![Span::styled(
                "› press Space to mark, Ctrl-Enter to transfer",
                Style::new().dim(),
            )]),
        };
        frame.render_widget(status_line, row4);
    }

    /// Hotkey footer: one dot-separated hint line. Keys take the accent color;
    /// labels are dim. Mirrors [`crate::tui::shell::draw_shell`]'s footer
    /// styling so the transfer screen reads as part of the app.
    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let hints: &[(&str, &str)] = &[
            ("Tab", "switch"),
            ("↑↓", "move"),
            ("→", "open"),
            ("Space", "mark"),
            ("^⏎", "transfer"),
            ("Esc", "cancel"),
            ("^C", "close"),
        ];
        let mut spans: Vec<Span> = Vec::with_capacity(hints.len() * 3);
        for (i, (k, label)) in hints.iter().enumerate() {
            if i > 0 {
                spans.push(Span::styled(" · ", Style::new().dim()));
            }
            spans.push(Span::styled(
                *k,
                theme::accent().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

#[cfg(test)]
mod tests {
    //! Render smoke + small-terminal tests for the transfer screen. The screen
    //! is a thin layer over [`super::render`] and [`super::Pane`], so these
    //! tests exercise the layout wiring (no panic, no overflow, focused row
    //! stays in view) rather than re-asserting per-pane painting.
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
        // Active upload.
        screen.active = Some(Progress {
            name: "alpha.txt".into(),
            direction: Direction::Upload,
            bytes_done: 256,
            bytes_total: Some(1024),
            rate_bps: Some(128),
            eta_secs: Some(6),
        });
        // One queued job.
        screen.queue.push(TransferJob {
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
        // Queue row.
        assert!(view.contains("queue"), "queue label missing: {view}");

        // Footer hotkeys.
        assert!(view.contains("Tab"), "footer Tab missing: {view}");
        assert!(view.contains("Space"), "footer Space missing: {view}");
        assert!(view.contains("^⏎"), "footer ^⏎ missing: {view}");

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
    fn draw_shows_no_transfer_in_flight_when_idle() {
        let backend = TestBackend::new(70, 20);
        let mut term = Terminal::new(backend).expect("test backend");
        let mut screen = canned_screen();
        screen.active = None;
        term.draw(|f| screen.draw(f, f.area())).expect("draw");
        let view = buffer_view(term.backend().buffer());
        assert!(
            view.contains("no transfer in flight"),
            "idle progress row missing: {view}"
        );
    }

    #[test]
    fn draw_handles_unknown_total_without_gauge_panic() {
        // `bytes_total` = None must render the "transferred…" form without a
        // Gauge (a missing percent would have panicked `Gauge::percent`).
        let backend = TestBackend::new(70, 20);
        let mut term = Terminal::new(backend).expect("test backend");
        let mut screen = canned_screen();
        screen.active = Some(Progress {
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
}
