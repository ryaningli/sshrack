//! Full-screen dual-pane transfer view for `sshrack sftp`: state + layout +
//! pure key routing.
//!
//! [`TransferScreen`] owns the two [`Pane`]s (local + remote), the focus side,
//! the in-flight [`Progress`], the pending [`TransferJob`] queue, and the
//! consolidated [`Status`] line. [`TransferScreen::draw`] lays the screen out
//! as four vertical bands — title (1) / panes (Fill) / progress+queue panel
//! (4) / hotkey footer (1) — and delegates the pane-row painting to
//! [`super::render`]. [`TransferScreen::on_key`] is the pure key router; the
//! queue-advance helpers ([`TransferScreen::next_job`] /
//! [`TransferScreen::clear_active`]) are the seam Task 10's event loop drives.
//!
//! Architectural red line (shared with [`super::pane`]): `draw`, `on_key`, and
//! the queue helpers perform no I/O. The screen reads its own state plus the
//! latest worker snapshots (`active`, `queue`) the loop drained onto it; it
//! never reads the network or the filesystem. Worker wiring lands in Task 10.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use sshrack_core::connect::sftp::proto::{Direction, OverwritePolicy, Progress, TransferJob};

use crate::tui::intent::Status;
use crate::tui::theme;
use crate::tui::transfer::pane::{Pane, PaneOutcome, Side};
use crate::tui::transfer::render;

/// Pure intent returned by [`TransferScreen::on_key`]. The screen mutates its
/// own focus / marks / queue / `pending_list`; this intent tells the
/// Task-10 event loop what side effect to perform (worker send, popup,
/// quit). Mirrors [`PaneOutcome`] in shape — enum-rather-than-`Option` so the
/// loop's match stays exhaustive over the action vocabulary.
///
/// Naming: `ScreenOutcome` (not `TransferOutcome`) deliberately, to avoid
/// collision with [`sshrack_core::connect::sftp::proto::TransferOutcome`], the
/// worker's per-job result enum (`Ok`/`Cancelled`/`Failed`). The two types
/// cross paths in the Task-10 loop (which drains `WorkerEvent::Done(proto)`
/// and routes `screen.on_key()`'s result), so giving them the same name would
/// force an alias at every import site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenOutcome {
    /// The key was consumed (or ignored); no side effect is needed. The
    /// screen's own state already reflects the result (focus flip, cursor
    /// move, mark toggle, queue append, `pending_list` set).
    Continue,
    /// Close the transfer screen and return to the launcher. `Ctrl-C` and
    /// `Esc` (with no active transfer) emit this.
    CloseTransfer,
    /// Cancel the in-flight transfer — the loop sends `WorkerCmd::Cancel`.
    /// `Esc` with an active transfer emits this.
    CancelActive,
    /// One or more jobs were appended to [`TransferScreen::queue`]. The loop
    /// calls [`TransferScreen::next_job`] to dispatch the first one if no
    /// transfer is currently active. `Ctrl-Enter` emits this.
    Enqueue,
}

/// The full-screen transfer view. Pure state plus a render entry point —
/// [`TransferScreen::draw`] lays out the screen and delegates pane painting to
/// [`render::draw_pane`]. [`TransferScreen::on_key`] is the pure key router;
/// Task 10 wires the worker handle + overwrite-policy popup onto this struct.
///
/// Reachability note: Task 8 shipped the state + pure render path; Task 9
/// added the pure `on_key` router + queue-advance helpers; Task 10 wires the
/// `sshrack sftp` event loop that drives all of it. Until Task 10 lands the
/// screen is constructed only by tests, so methods that have no test caller
/// (the setters + private draw helpers + the new key router) carry scoped
/// `#[allow(dead_code)]` with the Task-10 consumer named in the doc comment —
/// no blanket module-level allow is in use.
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
    /// The next directory listing the screen wants the worker to fetch, set by
    /// [`on_key`](Self::on_key) when the focused pane emits `StepInto` /
    /// `StepUp` / `RequestList`. `None` when no list is pending. The Task-10
    /// loop reads this after each keypress, dispatches the `WorkerCmd::List`
    /// (or sync `LocalDirSource::list` for the local side), feeds the result
    /// back via [`Pane::set_entries`], and clears the field. Pure: setting
    /// this performs no I/O.
    pub pending_list: Option<(Side, PathBuf)>,
    /// The user's batch-level overwrite answer, set by the Task-10 loop after
    /// the first overwrite popup (`OverwriteAll` / `SkipAll` apply to the rest
    /// of the batch). `None` until the first conflict resolves; per-job
    /// [`decide`](super::overwrite::decide) calls read this so a single popup
    /// governs a whole queued batch. Pure: setting this performs no I/O.
    pub overwrite_policy: Option<OverwritePolicy>,
}

impl TransferScreen {
    /// Construct a fresh screen with two empty panes at the given cwds, focus
    /// on Local, no active transfer, an empty queue, an empty status, and no
    /// pending list. Pure: no I/O.
    ///
    /// Reachability: Task-10 sftp dispatch constructs the live screen via
    /// [`crate::tui::transfer::open::open_transfer`]; the Task-8 render path
    /// + Task-9 key router are also exercised by tests.
    #[must_use]
    pub fn new(local_cwd: PathBuf, remote_cwd: PathBuf) -> Self {
        Self {
            local: Pane::new(local_cwd),
            remote: Pane::new(remote_cwd),
            focus: Side::Local,
            active: None,
            queue: Vec::new(),
            status: Status::empty(),
            pending_list: None,
            overwrite_policy: None,
        }
    }

    /// Replace the in-flight transfer snapshot (or clear it with `None`).
    /// Pure setter — the loop drives it from drained worker events.
    pub fn set_active(&mut self, progress: Option<Progress>) {
        self.active = progress;
    }

    /// Replace the consolidated status. Pure setter.
    pub fn set_status(&mut self, status: Status) {
        self.status = status;
    }

    /// Mutable accessor for the local pane. `on_key` accesses `self.local`
    /// directly (it lives in the same module); this accessor is for external
    /// callers (the loop feeding a worker `Listing` event into the pane, and
    /// `LocalDirSource`-fed listings on navigation).
    pub fn local_mut(&mut self) -> &mut Pane {
        &mut self.local
    }

    /// Mutable accessor for the remote pane. See [`Self::local_mut`].
    pub fn remote_mut(&mut self) -> &mut Pane {
        &mut self.remote
    }

    /// Pure key router. Mirrors the app's three-layer discipline
    /// (Press-only): `Tab`/`Shift-Tab` flip focus, `Ctrl-Enter` enqueues the
    /// focused pane's marked (or selected) entries, `Esc` cancels an active
    /// transfer or else closes the screen, `Ctrl-C` always closes, and
    /// everything else delegates to the focused [`Pane::on_key`]. Performs no
    /// I/O; the returned [`ScreenOutcome`] tells the Task-10 loop what side
    /// effect to run.
    ///
    /// For navigation intents (`StepInto` / `StepUp` / `RequestList`) this
    /// sets [`pending_list`](Self::pending_list) and returns `Continue` —
    /// Task 10 reads `pending_list` after each keypress, performs the list
    /// (sync `LocalDirSource::list` for the local side, `WorkerCmd::List` for
    /// the remote side), feeds the result back via [`Pane::set_entries`], and
    /// clears the field.
    ///
    /// Reachability: Task 10's sftp event loop calls this on each polled key
    /// via [`App::route_transfer`](crate::tui::app::App::route_transfer).
    pub fn on_key(&mut self, key: KeyEvent) -> ScreenOutcome {
        if key.kind != KeyEventKind::Press {
            return ScreenOutcome::Continue;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            // Tab / Shift-Tab flip focus between the two panes.
            KeyCode::Tab | KeyCode::BackTab if !ctrl => {
                self.flip_focus();
                ScreenOutcome::Continue
            }
            // Ctrl-Enter enqueues the focused pane's marked (or selected)
            // entries as transfer jobs. (Legacy alias — many terminals collapse
            // Ctrl-Enter to a bare Enter, so the footer advertises Ctrl-S below
            // as the reliable primary trigger. Kept for terminals that deliver
            // it and for muscle memory.)
            KeyCode::Enter if ctrl => self.enqueue_from_focused(),
            // Ctrl-S: the primary, footer-advertised transfer trigger. A control
            // char (0x13), so — unlike Ctrl-Enter — it survives terminal
            // decoding on every terminal. Transfers the focused pane's marked
            // (or selected) entries: a file, a dir (recursive), or a marked
            // batch. Direction follows focus (Local → Upload, Remote → Download).
            // No clash with the wizards' Ctrl-S = save: those are form overlays,
            // and this Layer-0 screen owns the key while it is open.
            KeyCode::Char('s') if ctrl => self.enqueue_from_focused(),
            // Esc: cancel an active transfer, otherwise close the screen.
            KeyCode::Esc => {
                if self.active.is_some() {
                    ScreenOutcome::CancelActive
                } else {
                    ScreenOutcome::CloseTransfer
                }
            }
            // Ctrl-C always closes (matches the rest of the app).
            KeyCode::Char('c') if ctrl => ScreenOutcome::CloseTransfer,
            // Everything else (arrows, Space, printable chars, Enter without
            // Ctrl, Backspace) delegates to the focused pane.
            _ => self.route_to_focused(key),
        }
    }

    /// Flip `focus` between [`Side::Local`] and [`Side::Remote`]. Pure setter.
    fn flip_focus(&mut self) {
        self.focus = match self.focus {
            Side::Local => Side::Remote,
            Side::Remote => Side::Local,
        };
    }

    /// Delegate a key to the focused pane and translate its [`PaneOutcome`]
    /// into a [`ScreenOutcome`]. Navigation intents set
    /// [`pending_list`](Self::pending_list); the rest are pure continue.
    /// Receives the full [`KeyEvent`] so the pane sees modifiers (Ctrl-P /
    /// Ctrl-N) intact.
    fn route_to_focused(&mut self, key: KeyEvent) -> ScreenOutcome {
        let focus = self.focus;
        let outcome = match focus {
            Side::Local => self.local.on_key(key),
            Side::Remote => self.remote.on_key(key),
        };
        match outcome {
            PaneOutcome::None | PaneOutcome::QueryChanged | PaneOutcome::ToggleMark(_) => {
                ScreenOutcome::Continue
            }
            // Enter / Right on a file activated it — enqueue the focused pane's
            // marked (or selected) entries. A dir took the StepInto arm above
            // (Enter on a dir navigates, never transfers — folders transfer via
            // Ctrl-S), so reaching here means the cursor was on a file (or marks
            // are present, which take priority).
            PaneOutcome::ActivateSelected => self.enqueue_from_focused(),
            PaneOutcome::StepInto(path) => {
                self.pending_list = Some((focus, path));
                ScreenOutcome::Continue
            }
            PaneOutcome::StepUp => {
                let parent = match focus {
                    Side::Local => self.local.cwd.parent().map(PathBuf::from),
                    Side::Remote => self.remote.cwd.parent().map(PathBuf::from),
                };
                if let Some(parent) = parent {
                    self.pending_list = Some((focus, parent));
                }
                ScreenOutcome::Continue
            }
            PaneOutcome::RequestList(path) => {
                self.pending_list = Some((focus, path));
                ScreenOutcome::Continue
            }
        }
    }

    /// Build transfer jobs for the focused pane's marked entries (or, if none
    /// are marked, the selected entry) and append them to [`queue`](Self::queue).
    /// Direction is `Upload` when the local pane is focused, `Download` when
    /// the remote pane is focused. `recursive` tracks `entry.is_dir`;
    /// `size_total` tracks `entry.size`. Marks are single-shot: they are
    /// cleared once their entries have been enqueued. Returns `Enqueue` when
    /// at least one job was queued, otherwise `Continue` (nothing marked, no
    /// selected entry).
    ///
    /// `dst` joins the OTHER pane's cwd with the source entry's file name —
    /// the natural "drop into the opposite directory" behavior.
    fn enqueue_from_focused(&mut self) -> ScreenOutcome {
        let focus = self.focus;
        let direction = match focus {
            Side::Local => Direction::Upload,
            Side::Remote => Direction::Download,
        };
        let dst_cwd = match focus {
            Side::Local => self.remote.cwd.clone(),
            Side::Remote => self.local.cwd.clone(),
        };

        // Gather (path, name, is_dir, size) for marked entries — or just the
        // selected entry when nothing is marked. Owned tuples so the borrow on
        // the pane ends before we mutate `self.queue`.
        let mut specs: Vec<(PathBuf, String, bool, Option<u64>)> = Vec::new();
        {
            let src = self.focused_pane();
            if !src.marked.is_empty() {
                for e in &src.entries {
                    if src.marked.contains(&e.path) {
                        specs.push((e.path.clone(), e.name.clone(), e.is_dir, e.size));
                    }
                }
            } else if let Some(sel) = src.selected_entry() {
                specs.push((sel.path.clone(), sel.name.clone(), sel.is_dir, sel.size));
            }
        }
        if specs.is_empty() {
            return ScreenOutcome::Continue;
        }

        // Marks are single-shot per enqueue — clear them now that their entries
        // are about to be queued.
        self.focused_pane_mut().marked.clear();

        for (path, name, is_dir, size) in specs {
            let file_name = path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.clone());
            let dst = dst_cwd.join(&file_name);
            // Dir entries carry a trailing `/` in their display name (matches
            // `LocalDirSource::list`); strip it for the job's display name.
            let display_name = name.trim_end_matches('/').to_string();
            self.queue.push(TransferJob {
                direction,
                src: path,
                dst,
                name: display_name,
                size_total: size,
                recursive: is_dir,
            });
        }
        ScreenOutcome::Enqueue
    }

    /// Borrow the focused pane immutably.
    fn focused_pane(&self) -> &Pane {
        match self.focus {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    /// Borrow the focused pane mutably.
    fn focused_pane_mut(&mut self) -> &mut Pane {
        match self.focus {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// Pop the next queued job (FIFO). The Task-10 loop calls this when
    /// `active` becomes `None` to dispatch the next transfer; returns `None`
    /// when the queue is empty. Pure mutator: no I/O.
    ///
    /// Reachability: Task 10's loop drives this off `WorkerEvent::Done`.
    pub fn next_job(&mut self) -> Option<TransferJob> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.queue.remove(0))
        }
    }

    /// Clear the in-flight transfer snapshot (`active = None`). The Task-10
    /// loop calls this after draining a `WorkerEvent::Done` so the next
    /// keypress / `next_job` sees no active transfer. Pure mutator.
    ///
    /// Reachability: Task 10's loop calls this off `WorkerEvent::Done`.
    pub fn clear_active(&mut self) {
        self.active = None;
    }

    /// Render the full screen into `area`: title band (1) / panes (Fill) /
    /// progress+queue panel (4) / hotkey footer (1). The panes split
    /// horizontally 50/50; each pane renders its own cwd row, filter box, and
    /// windowed list via [`render::draw_pane`]. The non-focused pane is dimmed
    /// overall. Pure: no I/O, no env access.
    ///
    /// Reachability: Task-10's transfer dispatch + event loop drives this via
    /// [`App::draw`](crate::tui::app::App::draw) when `App::transfer` is set.
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
                "› press Space to mark, ^S to transfer (Enter on a file)",
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
            ("^S", "transfer"),
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

// Render smoke + on_key routing tests live in a sibling file via `#[path]` so
// this module stays under the 800-line guideline. The split is mechanical —
// the tests are inline-equivalent (they reach into `super::*` private items
// the same way an inline `mod tests` would).
#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
