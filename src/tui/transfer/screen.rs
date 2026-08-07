//! Full-screen dual-pane transfer view for `sshrack sftp`: state + layout +
//! pure key routing.
//!
//! [`TransferScreen`] owns the two [`Pane`]s (local + remote), the focus side,
//! the [`TransferLedger`] (single source of truth for queued / in-flight /
//! recently-finished tasks), and the consolidated [`Status`] line.
//! [`TransferScreen::draw`] lays the screen out as four vertical bands — title
//! (1) / panes (Fill) / progress+queue panel (4) / hotkey footer (1) — and
//! delegates the pane-row painting to [`super::render`].
//! [`TransferScreen::on_key`] is the pure key router; the queue-advance
//! helpers ([`TransferScreen::next_job`] /
//! [`TransferScreen::finish_inflight`]) are the seam the event loop drives.
//!
//! Architectural red line (shared with [`super::pane`]): `draw`, `on_key`, and
//! the queue helpers perform no I/O. The screen reads its own state plus the
//! latest worker snapshots the loop drained onto the ledger; it never reads
//! the network or the filesystem.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

use sshrack_core::connect::sftp::proto::{
    Direction, OverwritePolicy, Progress, TransferJob, TransferOutcome,
};
use sshrack_core::dirsource::DirEntry;
use sshrack_core::pathfind::{ParsedQuery, SearchEvent};

use crate::tui::dialog;
use crate::tui::intent::Status;
use crate::tui::theme;
use crate::tui::transfer::close_confirm::CloseConfirm;
use crate::tui::transfer::ledger::TransferLedger;
use crate::tui::transfer::pane::{Pane, PaneOutcome, Side};
use crate::tui::transfer::queue_overlay::QueueOverlay;
use crate::tui::transfer::render;

/// Pure intent returned by [`TransferScreen::on_key`]. The screen mutates its
/// own focus / marks / queue / `pending_list`; this intent tells the run
/// loop what side effect to perform (worker send, popup, quit). Mirrors
/// [`PaneOutcome`] in shape — enum-rather-than-`Option` so the loop's match
/// stays exhaustive over the action vocabulary.
///
/// Naming: `ScreenOutcome` (not `TransferOutcome`) deliberately, to avoid
/// collision with [`sshrack_core::connect::sftp::proto::TransferOutcome`], the
/// worker's per-job result enum (`Ok`/`Cancelled`/`Failed`). The two types
/// cross paths in the run loop (which drains `WorkerEvent::Done(proto)` and
/// routes `screen.on_key()`'s result), so giving them the same name would
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
    /// One or more jobs were appended to the ledger. The loop calls
    /// [`TransferScreen::next_job`] to dispatch the first one if no transfer is
    /// currently in flight. `Ctrl-Enter` emits this.
    Enqueue,
    /// Reply to the host-key overlay: the user accepted (`true`) or rejected
    /// (`false`) an unknown host's fingerprint. The loop forwards it to the
    /// worker as `WorkerCmd::HostKeyConfirm` and dismisses the overlay. Emitted
    /// only while `Connecting` (the overlay is set by the
    /// `WorkerEvent::HostKeyNeedsConfirm` drain and cleared on this outcome).
    HostKeyConfirm(bool),
}

/// Where the SFTP session is in its connect lifecycle. Drives both `on_key`
/// (gates keys until connected) and `draw` (Connecting / ConnectFailed hints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectState {
    /// Master handshake in progress on the worker thread. `Esc`/`Ctrl-C`
    /// cancel (close the screen → drop the worker → it aborts the handshake).
    Connecting,
    /// Handshake done; the worker is in its service loop. Normal browsing.
    Connected,
    /// Handshake failed. The status bar already shows the reason; the remote
    /// placeholder shows `connection failed` + an `Esc to return` hint.
    /// `Esc`/`Ctrl-C` return to the launcher. No other keys do anything.
    ConnectFailed,
}

/// Host-key confirmation overlay (unknown host). Owned by [`TransferScreen`]
/// like [`CloseConfirm`] / [`QueueOverlay`]. Set by the run loop when a
/// [`WorkerEvent::HostKeyNeedsConfirm`](sshrack_core::connect::sftp::proto::WorkerEvent::HostKeyNeedsConfirm)
/// drains (only while `Connecting`); `Enter`/`y` accept, `n`/`Esc` reject via
/// [`ScreenOutcome::HostKeyConfirm`], and the run loop dismisses the overlay on
/// either outcome.
///
/// Unlike [`CloseConfirm`], this overlay has no `closed` flag: the run loop
/// clears `host_key` to `None` unconditionally on every outcome (the worker
/// reply is mandatory, so there is no "neutral key keeps it open" state that
/// the screen needs to inspect later).
///
/// [`CloseConfirm`]: super::close_confirm::CloseConfirm
/// [`QueueOverlay`]: super::queue_overlay::QueueOverlay
#[derive(Debug, Clone)]
pub struct HostKeyPrompt {
    /// The host token (address) the worker scanned — shown in the overlay title.
    pub host: String,
    /// Multi-line confirm text from `hostkey::confirm_text` (the "authenticity
    /// of host …" message + algorithm + fingerprint).
    pub fingerprint: String,
}

/// The full-screen transfer view. Pure state plus a render entry point —
/// [`TransferScreen::draw`] lays out the screen and delegates pane painting to
/// [`render::draw_pane`]. [`TransferScreen::on_key`] is the pure key router;
/// the worker and overwrite-policy popup are driven by the live run loop.
///
/// Not `Clone`: the run loop owns the single live instance, and the
/// `search_rx`/`search_cancel` pair is a single-consumer channel + flag that
/// cannot be duplicated.
#[derive(Debug)]
pub struct TransferScreen {
    /// The local-filesystem pane. Owns its cwd, entries, query, cursor, marks.
    pub local: Pane,
    /// The remote (SFTP) pane. Same shape as `local`; entries are worker-fed.
    pub remote: Pane,
    /// Title for the remote pane's bordered block. Defaults to `"remote"`;
    /// [`open_transfer`](super::open::open_transfer) sets it to `"<user>@<host>"`
    /// once auth resolves. The local pane's title is the literal `"local"`
    /// (passed at the render call site, not stored).
    pub remote_title: String,
    /// Which pane receives navigation keys. The other pane is rendered dim.
    pub focus: Side,
    /// The transfer ledger: single source of truth for queued / in-flight /
    /// recently-finished tasks + the queue-level pause flag. Drives both the
    /// status-bar counters and the queue-manager popup. Mutated by the run-loop
    /// from drained `WorkerEvent`s.
    pub ledger: TransferLedger,
    /// The consolidated status line (rendered at the bottom of the progress
    /// panel). Carries the same transient one-liner feedback the rest of the
    /// app surfaces via [`Status`].
    pub status: Status,
    /// The next directory listing the screen wants the worker to fetch, set by
    /// [`on_key`](Self::on_key) when the focused pane emits `StepInto` /
    /// `StepUp` / `RequestList`. `None` when no list is pending. The run
    /// loop reads this after each keypress, dispatches the `WorkerCmd::List`
    /// (or sync `LocalDirSource::list` for the local side), feeds the result
    /// back via [`Pane::set_entries`], and clears the field. Pure: setting
    /// this performs no I/O.
    pub pending_list: Option<(Side, PathBuf)>,
    /// The user's batch-level overwrite answer, set by the run loop after
    /// the first overwrite popup (`OverwriteAll` / `SkipAll` apply to the rest
    /// of the batch). `None` until the first conflict resolves; per-job
    /// [`decide`](super::overwrite::decide) calls read this so a single popup
    /// governs a whole queued batch. Pure: setting this performs no I/O.
    pub overwrite_policy: Option<OverwritePolicy>,
    /// The `^Q` queue-manager modal. `None` when closed. Owned here (not as an
    /// `App::overlay`) because the transfer screen bypasses the overlay stack.
    pub queue_overlay: Option<QueueOverlay>,
    /// The quit-SFTP confirmation modal. `None` unless the user tried to quit
    /// (`Esc` final layer / `Ctrl-C`) while a transfer was in flight — see
    /// [`TransferScreen::request_close`]. Owned here (not on the `App` overlay
    /// stack) because the transfer screen bypasses that stack and owns its own
    /// popups, like [`queue_overlay`](Self::queue_overlay).
    pub close_confirm: Option<CloseConfirm>,
    /// The host-key confirmation overlay. `None` unless the worker emitted
    /// `WorkerEvent::HostKeyNeedsConfirm` for an unknown host (only while
    /// `Connecting`). Owned here for the same reason as `close_confirm` — the
    /// transfer screen owns its own popups. Dismissed by the run loop on
    /// [`ScreenOutcome::HostKeyConfirm`].
    pub host_key: Option<HostKeyPrompt>,
    /// Pending search launch: the focused side + parsed query that the run
    /// loop (Task 9) reads to spawn a
    /// [`PathSearch`](sshrack_core::pathfind::PathSearch). Set by
    /// [`search_request`](Self::search_request) when a multi-segment query
    /// enters find mode; the run loop clears it after launching. Pure: setting
    /// this performs no I/O.
    pub pending_search: Option<(Side, ParsedQuery)>,
    /// Receiver for streamed search events, installed by the run loop (Task 9)
    /// when it launches a search. The run loop drains it and feeds events to
    /// [`apply_search_event`](Self::apply_search_event).
    pub search_rx: Option<std::sync::mpsc::Receiver<SearchEvent>>,
    /// Cancel flag for the in-flight search, installed by the run loop (Task 9)
    /// alongside `search_rx`. [`cancel_search`](Self::cancel_search) flips it.
    pub search_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Generation tag for the current search. Incremented by the run loop
    /// on every new launch; [`apply_search_event`](Self::apply_search_event)
    /// ignores events whose `gen` ≠ this, so stale results from a superseded
    /// query never paint.
    pub search_gen: u32,
    /// The pane whose search currently owns the `search_rx` / `search_cancel`
    /// / `search_gen` triple — i.e. the side of the single in-flight
    /// cross-directory find. `None` when no search is in flight. The run-loop
    /// drain reads this to route streamed `SearchEvent`s to the correct pane;
    /// it CANNOT infer the side from `pane.search.is_some()`, because
    /// stale-while-revalidate keeps a finished find's `search` as `Some`, so
    /// after a Shift-Tab both panes can carry `search = Some` at once (a stale
    /// leftover on one side, the new in-flight find on the other). Set by
    /// [`begin_search`](Self::begin_search) at launch, cleared by
    /// [`cancel_search`](Self::cancel_search).
    pub search_side: Option<Side>,
    /// Remote home directory (`open_transfer` fills this in Task 10); `None`
    /// until then, so remote `~`-expansion degrades to the remote cwd.
    pub remote_home: Option<PathBuf>,
    /// Connect lifecycle. `Connecting` on entry (the screen shows while the
    /// worker thread runs the master handshake); `Connected` once the worker's
    /// `Connected` event drains; `ConnectFailed` on `ConnectFailed`. Gates
    /// `on_key` and drives the Connecting/failed hints in `draw`.
    pub connect: ConnectState,
    /// Global spinner phase for the find-mode "searching" filter-row label.
    /// Advanced once per run-loop tick ([`advance_spinner`](Self::advance_spinner))
    /// while any pane's search is in flight; read by `draw` → `draw_pane` →
    /// `find_count_label` to pick the current braille frame. Read-only in
    /// render, never mutated there.
    pub spinner: usize,
}

impl TransferScreen {
    /// Construct a fresh screen with two empty panes at the given cwds, focus
    /// on Local, no active transfer, an empty queue, an empty status, and no
    /// pending list. Pure: no I/O.
    ///
    /// Reachability: the live screen is constructed by
    /// [`crate::tui::transfer::open::open_transfer`]; the render path and key
    /// router are also exercised by tests.
    #[must_use]
    pub fn new(local_cwd: PathBuf, remote_cwd: PathBuf) -> Self {
        Self {
            local: Pane::new(local_cwd),
            remote: Pane::new(remote_cwd),
            focus: Side::Local,
            ledger: TransferLedger::new(),
            status: Status::empty(),
            remote_title: "remote".to_string(),
            pending_list: None,
            overwrite_policy: None,
            queue_overlay: None,
            close_confirm: None,
            host_key: None,
            pending_search: None,
            search_rx: None,
            search_cancel: None,
            search_gen: 0,
            search_side: None,
            remote_home: None,
            connect: ConnectState::Connecting,
            spinner: 0,
        }
    }

    /// Advance the global spinner phase by one tick if (and only if) a find
    /// search is in flight on either pane. Called by the run loop every tick
    /// before draw so the find-mode filter-row label animates. A no-op when no
    /// search is active (the phase does not advance, so an idle screen holds a
    /// stable frame). Pure: mutates only `self.spinner`.
    pub(crate) fn advance_spinner(&mut self) {
        let any_searching = self.local.search.as_ref().is_some_and(|s| s.searching)
            || self.remote.search.as_ref().is_some_and(|s| s.searching);
        if any_searching {
            self.spinner = self.spinner.wrapping_add(1);
        }
    }

    /// Update the in-flight task's progress snapshot (from
    /// `WorkerEvent::Progress`). `None` is a no-op (the `Done` arm calls
    /// [`finish_inflight`](Self::finish_inflight) to clear it).
    pub fn set_active(&mut self, progress: Option<Progress>) {
        if let Some(p) = progress {
            self.ledger.set_inflight_progress(p);
        }
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

    /// Apply a remote listing result drained from a `WorkerEvent::Listing`.
    ///
    /// - `Ok`: adopt the entries only when the listed cwd still matches the
    ///   pane's cwd — the user may have navigated further while the listing
    ///   was in flight, in which case the now-stale result is dropped.
    /// - `Err`: the listing failed (the path does not exist or is unreachable
    ///   over SFTP). Revert the pane to its pre-switch cwd + entries and
    ///   surface the failure, mirroring the local arm so the pane never sits
    ///   on an unreachable path with the previous listing still visible — the
    ///   "wrong directory" transfer bug.
    ///
    /// Pure: no I/O. Extracted from the run loop so the Err-revert path is
    /// unit-testable without a live `SftpWorker` (which spawns a real master).
    pub fn apply_remote_listing(
        &mut self,
        listed_cwd: PathBuf,
        res: Result<Vec<DirEntry>, String>,
    ) {
        match res {
            Ok(entries) => {
                if self.remote.core.cwd == listed_cwd {
                    self.remote.set_entries(entries);
                    // The list completed and is current → clear the in-flight
                    // indicator the run loop set when it sent List (dir switch
                    // / initial seed / post-transfer refresh).
                    self.remote.loading = false;
                }
                // cwd ≠ listed_cwd: the user navigated further while this list
                // was in flight. Drop the stale result WITHOUT clearing loading
                // — the current cwd's own list is still pending, and clearing
                // here would flash the pane out of loading before its real
                // listing lands.
            }
            Err(msg) => {
                self.remote.revert_switch();
                self.remote.loading = false;
                self.status = Status::error(format!("remote list failed: {msg}"));
            }
        }
    }

    /// Unified quit guard. Every code path that would close the SFTP screen
    /// routes through here — both `Esc`'s final layer and `Ctrl-C` — so the
    /// trigger key is irrelevant: any quit while a transfer is in flight is
    /// intercepted.
    ///
    /// If a transfer is in flight (and the overlay is not already open), open
    /// [`CloseConfirm`] snapshotted to that task and return [`Continue`](ScreenOutcome::Continue)
    /// (stay in SFTP; the user confirms via the overlay). Otherwise return
    /// [`CloseTransfer`](ScreenOutcome::CloseTransfer) at once. If the in-flight
    /// id/job cannot be resolved (should not happen — `has_inflight` implies a
    /// resolvable `inflight_id`), fall through to closing so a broken ledger
    /// never traps the user in the screen.
    fn request_close(&mut self) -> ScreenOutcome {
        if self.close_confirm.is_none()
            && let Some(id) = self.ledger.inflight_id()
            && let Some(job) = self.ledger.job_for(id)
        {
            self.close_confirm = Some(CloseConfirm::new(job.direction, job.name.clone()));
            return ScreenOutcome::Continue;
        }
        ScreenOutcome::CloseTransfer
    }

    /// Pure key router. Mirrors the app's three-layer discipline
    /// (Press-only): `Tab` completes the focused pane's query from its
    /// highlighted candidate (directory → `name/` enters the next level;
    /// file → full name). In filter mode it falls back to flipping focus when
    /// the query is empty or no candidate is under the cursor; in find mode
    /// (an active cross-directory search) `Tab` never flips focus — it
    /// completes or is swallowed (in flight, zero results, or no candidate) so
    /// a search session never bounces panes; `Shift-Tab` always flips focus,
    /// `Ctrl-Enter` enqueues the focused pane's marked (or selected)
    /// entries, `Esc` peels layers inside-out (cancel an in-flight find, else
    /// clear a non-empty filter query, else quit), `Ctrl-C` quits outright —
    /// both quit paths route through [`request_close`](Self::request_close)
    /// and confirm first if a transfer is in flight — and everything else
    /// delegates to the focused [`Pane::on_key`]. Performs no I/O; the
    /// returned [`ScreenOutcome`] tells the run loop what side effect to run.
    ///
    /// For navigation intents (`StepInto` / `StepUp` / `RequestList`) this
    /// sets [`pending_list`](Self::pending_list) and returns `Continue` —
    /// the run loop reads `pending_list` after each keypress, performs the
    /// list (sync `LocalDirSource::list` for the local side, `WorkerCmd::List`
    /// for the remote side), feeds the result back via [`Pane::set_entries`],
    /// and clears the field.
    ///
    /// Reachability: the sftp event loop calls this on each polled key via
    /// [`App::route_transfer`](crate::tui::app::App::route_transfer).
    pub fn on_key(&mut self, key: KeyEvent) -> ScreenOutcome {
        if key.kind != KeyEventKind::Press {
            return ScreenOutcome::Continue;
        }
        // Host-key confirmation overlay. Only set while `Connecting` (the
        // worker emits `HostKeyNeedsConfirm` before the master handshake) and
        // intercepted here BEFORE the connect-lifecycle close-key handling so
        // `Enter`/`y`/`n`/`Esc` route to confirm/reject instead of closing the
        // screen. Mirrors `CloseConfirm`/`QueueOverlay`'s modal shape: any
        // other key re-seats the overlay and returns `Continue`.
        if let Some(ov) = self.host_key.take() {
            let accept = match key.code {
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => Some(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(false),
                _ => None,
            };
            match accept {
                Some(decision) => return ScreenOutcome::HostKeyConfirm(decision),
                None => {
                    self.host_key = Some(ov);
                    return ScreenOutcome::Continue;
                }
            }
        }
        // Connect lifecycle gates. Until the worker reports Connected, the
        // panes have no usable entries — swallow everything except the close
        // keys so a reflexive navigation cannot crash on an empty list. The
        // close keys let the user cancel a Connecting handshake (Esc/Ctrl-C →
        // CloseTransfer → the loop drops the worker → handshake aborts) or
        // leave a ConnectFailed screen.
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let is_close_key =
            matches!(key.code, KeyCode::Esc) || ctrl && matches!(key.code, KeyCode::Char('c'));
        match self.connect {
            ConnectState::Connecting | ConnectState::ConnectFailed => {
                return if is_close_key {
                    ScreenOutcome::CloseTransfer
                } else {
                    ScreenOutcome::Continue
                };
            }
            ConnectState::Connected => {} // fall through to normal dispatch
        }
        // The queue-manager overlay is modal: when open it owns every key.
        // The `is_some` gate proves `take()` yields `Some`, but the compiler
        // can not see through it, so the `None` arm stays panic-free (no
        // `unwrap()`) rather than relying on the borrow-proven unreachable.
        if self.queue_overlay.is_some() {
            let mut ov = match self.queue_overlay.take() {
                Some(ov) => ov,
                None => return ScreenOutcome::Continue,
            };
            let out = ov.on_key(key, &mut self.ledger);
            if !ov.closed {
                self.queue_overlay = Some(ov);
            }
            return out;
        }
        // The quit-confirm overlay is modal: when open it owns every key.
        // Confirmed (CloseTransfer) or cancelled (closed) the overlay is not
        // reseated; a neutral key keeps it open. Same shape as the
        // queue-overlay gate above.
        if self.close_confirm.is_some() {
            let mut ov = match self.close_confirm.take() {
                Some(ov) => ov,
                None => return ScreenOutcome::Continue,
            };
            let out = ov.on_key(key);
            if !ov.closed() && !matches!(out, ScreenOutcome::CloseTransfer) {
                self.close_confirm = Some(ov);
            }
            return out;
        }
        // Find mode: when the focused pane has an active search, `Enter` jumps
        // to the selected result's directory and `Space` marks it (both
        // intercepted here so they never reach the dir-list path).
        let in_search = self.focused_pane().search.is_some();
        match key.code {
            // Shift-Tab always flips focus — the dedicated pane-switch escape
            // that is never swallowed by completion.
            KeyCode::BackTab if !ctrl => {
                self.flip_focus();
                ScreenOutcome::Continue
            }
            // Tab completes the focused pane's query from its highlighted
            // candidate when one exists (directory → name/ enters the next
            // level; file → full name). In filter mode (no active search,
            // incl. an empty query) it otherwise flips focus. In find mode
            // (an active cross-directory search) Tab NEVER flips focus —
            // whether the search is in flight, finished with zero results,
            // or has a candidate — so a search-session Tab never bounces the
            // user to the other pane (Shift-Tab is the dedicated,
            // always-switches escape).
            KeyCode::Tab if !ctrl => {
                // Flip focus only in filter mode when Tab did not just
                // complete a candidate. In find mode Tab is completion-only:
                // it completes, or is swallowed (never flips). complete_focused
                // applies the completion as a side effect, so its result gates
                // the flip; the in_find guard keeps any find-mode Tab from
                // switching panes.
                let completed = self.complete_focused();
                let in_find = self.focused_pane().search.is_some();
                if !completed && !in_find {
                    self.flip_focus();
                }
                ScreenOutcome::Continue
            }
            // Ctrl-Enter enqueues the focused pane's marked (or selected)
            // entries as transfer jobs. (Legacy alias — many terminals collapse
            // Ctrl-Enter to a bare Enter, so the footer advertises Ctrl-S below
            // as the reliable primary trigger. Kept for terminals that deliver
            // it and for muscle memory.) Routes through `enqueue_focused` so a
            // search-result selection enqueues from the search results.
            KeyCode::Enter if ctrl => self.enqueue_focused(),
            // Ctrl-S: the primary, footer-advertised transfer trigger. A control
            // char (0x13), so — unlike Ctrl-Enter — it survives terminal
            // decoding on every terminal. Transfers the focused pane's marked
            // (or selected) entries: a file, a dir (recursive), or a marked
            // batch. Direction follows focus (Local → Upload, Remote → Download).
            // No clash with the wizards' Ctrl-S = save: those are form overlays,
            // and this Layer-0 screen owns the key while it is open.
            KeyCode::Char('s') if ctrl => self.enqueue_focused(),
            // Esc peels layers inside-out: cancel an in-flight cross-dir find,
            // else clear a non-empty filter query (mirrors find mode — the
            // instinct to clear the search box must not close the session),
            // else quit via request_close (confirms first if a transfer is in
            // flight). Cancelling an in-flight transfer is owned by ^Q's queue
            // manager, not Esc — so Esc never silently discards an active task.
            KeyCode::Esc => {
                if in_search {
                    self.cancel_search();
                    ScreenOutcome::Continue
                } else if !self.focused_pane().core.query.is_empty() {
                    self.clear_query(self.focus);
                    ScreenOutcome::Continue
                } else {
                    self.request_close()
                }
            }
            // Ctrl-C quits via request_close (opens the confirm overlay if a
            // transfer is in flight, else closes immediately).
            KeyCode::Char('c') if ctrl => self.request_close(),
            // Ctrl-Q toggles the queue-manager overlay. (Bare `q`/`Q` stay
            // bound to the pane search box per the no-bare-hotkey invariant.)
            KeyCode::Char('q') if ctrl => {
                self.queue_overlay.get_or_insert(QueueOverlay::new());
                ScreenOutcome::Continue
            }
            // Enter (no Ctrl) on a search result: a FILE enqueues (parity with
            // filter mode, where Enter on a file transfers) and a DIRECTORY
            // jumps into itself (parity with filter mode, where Enter on a dir
            // enters). Ctrl-Enter / Ctrl-S above already enqueue either kind.
            KeyCode::Enter if in_search => {
                let is_dir = self
                    .focused_pane()
                    .search
                    .as_ref()
                    .and_then(|s| s.selected())
                    .is_some_and(|m| m.is_dir);
                if is_dir {
                    self.jump_to_search_result()
                } else {
                    self.enqueue_focused()
                }
            }
            // Everything else delegates to the focused pane: arrows (move the
            // search/listing cursor), Backspace/Left (edit query or step up),
            // and printable chars — INCLUDING Space, which find mode treats as
            // a query char. Find has no marking: the cross-dir `marked` set is
            // a current-dir concept (toggle + single-shot), and letting find
            // results into it caused stale-mark pollution and same-name dst
            // collisions. In filter mode Space still reaches the pane's own
            // mark-toggle.
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
            // The filter query changed: re-evaluate filter-vs-find mode for the
            // focused pane. `search_request` may flip the pane into find mode
            // (multi-segment query) and stash `pending_search` for the run loop,
            // or drop it back to filter mode (single-segment/empty).
            PaneOutcome::QueryChanged => {
                let q = self.focused_pane().core.query.clone();
                self.search_request(focus, q);
                ScreenOutcome::Continue
            }
            PaneOutcome::None | PaneOutcome::ToggleMark(_) => ScreenOutcome::Continue,
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
                    Side::Local => self.local.core.cwd.parent().map(PathBuf::from),
                    Side::Remote => self.remote.core.cwd.parent().map(PathBuf::from),
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
    /// are marked, the selected entry) and append them to the ledger as
    /// `Queued` tasks. Direction is `Upload` when the local pane is focused,
    /// `Download` when the remote pane is focused. `recursive` tracks
    /// `entry.is_dir`; `size_total` tracks `entry.size`. Marks are single-shot:
    /// they are cleared once their entries have been enqueued. Returns
    /// `Enqueue` when at least one job was queued, otherwise `Continue`
    /// (nothing marked, no selected entry).
    ///
    /// `dst` joins the OTHER pane's cwd with the source entry's file name —
    /// the natural "drop into the opposite directory" behavior.
    pub(crate) fn enqueue_from_focused(&mut self) -> ScreenOutcome {
        let focus = self.focus;
        let direction = match focus {
            Side::Local => Direction::Upload,
            Side::Remote => Direction::Download,
        };
        let dst_cwd = match focus {
            Side::Local => self.remote.core.cwd.clone(),
            Side::Remote => self.local.core.cwd.clone(),
        };

        // Gather (path, name, is_dir, size) for marked entries — or just the
        // selected entry when nothing is marked. Owned tuples so the borrow on
        // the pane ends before we mutate `self.ledger`.
        let mut specs: Vec<(PathBuf, String, bool, Option<u64>)> = Vec::new();
        {
            let src = self.focused_pane();
            if !src.core.marked.is_empty() {
                for e in &src.core.entries {
                    if src.core.marked.contains(&e.path) {
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
        self.focused_pane_mut().core.marked.clear();

        for (path, name, is_dir, size) in specs {
            let file_name = path
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| path.clone());
            let dst = dst_cwd.join(&file_name);
            // Dir entries carry a trailing `/` in their display name (matches
            // `LocalDirSource::list`); strip it for the job's display name.
            let display_name = name.trim_end_matches('/').to_string();
            self.ledger.enqueue(TransferJob {
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
    pub(crate) fn focused_pane(&self) -> &Pane {
        match self.focus {
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    /// Borrow the focused pane mutably.
    pub(crate) fn focused_pane_mut(&mut self) -> &mut Pane {
        match self.focus {
            Side::Local => &mut self.local,
            Side::Remote => &mut self.remote,
        }
    }

    /// Mark the head queued task in-flight and return its job (cloned) so the
    /// loop can send `WorkerCmd::Transfer`. Returns `None` when the queue is
    /// empty or paused. Pure mutator: no I/O.
    pub fn next_job(&mut self) -> Option<TransferJob> {
        let id = self.ledger.next_to_dispatch()?;
        self.ledger.job_for(id)
    }

    /// Mark the in-flight task `Done(outcome)` and clear its progress snapshot.
    /// Called from the run-loop's `WorkerEvent::Done` arm (replaces the old
    /// `clear_active` — the outcome is now retained as history).
    pub fn finish_inflight(&mut self, outcome: TransferOutcome) {
        self.ledger.finish_inflight(outcome);
    }

    /// Drop the in-flight task entirely (dispatch aborted before the job was
    /// sent — the overwrite-popup Cancel path).
    pub fn abort_inflight(&mut self) {
        self.ledger.abort_inflight();
    }

    /// Drop every queued task (overwrite-popup Cancel clears the batch).
    pub fn clear_queued(&mut self) {
        self.ledger.clear_queued();
    }

    /// Whether a transfer is currently in flight.
    pub fn has_inflight(&self) -> bool {
        self.ledger.has_inflight()
    }

    /// Whether any queued task remains (the post-Done refresh gate).
    pub fn queue_empty(&self) -> bool {
        self.ledger.queue_empty()
    }

    /// Direction of the in-flight task, else the most-recently-finished one.
    pub fn last_direction(&self) -> Option<Direction> {
        self.ledger.last_direction()
    }

    /// Render the full screen into `area`: title band (1) / panes (Fill) /
    /// progress+summary panel (2) / hotkey footer (1). The panes split
    /// horizontally 50/50; each pane renders its own cwd row, filter box, and
    /// windowed list via [`render::draw_pane`]. The non-focused pane is dimmed
    /// overall. Pure: no I/O, no env access.
    ///
    /// Reachability: the transfer dispatch + event loop drives this via
    /// [`App::draw`](crate::tui::app::App::draw) when `App::transfer` is set.
    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let [title_area, panes_area, panel_area, footer_area] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Length(2),
            Constraint::Length(1),
        ])
        .areas(area);

        self.draw_title(frame, title_area);

        let [local_area, remote_area] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(panes_area);

        // The local pane is always live (read-only browsing context while the
        // remote connects). The remote pane only goes live once `Connected`;
        // before that it is a bordered, host-titled placeholder so a pending or
        // failed connection never reads as an empty connected root (`/` + `0/0`
        // + a stale listing).
        render::draw_pane(
            frame,
            local_area,
            &self.local,
            self.focus == Side::Local,
            "local",
            self.spinner,
        );
        match self.connect {
            ConnectState::Connected => render::draw_pane(
                frame,
                remote_area,
                &self.remote,
                self.focus == Side::Remote,
                &self.remote_title,
                self.spinner,
            ),
            ConnectState::Connecting => self.draw_remote_pending(
                frame,
                remote_area,
                &format!("Connecting to {}…", self.remote_title),
                false,
            ),
            ConnectState::ConnectFailed => {
                self.draw_remote_pending(frame, remote_area, "connection failed", true);
            }
        }

        self.draw_progress_panel(frame, panel_area);
        self.draw_footer(frame, footer_area);

        // The queue-manager overlay paints last so it sits above every band.
        if let Some(ov) = &self.queue_overlay {
            ov.draw(frame, &self.ledger);
        }
        // The quit-confirm overlay paints last so it sits above every band,
        // including the queue overlay.
        if let Some(ov) = &self.close_confirm {
            ov.draw(frame);
        }
        // The host-key overlay paints last so it sits above every band,
        // including the close-confirm overlay. Only present while `Connecting`.
        if let Some(ov) = &self.host_key {
            ov.draw(frame);
        }
    }

    /// Remote pane before `Connected`: a dim bordered frame titled with the
    /// host and a single centered status line. Replaces the live listing so a
    /// pending or failed connection never reads as an empty connected root
    /// (`/` + `0/0` + a stale listing). `danger` colors the message red
    /// (ConnectFailed) and appends a dim `Esc to return` hint below it;
    /// otherwise it is dim (Connecting). The interior is `Clear`ed every frame
    /// so no stale listing bleeds through across states. Pure: no I/O.
    fn draw_remote_pending(&self, frame: &mut Frame, area: Rect, message: &str, danger: bool) {
        let block = Block::new()
            .borders(Borders::ALL)
            .border_style(Style::new().dim())
            .title(Span::styled(
                format!(" {} ", self.remote_title),
                Style::new().dim(),
            ));
        let inner = block.inner(area);
        frame.render_widget(&block, area);
        frame.render_widget(Clear, inner);

        // Center vertically. On a failed connection (danger) append a dim
        // `Esc to return` hint below the message: the modal dialog was removed
        // (the status bar already carries the reason), so the placeholder is the
        // visual anchor plus the single exit cue.
        let msg_style = if danger {
            Style::new().fg(theme::DANGER)
        } else {
            Style::new().dim()
        };
        let lines: Vec<Line> = if danger {
            vec![
                Line::from(Span::styled(message, msg_style)),
                Line::from(Span::styled("Esc to return", Style::new().dim())),
            ]
        } else {
            vec![Line::from(Span::styled(message, msg_style))]
        };
        let count = lines.len() as u16;
        let top = inner.y + inner.height.saturating_sub(count) / 2;
        frame.render_widget(
            Paragraph::new(lines).alignment(Alignment::Center),
            Rect::new(inner.x, top, inner.width, count),
        );
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

    /// Progress + summary panel: a 2-row band. Row 1 holds the active transfer
    /// text plus a visible-track bar, and is left blank when idle (the row
    /// height is reserved so a transfer starting does not reflow). Row 2 is the
    /// `done X/Y [· fail Z] [· paused]` summary — shown only when the ledger has
    /// work — with any transient status message appended; `summary_line` bounds
    /// the message so it can not push the counts off the row. The hotkey
    /// reference lives in the footer.
    fn draw_progress_panel(&self, frame: &mut Frame, area: Rect) {
        let [row1, row2] =
            Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

        // Row 1: the active transfer (blank-looking when idle —
        // `draw_active_transfer` paints the dim placeholder without a progress
        // snapshot). Keeps the live progress visible without opening the queue
        // popup.
        render::draw_active_transfer(frame, row1, self.ledger.active_progress());

        // Row 2: done/total + fail (+ paused) summary, with any transient
        // status message appended.
        let line = render::summary_line(&self.ledger, &self.status, area.width);
        frame.render_widget(Paragraph::new(line), row2);
    }

    /// Hotkey footer: one dot-separated hint line. Keys take the accent color;
    /// labels are dim. On a narrow terminal, trailing hints are dropped (via
    /// [`render::fit_hint_count`]) and a dim `…` marks the truncation, so the
    /// footer degrades gracefully instead of being silently clipped.
    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let hints: &[(&str, &str)] = &[
            ("Tab", "complete"),
            ("↑↓", "move"),
            ("←", "up"),
            ("→", "open"),
            ("Space", "mark"),
            ("^S", "transfer"),
            ("^Q", "queue"),
            ("Esc", "cancel"),
            ("^C", "close"),
            ("F1", "help"),
        ];
        let count = render::fit_hint_count(hints, area.width);
        let mut spans: Vec<Span> = Vec::with_capacity(hints.len() * 3);
        for (i, (k, label)) in hints.iter().take(count).enumerate() {
            if i > 0 {
                spans.push(Span::styled(" · ", Style::new().dim()));
            }
            spans.push(Span::styled(
                *k,
                theme::accent().add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(format!(" {label}"), Style::new().dim()));
        }
        if count < hints.len() {
            spans.push(Span::styled(" …", Style::new().dim()));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

impl HostKeyPrompt {
    /// Render the centered host-key confirmation dialog above the transfer
    /// screen. Uses [`dialog::draw_dialog`] for the bordered box + hotkey
    /// footer; the body is the multi-line confirm text from
    /// `hostkey::confirm_text` (authenticity + algorithm + fingerprint).
    pub(crate) fn draw(&self, frame: &mut Frame) {
        // `fingerprint` is the multi-line confirm_text; count its rows so the
        // dialog sizes to fit. Fall back to 1 for an empty message.
        let body_rows = self.fingerprint.lines().count().max(1) as u16;
        let body_area = dialog::draw_dialog(
            frame,
            &format!("Unknown host: {}", self.host),
            body_rows,
            &[("Enter/y", "accept"), ("n/Esc", "reject")],
        );
        frame.render_widget(Paragraph::new(self.fingerprint.clone()), body_area);
    }
}

// Render smoke + on_key routing tests live in a sibling file via `#[path]` so
// this module stays under the 800-line guideline. The split is mechanical —
// the tests are inline-equivalent (they reach into `super::*` private items
// the same way an inline `mod tests` would).
#[cfg(test)]
#[path = "screen_tests.rs"]
mod tests;
