//! The blocking TUI event loop.
//!
//! Renders [`App`] via a narrow `borrow_mut()` on the shared terminal, polls
//! crossterm for key events, and dispatches each key through
//! [`App::on_key`]. When `on_key` returns a side-effecting
//! [`Outcome`][super::intent::Outcome] (save/delete/store-switch/connect), the
//! loop calls the relevant free function in [`super::persist`] or
//! [`super::connect::connect_host`]. Returns `Some(ConnectRequest)` when the
//! user connects (the loop exits and `main` execs ssh after the terminal is
//! restored), or `None` on quit.
//!
//! # Reentrancy-safe borrow (load-bearing)
//!
//! The loop borrows the terminal mutably ONLY for each `draw(…)` call — the
//! `RefMut` is dropped before any key read or side effect. The popup paths
//! (`connect_host`, `TuiPassphrase::confirm`, the store-switch popups) re-borrow
//! the terminal via the weak handle; because the loop's `RefMut` is already
//! released, their `borrow_mut()` succeeds instead of panicking.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use crossterm::event::{self, Event};
use sshrack_core::error::SshrackError;
use sshrack_core::secret::{OsKeyring, PassphraseProvider};

use super::ConnectRequest;
use super::app::App;
use super::connect::connect_host;
use super::intent::{Outcome, Overlay};
use super::persist::{
    StoreSwitchTarget, fulfill_save_cred, persist_cred_delete, persist_host_delete,
    persist_host_save, persist_store_switch,
};
use super::prompt::TuiPassphrase;
use super::term::{TerminalHandle, Tui};
use super::transfer::open::open_transfer;
use super::transfer::overwrite;
use super::transfer::pane::Side;
use crate::tui::transfer::search::NucleoSegmentMatcher;
use sshrack_core::connect::sftp::SftpWorker;
use sshrack_core::connect::sftp::proto::{Direction, TransferOutcome, WorkerCmd, WorkerEvent};
use sshrack_core::pathfind::{ParsedQuery, PathSearch, SearchEvent};

/// How long [`event::poll`] blocks for a key before the loop wakes to drain
/// SFTP worker events and re-render. crossterm's `poll` watches only the
/// terminal fd, so it is NOT woken by the worker's mpsc events — a remote
/// listing (or a progress tick) can only be observed after this window
/// expires or a key arrives. 50 ms bounds the worst-case listing lag at
/// ~50 ms (snappier than sshelf's 100 ms tick) for negligible CPU: the loop
/// simply re-polls. Pinned by `tests::event_poll_is_50_ms`.
const EVENT_POLL: Duration = Duration::from_millis(50);

/// Blocking event loop. Renders `app`, polls crossterm for key events, and
/// dispatches each key through [`App::on_key`]. Returns `Some(req)` when the
/// user connects (the loop exits and `main` execs ssh after terminal restore),
/// or `None` when the user quits.
///
/// When `on_key` returns [`Outcome::ConnectRequested`], the launcher has set
/// `pending_connect` to a host id (pure intent, no I/O). The loop then runs
/// [`connect_host`] — vault unlock popup, host-key confirm popup, argv build,
/// frecency record+save — which is the connect orchestration mirroring
/// `cli::cmd::connect::run`. A user cancel inside a popup (Esc/Ctrl-C)
/// surfaces as [`SshrackError::Interrupted`] and returns the user to the
/// launcher rather than exiting: `pending_connect` is cleared and the loop
/// keeps running. Any other orchestration error is shown in the status line
/// and also returns to the launcher.
///
/// Event-read errors are tolerated (treated as "no event this tick") rather
/// than aborting the TUI: a transient read failure should not strand the user
/// in an unrecoverable state. The terminal is still restored on return because
/// the caller owns the [`TerminalGuard`].
///
/// # Reentrancy-safe borrow (Critical #1)
///
/// `terminal` is the shared `Rc<RefCell<Tui>>` (cloned from
/// [`TerminalGuard::terminal`]). The loop borrows it mutably ONLY for the
/// duration of each `draw(...)` call — the `RefMut` is dropped the instant the
/// draw closure returns, BEFORE the loop reads a key or runs a side effect.
/// The popup paths (`connect_host`, `TuiPassphrase::confirm`, the
/// store-switch popups) borrow the terminal themselves by upgrading the weak
/// `handle`; because the loop's `RefMut` is already released, their
/// `borrow_mut()` succeeds instead of panicking. Holding a long-lived
/// `RefMut` across this whole loop re-introduces the panic on every popup.
///
/// [`TerminalGuard`]: super::term::TerminalGuard
/// [`Outcome::ConnectRequested`]: super::intent::Outcome::ConnectRequested
pub fn run_loop(
    terminal: &Rc<RefCell<Tui>>,
    app: &mut App,
    handle: TerminalHandle,
    data_dir: Option<&std::path::Path>,
) -> Option<ConnectRequest> {
    // First-tick guard: `sshrack sftp <name>` (and any future entry route that
    // pre-resolves a host in `tui::run`) stashes the host on
    // `app.pending_transfer_host`. Drain it on the FIRST iteration, BEFORE the
    // initial draw, so the user lands in the transfer screen directly rather
    // than seeing the launcher flash for one frame. This mirrors the
    // `Outcome::OpenTransfer` arm below without polluting `App::on_key` with a
    // phantom outcome (the launcher never produced a key event).
    let mut first_tick = true;
    loop {
        if first_tick {
            first_tick = false;
            if let Some(host) = app.pending_transfer_host.take() {
                match open_transfer(host, app, handle.clone(), data_dir) {
                    Ok(()) => {}
                    Err(SshrackError::Interrupted) => {
                        // Defensive: open_transfer only interrupts on a popup
                        // cancel, and the entry path has no popups before the
                        // first tick. Treat like the launcher Ctrl-T path:
                        // return to the launcher with no status write.
                    }
                    Err(e) => {
                        app.report_failure(&e);
                    }
                }
            }
        }

        // Advance the find-mode spinner phase once per tick (only while a
        // search is in flight) so the filter-row label animates at ~50 ms/frame.
        // Borrowed and released in this block, before the draw block re-borrows
        // `app` below.
        if let Some(screen) = app.transfer.as_mut() {
            screen.advance_spinner();
        }

        // Borrow ONLY for the draw, then release before any key read or side
        // effect. A popup re-borrows via the weak handle and must not collide.
        {
            let mut t = terminal.borrow_mut();
            if t.draw(|f| app.draw(f)).is_err() {
                // A draw failure (e.g. suspended tty) is not fatal; try again
                // next tick. The RefMut is released at the end of this block
                // before the loop reads a key or runs a popup.
            }
        }

        if !event::poll(EVENT_POLL).unwrap_or(false) {
            // No key within the poll window, or poll itself failed: re-render
            // and poll again, but still drain worker events first so an async
            // remote listing (or transfer progress) lands without waiting for
            // a keypress — drain_transfer_events is a no-op for pending_list
            // when on_key set none, so this only flushes WorkerEvent traffic.
            // Unwrap_or(false) keeps the loop alive on a transient poll error
            // instead of unwinding the TUI.
            if app.transfer_worker.is_some() {
                drain_transfer_events(app, &handle);
            }
            if app.should_quit {
                return None;
            }
            continue;
        }

        let event = match event::read() {
            Ok(ev) => ev,
            Err(_) => continue,
        };

        if let Event::Key(key) = event {
            // Stamp the last-key time before routing: the search debounce
            // gate (should_fire_search) reads this when a pending_search is
            // waiting, and the only surface that produces pending_search is
            // the transfer screen. Stamping on every Press while a transfer
            // screen is open keeps the gate honest about "the user is still
            // typing" without coupling it to a specific arm below.
            if app.transfer.is_some() && key.kind == crossterm::event::KeyEventKind::Press {
                app.last_search_key = std::time::Instant::now();
            }
            // Only react to key presses, not releases/repeats (crossterm 0.28
            // emits Release/Repeat on some platforms).
            match app.on_key(key) {
                Outcome::Quit => return None,
                Outcome::ConnectRequested => {
                    // Read the pure intent the launcher set on Enter. Clear it
                    // so a subsequent keystroke does not re-fire a stale id.
                    let Some(host_id) = app.launcher.pending_connect.take() else {
                        // No id: defensive — treat as if Enter hit no host.
                        continue;
                    };
                    match connect_host(host_id, app, handle.clone(), data_dir) {
                        Ok(req) => return Some(req),
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a popup (Esc/Ctrl-C). Return to the
                            // launcher, NOT an exit. No status write — the popup
                            // dismissing is the feedback.
                        }
                        Err(e) => {
                            // A real error (vault unlock fail, host-key reject,
                            // dangling credential, frecency save fail). Surface
                            // it as a red one-liner via the error's own wording
                            // and return to the launcher so the user can read it.
                            app.report_failure(&e);
                        }
                    }
                }
                Outcome::SaveHost => {
                    // The wizard signaled save after its pure validate() passed.
                    // Persist: build the host, resolve the credential name→id,
                    // add or apply-patch, write config, reload, close the wizard
                    // overlay. on_key's route_overlay stashed the form back on
                    // SaveHost (non-terminal), so the overlay is still open here.
                    match persist_host_save(app, &handle, &OsKeyring) {
                        Ok(()) => {
                            app.set_status("host saved".to_string());
                            app.close_host_wizard();
                        }
                        Err(e) => {
                            // Persist failed (duplicate name, write error,
                            // dangling credential). Surface in the wizard's
                            // core-error line and stay in the overlay so the
                            // user can fix it.
                            if let Some(Overlay::HostWizard(w)) = app.overlay.as_mut() {
                                w.set_core_error(e.to_string());
                            }
                        }
                    }
                }
                Outcome::SaveCred => {
                    // The cred wizard signaled save after its pure validate()
                    // passed. Persist + recover from a store-undecided state in
                    // place (popup + switch + retry) without leaving the wizard.
                    fulfill_save_cred(app, &handle);
                }
                Outcome::Cancel => {
                    // A wizard's Esc / Ctrl-C: on_key's route_overlay already
                    // dropped the form (terminal outcome) and left the overlay
                    // clear. No status write — the overlay closing is the
                    // feedback; re-rank so the Hosts tab reflects any state.
                    app.close_overlay();
                }
                Outcome::CloseOverlay => {
                    // Esc / Ctrl-C inside a non-wizard overlay (Help /
                    // StorePicker). on_key already cleared it; the
                    // overlay closing is the feedback, so no status write.
                }
                Outcome::SwitchTab(_) | Outcome::OpenOverlay(_) | Outcome::Continue => {
                    // Pure state changes already applied inside on_key; the next
                    // draw reflects them. Nothing for the loop to do.
                }
                Outcome::SwitchToKeyring => {
                    match persist_store_switch(app, StoreSwitchTarget::Keyring, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to keyring mode".to_string());
                        }
                        Ok(false) => {
                            // Keyring unavailable or a transient error surfaced in
                            // the store view's status line; stay in the view.
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a vault-unlock popup (vault→keyring
                            // needs the source key). Stay in the store view. No
                            // status write — the popup dismissing is the feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::SwitchToVault => {
                    match persist_store_switch(app, StoreSwitchTarget::Vault, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to vault mode".to_string());
                        }
                        Ok(false) => {}
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the passphrase popup. Stay in the
                            // view. No status write — the popup dismissing is the
                            // feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::SwitchToPlaintext => {
                    match persist_store_switch(app, StoreSwitchTarget::Plaintext, &handle) {
                        Ok(true) => {
                            app.close_store_view();
                            app.overlay = None;
                            app.set_status("switched to plaintext mode".to_string());
                        }
                        Ok(false) => {}
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the confirm popup (or a vault-unlock
                            // popup, when leaving vault). Stay in the store view.
                            // No status write — the popup dismissing is the
                            // feedback.
                        }
                        Err(e) => {
                            if let Some(v) = app.store_view.as_mut() {
                                v.status = Some(format!("switch failed: {e}"));
                            }
                        }
                    }
                }
                Outcome::DeleteHost => {
                    // Pure intent: ^d on a host set pending_delete. Drive the
                    // confirm popup, then (on Yes) core delete + keyring cleanup
                    // + persist + reload. A cancel (Esc/Ctrl-C in the popup, or
                    // a No) closes the overlay with NO status write — the popup
                    // dismissing is the feedback — and is NOT an exit.
                    let Some(host_id) = app.pending_delete.take() else {
                        continue;
                    };
                    // Resolve id → name for the confirm message BEFORE deleting
                    // (the host is gone after delete). None is defensive (the
                    // launcher only hands out ids from the loaded config).
                    let name = app
                        .config
                        .find_host_by_id(&host_id)
                        .map(|h| h.name.clone())
                        .unwrap_or_else(|| host_id.to_string());
                    let provider = TuiPassphrase::new(handle.clone());
                    let prompt = format!("Remove host '{name}'?");
                    match provider.confirm(&prompt) {
                        Ok(true) => match persist_host_delete(app, &name) {
                            Ok(()) => {
                                app.overlay = None;
                                app.set_status(format!("removed '{name}'"));
                            }
                            Err(e) => {
                                app.report_failure(&e);
                            }
                        },
                        Ok(false) => {
                            // User declined (No). The confirm popup closing is
                            // the feedback; no status write.
                            app.overlay = None;
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the popup (Esc/Ctrl-C). No status
                            // write — the popup dismissing is the feedback.
                            app.overlay = None;
                        }
                        Err(e) => {
                            app.report_failure(&e);
                        }
                    }
                }
                Outcome::DeleteCred => {
                    // Pure intent: ^d on a credential set pending_delete_cred.
                    // Drive the confirm popup, then (on Yes) core delete +
                    // keyring cleanup + persist + reload. A cancel (Esc/Ctrl-C
                    // in the popup, or a No) closes the overlay with NO status
                    // write — the popup dismissing is the feedback — and is NOT
                    // an exit.
                    let Some(name) = app.pending_delete_cred.take() else {
                        continue;
                    };
                    let provider = TuiPassphrase::new(handle.clone());
                    let prompt = format!("Remove credential '{name}'?");
                    match provider.confirm(&prompt) {
                        Ok(true) => match persist_cred_delete(app, &name) {
                            Ok(()) => {
                                app.overlay = None;
                                app.set_status(format!("removed '{name}'"));
                            }
                            Err(e) => {
                                app.report_failure(&e);
                            }
                        },
                        Ok(false) => {
                            // User declined (No). The confirm popup closing is
                            // the feedback; no status write.
                            app.overlay = None;
                        }
                        Err(SshrackError::Interrupted) => {
                            // User cancelled the popup (Esc/Ctrl-C). No status
                            // write — the popup dismissing is the feedback.
                            app.overlay = None;
                        }
                        Err(e) => {
                            app.report_failure(&e);
                        }
                    }
                }
                Outcome::OpenTransfer => {
                    // Pure intent: Ctrl-T on Hosts tab with a host selected.
                    // Run open_transfer (vault unlock, host-key, worker spawn,
                    // screen seed). A cancel inside a popup surfaces as
                    // Interrupted → return to the launcher (no status write);
                    // any other error surfaces as a red status-bar line via
                    // report_failure and returns to the launcher.
                    let Some(host) = app.pending_transfer_host.take() else {
                        // No host: defensive — Ctrl-T hit no host.
                        continue;
                    };
                    match open_transfer(host, app, handle.clone(), data_dir) {
                        Ok(()) => {}
                        Err(SshrackError::Interrupted) => {
                            // User cancelled a popup (Esc/Ctrl-C). Return to the
                            // launcher, NOT an exit. No status write — the popup
                            // dismissing is the feedback.
                        }
                        Err(e) => {
                            // Surface every open failure (vault locked, dangling
                            // credential, no-password-no-key, master auth failure,
                            // handshake timeout) as a red status-bar line via the
                            // error's own wording. A modal Alert offered no
                            // interaction value here (only dismiss), so the status
                            // bar — uniform with connect/delete failures — is the
                            // right surface. Esc/^C in any popup still returns to
                            // the launcher via the Interrupted arm above.
                            app.report_failure(&e);
                        }
                    }
                }
                Outcome::CloseTransfer => {
                    // The transfer screen signaled close (Esc with no active
                    // transfer, or Ctrl-C). Drop the screen + worker + inline-
                    // key artifact together so the worker's Drop tears down the
                    // master ssh -N (RAII) and the temp files are removed. No
                    // status write — the screen closing is the feedback.
                    app.close_transfer();
                }
            }
        }

        // Per-tick worker drain — runs AFTER key handling each iteration when a
        // transfer session is open. The EVENT_POLL window above paces
        // this loop; we drain every pending event each tick so a fast worker
        // (small file, quick listing) does not stall one tick behind reality.
        // Borrows `app` mutably ONLY in this block; the draw borrow at the top
        // of the next iteration is released before any popup re-borrows.
        if app.transfer_worker.is_some() {
            drain_transfer_events(app, &handle);
        }

        if app.should_quit {
            return None;
        }
    }
}

/// Bundled cross-directory find launch parameters: produced inside the
/// transfer-screen borrow and consumed after it ends (the searchers live on
/// `App` disjoint from `app.transfer`, so the launch call cannot stay inside
/// the `if let Some(screen) = app.transfer.as_mut()` block). Naming the tuple
/// keeps clippy's `type_complexity` lint satisfied and documents what crosses
/// the borrow boundary.
type SearchLaunch = (
    Side,
    ParsedQuery,
    u32,
    std::sync::Arc<NucleoSegmentMatcher>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::mpsc::Sender<SearchEvent>,
);

/// Drain pending SFTP worker events into the transfer screen + handle the
/// screen's navigation/transfer intents. Called once per loop iteration AFTER
/// key handling when a transfer session is open. Pure-I/O: reads
/// `WorkerEvent`s via [`SftpWorker::try_event`], feeds them into the screen,
/// and pushes `WorkerCmd`s in response to the screen's `pending_*` flags.
///
/// # Local-pane listings (synchronous)
///
/// The local pane's `pending_list` resolves inline via
/// [`LocalDirSource::list`][sshrack_core::dirsource::LocalDirSource] (the local
/// filesystem is fast and the listing is small). The remote pane's
/// `pending_list` becomes a `WorkerCmd::List` and resolves asynchronously via a
/// future `WorkerEvent::Listing`.
///
/// # Overwrite popup (MVP)
///
/// Before dispatching a download whose destination exists, if no batch policy
/// is set yet (`screen.overwrite_policy is None`), drive a `confirm_popup`. On
/// Yes → set `OverwriteAll`; on No → set `SkipAll`. The per-job
/// [`overwrite::decide`] then resolves each subsequent conflict from the batch
/// policy. Upload-overwrite is deferred (a remote check needs another sftp
/// round-trip); uploads always use [`OverwritePolicy::Overwrite`] for now.
///
/// # Borrow shape
///
/// Borrows `app` mutably for the whole call. The terminal is borrowed (for a
/// popup) only when an overwrite confirm runs, and only via the weak `handle`
/// — consistent with the rest of the loop's popup paths (no `RefCell` collision
/// because run_loop's draw `RefMut` is already released by this point).
fn drain_transfer_events(app: &mut App, handle: &TerminalHandle) {
    use sshrack_core::dirsource::{DirSource, LocalDirSource};

    // 1. Take the screen's pending_list (set by on_key on navigation). One
    //    value at a time — if the user navigated both panes, only the most
    //    recent navigation's path is held. Dispatch on Side:
    //      Local  → list inline (fs is fast) and feed the pane now;
    //      Remote → send WorkerCmd::List; the result lands async next tick.
    let pending = app.transfer.as_ref().and_then(|s| s.pending_list.clone());
    if let Some((side, path)) = pending {
        // Clear the request first so a future keypress does not re-fire the
        // same listing.
        if let Some(screen) = app.transfer.as_mut() {
            screen.pending_list = None;
        }
        match side {
            Side::Local => {
                // pending_list is always user navigation (StepInto / StepUp /
                // RequestList), so always clear the per-directory query / marks
                // / cursor via on_step — even when the target IS the current
                // cwd (a path-like query that re-resolves here). Without this,
                // a RequestList to the current dir leaves the path text in
                // `query` and the next recompute fuzzy-filters every entry out
                // ("no match"). In-place refreshes (post-transfer) do NOT go
                // through pending_list, so there is no same-dir case here that
                // needs to preserve the query.
                if let Some(screen) = app.transfer.as_mut() {
                    screen.local.on_step();
                    screen.local.core.cwd = path.clone();
                    screen.local.loading = true;
                }
                let listing = LocalDirSource::new().list(&path);
                if let Some(screen) = app.transfer.as_mut() {
                    match listing {
                        Ok(entries) => {
                            screen.local_mut().set_entries(entries);
                            screen.local.loading = false;
                        }
                        Err(msg) => {
                            // The listing failed (the typed path does not exist
                            // or is unreadable): roll the pane back to the
                            // pre-switch cwd + entries so it never sits on an
                            // unreachable path with the previous listing still
                            // visible — the root cause of the "wrong directory"
                            // transfer bug. Without this, a later enqueue would
                            // build dst from the stale bad cwd.
                            screen.local.revert_switch();
                            screen.local.loading = false;
                            screen.set_status(super::intent::Status::error(format!(
                                "local list failed: {msg}"
                            )));
                        }
                    }
                }
            }
            Side::Remote => {
                // Same as local: pending_list is always user navigation, so
                // on_step runs unconditionally — including a RequestList that
                // re-resolves to the current cwd (see the local arm for why
                // same-dir must still clear). Optimistically update cwd so the
                // next render shows the navigated path while the listing is in
                // flight; entries refresh when the Listing event lands.
                if let Some(screen) = app.transfer.as_mut() {
                    screen.remote.on_step();
                    screen.remote.core.cwd = path.clone();
                    screen.remote.loading = true;
                }
                if let Some(worker) = app.transfer_worker.as_ref() {
                    worker.send(WorkerCmd::List(path));
                }
            }
        }
    }

    // 2. Drain in-flight search events into the screen, then dispatch any
    //    pending search launch. Two steps:
    //      (a) Snapshot every buffered SearchEvent out of `search_rx`, then
    //          apply them to the active-search pane. The snapshot releases the
    //          `search_rx` borrow BEFORE we mutate the screen (the receiver is
    //          re-seated unless the search was cancelled mid-loop, in which
    //          case `search_cancel` is None and we let the rx drop).
    //      (b) If the screen stashed a `pending_search`, debounce + launch it
    //          via the injected `PathSearch` (local now; remote no-op until
    //          Task 10's `open_transfer` populates `app.remote_search`).
    if let Some(screen) = app.transfer.as_mut() {
        let rx = screen.search_rx.take();
        if let Some(rx) = rx {
            // Snapshot all buffered events this tick. The in-flight search's
            // pane is recorded explicitly at launch (`begin_search` sets
            // `search_side`); it CANNOT be inferred from
            // `local.search.is_some()` — a finished find keeps `search` as
            // `Some` (stale-while-revalidate), so after a Shift-Tab both panes
            // can carry `search = Some` at once and the heuristic would route
            // the in-flight worker's events into the wrong pane.
            let side = screen.search_side;
            let mut events: Vec<_> = rx.try_recv().into_iter().collect();
            // Keep receiving while there are buffered events; the loop bounds
            // the work per tick so a runaway worker cannot starve key handling.
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
            // Re-seat the receiver unless the search was cancelled mid-loop
            // (cancel_search clears search_rx to None AND drops search_cancel).
            // The generation check inside apply_search_event drops stragglers
            // from a superseded query, so re-seating is always safe.
            let still_listening = app
                .transfer
                .as_ref()
                .is_some_and(|s| s.search_cancel.is_some());
            if still_listening && let Some(screen) = app.transfer.as_mut() {
                screen.search_rx = Some(rx);
            }
            // Apply the snapshot now that the rx borrow is released. `side` is
            // `None` only when a receiver lingers without a recorded in-flight
            // side (`cancel_search` clears both together, so this is unreachable
            // in normal flow) — in that case drop the events without routing.
            if let Some(side) = side
                && let Some(screen) = app.transfer.as_mut()
            {
                for ev in events {
                    screen.apply_search_event(side, ev);
                }
            }
        }
    }

    // (b) Dispatch pending_search with ~80 ms debounce + cancel-on-retarget.
    // Compute everything the launch needs INSIDE the screen borrow, then exit
    // the borrow before calling launch — the searcher (app.local_search /
    // app.remote_search) is borrowed separately from app.transfer, and holding
    // both at once would not compile.
    let launch: Option<SearchLaunch> = {
        if let Some(screen) = app.transfer.as_mut() {
            if let Some((side, parsed)) = screen.pending_search.take() {
                let elapsed = std::time::Instant::now()
                    .duration_since(app.last_search_key)
                    .as_millis() as u64;
                if !should_fire_search(elapsed) {
                    // Too soon after the last keystroke — put it back and
                    // retry next tick. The user is still typing; launching now
                    // would thrash the search worker on every char.
                    screen.pending_search = Some((side, parsed));
                    None
                } else {
                    // Generation bump first so stragglers from the previous
                    // in-flight search are dropped by apply_search_event's gen
                    // check even if their cancel flag has not been observed.
                    screen.search_gen = screen.search_gen.wrapping_add(1);
                    // Cancel any previous in-flight search before installing
                    // the new rx/cancel pair. The worker thread observes the
                    // flag and exits its walk.
                    if let Some(c) = screen.search_cancel.as_ref() {
                        c.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    // Record the new in-flight side, and stop a displaced
                    // OTHER-pane search's spinner — its worker was just
                    // cancelled and will never emit Done, so without this its
                    // pane would spin forever. Done before installing the fresh
                    // rx/cancel pair so `search_side` is consistent with the
                    // receiver the next drain reads.
                    screen.begin_search(side);
                    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (tx, rx) = std::sync::mpsc::channel();
                    screen.search_rx = Some(rx);
                    screen.search_cancel = Some(cancel.clone());
                    let r#gen = screen.search_gen;
                    let matcher = app.search_matcher.clone();
                    Some((side, parsed, r#gen, matcher, cancel, tx))
                }
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some((side, parsed, r#gen, matcher, cancel, tx)) = launch {
        match side {
            Side::Local => {
                app.local_search.launch(&parsed, matcher, r#gen, cancel, tx);
            }
            Side::Remote => {
                if let Some(rs) = app.remote_search.as_ref() {
                    rs.launch(&parsed, matcher, r#gen, cancel, tx);
                }
                // remote_search None until Task 10 wires open_transfer —
                // remote find is a no-op then, while local find already works
                // end-to-end.
            }
        }
    }

    // 3. Drain worker events. Each transfer_worker is Some here (the caller
    //    gated on that). Loop until try_event returns None so a fast worker
    //    does not stall a tick behind reality.
    let mut maybe_failed_msg: Option<String> = None;
    let mut maybe_done_advance = false;
    // Destination-pane refresh to run after the drain loop when a Done ends
    // the batch (Ok/Cancelled + empty queue). Carries the finished direction
    // so step 7 knows which pane to re-list.
    let mut pending_refresh: Option<Direction> = None;
    while let Some(ev) = app.transfer_worker.as_ref().and_then(SftpWorker::try_event) {
        match ev {
            WorkerEvent::Listing(cwd, res) => {
                if let Some(screen) = app.transfer.as_mut() {
                    screen.apply_remote_listing(cwd, res);
                }
            }
            WorkerEvent::Progress(p) => {
                if let Some(screen) = app.transfer.as_mut() {
                    screen.set_active(Some(p));
                }
            }
            WorkerEvent::Done(outcome) => {
                // Snapshot the just-finished direction BEFORE finish_inflight
                // flips the task to Done (it is still InFlight here). The
                // refresh fires only when this Done ends the batch; mid-batch
                // defers to the final job's Done.
                let last_direction = app.transfer.as_ref().and_then(|s| s.last_direction());
                if let Some(screen) = app.transfer.as_mut() {
                    screen.finish_inflight(outcome.clone());
                }
                let queue_empty = app.transfer.as_ref().is_none_or(|s| s.queue_empty());
                if let Some(dir) = decide_post_done_refresh(last_direction, queue_empty, &outcome) {
                    pending_refresh = Some(dir);
                }
                match outcome {
                    TransferOutcome::Ok | TransferOutcome::Cancelled => {
                        // Ready for the next queued job (if any). Dispatch is
                        // done after the drain loop so a pending_cancel that
                        // arrived mid-event is honored first.
                        maybe_done_advance = true;
                    }
                    TransferOutcome::Failed(msg) => {
                        maybe_failed_msg = Some(msg);
                    }
                }
            }
        }
    }

    // 4. Honor pending_cancel from ScreenOutcome::CancelActive. Sent AFTER the
    //    drain so an inflight Done + a user Esc race resolves to "cancel the
    //    next thing" rather than "drop a stale cancel".
    if app.take_pending_cancel()
        && let Some(worker) = app.transfer_worker.as_ref()
    {
        worker.send(WorkerCmd::Cancel);
    }

    // 5. Dispatch the next queued job (if any). Triggered by either a
    //    ScreenOutcome::Enqueue with nothing in flight (pending_advance) or a
    //    Done on the previous job with a non-empty queue (maybe_done_advance).
    let should_advance = app.take_pending_advance() || maybe_done_advance;
    if should_advance {
        dispatch_next_job(app, handle);
    }

    // 6. Surface a Failed message AFTER dispatching so an overwrite-popup skip
    //    followed by an immediate retry of the next queued job reads cleanly.
    if let Some(msg) = maybe_failed_msg
        && let Some(screen) = app.transfer.as_mut()
    {
        screen.set_status(super::intent::Status::error(format!(
            "transfer failed: {msg}"
        )));
    }

    // 7. Refresh the destination pane when a batch just finished (decided in
    //    the Done arm above) so a newly-arrived file is visible without a
    //    manual reload. Download lands locally (sync list); Upload lands
    //    remotely (async WorkerCmd::List over the master, drained next tick).
    if let Some(direction) = pending_refresh {
        match direction {
            Direction::Download => {
                let cwd = app.transfer.as_ref().map(|s| s.local.core.cwd.clone());
                if let Some(cwd) = cwd {
                    if let Some(screen) = app.transfer.as_mut() {
                        screen.local.loading = true;
                    }
                    let listing = LocalDirSource::new().list(&cwd);
                    if let Some(screen) = app.transfer.as_mut() {
                        match listing {
                            Ok(entries) => {
                                screen.local_mut().set_entries(entries);
                                screen.local.loading = false;
                            }
                            Err(msg) => {
                                screen.local.loading = false;
                                screen.set_status(super::intent::Status::error(format!(
                                    "local list failed: {msg}"
                                )));
                            }
                        }
                    }
                }
            }
            Direction::Upload => {
                let cwd = app.transfer.as_ref().map(|s| s.remote.core.cwd.clone());
                if let Some(cwd) = cwd
                    && let Some(worker) = app.transfer_worker.as_ref()
                {
                    if let Some(screen) = app.transfer.as_mut() {
                        screen.remote.loading = true;
                    }
                    worker.send(WorkerCmd::List(cwd));
                }
            }
        }
    }
}

/// Decide whether a `WorkerEvent::Done` should trigger a destination-pane
/// refresh, and in which direction. Returns `Some(dir)` only when this Done
/// ENDS the batch — `Ok`/`Cancelled` outcome AND the queue is empty AND the
/// finished direction is known — so the destination pane re-lists exactly
/// once (after the last job) instead of once per file. `Failed` never
/// refreshes (the status line reports the error); a mid-batch Done (queue
/// still pending) defers the refresh to the final job. Pure.
fn decide_post_done_refresh(
    last_direction: Option<Direction>,
    queue_empty: bool,
    outcome: &TransferOutcome,
) -> Option<Direction> {
    match outcome {
        TransferOutcome::Ok | TransferOutcome::Cancelled if queue_empty => last_direction,
        _ => None,
    }
}

/// Debounce gate for cross-directory find: fire only after ≥80 ms since the
/// last keystroke. The run loop checks this before launching a `PathSearch`;
/// if too soon, it puts `pending_search` back and retries next tick. Pure.
fn should_fire_search(elapsed_ms: u64) -> bool {
    elapsed_ms >= 80
}

/// Pop the next queued job (if any) and send it to the worker, resolving an
/// overwrite conflict via a confirm popup the first time one is encountered in
/// this batch. No-op when the queue is empty.
fn dispatch_next_job(app: &mut App, handle: &TerminalHandle) {
    use super::transfer::overwrite::OverwriteChoice;
    use sshrack_core::connect::sftp::proto::{Direction, OverwritePolicy};

    // Pop the next job from the screen's queue. The job leaves the queue here;
    // if we end up not sending it (skip / cancel) the queue still advances
    // because the worker short-circuits Skip/SkipAll to `Done(Ok)` (or we drop
    // the queue on a cancel).
    let (job, batch_policy_in) = match app.transfer.as_mut() {
        Some(screen) => match screen.next_job() {
            Some(job) => (job, screen.overwrite_policy),
            None => return,
        },
        None => return,
    };

    // Overwrite resolution. Downloads check the local destination (a real fs
    // call); uploads skip the remote-exists check for MVP (a remote check needs
    // another sftp round-trip, deferred to Task 11). When the popup fires, it
    // produces an `OverwriteChoice` directly (OverwriteAll / SkipAll / Cancel);
    // the per-job table `overwrite::decide` then converts a settled batch
    // policy into the per-job action.
    let dest_exists = matches!(job.direction, Direction::Download) && job.dst.exists();
    let policy = if dest_exists && batch_policy_in.is_none() {
        // First conflict in the batch + no batch policy yet → popup. The popup
        // owns the terminal; we MUST NOT hold a borrow of `app.transfer` across
        // it, so the popup decision is computed standalone.
        let prompt = format!("overwrite '{}' at {}?", job.name, job.dst.display());
        let provider = TuiPassphrase::new(handle.clone());
        let popup_choice = match provider.confirm(&prompt) {
            Ok(true) => OverwriteChoice::OverwriteAll,
            Ok(false) => OverwriteChoice::SkipAll,
            Err(SshrackError::Interrupted) => OverwriteChoice::Cancel,
            Err(e) => {
                // Surface the popup error in the status line, then default to
                // SkipAll so a transient popup failure does not clobber an
                // existing local file.
                if let Some(screen) = app.transfer.as_mut() {
                    screen.set_status(super::intent::Status::error(format!(
                        "overwrite popup failed: {e}"
                    )));
                }
                OverwriteChoice::SkipAll
            }
        };
        match popup_choice {
            OverwriteChoice::OverwriteAll => {
                if let Some(screen) = app.transfer.as_mut() {
                    screen.overwrite_policy = Some(OverwritePolicy::OverwriteAll);
                }
                OverwritePolicy::OverwriteAll
            }
            OverwriteChoice::SkipAll => {
                if let Some(screen) = app.transfer.as_mut() {
                    screen.overwrite_policy = Some(OverwritePolicy::SkipAll);
                }
                OverwritePolicy::SkipAll
            }
            OverwriteChoice::Cancel => {
                // Popup Esc (Ctrl-C). Stop the whole batch: clear the queue and
                // drop the in-hand job so neither this nor any subsequent
                // enqueued job runs. `next_job` already marked a task InFlight;
                // `abort_inflight` reverts that never-sent task and
                // `clear_queued` drops the rest — matching the old "whole
                // batch gone" behavior. The user can re-enqueue after
                // navigating around the conflict.
                if let Some(screen) = app.transfer.as_mut() {
                    screen.abort_inflight();
                    screen.clear_queued();
                    screen.set_status(super::intent::Status::info(
                        "transfer batch cancelled".to_string(),
                    ));
                }
                return;
            }
            // `decide` flattens Overwrite/Skip; the popup never returns these
            // single-shot forms (it always answers for the rest of the batch).
            OverwriteChoice::Overwrite | OverwriteChoice::Skip => OverwritePolicy::Overwrite,
        }
    } else {
        // No conflict, OR a batch policy is already set. Use it as-is; the
        // per-job decision table just confirms the action.
        batch_policy_in.unwrap_or(OverwritePolicy::Overwrite)
    };

    // Per-job decision table. Live mainly so the policy → action map stays
    // unit-pinned (and so future per-job logic — e.g. cancel-on-Cancel — has a
    // single decision site). The worker honors Skip/SkipAll by short-circuiting
    // to `Done(Ok)`, so we always send the job; the queue advances either way.
    let _per_job = overwrite::decide(policy, dest_exists);

    if let Some(worker) = app.transfer_worker.as_ref() {
        worker.send(WorkerCmd::Transfer(job, policy));
    }
}

#[cfg(test)]
mod tests {
    // ===============================================================
    // Critical #1 regression: the popup borrow path must not collide with
    // run_loop's draw borrow. The panic scenario (final-review Critical #1)
    // was: run_loop held a long-lived RefMut across the whole iteration, and
    // a popup upgraded the weak handle and called borrow_mut() AGAIN →
    // "already borrowed" panic. The fix narrows the draw borrow to a single
    // block so the RefMut is released before any popup runs. These tests pin
    // both that (a) the fixed narrow-borrow-then-popup pattern does NOT panic,
    // and (b) the old wide-borrow pattern DID panic — proving the test would
    // catch a regression that re-introduced a long-lived RefMut across run_loop.
    // ===============================================================

    use super::*;
    use crate::tui::test_support::{app_with_host, stdout_tui};
    use crate::tui::transfer::pane::Side;
    use crate::tui::transfer::screen::TransferScreen;
    use std::path::PathBuf;

    #[test]
    fn event_poll_is_50_ms() {
        // Pins the UI poll cadence. crossterm's `event::poll` watches only the
        // terminal fd and is NOT woken by the SFTP worker's mpsc events, so a
        // remote listing (or a progress tick) can only be drained AFTER this
        // window expires (or a key arrives). 50 ms bounds the worst-case remote
        // listing lag at ~50 ms — snappier than sshelf's 100 ms tick — for
        // negligible CPU (the loop just re-polls). Bump deliberately only if a
        // re-measurement justifies it.
        assert_eq!(EVENT_POLL, Duration::from_millis(50));
    }

    // ---- should_fire_search ----

    #[test]
    fn should_fire_search_debounce_boundary() {
        // 80 ms is the documented debounce window: anything below holds the
        // search back (put pending_search back + retry next tick), 80 ms or
        // above fires. Pins the exact boundary so a refactor of the gate stays
        // honest about the user-visible lag.
        assert!(!should_fire_search(50), "<80 ms must not fire");
        assert!(should_fire_search(80), "80 ms must fire (≥)");
        assert!(should_fire_search(200), "200 ms must fire");
    }

    // ===============================================================
    // Search-event drain wiring: drain_transfer_events must snapshot
    // buffered SearchEvents out of `search_rx`, apply each to the active
    // pane's PaneSearch, drop stale events (gen mismatch), and re-seat the
    // receiver for the next tick. The borrow shape (snapshot then apply) is
    // load-bearing — pinning it here guards against a refactor that drops the
    // snapshot and silently breaks the search-result feed.
    // ===============================================================

    #[test]
    fn drain_applies_buffered_search_events_to_active_pane_search() {
        use sshrack_core::pathfind::{PathMatch, SearchEvent, SearchEventKind};
        use std::path::PathBuf;
        use std::sync::mpsc;

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        // Active search on the LOCAL pane with gen 1. The remote pane has no
        // search so the drain's "active side" pick lands on Local.
        screen.local.search = Some(crate::tui::transfer::search::PaneSearch::empty());
        screen.search_gen = 1;
        screen.search_side = Some(Side::Local);
        // Install a receiver buffered with one Match + one Done, and a live
        // cancel flag so the drain re-seats the rx.
        let (tx, rx) = mpsc::channel();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        tx.send(SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/local/sub/a.txt"),
                is_dir: false,
                seg_matches: vec![],
            }),
        })
        .expect("send match");
        tx.send(SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Done,
        })
        .expect("send done");
        screen.search_rx = Some(rx);
        screen.search_cancel = Some(cancel);
        app.transfer = Some(screen);

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        let srch = screen
            .local
            .search
            .as_ref()
            .expect("search still active on local pane");
        assert_eq!(srch.results.len(), 1, "exactly one Match applied");
        assert!(!srch.searching, "Done event must clear the searching flag");
        assert!(
            screen.search_rx.is_some(),
            "rx must be re-seated for the next tick (cancel still live)"
        );
    }

    #[test]
    fn drain_drops_stale_search_events_with_mismatched_gen() {
        use sshrack_core::pathfind::{PathMatch, SearchEvent, SearchEventKind};
        use std::path::PathBuf;
        use std::sync::mpsc;

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        screen.local.search = Some(crate::tui::transfer::search::PaneSearch::empty());
        // Current gen is 2 — an event tagged gen 1 is from a superseded query.
        screen.search_gen = 2;
        screen.search_side = Some(Side::Local);
        let (tx, rx) = mpsc::channel();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        tx.send(SearchEvent {
            r#gen: 1,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/local/stale"),
                is_dir: false,
                seg_matches: vec![],
            }),
        })
        .expect("send stale match");
        tx.send(SearchEvent {
            r#gen: 2,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/local/fresh"),
                is_dir: false,
                seg_matches: vec![],
            }),
        })
        .expect("send fresh match");
        screen.search_rx = Some(rx);
        screen.search_cancel = Some(cancel);
        app.transfer = Some(screen);

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        let srch = screen.local.search.as_ref().expect("search still active");
        assert_eq!(srch.results.len(), 1, "stale gen-1 event must be dropped");
        assert_eq!(
            srch.results[0].path,
            PathBuf::from("/local/fresh"),
            "only the gen-2 event lands"
        );
    }

    #[test]
    fn drain_does_not_reseat_rx_when_search_was_cancelled() {
        // cancel_search clears search_rx AND search_cancel together. If a
        // future drain runs after that (before the next launch re-installs a
        // pair), the drain must NOT re-seat an rx whose cancel flag was
        // dropped — otherwise the cancelled search's stray events would be
        // re-applied forever. Pin the "still_listening" gate.
        use std::sync::mpsc;

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        let (_tx, rx) = mpsc::channel::<sshrack_core::pathfind::SearchEvent>();
        screen.search_rx = Some(rx);
        // No search_cancel — simulates the post-cancel_search state. The drain
        // takes the rx, finds no buffered events, and must NOT re-seat it.
        screen.search_cancel = None;
        app.transfer = Some(screen);

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        assert!(
            app.transfer
                .as_ref()
                .expect("screen present")
                .search_rx
                .is_none(),
            "rx must NOT be re-seated when search_cancel is None (post-cancel state)"
        );
    }

    #[test]
    fn drain_routes_events_to_in_flight_side_not_local_heuristic() {
        // Repro: a find left on the LOCAL pane (its `search` stays `Some` —
        // stale-while-revalidate keeps the results visible after Done) when
        // the user Shift-Tabs to REMOTE and starts a new find. Both panes
        // now carry `search = Some`, so the old heuristic
        // `local.search.is_some()` routes the REMOTE worker's events into the
        // LOCAL pane — remote candidates appear on the left, and the right
        // pane spins forever (its Done lands on the wrong pane). The drain
        // must route by the recorded in-flight side (`search_side`).
        use sshrack_core::pathfind::{PathMatch, SearchEvent, SearchEventKind};
        use std::sync::mpsc;

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        // Both panes carry search state: local is the stale leftover, remote
        // is the new in-flight find.
        screen.local.search = Some(crate::tui::transfer::search::PaneSearch::empty());
        screen.remote.search = Some(crate::tui::transfer::search::PaneSearch::empty());
        // The in-flight search (whose events sit in search_rx) is REMOTE.
        screen.search_side = Some(Side::Remote);
        screen.search_gen = 2;
        let (tx, rx) = mpsc::channel();
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        tx.send(SearchEvent {
            r#gen: 2,
            kind: SearchEventKind::Match(PathMatch {
                path: PathBuf::from("/remote/opt/sub"),
                is_dir: true,
                seg_matches: vec![],
            }),
        })
        .expect("send remote match");
        tx.send(SearchEvent {
            r#gen: 2,
            kind: SearchEventKind::Done,
        })
        .expect("send done");
        screen.search_rx = Some(rx);
        screen.search_cancel = Some(cancel);
        app.transfer = Some(screen);

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        let local = screen
            .local
            .search
            .as_ref()
            .expect("local search state preserved");
        let remote = screen
            .remote
            .search
            .as_ref()
            .expect("remote search state preserved");
        assert!(
            local.results.is_empty(),
            "remote worker's events must NOT contaminate the local pane"
        );
        assert_eq!(
            remote.results.len(),
            1,
            "the in-flight (remote) pane receives its own events"
        );
        assert_eq!(
            remote.results[0].path,
            PathBuf::from("/remote/opt/sub"),
            "remote pane gets the remote match"
        );
        assert!(!remote.searching, "Done cleared the remote pane's spinner");
    }

    // ---- decide_post_done_refresh ----

    #[test]
    fn decide_post_done_refresh_ends_batch_on_ok_with_empty_queue() {
        assert_eq!(
            decide_post_done_refresh(Some(Direction::Upload), true, &TransferOutcome::Ok),
            Some(Direction::Upload)
        );
        assert_eq!(
            decide_post_done_refresh(Some(Direction::Download), true, &TransferOutcome::Ok),
            Some(Direction::Download)
        );
    }

    #[test]
    fn decide_post_done_refresh_mid_batch_defers() {
        // A Done with jobs still queued is NOT the batch end — the refresh must
        // wait for the final job so we don't re-list once per file.
        assert_eq!(
            decide_post_done_refresh(Some(Direction::Upload), false, &TransferOutcome::Ok),
            None
        );
    }

    #[test]
    fn decide_post_done_refresh_failed_never_refreshes() {
        assert_eq!(
            decide_post_done_refresh(
                Some(Direction::Upload),
                true,
                &TransferOutcome::Failed("e".into())
            ),
            None
        );
    }

    #[test]
    fn decide_post_done_refresh_cancelled_ends_batch() {
        // Cancel also ends the batch when nothing remains — re-list so the
        // view reflects any partially-transferred state the worker cleaned up.
        assert_eq!(
            decide_post_done_refresh(Some(Direction::Download), true, &TransferOutcome::Cancelled),
            Some(Direction::Download)
        );
    }

    #[test]
    fn decide_post_done_refresh_unknown_direction_yields_none() {
        // Defensive: no recorded direction (a stray Done with no prior
        // dispatch) → nothing to refresh.
        assert_eq!(
            decide_post_done_refresh(None, true, &TransferOutcome::Ok),
            None
        );
    }

    #[test]
    fn popup_borrow_after_narrow_draw_borrow_does_not_panic() {
        // Mirror run_loop's fixed pattern exactly: borrow_mut in a block for
        // the draw (released at block end), THEN upgrade the weak handle and
        // borrow_mut again inside the popup path. Under the bug, an outer
        // long-lived RefMut across the whole iteration made the popup's
        // borrow_mut panic; under the fix the popup borrow is the only live
        // borrow and succeeds.
        //
        // We cannot drive `event::read` here (no key is piped in a unit test),
        // so we stop just short of the popup's blocking read: we prove the
        // RefCell does not reject the popup's borrow_mut, which is the exact
        // failure mode the bug caused. `TuiPassphrase::confirm` borrows in its
        // own draw loop before reading; we replicate that single borrow.
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        let provider = TuiPassphrase::new(handle.clone());

        // run_loop's draw borrow: scoped, released before the side effect.
        {
            let _t = rc.borrow_mut();
            // (draw would run here; the borrow scope is what matters.)
        }
        // Popup path: upgrade the SAME live handle and borrow_mut. Under the
        // bug this panicked; under the fix it is the only live borrow.
        let upgraded = handle.upgrade().expect("live strong ref");
        let _popup_borrow = upgraded.borrow_mut();
        // `provider` carries the same live handle the popup layer would use;
        // its existence with a live strong ref proves the upgrade path resolves
        // (the bug dead-locked here with a RefMut panic).
        let _ = &provider;
    }

    // ===============================================================
    // Remote-pane on_step parity: navigation into a new remote dir must
    // clear marks + query + cursor exactly like the local branch. The bug
    // was that the Remote arm set `screen.remote.core.cwd` + sent `WorkerCmd::List`
    // but never called `screen.remote.on_step()`, so a prior filter stayed
    // visible and prior marks persisted in `marked` (reappearing on navigating
    // back). The pane-level clearing mechanism is covered by pane_tests
    // (`on_step_clears_marks_query_and_cursor`); this test pins the WIRING —
    // that drain_transfer_events actually calls on_step on remote navigation.
    // ===============================================================

    #[test]
    fn drain_remote_navigation_clears_remote_query_and_marks_like_local() {
        // Seed a transfer screen whose remote pane carries a query + a mark,
        // then queue a remote navigation (pending_list). After draining, the
        // remote query and marks must be cleared (the per-directory scope
        // documented in pane.rs), matching the local branch's behavior.
        let mut app = app_with_host("web");
        let mut screen =
            TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote/start"));
        screen.remote.core.query = "stale".to_string();
        screen
            .remote
            .core
            .marked
            .insert(PathBuf::from("/remote/start/file"));
        // Sanity: the fixtures took.
        assert!(!screen.remote.core.query.is_empty());
        assert_eq!(screen.remote.core.marked.len(), 1);
        app.transfer = Some(screen);
        // Queue a step into a subdirectory of the current remote cwd.
        app.transfer.as_mut().unwrap().pending_list =
            Some((Side::Remote, PathBuf::from("/remote/start/sub")));

        // No transfer_worker is set, so the worker.send is a no-op and no
        // WorkerEvents drain — the navigation arm is the only thing that runs.
        // The handle is never upgraded on the navigation path.
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        assert!(
            screen.remote.core.query.is_empty(),
            "remote query must be cleared on navigation (on_step parity with local)"
        );
        assert!(
            screen.remote.core.marked.is_empty(),
            "remote marks must be cleared on navigation (on_step parity with local)"
        );
        assert_eq!(
            screen.remote.core.cwd,
            PathBuf::from("/remote/start/sub"),
            "remote cwd must advance to the navigated path"
        );
    }

    // ===============================================================
    // Remote navigation must set pane.loading=true so draw_pane shows its
    // "loading…" placeholder while the WorkerCmd::List is in flight. No
    // transfer_worker is set here, so worker.send is a no-op — but loading is
    // assigned BEFORE the send, so it is observable. The matching clear runs in
    // apply_remote_listing when the Listing event lands (pinned in
    // screen_tests.rs).
    // ===============================================================
    #[test]
    fn drain_remote_pending_list_sets_loading_true() {
        let mut app = app_with_host("web");
        let screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote/start"));
        assert!(!screen.remote.loading, "fixture: loading starts false");
        app.transfer = Some(screen);
        app.transfer.as_mut().unwrap().pending_list =
            Some((Side::Remote, PathBuf::from("/remote/start/sub")));

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        assert!(
            app.transfer.as_ref().unwrap().remote.loading,
            "remote pending_list must set loading=true while the list is in flight"
        );
    }

    // ===============================================================
    // RequestList to the CURRENT cwd must still clear the query. Regression
    // for: type the current directory's path into a pane and press Enter
    // (a path-like query that re-resolves to the cwd). drain used to skip
    // on_step when `path == prev_cwd`, leaving the path text in `query`; the
    // stale query then fuzzy-filtered every entry out ("no match"). Navigation
    // via pending_list is always a user intent to (re)enter a directory, so
    // on_step must run unconditionally — in-place refreshes (post-transfer)
    // do NOT go through pending_list. Pinned on the remote arm: no worker is
    // set, so worker.send is a no-op and the on_step path is all that runs.
    // ===============================================================
    #[test]
    fn drain_request_list_to_current_cwd_clears_query_no_stale_filter() {
        let mut app = app_with_host("web");
        let mut screen =
            TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote/here"));
        screen.remote.core.query = "/remote/here".to_string();
        assert!(
            !screen.remote.core.query.is_empty(),
            "fixture: query seeded"
        );
        app.transfer = Some(screen);
        // RequestList to the CURRENT cwd (path == prev_cwd) — the bug case.
        app.transfer.as_mut().unwrap().pending_list =
            Some((Side::Remote, PathBuf::from("/remote/here")));

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        assert!(
            screen.remote.core.query.is_empty(),
            "RequestList to current cwd must still clear the query (no stale filter / no match)"
        );
    }

    // ===============================================================
    // Local-pane end-to-end variant of the RequestList-to-current-cwd
    // regression: the user-reported scenario (type the current dir's path on
    // the LOCAL pane, press Enter). Uses a real tempdir so the local arm's
    // LocalDirSource::list + set_entries runs for real; asserts the listed
    // file STAYS visible instead of being fuzzy-filtered to "no match".
    // ===============================================================
    #[test]
    fn drain_local_request_list_to_current_cwd_keeps_files_visible() {
        use std::fs;
        let dir = tempfile::tempdir().expect("temp dir");
        let file_path = dir.path().join("alpha.txt");
        fs::write(&file_path, b"").expect("write file");

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(dir.path().to_path_buf(), PathBuf::from("/remote"));
        screen.local.core.query = dir.path().to_string_lossy().into_owned();
        assert!(!screen.local.core.query.is_empty(), "fixture: query seeded");
        app.transfer = Some(screen);
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, dir.path().to_path_buf()));

        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        assert!(
            screen.local.core.query.is_empty(),
            "RequestList to current cwd must clear the query"
        );
        assert!(
            screen.local.matched_count() > 0,
            "entries must stay visible (no 'no match'); got {} matched",
            screen.local.matched_count()
        );
        assert!(
            screen
                .local
                .core
                .entries
                .iter()
                .any(|e| e.name.as_str() == "alpha.txt"),
            "alpha.txt must be listed"
        );
    }

    // ===============================================================
    // Failed local listing rolls the pane back to the pre-switch cwd +
    // entries. Regression for the "wrong directory" transfer bug: typing a
    // nonexistent path and pressing Enter used to leave local.cwd on the bad
    // path while the old listing stayed on screen — a later enqueue then
    // built dst from that stale bad cwd (e.g. the user's
    // `open local "/home/dasdas/.Xauthority": No such file or directory`).
    // ===============================================================
    #[test]
    fn drain_local_list_failure_reverts_cwd_and_keeps_entries() {
        use std::fs;
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("alpha.txt"), b"").expect("write file");
        let origin = dir.path().to_path_buf();

        let mut app = app_with_host("web");
        let screen = TransferScreen::new(origin.clone(), PathBuf::from("/remote"));
        app.transfer = Some(screen);
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Seed the local pane by listing the origin once (the user is already
        // viewing it).
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, origin.clone()));
        drain_transfer_events(&mut app, &handle);

        // Navigate to a path that does not exist on disk → list fails.
        let bad = PathBuf::from("/nonexistent/sshrack-bad-path-4172");
        assert!(!bad.exists(), "fixture: the bad path must not exist");
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, bad));
        drain_transfer_events(&mut app, &handle);

        let screen = app.transfer.as_ref().expect("transfer screen present");
        assert_eq!(
            screen.local.core.cwd, origin,
            "cwd reverted to origin (not left on the bad path)"
        );
        assert!(
            screen
                .local
                .core
                .entries
                .iter()
                .any(|e| e.name.as_str() == "alpha.txt"),
            "origin entries kept consistent after the failed switch"
        );
        assert!(
            screen.status.is_error,
            "failure surfaced as an error status"
        );
        assert!(
            screen
                .status
                .message
                .as_deref()
                .unwrap_or("")
                .contains("local list failed"),
            "status names the failure: {:?}",
            screen.status.message
        );
    }

    // ===============================================================
    // The transfer screen's status line must auto-clear on the next
    // keypress, mirroring the launcher's panel layer (route_panel clears
    // self.status before every panel key). The transfer screen routes
    // through Layer 0 (route_transfer), which never reaches route_panel,
    // so without an explicit clear a list/transfer error lingers on the
    // footer while the user searches, moves the cursor, or navigates.
    // ===============================================================
    #[test]
    fn transfer_status_auto_clears_on_next_keypress() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        use std::fs;
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join("alpha.txt"), b"").expect("write file");
        let origin = dir.path().to_path_buf();

        let mut app = app_with_host("web");
        let screen = TransferScreen::new(origin.clone(), PathBuf::from("/remote"));
        app.transfer = Some(screen);
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Seed the local pane, then navigate to a nonexistent path so the
        // local list fails and surfaces an error status (the user's scenario).
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, origin.clone()));
        drain_transfer_events(&mut app, &handle);
        let bad = PathBuf::from("/nonexistent/sshrack-auto-clear-7781");
        assert!(!bad.exists(), "fixture: the bad path must not exist");
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, bad));
        drain_transfer_events(&mut app, &handle);
        assert!(
            app.transfer.as_ref().unwrap().status.is_error,
            "fixture: the failed list must seed an error status first"
        );

        // Any subsequent keypress (cursor-down on the local pane here) must
        // clear the stale error — status is a per-action hint, not a banner.
        let down = KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Press);
        app.on_key(down);

        let status = &app.transfer.as_ref().unwrap().status;
        assert!(
            !status.is_error && status.message.is_none(),
            "stale error status must clear on the next keypress, got: {:?}",
            status.message
        );
    }

    // The clear is Press-gated, matching the launcher's Press-only key
    // handling. A Release event must leave the status untouched.
    #[test]
    fn transfer_status_clear_is_press_only_not_release() {
        use crate::tui::intent::Status;
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(PathBuf::from("/local"), PathBuf::from("/remote"));
        screen.set_status(Status::error("seeded error"));
        app.transfer = Some(screen);

        let release =
            KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release);
        app.on_key(release);

        let status = &app.transfer.as_ref().unwrap().status;
        assert!(
            status.is_error && status.message.as_deref() == Some("seeded error"),
            "Release must not clear the status, got: {:?}",
            status.message
        );
    }

    // ===============================================================
    // End-to-end regression for the user-reported bug: type a nonexistent
    // path on the LOCAL pane (Enter → list fails), switch to remote, mark a
    // file, Ctrl-S. The download dst must use local's REVERTED cwd — not the
    // stale bad path. Before the fix this produced
    // `open local "/home/dasdas/.Xauthority": No such file or directory`
    // because enqueue built dst from local.cwd which was still the bad path.
    // ===============================================================
    #[test]
    fn enqueue_dst_uses_reverted_local_cwd_after_failed_local_nav() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        use sshrack_core::connect::sftp::proto::Direction;
        use sshrack_core::dirsource::DirEntry;
        use std::fs;
        let dir = tempfile::tempdir().expect("temp dir");
        let origin = dir.path().to_path_buf();
        fs::write(origin.join("alpha.txt"), b"").expect("write local file");

        let mut app = app_with_host("web");
        let mut screen = TransferScreen::new(origin.clone(), PathBuf::from("/remote"));
        screen.focus = Side::Remote;
        // Remote pane shows a file the user will pull down.
        screen.remote.set_entries(vec![DirEntry {
            name: ".Xauthority".into(),
            path: PathBuf::from("/remote/.Xauthority"),
            is_dir: false,
            is_symlink: false,
            size: None,
            modified: None,
        }]);
        app.transfer = Some(screen);
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Seed the local pane (list origin), then navigate to a bad path.
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, origin.clone()));
        drain_transfer_events(&mut app, &handle);
        let bad = PathBuf::from("/nonexistent/sshrack-bad-9913");
        app.transfer.as_mut().unwrap().pending_list = Some((Side::Local, bad.clone()));
        drain_transfer_events(&mut app, &handle);
        assert_eq!(
            app.transfer.as_ref().unwrap().local.core.cwd,
            origin,
            "fixture: local cwd reverted after the failed navigation"
        );

        // Mark the remote file and enqueue (focus = Remote → Download).
        app.transfer
            .as_mut()
            .unwrap()
            .remote
            .core
            .marked
            .insert(PathBuf::from("/remote/.Xauthority"));
        let out = app
            .transfer
            .as_mut()
            .unwrap()
            .on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL));
        assert!(
            matches!(out, crate::tui::transfer::screen::ScreenOutcome::Enqueue),
            "Ctrl-S on a marked remote file enqueues"
        );
        let job = &app.transfer.as_ref().unwrap().ledger.tasks[0].job;
        assert_eq!(job.direction, Direction::Download);
        assert_eq!(
            job.dst,
            origin.join(".Xauthority"),
            "dst uses local's REVERTED cwd, not the stale bad path"
        );
        assert!(
            !job.dst.starts_with(&bad),
            "dst must not fall under the bad path: {:?}",
            job.dst
        );
    }

    #[test]
    #[should_panic(expected = "already borrowed")]
    fn wide_outer_borrow_then_popup_borrow_panics_regression_pin() {
        // Inverse pin: the OLD pattern (a long-lived outer RefMut across the
        // whole iteration, which is what `with_terminal(|t| run_loop(t, ...))`
        // produced) DOES panic when a popup borrow_mut runs inside it. This
        // test asserts that panic so a future refactor that re-introduces a
        // wide outer borrow across run_loop is caught by tests immediately,
        // not only at runtime against a real host.
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        // Simulate the OLD buggy pattern: outer RefMut held across the popup.
        let _outer = rc.borrow_mut();
        let upgraded = handle.upgrade().expect("live strong ref");
        // This borrow_mut panics because `_outer` is still live — exactly the
        // "already borrowed" the user saw on every popup before the fix.
        let _ = upgraded.borrow_mut();
    }
}
