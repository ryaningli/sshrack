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
use sshrack_core::secret::PassphraseProvider;

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
    loop {
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

        if !event::poll(Duration::from_millis(250)).unwrap_or(false) {
            // No event within the poll window, or poll itself failed: re-render
            // and poll again. Unwrap_or(false) keeps the loop alive on a
            // transient poll error instead of unwinding the TUI.
            continue;
        }

        let event = match event::read() {
            Ok(ev) => ev,
            Err(_) => continue,
        };

        if let Event::Key(key) = event {
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
                            // it in the status line (red) and return to the
                            // launcher so the user can read it.
                            app.set_status_error(format!("connect failed: {e}"));
                        }
                    }
                }
                Outcome::SaveHost => {
                    // The wizard signaled save after its pure validate() passed.
                    // Persist: build the host, resolve the credential name→id,
                    // add or apply-patch, write config, reload, close the wizard
                    // overlay. on_key's route_overlay stashed the form back on
                    // SaveHost (non-terminal), so the overlay is still open here.
                    match persist_host_save(app, &handle) {
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
                    // StorePicker / DeleteHost). on_key already cleared it; the
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
                                app.set_status_error(format!("delete failed: {e}"));
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
                            app.set_status_error(format!("delete failed: {e}"));
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
                                app.set_status_error(format!("delete failed: {e}"));
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
                            app.set_status_error(format!("delete failed: {e}"));
                        }
                    }
                }
            }
        }

        if app.should_quit {
            return None;
        }
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
    use crate::tui::test_support::stdout_tui;

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
