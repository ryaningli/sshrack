//! Install a SIGINT/SIGTERM handler that wipes any live sshrack temp files
//! (registered in `sshrack_core::tempfile_registry`) before the process exits.
//! `Drop` is skipped when the process is killed by a signal; this closes that
//! leak for the common Ctrl-C / SIGTERM case (SIGKILL/OOM still falls to the
//! startup `sweep`). Uses signal-hook's deferred (self-pipe) model so cleanup
//! runs in normal thread context — safe to call `std::fs`.
//!
//! The handler calls `cleanup_all` (a no-op when nothing is registered) then
//! exits with the conventional 128 + signo code, so Ctrl-C outside a
//! connection behaves as before.

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::sync::Once;

/// Install the SIGINT/SIGTERM handler. Idempotent; intended to be called once
/// from `main` after the askpass-role early-return (the askpass helper fork is
/// short-lived and owns no temp files).
pub fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // If Signals::new fails, best-effort: skip — the startup `sweep` stays
        // the backstop. signal-hook's self-pipe deferral means `signals.forever`
        // runs in normal thread context, so calling `std::fs` there is safe.
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(s) => s,
            Err(_) => return,
        };
        // If spawn fails after Signals::new succeeded, `signals` is dropped on
        // the spot (it is moved into the closure): signal-hook unregisters, the
        // OS default disposition for SIGINT/SIGTERM is restored, so Ctrl-C still
        // kills the process — SIGINT is not silently swallowed. The startup
        // `sweep` remains the on-disk backstop either way.
        let _ = std::thread::Builder::new()
            .name("sshrack-signal-cleanup".into())
            .spawn(move || {
                // Block for the first signal, then clean up and exit. We never
                // survive a signal to handle a second one, so a single
                // `.next()` (not a `for` loop) is the correct shape.
                if let Some(sig) = signals.forever().next() {
                    let _ = sshrack_core::tempfile_registry::cleanup_all();
                    // 128 + signo is the shell convention for a signal exit.
                    std::process::exit(128 + sig);
                }
            });
    });
}
