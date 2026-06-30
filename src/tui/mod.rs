//! Interactive TUI front end. Thin view over sshrack-core; all data paths go
//! through core, never reimplemented here.
//!
//! Task 11 shipped the foundation (App, event loop, RAII terminal guard,
//! delayed-exec ConnectRequest). Task 14 wires the launcher: [`App`] now owns
//! the host list, frecency table, and credential-name lookup loaded from core
//! at startup, and routes `on_key`/`draw` to the launcher view.
//!
//! Architectural red line: the TUI holds no data path. [`App::on_key`] is pure
//! (no I/O) so it is unit-testable without a terminal. Side effects (persist,
//! exec) happen in the loop *after* `on_key`, never inside it. The terminal is
//! fully restored via [`TerminalGuard`]'s drop *before* `main` calls
//! [`sshrack_core::connect::launch`], so ssh never writes into the alternate
//! screen.

use std::collections::HashMap;

use crate::cli::Cli;
use sshrack_core::config::path as config_path;
use sshrack_core::config::store;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use ulid::Ulid;

pub mod app;
pub mod help;
pub mod launcher;
pub mod popup;
pub mod prompt;
pub mod wizard;

pub use app::{App, TerminalGuard, run_loop};

/// Reverse lookup from a credential ULID to its display name, built once at
/// startup from the loaded config. Lets the launcher show `Auth::Ref` targets
/// by name without re-scanning the credential table on every render.
pub type CredentialNames = HashMap<Ulid, String>;

/// What `main` needs to spawn ssh after the TUI exits. All pre-exec side
/// effects (resolve, vault unlock, host-key confirm, frecency save) have
/// already happened inside the TUI before this is returned.
///
/// `main` consumes this *after* the [`TerminalGuard`] has been dropped and the
/// terminal restored, so ssh inherits a normal terminal, not the alternate
/// screen.
pub struct ConnectRequest {
    /// Fully-resolved ssh/scp argv (program + args). `main` passes it straight
    /// to [`sshrack_core::connect::launch`].
    pub argv: Vec<String>,
    /// Where the password (if any) comes from at exec time. Carried by value
    /// because [`sshrack_core::credential::PasswordSource`] owns a
    /// `Zeroizing<String>` for the inline case.
    pub source: sshrack_core::credential::PasswordSource,
}

/// TUI entry point. Returns `Ok(None)` when the user quits without connecting,
/// `Ok(Some(req))` when the TUI wants `main` to exec ssh after terminal
/// restore, or `Err` if terminal setup failed.
///
/// Loads the config (hosts + named credentials) and the frecency table from
/// core *before* entering the alternate screen, so the launcher has data ready
/// to render on the first frame. A missing config or frecency file is treated
/// as empty (a fresh install shows an empty-state message, not an error).
///
/// The [`TerminalGuard`] owns the terminal and is dropped at the end of this
/// function (raw mode off, alternate screen left), so by the time the
/// `Option<ConnectRequest>` reaches `main` the terminal is fully restored.
pub fn run(cli: &Cli) -> Result<Option<ConnectRequest>, SshrackError> {
    // Load core data before touching the terminal: a load error should reach
    // the user on their normal terminal, not the alternate screen.
    let config_path = config_path::resolve(cli.config.as_deref());
    let cfg = config_path
        .as_ref()
        .map(|p| store::load(p))
        .transpose()?
        .unwrap_or_default();

    // Best-effort frecency load: a missing/corrupt file is an empty table,
    // never a reason to strand the user.
    let frecency = config_path::default_data_dir()
        .as_ref()
        .map(|d| frecency::store::load(d).unwrap_or_default())
        .unwrap_or_default();

    let credential_names: CredentialNames = cfg
        .credentials
        .iter()
        .map(|c| (c.id, c.name.clone()))
        .collect();

    let app = App::new(cfg.hosts, frecency, credential_names);

    let guard = TerminalGuard::enter()?;
    let mut app = app;
    // run_loop borrows the terminal through the guard; the guard itself stays
    // alive here, so the screen stays in alternate/raw mode for the duration.
    // `with_terminal` hands `run_loop` a `&mut Tui` without surrendering guard
    // ownership, so RAII restore still runs at function return.
    let request = guard.with_terminal(|terminal| run_loop(terminal, &mut app));
    // `guard` drops at function return: disable_raw_mode +
    // LeaveAlternateScreen. The terminal is restored on every path — plain
    // quit, connect, or early return from run_loop — because Drop always runs.
    Ok(request)
}
