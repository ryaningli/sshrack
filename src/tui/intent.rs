//! Pure intent and status types shared across the TUI.
//!
//! [`Outcome`] is what [`crate::tui::app::App::on_key`] returns: a description
//! of what the event loop should do next, with no I/O performed. Keeping it
//! separate from `App` makes the state-machine boundary explicit — `on_key` is
//! pure, side effects happen in the loop. [`Overlay`] enumerates the one-at-a-
//! time dialogs layered on the shell. [`Status`] is the consolidated status-bar
//! message (info or error) shown in the footer.

use super::tab::Tab;
use super::wizard::{CredForm, HostForm};

/// The pure result of handling one key. Side effects happen in the loop, not
/// in [`App::on_key`], so key logic stays unit-testable without a terminal.
///
/// Later tasks grow this enum (EditHost, AddHost, AddCred, RemoveHost, ...).
//
// `SwitchTab(Tab)` / `OpenOverlay(Overlay)` carry their payload for test
// assertions (`matches!(outcome, Outcome::SwitchTab(Tab::Settings))`) and as
// self-documenting intent — the loop pattern-matches them with `_` because the
// state mutation already happened in `on_key`. `large_enum_variant`: the
// `ConnectRequested` variant carries a `Ulid` (small), but clippy sizes the
// whole enum by its largest variant; the wizard-carrying `Overlay` enum below
// is the real offender, and the allow here keeps the two enums consistent.
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// User asked to quit; the loop returns `None` (no connect).
    Quit,
    /// Nothing of interest happened; keep rendering and reading events.
    Continue,
    /// Pure intent: the user pressed Enter on a host. `on_key` sets the
    /// launcher's `pending_connect` field to the host's id and returns this.
    /// The event loop reads the id, runs the I/O-heavy connect orchestration
    /// ([`crate::tui::connect_host`]), and either returns the resulting
    /// [`ConnectRequest`] to `main` or — on user cancel — returns to the
    /// launcher. This variant carries no data because the id lives on the
    /// launcher (single source of truth, clearable on cancel).
    ConnectRequested,
    /// Pure intent: the host wizard wants to persist its form. The wizard's
    /// `on_key` validated the fields already; the loop resolves the credential
    /// name→id, builds a [`Host`], calls [`host::add_host`]/applies the patch,
    /// persists the config, reloads hosts, and returns to the launcher. The
    /// intent carries no data because the form lives on the wizard (single
    /// source of truth, clearable on cancel).
    ///
    /// [`host::add_host`]: sshrack_core::host::add_host
    SaveHost,
    /// Pure intent: the credential wizard wants to persist its form. The
    /// wizard's `on_key` validated the fields already; the loop builds a
    /// [`sshrack_core::config::schema::CredentialBody`], seals any password
    /// per the configured store mode (keyring / vault / plaintext) via core's
    /// [`sshrack_core::secret::vault::seal_body`], calls
    /// `credential::add_credential` (add) or splices in place preserving the
    /// original id (edit), persists the config, reloads, and returns to the
    /// launcher.
    SaveCred,
    /// Pure intent: the user pressed Esc / Ctrl-C inside the wizard. The loop
    /// discards the wizard and returns to the launcher.
    Cancel,
    /// Pure intent: the store view's cursor is on keyring. The loop probes
    /// [`sshrack_core::secret::OsKeyring`] availability, then migrates every
    /// stored password into keyring mode via [`vault::transform::migrate`] (the
    /// same core path the CLI's `store use keyring` takes) and persists the
    /// config. A failure (keyring daemon down, migrate error, write error)
    /// surfaces in the store view's status line and stays in the view.
    ///
    /// [`vault::transform::migrate`]: sshrack_core::secret::vault::transform::migrate
    SwitchToKeyring,
    /// Pure intent: the store view's cursor is on vault. The loop drives a
    /// masked double-entry passphrase popup via [`TuiPassphrase`], then calls
    /// [`vault::enable`] (the same core fn the CLI's `store use vault` uses) to
    /// derive a fresh key, write the verifier, and migrate every existing
    /// password into vault mode, and persists the config. A cancel inside the
    /// passphrase popup surfaces as [`SshrackError::Interrupted`] → stay in the
    /// view with NO status write (the popup dismissing is the feedback); other
    /// errors surface in the view's status line.
    ///
    /// [`vault::enable`]: sshrack_core::secret::vault::enable
    SwitchToVault,
    /// Pure intent: the store view's cursor is on plaintext. The loop drives a
    /// confirm popup (downgrade warning) via [`TuiPassphrase::confirm`]; on Yes
    /// it migrates every stored password into plaintext mode via
    /// [`vault::transform::migrate`] (the same core path the CLI's `store use
    /// plaintext` takes) and persists the config. On No it cancels (no
    /// migration). Leaving vault mode needs the source vault key, unlocked via
    /// [`TuiPassphrase`] first.
    ///
    /// [`vault::transform::migrate`]: sshrack_core::secret::vault::transform::migrate
    SwitchToPlaintext,
    /// Pure intent: the user pressed `^d` on the selected host. The launcher's
    /// `on_key` set `pending_delete` to the host's id and returned this. The
    /// event loop drives a "Remove <name>? (y/n)" confirm popup via
    /// [`TuiPassphrase::confirm`]; on Yes it calls
    /// [`host::delete_host_with_secret`] (remove + keyring cleanup so no secret
    /// is orphaned), persists, reloads, and returns to the launcher with a
    /// "removed <name>" status. No / Esc cancels. `on_key` itself does NO I/O.
    ///
    /// [`host::delete_host_with_secret`]: sshrack_core::host::delete_host_with_secret
    DeleteHost,
    /// Pure intent: the user pressed `^d` on the selected credential. The
    /// credential panel's selection points at the target; `on_key` itself does
    /// NO I/O. The event loop drives a "Remove <name>? (y/n)" confirm popup via
    /// [`TuiPassphrase::confirm`]; on Yes it calls
    /// [`credential::delete_credential_with_secret`] (remove + keyring cleanup
    /// so no secret is orphaned), persists, reloads, and returns to the panel
    /// with a "removed <name>" status. No / Esc cancels.
    ///
    /// [`credential::delete_credential_with_secret`]: sshrack_core::credential::delete_credential_with_secret
    DeleteCred,
    /// Pure intent: switch the active tab (Tab / Shift-Tab).
    /// `on_key` already set `active_tab`; the loop just re-renders. The carried
    /// `Tab` is matched by tests via `matches!(out, Outcome::SwitchTab(Tab::…))`
    /// to assert *which* tab was routed to; `matches!` only structurally inspects
    /// the value (does not read the field), so clippy flags the payload as dead.
    /// Kept because the structural-match observability is the whole point.
    #[allow(dead_code)]
    SwitchTab(Tab),
    /// Pure intent: open an overlay. `on_key` already stashed the overlay on
    /// `App::overlay`; the loop just re-renders. The carried `Overlay` is matched
    /// by tests via `matches!(out, Outcome::OpenOverlay(Overlay::…))` to assert
    /// *which* overlay opened; `matches!` only structurally inspects it (does not
    /// read the field), so clippy flags the payload as dead. Kept because the
    /// structural-match observability is the whole point.
    #[allow(dead_code)]
    OpenOverlay(Overlay),
    /// Pure intent: close the current overlay (Esc / Ctrl-C inside one). The
    /// loop clears `App::overlay` and surfaces a default status.
    CloseOverlay,
    /// Pure intent: the user pressed `Ctrl-T` on the Hosts tab with a host
    /// selected. `on_key` set `App::pending_transfer_host` to the selected host. The
    /// event loop reads the Host, runs [`crate::tui::transfer::open::open_transfer`]
    /// (which mirrors `connect_host`'s auth/hostkey steps then opens the
    /// `SftpWorker`), and assigns `App::transfer` + `App::transfer_worker`. A
    /// cancel inside a vault/host-key popup surfaces as
    /// [`SshrackError::Interrupted`] → return to the launcher (no status write).
    ///
    /// This variant carries no data because the Host lives on `App` (single
    /// source of truth, clearable on cancel), mirroring
    /// [`Outcome::ConnectRequested`].
    ///
    /// [`SshrackError::Interrupted`]: sshrack_core::error::SshrackError::Interrupted
    OpenTransfer,
    /// Pure intent: the user asked to leave the transfer screen
    /// (`ScreenOutcome::CloseTransfer` — Esc with no transfer in flight, or
    /// Ctrl-C inside the transfer screen). The loop drops `App::transfer`,
    /// `App::transfer_worker`, and `App::transfer_key_artifact` together so the
    /// worker's `Drop` tears down the master `ssh -N` (RAII) and the inline-key
    /// temp files are removed. No status write — the screen closing is the
    /// feedback.
    CloseTransfer,
}

/// An overlay layered on top of the shell. The shell keeps rendering behind it
/// (no dark scrim — terminals cannot do translucency; [`draw_dialog`] clears
/// the dialog area instead). At most one overlay is open at a time.
///
/// `Clone`: `on_key` `take()`s the overlay to route a key into it without a
/// borrow conflict, then stashes it back unless the overlay signaled a
/// terminal outcome (save / cancel). Carrying the wizard forms inside their
/// variants keeps the form state alive across keystrokes without a separate
/// `Option<HostForm>` field.
//
// `large_enum_variant`: the wizard variants carry full forms while
// Help/StorePicker are near-ZSTs — the enum is box-free by intent
// (a single live overlay, cloned only on OpenOverlay).
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Overlay {
    /// The Help keymap reference (F1). Static text — no carried state.
    Help,
    /// Host add/edit wizard. The form lives inside the overlay so its state
    /// survives across keystrokes.
    HostWizard(HostForm),
    /// Credential add/edit wizard.
    CredWizard(CredForm),
    /// Storage-mode picker (opened from Settings). Task 8 drives the cursor +
    /// switch intents; for Task 6 Esc closes it.
    StorePicker,
    /// A modal error alert (e.g. a failed SFTP open). `body` is the multi-line
    /// message; `Esc` / `Ctrl-C` close it via the standard overlay close path
    /// (`Outcome::CloseOverlay`) — the shell renders behind it. Set by the
    /// `OpenTransfer` arm for every `open_transfer` failure.
    Alert { title: String, body: String },
}

/// The consolidated status-bar message: a transient one-liner the user reads as
/// feedback after every action (save, cancel, delete, switch, error). Carried on
/// [`App::status`] and rendered as a single footer line across every view
/// (Task 20: unify the per-action status into one channel). `is_error` tints the
/// line red so failures stand out from informational notices.
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// The message text, or `None` to show the default key-binding hint.
    pub message: Option<String>,
    /// `true` for failures (red); `false` for informational notices (normal).
    pub is_error: bool,
}

impl Status {
    /// An informational status (e.g. "host saved").
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            is_error: false,
        }
    }

    /// An error status (rendered red).
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            message: Some(message.into()),
            is_error: true,
        }
    }

    /// No status — the footer falls back to the default key-binding hint.
    pub fn empty() -> Self {
        Self {
            message: None,
            is_error: false,
        }
    }
}
