//! Inline passphrase / input prompts for the TUI: a
//! [`sshrack_core::secret::PassphraseProvider`] impl driven by ratatui popups,
//! plus a host-key confirm closure for
//! [`sshrack_core::hostkey::run_host_key_flow`].
//!
//! # Terminal-borrow design
//!
//! [`sshrack_core::secret::PassphraseProvider`] methods are `&self`, but
//! rendering a ratatui popup needs `&mut Tui`. We solve this without changing
//! the core trait and without `unsafe` by sharing the terminal behind an
//! `Rc<RefCell<Tui>>` whose only strong ref lives in
//! [`crate::tui::app::TerminalGuard`]. The prompt layer holds a *weak* handle
//! ([`crate::tui::app::TerminalHandle`] = `Weak<RefCell<Tui>>`) cloned from the
//! guard; [`TuiPassphrase`] stores it and its `&self` methods [`upgrade`] it at
//! call time, then `borrow_mut()` the terminal to drive a popup. Because the
//! handle is weak, a `TuiPassphrase` (or host-key closure) that outlives the
//! guard cannot keep the `Tui` alive past the RAII restore — [`upgrade`]
//! returns `None` and the call surfaces as a silent
//! [`SshrackError::Interrupted`] cancel.
//!
//! [`upgrade`]: std::rc::Weak::upgrade
//!
//! # Purity boundary
//!
//! The terminal-driving functions are I/O and not unit-testable. The single
//! *decision* — which key yields which yes/no answer — is extracted into the
//! pure [`confirm_from_key`] helper, which IS unit-tested (TDD: RED then
//! GREEN). The popup wires raw keys to that helper.

use std::cell::RefCell;
use std::rc::Rc;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::Alignment,
    style::{Style, Stylize},
    text::Line,
    widgets::Paragraph,
};
use sshrack_core::error::SshrackError;
use sshrack_core::secret::PassphraseProvider;
use zeroize::Zeroizing;

use super::popup;
use super::{TerminalHandle, Tui};

/// The yes/no answer derived from a single key in a confirm popup.
///
/// Kept distinct from `bool` so the popup loop can distinguish "this key is a
/// decision" ([`ConfirmAnswer::Yes`]/[`ConfirmAnswer::No`]) from "keep waiting"
/// ([`ConfirmAnswer::Pending`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAnswer {
    /// User confirmed (y/Y).
    Yes,
    /// User declined (n/N/Esc).
    No,
    /// Key does not resolve to a decision; the popup keeps reading.
    Pending,
}

/// Pure decision for a yes/no popup: which key yields which answer. Has no
/// I/O, so it is unit-testable without a terminal or event source.
///
/// - `y`/`Y` → [`ConfirmAnswer::Yes`]
/// - `n`/`N`/`Esc` → [`ConfirmAnswer::No`] (Esc is a cancel = decline)
/// - anything else → [`ConfirmAnswer::Pending`]
pub fn confirm_from_key(key: KeyCode) -> ConfirmAnswer {
    match key {
        KeyCode::Char('y') | KeyCode::Char('Y') => ConfirmAnswer::Yes,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmAnswer::No,
        _ => ConfirmAnswer::Pending,
    }
}

/// A store-mode selection made in the store-pick popup. The popup returns
/// `Option<StorePick>` — `None` when the user cancelled. Distinct from
/// `crate::tui::store::StoreModeChoice` (the `Overlay::StorePicker` dialog
/// view that returns `Outcome`) because this popup must return a selection
/// synchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePick {
    Keyring,
    Vault,
    Plaintext,
}

impl StorePick {
    /// Render + navigation order shown in the popup.
    pub const ORDER: &'static [StorePick] =
        &[StorePick::Keyring, StorePick::Vault, StorePick::Plaintext];

    /// The user-facing label.
    pub fn label(self) -> &'static str {
        match self {
            StorePick::Keyring => "keyring",
            StorePick::Vault => "vault",
            StorePick::Plaintext => "plaintext",
        }
    }

    /// A one-line trade-off blurb shown beside the option in the popup.
    pub fn blurb(self) -> &'static str {
        match self {
            StorePick::Keyring => "OS keyring (recommended); needs a Secret Service daemon",
            StorePick::Vault => "master-passphrase encryption (portable across machines)",
            StorePick::Plaintext => "stored in the clear — a security downgrade",
        }
    }
}

/// The decoded action for one key in the store-pick popup. Mirrors the shape of
/// [`ConfirmAnswer`]: distinguishes "this key does something" from "ignore me".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePickAction {
    /// Move the cursor up (wraps).
    Up,
    /// Move the cursor down (wraps).
    Down,
    /// Enter: confirm the highlighted option.
    Confirm,
    /// Esc / Ctrl-C: cancel the popup.
    Cancel,
    /// Any other key: ignored.
    Other,
}

/// Pure decision for the store-pick popup: which key yields which action. No
/// I/O, so it is unit-testable without a terminal. `Ctrl-C` cancels regardless
/// of the underlying char.
pub fn store_pick_action_from_key(key: KeyCode, mods: KeyModifiers) -> StorePickAction {
    if mods == KeyModifiers::CONTROL && key == KeyCode::Char('c') {
        return StorePickAction::Cancel;
    }
    match key {
        KeyCode::Up => StorePickAction::Up,
        KeyCode::Down => StorePickAction::Down,
        KeyCode::Enter => StorePickAction::Confirm,
        KeyCode::Esc => StorePickAction::Cancel,
        _ => StorePickAction::Other,
    }
}

/// Mask character shown for each typed password byte. The literal bullet keeps
/// the field non-empty looking without leaking length precisely.
const MASK: &str = "•";

/// Upgrade a weak terminal handle to the owning `Rc<RefCell<Tui>>` so the
/// caller can `borrow_mut()` it for the duration of one popup call. Returns
/// [`SshrackError::Interrupted`] (the same silent cancel a `Ctrl-C` produces)
/// when the guard is already gone — a popup that runs after `tui::run`
/// returned cannot render and is treated as user-initiated cancellation, never
/// as a noisy panic or `io error`.
fn upgrade_terminal(handle: &TerminalHandle) -> Result<Rc<RefCell<Tui>>, SshrackError> {
    handle.upgrade().ok_or(SshrackError::Interrupted)
}

/// Read a vault passphrase via a masked-input popup. Returns the typed string
/// wrapped in [`Zeroizing`] so it is wiped on drop. `Enter` submits; `Esc` or
/// `Ctrl-C` cancels ([`SshrackError::Interrupted`]). The popup re-renders on
/// every keystroke so masking tracks input live.
pub fn prompt_password(terminal: &mut Tui, title: &str) -> Result<Zeroizing<String>, SshrackError> {
    // Zeroizing wrapper so the typed passphrase bytes are wiped on drop on
    // EVERY path — including cancel (Esc/Ctrl-C), where the buffer would
    // otherwise sit on the heap until the allocator reuses the slot. On Submit
    // we move the inner String into a fresh Zeroizing so the wipe still runs
    // when the caller drops the returned value.
    let mut buffer = Zeroizing::new(String::new());
    loop {
        render_password_popup(terminal, title, buffer.as_str(), None);
        match read_decision_key()? {
            KeyDecision::Char(ch) => buffer.push(ch),
            KeyDecision::Backspace => {
                buffer.pop();
            }
            KeyDecision::Submit => {
                // Move the inner String out so this Zeroizing does not double-
                // hold it; the returned Zeroizing owns the wipe from here.
                // `&mut *buffer` goes through DerefMut to the inner String
                // (not AsMut<str>), so mem::take yields the owned String.
                let inner = std::mem::take(&mut *buffer);
                return Ok(Zeroizing::new(inner));
            }
            KeyDecision::Cancel => return Err(SshrackError::Interrupted),
            KeyDecision::Other => {}
        }
    }
}

/// Read a new passphrase twice via masked popups, looping until the two entries
/// match. A mismatch re-prompts from scratch. Cancel (`Esc`/`Ctrl-C`) at any
/// point yields [`SshrackError::Interrupted`].
pub fn prompt_password_confirm(
    terminal: &mut Tui,
    title: &str,
) -> Result<Zeroizing<String>, SshrackError> {
    loop {
        let first = prompt_password(terminal, title)?;
        // Zeroizing so the second-entry bytes are wiped on cancel / mismatch
        // restart, not left on the heap. On match we move the inner String
        // into the returned Zeroizing (same pattern as prompt_password).
        let mut second = Zeroizing::new(String::new());
        loop {
            render_password_popup(terminal, "Confirm passphrase", second.as_str(), None);
            match read_decision_key()? {
                KeyDecision::Char(ch) => second.push(ch),
                KeyDecision::Backspace => {
                    second.pop();
                }
                KeyDecision::Submit => {
                    if second.as_str() == first.as_str() {
                        let inner = std::mem::take(&mut *second);
                        return Ok(Zeroizing::new(inner));
                    }
                    // Mismatch: flash a hint and restart the whole flow. The
                    // second buffer drops here (Zeroizing wipes it) before the
                    // next iteration builds a fresh one.
                    render_password_popup(terminal, "Mismatch — try again", "", Some(true));
                    break;
                }
                KeyDecision::Cancel => return Err(SshrackError::Interrupted),
                KeyDecision::Other => {}
            }
        }
    }
}

/// Render `text` in a popup and read keys until [`confirm_from_key`] resolves.
/// Returns `Ok(true)` on Yes, `Ok(false)` on No/Esc, `Err(Interrupted)` on
/// `Ctrl-C`.
pub fn confirm_popup(terminal: &mut Tui, text: &str) -> Result<bool, SshrackError> {
    loop {
        let lines = text
            .lines()
            .map(Line::from)
            .chain(std::iter::once(Line::from("")))
            .chain(std::iter::once(
                Line::from("[y] yes   [n] no").style(Style::new().dim()),
            ))
            .collect::<Vec<_>>();
        let body = Paragraph::new(lines).alignment(Alignment::Left);
        terminal
            .draw(|f| popup::render_popup(f, "Confirm", body))
            .map_err(SshrackError::from_prompt_io)?;

        if !event::poll(std::time::Duration::from_millis(250))
            .map_err(SshrackError::from_prompt_io)?
        {
            continue;
        }
        let Event::Key(key) = event::read().map_err(SshrackError::from_prompt_io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Ctrl-C cancels the whole flow.
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return Err(SshrackError::Interrupted);
        }
        match confirm_from_key(key.code) {
            ConfirmAnswer::Yes => return Ok(true),
            ConfirmAnswer::No => return Ok(false),
            ConfirmAnswer::Pending => {}
        }
    }
}

/// Decoded result of one key in a password popup.
enum KeyDecision {
    /// A printable character was typed; append to the buffer.
    Char(char),
    /// Backspace: drop the last char.
    Backspace,
    /// Enter: submit the buffer.
    Submit,
    /// Esc / Ctrl-C: cancel the prompt.
    Cancel,
    /// Any other key (modifiers-only, releases, arrows, ...): ignored.
    Other,
}

/// Block until one key press, then decode it into a [`KeyDecision`]. Returns
/// [`SshrackError::Interrupted`] on a read failure that looks like a user
/// cancel (EINTR); other I/O errors propagate as [`SshrackError::Io`].
fn read_decision_key() -> Result<KeyDecision, SshrackError> {
    loop {
        if !event::poll(std::time::Duration::from_millis(250))
            .map_err(SshrackError::from_prompt_io)?
        {
            continue;
        }
        let Event::Key(key) = event::read().map_err(SshrackError::from_prompt_io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        // Ctrl-C is cancel regardless of the underlying char.
        if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
            return Ok(KeyDecision::Cancel);
        }
        // Ignore Ctrl/Alt/AltGr combos — only bare characters are password
        // bytes. A bare Enter submits, a bare Backspace deletes, a bare Esc
        // cancels.
        if !key.modifiers.is_empty() {
            return Ok(KeyDecision::Other);
        }
        return Ok(match key.code {
            KeyCode::Char(ch) => KeyDecision::Char(ch),
            KeyCode::Enter => KeyDecision::Submit,
            KeyCode::Backspace => KeyDecision::Backspace,
            KeyCode::Esc => KeyDecision::Cancel,
            _ => KeyDecision::Other,
        });
    }
}

/// Render the password popup. `buffer` is masked with [`MASK`]; `mismatch`
/// non-None tints the title to signal a failed confirmation. Draw errors are
/// tolerated (best-effort render); a transient failure is retried on the next
/// keystroke loop iteration.
fn render_password_popup(terminal: &mut Tui, title: &str, buffer: &str, mismatch: Option<bool>) {
    let masked: String = std::iter::repeat_n(MASK, buffer.chars().count()).collect();
    let mut lines = vec![Line::from(masked.as_str()).bold()];
    lines.push(Line::from(""));
    lines.push(Line::from("[Enter] confirm   [Esc] cancel").style(Style::new().dim()));
    let body = Paragraph::new(lines).alignment(Alignment::Left);
    let title = if mismatch == Some(true) {
        "Mismatch — try again"
    } else {
        title
    };
    let _ = terminal.draw(|f| popup::render_popup(f, title, body));
}

/// [`PassphraseProvider`] for the TUI. Holds a weak handle to the terminal
/// (cloned from [`crate::tui::app::TerminalGuard::handle`]); its `&self`
/// methods [`upgrade`](std::rc::Weak::upgrade) the handle and `borrow_mut()`
/// the terminal to drive a popup. If the guard has already dropped, the
/// `upgrade` returns `None` and the call surfaces as
/// [`SshrackError::Interrupted`] — a popup cannot run after the terminal
/// restore, so it is treated as a silent cancel.
///
/// Construct via [`TuiPassphrase::new`] *while the guard is alive* and pass it
/// to [`sshrack_core::secret::vault::ensure_unlocked_vault_key`] (or any other
/// core API that consumes a `&dyn PassphraseProvider`).
pub struct TuiPassphrase {
    terminal: TerminalHandle,
}

impl TuiPassphrase {
    /// Build a provider that drives popups on `terminal` (a weak handle cloned
    /// from the live [`crate::tui::app::TerminalGuard`]).
    pub fn new(terminal: TerminalHandle) -> Self {
        Self { terminal }
    }
}

impl PassphraseProvider for TuiPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        let rc = upgrade_terminal(&self.terminal)?;
        prompt_password(&mut rc.borrow_mut(), "Passphrase")
    }

    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        let rc = upgrade_terminal(&self.terminal)?;
        prompt_password_confirm(&mut rc.borrow_mut(), "New passphrase")
    }

    fn confirm(&self, text: &str) -> Result<bool, SshrackError> {
        let rc = upgrade_terminal(&self.terminal)?;
        confirm_popup(&mut rc.borrow_mut(), text)
    }
}

/// Build a host-key confirm closure for [`sshrack_core::hostkey::run_host_key_flow`],
/// paired with a shared interruption flag. The closure renders the fingerprint
/// text in a confirm popup and returns the user's yes/no decision. On
/// `Ctrl-C`/`Esc` (`confirm_popup` returns [`SshrackError::Interrupted`]) or when
/// the guard is already gone, the closure returns `false` (decline —
/// `run_host_key_flow` then surfaces [`SshrackError::HostKeyNotConfirmed`]) AND
/// flips the shared [`Cell`] so the caller ([`super::connect::connect_host`])
/// can re-surface the cancel as `Interrupted` afterwards. This keeps the
/// connect-cancel UX consistent with the vault-unlock popup: a cancel inside
/// the host-key popup returns the user to the launcher (no status write), NOT
/// a "connect failed" error.
///
/// `terminal` is a weak handle captured by move; the closure is `FnOnce`
/// because `run_host_key_flow` consumes it. If the guard is gone by the time
/// the closure runs, the popup cannot render and the closure returns `false`
/// (decline) via [`upgrade_terminal`]'s `Interrupted` mapping AND marks the
/// flow interrupted — never a panic.
///
/// Returns `(closure, interrupted_flag)`: pass the closure to
/// `run_host_key_flow`, then inspect the flag; when it is `true`, return
/// `Err(SshrackError::Interrupted)` from the caller so the cancel returns the
/// user to the launcher (no status write), not as a host-key rejection.
pub fn host_key_confirm(
    terminal: TerminalHandle,
) -> (
    impl FnOnce(&str) -> bool + use<>,
    std::rc::Rc<std::cell::Cell<bool>>,
) {
    let flag = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag_for_closure = std::rc::Rc::clone(&flag);
    let closure = move |text: &str| {
        // An interrupted confirm (Ctrl-C, or guard already dropped) flips the
        // shared flag so the caller re-surfaces it as Interrupted (cancel),
        // and declines the popup so run_host_key_flow does NOT append the key.
        match upgrade_terminal(&terminal).and_then(|rc| confirm_popup(&mut rc.borrow_mut(), text)) {
            Ok(decision) => decision,
            Err(SshrackError::Interrupted) => {
                flag_for_closure.set(true);
                false
            }
            // Any other error (e.g. an I/O failure mid-popup) also declines;
            // surfacing those is the caller's job, but they are not a cancel.
            Err(_) => false,
        }
    };
    (closure, flag)
}

/// Drive the store-mode pick popup on the terminal behind `handle`. Returns
/// `Ok(Some(pick))` when the user chose a mode, `Ok(None)` when they cancelled
/// (Esc / Ctrl-C), or `Err(Interrupted)` when the terminal guard is already
/// gone (a popup after `tui::run` returned — treated as a silent cancel, never
/// a panic). Used by the SaveCred recovery path so the user can choose a store
/// mode without leaving the credential wizard.
pub fn prompt_store_pick(handle: &TerminalHandle) -> Result<Option<StorePick>, SshrackError> {
    let rc = upgrade_terminal(handle)?;
    store_pick_popup(&mut rc.borrow_mut())
}

/// Render the three store modes with a cursor marker and read keys until the
/// user confirms or cancels. Mirrors [`confirm_popup`]'s render/poll/read loop.
fn store_pick_popup(terminal: &mut Tui) -> Result<Option<StorePick>, SshrackError> {
    let mut cursor: usize = 0;
    let len = StorePick::ORDER.len();
    loop {
        let mut lines: Vec<Line> = StorePick::ORDER
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let marker = if i == cursor { "▶ " } else { "  " };
                Line::from(format!("{marker}{} — {}", m.label(), m.blurb()))
            })
            .collect();
        lines.push(Line::from(""));
        lines.push(
            Line::from("[↑/↓] select   [Enter] confirm   [Esc] cancel")
                .style(ratatui::style::Style::new().dim()),
        );
        let body =
            ratatui::widgets::Paragraph::new(lines).alignment(ratatui::layout::Alignment::Left);
        terminal
            .draw(|f| popup::render_popup(f, "Choose store mode", body))
            .map_err(SshrackError::from_prompt_io)?;

        if !event::poll(std::time::Duration::from_millis(250))
            .map_err(SshrackError::from_prompt_io)?
        {
            continue;
        }
        let Event::Key(key) = event::read().map_err(SshrackError::from_prompt_io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match store_pick_action_from_key(key.code, key.modifiers) {
            StorePickAction::Up => cursor = (cursor + len - 1) % len,
            StorePickAction::Down => cursor = (cursor + 1) % len,
            StorePickAction::Confirm => return Ok(StorePick::ORDER.get(cursor).copied()),
            StorePickAction::Cancel => return Ok(None),
            StorePickAction::Other => {}
        }
    }
}

#[cfg(test)]
mod tests {
    //! TDD for the pure `confirm_from_key` decision (RED → GREEN). The popup
    //! rendering and key-reading are I/O and are not unit-tested here; they are
    //! covered by integration tests in a later task.

    use super::*;
    use crossterm::event::KeyCode;

    #[test]
    fn y_uppercase_and_lowercase_are_yes() {
        assert_eq!(confirm_from_key(KeyCode::Char('y')), ConfirmAnswer::Yes);
        assert_eq!(confirm_from_key(KeyCode::Char('Y')), ConfirmAnswer::Yes);
    }

    #[test]
    fn n_uppercase_and_lowercase_are_no() {
        assert_eq!(confirm_from_key(KeyCode::Char('n')), ConfirmAnswer::No);
        assert_eq!(confirm_from_key(KeyCode::Char('N')), ConfirmAnswer::No);
    }

    #[test]
    fn esc_is_no() {
        assert_eq!(confirm_from_key(KeyCode::Esc), ConfirmAnswer::No);
    }

    #[test]
    fn enter_and_other_keys_are_pending() {
        assert_eq!(confirm_from_key(KeyCode::Enter), ConfirmAnswer::Pending);
        assert_eq!(confirm_from_key(KeyCode::Char('a')), ConfirmAnswer::Pending);
        assert_eq!(confirm_from_key(KeyCode::Backspace), ConfirmAnswer::Pending);
        assert_eq!(confirm_from_key(KeyCode::Tab), ConfirmAnswer::Pending);
    }

    #[test]
    fn confirm_answer_equality_holds() {
        // Pin the enum shape so downstream matches stay exhaustive.
        assert_ne!(ConfirmAnswer::Yes, ConfirmAnswer::No);
        assert_ne!(ConfirmAnswer::Yes, ConfirmAnswer::Pending);
        assert_ne!(ConfirmAnswer::No, ConfirmAnswer::Pending);
    }

    #[test]
    fn store_pick_up_down_navigate() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Up, KeyModifiers::NONE),
            StorePickAction::Up
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Down, KeyModifiers::NONE),
            StorePickAction::Down
        );
    }

    #[test]
    fn store_pick_enter_confirms_esc_cancels() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Enter, KeyModifiers::NONE),
            StorePickAction::Confirm
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Esc, KeyModifiers::NONE),
            StorePickAction::Cancel
        );
    }

    #[test]
    fn store_pick_ctrl_c_cancels() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            StorePickAction::Cancel
        );
    }

    #[test]
    fn store_pick_other_keys_are_other() {
        assert_eq!(
            store_pick_action_from_key(KeyCode::Char('a'), KeyModifiers::NONE),
            StorePickAction::Other
        );
        assert_eq!(
            store_pick_action_from_key(KeyCode::Tab, KeyModifiers::NONE),
            StorePickAction::Other
        );
    }

    #[test]
    fn store_pick_order_and_labels_are_stable() {
        assert_eq!(
            StorePick::ORDER,
            &[StorePick::Keyring, StorePick::Vault, StorePick::Plaintext]
        );
        assert_eq!(StorePick::Keyring.label(), "keyring");
        assert_eq!(StorePick::Vault.label(), "vault");
        assert_eq!(StorePick::Plaintext.label(), "plaintext");
        // blurbs are non-empty one-liners (rendered beside each option).
        for m in StorePick::ORDER {
            assert!(!m.blurb().is_empty());
        }
    }
}
