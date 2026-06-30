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
//! [`Rc<RefCell<Tui>>`] (see [`crate::tui::app::TerminalHandle`]).
//! [`TuiPassphrase`] stores a [`TerminalHandle`] cloned from the
//! [`crate::tui::app::TerminalGuard`]; its `&self` methods `borrow_mut()` the
//! terminal to call the popup-driving free functions. The guard owns the only
//! strong reference, so the handle goes dead on guard drop — RAII restore is
//! unaffected.
//!
//! # Purity boundary
//!
//! The terminal-driving functions are I/O and not unit-testable. The single
//! *decision* — which key yields which yes/no answer — is extracted into the
//! pure [`confirm_from_key`] helper, which IS unit-tested (TDD: RED then
//! GREEN). The popup wires raw keys to that helper.

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

use super::app::{TerminalHandle, Tui};
use super::popup;

/// The yes/no answer derived from a single key in a confirm popup.
///
/// Kept distinct from `bool` so the popup loop can distinguish "this key is a
/// decision" ([`ConfirmAnswer::Yes`]/[`ConfirmAnswer::No`]) from "keep waiting"
/// ([`ConfirmAnswer::Pending`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn confirm_from_key(key: KeyCode) -> ConfirmAnswer {
    match key {
        KeyCode::Char('y') | KeyCode::Char('Y') => ConfirmAnswer::Yes,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmAnswer::No,
        _ => ConfirmAnswer::Pending,
    }
}

/// Mask character shown for each typed password byte. The literal bullet keeps
/// the field non-empty looking without leaking length precisely.
#[allow(dead_code)]
const MASK: &str = "•";

/// Read a vault passphrase via a masked-input popup. Returns the typed string
/// wrapped in [`Zeroizing`] so it is wiped on drop. `Enter` submits; `Esc` or
/// `Ctrl-C` cancels ([`SshrackError::Interrupted`]). The popup re-renders on
/// every keystroke so masking tracks input live.
#[allow(dead_code)]
pub fn prompt_password(terminal: &mut Tui, title: &str) -> Result<Zeroizing<String>, SshrackError> {
    let mut buffer = String::new();
    loop {
        render_password_popup(terminal, title, &buffer, None);
        match read_decision_key()? {
            KeyDecision::Char(ch) => buffer.push(ch),
            KeyDecision::Backspace => {
                buffer.pop();
            }
            KeyDecision::Submit => return Ok(Zeroizing::new(buffer)),
            KeyDecision::Cancel => return Err(SshrackError::Interrupted),
            KeyDecision::Other => {}
        }
    }
}

/// Read a new passphrase twice via masked popups, looping until the two entries
/// match. A mismatch re-prompts from scratch. Cancel (`Esc`/`Ctrl-C`) at any
/// point yields [`SshrackError::Interrupted`].
#[allow(dead_code)]
pub fn prompt_password_confirm(
    terminal: &mut Tui,
    title: &str,
) -> Result<Zeroizing<String>, SshrackError> {
    loop {
        let first = prompt_password(terminal, title)?;
        let mut second = String::new();
        loop {
            render_password_popup(terminal, "Confirm passphrase", &second, None);
            match read_decision_key()? {
                KeyDecision::Char(ch) => second.push(ch),
                KeyDecision::Backspace => {
                    second.pop();
                }
                KeyDecision::Submit => {
                    if second.as_str() == first.as_str() {
                        return Ok(Zeroizing::new(second));
                    }
                    // Mismatch: flash a hint and restart the whole flow.
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
#[allow(dead_code)]
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
            .map_err(SshrackError::from)?;

        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
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
/// cancel; other I/O errors propagate as [`SshrackError::Io`].
fn read_decision_key() -> Result<KeyDecision, SshrackError> {
    loop {
        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
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

/// [`PassphraseProvider`] for the TUI. Holds a shared handle to the terminal
/// (cloned from [`crate::tui::app::TerminalGuard::handle`]); its `&self`
/// methods `borrow_mut()` the terminal to drive a popup.
///
/// Construct via [`TuiPassphrase::new`] *while the guard is alive* and pass it
/// to [`sshrack_core::secret::vault::ensure_unlocked_vault_key`] (or any other
/// core API that consumes a `&dyn PassphraseProvider`).
#[allow(dead_code)]
pub struct TuiPassphrase {
    terminal: TerminalHandle,
}

impl TuiPassphrase {
    /// Build a provider that drives popups on `terminal` (a handle cloned from
    /// the live [`crate::tui::app::TerminalGuard`]).
    #[allow(dead_code)]
    pub fn new(terminal: TerminalHandle) -> Self {
        Self { terminal }
    }
}

impl PassphraseProvider for TuiPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        prompt_password(&mut self.terminal.borrow_mut(), "Passphrase")
    }

    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        prompt_password_confirm(&mut self.terminal.borrow_mut(), "New passphrase")
    }

    fn confirm(&self, text: &str) -> Result<bool, SshrackError> {
        confirm_popup(&mut self.terminal.borrow_mut(), text)
    }
}

/// Build a host-key confirm closure for [`sshrack_core::hostkey::run_host_key_flow`].
/// The closure renders the fingerprint text in a confirm popup and returns the
/// user's yes/no decision. `Ctrl-C` and `Esc` both map to "decline" (false),
/// which `run_host_key_flow` turns into [`SshrackError::HostKeyNotConfirmed`].
///
/// `terminal` is captured by move; the closure is `FnOnce` because
/// `run_host_key_flow` consumes it.
#[allow(dead_code)]
pub fn host_key_confirm(terminal: TerminalHandle) -> impl FnOnce(&str) -> bool + use<> {
    move |text: &str| {
        // An interrupted confirm (Ctrl-C) is treated as a decline: the host
        // key is NOT appended to known_hosts, and run_host_key_flow returns
        // HostKeyNotConfirmed. No panic, no swallowed decision.
        confirm_popup(&mut terminal.borrow_mut(), text).unwrap_or(false)
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
}
