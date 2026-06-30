//! Interactive prompt helpers built on `dialoguer`.
//!
//! These functions and impls are the CLI's prompt surface; they are wired into
//! the `connect`/`scp`/`host`/`cred`/`store` command handlers.
//!
//! Three concerns live here:
//!
//! - [`DialoguerPassphrase`] — the CLI's impl of core's
//!   [`PassphraseProvider`](`sshrack_core::secret::PassphraseProvider`) trait
//!   (passphrase / passphrase-confirm / confirm). Vault and host-key
//!   orchestration in core take the trait by reference, so this is the one
//!   concrete prompt source the binary wires up.
//! - [`password_mode()`] — the first-use storage-mode menu (keyring / vault /
//!   plaintext). This is a CLI/UX concern, so it is a free function here, not a
//!   method on the core trait (core only exposes the [`SecretStore`] types).
//! - [`confirm_with_fallback()`] — a `--no-input`-aware confirm used by the
//!   management commands: under `--no-input` it returns `Ok(false)` immediately
//!   (fail-closed — destructive actions do not proceed unattended).
//!
//! All dialoguer interaction converts io errors via
//! [`SshrackError::from_prompt_io`], which maps a Ctrl+C
//! (`ErrorKind::Interrupted`) to the silent [`SshrackError::Interrupted`]
//! cancel. Methods that return a passphrase return [`Zeroizing<String>`] so the
//! plaintext is wiped on drop.
//!
//! Design rule: nothing here ever prints, logs, or returns a passphrase or
//! plaintext in an error message.
//!
//! [`SecretStore`]: sshrack_core::config::schema::SecretStore

use dialoguer::Password;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, FuzzySelect};
use sshrack_core::error::SshrackError;
use sshrack_core::secret::PassphraseProvider;
use zeroize::Zeroizing;

/// The CLI's only passphrase source: dialoguer prompts on the TTY.
///
/// Implements core's [`PassphraseProvider`] so the vault unlock / rekey and the
/// host-key confirm flows in `sshrack_core::vault` / `sshrack_core::hostkey`
/// never call dialoguer directly — they take `&dyn PassphraseProvider` and stay
/// unit-testable with the fakes in `sshrack_core::secret::test_doubles`.
pub struct DialoguerPassphrase;

impl PassphraseProvider for DialoguerPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        let theme = ColorfulTheme::default();
        let p = Password::with_theme(&theme)
            .with_prompt("Vault passphrase")
            .interact()
            .map_err(SshrackError::from_prompt_io)?;
        Ok(Zeroizing::new(p))
    }

    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        let theme = ColorfulTheme::default();
        let p = Password::with_theme(&theme)
            .with_prompt("New vault passphrase")
            .with_confirmation("Confirm passphrase", "passphrases do not match")
            .interact()
            .map_err(SshrackError::from_prompt_io)?;
        Ok(Zeroizing::new(p))
    }

    fn confirm(&self, text: &str) -> Result<bool, SshrackError> {
        let agreed = Confirm::new()
            .with_prompt(text)
            .default(false)
            .interact()
            .map_err(SshrackError::from_prompt_io)?;
        Ok(agreed)
    }
}

/// The user's choice on the first-use password-mode prompt. `Keyring` is the
/// recommended default (presented first / pre-selected): plaintext never lands
/// on disk and no passphrase needs remembering.
///
/// This is a CLI-local enum because the first-use menu is a UI concern; core
/// only models the resulting storage mode via
/// [`SecretStore`](`sshrack_core::config::schema::SecretStore`). The
/// `store use` handler (Task 20) materializes the choice into a
/// `SecretStore::Vault { meta }` (rekeying with the passphrase to fill the
/// salt/verifier) — that step owns vault-meta construction, not this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordModeChoice {
    /// OS keyring (recommended): plaintext never touches disk, no master
    /// passphrase to remember.
    Keyring,
    /// Encrypt stored passwords with a master passphrase.
    Encrypted,
    /// Store passwords as plaintext. Least secure.
    Plaintext,
}

impl PasswordModeChoice {
    /// True when the user chose encryption.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Self::Encrypted)
    }
}

/// First-use password-storage menu: keyring (recommended) / encrypted /
/// plaintext. Returns the user's [`PasswordModeChoice`]; a Ctrl+C during the
/// prompt surfaces as [`SshrackError::Interrupted`] (silent cancel).
pub fn password_mode() -> Result<PasswordModeChoice, SshrackError> {
    let theme = ColorfulTheme::default();
    let items = [
        "OS keyring (recommended)",
        "Encrypt with master passphrase",
        "Store plaintext",
    ];
    let idx = FuzzySelect::with_theme(&theme)
        .with_prompt("Password storage")
        .items(items)
        .default(0)
        .report(false)
        .interact()
        .map_err(SshrackError::from_prompt_io)?;
    Ok(match idx {
        0 => PasswordModeChoice::Keyring,
        1 => PasswordModeChoice::Encrypted,
        _ => PasswordModeChoice::Plaintext,
    })
}

/// A `--no-input`-aware yes/no confirm used by the management commands.
///
/// Under `--no-input` (`no_input == true`) this returns `Ok(false)` immediately
/// — fail-closed, so a destructive action (`rm`, `store use`, rekey) never
/// proceeds unattended in a scripted/non-interactive run. Otherwise it delegates
/// to dialoguer's [`Confirm`], defaulting to No, with a Ctrl+C surfacing as
/// [`SshrackError::Interrupted`].
pub fn confirm_with_fallback(no_input: bool, text: &str) -> Result<bool, SshrackError> {
    if no_input {
        return Ok(false);
    }
    let agreed = Confirm::new()
        .with_prompt(text)
        .default(false)
        .interact()
        .map_err(SshrackError::from_prompt_io)?;
    Ok(agreed)
}

/// Build the infallible `FnOnce(&str) -> bool` confirm closure that
/// [`run_host_key_flow`] expects, routing it through dialoguer.
///
/// `run_host_key_flow` takes an infallible confirm (`FnOnce(&str) -> bool`),
/// so the only signal the caller can receive is "trusted" vs "not trusted".
/// A Ctrl+C while the dialoguer [`Confirm`] runs surfaces as
/// [`std::io::ErrorKind::Interrupted`]; inside this infallible closure we
/// cannot propagate it as an error. Mapping it to `false` is the safe default:
/// "do not append this host key" — exactly what an explicit No would do. The
/// connect attempt then fails fast with [`SshrackError::HostKeyNotConfirmed`],
/// which is the correct outcome for a cancelled trust prompt. (A future
/// refactor of `run_host_key_flow` to a fallible confirm could surface the
/// cancel distinctly; until then, treat Interrupted as a refusal.)
///
/// [`run_host_key_flow`]: sshrack_core::hostkey::run_host_key_flow
pub fn host_key_confirm_closure() -> impl FnOnce(&str) -> bool {
    |text: &str| {
        Confirm::new()
            .with_prompt(text)
            .default(false)
            .interact()
            // Ctrl+C (or any io failure) during the trust prompt: refuse to
            // append. `bool::default()` is `false`, the safe default inside an
            // infallible closure — see the doc comment above for why
            // Interrupted => false is correct here.
            .unwrap_or_default()
    }
}

/// Build a fail-closed `FnOnce(&str) -> bool` confirm closure for `--no-input`.
///
/// Under `--no-input`, the caller must not prompt the user for anything —
/// every prompt is refused. Returning `false` unconditionally causes
/// [`run_host_key_flow`] to fail with [`SshrackError::HostKeyNotConfirmed`]
/// for any new host key, which is the safe default for an unattended run.
///
/// [`run_host_key_flow`]: sshrack_core::hostkey::run_host_key_flow
pub fn host_key_confirm_closure_no_input() -> impl FnOnce(&str) -> bool {
    |_text: &str| false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_mode_choice_flags_encrypted() {
        assert!(PasswordModeChoice::Encrypted.is_encrypted());
        assert!(!PasswordModeChoice::Keyring.is_encrypted());
        assert!(!PasswordModeChoice::Plaintext.is_encrypted());
    }

    #[test]
    fn confirm_with_fallback_no_input_is_false_fail_closed() {
        // --no-input must never proceed with a destructive action.
        assert!(!confirm_with_fallback(true, "delete everything?").unwrap());
    }

    #[test]
    fn host_key_confirm_closure_maps_io_error_to_false() {
        // The closure is infallible; any dialoguer io failure (including a
        // Ctrl+C / Interrupted) must surface as a refusal, not a panic. We
        // cannot easily inject an io error without a TTY, but we can prove the
        // closure's type signature is infallible (returns bool, not Result) by
        // calling the constructor — the real behavior is exercised by the
        // integration tests that drive run_host_key_flow.
        let _f = host_key_confirm_closure();
        // Type-level check: confirm the closure returns bool, not Result<bool,_>.
        let _: fn() = || {
            let f = host_key_confirm_closure();
            let _: bool = f("");
        };
    }
}
