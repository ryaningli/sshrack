//! TTY interaction for the CLI: host-key yes/no, vault passphrase prompts,
//! the destructive-action confirm, and the two `PassphraseProvider` impls
//! (`TtyPassphrase` for a human at a terminal, `EnvPassphrase` for script/CI
//! reading `SSHRACK_PASSPHRASE`).
//!
//! The CLI defaults to interactive when a TTY is present; escape-hatch flags
//! (`--accept-new`, `--yes`, `SSHRACK_PASSPHRASE`) take precedence and skip
//! the prompt. Without a TTY the prompt helpers return a safe default so the
//! CLI never hangs — callers fall back to the escape hatch or error.

use std::io::{IsTerminal, Write};

use zeroize::Zeroizing;

use sshrack_core::error::SshrackError;
use sshrack_core::secret::PassphraseProvider;
use sshrack_core::secret::vault;

/// Pure kernel of [`has_tty`]: a prompt is reachable only when BOTH stdin and
/// stderr are terminals. Separated so the rule is unit-testable.
fn is_tty_pair(stdin_tty: bool, stderr_tty: bool) -> bool {
    stdin_tty && stderr_tty
}

/// Whether a prompt can reach a human right now (both stdin and stderr are a
/// terminal). All CLI prompts gate on this so scripts/CI never hang.
pub(crate) fn has_tty() -> bool {
    is_tty_pair(
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    )
}

/// Parse a yes/no answer, case-insensitive: `y`/`yes` -> true, anything else
/// (empty, Ctrl-D, `no`) -> false. Default No, mirroring ssh.
pub(crate) fn parse_yes_no(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Print `text` to stderr and read one yes/no line. Returns `false` when there
/// is no tty, on EOF, or on read error — the CLI never hangs.
pub(crate) fn prompt_yes_no(text: &str) -> bool {
    if !has_tty() {
        return false;
    }
    let _ = writeln!(std::io::stderr(), "{text}");
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => false, // EOF (Ctrl-D)
        Ok(_) => parse_yes_no(&line),
        Err(_) => false,
    }
}

/// Destructive-action confirm: print `text` + `(y/N)` and read yes/no. Default
/// No. Used by `host rm` / `cred rm` / `store use plaintext` when `--yes` is
/// absent and a tty is present.
pub(crate) fn tty_confirm(text: &str) -> bool {
    prompt_yes_no(&format!("{text} (y/N) "))
}

/// Read a passphrase with no echo. Empty/failed read yields an empty string
/// (the caller's vault-unlock will then fail the verifier cleanly).
pub(crate) fn prompt_passphrase(prompt: &str) -> Zeroizing<String> {
    Zeroizing::new(rpassword::prompt_password(prompt).unwrap_or_default())
}

/// Read a new passphrase twice, looping until the entries match. Three
/// mismatched attempts surface as `Interrupted`. Used by enable/rekey.
pub(crate) fn prompt_passphrase_confirm(
    new_prompt: &str,
    confirm_prompt: &str,
) -> Result<Zeroizing<String>, SshrackError> {
    for _ in 0..3 {
        let a = rpassword::prompt_password(new_prompt).unwrap_or_default();
        let b = rpassword::prompt_password(confirm_prompt).unwrap_or_default();
        if !a.is_empty() && a == b {
            return Ok(Zeroizing::new(a));
        }
        let _ = writeln!(std::io::stderr(), "passphrases did not match; try again");
    }
    Err(SshrackError::Interrupted)
}

/// `PassphraseProvider` backed by a real terminal. Injected when [`has_tty`].
pub(crate) struct TtyPassphrase;

impl PassphraseProvider for TtyPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        Ok(prompt_passphrase("Enter vault passphrase: "))
    }
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        prompt_passphrase_confirm("Enter new vault passphrase: ", "Confirm passphrase: ")
    }
    fn confirm(&self, text: &str) -> Result<bool, SshrackError> {
        Ok(prompt_yes_no(text))
    }
}

/// `PassphraseProvider` backed solely by `SSHRACK_PASSPHRASE`. Injected when
/// no tty is present (scripts/CI). `passphrase` errors `Interrupted` when the
/// env var is unset; `confirm` is `false` (an env var cannot answer yes/no).
pub(crate) struct EnvPassphrase;

impl PassphraseProvider for EnvPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        vault::passphrase_from_env().ok_or(SshrackError::Interrupted)
    }
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        self.passphrase()
    }
    fn confirm(&self, _text: &str) -> Result<bool, SshrackError> {
        Ok(false)
    }
}

/// Pick the passphrase provider by tty presence: `TtyPassphrase` for a human,
/// `EnvPassphrase` (env-only) for scripts/CI. The env var still wins when set
/// — `ensure_unlocked_vault_key` reads it before consulting the provider.
pub(crate) fn passphrase_provider() -> Box<dyn PassphraseProvider> {
    if has_tty() {
        Box::new(TtyPassphrase)
    } else {
        Box::new(EnvPassphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_tty_pair_requires_both_stdin_and_stderr() {
        assert!(!is_tty_pair(false, false));
        assert!(!is_tty_pair(true, false));
        assert!(!is_tty_pair(false, true));
        assert!(is_tty_pair(true, true));
    }

    #[test]
    fn parse_yes_no_accepts_y_yes_case_insensitive() {
        assert!(parse_yes_no("y"));
        assert!(parse_yes_no("yes"));
        assert!(parse_yes_no("  YES "));
        assert!(parse_yes_no("Y"));
    }

    #[test]
    fn parse_yes_no_rejects_everything_else_default_no() {
        assert!(!parse_yes_no("n"));
        assert!(!parse_yes_no("no"));
        assert!(!parse_yes_no(""));
        assert!(!parse_yes_no("yeah"));
        assert!(!parse_yes_no("true"));
    }
}
