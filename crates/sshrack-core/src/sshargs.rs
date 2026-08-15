//! Save-time validation and connect-time tokenization of a host's raw
//! `ssh_args` (shell-split ssh option flags). Pure; no I/O.

use crate::error::SshrackError;

/// Trim a raw `ssh_args` value and map empty/whitespace-only input to `None`
/// so a clean config never serializes an empty field.
pub fn normalize(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Validate a raw `ssh_args` value at save time. Rejects control characters
/// (they could smuggle argv/config structure), unterminated quotes, and empty
/// tokens. Accepts any token shape — `-o "SetEnv FOO=1"` legitimately splits
/// into a non-dash token.
pub fn validate(raw: &str) -> Result<(), SshrackError> {
    if raw.chars().any(char::is_control) {
        return Err(SshrackError::InvalidSshArgs {
            reason: "control characters are not allowed".into(),
        });
    }
    let Some(tokens) = shlex::split(raw) else {
        return Err(SshrackError::InvalidSshArgs {
            reason: "unterminated quote".into(),
        });
    };
    if tokens.iter().any(String::is_empty) {
        return Err(SshrackError::InvalidSshArgs {
            reason: "empty argument".into(),
        });
    }
    Ok(())
}

/// Shell-split for connect time. Save-time validation guarantees validity for
/// hosts saved through sshrack; a hand-edited config can still carry invalid
/// input, which is dropped with a warning (never hang, never crash).
pub fn tokens(raw: &str) -> Vec<String> {
    let split = shlex::split(raw).unwrap_or_default();
    if split.is_empty() && !raw.trim().is_empty() {
        tracing::warn!("dropping invalid ssh_args: {raw:?}");
    }
    split
}

/// The scp-safe subset of [`tokens`]: scp accepts ssh's `-o` options but not
/// its flags (`-X`, `-L`, …), so only `-o X` pairs and combined `-oX=Y`
/// tokens are forwarded. A dangling `-o` (no value) is dropped.
pub fn o_option_tokens(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tokens = tokens(raw);
    let mut iter = tokens.into_iter();
    while let Some(tok) = iter.next() {
        if tok == "-o" {
            if let Some(v) = iter.next() {
                out.push(tok);
                out.push(v);
            }
        } else if tok.starts_with("-o") && tok.len() > 2 {
            out.push(tok);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_flags_and_quoted_values() {
        assert!(validate("-o ServerAliveInterval=30").is_ok());
        assert!(validate("-o \"SetEnv FOO=1\" -X -4").is_ok());
        assert!(validate("").is_ok());
    }

    #[test]
    fn validate_rejects_control_characters() {
        assert!(validate("-o X=1\nProxyCommand=evil").is_err());
        assert!(validate("-o X=1\t").is_err());
    }

    #[test]
    fn validate_rejects_unterminated_quote() {
        assert!(validate("-o \"unterminated").is_err());
    }

    #[test]
    fn validate_rejects_empty_token() {
        assert!(validate("-o ''").is_err());
    }

    #[test]
    fn tokens_split_on_shell_rules() {
        assert_eq!(
            tokens("-o \"SetEnv FOO=1\" -X"),
            vec![
                "-o".to_string(),
                "SetEnv FOO=1".to_string(),
                "-X".to_string()
            ]
        );
    }

    #[test]
    fn tokens_lossy_on_invalid_input() {
        // A hand-edited config can carry invalid args past save-time
        // validation; connect-time tokenization degrades to empty (warned).
        assert!(tokens("-o \"unterminated").is_empty());
    }

    #[test]
    fn normalize_trims_and_drops_empty() {
        assert_eq!(normalize(Some("  -o X=1 ")), Some("-o X=1".to_string()));
        assert_eq!(normalize(Some("   ")), None);
        assert_eq!(normalize(None), None);
    }

    #[test]
    fn o_option_tokens_keeps_only_dash_o_pairs() {
        assert_eq!(
            o_option_tokens("-o ServerAliveInterval=30 -X -oCompression=yes -L 8080:x:80"),
            vec![
                "-o".to_string(),
                "ServerAliveInterval=30".to_string(),
                "-oCompression=yes".to_string(),
            ]
        );
    }

    #[test]
    fn o_option_tokens_dangling_dash_o_is_dropped() {
        // `-o` with no following token cannot be forwarded safely.
        assert!(o_option_tokens("-X -o").is_empty());
    }
}
