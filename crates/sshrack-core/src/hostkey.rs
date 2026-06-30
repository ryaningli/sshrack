//! Host-key pre-flight: confirm a new host's key before launching ssh/scp.
//!
//! Behaviour mirrors `ssh`'s defaults (`StrictHostKeyChecking=ask`):
//!   - known key        -> proceed (a changed key is rejected by ssh itself)
//!   - new key + tty    -> prompt with the key fingerprint; on accept, append
//!   - new key + no tty -> reject (no reliable way to confirm a human is present)
//!
//! This runs entirely before `connect::launch`; it never touches the ssh data
//! stream and never touches passwords.
//!
//! The single orchestration entry is [`run_host_key_flow`]. Its only
//! side-effect seam beyond the `ssh-keyscan`/`ssh-keygen` spawns is the
//! injected `confirm` callback: the CLI passes a closure over `--accept-new`,
//! the TUI passes a crossterm-based confirm, tests pass a closure. Core never
//! depends on a UI crate.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::SshrackError;

/// SSH public-key algorithm sshrack knows how to display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgo {
    Ed25519,
    Ecdsa,
    Rsa,
    /// Anything else ssh-keygen reported (e.g. DSA, security-key types).
    Other,
}

impl KeyAlgo {
    /// Uppercase label as emitted by `ssh-keygen -lf`, for display.
    pub fn label(self) -> &'static str {
        match self {
            KeyAlgo::Ed25519 => "ED25519",
            KeyAlgo::Ecdsa => "ECDSA",
            KeyAlgo::Rsa => "RSA",
            KeyAlgo::Other => "OTHER",
        }
    }

    /// Parse the parenthesized algorithm token from `ssh-keygen -lf` (e.g.
    /// `ED25519` -> `Ed25519`). Case-insensitive; unknown -> `Other`.
    fn from_label(raw: &str) -> KeyAlgo {
        match raw.trim().to_ascii_lowercase().as_str() {
            "ed25519" => KeyAlgo::Ed25519,
            "ecdsa" => KeyAlgo::Ecdsa,
            "rsa" => KeyAlgo::Rsa,
            _ => KeyAlgo::Other,
        }
    }
}

/// One key fingerprint as reported by `ssh-keygen -lf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// Key length in bits (e.g. 256, 3072).
    pub bits: u32,
    /// Algorithm of this key.
    pub algo: KeyAlgo,
    /// Full fingerprint including the `SHA256:` prefix.
    pub sha256: String,
}

/// Parse `ssh-keygen -lf -` output (one fingerprint per line) into structured
/// fingerprints. Blank lines, comments, and malformed lines are skipped.
///
/// Expected line shape (OpenSSH 8.x+):
/// `256 SHA256:abc... 192.168.1.10 (ED25519)`
pub fn parse_fingerprints(output: &str) -> Vec<Fingerprint> {
    output.lines().filter_map(parse_fingerprint_line).collect()
}

fn parse_fingerprint_line(line: &str) -> Option<Fingerprint> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let bits: u32 = parts.next()?.parse().ok()?;
    let sha256 = parts.next()?;
    if !sha256.starts_with("SHA256:") {
        return None;
    }
    let _host = parts.next()?;
    let algo_token = parts.next()?;
    let label = algo_token.trim_start_matches('(').trim_end_matches(')');
    Some(Fingerprint {
        bits,
        algo: KeyAlgo::from_label(label),
        sha256: sha256.to_string(),
    })
}

/// Choose the single fingerprint to show on first connect. Mirrors ssh's
/// single-key prompt: prefer ed25519, then ecdsa, then rsa, then whatever is
/// left. Returns `None` only when there are no fingerprints at all.
pub fn pick_primary(fps: &[Fingerprint]) -> Option<&Fingerprint> {
    for algo in [KeyAlgo::Ed25519, KeyAlgo::Ecdsa, KeyAlgo::Rsa] {
        if let Some(fp) = fps.iter().find(|f| f.algo == algo) {
            return Some(fp);
        }
    }
    fps.first()
}

/// What `run_host_key_flow` should do for a host, given whether its key is
/// already trusted and whether a human can answer a prompt right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyAction {
    /// Key already trusted — launch ssh directly.
    Launch,
    /// New key, and a tty is available — scan + prompt.
    Prompt,
    /// New key but no tty — cannot confirm; reject.
    Reject,
}

/// Decide the action from the two facts. Pure, so the tty/known checks stay
/// out of the orchestration path and the matrix is unit-testable.
pub fn classify(is_known: bool, has_tty: bool) -> HostKeyAction {
    match (is_known, has_tty) {
        (true, _) => HostKeyAction::Launch,
        (false, true) => HostKeyAction::Prompt,
        (false, false) => HostKeyAction::Reject,
    }
}

/// The confirmation prompt shown for a new host. Mirrors ssh's first-connect
/// message (including the `is:` colon before the fingerprint).
pub fn confirm_text(host: &str, fp: &Fingerprint) -> String {
    format!(
        "The authenticity of host '{host}' can't be established.\n\
         {algo} key fingerprint is: {sha256}.\n\
         Are you sure you want to continue connecting?",
        algo = fp.algo.label(),
        sha256 = fp.sha256,
    )
}

/// The lookup key ssh/ssh-keygen use for a host at `port` in known_hosts.
/// Standard port 22 is stored bare; any other port is `[host]:port`.
pub fn host_query(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Default known_hosts path: `$HOME/.ssh/known_hosts`. `None` if the home
/// directory cannot be determined.
pub fn known_hosts_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|bd| bd.home_dir().join(".ssh").join("known_hosts"))
}

/// Whether `host` (any key type) already appears in `known_hosts`, using
/// `ssh-keygen -F` exactly as ssh's own lookup does. A missing file means
/// nothing is trusted yet (returns `false`, not an error).
pub fn is_known(host: &str, port: u16, known_hosts: &Path) -> Result<bool, SshrackError> {
    if !known_hosts.exists() {
        return Ok(false);
    }
    let query = host_query(host, port);
    let status = Command::new("ssh-keygen")
        .args(["-F", &query, "-f"])
        .arg(known_hosts)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(SshrackError::Io)?;
    Ok(status.success())
}

/// Scan the host's keys and return their fingerprints. Runs
/// `ssh-keyscan -p <port> <host>` and pipes it through `ssh-keygen -lf -`.
pub fn scan_fingerprints(host: &str, port: u16) -> Result<Vec<Fingerprint>, SshrackError> {
    use std::io::Write;

    let keyscan = Command::new("ssh-keyscan")
        .args(["-T", "5", "-p", &port.to_string()])
        .arg(host)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(SshrackError::Io)?;
    if !keyscan.status.success() {
        return Err(SshrackError::HostKeyScanFailed {
            host: host.to_string(),
        });
    }
    if keyscan.stdout.is_empty() {
        return Err(SshrackError::HostKeyScanEmpty {
            host: host.to_string(),
        });
    }

    let mut keygen = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(SshrackError::Io)?;
    if let Some(stdin) = keygen.stdin.as_mut() {
        stdin.write_all(&keyscan.stdout).map_err(SshrackError::Io)?;
    }
    let out = keygen.wait_with_output().map_err(SshrackError::Io)?;
    if !out.status.success() {
        return Err(SshrackError::HostKeyScanFailed {
            host: host.to_string(),
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_fingerprints(&text))
}

/// Drop ssh-keyscan's banner comment lines (`# host:port SSH-2.0-...`) and
/// blank lines, returning only the key entries joined by newlines (no trailing
/// newline). Pure, so the exact filtering is unit-testable; used by
/// `append_to_known_hosts` to keep `known_hosts` free of ssh-keyscan's chatter.
pub fn strip_comments(raw: &str) -> String {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Append the host's keys, hashed, to `known_hosts`. Uses `ssh-keyscan -H` so
/// the stored entries match ssh's `HashKnownKeys=yes` default, and drops
/// ssh-keyscan's banner comment lines so the file stays clean. Creates the
/// parent `~/.ssh` directory if needed.
pub fn append_to_known_hosts(
    host: &str,
    port: u16,
    known_hosts: &Path,
) -> Result<(), SshrackError> {
    use std::io::Write;

    if let Some(parent) = known_hosts.parent() {
        std::fs::create_dir_all(parent).map_err(SshrackError::Io)?;
    }
    let scan = Command::new("ssh-keyscan")
        .args(["-T", "5", "-H", "-p", &port.to_string()])
        .arg(host)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(SshrackError::Io)?;
    if !scan.status.success() {
        return Err(SshrackError::HostKeyScanFailed {
            host: host.to_string(),
        });
    }
    let clean = strip_comments(&String::from_utf8_lossy(&scan.stdout));
    if clean.is_empty() {
        return Err(SshrackError::HostKeyScanEmpty {
            host: host.to_string(),
        });
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(known_hosts)
        .map_err(SshrackError::Io)?;
    file.write_all(clean.as_bytes()).map_err(SshrackError::Io)?;
    file.write_all(b"\n").map_err(SshrackError::Io)?;
    Ok(())
}

/// Pre-flight host-key check. Call before `connect::launch`.
///
/// This is the single orchestration entry for the host-key flow. The only
/// side-effect seam beyond the `ssh-keyscan`/`ssh-keygen` spawns is the
/// injected `confirm` callback — core never calls a UI crate directly. The
/// caller decides how the "trust this new fingerprint?" question is answered
/// (CLI: a closure over `--accept-new`; TUI: a crossterm-based confirm; tests: a closure).
///
/// - known key            -> `Ok(())` (a changed key is detected and rejected
///   by ssh itself at connect time; `ssh-keygen -F` only checks for presence,
///   so a changed key still looks "known" here).
/// - new key + tty        -> scan, ask `confirm(&text)`, append on accept.
/// - new key + no tty     -> `Err(HostKeyNotConfirmed)` (no human to confirm).
/// - `confirm` returns
///   `false`              -> `Err(HostKeyNotConfirmed)` — the caller refused.
pub fn run_host_key_flow(
    host: &str,
    port: u16,
    confirm: impl FnOnce(&str) -> bool,
) -> Result<(), SshrackError> {
    use std::io::IsTerminal;

    let known_hosts = known_hosts_path().ok_or(SshrackError::NoKnownHostsPath)?;
    let known = is_known(host, port, &known_hosts)?;
    let has_tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();

    match classify(known, has_tty) {
        HostKeyAction::Launch => Ok(()),
        HostKeyAction::Reject => Err(SshrackError::HostKeyNotConfirmed {
            host: host.to_string(),
        }),
        HostKeyAction::Prompt => {
            let fps = scan_fingerprints(host, port)?;
            let primary = pick_primary(&fps).ok_or(SshrackError::HostKeyScanEmpty {
                host: host.to_string(),
            })?;
            let text = confirm_text(host, primary);
            if confirm(&text) {
                append_to_known_hosts(host, port, &known_hosts)?;
                Ok(())
            } else {
                Err(SshrackError::HostKeyNotConfirmed {
                    host: host.to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Recorded real `ssh-keygen -lf -` output for 192.168.66.173 (ed25519,
    // ecdsa, rsa). Using real bytes keeps the parser honest across algorithm
    // ordering and bit widths.
    const REAL_KEYGEN_LF: &str = "\
256 SHA256:sbuplVt8gXPKlk/acf+2GHKMDt/h9BX2onTVWlLuk4s 192.168.66.173 (ECDSA)
3072 SHA256:houatAZjQEpvqJpWpfrvW1wyPfcAoe03m6RiJCdc1qU 192.168.66.173 (RSA)
256 SHA256:y3UJmXd6a3X2SAJkDNBVeX7n4fdhuObdmvJ/wKrBY/s 192.168.66.173 (ED25519)
";

    #[test]
    fn parses_all_three_key_types() {
        let fps = parse_fingerprints(REAL_KEYGEN_LF);
        assert_eq!(fps.len(), 3);
        let ecdsa = fps.iter().find(|f| f.algo == KeyAlgo::Ecdsa).unwrap();
        assert_eq!(ecdsa.bits, 256);
        assert_eq!(
            ecdsa.sha256,
            "SHA256:sbuplVt8gXPKlk/acf+2GHKMDt/h9BX2onTVWlLuk4s"
        );
        let rsa = fps.iter().find(|f| f.algo == KeyAlgo::Rsa).unwrap();
        assert_eq!(rsa.bits, 3072);
        let ed = fps.iter().find(|f| f.algo == KeyAlgo::Ed25519).unwrap();
        assert_eq!(
            ed.sha256,
            "SHA256:y3UJmXd6a3X2SAJkDNBVeX7n4fdhuObdmvJ/wKrBY/s"
        );
    }

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let input = "\
# 192.168.66.173:22 SSH-2.0-OpenSSH_8.9p1

256 SHA256:y3UJmXd6a3X2SAJkDNBVeX7n4fdhuObdmvJ/wKrBY/s 192.168.66.173 (ED25519)
garbage line with no fingerprint
";
        let fps = parse_fingerprints(input);
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].algo, KeyAlgo::Ed25519);
    }

    #[test]
    fn parse_ignores_lines_without_sha256_token() {
        // A line that parses to two tokens but the second is not SHA256:...
        // must be skipped, not panic.
        let fps = parse_fingerprints("256 notafingerprint host (RSA)\n");
        assert!(fps.is_empty());
    }

    #[test]
    fn unknown_algo_maps_to_other() {
        let fps = parse_fingerprints("256 SHA256:abc host (DSA)\n");
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].algo, KeyAlgo::Other);
    }

    #[test]
    fn pick_primary_prefers_ed25519_then_ecdsa_then_rsa() {
        let fps = parse_fingerprints(REAL_KEYGEN_LF);
        let primary = pick_primary(&fps).unwrap();
        assert_eq!(primary.algo, KeyAlgo::Ed25519);

        // ed25519 absent -> ecdsa wins.
        let no_ed = fps
            .iter()
            .filter(|f| f.algo != KeyAlgo::Ed25519)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(pick_primary(&no_ed).unwrap().algo, KeyAlgo::Ecdsa);

        // only rsa -> rsa.
        let only_rsa = fps
            .iter()
            .filter(|f| f.algo == KeyAlgo::Rsa)
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(pick_primary(&only_rsa).unwrap().algo, KeyAlgo::Rsa);
    }

    #[test]
    fn pick_primary_empty_returns_none() {
        assert!(pick_primary(&[]).is_none());
    }

    #[test]
    fn classify_known_launches() {
        assert_eq!(classify(true, true), HostKeyAction::Launch);
        assert_eq!(classify(true, false), HostKeyAction::Launch);
    }

    #[test]
    fn classify_unknown_with_tty_prompts() {
        assert_eq!(classify(false, true), HostKeyAction::Prompt);
    }

    #[test]
    fn classify_unknown_without_tty_rejects() {
        assert_eq!(classify(false, false), HostKeyAction::Reject);
    }

    #[test]
    fn confirm_text_matches_ssh_shape() {
        let fp = Fingerprint {
            bits: 256,
            algo: KeyAlgo::Ed25519,
            sha256: "SHA256:abc".into(),
        };
        let text = confirm_text("192.168.66.173", &fp);
        assert!(text.contains("The authenticity of host '192.168.66.173' can't be established."));
        assert!(text.contains("ED25519 key fingerprint is: SHA256:abc."));
        assert!(text.contains("Are you sure you want to continue connecting?"));
    }

    #[test]
    fn host_query_plain_for_port_22() {
        assert_eq!(host_query("10.0.0.5", 22), "10.0.0.5");
    }

    #[test]
    fn host_query_bracketed_for_nonstandard_port() {
        assert_eq!(host_query("10.0.0.5", 2222), "[10.0.0.5]:2222");
    }

    #[test]
    fn strip_comments_drops_banner_and_blank_keeps_keys() {
        let raw = "\
# 192.168.66.173:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15
|1|abc=|def= ecdsa-sha2-nistp256 AAAA...
# 192.168.66.173:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15
|1|ghi=|jkl= ssh-ed25519 AAAA...

# 192.168.66.173:22 SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15
";
        assert_eq!(
            strip_comments(raw),
            "|1|abc=|def= ecdsa-sha2-nistp256 AAAA...\n|1|ghi=|jkl= ssh-ed25519 AAAA..."
        );
    }

    #[test]
    fn strip_comments_empty_when_only_comments_and_blanks() {
        assert_eq!(strip_comments("# banner\n\n# another\n"), "");
    }
}
