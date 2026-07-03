//! Shared helpers for the `host`/`cred` command handlers.
//!
//! These wrap the cross-cutting concerns every CRUD handler repeats: loading
//! and saving the config, resolving a `--credential <name>` to a stable
//! [`Ulid`] before a pure core call, and ranking hosts by frecency for
//! `host ls --sort frecency`.
//!
//! The only passphrase source in this layer is [`EnvPassphrase`] (the
//! `SSHRACK_PASSPHRASE` env var). There are no TTY prompts anywhere here.
//!
//! Nothing here prints, logs, or returns a password in an error message.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ulid::Ulid;
use zeroize::Zeroizing;

use sshrack_core::config::path as config_path;
use sshrack_core::config::schema::{Host, InlineKey, Secret, SshrackConfig};
use sshrack_core::config::store;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::secret::PassphraseProvider;
use sshrack_core::secret::vault;

use crate::cli::args::SortMode;
use crate::shared::exit_code;

/// Load the config at `override_path` (or the XDG default). A missing file is
/// an empty config. Returns the resolved path and the config, or an `Err`
/// carrying the printed-message + exit-code pair so the caller can return it
/// directly.
pub fn load_config(
    override_path: Option<&Path>,
) -> Result<(PathBuf, SshrackConfig), (String, i32)> {
    let config_path = config_path::resolve(override_path);
    let cfg = config_path
        .as_ref()
        .map(|p| store::load(p))
        .transpose()
        .map(|c| c.unwrap_or_default())
        .map_err(|e| (format!("sshrack: config error: {e}"), exit_code::USAGE))?;
    // resolve never returns None in practice (home dir is found), but fall
    // back to a sentinel path so the save side has somewhere to write.
    let path = config_path.unwrap_or_else(|| PathBuf::from("config.toml"));
    Ok((path, cfg))
}

/// Atomically persist `cfg` to `path`. Returns an `Err` (message + exit code)
/// on failure so callers can surface it uniformly.
pub fn save_config(path: &Path, cfg: &SshrackConfig) -> Result<(), (String, i32)> {
    store::save(path, cfg).map_err(|e| {
        (
            format!("sshrack: failed to save config: {e}"),
            exit_code::USAGE,
        )
    })
}

/// Resolve `--credential <name>` to the credential's stable [`Ulid`], or
/// `None` when no `--credential` was given. Failures (name unknown) carry the
/// printed message + exit code so the caller returns them directly.
pub fn resolve_credential_name(
    cfg: &SshrackConfig,
    credential: Option<&str>,
) -> Result<Option<Ulid>, (String, i32)> {
    match credential {
        None => Ok(None),
        Some(name) => match cfg.find_credential_by_name(name) {
            Some(c) => Ok(Some(c.id)),
            None => {
                let err = credential::credential_not_found(cfg, name);
                Err((format!("sshrack: {err}"), exit_code::NOT_FOUND))
            }
        },
    }
}

/// Unlock the vault when vault mode is active, returning the master key (or
/// `None` when not in vault mode). Used by `host/cred show --reveal`. The
/// passphrase comes only from `SSHRACK_PASSPHRASE` (via [`EnvPassphrase`]);
/// an unset env var surfaces as a `STORE` error.
pub fn unlock_vault_key(cfg: &SshrackConfig) -> Result<Option<vault::VaultKey>, (String, i32)> {
    let provider = EnvPassphrase;
    let env_pw = vault::passphrase_from_env();
    vault::ensure_unlocked_vault_key(cfg, env_pw.as_ref(), &provider).map_err(|e| {
        (
            format!("sshrack: vault unlock failed: {e}"),
            exit_code::STORE,
        )
    })
}

/// The only passphrase source in the non-interactive CLI: the
/// `SSHRACK_PASSPHRASE` env var. Errors if unset (mapped to
/// [`SshrackError::Interrupted`] so the vault unlock path produces a clean
/// "vault unlock failed" message rather than a TTY hang).
pub struct EnvPassphrase;

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

// ===========================================================================
// field selection + table rendering (shared by host ls and cred ls)
// ===========================================================================

/// Parse a comma-separated `--fields` spec against `allowed`. De-dupes but
/// preserves order. Empty/whitespace-only falls back to `allowed`.
pub(crate) fn selected_fields(
    spec: Option<&str>,
    allowed: &[&'static str],
) -> Result<Vec<&'static str>, (String, i32)> {
    let names: Vec<&'static str> = match spec {
        None => allowed.to_vec(),
        Some(s) => {
            let parsed: Vec<&str> = s
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parsed.is_empty() {
                allowed.to_vec()
            } else {
                for name in &parsed {
                    if !allowed.contains(name) {
                        return Err((
                            format!(
                                "sshrack: unknown field '{name}' — valid fields: {}",
                                allowed.join(", ")
                            ),
                            exit_code::VALIDATION,
                        ));
                    }
                }
                parsed
                    .iter()
                    .map(|s| allowed.iter().copied().find(|a| a == s).unwrap_or(""))
                    .collect()
            }
        }
    };
    Ok(names)
}

/// Print a slice of Serialize rows as a JSON array (single line).
pub(crate) fn print_json_array<T: serde::Serialize>(rows: &[T]) {
    let json = serde_json::to_string(rows).unwrap_or_else(|e| {
        eprintln!("sshrack: json error: {e}");
        String::from("[]")
    });
    println!("{json}");
}

/// Print `msg` to stderr and return `code`. The single point for failure exits.
pub(crate) fn fail(msg: &str, code: i32) -> i32 {
    if !msg.is_empty() {
        eprintln!("{msg}");
    }
    code
}

/// Rank/sort hosts per `--sort`. `None` keeps config order. Loads the frecency
/// table from the data dir for the frecency/recent modes (best-effort: a
/// missing/corrupt file falls back to an empty table).
///
/// Borrows the input slice so the returned `&Host` refs share the caller's
/// lifetime (the underlying `Host` storage), not a function-local one — this is
/// what lets the frecency/recent arms go through the core `rank` / `rank_by_recent`
/// helpers, whose `RankedHost<'a>` borrows the input.
pub fn sort_hosts<'a>(hosts: &'a [&'a Host], sort: Option<SortMode>) -> Vec<&'a Host> {
    let Some(mode) = sort else {
        return hosts.to_vec();
    };
    let data_dir = config_path::default_data_dir();
    let frec = data_dir
        .as_ref()
        .map(|d| frecency::store::load(d).unwrap_or_default())
        .unwrap_or_default();
    match mode {
        SortMode::Frecency => {
            // match-then-score-then-name; an empty query reduces it to
            // score-then-name, which is the documented `--sort frecency` order.
            frecency::rank(hosts, "", &frec)
                .into_iter()
                .map(|r| r.host)
                .collect()
        }
        SortMode::Recent => {
            // Most-recently-used first (strict recency), distinct from the
            // score-based frecency order.
            frecency::rank_by_recent(hosts, &frec)
                .into_iter()
                .map(|r| r.host)
                .collect()
        }
        SortMode::Name => {
            let mut v = hosts.to_vec();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            v
        }
    }
}

// ===========================================================================
// inline identity-key import (--identity-stdin / --identity-file)
// ===========================================================================

/// Read a file's full contents into a plaintext [`Secret`]. Used for
/// `--identity-file` / `--certificate-file`: the path is on argv (not secret),
/// the file contents become the inline secret. The contents are validated as
/// UTF-8 because [`Secret::Plain`] holds a `String` — binary key material is
/// rejected at this boundary.
///
/// Returns `Err(anyhow::Error)`; the caller formats it via `{e:#}` (the anyhow
/// chain) so the user sees both the underlying cause and the offending path.
pub fn read_secret_file(path: &Path) -> Result<Secret> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("identity file {} is not valid UTF-8", path.display()))?;
    Ok(Secret::Plain(text))
}

/// Read all of `reader` into a plaintext [`Secret`]. Used for `--identity-stdin`
/// / `--certificate-stdin`: nothing secret touches argv. Like
/// [`read_secret_file`], the contents must be valid UTF-8.
pub fn read_secret_stdin(reader: &mut dyn Read) -> Result<Secret> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .context("failed to read identity from stdin")?;
    let text = String::from_utf8(bytes).context("stdin identity is not valid UTF-8")?;
    Ok(Secret::Plain(text))
}

/// The inline-key import flags shared by `cred add/edit` and `host add/edit`
/// (Independent branch). All four handlers resolve these the same way, so the
/// resolution lives here as one source of truth — clap already enforces the
/// `--identity` ↔ `--identity-stdin`/`--identity-file` mutual exclusion at parse
/// time, so this helper only needs to distinguish "path" from "inline" branches.
///
/// Returns `Ok(Some(InlineKey))` when an inline source (`--identity-stdin` or
/// `--identity-file`) was given; `Ok(None)` when only `--identity <path>` (or
/// nothing) was given — the caller still owns the path-key path via the existing
/// `--identity` flag. Certificate flags (`--certificate-stdin`/`--certificate-file`)
/// attach to an inline key only; they are silently ignored on the path branch
/// (a path identity auto-loads its `-cert.pub` sibling, per OpenSSH convention).
#[allow(clippy::too_many_arguments)]
pub fn resolve_inline_identity(
    identity_stdin: bool,
    identity_file: Option<&Path>,
    certificate_stdin: bool,
    certificate_file: Option<&Path>,
    stdin: &mut dyn Read,
) -> Result<Option<InlineKey>> {
    let private_sec = if identity_stdin {
        read_secret_stdin(stdin)?
    } else if let Some(p) = identity_file {
        read_secret_file(p)?
    } else {
        // No inline source; the caller's existing --identity <path> handling
        // owns the path-key branch.
        return Ok(None);
    };
    let certificate_sec = if certificate_stdin {
        Some(read_secret_stdin(stdin)?)
    } else if let Some(p) = certificate_file {
        Some(read_secret_file(p)?)
    } else {
        None
    };
    Ok(Some(InlineKey {
        private_key: Some(private_sec),
        certificate: certificate_sec,
        keyring: false,
    }))
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for the inline-key import helpers. The helpers wrap
    //! `std::fs::read` / `std::io::Read::read_to_end` + a UTF-8 decode, returning
    //! `Secret::Plain`; the sealing per store mode happens downstream in the
    //! existing persist path. These tests pin the contract: bytes in, plaintext
    //! `Secret` out, and a clean error on non-UTF-8 input.

    use super::*;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn temp_dir_for_pid() -> PathBuf {
        std::env::temp_dir().join(format!("sshrack-test-{}", std::process::id()))
    }

    #[test]
    fn read_secret_file_returns_plain_secret_of_file_contents() {
        // Round-trip: write → read → Secret::Plain. The path is on argv (not
        // secret); the file's bytes become the inline secret verbatim.
        let dir = temp_dir_for_pid();
        std::fs::create_dir_all(&dir).unwrap();
        let keyfile = dir.join("read_secret_file_plain");
        std::fs::write(&keyfile, "KEY-CONTENTS").unwrap();
        let s = read_secret_file(&keyfile).unwrap();
        assert_eq!(s.as_plain(), Some("KEY-CONTENTS"));
        let _ = std::fs::remove_file(&keyfile);
    }

    #[test]
    fn read_secret_stdin_returns_plain_secret_of_reader_contents() {
        // Drive the stdin helper with a cursor: bytes in → Secret::Plain out.
        let input = "STDIN-KEY-CONTENTS";
        let mut cursor = Cursor::new(input);
        let s = read_secret_stdin(&mut cursor).unwrap();
        assert_eq!(s.as_plain(), Some("STDIN-KEY-CONTENTS"));
    }

    #[test]
    fn read_secret_file_errors_on_non_utf8_bytes() {
        // A binary key file (or any non-UTF-8 input) must error cleanly — the
        // path is named in the error context so the user knows which file.
        let dir = temp_dir_for_pid();
        std::fs::create_dir_all(&dir).unwrap();
        let keyfile = dir.join("read_secret_file_non_utf8");
        std::fs::write(&keyfile, [0xFFu8, 0xFE, 0xFD]).unwrap();
        let err = read_secret_file(&keyfile).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not valid UTF-8"),
            "expected UTF-8 error mentioning the file, got: {msg}"
        );
        assert!(
            msg.contains(keyfile.to_string_lossy().as_ref()),
            "error must name the offending path, got: {msg}"
        );
        let _ = std::fs::remove_file(&keyfile);
    }

    #[test]
    fn read_secret_file_errors_when_file_missing() {
        // A missing file must error cleanly with the path in the message.
        let dir = temp_dir_for_pid();
        let nosuch = dir.join("does-not-exist-read_secret_file");
        let err = read_secret_file(&nosuch).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to read identity file"),
            "expected an io error message, got: {msg}"
        );
    }

    #[test]
    fn resolve_inline_identity_returns_none_when_no_inline_source() {
        // No --identity-stdin / --identity-file: the helper returns None and
        // leaves the path-key branch to the caller.
        let mut cursor = Cursor::new(b"");
        let out = resolve_inline_identity(false, None, false, None, &mut cursor).unwrap();
        assert!(out.is_none(), "no inline source → None");
    }

    #[test]
    fn resolve_inline_identity_reads_private_from_stdin() {
        // --identity-stdin: private key read from stdin, no certificate.
        let mut cursor = Cursor::new("PRIVATE-KEY-TEXT");
        let ik = resolve_inline_identity(true, None, false, None, &mut cursor)
            .unwrap()
            .expect("inline source present");
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("PRIVATE-KEY-TEXT")
        );
        assert!(ik.certificate.is_none());
    }

    #[test]
    fn resolve_inline_identity_stdin_consumes_whole_stream_for_private_key() {
        // --identity-stdin reads the ENTIRE stdin stream into the private key.
        // There is no way to frame two separate reads (private then certificate)
        // off one stdin handle: the second read would hit EOF and yield an empty
        // certificate, silently corrupting the key. That is why clap rejects
        // `--identity-stdin` together with `--certificate-stdin` at parse time
        // (see the args.rs conflict tests) — a certificate via stdin must pair
        // with `--identity-file <path>`, a separate stream. This helper-level
        // test pins the contract that the private-stdin branch consumes stdin
        // in full, so the helper's behavior matches the reason the combo is
        // blocked upstream.
        let mut cursor = Cursor::new("PRIVATE-KEY-TEXT\nCERT-MATERIAL");
        let ik = resolve_inline_identity(true, None, false, None, &mut cursor)
            .unwrap()
            .expect("inline source present");
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("PRIVATE-KEY-TEXT\nCERT-MATERIAL")
        );
        assert!(ik.certificate.is_none());
    }

    #[test]
    fn resolve_inline_identity_reads_private_from_file_cert_from_file() {
        // --identity-file <a> --certificate-file <b>: both read from files, in
        // the order private-then-certificate.
        let dir = temp_dir_for_pid();
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("resolve_inline_priv");
        let cert_path = dir.join("resolve_inline_cert");
        std::fs::write(&priv_path, "FILE-PRIVATE").unwrap();
        std::fs::write(&cert_path, "FILE-CERT").unwrap();
        let mut cursor = Cursor::new(b"");
        let ik = resolve_inline_identity(
            false,
            Some(&priv_path),
            false,
            Some(&cert_path),
            &mut cursor,
        )
        .unwrap()
        .expect("inline source present");
        assert_eq!(
            ik.private_key.as_ref().and_then(Secret::as_plain),
            Some("FILE-PRIVATE")
        );
        assert_eq!(
            ik.certificate.as_ref().and_then(Secret::as_plain),
            Some("FILE-CERT")
        );
        let _ = std::fs::remove_file(&priv_path);
        let _ = std::fs::remove_file(&cert_path);
    }
}
