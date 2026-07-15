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
use sshrack_core::config::schema::{
    CredentialBody, Host, InlineKey, KeySource, Secret, SshrackConfig,
};
use sshrack_core::config::store;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::id::OwnerKind;
use sshrack_core::secret::OsKeyring;
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

/// Seal an inline-key body's freshly collected plaintext secrets (private key,
/// optional certificate) per the active store mode, mirroring the TUI persist
/// path. Vault mode encrypts them under the master passphrase sourced from
/// `SSHRACK_PASSPHRASE` (errors as `STORE` if unset); plaintext mode stores
/// them verbatim; an undecided mode is treated as plaintext by [`vault::seal_body`].
///
/// Bodies without an inline key (path-key, password-only, or secretless) pass
/// through unchanged — only [`KeySource::Inline`] carries plaintext material
/// that needs sealing. `owner_kind` + `owner_id` select the keyring account;
/// they are unused while keyring mode rejects inline keys at validation time,
/// but threaded for symmetry with [`vault::seal_body`].
///
/// Returns the printed-message + exit-code pair on failure so callers can
/// return it directly. Never puts key text in the error message.
pub fn seal_inline_body(
    body: CredentialBody,
    owner_kind: OwnerKind,
    owner_id: &Ulid,
    cfg: &SshrackConfig,
) -> Result<CredentialBody, (String, i32)> {
    // Only inline-key bodies carry plaintext secret material that needs sealing.
    // Path-key / password-only / secretless bodies have nothing to re-host.
    if !matches!(body.key, Some(KeySource::Inline(_))) {
        return Ok(body);
    }
    let vault_key = unlock_vault_key(cfg)?;
    let backend = OsKeyring;
    vault::seal_body(
        body,
        owner_kind,
        owner_id,
        cfg,
        vault_key.as_ref(),
        &backend,
    )
    .map_err(|e| {
        (
            format!("sshrack: failed to seal inline key: {e}"),
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
                // Single pass: validate each name against `allowed`, map it to
                // its canonical `&'static str`, and de-dup preserving the
                // user's order. An unknown name errors and names the field; a
                // known name never yields an empty string (the find is gated by
                // the same `allowed` it reads from, so the `let-else` is the
                // sole exit for unknowns).
                let mut selected: Vec<&'static str> = Vec::with_capacity(parsed.len());
                for name in &parsed {
                    let Some(canonical) = allowed.iter().copied().find(|a| a == name) else {
                        return Err((
                            format!(
                                "sshrack: unknown field '{name}' — valid fields: {}",
                                allowed.join(", ")
                            ),
                            exit_code::VALIDATION,
                        ));
                    };
                    if !selected.contains(&canonical) {
                        selected.push(canonical);
                    }
                }
                selected
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
    // Normalize the trailing newline so a key whose `-----END ...-----` line is
    // not followed by '\n' does not later fail in ssh with "error in libcrypto".
    Ok(Secret::Plain(
        sshrack_core::connect::ensure_trailing_newline(&text),
    ))
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
    Ok(Secret::Plain(
        sshrack_core::connect::ensure_trailing_newline(&text),
    ))
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

    #[test]
    fn read_secret_file_returns_plain_secret_of_file_contents() {
        // Round-trip: write → read → Secret::Plain. The path is on argv (not
        // secret); the file's bytes become the inline secret verbatim. The
        // tempdir is reaped automatically when `dir` drops.
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("read_secret_file_plain");
        std::fs::write(&keyfile, "KEY-CONTENTS").unwrap();
        let s = read_secret_file(&keyfile).unwrap();
        // Ingest normalizes a trailing newline so a hand-edited file without one
        // still yields a Secret whose text ends in '\n'.
        assert_eq!(s.as_plain(), Some("KEY-CONTENTS\n"));
    }

    #[test]
    fn read_secret_stdin_returns_plain_secret_of_reader_contents() {
        // Drive the stdin helper with a cursor: bytes in → Secret::Plain out.
        let input = "STDIN-KEY-CONTENTS";
        let mut cursor = Cursor::new(input);
        let s = read_secret_stdin(&mut cursor).unwrap();
        assert_eq!(s.as_plain(), Some("STDIN-KEY-CONTENTS\n"));
    }

    #[test]
    fn read_secret_file_normalizes_missing_trailing_newline() {
        // A key file without a trailing newline still yields a Secret whose text
        // ends in '\n' — defense at the ingest boundary so what gets sealed (and
        // later materialized) is already correct.
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("read_secret_file_no_newline");
        std::fs::write(&keyfile, "-----END KEY-----").unwrap();
        let s = read_secret_file(&keyfile).unwrap();
        assert_eq!(s.as_plain(), Some("-----END KEY-----\n"));
    }

    #[test]
    fn read_secret_stdin_normalizes_missing_trailing_newline() {
        let mut cursor = Cursor::new("-----END KEY-----");
        let s = read_secret_stdin(&mut cursor).unwrap();
        assert_eq!(s.as_plain(), Some("-----END KEY-----\n"));
    }

    #[test]
    fn read_secret_file_errors_on_non_utf8_bytes() {
        // A binary key file (or any non-UTF-8 input) must error cleanly — the
        // path is named in the error context so the user knows which file.
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("read_secret_file_non_utf8");
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
    }

    #[test]
    fn read_secret_file_errors_when_file_missing() {
        // A missing file must error cleanly with the path in the message. The
        // tempdir exists but the named file inside it does not.
        let dir = tempfile::tempdir().unwrap();
        let nosuch = dir.path().join("does-not-exist-read_secret_file");
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
            Some("PRIVATE-KEY-TEXT\n")
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
            Some("PRIVATE-KEY-TEXT\nCERT-MATERIAL\n")
        );
        assert!(ik.certificate.is_none());
    }

    #[test]
    fn resolve_inline_identity_reads_private_from_file_cert_from_file() {
        // --identity-file <a> --certificate-file <b>: both read from files, in
        // the order private-then-certificate.
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("resolve_inline_priv");
        let cert_path = dir.path().join("resolve_inline_cert");
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
            Some("FILE-PRIVATE\n")
        );
        assert_eq!(
            ik.certificate.as_ref().and_then(Secret::as_plain),
            Some("FILE-CERT\n")
        );
    }

    // ---- seal_inline_body: per-mode sealing at the CLI boundary ----
    //
    // These pin the regression where the CLI add/edit handlers stored inline
    // key text as plaintext even under vault mode: `seal_inline_body` must
    // delegate to `vault::seal_body` so vault mode encrypts, plaintext mode
    // keeps verbatim, and non-inline bodies pass through.

    use sshrack_core::config::schema::{CredentialBody, KeySource};
    use sshrack_core::id::OwnerKind;
    use sshrack_core::secret::OsKeyring;
    use sshrack_core::secret::vault;
    use ulid::Ulid;

    #[test]
    fn seal_inline_body_passes_through_path_key_body_unchanged() {
        // A path-key body has no plaintext secret to re-host; it must return
        // verbatim (same user, same path, no encryption applied).
        let cfg = SshrackConfig::default(); // undecided mode
        let id = Ulid::new();
        let body = CredentialBody::new("u").with_key("/home/u/.ssh/id_ed25519");
        let out = seal_inline_body(body, OwnerKind::Credential, &id, &cfg).unwrap();
        assert_eq!(out.user, "u");
        assert!(matches!(
            out.key,
            Some(KeySource::Path(ref p)) if p == std::path::Path::new("/home/u/.ssh/id_ed25519")
        ));
    }

    #[test]
    fn seal_inline_body_keeps_plaintext_in_undecided_mode() {
        // Undecided store mode (None) is treated as plaintext: a freshly
        // collected inline key stays Secret::Plain — no encryption is applied,
        // and no vault unlock is attempted (so the call succeeds without
        // SSHRACK_PASSPHRASE).
        let cfg = SshrackConfig::default();
        let id = Ulid::new();
        let body =
            CredentialBody::new("u").with_inline_key(Secret::Plain("PRIVATE-TEXT".into()), None);
        let out = seal_inline_body(body, OwnerKind::Host, &id, &cfg).unwrap();
        match out.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(
                    ik.private_key.as_ref().and_then(Secret::as_plain),
                    Some("PRIVATE-TEXT"),
                    "undecided mode must keep plaintext"
                );
            }
            other => panic!("expected Inline key, got {other:?}"),
        }
    }

    #[test]
    fn seal_inline_body_encrypts_inline_key_under_vault_mode() {
        // REGRESSION: the CLI add/edit handlers used to skip sealing, storing
        // inline key text as plaintext even when the user chose vault mode.
        // `seal_inline_body` must encrypt under vault mode (the helper derives
        // the vault key from SSHRACK_PASSPHRASE the same way `cred add` does).
        //
        // Requires SSHRACK_PASSPHRASE to be set (the standard test-run
        // contract); skip gracefully if a developer runs `cargo test` without
        // it, rather than failing opaquely.
        let Some(passphrase) = vault::passphrase_from_env() else {
            eprintln!(
                "[skip] seal_inline_body_encrypts_inline_key_under_vault_mode: \
                 SSHRACK_PASSPHRASE unset"
            );
            return;
        };
        let mut cfg = SshrackConfig::default();
        let backend = OsKeyring;
        // Turn on vault mode with the same passphrase seal_inline_body will
        // read back from the env, so the derived key matches the verifier.
        vault::enable(&mut cfg, passphrase.as_str(), None, &backend).unwrap();
        let id = Ulid::new();
        let body = CredentialBody::new("u").with_inline_key(
            Secret::Plain("SUPER-SECRET-PRIVATE-KEY-BODY".into()),
            Some(Secret::Plain("CERT-BODY".into())),
        );
        let out = seal_inline_body(body, OwnerKind::Credential, &id, &cfg).unwrap();
        let ik = match out.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline key, got {other:?}"),
        };
        // Both secrets must be Encrypted now, and the plaintext must NOT
        // appear anywhere in the body.
        assert!(
            matches!(ik.private_key, Some(Secret::Encrypted(_))),
            "private_key must be Encrypted under vault mode"
        );
        assert!(
            matches!(ik.certificate, Some(Secret::Encrypted(_))),
            "certificate must be Encrypted under vault mode"
        );
        let serialized = format!("{ik:?}");
        assert!(
            !serialized.contains("SUPER-SECRET-PRIVATE-KEY-BODY"),
            "plaintext key leaked through sealing: {serialized}"
        );
        assert!(
            !serialized.contains("CERT-BODY"),
            "plaintext cert leaked through sealing: {serialized}"
        );
    }

    // ---- selected_fields: --fields parsing, ordering, dedup, validation ----
    //
    // Pins the contract documented on `selected_fields`: None/whitespace falls
    // back to `allowed`; a comma list is a user-ordered subset; repeats de-dup
    // (the doc promises "De-dupes but preserves order"); an unknown name is a
    // VALIDATION-exit error that names the offending field.

    use sshrack_core::config::schema::Auth;

    /// The canonical allowed-field table for `host ls`, reused across the
    /// `selected_fields` assertions so they mirror the real caller.
    const HOST_FIELDS: &[&str] = &["name", "host", "user", "port", "auth"];

    #[test]
    fn selected_fields_none_returns_all_allowed() {
        // No --fields → the full allowed set, in allowed's order.
        let out = selected_fields(None, HOST_FIELDS).expect("None is always Ok");
        assert_eq!(out, HOST_FIELDS);
    }

    #[test]
    fn selected_fields_returns_ordered_subset_in_user_order() {
        // The subset follows the user's comma order, not `allowed`'s order.
        let out = selected_fields(Some("host,name"), HOST_FIELDS).expect("valid names");
        assert_eq!(out, vec!["host", "name"]);
    }

    #[test]
    fn selected_fields_dedupes_repeated_names_preserving_order() {
        // REGRESSION: the doc promises "De-dupes but preserves order", but the
        // old implementation mapped `name,name` → `["name","name"]` (no dedup),
        // which would render the column twice in `print_text_table`. A repeated
        // name collapses to a single entry at its first-seen position.
        let out = selected_fields(Some("name,name"), HOST_FIELDS).expect("valid names");
        assert_eq!(out, vec!["name"]);

        // Dedup keeps first-seen order across distinct repeats: `port,name,port`
        // → `["port","name"]`.
        let out = selected_fields(Some("port,name,port"), HOST_FIELDS).expect("valid names");
        assert_eq!(out, vec!["port", "name"]);
    }

    #[test]
    fn selected_fields_whitespace_only_falls_back_to_allowed() {
        // An all-whitespace spec (`"  ,  "`) trims to no names → full allowed.
        let out = selected_fields(Some("  ,  "), HOST_FIELDS).expect("whitespace → allowed");
        assert_eq!(out, HOST_FIELDS);
    }

    #[test]
    fn selected_fields_empty_string_falls_back_to_allowed() {
        // An empty string also trims to no names → full allowed.
        let out = selected_fields(Some(""), HOST_FIELDS).expect("empty → allowed");
        assert_eq!(out, HOST_FIELDS);
    }

    #[test]
    fn selected_fields_unknown_name_is_validation_error_naming_field() {
        // A single unknown field → Err with VALIDATION exit, naming the field.
        let (msg, code) = selected_fields(Some("nope"), HOST_FIELDS).expect_err("unknown field");
        assert!(
            msg.contains("unknown field 'nope'"),
            "error must name the unknown field, got: {msg}"
        );
        assert_eq!(code, exit_code::VALIDATION);
    }

    #[test]
    fn selected_fields_unknown_among_valid_errors_naming_the_unknown() {
        // `nope,host`: the error names `nope` (the unknown one), not `host`.
        let (msg, code) =
            selected_fields(Some("nope,host"), HOST_FIELDS).expect_err("mixed unknown+valid");
        assert!(
            msg.contains("unknown field 'nope'"),
            "error must name the unknown field, got: {msg}"
        );
        assert_eq!(code, exit_code::VALIDATION);
    }

    #[test]
    fn selected_fields_never_yields_empty_column_name() {
        // The old `unwrap_or("")` fallback was flagged as a latent bug: a
        // validated name must always resolve to a real `&'static str` from
        // `allowed`, never "". After the single-pass rewrite the fallback is
        // gone (replaced by a `let-else` error); assert no "" sneaks through
        // for a valid spec.
        let out =
            selected_fields(Some("name,host,user,port,auth"), HOST_FIELDS).expect("all valid");
        assert!(
            !out.iter().any(|f| f.is_empty()),
            "no field should be empty, got: {out:?}"
        );
    }

    // ---- sort_hosts: None preserves order, Name sorts alphabetically ----
    //
    // Frecency/Recent delegate to the core `frecency` table loaded from the
    // machine-local data dir, so their output order is not hermetic; they are
    // intentionally not asserted here (the arms are exercised end-to-end via
    // the binary integration tests instead).

    /// Build a minimal `Host` with the given name for sort assertions.
    fn sort_test_host(name: &str) -> Host {
        Host {
            id: Ulid::new(),
            name: name.into(),
            host: "h".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        }
    }

    #[test]
    fn sort_hosts_none_preserves_input_order() {
        // No --sort → config/input order is returned unchanged (the frecency
        // table is never even loaded on this arm).
        let gamma = sort_test_host("gamma");
        let alpha = sort_test_host("alpha");
        let beta = sort_test_host("beta");
        let refs = vec![&gamma, &alpha, &beta];
        let out = sort_hosts(&refs, None);
        let names: Vec<&str> = out.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["gamma", "alpha", "beta"]);
    }

    #[test]
    fn sort_hosts_name_sorts_alphabetically() {
        // --sort name → alphabetical by name, regardless of input order.
        let gamma = sort_test_host("gamma");
        let alpha = sort_test_host("alpha");
        let beta = sort_test_host("beta");
        let refs = vec![&gamma, &alpha, &beta];
        let out = sort_hosts(&refs, Some(SortMode::Name));
        let names: Vec<&str> = out.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }
}
