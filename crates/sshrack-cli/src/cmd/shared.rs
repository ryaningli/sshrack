//! Shared helpers for the `host`/`cred` command handlers.
//!
//! These wrap the cross-cutting concerns every CRUD handler repeats: loading
//! and saving the config, resolving a `--credential <alias>` to a stable
//! [`Ulid`] before a pure core call, deciding the active password-storage mode
//! (the first-use prompt lives here, not in core), and ranking hosts by
//! frecency for `host ls --sort frecency`.
//!
//! Nothing here prints, logs, or returns a password in an error message.

use std::io::Write;
use std::path::{Path, PathBuf};

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Input, Password};
use ulid::Ulid;
use zeroize::Zeroizing;

use sshrack_core::config::path as config_path;
use sshrack_core::config::schema::{Host, SshrackConfig};
use sshrack_core::config::store;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::frecency;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::PassphraseProvider;
use sshrack_core::secret::vault;

use crate::cli::SortMode;
use crate::exit_code;
use crate::prompt::{self, DialoguerPassphrase};

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

/// Resolve `--credential <alias>` to the credential's stable [`Ulid`], or
/// `None` when no `--credential` was given. Failures (alias unknown) carry the
/// printed message + exit code so the caller returns them directly.
pub fn resolve_credential_alias(
    cfg: &SshrackConfig,
    credential: Option<&str>,
) -> Result<Option<Ulid>, (String, i32)> {
    match credential {
        None => Ok(None),
        Some(alias) => match cfg.find_credential_by_alias(alias) {
            Some(c) => Ok(Some(c.id)),
            None => {
                let err = credential::credential_not_found(cfg, alias);
                Err((format!("sshrack: {err}"), exit_code::NOT_FOUND))
            }
        },
    }
}

/// Decide the password-storage mode when an inline password is being collected.
///
/// If the config already has a mode (`cfg.store.is_some()`), this is a no-op.
/// Otherwise: under `--no-input`, refuse (first-use needs the TTY menu); else
/// run the [`prompt::password_mode`] menu and, for the encrypted choice, call
/// [`vault::enable`] to mint the salt/verifier and migrate any existing
/// passwords. The keyring choice needs no setup here (per-entry staging happens
/// at seal time); the plaintext choice needs none either.
///
/// Returns the updated config (mode now decided) on success, or an `Err`
/// (message + exit code) on refusal / unlock failure.
pub fn ensure_storage_mode_decided(
    cfg: &mut SshrackConfig,
    no_input: bool,
    backend: &OsKeyring,
) -> Result<(), (String, i32)> {
    if cfg.mode_chosen() {
        return Ok(());
    }
    if no_input {
        return Err((
            "sshrack: password storage mode is undecided; run interactively once to choose, or `sshrack store use <mode>`"
                .into(),
            exit_code::STORE,
        ));
    }
    let choice = prompt::password_mode().map_err(prompt_err_to_exit)?;
    if choice.is_encrypted() {
        // Vault mode: derive a fresh key from a confirmed passphrase, write the
        // verifier, and migrate any existing plaintext passwords into vault
        // mode before flipping cfg.store.
        let provider = DialoguerPassphrase;
        let passphrase = provider
            .passphrase_confirm()
            .map_err(|e| (format!("sshrack: {e}"), exit_code::USAGE))?;
        vault::enable(cfg, &passphrase, None, backend).map_err(|e| {
            (
                format!("sshrack: failed to enable vault mode: {e}"),
                exit_code::STORE,
            )
        })?;
    }
    Ok(())
}

/// Map a prompt-side [`SshrackError`] to a printed message + exit code. A
/// Ctrl+C cancel is silent (exits 130) — consistent with the connect path.
fn prompt_err_to_exit(e: SshrackError) -> (String, i32) {
    if matches!(e, SshrackError::Interrupted) {
        return (String::new(), 130);
    }
    (format!("sshrack: {e}"), exit_code::USAGE)
}

/// Unlock the vault when vault mode is active, returning the master key (or
/// `None` when not in vault mode). Used by `host/cred add` (inline password)
/// and `show --reveal` paths. Under `--no-input` the env-passphrase must supply
/// the key; otherwise the TTY provider prompts.
pub fn unlock_vault_key(
    cfg: &SshrackConfig,
    no_input: bool,
) -> Result<Option<vault::VaultKey>, (String, i32)> {
    let provider: &dyn PassphraseProvider = if no_input {
        &NoInputPassphrase
    } else {
        &DialoguerPassphrase
    };
    let env_pw = vault::passphrase_from_env();
    vault::ensure_unlocked_vault_key(cfg, env_pw.as_ref(), provider).map_err(|e| {
        (
            format!("sshrack: vault unlock failed: {e}"),
            exit_code::STORE,
        )
    })
}

/// A [`PassphraseProvider`] that refuses every prompt. Used under `--no-input`
/// so the vault unlock path fails unless `SSHRACK_PASSPHRASE` is set.
pub(crate) struct NoInputPassphrase;

impl PassphraseProvider for NoInputPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        Err(SshrackError::Interrupted)
    }

    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        Err(SshrackError::Interrupted)
    }

    fn confirm(&self, _text: &str) -> Result<bool, SshrackError> {
        Ok(false)
    }
}

// ===========================================================================
// generic prompt helpers (shared by host and cred)
// ===========================================================================

/// Read a free-text string from the TTY.
pub(crate) fn prompt_string(label: &str) -> Result<String, i32> {
    prompt_string_with_default(label, "")
}

/// Read a free-text string, pre-filled with `default` when non-empty.
pub(crate) fn prompt_string_with_default(label: &str, default: &str) -> Result<String, i32> {
    let theme = ColorfulTheme::default();
    let mut input = Input::with_theme(&theme).with_prompt(label);
    if !default.is_empty() {
        input = input.default(default.to_owned());
    }
    match input.interact_text() {
        Ok(s) => Ok(s),
        Err(e) => Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    }
}

/// Read a port number, pre-filled with `default`.
pub(crate) fn prompt_port(default: u16) -> Result<u16, i32> {
    let theme = ColorfulTheme::default();
    match Input::with_theme(&theme)
        .with_prompt("Port")
        .default(default)
        .interact_text()
    {
        Ok(p) => Ok(p),
        Err(e) => Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    }
}

/// Read a password (no echo).
pub(crate) fn prompt_password(label: &str) -> Result<String, i32> {
    let theme = ColorfulTheme::default();
    match Password::with_theme(&theme).with_prompt(label).interact() {
        Ok(s) => Ok(s),
        Err(e) => Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    }
}

/// A `--no-input`-aware confirm: under `--no-input` returns `Ok(false)` (fail-
/// closed — destructive actions do not proceed unattended); otherwise delegates
/// to [`prompt::confirm_with_fallback`]. Used by `host rm` / `cred rm`.
pub(crate) fn confirm_destructive(no_input: bool, text: &str) -> Result<bool, i32> {
    prompt::confirm_with_fallback(no_input, text).map_err(|e| prompt_fail(&e))
}

/// Convert a prompt-side error into a silent exit (130 for cancel) or a printed
/// USAGE exit.
pub(crate) fn prompt_fail(e: &SshrackError) -> i32 {
    if matches!(e, SshrackError::Interrupted) {
        return 130;
    }
    eprintln!("sshrack: {e}");
    exit_code::USAGE
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

/// Render the aligned-text table. `cell_fn` produces the value for one
/// (field, row) pair.
pub(crate) fn print_text_table<T, F>(rows: &[&T], fields: &[&str], cell_fn: F)
where
    F: Fn(&str, &T) -> String,
{
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| fields.iter().map(|f| cell_fn(f, r)).collect())
        .collect();
    let widths: Vec<usize> = (0..fields.len())
        .map(|col| {
            fields[col]
                .len()
                .max(body.iter().map(|r| r[col].len()).max().unwrap_or(0))
        })
        .collect();
    let header_row: Vec<String> = fields.iter().map(|f| f.to_uppercase()).collect();
    let mut out = std::io::stdout().lock();
    let _ = write_row(&mut out, &header_row, &widths);
    for r in &body {
        let _ = write_row(&mut out, r, &widths);
    }
}

fn write_row<W: Write>(w: &mut W, row: &[String], widths: &[usize]) -> std::io::Result<()> {
    for (cell, w_) in row.iter().zip(widths) {
        write!(w, "{:<width$}  ", cell, width = w_)?;
    }
    writeln!(w)
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
            // match-then-score-then-alias; an empty query reduces it to
            // score-then-alias, which is the documented `--sort frecency` order.
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
        SortMode::Alias => {
            let mut v = hosts.to_vec();
            v.sort_by(|a, b| a.alias.cmp(&b.alias));
            v
        }
    }
}
