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

use std::path::{Path, PathBuf};

use ulid::Ulid;
use zeroize::Zeroizing;

use sshrack_core::config::path as config_path;
use sshrack_core::config::schema::{Host, SshrackConfig};
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
