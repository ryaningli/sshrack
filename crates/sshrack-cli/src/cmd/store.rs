//! `sshrack store …` handler: password storage-mode management.
//!
//! Sub-actions: [`status`](Self::status), [`use`](Self::use_mode),
//! [`rekey`](Self::rekey), [`lock`](Self::lock), [`unlock`](Self::unlock),
//! [`config`](Self::config) (get/set the non-secret vault runtime fields).
//!
//! ## Mode switch (`store use`)
//!
//! Switching modes is a one-pass re-host of every stored password via
//! [`vault::transform::migrate`] (or [`vault::enable`] for the vault target,
//! which itself migrates). Three rules drive the per-target arms:
//!
//! - **target = keyring**: probe [`OsKeyring::available`] first — if the daemon
//!   is unreachable, error `STORE` and do NOT migrate (a migration that drops
//!   plaintext on the floor because the keyring is gone would lose passwords).
//! - **target = vault**: collect a confirmed passphrase (under `--no-input` the
//!   passphrase must come from `SSHRACK_PASSPHRASE` env, else error); then
//!   [`vault::enable`] derives a fresh key, writes the verifier, and migrates
//!   every existing password into vault mode before flipping `cfg.store`.
//! - **target = plaintext**: a security downgrade — confirm unless `--yes`;
//!   under `--no-input` require an explicit `--yes` or error (a destructive
//!   switch never proceeds unattended). When the source is vault, unlock first
//!   (the source key is needed to decrypt every body before re-sealing as
//!   plaintext).
//!
//! Leaving keyring mode also requires `available()` (the keyring entries must be
//! readable to migrate them off the keyring).
//!
//! ## Non-transactional save
//!
//! `migrate`/`enable` mutate in-memory bodies (and, when leaving keyring mode,
//! delete OS-keyring entries); `store::save` is a separate atomic step
//! afterward. The on-disk config is unchanged until save succeeds, so a failure
//! between migrate and save leaves the source config intact on disk. Within
//! migrate, a re-seal failure cannot lose a password — the old keyring entry is
//! deleted only after the body is re-sealed.

use sshrack_core::config::schema::{SecretStore, SshrackConfig, VaultMeta};
use sshrack_core::error::SshrackError;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::PassphraseProvider;
use sshrack_core::secret::SecretBackend;
use sshrack_core::secret::vault;

use crate::cli::{Cli, OutputFormat, StoreAction, StoreMode};
use crate::exit_code;
use crate::format as fmt;
use crate::prompt::DialoguerPassphrase;

use super::shared::{
    NoInputPassphrase, confirm_destructive, fail, load_config, save_config, unlock_vault_key,
};

/// The single tunable vault runtime field exposed by `store config`: the
/// master-key cache TTL in seconds (`0` disables caching). KDF cost params
/// (`m`/`t`/`p`) are intentionally NOT here — changing them alters the derived
/// key and requires re-encryption, which is `rekey`'s job.
const CACHE_TTL_FIELD: &str = "cache-ttl-secs";

/// Dispatch for the `Store` arm of the CLI.
pub fn run(cli: &Cli, action: &StoreAction) -> i32 {
    match action {
        StoreAction::Status => status(cli),
        StoreAction::Use {
            mode,
            cache_ttl_secs,
            yes,
        } => use_mode(cli, *mode, *cache_ttl_secs, *yes),
        StoreAction::Rekey => rekey(cli),
        StoreAction::Lock => lock(cli),
        StoreAction::Unlock => unlock(cli),
        StoreAction::Config { action } => config(cli, action.as_ref()),
    }
}

// ===========================================================================
// status
// ===========================================================================

/// `sshrack store status`: print the active mode and per-kind password counts.
/// Read-only — never prompts, unlocks, or writes. `--format json` emits the
/// locked [`fmt::StoreStatusRow`] (no secrets).
fn status(cli: &Cli) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let (encrypted, plaintext, keyring) = vault::transform::count_secrets(&cfg);

    if matches!(cli.format, OutputFormat::Json) {
        // The locked row carries no secret material (only mode + non-secret KDF
        // params + a boolean verifier presence). Counts are not in the row
        // schema; print them on stderr so the JSON on stdout stays a single
        // clean object for `jq`.
        let row = fmt::store_status_row(&cfg);
        let json = match serde_json::to_string(&row) {
            Ok(s) => s,
            Err(e) => return fail(&format!("sshrack: json error: {e}"), exit_code::USAGE),
        };
        println!("{json}");
        eprintln!("passwords: {encrypted} encrypted, {plaintext} plaintext, {keyring} in keyring");
        return exit_code::SUCCESS;
    }

    print!("{}", report(&cfg, encrypted, plaintext, keyring));
    exit_code::SUCCESS
}

/// Pure: the human-readable status report. Separated from [`status`] so it is
/// unit-testable without capturing stdout.
fn report(cfg: &SshrackConfig, encrypted: usize, plaintext: usize, keyring: usize) -> String {
    let (mode_line, counts) = match &cfg.store {
        Some(SecretStore::Vault { meta }) => (
            format!(
                "mode:       vault ({})\ncache ttl:  {}s",
                meta.kdf, meta.cache_ttl_secs
            ),
            format!(
                "passwords:  {encrypted} encrypted, {plaintext} plaintext, {keyring} in keyring"
            ),
        ),
        Some(SecretStore::Keyring) => (
            "mode:       keyring".to_string(),
            format!(
                "passwords:  {keyring} in keyring, {plaintext} plaintext, {encrypted} encrypted"
            ),
        ),
        Some(SecretStore::Plaintext) => (
            "mode:       plaintext".to_string(),
            format!(
                "passwords:  {plaintext} plaintext, {encrypted} encrypted, {keyring} in keyring"
            ),
        ),
        None => (
            "mode:       undecided".to_string(),
            format!(
                "passwords:  {plaintext} plaintext, {encrypted} encrypted, {keyring} in keyring"
            ),
        ),
    };
    format!("{mode_line}\n{counts}\n")
}

// ===========================================================================
// use <mode>
// ===========================================================================

/// `sshrack store use <mode>`: switch the storage mode and migrate every stored
/// password in one pass. See the module docs for the per-target rules.
fn use_mode(cli: &Cli, mode: StoreMode, cache_ttl_secs: Option<u64>, yes: bool) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    let backend = OsKeyring;

    let result = match mode {
        StoreMode::Keyring => switch_to_keyring(&mut cfg, &path, cli.no_input, &backend),
        StoreMode::Vault => {
            switch_to_vault(&mut cfg, &path, cache_ttl_secs, cli.no_input, &backend)
        }
        StoreMode::Plaintext => switch_to_plaintext(&mut cfg, &path, cli.no_input, yes, &backend),
    };
    match result {
        Ok(code) => code,
        Err((msg, code)) => fail(&msg, code),
    }
}

/// How a `use <mode>` switch resolves against the current config: either a
/// no-op (already in the target mode) or a migration that may need the source
/// vault key to decrypt existing bodies. Pure.
#[derive(Debug, PartialEq, Eq)]
enum Switch {
    /// Target mode already active — print and return without migrating.
    AlreadyThere,
    /// A re-host is required. `needs_source_key` is true only when the source is
    /// vault and the target is not (the old vault key must decrypt bodies).
    Migrate { needs_source_key: bool },
}

/// Pure: how a `use <mode>` switch resolves against the current config, without
/// any I/O. Encodes the no-op and source-key rules the switch arms execute.
fn classify(cfg: &SshrackConfig, mode: StoreMode) -> Switch {
    let already = match mode {
        StoreMode::Plaintext => cfg.is_plaintext(),
        StoreMode::Vault => cfg.is_vault(),
        StoreMode::Keyring => cfg.is_keyring(),
    };
    if already {
        return Switch::AlreadyThere;
    }
    // Only vault→X needs the old vault key to decrypt source bodies. enable
    // (target=vault) is only reached from a non-vault source.
    let needs_source_key = cfg.is_vault() && !matches!(mode, StoreMode::Vault);
    Switch::Migrate { needs_source_key }
}

/// Switch to keyring mode. Fail-fast on [`OsKeyring::available`]; migrate via
/// [`vault::transform::migrate`] with the source key (if leaving vault).
fn switch_to_keyring(
    cfg: &mut SshrackConfig,
    path: &std::path::Path,
    no_input: bool,
    backend: &OsKeyring,
) -> Result<i32, (String, i32)> {
    if matches!(classify(cfg, StoreMode::Keyring), Switch::AlreadyThere) {
        println!("already in keyring mode");
        return Ok(exit_code::SUCCESS);
    }
    vault::cache::clear_default_cache();
    if !backend.available() {
        return Err((
            "sshrack: OS keyring is unavailable; cannot migrate into keyring mode".into(),
            exit_code::STORE,
        ));
    }
    let source_key = if matches!(
        classify(cfg, StoreMode::Keyring),
        Switch::Migrate {
            needs_source_key: true
        }
    ) {
        unlock_vault_key(cfg, no_input)?
    } else {
        None
    };
    let n = vault::transform::migrate(
        cfg,
        &SecretStore::Keyring,
        source_key.as_ref(),
        None,
        backend,
    )
    .map_err(store_err("failed to migrate into keyring mode"))?;
    cfg.store = Some(SecretStore::Keyring);
    save_config(path, cfg)?;
    println!("switched to keyring mode; {n} password(s) moved to the OS keyring");
    Ok(exit_code::SUCCESS)
}

/// Switch to vault mode. Collect a confirmed passphrase (env under
/// `--no-input`), then [`vault::enable`] derives the key, writes the verifier,
/// and migrates every existing password before flipping `cfg.store`.
fn switch_to_vault(
    cfg: &mut SshrackConfig,
    path: &std::path::Path,
    cache_ttl_secs: Option<u64>,
    no_input: bool,
    backend: &OsKeyring,
) -> Result<i32, (String, i32)> {
    if matches!(classify(cfg, StoreMode::Vault), Switch::AlreadyThere) {
        println!("already in vault mode; use `sshrack store rekey` to change the passphrase");
        return Ok(exit_code::SUCCESS);
    }
    // Leaving keyring mode: the keyring entries must be readable to migrate.
    if cfg.is_keyring() && !backend.available() {
        return Err((
            "sshrack: OS keyring is unavailable; cannot read keyring entries to migrate".into(),
            exit_code::STORE,
        ));
    }
    vault::cache::clear_default_cache();
    let passphrase = if no_input {
        // Under --no-input the passphrase must come from the env; refuse to
        // prompt. An unset env surfaces as a store error, not a TTY hang.
        match vault::passphrase_from_env() {
            Some(p) => p,
            None => {
                return Err((
                    "sshrack: vault passphrase required (set SSHRACK_PASSPHRASE or run without --no-input)"
                        .into(),
                    exit_code::STORE,
                ));
            }
        }
    } else {
        match DialoguerPassphrase.passphrase_confirm() {
            Ok(p) => p,
            Err(SshrackError::Interrupted) => return Ok(130), // silent cancel
            Err(e) => return Err((format!("sshrack: {e}"), exit_code::USAGE)),
        }
    };
    vault::enable(cfg, &passphrase, cache_ttl_secs, backend)
        .map_err(store_err("failed to enable vault mode"))?;
    save_config(path, cfg)?;
    println!("switched to vault mode; all passwords encrypted under the master passphrase");
    Ok(exit_code::SUCCESS)
}

/// Switch to plaintext mode. A security downgrade: confirm unless `--yes`.
/// Under `--no-input`, an explicit `--yes` is required or the switch is refused
/// (a destructive action never proceeds unattended). When the source is vault,
/// unlock first (the source key decrypts every body before re-sealing).
fn switch_to_plaintext(
    cfg: &mut SshrackConfig,
    path: &std::path::Path,
    no_input: bool,
    yes: bool,
    backend: &OsKeyring,
) -> Result<i32, (String, i32)> {
    if matches!(classify(cfg, StoreMode::Plaintext), Switch::AlreadyThere) {
        println!("already in plaintext mode");
        return Ok(exit_code::SUCCESS);
    }
    // A destructive downgrade: under --no-input require an explicit --yes, else
    // refuse (confirm_with_fallback returns false under --no-input, so a bare
    // `store use plaintext --no-input` errors rather than silently downgrading).
    if no_input && !yes {
        return Err((
            "sshrack: switching to plaintext is a security downgrade; pass --yes to confirm".into(),
            exit_code::USAGE,
        ));
    }
    if !confirm_plaintext_downgrade(yes, no_input)? {
        // User declined the interactive prompt (default No).
        println!("plaintext switch cancelled");
        return Ok(exit_code::SUCCESS);
    }
    vault::cache::clear_default_cache();
    let source_key = if matches!(
        classify(cfg, StoreMode::Plaintext),
        Switch::Migrate {
            needs_source_key: true
        }
    ) {
        unlock_vault_key(cfg, no_input)?
    } else {
        None
    };
    if cfg.is_keyring() && !backend.available() {
        return Err((
            "sshrack: OS keyring is unavailable; cannot read keyring entries to migrate".into(),
            exit_code::STORE,
        ));
    }
    let n = vault::transform::migrate(
        cfg,
        &SecretStore::Plaintext,
        source_key.as_ref(),
        None,
        backend,
    )
    .map_err(store_err("failed to migrate into plaintext mode"))?;
    cfg.store = Some(SecretStore::Plaintext);
    save_config(path, cfg)?;
    println!("switched to plaintext mode; {n} password(s) written in plaintext");
    Ok(exit_code::SUCCESS)
}

/// Confirm the irreversible plaintext write unless `--yes`. Returns true to
/// proceed. Under `--no-input` the caller has already verified `--yes`, so this
/// is only reached interactively.
fn confirm_plaintext_downgrade(yes: bool, no_input: bool) -> Result<bool, (String, i32)> {
    if yes {
        return Ok(true);
    }
    confirm_destructive(no_input, "Store ALL passwords in plaintext?")
        .map_err(|code| (String::new(), code))
}

/// Wrap a vault/migrate error into a printed-message + exit-code pair.
fn store_err(context: &'static str) -> impl Fn(SshrackError) -> (String, i32) {
    move |e| (format!("sshrack: {context}: {e}"), exit_code::STORE)
}

// ===========================================================================
// rekey / lock / unlock
// ===========================================================================

/// `sshrack store rekey`: change the master passphrase. Unlock under the
/// current passphrase, decrypt everything to plaintext, clear the vault, then
/// re-enable under a fresh passphrase (new salt, new verifier). Errors
/// `VaultNotEnabled` when no vault is configured.
fn rekey(cli: &Cli) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    let backend = OsKeyring;

    // Drop any cached master key first: a stale cache from the old passphrase
    // could mask the unlock step or serve a key rekey is about to replace.
    vault::cache::clear_default_cache();
    if !cfg.is_vault() {
        return fail(
            "sshrack: rekey is vault-only; no vault is configured",
            exit_code::STORE,
        );
    }

    let provider: &dyn sshrack_core::secret::PassphraseProvider = if cli.no_input {
        &NoInputPassphrase
    } else {
        &DialoguerPassphrase
    };
    let env_pw = vault::passphrase_from_env();

    // Unlock with the current passphrase, decrypt everything to plaintext.
    let old_key = match vault::ensure_unlocked_vault_key(&cfg, env_pw.as_ref(), provider) {
        Ok(Some(k)) => k,
        Ok(None) => {
            // Unreachable: is_vault() is true above, so ensure_unlocked_vault_key
            // either returns Some(key) or errors VaultLocked — never Ok(None).
            return fail("sshrack: rekey: vault not enabled", exit_code::STORE);
        }
        Err(SshrackError::Interrupted) => return 130,
        Err(e) => {
            return fail(
                &format!("sshrack: vault unlock failed: {e}"),
                exit_code::STORE,
            );
        }
    };
    if let Err(e) = vault::transform::decrypt_all(&mut cfg, &old_key) {
        return fail(&format!("sshrack: rekey: {e}"), exit_code::STORE);
    }
    // Preserve the configured cache TTL across rekey so a prior
    // `store config set cache-ttl-secs` survives a passphrase change. KDF
    // params get fresh defaults; TTL is pure metadata, not key-derived.
    let preserved_ttl = cfg.vault_meta().map(|m| m.cache_ttl_secs);
    cfg.store = None;

    // Re-enable under a fresh passphrase (new salt, new verifier).
    let new_passphrase = if cli.no_input {
        match vault::passphrase_from_env() {
            Some(p) => p,
            None => {
                return fail(
                    "sshrack: new vault passphrase required (set SSHRACK_PASSPHRASE or run without --no-input)",
                    exit_code::STORE,
                );
            }
        }
    } else {
        match DialoguerPassphrase.passphrase_confirm() {
            Ok(p) => p,
            Err(SshrackError::Interrupted) => return 130,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::USAGE),
        }
    };
    if let Err(e) = vault::enable(&mut cfg, &new_passphrase, preserved_ttl, &backend) {
        return fail(
            &format!("sshrack: failed to rekey vault: {e}"),
            exit_code::STORE,
        );
    }
    if let Err((msg, code)) = save_config(&path, &cfg) {
        return fail(&msg, code);
    }
    println!("vault rekeyed; all passwords re-encrypted under the new passphrase");
    exit_code::SUCCESS
}

/// `sshrack store lock`: drop the cached master key so the next connection
/// re-prompts. Idempotent — a missing cache file is not an error. Errors
/// `STORE` when no vault is configured (locking is meaningless in plaintext).
fn lock(cli: &Cli) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    if !cfg.is_vault() {
        return fail(
            "sshrack: lock is vault-only; no vault is configured",
            exit_code::STORE,
        );
    }
    vault::cache::clear_default_cache();
    println!("vault locked; the next connection will re-prompt for the passphrase");
    exit_code::SUCCESS
}

/// `sshrack store unlock`: pre-warm the cached master key so subsequent
/// non-interactive invocations hit the cache. Idempotent. Errors `STORE` when
/// no vault is configured.
fn unlock(cli: &Cli) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    if !cfg.is_vault() {
        return fail(
            "sshrack: unlock is vault-only; no vault is configured",
            exit_code::STORE,
        );
    }
    let provider: &dyn sshrack_core::secret::PassphraseProvider = if cli.no_input {
        &NoInputPassphrase
    } else {
        &DialoguerPassphrase
    };
    let env_pw = vault::passphrase_from_env();
    match vault::ensure_unlocked_vault_key(&cfg, env_pw.as_ref(), provider) {
        Ok(_) => {}
        Err(SshrackError::Interrupted) => return 130,
        Err(e) => {
            return fail(
                &format!("sshrack: vault unlock failed: {e}"),
                exit_code::STORE,
            );
        }
    }
    println!("vault unlocked; master key cached for the TTL window");
    exit_code::SUCCESS
}

// ===========================================================================
// config (get/set non-secret vault runtime fields)
// ===========================================================================

/// `sshrack store config [show|get <field>|set <field> <value>]`: read/write
/// non-secret vault runtime fields. Currently only `cache-ttl-secs` (the one
/// field whose change needs no re-encryption). `show` with no sub-action lists
/// every field.
fn config(cli: &Cli, action: Option<&crate::cli::ConfigAction>) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    match action {
        None | Some(crate::cli::ConfigAction::Show) => config_show(&cfg),
        Some(crate::cli::ConfigAction::Get { field }) => config_get(&cfg, field),
        Some(crate::cli::ConfigAction::Set { field, value }) => {
            config_set(&mut cfg, &path, field, value)
        }
    }
}

/// Print every tunable field and its current value. Reports "no vault
/// configured" in plaintext mode rather than erroring (mirrors `status`).
fn config_show(cfg: &SshrackConfig) -> i32 {
    match cfg.vault_meta() {
        Some(meta) => {
            println!("{CACHE_TTL_FIELD} = {}", meta.cache_ttl_secs);
        }
        None => println!("mode: plaintext (no vault configured)"),
    }
    exit_code::SUCCESS
}

/// Print a single field's current value. Errors `STORE` in plaintext mode and
/// `VALIDATION` for an unrecognized field name.
fn config_get(cfg: &SshrackConfig, field: &str) -> i32 {
    if field != CACHE_TTL_FIELD {
        return fail(
            &format!("sshrack: unknown vault field '{field}' (valid: {CACHE_TTL_FIELD})"),
            exit_code::VALIDATION,
        );
    }
    let Some(meta) = cfg.vault_meta() else {
        return fail(
            "sshrack: no vault configured (run `sshrack store use vault`)",
            exit_code::STORE,
        );
    };
    println!("{}", meta.cache_ttl_secs);
    exit_code::SUCCESS
}

/// Validate and persist a single field's value. Validation runs before the file
/// is written, so a bad value leaves the on-disk config untouched.
fn config_set(cfg: &mut SshrackConfig, path: &std::path::Path, field: &str, value: &str) -> i32 {
    if field != CACHE_TTL_FIELD {
        return fail(
            &format!("sshrack: unknown vault field '{field}' (valid: {CACHE_TTL_FIELD})"),
            exit_code::VALIDATION,
        );
    }
    let secs: u64 = match value.parse() {
        Ok(s) => s,
        Err(_) => {
            return fail(
                &format!(
                    "sshrack: invalid value for {CACHE_TTL_FIELD}: '{value}' (expected a non-negative integer; 0 disables caching)"
                ),
                exit_code::VALIDATION,
            );
        }
    };
    let Some(meta) = vault_meta_mut(cfg) else {
        return fail(
            "sshrack: no vault configured (run `sshrack store use vault`)",
            exit_code::STORE,
        );
    };
    meta.cache_ttl_secs = secs;
    if let Err((msg, code)) = save_config(path, cfg) {
        return fail(&msg, code);
    }
    println!("{CACHE_TTL_FIELD} = {secs}");
    exit_code::SUCCESS
}

/// Borrow the mutable [`VaultMeta`] when in vault mode, else `None`.
fn vault_meta_mut(cfg: &mut SshrackConfig) -> Option<&mut VaultMeta> {
    match &mut cfg.store {
        Some(SecretStore::Vault { meta }) => Some(meta),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::{Credential, CredentialBody, Host, Secret, VaultMeta};

    fn plain_cfg() -> SshrackConfig {
        SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        }
    }

    fn vault_cfg() -> SshrackConfig {
        SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: VaultMeta::default_argon2id("AA=="),
            }),
            ..SshrackConfig::default()
        }
    }

    #[test]
    fn classify_same_mode_is_already_there() {
        assert_eq!(
            classify(&plain_cfg(), StoreMode::Plaintext),
            Switch::AlreadyThere
        );
        assert_eq!(
            classify(&vault_cfg(), StoreMode::Vault),
            Switch::AlreadyThere
        );
    }

    #[test]
    fn classify_to_vault_needs_no_source_key_from_plaintext() {
        assert_eq!(
            classify(&plain_cfg(), StoreMode::Vault),
            Switch::Migrate {
                needs_source_key: false
            }
        );
    }

    #[test]
    fn classify_from_vault_to_plaintext_needs_source_key() {
        assert!(matches!(
            classify(&vault_cfg(), StoreMode::Plaintext),
            Switch::Migrate {
                needs_source_key: true
            }
        ));
    }

    #[test]
    fn classify_from_keyring_to_plaintext_needs_no_source_key() {
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        assert!(matches!(
            classify(&cfg, StoreMode::Plaintext),
            Switch::Migrate {
                needs_source_key: false
            }
        ));
    }

    #[test]
    fn report_undecided_mode() {
        let cfg = SshrackConfig::default();
        let out = report(&cfg, 0, 0, 0);
        assert!(out.contains("mode:       undecided"), "was:\n{out}");
    }

    #[test]
    fn report_vault_shows_kdf_and_ttl() {
        let cfg = vault_cfg();
        let out = report(&cfg, 1, 0, 0);
        assert!(out.starts_with("mode:       vault ("), "was:\n{out}");
        assert!(out.contains("cache ttl:"), "was:\n{out}");
        assert!(out.contains("1 encrypted"), "was:\n{out}");
    }

    #[test]
    fn config_set_rejects_bad_value_string() {
        // Pure: validation path; we don't actually save (no tmp path needed
        // because parsing fails first).
        let mut cfg = vault_cfg();
        let code = config_set(
            &mut cfg,
            std::path::Path::new("/nonexistent/x.toml"),
            "cache-ttl-secs",
            "abc",
        );
        assert_eq!(code, exit_code::VALIDATION);
    }

    #[test]
    fn config_get_unknown_field_is_validation_error() {
        let cfg = vault_cfg();
        assert_eq!(config_get(&cfg, "nope"), exit_code::VALIDATION);
    }

    #[test]
    fn config_get_in_plaintext_is_store_error() {
        let cfg = plain_cfg();
        assert_eq!(config_get(&cfg, "cache-ttl-secs"), exit_code::STORE);
    }

    // ---- report counts across mixed bodies (representation-driven) ----

    #[test]
    fn report_counts_mixed_kinds() {
        // One encrypted credential, one plaintext host, one keyring marker host.
        let mut cfg = vault_cfg();
        cfg.credentials.push(Credential {
            id: ulid::Ulid::new(),
            alias: "enc".into(),
            body: CredentialBody {
                user: "u".into(),
                password: Some(Secret::Encrypted(
                    sshrack_core::config::schema::EncryptedSecret {
                        nonce: "n".into(),
                        cipher: "c".into(),
                    },
                )),
                key: None,
                keyring: false,
            },
        });
        cfg.hosts.push(Host {
            id: ulid::Ulid::new(),
            alias: "plain-host".into(),
            host: "h".into(),
            port: 22,
            auth: sshrack_core::config::schema::Auth::Inline(CredentialBody {
                user: "u".into(),
                password: Some(Secret::Plain("p".into())),
                key: None,
                keyring: false,
            }),
        });
        cfg.hosts.push(Host {
            id: ulid::Ulid::new(),
            alias: "kr-host".into(),
            host: "k".into(),
            port: 22,
            auth: sshrack_core::config::schema::Auth::Inline(CredentialBody {
                user: "u".into(),
                password: None,
                key: None,
                keyring: true,
            }),
        });
        let (enc, plain, kr) = vault::transform::count_secrets(&cfg);
        assert_eq!((enc, plain, kr), (1, 1, 1));
    }
}
