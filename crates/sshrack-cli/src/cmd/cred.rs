//! `sshrack cred …` handlers: add / ls / show / edit / rm.
//!
//! Same shape as [`super::host`] but for reusable `[[credentials]]` entries.
//! `--credential` is N/A (a credential cannot reference another credential);
//! the body is built from `--user`/`--identity` or an interactive prompt.
//!
//! `rm` warns before removing when [`credential::find_referrers`] is non-empty
//! — references are by id, so removing the credential leaves dangling refs.
//! The referrer host aliases are listed (reverse-resolved from the ids).
//!
//! The prompt helpers here return `Result<T, i32>` (an exit code on failure),
//! not `Result<T, SshrackError>`. Because `i32` does not implement
//! `FromResidual`, the `?` operator cannot propagate these errors, so the
//! `clippy::question_mark` lint is suppressed at the module level (see
//! [`super::host`] for the same rationale).

#![allow(clippy::question_mark)]

use dialoguer::FuzzySelect;
use dialoguer::theme::ColorfulTheme;
use zeroize::Zeroizing;

use sshrack_core::config::schema::{Auth, Credential, CredentialBody};
use sshrack_core::credential as cred_core;
use sshrack_core::error::SshrackError;
use sshrack_core::host;
use sshrack_core::id::{OwnerKind, new_id};
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::vault;

use crate::cli::{Cli, CredAction, OutputFormat};
use crate::exit_code;
use crate::format as fmt;

use super::shared::{
    confirm_destructive, ensure_storage_mode_decided, fail, load_config, print_json_array,
    print_text_table, prompt_fail, prompt_password, prompt_string, prompt_string_with_default,
    save_config, selected_fields, unlock_vault_key,
};

/// Dispatch for the `Cred` arm of the CLI.
pub fn run(cli: &Cli, action: &CredAction) -> i32 {
    let no_input = cli.no_input
        || matches!(
            action,
            CredAction::Add { no_input: true, .. } | CredAction::Edit { no_input: true, .. }
        );
    match action {
        CredAction::Add {
            alias,
            user,
            identity,
            no_input: _,
            force,
        } => add(
            cli,
            alias.as_deref(),
            user.as_deref(),
            identity.as_deref(),
            *force,
            no_input,
        ),
        CredAction::Ls { fields } => ls(cli, fields.as_deref()),
        CredAction::Show { alias, reveal } => show(cli, alias, *reveal, no_input),
        CredAction::Edit {
            alias,
            user,
            identity,
            clear_identity,
            rename,
            no_input: _,
        } => edit(
            cli,
            alias.as_deref(),
            user.as_deref(),
            identity.as_deref(),
            *clear_identity,
            rename.as_deref(),
            no_input,
        ),
        CredAction::Rm { alias, yes } => rm(cli, alias.as_deref(), *yes, no_input),
    }
}

/// Every column `cred ls` can show, in default order.
const ALL_CRED_FIELDS: &[&str] = &["alias", "user", "secret"];

// ===========================================================================
// add
// ===========================================================================

fn add(
    cli: &Cli,
    alias: Option<&str>,
    user: Option<&str>,
    identity: Option<&std::path::Path>,
    force: bool,
    no_input: bool,
) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Resolve the alias: explicit wins; otherwise interactive (or error under
    // --no-input). Validate forbidden chars + duplicate before field work.
    let alias = match alias {
        Some(a) => a.to_owned(),
        None if no_input => {
            return fail(
                "sshrack: missing required field: credential alias (required in --no-input mode; omit --no-input for interactive entry)",
                exit_code::VALIDATION,
            );
        }
        None => match prompt_fresh_alias(&cfg, "New credential alias", force) {
            Ok(a) => a,
            Err(ret) => return ret,
        },
    };
    if let Err(e) = host::validate_alias_chars(&alias) {
        return fail(&format!("sshrack: {e}"), exit_code::VALIDATION);
    }
    if let Err(e) = cred_core::validate_no_duplicate_credential(&cfg, &alias, force) {
        return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
    }

    let cred_id = new_id();

    // Build the body: --no-input uses flags (password cannot come from a flag);
    // interactive prompts the body (user/secret) and seals any inline password.
    let body = if no_input {
        let opts = cred_core::AddOptions {
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            no_input,
            force,
        };
        match cred_core::build_body(&opts) {
            Ok(b) => b,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    } else {
        let body = match prompt_credential_body(user, identity) {
            Ok(b) => b,
            Err(ret) => return ret,
        };
        // Seal any inline plaintext password per the active storage mode.
        match seal_body_with_password(&mut cfg, body, OwnerKind::Credential, &cred_id) {
            Ok(b) => b,
            Err(ret) => return ret,
        }
    };

    let next = match cred_core::add_credential(&cfg, cred_id, &alias, body) {
        Ok(n) => n,
        Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
    };
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("added credential '{alias}'");
    exit_code::SUCCESS
}

// ===========================================================================
// ls
// ===========================================================================

fn ls(cli: &Cli, fields_spec: Option<&str>) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };
    if cfg.credentials.is_empty() {
        println!("no credentials yet — add one with: sshrack cred add <alias>");
        return exit_code::SUCCESS;
    }

    let selected = match selected_fields(fields_spec, ALL_CRED_FIELDS) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    match cli.format {
        OutputFormat::Json => {
            let rows: Vec<_> = cfg
                .credentials
                .iter()
                .map(fmt::credential_list_row)
                .collect();
            print_json_array(&rows);
        }
        OutputFormat::Text => {
            let refs: Vec<&Credential> = cfg.credentials.iter().collect();
            print_text_table(&refs, &selected, cell);
        }
    }
    exit_code::SUCCESS
}

// ===========================================================================
// show
// ===========================================================================

fn show(cli: &Cli, alias: &str, reveal: bool, no_input: bool) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let Some(cred) = cfg.find_credential_by_alias(alias) else {
        let err = cred_core::credential_not_found(&cfg, alias);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    let revealed_pw = if reveal {
        match reveal_password(&cfg, cred, no_input) {
            Ok(r) => r,
            Err(ret) => return ret,
        }
    } else {
        RevealedPassword::Masked
    };

    match cli.format {
        OutputFormat::Json => {
            // The credential's locked JSON shape (no secret value).
            let row = fmt::credential_list_row(cred);
            let json = serde_json::to_string(&row).unwrap_or_else(|e| {
                eprintln!("sshrack: json error: {e}");
                String::from("{}")
            });
            if let Some(pw) = revealed_pw.as_json_field() {
                let trimmed = json.trim_end_matches('}');
                println!("{trimmed},\"password\":\"{pw}\"}}");
            } else {
                println!("{json}");
            }
        }
        OutputFormat::Text => {
            print!("{}", format_detail(cred, &revealed_pw));
        }
    }
    exit_code::SUCCESS
}

// ===========================================================================
// edit
// ===========================================================================

fn edit(
    cli: &Cli,
    alias: Option<&str>,
    user: Option<&str>,
    identity: Option<&std::path::Path>,
    clear_identity: bool,
    rename: Option<&str>,
    no_input: bool,
) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let alias = match pick_existing_credential(&cfg, alias, no_input) {
        Ok(a) => a,
        Err(ret) => return ret,
    };
    let Some(orig) = cfg.find_credential_by_alias(&alias).cloned() else {
        let err = cred_core::credential_not_found(&cfg, &alias);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    if let Some(new) = rename {
        if let Err(e) = cred_core::validate_rename_credential(&cfg, &alias, new) {
            return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
        }
    }

    let has_any_flag = user.is_some() || identity.is_some() || clear_identity || rename.is_some();

    let updated = if !has_any_flag && !no_input {
        // Full interactive path: re-collect the body and re-seal.
        let body = match prompt_credential_body(Some(&orig.body.user), orig.body.key.as_deref()) {
            Ok(b) => b,
            Err(ret) => return ret,
        };
        let sealed = match seal_body_with_password(&mut cfg, body, OwnerKind::Credential, &orig.id)
        {
            Ok(b) => b,
            Err(ret) => return ret,
        };
        Credential {
            id: orig.id,
            alias: orig.alias.clone(),
            body: sealed,
        }
    } else if !has_any_flag && no_input {
        println!("no changes");
        return exit_code::SUCCESS;
    } else {
        // PATCH path: only flagged fields change.
        let opts = cred_core::EditOptions {
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            clear_identity,
            rename: rename.map(Into::into),
            no_input,
        };
        match cred_core::apply_credential_patch(&orig, &opts) {
            Ok(c) => c,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    };

    // Replace in place by id (orig may have been renamed).
    let mut next = cfg.clone();
    if let Some(slot) = next.credentials.iter_mut().find(|c| c.id == orig.id) {
        *slot = updated;
    }
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    let final_alias = next
        .credentials
        .iter()
        .find(|c| c.id == orig.id)
        .map(|c| c.alias.as_str())
        .unwrap_or(&alias);
    if rename.is_some() && final_alias != alias {
        println!("renamed '{alias}' -> '{final_alias}'");
    }
    println!("edited credential '{final_alias}'");
    exit_code::SUCCESS
}

// ===========================================================================
// rm
// ===========================================================================

fn rm(cli: &Cli, alias: Option<&str>, yes: bool, no_input: bool) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let alias = match pick_existing_credential(&cfg, alias, no_input) {
        Ok(a) => a,
        Err(ret) => return ret,
    };

    // Look up the credential to get its id for referrer lookup.
    let Some(cred) = cfg.find_credential_by_alias(&alias) else {
        let err = cred_core::credential_not_found(&cfg, &alias);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };
    let cred_id = cred.id;

    // Warn + list referrers (host aliases, reverse-resolved from the ids).
    let referrer_aliases: Vec<String> = cred_core::find_referrers(&cfg, &cred_id)
        .iter()
        .filter_map(|hid| cfg.find_host_by_id(hid).map(|h| h.alias.clone()))
        .collect();

    // Confirm unless --yes. Under --no-input without --yes, fail-closed
    // (confirm_destructive returns false); the referrer warning still prints
    // so the user sees what would be affected.
    if !yes {
        if !referrer_aliases.is_empty() {
            println!(
                "warning: credential '{alias}' is referenced by host(s): {}",
                referrer_aliases.join(", ")
            );
        }
        let confirmed =
            match confirm_destructive(no_input, &format!("Remove credential '{alias}'?")) {
                Ok(c) => c,
                Err(ret) => return ret,
            };
        if !confirmed {
            println!("aborted");
            return exit_code::SUCCESS;
        }
    } else if !referrer_aliases.is_empty() {
        // Even with --yes, surface the dangling refs so the user knows.
        eprintln!(
            "warning: credential '{alias}' was referenced by host(s): {} (references are now dangling)",
            referrer_aliases.join(", ")
        );
    }

    let backend = OsKeyring;
    let next = match cred_core::delete_credential_with_secret(&cfg, &alias, &backend) {
        Ok(n) => n,
        Err(e) => return fail(&format!("sshrack: {e}"), exit_code::NOT_FOUND),
    };
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("removed credential '{alias}'");
    exit_code::SUCCESS
}

// ===========================================================================
// helpers (credential-specific)
// ===========================================================================

/// The value of one column for one credential (pure).
fn cell(field: &str, c: &Credential) -> String {
    match field {
        "alias" => c.alias.clone(),
        "user" => c.body.user.clone(),
        "secret" => fmt::secret_kind_label(&c.body.secret_kind()).into(),
        _ => String::new(),
    }
}

/// Prompt for a fresh alias, re-prompting on a collision or forbidden char.
fn prompt_fresh_alias(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    label: &str,
    force: bool,
) -> Result<String, i32> {
    loop {
        let s = match prompt_string(label) {
            Ok(s) => s,
            ret @ Err(_) => return ret,
        };
        match host::validate_alias_chars(&s) {
            Ok(()) => match cred_core::validate_no_duplicate_credential(cfg, &s, force) {
                Ok(()) => return Ok(s),
                Err(e) => eprintln!("sshrack: {e}"),
            },
            Err(e) => eprintln!("sshrack: {e}"),
        }
    }
}

/// Pick an existing credential by alias. Interactive menu when omitted and not
/// `--no-input`; error when omitted and `--no-input`.
fn pick_existing_credential(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    alias: Option<&str>,
    no_input: bool,
) -> Result<String, i32> {
    if let Some(a) = alias {
        return Ok(a.to_owned());
    }
    if cfg.credentials.is_empty() {
        println!("no credentials yet — add one with: sshrack cred add <alias>");
        return Err(exit_code::SUCCESS);
    }
    if no_input {
        return Err(fail(
            "sshrack: credential alias required in --no-input mode",
            exit_code::USAGE,
        ));
    }
    let theme = ColorfulTheme::default();
    let items: Vec<&str> = cfg.credentials.iter().map(|c| c.alias.as_str()).collect();
    let idx = match FuzzySelect::with_theme(&theme)
        .with_prompt("Select credential")
        .items(&items)
        .default(0)
        .report(false)
        .interact()
    {
        Ok(i) => i,
        Err(e) => return Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    };
    Ok(items[idx].to_owned())
}

/// Prompt for the credential body's fields. `default_user` / `default_key`
/// pre-fill when editing.
fn prompt_credential_body(
    default_user: Option<&str>,
    default_key: Option<&std::path::Path>,
) -> Result<CredentialBody, i32> {
    let theme = ColorfulTheme::default();
    let items = ["Password", "Identity key", "Default (no secret)"];
    let default_idx = match default_key {
        Some(_) => 1,
        None => 0,
    };
    let idx = match FuzzySelect::with_theme(&theme)
        .with_prompt("Secret kind")
        .items(items)
        .default(default_idx)
        .report(false)
        .interact()
    {
        Ok(i) => i,
        Err(e) => return Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    };

    let user_default = default_user.unwrap_or("root");
    let user = match prompt_string_with_default("Login user", user_default) {
        Ok(s) => s,
        Err(ret) => return Err(ret),
    };

    match idx {
        0 => {
            let pw = match prompt_password("Password") {
                Ok(p) => p,
                Err(ret) => return Err(ret),
            };
            Ok(CredentialBody::new(user).with_password(pw))
        }
        1 => {
            let key_default = default_key
                .and_then(|p| p.to_str())
                .filter(|s| !s.is_empty());
            let key = match key_default {
                Some(d) => match prompt_string_with_default("Identity key path", d) {
                    Ok(s) => s,
                    Err(ret) => return Err(ret),
                },
                None => match prompt_string("Identity key path") {
                    Ok(s) => s,
                    Err(ret) => return Err(ret),
                },
            };
            Ok(CredentialBody::new(user).with_key(std::path::PathBuf::from(key)))
        }
        _ => Ok(CredentialBody::new(user)),
    }
}

/// Seal a freshly-collected body's inline plaintext password per the active
/// storage mode. Resolves first-use mode and unlocks the vault as needed.
fn seal_body_with_password(
    cfg: &mut sshrack_core::config::schema::SshrackConfig,
    body: CredentialBody,
    owner: OwnerKind,
    owner_id: &ulid::Ulid,
) -> Result<CredentialBody, i32> {
    let needs_seal = matches!(
        body.password,
        Some(sshrack_core::config::schema::Secret::Plain(_))
    );
    if !needs_seal {
        return Ok(body);
    }
    let backend = OsKeyring;
    if let Err((msg, code)) = ensure_storage_mode_decided(cfg, false, &backend) {
        return Err(fail(&msg, code));
    }
    let vault_key = match unlock_vault_key(cfg, false) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    match vault::seal_body(body, owner, owner_id, cfg, vault_key.as_ref(), &backend) {
        Ok(b) => Ok(b),
        Err(e) => Err(fail(&format!("sshrack: {e}"), exit_code::STORE)),
    }
}

/// What the password line of `cred show` should render (mirrors host's).
#[derive(Debug, Clone)]
enum RevealedPassword {
    Masked,
    Plaintext(Zeroizing<String>),
    KeyringMissing,
    None,
}

impl RevealedPassword {
    fn as_json_field(&self) -> Option<&str> {
        match self {
            RevealedPassword::Plaintext(p) => Some(p.as_str()),
            RevealedPassword::KeyringMissing => Some("(not in keyring)"),
            _ => None,
        }
    }

    fn text_line(&self, keyring_body: bool) -> String {
        match self {
            RevealedPassword::Masked => {
                if keyring_body {
                    "(stored in keyring)".into()
                } else {
                    "(hidden)".into()
                }
            }
            RevealedPassword::Plaintext(p) => p.as_str().to_owned(),
            RevealedPassword::KeyringMissing => "(not in keyring)".into(),
            RevealedPassword::None => String::new(),
        }
    }
}

/// Resolve the revealed password for a credential.
fn reveal_password(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    cred: &Credential,
    no_input: bool,
) -> Result<RevealedPassword, i32> {
    let vault_key = match unlock_vault_key(cfg, no_input) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    // Reuse credential::resolve via a synthetic host that references this
    // credential by id — resolve returns PasswordSource keyed off the cred id.
    let host_shell = sshrack_core::config::schema::Host {
        id: new_id(),
        alias: cred.alias.clone(),
        host: String::new(),
        port: 22,
        auth: Auth::reference(cred.id),
    };
    let resolved = match cred_core::resolve(&host_shell, cfg, vault_key.as_ref()) {
        Ok(r) => r,
        Err(e) => return Err(fail(&format!("sshrack: {e}"), exit_code::STORE)),
    };
    Ok(match resolved.password {
        cred_core::PasswordSource::None => RevealedPassword::None,
        cred_core::PasswordSource::Inline(p) => RevealedPassword::Plaintext(p),
        cred_core::PasswordSource::Keyring { key } => {
            match sshrack_core::secret::keyring::get(&key) {
                Ok(Some(p)) => RevealedPassword::Plaintext(p),
                Ok(None) | Err(_) => RevealedPassword::KeyringMissing,
            }
        }
    })
}

/// Render a single credential's fields as text (pure).
fn format_detail(cred: &Credential, reveal: &RevealedPassword) -> String {
    let mut out = String::new();
    out.push_str(&format!("alias:    {}\n", cred.alias));
    out.push_str(&format!("id:       {}\n", cred.id));
    out.push_str(&format!("user:     {}\n", cred.body.user));
    match (
        &cred.body.key,
        cred.body.password.is_some(),
        cred.body.keyring,
    ) {
        (Some(k), _, _) => out.push_str(&format!("key:      {}\n", k.display())),
        (None, _, true) => {
            let line = reveal.text_line(true);
            if !line.is_empty() {
                out.push_str(&format!("password: {line}\n"));
            }
        }
        (None, true, false) => {
            let line = reveal.text_line(false);
            if !line.is_empty() {
                out.push_str(&format!("password: {line}\n"));
            }
        }
        (None, false, false) => out.push_str("auth:     default keys\n"),
    }
    out
}

// ---- shared, host-local helpers re-exported for cred ----
