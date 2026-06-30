//! `sshrack host …` handlers: add / ls / show / edit / rm / cp.
//!
//! Each handler maps a [`HostAction`] to core pure functions
//! (`host::{add_host, apply_patch, finalize_body, …}`) and persists via
//! [`config::store::save`]. Every handler honors `--no-input` (missing required
//! fields error out; no field prompts) and `--format json|text`.
//!
//! Ref-by-id invariant: `--credential <name>` is resolved to a [`Ulid`] here
//! before any core call (fail-fast on an unknown name). `ls`/`show` reverse-
//! resolve the stored `Ulid` back to the credential name for display — the
//! on-disk form is always the id.
//!
//! Nothing here prints a password in an error message. `show --reveal` is the
//! only path that materializes a plaintext, and it goes to stdout.
//!
//! The prompt helpers here return `Result<T, i32>` (an exit code on failure),
//! not `Result<T, SshrackError>`. Because `i32` does not implement
//! `FromResidual`, the `?` operator cannot propagate these errors, so the
//! `clippy::question_mark` lint (which would rewrite `match { Ok => x, Err => return Err(e) }`
//! into `?`) is suppressed at the module level.

#![allow(clippy::question_mark)]

use std::borrow::Cow;

use dialoguer::FuzzySelect;
use dialoguer::theme::ColorfulTheme;
use ulid::Ulid;
use zeroize::Zeroizing;

use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::credential::{self as cred_core, PasswordSource};
use sshrack_core::error::SshrackError;
use sshrack_core::host;
use sshrack_core::id::{OwnerKind, new_id};
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::vault;

use crate::cli::{Cli, HostAction, OutputFormat};
use crate::exit_code;
use crate::format as fmt;

use super::shared::{
    confirm_destructive, ensure_storage_mode_decided, fail, load_config, print_json_array,
    print_text_table, prompt_fail, prompt_password, prompt_port, prompt_string,
    prompt_string_with_default, resolve_credential_name, save_config, selected_fields, sort_hosts,
    unlock_vault_key,
};

/// Dispatch for the `Host` arm of the CLI.
pub fn run(cli: &Cli, action: &HostAction) -> i32 {
    let no_input = cli.no_input || subcommand_no_input(action);
    match action {
        HostAction::Add {
            name,
            host,
            user,
            port,
            identity,
            credential,
            no_input: _,
            force,
        } => add(
            cli,
            name.as_deref(),
            host.as_deref(),
            user.as_deref(),
            *port,
            identity.as_deref(),
            credential.as_deref(),
            *force,
            no_input,
        ),
        HostAction::Ls { fields, sort } => ls(cli, fields.as_deref(), *sort),
        HostAction::Show { name, reveal } => show(cli, name, *reveal, no_input),
        HostAction::Edit {
            name,
            host,
            user,
            port,
            identity,
            rename,
            credential,
            clear_identity,
            clear_password,
            clear_credential,
            no_input: _,
        } => edit(
            cli,
            name.as_deref(),
            host.as_deref(),
            user.as_deref(),
            *port,
            identity.as_deref(),
            rename.as_deref(),
            credential.as_deref(),
            *clear_identity,
            *clear_password,
            *clear_credential,
            no_input,
        ),
        HostAction::Rm { name, yes } => rm(cli, name.as_deref(), *yes, no_input),
        HostAction::Cp { src, dst } => cp(cli, src.as_deref(), dst.as_deref(), no_input),
    }
}

/// `host add` carries its own `--no-input` flag (clap flattens it onto the
/// subcommand). The global `--no-input` and the subcommand flag both suppress
/// prompts; OR them.
fn subcommand_no_input(action: &HostAction) -> bool {
    matches!(
        action,
        HostAction::Add { no_input: true, .. } | HostAction::Edit { no_input: true, .. }
    )
}

// ===========================================================================
// add
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn add(
    cli: &Cli,
    name: Option<&str>,
    host_addr: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&std::path::Path>,
    credential: Option<&str>,
    force: bool,
    no_input: bool,
) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Validate the name up front (forbidden chars) and the duplicate check
    // before any prompt or field work — fail-fast on local errors.
    let name = match resolve_name(&cfg, name, force, no_input, "host") {
        Ok(a) => a,
        Err(ret) => return ret,
    };
    if let Err(e) = host::validate_name_chars(&name) {
        return fail(&format!("sshrack: {e}"), exit_code::VALIDATION);
    }
    if let Err(e) = host::validate_no_duplicate(&cfg, &name, force) {
        return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
    }

    // Resolve `--credential <name>` → Ulid (fail-fast if unknown).
    let cred_ulid = match resolve_credential_name(&cfg, credential) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let opts = host::AddOptions {
        host: host_addr.map(Into::into),
        port,
        credential: cred_ulid,
        user: user.map(Into::into),
        identity: identity.map(std::path::PathBuf::from),
        no_input,
        force,
    };

    // Required `host` field is enforced here for both modes.
    let host_addr_owned = match opts.host.clone() {
        Some(h) => h,
        None if no_input => {
            return fail(
                "sshrack: missing required field: host (pass --host or drop --no-input)",
                exit_code::VALIDATION,
            );
        }
        None => match prompt_string("Remote hostname or IP") {
            Ok(s) => s,
            Err(ret) => return ret,
        },
    };

    let host_id = new_id();
    let mut new_host = match host::merge_fields(host_id, &name, &opts) {
        Ok(h) => h,
        Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
    };
    // merge_fields uses opts.host; override with the (possibly just-prompted)
    // resolved value so the prompt path is reflected.
    new_host.host = host_addr_owned;

    // Interactive auth: if no auth flag was given and we're not in --no-input,
    // prompt for the auth method and collect any inline password.
    if !no_input && !host::auth_supplied_by_flags(&opts) {
        match prompt_auth_and_seal(&mut cfg, &mut new_host.auth, OwnerKind::Host, &host_id) {
            Ok(()) => {}
            Err(ret) => return ret,
        }
    }

    // add_host validates name chars again (cheap) and appends; force replaces.
    let next = if force {
        // Replace in place on --force, preserving nothing (the name is the
        // key). A fresh id is correct — but if the host being overwritten was
        // keyring-marked, its keyring entry (keyed by the OLD id) must be
        // cleaned up so no orphaned secret is left behind, exactly like `rm`.
        // Best-effort: a missing/unreachable entry is silently ignored.
        host::forget_keyring_on_overwrite(&cfg, &name, &OsKeyring);
        let mut replaced = cfg.clone();
        if let Some(slot) = replaced.hosts.iter_mut().find(|h| h.name == name) {
            *slot = new_host;
        } else {
            replaced.hosts.push(new_host);
        }
        replaced
    } else {
        match host::add_host(
            &cfg,
            host_id,
            &name,
            &new_host.host,
            new_host.port,
            new_host.auth.clone(),
        ) {
            Ok(next) => next,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    };

    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("added host '{name}'");
    exit_code::SUCCESS
}

// ===========================================================================
// ls
// ===========================================================================

fn ls(cli: &Cli, fields_spec: Option<&str>, sort: Option<crate::cli::SortMode>) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    if cfg.hosts.is_empty() {
        println!("no hosts yet — add one with: sshrack host add <name>");
        return exit_code::SUCCESS;
    }

    let selected = match selected_fields(fields_spec, ALL_HOST_FIELDS) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Sort: rank/sort_hosts returns a Vec<&Host> borrowing cfg.hosts.
    let host_refs: Vec<&Host> = cfg.hosts.iter().collect();
    let ordered = sort_hosts(&host_refs, sort);

    match cli.format {
        OutputFormat::Json => {
            let mut rows = Vec::with_capacity(ordered.len());
            for h in &ordered {
                let cred_name = credential_name_for_host(&cfg, h);
                rows.push(fmt::host_list_row(h, cred_name));
            }
            print_json_array(&rows);
        }
        OutputFormat::Text => {
            print_text_table(&ordered, &selected, |field, h| cell(field, h, &cfg));
        }
    }
    exit_code::SUCCESS
}

// ===========================================================================
// show
// ===========================================================================

fn show(cli: &Cli, name: &str, reveal: bool, no_input: bool) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let Some(host) = cfg.find_host_by_name(name) else {
        let err = host::host_not_found(&cfg, name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    // Reverse-resolve the credential id → name for display.
    let cred_name = credential_name_for_host(&cfg, host);

    // --reveal: decrypt (vault mode ⇒ unlock first) and fetch (keyring mode).
    let revealed_pw = if reveal {
        match reveal_password(&cfg, host, no_input) {
            Ok(r) => r,
            Err(ret) => return ret,
        }
    } else {
        RevealedPassword::Masked
    };

    match cli.format {
        OutputFormat::Json => {
            // Serialize the row (with the reveal password attached when --reveal)
            // through serde so the password is correctly JSON-escaped. Never
            // hand-splice: a password with `"`, `\`, or control chars must
            // round-trip as valid JSON.
            let id_str = host.id.to_string();
            let row = fmt::host_detail_row(host, &id_str, cred_name, revealed_pw.json_password());
            let json = serde_json::to_string(&row).unwrap_or_else(|e| {
                eprintln!("sshrack: json error: {e}");
                String::from("{}")
            });
            println!("{json}");
        }
        OutputFormat::Text => {
            print!("{}", format_detail(&cfg, host, cred_name, &revealed_pw));
        }
    }
    exit_code::SUCCESS
}

// ===========================================================================
// edit
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn edit(
    cli: &Cli,
    name: Option<&str>,
    host_addr: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&std::path::Path>,
    rename: Option<&str>,
    credential: Option<&str>,
    clear_identity: bool,
    clear_password: bool,
    clear_credential: bool,
    no_input: bool,
) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Pick the name (interactive menu when omitted and not --no-input).
    let name = match pick_existing_host(&cfg, name, no_input) {
        Ok(a) => a,
        Err(ret) => return ret,
    };

    let Some(orig) = cfg.find_host_by_name(&name).cloned() else {
        let err = host::host_not_found(&cfg, &name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    // Validate rename target before any field work.
    if let Some(new) = rename {
        if let Err(e) = host::validate_rename(&cfg, &name, new) {
            return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
        }
    }

    let has_any_flag = host_addr.is_some()
        || port.is_some()
        || user.is_some()
        || identity.is_some()
        || rename.is_some()
        || credential.is_some()
        || clear_identity
        || clear_password
        || clear_credential;

    // Resolve `--credential <name>` → Ulid (fail-fast).
    let cred_ulid = match resolve_credential_name(&cfg, credential) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let updated = if !has_any_flag && !no_input {
        // Full interactive prompt path (no flags given): re-collect host/port
        // and auth with the current values pre-filled, then re-seal.
        let new_host_addr = match prompt_string_with_default("Remote hostname or IP", &orig.host) {
            Ok(s) => s,
            Err(ret) => return ret,
        };
        let new_port = match prompt_port(orig.port) {
            Ok(p) => p,
            Err(ret) => return ret,
        };
        let new_auth = match prompt_auth_menu(&cfg, Some(&orig.auth)) {
            Ok(a) => a,
            Err(ret) => return ret,
        };
        // Stamp the original id (kept on the host) and the original name; a
        // rename in the full-prompt path is a separate edit.
        let mut rebuilt =
            host::finalize_body(orig.id, &orig.name, &new_host_addr, new_port, new_auth);
        match prompt_auth_and_seal(&mut cfg, &mut rebuilt.auth, OwnerKind::Host, &orig.id) {
            Ok(()) => {}
            Err(ret) => return ret,
        }
        rebuilt
    } else if !has_any_flag && no_input {
        // --no-input with no flags: nothing to do.
        println!("no changes");
        return exit_code::SUCCESS;
    } else {
        // PATCH path: only flagged fields change (the hard rule).
        let opts = host::EditOptions {
            host: host_addr.map(Into::into),
            port,
            credential: cred_ulid,
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            rename: rename.map(Into::into),
            clear_identity,
            clear_password,
            clear_credential,
        };
        match host::apply_patch(&orig, &opts) {
            Ok(h) => h,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    };

    // Replace in place by id (orig may have been renamed).
    let mut next = cfg.clone();
    if let Some(slot) = next.hosts.iter_mut().find(|h| h.id == orig.id) {
        *slot = updated;
    }
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    let final_name = next
        .hosts
        .iter()
        .find(|h| h.id == orig.id)
        .map(|h| h.name.as_str())
        .unwrap_or(&name);
    if rename.is_some() && final_name != name {
        println!("renamed '{name}' -> '{final_name}'");
    }
    println!("edited host '{final_name}'");
    exit_code::SUCCESS
}

// ===========================================================================
// rm
// ===========================================================================

fn rm(cli: &Cli, name: Option<&str>, yes: bool, no_input: bool) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let name = match pick_existing_host(&cfg, name, no_input) {
        Ok(a) => a,
        Err(ret) => return ret,
    };

    // Confirm unless --yes. Under --no-input without --yes, fail-closed.
    if !yes {
        let confirmed = match confirm_destructive(no_input, &format!("Remove host '{name}'?")) {
            Ok(c) => c,
            Err(ret) => return ret,
        };
        if !confirmed {
            println!("aborted");
            return exit_code::SUCCESS;
        }
    }

    let backend = OsKeyring;
    let next = match host::delete_host_with_secret(&cfg, &name, &backend) {
        Ok(n) => n,
        Err(e) => {
            return fail(&format!("sshrack: {e}"), map_not_found_or_validation(&e));
        }
    };
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("removed host '{name}'");
    exit_code::SUCCESS
}

// ===========================================================================
// cp
// ===========================================================================

fn cp(cli: &Cli, src: Option<&str>, dst: Option<&str>, no_input: bool) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let (src_name, dst_name) = match (src, dst) {
        (Some(s), Some(d)) => (s.to_owned(), d.to_owned()),
        (None, None) => {
            if cfg.hosts.is_empty() {
                println!("no hosts to copy — add one with: sshrack host add <name>");
                return exit_code::SUCCESS;
            }
            if no_input {
                return fail(
                    "sshrack: host cp needs <src> <dst> in --no-input mode",
                    exit_code::USAGE,
                );
            }
            let s = match pick_host_menu(&cfg) {
                Ok(a) => a,
                Err(ret) => return ret,
            };
            let d = match prompt_fresh_name(&cfg, "New name", true) {
                Ok(a) => a,
                Err(ret) => return ret,
            };
            (s, d)
        }
        // Exactly one positional is ambiguous.
        _ => {
            return fail(
                "sshrack: host cp needs both <src> and <dst> (or no args for interactive mode)",
                exit_code::USAGE,
            );
        }
    };

    // Validate dst + look up src before any write.
    if let Err(e) = host::validate_dst(&cfg, &dst_name) {
        return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
    }
    let Some(src_host) = cfg.find_host_by_name(&src_name).cloned() else {
        let err = host::host_not_found(&cfg, &src_name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    let dst_id = new_id();
    let cloned = host::clone_host_as(&src_host, dst_id, &dst_name);

    // Best-effort copy the keyring entry so the copy connects immediately.
    let backend = OsKeyring;
    if let Err(e) = host::copy_keyring_entry(&src_host, &cloned, &backend) {
        eprintln!(
            "warning: could not stage keyring password for '{}': {e}",
            dst_name
        );
    }

    cfg.hosts.push(cloned);
    if let Err((msg, code)) = save_config(&path, &cfg) {
        return fail(&msg, code);
    }
    println!("copied host '{src_name}' -> '{dst_name}'");
    exit_code::SUCCESS
}

// ===========================================================================
// shared prompt + display helpers (host-specific)
// ===========================================================================

/// Every column `host ls` can show, in default order. The `auth` column label
/// is `cred:<name>` for a reference (reverse-resolved), else the secret kind.
const ALL_HOST_FIELDS: &[&str] = &["name", "host", "user", "port", "auth"];

/// Resolve a fresh name (for `add`). Interactive when not `--no-input`:
/// re-prompts until it passes the forbidden-char and duplicate checks.
fn resolve_name(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    name: Option<&str>,
    force: bool,
    no_input: bool,
    kind: &str,
) -> Result<String, i32> {
    if let Some(a) = name {
        return Ok(a.to_owned());
    }
    if no_input {
        return Err(fail(
            &format!(
                "sshrack: missing required field: {kind} name (required in --no-input mode; omit --no-input for interactive entry)"
            ),
            exit_code::VALIDATION,
        ));
    }
    prompt_fresh_name(cfg, "New host name", force)
}

/// Prompt for a fresh name, re-prompting on a collision or forbidden char.
fn prompt_fresh_name(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    prompt: &str,
    force: bool,
) -> Result<String, i32> {
    loop {
        let s = match prompt_string(prompt) {
            Ok(s) => s,
            ret @ Err(_) => return ret,
        };
        match host::validate_name_chars(&s) {
            Ok(()) => match host::validate_no_duplicate(cfg, &s, force) {
                Ok(()) => return Ok(s),
                Err(e) => eprintln!("sshrack: {e}"),
            },
            Err(e) => eprintln!("sshrack: {e}"),
        }
    }
}

/// Pick an existing host by name. Interactive menu when `name` is `None`
/// and not `--no-input`; error when `None` and `--no-input`.
fn pick_existing_host(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    name: Option<&str>,
    no_input: bool,
) -> Result<String, i32> {
    if let Some(a) = name {
        return Ok(a.to_owned());
    }
    if cfg.hosts.is_empty() {
        println!("no hosts yet — add one with: sshrack host add <name>");
        return Err(exit_code::SUCCESS);
    }
    if no_input {
        return Err(fail(
            "sshrack: host name required in --no-input mode",
            exit_code::USAGE,
        ));
    }
    pick_host_menu(cfg)
}

/// Interactive host picker (FuzzySelect over names).
fn pick_host_menu(cfg: &sshrack_core::config::schema::SshrackConfig) -> Result<String, i32> {
    let theme = ColorfulTheme::default();
    let items: Vec<&str> = cfg.hosts.iter().map(|h| h.name.as_str()).collect();
    let idx = FuzzySelect::with_theme(&theme)
        .with_prompt("Select host")
        .items(&items)
        .default(0)
        .report(false)
        .interact()
        .map_err(|e| prompt_fail(&SshrackError::from_prompt_io(e)));
    let idx = match idx {
        Ok(i) => i,
        Err(code) => return Err(code),
    };
    Ok(items[idx].to_owned())
}

/// The AUTH column label for a host: `cred:<name>` for a reference (reverse-
/// resolved from the id), else the secret-kind label (`key`/`password`/...).
fn cell(field: &str, h: &Host, cfg: &sshrack_core::config::schema::SshrackConfig) -> String {
    match field {
        "name" => h.name.clone(),
        "host" => h.host.clone(),
        "user" => derive_user(&h.auth, cfg),
        "port" => h.port.to_string(),
        "auth" => derive_auth_label(&h.auth, cfg),
        _ => String::new(),
    }
}

/// The user a host authenticates as. Inline body's user; for a credential
/// reference, the referenced credential's user (`?` for a dangling ref so the
/// table never errors).
fn derive_user(auth: &Auth, cfg: &sshrack_core::config::schema::SshrackConfig) -> String {
    match auth {
        Auth::Inline(body) => body.user.clone(),
        Auth::Ref { credential } => cfg
            .find_credential_by_id(credential)
            .map(|c| c.body.user.clone())
            .unwrap_or_else(|| "?".into()),
    }
}

/// The AUTH column label: `cred:<name>` for a reference, else the secret kind.
fn derive_auth_label(auth: &Auth, cfg: &sshrack_core::config::schema::SshrackConfig) -> String {
    match auth {
        Auth::Ref { credential } => match cfg.find_credential_by_id(credential) {
            Some(c) => format!("cred:{}", c.name),
            None => "cred:?".into(),
        },
        Auth::Inline(body) => fmt::secret_kind_label(&body.secret_kind()).into(),
    }
}

/// Reverse-resolve a host's credential reference id to its name (for JSON
/// output). `None` for inline auth or a dangling reference.
fn credential_name_for_host<'a>(
    cfg: &'a sshrack_core::config::schema::SshrackConfig,
    host: &Host,
) -> Option<&'a str> {
    match &host.auth {
        Auth::Ref { credential } => cfg
            .find_credential_by_id(credential)
            .map(|c| c.name.as_str()),
        _ => None,
    }
}

/// What the password line of `host show` should render.
#[derive(Debug, Clone)]
enum RevealedPassword {
    /// Masked (non-reveal). Rendered as `(hidden)` for inline, `(stored in keyring)` for keyring.
    Masked,
    /// Reveal succeeded; the decrypted plaintext (wiped on drop).
    Plaintext(Zeroizing<String>),
    /// Reveal was requested but the keyring entry is missing / backend down.
    KeyringMissing,
    /// No password to show (key-only / default body).
    None,
}

impl RevealedPassword {
    /// The value to attach as the JSON `password` field on the reveal row, or
    /// `None` to omit it (non-reveal paths). Returned as a `Cow` so the row
    /// builder can borrow the plaintext without copying. serde owns the
    /// escaping — this is never hand-spliced into the JSON.
    fn json_password(&self) -> Option<Cow<'_, str>> {
        match self {
            RevealedPassword::Plaintext(p) => Some(Cow::Borrowed(p.as_str())),
            RevealedPassword::Masked => None,
            RevealedPassword::KeyringMissing => Some(Cow::Borrowed("(not in keyring)")),
            RevealedPassword::None => None,
        }
    }

    /// The text-mode password line (without leading "password: ").
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

/// Resolve the revealed password for a host: decrypt inline/vault, fetch
/// keyring. Inline with no secret → None. Best-effort on keyring misses.
fn reveal_password(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    host: &Host,
    no_input: bool,
) -> Result<RevealedPassword, i32> {
    // Unlock the vault if needed (vault mode). Non-vault configs need no key.
    let vault_key = match unlock_vault_key(cfg, no_input) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    let resolved = match cred_core::resolve(host, cfg, vault_key.as_ref()) {
        Ok(r) => r,
        Err(e) => return Err(fail(&format!("sshrack: {e}"), exit_code::STORE)),
    };
    Ok(match resolved.password {
        PasswordSource::None => RevealedPassword::None,
        PasswordSource::Inline(p) => RevealedPassword::Plaintext(p),
        PasswordSource::Keyring { key } => match sshrack_core::secret::keyring::get(&key) {
            Ok(Some(p)) => RevealedPassword::Plaintext(p),
            Ok(None) | Err(_) => RevealedPassword::KeyringMissing,
        },
    })
}

/// Render a single host's fields as text (pure). `reveal` decides the password
/// line. For a credential reference the body is resolved through `cfg` so the
/// referenced credential's user/key/password are shown; a dangling reference
/// surfaces `(dangling reference)`.
fn format_detail(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    host: &Host,
    cred_name: Option<&str>,
    reveal: &RevealedPassword,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("name:     {}\n", host.name));
    out.push_str(&format!("id:       {}\n", host.id));
    out.push_str(&format!("host:     {}\n", host.host));
    out.push_str(&format!("port:     {}\n", host.port));
    match &host.auth {
        Auth::Ref { credential } => match cfg.find_credential_by_id(credential) {
            Some(c) => {
                out.push_str(&format!("auth:     credential '{}'\n", c.name));
                render_body_lines(&c.body, reveal, &mut out);
            }
            None => {
                out.push_str(&format!(
                    "auth:     credential '{}'\n",
                    cred_name_or_id(cred_name, credential)
                ));
                out.push_str("user:     (dangling reference)\n");
            }
        },
        Auth::Inline(body) => {
            render_body_lines(body, reveal, &mut out);
        }
    }
    out
}

/// Render user + secret lines for an inline body.
fn render_body_lines(body: &CredentialBody, reveal: &RevealedPassword, out: &mut String) {
    out.push_str(&format!("user:     {}\n", body.user));
    match (&body.key, body.password.is_some(), body.keyring) {
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
}

fn cred_name_or_id<'a>(name: Option<&'a str>, id: &Ulid) -> Cow<'a, str> {
    match name {
        Some(a) => Cow::Borrowed(a),
        None => Cow::Owned(id.to_string()),
    }
}

// ---- interactive auth prompt + seal (shared shape, host-specific owner) ----

/// Prompt for the auth method and collect any inline password, then seal it
/// per the active storage mode. Mutates `auth` in place. The owner id is used
/// for keyring keying.
fn prompt_auth_and_seal(
    cfg: &mut sshrack_core::config::schema::SshrackConfig,
    auth: &mut Auth,
    owner: OwnerKind,
    owner_id: &Ulid,
) -> Result<(), i32> {
    let chosen = match prompt_auth_menu(cfg, Some(&*auth)) {
        Ok(a) => a,
        Err(ret) => return Err(ret),
    };
    // If the user chose an inline password, collect it and seal.
    let sealed = match seal_auth_with_password(cfg, chosen, owner, owner_id) {
        Ok(a) => a,
        Err(ret) => return Err(ret),
    };
    *auth = sealed;
    Ok(())
}

/// Prompt for the auth method. `current` pre-selects the menu when given.
fn prompt_auth_menu(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    current: Option<&Auth>,
) -> Result<Auth, i32> {
    use sshrack_core::config::schema::AuthChoice;
    let theme = ColorfulTheme::default();
    let items = [
        "Reuse a credential",
        "Inline password",
        "Inline identity key",
        "Default (ssh agent / no secret)",
    ];
    let default_idx = match current {
        Some(Auth::Ref { .. }) => 0,
        Some(Auth::Inline(b)) => match b.secret_kind() {
            sshrack_core::config::schema::SecretKind::Password => 1,
            sshrack_core::config::schema::SecretKind::Key => 2,
            _ => 3,
        },
        None => 3,
    };
    let idx = match FuzzySelect::with_theme(&theme)
        .with_prompt("Auth method")
        .items(items)
        .default(default_idx)
        .report(false)
        .interact()
    {
        Ok(i) => i,
        Err(e) => return Err(prompt_fail(&SshrackError::from_prompt_io(e))),
    };
    let choice = match idx {
        0 => AuthChoice::Credential {
            name: String::new(),
        },
        1 => AuthChoice::InlinePassword,
        2 => AuthChoice::InlineKey,
        _ => AuthChoice::Default,
    };
    auth_from_choice(cfg, choice)
}

/// Turn an [`AuthChoice`] into an [`Auth`], prompting for sub-fields. For the
/// credential choice the user picks a credential name (resolved to id by the
/// caller before persisting).
fn auth_from_choice(
    cfg: &sshrack_core::config::schema::SshrackConfig,
    choice: sshrack_core::config::schema::AuthChoice,
) -> Result<Auth, i32> {
    use sshrack_core::config::schema::AuthChoice;
    match choice {
        AuthChoice::Credential { .. } => {
            if cfg.credentials.is_empty() {
                eprintln!("sshrack: no credentials configured; add one with `sshrack cred add`");
                return Err(exit_code::USAGE);
            }
            let theme = ColorfulTheme::default();
            let items: Vec<&str> = cfg.credentials.iter().map(|c| c.name.as_str()).collect();
            let idx = match FuzzySelect::with_theme(&theme)
                .with_prompt("Credential")
                .items(&items)
                .default(0)
                .report(false)
                .interact()
            {
                Ok(i) => i,
                Err(e) => return Err(prompt_fail(&SshrackError::from_prompt_io(e))),
            };
            let cred = &cfg.credentials[idx];
            Ok(Auth::reference(cred.id))
        }
        AuthChoice::InlinePassword => {
            let user = match prompt_string_with_default("Login user", "root") {
                Ok(s) => s,
                Err(ret) => return Err(ret),
            };
            let pw = match prompt_password("Password") {
                Ok(p) => p,
                Err(ret) => return Err(ret),
            };
            Ok(Auth::inline(CredentialBody::new(user).with_password(pw)))
        }
        AuthChoice::InlineKey => {
            let user = match prompt_string_with_default("Login user", "root") {
                Ok(s) => s,
                Err(ret) => return Err(ret),
            };
            let key = match prompt_string("Identity key path") {
                Ok(s) => s,
                Err(ret) => return Err(ret),
            };
            Ok(Auth::inline(
                CredentialBody::new(user).with_key(std::path::PathBuf::from(key)),
            ))
        }
        AuthChoice::Default => {
            let user = match prompt_string_with_default("Login user", "root") {
                Ok(s) => s,
                Err(ret) => return Err(ret),
            };
            Ok(Auth::inline(CredentialBody::new(user)))
        }
    }
}

/// Seal a freshly-collected auth (with an inline plaintext password if any) per
/// the active storage mode. Resolves first-use mode if undecided, and unlocks
/// the vault when vault mode is active.
fn seal_auth_with_password(
    cfg: &mut sshrack_core::config::schema::SshrackConfig,
    auth: Auth,
    owner: OwnerKind,
    owner_id: &Ulid,
) -> Result<Auth, i32> {
    // Only inline bodies with a plaintext password need sealing.
    let needs_seal = matches!(
        &auth,
        Auth::Inline(b) if matches!(b.password, Some(sshrack_core::config::schema::Secret::Plain(_)))
    );
    if !needs_seal {
        return Ok(auth);
    }
    let backend = OsKeyring;
    if let Err((msg, code)) = ensure_storage_mode_decided(cfg, false, &backend) {
        return Err(fail(&msg, code));
    }
    let vault_key = match unlock_vault_key(cfg, false) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    match vault::seal_auth(auth, owner, owner_id, cfg, vault_key.as_ref(), &backend) {
        Ok(a) => Ok(a),
        Err(e) => Err(fail(&format!("sshrack: {e}"), exit_code::STORE)),
    }
}

// ---- generic prompt helpers: re-exported from `shared` ----
//
// prompt_string / prompt_string_with_default / prompt_port / prompt_password /
// confirm / prompt_fail / selected_fields / print_json_array / print_text_table
// all live in [`super::shared`] so `host` and `cred` share one implementation.
// The `use super::shared::*`-style imports at the top of this file bring them
// into scope as `shared::prompt_string` etc.

// ---- error→exit-code helpers ----

/// Map a not-found vs other validation error to its exit code.
fn map_not_found_or_validation(e: &SshrackError) -> i32 {
    match e {
        SshrackError::HostNotFound { .. } | SshrackError::CredentialNotFound { .. } => {
            exit_code::NOT_FOUND
        }
        _ => exit_code::VALIDATION,
    }
}
