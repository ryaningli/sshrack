//! `sshrack host …` handlers: add / ls / show / edit / rm / cp.
//!
//! Scriptable CRUD surface. Each handler maps a [`HostAction`] to core pure
//! functions (`host::{add_host, apply_patch, finalize_body, …}`) and persists
//! via [`config::store::save`]. Missing required fields error; there are no
//! field prompts. `--format json|text` selects the output shape.
//!
//! Ref-by-id invariant: `--credential <name>` is resolved to a [`Ulid`] here
//! before any core call (fail-fast on an unknown name). `ls`/`show` reverse-
//! resolve the stored `Ulid` back to the credential name for display — the
//! on-disk form is always the id.
//!
//! Nothing here prints a password in an error message. `show --reveal` is the
//! only path that materializes a plaintext, and it goes to stdout.

use std::borrow::Cow;

use ulid::Ulid;
use zeroize::Zeroizing;

use sshrack_core::config::schema::{Auth, CredentialBody, Host};
use sshrack_core::credential::{self as cred_core, PasswordSource};
use sshrack_core::error::SshrackError;
use sshrack_core::host;
use sshrack_core::id::new_id;
use sshrack_core::secret::OsKeyring;
use sshrack_core::secret::SecretBackend;

use crate::cli::args::{Cli, HostAction, OutputFormat};
use crate::shared::exit_code;
use crate::shared::format as fmt;

use super::shared::{
    fail, load_config, print_json_array, resolve_credential_name, save_config, seal_inline_body,
    selected_fields, sort_hosts, unlock_vault_key,
};
use crate::cli::table::print_text_table;

/// Dispatch for the `Host` arm of the CLI.
pub fn run(cli: &Cli, action: &HostAction) -> i32 {
    match action {
        HostAction::Add {
            name,
            host,
            user,
            port,
            identity,
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            credential,
            force,
        } => add(
            cli,
            name.as_deref(),
            host.as_deref(),
            user.as_deref(),
            *port,
            identity.as_deref(),
            *identity_stdin,
            identity_file.as_deref(),
            *certificate_stdin,
            certificate_file.as_deref(),
            credential.as_deref(),
            *force,
        ),
        HostAction::Ls { fields, sort } => ls(cli, fields.as_deref(), *sort),
        HostAction::Show { name, reveal } => show(cli, name, *reveal),
        HostAction::Edit {
            name,
            host,
            user,
            port,
            identity,
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            rename,
            credential,
            clear_identity,
            clear_password,
            clear_credential,
        } => edit(
            cli,
            name.as_deref(),
            host.as_deref(),
            user.as_deref(),
            *port,
            identity.as_deref(),
            *identity_stdin,
            identity_file.as_deref(),
            *certificate_stdin,
            certificate_file.as_deref(),
            rename.as_deref(),
            credential.as_deref(),
            *clear_identity,
            *clear_password,
            *clear_credential,
        ),
        HostAction::Rm { name, yes } => rm(cli, name.as_deref(), *yes),
        HostAction::Cp { src, dst } => cp(cli, src.as_deref(), dst.as_deref()),
    }
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
    identity_stdin: bool,
    identity_file: Option<&std::path::Path>,
    certificate_stdin: bool,
    certificate_file: Option<&std::path::Path>,
    credential: Option<&str>,
    force: bool,
) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Validate the name up front (forbidden chars) and the duplicate check
    // before any field work — fail-fast on local errors.
    let name = match require_name(name, "host") {
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

    // Required `host` field is enforced here (no flag ⇒ error).
    let host_addr_owned = match host_addr {
        Some(h) => h.to_owned(),
        None => {
            return fail(
                "sshrack: missing required field: host (pass --host)",
                exit_code::VALIDATION,
            );
        }
    };

    // Identity source resolution (Independent branch only). --identity <path>
    // stays a path reference via the existing AddOptions.identity field; the
    // inline import flags (--identity-stdin / --identity-file) read the key
    // CONTENTS into the body via with_inline_key so the file can be deleted
    // afterward. Key text never enters argv. Mutually exclusive with
    // --credential (clap-enforced route: --credential is Reference, the inline
    // import flags are Independent-only).
    let inline_key = if identity_stdin || identity_file.is_some() {
        match super::shared::resolve_inline_identity(
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            &mut std::io::stdin(),
        ) {
            Ok(Some(ik)) => Some(ik),
            Ok(None) => unreachable!("inline source guarded above"),
            Err(e) => return fail(&format!("sshrack: {e:#}"), exit_code::VALIDATION),
        }
    } else {
        None
    };

    let host_id = new_id();
    let new_host = if let Some(ik) = inline_key {
        // Independent-Inline branch: build the body directly via
        // with_inline_key (AddOptions.identity is path-only). The default user
        // mirrors build_auth: --user when given, "root" otherwise.
        let user_owned = user.map(str::to_owned).unwrap_or_else(|| "root".into());
        let private_sec = ik
            .private_key
            .expect("invariant: resolve_inline_identity sets private_key on the inline branch");
        let body = CredentialBody::new(user_owned).with_inline_key(private_sec, ik.certificate);
        // Seal the freshly collected plaintext key/cert per the active store
        // mode (vault encrypts under SSHRACK_PASSPHRASE; plaintext stores
        // verbatim) before persisting. Keyed by the host's stable id so a
        // future inline-keyring path would land in the right account.
        let sealed_body =
            match seal_inline_body(body, sshrack_core::id::OwnerKind::Host, &host_id, &cfg) {
                Ok(b) => b,
                Err((msg, code)) => return fail(&msg, code),
            };
        sshrack_core::config::schema::Host {
            id: host_id,
            name: name.clone(),
            host: host_addr_owned.clone(),
            port: port.unwrap_or(22),
            auth: Auth::inline(sealed_body),
        }
    } else {
        let opts = host::AddOptions {
            host: Some(host_addr_owned.clone()),
            port,
            credential: cred_ulid,
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            force,
        };
        match host::merge_fields(host_id, &name, &opts) {
            Ok(h) => h,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    };
    // No password is collected here — passwords never enter argv. A password
    // host must be created via the TUI (where the inline password can be
    // sealed into the active storage mode).

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

fn ls(cli: &Cli, fields_spec: Option<&str>, sort: Option<crate::cli::args::SortMode>) -> i32 {
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

fn show(cli: &Cli, name: &str, reveal: bool) -> i32 {
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
        match reveal_password(&cfg, host) {
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
    identity_stdin: bool,
    identity_file: Option<&std::path::Path>,
    certificate_stdin: bool,
    certificate_file: Option<&std::path::Path>,
    rename: Option<&str>,
    credential: Option<&str>,
    clear_identity: bool,
    clear_password: bool,
    clear_credential: bool,
) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let name = match require_name(name, "host") {
        Ok(a) => a,
        Err(ret) => return ret,
    };
    let Some(orig) = cfg.find_host_by_name(&name).cloned() else {
        let err = host::host_not_found(&cfg, &name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    // Validate rename target before any field work.
    if let Some(new) = rename
        && let Err(e) = host::validate_rename(&cfg, &name, new)
    {
        return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
    }

    let has_any_flag = host_addr.is_some()
        || port.is_some()
        || user.is_some()
        || identity.is_some()
        || identity_stdin
        || identity_file.is_some()
        || certificate_stdin
        || certificate_file.is_some()
        || rename.is_some()
        || credential.is_some()
        || clear_identity
        || clear_password
        || clear_credential;

    if !has_any_flag {
        // Patch-only: nothing to do.
        println!("no changes");
        return exit_code::SUCCESS;
    }

    // Resolve `--credential <name>` → Ulid (fail-fast).
    let cred_ulid = match resolve_credential_name(&cfg, credential) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // PATCH path: only flagged fields change (the hard rule).
    //
    // The inline-key import flags (--identity-stdin / --identity-file) read key
    // CONTENTS into the body — they bypass apply_patch (which is path-only)
    // and rebuild the inline body directly. Only valid under Independent auth
    // (a Reference host switches its auth via --credential / --clear-credential,
    // never via identity flags). Key text never enters argv.
    let updated = if identity_stdin || identity_file.is_some() {
        let user_owned = match &orig.auth {
            Auth::Inline(body) => user.map(str::to_owned).unwrap_or_else(|| body.user.clone()),
            _ => user.map(str::to_owned).unwrap_or_else(|| "root".into()),
        };
        let inline_key = match super::shared::resolve_inline_identity(
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            &mut std::io::stdin(),
        ) {
            Ok(Some(ik)) => ik,
            Ok(None) => unreachable!("inline source guarded above"),
            Err(e) => return fail(&format!("sshrack: {e:#}"), exit_code::VALIDATION),
        };
        let private_sec = inline_key
            .private_key
            .expect("invariant: resolve_inline_identity sets private_key on the inline branch");
        let body =
            CredentialBody::new(user_owned).with_inline_key(private_sec, inline_key.certificate);
        // Seal the freshly collected plaintext key/cert per the active store
        // mode (vault encrypts under SSHRACK_PASSPHRASE; plaintext stores
        // verbatim) before persisting. The host id is stable across edits.
        let sealed_body =
            match seal_inline_body(body, sshrack_core::id::OwnerKind::Host, &orig.id, &cfg) {
                Ok(b) => b,
                Err((msg, code)) => return fail(&msg, code),
            };
        let mut h = orig.clone();
        h.auth = Auth::inline(sealed_body);
        if let Some(new_name) = rename {
            h.name = new_name.to_owned();
        }
        if let Some(new_host) = host_addr {
            h.host = new_host.to_owned();
        }
        if let Some(new_port) = port {
            h.port = new_port;
        }
        h
    } else {
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

fn rm(cli: &Cli, name: Option<&str>, yes: bool) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let name = match require_name(name, "host") {
        Ok(a) => a,
        Err(ret) => return ret,
    };

    // Destructive confirmation: --yes skips the prompt (script escape hatch);
    // otherwise confirm on a tty, or error without one.
    let confirmed = yes || crate::cli::prompt::tty_confirm(&format!("Remove host '{name}'?"));
    if !confirmed {
        return fail(
            &format!(
                "sshrack: not removing host '{name}' (pass --yes, or run in a tty to confirm)"
            ),
            exit_code::USAGE,
        );
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

fn cp(cli: &Cli, src: Option<&str>, dst: Option<&str>) -> i32 {
    let (path, mut cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let (src_name, dst_name) = match (src, dst) {
        (Some(s), Some(d)) => (s.to_owned(), d.to_owned()),
        // Exactly one or zero positionals: error (both are required now).
        _ => {
            return fail(
                "sshrack: host cp needs both <src> and <dst>",
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
// shared helpers (host-specific)
// ===========================================================================

/// Every column `host ls` can show, in default order. The `auth` column label
/// is `cred:<name>` for a reference (reverse-resolved), else the secret kind.
const ALL_HOST_FIELDS: &[&str] = &["name", "host", "user", "port", "auth"];

/// Require a positional `<name>`. Errors `USAGE` when absent — the interactive
/// name picker lives in the TUI.
fn require_name(name: Option<&str>, kind: &str) -> Result<String, i32> {
    match name {
        Some(a) => Ok(a.to_owned()),
        None => Err(fail(
            &format!("sshrack: missing required field: {kind} name"),
            exit_code::USAGE,
        )),
    }
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
) -> Result<RevealedPassword, i32> {
    // Unlock the vault if needed (vault mode). Non-vault configs need no key.
    let vault_key = match unlock_vault_key(cfg) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    let backend = sshrack_core::secret::OsKeyring;
    let resolved = match cred_core::resolve(host, cfg, vault_key.as_ref(), &backend) {
        Ok(r) => r,
        Err(e) => return Err(fail(&format!("sshrack: {e}"), exit_code::STORE)),
    };
    Ok(match resolved.password {
        PasswordSource::None => RevealedPassword::None,
        PasswordSource::Inline(p) => RevealedPassword::Plaintext(p),
        // Plaintext mode: the password already lives at 0600 in the config, so
        // read it straight back (the connect path's config channel reuses the
        // same reader). host_id is the routing label; the password comes from
        // the host being shown. None (e.g. key-only) surfaces as no password.
        PasswordSource::Config { .. } => match cred_core::plaintext_password(host, cfg) {
            Some(p) => RevealedPassword::Plaintext(p),
            None => RevealedPassword::None,
        },
        PasswordSource::Keyring { key } => match backend.get(&key) {
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
        (Some(k), _, _) => out.push_str(&format!("key:      {}\n", fmt::identity_display(k))),
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

#[cfg(test)]
mod tests {
    //! Unit tests for the private pure helpers that drive `host ls`/`show`/`rm`
    //! output and exit codes: cell rendering, dangling-reference fallbacks,
    //! body-line rendering across all four secret arms, and error-to-exit-code
    //! mapping. Pure: feeds fixtures, asserts strings/codes.
    use super::*;
    use sshrack_core::config::schema::{Credential, SshrackConfig};
    use sshrack_core::error::DidYouMean;

    // ---- fixtures ----

    /// An inline-password host (user "deploy", secret kind "password").
    fn inline_pw_host() -> Host {
        Host {
            id: Ulid::new(),
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            auth: Auth::Inline(CredentialBody::new("deploy").with_password("hunter2")),
        }
    }

    /// A config holding one credential named "team-dev" (key auth, user
    /// "deploy"). Returns the config plus the credential's id for building
    /// `Auth::reference`.
    fn cfg_with_cred() -> (SshrackConfig, Ulid) {
        let cred_id = Ulid::new();
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: cred_id,
                name: "team-dev".into(),
                body: CredentialBody::new("deploy").with_key("/home/u/.ssh/team_ed25519"),
            }],
            ..Default::default()
        };
        (cfg, cred_id)
    }

    // ---- require_name ----

    #[test]
    fn require_name_some_returns_owned_name() {
        assert_eq!(require_name(Some("web1"), "host").as_deref(), Ok("web1"));
    }

    #[test]
    fn require_name_none_returns_usage_exit_code() {
        // None prints to stderr via `fail` and returns USAGE.
        assert_eq!(require_name(None, "host"), Err(exit_code::USAGE));
    }

    // ---- cell ----

    #[test]
    fn cell_renders_each_field_for_inline_host() {
        let h = inline_pw_host();
        let cfg = SshrackConfig::default();
        assert_eq!(cell("name", &h, &cfg), "web1");
        assert_eq!(cell("host", &h, &cfg), "10.0.0.5");
        assert_eq!(cell("user", &h, &cfg), "deploy");
        assert_eq!(cell("port", &h, &cfg), "2222");
        assert_eq!(cell("auth", &h, &cfg), "password");
    }

    #[test]
    fn cell_renders_resolved_credential_user_and_auth_label() {
        let (cfg, cred_id) = cfg_with_cred();
        let h = Host {
            id: Ulid::new(),
            name: "db1".into(),
            host: "db.internal".into(),
            port: 22,
            auth: Auth::reference(cred_id),
        };
        assert_eq!(cell("user", &h, &cfg), "deploy");
        assert_eq!(cell("auth", &h, &cfg), "cred:team-dev");
    }

    #[test]
    fn cell_unknown_field_returns_empty_string() {
        let h = inline_pw_host();
        let cfg = SshrackConfig::default();
        assert_eq!(cell("bogus", &h, &cfg), "");
    }

    // ---- derive_user ----

    #[test]
    fn derive_user_inline_returns_body_user() {
        let auth = Auth::Inline(CredentialBody::new("ops"));
        assert_eq!(derive_user(&auth, &SshrackConfig::default()), "ops");
    }

    #[test]
    fn derive_user_resolved_ref_returns_credential_user() {
        let (cfg, cred_id) = cfg_with_cred();
        let auth = Auth::reference(cred_id);
        assert_eq!(derive_user(&auth, &cfg), "deploy");
    }

    #[test]
    fn derive_user_dangling_ref_returns_question_mark() {
        // A credential id not present in cfg must never panic — it surfaces
        // "?" so the ls table stays renderable.
        let cfg = SshrackConfig::default();
        let auth = Auth::reference(Ulid::new());
        assert_eq!(derive_user(&auth, &cfg), "?");
    }

    // ---- derive_auth_label ----

    #[test]
    fn derive_auth_label_resolved_ref_shows_cred_prefix_and_name() {
        let (cfg, cred_id) = cfg_with_cred();
        let auth = Auth::reference(cred_id);
        assert_eq!(derive_auth_label(&auth, &cfg), "cred:team-dev");
    }

    #[test]
    fn derive_auth_label_dangling_ref_shows_cred_question() {
        let cfg = SshrackConfig::default();
        let auth = Auth::reference(Ulid::new());
        assert_eq!(derive_auth_label(&auth, &cfg), "cred:?");
    }

    #[test]
    fn derive_auth_label_inline_secret_kinds() {
        let cfg = SshrackConfig::default();
        // password
        let pw = Auth::Inline(CredentialBody::new("u").with_password("p"));
        assert_eq!(derive_auth_label(&pw, &cfg), "password");
        // key (path)
        let key = Auth::Inline(CredentialBody::new("u").with_key("/k"));
        assert_eq!(derive_auth_label(&key, &cfg), "key");
        // keyring marker
        let keyring = Auth::Inline(CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        });
        assert_eq!(derive_auth_label(&keyring, &cfg), "keyring");
        // default (no secret)
        let default = Auth::Inline(CredentialBody::new("u"));
        assert_eq!(derive_auth_label(&default, &cfg), "default");
    }

    // ---- credential_name_for_host ----

    #[test]
    fn credential_name_for_host_resolved_ref_returns_name() {
        let (cfg, cred_id) = cfg_with_cred();
        let host = Host {
            id: Ulid::new(),
            name: "db1".into(),
            host: "db".into(),
            port: 22,
            auth: Auth::reference(cred_id),
        };
        assert_eq!(credential_name_for_host(&cfg, &host), Some("team-dev"));
    }

    #[test]
    fn credential_name_for_host_dangling_ref_returns_none() {
        let cfg = SshrackConfig::default();
        let host = Host {
            id: Ulid::new(),
            name: "orphan".into(),
            host: "db".into(),
            port: 22,
            auth: Auth::reference(Ulid::new()),
        };
        assert_eq!(credential_name_for_host(&cfg, &host), None);
    }

    #[test]
    fn credential_name_for_host_inline_returns_none() {
        let cfg = SshrackConfig::default();
        let host = inline_pw_host();
        assert_eq!(credential_name_for_host(&cfg, &host), None);
    }

    // ---- format_detail ----

    #[test]
    fn format_detail_resolved_ref_shows_credential_name_and_body() {
        let (cfg, cred_id) = cfg_with_cred();
        let host = Host {
            id: Ulid::new(),
            name: "db1".into(),
            host: "db.internal".into(),
            port: 22,
            auth: Auth::reference(cred_id),
        };
        let out = format_detail(&cfg, &host, Some("team-dev"), &RevealedPassword::Masked);
        assert!(
            out.contains("auth:     credential 'team-dev'"),
            "got: {out}"
        );
        assert!(out.contains("user:     deploy"), "got: {out}");
        assert!(
            out.contains("key:      /home/u/.ssh/team_ed25519"),
            "got: {out}"
        );
        assert!(
            !out.contains("dangling reference"),
            "resolved ref must not say dangling: {out}"
        );
    }

    #[test]
    fn format_detail_dangling_ref_shows_dangling_marker_and_ulid() {
        let dangling_id = Ulid::new();
        let cfg = SshrackConfig::default();
        let host = Host {
            id: Ulid::new(),
            name: "orphan".into(),
            host: "h".into(),
            port: 22,
            auth: Auth::reference(dangling_id),
        };
        // cred_name None → the ulid string is used in the auth line.
        let out = format_detail(&cfg, &host, None, &RevealedPassword::Masked);
        assert!(
            out.contains("user:     (dangling reference)"),
            "expected dangling marker, got: {out}"
        );
        assert!(
            out.contains(&dangling_id.to_string()),
            "expected the ulid in the auth line, got: {out}"
        );
    }

    #[test]
    fn format_detail_inline_shows_user_and_masked_password() {
        let cfg = SshrackConfig::default();
        let host = inline_pw_host();
        let out = format_detail(&cfg, &host, None, &RevealedPassword::Masked);
        assert!(out.contains("name:     web1"), "got: {out}");
        assert!(out.contains("user:     deploy"), "got: {out}");
        assert!(out.contains("password: (hidden)"), "got: {out}");
    }

    // ---- render_body_lines ----

    #[test]
    fn render_body_lines_key_only_emits_key_line_no_password() {
        let body = CredentialBody::new("ops").with_key("/home/u/.ssh/id_ed25519");
        let mut out = String::new();
        render_body_lines(&body, &RevealedPassword::Masked, &mut out);
        assert!(out.contains("user:     ops"), "got: {out}");
        assert!(
            out.contains("key:      /home/u/.ssh/id_ed25519"),
            "got: {out}"
        );
        // No password line for a key-only body.
        assert!(!out.contains("password:"), "got: {out}");
    }

    #[test]
    fn render_body_lines_keyring_marker_masked_emits_stored_in_keyring() {
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        let mut out = String::new();
        render_body_lines(&body, &RevealedPassword::Masked, &mut out);
        assert!(out.contains("password: (stored in keyring)"), "got: {out}");
    }

    #[test]
    fn render_body_lines_keyring_marker_revealed_emits_plaintext() {
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        let mut out = String::new();
        render_body_lines(
            &body,
            &RevealedPassword::Plaintext(Zeroizing::new("s3cret".into())),
            &mut out,
        );
        assert!(out.contains("password: s3cret"), "got: {out}");
    }

    #[test]
    fn render_body_lines_password_masked_emits_hidden_and_never_plaintext() {
        let body = CredentialBody::new("u").with_password("hunter2");
        let mut out = String::new();
        render_body_lines(&body, &RevealedPassword::Masked, &mut out);
        assert!(out.contains("password: (hidden)"), "got: {out}");
        // The actual password must never appear under Masked.
        assert!(!out.contains("hunter2"), "got: {out}");
    }

    #[test]
    fn render_body_lines_default_keys_emits_default_marker() {
        let body = CredentialBody::new("ec2-user");
        let mut out = String::new();
        render_body_lines(&body, &RevealedPassword::Masked, &mut out);
        assert!(out.contains("user:     ec2-user"), "got: {out}");
        assert!(out.contains("auth:     default keys"), "got: {out}");
        // No password line for a default body.
        assert!(!out.contains("password:"), "got: {out}");
    }

    #[test]
    fn render_body_lines_password_with_revealed_none_emits_no_password_line() {
        // A password body with RevealedPassword::None (no password to show)
        // must not emit a password line at all.
        let body = CredentialBody::new("u").with_password("ignored");
        let mut out = String::new();
        render_body_lines(&body, &RevealedPassword::None, &mut out);
        assert!(out.contains("user:     u"), "got: {out}");
        assert!(!out.contains("password:"), "got: {out}");
    }

    // ---- map_not_found_or_validation ----

    #[test]
    fn map_not_found_or_validation_host_not_found_maps_to_not_found() {
        let e = SshrackError::HostNotFound {
            name: "ghost".into(),
            hint: DidYouMean::none(),
        };
        assert_eq!(map_not_found_or_validation(&e), exit_code::NOT_FOUND);
    }

    #[test]
    fn map_not_found_or_validation_credential_not_found_maps_to_not_found() {
        let e = SshrackError::CredentialNotFound {
            name: "ghost".into(),
            hint: DidYouMean::none(),
        };
        assert_eq!(map_not_found_or_validation(&e), exit_code::NOT_FOUND);
    }

    #[test]
    fn map_not_found_or_validation_other_error_maps_to_validation() {
        let e = SshrackError::HostAlreadyExists { name: "x".into() };
        assert_eq!(map_not_found_or_validation(&e), exit_code::VALIDATION);
    }

    // ---- cred_name_or_id ----

    #[test]
    fn cred_name_or_id_some_returns_borrowed_name() {
        let id = Ulid::new();
        let cow = cred_name_or_id(Some("team-dev"), &id);
        assert_eq!(cow, "team-dev");
        assert!(matches!(cow, Cow::Borrowed(_)));
    }

    #[test]
    fn cred_name_or_id_none_returns_owned_ulid_string() {
        let id = Ulid::new();
        let cow = cred_name_or_id(None, &id);
        assert_eq!(cow, id.to_string());
        assert!(matches!(cow, Cow::Owned(_)));
    }
}
