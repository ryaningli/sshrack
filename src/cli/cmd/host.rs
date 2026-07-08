//! `sshrack host …` handlers: add / ls / show / edit / rm / cp.
//!
//! Non-interactive surface. Each handler maps a [`HostAction`] to core pure
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

    // Require an explicit --yes (destructive confirmation). No interactive
    // fallback — the TUI handles unattended-less flows.
    if !yes {
        return fail(
            &format!("sshrack: pass --yes to confirm removal of host '{name}'"),
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
