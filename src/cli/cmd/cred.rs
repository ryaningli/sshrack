//! `sshrack cred …` handlers: add / ls / show / edit / rm.
//!
//! Non-interactive surface, same shape as [`super::host`] but for reusable
//! `[[credentials]]` entries. `--credential` is N/A (a credential cannot
//! reference another credential); the body is built from `--user`/`--identity`.
//! A password credential cannot be created from the CLI (passwords never enter
//! argv) — use the TUI for that.
//!
//! `rm` warns before removing when [`credential::find_referrers`] is non-empty
//! — references are by id, so removing the credential leaves dangling refs.
//! The referrer host names are listed (reverse-resolved from the ids).

use std::borrow::Cow;

use zeroize::Zeroizing;

use sshrack_core::config::schema::{Auth, Credential, CredentialBody};
use sshrack_core::credential as cred_core;
use sshrack_core::host;
use sshrack_core::id::new_id;

use crate::cli::args::{Cli, CredAction, OutputFormat};
use crate::shared::exit_code;
use crate::shared::format as fmt;

use super::shared::{
    fail, load_config, print_json_array, save_config, selected_fields, unlock_vault_key,
};
use crate::cli::table::print_text_table;

/// Dispatch for the `Cred` arm of the CLI.
pub fn run(cli: &Cli, action: &CredAction) -> i32 {
    match action {
        CredAction::Add {
            name,
            user,
            identity,
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            force,
        } => add(
            cli,
            name.as_deref(),
            user.as_deref(),
            identity.as_deref(),
            *identity_stdin,
            identity_file.as_deref(),
            *certificate_stdin,
            certificate_file.as_deref(),
            *force,
        ),
        CredAction::Ls { fields } => ls(cli, fields.as_deref()),
        CredAction::Show { name, reveal } => show(cli, name, *reveal),
        CredAction::Edit {
            name,
            user,
            identity,
            identity_stdin,
            identity_file,
            certificate_stdin,
            certificate_file,
            clear_identity,
            rename,
        } => edit(
            cli,
            name.as_deref(),
            user.as_deref(),
            identity.as_deref(),
            *identity_stdin,
            identity_file.as_deref(),
            *certificate_stdin,
            certificate_file.as_deref(),
            *clear_identity,
            rename.as_deref(),
        ),
        CredAction::Rm { name, yes } => rm(cli, name.as_deref(), *yes),
    }
}

/// Every column `cred ls` can show, in default order.
const ALL_CRED_FIELDS: &[&str] = &["name", "user", "secret"];

// ===========================================================================
// add
// ===========================================================================

#[allow(clippy::too_many_arguments)]
fn add(
    cli: &Cli,
    name: Option<&str>,
    user: Option<&str>,
    identity: Option<&std::path::Path>,
    identity_stdin: bool,
    identity_file: Option<&std::path::Path>,
    certificate_stdin: bool,
    certificate_file: Option<&std::path::Path>,
    force: bool,
) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    // Resolve + validate the name before any field work.
    let name = match require_name(name, "credential") {
        Ok(a) => a,
        Err(ret) => return ret,
    };
    if let Err(e) = host::validate_name_chars(&name) {
        return fail(&format!("sshrack: {e}"), exit_code::VALIDATION);
    }
    if let Err(e) = cred_core::validate_no_duplicate_credential(&cfg, &name, force) {
        return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
    }

    let cred_id = new_id();

    // Build the body from flags. `user` is required; a password cannot come
    // from a flag.
    //
    // Identity source resolution: --identity <path> stays a path reference
    // (KeySource::Path) via the existing AddOptions.identity field. The inline
    // import flags (--identity-stdin / --identity-file) read the key CONTENTS
    // into the body via with_inline_key so the file can be deleted afterward.
    // Key text never enters argv — only paths and the boolean stdin flag do.
    let body = if identity_stdin || identity_file.is_some() {
        let user_owned = match user {
            Some(u) => u.to_string(),
            None => {
                return fail(
                    "sshrack: missing required field: user (pass --user)",
                    exit_code::VALIDATION,
                );
            }
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
        CredentialBody::new(user_owned).with_inline_key(private_sec, inline_key.certificate)
    } else {
        let opts = cred_core::AddOptions {
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            force,
        };
        match cred_core::build_body(&opts) {
            Ok(b) => b,
            Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
        }
    };

    let next = match cred_core::add_credential(&cfg, cred_id, &name, body) {
        Ok(n) => n,
        Err(e) => return fail(&format!("sshrack: {e}"), exit_code::VALIDATION),
    };
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("added credential '{name}'");
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
        println!("no credentials yet — add one with: sshrack cred add <name>");
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
                .map(|c| fmt::credential_list_row(c, None))
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

fn show(cli: &Cli, name: &str, reveal: bool) -> i32 {
    let (_path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let Some(cred) = cfg.find_credential_by_name(name) else {
        let err = cred_core::credential_not_found(&cfg, name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    let revealed_pw = if reveal {
        match reveal_password(&cfg, cred) {
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
            let row = fmt::credential_list_row(cred, revealed_pw.json_password());
            let json = serde_json::to_string(&row).unwrap_or_else(|e| {
                eprintln!("sshrack: json error: {e}");
                String::from("{}")
            });
            println!("{json}");
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

#[allow(clippy::too_many_arguments)]
fn edit(
    cli: &Cli,
    name: Option<&str>,
    user: Option<&str>,
    identity: Option<&std::path::Path>,
    identity_stdin: bool,
    identity_file: Option<&std::path::Path>,
    certificate_stdin: bool,
    certificate_file: Option<&std::path::Path>,
    clear_identity: bool,
    rename: Option<&str>,
) -> i32 {
    let (path, cfg) = match load_config(cli.config.as_deref()) {
        Ok(v) => v,
        Err((msg, code)) => return fail(&msg, code),
    };

    let name = match require_name(name, "credential") {
        Ok(a) => a,
        Err(ret) => return ret,
    };
    let Some(orig) = cfg.find_credential_by_name(&name).cloned() else {
        let err = cred_core::credential_not_found(&cfg, &name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };

    if let Some(new) = rename {
        if let Err(e) = cred_core::validate_rename_credential(&cfg, &name, new) {
            return fail(&format!("sshrack: {e}"), exit_code::DUPLICATE);
        }
    }

    let has_any_flag = user.is_some()
        || identity.is_some()
        || identity_stdin
        || identity_file.is_some()
        || certificate_stdin
        || certificate_file.is_some()
        || clear_identity
        || rename.is_some();
    if !has_any_flag {
        // Patch-only: nothing to do.
        println!("no changes");
        return exit_code::SUCCESS;
    }

    // PATCH path: only flagged fields change.
    //
    // The inline-key import flags (--identity-stdin / --identity-file) read key
    // CONTENTS into the body — they bypass apply_credential_patch (which is
    // path-only) and rebuild the body inline. Key text never enters argv.
    let updated = if identity_stdin || identity_file.is_some() {
        let user_owned = user
            .map(str::to_owned)
            .unwrap_or_else(|| orig.body.user.clone());
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
        let final_name = rename
            .map(str::to_owned)
            .unwrap_or_else(|| orig.name.clone());
        sshrack_core::config::schema::Credential {
            id: orig.id,
            name: final_name,
            body,
        }
    } else {
        let opts = cred_core::EditOptions {
            user: user.map(Into::into),
            identity: identity.map(std::path::PathBuf::from),
            clear_identity,
            rename: rename.map(Into::into),
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
    let final_name = next
        .credentials
        .iter()
        .find(|c| c.id == orig.id)
        .map(|c| c.name.as_str())
        .unwrap_or(&name);
    if rename.is_some() && final_name != name {
        println!("renamed '{name}' -> '{final_name}'");
    }
    println!("edited credential '{final_name}'");
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

    let name = match require_name(name, "credential") {
        Ok(a) => a,
        Err(ret) => return ret,
    };

    // Look up the credential to get its id for referrer lookup.
    let Some(cred) = cfg.find_credential_by_name(&name) else {
        let err = cred_core::credential_not_found(&cfg, &name);
        return fail(&format!("sshrack: {err}"), exit_code::NOT_FOUND);
    };
    let cred_id = cred.id;

    // Warn + list referrers (host names, reverse-resolved from the ids).
    let referrer_names: Vec<String> = cred_core::find_referrers(&cfg, &cred_id)
        .iter()
        .filter_map(|hid| cfg.find_host_by_id(hid).map(|h| h.name.clone()))
        .collect();

    // Require an explicit --yes (destructive confirmation). No interactive
    // fallback — the TUI handles unattended-less flows. The referrer warning
    // still prints so the user sees what would be affected.
    if !yes {
        if !referrer_names.is_empty() {
            println!(
                "warning: credential '{name}' is referenced by host(s): {}",
                referrer_names.join(", ")
            );
        }
        return fail(
            &format!("sshrack: pass --yes to confirm removal of credential '{name}'"),
            exit_code::USAGE,
        );
    } else if !referrer_names.is_empty() {
        // Even with --yes, surface the dangling refs so the user knows.
        eprintln!(
            "warning: credential '{name}' was referenced by host(s): {} (references are now dangling)",
            referrer_names.join(", ")
        );
    }

    let backend = sshrack_core::secret::OsKeyring;
    let next = match cred_core::delete_credential_with_secret(&cfg, &name, &backend) {
        Ok(n) => n,
        Err(e) => return fail(&format!("sshrack: {e}"), exit_code::NOT_FOUND),
    };
    if let Err((msg, code)) = save_config(&path, &next) {
        return fail(&msg, code);
    }
    println!("removed credential '{name}'");
    exit_code::SUCCESS
}

// ===========================================================================
// helpers (credential-specific)
// ===========================================================================

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

/// The value of one column for one credential (pure).
fn cell(field: &str, c: &Credential) -> String {
    match field {
        "name" => c.name.clone(),
        "user" => c.body.user.clone(),
        "secret" => fmt::secret_kind_label(&c.body.secret_kind()).into(),
        _ => String::new(),
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
    /// The value to attach as the JSON `password` field on the reveal row, or
    /// `None` to omit it (non-reveal paths). Returned as a `Cow` so the row
    /// builder can borrow the plaintext without copying. serde owns the
    /// escaping — this is never hand-spliced into the JSON.
    fn json_password(&self) -> Option<Cow<'_, str>> {
        match self {
            RevealedPassword::Plaintext(p) => Some(Cow::Borrowed(p.as_str())),
            RevealedPassword::KeyringMissing => Some(Cow::Borrowed("(not in keyring)")),
            RevealedPassword::Masked | RevealedPassword::None => None,
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
) -> Result<RevealedPassword, i32> {
    let vault_key = match unlock_vault_key(cfg) {
        Ok(k) => k,
        Err((msg, code)) => return Err(fail(&msg, code)),
    };
    // Reuse credential::resolve via a synthetic host that references this
    // credential by id — resolve returns PasswordSource keyed off the cred id.
    let host_shell = sshrack_core::config::schema::Host {
        id: new_id(),
        name: cred.name.clone(),
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
    out.push_str(&format!("name:     {}\n", cred.name));
    out.push_str(&format!("id:       {}\n", cred.id));
    out.push_str(&format!("user:     {}\n", cred.body.user));
    match (
        &cred.body.key,
        cred.body.password.is_some(),
        cred.body.keyring,
    ) {
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
    out
}
