//! Persistence side-effects for the TUI event loop.
//!
//! [`crate::tui::app::App::on_key`] is pure — it only mutates in-memory state and
//! returns an [`crate::tui::intent::Outcome`]. The loop calls the free functions
//! in this module to actually write to disk: add/edit/delete a host or
//! credential, switch the global storage mode, and reload the config + re-rank
//! the panels afterward. Each fn takes `&mut App` (and the `TerminalHandle`
//! where a popup may be needed) so it stays a leaf of the loop, not a method on
//! `App` — keeping `App` itself free of I/O.

use sshrack_core::config::schema::{Auth, Credential, SecretStore};
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
use sshrack_core::host;
use sshrack_core::id::OwnerKind;
use sshrack_core::secret::{OsKeyring, PassphraseProvider, SecretBackend, vault};

use ulid::Ulid;

use super::app::App;
use super::intent::Overlay;
use super::prompt::TuiPassphrase;
use super::term::TerminalHandle;

/// True if the body carries a freshly collected plaintext secret that must be
/// sealed per the store mode: a plaintext password, or an inline key with
/// plaintext private/cert text. Already-sealed ([`Secret::Encrypted`]) or
/// marker-only bodies (e.g. a keyring-marker inline key with no in-body text)
/// pass through unchanged — they have nothing to re-host.
///
/// This widens the TUI persist seal trigger so inline-key plaintext routes
/// through [`vault::seal_body`] under any decided mode, matching the CLI path
/// (which seals via `seal_inline_body`). Previously the trigger only fired on
/// `password == Plain`, so an inline-key body's plaintext was written to
/// `config.toml` verbatim even under vault/keyring mode.
///
/// [`Secret::Encrypted`]: sshrack_core::config::schema::Secret::Encrypted
fn body_has_plaintext_secret(body: &sshrack_core::config::schema::CredentialBody) -> bool {
    use sshrack_core::config::schema::{KeySource, Secret};
    if matches!(body.password, Some(Secret::Plain(_))) {
        return true;
    }
    matches!(
        &body.key,
        Some(KeySource::Inline(ik))
            if matches!(ik.private_key, Some(Secret::Plain(_)))
                || matches!(ik.certificate, Some(Secret::Plain(_)))
    )
}

/// Fulfill a [`Outcome::SaveHost`] intent: resolve the form to a [`Host`],
/// persist via core, reload, and update the app's config. Pure validation
/// already passed inside the wizard; this is the I/O half — duplicate-name /
/// config-write failures surface as [`SshrackError`] so the loop can show them
/// in the wizard's error line.
///
/// Add mode: `host::add_host` with a fresh id. Edit mode: `host::finalize_body`
/// preserving the original id (so a keyring entry keyed by that id is not
/// orphaned). For a [`Reference`][crate::tui::wizard::AuthChoice::Reference]
/// auth choice, the picked credential name is resolved to its stable [`Ulid`]
/// here (the wizard only ever holds the name). For an
/// [`Independent`][crate::tui::wizard::AuthChoice::Independent] auth choice
/// whose secret is a password OR an inline (pasted) identity key, the inline
/// plaintext is sealed per the configured store mode (keyring / vault /
/// plaintext) here — mirroring `persist_cred_save` — so the host owns its own
/// secret without a detour to the credential tab. The seal trigger is
/// [`body_has_plaintext_secret`]: any freshly collected in-body plaintext
/// (password or inline key text) routes through [`vault::seal_body`]; an
/// already-sealed body passes through unchanged.
///
/// Keyring lifecycle: an inline password is keyed by the host's ULID
/// (`OwnerKind::Host`); on edit the old entry is cleaned up, and on delete /
/// `host cp` / `host add --force` the same id-keyed cleanup runs.
pub(crate) fn persist_host_save(
    app: &mut App,
    handle: &TerminalHandle,
    backend: &dyn SecretBackend,
) -> Result<(), SshrackError> {
    // Take the form out of the overlay so we can borrow `app.config` for the
    // credential-name → id resolution without a borrow conflict. The form lives
    // inside `Overlay::HostWizard`; clone it out (the overlay keeps its copy so
    // an error-path set_core_error still reaches the user).
    let Some(Overlay::HostWizard(form)) = app.overlay.clone() else {
        return Ok(());
    };

    // Resolve credential name → id (only when the user picked Reference).
    let resolved_credential = match form.selected_credential_name() {
        Some(name) => Some(
            app.config
                .find_credential_by_name(name)
                .map(|c| c.id)
                .ok_or(SshrackError::CredentialNotFound {
                    name: name.to_string(),
                    hint: sshrack_core::error::DidYouMean::none(),
                })?,
        ),
        None => None,
    };

    let mut auth = form.build_auth(resolved_credential);
    let name = form.name.trim().to_string();
    let host_addr = form.host_addr.trim().to_string();
    let port = form.parsed_port();

    // The id that will own this host (and any keyring entry). Fresh for add,
    // original for edit (so the keyring entry is not orphaned).
    let target_id = if form.editing {
        form.orig_id.ok_or(SshrackError::MissingRequiredField {
            field: "orig_id (edit mode)",
        })?
    } else {
        Ulid::new()
    };

    // ── Preserve an existing inline password on edit when the field was left
    //    blank (mirror persist_cred_save's keep-existing-password branch). ────
    if form.editing
        && form.secret_kind == super::wizard::SecretChoice::Password
        && form.password.is_empty()
        && let Auth::Inline(body) = &auth
        && body.password.is_none()
    {
        let orig = app
            .config
            .find_host_by_id(&target_id)
            .ok_or(SshrackError::HostNotFound {
                name: target_id.to_string(),
                hint: sshrack_core::error::DidYouMean::none(),
            })?;
        if let Some(orig_body) = orig.auth.inline_body() {
            let mut kept = body.clone();
            kept.password = orig_body.password.clone();
            kept.keyring = orig_body.keyring;
            auth = Auth::inline(kept);
        }
    }

    // ── Seal any freshly collected plaintext secret per the configured store
    //    mode (mirror persist_cred_save). The trigger is
    //    [`body_has_plaintext_secret`]: a plaintext password OR an inline key
    //    with plaintext private/cert text. Already-sealed (Encrypted) or
    //    marker-only bodies pass through unchanged. Previously only the
    //    password was sealed, so an inline-key body's plaintext was written to
    //    config.toml verbatim even under vault/keyring mode — a divergence from
    //    the CLI path (which seals via `seal_inline_body`). A secret-carrying
    //    body with no store mode decided is a user-facing error, NOT a silent
    //    plaintext fallback. Vault unlock via TuiPassphrase (no-op unless vault
    //    mode); under SSHRACK_PASSPHRASE the env value shadows the popup.
    if let Some(body) = auth.inline_body()
        && body_has_plaintext_secret(body)
    {
        if app.config.store.is_none() {
            return Err(SshrackError::StoreModeNotDecided);
        }
        let passphrase_provider = TuiPassphrase::new(handle.clone());
        let env_pw = vault::passphrase_from_env();
        let vault_key =
            vault::ensure_unlocked_vault_key(&app.config, env_pw.as_ref(), &passphrase_provider)?;
        let sealed = vault::seal_body(
            body.clone(),
            OwnerKind::Host,
            &target_id,
            &app.config,
            vault_key.as_ref(),
            backend,
        )?;
        auth = Auth::inline(sealed);
    }

    let new_cfg = if form.editing {
        // Edit: preserve the original id (keyring-keyed). The form already holds
        // every field, so stamp the original id onto the freshly built host and
        // splice it in place of the original. A rename to another host's name
        // is rejected by validate_rename (excluding the current name).
        let orig = app
            .config
            .find_host_by_id(&target_id)
            .ok_or(SshrackError::HostNotFound {
                name: target_id.to_string(),
                hint: sshrack_core::error::DidYouMean::none(),
            })?;
        if orig.name != name {
            host::validate_rename(&app.config, &orig.name, &name)?;
        }
        let edited = host::finalize_body(
            target_id,
            &name,
            &host_addr,
            port,
            // The wizard has no ssh-args field yet (wired later); preserve the
            // original host's flags across an edit instead of wiping them.
            orig.ssh_args.clone(),
            auth,
        );
        let mut next = app.config.clone();
        if let Some(slot) = next.hosts.iter_mut().find(|h| h.id == target_id) {
            *slot = edited;
        }
        next
    } else {
        // Add: fresh id, append. host::add_host validates the name chars and
        // appends. The duplicate-name check is host::validate_no_duplicate; we
        // run it here so the error surfaces before the append (add_host itself
        // only checks forbidden chars).
        host::validate_no_duplicate(&app.config, &name, false)?;
        // The wizard has no ssh-args field yet (wired later); a fresh host
        // starts with no flags.
        host::add_host(&app.config, target_id, &name, &host_addr, port, None, auth)?
    };

    // Persist + reload (so the on-disk file is the source of truth and the
    // in-memory config round-trips through TOML).
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        // No path resolved (fresh install, no home dir): keep the new config in
        // memory only. The launcher will still show the host this session.
        app.set_config(new_cfg);
    }
    Ok(())
}

/// Fulfill a [`Outcome::DeleteHost`] intent (after the user confirmed the
/// popup): call [`host::delete_host_with_secret`] — which removes the host and
/// best-effort forgets its keyring entry when the host's inline body was
/// keyring-marked (so no orphaned secret is left behind) — then persist +
/// reload + re-rank the launcher. Mirrors the CLI's `host rm` sequence
/// (`cli::cmd::host::rm` → `host::delete_host_with_secret` → save). The
/// keyring backend is [`OsKeyring`] (the production backend); a down keyring
/// daemon is tolerated by `forget_keyring_secret` as a best-effort no-op.
///
/// `name` is the host's name at confirm time (the caller resolved id→name
/// before deleting). An absent host surfaces as [`SshrackError::HostNotFound`]
/// (defensive: the launcher only hands out ids from the loaded config, but a
/// concurrent edit could race — the error is clearer than a silent no-op).
pub(crate) fn persist_host_delete(app: &mut App, name: &str) -> Result<(), SshrackError> {
    let backend = OsKeyring;
    let new_cfg = host::delete_host_with_secret(&app.config, name, &backend)?;
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        app.set_config(new_cfg);
    }
    // Re-rank so the launcher reflects the (shorter) host list and the
    // selection clamps back into range. The credential panel is unaffected by a
    // host delete but re-running recompute is cheap and keeps both panels in
    // sync if a future change ties them together.
    app.recompute_panels();
    Ok(())
}

/// Fulfill a [`Outcome::DeleteCred`] intent (after the user confirmed the
/// popup): call [`credential::delete_credential_with_secret`] — which removes
/// the credential and best-effort forgets its keyring entry when the body was
/// keyring-marked (so no orphaned secret is left behind) — then persist +
/// reload + re-rank the credential panel. Mirrors the CLI's `cred rm` sequence.
///
/// `name` is the credential's name at confirm time (the caller captured it
/// before deleting). An absent credential surfaces as
/// [`SshrackError::CredentialNotFound`] (defensive: the panel only hands out
/// names from the loaded config, but a concurrent edit could race — the error
/// is clearer than a silent no-op).
///
/// [`credential::delete_credential_with_secret`]: sshrack_core::credential::delete_credential_with_secret
pub(crate) fn persist_cred_delete(app: &mut App, name: &str) -> Result<(), SshrackError> {
    let backend = OsKeyring;
    let new_cfg = credential::delete_credential_with_secret(&app.config, name, &backend)?;
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        app.set_config(new_cfg);
    }
    // Re-rank so the credential panel reflects the (shorter) list and the
    // selection clamps back into range. The host panel is re-ranked too so a
    // host whose auth referenced the deleted credential (now dangling) keeps a
    // coherent display label.
    app.recompute_panels();
    Ok(())
}

/// Fulfill a [`Outcome::SaveCred`] intent: build the credential body, seal any
/// password per the configured store mode via core
/// ([`sshrack_core::secret::vault::seal_body`]), add (fresh id) or splice in
/// place (preserving the original id — keyring-keyed), persist, reload. Pure
/// validation already passed inside the wizard; this is the I/O half.
///
/// **Store-mode-undecided guard.** When the user picked a Password but
/// `cfg.store` is `None` (no mode chosen yet), the wizard surfaces a clear
/// "run `sshrack store use <mode>` first" error instead of silently picking a
/// mode. Core's `seal_body` treats `None` as plaintext, which would store the
/// password in the clear without the user ever choosing that — the wizard
/// refuses to make that choice for them. Vault unlock happens here via
/// [`TuiPassphrase`] (mirroring [`connect_host`]); a popup cancel surfaces as
/// [`SshrackError::Interrupted`], which the loop maps to "stay in the wizard".
///
/// [`connect_host`]: super::connect::connect_host
pub(crate) fn persist_cred_save(
    app: &mut App,
    handle: &TerminalHandle,
    backend: &dyn SecretBackend,
) -> Result<(), SshrackError> {
    // Take the form out of the overlay so we can borrow app.config/launcher
    // without a conflict. The form lives inside `Overlay::CredWizard`; clone it
    // out (the overlay keeps its copy so an error-path set_core_error reaches
    // the user).
    let Some(Overlay::CredWizard(form)) = app.overlay.clone() else {
        return Ok(());
    };

    let name = form.name.trim().to_string();

    // ── Decide the id and the pre-seal body. ────────────────────────────────
    // Edit mode preserves the original id (the keyring entry + every host
    // Auth::Ref are keyed by it). When the edit leaves the password field
    // blank under the Password choice, keep the existing body's password so a
    // user editing only the user/name does not silently drop the password.
    let (id, mut body) = if form.editing {
        let orig_id = form.orig_id.ok_or(SshrackError::MissingRequiredField {
            field: "orig_id (cred edit mode)",
        })?;
        let orig = app
            .config
            .find_credential_by_id(&orig_id)
            .ok_or_else(|| credential::credential_not_found(&app.config, &orig_id.to_string()))?;
        let mut body = form.build_body();
        if form.secret_kind == super::wizard::SecretChoice::Password
            && form.password.is_empty()
            && body.password.is_none()
        {
            // Preserve the existing password: re-attach it as plaintext (it is
            // re-sealed below per the current store mode, so an encrypted body
            // round-trips through encrypt again cleanly).
            body.password = orig.body.password.clone();
        }
        if orig.name != name {
            credential::validate_rename_credential(&app.config, &orig.name, &name)?;
        }
        (orig_id, body)
    } else {
        // Add: fresh id. Duplicate-name check runs before the append.
        credential::validate_no_duplicate_credential(&app.config, &name, false)?;
        (Ulid::new(), form.build_body())
    };

    // ── Seal any freshly collected plaintext secret per the configured store
    //    mode. The trigger is [`body_has_plaintext_secret`]: a plaintext
    //    password OR an inline key with plaintext private/cert text. Only when
    //    there is a freshly collected plaintext secret to re-host (a path-key /
    //    none / already-sealed body passes through unchanged). And only when a
    //    store mode is decided; a secret-carrying body with no mode decided is a
    //    user-facing error, NOT a silent plaintext fallback. Previously only the
    //    password was sealed, so an inline-key body's plaintext diverged from
    //    the CLI path (which seals via `seal_inline_body`).
    if body_has_plaintext_secret(&body) {
        if app.config.store.is_none() {
            return Err(SshrackError::StoreModeNotDecided);
        }
        // Vault unlock (no-op unless vault mode). TuiPassphrase drives a masked
        // popup; under SSHRACK_PASSPHRASE the env value shadows it. A popup
        // cancel surfaces as Interrupted, which the loop maps to "stay in the
        // wizard" rather than an exit.
        let passphrase_provider = TuiPassphrase::new(handle.clone());
        let env_pw = vault::passphrase_from_env();
        let vault_key =
            vault::ensure_unlocked_vault_key(&app.config, env_pw.as_ref(), &passphrase_provider)?;
        body = vault::seal_body(
            body,
            OwnerKind::Credential,
            &id,
            &app.config,
            vault_key.as_ref(),
            backend,
        )?;
    }

    // ── Build the credential and splice / append. ───────────────────────────
    let credential = Credential {
        id,
        name: name.clone(),
        body,
    };
    let new_cfg = if form.editing {
        let mut next = app.config.clone();
        if let Some(slot) = next.credentials.iter_mut().find(|c| c.id == id) {
            *slot = credential;
        }
        next
    } else {
        // add_credential validates name chars + body and appends.
        credential::add_credential(&app.config, id, &name, credential.body)?
    };

    // Persist + reload (the on-disk file is the source of truth).
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        app.set_config(new_cfg);
    }
    Ok(())
}

/// Map the popup's selection onto the loop's switch target.
pub(crate) fn map_store_pick(pick: super::prompt::StorePick) -> StoreSwitchTarget {
    match pick {
        super::prompt::StorePick::Keyring => StoreSwitchTarget::Keyring,
        super::prompt::StorePick::Vault => StoreSwitchTarget::Vault,
        super::prompt::StorePick::Plaintext => StoreSwitchTarget::Plaintext,
    }
}

/// Recover from a `StoreModeNotDecided` save: drive the store-pick popup, run
/// the switch via [`persist_store_switch`], then retry the cred save. Returns
/// `Ok(true)` when the retry succeeded; `Ok(false)` when the user cancelled the
/// popup or the switch was refused (reason already in the wizard's core-error
/// line); `Err` propagates a real failure so [`fulfill_save_cred`] can surface
/// it. Called only from [`fulfill_save_cred`].
pub(crate) fn recover_store_mode_and_retry_cred_save(
    app: &mut App,
    handle: &TerminalHandle,
) -> Result<bool, SshrackError> {
    let pick = super::prompt::prompt_store_pick(handle)?;
    let Some(target) = pick.map(map_store_pick) else {
        // User cancelled the popup. Stay in the wizard with a clear reason.
        if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
            w.set_core_error("store selection cancelled".into());
        }
        return Ok(false);
    };
    match persist_store_switch(app, target, handle)? {
        true => {
            // Store mode switched + persisted; retry the save. Any error propagates
            // (fulfill_save_cred surfaces it in the wizard's core-error line).
            let backend = OsKeyring;
            persist_cred_save(app, handle, &backend).map(|_| true)
        }
        false => {
            // Switch refused (keyring daemon down, plaintext declined, ...).
            if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
                w.set_core_error(
                    "could not switch store mode (unavailable or declined); \
                     switch via the Settings tab"
                        .into(),
                );
            }
            Ok(false)
        }
    }
}

/// Handle an [`Outcome::SaveCred`] intent end-to-end: persist the cred, and on
/// `StoreModeNotDecided` recover in place via a store-pick popup + switch +
/// retry instead of erroring out of the wizard. All outcomes surface through
/// the wizard's core-error line or a launcher status + wizard close.
pub(crate) fn fulfill_save_cred(app: &mut App, handle: &TerminalHandle) {
    let backend = OsKeyring;
    match persist_cred_save(app, handle, &backend) {
        Ok(()) => {
            app.set_status("credential saved".to_string());
            app.close_cred_wizard();
        }
        Err(SshrackError::StoreModeNotDecided) => {
            match recover_store_mode_and_retry_cred_save(app, handle) {
                Ok(true) => {
                    app.set_status("credential saved".to_string());
                    app.close_cred_wizard();
                }
                Ok(false) => {} // cancelled or switch refused; reason already in core-error.
                Err(SshrackError::Interrupted) => {
                    if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
                        w.set_core_error("cancelled".into());
                    }
                }
                Err(e) => {
                    if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
                        w.set_core_error(e.to_string());
                    }
                }
            }
        }
        Err(SshrackError::Interrupted) => {
            if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
                w.set_core_error("vault unlock cancelled".into());
            }
        }
        Err(e) => {
            if let Some(Overlay::CredWizard(w)) = app.overlay.as_mut() {
                w.set_core_error(e.to_string());
            }
        }
    }
}

/// Which target mode a [`Outcome::SwitchToKeyring`]/[`Outcome::SwitchToVault`]/
/// [`Outcome::SwitchToPlaintext`] intent wants. Carried so the shared
/// [`persist_store_switch`] helper can dispatch on one enum rather than three
/// near-identical loop arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreSwitchTarget {
    Keyring,
    Vault,
    Plaintext,
}

/// Fulfill a store-mode switch intent. Mirrors `cli::cmd::store`'s three switch
/// arms but swaps the UI surface: vault's master passphrase comes from
/// [`TuiPassphrase::passphrase_confirm`] (masked double-entry popup) instead of
/// `SSHRACK_PASSPHRASE`; plaintext's `--yes` becomes a confirm popup; keyring's
/// availability probe surfaces in the store view's status line.
///
/// Returns `Ok(true)` when the switch succeeded + persisted (the loop closes
/// the view and surfaces a launcher status). Returns `Ok(false)` when the switch
/// was *refused* by the user or the environment (keyring daemon down, plaintext
/// declined) and the reason is already in the store view's status line — the
/// loop leaves the view open so the user can read it. Returns `Err` on a real
/// core/IO failure (vault unlock cancel surfaces as [`SshrackError::Interrupted`];
/// migrate/write errors propagate so the loop can show them).
pub(crate) fn persist_store_switch(
    app: &mut App,
    target: StoreSwitchTarget,
    handle: &TerminalHandle,
) -> Result<bool, SshrackError> {
    // No-op when already in the target mode — surface and stay.
    let already = match target {
        StoreSwitchTarget::Keyring => app.config.is_keyring(),
        StoreSwitchTarget::Vault => app.config.is_vault(),
        StoreSwitchTarget::Plaintext => app.config.is_plaintext(),
    };
    if already {
        set_store_status(app, format!("already in {} mode", target_label(target)));
        return Ok(false);
    }

    // Leaving keyring mode needs the keyring entries readable to migrate them.
    if app.config.is_keyring() && !OsKeyring.available() {
        set_store_status(
            app,
            "keyring unavailable; cannot read keyring entries to migrate".into(),
        );
        return Ok(false);
    }

    let provider = TuiPassphrase::new(handle.clone());
    let backend = OsKeyring;

    match target {
        StoreSwitchTarget::Keyring => {
            // Probe availability first — a migrate into a dead keyring would
            // drop plaintext on the floor.
            if !backend.available() {
                set_store_status(app, "OS keyring unavailable; cannot migrate".into());
                return Ok(false);
            }
            // Source vault key needed only when leaving vault mode.
            let source_key = if app.config.is_vault() {
                let env_pw = vault::passphrase_from_env();
                vault::ensure_unlocked_vault_key(&app.config, env_pw.as_ref(), &provider)?
            } else {
                None
            };
            vault::cache::clear_default_cache();
            let n = vault::transform::migrate(
                &mut app.config,
                &SecretStore::Keyring,
                source_key.as_ref(),
                None,
                &backend,
            )?;
            app.config.store = Some(SecretStore::Keyring);
            persist_and_reload(app)?;
            let _ = n;
            Ok(true)
        }
        StoreSwitchTarget::Vault => {
            // Masked double-entry popup for the new master passphrase. A cancel
            // surfaces as Interrupted (handled by the loop as "stay in view").
            let passphrase = provider.passphrase_confirm()?;
            vault::cache::clear_default_cache();
            // enable derives a fresh key, writes the verifier, migrates every
            // existing password into vault mode, and flips cfg.store.
            vault::enable(&mut app.config, &passphrase, None, &backend)?;
            persist_and_reload(app)?;
            Ok(true)
        }
        StoreSwitchTarget::Plaintext => {
            // Downgrade confirmation via a popup (mirrors the CLI's --yes).
            let text = "Switching to plaintext mode stores every password in the\n\
                clear in config.toml. Anyone who reads the file gets every\n\
                password. Continue?";
            if !provider.confirm(text)? {
                set_store_status(app, "plaintext switch declined".into());
                return Ok(false);
            }
            // Source vault key needed when leaving vault mode.
            let source_key = if app.config.is_vault() {
                let env_pw = vault::passphrase_from_env();
                vault::ensure_unlocked_vault_key(&app.config, env_pw.as_ref(), &provider)?
            } else {
                None
            };
            vault::cache::clear_default_cache();
            let _n = vault::transform::migrate(
                &mut app.config,
                &SecretStore::Plaintext,
                source_key.as_ref(),
                None,
                &backend,
            )?;
            app.config.store = Some(SecretStore::Plaintext);
            persist_and_reload(app)?;
            Ok(true)
        }
    }
}

/// Persist `app.config` to its on-disk path and reload it back through core's
/// store::load (so the in-memory config round-trips through TOML and the
/// credential-name lookup rebuilds). When no path is resolved (fresh install),
/// keep the new config in memory only.
pub(crate) fn persist_and_reload(app: &mut App) -> Result<(), SshrackError> {
    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &app.config)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    }
    Ok(())
}

/// Set the store view's status line (best-effort: the view may be gone on a
/// late error path). After a successful switch the loop closes the view, so a
/// status set here only matters on a refusal / transient error that keeps the
/// view open.
pub(crate) fn set_store_status(app: &mut App, msg: String) {
    if let Some(v) = app.store_view.as_mut() {
        v.status = Some(msg);
    }
}

/// The user-facing label for a [`StoreSwitchTarget`]. Used in status messages.
pub(crate) fn target_label(target: StoreSwitchTarget) -> &'static str {
    match target {
        StoreSwitchTarget::Keyring => "keyring",
        StoreSwitchTarget::Vault => "vault",
        StoreSwitchTarget::Plaintext => "plaintext",
    }
}

#[cfg(test)]
mod tests {
    //! Persistence-layer tests for the TUI loop's I/O functions. These call the
    //! moved fns directly (persist_host_save / persist_cred_save /
    //! persist_store_switch / fulfill_save_cred / the delete helpers) to pin the
    //! I/O half: build an App + wizard form, run the fn, assert on the reloaded
    //! on-disk config + panel re-rank. The on_key-driven equivalents stay in
    //! `app.rs`.

    use super::*;
    use crate::tui::test_support::{dead_handle, stdout_tui};
    use sshrack_core::config::schema::{
        Auth, Credential, CredentialBody, Host, SecretKind, SecretStore, SshrackConfig,
    };
    use sshrack_core::frecency::Frecency;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use zeroize::Zeroizing;

    #[test]
    fn persist_host_save_add_appends_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Start from an empty config persisted to disk (so the reload reads the
        // file the save wrote).
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        // Open the add wizard and fill the form. The form lives inside the
        // overlay now, so take/mutate/putback to set fields.
        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "web-prod".into();
        w.host_addr = "10.0.0.5".into();
        w.port = "2222".into();
        w.user = "deploy".into();
        app.overlay = Some(Overlay::HostWizard(w));

        persist_host_save(&mut app, &dead_handle(), &OsKeyring).expect("add save should succeed");

        // Wizard is NOT auto-closed by persist (the loop does that); but the
        // config has been reloaded with the new host.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        assert_eq!(reloaded.hosts[0].name, "web-prod");
        assert_eq!(reloaded.hosts[0].host, "10.0.0.5");
        assert_eq!(reloaded.hosts[0].port, 2222);
        assert_eq!(reloaded.hosts[0].auth.inline_body().unwrap().user, "deploy");
    }

    #[test]
    fn persist_host_save_edit_preserves_id_and_persists() {
        use ulid::Ulid;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: orig_id,
                name: "web".into(),
                host: "10.0.0.5".into(),
                port: 22,
                ssh_args: None,
                auth: Auth::inline(CredentialBody::new("ops")),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        // Open the edit wizard for that host and change the port + name.
        assert!(app.open_host_wizard_edit(orig_id));
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.port = "2200".into();
        w.name = "web-renamed".into();
        app.overlay = Some(Overlay::HostWizard(w));

        persist_host_save(&mut app, &dead_handle(), &OsKeyring).expect("edit save should succeed");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        let h = &reloaded.hosts[0];
        assert_eq!(h.id, orig_id, "edit must preserve the original id");
        assert_eq!(h.name, "web-renamed");
        assert_eq!(h.port, 2200);
    }

    #[test]
    fn persist_host_save_add_rejects_duplicate_name() {
        use ulid::Ulid;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web".into(),
                host: "h".into(),
                port: 22,
                ssh_args: None,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "web".into(); // duplicate
        w.host_addr = "h2".into();
        app.overlay = Some(Overlay::HostWizard(w));

        let err = persist_host_save(&mut app, &dead_handle(), &OsKeyring).unwrap_err();
        assert!(matches!(err, SshrackError::HostAlreadyExists { .. }));
        // The duplicate host was NOT written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
    }

    #[test]
    fn persist_host_save_credential_choice_resolves_name_to_id() {
        use ulid::Ulid;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cid = Ulid::new();
        let cfg = SshrackConfig {
            credentials: vec![sshrack_core::config::schema::Credential {
                id: cid,
                name: "ops-key".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add(); // seeds credential_names from config
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "web".into();
        w.host_addr = "10.0.0.5".into();
        w.auth_choice = super::super::wizard::AuthChoice::Reference { idx: 0 };
        app.overlay = Some(Overlay::HostWizard(w));

        persist_host_save(&mut app, &dead_handle(), &OsKeyring).unwrap();

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let h = &reloaded.hosts[0];
        assert_eq!(
            h.auth.credential_id(),
            Some(cid),
            "credential name must resolve to id"
        );
    }

    #[test]
    fn persist_host_save_credential_choice_unknown_name_errors() {
        // A dangling credential (name not in config) must surface as
        // CredentialNotFound, not silently fall back to inline default.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        // No credentials defined; force a Credential choice with idx 0 (which
        // names nothing). build_auth falls back to inline, but the loop's
        // selected_credential_name() returns None when the list is empty, so
        // this path actually skips the resolution. To exercise the unknown-name
        // branch, inject a credential name that does not exist.
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "web".into();
        w.host_addr = "10.0.0.5".into();
        w.credential_names = vec!["ghost".into()]; // not in config
        w.auth_choice = super::super::wizard::AuthChoice::Reference { idx: 0 };
        app.overlay = Some(Overlay::HostWizard(w));

        let err = persist_host_save(&mut app, &dead_handle(), &OsKeyring).unwrap_err();
        assert!(matches!(err, SshrackError::CredentialNotFound { .. }));
    }

    // ---- persist_host_save: Independent inline password seals per store mode ----
    // Mirrors the cred wizard's seal tests. The plaintext no-leak test (under
    // Keyring) pins the invariant: a host-own password must not live in the body
    // when the store mode is keyring. The keyring backend is not reliably
    // reachable in unit tests (needs a D-Bus / Secret Service daemon), so the
    // keyring test is #[ignore]'d — exercise it via the Task 3 manual smoke.

    #[test]
    fn persist_host_save_independent_password_seals_under_plaintext() {
        // Inline password under plaintext store: body carries Secret::Plain, no
        // keyring marker. The plaintext no-leak invariant for the OTHER modes is
        // pinned by the keyring test below; this test pins that plaintext truly
        // round-trips through seal_body for a host-own password.
        use super::super::wizard::{AuthChoice, SecretChoice};
        use sshrack_core::config::schema::Secret;
        use zeroize::Zeroizing;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "pw-host".into();
        w.host_addr = "10.0.0.1".into();
        w.auth_choice = AuthChoice::Independent;
        w.secret_kind = SecretChoice::Password;
        w.password = Zeroizing::new("hunter2".into());
        app.overlay = Some(Overlay::HostWizard(w));

        persist_host_save(&mut app, &dead_handle(), &OsKeyring).expect("seal + save succeeds");

        let saved = app.config.find_host_by_name("pw-host").expect("host saved");
        let body = saved.auth.inline_body().expect("inline body");
        assert_eq!(body.secret_kind(), SecretKind::Password);
        assert_eq!(
            body.password.as_ref().and_then(Secret::as_plain),
            Some("hunter2")
        );
        assert!(!body.keyring, "plaintext mode: no keyring marker");
    }

    #[test]
    #[ignore = "needs a reachable OS keyring backend; exercise via the Task 3 manual smoke"]
    fn persist_host_save_independent_password_seals_under_keyring() {
        // Keyring store: body keeps only the keyring marker; the password is NOT
        // in the body (it lives in the OS keyring, keyed by the host's ULID).
        // This is the no-leak invariant: a host-own password must not appear as
        // plaintext in config.toml under keyring mode.
        use super::super::wizard::{AuthChoice, SecretChoice};
        use sshrack_core::config::schema::SecretStore;
        use zeroize::Zeroizing;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "kr-host".into();
        w.host_addr = "10.0.0.1".into();
        w.auth_choice = AuthChoice::Independent;
        w.secret_kind = SecretChoice::Password;
        w.password = Zeroizing::new("hunter2".into());
        app.overlay = Some(Overlay::HostWizard(w));

        persist_host_save(&mut app, &dead_handle(), &OsKeyring).expect("seal + save succeeds");

        let saved = app.config.find_host_by_name("kr-host").expect("host saved");
        let body = saved.auth.inline_body().expect("inline body");
        assert!(
            body.keyring,
            "keyring mode: body must carry the keyring marker"
        );
        assert!(
            body.password.is_none(),
            "keyring mode: plaintext must NOT live in the body"
        );
    }

    // ===============================================================
    // Inline-key plaintext sealing under keyring mode (Task 8).
    //
    // The seal trigger was widened from "password == Plain" to
    // [`body_has_plaintext_secret`] so an inline-key body's private/cert text
    // also routes through `vault::seal_body`. Under keyring mode that stores
    // the text in the backend and leaves a marker body (`ik.keyring == true`,
    // no in-body text). The OS keyring is not reachable in CI, so these tests
    // inject a local in-memory `SecretBackend` impl (core's `FakeBackend` is
    // `pub(crate)` and invisible to the binary crate) and assert the slot
    // contents directly — the no-leak invariant the `#[ignore]`'d OS-keyring
    // test above cannot check.
    // ===============================================================

    /// In-memory `SecretBackend` for the persist tests. Mirrors core's
    /// `FakeBackend` (keyed by the raw account key) but lives in the binary
    /// test module so the persist fns can accept it via the injected
    /// `&dyn SecretBackend` parameter.
    struct FakeSecretBackend {
        entries: RefCell<HashMap<String, String>>,
    }

    impl FakeSecretBackend {
        fn new() -> Self {
            Self {
                entries: RefCell::new(HashMap::new()),
            }
        }
    }

    impl SecretBackend for FakeSecretBackend {
        fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError> {
            self.entries
                .borrow_mut()
                .insert(key.to_string(), secret.to_string());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
            Ok(self
                .entries
                .borrow()
                .get(key)
                .map(|p| Zeroizing::new(p.clone())))
        }
        fn delete_at(&self, key: &str) -> Result<(), SshrackError> {
            self.entries.borrow_mut().remove(key);
            Ok(())
        }
        fn available(&self) -> bool {
            true
        }
    }

    #[test]
    fn persist_host_save_inline_key_seals_under_keyring_into_backend() {
        // Keyring store + an inline (pasted) private key: the persist path must
        // route the plaintext through seal_body, which stores it in the
        // backend under the host's inline-private slot and leaves a marker body
        // (`ik.keyring == true`, no in-body text). This is the no-leak
        // invariant for inline key text under keyring mode — previously the
        // TUI never sealed inline keys, so the plaintext was written to
        // config.toml verbatim.
        use super::super::wizard::{AuthChoice, SecretChoice, SourceChoice};
        use sshrack_core::config::schema::{InlineKey, KeySource, SecretStore};
        use sshrack_core::id::{OwnerKind, keyring_key_inline_priv};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "ik-host".into();
        w.host_addr = "10.0.0.1".into();
        w.auth_choice = AuthChoice::Independent;
        w.secret_kind = SecretChoice::IdentityKey;
        w.source = SourceChoice::Inline;
        w.inline_private = "PRIVATEKEYTEXT".into();
        app.overlay = Some(Overlay::HostWizard(w));

        let backend = FakeSecretBackend::new();
        persist_host_save(&mut app, &dead_handle(), &backend).expect("seal + save succeeds");

        let saved = app.config.find_host_by_name("ik-host").expect("host saved");
        let body = saved.auth.inline_body().expect("inline body");
        // The body is now a keyring marker: ik.keyring == true and no in-body
        // private/cert text.
        let ik = match &body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline key after seal, got {other:?}"),
        };
        let expected = InlineKey {
            private_key: None,
            certificate: None,
            keyring: true,
        };
        assert_eq!(
            *ik, expected,
            "keyring mode: inline key must be a marker (no in-body text)"
        );
        assert!(
            ik.private_key.is_none(),
            "keyring mode: private key text must NOT live in the body"
        );
        // The plaintext lives in the backend under the host's inline-private
        // slot, keyed by the host's ULID.
        let host_id = saved.id;
        let slot = backend
            .get(&keyring_key_inline_priv(OwnerKind::Host, &host_id))
            .unwrap()
            .expect("private key text stored in the backend");
        assert_eq!(slot.as_str(), "PRIVATEKEYTEXT");
        assert!(
            body.password.is_none(),
            "no password on a key-carrying body"
        );
        // The plaintext never reached the on-disk config.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("PRIVATEKEYTEXT"),
            "private key text leaked into config.toml"
        );
    }

    #[test]
    fn persist_cred_save_inline_key_seals_under_keyring_into_backend() {
        // Mirror of the host test for the credential wizard: an inline private
        // key + certificate under keyring mode must seal both texts into the
        // backend (private + cert slots) and leave a marker body. Pins the
        // widening on the cred persist path too.
        use super::super::wizard::{SecretChoice, SourceChoice};
        use sshrack_core::config::schema::{InlineKey, KeySource, SecretStore};
        use sshrack_core::id::{OwnerKind, keyring_key_inline_cert, keyring_key_inline_priv};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Keyring),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ik-cred".into();
        w.user = "deploy".into();
        w.secret_kind = SecretChoice::IdentityKey;
        w.source = SourceChoice::Inline;
        w.inline_private = "PRIVATEKEYTEXT".into();
        w.inline_cert = "CERTTEXT".into();
        app.overlay = Some(Overlay::CredWizard(w));

        let backend = FakeSecretBackend::new();
        persist_cred_save(&mut app, &dead_handle(), &backend).expect("seal + save succeeds");

        let saved = app
            .config
            .find_credential_by_name("ik-cred")
            .expect("cred saved");
        let body = &saved.body;
        let ik = match &body.key {
            Some(KeySource::Inline(ik)) => ik,
            other => panic!("expected Inline key after seal, got {other:?}"),
        };
        let expected = InlineKey {
            private_key: None,
            certificate: None,
            keyring: true,
        };
        assert_eq!(
            *ik, expected,
            "keyring mode: inline key must be a marker (no in-body text)"
        );
        let cred_id = saved.id;
        let priv_slot = backend
            .get(&keyring_key_inline_priv(OwnerKind::Credential, &cred_id))
            .unwrap()
            .expect("private key text stored in the backend");
        assert_eq!(priv_slot.as_str(), "PRIVATEKEYTEXT");
        let cert_slot = backend
            .get(&keyring_key_inline_cert(OwnerKind::Credential, &cred_id))
            .unwrap()
            .expect("cert text stored in the backend");
        assert_eq!(cert_slot.as_str(), "CERTTEXT");
        // Neither plaintext reached the on-disk config.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(
            !on_disk.contains("PRIVATEKEYTEXT") && !on_disk.contains("CERTTEXT"),
            "key text leaked into config.toml"
        );
    }

    #[test]
    fn persist_host_save_inline_key_under_undecided_store_errors_not_silent_plaintext() {
        // An inline-key body with no store mode decided must surface
        // StoreModeNotDecided, NOT silently fall through to plaintext (which
        // core's seal would otherwise do). Mirrors the password undecided-mode
        // guard, widened to inline keys.
        use super::super::wizard::{AuthChoice, SecretChoice, SourceChoice};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_host_wizard_add();
        let Overlay::HostWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("host wizard open");
        };
        w.name = "ik-host".into();
        w.host_addr = "10.0.0.1".into();
        w.auth_choice = AuthChoice::Independent;
        w.secret_kind = SecretChoice::IdentityKey;
        w.source = SourceChoice::Inline;
        w.inline_private = "PRIVATEKEYTEXT".into();
        app.overlay = Some(Overlay::HostWizard(w));

        let backend = FakeSecretBackend::new();
        let err = persist_host_save(&mut app, &dead_handle(), &backend).unwrap_err();
        assert!(
            matches!(err, SshrackError::StoreModeNotDecided),
            "undecided store mode must error, not silently pick plaintext: {err}"
        );
        // Nothing was written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.hosts.is_empty());
    }

    // ===============================================================
    // Store mode view: persist_store_switch (I/O layer). The F2 entry +
    // Esc/cursor tests were removed when F2 was dropped as a binding (Task 6
    // conflict fix); these two open the view directly via open_store_view().
    // ===============================================================

    #[test]
    fn persist_store_switch_already_in_target_is_noop_status() {
        // Switching to plaintext when already plaintext sets a status and
        // returns Ok(false) — no migrate, no write.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());
        // Open the store view so set_store_status has somewhere to write.
        app.open_store_view();
        let result = persist_store_switch(&mut app, StoreSwitchTarget::Plaintext, &dead_handle());
        assert!(matches!(result, Ok(false)), "already-there is Ok(false)");
        assert!(
            app.store_view
                .as_ref()
                .and_then(|v| v.status.as_deref())
                .unwrap_or("")
                .contains("already in plaintext mode")
        );
    }

    #[test]
    fn persist_store_switch_keyring_unavailable_when_no_daemon_returns_ok_false() {
        // In a sandboxed test env the Secret Service daemon is almost always
        // down, so OsKeyring::available() is false. The switch must refuse
        // gracefully (Ok(false) with a status), NOT error or migrate.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());
        app.open_store_view();
        let result = persist_store_switch(&mut app, StoreSwitchTarget::Keyring, &dead_handle());
        match result {
            Ok(false) => {
                // Daemon down → refused with a status (the expected path here).
                let status = app
                    .store_view
                    .as_ref()
                    .and_then(|v| v.status.as_deref())
                    .unwrap_or("");
                assert!(
                    status.contains("unavailable"),
                    "expected an unavailable status, got: {status}"
                );
            }
            // If the daemon happens to be up in this env, the migrate runs and
            // the switch succeeds — also a valid outcome, so accept Ok(true).
            Ok(true) => {}
            Err(e) => panic!("keyring switch should not error in a no-daemon env: {e}"),
        }
    }

    // ===============================================================
    // Task 19: delete flow (^d → confirm → core delete) — I/O half.
    // ===============================================================

    #[test]
    fn persist_host_delete_removes_host_and_persists() {
        use ulid::Ulid;
        // The I/O half of the delete flow: core remove + keyring cleanup + save
        // + reload + re-rank. Driven here directly (the loop's wiring is the
        // popup → yes → this fn).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            hosts: vec![
                Host {
                    id: Ulid::new(),
                    name: "web".into(),
                    host: "h".into(),
                    port: 22,
                    ssh_args: None,
                    auth: Auth::inline(CredentialBody::new("u")),
                },
                Host {
                    id: Ulid::new(),
                    name: "db".into(),
                    host: "h2".into(),
                    port: 22,
                    ssh_args: None,
                    auth: Auth::inline(CredentialBody::new("u")),
                },
            ],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());
        assert_eq!(app.config().hosts.len(), 2);

        persist_host_delete(&mut app, "web").expect("delete should succeed");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.hosts.len(), 1, "only one host remains");
        assert_eq!(reloaded.hosts[0].name, "db");
        // Launcher re-ranked so the surviving host shows up.
        assert_eq!(app.launcher.ranked.len(), 1);
    }

    #[test]
    fn persist_host_delete_unknown_host_errors() {
        // A name absent from the config surfaces as HostNotFound (defensive:
        // the launcher only hands out ids from the loaded config, but a race or
        // a stale confirm must not silently no-op).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let mut app = App::new(
            sshrack_core::config::store::load(&path).unwrap(),
            Some(path),
            Frecency::default(),
            HashMap::new(),
        );
        let err = persist_host_delete(&mut app, "ghost").unwrap_err();
        assert!(matches!(err, SshrackError::HostNotFound { .. }));
    }

    // ===============================================================
    // Credential wizard: persist_cred_save + entry routing.
    // ===============================================================

    #[test]
    fn cred_add_none_kind_persists_user_only_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::None;
        app.overlay = Some(Overlay::CredWizard(w));

        persist_cred_save(&mut app, &dead_handle(), &OsKeyring).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.credentials.len(), 1);
        assert_eq!(reloaded.credentials[0].name, "ops");
        assert_eq!(reloaded.credentials[0].body.user, "deploy");
        assert_eq!(
            reloaded.credentials[0].body.secret_kind(),
            SecretKind::Default
        );
    }

    #[test]
    fn cred_add_identity_kind_persists_key_credential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Plaintext store mode so no sealing/vault path is exercised.
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::IdentityKey;
        w.identity = "/home/me/.ssh/id_ed25519".into();
        app.overlay = Some(Overlay::CredWizard(w));

        persist_cred_save(&mut app, &dead_handle(), &OsKeyring).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.body.secret_kind(), SecretKind::Key);
        assert_eq!(
            c.body
                .key
                .as_ref()
                .and_then(sshrack_core::config::schema::KeySource::as_path),
            Some(std::path::Path::new("/home/me/.ssh/id_ed25519"))
        );
    }

    #[test]
    fn cred_add_password_with_store_mode_plaintext_persists_plain_secret() {
        // Password + a decided store mode (Plaintext) → seal_body writes
        // Secret::Plain inline. The password must be sealed, not stored raw in
        // argv, and must survive the reload.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::Password;
        *w.password = "hunter2".into();
        app.overlay = Some(Overlay::CredWizard(w));

        persist_cred_save(&mut app, &dead_handle(), &OsKeyring).expect("add save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.body.secret_kind(), SecretKind::Password);
        assert_eq!(c.body.password_plain(), Some("hunter2"));
    }

    #[test]
    fn cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext() {
        // The crux of the "do not auto-pick a mode" rule: a Password choice
        // with cfg.store == None must surface StoreModeNotDecided, NOT silently
        // fall through to plaintext (which core's seal would otherwise do).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::Password;
        *w.password = "hunter2".into();
        app.overlay = Some(Overlay::CredWizard(w));

        let err = persist_cred_save(&mut app, &dead_handle(), &OsKeyring).unwrap_err();
        assert!(
            matches!(err, SshrackError::StoreModeNotDecided),
            "undecided store mode must error, not silently pick plaintext: {err}"
        );
        // Nothing was written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.credentials.is_empty());
    }

    #[test]
    fn fulfill_save_cred_undecided_with_dead_handle_stays_in_wizard_with_cancel_msg() {
        // SaveCred on a Password cred with store undecided would normally error
        // out (persist_cred_save returns StoreModeNotDecided). fulfill_save_cred
        // must catch that, try the store-pick popup, and — when the popup cannot
        // render (dead handle, as in tests) — surface a cancel message and KEEP
        // the wizard open (no panic, no silent drop, no close). Mirrors how
        // cred_add_password_with_store_mode_undecided_errors_not_silent_plaintext
        // builds the App + cred form.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());
        // store undecided by construction: SshrackConfig::default().store is None.
        assert!(app.config.store.is_none());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        w.secret_kind = super::super::wizard::SecretChoice::Password;
        *w.password = "hunter2".into();
        app.overlay = Some(Overlay::CredWizard(w));

        fulfill_save_cred(&mut app, &dead_handle());

        // The wizard stayed open (popup upgrade failed → Interrupted → cancel).
        assert!(
            app.cred_wizard().is_some(),
            "stayed in wizard on popup cancel"
        );
        let msg = app
            .cred_wizard()
            .and_then(|w| w.core_error.as_deref())
            .unwrap_or_default();
        assert!(
            msg.to_lowercase().contains("cancel"),
            "recovery should surface a cancel message, got: {msg}"
        );
        // And nothing was written.
        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.credentials.is_empty());
    }

    #[test]
    fn cred_add_duplicate_name_errors() {
        use ulid::Ulid;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: Ulid::new(),
                name: "ops".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into(); // duplicate
        w.user = "deploy".into();
        app.overlay = Some(Overlay::CredWizard(w));

        let err = persist_cred_save(&mut app, &dead_handle(), &OsKeyring).unwrap_err();
        assert!(matches!(err, SshrackError::CredentialAlreadyExists { .. }));
    }

    #[test]
    fn cred_edit_preserves_original_id_and_password_when_password_blank() {
        use ulid::Ulid;
        // Editing only the user/name with the password field left blank MUST
        // keep the existing password (and the original id). The original body is
        // a plaintext-password credential under Plaintext store mode.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            credentials: vec![Credential {
                id: orig_id,
                name: "ops".into(),
                body: CredentialBody::new("deploy").with_password("topsecret"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        assert!(app.open_cred_wizard_edit("ops"));
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        // The chooser opens on Password (the original kind). Leave the password
        // field blank and rename.
        assert_eq!(w.secret_kind, super::super::wizard::SecretChoice::Password);
        assert!(w.password.is_empty(), "edit form must not echo plaintext");
        w.name = "ops2".into();
        w.user = "ops".into();
        app.overlay = Some(Overlay::CredWizard(w));

        persist_cred_save(&mut app, &dead_handle(), &OsKeyring).expect("edit save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert_eq!(reloaded.credentials.len(), 1);
        let c = &reloaded.credentials[0];
        assert_eq!(c.id, orig_id, "edit must preserve the original id");
        assert_eq!(c.name, "ops2");
        assert_eq!(
            c.body.password_plain(),
            Some("topsecret"),
            "blank password field must keep the existing password"
        );
    }

    #[test]
    fn cred_edit_changing_user_keeps_id_and_password() {
        use ulid::Ulid;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let orig_id = Ulid::new();
        let cfg = SshrackConfig {
            store: Some(SecretStore::Plaintext),
            credentials: vec![Credential {
                id: orig_id,
                name: "ops".into(),
                body: CredentialBody::new("deploy").with_password("topsecret"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        assert!(app.open_cred_wizard_edit("ops"));
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.user = "root".into();
        // password left blank → preserved.
        app.overlay = Some(Overlay::CredWizard(w));

        persist_cred_save(&mut app, &dead_handle(), &OsKeyring).expect("edit save");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        let c = &reloaded.credentials[0];
        assert_eq!(c.id, orig_id);
        assert_eq!(c.body.user, "root");
        assert_eq!(c.body.password_plain(), Some("topsecret"));
    }

    // ===============================================================
    // Credentials panel: persist_cred_save rerank + delete I/O.
    // ===============================================================

    #[test]
    fn persist_cred_save_reranks_cred_panel_after_reload() {
        // After a cred save the on-disk config is reloaded and the cred panel
        // must reflect the new credential. Drive the loop's save half directly
        // (persist path), then assert the panel sees the new credential.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        // Provide a live (never-upgraded) weak handle so the vault unlock path
        // stays a no-op (no plaintext password in this body).
        let rc = Rc::new(RefCell::new(stdout_tui()));
        let handle: TerminalHandle = Rc::downgrade(&rc);

        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());
        // Open the add wizard and fill the form with a default-only body.
        app.open_cred_wizard_add();
        let Overlay::CredWizard(mut w) = app.overlay.take().unwrap() else {
            unreachable!("cred wizard open");
        };
        w.name = "ops".into();
        w.user = "deploy".into();
        // secret_kind stays None → no password to seal → no vault unlock needed.
        app.overlay = Some(Overlay::CredWizard(w));

        // The save path under test: persist + reload + close_cred_wizard (which
        // re-ranks the cred panel).
        persist_cred_save(&mut app, &handle, &OsKeyring).expect("cred save should succeed");
        app.close_cred_wizard();

        // The cred panel now ranks the new credential.
        assert_eq!(app.config().credentials.len(), 1);
        assert_eq!(app.cred_panel().ranked.len(), 1);
        assert_eq!(app.config().credentials[0].name, "ops");
    }

    #[test]
    fn persist_cred_delete_removes_credential_and_reranks_panel() {
        use ulid::Ulid;
        // The loop's delete half: after confirm, persist_cred_delete removes
        // the credential, persists, reloads, and re-ranks the cred panel so it
        // reflects the shorter list.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = SshrackConfig {
            credentials: vec![Credential {
                id: Ulid::new(),
                name: "ops".into(),
                body: CredentialBody::new("deploy"),
            }],
            ..SshrackConfig::default()
        };
        sshrack_core::config::store::save(&path, &cfg).unwrap();
        let mut app = App::new(cfg, Some(path.clone()), Frecency::default(), HashMap::new());

        persist_cred_delete(&mut app, "ops").expect("cred delete should succeed");

        let reloaded = sshrack_core::config::store::load(&path).unwrap();
        assert!(reloaded.credentials.is_empty());
        assert!(
            app.cred_panel().ranked.is_empty(),
            "cred panel must re-rank to empty after the only credential is deleted"
        );
    }

    #[test]
    fn persist_cred_delete_unknown_credential_errors() {
        // Deleting a name not in the config surfaces CredentialNotFound rather
        // than silently no-op'ing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        sshrack_core::config::store::save(&path, &SshrackConfig::default()).unwrap();
        let cfg = sshrack_core::config::store::load(&path).unwrap();
        let mut app = App::new(cfg, Some(path), Frecency::default(), HashMap::new());

        let err = persist_cred_delete(&mut app, "ghost").unwrap_err();
        assert!(matches!(err, SshrackError::CredentialNotFound { .. }));
    }
}
