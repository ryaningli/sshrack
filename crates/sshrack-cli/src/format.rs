//! Output shaping for `host ls/show`, `cred ls`, and `store status`.
//!
//! These row structs and helpers form the `--format json` contract; they are
//! wired into the command handlers in Tasks 19–20. Until then they are unused
//! at the call site (only the unit tests reference them), so the module
//! carries `#![allow(dead_code)]` — the same convention `exit_code` uses for
//! ahead-of-time declarations.
//!
//! Two output paths exist: human-readable aligned text (the default, rendered
//! by the command handlers in later tasks) and machine-readable JSON selected
//! by the global `--format json`. The JSON path is the automation contract: it
//! is produced exclusively by the `#[derive(Serialize)]` structs in this
//! module, whose field names are the stable public schema. The unit tests lock
//! the field names and their presence so a refactor cannot silently change
//! what `jq` sees.
//!
//! Security rule: **no struct in this module ever carries a password, key, or
//! any secret material.** Rows expose only routing/identity metadata (alias,
//! host, port, user, an auth-kind label, and the referenced credential alias).
//! A password is represented only by its *kind* (`"password"`, `"key"`,
//! `"keyring"`, `"default"`), never its value.

#![allow(dead_code)]

use std::borrow::Cow;

use serde::Serialize;

use sshrack_core::config::schema::{
    Auth, Credential, CredentialBody, Host, SecretKind, SecretStore, SshrackConfig,
};

/// A single `host ls` row. Field names are the stable `--format json` schema.
///
/// `auth_kind` is one of `"credential"`, `"password"`, `"key"`, `"keyring"`,
/// `"default"`. `credential_alias` is `Some` only when `auth_kind ==
/// "credential"`; it is the referenced credential's alias (resolved from the
/// id by the caller), never the id itself. `user` is the inline body's user,
/// or the referenced credential's user.
#[derive(Debug, Clone, Serialize)]
pub struct HostListRow<'a> {
    pub alias: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub auth_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_alias: Option<&'a str>,
}

/// A single `host show` row — the same fields as [`HostListRow`] plus the
/// stable id and the identity-file path (when an inline key is set). The id is
/// the non-sensitive stable identity used by the OS-keyring account label.
#[derive(Debug, Clone, Serialize)]
pub struct HostDetailRow<'a> {
    pub alias: &'a str,
    pub id: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub auth_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_alias: Option<&'a str>,
    /// Identity-file path for inline-key auth (`None` for credential refs and
    /// non-key inline bodies). Rendered via `to_string_lossy` so non-UTF-8 paths
    /// still serialize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Cow<'a, str>>,
}

/// A single `cred ls` row. Field names are the stable `--format json` schema.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialListRow<'a> {
    pub alias: &'a str,
    pub user: &'a str,
    pub secret_kind: &'static str,
}

/// A `store status` row describing the active password-storage mode.
///
/// `mode` is one of `"keyring"`, `"vault"`, `"plaintext"`, or `"undecided"`
/// (fresh config). `vault` carries the non-secret KDF parameters
/// (`kdf`, `memory_kib`, `time_cost`, `lanes`, `cache_ttl_secs`); a present
/// `verifier` is reported only as a boolean (the ciphertext itself is never
/// surfaced).
#[derive(Debug, Clone, Serialize)]
pub struct StoreStatusRow {
    pub mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_cost: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lanes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_verifier: Option<bool>,
}

/// The stable label for an [`Auth`] variant, for JSON/text output. Returns
/// `"credential"` for a credential reference, otherwise the inline body's
/// [`SecretKind`] label.
pub fn auth_kind_label(auth: &Auth) -> &'static str {
    match auth {
        Auth::Ref { .. } => "credential",
        Auth::Inline(body) => secret_kind_label(&body.secret_kind()),
    }
}

/// The stable label for a [`SecretKind`], for JSON/text output.
pub fn secret_kind_label(kind: &SecretKind) -> &'static str {
    match kind {
        SecretKind::Password => "password",
        SecretKind::Key => "key",
        SecretKind::KeyringPassword => "keyring",
        SecretKind::Default => "default",
    }
}

/// Build a [`HostListRow`] from a host plus the alias of its referenced
/// credential (resolved by the caller from the id; `None` for inline auth or
/// a dangling reference). Pure.
pub fn host_list_row<'a>(host: &'a Host, credential_alias: Option<&'a str>) -> HostListRow<'a> {
    HostListRow {
        alias: &host.alias,
        host: &host.host,
        port: host.port,
        user: user_of(host.auth.inline_body()),
        auth_kind: auth_kind_label(&host.auth),
        credential_alias,
    }
}

/// Build a [`HostDetailRow`] from a host plus its referenced credential alias
/// and the string form of its id. Pure. `identity` borrows the inline body's
/// key path when present; for a credential reference it is `None`.
pub fn host_detail_row<'a>(
    host: &'a Host,
    id_str: &'a str,
    credential_alias: Option<&'a str>,
) -> HostDetailRow<'a> {
    HostDetailRow {
        alias: &host.alias,
        id: id_str,
        host: &host.host,
        port: host.port,
        user: user_of(host.auth.inline_body()),
        auth_kind: auth_kind_label(&host.auth),
        credential_alias,
        identity: host
            .auth
            .inline_body()
            .and_then(|b| b.key.as_deref())
            .map(|p| p.to_string_lossy()),
    }
}

/// Build a [`CredentialListRow`] from a credential. Pure.
pub fn credential_list_row(cred: &Credential) -> CredentialListRow<'_> {
    CredentialListRow {
        alias: &cred.alias,
        user: &cred.body.user,
        secret_kind: secret_kind_label(&cred.body.secret_kind()),
    }
}

/// Build a [`StoreStatusRow`] from a config's active [`SecretStore`]. Pure.
pub fn store_status_row(cfg: &SshrackConfig) -> StoreStatusRow {
    match &cfg.store {
        None => StoreStatusRow {
            mode: "undecided",
            kdf: None,
            memory_kib: None,
            time_cost: None,
            lanes: None,
            cache_ttl_secs: None,
            has_verifier: None,
        },
        Some(SecretStore::Plaintext) => StoreStatusRow {
            mode: "plaintext",
            kdf: None,
            memory_kib: None,
            time_cost: None,
            lanes: None,
            cache_ttl_secs: None,
            has_verifier: None,
        },
        Some(SecretStore::Keyring) => StoreStatusRow {
            mode: "keyring",
            kdf: None,
            memory_kib: None,
            time_cost: None,
            lanes: None,
            cache_ttl_secs: None,
            has_verifier: None,
        },
        Some(SecretStore::Vault { meta }) => StoreStatusRow {
            mode: "vault",
            kdf: Some(meta.kdf.clone()),
            memory_kib: Some(meta.m),
            time_cost: Some(meta.t),
            lanes: Some(meta.p),
            cache_ttl_secs: Some(meta.cache_ttl_secs),
            has_verifier: Some(meta.verifier.is_some()),
        },
    }
}

/// The user a host authenticates as. For an inline body, the body's user; for a
/// credential reference, `None` (the caller resolves the credential's user).
fn user_of(body: Option<&CredentialBody>) -> &str {
    match body {
        Some(b) => &b.user,
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sshrack_core::config::schema::{CredentialBody, Host, SshrackConfig, VaultMeta};
    use ulid::Ulid;

    /// A host with inline password auth, for fixture use.
    fn inline_host() -> Host {
        Host {
            id: Ulid::new(),
            alias: "web1".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            auth: Auth::Inline(CredentialBody::new("deploy").with_password("hunter2")),
        }
    }

    /// A host referencing a credential by id, for fixture use.
    fn ref_host(cred_id: Ulid) -> Host {
        Host {
            id: Ulid::new(),
            alias: "db1".into(),
            host: "db.internal".into(),
            port: 22,
            auth: Auth::reference(cred_id),
        }
    }

    #[test]
    fn host_list_row_json_has_stable_field_names() {
        let host = inline_host();
        let row = host_list_row(&host, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().expect("row serializes to an object");

        // Stable field set — adding/removing/renaming any of these is a
        // breaking change to the automation contract.
        let expected_keys = ["alias", "host", "port", "user", "auth_kind"];
        for k in expected_keys {
            assert!(obj.contains_key(k), "missing stable field '{k}' in: {json}");
        }
        // credential_alias is skipped when None (no credential reference).
        assert!(
            !obj.contains_key("credential_alias"),
            "credential_alias must be absent when None: {json}"
        );
        assert_eq!(obj["alias"], "web1");
        assert_eq!(obj["host"], "10.0.0.5");
        assert_eq!(obj["port"], 2222);
        assert_eq!(obj["user"], "deploy");
        assert_eq!(obj["auth_kind"], "password");
    }

    #[test]
    fn host_list_row_credential_ref_includes_alias() {
        let cred_id = Ulid::new();
        let host = ref_host(cred_id);
        let row = host_list_row(&host, Some("team-dev"));
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        assert_eq!(obj["auth_kind"], "credential");
        assert_eq!(obj["credential_alias"], "team-dev");
        // A credential reference has no inline user; the row surfaces an empty
        // string (the caller resolves the credential's user if it wants it).
        assert_eq!(obj["user"], "");
    }

    #[test]
    fn host_detail_row_json_includes_id_and_identity() {
        let host = Host {
            id: Ulid::new(),
            alias: "box".into(),
            host: "1.2.3.4".into(),
            port: 22,
            auth: Auth::Inline(CredentialBody::new("root").with_key("/home/u/.ssh/id_ed25519")),
        };
        let id_str = host.id.to_string();
        let row = host_detail_row(&host, &id_str, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        assert_eq!(obj["alias"], "box");
        assert_eq!(obj["id"], id_str);
        assert_eq!(obj["auth_kind"], "key");
        assert_eq!(obj["identity"], "/home/u/.ssh/id_ed25519");
    }

    #[test]
    fn credential_list_row_json_has_stable_field_names() {
        let cred = sshrack_core::config::schema::Credential {
            id: Ulid::new(),
            alias: "team-dev".into(),
            body: CredentialBody::new("deploy").with_password("s3cret"),
        };
        let row = credential_list_row(&cred);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        for k in ["alias", "user", "secret_kind"] {
            assert!(obj.contains_key(k), "missing stable field '{k}': {json}");
        }
        assert_eq!(obj["alias"], "team-dev");
        assert_eq!(obj["user"], "deploy");
        assert_eq!(obj["secret_kind"], "password");
        // No secret value ever appears in a row: the credential's actual
        // password ("s3cret") must not leak. ("password" the kind label is
        // fine — it names the secret type, not the secret.)
        assert!(
            !json.contains("s3cret"),
            "JSON row must not carry a secret value: {json}"
        );
    }

    #[test]
    fn store_status_undecided() {
        let cfg = SshrackConfig::default();
        let row = store_status_row(&cfg);
        let json = serde_json::to_string(&row).unwrap();
        assert_eq!(row.mode, "undecided");
        // Undecided carries no vault params.
        assert_eq!(json, r#"{"mode":"undecided"}"#);
    }

    #[test]
    fn store_status_vault_carries_non_secret_kdf_params() {
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: VaultMeta::default_argon2id("c2FsdA=="),
            }),
            ..Default::default()
        };
        let row = store_status_row(&cfg);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        assert_eq!(obj["mode"], "vault");
        assert_eq!(obj["kdf"], "argon2id");
        assert!(obj.contains_key("memory_kib"));
        assert!(obj.contains_key("time_cost"));
        assert!(obj.contains_key("lanes"));
        assert!(obj.contains_key("cache_ttl_secs"));
        assert_eq!(obj["has_verifier"], false);
        // The verifier ciphertext and the salt must never appear in status —
        // only the boolean "does a verifier exist". ("has_verifier" the field
        // name is fine; it is not a secret.)
        assert!(
            !json.contains("c2FsdA=="),
            "vault status must not leak the salt: {json}"
        );
    }

    #[test]
    fn secret_kind_labels_are_stable_strings() {
        assert_eq!(secret_kind_label(&SecretKind::Password), "password");
        assert_eq!(secret_kind_label(&SecretKind::Key), "key");
        assert_eq!(secret_kind_label(&SecretKind::KeyringPassword), "keyring");
        assert_eq!(secret_kind_label(&SecretKind::Default), "default");
    }

    #[test]
    fn auth_kind_label_distinguishes_credential_ref_from_inline() {
        let cred_ref = Auth::reference(Ulid::new());
        assert_eq!(auth_kind_label(&cred_ref), "credential");

        let inline_pw = Auth::Inline(CredentialBody::new("u").with_password("p"));
        assert_eq!(auth_kind_label(&inline_pw), "password");
    }
}
