//! Output shaping for `host ls/show`, `cred ls`, and `store status`.
//!
//! The host/cred row structs and helpers form the `--format json` contract and
//! are wired into the `cmd::host`/`cmd::cred` handlers. The `store status` row
//! ([`StoreStatusRow`] / [`store_status_row`]) is consumed by the
//! `cmd::store` handler.
//!
//! Two output paths exist: human-readable aligned text (the default, rendered
//! by the command handlers) and machine-readable JSON selected by the global
//! `--format json`. The JSON path is the automation contract: it is produced
//! exclusively by the `#[derive(Serialize)]` structs in this module, whose
//! field names are the stable public schema. The unit tests lock the field
//! names and their presence so a refactor cannot silently change what `jq`
//! sees.
//!
//! Security rule: **no struct in this module ever carries a password, key, or
//! any secret material — with one documented exception.** Rows expose only
//! routing/identity metadata (name, host, port, user, an auth-kind label, and
//! the referenced credential name). A password is represented only by its
//! *kind* (`"password"`, `"key"`, `"keyring"`, `"default"`), never its value.
//! The single exception is the **reveal row**: when the user explicitly runs
//! `show --reveal` (host or credential), the revealed plaintext is attached as
//! a `password` field on the detail/list row and serialized through `serde` so
//! it is correctly JSON-escaped. The field is `Option`, filled only under
//! `--reveal`, and `skip_serializing_if = "Option::is_none"` so non-reveal JSON
//! is byte-identical to before (no `password` key). This keeps the locked
//! `--format json` contract: hand-splicing is forbidden, and serde owns the
//! escaping.

use std::borrow::Cow;

use serde::Serialize;

use sshrack_core::config::schema::{
    Auth, Credential, CredentialBody, Host, SecretKind, SecretStore, SshrackConfig,
};

/// A single `host ls` row. Field names are the stable `--format json` schema.
///
/// `auth_kind` is one of `"credential"`, `"password"`, `"key"`, `"keyring"`,
/// `"default"`. `credential_name` is `Some` only when `auth_kind ==
/// "credential"`; it is the referenced credential's name (resolved from the
/// id by the caller), never the id itself. `user` is the inline body's user,
/// or the referenced credential's user.
#[derive(Debug, Clone, Serialize)]
pub struct HostListRow<'a> {
    pub name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub auth_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_name: Option<&'a str>,
}

/// A single `host show` row — the same fields as [`HostListRow`] plus the
/// stable id and the identity-file path (when an inline key is set). The id is
/// the non-sensitive stable identity used by the OS-keyring account label.
///
/// `password` is the **reveal exception**: `Some` only when the caller is
/// rendering a `show --reveal` result, carrying the decrypted plaintext so serde
/// escapes it correctly. It is `None` (and therefore absent from the JSON, via
/// `skip_serializing_if`) for every non-reveal path.
#[derive(Debug, Clone, Serialize)]
pub struct HostDetailRow<'a> {
    pub name: &'a str,
    pub id: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub auth_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_name: Option<&'a str>,
    /// Identity-file path for inline-key auth (`None` for credential refs and
    /// non-key inline bodies). Rendered via `to_string_lossy` so non-UTF-8 paths
    /// still serialize.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Cow<'a, str>>,
    /// The revealed plaintext, present only under `show --reveal`. See the
    /// module-level "reveal exception" note for why this is the one row that
    /// carries a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Cow<'a, str>>,
}

/// A single `cred ls` / `cred show` row. Field names are the stable
/// `--format json` schema.
///
/// `password` is the **reveal exception**: `Some` only when the caller is
/// rendering a `show --reveal` result, carrying the decrypted plaintext so serde
/// escapes it correctly. It is `None` (and therefore absent from the JSON, via
/// `skip_serializing_if`) for every non-reveal path (including plain `cred ls`,
/// which never reveals).
#[derive(Debug, Clone, Serialize)]
pub struct CredentialListRow<'a> {
    pub name: &'a str,
    pub user: &'a str,
    pub secret_kind: &'static str,
    /// The revealed plaintext, present only under `show --reveal`. See the
    /// module-level "reveal exception" note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<Cow<'a, str>>,
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

/// Build a [`HostListRow`] from a host plus the name of its referenced
/// credential (resolved by the caller from the id; `None` for inline auth or
/// a dangling reference). Pure.
pub fn host_list_row<'a>(host: &'a Host, credential_name: Option<&'a str>) -> HostListRow<'a> {
    HostListRow {
        name: &host.name,
        host: &host.host,
        port: host.port,
        user: user_of(host.auth.inline_body()),
        auth_kind: auth_kind_label(&host.auth),
        credential_name,
    }
}

/// Build a [`HostDetailRow`] from a host plus its referenced credential name
/// and the string form of its id. Pure. `identity` borrows the inline body's
/// key path when present; for a credential reference it is `None`. `password`
/// is the revealed plaintext under `--reveal` (`None` otherwise); passing it
/// here (rather than hand-splicing it into the JSON) is what keeps the password
/// correctly escaped.
pub fn host_detail_row<'a>(
    host: &'a Host,
    id_str: &'a str,
    credential_name: Option<&'a str>,
    password: Option<Cow<'a, str>>,
) -> HostDetailRow<'a> {
    HostDetailRow {
        name: &host.name,
        id: id_str,
        host: &host.host,
        port: host.port,
        user: user_of(host.auth.inline_body()),
        auth_kind: auth_kind_label(&host.auth),
        credential_name,
        identity: host
            .auth
            .inline_body()
            .and_then(|b| b.key.as_deref())
            .map(|p| p.to_string_lossy()),
        password,
    }
}

/// Build a [`CredentialListRow`] from a credential. Pure. `password` is the
/// revealed plaintext under `--reveal` (`None` for `cred ls`, which never
/// reveals); passing it here (rather than hand-splicing it into the JSON) is
/// what keeps the password correctly escaped.
pub fn credential_list_row<'a>(
    cred: &'a Credential,
    password: Option<Cow<'a, str>>,
) -> CredentialListRow<'a> {
    CredentialListRow {
        name: &cred.name,
        user: &cred.body.user,
        secret_kind: secret_kind_label(&cred.body.secret_kind()),
        password,
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
    //! Tests for the JSON/text output shapes of `ls`/`show`: field-name
    //! stability (the `--format json` contract), text alignment, and the
    //! credential-name reverse lookup. Pure: feeds fixtures, asserts strings.
    use super::*;
    use serde_json::Value;
    use sshrack_core::config::schema::{CredentialBody, Host, SshrackConfig, VaultMeta};
    use ulid::Ulid;

    /// A host with inline password auth, for fixture use.
    fn inline_host() -> Host {
        Host {
            id: Ulid::new(),
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            auth: Auth::Inline(CredentialBody::new("deploy").with_password("hunter2")),
        }
    }

    /// A host referencing a credential by id, for fixture use.
    fn ref_host(cred_id: Ulid) -> Host {
        Host {
            id: Ulid::new(),
            name: "db1".into(),
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
        let expected_keys = ["name", "host", "port", "user", "auth_kind"];
        for k in expected_keys {
            assert!(obj.contains_key(k), "missing stable field '{k}' in: {json}");
        }
        // credential_name is skipped when None (no credential reference).
        assert!(
            !obj.contains_key("credential_name"),
            "credential_name must be absent when None: {json}"
        );
        assert_eq!(obj["name"], "web1");
        assert_eq!(obj["host"], "10.0.0.5");
        assert_eq!(obj["port"], 2222);
        assert_eq!(obj["user"], "deploy");
        assert_eq!(obj["auth_kind"], "password");
    }

    #[test]
    fn host_list_row_credential_ref_includes_name() {
        let cred_id = Ulid::new();
        let host = ref_host(cred_id);
        let row = host_list_row(&host, Some("team-dev"));
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        assert_eq!(obj["auth_kind"], "credential");
        assert_eq!(obj["credential_name"], "team-dev");
        // A credential reference has no inline user; the row surfaces an empty
        // string (the caller resolves the credential's user if it wants it).
        assert_eq!(obj["user"], "");
    }

    #[test]
    fn host_detail_row_json_includes_id_and_identity() {
        let host = Host {
            id: Ulid::new(),
            name: "box".into(),
            host: "1.2.3.4".into(),
            port: 22,
            auth: Auth::Inline(CredentialBody::new("root").with_key("/home/u/.ssh/id_ed25519")),
        };
        let id_str = host.id.to_string();
        let row = host_detail_row(&host, &id_str, None, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        assert_eq!(obj["name"], "box");
        assert_eq!(obj["id"], id_str);
        assert_eq!(obj["auth_kind"], "key");
        assert_eq!(obj["identity"], "/home/u/.ssh/id_ed25519");
    }

    #[test]
    fn credential_list_row_json_has_stable_field_names() {
        let cred = sshrack_core::config::schema::Credential {
            id: Ulid::new(),
            name: "team-dev".into(),
            body: CredentialBody::new("deploy").with_password("s3cret"),
        };
        let row = credential_list_row(&cred, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();

        for k in ["name", "user", "secret_kind"] {
            assert!(obj.contains_key(k), "missing stable field '{k}': {json}");
        }
        assert_eq!(obj["name"], "team-dev");
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

    // ---- reveal-row JSON escaping tests (Finding 1) ----
    //
    // The reveal path must serialize the password through serde so characters
    // that would break hand-spliced JSON (`"`, `\`, newlines, control chars)
    // round-trip as valid JSON. Non-reveal JSON must never carry a password.

    #[test]
    fn host_detail_row_reveal_escapes_quotes_and_backslashes() {
        // A password containing both `"` and `\` — the classic injection pair.
        let host = inline_host();
        let id_str = host.id.to_string();
        let pw = r#"p"a\th"#; // contains " and \
        let row = host_detail_row(&host, &id_str, None, Some(Cow::Borrowed(pw)));
        let json = serde_json::to_string(&row).unwrap();

        // Must parse back as valid JSON (hand-splicing would break here).
        let v: Value = serde_json::from_str(&json).expect("reveal JSON must be valid");
        let obj = v.as_object().unwrap();
        assert_eq!(obj["password"], pw, "password must round-trip exactly");
        // And no raw `"` leaked unescaped into the wire form.
        assert!(
            json.contains(r#"\"a\\th"#),
            "expected escaped form in: {json}"
        );
    }

    #[test]
    fn host_detail_row_reveal_escapes_newline_and_control_char() {
        let host = inline_host();
        let id_str = host.id.to_string();
        // A newline plus a NUL-like control char (U+0001). Both are illegal
        // bare inside a JSON string and must be escaped by serde.
        let pw = "line1\nline2\u{0001}end";
        let row = host_detail_row(&host, &id_str, None, Some(Cow::Borrowed(pw)));
        let json = serde_json::to_string(&row).unwrap();

        let v: Value = serde_json::from_str(&json).expect("reveal JSON must be valid");
        assert_eq!(v["password"], pw);
        // The raw newline must not appear unescaped in the wire form.
        assert!(
            !json.contains('\n'),
            "raw newline must be escaped in reveal JSON: {json:?}"
        );
    }

    #[test]
    fn host_detail_row_non_reveal_has_no_password_field() {
        // The non-reveal path passes `None`; the `password` key must be absent
        // (not just empty) so the locked `--format json` contract is preserved.
        let host = inline_host();
        let id_str = host.id.to_string();
        let row = host_detail_row(&host, &id_str, None, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("password"),
            "non-reveal JSON must not carry a password field: {json}"
        );
    }

    #[test]
    fn credential_list_row_reveal_round_trips_through_json() {
        let cred = sshrack_core::config::schema::Credential {
            id: Ulid::new(),
            name: "team-dev".into(),
            body: CredentialBody::new("deploy").with_password("ignored"),
        };
        // A nasty password mixing every escapable class.
        let pw = "a\"b\\c\nd\te\u{0000}f";
        let row = credential_list_row(&cred, Some(Cow::Borrowed(pw)));
        let json = serde_json::to_string(&row).unwrap();

        let v: Value = serde_json::from_str(&json).expect("reveal JSON must be valid");
        assert_eq!(v["password"], pw);
        assert_eq!(v["name"], "team-dev");
    }

    #[test]
    fn credential_list_row_non_reveal_has_no_password_field() {
        let cred = sshrack_core::config::schema::Credential {
            id: Ulid::new(),
            name: "team-dev".into(),
            body: CredentialBody::new("deploy").with_password("s3cret"),
        };
        let row = credential_list_row(&cred, None);
        let json = serde_json::to_string(&row).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("password"),
            "non-reveal JSON must not carry a password field: {json}"
        );
        // And the actual secret still must not leak.
        assert!(!json.contains("s3cret"));
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
