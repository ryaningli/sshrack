//! Configuration data model and TOML (de)serialization.

use std::path::PathBuf;

use crate::error::SshrackError;
use ulid::Ulid;

/// A stored password payload, in either storage mode. `untagged` keeps each
/// mode's TOML natural: plaintext mode writes `password = "x"` (a bare
/// string, [`Secret::Plain`]); encrypted mode writes
/// `password = { nonce = "...", cipher = "..." }` ([`Secret::Encrypted`]).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Secret {
    /// Plaintext password (plaintext storage mode).
    Plain(String),
    /// Authenticated ciphertext: base64 nonce + base64 (ciphertext||tag).
    Encrypted(EncryptedSecret),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the plaintext so `format!("{:?}", secret)` can never leak a
        // password to logs/error messages. Mirrors the redacting Debug on the
        // consumer-side `credential::PasswordSource`.
        match self {
            Secret::Plain(_) => f.write_str("Plain(<redacted>)"),
            Secret::Encrypted(e) => f.debug_tuple("Encrypted").field(e).finish(),
        }
    }
}

impl Secret {
    /// The plaintext if this is [`Secret::Plain`]; `None` for encrypted
    /// secrets. Lets display/test code read a plaintext password without
    /// touching cryptography.
    pub fn as_plain(&self) -> Option<&str> {
        match self {
            Secret::Plain(p) => Some(p),
            Secret::Encrypted(_) => None,
        }
    }

    /// True when the secret is encrypted (needs the master key to read).
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Secret::Encrypted(_))
    }
}

/// The on-disk form of an encrypted password: two base64 strings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EncryptedSecret {
    /// Base64-encoded 24-byte XChaCha20 nonce.
    pub nonce: String,
    /// Base64-encoded ciphertext + 16-byte Poly1305 tag.
    pub cipher: String,
}

/// Argon2id parameters + cache policy for the encrypted ("vault") mode. Stored
/// flattened inside `[store]` (as the `Vault` variant of [`SecretStore`]). The
/// salt is public by design (Kerckhoffs); security rests on the master
/// passphrase the user remembers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultMeta {
    /// KDF algorithm tag. Always `"argon2id"` for now; parsed, not free-form.
    pub kdf: String,
    /// Base64-encoded salt (16 bytes).
    pub salt: String,
    /// Argon2id memory cost in KiB.
    pub m: u32,
    /// Argon2id time cost (iterations).
    pub t: u32,
    /// Argon2id parallelism (lanes).
    pub p: u32,
    /// Master-key cache TTL in seconds (0 disables caching).
    pub cache_ttl_secs: u64,
    /// A ciphertext of a known plaintext, used at unlock to prove the master
    /// key (and thus the passphrase) is correct before caching it. `None` for
    /// a freshly default meta before `store use vault` fills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<EncryptedSecret>,
}

impl VaultMeta {
    /// Default cache window: 30 minutes, balances usability vs. exposure.
    pub const DEFAULT_CACHE_TTL_SECS: u64 = 1800;

    /// Build an Argon2id meta with the project's default cost (64 MiB / 3 /
    /// 4) and the default cache TTL. `salt_b64` is the base64-encoded salt.
    pub fn default_argon2id(salt_b64: impl Into<String>) -> Self {
        Self {
            kdf: "argon2id".into(),
            salt: salt_b64.into(),
            m: 65_536,
            t: 3,
            p: 4,
            cache_ttl_secs: Self::DEFAULT_CACHE_TTL_SECS,
            verifier: None,
        }
    }

    /// True if the algorithm tag is one this build can derive a key for.
    pub fn supports_kdf(&self) -> bool {
        self.kdf == "argon2id"
    }
}

/// The active password-storage mode for a config. Mutually exclusive: exactly
/// one is in effect once the user has chosen. `None` at the [`SshrackConfig`]
/// level is the fresh-config "undecided" state that triggers the first-use
/// mode prompt.
///
/// Serialized as a `[store]` table tagged by `mode`:
/// - plaintext → `[store] mode = "plaintext"`
/// - vault     → `[store] mode = "vault"` + the flattened [`VaultMeta`] fields
/// - keyring   → `[store] mode = "keyring"`
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum SecretStore {
    /// Passwords stored as plaintext inline in `config.toml`.
    Plaintext,
    /// Passwords encrypted inline (Argon2id + XChaCha20-Poly1305).
    Vault {
        /// Vault parameters (KDF, salt, verifier, cache policy), flattened
        /// into the `[store]` table next to `mode = "vault"`.
        #[serde(flatten)]
        meta: VaultMeta,
    },
    /// Passwords in the OS keyring; bodies carry only a `keyring = true` marker.
    Keyring,
}

/// A reusable login identity: username plus at most one auth secret (password
/// or key). Shared by `[[credentials]]` entries (via [`Credential`]) and inline
/// host auth ([`Auth::Inline`]).
///
/// "At most one secret" is enforced by [`CredentialBody::validate`]; `None`/`None`
/// means "ssh default / agent keys".
///
/// The stable identity ([`Ulid`]) lives on the owner ([`Credential`] or
/// [`Host`]), not on the body — a body is the secret payload, the owner is the
/// named thing. The OS-keyring account key is derived from the owner kind plus
/// that owner id (via [`crate::id::keyring_key`]), so renaming an owner never
/// orphans its keyring password.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialBody {
    /// Login user delivered to ssh (`-l`) / scp (`user@`).
    pub user: String,
    /// Plaintext or encrypted password. `None` when not used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Secret>,
    /// Identity key source: a path, or pasted inline contents. `None` when
    /// not used. Mutually exclusive with `password` and the `keyring` marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeySource>,
    /// Marker for keyring mode: when `true`, the password lives in the OS
    /// keyring (keyed by the owner id) and the body carries no inline secret.
    /// Mutually exclusive with `password` and `key`. Defaults to `false` and is
    /// omitted from TOML when false, so pre-keyring configs parse unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keyring: bool,
}

/// The kind of secret a [`CredentialBody`] carries, for display/interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    Key,
    /// Password stored in the OS keyring; the body carries only the
    /// `keyring = true` marker.
    KeyringPassword,
    /// No explicit secret — rely on ssh default keys / agent.
    Default,
}

/// A selectable auth method for the interactive `add`/`edit`/`cred` menus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChoice {
    /// Reuse a named `[[credentials]]` entry by name.
    Credential {
        /// The credential name to reference.
        name: String,
    },
    /// Inline username + password collected at the prompt.
    InlinePassword,
    /// Inline username + identity key path collected at the prompt.
    InlineKey,
    /// Username only; rely on the ssh default / agent.
    Default,
}

/// Where an identity key lives: a file on disk ([`KeySource::Path`]), or pasted
/// contents carried inline ([`KeySource::Inline`]). `untagged` so a legacy
/// `key = "/path"` (bare string) still parses as [`KeySource::Path`] with no
/// migration step.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum KeySource {
    /// A path to a private key file on the local disk. Serializes as a bare
    /// TOML string (`key = "/path"`), matching the pre-feature on-disk shape.
    Path(PathBuf),
    /// Pasted private-key material (and an optional certificate), carried as
    /// [`Secret`] so vault/plaintext storage modes apply. Keyring mode is not
    /// supported for inline keys (see [`CredentialBody::validate`]).
    Inline(InlineKey),
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact inline key material — it is key text, as sensitive as a password.
        // Path is a filesystem location, not secret.
        match self {
            KeySource::Path(p) => f.debug_tuple("Path").field(p).finish(),
            KeySource::Inline(_) => f.write_str("Inline(<redacted>)"),
        }
    }
}

impl KeySource {
    /// The on-disk path if this is [`KeySource::Path`]; `None` for inline keys.
    /// Connection code feeds this to ssh's `-i` flag; patch/resolve logic uses
    /// it to keep behavior stable while inline-key handling lands in later tasks.
    pub fn as_path(&self) -> Option<&std::path::Path> {
        match self {
            KeySource::Path(p) => Some(p.as_path()),
            KeySource::Inline(_) => None,
        }
    }
}

/// The inline (pasted) form of a [`KeySource`]. `private_key` is the key text;
/// `certificate` is an optional SSH certificate (`*-cert.pub` contents).
/// `keyring` is reserved for a future keyring-backed inline key; for now
/// [`CredentialBody::validate`] rejects `Inline` when it or the body-level
/// `keyring` marker is set.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InlineKey {
    /// Private-key text. `None` only in a keyring-marker form (currently rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Secret>,
    /// Optional SSH certificate text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Secret>,
    /// Reserved: inline key lives in the OS keyring. Currently rejected in
    /// [`CredentialBody::validate`] (inline keys need vault/plaintext mode).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keyring: bool,
}

impl std::fmt::Debug for InlineKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact both secrets; keyring is a boolean flag, not sensitive.
        f.debug_struct("InlineKey")
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "certificate",
                &self.certificate.as_ref().map(|_| "<redacted>"),
            )
            .field("keyring", &self.keyring)
            .finish()
    }
}

impl CredentialBody {
    /// Build a default-only body (user, no secret). The owner assigns and
    /// carries the id; a body carries none.
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: None,
            key: None,
            keyring: false,
        }
    }

    /// Set the password secret as plaintext (clears any key). Builder.
    /// Encryption is applied later by the vault layer, not the builder.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(Secret::Plain(password.into()));
        self.key = None;
        self.keyring = false;
        self
    }

    /// Set the key to a file path (clears any password). Builder.
    pub fn with_key(mut self, key: impl Into<PathBuf>) -> Self {
        self.key = Some(KeySource::Path(key.into()));
        self.password = None;
        self.keyring = false;
        self
    }

    /// Set the key to pasted inline material (clears any password). Builder.
    /// `private_key` is the key text; `certificate` is an optional SSH cert.
    pub fn with_inline_key(mut self, private_key: Secret, certificate: Option<Secret>) -> Self {
        self.key = Some(KeySource::Inline(InlineKey {
            private_key: Some(private_key),
            certificate,
            keyring: false,
        }));
        self.password = None;
        self.keyring = false;
        self
    }

    /// Which secret kind this body carries.
    pub fn secret_kind(&self) -> SecretKind {
        if self.keyring {
            SecretKind::KeyringPassword
        } else if self.key.is_some() {
            SecretKind::Key
        } else if self.password.is_some() {
            SecretKind::Password
        } else {
            SecretKind::Default
        }
    }

    /// Enforce the mutual-exclusion invariant: at most one of password / key
    /// (Path or Inline) / keyring marker. Any pair set is a malformed body — no
    /// silent winner. An inline key in keyring-marker form (`ik.keyring == true`
    /// with no in-body secret text) is the sealed form stored under keyring
    /// storage and is accepted; a marker that coexists with in-body plaintext
    /// is a half-migrated body and is rejected.
    pub fn validate(&self) -> Result<(), SshrackError> {
        // Count the secret slots: password, any key (Path or Inline), and the
        // body-level keyring marker (password-in-keyring). At most one allowed.
        let key_present = self.key.is_some();
        let secrets_set = [self.password.is_some(), key_present, self.keyring]
            .into_iter()
            .filter(|b| *b)
            .count();
        if secrets_set > 1 {
            return Err(SshrackError::InvalidCredentialBody {
                user: self.user.clone(),
            });
        }
        // An inline key whose text lives in the OS keyring (`ik.keyring == true`)
        // is the sealed form under keyring storage: it carries no in-body secret
        // text, so accept it. Reject a marker that coexists with in-body plaintext
        // — that is a half-migrated body, not a valid sealed form.
        if let Some(KeySource::Inline(ik)) = &self.key
            && ik.keyring
            && (ik.private_key.is_some() || ik.certificate.is_some())
        {
            return Err(SshrackError::InvalidCredentialBody {
                user: self.user.clone(),
            });
        }
        Ok(())
    }

    /// The plaintext password if stored in the clear; `None` for encrypted or
    /// unset. Callers that must read the value regardless of mode go through
    /// `credential::resolve`, which decrypts.
    pub fn password_plain(&self) -> Option<&str> {
        self.password.as_ref().and_then(Secret::as_plain)
    }
}

/// A named credential table entry: a first-class id, a name, plus its
/// [`CredentialBody`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// Stable, globally-unique identity for this credential. The OS-keyring
    /// account key is derived from this id (not the name), so renaming a
    /// credential never orphans its keyring password.
    pub id: Ulid,
    pub name: String,
    #[serde(flatten)]
    pub body: CredentialBody,
}

/// How a host authenticates — exactly one variant applies (mutually exclusive).
///
/// TOML is untagged for readability:
/// - `auth = { credential = "01J..." }`              -> [`Auth::Ref`] (by id)
/// - `auth = { user = "root", password = "..." }`     -> [`Auth::Inline`] (password)
/// - `auth = { user = "ops", key = "..." }`           -> [`Auth::Inline`] (key)
/// - `auth = { user = "ec2-user" }`                   -> [`Auth::Inline`] (default)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Auth {
    /// Reference a `[[credentials]]` entry by its stable id.
    Ref { credential: Ulid },
    /// Inline user + optional secret (at most one of password/key).
    Inline(CredentialBody),
}

impl Auth {
    /// Build a credential-reference auth by id.
    pub fn reference(credential_id: Ulid) -> Self {
        Auth::Ref {
            credential: credential_id,
        }
    }

    /// Build an inline auth from a body.
    pub fn inline(body: CredentialBody) -> Self {
        Auth::Inline(body)
    }

    /// The referenced credential id, if this is [`Auth::Ref`].
    pub fn credential_id(&self) -> Option<Ulid> {
        match self {
            Auth::Ref { credential } => Some(*credential),
            Auth::Inline(_) => None,
        }
    }

    /// The inline body, if this is [`Auth::Inline`].
    pub fn inline_body(&self) -> Option<&CredentialBody> {
        match self {
            Auth::Ref { .. } => None,
            Auth::Inline(body) => Some(body),
        }
    }

    /// The inline body mutably, if this is [`Auth::Inline`].
    pub fn inline_body_mut(&mut self) -> Option<&mut CredentialBody> {
        match self {
            Auth::Ref { .. } => None,
            Auth::Inline(body) => Some(body),
        }
    }
}

/// A single managed host entry. Auth is an enum; `user` lives inside `auth`.
/// The first-class `id` is the stable identity (keyring key, cross-host
/// reference target) — independent of the name, which the user may rename.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Host {
    /// Stable, globally-unique identity for this host.
    pub id: Ulid,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub auth: Auth,
}

fn default_port() -> u16 {
    22
}

/// Default value for [`SshrackConfig::format_version`] (the only config format
/// this build knows).
fn default_format_version() -> u32 {
    1
}

/// The full sshrack configuration: hosts plus reusable credentials.
///
/// `Default` is implemented manually (not derived) so the meaning of a fresh
/// config — `format_version = 1`, empty hosts/credentials, undecided store — is
/// explicit and does not depend on `Ulid: Default`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SshrackConfig {
    /// On-disk format version. `1` is the only version this build reads or
    /// writes; defaulted on read so a config missing the field still parses.
    #[serde(default = "default_format_version")]
    pub format_version: u32,
    #[serde(default)]
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub credentials: Vec<Credential>,
    /// The active password-storage mode, or `None` when undecided (fresh
    /// config). See [`SecretStore`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<SecretStore>,
}

impl Default for SshrackConfig {
    fn default() -> Self {
        Self {
            format_version: 1,
            hosts: Vec::new(),
            credentials: Vec::new(),
            store: None,
        }
    }
}

impl SshrackConfig {
    /// Find a host by name.
    pub fn find_host_by_name(&self, name: &str) -> Option<&Host> {
        self.hosts.iter().find(|h| h.name == name)
    }

    /// Find a host by id.
    pub fn find_host_by_id(&self, id: &Ulid) -> Option<&Host> {
        self.hosts.iter().find(|h| &h.id == id)
    }

    /// Find a credential by name.
    pub fn find_credential_by_name(&self, name: &str) -> Option<&Credential> {
        self.credentials.iter().find(|c| c.name == name)
    }

    /// Find a credential by id.
    pub fn find_credential_by_id(&self, id: &Ulid) -> Option<&Credential> {
        self.credentials.iter().find(|c| &c.id == id)
    }

    /// True when vault encryption is the active mode.
    pub fn is_vault(&self) -> bool {
        matches!(self.store, Some(SecretStore::Vault { .. }))
    }

    /// The vault meta, iff vault mode is active.
    pub fn vault_meta(&self) -> Option<&VaultMeta> {
        match &self.store {
            Some(SecretStore::Vault { meta }) => Some(meta),
            _ => None,
        }
    }

    /// True when keyring is the active mode.
    pub fn is_keyring(&self) -> bool {
        matches!(self.store, Some(SecretStore::Keyring))
    }

    /// True when plaintext is the active mode.
    pub fn is_plaintext(&self) -> bool {
        matches!(self.store, Some(SecretStore::Plaintext))
    }

    /// True once the user has explicitly chosen any mode (not undecided).
    pub fn mode_chosen(&self) -> bool {
        self.store.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    #[test]
    fn default_config_has_format_version_one() {
        let cfg = SshrackConfig::default();
        assert_eq!(cfg.format_version, 1);
    }

    #[test]
    fn format_version_defaults_on_read_when_absent() {
        // A config missing format_version (legacy shape) still parses to 1.
        let input = r#"
[[hosts]]
id = "01HXYZ0000000000000000000E"
name = "h"
host = "x"
auth = { user = "root" }
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        assert_eq!(cfg.format_version, 1);
    }

    #[test]
    fn format_version_round_trips() {
        let cfg = SshrackConfig::default();
        let s = toml::to_string(&cfg).unwrap();
        assert!(
            s.contains("format_version = 1"),
            "expected format_version in TOML, got: {s}"
        );
        let back: SshrackConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.format_version, 1);
    }

    #[test]
    fn host_and_credential_get_distinct_ids() {
        // Owners carry first-class ids; two unrelated owners must not collide.
        let h = Host {
            id: crate::id::new_id(),
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody::new("u")),
        };
        let c = Credential {
            id: crate::id::new_id(),
            name: "c".into(),
            body: CredentialBody::new("u"),
        };
        assert_ne!(h.id, c.id);
    }

    #[test]
    fn body_construction_does_not_carry_an_id() {
        // The id now lives on the owner; a body has no id field at all.
        let b = CredentialBody::new("u");
        // If a field named `id` existed on the body, this would not compile.
        // Touch only id-bearing accessors that remain valid.
        assert_eq!(b.user, "u");
        assert!(b.password.is_none());
        assert!(b.key.is_none());
        assert!(!b.keyring);
    }

    #[test]
    fn builders_keep_body_secret_slot_only() {
        // with_password / with_key change only the secret slot.
        let bp = CredentialBody::new("u").with_password("p");
        assert_eq!(bp.password_plain(), Some("p"));
        assert!(bp.key.is_none());
        assert!(!bp.keyring);
        let bk = CredentialBody::new("u").with_key("/k");
        assert_eq!(
            bk.key.as_ref().and_then(KeySource::as_path),
            Some(std::path::Path::new("/k"))
        );
        assert!(bk.password.is_none());
    }

    #[test]
    fn parses_reference_auth_by_id() {
        let cid = Ulid::from_string("01HXYZ0000000000000000000Z").unwrap();
        let input = format!(
            r#"
[[hosts]]
id = "01HXYZ000000000000000000A1"
name = "web1"
host = "10.0.0.5"
auth = {{ credential = "{cid}" }}

[[credentials]]
id = "{cid}"
name = "team-dev"
user = "deploy"
key = "~/.ssh/team_ed25519"
"#
        );
        let cfg: SshrackConfig = toml::from_str(&input).unwrap();
        let h = cfg.find_host_by_name("web1").unwrap();
        assert_eq!(h.auth.credential_id(), Some(cid));
        assert!(h.auth.inline_body().is_none());
        let c = cfg.find_credential_by_id(&cid).unwrap();
        assert_eq!(c.name, "team-dev");
        assert_eq!(c.body.user, "deploy");
        assert_eq!(
            c.body.key.as_ref().and_then(KeySource::as_path),
            Some(std::path::Path::new("~/.ssh/team_ed25519"))
        );
    }

    #[test]
    fn parses_inline_password_auth() {
        let input = r#"
[[hosts]]
id = "01HXYZ0000000000000000000A"
name = "db"
host = "db.example.com"
auth = { user = "postgres", password = "s3cret" }
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        let body = cfg
            .find_host_by_name("db")
            .unwrap()
            .auth
            .inline_body()
            .unwrap();
        assert_eq!(body.user, "postgres");
        assert_eq!(body.password_plain(), Some("s3cret"));
        assert!(body.key.is_none());
    }

    #[test]
    fn parses_inline_key_auth() {
        let input = r#"
[[hosts]]
id = "01HXYZ0000000000000000000B"
name = "gw"
host = "gw.example.com"
auth = { user = "ops", key = "~/.ssh/gw_ed25519" }
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        let body = cfg
            .find_host_by_name("gw")
            .unwrap()
            .auth
            .inline_body()
            .unwrap();
        assert_eq!(body.secret_kind(), SecretKind::Key);
    }

    #[test]
    fn parses_default_auth_user_only() {
        let input = r#"
[[hosts]]
id = "01HXYZ0000000000000000000C"
name = "jump"
host = "jump.example.com"
auth = { user = "ec2-user" }
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        let body = cfg
            .find_host_by_name("jump")
            .unwrap()
            .auth
            .inline_body()
            .unwrap();
        assert_eq!(body.secret_kind(), SecretKind::Default);
        assert!(body.password.is_none());
        assert!(body.key.is_none());
    }

    #[test]
    fn port_defaults_to_22() {
        let input = r#"
[[hosts]]
id = "01HXYZ0000000000000000000D"
name = "mini"
host = "10.0.0.5"
auth = { user = "root" }
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        assert_eq!(cfg.find_host_by_name("mini").unwrap().port, 22);
    }

    #[test]
    fn round_trips_reference_and_inline() {
        let cid = crate::id::new_id();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: crate::id::new_id(),
                name: "web1".into(),
                host: "10.0.0.5".into(),
                port: 22,
                auth: Auth::reference(cid),
            }],
            credentials: vec![Credential {
                id: cid,
                name: "team-dev".into(),
                body: CredentialBody::new("deploy").with_password("p"),
            }],
            ..Default::default()
        };
        let s = toml::to_string(&cfg).unwrap();
        let back: SshrackConfig = toml::from_str(&s).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn reference_auth_serializes_to_credential_id() {
        let cid = Ulid::from_string("01HXYZ0000000000000000000Z").unwrap();
        let h = Host {
            id: crate::id::new_id(),
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::reference(cid),
        };
        let s = toml::to_string(&h).unwrap();
        assert!(
            s.contains(&format!("credential = \"{cid}\"")),
            "expected ref-by-id in TOML, got: {s}"
        );
        assert!(!s.contains("credential = \"web1\""));
    }

    #[test]
    fn body_validate_rejects_both_password_and_key() {
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Plain("p".into())),
            key: Some(KeySource::Path(PathBuf::from("/k"))),
            keyring: false,
        };
        assert!(matches!(
            body.validate(),
            Err(SshrackError::InvalidCredentialBody { .. })
        ));
    }

    #[test]
    fn body_validate_accepts_each_single_and_default() {
        assert!(CredentialBody::new("u").validate().is_ok());
        assert!(
            CredentialBody::new("u")
                .with_password("p")
                .validate()
                .is_ok()
        );
        assert!(CredentialBody::new("u").with_key("/k").validate().is_ok());
    }

    #[test]
    fn secret_kind_matches_set_secret() {
        assert_eq!(CredentialBody::new("u").secret_kind(), SecretKind::Default);
        assert_eq!(
            CredentialBody::new("u").with_password("p").secret_kind(),
            SecretKind::Password
        );
        assert_eq!(
            CredentialBody::new("u").with_key("/k").secret_kind(),
            SecretKind::Key
        );
    }

    // ---- KeySource: untagged serde keeps `key = "/path"` binary-compatible ----

    #[test]
    fn keysource_path_round_trips_as_bare_string() {
        // The untagged enum must serialize Path back to a bare TOML string so the
        // on-disk shape is unchanged for path keys (and pre-existing configs parse).
        let body = CredentialBody::new("u").with_key("/home/me/.ssh/id_ed25519");
        let toml = toml::to_string(&body).unwrap();
        assert!(
            toml.contains("key = \"/home/me/.ssh/id_ed25519\""),
            "Path key must round-trip as a bare string, got:\n{toml}"
        );
        // And parse straight back.
        let back: CredentialBody = toml::from_str(&toml).unwrap();
        assert!(matches!(back.key, Some(KeySource::Path(_))));
    }

    #[test]
    fn keysource_legacy_bare_string_parses_as_path() {
        // A pre-feature config writes `key = "/old/path"`. That must parse into
        // KeySource::Path with no migration step and no format_version bump.
        let toml = r#"user = "deploy"
key = "/old/path"
"#;
        let body: CredentialBody = toml::from_str(toml).unwrap();
        assert_eq!(
            body.key.as_ref().and_then(|k| match k {
                KeySource::Path(p) => Some(p.to_string_lossy().into_owned()),
                _ => None,
            }),
            Some("/old/path".to_string())
        );
    }

    #[test]
    fn keysource_inline_round_trips_via_plain_secret() {
        let body = CredentialBody::new("u").with_inline_key(
            Secret::Plain("PRIV".into()),
            Some(Secret::Plain("CERT".into())),
        );
        let toml = toml::to_string(&body).unwrap();
        let back: CredentialBody = toml::from_str(&toml).unwrap();
        match &back.key {
            Some(KeySource::Inline(ik)) => {
                assert_eq!(
                    ik.private_key.as_ref().and_then(Secret::as_plain),
                    Some("PRIV")
                );
                assert_eq!(
                    ik.certificate.as_ref().and_then(Secret::as_plain),
                    Some("CERT")
                );
            }
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn keysource_debug_redacts_inline_contents() {
        // Key material must never survive {:?} formatting.
        let body =
            CredentialBody::new("u").with_inline_key(Secret::Plain("SUPERSECRET".into()), None);
        let dbg = format!("{:?}", body.key);
        assert!(
            !dbg.contains("SUPERSECRET"),
            "Debug leaked inline key text: {dbg}"
        );
    }

    // ---- validate: mutex incl. Inline + keyring-mode rejection ----

    #[test]
    fn validate_rejects_inline_key_under_keyring_mode_marker() {
        // The top-level `keyring = true` marker means "the password is in the OS
        // keyring". Inline key contents are not supported in keyring mode (see plan
        // design note), so the combination is a malformed body.
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: Some(Secret::Plain("k".into())),
                certificate: None,
                keyring: true,
            })),
            keyring: false,
        };
        assert!(body.validate().is_err());
    }

    #[test]
    fn validate_accepts_inline_key_in_keyring_marker_form() {
        // A keyring-stored inline key carries no in-body secret text — private_key
        // and certificate are both None, and ik.keyring marks their residence in
        // the OS keyring. This is the sealed form produced under keyring mode and
        // must pass validation.
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: None,
                certificate: None,
                keyring: true,
            })),
            keyring: false,
        };
        assert!(body.validate().is_ok());
    }

    #[test]
    fn validate_rejects_plaintext_inline_key_under_keyring_marker() {
        // The marker must never coexist with in-body plaintext: that is a
        // half-migrated body (text not yet moved to the keyring). Reject it as a
        // malformed body.
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: Some(Secret::Plain("k".into())),
                certificate: None,
                keyring: true,
            })),
            keyring: false,
        };
        assert!(body.validate().is_err());
    }

    #[test]
    fn validate_accepts_inline_key_without_keyring_marker() {
        let body = CredentialBody::new("u").with_inline_key(Secret::Plain("k".into()), None);
        assert!(body.validate().is_ok());
    }

    #[test]
    fn validate_rejects_password_and_inline_key_together() {
        let mut body = CredentialBody::new("u").with_password("p");
        body.key = Some(KeySource::Inline(InlineKey {
            private_key: Some(Secret::Plain("k".into())),
            certificate: None,
            keyring: false,
        }));
        assert!(body.validate().is_err());
    }

    // ---- secret_kind: Path and Inline both report Key ----

    #[test]
    fn secret_kind_is_key_for_inline_keysource() {
        let body = CredentialBody::new("u").with_inline_key(Secret::Plain("k".into()), None);
        assert_eq!(body.secret_kind(), SecretKind::Key);
    }

    #[test]
    fn find_credential_returns_none_when_absent() {
        let cfg = SshrackConfig::default();
        assert!(cfg.find_credential_by_name("nope").is_none());
        let id = crate::id::new_id();
        assert!(cfg.find_credential_by_id(&id).is_none());
    }

    #[test]
    fn find_host_by_id_and_credential_by_id_hit() {
        let hid = crate::id::new_id();
        let cid = crate::id::new_id();
        let cfg = SshrackConfig {
            hosts: vec![Host {
                id: hid,
                name: "h".into(),
                host: "x".into(),
                port: 22,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            credentials: vec![Credential {
                id: cid,
                name: "c".into(),
                body: CredentialBody::new("u"),
            }],
            ..Default::default()
        };
        assert_eq!(cfg.find_host_by_id(&hid).unwrap().name, "h");
        assert_eq!(cfg.find_credential_by_id(&cid).unwrap().name, "c");
        // Wrong id misses.
        let other = crate::id::new_id();
        assert!(cfg.find_host_by_id(&other).is_none());
        assert!(cfg.find_credential_by_id(&other).is_none());
    }

    #[test]
    fn secret_plain_round_trips_through_toml() {
        let body = CredentialBody::new("u").with_password("hunter2");
        let s = toml::to_string(&body).unwrap();
        // Plaintext serializes as a bare string (untagged variant).
        assert!(s.contains("password = \"hunter2\""));
        let back: CredentialBody = toml::from_str(&s).unwrap();
        assert_eq!(back.password_plain(), Some("hunter2"));
    }

    #[test]
    fn plaintext_mode_toml_deserializes_as_plain() {
        // Plaintext mode stores a bare string; it round-trips through Plain.
        let input = r#"
[[credentials]]
id = "01HXYZ00000000000000000002"
name = "team"
user = "deploy"
password = "s3cret"
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        assert_eq!(cfg.credentials[0].body.password_plain(), Some("s3cret"));
    }

    #[test]
    fn encrypted_secret_round_trips() {
        use crate::config::schema::EncryptedSecret;
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Encrypted(EncryptedSecret {
                nonce: "bm9uY2U=".into(),
                cipher: "Y2lwaGVy".into(),
            })),
            key: None,
            keyring: false,
        };
        let s = toml::to_string(&body).unwrap();
        let back: CredentialBody = toml::from_str(&s).unwrap();
        match back.password {
            Some(Secret::Encrypted(e)) => {
                assert_eq!(e.nonce, "bm9uY2U=");
                assert_eq!(e.cipher, "Y2lwaGVy");
            }
            other => panic!("expected Encrypted, got {other:?}"),
        }
        // No plaintext leaks to disk for an encrypted body.
        assert!(!s.contains("s3cret"));
    }

    #[test]
    fn vault_meta_default_is_argon2id_with_30min_cache() {
        let m = VaultMeta::default_argon2id("AA==");
        assert_eq!(m.kdf, "argon2id");
        assert_eq!(m.cache_ttl_secs, VaultMeta::DEFAULT_CACHE_TTL_SECS);
        assert_eq!(m.cache_ttl_secs, 1800);
        assert!(m.m > 0 && m.t > 0 && m.p > 0);
    }

    #[test]
    fn sshrack_config_round_trips_vault_and_acknowledgement() {
        use crate::config::schema::SecretStore;
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: VaultMeta::default_argon2id("AA=="),
            }),
            ..Default::default()
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(s.contains("[store]"));
        let back: SshrackConfig = toml::from_str(&s).unwrap();
        assert!(back.is_vault());
        assert!(!matches!(back.store, Some(SecretStore::Plaintext)));
    }

    #[test]
    fn empty_config_has_no_vault_and_unacknowledged() {
        let cfg = SshrackConfig::default();
        assert!(!cfg.is_vault());
        assert!(!cfg.mode_chosen());
    }

    #[test]
    fn secret_store_round_trips_all_modes() {
        use crate::config::schema::{SecretStore, VaultMeta};
        // Plaintext
        let p = SecretStore::Plaintext;
        let s = toml::to_string(&p).unwrap();
        let back: SecretStore = toml::from_str(&s).unwrap();
        assert_eq!(back, p);
        // Vault (flatten meta into the [store] table)
        let v = SecretStore::Vault {
            meta: VaultMeta::default_argon2id("AA=="),
        };
        let s = toml::to_string(&v).unwrap();
        assert!(s.contains("mode = \"vault\""));
        assert!(s.contains("kdf = \"argon2id\""));
        let back: SecretStore = toml::from_str(&s).unwrap();
        assert_eq!(back, v);
        // Keyring
        let k = SecretStore::Keyring;
        let s = toml::to_string(&k).unwrap();
        assert!(s.contains("mode = \"keyring\""));
        let back: SecretStore = toml::from_str(&s).unwrap();
        assert_eq!(back, k);
    }

    #[test]
    fn sshrack_config_undecided_has_no_store_table() {
        let cfg = SshrackConfig::default();
        assert!(!cfg.mode_chosen());
        assert!(!cfg.is_vault());
        let s = toml::to_string(&cfg).unwrap();
        assert!(
            !s.contains("[store]"),
            "undecided config must not serialize a store table"
        );
    }

    #[test]
    fn keyring_marker_round_trips_and_defaults_false() {
        // `keyring = true` marks a body whose plaintext lives in the OS keyring;
        // it round-trips and serializes only when true.
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        let s = toml::to_string(&body).unwrap();
        assert!(s.contains("keyring = true"), "serialized: {s}");
        let back: CredentialBody = toml::from_str(&s).unwrap();
        assert!(back.keyring);
        // Default-constructed body has no keyring marker.
        assert!(!CredentialBody::new("u").keyring);
        // A false marker is skipped on serialization.
        let s2 = toml::to_string(&CredentialBody::new("u")).unwrap();
        assert!(!s2.contains("keyring"));
    }

    #[test]
    fn keyring_marker_parses_from_toml() {
        let input = r#"
[[credentials]]
id = "01HXYZ00000000000000000003"
name = "team"
user = "deploy"
keyring = true
"#;
        let cfg: SshrackConfig = toml::from_str(input).unwrap();
        assert!(cfg.credentials[0].body.keyring);
    }

    #[test]
    fn validate_rejects_keyring_with_password() {
        let body = CredentialBody {
            user: "u".into(),
            password: Some(Secret::Plain("p".into())),
            key: None,
            keyring: true,
        };
        assert!(matches!(
            body.validate(),
            Err(SshrackError::InvalidCredentialBody { .. })
        ));
    }

    #[test]
    fn validate_rejects_keyring_with_key() {
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Path(PathBuf::from("/k"))),
            keyring: true,
        };
        assert!(matches!(
            body.validate(),
            Err(SshrackError::InvalidCredentialBody { .. })
        ));
    }

    #[test]
    fn validate_accepts_keyring_alone() {
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        assert!(body.validate().is_ok());
    }

    #[test]
    fn secret_kind_keyring_when_marker_set() {
        let body = CredentialBody {
            user: "u".into(),
            password: None,
            key: None,
            keyring: true,
        };
        assert_eq!(body.secret_kind(), SecretKind::KeyringPassword);
    }

    #[test]
    fn secret_debug_redacts_plain_password() {
        // Plain must never leak its plaintext through Debug — passwords must
        // not appear in logs or error messages.
        let plain = Secret::Plain("hunter2".into());
        let dbg = format!("{plain:?}");
        assert!(!dbg.contains("hunter2"), "Debug leaked plaintext: {dbg}");
        assert!(dbg.contains("redacted"), "missing redaction marker: {dbg}");
    }

    #[test]
    fn secret_debug_keeps_encrypted_fields() {
        // Encrypted payloads (base64 nonce/cipher) are not sensitive — Debug
        // surfaces them for diagnostics.
        let enc = Secret::Encrypted(EncryptedSecret {
            nonce: "bm9uY2U=".into(),
            cipher: "Y2lwaGVy".into(),
        });
        let dbg = format!("{enc:?}");
        assert!(dbg.contains("Encrypted"), "missing variant tag: {dbg}");
        assert!(dbg.contains("bm9uY2U="), "missing nonce field: {dbg}");
        assert!(dbg.contains("Y2lwaGVy"), "missing cipher field: {dbg}");
        assert!(
            !dbg.contains("redacted"),
            "encrypted should not be redacted: {dbg}"
        );
    }

    #[test]
    fn sshrack_config_vault_store_round_trips() {
        use crate::config::schema::{SecretStore, VaultMeta};
        let cfg = SshrackConfig {
            store: Some(SecretStore::Vault {
                meta: VaultMeta::default_argon2id("AA=="),
            }),
            ..SshrackConfig::default()
        };
        let s = toml::to_string(&cfg).unwrap();
        assert!(s.contains("[store]"));
        let back: SshrackConfig = toml::from_str(&s).unwrap();
        assert!(back.is_vault());
        assert!(back.vault_meta().is_some());
    }
}
