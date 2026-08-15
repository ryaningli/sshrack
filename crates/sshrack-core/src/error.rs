//! Crate-wide error type for the sshrack core library.

use std::fmt;

use thiserror::Error;

/// Renders a `(did you mean '…'?)` hint after a not-found error, or nothing
/// when there is no suggestion. Carried by [`SshrackError::HostNotFound`] and
/// [`SshrackError::CredentialNotFound`]; built by `host::host_not_found` /
/// `credential::credential_not_found` from a [`crate::suggest`] lookup.
#[derive(Debug, Clone)]
pub struct DidYouMean(Option<String>);

impl DidYouMean {
    /// No suggestion — renders as the empty string.
    pub fn none() -> Self {
        Self(None)
    }

    /// Build from an optional suggestion borrowed from the config.
    pub fn from_option(opt: Option<&str>) -> Self {
        Self(opt.map(str::to_owned))
    }
}

impl fmt::Display for DidYouMean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(suggestion) => write!(f, " (did you mean '{suggestion}'?)"),
            None => Ok(()),
        }
    }
}

/// Errors returned by sshrack library modules.
#[derive(Debug, Error)]
pub enum SshrackError {
    #[error("missing host name — usage: sshrack ssh <name> [command...]")]
    NoCommand,

    /// The user cancelled an interactive prompt (Ctrl+C). Handled silently at
    /// the top level — never printed — so cancelling a prompt exits quietly
    /// with status 130 instead of a noisy `io error: read interrupted`.
    #[error("interrupted by user")]
    Interrupted,

    #[error("missing required field: {field}")]
    MissingRequiredField { field: &'static str },

    #[error("host name not found: {name}{hint}")]
    HostNotFound { name: String, hint: DidYouMean },

    #[error("name '{name}' must not contain {ch:?}")]
    InvalidNameChar { name: String, ch: char },

    #[error("invalid ssh args: {reason}")]
    InvalidSshArgs { reason: String },

    #[error("host name already exists: {name} (use --force to overwrite)")]
    HostAlreadyExists { name: String },

    #[error("name '{name}' is already used")]
    NameTaken { name: String },

    #[error("credential name not found: {name}{hint}")]
    CredentialNotFound { name: String, hint: DidYouMean },

    #[error("credential name already exists: {name} (use --force to overwrite)")]
    CredentialAlreadyExists { name: String },

    #[error("credential body for user '{user}' must set at most one of password/key")]
    InvalidCredentialBody { user: String },

    #[error("failed to read config file {path}: {source}")]
    ConfigRead {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    ConfigParse {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("failed to serialize config to {path}: {source}")]
    ConfigSerialize {
        path: std::path::PathBuf,
        #[source]
        source: toml::ser::Error,
    },

    #[error("failed to write config file {path}: {source}")]
    ConfigWrite {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("askpass: no password file path in environment ({env})")]
    AskpassNoFile { env: &'static str },

    #[error("askpass: failed to read password file {path}: {source}")]
    AskpassRead {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("askpass: password file contents were not valid UTF-8")]
    AskpassEncoding,

    #[error("askpass: failed to write password file {path}: {source}")]
    AskpassWrite {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Plaintext-mode config channel: `SSHRACK_HOST_ID` did not parse as a
    /// ULID. `raw` is the offending value (never a secret — it is a routing
    /// label set by the parent sshrack process, not user input).
    #[error("askpass: malformed host id {raw:?}")]
    AskpassBadHostId { raw: String },

    /// Plaintext-mode config channel: the host id parsed but no host with that
    /// id is present in the config. `id` is the ULID string (never a secret).
    #[error("askpass: host {id:?} not found in config")]
    AskpassHostMissing { id: String },

    /// Plaintext-mode config channel: the host exists but has no plaintext
    /// password (key-only, keyring-marked, or an encrypted vault body the
    /// helper cannot read without the master key). `id` is the ULID string.
    #[error("askpass: host {id:?} has no plaintext password in config")]
    AskpassNoPlaintextPassword { id: String },

    /// Plaintext-mode config channel: neither `SSHRACK_CONFIG` nor the XDG
    /// default config path could be resolved (no home/config directory). The
    /// parent must set `SSHRACK_CONFIG` in that environment.
    #[error("askpass: could not resolve the config file path")]
    AskpassNoConfigPath,

    /// The SFTP master pointed the helper here with `SSHRACK_ASKPASS_DENY` set:
    /// the TUI owns the tty, so the helper refuses to prompt and ssh must fail
    /// the auth immediately. Carries no secret.
    #[error("askpass denied: SFTP session has no password configured")]
    AskpassDenied,

    #[error("failed to resolve path to this binary: {source}")]
    SelfExe {
        #[source]
        source: std::io::Error,
    },

    #[error("home directory not found; cannot locate ~/.ssh/known_hosts")]
    NoKnownHostsPath,

    #[error(
        "host key for '{host}' is not confirmed — connect manually first or remove the entry with ssh-keygen -R '{host}'"
    )]
    HostKeyNotConfirmed { host: String },

    #[error("ssh-keyscan failed for '{host}' (is the host reachable on that port?)")]
    HostKeyScanFailed { host: String },

    #[error("ssh-keyscan returned no host keys for '{host}'")]
    HostKeyScanEmpty { host: String },

    /// The vault holds encrypted passwords but no master key was provided
    /// (no `sshrack store unlock` and no `SSHRACK_PASSPHRASE`). Surface to the
    /// user as a "run unlock" hint, never with the underlying secret.
    #[error("vault is locked — run `sshrack store unlock` or provide SSHRACK_PASSPHRASE")]
    VaultLocked,

    /// The passphrase did not match the vault's verifier, or the vault
    /// metadata (salt, KDF params, base64) was corrupt. No name attached —
    /// unlock failure is vault-wide, not per-credential.
    #[error("failed to unlock vault (wrong passphrase or corrupted vault metadata)")]
    VaultUnlockFailed,

    /// XChaCha20-Poly1305 encryption or nonce generation failed for a single
    /// password. Never carries a per-credential name; the transform layer
    /// surfaces this where the name is known.
    #[error("failed to encrypt a password")]
    EncryptionFailed,

    /// Decryption (or base64/nonce decode) failed for one credential. The
    /// `name` names *which* credential failed — never the secret itself.
    #[error("failed to decrypt password for credential '{name}'")]
    DecryptionFailed { name: String },

    /// A vault operation was attempted (e.g. lock, rekey) but no vault is
    /// configured. Tell the user to run `sshrack store use vault` first.
    #[error("vault is not enabled — run `sshrack store use vault` first")]
    VaultNotEnabled,

    /// A password was about to be sealed but no storage mode has been chosen
    /// yet (`[store] mode` unset). Sealing with `cfg.store == None` would
    /// silently store the password in the clear (plaintext), which is a choice
    /// the user must make explicitly. The interactive paths (the credential
    /// wizard) surface this instead of picking a mode on the user's behalf.
    #[error("no storage mode chosen — run `sshrack store use <keyring|vault|plaintext>` first")]
    StoreModeNotDecided,

    /// `store config` was given a field name that is not a tunable vault field.
    /// `field` is the offending name; it is never a secret.
    #[error("unknown vault config field '{field}'")]
    UnknownVaultField { field: String },

    /// `store config set` received a value that fails the field's validation.
    /// `field` is the kebab-case field name, `value` the rejected input, and
    /// `hint` the expected shape. None of these carry secrets.
    #[error("invalid value '{value}' for vault field '{field}': {hint}")]
    InvalidVaultFieldValue {
        field: &'static str,
        value: String,
        hint: &'static str,
    },

    /// `host ls --fields` / `cred ls --fields` was given a name that is not a
    /// valid column. `field` is the offending name; `available` lists the valid
    /// fields. Never carries a secret.
    #[error("unknown field '{field}' — valid fields: {available}")]
    UnknownField { field: String, available: String },

    /// Reading or writing the master-key cache file failed. `path` is the
    /// cache file; `source` is the underlying io error. The cache is best-effort
    /// so callers usually log-and-continue rather than propagating this.
    #[error("failed to read/write master-key cache {path}: {source}")]
    CacheIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The OS keyring backend is unavailable (no Secret Service daemon, locked
    /// keychain, etc.). Surfaced when keyring mode is active but the backend
    /// cannot be reached. Carries no secret.
    #[error(
        "OS keyring unavailable — start a Secret Service daemon (e.g. gnome-keyring) or switch modes"
    )]
    KeyringUnavailable,

    /// A keyring read/write/delete failed for a reason other than a missing
    /// entry. `detail` is the backend's category ("read"/"write"/"delete"),
    /// never a secret.
    #[error("keyring error: {detail}")]
    KeyringIo { detail: &'static str },

    /// The askpass helper was pointed at a keyring entry (`SSHRACK_KEYRING_KEY`)
    /// that does not exist. `key` is the id-derived account label (`host:<ulid>`
    /// or `cred:<ulid>`) — a non-sensitive routing label, never the secret.
    /// Surfaced by the askpass helper when [`crate::secret::keyring::get`] returns
    /// `Ok(None)`.
    #[error("askpass: no keyring entry for '{key}'")]
    KeyringNoEntry { key: String },

    /// A generic I/O failure from an interactive prompt or terminal read.
    /// The Display names only the category ("io error"); the underlying
    /// `io::Error` is the `source`, so a chain-walking renderer (anyhow
    /// `{:#}` in `main.rs`) prints the detail exactly once. Inlining `{0}`
    /// here would duplicate it (`io error: boom: boom`).
    #[error("io error")]
    Io(#[from] std::io::Error),

    /// The SFTP worker failed to open: the master `ssh -N` spawn failed, the
    /// handshake timed out, or the worker thread could not be spawned. `detail`
    /// is the worker's human-readable failure string; it never carries a secret
    /// (the worker never puts passwords in error messages).
    #[error("sftp open failed: {detail}")]
    SftpOpenFailed { detail: String },
}

impl SshrackError {
    /// Convert an io error raised by a TUI prompt (crossterm-based).
    ///
    /// A Ctrl+C surfaces from the terminal layer as
    /// [`std::io::ErrorKind::Interrupted`]; map that to the silent
    /// [`SshrackError::Interrupted`] cancel rather than a noisy io failure.
    /// Anything else is a genuine io error. Accepts any `Into<io::Error>` so
    /// both prompt-layer errors and raw `io::Error` map in one step, letting
    /// call sites drop their per-module `io_err` helpers.
    pub fn from_prompt_io(error: impl Into<std::io::Error>) -> Self {
        let error = error.into();
        if error.kind() == std::io::ErrorKind::Interrupted {
            Self::Interrupted
        } else {
            Self::Io(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_prompt_io_interrupted_is_cancel() {
        let e = SshrackError::from_prompt_io(std::io::Error::from(std::io::ErrorKind::Interrupted));
        assert!(matches!(e, SshrackError::Interrupted));
    }

    #[test]
    fn from_prompt_io_other_is_io() {
        let e = SshrackError::from_prompt_io(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(e, SshrackError::Io(_)));
    }

    #[test]
    fn io_variant_does_not_inline_source_display() {
        // The Display must name only the failure category; the underlying
        // `io::Error` is the `source` and carries the detail. A chain-walking
        // renderer (anyhow `{:#}` in `main.rs`) prints `io error: <source>`
        // exactly once. Inlining `{0}` would yield `io error: boom: boom`.
        let e = SshrackError::Io(std::io::Error::other("boom"));
        assert_eq!(e.to_string(), "io error");
        assert_eq!(std::error::Error::source(&e).unwrap().to_string(), "boom");
    }

    #[test]
    fn did_you_mean_none_is_empty() {
        assert_eq!(DidYouMean::none().to_string(), "");
    }

    #[test]
    fn did_you_mean_some_renders_hint() {
        let s = DidYouMean::from_option(Some("ets-pc")).to_string();
        assert_eq!(s, " (did you mean 'ets-pc'?)");
    }

    #[test]
    fn host_not_found_displays_with_hint() {
        let e = SshrackError::HostNotFound {
            name: "ets-pcc".into(),
            hint: DidYouMean::from_option(Some("ets-pc")),
        };
        assert_eq!(
            e.to_string(),
            "host name not found: ets-pcc (did you mean 'ets-pc'?)"
        );
    }

    #[test]
    fn credential_not_found_displays_without_hint() {
        let e = SshrackError::CredentialNotFound {
            name: "ghost".into(),
            hint: DidYouMean::none(),
        };
        assert_eq!(e.to_string(), "credential name not found: ghost");
    }

    #[test]
    fn vault_errors_never_leak_secrets() {
        let variants = [
            SshrackError::VaultLocked.to_string(),
            SshrackError::VaultUnlockFailed.to_string(),
            SshrackError::EncryptionFailed.to_string(),
            SshrackError::DecryptionFailed {
                name: "team".into(),
            }
            .to_string(),
            SshrackError::VaultNotEnabled.to_string(),
            SshrackError::UnknownVaultField {
                field: "cache-ttl-secs".into(),
            }
            .to_string(),
            SshrackError::InvalidVaultFieldValue {
                field: "cache-ttl-secs",
                value: "abc".into(),
                hint: "expected a number",
            }
            .to_string(),
        ];
        let forbidden = ["hunter2", "s3cret", "password123"];
        for msg in variants {
            for word in forbidden {
                assert!(!msg.contains(word), "error leaks secret: {msg}");
            }
        }
    }

    #[test]
    fn keyring_errors_never_leak_secrets() {
        let msgs = [
            SshrackError::KeyringUnavailable.to_string(),
            SshrackError::KeyringIo { detail: "dbus" }.to_string(),
            SshrackError::KeyringNoEntry {
                key: "host:web1".into(),
            }
            .to_string(),
        ];
        for m in msgs {
            assert!(!m.contains("hunter2") && !m.contains("password"));
        }
    }

    #[test]
    fn keyring_no_entry_names_key_not_secret() {
        // The variant carries only the keyring account key (a non-sensitive
        // host:/cred: label), never the secret. The label must appear so users
        // know which entry is missing.
        let e = SshrackError::KeyringNoEntry {
            key: "cred:team-dev".into(),
        };
        let msg = e.to_string();
        assert!(
            msg.contains("cred:team-dev"),
            "msg should name the key: {msg}"
        );
        assert!(
            msg.contains("no keyring entry"),
            "msg should describe a missing entry: {msg}"
        );
    }

    #[test]
    fn decryption_failed_names_credential() {
        let e = SshrackError::DecryptionFailed {
            name: "team".into(),
        };
        assert!(e.to_string().contains("team"));
    }

    #[test]
    fn unknown_field_displays_available() {
        let e = SshrackError::UnknownField {
            field: "xyz".into(),
            available: "name, host, port".into(),
        };
        assert_eq!(
            e.to_string(),
            "unknown field 'xyz' — valid fields: name, host, port"
        );
    }
}
