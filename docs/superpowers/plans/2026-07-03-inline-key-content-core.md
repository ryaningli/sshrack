# Inline Key Content (core + CLI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Let a credential (and an Independent host) carry a private key's **contents** — pasted text — not just a file path, so users no longer have to drop a key file on disk before adding it. Covers the data model, encrypted storage, connection-time materialization, encrypted-key passphrase fix, and CLI import. TUI pasting is a follow-up plan.

**Architecture:** Upgrade `CredentialBody.key` from `Option<PathBuf>` to `Option<KeySource>`, where `KeySource` is an `#[serde(untagged)]` enum (`Path(PathBuf)` | `Inline(InlineKey)`) so existing `key = "/path"` TOML parses unchanged (zero migration code). Inline key contents reuse the existing `Secret` (Plain/Encrypted) container, so vault/plaintext storage modes work with no new crypto. At connect time `resolve` returns the decrypted inline material on `ResolvedAuth`; the connect orchestration writes it to a `0600` temp file (`KeyArtifact`, RAII-deleted after `ssh` exits) and points `ssh -i` at it — leaving `build_argv` untouched. Separately, fix a pre-existing blind spot: encrypted private keys (even Path mode) currently fail because `SSH_ASKPASS_REQUIRE=force` makes ssh call our askpass helper, which has no payload; a key-only connection now leaves askpass unset so ssh falls back to `/dev/tty` to ask for the key passphrase.

**Tech Stack:** Rust 2024, MSRV 1.86, thiserror, zeroize, serde/toml. sshrack-core only for Tasks 1–4; the root `sshrack` binary for Task 5.

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, error messages, help text, commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. Process/PTY behavior is covered by integration tests.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords / key material are `Zeroizing<String>`/`Secret` end-to-end** — never logged, printed, embedded in errors, or placed in argv. (Inline private-key text is key material: treat it identically.)
- **`sshrack-core` zero-UI invariant** — Tasks 1–4 never touch `src/`; Task 5 touches `src/cli/` + `src/shared/` only (CLI is non-interactive). `sshrack-core/Cargo.toml` never lists UI crates.
- **Never reimplement SSH** — materialize key text to a temp file and let the system `ssh -i` read it; do not parse/decrypt key files ourselves (encrypted-key passphrase is answered by ssh itself at the tty).
- **CLI non-interactive** — never prompts; key contents come from stdin/file, never argv.
- **Tests hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Dev stage, no compat code** — replace outright; the untagged-serde trick below is the migration (no parallel old path).
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). No `Co-Authored-By`.

**Scope invariant:** Tasks 1–4 are in `crates/sshrack-core/`. Task 5 is in `src/cli/` + `src/shared/`. No TUI changes in this plan.

---

## Inventory (the contract this plan must satisfy)

| Concern | Today | After |
|---|---|---|
| `CredentialBody.key` | `Option<PathBuf>` (`config/schema.rs:154`) | `Option<KeySource>` |
| `with_key` builder | `with_key(impl Into<PathBuf>)` (`schema.rs:213`) | keeps `with_key(PathBuf)`; adds `with_inline_key(private, cert)` |
| `validate()` mutex | password/key/keyring three-way (`schema.rs:235`) | adds: Inline key is a secret; keyring mode rejects Inline |
| `secret_kind()` | returns `Key` when `key.is_some()` (`schema.rs:221`) | unchanged semantics (Path or Inline both → `Key`) |
| `seal_body` / `seal_auth` | seal password only (`vault/mod.rs:258,291`) | also seal Inline key's private_key/certificate |
| `count_secrets` | counts password secrets (`vault/transform.rs`) | also counts Inline key secrets |
| `resolve` | `body.key` (PathBuf) → `ResolvedAuth.key_path` (`credential.rs:459,472`) | Inline → decrypt → `ResolvedAuth.inline_key`; key_path stays None |
| `ResolvedAuth` | `{ user, key_path, password }` (`credential.rs:73`) | add `inline_key: Option<InlineKeyMaterial>` |
| connect launch | writes password temp file; asks ssh to use askpass (`connect/mod.rs:115`) | also materializes Inline key → temp file for `-i`; key-only drops askpass env |
| encrypted-key passphrase | **broken** (force-askpass, no payload) | key-only leaves askpass unset → ssh asks at `/dev/tty` |
| CLI `cred add`/`host add` | `--identity <path>` only | `--identity-stdin` / `--identity-file` (+ cert variants) |
| `ls`/`show` rendering | `b.key.as_deref()` (`format.rs:186`) | Path → path; Inline → masked `[inline]` |

---

## Task 1: `KeySource` model + untagged serde + validate mutex

**Files:**
- Modify: `crates/sshrack-core/src/config/schema.rs` (CredentialBody, new KeySource/InlineKey, validate, with_key, with_inline_key, secret_kind)

**Interfaces:**
- Produces:
  - `pub enum KeySource { Path(PathBuf), Inline(InlineKey) }` (`#[serde(untagged)]`, `Debug` redacts Inline contents)
  - `pub struct InlineKey { pub private_key: Option<Secret>, pub certificate: Option<Secret>, pub keyring: bool }`
  - `CredentialBody.key: Option<KeySource>` (replaces `Option<PathBuf>`)
  - `CredentialBody::with_key(impl Into<PathBuf>) -> Self` (unchanged signature; wraps as `KeySource::Path`)
  - `CredentialBody::with_inline_key(private: Secret, certificate: Option<Secret>) -> Self`
  - `CredentialBody::validate()` enforces: at most one of {password, key (Path or Inline), keyring marker}; **and** `keyring == true` is incompatible with `KeySource::Inline`.

- [ ] **Step 1: Write the failing tests (RED)**

Add to the `#[cfg(test)] mod tests` block in `schema.rs` (near the existing `with_key`/`secret_kind` tests around line 576–682):

```rust
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
    let body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("PRIV".into()), Some(Secret::Plain("CERT".into())));
    let toml = toml::to_string(&body).unwrap();
    let back: CredentialBody = toml::from_str(&toml).unwrap();
    match &back.key {
        Some(KeySource::Inline(ik)) => {
            assert_eq!(ik.private_key.as_ref().and_then(Secret::as_plain), Some("PRIV"));
            assert_eq!(ik.certificate.as_ref().and_then(Secret::as_plain), Some("CERT"));
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}

#[test]
fn keysource_debug_redacts_inline_contents() {
    // Key material must never survive {:?} formatting.
    let body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("SUPERSECRET".into()), None);
    let dbg = format!("{:?}", body.key);
    assert!(!dbg.contains("SUPERSECRET"), "Debug leaked inline key text: {dbg}");
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
fn validate_accepts_inline_key_without_keyring_marker() {
    let body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("k".into()), None);
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
    let body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("k".into()), None);
    assert_eq!(body.secret_kind(), SecretKind::Key);
}
```

- [ ] **Step 2: Run — expect compile failure (RED)**

```bash
cargo test -p sshrack-core --lib config::schema 2>&1 | head -30
```
Expected: fails to compile (`cannot find type KeySource` / `InlineKey` / `with_inline_key`).

- [ ] **Step 3: Implement — add the types, change `key`, update builders/validate**

In `crates/sshrack-core/src/config/schema.rs`, above the `CredentialBody` impl block, add (with doc comments stating Inline stores key *material* via `Secret`, redacted in Debug):

```rust
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
            .field("private_key", &self.private_key.as_ref().map(|_| "<redacted>"))
            .field("certificate", &self.certificate.as_ref().map(|_| "<redacted>"))
            .field("keyring", &self.keyring)
            .finish()
    }
}
```

Change the `CredentialBody.key` field type and add the inline builder:

```rust
    /// Identity key source: a path, or pasted inline contents. `None` when
    /// not used. Mutually exclusive with `password` and the `keyring` marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeySource>,
```

```rust
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
```

Update `validate()` to treat Inline as a secret and reject keyring+Inline. Replace the existing `secrets_set` count + check with:

```rust
    pub fn validate(&self) -> Result<(), SshrackError> {
        // Count the secret slots: password, any key (Path or Inline), and the
        // body-level keyring marker (password-in-keyring). At most one allowed.
        let key_present = self.key.is_some();
        let inline_keyring = matches!(
            self.key,
            Some(KeySource::Inline(ref ik)) if ik.keyring
        );
        let secrets_set = [self.password.is_some(), key_present, self.keyring]
            .into_iter()
            .filter(|b| *b)
            .count();
        if secrets_set > 1 {
            return Err(SshrackError::InvalidCredentialBody {
                user: self.user.clone(),
            });
        }
        // Inline key contents are not supported in keyring storage mode: the
        // body-level `keyring` marker or the Inline's own `keyring` flag both
        // mean "key text in the OS keyring", which this MVP does not implement.
        if inline_keyring
            || (matches!(self.key, Some(KeySource::Inline(_))) && self.keyring)
        {
            return Err(SshrackError::InlineKeyNeedsVaultOrPlaintext);
        }
        Ok(())
    }
```

`secret_kind()` already returns `Key` when `key.is_some()`; it needs no change (both Path and Inline satisfy `is_some()`). Leave the `new()` builder initializers setting `key: None` (type updates automatically). Update any other `CredentialBody { ... }` literal in the crate's tests to use the new `key` type if the compiler flags them (they are `#[cfg(test)]`, so adjust as needed).

- [ ] **Step 4: Add the new error variant**

In `crates/sshrack-core/src/error.rs`, add a variant (alphabetized near the other credential errors):

```rust
    /// An inline (pasted) identity key was given on a body in keyring storage
    /// mode, which is not supported. Inline keys require vault or plaintext
    /// storage. The message never includes key material.
    #[error("inline identity key requires vault or plaintext storage mode")]
    InlineKeyNeedsVaultOrPlaintext,
```

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack-core --lib config::schema
```
Expected: all schema tests pass.

- [ ] **Step 6: Fix the compile breakages this field-type change causes across the crate, but DO NOT change behavior yet**

`grep -rn "\.key\b\|body.key\|\.key =" crates/sshrack-core/src/` will find call sites in `credential.rs` (`resolve` reads `body.key`, `cred.body.key`), `vault/mod.rs` (`seal_body` passes `body.key` through), and tests. For this task, make them **compile without changing behavior**:
- In `credential::resolve` (`credential.rs:459,472`): the two `body.key.clone()` / `cred.body.key.clone()` currently feed `ResolvedAuth::from_plain(.., key_path, ..)` which expects `Option<PathBuf>`. For now, map a `KeySource::Path(p)` to `Some(p)` and `KeySource::Inline(_)` / `None` to `None` (Inline handling lands in Task 3). Keep `from_plain`'s signature (`Option<PathBuf>`) for this task.
- Leave `vault::seal_body` passing `key: body.key` through verbatim (sealing Inline lands in Task 2).

```bash
cargo build -p sshrack-core
```
Expected: clean build. (`cargo test --workspace` will have failures in `credential`/`vault` tests that assert on `key` — those are updated in Tasks 2–3; this task's own schema tests must pass.)

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): KeySource model for path or inline identity keys"
```

---

## Task 2: Seal/unseal inline key secrets + count them

**Files:**
- Modify: `crates/sshrack-core/src/secret/vault/mod.rs` (`seal_body`, `seal_auth`)
- Modify: `crates/sshrack-core/src/secret/vault/transform.rs` (`count_secrets`, add `finalize_secret`)
- Modify: `crates/sshrack-core/src/credential.rs` (`decrypt_secret` reused for key material)

**Interfaces:**
- Consumes: Task 1's `KeySource::Inline(InlineKey { private_key: Option<Secret>, certificate: Option<Secret>, .. })`, `Secret::Plain/Encrypted`, `transform::finalize_password`.
- Produces:
  - `pub fn finalize_secret(plain: &str, cfg: &SshrackConfig, key: Option<&VaultKey>) -> Result<Secret, SshrackError>` (in `transform.rs`; same body as `finalize_password` — encrypt bytes under vault, else plaintext — named separately to read clearly at call sites).
  - `seal_body` now also seals an Inline key's `private_key` and `certificate` when they are `Secret::Plain` (Plain → Encrypted under vault; plaintext mode leaves Plain; keyring-mode Inline was already rejected by `validate` in Task 1, so seal_body never sees it).
  - `count_secrets` counts Inline key secrets too (so store-mode switches/rekeys see them).

- [ ] **Step 1: Write the failing tests (RED)**

In `crates/sshrack-core/src/secret/vault/mod.rs` tests (mirror the existing `seal_body` test style near the bottom of the file):

```rust
#[test]
fn seal_body_encrypts_inline_private_key_and_certificate_under_vault() {
    use crate::config::schema::{InlineKey, KeySource, SecretStore};
    let (cfg, key) = vault_cfg(); // the existing helper that builds a Vault-mode cfg + key
    let body = CredentialBody::new("u").with_inline_key(
        Secret::Plain("PRIV-TEXT".into()),
        Some(Secret::Plain("CERT-TEXT".into())),
    );
    let sealed = seal_body(body, OwnerKind::Credential, &Ulid::new(), &cfg, Some(&key), &FakeBackend::new()).unwrap();
    match sealed.key {
        Some(KeySource::Inline(ik)) => {
            assert!(ik.private_key.unwrap().is_encrypted(), "private_key sealed");
            assert!(ik.certificate.unwrap().is_encrypted(), "certificate sealed");
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}

#[test]
fn seal_body_leaves_inline_key_plaintext_in_plaintext_mode() {
    use crate::config::schema::{KeySource, SecretStore};
    let cfg = plaintext_cfg(); // existing helper or build: store = Plaintext
    let body = CredentialBody::new("u").with_inline_key(Secret::Plain("PRIV".into()), None);
    let sealed = seal_body(body, OwnerKind::Credential, &Ulid::new(), &cfg, None, &FakeBackend::new()).unwrap();
    match sealed.key {
        Some(KeySource::Inline(ik)) => {
            assert_eq!(ik.private_key.unwrap().as_plain(), Some("PRIV"));
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}
```

In `transform.rs` tests:

```rust
#[test]
fn count_secrets_counts_inline_key_secrets() {
    use crate::config::schema::{Credential, CredentialBody};
    let cfg = SshrackConfig {
        credentials: vec![Credential {
            id: Ulid::new(), name: "ops".into(),
            body: CredentialBody::new("u")
                .with_inline_key(Secret::Plain("k".into()), Some(Secret::Plain("c".into()))),
        }],
        ..empty_config()
    };
    let (enc, plain, _keyring) = count_secrets(&cfg);
    // private_key + certificate = 2 plaintext secrets.
    assert_eq!((enc, plain), (0, 2));
}
```

(Use the existing test helpers in those files for `vault_cfg`/`plaintext_cfg`/`empty_config`; if a helper is missing, construct inline the way neighboring tests do.)

- [ ] **Step 2: Run — expect RED** (new tests fail: `finalize_secret` missing; Inline Plain not encrypted).

- [ ] **Step 3: Implement `finalize_secret`** in `transform.rs` (right after `finalize_password`):

```rust
/// Finalize one inline **key/cert** secret the same way [`finalize_password`]
/// finalizes a password: encrypt under vault when a key is present, else keep
/// plaintext. Separate name from `finalize_password` so call sites read as
/// "key material", not "password". Keyring mode is never reached here (an
/// inline key on a keyring-mode body is rejected by `CredentialBody::validate`
/// before sealing).
pub fn finalize_secret(
    plain: &str,
    cfg: &SshrackConfig,
    key: Option<&VaultKey>,
) -> Result<Secret, SshrackError> {
    // Identical logic to finalize_password; the duplication is intentional and
    // small, and avoids passing a "kind" flag that would couple these two
    // unrelated concerns.
    match (&cfg.store, key) {
        (Some(SecretStore::Vault { .. }), Some(k)) => {
            Ok(Secret::Encrypted(crypto::encrypt(plain.as_bytes(), k)?))
        }
        (Some(SecretStore::Vault { .. }), None) => Err(SshrackError::VaultLocked),
        _ => Ok(Secret::Plain(plain.to_string())),
    }
}
```

- [ ] **Step 4: Extend `seal_body` to seal an Inline key** in `vault/mod.rs`. Replace the body of `seal_body` so it also seals inline key material (Path passes through unchanged):

```rust
pub fn seal_body(
    body: CredentialBody,
    kind: OwnerKind,
    id: &Ulid,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<CredentialBody, SshrackError> {
    let password = match body.password {
        Some(Secret::Plain(ref p)) => seal_password(p, kind, id, cfg, vault_key, backend)?,
        other => other,
    };
    let key = match body.key {
        // Inline key material: re-host private_key + certificate per the mode.
        Some(KeySource::Inline(ik)) => Some(KeySource::Inline(seal_inline_key(ik, cfg, vault_key)?)),
        // A path reference or absent key passes through unchanged.
        other => other,
    };
    let keyring = password.is_none() && cfg.is_keyring();
    Ok(CredentialBody {
        user: body.user,
        password,
        key,
        keyring,
    })
}

/// Seal an inline key's freshly-collected plaintext secrets (private key, and
/// the optional certificate) per the active mode. Already-sealed (Encrypted)
/// secrets pass through. Keyring mode is rejected upstream by `validate`.
fn seal_inline_key(
    mut ik: InlineKey,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
) -> Result<InlineKey, SshrackError> {
    if let Some(Secret::Plain(ref p)) = ik.private_key {
        ik.private_key = Some(transform::finalize_secret(p, cfg, vault_key)?);
    }
    if let Some(Secret::Plain(ref c)) = ik.certificate {
        ik.certificate = Some(transform::finalize_secret(c, cfg, vault_key)?);
    }
    Ok(ik)
}
```

(`seal_auth` already delegates Inline bodies through `seal_body`, so it needs no change.)

- [ ] **Step 5: Extend `count_secrets`** in `transform.rs` to count Inline key secrets. Find the existing loop that maps bodies to `(encrypted, plaintext, keyring)` counts and add an arm for `KeySource::Inline`:

```rust
// Inside the per-body counting closure, after counting `body.password`:
if let Some(KeySource::Inline(ik)) = &body.key {
    if let Some(s) = &ik.private_key {
        count_one_secret(s, &mut encrypted, &mut plaintext);
    }
    if let Some(s) = &ik.certificate {
        count_one_secret(s, &mut encrypted, &mut plaintext);
    }
}
```

(Where `count_one_secret` is a tiny local helper — or inline the same `match` the existing password-counting code uses for `Secret::Encrypted`/`Plain`. Mirror the existing style exactly.)

- [ ] **Step 6: Run — pass**

```bash
cargo test -p sshrack-core --lib secret::vault && cargo test -p sshrack-core --lib secret::vault::transform
```
Expected: new + existing tests pass.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy -p sshrack-core --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): seal and count inline key secrets per store mode"
```

---

## Task 3: `resolve` carries inline material + `KeyArtifact` materialization

**Files:**
- Modify: `crates/sshrack-core/src/credential.rs` (`ResolvedAuth`, `resolve`, reuse `decrypt_secret`)
- Modify: `crates/sshrack-core/src/connect/mod.rs` (new `KeyArtifact` + `materialize_resolved_key` helper)

**Interfaces:**
- Consumes: Task 1's `KeySource::Inline(InlineKey)`, Task 2's sealed Inline secrets, `decrypt_secret`.
- Produces:
  - `pub struct InlineKeyMaterial { pub private: Zeroizing<String>, pub certificate: Option<Zeroizing<String>> }` (Debug redacts).
  - `ResolvedAuth` gains `pub inline_key: Option<InlineKeyMaterial>`.
  - `resolve` sets `inline_key` for an Inline KeySource (decrypting private/cert via `vault`) and leaves `key_path = None` for that arm; Path arm still sets `key_path` and leaves `inline_key = None`.
  - `pub struct KeyArtifact { ... }` with `pub fn write(private: &Zeroizing<String>, certificate: Option<&Zeroizing<String>>) -> Result<KeyArtifact, SshrackError>`, `pub fn private_path(&self) -> &Path`, and a `Drop` that best-effort deletes both temp files.
  - The connect orchestration (in `src/` — located in Task 3 Step 5) calls materialization before `build_argv` and holds the `KeyArtifact` across `launch`.

- [ ] **Step 1: Write the failing tests (RED)**

In `credential.rs` tests (extend the existing `resolve` tests near `password_source_debug_redacts_inline_plaintext`):

```rust
#[test]
fn resolve_path_key_sets_key_path_and_no_inline_material() {
    let host = host_with_inline_body(
        CredentialBody::new("u").with_key("/k/id"),
    );
    let cfg = empty_config_with_host(host.clone());
    let r = resolve(&host, &cfg, None).unwrap();
    assert_eq!(r.key_path.as_deref(), Some(std::path::Path::new("/k/id")));
    assert!(r.inline_key.is_none());
}

#[test]
fn resolve_inline_plain_key_materializes_decrypted_text() {
    use crate::config::schema::{InlineKey, KeySource};
    let mut body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("PRIV-TEXT".into()), Some(Secret::Plain("CERT-TEXT".into())));
    let host = host_with_inline_body(body.clone());
    let cfg = empty_config_with_host(host.clone());
    let r = resolve(&host, &cfg, None).unwrap();
    // Path stays None; the decrypted material rides on inline_key.
    assert!(r.key_path.is_none());
    let mat = r.inline_key.expect("inline material present");
    assert_eq!(mat.private.as_str(), "PRIV-TEXT");
    assert_eq!(mat.certificate.as_ref().map(|c| c.as_str()), Some("CERT-TEXT"));
}

#[test]
fn resolve_inline_encrypted_key_needs_vault_key() {
    // Encrypted inline key with no vault key -> VaultLocked (mirrors passwords).
    // Build an Encrypted inline body via vault::seal_body under vault mode, then
    // resolve with no key. (Use the existing vault_cfg() helper to encrypt.)
    // ... arrange an Encrypted InlineKey, then:
    let r = resolve(&host, &cfg, None);
    assert!(matches!(r, Err(SshrackError::VaultLocked)));
}

#[test]
fn inline_key_material_debug_redacts() {
    let m = InlineKeyMaterial {
        private: Zeroizing::new("SECRET".into()),
        certificate: None,
    };
    assert!(!format!("{:?}", m).contains("SECRET"));
}
```

(Use the existing test helpers `host_with_inline_body` / `empty_config_with_host` in `credential.rs` tests; if absent, construct a `Host` with `Auth::Inline(body)` and a `SshrackConfig` the way neighboring tests do.)

In `connect/mod.rs` tests:

```rust
#[test]
fn key_artifact_writes_private_and_cert_siblings_then_cleanup_removes_both() {
    use zeroize::Zeroizing;
    let priv_text = Zeroizing::new("PRIVATE-KEY-TEXT".into());
    let cert_text = Zeroizing::new("CERTIFICATE-TEXT".into());
    let paths: std::cell::RefCell<Vec<std::path::PathBuf>> = std::cell::RefCell::new(vec![]);
    {
        let a = KeyArtifact::write(&priv_text, Some(&cert_text)).unwrap();
        // ssh expects the cert at <private>-cert.pub in the same dir.
        let p = a.private_path().to_path_buf();
        assert!(p.exists());
        let cert_sibling = p.with_file_name(format!(
            "{}-cert.pub",
            p.file_name().unwrap().to_string_lossy()
        ));
        assert!(cert_sibling.exists(), "cert sibling must exist at {cert_sibling:?}");
        *paths.borrow_mut() = vec![p, cert_sibling];
        // Files carry the material.
        assert_eq!(std::fs::read_to_string(&paths.borrow()[0]).unwrap(), "PRIVATE-KEY-TEXT");
    }
    // After Drop (scope exit), both temp files are gone.
    for p in paths.borrow().iter() {
        assert!(!p.exists(), "temp file {p:?} should be removed after drop");
    }
}
```

- [ ] **Step 2: Run — expect RED** (`InlineKeyMaterial` / `KeyArtifact` missing; `resolve` doesn't set `inline_key`).

- [ ] **Step 3: Implement `InlineKeyMaterial` + extend `ResolvedAuth` + `resolve`** in `credential.rs`:

```rust
/// Decrypted inline key material, ready to be written to a temp file for
/// `ssh -i`. Carried on [`ResolvedAuth`] only when the body's key is an inline
/// ([`KeySource::Inline`]) source; a path source puts its path on
/// `key_path` instead. Both fields are `Zeroizing` so the plaintext is wiped
/// on drop. `Debug` redacts.
#[derive(Debug, Default)]
pub struct InlineKeyMaterial {
    /// Private-key text.
    pub private: Zeroizing<String>,
    /// Optional SSH certificate text.
    pub certificate: Option<Zeroizing<String>>,
}

impl InlineKeyMaterial {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineKeyMaterial")
            .field("private", &"<redacted>")
            .field("certificate", &self.certificate.is_some())
            .finish()
    }
}
```
(If the derived `Debug` above would leak, implement `Debug` manually to call `fmt_redacted`; the test `inline_key_material_debug_redacts` enforces it.)

Extend `ResolvedAuth`:
```rust
pub struct ResolvedAuth {
    pub user: String,
    pub key_path: Option<PathBuf>,
    pub password: PasswordSource,
    /// Decrypted inline key text when the body's key is pasted material; the
    /// connect layer writes it to a temp file and points `ssh -i` there. `None`
    /// for path-key / no-key bodies. Mutually exclusive with `key_path`.
    #[serde(skip)]   // ResolvedAuth is not serialized; field is for completeness.
    pub inline_key: Option<InlineKeyMaterial>,
}
```
Update `ResolvedAuth::from_plain` / `Default` to initialize `inline_key: None`.

In `resolve`, change the `key` handling: instead of mapping `body.key` straight to `key_path`, branch on `KeySource`:

```rust
    // Replace the current `key_path` derivation with:
    let (key_path, inline_key) = match key_source {
        None => (None, None),
        Some(crate::config::schema::KeySource::Path(p)) => (Some(p.clone()), None),
        Some(crate::config::schema::KeySource::Inline(ik)) => {
            // Decrypt private + cert (None/Plain need no key; Encrypted needs vault).
            let private = decrypt_secret(ik.private_key.as_ref(), vault, name_label)?;
            let certificate = decrypt_secret(ik.certificate.as_ref(), vault, name_label)?;
            let private = private.unwrap_or_else(|| Zeroizing::new(String::new()));
            (None, Some(InlineKeyMaterial { private, certificate }))
        }
    };
```
(Where `key_source` is the value previously bound to `body.key.clone()` / `cred.body.key.clone()` in the `match &host.auth` arms — keep those arms returning `key_source` instead of `key_path`, then derive `key_path`/`inline_key` as above. `from_plain`'s mutex check still runs on `(key_path.is_some(), password)`; an Inline body has `key_path = None` so the key+password mutex is enforced by `body.validate()` upstream — which Task 1 already guarantees.)

- [ ] **Step 4: Implement `KeyArtifact`** in `connect/mod.rs` (next to `write_password_file`):

```rust
/// Temp files holding a pasted identity key, written so `ssh -i` can read them.
/// `Drop` best-effort deletes both files so the plaintext does not outlive the
/// ssh process. The private key is `0600`; the certificate sits beside it as
/// `<private>-cert.pub` (the OpenSSH auto-load convention). The paths embed the
/// pid + nanos so concurrent connections never collide.
pub struct KeyArtifact {
    private: PathBuf,
    cert: Option<PathBuf>,
}

impl KeyArtifact {
    /// Write `private` (and an optional `certificate`) to fresh `0600` temp
    /// files in the std temp dir. Returns the artifact; dropping it removes the
    /// files. The private path is what the caller passes to `ssh -i`.
    pub fn write(
        private: &Zeroizing<String>,
        certificate: Option<&Zeroizing<String>>,
    ) -> Result<Self, SshrackError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let private_path = std::env::temp_dir().join(format!(
            "sshrack-key-{}-{}.pem",
            std::process::id(),
            nanos,
        ));
        let write_err = |source: std::io::Error| SshrackError::AskpassWrite {
            path: private_path.clone(),
            source,
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&private_path)
            .map_err(write_err)?;
        f.write_all(private.as_bytes()).map_err(|e| {
            let _ = std::fs::remove_file(&private_path);
            write_err(e)
        })?;

        // Certificate, if any: write beside the private key as <name>-cert.pub
        // so ssh -i <private> auto-loads it. Same 0600 perms.
        let cert_path = if let Some(cert) = certificate {
            let cp = private_path.with_file_name(format!(
                "{}-cert.pub",
                private_path.file_name().unwrap_or_default().to_string_lossy()
            ));
            let mut cf = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&cp)
                .map_err(|e| SshrackError::AskpassWrite { path: cp.clone(), source: e })?;
            cf.write_all(cert.as_bytes()).map_err(|e| {
                let _ = std::fs::remove_file(&private_path);
                let _ = std::fs::remove_file(&cp);
                SshrackError::AskpassWrite { path: cp.clone(), source: e }
            })?;
            Some(cp)
        } else {
            None
        };

        Ok(Self { private: private_path, cert: cert_path })
    }

    /// The path to pass to `ssh -i`.
    pub fn private_path(&self) -> &Path {
        &self.private
    }
}

impl Drop for KeyArtifact {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.private);
        if let Some(c) = &self.cert {
            let _ = std::fs::remove_file(c);
        }
    }
}
```

(`SshrackError::AskpassWrite` is reused — it already carries a path + io::Error and is the right "temp secret file write failed" error. `file_name()` returning `None` is guarded by `unwrap_or_default` → empty string, which would just make a weird path; in practice the path always has a filename. If clippy flags `unwrap_or_default` on `OsStr`, switch to `.to_string_lossy().into_owned()`.)

- [ ] **Step 5: Wire materialization into the connect orchestration**

Locate the connect orchestration that calls `credential::resolve` → `connect::ssh::build` / `connect::scp::build` → `connect::launch` (it is in `src/`, likely `src/cli/mod.rs` for the CLI connect arms and `src/tui/connect.rs` for the TUI — both the CLI and TUI connect paths must materialize). At each call site, between `resolve` and `build`, insert materialization that holds the `KeyArtifact` across `launch`:

```rust
// `resolved` is the ResolvedAuth from resolve(...).
let inline_key = resolved.inline_key.take();
let _key_artifact: Option<connect::KeyArtifact> = if let Some(mat) = inline_key {
    let artifact = connect::KeyArtifact::write(&mat.private, mat.certificate.as_ref())?;
    // build_argv reads resolved.key_path, so fill it with the temp path.
    resolved.key_path = Some(artifact.private_path().to_path_buf());
    Some(artifact)
} else {
    None
};
// ... existing build(argv) + launch(argv, resolved.password, exe) ...
// `_key_artifact` drops here, after launch returns, deleting the temp files.
```

Search for every `connect::launch(` call and ensure each is preceded by this block. (If a shared helper performs resolve→build→launch, put the block there once. Prefer one helper over duplicating in both surfaces — see project DRY rule.)

Re-export `KeyArtifact` from `connect::mod` (`pub use` or it is already `pub` at `connect::KeyArtifact` depending on module shape — confirm the path the call sites import from).

- [ ] **Step 6: Run — pass**

```bash
cargo test -p sshrack-core --lib credential
cargo test -p sshrack-core --lib connect
cargo build --workspace
```
Expected: all pass; workspace builds (orchestration in `src/` now compiles against the new `inline_key` field).

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(core): resolve inline key to a temp-file KeyArtifact for ssh -i"
```

---

## Task 4: Encrypted-key passphrase — key-only connections leave askpass unset

**Files:**
- Modify: `crates/sshrack-core/src/connect/mod.rs` (`askpass_env_for` — `PasswordSource::None` arm)
- Modify: the `env_for_none_has_required_keys_and_no_secret_env` test (RED→GREEN inversion)

**Interfaces:**
- Consumes: `PasswordSource::None`.
- Produces: when `source == PasswordSource::None`, `askpass_env_for` returns an **empty** `Vec` (no `SSH_ASKPASS`, no `REQUIRE=force`, no `DISPLAY`) so ssh falls back to `/dev/tty` for an encrypted key's passphrase (and never calls our payload-less askpass helper).

- [ ] **Step 1: Invert the existing test (RED)**

In `connect/mod.rs` tests, change `env_for_none_has_required_keys_and_no_secret_env` to assert the new contract — rename and rewrite:

```rust
#[test]
fn env_for_none_sets_no_askpass_so_ssh_asks_passphrase_at_tty() {
    // A key-only (or default) connection has no account password to inject, so
    // ssh must NOT be pointed at our askpass helper: if the private key is
    // encrypted, ssh would call askpass (which has no payload for a key-only
    // connection) and fail. Leaving SSH_ASKPASS unset lets ssh fall back to
    // /dev/tty and prompt the user for the key passphrase itself.
    let env = env_for(&PasswordSource::None);
    assert!(env.is_empty(), "key-only connections set no askpass env, got {env:?}");
}
```

- [ ] **Step 2: Run — expect RED** (the current impl returns the 3-entry triplet for `None`).

```bash
cargo test -p sshrack-core --lib connect::tests::env_for_none_sets_no_askpass_so_ssh_asks_passphrase_at_tty
```

- [ ] **Step 3: Implement — short-circuit `None`**

In `askpass_env_for` (`connect/mod.rs:35`), add an early return at the top:

```rust
fn askpass_env_for(
    self_exe: &Path,
    source: &PasswordSource,
    pw_file: Option<&Path>,
) -> Vec<(&'static str, String)> {
    // Key-only / default-auth connection: nothing to inject. Leaving askpass
    // unset lets ssh prompt at /dev/tty for an encrypted key's passphrase
    // (otherwise ssh would call this payload-less helper and fail).
    if matches!(source, PasswordSource::None) {
        return Vec::new();
    }
    let mut env: Vec<(&'static str, String)> = vec![
        ("SSH_ASKPASS", self_exe.to_string_lossy().into_owned()),
        ("SSH_ASKPASS_REQUIRE", "force".to_string()),
        ("DISPLAY", ":0".to_string()),
    ];
    match source {
        PasswordSource::Inline(_) => {
            if let Some(p) = pw_file {
                env.push((ASKPASS_FILE_ENV, p.to_string_lossy().into_owned()));
            }
        }
        PasswordSource::Keyring { key } => {
            env.push((KEYRING_KEY_ENV, key.clone()));
        }
        PasswordSource::None => {}
    }
    env
}
```

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack-core --lib connect
```
Expected: all pass (the `Inline` and `Keyring` env tests are unchanged; only the `None` contract changed).

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "fix(core): let ssh prompt for an encrypted key's passphrase on key-only connections"
```

---

## Task 5: CLI — import key contents via stdin/file + mask inline in ls/show

**Files:**
- Modify: `src/cli/args.rs` (`CredAction::Add`/`Edit`, `HostAction::Add`/`Edit`, and the global/connect `--identity` area as needed)
- Modify: `src/cli/mod.rs` (the cred/host add/edit handlers that build the body — read stdin/file into `Secret::Plain`)
- Modify: `src/shared/format.rs` (render `KeySource::Inline` masked; never emit key text)

**Interfaces:**
- Consumes: Task 1's `with_inline_key(Secret, Option<Secret>)`, `KeySource`.
- Produces: new flags `--identity-stdin` (bool), `--identity-file <PATH>` on `cred add/edit` and `host add/edit` (Independent); `--certificate-stdin`, `--certificate-file <PATH>` likewise. `--identity <path>` (path reference) is unchanged and conflicts-with the stdin/file flags.

- [ ] **Step 1: Write the failing tests (RED)**

In `src/cli/mod.rs` tests (or a new `#[cfg(test)]` block for the new import helper), test the pure read-into-Secret helper:

```rust
#[test]
fn read_identity_file_returns_plain_secret_of_contents() {
    // Write a temp key file, read it via the same helper the handler uses.
    let dir = std::env::temp_dir().join(format!("sshrack-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let keyfile = dir.join("id_test");
    std::fs::write(&keyfile, "KEY-CONTENTS").unwrap();
    let s = read_secret_file(&keyfile).unwrap();
    assert_eq!(s.as_plain(), Some("KEY-CONTENTS"));
    let _ = std::fs::remove_file(&keyfile);
}

#[test]
fn read_identity_stdin_returns_plain_secret_of_stdin_contents() {
    // Drive the stdin helper with a cursor.
    let input = "STDIN-KEY-CONTENTS";
    let s = read_secret_stdin(&mut std::io::Cursor::new(input)).unwrap();
    assert_eq!(s.as_plain(), Some("STDIN-KEY-CONTENTS"));
}
```

In `src/shared/format.rs` tests:

```rust
#[test]
fn inline_key_renders_as_masked_placeholder_not_contents() {
    use sshrack_core::config::schema::{InlineKey, KeySource, Secret};
    let body = CredentialBody::new("u")
        .with_inline_key(Secret::Plain("SECRET-TEXT".into()), None);
    let rendered = credential_secret_summary(&body); // the existing/new helper used by ls/show
    assert!(!rendered.contains("SECRET-TEXT"), "ls/show leaked inline key text");
    assert!(rendered.contains("inline"), "expected an inline marker, got {rendered}");
}
```

- [ ] **Step 2: Run — expect RED** (helpers missing; format renders key text via `as_deref`).

- [ ] **Step 3: Add the clap flags** in `src/cli/args.rs`. On `CredAction::Add` (and mirror on `Edit`, and the Independent flags on `HostAction::Add`/`Edit`):

```rust
        /// Read the private key **contents** from stdin (mutually exclusive
        /// with --identity / --identity-file). The contents are stored inline
        /// (encrypted under vault, or plaintext) — never passed on argv.
        #[arg(long, conflicts_with_all = ["identity", "identity_file"])]
        identity_stdin: bool,
        /// Read the private key **contents** from this file (mutually exclusive
        /// with --identity / --identity-stdin). The file is read once at add
        /// time; its contents are stored inline, so the file may be deleted
        /// afterward.
        #[arg(long, conflicts_with_all = ["identity", "identity_stdin"])]
        identity_file: Option<PathBuf>,
        /// Read an SSH **certificate** from stdin (optional; pairs with
        /// --identity-stdin / --identity-file).
        #[arg(long)]
        certificate_stdin: bool,
        /// Read an SSH **certificate** from this file (optional).
        #[arg(long, conflicts_with = "certificate_stdin")]
        certificate_file: Option<PathBuf>,
```

(Use clap's `conflicts_with_all` / `conflicts_with` so exactly one identity source is allowed. The existing `identity: Option<PathBuf>` stays as the path-reference source.)

- [ ] **Step 4: Implement the read helpers** in `src/cli/mod.rs`:

```rust
use std::io::Read;
use sshrack_core::config::schema::Secret;

/// Read a file's full contents into a plaintext [`Secret`]. Used for
/// --identity-file / --certificate-file: the path is on argv (not secret), the
/// file contents become the inline secret.
fn read_secret_file(path: &std::path::Path) -> Result<Secret, SshrackError> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("identity file {} is not valid UTF-8", path.display()))?;
    Ok(Secret::Plain(text))
}

/// Read all of stdin into a plaintext [`Secret`]. Used for --identity-stdin /
/// --certificate-stdin: nothing secret touches argv.
fn read_secret_stdin(reader: &mut dyn Read) -> Result<Secret, SshrackError> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).context("failed to read identity from stdin")?;
    let text = String::from_utf8(bytes).context("stdin identity is not valid UTF-8")?;
    Ok(Secret::Plain(text))
}
```
(Use `anyhow::Context` as the rest of `src/cli` does; map to the handler's error type at the call site the way neighboring CLI errors are mapped. These helpers return `Secret::Plain`; sealing per store mode happens in the existing persist path via `seal_body`/`seal_auth` — no change there.)

In the cred/host add/edit handlers, after the existing `--identity` handling, resolve the identity source:

```rust
let key_source: Option<KeySource> = if let Some(path) = opts.identity {
    Some(KeySource::Path(path))
} else if opts.identity_stdin {
    let priv_sec = read_secret_stdin(&mut std::io::stdin())?;
    let cert_sec = if opts.certificate_stdin {
        Some(read_secret_stdin(&mut std::io::stdin())?)
    } else if let Some(cp) = opts.certificate_file {
        Some(read_secret_file(&cp)?)
    } else {
        None
    };
    let mut body = CredentialBody::new(user);
    body = body.with_inline_key(priv_sec, cert_sec);
    Some(KeySource::Inline(/* already set on body; or build InlineKey directly */))
} else if let Some(fp) = opts.identity_file {
    let priv_sec = read_secret_file(&fp)?;
    // ... same cert handling ...
    Some(KeySource::Inline(/* ... */))
} else {
    None
};
```
(Cleaner: have the handler build the `CredentialBody` directly via `with_inline_key` / `with_key`, mirroring how it already builds the body for `--identity` today. The exact shape follows the existing handler's body-building style in `src/cli/mod.rs`; keep one source of truth for "resolve identity flags → body" rather than duplicating across cred and host handlers — if a shared helper fits, extract it.)

- [ ] **Step 5: Mask inline keys in `ls`/`show`** in `src/shared/format.rs`. Find every place that dereferences `body.key` as a path (e.g. `format.rs:186` `b.key.as_deref()`). Replace with a branch:

```rust
let key_display: String = match &body.key {
    None => String::new(),
    Some(KeySource::Path(p)) => p.to_string_lossy().into_owned(),
    Some(KeySource::Inline(_)) => "<inline>".to_string(),
};
```
Use `key_display` wherever the path was previously rendered (text and JSON shapes). **Never** render `Inline` contents. JSON `ls`/`show` already exposes `secret_kind` ("key"); add an `"identity_source": "path" | "inline"` field if the existing JSON shape renders the key path (keep field names stable and lowercase to match the locked JSON contract).

- [ ] **Step 6: Run — pass**

```bash
cargo test --workspace
```
Expected: all pass.

- [ ] **Step 7: Manual + clippy + fmt + commit**

```bash
cargo run -q -- cred add t1 --user u --identity-stdin < ~/.ssh/id_ed25519   # then `cred show t1` shows <inline>, not the key
cargo run -q -- cred ls
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(cli): import identity key contents via stdin/file; mask inline in ls/show"
```

---

## Task 6: Docs + full gate

**Files:**
- Modify: `CLAUDE.md` (Identity & Config Model + CLI Contract sections: note inline key contents)
- Modify: `crates/sshrack-core/src/credential.rs` / `config/schema.rs` module docs if they claim key is a path

- [ ] **Step 1: Update CLAUDE.md**

In **Identity & Config Model**, under the **Independent** bullet, add: an inline key may be either a file `Path` or pasted `Inline` contents (`KeySource`); inline contents are stored as `Secret` (vault/plaintext only — keyring mode rejects them) and materialized to a `0600` temp file at connect time for `ssh -i`, deleted after. Encrypted private keys: ssh prompts for the passphrase at the tty on key-only connections (sshrack leaves askpass unset).

In **CLI Contract**, add a row: `--identity-stdin` / `--identity-file` (and `--certificate-*`) import key **contents**; contents never enter argv. `--identity <path>` remains the path-reference source.

- [ ] **Step 2: Full gate + release build**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

- [ ] **Step 3: End-to-end manual smoke (real or temp key)**

```bash
# Inline plaintext key, plaintext store:
cargo run -q -- store use plaintext --yes
cargo run -q -- cred add t1 --user u --identity-stdin < /tmp/test_key
cargo run -q -- cred show t1          # shows <inline>, no key text
cargo run -q -- cred ls               # shows t1 / u / key
# Inline key under vault:
cargo run -q -- store use vault       # via SSHRACK_PASSPHRASE
cargo run -q -- cred add t2 --user u --identity-file /tmp/test_key --certificate-file /tmp/test_cert
# Encrypted private key (generate one with ssh-keygen -N 'pw' ...), then connect:
cargo run -q -- <host-using-t1> echo ok   # ssh prompts "Enter passphrase for key" at the tty
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs(core,cli): inline identity key contents (path or pasted)"
```

Then use the `superpowers:finishing-a-development-branch` skill to merge or PR.

---

## Self-Review

**1. Spec coverage:**
- Paste key contents (not just path) — Task 1 (model) + Task 5 (CLI import). ✅ (TUI paste is the follow-up plan.)
- Reuse existing storage (vault/plaintext) — Task 2 (seal/unseal). ✅
- Connection works with pasted key — Task 3 (materialize temp file for `-i`). ✅
- Encrypted-key passphrase — Task 4 (key-only leaves askpass unset; ssh prompts at tty). ✅
- Optional certificate — Task 1 (`InlineKey.certificate`) + Task 2 (seal both) + Task 3 (`<private>-cert.pub` sibling) + Task 5 (`--certificate-*`). ✅
- No key text in argv/logs/`ls`/`show`/errors — Task 1 (redacting Debug) + Task 3 (Zeroizing + temp file) + Task 5 (mask render). ✅
- No migration / no compat shim — Task 1 (untagged serde, legacy `key="/path"` parses). ✅
- Keyring mode handling — Task 1 (validate rejects Inline under keyring). ✅

**2. Placeholder scan:** No TBD/TODO. Where a call site is mechanical (CLI handler body-building, format render branch), the exact code or a precise pattern + the neighboring-style reference is given; the implementer subagent locates line numbers via grep.

**3. Type consistency:** `KeySource` / `InlineKey` (Task 1) are consumed identically in Tasks 2–5. `InlineKeyMaterial` / `KeyArtifact` (Task 3) thread from `resolve` → orchestration → drop. `ResolvedAuth.inline_key` / `key_path` mutual exclusion holds (Path sets key_path; Inline sets inline_key). `Secret::Plain` flows stdin/file → seal → store → decrypt → temp file unchanged across all tasks.

**4. Known follow-up (out of scope, tracked in memory `inline-key-content-design`):** TUI paste (ratatui-textarea) + cred/host wizard Source sub-field = Plan 2. Keyring-mode inline keys = future (validate currently rejects).
