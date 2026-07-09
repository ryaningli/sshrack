# Keyring-Mode Inline Key Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `store = keyring` fully support inline (pasted) identity keys — the private key + optional certificate text live in the OS keyring, never as plaintext in `config.toml` — and eliminate the misleading `vault is locked` error by making the stale-residual state structurally unreachable rather than papering over it with a special error.

**Architecture:** `InlineKey.keyring` is an existing-but-dormant flag. We activate it as a first-class representation: under keyring mode, `seal_inline_key` writes the private/cert text to two dedicated keyring slots (`<kind>:<id>#ikpriv` / `#ikcert`) and clears the in-body text; `resolve` reads them back and materializes a temp file for `ssh -i`; `migrate` re-hosts inline key text across store-mode switches (no short-circuit); lifecycle (rm/cp/overwrite) cleans all three slots. The `SecretBackend` trait gains raw `set_at`/`delete_at` (get is already raw) so a single owner can own multiple slots. **No compatibility shims:** the now-dead `InlineKeyNeedsVaultOrPlaintext` variant and `re_seal_inline_secret` function are deleted, and `resolve` keeps using `decrypt_secret`'s existing `VaultLocked` for the "encrypted secret with no vault key" case — accurate in vault mode ("go unlock"), and unreachable in keyring mode once migration is fixed (no special residual-error path).

**Tech Stack:** Rust 2024, MSRV 1.88, `sshrack-core` (thiserror, zero UI deps), binary (ratatui + crossterm + anyhow). `keyring` v4 (stores arbitrary-length strings — private keys are fine).

## Global Constraints

- **English only** — all source, comments, doc comments, errors, help text, log output, commit messages.
- **Zero `unsafe`** — never, including tests.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **Secrets are `Zeroizing<String>` end-to-end** — never logged, printed, in errors, or in argv. Inline key text is as sensitive as a password.
- **Library errors use `thiserror`**; application errors use `anyhow` with `.context()`. All fallible ops propagate via `?`.
- **No duplicate logic** — shared helpers live in one place (e.g. `secret/mod.rs`, `id.rs`). The host and credential `copy_keyring_entry` duplicates must be consolidated.
- **Dev stage — no compat/transition residue.** Unreleased; no migration shims for old behavior, no defensive code for states the data model makes unreachable, no "Reserved" placeholders. When a change makes a variant/function/comment dead, delete it in the same plan — do not leave `#[allow(dead_code)]`, "unreachable" defense arms, or stale "validate rejects this" comments. `InlineKey.keyring` becomes a real representation, not a compatibility curiosity.
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Tests hermetic** — `cargo test --workspace` under no env vars; inject via params/traits/tempfiles; never mutate the real env. CI runs under a pty: `script -qec "cargo test --workspace" /dev/null`.
- **Conventional Commits** — `<type>(<scope>): <desc>`, no `Co-Authored-By`. Explicit `git add <paths>`, never `git add -A`. Branch: `feat/keyring-inline-key`.
- **Match the layer to the bug** — pure logic uses unit TDD; state bugs use `on_key` + state assert; layout regressions use `TestBackend` + insta.
- **Keyring slot key scheme (fixed):**
  - password: `keyring_key(kind, id)` → `host:<id>` / `cred:<id>` (unchanged)
  - inline private key: `keyring_key_inline_priv(kind, id)` → `host:<id>#ikpriv` / `cred:<id>#ikpriv` (new)
  - inline certificate: `keyring_key_inline_cert(kind, id)` → `host:<id>#ikcert` / `cred:<id>#ikcert` (new)
- **`SecretBackend` interface (fixed):** add raw `set_at(key, &str)` / `delete_at(key)`; `get(key)` is already raw; `set(kind,id,&str)` and `delete(kind,id)` become default methods delegating through `keyring_key`. `OsKeyring` and `FakeBackend` implement only the raw four.

---

## File Structure

All paths are repo-relative. Files are grouped by responsibility.

**Core crate (`crates/sshrack-core/src/`):**
- `id.rs` — add `keyring_key_inline_priv` / `keyring_key_inline_cert` (pure key derivation).
- `secret/mod.rs` — `SecretBackend` trait gains `set_at`/`delete_at`; `set`/`delete` become defaults; `OsKeyring`/`FakeBackend` updated; `forget_keyring_secret` extended to delete inline slots; new shared `copy_inline_keyring_slots` / `forget_inline_keyring_slots` helpers.
- `config/schema.rs` — `CredentialBody::validate` relaxes to allow `ik.keyring == true` marker bodies (the dead `InlineKeyNeedsVaultOrPlaintext` arm goes away); `InlineKey` doc updated (no longer "Reserved").
- `error.rs` — **delete** the now-unused `InlineKeyNeedsVaultOrPlaintext` variant (and its leak-scan entry if present).
- `secret/vault/mod.rs` — `seal_inline_key` gains `kind`/`id`/`backend` and a keyring branch; `seal_body` passes them through; stale "Keyring mode is rejected upstream by validate" comments removed.
- `secret/vault/transform.rs` — `migrate_body_inline_key` no longer short-circuits on keyring target (real bidirectional migration); **delete** the dead `re_seal_inline_secret` function; `leaving_keyring` cleanup deletes inline slots; `count_secrets` counts `ik.keyring` bodies (stale "rejected by validate" comment removed); `decrypt_all`/`decrypt_body` decrypt inline-key Encrypted (fixes pre-existing rekey gap).
- `credential.rs` — `resolve` gains `backend` param and a keyring read branch; `decrypt_secret` is unchanged (still returns `VaultLocked` for the no-vault-key case — that path is now unreachable in keyring mode, which is the point); `copy_keyring_entry` (cred) consolidated onto the shared helper.
- `host.rs` — `copy_keyring_entry` (host) consolidated onto shared helper; `delete_host_with_secret` / `forget_keyring_on_overwrite` snapshot `ik.keyring`.
- `connect/scp.rs` — `resolve` caller gains backend (threaded from `connect::scp::build`).

**Binary (`src/`):**
- `cli/cmd/connect.rs` — `resolve` caller gains `OsKeyring`.
- `cli/cmd/scp.rs` — threads backend into `connect::scp::build`.
- `cli/cmd/host.rs`, `cli/cmd/cred.rs` — display-path `resolve` calls gain backend (already construct `OsKeyring` nearby).
- `tui/persist.rs` — both seal blocks (`persist_host_save` :114, `persist_cred_save` :313) widen their trigger so inline-key plaintext is sealed under any decided mode (fixes pre-existing TUI/CLI divergence where TUI inline keys were never sealed).
- `tui/connect.rs`, `tui/transfer/open.rs` — `resolve` callers gain backend.

**Docs:**
- `docs/architecture.md` — :79 corrected (keyring mode stores inline keys in the OS keyring; no longer "rejects them").
- Memory file `keyring-inline-key.md` — design record.

---

## Task 1: SecretBackend raw methods + inline keyring-key helpers

The foundation. Every other task depends on the trait being able to address multiple keyring slots per owner, and on the key-derivation helpers existing.

**Files:**
- Modify: `crates/sshrack-core/src/id.rs`
- Modify: `crates/sshrack-core/src/secret/mod.rs` (trait + `OsKeyring` + `FakeBackend`)
- Test: inline `#[cfg(test)] mod tests` in both files

**Interfaces:**
- Consumes: existing `keyring_key(kind, id)`, `OwnerKind`, `Ulid`.
- Produces:
  - `pub fn keyring_key_inline_priv(kind: OwnerKind, id: &Ulid) -> String`
  - `pub fn keyring_key_inline_cert(kind: OwnerKind, id: &Ulid) -> String`
  - `SecretBackend::set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError>`
  - `SecretBackend::delete_at(&self, key: &str) -> Result<(), SshrackError>`
  - `SecretBackend::set` / `SecretBackend::delete` become provided methods (default impls).

- [ ] **Step 1: Write the failing tests for the key helpers** (`id.rs` tests module)

```rust
#[test]
fn inline_priv_key_is_base_plus_suffix() {
    let id = Ulid::new();
    assert_eq!(keyring_key_inline_priv(OwnerKind::Host, &id), format!("host:{id}#ikpriv"));
    assert_eq!(
        keyring_key_inline_priv(OwnerKind::Credential, &id),
        format!("cred:{id}#ikpriv")
    );
}

#[test]
fn inline_cert_key_is_base_plus_suffix() {
    let id = Ulid::new();
    assert_eq!(
        keyring_key_inline_cert(OwnerKind::Host, &id),
        format!("host:{id}#ikcert")
    );
}

#[test]
fn inline_keys_share_base_with_password_key() {
    // The three slots for one owner all share the `<kind>:<id>` prefix; only
    // the suffix differs, so they are distinct entries but visibly co-owned.
    let id = Ulid::new();
    let base = keyring_key(OwnerKind::Host, &id);
    assert!(keyring_key_inline_priv(OwnerKind::Host, &id).starts_with(&base));
    assert!(keyring_key_inline_cert(OwnerKind::Host, &id).starts_with(&base));
}
```

- [ ] **Step 2: Run the helper tests — expect compile failure (functions undefined)**

Run: `cargo test -p sshrack-core --lib id::tests`
Expected: FAIL — `cannot find function keyring_key_inline_priv`.

- [ ] **Step 3: Implement the key helpers** (`id.rs`, immediately after `keyring_key`)

```rust
/// The keyring account key for an inline private key stored under keyring
/// mode. Shares the `<kind>:<id>` base with [`keyring_key`] (the password
/// slot) and appends a `#ikpriv` suffix so a single owner may own a password
/// slot, a private-key slot, and a certificate slot simultaneously.
pub fn keyring_key_inline_priv(kind: OwnerKind, id: &Ulid) -> String {
    format!("{}#ikpriv", keyring_key(kind, id))
}

/// The keyring account key for an inline SSH certificate stored under keyring
/// mode. Appends `#ikcert` to the owner's base key.
pub fn keyring_key_inline_cert(kind: OwnerKind, id: &Ulid) -> String {
    format!("{}#ikcert", keyring_key(kind, id))
}
```

- [ ] **Step 4: Run the helper tests — expect PASS**

Run: `cargo test -p sshrack-core --lib id::tests`
Expected: PASS (all `id::tests` green).

- [ ] **Step 5: Write the failing test for raw `set_at`/`delete_at` via `FakeBackend`** (`secret/mod.rs` tests module)

```rust
#[test]
fn fake_backend_round_trips_inline_slots_independently() {
    // An owner's password slot, private-key slot, and certificate slot are
    // three independent entries addressed by raw key. Writing one must not
    // disturb the others; deleting one must not touch the others.
    let id = Ulid::new();
    let be = FakeBackend::new();
    be.set_at(&keyring_key(OwnerKind::Host, &id), "pw").unwrap();
    be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &id), "PRIV")
        .unwrap();
    be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &id), "CERT")
        .unwrap();
    assert_eq!(be.get(&keyring_key(OwnerKind::Host, &id)).unwrap().as_deref(), Some("pw"));
    assert_eq!(
        be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
            .unwrap()
            .as_deref(),
        Some("PRIV")
    );
    // Deleting the password slot leaves the key slots intact.
    be.delete_at(&keyring_key(OwnerKind::Host, &id)).unwrap();
    assert!(be.get(&keyring_key(OwnerKind::Host, &id)).unwrap().is_none());
    assert_eq!(
        be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
            .unwrap()
            .as_deref(),
        Some("PRIV")
    );
}

#[test]
fn provided_set_delete_delegate_through_keyring_key() {
    // The default set/delete(kind,id) must route through keyring_key, so the
    // existing password-slot callers keep working unchanged.
    let id = Ulid::new();
    let be = FakeBackend::new();
    be.set(OwnerKind::Host, &id, "pw").unwrap();
    assert_eq!(
        be.get(&keyring_key(OwnerKind::Host, &id)).unwrap().as_deref(),
        Some("pw")
    );
    be.delete(OwnerKind::Host, &id).unwrap();
    assert!(be.get(&keyring_key(OwnerKind::Host, &id)).unwrap().is_none());
}
```

- [ ] **Step 6: Run — expect compile failure (`set_at`/`delete_at` undefined on trait)**

Run: `cargo test -p sshrack-core --lib secret::tests`
Expected: FAIL — `no method named set_at`.

- [ ] **Step 7: Convert the `SecretBackend` trait to raw + provided methods** (`secret/mod.rs`)

Replace the four-method trait body (the `fn set` / `fn get` / `fn delete` / `fn available` block at `secret/mod.rs:35-45`) with:

```rust
pub trait SecretBackend {
    /// Store `secret` under the raw account `key` (overwrites). I/O. Used for
    /// the password slot (`<kind>:<id>`) and the inline-key slots
    /// (`<kind>:<id>#ikpriv` / `#ikcert`).
    fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError>;
    /// Fetch the secret for a raw account key; `Ok(None)` when absent.
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError>;
    /// Delete the entry for a raw account key if present. A missing entry is
    /// success.
    fn delete_at(&self, key: &str) -> Result<(), SshrackError>;
    /// True when the backend is reachable (a daemon is running / keychain
    /// unlocked). Probed before migrating into keyring mode.
    fn available(&self) -> bool;

    /// Store `password` under the owner's password slot (`<kind>:<id>`).
    /// Provided for ergonomics: existing password-slot callers are unchanged.
    fn set(&self, kind: OwnerKind, id: &Ulid, password: &str) -> Result<(), SshrackError> {
        self.set_at(&crate::id::keyring_key(kind, id), password)
    }
    /// Delete the owner's password slot. Provided for ergonomics.
    fn delete(&self, kind: OwnerKind, id: &Ulid) -> Result<(), SshrackError> {
        self.delete_at(&crate::id::keyring_key(kind, id))
    }
}
```

Update `OsKeyring` impl (`secret/mod.rs:65-78`) — replace `set`/`delete` bodies with `set_at`/`delete_at` (get/available unchanged):

```rust
impl SecretBackend for OsKeyring {
    fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError> {
        keyring::set_by_key(key, secret)
    }
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
        keyring::get(key)
    }
    fn delete_at(&self, key: &str) -> Result<(), SshrackError> {
        keyring::delete_by_key(key)
    }
    fn available(&self) -> bool {
        keyring::daemon_available()
    }
}
```

Update `FakeBackend` impl (`secret/mod.rs:119-142`) — replace `set`/`delete` with `set_at`/`delete_at` operating on raw keys (drop the inner `keyring_key` call):

```rust
impl SecretBackend for FakeBackend {
    fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError> {
        self.entries.borrow_mut().insert(key.to_string(), secret.to_string());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
        Ok(self.entries.borrow().get(key).map(|p| Zeroizing::new(p.clone())))
    }
    fn delete_at(&self, key: &str) -> Result<(), SshrackError> {
        self.entries.borrow_mut().remove(key);
        Ok(())
    }
    fn available(&self) -> bool {
        self.available
    }
}
```

- [ ] **Step 8: Run the full core test suite — expect green**

Run: `cargo test -p sshrack-core --lib`
Expected: PASS — all existing tests still green (the `set`/`delete` default methods preserve the password-slot callers), plus the new raw-slot tests.

- [ ] **Step 9: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/id.rs crates/sshrack-core/src/secret/mod.rs
git commit -m "feat(secret): add raw set_at/delete_at and inline-keyring-key helpers"
```

---

## Task 2: Relax `validate` + delete the dead `InlineKeyNeedsVaultOrPlaintext` variant

The precondition guard: `validate` must accept a keyring-marker inline body (`ik.keyring == true`, no in-body text). Once it does, the `InlineKeyNeedsVaultOrPlaintext` variant has no caller left and is deleted (dev stage — no dead variants).

**Files:**
- Modify: `crates/sshrack-core/src/config/schema.rs` (`validate` :327-351 + test module)
- Modify: `crates/sshrack-core/src/error.rs` (delete `InlineKeyNeedsVaultOrPlaintext` :74-75)

**Interfaces:**
- Consumes: Task 1 (independent of it).
- Produces: relaxed `validate` accepting `ik.keyring == true` marker bodies; `SshrackError` minus one dead variant.

- [ ] **Step 1: Write the failing validate tests** (`schema.rs` test module)

```rust
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
```

- [ ] **Step 2: Run — the first test fails (validate currently rejects all `ik.keyring`)**

Run: `cargo test -p sshrack-core --lib config::schema::tests`
Expected: `validate_accepts_inline_key_in_keyring_marker_form` FAILS (the existing :347 branch returns `InlineKeyNeedsVaultOrPlaintext`); the second PASSES (already rejected).

- [ ] **Step 3: Relax `validate`** (`schema.rs:327-351`)

Replace the whole `validate` body. The `secrets_set > 1` mutex already rejects `body.keyring (password marker) + key` and `password + key`, so the special inline-keyring branch is no longer needed — only the "marker must not coexist with plaintext text" rule remains:

```rust
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
```

- [ ] **Step 4: Run the validate tests — expect PASS; update the now-stale old test**

Run: `cargo test -p sshrack-core --lib config::schema::tests`
Expected: the two new tests PASS. The old `validate_rejects_inline_key_under_keyring_mode_marker` test (schema.rs:873) built `private_key: Some(Plain) + keyring: true` — it still rejects, now via `InvalidCredentialBody` instead of `InlineKeyNeedsVaultOrPlaintext`. Update that test to assert `is_err()` (drop any assertion on the specific variant). `validate_accepts_inline_key_without_keyring_marker` (:891) and `validate_rejects_password_and_inline_key_together` (:897) still pass unchanged.

- [ ] **Step 5: Delete the dead `InlineKeyNeedsVaultOrPlaintext` variant** (`error.rs:74-75`)

Grep confirms its only caller was `schema.rs:348`, which Step 3 removed. Delete the variant and its doc comment. If `error.rs`'s secret-leak scan test (`vault_errors_never_leak_secrets`, :358-385) enumerated it by name, drop that line too.

```bash
# Verify no remaining references before deleting:
grep -rn "InlineKeyNeedsVaultOrPlaintext" crates/ src/
# Expected: only the error.rs definition. Delete it.
```

- [ ] **Step 6: Run the full core suite — expect green**

Run: `cargo test -p sshrack-core --lib`
Expected: PASS — no remaining references to the deleted variant; validate tests green.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/config/schema.rs crates/sshrack-core/src/error.rs
git commit -m "feat(core): allow keyring-stored inline keys; drop dead InlineKeyNeedsVaultOrPlaintext"
```

---

## Task 3: Seal inline keys into the keyring (write path)

Under keyring mode, `seal_inline_key` must store private/cert text in the two keyring slots and leave a marker body — mirroring how `seal_password` stores the password and returns `None`.

**Files:**
- Modify: `crates/sshrack-core/src/secret/vault/mod.rs` (`seal_inline_key` :299-311 + its doc, `seal_body` call site :277, `finalize_secret` doc :52-57 if it references keyring)
- Test: `vault/mod.rs` test module

**Interfaces:**
- Consumes: Task 1 (`set_at`, `keyring_key_inline_priv`/`_cert`), Task 2 (relaxed `validate`).
- Produces: `seal_inline_key` with signature `fn seal_inline_key(ik, kind, id, cfg, vault_key, backend) -> Result<InlineKey, SshrackError>`; bodies produced with `ik.keyring == true` and cleared text under keyring mode.

- [ ] **Step 1: Write the failing seal test** (`vault/mod.rs` test module)

```rust
#[test]
fn seal_inline_key_keyring_mode_stores_text_in_keyring_and_clears_body() {
    // Under keyring mode, sealing an inline key with plaintext private + cert
    // must: (a) write both texts to the keyring slots, (b) clear the in-body
    // text, (c) set ik.keyring = true. The body left on disk carries no secret.
    use crate::config::schema::{InlineKey, KeySource, Secret, SecretStore};
    use crate::secret::test_doubles::FakeBackend;
    use ulid::Ulid;

    let mut cfg = SshrackConfig::default();
    cfg.store = Some(SecretStore::Keyring);
    let id = Ulid::new();
    let backend = FakeBackend::new();
    let ik = InlineKey {
        private_key: Some(Secret::Plain("PRIV-TEXT".into())),
        certificate: Some(Secret::Plain("CERT-TEXT".into())),
        keyring: false,
    };
    let sealed = super::seal_inline_key(ik, OwnerKind::Host, &id, &cfg, None, &backend).unwrap();
    // Body cleared + marker set.
    assert!(sealed.private_key.is_none());
    assert!(sealed.certificate.is_none());
    assert!(sealed.keyring);
    // Both texts live in the keyring under the slot keys.
    assert_eq!(
        backend
            .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
            .unwrap()
            .as_deref(),
        Some("PRIV-TEXT")
    );
    assert_eq!(
        backend
            .get(&crate::id::keyring_key_inline_cert(OwnerKind::Host, &id))
            .unwrap()
            .as_deref(),
        Some("CERT-TEXT")
    );
}

#[test]
fn seal_inline_key_keyring_mode_without_cert_leaves_cert_slot_absent() {
    // A private-only inline key writes only the priv slot; the cert slot is
    // not created.
    use crate::config::schema::{InlineKey, Secret, SecretStore};
    use crate::secret::test_doubles::FakeBackend;
    use ulid::Ulid;

    let mut cfg = SshrackConfig::default();
    cfg.store = Some(SecretStore::Keyring);
    let id = Ulid::new();
    let backend = FakeBackend::new();
    let ik = InlineKey {
        private_key: Some(Secret::Plain("PRIV".into())),
        certificate: None,
        keyring: false,
    };
    let sealed = super::seal_inline_key(ik, OwnerKind::Host, &id, &cfg, None, &backend).unwrap();
    assert!(sealed.keyring);
    assert!(sealed.private_key.is_none());
    assert!(
        backend
            .get(&crate::id::keyring_key_inline_cert(OwnerKind::Host, &id))
            .unwrap()
            .is_none()
    );
}
```

- [ ] **Step 2: Run — expect compile failure (signature mismatch)**

Run: `cargo test -p sshrack-core --lib secret::vault::tests`
Expected: FAIL — `seal_inline_key` takes 3 args, test passes 6.

- [ ] **Step 3: Rewrite `seal_inline_key`** (`vault/mod.rs:299-311`)

Replace the function and its doc comment. Remove the stale "Keyring mode is rejected upstream by `CredentialBody::validate`" sentence — keyring mode is now a supported write target:

```rust
/// Seal an inline key's freshly collected plaintext secrets (private key, and
/// the optional certificate) per the active mode:
/// - keyring mode → store each text in its OS-keyring slot, clear the in-body
///   text, and set `ik.keyring = true` (the body becomes a marker).
/// - vault mode → encrypt each text under `vault_key` as `Secret::Encrypted`.
/// - plaintext/undecided → keep each text as `Secret::Plain`.
///
/// Already-sealed (`Encrypted`) secrets pass through (vault re-save is a
/// no-op; re-sealing a keyring marker body is a no-op).
fn seal_inline_key(
    mut ik: InlineKey,
    kind: OwnerKind,
    id: &Ulid,
    cfg: &SshrackConfig,
    vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<InlineKey, SshrackError> {
    if cfg.is_keyring() {
        if let Some(Secret::Plain(ref p)) = ik.private_key {
            backend.set_at(&crate::id::keyring_key_inline_priv(kind, id), p)?;
            ik.private_key = None;
        }
        if let Some(Secret::Plain(ref c)) = ik.certificate {
            backend.set_at(&crate::id::keyring_key_inline_cert(kind, id), c)?;
            ik.certificate = None;
        }
        ik.keyring = true;
        return Ok(ik);
    }
    // Vault / plaintext path: finalize each in-body secret in place via the
    // shared helper (encrypt under vault, or keep plaintext).
    if let Some(Secret::Plain(ref p)) = ik.private_key {
        ik.private_key = Some(transform::finalize_secret(p, cfg, vault_key)?);
    }
    if let Some(Secret::Plain(ref c)) = ik.certificate {
        ik.certificate = Some(transform::finalize_secret(c, cfg, vault_key)?);
    }
    Ok(ik)
}
```

Ensure `use crate::id::OwnerKind;` and `use crate::secret::SecretBackend;` are in scope at the top of `vault/mod.rs` (check existing imports — `OwnerKind` may already be imported via `seal_body`).

- [ ] **Step 4: Thread the new args through `seal_body`** (`vault/mod.rs:277`)

The call site currently reads:
```rust
Some(KeySource::Inline(ik)) => {
    Some(KeySource::Inline(seal_inline_key(ik, cfg, vault_key)?))
}
```
Change to pass `kind`, `id`, `backend` (all already parameters of `seal_body`):
```rust
Some(KeySource::Inline(ik)) => {
    Some(KeySource::Inline(seal_inline_key(ik, kind, id, cfg, vault_key, backend)?))
}
```

- [ ] **Step 5: Clean stale comments** (`vault/transform.rs:52-57`)

`finalize_secret`'s doc says "Keyring mode is never reached here (an inline key on a keyring-mode body is rejected by `CredentialBody::validate` before sealing)." That is now false — keyring mode is reached in `seal_inline_key`, which handles it before calling `finalize_secret`. Rewrite the sentence to: "Keyring mode is handled by `seal_inline_key` before this helper runs, so only vault/plaintext reach here."

- [ ] **Step 6: Run the seal tests — expect PASS, fix any call-site fallout**

Run: `cargo test -p sshrack-core --lib`
Expected: new seal tests PASS. Existing `seal_body` tests (vault/plaintext inline keys) still PASS — the non-keyring path is unchanged. `seal_auth` (`:320`) delegates to `seal_body` and needs no change.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/secret/vault/mod.rs crates/sshrack-core/src/secret/vault/transform.rs
git commit -m "feat(secret): seal inline keys into the OS keyring under keyring mode"
```

---

## Task 4: `resolve` reads keyring inline keys

`resolve` gains a `backend` parameter and a keyring read branch for `ik.keyring` marker bodies. `decrypt_secret` is unchanged: an `Encrypted` inline key with no vault key still returns `VaultLocked` — that is accurate in vault mode ("go unlock"), and the keyring-mode case is structurally unreachable once migration is fixed (Task 5), so no special-case error is added.

**Files:**
- Modify: `crates/sshrack-core/src/credential.rs` (`resolve` :540-628; `decrypt_secret` :485-513 unchanged)
- Update all `resolve` callers — production: `src/cli/cmd/connect.rs:133`, `crates/sshrack-core/src/connect/scp.rs:105`, `src/tui/connect.rs:105`, `src/tui/transfer/open.rs:94`, `src/cli/cmd/host.rs:722`, `src/cli/cmd/cred.rs:545`; tests: `credential.rs` test module (~15 calls), `src/tui/connect.rs:203`, `src/tui/transfer/open.rs:311`.

**Interfaces:**
- Consumes: Task 1 (`get`, inline key helpers).
- Produces: `pub fn resolve(host, cfg, vault, backend: &dyn SecretBackend) -> Result<ResolvedAuth, SshrackError>`.

- [ ] **Step 1: Write the failing resolve test** (`credential.rs` test module)

```rust
#[test]
fn resolve_inline_key_in_keyring_reads_text_from_backend() {
    // A keyring-marker inline key (ik.keyring = true, no in-body text) resolves
    // by reading the private/cert text from the backend slots and carrying it
    // as InlineKeyMaterial for temp-file materialization.
    use crate::config::schema::{CredentialBody, InlineKey, KeySource, SecretStore};
    use crate::secret::test_doubles::FakeBackend;
    use ulid::Ulid;

    let mut cfg = SshrackConfig::default();
    cfg.store = Some(SecretStore::Keyring);
    let id = Ulid::new();
    let backend = FakeBackend::new();
    backend.set_at(
        &crate::id::keyring_key_inline_priv(OwnerKind::Host, &id),
        "PRIV-TEXT",
    ).unwrap();
    backend.set_at(
        &crate::id::keyring_key_inline_cert(OwnerKind::Host, &id),
        "CERT-TEXT",
    ).unwrap();
    let h = Host {
        id,
        name: "k".into(),
        host: "x".into(),
        port: 22,
        auth: Auth::inline(CredentialBody {
            user: "u".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: None,
                certificate: None,
                keyring: true,
            })),
            keyring: false,
        }),
    };
    let r = resolve(&h, &cfg, None, &backend).unwrap();
    let mat = r.inline_key.expect("inline material present");
    assert_eq!(mat.private.as_str(), "PRIV-TEXT");
    assert_eq!(mat.certificate.as_ref().map(|c| c.as_str()), Some("CERT-TEXT"));
}
```

- [ ] **Step 2: Run — expect compile failure (signature lacks `backend`)**

Run: `cargo test -p sshrack-core --lib credential::tests`
Expected: FAIL — `resolve` takes 3 args.

- [ ] **Step 3: Update `resolve` signature + inline-key branch** (`credential.rs:540`)

Add the `backend` parameter. Replace the inline-key match arm (`:587-602`) so a keyring-marker body reads from the backend; the in-body branch keeps using `decrypt_secret` unchanged:

```rust
pub fn resolve(
    host: &Host,
    cfg: &SshrackConfig,
    vault: Option<&crate::secret::vault::VaultKey>,
    backend: &dyn crate::secret::SecretBackend,
) -> Result<ResolvedAuth, SshrackError> {
    // ... (owner_kind / owner_id / name_label binding unchanged) ...
```

```rust
    let (key_path, inline_key) = match key_source {
        None => (None, None),
        Some(KeySource::Path(p)) => (Some(p.clone()), None),
        Some(KeySource::Inline(ik)) => {
            // A keyring-marker body carries no in-body text — read both texts
            // from the OS-keyring slots. Otherwise decrypt the in-body Secret
            // (Plain needs no key; Encrypted needs the vault key).
            let (private, certificate) = if ik.keyring {
                let priv_text = backend
                    .get(&crate::id::keyring_key_inline_priv(owner_kind, &owner_id))?
                    .unwrap_or_else(|| Zeroizing::new(String::new()));
                let cert_text = backend
                    .get(&crate::id::keyring_key_inline_cert(owner_kind, &owner_id))?;
                (priv_text, cert_text)
            } else {
                let priv_text = decrypt_secret(ik.private_key.as_ref(), vault, name_label)?
                    .unwrap_or_else(|| Zeroizing::new(String::new()));
                let cert_text = decrypt_secret(ik.certificate.as_ref(), vault, name_label)?;
                (priv_text, cert_text)
            };
            (None, Some(InlineKeyMaterial { private, certificate }))
        }
    };
```

`decrypt_secret` (`:485-513`) is left exactly as-is. `owner_kind` is already bound earlier in `resolve` (it builds `keyring_key(owner_kind, ...)` at :607).

- [ ] **Step 4: Run the new resolve test — expect PASS**

Run: `cargo test -p sshrack-core --lib credential::tests::resolve_inline`
Expected: PASS.

- [ ] **Step 5: Update every `resolve` caller to pass a backend**

For each production caller, introduce `let backend = OsKeyring;` near the existing vault-unlock block and pass `&backend`:

- `src/cli/cmd/connect.rs:133` — `credential::resolve(&resolved_host, &cfg, vault_key.as_ref(), &OsKeyring)?` (`OsKeyring` should be in scope via `use sshrack_core::secret::OsKeyring;` — add the import if missing).
- `crates/sshrack-core/src/connect/scp.rs:105` — inside `connect::scp::build`. Add a `backend: &dyn SecretBackend` parameter to `build`, thread it from `src/cli/cmd/scp.rs` (which constructs `OsKeyring`).
- `src/tui/connect.rs:105` — `credential::resolve(&resolved_host, cfg, vault_key.as_ref(), &OsKeyring)?`.
- `src/tui/transfer/open.rs:94` — same pattern (`&OsKeyring`).
- `src/cli/cmd/host.rs:722` and `src/cli/cmd/cred.rs:545` — display paths that today bypass the trait and call `secret::keyring::get` directly (`:737` / `:562`). Thread `&OsKeyring` into `resolve` so the keyring-inline-key path is uniform.

For every test caller of `resolve` (in `credential.rs` tests, `src/tui/connect.rs:203`, `src/tui/transfer/open.rs:311`), add `&FakeBackend::new()` as the fourth argument.

- [ ] **Step 6: Run the full workspace test suite — expect green**

Run: `script -qec "cargo test --workspace" /dev/null`
Expected: PASS. Any remaining failure is a missed caller; grep `credential::resolve(` / `::resolve(` (excluding `config::path::resolve` and `host::resolve_target`) to find stragglers.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/credential.rs crates/sshrack-core/src/connect/scp.rs src/cli/cmd/connect.rs src/cli/cmd/scp.rs src/cli/cmd/host.rs src/cli/cmd/cred.rs src/tui/connect.rs src/tui/transfer/open.rs
git commit -m "feat(core): resolve keyring-stored inline keys via the backend"
```

---

## Task 5: Migrate inline keys across store-mode switches (no short-circuit) + delete dead `re_seal_inline_secret`

Remove the `Keyring`-target short-circuit in `migrate_body_inline_key` (`transform.rs:375-377` — the residual root cause) and implement true bidirectional migration. The now-dead `re_seal_inline_secret` function is deleted (dev stage — no dead code). Also fix `leaving_keyring` to delete the inline slots so they do not become orphans.

**Files:**
- Modify: `crates/sshrack-core/src/secret/vault/transform.rs` (`migrate_body_inline_key` :359-393; **delete** `re_seal_inline_secret` :407-441; `leaving_keyring` cleanup :322/:345; add `extract_inline_text` / `delete_inline_slots` helpers)
- Test: `transform.rs` test module

**Interfaces:**
- Consumes: Task 1 (backend raw + helpers), Task 3 (seal semantics).
- Produces: `migrate_body_inline_key` with a real keyring branch; no change to `migrate`'s public signature (it already takes `backend`).

- [ ] **Step 1: Write the failing migration tests** (`transform.rs` test module)

```rust
#[test]
fn migrate_vault_to_keyring_moves_inline_key_to_keyring_slots() {
    // THE RESIDUAL ROOT CAUSE: vault -> keyring migration must decrypt the
    // inline key and store its plaintext in the keyring slots, leaving a
    // marker body (ik.keyring = true, no in-body text). Previously this
    // short-circuited and left the Encrypted ciphertext stranded under
    // keyring mode — which then misreported as `vault is locked` at connect.
    use crate::config::schema::{InlineKey, KeySource, Secret, SecretStore};
    use crate::secret::test_doubles::FakeBackend;
    use crate::secret::vault::crypto;

    let key = [9u8; 32];
    let enc_priv = crypto::encrypt(b"PRIV", &key).unwrap();
    let id = Ulid::new();
    let mut cfg = SshrackConfig {
        store: Some(SecretStore::Vault {
            meta: VaultMeta::default_argon2("c2FsdA==".into()),
        }),
        hosts: vec![Host {
            id,
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "u".into(),
                password: None,
                key: Some(KeySource::Inline(InlineKey {
                    private_key: Some(Secret::Encrypted(enc_priv)),
                    certificate: None,
                    keyring: false,
                })),
                keyring: false,
            }),
        }],
        ..Default::default()
    };
    let backend = FakeBackend::new();
    let vkey = VaultKey::from(key);
    migrate(&mut cfg, &SecretStore::Keyring, Some(&vkey), None, &backend).unwrap();
    let body = cfg.hosts[0].auth.inline_body().unwrap();
    let ik = match &body.key {
        Some(KeySource::Inline(ik)) => ik,
        _ => panic!("expected Inline"),
    };
    assert!(ik.keyring, "marker must be set");
    assert!(ik.private_key.is_none(), "in-body text must be cleared");
    let stored = backend
        .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
        .unwrap()
        .expect("priv slot written");
    assert_eq!(stored.as_str(), "PRIV");
}

#[test]
fn migrate_keyring_to_vault_encrypts_inline_key_from_keyring_slots() {
    // Reverse direction: a keyring-marker inline key is read from the slots and
    // re-encrypted under the target vault key; the marker is cleared and the
    // source slots are deleted (no orphans).
    use crate::config::schema::{InlineKey, KeySource, Secret, SecretStore};
    use crate::secret::test_doubles::FakeBackend;

    let id = Ulid::new();
    let mut cfg = SshrackConfig {
        store: Some(SecretStore::Keyring),
        hosts: vec![Host {
            id,
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "u".into(),
                password: None,
                key: Some(KeySource::Inline(InlineKey {
                    private_key: None,
                    certificate: None,
                    keyring: true,
                })),
                keyring: false,
            }),
        }],
        ..Default::default()
    };
    let backend = FakeBackend::new();
    backend.set_at(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id), "PRIV").unwrap();
    let target = SecretStore::Vault {
        meta: VaultMeta::default_argon2("c2FsdA==".into()),
    };
    let target_key = VaultKey::from([9u8; 32]);
    migrate(&mut cfg, &target, None, Some(&target_key), &backend).unwrap();
    let ik = match &cfg.hosts[0].auth.inline_body().unwrap().key {
        Some(KeySource::Inline(ik)) => ik,
        _ => panic!("expected Inline"),
    };
    assert!(!ik.keyring, "marker cleared after leaving keyring");
    assert!(matches!(ik.private_key, Some(Secret::Encrypted(_))), "re-encrypted under target key");
    assert!(
        backend
            .get(&crate::id::keyring_key_inline_priv(OwnerKind::Host, &id))
            .unwrap()
            .is_none(),
        "priv slot must be deleted after leaving keyring"
    );
}
```

The tests build `cfg` directly (no `SecretOwner` helper needed — `migrate` derives owners internally). Confirm `VaultKey::from([u8;32])` is the constructor used by the existing `migrate_vault_to_vault_rekeys_inline_key_under_new_key` test (`:905`) and mirror it exactly.

- [ ] **Step 2: Run — expect failure (short-circuit strands the ciphertext; reverse direction has no keyring read)**

Run: `cargo test -p sshrack-core --lib secret::vault::transform::tests`
Expected: both FAIL.

- [ ] **Step 3: Add the supporting helpers** (`transform.rs`, near `extract_plain`)

```rust
/// Which inline-key slot a text belongs to.
enum InlineSlot {
    Private,
    Certificate,
}

/// Extract an inline-key text as wiped plaintext, whether it currently lives
/// in-body (`Plain`/`Encrypted`) or in the OS keyring (keyring-marker body).
/// `None` when there is no private/cert text at all. `owner.name_label` tags a
/// decryption failure (never the secret).
fn extract_inline_text(
    secret: Option<Secret>,
    owner: &SecretOwner<'_>,
    source_vault_key: Option<&VaultKey>,
    slot: InlineSlot,
    backend: &dyn SecretBackend,
) -> Result<Option<Zeroizing<String>>, SshrackError> {
    match secret {
        None => {
            // A keyring-marker body keeps its text in the slot.
            let key = match slot {
                InlineSlot::Private => crate::id::keyring_key_inline_priv(owner.kind, &owner.id),
                InlineSlot::Certificate => crate::id::keyring_key_inline_cert(owner.kind, &owner.id),
            };
            Ok(backend.get(&key)?)
        }
        Some(Secret::Plain(p)) => Ok(Some(Zeroizing::new(p))),
        Some(Secret::Encrypted(enc)) => {
            let key = source_vault_key.ok_or(SshrackError::VaultLocked)?;
            Ok(Some(crypto::decrypt(&enc, key).map_err(|_| {
                SshrackError::DecryptionFailed { name: owner.name_label.to_string() }
            })?))
        }
    }
}

/// Delete both inline-keyring slots for an owner (best-effort, no orphans on
/// leaving keyring mode). A missing slot is success.
fn delete_inline_slots(backend: &dyn SecretBackend, owner: &SecretOwner<'_>) {
    let _ = backend.delete_at(&crate::id::keyring_key_inline_priv(owner.kind, &owner.id));
    let _ = backend.delete_at(&crate::id::keyring_key_inline_cert(owner.kind, &owner.id));
}
```

- [ ] **Step 4: Rewrite `migrate_body_inline_key`** (`transform.rs:359-393`)

Add `backend: &dyn SecretBackend` to the signature; `owner` already carries `kind`/`id`. Replace the short-circuit with real bidirectional handling:

```rust
fn migrate_body_inline_key(
    body: &mut CredentialBody,
    owner: &SecretOwner<'_>,
    target: &SecretStore,
    source_vault_key: Option<&VaultKey>,
    target_vault_key: Option<&VaultKey>,
    backend: &dyn SecretBackend,
) -> Result<bool, SshrackError> {
    let Some(KeySource::Inline(ik)) = &mut body.key else {
        return Ok(false);
    };
    // Extract the current plaintext (from the in-body Secret, or from the
    // keyring slots when this is a keyring-marker body), then re-seal per target.
    let priv_plain = extract_inline_text(
        ik.private_key.take(),
        owner,
        source_vault_key,
        InlineSlot::Private,
        backend,
    )?;
    let cert_plain = extract_inline_text(
        ik.certificate.take(),
        owner,
        source_vault_key,
        InlineSlot::Certificate,
        backend,
    )?;
    match target {
        SecretStore::Keyring => {
            if let Some(p) = &priv_plain {
                backend.set_at(&crate::id::keyring_key_inline_priv(owner.kind, &owner.id), p)?;
            } else {
                let _ = backend.delete_at(&crate::id::keyring_key_inline_priv(owner.kind, &owner.id));
            }
            if let Some(c) = &cert_plain {
                backend.set_at(&crate::id::keyring_key_inline_cert(owner.kind, &owner.id), c)?;
            } else {
                let _ = backend.delete_at(&crate::id::keyring_key_inline_cert(owner.kind, &owner.id));
            }
            ik.keyring = true;
        }
        SecretStore::Plaintext => {
            ik.private_key = priv_plain.map(|p| Secret::Plain(p.to_string()));
            ik.certificate = cert_plain.map(|c| Secret::Plain(c.to_string()));
            ik.keyring = false;
            delete_inline_slots(backend, owner);
        }
        SecretStore::Vault { .. } => {
            ik.private_key = priv_plain
                .as_ref()
                .map(|p| {
                    let k = target_vault_key.ok_or(SshrackError::VaultLocked)?;
                    Ok::<_, SshrackError>(Secret::Encrypted(crypto::encrypt(p.as_bytes(), k)?))
                })
                .transpose()?;
            ik.certificate = cert_plain
                .as_ref()
                .map(|c| {
                    let k = target_vault_key.ok_or(SshrackError::VaultLocked)?;
                    Ok::<_, SshrackError>(Secret::Encrypted(crypto::encrypt(c.as_bytes(), k)?))
                })
                .transpose()?;
            ik.keyring = false;
            delete_inline_slots(backend, owner);
        }
    }
    Ok(true)
}
```

Update `migrate_body` (`:299`) to pass `backend` into `migrate_body_inline_key` (it already has `backend` as a parameter — see the surrounding `:279-310`).

- [ ] **Step 5: Delete the dead `re_seal_inline_secret` function** (`transform.rs:407-441`)

`re_seal_inline_secret` was only called by the old `migrate_body_inline_key` (:378, :385). Step 4 replaced those calls with `extract_inline_text`. Grep to confirm zero callers, then delete the function and its doc comment (which contained the stale "Keyring arm is unreachable … short-circuits" note).

```bash
grep -rn "re_seal_inline_secret" crates/ src/
# Expected: only the transform.rs definition. Delete it.
```

- [ ] **Step 6: Ensure `leaving_keyring` deletes inline slots** (`transform.rs:322` / `:345`)

Find where migrating away from keyring deletes the password slot (grep `backend.delete` / `delete_at` in `transform.rs`). When a body had a keyring-stored inline key, call `delete_inline_slots(backend, owner)` alongside the password-slot deletion so no slot is orphaned. (If cleanup is centralized per-body, this is one call in the right place; the new `migrate_body_inline_key` Vault/Plaintext arms already call it for the inline-key text, but verify the host/credential that had a keyring inline key is fully cleaned when leaving keyring mode.)

- [ ] **Step 7: Run migration tests + full core suite — expect green**

Run: `cargo test -p sshrack-core --lib secret::vault::transform`
Then: `cargo test -p sshrack-core --lib`
Expected: the two new tests PASS; existing `migrate_plaintext_to_vault_encrypts_inline_key` / `migrate_vault_to_plaintext_decrypts_inline_key` / `migrate_vault_to_vault_rekeys_inline_key_under_new_key` still PASS; no reference to `re_seal_inline_secret` remains.

- [ ] **Step 8: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/secret/vault/transform.rs
git commit -m "fix(secret): migrate inline keys across store-mode switches; drop dead re_seal_inline_secret"
```

---

## Task 6: `count_secrets` + `rekey` cover inline keys

Two correctness gaps in the bookkeeping/rekey path: `count_secrets` under-counts keyring-marker inline bodies, and `decrypt_all`/`decrypt_body` (used by `store rekey`) only decrypt passwords — leaving inline-key ciphertext on the old vault key.

**Files:**
- Modify: `crates/sshrack-core/src/secret/vault/transform.rs` (`count_secrets` :79-110, `decrypt_all` :158-178, `decrypt_body` :128-154)
- Test: `transform.rs` test module

**Interfaces:**
- Consumes: Task 5 (consistent migration).
- Produces: no signature changes; `count_secrets` and `decrypt_all`/`decrypt_body` now cover inline-key material.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn count_secrets_counts_keyring_marker_inline_body() {
    // A keyring-marker inline body (ik.keyring = true) must count toward the
    // keyring total so `store status` and `store use` show accurate counts.
    use crate::config::schema::{InlineKey, KeySource};
    let cfg = SshrackConfig {
        hosts: vec![Host {
            id: Ulid::new(),
            name: "h".into(),
            host: "x".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "u".into(),
                password: None,
                key: Some(KeySource::Inline(InlineKey {
                    private_key: None,
                    certificate: None,
                    keyring: true,
                })),
                keyring: false,
            }),
        }],
        ..Default::default()
    };
    let (_enc, _plain, keyring) = count_secrets(&cfg);
    assert!(keyring >= 1, "keyring-marker inline body must be counted");
}
```

For the rekey fix, add a test mirroring `migrate_vault_to_vault_rekeys_inline_key_under_new_key` (`:905`) but exercising the `decrypt_all` → `enable` path (`store rekey`). Verify the inline key's `Encrypted` ciphertext is re-encrypted under the new key and decrypts to the original plaintext under that new key.

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p sshrack-core --lib secret::vault::transform`
Expected: the count test FAILS (keyring-marker body currently counts as 0); the rekey test FAILS (inline key not re-encrypted).

- [ ] **Step 3: Fix `count_secrets`** (`transform.rs:79-110`)

In the per-body loop, when `b.key` is `Some(KeySource::Inline(ik))`: if `ik.keyring` → increment `keyring`; else → count `private_key` and `certificate` as today. Remove the stale "Keyring-mode inline keys are rejected by validate" comment (`:97-98`):

```rust
if let Some(KeySource::Inline(ik)) = &b.key {
    if ik.keyring {
        keyring += 1;
    } else {
        if let Some(s) = &ik.private_key {
            count_one_secret(s, &mut enc, &mut plain);
        }
        if let Some(s) = &ik.certificate {
            count_one_secret(s, &mut enc, &mut plain);
        }
    }
}
```

- [ ] **Step 4: Fix `decrypt_body` / `decrypt_all` to decrypt inline-key Encrypted** (`transform.rs:128-178`)

In `decrypt_body`, after decrypting the password, also decrypt the inline key's `private_key` and `certificate` when they are `Encrypted`:

```rust
if let Some(KeySource::Inline(ik)) = &mut body.key {
    if let Some(Secret::Encrypted(enc)) = ik.private_key.take() {
        ik.private_key = Some(Secret::Plain(
            String::from_utf8_lossy(&crypto::decrypt(&enc, key)?).into_owned(),
        ));
    }
    if let Some(Secret::Encrypted(enc)) = ik.certificate.take() {
        ik.certificate = Some(Secret::Plain(
            String::from_utf8_lossy(&crypto::decrypt(&enc, key)?).into_owned(),
        ));
    }
}
```

`decrypt_all` calls `decrypt_body` per body, so it is fixed transitively. Preserve the return-count semantics (count an inline-key body as decrypted too).

- [ ] **Step 5: Run — expect green**

Run: `cargo test -p sshrack-core --lib secret::vault::transform`
Expected: both new tests PASS; existing count/rekey tests still PASS.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/secret/vault/transform.rs
git commit -m "fix(secret): count keyring inline keys and re-encrypt them on rekey"
```

---

## Task 7: Lifecycle — rm/cp/overwrite clean and copy all inline slots

`forget_keyring_secret` and the two `copy_keyring_entry` impls only handle the password slot. Extend them to the private + cert slots, and consolidate the duplicated `copy_keyring_entry` onto one shared helper.

**Files:**
- Modify: `crates/sshrack-core/src/secret/mod.rs` (`forget_keyring_secret` :83-92; new `forget_inline_keyring_slots` + `copy_inline_keyring_slots`)
- Modify: `crates/sshrack-core/src/host.rs` (`delete_host_with_secret` :451-465, `forget_keyring_on_overwrite` :477-483, `copy_keyring_entry` :490-505)
- Modify: `crates/sshrack-core/src/credential.rs` (`delete_credential_with_secret` :439-455, `copy_keyring_entry` :466-478)
- Test: respective test modules

**Interfaces:**
- Consumes: Task 1 (raw `delete_at`/`get`/`set_at` + inline helpers).
- Produces: `pub fn forget_inline_keyring_slots(backend, kind, id, marked: bool)`, `pub fn copy_inline_keyring_slots(backend, kind, src_id, dst_id) -> Result<bool, SshrackError>`.

- [ ] **Step 1: Write failing tests for the shared helpers** (`secret/mod.rs` tests)

```rust
#[test]
fn forget_inline_keyring_slots_deletes_priv_and_cert() {
    let id = Ulid::new();
    let be = FakeBackend::new();
    be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &id), "p").unwrap();
    be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &id), "c").unwrap();
    super::forget_inline_keyring_slots(&be, OwnerKind::Host, &id, true);
    assert!(be.get(&keyring_key_inline_priv(OwnerKind::Host, &id)).unwrap().is_none());
    assert!(be.get(&keyring_key_inline_cert(OwnerKind::Host, &id)).unwrap().is_none());
}

#[test]
fn copy_inline_keyring_slots_copies_priv_and_cert_to_new_owner() {
    let src = Ulid::new();
    let dst = Ulid::new();
    let be = FakeBackend::new();
    be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &src), "p").unwrap();
    be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &src), "c").unwrap();
    let copied = super::copy_inline_keyring_slots(&be, OwnerKind::Host, &src, &dst).unwrap();
    assert!(copied);
    assert_eq!(be.get(&keyring_key_inline_priv(OwnerKind::Host, &dst)).unwrap().as_deref(), Some("p"));
    assert_eq!(be.get(&keyring_key_inline_cert(OwnerKind::Host, &dst)).unwrap().as_deref(), Some("c"));
}
```

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p sshrack-core --lib secret::tests`
Expected: FAIL — functions undefined.

- [ ] **Step 3: Add the shared helpers** (`secret/mod.rs`, near `forget_keyring_secret` :83)

```rust
/// Best-effort delete of an owner's inline-key keyring slots (private +
/// certificate) when the owning body carried a keyring-stored inline key.
/// Never returns an error. Mirrors [`forget_keyring_secret`] for the inline
/// slots.
pub fn forget_inline_keyring_slots(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    id: &Ulid,
    marked: bool,
) {
    if marked {
        let _ = backend.delete_at(&crate::id::keyring_key_inline_priv(kind, id));
        let _ = backend.delete_at(&crate::id::keyring_key_inline_cert(kind, id));
    }
}

/// Copy an owner's inline-key keyring slots (private + certificate) from
/// `src_id` to `dst_id`, if the source has any. Returns `true` if at least one
/// slot was copied. Used by `host cp` so the cloned host owns its keyring key.
pub fn copy_inline_keyring_slots(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    src_id: &Ulid,
    dst_id: &Ulid,
) -> Result<bool, SshrackError> {
    let mut copied = false;
    let priv_key = crate::id::keyring_key_inline_priv(kind, src_id);
    if let Some(p) = backend.get(&priv_key)? {
        backend.set_at(&crate::id::keyring_key_inline_priv(kind, dst_id), &p)?;
        copied = true;
    }
    let cert_key = crate::id::keyring_key_inline_cert(kind, src_id);
    if let Some(c) = backend.get(&cert_key)? {
        backend.set_at(&crate::id::keyring_key_inline_cert(kind, dst_id), &c)?;
        copied = true;
    }
    Ok(copied)
}
```

- [ ] **Step 4: Wire them into host/credential delete + copy**

In `delete_host_with_secret` (`host.rs:451-465`) and `delete_credential_with_secret` (`credential.rs:439-455`): snapshot the body's inline-key keyring flag before deletion and call `forget_inline_keyring_slots` alongside the existing `forget_keyring_secret`.

In both `copy_keyring_entry` impls (host `:490-505`, credential `:466-478`): after copying the password slot, call `copy_inline_keyring_slots(backend, kind, &src.id, &dst.id)?`. Consolidate the duplicated password-slot copy logic onto a single shared helper too (or call the existing pattern + the new inline helper) — the goal is one implementation of "copy all keyring slots for an owner", not two. (The credential variant has no production caller today, but keeping both surfaces symmetric and de-duplicated matches the no-duplicate-logic rule.)

`forget_keyring_on_overwrite` (`host.rs:477-483`, used by `host add --force`): also forget inline slots when overwriting a host that had a keyring inline key.

- [ ] **Step 5: Run — expect green**

Run: `cargo test -p sshrack-core --lib`
Expected: new helper tests PASS; existing host/cred lifecycle tests still PASS. Add (or update) a `host cp` test asserting the cloned host's inline slots exist when the source had a keyring inline key.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add crates/sshrack-core/src/secret/mod.rs crates/sshrack-core/src/host.rs crates/sshrack-core/src/credential.rs
git commit -m "feat(secret): clean and copy inline-key keyring slots on rm/cp/overwrite"
```

---

## Task 8: Wire the entry points (TUI persist + CLI resolve callers)

Two surface fixes: (a) the TUI persist seal blocks only trigger on `password == Plain`, so inline-key plaintext is never sealed (a pre-existing TUI/CLI divergence — CLI already seals via `seal_inline_body`); (b) the resolve callers threaded in Task 4 are verified end-to-end here with integration-level coverage.

**Files:**
- Modify: `src/tui/persist.rs` (`persist_host_save` seal block :114-137, `persist_cred_save` seal block :313-338)
- Verify: `src/cli/cmd/connect.rs`, `src/cli/cmd/scp.rs`, `src/tui/connect.rs`, `src/tui/transfer/open.rs` (resolve callers — already changed in Task 4, verified here)
- Test: `src/tui/persist.rs` test module + integration tests in `tests/`

**Interfaces:**
- Consumes: Task 3 (seal handles keyring inline), Task 4 (resolve takes backend).
- Produces: TUI persist seals inline-key plaintext under any decided mode.

- [ ] **Step 1: Write a failing persist test** (`src/tui/persist.rs` test module, or `on_key`-level state test)

Construct an `App` in keyring mode, stage a host-add form with an inline private key, invoke the persist path, and assert the resulting body is a keyring marker (`ik.keyring == true`, no in-body text) with the text in a (fake) backend. Use the lightest layer that reaches the failure. If the persist functions use `OsKeyring` directly (`:127`/`:330`) and so cannot accept a fake, refactor minimally to take `&dyn SecretBackend` so the test injects `FakeBackend` (this is a testability improvement, not compat code).

- [ ] **Step 2: Run — expect failure (inline key sealed as plaintext, not keyring marker)**

Run: `cargo test --bin sshrack persist`
Expected: FAIL — the body still has `private_key: Some(Plain(...))` instead of a keyring marker.

- [ ] **Step 3: Widen the TUI persist seal triggers** (`src/tui/persist.rs:114-137` and `:313-338`)

Change the `if` condition so any in-body plaintext secret (password **or** inline key text) routes through `seal_body`. The predicate: "the body has a plaintext password OR a `KeySource::Inline` carrying a `Plain` private/cert." In `persist_host_save`:

```rust
// Seal any freshly collected plaintext secret (password OR inline key text)
// per the configured store mode. Previously only password was sealed, so an
// inline-key body's plaintext was written to config.toml verbatim even under
// vault/keyring mode — a divergence from the CLI path (which seals via
// seal_inline_body). Vault unlock via TuiPassphrase (no-op unless vault mode).
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
    let backend = OsKeyring;
    let sealed = vault::seal_body(
        body.clone(),
        OwnerKind::Host,
        &target_id,
        &app.config,
        vault_key.as_ref(),
        &backend,
    )?;
    auth = Auth::inline(sealed);
}
```

Add a small pure helper (in `persist.rs`):

```rust
/// True if the body carries a freshly collected plaintext secret that must be
/// sealed per the store mode: a plaintext password, or an inline key with
/// plaintext private/cert text. Already-sealed (Encrypted) or marker bodies
/// pass through unchanged.
fn body_has_plaintext_secret(body: &sshrack_core::config::schema::CredentialBody) -> bool {
    use sshrack_core::config::schema::{KeySource, Secret};
    if matches!(body.password, Some(Secret::Plain(_))) {
        return true;
    }
    matches!(
        &body.key,
        Some(KeySource::Inline(ik)) if matches!(ik.private_key, Some(Secret::Plain(_)))
            || matches!(ik.certificate, Some(Secret::Plain(_)))
    )
}
```

Apply the same widening to `persist_cred_save` (`:313-338`) using `OwnerKind::Credential`.

- [ ] **Step 4: Run the persist test — expect PASS**

Run: `cargo test --bin sshrack persist`
Expected: PASS — TUI now seals inline keys under keyring mode.

- [ ] **Step 5: Add an integration test for the connect path under keyring mode**

In `tests/` (alongside the existing mock-ssh shim tests), add a test that: builds a config in keyring mode with a host whose inline key text is in a seeded keyring, runs the connect pre-exec path, and asserts the materialized temp file contains the key text and the ssh argv carries `-i <tempfile>`. Mirror existing `connect_flow_test` patterns. Assert the key text never appears in argv (the existing secret-never-in-argv invariant).

- [ ] **Step 6: Run the full suite under a pty — expect green**

Run: `script -qec "cargo test --workspace" /dev/null`
Expected: PASS.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add src/tui/persist.rs tests/
git commit -m "fix(tui): seal inline-key plaintext under any store mode; verify keyring connect path"
```

---

## Task 9: Docs + end-to-end smoke

Correct the stale architecture doc, record the design in memory, and provide a manual smoke checklist for the original bug scenario.

**Files:**
- Modify: `docs/architecture.md` (:79)
- Create: memory file `keyring-inline-key.md` + index line in `MEMORY.md`

**Interfaces:** None (docs only).

- [ ] **Step 1: Correct `docs/architecture.md:79`**

The line currently says inline contents are "clear text under plaintext — **keyring mode rejects them at validation time**". Replace with:

```markdown
…sealed as `Secret` (Argon2id + XChaCha20-Poly1305 under vault, clear text under plaintext, **OS-keyring-stored under keyring mode** — the private key and optional certificate text live in the keyring under `<kind>:<id>#ikpriv` / `#ikcert` slots, and the body carries only an `ik.keyring = true` marker); at connect time, materialized to a `0600` temp file for `ssh -i` and deleted after the connection…
```

- [ ] **Step 2: Write the memory file** (`/home/ryan/.claude/projects/-home-ryan-workspace-open-source-sshrack/memory/keyring-inline-key.md`)

```markdown
---
name: keyring-inline-key
description: keyring 模式完整支持 inline key(私钥/证书存 OS keyring #ikpriv/#ikcert 槽,body 留 marker);merged <HASH> 2026-07-08
metadata:
  type: project
---

sshrack keyring 模式曾不支持 inline key:`validate` 声称拒绝但实际只看 body marker(不看 store 模式),`migrate_body_inline_key` 对 keyring 目标短路(transform.rs:375-377)把 vault 时代的 Encrypted 残留原封保留,`resolve` 撞见 Encrypted+无 vault key 时经 decrypt_secret 返 VaultLocked(credential.rs:510),keyring 模式下状态栏显示 "run sshrack store unlock" 完全误导。

修复(<HASH>,plan `docs/superpowers/plans/2026-07-08-keyring-inline-key.md`)激活了已预留的 `InlineKey.keyring` 字段:keyring 模式下私钥/证书文本存 OS keyring 两个槽(`<kind>:<id>#ikpriv`/`#ikcert`,helper `id::keyring_key_inline_priv`/`_cert`),body 只留 marker(无私钥文本,validate 放行)。`SecretBackend` 加 raw `set_at`/`delete_at`(get 已 raw),`set`/`delete(kind,id)` 变默认方法。

核心改动:`seal_inline_key`(vault/mod.rs)加 kind/id/backend + keyring 分支(对称 seal_password);`resolve`(credential.rs)加 backend 参数(6 生产 + ~17 测试 caller)+ keyring 读取分支,inline 仍走 `decrypt_secret`(Encrypted+无 vault key → VaultLocked,在 vault 模式准确;keyring 模式下该态不可达,不为它写专门错误);`migrate_body_inline_key` 不再短路,双向迁移 vault↔keyring/plaintext↔keyring(此前 vault→keyring 零测试);`count_secrets`/`decrypt_all` 覆盖 inline(pre-existing rekey bug 顺手修);lifecycle(rm/cp/overwrite)清理/复制两槽(共享 `copy_inline_keyring_slots`/`forget_inline_keyring_slots`,消除 host/cred 重复)。

Dev-stage 清理(无兼容):删死变体 `InlineKeyNeedsVaultOrPlaintext`(放开 validate 后无 caller)、删死函数 `re_seal_inline_secret`(migrate 重写后无 caller)、清所有"validate rejects keyring"过时注释。**不为旧 bug 的脏数据残留写专门错误/容错**——migrate 修好后该态不可达;用户既有脏 host(如 ets-135)删掉重建。关联 [[inline-key-content-design]](原"keyring 不支持 inline"已升级兑现)、[[unified-error-feedback]]、[[tty-safe-sftp-open]]。
```

Replace `<HASH>` with the actual merge commit hash after the branch lands. Add the index line to `MEMORY.md`:

```markdown
- [keyring inline key](keyring-inline-key.md) — keyring 模式完整支持 inline key(#ikpriv/#ikcert 两槽 + ik.keyring marker;修 migrate 短路/误报;删 InlineKeyNeedsVaultOrPlaintext + re_seal_inline_secret 死代码)
```

- [ ] **Step 3: Manual smoke checklist (run after merge)**

Provide this to the user (no automation):
1. `sshrack` (TUI) → add a host with an inline private key under keyring mode → confirm `config.toml` shows `auth.key.keyring = true` with no `private_key` text; confirm the key text is in the `#ikpriv` keyring slot (`secret-tool lookup ...` or platform equivalent).
2. Connect to that host → confirm ssh spawns and authenticates (temp file materialized).
3. `store use vault` then `store use keyring` round-trip → inline key migrates correctly both ways (no stranded ciphertext, no orphan slots).
4. `store rekey` under vault mode → inline key re-encrypted under the new key.
5. The original bug repro is now structurally gone — a clean keyring-mode install never produces a stranded Encrypted inline key. (The user's existing `ets-135` stale entry must be deleted and re-added by hand — no repair command, by design.)

- [ ] **Step 4: Commit docs**

```bash
git add docs/architecture.md
git commit -m "docs: keyring mode stores inline keys in the OS keyring"
```

(Memory files live outside the repo; they are written directly, not committed.)

---

## Self-Review

**1. Spec coverage** (the three user decisions + the root-cause report's layers):
- *Decision ① (inline key text in OS keyring):* Task 1 (slots/helpers), Task 3 (seal writes slots), Task 4 (resolve reads slots), Task 5 (migrate moves slots). ✓
- *Decision ② (TUI + CLI full path):* Task 8 (TUI persist widened + CLI resolve callers + integration test). CLI identity-import already routes through `seal_inline_body` → `seal_body`, so Task 3's seal change covers it; Task 8 verifies. ✓
- *Decision ③ (manual rebuild; no repair command; no compat code):* no `InlineKeyUnreadable`, no "re-add" guidance — the stale-residual state is made structurally unreachable (Task 5 fixes the only producer). Existing dirty entries are rebuilt by hand. Dead variant/function/comments deleted in-task. ✓
- *Root-cause layer 1 (error semantics):* resolved by removal, not addition — `VaultLocked` stays accurate (vault mode = go unlock; keyring mode = unreachable). ✓
- *Root-cause layer 2 (migrate short-circuit):* Task 5. ✓
- *Root-cause layer 3 (design fissure — validate allows, migrate/resolve assumed unreachable):* Task 2 (validate deliberately allows) + Task 3/4/5 (the now-reachable state handled everywhere). ✓
- *Pre-existing bugs surfaced & fixed:* TUI persist never sealed inline keys (Task 8); rekey didn't re-encrypt inline keys (Task 6); leaving-keyring left inline orphans (Task 5). ✓
- *Dev-stage cleanup:* `InlineKeyNeedsVaultOrPlaintext` deleted (Task 2); `re_seal_inline_secret` deleted (Task 5); stale "validate rejects keyring" comments cleaned (Tasks 3, 6). ✓

**2. Placeholder scan:** No "TBD"/"TODO"/"add error handling"/"similar to Task N". Every code step has the actual code. The `VaultKey::from([u8;32])` constructor in Task 5 is pinned to the existing `migrate_vault_to_vault_rekeys_inline_key_under_new_key` test (`:905`) by name — the implementer reads that test and mirrors it. ✓

**3. Type consistency:** `keyring_key_inline_priv`/`_cert(kind, id) -> String` used identically in Tasks 1/3/4/5/7. `set_at(&self, key: &str, secret: &str)`/`delete_at(&self, key: &str)` identical in Tasks 1/3/5/7. `resolve(..., backend: &dyn SecretBackend)` identical across Task 4 callers. `seal_inline_key(ik, kind, id, cfg, vault_key, backend)` in Task 3, called from `seal_body`. No `InlineKeyUnreadable`/`read_inline_secret` remain. ✓

**4. Task ordering / dependencies:** 1 → {2,3,4,5,7} → {6,8} → 9. Each task ends with a compiling, tested, committed state. No task depends on a later task. ✓

**5. Risk notes for the implementer:**
- Task 4 is the largest (resolve signature change touches ~23 call sites). Budget the most review attention there. Grep `::resolve(` and exclude `config::path::resolve` / `host::resolve_target` to avoid false edits.
- Task 5 changes `migrate_body_inline_key`'s signature — `migrate` (public) already has `backend`, so no external caller changes, but the internal `migrate_body` threading must be verified.
- `VaultKey::from([u8; 32])` — confirm the constructor exists by reading the existing `:905` test; mirror it exactly.
- If `persist.rs` uses `OsKeyring` literally, Task 8 step 1 requires a minimal refactor to accept `&dyn SecretBackend` for testability — keep it minimal and note it in the commit. This is a testability improvement, not compat code.
- The "encrypted inline key under keyring mode" state is unreachable after Task 5; do not add defensive handling for it anywhere. If a test needs the body, build it via the migration path (vault → keyring), not by hand-constructing an impossible body.
