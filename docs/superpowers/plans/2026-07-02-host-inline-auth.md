# Host Inline Auth (Reference / Independent) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Let a host carry its own auth ("Independent": user + None/Password/IdentityKey) instead of only referencing a `[[credentials]]` entry ("Reference"), in both the TUI wizard and the CLI — without weakening the "passwords never enter argv" security invariant.

**Architecture:** Core is already complete (`Auth::Inline(CredentialBody)` exists; the keyring lifecycle is fully keyed by `OwnerKind::Host` + the host ULID; `seal_body(.., OwnerKind::Host, ..)` works; `apply_patch`/`patch_body` already patch inline bodies). The real bottleneck is the TUI host wizard: its `AuthChoice` is a 3-state `Default/Credential/InlineKey` with `InlinePassword` intentionally removed, and `persist_host_save` never seals a password. This plan rebuilds the host wizard's auth as a 2-state **Reference / Independent** chooser where Independent reuses the credential wizard's existing `SecretChoice` (None/Password/IdentityKey) and `persist_host_save` gains the same seal step `persist_cred_save` already runs (with `OwnerKind::Host`). The CLI already supports both modes (`--user`/`--identity` = Independent, `--credential` = Reference); inline **password** stays TUI-only because passwords never enter argv — so the CLI task is terminology alignment + regression tests, not new behavior.

**Tech Stack:** Rust 2024, MSRV 1.86, ratatui 0.30, crossterm 0.28, zeroize, ulid, sshrack-core (pure backend, zero-UI).

## Global Constraints

Copied verbatim from `CLAUDE.md` hard rules — every task implicitly inherits these:

- **English only** — all source, comments, doc comments, errors, help text, logs, commits.
- **Zero `unsafe`** — never, including tests. Rust 2024 `set_var` is unsafe; tests inject via seams.
- **Zero `unwrap()`/`expect()`** in production code — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR. `build_auth`, `reachable_fields`, `new_edit` round-trip are pure.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv/`ps`. A redacting `Debug` impl is required on any struct holding a password (mirror `CredForm`'s redacting `Debug`).
- **Keyring mode: main process never materializes a keyring password's plaintext** — only the `SSH_ASKPASS` helper reads it (`seal_body` writes the keyring entry + sets `body.keyring = true` + clears `body.password`).
- **Tests hermetic** — `cargo test --bin sshrack` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **`sshrack-core` zero-UI invariant** — its `Cargo.toml` never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`.
- **Dev stage, no compat code** — no transition shims, no dead variants left behind. The old `AuthChoice::Default`/`Credential`/`InlineKey` and `AuthKind::Default`/`Credential`/`InlineKey` must be fully removed, not retained "just in case".
- **Never reimplement SSH** — no `russh`/`ssh2`/`russh-sftp`.
- **cargo test uses `--bin sshrack`** (binary crate, no `--lib`).

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Each task ends with a commit.

---

## Background (read this before any task)

**The host auth model today (`crates/sshrack-core/src/config/schema.rs`):**

```rust
pub enum Auth {
    Ref { credential: Ulid },          // reference a [[credentials]] entry by id
    Inline(CredentialBody),             // host-own user + optional secret
}
pub struct CredentialBody {
    pub user: String,
    pub password: Option<Secret>,       // Secret::Plain(plaintext) before sealing
    pub key: Option<PathBuf>,
    pub keyring: bool,                  // marker: password lives in OS keyring
}
```

`Auth::Inline` already carries a full `CredentialBody`, so an inline **password** is representable today. Core's keyring lifecycle already treats a host as a secret owner:

- `id::keyring_key(OwnerKind::Host, &id)` → `"host:{id}"` (`crates/sshrack-core/src/id.rs:23-27`).
- `host::delete_host_with_secret` forgets the keyring entry when `auth.inline_body().keyring` (`host.rs:445-459`).
- `host::forget_keyring_on_overwrite` handles `host add --force` (`host.rs:471-477`).
- `host::copy_keyring_entry` handles `host cp` (`host.rs:484-495`).
- `host::apply_patch` / `patch_body` patch an inline body and preserve the keyring marker (`host.rs:345-403`).
- `credential::resolve` returns a `PasswordSource` for both `Auth::Ref` and `Auth::Inline`, including `Keyring { key }` for keyring-marked bodies (`credential.rs:439-495`).
- `vault::seal_body(body, OwnerKind::Host, &id, cfg, vault_key, backend)` is already exercised by a test (`secret/vault/mod.rs:567`).

**So core needs zero changes.** Every task below is in the frontend (`src/tui/`, `src/cli/`, `src/shared/`) plus docs.

**The credential wizard is the template.** `src/tui/wizard/cred.rs` already does everything the host wizard needs to learn:

- `CredForm { name, user, identity, secret_kind: SecretChoice, password: Zeroizing<String>, … }` with a redacting `Debug` (`cred.rs:32-84`).
- `SecretChoice { None, Password, IdentityKey }` with `ORDER`/`next`/`prev`/`label` (`mod.rs:199-242`).
- `reachable_fields()` / `move_focus()` / `is_last_reachable()` — conditional field navigation that skips `Password` unless the secret choice is Password (`cred.rs:150-180`).
- `edit_focused_push`/`pop` routing chars to the password field only under Password (`cred.rs:261-299`).
- `build_body()` assembling a `CredentialBody` with a plaintext `Secret::Plain` password (`cred.rs:319-340`).
- `draw_in_dialog` / `cursor_target` / `render_row` / `row_value_and_placeholder` rendering reachable rows + masking the password (`cred.rs:345-468`).
- `persist_cred_save` sealing the plaintext password via `vault::seal_body(.., OwnerKind::Credential, &id, ..)` with a store-mode-undecided guard and vault unlock (`app.rs:1660-1767`).

The host wizard gains the **same** secret-handling ability, plus a Reference/Independent auth chooser that the credential wizard does not have.

**Why this is one atomic task, not several.** `AuthChoice` and `Field` are shared enums; changing them breaks every `match` in `host.rs` at once. And `SecretChoice::Password` must become reachable in the host wizard together with the `persist_host_save` seal step — otherwise `build_auth` emits a plaintext `body.password` that the unmodified `persist_host_save` writes to disk in the clear. Task 1 therefore lands the whole TUI host-wizard rewrite end-to-end in one commit.

---

## File Structure

```
src/tui/wizard/
├── mod.rs          # MODIFY: AuthChoice → Reference/Independent; AuthKind → Reference/Independent;
│                   #         Field gains Secret/Identity/Password; label/ORDER; module docs rewrite
├── host.rs         # MODIFY: HostForm gains secret_kind/identity/password; inline_key → identity;
│                   #         new_add/new_edit/build_auth/reachable_fields/move_focus/validate;
│                   #         on_key/edit_focused_*/cursor_target/draw_in_dialog/render_row/row_value_and_placeholder
└── cred.rs         # UNCHANGED (the template)
src/tui/
└── app.rs          # MODIFY: persist_host_save gains the inline-password seal step (mirror persist_cred_save)
src/cli/
├── args.rs         # MODIFY: HostAction::Add/Edit help text terminology alignment (independent / reference)
└── cmd/host.rs     # VERIFY: error messages use the same terminology; add/keep regression coverage
src/shared/
└── format.rs       # UNCHANGED (already displays inline vs ref correctly via auth_kind_label/user_of)
CLAUDE.md           # MODIFY: document the host auth model (Reference/Independent) + CLI parity
crates/sshrack-core/ # UNCHANGED
```

---

## Task 1: TUI host wizard — Reference/Independent auth + Independent secret + persist seal

**Files:**
- Modify: `src/tui/wizard/mod.rs` (AuthChoice, AuthKind, Field, labels, module docs)
- Modify: `src/tui/wizard/host.rs` (HostForm, construction, build_auth, navigation, on_key, render)
- Modify: `src/tui/app.rs` (`persist_host_save` gains the seal step)
- Test: `src/tui/wizard/mod.rs` `#[cfg(test)]`, `src/tui/wizard/host.rs` `#[cfg(test)]`, `src/tui/app.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `sshrack_core::config::schema::{Auth, CredentialBody, Host, SecretKind, Secret}`; `super::wizard::SecretChoice` (already in `mod.rs`); `zeroize::Zeroizing`; the `persist_cred_save` seal block (`app.rs:1709-1739`) as the literal template.
- Produces:
  - `pub enum AuthChoice { Reference { idx: usize }, Independent }` (replaces `Default`/`Credential`/`InlineKey`).
  - `enum AuthKind { Reference, Independent }` (replaces `Default`/`Credential`/`InlineKey`).
  - `pub enum Field { Name, Host, Port, User, Auth, Secret, Identity, Password }` (gains `Secret`/`Identity`/`Password`).
  - `HostForm` gains `pub secret_kind: SecretChoice`, `pub identity: String` (renamed from `inline_key`), `pub password: Zeroizing<String>`; redacting `Debug`.
  - `HostForm::build_auth(resolved_credential: Option<Ulid>) -> Auth` (Independent assembles the inline body including a plaintext password under `SecretChoice::Password`).
  - `persist_host_save` seals an inline plaintext password via `vault::seal_body(.., OwnerKind::Host, &target_id, ..)` before persist.

### Step 1: Write failing tests (RED)

Add to `src/tui/wizard/host.rs` `#[cfg(test)]` module. These pin the new contract before any code changes them from red.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::{Auth, CredentialBody, Secret, SecretKind};

    fn form_independent(secret: SecretChoice) -> HostForm {
        let mut f = HostForm::new_add(vec![]);
        f.name = "web1".into();
        f.host_addr = "10.0.0.1".into();
        f.auth_choice = AuthChoice::Independent;
        f.secret_kind = secret;
        f
    }

    #[test]
    fn build_auth_independent_none_is_inline_default_body() {
        let f = form_independent(SecretChoice::None);
        let Auth::Inline(body) = f.build_auth(None) else { panic!("inline") };
        assert_eq!(body.user, "root"); // empty user falls back to root
        assert_eq!(body.secret_kind(), SecretKind::Default);
    }

    #[test]
    fn build_auth_independent_identity_key_attaches_key() {
        let mut f = form_independent(SecretChoice::IdentityKey);
        f.identity = "/home/u/.ssh/id_ed25519".into();
        let Auth::Inline(body) = f.build_auth(None) else { panic!("inline") };
        assert_eq!(body.user, "root");
        assert_eq!(body.secret_kind(), SecretKind::Key);
    }

    #[test]
    fn build_auth_independent_password_attaches_plaintext() {
        let mut f = form_independent(SecretChoice::Password);
        f.password = Zeroizing::new("hunter2".into());
        let Auth::Inline(body) = f.build_auth(None) else { panic!("inline") };
        assert_eq!(body.user, "root");
        assert_eq!(body.secret_kind(), SecretKind::Password);
        assert_eq!(body.password.as_ref().and_then(Secret::as_plain), Some("hunter2"));
    }

    #[test]
    fn build_auth_reference_uses_resolved_id() {
        let mut f = HostForm::new_add(vec!["ops".into()]);
        f.name = "web1".into();
        f.host_addr = "10.0.0.1".into();
        f.auth_choice = AuthChoice::Reference { idx: 0 };
        let id = Ulid::new();
        assert!(matches!(f.build_auth(Some(id)), Auth::Ref { credential } if credential == id));
    }

    #[test]
    fn reachable_fields_reference_skips_user_and_secret_rows() {
        let f = form_independent(SecretChoice::None); // baseline
        let mut r = f;
        r.auth_choice = AuthChoice::Reference { idx: 0 };
        let fields = r.reachable_fields();
        assert!(fields.contains(&Field::Auth));
        assert!(!fields.contains(&Field::User));
        assert!(!fields.contains(&Field::Secret));
        assert!(!fields.contains(&Field::Password));
    }

    #[test]
    fn reachable_fields_independent_password_exposes_password_not_identity() {
        let mut f = form_independent(SecretChoice::Password);
        let fields = f.reachable_fields();
        assert!(fields.contains(&Field::Password));
        assert!(!fields.contains(&Field::Identity));
    }

    #[test]
    fn new_edit_inline_password_round_trips_to_independent_password_no_plaintext() {
        let host = Host {
            id: Ulid::new(), name: "h".into(), host: "1.1.1.1".into(), port: 22,
            auth: Auth::Inline(CredentialBody::new("root").with_password("hunter2")),
        };
        let f = HostForm::new_edit(&host, vec![], None);
        assert!(matches!(f.auth_choice, AuthChoice::Independent));
        assert_eq!(f.secret_kind, SecretChoice::Password);
        assert!(f.password.is_empty(), "plaintext must never be echoed back into the form");
    }
}
```

Run: `cargo test --bin sshrack wizard::host 2>&1 | tail -20`
Expected: FAIL (the variants/fields/methods do not exist yet).

### Step 2: Rewrite `src/tui/wizard/mod.rs` enums + labels

Replace the three-state `AuthChoice`/`AuthKind` block (`mod.rs:39-79`) with the two-state form. Replace the `Field` enum (`mod.rs:81-136`) to add `Secret`/`Identity`/`Password`.

```rust
/// The selectable auth strategies offered by the host wizard. Two states only:
/// reuse a named `[[credentials]]` entry, or carry an inline (host-own) config.
/// This is the wizard's own input shape — distinct from core's [`Auth`] because
/// the wizard works in *names* (a credential name the user picks) while core
/// stores *ids* (the loop resolves name→id before persist). The inline secret
/// kind is a separate [`SecretChoice`] row that appears only under Independent.
///
/// [`Auth`]: sshrack_core::config::schema::Auth
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthChoice {
    /// Reuse a named `[[credentials]]` entry. `idx` indexes the credential
    /// list the wizard was constructed with; the loop reads the name and
    /// resolves it to an id at save time.
    Reference { idx: usize },
    /// Host-own auth: an inline user plus an optional secret (None / Password /
    /// IdentityKey), chosen on the Secret row.
    Independent,
}

impl AuthChoice {
    /// Display order used by the auth chooser's `←`/`→` cycling. Independent
    /// first: it is the zero-config default (a fresh host with no credential
    /// yet defined should be addable without forcing a detour to the cred tab).
    const ORDER: &'static [AuthKind] = &[AuthKind::Independent, AuthKind::Reference];

    /// Which slot in [`AuthChoice::ORDER`] this variant occupies.
    fn kind(&self) -> AuthKind {
        match self {
            AuthChoice::Reference { .. } => AuthKind::Reference,
            AuthChoice::Independent => AuthKind::Independent,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    Independent,
    Reference,
}

/// The focused field in the host form. `Tab`/`↑`/`↓` (and `Enter` to advance)
/// move through the reachable ones in declaration order; the last reachable
/// field's `Enter` triggers a save. `User`/`Secret`/`Identity`/`Password` are
/// reachable only under [`AuthChoice::Independent`] (and `Identity`/`Password`
/// further depend on [`SecretChoice`]); the form filters them at navigation
/// time via [`HostForm::reachable_fields`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Host,
    Port,
    User,
    Auth,
    Secret,
    Identity,
    Password,
}

impl Field {
    /// Top-to-bottom render + navigation order.
    const ORDER: &'static [Field] = &[
        Field::Name,
        Field::Host,
        Field::Port,
        Field::User,
        Field::Auth,
        Field::Secret,
        Field::Identity,
        Field::Password,
    ];

    fn idx(self) -> usize {
        Self::ORDER
            .iter()
            .position(|f| *f == self)
            .expect("invariant: every Field variant is in ORDER")
    }

    /// Human label shown in the form. Capitalized so the add/edit forms read
    /// "Name" / "Host" / ... rather than lowercase.
    fn label(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Host => "Host",
            Field::Port => "Port",
            Field::User => "User",
            Field::Auth => "Auth",
            Field::Secret => "Secret",
            Field::Identity => "Identity",
            Field::Password => "Password",
        }
    }

    // NOTE: remove the old `next`/`prev`/`is_last` methods — navigation now goes
    // through HostForm::reachable_fields + move_focus (mirroring CredForm), so a
    // flat ORDER-based next/prev is wrong once rows are conditional. Delete them
    // outright; do not leave them dead (dev-stage no-dead-code rule).
}
```

Update the existing `host_field_labels_are_capitalized` test (`mod.rs:398-417`) to assert the three new labels too:

```rust
assert_eq!(Field::Auth.label(), "Auth");
assert_eq!(Field::Secret.label(), "Secret");
assert_eq!(Field::Identity.label(), "Identity");
assert_eq!(Field::Password.label(), "Password");
```

The shared `HOST_VALUE_COL` (`mod.rs:357`) is `2 + 5 + 2` (label padded to 5). The new labels `Identity`/`Password`/`Secret` are up to 8 chars, so bump the host label pad to 8 to match credentials, and update the constant:

```rust
pub(super) const HOST_VALUE_COL: u16 = 2 + 8 + 2;
```

…and update `render_row`'s `format!("{cursor}{label:>5}: ")` to `{label:>8}: ` (see Step 5).

`SecretChoice`, `CredField`, `validate_cred`, `value_spans` are **unchanged**.

### Step 3: Rewrite `HostForm` state, construction, `build_auth`, navigation, `validate`

Replace the `HostForm` struct (`host.rs:31-73`), `new_add`/`new_edit` (`host.rs:75-144`), `cycle_auth`/`cycle_credential`/`selected_credential_name`/`parsed_port`/`build_auth` (`host.rs:146-233`). Keep `set_core_error`.

```rust
use zeroize::Zeroizing;

/// The host form's editable state. All text fields are owned `String`s; the
/// password is `Zeroizing` so it is wiped on drop. The wizard builds this empty
/// (add mode) or prefilled from an existing [`Host`] (edit mode).
#[derive(Clone)]
pub struct HostForm {
    pub name: String,
    pub host_addr: String,
    /// Port as a string (parsed at save time; empty falls back to 22).
    pub port: String,
    /// Inline login user. Used only under Independent (Reference pulls the user
    /// from the referenced credential). Empty falls back to "root" at save.
    pub user: String,
    pub auth_choice: AuthChoice,
    /// Secret kind for the Independent branch (None / Password / IdentityKey).
    /// Ignored under Reference.
    pub secret_kind: SecretChoice,
    /// Identity-key path, edited when secret_kind is IdentityKey.
    pub identity: String,
    /// Masked password, edited when secret_kind is Password. `Zeroizing` so it
    /// is wiped on drop; never echoed back from an existing host (edit re-types).
    pub password: Zeroizing<String>,
    pub focus: Field,
    pub error: Option<SaveError>,
    pub core_error: Option<String>,
    pub editing: bool,
    pub orig_id: Option<Ulid>,
    pub credential_names: Vec<String>,
}

impl std::fmt::Debug for HostForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the password — mirrors CredForm's redacting Debug so a
        // format!("{:?}", form) / dbg!(form) can never leak plaintext.
        f.debug_struct("HostForm")
            .field("name", &self.name)
            .field("host_addr", &self.host_addr)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("auth_choice", &self.auth_choice)
            .field("secret_kind", &self.secret_kind)
            .field("identity", &self.identity)
            .field("password", &"<redacted>")
            .field("focus", &self.focus)
            .field("error", &self.error)
            .field("core_error", &self.core_error)
            .field("editing", &self.editing)
            .field("orig_id", &self.orig_id)
            .field("credential_names", &self.credential_names)
            .finish()
    }
}

impl HostForm {
    /// Fresh add-mode form: Independent + None (zero-config default), focus Name.
    pub fn new_add(credential_names: Vec<String>) -> Self {
        Self {
            name: String::new(),
            host_addr: String::new(),
            port: String::new(),
            user: String::new(),
            auth_choice: AuthChoice::Independent,
            secret_kind: SecretChoice::None,
            identity: String::new(),
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: false,
            orig_id: None,
            credential_names,
        }
    }

    /// Edit-mode form prefilled from `host`. Reference → Reference{idx}; Inline
    /// → Independent + secret_kind derived from the body. The password is NEVER
    /// carried into the form: the user re-types to change it, and leaving the
    /// field empty on a Password-kind edit keeps the existing secret (handled by
    /// the loop at save time, mirroring CredForm).
    pub fn new_edit(
        host: &Host,
        credential_names: Vec<String>,
        referenced_credential_name: Option<&str>,
    ) -> Self {
        let (auth_choice, user, secret_kind, identity) = match &host.auth {
            Auth::Ref { .. } => {
                let idx = referenced_credential_name
                    .and_then(|name| credential_names.iter().position(|n| n == name))
                    .unwrap_or(0);
                (AuthChoice::Reference { idx }, String::new(), SecretChoice::None, String::new())
            }
            Auth::Inline(body) => {
                use sshrack_core::config::schema::SecretKind;
                let u = body.user.clone();
                let (sk, iden) = match body.secret_kind() {
                    SecretKind::Key => (
                        SecretChoice::IdentityKey,
                        body.key
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ),
                    SecretKind::Password | SecretKind::KeyringPassword => {
                        (SecretChoice::Password, String::new())
                    }
                    SecretKind::Default => (SecretChoice::None, String::new()),
                };
                (AuthChoice::Independent, u, sk, iden)
            }
        };
        Self {
            name: host.name.clone(),
            host_addr: host.host.clone(),
            port: host.port.to_string(),
            user,
            auth_choice,
            secret_kind,
            identity,
            password: Zeroizing::new(String::new()),
            focus: Field::Name,
            error: None,
            core_error: None,
            editing: true,
            orig_id: Some(host.id),
            credential_names,
        }
    }

    /// Advance the auth chooser by `delta` (signed), wrapping. When the current
    /// choice is Reference, also cycles the credential list (so `←`/`→` first
    /// land on Reference, then further presses cycle names). Pure.
    fn cycle_auth(&mut self, delta: i32) {
        let cur_kind = self.auth_choice.kind();
        let order = AuthChoice::ORDER;
        let cur_pos = order
            .iter()
            .position(|k| *k == cur_kind)
            .expect("invariant: every AuthChoice variant is in ORDER");
        let next_pos = (cur_pos as i32 + delta).rem_euclid(order.len() as i32) as usize;
        let next_kind = order[next_pos];
        self.auth_choice = match next_kind {
            AuthKind::Independent => AuthChoice::Independent,
            AuthKind::Reference => {
                let prev_idx = match self.auth_choice {
                    AuthChoice::Reference { idx } => idx,
                    _ => 0,
                };
                let idx = if self.credential_names.is_empty() {
                    0
                } else {
                    prev_idx.min(self.credential_names.len() - 1)
                };
                AuthChoice::Reference { idx }
            }
        };
    }

    /// Cycle the credential index within the Reference chooser by `delta`.
    fn cycle_credential(&mut self, delta: i32) {
        let n = self.credential_names.len();
        if n == 0 {
            return;
        }
        let cur = match self.auth_choice {
            AuthChoice::Reference { idx } => idx,
            _ => 0,
        };
        let next = (cur as i32 + delta).rem_euclid(n as i32) as usize;
        self.auth_choice = AuthChoice::Reference { idx: next };
    }

    /// The currently-selected credential name, if Reference and idx in range.
    pub fn selected_credential_name(&self) -> Option<&str> {
        match self.auth_choice {
            AuthChoice::Reference { idx } => self.credential_names.get(idx).map(String::as_str),
            _ => None,
        }
    }

    pub fn parsed_port(&self) -> u16 {
        self.port.trim().parse::<u16>().unwrap_or(22)
    }

    /// Build the inline [`CredentialBody`] for the Independent branch. Pure.
    /// A non-empty Password field attaches a plaintext [`Secret::Plain`]; the
    /// loop seals it per the store mode after this. An empty Password field
    /// leaves the body without a password (the loop preserves the existing
    /// password in edit mode).
    fn build_inline_body(&self) -> CredentialBody {
        let user = if self.user.trim().is_empty() {
            "root".to_string()
        } else {
            self.user.clone()
        };
        match self.secret_kind {
            SecretChoice::None => CredentialBody::new(user),
            SecretChoice::IdentityKey => {
                let key = self.identity.trim();
                let mut body = CredentialBody::new(user);
                if !key.is_empty() {
                    body = body.with_key(key);
                }
                body
            }
            SecretChoice::Password => {
                let pw = self.password.as_str();
                if pw.is_empty() {
                    CredentialBody::new(user)
                } else {
                    CredentialBody::new(user).with_password(pw)
                }
            }
        }
    }

    /// Build the core [`Auth`] for this form, given the resolved credential id
    /// (if any). Pure. A None id for a Reference choice falls back to an inline
    /// default body (the loop will have already failed validation before
    /// reaching here in the real path, but this keeps the function total).
    pub fn build_auth(&self, resolved_credential: Option<Ulid>) -> Auth {
        match self.auth_choice {
            AuthChoice::Reference { .. } => match resolved_credential {
                Some(id) => Auth::reference(id),
                None => Auth::inline(CredentialBody::new(
                    if self.user.trim().is_empty() { "root".into() } else { self.user.clone() },
                )),
            },
            AuthChoice::Independent => Auth::inline(self.build_inline_body()),
        }
    }

    pub fn set_core_error(&mut self, msg: String) {
        self.core_error = Some(msg);
    }

    /// The ordered list of fields the user can navigate to. Reference shows only
    /// Name/Host/Port/Auth (the user comes from the credential). Independent
    /// always shows User/Auth/Secret, plus Identity (IdentityKey) or Password
    /// (Password) — never both, never neither's secret-specific row.
    fn reachable_fields(&self) -> Vec<Field> {
        Field::ORDER
            .iter()
            .copied()
            .filter(|f| match self.auth_choice {
                AuthChoice::Reference { .. } => {
                    matches!(f, Field::Name | Field::Host | Field::Port | Field::Auth)
                }
                AuthChoice::Independent => match self.secret_kind {
                    SecretChoice::None => !matches!(f, Field::Identity | Field::Password),
                    SecretChoice::IdentityKey => *f != Field::Password,
                    SecretChoice::Password => *f != Field::Identity,
                },
            })
            .collect()
    }

    fn focus_idx(&self) -> usize {
        let reachable = self.reachable_fields();
        reachable.iter().position(|f| *f == self.focus).unwrap_or(0)
    }

    fn move_focus(&mut self, delta: i32) {
        let reachable = self.reachable_fields();
        if reachable.is_empty() {
            return;
        }
        let cur = self.focus_idx() as i32;
        let next = (cur + delta).rem_euclid(reachable.len() as i32) as usize;
        self.focus = reachable[next];
        self.error = None;
    }

    fn is_last_reachable(&self, field: Field) -> bool {
        self.reachable_fields().last().copied() == Some(field)
    }
}
```

`validate` (`mod.rs:172-186`) is unchanged in effect — name + host still required. (User/Password stay optional.) Do not add a user check: Independent defaults user to "root" and Reference does not use it.

- [ ] Run: `cargo test --bin sshrack wizard::host::tests::build_auth 2>&1 | tail -20` — the three `build_auth_*` tests now pass; `reachable_fields_*` and `new_edit_*` pass too.

### Step 4: Rewrite `on_key`, `edit_focused_push`/`pop`, `attempt_save`, `cursor_target`

Replace the body of `on_key` (`host.rs:259-340`) to navigate via `move_focus`/`is_last_reachable` and add Secret-row cycling; replace `edit_focused_push`/`pop` (`host.rs:344-392`) and `cursor_target` (`host.rs:466-479`).

```rust
pub fn on_key(&mut self, key: KeyEvent) -> Outcome {
    if key.kind != KeyEventKind::Press {
        return Outcome::Continue;
    }
    self.core_error = None;
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let ctrl_c_only = key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c');

    if ctrl_c_only {
        return Outcome::Cancel;
    }

    match key.code {
        KeyCode::Esc => Outcome::Cancel,
        KeyCode::Char('s') if ctrl => self.attempt_save(),
        KeyCode::Tab | KeyCode::Down if !ctrl => {
            self.move_focus(1);
            Outcome::Continue
        }
        KeyCode::BackTab | KeyCode::Up if !ctrl => {
            self.move_focus(-1);
            Outcome::Continue
        }
        KeyCode::Enter => {
            if self.is_last_reachable(self.focus) {
                self.attempt_save()
            } else {
                self.move_focus(1);
                Outcome::Continue
            }
        }
        // Auth row: ←/→ cycle Reference/Independent; Shift-←/→ cycle the
        // credential list (only meaningful under Reference).
        KeyCode::Left if self.focus == Field::Auth && !shift => {
            self.cycle_auth(-1);
            self.error = None;
            Outcome::Continue
        }
        KeyCode::Right if self.focus == Field::Auth && !shift => {
            self.cycle_auth(1);
            self.error = None;
            Outcome::Continue
        }
        KeyCode::Left if self.focus == Field::Auth && shift => {
            if matches!(self.auth_choice, AuthChoice::Reference { .. }) {
                self.cycle_credential(-1);
            }
            self.error = None;
            Outcome::Continue
        }
        KeyCode::Right if self.focus == Field::Auth && shift => {
            if matches!(self.auth_choice, AuthChoice::Reference { .. }) {
                self.cycle_credential(1);
            }
            self.error = None;
            Outcome::Continue
        }
        // Secret row: ←/→ cycle None / Password / IdentityKey (Independent only).
        KeyCode::Left if self.focus == Field::Secret => {
            self.secret_kind = self.secret_kind.prev();
            self.error = None;
            Outcome::Continue
        }
        KeyCode::Right if self.focus == Field::Secret => {
            self.secret_kind = self.secret_kind.next();
            self.error = None;
            Outcome::Continue
        }
        KeyCode::Backspace => {
            self.edit_focused_pop();
            Outcome::Continue
        }
        KeyCode::Char(c) if !ctrl => {
            self.edit_focused_push(c);
            Outcome::Continue
        }
        _ => Outcome::Continue,
    }
}

fn edit_focused_push(&mut self, c: char) {
    match self.focus {
        Field::Name => self.name.push(c),
        Field::Host => self.host_addr.push(c),
        Field::Port => {
            if c.is_ascii_digit() {
                self.port.push(c);
            }
        }
        Field::User => self.user.push(c),
        Field::Identity => self.identity.push(c),
        Field::Password if self.secret_kind == SecretChoice::Password => self.password.push(c),
        // Auth / Secret are chooser rows driven by ←/→; no text entry.
        Field::Auth | Field::Secret | Field::Password => {}
    }
    if Some(self.focus) == self.error.map(SaveError::field) {
        self.error = None;
    }
}

fn edit_focused_pop(&mut self) {
    match self.focus {
        Field::Name => self.name.pop(),
        Field::Host => self.host_addr.pop(),
        Field::Port => self.port.pop(),
        Field::User => self.user.pop(),
        Field::Identity => self.identity.pop(),
        Field::Password if self.secret_kind == SecretChoice::Password => self.password.pop(),
        Field::Auth | Field::Secret | Field::Password => {}
    }
    if Some(self.focus) == self.error.map(SaveError::field) {
        self.error = None;
    }
}

fn attempt_save(&mut self) -> Outcome {
    match validate(self) {
        Ok(()) => Outcome::SaveHost,
        Err(e) => {
            self.error = Some(e);
            self.focus = e.field();
            Outcome::Continue
        }
    }
}

fn cursor_target(&self) -> Option<(usize, usize)> {
    let row = self.focus_idx();
    let offset = match self.focus {
        Field::Name => self.name.chars().count(),
        Field::Host => self.host_addr.chars().count(),
        Field::Port => self.port.chars().count(),
        Field::User => self.user.chars().count(),
        Field::Identity => self.identity.chars().count(),
        Field::Password => self.password.chars().count(),
        Field::Auth | Field::Secret => return None,
    };
    Some((row, offset))
}
```

### Step 5: Rewrite `draw_in_dialog`, `render_row`, `row_value_and_placeholder`

Mirror `CredForm::draw_in_dialog` (`cred.rs:345-389`) and `render_row` (`cred.rs:419-467`) — they already render a conditional row set with a masked password. The host version differs only in: it iterates `self.reachable_fields()` (not a fixed `Field::ORDER`), uses `HOST_VALUE_COL`, pads labels to 8, and the Auth row has its own chooser + placeholder text.

```rust
pub fn draw_in_dialog(&self, frame: &mut Frame, body: ratatui::layout::Rect) {
    let reachable = self.reachable_fields();
    let rows: Vec<Line> = reachable.iter().map(|f| self.render_row(*f)).collect();

    let [fields_area, error_area, hint_area] = Layout::vertical([
        Constraint::Length(reachable.len() as u16),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(body);

    frame.render_widget(Paragraph::new(rows), fields_area);

    let error_line = if let Some(msg) = &self.core_error {
        Line::from(vec![
            Span::styled("  ! ", Style::new().fg(theme::DANGER).bold()),
            Span::styled(msg.clone(), Style::new().fg(theme::DANGER)),
        ])
    } else {
        match self.error {
            Some(e) => Line::from(vec![
                Span::styled("  ! ", Style::new().fg(theme::DANGER).bold()),
                Span::styled(e.message(), Style::new().fg(theme::DANGER)),
            ]),
            None => Line::raw(""),
        }
    };
    frame.render_widget(error_line, error_area);

    let hint = match self.focus {
        Field::Auth => "  <- -> cycle Independent/Reference  ·  Shift-<- -> cycle credential  ·  ^s save  ·  Esc cancel",
        Field::Secret => "  <- -> cycle None/Password/IdentityKey  ·  ^s save  ·  Esc cancel",
        _ => "  Tab/up-down next  ·  ^s save  ·  Esc cancel",
    };
    frame.render_widget(Paragraph::new(hint).style(Style::new().dim()), hint_area);

    if let Some((row, offset)) = self.cursor_target() {
        let max_x = fields_area.x + fields_area.width.saturating_sub(1);
        let x = (fields_area.x + HOST_VALUE_COL + offset as u16).min(max_x);
        let y = fields_area.y + row as u16;
        frame.set_cursor_position((x, y));
    }
}

fn render_row(&self, field: Field) -> Line<'static> {
    let label = field.label();
    let focused = self.focus == field;
    let cursor = if focused { "▶ " } else { "  " };
    let label_span = Span::styled(
        format!("{cursor}{label:>8}: "),
        if focused {
            theme::accent().add_modifier(Modifier::BOLD)
        } else {
            Style::new().dim()
        },
    );
    let (value_str, placeholder) = self.row_value_and_placeholder(field);
    let mut spans = vec![label_span];
    spans.extend(value_spans(&value_str, placeholder));
    Line::from(spans).alignment(Alignment::Left)
}

fn row_value_and_placeholder(&self, field: Field) -> (String, Option<&'static str>) {
    match field {
        Field::Name => (self.name.clone(), Some("e.g. web-prod (no : @ or whitespace)")),
        Field::Host => (self.host_addr.clone(), Some("e.g. 10.0.0.5 or host.example.com")),
        Field::Port => {
            let v = self.port.clone();
            let ph = if v.is_empty() { Some("22 (default)") } else { None };
            (v, ph)
        }
        Field::User => (self.user.clone(), Some("root (default)")),
        Field::Auth => {
            let v = match &self.auth_choice {
                AuthChoice::Independent => "Independent".to_string(),
                AuthChoice::Reference { idx } => match self.credential_names.get(*idx) {
                    Some(name) => format!("Reference: {name}"),
                    None => "Reference: <none defined>".to_string(),
                },
            };
            let ph = match self.auth_choice {
                AuthChoice::Independent => Some("<- -> cycle to Reference"),
                AuthChoice::Reference { .. } => {
                    if self.credential_names.is_empty() {
                        Some("no credentials defined — add one with the cred wizard")
                    } else {
                        Some("Shift-<- -> cycle credential")
                    }
                }
            };
            (v, ph)
        }
        Field::Secret => {
            let v = self.secret_kind.label().to_string();
            let ph = match self.secret_kind {
                SecretChoice::None => Some("<- -> cycle: Password / IdentityKey / None"),
                SecretChoice::Password => Some("type the password below"),
                SecretChoice::IdentityKey => Some("type the key path"),
            };
            (v, ph)
        }
        Field::Identity => (self.identity.clone(), Some("path to a private key")),
        Field::Password => {
            // Masked: one bullet per char. Never echo the plaintext.
            let masked: String = std::iter::repeat_n('•', self.password.chars().count()).collect();
            let ph = if self.editing { Some("leave blank to keep existing") } else { Some("type the password") };
            (masked, ph)
        }
    }
}
```

`title()` (`host.rs:483-489`) is unchanged.

- [ ] Run: `cargo build --workspace 2>&1 | tail -20` — compiles. Fix any straggler references to the removed `Field::next`/`prev`/`is_last`, `AuthChoice::Default`/`Credential`/`InlineKey`, `AuthKind::Default`/`Credential`/`InlineKey`, or `inline_key`.
- [ ] Run: `rg -n 'InlineKey|AuthChoice::Default|AuthChoice::Credential|AuthKind::Default|inline_key' src/` — expect **zero** hits (dev-stage: no dead names).

### Step 6: `persist_host_save` — seal the inline password (mirror `persist_cred_save`)

`persist_host_save` (`app.rs:1501-1574`) currently calls `form.build_auth(..)` and persists directly. Insert the seal step between building `auth` and building `new_cfg`, mirroring `persist_cred_save` (`app.rs:1709-1739`). Use `app.handle()` (already a method, `app.rs:121`) for the vault-unlock popup — no signature change, no caller change, no existing-test change.

The sealed body must be keyed by the **target host id** (fresh for add, original for edit) so the keyring entry matches what `delete_host_with_secret`/`copy_keyring_entry` later clean up. Compute `target_id` up front and pass it to both `add_host` and `finalize_body`.

```rust
fn persist_host_save(app: &mut App) -> Result<(), SshrackError> {
    let Some(Overlay::HostWizard(form)) = app.overlay.clone() else {
        return Ok(());
    };

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
    {
        if let Auth::Inline(body) = &auth {
            if body.password.is_none() {
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
        }
    }

    // ── Seal an inline plaintext password per the configured store mode ─────
    // (mirror persist_cred_save). Only when there is a freshly collected
    // plaintext password; a key / none body passes through unchanged. A Password
    // choice with no store mode decided is a user-facing error, NOT a silent
    // plaintext fallback.
    if let Some(body) = auth.inline_body() {
        if matches!(body.password, Some(sshrack_core::config::schema::Secret::Plain(_))) {
            if app.config.store.is_none() {
                return Err(SshrackError::StoreModeNotDecided);
            }
            use sshrack_core::id::OwnerKind;
            use sshrack_core::secret::{OsKeyring, vault};
            let passphrase_provider = TuiPassphrase::new(app.handle());
            let env_pw = vault::passphrase_from_env();
            let vault_key = vault::ensure_unlocked_vault_key(
                &app.config,
                env_pw.as_ref(),
                &passphrase_provider,
            )?;
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
    }

    let new_cfg = if form.editing {
        let orig = app
            .config
            .find_host_by_id(&target_id)
            .ok_or(SshrackError::HostNotFound {
                name: target_id.to_string(),
                hint: sshrack_core::error::DidYouMean::none(),
            })?;
        if orig.name != name {
            sshrack_core::host::validate_rename(&app.config, &orig.name, &name)?;
        }
        let edited = sshrack_core::host::finalize_body(target_id, &name, &host_addr, port, auth);
        let mut next = app.config.clone();
        if let Some(slot) = next.hosts.iter_mut().find(|h| h.id == target_id) {
            *slot = edited;
        }
        next
    } else {
        sshrack_core::host::validate_no_duplicate(&app.config, &name, false)?;
        sshrack_core::host::add_host(&app.config, target_id, &name, &host_addr, port, auth)?
    };

    if let Some(path) = app.config_path() {
        sshrack_core::config::store::save(path, &new_cfg)?;
        let reloaded = sshrack_core::config::store::load(path)?;
        app.set_config(reloaded);
    } else {
        app.set_config(new_cfg);
    }
    Ok(())
}
```

**Confirm before writing:** `SshrackError::StoreModeNotDecided`, `vault::passphrase_from_env`, `vault::ensure_unlocked_vault_key`, `vault::seal_body`, `OsKeyring`, `TuiPassphrase::new`, `Auth::inline_body`, `host::finalize_body`, `host::add_host`, `host::validate_no_duplicate`, `host::validate_rename` — every one of these is already used by `persist_cred_save` / the existing `persist_host_save`, so the imports resolve. If `StoreModeNotDecided` is not in scope, import it the same way `persist_cred_save` does.

### Step 7: Persist-seal tests

Add to `src/tui/app.rs` `#[cfg(test)]` next to the existing `persist_host_save_*` tests (`app.rs:2269-2414`). Pattern them on the existing `persist_host_save_credential_choice_resolves_name_to_id` test for harness setup (temp config, `store` mode set, `Overlay::HostWizard(form)`).

```rust
// Inline password under plaintext store: body carries Secret::Plain, no keyring entry.
#[test]
fn persist_host_save_independent_password_seals_under_plaintext() {
    let (mut app, _tmp) = app_with_store(SecretStore::Plaintext); // helper used by cred tests
    let mut form = HostForm::new_add(vec![]);
    form.name = "pw-host".into();
    form.host_addr = "10.0.0.1".into();
    form.auth_choice = AuthChoice::Independent;
    form.secret_kind = SecretChoice::Password;
    form.password = Zeroizing::new("hunter2".into());
    app.overlay = Some(Overlay::HostWizard(form));
    persist_host_save(&mut app).expect("seal + save succeeds");
    let saved = app.config.find_host_by_name("pw-host").expect("host saved");
    let body = saved.auth.inline_body().expect("inline");
    assert_eq!(body.password.as_ref().and_then(Secret::as_plain), Some("hunter2"));
    assert!(!body.keyring);
}

// Keyring store: body keeps only the keyring marker; the password is NOT in the body.
#[test]
fn persist_host_save_independent_password_seals_under_keyring() {
    let (mut app, _tmp) = app_with_store(SecretStore::Keyring);
    let mut form = HostForm::new_add(vec![]);
    form.name = "kr-host".into();
    form.host_addr = "10.0.0.1".into();
    form.auth_choice = AuthChoice::Independent;
    form.secret_kind = SecretChoice::Password;
    form.password = Zeroizing::new("hunter2".into());
    app.overlay = Some(Overlay::HostWizard(form));
    persist_host_save(&mut app).expect("seal + save succeeds");
    let saved = app.config.find_host_by_name("kr-host").expect("host saved");
    let body = saved.auth.inline_body().expect("inline");
    assert!(body.keyring);
    assert!(body.password.is_none(), "keyring mode: plaintext must not live in the body");
}
```

**Note for the implementer:** `app_with_store` / the cred-test harness may be named differently in this file — find the helper `persist_cred_save` tests use to build an `App` with a temp config + chosen `SecretStore`, and reuse it. The keyring test depends on a keyring backend being available; if the existing cred keyring test uses a fake/in-memory backend, use the same. If no keyring backend is reachable in tests, keep the plaintext test (which pins the no-leak invariant) and mark the keyring test `#[ignore]` with a comment pointing at the manual smoke in Task 3 — do NOT delete it.

### Step 8: Verify + commit

- [ ] `cargo test --bin sshrack wizard 2>&1 | tail -20` — all wizard tests pass.
- [ ] `cargo test --bin sshrack persist_host_save 2>&1 | tail -20` — persist tests pass.
- [ ] `cargo test --workspace 2>&1 | tail -10` — full suite green.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] `cargo fmt`.
- [ ] `git add -A && git commit -m "feat(tui): host wizard Reference/Independent auth with inline password sealing"`

---

## Task 2: CLI terminology alignment + dual-mode regression coverage

**Files:**
- Modify: `src/cli/args.rs` (HostAction::Add/Edit doc comments)
- Verify: `src/cli/cmd/host.rs` (error messages terminology; no behavior change)
- Test: `tests/json_output_test.rs` or `src/cli/cmd/host.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: the existing CLI surface (`--user`/`--identity`/`--credential`).
- Produces: help/error text that names the two modes consistently with the TUI ("Independent"/"Reference"); regression tests pinning that the CLI creates Independent hosts via `--user`/`--identity` and Reference hosts via `--credential`, and that `--clear-credential` drops back to Independent.

**Premise (do not re-derive):** the CLI already builds both auth shapes via core's `host::build_auth` / `host::apply_patch` (surveyed: `--credential` → `Auth::Ref`; `--user`/`--identity` → `Auth::Inline`; `--clear-credential` → `Auth::Inline` default; no inline-password path — by design, passwords never enter argv). This task changes **wording and tests only**, not behavior.

### Step 1: Align help text

In `src/cli/args.rs`, update the doc comments on `HostAction::Add` and `HostAction::Edit` so the auth flags read with the same vocabulary the TUI now uses. For example, on `--credential`: `Reference a [[credentials]] entry by name (mutually exclusive with the independent flags)`. On `--user`: `Login user for independent auth (used when --credential is absent; defaults to "root")`. On `--identity`: `Path to a private key for independent auth`. On `--clear-credential`: `Drop the credential reference, reverting to independent auth (user defaults to "root")`.

Do NOT add a new `--auth` flag — the existing flags already express every reachable auth shape, and adding one would be redundant (YAGNI). Run `cargo run -q -- host add --help` and `cargo run -q -- host edit --help` to eyeball the result.

### Step 2: Error-message terminology

Grep `src/cli/cmd/host.rs` for user-facing strings mentioning "credential" / "auth" and make sure they are consistent with the Independent/Reference vocabulary where it reads awkwardly. This is light touch — if the existing wording is already clear, change nothing here and say so in the task report.

### Step 3: Dual-mode regression tests

Add tests pinning the CLI's auth behavior (so a future refactor cannot silently drop a mode). Prefer integration tests that drive the `sshrack` binary via `CARGO_BIN_EXE_sshrack` (pattern: existing `tests/json_output_test.rs`), or unit tests on `host::build_auth` / `host::apply_patch` if that harness is awkward. At minimum pin:

- `host add h --host 1.1.1.1 --user ops` → persisted host is `Auth::Inline` (Independent-None).
- `host add h --host 1.1.1.1 --identity /k` → `Auth::Inline` with a key (Independent-IdentityKey).
- `host add h --host 1.1.1.1 --credential ops` → `Auth::Ref` (Reference).
- `host edit h --clear-credential` (from a Reference host) → `Auth::Inline` default.
- `host add h --host 1.1.1.1` (no auth flag) → `Auth::Inline` default user "root" (Independent-None).

### Step 4: Verify + commit

- [ ] `cargo test --workspace 2>&1 | tail -10` — green.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt`.
- [ ] `git add -A && git commit -m "test(cli): pin host independent/reference auth modes and align wording"`

---

## Task 3: Documentation + cleanup + final verification

**Files:**
- Modify: `src/tui/wizard/host.rs` module docs (the `host.rs:1-14` block that says "Inline PASSWORD is intentionally NOT in this wizard")
- Modify: `src/tui/wizard/mod.rs` module docs (the `mod.rs:39-45` block that says the same)
- Modify: `CLAUDE.md` (host auth model + CLI parity)

### Step 1: Rewrite the wizard module docs

`src/tui/wizard/host.rs:1-14` currently justifies the absence of inline password. Rewrite it to describe the new shape: auth is a Reference/Independent chooser; Independent carries user + None/Password/IdentityKey; the password is sealed by the loop per the store mode (keyring/vault/plaintext), mirroring the credential wizard. `src/tui/wizard/mod.rs:39-45` (the `AuthChoice` doc) gets the same update. Remove any sentence that says inline password is absent or owned-by-a-credential.

### Step 2: Update CLAUDE.md

Update the Identity & Config Model / CLI Contract / Storage sections so they reflect:

- A host authenticates either by **Reference** (`Auth::Ref`, a credential id) or **Independent** (`Auth::Inline`, a host-own `CredentialBody` with None/Password/IdentityKey).
- The TUI host wizard exposes both; the CLI exposes both via `--user`/`--identity` (Independent) and `--credential` (Reference).
- An inline **password** is TUI-only (passwords never enter argv). The CLI can still create Independent-None and Independent-IdentityKey hosts.
- The keyring lifecycle keys an inline password by the host's ULID (`OwnerKind::Host`); delete/cp/overwrite all clean it up.

Do not invent new sections — edit the existing prose in place.

### Step 3: Final audit + smoke

- [ ] `rg -n 'intentionally NOT|owned by a credential|InlineKey|inline_key|AuthChoice::Default|AuthChoice::Credential|AuthKind::Default' src/ CLAUDE.md` — expect zero hits.
- [ ] `cargo build --workspace --release`.
- [ ] `cargo test --workspace`.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] `cargo fmt --check`.
- [ ] Manual TUI smoke (the subagents cannot run the interactive TUI): `cargo run -q -- host add` → cycle Auth to Independent/Reference; under Independent cycle Secret to Password, type a password, save; `host ls` shows the host; re-edit it (`host edit <name>`) and confirm the password field reads "leave blank to keep existing". Then `store use plaintext` (or keyring) and confirm an inline-password host connects.
- [ ] `git add -A && git commit -m "docs: host Reference/Independent auth model across wizard and CLAUDE.md"`

---

## Self-Review

**1. Spec coverage.** The user's ask: "TUI and CLI both let a host use independent OR existing credentials when adding/editing." TUI independent = Task 1 (Reference/Independent + Independent None/Password/IdentityKey + seal). CLI independent = already present (verified), pinned + worded in Task 2. Inline password: TUI yes (Task 1); CLI no — by the passwords-never-enter-argv invariant (called out in Goal + Task 2 premise). This is a deliberate, documented scope line, not a gap.

**2. Placeholder scan.** Every code step carries the actual code. The two render steps (Task 1 Steps 4–5) reference `cred.rs` file:line as the template and spell out the exact differences (reachable_fields vs fixed ORDER; HOST_VALUE_COL; Auth-row chooser text) — these are precise diffs, not "similar to." The persist-seal test (Task 1 Step 7) names the helper to reuse and the fallback (`#[ignore]`) if no keyring backend is reachable in tests; it is not a TODO.

**3. Type consistency.** `AuthChoice { Reference{idx}, Independent }`, `AuthKind { Independent, Reference }`, `Field { Name, Host, Port, User, Auth, Secret, Identity, Password }`, `HostForm.secret_kind: SecretChoice`, `HostForm.identity: String`, `HostForm.password: Zeroizing<String>`, `build_auth(Option<Ulid>) -> Auth`, `build_inline_body() -> CredentialBody`, `reachable_fields() -> Vec<Field>`, `persist_host_save(&mut App) -> Result<(), SshrackError>` (signature unchanged; uses `app.handle()`). The seal block reuses `OwnerKind::Host`, `vault::seal_body`, `SshrackError::StoreModeNotDecided` exactly as `persist_cred_save` does. `inline_key` is fully renamed to `identity` — no stale references (Step 5 includes an `rg` gate).

**Gaps the implementer must confirm at the keyboard (called out inline, not deferred):**
- `app_with_store` / the cred-test `App` harness helper — reuse whatever `persist_cred_save` tests already use.
- `SshrackError::StoreModeNotDecided` import path — match `persist_cred_save`.
- Keyring-backend availability in tests — keep the plaintext no-leak test unconditionally; `#[ignore]` the keyring one only if no backend is reachable.
