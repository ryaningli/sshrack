# sshrack Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild sshrack as a Cargo workspace with a UI-free capability core (`sshrack-core`), a non-interactive-capable CLI (`sshrack-cli`), and a deferred TUI crate — porting the verified backend from `sshrack-old` while fixing its identity model and adding first-class ULIDs, ref-by-id, frecency, and a `--no-input`/`--format json` CLI contract.

**Architecture:** Three crates. `sshrack-core` holds all pure/IO capability and **never** depends on `dialoguer`/`ratatui`/`console` (compiler-enforced). Side effects (keyring I/O, passphrase source, host-key confirmation) are injected via traits defined in core. `sshrack-cli` is clap-driven, owns dialoguer interaction, and hosts the SSH_ASKPASS role dispatch. `sshrack-tui` is a stub deferred to a later phase.

**Tech Stack:** Rust edition 2024, MSRV 1.86. clap 4 (derive), serde + toml, thiserror (core errors), anyhow (cli errors), directories, zeroize, ulid, argon2, chacha20poly1305, getrandom, base64, keyring (platform-conditional), dialoguer/console (cli only), tracing. No `age`, no `ssh2-config`, no SSH protocol library.

## Global Constraints

Copied verbatim from `docs/superpowers/specs/2026-06-30-sshrack-rewrite-design.md` and `CLAUDE.md`:

- **English only** in all source, comments, doc comments, errors, help text, logs, and commit messages.
- **Zero `unsafe`** anywhere. PTY/terminal concerns go through cross-platform crates.
- **Zero `unwrap()`/`expect()`** in non-test production code. Only `expect("invariant: ...")` in genuinely unreachable spots.
- **TDD for pure logic**: write the failing test first, then implement, for every pure module (config parse, argv assembly, credential resolve, id helpers, frecency `rank`, crypto).
- **Clippy strict**: `cargo clippy -- -D warnings` passes before every commit.
- **Format**: `cargo fmt` passes before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged, printed, or embedded in errors; keyring mode main process never materializes plaintext.
- **Tests are hermetic**: `cargo test` is green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **CLI is a general-purpose tool**: help/errors/commit messages must NOT say "for AI" or "for agents". `--no-input` and `--format json` are neutral capability descriptions.
- **No compatibility/transition code** (dev stage, unreleased): no parsing of legacy name-refs, no dual-form shims. `format_version` starts at `1`.
- **Hard rules carried from prior pain**: clap derive parses everything (no hand-written dispatch); patch commands touch only named fields; fail-fast validation precedes interaction and network IO.
- MSRV 1.86. Predecessor source is at `/home/ryan/workspace/open-source/sshrack-old`.

---

## File Structure

Final target tree (built incrementally across tasks):

```
sshrack/
├── Cargo.toml                         # [workspace] members + shared metadata
├── crates/
│   ├── sshrack-core/
│   │   ├── Cargo.toml                 # NO dialoguer/ratatui/console ever
│   │   └── src/
│   │       ├── lib.rs                 # re-exports
│   │       ├── error.rs               # SshrackError (thiserror), ported
│   │       ├── fsutil.rs              # write_private (0600), ported
│   │       ├── id.rs                  # NEW: Ulid helpers, owner kinds
│   │       ├── config/
│   │       │   ├── mod.rs
│   │       │   ├── schema.rs          # ported + first-class id + ref-by-id + format_version
│   │       │   ├── path.rs            # ported + data_dir() for frecency
│   │       │   └── store.rs           # ported atomic load/save
│   │       ├── secret/
│   │       │   ├── mod.rs             # traits: SecretBackend, PassphraseProvider
│   │       │   ├── keyring.rs         # ported OS keyring I/O behind the trait
│   │       │   └── vault/
│   │       │       ├── mod.rs         # VaultKey, orchestration
│   │       │       ├── crypto.rs      # ported verbatim
│   │       │       ├── cache.rs       # ported TTL cache + verifier
│   │       │       └── transform.rs   # ported migrate
│   │       ├── credential.rs          # ported + ref-by-id resolve
│   │       ├── host.rs                # ported name validation/CRUD pure logic
│   │       ├── suggest.rs             # ported fuzzy did-you-mean
│   │       ├── connect/
│   │       │   ├── mod.rs             # ported zero-copy launcher
│   │       │   ├── ssh.rs             # ported ssh argv assembly
│   │       │   └── scp.rs             # ported scp argv assembly
│   │       ├── askpass.rs             # ported askpass protocol
│   │       ├── hostkey.rs             # ported + run_host_key_flow(confirm callback)
│   │       └── frecency/
│   │           ├── mod.rs             # NEW: Score, rank(), record()
│   │           └── store.rs           # NEW: machine-local TOML persistence
│   ├── sshrack-cli/
│   │   ├── Cargo.toml                 # depends on sshrack-core + dialoguer/console
│   │   └── src/
│   │       ├── main.rs                # role dispatch (askpass vs CLI) + entry
│   │       ├── cli.rs                 # clap Cli/Command/HostAction/CredAction/StoreAction
│   │       ├── format.rs              # NEW: --format json|text output shapes
│   │       ├── prompt.rs              # dialoguer Prompt impl + auth/menu builders
│   │       ├── exit_code.rs           # NEW: stable exit codes
│   │       └── cmd/
│   │           ├── mod.rs
│   │           ├── connect.rs         # <name>/ssh route: resolve+hostkey+launch
│   │           ├── scp.rs             # scp route
│   │           ├── host.rs            # host add/ls/show/edit/rm/cp
│   │           ├── cred.rs            # cred add/ls/show/edit/rm
│   │           └── store.rs           # store status/use/rekey/lock/unlock/config
│   └── sshrack-tui/
│       ├── Cargo.toml                 # deferred; stub only
│       └── src/lib.rs                 # empty placeholder
└── CLAUDE.md                          # rewritten in the final task
```

**Key redesign vs sshrack-old** (the highest-value work in this plan; everything else is port + verify):

1. **First-class top-level id.** `Host` and `Credential` each carry `id: Ulid` as a first-class immutable field generated at construction. The `id` no longer lives on `CredentialBody` (it was there only for keyring keying). keyring and frecency both key off the owning object's top-level id — one identity layer, not two.
2. **Reference by id.** `Auth::Ref { credential: Ulid }` (not name). `host ls`/`show` reverse-resolve id→name for display; `host add/edit --credential <name>` resolves name→id before persisting. Renaming a credential never dangles references.
3. **frecency is a first-period backend capability**, surfaced via `host ls --sort frecency`, keyed by host ULID, persisted under the data dir (separate from config).
4. **CLI dual-mode contract**: global `--no-input`, global `--format json`, stable exit codes.
5. **No TUI in this plan** (`sshrack-tui` is an empty stub); `sftp` command is also deferred.

---

## Task 1: Workspace skeleton

**Files:**
- Modify (repo root): `Cargo.toml` → convert to `[workspace]` root
- Create: `crates/sshrack-core/Cargo.toml`, `crates/sshrack-core/src/lib.rs`
- Create: `crates/sshrack-cli/Cargo.toml`, `crates/sshrack-cli/src/main.rs`
- Create: `crates/sshrack-tui/Cargo.toml`, `crates/sshrack-tui/src/lib.rs`

**Interfaces:**
- Produces: a workspace where `cargo build` succeeds, `cargo run -p sshrack-cli -- --help` prints help, and `sshrack-core` provably has zero UI deps.

- [ ] **Step 1: Replace the root `Cargo.toml` with a workspace manifest**

Write the root `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = [
    "crates/sshrack-core",
    "crates/sshrack-cli",
    "crates/sshrack-tui",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.86"
license = "MIT"
authors = ["ryaningli"]

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

- [ ] **Step 2: Create `sshrack-core` crate manifest (no UI deps)**

`crates/sshrack-core/Cargo.toml`:

```toml
[package]
name = "sshrack-core"
description = "Capability core for sshrack: hosts, credentials, secrets, connection, transfer."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true

[lib]
path = "src/lib.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
toml = "1"
thiserror = "2"
directories = "6"
zeroize = { version = "1", features = ["derive"] }
ulid = { version = "1", features = ["serde"] }
argon2 = "0.5.3"
chacha20poly1305 = "0.10.1"
getrandom = "0.4.3"
base64 = "0.22.1"
tracing = "0.1"

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3", features = ["apple-native"] }

[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3", features = ["async-secret-service", "crypto-rust", "async-io"] }

[dev-dependencies]
tempfile = "3"
```

Note: `clap`, `dialoguer`, `console`, `ratatui` are deliberately absent. Adding any of them later is a build failure by intent.

- [ ] **Step 3: Create `sshrack-core/src/lib.rs`**

```rust
//! Capability core for sshrack.
//!
//! Pure and IO capabilities for host/credential management, secret storage,
//! connection, and transfer. This crate has no UI dependencies: front-ends
//! (CLI, TUI) inject side effects via the traits defined here.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod error;
```

(Create `crates/sshrack-core/src/error.rs` as an empty placeholder for now — a unit struct `SshrackError` is added in Task 2. To keep Step 3 compiling, put a temporary empty enum in `error.rs` and replace it in Task 2. Minimal temporary `error.rs`:

```rust
//! Crate-wide error type. Populated in a later task.
#[derive(Debug, thiserror::Error)]
pub enum SshrackError {
    #[error("placeholder")]
    Placeholder,
}
```

)

- [ ] **Step 4: Create `sshrack-cli` crate manifest + a minimal main**

`crates/sshrack-cli/Cargo.toml`:

```toml
[package]
name = "sshrack-cli"
description = "Command-line front end for sshrack."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true

[[bin]]
name = "sshrack"
path = "src/main.rs"

[dependencies]
sshrack-core = { path = "../sshrack-core" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
dialoguer = { version = "0.12.0", features = ["fuzzy-select"] }
console = "0.16"
strsim = "0.11.1"
ctrlc = "3.5.2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

`crates/sshrack-cli/src/main.rs`:

```rust
//! sshrack binary entry. Hosts the CLI and the SSH_ASKPASS role dispatch.

fn main() -> anyhow::Result<()> {
    // Real dispatch lands in later tasks. For now, print a stub so the
    // workspace builds end-to-end.
    println!("sshrack (skeleton)");
    Ok(())
}
```

- [ ] **Step 5: Create `sshrack-tui` stub crate**

`crates/sshrack-tui/Cargo.toml`:

```toml
[package]
name = "sshrack-tui"
description = "Interactive TUI front end for sshrack (deferred)."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true

[lib]
path = "src/lib.rs"
```

`crates/sshrack-tui/src/lib.rs`:

```rust
//! Interactive TUI for sshrack. Deferred to a later phase; intentionally empty.
```

- [ ] **Step 6: Build the workspace and verify the help output**

Run: `cargo build --workspace`
Expected: builds with no errors (warnings about unused imports are acceptable transiently within this task, but must be cleaned before the commit step).

Run: `cargo run -p sshrack-cli -- --help || true`
Expected: prints `sshrack (skeleton)` (no clap wiring yet; the `--help` is not recognized until Task 14 — the `|| true` lets this step pass while the skeleton stands alone). The point of this step is that the binary runs.

- [ ] **Step 7: Verify core has zero UI deps (the hard invariant)**

Run: `cargo tree -p sshrack-core | grep -E 'dialoguer|ratatui|console|crossterm' || echo "CLEAN"`
Expected: `CLEAN` (no matches). If anything matches, stop and remove the offending dependency from `sshrack-core/Cargo.toml`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/
git commit -m "build(workspace): scaffold core/cli/tui crates"
```

---

## Task 2: Port `error` and `fsutil`

**Files:**
- Modify: `crates/sshrack-core/src/error.rs` (replace placeholder)
- Create: `crates/sshrack-core/src/fsutil.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod fsutil;`)

**Interfaces:**
- Produces: `SshrackError` (the full error enum, thiserror) and `fsutil::write_private(path, bytes) -> Result<(), SshrackError>` (0600 atomic-ish write used by config + connect).

**Approach:** These two files are foundational and used everywhere. Port them near-verbatim from sshrack-old, adjusting only the `crate::` paths that move (none for these two — they have no internal deps except each other). `fsutil::write_private` is the 0600 helper consumed by `config::store` and `connect`.

- [ ] **Step 1: Port `error.rs`**

Copy `/home/ryan/workspace/open-source/sshrack-old/src/error.rs` verbatim into `crates/sshrack-core/src/error.rs`. Read it first to confirm its variants (it references `DidYouMean`, `SshrackError` variants like `ConfigParse`, `KeyringUnavailable`, `VaultUnlockFailed`, `DecryptionFailed`, `AskpassRead`, etc.). Keep all variants — later tasks depend on the full set. Update the module doc comment to say "core" instead of nothing.

- [ ] **Step 2: Port `fsutil.rs`**

Copy `/home/ryan/workspace/open-source/sshrack-old/src/fsutil.rs` verbatim. Confirm it exposes `pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), SshrackError>` using `OpenOptionsExt::mode(0o600)` under `cfg(target_family = "unix")`.

- [ ] **Step 3: Wire the modules**

In `crates/sshrack-core/src/lib.rs`, ensure:

```rust
pub mod error;
pub mod fsutil;
```

- [ ] **Step 4: Build + clippy + fmt**

Run: `cargo build -p sshrack-core && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-core/src/error.rs crates/sshrack-core/src/fsutil.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): port error type and fsutil private-write helper"
```

---

## Task 3: Identity helpers (`id.rs`) — NEW

**Files:**
- Create: `crates/sshrack-core/src/id.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod id;`)

**Interfaces:**
- Produces:
  - `pub fn new_id() -> Ulid` — fresh identity.
  - `pub enum OwnerKind { Host, Credential }` with `pub fn keyring_key(kind: OwnerKind, id: &Ulid) -> String` returning `"host:<id>"` / `"cred:<id>"` (pure, unit-tested).

This centralizes the keyring-key derivation that sshrack-old kept inside `keyring.rs::SecretOwner`. Owner is now just a kind + the owning object's top-level id.

- [ ] **Step 1: Write the failing tests**

`crates/sshrack-core/src/id.rs`:

```rust
//! Identity helpers for sshrack.
//!
//! Every host and credential carries a first-class, immutable `Ulid`. The
//! keyring account key is derived from the owner kind plus that id (never the
//! name), so renaming an owner never moves its keyring entry.

use ulid::Ulid;

/// Generate a fresh identity.
pub fn new_id() -> Ulid {
    Ulid::new()
}

/// Whose secret a keyring entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    Host,
    Credential,
}

/// Pure: the keyring account key for an owner kind + id. Name-free on purpose
/// so renames are safe.
pub fn keyring_key(kind: OwnerKind, id: &Ulid) -> String {
    match kind {
        OwnerKind::Host => format!("host:{id}"),
        OwnerKind::Credential => format!("cred:{id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_key_is_kind_plus_id() {
        let id = Ulid::new();
        assert_eq!(keyring_key(OwnerKind::Host, &id), format!("host:{id}"));
        assert_eq!(
            keyring_key(OwnerKind::Credential, &id),
            format!("cred:{id}")
        );
    }

    #[test]
    fn host_and_credential_with_same_id_differ_by_prefix() {
        let id = Ulid::new();
        assert_ne!(
            keyring_key(OwnerKind::Host, &id),
            keyring_key(OwnerKind::Credential, &id)
        );
    }

    #[test]
    fn new_id_is_unique_enough() {
        assert_ne!(new_id(), new_id());
    }
}
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cargo test -p sshrack-core id:: -- --nocapture`
Expected: 3 passing. (RED→GREEN collapsed because the implementation is inline above; if following strict TDD, write only the tests first, watch them fail on missing `OwnerKind`, then add the implementation.)

- [ ] **Step 3: Wire the module**

In `lib.rs`: `pub mod id;`

- [ ] **Step 4: clippy + fmt + commit**

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

```bash
git add crates/sshrack-core/src/id.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): add first-class identity helpers (id + keyring key)"
```

---

## Task 4: Config schema — port + first-class id + ref-by-id + format_version

**Files:**
- Create: `crates/sshrack-core/src/config/mod.rs`
- Create: `crates/sshrack-core/src/config/schema.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (add `pub mod config;`)

**Interfaces:**
- Produces (the redesigned types later tasks rely on):
  - `SshrackConfig { format_version, hosts: Vec<Host>, credentials: Vec<Credential>, store: Option<SecretStore> }`
  - `Host { id: Ulid, name: String, host: String, port: u16, auth: Auth }` (id is first-class, top-level)
  - `Credential { id: Ulid, name: String, body: CredentialBody }` (id is first-class, top-level)
  - `Auth { Ref { credential: Ulid }, Inline(CredentialBody) }` (**ref-by-id**, not name)
  - `CredentialBody { user, password: Option<Secret>, key: Option<PathBuf>, keyring: bool }` (**no id field** — id moved to the owner)
  - `Secret`, `EncryptedSecret`, `VaultMeta`, `SecretStore`, `SecretKind`, `AuthChoice`
  - `SshrackConfig::find_host_by_name`, `find_host_by_id`, `find_credential_by_name`, `find_credential_by_id`, `is_vault`, `is_keyring`, `is_plaintext`, `mode_chosen`, `vault_meta`

**Approach:** Port `sshrack-old/src/config/schema.rs`, then apply four targeted changes. The ported unit tests come along and are updated to the new shapes.

- [ ] **Step 1: Port the file, then apply the redesign**

Copy `/home/ryan/workspace/open-source/sshrack-old/src/config/schema.rs` to `crates/sshrack-core/src/config/schema.rs`. Then make these edits:

**1a. Add `format_version`:** on `SshrackConfig` add `#[serde(default = "default_format_version")] pub format_version: u32` and `fn default_format_version() -> u32 { 1 }`.

**1b. Move `id` off `CredentialBody` to the owners.** Remove `pub id: Option<Ulid>` from `CredentialBody` and its builders/`id()`/`retain_id`/`ensure_ids` machinery. Add a first-class `id: Ulid` (non-optional) to both `Host` and `Credential`. Constructors that build a `Host`/`Credential` take or generate the id:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Host {
    pub id: Ulid,
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub auth: Auth,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub id: Ulid,
    pub name: String,
    #[serde(flatten)]
    pub body: CredentialBody,
}
```

Because `id: Ulid` is non-optional and `Ulid: Default` is NOT desired, `SshrackConfig` no longer derives `Default` via `#[derive(Default)]` cleanly. Implement `Default` manually with `format_version: 1` and empty vecs:

```rust
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
```

**1c. Reference by id.** Change `Auth::Ref`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Auth {
    /// Reference a [[credentials]] entry by its stable id.
    Ref { credential: Ulid },
    /// Inline user + optional secret.
    Inline(CredentialBody),
}

impl Auth {
    pub fn reference(credential_id: Ulid) -> Self {
        Auth::Ref { credential: credential_id }
    }
    /// The referenced credential id, if this is `Auth::Ref`.
    pub fn credential_id(&self) -> Option<Ulid> {
        match self {
            Auth::Ref { credential } => Some(*credential),
            Auth::Inline(_) => None,
        }
    }
    // keep inline_body() / inline_body_mut() helpers
}
```

**1d. Add id-based lookups.** On `SshrackConfig` add:

```rust
pub fn find_host_by_name(&self, name: &str) -> Option<&Host> {
    self.hosts.iter().find(|h| h.name == name)
}
pub fn find_host_by_id(&self, id: &Ulid) -> Option<&Host> {
    self.hosts.iter().find(|h| &h.id == id)
}
pub fn find_credential_by_name(&self, name: &str) -> Option<&Credential> {
    self.credentials.iter().find(|c| c.name == name)
}
pub fn find_credential_by_id(&self, id: &Ulid) -> Option<&Credential> {
    self.credentials.iter().find(|c| &c.id == id)
}
```

Remove the old `find_name`/`find_credential` name-only methods (callers migrate over the next tasks). Keep `is_vault`/`is_keyring`/`is_plaintext`/`mode_chosen`/`vault_meta` as-is.

- [ ] **Step 2: Update the ported tests to the new shapes**

In the `#[cfg(test)] mod tests` at the bottom of `schema.rs`, update every constructor:
- `HostConfig { name, host, port, auth }` → `Host { id: crate::id::new_id(), name, host, port, auth }`.
- `Auth::reference("team-dev")` → `Auth::reference(<the credential's id>)`.
- The reference-auth parse test now feeds `auth = { credential = "01J..." }` (a ULID string) and asserts `credential_id()` returns it; flip the construct-then-serialize test to confirm the on-disk form is `credential = "<ulid>"`.
- Drop any test referencing `body.id` / `ensure_ids` / `retain_id`.

Add a regression test asserting the on-disk form is ref-by-id:

```rust
#[test]
fn reference_auth_serializes_to_credential_id() {
    let cid = ulid::Ulid::from_string("01HXYZ0000000000000000001").unwrap();
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
```

- [ ] **Step 3: Create `config/mod.rs`**

```rust
//! Configuration data model, schema, path resolution, and persistence.

pub mod path;
pub mod schema;
pub mod store;
```

(Leave `path`/`store` to Tasks 5; for now add temporary empty modules or comment the lines and uncomment in Task 5. Simplest: create `path.rs`/`store.rs` as empty `//! …` files now and fill them next task.)

- [ ] **Step 4: Run the tests, clippy, fmt**

Run: `cargo test -p sshrack-core config::schema:: -- --nocapture`
Expected: all schema tests green.

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-core/src/config/ crates/sshrack-core/src/lib.rs
git commit -m "feat(config): port schema with first-class id and ref-by-id"
```

---

## Task 5: Config path + store (atomic load/save)

**Files:**
- Modify: `crates/sshrack-core/src/config/path.rs`
- Modify: `crates/sshrack-core/src/config/store.rs`

**Interfaces:**
- Produces:
  - `path::default_config_path() -> Option<PathBuf>`
  - `path::resolve(override_path: Option<&Path>) -> Option<PathBuf>`
  - `path::default_data_dir() -> Option<PathBuf>` (NEW — for frecency; resolves to the XDG data dir, e.g. `~/.local/share/sshrack`)
  - `store::load(path) -> Result<SshrackConfig, SshrackError>` (missing file ⇒ empty config)
  - `store::save(path, cfg) -> Result<(), SshrackError>` (atomic 0600 write)

- [ ] **Step 1: Port `path.rs` and add `default_data_dir`**

Copy `/home/ryan/workspace/open-source/sshrack-old/src/config/path.rs`. Append:

```rust
/// The default data directory (XDG data dir / sshrack), for machine-local
/// state such as frecency. Created lazily by callers.
pub fn default_data_dir() -> Option<PathBuf> {
    let proj = directories::ProjectDirs::from("dev", "sshrack", "sshrack")?;
    Some(proj.data_dir().to_path_buf())
}
```

Add a test that `default_data_dir()` ends with `sshrack` (mirroring the existing config-dir test).

- [ ] **Step 2: Port `store.rs`**

Copy `/home/ryan/workspace/open-source/sshrack-old/src/config/store.rs` verbatim (it uses `crate::fsutil::write_private`, `crate::config::schema::SshrackConfig`, `crate::error::SshrackError` — all present). Update the ported tests' `HostConfig` constructions to the new `Host { id, name, host, port, auth }` shape.

- [ ] **Step 3: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core config:: -- --nocapture`
Expected: green.

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 4: Commit**

```bash
git add crates/sshrack-core/src/config/path.rs crates/sshrack-core/src/config/store.rs
git commit -m "feat(config): port atomic config store and add data-dir path"
```

---

## Task 6: Vault crypto + cache (verbatim port)

**Files:**
- Create: `crates/sshrack-core/src/secret/mod.rs`
- Create: `crates/sshrack-core/src/secret/vault/mod.rs`
- Create: `crates/sshrack-core/src/secret/vault/crypto.rs`
- Create: `crates/sshrack-core/src/secret/vault/cache.rs`

**Interfaces:**
- Produces: `secret::vault::VaultKey` (`Zeroizing<[u8;32]>`), `crypto::{derive_key, encrypt, decrypt, DecryptError}`, `cache::VaultCache` (TTL + verifier), and `fast_meta` test helper.

**Approach:** Pure cryptography — port verbatim. Only path changes: `crate::config::schema::…` stays valid (core re-exports the same schema module path). The old `vault/mod.rs` defined `VaultKey` and `fast_meta`; port that too.

- [ ] **Step 1: Port `vault/crypto.rs` and `vault/cache.rs` and `vault/mod.rs`**

Copy the three files from sshrack-old, placing them at the paths above. Adjust internal `use crate::vault::…` → `use crate::secret::vault::…`. Keep all `#[cfg(test)]` tests; they cover determinism, round-trip, tamper-detection, and TTL expiry.

`crates/sshrack-core/src/secret/vault/mod.rs` should re-export `VaultKey`, `crypto`, `cache`, and the `fast_meta` test helper.

- [ ] **Step 2: Create `secret/mod.rs` (placeholder trait module; traits land in Task 7)**

```rust
//! Secret storage: storage-mode backends behind injected traits.

pub mod vault;
// keyring + traits are added in the next task.
```

- [ ] **Step 3: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core secret::vault:: -- --nocapture`
Expected: green (all crypto/cache tests pass — this is the verbatim port, so failures mean a path typo).

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 4: Commit**

```bash
git add crates/sshrack-core/src/secret/
git commit -m "feat(secret): port vault crypto and passphrase cache"
```

---

## Task 7: Secret traits + keyring backend

**Files:**
- Modify: `crates/sshrack-core/src/secret/mod.rs` (add traits)
- Create: `crates/sshrack-core/src/secret/keyring.rs`

**Interfaces:**
- Produces:
  - `secret::SecretBackend` trait: `set(kind: OwnerKind, id: &Ulid, password: &str)`, `get(key: &str) -> Option<Zeroizing<String>>`, `delete(kind, id)`, `available() -> bool`.
  - `secret::PassphraseProvider` trait: `passphrase()`, `passphrase_confirm()`, `confirm(text) -> bool`. (The `password_mode()` first-use prompt moves to the CLI layer; core only needs the passphrase + confirm seams. See Task 17 for the first-use mode prompt.)
  - `secret::OsKeyring` impl of `SecretBackend` (delegates to `secret::keyring`).
  - `secret::forget_keyring_secret(backend, kind, id, marked)` helper.
  - `secret::keyring::{SERVICE, KEYRING_KEY_ENV, get, daemon_available}` (pure `keyring_key` is now in `id.rs`; the OS I/O stays here).

**Approach:** This is the seam extraction the spec calls for. Port the OS keyring I/O from `sshrack-old/src/keyring.rs` but route keying through `id::keyring_key` (instead of the old `SecretOwner`). Port the `SecretBackend` trait + `OsKeyring` + test doubles from `secrets.rs`, trimming the `Prompt::password_mode` method (CLI concern).

- [ ] **Step 1: Port `keyring.rs` I/O**

Create `crates/sshrack-core/src/secret/keyring.rs` from sshrack-old's `keyring.rs`. Keep `SERVICE`, `KEYRING_KEY_ENV`, `get(key)`, `delete_via_key`, `daemon_available()`. Replace the `set(owner, id)` / `delete(owner, id)` / `keyring_key(owner, id)` signatures with key-string-based ones:

```rust
//! OS keyring password storage (keyring mode), behind the SecretBackend trait.

use zeroize::Zeroizing;
use crate::error::SshrackError;

pub const SERVICE: &str = "sshrack";
/// Env var naming the keyring account the askpass helper fetches.
pub const KEYRING_KEY_ENV: &str = "SSHRACK_KEYRING_KEY";

fn entry_for(key: &str) -> Result<keyring::Entry, SshrackError> {
    keyring::Entry::new(SERVICE, key).map_err(|_| SshrackError::KeyringUnavailable)
}

/// Fetch the password for a raw account key; Ok(None) when absent.
pub fn get(key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
    let entry = entry_for(key)?;
    match entry.get_password() {
        Ok(p) => Ok(Some(Zeroizing::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(SshrackError::KeyringIo { detail: "read" }),
    }
}

/// Delete by raw account key; missing entry is success.
pub fn delete_by_key(key: &str) -> Result<(), SshrackError> {
    let entry = entry_for(key)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(SshrackError::KeyringIo { detail: "delete" }),
    }
}

/// True when the OS keyring backend is reachable.
pub fn daemon_available() -> bool {
    // verbatim probe from sshrack-old
    let probe = match keyring::Entry::new(SERVICE, "__sshrack_probe__") {
        Ok(e) => e,
        Err(_) => return false,
    };
    let reachable = probe.set_password("").is_ok();
    if reachable {
        let _ = probe.delete_credential();
    }
    reachable
}
```

(`KeyringUnavailable` / `KeyringIo` variants already exist in `SshrackError`.)

- [ ] **Step 2: Define the traits + OsKeyring in `secret/mod.rs`**

Append to `crates/sshrack-core/src/secret/mod.rs`:

```rust
//! Secret storage backends behind injected traits.
//!
//! Core defines [`SecretBackend`] (where stored secrets live) and
//! [`PassphraseProvider`] (how a vault passphrase is obtained). The CLI
//! supplies concrete impls; tests supply fakes. Nothing here prints or logs a
//! passphrase.

use zeroize::Zeroizing;
use ulid::Ulid;
use crate::error::SshrackError;
use crate::id::OwnerKind;

pub mod keyring;
pub mod vault;

/// The OS keyring (or a test double) behind a single seam.
pub trait SecretBackend {
    fn set(&self, kind: OwnerKind, id: &Ulid, password: &str) -> Result<(), SshrackError>;
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError>;
    fn delete(&self, kind: OwnerKind, id: &Ulid) -> Result<(), SshrackError>;
    fn available(&self) -> bool;
}

/// Where a vault passphrase comes from. Methods that read a passphrase return
/// [`Zeroizing<String>`] so the plaintext is wiped on drop.
pub trait PassphraseProvider {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError>;
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError>;
    /// A yes/no confirmation, defaulting to No.
    fn confirm(&self, text: &str) -> Result<bool, SshrackError>;
}

/// The real OS keyring.
pub struct OsKeyring;

impl SecretBackend for OsKeyring {
    fn set(&self, kind: OwnerKind, id: &Ulid, password: &str) -> Result<(), SshrackError> {
        let key = crate::id::keyring_key(kind, id);
        let entry = keyring::entry_for_pub(&key)?; // see note below
        entry
            .set_password(password)
            .map_err(|_| SshrackError::KeyringIo { detail: "write" })
    }
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
        keyring::get(key)
    }
    fn delete(&self, kind: OwnerKind, id: &Ulid) -> Result<(), SshrackError> {
        keyring::delete_by_key(&crate::id::keyring_key(kind, id))
    }
    fn available(&self) -> bool {
        keyring::daemon_available()
    }
}

/// Best-effort delete of a keyring entry when the owner was keyring-marked.
pub fn forget_keyring_secret(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    id: &Ulid,
    marked: bool,
) {
    if marked {
        let _ = backend.delete(kind, id);
    }
}
```

Note: expose a small `pub(crate) fn entry_for_pub(key) -> Result<keyring::Entry, SshrackError>` from `keyring.rs` (rename the private `entry_for`) so `OsKeyring::set` can construct the entry. Alternatively, expose a `pub(crate) fn set_by_key(key, password)` helper in `keyring.rs` and call it from `OsKeyring::set`. Pick the helper and keep it consistent.

- [ ] **Step 3: Port the test doubles**

Bring the `FakeBackend` (in-memory keyring keyed by the derived key) and the trait-level tests from sshrack-old's `secrets.rs`, adjusting `set`/`delete` to the `(kind, id)` signature and keying via `crate::id::keyring_key`. Drop the `FakePrompt`/`DialoguerPrompt`/`password_mode` machinery (CLI concern, Task 17) — but keep a minimal `FakePassphraseProvider` for vault tests.

- [ ] **Step 4: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core secret:: -- --nocapture`
Expected: green (crypto + cache + keyring-key tests).

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-core/src/secret/
git commit -m "feat(secret): extract SecretBackend/PassphraseProvider traits and keyring impl"
```

---

## Task 8: Credential resolution (ref-by-id)

**Files:**
- Create: `crates/sshrack-core/src/credential.rs`
- Create: `crates/sshrack-core/src/suggest.rs`

**Interfaces:**
- Produces:
  - `credential::PasswordSource { None, Inline(Zeroizing<String>), Keyring { key } }` (Debug redacts Inline)
  - `credential::ResolvedAuth { user, key_path, password }` + `from_plain`
  - `credential::resolve(host: &Host, cfg: &SshrackConfig, vault: Option<&VaultKey>) -> Result<ResolvedAuth, SshrackError>` — follows `Auth::Ref { credential: Ulid }` via `find_credential_by_id` (NOT name)
  - `credential::find_referrers(cfg, cred_id) -> Vec<Ulid>` (hosts whose auth refs this credential id — for delete warnings)
  - `suggest::closest(candidates, query) -> Option<String>`

- [ ] **Step 1: Port `suggest.rs`**

Copy sshrack-old's `suggest.rs` verbatim (pure Levenshtein-ish did-you-mean via `strsim`).

- [ ] **Step 2: Port `credential.rs` and switch refs to id**

Copy sshrack-old's `credential.rs`. Apply:
- `resolve`'s `Auth::Ref { credential }` arm: `credential` is now a `Ulid`. Look up via `cfg.find_credential_by_id(&credential).ok_or_else(|| SshrackError::CredentialNotFound { ... })?`. The keyring owner becomes `OwnerKind::Credential` with `cred.id`; the inline arm uses `OwnerKind::Host` with `host.id`.
- `credential_not_found` / `find_referrers` now operate on ids. `find_referrers(cfg, cred_id: &Ulid)` returns the host **ids** (or names — pick ids for stability; display layer maps to name) whose `auth.credential_id() == Some(cred_id)`.
- Update `merge_credential`/`validate_*` to take `id`/`name` explicitly (construct `Credential { id, name, body }`).
- Keep `decrypt_secret` and the `PasswordSource` Debug-redaction tests; update them to the new `Host`/`Credential` shapes.

- [ ] **Step 3: Update tests**

Port the credential tests, updating every `Auth::Ref` to use a real ULID and every host/cred construction to the new shapes. Add a regression test: a credential referenced by id can be **renamed** (name changed) without breaking `resolve`.

- [ ] **Step 4: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core credential:: suggest:: -- --nocapture`
Expected: green.

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-core/src/credential.rs crates/sshrack-core/src/suggest.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): port credential resolution with ref-by-id"
```

---

## Task 9: ssh/scp argv assembly (verbatim port)

**Files:**
- Create: `crates/sshrack-core/src/connect/mod.rs`
- Create: `crates/sshrack-core/src/connect/ssh.rs`
- Create: `crates/sshrack-core/src/connect/scp.rs`

**Interfaces:**
- Produces:
  - `connect::ssh::Overrides { user, port, identity, credential: Option<Ulid>, ad_hoc }` (credential is now a ULID, resolved by the CLI before calling)
  - `connect::ssh::build(resolved, host: &Host, overrides, remote_command) -> Vec<String>`
  - `connect::scp::build(...)` (name:path expansion to `user@host:path`)

- [ ] **Step 1: Port `cmd/ssh.rs` and `cmd/scp.rs`**

Copy them to `connect/ssh.rs` and `connect/scp.rs`. Adjust:
- `use crate::config::schema::HostConfig` → `use crate::config::schema::Host`.
- `Overrides.credential: Option<String>` → `Option<Ulid>`. (The CLI resolves `--credential <name>` to an id before constructing `Overrides`; the argv builder does not need the name.)
- The `host()` test helper constructs the new `Host { id, name, host, port, auth }`.

`crates/sshrack-core/src/connect/mod.rs`:

```rust
//! Connection: ssh/scp argv assembly and the zero-copy launcher.
//!
//! The launcher itself (spawn + inherited stdio + askpass env wiring) is added
//! in Task 11.

pub mod scp;
pub mod ssh;
```

- [ ] **Step 2: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core connect:: -- --nocapture`
Expected: green.

Run: `cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 3: Commit**

```bash
git add crates/sshrack-core/src/connect/
git commit -m "feat(connect): port ssh/scp argv assembly"
```

---

## Task 10: askpass protocol (port)

**Files:**
- Create: `crates/sshrack-core/src/askpass.rs`

**Interfaces:**
- Produces:
  - `askpass::ASKPASS_FILE_ENV`
  - `askpass::materialize(path) -> Result<Zeroizing<String>, SshrackError>`
  - `askpass::run() -> Result<(), SshrackError>` (reads env set by the launcher; keyring branch via `secret::keyring::get`, file branch via `materialize`)

- [ ] **Step 1: Port `askpass.rs`**

Copy sshrack-old's `askpass.rs`. Adjust the keyring import to `crate::secret::keyring::{get, KEYRING_KEY_ENV}`. Keep the file-based tests (they write a 0600 tmp and assert round-trip + non-utf8 rejection).

- [ ] **Step 2: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core askpass:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 3: Commit**

```bash
git add crates/sshrack-core/src/askpass.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): port askpass protocol"
```

---

## Task 11: Zero-copy launcher (port)

**Files:**
- Modify: `crates/sshrack-core/src/connect/mod.rs`

**Interfaces:**
- Produces:
  - `connect::current_exe() -> Result<PathBuf, SshrackError>`
  - `connect::launch(argv, source: PasswordSource, self_exe: &Path) -> Result<i32, SshrackError>` (stdio inherited; `Inline` ⇒ 0600 temp file via `SSHRACK_ASKPASS_FILE`, `Keyring` ⇒ `SSHRACK_KEYRING_KEY`, `None` ⇒ no payload)
  - `connect::env_for(source) -> Vec<(&'static str, String)>` (test seam)

- [ ] **Step 1: Port the launcher into `connect/mod.rs`**

Append sshrack-old's `connect.rs` body (the `askpass_env_for` / `env_for` / `write_password_file` / `launch` / `current_exe` functions + tests) into `connect/mod.rs`, below the module doc and `pub mod` declarations. Adjust imports: `use crate::askpass::ASKPASS_FILE_ENV; use crate::secret::keyring::KEYRING_KEY_ENV; use crate::credential::PasswordSource;`.

- [ ] **Step 2: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core connect:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

Expected: the `write_password_file_is_0600_and_round_trips` and env-shape tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/sshrack-core/src/connect/mod.rs
git commit -m "feat(connect): port zero-copy launcher with askpass wiring"
```

---

## Task 12: Host-key pre-flight + confirm callback

**Files:**
- Create: `crates/sshrack-core/src/hostkey.rs`

**Interfaces:**
- Produces:
  - `hostkey::run_host_key_flow(host: &str, port: u16, confirm: impl FnOnce(&str) -> bool) -> Result<(), SshrackError>` — pure orchestration over `ssh-keyscan` + `ssh-keygen -F`; the **confirm callback** is the injected seam (CLI passes a dialoguer confirm; tests pass a closure).
  - Keep the pure helpers sshrack-old already factored out: `classify`, `parse_fingerprints`, `pick_primary`, `confirm_text`.

- [ ] **Step 1: Port and refactor `hostkey.rs`**

Copy sshrack-old's `hostkey.rs`. Extract the top-level "ensure trusted" entry into `run_host_key_flow(host, port, confirm)`. The new key vs changed-key decision calls `confirm(&text)`; a `false` return maps to `SshrackError::HostKeyRejected` (add the variant if absent). Unattended (no tty) unknown-key refusal stays.

- [ ] **Step 2: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core hostkey:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

The pure fingerprint/classify tests pass without network; the full `ssh-keyscan` flow is covered by an integration test in Task 19.

- [ ] **Step 3: Commit**

```bash
git add crates/sshrack-core/src/hostkey.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): port host-key pre-flight with injected confirm callback"
```

---

## Task 13: Host CRUD pure logic

**Files:**
- Create: `crates/sshrack-core/src/host.rs`

**Interfaces:**
- Produces (pure validation + CRUD-helpers, no I/O):
  - `host::validate_name_chars(name) -> Result<(), SshrackError>`
  - `host::validate_no_duplicate_host(cfg, name, force) -> Result<(), SshrackError>`
  - `host::validate_rename_host(cfg, current, new) -> Result<(), SshrackError>`
  - `host::add_host(cfg, id, name, host, port, auth) -> Result<SshrackConfig, SshrackError>` (returns a new immutable config)
  - `host::remove_host(cfg, name) -> Option<SshrackConfig>`
  - `host::resolve_target(...)` — name → `&Host` with did-you-mean, used by the connect path

- [ ] **Step 1: Port and adapt `host.rs`**

Copy sshrack-old's `host.rs`. Update name/cred lookups to the new id-based finders where relevant. `add_host` now takes an explicit `id: Ulid` (the caller generates it via `id::new_id()`). Keep `validate_name_chars` and the forbidden-char set verbatim.

- [ ] **Step 2: Port/adapt the host add/edit/cp/rm pure helpers from `cmd/host/*`**

Lift the decision logic out of sshrack-old's `cmd/host/add.rs`/`edit.rs`/`rm.rs`/`cp.rs` into core pure functions (`build_auth`, `auth_supplied_by_flags`, `merge_fields`, `apply_patch`, `finalize_body`, `delete_host_with_secret`). The keyring cleanup goes through `secret::forget_keyring_secret`; `cp`'s keyring copy through `SecretBackend`. Interactive prompt code stays in the CLI (Task 17). The id-preservation hack from old `edit.rs` becomes a pure `finalize_body(orig_id, new_body)`.

- [ ] **Step 3: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core host:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 4: Commit**

```bash
git add crates/sshrack-core/src/host.rs crates/sshrack-core/src/lib.rs
git commit -m "feat(core): port host CRUD pure logic"
```

---

## Task 14: Credential CRUD pure logic

**Files:**
- Modify: `crates/sshrack-core/src/credential.rs` (add CRUD helpers + seal)

**Interfaces:**
- Produces: `credential::add_credential`, `remove_credential`, `validate_no_duplicate_credential`, `validate_rename_credential`, `merge_credential`, plus the vault **seal** path (`seal_password`/`finalize_password`) that routes plaintext → plaintext/vault/keyring per the active store mode, behind `&dyn SecretBackend` / `&dyn PassphraseProvider`.

- [ ] **Step 1: Port `cmd/cred/*` pure logic + the vault transform**

Lift `cmd/cred/add.rs`/`edit.rs`/`rm.rs` decision logic into core. Port `vault/transform.rs` (migrate, finalize_password, count_secrets) so the seal path can flip a `Secret::Plain` ↔ encrypted ↔ keyring marker depending on `[store] mode`. All side effects go through the injected traits.

- [ ] **Step 2: Run tests, clippy, fmt, commit**

Run: `cargo test -p sshrack-core credential:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

```bash
git add crates/sshrack-core/src/credential.rs crates/sshrack-core/src/secret/
git commit -m "feat(core): port credential CRUD pure logic and seal path"
```

---

## Task 15: frecency (NEW backend capability)

**Files:**
- Create: `crates/sshrack-core/src/frecency/mod.rs`
- Create: `crates/sshrack-core/src/frecency/store.rs`

**Interfaces:**
- Produces:
  - `frecency::Score` / `frecency::Frecency` (a `HashMap<Ulid, { score: f64, last_used: SystemTime }>`)
  - `frecency::rank(hosts: &[&Host], query: &str, frec: &Frecency) -> Vec<RankedHost>` — pure; sort by (fuzzy-match presence → frecency score → name). Uses `strsim` for a first-period matcher (nucleo arrives with the TUI phase).
  - `frecency::record(&mut Frecency, id: &Ulid)` — bump score (zoxide 4-tier: `<1h ×4, <1d ×2, <1w ÷2, else ÷4`)
  - `frecency::store::load(dir) -> Frecency` / `save(dir, &Frecency)` — atomic TOML under `~/.local/share/sshrack/frecency.toml`

- [ ] **Step 1: Write the failing tests for `rank` and `record` (TDD)**

In `frecency/mod.rs` `#[cfg(test)]`, test:
- `record` on a fresh entry sets a high score; recording again after no time keeps it high.
- `rank` with empty query orders by score desc, ties broken by name.
- `rank` with a query puts hosts whose name contains the query ahead of non-matches.

(Note: tests must not depend on real wall-clock; inject `last_used` directly via a constructor `Frecency::with_now` that takes a `SystemTime`, or build the map by hand in tests.)

- [ ] **Step 2: Implement `record` (zoxide 4-tier)**

```rust
//! frecency (frequency + recency) scoring and machine-local persistence.

use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use ulid::Ulid;
use crate::config::schema::Host;
use crate::error::SshrackError;

const HOUR: u64 = 3600;
const DAY: u64 = 86_400;
const WEEK: u64 = DAY * 7;

/// Per-host usage state.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Entry {
    pub score: f64,
    pub last_used: Option<SystemTime>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Frecency {
    pub map: HashMap<Ulid, Entry>,
}

impl Frecency {
    /// Record a connection to `id` at `now`, applying the zoxide 4-tier decay.
    pub fn record_at(&mut self, id: &Ulid, now: SystemTime) {
        let prev = self.map.get(id).copied().unwrap_or_default();
        let age_secs = prev
            .last_used
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        let mult = if age_secs < HOUR {
            4.0
        } else if age_secs < DAY {
            2.0
        } else if age_secs < WEEK {
            0.5
        } else {
            0.25
        };
        let next_score = prev.score * mult + 1.0;
        self.map.insert(
            *id,
            Entry { score: next_score, last_used: Some(now) },
        );
    }

    /// Record using the real wall clock.
    pub fn record(&mut self, id: &Ulid) {
        self.record_at(id, SystemTime::now());
    }

    /// The score for `id`, or 0.0.
    pub fn score(&self, id: &Ulid) -> f64 {
        self.map.get(id).map(|e| e.score).unwrap_or(0.0)
    }
}

/// A host plus its computed rank signal.
#[derive(Debug, Clone)]
pub struct RankedHost<'a> {
    pub host: &'a Host,
    pub score: f64,
}

/// Rank hosts by fuzzy-match presence, then frecency score, then name.
/// Pure; `query` is matched case-insensitively as a substring in the name.
pub fn rank<'a>(hosts: &'a [&Host], query: &str, frec: &Frecency) -> Vec<RankedHost<'a>> {
    let q = query.to_lowercase();
    let mut out: Vec<RankedHost<'a>> = hosts
        .iter()
        .map(|h| RankedHost { host: h, score: frec.score(&h.id) })
        .collect();
    out.sort_by(|a, b| {
        // matches first
        let am = a.host.name.to_lowercase().contains(&q) as u8;
        let bm = b.host.name.to_lowercase().contains(&q) as u8;
        bm.cmp(&am)
            .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.host.name.cmp(&b.host.name))
    });
    out
}
```

(Adjust `record_at`'s decay to match the test expectations; the tests are the source of truth.)

- [ ] **Step 3: Implement persistence (`frecency/store.rs`)**

Atomic TOML write under `default_data_dir()/frecency.toml`, mirroring `config::store::save` (0600 temp + rename). `load` of a missing file ⇒ empty `Frecency`. Use a small `#[derive(Serialize, Deserialize)]` mirror struct (TOML cannot serialize `SystemTime` directly — store `last_used` as seconds-since-epoch `i64`).

- [ ] **Step 4: Run tests, clippy, fmt**

Run: `cargo test -p sshrack-core frecency:: -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-core/src/frecency/ crates/sshrack-core/src/lib.rs
git commit -m "feat(core): add frecency scoring and machine-local persistence"
```

---

## Task 16: Core crate — final integration gate

**Files:** none new (verification only).

- [ ] **Step 1: Full core test + clippy + fmt**

Run: `cargo test -p sshrack-core -- --nocapture && cargo clippy -p sshrack-core -- -D warnings && cargo fmt`
Expected: all green. If any test fails, fix before proceeding — the CLI layer depends on a correct core.

- [ ] **Step 2: Re-verify the zero-UI-dep invariant**

Run: `cargo tree -p sshrack-core | grep -E 'dialoguer|ratatui|console|crossterm' || echo CLEAN`
Expected: `CLEAN`.

- [ ] **Step 3: Commit any formatting/test fixes**

```bash
git add -A crates/sshrack-core
git commit -m "test(core): green core gate before CLI layer" || echo "nothing to commit"
```

---

## Task 17: CLI clap structure + role dispatch

**Files:**
- Create: `crates/sshrack-cli/src/cli.rs`
- Create: `crates/sshrack-cli/src/exit_code.rs`
- Modify: `crates/sshrack-cli/src/main.rs`

**Interfaces:**
- Produces:
  - `cli::Cli` (top-level) with global `--config`, `--no-input`, `--format json|text`, and `ConnectOptions` flattened.
  - `cli::Command { Ssh, Scp, Host, Cred, Store, Connect(external_subcommand) }` — **no `Tui` and no `Sftp` variant** (deferred). A bare `sshrack` (no subcommand) prints help (the old "open TUI" behavior is dropped for this period).
  - `cli::HostAction`/`CredAction`/`StoreAction` enums. `HostAction::Ls` gains `#[arg(long)] sort: Option<SortMode>` (`frecency|name|recent`).
  - `exit_code::ExitCode` constants: `SUCCESS=0`, `USAGE=2`, `NOT_FOUND=4`, `DUPLICATE=5`, `VALIDATION=6`, `CONNECT=7`, `STORE=8`.
  - `main.rs` role dispatch: if `SSHRACK_ASKPASS_FILE` or `SSHRACK_KEYRING_KEY` is set, run `sshrack_core::askpass::run()`; otherwise parse CLI.

- [ ] **Step 1: Write `exit_code.rs`**

```rust
//! Stable process exit codes. The CLI maps domain errors to these so scripts
//! and automation can branch on them.

pub const SUCCESS: i32 = 0;
pub const USAGE: i32 = 2;
pub const NOT_FOUND: i32 = 4;
pub const DUPLICATE: i32 = 5;
pub const VALIDATION: i32 = 6;
pub const CONNECT: i32 = 7;
pub const STORE: i32 = 8;
```

- [ ] **Step 2: Write `cli.rs`**

Port sshrack-old's `cli.rs` clap structs. Changes:
- Drop the `Tui` variant and the bare-`sshrack`-opens-TUI behavior (print `--help` instead, or a one-line pointer to `--help`).
- Drop any `Sftp` plumbing (none existed, but do not add it).
- Add global `#[arg(long, global = true)] pub no_input: bool` and `#[arg(long = "format", global = true, default_value = "text")] pub format: OutputFormat` where `OutputFormat` is `clap::ValueEnum { Text, Json }`.
- `HostAction::Add`'s `--credential <name>` stays a `String` (the CLI resolves name→id in Task 19's connect/cmd code, not in clap).
- `HostAction::Ls` gets `sort: Option<SortMode>`.

- [ ] **Step 3: Write role dispatch in `main.rs`**

```rust
//! sshrack binary entry. Dispatches between the SSH_ASKPASS helper role and
//! the CLI based on environment variables set by the launcher.

use sshrack_core::askpass;

mod cli;
mod cmd;
mod exit_code;
mod format;
mod prompt;

fn main() {
    // Askpass role: the launcher (or ssh) forks us with one of these set.
    if std::env::var_os(askpass::ASKPASS_FILE_ENV).is_some()
        || std::env::var_os(sshrack_core::secret::keyring::KEYRING_KEY_ENV).is_some()
    {
        match askpass::run() {
            Ok(()) => std::process::exit(exit_code::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(exit_code::CONNECT);
            }
        }
    }

    let code = run_cli();
    std::process::exit(code);
}

fn run_cli() -> i32 {
    // Parse + dispatch lands in later tasks. Stub returns SUCCESS.
    let _cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => { e.print().ok(); std::process::exit(e.exit_code()); }
    };
    // TODO(Task 19+): dispatch on _cli.cmd
    eprintln!("sshrack CLI dispatch not yet implemented");
    exit_code::SUCCESS
}
```

(Leave the `cmd`/`format`/`prompt` modules as empty `//! …` files now; they are filled in the next tasks.)

- [ ] **Step 4: Build, clippy, fmt**

Run: `cargo build -p sshrack-cli && cargo clippy -p sshrack-cli -- -D warnings && cargo fmt`

Run: `cargo run -p sshrack-cli -- --help`
Expected: clap prints help listing `ssh`, `scp`, `host`, `cred`, `store`, and global `--config`/`--no-input`/`--format`. No `tui`, no `sftp`.

- [ ] **Step 5: Commit**

```bash
git add crates/sshrack-cli/
git commit -m "feat(cli): clap structure with global --no-input/--format and askpass dispatch"
```

---

## Task 18: CLI prompt + format modules

**Files:**
- Create: `crates/sshrack-cli/src/prompt.rs`
- Create: `crates/sshrack-cli/src/format.rs`

**Interfaces:**
- Produces:
  - `prompt::DialoguerPassphrase` impl of `sshrack_core::secret::PassphraseProvider`.
  - `prompt::password_mode() -> Result<PasswordModeChoice>` — first-use mode menu (Keyring/Encrypted/Plaintext). Owned by the CLI because it is a UI concern; core only exposes the `SecretStore` types.
  - `prompt::confirm_with_fallback(no_input: bool, text)` — returns `false` immediately under `--no-input` (fail-closed), else dialoguer confirm.
  - `format::Output` abstraction: `format::print_hosts_text(...)`, `print_hosts_json(...)`, etc., selected by the global `--format`. JSON shapes are `#[derive(Serialize)]` structs with stable field names.

- [ ] **Step 1: Implement `prompt.rs`**

Port sshrack-old's `DialoguerPrompt` (split: the `PassphraseProvider` methods go into a `DialoguerPassphrase` impl; `password_mode` + `confirm` become free functions). Add the `--no-input` fail-closed behavior to confirm.

- [ ] **Step 2: Implement `format.rs` JSON shapes**

Define serde structs for each query/management output (host list row, host detail, credential list row, store status). Add a unit test that serializes a sample to JSON and asserts a stable shape (key names + presence), so the AI/automation contract is locked.

- [ ] **Step 3: clippy + fmt + commit**

Run: `cargo clippy -p sshrack-cli -- -D warnings && cargo fmt`

```bash
git add crates/sshrack-cli/src/prompt.rs crates/sshrack-cli/src/format.rs
git commit -m "feat(cli): dialoguer prompt impl and --format json shapes"
```

---

## Task 19: CLI connect path (`<name>` / `ssh`)

**Files:**
- Create: `crates/sshrack-cli/src/cmd/mod.rs`
- Create: `crates/sshrack-cli/src/cmd/connect.rs`

**Interfaces:**
- Produces: `cmd::connect::run(cli, no_input) -> i32` that:
  1. resolves the name → `&Host` (fail-fast: not-found + did-you-mean **before** any network IO),
  2. resolves the credential override `--credential <name>` → `Ulid` (fail-fast if unknown),
  3. loads/injects vault key (prompt via `DialoguerPassphrase` if vault mode; `--no-input` ⇒ require `SSHRACK_PASSPHRASE` env or fail),
  4. `credential::resolve` → `ResolvedAuth`,
  5. `hostkey::run_host_key_flow(host, port, confirm)` — confirm via dialoguer (fail-closed under `--no-input`),
  6. `connect::ssh::build` → argv,
  7. `connect::launch(argv, source, &current_exe())`,
  8. on success `frecency::record(host.id)` + `frecency::save` (persist **before** launching ssh — see spec §7; do the record/save, then launch).

- [ ] **Step 1: Implement `cmd::connect::run`** following the 8-step order. Honor the global `--no-input`: any prompt that would block instead maps to a `VALIDATION`/`USAGE` exit.

- [ ] **Step 2: Manual smoke test against a throwaway local ssh target** (or a mock). At minimum:

Run: `cargo run -p sshrack-cli -- --help` (sanity), then against a host name configured via `host add`:

```bash
cargo run -p sshrack-cli -- host add web1 --host 127.0.0.1 --user "$USER" --identity "$HOME/.ssh/id_ed25519" --no-input
cargo run -p sshrack-cli -- web1 uname -a
```

Expected: connects (or fails with a clear error if the key/host is unreachable); the error path is acceptable as long as it is the expected failure, not a panic.

- [ ] **Step 3: clippy + fmt + commit**

Run: `cargo clippy -p sshrack-cli -- -D warnings && cargo fmt`

```bash
git add crates/sshrack-cli/src/cmd/
git commit -m "feat(cli): connect path with fail-fast validation and frecency record"
```

---

## Task 20: CLI scp path + host/cred/store commands

**Files:**
- Create: `crates/sshrack-cli/src/cmd/scp.rs`
- Create: `crates/sshrack-cli/src/cmd/host.rs`
- Create: `crates/sshrack-cli/src/cmd/cred.rs`
- Create: `crates/sshrack-cli/src/cmd/store.rs`
- Modify: `crates/sshrack-cli/src/main.rs` (wire dispatch)

**Interfaces:**
- Produces: per-resource command handlers that call core pure functions, then `config::store::save`. Each honors `--no-input` (no field prompts) and `--format` (ls/show/status emit JSON or text). `host ls --sort frecency` reads `frecency::store::load` and uses `frecency::rank`.

- [ ] **Step 1: `cmd/scp.rs`** — port sshrack-old's scp dispatch (name:path expansion), using `connect::scp::build` and the same vault/hostkey resolution as connect.

- [ ] **Step 2: `cmd/host.rs`** — add/ls/show/edit/rm/cp. Patch commands (`edit`) touch only fields whose flags are present (the §3.3 rule). `ls` supports `--fields` and `--sort`. add/edit with `--credential <name>` resolve to id before persisting; show/ls reverse-resolve id→name for display.

- [ ] **Step 3: `cmd/cred.rs`** — add/ls/show/edit/rm. rm warns when `credential::find_referrers` is non-empty (references survive because they are by id — they become dangling only if the credential is actually removed; surface the referrer names so the user knows).

- [ ] **Step 4: `cmd/store.rs`** — status/use/rekey/lock/unlock/config. `use keyring` fails fast via `SecretBackend::available()` before migrating; `use vault` prompts for a passphrase via `DialoguerPassphrase`. All migrations route through the core seal/transform path.

- [ ] **Step 5: Wire dispatch in `main.rs::run_cli`** — match `cli.cmd` to the handlers; map `SshrackError` to `exit_code` (NotFound→`NOT_FOUND`, AlreadyExists→`DUPLICATE`, validation→`VALIDATION`, connect→`CONNECT`, store→`STORE`).

- [ ] **Step 6: Build, clippy, fmt, manual smoke**

Run: `cargo build -p sshrack-cli && cargo clippy --workspace -- -D warnings && cargo fmt`

Manual:
```bash
cargo run -p sshrack-cli -- host ls --format json
cargo run -p sshrack-cli -- host ls --sort frecency
cargo run -p sshrack-cli -- cred ls --format json
cargo run -p sshrack-cli -- store status
```

- [ ] **Step 7: Commit**

```bash
git add crates/sshrack-cli/
git commit -m "feat(cli): scp/host/cred/store commands with json output and exit codes"
```

---

## Task 21: Integration tests

**Files:**
- Create: `crates/sshrack-core/tests/resolve_ref_by_id_test.rs`
- Create: `crates/sshrack-core/tests/frecency_persist_test.rs`
- Create: `crates/sshrack-cli/tests/connect_flow_test.rs` (mock ssh via PATH)
- Create: `crates/sshrack-cli/tests/json_output_test.rs`

**Interfaces:** consumes core + CLI public APIs.

- [ ] **Step 1: `resolve_ref_by_id_test.rs`** — build a config with a host referencing a credential by id; rename the credential's name; assert `resolve` still succeeds (ref-by-id does not dangle).

- [ ] **Step 2: `frecency_persist_test.rs`** — `record` a host, `save` to a temp data dir, `load` back, assert the score round-trips.

- [ ] **Step 3: `connect_flow_test.rs`** — set up a fake `ssh` earlier in PATH that records its argv + env to a file; run the connect path against a temp config; assert the argv shape and the askpass env (no plaintext in env for the keyring path).

- [ ] **Step 4: `json_output_test.rs`** — run `host ls --format json` / `cred ls --format json` against a temp config and parse the stdout as JSON (locks the automation contract).

- [ ] **Step 5: Run the full workspace suite, clippy, fmt**

Run: `cargo test --workspace -- --nocapture && cargo clippy --workspace -- -D warnings && cargo fmt`
Expected: all green. Hermetic — if `SSHRACK_PASSPHRASE` is set in the real shell, tests must still pass (no `env -u`).

- [ ] **Step 6: Commit**

```bash
git add crates/sshrack-core/tests crates/sshrack-cli/tests
git commit -m "test: ref-by-id, frecency persist, connect flow, json output"
```

---

## Task 22: Rewrite CLAUDE.md

**Files:**
- Modify: `CLAUDE.md` (full rewrite of the project-instructions file)

- [ ] **Step 1: Rewrite CLAUDE.md** to reflect the new architecture. The existing file is copied from sshrack-old (single-crate, id-on-body, TUI-phase-0, name-ref). Replace/extend the relevant sections:

  - **Project Overview**: keep the wrapping-ssh / three-storage-mode / keyring-lifecycle text, but reframe storage modes around the new core/cli/tui split. State the **backend/frontend** mental model explicitly.
  - **Architecture (NEW section):** the workspace layout (`sshrack-core` zero-UI-dep invariant, `sshrack-cli`, `sshrack-tui` deferred). The trait-injection seams (`SecretBackend`, `PassphraseProvider`, host-key confirm). The askpass role-dispatch in the CLI binary.
  - **Build Commands:** workspace forms — `cargo build --workspace`, `cargo test -p sshrack-core`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt`.
  - **Identity model:** first-class top-level `id: Ulid` on Host and Credential; references by id; keyring and frecency key off the owner id.
  - **CLI contract (NEW section):** `--no-input` (no prompts, fail-closed), `--format json|text` (global), stable exit codes. State plainly that the CLI is a general-purpose tool (no "for AI" framing).
  - **On-disk layout:** `~/.config/sshrack/config.toml` (store meta + hosts + creds) vs `~/.local/share/sshrack/frecency.toml` (machine-local state, never synced). `format_version = 1`.
  - **Deferred:** `sshrack sftp`, the TUI, port forwarding, `~/.ssh/config` import, 2FA.
  - **Hard Rules / Constraints:** keep all existing hard rules (English only, zero unsafe, zero unwrap, TDD for pure logic, clippy strict, fmt, error handling, no SSH protocol lib, credentials are sensitive). Keep "Solve the Problem First".
  - **Dependency Policy / Version Release / Rust Skills:** keep as-is.

  Keep the existing tone and depth; do not truncate the kept sections.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: rewrite CLAUDE.md for workspace core/cli/tui architecture"
```

---

## Self-Review (completed by the plan author)

**1. Spec coverage** — checked each spec section:
- §1 Vision (backend/frontend, CLI general-purpose, TUI deferred) → Tasks 1, 17, 22.
- §2 Architecture (workspace, zero-UI core, trait seams, askpass role) → Tasks 1, 7, 11, 17.
- §3 CLI surface + `--no-input`/`--format`/exit codes + three carried-over rules → Tasks 17, 18, 20. `sftp` deferred per user (no task — correct).
- §4 Identity + ref-by-id + format_version → Tasks 3, 4, 8, 13.
- §5 Storage/security → Tasks 6, 7, 14, 20.
- §6 Porting map + trait seams → Tasks 2–14.
- §7 frecency → Task 15.
- §8 On-disk layout → Tasks 5, 15.
- §9 Deferred scope → no tasks (correct).
- §10 Testing → Tasks 1–21 inline + Task 21 integration.
- §11 Dependencies → Task 1 manifests.
- §12 Implementation slices → maps to Tasks 1→22 in order.

**2. Placeholder scan** — no "TBD/TODO/fill in" outside the single intentional `TODO(Task 19+)` marker inside a stub `main.rs`, which is replaced in Task 20 Step 5. No "add appropriate error handling" steps. Pure-port steps name the exact source file to copy and the exact edits; they are not placeholders because the source is a concrete existing asset.

**3. Type consistency** — `Host`/`Credential` carry `id: Ulid` everywhere (Tasks 4, 8, 13, 14, 19, 20). `Auth::Ref { credential: Ulid }` consistently; `credential_id()` accessor used in `find_referrers` (Task 8) and display (Task 20). `OwnerKind` + `id::keyring_key` used by `SecretBackend` (Task 7) and `OsKeyring`. `PasswordSource` flows from `resolve` (Task 8) → `connect::launch` (Task 11) → askpass env (Task 10). `format_version: u32` on `SshrackConfig` (Task 4) and noted in CLAUDE.md (Task 22).
