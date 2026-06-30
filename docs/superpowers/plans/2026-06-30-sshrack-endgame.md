# sshrack Endgame Plan: TUI + Non-Interactive CLI + `alias`→`name` + Single-Binary Routing

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Make `sshrack` a single binary that routes to a fully non-interactive CLI (for scripts/agents) or a ratatui TUI (for humans) based on invocation shape; rename `alias`→`name` everywhere; remove the separate `sshrack-cli`/`sshrack-tui` crates.

**Architecture:** One root bin crate (`src/main.rs` dispatch) + `src/cli/` (pure non-interactive) + `src/tui/` (ratatui) + `src/shared/` (format/exit_code). `sshrack-core` stays a pure, zero-UI lib and is untouched except for the `alias`→`name` rename. Routing rule: bare `sshrack`→TUI launcher; `host add`/`edit` with no content flags→TUI wizard; everything else→CLI. The TUI is a thin view over core (data paths go through core; `on_key` logic is pure and unit-tested), borrowing patterns from `sshelf` (ratatui 0.30 + crossterm + nucleo-matcher).

**Tech Stack:** Rust 2024, MSRV 1.86, clap derive, thiserror (core) + anyhow (frontend), ratatui 0.30, crossterm 0.28, nucleo-matcher 0.3, serde/toml, zeroize, ulid, argon2, chacha20poly1305.

## Global Constraints

Every task implicitly inherits these (from `CLAUDE.md` hard rules — verbatim values):

- **English only** — all source, comments, doc comments, errors, help text, logs, commits.
- **Zero `unsafe`** — never, including tests. Rust 2024 `set_var` is unsafe; tests inject via params/seams, never mutate the real env.
- **Zero `unwrap()`/`expect()`** in production code — only in `#[cfg(test)]` or `expect("invariant: ...")` for genuinely unreachable states.
- **TDD for pure logic** — RED → GREEN → REFACTOR.
- **`cargo clippy --workspace --all-targets -- -D warnings`** + **`cargo fmt`** green before every commit.
- **Passwords are `Zeroizing<String>`** end-to-end; never logged/printed/in errors/argv/`ps`. Keyring mode: main process never materializes keyring plaintext. Temp files: atomic `create_new` + `0600`.
- **Never reimplement SSH** — no `russh`/`ssh2`/`russh-sftp`; spawn system `ssh`/`scp`.
- **Tests are hermetic** — `cargo test` green in a real shell with `SSHRACK_PASSPHRASE` set; no `env -u` fallback.
- **`sshrack-core` zero-UI invariant** — its `Cargo.toml` never lists `dialoguer`/`ratatui`/`console`/`crossterm`.
- **Dev stage, no compat code** — no serde rename shims, no `--no-input` toggle, no alias→name transition stubs. Refactor thoroughly.

**Commit style:** `<type>(<scope>): <desc>` (Conventional Commits). Each task ends with a commit.

---

## File Structure (target, after all blocks)

```
sshrack/
├── Cargo.toml                    # [workspace] members=[crates/sshrack-core] + [package] name=sshrack + [[bin]]
├── src/
│   ├── main.rs                   # askpass role dispatch + cli/tui routing
│   ├── cli/
│   │   ├── mod.rs                # pub fn run(cli: &Cli) -> i32  (non-interactive only)
│   │   ├── args.rs               # clap structs (Cli/Command/HostAction/...) — renamed from cli.rs
│   │   ├── table.rs              # print_text_table (CLI-only stdout table)
│   │   └── cmd/
│   │       ├── mod.rs
│   │       ├── connect.rs        # ssh connect (non-interactive: env passphrase, --accept-new)
│   │       ├── scp.rs            # scp transfer (non-interactive)
│   │       ├── host.rs           # host CRUD (flags-only; missing field errors)
│   │       ├── cred.rs           # cred CRUD (flags-only)
│   │       └── store.rs          # store mode (env passphrase, --yes)
│   ├── tui/
│   │   ├── mod.rs                # pub fn run() -> Option<ConnectRequest>; event loop entry
│   │   ├── app.rs                # App struct, on_key -> Outcome (pure), state
│   │   ├── prompt.rs             # PassphraseProvider impl + host-key confirm closure (ratatui popups)
│   │   ├── launcher.rs           # host list + frecency + nucleo fuzzy + render
│   │   ├── wizard.rs             # host/cred add/edit form (TextField, Chooser, try_save)
│   │   ├── popup.rs              # confirm / vault-unlock / host-key popups
│   │   └── help.rs               # F1 help overlay + status bar
│   └── shared/
│       ├── mod.rs
│       ├── format.rs             # JSON row structs + label fns (cli + tui reuse labels)
│       └── exit_code.rs          # stable exit codes
├── tests/
│   └── json_output_test.rs       # drives the sshrack binary (moved from crates/sshrack-cli/tests)
└── crates/
    └── sshrack-core/             # UNCHANGED except alias→name rename
```

**Removed:** `crates/sshrack-cli/` (merged into root `src/cli/`), `crates/sshrack-tui/` (was empty stub; replaced by root `src/tui/`).

---

## Block 1 — `alias` → `name` rename (mechanical, must be first)

`name` identifier is confirmed unused (safe). Rename is total: no serde rename shims. Order core→cli→tests→docs keeps it compiling.

### Task 1: Core rename

**Files:**
- Modify: `crates/sshrack-core/src/config/schema.rs` (fields `alias`→`name` on `Host`/`Credential`; `AuthChoice::Credential{alias}`→`{name}`; `find_host_by_alias`→`find_host_by_name`; `find_credential_by_alias`→`find_credential_by_name`)
- Modify: `crates/sshrack-core/src/host.rs` (`validate_alias_chars`→`validate_name_chars`; `FORBIDDEN_ALIAS_CHARS`→`FORBIDDEN_NAME_CHARS`; error builders `host_not_found`/`host_already_exists`; all `.alias` reads/writes)
- Modify: `crates/sshrack-core/src/credential.rs` (same shape; `.alias`→`.name`)
- Modify: `crates/sshrack-core/src/error.rs` (variant `AliasTaken`→`NameTaken`; fields `alias`→`name` on `HostNotFound`/`CredentialNotFound`/`HostAlreadyExists`/`CredentialAlreadyExists`/`InvalidAliasChar`→`InvalidNameChar`; every `#[error("...")]` string: "host alias"→"host name", "credential alias"→"credential name", etc.)
- Modify: `crates/sshrack-core/src/connect/scp.rs` (operand docs `alias:path`→`name:path`; `plan_host_alias`→`plan_host_name`; error text)
- Modify: `crates/sshrack-core/src/frecency/mod.rs` (sort comparator `a.host.alias.cmp`→`a.host.name.cmp`; `to_lowercase().contains` on name)
- Modify: `crates/sshrack-core/src/secret/vault/transform.rs` (`alias_label`→`name_label` if present; display refs)

**Interfaces:**
- Produces: `Host{name}`, `Credential{name}`; `validate_name_chars(&str) -> Result<(), SshrackError>`; `find_host_by_name(&self, name: &str)`; `find_credential_by_name(&self, name: &str)`; `SshrackError::NameTaken{name}`, `InvalidNameChar{name, ch}`; `HostNotFound{name, hint}`, `CredentialNotFound{name, hint}`.

- [ ] **Step 1: Rename core identifiers**

Use ripgrep to enumerate, then `sed` per file. Do NOT blind-replace the English word "alias" inside prose — review each hit.

```bash
# Enumerate first (review before replacing)
rg -n 'alias' crates/sshrack-core/src/ | rg -v '//|///|//!'   # code hits
rg -n 'alias' crates/sshrack-core/src/ | rg  '//|///|//!'     # prose hits (review)
```

Identifier renames (code only):
```bash
# schema.rs, host.rs, credential.rs
sed -i 's/find_host_by_alias/find_host_by_name/g; s/find_credential_by_alias/find_credential_by_name/g' crates/sshrack-core/src/config/schema.rs
sed -i 's/validate_alias_chars/validate_name_chars/g; s/FORBIDDEN_ALIAS_CHARS/FORBIDDEN_NAME_CHARS/g' crates/sshrack-core/src/host.rs
# field access .alias -> .name (core only)
sed -i 's/\.alias\b/.name/g' crates/sshrack-core/src/host.rs crates/sshrack-core/src/credential.rs crates/sshrack-core/src/frecency/mod.rs
# field decl `pub alias:` -> `pub name:`
sed -i 's/pub alias:/pub name:/g' crates/sshrack-core/src/config/schema.rs
sed -i 's/alias: String,/name: String,/g' crates/sshrack-core/src/config/schema.rs   # AuthChoice::Credential{ alias }
```

- [ ] **Step 2: Rename error variants + messages (manual, in error.rs)**

Edit `error.rs` by hand: `AliasTaken`→`NameTaken`, `InvalidAliasChar`→`InvalidNameChar`, field `alias`→`name`. Rewrite every `#[error("...")]` string replacing "alias"→"name" (e.g. `"missing host alias"`→`"missing host name"`, `"alias '{alias}' must not contain..."`→`"name '{name}' must not contain..."`).

- [ ] **Step 3: Fix prose references (manual)**

In `connect/scp.rs`, `schema.rs` doc comments, `keyring.rs`, `id.rs`: replace "alias" with "name" where it refers to the field/concept. Keep "rename" (verb) where it means the action.

- [ ] **Step 4: Build core in isolation**

Run: `cargo build -p sshrack-core`
Expected: compiles (cli will be broken — that's Task 2). If core-only errors, fix them here.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor(core): rename alias to name across host/credential schema"
```

---

### Task 2: CLI rename (clap flags + cmd + JSON keys)

**Files:**
- Modify: `crates/sshrack-cli/src/cli.rs` (`HostAction::Add{alias}`→`{name}` positional; `--rename <NEW_ALIAS>` doc→`<NEW_NAME>`; `SortMode::Alias`→`SortMode::Name`; help text `<alias>`→`<name>`)
- Modify: `crates/sshrack-cli/src/cmd/{host,cred,connect,scp,store,shared}.rs` (`.alias`→`.name`; `resolve_alias`→`resolve_name`; `resolve_credential_alias`→`resolve_credential_name`; `credential_alias_for_host`→`credential_name_for_host`)
- Modify: `crates/sshrack-cli/src/format.rs` (`HostListRow.alias`→`.name`; `CredentialListRow.alias`→`.name`; `HostDetailRow.alias`→`.name`; `credential_alias`→`credential_name`; **JSON keys change: `{"alias":...}`→`{"name":...}`, `{"credential_alias":...}`→`{"credential_name":...}`**)

**Interfaces:**
- Produces: CLI flag `host add <name>` (positional), `host show <name>`, `host edit <name>`, `host rm <name>`; JSON output `{"name":..., "credential_name":...}`.

- [ ] **Step 1: Rename clap fields**

```bash
sed -i 's/alias: Option<String>/name: Option<String>/g; s/alias: String,/name: String,/g; s/alias: String$/name: String/g' crates/sshrack-cli/src/cli.rs
sed -i 's/SortMode::Alias/SortMode::Name/g' crates/sshrack-cli/src/cli.rs
# help/doc text: review manually (do not blind-replace 'alias' the English word)
```

In `cli.rs`, manually fix: the `SortMode` doc "Sort alphabetically by alias"→"by name"; `Add`/`Edit`/`Show`/`Rm` doc comments `<alias>`→`<name>`; `--rename` placeholder `<NEW_ALIAS>`→`<NEW_NAME>`; `external_subcommand` doc `<alias>`→`<name>`.

- [ ] **Step 2: Rename cmd handlers**

```bash
sed -i 's/\.alias\b/.name/g' crates/sshrack-cli/src/cmd/*.rs
sed -i 's/resolve_alias/resolve_name/g; s/resolve_credential_alias/resolve_credential_name/g; s/credential_alias_for_host/credential_name_for_host/g' crates/sshrack-cli/src/cmd/*.rs
```

Where a handler destructures `HostAction::Add { alias, .. }`, update the binding to `name`.

- [ ] **Step 3: Rename JSON keys (format.rs)**

```bash
sed -i 's/pub alias:/pub name:/g' crates/sshrack-cli/src/format.rs
sed -i 's/credential_alias/credential_name/g' crates/sshrack-cli/src/format.rs
```

Manual: in `format.rs` row-builder fns, `&host.alias`→`&host.name`, `&cred.alias`→`&cred.name`.

- [ ] **Step 4: Build full workspace**

Run: `cargo build --workspace`
Expected: compiles. Fix remaining `.alias`/`alias:` stragglers via `rg -n 'alias' crates/sshrack-cli/src/`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor(cli): rename alias to name in flags, handlers, and JSON contract"
```

---

### Task 3: Test rename

**Files:**
- Modify: `crates/sshrack-cli/tests/json_output_test.rs` (assertions `row["alias"]`→`row["name"]`; `credential_alias`→`credential_name`; fn params `alias:`→`name:`)
- Modify: `crates/sshrack-cli/src/format.rs` `#[cfg(test)]` (`expected_keys` arrays; field assertions)
- Modify: `crates/sshrack-core/src/{host,credential,config/schema}.rs` `#[cfg(test)]` (`.alias ==`→`.name ==`; TOML literals `alias = "web1"`→`name = "web1"`; test fn names `*alias*`→`*name*` where they reference the field)
- Modify: `crates/sshrack-core/tests/resolve_ref_by_id_test.rs` (`rename_credential_alias`→`rename_credential_name`; `.alias` asserts)

- [ ] **Step 1: Rename test assertions**

```bash
sed -i 's/\["alias"\]/["name"]/g; s/credential_alias/credential_name/g' crates/sshrack-cli/tests/json_output_test.rs crates/sshrack-cli/src/format.rs
# TOML literals in core tests
sed -i 's/alias = /name = /g' crates/sshrack-core/src/config/schema.rs crates/sshrack-core/src/host.rs crates/sshrack-core/src/credential.rs
sed -i 's/\.alias\b/.name/g' crates/sshrack-core/src/*.rs crates/sshrack-core/tests/*.rs
```

Review `rg -n 'alias' crates/` — remaining hits must be English prose only (e.g. "rename", or historical notes you will rewrite in Task 4).

- [ ] **Step 2: Run full test suite**

Run: `cargo test --workspace`
Expected: all green. Any failure is a missed rename — fix via the error's file:line.

- [ ] **Step 3: clippy + fmt**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "test: align alias->name rename in test fixtures and assertions"
```

---

### Task 4: Documentation rename

**Files:**
- Modify: `CLAUDE.md` (architecture section: "alias validation"→"name validation", "alias resolution"→"name resolution", "The `alias` is a human-readable..."→"The `name` is...", "reverse-resolve id→alias"→"id→name", `alias:path`→`name:path`)
- Modify: `docs/superpowers/specs/2026-06-30-sshrack-rewrite-design.md` (§4 schema TOML `alias =`→`name =`; §3 `<alias>`→`<name>`; concept prose)
- Modify: `docs/superpowers/plans/2026-06-30-sshrack-rewrite.md` (concept refs — skim, fix field/flag refs)

- [ ] **Step 1: Rewrite prose (manual, semantic)**

Do NOT blind-sed docs. Read each "alias" hit; replace with "name" when it refers to the field/handle; keep "rename" (verb) and any historical "was called alias" framing (remove the latter — dev stage, no compat narrative).

- [ ] **Step 2: Final audit**

Run: `rg -n '\balias\b' CLAUDE.md docs/ src/ crates/ 2>/dev/null`
Expected: zero hits (or only clearly-unrelated English like a variable named differently — there should be none here).

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "docs: rename alias to name in CLAUDE.md, spec, and plan"
```

---

## Block 2 — Crate restructure (single root binary)

Behavior unchanged after this block: CLI still interactive, still has `--no-input` (removed in Block 3). Only structure moves.

### Task 5: Rewrite root `Cargo.toml`

**Files:**
- Modify: `Cargo.toml` (root) — becomes `[workspace]` + `[package]` + `[[bin]]`.

- [ ] **Step 1: Rewrite root Cargo.toml**

```toml
[workspace]
resolver = "3"
members = ["crates/sshrack-core"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.86"
license = "MIT"
authors = ["ryaningli"]

[package]
name = "sshrack"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
sshrack-core = { path = "crates/sshrack-core" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zeroize = "1"
ulid = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
dialoguer = { version = "0.11", features = ["fuzzy-select"] }   # removed in Block 3
console = "0.15"                                                # removed in Block 3
strsim = "0.11"                                                 # only if cli actually uses it directly; else drop

[dev-dependencies]
tempfile = "3"
```

Note: root package is an implicit workspace member — do not add `""` to `members`.

- [ ] **Step 2: Verify core still builds standalone**

Run: `cargo build -p sshrack-core`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml && git commit -m "build: make root package the sshrack binary over workspace core"
```

---

### Task 6: Move CLI sources into root `src/`, create `shared/`, delete old crates

**Files:**
- Create: `src/main.rs` (copy of `crates/sshrack-cli/src/main.rs`)
- Create: `src/cli/mod.rs`, `src/cli/args.rs` (was `cli.rs`), `src/cli/table.rs` (was `print_text_table` in `shared.rs`), `src/cli/cmd/{mod,connect,scp,host,cred,store}.rs`
- Create: `src/shared/{mod,format,exit_code}.rs` (was `format.rs` + `exit_code.rs`)
- Move: `crates/sshrack-cli/tests/json_output_test.rs` → `tests/json_output_test.rs`
- Delete: `crates/sshrack-cli/`, `crates/sshrack-tui/`

**Interfaces:**
- Produces: `src/main.rs` with `mod cli; mod shared;` (drop `mod prompt;` stays temporarily as `src/cli/prompt.rs` until Block 3). `cli::Cli`, `cli::run(cli) -> i32`, `shared::format`, `shared::exit_code`.

- [ ] **Step 1: Create directories and move files**

```bash
mkdir -p src/cli/cmd src/shared tests
git mv crates/sshrack-cli/src/main.rs src/main.rs
git mv crates/sshrack-cli/src/cli.rs src/cli/args.rs
git mv crates/sshrack-cli/src/prompt.rs src/cli/prompt.rs
git mv crates/sshrack-cli/src/format.rs src/shared/format.rs
git mv crates/sshrack-cli/src/exit_code.rs src/shared/exit_code.rs
git mv crates/sshrack-cli/src/cmd/connect.rs src/cli/cmd/connect.rs
git mv crates/sshrack-cli/src/cmd/scp.rs src/cli/cmd/scp.rs
git mv crates/sshrack-cli/src/cmd/host.rs src/cli/cmd/host.rs
git mv crates/sshrack-cli/src/cmd/cred.rs src/cli/cmd/cred.rs
git mv crates/sshrack-cli/src/cmd/store.rs src/cli/cmd/store.rs
git mv crates/sshrack-cli/src/cmd/shared.rs src/cli/cmd/shared.rs
git mv crates/sshrack-cli/src/cmd/mod.rs src/cli/cmd/mod.rs
git mv crates/sshrack-cli/tests/json_output_test.rs tests/json_output_test.rs
```

- [ ] **Step 2: Author module roots**

`src/cli/mod.rs`:
```rust
//! Non-interactive command surface. All handlers are flags-only; missing
//! required fields error instead of prompting. Interaction lives in `tui`.
pub mod args;
pub mod cmd;
pub mod prompt;   // deleted in Block 3
pub mod table;

use crate::shared::exit_code;

pub use args::Cli;

/// Dispatch the parsed CLI. Returns the process exit code.
pub fn run(cli: &Cli) -> i32 {
    use args::Command;
    match &cli.cmd {
        None => {
            // Routed to TUI in Block 4; placeholder keeps behavior for now.
            Cli::command().print_help().ok();
            exit_code::SUCCESS
        }
        Some(Command::Ssh { .. }) | Some(Command::Connect(_)) => cmd::connect::run(cli),
        Some(Command::Scp { .. }) => cmd::scp::run(cli),
        Some(Command::Host { action }) => cmd::host::run(cli, action),
        Some(Command::Cred { action }) => cmd::cred::run(cli, action),
        Some(Command::Store { action }) => cmd::store::run(cli, action),
    }
}
```

`src/shared/mod.rs`:
```rust
//! Output shaping and exit codes shared by `cli` and `tui`.
pub mod exit_code;
pub mod format;
```

`src/cli/table.rs`: move `print_text_table` (and only it) out of the old `cmd/shared.rs` into here. Keep `cmd/shared.rs` for the rest (resolve helpers, NoInputPassphrase, etc. — culled in Block 3).

- [ ] **Step 3: Rewrite `src/main.rs`**

```rust
//! sshrack binary entry. Dispatches the SSH_ASKPASS helper role vs the CLI/TUI.
use clap::CommandFactory;
use sshrack_core::askpass;

mod cli;
mod shared;

fn main() {
    if std::env::var_os(askpass::ASKPASS_FILE_ENV).is_some()
        || std::env::var_os(sshrack_core::secret::keyring::KEYRING_KEY_ENV).is_some()
    {
        match askpass::run() {
            Ok(()) => std::process::exit(shared::exit_code::SUCCESS),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(shared::exit_code::CONNECT);
            }
        }
    }
    let code = run_main();
    std::process::exit(code);
}

fn run_main() -> i32 {
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            e.print().ok();
            return e.exit_code();
        }
    };
    cli::run(&cli)
}
```

- [ ] **Step 4: Delete old crates and fix imports**

```bash
git rm -r crates/sshrack-cli crates/sshrack-tui
```

Across `src/`, fix module paths: `use crate::format`→`use crate::shared::format`; `use crate::exit_code`→`use crate::shared::exit_code`; `crate::cmd::`→`crate::cli::cmd::`; references to `cli::Cli`/`cli::Command`→`cli::args::Cli`/`cli::args::Command` (re-export `Cli` from `cli/mod.rs` as above). `cmd/shared.rs` references to `super::` table fn now point at `crate::cli::table`.

- [ ] **Step 5: Build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: green, `sshrack` binary produced, `tests/json_output_test.rs` resolves `CARGO_BIN_EXE_sshrack`. Verify `cargo run -q -- --help` prints help.

- [ ] **Step 6: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "refactor: merge sshrack-cli into root binary, add shared layer"
```

---

## Block 3 — Strip CLI interactivity (fail-closed, non-interactive only)

### Task 7: Add `--accept-new`; delete `prompt.rs`

**Files:**
- Modify: `src/cli/args.rs` (`ConnectOptions`: add `--accept-new` bool)
- Delete: `src/cli/prompt.rs` (entire file — `DialoguerPassphrase`, `password_mode`, `confirm_with_fallback`, `host_key_confirm_closure*`, `PasswordModeChoice`)
- Modify: `src/cli/mod.rs` (remove `pub mod prompt;`)
- Modify: `Cargo.toml` (remove `dialoguer` + `console` deps)
- Modify: `src/cli/cmd/{connect,scp,host,cred,store,shared}.rs` (remove all `prompt::` imports/uses — replaced in Task 8)

**Interfaces:**
- Produces: `ConnectOptions { accept_new: bool }`; no `prompt` module. Host-key confirm closures are now inline lambdas in `connect.rs`/`scp.rs`.

- [ ] **Step 1: Add `--accept-new` to ConnectOptions**

In `src/cli/args.rs`, add to `ConnectOptions`:
```rust
    /// Accept a host key seen for the first time (like ssh's accept-new).
    /// Default refuses unknown keys. Changed keys are always rejected.
    #[arg(long = "accept-new")]
    pub accept_new: bool,
```
Add `accept_new: false` to the `Default` impl (or derive Default — check current style; `ConnectOptions` derives `Default`, so the bool defaults to `false` automatically — verify no manual impl). Include it in `overlay`: `accept_new: self.accept_new || base.accept_new`.

- [ ] **Step 2: Delete prompt.rs and its module decl**

```bash
git rm src/cli/prompt.rs
```
Remove `pub mod prompt;` from `src/cli/mod.rs`.

- [ ] **Step 3: Remove dialoguer/console from Cargo.toml**

Delete the two dependency lines. (Build will now fail on every `use dialoguer`/`use console` — fixed in Task 8.)

- [ ] **Step 4: Commit (intermediate — build still broken, fixed next task)**

This task and 3.2 land together; commit at end of 3.2. (If your workflow requires green commits, fold 3.1 steps into 3.2.)

---

### Task 8: Strip interactive branches from all cmd handlers

**Files:**
- Modify: `src/cli/cmd/connect.rs` (drop `DialoguerPassphrase`; always use env/NoInput passphrase; host-key confirm closure: `|_| opts.accept_new` for new keys)
- Modify: `src/cli/cmd/scp.rs` (same as connect)
- Modify: `src/cli/cmd/host.rs` (remove `prompt_fresh_alias`, `pick_host_menu`, `prompt_auth_menu`, `auth_from_choice`, `prompt_auth_and_seal`, `seal_auth_with_password`, `pick_existing_host`, the full-prompt `edit` mode, `cp` interactive; missing field → error; `rm` requires `--yes`)
- Modify: `src/cli/cmd/cred.rs` (remove `prompt_fresh_alias`, `pick_existing_credential`, `prompt_credential_body`, `seal_body_with_password`, full-prompt `edit`; missing field → error; `rm` requires `--yes`)
- Modify: `src/cli/cmd/store.rs` (`use vault` passphrase from `SSHRACK_PASSPHRASE` only (missing → error); `use plaintext` always requires `--yes`; `rekey` from env only)
- Modify: `src/cli/cmd/shared.rs` (remove `ensure_storage_mode_decided` first-use menu — replace with "run `sshrack store use <mode>` first" error; remove all `prompt_*` helpers; rename `NoInputPassphrase`→`EnvPassphrase`, make it the only provider)
- Modify: `src/cli/args.rs` (remove global `--no-input` flag and the per-subcommand `no_input` bools from `HostAction::Add/Edit`, `CredAction::Add/Edit`)

**Interfaces:**
- Produces: `shared::EnvPassphrase` (only `PassphraseProvider` impl — reads `SSHRACK_PASSPHRASE`, errors otherwise). `host add` with missing `--host` → `exit_code::VALIDATION`. `host rm <name>` without `--yes` → error. `store use vault` without env → error.

**Audit checklist (every `no_input`/`subcommand_no_input` consumer — from exploration):**
`connect.rs`, `scp.rs`, `host.rs` (~13 sites), `cred.rs` (~7 sites), `store.rs` (~9 sites), `shared.rs` (3 sites). Each becomes unconditional.

- [ ] **Step 1: connect.rs + scp.rs — env-only passphrase, accept-new closure**

In both, replace the `if cli.no_input { NoInputPassphrase } else { DialoguerPassphrase }` branch with unconditional `EnvPassphrase`. For host-key confirm, replace `prompt::host_key_confirm_closure(_no_input)` with an inline closure:
```rust
let accept_new = opts.accept_new;   // resolved overlay of top-level + subcommand
let confirm = move |_fingerprint: &str| accept_new;
hostkey::run_host_key_flow(&host, port, confirm)?;
```
(`run_host_key_flow` only calls `confirm` for *new* keys; changed keys are rejected upstream by ssh. So returning `accept_new` is correct.)

- [ ] **Step 2: host.rs — flags-only**

Delete the prompt helper fns listed above. In `add`: if `name.is_none()` → that's a TUI route (Block 4 handles it; for now error `exit_code::USAGE` "missing <name>"). If `host.is_none()` → `exit_code::VALIDATION` "missing --host". If `--credential` given, resolve via `credential::resolve`; else no auth menu. In `edit`: keep the patch path only; remove the full-prompt mode. In `rm`: if `!yes` → error "pass --yes to confirm". In `cp`: require both `src` and `dst` positionals, else error.

- [ ] **Step 3: cred.rs — flags-only**

Mirror host.rs: delete prompt helpers; `add` requires `--user` (and `name`); `rm` requires `--yes`; `edit` patch-only.

- [ ] **Step 4: store.rs — env-only + --yes**

`use vault`: passphrase from `vault::passphrase_from_env()`; if `None` → error "set SSHRACK_PASSPHRASE or use the TUI". `use plaintext`: require `--yes` else error. `rekey`/`unlock`: env-only.

- [ ] **Step 5: shared.rs — EnvPassphrase is the only provider**

```rust
/// The only passphrase source in the non-interactive CLI: the
/// SSHRACK_PASSPHRASE env var. Errors if unset.
pub struct EnvPassphrase;
impl PassphraseProvider for EnvPassphrase {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        vault::passphrase_from_env().ok_or(SshrackError::Interrupted)
    }
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> { self.passphrase() }
    fn confirm(&self, _text: &str) -> Result<bool, SshrackError> { Ok(false) }
}
```
Remove `ensure_storage_mode_decided` (first-use menu); replace its call sites with a direct error: store mode undecided → `exit_code::STORE` "run `sshrack store use <mode>` first". Remove all `prompt_*` helpers.

- [ ] **Step 6: args.rs — remove --no-input**

Delete the global `no_input` field from `Cli` and the `no_input` bool from `HostAction::Add`/`Edit` and `CredAction::Add`/`Edit`.

- [ ] **Step 7: Build + test + clippy + fmt**

```bash
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
```
Update `tests/json_output_test.rs` if it passes `--no-input` (remove that flag). Expected: green.

- [ ] **Step 8: Verify behavior**

```bash
cargo run -q -- host add myhost                 # expect error: missing --host
cargo run -q -- host rm myhost                  # expect error: pass --yes
cargo run -q -- host ls                         # still works (non-interactive)
```

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -m "refactor(cli): strip all interactivity; CLI is now fail-closed non-interactive"
```

---

## Block 4 — Routing dispatch + TUI stub

### Task 9: Route in `run_main` (None / empty-add / empty-edit → TUI)

**Files:**
- Modify: `src/main.rs` (`run_main`: decide TUI vs CLI before calling `cli::run`)

**Interfaces:**
- Consumes: `cli::Cli`, `cli::args::{Command, HostAction, CredAction}`.
- Produces: calls `tui::run()` (Task 10 stub) for TUI routes; `cli::run(&cli)` otherwise.

- [ ] **Step 1: Add the routing predicate**

In `src/main.rs`, add `mod tui;` and route:
```rust
fn run_main() -> i32 {
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => { e.print().ok(); return e.exit_code(); }
    };
    if route_is_tui(&cli) {
        return match tui::run(&cli) {
            Ok(code) => code,
            Err(e) => { eprintln!("{e}"); shared::exit_code::CONNECT }
        };
    }
    cli::run(&cli)
}

/// A bare `sshrack`, or `host/cred add|edit` with no content flags, routes to
/// the TUI. Everything else (connect, scp, ls, show, rm, cp, store) is CLI.
fn route_is_tui(cli: &cli::Cli) -> bool {
    use cli::args::{Command, HostAction, CredAction};
    match &cli.cmd {
        None => true,
        Some(Command::Host { action }) => add_or_edit_is_empty_host(action),
        Some(Command::Cred { action }) => add_or_edit_is_empty_cred(action),
        _ => false,
    }
}
```

`add_or_edit_is_empty_host`: for `HostAction::Add`, true when `name/host/user/port/identity/credential/force` all unset; for `Edit`, true when no edit flag set (reuse the `host::edit_has_any_flag` predicate, renamed from the no-input era — or inline the check). `host edit <name>` (name set, no edit flags) returns true → TUI edit wizard.

- [ ] **Step 2: Commit (after 4.2 stub exists so it compiles)**

---

### Task 10: TUI stub

**Files:**
- Create: `src/tui/mod.rs`

- [ ] **Step 1: Stub `tui::run`**

```rust
//! Interactive TUI front end. Thin view over sshrack-core; all data paths go
//! through core, never reimplemented here.
use crate::cli::Cli;

pub fn run(_cli: &Cli) -> Result<i32, sshrack_core::error::SshrackError> {
    // Replaced by the real launcher in Block 5.
    eprintln!("sshrack TUI (not yet implemented)");
    Ok(crate::shared::exit_code::SUCCESS)
}
```

- [ ] **Step 2: Add TUI deps to Cargo.toml**

```toml
ratatui = "0.30"
crossterm = "0.28"
nucleo-matcher = "0.3"
```

- [ ] **Step 3: Build + verify routing**

```bash
cargo build --workspace
cargo run -q --                       # prints "sshrack TUI (not yet implemented)"
cargo run -q -- host add             # same (empty add → TUI route)
cargo run -q -- host add --name x --host 1.2.3.4 --user root   # CLI (errors on missing cred, fine)
cargo run -q -- host ls              # CLI (works)
```

- [ ] **Step 4: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): add routing dispatch and tui module stub"
```

---

## Block 5 — TUI MVP (ratatui, thin view over core)

**Design red line (borrowed from sshelf, avoiding its coupling):** the TUI holds no data path. Every mutation goes through `sshrack-core` (`host::add`, `credential::resolve`, `connect::launch`, …). `on_key` returns a pure `Outcome` (unit-tested); side effects (persist, exec) happen in the loop after `on_key`. Delayed exec: the TUI restores the terminal *before* returning, then `main` calls `connect::launch`.

### Task 11: TUI infrastructure (App, event loop, terminal guard, run contract)

**Files:**
- Create: `src/tui/app.rs` — `App` state, `Outcome` enum, `on_key` (pure).
- Modify: `src/tui/mod.rs` — `run()` entry, terminal setup/teardown, connect orchestration.

**Interfaces:**
- Produces:
  - `pub struct ConnectRequest { pub argv: Vec<String>, pub source: sshrack_core::credential::PasswordSource }`
  - `pub fn run(cli: &Cli) -> Result<Option<ConnectRequest>, SshrackError>` — `None` = user quit, no connect.
  - `enum Outcome { Quit, Continue, Connect(ConnectRequest), OpenHostWizard(Option<Ulid>), … }` (grown in later tasks).
  - `struct App { … }` with `fn on_key(&mut self, key: KeyEvent) -> Outcome` (pure: no I/O).

- [ ] **Step 1: Define the delayed-exec contract + Outcome**

`src/tui/mod.rs`:
```rust
//! Interactive TUI. Thin view over sshrack-core. The run loop returns an
//! optional ConnectRequest; `main` does the actual exec after the terminal is
//! restored, so ssh never writes into the alternate screen.
use crate::cli::Cli;
use sshrack_core::error::SshrackError;

pub mod app;
pub mod help;
pub mod launcher;
pub mod popup;
pub mod prompt;
pub mod wizard;

/// What `main` needs to spawn ssh after the TUI exits. All pre-exec side
/// effects (resolve, vault unlock, host-key confirm, frecency save) have
/// already happened inside the TUI before this is returned.
pub struct ConnectRequest {
    pub argv: Vec<String>,
    pub source: sshrack_core::credential::PasswordSource,
}

pub fn run(_cli: &Cli) -> Result<Option<ConnectRequest>, SshrackError> {
    // Implemented in Step 3.
    Ok(None)
}
```

- [ ] **Step 2: Terminal guard (RAII restore)**

`src/tui/app.rs` (terminal half — or a `src/tui/term.rs` if you prefer):
```rust
use crossterm::{execute, terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// RAII guard: enters raw mode + alternate screen on creation, restores on
/// drop. Drop always runs, so the terminal is restored even if a connect
/// orchestration step errors.
pub struct TerminalGuard;

impl TerminalGuard {
    pub fn enter() -> io::Result<Tui> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Terminal::new(CrosstermBackend::new(io::stdout()))?)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}
```

- [ ] **Step 3: App skeleton + event loop**

`src/tui/app.rs`:
```rust
use crossterm::event::{self, Event, KeyEvent};
use ratatui::Frame;
use std::time::Duration;

use super::ConnectRequest;

/// The pure result of handling one key. Side effects happen in the loop, not
/// here, so key logic is unit-testable without a terminal.
pub enum Outcome {
    Quit,
    Continue,
    Connect(ConnectRequest),
    // grown in 5.4/5.6: EditHost(Ulid), AddHost, AddCred, RemoveHost(Ulid), …
}

pub struct App {
    pub should_quit: bool,
    // fields added in later tasks: hosts, query, selected, mode, popup, …
}

impl App {
    pub fn new() -> Self { Self { should_quit: false } }

    /// Pure: decide what should happen next. No I/O.
    pub fn on_key(&mut self, _key: KeyEvent) -> Outcome {
        Outcome::Continue
    }

    /// Render current state. Pure-ish (only writes to the frame).
    pub fn draw(&self, _frame: &mut Frame) {}
}

pub fn run_loop(terminal: &mut super::app::Tui, app: &mut App) -> Option<ConnectRequest> {
    loop {
        let _ = terminal.draw(|f| app.draw(f));
        if !event::poll(Duration::from_millis(250)).unwrap_or(false) { continue; }
        if let Event::Key(key) = event::read().unwrap_or(Event::Key(dummy_key())) {
            match app.on_key(key) {
                Outcome::Quit => return None,
                Outcome::Connect(req) => return Some(req),
                Outcome::Continue => {}
            }
        }
        if app.should_quit { return None; }
    }
}

fn dummy_key() -> KeyEvent { KeyEvent::new(crossterm::event::KeyCode::Esc, crossterm::event::KeyModifiers::NONE) }
```
(Wire `tui::run` to build `App`, `TerminalGuard::enter()`, call `run_loop`, return its `Option<ConnectRequest>` — the guard's drop restores the terminal before `main` execs.)

- [ ] **Step 4: TDD — on_key is pure**

In `src/tui/app.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn quit_key_yields_quit_outcome() {
        // Once an Esc→Quit rule is added, this pins it. Adjust the key to
        // match the chosen quit binding.
        let mut app = App::new();
        let _ = app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        // assert!(matches!(...)); fill once the binding lands.
    }
}
```

- [ ] **Step 5: Build + clippy + fmt + commit**

```bash
cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): app skeleton, terminal guard, delayed-exec contract"
```

---

### Task 12: `tui/prompt.rs` — PassphraseProvider + host-key confirm closure

**Files:**
- Create: `src/tui/popup.rs` — centered popup primitive (Clear + bordered Paragraph).
- Create: `src/tui/prompt.rs` — `TuiPassphrase` (impl `PassphraseProvider`), host-key confirm closure.

**Interfaces:**
- Consumes: `sshrack_core::secret::PassphraseProvider` (`&self`: `passphrase/passphrase_confirm/confirm`), `sshrack_core::hostkey::run_host_key_flow(confirm: impl FnOnce(&str)->bool)`.
- Produces: `TuiPassphrase` (drives a popup to read input), `pub fn confirm_host_key(fingerprint: &str, terminal, app) -> bool`.

**Note:** the ratatui rendering inside a popup can't be unit-tested cleanly. Extract the *decision* (what y/n means) into a pure helper and TDD that; the popup wires keys to the helper.

- [ ] **Step 1: popup primitive**

`src/tui/popup.rs`: a fn `pub fn centered_rect(area, width, height) -> Rect` (standard ratatui recipe) + a `Popup` render helper drawing a `Clear`-backed bordered area. Keep it ~40 lines.

- [ ] **Step 2: pure confirm decision helper (TDD)**

`src/tui/prompt.rs`:
```rust
/// Pure decision for a yes/no popup: which key yields which answer.
pub enum ConfirmAnswer { Yes, No, Pending }

pub fn confirm_from_key(key: crossterm::event::KeyCode) -> ConfirmAnswer {
    use crossterm::event::KeyCode::*;
    match key {
        Char('y') | Char('Y') => ConfirmAnswer::Yes,
        Char('n') | Char('N') | Esc => ConfirmAnswer::No,
        _ => ConfirmAnswer::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode::*;
    #[test]
    fn y_is_yes_n_is_no() {
        assert!(matches!(confirm_from_key(Char('y')), ConfirmAnswer::Yes));
        assert!(matches!(confirm_from_key(Char('N')), ConfirmAnswer::No));
        assert!(matches!(confirm_from_key(Enter), ConfirmAnswer::Pending));
    }
}
```

- [ ] **Step 3: TuiPassphrase (impl PassphraseProvider via popup)**

```rust
use sshrack_core::error::SshrackError;
use sshrack_core::secret::PassphraseProvider;
use zeroize::Zeroizing;

pub struct TuiPassphrase<'a> { /* borrow terminal + app state */ pub _p: &'a () }

impl PassphraseProvider for TuiPassphrase<'_> {
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
        // Drive a password popup (masked input), loop until Enter. Return the
        // typed string wrapped in Zeroizing. Esc → SshrackError::Interrupted.
        todo!("wire popup in Step 4")
    }
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
        // Two masked popups; loop until they match. (Same masking as passphrase.)
        todo!("wire popup in Step 4")
    }
    fn confirm(&self, text: &str) -> Result<bool, SshrackError> {
        // Render `text` in a popup, read keys, map via confirm_from_key.
        todo!("wire popup in Step 4")
    }
}
```

- [ ] **Step 4: Wire the popups**

Implement the three `todo!`s using `popup` + `event::read`. Host-key confirm closure (used by connect orchestration in 5.5):
```rust
pub fn host_key_confirm(/* terminal, app */) -> impl FnOnce(&str) -> bool {
    move |fingerprint: &str| {
        // render "Trust new host key: <fingerprint>? (y/n)" popup,
        // loop on keys via confirm_from_key; Esc/Ctrl-C → false.
        true // placeholder; real impl reads a key
    }
}
```

- [ ] **Step 5: Build + test + clippy + fmt + commit**

```bash
cargo test -p sshrack --lib tui::prompt
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): passphrase provider and host-key confirm via popups"
```

---

### Task 13: Launcher data layer — frecency + nucleo fuzzy rank (pure, TDD)

**Files:**
- Create: `src/tui/launcher.rs` — pure ranking + a `Launcher` state struct (query, selected).

**Interfaces:**
- Consumes: `sshrack_core::config::schema::Host` (has `.name`, `.id`), `sshrack_core::frecency::{rank, Frecency}`.
- Produces: `pub fn rank_hosts(hosts: &[Host], frecency: &Frecency, query: &str) -> Vec<RankedHost>` where `RankedHost { host_idx: usize, score: u32 }`. Empty query → frecency-only order (via `frecency::rank`); non-empty → nucleo match score, ties broken by frecency then name.

- [ ] **Step 1: Write failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sshrack_core::config::schema::Host;
    use sshrack_core::frecency::Frecency;

    fn host(name: &str) -> Host { /* build a Host with .name = name, fresh id */ todo!() }

    #[test]
    fn empty_query_orders_by_frecency() {
        let hosts = vec![host("alpha"), host("beta")];
        let mut fr = Frecency::default();
        // make beta more recent/frequent
        // fr.record_at(&beta_id, now);  — inject a fixed timestamp
        let ranked = rank_hosts(&hosts, &fr, "");
        assert_eq!(ranked[0].host_idx, /* beta's index */ 1);
    }

    #[test]
    fn query_filters_and_ranks_by_match() {
        let hosts = vec![host("web-prod"), host("db-staging"), host("web-dev")];
        let fr = Frecency::default();
        let ranked = rank_hosts(&hosts, &fr, "web");
        let names: Vec<&str> = ranked.iter().map(|r| hosts[r.host_idx].name.as_str()).collect();
        assert_eq!(names, vec!["web-dev", "web-prod"]); // both match 'web'; order by score
    }
}
```

- [ ] **Step 2: Run — expect fail (undefined)**

```bash
cargo test -p sshrack --lib tui::launcher 2>&1 | head
```

- [ ] **Step 3: Implement**

```rust
use nucleo_matcher::{Config, Matcher};
use nucleo_matcher::pattern::{Pattern, CaseMatching, Normalization};
use nucleo_matcher::Utf32Str;
use sshrack_core::config::schema::Host;
use sshrack_core::frecency::Frecency;

pub struct RankedHost { pub host_idx: usize, pub score: u32 }

pub fn rank_hosts(hosts: &[Host], _frecency: &Frecency, query: &str) -> Vec<RankedHost> {
    if query.is_empty() {
        // frecency-only: delegate to sshrack_core::frecency::rank over host ids,
        // map back to indices in original order. (If core's rank takes a Vec of
        // (id, score) and returns sorted ids, translate here.)
        return (0..hosts.len()).map(|i| RankedHost { host_idx: i, score: 0 }).collect();
    }
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Smart, Normalization::Smart);
    let mut scored: Vec<RankedHost> = hosts.iter().enumerate()
        .filter_map(|(i, h)| {
            let mut buf = Vec::new();
            let s = pattern.score(Utf32Str::Ascii(h.name.as_bytes()), &mut matcher)?;
            // fold frecency into the score so ties break toward recent/frequent
            Some(RankedHost { host_idx: i, score: s })
        })
        .collect();
    scored.sort_by(|a, b| b.score.cmp(&a.score));
    scored
}
```
(Refine the empty-query branch to actually use `frecency::rank`; the test pins the contract.)

- [ ] **Step 4: Run — pass**

```bash
cargo test -p sshrack --lib tui::launcher
```

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): pure host ranking with frecency and nucleo fuzzy"
```

---

### Task 14: Launcher render + key handling

**Files:**
- Modify: `src/tui/launcher.rs` (render + `on_key` for launcher mode).
- Modify: `src/tui/app.rs` (`App` owns launcher state; route `on_key` to it).

**Interfaces:**
- Consumes: `rank_hosts` (5.3), loaded `Config` (hosts), `Frecency`.
- Produces: keys: type into query; `↑/↓` or `^p/^n` move selection; `Enter` → `Outcome::Connect` (resolved in 5.5); `^a` add host; `^e` edit; `^d` delete; `Esc` quit.

- [ ] **Step 1: Launcher state**

```rust
pub struct Launcher {
    pub query: String,
    pub selected: usize,
    pub ranked: Vec<RankedHost>,   // recomputed on each keystroke
}
```

- [ ] **Step 2: Render — list with fuzzy highlight**

Draw a `List` of host names; highlight matched substrings (compute match indices via nucleo's `indices(...)`). Show frecency tier/score on the right. Status line: "Enter connect · ^a add · ^e edit · ^d del · F1 help · Esc quit". (One complete render fn; reuse for cred list later.)

- [ ] **Step 3: on_key**

```rust
pub fn on_key(&mut self, key: KeyEvent, hosts: &[Host]) -> Outcome {
    use crossterm::event::KeyCode::*;
    match key.code {
        Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Outcome::Quit,
        Esc => { if self.query.is_empty() { Outcome::Quit } else { self.query.clear(); recompute(self, hosts); Outcome::Continue } }
        Enter => self.selected_host(hosts).map(|h| /* Outcome::Connect — built in 5.5 */ Outcome::Continue).unwrap_or(Outcome::Continue),
        Char(c) => { self.query.push(c); recompute(self, hosts); Outcome::Continue }
        Backspace => { self.query.pop(); recompute(self, hosts); Outcome::Continue }
        Down | Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => { move_sel(self, 1); Outcome::Continue }
        Up | Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => { move_sel(self, -1); Outcome::Continue }
        _ => Outcome::Continue,
    }
}
```
(Add `^a/^e/^d` to switch to wizard/delete modes in 5.6/5.9.)

- [ ] **Step 4: Build + manual smoke + commit**

```bash
cargo build --workspace
# smoke: cargo run -q --   (needs ≥1 host in config; add via CLI first)
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): launcher list with fuzzy filter and key bindings"
```

---

### Task 15: Deferred-exec connect orchestration

**Files:**
- Modify: `src/tui/mod.rs` — `connect_host(host_id) -> Result<ConnectRequest, SshrackError>` doing all pre-exec side effects.
- Modify: `src/main.rs` — on `Some(req)`, `connect::launch(req.argv, req.source, &connect::current_exe()?)`.

**Interfaces:**
- Consumes (core): `host::resolve_target`, `credential::resolve`, `vault::ensure_unlocked_vault_key`, `hostkey::run_host_key_flow`, `connect::ssh::build`, `frecency::store::save`, `connect::current_exe`, `connect::launch`.

- [ ] **Step 1: Orchestration (mirror `cli::cmd::connect::run`, minus the prompt/launch split)**

```rust
fn connect_host(host_id: ulid::Ulid, cfg: &Config, frec: &mut Frecency) -> Result<ConnectRequest, SshrackError> {
    let host = cfg.find_host_by_id(&host_id).ok_or(SshrackError::HostNotFound { name: host_id.to_string(), hint: /* did-you-mean empty */ })?;
    // 1. vault unlock (TuiPassphrase) — only if mode is vault and not cached
    // 2. resolve auth -> PasswordSource (keyring key / inline / none)
    // 3. host-key pre-flight with TUI confirm closure (5.2)
    // 4. build argv via connect::ssh::build
    // 5. frecency record + save (BEFORE exec)
    //    frec.record_at(&host_id, now); frecency::store::save(frec, &data_dir)?;
    let argv = /* connect::ssh::build(...) */;
    let source = /* PasswordSource from resolved auth */;
    Ok(ConnectRequest { argv, source })
}
```
Read `cli::cmd::connect::run` and replicate its sequence exactly, swapping `EnvPassphrase`→`TuiPassphrase` and the host-key closure→the TUI one.

- [ ] **Step 2: main launches**

`src/main.rs`:
```rust
if route_is_tui(&cli) {
    return match tui::run(&cli)? {
        Some(req) => {
            // terminal already restored by TerminalGuard drop before this point
            let code = sshrack_core::connect::launch(req.argv, req.source, &sshrack_core::connect::current_exe()?)?;
            code
        }
        None => shared::exit_code::SUCCESS,
    };
}
```
Verify the `TerminalGuard` is dropped (terminal restored) *before* `launch` — structure `tui::run` so the guard's scope ends before returning the `ConnectRequest`. (Easiest: `run` takes the guard by value and drops it at end of scope after `run_loop` returns.)

- [ ] **Step 3: Integration test — mock-ssh connect from TUI path is hard; instead unit-test `connect_host` with a fake backend + fake frecency (TDD the orchestration's pure decisions where possible), and rely on the existing `connect_flow_test.rs` (core) for launch correctness.**

- [ ] **Step 4: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): wire connect orchestration to delayed exec"
```

---

### Task 16: Host add/edit wizard

**Files:**
- Create: `src/tui/wizard.rs` — `HostWizard` form state, `try_save` validation (TDD), render, on_key.

**Interfaces:**
- Consumes: `sshrack_core::host::{add, edit, validate_name_chars}`, `sshrack_core::config::schema::{Host, Auth}`.
- Produces: a wizard that on `^s`/`Enter`-on-last-field calls `host::add`/`host::edit` and returns to the launcher.

- [ ] **Step 1: TDD `try_save` validation (pure)**

```rust
pub struct HostForm {
    pub name: String,
    pub host_addr: String,
    pub port: u16,
    pub auth_choice: AuthChoice,   // Default | Credential(name) | InlineKey(path)
    pub errors: Vec<&'static str>,
}

pub enum SaveError { MissingName, MissingHost, InvalidName }

pub fn validate(form: &HostForm) -> Result<(), SaveError> {
    if form.name.trim().is_empty() { return Err(SaveError::MissingName); }
    if sshrack_core::host::validate_name_chars(&form.name).is_err() { return Err(SaveError::InvalidName); }
    if form.host_addr.trim().is_empty() { return Err(SaveError::MissingHost); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_name_and_host() {
        assert!(matches!(validate(&blank_form()), Err(SaveError::MissingName)));
        assert!(matches!(validate(&form_with_name_only()), Err(SaveError::MissingHost)));
    }
    #[test]
    fn accepts_complete_form() {
        assert!(validate(&complete_form()).is_ok());
    }
}
```

- [ ] **Step 2: Form render + on_key**

Render fields top-to-bottom (name, host, port, auth). `Tab`/`↑`/`↓` move focus; for `auth_choice` use a Chooser (`←`/`→` cycles Default→Credential→InlineKey, mirroring sshelf `ui/wizard.rs:410-424`). When auth=Credential, `←`/`→` cycles the credential list (loaded from config). Show placeholder hints in dim. On last field `Enter` or any `^s` → `validate` then `host::add`/`host::edit`; on error, set `errors` and focus the bad field (sshelf `try_save` pattern, `ui/wizard.rs:460-532`).

- [ ] **Step 3: Wire `^a`/`^e` from launcher into the wizard; on save, reload config and return to launcher.**

- [ ] **Step 4: Build + test + clippy + fmt + commit**

```bash
cargo test -p sshrack --lib tui::wizard
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): host add/edit wizard with validation"
```

---

### Task 17: Credential add/edit wizard

**Files:**
- Modify: `src/tui/wizard.rs` — add `CredForm` + `validate` (TDD) + render + on_key.

- [ ] **Step 1: TDD `validate` (requires name + user)**

Mirror Task 16's pattern: `CredForm { name, user, identity, secret_kind }`; `validate` requires non-empty name + user.

- [ ] **Step 2: Render + on_key** — same form idioms; `secret_kind` Chooser (Password / IdentityKey / None); password field masked (`•••`). On save call `credential::add`/`credential::edit`.

- [ ] **Step 3: Entry point** — add `sshrack cred` (bare add/edit) routing to TUI in `route_is_tui` (Task 9 already covers `Cred` add/edit empty). Launch wizard from a launcher key (e.g. a cred-list view opened via a key, or reuse `^a` in a cred mode).

- [ ] **Step 4: Build + test + clippy + fmt + commit**

```bash
cargo test -p sshrack --lib tui::wizard && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): credential add/edit wizard"
```

---

### Task 18: Store mode view + vault passphrase

**Files:**
- Modify: `src/tui/wizard.rs` (or new `src/tui/store.rs`) — a "store" view: shows current mode, lets the user pick keyring/vault/plaintext, enters vault passphrase via `TuiPassphrase::passphrase_confirm`.

- [ ] **Step 1: View** — list the three modes; `↑`/`↓` + `Enter` to choose. On vault: drive `TuiPassphrase.passphrase_confirm()` then call `secret::vault::enable(...)` (the same core fn `cli::cmd::store::switch_to_vault` uses). On plaintext: render a confirmation popup (reuse `confirm_from_key`). On keyring: call the migrate path.

- [ ] **Step 2: Entry** — bind a key (e.g. `F2`) in the launcher to open the store view.

- [ ] **Step 3: Build + clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): store mode switch view"
```

---

### Task 19: Confirm popups wired into flows (delete / host-key / vault unlock)

**Files:**
- Modify: `src/tui/popup.rs`, `src/tui/launcher.rs` (`^d` delete flow), `src/tui/mod.rs` (connect uses host-key + vault popups).

- [ ] **Step 1: Delete flow** — `^d` on selected host → render "Remove <name>? (y/n)" popup via `confirm_from_key`; on Yes call `host::remove` (and `forget_keyring_secret` if marked). Refresh launcher.

- [ ] **Step 2: Vault unlock popup at connect** — in `connect_host` (5.5), if vault locked, drive `TuiPassphrase.passphrase()` in a popup before resolving auth.

- [ ] **Step 3: Host-key popup at connect** — `connect_host` uses the TUI host-key confirm closure (5.2) showing the fingerprint.

- [ ] **Step 4: Build + clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): wire delete, vault-unlock, and host-key confirm popups"
```

---

### Task 20: Help overlay (F1) + status bar

**Files:**
- Create: `src/tui/help.rs` — `F1` full-screen keybinding reference.
- Modify: `src/tui/app.rs` — bottom status bar (last action / error / counts).

- [ ] **Step 1: Help overlay** — render a `Paragraph` listing all bindings (launcher + wizard + store), `Esc`/`F1` to dismiss.

- [ ] **Step 2: Status bar** — `App` holds `status: String`; every action sets it; render a one-line footer. Errors render in red.

- [ ] **Step 3: Build + clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt
git add -A && git commit -m "feat(tui): help overlay and status bar"
```

---

## Block 6 — Documentation + final verification

### Task 21: Rewrite CLAUDE.md architecture; mark spec/plan delivered; record breaking changes

**Files:**
- Modify: `CLAUDE.md` — architecture section: single root binary, `src/{cli,tui,shared}`, routing rule; remove the 3-crate description and the "TUI deferred" framing; update CLI contract (no `--no-input`, `--accept-new`, `--yes` for destructive, env passphrase).
- Modify: `docs/superpowers/specs/2026-06-30-sshrack-rewrite-design.md` — strike the "TUI deferred" notes; mark TUI delivered; keep sftp/port-forward/config-import/2FA/print-command as a documented later phase.
- Modify: `docs/superpowers/plans/2026-06-30-sshrack-rewrite.md` — add a pointer to this endgame plan.

- [ ] **Step 1: Rewrite CLAUDE.md architecture + CLI contract sections** (manual; the alias→name change from Block 1 already touched the prose).

- [ ] **Step 2: Document breaking changes** — in CLAUDE.md or a `docs/breaking-changes.md`: JSON keys `alias`→`name`, `credential_alias`→`credential_name`; TOML key `alias`→`name`; `--no-input` removed; `host/cred rm` requires `--yes`; `store use vault`/`rekey` are env-only on the CLI.

- [ ] **Step 3: Final full verification**

```bash
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
rg -n '\balias\b|\bno_input\b|dialoguer|sshrack-cli|sshrack-tui' CLAUDE.md docs src crates 2>/dev/null || true
```
Expected: all green; the rg returns no `alias`/`no_input`/`dialoguer`/`sshrack-cli`/`sshrack-tui` identifiers (only intentional historical prose if any).

- [ ] **Step 4: Manual end-to-end smoke**

```bash
SSHRACK_PASSPHRASE=... cargo run -q -- store use keyring
cargo run -q -- host add myhost --host 127.0.0.1 --user root   # CLI
cargo run -q --                                                 # TUI launcher
cargo run -q -- host add                                        # TUI wizard
cargo run -q -- host ls --format json                           # {"name":"myhost",...}
cargo run -q -- host rm myhost                                  # errors: pass --yes
cargo run -q -- host rm myhost --yes                            # removes
```

- [ ] **Step 5: Commit + branch finish**

```bash
git add -A && git commit -m "docs: update architecture for single-binary cli+tui routing"
```
Then use the `finishing-a-development-branch` skill to merge/PR.

---

## Self-Review (completed by planner)

- **Spec coverage:** spec §3 CLI surface — covered (Block 3 keeps it non-interactive). spec §4 identity (id + name) — Block 1. spec §5 storage/security — unchanged (Block 3 only swaps prompt source). spec §7 frecency — reused in launcher (5.3). spec §9 deferred (sftp/port-forward/config-import/2FA/print-command) — explicitly out, documented in 6.1.
- **Placeholder scan:** `todo!()` appears in 5.2/5.5 only where the implementer must wire ratatui rendering to an already-specified pure helper — acceptable (the decision logic is pinned by tests). No "TBD"/"add error handling".
- **Type consistency:** `ConnectRequest{argv, source}` consistent across 5.1/5.5/main. `rank_hosts` signature consistent 5.3/5.4. `PassphraseProvider` is `&self` (matches core). `PasswordSource` lives in `sshrack_core::credential`. `find_host_by_id` exists on Config (used in 5.5).
- **Gaps to watch at implementation:** (1) `frecency::rank` exact signature — confirm in core before writing 5.3's empty-query branch; (2) `connect::ssh::build` argv builder signature — confirm before 5.5; (3) `vault::enable` signature for `store use vault` — confirm before 5.8.
