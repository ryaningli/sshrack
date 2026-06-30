# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sshrack is a terminal-native remote server management tool written in Rust. Binary name: `sshrack`.

It wraps the system `ssh` / `scp` (it does **not** reimplement the SSH protocol) and adds a config + credential layer, plus `SSH_ASKPASS`-based password injection for password-only hosts. Keys are preferred; passwords are the fallback.

The tool has a **backend / frontend split**, like a web app:

- **Backend** (`sshrack-core`) — a pure capability layer: host/credential management, secret storage, connection, transfer, frecency. It has **zero UI dependencies** (no `dialoguer`, no `ratatui`, no `console`). This is a compiler-enforced invariant, not a convention.
- **Frontends** — thin views over the backend that hold no data path of their own:
  - `sshrack-cli` — a general-purpose, non-interactive-capable command surface. Usable by humans and by scripts/automation alike. Given all flags, it completes with **zero interaction, no TTY, no prompts**. Nothing in its help or user-facing text frames it as "for AI" — it is a normal CLI tool; `--no-input` and `--format json` are neutral capability descriptions.
  - `sshrack-tui` — a human-friendly interactive shell (**deferred**; currently an empty stub).

Both front-ends converge on the same pure functions in core. Side effects (OS keyring I/O, master-passphrase source, host-key confirmation) are **injected via traits** defined in core, so the capability layer stays testable without a TTY or a keyring daemon.

Passwords at rest use one of **three global storage modes** (the user picks one on first use, stored as `[store] mode = ...` in `config.toml`): **keyring** (recommended — OS keyring; the entry is keyed by the owning host/credential's stable ULID id, not the alias, so renaming never orphans it), **vault** (Argon2id + XChaCha20-Poly1305 encrypted inline, unlocked by a master passphrase), or **plaintext** (stored in the clear). In keyring mode the main sshrack process never holds a password's plaintext: at connect time the `SSH_ASKPASS` helper (a fork of sshrack) fetches it directly from the keyring via `SSHRACK_KEYRING_KEY`. In plaintext/vault mode the parent stages the password in a `0600` temp file the helper reads.

**Keyring lifecycle.** Removing a keyring-password host/credential deletes its keyring entry, so no orphaned secret is left behind. `host cp` copies the source's keyring entry to the copy's fresh id. `host add --force` overwriting a keyring-marked host also cleans up the old entry.

## Architecture

Cargo workspace, three crates:

```
sshrack/
├── Cargo.toml                  # [workspace] members + shared metadata
└── crates/
    ├── sshrack-core/           # BACKEND: pure capability, ZERO UI deps
    │   └── src/
    │       ├── config/         #   TOML schema + atomic load/save + path
    │       ├── connect/        #   ssh/scp argv assembly + zero-copy launcher + SSH_ASKPASS env wiring
    │       ├── secret/         #   SecretBackend/PassphraseProvider traits + keyring + vault/{crypto,cache,transform}
    │       ├── credential.rs   #   auth resolution (ref-by-id), credential CRUD pure logic
    │       ├── host.rs         #   alias validation, host CRUD pure logic
    │       ├── hostkey.rs      #   proactive host-key pre-flight (ssh-keyscan + injected confirm)
    │       ├── frecency/       #   zoxide-style scoring + machine-local persistence
    │       ├── askpass.rs      #   askpass protocol (temp-file / keyring branches)
    │       ├── id.rs           #   ULID identity helpers + keyring-key derivation
    │       ├── fsutil.rs       #   0600 atomic write helper (shared)
    │       ├── suggest.rs      #   did-you-mean fuzzy hint
    │       └── error.rs        #   SshrackError (thiserror)
    ├── sshrack-cli/            # FRONTEND 1: the `sshrack` binary
    │   └── src/
    │       ├── main.rs         #   SSH_ASKPASS role dispatch + CLI entry
    │       ├── cli.rs          #   clap derive (Cli/Command/HostAction/CredAction/StoreAction)
    │       ├── cmd/            #   connect/scp/host/cred/store handlers + shared
    │       ├── prompt.rs       #   DialoguerPassphrase + password_mode menu + --no-input confirm
    │       ├── format.rs       #   --format json|text output shapes (locked contract)
    │       └── exit_code.rs    #   stable exit codes
    └── sshrack-tui/            # FRONTEND 2: ratatui shell (DEFERRED — empty stub)
```

### Invariants

- `sshrack-core/Cargo.toml` **never** lists `dialoguer`, `ratatui`, or `console`. Adding any of them is a build failure by intent.
- Side effects are injected via traits: core defines `secret::SecretBackend` (keyring set/get/delete/available), `secret::PassphraseProvider` (passphrase/passphrase_confirm/confirm), and `hostkey::run_host_key_flow` takes a `confirm: impl FnOnce(&str) -> bool` callback. The CLI injects dialoguer-based impls (or `NoInputPassphrase` under `--no-input`); tests inject fakes.
- The shipped `sshrack` binary is a **single executable** that doubles as its own `SSH_ASKPASS` helper: `main.rs` dispatches on `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` to the askpass role, otherwise parses the CLI.
- The connect path **never sits in the ssh data stream**: `ssh`/`scp` are spawned with inherited stdio. There is no PTY pump.
- `frecency` is persisted **before** spawning ssh, so a hung ssh never loses the usage record.

## Build Commands

```bash
cargo build --workspace             # Build all crates
cargo build --release               # Production build
cargo run -p sshrack-cli -- --help  # Run the binary
cargo fmt                           # Format code
cargo clippy --workspace --all-targets -- -D warnings   # Lint (warnings as errors, incl. tests)
cargo test --workspace              # Run all tests
cargo test -p sshrack-core          # Core crate only
cargo test --test name              # Specific integration test
cargo test -- --nocapture           # Run tests with stdout visible
```

> **Important:** Rust builds are slow. Avoid unnecessary `cargo clean` — it invalidates incremental caches and forces a full rebuild. Only run it when there is a concrete reason (switching toolchains, recovering from corrupted artifacts).

## Development Constraints

### Priority: Solve the Problem First

When fixing a bug or implementing a feature, **solve the core problem before worrying about tests, clippy, or formatting**. The workflow is:

1. **Fix the problem** — make the connection work, the feature behave, the bug gone.
2. **Verify the fix** — exercise it against a real host or a local mock process, spot-check the output.
3. **Then clean up** — add/extend tests, clippy, fmt, doc comments. These are prerequisites for committing, not for solving.

Do not block on clippy or formatting while the actual issue is still unresolved.

### Hard Rules

- **English only** — all source code, comments, doc comments, error messages, help text, and log output must be in English. Commit messages follow the same rule (see Git Commit Convention).
- **Zero `unsafe`** — no unsafe blocks allowed, ever, including in tests. (Rust 2024 made `std::env::set_var` unsafe; tests must inject values via parameters/seams rather than mutate the real env.)
- **Zero `unwrap()` / `expect()`** in production code. Only permitted in `#[cfg(test)]` modules and genuinely unreachable states with `expect("invariant: ...")`.
- **TDD for pure logic** — write tests before implementation (RED → GREEN → REFACTOR) for pure-logic modules (config parsing, command assembly, credential encode/decode, alias resolution, frecency scoring). Process/PTY-dependent behavior is covered by integration tests instead.
- **Write enough tests** — unit tests for pure logic; integration tests where feasible (spawning a local mock process, exercising the connect path). There is no hard coverage gate — use judgment to cover meaningful branches and edge cases, including failure paths.
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` must pass before every commit.
- **Format** — `cargo fmt` must pass before every commit.
- **Error handling** — library errors use `thiserror`; application errors use `anyhow` with `.context()`. All fallible operations propagate errors via `?`.

### Code Style

- Rust edition 2024, MSRV 1.86.
- **Cross-platform ready, Unix first** — first period targets Linux and macOS. Gate unavoidable platform differences behind `cfg(target_os)` so Windows support can be added later without re-architecting. Do not block on Windows now.
- Domain-based module organization, not type-based.
- `&str` over `String` in function signatures; `impl Into<String>` for constructors that need ownership.
- Prefer iterators over loops for transformations.
- Default to private visibility; use `pub(crate)` for internal sharing.
- Accept `&[u8]` / `&str` at boundaries; convert to owned types only when necessary.
- **No duplicate logic** (dev-stage rule) — shared helpers belong in `fsutil` / core, not copy-pasted across modules. Staged inline copies must be removed once the canonical home lands.

### Documentation

- **Public items must have doc comments** — all `pub` and `pub(crate)` items require `///` doc comments.
- **Module-level doc comments** — every `mod` must have a `//!` doc comment explaining the module's purpose.
- **Keep doc comments concise** — one short sentence for the purpose, additional details only when the "why" is non-obvious.

## Identity & Config Model

Both `Host` and `Credential` carry a **first-class, immutable `id: Ulid`** (generated at construction via `id::new_id()`). The id feeds three things: keyring keying, frecency keying, and cross-object references. The `alias` is a human-readable, mutable, unique handle (renamable).

- **Reference by id.** `host.auth` references a credential by its ULID (`Auth::Ref { credential: Ulid }`), not by alias. **Renaming a credential never dangles a host reference.** For human readability, `host ls`/`show` reverse-resolve id→alias; on `add`/`edit` the user specifies a credential by alias and the CLI resolves it to an id before persisting.
- A `format_version` field (currently `1`) is included for future migrations.
- `CredentialBody` (user + optional secret) carries no id — the id lives on the owner.

## CLI Contract

The CLI is a general-purpose tool. Its non-interactive contract (first period):

| Capability | Behavior |
|---|---|
| `--no-input` | Missing fields do **not** prompt; the command errors and exits. Full flags ⇒ zero-interaction completion. Safe for scripts/CI. |
| `--format json` (global) | Query/management commands emit structured JSON (locked field names). Default is human-readable text. |
| Stable exit codes | `0` success; `2` usage; `4` not-found; `5` duplicate; `6` validation; `7` connect; `8` store. |

**Hard rules carried from prior pain:**

1. **clap derive parses everything** — no hand-written parse/dispatch.
2. **Patch commands touch only the named fields** — supplying a flag must not pop an interactive menu for an unspecified field.
3. **Fail-fast validation precedes interaction and network IO** — duplicate / not-found / reserved-word checks, and connection-path local checks (credential existence via `credential::resolve`), run *before* any prompt and *before* any network IO.

## Storage & Security

Three global storage modes, chosen on first use (`[store] mode`):

- **keyring** (default, recommended): plaintext never touches disk; keyring entry keyed by owner ULID.
- **vault**: Argon2id (64 MiB / t=3 / p=4) + XChaCha20-Poly1305, encrypted inline; TTL-cached master key with a verifier; `SSHRACK_PASSPHRASE` env var supplies the passphrase for scripts (shadows the TTY prompt).
- **plaintext**: clear text; file is `0600`.

**Security invariants:**

- Passwords are `Zeroizing<String>` end-to-end; never logged, printed, embedded in errors, or placed in argv / visible in `ps`.
- In keyring mode the main process never materializes a keyring password's plaintext — only the short-lived `SSH_ASKPASS` helper reads it.
- Plaintext/vault mode stage the password in a `0600` temp file (atomic `create_new`) the helper reads and deletes.
- Proactive host-key pre-flight (`ssh-keyscan` + fingerprint confirm via the injected callback); reject silent `accept-new` trust. New key confirmed once; changed key rejected (delegated to ssh at connect time, as in the predecessor).

## On-disk Layout

| File | Location | Contents | Synced across machines? |
|---|---|---|---|
| config | `~/.config/sshrack/config.toml` | store meta + hosts + credentials | yes (vault mode encrypts secrets inline) |
| frecency | `~/.local/share/sshrack/frecency.toml` | usage state (ULID → score, last_used) | **no** (machine-local) |

Single `config.toml` for store-meta + hosts + creds (one coherent, portable unit; CRUD rewrite is cheap — frecency is the only high-frequency writer and is split out). macOS paths follow the `directories` crate conventions.

## External Process & PTY Boundaries

sshrack spawns `ssh`/`scp` with **inherited stdio** and never reads or writes the data stream. Treat anything that touches the OS process tree or terminal state as an **integration concern, not pure logic**: extract the decision logic (prompt matching, command assembly, config resolution, host-key classification) into pure, unit-testable functions in core, and cover the process behavior with integration tests (the `connect_flow_test` uses a mock-ssh shim).

## Project-Specific Constraints

### Never Reimplement SSH

sshrack is an orchestration layer over the system OpenSSH. Do **not** introduce an SSH protocol library (e.g. `russh`, `ssh2`, `russh-sftp`) to reimplement the protocol layer. Spawn and drive the system `ssh` / `scp` binaries instead. SFTP-over-protocol-library is explicitly banned; future interactive SFTP transfer must use ControlMaster + the system `sftp` binary.

### Credentials Are Sensitive

- Never log, print, or embed passwords in error messages or debug output.
- Keep plaintext passwords in memory for the shortest possible lifetime; do not park them in long-lived structs.
- Code that handles passwords must respect which storage path it is on (keyring vs vault/plaintext temp-file).

## Deferred (out of first period)

- **TUI** (`sshrack-tui`): HostPicker launcher (frecency + fuzzy), host/cred/store CRUD views, which-key help, deferred-connect tear-down/restore handoff.
- **`sshrack sftp`** + dual-pane SFTP transfer (ControlMaster + `sftp -b -`, tiered progress).
- Port forwarding, `~/.ssh/config` read-only import, 2FA, `print-command` + clipboard.

The CLI scriptable-transfer moat (`sshrack scp`) and non-interactive command execution (`sshrack <alias> <cmd>`) remain first-class.

## Git Commit Convention

Follows [Conventional Commits](https://www.conventionalcommits.org/), referencing [git-cliff](https://github.com/orhun/git-cliff) conventions.

### Format

```
<type>(<scope>): <description>

<body>
```

- **type** (required): `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `style`, `build`, `ci`, `chore`
- **scope** (required): module or component name (`core`, `cli`, `config`, `secret`, `connect`, …). Commits without scope are excluded from CHANGELOG.
- **description** (required): concise English description.

### Examples

```
feat(config): add TOML host list parsing
fix(cli): handle non-English password prompts
refactor(core): extract credential resolution into its own module
chore(deps): upgrade clap to v4
```

### Breaking Changes

Append `!` to the subject or use a `BREAKING CHANGE:` footer.

### Branch Naming

```
feat/<description>
fix/<description>
refactor/<description>
```

## Version Release

When asked to release without a specific version, auto-increment PATCH (e.g. `0.1.0` → `0.1.1`).

Steps:

```bash
# 1. Update version in Cargo.toml (workspace.package.version)
vim Cargo.toml

# 2. Sync Cargo.lock
cargo check

# 3. Generate CHANGELOG (overwrites full file)
git cliff --tag v0.1.1 > CHANGELOG.md

# 4. Commit version bump
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore(release): prepare for v0.1.1"

# 5. Create annotated tag
changelog=$(git cliff --unreleased --strip all)
git tag -a v0.1.1 -m "Release v0.1.1" -m "$changelog"
```

- `git cliff --tag <version> > CHANGELOG.md`: full CHANGELOG, overwrite.
- `git cliff --unreleased --strip all`: concise summary for tag message.
- Tag format: `v<semver>` with `git tag -a` (annotated).
- `chore(release):` commits are excluded from CHANGELOG via cliff.toml skip rules.

## Dependency Policy

### Principles

- **Don't reinvent the wheel** — check crates.io before writing custom implementations.
- **Prefer established, actively maintained crates** — evaluate download counts, recent activity, issue responsiveness.
- **Minimize dependency count** — every crate is a maintenance burden.

### Adding Dependencies

Use `cargo add -p <crate>` instead of editing `Cargo.toml` directly.

```bash
cargo add serde -p sshrack-core --features derive
cargo add serde_json -p sshrack-cli
cargo add -D proptest                         # Dev dependency
```

### Evaluating a Crate

Clone to a temp directory and inspect: commit history, open issues, test coverage, MSRV, `unsafe` usage, transitive dependencies, documentation.

**Banned** for this project: SSH protocol libraries (`russh`, `ssh2`, `russh-sftp`), `age`, `ssh2-config` (keeps MSRV at 1.86 and the surface small).

## Rust Skills

Use Rust Skills for development guidance. Route via meta-cognition:

**Layer 1** (language mechanics): `m01-ownership`, `m02-resource`, `m03-mutability`, `m04-zero-cost`, `m05-type-driven`, `m06-error-handling`, `m07-concurrency`, `m10-performance`, `m11-ecosystem`, `m15-anti-pattern`.

**Layer 3** (domain constraints): `domain-cli` (primary — this is a CLI tool).
