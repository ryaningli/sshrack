# CLAUDE.md

Guidance for Claude Code working in this repo. **Long-form reference lives in `docs/`** (read on demand — not auto-loaded into context); this file keeps only high-frequency, non-obvious essentials.

**Reference index:**
- Architecture · invariants · identity/config model · on-disk layout · PTY boundaries → [`docs/architecture.md`](docs/architecture.md)
- TUI structural design (shell/tabs/overlays/wizards/file picker) → [`docs/tui.md`](docs/tui.md)
- SFTP transfer design → [`docs/sftp.md`](docs/sftp.md)
- Migration from `sshrack-old` → [`docs/migration.md`](docs/migration.md)
- Release runbook → [`docs/release.md`](docs/release.md)
- Dependency policy · Rust-skills routing → [`docs/dependency-policy.md`](docs/dependency-policy.md)

## Project Overview

sshrack is a terminal-native remote server management tool written in Rust (binary `sshrack`). It wraps the system `ssh`/`scp`/`sftp` (it does **not** reimplement SSH) and adds a config + credential layer plus `SSH_ASKPASS`-based password injection. Keys preferred; passwords the fallback.

**Backend/frontend split** in a single binary:
- **Backend** (`sshrack-core`, sole workspace member) — pure capability layer with **zero UI deps** (no `ratatui`/`crossterm`/`nucleo-matcher`/`console`). Compiler-enforced invariant.
- **CLI** (`src/cli/`) — defaults to interactive on a tty; per-scenario escape hatches (`--accept-new`, `--yes`, `SSHRACK_PASSPHRASE`) keep every command scriptable.
- **TUI** (`src/tui/`) — interactive shell (ratatui 0.30 + crossterm + nucleo-matcher).

Side effects (keyring I/O, passphrase source, host-key confirm) are **injected via traits** defined in core. Passwords at rest use one of three global modes (`[store] mode`): **keyring** (default, OS keyring, keyed by owner ULID), **vault** (Argon2id + XChaCha20-Poly1305 inline), or **plaintext** (`0600`).

## Build Commands

```bash
cargo build --workspace             # Build core + the sshrack binary
cargo build --release               # Production build
cargo run -- --help                 # CLI help; bare `cargo run -q --` opens the TUI
cargo fmt                           # Format code
cargo clippy --workspace --all-targets -- -D warnings   # Lint (warnings as errors, incl. tests)
cargo test --workspace              # Run all tests
cargo test -p sshrack-core          # Core crate only
cargo test --test name              # Specific integration test
cargo test -- --nocapture           # Run tests with stdout visible
```

> **Important:** Rust builds are slow. Avoid unnecessary `cargo clean` — it invalidates incremental caches and forces a full rebuild. Only run it when there is a concrete reason (switching toolchains, recovering from corrupted artifacts).

## Routing Rule (CLI vs TUI)

`src/main.rs` dispatches on the parsed subcommand:

| Invocation | Routes to |
|---|---|
| `sshrack` (bare) | TUI launcher |
| `sshrack host add` (no flags, no name) | TUI host-add wizard |
| `sshrack host edit <name>` (no edit flags) | TUI host-edit wizard |
| `sshrack cred add` (no flags, no name) | TUI cred-add wizard |
| `sshrack cred edit <name>` (no edit flags) | TUI cred-edit wizard |
| anything else | CLI (interactive on a tty) |

A flagged field is **always a CLI patch, never a wizard** — `host edit x --port 22` is the CLI; `host edit x` is the wizard. A name positional alone on `host add x` is the CLI (which then errors: missing `--host`); only a truly flag-less `host add` opens the wizard.

## TUI Keys

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | cycle tab (Hosts / Credentials / Settings) |
| type | filter the active panel's search box (`⌫` deletes; bare letters/digits never act as hotkeys — they reach the query) |
| `↑`/`↓` or `^n`/`^p` | move selection |
| `Enter` | Hosts: connect · Credentials: edit · Settings: edit the storage-mode row |
| `^a` / `^e` / `^d` | add / edit / delete (current tab; delete opens a confirm) |
| `F1` | help overlay (also closes it) |
| `Esc` | clear query / close overlay / quit (from launcher) |
| `^c` | cancel active overlay · quit (from launcher) |

Bare `c`, `?`, `1`/`2`/`3` always reach the search box (never act as hotkeys). Old `c`/`Shift-C`/`F2`/`?` bindings are gone — use `Ctrl-A`/`Ctrl-S`/`F1`.

## SFTP Transfer Keys

| Key | Action |
|---|---|
| `Tab` | switch pane (focus = direction: local→upload, remote→download) |
| `Space` | listing: mark entry (current-dir scope, single-shot per enqueue) · find: append to the query (find has no marking) |
| `^s` | enqueue marked/selected (dirs recurse via `get -R`/`put -R`) — the advertised trigger |
| `^Q` | open the queue-manager overlay (retry / remove / cancel / pause) |
| `Enter` | on a file: enqueue · on a directory: enter (never transfers) |
| `Esc` | cancel in-flight transfer / close |
| `^c` | close |

`Ctrl-Enter` collapses to a bare `Enter` on many terminals, so it is only a hidden alias. Entry: `sshrack sftp <name>` or `Ctrl-T` on a host. Full SFTP architecture → [`docs/sftp.md`](docs/sftp.md).

The pane filter box is path-aware: a plain name fuzzy-filters the current directory; any `/` triggers a drill find where intermediate segments match directory names **exactly** and only the final segment fuzzy-matches within the resolved directory (a trailing `/` lists that directory's contents).

## Development Constraints

### Priority: Solve the Problem First

When fixing a bug or implementing a feature, **solve the core problem before worrying about tests, clippy, or formatting**:

1. **Fix the problem** — make it work / behave / the bug gone.
2. **Verify the fix** — exercise against a real host or a local mock process.
3. **Then clean up** — tests, clippy, fmt, doc comments. These are prerequisites for committing, not for solving.

Do not block on clippy or formatting while the actual issue is still unresolved.

### Hard Rules

- **English only** — all source, comments, doc comments, errors, help text, log output, and commit messages.
- **Zero `unsafe`** — never, including tests. (Rust 2024 made `std::env::set_var` unsafe; tests inject via params/seams — hermetic discipline in Testing.)
- **Zero `unwrap()` / `expect()`** in production — only `#[cfg(test)]` or genuinely unreachable states with `expect("invariant: ...")`.
- **TDD for pure logic** — RED → GREEN → REFACTOR (which modules, and the integration boundary, are listed in Testing).
- **Write enough tests** — no hard coverage gate; use judgment to cover meaningful branches and failure paths (see Testing for which layer to pick).
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Error handling** — library errors use `thiserror`; application errors use `anyhow` with `.context()`. All fallible ops propagate via `?`.

### Testing

**Match the layer to the bug** — use the lightest layer that reaches the failure:

| Layer | Locks | Use for |
|---|---|---|
| Unit, TDD (pure logic) | input → output | core: config parse, command assembly, credential encode/decode, name resolution, frecency |
| `on_key` + state assert | a state field after a key sequence | state / index / selection / mode bugs — lightest, no rendering |
| TestBackend + `insta` snapshot | one rendered frame | layout / truncation / highlight regressions |
| `on_key` chain → draw → `insta` | a frame after a key sequence | interaction flows (key → state → picture) |
| Integration (mock-ssh shim) | real `ssh`/`scp`/`sftp` argv + env | connect/transfer process behavior; password-never-in-argv |

`on_key` covers the **logic core, not the I/O boundary**. `App::on_key` is a pure state machine and `draw` is pure render — for a logic bug it equals real use; for a decode / raw-mode / event-loop / side-effect bug it cannot see the failure. Feed `KeyEvent`s that match the keymap's own definitions (same enum in test and prod): the silent risk is a false green from a path no real terminal produces.

**Hermetic by default.** `cargo test --workspace` with no env vars must pass; tests never mutate the real environment (inject via params / traits / tempfiles); fix dynamic output (timestamps, ULIDs) at the input, not after.

**Snapshots.** Seed the baseline once with `INSTA_UPDATE=always cargo test <name>`; commit the `.snap`, never the `.snap.new`. Accept intentional changes via `cargo insta review`.

**CI runs tests under a pty:** the test step is `script -qec "cargo test --workspace" /dev/null`. `stdout_tui` (src/tui/test_support.rs) builds a real `CrosstermBackend` whose `Terminal::new` probes the tty, and CI's pipe-bound stdout returns `EAGAIN` without the wrapper — keep `script -qec` and its `-e` (cargo exit-code propagation) when editing the workflow. Those `stdout_tui`-backed tests are borrow-regression pins, not a template: new TUI tests use `TestBackend` / `on_key`, not real terminals.

### Code Style

- Rust edition 2024, MSRV 1.88.
- **Cross-platform ready, Unix first** — target Linux/macOS now; gate platform diffs behind `cfg(target_os)` so Windows can be added later without re-architecting. Do not block on Windows now.
- Domain-based module organization, not type-based.
- `&str` over `String` in signatures; `impl Into<String>` for constructors needing ownership.
- Prefer iterators over loops for transformations.
- Default to private visibility; use `pub(crate)` for internal sharing.
- Accept `&[u8]` / `&str` at boundaries; convert to owned only when necessary.
- **No duplicate logic** (dev-stage rule) — shared helpers belong in `fsutil` / core, not copy-pasted. Staged inline copies must be removed once the canonical home lands.

### Documentation

- **Public items need doc comments** — all `pub`/`pub(crate)` items require `///`.
- **Module-level doc comments** — every `mod` has a `//!` explaining its purpose.
- **Keep doc comments concise** — one short sentence; detail only when the "why" is non-obvious.

## Core Invariants

- **`sshrack-core` is zero-UI** — its `Cargo.toml` never lists `ratatui`/`crossterm`/`nucleo-matcher`/`console`. Adding any is a build failure by intent.
- **Side effects injected via traits** — `secret::SecretBackend`, `secret::PassphraseProvider`, `hostkey::run_host_key_flow` takes a `confirm` callback. TUI/CLI/tests inject impls.
- **Single binary doubles as its own `SSH_ASKPASS` helper** — `main.rs` dispatches on `SSHRACK_ASKPASS_FILE`/`SSHRACK_KEYRING_KEY`.
- **Connect path never sits in the ssh data stream** — `ssh`/`scp`/`sftp` spawned with inherited stdio; no PTY pump.
- **Frecency persisted before spawning ssh** — a hung ssh never loses the usage record.

Full detail (workspace tree, identity/config model, on-disk layout, PTY boundaries) → [`docs/architecture.md`](docs/architecture.md).

## Identity & Config Model (essentials)

Hosts and credentials reference each other by **immutable ULID `id`**, not by name — **renaming a credential never dangles a host reference.** `host ls`/`show` reverse-resolve id→name; `add`/`edit` take a name and resolve it to an id before persisting. A host's `Auth` is either `Ref { credential: Ulid }` or `Inline(CredentialBody)` (host-own user + optional secret). Full model (KeySource Path/Inline, `format_version`, etc.) → [`docs/architecture.md`](docs/architecture.md).

## CLI Contract

The CLI defaults to interactive when a TTY is present — it prompts for host-key confirmation, vault passphrase, and destructive-action confirmation. Non-interactive escape hatches (`--accept-new`, `--yes`, `SSHRACK_PASSPHRASE`) are always available and take precedence over the prompt. Without a TTY, the CLI falls back to the escape hatch or errors with a hint — it never hangs.

| Capability | Behavior |
|---|---|
| Interactive on a tty | Prompts for host-key / passphrase / destructive confirm. No `--no-input` flag — escape hatches are per-scenario, not a global toggle. Missing required *config* flags still error + exit `2`/`6`. |
| `--accept-new` | Skip the host-key confirm prompt: accept a first-seen key (global + per-subcommand). |
| `--yes` (destructive) | Skip the destructive-confirm prompt for `host rm`, `cred rm`, `store use plaintext` (required when there is no tty). |
| `--format json` (global) | Structured JSON output (locked field names); default is text. |
| `SSHRACK_PASSPHRASE` (env) | Vault passphrase escape hatch (`store use vault`, `store rekey`); without it on a tty, the CLI prompts. |
| `--identity-stdin`/`--identity-file` (+ `--certificate-*`) | Import identity-key/certificate **contents** as a sealed `Secret`, never in argv. `--identity <path>` is the unread path reference. Inline key renders as `"<inline>"`; key text never displayed. |
| Stable exit codes | `0` ok · `2` usage · `4` not-found · `5` duplicate · `6` validation · `7` connect · `8` store. |

**Hard rules carried from prior pain:**

1. **clap derive parses everything** — no hand-written parse/dispatch.
2. **Patch commands touch only named fields** — a flag must not pop an interactive menu for an unspecified field (patch-vs-wizard enforced by `route_is_tui`).
3. **Fail-fast validation precedes network IO** — duplicate/not-found/reserved-word + connection-path local checks (credential existence via `credential::resolve`) run *before* any network IO.
4. **Passwords and key text never enter argv** — an inline (host-own) password is TUI-only; inline key contents reach sshrack only via stdin / a named file, never an argv value visible in `ps`.

## Security Essentials

- Passwords are `Zeroizing<String>` end-to-end; never logged, printed, in errors, or in argv/`ps`.
- In keyring mode the main process never materializes a keyring password's plaintext — only the short-lived `SSH_ASKPASS` helper reads it.
- Plaintext/vault mode stage the password in a `0600` temp file (atomic `create_new`) the helper reads and deletes.
- Keyring lifecycle: removing a keyring-marked host/cred **deletes its keyring entry** (no orphans); `host cp` copies the entry to the new id; `host add --force` cleans up the old entry.
- Proactive host-key pre-flight (`ssh-keyscan` + fingerprint confirm via the injected callback): a new key is shown with its fingerprint and confirmed once on a tty; `--accept-new` skips the prompt; a changed key is rejected (delegated to ssh at connect time).
- Keep plaintext passwords in memory for the shortest possible lifetime; respect which storage path code is on (keyring vs vault/plaintext temp-file).

## Never Reimplement SSH

sshrack is an orchestration layer over system OpenSSH. Do **not** introduce an SSH protocol library (`russh`, `ssh2`, `russh-sftp`) to reimplement the protocol. Spawn and drive the system `ssh`/`scp`/`sftp` binaries. SFTP-over-protocol-library is banned; interactive SFTP uses ControlMaster + the system `sftp` binary.

## On-disk Layout

| File | Location | Contents | Synced? |
|---|---|---|---|
| config | `~/.config/sshrack/config.toml` | store meta + hosts + credentials | yes (vault encrypts secrets inline) |
| frecency | `~/.local/share/sshrack/frecency.toml` | usage state (ULID → score, last_used) | **no** (machine-local) |

Single `config.toml` for store-meta + hosts + creds (one portable unit; CRUD rewrite is cheap — frecency is the only high-frequency writer and is split out). macOS paths follow the `directories` crate.

## Banned Dependencies

SSH protocol libraries (`russh`, `ssh2`, `russh-sftp`), `age`, `ssh2-config` (keeps MSRV 1.88 and the surface small). Full policy + crate-evaluation checklist → [`docs/dependency-policy.md`](docs/dependency-policy.md).

## Git Commit Convention

Conventional Commits ([git-cliff](https://github.com/orhun/git-cliff) conventions). **No `Co-Authored-By` trailer.**

```
<type>(<scope>): <description>
```

- **type** (required): `feat`, `fix`, `refactor`, `perf`, `docs`, `test`, `style`, `build`, `ci`, `chore`.
- **scope** (required): module/component (`core`, `cli`, `config`, `secret`, `connect`, …). Commits without scope are excluded from CHANGELOG.
- **description** (required): concise English.
- **Breaking:** append `!` to the subject or add a `BREAKING CHANGE:` footer.

Branches: `feat/<desc>` · `fix/<desc>` · `refactor/<desc>`. Release steps → [`docs/release.md`](docs/release.md).
