# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sshrack is a terminal-native remote server management tool written in Rust. Binary name: `sshrack`.

It wraps the system `ssh` / `scp` (it does **not** reimplement the SSH protocol) and adds a config + credential layer, plus `SSH_ASKPASS`-based password injection for password-only hosts. Keys are preferred; passwords are the fallback.

The tool has a **backend / frontend split**, like a web app, delivered as a single root binary `sshrack`:

- **Backend** (`sshrack-core`, the sole workspace member crate) — a pure capability layer: host/credential management, secret storage, connection, transfer, frecency. It has **zero UI dependencies** (no `ratatui`, no `crossterm`, no `nucleo-matcher`, no `console`). This is a compiler-enforced invariant, not a convention.
- **Frontends** — both live inside the root binary (`src/`), as thin views over the backend that hold no data path of their own:
  - `src/cli/` — a **non-interactive** command surface. The CLI **never** prompts: given all flags it completes with zero interaction, no TTY. Missing required flags error out. Usable by humans and by scripts/CI alike.
  - `src/tui/` — a human-friendly interactive shell (ratatui 0.30 + crossterm + nucleo-matcher): launcher with frecency + fuzzy filter, host/credential add-edit wizards, store-mode switch view, connect orchestration, help overlay, consolidated status bar.

Both front-ends converge on the same pure functions in core. Side effects (OS keyring I/O, master-passphrase source, host-key confirmation) are **injected via traits** defined in core, so the capability layer stays testable without a TTY or a keyring daemon.

**Single-binary routing.** `src/main.rs` dispatches on the parsed subcommand: a bare `sshrack`, or `host`/`cred` `add`/`edit` carrying **no content flags**, routes to the TUI; everything else — connect shorthand, `ssh`/`scp`, `host`/`cred` `ls`/`show`/`rm`/`cp`, `store`, and any `add`/`edit` that carries a flag (a flagged field is always a CLI patch, never a wizard) — runs the non-interactive CLI. `--help`/`--version` and usage errors stay owned by clap.

Passwords at rest use one of **three global storage modes** (the user picks one on first use, stored as `[store] mode = ...` in `config.toml`): **keyring** (recommended — OS keyring; the entry is keyed by the owning host/credential's stable ULID id, not the name, so renaming never orphans it), **vault** (Argon2id + XChaCha20-Poly1305 encrypted inline, unlocked by a master passphrase), or **plaintext** (stored in the clear). In keyring mode the main sshrack process never holds a password's plaintext: at connect time the `SSH_ASKPASS` helper (a fork of sshrack) fetches it directly from the keyring via `SSHRACK_KEYRING_KEY`. In plaintext/vault mode the parent stages the password in a `0600` temp file the helper reads.

**Keyring lifecycle.** Removing a keyring-password host/credential deletes its keyring entry, so no orphaned secret is left behind. `host cp` copies the source's keyring entry to the copy's fresh id. `host add --force` overwriting a keyring-marked host also cleans up the old entry.

## Architecture

Cargo workspace: one member crate (the pure backend) plus the root package that is the `sshrack` binary.

```
sshrack/
├── Cargo.toml                  # [workspace] members = ["crates/sshrack-core"]; [package] = the sshrack bin
├── src/                        # FRONTEND: the `sshrack` binary (single executable)
│   ├── main.rs                 #   SSH_ASKPASS role dispatch + cli/tui routing (route_is_tui)
│   ├── cli/                    #   NON-INTERACTIVE command surface (never prompts)
│   │   ├── args.rs             #     clap derive (Cli/Command/HostAction/CredAction/StoreAction)
│   │   ├── table.rs            #     text table rendering for ls/show
│   │   └── mod.rs              #     cmd handlers (connect/scp/host/cred/store) + run()
│   ├── tui/                    #   INTERACTIVE ratatui shell (three-band shell + tabs + overlays)
│   │   ├── shell.rs            #     three-band renderer (brand+tabs / panel area / hotkey footer)
│   │   ├── tab.rs              #     Tab enum (Hosts/Credentials/Settings) + tab_key_decision
│   │   ├── panel.rs            #     shared rank_by_name helper (frecency + nucleo fuzzy)
│   │   ├── launcher.rs         #     Hosts panel: frecency-tiered host list + fuzzy filter + search box
│   │   ├── cred_panel.rs       #     Credentials panel (same shape, no secrets rendered)
│   │   ├── settings.rs         #     Settings panel: storage-mode row + picker overlay driver
│   │   ├── dialog.rs           #     overlay chrome (titled border + hotkey footer → body Rect)
│   │   ├── wizard.rs           #     host add/edit + credential add/edit wizards (draw_in_dialog)
│   │   ├── store.rs            #     store-mode switch view (keyring/vault/plaintext) in a dialog
│   │   ├── connect.rs          #     ConnectRequest orchestration + delayed exec handoff
│   │   ├── prompt.rs           #     TUI PassphraseProvider impl (crossterm-based)
│   │   ├── popup.rs            #     centered popup renderer (used by prompt.rs confirm dialogs)
│   │   ├── theme.rs            #     design tokens (accent, gutter, brand) — the single color surface
│   │   ├── help.rs             #     F1 help dialog (draw_help_dialog + keymap reference)
│   │   ├── app.rs              #     App state machine + on_key (pure) + draw
│   │   ├── intent.rs           #     pure intent/state types: Outcome / Overlay / Status
│   │   ├── term.rs             #     RAII terminal ownership: TerminalGuard / TerminalHandle / Tui
│   │   ├── persist.rs          #     persist_* side-effects (host/cred CRUD, store switch) called by the loop
│   │   ├── run_loop.rs         #     blocking event loop: poll keys → on_key → dispatch Outcome
│   │   ├── test_support.rs     #     #[cfg(test)] shared App/press helpers for app/persist/run_loop tests
│   │   └── mod.rs              #     re-exports + run() entry
│   └── shared/
│       ├── format.rs           #     --format json|text output shapes (locked contract)
│       ├── exit_code.rs        #     stable exit codes
│       └── mod.rs
└── crates/
    └── sshrack-core/           # BACKEND: pure capability, ZERO UI deps (the only workspace member)
        └── src/
            ├── config/         #   TOML schema + atomic load/save + path
            ├── connect/        #   ssh/scp argv assembly + zero-copy launcher + SSH_ASKPASS env wiring
            ├── secret/         #   SecretBackend/PassphraseProvider traits + keyring + vault/{crypto,cache,transform}
            ├── credential.rs   #   auth resolution (ref-by-id), credential CRUD pure logic
            ├── host.rs         #   name validation, host CRUD pure logic
            ├── hostkey.rs      #   proactive host-key pre-flight (ssh-keyscan + injected confirm)
            ├── frecency/       #   zoxide-style scoring + machine-local persistence
            ├── askpass.rs      #   askpass protocol (temp-file / keyring branches)
            ├── id.rs           #   ULID identity helpers + keyring-key derivation
            ├── fsutil.rs       #   0600 atomic write helper (shared)
            ├── suggest.rs      #   did-you-mean fuzzy hint
            └── error.rs        #   SshrackError (thiserror)
```

### Routing rule (the contract)

| Invocation | Routes to |
|---|---|
| `sshrack` (bare) | TUI launcher |
| `sshrack host add` (no flags, no name) | TUI host-add wizard |
| `sshrack host edit <name>` (no edit flags) | TUI host-edit wizard |
| `sshrack cred add` (no flags, no name) | TUI cred-add wizard |
| `sshrack cred edit <name>` (no edit flags) | TUI cred-edit wizard |
| anything else | CLI (non-interactive) |

A flagged field is **always** a CLI patch, never a wizard — `host edit x --port 22` is the CLI; `host edit x` is the wizard. A name positional alone on `host add x` is the CLI (which then errors: missing `--host`); only a truly flag-less `host add` opens the wizard.

### TUI keys

| Key | Action |
|---|---|
| `Tab` / `Shift-Tab` | cycle tab (Hosts / Credentials / Settings) |
| type | filter the active panel's search box (`⌫` deletes; bare letters/digits never act as hotkeys — they reach the query) |
| `↑`/`↓` or `^n`/`^p` | move selection |
| `Enter` | Hosts: connect · Credentials: edit · Settings: edit the storage-mode row |
| `^a` / `^e` / `^d` | add / edit / delete (current tab; delete opens a confirm) |
| `F1` | help overlay (also closes it) |
| `Esc` | clear query / close overlay / quit (from launcher) |
| `^c` | quit |

The single-char conflict fix: bare `c`, `?`, and `1`/`2`/`3` always reach the active panel's search box (never act as hotkeys). The old `c` add-credential, `Shift-C`/`F2` store-mode switch, and `?` help bindings are gone — use `Ctrl-A`/`Ctrl-S`/`F1` instead.

### Invariants

- `sshrack-core/Cargo.toml` **never** lists `ratatui`, `crossterm`, `nucleo-matcher`, or `console`. UI crates are dependencies of the root package only. Adding any of them to core is a build failure by intent.
- Side effects are injected via traits: core defines `secret::SecretBackend` (keyring set/get/delete/available), `secret::PassphraseProvider` (passphrase/passphrase_confirm/confirm), and `hostkey::run_host_key_flow` takes a `confirm: impl FnOnce(&str) -> bool` callback. The TUI injects crossterm-based impls; the CLI reads the vault passphrase from `SSHRACK_PASSPHRASE` (no prompt); tests inject fakes.
- The shipped `sshrack` binary is a **single executable** that doubles as its own `SSH_ASKPASS` helper: `main.rs` dispatches on `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` to the askpass role, otherwise parses the CLI and routes cli vs tui.
- The connect path **never sits in the ssh data stream**: `ssh`/`scp` are spawned with inherited stdio. There is no PTY pump.
- `frecency` is persisted **before** spawning ssh, so a hung ssh never loses the usage record.

## Build Commands

```bash
cargo build --workspace             # Build core + the sshrack binary
cargo build --release               # Production build
cargo run -- --help                 # Run the binary (CLI help); bare `cargo run -q --` opens the TUI
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
- **TDD for pure logic** — write tests before implementation (RED → GREEN → REFACTOR) for pure-logic modules (config parsing, command assembly, credential encode/decode, name resolution, frecency scoring). Process/PTY-dependent behavior is covered by integration tests instead.
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

Both `Host` and `Credential` carry a **first-class, immutable `id: Ulid`** (generated at construction via `id::new_id()`). The id feeds three things: keyring keying, frecency keying, and cross-object references. The `name` is a human-readable, mutable, unique handle (renamable).

- **Reference by id.** A host authenticates one of two ways:
  - **Reference** — `Auth::Ref { credential: Ulid }` points at a `[[credentials]]` entry by its ULID, not by name. **Renaming a credential never dangles a host reference.** For human readability, `host ls`/`show` reverse-resolve id→name; on `add`/`edit` the user specifies a credential by name and the CLI/wizard resolves it to an id before persisting.
  - **Independent** — `Auth::Inline(CredentialBody)` carries a host-own user plus an optional secret of kind None / Password / IdentityKey. The host owns its secret directly, so it works without a detour to the credential tab; the password variant is keyring-keyed by the host's ULID (`OwnerKind::Host`), so the same rename-safe and delete/`cp`/`--force` cleanup rules apply as for credentials. An IdentityKey secret is modeled by `KeySource`, which is either a file **`Path`** (a reference, delivered to `ssh -i <path>`) or pasted **`Inline`** contents; inline contents are sealed as `Secret` (Argon2id + XChaCha20-Poly1305 under vault, clear text under plaintext — **keyring mode rejects them at validation time**) and, at connect time, materialized to a `0600` temp file for `ssh -i` and deleted after the connection. Encrypted (passphrase-protected) private keys are not decrypted by sshrack: on a key-only connection sshrack leaves `SSH_ASKPASS` unset so OpenSSH prompts for the passphrase at the tty itself.
- Both surfaces expose the full chooser: the **TUI** host wizard cycles Auth between Reference and Independent (and, under Independent, Secret between None/Password/IdentityKey); the **CLI** exposes both via `--credential` (Reference) and `--user` / `--identity` (Independent). Inline **None** and **IdentityKey** hosts can be created either way; an inline **password** is TUI-only (passwords never enter argv — see CLI Contract). Inline key *contents* reach the CLI via `--identity-stdin` / `--identity-file` (plus `--certificate-stdin` / `--certificate-file`); the path-reference source remains `--identity <path>`.
- A `format_version` field (currently `1`) is included for future migrations.
- `CredentialBody` (user + optional secret) carries no id — the id lives on the owner (the credential, or the host when inline).

## CLI Contract

The CLI (`src/cli/`) is **always non-interactive** — it never prompts. Anything that needs input the CLI cannot supply (a password, a master passphrase, a destructive confirmation, an interactive host/cred edit) is either rejected with an error or sourced from the environment, never from a TTY. Interactive flows live in the TUI.

| Capability | Behavior |
|---|---|
| Non-interactive by construction | No `--no-input` flag exists. Missing required flags ⇒ error + exit `2`/`6`. Safe for scripts/CI by default. |
| `--accept-new` | Accept a host key seen for the first time (like ssh's `accept-new`). Available globally and per-subcommand. |
| `--yes` (destructive) | Required for `host rm`, `cred rm`, and `store use plaintext` (the plaintext downgrade wipes/seals secrets). Without it the command errors. Interactive confirm lives in the TUI. |
| `--format json` (global) | Query/management commands emit structured JSON (locked field names). Default is human-readable text. |
| `SSHRACK_PASSPHRASE` (env) | Supplies the vault master passphrase on the CLI path (e.g. `store use vault`, `store rekey`). There is no CLI passphrase prompt — set the env var or use the TUI. |
| `--identity-stdin` / `--identity-file` (and `--certificate-stdin` / `--certificate-file`) | Import identity-key (and certificate) **contents** — the bytes are read from stdin or a file and stored as a sealed `Secret`, never placed in argv. `--identity <path>` remains the path-reference source (the file is not read). Available on `cred add`/`edit` and `host add`/`edit` under Independent-IdentityKey. `ls`/`show` render an inline key as `"<inline>"` in both text and `--format json` (the existing `identity` field is overloaded for this — there is no separate `identity_source` field); the key text itself is never displayed. |
| Stable exit codes | `0` success; `2` usage; `4` not-found; `5` duplicate; `6` validation; `7` connect; `8` store. |

**Hard rules carried from prior pain:**

1. **clap derive parses everything** — no hand-written parse/dispatch.
2. **Patch commands touch only the named fields** — supplying a flag must not pop an interactive menu for an unspecified field (the patch-vs-wizard line is enforced by `route_is_tui`).
3. **Fail-fast validation precedes network IO** — duplicate / not-found / reserved-word checks, and connection-path local checks (credential existence via `credential::resolve`), run *before* any network IO. (There is no interaction to precede — the CLI does not prompt.)
4. **Passwords and key text never enter argv** — neither a credential password nor an inline (host-own) password can be created from the CLI; use the TUI for that. The CLI can still create Independent-None and Independent-IdentityKey hosts via `--user` / `--identity` (path reference) or `--identity-stdin` / `--identity-file` (pasted contents). Inline key contents reach sshrack only through stdin / a named file, never through an argv value that would be visible in `ps`.

## Storage & Security

Three global storage modes, chosen on first use (`[store] mode`):

> On TUI startup, if no store mode is chosen and the OS keyring is available, sshrack adopts keyring silently; otherwise the mode stays undecided and the first password save prompts.

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

## TUI (delivered)

The interactive shell (`src/tui/`) is delivered as a **three-band shell + tabs + overlays**:

- **Shell (`shell.rs`):** a three-band layout — top band is the brand word + tab bar; the middle band is the active panel's area (each panel renders its own one-line status row at the bottom of this band); the bottom band is hotkey hints, always shown. `draw_shell` returns the middle `Rect` for the panel to render into.
- **Tabs (`tab.rs` + `Tab` enum):** Hosts / Credentials / Settings, default Hosts. `Tab`/`Shift-Tab` cycle. The active tab is the only routing state (`App::active_tab`); the old full-screen `Mode` enum is gone.
- **Panels:** Hosts panel (`launcher.rs`, frecency-tiered host list + nucleo fuzzy filter + search box), Credentials panel (`cred_panel.rs`, same shape, no secrets rendered), Settings panel (`settings.rs`, storage-mode row).
- **Overlays (`Overlay` enum, at most one open at a time):** host add/edit wizard, credential add/edit wizard, store-mode picker, and the F1 help reference are all **dialogs** (`dialog.rs` chrome: titled bordered area + hotkey footer, no dark scrim) layered on top of the shell — not full-screen modes. Dialogs size to their content and scroll to keep the focused field (and, for Help, every binding row) visible on small terminals. `Esc`/`Ctrl-C` inside an overlay closes it; the shell keeps rendering behind it.
- **Host wizard auth:** the Auth row cycles `Independent ↔ Reference` with `←`/`→`. Under Reference a dedicated **Credential** row appears; `Enter` there opens a fuzzy credential-picker overlay (type to filter, `↑`/`↓` to move, `Enter` to select, `Esc` to cancel) — replacing the old in-place `Shift-←/→` cycle so a host can reuse a credential even when dozens exist. Under Independent the `Secret` row cycles `None / Password / IdentityKey` as before.
- **Event routing (split across `app`/`intent`/`persist`/`run_loop`/`term`):** `App::on_key` (in `app.rs`) returns a pure-intent `Outcome` (`SwitchTab` / `OpenOverlay` / `CloseOverlay` / `SaveHost` / `DeleteHost` / `ConnectRequested` / `Quit` / …) declared in `intent.rs`; `run_loop.rs` drives the blocking loop and applies the I/O via the free functions in `persist.rs` (host/cred CRUD, keyring cleanup, store switch) and `connect::connect_host` (confirm popups via `TuiPassphrase`, connect orchestration with delayed exec — the terminal owned by `term.rs`'s `TerminalGuard` is restored before `ssh` inherits it). Each panel surfaces a one-line status row at the bottom of its own area; the status is a transient per-action hint that auto-clears on the next panel keypress.

It is reached by a bare `sshrack`, or by `host`/`cred` `add`/`edit` with no content flags. CLI entry (`host add`, `cred add`, etc.) routes straight to the matching tab + overlay.

## Later phase (still deferred)

- **`sshrack sftp`** + dual-pane SFTP transfer (ControlMaster + `sftp -b -`, tiered progress).
- Port forwarding, `~/.ssh/config` read-only import, 2FA, `print-command` + clipboard.

The CLI scriptable-transfer moat (`sshrack scp`) and non-interactive command execution (`sshrack <name> <cmd>`) remain first-class.

## Breaking Changes (vs. the predecessor `sshrack-old`)

Recorded for migration; this project is pre-1.0 and carries no compat shim (per the dev-stage rule).

- **Identifier rename `alias` → `name`.** JSON output keys `alias`→`name` and `credential_alias`→`credential_name`; TOML key `alias`→`name` in hosts and credentials. `--credential` accepts a name.
- **`--no-input` removed.** The CLI is non-interactive by construction; there is no flag to toggle. Missing required flags now error directly.
- **`host rm` / `cred rm` require `--yes`.** Plain-text store downgrade (`store use plaintext`) also requires `--yes`.
- **`store use vault` / `store rekey` are env-only on the CLI path.** The vault passphrase must come from `SSHRACK_PASSPHRASE`; there is no CLI passphrase prompt. Use the TUI for an interactive prompt.
- **Workspace collapsed to one member crate.** `sshrack-cli` and `sshrack-tui` no longer exist as separate crates — their sources moved into the root `src/{cli,tui,shared}` of the single `sshrack` binary. Only `sshrack-core` remains as a workspace member.

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
cargo add serde_json -p sshrack               # the root binary package
cargo add -D proptest                         # Dev dependency
```

### Evaluating a Crate

Clone to a temp directory and inspect: commit history, open issues, test coverage, MSRV, `unsafe` usage, transitive dependencies, documentation.

**Banned** for this project: SSH protocol libraries (`russh`, `ssh2`, `russh-sftp`), `age`, `ssh2-config` (keeps MSRV at 1.86 and the surface small).

## Rust Skills

Use Rust Skills for development guidance. Route via meta-cognition:

**Layer 1** (language mechanics): `m01-ownership`, `m02-resource`, `m03-mutability`, `m04-zero-cost`, `m05-type-driven`, `m06-error-handling`, `m07-concurrency`, `m10-performance`, `m11-ecosystem`, `m15-anti-pattern`.

**Layer 3** (domain constraints): `domain-cli` (primary — this is a CLI tool).
