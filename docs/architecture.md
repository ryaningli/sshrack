# Architecture

Reference: workspace layout, core invariants, the identity/config model, on-disk
layout, and external-process boundaries. Split out of `AGENTS.md` for length;
the high-frequency bits (build commands, hard constraints, routing, TUI keys)
live there. Each module also carries a `//!` doc comment — this file is the
bird's-eye view across them.

## Workspace Layout

Cargo workspace: one member crate (the pure backend) plus the root package that is the `sshrack` binary.

```text
sshrack/
├── Cargo.toml                  # [workspace] members = ["crates/sshrack-core"]; [package] = the sshrack bin
├── src/                        # FRONTEND: the `sshrack` binary (single executable)
│   ├── main.rs                 #   SSH_ASKPASS role dispatch + cli/tui routing (route_is_tui)
│   ├── cli/                    #   command surface (tty-interactive + escape hatches)
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
            ├── connect/        #   ssh/scp/sftp argv assembly + zero-copy launcher + ControlMaster mux + SSH_ASKPASS env wiring (sftp/ subdir: argv/parse/proto/source/worker)
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

## Core Invariants

- `sshrack-core/Cargo.toml` **never** lists `ratatui`, `crossterm`, `nucleo-matcher`, or `console`. UI crates are dependencies of the root package only. Adding any of them to core is a build failure by intent.
- Side effects are injected via traits: core defines `secret::SecretBackend` (keyring set/get/delete/available), `secret::PassphraseProvider` (passphrase/passphrase_confirm/confirm), and `hostkey::run_host_key_flow` takes a `confirm: impl FnOnce(&str) -> bool` callback. The TUI injects crossterm-based impls; the CLI uses a tty prompt with `SSHRACK_PASSPHRASE` as the escape hatch; tests inject fakes.
- The shipped `sshrack` binary is a **single executable** that doubles as its own `SSH_ASKPASS` helper: `main.rs` dispatches on `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` to the askpass role, otherwise parses the CLI and routes cli vs tui.
- The connect path **never sits in the ssh data stream**: `ssh`/`scp` are spawned with inherited stdio. There is no PTY pump.
- `frecency` is persisted **before** spawning ssh, so a hung ssh never loses the usage record.

## Identity & Config Model

Both `Host` and `Credential` carry a **first-class, immutable `id: Ulid`** (generated at construction via `id::new_id()`). The id feeds three things: keyring keying, frecency keying, and cross-object references. The `name` is a human-readable, mutable, unique handle (renamable).

- **Reference by id.** A host authenticates one of two ways:
  - **Reference** — `Auth::Ref { credential: Ulid }` points at a `[[credentials]]` entry by its ULID, not by name. **Renaming a credential never dangles a host reference.** For human readability, `host ls`/`show` reverse-resolve id→name; on `add`/`edit` the user specifies a credential by name and the CLI/wizard resolves it to an id before persisting.
  - **Independent** — `Auth::Inline(CredentialBody)` carries a host-own user plus an optional secret of kind None / Password / IdentityKey. The host owns its secret directly, so it works without a detour to the credential tab; the password variant is keyring-keyed by the host's ULID (`OwnerKind::Host`), so the same rename-safe and delete/`cp`/`--force` cleanup rules apply as for credentials. An IdentityKey secret is modeled by `KeySource`, which is either a file **`Path`** (a reference, delivered to `ssh -i <path>`) or pasted **`Inline`** contents; inline contents are sealed as `Secret` (Argon2id + XChaCha20-Poly1305 under vault, clear text under plaintext, **OS-keyring-stored under keyring mode** — the private key and optional certificate text live in the keyring under `<kind>:<id>#ikpriv` / `#ikcert` slots, and the body carries only an `ik.keyring = true` marker) and, at connect time, materialized to a `0600` temp file for `ssh -i` and deleted after the connection. Encrypted (passphrase-protected) private keys are not decrypted by sshrack: on a key-only connection sshrack leaves `SSH_ASKPASS` unset so OpenSSH prompts for the passphrase at the tty itself.
- Both surfaces expose the full chooser: the **TUI** host wizard cycles Auth between Reference and Independent (and, under Independent, Secret between None/Password/IdentityKey); the **CLI** exposes both via `--credential` (Reference) and `--user` / `--identity` (Independent). Inline **None** and **IdentityKey** hosts can be created either way; an inline **password** is TUI-only (passwords never enter argv — see the CLI Contract in `AGENTS.md`). Inline key *contents* reach the CLI via `--identity-stdin` / `--identity-file` (plus `--certificate-stdin` / `--certificate-file`); the path-reference source remains `--identity <path>`.
- **Host `ssh_args`** — optional raw ssh option flags (e.g. `-o ServerAliveInterval=30`), stored verbatim on the host, shell-split at connect time, appended after sshrack's own options (ssh's last-`-o`-wins makes user overrides possible). Validated at save time (no control chars, no unterminated quotes, no empty tokens). ssh and the SFTP master receive all tokens; scp receives only the `-o Key=Value` subset.
- A `format_version` field (currently `1`) is included for future migrations.
- `CredentialBody` (user + optional secret) carries no id — the id lives on the owner (the credential, or the host when inline).

## On-disk Layout

| File | Location | Contents | Synced across machines? |
|---|---|---|---|
| config | `~/.config/sshrack/config.toml` | store meta + hosts + credentials | yes (vault mode encrypts secrets inline) |
| frecency | `~/.local/share/sshrack/frecency.toml` | usage state (ULID → score, last_used) | **no** (machine-local) |

Single `config.toml` for store-meta + hosts + creds (one coherent, portable unit; CRUD rewrite is cheap — frecency is the only high-frequency writer and is split out). macOS paths follow the `directories` crate conventions.

## External Process & PTY Boundaries

sshrack spawns `ssh`/`scp` with **inherited stdio** and never reads or writes the data stream. Treat anything that touches the OS process tree or terminal state as an **integration concern, not pure logic**: extract the decision logic (prompt matching, command assembly, config resolution, host-key classification) into pure, unit-testable functions in core, and cover the process behavior with integration tests (the `connect_flow_test` uses a mock-ssh shim).
