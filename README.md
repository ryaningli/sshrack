# sshrack

> Terminal-native remote server management. A config + credential layer over system `ssh` / `scp` / `sftp`, with an interactive TUI and a scriptable CLI.

[![CI](https://github.com/ryaningli/sshrack/actions/workflows/ci.yml/badge.svg)](https://github.com/ryaningli/sshrack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust: 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/tools/install)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](#-supported-platforms)
[![Stage](https://img.shields.io/badge/stage-Alpha%20%7C%20active%20development-9cf.svg)](#-roadmap)

**English** | [简体中文](README.zh-CN.md)

![sshrack TUI demo](./assets/tui.gif)

## ✨ Features

- **Config + credential layer** — Hosts and credentials live in one TOML file. A credential is reusable across hosts, and a rename or update takes effect everywhere — no duplicated entries. Keys preferred; passwords the fallback.
- **Three storage modes** — Passwords at rest in the **OS keyring** (default), an encrypted **vault** (master-passphrase protected), or **plaintext** (`0600`). Switch any time; `store use` migrates every secret.
- **Scriptable CLI** — Every command is scriptable: `sshrack web1 df -h`, `sshrack scp ./app.tar web1:/tmp/`, `sshrack --format json host ls`. On a tty it prompts for host-key / passphrase / destructive confirms; `--accept-new`, `--yes`, and `SSHRACK_PASSPHRASE` skip the prompts, and without a tty it errors with a hint instead of hanging.
- **Interactive TUI** — A ratatui shell with Hosts / Credentials / Settings tabs, fuzzy filter, frecency-ranked list, and full add/edit wizards. Bare `sshrack` opens it.
- **SSH · SCP · SFTP** — Drives the system OpenSSH binaries (it does **not** reimplement SSH). Connect for a shell, `scp` for scripted transfer, `sftp` for a dual-pane transfer screen.
- **Secure by construction** — Passwords never enter argv / `ps`, and are never logged, printed, or shown in errors. Proactive host-key pre-flight: a new key is shown with its fingerprint and confirmed, or accepted via an explicit `--accept-new`.
- **Frecency ranking** — zoxide-style scoring surfaces the hosts you reach most. The usage record is saved *before* connecting, so a hung connection never loses it.

> sshrack is under active development (Alpha). The CLI, TUI, and SFTP transfer screen are functional; expect rough edges.

## 📦 Installation

### From crates.io (recommended)

```bash
cargo install sshrack
```

### Build from source

Prerequisites:

- [Rust](https://www.rust-lang.org/tools/install) toolchain (MSRV **1.88+**, edition 2024)
- System `ssh`, `scp`, `sftp` (OpenSSH) on `PATH`
- SFTP transfer needs OpenSSH with `ControlMaster` (default on; disabled by some hardened `ssh_config`)

```bash
git clone https://github.com/ryaningli/sshrack.git
cd sshrack
cargo build --release
# Binary: target/release/sshrack (put it on your PATH)
```

## 🚀 Usage

### CLI

```bash
sshrack web1 df -h                       # connect, run a one-off command
sshrack ssh web1                         # interactive remote shell
sshrack scp ./app.tar web1:/tmp/         # scripted file transfer
sshrack sftp web1                        # dual-pane transfer screen

sshrack host add web1 --host 10.0.0.4 --user deploy --identity ~/.ssh/id_ed25519
sshrack host ls --sort frecency          # list hosts, frecency-ordered
sshrack cred add deploy --user deploy --identity ~/.ssh/id_ed25519
sshrack --format json host ls            # JSON output for scripts
```

Per-connection overrides (`-l`/`-p`/`-i`/`-c`/`--ad-hoc`/`--accept-new`) layer over the resolved config for that one connection.

### TUI (interactive)

```bash
sshrack                                  # bare invocation opens the TUI
```

| Key | Action |
| --- | --- |
| `Tab` / `Shift-Tab` | cycle tab (Hosts / Credentials / Settings) |
| type | filter the active panel (fuzzy) |
| `↑`/`↓` | move selection |
| `Enter` | Hosts: connect · Credentials: edit · Settings: edit storage mode |
| `^a` / `^e` / `^d` | add / edit / delete (delete opens a confirm) |
| `F1` / `Esc` / `^c` | help / clear-or-close / cancel-or-quit |

On a host, `Ctrl-T` opens the SFTP transfer screen (`Tab` switches pane / direction, `Space` marks, `^s` enqueues, `^Q` manages the queue).

## ⚙️ Configuration

| File | Location | Purpose |
| --- | --- | --- |
| `config.toml` | `~/.config/sshrack/config.toml` | store meta + hosts + credentials (portable; vault mode encrypts secrets inline) |
| `frecency.toml` | `~/.local/share/sshrack/frecency.toml` | usage state (ULID → score, last_used); machine-local, never synced |

Storage mode and the full on-disk layout are covered in [`docs/architecture.md`](docs/architecture.md).

## 💻 Supported platforms

| Platform | Status |
| --- | --- |
| Linux | ✅ Supported (primary) |
| macOS | ✅ Supported (paths follow the `directories` crate) |
| Windows | ⚪ Cross-platform ready, not yet invested — platform diffs are gated behind `cfg(target_os)` so it can land without re-architecting |

## 🛠️ Development

```bash
cargo build --workspace                  # build core + the sshrack binary
cargo run -- --help                      # CLI help; bare `cargo run -q --` opens the TUI
cargo fmt                                # format
cargo clippy --workspace --all-targets -- -D warnings   # lint (warnings as errors)
cargo test --workspace                   # run all tests
```

Quality gates before every commit: `cargo fmt` green, clippy green, tests green.

CI runs the suite under a pty (`script -qec "cargo test --workspace" /dev/null`) because some TUI tests build a real terminal backend. See [`CLAUDE.md`](CLAUDE.md) for the full architecture, routing rules, and constraints.

## 🧱 Architecture

sshrack has a **strict backend/frontend split** in a single binary:

```
sshrack-core (pure backend, ZERO UI deps)        ─▶  sshrack binary (frontend)
  config · credential · secret · connect              ├─ cli/   tty-interactive + escape hatches
  hostkey · frecency · askpass · error                └─ tui/   interactive ratatui shell
   │                                                      │
   └─ side effects injected via traits                    └─ injects crossterm impls
     (SecretBackend, PassphraseProvider, host-key confirm)
                              │
                              ▼
                  system ssh / scp / sftp  (inherited stdio, no PTY pump)
```

- **`sshrack-core` is zero-UI** — its `Cargo.toml` never lists `ratatui` / `crossterm` / `nucleo-matcher` / `console`. Adding any is a build failure by intent.
- **Never reimplements SSH** — spawns and drives the system OpenSSH binaries; no SSH protocol library.
- **The binary doubles as its own `SSH_ASKPASS` helper** — `main.rs` dispatches on `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` to the askpass role.

## 🔐 Security

- Passwords never enter argv / `ps`, and are never logged, printed, or shown in errors; secrets held in memory are wiped as soon as they're used.
- The vault encrypts secrets inline with Argon2id + XChaCha20-Poly1305; the OS keyring keeps them out of the config file entirely.
- Proactive host-key pre-flight: a new key is confirmed once; a changed key is rejected.
- Plaintext/vault mode stage a password in a `0600` temp file that is deleted right after use; pasted (inline) identity keys are wiped on exit or `Ctrl-C` / `SIGTERM`.

## 🗺️ Roadmap

sshrack is being built out incrementally.

- ✅ Core config/credential/secret model + CLI + TUI shell.
- ✅ SFTP dual-pane transfer screen (ControlMaster + system `sftp`).
- ✅ Inline (pasted) identity keys across all storage modes.
- 🔜 Windows support (gated behind `cfg(target_os)`, no re-architecture needed).
- 🔜 Tagged releases with pre-built binaries.

## 📚 Documentation

- [`docs/architecture.md`](docs/architecture.md) — workspace, identity/config model, on-disk layout, process boundaries
- [`docs/tui.md`](docs/tui.md) — TUI structural design (shell / tabs / overlays / wizards)
- [`docs/sftp.md`](docs/sftp.md) — SFTP transfer design
- [`docs/dependency-policy.md`](docs/dependency-policy.md) — dependency rules + the banned-dependency list
- [`docs/migration.md`](docs/migration.md) · [`docs/release.md`](docs/release.md) — migration notes + release runbook

## 🤝 Contributing

Contributions are welcome. Please read [`CLAUDE.md`](CLAUDE.md) first — it covers the architecture, routing rules, code style, and the quality gates every change must pass. For larger work, open an issue to discuss the direction first.

## 🤖 Authorship

This project is developed with AI.

## 📄 License

[MIT](LICENSE) © ryaningli
