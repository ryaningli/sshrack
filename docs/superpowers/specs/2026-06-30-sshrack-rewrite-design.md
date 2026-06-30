# sshrack Rewrite — Design Spec

> Date: 2026-06-30
> Status: Approved design (brainstorming output). Implementation plan follows separately.
> Predecessor: `sshrack-old` (sound backend, messy planning). Reference: `sshelf` v0.9.0 (borrow the essence, not the code).

---

## 1. Vision

sshrack is a terminal-native remote-server management tool: host management, credential
management, SSH connection, and file transfer. It replicates what tools like XShell / Termius
do, in two front-ends over one capability core:

- **CLI** — a general-purpose, non-interactive-capable command surface. Usable by humans and by
  scripts/agents alike. The distinguishing trait is that, given all flags, it completes with
  **zero interaction, no TTY, no prompts**. It is a normal CLI tool; nothing in its help or
  user-facing text frames it as "for AI".
- **TUI** — a human-friendly interactive shell (deferred; see §9). Modern, direct, ergonomic.

The guiding mental model is **backend / frontend separation**: the backend is a pure capability
layer (host/cred/connect/transfer/store/secret); the front-ends are *views* over it and hold no
data path of their own. Both entries converge on the same pure functions.

It wraps the system `ssh` / `scp` — it does **not** reimplement the SSH protocol. No protocol
library (`russh`, `ssh2`, `russh-sftp`) is permitted.

## 2. Architecture: Cargo Workspace

Physical separation enforced by the compiler. The backend crate **cannot** depend on any UI
library — that is a hard, machine-checked invariant, not a convention.

```
sshrack/                       # workspace root
├── Cargo.toml                 # [workspace] members
├── crates/
│   ├── sshrack-core/          # BACKEND: pure capability layer, ZERO UI deps
│   │   ├── config/            #   TOML schema + atomic load/save
│   │   ├── id/                #   Ulid identity helpers (host + cred)
│   │   ├── credential/        #   auth resolution, cred CRUD logic (pure)
│   │   ├── host/              #   name resolution, host CRUD logic (pure)
│   │   ├── secret/            #   store mode + trait SecretBackend / PassphraseProvider
│   │   │   ├── keyring.rs      #     OS keyring I/O (behind the trait)
│   │   │   └── vault/         #     argon2id + xchacha20poly1305 (ported), TTL cache + verifier
│   │   ├── connect/           #   ssh argv assembly + zero-copy launcher + SSH_ASKPASS wiring
│   │   ├── transfer/          #   scp argv assembly (scriptable transfer)
│   │   ├── hostkey/           #   proactive host-key pre-flight (ssh-keyscan + confirm callback)
│   │   ├── frecency/          #   zoxide-style scoring + machine-local persistence
│   │   └── askpass/           #   askpass protocol logic
│   ├── sshrack-cli/           # FRONTEND 1: clap derive, --no-input, --format json
│   │   └── main.rs            #   also hosts the SSH_ASKPASS role dispatch (single binary)
│   └── sshrack-tui/           # FRONTEND 2: ratatui (DEFERRED — empty shell first期 if built at all)
└── docs/
```

### 2.1 Invariants

- `sshrack-core/Cargo.toml` **never** lists `dialoguer`, `ratatui`, or `console`. The compiler
  guarantees backend purity.
- Side effects are **injected via traits**. Core defines `SecretBackend`, `PassphraseProvider`,
  and a host-key confirmation callback. The CLI injects non-interactive / env / error
  implementations; the TUI will later inject dialog-based implementations.
- The shipped binary is a **single executable**: `sshrack` doubles as its own `SSH_ASKPASS`
  helper (ssh forks `SSH_ASKPASS`, which points back at sshrack). Role dispatch lives in the CLI
  crate's `main.rs`; the askpass *protocol* logic lives in core.

## 3. CLI Command Surface (first期)

Verb-noun grouping, all parsed with **clap derive** (no hand-written parse/dispatch — see §6).

```
sshrack <name> [cmd...]          # connect / run remote command (bare name)
sshrack ssh <name> [cmd...]      # explicit connect
sshrack scp <src> <dst>           # scriptable transfer (name:path expansion)

sshrack host  add|ls|show|edit|rm|cp     # host CRUD
sshrack cred  add|ls|show|edit|rm        # credential CRUD
sshrack store status|use|rekey|lock|unlock|config   # storage mode
```

Deferred to the TUI phase: `sshrack sftp` (interactive/batch SFTP browsing).

### 3.1 Non-interactive contract (first期)

| Capability | Behavior |
|---|---|
| `--no-input` | Missing fields do **not** prompt; the command errors and exits. Full flags ⇒ zero-interaction completion. Safe for scripts/CI. |
| `--format json` (global) | Query/management commands emit structured JSON (with error codes). Default is human-readable tables. |
| Stable exit codes | `0` success; distinct non-zero codes for not-found / duplicate / validation-failure / connection-failure. |

### 3.2 `host ls` sorting (frecency透出)

`host ls --sort frecency|name|recent` surfaces the backend frecency capability even without a
TUI. Default sort order is configurable.

### 3.3 Hard rules carried over from prior pain (memory)

1. **clap derive parses everything** — no hand-written parse/dispatch (a hand-rolled dispatch
   once broke `rm -y`).
2. **Patch commands touch only the named fields** — supplying a flag must not pop an interactive
   menu for an unspecified field (a `--port` patch once wrongly triggered the password menu).
3. **Fail-fast validation precedes interaction and network IO** — duplicate / not-found /
   reserved-word checks, and connection-path local checks (credential existence via
   `credential::resolve`), run *before* any prompt and *before* any network IO (an unreachable
   address once masked a dangling-credential error).

## 4. Identity & Config Schema

Both host and credential carry a **first-class, immutable `id: Ulid`**, generated at creation.
This corrects sshrack-old, where the id existed only to key the keyring. The id now feeds three
things: keyring keying, frecency keying, and cross-object references. The `name` is a
human-readable, mutable, unique handle (renamable).

`host.auth` references a credential **by id** (immutable; rename never breaks the link). For
human readability, `ls`/`show` resolve and display the name; on `add`/`edit` the user specifies
a credential by name and the CLI resolves it to an id before persisting (an interaction-layer
nicety that does not affect the on-disk form).

```toml
[store]
mode = "keyring"                # or "vault" (+ KDF fields) or "plaintext"

[[credentials]]
id = "01J8X...ULID"             # first-class immutable identity
name = "team-deploy"            # mutable unique handle
user = "deploy"
key = "~/.ssh/team_ed25519"

[[hosts]]
id = "01J8Y...ULID"             # first-class immutable identity (keyring + frecency + refs)
name = "web-prod"
host = "10.0.1.5"
port = 22
auth = { credential = "01J8X...ULID" }   # reference by cred id — never dangles on rename
```

A `format_version` field (borrowed from sshelf) is included to enable future migrations without
breaking old installs.

## 5. Storage & Security Model

Three global storage modes, chosen on first use, stored as `[store] mode`:

| Mode | On disk | Main process holds plaintext? | Password path at connect |
|---|---|---|---|
| **keyring** (default, recommended) | config holds only a `keyring = true` marker; the keyring entry is keyed by the body's stable ULID | **Never** | the `SSH_ASKPASS` helper reads the keyring directly via `SSHRACK_KEYRING_KEY` |
| **vault** | argon2id + xchacha20poly1305 encrypted inline; TTL cache + verifier | briefly (after decrypt) | parent stages a `0600` temp file the helper reads |
| **plaintext** | clear text (`chmod 600`) | yes | same `0600` temp file path |

**Keyring lifecycle:** ULID keying (rename never orphans); `rm` deletes the keyring entry (no
orphan); `host cp` copies the source entry to the copy's fresh id (warns if unavailable).

**Security invariants (ported; required by CLAUDE.md):**
- Passwords are `Zeroizing<String>` end-to-end; never logged, printed, embedded in errors, or
  placed in argv / visible in `ps`.
- In keyring mode the main process never materializes a keyring password's plaintext.
- Temp files use atomic `create_new` + `0600`.
- Proactive host-key pre-flight (`ssh-keyscan` + fingerprint confirm); reject silent
  `accept-new` trust. New key confirmed once; changed key rejected; unattended unknown key
  refused.

## 6. Porting Map (sshrack-old → sshrack-core)

Port the verified backend, refactoring interfaces/naming as it lands; rewrite the front-ends.

| Item | Source | Refactor action |
|---|---|---|
| vault crypto (argon2 + xchacha) | `vault/crypto.rs` | near-verbatim, pure |
| vault cache (TTL + verifier) | `vault/cache.rs` | retain |
| keyring I/O | `keyring.rs` | converge behind `trait SecretBackend` |
| askpass protocol | `askpass.rs` | protocol → core; role dispatch → cli main |
| zero-copy launcher | `connect.rs` | verbatim (stdio inherited) |
| ssh / scp argv assembly | `cmd/ssh.rs`, `cmd/scp.rs` | pure functions, verbatim |
| config schema + atomic write | `config/` | retain schema; add `format_version`; add first-class id; ref-by-id |
| credential / host resolve + CRUD pure logic | `credential.rs`, `host.rs`, `cmd/*` | decision functions → core; dialoguer interaction stays in cli |
| hostkey pre-flight | `hostkey.rs` | wrap as `run_host_key_flow(confirm: impl Fn)`; inject callback |
| id-preservation hack on edit | `host/edit.rs`, `cred/edit.rs` | lift to pure `finalize_body(orig_id, new_body)` |
| rm keyring cleanup | `host/rm.rs`, `cred/rm.rs` | extract `delete_*_with_secret` (marker → pure remove → keyring delete) |

**Trait seams to extract (root cause: two un-abstracted side effects):**

```text
trait PassphraseProvider { fn get(&mut self, meta: &VaultMeta) -> Result<VaultKey>; }
trait SecretBackend {
    fn keyring_set(&mut self, owner, id, pw: &str) -> Result<()>;
    fn keyring_get(&self, key: &str) -> Result<Option<Zeroizing<String>>>;
    fn keyring_delete(&mut self, owner, id) -> Result<()>;
    fn keyring_available(&self) -> bool;
}
```

## 7. Frecency (first期, backend capability)

frecency = **frequency + recency** scoring (Firefox / zoxide lineage). It ranks objects so the
most-likely-wanted float to the top: frequently-used *and* recently-used win.

- Algorithm: zoxide 4-tier multiplier on a base score (used <1h ×4, <1d ×2, <1w ÷2, else ÷4).
  Pure `rank(items, query, frecency) -> Vec<Ranked>`, unit-testable.
- Keyed by **ULID** (rename never loses history), consistent with keyring keying.
- Recorded on successful connect; **persisted before** spawning ssh (so a hung ssh never loses
  the record).
- Stored at `~/.local/share/sshrack/frecency.toml`, **separate** from config (machine-local,
  high write frequency, must NOT sync across machines), atomic write.
- First期 surface: `host ls --sort frecency`. Primary consumer (the TUI launcher) comes later;
  the backend capability ships now.

## 8. On-disk Layout

| File | Location | Contents | Synced across machines? |
|---|---|---|---|
| config | `~/.config/sshrack/config.toml` | store meta + hosts + credentials | yes (vault mode encrypts secrets inline) |
| frecency | `~/.local/share/sshrack/frecency.toml` | usage state (ULID → score, last_used) | **no** (machine-local) |

Single `config.toml` for store-meta + hosts + creds (one coherent, portable configuration unit;
host inventory is a few KB, CRUD rewrite is cheap). frecency is split out because it is the only
high-frequency writer and must never follow a cross-machine sync. macOS path follows
`directories` conventions.

## 9. Scope: Deferred to the TUI Phase

- **TUI** (ratatui): HostPicker launcher (frecency + nucleo fuzzy), host/cred/store CRUD views,
  which-key help, deferred-connect tear-down/restore handoff.
- **`sshrack sftp`** + dual-pane SFTP transfer (ControlMaster + `sftp -b -`, tiered progress).
- Port forwarding, `~/.ssh/config` read-only import, 2FA, `print-command` + clipboard.

These are explicitly out of first期 scope. The CLI scriptable-transfer moat (`sshrack scp`) and
non-interactive command execution (`sshrack <name> <cmd>`) remain first-class and untouched.

## 10. Testing Strategy

Per the CLAUDE.md TDD hard rule:

- **Pure-logic TDD (RED → GREEN → REFACTOR):** crypto, argv assembly, credential/host resolve,
  id generation & ref resolution, frecency `rank()`, config parse, JSON output serialization.
- **Integration tests:** spawn a local mock process for connect/scp paths, askpass role, keyring
  I/O, host-key pre-flight.
- **Tests must be hermetic:** `cargo test` must pass green in a real shell with env vars (e.g.
  `SSHRACK_PASSPHRASE`) already set. No `env -u` fallback.
- Per-crate tests are independent; workspace `cargo test` green is a commit gate.

## 11. Dependencies

Keep lean. Reuse the prior crate set: clap, serde, toml, thiserror, anyhow, directories,
zeroize, ulid, argon2, chacha20poly1305, getrandom, base64, keyring (platform-conditional),
dialoguer/console (cli crate only), tracing. **Do not** add `age` or `ssh2-config` (keeps MSRV
1.86 and the dependency surface small). ratatui and fuzzy/which-key crates arrive with the TUI
phase, in the tui crate only.

## 12. Implementation Slices (suggested order)

Each slice obeys the hard rules (pure-logic TDD, clippy `-D warnings`, fmt, English, no
`unsafe`/`unwrap`, `Zeroizing` passwords). Each non-trivial slice may get its own plan.

1. **Workspace skeleton** — `[workspace]` + three crate stubs; `sshrack-core` with zero UI deps;
   cli `main.rs` builds and prints help.
2. **Config + identity** — schema with first-class ULID + ref-by-id + `format_version`; atomic
   load/save; pure CRUD logic. TDD.
3. **Secret layer** — port vault crypto + cache; extract `SecretBackend` / `PassphraseProvider`
   traits; keyring impl behind the trait.
4. **askpass + connect** — port askpass protocol (core) + role dispatch (cli main); zero-copy
   launcher; ssh/scp argv assembly; host-key pre-flight with injected confirm.
5. **CLI command surface** — clap derive for `<name>`/`ssh`/`scp`/`host`/`cred`/`store`;
   `--no-input`, `--format json`, stable exit codes; dialoguer interaction in cli only.
6. **frecency** — `rank()` + machine-local persistence; `host ls --sort frecency`.
7. **Test pass + polish** — integration coverage, clippy, fmt, docs.

Then a separate TUI phase (see §9), starting from the trait seams already in place.
