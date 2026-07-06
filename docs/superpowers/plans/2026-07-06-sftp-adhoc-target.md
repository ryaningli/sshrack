# SFTP `--ad-hoc` Target Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task gets a fresh implementer subagent + a reviewer subagent.

**Goal:** Make `sshrack --ad-hoc -c <cred> sftp <address>` (and the `--user`/`--port`/`--identity` overrides) open the SFTP transfer screen for an unsaved host — mirroring exactly what `sshrack ssh`/`scp` already do via `host::resolve_target`.

**Architecture:** Today the `sshrack sftp` entry resolves the positional as a saved name only (`cfg.find_host_by_name`), ignoring the subcommand's `ConnectOptions` (`--ad-hoc`/`-c`/`--user`/`--port`/`--identity`); `open_transfer` then re-looks-up the host by id (`cfg.find_host_by_id`), which an ad-hoc host is never in the config. Fix in two steps: (1) refactor the transfer-open path to carry a resolved `Host` end-to-end instead of a `Ulid` (no behavior change); (2) at the entry, resolve the target with `host::resolve_target` + the merged `ConnectOptions` — the same call `cli/cmd/connect.rs` makes — so an ad-hoc literal becomes an ephemeral `Host` that flows straight into `open_transfer`.

**Tech Stack:** Rust 2024, MSRV 1.86, clap (already parses `Command::Sftp { opts, name }` with `ConnectOptions`), sshrack-core `host::resolve_target` (already implemented + tested).

## Global Constraints (from CLAUDE.md — verbatim values every task inherits)

- **English only** — all source, comments, doc comments, errors, help text, log output, and commits.
- **Zero `unsafe`** — never, including tests. Tests inject via params/seams, never mutate `std::env`.
- **Zero `unwrap()`/`expect()`** in production — only `#[cfg(test)]` or `expect("invariant: ...")`.
- **No duplicate logic** (dev-stage rule) — reuse `host::resolve_target`; do NOT re-roll ad-hoc construction in the TUI.
- **Validate before network/prompts** — credential-name→id resolution and the ad-hoc-needs-identity check must run BEFORE the alternate screen / any popup.
- **`sshrack-core` zero-UI invariant** — this plan never touches `crates/sshrack-core/`. All work is in `src/tui/` + `docs/`.
- **Tests are hermetic** — `cargo test` green with `SSHRACK_PASSPHRASE` set in the real shell; no `env -u`.
- **Clippy strict** — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- **Format** — `cargo fmt` green before every commit.
- **Commit style:** `<type>(<scope>): <desc>` (Conventional Commits, English). **No `Co-Authored-By` trailer.** Use explicit `git add <paths>` — **never `git add -A`** (it pulls in unrelated untracked files).

**Scope invariant:** All production work is in `src/tui/{app.rs, mod.rs, run_loop.rs, transfer/open.rs}`. No new dependencies. No CLI/args changes (the flags already exist and parse). `--accept-new` is explicitly OUT OF SCOPE — host-key confirmation stays the interactive TUI popup (`host_key_confirm`), identical to the launcher `Ctrl-T` path; an sftp session is interactive anyway.

---

## File Structure (target — all existing files)

```
src/tui/
├── app.rs              # pending_transfer field: Option<Ulid> → Option<Host> (renamed pending_transfer_host);
│                       #   Ctrl-T stashes h.clone(); test accessor returns the id
├── mod.rs              # resolve_transfer_target() — NEW pure helper (Task 2); entry wiring in run()
├── run_loop.rs         # both open_transfer call sites pass Host (not Ulid)
└── transfer/
    └── open.rs         # open_transfer(host: Host, …) — drop the find_host_by_id re-lookup
docs/sftp.md            # Entry section: note --ad-hoc support
```

No new files. No `src/cli/` changes. No `crates/sshrack-core/` changes.

---

## Inventory (the contract this plan must satisfy — verified by reading the code)

- `Command::Sftp { opts: ConnectOptions, name: String }` — `src/cli/args.rs:179-186`. `ConnectOptions` already carries `ad_hoc`, `credential` (`-c`), `user` (`-l`), `port` (`-p`), `identity` (`-i`), `accept_new`. `opts.overlay(&cli.connect_opts)` merges subcommand-level over top-level (`args.rs:69-79`). **No change needed here.**
- `host::resolve_target(cfg, target, &ResolveOverrides) -> Result<Host, SshrackError>` — `crates/sshrack-core/src/host.rs:192-215`. Decision table: name hit → entry (credential override applies); name miss + `ad_hoc` → ephemeral `Host { name: address, host: address, … }` via `ad_hoc_host` (fresh id); name miss + `!ad_hoc` → `HostNotFound`. Ad-hoc without `--credential`/`--user` → `MissingRequiredField`. **Already implemented + heavily tested (host.rs:810-891). Reuse as-is.**
- Current sftp entry resolution — `src/tui/mod.rs:156-164` — matches only `EntryMode::Transfer { name }` and calls `cfg.find_host_by_name(name)`; **ignores `opts` entirely.** This is the gap.
- `open_transfer(host_id: Ulid, …)` — `src/tui/transfer/open.rs:73` — re-looks-up via `cfg.find_host_by_id(&host_id)` (open.rs:82-91). An ad-hoc host has no config entry → would `HostNotFound`. Second gap.
- `App::pending_transfer: Option<Ulid>` — `src/tui/app.rs:132`. Set at `app.rs:622` (Ctrl-T, `h.id`) and `mod.rs:175` (entry). Read + cleared at `run_loop.rs:104` (first tick) and `run_loop.rs:377` (Ctrl-T arm).
- The reference connect path — `src/cli/cmd/connect.rs:85-115` — resolves `--credential` name→id FIRST (fail-fast), then builds `ResolveOverrides` and calls `host::resolve_target`. Task 2 mirrors this exact sequence in the TUI.

---

## Task 1: Carry a resolved `Host` through the transfer-open path (refactor — NO behavior change)

**Why first, alone:** the type migration touches 4 files and only stays green when all pieces move together; isolating it from the feature gives the reviewer a zero-behavior-change diff. After this task `open_transfer` consumes a `Host` directly and the entry still resolves a saved name (ad-hoc lands in Task 2).

**Files:**
- Modify: `src/tui/app.rs:13,132,188,528-534,622,2543,2561,2579,2595,2609`
- Modify: `src/tui/mod.rs:156-164,174-176`
- Modify: `src/tui/run_loop.rs:104-105,377-381`
- Modify: `src/tui/transfer/open.rs:28,37,44,46-72(near 51),73-93,195`

**Interfaces:**
- Produces: `pub fn open_transfer(host: Host, app: &mut App, handle: TerminalHandle, _data_dir: Option<&Path>) -> Result<(), SshrackError>` (was `host_id: Ulid`).
- Produces: `App::pending_transfer_host: Option<Host>` (was `pending_transfer: Option<Ulid>`); test accessor `pending_transfer_id() -> Option<Ulid>`.

- [ ] **Step 1: `src/tui/app.rs` — field type + imports + Ctrl-T write site**

At line 13, widen the schema import so production code can name `Host`:

```rust
use sshrack_core::config::schema::{Host, SshrackConfig};
```

At lines 131-132, rename the field and change its type (keep the doc above it; extend it):

```rust
    /// [`super::transfer::open::open_transfer`]. Mirrors `pending_connect`.
    /// Holds the resolved `Host` (a saved host from the launcher, or an ad-hoc
    /// host built at the `sshrack sftp` entry) — `open_transfer` consumes it
    /// directly, no id→host re-lookup.
    pub(super) pending_transfer_host: Option<Host>,
```

At line 188 (the `App::new` initializer list), rename:

```rust
            pending_transfer_host: None,
```

At line 622 (the Ctrl-T handler), stash the whole host instead of just its id:

```rust
                self.pending_transfer_host = Some(h.clone());
```

- [ ] **Step 2: `src/tui/app.rs` — test accessor returns the id**

At lines 528-534, rename the accessor and derive the id from the stashed `Host` (keeps the 6 existing test call-sites reading an id, not a `Host`):

```rust
    /// The id of the pending-transfer host set by `Ctrl-T` on the launcher (or
    /// the `sshrack sftp` entry). The loop reads (and clears) the field to run
    /// `open_transfer`. Returns the id — not the `Host` — so existing tests that
    /// drive the open intent keep reading an id.
    #[cfg(test)]
    pub fn pending_transfer_id(&self) -> Option<Ulid> {
        self.pending_transfer_host.as_ref().map(|h| h.id)
    }
```

- [ ] **Step 3: `src/tui/app.rs` — update the 5 test call-sites**

At lines 2543, 2561, 2579, 2595, 2609, rename the method call `app.pending_transfer()` → `app.pending_transfer_id()`. (Bodies unchanged — they already compare against a `Ulid` / call `.is_none()`.)

- [ ] **Step 4: `src/tui/mod.rs` — entry produces a `Host` (still named-only, no ad-hoc yet)**

At lines 156-164, the entry-resolution block clones the resolved `Host` instead of taking its id:

```rust
    let entry_mode = entry_mode_from_cmd(cli.cmd.as_ref());
    let pending_transfer_host = match &entry_mode {
        EntryMode::Transfer { name } => {
            let host = cfg
                .find_host_by_name(name)
                .ok_or_else(|| host::host_not_found(&cfg, name))?;
            Some(host.clone())
        }
        _ => None,
    };
```

At lines 174-176, stash the `Host`:

```rust
    if let Some(h) = pending_transfer_host {
        app.pending_transfer_host = Some(h);
    }
```

- [ ] **Step 5: `src/tui/run_loop.rs` — both drain sites pass a `Host`**

At lines 104-105 (first-tick drain):

```rust
            if let Some(host) = app.pending_transfer_host.take() {
                match open_transfer(host, app, handle.clone(), data_dir) {
```

At lines 377-381 (the `Outcome::OpenTransfer` arm):

```rust
                    let Some(host) = app.pending_transfer_host.take() else {
                        // No host: defensive — Ctrl-T hit no host.
                        continue;
                    };
                    match open_transfer(host, app, handle.clone(), data_dir) {
```

- [ ] **Step 6: `src/tui/transfer/open.rs` — signature takes `Host`, drop the id re-lookup**

At line 28, widen the schema import:

```rust
use sshrack_core::config::schema::{Host, SshrackConfig};
```

At line 37, DELETE the now-unused production import (production no longer names `Ulid` after this task; the test module re-imports it in Step 8):

```rust
use ulid::Ulid;
```

At line 44, DELETE the now-unused import (it was only used by the `find_host_by_id` error being removed):

```rust
use sshrack_core::error::DidYouMean;
```

Update the doc-comment step list. Find the line under the `open_transfer` doc that reads (near line 51):

```rust
/// 1. Look up the host by id (no name to resolve — the launcher picked it).
```

Replace it with:

```rust
/// 1. Carry the resolved `host` — the caller (launcher `Ctrl-T`, or the
///    `sshrack sftp` entry) already resolved the target (a saved name OR an
///    ad-hoc literal built by `host::resolve_target`), so there is no id→host
///    re-lookup here. An ad-hoc host is never in the config.
```

Change the signature + Step-1 body (lines 73-93) to consume the passed `Host`:

```rust
pub fn open_transfer(
    host: Host,
    app: &mut App,
    handle: TerminalHandle,
    _data_dir: Option<&Path>,
) -> Result<(), SshrackError> {
    let cfg: &SshrackConfig = app.config();

    // ── Step 1: Carry the resolved host. The caller already resolved it (saved
    // name or ad-hoc literal), so there is no id→host lookup to redo. `port`
    // is read before `host` moves into `resolved_host` (used by the host-key
    // flow below). ─────────────────────────────────────────────────────────────
    let port = host.port;
    let resolved_host = host;
```

(Leave everything below — Steps 2-7, the `remote_title` call, the `SftpWorker::open` spawn, the screen seed — unchanged. `resolved_host` is still the binding later code moves into `SftpWorker::open`.)

- [ ] **Step 7: `src/tui/transfer/open.rs` — test module re-imports `Ulid`**

At line 195 (the test module's `use super::*;`), the deletion in Step 6 stops `Ulid` reaching the tests. Add it explicitly inside the test module, right after `use super::*;`:

```rust
    use super::*;
    use ulid::Ulid;
```

- [ ] **Step 8: Build + test + clippy + fmt**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
```
Expected: build green (the `Host`/`Ulid`/`DidYouMean` import moves resolve cleanly); all tests pass (behavior unchanged — the Ctrl-T tests now read `pending_transfer_id()`); clippy clean.

- [ ] **Step 9: Commit**

```bash
git add src/tui/app.rs src/tui/mod.rs src/tui/run_loop.rs src/tui/transfer/open.rs
git commit -m "refactor(tui): carry a resolved Host through the sftp transfer-open path"
```

---

## Task 2: Resolve ad-hoc targets at the `sshrack sftp` entry (the feature)

**Files:**
- Modify: `src/tui/mod.rs:19,22-24(near),156-164,174-176` (imports + new helper + wiring) and the test module
- Modify: `docs/sftp.md:14`

**Interfaces:**
- Consumes: `App::pending_transfer_host: Option<Host>` and `open_transfer(host: Host, …)` from Task 1.
- Consumes: `host::resolve_target` + `host::ResolveOverrides` + `credential::credential_not_found` (all in sshrack-core).
- Produces: `fn resolve_transfer_target(cmd: Option<&Command>, cfg: &SshrackConfig, top: &ConnectOptions) -> Result<Option<Host>, SshrackError>` (private, pure).

- [ ] **Step 1: Write the failing tests (RED)**

In `src/tui/mod.rs`, inside the existing `#[cfg(test)] mod tests` (after the `sftp_maps_to_transfer_entry_mode_on_hosts_tab` test near line 405), add a new test group. The test module already has `use super::*;` and `use crate::cli::args::{Command, CredAction, HostAction};`; extend the latter and add the schema + ulid imports these tests need:

```rust
    use crate::cli::args::{Command, ConnectOptions, CredAction, HostAction};
    use sshrack_core::config::schema::{Auth, CredentialBody, SshrackConfig};
    use ulid::Ulid;
```

(If `CredAction`/`HostAction` are unused after, keep them — other tests in the module use them.) Then append these tests:

```rust
    // ---- resolve_transfer_target: the `sshrack sftp` entry honors --ad-hoc
    // and the per-connection overrides exactly like the ssh/scp connect path
    // (host::resolve_target). Pure; no terminal, no I/O. ----

    fn named_host_cfg() -> SshrackConfig {
        // One saved host named "web1"; an address like "10.0.0.4" is NOT a name.
        SshrackConfig {
            hosts: vec![Host {
                id: Ulid::new(),
                name: "web1".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                auth: Auth::inline(CredentialBody::new("u")),
            }],
            ..Default::default()
        }
    }

    fn sftp_cmd(name: &str, opts: ConnectOptions) -> Command {
        Command::Sftp {
            opts,
            name: name.into(),
        }
    }

    #[test]
    fn resolve_transfer_target_none_for_non_sftp() {
        // A bare `sshrack` (no subcommand) has no sftp target to resolve.
        let cfg = SshrackConfig::default();
        assert!(resolve_transfer_target(None, &cfg, &ConnectOptions::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_transfer_target_named_host_returns_the_entry() {
        // `sshrack sftp web1` (no overrides) resolves to the saved host as-is.
        let cfg = named_host_cfg();
        let host = resolve_transfer_target(
            Some(&sftp_cmd("web1", ConnectOptions::default())),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap()
        .expect("named host resolves");
        assert_eq!(host.name, "web1");
        assert_eq!(host.host, "10.0.0.5");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn resolve_transfer_target_ad_hoc_with_credential_builds_ephemeral_ref() {
        // `sshrack --ad-hoc -c yushi sftp 192.168.20.18`: address is not a name;
        // --ad-hoc builds an ephemeral host whose auth references the credential.
        let cfg = named_host_cfg(); // "192.168.20.18" is not a name here
        // Inject a saved credential named "yushi" so -c resolves to its id.
        let mut cfg = cfg;
        let cred_id = Ulid::new();
        cfg.credentials.push(sshrack_core::config::schema::Credential {
            id: cred_id,
            name: "yushi".into(),
            body: CredentialBody::new("deploy"),
        });
        let top = ConnectOptions {
            ad_hoc: true,
            credential: Some("yushi".into()),
            ..Default::default()
        };
        let host = resolve_transfer_target(Some(&sftp_cmd("192.168.20.18", top.clone())), &cfg, &top)
            .unwrap()
            .expect("ad-hoc resolves");
        assert_eq!(host.host, "192.168.20.18");
        assert_eq!(host.port, 22);
        assert_eq!(host.auth.credential_id(), Some(cred_id));
    }

    #[test]
    fn resolve_transfer_target_ad_hoc_with_user_builds_inline_body() {
        // `sshrack --ad-hoc --user ryan -p 2222 sftp host.example`: ad-hoc inline
        // user (+ optional port) builds an ephemeral inline-auth host.
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions {
            ad_hoc: true,
            user: Some("ryan".into()),
            port: Some(2222),
            ..Default::default()
        };
        let host = resolve_transfer_target(Some(&sftp_cmd("host.example", opts.clone())), &cfg, &opts)
            .unwrap()
            .expect("ad-hoc resolves");
        assert_eq!(host.host, "host.example");
        assert_eq!(host.port, 2222);
        let body = host.auth.inline_body().expect("inline auth");
        assert_eq!(body.user, "ryan");
    }

    #[test]
    fn resolve_transfer_target_ad_hoc_without_identity_errors() {
        // `--ad-hoc` with neither --credential nor --user cannot log in; fail
        // fast (MissingRequiredField) before the alternate screen.
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions {
            ad_hoc: true,
            ..Default::default()
        };
        let err = resolve_transfer_target(Some(&sftp_cmd("10.0.0.4", opts)), &cfg, &ConnectOptions::default())
            .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::MissingRequiredField { .. }
        ));
    }

    #[test]
    fn resolve_transfer_target_dangling_credential_errors() {
        // `-c nope` naming an unknown credential must fail fast (credential not
        // found), NOT fall through to ad-hoc / host-not-found.
        let cfg = SshrackConfig::default();
        let opts = ConnectOptions {
            credential: Some("nope".into()),
            ..Default::default()
        };
        let err = resolve_transfer_target(Some(&sftp_cmd("web1", opts)), &cfg, &ConnectOptions::default())
            .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::CredentialNotFound { .. }
        ));
    }

    #[test]
    fn resolve_transfer_target_named_miss_without_ad_hoc_is_host_not_found() {
        // `sshrack sftp ghost` (no --ad-hoc): unknown name → HostNotFound (the
        // existing pre-Task-2 behavior preserved).
        let cfg = named_host_cfg();
        let err = resolve_transfer_target(
            Some(&sftp_cmd("ghost", ConnectOptions::default())),
            &cfg,
            &ConnectOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            sshrack_core::error::SshrackError::HostNotFound { ref name, .. } if name == "ghost"
        ));
    }

    #[test]
    fn resolve_transfer_target_overlays_top_level_opts() {
        // Top-level flags (`sshrack --ad-hoc ...`) merge with subcommand flags —
        // either level opting into --ad-hoc is enough. Mirrors ConnectOptions::overlay.
        let cfg = SshrackConfig::default();
        let top = ConnectOptions {
            ad_hoc: true,
            user: Some("ryan".into()),
            ..Default::default()
        };
        // Subcommand opts empty; top-level carries --ad-hoc + --user.
        let host = resolve_transfer_target(
            Some(&sftp_cmd("host.example", ConnectOptions::default())),
            &cfg,
            &top,
        )
        .unwrap()
        .expect("top-level --ad-hoc applies");
        assert_eq!(host.host, "host.example");
        assert_eq!(host.auth.inline_body().unwrap().user, "ryan");
    }
```

- [ ] **Step 2: Run — expect RED (helper absent)**

```bash
cargo test -p sshrack --lib tui::tests::resolve_transfer_target 2>&1 | head -30
```
Expected: fails to compile — `cannot find function resolve_transfer_target` (and `Host` may be unresolved in production scope until Step 3).

- [ ] **Step 3: Implement the pure helper (GREEN)**

In `src/tui/mod.rs`, first widen the module-level imports. Line 19 becomes:

```rust
use crate::cli::args::{Command, ConnectOptions, CredAction, HostAction};
```

Line 22-24 (the schema + error region) becomes:

```rust
use sshrack_core::config::schema::{Host, SecretStore, SshrackConfig};
use sshrack_core::config::store as config_store;
use sshrack_core::credential;
use sshrack_core::error::SshrackError;
```

Then add the helper. Place it just ABOVE `fn entry_mode_from_cmd` (around line 251), so it sits with the other `Command`→intent logic:

```rust
/// Resolve the `sshrack sftp` entry target into a concrete [`Host`], honoring
/// the merged `--ad-hoc`/`--credential`/`--user`/`--port`/`--identity` flags
/// exactly like the ssh/scp connect path — a thin wrapper over
/// [`host::resolve_target`]. Returns `Ok(None)` when the CLI is not an `sftp`
/// command.
///
/// Pure: no I/O, no terminal. The sftp entry path in [`run`] calls this BEFORE
/// the alternate screen so an unknown name, a dangling `--credential`, or an
/// ad-hoc target without an identity errors out on the normal terminal
/// (mirroring the CLI connect path's fail-fast-before-network rule). The
/// credential name is resolved to an id here (and only here) for the same
/// reason — a dangling `-c` errors before any popup or connection.
fn resolve_transfer_target(
    cmd: Option<&Command>,
    cfg: &SshrackConfig,
    top: &ConnectOptions,
) -> Result<Option<Host>, SshrackError> {
    let Some(Command::Sftp { opts, name }) = cmd else {
        return Ok(None);
    };
    let merged = opts.clone().overlay(top);
    let cred_ulid = match merged.credential.as_deref() {
        None => None,
        Some(cname) => Some(
            cfg.find_credential_by_name(cname)
                .map(|c| c.id)
                .ok_or_else(|| credential::credential_not_found(cfg, cname))?,
        ),
    };
    let overrides = host::ResolveOverrides {
        ad_hoc: merged.ad_hoc,
        credential: cred_ulid,
        port: merged.port,
        user: merged.user.as_deref(),
        identity: merged.identity.as_deref(),
    };
    Ok(Some(host::resolve_target(cfg, name, &overrides)?))
}
```

- [ ] **Step 4: Wire the helper into `run`**

Replace the Task-1 entry-resolution block (`let pending_transfer_host = match &entry_mode { … }`, lines ~156-164) with a single call. The `entry_mode` var stays (still needed for `apply_entry_mode`'s tab landing):

```rust
    let entry_mode = entry_mode_from_cmd(cli.cmd.as_ref());
    // Resolve the sftp entry target (saved name OR ad-hoc literal) BEFORE the
    // alternate screen: an unknown name / dangling --credential / ad-hoc-without-
    // identity errors here, on the normal terminal, mapped to exit NOT_FOUND by
    // main (mirroring the CLI connect path). Non-sftp commands resolve to None.
    let pending_transfer_host =
        resolve_transfer_target(cli.cmd.as_ref(), &cfg, &cli.connect_opts)?;
```

The stash block (lines ~174-176) is unchanged from Task 1:

```rust
    if let Some(h) = pending_transfer_host {
        app.pending_transfer_host = Some(h);
    }
```

- [ ] **Step 5: Run — pass**

```bash
cargo test -p sshrack --lib tui::tests::resolve_transfer_target
cargo test --workspace
```
Expected: the 8 new tests pass; the full suite stays green.

- [ ] **Step 6: Document ad-hoc support in `docs/sftp.md`**

At line 14, extend the CLI entry bullet so a reader knows `--ad-hoc` works (the remote pane title for an ad-hoc host shows the address, since `host::resolve_target` sets `name = address`):

```markdown
- `sshrack sftp <name>` (CLI — opens the TUI straight into the transfer screen for that host; a missing host fails `HostNotFound` BEFORE the alternate screen, exit 4). Honors the same per-connection flags as `ssh`/`scp` — `--ad-hoc`, `-c/--credential`, `-l/--user`, `-p/--port`, `-i/--identity` — so `sshrack --ad-hoc -c yushi sftp 192.168.20.18` opens the screen for an unsaved host (remote pane title = the address). `--accept-new` is a no-op here: a first-seen host key is confirmed via the interactive popup, same as `Ctrl-T`.
```

- [ ] **Step 7: Build + test + clippy + fmt + commit**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt
git add src/tui/mod.rs docs/sftp.md
git commit -m "feat(tui): resolve --ad-hoc and override targets at the sftp entry"
```

- [ ] **Step 8: Manual smoke (optional but recommended)**

```bash
cargo build --release
./target/release/sshrack --ad-hoc -c yushi sftp 192.168.20.18   # requires a saved credential named "yushi"
```
Expected: the transfer screen opens directly; the remote pane title shows `192.168.20.18`; the remote pane lists the home directory. Also verify the existing paths still work: `./target/release/sshrack sftp <saved-name>` (Ctrl-T from the launcher). A dangling `-c nope sftp x` should print `host not found`-style on the normal terminal (exit 4) WITHOUT flipping to the alternate screen.

---

## Self-Review

**1. Spec coverage (the user's ask: "sftp 的自定义主机运行也要支持一下，类似于 scp ssh 的支持"):**
- `--ad-hoc` literal address → ad-hoc ephemeral `Host` — Task 2 helper → `resolve_target` ad-hoc arm. ✅ (test `resolve_transfer_target_ad_hoc_with_credential_builds_ephemeral_ref`)
- `-c <cred>` reuse for an ad-hoc target — Task 2 resolves the name→id and passes it via `ResolveOverrides.credential`. ✅
- `--user`/`--port`/`--identity` overrides — merged by `opts.overlay(top)`, flow into `ResolveOverrides`. ✅ (tests `…_ad_hoc_with_user_builds_inline_body`, `…_overlays_top_level_opts`)
- "类似于 scp ssh 的支持" — the helper calls the SAME `host::resolve_target` the ssh/scp handlers use; no re-rolled logic. ✅
- The blocking error (`host name not found: 192.168.20.18`) — gone: the entry no longer falls through to `find_host_by_name` when `--ad-hoc` is set. ✅

**2. Placeholder scan:** No TBD/TODO. Every step has runnable code or an exact edit. Test bodies include the assertions. The one "near line N" qualifiers reference verified line numbers from the current source.

**3. Type consistency:** `Host` (the schema struct) is the single type threaded through: `App::pending_transfer_host: Option<Host>` (Task 1) ↔ `resolve_transfer_target -> Result<Option<Host>, _>` (Task 2) ↔ `open_transfer(host: Host, …)` (Task 1). `pending_transfer_id()` returns `Option<Ulid>` in both production (accessor) and tests. `Command::Sftp { opts, name }` field names match `args.rs:179-186`. `ResolveOverrides` field names (`ad_hoc`/`credential`/`port`/`user`/`identity`) match `host.rs:162-173`. `ConnectOptions::overlay(self, base)` call direction matches `args.rs:69` and `connect.rs:53`.

**4. Out-of-scope explicit:** `--accept-new` left as the interactive popup (noted in the doc bullet). No CLI/args changes. No core changes. No keyring/vault behavior change for ad-hoc (an ad-hoc host with a `--credential` ref uses the credential's existing secret path; an ad-hoc inline-`--user` host has no password — same as ssh ad-hoc).

**5. Order safety:** Task 1 is a pure refactor (build green, tests green, behavior identical). Task 2 builds on Task 1's `Host`-carrying plumbing. Either task can be reviewed/rejected independently. A worktree-isolated implementer per task sees a green build at each commit.
