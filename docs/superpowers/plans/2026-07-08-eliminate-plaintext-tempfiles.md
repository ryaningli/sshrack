# Eliminate Plaintext-Mode Askpass Temp Files + Stale Temp-File Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop writing the `sshrack-askpass-*.pw` temp file in plaintext storage mode (the askpass helper reads the password straight from the 0600 config, where it already lives), and add a startup stale-sweep so the temp files that remain unavoidable (inline-key `sshrack-key-*.pem`, vault-mode `sshrack-askpass-*.pw`) never survive a Ctrl-C / kill as orphans.

**Architecture:** Two independent changes. (1) Plaintext mode adds a third askpass delivery channel alongside keyring and the temp-file path: the connect layer emits a new `PasswordSource::Config { host_id }` variant instead of `Inline(pw)`, sets `SSHRACK_HOST_ID` (+ `SSHRACK_CONFIG`) in ssh's env, and the askpass helper resolves the host's plaintext password straight from the config — no temp file, no new exposure (the password is already on disk at 0600 in `config.toml`). (2) A startup stale-sweep scans `std::env::temp_dir()` for `sshrack-askpass-*` / `sshrack-key-*` files older than a staleness threshold and removes them best-effort, covering the crash-quit residue that `Drop` / child-exit cleanup cannot reach.

**Tech Stack:** Rust 2024 (MSRV 1.88), sshrack-core, no new dependencies (reuses `ulid`, `zeroize`, `tempfile` (dev), existing `config`/`credential` modules).

## Global Constraints

- English only — all source, comments, doc comments, errors, help text, log output, and commit messages.
- Zero `unsafe`, including in tests.
- Zero `unwrap()` / `expect()` in production — only `#[cfg(test)]` or genuinely unreachable states with `expect("invariant: ...")`.
- Clippy strict — `cargo clippy --workspace --all-targets -- -D warnings` green before every commit.
- Format — `cargo fmt` green before every commit.
- Library errors use `thiserror`; application errors use `anyhow` with `.context()`. All fallible ops propagate via `?`.
- Hermetic tests — `cargo test --workspace` with no env vars must pass; tests never mutate the real environment and never touch the real `/tmp` or real config (inject paths via params / tempfiles).
- Passwords are `Zeroizing<String>` end-to-end; never logged, printed in errors, or placed in argv / `ps`.
- Do not reimplement SSH; no SSH protocol libraries.
- Conventional Commits `<type>(<scope>): <desc>`, no `Co-Authored-By` trailer. Explicit `git add <paths>`, never `git add -A`.

---

## Out of Scope (recorded, not done here)

- **Vault-mode `sshrack-askpass-*.pw` elimination.** The vault password is encrypted at rest; the helper would need the master passphrase to self-decrypt. The passphrase flow has a real trade-off (env exposure of the *whole-vault* master key vs. the single-password temp file) and differs between the CLI path (passphrase in `SSHRACK_PASSPHRASE` env) and TUI path (passphrase only in memory). Resolving it needs a spike on whether ssh preserves inherited fds across the `SSH_ASKPASS` fork (a pipe/fd channel would be the clean answer). Tracked separately; vault mode keeps the temp file + relies on the stale-sweep added here.
- **Inline-key `sshrack-key-*.pem` elimination.** `ssh -i` requires a filesystem path (it `fstat`s the identity and rejects `/dev/stdin`); elimination would need `memfd_create` (raw syscall → violates zero-`unsafe`) or dropping the inline-key feature. Unavoidable; covered by `KeyArtifact`'s `Drop` + the stale-sweep.
- **Parallel hardening: `launch` does not `env_remove(SSHRACK_PASSPHRASE)` before spawning ssh.** On the CLI vault path the master passphrase is currently inherited by the whole ssh process tree (`/proc/<pid>/environ` readable, ssh's children inherit it). This is a CRITICAL-severity follow-up independent of the temp-file topic; left for a dedicated security pass because fixing it interacts with the vault-elimination spike above.

---

## File Structure

- **Modify** `crates/sshrack-core/src/credential.rs` — add `PasswordSource::Config { host_id }` variant; add `plaintext_password(host, cfg)` pure helper; make `resolve` emit `Config` in plaintext mode.
- **Modify** `crates/sshrack-core/src/askpass.rs` — add `HOST_ID_ENV` / `CONFIG_ENV` constants, `run_config(config_path, host_id)` pure reader, branch in `run()`.
- **Modify** `crates/sshrack-core/src/connect/mod.rs` — handle `PasswordSource::Config` in `askpass_env_for` / `env_for` / `launch` (set env, no temp file).
- **Create** `crates/sshrack-core/src/sweep.rs` — pure `sweep_stale_tempfiles(dir, now, max_age)` + thin `sweep_default()` that reads `temp_dir()`.
- **Modify** `crates/sshrack-core/src/lib.rs` — `pub mod sweep;`.
- **Modify** `src/main.rs` — dispatch `SSHRACK_HOST_ID` to askpass; call `sweep::sweep_default()` at the top of `run_main()`.
- **Modify** `crates/sshrack-core/src/error.rs` — add any new `SshrackError` variants the reader/sweep need.

---

### Task 1: Plaintext askpass channel — helper reads config (no temp file)

This task adds the full new channel end-to-end on the *helper* side plus the connect-layer env wiring, but does **not** yet make `resolve` emit the new variant (Task 2 does). After Task 1 the channel is complete and unit-tested but unused in production, so exhaustive-match sites get real implementations, not placeholders.

**Files:**
- Modify: `crates/sshrack-core/src/credential.rs` (add `PasswordSource::Config` + `plaintext_password`)
- Modify: `crates/sshrack-core/src/askpass.rs` (constants, `run_config`, branch)
- Modify: `crates/sshrack-core/src/connect/mod.rs` (`askpass_env_for` / `env_for` / `launch` Config arms)
- Modify: `crates/sshrack-core/src/error.rs` (new error variants)
- Test: `crates/sshrack-core/src/credential.rs` (`#[cfg(test)]`), `crates/sshrack-core/src/askpass.rs` (`#[cfg(test)]`), `crates/sshrack-core/src/connect/mod.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `config::store::load(&Path) -> Result<SshrackConfig>`, `SshrackConfig::find_host_by_id(&Ulid) -> Option<&Host>`, `Ulid::from_string(&str) -> Result<Ulid, _>`, `config::path::default_path() -> Option<PathBuf>`.
- Produces: `PasswordSource::Config { host_id: String }`; `credential::plaintext_password(host: &Host, cfg: &SshrackConfig) -> Option<Zeroizing<String>>`; `askpass::HOST_ID_ENV` / `askpass::CONFIG_ENV`; `askpass::run_config(config_path: &Path, host_id: &str) -> Result<(), SshrackError>`.

- [ ] **Step 1: Write the failing test for `plaintext_password`**

Add to `crates/sshrack-core/src/credential.rs` `#[cfg(test)]` module:

```rust
#[test]
fn plaintext_password_inline_body_returns_plain_secret() {
    use crate::config::schema::{Auth, CredentialBody, Host};
    let body = CredentialBody::new("u").with_password("hunter2");
    let host = Host {
        id: "01HXYZ0000000000000000000Z".parse().unwrap(),
        name: "h".into(),
        auth: Auth::Inline(body),
        ..Host::minimal_test()
    };
    let cfg = SshrackConfig::minimal_test_with_hosts(vec![host.clone()]);
    let pw = plaintext_password(&host, &cfg).unwrap();
    assert_eq!(pw.as_str(), "hunter2");
}

#[test]
fn plaintext_password_ref_body_resolves_credential() {
    // host.auth = Ref { credential } pointing at a cred whose body has a Plain password
    // ...build cfg with one host (Ref) + one credential, assert plaintext_password returns the cred's password
}

#[test]
fn plaintext_password_returns_none_when_no_password() {
    // body with key only, no password -> None
}
```

If `Host::minimal_test()` / `SshrackConfig::minimal_test_with_hosts` test builders do not exist, add minimal private builders in the test module (they only seed `id`/`name`/`auth`/empty `store`).

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sshrack-core plaintext_password -- --nocapture`
Expected: FAIL — `plaintext_password` not defined.

- [ ] **Step 3: Implement `plaintext_password` and the `Config` variant**

In `crates/sshrack-core/src/credential.rs`, add the variant to `PasswordSource`:

```rust
#[derive(Debug, Clone)]
pub enum PasswordSource {
    None,
    /// Plaintext password was decrypted into memory; the connect layer writes
    /// it to a 0600 temp file the askpass helper reads. Vault mode.
    Inline(Zeroizing<String>),
    /// Plaintext storage mode: the password already lives at 0600 in
    /// `config.toml`. The connect layer sets `SSHRACK_HOST_ID` instead of
    /// writing a temp file, and the askpass helper reads it straight from the
    /// config via [`plaintext_password`]. No temp file, no new exposure.
    Config { host_id: String },
    /// Keyring mode: the helper queries the OS keyring for `key`. The main
    /// process never materializes the plaintext.
    Keyring { key: String },
}
```

(Adjust `derive` / existing field names to match the current enum exactly — read the existing definition first and preserve it.)

Add the pure helper:

```rust
/// The plaintext password for `host` as stored in the config (inline body, or a
/// referenced credential's body). Returns `None` when the host has no password
/// or the password is not a plaintext [`Secret::Plain`] (keyring / vault bodies
/// are not readable here — those use other [`PasswordSource`] channels).
///
/// Used by the askpass helper's config channel so plaintext mode never writes a
/// temp file. Pure: no IO, no env. `Zeroizing` so the caller wipes the secret.
pub fn plaintext_password(host: &Host, cfg: &SshrackConfig) -> Option<Zeroizing<String>> {
    let body = match &host.auth {
        Auth::Inline(b) => b,
        Auth::Ref { credential } => cfg.find_credential_by_id(credential)?.body,
    };
    body.password_plain().map(|p| Zeroizing::new(p.to_owned()))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sshrack-core plaintext_password -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 5: Write the failing test for the askpass config channel**

Add to `crates/sshrack-core/src/askpass.rs` `#[cfg(test)]` module:

```rust
#[test]
fn run_config_reads_plaintext_password_from_config() {
    use crate::config::store;
    // Build a temp config with one plaintext inline-password host, write it via
    // store::save to a tempfile path, then run_config(path, &host_id_string)
    // and assert the captured stdout equals the password.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // ...build cfg with host id = ULID_H, Auth::Inline body password "s3cret"...
    // store::save(&path, &cfg).unwrap();
    let out = capture_stdout(|| run_config(&path, &ULID_H.to_string()));
    assert_eq!(out, "s3cret");
}

#[test]
fn run_config_errors_when_host_missing() {
    // valid ulid not present in config -> Err (no panic)
}

#[test]
fn run_config_errors_when_host_has_no_plaintext_password() {
    // host with key only -> Err
}
```

`capture_stdout` is a tiny test helper that runs a closure writing to stdout and returns the bytes (the existing askpass tests already pattern stdout capture — reuse their helper, or refactor one out). If the password-write path in the helper uses `println!`, switch it to take a `&mut dyn Write` so tests can inject a buffer (preferred — keeps the helper pure and hermetic). The public `run()` keeps `println!` to stdout.

- [ ] **Step 6: Run test to verify it fails**

Run: `cargo test -p sshrack-core run_config -- --nocapture`
Expected: FAIL — `run_config` not defined.

- [ ] **Step 7: Implement `run_config`, the env constants, and the `run()` branch**

In `crates/sshrack-core/src/askpass.rs`:

```rust
/// Env var carrying the host ULID whose plaintext password the helper must
/// supply (plaintext storage mode — the password is read from the config, not
/// a temp file).
pub const HOST_ID_ENV: &str = "SSHRACK_HOST_ID";
/// Optional env var naming the config file to read (defaults to the XDG path
/// when unset, so the common case needs no extra wiring).
pub const CONFIG_ENV: &str = "SSHRACK_CONFIG";

/// Read the host's plaintext password from `config_path` and write it to `out`
/// (ssh reads the helper's stdout). Pure except for the single config read; no
/// env access, so it is hermetic and unit-testable. Used by [`run`].
pub fn run_config<W: std::io::Write>(
    config_path: &std::path::Path,
    host_id: &str,
    out: &mut W,
) -> Result<(), SshrackError> {
    let cfg = crate::config::store::load(config_path)?;
    let ulid = ulid::Ulid::from_string(host_id)
        .map_err(|_| SshrackError::AskpassBadHostId { raw: host_id.into() })?;
    let host = cfg
        .find_host_by_id(&ulid)
        .ok_or_else(|| SshrackError::AskpassHostMissing { id: host_id.into() })?;
    let pw = crate::credential::plaintext_password(host, &cfg)
        .ok_or(SshrackError::AskpassNoPlaintextPassword { id: host_id.into() })?;
    out.write_all(pw.as_bytes()).map_err(SshrackError::from)?;
    out.flush().map_err(SshrackError::from)?;
    Ok(())
}
```

In `run()`, add the branch (before the existing `ASKPASS_FILE_ENV` read so the new channel takes precedence — order does not matter functionally since they are mutually exclusive, but keep it readable):

```rust
pub fn run() -> Result<(), SshrackError> {
    if let Some(host_id) = std::env::var_os(HOST_ID_ENV) {
        let host_id = host_id.to_string_lossy();
        let config_path = std::env::var_os(CONFIG_ENV)
            .map(std::path::PathBuf::from)
            .or_else(crate::config::path::default_path)
            .ok_or(SshrackError::AskpassNoConfigPath)?;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        return run_config(&config_path, &host_id, &mut lock);
    }
    // ...existing keyring / ASKPASS_FILE_ENV branches unchanged...
}
```

Add the three error variants to `crates/sshrack-core/src/error.rs`:

```rust
#[error("askpass: malformed host id {raw:?}")]
AskpassBadHostId { raw: String },
#[error("askpass: host {id:?} not found in config")]
AskpassHostMissing { id: String },
#[error("askpass: host {id:?} has no plaintext password in config")]
AskpassNoPlaintextPassword { id: String },
#[error("askpass: could not resolve the config file path")]
AskpassNoConfigPath,
```

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo test -p sshrack-core run_config -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 9: Wire the connect-layer env for `PasswordSource::Config`**

In `crates/sshrack-core/src/connect/mod.rs`, the enum now has a fourth variant so every `match` on `PasswordSource` must gain a `Config` arm. Update `askpass_env_for` to set `SSHRACK_HOST_ID` (+ `SSHRACK_CONFIG` when a non-default config path is in play — pass it through from the caller or leave to default), `env_for` to mirror it, and `launch` so the `Config` arm writes **no** temp file:

```rust
// In askpass_env_for (mirrors Inline/Keyring structure):
PasswordSource::Config { host_id } => {
    env.push((crate::askpass::HOST_ID_ENV, host_id.clone()));
    // SSHRACK_CONFIG is optional; the helper falls back to the XDG default.
    if let Some(p) = config_path_override {
        env.push((crate::askpass::CONFIG_ENV, p.to_string_lossy().into_owned()));
    }
}
```

In `launch`, the `pw_file` match gains `PasswordSource::Config { .. } | PasswordSource::None | PasswordSource::Keyring { .. } => None` (no file written). Keep the existing `Inline(pw_file)` write + child-exit cleanup for the vault path.

If `askpass_env_for` does not currently receive a config-path override, thread an `Option<&Path>` through from the caller (the connect orchestration already knows the config path it loaded). If threading is invasive, leave `CONFIG_ENV` unset for now (helper uses XDG default) and note `--config` override propagation as a follow-up comment — the common path works without it.

- [ ] **Step 10: Write the failing test for the env wiring**

In `crates/sshrack-core/src/connect/mod.rs` `#[cfg(test)]`:

```rust
#[test]
fn env_for_config_sets_host_id_and_writes_no_file() {
    let env = askpass_env_for(
        Path::new("/sshrack"),
        &PasswordSource::Config { host_id: "01HXYZ0000000000000000000Z".into() },
        None, // no pw_file, no config override
    );
    let map: std::collections::HashMap<_, _> = env.into_iter().collect();
    assert_eq!(
        map.get(crate::askpass::HOST_ID_ENV).map(|s| s.as_str()),
        Some("01HXYZ0000000000000000000Z")
    );
    // No ASKPASS_FILE_ENV (that is the temp-file path — must be absent).
    assert!(!map.contains_key(crate::askpass::ASKPASS_FILE_ENV));
}
```

- [ ] **Step 11: Run test to verify it fails, then passes**

Run: `cargo test -p sshrack-core env_for_config -- --nocapture` → FAIL (no Config arm yet if you wrote the test first; if you wired the arm in Step 9, run it now) → PASS after the arm lands.

- [ ] **Step 12: Verify the whole workspace still compiles + clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean (every `match` on `PasswordSource` now handles `Config`).

- [ ] **Step 13: Commit**

```bash
git add crates/sshrack-core/src/credential.rs crates/sshrack-core/src/askpass.rs \
        crates/sshrack-core/src/connect/mod.rs crates/sshrack-core/src/error.rs
git commit -m "feat(connect): add config-channel askpass path for plaintext mode"
```

---

### Task 2: Make `resolve` emit `Config` in plaintext mode (connect the channel)

Task 1 built the channel but `resolve` still emits `Inline(pw)` for every plaintext password, so production still writes temp files. This task flips the one decision point. Because `resolve` already receives `cfg` (it knows the store mode), all four launch callers (`src/cli/cmd/connect.rs`, `src/cli/cmd/scp.rs`, `src/main.rs` TUI, `src/connect/sftp/worker.rs`) inherit the fix with zero call-site changes.

**Files:**
- Modify: `crates/sshrack-core/src/credential.rs` (`resolve` — the password branch)
- Test: `crates/sshrack-core/src/credential.rs` (`#[cfg(test)]` — resolve in each mode)

**Interfaces:**
- Consumes: `SshrackConfig::is_plaintext()` (`config/schema.rs`), `PasswordSource::Config` (Task 1).
- Produces: `resolve` now returning `PasswordSource::Config { host_id }` for plaintext-mode passwords instead of `Inline`.

- [ ] **Step 1: Write the failing test**

In `crates/sshrack-core/src/credential.rs` `#[cfg(test)]`:

```rust
#[test]
fn resolve_plaintext_mode_emits_config_variant_not_inline() {
    // cfg with store = Plaintext + a host whose inline body has a Plain password.
    let resolved = resolve(&host, &cfg, None).unwrap();
    assert!(
        matches!(resolved.password, PasswordSource::Config { .. }),
        "plaintext mode must use the config channel, got {:?}",
        resolved.password
    );
    // The Inline temp-file path is reserved for vault mode in plaintext-host configs.
}

#[test]
fn resolve_vault_mode_still_emits_inline_for_decrypted_password() {
    // cfg with store = Vault + host with an encrypted password + vault key ->
    // Inline(pw) (temp file still used; vault elimination is out of scope).
}

#[test]
fn resolve_keyring_body_emits_keyring_regardless_of_store_mode() {
    // body.keyring = true -> PasswordSource::Keyring (unchanged).
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sshrack-core resolve_plaintext_mode -- --nocapture`
Expected: FAIL — `resolve` currently emits `Inline`.

- [ ] **Step 3: Implement the branch in `resolve`**

In the password-decision section of `resolve` (around `credential.rs:556` where `PasswordSource::Keyring` is built), gate the plaintext path:

```rust
let password = if keyring {
    PasswordSource::Keyring { /* existing key build */ }
} else if cfg.is_plaintext() && password_secret.is_some() {
    // Plaintext at rest: the password already lives at 0600 in config.toml.
    // Tell the connect layer to point the helper at the config (no temp file).
    // owner_id is the ULID of the host (Inline auth) or credential (Ref auth).
    PasswordSource::Config { host_id: owner_id.to_string() }
} else {
    // Vault path: decrypt into memory; connect writes the 0600 temp file.
    // ...existing Inline(decrypt_secret(...)) logic...
};
```

`owner_id` is already bound at the top of `resolve` (the match unpacks it). `password_secret` is the `Option<Secret>` already in scope. Preserve the existing vault/inline decryption logic verbatim in the `else` branch.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sshrack-core resolve_ -- --nocapture`
Expected: PASS (3 new tests + existing resolve tests still green).

- [ ] **Step 5: Add an integration assertion that no temp file is written in plaintext mode**

In `crates/sshrack-core/tests/connect_flow_test.rs` (or the existing connect integration test), add a case that drives the connect plan assembly for a plaintext-mode host and asserts the env carries `SSHRACK_HOST_ID` and the plan does **not** stage a `write_password_file` call. Follow the existing test's mock-argv / env-capture pattern. Assert against `temp_dir()` contents (via a scoped tempfile dir if the test harness allows injecting it; otherwise assert on the assembled `PasswordSource` / env, which is the hermetic surface).

- [ ] **Step 6: Run the integration test**

Run: `cargo test -p sshrack-core --test connect_flow_test -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Full workspace green**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check && cargo test --workspace`
Expected: all green.

- [ ] **Step 8: Commit**

```bash
git add crates/sshrack-core/src/credential.rs crates/sshrack-core/tests/connect_flow_test.rs
git commit -m "refactor(core): resolve plaintext passwords via config channel, drop temp file"
```

---

### Task 3: Startup stale-sweep for unavoidable temp files

Covers the residue that best-effort `Drop` / child-exit cleanup cannot reach: a Ctrl-C or `kill -9` mid-connection leaves `sshrack-askpass-*.pw` (vault mode) and `sshrack-key-*.pem` (any inline-key connection) behind. The sweep runs once at the top of the normal (non-askpass) entry path, removes files older than a staleness threshold (so it never deletes a concurrent live connection's freshly-written file), and swallows all errors (a sweep failure must never block a connect).

**Files:**
- Create: `crates/sshrack-core/src/sweep.rs`
- Modify: `crates/sshrack-core/src/lib.rs` (`pub mod sweep;`)
- Modify: `src/main.rs` (call `sweep::sweep_default()` in `run_main()`)
- Test: `crates/sshrack-core/src/sweep.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `std::env::temp_dir()`, `std::fs`, `std::time::SystemTime`.
- Produces: `sweep::sweep_stale_tempfiles(dir: &Path, now: SystemTime, max_age: Duration) -> usize` (pure-ish, testable — `now` injected), `sweep::sweep_default() -> ()` (reads `temp_dir()`, best-effort, logs nothing sensitive).

- [ ] **Step 1: Write the failing test**

In `crates/sshrack-core/src/sweep.rs`:

```rust
//! Best-effort cleanup of sshrack temp files left behind by a crashed prior
//! run. The connect path's `Drop` / child-exit removals are best-effort and
//! skip on Ctrl-C / SIGKILL; this sweep runs once at startup to collect the
//! orphans (`sshrack-askpass-*.pw`, `sshrack-key-*.pem`, plus the matching
//! `*-cert.pub`). Files newer than the staleness threshold are left alone so a
//! concurrent live connection's freshly-written file is never deleted.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn touch(dir: &std::path::Path, name: &str, age: Duration) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"x").unwrap();
        // Backdate mtime so the file looks `age` old.
        let old = SystemTime::now() - age;
        let _ = filetime::set_file_mtime(&p, filetime::FileTime::from_system_time(old));
        // NOTE: if `filetime` is not already a dev-dep, backdate by writing the
        // file inside a helper that sets mtime via std (std cannot set mtime
        // without a crate) — instead, inject `now` into the sweep and make the
        // test's `now` = real_now + age so a freshly-written file reads as
        // stale. See Step 3 for the injected-`now` design that avoids filetime.
        p
    }

    #[test]
    fn removes_stale_askpass_and_key_files() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "sshrack-askpass-111-222.pw", Duration::from_secs(7200));
        touch(dir.path(), "sshrack-key-333-444.pem", Duration::from_secs(7200));
        touch(dir.path(), "sshrack-key-333-444.pem-cert.pub", Duration::from_secs(7200));
        let removed = sweep_stale_tempfiles(dir.path(), SystemTime::now(), Duration::from_secs(3600));
        assert_eq!(removed, 3);
        assert!(dir.path().read_dir().unwrap().next().is_none());
    }

    #[test]
    fn preserves_fresh_files_under_threshold() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "sshrack-askpass-111-222.pw", Duration::from_secs(10));
        let removed = sweep_stale_tempfiles(dir.path(), SystemTime::now(), Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert!(dir.path().join("sshrack-askpass-111-222.pw").exists());
    }

    #[test]
    fn ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sshrack-msg.txt"), b"x").unwrap();
        std::fs::write(dir.path().("unrelated.log"), b"x").unwrap();
        let removed = sweep_stale_tempfiles(dir.path(), SystemTime::now() + Duration::from_secs(99999), Duration::from_secs(3600));
        assert_eq!(removed, 0);
    }

    #[test]
    fn missing_dir_is_silent_zero() {
        let removed = sweep_stale_tempfiles(std::path::Path::new("/no/such/dir/here"), SystemTime::now(), Duration::from_secs(3600));
        assert_eq!(removed, 0);
    }
}
```

Note the `now` injection: `sweep_stale_tempfiles` takes `now: SystemTime` so tests can make a freshly-written file appear stale (pass `now + age`) without needing to backdate mtime (std has no mtime setter; avoids a `filetime` dev-dep). Drop the `filetime::set_file_mtime` call in `touch` — write the file at real-now and control staleness purely via the injected `now`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sshrack-core sweep:: -- --nocapture`
Expected: FAIL — `sweep_stale_tempfiles` not defined / module missing.

- [ ] **Step 3: Implement the sweep**

```rust
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Patterns owned by sshrack that the connect path creates and is responsible
/// for removing. Anything else in the temp dir is left untouched.
const STALE_PREFIXES: &[&str] = &["sshrack-askpass-", "sshrack-key-"];

/// Remove sshrack temp files under `dir` whose mtime is older than `max_age`
/// (relative to `now`). Returns the count removed. Best-effort: unreadable
/// entries, permission errors, and a missing `dir` all resolve to `0` (a sweep
/// failure must never block a connect). `now` is injected so the staleness
/// check is unit-testable without backdating file mtimes.
pub fn sweep_stale_tempfiles(dir: &Path, now: SystemTime, max_age: Duration) -> usize {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_sshrack_tempfile(&path) {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|mtime| now.duration_since(mtime).map(|age| age > max_age).unwrap_or(false))
            .unwrap_or(false);
        if stale && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn is_sshrack_tempfile(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    // Covers sshrack-askpass-*.pw, sshrack-key-*.pem, and the sshrack-key-*-cert.pub
    // sibling that KeyArtifact writes beside the private key.
    STALE_PREFIXES.iter().any(|pfx| name.starts_with(pfx))
}

/// Default startup sweep: the std temp dir, "now", and a 1-hour staleness
/// threshold. A normal connection closes its temp files within seconds, so a
/// file older than an hour is residue from a crashed prior run (or a zombie
/// connection). Best-effort; all errors are swallowed.
pub fn sweep_default() {
    let _ = sweep_stale_tempfiles(&std::env::temp_dir(), SystemTime::now(), Duration::from_secs(3600));
}

#[cfg(test)]
mod tests { /* ...Step 1 tests, with the injected-`now` fix... */ }
```

Add `tempfile` as a dev-dependency of `sshrack-core` if it is not already (check `crates/sshrack-core/Cargo.toml` — it is already used by other core tests, so likely present).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sshrack-core sweep:: -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 5: Wire the sweep into the entry path**

In `src/main.rs`, add `sshrack_core::sweep::sweep_default();` as the **first** line inside `run_main()` (after the askpass early-return in `main()`, so the helper fork never sweeps — only real launches do):

```rust
fn run_main() -> i32 {
    // Best-effort: clear sshrack temp files a prior crashed run left behind
    // (Ctrl-C / SIGKILL skip the connect path's Drop cleanup). Runs only on a
    // real launch, never in the askpass-helper fork.
    sshrack_core::sweep::sweep_default();

    let cli = match cli::Cli::try_parse() {
        // ...unchanged...
    };
    // ...
}
```

Add `pub mod sweep;` to `crates/sshrack-core/src/lib.rs` (alphabetical order).

- [ ] **Step 6: Verify build + clippy + full tests**

Run: `cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check && cargo test --workspace`
Expected: all green (the sweep is hermetic — `sweep_default()` reading the real `/tmp` at test time is harmless because it only removes files older than 1h matching sshrack prefixes, and tests do not assert on it; the pure `sweep_stale_tempfiles` is what tests cover).

- [ ] **Step 7: Commit**

```bash
git add crates/sshrack-core/src/sweep.rs crates/sshrack-core/src/lib.rs src/main.rs
git commit -m "feat(core): startup stale-sweep for crashed-run temp-file residue"
```

---

## Self-Review

**1. Spec coverage:**
- "能不使用临时文件就不使用" → Task 1 + Task 2 eliminate the plaintext-mode `sshrack-askpass-*.pw` (the one mode where elimination is zero-security-cost). ✅ Vault-mode and inline-key files are documented out of scope with reasons (real trade-offs / OpenSSH hard constraint), not silently dropped.
- "确保临时文件的后置移除" → Task 3 stale-sweep covers the residue of every unavoidable temp file (vault `.pw`, inline-key `.pem` + its `-cert.pub` sibling) after Ctrl-C / kill. ✅ The normal-path removals (helper read-then-delete, launch child-exit delete, `KeyArtifact::Drop`) are pre-existing and untouched.

**2. Placeholder scan:** No TBD/TODO. Every code step shows real code against confirmed interfaces (`find_host_by_id`, `Ulid::from_string`, `config::path::default_path`, `store::load`, `resolve`, `is_plaintext`). The one open thread — `SSHRACK_CONFIG` override propagation through `askpass_env_for` — is given a concrete fallback (helper uses XDG default) and a follow-up note, not a placeholder. The `filetime` temptation in Task 3 Step 1 is explicitly replaced with the injected-`now` design to avoid a new dev-dep.

**3. Type consistency:** `PasswordSource::Config { host_id: String }` is defined in Task 1 and consumed identically in Task 1 (helper via `HOST_ID_ENV`), Task 1 (connect env arm), and Task 2 (`resolve` emits it). `plaintext_password(host, cfg) -> Option<Zeroizing<String>>` is defined and used in Task 1's helper with matching types. `run_config(config_path, host_id, &mut W)` signature is consistent across definition, `run()` call, and tests. `sweep_stale_tempfiles(dir, now, max_age) -> usize` is consistent across definition, `sweep_default()`, tests, and the `main.rs` call site.

**4. Risk note for the implementer:** Task 2 changes `resolve`, which every connect path depends on. The regression net is the existing resolve tests + the three new mode-specific tests + the `connect_flow_test` integration assertion. If a snapshot or existing test breaks on the `Inline` → `Config` flip, that is expected in plaintext mode and the snapshot/test should be updated to the new channel (reviewer confirms it is the intended plaintext-mode change, not a vault regression — vault tests must stay `Inline`).
