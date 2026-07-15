//! Identity-import binary contract tests: `--identity-stdin` / `--identity-file`
//! read private-key **contents** into a sealed [`Secret`] (never visible in argv
//! or `ps`), and `--accept-new` is a connect-time host-key policy. These drive
//! the real `sshrack` binary, then load the temp config via `sshrack-core` to
//! inspect the *stored* representation — the strongest hermetic proof that key
//! text is sealed (not leaked) without needing a real network connect.
//!
//! What is pinned here:
//! - `--identity-stdin` / `--identity-file` round-trip into an inline key on the
//!   host/credential, in both plaintext (round-trips verbatim) and vault
//!   (stored `Encrypted`, raw PEM absent from `config.toml`) storage modes.
//! - The `--accept-new` flag's real semantics: it is a top-level connect-time
//!   flag, **not** a persisted host field (the plan's "round-trips in host show"
//!   premise was incorrect — corrected and pinned here).
//! - A `cred add` smoke matrix (key-only / user-only / identity-stdin).
//!
//! Hermeticity: every run points `--config` at a fresh temp file. The vault-mode
//! run passes `SSHRACK_PASSPHRASE` to the spawned child only (never `set_var`).
//! No network or `known_hosts` is touched (management commands only).

use std::path::PathBuf;
use std::process::Command;

use sshrack_core::config::schema::{KeySource, Secret};
use sshrack_core::config::store;

/// A distinctive plaintext marker we pipe in as "key text". If it ever appears
/// in argv it would be a leak; in plaintext mode it round-trips into the config,
/// in vault mode it must NOT appear in the config.
const KEY_MARKER: &str = "TEST_PRIVATE_KEY_MARKER_42";

/// Path to the built `sshrack` binary, provided by cargo's test harness.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sshrack"))
}

/// Run `sshrack <args...>` with `--config <tmp>` and optional stdin, returning
/// (exit_code, stdout, stderr).
fn run(args: &[&str], config: &std::path::Path) -> (i32, String, String) {
    run_with(None, args, config)
}

/// Run with optional piped stdin (for `--identity-stdin`).
fn run_stdin(stdin: &str, args: &[&str], config: &std::path::Path) -> (i32, String, String) {
    run_with(Some(stdin), args, config)
}

/// Run with optional piped stdin + optional extra env (for vault mode). The env
/// is passed to the spawned child only.
fn run_with(stdin: Option<&str>, args: &[&str], config: &std::path::Path) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.arg("--config").arg(config);
    for a in args {
        cmd.arg(a);
    }
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn sshrack");
    if let Some(s) = stdin {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(s.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait sshrack");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run with extra env vars (e.g. `SSHRACK_PASSPHRASE` for vault mode) + stdin.
fn run_env_stdin(
    env: &[(&str, &str)],
    stdin: &str,
    args: &[&str],
    config: &std::path::Path,
) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.arg("--config").arg(config);
    for (k, v) in env {
        cmd.env(k, v);
    }
    for a in args {
        cmd.arg(a);
    }
    cmd.stdin(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn sshrack");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait sshrack");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Load the temp config and return the inline private-key [`Secret`] for the
/// named host, asserting the key is an inline (not path) source.
fn host_inline_private(cfg_path: &std::path::Path, name: &str) -> Secret {
    let cfg = store::load(cfg_path).expect("load config");
    let host = cfg
        .hosts
        .iter()
        .find(|h| h.name == name)
        .unwrap_or_else(|| panic!("host '{name}' present"));
    let body = host
        .auth
        .inline_body()
        .unwrap_or_else(|| panic!("host '{name}' has inline body"));
    let key = body.key.as_ref().expect("host has a key");
    match key {
        KeySource::Inline(ik) => ik.private_key.clone().expect("inline private_key"),
        KeySource::Path(_) => panic!("expected inline key, got Path"),
    }
}

/// Like [`host_inline_private`] but for a named credential.
fn cred_inline_private(cfg_path: &std::path::Path, name: &str) -> Secret {
    let cfg = store::load(cfg_path).expect("load config");
    let cred = cfg
        .credentials
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("cred '{name}' present"));
    let key = cred.body.key.as_ref().expect("cred has a key");
    match key {
        KeySource::Inline(ik) => ik.private_key.clone().expect("inline private_key"),
        KeySource::Path(_) => panic!("expected inline key, got Path"),
    }
}

fn fresh_config() -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    (dir.path().join("config.toml"), dir)
}

// ===========================================================================
// --identity-stdin: plaintext-mode round-trip (key text never in argv)
// ===========================================================================

/// `host add ... --identity-stdin` reads key contents from stdin, stores an
/// inline key on the host. The key text is piped via stdin (never in argv), and
/// in the default undecided/plaintext mode it round-trips as `Secret::Plain`
/// containing exactly the input. This is the binary-level proof that the stdin
/// import path works end-to-end.
#[test]
fn host_add_identity_stdin_round_trips_as_plain_in_plaintext_mode() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run_stdin(
        KEY_MARKER,
        &[
            "host",
            "add",
            "h",
            "--host",
            "1.1.1.1",
            "--user",
            "u",
            "--identity-stdin",
        ],
        &cfg,
    );
    assert_eq!(code, 0, "host add --identity-stdin succeeds: {stderr}");

    let sec = host_inline_private(&cfg, "h");
    match sec {
        // The import path normalizes a trailing newline onto the key text
        // (`ensure_trailing_newline` — PEM without it fails in libssh), so we
        // assert containment, not exact equality.
        Secret::Plain(s) => assert!(
            s.contains(KEY_MARKER),
            "plaintext round-trip of stdin key: {s:?}"
        ),
        other => panic!("plaintext mode stores Plain, got {other:?}"),
    }
}

// ===========================================================================
// --identity-stdin: vault mode seals the key (Encrypted, not in config.toml)
// ===========================================================================

/// Under vault mode, `host add ... --identity-stdin` stores the key as
/// `Secret::Encrypted` and the raw PEM marker does **not** appear anywhere in
/// the serialized `config.toml`. This is the sealed-secret contract: key text
/// lives only in the encrypted payload, never in argv and never in cleartext on
/// disk. `SSHRACK_PASSPHRASE` is passed to the child only.
#[test]
fn host_add_identity_stdin_under_vault_seals_key_out_of_config() {
    let (cfg, _dir) = fresh_config();
    let passphrase = "test-vault-passphrase";

    // Enable vault mode (Argon2id derivation — ~1.5s, acceptable for one test).
    let mut cmd = Command::new(bin());
    cmd.arg("--config").arg(&cfg);
    cmd.env("SSHRACK_PASSPHRASE", passphrase);
    cmd.arg("store").arg("use").arg("vault");
    let out = cmd.output().expect("spawn store use vault");
    assert_eq!(
        out.status.code(),
        Some(0),
        "store use vault succeeds: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Add the host with the inline key under vault mode.
    let (code, _stdout, stderr) = run_env_stdin(
        &[("SSHRACK_PASSPHRASE", passphrase)],
        KEY_MARKER,
        &[
            "host",
            "add",
            "h",
            "--host",
            "1.1.1.1",
            "--user",
            "u",
            "--identity-stdin",
        ],
        &cfg,
    );
    assert_eq!(
        code, 0,
        "vault host add --identity-stdin succeeds: {stderr}"
    );

    // Stored representation is Encrypted.
    let sec = host_inline_private(&cfg, "h");
    assert!(
        matches!(sec, Secret::Encrypted(_)),
        "vault mode stores Encrypted, got {sec:?}"
    );

    // Raw PEM marker must NOT appear in the config file.
    let raw = std::fs::read_to_string(&cfg).expect("read config");
    assert!(
        !raw.contains(KEY_MARKER),
        "raw key text must not leak into config.toml under vault mode"
    );
}

// ===========================================================================
// --identity-file: same sealed-secret path via a named file
// ===========================================================================

/// `host add ... --identity-file <path>` reads key contents from the file and
/// stores an inline key (same as stdin, but sourced from disk). Round-trips as
/// `Plain` in plaintext mode.
#[test]
fn host_add_identity_file_round_trips_as_plain() {
    let dir = tempfile::tempdir().expect("temp dir");
    let key_file = dir.path().join("id_test");
    std::fs::write(&key_file, KEY_MARKER).expect("write key file");

    let (cfg, _cfg_dir) = fresh_config();
    let key_path = key_file.to_string_lossy().into_owned();
    let (code, _stdout, stderr) = run(
        &[
            "host",
            "add",
            "h",
            "--host",
            "1.1.1.1",
            "--user",
            "u",
            "--identity-file",
            &key_path,
        ],
        &cfg,
    );
    assert_eq!(code, 0, "host add --identity-file succeeds: {stderr}");

    let sec = host_inline_private(&cfg, "h");
    match sec {
        Secret::Plain(s) => assert!(s.contains(KEY_MARKER), "file identity round-trips: {s:?}"),
        other => panic!("plaintext mode stores Plain, got {other:?}"),
    }
}

// ===========================================================================
// cred add --identity-stdin: same sealed-secret contract on a credential
// ===========================================================================

/// `cred add ... --identity-stdin` reads key contents into the credential's
/// inline key. Same contract as the host path.
#[test]
fn cred_add_identity_stdin_round_trips_as_plain() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run_stdin(
        KEY_MARKER,
        &["cred", "add", "ops", "--user", "deploy", "--identity-stdin"],
        &cfg,
    );
    assert_eq!(code, 0, "cred add --identity-stdin succeeds: {stderr}");

    let sec = cred_inline_private(&cfg, "ops");
    match sec {
        Secret::Plain(s) => assert!(
            s.contains(KEY_MARKER),
            "cred stdin identity round-trips: {s:?}"
        ),
        other => panic!("plaintext mode stores Plain, got {other:?}"),
    }
}

// ===========================================================================
// cred add smoke matrix
// ===========================================================================

/// Key-only credential (`--identity <path>`, no password): a path reference, not
/// inline. `secret_kind` in the JSON output is `"key"`.
#[test]
fn cred_add_key_only_path_identity_succeeds() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(
        &[
            "cred",
            "add",
            "ops",
            "--user",
            "deploy",
            "--identity",
            "/keys/ops",
        ],
        &cfg,
    );
    assert_eq!(code, 0, "cred add key-only succeeds: {stderr}");

    let cfg_loaded = store::load(&cfg).expect("load");
    let cred = cfg_loaded
        .credentials
        .iter()
        .find(|c| c.name == "ops")
        .expect("cred present");
    // Path identity (not inline): the key is a path reference.
    assert!(
        matches!(cred.body.key, Some(KeySource::Path(_))),
        "key-only cred stores a Path identity"
    );
}

/// User-only credential (no key, no password): the default-keys body. This is
/// the "rely on ssh defaults" shape.
#[test]
fn cred_add_user_only_is_default_keys_body() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["cred", "add", "ops", "--user", "deploy"], &cfg);
    assert_eq!(code, 0, "cred add user-only succeeds: {stderr}");

    let cfg_loaded = store::load(&cfg).expect("load");
    let cred = cfg_loaded
        .credentials
        .iter()
        .find(|c| c.name == "ops")
        .expect("cred present");
    assert!(cred.body.key.is_none(), "user-only cred has no key");
    assert!(
        cred.body.password.is_none(),
        "user-only cred has no password"
    );
    assert_eq!(cred.body.user, "deploy");
}

/// Identity-stdin credential (covered in detail above) — this matrix entry just
/// re-pins exit 0 + the inline kind so the three cred shapes are visible
/// together.
#[test]
fn cred_add_identity_stdin_is_inline_kind() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run_stdin(
        KEY_MARKER,
        &["cred", "add", "ops", "--user", "deploy", "--identity-stdin"],
        &cfg,
    );
    assert_eq!(code, 0, "cred add identity-stdin succeeds: {stderr}");

    let cfg_loaded = store::load(&cfg).expect("load");
    let cred = cfg_loaded
        .credentials
        .iter()
        .find(|c| c.name == "ops")
        .expect("cred present");
    assert!(
        matches!(cred.body.key, Some(KeySource::Inline(_))),
        "identity-stdin cred stores an Inline key"
    );
}

// ===========================================================================
// --accept-new: connect-time flag, NOT a persisted host field (spec correction)
// ===========================================================================

/// `--accept-new` is a top-level `ConnectOptions` flag applied at connect time
/// (it OR's into the host-key confirm policy). It is **not** a persisted host
/// attribute: `host add` does not store it and `host show` does not surface it.
/// The plan's "round-trips in host show" premise was incorrect; these tests pin
/// the actual contract so a future change is deliberate, not accidental.
///
/// (1) `--accept-new` before the subcommand is accepted by clap (exit 0); the
///     host is stored normally.
#[test]
fn accept_new_top_level_is_accepted_by_host_add() {
    let (cfg, _dir) = fresh_config();
    let mut cmd = Command::new(bin());
    cmd.arg("--accept-new").arg("--config").arg(&cfg);
    cmd.args(["host", "add", "h", "--host", "1.1.1.1"]);
    let out = cmd.output().expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(0),
        "top-level --accept-new accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// (2) `--accept-new` *after* the `host add` subcommand is rejected by clap
///     (USAGE), because `HostAction` does not define that flag.
#[test]
fn accept_new_after_subcommand_is_rejected_by_clap() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, _stderr) = run(
        &["host", "add", "h", "--accept-new", "--host", "1.1.1.1"],
        &cfg,
    );
    assert_eq!(code, 2, "clap rejects --accept-new on host add (USAGE)");
}

/// (3) A host added with top-level `--accept-new` does NOT persist any
///     accept-new flag — the loaded config has no such field. (The host is a
///     normal inline host.) This documents that accept-new is connect-time only.
#[test]
fn accept_new_is_not_persisted_on_the_host() {
    let (cfg, _dir) = fresh_config();
    let mut cmd = Command::new(bin());
    cmd.arg("--accept-new").arg("--config").arg(&cfg);
    cmd.args(["host", "add", "h", "--host", "1.1.1.1"]);
    let out = cmd.output().expect("spawn");
    assert_eq!(out.status.code(), Some(0));

    // The serialized config carries only the standard host fields — there is no
    // accept_new column on a host (it is a connect-time ConnectOptions flag).
    let raw = std::fs::read_to_string(&cfg).expect("read config");
    assert!(
        !raw.contains("accept_new") && !raw.contains("accept-new"),
        "accept-new must not persist onto the host: {raw}"
    );
}
