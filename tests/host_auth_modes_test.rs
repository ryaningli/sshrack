//! Regression coverage pinning the CLI's two host auth modes: **Independent**
//! (`Auth::Inline`, reached via `--user`/`--identity` or no auth flag) and
//! **Reference** (`Auth::Ref`, reached via `--credential <name>`). Also covers
//! the `--clear-credential` switch from Reference back to Independent.
//!
//! These drive the real `sshrack` binary against a temp config and read the
//! persisted auth back via `host ls --format json` (where `auth_kind` is
//! `"credential"` for Reference and `"default"`/`"key"` for Independent). They
//! lock the CLI wiring so a future refactor cannot silently drop a mode — the
//! pure `build_auth`/`apply_patch` logic is already covered in core.
//!
//! Hermeticity: every run points `--config` at a fresh temp file; no network or
//! `known_hosts` is touched (management commands only); `SSHRACK_PASSPHRASE` in
//! the parent env is irrelevant (these hosts carry no password).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Path to the built `sshrack` binary, provided by cargo's test harness.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sshrack"))
}

/// Run `sshrack <args...>` with `--config <tmp>`, returning (exit_code,
/// stdout, stderr).
fn run(args: &[&str], config: &std::path::Path) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.arg("--config").arg(config);
    for a in args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("run sshrack binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Fetch the single host row from `host ls --format json`. Asserts exactly one
/// host exists (the one the test just added/edited).
fn host_row(config: &std::path::Path) -> Value {
    let (code, stdout, stderr) = run(&["host", "ls", "--format", "json"], config);
    assert_eq!(code, 0, "host ls failed: {stderr}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    let arr = parsed.as_array().expect("host ls json is an array").clone();
    assert_eq!(arr.len(), 1, "expected exactly one host row, got {arr:?}");
    arr.into_iter().next().expect("one row")
}

/// `host add` with no auth flag → Independent auth, default user `root`. The
/// `auth_kind` is `"default"` (no key, no password) and `credential_name` is
/// absent.
#[test]
fn host_add_no_auth_flag_is_independent_default_root() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    let (code, _stdout, stderr) = run(&["host", "add", "h", "--host", "1.1.1.1"], &cfg);
    assert_eq!(code, 0, "host add failed: {stderr}");

    let row = host_row(&cfg);
    assert_eq!(row["name"], "h", "row: {row}");
    assert_eq!(row["user"], "root", "default user is root");
    assert_eq!(
        row["auth_kind"], "default",
        "no auth flag → Independent default body"
    );
    assert!(
        row.get("credential_name").is_none() || row["credential_name"].is_null(),
        "no credential reference for Independent auth"
    );
}

/// `host add --user ops` → Independent auth with that user (Independent-None:
/// no key, no password).
#[test]
fn host_add_user_is_independent_with_user() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    let (code, _stdout, stderr) = run(
        &["host", "add", "h", "--host", "1.1.1.1", "--user", "ops"],
        &cfg,
    );
    assert_eq!(code, 0, "host add failed: {stderr}");

    let row = host_row(&cfg);
    assert_eq!(row["user"], "ops");
    assert_eq!(
        row["auth_kind"], "default",
        "--user alone → Independent-None (default body, just a custom user)"
    );
    assert!(
        row.get("credential_name").is_none() || row["credential_name"].is_null(),
        "no credential reference for Independent auth"
    );
}

/// `host add --identity /k` → Independent auth with a key
/// (Independent-IdentityKey). `auth_kind` is `"key"`.
#[test]
fn host_add_identity_is_independent_with_key() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    let (code, _stdout, stderr) = run(
        &["host", "add", "h", "--host", "1.1.1.1", "--identity", "/k"],
        &cfg,
    );
    assert_eq!(code, 0, "host add failed: {stderr}");

    let row = host_row(&cfg);
    assert_eq!(
        row["auth_kind"], "key",
        "--identity → Independent-IdentityKey"
    );
    assert!(
        row.get("credential_name").is_none() || row["credential_name"].is_null(),
        "no credential reference for Independent auth"
    );
}

/// `host add --credential <name>` → Reference auth (`Auth::Ref`). `auth_kind`
/// is `"credential"` and `credential_name` carries the referenced entry's name.
#[test]
fn host_add_credential_is_reference() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    // A key-only credential needs no storage-mode decision (no password).
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
    assert_eq!(code, 0, "cred add failed: {stderr}");

    let (code, _stdout, stderr) = run(
        &[
            "host",
            "add",
            "h",
            "--host",
            "1.1.1.1",
            "--credential",
            "ops",
        ],
        &cfg,
    );
    assert_eq!(code, 0, "host add failed: {stderr}");

    let row = host_row(&cfg);
    assert_eq!(row["auth_kind"], "credential", "--credential → Reference");
    assert_eq!(
        row["credential_name"], "ops",
        "credential_name reverse-resolves to the referenced entry's name"
    );
    // The `user` field reflects the inline body only (empty for a Reference
    // host, whose user lives on the referenced credential). The auth_kind +
    // credential_name are the contract that pins Reference mode here.
}

/// `host edit --clear-credential` on a Reference host → reverts to Independent
/// auth with the default user `root`. This is the Reference→Independent switch.
#[test]
fn host_edit_clear_credential_reverts_to_independent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    // Stand up a Reference host first.
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
    assert_eq!(code, 0, "cred add failed: {stderr}");
    let (code, _stdout, stderr) = run(
        &[
            "host",
            "add",
            "h",
            "--host",
            "1.1.1.1",
            "--credential",
            "ops",
        ],
        &cfg,
    );
    assert_eq!(code, 0, "host add failed: {stderr}");
    let before = host_row(&cfg);
    assert_eq!(before["auth_kind"], "credential", "precondition: Reference");

    // Drop the reference.
    let (code, _stdout, stderr) = run(&["host", "edit", "h", "--clear-credential"], &cfg);
    assert_eq!(code, 0, "host edit failed: {stderr}");

    let after = host_row(&cfg);
    assert_eq!(
        after["auth_kind"], "default",
        "--clear-credential reverts to Independent default body"
    );
    assert_eq!(after["user"], "root", "Independent default user is root");
    assert!(
        after.get("credential_name").is_none() || after["credential_name"].is_null(),
        "credential reference is dropped"
    );
}
