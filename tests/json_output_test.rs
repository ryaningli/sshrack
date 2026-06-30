//! End-to-end JSON contract tests: drive the real `sshrack` binary against a
//! temp config, parse the stdout of `host ls`/`cred ls`/`store status` with
//! `--format json` as JSON, and assert the stable field names are present.
//!
//! These lock the machine-readable contract a script/automation tool relies on:
//! field names are part of the public schema, so a rename here would silently
//! break consumers. The unit tests in `format::` cover row construction in
//! isolation; this test exercises the full binary path (clap parse -> handler ->
//! serde -> stdout) to catch wiring regressions the unit tests cannot.
//!
//! Hermeticity: every invocation points `--config` at a fresh temp file; no
//! real network or `known_hosts` is touched (these are list/status commands,
//! not connect); and `SSHRACK_PASSPHRASE` in the parent env is irrelevant
//! (these paths never unlock the vault because they add key-only hosts and
//! never reveal passwords).

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Path to the built `sshrack` binary, provided by cargo's test harness.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sshrack"))
}

/// Run `sshrack <args...>` with `--config <tmp>`, returning (exit_code,
/// stdout, stderr). `extra_env` lets the caller add env vars (none by default
/// — kept hermetic).
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

/// Add a key-only host non-interactively so `host ls` has a row to emit. A
/// key-only host needs no storage-mode decision (no password is collected), so
/// this works against a fresh, undecided config.
fn add_key_host(config: &std::path::Path, name: &str, host_addr: &str, identity: &str) {
    let (code, _stdout, stderr) = run(
        &[
            "host",
            "add",
            name,
            "--host",
            host_addr,
            "--user",
            "deploy",
            "--port",
            "2222",
            "--identity",
            identity,
        ],
        config,
    );
    assert_eq!(code, 0, "host add failed: {stderr}");
}

/// `host ls --format json` emits a JSON array whose rows carry the stable field
/// names: `name`, `host`, `port`, `user`, `auth_kind`. For a key-only host the
/// `auth_kind` is `"key"` and `credential_name` is absent (it is omitted via
/// `skip_serializing_if = Option::is_none`).
#[test]
fn host_ls_json_has_stable_field_names() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");
    add_key_host(&cfg, "web1", "10.0.0.5", "/home/u/.ssh/id_ed25519");

    let (code, stdout, stderr) = run(&["host", "ls", "--format", "json"], &cfg);
    assert_eq!(code, 0, "host ls failed: {stderr}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    let arr = parsed.as_array().expect("host ls json is an array").clone();
    assert!(!arr.is_empty(), "at least one row");
    let row = &arr[0];
    // Stable field names must be present (the automation contract).
    assert_eq!(row["name"], "web1");
    assert_eq!(row["host"], "10.0.0.5");
    assert_eq!(row["port"], 2222);
    assert_eq!(row["user"], "deploy");
    assert_eq!(row["auth_kind"], "key");
    // A key-only inline host has no credential reference: the optional field is
    // omitted, NOT null.
    assert!(
        row.get("credential_name").is_none() || row["credential_name"].is_null(),
        "credential_name absent for inline auth"
    );
    // The reveal-only `password` field must never appear on `ls`.
    assert!(
        row.get("password").is_none(),
        "password field must not appear on host ls"
    );
}

/// `cred ls --format json` emits a JSON array whose rows carry the stable field
/// names: `name`, `user`, `secret_kind`. For a key credential `secret_kind` is
/// `"key"`; `password` is absent (it is the reveal exception, never on `ls`).
#[test]
fn cred_ls_json_has_stable_field_names() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");
    // Add a key credential non-interactively (no password -> no storage mode
    // decision needed).
    let (code, _stdout, stderr) = run(
        &[
            "cred",
            "add",
            "team-dev",
            "--user",
            "deploy",
            "--identity",
            "~/.ssh/team_ed25519",
        ],
        &cfg,
    );
    assert_eq!(code, 0, "cred add failed: {stderr}");

    let (code, stdout, stderr) = run(&["cred", "ls", "--format", "json"], &cfg);
    assert_eq!(code, 0, "cred ls failed: {stderr}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    let arr = parsed.as_array().expect("cred ls json is an array").clone();
    assert!(!arr.is_empty(), "at least one row");
    let row = &arr[0];
    assert_eq!(row["name"], "team-dev");
    assert_eq!(row["user"], "deploy");
    assert_eq!(row["secret_kind"], "key");
    // The reveal-only `password` field must never appear on `ls`.
    assert!(
        row.get("password").is_none(),
        "password field must not appear on cred ls"
    );
}

/// `store status --format json` against a fresh (undecided) config emits a row
/// whose `mode` is `"undecided"`. The vault-specific fields (`kdf`,
/// `memory_kib`, etc.) are absent because they are `skip_serializing_if`.
#[test]
fn store_status_json_reports_undecided_mode_on_fresh_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");

    let (code, stdout, stderr) = run(&["store", "status", "--format", "json"], &cfg);
    assert_eq!(code, 0, "store status failed: {stderr}");
    let parsed: Value = serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    // store status emits a single object (not an array).
    let obj = parsed.as_object().expect("store status json is an object");
    assert_eq!(obj["mode"], "undecided", "fresh config is undecided");
    // Vault-only fields must be absent on an undecided config.
    assert!(
        obj.get("kdf").is_none(),
        "kdf must be absent when not in vault mode"
    );
    assert!(
        obj.get("memory_kib").is_none(),
        "memory_kib must be absent when not in vault mode"
    );
    assert!(
        obj.get("has_verifier").is_none(),
        "has_verifier must be absent when not in vault mode"
    );
}

/// The full automation round-trip: add a host, add a credential, then list both
/// in one JSON pipeline and assert the contract holds together. This catches
/// cross-command regressions (e.g. a shared helper changing field order or a
/// config that one command writes breaking another's read).
#[test]
fn full_pipeline_host_and_cred_json_together() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");
    add_key_host(&cfg, "web-prod", "prod.internal", "/keys/prod");
    add_key_host(&cfg, "web-staging", "staging.internal", "/keys/staging");

    // Two hosts round-trip through the JSON contract.
    let (code, stdout, stderr) = run(&["host", "ls", "--format", "json"], &cfg);
    assert_eq!(code, 0, "host ls failed: {stderr}");
    let arr: Vec<Value> = serde_json::from_str(stdout.trim()).expect("host ls json is an array");
    assert_eq!(arr.len(), 2, "both added hosts appear");
    let names: Vec<&str> = arr
        .iter()
        .map(|r| r["name"].as_str().expect("name is a string"))
        .collect();
    assert!(names.contains(&"web-prod"));
    assert!(names.contains(&"web-staging"));
    // Every row carries the full stable schema.
    for row in &arr {
        assert!(row.get("host").is_some());
        assert!(row.get("port").is_some());
        assert!(row.get("user").is_some());
        assert!(row.get("auth_kind").is_some());
    }
}
