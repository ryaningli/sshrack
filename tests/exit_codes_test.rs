//! Exit-code matrix: drive the real `sshrack` binary across every error path
//! and assert the stable process exit code + a stderr property. These codes are
//! the script/automation contract documented in `CLAUDE.md` ("Stable exit
//! codes"), so a regression here silently breaks consumers that branch on `$?`.
//!
//! Covered paths: duplicate name, missing `--yes` confirmations, unknown
//! host/credential references, missing required fields, missing operands, and
//! the dangling-credential fail-fast (which must fire *before* any network IO).
//!
//! Hermeticity: every run points `--config` at a fresh temp file; these are
//! management/list commands, so no network or `known_hosts` is touched. The
//! `SSHRACK_PASSPHRASE` parent env is irrelevant (no vault unlock here).
//!
//! tty-path coverage split: the destructive confirm (`tty_confirm`) reaches a
//! human only when BOTH stdin and stderr are a terminal. `Command::output()`
//! pipes stdio, so `has_tty()` is false and the `--yes`-absent tests below pin
//! the **no-tty error branch**. The tty yes/no branch (`prompt_yes_no`
//! returning true on `y`/`yes`) is covered by the unit tests in
//! `src/cli/prompt.rs` (`is_tty_pair`, `parse_yes_no`,
//! `prompt_yes_no_returns_false_without_tty`) plus manual verification.
//! Automating it here would need a pty harness the repo does not yet carry:
//! an unsafe-free `openpty` wrapper requires a direct `nix` dev-dependency
//! (`nix` is only transitive today, via `keyring -> mac_address`), and the
//! `script`(1) wrapper diverges between util-linux and BSD/macOS. The no-tty
//! pins + the `prompt.rs` unit layer are therefore the coverage vehicle by
//! intent, not by oversight.

use std::path::PathBuf;
use std::process::Command;

/// Exit codes mirroring `src/shared/exit_code.rs`. That module lives in the
/// binary crate (not `sshrack-core`) and so is not importable from integration
/// tests; these named constants keep the values out of magic-number form. If
/// the source values change, update both — they are a public contract.
mod exit_code {
    /// Successful execution.
    pub const SUCCESS: i32 = 0;
    /// Invalid command-line usage (missing arg, unknown flag, missing --yes).
    pub const USAGE: i32 = 2;
    /// A referenced host, credential, or resource was not found.
    pub const NOT_FOUND: i32 = 4;
    /// A name collision blocked a create/rename.
    pub const DUPLICATE: i32 = 5;
    /// Input failed validation (bad port, malformed name, missing field).
    pub const VALIDATION: i32 = 6;
}

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

/// Fresh temp config path the tests write into via the binary.
fn fresh_config() -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg = dir.path().join("config.toml");
    (cfg, dir)
}

// ---------------------------------------------------------------------------
// DUPLICATE (5)
// ---------------------------------------------------------------------------

/// `host add web1` twice (same name) → the second add fails with `DUPLICATE`.
/// Pins the fail-fast duplicate check that fires before any field work.
#[test]
fn host_add_duplicate_name_exits_duplicate() {
    let (cfg, _dir) = fresh_config();
    let (code, _o, _e) = run(&["host", "add", "web1", "--host", "1.1.1.1"], &cfg);
    assert_eq!(code, exit_code::SUCCESS, "first add should succeed");

    let (code, _stdout, stderr) = run(&["host", "add", "web1", "--host", "2.2.2.2"], &cfg);
    assert_eq!(
        code,
        exit_code::DUPLICATE,
        "second add of same name exits DUPLICATE: {stderr}"
    );
    assert!(
        stderr.contains("already exists"),
        "duplicate message names the collision: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// USAGE (2): missing --yes confirmations, missing operands, missing name
// ---------------------------------------------------------------------------

/// `host rm <name>` without `--yes` is rejected (USAGE) when stdio is not a
/// tty: the hint tells the user to pass `--yes` or run in a tty. On a tty,
/// `tty_confirm` would prompt `(y/N)` instead of erroring. (`Command::output()`
/// pipes stdio, so `has_tty()` is false here — this pins the no-tty error path.)
#[test]
fn host_rm_without_yes_is_rejected_as_usage() {
    let (cfg, _dir) = fresh_config();
    run(&["host", "add", "web1", "--host", "1.1.1.1"], &cfg);

    let (code, _stdout, stderr) = run(&["host", "rm", "web1"], &cfg);
    assert_eq!(
        code,
        exit_code::USAGE,
        "rm without --yes exits USAGE: {stderr}"
    );
    assert!(
        stderr.contains("--yes") && stderr.contains("tty"),
        "rejection hints at --yes and a tty: {stderr}"
    );
}

/// `host rm <name> --yes` succeeds (the host exists, the confirmation is given).
#[test]
fn host_rm_with_yes_succeeds() {
    let (cfg, _dir) = fresh_config();
    run(&["host", "add", "web1", "--host", "1.1.1.1"], &cfg);

    let (code, stdout, stderr) = run(&["host", "rm", "web1", "--yes"], &cfg);
    assert_eq!(
        code,
        exit_code::SUCCESS,
        "rm with --yes exits SUCCESS: {stderr}"
    );
    assert!(
        stdout.contains("removed"),
        "rm prints a confirmation: {stdout}"
    );
}

/// `scp` with no operands → USAGE (the user gave sshrack nothing to transfer).
#[test]
fn scp_with_no_operands_exits_usage() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["scp"], &cfg);
    assert_eq!(
        code,
        exit_code::USAGE,
        "scp with no operands exits USAGE: {stderr}"
    );
    assert!(
        stderr.contains("no operands"),
        "scp names the missing operands: {stderr}"
    );
}

/// `host edit` with no name → USAGE. Edit needs a target; the nameless form is
/// a usage error, not the add wizard (Finding #3 in the routing logic).
#[test]
fn host_edit_without_name_exits_usage() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["host", "edit"], &cfg);
    assert_eq!(
        code,
        exit_code::USAGE,
        "host edit with no name exits USAGE: {stderr}"
    );
    assert!(
        stderr.contains("edit requires"),
        "the error tells the user edit needs a name: {stderr}"
    );
}

/// `store use plaintext` without `--yes` is rejected (USAGE) when stdio is not
/// a tty. The security downgrade needs explicit confirmation: either `--yes`,
/// or a `tty_confirm` `(y/N)` prompt when a tty is attached. (`Command::output()`
/// pipes stdio, so `has_tty()` is false here — this pins the no-tty error path,
/// and the hint names both `--yes` and a tty.)
#[test]
fn store_use_plaintext_without_yes_is_rejected_as_usage() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["store", "use", "plaintext"], &cfg);
    assert_eq!(
        code,
        exit_code::USAGE,
        "store use plaintext without --yes exits USAGE: {stderr}"
    );
    assert!(
        stderr.contains("--yes") && stderr.contains("tty"),
        "rejection hints at --yes and a tty: {stderr}"
    );
}

/// `store use plaintext --yes` succeeds (fresh config → downgrade is a no-op
/// that confirms the path works end-to-end).
#[test]
fn store_use_plaintext_with_yes_succeeds() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["store", "use", "plaintext", "--yes"], &cfg);
    assert_eq!(
        code,
        exit_code::SUCCESS,
        "store use plaintext --yes exits SUCCESS: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// NOT_FOUND (4): unknown references + dangling credential
// ---------------------------------------------------------------------------

/// `cred edit <unknown>` → NOT_FOUND. The credential table has no such entry.
#[test]
fn cred_edit_unknown_name_exits_not_found() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["cred", "edit", "nope", "--user", "u"], &cfg);
    assert_eq!(
        code,
        exit_code::NOT_FOUND,
        "unknown credential exits NOT_FOUND: {stderr}"
    );
    assert!(
        stderr.contains("not found"),
        "error names the missing credential: {stderr}"
    );
}

/// `host add <name> --credential <unknown>` → NOT_FOUND, and the failure is a
/// *local* validation that fires before any network IO (the dangling reference
/// is caught at name-resolution time, not deferred to the connect path). We
/// assert the code + that stderr does not mention a network/ssh-keyscan failure.
#[test]
fn host_add_dangling_credential_exits_not_found_before_network() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(
        &[
            "host",
            "add",
            "web1",
            "--host",
            "1.1.1.1",
            "--credential",
            "nope",
        ],
        &cfg,
    );
    assert_eq!(
        code,
        exit_code::NOT_FOUND,
        "dangling --credential exits NOT_FOUND: {stderr}"
    );
    assert!(
        stderr.contains("not found") && !stderr.contains("keyscan") && !stderr.contains("network"),
        "fail-fast local check (no network IO attempted): {stderr}"
    );
}

// ---------------------------------------------------------------------------
// VALIDATION (6): missing required field
// ---------------------------------------------------------------------------

/// `host add <name>` with no `--host` → VALIDATION. The name is given but the
/// required `host` field is missing; this is distinct from a usage error (the
/// invocation shape is valid, the content fails validation).
#[test]
fn host_add_name_but_no_host_exits_validation() {
    let (cfg, _dir) = fresh_config();
    let (code, _stdout, stderr) = run(&["host", "add", "x"], &cfg);
    assert_eq!(
        code,
        exit_code::VALIDATION,
        "name without --host exits VALIDATION: {stderr}"
    );
    assert!(
        stderr.contains("--host"),
        "error names the missing required field: {stderr}"
    );
}
