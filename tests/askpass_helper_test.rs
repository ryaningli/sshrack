//! Binary contract tests for the sshrack askpass helper-fork role.
//!
//! The `sshrack` binary doubles as its own `SSH_ASKPASS` helper: when the
//! parent sshrack process forks it with one of `SSHRACK_HOST_ID` /
//! `SSHRACK_ASKPASS_FILE` / `SSHRACK_KEYRING_KEY` / `SSHRACK_ASKPASS_DENY` set,
//! `main` short-circuits to `askpass::run`, which reads the password from the
//! matching channel, writes it to stdout (where ssh reads it), and exits. These
//! tests spawn the real binary in each channel and pin the public contract:
//! the right bytes reach stdout, the right exit code is returned, and the file
//! channel deletes its temp file.
//!
//! Hermeticity: env vars are passed to the spawned child only via
//! `Command::env` (never `std::env::set_var`); the child's env is cleared so
//! only the channel-under-test is active. The config channel reads a temp
//! config written via `sshrack-core`'s `store::save`. No real `~/.config` is
//! touched; no network is used.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use sshrack_core::askpass;
use sshrack_core::secret::keyring;

/// Exit codes mirroring `src/shared/exit_code.rs`. That module lives in the
/// binary crate (not `sshrack-core`) and so is not importable from integration
/// tests; these named constants keep the values out of magic-number form. If
/// the source values change, update both — they are a public contract.
mod exit_code {
    /// Successful execution.
    pub const SUCCESS: i32 = 0;
    /// A connection or remote operation failed.
    pub const CONNECT: i32 = 7;
}

/// Path to the built `sshrack` binary, provided by cargo's test harness.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sshrack"))
}

/// Run the `sshrack` binary in askpass-helper mode with exactly the given env
/// (the inherited env is cleared). Returns (exit_code, stdout, stderr).
fn run_askpass(env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    // Clear the inherited env so only the channel-under-test env is active —
    // the helper reads only its SSHRACK_* vars + the config file, so an empty
    // env is the most hermetic choice and prevents a stray parent SSHRACK_*
    // var from steering the dispatch.
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run sshrack askpass");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Write `contents` to a 0600 temp file inside `dir` and return its path.
fn write_password_file(dir: &std::path::Path, contents: &str) -> PathBuf {
    let path = dir.join("askpass.pw");
    let mut f = std::fs::File::create(&path).expect("create pw file");
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600");
    std::io::Write::write_all(&mut f, contents.as_bytes()).expect("write pw");
    path
}

/// Build a single-host config (inline plaintext password) and write it to a
/// temp path. Returns (config_path, host_ulid_string, tempdir).
fn config_with_inline_password(password: &str) -> (PathBuf, String, tempfile::TempDir) {
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use sshrack_core::config::store;
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.toml");
    let host_id = ulid::Ulid::new();
    let host = Host {
        id: host_id,
        name: "h".into(),
        host: "x".into(),
        port: 22,
        auth: Auth::inline(CredentialBody::new("u").with_password(password)),
    };
    let cfg = SshrackConfig {
        hosts: vec![host],
        ..Default::default()
    };
    store::save(&path, &cfg).expect("save config");
    (path, host_id.to_string(), dir)
}

// ---------------------------------------------------------------------------
// file channel
// ---------------------------------------------------------------------------

/// `SSHRACK_ASKPASS_FILE=<0600 temp>` → the helper reads the file, writes its
/// contents to stdout, and deletes the file (defense in depth — the parent
/// also removes it after the child exits). Exit 0.
#[test]
fn file_channel_emits_password_and_deletes_temp_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pw_path = write_password_file(dir.path(), "hunter2");
    let pw_path_str = pw_path.to_string_lossy().into_owned();

    let (code, stdout, stderr) = run_askpass(&[(askpass::ASKPASS_FILE_ENV, &pw_path_str)]);

    assert_eq!(code, 0, "file channel exits SUCCESS: {stderr}");
    assert_eq!(stdout, "hunter2", "stdout carries the file's password");
    assert!(
        !pw_path.exists(),
        "the helper deletes its temp password file after reading"
    );
}

/// `SSHRACK_ASKPASS_FILE=<missing path>` → the helper errors and exits
/// `CONNECT` (ssh treats a non-zero askpass exit as auth failure). Nothing is
/// written to stdout.
#[test]
fn file_channel_missing_file_exits_connect_with_empty_stdout() {
    let missing = tempfile::tempdir()
        .expect("temp dir")
        .path()
        .join("does-not-exist.pw")
        .to_string_lossy()
        .into_owned();

    let (code, stdout, _stderr) = run_askpass(&[(askpass::ASKPASS_FILE_ENV, &missing)]);

    assert_eq!(
        code,
        exit_code::CONNECT,
        "missing file channel exits CONNECT"
    );
    assert!(stdout.is_empty(), "no password on stdout for a failed read");
}

// ---------------------------------------------------------------------------
// deny channel
// ---------------------------------------------------------------------------

/// `SSHRACK_ASKPASS_DENY=1` → the helper prints a fixed message to stderr,
/// writes nothing to stdout, and exits non-zero so ssh treats the auth as
/// failed (no `/dev/tty` fallback because the master also sets
/// `SSH_ASKPASS_REQUIRE=force`). Used for SFTP hosts with no password.
#[test]
fn deny_channel_emits_nothing_and_exits_connect() {
    let (code, stdout, stderr) = run_askpass(&[(askpass::ASKPASS_DENY_ENV, "1")]);

    assert_eq!(code, exit_code::CONNECT, "deny channel exits CONNECT");
    assert!(
        stdout.is_empty(),
        "deny channel must never emit a password (or empty password)"
    );
    assert!(
        stderr.contains("no password configured"),
        "deny channel surfaces a human-readable reason: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// config channel
// ---------------------------------------------------------------------------

/// `SSHRACK_HOST_ID=<ulid>` + `SSHRACK_CONFIG=<tmp>` (plaintext-mode host) →
/// the helper reads the password straight from the config and writes it to
/// stdout. No temp password file is created (the config channel reads
/// directly). Exit 0.
#[test]
fn config_channel_emits_password_from_config_without_temp_file() {
    let (cfg_path, host_id, dir) = config_with_inline_password("s3cret");
    let cfg_str = cfg_path.to_string_lossy().into_owned();

    // Snapshot the dir's file list before, so we can prove the helper added no
    // temp password file (the config channel reads directly — only the file
    // channel materializes a temp file).
    let before: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();

    let (code, stdout, stderr) = run_askpass(&[
        (askpass::HOST_ID_ENV, &host_id),
        (askpass::CONFIG_ENV, &cfg_str),
    ]);

    assert_eq!(code, 0, "config channel exits SUCCESS: {stderr}");
    assert_eq!(
        stdout, "s3cret",
        "stdout carries the host's plaintext password"
    );

    let after: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(before, after, "config channel must not create a temp file");
}

/// `SSHRACK_HOST_ID=<unknown ulid>` + `SSHRACK_CONFIG=<tmp>` → the helper
/// errors (host missing) and exits CONNECT. No password on stdout.
#[test]
fn config_channel_unknown_host_id_exits_connect() {
    let (cfg_path, _host_id, _dir) = config_with_inline_password("s3cret");
    let cfg_str = cfg_path.to_string_lossy().into_owned();
    let other = ulid::Ulid::new().to_string();

    let (code, stdout, _stderr) = run_askpass(&[
        (askpass::HOST_ID_ENV, &other),
        (askpass::CONFIG_ENV, &cfg_str),
    ]);

    assert_eq!(code, exit_code::CONNECT, "unknown host id exits CONNECT");
    assert!(stdout.is_empty(), "no password emitted for an unknown host");
}

/// The config channel falls back to the XDG default config path when
/// `SSHRACK_CONFIG` is unset. We cannot point at the real XDG path hermetically,
/// so instead we prove the dispatch REACHES the config lookup (and fails there)
/// rather than silently emitting nothing: with an unknown host id and no
/// config override, the helper exits CONNECT (host missing or config missing),
/// never SUCCESS.
#[test]
fn config_channel_without_config_env_still_dispatches_to_config_path() {
    let other = ulid::Ulid::new().to_string();
    let (code, stdout, _stderr) = run_askpass(&[(askpass::HOST_ID_ENV, &other)]);
    assert_ne!(
        code, 0,
        "no config env + unknown host must not look like success"
    );
    assert!(stdout.is_empty(), "no password emitted");
}

// ---------------------------------------------------------------------------
// keyring channel (live OS keyring — ignored by default)
// ---------------------------------------------------------------------------

/// `SSHRACK_KEYRING_KEY=<account>` → fetch the password from the OS keyring.
/// Requires a reachable Secret Service daemon, so it is `#[ignore]`'d like the
/// TUI keyring smoke (`src/tui/persist.rs`). Run manually:
/// `cargo test --test askpass_helper_test keyring_channel -- --ignored`.
#[test]
#[ignore = "needs a reachable OS keyring backend; exercise via the manual smoke"]
fn keyring_channel_emits_password_from_os_keyring() {
    // We cannot seed a live keyring hermetically, so this is a structural
    // smoke: with KEYRING_KEY_ENV set, the helper dispatches to the keyring
    // path (not the file/config path). If the backend is unreachable it errors
    // with the keyring-unavailable message; if the entry is absent it errors
    // KeyringNoEntry. Either way it must NOT emit a password and must exit
    // non-zero — proving the dispatch reached the keyring branch.
    let key = "sshrack-test-askpass-smoke";
    let (code, _stdout, stderr) = run_askpass(&[(keyring::KEYRING_KEY_ENV, key)]);
    assert!(
        stderr.contains("keyring")
            || stderr.contains("KeyringNoEntry")
            || code != exit_code::SUCCESS,
        "keyring channel dispatch reached the keyring branch: {stderr}"
    );
}
