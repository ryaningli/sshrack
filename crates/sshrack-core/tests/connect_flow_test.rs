//! End-to-end connect-flow test: a real subprocess for `connect::launch` driven
//! by a fake `ssh` shim.
//!
//! This is the integration layer over the connect path. The unit tests in
//! `connect::ssh` cover pure argv assembly, and the `env_for`/`askpass_env_for`
//! unit tests cover the env shape in isolation. This test exercises the real
//! `connect::launch` function end-to-end: it spawns a child (a fake `ssh` shim
//! that records its argv + selected environment to a temp file), lets the
//! production env wiring run, then asserts what the child actually observed.
//!
//! Why this lives at the core layer (not the CLI binary): the full CLI connect
//! path (`cmd::connect::run`) calls `hostkey::run_host_key_flow`, whose
//! `known_hosts` path is hardcoded to `~/.ssh/known_hosts` with no env override
//! and which runs real `ssh-keyscan` against the target. That is not hermetic
//! (it mutates the user's known_hosts and touches the network). `connect::launch`
//! is the actual env-wiring + spawn seam and is `pub`, so driving it directly
//! with a fake `ssh` gives a hermetic real-subprocess test of the connect flow.
//!
//! Hermeticity: the shim is an absolute path used as `argv[0]`, so `PATH` is
//! never consulted to find `ssh` (no `PATH` mutation, no `set_var`); no network
//! is touched (the shim exits 0 without connecting); and `SSHRACK_PASSPHRASE`
//! in the parent env does not affect the launcher (it never reads env vars).

use std::path::Path;

use sshrack_core::connect;
use sshrack_core::credential::PasswordSource;
use zeroize::Zeroizing;

/// A parsed capture from the fake `ssh` shim: the argv it received, plus the
/// selected environment variables sshrack's launcher set.
#[derive(Debug)]
struct ShimCapture {
    argv: Vec<String>,
    env: std::collections::HashMap<String, String>,
}

/// Write a fake `ssh` shell script to `shim_path` that records its argv and the
/// sshrack-relevant environment variables to `out_path`, then exits 0.
///
/// The shim base64-encodes each argv element (so embedded newlines/NULs in a
/// remote command survive), prints them one per line, then a `---ENV---`
/// separator and each captured `KEY=VALUE` pair. Reading uses the same framing.
fn write_ssh_shim(shim_path: &Path, out_path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let out = out_path.to_string_lossy();
    // Capture argv (base64 per element, including $0) then env vars. Env values
    // for our controlled inputs contain no newlines, so plain KEY=VALUE works.
    let script = format!(
        "#!/bin/sh\n\
         : > '{out}'\n\
         for a in \"$0\" \"$@\"; do printf '%s\\n' \"$(printf '%s' \"$a\" | base64)\" >> '{out}'; done\n\
         printf '%s\\n' '---ENV---' >> '{out}'\n\
         for k in SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY SSHRACK_ASKPASS_FILE SSHRACK_KEYRING_KEY SSHRACK_HOST_ID SSHRACK_CONFIG; do\n\
           eval \"v=\\$$k\"\n\
           if [ -n \"${{v:+set}}\" ]; then printf '%s=%s\\n' \"$k\" \"$v\" >> '{out}'; fi\n\
         done\n\
         exit 0\n",
    );
    std::fs::write(shim_path, script)?;
    std::fs::set_permissions(shim_path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Read the shim's capture file back into structured form.
fn read_capture(out_path: &Path) -> ShimCapture {
    let contents = std::fs::read_to_string(out_path).expect("shim capture file readable");
    let mut lines = contents.lines();
    let mut argv: Vec<String> = Vec::new();
    for line in lines.by_ref() {
        if line == "---ENV---" {
            break;
        }
        // base64-decode each argv element. The first element is argv[0] (the
        // shim path) because the shim echoes "$0" "$@".
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(line.trim())
            .expect("base64 argv line");
        argv.push(String::from_utf8(bytes).expect("argv utf8"));
    }
    let mut env: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }
    ShimCapture { argv, env }
}

/// Set up a fresh shim in a temp dir and return (shim_path, capture_path, dir).
fn fresh_shim() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let shim = dir.path().join("ssh");
    let capture = dir.path().join("capture.txt");
    write_ssh_shim(&shim, &capture).expect("write shim");
    (dir, shim, capture)
}

/// Drive `connect::launch` retrying transient ETXTBSY (errno 26, "Text file
/// busy"). Under `cargo test --workspace` many binaries run in parallel and a
/// freshly-written shim script can be exec'd before its directory entry fully
/// settles; the error vanishes on immediate retry. Production `launch` does NOT
/// retry — a real ETXTBSY there signals a genuine problem, not a race.
fn launch_retrying_etxtbsy(
    argv: Vec<String>,
    source: PasswordSource,
    self_exe: &Path,
    config_path: Option<&Path>,
) -> i32 {
    let mut last = String::new();
    for _ in 0..6 {
        match connect::launch(argv.clone(), source.clone(), self_exe, config_path) {
            Ok(code) => return code,
            Err(sshrack_core::error::SshrackError::Io(io)) if io.raw_os_error() == Some(26) => {
                last = format!("{io}");
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(e) => panic!("launch failed (non-transient): {e}"),
        }
    }
    panic!("launch failed: ETXTBSY persisted across retries ({last})");
}

/// A key-only host: the launcher sets NO askpass env at all. There is no
/// account password to inject, so ssh must NOT be pointed at our payload-less
/// askpass helper — if it were, an encrypted private key would make ssh call
/// the helper (which has nothing to deliver) and fail. Leaving `SSH_ASKPASS`
/// unset lets ssh fall back to `/dev/tty` and prompt the user for the key
/// passphrase itself. argv shape is unaffected. This is the happy path for the
/// most common host shape.
#[test]
fn key_only_host_launches_ssh_with_argv_and_no_askpass_env() {
    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");

    // argv mirrors what connect::ssh::build produces for a key host. argv[0]
    // is the shim path so Command::new(&argv[0]) runs the shim without PATH.
    let argv: Vec<String> = vec![
        shim_path.to_string_lossy().into_owned(),
        "-l".into(),
        "deploy".into(),
        "-p".into(),
        "2222".into(),
        "-i".into(),
        "/home/u/.ssh/id_ed25519".into(),
        "10.0.0.5".into(),
        "uname".into(),
        "-r".into(),
    ];
    let code = launch_retrying_etxtbsy(argv, PasswordSource::None, &self_exe, None);
    assert_eq!(code, 0, "shim exits 0");
    let cap = read_capture(&capture_path);

    // (a) argv shape: ssh argv[0] is the shim; the rest is what ssh received.
    // The shim echoes "$0" "$@", so cap.argv[0] is the shim path (the launcher
    // set argv[0] = shim path, not "ssh" — that is expected for this seam).
    let received = &cap.argv[1..];
    // -l <user>
    let l_idx = received.iter().position(|a| a == "-l").expect("-l present");
    assert_eq!(received[l_idx + 1], "deploy");
    // -p <port>
    let p_idx = received.iter().position(|a| a == "-p").expect("-p present");
    assert_eq!(received[p_idx + 1], "2222");
    // -i <identity>
    let i_idx = received.iter().position(|a| a == "-i").expect("-i present");
    assert_eq!(received[i_idx + 1], "/home/u/.ssh/id_ed25519");
    // host then remote command, verbatim and in order.
    let host_idx = received
        .iter()
        .position(|a| a == "10.0.0.5")
        .expect("host present");
    assert_eq!(&received[host_idx + 1..], &["uname", "-r"]);

    // (b) The launcher adds no askpass env for a key-only host. SSH_ASKPASS and
    // SSH_ASKPASS_REQUIRE are what make ssh call the helper — neither may be
    // set, nor may the payload envs. (DISPLAY alone never triggers askpass, and
    // the child inherits the parent's env, so DISPLAY is not asserted here —
    // the pure `env_for(None)` unit test locks that the launcher adds nothing.)
    for k in [
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "SSHRACK_ASKPASS_FILE",
        "SSHRACK_KEYRING_KEY",
    ] {
        assert!(
            !cap.env.contains_key(k),
            "key-only host must not set askpass env {k}, got {:?}",
            cap.env
        );
    }
}

/// The keyring path: the launcher sets `SSHRACK_KEYRING_KEY` (and NOT the
/// askpass file), because the plaintext lives in the OS keyring and the helper
/// fetches it directly. No plaintext exists in the parent process.
#[test]
fn keyring_source_sets_keyring_env_not_file() {
    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");
    let argv: Vec<String> = vec![shim_path.to_string_lossy().into_owned(), "10.0.0.5".into()];
    let code = launch_retrying_etxtbsy(
        argv,
        PasswordSource::Keyring {
            key: "host:01J".into(),
        },
        &self_exe,
        None,
    );
    assert_eq!(code, 0);
    let cap = read_capture(&capture_path);
    assert_eq!(
        cap.env.get("SSHRACK_KEYRING_KEY").map(String::as_str),
        Some("host:01J")
    );
    assert!(
        !cap.env.contains_key("SSHRACK_ASKPASS_FILE"),
        "keyring path must not set the askpass file"
    );
    // Triplet still present.
    assert!(cap.env.contains_key("SSH_ASKPASS"));
    assert_eq!(
        cap.env.get("SSH_ASKPASS_REQUIRE").map(String::as_str),
        Some("force")
    );
}

/// The inline (plaintext/vault) path: the launcher materializes a 0600 temp
/// file and points `SSHRACK_ASKPASS_FILE` at it. The shim must observe the file
/// env (and not the keyring key). The plaintext is delivered via the file, not
/// the parent env, so it never appears in `env` output.
#[test]
fn inline_source_stages_askpass_file_not_keyring() {
    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");
    let argv: Vec<String> = vec![shim_path.to_string_lossy().into_owned(), "10.0.0.5".into()];
    let code = launch_retrying_etxtbsy(
        argv,
        PasswordSource::Inline(Zeroizing::new("hunter2".into())),
        &self_exe,
        None,
    );
    assert_eq!(code, 0);
    let cap = read_capture(&capture_path);
    let file_env = cap
        .env
        .get("SSHRACK_ASKPASS_FILE")
        .expect("inline path sets the askpass file");
    // The launcher cleans up the file after the child exits, so only assert the
    // env was set to a non-empty path — the plaintext never appears in env.
    assert!(!file_env.is_empty(), "askpass file path is non-empty");
    assert!(
        !cap.env.contains_key("SSHRACK_KEYRING_KEY"),
        "inline path must not set the keyring key"
    );
    // The plaintext password must NOT leak into any captured env var.
    for (k, v) in &cap.env {
        assert!(!v.contains("hunter2"), "plaintext leaked into env: {k}={v}");
    }
}

/// `connect::env_for` is the public test seam over the env-wiring helper. Lock
/// the env shape for each `PasswordSource` variant as a pure (no-subprocess)
/// complement to the real-subprocess tests above: it documents exactly which
/// keys each variant sets, independent of any shell shim quirks.
#[test]
fn env_for_seam_documents_env_shape_per_source() {
    // None: no askpass env at all. A key-only connection has no account
    // password to inject, so ssh must NOT be pointed at our payload-less
    // askpass helper — leaving SSH_ASKPASS unset lets ssh prompt at /dev/tty
    // for an encrypted private key's passphrase itself.
    let none = connect::env_for(&PasswordSource::None, None);
    assert!(
        none.is_empty(),
        "key-only connections set no askpass env, got {none:?}"
    );

    // Keyring: triplet + keyring key, no file.
    let kr = connect::env_for(
        &PasswordSource::Keyring {
            key: "cred:01J".into(),
        },
        None,
    );
    let kr_map: std::collections::HashMap<&str, &str> =
        kr.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(kr_map.get("SSHRACK_KEYRING_KEY").copied(), Some("cred:01J"));
    assert!(!kr_map.contains_key("SSHRACK_ASKPASS_FILE"));

    // Config (plaintext mode): triplet + host id, no file, no keyring key.
    // SSHRACK_CONFIG is forwarded when the caller passes a config path so the
    // helper reads the same file the parent loaded.
    let cfg_env = connect::env_for(
        &PasswordSource::Config {
            host_id: "01HXYZ0000000000000000000Z".into(),
        },
        Some(std::path::Path::new("/custom/config.toml")),
    );
    let cfg_map: std::collections::HashMap<&str, &str> =
        cfg_env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(
        cfg_map.get("SSHRACK_HOST_ID").copied(),
        Some("01HXYZ0000000000000000000Z")
    );
    assert_eq!(
        cfg_map.get("SSHRACK_CONFIG").copied(),
        Some("/custom/config.toml")
    );
    assert!(
        !cfg_map.contains_key("SSHRACK_ASKPASS_FILE"),
        "config path must not stage a temp file"
    );
    assert!(
        !cfg_map.contains_key("SSHRACK_KEYRING_KEY"),
        "config path must not stage the keyring key"
    );
}

/// Plaintext-mode end-to-end: `credential::resolve` flips to the config channel
/// for a plaintext-mode host, and `connect::launch` must wire that channel
/// without writing a temp file. Drives the real `resolve` decision (Task 2's
/// one flipped branch) into the real `launch` subprocess, then asserts the
/// child observed `SSHRACK_HOST_ID` equal to the host's ULID, the
/// `SSHRACK_ASKPASS_FILE` env is absent (no temp file staged), and the
/// keyring env is absent. This is the integration lock that ties the resolve
/// flip to the connect wiring.
#[test]
fn plaintext_mode_host_resolves_to_config_channel_and_writes_no_temp_file() {
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SecretStore, SshrackConfig};
    use sshrack_core::credential::resolve;
    use sshrack_core::secret::OsKeyring;
    use ulid::Ulid;

    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");

    let host_id = Ulid::new();
    let h = Host {
        id: host_id,
        name: "web1".into(),
        host: "10.0.0.5".into(),
        port: 22,
        auth: Auth::inline(CredentialBody::new("deploy").with_password("hunter2")),
    };
    let cfg = SshrackConfig {
        store: Some(SecretStore::Plaintext),
        ..Default::default()
    };

    // The flipped decision point: plaintext mode resolves to the config channel.
    let resolved = resolve(&h, &cfg, None, &OsKeyring).expect("resolve ok");
    let host_id_emitted = match &resolved.password {
        PasswordSource::Config { host_id } => host_id.clone(),
        other => panic!("plaintext mode must resolve to Config, got {other:?}"),
    };
    assert_eq!(host_id_emitted, host_id.to_string());

    let argv: Vec<String> = vec![shim_path.to_string_lossy().into_owned(), "10.0.0.5".into()];
    let code = launch_retrying_etxtbsy(
        argv,
        resolved.password.clone(),
        &self_exe,
        None, // default config path; the shim does not read it
    );
    assert_eq!(code, 0, "shim exits 0");

    let cap = read_capture(&capture_path);

    // The child saw the host id (the helper resolves it back to the password).
    let expected_host_id = host_id.to_string();
    assert_eq!(
        cap.env.get("SSHRACK_HOST_ID").map(String::as_str),
        Some(expected_host_id.as_str()),
        "config channel must set SSHRACK_HOST_ID to the host's ULID"
    );

    // No temp file is staged: the askpass-file env is absent. The password
    // never exists as a standalone file in this path.
    assert!(
        !cap.env.contains_key("SSHRACK_ASKPASS_FILE"),
        "plaintext mode must not stage an askpass temp file"
    );
    assert!(
        !cap.env.contains_key("SSHRACK_KEYRING_KEY"),
        "plaintext mode must not set the keyring key"
    );

    // The askpass triplet is still wired so ssh actually invokes the helper.
    assert!(cap.env.contains_key("SSH_ASKPASS"));
    assert_eq!(
        cap.env.get("SSH_ASKPASS_REQUIRE").map(String::as_str),
        Some("force")
    );

    // The plaintext password must not leak into any captured env var.
    for (k, v) in &cap.env {
        assert!(!v.contains("hunter2"), "plaintext leaked into env: {k}={v}");
    }
}
