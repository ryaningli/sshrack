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

/// In-memory `SecretBackend` for the keyring-mode connect test. Core's
/// `FakeBackend` is `pub(crate)` and invisible to integration tests, so the
/// test defines its own minimal impl keyed by the raw account key (mirroring
/// `OsKeyring`). Used only to seed the inline-key slots and let `resolve`
/// read them back — no daemon dependency, hermetic in CI.
struct LocalFakeBackend {
    entries: std::cell::RefCell<std::collections::HashMap<String, String>>,
}

impl LocalFakeBackend {
    fn new() -> Self {
        Self {
            entries: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }
}

impl sshrack_core::secret::SecretBackend for LocalFakeBackend {
    fn set_at(&self, key: &str, secret: &str) -> Result<(), sshrack_core::error::SshrackError> {
        self.entries
            .borrow_mut()
            .insert(key.to_string(), secret.to_string());
        Ok(())
    }
    fn get(
        &self,
        key: &str,
    ) -> Result<Option<Zeroizing<String>>, sshrack_core::error::SshrackError> {
        Ok(self
            .entries
            .borrow()
            .get(key)
            .map(|p| Zeroizing::new(p.clone())))
    }
    fn delete_at(&self, key: &str) -> Result<(), sshrack_core::error::SshrackError> {
        self.entries.borrow_mut().remove(key);
        Ok(())
    }
    fn available(&self) -> bool {
        true
    }
}

/// Keyring-mode inline-key end-to-end: a host whose inline key text lives in
/// the OS keyring (the body is the sealed marker form) must, through the
/// connect pre-exec path, (a) materialize a `0600` temp file containing the
/// key text, (b) carry `-i <tempfile>` in the ssh argv, and (c) NEVER let the
/// key text itself appear in argv. This is the secret-never-in-argv invariant
/// extended to keyring-backed inline keys (Task 4's `resolve` reads the text
/// from the backend; Task 8 wires it through the connect path).
///
/// Drives the real `credential::resolve` decision (the keyring-marker inline
/// branch) into the real `materialize_inline_key` + `ssh::build` + `launch`,
/// then asserts what the child actually observed. The temp file is read
/// before the artifact drops (its `Drop` deletes it on launch completion).
#[test]
fn keyring_mode_inline_key_materializes_temp_file_and_never_leaks_to_argv() {
    use sshrack_core::config::schema::{
        Auth, CredentialBody, Host, InlineKey, KeySource, SecretStore, SshrackConfig,
    };
    use sshrack_core::connect::ssh;
    use sshrack_core::credential::{PasswordSource, resolve};
    use sshrack_core::id::{OwnerKind, keyring_key_inline_cert, keyring_key_inline_priv};
    use sshrack_core::secret::SecretBackend;
    use ulid::Ulid;

    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");

    // A keyring-mode config + a host whose inline key is the sealed marker
    // form (ik.keyring == true, no in-body text). The plaintext lives in the
    // backend slots — seeded below.
    let cfg = SshrackConfig {
        store: Some(SecretStore::Keyring),
        ..Default::default()
    };
    let backend = LocalFakeBackend::new();
    let host_id = Ulid::new();
    let h = Host {
        id: host_id,
        name: "kr-ik-host".into(),
        host: "10.0.0.5".into(),
        port: 22,
        auth: Auth::inline(CredentialBody {
            user: "deploy".into(),
            password: None,
            key: Some(KeySource::Inline(InlineKey {
                private_key: None,
                certificate: None,
                keyring: true,
            })),
            keyring: false,
        }),
    };
    const PRIVATE_TEXT: &str = "PRIVATEKEYTEXT-NEVER-IN-ARGV";
    const CERT_TEXT: &str = "CERTTEXT-NEVER-IN-ARGV";
    backend
        .set_at(
            &keyring_key_inline_priv(OwnerKind::Host, &host_id),
            PRIVATE_TEXT,
        )
        .unwrap();
    backend
        .set_at(
            &keyring_key_inline_cert(OwnerKind::Host, &host_id),
            CERT_TEXT,
        )
        .unwrap();

    // Step 1: resolve reads the inline-key text from the backend slots.
    let mut resolved = resolve(&h, &cfg, None, &backend).expect("resolve ok");
    let inline_mat = resolved
        .inline_key
        .as_ref()
        .expect("inline key materialized from keyring slots");
    assert_eq!(inline_mat.private.as_str(), PRIVATE_TEXT);
    assert_eq!(
        inline_mat.certificate.as_ref().map(|c| c.as_str()),
        Some(CERT_TEXT)
    );

    // Step 2: materialize the temp file. The artifact's Drop deletes the files
    // — hold it across launch so the plaintext outlives the ssh process.
    let key_artifact = sshrack_core::connect::materialize_inline_key(&mut resolved)
        .expect("materialize ok")
        .expect("artifact present for inline key");
    let temp_private_path = resolved
        .key_path
        .clone()
        .expect("key_path points at the temp file");

    // (a) The materialized temp file contains the private key text.
    let temp_contents = std::fs::read_to_string(&temp_private_path)
        .expect("temp private file readable before drop");
    assert!(
        temp_contents.contains(PRIVATE_TEXT),
        "temp file must contain the private key text"
    );
    // The certificate sits beside it as <private>-cert.pub (OpenSSH auto-load).
    let cert_path = {
        let mut p = temp_private_path.clone().into_os_string();
        p.push("-cert.pub");
        std::path::PathBuf::from(p)
    };
    let cert_contents =
        std::fs::read_to_string(&cert_path).expect("temp cert file readable before drop");
    assert!(
        cert_contents.contains(CERT_TEXT),
        "temp cert file must contain the certificate text"
    );

    // Step 3: build the ssh argv. (b) It carries `-i <tempfile>`. (c) The key
    // text NEVER appears in argv (the secret-never-in-argv invariant).
    let argv = ssh::build(&resolved, &h, &ssh::Overrides::default(), &[]);
    let i_idx = argv
        .iter()
        .position(|a| a == "-i")
        .expect("argv carries -i for an inline-key host");
    assert_eq!(
        argv[i_idx + 1],
        temp_private_path.to_string_lossy(),
        "-i points at the materialized temp file"
    );
    for arg in &argv {
        assert!(
            !arg.contains(PRIVATE_TEXT) && !arg.contains(CERT_TEXT),
            "key text leaked into ssh argv: {arg}"
        );
    }

    // Step 4: drive the real launcher with the shim so the end-to-end path is
    // locked (launch must not mutate argv to inject key text either). The
    // artifact is held across launch and drops afterward, wiping both files.
    let launch_argv: Vec<String> = std::iter::once(shim_path.to_string_lossy().into_owned())
        .chain(argv.iter().skip(1).cloned())
        .collect();
    let code = launch_retrying_etxtbsy(launch_argv, PasswordSource::None, &self_exe, None);
    assert_eq!(code, 0, "shim exits 0");
    let cap = read_capture(&capture_path);
    let received = &cap.argv[1..]; // skip argv[0] (the shim path)
    let shim_i_idx = received
        .iter()
        .position(|a| a == "-i")
        .expect("shim observed -i in argv");
    assert_eq!(
        received[shim_i_idx + 1],
        temp_private_path.to_string_lossy(),
        "shim saw -i pointed at the temp file"
    );
    for arg in received {
        assert!(
            !arg.contains(PRIVATE_TEXT) && !arg.contains(CERT_TEXT),
            "key text leaked into the shim's captured argv: {arg}"
        );
    }

    // After launch the artifact drops and deletes both temp files.
    drop(key_artifact);
    assert!(
        !temp_private_path.exists(),
        "temp private file deleted after the artifact drops"
    );
    assert!(
        !cert_path.exists(),
        "temp cert file deleted after the artifact drops"
    );
}

// ===========================================================================
// scp `build -> launch` shim integration (Task 5.1)
// ===========================================================================
// `scp::build` assembles a `ScpPlan { argv, password, remote_hosts,
// key_artifact, .. }` whose `argv[0] == "scp"`. `connect::launch` does
// `Command::new(&argv[0])`, so swapping `argv[0]` for the shim path runs the
// shim (not a real scp) without PATH lookup or network. These tests drive the
// real `scp::build` -> real `connect::launch` -> shim capture, then assert the
// argv shape and the password/key-text-never-in-argv-or-env invariant.

/// A scp plan for an inline-password host, driven through `connect::launch`
/// with `argv[0]` swapped for the shim, must (a) carry `user@host:path` and
/// `-P <port>` in the argv the shim observed, and (b) never let the password
/// string appear in the captured argv or env (the Inline source stages a temp
/// file pointed at by `SSHRACK_ASKPASS_FILE`, never the secret itself).
#[test]
fn scp_build_drives_launch_with_shim_argv_and_password_never_in_argv() {
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use sshrack_core::connect::scp;
    use sshrack_core::connect::ssh::Overrides;
    use ulid::Ulid;

    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");

    // Undecided store + inline password body resolves to PasswordSource::Inline,
    // so launch stages a 0600 temp file the askpass helper reads.
    let cfg = SshrackConfig {
        hosts: vec![Host {
            id: Ulid::new(),
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            auth: Auth::inline(CredentialBody::new("deploy").with_password("hunter2")),
        }],
        ..Default::default()
    };
    let backend = LocalFakeBackend::new();

    let plan = scp::build(
        &["local.txt".into(), "web1:/srv/app".into()],
        &cfg,
        &Overrides::default(),
        None,
        &backend,
    )
    .expect("scp build ok");

    // (a) argv shape: scp argv[0]; -P <port>; the rewritten user@host:path
    // operand. No key on this host -> no -i. The password lives only in
    // plan.password, never in argv.
    assert_eq!(plan.argv[0], "scp");
    assert!(
        plan.argv.iter().any(|a| a == "deploy@10.0.0.5:/srv/app"),
        "scp argv rewrites name:path to user@host:path: {:?}",
        plan.argv
    );
    let p_idx = plan
        .argv
        .iter()
        .position(|a| a == "-P")
        .expect("-P present");
    assert_eq!(plan.argv[p_idx + 1], "2222");
    assert!(
        !plan.argv.iter().any(|a| a == "-i"),
        "a password-only host must not carry -i"
    );
    for arg in &plan.argv {
        assert!(!arg.contains("hunter2"), "password in scp argv: {arg}");
    }

    // (b) Drive the real launcher with argv[0] swapped for the shim path so the
    // end-to-end launch path is exercised hermetically (no PATH, no network).
    let mut launch_argv = plan.argv.clone();
    launch_argv[0] = shim_path.to_string_lossy().into_owned();
    let code = launch_retrying_etxtbsy(launch_argv, plan.password.clone(), &self_exe, None);
    assert_eq!(code, 0, "shim exits 0");
    let cap = read_capture(&capture_path);

    // The shim observed the scp operand and -P, but never the password.
    let received = &cap.argv[1..]; // skip argv[0] (the shim path)
    assert!(received.iter().any(|a| a == "deploy@10.0.0.5:/srv/app"));
    let shim_p_idx = received
        .iter()
        .position(|a| a == "-P")
        .expect("shim saw -P");
    assert_eq!(received[shim_p_idx + 1], "2222");
    assert!(
        !received.iter().any(|a| a == "-i"),
        "shim must not see -i for a password-only host"
    );
    for arg in received {
        assert!(!arg.contains("hunter2"), "password in shim argv: {arg}");
    }
    // The Inline source stages a temp file pointed at by SSHRACK_ASKPASS_FILE;
    // the password itself never appears in any captured env value.
    assert!(
        cap.env.contains_key("SSHRACK_ASKPASS_FILE"),
        "Inline source must stage the askpass file env, got {:?}",
        cap.env
    );
    for (k, v) in &cap.env {
        assert!(!v.contains("hunter2"), "password leaked into env {k}={v}");
    }
}

/// Two remote operands: build records both endpoints in `remote_hosts` (for
/// host-key confirmation), but the password/identity come from the FIRST remote
/// only — the launch path never re-resolves after the network host-key check.
/// This is a plan-level assertion (the "first host wins" contract lives in
/// `build`, not in `launch`).
#[test]
fn scp_multi_remote_first_host_wins_password() {
    use sshrack_core::config::schema::{Auth, CredentialBody, Host, SshrackConfig};
    use sshrack_core::connect::scp;
    use sshrack_core::connect::ssh::Overrides;
    use ulid::Ulid;

    let cfg = SshrackConfig {
        hosts: vec![
            Host {
                id: Ulid::new(),
                name: "web1".into(),
                host: "10.0.0.5".into(),
                port: 2222,
                auth: Auth::inline(CredentialBody::new("deploy").with_password("pw1-first")),
            },
            Host {
                id: Ulid::new(),
                name: "web2".into(),
                host: "10.0.0.6".into(),
                port: 3322,
                auth: Auth::inline(CredentialBody::new("ops").with_password("pw2-second")),
            },
        ],
        ..Default::default()
    };
    let backend = LocalFakeBackend::new();

    let plan = scp::build(
        &[
            "archive.tar".into(),
            "web1:/srv/a".into(),
            "web2:/srv/b".into(),
        ],
        &cfg,
        &Overrides::default(),
        None,
        &backend,
    )
    .expect("scp build ok");

    // Both remotes recorded for host-key confirmation, first-appearance order.
    assert_eq!(plan.remote_hosts.len(), 2, "two distinct remote endpoints");
    assert_eq!(plan.remote_hosts[0].0, "10.0.0.5");
    assert_eq!(plan.remote_hosts[0].1, 2222);
    assert_eq!(plan.remote_hosts[1].0, "10.0.0.6");
    assert_eq!(plan.remote_hosts[1].1, 3322);

    // The FIRST remote's password wins. -P also comes from the first remote
    // (web1's 2222), not web2's 3322.
    match &plan.password {
        PasswordSource::Inline(p) => assert_eq!(
            p.as_str(),
            "pw1-first",
            "first remote's password must win, got {p:?}"
        ),
        other => panic!("expected Inline password from first host, got {other:?}"),
    }
    let p_idx = plan
        .argv
        .iter()
        .position(|a| a == "-P")
        .expect("-P present");
    assert_eq!(
        plan.argv[p_idx + 1],
        "2222",
        "-P comes from the first remote (web1), not web2"
    );
    // Both operands rewritten to user@host:path with each host's own user.
    assert!(plan.argv.iter().any(|a| a == "deploy@10.0.0.5:/srv/a"));
    assert!(plan.argv.iter().any(|a| a == "ops@10.0.0.6:/srv/b"));
}

/// An inline (pasted) identity key on a scp host: build materializes a 0600
/// temp file, argv's `-i` points at that temp path (never the key text), and
/// the plan holds the `KeyArtifact` so the file survives launch. Driven through
/// the real launcher with the shim, the secret-never-in-argv invariant extends
/// end-to-end through the connect path.
#[test]
fn scp_identity_temp_file_is_referenced_not_inlined() {
    use sshrack_core::config::schema::{
        Auth, CredentialBody, Host, InlineKey, KeySource, Secret, SshrackConfig,
    };
    use sshrack_core::connect::scp;
    use sshrack_core::connect::ssh::Overrides;
    use ulid::Ulid;

    const PRIVATE_TEXT: &str = "SCP-INLINE-KEY-NEVER-IN-ARGV";

    let (_dir, shim_path, capture_path) = fresh_shim();
    let self_exe = std::env::current_exe().expect("current_exe");

    let cfg = SshrackConfig {
        hosts: vec![Host {
            id: Ulid::new(),
            name: "ik-host".into(),
            host: "10.0.0.5".into(),
            port: 22,
            auth: Auth::inline(CredentialBody {
                user: "deploy".into(),
                password: None,
                key: Some(KeySource::Inline(InlineKey {
                    private_key: Some(Secret::Plain(PRIVATE_TEXT.into())),
                    certificate: None,
                    keyring: false,
                })),
                keyring: false,
            }),
        }],
        ..Default::default()
    };
    let backend = LocalFakeBackend::new();

    let plan = scp::build(
        &["file.bin".into(), "ik-host:/tmp/".into()],
        &cfg,
        &Overrides::default(),
        None,
        &backend,
    )
    .expect("scp build ok");

    // build materializes the inline key to a 0600 temp file and points -i at it.
    let i_idx = plan
        .argv
        .iter()
        .position(|a| a == "-i")
        .expect("-i present for an inline-key host");
    let temp_path = std::path::PathBuf::from(&plan.argv[i_idx + 1]);
    assert!(
        temp_path.to_string_lossy().contains("sshrack-key-"),
        "-i should point at a sshrack temp key file, got {temp_path:?}"
    );
    for arg in &plan.argv {
        assert!(!arg.contains(PRIVATE_TEXT), "key text in scp argv: {arg}");
    }
    let artifact = plan
        .key_artifact
        .as_ref()
        .expect("build must hold the KeyArtifact so the temp file survives launch");
    let _ = artifact; // referenced to assert presence; held alive by `plan`
    // The temp file contains the materialized key text while the plan (and its
    // artifact) is alive.
    assert!(
        std::fs::read_to_string(&temp_path)
            .map(|c| c.contains(PRIVATE_TEXT))
            .unwrap_or(false),
        "temp key file at {temp_path:?} must contain the private key text"
    );

    // Drive the real launcher with the shim so the end-to-end path is locked:
    // launch must not mutate argv to inject key text either.
    let mut launch_argv = plan.argv.clone();
    launch_argv[0] = shim_path.to_string_lossy().into_owned();
    let code = launch_retrying_etxtbsy(launch_argv, plan.password.clone(), &self_exe, None);
    assert_eq!(code, 0, "shim exits 0");
    let cap = read_capture(&capture_path);

    // The shim observed -i pointed at the SAME temp file, and never the key text.
    let received = &cap.argv[1..]; // skip argv[0] (the shim path)
    let shim_i_idx = received
        .iter()
        .position(|a| a == "-i")
        .expect("shim saw -i");
    assert_eq!(
        received[shim_i_idx + 1],
        temp_path.to_string_lossy(),
        "shim saw -i pointed at the materialized temp key file"
    );
    for arg in received {
        assert!(
            !arg.contains(PRIVATE_TEXT),
            "key text leaked into shim argv: {arg}"
        );
    }

    // Drop the plan (and its artifact) AFTER launch so the temp file outlives
    // scp; the artifact's Drop removes the temp key file.
    drop(plan);
    assert!(
        !temp_path.exists(),
        "temp key file deleted after the plan (and its artifact) drops"
    );
}
