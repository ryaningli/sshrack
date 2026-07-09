//! Pure argv builders for the SFTP ControlMaster + `sftp` batch layer.
//!
//! Every function here is pure (no I/O, no env mutation) except
//! [`control_socket_path`], which reads `XDG_RUNTIME_DIR` and the pid. The dir
//! choice itself is factored into [`runtime_dir`] so it is unit-testable without
//! touching the real environment.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::schema::Host;
use crate::connect::ssh::{Overrides, connect_opts};
use crate::credential::ResolvedAuth;

/// Process-local counter so concurrent `control_socket_path()` calls within one
/// sshrack process never produce the same socket name. The pid already
/// separates processes; this separates sessions within a process.
static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Choose the runtime directory for the control socket: `$XDG_RUNTIME_DIR`
/// when set and non-empty, else [`std::env::temp_dir()`]. Pure — takes the env
/// value as a parameter so it is unit-testable without mutating the real
/// environment.
///
/// Rationale: `/tmp` is world-writable and sticky-leaves stale sockets; the
/// XDG runtime dir is per-user (`/run/user/<uid>`) and cleared on logout, so
/// sockets there never leak across users and are reaped on session end.
pub fn runtime_dir(xdg: Option<&Path>) -> PathBuf {
    match xdg {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::env::temp_dir(),
    }
}

/// Control socket path under `$XDG_RUNTIME_DIR` (falling back to the std temp
/// dir). Per-process, per-session unique so concurrent sshrack sftp sessions
/// never collide: `sshrack-mux-<pid>-<n>.sock` under [`runtime_dir`].
///
/// Reads `XDG_RUNTIME_DIR` from the real environment (the only non-pure step);
/// the dir choice itself is [`runtime_dir`] and is tested directly.
pub fn control_socket_path() -> PathBuf {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let dir = runtime_dir(xdg.as_deref());
    let n = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("sshrack-mux-{}-{n}.sock", std::process::id()))
}

/// `ssh -N -o ControlMaster=yes -o ControlPath=<sock> -o ConnectTimeout=10
///   -o ServerAliveInterval=15  <connect_opts> <host>` — owns the muxed
/// connection.
///
/// The master carries port/identity (via [`connect_opts`]) so the sftp mount
/// can carry only `ControlPath` + target. `-N` means no remote command — the
/// master just holds the connection open. `ConnectTimeout=10` bounds the first
/// connect; `ServerAliveInterval=15` lets a dead master detect a half-open
/// connection reasonably fast.
pub fn master_argv(
    resolved: &ResolvedAuth,
    host: &Host,
    overrides: &Overrides,
    sock: &Path,
) -> Vec<String> {
    let cp = format!("ControlPath={}", sock.display());
    let mut argv: Vec<String> = vec![
        "ssh".into(),
        "-N".into(),
        "-o".into(),
        "ControlMaster=yes".into(),
        "-o".into(),
        cp,
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=15".into(),
    ];
    argv.extend(connect_opts(resolved, host, overrides));
    argv.push(host.host.clone());
    argv
}

/// `sftp -b - -o ControlPath=<sock> <user@host>` — mounts the master. No
/// `-P`/`-i`/`-J`: the master already carries port/identity, and this avoids
/// the ssh `-p` vs sftp `-P` flag clash. `-b -` reads batch commands from
/// stdin so sshrack can drive `get`/`put` without the data stream touching
/// argv.
pub fn sftp_batch_argv(target: &str, sock: &Path) -> Vec<String> {
    vec![
        "sftp".into(),
        "-b".into(),
        "-".into(),
        "-o".into(),
        format!("ControlPath={}", sock.display()),
        target.into(),
    ]
}

/// `ssh -o ControlPath=<sock> -O check <target>` — readiness poll. Returns
/// success only when the master is up and the muxed connection is healthy.
pub fn control_check_argv(target: &str, sock: &Path) -> Vec<String> {
    vec![
        "ssh".into(),
        "-o".into(),
        format!("ControlPath={}", sock.display()),
        "-O".into(),
        "check".into(),
        target.into(),
    ]
}

/// `ssh -o ControlPath=<sock> -O exit <target>` — master teardown. Sent after
/// the sftp batch exits so the background `ssh -N` does not linger.
pub fn control_exit_argv(target: &str, sock: &Path) -> Vec<String> {
    vec![
        "ssh".into(),
        "-o".into(),
        format!("ControlPath={}", sock.display()),
        "-O".into(),
        "exit".into(),
        target.into(),
    ]
}

/// The sftp target string `<user>@<host>` used as sftp's last argv token. The
/// user comes from the resolved identity (so overrides are already applied);
/// the host is the network endpoint.
pub fn sftp_target(resolved: &ResolvedAuth, host: &Host) -> String {
    format!("{}@{}", resolved.user, host.host)
}

/// Shell-quote a path for an sftp batch line (`get`/`put` operands). Wraps the
/// value in `"..."` and backslash-escapes `"`, `\`, and `$`.
///
/// Minimal but correct for sftp operands: sftp's batch parser treats a quoted
/// token as a single operand, so filenames with spaces survive (the scp→sftp
/// lesson — scp's own arg parsing lost spaces that sftp's batch mode preserves
/// once quoted). Escaping `$` also prevents shell-style expansion if the batch
/// line ever round-trips through a shell context.
pub fn shell_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for ch in path.chars() {
        match ch {
            '"' | '\\' | '$' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{Auth, CredentialBody, Host};
    use crate::credential::{PasswordSource, ResolvedAuth};
    use std::path::PathBuf;

    fn host() -> Host {
        Host {
            id: crate::id::new_id(),
            name: "web1".into(),
            host: "192.168.1.10".into(),
            port: 2222,
            auth: Auth::inline(CredentialBody::new("deploy").with_key("~/.ssh/id_ed25519")),
        }
    }

    fn resolved() -> ResolvedAuth {
        ResolvedAuth {
            user: "deploy".into(),
            key_path: Some(PathBuf::from("~/.ssh/id_ed25519")),
            password: PasswordSource::None,
            inline_key: None,
        }
    }

    // ---- runtime_dir (pure) ----

    #[test]
    fn runtime_dir_uses_xdg_when_set_and_non_empty() {
        assert_eq!(
            runtime_dir(Some(Path::new("/run/user/1000"))),
            PathBuf::from("/run/user/1000")
        );
    }

    #[test]
    fn runtime_dir_falls_back_to_temp_when_xdg_none() {
        assert_eq!(runtime_dir(None), std::env::temp_dir());
    }

    #[test]
    fn runtime_dir_falls_back_to_temp_when_xdg_empty() {
        // An empty XDG_RUNTIME_DIR is treated as unset (defensive: some envs
        // set it blank, and an empty path is not a usable directory).
        assert_eq!(runtime_dir(Some(Path::new(""))), std::env::temp_dir());
    }

    // ---- control_socket_path ----

    #[test]
    fn control_socket_path_under_runtime_dir_with_mux_prefix() {
        let p = control_socket_path();
        let dir = runtime_dir(
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .as_deref(),
        );
        assert!(
            p.starts_with(&dir),
            "socket {p:?} must live under runtime dir {dir:?}"
        );
        let name = p
            .file_name()
            .expect("invariant: socket path always has a file name")
            .to_string_lossy()
            .into_owned();
        let prefix = format!("sshrack-mux-{}-", std::process::id());
        assert!(
            name.starts_with(&prefix),
            "socket name {name} must start with {prefix}"
        );
        assert!(
            name.ends_with(".sock"),
            "socket name {name} must end with .sock"
        );
    }

    #[test]
    fn control_socket_path_unique_across_calls() {
        // The process-local counter must make every call produce a distinct
        // path so concurrent sshrack sftp sessions never collide on one socket.
        let a = control_socket_path();
        let b = control_socket_path();
        assert_ne!(a, b, "consecutive control_socket_path() calls must differ");
    }

    // ---- master_argv ----

    #[test]
    fn master_argv_exact_shape() {
        // The fixture is key-only with no password, so `connect_opts` appends
        // its key-only tail (`-o IdentitiesOnly=yes -o PasswordAuthentication=no`)
        // after `-i <key>`. The SFTP master is non-interactive (no tty), so a
        // bad key fails faster here too — harmless and aligned with the
        // interactive `ssh` argv.
        let argv = master_argv(
            &resolved(),
            &host(),
            &Overrides::default(),
            Path::new("/run/user/1000/mux.sock"),
        );
        assert_eq!(
            argv,
            vec![
                "ssh".to_string(),
                "-N".to_string(),
                "-o".to_string(),
                "ControlMaster=yes".to_string(),
                "-o".to_string(),
                "ControlPath=/run/user/1000/mux.sock".to_string(),
                "-o".to_string(),
                "ConnectTimeout=10".to_string(),
                "-o".to_string(),
                "ServerAliveInterval=15".to_string(),
                "-l".to_string(),
                "deploy".to_string(),
                "-p".to_string(),
                "2222".to_string(),
                "-i".to_string(),
                "~/.ssh/id_ed25519".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                "-o".to_string(),
                "PasswordAuthentication=no".to_string(),
                "192.168.1.10".to_string(),
            ]
        );
    }

    #[test]
    fn master_argv_carries_overrides() {
        // CLI overrides (user/port/identity) flow through connect_opts into the
        // master argv, so `sftp <name>` honors the same flags as `ssh <name>`.
        let o = Overrides {
            user: Some("root".into()),
            port: Some(22000),
            identity: Some(PathBuf::from("/root-key")),
            ..Default::default()
        };
        let argv = master_argv(&resolved(), &host(), &o, Path::new("/tmp/m.sock"));
        assert!(argv.contains(&"root".to_string()));
        assert!(argv.contains(&"22000".to_string()));
        assert!(argv.contains(&"/root-key".to_string()));
        // Master-only tokens still present alongside overrides.
        assert!(argv.contains(&"-N".to_string()));
        assert!(argv.contains(&"ControlMaster=yes".to_string()));
        assert_eq!(argv.last(), Some(&"192.168.1.10".to_string()));
    }

    #[test]
    fn master_argv_no_identity_when_resolved_has_none() {
        // A password-only / default-auth resolved identity has no key path; the
        // master argv must then omit -i (ssh-agent / password path).
        let mut r = resolved();
        r.key_path = None;
        let argv = master_argv(&r, &host(), &Overrides::default(), Path::new("/tmp/m.sock"));
        assert!(!argv.contains(&"-i".to_string()));
    }

    // ---- sftp_batch_argv ----

    #[test]
    fn sftp_batch_argv_exact_shape() {
        // The sftp mount carries ONLY ControlPath + target: no -P/-i/-J (the
        // master already negotiated those; this avoids the -p/-P clash).
        let argv = sftp_batch_argv("deploy@192.168.1.10", Path::new("/run/user/1000/mux.sock"));
        assert_eq!(
            argv,
            vec![
                "sftp".to_string(),
                "-b".to_string(),
                "-".to_string(),
                "-o".to_string(),
                "ControlPath=/run/user/1000/mux.sock".to_string(),
                "deploy@192.168.1.10".to_string(),
            ]
        );
    }

    // ---- control_check_argv / control_exit_argv ----

    #[test]
    fn control_check_argv_exact_shape() {
        let argv = control_check_argv("deploy@192.168.1.10", Path::new("/run/user/1000/mux.sock"));
        assert_eq!(
            argv,
            vec![
                "ssh".to_string(),
                "-o".to_string(),
                "ControlPath=/run/user/1000/mux.sock".to_string(),
                "-O".to_string(),
                "check".to_string(),
                "deploy@192.168.1.10".to_string(),
            ]
        );
    }

    #[test]
    fn control_exit_argv_exact_shape() {
        let argv = control_exit_argv("deploy@192.168.1.10", Path::new("/run/user/1000/mux.sock"));
        assert_eq!(
            argv,
            vec![
                "ssh".to_string(),
                "-o".to_string(),
                "ControlPath=/run/user/1000/mux.sock".to_string(),
                "-O".to_string(),
                "exit".to_string(),
                "deploy@192.168.1.10".to_string(),
            ]
        );
    }

    // ---- sftp_target ----

    #[test]
    fn sftp_target_is_user_at_host() {
        assert_eq!(sftp_target(&resolved(), &host()), "deploy@192.168.1.10");
    }

    #[test]
    fn sftp_target_uses_resolved_user_not_host_auth() {
        // The resolved user wins (so a credential reference's user is used even
        // when the host's inline body named a different one). This is the same
        // precedence ssh::build applies for `-l`.
        let mut r = resolved();
        r.user = "release".into();
        assert_eq!(sftp_target(&r, &host()), "release@192.168.1.10");
    }

    // ---- shell_quote ----

    #[test]
    fn shell_quote_wraps_plain_in_double_quotes() {
        assert_eq!(shell_quote("plain"), "\"plain\"");
    }

    #[test]
    fn shell_quote_empty() {
        assert_eq!(shell_quote(""), "\"\"");
    }

    #[test]
    fn shell_quote_escapes_double_quote_backslash_dollar() {
        // Input:  a"b\c$d
        // Output: "a\"b\\c\$d"
        let q = shell_quote("a\"b\\c$d");
        assert_eq!(q, "\"a\\\"b\\\\c\\$d\"");
    }

    #[test]
    fn shell_quote_path_with_space_survives() {
        // The scp→sftp lesson: filenames with spaces must survive sftp batch
        // parsing once quoted.
        assert_eq!(shell_quote("my file.txt"), "\"my file.txt\"");
    }

    #[test]
    fn shell_quote_preserves_non_special_metacharacters() {
        // Characters that need NO escaping under sftp's batch quoting are left
        // alone (space, single quote, backtick, etc. — sftp batch does not
        // interpret shell metacharacters inside a quoted token).
        assert_eq!(shell_quote("a b'c`e"), "\"a b'c`e\"");
    }
}
