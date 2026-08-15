//! Build the `ssh` argv from a resolved identity, a host's network fields, and
//! optional overrides.

use std::path::PathBuf;

use ulid::Ulid;

use crate::config::schema::Host;
use crate::credential::ResolvedAuth;

/// Per-invocation overrides (from CLI flags); `None`/`false` means "use resolved".
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub user: Option<String>,
    pub port: Option<u16>,
    pub identity: Option<PathBuf>,
    /// `--credential <name>`: reuse a `[[credentials]]` entry for this one
    /// connection (overlays the resolved auth). For an address target
    /// (unregistered `user@host`/IP) this is the identity source. The CLI
    /// resolves the name to the credential's stable [`Ulid`] before
    /// constructing this; the argv builder never sees the name.
    pub credential: Option<Ulid>,
}

/// The ssh connection options shared by the interactive `ssh` argv and the
/// SFTP master/sftp argv: `-l <user> -p <port> (-i <key>)?`, plus an optional
/// key-only tail (see below). Pure.
///
/// `resolved` supplies the auth identity (user, key). `host` supplies the
/// network endpoint (`port`). Overrides win over both. The identity is
/// `override > resolved.key_path` (ssh-agent covers the rest); absent when
/// neither is set.
///
/// When an identity is present AND [`crate::credential::PasswordSource::None`],
/// the function also appends `-o IdentitiesOnly=yes -o PasswordAuthentication=no`
/// so a bad/unreadable key fails fast instead of degrading to an interactive
/// password prompt (which is the prompt users Ctrl-C out of, leaking the
/// inline-key temp file).
pub fn connect_opts(resolved: &ResolvedAuth, host: &Host, overrides: &Overrides) -> Vec<String> {
    let mut opts: Vec<String> = Vec::new();

    let user = overrides.user.as_deref().unwrap_or(&resolved.user);
    opts.push("-l".into());
    opts.push(user.into());

    let port = overrides.port.unwrap_or(host.port);
    opts.push("-p".into());
    opts.push(port.to_string());

    // Identity: explicit override > resolved key. (ssh-agent handles the rest.)
    let identity = overrides.identity.as_ref().or(resolved.key_path.as_ref());
    if let Some(k) = identity {
        opts.push("-i".into());
        opts.push(k.to_string_lossy().into_owned());
    }

    // Key-only host (identity present, no account password): restrict ssh so a
    // bad/unreadable key fails fast with "Permission denied (publickey)" rather
    // than silently degrading to an interactive password prompt — which is the
    // prompt users Ctrl-C out of, leaking the inline-key temp file. We disable
    // the `password` method only (not keyboard-interactive), so key-then-2FA
    // flows still work; the host has no password secret anyway. IdentitiesOnly
    // additionally stops ssh dragging in unrelated ssh-agent keys.
    let has_identity = identity.is_some();
    let no_password = matches!(resolved.password, crate::credential::PasswordSource::None);
    if has_identity && no_password {
        opts.push("-o".into());
        opts.push("IdentitiesOnly=yes".into());
        opts.push("-o".into());
        opts.push("PasswordAuthentication=no".into());
    }

    // Host-level raw ssh flags, appended AFTER sshrack's own options above:
    // ssh applies the last `-o` for a repeated key, so a user's
    // `-o IdentitiesOnly=no` deliberately overrides the default. Invalid
    // input (hand-edited config) is dropped with a warning by `tokens`.
    if let Some(raw) = &host.ssh_args {
        opts.extend(crate::sshargs::tokens(raw));
    }

    opts
}

/// Assemble the full `ssh` argv.
///
/// `resolved` supplies the auth identity (user, key, password — password is
/// consumed by the caller via `connect::launch`, not here). `host` supplies the
/// network endpoint (`host`, `port`). Overrides win over both. The host's
/// `ssh_args` flags land at the end of the option block (via
/// [`connect_opts`]), before the destination.
pub fn build(
    resolved: &ResolvedAuth,
    host: &Host,
    overrides: &Overrides,
    remote_command: &[String],
) -> Vec<String> {
    let mut argv: Vec<String> = vec!["ssh".into()];
    argv.extend(connect_opts(resolved, host, overrides));
    argv.push(host.host.clone());
    argv.extend_from_slice(remote_command);
    argv
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
            ssh_args: None,
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

    #[test]
    fn interactive_shell_argv() {
        let argv = build(&resolved(), &host(), &Overrides::default(), &[]);
        assert_eq!(argv[0], "ssh");
        assert!(argv.contains(&"-l".to_string()));
        assert!(argv.contains(&"deploy".to_string()));
        assert!(argv.contains(&"-p".to_string()));
        assert!(argv.contains(&"2222".to_string()));
        assert!(argv.contains(&"-i".to_string()));
        assert!(argv.contains(&"192.168.1.10".to_string()));
        assert_eq!(argv.last(), Some(&"192.168.1.10".to_string()));
    }

    #[test]
    fn remote_command_appended() {
        let argv = build(
            &resolved(),
            &host(),
            &Overrides::default(),
            &["uname".into(), "-r".into()],
        );
        let host_idx = argv.iter().position(|a| a == "192.168.1.10").unwrap();
        assert_eq!(&argv[host_idx + 1..], &["uname", "-r"]);
    }

    #[test]
    fn overrides_win_over_resolved() {
        let o = Overrides {
            user: Some("root".into()),
            port: Some(22000),
            identity: Some(PathBuf::from("/other-key")),
            ..Default::default()
        };
        let argv = build(&resolved(), &host(), &o, &[]);
        assert!(argv.contains(&"root".to_string()));
        assert!(argv.contains(&"22000".to_string()));
        assert!(argv.contains(&"/other-key".to_string()));
        assert!(!argv.contains(&"deploy".to_string()));
    }

    #[test]
    fn resolved_user_used_when_no_override() {
        let argv = build(&resolved(), &host(), &Overrides::default(), &[]);
        assert!(argv.contains(&"deploy".to_string()));
    }

    #[test]
    fn connect_opts_returns_user_port_identity() {
        // The shared connection-option tokens reused by the SFTP master argv:
        // exactly `-l <user> -p <port> -i <key>` in this order, with no `ssh`
        // prefix and no host/command tail (those are the caller's concern).
        // The key-only-no-password tail (`-o IdentitiesOnly=yes
        // -o PasswordAuthentication=no`) is asserted separately; see
        // `connect_opts_key_only_no_password_restricts_to_publickey`.
        let opts = connect_opts(&resolved(), &host(), &Overrides::default());
        assert_eq!(
            opts,
            vec![
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
            ]
        );
    }

    #[test]
    fn connect_opts_drops_identity_when_neither_override_nor_resolved_key() {
        // No key path on the resolved auth and no identity override → no -i.
        let mut r = resolved();
        r.key_path = None;
        let opts = connect_opts(&r, &host(), &Overrides::default());
        assert!(!opts.contains(&"-i".to_string()));
        assert_eq!(
            opts,
            vec![
                "-l".to_string(),
                "deploy".to_string(),
                "-p".to_string(),
                "2222".to_string(),
            ]
        );
    }

    #[test]
    fn connect_opts_overrides_win_over_resolved() {
        let o = Overrides {
            user: Some("root".into()),
            port: Some(22000),
            identity: Some(PathBuf::from("/other-key")),
            ..Default::default()
        };
        let opts = connect_opts(&resolved(), &host(), &o);
        assert_eq!(
            opts,
            vec![
                "-l".to_string(),
                "root".to_string(),
                "-p".to_string(),
                "22000".to_string(),
                "-i".to_string(),
                "/other-key".to_string(),
                "-o".to_string(),
                "IdentitiesOnly=yes".to_string(),
                "-o".to_string(),
                "PasswordAuthentication=no".to_string(),
            ]
        );
    }

    #[test]
    fn connect_opts_key_only_no_password_restricts_to_publickey() {
        // A key-only host (identity present, PasswordSource::None) must restrict
        // ssh so a bad/unreadable key fails fast instead of degrading to a
        // password prompt. IdentitiesOnly=yes + PasswordAuthentication=no.
        let opts = connect_opts(&resolved(), &host(), &Overrides::default());
        assert!(
            opts.windows(2)
                .any(|w| w == ["-o".to_string(), "IdentitiesOnly=yes".to_string()]),
            "key-only host must set IdentitiesOnly=yes, got {opts:?}"
        );
        assert!(
            opts.windows(2)
                .any(|w| w == ["-o".to_string(), "PasswordAuthentication=no".to_string()]),
            "key-only host must set PasswordAuthentication=no, got {opts:?}"
        );
    }

    #[test]
    fn connect_opts_key_plus_password_does_not_restrict() {
        // A host with BOTH a key and a password keeps password fallback — do not
        // add the publickey-only restrictions.
        let mut r = resolved();
        r.password = PasswordSource::Inline(zeroize::Zeroizing::new("pw".into()));
        let opts = connect_opts(&r, &host(), &Overrides::default());
        assert!(!opts.iter().any(|a| a == "PasswordAuthentication=no"));
        assert!(!opts.iter().any(|a| a == "IdentitiesOnly=yes"));
    }

    #[test]
    fn connect_opts_appends_ssh_args_after_sshrack_options() {
        let h = Host {
            ssh_args: Some("-o ServerAliveInterval=30 -o IdentitiesOnly=no".into()),
            ..host()
        };
        let opts = connect_opts(&resolved(), &h, &Overrides::default());
        let ident_idx = opts
            .iter()
            .position(|a| a == "IdentitiesOnly=yes")
            .expect("invariant: key-only fixture appends IdentitiesOnly");
        let alive_idx = opts
            .iter()
            .position(|a| a == "ServerAliveInterval=30")
            .expect("invariant: ssh_args appended");
        // User args come AFTER sshrack's own -o pair so repeated keys override.
        assert!(alive_idx > ident_idx);
        // ssh's last-wins rule makes the user's override meaningful:
        assert!(opts.contains(&"IdentitiesOnly=no".to_string()));
    }

    #[test]
    fn build_keeps_destination_last_with_ssh_args() {
        let h = Host {
            ssh_args: Some("-X".into()),
            ..host()
        };
        let argv = build(&resolved(), &h, &Overrides::default(), &[]);
        assert_eq!(argv.last(), Some(&"192.168.1.10".to_string()));
        assert!(argv.contains(&"-X".to_string()));
    }

    #[test]
    fn connect_opts_no_key_no_password_no_restrictions() {
        // No identity at all (agent / password-less) → no -i and no restrictions.
        let mut r = resolved();
        r.key_path = None;
        let opts = connect_opts(&r, &host(), &Overrides::default());
        assert!(!opts.contains(&"-i".to_string()));
        assert!(!opts.iter().any(|a| a == "PasswordAuthentication=no"));
    }
}
