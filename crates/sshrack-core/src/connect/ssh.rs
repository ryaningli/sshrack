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
    /// connection (overlays the resolved auth). For an ad-hoc target this is
    /// the identity source. The CLI resolves the name to the credential's
    /// stable [`Ulid`] before constructing this; the argv builder never sees
    /// the name.
    pub credential: Option<Ulid>,
    /// `--ad-hoc`: the target is a literal address, not a config name.
    pub ad_hoc: bool,
}

/// The ssh connection options shared by the interactive `ssh` argv and the
/// SFTP master/sftp argv: `-l <user> -p <port> (-i <key>)?`. Pure.
///
/// `resolved` supplies the auth identity (user, key). `host` supplies the
/// network endpoint (`port`). Overrides win over both. The identity is
/// `override > resolved.key_path` (ssh-agent covers the rest); absent when
/// neither is set.
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

    opts
}

/// Assemble the full `ssh` argv.
///
/// `resolved` supplies the auth identity (user, key, password — password is
/// consumed by the caller via `connect::launch`, not here). `host` supplies the
/// network endpoint (`host`, `port`). Overrides win over both.
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
            ]
        );
    }
}
