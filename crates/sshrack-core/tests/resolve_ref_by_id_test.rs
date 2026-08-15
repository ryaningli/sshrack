//! End-to-end: a host's `Auth::Ref` (by id) survives a credential name rename.
//!
//! This is an integration test (not a unit test): it builds a real config,
//! writes it to a temp file via [`config::store::save`], reloads it, renames the
//! referenced credential's name, and asserts [`credential::resolve`] still
//! resolves the host's auth — proving ref-by-id never dangles across a real
//! disk round-trip. The unit tests in `credential::` cover the in-memory
//! rename; this test locks the contract end-to-end through TOML serialization.

use sshrack_core::config::schema::{Auth, Credential, CredentialBody, Host, SshrackConfig};
use sshrack_core::config::store;
use sshrack_core::credential;
use sshrack_core::id::new_id;
use sshrack_core::secret::OsKeyring;

/// A host referencing a credential by its stable id keeps resolving after the
/// credential's name is renamed and the whole config is saved + reloaded.
///
/// The reference is by id, so the rename (which touches only `name`) cannot
/// orphan it. The reloaded config must resolve to the credential's user and key
/// under the new name.
#[test]
fn ref_by_id_survives_credential_name_rename_across_disk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg_path = dir.path().join("config.toml");

    // Build a credential and a host that references it by id.
    let cred_id = new_id();
    let host_id = new_id();
    let cfg = SshrackConfig {
        hosts: vec![Host {
            id: host_id,
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 2222,
            ssh_args: None,
            auth: Auth::reference(cred_id),
        }],
        credentials: vec![Credential {
            id: cred_id,
            name: "team-dev".into(),
            body: CredentialBody::new("deploy").with_key("~/.ssh/team_ed25519"),
        }],
        ..Default::default()
    };

    // Persist + reload (the disk round-trip is the integration angle).
    store::save(&cfg_path, &cfg).expect("save");
    let loaded = store::load(&cfg_path).expect("load");
    // The reference survived serialization: still resolves before the rename.
    let host = loaded.find_host_by_name("web1").expect("host present");
    let resolved =
        credential::resolve(host, &loaded, None, &OsKeyring).expect("resolve before rename");
    assert_eq!(resolved.user, "deploy");
    assert_eq!(
        resolved.key_path.as_deref(),
        Some(std::path::Path::new("~/.ssh/team_ed25519"))
    );

    // Rename the credential's name in the reloaded config and re-persist.
    let renamed = rename_credential_name(&loaded, "team-dev", "prod-team").expect("rename");
    assert_ne!(
        loaded.credentials[0].name, renamed.credentials[0].name,
        "sanity: rename actually changed the name"
    );
    // The id is unchanged across the rename (the stability invariant).
    assert_eq!(renamed.credentials[0].id, cred_id);
    store::save(&cfg_path, &renamed).expect("save renamed");
    let reloaded = store::load(&cfg_path).expect("load renamed");

    // The host's Auth::Ref still points at the same id and still resolves.
    let host = reloaded.find_host_by_name("web1").expect("host present");
    assert_eq!(host.auth.credential_id(), Some(cred_id));
    let resolved =
        credential::resolve(host, &reloaded, None, &OsKeyring).expect("resolve after rename");
    assert_eq!(
        resolved.user, "deploy",
        "user travels with the credential, not the name"
    );
    assert_eq!(
        resolved.key_path.as_deref(),
        Some(std::path::Path::new("~/.ssh/team_ed25519"))
    );
    // The new name is findable by name, the old one is gone.
    assert!(reloaded.find_credential_by_name("prod-team").is_some());
    assert!(reloaded.find_credential_by_name("team-dev").is_none());
}

/// Deleting the referenced credential makes `resolve` fail (the dangling
/// reference surfaces as `CredentialNotFound`). This is the negative arm of
/// ref-by-id: a deleted credential is detected, never silently swallowed.
#[test]
fn ref_by_id_dangles_when_credential_deleted_across_disk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cfg_path = dir.path().join("config.toml");

    let cred_id = new_id();
    let cfg = SshrackConfig {
        hosts: vec![Host {
            id: new_id(),
            name: "web1".into(),
            host: "10.0.0.5".into(),
            port: 22,
            ssh_args: None,
            auth: Auth::reference(cred_id),
        }],
        credentials: vec![Credential {
            id: cred_id,
            name: "team-dev".into(),
            body: CredentialBody::new("deploy"),
        }],
        ..Default::default()
    };
    store::save(&cfg_path, &cfg).expect("save");
    let mut loaded = store::load(&cfg_path).expect("load");

    // Delete the credential and re-persist.
    loaded.credentials.clear();
    store::save(&cfg_path, &loaded).expect("save after delete");
    let reloaded = store::load(&cfg_path).expect("load after delete");

    let host = reloaded.find_host_by_name("web1").expect("host present");
    let err =
        credential::resolve(host, &reloaded, None, &OsKeyring).expect_err("dangling ref errors");
    assert!(
        matches!(
            err,
            sshrack_core::error::SshrackError::CredentialNotFound { .. }
        ),
        "expected CredentialNotFound, got {err:?}"
    );
}

/// Return a new config with the named credential's name changed to `new_name`,
/// preserving the credential's id and body. Mirrors what `cred edit --rename`
/// produces at the pure-logic layer.
fn rename_credential_name(
    cfg: &SshrackConfig,
    old_name: &str,
    new_name: &str,
) -> Option<SshrackConfig> {
    let mut next = cfg.clone();
    let cred = next.credentials.iter_mut().find(|c| c.name == old_name)?;
    cred.name = new_name.into();
    Some(next)
}
