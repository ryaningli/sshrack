//! Identity helpers for sshrack.
//!
//! Every host and credential carries a first-class, immutable `Ulid`. The
//! keyring account key is derived from the owner kind plus that id (never the
//! name), so renaming an owner never moves its keyring entry.

use ulid::Ulid;

/// Generate a fresh identity.
pub fn new_id() -> Ulid {
    Ulid::new()
}

/// Whose secret a keyring entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    Host,
    Credential,
}

/// Pure: the keyring account key for an owner kind + id. Name-free on purpose
/// so renames are safe.
pub fn keyring_key(kind: OwnerKind, id: &Ulid) -> String {
    match kind {
        OwnerKind::Host => format!("host:{id}"),
        OwnerKind::Credential => format!("cred:{id}"),
    }
}

/// The keyring account key for an inline private key stored under keyring
/// mode. Shares the `<kind>:<id>` base with [`keyring_key`] (the password
/// slot) and appends a `#ikpriv` suffix so a single owner may own a password
/// slot, a private-key slot, and a certificate slot simultaneously.
pub fn keyring_key_inline_priv(kind: OwnerKind, id: &Ulid) -> String {
    format!("{}#ikpriv", keyring_key(kind, id))
}

/// The keyring account key for an inline SSH certificate stored under keyring
/// mode. Appends `#ikcert` to the owner's base key.
pub fn keyring_key_inline_cert(kind: OwnerKind, id: &Ulid) -> String {
    format!("{}#ikcert", keyring_key(kind, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_key_is_kind_plus_id() {
        let id = Ulid::new();
        assert_eq!(keyring_key(OwnerKind::Host, &id), format!("host:{id}"));
        assert_eq!(
            keyring_key(OwnerKind::Credential, &id),
            format!("cred:{id}")
        );
    }

    #[test]
    fn host_and_credential_with_same_id_differ_by_prefix() {
        let id = Ulid::new();
        assert_ne!(
            keyring_key(OwnerKind::Host, &id),
            keyring_key(OwnerKind::Credential, &id)
        );
    }

    #[test]
    fn new_id_is_unique_enough() {
        assert_ne!(new_id(), new_id());
    }

    #[test]
    fn inline_priv_key_is_base_plus_suffix() {
        let id = Ulid::new();
        assert_eq!(
            keyring_key_inline_priv(OwnerKind::Host, &id),
            format!("host:{id}#ikpriv")
        );
        assert_eq!(
            keyring_key_inline_priv(OwnerKind::Credential, &id),
            format!("cred:{id}#ikpriv")
        );
    }

    #[test]
    fn inline_cert_key_is_base_plus_suffix() {
        let id = Ulid::new();
        assert_eq!(
            keyring_key_inline_cert(OwnerKind::Host, &id),
            format!("host:{id}#ikcert")
        );
    }

    #[test]
    fn inline_keys_share_base_with_password_key() {
        let id = Ulid::new();
        let base = keyring_key(OwnerKind::Host, &id);
        assert!(keyring_key_inline_priv(OwnerKind::Host, &id).starts_with(&base));
        assert!(keyring_key_inline_cert(OwnerKind::Host, &id).starts_with(&base));
    }
}
