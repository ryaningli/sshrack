//! Identity helpers for sshrack.
//!
//! Every host and credential carries a first-class, immutable `Ulid`. The
//! keyring account key is derived from the owner kind plus that id (never the
//! alias), so renaming an owner never moves its keyring entry.

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

/// Pure: the keyring account key for an owner kind + id. Alias-free on purpose
/// so renames are safe.
pub fn keyring_key(kind: OwnerKind, id: &Ulid) -> String {
    match kind {
        OwnerKind::Host => format!("host:{id}"),
        OwnerKind::Credential => format!("cred:{id}"),
    }
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
}
