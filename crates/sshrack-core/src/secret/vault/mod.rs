//! Master-passphrase encryption for stored passwords ("vault" mode).
//!
//! Split into a pure cryptography core ([`crypto`]), pure body/config
//! transforms ([`transform`]), and an I/O-only key cache ([`cache`]). The
//! orchestration that ties them to the CLI (unlock/enable/rekey/seal_body) lands
//! in a later task.
//!
//! Design rule: nothing in this module ever prints, logs, or returns a
//! passphrase, master key, or plaintext in an error message.

pub mod cache;
pub mod crypto;
pub mod transform;

/// The derived 32-byte master key. Wrapped in [`Zeroizing`] so it is wiped on
/// drop. Produced by [`crypto::derive_key`]; consumed by
/// [`crypto::encrypt`]/[`crypto::decrypt`] and the body transforms that land in
/// later tasks.
pub type VaultKey = zeroize::Zeroizing<[u8; 32]>;

/// Low-cost Argon2id meta for tests: the default 64 MiB / 3 / 4 cost would
/// make the suite seconds-slow. Shared by the vault and credential tests.
#[cfg(test)]
pub(crate) fn fast_meta(salt_b64: &str) -> crate::config::schema::VaultMeta {
    use crate::config::schema::VaultMeta;
    VaultMeta {
        m: 8,
        t: 1,
        p: 1,
        ..VaultMeta::default_argon2id(salt_b64)
    }
}
