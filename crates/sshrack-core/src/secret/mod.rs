//! Secret storage backends behind injected traits.
//!
//! Core defines two side-effect seams so the vault orchestration and the
//! host-key pre-flight can be unit-tested without a running keyring daemon or a
//! TTY:
//!
//! - [`SecretBackend`] — where stored secrets live (the OS keyring or a test
//!   double).
//! - [`PassphraseProvider`] — how a vault passphrase is obtained.
//!
//! The CLI supplies concrete impls ([`OsKeyring`] plus its own prompt impl);
//! tests supply the fakes in [`test_doubles`]. Nothing here prints, logs, or
//! returns a passphrase or plaintext in an error message.
//!
//! Submodules:
//! - [`vault`] — master-passphrase encryption (crypto + key cache).
//! - [`keyring`] — OS keyring I/O over raw account keys.

use ulid::Ulid;
use zeroize::Zeroizing;

use crate::error::SshrackError;
use crate::id::OwnerKind;

pub mod keyring;
pub mod vault;

/// The OS keyring (or a test double) behind a single seam. The vault
/// write/migrate path and the rm/cp keyring cleanup go through this, so they
/// are unit-testable without a running Secret Service daemon.
///
/// Raw-keyed at the required layer: `set_at`/`get`/`delete_at` take a raw
/// account key (`<kind>:<id>` for the password slot, `<kind>:<id>#ikpriv` /
/// `#ikcert` for inline-key slots). The `OwnerKind + Ulid` `set`/`delete`
/// defaults are ergonomic wrappers over [`crate::id::keyring_key`] for the
/// password slot; inline-key slots go through the raw methods directly.
pub trait SecretBackend {
    /// Store `secret` under the raw account `key` (overwrites). I/O. Used for
    /// the password slot (`<kind>:<id>`) and the inline-key slots
    /// (`<kind>:<id>#ikpriv` / `#ikcert`).
    fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError>;
    /// Fetch the secret for a raw account key; `Ok(None)` when absent.
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError>;
    /// Delete the entry for a raw account key if present. A missing entry is
    /// success.
    fn delete_at(&self, key: &str) -> Result<(), SshrackError>;
    /// True when the backend is reachable (a daemon is running / keychain
    /// unlocked). Probed before migrating into keyring mode.
    fn available(&self) -> bool;

    /// Store `password` under the owner's password slot (`<kind>:<id>`).
    /// Provided for ergonomics: existing password-slot callers are unchanged.
    fn set(&self, kind: OwnerKind, id: &Ulid, password: &str) -> Result<(), SshrackError> {
        self.set_at(&crate::id::keyring_key(kind, id), password)
    }
    /// Delete the owner's password slot. Provided for ergonomics.
    fn delete(&self, kind: OwnerKind, id: &Ulid) -> Result<(), SshrackError> {
        self.delete_at(&crate::id::keyring_key(kind, id))
    }
}

/// Where a vault passphrase comes from. Methods that read a passphrase return
/// [`Zeroizing<String>`] so the plaintext is wiped on drop.
///
/// The first-use password-mode menu (keyring / vault / plaintext) is a CLI
/// interaction concern and is NOT on this trait — see Task 17.
pub trait PassphraseProvider {
    /// Read the vault master passphrase once, no echo.
    fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError>;
    /// Read a new passphrase, looping until two entries match. Used by
    /// enable/rekey and the first-use vault prompt.
    fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError>;
    /// A yes/no confirmation with `text` as the prompt, defaulting to No.
    fn confirm(&self, text: &str) -> Result<bool, SshrackError>;
}

/// The real OS keyring. Delegates to [`keyring`].
pub struct OsKeyring;

impl SecretBackend for OsKeyring {
    fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError> {
        keyring::set_by_key(key, secret)
    }
    fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
        keyring::get(key)
    }
    fn delete_at(&self, key: &str) -> Result<(), SshrackError> {
        keyring::delete_by_key(key)
    }
    fn available(&self) -> bool {
        keyring::daemon_available()
    }
}

/// Best-effort delete of a keyring entry when the owning body was keyring-marked.
/// Centralizes the rm cleanup policy (delete-if-marked, ignore errors) so host
/// and credential removal share one implementation. Never returns an error.
pub fn forget_keyring_secret(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    id: &Ulid,
    marked: bool,
) {
    if marked {
        let _ = backend.delete(kind, id);
    }
}

/// Best-effort delete of an owner's inline-key keyring slots (private +
/// certificate) when the owning body carried a keyring-stored inline key.
/// Never returns an error. Mirrors [`forget_keyring_secret`] for the inline
/// slots. `marked` is the source body's inline-key `keyring` flag.
pub fn forget_inline_keyring_slots(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    id: &Ulid,
    marked: bool,
) {
    if marked {
        let _ = backend.delete_at(&crate::id::keyring_key_inline_priv(kind, id));
        let _ = backend.delete_at(&crate::id::keyring_key_inline_cert(kind, id));
    }
}

/// Copy an owner's password keyring slot from `src_id` to `dst_id` when present.
/// Returns `true` if a slot was copied. Centralizes the cp cleanup policy so
/// host and credential copy share one implementation (no duplicated match
/// arms). Never materializes the password outside the backend round-trip.
pub fn copy_keyring_secret(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    src_id: &Ulid,
    dst_id: &Ulid,
) -> Result<bool, SshrackError> {
    match backend.get(&crate::id::keyring_key(kind, src_id))? {
        Some(pw) => {
            backend.set(kind, dst_id, &pw)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Copy an owner's inline-key keyring slots (private + certificate) from
/// `src_id` to `dst_id`, if the source has any. Returns `true` if at least one
/// slot was copied. Used by `host cp` / `cred cp` so the cloned owner owns its
/// keyring-stored inline key. Absent slots are silently skipped (not every
/// inline key has a certificate); real I/O errors propagate via `?`.
pub fn copy_inline_keyring_slots(
    backend: &dyn SecretBackend,
    kind: OwnerKind,
    src_id: &Ulid,
    dst_id: &Ulid,
) -> Result<bool, SshrackError> {
    let mut copied = false;
    let priv_key = crate::id::keyring_key_inline_priv(kind, src_id);
    if let Some(p) = backend.get(&priv_key)? {
        backend.set_at(&crate::id::keyring_key_inline_priv(kind, dst_id), &p)?;
        copied = true;
    }
    let cert_key = crate::id::keyring_key_inline_cert(kind, src_id);
    if let Some(c) = backend.get(&cert_key)? {
        backend.set_at(&crate::id::keyring_key_inline_cert(kind, dst_id), &c)?;
        copied = true;
    }
    Ok(copied)
}

#[cfg(test)]
pub(crate) mod test_doubles {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// In-memory keyring for tests. Keyed by the derived account key, so it
    /// honours [`crate::id::keyring_key`] exactly like the OS backend.
    pub(crate) struct FakeBackend {
        /// `account key -> plaintext`. Public so tests can seed/inspect it.
        pub entries: RefCell<HashMap<String, String>>,
        /// Drives [`SecretBackend::available`]. Defaults to `true`.
        pub available: bool,
    }

    impl FakeBackend {
        /// Empty keyring, reported as available.
        pub(crate) fn new() -> Self {
            Self {
                entries: Default::default(),
                available: true,
            }
        }
    }

    impl SecretBackend for FakeBackend {
        fn set_at(&self, key: &str, secret: &str) -> Result<(), SshrackError> {
            self.entries
                .borrow_mut()
                .insert(key.to_string(), secret.to_string());
            Ok(())
        }
        fn get(&self, key: &str) -> Result<Option<Zeroizing<String>>, SshrackError> {
            Ok(self
                .entries
                .borrow()
                .get(key)
                .map(|p| Zeroizing::new(p.clone())))
        }
        fn delete_at(&self, key: &str) -> Result<(), SshrackError> {
            self.entries.borrow_mut().remove(key);
            Ok(())
        }
        fn available(&self) -> bool {
            self.available
        }
    }

    /// Minimal passphrase provider for vault tests: each method returns a
    /// canned answer, or the given error (simulating no-tty / a cancelled
    /// prompt). The scripted value is held in a `RefCell<Option<Result<…>>>`
    /// and consumed via `Option::take`, because [`SshrackError`] is not
    /// `Clone`. A second call after the scripted value is consumed falls back
    /// to [`SshrackError::Interrupted`].
    pub(crate) struct FakePassphraseProvider {
        pub passphrase: RefCell<Option<Result<String, SshrackError>>>,
        pub passphrase_confirm: RefCell<Option<Result<String, SshrackError>>>,
        pub confirm: RefCell<Option<Result<bool, SshrackError>>>,
    }

    impl PassphraseProvider for FakePassphraseProvider {
        fn passphrase(&self) -> Result<Zeroizing<String>, SshrackError> {
            self.passphrase
                .borrow_mut()
                .take()
                .unwrap_or(Err(SshrackError::Interrupted))
                .map(Zeroizing::new)
        }
        fn passphrase_confirm(&self) -> Result<Zeroizing<String>, SshrackError> {
            self.passphrase_confirm
                .borrow_mut()
                .take()
                .unwrap_or(Err(SshrackError::Interrupted))
                .map(Zeroizing::new)
        }
        fn confirm(&self, _text: &str) -> Result<bool, SshrackError> {
            self.confirm
                .borrow_mut()
                .take()
                .unwrap_or(Err(SshrackError::Interrupted))
        }
    }

    /// A passphrase provider that refuses every method: `confirm` returns
    /// `false`, every other method errors `Interrupted`. Used by tests whose
    /// vault is already unlocked (so the passphrase branch is never reached)
    /// or that exercise a fall-through-to-prompt path expecting it to error
    /// off-tty.
    pub(crate) fn deny() -> FakePassphraseProvider {
        FakePassphraseProvider {
            passphrase: RefCell::new(Some(Err(SshrackError::Interrupted))),
            passphrase_confirm: RefCell::new(Some(Err(SshrackError::Interrupted))),
            confirm: RefCell::new(Some(Ok(false))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{OwnerKind, keyring_key, keyring_key_inline_cert, keyring_key_inline_priv};
    use ulid::Ulid;

    #[test]
    fn fake_backend_round_trips_via_keyring_key() {
        let b = test_doubles::FakeBackend::new();
        let id = Ulid::new();
        b.set(OwnerKind::Credential, &id, "hunter2").unwrap();
        let got = b.get(&keyring_key(OwnerKind::Credential, &id)).unwrap();
        assert_eq!(got.as_deref().map(String::as_str), Some("hunter2"));
        b.delete(OwnerKind::Credential, &id).unwrap();
        assert!(
            b.get(&keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fake_backend_keys_host_and_credential_distinctly() {
        // Same id, different kind -> different key (the prefix disambiguates).
        let b = test_doubles::FakeBackend::new();
        let id = Ulid::new();
        b.set(OwnerKind::Host, &id, "host-pw").unwrap();
        b.set(OwnerKind::Credential, &id, "cred-pw").unwrap();
        assert_eq!(
            b.get(&keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("host-pw")
        );
        assert_eq!(
            b.get(&keyring_key(OwnerKind::Credential, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("cred-pw")
        );
    }

    #[test]
    fn forget_deletes_only_when_marked() {
        let b = test_doubles::FakeBackend::new();
        let id = Ulid::new();
        b.set(OwnerKind::Host, &id, "p").unwrap();
        // Not marked: entry must survive (the cleanup is delete-if-marked).
        forget_keyring_secret(&b, OwnerKind::Host, &id, false);
        assert!(b.get(&keyring_key(OwnerKind::Host, &id)).unwrap().is_some());
        // Marked: entry is removed, best-effort.
        forget_keyring_secret(&b, OwnerKind::Host, &id, true);
        assert!(b.get(&keyring_key(OwnerKind::Host, &id)).unwrap().is_none());
    }

    #[test]
    fn fake_passphrase_provider_returns_canned_passphrase() {
        use test_doubles::FakePassphraseProvider;
        let p = FakePassphraseProvider {
            passphrase: std::cell::RefCell::new(Some(Ok("hunter2".into()))),
            passphrase_confirm: std::cell::RefCell::new(Some(Ok("hunter2".into()))),
            confirm: std::cell::RefCell::new(Some(Ok(true))),
        };
        let got: Zeroizing<String> = p.passphrase().unwrap();
        assert_eq!(got.as_str(), "hunter2");
        assert!(p.confirm("ok?").unwrap());
    }

    #[test]
    fn fake_passphrase_provider_propagates_error() {
        use test_doubles::FakePassphraseProvider;
        let p = FakePassphraseProvider {
            passphrase: std::cell::RefCell::new(Some(Err(SshrackError::Interrupted))),
            passphrase_confirm: std::cell::RefCell::new(Some(Ok("x".into()))),
            confirm: std::cell::RefCell::new(Some(Ok(false))),
        };
        assert!(matches!(p.passphrase(), Err(SshrackError::Interrupted)));
    }

    #[test]
    fn deny_passphrase_provider_refuses_everything() {
        use test_doubles::deny;
        let p = deny();
        assert!(matches!(p.passphrase(), Err(SshrackError::Interrupted)));
        assert!(!p.confirm("sure?").unwrap());
    }

    #[test]
    fn fake_backend_round_trips_inline_slots_independently() {
        let id = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set_at(&keyring_key(OwnerKind::Host, &id), "pw").unwrap();
        be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &id), "PRIV")
            .unwrap();
        be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &id), "CERT")
            .unwrap();
        assert_eq!(
            be.get(&keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("pw")
        );
        assert_eq!(
            be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("PRIV")
        );
        be.delete_at(&keyring_key(OwnerKind::Host, &id)).unwrap();
        assert!(
            be.get(&keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("PRIV")
        );
    }

    #[test]
    fn provided_set_delete_delegate_through_keyring_key() {
        let id = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set(OwnerKind::Host, &id, "pw").unwrap();
        assert_eq!(
            be.get(&keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("pw")
        );
        be.delete(OwnerKind::Host, &id).unwrap();
        assert!(
            be.get(&keyring_key(OwnerKind::Host, &id))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn forget_inline_keyring_slots_deletes_priv_and_cert() {
        let id = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &id), "p")
            .unwrap();
        be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &id), "c")
            .unwrap();
        super::forget_inline_keyring_slots(&be, OwnerKind::Host, &id, true);
        assert!(
            be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .is_none()
        );
        assert!(
            be.get(&keyring_key_inline_cert(OwnerKind::Host, &id))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn forget_inline_keyring_slots_noop_when_not_marked() {
        // Not marked: slots must survive (the cleanup is delete-if-marked).
        let id = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &id), "p")
            .unwrap();
        super::forget_inline_keyring_slots(&be, OwnerKind::Host, &id, false);
        assert_eq!(
            be.get(&keyring_key_inline_priv(OwnerKind::Host, &id))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("p")
        );
    }

    #[test]
    fn copy_inline_keyring_slots_copies_priv_and_cert_to_new_owner() {
        let src = Ulid::new();
        let dst = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set_at(&keyring_key_inline_priv(OwnerKind::Host, &src), "p")
            .unwrap();
        be.set_at(&keyring_key_inline_cert(OwnerKind::Host, &src), "c")
            .unwrap();
        let copied = super::copy_inline_keyring_slots(&be, OwnerKind::Host, &src, &dst).unwrap();
        assert!(copied);
        assert_eq!(
            be.get(&keyring_key_inline_priv(OwnerKind::Host, &dst))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("p")
        );
        assert_eq!(
            be.get(&keyring_key_inline_cert(OwnerKind::Host, &dst))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("c")
        );
    }

    #[test]
    fn copy_inline_keyring_slots_returns_false_when_no_slots_present() {
        // No source slots → nothing copied, returns false. The source owner
        // simply owns no inline-key keyring material.
        let src = Ulid::new();
        let dst = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        let copied = super::copy_inline_keyring_slots(&be, OwnerKind::Host, &src, &dst).unwrap();
        assert!(!copied);
    }

    #[test]
    fn copy_keyring_secret_copies_password_slot_to_new_owner() {
        let src = Ulid::new();
        let dst = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        be.set(OwnerKind::Credential, &src, "hunter2").unwrap();
        let copied = super::copy_keyring_secret(&be, OwnerKind::Credential, &src, &dst).unwrap();
        assert!(copied);
        assert_eq!(
            be.get(&keyring_key(OwnerKind::Credential, &dst))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
        // Source survives (copy, not move).
        assert_eq!(
            be.get(&keyring_key(OwnerKind::Credential, &src))
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("hunter2")
        );
    }

    #[test]
    fn copy_keyring_secret_returns_false_when_slot_absent() {
        let src = Ulid::new();
        let dst = Ulid::new();
        let be = test_doubles::FakeBackend::new();
        let copied = super::copy_keyring_secret(&be, OwnerKind::Host, &src, &dst).unwrap();
        assert!(!copied);
    }
}
