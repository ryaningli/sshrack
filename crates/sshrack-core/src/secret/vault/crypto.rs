//! Pure cryptography for vault mode: Argon2id key derivation and
//! XChaCha20-Poly1305 authenticated encryption. No I/O, no RNG except inside
//! [`encrypt`] (a 24-byte nonce via `getrandom`). All functions are
//! deterministic except [`encrypt`], whose nonce is random per call.

use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use zeroize::Zeroizing;

use crate::config::schema::{EncryptedSecret, VaultMeta};
use crate::error::SshrackError;
use crate::secret::vault::VaultKey;

/// Derive the 32-byte master key from a passphrase + vault metadata via
/// Argon2id. Deterministic: identical inputs yield an identical key.
///
/// Fails as [`SshrackError::VaultUnlockFailed`] when the metadata is unusable
/// (unsupported KDF, malformed salt, bad Argon2 params) or Argon2 itself
/// rejects the inputs. This is vault-wide — `derive_key` only converts a
/// passphrase into a key, so no per-credential context exists here.
pub fn derive_key(passphrase: &str, meta: &VaultMeta) -> Result<VaultKey, SshrackError> {
    if !meta.supports_kdf() {
        return Err(SshrackError::VaultUnlockFailed);
    }
    let salt = STANDARD
        .decode(&meta.salt)
        .map_err(|_| SshrackError::VaultUnlockFailed)?;
    // `m` is in KiB (per the argon2 0.5 `Params::new` contract); the default
    // 65_536 therefore means 64 MiB. `Some(32)` pins the output to one key.
    let params = argon2::Params::new(meta.m, meta.t, meta.p, Some(32))
        .map_err(|_| SshrackError::VaultUnlockFailed)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|_| SshrackError::VaultUnlockFailed)?;
    Ok(Zeroizing::new(key))
}

/// Encrypt `plain` under `key` with a fresh random 24-byte nonce.
pub fn encrypt(plain: &[u8], key: &[u8; 32]) -> Result<EncryptedSecret, SshrackError> {
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SshrackError::EncryptionFailed)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plain)
        .map_err(|_| SshrackError::EncryptionFailed)?;
    Ok(EncryptedSecret {
        nonce: STANDARD.encode(nonce),
        cipher: STANDARD.encode(&ciphertext),
    })
}

/// Decryption failure: wrong key, tampering, corruption, or malformed
/// base64/nonce. Fieldless on purpose — a crypto primitive must not reveal
/// which check failed (that would be a decryption oracle) and carries no
/// credential alias. Business-layer callers attach
/// [`SshrackError::DecryptionFailed`] with the alias they know.
#[derive(Debug, thiserror::Error)]
#[error("decryption failed")]
pub struct DecryptError;

/// Decrypt an [`EncryptedSecret`] under `key`. Any failure (wrong key,
/// tampering, corruption, malformed base64/nonce) collapses to the fieldless
/// [`DecryptError`] — it never reveals which check failed (no decryption
/// oracle) and never carries a credential alias. Callers that know the alias
/// map it to [`SshrackError::DecryptionFailed`] at the business layer.
pub fn decrypt(
    secret: &EncryptedSecret,
    key: &[u8; 32],
) -> Result<Zeroizing<String>, DecryptError> {
    let nonce_bytes = STANDARD.decode(&secret.nonce).map_err(|_| DecryptError)?;
    let ciphertext = STANDARD.decode(&secret.cipher).map_err(|_| DecryptError)?;
    if nonce_bytes.len() != 24 {
        return Err(DecryptError);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| DecryptError)?;
    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::secret::vault::fast_meta;

    #[test]
    fn derive_key_is_deterministic() {
        let m = fast_meta("AAAAAAAAAAAAAAAAAAAAAA=="); // 16 zero bytes
        let a = derive_key("hunter2", &m).unwrap();
        let b = derive_key("hunter2", &m).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn derive_key_changes_with_salt() {
        // Both salts decode to 16 bytes under Rust's strict base64 0.22
        // engine (trailing bits of an `==` group must be zero; a literal run
        // of 'B' chars fails that, so we use a leading-byte salt instead).
        let m1 = fast_meta("AAAAAAAAAAAAAAAAAAAAAA==");
        let m2 = fast_meta("EAAAAAAAAAAAAAAAAAAAAA==");
        assert_ne!(
            *derive_key("hunter2", &m1).unwrap(),
            *derive_key("hunter2", &m2).unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = [7u8; 32];
        let enc = encrypt(b"hunter2", &key).unwrap();
        let dec = decrypt(&enc, &key).unwrap();
        assert_eq!(dec.as_str(), "hunter2");
    }

    #[test]
    fn encrypt_uses_a_fresh_nonce_each_call() {
        let key = [7u8; 32];
        let a = encrypt(b"same", &key).unwrap();
        let b = encrypt(b"same", &key).unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce must be random per encryption");
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let enc = encrypt(b"hunter2", &[1u8; 32]).unwrap();
        assert!(decrypt(&enc, &[2u8; 32]).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [7u8; 32];
        let mut enc = encrypt(b"hunter2", &key).unwrap();
        // Flip a character in the base64 ciphertext (still valid base64).
        let mut bytes = enc.cipher.into_bytes();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        enc.cipher = String::from_utf8(bytes).unwrap();
        assert!(decrypt(&enc, &key).is_err());
    }
}
