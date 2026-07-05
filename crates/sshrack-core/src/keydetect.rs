//! Detect SSH private-key files so the file picker can highlight them. Two
//! pure predicates: a header check (read the file's first line elsewhere and
//! pass it here — this fn does no IO) and a cheaper filename heuristic used as
//! the fast path before any file is opened.

/// `true` iff `first_line` is a PEM/OpenSSH private-key armor header
/// (`-----BEGIN … PRIVATE KEY-----`). Covers RSA, DSA, EC, OpenSSH native,
/// PKCS#8 unencrypted, and PKCS#8 encrypted. Pure — the caller reads the file's
/// first line and passes it in; this fn never opens a file.
pub fn looks_like_private_key_header(first_line: &str) -> bool {
    let t = first_line.trim_end();
    t.starts_with("-----BEGIN ") && t.ends_with(" PRIVATE KEY-----")
}

/// Cheap zero-IO hint that `name` looks like a private-key file: exactly
/// `id_rsa`, any `id_*`, or ending `.pem` / `.key`. Excludes `.pub`. Used as the
/// fast path before reading a header; the authoritative check is
/// [`looks_like_private_key_header`] on the file's first line.
pub fn looks_like_key_filename(name: &str) -> bool {
    if name.ends_with(".pub") {
        return false;
    }
    name == "id_rsa" || name.starts_with("id_") || name.ends_with(".pem") || name.ends_with(".key")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- looks_like_private_key_header ----

    #[test]
    fn recognizes_all_mainstream_armor_headers() {
        for line in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ] {
            assert!(
                looks_like_private_key_header(line),
                "should recognize: {line}"
            );
        }
    }

    #[test]
    fn rejects_public_key_and_random_lines() {
        assert!(!looks_like_private_key_header("ssh-rsa AAAAB3Nza..."));
        assert!(!looks_like_private_key_header("-----BEGIN PUBLIC KEY-----"));
        assert!(!looks_like_private_key_header("not a key at all"));
        assert!(!looks_like_private_key_header(""));
    }

    // ---- looks_like_key_filename ----

    #[test]
    fn filename_heuristic_flags_common_key_names() {
        assert!(looks_like_key_filename("id_rsa"));
        assert!(looks_like_key_filename("id_ed25519"));
        assert!(looks_like_key_filename("id_ecdsa"));
        assert!(looks_like_key_filename("mykey.pem"));
        assert!(looks_like_key_filename("deploy.key"));
    }

    #[test]
    fn filename_heuristic_skips_non_keys() {
        assert!(!looks_like_key_filename("id_rsa.pub"));
        assert!(!looks_like_key_filename("known_hosts"));
        assert!(!looks_like_key_filename("config"));
        assert!(!looks_like_key_filename("readme.txt"));
    }
}
