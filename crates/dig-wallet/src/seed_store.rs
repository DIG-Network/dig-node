//! At-rest wallet-seed custody via `dig-keystore` (#205 PR4, design C.2/§18.12).
//!
//! `dig-wallet`'s on-disk seed file (`seed_path()`, `crate::lib`) was encrypted with
//! `digstore_chain::seed` (Argon2id + AES-GCM, a bespoke 1-byte-version + 32-byte-salt +
//! 12-byte-nonce layout). This module migrates NEW writes to the `dig-keystore` crate's
//! [`dig_keystore::opaque`] container (the SAME Argon2id + AES-256-GCM primitives, behind a
//! versioned, magic-tagged, CRC-guarded on-disk format shared with every other DIG binary's
//! keystore) — consolidating seed custody onto the ecosystem's canonical crate (Appendix B /
//! design C.2), rather than reinventing it here.
//!
//! `opaque` (not the fixed-length `Keystore<K: KeyScheme>` API) is the right fit: a BIP-39
//! mnemonic phrase is arbitrary-length text, not a fixed 32-byte scheme secret, and this
//! module wants byte-for-byte the SAME plaintext (the mnemonic string) in and out — no
//! `KeyScheme`-style derived-key reconstruction is needed here.
//!
//! ## Backwards compatibility (§5.1 spirit, HARD RULE for at-rest secrets)
//!
//! A seed file written by an older `dig-wallet` build must keep opening. [`decrypt_seed`]
//! detects the on-disk format by its leading magic: a `dig-keystore` container starts with
//! one of `DIGVK1`/`DIGLW1`/`DIGOP1` (`dig_keystore::format`'s known magics); anything else is
//! treated as the legacy `digstore_chain::seed::EncryptedSeed` layout (`version(1) ‖ salt(32)
//! ‖ nonce(12) ‖ ciphertext+tag`, which never starts with those ASCII magics — its first byte
//! is the fixed version constant `1`). [`legacy_read_still_works`] proves an OLD-format blob,
//! produced by the actual legacy crate, still decrypts correctly under the new reader — the
//! golden-fixture old-seed read test required by this migration.
//!
//! All NEW writes ([`encrypt_seed`]) use the `dig-keystore` format; there is no code path that
//! writes the legacy format anymore, but every code path that reads a seed file goes through
//! [`decrypt_seed`], so a file written before this change keeps unlocking.

use dig_keystore::{opaque, KdfParams, KeystoreError, Password};
use digstore_chain::seed::{decrypt_seed as legacy_decrypt, EncryptedSeed};
use zeroize::Zeroizing;

/// The 6-byte magics `dig-keystore` recognizes (`dig_keystore::format`'s `is_known_magic`,
/// mirrored here since that predicate is private to that crate). A file starting with one of
/// these is a `dig-keystore` container; anything else is read as the legacy
/// `digstore_chain::seed` layout.
const DIG_KEYSTORE_MAGICS: [[u8; 6]; 3] = [*b"DIGVK1", *b"DIGLW1", *b"DIGOP1"];

fn is_dig_keystore_blob(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && DIG_KEYSTORE_MAGICS.contains(&bytes[0..6].try_into().unwrap())
}

/// Encrypt `mnemonic` at rest under `password`, using the CURRENT (`dig-keystore` `opaque`)
/// format. Returns the complete on-disk file bytes — write them verbatim to `seed_path()`.
pub fn encrypt_seed(mnemonic: &str, password: &str) -> Result<Vec<u8>, String> {
    opaque::seal(
        &Password::from(password),
        mnemonic.as_bytes(),
        KdfParams::default(),
    )
    .map_err(|e| e.to_string())
}

/// Decrypt an on-disk seed file under `password`, accepting EITHER the current `dig-keystore`
/// format OR a legacy `digstore_chain::seed::EncryptedSeed` blob (pre-migration files keep
/// opening — see the module docs). Returns the mnemonic phrase.
pub fn decrypt_seed(bytes: &[u8], password: &str) -> Result<Zeroizing<String>, String> {
    if is_dig_keystore_blob(bytes) {
        let plain = opaque::open(&Password::from(password), bytes).map_err(map_keystore_err)?;
        let s = String::from_utf8(plain.to_vec())
            .map_err(|_| "corrupt seed file: not valid UTF-8".to_string())?;
        Ok(Zeroizing::new(s))
    } else {
        // Legacy pre-migration format.
        let enc = EncryptedSeed::from_bytes(bytes).map_err(|e| e.to_string())?;
        legacy_decrypt(&enc, password).map_err(|e| e.to_string())
    }
}

/// Map a wrong-password/tamper failure to the SAME "wrong password" phrasing callers already
/// match on for the legacy path, so both formats behave identically at the call sites.
fn map_keystore_err(e: KeystoreError) -> String {
    match e {
        KeystoreError::DecryptFailed => "decrypt failed: wrong password or corrupt data".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    /// **Proves:** a mnemonic encrypted with [`encrypt_seed`] decrypts back to the exact
    /// same phrase under the same password via [`decrypt_seed`].
    #[test]
    fn round_trip_recovers_exact_mnemonic() {
        let blob = encrypt_seed(PHRASE, "hunter2").unwrap();
        let recovered = decrypt_seed(&blob, "hunter2").unwrap();
        assert_eq!(&*recovered, PHRASE);
    }

    /// **Proves:** the wrong password fails closed (no partial/garbage mnemonic returned).
    #[test]
    fn wrong_password_fails_closed() {
        let blob = encrypt_seed(PHRASE, "right").unwrap();
        assert!(decrypt_seed(&blob, "wrong").is_err());
    }

    /// **Proves:** new writes use the `dig-keystore` on-disk format (a recognized magic),
    /// not the legacy `digstore_chain::seed` layout.
    #[test]
    fn new_writes_are_dig_keystore_format() {
        let blob = encrypt_seed(PHRASE, "pw").unwrap();
        assert!(is_dig_keystore_blob(&blob));
    }

    /// **Golden-fixture old-seed read test.** Encrypts `PHRASE` with the ACTUAL legacy
    /// `digstore_chain::seed` crate (the exact code path every pre-migration `dig-wallet`
    /// build used to persist a seed), then asserts the NEW unified [`decrypt_seed`] still
    /// reads that old-format file correctly. This is the backwards-compatibility proof
    /// required by the migration: a seed file written before this change keeps opening.
    #[test]
    fn legacy_digstore_chain_seed_file_still_decrypts() {
        let legacy_enc = digstore_chain::seed::encrypt_seed(PHRASE, "legacy-pw").unwrap();
        let legacy_bytes = legacy_enc.to_bytes();

        // The legacy format is NOT mistaken for a dig-keystore container.
        assert!(!is_dig_keystore_blob(&legacy_bytes));

        let recovered = decrypt_seed(&legacy_bytes, "legacy-pw").unwrap();
        assert_eq!(
            &*recovered, PHRASE,
            "an old-format seed file must still decrypt"
        );
    }

    /// **Proves:** a legacy-format file with the wrong password still fails closed under the
    /// new unified reader (the fallback path reuses the legacy crate's own AEAD check).
    #[test]
    fn legacy_seed_file_wrong_password_fails_closed() {
        let legacy_enc = digstore_chain::seed::encrypt_seed(PHRASE, "right").unwrap();
        let legacy_bytes = legacy_enc.to_bytes();
        assert!(decrypt_seed(&legacy_bytes, "wrong").is_err());
    }

    /// **Proves:** a short/garbage file (neither format) fails cleanly, never panics.
    #[test]
    fn garbage_bytes_fail_cleanly() {
        assert!(decrypt_seed(&[0u8; 4], "pw").is_err());
        assert!(decrypt_seed(b"not a seed file at all", "pw").is_err());
    }
}
