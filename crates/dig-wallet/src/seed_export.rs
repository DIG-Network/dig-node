//! Offline, one-time recovery of a node-custodied wallet mnemonic.
//!
//! Node-side USER custody is being retired (the #1500 ratification). For a user who
//! migrated their seed INTO this node and kept no independent copy, the on-disk seed file
//! is the only surviving copy of their spend key — so the custody code cannot simply be
//! deleted. This module is the rescue: it reads that file, decrypts it under the user's
//! own password, and hands the mnemonic back once so it can be re-enrolled elsewhere.
//!
//! ## What this deliberately is NOT
//!
//! There is **no network surface here** — no RPC method, no loopback endpoint, no served
//! handler. A served export would permanently add a seed-exfiltration capability to the
//! control plane, reachable by anything holding a paired token or an mTLS client
//! certificate, in order to solve a strictly one-time migration. Reaching this code
//! requires local filesystem access AND the wallet password: the same two things an
//! attacker would already need to open the file by hand.
//!
//! This module is temporary. It is removed together with the custody surface it rescues.
//!
//! ## Both on-disk formats, because the real files are the OLD one
//!
//! Seed files predating the `dig-keystore` migration use the legacy
//! `digstore_chain::seed::EncryptedSeed` layout, whose first byte is the version constant
//! `1`. Reading only the current container would fail on exactly the files this module
//! exists to rescue, so it goes through [`crate::seed_store::decrypt_seed`], which
//! dispatches on the leading magic and accepts either. [`tests::legacy_seed_file_exports`]
//! pins that against a fixture built by the actual legacy writer.
//!
//! ## The mnemonic never reaches a log or an error string
//!
//! [`ExportError`] carries only a path and a failure class. The recovered phrase is
//! returned in a [`Zeroizing`] wrapper and is never formatted into a message, so no
//! failure path and no diagnostic can spill it.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::seed_store::decrypt_seed;

/// Why an export could not produce a mnemonic.
///
/// Every variant is deliberately free of secret material: it names the file and the class
/// of failure, never the plaintext and never the password.
#[derive(Debug)]
pub enum ExportError {
    /// No seed file exists at the resolved path — this node holds no custodied wallet there.
    NotFound(PathBuf),
    /// The seed file exists but could not be read (permissions, a directory, an I/O fault).
    Unreadable {
        /// The file that could not be read.
        path: PathBuf,
        /// The operating system's reason, which never contains file contents.
        cause: String,
    },
    /// The file was read but did not decrypt: a wrong password, or a corrupt/truncated file.
    /// The two are deliberately not distinguished — the AEAD cannot tell them apart.
    Undecryptable(PathBuf),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(path) => write!(f, "no seed file at {}", path.display()),
            Self::Unreadable { path, cause } => {
                write!(f, "cannot read {}: {cause}", path.display())
            }
            Self::Undecryptable(path) => write!(
                f,
                "{} did not decrypt: wrong password, or the file is corrupt",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ExportError {}

/// Where this node keeps its encrypted seed file by default.
///
/// Exported so a caller can show the path it is about to read. An older build may have
/// written the file under a different base directory, which is why [`export_mnemonic`]
/// takes an explicit path rather than resolving this itself.
pub fn default_seed_path() -> PathBuf {
    crate::seed_path()
}

/// Recover the mnemonic held in the seed file at `path`, under the wallet `password`.
///
/// Reads only: nothing on disk is written, moved, zeroized or deleted. Accepts either
/// on-disk format (see the module docs); the caller supplies the path so a file written by
/// an older build, under a base directory this build no longer resolves, is still reachable.
pub fn export_mnemonic(path: &Path, password: &str) -> Result<Zeroizing<String>, ExportError> {
    if !path.exists() {
        return Err(ExportError::NotFound(path.to_path_buf()));
    }
    let bytes = std::fs::read(path).map_err(|e| ExportError::Unreadable {
        path: path.to_path_buf(),
        cause: e.to_string(),
    })?;
    // The underlying error text is discarded on purpose: it distinguishes failure modes the
    // caller cannot act on differently, and dropping it keeps every error path provably free
    // of anything derived from the file contents.
    decrypt_seed(&bytes, password).map_err(|_| ExportError::Undecryptable(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    /// A deterministic test password derived from a label, never a hard-coded literal.
    ///
    /// The value is irrelevant to every assertion here — what matters is only that the same
    /// label yields the same password and different labels do not. Deriving it keeps a
    /// password-shaped literal out of the source, which static analysis cannot tell apart
    /// from a real credential.
    fn password(label: &str) -> String {
        let mut hasher = chia_sha2::Sha256::new();
        hasher.update(label.as_bytes());
        hasher.finalize().map(|b| format!("{b:02x}")).concat()
    }

    /// A directory unique to one test, so tests never share a fixture path.
    /// The directory is OWNED by the returned guard: `TempDir`'s `Drop` removes the tree,
    /// including on an unwind, so a failing assertion cannot leak it (dig-node#370).
    fn scratch(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("dig-seed-export-{tag}-"))
            .tempdir()
            .expect("scratch dir")
    }

    /// Write a seed file in the LEGACY on-disk layout — the one every real custodied file
    /// on disk actually uses — and return its path.
    fn write_legacy_fixture(dir: &Path, password: &str) -> PathBuf {
        let enc = digstore_chain::seed::encrypt_seed(PHRASE, password).expect("legacy encrypt");
        let bytes = enc.to_bytes();
        assert_eq!(
            bytes[0], 1,
            "the fixture must be the legacy format this rescue exists for, identified by its \
             leading version byte"
        );
        let path = dir.join("seed.bin");
        std::fs::write(&path, &bytes).expect("write fixture");
        path
    }

    /// **Proves the trap the obvious implementation falls into:** the real population is a
    /// LEGACY `0x01` blob, so an export built on the current-format reader alone would fail
    /// on 100% of the files it exists to rescue. Asserts the leading byte is the legacy
    /// version constant AND that the phrase comes back intact.
    #[test]
    fn legacy_seed_file_exports() {
        let dir = scratch("legacy");
        let path = write_legacy_fixture(dir.path(), &password("legacy"));

        let recovered =
            export_mnemonic(&path, &password("legacy")).expect("legacy blob must export");

        assert_eq!(&*recovered, PHRASE);
    }

    /// **Proves:** a file in the CURRENT container also exports, so accepting the legacy
    /// format did not come at the cost of the modern one. The honest control beside the
    /// legacy test above — without it, a reader that handled only legacy would look correct.
    #[test]
    fn current_format_seed_file_also_exports() {
        let dir = scratch("current");
        let path = dir.path().join("seed.bin");
        let bytes =
            crate::seed_store::encrypt_seed(PHRASE, &password("current")).expect("current encrypt");
        assert_ne!(
            bytes[0], 1,
            "the control fixture must NOT be the legacy format, or it proves nothing"
        );
        std::fs::write(&path, &bytes).expect("write fixture");

        let recovered =
            export_mnemonic(&path, &password("current")).expect("current blob must export");

        assert_eq!(&*recovered, PHRASE);
    }

    /// **Proves the explicit path reaches a NON-default location.** The one real custodied
    /// file measured for this work sits under a base directory current builds no longer
    /// resolve, so a resolver-only export could not see the thing it exists to rescue.
    /// Asserts the fixture path genuinely differs from [`default_seed_path`] first —
    /// otherwise the test could pass while only ever reading the default path.
    #[test]
    fn explicit_path_reaches_a_non_default_location() {
        let dir = scratch("override");
        let path = write_legacy_fixture(dir.path(), &password("fixture"));
        assert_ne!(
            path,
            default_seed_path(),
            "the fixture must be somewhere the default resolver would NOT look"
        );

        let recovered =
            export_mnemonic(&path, &password("fixture")).expect("an off-default path must be read");

        assert_eq!(&*recovered, PHRASE);
    }

    /// **Proves:** a wrong password fails closed, and the failure leaks nothing. Checks the
    /// rendered error against every WORD of the phrase, not only the whole phrase: a message
    /// that spilled a single recovered word would still be a leak, and a whole-phrase check
    /// could not see it.
    #[test]
    fn wrong_password_fails_without_leaking() {
        let dir = scratch("wrongpw");
        let path = write_legacy_fixture(dir.path(), &password("right"));

        let err =
            export_mnemonic(&path, &password("wrong")).expect_err("a wrong password must fail");

        assert!(matches!(err, ExportError::Undecryptable(_)));
        let rendered = format!("{err} / {err:?}");
        for word in PHRASE.split_whitespace() {
            assert!(
                !rendered.contains(word),
                "the error text leaked the mnemonic word {word:?}: {rendered}"
            );
        }
    }

    /// **Proves:** an absent file is reported as absent rather than as a password failure,
    /// so a user is not told to retype a password for a wallet this node never held.
    #[test]
    fn missing_file_is_reported_as_missing() {
        let dir = scratch("missing");
        let path = dir.path().join("nothing-here.bin");

        let err =
            export_mnemonic(&path, &password("fixture")).expect_err("an absent file must fail");

        assert!(matches!(err, ExportError::NotFound(_)));
    }

    /// **Proves:** exporting does not modify the file. The rescue runs against what may be
    /// the only surviving copy of a spend key, so a read that wrote back would be a
    /// funds-loss bug rather than a tidiness one.
    #[test]
    fn export_leaves_the_file_byte_identical() {
        let dir = scratch("readonly");
        let path = write_legacy_fixture(dir.path(), &password("fixture"));
        let before = std::fs::read(&path).expect("read before");

        export_mnemonic(&path, &password("fixture")).expect("export");
        let _ = export_mnemonic(&path, &password("wrong"));

        assert_eq!(before, std::fs::read(&path).expect("read after"));
    }
}
