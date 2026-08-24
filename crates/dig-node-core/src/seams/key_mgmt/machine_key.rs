//! Seam 7's at-rest half (dig_ecosystem#2168): the node's MACHINE identity seed, sealed in a
//! `dig-keystore` [`opaque`] container instead of the ad-hoc plaintext `identity_key.bin` that
//! `digstore_remote::identity::load_or_create_seed` writes.
//!
//! # What this is, and what it is NOT (#908, dig-node `SPEC.md` §16.4)
//!
//! This seed is the node **authenticating itself** — it derives the BLS key the node's CA-signed
//! [`NodeCert`](dig_tls::NodeCert) is bound to, and therefore the stable `peer_id` the peer
//! network knows the node by. It is **explicitly not user custody**: the user's DID/wallet keys
//! live in the dig-app and never enter the engine, and dig-node#327 removed the node-side user
//! custody plane outright. `dig-keystore` is consumed with its `custody` feature OFF for exactly
//! that reason — the boundary is expressed in the dependency graph, where it can be checked
//! (dig-keystore `SPEC.md` §18.2), rather than only in prose.
//!
//! A later "tighten custody" change must not delete this: the node needs its own credential.
//!
//! # What the container buys today, stated without overselling it
//!
//! The seed is sealed with [`opaque::seal`] (Argon2id + AES-256-GCM, `DIGOP1`) under a
//! per-install random wrapping secret, and both records live in a [`HardwareBoundBackend`] over a
//! [`FileBackend`]. **No platform hardware provider ships yet**, so on every real host the tier
//! resolves to `Software(NotRequested)` and the two records are protected by the owner-only file
//! mode alone — *the same protection the plaintext file it replaces had*. The wrapping secret
//! sits beside the blob because an unattended service has no operator to type a passphrase, and a
//! passphrase the node can always recover by itself is not a secret from anyone who can read the
//! node's own directory. This module does not pretend otherwise, and neither does
//! [`MachineKeyStore::protection_summary`].
//!
//! What it does buy is the shape: once a provider exists, [`HardwareBoundBackend::bind`] wraps
//! both records in place, and the pair stops opening on any other machine — with no format change
//! and no re-minted `peer_id`. [`MachineKeyStore::protection`] reports the *blob's* tier, never
//! the host's, because a capable host does not retroactively protect bytes already at rest
//! (dig-keystore `SPEC.md` §17.5b).
//!
//! # Binding this key is the sanctioned case, and it is not a seed backup
//!
//! dig-keystore `SPEC.md` §17.5b requires an off-device backup before binding a *recovery seed*,
//! because a cleared TPM is permanent and for a wallet seed that is funds loss. This key is
//! **re-issuable** — losing it costs the node its `peer_id` and nothing else, no funds and no
//! identity a user owns — which §17.5b names as the case where binding is a straight hardening
//! win. Nothing here may grow a path that seals a user's seed under the same call.

use std::path::Path;
use std::sync::Arc;

use dig_keystore::backend::{BackendKey, FileBackend, KeychainBackend};
use dig_keystore::hardware::{
    HardwareBoundBackend, HardwarePolicy, HardwareProvider, ProtectionTier,
};
use dig_keystore::{opaque, KdfParams, KeystoreError, Password};
use zeroize::Zeroizing;

/// Storage key of the sealed `DIGOP1` blob holding the 32-byte identity seed.
const SEED_RECORD: &str = "machine-identity";

/// Storage key of the per-install random secret the seed blob is sealed under. A separate record
/// so a future [`HardwareBoundBackend::bind`] wraps it too, rather than leaving the opening secret
/// portable beside a bound blob.
const WRAP_RECORD: &str = "machine-identity-wrap";

/// Bytes of the per-install wrapping secret.
const WRAP_SECRET_LEN: usize = 32;

/// The legacy plaintext file this module supersedes, written by
/// `digstore_remote::identity::load_or_create_seed`. Read once, migrated, then removed.
pub const LEGACY_SEED_FILE: &str = "identity_key.bin";

/// Why the node could not produce a machine identity seed.
#[derive(Debug)]
pub enum MachineKeyError {
    /// The keystore refused a read, write or unseal.
    Keystore(KeystoreError),
    /// The filesystem refused the legacy-file migration.
    Io(std::io::Error),
    /// A stored record decoded, but was not the length its role requires.
    Malformed {
        /// Which record.
        record: &'static str,
        /// How many bytes it held.
        len: usize,
    },
}

impl std::fmt::Display for MachineKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keystore(e) => write!(f, "machine key store: {e}"),
            Self::Io(e) => write!(f, "machine key store: {e}"),
            Self::Malformed { record, len } => write!(
                f,
                "machine key record {record} is {len} bytes, not the expected length"
            ),
        }
    }
}

impl std::error::Error for MachineKeyError {}

impl From<KeystoreError> for MachineKeyError {
    fn from(e: KeystoreError) -> Self {
        Self::Keystore(e)
    }
}

impl From<std::io::Error> for MachineKeyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The node's sealed machine-identity seed, over one directory.
pub struct MachineKeyStore {
    backend: HardwareBoundBackend,
    kdf: KdfParams,
}

impl MachineKeyStore {
    /// Open the store rooted at `dir`, resolving the protection tier once.
    ///
    /// `provider` is the host's hardware key-wrapping provider. **Production passes
    /// [`platform_provider`], which is `None` on every host today**; tests inject a double to
    /// exercise the bound tier. The policy is [`HardwarePolicy::Optional`] so a node on a host
    /// with no trusted component still starts and simply reports what protects its key — refusing
    /// to boot the peer network over absent hardware would strand every node in existence.
    ///
    /// # Errors
    /// [`MachineKeyError::Keystore`] if the tier cannot be resolved.
    pub fn open(
        dir: impl AsRef<Path>,
        provider: Option<Arc<dyn HardwareProvider>>,
    ) -> Result<Self, MachineKeyError> {
        Ok(Self {
            backend: HardwareBoundBackend::new(
                FileBackend::new(dir.as_ref()),
                provider,
                HardwarePolicy::Optional,
            )?,
            kdf: KdfParams::DEFAULT,
        })
    }

    /// Cheap KDF parameters, so a test suite is not 64 MiB of Argon2id per seal. Tests only:
    /// `FAST_TEST` is deliberately not a security floor, and production never reaches this.
    #[cfg(test)]
    fn with_fast_kdf(mut self) -> Self {
        self.kdf = KdfParams::FAST_TEST;
        self
    }

    /// The node's 32-byte identity seed: unsealed if a blob exists, migrated from
    /// `legacy_dir/identity_key.bin` if one is there, else freshly minted and sealed.
    ///
    /// **An existing blob that will not open is an error, never a re-mint.** Regenerating here
    /// would hand the node a brand-new `peer_id`, silently changing the identity the whole peer
    /// network knows it by, in exactly the situation where the real key is most likely still
    /// intact on the machine that sealed it.
    ///
    /// # Errors
    /// [`MachineKeyError`] if a record cannot be read, unsealed, or written.
    pub fn load_or_create(
        &self,
        legacy_dir: Option<&Path>,
    ) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
        let seed_key = BackendKey::new(SEED_RECORD);
        if self.backend.exists(&seed_key)? {
            return self.unseal_stored(&seed_key);
        }
        let seed = match legacy_dir.map(Self::read_legacy).transpose()?.flatten() {
            Some(seed) => seed,
            None => Zeroizing::new(random_bytes::<32>()),
        };
        self.seal_new(&seed_key, &seed)?;
        if let Some(dir) = legacy_dir {
            // Only reached once `seal_new` has proven the sealed copy reads back from storage:
            // removing the one plaintext copy before that would destroy the node's identity.
            let _ = std::fs::remove_file(dir.join(LEGACY_SEED_FILE));
        }
        Ok(seed)
    }

    /// What protects **this node's stored seed** — read from the blob, not inferred from the host.
    ///
    /// # Errors
    /// [`MachineKeyError::Keystore`] if no seed is stored yet, or the blob cannot be classified.
    pub fn protection(&self) -> Result<ProtectionTier, MachineKeyError> {
        Ok(self.backend.blob_tier(&BackendKey::new(SEED_RECORD))?)
    }

    /// One honest sentence about the stored seed's protection, fit for a log line or status field.
    ///
    /// On a host with no provider this says the key is protected by file permissions and names the
    /// reason the tier degraded — it never implies hardware backing the key does not have. On a
    /// blob this host cannot open it makes **no recovery promise**: dig-keystore `SPEC.md` §17.5b
    /// records that the envelope carries a hardware *class* and no device identity, so the same
    /// error is returned for a blob copied off its machine (recoverable by going back) and for the
    /// original machine with its trusted component wiped (permanent). Any reassurance would be a
    /// guess, and the wrong guess is the irreversible one.
    pub fn protection_summary(&self) -> String {
        match self.protection() {
            // The blob names a hardware CLASS and carries no device identity, so "it is wrapped"
            // is NOT "this host can open it". Only a host bound to the same class may speak in the
            // first person about it; anything else gets the conditional below.
            Ok(ProtectionTier::Hardware(kind))
                if self.backend.tier() == &ProtectionTier::Hardware(kind) =>
            {
                format!(
                    "machine identity key is sealed to this host's {kind}; it does not open on \
                     another machine"
                )
            }
            Ok(ProtectionTier::Hardware(kind)) => format!(
                "machine identity key is sealed to {kind} hardware this host is not bound to; it \
                 may open on the machine that sealed it only if that machine's trusted component \
                 is intact"
            ),
            Ok(tier @ ProtectionTier::Software(_)) => format!(
                "machine identity key is {tier}: protected by owner-only file permissions, not by \
                 hardware, and it would open on another machine"
            ),
            Err(e) => format!("machine identity key protection is unknown: {e}"),
        }
    }

    /// Unseal an already-stored seed blob.
    fn unseal_stored(&self, seed_key: &BackendKey) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
        let wrap = self.read_wrap_secret()?;
        let blob = self.backend.read(seed_key)?;
        let plain = opaque::open(&Password::new(wrap.as_slice()), &blob)?;
        exactly_32(SEED_RECORD, &plain)
    }

    /// Seal `seed` under a fresh wrapping secret, proving it reads back before reporting success.
    fn seal_new(
        &self,
        seed_key: &BackendKey,
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<(), MachineKeyError> {
        let wrap = Zeroizing::new(random_bytes::<WRAP_SECRET_LEN>());
        self.backend
            .write(&BackendKey::new(WRAP_RECORD), wrap.as_slice())?;
        let blob = opaque::seal(&Password::new(wrap.as_slice()), seed.as_slice(), self.kdf)?;
        self.backend.write(seed_key, &blob)?;

        // Prove the round trip from STORAGE, not from the value just computed. A seal this host
        // cannot reopen has replaced the only copy of the node's identity with unreadable bytes,
        // and a success returned over that is the worst outcome this module has.
        let reopened = self.unseal_stored(seed_key)?;
        if reopened.as_slice() != seed.as_slice() {
            return Err(MachineKeyError::Malformed {
                record: SEED_RECORD,
                len: reopened.len(),
            });
        }
        Ok(())
    }

    /// The per-install wrapping secret.
    fn read_wrap_secret(&self) -> Result<Zeroizing<Vec<u8>>, MachineKeyError> {
        let bytes = self.backend.read(&BackendKey::new(WRAP_RECORD))?;
        if bytes.len() != WRAP_SECRET_LEN {
            return Err(MachineKeyError::Malformed {
                record: WRAP_RECORD,
                len: bytes.len(),
            });
        }
        Ok(Zeroizing::new(bytes))
    }

    /// The legacy plaintext seed, if `dir` holds one.
    fn read_legacy(dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, MachineKeyError> {
        let path = dir.join(LEGACY_SEED_FILE);
        if !path.exists() {
            return Ok(None);
        }
        exactly_32(LEGACY_SEED_FILE, &std::fs::read(&path)?).map(Some)
    }
}

/// Narrow a stored record to the 32 bytes a seed must be.
fn exactly_32(record: &'static str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
    <[u8; 32]>::try_from(bytes)
        .map(Zeroizing::new)
        .map_err(|_| MachineKeyError::Malformed {
            record,
            len: bytes.len(),
        })
}

/// `N` bytes from the OS CSPRNG. Panics only if the CSPRNG is unavailable, which on any supported
/// platform means the process cannot safely produce key material at all.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out)
        .expect("operating system CSPRNG must be available to generate key material");
    out
}

/// The user-global DIG identity directory the node's machine key lives in:
/// `$DIG_IDENTITY_DIR`, else `<config_dir>/dig` (`~/.config/dig`, `%APPDATA%\dig`).
///
/// This is deliberately the SAME directory `digstore_remote::identity` used for the plaintext
/// `identity_key.bin`, so the migration finds the existing seed in place and the node keeps its
/// `peer_id`. The path is reproduced here rather than imported because digstore keeps its
/// `identity_dir` private; the `DIG_IDENTITY_DIR` override must stay byte-identical to it, or a
/// node started under that variable would silently mint a second identity.
///
/// # Errors
/// [`MachineKeyError::Io`] if the platform exposes no config directory.
pub fn identity_store_dir() -> Result<std::path::PathBuf, MachineKeyError> {
    if let Some(dir) = std::env::var_os("DIG_IDENTITY_DIR") {
        return Ok(std::path::PathBuf::from(dir));
    }
    dirs::config_dir()
        .map(|base| base.join("dig"))
        .ok_or_else(|| {
            MachineKeyError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no OS config directory available for the dig identity key",
            ))
        })
}

/// This host's hardware key-wrapping provider.
///
/// **`None` on every host today.** `dig-keystore` ships no platform binding — its `hardware`
/// module forbids `unsafe`, so the TPM / Secure-Enclave FFI lives in a future workspace member
/// (dig_ecosystem#1693) — so every host resolves `Software(NotRequested)`. This function is the
/// single seam that changes when that lands; nothing else in the node moves.
pub fn platform_provider() -> Option<Arc<dyn HardwareProvider>> {
    None
}

/// Load or mint the node's machine identity seed under `dir`, migrating a legacy plaintext
/// `identity_key.bin` from `legacy_dir` if one is present.
///
/// # Errors
/// [`MachineKeyError`] if the store cannot be opened, read, or written.
pub fn load_or_create_sealed_seed(
    dir: impl AsRef<Path>,
    legacy_dir: Option<&Path>,
) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
    MachineKeyStore::open(dir, platform_provider())?.load_or_create(legacy_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::hardware::double::FakeDevice;
    use dig_keystore::hardware::{DegradeReason, HardwareKind};

    /// A store over `dir` with no hardware provider — what every real host resolves today.
    fn software_store(dir: &Path) -> MachineKeyStore {
        MachineKeyStore::open(dir, None)
            .expect("Optional policy opens on a host with no provider")
            .with_fast_kdf()
    }

    /// A store over `dir` bound to a specific fake trusted component. `device_id` IS the machine:
    /// two ids are two hosts, which is how the cross-machine property is exercised at all while
    /// no platform provider ships (dig_ecosystem#1693).
    fn hardware_store(dir: &Path, device_id: u8) -> MachineKeyStore {
        MachineKeyStore::open(
            dir,
            Some(Arc::new(FakeDevice::working(
                HardwareKind::WindowsTpm20,
                device_id,
            ))),
        )
        .expect("a self-testing provider resolves the hardware tier")
        .with_fast_kdf()
    }

    /// Every byte at rest under `dir`, concatenated — the view an attacker with read access has.
    fn all_bytes_at_rest(dir: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("store dir") {
            let path = entry.expect("dir entry").path();
            if path.is_file() {
                out.extend_from_slice(&std::fs::read(&path).expect("record"));
            }
        }
        out
    }

    /// Whether `haystack` contains `needle` as a contiguous run.
    fn contains_run(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// **Proves:** `DIG_IDENTITY_DIR` still selects the identity directory.
    ///
    /// **Catches:** dropping the override while reproducing digstore's private `identity_dir`.
    /// That regression is invisible on a developer machine — the default branch works fine — and
    /// shows up only as a node started under the variable minting a SECOND identity beside the
    /// one it already had, silently changing its `peer_id`.
    #[test]
    fn the_identity_dir_override_is_honoured() {
        let dir = tempfile::tempdir().expect("tempdir");
        let previous = std::env::var_os("DIG_IDENTITY_DIR");
        std::env::set_var("DIG_IDENTITY_DIR", dir.path());

        let resolved = identity_store_dir().expect("override resolves");

        match previous {
            Some(v) => std::env::set_var("DIG_IDENTITY_DIR", v),
            None => std::env::remove_var("DIG_IDENTITY_DIR"),
        }
        assert_eq!(
            resolved,
            dir.path(),
            "DIG_IDENTITY_DIR must win, exactly as it does for the legacy plaintext seed"
        );
    }

    /// **Proves:** the seed survives a round trip through the container at all — the control every
    /// other test here needs in order to mean anything.
    #[test]
    fn a_sealed_seed_reopens_to_the_same_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path());

        let minted = store.load_or_create(None).expect("mint");
        let reopened = store.load_or_create(None).expect("reopen");

        assert_eq!(
            minted.as_slice(),
            reopened.as_slice(),
            "the second call must unseal the stored seed, not mint a second one"
        );
    }

    /// **Proves:** the node keeps its `peer_id` across a restart, which is the whole point of a
    /// PERSISTENT machine identity.
    ///
    /// **Catches:** a store that re-mints on every process start. That regression is invisible to
    /// a single-`MachineKeyStore` test, because the nearest wrong implementation caches the seed
    /// in the struct — so this deliberately opens a SECOND store over the same directory, the way
    /// a restart does.
    #[test]
    fn a_restart_over_the_same_directory_recovers_the_same_seed() {
        let dir = tempfile::tempdir().expect("tempdir");

        let first = software_store(dir.path()).load_or_create(None).expect("mint");
        let after_restart = software_store(dir.path())
            .load_or_create(None)
            .expect("restart");

        assert_eq!(
            first.as_slice(),
            after_restart.as_slice(),
            "a restart must recover the identity, not silently change the node's peer_id"
        );
    }

    /// **Proves:** the seed is not readable from the bytes on disk — the defect
    /// dig_ecosystem#2168 names, where `identity_key.bin` held the raw 32 bytes.
    ///
    /// The needle is the seed the store just returned, so this cannot pass by scanning for a
    /// value the fixture invented; and it scans EVERY file under the root, so moving the plaintext
    /// into a sibling record would still be caught.
    #[test]
    fn the_seed_never_appears_verbatim_in_any_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path());
        let seed = store.load_or_create(None).expect("mint");

        let at_rest = all_bytes_at_rest(dir.path());
        assert!(
            !at_rest.is_empty(),
            "control: the store must actually have written something to scan"
        );
        assert!(
            contains_run(&at_rest, &at_rest[..8]),
            "control: the scanner must be able to find a run that IS present"
        );
        assert!(
            !contains_run(&at_rest, seed.as_slice()),
            "the identity seed is at rest in plaintext"
        );
    }

    /// **Proves:** an existing node keeps its identity when it upgrades onto the sealed container,
    /// and the plaintext file it came from is gone afterwards.
    ///
    /// **Catches:** a migration that mints a fresh seed (the node loses its peer_id on upgrade)
    /// AND one that seals a copy while leaving the readable original in place, which would make
    /// the whole change cosmetic. Both are asserted, because either alone passes over the other.
    #[test]
    fn a_legacy_plaintext_seed_is_adopted_and_its_file_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let legacy = tempfile::tempdir().expect("legacy dir");
        let legacy_seed = [0xA7u8; 32];
        std::fs::write(legacy.path().join(LEGACY_SEED_FILE), legacy_seed).expect("legacy seed");

        let adopted = software_store(dir.path())
            .load_or_create(Some(legacy.path()))
            .expect("migrate");

        assert_eq!(
            adopted.as_slice(),
            &legacy_seed,
            "migration must carry the existing identity forward, not mint a new one"
        );
        assert!(
            !legacy.path().join(LEGACY_SEED_FILE).exists(),
            "the plaintext seed must not survive the migration"
        );
        assert_eq!(
            software_store(dir.path())
                .load_or_create(None)
                .expect("restart after migration")
                .as_slice(),
            &legacy_seed,
            "the migrated seed must be recoverable from the sealed copy alone"
        );
    }

    /// **Proves the negative the hardware tier exists to buy:** a seed sealed on one machine does
    /// not open on another.
    ///
    /// The fixture varies exactly ONE thing — the device id, i.e. which machine — and keeps a
    /// truthful control: after the foreign device is refused, the ORIGINAL device is asked again
    /// and must still return the original seed. Without that control an implementation that had
    /// simply destroyed the blob would pass, which is the opposite of the property under test.
    ///
    /// **Catches:** the worst available regression — re-minting on an unseal failure. That would
    /// make `load_or_create` succeed on the foreign machine and hand the node a new identity,
    /// while an assertion written only as "the returned set is empty" would not notice.
    #[test]
    fn a_seed_sealed_by_one_machine_does_not_open_on_another() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = hardware_store(dir.path(), 1)
            .load_or_create(None)
            .expect("seal on machine 1");
        let blob_before = all_bytes_at_rest(dir.path());

        let foreign = hardware_store(dir.path(), 2).load_or_create(None);

        assert!(
            foreign.is_err(),
            "a seed bound to another machine must not open here, and must NOT be re-minted: got {:?}",
            foreign.as_ref().map(|s| hex::encode(s.as_slice()))
        );
        assert_eq!(
            all_bytes_at_rest(dir.path()),
            blob_before,
            "the refusal must leave the stored identity byte-identical"
        );
        assert_eq!(
            hardware_store(dir.path(), 1)
                .load_or_create(None)
                .expect("the sealing machine still opens it")
                .as_slice(),
            sealed.as_slice(),
            "control: the original machine must still recover the identity"
        );
    }

    /// **Proves:** a host with no hardware provider reports what it actually has.
    ///
    /// **Catches:** a summary that advertises hardware backing on the tier every real host
    /// resolves today — the "claiming protection it lacks" failure. Asserted on the tier AND on
    /// the sentence, because a correct tier rendered into a reassuring sentence is the version a
    /// user would actually be misled by.
    #[test]
    fn a_host_with_no_provider_reports_software_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = software_store(dir.path());
        store.load_or_create(None).expect("mint");

        // The two tiers answer different questions and are pinned separately on purpose: the HOST
        // has no provider, and the BLOB is therefore an unwrapped software envelope. Asserting
        // only one of them is how a summary ends up rendering the wrong one (see
        // `an_unwrapped_blob_on_a_capable_host_is_reported_as_software`, where they disagree).
        assert_eq!(
            store.backend.tier(),
            &ProtectionTier::Software(DegradeReason::NotRequested),
            "no platform provider ships today, so this is the honest HOST tier"
        );
        assert_eq!(
            store.protection().expect("tier"),
            ProtectionTier::Software(DegradeReason::BlobNotWrapped),
            "with no hardware to wrap it, the stored blob is the bare passphrase envelope"
        );

        let summary = store.protection_summary();
        assert!(
            summary.contains("not by hardware"),
            "summary must not leave hardware backing implied: {summary}"
        );
        assert!(
            summary.contains("would open on another machine"),
            "summary must state the copy-resistance this key does NOT have: {summary}"
        );
    }

    /// **Proves:** the blob's OWN tier is reported, not the host's.
    ///
    /// **Catches:** rendering `HardwareBoundBackend::tier()` instead of `blob_tier()`. The fixture
    /// is the one place the two disagree: a hardware-capable host holding a blob written before
    /// binding. A host-tier implementation calls that key TPM-protected, which is a claim of
    /// copy-resistance the bytes do not have — and note the tier value alone cannot catch this,
    /// which is why the fixture puts a software blob under a hardware host rather than asserting
    /// the outcome on a matched pair.
    #[test]
    fn an_unwrapped_blob_on_a_capable_host_is_reported_as_software() {
        let dir = tempfile::tempdir().expect("tempdir");
        software_store(dir.path()).load_or_create(None).expect("mint unwrapped");

        let capable = hardware_store(dir.path(), 1);

        assert!(
            capable.backend.tier().is_hardware_bound(),
            "control: the HOST must be hardware-capable, or this proves nothing"
        );
        assert_eq!(
            capable.protection().expect("blob tier"),
            ProtectionTier::Software(DegradeReason::BlobNotWrapped),
            "a capable host does not retroactively protect bytes already at rest"
        );
    }

    /// **Proves:** an unopenable blob gets no recovery promise (dig-keystore `SPEC.md` §17.5b).
    ///
    /// `HardwareUnwrapFailed` is returned identically for a blob copied off its machine
    /// (recoverable by going back) and for the original machine with its trusted component wiped
    /// (permanent, unrecoverable). So the surface may state the conditional and must never
    /// reassure — this pins the words that would do so.
    #[test]
    fn an_unopenable_blob_is_described_without_a_recovery_promise() {
        let dir = tempfile::tempdir().expect("tempdir");
        hardware_store(dir.path(), 1).load_or_create(None).expect("seal");

        let summary = software_store(dir.path()).protection_summary();

        for banned in ["recoverable", "will open", "simply", "safe to"] {
            assert!(
                !summary.to_lowercase().contains(banned),
                "summary makes a recovery promise the error cannot support ({banned}): {summary}"
            );
        }
        assert!(
            summary.contains("only if"),
            "summary must state the condition it cannot verify, rather than omitting it: {summary}"
        );
    }
}
