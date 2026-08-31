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
//! The seed is sealed with [`opaque::seal`] (Argon2id + AES-256-GCM, `DIGOP1`) under a 32-byte
//! CSPRNG **device key**, exactly the shape dig-node `SPEC.md` §16.4 already specifies for the
//! wallet host's unattended `autoseed` — same container, same key model, so the node has ONE
//! at-rest primitive rather than two rival ones.
//!
//! **The device key lives in a SIBLING directory, never beside the sealed blob** (§16.4: "that
//! separation IS the partial-exfiltration boundary"). An unattended service has no operator to
//! type a passphrase, so the key it seals under must be on disk somewhere; putting it in the same
//! directory would mean any copy of that directory — a backup, a synced folder, a support bundle,
//! a container image layer — carries both halves and the container protects nothing. Split, the
//! common single-directory grab yields ciphertext.
//!
//! **Platform hardware binding is LIVE** (dig-node#367): [`MachineKeyStore::open_platform_bound`]
//! walks the `dig-keystore-hardware` ladder -- Windows TPM 2.0 via CNG, Apple Secure Enclave,
//! Linux TPM 2.0 -- and a host that can prove one seals both halves under a wrapping key that
//! cannot leave that component, so copying the directory to another machine yields bytes nobody
//! can open. A host that cannot lands on the software floor and SAYS WHY.
//!
//! On that floor -- which is still where most hosts and every CI runner land -- what protects the
//! two halves is their SEPARATION, plus whatever file permissions the platform gives them, which
//! is NOT the same on both. On Unix each is mode `0600`, set at `open` time. **On Windows both
//! inherit the profile ACL**: dig-keystore `FileBackend`s `enforce_owner_only` is `#[cfg(unix)]`,
//! and this module installs no explicit DACL either, unlike `SPEC.md` §16.4s wallet files.
//! [`at_rest_floor`] is the ONE place that sentence is written, so
//! [`MachineKeyStore::protection_summary`] cannot drift from it.
//!
//! Hardware wrapping is an OUTER envelope: the format does not change and the `peer_id` is not
//! re-minted when a host gains or loses it. [`MachineKeyStore::protection`] reports the *blob's*
//! tier, never the host's, because a capable host does not retroactively protect bytes already at
//! rest (dig-keystore `SPEC.md` §17.5b) -- an existing keystore stays software-tier until it is
//! rewritten on the capable host.
//!
//! # Two failure behaviours, both carried over from `SPEC.md` §16.4
//!
//! Sealing RAISES the cost of getting these wrong. The artifact this replaced was a single
//! plaintext file, so a spurious "it is not there" minted a new seed *beside a recoverable
//! original*. With two coupled sealed halves the same misread destroys the identity permanently,
//! because both halves are replaced at once. So:
//!
//! - **Existence is answered by [`presence`], never `Path::exists`.** `exists()` reports a locked,
//!   permission-denied or otherwise unreadable path as ABSENT, and the next thing this module does
//!   with an absent answer is MINT. An undeterminable read refuses
//!   ([`MachineKeyError::ExistenceUndeterminable`]) instead of guessing.
//! - **The device key is installed with `create_new`, the OS atomic test-and-set.** Two starts
//!   racing -- a service restart overlapping the outgoing process, or a manual run beside the
//!   service -- cannot each install a different device key, so the state "process B key beside
//!   process A blob" is unreachable rather than merely unlikely. Where the two halves are
//!   nonetheless mismatched (a half-restored backup), that state has a NAME and a stated remedy
//!   ([`MachineKeyError::DeviceKeyUnusable`]), because the no-re-mint rule cannot heal it.
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

use crate::shared::at_rest::{presence, write_new_owner_only, Presence};
use zeroize::Zeroizing;

/// Storage key of the sealed `DIGOP1` blob holding the 32-byte identity seed.
const SEED_RECORD: &str = "machine-identity";

/// Filename of the per-install device key the seed blob is sealed under. Held in the SIBLING
/// device directory, never beside the blob — see the module doc, and dig-node `SPEC.md` §16.4,
/// which specifies the same split for the wallet host.
const DEVICE_KEY_FILE: &str = "device.key";

/// Bytes of the per-install device key. Matches §16.4's `device.key`: 32 raw CSPRNG bytes.
const DEVICE_KEY_LEN: usize = 32;

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
    /// Whether the identity is already on disk could not be DETERMINED, so nothing was minted.
    ///
    /// Refusing is the whole point. Treating an unreadable path as an absent one would mint a new
    /// seed over a real identity whose two halves are then both gone.
    ExistenceUndeterminable {
        /// The path whose existence could not be read.
        path: std::path::PathBuf,
        /// Why the metadata read failed.
        source: std::io::Error,
    },
    /// The seed blob is on disk but its device key is missing or does not open it.
    ///
    /// Named, rather than surfaced as a bare decrypt failure, because it is the ONE state the
    /// no-re-mint rule cannot heal by itself and the operator has to act on.
    DeviceKeyUnusable {
        /// Where the device key is expected.
        device_key: std::path::PathBuf,
        /// Where the sealed blob lives.
        blob_dir: std::path::PathBuf,
        /// What went wrong.
        detail: String,
    },
    /// The device key is THERE but could not be read right now.
    ///
    /// Split from [`Self::DeviceKeyUnusable`] because the two carry opposite instructions and
    /// only one of them is safe to act on. A sharing violation from an on-access scanner, a
    /// roaming-profile sync, or a transient I/O error all surface here — and every one of them
    /// resolves by itself. Folding them into the mismatch variant asserted a false cause about a
    /// file that was present and intact, and told the operator to REMOVE BOTH HALVES, which
    /// destroys the identity this module exists to protect. Undeterminable means retry, never
    /// remove.
    DeviceKeyUnreadable {
        /// Where the device key is.
        path: std::path::PathBuf,
        /// Why this read failed. Says nothing about whether the key is correct.
        source: std::io::Error,
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
            Self::ExistenceUndeterminable { path, source } => write!(
                f,
                concat!(
                    "cannot determine whether the machine identity already exists at {} ({}). ",
                    "Refusing to mint a new one, because minting over an existing identity would ",
                    "destroy it permanently. This is usually transient: resolve the access error ",
                    "and restart. Do not remove anything."
                ),
                path.display(),
                source
            ),
            Self::DeviceKeyUnreadable { path, source } => write!(
                f,
                concat!(
                    "the machine identity device key at {} is present but could not be read ",
                    "({}). This says NOTHING about whether it is the right key -- a locked or ",
                    "temporarily unreadable file is not a wrong one. It is usually transient ",
                    "(an on-access scanner, a profile sync, a busy volume): retry, and do not ",
                    "remove either half."
                ),
                path.display(),
                source
            ),
            Self::DeviceKeyUnusable {
                device_key,
                blob_dir,
                detail,
            } => write!(
                f,
                concat!(
                    "the machine identity in {} could not be opened by the device key at {} ",
                    "({}).
KNOWN: the two do not currently match.
UNDETERMINED: which of them ",
                    "is the wrong one, and whether the matching half still exists somewhere. ",
                    "Nothing here can tell you.
DO FIRST: restore {} from the same backup as {}, ",
                    "and confirm the node starts.
ONLY IF you are certain no matching device key ",
                    "exists anywhere does removing both halves become the remedy -- that mints a ",
                    "new identity and permanently discards the old peer_id."
                ),
                blob_dir.display(),
                device_key.display(),
                detail,
                device_key.display(),
                blob_dir.display()
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
    /// Holds the sealed `DIGOP1` seed blob.
    backend: HardwareBoundBackend,
    /// Path of the device key the blob is sealed under, in a sibling directory.
    ///
    /// A raw 32-byte file rather than a keystore record, matching `SPEC.md` §16.4's `device.key`
    /// exactly. The reason is atomicity, not layering: it is written with `create_new`, the OS's
    /// own test-and-set, so two concurrent starts cannot each install a different device key and
    /// leave one process's key beside the other's blob. `FileBackend::write` is
    /// tmp-plus-rename, i.e. REPLACE semantics, which is precisely the operation that produces
    /// that mismatch.
    device_key_path: std::path::PathBuf,
    /// The identity directory the sealed blob lives in, for the path-level presence check and for
    /// naming both halves in [`MachineKeyError::DeviceKeyUnusable`].
    blob_dir: std::path::PathBuf,
    kdf: KdfParams,
    /// Runs between the blob write and the read-back in [`Self::seal_new`]. Tests only.
    ///
    /// The read-back exists so the LOSING racer adopts the winner identity, and that property is
    /// unobservable without a way to make another writer land inside the window -- which is
    /// exactly how a mutation replacing the read-back with the value just computed stayed green.
    /// This hook is the seam that makes the window reachable from a test.
    #[cfg(test)]
    after_blob_write: Option<Box<dyn Fn() + Send + Sync>>,
}

impl MachineKeyStore {
    /// Open the store rooted at `dir`, resolving the protection tier once.
    ///
    /// `provider` is a hardware key-wrapping provider chosen by the CALLER — the seam a test
    /// injects a double through. **Production does not use this constructor**; it uses
    /// [`Self::open_platform_bound`], which walks the real platform ladder.
    ///
    /// The policy is [`HardwarePolicy::Optional`] so a node on a host with no trusted component
    /// still starts and simply reports what protects its key — refusing to boot the peer network
    /// over absent hardware would strand every node in existence.
    ///
    /// # Errors
    /// [`MachineKeyError::Keystore`] if the tier cannot be resolved.
    pub fn open(
        dir: impl AsRef<Path>,
        provider: Option<Arc<dyn HardwareProvider>>,
    ) -> Result<Self, MachineKeyError> {
        let dir = dir.as_ref();
        Ok(Self {
            backend: HardwareBoundBackend::new(
                FileBackend::new(dir),
                provider,
                HardwarePolicy::Optional,
            )?,
            device_key_path: device_dir(dir)?.join(DEVICE_KEY_FILE),
            blob_dir: dir.to_path_buf(),
            kdf: KdfParams::DEFAULT,
            #[cfg(test)]
            after_blob_write: None,
        })
    }

    /// Open the store rooted at `dir`, bound to the strongest trusted component THIS host can
    /// actually prove — the production constructor.
    ///
    /// # Why the ladder chooses, rather than this function
    ///
    /// [`dig_keystore_hardware::bind_strongest`] walks every platform candidate in preference
    /// order, and a candidate is only accepted once it has passed a live wrap/unwrap self-test.
    /// Taking `platform_candidates().next()` instead would hand over the FIRST candidate whether
    /// or not it works, and a TPM that fails its round-trip would degrade the whole node to
    /// software rather than falling to the next rung.
    ///
    /// It also distinguishes the two negatives that matter to an operator: a platform this build
    /// ships no provider for reports *that*, where a bare `None` provider would report
    /// `NotRequested` — "nobody asked" — when the truth is "nobody could answer".
    ///
    /// # It asks strictly, and it handles the no
    ///
    /// The policy asked for is [`HardwarePolicy::Preferred`], which is the only one that refuses
    /// to turn *"this host could not be inspected"* into *"this host has no hardware"*. That
    /// distinction is the whole point of the tier being reported at all, so the strict ask is
    /// right — but a refusal cannot be allowed to reach the caller, because
    /// [`Self::open_platform_bound`] is on the node's BOOT path and a node that cannot construct
    /// its machine key is a node that cannot start.
    ///
    /// [`HardwarePolicy::Required`] is not a candidate at all: it would lock out every host whose
    /// provider cannot bind — an Intel Mac, a Linux box with no TPM, a CI runner — which is a
    /// lockout rather than a posture.
    ///
    /// So the shape is ask-strictly-then-degrade-explicitly, in
    /// [`bind_preferring_hardware`]: on the one refusal `Preferred` can produce, re-bind under
    /// [`HardwarePolicy::Optional`] and **say so, with the probe's own detail**. The downgrade
    /// becomes a stated decision in the log and in [`Self::protection_summary`], instead of
    /// either a silent one or a dead node.
    ///
    /// # This is the node's machine key, not user custody
    ///
    /// The seed sealed here is `DIGOP1`/`DIGVK1` — the identity the node dials peers under. It is
    /// NOT a user's wallet key, and §908's boundary is untouched by this: the node still holds no
    /// key it can spend a user's funds with, before this change or after it.
    ///
    /// # Errors
    /// [`MachineKeyError::Keystore`] if the ladder cannot settle a tier even under `Optional`.
    pub fn open_platform_bound(dir: impl AsRef<Path>) -> Result<Self, MachineKeyError> {
        let dir = dir.as_ref();
        let backend = bind_preferring_hardware(
            |policy| dig_keystore_hardware::bind_strongest(FileBackend::new(dir), policy),
            |detail, tier| {
                tracing::warn!(
                    probe_detail = %detail,
                    tier = %tier,
                    "machine key: hardware binding WAS attempted and could not be established — \
                     this host's trusted component answered inconclusively, which is not the same \
                     as its absence. Continuing on the software tier; the component may still be \
                     present and worth investigating"
                );
            },
        )?;
        Ok(Self {
            backend,
            device_key_path: device_dir(dir)?.join(DEVICE_KEY_FILE),
            blob_dir: dir.to_path_buf(),
            kdf: KdfParams::DEFAULT,
            #[cfg(test)]
            after_blob_write: None,
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
        // `presence`, never `Path::exists`. `exists()` reports a locked, permission-denied or
        // otherwise unreadable path as ABSENT, and the one branch below that mints would then
        // overwrite both halves of a real identity that was merely unreadable for a moment.
        // Before this seed was sealed that misread cost a recoverable duplicate; now both halves
        // would be gone, so the read refuses instead.
        //
        // Written as a MATCH with both arms named rather than as an early `return`: the mint is
        // reachable from exactly one arm, and a reader can see which one without tracing control
        // flow (dig-node#345).
        match self.seed_presence()? {
            Presence::Present => self.unseal_stored(&seed_key),
            Presence::Absent => self.mint_or_migrate(&seed_key, legacy_dir),
        }
    }

    /// No sealed blob exists: adopt a legacy plaintext seed if there is one, else mint a fresh one.
    ///
    /// # The no-mint rule, stated as an arm rather than carried by an operator
    ///
    /// This is the only code path in the module that can create a new identity, and the only one
    /// that deletes the legacy plaintext. It may run ONLY on
    /// [`LegacySeed::ConfirmedAbsent`] — a value [`Self::read_legacy`] constructs in a single
    /// place, from a [`Presence::Absent`] answer, and never from a failed read.
    ///
    /// The previous shape was safe only because `read_legacy` happened to use `?` on its
    /// `fs::read`. Swap that one operator for `.ok()` and an unreadable-but-present legacy seed
    /// reads as absent, so this function mints over it and then deletes it — irreversible key
    /// loss, produced by a character. A rule that depends on which operator someone typed is one
    /// refactor away from being gone, so it is a named variant now and
    /// `an_unreadable_legacy_seed_is_never_minted_over_or_deleted` fails if that relaxation is
    /// ever made.
    fn mint_or_migrate(
        &self,
        seed_key: &BackendKey,
        legacy_dir: Option<&Path>,
    ) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
        let legacy = match legacy_dir {
            Some(dir) => Self::read_legacy(dir)?,
            None => LegacySeed::ConfirmedAbsent,
        };
        let seed = match &legacy {
            LegacySeed::Found(seed) => seed.clone(),
            LegacySeed::ConfirmedAbsent => Zeroizing::new(random_bytes::<32>()),
        };
        let settled = self.seal_new(seed_key, &seed)?;
        if let (LegacySeed::Found(_), Some(dir)) = (&legacy, legacy_dir) {
            // Two conditions, both required, and both now visible in the pattern: the legacy seed
            // was CONFIRMED READ (never merely "not seen"), and `seal_new` has proven the sealed
            // copy reads back from storage. Removing the one plaintext copy without either would
            // destroy the node's identity.
            let _ = std::fs::remove_file(dir.join(LEGACY_SEED_FILE));
        }
        Ok(settled)
    }

    /// Whether a sealed seed blob is already stored, refusing to guess.
    ///
    /// # Errors
    /// [`MachineKeyError::ExistenceUndeterminable`] if the metadata read fails.
    fn seed_presence(&self) -> Result<Presence, MachineKeyError> {
        let path = self.seed_blob_path();
        presence(&path).map_err(|source| MachineKeyError::ExistenceUndeterminable { path, source })
    }

    /// Where the keystore keeps the sealed blob. Mirrors `FileBackend`'s `<key>.dks` layout.
    fn seed_blob_path(&self) -> std::path::PathBuf {
        self.blob_dir.join(format!("{SEED_RECORD}.dks"))
    }

    /// What protects **this node's stored seed** — read from the blob, not inferred from the host.
    ///
    /// # Errors
    /// [`MachineKeyError::Keystore`] if no seed is stored yet, or the blob cannot be classified.
    pub fn protection(&self) -> Result<ProtectionTier, MachineKeyError> {
        Ok(self.backend.blob_tier(&BackendKey::new(SEED_RECORD))?)
    }

    /// One honest sentence about the stored SEED's protection, fit for a log line or status field.
    ///
    /// # What sealing does NOT buy, and why that must be said here (dig-node#343)
    ///
    /// Every sentence below describes the stored SEED. It does not describe
    /// `<cache_dir>/peer-net/identity/node.key` — the BLS/TLS key DERIVED from that seed, which
    /// `dig_tls::NodeCert::load_or_generate` persists UNSEALED because the dig-gossip pool
    /// listener loads it from disk by path (`dig_peer_protocol::load_ssl_cert`).
    ///
    /// That derived key is the artifact peers actually authenticate: `peer_id` is
    /// `SHA-256(TLS SPKI DER)`, so whoever reads that one file has this node's network identity
    /// for every purpose the network cares about — dialing as it, serving as it, and any
    /// authorization keyed on it — WITHOUT touching either half of the sealed pair.
    ///
    /// So a summary that said only "sealed to this host" would be true of the seed and false of
    /// the thing a reader assumes it means. [`DERIVED_KEY_CAVEAT`] is therefore appended to every
    /// variant, including the failure one, and
    /// `the_protection_summary_never_claims_copy_resistance_without_naming_the_derived_key`
    /// fails if a variant is added without it.
    ///
    /// Sealing the derived key is the better fix and is NOT done here: the key is written by
    /// `dig-tls`, in another repo, and is read back by path by a third crate, so it is a
    /// release-first cascade rather than a change this module can make. An honest documented gap
    /// beats an unstated one in the meantime.
    ///
    /// On a host with no provider this says the key is protected by file permissions and names the
    /// reason the tier degraded — it never implies hardware backing the key does not have. On a
    /// blob this host cannot open it makes **no recovery promise**: dig-keystore `SPEC.md` §17.5b
    /// records that the envelope carries a hardware *class* and no device identity, so the same
    /// error is returned for a blob copied off its machine (recoverable by going back) and for the
    /// original machine with its trusted component wiped (permanent). Any reassurance would be a
    /// guess, and the wrong guess is the irreversible one.
    pub fn protection_summary(&self) -> String {
        format!("{}. {DERIVED_KEY_CAVEAT}", self.seed_protection_summary())
    }

    /// The seed-only half of [`Self::protection_summary`], without the derived-key caveat.
    ///
    /// Split out so the caveat is appended in ONE place rather than in each arm: a variant added
    /// later cannot forget it, because there is nowhere to forget it.
    fn seed_protection_summary(&self) -> String {
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
                concat!(
                    "machine identity key is {}: not hardware-backed, and it would open on ",
                    "another machine. At rest it is protected by {}."
                ),
                tier,
                at_rest_floor()
            ),
            Err(e) => format!("machine identity key protection is unknown: {e}"),
        }
    }

    /// Unseal an already-stored seed blob.
    fn unseal_stored(&self, seed_key: &BackendKey) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
        let device_key = self.read_device_key()?;
        let blob = self.backend.read(seed_key)?;
        // A device key that is present but does not open the blob beside it is the mismatch
        // state, not a corrupt-file state. Reporting it as a bare `DecryptFailed` would hand the
        // operator the one message that names neither the cause nor the remedy.
        let plain = opaque::open(&Password::new(device_key.as_slice()), &blob)
            .map_err(|e| self.device_key_unusable(e))?;
        exactly_32(SEED_RECORD, &plain)
    }

    /// Seal `seed` under the install device key and return the seed actually SETTLED on disk
    /// afterwards -- which is not always the one passed in.
    ///
    /// # Why this returns a seed instead of the unit type
    ///
    /// Two starts can reach here at once: a service restart racing the outgoing process, or a
    /// manual run beside the service. The device key is installed with `create_new`, the atomic
    /// test-and-set the OS already provides, so exactly one racer creates it and the other
    /// ADOPTS it rather than installing a second. That single decision is what makes the mismatch
    /// state -- process B device key beside process A blob, neither able to open the other --
    /// unreachable rather than merely unlikely.
    ///
    /// Both racers then seal under the SAME device key, so whichever blob write lands last is
    /// openable. The loser reads back a seed it did not mint; that is a correct outcome, not an
    /// error, and adopting it is what makes both processes agree on one `peer_id`.
    fn seal_new(
        &self,
        seed_key: &BackendKey,
        seed: &Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, MachineKeyError> {
        let device_key = self.ensure_device_key()?;
        let blob = opaque::seal(
            &Password::new(device_key.as_slice()),
            seed.as_slice(),
            self.kdf,
        )?;
        self.backend.write(seed_key, &blob)?;
        #[cfg(test)]
        if let Some(hook) = &self.after_blob_write {
            hook();
        }

        // Read back from STORAGE, not from the value just computed. A seal this host cannot
        // reopen has replaced the only copy of the node identity with unreadable bytes, and a
        // success returned over that is the worst outcome this module has.
        self.unseal_stored(seed_key)
    }

    /// The install device key: create it atomically, or adopt the one a concurrent start won.
    ///
    /// `create_new` is the whole mechanism. A [`presence`] check followed by a write would be a
    /// TOCTOU race whose window is exactly a concurrent start -- the case this defends.
    fn ensure_device_key(&self) -> Result<Zeroizing<Vec<u8>>, MachineKeyError> {
        let fresh = Zeroizing::new(random_bytes::<DEVICE_KEY_LEN>());
        match write_new_owner_only(&self.device_key_path, fresh.as_slice()) {
            Ok(()) => Ok(Zeroizing::new(fresh.to_vec())),
            // Another process installed one first. Adopt it -- installing a second would strand
            // whichever blob was sealed under the first.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self.read_device_key(),
            Err(e) => Err(MachineKeyError::Io(e)),
        }
    }

    /// The per-install device key, from the sibling device directory.
    ///
    /// **Three-valued, exactly like [`Self::seed_presence`] and [`Self::read_legacy`]** — and this
    /// is the read where getting it wrong is worst, because its failure message carries a
    /// DESTRUCTIVE instruction. A bare `fs::read` folds a transient sharing violation (os error
    /// 32, what any on-access scanner produces) into the same variant as a genuine mismatch, so
    /// the node asserts a false cause about a present, intact file and tells the operator to
    /// remove both halves. Measured: both halves intact, the same seed opening the instant the
    /// lock released.
    ///
    /// So: **absent** is a real mismatch ([`MachineKeyError::DeviceKeyUnusable`]); **present but
    /// unreadable** is [`MachineKeyError::DeviceKeyUnreadable`], which says retry and never
    /// remove; **undeterminable existence** refuses like every other read here.
    fn read_device_key(&self) -> Result<Zeroizing<Vec<u8>>, MachineKeyError> {
        let path = &self.device_key_path;
        let found = presence(path).map_err(|source| MachineKeyError::ExistenceUndeterminable {
            path: path.clone(),
            source,
        })?;
        if found == Presence::Absent {
            return Err(self.device_key_unusable("it is not there"));
        }
        let bytes = std::fs::read(path).map_err(|source| MachineKeyError::DeviceKeyUnreadable {
            path: path.clone(),
            source,
        })?;
        if bytes.len() != DEVICE_KEY_LEN {
            return Err(self.device_key_unusable(format!(
                "it is {} bytes, not the {DEVICE_KEY_LEN} a device key must be",
                bytes.len()
            )));
        }
        Ok(Zeroizing::new(bytes))
    }

    /// Name the device-key/blob mismatch state, with both paths and the recovery path.
    fn device_key_unusable(&self, detail: impl std::fmt::Display) -> MachineKeyError {
        MachineKeyError::DeviceKeyUnusable {
            device_key: self.device_key_path.clone(),
            blob_dir: self.blob_dir.clone(),
            detail: detail.to_string(),
        }
    }

    /// The legacy plaintext seed at `dir`, three-valued by construction (dig-node#345).
    ///
    /// The two safe answers are VALUES; every unsafe answer is an `Err`. In particular there is
    /// no way to obtain [`LegacySeed::ConfirmedAbsent`] from a failed read: it is produced in
    /// exactly one place, from a [`Presence::Absent`] verdict, which is what makes
    /// "never mint over a seed that is merely unreadable" a property of the type rather than of
    /// the error operator on the next line.
    fn read_legacy(dir: &Path) -> Result<LegacySeed, MachineKeyError> {
        let path = dir.join(LEGACY_SEED_FILE);
        // Same refusal as the mint decision: an unreadable legacy path reported as absent would
        // mint a NEW identity while the real one sat right there, unreadable for a moment.
        let found = presence(&path).map_err(|source| MachineKeyError::ExistenceUndeterminable {
            path: path.clone(),
            source,
        })?;
        match found {
            Presence::Absent => Ok(LegacySeed::ConfirmedAbsent),
            Presence::Present => match std::fs::read(&path) {
                Ok(bytes) => exactly_32(LEGACY_SEED_FILE, &bytes).map(LegacySeed::Found),
                // NAMED, so the rule is legible at the point it is enforced: a legacy seed that
                // is PRESENT but unreadable is a refusal, never an absence. An on-access scanner,
                // a roaming-profile sync or a permission blip all land here, and every one of
                // them resolves by itself — whereas treating any of them as "no seed" mints over
                // the real identity and then deletes it.
                Err(source) => Err(MachineKeyError::ExistenceUndeterminable { path, source }),
            },
        }
    }
}

/// What the legacy plaintext seed read established. Three-valued: the two safe answers are
/// variants and everything else is an `Err` (dig-node#345).
enum LegacySeed {
    /// A legacy plaintext seed was READ and validated. Migrating it is safe, and it is the only
    /// answer that permits deleting the plaintext copy afterwards.
    Found(Zeroizing<[u8; 32]>),
    /// The legacy path was determined to be ABSENT. The ONLY answer that permits minting.
    ///
    /// Constructed in exactly one place, from [`Presence::Absent`]. A read failure can never
    /// produce it, which is the whole point of the variant.
    ConfirmedAbsent,
}

/// The sentence appended to every protection summary, naming what sealing the seed does NOT cover
/// (dig-node#343).
///
/// It is a constant rather than prose repeated per arm so the claim cannot drift between the
/// variants, and so a test can assert its presence rather than matching on wording.
pub const DERIVED_KEY_CAVEAT: &str = "The DERIVED peer key at peer-net/identity/node.key is NOT \
     sealed \u{2014} it is stored readable because the peer listener loads it by path, and \
     possession of that one file is possession of this node's peer_id";

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

/// The SIBLING directory holding the device key for the identity blobs in `dir`.
///
/// `<config_dir>/dig` -> `<config_dir>/dig-device`, mirroring dig-node `SPEC.md` §16.4's
/// `<user_base>/DigWallet/` -> `<user_base>/DigNode/device/`. A sibling, never a child: a child
/// would travel inside every copy of the identity directory and the split would buy nothing.
///
/// # Errors
/// [`MachineKeyError::Io`] if `dir` has no parent or no final component -- a filesystem root
/// cannot have a sibling, and silently falling back to a child would quietly remove the boundary.
fn device_dir(dir: &Path) -> Result<std::path::PathBuf, MachineKeyError> {
    match (dir.parent(), dir.file_name()) {
        (Some(parent), Some(name)) => {
            let mut sibling = name.to_os_string();
            sibling.push("-device");
            Ok(parent.join(sibling))
        }
        _ => Err(MachineKeyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "identity dir {} has no sibling to hold the device key",
                dir.display()
            ),
        ))),
    }
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

/// What actually protects the two halves at rest on THIS platform, in one clause.
///
/// Exists so the operator-facing sentence and the enforcement cannot drift apart. Saying
/// "owner-only file permissions" unconditionally was a false claim on Windows, where neither
/// dig-keystore `FileBackend` (whose `enforce_owner_only` is `#[cfg(unix)]`) nor this module
/// installs an explicit DACL -- both halves simply inherit the profile ACL.
fn at_rest_floor() -> &'static str {
    #[cfg(unix)]
    {
        "owner-only file permissions (mode 0600) and their separate directories"
    }
    #[cfg(not(unix))]
    {
        concat!(
            "their separate directories, plus the permissions inherited from your user profile ",
            "-- this build installs no explicit owner-only ACL on Windows"
        )
    }
}

/// Bind the strongest trusted component `bind` can prove, asking strictly and degrading loudly.
///
/// `bind` is the ladder walk, parameterised by policy so that the caller decides which candidate
/// list is walked: production hands it [`dig_keystore_hardware::bind_strongest`] over the real
/// platform, and a test hands it `bind_strongest_from` over a chosen provider — because no CI
/// runner can be made to produce an indeterminate TPM probe on demand, and that outcome is the
/// only one this function exists to handle.
///
/// # The one refusal `Preferred` can produce, and why it is caught here
///
/// Under [`HardwarePolicy::Preferred`] the ladder degrades on every negative EXCEPT
/// [`DegradeReason::ProbeIndeterminate`] — a host that could not be inspected at all. That
/// refusal is deliberate in `dig-keystore`: an unknown must never be laundered into a confident
/// "no hardware here". It is also fatal in this position, because the refusal gates opening an
/// EXISTING keystore, not merely minting a new one, so an inconclusive probe would take a node
/// that has been serving the peer network for months offline.
///
/// A degrade that is announced is the honest resolution of that tension. The node keeps running;
/// the reason it is running on software is in the log with the probe's own detail, and in
/// [`MachineKeyStore::protection_summary`] as `ProbeIndeterminate` rather than as the confident
/// `NoHardwarePresent` this codebase must never fabricate.
///
/// `announce_degrade` is that report, taken as a parameter rather than emitted inline for one
/// reason: it is the part of this function a test can OBSERVE. Asking `Preferred` and then
/// degrading has, by construction, the same end state as asking `Optional` outright — the tier is
/// identical either way — so the announcement is the only thing that distinguishes a considered
/// downgrade from an unconsidered one, and a silent `tracing::warn!` would leave the whole
/// difference untestable.
///
/// Note what this does NOT swallow: an indeterminate candidate does not mask a working one. The
/// ladder only applies the policy when NO candidate was selected, so a host with a healthy TPM
/// behind a flaky first candidate still settles on hardware and never reaches this path.
///
/// # Errors
/// [`MachineKeyError::Keystore`] for any failure other than the indeterminate refusal, and for
/// the refusal itself if the `Optional` re-bind also fails.
fn bind_preferring_hardware(
    bind: impl Fn(HardwarePolicy) -> Result<HardwareBoundBackend, KeystoreError>,
    announce_degrade: impl FnOnce(&str, &ProtectionTier),
) -> Result<HardwareBoundBackend, MachineKeyError> {
    match bind(HardwarePolicy::Preferred) {
        Ok(backend) => Ok(backend),
        Err(KeystoreError::HardwareProbeIndeterminate { detail }) => {
            let backend = bind(HardwarePolicy::Optional)?;
            announce_degrade(&detail, backend.tier());
            Ok(backend)
        }
        Err(e) => Err(e.into()),
    }
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
    MachineKeyStore::open_platform_bound(dir)?.load_or_create(legacy_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_keystore::hardware::double::FakeDevice;
    use dig_keystore::hardware::{DegradeReason, HardwareKind};

    /// The identity dir for a test, as a CHILD of `root` so its sibling device dir also lands
    /// inside the tempdir and is cleaned up with it.
    fn identity_dir(root: &tempfile::TempDir) -> std::path::PathBuf {
        root.path().join("dig")
    }

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

    /// Every byte in every file under `dir`, recursively — the view an attacker holding a copy of
    /// that directory has.
    fn all_bytes_at_rest(dir: &Path) -> Vec<u8> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                out.extend_from_slice(&all_bytes_at_rest(&path));
            } else {
                out.extend_from_slice(&std::fs::read(&path).expect("record"));
            }
        }
        out
    }

    /// Whether `haystack` contains `needle` as a contiguous run.
    fn contains_run(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// **Proves (dig-node#345):** a legacy plaintext seed that is PRESENT but unreadable is never
    /// minted over, and is never deleted.
    ///
    /// This is the destructive case the module exists to prevent, and until now nothing tested
    /// it: `read_legacy` was safe only because its `fs::read` happened to carry a `?`. Replace
    /// that operator with `.ok()` — a one-character relaxation a refactor could make in good
    /// faith — and the unreadable seed reads as ABSENT, so `load_or_create` mints a new identity,
    /// seals it, and then removes the real seed. Both halves gone, from a character.
    ///
    /// The fixture is a DIRECTORY at the legacy seed path. It is the one shape that makes
    /// `presence` answer `Present` while `fs::read` fails, on every platform, without needing
    /// permissions the runner may or may not have — which matters because a `chmod`-based fixture
    /// is exactly the kind that silently stops discriminating under root (dig-node#355).
    #[test]
    fn an_unreadable_legacy_seed_is_never_minted_over_or_deleted() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        std::fs::create_dir_all(&dir).expect("identity dir");
        let legacy_dir = root.path().join("legacy");
        std::fs::create_dir_all(&legacy_dir).expect("legacy dir");

        // Present to `presence`, unreadable to `fs::read`, on every platform.
        let legacy_path = legacy_dir.join(LEGACY_SEED_FILE);
        std::fs::create_dir(&legacy_path).expect("the unreadable fixture");
        assert_eq!(
            presence(&legacy_path).expect("presence"),
            Presence::Present,
            "the fixture must LOOK present, or this test proves nothing"
        );
        assert!(
            std::fs::read(&legacy_path).is_err(),
            "the fixture must be unreadable, or this test proves nothing"
        );

        let store = software_store(&dir);
        let err = store
            .load_or_create(Some(&legacy_dir))
            .expect_err("an unreadable legacy seed must refuse, never mint");

        assert!(
            matches!(err, MachineKeyError::ExistenceUndeterminable { .. }),
            "the refusal must name the undetermined read, got: {err}"
        );
        assert!(
            legacy_path.exists(),
            "the legacy seed must NOT be deleted when it could not be read"
        );
        assert!(
            !store.seed_blob_path().exists(),
            "nothing may be sealed over an identity we could not read"
        );
    }

    /// The control for the test above: a legacy seed that IS readable is migrated, and only then
    /// is the plaintext removed.
    ///
    /// Without this, an implementation that refused every legacy path would pass the refusal test
    /// while breaking migration entirely — the failure mode a one-sided assertion cannot see.
    #[test]
    fn a_readable_legacy_seed_is_adopted_and_then_removed() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        std::fs::create_dir_all(&dir).expect("identity dir");
        let legacy_dir = root.path().join("legacy");
        std::fs::create_dir_all(&legacy_dir).expect("legacy dir");

        let legacy_path = legacy_dir.join(LEGACY_SEED_FILE);
        let planted = [7u8; 32];
        std::fs::write(&legacy_path, planted).expect("plant the legacy seed");

        let store = software_store(&dir);
        let settled = store
            .load_or_create(Some(&legacy_dir))
            .expect("a readable legacy seed migrates");

        assert_eq!(
            settled.as_slice(),
            &planted,
            "the legacy identity must be ADOPTED, not replaced"
        );
        assert!(
            !legacy_path.exists(),
            "the plaintext copy is removed once the sealed copy reads back"
        );
    }

    /// **Proves:** `ConfirmedAbsent` is the ONLY answer that reaches the mint, and it is produced
    /// only from a determined absence.
    ///
    /// Asserted directly on `read_legacy` because the destructive consequence is two calls away
    /// from the read, and a test that only observes the consequence cannot say which of the two
    /// decisions was wrong.
    #[test]
    fn read_legacy_reports_confirmed_absence_only_for_a_determined_absence() {
        let root = tempfile::tempdir().expect("tempdir");
        let empty = root.path().join("empty");
        std::fs::create_dir_all(&empty).expect("dir");
        assert!(
            matches!(
                MachineKeyStore::read_legacy(&empty),
                Ok(LegacySeed::ConfirmedAbsent)
            ),
            "a determined absence is the one value that permits a mint"
        );

        let blocked = root.path().join("blocked");
        std::fs::create_dir_all(&blocked).expect("dir");
        std::fs::create_dir(blocked.join(LEGACY_SEED_FILE)).expect("unreadable fixture");
        assert!(
            matches!(
                MachineKeyStore::read_legacy(&blocked),
                Err(MachineKeyError::ExistenceUndeterminable { .. })
            ),
            "an unreadable legacy seed must be an Err, never ConfirmedAbsent"
        );
    }

    /// **Proves (dig-node#343):** no protection summary ever claims copy-resistance without also
    /// naming the derived peer key that is NOT covered.
    ///
    /// Sealing the seed builds a real partial-exfiltration boundary — recovering it needs BOTH
    /// `machine-identity.dks` and the sibling `device.dks`. But the key peers actually
    /// authenticate is the DERIVED one at `peer-net/identity/node.key`, stored unsealed one
    /// directory away, and `peer_id = SHA-256(SPKI DER)`. So "sealed to this host; it does not
    /// open on another machine" is true of the seed and false of the artifact a reader assumes it
    /// means — a shipped surface asserting a protection that does not cover the thing at risk.
    ///
    /// Asserted over BOTH tiers and the error path, because the caveat is only load-bearing if it
    /// cannot be lost by adding one more arm.
    #[test]
    fn the_protection_summary_never_claims_copy_resistance_without_naming_the_derived_key() {
        let root = tempfile::tempdir().expect("tempdir");

        let software_dir = identity_dir(&root);
        let software = software_store(&software_dir);
        software.load_or_create(None).expect("mint + seal");
        let software_summary = software.protection_summary();
        assert!(
            software_summary.contains(DERIVED_KEY_CAVEAT),
            "the software-tier summary must name the uncovered derived key: {software_summary}"
        );

        let hardware_dir = root.path().join("hw");
        let hardware = hardware_store(&hardware_dir, 1);
        hardware.load_or_create(None).expect("mint + seal");
        let hardware_summary = hardware.protection_summary();
        assert!(
            hardware_summary.contains("does not open on another machine"),
            "the hardware-tier claim under test must actually be made: {hardware_summary}"
        );
        assert!(
            hardware_summary.contains(DERIVED_KEY_CAVEAT),
            "the copy-resistance claim must be scoped to the SEED: {hardware_summary}"
        );

        // The error path too: a store with nothing sealed yet still reports a tier, and the
        // caveat is exactly as true there.
        let empty_dir = root.path().join("empty");
        let empty_summary = software_store(&empty_dir).protection_summary();
        assert!(
            empty_summary.contains(DERIVED_KEY_CAVEAT),
            "even an unknown-protection summary must not imply the derived key is covered: \
             {empty_summary}"
        );
    }

    /// **Proves:** `DIG_IDENTITY_DIR` still selects the identity directory.
    ///
    /// **Catches:** dropping the override while reproducing digstore's private `identity_dir`.
    /// That regression is invisible on a developer machine — the default branch works fine — and
    /// shows up only as a node started under the variable minting a SECOND identity beside the
    /// one it already had, silently changing its `peer_id`.
    #[test]
    fn the_identity_dir_override_is_honoured() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let previous = std::env::var_os("DIG_IDENTITY_DIR");
        std::env::set_var("DIG_IDENTITY_DIR", &dir);

        let resolved = identity_store_dir().expect("override resolves");

        match previous {
            Some(v) => std::env::set_var("DIG_IDENTITY_DIR", v),
            None => std::env::remove_var("DIG_IDENTITY_DIR"),
        }
        assert_eq!(
            resolved, dir,
            "DIG_IDENTITY_DIR must win, exactly as it does for the legacy plaintext seed"
        );
    }

    /// A path whose *existence cannot be determined*, while every other path stays writable.
    ///
    /// An interior NUL byte is rejected by the platform path conversion itself -- `InvalidInput`
    /// from `CString::new` on Unix and from the UTF-16 conversion on Windows -- so `try_exists`
    /// returns `Err` on both, deterministically, without a permission fixture only one platform
    /// can express. It stands in for the real causes (an AV/EDR sharing violation, roaming-profile
    /// sync, a changed ACL, `EIO`, `EMFILE`) which all arrive the same way: as an `Err` from the
    /// metadata call. Borrowed from `dig-wallet`'s `autoseed` tests, which established the shape.
    fn undeterminable_dir(root: &tempfile::TempDir) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{}\0dig", root.path().display()))
    }

    /// A device-key path that EXISTS but cannot be read, portably and deterministically.
    ///
    /// A directory: `try_exists` says `Present`, and `fs::read` fails on every platform
    /// (`IsADirectory` on Unix, access denied on Windows). It stands in for the real cause the
    /// gate measured -- a `share_mode(0)` lock from an on-access scanner, os error 32 -- which is
    /// only expressible on Windows. What matters is the SHAPE both produce: present, intact, and
    /// momentarily unreadable.
    fn unreadable_device_key(dir: &Path) {
        let path = device_dir(dir).expect("sibling").join(DEVICE_KEY_FILE);
        std::fs::create_dir_all(&path).expect("a present but unreadable device key");
    }

    /// **Proves:** a device key that is present but momentarily unreadable is NOT reported as a
    /// mismatch, and carries no instruction to remove anything.
    ///
    /// **Catches the gating finding.** A bare `fs::read` folds a transient sharing violation into
    /// `DeviceKeyUnusable`, which asserts a false cause about a present, intact file and tells the
    /// operator to remove BOTH halves -- destroying the identity this module exists to protect.
    /// The gate measured exactly that with both halves intact and the seed opening again the
    /// moment the lock released.
    ///
    /// The fixture varies ONE thing (the device key becomes unreadable while everything else is
    /// untouched) and the assertions pin the VARIANT plus the WORDS, because a correct variant
    /// rendered into a remove-both sentence would mislead identically.
    #[test]
    fn a_present_but_unreadable_device_key_is_not_reported_as_a_mismatch() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        software_store(&dir).load_or_create(None).expect("mint");
        std::fs::remove_file(device_dir(&dir).expect("sibling").join(DEVICE_KEY_FILE))
            .expect("clear the real key");
        unreadable_device_key(&dir);

        let outcome = software_store(&dir).load_or_create(None);

        let Err(e @ MachineKeyError::DeviceKeyUnreadable { .. }) = outcome else {
            panic!("a present-but-unreadable device key must not read as a mismatch: {outcome:?}");
        };
        let message = e.to_string().to_lowercase();
        assert!(
            message.contains("retry"),
            "an undeterminable read must tell the operator to retry: {message}"
        );
        for destructive in ["removing both", "remove both", "minted deliberately"] {
            assert!(
                !message.contains(destructive),
                "a transient read must never carry a destructive instruction ({destructive}): {message}"
            );
        }
    }

    /// **Proves:** a wrong-length device key is a real mismatch and still reads honestly.
    ///
    /// **Catches:** the branch B7 found untested, which shared its message with the genuine
    /// mismatch. It must NOT be reclassified as merely unreadable while fixing the finding above
    /// -- a truncated key really is unusable -- so this is the control that keeps that fix from
    /// over-reaching.
    #[test]
    fn a_wrong_length_device_key_is_a_mismatch_that_names_what_is_undetermined() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        software_store(&dir).load_or_create(None).expect("mint");
        std::fs::write(
            device_dir(&dir).expect("sibling").join(DEVICE_KEY_FILE),
            [0x22u8; DEVICE_KEY_LEN - 1],
        )
        .expect("truncated device key");

        let outcome = software_store(&dir).load_or_create(None);

        let Err(e @ MachineKeyError::DeviceKeyUnusable { .. }) = outcome else {
            panic!("a truncated device key is a genuine mismatch: {outcome:?}");
        };
        let message = e.to_string();
        assert!(
            message.contains(&format!("not the {DEVICE_KEY_LEN}")),
            "the detail must say what was actually wrong: {message}"
        );
        assert!(
            message.contains("KNOWN:") && message.contains("UNDETERMINED:"),
            "the message must separate what is known from what it cannot establish: {message}"
        );
        assert!(
            message.find("DO FIRST:") < message.find("ONLY IF"),
            "restoring must be offered BEFORE the irreversible option: {message}"
        );
    }

    /// **Proves:** `seal_new` returns the seed that is on DISK, not the one it just minted.
    ///
    /// **Catches the mutation that stayed green (B6):** replacing the read-back with the computed
    /// value. That is what makes a losing racer adopt the winner identity instead of returning an
    /// identity no longer stored anywhere -- two processes would otherwise disagree about the
    /// node `peer_id` while only one blob survives.
    ///
    /// The property is unobservable unless another writer lands INSIDE the write/read-back window,
    /// so the fixture uses the test-only hook to put one there. Asserting on an ordinary mint
    /// cannot see it: there, the computed value and the stored value are equal by construction.
    #[test]
    fn seal_new_adopts_the_seed_a_racing_writer_left_on_disk() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let winner = [0x99u8; 32];

        let mut store = software_store(&dir);
        // Install the device key first, so the "racer" seals under the same one -- which is what
        // `ensure_device_key` guarantees in production.
        let device_key = store.ensure_device_key().expect("install");
        let racing_blob = opaque::seal(
            &Password::new(device_key.as_slice()),
            &winner,
            KdfParams::FAST_TEST,
        )
        .expect("the racer seals its own seed");
        let blob_path = store.seed_blob_path();
        store.after_blob_write = Some(Box::new(move || {
            std::fs::write(&blob_path, &racing_blob).expect("the racer wins the write");
        }));

        let settled = store.load_or_create(None).expect("mint and settle");

        assert_eq!(
            settled.as_slice(),
            &winner,
            "the loser must adopt the identity actually on disk, not the one it minted"
        );
        assert_eq!(
            software_store(&dir)
                .load_or_create(None)
                .expect("restart")
                .as_slice(),
            &winner,
            "control: that is genuinely the identity a later start reads"
        );
    }

    /// **Proves:** an identity that cannot be READ is never treated as an identity that is not
    /// THERE.
    ///
    /// **Catches the HIGH finding this module was gated on.** `FileBackend::exists` is
    /// `path.exists()`, i.e. `fs::metadata(..).is_ok()`, so one transient metadata failure in
    /// post-migration steady state returns `false`, falls through to `random_bytes`, and
    /// overwrites BOTH halves -- changing `peer_id` silently and irrecoverably, with no attacker
    /// and no malformed input involved.
    ///
    /// The fixture makes the *existence read itself* fail while nothing else is wrong, which is
    /// the only way to distinguish "refused because it could not tell" from "failed because the
    /// directory was broken". Asserting merely that the call errored would not: a store over a
    /// genuinely unusable directory errors under the buggy code too. So this pins the VARIANT.
    #[test]
    fn an_undeterminable_existence_read_refuses_instead_of_minting() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = software_store(&undeterminable_dir(&root));

        let outcome = store.load_or_create(None);

        assert!(
            matches!(
                outcome,
                Err(MachineKeyError::ExistenceUndeterminable { .. })
            ),
            "an unreadable path must refuse, not mint over a possibly-real identity: {:?}",
            outcome.as_ref().map(|s| hex::encode(s.as_slice()))
        );
    }

    /// **Proves:** the same refusal guards the MIGRATION read, not only the steady-state one.
    ///
    /// **Catches:** fixing `load_or_create` while leaving `read_legacy` on `Path::exists`. That
    /// version mints a brand-new identity while the node's real plaintext seed sits right there,
    /// unreadable for a moment -- and then, because the mint succeeds, deletes nothing and leaves
    /// two identities. The control keeps a truthful comparison: with a READABLE legacy dir the
    /// same call adopts the existing seed rather than minting.
    #[test]
    fn an_undeterminable_legacy_read_refuses_instead_of_minting() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let legacy_root = tempfile::tempdir().expect("legacy");

        let outcome = software_store(&dir).load_or_create(Some(&undeterminable_dir(&legacy_root)));
        assert!(
            matches!(
                outcome,
                Err(MachineKeyError::ExistenceUndeterminable { .. })
            ),
            "an unreadable legacy path must refuse: {:?}",
            outcome.as_ref().map(|s| hex::encode(s.as_slice()))
        );

        // Control: the identical call over a READABLE legacy dir adopts the seed that is there.
        let readable = tempfile::tempdir().expect("readable legacy");
        std::fs::write(readable.path().join(LEGACY_SEED_FILE), [0x5Cu8; 32]).expect("legacy seed");
        assert_eq!(
            software_store(&dir)
                .load_or_create(Some(readable.path()))
                .expect("readable legacy adopts")
                .as_slice(),
            &[0x5Cu8; 32],
            "control: a readable legacy seed must still be adopted"
        );
    }

    /// **Proves:** a second start cannot install a second device key over the first.
    ///
    /// **Catches the other HIGH finding.** With `FileBackend::write` (tmp + rename, i.e. REPLACE)
    /// on the device key, two overlapping starts leave process B key beside process A blob --
    /// neither opens the other, and the no-re-mint rule then prevents self-healing forever.
    ///
    /// The fixture is the observable consequence rather than the timing: it drives the device-key
    /// install twice and requires the SECOND to adopt the first key rather than replace it, then
    /// proves the blob sealed under the first still opens afterwards. A test that only raced two
    /// threads would be nondeterministic and would usually pass on the broken code.
    #[test]
    fn a_second_start_adopts_the_device_key_rather_than_replacing_it() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let store = software_store(&dir);

        let first = store.ensure_device_key().expect("install");
        let seed = store
            .load_or_create(None)
            .expect("seal under the first key");

        let second = store.ensure_device_key().expect("adopt");

        assert_eq!(
            first.as_slice(),
            second.as_slice(),
            "the second start must ADOPT the installed device key, never install a second one"
        );
        assert_eq!(
            software_store(&dir)
                .load_or_create(None)
                .expect("the blob must still open after a second start")
                .as_slice(),
            seed.as_slice(),
            "a blob sealed under the first key must survive a second start"
        );
    }

    /// **Proves:** a device key that does not match the blob is a NAMED state with a remedy.
    ///
    /// **Catches:** surfacing the mismatch as a bare `DecryptFailed`, which names neither the
    /// cause nor the recovery and leaves an operator with a permanently dead node and one
    /// uninformative log line. Also pins that it is not silently re-minted.
    #[test]
    fn a_mismatched_device_key_is_named_with_both_halves_and_a_remedy() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        software_store(&dir).load_or_create(None).expect("mint");

        // A half-restored backup: the blob from one install, the device key from another.
        let device = device_dir(&dir).expect("sibling").join(DEVICE_KEY_FILE);
        std::fs::write(&device, [0x11u8; DEVICE_KEY_LEN]).expect("foreign device key");

        let outcome = software_store(&dir).load_or_create(None);

        let Err(e @ MachineKeyError::DeviceKeyUnusable { .. }) = outcome else {
            panic!("a mismatched device key must be named, got {outcome:?}");
        };
        let message = e.to_string();
        for expected in [
            device.display().to_string(),
            dir.display().to_string(),
            "restore".to_string(),
        ] {
            assert!(
                message.contains(&expected),
                "the message must name both halves and the remedy ({expected}): {message}"
            );
        }
    }

    /// **Proves:** the seed survives a round trip through the container at all — the control every
    /// other test here needs in order to mean anything.
    #[test]
    fn a_sealed_seed_reopens_to_the_same_bytes() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let store = software_store(&dir);

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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);

        let first = software_store(&dir).load_or_create(None).expect("mint");
        let after_restart = software_store(&dir).load_or_create(None).expect("restart");

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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let store = software_store(&dir);
        let seed = store.load_or_create(None).expect("mint");

        // The tempdir ROOT, so BOTH halves are in scope: scanning only the identity
        // directory would miss a regression that parked the plaintext in the device dir.
        let at_rest = all_bytes_at_rest(root.path());
        assert!(
            !at_rest.is_empty(),
            "control: the store must actually have written something to scan"
        );
        assert!(
            !all_bytes_at_rest(&device_dir(&dir).expect("sibling")).is_empty(),
            "control: the device half must be inside the scanned tree, or this sees one of two files"
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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let legacy = tempfile::tempdir().expect("legacy dir");
        let legacy_seed = [0xA7u8; 32];
        std::fs::write(legacy.path().join(LEGACY_SEED_FILE), legacy_seed).expect("legacy seed");

        let adopted = software_store(&dir)
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
            software_store(&dir)
                .load_or_create(None)
                .expect("restart after migration")
                .as_slice(),
            &legacy_seed,
            "the migrated seed must be recoverable from the sealed copy alone"
        );
    }

    /// **Proves:** the device key is NOT in the identity directory, and the sealed blob alone
    /// does not open without it.
    ///
    /// This is the partial-exfiltration boundary dig-node `SPEC.md` §16.4 specifies, and it is the
    /// only confidentiality this key has on a host with no hardware provider — which is every host
    /// today. Asserting merely that the seed is absent from the identity dir would pass on an
    /// implementation that stored the device key right beside it, so the second half opens a store
    /// over a copy of the identity half ALONE and requires it to refuse.
    #[test]
    fn the_device_key_lives_outside_the_identity_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let seed = software_store(&dir).load_or_create(None).expect("mint");

        let device = device_dir(&dir).expect("sibling");
        assert!(
            !device.starts_with(&dir),
            "the device key must not be a child of the identity dir it protects: {device:?}"
        );
        assert!(
            !contains_run(&all_bytes_at_rest(&dir), seed.as_slice()),
            "control: the identity half must not hold the seed in the clear either"
        );

        // Exfiltrate the identity half only, the way copying one directory does.
        let stolen_root = tempfile::tempdir().expect("stolen");
        let stolen = identity_dir(&stolen_root);
        std::fs::create_dir_all(&stolen).expect("stolen dir");
        for entry in std::fs::read_dir(&dir).expect("identity dir") {
            let from = entry.expect("entry").path();
            std::fs::copy(&from, stolen.join(from.file_name().expect("name"))).expect("copy");
        }

        let opened = software_store(&stolen).load_or_create(None);
        assert!(
            opened.is_err(),
            "the identity half alone must not yield the seed -- and must not mint a new one: {:?}",
            opened.as_ref().map(|s| hex::encode(s.as_slice()))
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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let sealed = hardware_store(&dir, 1)
            .load_or_create(None)
            .expect("seal on machine 1");
        let blob_before = all_bytes_at_rest(&dir);

        let foreign = hardware_store(&dir, 2).load_or_create(None);

        assert!(
            foreign.is_err(),
            "a seed bound to another machine must not open here, and must NOT be re-minted: got {:?}",
            foreign.as_ref().map(|s| hex::encode(s.as_slice()))
        );
        assert_eq!(
            all_bytes_at_rest(&dir),
            blob_before,
            "the refusal must leave the stored identity byte-identical"
        );
        assert_eq!(
            hardware_store(&dir, 1)
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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let store = software_store(&dir);
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
            summary.contains("not hardware-backed"),
            "summary must not leave hardware backing implied: {summary}"
        );
        assert!(
            summary.contains("would open on another machine"),
            "summary must state the copy-resistance this key does NOT have: {summary}"
        );

        // The at-rest floor is NOT the same on both platforms, and the sentence must say which
        // one the operator actually has. Asserted per platform against concrete words rather than
        // against `at_rest_floor()` itself, which would pass for any string that function returns.
        #[cfg(unix)]
        assert!(
            summary.contains("0600"),
            "on Unix the summary must name the owner-only mode it really sets: {summary}"
        );
        #[cfg(not(unix))]
        {
            assert!(
                summary.contains("inherited from your user profile"),
                "on Windows the summary must say permissions are inherited: {summary}"
            );
            assert!(
                !summary.contains("owner-only file permissions"),
                "on Windows nothing installs an owner-only ACL, so claiming one is false: {summary}"
            );
        }
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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        software_store(&dir)
            .load_or_create(None)
            .expect("mint unwrapped");

        let capable = hardware_store(&dir, 1);

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
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        hardware_store(&dir, 1).load_or_create(None).expect("seal");

        let summary = software_store(&dir).protection_summary();

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

    /// **The production constructor consults the platform, and `NotRequested` is the one tier it
    /// can never report.**
    ///
    /// This is the whole of dig-node#367 as an assertion. `platform_provider()` used to be
    /// `pub fn platform_provider() -> Option<_> { None }`, sitting under a doc comment stating
    /// that `dig-keystore` shipped no platform binding — untrue since `ed9601a3` / v0.12.0. The
    /// seam at `open` was already fully composed; one hardcoded `None` kept it dark, and the
    /// comment explaining the `None` is what stopped anyone looking.
    ///
    /// # Why `NotRequested` is the right needle, and an outcome assertion is not
    ///
    /// The tier this host reports is a property of the HOST, so it is not assertable: this suite
    /// runs on Windows TPM boxes, on macOS, and on Linux CI runners with no TPM at all, and the
    /// honest answer differs on each. Pinning `Hardware(WindowsTpm20)` would fail on CI; pinning
    /// `Software(..)` would pass on a host that never asked, which is the defect.
    ///
    /// `DegradeReason::NotRequested` means precisely *"the caller supplied no provider or
    /// explicitly opted out"* — it is the fingerprint of the old hardcoded `None`, and it is
    /// UNREACHABLE through [`MachineKeyStore::open_platform_bound`] on every host, because
    /// `bind_strongest` either settles on hardware, or reports a confident absence, or reports
    /// `PlatformUnsupported`. So the assertion is host-independent while still being exactly the
    /// regression.
    ///
    /// Reverting the seam to `MachineKeyStore::open(dir, None)` turns this red on every platform.
    #[test]
    fn the_production_store_asks_the_platform_and_never_reports_notrequested() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);

        let store = MachineKeyStore::open_platform_bound(&dir)
            .expect("Optional policy opens on every host, including one with no provider");

        assert_ne!(
            store.backend.tier(),
            &ProtectionTier::Software(DegradeReason::NotRequested),
            "the production constructor reported that nobody asked for hardware binding, which \
             is the hardcoded `None` this ticket removed -- not a fact about this host"
        );

        // The control. Without it the assertion above is satisfied by a constructor that returns
        // any other tier for any reason at all, including one that stopped consulting the host.
        // `open(dir, None)` is the shape being regressed AWAY from, and it must still be able to
        // express `NotRequested` -- if it cannot, the needle has stopped naming the defect and
        // this test has gone vacuous.
        let opted_out = MachineKeyStore::open(&dir, None).expect("Optional policy always opens");
        assert_eq!(
            opted_out.backend.tier(),
            &ProtectionTier::Software(DegradeReason::NotRequested),
            "an explicit opt-out is what NotRequested means; if this no longer holds, the \
             assertion above proves nothing"
        );
    }

    /// **An uninspectable host degrades, announces why, and does NOT refuse to open.**
    ///
    /// `Preferred` is the policy production asks for, and in dig-keystore 0.13 it treats an
    /// indeterminate probe as an ERROR rather than an absence — correctly, since laundering an
    /// unknown into a confident `NoHardwarePresent` is the defect the three-valued probe exists
    /// to prevent. In this position that refusal gates opening an EXISTING keystore, so an
    /// inconclusive probe would take a running node off the peer network.
    ///
    /// # Why the fixture is one indeterminate provider and not "no provider"
    ///
    /// A host with no provider degrades under `Preferred` already, so a no-provider fixture
    /// passes whether or not the refusal is handled — it cannot distinguish this fix from its
    /// absence. `FakeDevice::indeterminate` is the only fixture that makes `Preferred` actually
    /// refuse, and the first assertion below PROVES it refuses rather than assuming it: without
    /// that control, `bind_preferring_hardware` returning `Ok` would be evidence of nothing.
    ///
    /// The announcement is asserted too, and it carries the weight the tier cannot: degrading
    /// after a strict ask reaches the same tier as never asking strictly, so the report is the
    /// only observable difference between a considered downgrade and an unconsidered one.
    #[test]
    fn an_uninspectable_host_degrades_with_its_reason_instead_of_refusing_to_open() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let device: Arc<dyn HardwareProvider> = Arc::new(FakeDevice::indeterminate(
            HardwareKind::WindowsTpm20,
            "TPM handle busy",
        ));
        let candidates = [Arc::clone(&device)];
        let bind = |policy| {
            dig_keystore_hardware::bind_strongest_from(FileBackend::new(&dir), &candidates, policy)
        };

        // The control: this fixture genuinely makes the strict ask fail. If dig-keystore ever
        // stops refusing here, the assertion below stops being about the refusal path at all.
        assert!(
            matches!(
                bind(HardwarePolicy::Preferred),
                Err(KeystoreError::HardwareProbeIndeterminate { .. })
            ),
            "the fixture must produce the refusal this test handles, or it proves nothing"
        );

        let mut announced: Option<String> = None;
        let backend = bind_preferring_hardware(bind, |detail, _tier| {
            announced = Some(detail.to_owned());
        })
        .expect("an uninspectable host must still open — this is the node's boot path");

        // The reason is carried through, not flattened. Reporting `NoHardwarePresent` here would
        // be a confident claim about a machine nothing successfully inspected.
        assert!(
            matches!(
                backend.tier(),
                ProtectionTier::Software(DegradeReason::ProbeIndeterminate { .. })
            ),
            "the degrade must carry the probe's own reason, got {:?}",
            backend.tier()
        );
        let announced = announced.expect("the downgrade must be announced, not taken silently");
        assert!(
            announced.contains("TPM handle busy"),
            "the announcement must carry the probe's own detail, so an operator can act on the \
             actual cause: {announced}"
        );
    }

    /// **A flaky candidate does not cost the host its hardware tier, and nothing is announced.**
    ///
    /// The second actor, and the reason the test above is not satisfied by a
    /// `bind_preferring_hardware` that announced a downgrade on every call. Here a WORKING device
    /// sits behind the indeterminate one: the ladder settles on hardware, so there is no
    /// downgrade to report and the reporter must stay silent. An implementation that reported
    /// unconditionally — the cheapest way to make the first test pass — fails this one.
    ///
    /// It also pins the narrowness of the refusal handling: the policy is applied by the ladder
    /// only when NO candidate was selected, so an inconclusive probe on one component never
    /// downgrades a host that has another that works.
    #[test]
    fn an_indeterminate_candidate_does_not_mask_a_working_one() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = identity_dir(&root);
        let candidates: [Arc<dyn HardwareProvider>; 2] = [
            Arc::new(FakeDevice::indeterminate(
                HardwareKind::WindowsTpm20,
                "TPM handle busy",
            )),
            Arc::new(FakeDevice::working(HardwareKind::MacSecureEnclave, 7)),
        ];

        let mut announced: Option<String> = None;
        let backend = bind_preferring_hardware(
            |policy| {
                dig_keystore_hardware::bind_strongest_from(
                    FileBackend::new(&dir),
                    &candidates,
                    policy,
                )
            },
            |detail, _tier| announced = Some(detail.to_owned()),
        )
        .expect("a host with one working component must bind to it");

        assert_eq!(
            backend.tier(),
            &ProtectionTier::Hardware(HardwareKind::MacSecureEnclave),
            "a working component behind a flaky one must still be selected"
        );
        assert!(
            announced.is_none(),
            "nothing was downgraded, so nothing may be reported as downgraded: {announced:?}"
        );
    }
}
