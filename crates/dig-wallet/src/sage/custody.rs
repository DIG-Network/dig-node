//! Node-custodied wallet seed lifecycle (#370, SPEC §18.20).
//!
//! For the thin-client model (epic #365) the node HOLDS the wallet key: it generates or imports
//! the BIP-39 seed, encrypts it at rest via [`crate::seed_store`] (`dig-keystore` Argon2id +
//! AES-256-GCM, §18.18), and loads an in-memory [`WalletSigner`] on unlock so the node can sign +
//! broadcast on the caller's behalf (§18.21).
//!
//! # Trust boundary (custody of mainnet-spending keys)
//!
//! This is the sanctioned custody locus for the paired-extension path, DISTINCT from the read-only
//! path of #217/#407 (where the node holds only the client's PUBLIC puzzle hashes and NEVER a key).
//! The seed/key NEVER leaves the node:
//!
//! - no lifecycle op returns the mnemonic or a secret key — [`WalletCustody::create`] returns only
//!   the receive address;
//! - the seed is encrypted at rest and is never logged;
//! - the ONLY seed egress is the node-local, password-gated [`WalletCustody::reveal_mnemonic`]
//!   (surfaced on the self-origin backup UI / a `dig-node wallet backup` CLI), NEVER over the paired
//!   authorized boundary (§7.12).
//!
//! Every op that mutates custody is authorized by the paired-token gate at the transport layer
//! (SPEC §7.12); this module owns the custody state machine + crypto, not the transport authz.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use chia_protocol::Bytes32;
use chia_wallet_sdk::types::{MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use digstore_chain::keys::{derive_indexed_keys, derive_wallet_keys, owner_address};
use digstore_chain::seed::{generate_mnemonic, validate_mnemonic};
use zeroize::Zeroizing;

use super::spend::WalletSigner;
use super::{Error, Result};
use crate::seed_store;

/// The minimum length of the password that encrypts the seed at rest. Mirrors the self-origin
/// wallet UI's floor (`crate::lib`), so both custody surfaces reject a trivially-weak password.
const MIN_PASSWORD_LEN: usize = 8;

/// How many unhardened HD indices the custodied signer covers by default (indices `0..N`). The
/// signer can spend a coin at any of these addresses' standard puzzle hashes; a coin outside the
/// range is not spendable by the loaded signer (the wallet stays within its first `N` addresses,
/// matching typical usage — the count is a construction parameter for callers that need more).
pub const DEFAULT_DERIVATION_COUNT: u32 = 50;

/// The Chia network the custodied signer signs for. Selects the aggregate-signature domain the
/// broadcast target validates against (mainnet in production; testnet11 for the simulator tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Chia mainnet — the production target.
    Mainnet,
    /// testnet11 — used by the `chia-sdk-test` simulator in tests.
    Testnet11,
}

impl Network {
    /// The `AGG_SIG_ME` additional data the network's consensus validates spend signatures against.
    fn agg_sig_data(self) -> Bytes32 {
        match self {
            Network::Mainnet => MAINNET_CONSTANTS.agg_sig_me_additional_data,
            Network::Testnet11 => TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        }
    }
}

/// The custody state reported by [`WalletCustody::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CustodyState {
    /// No seed on this device — the wallet has not been created/imported yet.
    None,
    /// An encrypted seed is on disk but no signer is loaded (needs `unlock`).
    Locked,
    /// A signer is loaded in memory (spend/sign is enabled).
    Unlocked,
}

/// The custody status: the state plus the receive address when unlocked.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CustodyStatus {
    /// The lifecycle state.
    pub state: CustodyState,
    /// The wallet's receive address (`xch1…`), present only when unlocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// An unlocked custody session: the in-memory signer + the wallet's receive address.
struct Unlocked {
    signer: Arc<WalletSigner>,
    address: String,
}

/// The node-custodied wallet key lifecycle (§18.20). Owns the encrypted-seed file path and the
/// in-memory unlocked signer; every method is transport-agnostic (authorization is the caller's
/// concern, §7.12). Cheap to `clone` — the unlocked state is shared behind an `Arc`.
#[derive(Clone)]
pub struct WalletCustody {
    /// The encrypted-seed file path (per node config dir, owner-only).
    seed_path: PathBuf,
    /// The network the loaded signer signs for.
    network: Network,
    /// How many unhardened HD indices the signer covers (`0..derivation_count`).
    derivation_count: u32,
    /// The in-memory unlocked session; `None` when locked. Shared across clones so an `unlock` on
    /// one handle is visible on the others.
    unlocked: Arc<RwLock<Option<Unlocked>>>,
}

impl WalletCustody {
    /// Build a custody manager over `seed_path`, signing for `network`, covering HD indices
    /// `0..derivation_count`.
    pub fn new(seed_path: PathBuf, network: Network, derivation_count: u32) -> Self {
        Self {
            seed_path,
            network,
            derivation_count: derivation_count.max(1),
            unlocked: Arc::new(RwLock::new(None)),
        }
    }

    /// Build a mainnet custody manager with the default derivation coverage.
    pub fn mainnet(seed_path: PathBuf) -> Self {
        Self::new(seed_path, Network::Mainnet, DEFAULT_DERIVATION_COUNT)
    }

    /// Whether an encrypted seed exists on disk.
    pub fn seed_exists(&self) -> bool {
        self.seed_path.exists()
    }

    /// The current lifecycle state (+ address when unlocked).
    pub fn status(&self) -> CustodyStatus {
        if let Some(u) = self.unlocked.read().unwrap().as_ref() {
            return CustodyStatus {
                state: CustodyState::Unlocked,
                address: Some(u.address.clone()),
            };
        }
        CustodyStatus {
            state: if self.seed_exists() {
                CustodyState::Locked
            } else {
                CustodyState::None
            },
            address: None,
        }
    }

    /// Generate a fresh 24-word wallet, encrypt it under `password`, persist it, and load the
    /// signer. Returns ONLY the receive address — the mnemonic is NEVER returned (§18.20: back it
    /// up via the node-local [`Self::reveal_mnemonic`]). Refuses if a wallet already exists.
    pub fn create(&self, password: &str) -> Result<String> {
        self.check_password(password)?;
        self.refuse_if_exists()?;
        let mnemonic = generate_mnemonic(24)
            .map_err(|e| Error::internal(format!("failed to generate a recovery phrase: {e}")))?;
        self.persist_and_unlock(&mnemonic, password)
    }

    /// Import an existing mnemonic (the one-time migration path, §18.20): validate it, encrypt +
    /// persist it under `password`, and load the signer. Refuses if a wallet already exists (delete
    /// first to replace). Returns the receive address.
    pub fn import(&self, mnemonic: &str, password: &str) -> Result<String> {
        self.check_password(password)?;
        self.refuse_if_exists()?;
        let m = validate_mnemonic(mnemonic)
            .map_err(|e| Error::api(format!("invalid recovery phrase: {e}")))?;
        self.persist_and_unlock(&m, password)
    }

    /// Restore a wallet from a mnemonic. Behaviourally identical to [`Self::import`]; a distinct
    /// name so the lifecycle surface reads naturally (§18.20).
    pub fn restore(&self, mnemonic: &str, password: &str) -> Result<String> {
        self.import(mnemonic, password)
    }

    /// Decrypt the on-disk seed with `password` and load the in-memory signer (the runtime signer
    /// load that replaces the bring-up-only `with_signer`). Wrong password fails closed. Returns
    /// the receive address.
    pub fn unlock(&self, password: &str) -> Result<String> {
        let mnemonic = self.read_seed(password)?;
        let (signer, address) = self.build_signer(&mnemonic)?;
        *self.unlocked.write().unwrap() = Some(Unlocked {
            signer: Arc::new(signer),
            address: address.clone(),
        });
        Ok(address)
    }

    /// Drop the in-memory signer (the encrypted seed stays on disk). Signing is disabled until the
    /// next [`Self::unlock`]. Idempotent.
    pub fn lock(&self) {
        *self.unlocked.write().unwrap() = None;
    }

    /// Delete the wallet: verify `password` against the on-disk seed (proof of ownership), then
    /// remove the seed file and lock. A wrong password fails closed and the seed is preserved.
    pub fn delete(&self, password: &str) -> Result<()> {
        // Verify ownership before destroying anything (fails closed on a wrong password).
        let _ = self.read_seed(password)?;
        std::fs::remove_file(&self.seed_path)
            .map_err(|e| Error::internal(format!("failed to delete the seed: {e}")))?;
        self.lock();
        Ok(())
    }

    /// NODE-LOCAL backup ONLY: decrypt + return the mnemonic. This is the sole seed-egress path and
    /// MUST NOT be exposed over the paired authorized boundary (§7.12/§18.20) — it exists for the
    /// self-origin backup UI / a `dig-node wallet backup` CLI. Wrong password fails closed.
    pub fn reveal_mnemonic(&self, password: &str) -> Result<Zeroizing<String>> {
        self.read_seed(password)
    }

    /// The in-memory signer for the sign/broadcast path (§18.21), or `None` when locked.
    pub fn signer(&self) -> Option<Arc<WalletSigner>> {
        self.unlocked
            .read()
            .unwrap()
            .as_ref()
            .map(|u| u.signer.clone())
    }

    // ---- internals --------------------------------------------------------

    /// Reject a password below the minimum length.
    fn check_password(&self, password: &str) -> Result<()> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(Error::api(format!(
                "password must be at least {MIN_PASSWORD_LEN} characters"
            )));
        }
        Ok(())
    }

    /// Refuse a create/import when a wallet already exists (never silently clobber a seed).
    fn refuse_if_exists(&self) -> Result<()> {
        if self.seed_exists() {
            return Err(Error::api(
                "a wallet already exists on this device; delete it first to create or import another",
            ));
        }
        Ok(())
    }

    /// Read + decrypt the on-disk seed under `password` (maps missing → 404, wrong password → 401).
    fn read_seed(&self, password: &str) -> Result<Zeroizing<String>> {
        let bytes = std::fs::read(&self.seed_path)
            .map_err(|_| Error::not_found("no wallet on this device"))?;
        seed_store::decrypt_seed(&bytes, password)
            .map_err(|_| Error::unauthorized("wrong password"))
    }

    /// Encrypt + persist `mnemonic` under `password` (owner-only), then load the signer.
    fn persist_and_unlock(&self, mnemonic: &str, password: &str) -> Result<String> {
        let enc = seed_store::encrypt_seed(mnemonic, password).map_err(Error::internal)?;
        if let Some(dir) = self.seed_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::internal(format!("failed to create the wallet dir: {e}")))?;
        }
        std::fs::write(&self.seed_path, &enc)
            .map_err(|e| Error::internal(format!("failed to persist the seed: {e}")))?;
        restrict_permissions(&self.seed_path);
        let (signer, address) = self.build_signer(mnemonic)?;
        *self.unlocked.write().unwrap() = Some(Unlocked {
            signer: Arc::new(signer),
            address: address.clone(),
        });
        Ok(address)
    }

    /// Derive the signer (over HD indices `0..derivation_count`) + the receive address from a
    /// mnemonic. The signer's per-key puzzle hashes are the standard p2 puzzle hashes the wallet's
    /// coins sit at, so it can sign any spend of a coin the wallet owns within its address range.
    fn build_signer(&self, mnemonic: &str) -> Result<(WalletSigner, String)> {
        let indexed = derive_indexed_keys(mnemonic, 0..self.derivation_count)
            .map_err(|e| Error::internal(format!("failed to derive wallet keys: {e}")))?;
        let secret_keys = indexed
            .into_iter()
            .map(|k| k.synthetic_sk)
            .collect::<Vec<_>>();
        let signer = WalletSigner::new(secret_keys, self.network.agg_sig_data());
        let keys0 = derive_wallet_keys(mnemonic)
            .map_err(|e| Error::internal(format!("failed to derive the receive address: {e}")))?;
        Ok((signer, owner_address(&keys0)))
    }
}

/// Restrict the seed file to owner read/write on Unix (`0600`); best-effort defense-in-depth
/// (loopback-only + at-rest encryption are the primary controls). No-op on non-Unix.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical BIP-39 test vector ("abandon…art") — a KNOWN mnemonic so an import→unlock
    /// round-trip is deterministic (the golden migration seed).
    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    /// A fresh custody manager over a unique temp seed path (no file yet). A small derivation count
    /// keeps the key-build fast in tests.
    fn fresh() -> (WalletCustody, PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dig-node-custody-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("seed.bin");
        (WalletCustody::new(path.clone(), Network::Mainnet, 3), path)
    }

    #[test]
    fn status_is_none_when_no_seed_exists() {
        let (c, _p) = fresh();
        assert_eq!(c.status().state, CustodyState::None);
        assert!(c.status().address.is_none());
    }

    #[test]
    fn create_persists_an_encrypted_seed_and_never_returns_the_mnemonic() {
        let (c, path) = fresh();
        let address = c.create("hunter2pw").unwrap();

        // The return is the receive address (an xch1 address has no spaces), NOT a 24-word phrase.
        assert!(address.starts_with("xch1"), "got {address}");
        assert!(
            !address.contains(' '),
            "create must not return the space-separated mnemonic"
        );

        // The seed file exists and is ENCRYPTED at rest — its bytes are a dig-keystore container,
        // and decrypting yields a 24-word phrase that is NOT present in plaintext on disk.
        let on_disk = std::fs::read(&path).unwrap();
        let recovered = seed_store::decrypt_seed(&on_disk, "hunter2pw").unwrap();
        assert_eq!(recovered.split_whitespace().count(), 24);
        assert!(
            !String::from_utf8_lossy(&on_disk).contains(&*recovered),
            "the mnemonic must not appear in plaintext in the seed file"
        );

        // Create leaves the wallet unlocked.
        assert_eq!(c.status().state, CustodyState::Unlocked);
        assert_eq!(c.status().address.as_deref(), Some(address.as_str()));
    }

    #[test]
    fn import_round_trips_the_golden_seed_and_unlock_recovers_the_same_address() {
        let (c, _p) = fresh();
        let addr_import = c.import(ABANDON, "correcthorse").unwrap();
        assert!(addr_import.starts_with("xch1"));

        // Lock, then unlock: the same on-disk seed re-derives the identical address.
        c.lock();
        assert_eq!(c.status().state, CustodyState::Locked);
        let addr_unlock = c.unlock("correcthorse").unwrap();
        assert_eq!(
            addr_unlock, addr_import,
            "unlock must recover the same wallet"
        );
    }

    #[test]
    fn unlock_loads_the_signer_and_lock_clears_it() {
        let (c, _p) = fresh();
        c.import(ABANDON, "correcthorse").unwrap();
        c.lock();

        // Locked: no signer available.
        assert!(c.signer().is_none(), "locked wallet exposes no signer");

        // Unlock loads a signer covering the configured HD indices (0..3).
        c.unlock("correcthorse").unwrap();
        let signer = c.signer().expect("unlock loads the signer");
        assert_eq!(
            signer.puzzle_hashes().len(),
            3,
            "the signer covers the 0..derivation_count addresses"
        );

        // The signer recognizes the wallet's index-0 coin (the address it reports).
        let keys0 = derive_wallet_keys(ABANDON).unwrap();
        assert!(
            signer.synthetic_for(keys0.owner_puzzle_hash).is_some(),
            "the loaded signer owns the wallet's first address"
        );

        // Lock clears the signer.
        c.lock();
        assert!(c.signer().is_none(), "lock drops the in-memory signer");
    }

    #[test]
    fn wrong_password_fails_closed_on_unlock() {
        let (c, _p) = fresh();
        c.create("rightpassword").unwrap();
        c.lock();
        let err = c.unlock("wrongpassword").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unauthorized);
        assert!(c.signer().is_none(), "a failed unlock loads no signer");
    }

    #[test]
    fn create_refuses_when_a_wallet_already_exists() {
        let (c, _p) = fresh();
        c.create("firstpassword").unwrap();
        let err = c.create("secondpassword").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Api);
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn import_refuses_when_a_wallet_already_exists() {
        let (c, _p) = fresh();
        c.create("firstpassword").unwrap();
        assert!(c.import(ABANDON, "anotherpassword").is_err());
    }

    #[test]
    fn delete_requires_the_correct_password_then_removes_the_seed() {
        let (c, path) = fresh();
        c.create("rightpassword").unwrap();
        assert!(path.exists());

        // Wrong password: fails closed, seed preserved.
        assert!(c.delete("wrongpassword").is_err());
        assert!(
            path.exists(),
            "a wrong-password delete must preserve the seed"
        );

        // Correct password: seed removed, back to `none`.
        c.delete("rightpassword").unwrap();
        assert!(!path.exists());
        assert_eq!(c.status().state, CustodyState::None);
        assert!(c.signer().is_none());
    }

    #[test]
    fn reveal_mnemonic_returns_the_phrase_only_with_the_right_password() {
        let (c, _p) = fresh();
        c.import(ABANDON, "correcthorse").unwrap();
        let revealed = c.reveal_mnemonic("correcthorse").unwrap();
        assert_eq!(&*revealed, ABANDON, "node-local backup recovers the phrase");
        assert!(
            c.reveal_mnemonic("wrongpassword").is_err(),
            "reveal fails closed on a wrong password"
        );
    }

    #[test]
    fn weak_password_is_rejected() {
        let (c, path) = fresh();
        assert!(c.create("short").is_err());
        assert!(!path.exists(), "a rejected create writes no seed");
    }

    #[test]
    fn invalid_mnemonic_is_rejected_on_import() {
        let (c, _p) = fresh();
        let err = c
            .import("not a valid bip39 phrase at all", "correcthorse")
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Api);
    }

    use super::super::ErrorKind;
}
