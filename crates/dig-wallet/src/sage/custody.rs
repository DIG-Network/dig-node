//! Node-custodied MULTI-wallet seed lifecycle (#370/#427, SPEC §18.20/§18.20a).
//!
//! For the thin-client model (epic #365) the node HOLDS the wallet keys: it generates or imports
//! one or MORE independent BIP-39 seeds, encrypts each at rest via [`crate::seed_store`]
//! (`dig-keystore` Argon2id + AES-256-GCM, §18.18) under its OWN password, and loads an in-memory
//! [`WalletSigner`] per wallet on unlock so the node can sign + broadcast on the caller's behalf
//! (§18.21). The extension's multi-wallet registry (`WalletEntry[]`) is migrated IN one wallet at a
//! time (#374); this manager is the node-side multi-wallet custodian that makes that possible.
//!
//! # Wallet identity (§18.20a)
//!
//! Each wallet's stable id is the decimal string of its seed's Chia BLS **master public-key
//! fingerprint** (a `u32`, the canonical Chia wallet id Sage/`get_keys`/CHIP-0002 use). It is
//! deterministic (same seed ⇒ same id on any device), non-secret (public-key-derived), and lets a
//! paired caller correlate a node wallet to its extension `WalletEntry` by fingerprint. Importing a
//! seed whose fingerprint already exists is refused — no double-custody of one key.
//!
//! One wallet is the ACTIVE wallet; every id-taking method defaults to it when the id is omitted,
//! so a single-wallet caller (and the pre-existing #370 single-seed layout) is unchanged.
//!
//! # On-disk layout + back-compat (§18.20a)
//!
//! - one encrypted seed per wallet at `<config_dir>/wallets/<id>.seed` (owner-only);
//! - a NON-SECRET manifest `<config_dir>/wallets/index.json` = `{ active, wallets:[{id, address?,
//!   label?, created_ms}] }` (atomic, owner-only) — no seed, no key ever;
//! - the LEGACY single seed at `<config_dir>/wallet-seed.bin` (the #370 layout) is adopted as the
//!   wallet with the reserved TRANSIENT id `default` (its fingerprint is unknowable while the seed
//!   is locked), made active when no other wallet is — so an existing single-wallet setup keeps
//!   working identically. It is CANONICALIZED to its real fingerprint id the first time it is
//!   unlocked (the mnemonic makes the fingerprint knowable), and a re-import of the legacy key under
//!   the same password is reconciled to that one entry — so one key is never custodied twice
//!   (§18.20a).
//!
//! # Trust boundary (custody of mainnet-spending keys)
//!
//! This is the sanctioned custody locus for the paired-extension path, DISTINCT from the read-only
//! path of #217/#407 (where the node holds only PUBLIC puzzle hashes and NEVER a key). A seed
//! NEVER leaves the node:
//!
//! - no lifecycle op returns a mnemonic or secret key — [`WalletCustody::create`]/`import`/`unlock`
//!   return only the wallet's id + receive address;
//! - each seed is encrypted at rest under its own password and is never logged;
//! - each seed is encrypted INDEPENDENTLY, so unlocking, signing with, or removing one wallet can
//!   never decrypt or affect another;
//! - every custody error fails closed (missing wallet → not-found, wrong password → unauthorized),
//!   never mutating another wallet;
//! - the ONLY seed egress is the node-local, password-gated [`WalletCustody::reveal_mnemonic`]
//!   (self-origin backup UI / a `dig-node wallet backup` CLI), NEVER over the paired boundary
//!   (§7.12).
//!
//! Every op that mutates custody is authorized by the paired-token gate at the transport layer
//! (SPEC §7.12); this module owns the custody state machine + crypto, not the transport authz.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chia::bls::SecretKey;
use chia_protocol::Bytes32;
use chia_wallet_sdk::types::{MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use digstore_chain::keys::{derive_indexed_keys, derive_wallet_keys, owner_address};
use digstore_chain::seed::{generate_mnemonic, validate_mnemonic};
use zeroize::Zeroizing;

use super::spend::WalletSigner;
use super::{Error, Result};
use crate::seed_store;

/// The minimum length of the password that encrypts a seed at rest. Mirrors the self-origin wallet
/// UI's floor (`crate::lib`), so every custody surface rejects a trivially-weak password.
const MIN_PASSWORD_LEN: usize = 8;

/// How many unhardened HD indices a custodied signer covers by default (indices `0..N`). The signer
/// can spend a coin at any of these addresses' standard puzzle hashes; a coin outside the range is
/// not spendable by the loaded signer (matching typical usage — the count is a construction
/// parameter for callers that need more).
pub const DEFAULT_DERIVATION_COUNT: u32 = 50;

/// The reserved id of the adopted LEGACY single wallet (`<config_dir>/wallet-seed.bin`, the #370
/// pre-multi-wallet layout). New wallets always receive a fingerprint id under `wallets/`.
const LEGACY_ID: &str = "default";
/// The subdirectory (under the node config dir) that holds the per-wallet seeds + the manifest.
const WALLETS_SUBDIR: &str = "wallets";
/// The non-secret manifest filename inside [`WALLETS_SUBDIR`].
const MANIFEST_FILE: &str = "index.json";
/// The legacy single-seed filename (the #370 layout), directly under the node config dir.
const LEGACY_SEED_FILE: &str = "wallet-seed.bin";

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

/// The custody state of a single wallet, reported by [`WalletCustody::status`]/[`WalletCustody::list`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CustodyState {
    /// No wallet on this device (the addressed wallet does not exist / there are no wallets).
    None,
    /// An encrypted seed is on disk but no signer is loaded (needs `unlock`).
    Locked,
    /// A signer is loaded in memory (spend/sign is enabled).
    Unlocked,
}

/// The custody status of the addressed (default: active) wallet. Back-compatible with the #370
/// single-wallet shape (`{ state, address? }`); the `id`/`active` fields are ADDITIVE.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CustodyStatus {
    /// The lifecycle state.
    pub state: CustodyState,
    /// The wallet's receive address (`xch1…`), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The addressed wallet's id, when a wallet was addressed (absent for the `none` state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Whether the addressed wallet is the active one (absent for the `none` state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

/// A wallet reference returned by the create/import/restore/unlock ops: the stable id + the receive
/// address. NEVER carries a seed or key.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletRef {
    /// The stable wallet id (master-key fingerprint, or `default` for the adopted legacy wallet).
    pub id: String,
    /// The wallet's receive address (`xch1…`).
    pub address: String,
}

/// A per-wallet enumeration entry ([`WalletCustody::list`]/`select`). NON-SECRET only.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletInfo {
    /// The stable wallet id.
    pub id: String,
    /// The receive address, when known (recorded at create/import, or cached on first unlock).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The optional human label the caller attached at create/import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether a signer is loaded for this wallet right now.
    pub state: CustodyState,
    /// Whether this is the active wallet (the one the sign/spend surface signs with, §18.21).
    pub active: bool,
}

/// A non-secret manifest entry (persisted in `index.json`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct ManifestEntry {
    /// The stable wallet id.
    id: String,
    /// The receive address (`xch1…`) when known; `None` until an adopted legacy wallet is unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// An optional human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// Creation (or adoption) timestamp, ms since the Unix epoch.
    #[serde(default)]
    created_ms: u64,
}

/// The non-secret wallet manifest (`<config_dir>/wallets/index.json`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// The active wallet's id, or `None` when no wallet is custodied.
    #[serde(default)]
    active: Option<String>,
    /// Every custodied wallet (non-secret metadata only).
    #[serde(default)]
    wallets: Vec<ManifestEntry>,
}

/// An unlocked custody session: the in-memory signer + the wallet's receive address.
struct Unlocked {
    signer: Arc<WalletSigner>,
    address: String,
}

/// The node-custodied MULTI-wallet key lifecycle (§18.20/§18.20a). Owns the wallets directory, the
/// non-secret manifest, and the in-memory per-wallet unlocked signers; every method is
/// transport-agnostic (authorization is the caller's concern, §7.12). Cheap to `clone` — all state
/// is shared behind `Arc`s so an `unlock`/`create`/`select` on one handle is visible on the others.
#[derive(Clone)]
pub struct WalletCustody {
    /// The node config directory (holds `wallets/` and the legacy `wallet-seed.bin`).
    config_dir: PathBuf,
    /// The network the loaded signers sign for.
    network: Network,
    /// How many unhardened HD indices each signer covers (`0..derivation_count`).
    derivation_count: u32,
    /// The non-secret manifest, loaded + reconciled with disk at construction.
    manifest: Arc<RwLock<Manifest>>,
    /// In-memory unlocked sessions keyed by wallet id; shared across clones.
    unlocked: Arc<RwLock<HashMap<String, Unlocked>>>,
}

impl WalletCustody {
    /// Build a multi-wallet custody manager over `config_dir` (the node config directory), signing
    /// for `network`, each signer covering HD indices `0..derivation_count`. Loads + reconciles the
    /// on-disk manifest (adopting a legacy `wallet-seed.bin` if present).
    pub fn new(config_dir: PathBuf, network: Network, derivation_count: u32) -> Self {
        let c = Self {
            config_dir,
            network,
            derivation_count: derivation_count.max(1),
            manifest: Arc::new(RwLock::new(Manifest::default())),
            unlocked: Arc::new(RwLock::new(HashMap::new())),
        };
        c.load_and_reconcile();
        c
    }

    /// Build a mainnet multi-wallet custody manager with the default derivation coverage.
    pub fn mainnet(config_dir: PathBuf) -> Self {
        Self::new(config_dir, Network::Mainnet, DEFAULT_DERIVATION_COUNT)
    }

    /// Whether ANY wallet is custodied on this device.
    pub fn any_wallet(&self) -> bool {
        !self.manifest.read().unwrap().wallets.is_empty()
    }

    /// Enumerate every custodied wallet (NON-SECRET metadata + live locked/unlocked state).
    pub fn list(&self) -> Vec<WalletInfo> {
        let man = self.manifest.read().unwrap();
        let unlocked = self.unlocked.read().unwrap();
        man.wallets
            .iter()
            .map(|w| WalletInfo {
                id: w.id.clone(),
                address: unlocked
                    .get(&w.id)
                    .map(|u| u.address.clone())
                    .or_else(|| w.address.clone()),
                label: w.label.clone(),
                state: if unlocked.contains_key(&w.id) {
                    CustodyState::Unlocked
                } else {
                    CustodyState::Locked
                },
                active: man.active.as_deref() == Some(w.id.as_str()),
            })
            .collect()
    }

    /// The lifecycle state (+ address/id/active) of the addressed wallet (default: the active
    /// wallet). Reports `none` when the addressed wallet does not exist / there are no wallets.
    pub fn status(&self, id: Option<&str>) -> CustodyStatus {
        let Ok(id) = self.resolve_id(id) else {
            return CustodyStatus {
                state: CustodyState::None,
                address: None,
                id: None,
                active: None,
            };
        };
        let active = self.manifest.read().unwrap().active.as_deref() == Some(id.as_str());
        if let Some(u) = self.unlocked.read().unwrap().get(&id) {
            return CustodyStatus {
                state: CustodyState::Unlocked,
                address: Some(u.address.clone()),
                id: Some(id),
                active: Some(active),
            };
        }
        CustodyStatus {
            state: CustodyState::Locked,
            address: self.manifest_address(&id),
            id: Some(id),
            active: Some(active),
        }
    }

    /// Generate a fresh 24-word wallet, derive its fingerprint id, encrypt it under `password`,
    /// persist it, record its manifest entry (making it active if none is), and load the signer.
    /// Returns ONLY the id + receive address — the mnemonic is NEVER returned (§18.20: back it up
    /// via the node-local [`Self::reveal_mnemonic`]). Refuses if that wallet already exists.
    pub fn create(&self, password: &str, label: Option<String>) -> Result<WalletRef> {
        self.check_password(password)?;
        let mnemonic = generate_mnemonic(24)
            .map_err(|e| Error::internal(format!("failed to generate a recovery phrase: {e}")))?;
        self.provision(&mnemonic, password, label)
    }

    /// Import an existing mnemonic (the per-wallet migration path, §18.20): validate it, derive its
    /// fingerprint id, encrypt + persist it under `password`, record the manifest entry, and load
    /// the signer. Refuses if a wallet with that key already exists (no double-custody). Returns the
    /// id + receive address.
    pub fn import(
        &self,
        mnemonic: &str,
        password: &str,
        label: Option<String>,
    ) -> Result<WalletRef> {
        self.check_password(password)?;
        let m = validate_mnemonic(mnemonic)
            .map_err(|e| Error::api(format!("invalid recovery phrase: {e}")))?;
        self.provision(&m, password, label)
    }

    /// Restore a wallet from a mnemonic. Behaviourally identical to [`Self::import`]; a distinct
    /// name so the lifecycle surface reads naturally (§18.20).
    pub fn restore(
        &self,
        mnemonic: &str,
        password: &str,
        label: Option<String>,
    ) -> Result<WalletRef> {
        self.import(mnemonic, password, label)
    }

    /// Decrypt the addressed wallet's on-disk seed with `password` and load its in-memory signer
    /// (the runtime signer load that replaces the bring-up-only `with_signer`). Multiple wallets may
    /// be unlocked at once. Wrong password fails closed. On the first unlock of the adopted legacy
    /// wallet (reserved id `default`), the wallet is CANONICALIZED to its real fingerprint id (§18.20a)
    /// — the decrypted mnemonic makes the fingerprint knowable, so the `default`-vs-`<fp>` split is
    /// collapsed and future dedup/delete address the ONE canonical entry. Returns the id + receive
    /// address (the canonical id after any canonicalization).
    pub fn unlock(&self, id: Option<&str>, password: &str) -> Result<WalletRef> {
        let id = self.resolve_id(id)?;
        let mnemonic = self.read_seed(&id, password)?;
        let (signer, address) = self.build_signer(&mnemonic)?;
        // Canonicalize a legacy `default` seed to its fingerprint id on first unlock — no
        // `default`-vs-`<fp>` split for one key (§18.20a), so dedup + delete address ONE entry.
        let id = if id == LEGACY_ID {
            self.canonicalize_legacy(&mnemonic)?
        } else {
            id
        };
        self.unlocked.write().unwrap().insert(
            id.clone(),
            Unlocked {
                signer: Arc::new(signer),
                address: address.clone(),
            },
        );
        self.cache_address(&id, &address);
        Ok(WalletRef { id, address })
    }

    /// Drop the addressed wallet's in-memory signer (its encrypted seed stays on disk). Signing with
    /// it is disabled until the next [`Self::unlock`]. Other wallets are unaffected. Idempotent (a
    /// no-op when the wallet does not exist / is already locked).
    pub fn lock(&self, id: Option<&str>) {
        if let Ok(id) = self.resolve_id(id) {
            self.unlocked.write().unwrap().remove(&id);
        }
    }

    /// Make `id` the ACTIVE wallet — the wallet the Sage-parity sign/spend surface signs with
    /// (§18.21). The wallet must exist. Returns its enumeration entry.
    pub fn select(&self, id: &str) -> Result<WalletInfo> {
        let id = self.resolve_id(Some(id))?;
        self.manifest.write().unwrap().active = Some(id.clone());
        self.persist_manifest();
        Ok(self.info_for(&id))
    }

    /// Delete ONLY the addressed wallet: verify `password` against its on-disk seed (proof of
    /// ownership), then remove its seed file + manifest entry + in-memory signer. Other wallets are
    /// untouched; if it was active, the active pointer moves to another remaining wallet (or clears
    /// when none remain). A wrong password fails closed and nothing is removed.
    pub fn delete(&self, id: Option<&str>, password: &str) -> Result<()> {
        let id = self.resolve_id(id)?;
        // Verify ownership before destroying anything (fails closed on a wrong password).
        let _ = self.read_seed(&id, password)?;
        let path = self.seed_path_for(&id);
        std::fs::remove_file(&path)
            .map_err(|e| Error::internal(format!("failed to delete the seed: {e}")))?;
        {
            let mut man = self.manifest.write().unwrap();
            man.wallets.retain(|w| w.id != id);
            if man.active.as_deref() == Some(id.as_str()) {
                man.active = man.wallets.first().map(|w| w.id.clone());
            }
        }
        self.persist_manifest();
        self.unlocked.write().unwrap().remove(&id);
        Ok(())
    }

    /// NODE-LOCAL backup ONLY: decrypt + return the addressed wallet's mnemonic. This is the sole
    /// seed-egress path and MUST NOT be exposed over the paired authorized boundary (§7.12/§18.20) —
    /// it exists for the self-origin backup UI / a `dig-node wallet backup` CLI. Wrong password
    /// fails closed.
    pub fn reveal_mnemonic(&self, id: Option<&str>, password: &str) -> Result<Zeroizing<String>> {
        let id = self.resolve_id(id)?;
        self.read_seed(&id, password)
    }

    /// The in-memory signer for the addressed wallet (default: the ACTIVE wallet) — the sign/broadcast
    /// path (§18.21). `None` when that wallet is locked / does not exist.
    pub fn signer(&self, id: Option<&str>) -> Option<Arc<WalletSigner>> {
        let id = self.resolve_id(id).ok()?;
        self.unlocked
            .read()
            .unwrap()
            .get(&id)
            .map(|u| u.signer.clone())
    }

    /// Verify `password` against the addressed wallet's on-disk seed WITHOUT loading a signer or
    /// changing any state (§18.24): decrypt the seed (the decrypted mnemonic is dropped immediately)
    /// and return `Ok` iff it decrypts. This is the read-only-session password check the unlock-auth
    /// state machine uses — a successful verify grants reads but never makes signing possible. Wrong
    /// password fails closed (`401`); a missing wallet is `404`. NEVER mutates custody.
    pub fn verify_password(&self, id: Option<&str>, password: &str) -> Result<()> {
        let id = self.resolve_id(id)?;
        // `read_seed` returns a `Zeroizing<String>`, dropped (and scrubbed) at the end of this scope.
        let _ = self.read_seed(&id, password)?;
        Ok(())
    }

    /// Build a ONE-SHOT signer for the addressed wallet (default: the ACTIVE wallet) by decrypting its
    /// on-disk seed with `password` — WITHOUT inserting it into the persistent `unlocked` session
    /// (§18.24 per-transaction sign). The returned `Arc<WalletSigner>` is the ONLY strong reference;
    /// when the caller drops it (after one signing operation) the decrypted-key allocation is released
    /// — the key is not retained. Wrong password fails closed (`401`); a missing wallet is `404`.
    pub fn sign_once(&self, id: Option<&str>, password: &str) -> Result<Arc<WalletSigner>> {
        let id = self.resolve_id(id)?;
        let mnemonic = self.read_seed(&id, password)?;
        let (signer, _address) = self.build_signer(&mnemonic)?;
        Ok(Arc::new(signer))
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

    /// Provision a wallet from a validated `mnemonic`: derive its fingerprint id, refuse a duplicate,
    /// encrypt + persist the seed (owner-only), record the manifest entry (active if first), and load
    /// the signer.
    fn provision(
        &self,
        mnemonic: &str,
        password: &str,
        label: Option<String>,
    ) -> Result<WalletRef> {
        let id = wallet_fingerprint(mnemonic)?.to_string();
        // Close the legacy double-custody gap (§18.20a): an adopted legacy `default` wallet has no
        // recorded fingerprint (its seed is encrypted, unreadable without a password), so the
        // fingerprint dedup below cannot see it. If the imported key IS the legacy key — provable by
        // decrypting the `default` seed with THIS password — canonicalize `default` → `<fp>` FIRST,
        // so `wallet_exists` then refuses this re-import instead of writing a second custody copy.
        self.reconcile_legacy_same_key(&id, password);
        if self.wallet_exists(&id) {
            return Err(Error::api(
                "a wallet with this key already exists on this node; delete it first to replace it",
            ));
        }
        let enc = seed_store::encrypt_seed(mnemonic, password).map_err(Error::internal)?;
        let path = self.seed_path_for(&id);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::internal(format!("failed to create the wallet dir: {e}")))?;
        }
        std::fs::write(&path, &enc)
            .map_err(|e| Error::internal(format!("failed to persist the seed: {e}")))?;
        restrict_permissions(&path);
        let (signer, address) = self.build_signer(mnemonic)?;
        {
            let mut man = self.manifest.write().unwrap();
            man.wallets.push(ManifestEntry {
                id: id.clone(),
                address: Some(address.clone()),
                label,
                created_ms: now_ms(),
            });
            if man.active.is_none() {
                man.active = Some(id.clone());
            }
        }
        self.persist_manifest();
        self.unlocked.write().unwrap().insert(
            id.clone(),
            Unlocked {
                signer: Arc::new(signer),
                address: address.clone(),
            },
        );
        Ok(WalletRef { id, address })
    }

    /// Whether a wallet with `id` already exists (a manifest entry OR a seed file on disk).
    fn wallet_exists(&self, id: &str) -> bool {
        self.seed_path_for(id).exists()
            || self
                .manifest
                .read()
                .unwrap()
                .wallets
                .iter()
                .any(|w| w.id == id)
    }

    /// Canonicalize the adopted legacy wallet (reserved id `default`) to its real fingerprint id,
    /// given its now-known `mnemonic` (§18.20a). Moves the encrypted seed `wallet-seed.bin` →
    /// `wallets/<fp>.seed` (its at-rest password is preserved — the file is moved, not re-encrypted),
    /// renames the manifest entry `default` → `<fp>` (preserving `active`, label, timestamp; recording
    /// the receive address), and re-keys any in-memory session. If a `<fp>` entry already exists (a
    /// duplicate that formed before this canonicalization), the legacy representation is DROPPED and
    /// the wallets collapse to the single canonical `<fp>` entry. Returns the canonical id.
    fn canonicalize_legacy(&self, mnemonic: &str) -> Result<String> {
        let fp = wallet_fingerprint(mnemonic)?.to_string();
        let legacy_path = self.legacy_seed_path();
        let target = self.wallets_dir().join(format!("{fp}.seed"));
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| Error::internal(format!("failed to create the wallet dir: {e}")))?;
        }
        if target.exists() {
            // The canonical seed already exists (a duplicate) → drop the legacy representation.
            let _ = std::fs::remove_file(&legacy_path);
        } else if legacy_path.exists() {
            // Move the legacy encrypted file to its canonical name (at-rest password preserved).
            if std::fs::rename(&legacy_path, &target).is_err() {
                std::fs::copy(&legacy_path, &target).map_err(|e| {
                    Error::internal(format!("failed to canonicalize the legacy seed: {e}"))
                })?;
                let _ = std::fs::remove_file(&legacy_path);
            }
            restrict_permissions(&target);
        }
        // The (public) receive address for the canonical manifest entry.
        let address = derive_wallet_keys(mnemonic).map(|k| owner_address(&k)).ok();
        {
            let mut man = self.manifest.write().unwrap();
            let fp_exists = man.wallets.iter().any(|w| w.id == fp);
            if let Some(pos) = man.wallets.iter().position(|w| w.id == LEGACY_ID) {
                if fp_exists {
                    // Collapse the duplicate: keep the existing `<fp>` entry, drop `default`.
                    man.wallets.remove(pos);
                } else {
                    man.wallets[pos].id = fp.clone();
                    if man.wallets[pos].address.is_none() {
                        man.wallets[pos].address = address;
                    }
                }
            }
            if man.active.as_deref() == Some(LEGACY_ID) {
                man.active = Some(fp.clone());
            }
        }
        self.persist_manifest();
        // Re-key any in-memory session `default` → `<fp>`.
        {
            let mut u = self.unlocked.write().unwrap();
            if let Some(sess) = u.remove(LEGACY_ID) {
                u.insert(fp.clone(), sess);
            }
        }
        Ok(fp)
    }

    /// If an adopted legacy `default` wallet holds the SAME key as `target_fp` — provable by
    /// decrypting the `default` seed with `password` — canonicalize it to `<fp>` so the fingerprint
    /// dedup guard sees it (§18.20a). Best-effort: a wrong/missing password or a different key leaves
    /// `default` untouched (it can still canonicalize later, on its own first unlock).
    fn reconcile_legacy_same_key(&self, target_fp: &str, password: &str) {
        let has_default = self
            .manifest
            .read()
            .unwrap()
            .wallets
            .iter()
            .any(|w| w.id == LEGACY_ID);
        if !has_default {
            return;
        }
        let Ok(bytes) = std::fs::read(self.legacy_seed_path()) else {
            return;
        };
        let Ok(mnemonic) = seed_store::decrypt_seed(&bytes, password) else {
            return;
        };
        if wallet_fingerprint(&mnemonic)
            .ok()
            .map(|f| f.to_string())
            .as_deref()
            == Some(target_fp)
        {
            let _ = self.canonicalize_legacy(&mnemonic);
        }
    }

    /// Resolve an optional caller-supplied id to a concrete wallet id: the given id when it exists,
    /// else the active wallet, else (when exactly one wallet exists) that wallet. Errors when no
    /// matching wallet is custodied.
    fn resolve_id(&self, id: Option<&str>) -> Result<String> {
        let man = self.manifest.read().unwrap();
        if let Some(req) = id {
            if man.wallets.iter().any(|w| w.id == req) {
                return Ok(req.to_string());
            }
            return Err(Error::not_found(format!(
                "no wallet with id {req} on this device"
            )));
        }
        if let Some(active) = man.active.as_ref() {
            if man.wallets.iter().any(|w| &w.id == active) {
                return Ok(active.clone());
            }
        }
        if man.wallets.len() == 1 {
            return Ok(man.wallets[0].id.clone());
        }
        Err(Error::not_found("no wallet on this device"))
    }

    /// Read + decrypt the addressed wallet's on-disk seed under `password` (maps missing → 404,
    /// wrong password → 401). Fails closed.
    fn read_seed(&self, id: &str, password: &str) -> Result<Zeroizing<String>> {
        let bytes = std::fs::read(self.seed_path_for(id))
            .map_err(|_| Error::not_found("no wallet on this device"))?;
        seed_store::decrypt_seed(&bytes, password)
            .map_err(|_| Error::unauthorized("wrong password"))
    }

    /// The receive address for `id` recorded in the manifest, if known.
    fn manifest_address(&self, id: &str) -> Option<String> {
        self.manifest
            .read()
            .unwrap()
            .wallets
            .iter()
            .find(|w| w.id == id)
            .and_then(|w| w.address.clone())
    }

    /// Cache a wallet's receive address into its manifest entry when previously unknown (an adopted
    /// legacy wallet learns its address on first unlock). Best-effort — a persist failure is
    /// non-fatal (the address re-derives on the next unlock).
    fn cache_address(&self, id: &str, address: &str) {
        let mut changed = false;
        {
            let mut man = self.manifest.write().unwrap();
            if let Some(w) = man.wallets.iter_mut().find(|w| w.id == id) {
                if w.address.as_deref() != Some(address) {
                    w.address = Some(address.to_string());
                    changed = true;
                }
            }
        }
        if changed {
            self.persist_manifest();
        }
    }

    /// The enumeration entry for one known wallet id (used by `select`).
    fn info_for(&self, id: &str) -> WalletInfo {
        let man = self.manifest.read().unwrap();
        let unlocked = self.unlocked.read().unwrap();
        let entry = man.wallets.iter().find(|w| w.id == id);
        WalletInfo {
            id: id.to_string(),
            address: unlocked
                .get(id)
                .map(|u| u.address.clone())
                .or_else(|| entry.and_then(|w| w.address.clone())),
            label: entry.and_then(|w| w.label.clone()),
            state: if unlocked.contains_key(id) {
                CustodyState::Unlocked
            } else {
                CustodyState::Locked
            },
            active: man.active.as_deref() == Some(id),
        }
    }

    /// The `wallets/` directory under the node config dir.
    fn wallets_dir(&self) -> PathBuf {
        self.config_dir.join(WALLETS_SUBDIR)
    }

    /// The manifest path (`wallets/index.json`).
    fn manifest_path(&self) -> PathBuf {
        self.wallets_dir().join(MANIFEST_FILE)
    }

    /// The legacy single-seed path (`<config_dir>/wallet-seed.bin`).
    fn legacy_seed_path(&self) -> PathBuf {
        self.config_dir.join(LEGACY_SEED_FILE)
    }

    /// The encrypted-seed file path for `id`: the legacy path for the reserved `default` wallet,
    /// else `wallets/<id>.seed`.
    fn seed_path_for(&self, id: &str) -> PathBuf {
        if id == LEGACY_ID {
            self.legacy_seed_path()
        } else {
            self.wallets_dir().join(format!("{id}.seed"))
        }
    }

    /// Load the on-disk manifest and reconcile it with the seed files actually present: adopt any
    /// seed file (incl. the legacy `wallet-seed.bin` as `default`) missing a manifest entry, drop
    /// entries whose seed file is gone, and repair a dangling active pointer. Self-healing, so a
    /// missing/corrupt manifest never orphans a seed file.
    fn load_and_reconcile(&self) {
        let mut man = self.read_manifest_file().unwrap_or_default();
        let mut changed = false;

        // Every seed file currently on disk → the set of valid ids.
        let mut on_disk: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(self.wallets_dir()) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("seed") {
                    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                        on_disk.push(stem.to_string());
                    }
                }
            }
        }
        if self.legacy_seed_path().exists() {
            on_disk.push(LEGACY_ID.to_string());
        }

        // Adopt seed files that have no manifest entry yet.
        for id in &on_disk {
            if !man.wallets.iter().any(|w| &w.id == id) {
                man.wallets.push(ManifestEntry {
                    id: id.clone(),
                    address: None,
                    label: None,
                    created_ms: now_ms(),
                });
                changed = true;
            }
        }
        // Drop entries whose seed file is gone.
        let before = man.wallets.len();
        man.wallets.retain(|w| on_disk.contains(&w.id));
        if man.wallets.len() != before {
            changed = true;
        }
        // Repair a dangling / missing active pointer.
        let active_ok = man
            .active
            .as_ref()
            .is_some_and(|a| man.wallets.iter().any(|w| &w.id == a));
        if !active_ok {
            let new_active = man.wallets.first().map(|w| w.id.clone());
            if man.active != new_active {
                man.active = new_active;
                changed = true;
            }
        }

        let non_empty = !man.wallets.is_empty();
        *self.manifest.write().unwrap() = man;
        // Persist a changed, non-empty manifest; never write an empty manifest on a fresh node.
        if changed && non_empty {
            self.persist_manifest();
        }
    }

    /// Parse the on-disk manifest, or `None` when absent/unreadable/corrupt (reconciliation rebuilds
    /// it from the seed files present).
    fn read_manifest_file(&self) -> Option<Manifest> {
        let bytes = std::fs::read(self.manifest_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Persist the manifest atomically + owner-only. Best-effort: a failure is logged, not fatal —
    /// the manifest is NON-SECRET and self-heals from the seed files on the next construction.
    fn persist_manifest(&self) {
        let dir = self.wallets_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("dig-wallet: WARN could not create the wallets dir: {e}");
            return;
        }
        let json = {
            let man = self.manifest.read().unwrap();
            match serde_json::to_vec_pretty(&*man) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("dig-wallet: WARN could not serialize the wallet manifest: {e}");
                    return;
                }
            }
        };
        let path = self.manifest_path();
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &json).is_err() {
            eprintln!("dig-wallet: WARN could not write the wallet manifest");
            return;
        }
        restrict_permissions(&tmp);
        // Replace the destination (Windows `rename` fails onto an existing file).
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            eprintln!("dig-wallet: WARN could not persist the wallet manifest: {e}");
            let _ = std::fs::remove_file(&tmp);
        }
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

/// The stable wallet id for a mnemonic: the Chia BLS **master public-key fingerprint** (a `u32`, the
/// canonical Chia wallet id). Deterministic + non-secret. Computed independently of the signing
/// derivation so a wallet's id is stable regardless of how many HD indices are covered.
fn wallet_fingerprint(mnemonic: &str) -> Result<u32> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| Error::api(format!("invalid recovery phrase: {e}")))?;
    let seed = Zeroizing::new(m.to_seed(""));
    let master_sk = SecretKey::from_seed(&seed[..]);
    Ok(master_sk.public_key().get_fingerprint())
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch — impossible in practice).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Restrict a file to owner read/write on Unix (`0600`); best-effort defense-in-depth (loopback-only
/// + at-rest encryption are the primary controls). No-op on non-Unix.
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical BIP-39 test vector ("abandon…art") — a KNOWN mnemonic so an import→unlock
    /// round-trip is deterministic (the golden migration seed).
    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    /// A second known-distinct test vector ("legal winner…") — a DIFFERENT seed (different
    /// fingerprint) so multi-wallet tests custody two independent keys.
    const LEGAL: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    /// The master-fingerprint id of `ABANDON` (asserted stable in `fingerprint_id_is_deterministic`).
    fn abandon_id() -> String {
        wallet_fingerprint(ABANDON).unwrap().to_string()
    }

    /// A fresh custody manager over a unique temp CONFIG DIR (no wallets yet). A small derivation
    /// count keeps the key-build fast in tests.
    fn fresh() -> (WalletCustody, PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dig-node-custody-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        (WalletCustody::new(dir.clone(), Network::Mainnet, 3), dir)
    }

    #[test]
    fn status_is_none_when_no_wallet_exists() {
        let (c, _p) = fresh();
        assert_eq!(c.status(None).state, CustodyState::None);
        assert!(c.status(None).address.is_none());
        assert!(c.list().is_empty());
        assert!(!c.any_wallet());
    }

    #[test]
    fn fingerprint_id_is_deterministic_and_nonsecret() {
        // Same seed ⇒ same id; the id is a decimal u32 (no mnemonic material).
        let a1 = wallet_fingerprint(ABANDON).unwrap();
        let a2 = wallet_fingerprint(ABANDON).unwrap();
        assert_eq!(a1, a2);
        let l = wallet_fingerprint(LEGAL).unwrap();
        assert_ne!(a1, l, "distinct seeds ⇒ distinct ids");
        assert!(a1.to_string().chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn create_persists_an_encrypted_seed_and_never_returns_the_mnemonic() {
        let (c, dir) = fresh();
        let w = c.create("hunter2pw", None).unwrap();

        // The return is the id + receive address (an xch1 address has no spaces), NOT a phrase.
        assert!(w.address.starts_with("xch1"), "got {}", w.address);
        assert!(!w.address.contains(' '), "must not return the mnemonic");
        assert!(
            w.id.chars().all(|ch| ch.is_ascii_digit()),
            "id is a fingerprint"
        );

        // The seed file exists under wallets/<id>.seed, ENCRYPTED, mnemonic not in plaintext.
        let path = dir.join("wallets").join(format!("{}.seed", w.id));
        let on_disk = std::fs::read(&path).unwrap();
        let recovered = seed_store::decrypt_seed(&on_disk, "hunter2pw").unwrap();
        assert_eq!(recovered.split_whitespace().count(), 24);
        assert!(
            !String::from_utf8_lossy(&on_disk).contains(&*recovered),
            "the mnemonic must not appear in plaintext in the seed file"
        );

        // Create leaves the wallet unlocked + active.
        let s = c.status(None);
        assert_eq!(s.state, CustodyState::Unlocked);
        assert_eq!(s.id.as_deref(), Some(w.id.as_str()));
        assert_eq!(s.active, Some(true));
    }

    #[test]
    fn import_uses_the_fingerprint_id_and_unlock_recovers_the_same_address() {
        let (c, _p) = fresh();
        let w = c.import(ABANDON, "correcthorse", None).unwrap();
        assert_eq!(w.id, abandon_id(), "id is the master fingerprint");

        // Lock, then unlock: the same on-disk seed re-derives the identical address.
        c.lock(None);
        assert_eq!(c.status(None).state, CustodyState::Locked);
        let w2 = c.unlock(None, "correcthorse").unwrap();
        assert_eq!(w2.address, w.address, "unlock recovers the same wallet");
        assert_eq!(w2.id, w.id);
    }

    #[test]
    fn import_refuses_the_same_key_twice_no_double_custody() {
        let (c, _p) = fresh();
        c.import(ABANDON, "correcthorse", None).unwrap();
        let err = c.import(ABANDON, "otherpassword", None).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Api);
        assert!(err.message.contains("already exists"));
        assert_eq!(
            c.list().len(),
            1,
            "the duplicate import must not add a wallet"
        );
    }

    #[test]
    fn two_independent_wallets_each_unlock_and_sign_independently() {
        let (c, _p) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(c.list().len(), 2);

        // The FIRST-created wallet is active; both are unlocked (import unlocks).
        assert!(c.signer(Some(&a.id)).is_some());
        assert!(c.signer(Some(&b.id)).is_some());

        // Lock A; B stays unlocked (independent) — removing/locking one never affects the other.
        c.lock(Some(&a.id));
        assert!(c.signer(Some(&a.id)).is_none(), "A locked");
        assert!(c.signer(Some(&b.id)).is_some(), "B unaffected");

        // Each unlocks only with ITS OWN password (independent encryption).
        assert!(
            c.unlock(Some(&a.id), "passphrase-b").is_err(),
            "A rejects B's password"
        );
        assert!(c.unlock(Some(&a.id), "passphrase-a").is_ok());
    }

    #[test]
    fn select_switches_the_active_wallet_and_the_effective_signer() {
        let (c, _p) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();

        // A is active (created first); signer(None) resolves to A.
        assert_eq!(c.status(None).id.as_deref(), Some(a.id.as_str()));
        let sig_a = c.signer(None).unwrap();
        assert_eq!(
            sig_a.puzzle_hashes(),
            c.signer(Some(&a.id)).unwrap().puzzle_hashes()
        );

        // Select B → signer(None) now resolves to B.
        let info = c.select(&b.id).unwrap();
        assert!(info.active);
        assert_eq!(c.status(None).id.as_deref(), Some(b.id.as_str()));
        assert_eq!(
            c.signer(None).unwrap().puzzle_hashes(),
            c.signer(Some(&b.id)).unwrap().puzzle_hashes()
        );
    }

    #[test]
    fn delete_removes_only_the_addressed_wallet_and_reassigns_active() {
        let (c, dir) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();
        // A is active. Delete A → B remains, becomes active; A's seed file is gone, B's intact.
        c.delete(Some(&a.id), "passphrase-a").unwrap();
        assert_eq!(c.list().len(), 1);
        assert_eq!(
            c.status(None).id.as_deref(),
            Some(b.id.as_str()),
            "active moved to B"
        );
        assert!(!dir.join("wallets").join(format!("{}.seed", a.id)).exists());
        assert!(dir.join("wallets").join(format!("{}.seed", b.id)).exists());
        // B still unlocks with its own password (untouched by A's deletion).
        c.lock(Some(&b.id));
        assert!(c.unlock(Some(&b.id), "passphrase-b").is_ok());
    }

    #[test]
    fn delete_wrong_password_fails_closed_and_preserves_every_wallet() {
        let (c, _p) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();
        assert!(c.delete(Some(&a.id), "wrong").is_err());
        assert_eq!(c.list().len(), 2, "a wrong-password delete removes nothing");
        // A different wallet's password must NOT delete A (independent seeds).
        assert!(c.delete(Some(&a.id), "passphrase-b").is_err());
        assert_eq!(c.list().len(), 2);
        let _ = b;
    }

    #[test]
    fn wrong_password_fails_closed_on_unlock() {
        let (c, _p) = fresh();
        c.create("rightpassword", None).unwrap();
        c.lock(None);
        let err = c.unlock(None, "wrongpassword").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Unauthorized);
        assert!(c.signer(None).is_none(), "a failed unlock loads no signer");
    }

    #[test]
    fn reveal_mnemonic_is_per_wallet_and_password_gated() {
        let (c, _p) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        c.import(LEGAL, "passphrase-b", None).unwrap();
        let revealed = c.reveal_mnemonic(Some(&a.id), "passphrase-a").unwrap();
        assert_eq!(&*revealed, ABANDON, "node-local backup recovers the phrase");
        // A's password cannot reveal it under the wrong password, nor with B's password.
        assert!(c.reveal_mnemonic(Some(&a.id), "passphrase-b").is_err());
        assert!(c.reveal_mnemonic(Some(&a.id), "wrong").is_err());
    }

    #[test]
    fn verify_password_checks_without_loading_a_signer() {
        let (c, _p) = fresh();
        c.import(ABANDON, "correcthorse", None).unwrap();
        c.lock(None);
        assert_eq!(c.status(None).state, CustodyState::Locked);
        // A correct password verifies; a wrong password fails closed. Neither loads a signer.
        assert!(c.verify_password(None, "correcthorse").is_ok());
        assert!(c.verify_password(None, "wrong").is_err());
        assert_eq!(
            c.status(None).state,
            CustodyState::Locked,
            "verify_password must not load a signer"
        );
        assert!(c.signer(None).is_none());
    }

    #[test]
    fn sign_once_builds_a_signer_without_persisting_a_session() {
        let (c, _p) = fresh();
        let held = c.import(ABANDON, "correcthorse", None).unwrap();
        c.lock(None);
        assert!(c.signer(None).is_none(), "locked");

        // sign_once builds a usable signer (same wallet's puzzle hashes) but does NOT persist it.
        let one = c.sign_once(None, "correcthorse").unwrap();
        assert!(!one.puzzle_hashes().is_empty());
        assert!(
            c.signer(None).is_none(),
            "sign_once must not load a persistent session"
        );
        assert_eq!(c.status(None).state, CustodyState::Locked);

        // The one-shot signer is the sole owner: dropping it releases the decrypted-key allocation.
        let weak = Arc::downgrade(&one);
        drop(one);
        assert!(
            weak.upgrade().is_none(),
            "the decrypted signer must not be retained after drop"
        );
        let _ = held;
    }

    #[test]
    fn sign_once_wrong_password_fails_closed() {
        let (c, _p) = fresh();
        c.import(ABANDON, "correcthorse", None).unwrap();
        c.lock(None);
        // NB: `WalletSigner` deliberately has no `Debug` (it holds secret keys), so we cannot
        // `unwrap_err()` the `Result<Arc<WalletSigner>, _>` — inspect the error via `err()`.
        let res = c.sign_once(None, "wrong");
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().kind, ErrorKind::Unauthorized);
        assert!(c.signer(None).is_none());
    }

    #[test]
    fn weak_password_is_rejected() {
        let (c, dir) = fresh();
        assert!(c.create("short", None).is_err());
        assert!(
            !dir.join("wallets").exists(),
            "a rejected create writes no wallet"
        );
    }

    #[test]
    fn invalid_mnemonic_is_rejected_on_import() {
        let (c, _p) = fresh();
        let err = c
            .import("not a valid bip39 phrase at all", "correcthorse", None)
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Api);
    }

    #[test]
    fn wallets_persist_and_reconcile_across_reconstruction() {
        let (c, dir) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();
        c.select(&b.id).unwrap();

        // A fresh manager over the same dir sees BOTH wallets (locked), with B still active.
        let c2 = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        assert_eq!(c2.list().len(), 2);
        assert_eq!(
            c2.status(None).id.as_deref(),
            Some(b.id.as_str()),
            "active persisted"
        );
        assert_eq!(c2.status(Some(&a.id)).state, CustodyState::Locked);
        // Both reopen with their own passwords.
        assert!(c2.unlock(Some(&a.id), "passphrase-a").is_ok());
        assert!(c2.unlock(Some(&b.id), "passphrase-b").is_ok());
    }

    #[test]
    fn reconcile_rebuilds_a_missing_manifest_from_seed_files() {
        let (c, dir) = fresh();
        let a = c.import(ABANDON, "passphrase-a", None).unwrap();
        // Delete the manifest but leave the seed file — reconstruction must re-adopt it.
        std::fs::remove_file(dir.join("wallets").join("index.json")).unwrap();
        let c2 = WalletCustody::new(dir, Network::Mainnet, 3);
        assert_eq!(c2.list().len(), 1, "the orphaned seed is re-adopted");
        assert_eq!(c2.list()[0].id, a.id);
        assert!(c2.unlock(Some(&a.id), "passphrase-a").is_ok());
    }

    // ---- legacy single-wallet back-compat (§18.20a) ----------------------

    /// Write a legacy `wallet-seed.bin` (the #370 single-wallet layout) directly, WITHOUT the
    /// multi-wallet manager — the exact on-disk state a pre-#427 node leaves behind.
    fn write_legacy_seed(dir: &Path, mnemonic: &str, password: &str) {
        std::fs::create_dir_all(dir).unwrap();
        let enc = seed_store::encrypt_seed(mnemonic, password).unwrap();
        std::fs::write(dir.join(LEGACY_SEED_FILE), enc).unwrap();
    }

    /// A unique temp config dir for the legacy-adoption tests (which build the on-disk state by hand).
    fn legacy_dir(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dig-node-custody-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn legacy_single_wallet_adopted_then_canonicalized_on_first_unlock() {
        let dir = legacy_dir("legacy");
        write_legacy_seed(&dir, ABANDON, "legacy-pw");

        // A pre-existing single-wallet setup: adopted as the active `default` wallet, locked
        // (its fingerprint is unknowable while the seed is encrypted).
        let c = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        assert_eq!(c.list().len(), 1);
        let s = c.status(None);
        assert_eq!(s.state, CustodyState::Locked);
        assert_eq!(s.id.as_deref(), Some(LEGACY_ID));
        assert_eq!(s.active, Some(true));

        // The no-id path (single-wallet back-compat) unlocks it — and CANONICALIZES it to its real
        // fingerprint id: `default` is gone, the file moved to wallets/<fp>.seed, still active + signing.
        let w = c.unlock(None, "legacy-pw").unwrap();
        assert_eq!(
            w.id,
            abandon_id(),
            "unlock canonicalizes to the fingerprint id"
        );
        assert!(w.address.starts_with("xch1"));
        assert!(
            !dir.join(LEGACY_SEED_FILE).exists(),
            "legacy file moved to its canonical name"
        );
        assert!(dir
            .join("wallets")
            .join(format!("{}.seed", abandon_id()))
            .exists());
        assert_eq!(c.list().len(), 1);
        assert_eq!(c.status(None).id.as_deref(), Some(abandon_id().as_str()));
        assert_eq!(c.status(None).active, Some(true));
        assert!(c.signer(None).is_some());
        // Addressable by its real fingerprint (survives a fresh reconstruction — no `default` left).
        let c2 = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        assert_eq!(c2.list()[0].id, abandon_id());
        assert!(c2.status(Some(LEGACY_ID)).state == CustodyState::None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_reimport_same_password_is_reconciled_not_duplicated() {
        // The #374 migration re-pushes the SAME seed the node already holds as legacy `default`.
        let dir = legacy_dir("legacy-reimport");
        write_legacy_seed(&dir, ABANDON, "legacy-pw");
        let c = WalletCustody::new(dir.clone(), Network::Mainnet, 3);

        // Re-import the legacy key under its own password → REFUSED as a duplicate, and the legacy
        // wallet is canonicalized to <fp> — NEVER a second custody entry (the defect this closes).
        let err = c.import(ABANDON, "legacy-pw", None).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Api);
        assert!(err.message.contains("already exists"));
        assert_eq!(c.list().len(), 1, "one key ⇒ exactly one custody entry");
        assert_eq!(c.list()[0].id, abandon_id());
        assert!(
            !dir.join(LEGACY_SEED_FILE).exists(),
            "legacy seed canonicalized away"
        );
        assert!(dir
            .join("wallets")
            .join(format!("{}.seed", abandon_id()))
            .exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_reimport_different_password_self_heals_to_one_entry_on_unlock() {
        // Edge: the legacy seed's password is unknown at import time (a different password), so the
        // import cannot prove same-key and a transient duplicate forms. The next unlock of the legacy
        // wallet collapses it to the single canonical entry — one key is never custodied twice.
        let dir = legacy_dir("legacy-diffpw");
        write_legacy_seed(&dir, ABANDON, "legacy-pw");
        let c = WalletCustody::new(dir.clone(), Network::Mainnet, 3);

        // Import the SAME key under a DIFFERENT password: undetectable now ⇒ a transient 2nd entry.
        let w = c.import(ABANDON, "other-password", None).unwrap();
        assert_eq!(w.id, abandon_id());
        assert_eq!(c.list().len(), 2, "transient duplicate (default + <fp>)");

        // Unlock the legacy `default` → canonicalization collapses the duplicate to ONE entry.
        c.unlock(Some(LEGACY_ID), "legacy-pw").unwrap();
        assert_eq!(c.list().len(), 1, "self-healed to a single custody entry");
        assert_eq!(c.list()[0].id, abandon_id());
        assert!(
            !dir.join(LEGACY_SEED_FILE).exists(),
            "the legacy representation is dropped"
        );
        assert!(dir
            .join("wallets")
            .join(format!("{}.seed", abandon_id()))
            .exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_wallet_coexists_with_new_fingerprint_wallets() {
        let dir = legacy_dir("legacy-coexist");
        write_legacy_seed(&dir, ABANDON, "legacy-pw");

        let c = WalletCustody::new(dir.clone(), Network::Mainnet, 3);
        // Import a SECOND, DISTINCT wallet (different key, different password) — it gets a fingerprint
        // id under wallets/; the un-unlocked legacy stays `default` + active (its key differs, and its
        // password is unknown, so it is left untouched, to canonicalize on its own first unlock).
        let b = c.import(LEGAL, "passphrase-b", None).unwrap();
        assert_eq!(c.list().len(), 2);
        assert_eq!(
            c.status(None).id.as_deref(),
            Some(LEGACY_ID),
            "legacy stays active"
        );
        assert_ne!(b.id, LEGACY_ID);
        assert!(dir.join("wallets").join(format!("{}.seed", b.id)).exists());
        assert!(dir.join(LEGACY_SEED_FILE).exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::super::ErrorKind;
}
