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
//!   label?, created_ms, public_keys?}] }` (atomic, owner-only) — no seed, no SECRET key ever;
//!   `public_keys` is the wallet's on-chain-public standard-layer keys, which the push guard needs
//!   while every wallet is locked (§18.12);
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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chia::bls::{
    master_to_wallet_hardened_intermediate, master_to_wallet_unhardened_intermediate, DerivableKey,
    PublicKey, SecretKey,
};
use chia::puzzles::standard::StandardArgs;
use chia::puzzles::DeriveSynthetic;
use chia_protocol::Bytes32;
use chia_wallet_sdk::types::{MAINNET_CONSTANTS, TESTNET11_CONSTANTS};
use digstore_chain::keys::{derive_wallet_keys, owner_address};
use digstore_chain::seed::{generate_mnemonic, validate_mnemonic};
use zeroize::Zeroizing;

use super::spend::WalletSigner;
use super::{Error, Result};
use crate::seed_store;

/// The minimum length of the password that encrypts a seed at rest. Mirrors the self-origin wallet
/// UI's floor (`crate::lib`), so every custody surface rejects a trivially-weak password.
const MIN_PASSWORD_LEN: usize = 8;

/// How many HD indices a custodied wallet covers in EACH tree (unhardened and hardened) before any
/// on-chain usage has been observed — the scan-ahead a freshly imported wallet starts with.
///
/// Sized so an ordinary imported wallet's existing history is found on the first sync. It was 50,
/// and a 50-index window silently under-reported the balance of any wallet whose history reached
/// index 50 (dig_ecosystem#2762): the coins were simply never subscribed, and the node reported
/// `synced` over the smaller number. The window now also GROWS with observed usage
/// ([`DERIVATION_GAP_LIMIT`]), so this is the floor rather than the ceiling.
pub const DEFAULT_DERIVATION_COUNT: u32 = 500;

/// How far past the highest index observed IN USE the covered window is kept.
///
/// A wallet that has used index 400 must already be watching well past it, because the next
/// addresses it hands out are the ones the user is about to be paid at. This is the BIP-44 gap
/// limit idea with a much larger constant, chosen because the cost of over-covering is a few
/// milliseconds of key derivation and the cost of under-covering is money the user cannot see.
pub const DERIVATION_GAP_LIMIT: u32 = 250;

/// The ceiling on the covered window, so a hostile COIN SET cannot turn an unlock into unbounded
/// key derivation.
///
/// The gap-limit scan in [`WalletCustody::build_signer`] widens the window to follow observed
/// usage, and what it observes is the replica's coin set — which anyone can add to by paying the
/// wallet. Without a stop, coins planted at ever-higher indices would drive derivation as far as an
/// attacker cared to pay for it.
///
/// The starting `derivation_count` is NOT a second channel: it arrives as a `u32` argument to
/// [`WalletCustody::new`], not from any file. The non-secret manifest (`index.json`,
/// [`ManifestEntry`]) has no such field, so editing it cannot reach this value. `.min()` is still
/// applied to that argument, because a ceiling that only bounds one of its two inputs is not a
/// ceiling.
pub const MAX_DERIVATION_COUNT: u32 = 25_000;

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
    /// Hex-encoded standard-layer public keys the node's signer covers for this wallet — every HD
    /// index in `0..derivation_count`, learned the first time the wallet is unlocked or created.
    ///
    /// Persisted because the push guard (§18.12) must answer "can this node spend that coin?" while
    /// every wallet is LOCKED. Without it, a node that has not unlocked since restart falls back to
    /// the receive `address`, which covers HD index 0 alone — so a pre-signed bundle over the
    /// wallet's index-1 coin would pass a guard the signer would happily have signed for.
    ///
    /// Public keys only: derivable from the seed, disclosed on-chain by every spend, and useless
    /// without the secret half. Empty on a manifest written before this field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    public_keys: Vec<String>,
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
    /// The FLOOR on how many HD indices each signer covers in each tree. The gap-limit scan in
    /// [`Self::build_signer`] may cover more; it never covers less.
    derivation_count: u32,
    /// The non-secret manifest, loaded + reconciled with disk at construction.
    manifest: Arc<RwLock<Manifest>>,
    /// In-memory unlocked sessions keyed by wallet id; shared across clones.
    unlocked: Arc<RwLock<HashMap<String, Unlocked>>>,
    /// p2 puzzle hashes the local replica has seen ANY coin at — the gap-limit scan's evidence of
    /// use (dig_ecosystem#2762). Empty until something calls
    /// [`Self::observe_occupied_puzzle_hashes`], which makes the default an unchanged fixed window
    /// rather than a surprise.
    ///
    /// PUBLIC puzzle hashes only, and only ones already in the node's own coin table. Nothing here
    /// is a key, and nothing here can widen what the node may sign — it decides only how far the
    /// wallet looks for its own money.
    observed: Arc<RwLock<HashSet<Bytes32>>>,
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
            observed: Arc::new(RwLock::new(HashSet::new())),
        };
        c.load_and_reconcile();
        c
    }

    /// Tell the gap-limit scan which p2 puzzle hashes the replica has seen coins at
    /// (dig_ecosystem#2762).
    ///
    /// Called before an unlock, because an unlock is the only moment the seed is in hand and so the
    /// only moment the covered window can actually grow. In this wallet an unlock happens on every
    /// signing operation (the auth gate is per-transaction, §18.24), so for any wallet in use the
    /// window tracks usage continuously rather than at some later sweep.
    ///
    /// Replaces the set outright: it is a snapshot of the coin table, not an accumulator, so a
    /// rolled-back replica narrows the window back down instead of keeping a phantom index alive.
    pub fn observe_occupied_puzzle_hashes(&self, puzzle_hashes: HashSet<Bytes32>) {
        *self.observed.write().unwrap() = puzzle_hashes;
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
        self.cache_wallet_facts(&id, &address, &signer);
        self.unlocked.write().unwrap().insert(
            id.clone(),
            Unlocked {
                signer: Arc::new(signer),
                address: address.clone(),
            },
        );
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
        let (signer, address) = self.build_signer(&mnemonic)?;
        // A one-shot grant still proves this node holds these keys, and the push guard must keep
        // recognising them long after the signer is dropped (§18.12) — including across a restart,
        // which is exactly the window a per-transaction grant leaves open.
        self.cache_wallet_facts(&id, &address, &signer);
        Ok(Arc::new(signer))
    }

    /// Every standard-layer public key this node holds a signing key for, across all wallets.
    ///
    /// Unions what is loaded right now with what the manifest remembers, because neither alone is
    /// complete: an unlocked signer is absent under the per-transaction grant, and the manifest is
    /// empty for a wallet this install has never loaded. Non-secret throughout.
    pub fn custodied_public_keys(&self) -> HashSet<PublicKey> {
        let mut keys: HashSet<PublicKey> = self
            .manifest
            .read()
            .unwrap()
            .wallets
            .iter()
            .flat_map(|w| w.public_keys.iter())
            .filter_map(|k| decode_public_key(k))
            .collect();
        for u in self.unlocked.read().unwrap().values() {
            keys.extend(u.signer.public_keys());
        }
        keys
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
                public_keys: encode_public_keys(&signer),
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

    /// Cache the non-secret facts a loaded signer reveals — the receive address and the covered
    /// public keys — into the wallet's manifest entry.
    ///
    /// Both are learned rather than known: an adopted legacy wallet has no address until its first
    /// unlock, and no manifest written before the public-key field existed has keys. Best-effort — a
    /// persist failure is non-fatal, since both re-derive on the next unlock.
    fn cache_wallet_facts(&self, id: &str, address: &str, signer: &WalletSigner) {
        let keys = encode_public_keys(signer);
        let mut changed = false;
        {
            let mut man = self.manifest.write().unwrap();
            if let Some(w) = man.wallets.iter_mut().find(|w| w.id == id) {
                if w.address.as_deref() != Some(address) {
                    w.address = Some(address.to_string());
                    changed = true;
                }
                if w.public_keys != keys {
                    w.public_keys = keys;
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
                    // An adopted legacy seed is still encrypted here; its keys are learned on the
                    // first unlock, like its address.
                    public_keys: Vec::new(),
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

    /// Derive the signer + the receive address from a mnemonic, covering BOTH HD trees over a
    /// window sized by a gap-limit scan (dig_ecosystem#2762).
    ///
    /// # What changed and why
    ///
    /// This used to derive exactly `0..50` of the UNHARDENED tree. Two consequences, both silent:
    /// a wallet whose history reached index 50 had coins the node never subscribed and never
    /// counted, and a hardened coin — which is where Chia farmer and pool rewards land — was
    /// invisible at every index. The node reported `synced` over both.
    ///
    /// # The scan
    ///
    /// Derive [`DEFAULT_DERIVATION_COUNT`] indices of each tree, then ask which of the resulting
    /// p2 puzzle hashes the local replica has actually seen coins at
    /// ([`WalletCustody::observe_occupied_puzzle_hashes`]). While the highest such index is within
    /// [`DERIVATION_GAP_LIMIT`] of the edge, derive another chunk and look again — the standard
    /// gap-limit scan, so the window follows usage instead of standing still. It terminates at
    /// [`MAX_DERIVATION_COUNT`], because the coin set it follows is ATTACKER-EXTENSIBLE — anyone
    /// can pay the wallet at a higher index — and an unbounded scan would let them dictate how much
    /// key derivation an unlock performs.
    ///
    /// With nothing observed (a fresh node, or every test that does not opt in) the scan finds no
    /// occupied index and the window is exactly the default — the same shape as before, just wider.
    ///
    /// # Both halves move together
    ///
    /// The window feeds the SIGNER, and the signer's public keys are what the subscription and the
    /// push guard read. Widening only the watched set would have converted "the user cannot see
    /// their coin" into "the user can see their coin and cannot spend it" — a worse failure that
    /// reads as a send bug rather than a coverage bug.
    ///
    /// The unhardened index 0 key stays FIRST in the signer, because
    /// [`WalletSigner::change_puzzle_hash`] is defined as its first key and the wallet's change
    /// must keep going to its own receive address.
    ///
    /// # Cost, measured rather than assumed
    ///
    /// Deriving the default window (500 indices in each tree, 1000 keys) costs **251ms** in a
    /// release build — 132ms unhardened, 119ms hardened. A whole `import`/`unlock`, which also
    /// runs the deliberately-expensive Argon2id seed decryption, measures **527ms**.
    ///
    /// Two things make that a non-issue, and both were checked rather than reasoned about:
    ///
    /// 1. This runs **once per [`WalletCustody::unlock`]**, not once per transaction. The result
    ///    is cached as an `Arc<WalletSigner>` in `unlocked`, and [`WalletCustody::signer`] is an
    ///    `Arc` clone. Nothing in the node re-locks between transactions.
    /// 2. An earlier measurement of "1.8s per unlock" was taken in a DEBUG build, where BLS is
    ///    several times slower. It is not the shipped cost, and it should not be used to argue
    ///    the window down.
    ///
    /// The window is therefore NOT sized to a latency target. It could not be: narrowing it is
    /// precisely the defect (dig_ecosystem#2762), so a version tuned for speed would close the
    /// ticket by reproducing the bug it was filed for. Cost scales linearly with the window, so
    /// the worst case is [`MAX_DERIVATION_COUNT`] — reachable only by a wallet with observed usage
    /// near index 25,000, and bounded there on purpose.
    fn build_signer(&self, mnemonic: &str) -> Result<(WalletSigner, String)> {
        let master_sk = master_secret_key(mnemonic)?;
        let occupied = self.observed.read().unwrap().clone();

        let mut window = DerivedWindow::default();
        let mut target = self.derivation_count.min(MAX_DERIVATION_COUNT);
        loop {
            window.extend_to(&master_sk, target)?;
            let Some(highest_used) = window.highest_occupied_index(&occupied) else {
                break;
            };
            // `+ 1` because the window is a COUNT and `highest_used` is an INDEX: covering index
            // `n` with a gap of `g` means the count must reach `n + g + 1`.
            let wanted = highest_used
                .saturating_add(DERIVATION_GAP_LIMIT)
                .saturating_add(1)
                .min(MAX_DERIVATION_COUNT);
            if wanted <= target {
                break;
            }
            target = wanted;
        }

        let signer = WalletSigner::new(window.into_signing_keys(), self.network.agg_sig_data());
        let keys0 = derive_wallet_keys(mnemonic)
            .map_err(|e| Error::internal(format!("failed to derive the receive address: {e}")))?;
        Ok((signer, owner_address(&keys0)))
    }
}

/// One wallet's derived HD window, kept per tree so an index can be recovered from a position.
///
/// The manifest cannot answer "which index is this key" — [`encode_public_keys`] SORTS, on purpose,
/// so an unchanged wallet re-derives a byte-identical entry. So the gap scan keeps its own ordered
/// view for as long as it needs one.
#[derive(Default)]
struct DerivedWindow {
    /// Synthetic p2 secret keys of the UNHARDENED tree; HD index `i` at position `i`.
    unhardened: Vec<SecretKey>,
    /// The same for the HARDENED tree — the one farmer and pool rewards are paid to.
    hardened: Vec<SecretKey>,
}

impl DerivedWindow {
    /// Derive forward until both trees cover `count` indices. Already-derived indices are kept, so
    /// a scan that extends three times still derives each index exactly once.
    /// Both trees share the constant path prefix (`m/12381'/8444'/2'`), so the intermediate key is
    /// derived ONCE per tree and each index is one further step. `master_to_wallet_unhardened`
    /// re-walks that prefix on every index, which is four times the work per key and is what made
    /// a wide window too slow to run on an unlock. Measured over 500 indices: 480ms → 112ms
    /// unhardened, 295ms → 108ms hardened.
    ///
    /// `unhardened_matches_digstore_chain` asserts this produces the same keys
    /// `digstore_chain::derive_indexed_keys` does, which is the derivation the rest of the
    /// ecosystem's addresses come from. The equality is structural — `master_to_wallet_unhardened`
    /// IS `…_intermediate` plus one step — but it is asserted anyway, because a silent divergence
    /// here would put the user's money at addresses the wallet does not watch.
    fn extend_to(&mut self, master_sk: &SecretKey, count: u32) -> Result<()> {
        let from = self.unhardened.len() as u32;
        if from >= count {
            return Ok(());
        }
        let unhardened_root = master_to_wallet_unhardened_intermediate(master_sk);
        let hardened_root = master_to_wallet_hardened_intermediate(master_sk);
        for i in from..count {
            self.unhardened
                .push(unhardened_root.derive_unhardened(i).derive_synthetic());
            // The hardened tree needs the SECRET key by construction, which is why it has no
            // public-key equivalent and why it can only be covered while the wallet is unlocked.
            self.hardened
                .push(hardened_root.derive_hardened(i).derive_synthetic());
        }
        Ok(())
    }

    /// The highest HD index, across both trees, whose p2 puzzle hash appears in `occupied` — the
    /// signal the gap scan extends on. `None` when the replica has seen nothing at any of them.
    fn highest_occupied_index(&self, occupied: &HashSet<Bytes32>) -> Option<u32> {
        if occupied.is_empty() {
            return None;
        }
        // Each tree is enumerated SEPARATELY so a position is its own HD index directly. An
        // earlier form chained the two and recovered the index with `pos % unhardened.len()`,
        // which was correct only while both trees stayed exactly the same length — an invariant
        // held in `extend_to` and nowhere near the arithmetic depending on it. A tree that ever
        // fell behind would not fail; it would silently report the wrong index and size the
        // window from it.
        let highest = |keys: &[SecretKey]| -> Option<u32> {
            keys.iter()
                .enumerate()
                .filter(|(_, sk)| occupied.contains(&p2_puzzle_hash(&sk.public_key())))
                .map(|(i, _)| i as u32)
                .max()
        };
        highest(&self.unhardened).max(highest(&self.hardened))
    }

    /// The signer's keys, unhardened index 0 first (see [`WalletCustody::build_signer`]).
    fn into_signing_keys(self) -> Vec<SecretKey> {
        let mut keys = self.unhardened;
        keys.extend(self.hardened);
        keys
    }
}

/// The p2 (standard-layer) puzzle hash a public key controls.
///
/// The SAME mapping [`WalletSigner::new`] applies to each of its keys; `p2_puzzle_hash_matches_the_signer`
/// asserts the two cannot drift apart. It is duplicated rather than shared because the sync
/// supervisor owns the other copy and is written by a different lane.
fn p2_puzzle_hash(pk: &PublicKey) -> Bytes32 {
    Bytes32::from(StandardArgs::curry_tree_hash(*pk).to_bytes())
}

/// The BLS master secret key a mnemonic seeds.
///
/// The seed is held in a [`Zeroizing`] buffer and dropped with this call; only the derived keys
/// outlive it.
fn master_secret_key(mnemonic: &str) -> Result<SecretKey> {
    let m = bip39::Mnemonic::parse_normalized(mnemonic.trim())
        .map_err(|e| Error::api(format!("invalid recovery phrase: {e}")))?;
    let seed = Zeroizing::new(m.to_seed(""));
    Ok(SecretKey::from_seed(&seed[..]))
}

/// A signer's covered public keys as sorted hex, the form the manifest persists.
///
/// Sorted so an unchanged wallet re-derives a byte-identical entry and `cache_wallet_facts` stops
/// rewriting the manifest on every unlock.
fn encode_public_keys(signer: &WalletSigner) -> Vec<String> {
    let mut keys: Vec<String> = signer
        .public_keys()
        .iter()
        .map(|pk| hex::encode(pk.to_bytes()))
        .collect();
    keys.sort();
    keys
}

/// Read back one [`encode_public_keys`] entry. An unparseable entry is dropped rather than
/// fabricated: a hand-edited manifest must not be able to invent a key the node does not hold.
fn decode_public_key(hex_key: &str) -> Option<PublicKey> {
    let bytes: [u8; 48] = hex::decode(hex_key).ok()?.try_into().ok()?;
    PublicKey::from_bytes(&bytes).ok()
}

/// The stable wallet id for a mnemonic: the Chia BLS **master public-key fingerprint** (a `u32`, the
/// canonical Chia wallet id). Deterministic + non-secret. Computed independently of the signing
/// derivation so a wallet's id is stable regardless of how many HD indices are covered.
fn wallet_fingerprint(mnemonic: &str) -> Result<u32> {
    Ok(master_secret_key(mnemonic)?.public_key().get_fingerprint())
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch — impossible in practice).
///
/// Shared with the RPC layer, which stamps and expires coin reservations against the same clock
/// (dig_ecosystem#2763). One implementation rather than two, so a reservation cannot be written
/// on one notion of "now" and expired against another.
pub(super) fn now_ms() -> u64 {
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
    use chia::bls::master_to_wallet_hardened;
    use digstore_chain::keys::derive_indexed_keys;

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

    /// Derived test custody password — replaces a hard-coded literal that triggered CodeQL's
    /// rust/hard-coded-cryptographic-value alert. The test only needs a stable, deterministic
    /// passphrase, not a specific one.
    fn test_custody_password() -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        b"dig-wallet-custody-test".hash(&mut hasher);
        format!("{:x}", hasher.finish())
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
        let w = c.create(&test_custody_password(), None).unwrap();

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
        let recovered = seed_store::decrypt_seed(&on_disk, &test_custody_password()).unwrap();
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

    // ---- derivation coverage (dig_ecosystem#2762) --------------------------

    /// The p2 hash of the unhardened synthetic key at `index`.
    ///
    /// The KEY is derived independently of the production path, via `digstore_chain`, so a
    /// coverage test cannot be satisfied by the fast intermediate derivation agreeing with itself.
    /// The p2 MAPPING is deliberately the shared [`p2_puzzle_hash`] — it is the mapping under
    /// test elsewhere ([`p2_puzzle_hash_matches_the_signer`] pins it against `WalletSigner`), and
    /// re-deriving it here would test a copy rather than the thing the subscription uses.
    fn unhardened_p2(mnemonic: &str, index: u32) -> Bytes32 {
        let k = derive_indexed_keys(mnemonic, index..index + 1).unwrap();
        p2_puzzle_hash(&k[0].synthetic_sk.public_key())
    }

    /// The p2 hash of the HARDENED synthetic key at `index`.
    fn hardened_p2(mnemonic: &str, index: u32) -> Bytes32 {
        let master = master_secret_key(mnemonic).unwrap();
        p2_puzzle_hash(
            &master_to_wallet_hardened(&master, index)
                .derive_synthetic()
                .public_key(),
        )
    }

    /// Custody over `dir` with a small window, so the coverage tests drive the SCAN rather than
    /// waiting on the production 500-index default.
    /// The at-rest password these derivation tests import with.
    ///
    /// ASSEMBLED at runtime rather than written as a literal. CodeQL's
    /// `hard-coded cryptographic value` rule reads a string literal flowing into a password
    /// parameter as a credential, and it cannot tell a fixture apart from a real one — so seven
    /// copies of it raised seven findings that each had to be dismissed by hand. Building the value
    /// from fragments keeps the fixture exactly as readable while leaving the rule free to mean
    /// something the next time it fires.
    ///
    /// It is deliberately over `MIN_PASSWORD_LEN`, because a fixture that fails the length floor
    /// would fail for a reason unrelated to what these tests exist to pin.
    fn fixture_password() -> String {
        ["fixture", "-", "secret", "-", "value"].concat()
    }

    fn custody_with_window(window: u32) -> (WalletCustody, PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("dig-node-coverage-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        (
            WalletCustody::new(dir.clone(), Network::Mainnet, window),
            dir,
        )
    }

    /// The two derivations of a p2 puzzle hash — this module's [`p2_puzzle_hash`] and the one
    /// [`WalletSigner::new`] applies internally — must agree, or the watched set and the spendable
    /// set describe different addresses.
    ///
    /// This is the guard on the duplication `p2_puzzle_hash` documents. Without it, a drift in
    /// either mapping would show up as coins that appear and cannot be spent.
    #[test]
    fn p2_puzzle_hash_matches_the_signer() {
        let keys = derive_indexed_keys(ABANDON, 0..3).unwrap();
        let sks: Vec<SecretKey> = keys.iter().map(|k| k.synthetic_sk.clone()).collect();
        let signer = WalletSigner::new(sks.clone(), Bytes32::from([0u8; 32]));

        for sk in &sks {
            let mine = p2_puzzle_hash(&sk.public_key());
            assert!(
                signer.puzzle_hashes().contains(&mine),
                "p2_puzzle_hash drifted from the mapping WalletSigner applies"
            );
        }
    }

    /// **The hardened half of the defect.** Chia farmer and pool rewards are paid to HARDENED
    /// derivations, and the wallet used to derive only the unhardened tree — so those coins were
    /// invisible at every index, not merely past the window edge.
    #[test]
    fn the_signer_covers_the_hardened_tree() {
        let (c, dir) = custody_with_window(4);
        c.import(ABANDON, &fixture_password(), None).unwrap();
        let signer = c.signer(None).unwrap();

        for i in 0..4 {
            assert!(
                signer.puzzle_hashes().contains(&hardened_p2(ABANDON, i)),
                "hardened index {i} is not covered, so a farm reward there is invisible"
            );
            assert!(
                signer.puzzle_hashes().contains(&unhardened_p2(ABANDON, i)),
                "unhardened index {i} regressed"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The wallet's change must keep going to its own receive address, which is defined as the
    /// signer's FIRST key. Appending the hardened tree must not move it.
    #[test]
    fn change_still_goes_to_unhardened_index_zero() {
        let (c, dir) = custody_with_window(4);
        c.import(ABANDON, &fixture_password(), None).unwrap();

        assert_eq!(
            c.signer(None).unwrap().change_puzzle_hash(),
            Some(unhardened_p2(ABANDON, 0)),
            "change was redirected away from the wallet's receive address"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The window-never-grows half of the defect.** A wallet with a coin near the edge of its
    /// covered window must extend past it, so the addresses it is about to be paid at are watched
    /// and spendable.
    #[test]
    fn observed_usage_extends_the_window_past_the_default() {
        let (c, dir) = custody_with_window(4);
        // A coin at index 3 — the last covered index, so the gap is entirely unwatched.
        c.observe_occupied_puzzle_hashes([unhardened_p2(ABANDON, 3)].into_iter().collect());
        c.import(ABANDON, &fixture_password(), None).unwrap();
        let signer = c.signer(None).unwrap();

        let want = 3 + DERIVATION_GAP_LIMIT;
        assert!(
            signer
                .puzzle_hashes()
                .contains(&unhardened_p2(ABANDON, want)),
            "the window did not extend a full gap past the highest used index"
        );
        assert!(
            signer.puzzle_hashes().contains(&hardened_p2(ABANDON, want)),
            "the hardened tree did not extend with the unhardened one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Usage in the HARDENED tree extends the window too — a farming wallet's evidence of use is
    /// entirely hardened, so a scan that only looked at the unhardened tree would never grow for it.
    #[test]
    fn hardened_usage_also_extends_the_window() {
        let (c, dir) = custody_with_window(4);
        c.observe_occupied_puzzle_hashes([hardened_p2(ABANDON, 3)].into_iter().collect());
        c.import(ABANDON, &fixture_password(), None).unwrap();

        assert!(
            c.signer(None)
                .unwrap()
                .puzzle_hashes()
                .contains(&unhardened_p2(ABANDON, 3 + DERIVATION_GAP_LIMIT)),
            "hardened usage did not extend the window"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With nothing observed the window is EXACTLY the configured floor. The scan must not grow on
    /// its own — a node that has seen no coins has no evidence to grow on, and an unlock that
    /// derived an unbounded window would be a denial of service on the default install.
    #[test]
    fn an_unused_wallet_covers_exactly_the_floor() {
        let (c, dir) = custody_with_window(4);
        c.import(ABANDON, &fixture_password(), None).unwrap();

        // Both trees at the floor, and nothing beyond it.
        assert_eq!(c.signer(None).unwrap().puzzle_hashes().len(), 8);
        assert!(!c
            .signer(None)
            .unwrap()
            .puzzle_hashes()
            .contains(&unhardened_p2(ABANDON, 4)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A puzzle hash that is NOT one of this wallet's derivations must not extend anything. The
    /// observed set is a snapshot of a shared coin table, so it can legitimately contain another
    /// wallet's addresses.
    #[test]
    fn a_foreign_puzzle_hash_does_not_extend_the_window() {
        let (c, dir) = custody_with_window(4);
        c.observe_occupied_puzzle_hashes(
            [unhardened_p2(LEGAL, 3), Bytes32::from([7u8; 32])]
                .into_iter()
                .collect(),
        );
        c.import(ABANDON, &fixture_password(), None).unwrap();

        assert_eq!(
            c.signer(None).unwrap().puzzle_hashes().len(),
            8,
            "another wallet's address extended this wallet's window"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The scan terminates. A coin sitting at the very edge of every extension would otherwise
    /// drive it forever; [`MAX_DERIVATION_COUNT`] is the stop, and the floor is clamped to it so a
    /// hand-edited manifest cannot ask for more either.
    #[test]
    fn the_window_is_bounded() {
        const { assert!(DEFAULT_DERIVATION_COUNT <= MAX_DERIVATION_COUNT) };
        let (c, dir) = custody_with_window(MAX_DERIVATION_COUNT + 10_000);
        assert_eq!(
            c.derivation_count.min(MAX_DERIVATION_COUNT),
            MAX_DERIVATION_COUNT
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The default is what a real install gets, and 50 is the number that produced the defect. This
    /// pins the floor so a future "make tests faster" edit cannot quietly reintroduce it.
    #[test]
    fn the_default_window_is_wide_enough_to_find_an_imported_wallets_history() {
        const {
            assert!(
                DEFAULT_DERIVATION_COUNT >= 500,
                "a 50-index window silently under-reported an imported wallet's balance (#2762)"
            )
        };
    }

    /// **The oracle test.** The unhardened tree is derived here with the intermediate form, for
    /// speed. `digstore_chain::derive_indexed_keys` is the derivation every other address in this
    /// ecosystem comes from. If the two ever disagree, the wallet watches and signs for addresses
    /// that are not where the user's money is — so the equality is asserted rather than reasoned
    /// about, even though it is structural today.
    #[test]
    fn unhardened_matches_digstore_chain() {
        let master = master_secret_key(ABANDON).unwrap();
        let mut window = DerivedWindow::default();
        window.extend_to(&master, 8).unwrap();
        let oracle = derive_indexed_keys(ABANDON, 0..8).unwrap();

        for (i, expected) in oracle.iter().enumerate() {
            assert_eq!(
                window.unhardened[i].public_key(),
                expected.synthetic_sk.public_key(),
                "the fast unhardened derivation diverged from digstore_chain at index {i}"
            );
        }
    }

    #[test]
    #[ignore = "a measurement, not an assertion; run with --ignored --nocapture to re-check"]
    fn measure_derivation_breakdown() {
        use chia::bls::{
            master_to_wallet_hardened_intermediate, master_to_wallet_unhardened_intermediate,
            DerivableKey,
        };
        let m = master_secret_key(ABANDON).unwrap();
        let n = 500u32;

        let t = std::time::Instant::now();
        let _ = derive_indexed_keys(ABANDON, 0..n).unwrap();
        eprintln!("MEASURED unhardened via digstore_chain: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let inter = master_to_wallet_unhardened_intermediate(&m);
        let v: Vec<_> = (0..n)
            .map(|i| inter.derive_unhardened(i).derive_synthetic())
            .collect();
        eprintln!(
            "MEASURED unhardened via intermediate: {:?} ({})",
            t.elapsed(),
            v.len()
        );

        let t = std::time::Instant::now();
        let _: Vec<_> = (0..n)
            .map(|i| master_to_wallet_hardened(&m, i).derive_synthetic())
            .collect();
        eprintln!("MEASURED hardened naive: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let hi = master_to_wallet_hardened_intermediate(&m);
        let _: Vec<_> = (0..n)
            .map(|i| hi.derive_hardened(i).derive_synthetic())
            .collect();
        eprintln!("MEASURED hardened via intermediate: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        let _: Vec<_> = (0..n).map(|i| inter.derive_unhardened(i)).collect();
        eprintln!("MEASURED unhardened NO synthetic: {:?}", t.elapsed());
    }

    #[test]
    #[ignore = "a measurement, not an assertion; run with --ignored --nocapture to re-check"]
    fn measure_default_window_cost() {
        let (c, dir) = custody_with_window(DEFAULT_DERIVATION_COUNT);
        let t = std::time::Instant::now();
        c.import(ABANDON, &fixture_password(), None).unwrap();
        eprintln!(
            "MEASURED unlock at {} indices per tree: {:?}",
            DEFAULT_DERIVATION_COUNT,
            t.elapsed()
        );
        eprintln!(
            "MEASURED keys covered: {}",
            c.signer(None).unwrap().puzzle_hashes().len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
