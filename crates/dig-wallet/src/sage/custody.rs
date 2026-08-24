//! The node's read-only view of any wallet seed it still holds at rest (SPEC §18.20a).
//!
//! # This module no longer custodies user keys
//!
//! It used to. The node once generated, imported, unlocked and SIGNED with a user's BIP-39 seed on
//! their behalf. The #1500 ratification (2026-07-22T03:27:48Z) settled that it must not: the user's
//! spend key lives in the user application, and `dig-account`'s `PolicyAuthorizer` is the only
//! enforcing custody gate. `dig_ecosystem#1701` froze that surface, measured the affected
//! population at **zero**, and then removed it — this module is what is left.
//!
//! What is left reads ONE non-secret file, `<config_dir>/wallets/index.json`, and answers two
//! questions for the chain-sync supervisor:
//!
//! - [`WalletCustody::any_wallet`] — is a wallet enrolled on this device at all? The supervisor
//!   needs this to tell "no wallet, nothing to follow" (the honest all-clear) apart from "a wallet
//!   is enrolled and its addresses are unreachable", which look identical from an empty address set
//!   (dig_ecosystem#2609).
//! - [`WalletCustody::custodied_public_keys`] — the wallet's on-chain-PUBLIC standard-layer keys,
//!   which become the addresses the supervisor subscribes and which the push guard checks a
//!   pre-signed bundle against (§18.12).
//!
//! # There is no longer a path from HERE to a private key
//!
//! No method in this module, or anywhere in [`crate::sage`], reads a `.seed` file, decrypts one,
//! derives a secret key, or builds a [`super::spend::WalletSigner`] from user material. The
//! Sage-parity plane cannot sign on a user's behalf because it can no longer obtain the material.
//!
//! The at-rest primitive those methods used, [`crate::seed_store`], survives for ONE caller:
//! [`crate::autoseed`], the node's own `DIGOP1`/`DIGVK1` OPERATOR identity, which no ratification
//! retires. That identity is the node's own machine credential, not a user's custody, and deleting
//! it would break the node's auth rather than tighten it.
//!
//! The rival implementation this module used to name — [`crate::lib`]'s self-origin wallet UI, which
//! sealed and opened a USER seed and signed with it — is GONE (dig-node#327). Its removal needed a
//! separate population count because the zero the #1701 freeze measured ranged over the custody
//! manifest and not over `seed_path()`; that count was taken, and the surface was removed. **§908 is
//! now satisfied on both planes.** `seed_store::encrypt_seed` is `#[cfg(test)]` as a result, so no
//! production code in this crate can seal a user seed at all.
//!
//! A seed a previous build already wrote stays recoverable offline via `dign wallet export-seed`
//! ([`crate::seed_export`]), which is why removing the surface strands nobody.
//!
//! # Back-compatibility, and why it is nearly moot
//!
//! A pre-existing install's manifest and `.seed` files are still read and reconciled, so an old
//! layout is described honestly rather than ignored. Nothing can ADD to it: with the provisioning
//! path gone, the enrolled set can only shrink. The measured population of such installs is zero,
//! so in practice every node answers "no wallet" — which is exactly what §908 says it should.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chia::bls::PublicKey;

use super::{Error, Result};

/// The reserved id of the LEGACY single wallet (`<config_dir>/wallet-seed.bin`, the #370
/// pre-multi-wallet layout), adopted into the manifest so an old install is described accurately.
const LEGACY_ID: &str = "default";
/// The subdirectory (under the node config dir) that holds the per-wallet seeds + the manifest.
const WALLETS_SUBDIR: &str = "wallets";
/// The non-secret manifest filename inside [`WALLETS_SUBDIR`].
const MANIFEST_FILE: &str = "index.json";
/// The legacy single-seed filename (the #370 layout), directly under the node config dir.
const LEGACY_SEED_FILE: &str = "wallet-seed.bin";

/// Whether a wallet is enrolled on this device.
///
/// There is no `Unlocked` variant. Unlocking a wallet meant decrypting its seed into a resident
/// signer, and that path is gone (dig_ecosystem#1701) — so an enrolled wallet is permanently
/// `Locked`, and a variant for the other state would report something no code can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CustodyState {
    /// No wallet on this device (the addressed wallet does not exist / there are no wallets).
    None,
    /// An encrypted seed is on disk. The node cannot open it and cannot sign with it.
    Locked,
}

/// The custody status of the addressed (default: active) wallet.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CustodyStatus {
    /// The enrolment state.
    pub state: CustodyState,
    /// The wallet's receive address (`xch1…`), when the manifest recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The addressed wallet's id, when a wallet was addressed (absent for the `none` state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Whether the addressed wallet is the active one (absent for the `none` state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

/// A per-wallet enumeration entry ([`WalletCustody::list`]). NON-SECRET only.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WalletInfo {
    /// The stable wallet id (its BLS master public-key fingerprint, or `default` for a legacy seed).
    pub id: String,
    /// The receive address, when the manifest recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The optional human label recorded when the wallet was enrolled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The enrolment state.
    pub state: CustodyState,
    /// Whether this is the active wallet.
    pub active: bool,
}

/// A non-secret manifest entry (persisted in `index.json`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct ManifestEntry {
    /// The stable wallet id.
    id: String,
    /// The receive address (`xch1…`) when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    /// An optional human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    /// Creation (or adoption) timestamp, ms since the Unix epoch.
    #[serde(default)]
    created_ms: u64,
    /// Hex-encoded standard-layer PUBLIC keys this wallet covers.
    ///
    /// The subscription set the chain-sync supervisor follows, and what the push guard (§18.12)
    /// checks a pre-signed bundle against — both of which must work while the node holds no key at
    /// all, which is why the keys are persisted here rather than derived on demand.
    ///
    /// Public keys only: disclosed on-chain by every spend and useless without the secret half.
    /// Empty for a wallet whose keys this install never learned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    public_keys: Vec<String>,
}

/// The non-secret wallet manifest (`<config_dir>/wallets/index.json`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Manifest {
    /// The active wallet's id, or `None` when no wallet is enrolled.
    #[serde(default)]
    active: Option<String>,
    /// Every enrolled wallet (non-secret metadata only).
    #[serde(default)]
    wallets: Vec<ManifestEntry>,
}

/// The node's read-only view of its enrolled wallets. Cheap to `clone` — the manifest is shared
/// behind an `Arc`, so every handle answers from one reconciled view.
#[derive(Clone)]
pub struct WalletCustody {
    /// The node config directory (holds `wallets/` and the legacy `wallet-seed.bin`).
    config_dir: PathBuf,
    /// The non-secret manifest, loaded + reconciled with disk at construction.
    manifest: Arc<RwLock<Manifest>>,
}

impl WalletCustody {
    /// Open the wallet manifest under `config_dir` (the node config directory), reconciling it with
    /// the seed files actually present.
    pub fn open(config_dir: PathBuf) -> Self {
        let c = Self {
            config_dir,
            manifest: Arc::new(RwLock::new(Manifest::default())),
        };
        c.load_and_reconcile();
        c
    }

    /// Whether ANY wallet is enrolled on this device.
    pub fn any_wallet(&self) -> bool {
        !self.manifest.read().unwrap().wallets.is_empty()
    }

    /// Enumerate every enrolled wallet (NON-SECRET metadata only).
    pub fn list(&self) -> Vec<WalletInfo> {
        let man = self.manifest.read().unwrap();
        man.wallets
            .iter()
            .map(|w| WalletInfo {
                id: w.id.clone(),
                address: w.address.clone(),
                label: w.label.clone(),
                state: CustodyState::Locked,
                active: man.active.as_deref() == Some(w.id.as_str()),
            })
            .collect()
    }

    /// The state (+ address/id/active) of the addressed wallet (default: the active wallet).
    /// Reports `none` when the addressed wallet does not exist / there are no wallets.
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
        CustodyStatus {
            address: self.manifest_address(&id),
            state: CustodyState::Locked,
            id: Some(id),
            active: Some(active),
        }
    }

    /// Every standard-layer PUBLIC key this device's enrolled wallets cover.
    ///
    /// Read from the manifest, so it is answerable while the node holds no key — which is the only
    /// state it is ever in now. Empty for a wallet whose keys this install never learned, and empty
    /// on a node with no wallet, which is the ordinary §908 case.
    pub fn custodied_public_keys(&self) -> HashSet<PublicKey> {
        self.manifest
            .read()
            .unwrap()
            .wallets
            .iter()
            .flat_map(|w| w.public_keys.iter())
            .filter_map(|k| decode_public_key(k))
            .collect()
    }

    // ---- internals --------------------------------------------------------

    /// Resolve an optional caller-supplied id to a concrete wallet id: the given id when it exists,
    /// else the active wallet, else (when exactly one wallet exists) that wallet. Errors when no
    /// matching wallet is enrolled.
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

    /// The `wallets/` directory under the node config dir.
    fn wallets_dir(&self) -> PathBuf {
        self.config_dir.join(WALLETS_SUBDIR)
    }

    /// The manifest path (`wallets/index.json`).
    fn manifest_path(&self) -> PathBuf {
        self.wallets_dir().join(MANIFEST_FILE)
    }

    /// Enrol a wallet on disk from PUBLIC keys alone, reproducing what a pre-#1701 install left
    /// behind. Test fixtures only.
    ///
    /// Takes public keys rather than a mnemonic ON PURPOSE. The production enrolment path is gone
    /// (dig_ecosystem#1701), and a fixture that accepted a seed would hand the test suite the exact
    /// capability this module was stripped of — so a future change could reintroduce custody and
    /// still be tested green.
    ///
    /// Writes the real `<id>.seed` file alongside the real `index.json`, because reconciliation
    /// drops a manifest entry whose seed file is missing. The seed bytes are opaque filler; nothing
    /// left in this crate can read them.
    #[cfg(test)]
    pub(crate) fn enroll_for_tests(config_dir: &Path, id: &str, public_keys: &[PublicKey]) {
        let dir = config_dir.join(WALLETS_SUBDIR);
        std::fs::create_dir_all(&dir).expect("create the wallets dir");
        std::fs::write(dir.join(format!("{id}.seed")), b"opaque-at-rest-blob")
            .expect("write the seed file");
        let manifest = Manifest {
            active: Some(id.to_string()),
            wallets: vec![ManifestEntry {
                id: id.to_string(),
                address: None,
                label: None,
                created_ms: now_ms(),
                public_keys: public_keys
                    .iter()
                    .map(|k| hex::encode(k.to_bytes()))
                    .collect(),
            }],
        };
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).expect("serialize the manifest"),
        )
        .expect("write the manifest");
    }

    /// The legacy single-seed path (`<config_dir>/wallet-seed.bin`).
    fn legacy_seed_path(&self) -> PathBuf {
        self.config_dir.join(LEGACY_SEED_FILE)
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
}

/// Read back one hex-encoded manifest public key. An unparseable entry is dropped rather than
/// fabricated: a hand-edited manifest must not be able to invent a key the node does not hold.
fn decode_public_key(hex_key: &str) -> Option<PublicKey> {
    let bytes: [u8; 48] = hex::decode(hex_key).ok()?.try_into().ok()?;
    PublicKey::from_bytes(&bytes).ok()
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
