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

use chia_bls::PublicKey;

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

/// A disciplined view of [`now_ms`] that cannot advance faster than real time actually elapses.
///
/// dig-node#502/#525/#528 anchor a reservation's lifetime (`RESERVATION_TTL_MS`,
/// `MAX_RESERVATION_HOLD_MS`) entirely on raw wall-clock readings — `submitted_at`/`expires_at`
/// are written from [`now_ms`], and every prune compares them against a fresh [`now_ms`] read.
/// #528 closes the case where the clock is ALREADY wrong at the instant a reservation is first
/// written (a self-contradiction between a row's own two columns). It does not close the general
/// form (dig-node#532): a wall clock that steps FORWARD while a reservation is already
/// live — an NTP step correction, a VM pause/resume, an operator setting the clock — produces no
/// such contradiction (the anchor and the jumped reading are each, in isolation, perfectly
/// ordinary), yet the very next prune reads the jumped clock as "this much time has passed" and
/// can retire a bundle's hold while it is still genuinely in flight. Unlike #528's residual, this
/// has NO bound at all: a clock stepped forward by a day retires every hold in the database on
/// the next read — the #348/#497 double-spend direction, with no ceiling.
///
/// `ClockGovernor` closes it by refusing to let its reported "now" advance faster than a
/// **monotonic** clock says real time has elapsed since the last reading. A wall-clock jump
/// forward is absorbed rather than trusted: the reported value keeps pace with real time and
/// simply runs behind the wall clock until real time genuinely catches up, at which point it
/// resumes tracking the wall clock exactly as before. There is no permanent freeze here — once
/// real elapsed time reaches the jumped value, the clamp stops binding on its own
/// (`the_clamp_releases_itself_once_real_time_catches_up`).
///
/// **The one direction this governor deliberately does NOT correct:** a wall clock that steps
/// BACKWARD is passed straight through, unclamped. That can only make a hold last LONGER than
/// intended, never shorter — the safe direction, and the one #502/#528 already accept elsewhere.
/// A governor that also clamped backward steps would be deciding a hold expired sooner than
/// either clock claims, which is exactly the failure this exists to close.
///
/// Lives for the process's lifetime and is NOT persisted: a restart re-seeds it from whatever the
/// wall clock reads at that moment (`WalletBackend::new`). A clock that is already wrong AT BOOT
/// is therefore unguarded by this governor — that is `now_ms` written directly into a fresh
/// reservation, and #528's write-time contradiction check is what catches it. This governor's job
/// starts the instant after boot: a clock that reads fine at startup and jumps forward LATER, mid
/// process lifetime, mid hold.
pub(super) struct ClockGovernor {
    /// The most recent reading this governor has vouched for.
    disciplined_ms: i64,
    /// The monotonic instant `disciplined_ms` was recorded at, so the NEXT reading is checked
    /// against how much real time a steady clock says has elapsed since then.
    anchor: std::time::Instant,
}

impl ClockGovernor {
    /// Seed the governor with the wall clock's current reading. Called once, at `WalletBackend`
    /// construction — never mid-lifetime, or every re-seed would re-trust whatever the wall clock
    /// says at that moment and defeat the discipline.
    pub(super) fn new(wall_now_ms: i64) -> Self {
        Self {
            disciplined_ms: wall_now_ms,
            anchor: std::time::Instant::now(),
        }
    }

    /// Accept a fresh wall-clock reading and return the disciplined value to use as "now" for
    /// reservation bookkeeping.
    pub(super) fn observe(&mut self, wall_now_ms: i64) -> i64 {
        self.observe_at(wall_now_ms, std::time::Instant::now())
    }

    /// The pure decision, with the monotonic instant taken as an explicit parameter so tests can
    /// construct two readings a known duration apart deterministically — `Instant + Duration` is a
    /// real, valid `Instant`, so this needs no sleep and no fake-clock trait to be exact.
    fn observe_at(&mut self, wall_now_ms: i64, at: std::time::Instant) -> i64 {
        let elapsed_ms: i64 = at
            .saturating_duration_since(self.anchor)
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let ceiling = self.disciplined_ms.saturating_add(elapsed_ms);
        let disciplined = wall_now_ms.min(ceiling);
        self.disciplined_ms = disciplined;
        self.anchor = at;
        disciplined
    }
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
    use std::time::Duration;

    // ---- ClockGovernor (dig-node#532) -------------------------------------
    //
    // Every test below drives `observe_at` with EXPLICIT `Instant` values rather than sleeping —
    // `Instant::now() + Duration` is a real, valid instant a fixed distance from another, so the
    // "real elapsed time" side of the decision is exact and the test is not flaky under load.

    #[test]
    fn a_wall_clock_matching_real_time_passes_through_unclamped() {
        let i0 = std::time::Instant::now();
        let mut gov = ClockGovernor {
            disciplined_ms: 1_000,
            anchor: i0,
        };

        // Five real seconds pass, and the wall clock agrees: it also reads five seconds later.
        let disciplined = gov.observe_at(6_000, i0 + Duration::from_secs(5));

        assert_eq!(
            disciplined, 6_000,
            "a wall clock that agrees with real elapsed time is never clamped"
        );
    }

    #[test]
    fn a_forward_jump_mid_hold_is_clamped_to_real_elapsed_time() {
        let i0 = std::time::Instant::now();
        let mut gov = ClockGovernor {
            disciplined_ms: 1_000,
            anchor: i0,
        };

        // Only 100 real ms pass, but the wall clock jumps forward a full hour (an NTP step, a VM
        // resume, an operator setting the clock) — exactly the case #528's write-time check
        // cannot see, because nothing about the reading itself is self-contradictory.
        let jumped_wall_clock = 1_000 + 3_600_000;
        let disciplined = gov.observe_at(jumped_wall_clock, i0 + Duration::from_millis(100));

        assert_eq!(
            disciplined, 1_100,
            "the jump is absorbed: the disciplined clock advances only by the real 100ms elapsed, \
             never by the hour the wall clock claims"
        );
    }

    #[test]
    fn a_backward_step_passes_through_unclamped() {
        let i0 = std::time::Instant::now();
        let mut gov = ClockGovernor {
            disciplined_ms: 1_000,
            anchor: i0,
        };

        // The wall clock steps BACKWARD to 500 (before the anchor). This governor's one job is
        // closing the EARLY-release direction; a backward step can only extend a hold, so it is
        // let through exactly as #502/#528 already accept elsewhere.
        let disciplined = gov.observe_at(500, i0 + Duration::from_millis(100));

        assert_eq!(
            disciplined, 500,
            "a backward wall-clock step is never clamped -- it can only make a hold last longer"
        );
    }

    #[test]
    fn the_clamp_releases_itself_once_real_time_catches_up() {
        let i0 = std::time::Instant::now();
        let mut gov = ClockGovernor {
            disciplined_ms: 0,
            anchor: i0,
        };

        // The wall clock jumps forward by one hour and then STAYS THERE (a one-time step, not a
        // runaway clock) while real time keeps advancing normally underneath it.
        let jumped = 3_600_000;

        // Immediately after the jump: almost no real time has passed, so the clamp binds hard.
        let d1 = gov.observe_at(jumped, i0 + Duration::from_millis(1));
        assert_eq!(
            d1, 1,
            "right after the jump, real elapsed time still governs"
        );

        // Real time keeps advancing while the wall clock holds steady at `jumped`.
        let d2 = gov.observe_at(jumped, i0 + Duration::from_secs(1800));
        assert_eq!(
            d2, 1_800_000,
            "the disciplined clock keeps tracking REAL elapsed time, still behind the jump"
        );

        // Once real elapsed time actually reaches the jumped value, the clamp stops binding on
        // its own -- no special unfreeze step, no repair to run, unlike #525/#528's lockout.
        let d3 = gov.observe_at(jumped, i0 + Duration::from_millis(3_600_000));
        assert_eq!(
            d3, jumped,
            "once real time catches up to the jumped wall clock, tracking resumes normally"
        );

        // And from here it tracks the wall clock again, exactly as if no jump had ever happened.
        let d4 = gov.observe_at(jumped + 60_000, i0 + Duration::from_millis(3_660_000));
        assert_eq!(
            d4,
            jumped + 60_000,
            "tracking is fully restored after the catch-up"
        );
    }

    // ---- the money property this governor protects ------------------------
    //
    // Built from the REAL `WalletDb` reservation API, not a hand-placed row -- the same shape
    // #528's own regression tests use, and for the same reason: a fixture starting in a state
    // production cannot reach hides the bug it is meant to catch.

    fn coin(id: &str) -> super::super::db::CoinRow {
        super::super::db::CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "ph".into(),
            amount: "100".into(),
            created_height: Some(10),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    fn reservation(
        tx: &str,
        coin_ids: &[&str],
        submitted_at: i64,
        expires_at: i64,
    ) -> super::super::db::PendingTransactionRow {
        super::super::db::PendingTransactionRow {
            transaction_id: tx.into(),
            bundle_hex: format!("bundle-of-{tx}"),
            fee: Some("10".into()),
            submitted_at,
            expires_at,
            attempts: 1,
            reserved_coin_ids: coin_ids.iter().map(|c| (*c).to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn a_forward_clock_jump_mid_hold_no_longer_releases_a_live_reservation_early() {
        let db = super::super::db::WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1")).await.unwrap();

        let ttl = super::super::rpc::RESERVATION_TTL_MS;
        let i0 = std::time::Instant::now();
        let mut gov = ClockGovernor {
            disciplined_ms: 0,
            anchor: i0,
        };

        // The bundle is pushed through the governed clock, at t=0. Real elapsed so far: none.
        let submitted = gov.observe_at(0, i0);
        db.reserve_spend(&reservation("tx1", &["c1"], submitted, submitted + ttl))
            .await
            .unwrap();

        // Two real minutes later, the wall clock is stepped forward by a full TTL's worth of time
        // in one jump (an NTP step) -- comfortably enough, read raw, to look like the reservation
        // has already lapsed, even though only two real minutes have actually passed.
        let raw_jumped_wall_clock = ttl + 1;
        let governed_now = gov.observe_at(raw_jumped_wall_clock, i0 + Duration::from_secs(120));
        assert!(
            governed_now < ttl,
            "the governed reading must stay well short of the reservation's real deadline -- a \
             raw read of {raw_jumped_wall_clock} would already exceed it"
        );

        // Pruning against the DISCIPLINED reading must not retire the still-live reservation.
        db.prune_reservations(governed_now).await.unwrap();
        assert!(
            db.unreserved_unspent_coins(None).await.unwrap().is_empty(),
            "a mid-hold forward clock jump must not release a coin whose bundle may still be \
             genuinely in flight -- the #348/#497 double-spend direction"
        );

        // The coin still returns once its true (governed) deadline is actually reached.
        let past_deadline = gov.observe_at(
            raw_jumped_wall_clock,
            i0 + Duration::from_millis(ttl as u64 + 1),
        );
        db.prune_reservations(past_deadline).await.unwrap();
        assert_eq!(
            db.unreserved_unspent_coins(None)
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.coin_id)
                .collect::<Vec<_>>(),
            vec!["c1".to_string()],
            "the coin is released once real elapsed time actually reaches the reservation's TTL"
        );
    }
}
