//! The externally-registered watch list (dig_ecosystem#2823).
//!
//! # Why this exists
//!
//! On a §908-correct install the user's account lives in **dig-app** and the node custodies no
//! seed at all. [`super::custody::WalletCustody`] therefore contributes ZERO puzzle hashes, the
//! supervisor's subscription set is empty, [`super::sync::initial_sync_with_authority`] refuses to run over it
//! (by design — an un-queried DB marked synced reads a funded wallet as empty), and the replica's
//! peak never advances. The default, correct install is the one that cannot sync.
//!
//! This registry is the other half of the subscription set: a persisted list of **G1 public keys**
//! a client asked the node to FOLLOW. Union it with custody's own set
//! ([`super::sync_supervisor::UnionPuzzleHashSource`]) and a node holding no keys can still watch
//! its user's addresses.
//!
//! # §908
//!
//! A public key is public. Registering one grants the node no signing capability, reveals no seed,
//! and moves no money — it aims the node's chain SUBSCRIPTIONS and nothing else. The identity
//! boundary is untouched: keys travel app → node, never the reverse, and never as secrets.
//!
//! # Privacy, stated rather than accidental
//!
//! Following an address makes it observable to the node's Chia peers that THIS machine cares about
//! it. That is already true of the node's own custodied addresses; registering the app's account
//! extends the same exposure to the app's addresses. `SPEC.md §18.6` states it for the user.
//!
//! # Failure posture
//!
//! Every branch here prefers to fail LOUDLY over following a smaller set than asked, because a
//! too-narrow watch set silently under-reports a balance (dig_ecosystem#2762) — a wrong answer
//! that looks like a working feature. Keys are parsed by the caller, so an undecodable request is
//! refused at the boundary instead of being registered as a subset; an entry that cannot be
//! decoded off disk is reported on stderr rather than dropped in silence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chia_bls::PublicKey;

/// A key this node can be asked to follow: a BLS G1 public key.
///
/// Re-exported under a name that says what the key is FOR, so a caller at the control-plane
/// boundary can speak this API without taking a direct dependency on the BLS crate.
pub type WatchKey = PublicKey;

/// The registry file, under the node config dir.
const WATCHLIST_FILE: &str = "watched-keys.json";

/// The persisted shape: sorted lowercase hex of each 48-byte G1 key.
///
/// Hex rather than a binary blob so an operator can read and audit the file, and sorted so an
/// unchanged registry re-serializes byte-identically and stops rewriting on every no-op call.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct WatchlistFile {
    /// Every registered key, sorted lowercase hex.
    keys: Vec<String>,
}

/// Public keys an external client asked this node to follow.
///
/// Cloning shares the inner state (an `Arc`), matching
/// [`super::custody::WalletCustody`], so a clone handed to the supervisor re-reads registrations
/// made through the RPC handler's clone on each connect attempt. While a session is running with
/// nothing subscribed, a first enrolment is picked up within one
/// [`super::sync_supervisor::PUZZLE_HASH_POLL`]; when addresses are already subscribed, additional
/// enrolments take effect at the next reconnect or restart (dig_ecosystem#2826).
#[derive(Debug, Clone)]
pub struct WatchRegistry {
    path: PathBuf,
    /// Keyed by the key's 48-byte G1 encoding rather than by [`PublicKey`], which is not `Ord`.
    /// The byte order is deterministic, so the persisted file and every read are stably sorted.
    keys: Arc<RwLock<BTreeSet<[u8; 48]>>>,
}

impl WatchRegistry {
    /// Open the registry under `config_dir`, loading whatever was previously registered.
    ///
    /// A missing file is the normal fresh-install state and yields an empty registry.
    pub fn new(config_dir: &Path) -> Self {
        let path = config_dir.join(WATCHLIST_FILE);
        let keys = load(&path);
        Self {
            path,
            keys: Arc::new(RwLock::new(keys)),
        }
    }

    /// Register `keys` to be followed. Returns how many were NOT already registered.
    ///
    /// Idempotent: re-registering a known key changes nothing and reports 0 added, so a client may
    /// safely re-announce its account on every unlock.
    ///
    /// `pub(crate)`, not `pub`, so the SINGLE DOOR onto enrolment
    /// ([`super::rpc::WalletBackend::watch_keys`]) is a guarantee the compiler holds rather than a
    /// convention a future caller can walk around: widening the followed set is what invalidates
    /// the replica's coverage, and a widening that happened outside that door would be invisible to
    /// every reviewer who checked the door (dig_ecosystem#2871).
    pub(crate) fn watch(&self, keys: &[PublicKey]) -> usize {
        let added = {
            let mut set = self.keys.write().unwrap();
            let before = set.len();
            set.extend(keys.iter().map(|k| k.to_bytes()));
            set.len() - before
        };
        if added > 0 {
            self.persist();
        }
        added
    }

    /// Deregister `keys`. Returns how many were actually registered and are now gone.
    ///
    /// This genuinely stops the following: the key leaves the in-memory set the supervisor re-reads
    /// AND the file a restart loads, so neither path can resurrect it.
    pub fn unwatch(&self, keys: &[PublicKey]) -> usize {
        let removed = {
            let mut set = self.keys.write().unwrap();
            keys.iter().filter(|k| set.remove(&k.to_bytes())).count()
        };
        if removed > 0 {
            self.persist();
        }
        removed
    }

    /// Every currently-registered key, in a stable order.
    pub fn registered(&self) -> Vec<PublicKey> {
        self.keys
            .read()
            .unwrap()
            .iter()
            // Every stored entry was validated on the way in, so a decode failure here is
            // impossible rather than merely unlikely; skipping is the inert choice if it ever
            // becomes possible.
            .filter_map(|b| PublicKey::from_bytes(b).ok())
            .collect()
    }

    /// Every registered key as lowercase hex — the form the control surface reports, and the same
    /// spelling a client passes to register it.
    pub fn registered_hex(&self) -> Vec<String> {
        self.keys.read().unwrap().iter().map(hex::encode).collect()
    }

    /// Whether anything at all is registered — the "is a wallet enrolled here" question for a node
    /// that custodies nothing.
    pub fn is_empty(&self) -> bool {
        self.keys.read().unwrap().is_empty()
    }

    /// Write the registry atomically and owner-only.
    ///
    /// Best-effort, and a failure is LOUD: the in-memory set is already correct, so the live node
    /// keeps following the right addresses, but a restart would follow fewer — exactly the silent
    /// under-report this module refuses to produce quietly.
    fn persist(&self) {
        let file = WatchlistFile {
            keys: self.keys.read().unwrap().iter().map(hex::encode).collect(),
        };
        let json = match serde_json::to_vec_pretty(&file) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("dig-wallet: ERROR could not serialize the watch list: {e}");
                return;
            }
        };
        if let Some(dir) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!(
                    "dig-wallet: ERROR could not create the config dir for the watch list: {e}"
                );
                return;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &json) {
            eprintln!("dig-wallet: ERROR could not write the watch list: {e}");
            return;
        }
        restrict_permissions(&tmp);
        // Windows `rename` fails onto an existing file.
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            eprintln!(
                "dig-wallet: ERROR could not persist the watch list; a restart would follow fewer \
                 addresses than registered: {e}"
            );
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Read the registry file. Absent or unreadable → empty.
///
/// An entry that will not decode is REPORTED, never silently discarded: the node is about to
/// follow fewer addresses than the operator registered, and the resulting balance would be too
/// small rather than obviously broken.
fn load(path: &Path) -> BTreeSet<[u8; 48]> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeSet::new();
    };
    let file: WatchlistFile = match serde_json::from_slice(&bytes) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "dig-wallet: ERROR the watch list at {} is unreadable, so NO registered address \
                 will be followed: {e}",
                path.display()
            );
            return BTreeSet::new();
        }
    };
    let mut set = BTreeSet::new();
    for entry in &file.keys {
        match decode_key(entry) {
            Some(k) => {
                set.insert(k.to_bytes());
            }
            None => eprintln!(
                "dig-wallet: ERROR a registered watch key is undecodable and will NOT be followed: \
                 {entry}"
            ),
        }
    }
    set
}

/// Parse one 48-byte G1 public key from hex.
///
/// A `0x` prefix is tolerated and normalized away, matching the published contract's rule for coin
/// ids, so a client that spells its keys either way is understood rather than silently rejected.
///
/// Public so the RPC boundary refuses a malformed request outright rather than registering the
/// subset that happened to parse.
pub fn decode_key(hex_key: &str) -> Option<PublicKey> {
    let unprefixed = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    let bytes: [u8; 48] = hex::decode(unprefixed).ok()?.try_into().ok()?;
    PublicKey::from_bytes(&bytes).ok()
}

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
    use chia_bls::SecretKey;

    /// A distinct, valid G1 key per `tag`.
    fn key(tag: u8) -> PublicKey {
        let mut seed = [0u8; 64];
        seed[0] = tag;
        SecretKey::from_seed(&seed).public_key()
    }

    /// The directory is OWNED by the returned guard: `TempDir`'s `Drop` removes the tree,
    /// including on an unwind, so a failing assertion cannot leak it (dig-node#370).
    fn dir(tag: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("dig-watchlist-{tag}-"))
            .tempdir()
            .expect("a scratch dir")
    }

    #[test]
    fn registers_and_reports_what_was_registered() {
        let d = dir("register");
        let r = WatchRegistry::new(d.path());
        assert!(r.is_empty(), "a fresh node registers nothing");

        assert_eq!(r.watch(&[key(1), key(2)]), 2);
        assert_eq!(r.registered().len(), 2);
        assert!(!r.is_empty());
    }

    /// Re-registering is a no-op, so a client may re-announce on every unlock.
    #[test]
    fn watch_is_idempotent() {
        let d = dir("idempotent");
        let r = WatchRegistry::new(d.path());
        r.watch(&[key(1)]);

        assert_eq!(r.watch(&[key(1)]), 0, "a known key adds nothing");
        assert_eq!(r.registered().len(), 1);
    }

    /// The whole point of persisting: a restart keeps following.
    #[test]
    fn survives_a_restart() {
        let d = dir("persist");
        WatchRegistry::new(d.path()).watch(&[key(1), key(2)]);

        let reopened = WatchRegistry::new(d.path());
        assert_eq!(reopened.registered(), vec_sorted(&[key(1), key(2)]));
    }

    /// `unwatch` must stop the following on BOTH paths — the live set the supervisor re-reads and
    /// the file a restart loads. A second key stays registered as an honest control, so an
    /// implementation that clears everything is visible rather than passing.
    #[test]
    fn unwatch_stops_following_live_and_after_restart() {
        let d = dir("unwatch");
        let r = WatchRegistry::new(d.path());
        r.watch(&[key(1), key(2)]);

        assert_eq!(r.unwatch(&[key(1)]), 1);
        assert_eq!(
            r.registered(),
            vec![key(2)],
            "the live set drops only key 1"
        );
        assert_eq!(
            WatchRegistry::new(d.path()).registered(),
            vec![key(2)],
            "and a restart does not resurrect it"
        );
    }

    /// Deregistering something never registered is honestly reported as 0, not as success.
    #[test]
    fn unwatch_of_an_unregistered_key_removes_nothing() {
        let d = dir("unwatch-unknown");
        let r = WatchRegistry::new(d.path());
        r.watch(&[key(1)]);

        assert_eq!(r.unwatch(&[key(9)]), 0);
        assert_eq!(r.registered(), vec![key(1)]);
    }

    /// A clone shares state, which is what lets an RPC registration reach the running supervisor
    /// without a restart.
    #[test]
    fn a_clone_sees_a_registration_made_through_another_handle() {
        let d = dir("clone");
        let handler = WatchRegistry::new(d.path());
        let supervisor = handler.clone();
        assert!(supervisor.is_empty());

        handler.watch(&[key(3)]);

        assert_eq!(supervisor.registered(), vec![key(3)]);
    }

    /// The published contract tolerates a `0x` prefix and normalizes it away, so both spellings
    /// must name the SAME key — a client that prefixes must not enrol a duplicate.
    #[test]
    fn a_0x_prefixed_key_is_the_same_key() {
        let plain = hex::encode(key(5).to_bytes());
        let prefixed = format!("0x{plain}");

        assert_eq!(decode_key(&prefixed), decode_key(&plain));
        assert_eq!(decode_key(&prefixed), Some(key(5)));
    }

    /// A corrupt file follows NOTHING rather than silently following a partial set.
    #[test]
    fn a_corrupt_file_yields_an_empty_registry() {
        let d = dir("corrupt");
        std::fs::write(d.path().join(WATCHLIST_FILE), b"{not json").unwrap();

        assert!(WatchRegistry::new(d.path()).is_empty());
    }

    /// The given keys in the registry's own stable (G1 byte) order.
    fn vec_sorted(keys: &[PublicKey]) -> Vec<PublicKey> {
        keys.iter()
            .map(|k| k.to_bytes())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|b| PublicKey::from_bytes(&b).unwrap())
            .collect()
    }
}
