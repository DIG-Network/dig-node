//! Subscription management (dig-node SPEC §14.1) — the node's OWN persisted set of subscribed stores.
//!
//! A **subscription** is a store the node has decided to actively HOLD, WATCH, SYNC, and PUBLISH:
//! subscribing starts chain-watching the store's CHIP-0035 singleton (§14.2), gap-filling the
//! generations it is missing (§14.3), and publishing provider records so peers find it as a holder
//! (§14.1); unsubscribing stops watching (and, at the caller's option, evicts the held modules).
//!
//! The subscription set is DISTINCT from the durable capsule inventory (the `.dig` modules under the
//! cache dir). The inventory answers "what does this node currently hold?"; the subscription set
//! answers "what does this node intend to keep current?" — it drives the proactive chain watcher +
//! gap-fill loop the SPEC specifies in §14. A store can be
//! subscribed before any of its modules are held (the watcher pulls them down); a module can be held
//! without a subscription (a one-off cached read). Keeping the two separate is what lets the node
//! *actively seek other nodes to pull the missing generations* rather than only reacting to reads.
//!
//! The set is persisted to `<cache>/subscriptions.json` so it survives restarts. Writes are atomic
//! (temp + rename) and serialized by the same cross-process advisory lock the config RMW uses, so two
//! DIG processes sharing the cache (the browser's in-process node + the standalone node) cannot lose
//! each other's subscription updates.
//!
//! This module is deliberately I/O-thin + pure where it can be: [`SubscriptionSet`] is a plain,
//! order-preserving, de-duplicated set of 64-hex store ids with all the add/remove/list logic, and it
//! is unit-tested directly. The disk layer ([`load`]/[`store`]) is a thin JSON codec over it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The on-disk file name for the persisted subscription set, kept at the ROOT of the cache dir next
/// to `config.json` / `modules/` (so it shares the cache's writability + lock handling).
pub const SUBSCRIPTIONS_FILE: &str = "subscriptions.json";

/// The persisted subscription document: a schema-versioned list of subscribed store ids.
///
/// Versioned so a future additive field (per-store options — pin depth, priority) is a
/// backwards-compatible read: an older reader ignores unknown fields, a newer reader defaults them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionsDoc {
    /// Schema version (currently `1`). Additive-only; a bump never removes/repurposes a field.
    pub version: u32,
    /// The subscribed store ids, lower-case 64-hex, in insertion order (stable for the UI + tests).
    pub stores: Vec<String>,
}

impl Default for SubscriptionsDoc {
    fn default() -> Self {
        SubscriptionsDoc {
            version: 1,
            stores: Vec::new(),
        }
    }
}

/// An in-memory, order-preserving, de-duplicated set of subscribed store ids (lower-case 64-hex).
///
/// All add/remove/list policy lives here so it is pure + directly unit-testable; the disk layer is a
/// thin codec ([`load`]/[`store`]). Store ids are normalized to lower-case on insert so the same
/// launcher id in mixed case is one subscription, never two.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionSet {
    stores: Vec<String>,
}

/// Whether `s` is a canonical 64-char hex store id.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The canonical form of a store id as stored in the set: trimmed + lower-cased. This is the SINGLE
/// normalization [`SubscriptionSet::add`]/[`remove`](SubscriptionSet::remove)/[`contains`](SubscriptionSet::contains)
/// apply, exposed so a caller (the `control.subscribe`/`unsubscribe` RPC echo) can report EXACTLY the
/// id that was persisted — never the raw input — so the echo can never disagree with
/// `control.listSubscriptions`.
pub fn normalize_store_id(store_id: &str) -> String {
    store_id.trim().to_ascii_lowercase()
}

impl SubscriptionSet {
    /// An empty set.
    pub fn new() -> Self {
        SubscriptionSet::default()
    }

    /// Build a set from a persisted document, normalizing (lower-case) + de-duplicating + dropping
    /// any malformed (non-64-hex) entry so a hand-edited/corrupt file can never inject a bad id.
    pub fn from_doc(doc: &SubscriptionsDoc) -> Self {
        let mut set = SubscriptionSet::new();
        for s in &doc.stores {
            let _ = set.add(s);
        }
        set
    }

    /// Serialize to a persisted document (schema version 1).
    pub fn to_doc(&self) -> SubscriptionsDoc {
        SubscriptionsDoc {
            version: 1,
            stores: self.stores.clone(),
        }
    }

    /// Subscribe to `store_id`. Returns `Ok(true)` if it was newly added, `Ok(false)` if it was
    /// already subscribed (idempotent), or `Err` if `store_id` is not a valid 64-hex id. The id is
    /// normalized to lower-case so mixed-case duplicates collapse to one subscription.
    pub fn add(&mut self, store_id: &str) -> Result<bool, String> {
        let id = normalize_store_id(store_id);
        if !is_hex64(&id) {
            return Err(format!("store_id must be 64-hex, got {store_id:?}"));
        }
        if self.stores.iter().any(|s| s == &id) {
            return Ok(false);
        }
        self.stores.push(id);
        Ok(true)
    }

    /// Unsubscribe from `store_id`. Returns `Ok(true)` if it was present + removed, `Ok(false)` if it
    /// was not subscribed (idempotent), or `Err` on a malformed id.
    pub fn remove(&mut self, store_id: &str) -> Result<bool, String> {
        let id = normalize_store_id(store_id);
        if !is_hex64(&id) {
            return Err(format!("store_id must be 64-hex, got {store_id:?}"));
        }
        let before = self.stores.len();
        self.stores.retain(|s| s != &id);
        Ok(self.stores.len() != before)
    }

    /// Whether `store_id` (case-insensitive) is subscribed.
    pub fn contains(&self, store_id: &str) -> bool {
        let id = normalize_store_id(store_id);
        self.stores.iter().any(|s| s == &id)
    }

    /// The subscribed store ids in insertion order (lower-case 64-hex).
    pub fn stores(&self) -> &[String] {
        &self.stores
    }

    /// How many stores are subscribed.
    pub fn len(&self) -> usize {
        self.stores.len()
    }

    /// Whether no stores are subscribed.
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }
}

/// The subscriptions file path for a given cache dir (`<cache>/subscriptions.json`).
pub fn subscriptions_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(SUBSCRIPTIONS_FILE)
}

/// Load the subscription set from `<cache>/subscriptions.json`. A missing, empty, or unparseable
/// file is an EMPTY set (never an error) — the node simply has no subscriptions yet. Malformed entries
/// inside a valid document are dropped by [`SubscriptionSet::from_doc`].
pub fn load(cache_dir: &Path) -> SubscriptionSet {
    let path = subscriptions_path(cache_dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return SubscriptionSet::new();
    };
    match serde_json::from_str::<SubscriptionsDoc>(&text) {
        Ok(doc) => SubscriptionSet::from_doc(&doc),
        // Tolerate a legacy/foreign shape: try a bare `{ "stores": [...] }` before giving up empty.
        Err(_) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => {
                let stores = v
                    .get("stores")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(str::to_string))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                SubscriptionSet::from_doc(&SubscriptionsDoc { version: 1, stores })
            }
            Err(_) => SubscriptionSet::new(),
        },
    }
}

/// Encode a subscription set to the pretty-printed JSON bytes persisted on disk. Pure (no I/O) so the
/// on-disk schema is directly assertable in a test.
pub fn encode(set: &SubscriptionSet) -> Vec<u8> {
    serde_json::to_vec_pretty(&set.to_doc()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> String {
        hex::encode([n; 32])
    }

    /// **Proves:** add is idempotent + insertion-ordered; a second add of the same id is a no-op
    /// (`Ok(false)`) and does not duplicate. **Catches:** a set that grows duplicates or reorders.
    #[test]
    fn add_is_idempotent_and_ordered() {
        let mut set = SubscriptionSet::new();
        assert_eq!(set.add(&id(1)), Ok(true), "first add is new");
        assert_eq!(set.add(&id(2)), Ok(true));
        assert_eq!(set.add(&id(1)), Ok(false), "re-add is a no-op");
        assert_eq!(set.stores(), &[id(1), id(2)], "insertion order preserved");
        assert_eq!(set.len(), 2);
    }

    /// **Proves:** mixed-case ids normalize to one lower-case subscription (not two).
    /// **Catches:** a case-sensitive set that double-subscribes the same store.
    #[test]
    fn add_normalizes_case() {
        let mut set = SubscriptionSet::new();
        let lower = id(0xab);
        let upper = lower.to_ascii_uppercase();
        assert_eq!(set.add(&upper), Ok(true));
        assert_eq!(set.add(&lower), Ok(false), "same id, different case");
        assert_eq!(set.stores(), std::slice::from_ref(&lower));
        assert!(set.contains(&upper), "contains is case-insensitive");
    }

    /// **Proves:** remove is idempotent (`Ok(false)` when absent) and unsubscribes when present.
    #[test]
    fn remove_is_idempotent() {
        let mut set = SubscriptionSet::new();
        set.add(&id(1)).unwrap();
        assert_eq!(set.remove(&id(9)), Ok(false), "not subscribed");
        assert_eq!(set.remove(&id(1)), Ok(true), "removed");
        assert!(set.is_empty());
        assert_eq!(set.remove(&id(1)), Ok(false), "already gone");
    }

    /// **Proves:** a malformed store id is rejected on add AND remove (never persisted).
    /// **Catches:** a bad id leaking into the watched set (which would drive a bogus chain read).
    #[test]
    fn rejects_malformed_ids() {
        let mut set = SubscriptionSet::new();
        assert!(set.add("not-hex").is_err());
        assert!(set.add("abcd").is_err(), "too short");
        assert!(set.add(&"zz".repeat(32)).is_err(), "non-hex chars");
        assert!(set.remove("not-hex").is_err());
        assert!(set.is_empty());
    }

    /// **Proves:** a persisted document round-trips through [`SubscriptionSet`] byte-stably, and
    /// [`from_doc`] drops malformed entries from a corrupt file.
    /// **Catches:** a codec that loses ordering or admits a bad id from disk.
    #[test]
    fn doc_roundtrip_and_sanitization() {
        let mut set = SubscriptionSet::new();
        set.add(&id(1)).unwrap();
        set.add(&id(2)).unwrap();
        let doc = set.to_doc();
        assert_eq!(doc.version, 1);
        assert_eq!(SubscriptionSet::from_doc(&doc), set, "clean round-trip");

        // A corrupt document with a bad + a good id: only the good one survives.
        let corrupt = SubscriptionsDoc {
            version: 1,
            stores: vec!["garbage".to_string(), id(3)],
        };
        let cleaned = SubscriptionSet::from_doc(&corrupt);
        assert_eq!(cleaned.stores(), &[id(3)], "malformed entry dropped");
    }

    /// **Proves:** load of a missing file is an empty set (never an error), and encode→load
    /// round-trips through the real on-disk JSON.
    /// **Catches:** a load that errors on first run, or a schema drift between encode + load.
    #[test]
    fn disk_roundtrip_and_missing_file() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        assert!(load(dir).is_empty(), "no file yet → empty");

        let mut set = SubscriptionSet::new();
        set.add(&id(7)).unwrap();
        set.add(&id(8)).unwrap();
        std::fs::write(subscriptions_path(dir), encode(&set)).unwrap();

        let loaded = load(dir);
        assert_eq!(loaded, set, "encode → disk → load round-trips");
    }

    /// **Proves:** `normalize_store_id` trims AND lower-cases, so it matches what add/remove persist;
    /// a whitespace-padded mixed-case id normalizes to the exact stored form. **Catches:** an RPC echo
    /// that reports the raw input and disagrees with `listSubscriptions`.
    #[test]
    fn normalize_matches_stored_form() {
        let raw = format!("  {}  ", id(0xcd).to_ascii_uppercase());
        let norm = normalize_store_id(&raw);
        assert_eq!(norm, id(0xcd), "trimmed + lower-cased");
        // And the stored form equals the normalized form.
        let mut set = SubscriptionSet::new();
        set.add(&raw).unwrap();
        assert_eq!(set.stores(), std::slice::from_ref(&norm));
    }

    /// **Proves:** load tolerates a legacy bare `{ "stores": [...] }` shape (no `version`).
    /// **Catches:** a strict decoder that would drop pre-versioned subscription files.
    #[test]
    fn load_tolerates_legacy_shape() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path();
        let legacy = serde_json::json!({ "stores": [id(4), "bad", id(5)] });
        std::fs::write(subscriptions_path(dir), legacy.to_string()).unwrap();
        let loaded = load(dir);
        assert_eq!(
            loaded.stores(),
            &[id(4), id(5)],
            "legacy shape, bad id dropped"
        );
    }
}
