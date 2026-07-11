//! The server-side VERIFICATION LEDGER (#307) — a bounded, short-TTL, in-memory record of the
//! per-resource verification verdict + Merkle inclusion-proof data the `/s/` serve path (#289)
//! already computes, retained so the loopback browser surface can EXPOSE it (`GET /verify/...`).
//!
//! The `/s/` serve path verifies every served resource against the store's CHAIN-ANCHORED root and
//! fails CLOSED (a tampered/decoy resource is never served). #289 surfaced only the aggregate verdict
//! per response header (`X-Dig-Verified`). This ledger RETAINS the verdict + the proof (leaf hash,
//! ordered sibling hashes + directions, the reconstructed leaf index, and the root the proof folds to)
//! for every resource served (or fail-closed rejected) for a `(store, root)` page session, so the
//! extension can render a page-level "Verified by Chia" badge + a proof-inspection modal.
//!
//! ## What is recorded, and when
//!
//! Recording happens on the EXISTING verify step — it reuses the inclusion-proof data the serve path
//! already computed, it does NOT re-verify. An entry is written when the serve reaches a DEFINITIVE
//! per-resource outcome:
//!
//! * a resource served from `local`/`peer`/`rpc` that verified → `verified` = the chain-anchored pin
//!   result (`true` under the default pin; `false` only when `DIG_NODE_PIN=off`);
//! * an `rpc` response whose bytes were fetched but FAILED verification (a decoy / tamper / a root
//!   that is not the anchored tip) → recorded `verified: false` with a `failReason`, and — per the
//!   fail-closed guarantee — NEVER served.
//!
//! A tier fall-through (a local decoy that falls through to peer/rpc) and a genuine upstream content
//! miss (`-32004`) are NOT verification failures and are NOT recorded — only the final, definitive
//! outcome for a resource key is.
//!
//! ## Aggregate rule
//!
//! * `verified` = there is at least one entry AND every entry verified — the badge is green
//!   "Verified by Chia" only then.
//! * `anyRpcFailed` = any entry with `source == "rpc" && !verified` — an RPC-sourced resource that did
//!   not tie to the chain, which flips the badge to "Unverified".
//!
//! ## Bounds
//!
//! In-memory only, never persisted. Keyed by `store:root`; entries deduped by resource key (a
//! re-served resource UPDATES its entry in place, preserving load order). Pruned by [`LEDGER_TTL`]
//! and capped at [`MAX_KEYS`] page sessions (oldest evicted) and [`MAX_RESOURCES_PER_KEY`] resources
//! per session, so a long-running node never grows the ledger without bound.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use digstore_core::merkle::{MerkleProof, ProofStep};
use serde::Serialize;

/// How long a `(store, root)` page session's ledger is retained after its last update. Short enough
/// that the ledger stays ephemeral (a page session), long enough for a page's resources to all load
/// and the user to open + inspect the badge modal.
pub const LEDGER_TTL: Duration = Duration::from_secs(15 * 60);

/// Max distinct `(store, root)` page sessions retained. Over this, the least-recently-updated session
/// is evicted. Bounds memory on a node that serves many stores.
pub const MAX_KEYS: usize = 64;

/// Max resources retained per page session. A well-formed store has far fewer; the cap is a guard
/// against an adversarial page requesting unbounded distinct resource keys.
pub const MAX_RESOURCES_PER_KEY: usize = 1024;

/// One sibling on a Merkle inclusion path, as exposed to the browser: the sibling hash (hex) and the
/// SIDE the sibling sits on. `dir == "left"` means the sibling is the LEFT node (so re-verification
/// folds `hash(sibling, acc)`); `dir == "right"` means the sibling is the RIGHT node (fold
/// `hash(acc, sibling)`). Mirrors [`ProofStep::is_left`] so a client re-verifier folds identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofSibling {
    pub hash: String,
    pub dir: String,
}

/// The Merkle inclusion-proof data for one resource, serialized for DISPLAY and optional client-side
/// RE-VERIFICATION. Re-verification uses `leafHash` + `siblings` (hash + dir) folded up to `proofRoot`
/// (the `verify()` fold); the entry's own `root` is then compared to `proofRoot` to confirm the proof
/// ties to the chain-anchored root. `leafIndex` is display-only (see [`leaf_index_from_path`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofData {
    /// `SHA-256(resource_ciphertext)` — the D5 per-resource Merkle leaf (hex).
    pub leaf_hash: String,
    /// The bottom-up sibling path (leaf → root), in fold order.
    pub siblings: Vec<ProofSibling>,
    /// The leaf's index among the generation's resource leaves, reconstructed from the sibling
    /// directions (display-only; not required to re-verify). See [`leaf_index_from_path`].
    pub leaf_index: u64,
    /// The root the proof folds to (hex). Equals the entry's `root` for a verified resource; differs
    /// for a fail-closed entry whose proof did not tie to the anchored root.
    pub proof_root: String,
}

impl ProofData {
    /// Serialize a [`MerkleProof`] into the browser-facing proof-data shape.
    pub fn from_merkle_proof(proof: &MerkleProof) -> Self {
        let siblings = proof
            .path
            .iter()
            .map(|s| ProofSibling {
                hash: hex::encode(s.hash.0),
                dir: if s.is_left { "left" } else { "right" }.to_string(),
            })
            .collect();
        ProofData {
            leaf_hash: hex::encode(proof.leaf.0),
            siblings,
            leaf_index: leaf_index_from_path(&proof.path),
            proof_root: hex::encode(proof.root.0),
        }
    }
}

/// Reconstruct a leaf's index from its inclusion-path directions: bottom-up, a LEFT-sibling step means
/// this node was the RIGHT child (bit 1) at that level, a right-sibling step means the LEFT child
/// (bit 0). This is exact for a leaf whose path has no odd-carry level (the common case — a balanced
/// generation, or any leaf off the tree's right spine). It is a DISPLAY value only: re-verification
/// folds the siblings and never consults the index, so an approximate value for a right-spine leaf in
/// an odd tree is harmless.
pub fn leaf_index_from_path(path: &[ProofStep]) -> u64 {
    let mut idx = 0u64;
    for (level, step) in path.iter().enumerate().take(64) {
        if step.is_left {
            idx |= 1u64 << level;
        }
    }
    idx
}

/// One recorded resource verdict for a `(store, root)` page session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    /// The resource key within the store (the `/s/` path, `index.html` for the default view).
    pub resource_key: String,
    /// Which tier served (or, for a fail-closed entry, produced the bytes for) this resource:
    /// `"local"` | `"peer"` | `"rpc"`.
    pub source: String,
    /// Whether the resource verified against the CHAIN-ANCHORED root. A served resource carries the
    /// pin result; a fail-closed (never-served) entry is always `false`.
    pub verified: bool,
    /// The store's resolved (chain-anchored, under the default pin) root this entry was served against
    /// (hex).
    pub root: String,
    /// The Merkle inclusion-proof data (for display + optional client re-verification).
    pub proof: ProofData,
    /// Why verification failed, for a fail-closed entry; `null` for a verified resource.
    pub fail_reason: Option<String>,
}

/// Per-`(store, root)` counts by source tier.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BySource {
    pub local: usize,
    pub peer: usize,
    pub rpc: usize,
}

/// Resource counts for a page session's ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub total: usize,
    pub verified: usize,
    pub failed: usize,
    pub by_source: BySource,
}

/// The page-level aggregate verdict the badge consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Aggregate {
    /// Green "Verified by Chia" only when this is `true`: at least one resource AND all verified.
    pub verified: bool,
    /// Any RPC-sourced resource that did not verify — flips the badge to "Unverified".
    pub any_rpc_failed: bool,
    pub counts: Counts,
}

/// The full read-only snapshot returned by `GET /verify/<store>[:<root>]`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSnapshot {
    pub store_id: String,
    pub root: String,
    pub aggregate: Aggregate,
    pub resources: Vec<LedgerEntry>,
}

impl LedgerSnapshot {
    /// An empty snapshot (nothing recorded for this store/root yet) — a valid, parseable response so
    /// a client can always read the surface without a special-cased 404.
    fn empty(store_id: String, root: String) -> Self {
        LedgerSnapshot {
            store_id,
            root,
            aggregate: Aggregate::default(),
            resources: Vec::new(),
        }
    }
}

/// One page session's entries + its last-touched instant (for TTL prune + LRU eviction).
#[derive(Debug)]
struct Session {
    entries: Vec<LedgerEntry>,
    updated: Instant,
}

/// The bounded, short-TTL, in-memory verification ledger. Interior-mutable (a plain `std::sync::Mutex`
/// held only for the brief record/read — never across an `.await`), so it lives behind `&Node`.
#[derive(Debug, Default)]
pub struct VerificationLedger {
    sessions: Mutex<HashMap<String, Session>>,
}

/// The `store:root` map key.
fn session_key(store_hex: &str, root_hex: &str) -> String {
    format!(
        "{}:{}",
        store_hex.to_ascii_lowercase(),
        root_hex.to_ascii_lowercase()
    )
}

impl VerificationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record (or update, deduped by resource key) one resource's verdict + proof for `(store, root)`.
    /// A no-op when `root_hex` is empty (a served resource always has a concrete root). Prunes expired
    /// sessions and enforces the [`MAX_KEYS`] / [`MAX_RESOURCES_PER_KEY`] bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        store_hex: &str,
        root_hex: &str,
        resource_key: &str,
        source: &str,
        verified: bool,
        proof: &MerkleProof,
        fail_reason: Option<String>,
    ) {
        if root_hex.is_empty() {
            return;
        }
        let entry = LedgerEntry {
            resource_key: resource_key.to_string(),
            source: source.to_string(),
            verified,
            root: root_hex.to_ascii_lowercase(),
            proof: ProofData::from_merkle_proof(proof),
            fail_reason,
        };
        let key = session_key(store_hex, root_hex);
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        prune_expired(&mut sessions, now);

        let session = sessions.entry(key).or_insert_with(|| Session {
            entries: Vec::new(),
            updated: now,
        });
        session.updated = now;
        match session
            .entries
            .iter_mut()
            .find(|e| e.resource_key == entry.resource_key)
        {
            Some(existing) => *existing = entry,
            None => {
                if session.entries.len() < MAX_RESOURCES_PER_KEY {
                    session.entries.push(entry);
                }
            }
        }

        evict_over_capacity(&mut sessions);
    }

    /// Read a snapshot for `(store, root)`. With an explicit `root`, that exact session; with `None`,
    /// the most-recently-updated session for the store (a page has one active root). Always returns a
    /// valid snapshot — empty when nothing is recorded. Prunes expired sessions first.
    pub fn snapshot(&self, store_hex: &str, root: Option<&str>) -> LedgerSnapshot {
        let store = store_hex.to_ascii_lowercase();
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        prune_expired(&mut sessions, now);

        let resolved_key = match root {
            Some(r) => Some(session_key(&store, r)),
            None => {
                let prefix = format!("{store}:");
                sessions
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .max_by_key(|(_, s)| s.updated)
                    .map(|(k, _)| k.clone())
            }
        };

        let Some(key) = resolved_key else {
            let root_hex = root.map(|r| r.to_ascii_lowercase()).unwrap_or_default();
            return LedgerSnapshot::empty(store, root_hex);
        };
        let Some(session) = sessions.get(&key) else {
            let root_hex = root.map(|r| r.to_ascii_lowercase()).unwrap_or_default();
            return LedgerSnapshot::empty(store, root_hex);
        };

        // The concrete root is the suffix after the single ':' in the key.
        let root_hex = key
            .split_once(':')
            .map(|(_, r)| r.to_string())
            .unwrap_or_default();
        let resources = session.entries.clone();
        let aggregate = aggregate_of(&resources);
        LedgerSnapshot {
            store_id: store,
            root: root_hex,
            aggregate,
            resources,
        }
    }
}

impl crate::Node {
    /// Record one resource's verify verdict + inclusion proof into the node's [`VerificationLedger`]
    /// (#307). Called from the `/s/` serve path at each DEFINITIVE per-resource outcome, reusing the
    /// proof data the verify step already computed — it does NOT re-verify. `source` is
    /// `"local"`/`"peer"`/`"rpc"`; `fail_reason` is `Some` only for a fail-closed (never-served) entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_verification(
        &self,
        store_hex: &str,
        root_hex: &str,
        resource_key: &str,
        source: &str,
        verified: bool,
        proof: &MerkleProof,
        fail_reason: Option<String>,
    ) {
        self.verification_ledger.record(
            store_hex,
            root_hex,
            resource_key,
            source,
            verified,
            proof,
            fail_reason,
        );
    }

    /// Read the verification-ledger snapshot for `(store, root)` — the read model behind
    /// `GET /verify/<store>[:<root>]`. `root = None` selects the store's most-recently-updated page
    /// session. Always returns a valid (possibly empty) snapshot.
    pub fn verification_ledger_snapshot(
        &self,
        store_hex: &str,
        root: Option<&str>,
    ) -> LedgerSnapshot {
        self.verification_ledger.snapshot(store_hex, root)
    }
}

/// Drop sessions whose last update is older than [`LEDGER_TTL`].
fn prune_expired(sessions: &mut HashMap<String, Session>, now: Instant) {
    sessions.retain(|_, s| now.duration_since(s.updated) < LEDGER_TTL);
}

/// Evict least-recently-updated sessions until at most [`MAX_KEYS`] remain.
fn evict_over_capacity(sessions: &mut HashMap<String, Session>) {
    while sessions.len() > MAX_KEYS {
        if let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, s)| s.updated)
            .map(|(k, _)| k.clone())
        {
            sessions.remove(&oldest);
        } else {
            break;
        }
    }
}

/// Compute the page-level aggregate from a session's entries.
fn aggregate_of(entries: &[LedgerEntry]) -> Aggregate {
    let mut counts = Counts::default();
    let mut all_verified = true;
    let mut any_rpc_failed = false;
    for e in entries {
        counts.total += 1;
        if e.verified {
            counts.verified += 1;
        } else {
            counts.failed += 1;
            all_verified = false;
            if e.source == "rpc" {
                any_rpc_failed = true;
            }
        }
        match e.source.as_str() {
            "local" => counts.by_source.local += 1,
            "peer" => counts.by_source.peer += 1,
            "rpc" => counts.by_source.rpc += 1,
            _ => {}
        }
    }
    Aggregate {
        verified: !entries.is_empty() && all_verified,
        any_rpc_failed,
        counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::Bytes32;

    /// A single-leaf proof rooted at the leaf (the shape a single-chunk resource produces).
    fn single_leaf_proof(leaf: u8, root: u8) -> MerkleProof {
        MerkleProof {
            leaf: Bytes32([leaf; 32]),
            path: Vec::new(),
            root: Bytes32([root; 32]),
        }
    }

    fn proof_with_path() -> MerkleProof {
        MerkleProof {
            leaf: Bytes32([1; 32]),
            path: vec![
                ProofStep {
                    hash: Bytes32([2; 32]),
                    is_left: false,
                },
                ProofStep {
                    hash: Bytes32([3; 32]),
                    is_left: true,
                },
            ],
            root: Bytes32([9; 32]),
        }
    }

    #[test]
    fn proof_data_serializes_leaf_siblings_index_and_root() {
        let pd = ProofData::from_merkle_proof(&proof_with_path());
        assert_eq!(pd.leaf_hash, hex::encode([1u8; 32]));
        assert_eq!(pd.proof_root, hex::encode([9u8; 32]));
        assert_eq!(pd.siblings.len(), 2);
        assert_eq!(pd.siblings[0].dir, "right"); // is_left=false → sibling on the right
        assert_eq!(pd.siblings[1].dir, "left"); // is_left=true → sibling on the left
                                                // leaf index from directions: level0 right(0) + level1 left(1<<1=2) = 2.
        assert_eq!(pd.leaf_index, 2);
    }

    #[test]
    fn leaf_index_is_zero_for_a_single_leaf() {
        assert_eq!(leaf_index_from_path(&[]), 0);
    }

    const STORE: &str = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const ROOT: &str = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee";

    #[test]
    fn records_and_reads_back_by_store_and_root() {
        let ledger = VerificationLedger::new();
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "local",
            true,
            &single_leaf_proof(1, 1),
            None,
        );
        ledger.record(
            STORE,
            ROOT,
            "app.js",
            "rpc",
            true,
            &single_leaf_proof(2, 2),
            None,
        );

        let snap = ledger.snapshot(STORE, Some(ROOT));
        assert_eq!(snap.store_id, STORE);
        assert_eq!(snap.root, ROOT);
        assert_eq!(snap.resources.len(), 2);
        assert_eq!(snap.aggregate.counts.total, 2);
        assert_eq!(snap.aggregate.counts.verified, 2);
        assert_eq!(snap.aggregate.counts.failed, 0);
        assert_eq!(snap.aggregate.counts.by_source.local, 1);
        assert_eq!(snap.aggregate.counts.by_source.rpc, 1);
        assert!(snap.aggregate.verified, "all verified → aggregate verified");
        assert!(!snap.aggregate.any_rpc_failed);
    }

    #[test]
    fn a_failed_rpc_resource_flips_aggregate_and_sets_any_rpc_failed() {
        let ledger = VerificationLedger::new();
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "local",
            true,
            &single_leaf_proof(1, 1),
            None,
        );
        ledger.record(
            STORE,
            ROOT,
            "evil.js",
            "rpc",
            false,
            &single_leaf_proof(2, 3),
            Some("served root is not the store's chain-anchored root".into()),
        );

        let snap = ledger.snapshot(STORE, Some(ROOT));
        assert_eq!(snap.aggregate.counts.total, 2);
        assert_eq!(snap.aggregate.counts.failed, 1);
        assert!(!snap.aggregate.verified, "a failed entry → not verified");
        assert!(snap.aggregate.any_rpc_failed, "source=rpc && !verified");
        let failed = snap
            .resources
            .iter()
            .find(|e| e.resource_key == "evil.js")
            .unwrap();
        assert!(!failed.verified);
        assert_eq!(failed.source, "rpc");
        assert!(failed.fail_reason.is_some());
    }

    #[test]
    fn re_serving_a_resource_updates_its_entry_in_place() {
        let ledger = VerificationLedger::new();
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "rpc",
            false,
            &single_leaf_proof(1, 2),
            Some("x".into()),
        );
        // Re-serve the SAME resource, now verified from local.
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "local",
            true,
            &single_leaf_proof(1, 1),
            None,
        );

        let snap = ledger.snapshot(STORE, Some(ROOT));
        assert_eq!(snap.resources.len(), 1, "deduped by resource key");
        assert!(snap.resources[0].verified);
        assert_eq!(snap.resources[0].source, "local");
        assert!(snap.resources[0].fail_reason.is_none());
    }

    #[test]
    fn snapshot_without_root_returns_the_most_recent_session() {
        let ledger = VerificationLedger::new();
        let root_a = "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
        ledger.record(
            STORE,
            root_a,
            "index.html",
            "local",
            true,
            &single_leaf_proof(1, 1),
            None,
        );
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "local",
            true,
            &single_leaf_proof(2, 2),
            None,
        );

        // No root → the most-recently-updated session (ROOT, recorded last).
        let snap = ledger.snapshot(STORE, None);
        assert_eq!(snap.root, ROOT);
        assert_eq!(snap.resources.len(), 1);
    }

    #[test]
    fn unknown_store_returns_an_empty_snapshot() {
        let ledger = VerificationLedger::new();
        let snap = ledger.snapshot(STORE, Some(ROOT));
        assert_eq!(snap.resources.len(), 0);
        assert!(!snap.aggregate.verified, "empty ledger is not verified");
        assert_eq!(snap.aggregate.counts.total, 0);
    }

    #[test]
    fn record_with_empty_root_is_a_no_op() {
        let ledger = VerificationLedger::new();
        ledger.record(
            STORE,
            "",
            "index.html",
            "rpc",
            true,
            &single_leaf_proof(1, 1),
            None,
        );
        let snap = ledger.snapshot(STORE, None);
        assert_eq!(snap.resources.len(), 0);
    }

    #[test]
    fn evicts_oldest_session_over_the_key_cap() {
        let ledger = VerificationLedger::new();
        // Record MAX_KEYS + 8 distinct roots; the oldest 8 must be evicted.
        for i in 0..(MAX_KEYS + 8) {
            let root = format!("{i:064x}");
            ledger.record(
                STORE,
                &root,
                "index.html",
                "local",
                true,
                &single_leaf_proof(1, 1),
                None,
            );
        }
        let sessions = ledger.sessions.lock().unwrap();
        assert_eq!(sessions.len(), MAX_KEYS, "capped at MAX_KEYS sessions");
    }

    #[test]
    fn snapshot_json_uses_camel_case_contract_fields() {
        let ledger = VerificationLedger::new();
        ledger.record(
            STORE,
            ROOT,
            "index.html",
            "rpc",
            false,
            &single_leaf_proof(1, 2),
            Some("bad".into()),
        );
        let snap = ledger.snapshot(STORE, Some(ROOT));
        let v = serde_json::to_value(&snap).unwrap();
        // The exact wire the extension consumes.
        assert!(v.get("storeId").is_some());
        assert!(v["aggregate"].get("anyRpcFailed").is_some());
        assert!(v["aggregate"]["counts"].get("bySource").is_some());
        let entry = &v["resources"][0];
        assert_eq!(entry["resourceKey"], "index.html");
        assert_eq!(entry["failReason"], "bad");
        assert!(entry["proof"].get("leafHash").is_some());
        assert!(entry["proof"].get("leafIndex").is_some());
        assert!(entry["proof"].get("proofRoot").is_some());
        assert_eq!(entry["proof"]["siblings"], serde_json::json!([]));
    }
}
