//! Store-melt propagation (epic #1316, pieces #3 + #4) — the node's receive → on-chain-verify →
//! delete → rebroadcast handler, plus the holder's watch → delete → broadcast path.
//!
//! # Why this is custody-critical
//!
//! Melting a store is an IRREVERSIBLE delete of published content. This module is what makes a melt
//! PROPAGATE across the P2P network so every holder reclaims disk — but the same machinery, if it
//! trusted the wrong thing, would let a forged announcement erase live data. The single load-bearing
//! rule is therefore **FAIL-CLOSED**: nothing is ever deleted unless the chain POSITIVELY confirms
//! the store's singleton is closed. A forged/replayed announcement, or a chain the node cannot reach,
//! deletes NOTHING (see [`confirm_melt`] / [`MeltStatus`]).
//!
//! # The wire (`dig_gossip`, opcode 221) is a PUBLIC broadcast — §5.4-EXEMPT
//!
//! A store deletion is public-by-nature and addressed to everyone (like L2 consensus gossip), so the
//! [`StoreMeltedAnnounce`] is mTLS-authenticated + signed, NOT recipient-sealed. Its signature is
//! attribution/anti-spam only; it is **never** the authority to delete data — the on-chain melt proof
//! is that authority.
//!
//! # The two entry points, and why they share one core
//!
//! - **Piece #4 — the MELTING holder** ([`process_holder_store`]): a store the node HOLDS whose
//!   singleton the chain observes as closed. Delete every held generation, broadcast a signed
//!   announcement, tombstone the store.
//! - **Piece #3 — a RECEIVING peer** ([`process_inbound`]): an inbound opcode-221 frame. Cheap-gate
//!   (held → not-tombstoned), verify melted ON-CHAIN, delete, and rebroadcast ONCE (convergent
//!   epidemic).
//!
//! Both funnel through [`decide_melt`] (the pure decision) and the shared [`TombstoneSet`] (the
//! set-once state that guarantees each node broadcasts at most once per store, so the epidemic
//! quiesces).
//!
//! # Ordering is a security property, not a nicety
//!
//! [`process_inbound`] establishes `held` and `not-tombstoned` — both O(local) — BEFORE it ever
//! touches the chain or verifies a signature. That ordering is what bounds a flood of announcements
//! for stores this node does not hold to O(1)-ish local work per message: an attacker cannot make a
//! cheap inbound frame cost a chain round-trip or a signature verification for content we never held.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use dig_gossip::{store_melted_payload, Bytes32, PeerId, StoreMeltedAnnounce};
use dig_tls::bls::SecretKey;

use crate::{AnchoredRootResolver, CapsuleStore, KeyManager};

/// Whether a store's singleton is closed (melted), still live, or currently unknowable.
///
/// Derived ONLY from a positive chain read (see [`MeltChain::confirm_melt`]) — never from an
/// announcement's contents or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeltStatus {
    /// The singleton lineage resolved to a closed store (`Ok(None)`) — the store IS melted.
    Melted,
    /// The singleton is still live (`Ok(Some(tip))`) — NEVER delete.
    Live,
    /// The chain was unreachable/errored (`Err`) — NEVER delete (fail-closed).
    Unknown,
}

/// The action to take for a store once its held-ness and on-chain status are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeltDecision {
    /// Delete every held generation and propagate the melt exactly once.
    DeleteAndPropagate,
    /// Do nothing — not held, not melted, unknowable, or already handled.
    Ignore,
}

/// The pure melt decision, shared by the holder (#4) and receiver (#3) paths.
///
/// The ONLY input that authorizes a delete is `status == Melted` from a positive chain read. `held`
/// and `already_tombstoned` are the cheap gates that MUST hold before the chain is consulted — this
/// function assumes the caller has already established them.
#[must_use]
pub fn decide_melt(held: bool, already_tombstoned: bool, status: MeltStatus) -> MeltDecision {
    match (held, already_tombstoned, status) {
        (true, false, MeltStatus::Melted) => MeltDecision::DeleteAndPropagate,
        _ => MeltDecision::Ignore,
    }
}

/// The set-once record of stores this node has already melted-and-propagated.
///
/// Both the holder loop and the receiver loop consult ONE instance. Its [`insert`](Self::insert) is a
/// compare-and-set: it returns `true` exactly once per store (the holding → deleted transition), which
/// is what bounds each node to a single broadcast per store and makes the epidemic terminate.
#[derive(Clone, Default)]
pub struct TombstoneSet {
    inner: Arc<Mutex<HashSet<[u8; 32]>>>,
}

impl TombstoneSet {
    /// An empty tombstone set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `store_id` has already been tombstoned.
    #[must_use]
    pub fn contains(&self, store_id: &[u8; 32]) -> bool {
        self.inner
            .lock()
            .expect("tombstone lock")
            .contains(store_id)
    }

    /// Compare-and-set: insert `store_id`, returning `true` iff it was NEWLY inserted.
    ///
    /// The single-broadcast guarantee rides on this: only the transition that returns `true` may
    /// propagate the melt, so a re-receipt (which returns `false`) never re-emits.
    pub fn insert(&self, store_id: [u8; 32]) -> bool {
        self.inner.lock().expect("tombstone lock").insert(store_id)
    }
}

// ---------------------------------------------------------------------------------------------
// Seams — the three effects the actuators drive, each a trait so the policy is spy-testable.
// ---------------------------------------------------------------------------------------------

/// The on-chain melt authority (NC-9). The ONLY thing that may authorize a delete.
///
/// Production maps the node's [`AnchoredRootResolver`] singleton-lineage walk to a [`MeltStatus`]; a
/// closed singleton (`Ok(None)`) is a melt, a live tip (`Ok(Some)`) is not, and an error is
/// fail-closed [`MeltStatus::Unknown`].
#[async_trait::async_trait]
pub trait MeltChain: Send + Sync {
    /// Resolve the on-chain melt status of `store_id`. MUST fail closed: any error/timeout is
    /// [`MeltStatus::Unknown`], never a melt.
    async fn confirm_melt(&self, store_id: &[u8; 32]) -> MeltStatus;
}

/// The node's held-content view + deletion. `held_store_ids` is the O(local) held-check the actuators
/// run BEFORE the chain; `delete_all_generations` unlinks every held generation of a store through the
/// audited cache-remove path (path-containment guarded, content-cache invalidating, idempotent).
#[async_trait::async_trait]
pub trait MeltCache: Send + Sync {
    /// The set of store ids this node currently holds any generation of.
    async fn held_store_ids(&self) -> HashSet<[u8; 32]>;
    /// Delete EVERY held generation of `store_id`. Returns how many were unlinked.
    async fn delete_all_generations(&self, store_id: &[u8; 32]) -> usize;
}

/// Flood a `store-melted` announcement to the pool, optionally excluding the peer it arrived from.
#[async_trait::async_trait]
pub trait MeltBroadcast: Send + Sync {
    /// Broadcast `announce` to every connected peer except `exclude`. Returns peers reached.
    async fn broadcast(&self, announce: &StoreMeltedAnnounce, exclude: Option<PeerId>) -> usize;
}

/// This node's `store-melted` signer: its BLS identity key + its `peer_id` for attribution.
///
/// The signature is attribution/anti-spam only (never the delete gate), but a well-formed
/// announcement still carries one so peers can rate-limit and dedup by origin.
pub struct MeltSigner {
    sk: SecretKey,
    peer_id: Bytes32,
}

impl MeltSigner {
    /// Build a signer from the node's §21 identity seed and its `peer_id` (`SHA-256(SPKI DER)`).
    #[must_use]
    pub fn new(seed: &[u8; 32], peer_id: Bytes32) -> Self {
        Self {
            sk: SecretKey::from_seed(seed),
            peer_id,
        }
    }

    /// A signed announcement for `(store_id, melt_height)`.
    #[must_use]
    pub fn sign_announce(&self, store_id: Bytes32, melt_height: u32) -> StoreMeltedAnnounce {
        StoreMeltedAnnounce::new_signed(&self.sk, store_id, melt_height, self.peer_id)
    }
}

/// The outcome of processing one store, for logging + tests. Every non-`Propagated` variant means
/// NOTHING was deleted and NOTHING was broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagateOutcome {
    /// The store is not held here — dropped before any chain read (receiver DoS guard).
    NotHeld,
    /// The store was already tombstoned — dropped before any chain read.
    AlreadyTombstoned,
    /// The chain did NOT confirm a melt (live singleton, or unreachable chain — fail-closed).
    NotMelted,
    /// The melt was confirmed on-chain: `generations` unlinked, `broadcasts` peers reached.
    Propagated {
        /// Held generations deleted.
        generations: usize,
        /// Peers the (re)broadcast reached.
        broadcasts: usize,
    },
}

// ---------------------------------------------------------------------------------------------
// Piece #3 — the RECEIVING path: cheap-gate → NC-9 verify → delete → rebroadcast once.
// ---------------------------------------------------------------------------------------------

/// Process one inbound `store-melted` announcement. See the module docs for the ordering rationale.
///
/// Sequence (each earlier gate strictly cheaper than the next, so a flood costs the least possible):
/// 1. **held?** — enumerate held stores; if this store is not held, drop with NO chain call, NO
///    signature check, NO rebroadcast ([`PropagateOutcome::NotHeld`]). This is the DoS guard.
/// 2. **already tombstoned?** — if so, drop with NO chain call ([`PropagateOutcome::AlreadyTombstoned`]).
/// 3. **NC-9 on-chain melt check** — [`MeltChain::confirm_melt`]. Only [`MeltStatus::Melted`] proceeds;
///    `Live`/`Unknown` are [`PropagateOutcome::NotMelted`] (fail-closed).
/// 4. **delete + rebroadcast once** — gated on the tombstone CAS: only the newly-inserting transition
///    deletes and rebroadcasts (excluding `sender`), so convergence terminates.
pub async fn process_inbound(
    chain: &dyn MeltChain,
    cache: &dyn MeltCache,
    broadcaster: &dyn MeltBroadcast,
    tombstone: &TombstoneSet,
    sender: Option<PeerId>,
    announce: &StoreMeltedAnnounce,
) -> PropagateOutcome {
    let store_id: [u8; 32] = announce.store_id.into();

    // Gate 1 — held? (cheap, local; the DoS guard — no chain/sig work for content we never held).
    if !cache.held_store_ids().await.contains(&store_id) {
        return PropagateOutcome::NotHeld;
    }
    // Gate 2 — already handled? (cheap, local; no chain read for a re-receipt).
    if tombstone.contains(&store_id) {
        return PropagateOutcome::AlreadyTombstoned;
    }
    // Gate 3 — NC-9: the ONLY delete authority. Fail-closed on Live/Unknown.
    let status = chain.confirm_melt(&store_id).await;
    if decide_melt(true, false, status) == MeltDecision::Ignore {
        return PropagateOutcome::NotMelted;
    }
    // Gate 4 — delete + propagate, exactly once. The CAS is what admits a single transition even
    // under a concurrent re-receipt racing past gate 2.
    if !tombstone.insert(store_id) {
        return PropagateOutcome::AlreadyTombstoned;
    }
    let generations = cache.delete_all_generations(&store_id).await;
    let broadcasts = broadcaster.broadcast(announce, sender).await;
    PropagateOutcome::Propagated {
        generations,
        broadcasts,
    }
}

// ---------------------------------------------------------------------------------------------
// Piece #4 — the MELTING holder: watch → delete → broadcast.
// ---------------------------------------------------------------------------------------------

/// Process one HELD store the holder is checking for melt. Enumerated by [`run_melt_tick`].
///
/// Same fail-closed core as the receiver, minus the held/DoS gate (the caller only passes held
/// stores): tombstone-check → NC-9 → (delete + broadcast a freshly-signed announcement, once).
pub async fn process_holder_store(
    chain: &dyn MeltChain,
    cache: &dyn MeltCache,
    broadcaster: &dyn MeltBroadcast,
    tombstone: &TombstoneSet,
    signer: &MeltSigner,
    store_id: [u8; 32],
    melt_height: u32,
) -> PropagateOutcome {
    if tombstone.contains(&store_id) {
        return PropagateOutcome::AlreadyTombstoned;
    }
    let status = chain.confirm_melt(&store_id).await;
    if decide_melt(true, false, status) == MeltDecision::Ignore {
        return PropagateOutcome::NotMelted;
    }
    if !tombstone.insert(store_id) {
        return PropagateOutcome::AlreadyTombstoned;
    }
    let generations = cache.delete_all_generations(&store_id).await;
    let announce = signer.sign_announce(Bytes32::from(store_id), melt_height);
    let broadcasts = broadcaster.broadcast(&announce, None).await;
    PropagateOutcome::Propagated {
        generations,
        broadcasts,
    }
}

/// Run ONE holder melt-check tick over every currently-held store. Returns how many stores were
/// melted-and-propagated this tick. `melt_height` is the advisory height hint stamped into the
/// announcement (the observed peak; never trusted by receivers).
pub async fn run_melt_tick(
    chain: &dyn MeltChain,
    cache: &dyn MeltCache,
    broadcaster: &dyn MeltBroadcast,
    tombstone: &TombstoneSet,
    signer: &MeltSigner,
    melt_height: u32,
) -> usize {
    let mut propagated = 0;
    for store_id in cache.held_store_ids().await {
        if matches!(
            process_holder_store(
                chain,
                cache,
                broadcaster,
                tombstone,
                signer,
                store_id,
                melt_height
            )
            .await,
            PropagateOutcome::Propagated { .. }
        ) {
            propagated += 1;
        }
    }
    propagated
}

// ---------------------------------------------------------------------------------------------
// Production seams — the live chain resolver, the node cache, and the gossip pool.
// ---------------------------------------------------------------------------------------------

/// Map the node's anchored-root resolver to a [`MeltChain`]. A closed singleton (`Ok(None)`) is a
/// melt; a live tip (`Ok(Some)`) is not; an error is fail-closed [`MeltStatus::Unknown`].
///
/// LOAD-BEARING: this is only ever consulted for a store the node HOLDS. A held store was on-chain
/// confirmed when it was cached, so `Ok(None)` genuinely means "melted", never "never launched".
#[async_trait::async_trait]
impl MeltChain for Arc<dyn AnchoredRootResolver> {
    async fn confirm_melt(&self, store_id: &[u8; 32]) -> MeltStatus {
        match self.anchored_root(store_id).await {
            Ok(None) => MeltStatus::Melted,
            Ok(Some(_live_tip)) => MeltStatus::Live,
            Err(_unreachable) => MeltStatus::Unknown,
        }
    }
}

/// The live node as a [`MeltCache`], over its audited capsule-store operations.
#[async_trait::async_trait]
impl MeltCache for Arc<crate::Node> {
    async fn held_store_ids(&self) -> HashSet<[u8; 32]> {
        self.cache_list_cached()
            .await
            .iter()
            .filter_map(|c| parse_hex32(&c.store_id))
            .collect()
    }

    async fn delete_all_generations(&self, store_id: &[u8; 32]) -> usize {
        let store_hex = hex::encode(store_id);
        let mut removed = 0;
        for capsule in self.cache_list_cached().await {
            if capsule.store_id == store_hex
                && self
                    .cache_remove_cached(&capsule.store_id, &capsule.root)
                    .await
                    .unwrap_or(false)
            {
                removed += 1;
            }
        }
        removed
    }
}

/// The gossip pool as a [`MeltBroadcast`], framing the announcement as opcode 221.
#[async_trait::async_trait]
impl MeltBroadcast for dig_gossip::GossipHandle {
    async fn broadcast(&self, announce: &StoreMeltedAnnounce, exclude: Option<PeerId>) -> usize {
        self.broadcast(dig_gossip::frame_store_melted(announce), exclude)
            .await
            .unwrap_or(0)
    }
}

/// Parse a lowercase 64-hex store id to 32 bytes, or `None` if malformed.
fn parse_hex32(hex_str: &str) -> Option<[u8; 32]> {
    if hex_str.len() != 64 {
        return None;
    }
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// Consume inbound opcode-221 frames forever, applying each through [`process_inbound`].
///
/// Spawned once at bring-up beside the holdings ingest (a SECOND `inbound_receiver()`). Mirrors
/// [`run_holdings_ingest`](super::holdings::run_holdings_ingest): non-221 frames are ignored, a lagged
/// broadcast channel is tolerated (a missed melt is re-heard from any peer that still holds + hears
/// it), and the loop performs egress ONLY on a confirmed melt it holds (the rebroadcast-once).
pub async fn run_store_melted_ingest(
    mut inbound: tokio::sync::broadcast::Receiver<(PeerId, dig_gossip::Message)>,
    chain: Arc<dyn MeltChain>,
    cache: Arc<dyn MeltCache>,
    broadcaster: Arc<dyn MeltBroadcast>,
    tombstone: TombstoneSet,
) {
    loop {
        let (sender, msg) = match inbound.recv().await {
            Ok(pair) => pair,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::debug!(
                    skipped,
                    "store-melt ingest lagged; a missed melt is re-heard from any holder"
                );
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };
        let Some(announce) = store_melted_payload(&msg) else {
            continue; // not an opcode-221 frame (or an undecodable one)
        };
        let outcome = process_inbound(
            &*chain,
            &*cache,
            &*broadcaster,
            &tombstone,
            Some(sender),
            &announce,
        )
        .await;
        if let PropagateOutcome::Propagated {
            generations,
            broadcasts,
        } = outcome
        {
            tracing::info!(
                store = %announce.store_id.to_string(),
                generations,
                broadcasts,
                "store-melt: on-chain-confirmed melt — deleted held content and rebroadcast once"
            );
        }
    }
}

/// Build this node's [`MeltSigner`] from its §21 identity seed + `peer_id`, or `None` if either is
/// unavailable (an announce-less node still DELETES on the receive path; only its own broadcasts are
/// disabled).
pub fn signer_from_node(node: &Arc<crate::Node>) -> Option<MeltSigner> {
    let seed = node.identity_seed_for_peer()?;
    let peer_id = parse_hex32(&node.peer_id_hex()?)?;
    Some(MeltSigner::new(&seed, Bytes32::from(peer_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -- Spies -------------------------------------------------------------------------------------

    /// A chain spy scripted to return a fixed status, counting every call so a test can assert the
    /// chain was (or was NOT) consulted.
    struct ChainSpy {
        status: MeltStatus,
        calls: AtomicUsize,
    }
    impl ChainSpy {
        fn new(status: MeltStatus) -> Self {
            Self {
                status,
                calls: AtomicUsize::new(0),
            }
        }
    }
    #[async_trait::async_trait]
    impl MeltChain for ChainSpy {
        async fn confirm_melt(&self, _store_id: &[u8; 32]) -> MeltStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.status
        }
    }

    /// A cache spy: a fixed held set (with a generation count per store), counting held-checks and
    /// recording deletions.
    struct CacheSpy {
        held: HashSet<[u8; 32]>,
        generations: usize,
        held_checks: AtomicUsize,
        deleted: Mutex<Vec<[u8; 32]>>,
    }
    impl CacheSpy {
        fn holding(stores: &[[u8; 32]], generations: usize) -> Self {
            Self {
                held: stores.iter().copied().collect(),
                generations,
                held_checks: AtomicUsize::new(0),
                deleted: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait::async_trait]
    impl MeltCache for CacheSpy {
        async fn held_store_ids(&self) -> HashSet<[u8; 32]> {
            self.held_checks.fetch_add(1, Ordering::SeqCst);
            self.held.clone()
        }
        async fn delete_all_generations(&self, store_id: &[u8; 32]) -> usize {
            self.deleted.lock().unwrap().push(*store_id);
            self.generations
        }
    }

    /// A broadcast spy recording every (announce store_id, exclude) it was asked to send.
    #[derive(Default)]
    struct BroadcastSpy {
        sent: Mutex<Vec<([u8; 32], Option<PeerId>)>>,
    }
    #[async_trait::async_trait]
    impl MeltBroadcast for BroadcastSpy {
        async fn broadcast(
            &self,
            announce: &StoreMeltedAnnounce,
            exclude: Option<PeerId>,
        ) -> usize {
            self.sent
                .lock()
                .unwrap()
                .push((announce.store_id.into(), exclude));
            1
        }
    }

    fn store(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A deterministic signer built from a labelled seed (never a hard-coded key).
    fn signer(label: &str) -> MeltSigner {
        use sha2::{Digest, Sha256};
        let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
        MeltSigner::new(&seed, Bytes32::from(store(0xAB)))
    }

    /// An unsigned-body announce for `store_id` (signature bytes are irrelevant to the receive path —
    /// the on-chain check is the gate, not the signature).
    fn announce_for(store_id: [u8; 32]) -> StoreMeltedAnnounce {
        signer("test/originator").sign_announce(Bytes32::from(store_id), 100)
    }

    async fn run_inbound(
        chain: &ChainSpy,
        cache: &CacheSpy,
        broadcaster: &BroadcastSpy,
        tombstone: &TombstoneSet,
        store_id: [u8; 32],
    ) -> PropagateOutcome {
        process_inbound(
            chain,
            cache,
            broadcaster,
            tombstone,
            Some(PeerId::from([0x55u8; 32])),
            &announce_for(store_id),
        )
        .await
    }

    // -- The 8 adversarial tests -------------------------------------------------------------------

    /// TEST 1 — a forged/replayed melt for a LIVE store (chain `Ok(Some)` → [`MeltStatus::Live`])
    /// deletes NOTHING and rebroadcasts NOTHING. Catches a gate that treats the signature — or the
    /// announcement's mere existence — as delete authority.
    #[tokio::test]
    async fn live_store_never_deleted() {
        let chain = ChainSpy::new(MeltStatus::Live);
        let cache = CacheSpy::holding(&[store(1)], 3);
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();

        let out = run_inbound(&chain, &cache, &bc, &tomb, store(1)).await;
        assert_eq!(out, PropagateOutcome::NotMelted);
        assert!(
            cache.deleted.lock().unwrap().is_empty(),
            "no delete for a live store"
        );
        assert!(
            bc.sent.lock().unwrap().is_empty(),
            "no rebroadcast for a live store"
        );
        assert!(
            !tomb.contains(&store(1)),
            "a live store is never tombstoned"
        );
    }

    /// TEST 2 — the TOP risk: an unreachable chain (`Err` → [`MeltStatus::Unknown`]) is FAIL-CLOSED.
    /// A held store whose melt cannot be confirmed is NEVER deleted and NEVER rebroadcast. Catches a
    /// verify that falls through to delete on error/timeout.
    #[tokio::test]
    async fn chain_error_is_fail_closed() {
        let chain = ChainSpy::new(MeltStatus::Unknown);
        let cache = CacheSpy::holding(&[store(1)], 2);
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();

        let out = run_inbound(&chain, &cache, &bc, &tomb, store(1)).await;
        assert_eq!(out, PropagateOutcome::NotMelted);
        assert!(
            cache.deleted.lock().unwrap().is_empty(),
            "fail-closed: no delete on chain error"
        );
        assert!(
            bc.sent.lock().unwrap().is_empty(),
            "fail-closed: no rebroadcast on chain error"
        );
        assert!(!tomb.contains(&store(1)));
    }

    /// TEST 3 — a GENUINE melt (held + `Ok(None)` → [`MeltStatus::Melted`]) deletes ALL held
    /// generations, tombstones the store, and rebroadcasts EXACTLY once (excluding the sender).
    /// Catches: no-delete, delete-without-rebroadcast, or rebroadcast-twice.
    #[tokio::test]
    async fn genuine_melt_deletes_all_and_rebroadcasts_once() {
        let chain = ChainSpy::new(MeltStatus::Melted);
        let cache = CacheSpy::holding(&[store(1)], 3); // 3 held generations
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();
        let sender = PeerId::from([0x55u8; 32]);

        let out = process_inbound(
            &chain,
            &cache,
            &bc,
            &tomb,
            Some(sender),
            &announce_for(store(1)),
        )
        .await;
        assert_eq!(
            out,
            PropagateOutcome::Propagated {
                generations: 3,
                broadcasts: 1
            }
        );
        assert_eq!(
            *cache.deleted.lock().unwrap(),
            vec![store(1)],
            "deleted the store's generations"
        );
        let sent = bc.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "rebroadcast EXACTLY once");
        assert_eq!(
            sent[0],
            (store(1), Some(sender)),
            "rebroadcast excludes the sender"
        );
        assert!(
            tomb.contains(&store(1)),
            "store is tombstoned after the transition"
        );
    }

    /// TEST 4 — a NEVER-HELD store is ignored BEFORE any chain read: `confirm_melt` is never invoked
    /// (chain spy == 0) and nothing is rebroadcast. Catches a chain call that precedes the held-check.
    #[tokio::test]
    async fn never_held_store_skips_chain_entirely() {
        let chain = ChainSpy::new(MeltStatus::Melted); // would delete IF the gate let it through
        let cache = CacheSpy::holding(&[store(2)], 3); // holds store 2, not store 1
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();

        let out = run_inbound(&chain, &cache, &bc, &tomb, store(1)).await;
        assert_eq!(out, PropagateOutcome::NotHeld);
        assert_eq!(
            chain.calls.load(Ordering::SeqCst),
            0,
            "no chain read for an un-held store"
        );
        assert!(bc.sent.lock().unwrap().is_empty());
        assert!(cache.deleted.lock().unwrap().is_empty());
    }

    /// TEST 5 — an ALREADY-TOMBSTONED store (a 2nd receipt) is ignored: no delete, NO chain read, no
    /// rebroadcast. Catches a tombstone that is not consulted, or a CAS that fails to guard rebroadcast.
    #[tokio::test]
    async fn already_tombstoned_is_inert() {
        let chain = ChainSpy::new(MeltStatus::Melted);
        let cache = CacheSpy::holding(&[store(1)], 3);
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();
        tomb.insert(store(1)); // already handled

        let out = run_inbound(&chain, &cache, &bc, &tomb, store(1)).await;
        assert_eq!(out, PropagateOutcome::AlreadyTombstoned);
        assert_eq!(
            chain.calls.load(Ordering::SeqCst),
            0,
            "no chain read for a re-receipt"
        );
        assert!(
            bc.sent.lock().unwrap().is_empty(),
            "no rebroadcast on re-receipt"
        );
        assert!(cache.deleted.lock().unwrap().is_empty());
    }

    /// TEST 6 — verify-cost DoS: M announcements for UN-HELD stores cost zero chain reads and exactly
    /// M held-checks (O(local) per message). Catches a chain call (or signature verify) that precedes
    /// the held-check and lets a cheap flood amplify into chain round-trips.
    #[tokio::test]
    async fn unheld_flood_costs_no_chain_reads() {
        let chain = ChainSpy::new(MeltStatus::Melted);
        let cache = CacheSpy::holding(&[], 0); // holds nothing — every announce is un-held
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();

        let flood = 64u8;
        for n in 0..flood {
            let out = run_inbound(&chain, &cache, &bc, &tomb, store(n)).await;
            assert_eq!(out, PropagateOutcome::NotHeld);
        }
        assert_eq!(
            chain.calls.load(Ordering::SeqCst),
            0,
            "un-held flood → zero chain reads"
        );
        assert_eq!(
            cache.held_checks.load(Ordering::SeqCst),
            flood as usize,
            "exactly one O(local) held-check per message"
        );
        assert!(bc.sent.lock().unwrap().is_empty());
    }

    /// TEST 7 — multi-node convergence TERMINATES: a ring of holders each melt-and-propagate exactly
    /// once, so total broadcasts == holder count and the epidemic quiesces (a re-receipt at a
    /// tombstoned node emits nothing). Catches a tombstone that is cleared or a rebroadcast on
    /// re-receipt.
    #[tokio::test]
    async fn convergence_terminates_at_holder_count() {
        // Model a ring of N holder nodes of the same melted store. Each node has its OWN tombstone +
        // cache; the chain confirms the melt for all. We drive each node with the inbound announce
        // TWICE (the second models a neighbour's rebroadcast arriving back) and assert each broadcasts
        // exactly once — so the network-wide total is exactly N and no node re-emits on the echo.
        let holders = 5usize;
        let mut total_broadcasts = 0usize;
        for _node in 0..holders {
            let chain = ChainSpy::new(MeltStatus::Melted);
            let cache = CacheSpy::holding(&[store(9)], 1);
            let bc = BroadcastSpy::default();
            let tomb = TombstoneSet::new();

            let first = run_inbound(&chain, &cache, &bc, &tomb, store(9)).await;
            let echo = run_inbound(&chain, &cache, &bc, &tomb, store(9)).await;

            assert!(
                matches!(first, PropagateOutcome::Propagated { .. }),
                "first melt propagates"
            );
            assert_eq!(
                echo,
                PropagateOutcome::AlreadyTombstoned,
                "the echo never re-emits"
            );
            assert_eq!(
                bc.sent.lock().unwrap().len(),
                1,
                "each node broadcasts at most once"
            );
            total_broadcasts += bc.sent.lock().unwrap().len();
        }
        assert_eq!(
            total_broadcasts, holders,
            "total broadcasts == holder count → quiesces"
        );
    }

    /// TEST 8 — piece #4 fail-closed: a HELD store whose lineage is transiently `Err`
    /// ([`MeltStatus::Unknown`]) triggers NO delete and NO broadcast from the holder tick; only a
    /// stable `Ok(None)` (`Melted`) does. Catches a holder that treats an error (or a bare
    /// anchored-root == None on an unreachable chain) as a false melt.
    #[tokio::test]
    async fn holder_tick_is_fail_closed_on_transient_error() {
        let sig = signer("test/holder");
        let cache = CacheSpy::holding(&[store(4)], 2);
        let bc = BroadcastSpy::default();
        let tomb = TombstoneSet::new();

        // Transient chain error → no delete, no broadcast, not tombstoned (retryable next tick).
        let unreachable = ChainSpy::new(MeltStatus::Unknown);
        let propagated = run_melt_tick(&unreachable, &cache, &bc, &tomb, &sig, 500).await;
        assert_eq!(
            propagated, 0,
            "fail-closed: an unreachable chain melts nothing"
        );
        assert!(cache.deleted.lock().unwrap().is_empty());
        assert!(bc.sent.lock().unwrap().is_empty());
        assert!(
            !tomb.contains(&store(4)),
            "not tombstoned — the holder retries next tick"
        );

        // Now a STABLE confirmed melt → delete + broadcast (with no exclude) exactly once.
        let melted = ChainSpy::new(MeltStatus::Melted);
        let propagated = run_melt_tick(&melted, &cache, &bc, &tomb, &sig, 500).await;
        assert_eq!(propagated, 1, "a stable Ok(None) melts the store");
        assert_eq!(*cache.deleted.lock().unwrap(), vec![store(4)]);
        let sent = bc.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "the holder broadcasts its own melt once");
        assert_eq!(
            sent[0],
            (store(4), None),
            "the holder's own broadcast has no exclude"
        );
    }

    // -- Supporting unit tests for the shared core -------------------------------------------------

    /// PROPERTY: only a held, not-tombstoned, on-chain-CONFIRMED melt authorizes a delete.
    #[test]
    fn only_a_held_confirmed_melt_deletes() {
        assert_eq!(
            decide_melt(true, false, MeltStatus::Melted),
            MeltDecision::DeleteAndPropagate
        );
        assert_eq!(
            decide_melt(true, false, MeltStatus::Live),
            MeltDecision::Ignore
        );
        assert_eq!(
            decide_melt(true, false, MeltStatus::Unknown),
            MeltDecision::Ignore
        );
        assert_eq!(
            decide_melt(false, false, MeltStatus::Melted),
            MeltDecision::Ignore
        );
        assert_eq!(
            decide_melt(true, true, MeltStatus::Melted),
            MeltDecision::Ignore
        );
    }

    /// PROPERTY: the tombstone CAS admits exactly one transition per store.
    #[test]
    fn tombstone_admits_one_transition() {
        let tomb = TombstoneSet::new();
        assert!(tomb.insert(store(7)), "first insert is the transition");
        assert!(tomb.contains(&store(7)));
        assert!(!tomb.insert(store(7)), "re-insert never re-admits");
    }
}
