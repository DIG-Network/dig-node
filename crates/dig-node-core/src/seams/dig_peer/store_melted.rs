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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dig_gossip::{store_melted_payload, Bytes32, PeerId, StoreMeltedAnnounce};
use dig_tls::bls::SecretKey;
use digstore_chain::coinset::ChainReads;

use crate::{CapsuleStore, KeyManager};

/// Whether a store's singleton is closed (melted), still live, or currently unknowable.
///
/// Derived ONLY from a positive chain read (see [`MeltChain::confirm_melt`]) — never from an
/// announcement's contents or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeltStatus {
    /// The store was minted and its singleton lineage has TERMINATED — the store IS melted. The only
    /// verdict that authorizes a delete.
    Melted,
    /// The lineage is intact, or has not started (a not-yet-minted store) — NEVER delete.
    Live,
    /// The chain could not settle the question — unreachable, errored, or an answer that cannot
    /// distinguish "terminated" from "never indexed". NEVER delete (fail-closed).
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
        self.locked().contains(store_id)
    }

    /// Compare-and-set: insert `store_id`, returning `true` iff it was NEWLY inserted.
    ///
    /// The single-broadcast guarantee rides on this: only the transition that returns `true` may
    /// propagate the melt, so a re-receipt (which returns `false`) never re-emits.
    pub fn insert(&self, store_id: [u8; 32]) -> bool {
        self.locked().insert(store_id)
    }

    /// The guarded set, recovering from poisoning rather than propagating a panic.
    ///
    /// The only code that ever holds this guard is a `HashSet` `contains`/`insert`, so a poisoned
    /// lock cannot mean a half-applied mutation — it only means some OTHER iteration panicked while
    /// this loop's guard happened to be held. Recovering keeps a panic in one melt from permanently
    /// disabling melt propagation for the process's lifetime; `expect`ing here would turn a single
    /// contained panic into a subsystem that panics on every subsequent frame forever.
    fn locked(&self) -> std::sync::MutexGuard<'_, HashSet<[u8; 32]>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// ---------------------------------------------------------------------------------------------
// Seams — the three effects the actuators drive, each a trait so the policy is spy-testable.
// ---------------------------------------------------------------------------------------------

/// The on-chain melt authority (NC-9). The ONLY thing that may authorize a delete.
///
/// Production is [`CoinsetMeltChain`], which resolves the verdict through
/// [`confirm_melt_via_chain`]. A trait so the policy above it is spy-testable.
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

/// The ceiling on the lineage walk. A store deeper than this resolves [`MeltStatus::Unknown`]
/// (fail-closed) rather than costing unbounded chain reads.
///
/// Sized from measurement, not guesswork: across all 53 DataLayer launcher coins on mainnet the
/// deepest live lineage is **599** generations, and 29 of the 53 have their tip one hop from the
/// launcher (mean depth ~7). 10_000 leaves two orders of magnitude of headroom while keeping the
/// walk bounded.
const MAX_LINEAGE_HOPS: usize = 10_000;

/// The deepest live DataLayer lineage measured on mainnet (all 53 launcher coins surveyed).
const DEEPEST_MEASURED_MAINNET_LINEAGE: usize = 599;

/// The ceiling MUST clear real mainnet depth by an order of magnitude, or a perfectly healthy store
/// silently resolves [`MeltStatus::Unknown`] forever. Enforced at COMPILE time rather than by a test:
/// a runtime `assert!` over two constants is folded away and proves nothing, and a test asserting
/// against `MAX_LINEAGE_HOPS` itself puts the same symbol on both sides so it moves with the value.
/// This fails the BUILD if the ceiling is ever cut below the measured floor.
const _: () = assert!(MAX_LINEAGE_HOPS >= DEEPEST_MEASURED_MAINNET_LINEAGE * 10);

/// Resolve `store_id`'s on-chain melt status by walking the singleton lineage along real COIN
/// PARENTAGE, starting from the launcher coin.
///
/// # Why parentage, and nothing else
///
/// Two cheaper-looking signals were tried and BOTH were unsound. They are recorded here because the
/// same shortcuts will look attractive again:
///
/// - **`anchored_root() == Ok(None)`.** That value is the node's fail-closed sentinel for *no
///   confirmed generation* everywhere else ([`crate::AnchoredRootResolver`], `chainwatch`), and
///   [`CoinsetResolver`](crate::CoinsetResolver) produces it for `"launcher coin is unspent (store
///   not minted yet)"` — a store whose lineage has not STARTED. Deleting on it erases live data. A
///   real melt does not even produce it: the walk returns an error for a tip spent without a
///   datastore child.
/// - **The `store_id` hint index.** A hint is an unauthenticated `CREATE_COIN` memo over an
///   arbitrary 32-byte value (#1473), so ANY party can put a record under any store's hint for the
///   price of a dust coin. Measurement settles it: of the 53 DataLayer stores on mainnet, **30 live
///   stores have a completely EMPTY `store_id` hint index** — their generations are not hinted to
///   `store_id` at all. For every one of those, a single planted spent coin would have made the
///   index non-empty and entirely spent, which is indistinguishable from a terminated lineage. The
///   hint index cannot carry a delete decision. `get_coin_records_by_hint` is also truncatable, and
///   truncation surfaces spent records first — the exact order that manufactures a false melt.
///
/// Coin parentage has neither weakness. A coin's `parent_coin_info` is fixed by which coin was
/// actually spent to create it, so **to place a coin anywhere in this walk an attacker must spend a
/// generation of the store — which needs the owner's authority.** The walk is unwritable by anyone
/// but the store's owner, and it never consults a hint.
///
/// # The verdict
///
/// 1. **Identity + minted.** The launcher coin whose `coin_id == store_id` must exist and be SPENT.
///    `coin_id == store_id` is a 256-bit hash preimage that cannot be ground, so this pins the walk
///    to the real store rather than to a singleton that merely *curries* `launcher_id == store_id`
///    (forgeable, #1473). An UNSPENT launcher is [`MeltStatus::Live`] — not minted yet is the
///    opposite of melted. On its own this fact discriminates nothing (it holds for every minted
///    store); it exists to anchor the walk's starting point.
/// 2. **Walk forward.** At each hop, take the children of the current coin and follow the single
///    ODD-amount child — the singleton, whose amount is invariant across generations. Reaching an
///    UNSPENT successor is [`MeltStatus::Live`]. Reaching a spent coin with NO successor is
///    [`MeltStatus::Melted`]: the lineage terminated.
///
/// Everything else fails closed to [`MeltStatus::Unknown`]: any transport error, more than one odd
/// child (ambiguous — never observed across 53 mainnet stores, but it must not guess), and
/// exceeding [`MAX_LINEAGE_HOPS`].
///
/// **Only a COMPLETELY EMPTY children page may conclude a melt, and never at hop 0.** Two distinct
/// hazards make this precise wording load-bearing:
///
/// - *Hop 0.* A minted store's launcher was spent precisely to create the eve singleton, so it
///   always has a child. Zero children at the first hop means the answer is untrustworthy — a
///   non-datastore launcher, or a [`ChainReads`] implementation whose `coin_records_by_parent_ids`
///   is the trait's empty DEFAULT. The one genuinely melted store on mainnet terminates at hop 1.
/// - *Truncation.* The children query honours a server-side limit, and the sibling hint query was
///   measured truncating 349 records (243 unspent) down to a page of 5 with **zero** unspent —
///   truncation surfaces spent records first, exactly the order that manufactures a false verdict.
///   A page that kept an even change coin but dropped the odd successor would otherwise look like a
///   terminated lineage. Requiring the page to be *entirely* empty is what asserts completeness
///   rather than trusting a page: truncation cannot turn a non-empty result set into an empty one
///   short of a zero limit, which is never sent. Children present but no singleton among them is
///   [`MeltStatus::Unknown`].
///
/// The residual assumption is that the coin index cannot report a coin as SPENT while omitting the
/// children created by that same spend — both come from processing the same block. Walking all 53
/// mainnet stores exercised ~380 spent-coin→child steps with no such inconsistency.
pub async fn confirm_melt_via_chain(chain: &dyn ChainReads, store_id: &[u8; 32]) -> MeltStatus {
    let launcher_id = chia_protocol::Bytes32::new(*store_id);

    // FACT 1 — the launcher coin `coin_id == store_id` exists and is SPENT.
    let launcher = match chain.coin_record(launcher_id).await {
        Ok(Some(record)) => record,
        // Nothing was ever minted under this id, so nothing can have melted. For a store we hold
        // content for that is an anomaly, never an authorization — fail closed.
        Ok(None) | Err(_) => return MeltStatus::Unknown,
    };
    if !launcher.spent {
        return MeltStatus::Live;
    }

    // FACT 2 — follow real parentage from the launcher to the end of the lineage.
    let mut current = launcher_id;
    for hop in 0..MAX_LINEAGE_HOPS {
        let children = match chain.coin_records_by_parent_ids(&[current], true).await {
            Ok(children) => children,
            Err(_unreachable) => return MeltStatus::Unknown,
        };
        // Re-check parentage locally rather than trusting that a "children of X" response contains
        // only children of X. The whole soundness argument is that a coin's `parent_coin_info` is
        // fixed by which coin was actually spent to create it; taking the server's word for which
        // coins those are would hand that argument back to whatever answered the query.
        let mut successors = children
            .iter()
            .filter(|child| child.coin.parent_coin_info == current)
            .filter(|child| child.coin.amount % 2 == 1);
        let Some(next) = successors.next() else {
            // Nothing here continues the lineage. Only ONE shape of that is a melt.
            return if hop == 0 {
                // A minted launcher always created the eve singleton. No successor at the first
                // hop means the answer is untrustworthy, not that the store is gone.
                MeltStatus::Unknown
            } else if children.is_empty() {
                // The spend created NOTHING — the lineage terminated.
                MeltStatus::Melted
            } else {
                // Children exist but none is a singleton. This is where a TRUNCATED page lands: the
                // query honours a server-side limit, and a page that dropped the odd successor
                // while keeping an even change coin is indistinguishable from a real melt. Only a
                // COMPLETELY EMPTY page may authorize a delete — truncation cannot manufacture that
                // from a non-empty result set (it would take a limit of zero, which is never sent).
                MeltStatus::Unknown
            };
        };
        if successors.next().is_some() {
            return MeltStatus::Unknown; // ambiguous lineage — never guess which one continues it
        }
        if !next.spent {
            return MeltStatus::Live;
        }
        current = next.coin.coin_id();
    }
    MeltStatus::Unknown
}

/// A short-lived memo of recent [`MeltStatus`] verdicts, keyed by store.
///
/// The walk costs one chain read per generation, and the receive path runs it per inbound
/// announcement for a held store — so without this, a peer could flood announcements for one held
/// store and multiply each cheap frame into a full lineage walk (up to ~600 reads for the deepest
/// store on mainnet). The cache bounds that to one walk per store per [`ttl`](Self::new).
///
/// Caching cannot cause a wrongful delete: a stale `Melted` is impossible to act on twice (the
/// tombstone admits one transition), and a stale `Live`/`Unknown` only DELAYS a real melt by at most
/// the TTL, which the holder watch re-checks on its next tick.
pub struct MeltVerdictCache {
    entries: Mutex<HashMap<[u8; 32], (MeltStatus, Instant)>>,
    ttl: Duration,
}

impl MeltVerdictCache {
    /// A cache whose entries expire after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// The remembered verdict for `store_id`, if one was recorded within the TTL.
    fn get(&self, store_id: &[u8; 32], now: Instant) -> Option<MeltStatus> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .get(store_id)
            .filter(|(_, at)| now.duration_since(*at) < self.ttl)
            .map(|(status, _)| *status)
    }

    /// Remember `status` for `store_id` as of `now`.
    fn put(&self, store_id: [u8; 32], status: MeltStatus, now: Instant) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(store_id, (status, now));
    }
}

/// How long a melt verdict is reused before the lineage is walked again.
const MELT_VERDICT_TTL: Duration = Duration::from_secs(300);

/// Whether store-melt propagation runs at all. Resolved from `DIG_NODE_STORE_MELT`; **default ON** —
/// only an explicit `off`/`0`/`false`/`no` disables it.
///
/// This is the operator's kill switch, and it exists because of what this subsystem does rather than
/// because anything is known to be wrong with it. It is the only path in the node that DELETES
/// content in response to chain state, the deletion is irreversible, and it propagates — so a fault
/// here is correlated across every holder rather than isolated to one node. Its decision function
/// has already been found unsound twice in review (an `Ok(None)` sentinel read as a melt, then an
/// attacker-writable hint index read as a terminated lineage), and both times the fix arrived before
/// release only because someone measured. An operator who suspects a third needs a way to stop the
/// deleting without downgrading the whole node.
///
/// Turning it off is safe and lossless: the node simply keeps content whose store has been melted,
/// which costs disk. Nothing else in the node depends on melt propagation having run. The strictly
/// less destructive background-pull leg already carries the same control
/// (`DIG_NODE_BACKFILL_ON_MISS`); this follows its shape exactly.
pub fn store_melt_enabled() -> bool {
    resolve_store_melt_enabled(std::env::var("DIG_NODE_STORE_MELT").ok().as_deref())
}

/// Pure core of [`store_melt_enabled`], so the policy is unit-tested without touching process-global
/// env. Default ON; only an explicit falsy value disables it.
fn resolve_store_melt_enabled(value: Option<&str>) -> bool {
    !matches!(
        value.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("off") | Some("0") | Some("false") | Some("no")
    )
}

/// The production [`MeltChain`] — [`confirm_melt_via_chain`] over the live coinset view, using the
/// same client (and the same `DIG_NODE_COINSET` override) as every other chain read in the node,
/// behind a short-TTL verdict cache so a flood of announcements cannot multiply into lineage walks.
pub struct CoinsetMeltChain {
    cache: MeltVerdictCache,
}

impl Default for CoinsetMeltChain {
    fn default() -> Self {
        Self::new()
    }
}

impl CoinsetMeltChain {
    /// The production melt chain, with the standard verdict TTL.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: MeltVerdictCache::new(MELT_VERDICT_TTL),
        }
    }
}

#[async_trait::async_trait]
impl MeltChain for CoinsetMeltChain {
    async fn confirm_melt(&self, store_id: &[u8; 32]) -> MeltStatus {
        if let Some(remembered) = self.cache.get(store_id, Instant::now()) {
            return remembered;
        }
        let status =
            confirm_melt_via_chain(&crate::seams::chia_peer::resolution_coinset(), store_id).await;
        self.cache.put(*store_id, status, Instant::now());
        status
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
        let mut removed = 0;
        for capsule in self.cache_list_cached().await {
            // Match on the PARSED 32 bytes, never on the hex TEXT. A capsule id is canonical-hex but
            // NOT canonical-case — `CapsuleKey::parse` admits and preserves mixed case, so the
            // directory name can be `Ab..cD` while `hex::encode` here would produce lowercase. A
            // textual compare therefore matches nothing for such a store while `held_store_ids`
            // (which decodes, and so is case-insensitive) still reports it held: the node would
            // tombstone the store, announce a melt of `generations: 0`, and go on serving the
            // content it just told the network it had deleted. Decoding both sides keeps the
            // held-check and the delete looking at the same identity.
            if parse_hex32(&capsule.store_id).as_ref() == Some(store_id)
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
///
/// A panic while applying a single frame is CONTAINED via
/// [`catch_iteration`](crate::shared::catch_iteration) so it cannot unwind out of the spawned task and
/// silently stop this node from ever ingesting another melt (#2067/#2068). `recv().await` stays at the
/// top of the loop, so a persistently-panicking source blocks on the next frame rather than
/// hot-spinning. A caught panic ABANDONS that frame — fail-closed, since every delete is gated behind
/// the on-chain check that the abandoned iteration never completed.
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
        // The guarded body holds no lock across the catch boundary: the tombstone's std `Mutex` is
        // taken and released inside each `TombstoneSet` call, never held across an await.
        let _ = crate::shared::catch_iteration(
            "store_melted_ingest",
            apply_inbound_melt(&chain, &cache, &broadcaster, &tombstone, sender, &announce),
        )
        .await;
    }
}

/// Apply ONE decoded inbound announcement — the awaited per-frame body of
/// [`run_store_melted_ingest`], split out so the iteration the loop guards against panic-death is a
/// standalone, testable unit.
async fn apply_inbound_melt(
    chain: &Arc<dyn MeltChain>,
    cache: &Arc<dyn MeltCache>,
    broadcaster: &Arc<dyn MeltBroadcast>,
    tombstone: &TombstoneSet,
    sender: PeerId,
    announce: &StoreMeltedAnnounce,
) {
    let outcome = process_inbound(
        &**chain,
        &**cache,
        &**broadcaster,
        tombstone,
        Some(sender),
        announce,
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

    /// TEST 3 — a GENUINE melt (held + a chain-confirmed [`MeltStatus::Melted`]) deletes ALL held
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

    // -- The PRODUCTION melt signal: `confirm_melt_via_chain` over a real `ChainReads` ------------
    //
    // The eight cases above drive a scripted `ChainSpy`, so they prove the POLICY but say nothing
    // about the chain-fact -> `MeltStatus` mapping — the link that has now shipped unsound TWICE
    // (`anchored_root() == Ok(None)` read as a melt; then an attacker-writable hint index read as a
    // terminated lineage). These drive the REAL `ChainReads` trait with a crafted lineage.

    use chia_protocol::{Bytes32 as ChiaBytes32, Coin, CoinSpend, SpendBundle};
    use digstore_chain::coinset::{CoinInfo, CoinRecord};
    use digstore_chain::error::{ChainError, Result as ChainResult};

    /// How the mock answers one read: a value, or a transport failure.
    enum Answer<T> {
        Ok(T),
        Unreachable,
    }

    /// Whether a crafted lineage ends in a melt or carries a live tip.
    enum Lineage {
        Terminated,
        LiveTip,
    }

    /// A chain holding ONE crafted singleton lineage, addressed by coin parentage.
    ///
    /// Only the two reads the gate performs are modelled; every other `ChainReads` method panics, so
    /// the gate cannot silently grow a chain dependency this test cannot see. In particular BOTH
    /// hint queries panic — the gate must never consult an attacker-writable index again.
    struct MockChain {
        launcher: Answer<Option<CoinInfo>>,
        /// parent coin id -> that coin's children.
        children: HashMap<[u8; 32], Vec<CoinRecord>>,
        /// A parent id whose children query fails, modelling a mid-walk outage.
        unreachable_at: Option<[u8; 32]>,
        /// When set, EVERY coin has one spent odd child, so the lineage never ends. Only the hop
        /// ceiling can stop a walk over this chain.
        endless: bool,
        parent_queries: AtomicUsize,
    }

    /// A coin record with an explicit parent + amount, so a real parentage chain can be built.
    fn coin_rec(parent: [u8; 32], amount: u64, spent: bool) -> CoinRecord {
        CoinInfo {
            coin: Coin::new(
                ChiaBytes32::new(parent),
                ChiaBytes32::new([0xC0; 32]),
                amount,
            ),
            spent,
            confirmed_block_index: 10,
            spent_block_index: if spent { 11 } else { 0 },
            timestamp: 0,
            coinbase: false,
        }
    }

    fn id_of(rec: &CoinRecord) -> [u8; 32] {
        rec.coin.coin_id().into()
    }

    impl MockChain {
        /// A launcher record (its own parentage is irrelevant; only `spent` is read).
        fn launcher_coin(spent: bool) -> CoinInfo {
            coin_rec([0xAA; 32], 1, spent)
        }

        /// A minted store (launcher spent) whose lineage runs `generations` singleton hops.
        ///
        /// `Lineage::Terminated` models a melt: the last generation is spent and created no
        /// successor. `Lineage::LiveTip` models a live store: the last generation is unspent.
        fn minted(store_id: [u8; 32], generations: usize, tip: Lineage) -> Self {
            let mut children: HashMap<[u8; 32], Vec<CoinRecord>> = HashMap::new();
            let mut parent = store_id;
            for gen in 0..generations {
                let last = gen + 1 == generations;
                let spent = !(last && matches!(tip, Lineage::LiveTip));
                let rec = coin_rec(parent, 1, spent);
                let id = id_of(&rec);
                children.insert(parent, vec![rec]);
                parent = id;
            }
            // The final coin has no recorded children: for `Terminated` that IS the melt; for
            // `LiveTip` the walk stops at the unspent coin before ever asking.
            children.entry(parent).or_default();
            Self {
                launcher: Answer::Ok(Some(Self::launcher_coin(true))),
                children,
                unreachable_at: None,
                endless: false,
                parent_queries: AtomicUsize::new(0),
            }
        }

        /// A minted store whose lineage NEVER ends: every coin has one spent odd successor.
        fn endless_lineage() -> Self {
            let mut chain = Self::minted(store(0), 1, Lineage::LiveTip);
            chain.endless = true;
            chain
        }

        fn with_launcher(mut self, launcher: Answer<Option<CoinInfo>>) -> Self {
            self.launcher = launcher;
            self
        }

        /// The coin the walk is standing on after `hop` steps (0 = the launcher itself).
        fn coin_at_hop(&self, store_id: [u8; 32], hop: usize) -> [u8; 32] {
            let mut parent = store_id;
            for _ in 0..hop {
                parent = id_of(&self.children[&parent][0]);
            }
            parent
        }

        /// Replace the children at the `hop`th step with coins CORRECTLY parented to that coin,
        /// given as `(amount, spent)`. Taking amounts rather than whole records is deliberate: a
        /// hand-built record is easy to parent to the wrong coin, which would make a test pass via
        /// the parentage filter while appearing to exercise something else.
        fn with_children_at_hop(
            mut self,
            store_id: [u8; 32],
            hop: usize,
            kids: Vec<(u64, bool)>,
        ) -> Self {
            let parent = self.coin_at_hop(store_id, hop);
            self.children.insert(
                parent,
                kids.into_iter()
                    .map(|(amount, spent)| coin_rec(parent, amount, spent))
                    .collect(),
            );
            self
        }

        /// Replace the children at the `hop`th step with coins parented to SOMETHING ELSE — coins the
        /// query returned but that are not actually children of the walked coin.
        fn with_foreign_children_at_hop(
            mut self,
            store_id: [u8; 32],
            hop: usize,
            kids: Vec<CoinRecord>,
        ) -> Self {
            let parent = self.coin_at_hop(store_id, hop);
            self.children.insert(parent, kids);
            self
        }

        fn unreachable_children(mut self, parent: [u8; 32]) -> Self {
            self.unreachable_at = Some(parent);
            self
        }
    }

    #[async_trait::async_trait]
    impl ChainReads for MockChain {
        async fn coin_record(&self, _name: ChiaBytes32) -> ChainResult<Option<CoinInfo>> {
            match &self.launcher {
                Answer::Ok(rec) => Ok(rec.clone()),
                Answer::Unreachable => Err(ChainError::Chain("coinset unreachable".into())),
            }
        }

        async fn coin_records_by_parent_ids(
            &self,
            parent_ids: &[ChiaBytes32],
            include_spent: bool,
        ) -> ChainResult<Vec<CoinRecord>> {
            assert!(
                include_spent,
                "the walk must see SPENT generations or it cannot follow the lineage at all"
            );
            assert_eq!(parent_ids.len(), 1, "the walk follows one coin at a time");
            self.parent_queries.fetch_add(1, Ordering::SeqCst);
            let parent: [u8; 32] = parent_ids[0].into();
            if self.unreachable_at == Some(parent) {
                return Err(ChainError::Chain("coinset unreachable".into()));
            }
            if self.endless {
                // Every coin bears one spent odd successor, whose id differs from its parent's, so
                // the walk always has somewhere to go and only the hop ceiling can end it.
                return Ok(vec![coin_rec(parent, 1, true)]);
            }
            Ok(self.children.get(&parent).cloned().unwrap_or_default())
        }

        async fn coin_records_by_hint(
            &self,
            _hint: ChiaBytes32,
            _include_spent: bool,
        ) -> ChainResult<Vec<CoinRecord>> {
            unreachable!("the melt gate must NEVER consult the attacker-writable hint index")
        }
        async fn unspent_coins_by_hint(&self, _hint: ChiaBytes32) -> ChainResult<Vec<Coin>> {
            unreachable!("the melt gate must NEVER consult the attacker-writable hint index")
        }
        async fn unspent_coins(&self, _ph: ChiaBytes32) -> ChainResult<Vec<Coin>> {
            unimplemented!("the melt gate must not read coins by puzzle hash")
        }
        async fn coin_records_by_puzzle_hash(
            &self,
            _ph: ChiaBytes32,
            _include_spent: bool,
        ) -> ChainResult<Vec<CoinRecord>> {
            unimplemented!("the melt gate must not read coin records by puzzle hash")
        }
        async fn coin_spend(
            &self,
            _coin_id: ChiaBytes32,
            _spent_height: u32,
        ) -> ChainResult<Option<CoinSpend>> {
            unimplemented!("the melt gate must not parse spends (#747-immunity)")
        }
        async fn peak_height(&self) -> ChainResult<u32> {
            unimplemented!("the melt gate must not read the peak")
        }
        async fn push(&self, _bundle: SpendBundle) -> ChainResult<()> {
            unimplemented!("the melt gate is read-only")
        }
        async fn estimate_fee(&self, _bundle: &SpendBundle, _target: u64) -> ChainResult<u64> {
            unimplemented!("the melt gate is read-only")
        }
    }

    /// CHAIN-1 — a GENUINE melt: the launcher is spent and the lineage runs to a spent generation
    /// with no successor. Mirrors the ONE terminated store on mainnet (`cee3e2b0…`), which ends at
    /// hop 1. This is the only shape that authorizes a delete.
    #[tokio::test]
    async fn a_lineage_that_terminates_is_melted() {
        let chain = MockChain::minted(store(1), 2, Lineage::Terminated);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Melted
        );
    }

    /// CHAIN-2 — a LIVE store: the walk reaches an UNSPENT successor. Covers the shape 52 of the 53
    /// mainnet stores have, including the 29 whose tip is one hop from the launcher.
    ///
    /// The deep case is **599** — the deepest live lineage measured on mainnet — not a token 60. A
    /// floor below the real maximum would let the ceiling be cut to a value that cannot resolve a
    /// store that actually exists while the suite stayed green.
    #[tokio::test]
    async fn a_lineage_with_an_unspent_tip_is_live() {
        for generations in [1usize, 2, 7, 599] {
            let chain = MockChain::minted(store(1), generations, Lineage::LiveTip);
            assert_eq!(
                confirm_melt_via_chain(&chain, &store(1)).await,
                MeltStatus::Live,
                "an unspent tip {generations} hops down is a live store"
            );
        }
    }

    /// CHAIN-3 — the hint index is not merely unused, it is UNREACHABLE. 30 of 53 live mainnet
    /// stores have an EMPTY `store_id` hint index, so one planted spent coin under that hint made
    /// the previous gate see "non-empty, all spent" and delete a LIVE store for the price of dust.
    /// The mock panics if either hint query is called, so any gate that reads hints fails outright.
    #[tokio::test]
    async fn the_gate_never_consults_a_hint_index() {
        let chain = MockChain::minted(store(1), 1, Lineage::LiveTip);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Live
        );
    }

    /// CHAIN-4 — the composition the gate called out as untested and lethal: an honest store with an
    /// EMPTY hint index PLUS one planted spent coin. Under parentage that is simply a live store —
    /// the planted coin is not a child of any generation, because creating one would require
    /// spending a generation, which needs the owner's key. Asserts `Live`, and that the verdict cost
    /// exactly ONE parentage read rather than being influenced by the plant.
    #[tokio::test]
    async fn empty_hint_index_plus_a_planted_spent_coin_is_still_live() {
        let store_id = store(0x42);
        // The honest lineage: launcher -> one unspent tip. Nothing is hinted anywhere.
        let mut chain = MockChain::minted(store_id, 1, Lineage::LiveTip);
        // The attacker's coin: spent, amount 1, but parented to a coin THEY own — not to any
        // generation of this store. It is therefore invisible to the walk.
        chain
            .children
            .insert([0xEE; 32], vec![coin_rec([0xEE; 32], 1, true)]);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Live,
            "an empty hint index plus a planted spent coin must NOT read as a terminated lineage"
        );
        assert_eq!(chain.parent_queries.load(Ordering::SeqCst), 1);
    }

    /// CHAIN-5 — an UNSPENT launcher means "not minted yet", NOT melted, and the walk never starts.
    /// This is the regression from the first unsound cut, which deleted on exactly this state.
    #[tokio::test]
    async fn unspent_launcher_is_not_minted_never_melted() {
        let chain = MockChain::minted(store(1), 2, Lineage::Terminated)
            .with_launcher(Answer::Ok(Some(MockChain::launcher_coin(false))));
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Live
        );
        assert_eq!(
            chain.parent_queries.load(Ordering::SeqCst),
            0,
            "the launcher fact settles it; the lineage is never walked"
        );
    }

    /// CHAIN-6 — hop-0 emptiness is NOT a melt. A minted launcher always created the eve singleton,
    /// so no children at the first hop means the answer is untrustworthy — a non-datastore launcher,
    /// or a `ChainReads` whose `coin_records_by_parent_ids` is the trait's empty DEFAULT impl. That
    /// default would otherwise turn every store into an instant `Melted`.
    #[tokio::test]
    async fn no_children_at_the_launcher_is_unknown_not_melted() {
        let chain = MockChain::minted(store(1), 1, Lineage::LiveTip).with_children_at_hop(
            store(1),
            0,
            vec![],
        );
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Unknown,
            "an empty first hop must never authorize an irreversible delete"
        );
    }

    /// CHAIN-7 — an EVEN-amount child is not a singleton successor, but neither is it evidence of a
    /// melt. This is where a TRUNCATED page lands: `coin_records_by_parent_ids` honours a
    /// server-side limit, and a page that kept an even change coin while dropping the odd successor
    /// is indistinguishable from a terminated lineage. Only a COMPLETELY EMPTY page may delete, so
    /// this must be `Unknown`.
    ///
    /// The sibling hint query was measured truncating 349 records (243 unspent) to a page of 5 with
    /// zero unspent — spent records first — so this hazard is real, not theoretical.
    #[tokio::test]
    async fn a_page_with_children_but_no_singleton_is_unknown_not_melted() {
        let store_id = store(3);
        let chain = MockChain::minted(store_id, 2, Lineage::Terminated).with_children_at_hop(
            store_id,
            1,
            vec![(2, false)],
        );
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Unknown,
            "a non-empty page without a singleton may be a truncated page — never delete on it"
        );
    }

    /// CHAIN-15 — a coin the query returned that is NOT actually parented to the walked coin is
    /// ignored. The soundness argument is that `parent_coin_info` is fixed by which coin was spent to
    /// create it; taking the server's word for membership of a "children of X" page would hand that
    /// argument straight back to whatever answered the query. A page of foreign coins is `Unknown`
    /// (non-empty, no successor) — never a melt.
    #[tokio::test]
    async fn a_child_not_parented_to_the_walked_coin_is_ignored() {
        let store_id = store(7);
        let chain = MockChain::minted(store_id, 2, Lineage::Terminated)
            // Spent, odd, superficially a perfect successor — but parented elsewhere.
            .with_foreign_children_at_hop(store_id, 1, vec![coin_rec([0xF0; 32], 1, true)]);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Unknown,
            "a foreign coin must never be walked as if it continued the lineage"
        );
    }

    /// CHAIN-16 — a foreign coin sitting BESIDE the genuine successor must not divert the walk: the
    /// real child is still followed and the lineage still resolves `Live`. With CHAIN-15 this pins
    /// the parentage filter in both directions — exclude impostors without discarding the true
    /// successor (a filter that dropped everything would make CHAIN-15 pass for the wrong reason).
    #[tokio::test]
    async fn a_foreign_coin_beside_the_real_successor_does_not_divert_the_walk() {
        let store_id = store(8);
        let mut chain = MockChain::minted(store_id, 2, Lineage::LiveTip);
        let real = chain.children[&store_id][0].clone();
        chain
            .children
            .insert(store_id, vec![coin_rec([0xF0; 32], 1, true), real]);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Live,
            "the genuine successor must still be followed past an impostor"
        );
    }

    /// CHAIN-13 — the planted-coin composition in its DANGEROUS form. CHAIN-4 covers a planted coin
    /// beside a lineage we can fully resolve as live; this covers one beside a lineage we CANNOT
    /// resolve (the chain fails mid-walk). The verdict must be `Unknown` — the planted coin must
    /// never supply the evidence the honest lineage failed to.
    #[tokio::test]
    async fn a_planted_coin_beside_an_unresolvable_lineage_is_unknown() {
        let store_id = store(0x43);
        let mut chain =
            MockChain::minted(store_id, 3, Lineage::LiveTip).unreachable_children(store_id);
        // The attacker's spent coin, parented to a coin they own — never to a generation of S.
        chain
            .children
            .insert([0xEE; 32], vec![coin_rec([0xEE; 32], 1, true)]);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Unknown,
            "an unresolvable lineage plus a planted coin must resolve Unknown, never Melted"
        );
    }

    /// CHAIN-8 — two odd children is ambiguous and must never be resolved by guessing which one
    /// continues the lineage. Fail closed.
    #[tokio::test]
    async fn an_ambiguous_fork_is_unknown() {
        let store_id = store(4);
        // Both are genuinely parented to the walked coin, so the fork is real rather than an
        // artefact of the parentage filter dropping one of them.
        let chain = MockChain::minted(store_id, 2, Lineage::Terminated).with_children_at_hop(
            store_id,
            1,
            vec![(1, true), (3, true)],
        );
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Unknown
        );
    }

    /// CHAIN-9 — a transport failure on the launcher read is fail-closed; the walk never starts.
    #[tokio::test]
    async fn unreachable_chain_on_the_launcher_read_is_unknown() {
        let chain =
            MockChain::minted(store(1), 2, Lineage::Terminated).with_launcher(Answer::Unreachable);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Unknown
        );
        assert_eq!(chain.parent_queries.load(Ordering::SeqCst), 0);
    }

    /// CHAIN-10 — a transport failure MID-WALK is fail-closed. An outage part-way down the lineage
    /// must not read as "the lineage ended here"; that collapse is how a transient coinset failure
    /// would become a correlated, network-wide deletion.
    #[tokio::test]
    async fn unreachable_chain_mid_walk_is_unknown() {
        let store_id = store(5);
        let chain = MockChain::minted(store_id, 3, Lineage::LiveTip).unreachable_children(store_id);
        assert_eq!(
            confirm_melt_via_chain(&chain, &store_id).await,
            MeltStatus::Unknown
        );
    }

    /// CHAIN-11 — an absent launcher coin: nothing was minted under this identity, so nothing can
    /// have melted.
    #[tokio::test]
    async fn absent_launcher_coin_is_unknown() {
        let chain =
            MockChain::minted(store(1), 2, Lineage::Terminated).with_launcher(Answer::Ok(None));
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(1)).await,
            MeltStatus::Unknown
        );
        assert_eq!(chain.parent_queries.load(Ordering::SeqCst), 0);
    }

    /// CHAIN-12 — the walk is BOUNDED against a lineage that never ends, and exhausting the ceiling
    /// is `Unknown`, never a melt.
    ///
    /// Asserts a LITERAL, not `MAX_LINEAGE_HOPS`. Comparing the observed read count against the same
    /// constant the code uses puts the symbol on both sides, so the assertion moves with the value:
    /// cutting the ceiling to 100 kept this green while silently making the walk unable to resolve
    /// the 599-generation store that exists on mainnet. Only a literal pins the number in force.
    #[tokio::test]
    async fn an_endless_lineage_fails_closed_at_exactly_ten_thousand_hops() {
        let chain = MockChain::endless_lineage();
        assert_eq!(
            confirm_melt_via_chain(&chain, &store(0)).await,
            MeltStatus::Unknown,
            "exhausting the hop ceiling must fail closed, never conclude a melt"
        );
        assert_eq!(
            chain.parent_queries.load(Ordering::SeqCst),
            10_000,
            "the ceiling in force must be exactly 10_000 hops"
        );
    }

    /// CACHE-1 — a repeated verdict for the same store is served from memory, so a flood of
    /// announcements for one held store cannot multiply into repeated lineage walks.
    #[test]
    fn the_verdict_cache_serves_a_repeat_within_its_ttl() {
        let cache = MeltVerdictCache::new(Duration::from_secs(300));
        let now = Instant::now();
        assert_eq!(cache.get(&store(1), now), None, "cold cache has no verdict");
        cache.put(store(1), MeltStatus::Live, now);
        assert_eq!(cache.get(&store(1), now), Some(MeltStatus::Live));
    }

    /// CACHE-2 — an expired verdict is NOT served, so a real melt is delayed by at most the TTL.
    #[test]
    fn the_verdict_cache_expires() {
        let ttl = Duration::from_secs(300);
        let cache = MeltVerdictCache::new(ttl);
        let now = Instant::now();
        cache.put(store(1), MeltStatus::Live, now);
        let later = now + ttl + Duration::from_secs(1);
        assert_eq!(
            cache.get(&store(1), later),
            None,
            "an expired verdict must force a fresh walk"
        );
    }

    // -- The REAL `MeltCache`: the only code here that actually unlinks files ---------------------
    //
    // Every case above drives `CacheSpy`, so none of them touch `MeltCache for Arc<Node>` — the impl
    // that does the deleting. Inverting its match (`==` -> `!=`, i.e. delete every OTHER store) left
    // the whole suite green. These drive the real impl against a real cache directory.

    /// Write a cached capsule at `<cache>/modules/<store_hex>/<root_hex>.dig`, verbatim — `store_hex`
    /// is used exactly as given so a MIXED-CASE directory can be modelled.
    fn write_cached_capsule(cache_dir: &std::path::Path, store_hex: &str, root_hex: &str) {
        let dir = cache_dir.join("modules").join(store_hex);
        std::fs::create_dir_all(&dir).expect("create store dir");
        std::fs::write(dir.join(format!("{root_hex}.dig")), b"capsule").expect("write capsule");
    }

    /// REAL-1 — the real `MeltCache` deletes the named store's generations and NOTHING else.
    ///
    /// Catches an inverted match: with `==` flipped to `!=` the node would unlink every OTHER store
    /// in the cache and leave the melted one in place, which no `CacheSpy` test can see.
    #[tokio::test]
    async fn the_real_cache_deletes_only_the_named_store() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let target = "aa".repeat(32);
        let bystander = "bb".repeat(32);
        write_cached_capsule(td.path(), &target, &"11".repeat(32));
        write_cached_capsule(td.path(), &target, &"22".repeat(32));
        write_cached_capsule(td.path(), &bystander, &"33".repeat(32));

        let target_id = parse_hex32(&target).expect("64-hex");
        let cache: &dyn MeltCache = &node;

        assert!(
            cache.held_store_ids().await.contains(&target_id),
            "precondition: the store is held"
        );
        assert_eq!(
            cache.delete_all_generations(&target_id).await,
            2,
            "both generations of the target are unlinked"
        );
        let held_after = cache.held_store_ids().await;
        assert!(!held_after.contains(&target_id), "the target is gone");
        assert!(
            held_after.contains(&parse_hex32(&bystander).expect("64-hex")),
            "a bystander store MUST survive — an inverted match would delete it instead"
        );
    }

    /// REAL-2 — a MIXED-CASE store directory is deleted, not silently skipped.
    ///
    /// `CapsuleKey::parse` admits and preserves mixed case (`is_canonical_hex_id` accepts any ASCII
    /// hex digit, with its own test asserting `Ab..cD` parses), so a mixed-case cache directory is
    /// reachable. `held_store_ids` DECODES the hex and so is case-insensitive; a delete that compared
    /// the hex TEXT against `hex::encode` (always lowercase) matched nothing. The node would then
    /// tombstone the store, broadcast a melt of `generations: 0`, and keep serving the content it had
    /// just announced as deleted — a melt reported but not performed.
    #[tokio::test]
    async fn the_real_cache_deletes_a_mixed_case_store_directory() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let mixed = format!("{}{}", "Ab".repeat(16), "cD".repeat(16));
        write_cached_capsule(td.path(), &mixed, &"44".repeat(32));

        let store_id = parse_hex32(&mixed).expect("mixed-case hex still decodes");
        let cache: &dyn MeltCache = &node;

        assert!(
            cache.held_store_ids().await.contains(&store_id),
            "the held-check decodes, so it already sees a mixed-case store"
        );
        assert_eq!(
            cache.delete_all_generations(&store_id).await,
            1,
            "the delete must match the same identity the held-check matched, not the hex casing"
        );
        assert!(
            !cache.held_store_ids().await.contains(&store_id),
            "the store is really gone from disk"
        );
    }

    /// REAL-3 — deleting a store this node does not hold unlinks nothing and reports zero.
    #[tokio::test]
    async fn the_real_cache_deletes_nothing_for_an_unheld_store() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        write_cached_capsule(td.path(), &"cc".repeat(32), &"55".repeat(32));
        let cache: &dyn MeltCache = &node;

        assert_eq!(cache.delete_all_generations(&store(0x7E)).await, 0);
        assert_eq!(
            cache.held_store_ids().await.len(),
            1,
            "the unrelated store is untouched"
        );
    }

    /// CAS-1 — the tombstone CAS admits exactly ONE winner under REAL concurrency.
    ///
    /// `convergence_terminates_at_holder_count` drives receipts sequentially, so gate 2 catches the
    /// echo and the CAS is never actually under test — dropping the CAS entirely left that test
    /// green. Concurrency is real here (the ingest task and the holder tick share one `TombstoneSet`),
    /// and the consequence of losing the CAS is a double broadcast. This races many threads on one
    /// store and asserts a single winner.
    #[test]
    fn the_tombstone_cas_admits_one_winner_under_contention() {
        let tomb = TombstoneSet::new();
        let winners = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(16));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let tomb = tomb.clone();
                let winners = Arc::clone(&winners);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait(); // maximise the overlap on the insert
                    if tomb.insert(store(0x9C)) {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "exactly one racer may take the holding->deleted transition, or the melt double-broadcasts"
        );
    }

    /// KILL-1 — the operator kill switch defaults ON and is turned off ONLY by an explicit falsy
    /// value, matching `DIG_NODE_BACKFILL_ON_MISS` exactly. Tested through the pure core so it never
    /// touches process-global env.
    #[test]
    fn the_kill_switch_defaults_on_and_honours_explicit_off() {
        assert!(resolve_store_melt_enabled(None), "absent means ON");
        assert!(
            resolve_store_melt_enabled(Some("")),
            "empty is not a disable"
        );
        for on in ["on", "1", "true", "yes", "anything-else"] {
            assert!(
                resolve_store_melt_enabled(Some(on)),
                "{on} must leave melt ON"
            );
        }
        for off in ["off", "0", "false", "no", "OFF", " Off ", "FALSE"] {
            assert!(
                !resolve_store_melt_enabled(Some(off)),
                "{off} must disable melt propagation"
            );
        }
    }

    /// CAS-2 — the tombstone CAS in `process_inbound` (gate 4) admits ONE transition when two
    /// receipts genuinely race past gate 2.
    ///
    /// `convergence_terminates_at_holder_count` drives receipts SEQUENTIALLY, so gate 2 always
    /// catches the echo and gate 4 is never under test — deleting the CAS entirely left that test
    /// green while the doc above it claimed concurrency protection. The race is real: the ingest task
    /// and the holder watch share one `TombstoneSet`.
    ///
    /// The race is made DETERMINISTIC rather than hoped for: the chain spy holds both callers at a
    /// barrier inside `confirm_melt`, so both are guaranteed to have passed gate 2 (the
    /// `contains` check) before either reaches gate 4. Without the CAS both would then delete and
    /// broadcast; with it, exactly one does.
    struct BarrierChainSpy {
        gate: tokio::sync::Barrier,
    }
    #[async_trait::async_trait]
    impl MeltChain for BarrierChainSpy {
        async fn confirm_melt(&self, _store_id: &[u8; 32]) -> MeltStatus {
            self.gate.wait().await;
            MeltStatus::Melted
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_receipts_broadcast_exactly_once() {
        let chain = Arc::new(BarrierChainSpy {
            gate: tokio::sync::Barrier::new(2),
        });
        let cache = Arc::new(CacheSpy::holding(&[store(1)], 3));
        let bc = Arc::new(BroadcastSpy::default());
        let tomb = TombstoneSet::new();
        let announce = announce_for(store(1));

        let one = {
            let (chain, cache, bc, tomb, announce) = (
                Arc::clone(&chain),
                Arc::clone(&cache),
                Arc::clone(&bc),
                tomb.clone(),
                announce.clone(),
            );
            tokio::spawn(async move {
                process_inbound(&*chain, &*cache, &*bc, &tomb, None, &announce).await
            })
        };
        let two = {
            let (chain, cache, bc, tomb, announce) = (
                Arc::clone(&chain),
                Arc::clone(&cache),
                Arc::clone(&bc),
                tomb.clone(),
                announce.clone(),
            );
            tokio::spawn(async move {
                process_inbound(&*chain, &*cache, &*bc, &tomb, None, &announce).await
            })
        };
        let outcomes = [one.await.expect("task"), two.await.expect("task")];

        let propagated = outcomes
            .iter()
            .filter(|o| matches!(o, PropagateOutcome::Propagated { .. }))
            .count();
        assert_eq!(
            propagated, 1,
            "exactly one racing receipt may take the holding->deleted transition"
        );
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "a lost CAS means the melt is broadcast twice from one node"
        );
        assert_eq!(
            cache.deleted.lock().unwrap().len(),
            1,
            "and the delete is attempted twice"
        );
    }
}
