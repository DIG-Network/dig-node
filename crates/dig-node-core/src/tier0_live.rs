//! Tier-0 eager-precache LIVE-WIRE (epic #1934, child 4b/7 — PR-3, the flywheel goes live).
//!
//! [`crate::tier0_prefetch`] owns the GOVERNED round orchestration ([`run_round`]) and the three
//! network/node SEAMS it drives — [`Tier0Fetcher`], [`SizeProbe`], [`LoadSignal`] — but leaves them
//! abstract so the governance is unit-tested without a live node. This module supplies the CONCRETE
//! implementations and SPAWNS the round loop at node bring-up, so a fleet node with an empty cache
//! autonomously fills its tier-0 budget from the DHT, becomes a discoverable provider, and yields to
//! tier-1 under real demand — the epic payoff.
//!
//! # The pipeline this wires
//!
//! ```text
//!   sampled content-key H (4a probe, quorum-reconciled)
//!     → PREIMAGE lookup: find providers (DHT find_node) → dig.resolveCapsule → VerifiedCapsuleKey
//!       (H == to_key(store,root), self-verified — a forged preimage is UNREPRESENTABLE, PR-2)
//!     → CHAIN-ANCHOR gate: verify_pinned_root(store, root) — the root MUST be the store's live
//!       on-chain tip, else DROP (a real-but-melted/stale/never-anchored root is refused, GATE 2)
//!     → CAPPED verified pull: CapsuleWarmer::warm_capped(store, root, max_bytes) — merkle-verify
//!       against the chain-anchored root, hard byte-cap, cache tagged Tier0Precache, ANNOUNCE holder
//! ```
//!
//! # The two NON-NEGOTIABLE gates (carried from PR-1/PR-2's adversarial + security review)
//!
//! 1. **CHAIN-ANCHOR (GATE 2).** A [`VerifiedCapsuleKey`] proves `to_key(store,root)==H` but NOT that
//!    `root` is the store's CURRENT chain-anchored generation. Before ANY fetch/cache, the pair passes
//!    [`AnchoredRootResolver::verify_pinned_root`] (a bounded coinset check) — enforced BOTH explicitly
//!    here (fail fast, no wasted pull) AND again inside [`CapsuleWarmer::warm_capped`] (defense in
//!    depth, the same [`ChainAnchoredModuleVerifier`] the reshare leg trusts). No fetch result is ever
//!    cached on a bare `VerifiedCapsuleKey`.
//! 2. **HARD-CAP `size_bytes`.** The `size_bytes` in a resolve answer is a provider-reported HINT. It
//!    is NEVER an allocation size or a cache-admission gate: [`run_round`] already caps the fetcher's
//!    `max_bytes` at `min(hint, remaining_sub_budget)`, and [`CapsuleWarmer::warm_capped`] lowers the
//!    pull's `max_module_size` to that ceiling, so an adversarial huge `size_bytes` (e.g. `u64::MAX`)
//!    can neither over-allocate nor bypass the tier-0 budget — the TRUE store size governs.
//!
//! # Anti-Sybil + amplification posture (unchanged, carried forward)
//!
//! Candidates come only from the quorum-reconciled 4a probe (identity bound to the verified mTLS SPKI,
//! never the payload). The loop is self-driven, rate-limited by ONE [`RoundRateLimiter`] shared across
//! ALL rounds (a fresh limiter per round would defeat the ceiling), and yields entirely to real inbound
//! demand via [`LoadSignal`].

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use digstore_core::Bytes32;

use crate::dht_sampling::{NeighbourhoodProbe, SplitMix64};
use crate::relevance::{NodeContext, RelevanceWeights};
use crate::seams::dig_peer::capsule_resolver::{CapsuleKeyResolver, MtlsCapsuleResolveClient};
use crate::seams::dig_peer::neighbourhood_probe::KeyspaceRouter;
use crate::seams::dig_peer::{CapsuleWarmer, WarmFailure, WarmOutcome};
use crate::shared::AnchoredRootResolver;
use crate::tier0_prefetch::{
    run_round, should_run_loop, tier0_precache_enabled, DiscardReason, FetchOutcome, LoadSignal,
    RoundRateLimiter, SizeProbe, Tier0Fetcher,
};

// =================================================================================================
// Process-global telemetry — the wired flag, the load gauge, the tier-0 land counter
// =================================================================================================

/// Whether the tier-0 precache loop has been spawned + wired this process. Read by `cache.stats`
/// (SPEC §7.10e/f) so a controller can tell "the flywheel is live" from "the seam is inert".
static TIER0_WIRED: AtomicBool = AtomicBool::new(false);

/// The count of stores this process's tier-0 loop has landed in the cache — the `cache.stats`
/// `tier0_precache.occupancy` figure. A monotonic land counter, not a live occupancy (an evicted
/// precache store still counts); reported as the best available tier-0 signal until an
/// eviction-aware ledger lands.
static TIER0_LANDED: AtomicU64 = AtomicU64::new(0);

/// The unix-ms timestamp of the most recent inbound serve/demand event, `0` if none yet. The
/// [`InboundLoadSignal`] reads it to back off tier-0 while the node is serving real demand.
static INBOUND_ACTIVITY_MS: AtomicU64 = AtomicU64::new(0);

/// How recently an inbound-demand event must have fired for the node to count as BUSY. Tier-0 is
/// opportunistic, so a short cooldown keeps a burst of real reads holding the loop off without
/// starving precache during genuine idle.
const BUSY_COOLDOWN_MS: u64 = 5_000;

/// Milliseconds since the unix epoch (saturating to `0` before 1970, which cannot occur here).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Record that the node just served / was asked to serve real inbound demand. Called from the
/// inbound-demand path ([`crate::Node::note_inbound_demand`]) so tier-0 yields to real load (#1934).
pub(crate) fn mark_inbound_activity() {
    INBOUND_ACTIVITY_MS.store(now_ms(), Ordering::Relaxed);
}

/// The ledger of store ids THIS process's tier-0 loop has landed in `<cache>/modules` — the tier tag
/// the modules-cache eviction sweep reads so a purely-precached store is the SACRIFICIAL tier (evicted
/// before demand-driven content, [`crate::Node::evict_modules_if_needed`]).
///
/// In-memory + process-scoped by design: a store landed by tier-0 is `Tier0Precache` while this process
/// runs (so the loop plateaus at cap by evicting its OWN older lands first); after a restart an
/// unlabeled on-disk module is treated as demand content (protected) and bounded only by plain LRU — a
/// fail-SAFE default that can never wrongly evict genuinely-demanded content.
fn tier0_land_ledger() -> &'static Mutex<HashSet<String>> {
    static LEDGER: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Record that the tier-0 loop landed `store_hex`, so the eviction sweep sacrifices it before demand.
pub(crate) fn mark_tier0_land(store_hex: &str) {
    tier0_land_ledger()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(store_hex.to_string());
}

/// Whether `store_hex` is a tier-0 precache land of THIS process (the eviction sweep's tier input).
#[must_use]
pub(crate) fn is_tier0_precache(store_hex: &str) -> bool {
    tier0_land_ledger()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains(store_hex)
}

/// Drop `store_hex` from the tier-0 ledger — called when the eviction sweep removes its last module, so
/// the ledger cannot grow without bound as stores are precached then evicted.
pub(crate) fn forget_tier0_land(store_hex: &str) {
    tier0_land_ledger()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(store_hex);
}

/// Whether the tier-0 precache loop is wired live this process (`cache.stats` §7.10e/f).
#[must_use]
pub(crate) fn tier0_wired() -> bool {
    TIER0_WIRED.load(Ordering::Relaxed)
}

/// The number of stores this process's tier-0 loop has landed (`cache.stats` occupancy figure).
#[must_use]
pub(crate) fn tier0_occupancy() -> u64 {
    TIER0_LANDED.load(Ordering::Relaxed)
}

/// The live inbound-load signal: BUSY iff a real inbound-demand event fired within [`BUSY_COOLDOWN_MS`].
///
/// A busy round yields entirely ([`crate::tier0_prefetch::RoundSkip::Busy`]) so speculative precache
/// never competes with real serving for bandwidth.
struct InboundLoadSignal;

impl LoadSignal for InboundLoadSignal {
    fn is_busy(&self) -> bool {
        let last = INBOUND_ACTIVITY_MS.load(Ordering::Relaxed);
        last != 0 && now_ms().saturating_sub(last) < BUSY_COOLDOWN_MS
    }
}

// =================================================================================================
// The fetcher's internal seams — each a small trait so the two gates are unit-tested with fakes
// =================================================================================================

/// A self-verified capsule preimage a fetch acts on: the `(store_id, root)` that provably hashes to
/// the sampled content-key, plus the provider-reported `size_bytes` HINT (hard-capped at fetch, never
/// trusted as an allocation size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Preimage {
    store_id: [u8; 32],
    root: [u8; 32],
    size_bytes: u64,
}

/// Turn a sampled DHT content-key into a self-verified `(store_id, root)` preimage by asking providers
/// and recomputing every answer ([`CapsuleKeyResolver`]). A seam so the fetcher + size probe are
/// tested without a socket. `None` when no provider yields a verifiable preimage.
#[async_trait]
trait PreimageLookup: Send + Sync {
    async fn lookup(&self, content_id: [u8; 32]) -> Option<Preimage>;
}

/// The chain-anchor gate (GATE 2): whether `root` is `store_id`'s CURRENT on-chain generation. A seam
/// over [`AnchoredRootResolver::verify_pinned_root`] so the gate is tested without a chain.
#[async_trait]
trait ChainAnchorGate: Send + Sync {
    async fn is_anchored(&self, store_id: [u8; 32], root: [u8; 32]) -> bool;
}

/// The verdict of a byte-capped, chain-anchored capsule warm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarmVerdict {
    /// The store was verified, cached (tier-0), and announced; the value is the true cached bytes.
    Cached(u64),
    /// The true store size exceeded the hard byte cap — nothing cached.
    OverCap,
    /// The chain could not confirm the generation — nothing cached (belt-and-suspenders with the
    /// explicit gate, since the warmer re-checks internally).
    NotAnchored,
    /// The pull could not complete (no holders, refused, or already warming) — nothing cached.
    Unavailable,
}

/// Fetch + merkle-verify + hard-byte-cap + cache + announce ONE `(store, root)`. A seam over
/// [`CapsuleWarmer::warm_capped`] so the fetcher is tested without a live pull.
#[async_trait]
trait CappedWarm: Send + Sync {
    async fn warm(&self, store_id: [u8; 32], root: [u8; 32], max_bytes: u64) -> WarmVerdict;
}

/// Run the tier-aware, size-capped LRU sweep over `<cache>/modules` so the self-driven precache loop
/// plateaus at the cache cap instead of growing to disk-exhaustion. A seam over
/// [`crate::Node::evict_modules_if_needed`] so the fetcher's post-land trigger is tested without a Node.
///
/// Shared with the reshare leg (#2053): the [`CapsuleWarmer`](crate::seams::dig_peer::CapsuleWarmer)
/// runs this SAME sweep after a reshare-warm land, so the tier-0 precache loop and the read-triggered
/// reshare both bound `<cache>/modules` through one implementation — no second, driftable evictor.
#[async_trait]
pub(crate) trait ModulesCacheEvictor: Send + Sync {
    async fn evict_if_needed(&self);
}

// =================================================================================================
// The concrete SizeProbe + Tier0Fetcher (composed from the seams above)
// =================================================================================================

/// The production [`SizeProbe`]: resolve the candidate's preimage and report its provider `size_bytes`
/// hint. The hint only feeds the selector's budget fit — the true size is enforced at fetch — so an
/// absurd hint merely keeps the candidate from being selected, never over-allocates.
struct Tier0SizeProbe {
    lookup: Arc<dyn PreimageLookup>,
}

#[async_trait]
impl SizeProbe for Tier0SizeProbe {
    async fn resolve_size(&self, content_id: [u8; 32]) -> Option<u64> {
        self.lookup
            .lookup(content_id)
            .await
            .map(|p| p.size_bytes)
            .filter(|&s| s > 0)
    }
}

/// The production [`Tier0Fetcher`]: resolve the preimage, ENFORCE the chain-anchor gate, then run the
/// byte-capped verified warm. Structurally incapable of caching content on a bare `VerifiedCapsuleKey`
/// — the gate sits between the resolve and the pull.
struct NodeTier0Fetcher {
    lookup: Arc<dyn PreimageLookup>,
    gate: Arc<dyn ChainAnchorGate>,
    warm: Arc<dyn CappedWarm>,
    evictor: Arc<dyn ModulesCacheEvictor>,
}

#[async_trait]
impl Tier0Fetcher for NodeTier0Fetcher {
    async fn fetch_and_cache(&self, content_id: [u8; 32], max_bytes: u64) -> FetchOutcome {
        // 1. Resolve the self-verified preimage. No provider answer → nothing to fetch.
        let Some(preimage) = self.lookup.lookup(content_id).await else {
            return FetchOutcome::Discarded(DiscardReason::Unavailable);
        };
        // 2. GATE 2 — chain-anchor. A real-but-melted/stale/never-anchored root is refused here, BEFORE
        //    any bandwidth is spent, so no fetch or cache ever acts on an unanchored root.
        if !self
            .gate
            .is_anchored(preimage.store_id, preimage.root)
            .await
        {
            return FetchOutcome::Discarded(DiscardReason::VerifyFailed);
        }
        // 3. Byte-capped, chain-anchored, merkle-verified pull → cache (tier-0) → announce.
        match self
            .warm
            .warm(preimage.store_id, preimage.root, max_bytes)
            .await
        {
            WarmVerdict::Cached(bytes) => {
                // Tag the land so the modules-cache sweep treats it as the sacrificial tier, then run
                // the tier-aware size-cap eviction so the self-driven loop PLATEAUS at the cache cap
                // instead of growing `<cache>/modules` to disk-exhaustion.
                mark_tier0_land(&hex::encode(preimage.store_id));
                TIER0_LANDED.fetch_add(1, Ordering::Relaxed);
                self.evictor.evict_if_needed().await;
                FetchOutcome::Cached(bytes)
            }
            WarmVerdict::OverCap => FetchOutcome::Discarded(DiscardReason::ExceededByteCap),
            WarmVerdict::NotAnchored => FetchOutcome::Discarded(DiscardReason::VerifyFailed),
            WarmVerdict::Unavailable => FetchOutcome::Discarded(DiscardReason::Unavailable),
        }
    }
}

// =================================================================================================
// Production seam implementations — DHT preimage lookup, resolver gate, warmer
// =================================================================================================

/// The production [`PreimageLookup`]: route toward the sampled key's DHT neighbourhood
/// ([`KeyspaceRouter::find_node`]), then ask each contact to resolve the preimage over mTLS, taking the
/// first SELF-VERIFIED answer. IPv6-first dialing is inherited from the shared NAT dial path (§5.2).
struct DhtPreimageLookup {
    router: Arc<dig_dht::DhtService>,
    resolver: CapsuleKeyResolver<MtlsCapsuleResolveClient>,
}

#[async_trait]
impl PreimageLookup for DhtPreimageLookup {
    async fn lookup(&self, content_id: [u8; 32]) -> Option<Preimage> {
        for contact in KeyspaceRouter::find_node(&self.router, content_id).await {
            if let Some(verified) = self
                .resolver
                .resolve_from(&contact, &[content_id])
                .await
                .into_iter()
                .next()
            {
                return Some(Preimage {
                    store_id: verified.store_id(),
                    root: verified.root(),
                    size_bytes: verified.size_bytes(),
                });
            }
        }
        None
    }
}

/// The production [`ChainAnchorGate`] over the node's [`AnchoredRootResolver`]: the root is anchored iff
/// the bounded `verify_pinned_root` coinset check confirms it is the store's live on-chain tip.
struct ResolverAnchorGate {
    resolver: Arc<dyn AnchoredRootResolver>,
}

#[async_trait]
impl ChainAnchorGate for ResolverAnchorGate {
    async fn is_anchored(&self, store_id: [u8; 32], root: [u8; 32]) -> bool {
        self.resolver
            .verify_pinned_root(&store_id, Bytes32(root))
            .await
            .is_ok()
    }
}

/// The production [`CappedWarm`] over the node's ONE [`CapsuleWarmer`] — reused so tier-0 precache and
/// the #1576 reshare leg can never drift in how they verify, cache, or announce.
struct WarmerCappedWarm {
    warmer: Arc<CapsuleWarmer>,
}

#[async_trait]
impl CappedWarm for WarmerCappedWarm {
    async fn warm(&self, store_id: [u8; 32], root: [u8; 32], max_bytes: u64) -> WarmVerdict {
        let store_hex = hex::encode(store_id);
        let root_hex = hex::encode(root);
        match self
            .warmer
            .warm_capped(&store_hex, &root_hex, max_bytes)
            .await
        {
            // Defense in depth: even though `warm_capped` lowered `max_module_size` to `max_bytes`, a
            // landed store larger than the cap is refused rather than counted (it must never happen).
            WarmOutcome::Held { bytes } if bytes <= max_bytes => WarmVerdict::Cached(bytes),
            WarmOutcome::Held { .. } => WarmVerdict::OverCap,
            // Already a holder — nothing new landed, but the store is present + announced. Zero bytes so
            // the round's byte tally is honest.
            WarmOutcome::AlreadyHeld => WarmVerdict::Cached(0),
            WarmOutcome::Refused(WarmFailure::NoChainAnchor) => WarmVerdict::NotAnchored,
            WarmOutcome::Refused(_) | WarmOutcome::AlreadyWarming => WarmVerdict::Unavailable,
        }
    }
}

/// The production [`ModulesCacheEvictor`] over the node's tier-aware modules-cache sweep — the
/// standing-occupancy bound that keeps the self-driven precache loop from exhausting disk. Shared with
/// the reshare leg (#2053) so both land paths sweep through the one Node implementation.
pub(crate) struct NodeModulesEvictor {
    node: Arc<crate::Node>,
}

impl NodeModulesEvictor {
    /// Wrap a node so its tier-aware modules-cache sweep can be injected as a [`ModulesCacheEvictor`]
    /// seam (into the tier-0 fetcher AND the reshare warmer).
    pub(crate) fn new(node: Arc<crate::Node>) -> Self {
        Self { node }
    }
}

#[async_trait]
impl ModulesCacheEvictor for NodeModulesEvictor {
    async fn evict_if_needed(&self) {
        self.node.evict_modules_if_needed().await;
    }
}

/// A no-op [`ModulesCacheEvictor`] for tests that build a warmer but do not exercise the sweep — the
/// warmer's `evictor` seam is mandatory (the compiler forces every land path to wire one), so tests
/// that only assert the pull/announce behaviour inject this.
#[cfg(test)]
pub(crate) struct NoopModulesEvictor;

#[cfg(test)]
#[async_trait]
impl ModulesCacheEvictor for NoopModulesEvictor {
    async fn evict_if_needed(&self) {}
}

// =================================================================================================
// The bring-up spawn
// =================================================================================================

/// How often a governed tier-0 round fires. Opportunistic + low-frequency: precache rides idle
/// capacity, so a long interval keeps it out of the way of real work while still filling over time.
const ROUND_INTERVAL: Duration = Duration::from_secs(300);

/// The rate-limiter window, in ROUNDS (ticks). With [`ROUND_INTERVAL`] this spans ~1 hour, so the
/// per-window ceilings below are the loop's hourly bandwidth budget.
const RATE_WINDOW_TICKS: u64 = 12;

/// The most stores one window admits — bounds connection churn from a burst of tiny fetches.
const STORES_PER_WINDOW: u64 = 128;

/// The most bytes one window admits — the LOAD-BEARING bandwidth ceiling (bandwidth is the real cost).
const BYTES_PER_WINDOW: u64 = 512 * 1024 * 1024;

/// Everything the tier-0 loop needs, resolved once by the peer-network bring-up.
///
/// Held as trait objects so the loop is built from either the production seams (below) or test fakes.
pub struct Tier0Runtime {
    probe: Arc<dyn NeighbourhoodProbe>,
    size_probe: Arc<dyn SizeProbe>,
    fetcher: Arc<dyn Tier0Fetcher>,
    node_ctx: NodeContext,
    cache_cap_bytes: u64,
    seed: u64,
}

impl Tier0Runtime {
    /// Assemble the PRODUCTION tier-0 runtime from the node's live peer stack (#1934, PR-3).
    ///
    /// - `node` runs the tier-aware modules-cache eviction sweep after each land (the disk bound);
    /// - `dht` locates providers + is the sampling source (the 4a probe routes through it);
    /// - `warmer` is the node's ONE reshare warmer, reused for chain-anchored byte-capped pulls;
    /// - `anchor_resolver` is the CHAIN — the only root of trust for GATE 2;
    /// - `identity`/`nat_config`/`network_id` dial providers over mTLS to resolve preimages.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn production(
        node: Arc<crate::Node>,
        dht: Arc<dig_dht::DhtService>,
        probe: Arc<dyn NeighbourhoodProbe>,
        warmer: Arc<CapsuleWarmer>,
        anchor_resolver: Arc<dyn AnchoredRootResolver>,
        identity: Arc<dig_nat::NodeCert>,
        nat_config: dig_nat::NatConfig,
        network_id: &str,
        peer_id: [u8; 32],
        cache_cap_bytes: u64,
    ) -> Self {
        let lookup: Arc<dyn PreimageLookup> = Arc::new(DhtPreimageLookup {
            router: dht,
            resolver: CapsuleKeyResolver::new(MtlsCapsuleResolveClient::new(
                identity, nat_config, network_id,
            )),
        });
        let size_probe: Arc<dyn SizeProbe> = Arc::new(Tier0SizeProbe {
            lookup: lookup.clone(),
        });
        let fetcher: Arc<dyn Tier0Fetcher> = Arc::new(NodeTier0Fetcher {
            lookup,
            gate: Arc::new(ResolverAnchorGate {
                resolver: anchor_resolver,
            }),
            warm: Arc::new(WarmerCappedWarm { warmer }),
            evictor: Arc::new(NodeModulesEvictor { node }),
        });
        Self {
            probe,
            size_probe,
            fetcher,
            node_ctx: NodeContext {
                peer_id,
                weights: RelevanceWeights::default(),
            },
            // Seed the keyspace sampler from the node's own id so two nodes don't sample in lockstep.
            seed: u64::from_le_bytes(peer_id[..8].try_into().unwrap_or([0; 8])),
            cache_cap_bytes,
        }
    }
}

/// SPAWN the tier-0 eager-precache loop at node bring-up (#1934, PR-3). Returns whether it was spawned.
///
/// The small-disk no-op is checked ONCE here ([`should_run_loop`]): a node whose tier-0 sub-budget is
/// below the useful floor never spawns the loop at all. When it spawns, the round loop:
/// - reads [`tier0_precache_enabled`] PER ROUND, so the `DIG_TIER0_PRECACHE` off-switch takes effect
///   live (never cached from startup);
/// - threads ONE [`RoundRateLimiter`] across ALL rounds, so the bandwidth ceiling spans rounds (a fresh
///   limiter per round would reset the budget every round and defeat the ceiling);
/// - yields entirely to real inbound demand via [`InboundLoadSignal`].
pub fn spawn_tier0_precache(runtime: Tier0Runtime) -> bool {
    // Small-disk graceful degradation (#1927): below the useful floor, do not spawn at all.
    if !should_run_loop(runtime.cache_cap_bytes) {
        return false;
    }
    TIER0_WIRED.store(true, Ordering::Relaxed);
    tokio::spawn(async move {
        let load = InboundLoadSignal;
        let mut rng = SplitMix64::new(runtime.seed);
        // ONE limiter for the whole loop — the shared ceiling across every round.
        let mut rate =
            RoundRateLimiter::new(STORES_PER_WINDOW, BYTES_PER_WINDOW, RATE_WINDOW_TICKS);
        let mut ticker = tokio::time::interval(ROUND_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut tick: u64 = 0;
        loop {
            ticker.tick().await;
            tick += 1;
            // `tier0_precache_enabled()` is read HERE, every round, so flipping the env flips the round.
            let outcome = run_round(
                tier0_precache_enabled(),
                &*runtime.probe,
                &*runtime.size_probe,
                &*runtime.fetcher,
                &load,
                &mut rng,
                &runtime.node_ctx,
                runtime.cache_cap_bytes,
                &mut rate,
                tick,
            )
            .await;
            if outcome.cached > 0 {
                tracing::debug!(
                    cached = outcome.cached,
                    cached_bytes = outcome.cached_bytes,
                    discarded = outcome.discarded,
                    "tier-0 precache round landed stores"
                );
            }
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -- Fakes for the fetcher's internal seams ----------------------------------------------------

    struct FixedLookup(Option<Preimage>);
    #[async_trait]
    impl PreimageLookup for FixedLookup {
        async fn lookup(&self, _content_id: [u8; 32]) -> Option<Preimage> {
            self.0
        }
    }

    struct FixedGate(bool);
    #[async_trait]
    impl ChainAnchorGate for FixedGate {
        async fn is_anchored(&self, _store_id: [u8; 32], _root: [u8; 32]) -> bool {
            self.0
        }
    }

    /// One recorded warm call: `(store_id, root, max_bytes)`.
    type WarmCall = ([u8; 32], [u8; 32], u64);

    /// A warm spy that records every warm call it was asked for and returns a scripted verdict — enough
    /// to prove the gate short-circuits the pull and the cap is threaded.
    struct SpyWarm {
        verdict: WarmVerdict,
        seen: Mutex<Vec<WarmCall>>,
    }
    #[async_trait]
    impl CappedWarm for SpyWarm {
        async fn warm(&self, store_id: [u8; 32], root: [u8; 32], max_bytes: u64) -> WarmVerdict {
            self.seen.lock().unwrap().push((store_id, root, max_bytes));
            self.verdict
        }
    }

    fn preimage() -> Preimage {
        Preimage {
            store_id: [0x11; 32],
            root: [0x22; 32],
            size_bytes: 4096,
        }
    }

    /// An evictor spy that counts how many times the post-land sweep was triggered.
    struct SpyEvictor {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl SpyEvictor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }
    #[async_trait]
    impl ModulesCacheEvictor for SpyEvictor {
        async fn evict_if_needed(&self) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn fetcher(lookup: Option<Preimage>, anchored: bool, warm: Arc<SpyWarm>) -> NodeTier0Fetcher {
        NodeTier0Fetcher {
            lookup: Arc::new(FixedLookup(lookup)),
            gate: Arc::new(FixedGate(anchored)),
            warm,
            evictor: SpyEvictor::new(),
        }
    }

    // -- GATE 2: chain-anchor -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_unanchored_root_is_rejected_and_never_warmed() {
        // The load-bearing new safety test: a VerifiedCapsuleKey whose root is NOT chain-anchored
        // (melted/stale/never-anchored) is refused BEFORE any pull, and nothing is cached.
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::Cached(4096),
            seen: Mutex::new(Vec::new()),
        });
        let f = fetcher(Some(preimage()), false, warm.clone());

        let outcome = f.fetch_and_cache([0x01; 32], 8192).await;

        assert_eq!(
            outcome,
            FetchOutcome::Discarded(DiscardReason::VerifyFailed),
            "an unanchored root must be discarded, never cached"
        );
        assert!(
            warm.seen.lock().unwrap().is_empty(),
            "the pull must not run for an unanchored root"
        );
    }

    #[tokio::test]
    async fn an_anchored_root_is_warmed_and_counts_a_land() {
        // The happy path: preimage resolves, the root IS anchored, the warm caches → Cached + occupancy.
        let before = tier0_occupancy();
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::Cached(4096),
            seen: Mutex::new(Vec::new()),
        });
        let evictor = SpyEvictor::new();
        let f = NodeTier0Fetcher {
            lookup: Arc::new(FixedLookup(Some(preimage()))),
            gate: Arc::new(FixedGate(true)),
            warm: warm.clone(),
            evictor: evictor.clone(),
        };

        let outcome = f.fetch_and_cache([0x01; 32], 8192).await;

        assert_eq!(outcome, FetchOutcome::Cached(4096));
        let seen = warm.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the anchored store is warmed once");
        assert_eq!(seen[0].2, 8192, "the byte cap is threaded to the warm");
        assert!(
            tier0_occupancy() > before,
            "a successful land increments the tier-0 occupancy counter"
        );
        assert_eq!(
            evictor.calls.load(Ordering::Relaxed),
            1,
            "the tier-aware modules-cache sweep runs after a land (the disk bound)"
        );
        // The landed store is now tagged tier-0 (the sacrificial tier) for the eviction sweep.
        assert!(
            is_tier0_precache(&hex::encode(preimage().store_id)),
            "a tier-0 land is tagged Tier0Precache for eviction"
        );
    }

    // -- size_bytes hard-cap ------------------------------------------------------------------------

    #[tokio::test]
    async fn an_over_cap_store_is_discarded_not_cached() {
        // The warm reports the true store exceeded the byte cap → discarded, never cached. An
        // adversarial huge size_bytes cannot bypass the budget: the true size governs.
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::OverCap,
            seen: Mutex::new(Vec::new()),
        });
        let f = fetcher(Some(preimage()), true, warm);

        let outcome = f.fetch_and_cache([0x01; 32], 1024).await;

        assert_eq!(
            outcome,
            FetchOutcome::Discarded(DiscardReason::ExceededByteCap),
            "a store larger than the hard cap must be discarded"
        );
    }

    #[tokio::test]
    async fn the_size_probe_reports_the_provider_hint() {
        // The size probe surfaces the resolved preimage's size_bytes hint (the selector fits it to the
        // budget; the true size is enforced at fetch).
        let probe = Tier0SizeProbe {
            lookup: Arc::new(FixedLookup(Some(preimage()))),
        };
        assert_eq!(probe.resolve_size([0x01; 32]).await, Some(4096));

        // No preimage → no size → dropped for the round (never zeroed).
        let empty = Tier0SizeProbe {
            lookup: Arc::new(FixedLookup(None)),
        };
        assert_eq!(empty.resolve_size([0x01; 32]).await, None);
    }

    // -- Unavailable providers ----------------------------------------------------------------------

    #[tokio::test]
    async fn no_resolvable_preimage_is_unavailable() {
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::Cached(1),
            seen: Mutex::new(Vec::new()),
        });
        let f = fetcher(None, true, warm.clone());

        assert_eq!(
            f.fetch_and_cache([0x01; 32], 8192).await,
            FetchOutcome::Discarded(DiscardReason::Unavailable),
        );
        assert!(
            warm.seen.lock().unwrap().is_empty(),
            "no pull without a resolvable preimage"
        );
    }

    #[tokio::test]
    async fn a_warmer_no_chain_anchor_maps_to_verify_failed() {
        // Even if the explicit gate passed, the warmer's OWN internal chain-anchor re-check refusing is
        // surfaced as a verify failure (defense in depth), never a silent cache.
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::NotAnchored,
            seen: Mutex::new(Vec::new()),
        });
        let f = fetcher(Some(preimage()), true, warm);
        assert_eq!(
            f.fetch_and_cache([0x01; 32], 8192).await,
            FetchOutcome::Discarded(DiscardReason::VerifyFailed),
        );
    }

    // -- The load signal ----------------------------------------------------------------------------

    #[test]
    fn the_load_signal_is_busy_only_just_after_inbound_activity() {
        // Fresh (no activity marked yet in THIS assertion's window) → not busy is not guaranteed
        // process-globally, so drive the transition explicitly: marking activity makes it busy.
        mark_inbound_activity();
        assert!(
            InboundLoadSignal.is_busy(),
            "the node is busy immediately after inbound demand"
        );
        // Simulate a stale timestamp older than the cooldown → idle again.
        INBOUND_ACTIVITY_MS.store(
            now_ms().saturating_sub(BUSY_COOLDOWN_MS + 1),
            Ordering::Relaxed,
        );
        assert!(
            !InboundLoadSignal.is_busy(),
            "after the cooldown elapses the node is idle enough to precache"
        );
    }

    // -- The small-disk spawn no-op -----------------------------------------------------------------

    fn tiny_runtime(cache_cap_bytes: u64) -> Tier0Runtime {
        struct EmptyProbe;
        #[async_trait]
        impl NeighbourhoodProbe for EmptyProbe {
            async fn observe_near(
                &self,
                _point: [u8; 32],
            ) -> Vec<crate::dht_sampling::PeerObservation> {
                Vec::new()
            }
        }
        let warm = Arc::new(SpyWarm {
            verdict: WarmVerdict::Unavailable,
            seen: Mutex::new(Vec::new()),
        });
        Tier0Runtime {
            probe: Arc::new(EmptyProbe),
            size_probe: Arc::new(Tier0SizeProbe {
                lookup: Arc::new(FixedLookup(None)),
            }),
            fetcher: Arc::new(fetcher(None, false, warm)),
            node_ctx: NodeContext {
                peer_id: [0; 32],
                weights: RelevanceWeights::default(),
            },
            cache_cap_bytes,
            seed: 1,
        }
    }

    #[tokio::test]
    async fn a_small_disk_node_does_not_spawn_the_loop() {
        // A cap whose 10% tier-0 slice is under the useful floor: the loop is NOT spawned.
        let tiny = (crate::tier0_prefetch::MIN_USEFUL_TIER0 * 10) - 1;
        assert!(
            !spawn_tier0_precache(tiny_runtime(tiny)),
            "a small-disk node must not spawn the tier-0 loop"
        );
    }
}
