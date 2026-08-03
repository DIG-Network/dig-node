//! Tier-0 eager-precache loop — the GOVERNED orchestration that turns the DHT-sampling flywheel
//! (epic #1934) into actually-cached speculative content (child 4b/7, the epic payoff).
//!
//! # What this module is
//! Children 1–3 + 4a are pure/seam pieces; this module WIRES them into one self-driven round:
//!
//! ```text
//!   sample_candidates (4a probe → quorum-reconciled candidates)      [dht_sampling]
//!     → size resolution (median size_hint, else ONE bounded probe, else DROP)
//!     → relevance score under THIS node's NodeContext                [relevance]
//!     → select_within_budget(tier0_budget_bytes(cache_cap))          [tier0_selector]
//!     → GOVERNED fetch: merkle-verify + hard byte-cap + cache(Tier0Precache) + announce
//! ```
//!
//! # Why every step is a governor, not a nicety (SECURITY-CRITICAL)
//! The loop is self-driven — NOT inbound-triggered — so it is not an amplification vector the way the
//! inbound-demand pull (#1990) is. But it still spends this node's bandwidth + disk on candidates an
//! attacker can INFLUENCE (they populate DHT provider snapshots). So every value an attacker can move
//! is bounded BEFORE it costs anything:
//!
//! - **Off-switch, DEFAULT-ON** ([`tier0_precache_enabled`]) — the user directive is "eagerly
//!   precache"; `DIG_TIER0_PRECACHE=0` disables. Fail-safe-explicit parse (mirrors
//!   [`crate::download::inbound_demand_cache_enabled`]).
//! - **Small-disk no-op** ([`should_run_loop`], #1927) — a node whose tier-0 sub-budget is below
//!   [`MIN_USEFUL_TIER0`] never runs the loop at all; it degrades gracefully rather than thrashing a
//!   tiny cache.
//! - **Backoff-when-serving** ([`LoadSignal`]) — a round yields entirely when the node is actively
//!   serving inbound reads; tier-0 is opportunistic and ALWAYS defers to real demand.
//! - **Rate limit** ([`RoundRateLimiter`]) — a token bucket on BOTH stores/window AND bytes/window,
//!   because bandwidth is the real cost, not request count.
//! - **Size resolution + hard byte-cap** — a candidate whose size cannot be resolved is DROPPED for
//!   the round (never fetched as an unbounded unknown), and the fetch enforces the TRUE store size
//!   against the reported hint, aborting + discarding an over-size store (defeats
//!   under-report-size-then-bloat).
//! - **Merkle-verify before cache; never execute** — the fetch reuses the existing verified download
//!   path, so attacker content is verified against the confirmed root before it lands and is never
//!   opened/executed.
//! - **Tier precedence** ([`CacheTier::Tier0Precache`], [`effective_tier`]) — precache is tagged
//!   Tier0 and sacrificed FIRST; a store later demanded by a peer is promoted (tier is
//!   MAX-across-ledgers), so precache can never evict genuinely-demanded content.
//!
//! # Anti-Sybil identity carries forward from 4a (unchanged)
//! Candidates come ONLY from [`sample_candidates`], whose votes are attributed to the probe's
//! mTLS-verified `PeerObservation::peer_id` — this loop never re-introduces a wire-supplied identity,
//! never bypasses the probe's caps, and preserves the reconciler's cross-region per-peer dedup.

use async_trait::async_trait;

use crate::dht_sampling::{
    sample_candidates, Candidate, KeyspaceRng, NeighbourhoodProbe, QuorumPolicy, DEFAULT_SAMPLE_POINTS,
};
use crate::relevance::{relevance, CacheTier, NodeContext, RelevanceInputs};
use crate::tier0_selector::{
    select_within_budget, tier0_budget_bytes, Candidate as SelectorCandidate,
};

// =================================================================================================
// Off-switch — DEFAULT-ON (the user directive is "eagerly precache")
// =================================================================================================

/// The off-switch env var. The tier-0 eager-precache loop is DEFAULT-ON; only an explicit falsy value
/// disables it (see [`tier0_precache_enabled`]).
pub const TIER0_PRECACHE_ENV: &str = "DIG_TIER0_PRECACHE";

/// Whether the tier-0 eager-precache loop is enabled: **default ON**; only an explicit falsy value
/// (`0`/`off`/`false`/`no`, case-insensitive) disables it.
///
/// DEFAULT-ON is a deliberate orchestrator decision: the loop is self-driven (it reads no
/// attacker-supplied trigger and pulls only quorum-corroborated, XOR-relevant, byte-capped content),
/// so it is NOT the amplification vector the inbound-demand pull (#1990, default-OFF) is — and the
/// standing user directive is to eagerly precache. The kill switch stays, fail-safe-explicit.
#[must_use]
pub fn tier0_precache_enabled() -> bool {
    resolve_tier0_precache(std::env::var(TIER0_PRECACHE_ENV).ok().as_deref())
}

/// Pure core of [`tier0_precache_enabled`]: default ON; only an explicit falsy value disables it.
/// Pure so the policy is unit-tested without touching process-global env.
fn resolve_tier0_precache(v: Option<&str>) -> bool {
    !matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("0") | Some("off") | Some("false") | Some("no")
    )
}

// =================================================================================================
// Small-disk no-op (#1927)
// =================================================================================================

/// The smallest tier-0 sub-budget worth running the loop for, in bytes (64 MiB). Below this, the
/// 10%-of-cache tier-0 slice is too small to hold a useful precache working set, so the loop is not
/// spawned at all — a graceful no-op on a tiny-disk node rather than churn on a few-KB budget.
pub const MIN_USEFUL_TIER0: u64 = 64 * 1024 * 1024;

/// Whether the loop should run at all given the whole node cache cap: `true` iff the derived tier-0
/// sub-budget clears [`MIN_USEFUL_TIER0`]. The caller checks this ONCE at bring-up and simply does not
/// spawn the loop when it is `false` (#1927 small-disk graceful degradation).
#[must_use]
pub fn should_run_loop(cache_cap_bytes: u64) -> bool {
    tier0_budget_bytes(cache_cap_bytes) >= MIN_USEFUL_TIER0
}

// =================================================================================================
// Rate limit — a token bucket on BOTH stores/window AND bytes/window
// =================================================================================================

/// A classic token bucket over a caller-supplied logical clock (ticks). PURE — time is injected, not
/// read from a clock — so refill + admission are deterministic and unit-testable. Tokens refill
/// continuously at `refill_per_tick` up to `capacity`; [`Self::try_take`] admits `amount` iff enough
/// tokens are available, consuming them.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_tick: f64,
    last_tick: u64,
}

impl TokenBucket {
    /// A full bucket holding `capacity` tokens, refilling `refill_per_tick` tokens each tick.
    #[must_use]
    pub fn new(capacity: u64, refill_per_tick: f64) -> Self {
        Self {
            capacity: capacity as f64,
            tokens: capacity as f64,
            refill_per_tick,
            last_tick: 0,
        }
    }

    /// Refill for the ticks elapsed since the last operation (never past `capacity`). A `now` at or
    /// before `last_tick` adds nothing (a non-monotonic clock cannot manufacture tokens).
    fn refill(&mut self, now: u64) {
        if now > self.last_tick {
            let elapsed = (now - self.last_tick) as f64;
            self.tokens = (self.tokens + elapsed * self.refill_per_tick).min(self.capacity);
            self.last_tick = now;
        }
    }

    /// Admit `amount` at time `now`: refill, then consume iff enough tokens remain. Returns whether
    /// admitted. A request larger than `capacity` can never be admitted (it would deadlock the bucket).
    pub fn try_take(&mut self, amount: u64, now: u64) -> bool {
        self.refill(now);
        let amount = amount as f64;
        if self.tokens + f64::EPSILON >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// The round rate limiter: a store-count bucket AND a byte bucket, both of which must admit a fetch
/// for it to proceed. Bandwidth is the real cost, so bytes/window is the load-bearing limit; the
/// store-count limit stops a burst of tiny fetches from hammering the network with connections.
#[derive(Debug, Clone)]
pub struct RoundRateLimiter {
    stores: TokenBucket,
    bytes: TokenBucket,
}

impl RoundRateLimiter {
    /// A limiter admitting up to `stores_per_window` stores and `bytes_per_window` bytes per window,
    /// each refilling over `window_ticks` ticks.
    #[must_use]
    pub fn new(stores_per_window: u64, bytes_per_window: u64, window_ticks: u64) -> Self {
        let window = window_ticks.max(1) as f64;
        Self {
            stores: TokenBucket::new(stores_per_window, stores_per_window as f64 / window),
            bytes: TokenBucket::new(bytes_per_window, bytes_per_window as f64 / window),
        }
    }

    /// Admit ONE store of `size_bytes` at time `now`: both buckets must have room. Atomic — if the
    /// byte bucket refuses, the store token is NOT consumed (checked before either is spent), so a
    /// refused fetch costs nothing against the store budget.
    pub fn try_admit(&mut self, size_bytes: u64, now: u64) -> bool {
        // Refill both, then check availability WITHOUT consuming, so a partial take never happens.
        self.stores.refill(now);
        self.bytes.refill(now);
        let store_ok = self.stores.tokens + f64::EPSILON >= 1.0;
        let bytes_ok = self.bytes.tokens + f64::EPSILON >= size_bytes as f64;
        if store_ok && bytes_ok {
            self.stores.tokens -= 1.0;
            self.bytes.tokens -= size_bytes as f64;
            true
        } else {
            false
        }
    }
}

// =================================================================================================
// Seams — the network + node sides the loop drives, mocked in tests
// =================================================================================================

/// The node-load signal the loop backs off on. A round yields ENTIRELY when [`Self::is_busy`] is
/// true, so speculative precache never competes with real inbound serving for bandwidth/CPU.
pub trait LoadSignal: Send + Sync {
    /// Whether the node is currently under enough real load that a speculative round should be
    /// skipped. The production impl reads the live inbound-serve gauge; a `false` return means idle
    /// enough to precache.
    fn is_busy(&self) -> bool;
}

/// Resolve the on-disk size of a candidate whose DHT snapshot carried no `size_hint`.
///
/// A seam over the concrete metadata probe so the size-resolution governor is testable without a
/// network. Called AT MOST [`MAX_SIZE_PROBES_PER_ROUND`] times per round, and ONLY for already-ADMITTED
/// (quorum-cleared) candidates — the probe cost is bounded by the admitted set, never by attacker
/// volume. `None` means the size could not be resolved, and the candidate is dropped for the round.
#[async_trait]
pub trait SizeProbe: Send + Sync {
    /// The resolved on-disk size in bytes, or `None` if it could not be determined cheaply.
    async fn resolve_size(&self, content_id: [u8; 32]) -> Option<u64>;
}

/// Why a governed fetch did not result in a cached store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardReason {
    /// The TRUE store size exceeded the hard byte cap (`min(reported_hint, remaining_sub_budget)`) —
    /// the under-report-size-then-bloat defence. The partial download is discarded, never cached.
    ExceededByteCap,
    /// The content failed merkle verification against its confirmed root — attacker/garbage content,
    /// discarded and never cached.
    VerifyFailed,
    /// The content could not be located/fetched (no reachable provider, timeout). Nothing cached.
    Unavailable,
}

/// The outcome of one governed fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The store was merkle-verified, cached tagged [`CacheTier::Tier0Precache`], and announced. The
    /// value is the TRUE number of bytes cached (always within the byte cap the caller passed).
    Cached(u64),
    /// Nothing was cached; the reason bounds what an attacker achieved (at most wasted, capped I/O).
    Discarded(DiscardReason),
}

/// Fetch, merkle-verify, cache (tagged [`CacheTier::Tier0Precache`]), and announce ONE candidate.
///
/// A seam over the existing verified download → cache → announce path so the loop's governors are
/// testable without a live node. The contract every impl MUST honour:
/// - enforce a HARD byte cap of `max_bytes` on the true store size — abort + discard a store that
///   exceeds it ([`DiscardReason::ExceededByteCap`]); NEVER cache an over-cap partial;
/// - merkle-verify against the confirmed root BEFORE caching — discard on failure
///   ([`DiscardReason::VerifyFailed`]); NEVER execute/open the content;
/// - on success, cache the store tagged [`CacheTier::Tier0Precache`] and announce it via the existing
///   holdings-announce path, returning [`FetchOutcome::Cached`] with the true cached size.
#[async_trait]
pub trait Tier0Fetcher: Send + Sync {
    /// Fetch + verify + cache the content for `content_id`, enforcing the hard byte cap `max_bytes`.
    async fn fetch_and_cache(&self, content_id: [u8; 32], max_bytes: u64) -> FetchOutcome;
}

// =================================================================================================
// Tier tagging — Tier0Precache ledger + MAX-across-ledgers effective tier
// =================================================================================================

/// The effective cache tier of a store given every ledger that has an opinion about it: the MAXIMUM
/// tier by eviction rank. A store this loop precached (Tier0) that a peer later demands (Tier1) must
/// be treated as Tier1 — precache never keeps a store PINNED at the sacrificed-first tier once real
/// demand appears. Returns `None` only when no ledger holds the store.
///
/// This is the "tier is max-across-ledgers" rule stated as a pure function, so the live cache
/// eviction path derives one authoritative tier from the tier-0 + inbound-demand ledgers without
/// either ledger being able to demote a store below what another asserts.
#[must_use]
pub fn effective_tier(tiers: impl IntoIterator<Item = CacheTier>) -> Option<CacheTier> {
    tiers.into_iter().max_by_key(|t| t.rank())
}

// =================================================================================================
// The governed round
// =================================================================================================

/// The anti-Sybil quorum policy the loop samples under. Uses the module default (3 distinct peers).
fn round_policy() -> QuorumPolicy {
    QuorumPolicy::default()
}

/// Why a round produced no fetches (for observability + tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundSkip {
    /// The off-switch is set (`DIG_TIER0_PRECACHE` falsy).
    Disabled,
    /// The node is actively serving real demand — tier-0 yields (backoff-when-serving).
    Busy,
    /// The tier-0 sub-budget is below [`MIN_USEFUL_TIER0`] (#1927 small-disk).
    SmallDisk,
}

/// The tallied result of one governed round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoundOutcome {
    /// Stores merkle-verified + cached (tagged Tier0Precache) + announced this round.
    pub cached: u32,
    /// Bytes cached this round (the sum of the true cached sizes).
    pub cached_bytes: u64,
    /// Candidates dropped because no size could be resolved (never fetched).
    pub dropped_unsized: u32,
    /// Fetches that discarded (over byte-cap, verify-fail, or unavailable) — bounded attacker cost.
    pub discarded: u32,
    /// Fetches not attempted because the rate limiter was exhausted this window.
    pub rate_limited: u32,
    /// Set when the WHOLE round was skipped before sampling (off-switch / busy / small-disk).
    pub skipped: Option<RoundSkip>,
}

impl RoundOutcome {
    fn skipped(reason: RoundSkip) -> Self {
        Self {
            skipped: Some(reason),
            ..Self::default()
        }
    }
}

/// A candidate that has cleared quorum AND had a size resolved — ready to score + select. Carries the
/// content id alongside the size so the selector's index maps back to the thing to fetch.
struct SizedCandidate {
    content_id: [u8; 32],
    size_bytes: u64,
    known_provider_count: u32,
}

/// The maximum metadata probes one round will issue for `None`-sized candidates. Bounds the
/// size-resolution cost to the admitted set regardless of how many unsized candidates appear.
pub const MAX_SIZE_PROBES_PER_ROUND: usize = 32;

/// Run ONE governed tier-0 precache round. See the module docs for the pipeline; every governor is
/// applied here in order, and nothing is fetched until it has passed all of them.
///
/// `now_tick` is the caller's logical clock for the rate limiter (a monotonic per-round counter or a
/// seconds-since-start is fine); `rate` is threaded across rounds by the caller so the window spans
/// rounds. Returns the round tally (including a `skipped` reason when the whole round short-circuits).
#[allow(clippy::too_many_arguments)]
pub async fn run_round<R: KeyspaceRng>(
    enabled: bool,
    probe: &dyn NeighbourhoodProbe,
    size_probe: &dyn SizeProbe,
    fetcher: &dyn Tier0Fetcher,
    load: &dyn LoadSignal,
    rng: &mut R,
    node: &NodeContext,
    cache_cap_bytes: u64,
    rate: &mut RoundRateLimiter,
    now_tick: u64,
) -> RoundOutcome {
    // -- Whole-round governors, cheapest first: nothing is sampled or fetched if any trips. ----------
    // `enabled` is the off-switch, read by the CALLER from [`tier0_precache_enabled`] once per round
    // and injected here — so `run_round` is a pure function of its arguments (no process-global env
    // read in the hot path), which keeps rounds deterministic + unit-testable without env mutation
    // (the #1991 parallel-runner env race). The caller threads `tier0_precache_enabled()` in on every
    // round, so flipping the env still flips the round.
    if !enabled {
        return RoundOutcome::skipped(RoundSkip::Disabled);
    }
    if load.is_busy() {
        return RoundOutcome::skipped(RoundSkip::Busy); // backoff-when-serving: yield to real demand
    }
    let budget = tier0_budget_bytes(cache_cap_bytes);
    if budget < MIN_USEFUL_TIER0 {
        return RoundOutcome::skipped(RoundSkip::SmallDisk);
    }

    // -- Discover: quorum-reconciled candidates from the verified-identity probe (4a). ---------------
    let candidates = sample_candidates(probe, rng, DEFAULT_SAMPLE_POINTS, &round_policy()).await;

    // -- Size resolution: median hint, else ONE bounded probe, else DROP for the round. --------------
    let mut outcome = RoundOutcome::default();
    let mut sized = Vec::new();
    let mut probes_used = 0usize;
    for cand in candidates {
        match resolve_candidate_size(cand, size_probe, &mut probes_used).await {
            Some(sc) => sized.push(sc),
            None => outcome.dropped_unsized += 1,
        }
    }

    // -- Score + select: relevance under THIS node's context, greedy within the sub-budget. ----------
    let selector_cands: Vec<SelectorCandidate> = sized
        .iter()
        .map(|sc| SelectorCandidate {
            size_bytes: sc.size_bytes,
            relevance: relevance(&relevance_inputs(sc), node),
        })
        .collect();
    let selected = select_within_budget(&selector_cands, budget);

    // -- Governed fetch: rate-limit + hard byte-cap each selected store, in selection order. ---------
    let mut remaining = budget;
    for idx in selected {
        let sc = &sized[idx];
        // The hard byte cap: the smaller of the reported size and the remaining sub-budget. The
        // fetcher enforces the TRUE size against this and discards an over-size store.
        let cap = sc.size_bytes.min(remaining);
        if cap == 0 {
            continue; // no sub-budget left this round
        }
        if !rate.try_admit(sc.size_bytes, now_tick) {
            outcome.rate_limited += 1;
            continue; // bandwidth/store budget for this window is spent — defer, never overspend
        }
        match fetcher.fetch_and_cache(sc.content_id, cap).await {
            FetchOutcome::Cached(bytes) => {
                outcome.cached += 1;
                outcome.cached_bytes += bytes;
                remaining = remaining.saturating_sub(bytes);
            }
            FetchOutcome::Discarded(_) => outcome.discarded += 1,
        }
    }
    outcome
}

/// Build the relevance inputs for a sized candidate. Speculative precache has no local reads yet, is
/// unpinned, and is not pin-adjacent — only the XOR-proximity primary + the (clamped) provider-count
/// scarcity term drive its score, which is exactly the ungameable-primary behaviour epic #1934 wants.
fn relevance_inputs(sc: &SizedCandidate) -> RelevanceInputs {
    RelevanceInputs {
        content_id: sc.content_id,
        size_bytes: sc.size_bytes,
        known_provider_count: sc.known_provider_count,
        local_read_count: 0,
        reads_recency_ticks: None,
        is_pinned: false,
        pin_adjacent: false,
    }
}

/// Resolve one candidate's size: use the reconciled median `size_hint` when present; otherwise, for
/// an ADMITTED candidate, spend ONE bounded metadata probe (up to [`MAX_SIZE_PROBES_PER_ROUND`] per
/// round). A candidate whose size is still unknown is DROPPED (returns `None`) — never fetched as an
/// unbounded unknown, and never zeroed (a zero size would make it maximally dense in the selector).
async fn resolve_candidate_size(
    cand: Candidate,
    size_probe: &dyn SizeProbe,
    probes_used: &mut usize,
) -> Option<SizedCandidate> {
    let size_bytes = match cand.size_hint {
        Some(size) if size > 0 => size,
        _ => {
            if *probes_used >= MAX_SIZE_PROBES_PER_ROUND {
                return None; // probe budget spent — defer this candidate rather than guess its size
            }
            *probes_used += 1;
            match size_probe.resolve_size(cand.content_id).await {
                Some(size) if size > 0 => size,
                _ => return None, // unresolved → dropped for the round (NEVER unwrap(None)→0)
            }
        }
    };
    Some(SizedCandidate {
        content_id: cand.content_id,
        size_bytes,
        known_provider_count: cand.known_provider_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht_sampling::{ObservedCandidate, PeerObservation, SplitMix64};
    use crate::relevance::{CacheEntry, evict_key, RelevanceWeights};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // -- Test doubles ------------------------------------------------------------------------------

    /// A probe returning a fixed candidate set: it reports the SAME three-peer quorum for `keys` at
    /// every point, so a round reliably admits them regardless of which points the rng samples.
    struct QuorumProbe {
        keys: Vec<([u8; 32], Option<u64>)>,
    }

    #[async_trait]
    impl NeighbourhoodProbe for QuorumProbe {
        async fn observe_near(&self, _point: [u8; 32]) -> Vec<PeerObservation> {
            (1u8..=3)
                .map(|peer| PeerObservation {
                    peer_id: [peer; 32],
                    holdings: self
                        .keys
                        .iter()
                        .map(|(k, size)| ObservedCandidate {
                            content_id: *k,
                            provider_count: 4,
                            size_hint: *size,
                        })
                        .collect(),
                })
                .collect()
        }
    }

    /// A probe that finds nothing.
    struct EmptyProbe;
    #[async_trait]
    impl NeighbourhoodProbe for EmptyProbe {
        async fn observe_near(&self, _point: [u8; 32]) -> Vec<PeerObservation> {
            Vec::new()
        }
    }

    struct Idle;
    impl LoadSignal for Idle {
        fn is_busy(&self) -> bool {
            false
        }
    }
    struct Busy;
    impl LoadSignal for Busy {
        fn is_busy(&self) -> bool {
            true
        }
    }

    /// A size probe returning a fixed size (or `None`), counting its calls so the per-round probe
    /// bound can be asserted.
    struct FixedSizeProbe {
        size: Option<u64>,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl SizeProbe for FixedSizeProbe {
        async fn resolve_size(&self, _content_id: [u8; 32]) -> Option<u64> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.size
        }
    }

    /// A fetcher that records every `(content_id, max_bytes)` it was asked to fetch and returns a
    /// scripted outcome. When `true_size` exceeds `max_bytes` it reports the byte-cap discard, exactly
    /// as the real fetcher must.
    struct ScriptedFetcher {
        true_size: u64,
        verify_ok: bool,
        seen: Mutex<Vec<(u32, u64)>>, // (first content byte, max_bytes) — enough to assert the cap
    }
    #[async_trait]
    impl Tier0Fetcher for ScriptedFetcher {
        async fn fetch_and_cache(&self, content_id: [u8; 32], max_bytes: u64) -> FetchOutcome {
            self.seen
                .lock()
                .unwrap()
                .push((content_id[0] as u32, max_bytes));
            if self.true_size > max_bytes {
                return FetchOutcome::Discarded(DiscardReason::ExceededByteCap);
            }
            if !self.verify_ok {
                return FetchOutcome::Discarded(DiscardReason::VerifyFailed);
            }
            FetchOutcome::Cached(self.true_size)
        }
    }

    fn node() -> NodeContext {
        NodeContext {
            peer_id: [0x00; 32],
            weights: RelevanceWeights::default(),
        }
    }

    /// A cache cap whose 10% tier-0 slice clears MIN_USEFUL_TIER0 (so the loop runs). 10 GiB → 1 GiB.
    const BIG_CAP: u64 = 10 * 1024 * 1024 * 1024;

    fn generous_rate() -> RoundRateLimiter {
        // Effectively unlimited within a single round.
        RoundRateLimiter::new(1_000_000, u64::MAX / 2, 1)
    }

    // -- Off-switch --------------------------------------------------------------------------------

    #[test]
    fn off_switch_defaults_on_and_only_falsy_disables() {
        assert!(resolve_tier0_precache(None), "default is ON");
        assert!(resolve_tier0_precache(Some("1")));
        assert!(resolve_tier0_precache(Some("on")));
        assert!(resolve_tier0_precache(Some("anything-else")));
        for off in ["0", "off", "false", "no", " OFF ", "False"] {
            assert!(!resolve_tier0_precache(Some(off)), "{off} must disable");
        }
    }

    #[tokio::test]
    async fn a_disabled_loop_fetches_nothing() {
        // `enabled = false` is the injected off-switch — no process-global env mutation, so this test
        // cannot race the default-ON rounds under the parallel runner (#1991).
        let fetcher = ScriptedFetcher {
            true_size: 10,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            false,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(1000))],
            },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.skipped, Some(RoundSkip::Disabled));
        assert!(fetcher.seen.lock().unwrap().is_empty(), "off = no fetches");
    }

    // -- Small-disk no-op --------------------------------------------------------------------------

    #[test]
    fn small_disk_budget_below_the_floor_does_not_run() {
        // A cap whose 10% slice is under MIN_USEFUL_TIER0.
        let tiny = (MIN_USEFUL_TIER0 * 10) - 1;
        assert!(!should_run_loop(tiny), "tiny budget must not run");
        assert!(should_run_loop(BIG_CAP), "a big cap runs");
    }

    #[tokio::test]
    async fn small_disk_round_skips_before_sampling() {
        let fetcher = ScriptedFetcher {
            true_size: 10,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(1000))],
            },
            &FixedSizeProbe {
                size: Some(1000),
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            1000, // 10% = 100 bytes, far below the floor
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.skipped, Some(RoundSkip::SmallDisk));
        assert!(fetcher.seen.lock().unwrap().is_empty());
    }

    // -- Backoff-when-serving ----------------------------------------------------------------------

    #[tokio::test]
    async fn a_busy_node_skips_the_round() {
        let fetcher = ScriptedFetcher {
            true_size: 10,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(1000))],
            },
            &FixedSizeProbe {
                size: Some(1000),
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Busy,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.skipped, Some(RoundSkip::Busy));
        assert!(
            fetcher.seen.lock().unwrap().is_empty(),
            "tier-0 must yield entirely while serving real demand"
        );
    }

    // -- Size resolution ---------------------------------------------------------------------------

    #[tokio::test]
    async fn an_unresolvable_size_is_dropped_never_zeroed() {
        // Candidate carries no size hint AND the probe cannot resolve it → dropped, not fetched.
        let probe = FixedSizeProbe {
            size: None,
            calls: AtomicUsize::new(0),
        };
        let fetcher = ScriptedFetcher {
            true_size: 10,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], None)],
            },
            &probe,
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert!(out.dropped_unsized >= 1, "the unsized candidate is dropped");
        assert_eq!(out.cached, 0, "an unsized candidate is never fetched");
        assert!(fetcher.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_none_sized_candidate_uses_one_bounded_probe() {
        // No hint, but the probe resolves a size → the candidate is sized + fetched.
        let probe = FixedSizeProbe {
            size: Some(2048),
            calls: AtomicUsize::new(0),
        };
        let fetcher = ScriptedFetcher {
            true_size: 2048,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], None)],
            },
            &probe,
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.cached, 1, "the probe-sized candidate is fetched");
        assert!(probe.calls.load(Ordering::SeqCst) >= 1, "a probe was used");
    }

    // -- Budget + byte-cap -------------------------------------------------------------------------

    #[tokio::test]
    async fn selected_total_never_exceeds_the_tier0_budget() {
        // Three big stores, budget only fits some — cached bytes must stay within the sub-budget.
        let budget = tier0_budget_bytes(BIG_CAP);
        let store_size = budget / 2 - 1; // two fit, three do not
        let keys = vec![
            ([0x01; 32], Some(store_size)),
            ([0x02; 32], Some(store_size)),
            ([0x03; 32], Some(store_size)),
        ];
        let fetcher = ScriptedFetcher {
            true_size: store_size,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe { keys },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(7),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert!(
            out.cached_bytes <= budget,
            "cached {} exceeds tier-0 budget {budget}",
            out.cached_bytes
        );
        assert!(out.cached <= 2, "at most two of three big stores fit");
    }

    #[tokio::test]
    async fn a_store_larger_than_its_hint_is_aborted_at_fetch() {
        // The candidate under-reports size (100), but the TRUE store is huge → the fetcher's byte cap
        // aborts + discards it. Nothing is cached.
        let fetcher = ScriptedFetcher {
            true_size: 10_000_000, // dwarfs the reported hint
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(100))],
            },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.cached, 0, "an over-size store must not be cached");
        assert_eq!(out.discarded, 1, "it is discarded at fetch");
        // The cap the fetcher was handed was the reported hint, not the true size.
        let seen = fetcher.seen.lock().unwrap();
        assert_eq!(seen[0].1, 100, "the hard cap is the reported size");
    }

    #[tokio::test]
    async fn a_merkle_verify_failure_discards_and_never_caches() {
        let fetcher = ScriptedFetcher {
            true_size: 1000,
            verify_ok: false, // verification fails
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(1000))],
            },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.cached, 0, "verify-fail must never cache");
        assert_eq!(out.discarded, 1);
    }

    #[tokio::test]
    async fn an_empty_neighbourhood_caches_nothing_without_error() {
        let fetcher = ScriptedFetcher {
            true_size: 1000,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &EmptyProbe,
            &FixedSizeProbe {
                size: Some(1000),
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(1),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.cached, 0);
        assert_eq!(out.skipped, None, "an empty round is not a skip, just no candidates");
    }

    // -- Rate limiting -----------------------------------------------------------------------------

    #[test]
    fn token_bucket_bounds_takes_and_refills_over_ticks() {
        let mut b = TokenBucket::new(10, 1.0); // 10 cap, +1/tick
        assert!(b.try_take(10, 0), "a full bucket admits its capacity");
        assert!(!b.try_take(1, 0), "then it is empty");
        assert!(b.try_take(5, 5), "5 ticks refill 5 tokens");
        assert!(!b.try_take(1, 5), "and no more");
        // Never exceeds capacity even after a long idle.
        assert!(b.try_take(10, 1_000_000), "refill caps at capacity");
        assert!(!b.try_take(1, 1_000_000));
    }

    #[test]
    fn round_rate_limiter_bounds_on_both_stores_and_bytes() {
        // Byte-limited: two 100-byte stores fit in a 250-byte window, the third does not.
        let mut r = RoundRateLimiter::new(100, 250, 1);
        assert!(r.try_admit(100, 0));
        assert!(r.try_admit(100, 0));
        assert!(!r.try_admit(100, 0), "byte budget for the window is spent");

        // Store-limited: a 2-store window refuses the third even with byte room to spare.
        let mut s = RoundRateLimiter::new(2, u64::MAX / 2, 1);
        assert!(s.try_admit(1, 0));
        assert!(s.try_admit(1, 0));
        assert!(!s.try_admit(1, 0), "store budget for the window is spent");
    }

    #[tokio::test]
    async fn the_rate_limiter_caps_fetches_per_window() {
        // Budget fits all three, but the rate limiter admits only two per window.
        let keys = vec![
            ([0x01; 32], Some(1000)),
            ([0x02; 32], Some(1000)),
            ([0x03; 32], Some(1000)),
        ];
        let fetcher = ScriptedFetcher {
            true_size: 1000,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let mut rate = RoundRateLimiter::new(2, u64::MAX / 2, 100); // 2 stores/window
        let out = run_round(
            true,
            &QuorumProbe { keys },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(3),
            &node(),
            BIG_CAP,
            &mut rate,
            0,
        )
        .await;
        assert!(out.cached <= 2, "at most two fetched under the store rate limit");
        assert!(out.rate_limited >= 1, "the third is rate-limited");
    }

    // -- Tier tagging + precedence -----------------------------------------------------------------

    #[test]
    fn effective_tier_is_the_max_across_ledgers() {
        // A store precached (Tier0) that a peer later demands (Tier1) is effectively Tier1.
        assert_eq!(
            effective_tier([CacheTier::Tier0Precache, CacheTier::Tier1Demand]),
            Some(CacheTier::Tier1Demand),
            "demand promotes a precached store above Tier0"
        );
        assert_eq!(
            effective_tier([CacheTier::Tier0Precache]),
            Some(CacheTier::Tier0Precache),
            "a purely-precached store stays Tier0"
        );
        assert_eq!(
            effective_tier([CacheTier::Tier1Demand, CacheTier::Tier2Bribed]),
            Some(CacheTier::Tier2Bribed)
        );
        assert_eq!(effective_tier([]), None, "no ledger holds it → no tier");
    }

    #[test]
    fn eviction_sacrifices_tier0_before_tier1_and_tier2() {
        // A full cache with one entry per tier: sorted by evict_key, Tier0 is sacrificed first.
        let mut entries = [
            CacheEntry {
                tier: CacheTier::Tier2Bribed,
                last_access_ticks: 1,
            },
            CacheEntry {
                tier: CacheTier::Tier1Demand,
                last_access_ticks: 1,
            },
            CacheEntry {
                tier: CacheTier::Tier0Precache,
                last_access_ticks: 999, // freshest, yet still evicted first by tier
            },
        ];
        entries.sort_by_key(evict_key);
        assert_eq!(
            entries[0].tier,
            CacheTier::Tier0Precache,
            "precache is sacrificed before real demand, even when freshest"
        );
        assert_eq!(entries[2].tier, CacheTier::Tier2Bribed, "paid retention lasts longest");
    }

    // -- Full-pipeline happy path ------------------------------------------------------------------

    #[tokio::test]
    async fn the_happy_path_caches_a_verified_quorum_candidate() {
        let fetcher = ScriptedFetcher {
            true_size: 4096,
            verify_ok: true,
            seen: Mutex::new(Vec::new()),
        };
        let out = run_round(
            true,
            &QuorumProbe {
                keys: vec![([0x10; 32], Some(4096))],
            },
            &FixedSizeProbe {
                size: None,
                calls: AtomicUsize::new(0),
            },
            &fetcher,
            &Idle,
            &mut SplitMix64::new(11),
            &node(),
            BIG_CAP,
            &mut generous_rate(),
            0,
        )
        .await;
        assert_eq!(out.cached, 1);
        assert_eq!(out.cached_bytes, 4096);
        assert_eq!(out.skipped, None);
    }
}
