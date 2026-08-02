//! Cache relevance + tier model + eviction precedence — the pure "brain" the
//! on-disk LRU cache (see [`crate`] `DIG_NODE_CACHE_CAP`) will later consult to
//! decide WHAT to keep, WHAT to sacrifice first, and WHEN a fresh candidate is
//! worth displacing an incumbent.
//!
//! Everything here is PURE and deterministic: no clock, no network, no
//! `Instant::now`, no I/O. Time enters ONLY as caller-supplied tick counters
//! (`reads_recency_ticks`, `last_access_ticks`), so the same inputs always yield
//! the same score and eviction decisions can be replayed and audited offline.
//!
//! # The model in one paragraph
//! Every cacheable store has a [`relevance`] score — higher means "more worth
//! keeping". The PRIMARY signal is the **XOR distance** between the content id
//! and this node's peer id: content whose id lands close to our peer id in the
//! 256-bit keyspace is content this node is naturally responsible for. Around
//! that primary term sit bounded, weighted bonuses: a **replication-scarcity**
//! term (keep what few others hold), a **local-demand** term (keep what our own
//! users read), a **pin-adjacency** bonus, and a large **pinned** bonus. Score
//! only decides desirability WITHIN a [`CacheTier`]; across tiers, eviction
//! precedence is fixed by the tier alone ([`evict_key`]).

/// Which acquisition tier a cached entry belongs to. The tier — NOT the
/// relevance score — decides cross-tier eviction precedence: a lower tier is
/// always sacrificed before a higher one, so speculative precache can never
/// push out content a user (Tier1) or a paying backer (Tier2) asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheTier {
    /// Speculatively fetched (DHT-neighbourhood precache). Sacrificed FIRST.
    Tier0Precache,
    /// Fetched to satisfy a real local read. Sacrificed only after all Tier0.
    Tier1Demand,
    /// Retained because a backer paid to keep it resident. Sacrificed LAST.
    Tier2Bribed,
}

impl CacheTier {
    /// Cross-tier eviction rank: **ascending** = evicted first. `Tier0Precache`
    /// → 0 (goes first), `Tier2Bribed` → 2 (goes last). Sorting entries by
    /// `(rank, last_access_ticks)` ascending therefore yields exactly
    /// tier0-oldest → … → tier2-newest, which is the eviction order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            CacheTier::Tier0Precache => 0,
            CacheTier::Tier1Demand => 1,
            CacheTier::Tier2Bribed => 2,
        }
    }
}

/// The tunable weights of the [`relevance`] weighted sum. Defaults keep the XOR
/// primary strictly dominant: no single bonus can outweigh the proximity term,
/// so the ungameable signal always leads (see [`RelevanceWeights::default`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RelevanceWeights {
    /// Weight of the XOR-proximity primary. Largest by construction.
    pub xor: f64,
    /// Weight of the (clamped) replication-scarcity term.
    pub scarcity: f64,
    /// Weight of the saturating local-read-count demand term.
    pub demand: f64,
    /// Weight of the read-recency freshness bonus.
    pub recency: f64,
    /// Weight of the pin-adjacency bonus (near a pinned store in keyspace).
    pub pin_adjacent: f64,
    /// Weight of the explicit-pin bonus. Large: a pinned store is maximally
    /// relevant regardless of the other signals.
    pub pinned: f64,
}

impl Default for RelevanceWeights {
    /// The `xor` weight (1.0) exceeds the SUM of every other bonus's clamped
    /// ceiling (0.25 + 0.4 + 0.2 + 0.15 = 1.0 excluding the pin override), so
    /// proximity is never dominated by the gameable secondary signals; `pinned`
    /// (2.0) deliberately overrides everything because an explicit pin is a
    /// direct operator instruction, not a heuristic.
    fn default() -> Self {
        Self {
            xor: 1.0,
            scarcity: 0.25,
            demand: 0.4,
            recency: 0.2,
            pin_adjacent: 0.15,
            pinned: 2.0,
        }
    }
}

/// The per-store signals fed into [`relevance`]. All caller-supplied and pure —
/// no field is read from a clock or the network inside this module.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RelevanceInputs {
    /// The content/store id (the value XOR-compared against the node peer id).
    pub content_id: [u8; 32],
    /// Size of the entry on disk. Carried for downstream knapsack selection
    /// (later children); it does not enter the relevance score itself.
    pub size_bytes: u64,
    /// How many providers THIS node currently believes hold the content. An
    /// UNTRUSTED, potentially-flooded count — clamped before use.
    pub known_provider_count: u32,
    /// How many times local users have read this store.
    pub local_read_count: u32,
    /// Age, in caller-defined ticks, since the most recent local read — smaller
    /// is more recent. `None` means "never read locally". Passed in (not read
    /// from a clock) to keep [`relevance`] pure.
    pub reads_recency_ticks: Option<u64>,
    /// The operator explicitly pinned this store.
    pub is_pinned: bool,
    /// This store sits adjacent (in keyspace) to a pinned store.
    pub pin_adjacent: bool,
}

/// The fixed context a node scores against: its own identity and its weights.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NodeContext {
    /// This node's peer id — the XOR-distance reference point.
    pub peer_id: [u8; 32],
    /// The scoring weights.
    pub weights: RelevanceWeights,
}

/// A relevance score: higher = more worth keeping. A thin, totally-ordered
/// wrapper over a finite `f64` (scores are always finite here, so
/// [`PartialOrd`] never yields `None` in practice).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RelevanceValue(pub f64);

impl RelevanceValue {
    /// The underlying score.
    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

/// Providers below this floor are treated as "effectively 1" — a deflated /
/// zeroed count cannot inflate scarcity past what a single provider warrants.
const SCARCITY_CLAMP_LO: u32 = 1;
/// Providers above this ceiling are treated as "abundant" — an inflated /
/// flooded count cannot push scarcity below its floor. Together with `_LO`,
/// this bounds the ENTIRE scarcity term to `[0, weights.scarcity]`.
const SCARCITY_CLAMP_HI: u32 = 32;
/// Local reads saturate here: past this, more reads don't grow the demand term
/// (a hammered store shouldn't monopolise the cache purely on read count).
const DEMAND_SATURATION: u32 = 16;
/// Recency half-life in ticks: a read `RECENCY_SCALE` ticks old contributes
/// half the freshness bonus of a just-now read.
const RECENCY_SCALE: f64 = 1000.0;

/// Compute the pure relevance score of a store for this node.
///
/// The weighted sum is:
/// `xor·proximity + scarcity·scarcity_term + demand·demand_term
///  + recency·recency_term + pin_adjacent·[adjacent] + pinned·[pinned]`.
///
/// ## Why XOR distance is the ungameable primary
/// Proximity is derived from `content_id XOR peer_id`. An attacker cannot choose
/// YOUR `peer_id`, and cannot cheaply grind a `content_id` that lands close to
/// it (that is a 256-bit preimage search), so they cannot manufacture "this is
/// your responsibility" relevance for arbitrary junk. Every gameable signal
/// below is a bounded ADDITIVE bonus that can nudge, never dominate, this term.
///
/// ## Monotonic proximity map
/// Proximity is `1 - (hi128 / 2^128)` where `hi128` is the top 128 bits of the
/// XOR distance. It is a strictly decreasing function of those high bits, so a
/// strictly smaller XOR distance (differing anywhere in the top 128 bits) yields
/// a strictly higher proximity. The low 128 bits are an intentional
/// f64-precision-limited tiebreak and do not perturb ordering.
#[must_use]
pub fn relevance(store: &RelevanceInputs, node: &NodeContext) -> RelevanceValue {
    let w = &node.weights;

    let proximity = xor_proximity(&store.content_id, &node.peer_id);
    let scarcity = scarcity_term(store.known_provider_count);
    let demand = demand_term(store.local_read_count);
    let recency = recency_term(store.reads_recency_ticks);

    let mut score =
        w.xor * proximity + w.scarcity * scarcity + w.demand * demand + w.recency * recency;

    if store.pin_adjacent {
        score += w.pin_adjacent;
    }
    if store.is_pinned {
        score += w.pinned;
    }

    RelevanceValue(score)
}

/// Map XOR distance to a proximity in `[0, 1]`, strictly decreasing in the top
/// 128 bits of `content_id XOR peer_id` (closer = higher). See [`relevance`].
fn xor_proximity(content_id: &[u8; 32], peer_id: &[u8; 32]) -> f64 {
    let mut hi = 0u128;
    for i in 0..16 {
        hi = (hi << 8) | u128::from(content_id[i] ^ peer_id[i]);
    }
    // hi / 2^128 in [0,1); proximity = 1 - that, strictly decreasing in hi.
    let distance_fraction = (hi as f64) / (u128::MAX as f64);
    1.0 - distance_fraction
}

/// Bounded replication-scarcity term in `[0, 1]`: fewer known providers → higher
/// (keep what few others hold). `known_provider_count` is UNTRUSTED, so it is
/// clamped to `[SCARCITY_CLAMP_LO, SCARCITY_CLAMP_HI]` FIRST — this is the
/// load-bearing anti-gaming step. A provider count flooded to `u32::MAX` clamps
/// to the ceiling (scarcity → 0) and a count deflated to 0 clamps to the floor
/// (scarcity → 1); because the whole term is then scaled by a weight strictly
/// smaller than the XOR weight, a lie can neither DOMINATE the score nor ZERO it
/// (the XOR + demand terms survive regardless).
fn scarcity_term(known_provider_count: u32) -> f64 {
    let clamped = known_provider_count.clamp(SCARCITY_CLAMP_LO, SCARCITY_CLAMP_HI);
    let span = f64::from(SCARCITY_CLAMP_HI - SCARCITY_CLAMP_LO);
    // clamped==LO → 1.0 (scarcest); clamped==HI → 0.0 (abundant).
    f64::from(SCARCITY_CLAMP_HI - clamped) / span
}

/// Saturating local-demand term in `[0, 1]`: read count normalised against
/// [`DEMAND_SATURATION`] so a heavily-read store cannot dominate on count alone.
fn demand_term(local_read_count: u32) -> f64 {
    let capped = local_read_count.min(DEMAND_SATURATION);
    f64::from(capped) / f64::from(DEMAND_SATURATION)
}

/// Read-recency freshness term in `[0, 1]`: `1 / (1 + age/RECENCY_SCALE)`, so a
/// just-now read (age 0) → 1.0 and older reads decay smoothly. `None` (never
/// read) → 0.0.
fn recency_term(reads_recency_ticks: Option<u64>) -> f64 {
    match reads_recency_ticks {
        None => 0.0,
        Some(age) => 1.0 / (1.0 + (age as f64) / RECENCY_SCALE),
    }
}

/// A cached entry as far as eviction is concerned: its tier and the tick of its
/// last access (smaller = older). The relevance SCORE is deliberately absent —
/// cross-tier precedence is by tier alone; score only ranks within a tier
/// during candidate selection, not during eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheEntry {
    /// The acquisition tier.
    pub tier: CacheTier,
    /// Tick of last access; smaller is older (LRU within a tier).
    pub last_access_ticks: u64,
}

/// The eviction sort key. Sorting entries by this key **ascending** evicts in
/// exactly the right order: all Tier0 (oldest first), then all Tier1 (oldest
/// first), then all Tier2 (oldest first) — i.e. precedence tier2 > tier1 > tier0
/// with LRU inside each tier.
#[must_use]
pub fn evict_key(entry: &CacheEntry) -> (u8, u64) {
    (entry.tier.rank(), entry.last_access_ticks)
}

/// Hysteresis primitive: should `candidate` displace `incumbent` from a full
/// cache? Only when the candidate is *strictly* more relevant by more than
/// `margin`. The margin is the anti-thrash band: without it, two stores with
/// near-equal scores would ping-pong in and out of the cache on every sweep.
/// At or below the margin the incumbent stays.
#[must_use]
pub fn should_displace(incumbent: RelevanceValue, candidate: RelevanceValue, margin: f64) -> bool {
    candidate.0 > incumbent.0 + margin
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An id that is all `byte`, for constructing controlled XOR distances.
    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// A store with neutral secondary signals — only `content_id` varies — so a
    /// test isolates one dimension at a time.
    fn plain_store(content_id: [u8; 32]) -> RelevanceInputs {
        RelevanceInputs {
            content_id,
            size_bytes: 1024,
            known_provider_count: 8,
            local_read_count: 0,
            reads_recency_ticks: None,
            is_pinned: false,
            pin_adjacent: false,
        }
    }

    fn node(peer_id: [u8; 32]) -> NodeContext {
        NodeContext {
            peer_id,
            weights: RelevanceWeights::default(),
        }
    }

    #[test]
    fn closer_xor_distance_ranks_strictly_higher() {
        let me = node(id(0x00));
        // near shares the whole top with peer_id (distance small); far differs
        // in the top byte (distance large).
        let mut near_id = id(0x00);
        near_id[31] = 0x01; // differs only in the LOW byte → tiny distance
        let mut far_id = id(0x00);
        far_id[0] = 0x80; // differs in the TOP bit → large distance

        let near = relevance(&plain_store(near_id), &me);
        let far = relevance(&plain_store(far_id), &me);

        assert!(
            near.get() > far.get(),
            "closer XOR distance must score strictly higher: near={} far={}",
            near.get(),
            far.get()
        );
    }

    #[test]
    fn zero_distance_is_maximum_proximity() {
        let me = node(id(0xAB));
        // content_id == peer_id → XOR distance 0 → proximity 1.0.
        let exact = relevance(&plain_store(id(0xAB)), &me);
        let elsewhere = relevance(&plain_store(id(0x00)), &me);
        assert!(exact.get() > elsewhere.get());
    }

    #[test]
    fn flooded_provider_count_cannot_dominate_the_score() {
        // A store FAR in keyspace with a deflated (0) provider count — the
        // maximally-favourable lie for scarcity — must still lose to a store
        // CLOSE in keyspace with a flooded (u32::MAX) provider count. XOR
        // primary wins; the scarcity clamp holds at both extremes.
        let me = node(id(0x00));

        let mut far_id = id(0x00);
        far_id[0] = 0xFF;
        let mut far_lying = plain_store(far_id);
        far_lying.known_provider_count = 0; // pretend "nobody else has it"

        let mut near_id = id(0x00);
        near_id[31] = 0x01;
        let mut near_flooded = plain_store(near_id);
        near_flooded.known_provider_count = u32::MAX; // pretend "everyone has it"

        let far = relevance(&far_lying, &me);
        let near = relevance(&near_flooded, &me);

        assert!(
            near.get() > far.get(),
            "XOR primary must beat a maximally-gamed scarcity signal: near={} far={}",
            near.get(),
            far.get()
        );
    }

    #[test]
    fn scarcity_term_is_clamped_at_both_extremes() {
        // count 0 and count 1 both clamp to the floor → identical scarcity.
        assert_eq!(scarcity_term(0), scarcity_term(1));
        // count HI and count u32::MAX both clamp to the ceiling → identical.
        assert_eq!(scarcity_term(SCARCITY_CLAMP_HI), scarcity_term(u32::MAX));
        // The floor is the max scarcity (1.0) and the ceiling the min (0.0).
        assert_eq!(scarcity_term(0), 1.0);
        assert_eq!(scarcity_term(u32::MAX), 0.0);
    }

    #[test]
    fn scarcity_swing_is_bounded_by_its_weight() {
        // The ENTIRE gameable swing of the scarcity term (count 0 vs count MAX),
        // holding everything else equal, is at most the scarcity weight.
        let me = node(id(0x00));
        let scarce = {
            let mut s = plain_store(id(0x10));
            s.known_provider_count = 0;
            relevance(&s, &me)
        };
        let abundant = {
            let mut s = plain_store(id(0x10));
            s.known_provider_count = u32::MAX;
            relevance(&s, &me)
        };
        let swing = scarce.get() - abundant.get();
        assert!(swing > 0.0, "scarcer must score higher");
        assert!(
            swing <= RelevanceWeights::default().scarcity + f64::EPSILON,
            "scarcity swing {swing} exceeds its weight"
        );
    }

    #[test]
    fn demand_and_recency_raise_but_pin_dominates() {
        let me = node(id(0x00));
        let base = relevance(&plain_store(id(0x40)), &me);

        let mut read = plain_store(id(0x40));
        read.local_read_count = 100;
        read.reads_recency_ticks = Some(0);
        let demanded = relevance(&read, &me);
        assert!(demanded.get() > base.get(), "reads raise relevance");

        let mut pinned = plain_store(id(0x40));
        pinned.is_pinned = true;
        let pin = relevance(&pinned, &me);
        assert!(
            pin.get() > demanded.get(),
            "an explicit pin dominates demand"
        );
    }

    #[test]
    fn recency_decays_with_age() {
        assert_eq!(recency_term(Some(0)), 1.0);
        assert!(recency_term(Some(0)) > recency_term(Some(500)));
        assert!(recency_term(Some(500)) > recency_term(Some(5000)));
        assert_eq!(recency_term(None), 0.0);
    }

    #[test]
    fn demand_term_saturates() {
        assert_eq!(demand_term(DEMAND_SATURATION), 1.0);
        assert_eq!(demand_term(DEMAND_SATURATION), demand_term(u32::MAX));
        assert!(demand_term(1) < demand_term(DEMAND_SATURATION));
    }

    #[test]
    fn eviction_order_is_tier0_then_tier1_then_tier2_lru_within() {
        // Deliberately shuffled input; the sorted-by-evict_key order is the
        // eviction order.
        let mut entries = [
            CacheEntry {
                tier: CacheTier::Tier2Bribed,
                last_access_ticks: 1,
            },
            CacheEntry {
                tier: CacheTier::Tier1Demand,
                last_access_ticks: 50,
            },
            CacheEntry {
                tier: CacheTier::Tier0Precache,
                last_access_ticks: 99,
            },
            CacheEntry {
                tier: CacheTier::Tier0Precache,
                last_access_ticks: 5,
            },
            CacheEntry {
                tier: CacheTier::Tier1Demand,
                last_access_ticks: 10,
            },
            CacheEntry {
                tier: CacheTier::Tier2Bribed,
                last_access_ticks: 100,
            },
        ];
        entries.sort_by_key(evict_key);

        let order: Vec<_> = entries
            .iter()
            .map(|e| (e.tier, e.last_access_ticks))
            .collect();
        assert_eq!(
            order,
            vec![
                (CacheTier::Tier0Precache, 5), // tier0 oldest first
                (CacheTier::Tier0Precache, 99),
                (CacheTier::Tier1Demand, 10), // then tier1 oldest first
                (CacheTier::Tier1Demand, 50),
                (CacheTier::Tier2Bribed, 1), // then tier2 oldest first
                (CacheTier::Tier2Bribed, 100),
            ]
        );
    }

    #[test]
    fn tier_ranks_are_ordered() {
        assert!(CacheTier::Tier0Precache.rank() < CacheTier::Tier1Demand.rank());
        assert!(CacheTier::Tier1Demand.rank() < CacheTier::Tier2Bribed.rank());
    }

    #[test]
    fn should_displace_respects_the_margin() {
        let incumbent = RelevanceValue(1.0);
        let margin = 0.1;

        // Below the margin: candidate barely higher → stays out.
        assert!(!should_displace(incumbent, RelevanceValue(1.05), margin));
        // Exactly at the margin: strict comparison → stays out.
        assert!(!should_displace(incumbent, RelevanceValue(1.1), margin));
        // Above the margin: displaces.
        assert!(should_displace(incumbent, RelevanceValue(1.11), margin));
        // A lower candidate never displaces.
        assert!(!should_displace(incumbent, RelevanceValue(0.5), margin));
    }
}
