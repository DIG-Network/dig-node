//! DHT random-sampling candidate discovery with multi-peer anti-Sybil quorum
//! reconciliation (epic #1934, child 2/7).
//!
//! This module answers ONE question: *which `.dig` store keys are worth even
//! considering for speculative precache?* It produces the CANDIDATE SET that
//! feeds [`dig_sex::RelevanceInputs`] (the `content_id` + an untrusted
//! `known_provider_count`); it does NOT score candidates (that is
//! [`dig_sex::relevance`], child #1) and does NOT select or fetch them (that is
//! [`dig_sex::select_within_capacity`], child #3, and the fetch loop, child #4).
//!
//! # The two halves
//!
//! 1. A **pure reconciliation policy** ([`reconcile`]) — given per-peer provider
//!    observations, admit only the content keys that clear an anti-Sybil quorum,
//!    deriving each admitted key's provider count from a robust cross-peer
//!    aggregate. No clock, no network, no RNG: the same observations always
//!    yield the same candidate set, so the security-critical logic is replayable
//!    and unit-tested with no I/O.
//! 2. **Random keyspace sampling** ([`sample_keyspace_points`]) — pick WHICH
//!    regions of the 256-bit keyspace to probe, spread across the space so
//!    coverage self-balances rather than fixating on keys this node already
//!    knows. Randomness enters ONLY through a caller-supplied [`KeyspaceRng`], so
//!    sampling is deterministic under a seeded RNG and therefore testable.
//!
//! The thin async composition ([`sample_candidates`]) ties them together over a
//! [`NeighbourhoodProbe`] seam so the WIRING is testable with a mock probe. The
//! concrete probe (dig-dht `find_node` toward each sampled point, then a
//! provider-snapshot RPC to the peers found there) is deferred to the fetch
//! child (#4) — this module owns discovery + reconciliation only.
//!
//! # How this fits the real dig-dht surface (v0.11.x)
//!
//! dig-dht's `find_providers(&ContentId)` looks up by a KNOWN content id and
//! returns provider records ALREADY AGGREGATED + deduped across responding
//! peers — it exposes no per-peer view, so it cannot on its own support quorum
//! reconciliation. The per-peer view instead comes from `DhtService::
//! provider_snapshot` (the RLY-009 `get_dht_records` shape, #1935): a node holds
//! records for keys near its OWN peer id, so ONE peer's snapshot is exactly a
//! [`PeerObservation`] — that peer's reported `(content_key, provider_count)`
//! set for its neighbourhood. Random keyspace points are reached with the
//! routing primitive `find_node`/`known_closest`, which accepts ANY [`dig_dht::
//! Key`], so we can probe arbitrary regions rather than only ids we already hold.
//! The DHT provider snapshot carries NO size, so [`ObservedCandidate::size_hint`]
//! is optional; the real size is learned when child #4 fetches.
//!
//! # The anti-Sybil model, stated honestly
//!
//! The quorum drops a SINGLE dishonest peer's unique injections, and the
//! median aggregate below denies any single peer control of an admitted key's
//! provider count. It does NOT — and cannot, at this layer — stop an attacker
//! who mints `M` distinct mTLS identities and has them all corroborate the same
//! key: distinct-peer agreement is a cost multiplier, not a proof of honesty.
//! That residual is bounded by the layers around this one: keyspace sampling
//! makes an attacker cover the WHOLE space rather than one chosen key, the
//! relevance XOR primary (child #1) means a corroborated junk key still scores
//! by an id the attacker cannot grind toward this node, and the final
//! `[1, 32]` provider-count clamp (child #1) caps whatever count survives here.

use std::collections::BTreeMap;

/// Distinct peers that must independently report a content key before it is
/// admitted as a candidate — the anti-Sybil quorum threshold `M`.
///
/// WHY a quorum at all: a single lying or Sybil peer can inject arbitrary junk
/// keys into its own snapshot. Requiring agreement from several DISTINCT peers
/// means one peer's unique fabrications never reach the candidate set — the
/// attacker must corroborate a key across `M` identities, not one.
///
/// WHY three: it is the smallest threshold that survives a single dishonest
/// responder while a healthy neighbourhood (many peers hold records for popular
/// keys) still clears it for genuine content. It is a floor, not a ceiling —
/// [`QuorumPolicy`] lets a caller raise it where the neighbourhood is denser.
pub const DEFAULT_QUORUM_MIN_PEERS: u32 = 3;

/// How many random keyspace points a sampling round probes by default.
///
/// Each point pulls one neighbourhood's worth of observations; spreading the
/// probes across the keyspace is what makes coverage self-balancing rather than
/// clustered around this node's own id.
pub const DEFAULT_SAMPLE_POINTS: usize = 8;

/// One peer's report about ONE content key, as read from that peer's provider
/// snapshot. UNTRUSTED: every field is a value a remote peer chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedCandidate {
    /// The 32-byte content KEY (a point in the DHT keyspace — already the
    /// domain-separated `ContentId::to_key` value). Fed verbatim as
    /// [`dig_sex::RelevanceInputs::content_id`] for XOR proximity.
    pub content_id: [u8; 32],
    /// How many providers THIS peer claims to know for the key. Untrusted and
    /// individually gameable — reconciled across peers, never taken as-is.
    pub provider_count: u32,
    /// The peer's claimed on-disk size, if its snapshot carried one. `None`
    /// when unknown (the DHT provider snapshot has no size); the true size is
    /// learned at fetch time (child #4).
    pub size_hint: Option<u64>,
}

/// One peer's full reported holdings set — the unit of "an independent
/// observation" for the quorum. Identity is the mTLS-verified `peer_id`, so two
/// observations from the same peer count ONCE toward a quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerObservation {
    /// The reporting peer's verified 32-byte id.
    pub peer_id: [u8; 32],
    /// Everything that peer reported it knows about in the probed region.
    pub holdings: Vec<ObservedCandidate>,
}

/// The anti-Sybil admission policy for [`reconcile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumPolicy {
    /// Minimum DISTINCT reporting peers (`M`) for a key to be admitted.
    pub min_distinct_peers: u32,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            min_distinct_peers: DEFAULT_QUORUM_MIN_PEERS,
        }
    }
}

/// An admitted candidate, ready to become a [`dig_sex::RelevanceInputs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The content key (keyspace point).
    pub content_id: [u8; 32],
    /// Robust cross-peer provider count (NOT the max of any one peer's claim).
    pub known_provider_count: u32,
    /// Robust cross-peer size hint, if any peer supplied one.
    pub size_hint: Option<u64>,
}

/// A deterministic source of random keyspace points. Injected (rather than
/// calling a global RNG/clock) so [`sample_keyspace_points`] stays pure and its
/// coverage is reproducible under a seed.
pub trait KeyspaceRng {
    /// The next 32-byte keyspace point.
    fn next_point(&mut self) -> [u8; 32];
}

/// A small, self-contained SplitMix64 generator — enough to spread sample points
/// across the keyspace deterministically without pulling in the `rand` crate.
///
/// SplitMix64 is chosen for one reason: it is a stateless-looking, well-mixed
/// integer stream from a single `u64` seed, so a caller can derive the seed from
/// node state (e.g. a hash of the peer id + a round counter) and replay the exact
/// same coverage. It is NOT cryptographic and MUST NOT be used for keys, nonces,
/// or anything an adversary benefits from predicting — it only chooses which
/// public keyspace regions to look at, where predictability costs nothing.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator. Any seed is valid; the same seed always replays the
    /// same point stream.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// One 64-bit output, advancing the state (the canonical SplitMix64 step).
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl KeyspaceRng for SplitMix64 {
    fn next_point(&mut self) -> [u8; 32] {
        // Four 64-bit draws fill the 256-bit point; big-endian packing keeps the
        // mapping stable across platforms so a seed replays identically anywhere.
        let mut point = [0u8; 32];
        for chunk in point.chunks_exact_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_be_bytes());
        }
        point
    }
}

/// Sample `k` random keyspace points from `rng` — the WHICH-to-probe half.
///
/// Pure over the injected generator: it performs no I/O and reads no clock, so
/// under a seeded [`SplitMix64`] the returned points (and therefore which
/// neighbourhoods a round probes) are fully reproducible. The points are the
/// raw targets a caller then routes toward with dig-dht `find_node`.
pub fn sample_keyspace_points(rng: &mut impl KeyspaceRng, k: usize) -> Vec<[u8; 32]> {
    (0..k).map(|_| rng.next_point()).collect()
}

/// Reconcile per-peer observations into the admitted candidate set: a content
/// key is kept only when at least `policy.min_distinct_peers` DISTINCT peers
/// report it, and each kept key's provider count is a robust cross-peer
/// aggregate (never a single peer's inflated claim).
///
/// The output is sorted by `content_id` for a deterministic, testable order.
#[must_use]
pub fn reconcile(observations: &[PeerObservation], policy: &QuorumPolicy) -> Vec<Candidate> {
    // Group every observation by content key, collapsing per PEER first: one
    // peer that lists the same key twice (or reports it across two probed
    // regions) must count ONCE toward the quorum, otherwise a single peer could
    // manufacture a quorum by itself. `reports[key][peer]` therefore holds at
    // most one entry per peer — the LAST value that peer reported for that key.
    let mut reports: BTreeMap<[u8; 32], BTreeMap<[u8; 32], ObservedCandidate>> = BTreeMap::new();
    for observation in observations {
        for held in &observation.holdings {
            reports
                .entry(held.content_id)
                .or_default()
                .insert(observation.peer_id, *held);
        }
    }

    reports
        .into_iter()
        .filter_map(|(content_id, per_peer)| admit(content_id, &per_peer, policy))
        .collect()
}

/// Admit one content key iff it clears the quorum, deriving its reconciled
/// count + size from the per-peer reports. `per_peer` is already deduped to one
/// entry per distinct peer, so its length IS the distinct-peer count.
fn admit(
    content_id: [u8; 32],
    per_peer: &BTreeMap<[u8; 32], ObservedCandidate>,
    policy: &QuorumPolicy,
) -> Option<Candidate> {
    let distinct_peers = u32::try_from(per_peer.len()).unwrap_or(u32::MAX);
    if distinct_peers < policy.min_distinct_peers {
        return None; // one (or too few) peers cannot vote a key in — Sybil guard
    }

    let counts: Vec<u32> = per_peer.values().map(|c| c.provider_count).collect();
    let sizes: Vec<u64> = per_peer.values().filter_map(|c| c.size_hint).collect();

    Some(Candidate {
        content_id,
        // MEDIAN, not max: a single peer inflating its count to `u32::MAX` moves
        // only one tail sample, so it cannot drag the median while honest peers
        // outnumber it — which is exactly the guarantee max would surrender.
        known_provider_count: lower_median_u32(counts),
        size_hint: lower_median_u64(sizes),
    })
}

/// The lower median of a non-empty `Vec<u32>` (consumes + sorts it). For an even
/// count the LOWER of the two middles is chosen: leaning small is the safe bias
/// against an inflation attack on the provider count. Panics never occur —
/// callers only pass the non-empty per-peer count vector of an admitted key.
fn lower_median_u32(mut values: Vec<u32>) -> u32 {
    debug_assert!(!values.is_empty(), "median of an admitted key is non-empty");
    values.sort_unstable();
    values[(values.len() - 1) / 2]
}

/// The lower median of the reported sizes, or `None` when no peer supplied one.
/// Same lower-median robustness as [`lower_median_u32`]; an absent size is not a
/// zero, so it is excluded rather than counted as the smallest.
fn lower_median_u64(mut values: Vec<u64>) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[(values.len() - 1) / 2])
}

/// The network side of a sampling round: given a keyspace point, return the
/// observations of the peers responsible for that region.
///
/// A seam (rather than a direct dig-dht call) so [`sample_candidates`]'s wiring
/// is testable with a mock. The production implementation routes toward `point`
/// with dig-dht `find_node`, then asks each peer found there for its
/// provider snapshot (RLY-009 `get_dht_records`) — that concrete probe lands
/// with the fetch child (#4); this module defines only the shape it consumes.
#[async_trait::async_trait]
pub trait NeighbourhoodProbe: Send + Sync {
    /// Observations of the peers near `point`. An unreachable region yields an
    /// empty vec (never an error) — a dead probe simply contributes nothing to
    /// the quorum, exactly like a peer that stayed silent.
    async fn observe_near(&self, point: [u8; 32]) -> Vec<PeerObservation>;
}

/// One full sampling round: sample `sample_points` keyspace points from `rng`,
/// probe each region through `probe`, and reconcile every observation gathered
/// into the admitted candidate set under `policy`.
///
/// Observations from ALL probed regions are reconciled TOGETHER, so a peer that
/// appears in two regions still counts once per key (the per-peer dedup in
/// [`reconcile`] holds across regions), and the quorum is measured against the
/// whole round rather than any single region.
pub async fn sample_candidates(
    probe: &dyn NeighbourhoodProbe,
    rng: &mut impl KeyspaceRng,
    sample_points: usize,
    policy: &QuorumPolicy,
) -> Vec<Candidate> {
    let mut observations = Vec::new();
    for point in sample_keyspace_points(rng, sample_points) {
        observations.extend(probe.observe_near(point).await);
    }
    reconcile(&observations, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An observation of one peer reporting one key with a given count/size.
    fn obs(peer: u8, key: [u8; 32], count: u32, size: Option<u64>) -> PeerObservation {
        PeerObservation {
            peer_id: [peer; 32],
            holdings: vec![ObservedCandidate {
                content_id: key,
                provider_count: count,
                size_hint: size,
            }],
        }
    }

    // -- Quorum: a single peer's junk never gets admitted --------------------------------------

    #[test]
    fn a_single_peers_unique_key_is_never_admitted() {
        // One peer, maximally lying (count = u32::MAX). With the default quorum
        // of 3 distinct peers, its unique key cannot cross the bar.
        let junk = [0xAA; 32];
        let admitted = reconcile(&[obs(1, junk, u32::MAX, Some(1))], &QuorumPolicy::default());
        assert!(
            admitted.is_empty(),
            "one peer alone must never get a key past the quorum"
        );
    }

    #[test]
    fn one_peer_reporting_a_key_many_times_still_counts_once() {
        // A peer cannot manufacture a quorum by listing the same key repeatedly:
        // its own duplicates collapse to a single distinct-peer vote.
        let key = [0x11; 32];
        let flooding_peer = PeerObservation {
            peer_id: [1; 32],
            holdings: vec![
                ObservedCandidate {
                    content_id: key,
                    provider_count: 5,
                    size_hint: None,
                },
                ObservedCandidate {
                    content_id: key,
                    provider_count: 9,
                    size_hint: None,
                },
                ObservedCandidate {
                    content_id: key,
                    provider_count: 7,
                    size_hint: None,
                },
            ],
        };
        let admitted = reconcile(&[flooding_peer], &QuorumPolicy::default());
        assert!(
            admitted.is_empty(),
            "a single peer's repeated reports are one vote, not a quorum"
        );
    }

    #[test]
    fn a_key_reported_by_the_quorum_is_admitted() {
        let key = [0x22; 32];
        let admitted = reconcile(
            &[
                obs(1, key, 4, Some(100)),
                obs(2, key, 4, Some(100)),
                obs(3, key, 4, Some(100)),
            ],
            &QuorumPolicy::default(),
        );
        assert_eq!(admitted.len(), 1, "three distinct peers clear the quorum");
        assert_eq!(admitted[0].content_id, key);
    }

    #[test]
    fn exactly_at_the_threshold_admits_and_one_below_rejects() {
        let key = [0x33; 32];
        let three = [
            obs(1, key, 1, None),
            obs(2, key, 1, None),
            obs(3, key, 1, None),
        ];
        assert_eq!(
            reconcile(&three, &QuorumPolicy::default()).len(),
            1,
            "exactly M distinct peers is admitted (>=, not >)"
        );
        assert!(
            reconcile(&three[..2], &QuorumPolicy::default()).is_empty(),
            "M-1 distinct peers is rejected"
        );
    }

    // -- Reconciled count is the median, never a liar's inflated max ---------------------------

    #[test]
    fn reconciled_count_is_the_median_not_the_liars_inflated_max() {
        // Three honest peers say ~5 providers; a fourth lies with u32::MAX. The
        // admitted count must track the honest cluster, not the lie.
        let key = [0x44; 32];
        let admitted = reconcile(
            &[
                obs(1, key, 5, None),
                obs(2, key, 6, None),
                obs(3, key, 5, None),
                obs(4, key, u32::MAX, None), // the inflating Sybil
            ],
            &QuorumPolicy::default(),
        );
        assert_eq!(admitted.len(), 1);
        let count = admitted[0].known_provider_count;
        assert!(
            count <= 6,
            "median must ignore the inflated max; got {count}"
        );
        assert!(
            count != u32::MAX,
            "a single liar must never set the reconciled count"
        );
    }

    #[test]
    fn a_single_deflating_liar_cannot_zero_the_count_either() {
        // The mirror attack: a liar reporting 0 to feign scarcity. The median
        // still tracks the honest majority.
        let key = [0x55; 32];
        let admitted = reconcile(
            &[
                obs(1, key, 8, None),
                obs(2, key, 8, None),
                obs(3, key, 9, None),
                obs(4, key, 0, None),
            ],
            &QuorumPolicy::default(),
        );
        assert!(
            admitted[0].known_provider_count >= 8,
            "a lone deflating liar cannot drag the median to zero"
        );
    }

    #[test]
    fn size_hint_is_reconciled_and_absent_when_no_peer_supplies_one() {
        let key = [0x66; 32];
        let with_sizes = reconcile(
            &[
                obs(1, key, 1, Some(10)),
                obs(2, key, 1, Some(20)),
                obs(3, key, 1, Some(1_000_000)), // outlier size
            ],
            &QuorumPolicy::default(),
        );
        let size = with_sizes[0].size_hint.expect("a size was supplied");
        assert!(size <= 20, "size hint is a robust median, not the outlier");

        let no_sizes = reconcile(
            &[
                obs(1, key, 1, None),
                obs(2, key, 1, None),
                obs(3, key, 1, None),
            ],
            &QuorumPolicy::default(),
        );
        assert_eq!(
            no_sizes[0].size_hint, None,
            "no size reported → None, not a fabricated zero"
        );
    }

    #[test]
    fn output_is_sorted_by_content_id_deterministically() {
        let low = [0x01; 32];
        let high = [0x99; 32];
        let quorum_for = |k: [u8; 32]| [obs(1, k, 1, None), obs(2, k, 1, None), obs(3, k, 1, None)];
        let mut all = quorum_for(high).to_vec();
        all.extend(quorum_for(low));
        let admitted = reconcile(&all, &QuorumPolicy::default());
        assert_eq!(
            admitted.iter().map(|c| c.content_id).collect::<Vec<_>>(),
            vec![low, high],
            "candidates come out sorted by content_id"
        );
    }

    // -- Keyspace sampling: deterministic + spread --------------------------------------------

    #[test]
    fn sampling_is_deterministic_under_a_seed() {
        let a = sample_keyspace_points(&mut SplitMix64::new(42), 8);
        let b = sample_keyspace_points(&mut SplitMix64::new(42), 8);
        assert_eq!(a, b, "the same seed replays the same points");

        let c = sample_keyspace_points(&mut SplitMix64::new(43), 8);
        assert_ne!(a, c, "a different seed yields different points");
    }

    #[test]
    fn sampling_covers_distinct_spread_keyspace_points() {
        let points = sample_keyspace_points(&mut SplitMix64::new(7), DEFAULT_SAMPLE_POINTS);
        assert_eq!(points.len(), DEFAULT_SAMPLE_POINTS);

        // All distinct (a good spread, not the same point repeated).
        let distinct: std::collections::BTreeSet<_> = points.iter().collect();
        assert_eq!(distinct.len(), points.len(), "sampled points are distinct");

        // The spread reaches both halves of the keyspace rather than clustering
        // in one corner — the top bit is set for some points and clear for others.
        assert!(
            points.iter().any(|p| p[0] & 0x80 != 0) && points.iter().any(|p| p[0] & 0x80 == 0),
            "sampling spans both halves of the keyspace"
        );
    }

    #[test]
    fn sampling_zero_points_is_empty() {
        assert!(sample_keyspace_points(&mut SplitMix64::new(1), 0).is_empty());
    }

    // -- The async composition over a mock probe ----------------------------------------------

    /// A probe that returns canned observations per keyspace point, so the
    /// composition is exercised with no network.
    struct MockProbe {
        by_point: std::collections::HashMap<[u8; 32], Vec<PeerObservation>>,
    }

    #[async_trait::async_trait]
    impl NeighbourhoodProbe for MockProbe {
        async fn observe_near(&self, point: [u8; 32]) -> Vec<PeerObservation> {
            self.by_point.get(&point).cloned().unwrap_or_default()
        }
    }

    #[tokio::test]
    async fn sample_candidates_reconciles_across_probed_regions() {
        // Seed the probe with observations keyed by the points seed 99 produces,
        // so the sampled points actually hit the canned regions.
        let points = sample_keyspace_points(&mut SplitMix64::new(99), 2);
        let key = [0x77; 32];
        let mut by_point = std::collections::HashMap::new();
        // Region 0: peers 1 and 2 report the key. Region 1: peer 3 reports it.
        // Only across BOTH regions does the key reach the 3-peer quorum — proving
        // the composition reconciles regions together, not in isolation.
        by_point.insert(points[0], vec![obs(1, key, 4, None), obs(2, key, 4, None)]);
        by_point.insert(points[1], vec![obs(3, key, 4, None)]);
        let probe = MockProbe { by_point };

        let admitted = sample_candidates(
            &probe,
            &mut SplitMix64::new(99),
            2,
            &QuorumPolicy::default(),
        )
        .await;
        assert_eq!(
            admitted.len(),
            1,
            "a key split across two regions still clears the whole-round quorum"
        );
        assert_eq!(admitted[0].content_id, key);
    }

    #[tokio::test]
    async fn sample_candidates_drops_a_key_only_one_region_corroborates() {
        let points = sample_keyspace_points(&mut SplitMix64::new(5), 2);
        let key = [0x88; 32];
        let mut by_point = std::collections::HashMap::new();
        // Only two distinct peers total across all regions → below quorum.
        by_point.insert(points[0], vec![obs(1, key, 4, None)]);
        by_point.insert(points[1], vec![obs(2, key, 4, None)]);
        let probe = MockProbe { by_point };

        let admitted =
            sample_candidates(&probe, &mut SplitMix64::new(5), 2, &QuorumPolicy::default()).await;
        assert!(
            admitted.is_empty(),
            "two distinct peers across the round is still under the quorum"
        );
    }
}
