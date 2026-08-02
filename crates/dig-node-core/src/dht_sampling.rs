//! DHT random-sampling candidate discovery with multi-peer anti-Sybil quorum
//! reconciliation (epic #1934, child 2/7).
//!
//! This module answers ONE question: *which `.dig` store keys are worth even
//! considering for speculative precache?* It produces the CANDIDATE SET that
//! feeds [`crate::relevance::RelevanceInputs`] (the `content_id` + an untrusted
//! `known_provider_count`); it does NOT score candidates (that is
//! [`crate::relevance`], child #1) and does NOT select or fetch them (that is
//! [`crate::tier0_selector`], child #3, and the fetch loop, child #4).
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
    /// [`crate::relevance::RelevanceInputs::content_id`] for XOR proximity.
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

/// An admitted candidate, ready to become a [`crate::relevance::RelevanceInputs`].
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

/// Reconcile per-peer observations into the admitted candidate set: a content
/// key is kept only when at least `policy.min_distinct_peers` DISTINCT peers
/// report it, and each kept key's provider count is a robust cross-peer
/// aggregate (never a single peer's inflated claim).
#[must_use]
pub fn reconcile(_observations: &[PeerObservation], _policy: &QuorumPolicy) -> Vec<Candidate> {
    todo!("child 2/7 — implement quorum reconciliation")
}

/// Sample `k` random keyspace points from `rng` — the WHICH-to-probe half.
pub fn sample_keyspace_points(_rng: &mut impl KeyspaceRng, _k: usize) -> Vec<[u8; 32]> {
    todo!("child 2/7 — implement keyspace sampling")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_peers_unique_key_is_never_admitted() {
        let junk = [0xAA; 32];
        let observations = vec![PeerObservation {
            peer_id: [1; 32],
            holdings: vec![ObservedCandidate {
                content_id: junk,
                provider_count: u32::MAX,
                size_hint: Some(1),
            }],
        }];
        let admitted = reconcile(&observations, &QuorumPolicy::default());
        assert!(
            admitted.is_empty(),
            "one peer alone must never get a key past the quorum"
        );
    }
}
