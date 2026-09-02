//! Which pool peers a forwarded ask is routed to, ranked by what THIS node has observed
//! (dig_ecosystem#3129 WU2, `dig-sex` 0.5 `routing`, SPEC §6.1.2).
//!
//! [`dig_sex::discovery::decide_forward`] used to receive the connected pool as a bare slice and take
//! a prefix of it. The pool arrives from a `HashMap`, so that prefix was not a random sample — it was
//! a *fixed arbitrary* one, and the same handful of peers absorbed every forwarded ask for the life
//! of the process. `dig-sex` 0.5 replaces the prefix with an order derived from observed answer
//! quality; this module is the adapter that supplies the two things the crate cannot obtain for
//! itself: a routing identity, and the outcomes to rank on.
//!
//! # THE load-bearing security property: the routing identity is the VERIFIED session identity
//!
//! `dig-sex` is generic over its `Peer`, so [`dig_sex::RoutablePeer::routing_key`] is the exact point
//! at which a peer could otherwise choose where it lands in this node's tiebreaks. A router that
//! rewards novelty and lets a peer pick its own identity is an eclipse attack with extra steps: a
//! hostile peer mints identities until it owns the reserved exploration slot and attracts every
//! query (NC-12).
//!
//! [`RoutedPeer`] therefore wraps the 32-byte `peer_id` that dig-gossip computed itself during the
//! mTLS handshake — `SHA-256(verified peer-cert SPKI DER)` — and NOTHING else. It is built by
//! [`RoutedPeer::from_pool_key`] from a key of the connected-pool map, whose only writer is
//! `PoolEvent::PeerAdded`'s `peer_id.to_hex()`. There is deliberately no constructor from an address,
//! from a provider record, from a dig-dht `Contact`, or from any field of any frame — the same rule
//! [`neighbourhood_probe`](crate::seams::dig_peer::neighbourhood_probe) already holds for its
//! anti-Sybil vote identity. Influencing the routing key costs a keypair AND admission to this node's
//! connected pool, and the tiebreak still mixes in a node-local seed the peer cannot observe.
//!
//! # The observations are CALLER-OBSERVED, and there is no other way in
//!
//! [`AskRoutingState::record`] is called from exactly one place — the forwarded-ask loop, once per
//! exchange this node itself issued and saw complete — and it is fed the
//! [`AskOutcome`](crate::seams::dig_peer::AskOutcome) that loop already classified plus a latency this
//! node measured on its own clock. No peer supplies a quality, a score, or a latency; a peer's only
//! influence is how it actually answers, which is the influence the ranking exists to reward.
//!
//! # Bounds: pool membership is the liveness gate, so there is no TTL
//!
//! [`AskRoutingState::decide`] calls [`dig_sex::AskObservations::retain`] with the CURRENT pool before
//! every decision, so a peer that has been cycled away leaves this node's memory at the same moment it
//! leaves the pool. The map is therefore keyed only by peers this node holds a verified session to,
//! never by untrusted input, and it cannot grow while the pool does not.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use dig_sex::discovery::{ForwardDecision, InboundAsk, RecursionConfig};
use dig_sex::{AskObservations, AskRouting, RoutablePeer, SelectionSeed};

use crate::seams::dig_peer::AskOutcome;

/// The [`SelectionSeed`] used before this node knows its own `peer_id`.
///
/// The seed decorrelates THIS node's tiebreaks from every other node's. Peer-network bring-up is
/// asynchronous, so an ask can in principle be decided before an identity exists; that window needs a
/// seed that is still not peer-derivable, which a fixed node-local constant satisfies. Distinct from
/// the eviction sweep's constant so the two orderings do not become correlated.
const UNIDENTIFIED_ROUTING_SEED: SelectionSeed =
    SelectionSeed::from_node_local(0x6469_675f_6173_6b73); // b"dig_asks"

/// One tick of the recency/latency clock, in wall time.
///
/// A second. `dig-sex` measures the latency scale in 4 ticks and the recency half-life in 900, which
/// read as a 4-second "a slow answer is worth less" scale and a 15-minute half-life — both the right
/// order for a recursive ask over the open internet. A sub-second answer rounds to zero ticks and so
/// scores full marks for speed, which is honest: nothing here needs to separate 40ms from 200ms.
const TICK: Duration = Duration::from_secs(1);

/// A pool peer, identified by the `peer_id` this node's own mTLS handshake produced.
///
/// See the module docs: this type existing at all is the security boundary, because it is the only
/// way a `dig-sex` routing key can be minted and it can only be minted from a verified identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RoutedPeer([u8; 32]);

impl RoutedPeer {
    /// The peer named by a connected-pool key — the 64-hex `SHA-256(TLS SPKI DER)` that
    /// `PoolEvent::PeerAdded` wrote. `None` for anything that is not one, so a malformed key drops out
    /// of routing entirely rather than being routed to under a fabricated identity.
    pub(crate) fn from_pool_key(key: &str) -> Option<Self> {
        let mut id = [0u8; 32];
        hex::decode_to_slice(key, &mut id).ok()?;
        Some(Self(id))
    }

    /// The peer that is not anybody, for the two exclusions `decide_forward` applies by identity.
    ///
    /// A requestor that is not a peer (a local caller) and an unresolved self-identity both need a
    /// value that excludes NOTHING. An all-zero `peer_id` is that value: it is a SHA-256 digest, so no
    /// real pool member can hold it, and equality against it therefore never fires. The previous
    /// `&str` shape used the empty string for exactly this reason and for exactly as long.
    pub(crate) const fn nobody() -> Self {
        Self([0u8; 32])
    }

    /// The 64-hex form, for looking this peer back up in the pool map.
    pub(crate) fn to_pool_key(self) -> String {
        hex::encode(self.0)
    }
}

impl RoutablePeer for RoutedPeer {
    /// The leading 8 bytes of the verified SPKI hash.
    ///
    /// A truncation of a digest, not a hash of a name: the value is uniform, and a peer that wanted a
    /// particular one would have to grind a keypair for it — and would then still face a tiebreak
    /// mixed with a node-local seed it cannot observe.
    fn routing_key(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("32 bytes has a leading 8"))
    }
}

/// This node's memory of how its pool peers answer forwarded asks, plus the seed its tiebreaks use.
#[derive(Debug)]
pub(crate) struct AskRoutingState {
    observations: Mutex<AskObservations<RoutedPeer>>,
    seed: SelectionSeed,
    epoch: Instant,
}

impl AskRoutingState {
    /// A fresh, empty routing memory seeded from this node's own `peer_id` (64-hex), or from the
    /// node-local constant when bring-up has not produced one yet.
    pub(crate) fn new(self_peer_id: Option<&str>) -> Self {
        let seed = self_peer_id
            .and_then(RoutedPeer::from_pool_key)
            .map_or(UNIDENTIFIED_ROUTING_SEED, |me| {
                SelectionSeed::from_peer_id(&me.0)
            });
        Self {
            observations: Mutex::new(AskObservations::default()),
            seed,
            epoch: Instant::now(),
        }
    }

    /// Decide the forwarded ask against the ranked pool.
    ///
    /// Everything about the decision except the ORDER is `dig-sex`'s and is untouched here: the
    /// fan-out, the hop cap, the two identity exclusions and every refusal arm. This adds the ranking
    /// input and drops the observations of peers no longer in `pool`, in that order, so a departed
    /// peer can neither be ranked nor remembered.
    pub(crate) fn decide(
        &self,
        config: &RecursionConfig,
        requestor: RoutedPeer,
        hops_remaining: Option<u8>,
        this_node: RoutedPeer,
        pool: &[RoutedPeer],
        relay_budget_available: bool,
    ) -> ForwardDecision<RoutedPeer> {
        let mut observations = self.lock();
        observations.retain(pool);
        dig_sex::discovery::decide_forward(
            config,
            &InboundAsk {
                requestor,
                hops_remaining,
            },
            &this_node,
            pool,
            relay_budget_available,
            &AskRouting {
                seed: self.seed,
                observations: &observations,
                now_ticks: self.now_ticks(),
            },
        )
    }

    /// Fold in one exchange this node issued and saw complete.
    ///
    /// The mapping from dig-node's five wire outcomes onto `dig-sex`'s three is the whole judgement
    /// here, and it follows SPEC §8.2A: answering is never worse than not answering. A peer that named
    /// a holder is `Conclusive`; a peer that answered and named nobody — whether it proved the absence
    /// or admitted it could not — is `Inconclusive`, because an honest empty answer is still an
    /// answer; a refusal, a timeout and an unreachable peer are `Silent`, because none of them looked.
    pub(crate) fn record(&self, peer: RoutedPeer, outcome: &AskOutcome, latency: Duration) {
        let observed = match outcome {
            AskOutcome::Answered(records) | AskOutcome::AnsweredInconclusive(records)
                if !records.is_empty() =>
            {
                dig_sex::AskOutcome::Conclusive
            }
            AskOutcome::Answered(_) | AskOutcome::AnsweredInconclusive(_) => {
                dig_sex::AskOutcome::Inconclusive
            }
            AskOutcome::Refused | AskOutcome::TimedOut | AskOutcome::Unreachable => {
                dig_sex::AskOutcome::Silent
            }
        };
        let now = self.now_ticks();
        self.lock().record(peer, observed, ticks(latency), now);
    }

    /// How many peers this node currently remembers. Test-only: production never reads the size, and
    /// the bound it proves is the pool's, not a number this code chooses.
    #[cfg(test)]
    pub(crate) fn observed_len(&self) -> usize {
        self.lock().len()
    }

    /// Whether this node has ever observed `peer` answer. Test-only, for the same reason.
    #[cfg(test)]
    pub(crate) fn is_unobserved(&self, peer: RoutedPeer) -> bool {
        self.lock().of(&peer).is_unobserved()
    }

    /// The quality `dig-sex` currently scores `peer` at. Test-only: production never reads a score,
    /// it reads the ORDER, and a caller able to read a score would be tempted to re-derive the
    /// ranking here instead of asking the crate that owns it.
    #[cfg(test)]
    pub(crate) fn quality_of(&self, peer: RoutedPeer) -> f64 {
        let now = self.now_ticks();
        self.lock().of(&peer).quality(now)
    }

    fn now_ticks(&self) -> u64 {
        ticks(self.epoch.elapsed())
    }

    /// A poisoned routing memory is recovered rather than propagated: losing the ranking degrades the
    /// order of a forwarded ask, which is never worth failing a read over.
    fn lock(&self) -> std::sync::MutexGuard<'_, AskObservations<RoutedPeer>> {
        self.observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A duration as whole [`TICK`]s.
fn ticks(elapsed: Duration) -> u64 {
    (elapsed.as_secs_f64() / TICK.as_secs_f64()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};

    fn peer(byte: u8) -> RoutedPeer {
        RoutedPeer([byte; 32])
    }

    /// The routing key must come from the verified `peer_id` bytes and nothing else, so a pool key and
    /// the identity it names round-trip exactly. The fixture uses two peers differing only in their
    /// TRAILING bytes as well as their leading ones, because a key read from the wrong end of the
    /// digest would still look plausible on a single-peer fixture.
    #[test]
    fn a_routing_key_is_the_leading_eight_bytes_of_the_verified_peer_id() {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        id[31] = 0xff;
        let routed = RoutedPeer::from_pool_key(&hex::encode(id)).expect("64-hex is a pool key");

        assert_eq!(routed.routing_key(), 0x0123_4567_89ab_cdef);
        assert_eq!(routed.to_pool_key(), hex::encode(id));
    }

    /// A key that is not a 64-hex `peer_id` yields no routable peer at all. Without this a malformed
    /// or truncated key would have to be given SOME identity, and any such identity is fabricated —
    /// which is precisely the channel the verified-identity rule closes.
    #[test]
    fn a_malformed_pool_key_names_no_routable_peer() {
        for key in ["", "zz", &"ab".repeat(31), &"ab".repeat(33), "not-hex"] {
            assert!(
                RoutedPeer::from_pool_key(key).is_none(),
                "{key:?} must not mint an identity"
            );
        }
    }

    /// The nobody sentinel must exclude nothing, so it may never equal a real pool member. Asserted
    /// against a peer whose id is all-ones as well as a realistic digest, because an equality written
    /// against the wrong field could still pass on a single hand-picked value.
    #[test]
    fn the_nobody_sentinel_equals_no_real_peer() {
        assert_ne!(RoutedPeer::nobody(), peer(0x01));
        assert_ne!(RoutedPeer::nobody(), peer(0xff));
        assert_eq!(RoutedPeer::nobody(), RoutedPeer::nobody());
    }

    /// A peer dropped from the pool must be forgotten at that moment — the property that replaces a
    /// TTL. Two peers are observed and only ONE is removed, so a `retain` that cleared everything (or
    /// nothing) fails just as loudly as one that kept the departed peer.
    #[test]
    fn an_observation_is_dropped_when_its_peer_leaves_the_pool() {
        let state = AskRoutingState::new(None);
        state.record(peer(1), &AskOutcome::Answered(vec![]), Duration::ZERO);
        state.record(peer(2), &AskOutcome::Answered(vec![]), Duration::ZERO);
        assert_eq!(state.observed_len(), 2);

        let _ = state.decide(
            &RecursionConfig::default(),
            RoutedPeer::nobody(),
            Some(2),
            RoutedPeer::nobody(),
            &[peer(1)],
            true,
        );

        assert_eq!(state.observed_len(), 1, "only the departed peer is dropped");
        assert!(
            state.is_unobserved(peer(2)),
            "the departed peer is forgotten"
        );
        assert!(
            !state.is_unobserved(peer(1)),
            "the peer still in the pool keeps its history"
        );
    }

    /// **The distinguishing test for the whole adoption:** the slate `decide_forward` chooses from is
    /// ORDERED by observation, not taken as a prefix of the caller's slice.
    ///
    /// The fixture puts the well-observed peer LAST in the pool and asks for a fan-out of one, so a
    /// prefix implementation — the shipped 0.4 behaviour, and the thing this adoption replaces — must
    /// return the first peer while a ranking implementation must return the last. Order is supplied
    /// explicitly rather than through a `HashMap`, because a fixture that could not control the input
    /// order could not tell the two implementations apart at all.
    ///
    /// A fan-out of one is deliberate: at two or more, `select_fan_out` reserves a slot for an
    /// unobserved peer, and the reserved slot alone would satisfy a weaker assertion.
    #[test]
    fn the_best_observed_peer_is_chosen_even_when_it_is_last_in_the_pool() {
        let state = AskRoutingState::new(None);
        let content = ContentId::store([9u8; 32]);
        let holder = ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([7u8; 32]),
            vec![CandidateAddr::direct("10.0.0.7".to_string(), 9444)],
            u64::MAX,
        );
        state.record(peer(1), &AskOutcome::Unreachable, Duration::ZERO);
        state.record(peer(2), &AskOutcome::Unreachable, Duration::ZERO);
        state.record(peer(3), &AskOutcome::Answered(vec![holder]), Duration::ZERO);

        let config = RecursionConfig {
            enabled: true,
            fan_out: 1,
            ..Default::default()
        };
        let decision = state.decide(
            &config,
            RoutedPeer::nobody(),
            Some(2),
            RoutedPeer::nobody(),
            &[peer(1), peer(2), peer(3)],
            true,
        );

        let ForwardDecision::Forward { peers, .. } = decision else {
            panic!("an enabled node with budget and eligible peers must forward: {decision:?}");
        };
        assert_eq!(
            peers,
            vec![peer(3)],
            "the observed-good peer is chosen, not the head of the slice"
        );
    }

    /// **Proves the ranking is an ADDITION, not a replacement:** every refusal `dig-sex` owns still
    /// fires through this seam, unchanged.
    ///
    /// Each arm is driven by the one input that produces it, so an adapter that swallowed a refusal —
    /// by pre-filtering the pool, by defaulting an unreadable budget, or by deciding locally — reddens
    /// on the arm it broke rather than on a single catch-all.
    #[test]
    fn every_refusal_the_crate_owns_still_reaches_the_caller() {
        use dig_sex::discovery::ForwardRefusal;

        /// One refusal and the single input that produces it.
        struct Case {
            config: RecursionConfig,
            hops_remaining: Option<u8>,
            pool: Vec<RoutedPeer>,
            relay_budget_available: bool,
            expected: ForwardRefusal,
        }

        let state = AskRoutingState::new(None);
        let on = RecursionConfig {
            enabled: true,
            ..Default::default()
        };
        let askable = || vec![peer(1)];
        let cases = [
            Case {
                config: RecursionConfig::default(),
                hops_remaining: Some(2),
                pool: askable(),
                relay_budget_available: true,
                expected: ForwardRefusal::Disabled,
            },
            Case {
                config: on,
                hops_remaining: None,
                pool: askable(),
                relay_budget_available: true,
                expected: ForwardRefusal::UnreadableHopBudget,
            },
            Case {
                config: on,
                hops_remaining: Some(0),
                pool: askable(),
                relay_budget_available: true,
                expected: ForwardRefusal::HopBudgetSpent,
            },
            Case {
                config: on,
                hops_remaining: Some(2),
                pool: askable(),
                relay_budget_available: false,
                expected: ForwardRefusal::RelayBudgetSpent,
            },
            Case {
                config: on,
                hops_remaining: Some(2),
                pool: Vec::new(),
                relay_budget_available: true,
                expected: ForwardRefusal::NoEligiblePeers,
            },
        ];
        for case in cases {
            let decision = state.decide(
                &case.config,
                RoutedPeer::nobody(),
                case.hops_remaining,
                RoutedPeer::nobody(),
                &case.pool,
                case.relay_budget_available,
            );
            assert_eq!(
                decision,
                ForwardDecision::Refuse(case.expected),
                "{:?} must survive the adapter",
                case.expected
            );
        }
    }

    /// **Proves the two identity exclusions still hold** now that they are stated over verified
    /// `peer_id`s rather than hex strings. Both are present at once with a third, askable peer, so a
    /// filter that dropped everything — which would satisfy a "the requestor was not asked" assertion
    /// vacuously — fails here.
    #[test]
    fn neither_the_requestor_nor_this_node_is_ever_asked() {
        let state = AskRoutingState::new(None);
        let config = RecursionConfig {
            enabled: true,
            ..Default::default()
        };
        let decision = state.decide(
            &config,
            peer(1),
            Some(2),
            peer(2),
            &[peer(1), peer(2), peer(3)],
            true,
        );

        let ForwardDecision::Forward { peers, .. } = decision else {
            panic!("a third eligible peer exists, so this must forward: {decision:?}");
        };
        assert_eq!(peers, vec![peer(3)]);
    }

    /// Answering is never worse than not answering, and naming a holder is better still (SPEC §8.2A).
    ///
    /// **Pins the ORDER, not merely that something was recorded.** All five wire outcomes are present
    /// at once and the assertion is a strict chain over their scores, so a mapping that collapsed any
    /// two of the three observation classes into one — the realistic way this match goes wrong —
    /// fails, and so does one that inverted a pair. An `Answered` carrying a holder and an `Answered`
    /// carrying none are BOTH present, because that pair is the only thing separating `Conclusive`
    /// from `Inconclusive` and a fixture with empty vectors alone cannot see it.
    #[test]
    fn naming_a_holder_beats_an_empty_answer_which_beats_not_answering() {
        let state = AskRoutingState::new(None);
        let content = ContentId::store([9u8; 32]);
        let holder = ProviderRecord::new(
            &content.to_key(),
            &PeerId::from_bytes([7u8; 32]),
            vec![CandidateAddr::direct("10.0.0.7".to_string(), 9444)],
            u64::MAX,
        );

        state.record(
            peer(1),
            &AskOutcome::Answered(vec![holder.clone()]),
            Duration::ZERO,
        );
        state.record(
            peer(2),
            &AskOutcome::AnsweredInconclusive(vec![holder]),
            Duration::ZERO,
        );
        state.record(peer(3), &AskOutcome::Answered(vec![]), Duration::ZERO);
        state.record(
            peer(4),
            &AskOutcome::AnsweredInconclusive(vec![]),
            Duration::ZERO,
        );
        state.record(peer(5), &AskOutcome::Refused, Duration::ZERO);
        state.record(peer(6), &AskOutcome::TimedOut, Duration::ZERO);
        state.record(peer(7), &AskOutcome::Unreachable, Duration::ZERO);

        let named = state.quality_of(peer(1));
        let empty = state.quality_of(peer(3));
        let silent = state.quality_of(peer(5));

        assert!(
            named > empty,
            "naming a holder ({named}) beats an empty answer ({empty})"
        );
        assert!(
            empty > silent,
            "an empty answer ({empty}) beats silence ({silent})"
        );
        assert_eq!(
            state.quality_of(peer(2)),
            named,
            "a holder named alongside an unfinished subtree is still a holder named"
        );
        assert_eq!(
            state.quality_of(peer(4)),
            empty,
            "an unfinished subtree that named nobody scores as an empty answer"
        );
        for byte in [6u8, 7] {
            assert_eq!(
                state.quality_of(peer(byte)),
                silent,
                "every non-answer scores as silence"
            );
        }
    }
}
