//! Peer conduct, and the dial share it earns (dig-sex SPEC §8.2A, dig-node#268).
//!
//! `dig_sex::conduct` classifies what this node observed a peer do and answers how much of the dial
//! budget that peer has earned. It was implemented, tested, and received not one observation from
//! dig-node. This module is the node's half: it holds the per-peer records, feeds them the outcomes
//! the ask loop already classifies, and exposes [`ConductState::dial_share`] so the ranking actually
//! spends fewer dials on peers that do not answer.
//!
//! # Why the classes are kept apart, and why that is a security property
//!
//! A **proven lie** (bytes that fail verification against the chain-anchored root) and a
//! **self-contradiction** (a peer that claimed to hold content, then answered absence) are both
//! *verifiable*: arithmetic and the peer's own words, checkable without trusting anyone. They carry a
//! durable penalty.
//!
//! **Non-performance** — a timeout, a reset, silence, a truncation — is *not* verifiable. It is
//! indistinguishable from genuine distress, and an attacker can manufacture it in an honest third
//! party by loading it up. So it decays on elapsed time alone, is capped, and MUST NOT reduce a dial
//! share to zero: if it could, inducing distress would become a way to evict an honest holder from
//! everybody's routing table. The crate enforces all three of those; this module's job is not to
//! undo them by feeding the wrong class.
//!
//! # Reputation is node-LOCAL and is never gossiped
//!
//! Nothing here is advertised, exchanged, or written to a peer-visible surface. A shared reputation
//! channel is a defamation primitive — one node's claim that a peer lied becomes every node's belief,
//! with no way to check it — so a record earned here influences only this node's own dialling.
//!
//! # Bounds: the pool is the liveness gate, so there is no TTL
//!
//! [`ConductState::retain`] is called with the CURRENT pool before every read, exactly as
//! [`AskRoutingState`](super::ask_routing) does for its observations. The map is therefore keyed only
//! by peers this node holds a verified session to and cannot grow while the pool does not — an
//! attacker cannot inflate it by minting identities it never connects with.

use std::collections::HashMap;
use std::sync::Mutex;

use dig_sex::{ConductEvidence, ConductRecord};

use super::ask_routing::RoutedPeer;

/// This node's memory of how its pool peers have behaved.
///
/// Keyed by [`RoutedPeer`] — the mTLS-verified `peer_id`, the same identity the ask router ranks on —
/// so a peer's conduct cannot be attributed to, or escaped by, an identity it chose for itself.
#[derive(Debug, Default)]
pub(crate) struct ConductState {
    records: Mutex<HashMap<RoutedPeer, ConductRecord>>,
}

impl ConductState {
    /// An empty conduct memory.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<RoutedPeer, ConductRecord>> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Fold one observation about `peer` into its record.
    ///
    /// An unseen peer starts from [`ConductRecord::neutral`], never from a penalised one: a peer this
    /// node has no history with must be indistinguishable from one that has behaved, or a fresh
    /// identity would be *better* than an honest long-lived one and the ranking would reward churn.
    pub(crate) fn observe(&self, peer: RoutedPeer, evidence: ConductEvidence, now_ticks: u64) {
        let mut records = self.lock();
        let record = records
            .get(&peer)
            .copied()
            .unwrap_or_else(ConductRecord::neutral);
        records.insert(peer, dig_sex::observe(record, evidence, now_ticks));
    }

    /// The share of the dial budget `peer` has earned, in `0.0..=1.0`.
    ///
    /// Decay is applied at READ time rather than on a timer, because the crate's decay is a pure
    /// function of elapsed ticks — so a peer whose non-performance has aged out recovers **without
    /// this node having to talk to it**. That direction is the point: a peer punished for silence
    /// that could only be forgiven by answering could never recover, because it is not being asked.
    pub(crate) fn dial_share(&self, peer: RoutedPeer, now_ticks: u64) -> f64 {
        let record = self
            .lock()
            .get(&peer)
            .copied()
            .unwrap_or_else(ConductRecord::neutral);
        dig_sex::dial_share(dig_sex::decay(record, now_ticks))
    }

    /// The subset of `pool` this node will still spend a dial on, worst conduct excluded.
    ///
    /// The threshold is "a share above zero", and it is not an arbitrary cut: `dig_sex::dial_share`
    /// returns exactly `0.0` for a peer with a PROVEN fault and floors every non-performance penalty
    /// at [`MIN_NON_PERFORMANCE_DIAL_SHARE`](dig_sex::MIN_NON_PERFORMANCE_DIAL_SHARE). So this
    /// excludes precisely the peers that lied or contradicted themselves — SPEC 8.3's durable
    /// exclusion, earned by verifiable evidence — and can never exclude a peer that was merely slow,
    /// however slow it was. Picking any threshold above the floor instead would hand an attacker the
    /// eviction primitive the floor exists to deny.
    ///
    /// `retain` runs first, so a peer that left the pool is neither ranked nor remembered.
    pub(crate) fn dialable(&self, pool: &[RoutedPeer], now_ticks: u64) -> Vec<RoutedPeer> {
        self.retain(pool);
        pool.iter()
            .copied()
            .filter(|peer| self.dial_share(*peer, now_ticks) > 0.0)
            .collect()
    }

    /// Drop the records of peers no longer in `pool`, so this map is bounded by pool membership.
    pub(crate) fn retain(&self, pool: &[RoutedPeer]) {
        self.lock().retain(|peer, _| pool.contains(peer));
    }

    /// How many peers this node currently holds conduct for. Test-only: the bound it proves is the
    /// pool's, not a number this code chooses.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> RoutedPeer {
        RoutedPeer::from_pool_key(&hex::encode([n; 32])).expect("64-hex is a pool key")
    }

    /// **Proves (#268):** a peer that delivers bytes failing verification loses dial share, while a
    /// peer observed answering honestly at the same moment keeps its full share.
    ///
    /// The honest peer is the load-bearing half. Asserting only that the liar drops passes on an
    /// implementation that penalises EVERY peer — including the one that behaved — because that
    /// implementation also drops the liar. Varying one actor against a truthful control is what
    /// separates "conduct is read" from "a number went down".
    #[test]
    fn a_proven_lie_costs_dial_share_while_an_honest_peer_keeps_its_own() {
        let conduct = ConductState::new();
        let liar = peer(0xa1);
        let honest = peer(0xb2);

        conduct.observe(liar, ConductEvidence::ProvenLie, 0);
        conduct.observe(honest, ConductEvidence::HonestAnswer, 0);

        let liar_share = conduct.dial_share(liar, 0);
        let honest_share = conduct.dial_share(honest, 0);

        assert!(
            liar_share < honest_share,
            "a proven lie must cost dial share (liar {liar_share}, honest {honest_share})"
        );
        assert!(
            (honest_share - 1.0).abs() < f64::EPSILON,
            "the honest peer must be unpenalised, or every peer is being penalised alike \
             (got {honest_share})"
        );
    }

    /// **Proves (#268):** a proven lie is DURABLE — it does not decay, however much time passes.
    ///
    /// This is the direction that distinguishes the two verifiable classes from non-performance, and
    /// it is asserted at a tick far beyond the non-performance decay window so a decay applied to the
    /// wrong field would show up here rather than passing silently.
    #[test]
    fn a_proven_lie_does_not_decay_with_elapsed_time() {
        let conduct = ConductState::new();
        let liar = peer(0xa2);
        conduct.observe(liar, ConductEvidence::ProvenLie, 0);

        let immediately = conduct.dial_share(liar, 0);
        let much_later = conduct.dial_share(liar, dig_sex::NON_PERFORMANCE_DECAY_TICKS * 100);

        assert!(
            (immediately - much_later).abs() < f64::EPSILON,
            "a verifiable fault is a fact about what the peer did and must not age away \
             ({immediately} then {much_later})"
        );
    }

    /// **Proves (#268):** non-performance costs some share and then recovers on ELAPSED TIME ALONE —
    /// the peer is never spoken to between the two reads.
    ///
    /// That is the property that keeps an attacker from evicting an honest holder by manufacturing
    /// distress in it. A recovery that required a fresh successful exchange would be unreachable for a
    /// peer nobody is dialling any more, which is precisely the peer being punished.
    #[test]
    fn non_performance_decays_on_elapsed_time_without_the_peer_being_talked_to() {
        let conduct = ConductState::new();
        let distressed = peer(0xc3);

        conduct.observe(distressed, ConductEvidence::NonPerformance, 0);
        let penalised = conduct.dial_share(distressed, 0);
        assert!(
            penalised < 1.0,
            "a timeout must cost something, or the observation is not being read ({penalised})"
        );

        // No `observe` between these two reads: nothing happened except the clock moving.
        let recovered = conduct.dial_share(distressed, dig_sex::NON_PERFORMANCE_DECAY_TICKS * 4);
        assert!(
            recovered > penalised,
            "non-performance must decay on elapsed time alone ({penalised} then {recovered})"
        );
    }

    /// **Proves (#268):** sustained non-performance never reduces a dial share to zero.
    ///
    /// Far more observations than the crate's ceiling, so an implementation that let the penalty run
    /// unbounded would reach zero here. A zero share means an honest peer that a hostile third party
    /// merely made SLOW can be removed from this node's dialling entirely — the eviction the floor
    /// exists to prevent.
    #[test]
    fn sustained_non_performance_never_silences_a_peer_completely() {
        let conduct = ConductState::new();
        let distressed = peer(0xd4);
        for _ in 0..(dig_sex::NON_PERFORMANCE_CEILING * 10) {
            conduct.observe(distressed, ConductEvidence::NonPerformance, 0);
        }

        let share = conduct.dial_share(distressed, 0);
        assert!(
            share >= dig_sex::MIN_NON_PERFORMANCE_DIAL_SHARE,
            "unverifiable distress must never drive a share below the floor (got {share})"
        );
        assert!(share > 0.0, "a distressed honest peer must remain dialable");
    }

    /// **Proves (#268):** an unobserved peer is treated as neutral, not as suspect.
    ///
    /// Guards the direction where a missing record is read as a bad one — which would make every newly
    /// connected peer worse than a known-mediocre one and quietly freeze the routing table.
    #[test]
    fn an_unobserved_peer_starts_neutral_rather_than_penalised() {
        let conduct = ConductState::new();
        let share = conduct.dial_share(peer(0xe5), 0);
        assert!(
            (share - 1.0).abs() < f64::EPSILON,
            "a peer with no history must be indistinguishable from one that behaved (got {share})"
        );
    }

    /// **Proves (#268):** conduct is bounded by pool membership — a departed peer leaves this node's
    /// memory when it leaves the pool, so the map cannot grow while the pool does not.
    #[test]
    fn retain_drops_peers_that_left_the_pool() {
        let conduct = ConductState::new();
        let stays = peer(0x01);
        let goes = peer(0x02);
        conduct.observe(stays, ConductEvidence::NonPerformance, 0);
        conduct.observe(goes, ConductEvidence::ProvenLie, 0);
        assert_eq!(conduct.len(), 2);

        conduct.retain(&[stays]);

        assert_eq!(conduct.len(), 1, "the departed peer must be forgotten");
        assert!(
            (conduct.dial_share(goes, 0) - 1.0).abs() < f64::EPSILON,
            "a forgotten peer returns to neutral — its durable fault was dropped WITH its session, \
             which is the bound's cost and is deliberate: the alternative is an unbounded map keyed \
             by identities an attacker mints for free"
        );
    }

    /// **Proves (#268):** the dial filter excludes a proven liar from the peers this node will spend
    /// a dial on, and leaves a merely-distressed peer in.
    ///
    /// This is the assertion that makes the whole wiring load-bearing rather than merely reachable:
    /// it is about the SET the node dials, not about a number a function returned. The distressed
    /// peer is the control, and it is the half that catches an over-eager filter — a threshold set
    /// anywhere above the non-performance floor would drop it too, handing an attacker exactly the
    /// eviction primitive the floor exists to deny.
    #[test]
    fn a_proven_liar_leaves_the_dial_set_while_a_merely_slow_peer_stays_in_it() {
        let conduct = ConductState::new();
        let liar = peer(0x11);
        let slow = peer(0x22);
        let quiet = peer(0x33);
        let pool = [liar, slow, quiet];

        conduct.observe(liar, ConductEvidence::ProvenLie, 0);
        // Far past the ceiling: as much non-performance as an attacker could ever manufacture.
        for _ in 0..(dig_sex::NON_PERFORMANCE_CEILING * 10) {
            conduct.observe(slow, ConductEvidence::NonPerformance, 0);
        }

        let dialable = conduct.dialable(&pool, 0);

        assert!(
            !dialable.contains(&liar),
            "a peer with a verifiable fault must not be dialled"
        );
        assert!(
            dialable.contains(&slow),
            "unverifiable distress must NEVER remove a peer from the dial set, however sustained —              otherwise loading an honest holder is enough to evict it"
        );
        assert!(
            dialable.contains(&quiet),
            "an unobserved peer must remain dialable"
        );
    }

    /// **Proves (#268):** a self-contradiction is treated as verifiable, like a lie and unlike a
    /// timeout — the peer contradicted its OWN claim, which needs no trust to check.
    #[test]
    fn a_self_contradiction_is_durable_like_a_lie_not_transient_like_a_timeout() {
        let conduct = ConductState::new();
        let contradictor = peer(0x44);
        conduct.observe(contradictor, ConductEvidence::SelfContradiction, 0);

        assert_eq!(
            conduct.dial_share(contradictor, dig_sex::NON_PERFORMANCE_DECAY_TICKS * 100),
            0.0,
            "a peer that announced content then denied holding it earned a durable exclusion"
        );
    }
}
