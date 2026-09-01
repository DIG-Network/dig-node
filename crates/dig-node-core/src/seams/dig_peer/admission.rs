//! Inbound admission for the mTLS peer surface (dig-sex SPEC §8.5, dig-node#269).
//!
//! `dig_sex::admission` decides whether inbound work is admitted; this module is the node's half —
//! it derives the authenticated identity to meter against, holds the meter, and makes the paired
//! release structural.
//!
//! # Admit BEFORE the work, not after
//!
//! The value of an admission meter is that it refuses before spending anything. A check placed after
//! the read/decode/fetch has already paid the cost it exists to avoid, so [`PeerAdmission::admit`] is
//! called at the top of each responder method, ahead of every dispatch.
//!
//! # Metered by the AUTHENTICATED identity, never by anything the caller chooses
//!
//! The meter key is the mTLS-verified `peer_id` the session derived — never a wire field, never a
//! connection counter, never a constant. A key a caller can choose freely turns a per-peer limit into
//! a limit on whichever bucket the caller picks, and a CONSTANT key collapses every requestor into one
//! shared bucket, so a single peer exhausts the allowance for everybody. That failure looks exactly
//! like working DoS protection until the moment it matters, which is why
//! [`dig_sex::AuthenticatedPeer`] is a newtype and why this module refuses rather than substituting a
//! placeholder when no verified identity exists.
//!
//! # An unauthenticated peer-surface request is REFUSED, not admitted unmetered
//!
//! In production every session reaching the responder carries a verified `peer_id` (the peer surface is
//! mTLS-only), so an absent one means the session carried no authenticated caller at all. Admitting it
//! unmetered would make "present no identity" the cheapest way to escape the meter — the guard would
//! be optional at the attacker's discretion. It is therefore refused as [`Refusal::MeterFull`]'s
//! sibling case, [`AdmissionRefusal::Unauthenticated`]. Nothing on the loopback admin / in-process FFI
//! path routes through here (that is `crate::handle_rpc`), so refusing costs no legitimate caller.
//!
//! # Release is structural, not remembered
//!
//! [`AdmissionGuard`] releases on `Drop`. A `release` skipped on an error path leaks allowance until
//! the node refuses everything, and an error path is precisely the one a hand-written release is
//! forgotten on — so the guard makes the omission unrepresentable rather than reviewable.

use std::sync::Mutex;

use dig_sex::{AdmissionLimits, AdmissionMeter, AuthenticatedPeer, Refusal, WorkKind};

use super::dht::hex64;

/// Why inbound work was refused at the boundary.
///
/// Wraps the crate's [`Refusal`] so the node can name the one case the crate cannot: a request with no
/// authenticated identity to meter against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// The session carried no mTLS-verified `peer_id`, so there is no identity to meter against.
    Unauthenticated,
    /// The crate's meter refused; the variant says which limit was reached.
    Limited(Refusal),
}

impl AdmissionRefusal {
    /// A short, stable reason string for the JSON-RPC error body and the serve log.
    ///
    /// Deliberately names the LIMIT rather than the peer's standing: shed load must be
    /// distinguishable from an outage by an operator reading a log, and from a ban by the peer
    /// reading the response.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            AdmissionRefusal::Unauthenticated => "unauthenticated",
            AdmissionRefusal::Limited(Refusal::GlobalCeiling) => "node at capacity",
            AdmissionRefusal::Limited(Refusal::PeerShare) => "peer at capacity",
            AdmissionRefusal::Limited(Refusal::RelayBudget) => "relay budget exhausted",
            AdmissionRefusal::Limited(Refusal::MeterFull) => "meter full",
            AdmissionRefusal::Limited(Refusal::RequestTooLarge) => "request too large",
        }
    }
}

/// The authenticated identity to meter against, derived from the session's verified `peer_id`.
///
/// `conn_key` is the mTLS-verified peer id as lowercase 64-hex, empty on a caller-less session. Only a
/// well-formed 64-hex value yields an identity: anything else is not a verified peer id, and coercing
/// it into one would meter distinct callers into whatever bucket the malformed value happened to hash
/// to.
#[must_use]
pub fn authenticated_peer(conn_key: &str) -> Option<AuthenticatedPeer> {
    hex64(conn_key).map(AuthenticatedPeer::from_verified_session)
}

/// How many peers are each guaranteed ONE concurrent slot, regardless of node-wide load.
///
/// Equal to [`crate::peer::MAX_INFLIGHT_PEER_CONNECTIONS`], and derived from it rather than restated,
/// because the property it buys is a comparison against that number: a peer that holds a connection
/// holds a reserved slot to go with it, so **admission can never be the scarcer resource**.
///
/// # Why a reserve exists at all (gate G1 on dig-node#456)
///
/// [`AdmissionMeter::admit`] tests the node-wide ceiling BEFORE the per-peer share, and the node-wide
/// counter is shared by every peer. With a single pool, the identities needed to deny the whole
/// network is `global_ceiling / per_peer_share` — at the dig-sex defaults, **eight**. A `peer_id` is
/// SHA-256 of a self-signed TLS SPKI, so eight identities cost eight keypairs, each one staying
/// INSIDE its own share so the per-peer limiter never fires. That is 8:1 amplification: eight free
/// identities silence the whole discovery, availability and content-read surface of the node.
///
/// Raising the ceiling only raises that price; it does not change the shape. What changes the shape is
/// spending the FIRST concurrent unit of each peer from a pool whose per-peer share is exactly one.
/// Denying an honest peer then costs one identity AND one held connection per slot — linear, 1:1, and
/// bounded by the connection cap the node already enforces rather than by a number 8x below it.
///
/// The reserve is not extra allowance: the total concurrent share of a peer is unchanged, only the
/// pool its first unit is drawn from. See [`PeerAdmission::with_reserved_first_slots`].
pub const RESERVED_FIRST_SLOTS: u32 = crate::peer::MAX_INFLIGHT_PEER_CONNECTIONS as u32;

/// Which pool the slot of a guard came from, so `Drop` returns it to the meter that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// The first concurrent unit of a peer, from the per-peer-guaranteed reserve.
    Reserved,
    /// Any further concurrent unit, from the shared node-wide pool.
    Burst,
}

/// One admitted unit of inbound work. Releases its slot on `Drop`, on every exit path.
///
/// Held by value across the work it admits; the borrow checker then makes "return before releasing"
/// impossible rather than merely discouraged.
#[derive(Debug)]
pub struct AdmissionGuard<'a> {
    admission: &'a PeerAdmission,
    peer: AuthenticatedPeer,
    kind: WorkKind,
    tier: Tier,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        // Returned to the pool it was TAKEN from. Releasing into the other one would credit allowance
        // that was never spent there and leak the pool that was — the same permanent leak a forgotten
        // release causes, only harder to see.
        let meter = match self.tier {
            Tier::Reserved => &self.admission.reserved,
            Tier::Burst => &self.admission.burst,
        };
        // A poisoned meter is recovered rather than propagated: refusing to RELEASE on the panic path
        // would leak the very allowance this guard exists to return, permanently.
        let mut meter = meter.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        meter.release(self.peer, self.kind);
    }
}

/// The inbound admission meter of the node, shared across every peer session.
///
/// Node-wide rather than per-connection, because a per-connection meter would let a peer buy more
/// allowance by opening more connections — the same collapse as a caller-chosen key wearing a
/// different shape.
///
/// Two pools, not one. See [`RESERVED_FIRST_SLOTS`] for why the first concurrent unit of each peer is
/// metered separately from the rest.
#[derive(Debug)]
pub struct PeerAdmission {
    /// The FIRST concurrent unit of own work of every peer. `per_peer_share` is 1 here, so one
    /// identity takes exactly one slot and the denial cost is linear in identities.
    reserved: Mutex<AdmissionMeter>,
    /// Everything beyond the first concurrent unit of a peer, plus all relayed work. Shared
    /// node-wide, and therefore the pool a busy node sheds from first — which is what shedding load
    /// should mean.
    burst: Mutex<AdmissionMeter>,
}

/// The limits this node admits under.
///
/// The dig-sex defaults are used for every dimension EXCEPT `max_request_units`, which is raised
/// to [`crate::MAX_AVAILABILITY_ITEMS`] — the largest batch this node advertises it answers. The
/// crate default of 256 is half that, and a clamp set below the advertised limit refuses work the
/// contract of the node says it serves: a 257-512 item `dig.getAvailability` batch would have been
/// answered `-32000 "request too large"` while [`crate::Node::availability_batch`] stood ready to
/// answer all 512. The clamp and the limit it clamps to must be the SAME number, so this derives one
/// from the other rather than restating it.
///
/// These are the BURST pool limits. They no longer describe the whole surface a peer can reach:
/// [`RESERVED_FIRST_SLOTS`] peers hold a guaranteed slot outside them.
///
/// # `relay_ceiling` is VACUOUS on this node today (gate S4 on dig-node#456)
///
/// Nothing in this crate constructs [`WorkKind::Relayed`] — every production `admit` call site passes
/// [`WorkKind::Own`] (`crate::peer::NodeResponder`). The separate relay budget of dig-sex SPEC 6.1.8
/// is therefore configured and never consulted: it is satisfied because the case it governs never
/// occurs, not because it is enforced. Stated here rather than left to read as an active rule, since
/// a limit nobody reaches and a limit nobody applies are indistinguishable from the number alone. The
/// ceiling is kept, not removed, so that the first producer of relayed work inherits a budget instead
/// of an omission.
#[must_use]
pub fn node_limits() -> AdmissionLimits {
    AdmissionLimits {
        max_request_units: crate::MAX_AVAILABILITY_ITEMS as u32,
        ..AdmissionLimits::default()
    }
}

impl Default for PeerAdmission {
    fn default() -> Self {
        Self::new(node_limits())
    }
}

impl PeerAdmission {
    /// A meter with no work in flight, admitting under `limits` with the production reserve.
    #[must_use]
    pub fn new(limits: AdmissionLimits) -> Self {
        Self::with_reserved_first_slots(limits, RESERVED_FIRST_SLOTS)
    }

    /// As [`PeerAdmission::new`], with the reserve sized explicitly so a test can exhaust it.
    ///
    /// `limits.per_peer_share` remains the TOTAL concurrent share of a peer: the first of those units
    /// is drawn from the reserve and the remainder from the burst pool, so the reserve grants no peer
    /// any extra concurrency — it only decides which pool the first unit is charged to.
    #[must_use]
    pub fn with_reserved_first_slots(limits: AdmissionLimits, reserved_first_slots: u32) -> Self {
        Self {
            reserved: Mutex::new(AdmissionMeter::new(AdmissionLimits {
                global_ceiling: reserved_first_slots,
                per_peer_share: 1,
                // Relayed work never reaches this pool (see `admit`), so a ceiling here would be
                // vacuous; zero states that rather than implying a budget nothing consults.
                relay_ceiling: 0,
                max_tracked_peers: limits.max_tracked_peers,
                max_request_units: limits.max_request_units,
            })),
            burst: Mutex::new(AdmissionMeter::new(AdmissionLimits {
                per_peer_share: limits.per_peer_share.saturating_sub(1),
                ..limits
            })),
        }
    }

    /// Admit one unit of inbound work for the session identified by `conn_key`, BEFORE performing it.
    ///
    /// `requested_units` is the attacker-chosen quantity the request asks for, clamped here at the
    /// boundary rather than deeper in where the cost would already be committed.
    ///
    /// Own work tries the reserve first and falls back to the burst pool; relayed work goes straight
    /// to the burst pool, where the separate relay ceiling of SPEC 6.1.8 applies unchanged. Work done
    /// on behalf of another node is exactly the work a loaded node should shed, so it is deliberately
    /// not given a guaranteed slot.
    ///
    /// # Errors
    ///
    /// [`AdmissionRefusal::Unauthenticated`] when the session carried no verified peer id, or
    /// [`AdmissionRefusal::Limited`] when a limit is reached. In both cases NO work has been done.
    pub fn admit(
        &self,
        conn_key: &str,
        kind: WorkKind,
        requested_units: u32,
    ) -> Result<AdmissionGuard<'_>, AdmissionRefusal> {
        let peer = authenticated_peer(conn_key).ok_or(AdmissionRefusal::Unauthenticated)?;
        if kind == WorkKind::Own {
            match Self::charge(&self.reserved, peer, kind, requested_units) {
                Ok(()) => return Ok(self.guard(peer, kind, Tier::Reserved)),
                // Both pools clamp on the SAME `max_request_units`, so retrying the burst pool could
                // only reach the identical refusal one lock later. Returning it here keeps the answer
                // to an over-sized request independent of how loaded the node happens to be.
                Err(Refusal::RequestTooLarge) => {
                    return Err(AdmissionRefusal::Limited(Refusal::RequestTooLarge));
                }
                // PeerShare (this peer already holds its reserved slot) or GlobalCeiling (every
                // reserved slot is held): both mean "not from the reserve", never "refuse".
                Err(_) => {}
            }
        }
        Self::charge(&self.burst, peer, kind, requested_units).map_err(AdmissionRefusal::Limited)?;
        Ok(self.guard(peer, kind, Tier::Burst))
    }

    /// Take one unit from `meter`, holding its lock for no longer than the accounting.
    fn charge(
        meter: &Mutex<AdmissionMeter>,
        peer: AuthenticatedPeer,
        kind: WorkKind,
        requested_units: u32,
    ) -> Result<(), Refusal> {
        meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(peer, kind, requested_units)
    }

    fn guard(&self, peer: AuthenticatedPeer, kind: WorkKind, tier: Tier) -> AdmissionGuard<'_> {
        AdmissionGuard {
            admission: self,
            peer,
            kind,
            tier,
        }
    }

    /// Units of work currently in flight node-wide, across both pools.
    ///
    /// Used by the tests of this module. It is deliberately NOT described as an operator surface:
    /// nothing renders it today, and a doc-comment promising a status readout that does not exist is
    /// the kind of claim that gets believed (gate S3 on dig-node#456).
    #[must_use]
    pub fn in_flight_total(&self) -> u32 {
        Self::pool_in_flight(&self.reserved) + Self::pool_in_flight(&self.burst)
    }

    /// Units in flight in the reserve pool — i.e. how many DISTINCT peers currently hold their
    /// guaranteed slot, since the per-peer share of that pool is one.
    #[must_use]
    pub fn reserved_in_flight(&self) -> u32 {
        Self::pool_in_flight(&self.reserved)
    }

    fn pool_in_flight(meter: &Mutex<AdmissionMeter>) -> u32 {
        meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .in_flight_total()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-hex conn_key that is distinct per `n` — the shape a real mTLS session yields.
    fn conn_key(n: u8) -> String {
        hex::encode([n; 32])
    }

    /// Limits with a per-peer share small enough to exhaust in a test, and a global ceiling well
    /// ABOVE it — so exhausting one peer's share can only be the PER-PEER limit, never the node-wide
    /// one. A test whose two ceilings are equal cannot tell those apart and would pass on a meter that
    /// had collapsed every peer into one bucket, which is the exact defect this file exists to prevent.
    fn limits() -> AdmissionLimits {
        AdmissionLimits {
            global_ceiling: 64,
            per_peer_share: 2,
            relay_ceiling: 16,
            max_tracked_peers: 1024,
            max_request_units: 8,
        }
    }

    /// **Proves (#269):** the meter is keyed on the AUTHENTICATED identity, so exhausting one peer's
    /// share refuses that peer and leaves a second peer entirely unaffected.
    ///
    /// The second peer is the load-bearing half. Asserting only that an over-quota peer is refused
    /// passes identically on a meter keyed by a CONSTANT — the shared-bucket mistake — because that
    /// meter also refuses at the limit. It just refuses everybody. Varying one actor while keeping an
    /// honest control is what distinguishes a per-peer limit from a global one wearing its clothes.
    #[test]
    fn exhausting_one_peers_share_does_not_refuse_a_different_peer() {
        let admission = PeerAdmission::new(limits());
        let noisy = conn_key(0xaa);
        let quiet = conn_key(0xbb);

        let _first = admission
            .admit(&noisy, WorkKind::Own, 1)
            .expect("first unit is within the share");
        let _second = admission
            .admit(&noisy, WorkKind::Own, 1)
            .expect("second unit is within the share");

        assert_eq!(
            admission.admit(&noisy, WorkKind::Own, 1).unwrap_err(),
            AdmissionRefusal::Limited(Refusal::PeerShare),
            "a third unit exceeds this peer's share and must be refused"
        );
        assert!(
            admission.admit(&quiet, WorkKind::Own, 1).is_ok(),
            "a DIFFERENT peer must be unaffected — if it is refused, every requestor shares one \
             bucket and a single peer can exhaust the allowance for everybody"
        );
    }

    /// **Proves (#269):** the guard releases on `Drop`, so allowance returns on every exit path.
    ///
    /// A `release` skipped on an error path leaks allowance until the node refuses everything, and the
    /// error path is the one a hand-written release is forgotten on. Dropping the guard here stands in
    /// for every such path, because `Drop` cannot distinguish them.
    #[test]
    fn a_dropped_guard_returns_its_allowance() {
        let admission = PeerAdmission::new(limits());
        let peer = conn_key(0xcc);

        {
            let _a = admission.admit(&peer, WorkKind::Own, 1).expect("first");
            let _b = admission.admit(&peer, WorkKind::Own, 1).expect("second");
            assert_eq!(admission.in_flight_total(), 2);
            assert!(
                admission.admit(&peer, WorkKind::Own, 1).is_err(),
                "the share must be exhausted while the guards are held, or the release below \
                 proves nothing"
            );
        }

        assert_eq!(
            admission.in_flight_total(),
            0,
            "both guards went out of scope; neither slot may still be held"
        );
        assert!(
            admission.admit(&peer, WorkKind::Own, 1).is_ok(),
            "the same peer must be admissible again once its work finished"
        );
    }

    /// **Proves (#269):** a session with no verified peer id is REFUSED, not admitted unmetered.
    ///
    /// Admitting it would make "present no identity" the cheapest way to escape the meter, and the
    /// alternative mistake — substituting a placeholder identity — is the shared bucket again. Both
    /// non-64-hex shapes are covered: absent, and present-but-malformed.
    #[test]
    fn an_unauthenticated_session_is_refused_rather_than_metered_under_a_placeholder() {
        let admission = PeerAdmission::new(limits());
        for bad in ["", "not-hex", &"ab".repeat(31), &"zz".repeat(32)] {
            assert_eq!(
                admission.admit(bad, WorkKind::Own, 1).unwrap_err(),
                AdmissionRefusal::Unauthenticated,
                "{bad:?} is not a verified peer id and must yield no admission"
            );
        }
        assert_eq!(
            admission.in_flight_total(),
            0,
            "a refused request must consume no allowance"
        );
    }

    /// **Proves (#269):** the attacker-chosen request size is clamped AT the boundary.
    ///
    /// `max_request_units` is 8 here, so 9 is over and 8 is at the bound. Pinning both sides matters:
    /// a bound tested only from below can only confirm itself, and a clamp that refused everything
    /// would pass a one-sided test while denying all legitimate work.
    #[test]
    fn an_oversized_request_is_refused_and_the_at_bound_request_is_admitted() {
        let admission = PeerAdmission::new(limits());
        let peer = conn_key(0xdd);

        assert_eq!(
            admission.admit(&peer, WorkKind::Own, 9).unwrap_err(),
            AdmissionRefusal::Limited(Refusal::RequestTooLarge),
            "one unit over max_request_units must be refused"
        );
        assert!(
            admission.admit(&peer, WorkKind::Own, 8).is_ok(),
            "the at-bound request must still be admitted, or the clamp denies legitimate work"
        );
    }

    /// **Proves (#269):** the node's admitted request size is the availability batch's OWN advertised
    /// limit, not the crate's smaller default.
    ///
    /// Asserting a literal 512 here would pass on a hard-coded constant that had drifted from
    /// `MAX_AVAILABILITY_ITEMS`; asserting the derivation is what keeps the two numbers one number.
    #[test]
    fn the_node_admits_a_request_as_large_as_the_availability_batch_it_advertises() {
        assert_eq!(
            node_limits().max_request_units,
            crate::MAX_AVAILABILITY_ITEMS as u32,
            "the admission clamp must equal the advertised batch limit, or the node refuses batches              it says it serves"
        );
        assert!(
            node_limits().max_request_units > AdmissionLimits::default().max_request_units,
            "the crate default is the smaller of the two — if this ever stops holding, the override              is doing nothing and the comment above it is false"
        );
    }

    /// **Proves (#269):** relayed work draws on its own ceiling, so work done on other nodes' behalf
    /// cannot consume the whole node-wide allowance (SPEC 6.1.8).
    ///
    /// **This test is the ONLY producer of [`WorkKind::Relayed`] in the crate** (gate S4 on #456). It
    /// proves the meter would enforce the budget; it does not show the budget being enforced in
    /// production, because no production call site asks for relayed work. See [`node_limits`].
    #[test]
    fn relayed_work_exhausts_the_relay_ceiling_while_own_work_still_admits() {
        let admission = PeerAdmission::new(AdmissionLimits {
            global_ceiling: 64,
            per_peer_share: 8,
            relay_ceiling: 1,
            max_tracked_peers: 1024,
            max_request_units: 8,
        });
        let peer = conn_key(0xee);

        let _relayed = admission
            .admit(&peer, WorkKind::Relayed, 1)
            .expect("the first relayed unit is within the relay ceiling");
        assert_eq!(
            admission.admit(&peer, WorkKind::Relayed, 1).unwrap_err(),
            AdmissionRefusal::Limited(Refusal::RelayBudget),
            "the relay ceiling is 1 and must be reached"
        );
        assert!(
            admission.admit(&peer, WorkKind::Own, 1).is_ok(),
            "OWN work draws on a separate budget — a spent relay allowance must not stop this node \
             serving its own callers"
        );
    }

    /// Hold as many concurrent units as `peer` can take, returning the guards so they stay held.
    ///
    /// Loops until the meter refuses rather than counting to a literal, so it measures the allowance
    /// the node actually grants instead of restating the number the test hoped for.
    fn hold_until_refused<'a>(
        admission: &'a PeerAdmission,
        peer: &str,
    ) -> Vec<AdmissionGuard<'a>> {
        let mut held = Vec::new();
        while let Ok(guard) = admission.admit(peer, WorkKind::Own, 1) {
            held.push(guard);
            assert!(held.len() < 1024, "a peer must not hold unbounded work");
        }
        held
    }

    /// **Proves (gate G1 on #456):** under the SHIPPED limits, eight free identities holding their
    /// full share each cannot refuse an honest peer that holds nothing.
    ///
    /// This is the exploit the security gate executed against the previous single-pool meter, run
    /// here against the configuration the node really ships (`PeerAdmission::default()`), not against
    /// hand-picked limits. Before the reserve it failed: 8 identities x `per_peer_share` = 64 =
    /// `global_ceiling`, every unit inside its own share so the per-peer limiter never fired, and the
    /// ninth peer was answered `-32000 "node at capacity"`.
    ///
    /// The honest ninth peer is the load-bearing half. Asserting only that the sybils were eventually
    /// refused would pass identically on the defective meter, because that meter also refuses at the
    /// limit — it just refuses everybody.
    #[test]
    fn eight_sybil_identities_cannot_deny_an_honest_peer_under_the_shipped_limits() {
        let admission = PeerAdmission::default();
        let sybils: Vec<String> = (0..8u8).map(conn_key).collect();

        let _held: Vec<_> = sybils
            .iter()
            .map(|peer| hold_until_refused(&admission, peer))
            .collect();

        let honest = conn_key(0xf0);
        assert!(
            admission.admit(&honest, WorkKind::Own, 1).is_ok(),
            "a peer holding ZERO work was refused while 8 free identities held theirs — the node-wide \
             pool is deniable at a Sybil cost of eight keypairs"
        );
    }

    /// **Proves (gate G1 on #456):** the same holds when the sybils spend everything they can, not
    /// merely eight of them.
    ///
    /// The single-pool meter needed `global_ceiling / per_peer_share` identities. This walks distinct
    /// identities until an honest newcomer is finally refused and asserts that the count reached is
    /// bounded BELOW by the reserve — i.e. denial is linear in identities held, not amplified by the
    /// per-peer share.
    #[test]
    fn denying_a_newcomer_costs_at_least_one_identity_per_reserved_slot() {
        // A small reserve so the walk terminates quickly. The single-pool meter would have needed
        // global_ceiling / per_peer_share = 4 / 2 = 2 identities; the reserve raises the floor.
        let limits = AdmissionLimits {
            global_ceiling: 4,
            per_peer_share: 2,
            relay_ceiling: 16,
            max_tracked_peers: 1024,
            max_request_units: 8,
        };
        let reserved_first_slots = 3;
        let admission = PeerAdmission::with_reserved_first_slots(limits, reserved_first_slots);

        let mut held = Vec::new();
        let mut identities = 0u32;
        loop {
            let peer = conn_key(u8::try_from(identities).expect("fewer than 256 identities"));
            let guards = hold_until_refused(&admission, &peer);
            if guards.is_empty() {
                break;
            }
            identities += 1;
            held.push(guards);
            assert!(identities < 64, "the meter must refuse a newcomer eventually");
        }

        assert!(
            identities > limits.global_ceiling / limits.per_peer_share,
            "denial took {identities} identities; a single shared pool needs only {} — the reserve is \
             not raising the floor",
            limits.global_ceiling / limits.per_peer_share
        );
        assert!(
            identities >= reserved_first_slots,
            "every reserved slot must be individually occupied before a newcomer can be refused; \
             {identities} identities is fewer than the {reserved_first_slots} reserved slots"
        );
    }

    /// **Proves (gate G1 on #456):** a peer holding work is shed BEFORE a peer holding none.
    ///
    /// This is the property the reserve exists to establish, stated directly and separately from the
    /// Sybil count: once the shared pool is spent, a busy peer is refused while a quiet one is served.
    /// A test that only checked the Sybil count would pass on a meter that had merely raised its
    /// ceiling, which is a price change rather than a shape change.
    #[test]
    fn a_spent_shared_pool_sheds_a_busy_peer_while_a_quiet_one_is_still_served() {
        // A shared ceiling two busy peers can spend entirely, and a reserve with room left over —
        // so the two outcomes below are distinguishable. With one pool they are not: the busy peer
        // and the quiet one receive the identical GlobalCeiling refusal.
        let limits = AdmissionLimits {
            global_ceiling: 8,
            per_peer_share: 5,
            relay_ceiling: 16,
            max_tracked_peers: 1024,
            max_request_units: 8,
        };
        let admission = PeerAdmission::with_reserved_first_slots(limits, 8);
        let busy = conn_key(0x11);
        let also_busy = conn_key(0x12);

        let _held = (
            hold_until_refused(&admission, &busy),
            hold_until_refused(&admission, &also_busy),
        );

        assert!(
            admission.admit(&busy, WorkKind::Own, 1).is_err(),
            "a peer that already holds its share must be refused once the shared pool is spent"
        );
        assert!(
            admission.admit(&conn_key(0xfe), WorkKind::Own, 1).is_ok(),
            "a peer holding NOTHING must still be served from the reserve — shedding must fall on \
             the peers holding work, not on whoever arrives next"
        );
    }

    /// **Proves (gate G2 on #456):** the SHIPPED configuration is pinned, every dimension of it.
    ///
    /// The gate set `global_ceiling: 1` — a node that serves nobody — and the full 1061-test suite
    /// stayed green, because `node_limits()` was asserted for one of its five dimensions and every
    /// other meter test supplied hand-picked limits. A configuration nothing measures is how G1
    /// landed green in the first place, so all five are pinned here and the reserve with them.
    #[test]
    fn the_shipped_admission_configuration_is_pinned() {
        let shipped = node_limits();
        assert_eq!(shipped.global_ceiling, 64, "burst pool node-wide ceiling");
        assert_eq!(shipped.per_peer_share, 8, "total concurrent share per peer");
        assert_eq!(shipped.relay_ceiling, 16, "SPEC 6.1.8 relay budget");
        assert_eq!(shipped.max_tracked_peers, 1024, "meter table size");
        assert_eq!(
            shipped.max_request_units,
            crate::MAX_AVAILABILITY_ITEMS as u32,
            "the admission clamp must equal the advertised batch limit"
        );
    }

    /// **Proves (gate G1/G2 on #456):** the reserve is at least as large as the connection cap, so
    /// admission is never the scarcer of the two resources.
    ///
    /// Asserted as the RELATION rather than as the literal 512: a literal would pass on a reserve that
    /// had drifted away from `MAX_INFLIGHT_PEER_CONNECTIONS`, which is the drift the derivation exists
    /// to prevent. The comparison against the burst ceiling is the one that would have failed before
    /// this change, when the whole surface was 64 slots wide.
    #[test]
    fn the_reserve_is_never_scarcer_than_the_connections_it_serves() {
        assert_eq!(
            RESERVED_FIRST_SLOTS,
            crate::peer::MAX_INFLIGHT_PEER_CONNECTIONS as u32,
            "every peer that can hold a connection must hold a guaranteed slot with it"
        );
        assert!(
            RESERVED_FIRST_SLOTS > node_limits().global_ceiling,
            "a reserve no larger than the shared ceiling reserves nothing: the shared pool would run \
             out first and the node would be deniable at global_ceiling / per_peer_share identities"
        );
    }

    /// **Proves (gate G1 on #456):** the reserve grants no peer EXTRA concurrency.
    ///
    /// The two-pool split must not become a share increase by accident — that would silently double
    /// the work one peer can pin. The total a single peer can hold is still `per_peer_share`, with the
    /// first unit charged to the reserve and the rest to the burst pool.
    #[test]
    fn the_reserve_does_not_widen_the_share_of_any_single_peer() {
        let admission = PeerAdmission::new(limits());
        let peer = conn_key(0x77);

        let held = hold_until_refused(&admission, &peer);
        assert_eq!(
            u32::try_from(held.len()).expect("small"),
            limits().per_peer_share,
            "one peer must still hold exactly per_peer_share units in total across both pools"
        );
        assert_eq!(
            admission.reserved_in_flight(),
            1,
            "exactly one of those units is the reserved slot"
        );
    }
}
