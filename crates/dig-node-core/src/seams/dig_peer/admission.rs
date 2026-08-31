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

/// One admitted unit of inbound work. Releases its slot on `Drop`, on every exit path.
///
/// Held by value across the work it admits; the borrow checker then makes "return before releasing"
/// impossible rather than merely discouraged.
#[derive(Debug)]
pub struct AdmissionGuard<'a> {
    admission: &'a PeerAdmission,
    peer: AuthenticatedPeer,
    kind: WorkKind,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        // A poisoned meter is recovered rather than propagated: refusing to RELEASE on the panic path
        // would leak the very allowance this guard exists to return, permanently.
        let mut meter = self
            .admission
            .meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        meter.release(self.peer, self.kind);
    }
}

/// The node's inbound admission meter, shared across every peer session.
///
/// One meter for the whole node, because the ceiling it enforces is node-wide: a per-connection meter
/// would let a peer buy more allowance by opening more connections, which is the same collapse as a
/// caller-chosen key wearing a different shape.
#[derive(Debug)]
pub struct PeerAdmission {
    meter: Mutex<AdmissionMeter>,
}

impl Default for PeerAdmission {
    fn default() -> Self {
        Self::new(AdmissionLimits::default())
    }
}

impl PeerAdmission {
    /// A meter with no work in flight, admitting under `limits`.
    #[must_use]
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            meter: Mutex::new(AdmissionMeter::new(limits)),
        }
    }

    /// Admit one unit of inbound work for the session identified by `conn_key`, BEFORE performing it.
    ///
    /// `requested_units` is the attacker-chosen quantity the request asks for, clamped here at the
    /// boundary rather than deeper in where the cost would already be committed.
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
        let mut meter = self
            .meter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        meter
            .admit(peer, kind, requested_units)
            .map_err(AdmissionRefusal::Limited)?;
        drop(meter);
        Ok(AdmissionGuard {
            admission: self,
            peer,
            kind,
        })
    }

    /// Units of work currently in flight node-wide. For tests and the operator status surface.
    #[must_use]
    pub fn in_flight_total(&self) -> u32 {
        self.meter
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

    /// **Proves (#269):** relayed work draws on its own ceiling, so work done on other nodes' behalf
    /// cannot consume the whole node-wide allowance (SPEC 6.1.8).
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
}
