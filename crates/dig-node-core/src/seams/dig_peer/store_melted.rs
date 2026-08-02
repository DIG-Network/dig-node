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
//! deletes NOTHING (see [`confirm_melt`]).
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
//!   singleton the chain-watch loop observes as closed. Delete every held generation, broadcast a
//!   signed announcement, tombstone the store.
//! - **Piece #3 — a RECEIVING peer** ([`process_inbound`]): an inbound opcode-221 frame. Verify held,
//!   verify melted on-chain, delete, and rebroadcast ONCE (convergent epidemic).
//!
//! Both funnel through [`decide_melt`] (the pure decision) and the shared [`TombstoneSet`] (the
//! set-once state that guarantees each node broadcasts at most once per store, so the epidemic
//! quiesces).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use digstore_core::Bytes32;

/// Whether a store's singleton is closed (melted), still live, or currently unknowable.
///
/// Derived ONLY from a positive chain read (see [`confirm_melt`]) — never from an announcement's
/// contents or signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeltStatus {
    /// The singleton lineage resolved to a closed store (`Ok(None)`) — the store IS melted.
    Melted,
    /// The singleton is still live (`Ok(Some(tip))`) — NEVER delete.
    Live,
    /// The chain was unreachable/errored (`Err`) — NEVER delete (fail-closed).
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
/// and `already_tombstoned` are the cheap gates that must be true/false BEFORE the chain is consulted
/// — this function assumes the caller has already established them (see [`process_inbound`]).
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
        self.inner.lock().expect("tombstone lock").contains(store_id)
    }

    /// Compare-and-set: insert `store_id`, returning `true` iff it was NEWLY inserted.
    ///
    /// The single-broadcast guarantee rides on this: only the transition that returns `true` may
    /// propagate the melt, so a re-receipt (which returns `false`) never re-emits.
    pub fn insert(&self, store_id: [u8; 32]) -> bool {
        self.inner.lock().expect("tombstone lock").insert(store_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROPERTY: only a held, not-yet-tombstoned, on-chain-CONFIRMED melt authorizes a delete;
    /// every other combination is ignored. This is the fail-closed core.
    #[test]
    fn only_a_held_confirmed_melt_deletes() {
        assert_eq!(
            decide_melt(true, false, MeltStatus::Melted),
            MeltDecision::DeleteAndPropagate
        );
        // Live or Unknown NEVER delete, whatever else is true.
        assert_eq!(
            decide_melt(true, false, MeltStatus::Live),
            MeltDecision::Ignore
        );
        assert_eq!(
            decide_melt(true, false, MeltStatus::Unknown),
            MeltDecision::Ignore
        );
        // Not held, or already tombstoned, never deletes even for a confirmed melt.
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
        let store = [7u8; 32];
        assert!(!tomb.contains(&store));
        assert!(tomb.insert(store), "first insert is the transition");
        assert!(tomb.contains(&store));
        assert!(!tomb.insert(store), "re-insert never re-admits");
    }

    // The 8 adversarial tests land here as the actuator is built.
    fn _unused(_: Bytes32) {}
}
