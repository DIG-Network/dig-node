//! THE single admission point (SPEC §5.3). Every discovery path — the DHT walk, this node's
//! locally-held provider set, the discovered cache, and any manual/operator add — MUST route a
//! candidate through [`admit`] before it becomes an entry decision. There MUST NOT be a second
//! admission function anywhere in this module tree.
//!
//! DIG-Network/dig-node#261 is the analogous defect: an absolute SPEC self-exclusion honoured by
//! the DHT leg and bypassed by the forwarded leg. The lesson is the rule: an invariant enforced on
//! some paths is not an invariant, it is a habit. So this file is deliberately the ONLY place that
//! compares a candidate against this node's own identity, and every caller — regardless of which
//! path produced the candidate — MUST call through here rather than re-implement the comparison.

use super::gate::{GateOutcome, MirrorCoinGatePort};

/// Which discovery path produced a candidate. Exists ONLY for logging/tests (SPEC §5.3 clause 4's
/// control needs to name the path a candidate arrived by) — it MUST NOT change the admission
/// decision, since that would be exactly the per-path habit §5.3 forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryPath {
    DhtWalk,
    LocalProviderSet,
    DiscoveredCache,
    ManualAdd,
}

/// A raw candidate as a discovery path hands it in, before the mirror-coin gate has run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub peer_id: [u8; 32],
    pub path: DiscoveryPath,
}

/// This node's own identity, on both SPEC §5.2 coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnIdentity {
    pub peer_id: [u8; 32],
    /// Every puzzle hash this node's own wallet controls. A `Vec` (not a single hash) because a
    /// wallet may hold more than one payout address; SPEC §5.2 excludes on membership, not equality
    /// to one distinguished value.
    pub controlled_puzzle_hashes: Vec<[u8; 32]>,
}

impl OwnIdentity {
    fn controls(&self, puzzle_hash: &[u8; 32]) -> bool {
        self.controlled_puzzle_hashes.iter().any(|h| h == puzzle_hash)
    }
}

/// What [`admit`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Eligible on the chain gate AND not self — carries the payout puzzle hash the entry would use.
    Admit { payout_puzzle_hash: [u8; 32] },
    /// Refused because the candidate is this node itself, on the peer_id coordinate, the puzzle_hash
    /// coordinate, or both (SPEC §5.2). Refused at admission, never a display filter (§5.3.3) — the
    /// caller MUST NOT write an entry for this candidate under any circumstance.
    SelfExcluded,
    /// The mirror-coin gate did not admit the candidate (SPEC §4, §10.3) — fail-closed
    /// ineligibility, not an accusation.
    GateIneligible,
}

/// THE single admission point. Every discovery path calls this and nothing else decides
/// self-exclusion.
///
/// Order matters and is deliberate: self-exclusion is checked FIRST, on the `peer_id` coordinate,
/// before any chain read — refusing this node's own peer id costs nothing and needs no gate result.
/// The `payout_puzzle_hash` coordinate can only be checked once the gate has produced one (SPEC §4.3
/// `owner_puzzle_hash()`), so that half of self-exclusion runs after the gate call but BEFORE the
/// gate's eligibility is trusted — an eligible-but-self-owned candidate is still refused, never
/// admitted then filtered.
pub async fn admit(
    candidate: &Candidate,
    own: &OwnIdentity,
    gate: &dyn MirrorCoinGatePort,
    mirror_collateral_epoch_ordinal: Option<u64>,
) -> AdmissionDecision {
    if candidate.peer_id == own.peer_id {
        return AdmissionDecision::SelfExcluded;
    }

    match gate
        .evaluate(candidate.peer_id, mirror_collateral_epoch_ordinal)
        .await
    {
        GateOutcome::Eligible {
            payout_puzzle_hash,
        } => {
            if own.controls(&payout_puzzle_hash) {
                AdmissionDecision::SelfExcluded
            } else {
                AdmissionDecision::Admit {
                    payout_puzzle_hash,
                }
            }
        }
        GateOutcome::Ineligible(_) => AdmissionDecision::GateIneligible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::gate::{GateIneligibleReason, MirrorCoinGatePort};
    use async_trait::async_trait;

    struct FakeGate {
        /// peer_id -> (eligible?, payout_puzzle_hash)
        eligible: std::collections::HashMap<[u8; 32], [u8; 32]>,
    }

    #[async_trait]
    impl MirrorCoinGatePort for FakeGate {
        async fn evaluate(&self, peer_id: [u8; 32], _epoch: Option<u64>) -> GateOutcome {
            match self.eligible.get(&peer_id) {
                Some(ph) => GateOutcome::Eligible {
                    payout_puzzle_hash: *ph,
                },
                None => GateOutcome::Ineligible(GateIneligibleReason::AbsentDeclaration),
            }
        }
    }

    fn own() -> OwnIdentity {
        OwnIdentity {
            peer_id: [0xAA; 32],
            controlled_puzzle_hashes: vec![[0xBB; 32]],
        }
    }

    /// SPEC §5.2 coordinate 1: own peer_id, foreign payout hash -> refused, on EVERY path.
    #[tokio::test]
    async fn own_peer_id_is_refused_on_every_discovery_path() {
        let gate = FakeGate {
            eligible: [([0xAA; 32], [0xCC; 32])].into_iter().collect(),
        };
        let own = own();
        for path in [
            DiscoveryPath::DhtWalk,
            DiscoveryPath::LocalProviderSet,
            DiscoveryPath::DiscoveredCache,
            DiscoveryPath::ManualAdd,
        ] {
            let candidate = Candidate {
                peer_id: own.peer_id,
                path,
            };
            let decision = admit(&candidate, &own, &gate, Some(1)).await;
            assert_eq!(decision, AdmissionDecision::SelfExcluded, "path {path:?}");
        }
    }

    /// SPEC §5.2 coordinate 2: foreign peer_id, but the gate resolves a payout hash this node's
    /// wallet controls -> refused.
    #[tokio::test]
    async fn own_controlled_payout_hash_is_refused_even_with_a_foreign_peer_id() {
        let own = own();
        let foreign_peer = [0x11; 32];
        let gate = FakeGate {
            eligible: [(foreign_peer, own.controlled_puzzle_hashes[0])]
                .into_iter()
                .collect(),
        };
        let candidate = Candidate {
            peer_id: foreign_peer,
            path: DiscoveryPath::DhtWalk,
        };
        let decision = admit(&candidate, &own, &gate, Some(1)).await;
        assert_eq!(decision, AdmissionDecision::SelfExcluded);
    }

    /// The §5.3.4 control: an otherwise-identical NON-self candidate on the same paths IS admitted.
    /// This distinguishes "excluded self" from "dropped everything".
    #[tokio::test]
    async fn control_a_non_self_candidate_is_admitted_on_every_path() {
        let own = own();
        let honest_peer = [0x22; 32];
        let honest_payout = [0xDD; 32];
        let gate = FakeGate {
            eligible: [(honest_peer, honest_payout)].into_iter().collect(),
        };
        for path in [
            DiscoveryPath::DhtWalk,
            DiscoveryPath::LocalProviderSet,
            DiscoveryPath::DiscoveredCache,
            DiscoveryPath::ManualAdd,
        ] {
            let candidate = Candidate {
                peer_id: honest_peer,
                path,
            };
            let decision = admit(&candidate, &own, &gate, Some(1)).await;
            assert_eq!(
                decision,
                AdmissionDecision::Admit {
                    payout_puzzle_hash: honest_payout
                },
                "path {path:?}"
            );
        }
    }

    #[tokio::test]
    async fn gate_ineligible_candidate_is_refused_but_not_marked_self() {
        let own = own();
        let gate = FakeGate {
            eligible: std::collections::HashMap::new(),
        };
        let candidate = Candidate {
            peer_id: [0x33; 32],
            path: DiscoveryPath::DhtWalk,
        };
        let decision = admit(&candidate, &own, &gate, Some(1)).await;
        assert_eq!(decision, AdmissionDecision::GateIneligible);
    }
}
