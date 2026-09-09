//! The data shapes the claim loop moves — deliberately named apart from #3250's `port.rs`
//! (`DistributorRef` / `EntrySlot`) because this side carries discovery provenance the funder side
//! has no concept of.

use chia_protocol::Bytes32;

/// A distributor this node has located on-chain and confirmed is ours (SPEC §1.3, §9.3): its launch
/// comment parsed and its reserve asset is `dig_constants::DIG_ASSET_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveredDistributor {
    pub launcher_id: Bytes32,
    pub store_id: Bytes32,
    pub root: Bytes32,
}

/// This node's own entry slot on one distributor (SPEC §10.2): keyed by a payout PUZZLE HASH, never
/// a pubkey, re-read fresh before every claim (SPEC §12.5 clause 3) and never cached across cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnEntry {
    pub payout_puzzle_hash: Bytes32,
    /// The slot's replay guard; `InitiatePayout` writes `counter + 1` (SPEC §10.2 clause 3).
    pub counter: u64,
    /// What this entry has accrued and not yet claimed, in $DIG base units.
    pub accrued_base_units: u64,
}

/// What one distributor's evaluation this cycle produced — never silently nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// `InitiatePayout` was submitted for this launcher id.
    Submitted { launcher_id: Bytes32 },
    /// SPEC §8.6 final sentence: skipped, not failed — no spend, no fee.
    SkippedBelowThreshold {
        launcher_id: Bytes32,
        accrued: u64,
        threshold: u64,
    },
    /// The fee ceiling (`crate::mirror::signer::MIRROR_SPEND_FEE_CEILING_MOJOS`-derived, see
    /// [`super::config`]) would be exceeded — skipped, not failed.
    SkippedFeeAboveCeiling {
        launcher_id: Bytes32,
        fee_mojos: u64,
        ceiling_mojos: u64,
    },
    /// SPEC §12.5 clause 1: no entry slot for our puzzle hash — terminal, non-error. Eviction
    /// already settled everything owed (SPEC §6.4).
    NoEntrySlot { launcher_id: Bytes32 },
    /// SPEC §9.3: the distributor's reserve asset is not `DIG_ASSET_ID` — not ours, dropped.
    NotOurs { launcher_id: Bytes32 },
}

/// The closed set of states this loop can be in. Never a health boolean (SPEC §2.4) — each name
/// maps to a different fact an operator can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimLoopState {
    /// No cycle has completed yet.
    #[default]
    Idle,
    /// The chain seam reported [`super::port::ClaimPortError::Unavailable`] — see the module doc's
    /// "chain seam" section. Zero cycles ran; this is the true state, not a silent no-op.
    ChainSourceUnavailable,
    /// The silent-failure case this ticket exists to prevent: at least one distributor was
    /// claimable, nothing was submitted, and no fault was reported. Computed, never asserted by a
    /// writer about itself — see [`ClaimStatus::compute_state`].
    ClaimableButNotClaiming,
    /// A cycle completed, nothing above is true.
    Nominal,
}

/// The anti-silence status surface (requirement 4): what an operator or a monitor reads to know
/// whether this loop is actually doing anything, never a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimStatus {
    pub distributors_known: u32,
    pub distributors_with_own_entry: u32,
    /// Computed independently of whether a submission actually happened this cycle — an
    /// entry that accrued at least `payout_threshold` with a fee at or under the ceiling. Comparing
    /// this against `claims_submitted` is what makes [`ClaimLoopState::ClaimableButNotClaiming`]
    /// catch a broken submit path even when discovery and evaluation both still look correct.
    pub distributors_claimable: u32,
    pub last_discovery_at: Option<u64>,
    pub last_cycle_at: Option<u64>,
    pub claims_submitted: u64,
    pub claims_skipped_below_threshold: u64,
    pub claims_skipped_fee_ceiling: u64,
    pub terminal_no_entry_slot: u32,
    /// Set when a chain call this cycle returned `ClaimPortError::Other(_)` — a real fault, distinct
    /// from `ChainSourceUnavailable` (no chain at all) and from ordinary skip outcomes.
    pub fault_reported: bool,
    pub state: ClaimLoopState,
}

impl Default for ClaimStatus {
    fn default() -> Self {
        ClaimStatus {
            distributors_known: 0,
            distributors_with_own_entry: 0,
            distributors_claimable: 0,
            last_discovery_at: None,
            last_cycle_at: None,
            claims_submitted: 0,
            claims_skipped_below_threshold: 0,
            claims_skipped_fee_ceiling: 0,
            terminal_no_entry_slot: 0,
            fault_reported: false,
            state: ClaimLoopState::Idle,
        }
    }
}

impl ClaimStatus {
    /// Derives [`ClaimLoopState`] from the status fields alone — a pure computation, so a test can
    /// assert `ClaimableButNotClaiming` directly against hand-built fields without driving a whole
    /// engine cycle, and so a stalled writer can never manufacture a healthier state than its own
    /// numbers support (SPEC §2.4's reasoning, applied to this loop's own surface).
    #[must_use]
    pub fn compute_state(&self) -> ClaimLoopState {
        if self.state == ClaimLoopState::ChainSourceUnavailable {
            return ClaimLoopState::ChainSourceUnavailable;
        }
        if self.last_cycle_at.is_none() {
            return ClaimLoopState::Idle;
        }
        if !self.fault_reported && self.distributors_claimable > 0 && self.claims_submitted == 0 {
            return ClaimLoopState::ClaimableButNotClaiming;
        }
        ClaimLoopState::Nominal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimable_but_not_claiming_is_computed_from_fields_alone() {
        let status = ClaimStatus {
            distributors_claimable: 3,
            claims_submitted: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::ClaimableButNotClaiming);
    }

    #[test]
    fn a_reported_fault_does_not_masquerade_as_claimable_but_not_claiming() {
        let status = ClaimStatus {
            distributors_claimable: 3,
            claims_submitted: 0,
            fault_reported: true,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::Nominal);
    }

    #[test]
    fn nothing_claimable_and_nothing_submitted_is_nominal() {
        let status = ClaimStatus {
            distributors_claimable: 0,
            claims_submitted: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::Nominal);
    }

    #[test]
    fn chain_source_unavailable_wins_over_every_other_reading() {
        let status = ClaimStatus {
            distributors_claimable: 5,
            claims_submitted: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            state: ClaimLoopState::ChainSourceUnavailable,
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::ChainSourceUnavailable);
    }
}
