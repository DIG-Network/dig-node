//! The chain port — the seam this whole engine is built against instead of `dig-rewards-coin`.
//!
//! `dig-rewards-coin` is SPEC-only as of the tag this lane read: `src/lib.rs` is a documented
//! placeholder and `pub mod distributor {}` is empty. Implementing the driver is
//! DIG-Network/dig_ecosystem#3249, a sibling lane. So the prover engine is built COMPLETELY against
//! a narrow trait derived from the SPEC's own described surface (not from the driver's internals,
//! so it is stable across #3249 landing), tested with an in-memory fake, and the production
//! adapter — until #3249 ships — reports [`ChainPortError::Unavailable`] and runs no cycles. See
//! [`unavailable`] for that adapter.

use super::admission::AdmittedPeer;
use async_trait::async_trait;

/// A 32-byte chain identifier (launcher id, store id, root, puzzle hash — all the same shape).
pub type Bytes32 = [u8; 32];

/// One distributor this node funds, as SPEC §1.3 names it: the generation it rewards plus its
/// launcher id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorRef {
    pub launcher_id: Bytes32,
    pub store_id: Bytes32,
    pub root: Bytes32,
}

/// One occupied entry slot, as SPEC §10.2 shapes it: keyed by a payout PUZZLE HASH, never a pubkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySlot {
    pub payout_puzzle_hash: Bytes32,
    pub counter: u64,
    /// SPEC §11.1: always `1` in the MVP; carried here because the chain state reports what is
    /// actually on the slot, not what this crate would choose to write.
    pub shares: u64,
}

/// One distributor's chain-derived state (SPEC §2.3 `counters`, §8, §12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributorChainState {
    pub reserve_base_units: u64,
    pub entries: Vec<EntrySlot>,
    /// The `RewardDistributorConstants::epoch_seconds` accrual window ordinal this distributor is
    /// currently in. NOT the mirror-collateral epoch (SPEC §0.3) — an unrelated clock.
    pub current_distributor_epoch: u64,
    /// SPEC §12.4: derived from the singleton's own spend history, never a self-report. `None`
    /// means the entry set has never been written to.
    pub last_entry_write_at: Option<u64>,
    pub total_paid_out_base_units: u64,
}

/// One add/remove decision destined for a bundle (SPEC §6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAction {
    /// Carries [`AdmittedPeer`] rather than loose fields: `AdmittedPeer` is mintable only by
    /// `admission::admit`, so an `Add` cannot be constructed from a discovery path that skipped
    /// admission — self-exclusion becomes a compile-time property of this type, not a convention
    /// every future discovery path must remember to honour (SPEC §5.3; DIG-Network/dig-node#261).
    Add(AdmittedPeer),
    Remove {
        payout_puzzle_hash: Bytes32,
        launcher_id: Bytes32,
    },
}

/// One distributor spend bundle: at most [`super::spec_constants::MAX_ENTRY_WRITES_PER_BUNDLE`]
/// actions, one fee (SPEC §6.3 clause 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryWriteBundle {
    pub launcher_id: Bytes32,
    pub actions: Vec<EntryAction>,
    pub fee_mojos: u64,
}

/// Why a chain port call could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainPortError {
    /// No chain source is wired yet — the [`unavailable`] adapter's only answer, and what any real
    /// adapter should answer for an unreachable chain too (SPEC §12.2 clause 4).
    Unavailable,
    /// A chain answered but the call failed for a reason worth a message (bounded before logging —
    /// SPEC §3.7 clause 4 applies to every attacker-adjacent string, and a chain error is not
    /// exempt).
    Other(String),
}

/// Reads and the one write this engine needs from the reward-distributor chain state. Derived from
/// the SPEC's described surface (§1.3 reads, §6.3 write), not from `dig-rewards-coin`'s internals.
#[async_trait]
pub trait RewardsChainPort: Send + Sync {
    /// SPEC §1.3: every distributor this node funds, with its `(store_id, root)`.
    async fn funded_distributors(&self) -> Result<Vec<DistributorRef>, ChainPortError>;

    /// SPEC §2.3, §8, §12.4: one distributor's current chain-derived state.
    async fn distributor_state(
        &self,
        launcher_id: Bytes32,
    ) -> Result<DistributorChainState, ChainPortError>;

    /// SPEC §6.3: submit ONE bundle of at most `MAX_ENTRY_WRITES_PER_BUNDLE` actions with a fee.
    async fn submit_entry_writes(&self, bundle: EntryWriteBundle) -> Result<(), ChainPortError>;

    /// SPEC §2.1: spend the distributor singleton's `NewEpoch` action when a synced state is
    /// needed for an entry-set write (§8.2) and the epoch has rolled. Idempotent in effect — SPEC
    /// §2.1 clause 3 names TWO willing spenders (this prover and #3251's claim loop) as correct,
    /// not a conflict, and neither MUST treat a not-yet-rolled epoch as an error or assume the
    /// other already did it.
    async fn spend_new_epoch(&self, launcher_id: Bytes32) -> Result<(), ChainPortError>;
}

/// The production adapter until DIG-Network/dig_ecosystem#3249 lands: reports
/// [`ChainPortError::Unavailable`] on every call and runs no cycles.
///
/// This is the named state `ChainSourceUnavailable` (SPEC §2.3), not a silent no-op — a no-op that
/// reported progress would be the exact honesty violation §2.4 forbids. When #3249 ships, this
/// adapter is replaced with one that calls the real driver through this same trait; nothing above
/// this seam changes.
pub struct UnavailableChainPort;

#[async_trait]
impl RewardsChainPort for UnavailableChainPort {
    async fn funded_distributors(&self) -> Result<Vec<DistributorRef>, ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn distributor_state(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<DistributorChainState, ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn submit_entry_writes(&self, _bundle: EntryWriteBundle) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }

    async fn spend_new_epoch(&self, _launcher_id: Bytes32) -> Result<(), ChainPortError> {
        Err(ChainPortError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_adapter_never_reports_a_cycle_ran() {
        let port = UnavailableChainPort;
        assert_eq!(
            port.funded_distributors().await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.distributor_state([0u8; 32]).await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.submit_entry_writes(EntryWriteBundle {
                launcher_id: [0u8; 32],
                actions: vec![],
                fee_mojos: 0,
            })
            .await,
            Err(ChainPortError::Unavailable)
        );
        assert_eq!(
            port.spend_new_epoch([0u8; 32]).await,
            Err(ChainPortError::Unavailable)
        );
    }
}
