//! The claim-side chain port — the seam this engine is built against instead of
//! `dig-rewards-coin` (see the module doc's "chain seam" section for why).
//!
//! Deliberately a DIFFERENT trait from #3250's `RewardsChainPort`: that one reads a funder's whole
//! entry set and writes entries; this one reads only THIS node's own entry slot and submits its own
//! payout.

use async_trait::async_trait;
use chia_protocol::Bytes32;

use super::types::{DiscoveredDistributor, OwnEntry};

/// Why a claim-chain call could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimPortError {
    /// No chain source is wired yet — [`UnavailableClaimChainPort`]'s only answer, and what any
    /// real adapter should answer for an unreachable chain too.
    Unavailable,
    /// A chain answered but the call failed for a reason worth a message (bounded before logging).
    Other(String),
}

/// The narrow surface the claim engine needs from the reward-distributor chain state, derived from
/// SPEC's described surface (§1.3 discovery, §8.3/§9.3 evaluation, §10.2/§12.5 the peer's own entry,
/// §10.2 clause 3 the claim write) — not from `dig-rewards-coin`'s internals.
#[async_trait]
pub trait ClaimChainPort: Send + Sync {
    /// SPEC §13.1: every CHIP-0051 distributor on chain whose launch comment parses per §1.3 —
    /// before the §9.3 reserve-asset filter, which the engine applies via [`Self::reserve_asset_id`].
    async fn discover_distributors(&self) -> Result<Vec<DiscoveredDistributor>, ClaimPortError>;

    /// Re-derive one launcher id's launch comment from chain (SPEC §13.2 clause 1: a gossip hint is
    /// untrusted, so it is verified through this same on-chain path, never trusted directly).
    /// `Ok(None)` means the comment does not parse — "not a DIG rewards distributor", not an error
    /// (SPEC §1.3).
    async fn resolve_launch_comment(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<DiscoveredDistributor>, ClaimPortError>;

    /// SPEC §9.1/§9.3: the distributor's on-chain `reserve_asset_id`.
    async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError>;

    /// SPEC §8.3: the distributor's own chain-curried `payout_threshold` — never hardcoded here.
    async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError>;

    /// SPEC §10.2/§12.5: this node's own entry slot, re-read fresh on EVERY call, EVERY cycle — the
    /// engine MUST NOT cache the result across cycles and MUST NOT treat one `Ok(None)` as
    /// permanent (Defect B): SPEC §12.5 clause 2 describes a legitimate re-entry path (evicted,
    /// re-challenged, re-admitted), and this call cannot tell "never admitted yet" apart from
    /// "evicted" from the absence alone — nor does it need to, since SPEC §6.4 clause 1 means
    /// nothing is owed either way. `Ok(None)` means only "no claim this cycle", never "no claim
    /// ever again".
    async fn own_entry(
        &self,
        launcher_id: Bytes32,
        payout_puzzle_hash: Bytes32,
    ) -> Result<Option<OwnEntry>, ClaimPortError>;

    /// The network fee, in mojos, an `InitiatePayout` for this launcher id would need.
    async fn required_fee_mojos(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError>;

    /// SPEC §10.2: submit ONE `InitiatePayout` for `payout_puzzle_hash` at `fee_mojos`.
    async fn submit_initiate_payout(
        &self,
        launcher_id: Bytes32,
        payout_puzzle_hash: Bytes32,
        fee_mojos: u64,
    ) -> Result<(), ClaimPortError>;
}

/// The production adapter until DIG-Network/dig_ecosystem#3249 lands: reports
/// [`ClaimPortError::Unavailable`] on every call and runs zero cycles — the named state
/// `ChainSourceUnavailable` (see the module doc), never a silent no-op.
pub struct UnavailableClaimChainPort;

#[async_trait]
impl ClaimChainPort for UnavailableClaimChainPort {
    async fn discover_distributors(&self) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn resolve_launch_comment(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn reserve_asset_id(&self, _launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn payout_threshold(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn own_entry(
        &self,
        _launcher_id: Bytes32,
        _payout_puzzle_hash: Bytes32,
    ) -> Result<Option<OwnEntry>, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn required_fee_mojos(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }

    async fn submit_initiate_payout(
        &self,
        _launcher_id: Bytes32,
        _payout_puzzle_hash: Bytes32,
        _fee_mojos: u64,
    ) -> Result<(), ClaimPortError> {
        Err(ClaimPortError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_adapter_never_reports_a_cycle_ran() {
        let port = UnavailableClaimChainPort;
        assert_eq!(
            port.discover_distributors().await,
            Err(ClaimPortError::Unavailable)
        );
        assert_eq!(
            port.own_entry(Bytes32::from([0u8; 32]), Bytes32::from([0u8; 32]))
                .await,
            Err(ClaimPortError::Unavailable)
        );
        assert_eq!(
            port.submit_initiate_payout(Bytes32::from([0u8; 32]), Bytes32::from([0u8; 32]), 0)
                .await,
            Err(ClaimPortError::Unavailable)
        );
    }
}
