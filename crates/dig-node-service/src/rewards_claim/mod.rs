//! The node's PEER-SIDE reward claim loop (DIG-Network/dig_ecosystem#3251).
//!
//! This is the other half of the reward-distributor lifecycle from
//! `dig_node_core::rewards` (DIG-Network/dig_ecosystem#3250, a sibling lane): that crate proves a
//! FUNDER's distributors are honest and writes entries; this module discovers the distributors that
//! cover the `(store_id, root)`s THIS node mirrors, watches its own entry slot, and submits
//! `InitiatePayout` on a jittered cadence. It lives in `dig-node-service`, not `dig-node-core`,
//! because `dig-mirror-coin` (the on-chain peer<->payout binding this loop reuses, SPEC §10.1) is a
//! dependency of this crate and not of `dig-node-core`.
//!
//! # No rival copy of a shared type
//!
//! `chia_protocol::Bytes32` is the one canonical 32-byte type — never a locally declared
//! `type Bytes32 = [u8; 32]`. This module's own types (`DiscoveredDistributor`, `OwnEntry`, the
//! [`ClaimChainPort`] trait) are named differently from #3250's `port.rs` (`DistributorRef`,
//! `EntrySlot`, `RewardsChainPort`) because they carry different behaviour: #3250 reads the FUNDER's
//! whole entry set and writes entries; this module reads only THIS node's own entry slot and submits
//! payout claims. Same protocol, other side, not a duplicate.
//!
//! # The chain seam
//!
//! `dig-rewards-coin` 0.7.0 ships a real driver (`discovery`, `payout`, `state`), landed by
//! DIG-Network/dig_ecosystem#3249. The production adapter is [`RealClaimChainPort`]
//! (`chain_port.rs`), built over this node's own corroborated chain source; [`UnavailableClaimChainPort`]
//! remains only as the engine's test double now. Two methods still refuse rather than answer:
//! `own_entry`'s accrued amount and `submit_initiate_payout` both need a chain-backed spendable
//! entry slot and a real reserve lineage proof that 0.7.0's read model does not carry — see
//! `chain_port.rs`'s own module doc, blocked on DIG-Network/dig_ecosystem#3356.
//!
//! A silent no-op that reported progress instead would be the exact defect this ticket exists to
//! prevent (SPEC §2.4): a refused method reports a NAMED [`ClaimPortError`] or
//! [`super::types::ClaimOutcome::Faulted`], never a fabricated success.
//!
//! # Wired into node startup (DIG-Network/dig_ecosystem#3268)
//! [`driver::spawn_claim_driver_from_config`] is the one call `dig-node-service::server`'s
//! `serve_with_shutdown` makes: it is gated on `RewardsClaimConfig::enabled` AND
//! `Config::enable_chain_sync` (the same flag `spawn_collateral_census` and
//! `mirror::bond_verify::spawn_bond_verifier_install` already gate on), and when both are true it
//! spawns a detached task that drives [`ClaimEngine::run_cycle`] on a jittered cadence forever,
//! over a [`RealClaimChainPort`] built from `state.wallet_chain`'s corroborated source. If that
//! source cannot be built (offline, no peers), the loop reports the named refusal
//! `ClaimDriverRefusal::ChainSourceUnbuildable` and runs zero cycles rather than installing
//! [`UnavailableClaimChainPort`] silently. [`driver::handle`] is the IN-PROCESS accessor a future
//! RPC can read against the `ClaimStatus` wire semantics — this module puts nothing on the wire
//! itself (see `driver`'s own module doc for why).

mod cadence;
mod chain_port;
mod config;
mod driver;
mod engine;
mod hints;
mod parser;
mod port;
mod types;

pub use cadence::{next_interval_seconds, FixedJitter, JitterSource, CLAIM_JITTER_SECONDS_DEFAULT};
pub use chain_port::{HintedLauncherIndex, LauncherIndex, RealClaimChainPort};
pub use config::{
    RewardsClaimConfig, CLAIM_CADENCE_SECONDS_DEFAULT, CLAIM_CYCLE_FEE_BUDGET_MOJOS_DEFAULT,
    CLAIM_FEE_CEILING_MOJOS_DEFAULT,
};
pub use driver::{handle, spawn_claim_driver_from_config, ClaimDriverRefusal, ClaimLoopHandle};
pub use engine::ClaimEngine;
pub use hints::{DistributorHint, DistributorHintSource, NoHintSource};
pub use parser::parse_launch_comment;
pub use port::{ClaimChainPort, ClaimPortError, UnavailableClaimChainPort};
pub use types::{ClaimLoopState, ClaimOutcome, ClaimStatus, DiscoveredDistributor, OwnEntry};

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles_and_loads() {
        // Skeleton checkpoint (kernel invariant 3): a compiling module with one passing test,
        // pushed before any design work. Superseded by the real engine tests as they land.
    }
}
