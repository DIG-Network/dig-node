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
//! `dig-rewards-coin` is v0.1.3, published on crates.io, and still SPEC-only (`src/` is
//! `error.rs` + `lib.rs`); its driver is
//! DIG-Network/dig_ecosystem#3249, still open. So the whole engine here is built against the narrow
//! [`ClaimChainPort`] trait derived from the SPEC's described surface, tested with a full in-memory
//! fake, and the production adapter — until #3249 ships — is [`UnavailableClaimChainPort`], which
//! reports the named state `ChainSourceUnavailable` and runs zero cycles. This mirrors #3250's own
//! `UnavailableChainPort` exactly. When #3249 lands, one adapter is written against
//! `ClaimChainPort` and nothing above this seam changes.
//!
//! A silent no-op that reported progress instead would be the exact defect this ticket exists to
//! prevent (SPEC §2.4): with the unavailable adapter wired, zero claims IS the true state, so the
//! status surface must say so by name, not by omission.
//!
//! # Not yet wired into node startup (Defect D — stated, not fixed here)
//! Nothing in this codebase constructs a [`ClaimEngine`] outside this module's own tests: there is
//! no scheduler that drives [`ClaimEngine::run_cycle`] on a cadence, and no RPC method exposes
//! [`ClaimStatus`] to an operator, even though [`RewardsClaimConfig::enabled`] defaults to `true`.
//! Wiring this into node startup — picking a concrete [`ClaimChainPort`] adapter, starting the
//! cadence loop, and exposing `ClaimStatus` over RPC — is a separate unit of work with its own
//! review surface, deferred out of this PR on purpose: the only production adapter available today
//! is [`UnavailableClaimChainPort`], and the real one arrives with
//! DIG-Network/dig_ecosystem#3249. Until that wiring lands, this module compiles, is fully tested
//! against the fake chain port, and does nothing in a running node.

mod cadence;
mod config;
mod engine;
mod hints;
mod parser;
mod port;
mod types;

pub use cadence::{next_interval_seconds, FixedJitter, JitterSource, CLAIM_JITTER_SECONDS_DEFAULT};
pub use config::{
    RewardsClaimConfig, CLAIM_CADENCE_SECONDS_DEFAULT, CLAIM_CYCLE_FEE_BUDGET_MOJOS_DEFAULT,
    CLAIM_FEE_CEILING_MOJOS_DEFAULT,
};
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
