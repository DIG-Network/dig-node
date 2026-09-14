//! The funder-side `RewardsChainPort` adapter (dig_ecosystem#3310).
//!
//! `dig_node_core::rewards::port::RewardsChainPort` exists and its single-install site
//! (`Node::install_reward_chain_port`) exists, but nothing constructs a real implementation: the
//! only adapter shipped so far is `UnavailableChainPort`, which answers `ChainPortError::Unavailable`
//! forever. This module is what makes `dig.getRewardDistributor` and
//! `dig.listRewardDistributorCommitments` answer for real.
//!
//! Two files, one job each:
//! - [`chain_source`] — the guarded chain read: `read_distributor_guarded`, which refuses a
//!   distributor whose launch constants carry `epoch_seconds == 0` BEFORE calling
//!   `dig_rewards_coin::state::read_distributor`, and the store_id/root recovery from the
//!   launcher's creating spend (the launch comment is a CLVM memo, not a field
//!   `dig-rewards-coin` reads for you).
//! - [`chain_port`] — [`chain_port::RealRewardsChainPort`], the `RewardsChainPort` implementation
//!   that serves `distributor_report` over the guarded reader and answers `Unavailable` for the
//!   four methods this ticket does not build (`funded_distributors`, `distributor_state`,
//!   `submit_entry_writes`, `spend_new_epoch` — SPEC surfaces owned by other tickets, #3249/#3250).
//!
//! Lives in `dig-node-service`, never `dig-node-core`: `dig-wallet` holds the only production
//! `ChainSource` and itself depends on `dig-node-core`, so consuming it from core would be
//! circular (see `dig_node_core::rewards::port`'s module doc).

pub mod chain_port;
pub mod chain_source;

pub use chain_port::RealRewardsChainPort;
