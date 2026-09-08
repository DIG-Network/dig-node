//! The rewards prover engine (DIG-Network/dig_ecosystem#3250): the node-side half of
//! `dig-rewards-coin`'s reward-distributor loop.
//!
//! It runs an always-on per-distributor cycle ([`cycle`]), gates every discovered mirror
//! candidate through the SPEC §4 mirror-coin proof ([`gate`], [`admission`]), issues and grades
//! §3 possession challenges ([`challenge`]), decides and rate-limits §6.3 entry-set writes
//! ([`writes`]), and derives the §12.4 staleness bound from chain-observed state only
//! ([`staleness`]).
//!
//! The chain seam ([`port`]'s `RewardsChainPort`) is UNIMPLEMENTED pending
//! DIG-Network/dig_ecosystem#3249 — `dig-rewards-coin` is SPEC-only today (its `distributor`
//! module is an empty placeholder). The production adapter wired into this crate is
//! `port::UnavailableChainPort`, which runs no cycles and reports
//! `port::ChainPortError::Unavailable` rather than a silent no-op. Every value this engine
//! compares against the SPEC's numeric bounds lives in [`spec_constants`], tagged with its
//! clause, so #3249 landing its own constants is a single, deliberate migration rather than a
//! scattered one.

pub mod admission;
pub mod challenge;
pub mod cycle;
pub mod gate;
pub mod port;
pub mod spec_constants;
pub mod staleness;
pub mod state;
pub mod writes;
