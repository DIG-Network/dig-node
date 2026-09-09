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
//!
//! # The worst-case spend, stated where a human reads it
//!
//! [`spec_constants::MAX_ENTRY_WRITES_PER_BUNDLE`] = 8 actions per bundle, at most one bundle per
//! [`spec_constants::ENTRY_WRITE_MIN_INTERVAL_SECONDS`] = 3,600 s → **24 bundles/day, 192 entry
//! actions/day**, per distributor this node funds.
//!
//! **Fee ceiling**: 24 × the operator's configured standard fee, per day, per distributor —
//! nominally ~0.00012 XCH/day at a typical ~0.000005 XCH fee, but **~0.24 XCH/day (≈88 XCH/year)**
//! at a congested 0.01 XCH fee. This bound is NOT independent of the rate bound above: 24
//! bundles/day is simultaneously the rate limit and the fee ceiling, so [`writes::FeeBudget`] does
//! not add a second, separate protection on top of the rate bound — stated plainly here so nobody
//! reads this engine as having two independent spend controls when it has one.
//!
//! **Eviction**: up to 96 `Remove` actions/day (half of 192, if every bundle is all removals). SPEC
//! §6.4: `RemoveEntry` settles the entry's full accrued balance, ignoring `payout_threshold` — so
//! sustained eviction can flush an entire 250-entry set's accrued balance, including sub-threshold
//! dust that could never otherwise have been claimed, in **~1.3 days** (250 entries / 192
//! actions-per-day capacity for removals alone).

pub mod admission;
pub mod challenge;
pub mod cycle;
pub mod gate;
pub mod port;
pub mod spec_constants;
pub mod staleness;
pub mod state;
pub mod writes;
