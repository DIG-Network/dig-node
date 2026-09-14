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
//! DIG-Network/dig_ecosystem#3310. What is missing is an ADAPTER, not a reader:
//! `dig-rewards-coin` 0.4.1 already ships `state::read_distributor(&impl ChainSource,
//! launcher_id) -> Result<Option<DistributorSnapshot>, RewardsError>` plus `ChainObservation` and
//! `clawback::recoverable_base_units`, but that reader does no socket I/O of its own — it takes a
//! caller-supplied `ChainSource` — so something must hold the chain source, drive the reader and
//! map its answers onto this trait. That adapter is built in `dig-node-service` and injected down
//! through [`crate::Node::install_reward_chain_port`] (#3310); the claim-side chain adapter is
//! tracked separately in #3307. Until then the production adapter wired into this crate is
//! `port::UnavailableChainPort`, which runs no cycles and reports
//! `port::ChainPortError::Unavailable` rather than a silent no-op. Every value this engine
//! compares against the SPEC's numeric bounds lives in [`spec_constants`], tagged with its
//! clause, so should the crate ever publish these prover-side numbers itself — 0.4.1's
//! `constants` module carries distributor-side values only, not these — the migration is a
//! single, deliberate one rather than a scattered one.
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
//! **Eviction**: if every bundle is all removals, the ceiling is **192 `Remove` actions/day** (24
//! bundles × 8 actions each) — the same 192-action/day cap stated above, not a fraction of it.
//! **96/day is a different number: the evict-plus-re-add churn ceiling**, since each churn (evict
//! one entry, admit a replacement) costs one `Remove` and one `Add`, so 192 actions/day buy at
//! most 96 churns/day. SPEC §6.4: `RemoveEntry` settles the entry's full accrued balance, ignoring
//! `payout_threshold` — so sustained churn can flush an entire 250-entry set's accrued balance,
//! including sub-threshold dust that could never otherwise have been claimed, in **~2.6 days**
//! (250 entries / 96 churns-per-day).

pub mod admission;
pub mod challenge;
pub mod cycle;
pub mod funded;
pub mod gate;
pub mod port;
pub mod spec_constants;
pub mod staleness;
pub mod state;
pub mod writes;
