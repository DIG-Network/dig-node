//! **The cold-start walk's chain-read budget** (dig-node#404).
//!
//! A node with an empty state directory computes every epoch since genesis before it can answer
//! `control.collateral.requirement`. Measured on mainnet from dig-node#401's branch: 103 epochs,
//! roughly eleven minutes. This file measures WHERE those reads go, because the remedy differs
//! entirely depending on the answer.
//!
//! # What is being counted, and why it is `block_timestamp`
//!
//! Each epoch costs two things: locating its census height, and censusing the population there.
//! Locating the height is [`dig_mirror_coin::census_height`], which bisects `[0, peak]` on block
//! timestamps. Nothing in the shipped stack memoises those reads -- `ChiaQueryProvider`'s
//! `block_timestamp` is a live round trip through the router, which asks `api.coinset.org` first --
//! so every probe of every epoch's search is paid again.
//!
//! The consequence is that the height search is not merely linear in the number of epochs: its
//! per-epoch cost is `O(log peak)`, and `peak` grows with the chain. A cold start therefore costs
//! `O(epochs x log peak)` with BOTH factors growing over time, which is the unbounded growth
//! dig-node#404 is about.
//!
//! # Why the assertions are read COUNTS and not wall-clock
//!
//! Eleven minutes is a property of one operator's link to one oracle. The read count is a property
//! of the algorithm, is identical on every machine, and is what actually grows. A fixture of three
//! epochs cannot demonstrate a fix for a hundred, but a fixture that runs the SAME epochs against
//! two different chain heights can demonstrate the growth itself -- which is the defect.

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use std::cell::RefCell;

/// Seconds per block, near enough to Chia's 18.75s target for the search to behave as it does on
/// mainnet. The exact value does not matter: the search bisects on the ORDER of timestamps.
const SECS_PER_BLOCK: u64 = 19;

/// The instant block zero carries. Arbitrary, and fixed so the fixture is deterministic.
const GENESIS_UNIX: u64 = 1_600_000_000;

/// Mainnet's peak at the time dig-node#404 was measured.
const MAINNET_PEAK: u32 = 9_196_171;

/// A chain that answers timestamps and counts how many times it was asked.
///
/// EVERY block is a transaction block here. Real chains have runs of non-transaction blocks that
/// [`dig_mirror_coin::census_height`] walks DOWN through, costing further reads per probe -- so
/// this fixture UNDERSTATES the shipped cost, and every bound asserted below is conservative.
struct CountingChain {
    peak: u32,
    reads: RefCell<u64>,
}

impl CountingChain {
    fn at_peak(peak: u32) -> Self {
        Self {
            peak,
            reads: RefCell::new(0),
        }
    }

    fn reads(&self) -> u64 {
        *self.reads.borrow()
    }

    /// The instant `height` is stamped with. Strictly increasing, which is the only property the
    /// bisection depends on.
    fn stamp(height: u32) -> u64 {
        GENESIS_UNIX + u64::from(height) * SECS_PER_BLOCK
    }
}

impl ChainSource for CountingChain {
    type Error = ChainSourceError;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(None)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Unsupported("coin_records_by_parent"))
    }

    fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Ok(None)
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(ChainSourceError::Unsupported("resolve_singleton_lineage"))
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(self.peak))
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        *self.reads.borrow_mut() += 1;
        if height > self.peak {
            return Ok(None);
        }
        Ok(Some(Self::stamp(height)))
    }
}

/// Blocks in one epoch, at this fixture's block time.
fn blocks_per_epoch() -> u64 {
    (7 * 24 * 60 * 60) / SECS_PER_BLOCK
}

/// Locate `epochs` successive epoch heights the way the shipped walk does, and report the reads.
///
/// The instants are spaced one epoch apart in the SAME units the chain is stamped in, and are
/// placed so that every one of them has already happened at `peak` -- a search for an epoch the
/// chain has not reached returns `None` without bisecting, and would measure nothing.
fn reads_to_locate(epochs: u32, peak: u32) -> u64 {
    let chain = CountingChain::at_peak(peak);
    let per_epoch = blocks_per_epoch();
    // Start far enough below the peak that `epochs` of them fit underneath it.
    let first = u64::from(peak) - per_epoch * u64::from(epochs) - 1;

    for n in 0..u64::from(epochs) {
        let height = u32::try_from(first + n * per_epoch).expect("height fits");
        let instant = CountingChain::stamp(height);
        let found = dig_mirror_coin::census_height(&chain, instant)
            .expect("the fixture answers every read")
            .expect("the epoch has started on chain");
        assert_eq!(
            found.height, height,
            "the search must land on the first block at or after the instant"
        );
    }
    chain.reads()
}

/// **The defect, stated as a measurement**: the per-epoch cost of locating a census height depends
/// on how tall the chain is, so a cold start gets more expensive as the chain ages even for the
/// same number of epochs.
///
/// This is the half of dig-node#404 that makes the growth super-linear. The other half -- one epoch
/// per week, forever -- is inherent to a model whose record for epoch *n* is derived from epoch
/// *n-1* (`EpochRecord::advance` steps the multiplier from its predecessor's), and is not what this
/// test is about.
#[test]
fn locating_a_census_height_costs_more_on_a_taller_chain() {
    const EPOCHS: u32 = 20;

    let at_mainnet = reads_to_locate(EPOCHS, MAINNET_PEAK);
    let at_four_times = reads_to_locate(EPOCHS, MAINNET_PEAK * 4);
    let at_sixteen_times = reads_to_locate(EPOCHS, MAINNET_PEAK * 16);

    println!(
        "reads for {EPOCHS} epochs: peak {MAINNET_PEAK} -> {at_mainnet}, \
         x4 -> {at_four_times}, x16 -> {at_sixteen_times}"
    );

    assert!(
        at_four_times > at_mainnet && at_sixteen_times > at_four_times,
        "the search cost must be shown to grow with chain height for this test to be measuring \
         the defect at all: {at_mainnet} / {at_four_times} / {at_sixteen_times}"
    );
}

/// **The bound the fix must establish.** Locating one epoch's census height MUST cost a number of
/// chain reads that does not depend on how tall the chain is.
///
/// The walk already knows a strict lower bound for the next epoch's height -- the census height of
/// the epoch it just recorded, which every record persists -- and it knows the instant it is
/// looking for. A search seeded with those cannot be forced to re-bisect the whole chain.
///
/// The budget is stated per epoch rather than in total so that it says the same thing about 103
/// epochs as it does about the twenty this fixture runs. It is deliberately generous: the point is
/// the ABSENCE of a dependence on `peak`, not a contest over constants.
#[test]
fn the_cost_of_locating_an_epoch_height_is_independent_of_chain_height() {
    const EPOCHS: u32 = 20;
    // Chain reads one epoch's height search may cost. A bisection of the whole chain needs about
    // log2(peak) of them -- 24 at mainnet's height and 28 at sixteen times it -- so a budget of
    // twelve cannot be met by any search that starts at height zero.
    const BUDGET_PER_EPOCH: u64 = 12;

    for multiple in [1u32, 4, 16] {
        let peak = MAINNET_PEAK * multiple;
        let reads = reads_to_locate(EPOCHS, peak);
        let budget = u64::from(EPOCHS) * BUDGET_PER_EPOCH;
        assert!(
            reads <= budget,
            "locating {EPOCHS} epoch heights at peak {peak} cost {reads} chain reads, over the \
             budget of {budget} -- the search is still paying for the chain's height"
        );
    }
}
