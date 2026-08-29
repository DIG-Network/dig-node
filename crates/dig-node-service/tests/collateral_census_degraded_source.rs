//! **A degraded chain view must not seal a low collateral requirement** (dig-node#405).
//!
//! The census reads its candidate population from one chain view. That view can be briefly thin —
//! a source that has pruned, one answering from a partial index, or a router falling through to a
//! weaker tier — and a thin view can only OMIT coins. It therefore describes a network smaller
//! than the chain holds, and the requirement derived from it comes out LOW: the direction that
//! leaves stores under-collateralised.
//!
//! Two properties used to make that permanent, each individually right. `EpochRecordStore::put`
//! never let a later record supersede one this node censused, which is what stops a lying peer
//! overwriting a node's own answer. And `catch_up` never re-censused an epoch it had already
//! recorded, which is what kept the walk cheap. Together they meant one badly-timed ten-minute
//! window sealed the figure for a seven-day epoch.
//!
//! # This probe degrades the SOURCE, not the record
//!
//! The lever the defect uses is control of what the source shows, so that is the lever pulled
//! here: the same chain is presented twice, once hiding a coin and once not, and the walk is run
//! against each. Asserting on records written by hand would prove only that `put` compares
//! integers the way its own unit tests already say it does.
//!
//! # Every coin comes from a genuine CAT spend
//!
//! The census authenticates a candidate by fetching its creating spend and EXECUTING the puzzle to
//! recover the advertisement. A hand-built `CoinRecord` never reaches that path, so a probe using
//! one would assert a property against a fixture that cannot exhibit it. The fixtures are built
//! with `dig-mirror-coin`'s own published test support, verbatim.
//!
//! # The control that keeps the assertion honest
//!
//! The degraded view hides ONE of two coins and keeps the other. A fixture hiding both would read
//! as the harsher case and is precisely the one that cannot tell a repair from a walk that simply
//! recorded nothing, because there would be no surviving figure to move.

mod support;

use std::collections::HashMap;

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_mirror_collateral::{EpochRecord, CENSUS_FINALITY_DEPTH_BLOCKS};
use dig_node_service::collateral::{EpochRecordStore, StoredEpoch, StoredRecord};
use dig_node_service::collateral_census::catch_up;
use num_bigint::BigInt;
use support::{
    creating_spend_of_amount, declared_memos, mirror_hint_for, root_1, root_2, store_a, store_b,
    wallet, Wallet,
};

/// The epoch the coins are published for, and the epoch the seeded record describes.
///
/// Epoch 1 is the record every node writes at bring-up from nothing, so seeding it needs no chain
/// read and the walk's target is the very next epoch.
const PUBLISHED_EPOCH: u64 = 1;
/// The epoch the census produces — the successor of [`PUBLISHED_EPOCH`], and the walk's target.
const TARGET_EPOCH: u64 = PUBLISHED_EPOCH + 1;

/// The height the census settles on, chosen by [`Chain::block_timestamp`] below.
const CENSUS_AT: u32 = 1_000;

/// A chain view that can be asked to HIDE part of its own population.
///
/// The hiding is at the puzzle-hash query, which is where a thin source actually loses coins: the
/// creating spends stay available, so a hidden coin is invisible rather than unauthenticatable.
/// Those are different failures with different outcomes — an unauthenticatable candidate already
/// aborts the census, while an invisible one silently lowers the count, and it is the silent one
/// this probe is about.
struct Chain {
    coins: Vec<CoinRecord>,
    creating_spends: HashMap<Bytes32, CoinSpend>,
    /// Coins omitted from every puzzle-hash answer, as a thin source omits them.
    hidden: Vec<Bytes32>,
    /// The Unix second [`TARGET_EPOCH`] begins at, as the walk computes it.
    epoch_start: u64,
}

impl Chain {
    fn new(epoch_start: u64) -> Self {
        Self {
            coins: Vec::new(),
            creating_spends: HashMap::new(),
            hidden: Vec::new(),
            epoch_start,
        }
    }

    /// Publish one honest, fully qualifying mirror coin, and return its id so a later view can hide
    /// it.
    fn publish(&mut self, owner: &Wallet, store: Bytes32, root: Bytes32, amount: u64) -> Bytes32 {
        let epoch = BigInt::from(PUBLISHED_EPOCH);
        let memos = declared_memos(
            mirror_hint_for(owner, store, root, &epoch),
            store,
            root,
            &epoch,
            &["https://mirror.example"],
        );
        let (spend, coin) = creating_spend_of_amount(owner, &memos, amount);
        self.coins.push(CoinRecord {
            coin,
            confirmed_height: Some(CENSUS_AT - 10),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        });
        self.creating_spends.insert(spend.coin.coin_id(), spend);
        coin.coin_id()
    }

    /// The same chain as seen through a source that cannot show `hidden`.
    fn hiding(&self, hidden: &[Bytes32]) -> Self {
        Self {
            coins: self.coins.clone(),
            creating_spends: self.creating_spends.clone(),
            hidden: hidden.to_vec(),
            epoch_start: self.epoch_start,
        }
    }
}

impl ChainSource for Chain {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(self
            .coins
            .iter()
            .find(|record| record.coin.coin_id() == coin_id)
            .cloned())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self
            .coins
            .iter()
            .filter(|record| record.coin.puzzle_hash == puzzle_hash)
            .filter(|record| !self.hidden.contains(&record.coin.coin_id()))
            .cloned()
            .collect())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Unsupported("coin_records_by_parent"))
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Ok(self.creating_spends.get(&coin_id).cloned())
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(ChainSourceError::Unsupported("resolve_singleton_lineage"))
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(CENSUS_AT + CENSUS_FINALITY_DEPTH_BLOCKS as u32 + 10))
    }

    /// Every height below [`CENSUS_AT`] sits one second BEFORE the epoch's start instant, and every
    /// height at or above it sits on the instant itself.
    ///
    /// So the first transaction block at or after the epoch's start is exactly [`CENSUS_AT`], and
    /// the census height is settled by the schedule rather than pinned by the fixture — which is
    /// the property production relies on to make every node census the same block.
    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(Some(if height < CENSUS_AT {
            self.epoch_start.saturating_sub(1)
        } else {
            self.epoch_start
        }))
    }
}

/// A store in a fresh temp dir holding only the epoch-1 record the bring-up writes.
fn seeded_store(name: &str) -> (EpochRecordStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "dig-node-405-{name}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let store = EpochRecordStore::at(dir.join("collateral-epochs.jsonl"));
    store
        .put(&StoredRecord::bootstrap())
        .expect("seed the genesis record");
    (store, dir)
}

/// What the store now says the network owes per store.
fn requirement(store: &EpochRecordStore, epoch: u64) -> (u64, u64) {
    match store.get(epoch) {
        StoredEpoch::Found(held) => (
            held.record.census.stores,
            held.record.required_per_store_dig_base_units,
        ),
        other => panic!("epoch {epoch} must be recorded, got {other:?}"),
    }
}

/// The whole defect, and its repair, as one sequence against one chain.
///
/// 1. A thin view shows one of the two mirror coins on chain. The walk records a census of ONE.
/// 2. The view recovers. The walk re-censuses the SAME block, finds both, and the low record is
///    replaced.
/// 3. The view goes thin again. The higher record stands — because a source can omit a coin for
///    free, and the downward direction must never be admitted.
#[test]
fn a_thin_chain_view_cannot_seal_a_low_requirement_and_a_healthy_one_repairs_it() {
    let epoch_start =
        (dig_constants::mirror_epoch_start_unix_ms(TARGET_EPOCH as i64) / 1_000).max(0) as u64;
    let per_store = EpochRecord::bootstrap().required_per_store_dig_base_units;

    let mut chain = Chain::new(epoch_start);
    let alice = wallet(1);
    let bob = wallet(2);
    let visible = chain.publish(&alice, store_a(), root_1(), per_store);
    let missed = chain.publish(&bob, store_b(), root_2(), per_store);
    assert_ne!(visible, missed, "the two coins must be distinct");

    let (store, dir) = seeded_store("seal");

    // 1 — the thin view. One coin is hidden; the other is the honest control that keeps this from
    // being a census of nothing, which any broken walk also produces.
    let thin = chain.hiding(&[missed]);
    let first = catch_up(&thin, &store, TARGET_EPOCH);
    assert_eq!(first.stopped, None, "the thin view still answers a census");
    assert_eq!(first.recorded.len(), 1, "the target epoch must be recorded");
    assert_eq!(
        first.recorded[0].stores, 1,
        "the thin view must under-count, or this probe is not exercising the defect"
    );
    let (low_stores, low_requirement) = requirement(&store, TARGET_EPOCH);
    assert_eq!(low_stores, 1);

    // 2 — the view recovers, at the SAME census height. The under-count must not survive it.
    let healthy = chain.hiding(&[]);
    let second = catch_up(&healthy, &store, TARGET_EPOCH);
    assert_eq!(second.stopped, None, "the healthy view stopped: {second:?}");
    assert!(
        second.recorded.is_empty(),
        "the epoch was already recorded, so nothing is a NEW record"
    );
    let repaired = second
        .superseded
        .expect("the healthy census must have replaced the under-count");
    assert_eq!(repaired.epoch, TARGET_EPOCH);
    assert_eq!(repaired.stores, 2, "both coins must now be counted");

    let (stores, high_requirement) = requirement(&store, TARGET_EPOCH);
    assert_eq!(stores, 2, "the store must serve the repaired count");
    assert_ne!(
        high_requirement, low_requirement,
        "the repair must move the figure the operator posts, not only the count"
    );

    // 3 — the view goes thin again. This is the direction an attacker gets for free, and the one
    // the repair must never admit.
    let thin_again = chain.hiding(&[missed]);
    let third = catch_up(&thin_again, &store, TARGET_EPOCH);
    assert_eq!(
        third.superseded, None,
        "a thinner view must not be reported as a repair"
    );
    let (still, still_requirement) = requirement(&store, TARGET_EPOCH);
    assert_eq!(still, 2, "a thin view talked the count back down");
    assert_eq!(
        still_requirement, high_requirement,
        "a thin view talked the requirement back down"
    );

    let _ = std::fs::remove_dir_all(dir);
}
