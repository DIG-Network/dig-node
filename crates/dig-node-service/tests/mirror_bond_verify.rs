//! Verifying a peer's claimed mirror coin against a chain (dig-node#466).
//!
//! Every coin here is created by a **genuine CAT spend** whose puzzle is executed to produce its
//! conditions — the same execution `MirrorCoin::from_creating_spend` performs. A hand-written
//! `CoinRecord` cannot exhibit the property under test, because the property is precisely that the
//! asset id, the amount and the owner are re-derived from executed on-chain code rather than read
//! from memos.
//!
//! The sharpest fixture in this file is not a malformed coin. It is a **real, fully collateralised,
//! honestly published mirror coin that bonds a different generation** — every property checks out
//! except the one that matters. That is the coin a hostile or merely stale publisher can point at,
//! and the only thing that catches it is `advertises`.

mod support;

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_node_core::mirror_bond::BondVerdict;
use dig_node_service::mirror::bond_verify::verdict_for;
use num_bigint::BigInt;
use std::collections::HashMap;

use support::{creating_spend, epoch, mirror_memos, root_1, root_2, store_a, wallet, COLLATERAL};

/// A chain holding exactly the coins it was built with, and their creating spends.
struct Chain {
    records: HashMap<Bytes32, CoinRecord>,
    spends: HashMap<Bytes32, CoinSpend>,
}

impl Chain {
    fn holding(coins: &[(CoinSpend, chia_protocol::Coin)]) -> Self {
        let mut records = HashMap::new();
        let mut spends = HashMap::new();
        for (spend, coin) in coins {
            records.insert(
                coin.coin_id(),
                CoinRecord {
                    coin: *coin,
                    confirmed_height: Some(100),
                    spent_height: None,
                    timestamp: Some(1_700_000_000),
                    coinbase: false,
                },
            );
            spends.insert(spend.coin.coin_id(), spend.clone());
        }
        Chain { records, spends }
    }

    /// The same chain, with `coin_id` already spent — collateral that has been reclaimed.
    fn with_spent(mut self, coin_id: Bytes32) -> Self {
        if let Some(record) = self.records.get_mut(&coin_id) {
            record.spent_height = Some(200);
        }
        self
    }
}

impl ChainSource for Chain {
    type Error = String;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(self.records.get(&coin_id).cloned())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self.records.values().cloned().collect())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Ok(self.spends.get(&coin_id).cloned())
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Ok(None)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(Some(1_000))
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(Some(1_700_000_000))
    }
}

/// A chain that cannot answer anything — a partitioned node, not an empty world.
struct Unreachable;

impl ChainSource for Unreachable {
    type Error = String;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn resolve_singleton_lineage(
        &self,
        _launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Err("no chain source reachable".into())
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Err("no chain source reachable".into())
    }
}

/// The world these tests share: one wallet bonding `root_1`, a DIFFERENT wallet bonding `root_2` of
/// the same store, and a chain holding both.
///
/// Two wallets rather than one because the fixture derives a coin's parent from `(owner, asset,
/// amount)`: two same-amount coins from one wallet would be the SAME coin, and the second
/// advertisement would silently overwrite the first's creating spend.
fn two_honest_bonds() -> (Chain, Bytes32, Bytes32) {
    let owner_1 = wallet(1);
    let owner_2 = wallet(2);
    let (spend_1, coin_1) = creating_spend(
        &owner_1,
        &mirror_memos(&owner_1, store_a(), root_1(), &["https://one.example"]),
    );
    let (spend_2, coin_2) = creating_spend(
        &owner_2,
        &mirror_memos(&owner_2, store_a(), root_2(), &["https://two.example"]),
    );
    let chain = Chain::holding(&[(spend_1, coin_1), (spend_2, coin_2)]);
    (chain, coin_1.coin_id(), coin_2.coin_id())
}

fn verdict(chain: &impl ChainSource, root: Bytes32, coin: Bytes32, required: Option<u64>) -> BondVerdict {
    verdict_for(chain, store_a(), root, &epoch(), required, coin)
}

/// **Proves:** a coin that bonds a DIFFERENT generation of the same store does not bond this one —
/// the acceptance condition of #466, stated as a peer advertising a bond it does not hold.
///
/// **Catches:** every check that stops short of step 4. A verifier that confirms the puzzle hash,
/// re-derives $DIG, and finds the full collateral present would pass this coin — because all three
/// are genuinely true of it. Only the exact-equality on the declared triple, with the hint
/// recomputed from the coin's own lineage owner, says no.
///
/// **The control is what makes the verdict mean anything.** The same coin, asked about the root it
/// really bonds, MUST verify: without that half, `Unbonded` here is equally explained by a fixture
/// too broken to verify at all, which is a test that asserts nothing.
#[test]
fn a_coin_that_bonds_another_root_does_not_bond_this_one() {
    let (chain, _bonds_root_1, bonds_root_2) = two_honest_bonds();

    assert_eq!(
        verdict(&chain, root_1(), bonds_root_2, Some(COLLATERAL)),
        BondVerdict::Unbonded,
        "a real, fully collateralised coin bonding root_2 does not bond root_1"
    );
    assert_eq!(
        verdict(&chain, root_2(), bonds_root_2, Some(COLLATERAL)),
        BondVerdict::Bonded,
        "control: the very same coin verifies for the generation it actually bonds"
    );
}

/// **Proves:** an honest, fully collateralised bond verifies.
///
/// **Catches:** a verifier that refuses everything, which would satisfy the test above on its own
/// and make the whole layer a denial rather than a check.
#[test]
fn a_valid_bond_verifies() {
    let (chain, bonds_root_1, _) = two_honest_bonds();

    assert_eq!(
        verdict(&chain, root_1(), bonds_root_1, Some(COLLATERAL)),
        BondVerdict::Bonded
    );
}

/// **Proves:** a chain that cannot answer yields `Unverified`, never `Unbonded`.
///
/// **Catches:** collapsing "could not look" into "looked and found nothing" — the failure that makes
/// a partitioned node rank every honest peer last. The reachable half is the control: it proves the
/// coin id used here is one that genuinely verifies, so the `Unverified` above is attributable to
/// the source and to nothing else. Exactly ONE thing varies between the two.
#[test]
fn an_unreachable_chain_is_unverified_not_unbonded() {
    let (chain, bonds_root_1, _) = two_honest_bonds();

    assert_eq!(
        verdict(&Unreachable, root_1(), bonds_root_1, Some(COLLATERAL)),
        BondVerdict::Unverified,
        "a source that could not answer has said nothing about this holder"
    );
    assert_eq!(
        verdict(&chain, root_1(), bonds_root_1, Some(COLLATERAL)),
        BondVerdict::Bonded,
        "control: the same coin, the same question, a reachable chain"
    );
}

/// **Proves:** a chain that answers and holds no such coin is a claim DISPROVEN, not one unexamined.
///
/// **Catches:** treating `Ok(None)` like `Err(_)`. They are the two halves of the `ChainSource`
/// contract and mapping both to `Unverified` would let a publisher name 32 random bytes and be
/// ranked exactly as well as a publisher that named nothing.
#[test]
fn a_coin_the_chain_does_not_have_is_unbonded() {
    let (chain, _, _) = two_honest_bonds();

    assert_eq!(
        verdict(&chain, root_1(), Bytes32::new([0xEE; 32]), Some(COLLATERAL)),
        BondVerdict::Unbonded
    );
}

/// **Proves:** collateral that has been reclaimed bonds nothing, even though every other property of
/// the coin is unchanged.
///
/// **Catches:** verifying the coin's shape while ignoring its state. A spent mirror coin still sits
/// at the mirror puzzle hash, still declares its tuple, and still passes `advertises` — its owner
/// simply has the money back.
#[test]
fn a_spent_bond_is_unbonded() {
    let (chain, bonds_root_1, _) = two_honest_bonds();
    let reclaimed = chain.with_spent(bonds_root_1);

    assert_eq!(
        verdict(&reclaimed, root_1(), bonds_root_1, Some(COLLATERAL)),
        BondVerdict::Unbonded
    );
}

/// **Proves:** the requirement is a bound checked from BOTH sides — one base unit short fails, and
/// exactly at the requirement passes.
///
/// **Catches:** an off-by-one in the comparison, which a one-sided test cannot see: a check written
/// `<=` instead of `<` rejects a bond that meets the requirement exactly, and only the at-bound half
/// notices.
#[test]
fn the_collateral_requirement_is_bounded_from_both_sides() {
    let (chain, bonds_root_1, _) = two_honest_bonds();

    assert_eq!(
        verdict(&chain, root_1(), bonds_root_1, Some(COLLATERAL + 1)),
        BondVerdict::Unbonded,
        "one base unit short of the requirement is not a full bond"
    );
    assert_eq!(
        verdict(&chain, root_1(), bonds_root_1, Some(COLLATERAL)),
        BondVerdict::Bonded,
        "exactly at the requirement IS a full bond"
    );
}

/// **Proves:** a node that has not censused the epoch still catches the lie, and declines to certify
/// the truth.
///
/// **Catches:** checking the collateral magnitude BEFORE the tuple binding. That ordering is
/// invisible on a censused node — every verdict is the same either way — and on an uncensused one it
/// turns the whole layer off: a holder pointing at a coin that plainly bonds another store would come
/// back `Unverified` rather than `Unbonded`, and rank ahead of nothing. The two assertions differ in
/// exactly one thing, which coin is claimed, so only the ORDER of the steps can explain the split.
#[test]
fn an_uncensused_node_still_catches_the_lie_but_will_not_certify_the_truth() {
    let (chain, bonds_root_1, bonds_root_2) = two_honest_bonds();

    assert_eq!(
        verdict(&chain, root_1(), bonds_root_2, None),
        BondVerdict::Unbonded,
        "the binding check runs first, so the lie is caught with no census at all"
    );
    assert_eq!(
        verdict(&chain, root_1(), bonds_root_1, None),
        BondVerdict::Unverified,
        "an honest bond this node cannot price is unproven, never proven"
    );
}

/// **Proves:** a coin at the mirror puzzle hash whose collateral is not $DIG is refused.
///
/// **Catches:** trusting the puzzle hash as an asset check. `mirror_coin_puzzle_hash()` is a CAT
/// outer hash but still only 32 bytes, so a coin of any asset may be paid to it; the asset id has to
/// come from re-deriving the creating spend, which is what `from_creating_spend` does.
#[test]
fn collateral_that_is_not_dig_is_unbonded() {
    let owner = wallet(3);
    let not_dig = Bytes32::new([0x5A; 32]);
    let (spend, coin) = support::creating_spend_of_asset(
        &owner,
        &mirror_memos(&owner, store_a(), root_1(), &["https://impostor.example"]),
        not_dig,
    );
    let chain = Chain::holding(&[(spend, coin)]);

    assert_eq!(
        verdict(&chain, root_1(), coin.coin_id(), Some(COLLATERAL)),
        BondVerdict::Unbonded
    );
}

/// **Proves:** a coin whose DECLARED tuple is this content but whose hint was morphed from a
/// different epoch is refused.
///
/// **Catches:** dropping either half of `advertises`. `mirror_hint` sums four terms including a
/// freely chosen `epoch`, so an author can solve for a hint landing on somebody else's bucket while
/// declaring whatever they like. Checking the declaration alone accepts a coin indexed as something
/// else; checking the hint alone accepts a coin bonding an entirely different store.
#[test]
fn a_declaration_that_disagrees_with_its_own_hint_is_unbonded() {
    let owner = wallet(4);
    let other_epoch = BigInt::from(99);
    let memos = support::declared_memos(
        support::mirror_hint_for(&owner, store_a(), root_1(), &other_epoch),
        store_a(),
        root_1(),
        &epoch(),
        &["https://mismatched.example"],
    );
    let (spend, coin) = creating_spend(&owner, &memos);
    let chain = Chain::holding(&[(spend, coin)]);

    assert_eq!(
        verdict(&chain, root_1(), coin.coin_id(), Some(COLLATERAL)),
        BondVerdict::Unbonded,
        "the declared tuple is right and the hint it sits under is not"
    );
}
