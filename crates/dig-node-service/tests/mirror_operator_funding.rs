//! **A mirror create is funded from the OPERATOR wallet's coins, or not at all** (dig-node#421).
//!
//! The defect this probe exists to prevent is not a crash. `WalletBackend::select_cats` selects over
//! the node-custodied replica's own coin table; the mirror signer signs with the §16.4 operator key.
//! Handing the first set to `dig_mirror_coin::create` produces a real, successful spend of the wrong
//! wallet's money — no error, no red test, and nothing on any surface that looks wrong.
//!
//! # Two wallets, both funded, is the only fixture that can show the difference
//!
//! Every probe below puts genuine $DIG at TWO different owner puzzle hashes on one chain. A fixture
//! with only the operator's coins would pass against a selector that ignored the owner argument
//! entirely and returned every $DIG coin it could see — which is exactly the implementation under
//! suspicion. Varying one actor while keeping a truthful control is what makes the assertions
//! discriminating rather than merely green.
//!
//! # Every coin comes from a genuine CAT spend
//!
//! A `Cat` is spendable only with a lineage proof reconstructed by EXECUTING its creating spend. A
//! hand-built `CoinRecord` never reaches that path, so a probe using one would assert lineage
//! handling against a fixture that cannot exhibit it. `support::ordinary_dig_coins` builds real CAT
//! spends, so a coin either resolves or genuinely does not.

mod support;

use std::collections::{HashMap, HashSet};

use chia_protocol::{Bytes32, CoinSpend};
use dig_chainsource_interface::{ChainSource, ChainSourceError, CoinRecord, SingletonLineage};
use dig_node_service::mirror::funding::{
    dig_cat_puzzle_hash, select_operator_dig_cats, FundingError,
};
use support::{ordinary_dig_coins, wallet, Wallet};

/// The margined requirement a create is funded for, in $DIG **base units** (1 DIG = 1_000).
///
/// Named rather than inlined so that no assertion below can be read as a claim about a particular
/// amount: this stands in for `apply_safety_margin(required_per_store, margin_bp)`, which the
/// planner derives and the selector never re-derives.
const REQUIRED: u64 = 40_000;

/// A chain holding whatever the test put on it — and nothing else.
#[derive(Default)]
struct Chain {
    /// Unspent coin records, by the puzzle hash they pay to.
    by_puzzle_hash: HashMap<Bytes32, Vec<CoinRecord>>,
    /// The spend that spent each coin — so `coin_spend(parent)` yields a coin's CREATING spend.
    spends: HashMap<Bytes32, CoinSpend>,
}

impl Chain {
    /// Publish `amounts` of ordinary $DIG at `owner`'s address, with their real creating spend.
    fn fund(&mut self, owner: &Wallet, amounts: &[u64], salt: u8) -> Vec<Bytes32> {
        let (spend, coins) = ordinary_dig_coins(owner, amounts, salt);
        self.spends.insert(spend.coin.coin_id(), spend);
        let mut ids: Vec<Bytes32> = Vec::new();
        for coin in coins {
            // A coin id is `(parent, puzzle_hash, amount)`. Two children of ONE spend paying the
            // SAME amount to the SAME address are therefore literally the same coin, and a fixture
            // that thinks it published two has published one. That collapse silently defeats every
            // per-coin assertion below -- committing "one of the two" commits both -- so it is a
            // fixture failure rather than something a test is left to notice.
            assert!(
                !ids.contains(&coin.coin_id()),
                "two fixture coins collapsed to one id; vary the AMOUNTS, not just the count"
            );
            ids.push(coin.coin_id());
            self.by_puzzle_hash
                .entry(coin.puzzle_hash)
                .or_default()
                .push(CoinRecord {
                    coin,
                    confirmed_height: Some(100),
                    spent_height: None,
                    timestamp: Some(1_700_000_000),
                    coinbase: false,
                });
        }
        ids
    }

    /// Publish coins whose creating spend is NOT on chain — a coin somebody paid to this address.
    fn fund_without_lineage(&mut self, owner: &Wallet, amounts: &[u64], salt: u8) {
        let (spend, coins) = ordinary_dig_coins(owner, amounts, salt);
        // The spend is deliberately NOT recorded, so the candidate cannot be authenticated.
        let _ = spend;
        for coin in coins {
            self.by_puzzle_hash
                .entry(coin.puzzle_hash)
                .or_default()
                .push(CoinRecord {
                    coin,
                    confirmed_height: Some(100),
                    spent_height: None,
                    timestamp: Some(1_700_000_000),
                    coinbase: false,
                });
        }
    }
}

impl ChainSource for Chain {
    type Error = ChainSourceError;

    fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Ok(None)
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self
            .by_puzzle_hash
            .get(&puzzle_hash)
            .cloned()
            .unwrap_or_default())
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

/// A chain that cannot answer at all — the fail-closed control.
struct Unreadable;

impl ChainSource for Unreadable {
    type Error = ChainSourceError;

    fn coin_record(&self, _: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn coin_records_by_puzzle_hash(
        &self,
        _: Bytes32,
        _: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn coin_records_by_parent(&self, _: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn coin_spend(&self, _: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn resolve_singleton_lineage(
        &self,
        _: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
    fn block_timestamp(&self, _: u32) -> Result<Option<u64>, Self::Error> {
        Err(ChainSourceError::Transport("no source".into()))
    }
}

/// The §16.4 operator wallet, whose money a mirror create locks.
fn operator() -> Wallet {
    wallet(0x21)
}

/// The node-custodied replica — a DIFFERENT wallet, on the same chain, holding $DIG of its own.
///
/// This is the wallet `WalletBackend::select_cats` reads. It exists in every fixture purely so that
/// selecting from it is a distinguishable outcome rather than an indistinguishable one.
fn replica() -> Wallet {
    wallet(0x77)
}

/// **The selector reads the OPERATOR's coins, and not the replica's.**
///
/// The discriminating fixture: the replica is funded so generously that a selector reading its set
/// would succeed with room to spare, while the operator holds exactly enough. The two assertions are
/// therefore independent — the returned coins are the operator's, AND none of them is the replica's
/// — because a selector that returned the union would satisfy the first alone.
#[test]
fn the_selector_funds_from_the_operator_wallet_and_never_from_the_replica() {
    let (operator, replica) = (operator(), replica());
    let mut chain = Chain::default();
    let operator_ids = chain.fund(&operator, &[REQUIRED], 0x01);
    let replica_ids = chain.fund(&replica, &[REQUIRED * 10], 0x02);

    let cats = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect("the operator holds exactly enough");

    let chosen: HashSet<Bytes32> = cats.iter().map(|c| c.coin.coin_id()).collect();
    assert_eq!(
        chosen,
        operator_ids.iter().copied().collect::<HashSet<_>>(),
        "the coins selected are the operator's own"
    );
    for id in &replica_ids {
        assert!(
            !chosen.contains(id),
            "a replica coin was selected: this is the spend of the wrong wallet's money that \
             dig-node#421 exists to make impossible"
        );
    }
    for cat in &cats {
        assert_eq!(
            cat.info.p2_puzzle_hash, operator.puzzle_hash,
            "every resolved CAT is owned by the operator's inner puzzle"
        );
    }
}

/// **A replica funded alone cannot fund an operator create.**
///
/// The mirror image of the probe above, and the one that fails loudly against the defect rather than
/// quietly: with ONLY the replica funded, a selector reading the replica's set returns coins and a
/// correct one refuses. The distinction is invisible in the previous test's success case if the
/// implementation returned a union.
#[test]
fn an_operator_with_no_coins_refuses_even_when_the_replica_is_rich() {
    let (operator, replica) = (operator(), replica());
    let mut chain = Chain::default();
    chain.fund(&replica, &[REQUIRED * 10], 0x02);

    let err = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect_err("the operator holds nothing");
    assert_eq!(
        err,
        FundingError::Insufficient {
            have_dig_base_units: 0,
            need_dig_base_units: REQUIRED,
        },
        "the operator's own address is empty, and the replica's balance is not its money"
    );
}

/// **A coin committed to an in-flight bundle is not selected into a second one.**
///
/// One reservation, one honest control: the operator holds two coins each covering the requirement,
/// and one of them is committed. A fixture reserving BOTH would read as the harsher case and is
/// exactly the one that cannot tell a working reservation filter from a selector that refused for
/// some other reason — there would be no uncommitted coin left to select.
#[test]
fn a_committed_coin_is_withheld_and_the_uncommitted_one_is_taken() {
    let operator = operator();
    let mut chain = Chain::default();
    // Distinct amounts, so the two coins are two coins. The COMMITTED one is the larger, so
    // largest-first reaches it first and a selector that ignored the commitment would visibly take
    // it -- a fixture committing the smaller would be satisfied by one that simply never looked.
    let ids = chain.fund(&operator, &[REQUIRED * 2, REQUIRED], 0x01);
    let (committed_id, free_id) = (ids[0], ids[1]);

    let committed: HashSet<String> = [hex::encode(committed_id)].into_iter().collect();
    let cats = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &committed)
        .expect("the uncommitted coin covers the requirement");

    let chosen: Vec<Bytes32> = cats.iter().map(|c| c.coin.coin_id()).collect();
    assert_eq!(
        chosen,
        vec![free_id],
        "the committed coin funds a bundle already in flight; selecting it again double-commits it"
    );
}

/// **Withholding the committed coin can turn a sufficient balance into a REFUSAL.**
///
/// The previous probe shows a reservation being skipped; this shows it actually costing something.
/// Without it, a filter that merely reordered candidates would pass: here the operator's raw balance
/// covers the requirement and its UNCOMMITTED balance does not, so an unfiltered selector succeeds
/// and a correct one refuses.
#[test]
fn a_reservation_that_makes_the_balance_short_refuses_rather_than_double_spending() {
    let operator = operator();
    let mut chain = Chain::default();
    // The raw balance COVERS the requirement (0.75 + 0.5 = 1.25x) and the uncommitted part does
    // not. That is the discriminating shape: an unfiltered selector succeeds here and a correct one
    // refuses, whereas a fixture whose raw balance were already short would refuse either way.
    let ids = chain.fund(&operator, &[REQUIRED * 3 / 4, REQUIRED / 2], 0x01);

    let committed: HashSet<String> = [hex::encode(ids[0])].into_iter().collect();
    let err = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &committed)
        .expect_err("three quarters of the balance is already committed");
    assert_eq!(
        err,
        FundingError::Insufficient {
            have_dig_base_units: REQUIRED / 2,
            need_dig_base_units: REQUIRED,
        },
        "only the uncommitted half is available, so the wallet is short and no spend is attempted"
    );
}

/// **A shortfall REFUSES; it never returns a short funding set.**
///
/// One base unit short, which is the boundary a partial-funding bug actually sits on. A create
/// funded from a short set locks collateral that does not satisfy the bond — money genuinely locked
/// for an advertisement that does not count.
#[test]
fn one_base_unit_short_refuses_rather_than_funding_a_smaller_coin() {
    let operator = operator();
    let mut chain = Chain::default();
    chain.fund(&operator, &[REQUIRED - 1], 0x01);

    let err = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect_err("one unit short");
    assert_eq!(
        err,
        FundingError::Insufficient {
            have_dig_base_units: REQUIRED - 1,
            need_dig_base_units: REQUIRED,
        }
    );
}

/// **Exactly at the requirement is funded** — the other side of the same bound.
///
/// Without this, the probe above is satisfied by an implementation that refuses everything.
#[test]
fn exactly_the_requirement_is_funded() {
    let operator = operator();
    let mut chain = Chain::default();
    chain.fund(&operator, &[REQUIRED], 0x01);

    let cats = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect("an exact cover is a cover");
    assert_eq!(cats.iter().map(|c| c.coin.amount).sum::<u64>(), REQUIRED);
}

/// **The target is the amount the caller passes, and the selection tracks it.**
///
/// Two requirements over one coin set, asserting that a larger requirement draws MORE coins. A
/// selector that ignored its amount argument — taking every coin, or exactly one — would answer the
/// same for both, which is how a create at a hard-coded collateral would go unnoticed.
#[test]
fn the_number_of_coins_drawn_follows_the_requirement_it_was_given() {
    let operator = operator();
    let mut chain = Chain::default();
    // Distinct amounts for the reason `Chain::fund` asserts, and each below the requirement so the
    // count genuinely has to grow: 0.6 + 0.5 + 0.4 = 1.5x, and no two of them cover 1x either.
    chain.fund(
        &operator,
        &[REQUIRED * 3 / 5, REQUIRED / 2, REQUIRED * 2 / 5],
        0x01,
    );

    let small =
        select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED / 2, &HashSet::new())
            .expect("covered");
    let large = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect("covered");

    assert_eq!(
        small.len(),
        1,
        "the largest coin alone covers half the requirement"
    );
    assert_eq!(
        large.len(),
        2,
        "no single coin covers the whole requirement, so a second is drawn"
    );
}

/// **A candidate that cannot be authenticated refuses the WHOLE selection.**
///
/// Anyone may pay a coin to any puzzle hash. A coin whose creating spend is not on chain cannot have
/// its lineage proof reconstructed, so it is not spendable — and dropping it and proceeding with the
/// rest would fund the create from a short set, which is the failure this crate refuses by design.
///
/// The fixture keeps a genuine, sufficient coin beside the unauthenticated one, so the refusal is
/// visibly caused by the bad candidate rather than by an empty wallet.
#[test]
fn an_unauthenticatable_candidate_refuses_the_selection_rather_than_being_skipped() {
    let operator = operator();
    let mut chain = Chain::default();
    chain.fund(&operator, &[REQUIRED], 0x01);
    // Larger, so largest-first reaches it FIRST and a skip would be observable as a success.
    chain.fund_without_lineage(&operator, &[REQUIRED * 2], 0x03);

    let err = select_operator_dig_cats(&chain, operator.puzzle_hash, REQUIRED, &HashSet::new())
        .expect_err("a candidate could not be proven spendable");
    assert!(
        matches!(err, FundingError::Unauthenticated { .. }),
        "expected an authentication refusal, got {err:?}"
    );
}

/// **An unreadable chain is UNKNOWN, never an empty wallet.**
///
/// The two are one `Ok(vec![])` apart and mean opposite things: an empty answer says this operator
/// holds no $DIG, which is a definite claim a source that failed to answer is in no position to
/// make. The variant is asserted, not merely the failure, because `Insufficient` would be that claim
/// wearing an error's name.
#[test]
fn a_chain_that_cannot_answer_is_unknown_rather_than_a_short_wallet() {
    let err = select_operator_dig_cats(
        &Unreadable,
        operator().puzzle_hash,
        REQUIRED,
        &HashSet::new(),
    )
    .expect_err("the source cannot answer");
    assert!(
        matches!(err, FundingError::Chain(_)),
        "an unreadable source must not report the wallet as short: {err:?}"
    );
}

/// The scan hash is the one the operator's coins actually land on.
///
/// A cheap structural check that keeps the fixtures honest: if `dig_cat_puzzle_hash` and the
/// fixture's CAT construction ever disagreed, every probe above would scan an address holding
/// nothing and the whole file would go green on empty wallets.
#[test]
fn the_fixture_coins_land_on_the_puzzle_hash_the_selector_scans() {
    let operator = operator();
    let (_, coins) = ordinary_dig_coins(&operator, &[REQUIRED], 0x01);
    assert_eq!(
        coins[0].puzzle_hash,
        dig_cat_puzzle_hash(operator.puzzle_hash),
        "the selector must scan the address the operator's $DIG actually sits at"
    );
}
