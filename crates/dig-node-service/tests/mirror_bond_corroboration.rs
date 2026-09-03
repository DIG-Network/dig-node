//! A `Bonded` verdict must rest on AGREEMENT across the node's own peers, never on one source
//! (dig-node#503).
//!
//! # What these tests are about, and why the fixture has to be shaped this way
//!
//! `mirror_bond_verify.rs` proves the four chain checks are internally sound. Every one of them is
//! *internal consistency* of a coin and the spend that created it, and that is exactly the hole:
//! an attacker who curries the real, public $DIG CAT puzzle around an INVENTED parent gets a coin
//! that passes all four, because nothing there asks whether the coin was ever on mainnet. So the
//! coin in the attack fixture below is not malformed in any way. It is a genuine CAT spend, at the
//! mirror puzzle hash, in $DIG, at full collateral, advertising exactly the `(store, root, epoch)`
//! being asked about. The ONLY thing wrong with it is that no other peer has ever seen it.
//!
//! Two consequences for how these fixtures are built:
//!
//! * **One peer varies; the rest stay honest.** A round where every peer lies cannot see a missing
//!   corroboration step, because there is no truthful answer left for the round to prefer.
//! * **The `Bonded` control is not optional.** Without a case where agreeing peers DO produce
//!   `Bonded`, every negative here is equally explained by a harness that can never produce a
//!   verdict at all — a suite that passes by asserting nothing.
//!
//! # Why the CHAIN half, and not `verdict_for`
//!
//! `verdict_for` returns `Unverified` before any chain read while `declaration_source_is_readable()`
//! is false, so `Bonded` is unreachable through it and the control above could not exist. #503's
//! concern lives entirely in the chain half, which is reachable today and composes unchanged when
//! the ownership half lands.

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use dig_node_core::mirror_bond::BondVerdict;
use dig_node_service::mirror::bond_verify::chain_bond_verdict;
use dig_wallet::sage::chain::ChainTransport;
use dig_wallet::sage::corroborated_source::CorroboratedChainSource;
use dig_wallet::sage::db::WalletDb;
use dig_wallet::sage::fallback::{FallbackCoin, FallbackCoinSpend};
use dig_wallet::sage::peer_reads::{CoinPeer, PeerCorroboratedReads, PeerSample};
use dig_wallet::sage::quorum::PeakClaim;

use support::{
    creating_spend, creating_spend_of_amount, epoch, mirror_memos, root_1, store_a, wallet,
    COLLATERAL,
};

// ---------------------------------------------------------------------------
// The doubles
// ---------------------------------------------------------------------------

/// ONE peer's whole view of the chain: the coins it will admit exist, and the spends it will
/// produce.
///
/// A map rather than a single scripted answer, because the property under test needs one peer to
/// answer a coin question AND a spend question consistently within its own story. A double that can
/// only voice one of the two cannot express a peer presenting a fabricated coin together with the
/// fabricated spend that created it — which is precisely the lie a single-source verifier believes.
#[derive(Clone, Default)]
struct ChainView {
    records: HashMap<Bytes32, FallbackCoin>,
    spends: HashMap<Bytes32, FallbackCoinSpend>,
}

impl ChainView {
    /// A view holding each `(creating spend, created coin)` pair: the coin as an unspent record,
    /// and the spend keyed by the coin it consumed — which is the parent read the bond path makes.
    fn holding(pairs: &[(CoinSpend, Coin)]) -> Self {
        let mut view = Self::default();
        for (spend, coin) in pairs {
            view.records.insert(coin.coin_id(), fallback_coin(coin));
            view.spends
                .insert(spend.coin.coin_id(), fallback_spend(spend));
        }
        view
    }
}

/// A coin as the record a peer reports for it. Unspent and confirmed, because a spent bond is
/// refused a step earlier and would mask everything below it.
fn fallback_coin(coin: &Coin) -> FallbackCoin {
    FallbackCoin {
        coin_id: hex::encode(coin.coin_id()),
        parent_coin_info: hex::encode(coin.parent_coin_info),
        puzzle_hash: hex::encode(coin.puzzle_hash),
        amount: coin.amount,
        created_height: Some(6_000_000),
        spent_height: None,
        created_timestamp: Some(1_700_000_000),
        spent_timestamp: None,
    }
}

/// A real `CoinSpend` as the spend a peer reports. The reveal and solution are the fixture's own
/// executed CLVM, so the puzzle hash IS the reveal's tree hash and the corroborated read's own
/// binding checks pass on the honest fixtures rather than being dodged.
fn fallback_spend(spend: &CoinSpend) -> FallbackCoinSpend {
    FallbackCoinSpend {
        coin_id: hex::encode(spend.coin.coin_id()),
        parent_coin_info: hex::encode(spend.coin.parent_coin_info),
        puzzle_hash: hex::encode(spend.coin.puzzle_hash),
        amount: spend.coin.amount,
        puzzle_reveal: hex::encode(&spend.puzzle_reveal),
        solution: hex::encode(&spend.solution),
    }
}

/// A peer that answers from one [`ChainView`], or refuses to answer at all.
struct ScriptedPeer {
    id: String,
    view: Option<ChainView>,
}

#[async_trait]
impl CoinPeer for ScriptedPeer {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn coin_record(
        &self,
        coin_id: Bytes32,
    ) -> dig_wallet::sage::Result<Option<FallbackCoin>> {
        match &self.view {
            Some(view) => Ok(view.records.get(&coin_id).cloned()),
            None => Err(dig_wallet::sage::Error::internal("peer did not answer")),
        }
    }

    async fn coin_spend(
        &self,
        coin_id: Bytes32,
    ) -> dig_wallet::sage::Result<Option<FallbackCoinSpend>> {
        match &self.view {
            Some(view) => Ok(view.spends.get(&coin_id).cloned()),
            None => Err(dig_wallet::sage::Error::internal("peer did not answer")),
        }
    }

    async fn peak_claim(&self) -> Option<PeakClaim> {
        None
    }
}

/// A draw of scripted peers with DISTINCT ids — one view each, never one view counted twice.
struct ScriptedSample {
    views: Vec<Option<ChainView>>,
}

#[async_trait]
impl PeerSample for ScriptedSample {
    async fn draw(&self) -> Vec<Arc<dyn CoinPeer>> {
        self.views
            .iter()
            .enumerate()
            .map(|(i, view)| {
                Arc::new(ScriptedPeer {
                    id: format!("10.0.0.{i}:8444"),
                    view: view.clone(),
                }) as Arc<dyn CoinPeer>
            })
            .collect()
    }
}

/// A corroborated source over exactly these peer views, on a fresh in-memory wallet DB.
async fn source_over(views: Vec<Option<ChainView>>) -> CorroboratedChainSource {
    let db = WalletDb::open_in_memory()
        .await
        .expect("in-memory wallet db");
    let reads = Arc::new(PeerCorroboratedReads::new(
        Arc::new(ScriptedSample { views }),
        db,
    ));
    CorroboratedChainSource::new(reads, tokio::runtime::Handle::current())
}

/// The same source, asked at the BOND floor -- what `ChainBondVerifier` actually uses.
async fn bond_floor_source_over(views: Vec<Option<ChainView>>) -> CorroboratedChainSource {
    source_over(views)
        .await
        .requiring_corroboration(dig_wallet::sage::quorum::BOND_CORROBORATION_FLOOR)
}

// ---------------------------------------------------------------------------
// The fixtures
// ---------------------------------------------------------------------------

/// The honest bond every case is measured against: a real, fully collateralised mirror coin
/// advertising `store_a()` at `root_1()` in the current epoch.
fn honest_bond() -> (CoinSpend, Coin) {
    let owner = wallet(1);
    creating_spend(
        &owner,
        &mirror_memos(&owner, store_a(), root_1(), &["https://honest.example"]),
    )
}

/// A coin that is wrong in NO way except that it was never on chain.
///
/// A different wallet and a different amount so its id genuinely differs from the honest bond's
/// (the fixture derives a parent from owner+asset+amount, so reusing either would produce the same
/// coin). It advertises the SAME `(store, root, epoch)` and carries the SAME full collateral, so
/// every check in `chain_bond_verdict` passes on it when a single source vouches for it. Only
/// corroboration can tell it apart from the honest one.
fn fabricated_bond() -> (CoinSpend, Coin) {
    let attacker = wallet(9);
    creating_spend_of_amount(
        &attacker,
        &mirror_memos(
            &attacker,
            store_a(),
            root_1(),
            &["https://attacker.example"],
        ),
        COLLATERAL,
    )
}

/// The chain half's verdict about `coin`, asked at full collateral.
fn verdict(source: &CorroboratedChainSource, coin: Bytes32) -> BondVerdict {
    chain_bond_verdict(
        source,
        store_a(),
        root_1(),
        &epoch(),
        Some(COLLATERAL),
        coin,
    )
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

/// **Proves:** THE BUG. A coin that only ONE peer has ever heard of is not `Bonded`, however
/// perfect the coin is.
///
/// **Catches:** a verdict sourced from a single provider — which is what
/// `ChainTransport::chain_source` hands out, since its router asks `api.coinset.org` first and its
/// own `ProviderInfo` records `trustless: false`. Against that source this exact fixture returns
/// `Bonded` and ranks the attacker's peer at zero collateral cost.
///
/// **Why the fixture is shaped this way:** three honest peers are kept, and only one varies. A
/// four-liar round could not see a missing corroboration step, because it would leave no truthful
/// answer for the round to prefer.
#[tokio::test(flavor = "multi_thread")]
async fn a_coin_only_one_peer_has_ever_seen_is_not_bonded() {
    let honest = honest_bond();
    let forged = fabricated_bond();

    let attacker_view = ChainView::holding(&[honest.clone(), forged.clone()]);
    let honest_view = ChainView::holding(std::slice::from_ref(&honest));

    let source = source_over(vec![
        Some(attacker_view),
        Some(honest_view.clone()),
        Some(honest_view.clone()),
        Some(honest_view),
    ])
    .await;

    assert_eq!(
        verdict(&source, forged.1.coin_id()),
        BondVerdict::Unbonded,
        "one peer vouching alone must not produce Bonded; three honest peers agreeing the coin \
         does not exist is a CORROBORATED absence, which disproves the claim rather than leaving \
         it unexamined"
    );
}

/// **Proves:** below the corroboration floor, no verdict is `Bonded` — not even about a genuine
/// coin.
///
/// **Catches:** a floor of one. `quorum::CORROBORATION_FLOOR` is 2, and a single answering peer is
/// `Insufficient` rather than a source. The coin here is the HONEST one on purpose: the refusal has
/// to come from the count, not from anything wrong with the coin.
#[tokio::test(flavor = "multi_thread")]
async fn one_answering_peer_cannot_bond_even_a_genuine_coin() {
    let honest = honest_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));

    let source = source_over(vec![Some(view)]).await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Unverified,
        "a lone source is UNKNOWN, never a bond -- and never an absence either"
    );
}

/// **Proves:** peers that split evenly settle nothing, and the verdict is `Unverified` rather than
/// either side's story.
///
/// **Catches:** believing a plurality. `required_agreement(4)` is 3, so a 2-vs-2 round has no
/// winner; a verifier that took the first answer, or the largest bucket regardless of the ratio,
/// would promote whichever half the attacker controls.
#[tokio::test(flavor = "multi_thread")]
async fn evenly_split_peers_do_not_bond() {
    let honest = honest_bond();
    let forged = fabricated_bond();

    let vouching = ChainView::holding(&[honest.clone(), forged.clone()]);
    let denying = ChainView::holding(std::slice::from_ref(&honest));

    let source = source_over(vec![
        Some(vouching.clone()),
        Some(vouching),
        Some(denying.clone()),
        Some(denying),
    ])
    .await;

    assert_eq!(
        verdict(&source, forged.1.coin_id()),
        BondVerdict::Unverified,
        "half the round vouching is disagreement, and disagreement is UNKNOWN"
    );
}

/// **Proves:** the control, and without it the three cases above prove nothing.
///
/// Agreeing peers holding a genuine, fully collateralised coin that advertises exactly the
/// requested `(store, root, epoch)` DO produce `Bonded`. If they did not, every `Unbonded` and
/// `Unverified` above would be equally explained by a harness that cannot reach a positive verdict
/// at all.
#[tokio::test(flavor = "multi_thread")]
async fn agreeing_peers_do_bond_a_genuine_coin() {
    let honest = honest_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));

    let source = source_over(vec![
        Some(view.clone()),
        Some(view.clone()),
        Some(view.clone()),
        Some(view),
    ])
    .await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Bonded,
        "corroboration must not make a real bond unverifiable -- the fix is a floor, not a wall"
    );
}

/// **Proves:** a transport with no corroborated-read surface REFUSES, and does not quietly hand
/// back the single-source router instead.
///
/// **Catches:** the fallback that would undo the whole fix. Falling through to one endpoint exactly
/// when the peers are unavailable is what lets that endpoint overrule them, and it is invisible
/// from the outside — the caller gets an `Ok` source and a `Bonded` verdict either way. The only
/// observable difference is that this call must be an `Err`.
#[tokio::test(flavor = "multi_thread")]
async fn a_transport_without_peer_reads_refuses_rather_than_using_the_router() {
    let transport = ChainTransport::new();

    let refused = transport.corroborated_chain_source(tokio::runtime::Handle::current());

    assert!(
        refused.is_err(),
        "with no peer reads there is nothing to corroborate against, and the router is NOT a \
         substitute"
    );
}

/// **Proves:** a source drawing ZERO peers errs rather than reporting an absence.
///
/// **Catches:** the collapse of UNKNOWN into "no such coin" at the read layer. That direction is
/// the expensive one on this path: `chain_bond_verdict` reads `Ok(None)` as *the publisher named a
/// coin that does not exist* and answers `Unbonded`, which would demote an honest holder every time
/// this node's peer tier was momentarily empty.
#[tokio::test(flavor = "multi_thread")]
async fn a_source_with_no_peers_errs_rather_than_reporting_an_absence() {
    use dig_chainsource_interface::ChainSource;

    let honest = honest_bond();
    let source = source_over(vec![]).await;

    assert!(
        source.coin_record(honest.1.coin_id()).is_err(),
        "no peers means UNKNOWN, never Ok(None)"
    );
    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Unverified,
        "and the verdict that reads it must fail closed, not answer Unbonded"
    );
}

/// **Proves the DEFECT, so the fix above is demonstrably load-bearing.**
///
/// The identical fabricated coin, read through a source that answers from ONE story -- the shape
/// `ChainTransport::chain_source` hands out, whose router asks `api.coinset.org` first and whose own
/// `ProviderInfo` records `trustless: false` -- verifies as `Bonded`. Nothing about the coin is
/// wrong; it was simply never on mainnet, and a single source has no way to say so.
///
/// This is the pre-change behaviour of the whole bond path, kept as a permanent witness: if the
/// corroboration seam is ever removed and a single-source read reinstated,
/// `a_coin_only_one_peer_has_ever_seen_is_not_bonded` flips to `Bonded` and this test explains why.
#[test]
fn a_single_source_bonds_the_fabricated_coin() {
    use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};

    /// A chain that is whatever one provider says it is.
    struct SingleSource {
        records: HashMap<Bytes32, CoinRecord>,
        spends: HashMap<Bytes32, CoinSpend>,
    }

    impl ChainSource for SingleSource {
        type Error = std::convert::Infallible;

        fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self.records.get(&coin_id).cloned())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_records_by_parent(&self, _p: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
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
            Ok(Some(6_000_000))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(None)
        }
    }

    let (spend, coin) = fabricated_bond();
    let source = SingleSource {
        records: HashMap::from([(
            coin.coin_id(),
            CoinRecord {
                coin,
                confirmed_height: Some(6_000_000),
                spent_height: None,
                timestamp: Some(1_700_000_000),
                coinbase: false,
            },
        )]),
        spends: HashMap::from([(spend.coin.coin_id(), spend)]),
    };

    assert_eq!(
        chain_bond_verdict(
            &source,
            store_a(),
            root_1(),
            &epoch(),
            Some(COLLATERAL),
            coin.coin_id(),
        ),
        BondVerdict::Bonded,
        "the fabricated coin passes every internal-consistency check; only corroboration catches it"
    );
}

// ---------------------------------------------------------------------------
// dig-node#513 item 1 -- the bond path's own corroboration floor
// ---------------------------------------------------------------------------

/// **Proves (dig-node#513 item 1):** a round only TWO peers answered does not bond, because the
/// bond path demands `BOND_CORROBORATION_FLOOR` and not the sync path's
/// `CORROBORATION_FLOOR = 2`.
///
/// **Catches:** the floor being inherited rather than chosen. `CORROBORATION_FLOOR` is two for a
/// liveness reason that belongs to the SYNC path -- a refused round stalls the wallet's replica --
/// and at two a pair of colluding peers is a full quorum, so a promotion costs an attacker two
/// voices. On this path a refusal costs nothing, so the floor can be higher and must be.
///
/// **Why the fixture is shaped this way:** four peers are drawn and two are silent, so the round
/// is *thin* rather than *dishonest*; the two that speak hold the GENUINE bond and agree with each
/// other perfectly. Nothing but the floor can refuse it. The control below is the identical
/// fixture at the default floor, differing in exactly one dimension -- the floor -- so this pair
/// cannot be satisfied by a harness that simply never bonds.
#[tokio::test(flavor = "multi_thread")]
async fn a_two_peer_round_does_not_bond_at_the_bond_floor() {
    let honest = honest_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));

    let source = bond_floor_source_over(vec![Some(view.clone()), Some(view), None, None]).await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Unverified,
        "two agreeing peers bonded a coin on the path where refusing is free"
    );
}

/// **Proves:** the control for the case above -- the SAME two-peer round DOES bond at the default
/// floor, so the refusal there is the bond floor and not the thinness of the fixture.
///
/// It also pins the sync path's floor from the other side: `CORROBORATION_FLOOR` must stay at two,
/// because raising it is what froze a user's replica, and a change that raised the shared constant
/// to satisfy the case above would turn this control red.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_two_peer_round_still_bonds_at_the_default_floor() {
    let honest = honest_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));

    let source = source_over(vec![Some(view.clone()), Some(view), None, None]).await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Bonded,
        "fixture: a two-peer round must bond at the default floor, or the case above proves nothing"
    );
}

/// **Proves:** the bond floor is not bought by DIALLING wider. Three peers answer, but only two of
/// them agree, and the round is refused.
///
/// **Catches:** a floor enforced only on how many peers ANSWERED. Under that reading a round of
/// twelve in which two voices agree clears a floor of three, which is the exact shape -- two
/// colluding peers plus noise -- the floor exists to refuse. `tally_with_floor` therefore applies
/// it to the AGREEING count too.
#[tokio::test(flavor = "multi_thread")]
async fn a_wide_round_in_which_only_two_peers_agree_does_not_bond() {
    let honest = honest_bond();
    let forged = fabricated_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));
    let dissent = ChainView::holding(std::slice::from_ref(&forged));

    let source = bond_floor_source_over(vec![Some(view.clone()), Some(view), Some(dissent)]).await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Unverified,
        "two agreeing voices among three answers cleared a floor of three"
    );
}

/// **Proves:** the control for the whole floor -- at the bond floor, a round of THREE agreeing
/// peers still bonds a genuine coin. The floor is a floor, not a wall.
#[tokio::test(flavor = "multi_thread")]
async fn three_agreeing_peers_do_bond_at_the_bond_floor() {
    let honest = honest_bond();
    let view = ChainView::holding(std::slice::from_ref(&honest));

    let source =
        bond_floor_source_over(vec![Some(view.clone()), Some(view.clone()), Some(view)]).await;

    assert_eq!(
        verdict(&source, honest.1.coin_id()),
        BondVerdict::Bonded,
        "the bond floor refused a round that met it exactly"
    );
}
