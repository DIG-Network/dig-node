//! A real DIG rewards distributor, launched once against `chia-sdk-test`'s peer simulator, and a
//! `MockChainSource` loaded from that real state — shared between
//! `tests/rewards_chain_port_a3.rs` (DIG-Network/dig_ecosystem#3310) and
//! `tests/rewards_claim_chain_port_3347.rs` (DIG-Network/dig_ecosystem#3347), which both need the
//! SAME real, decodable launch rather than two independently hand-rolled ones. See
//! `rewards_chain_port_a3.rs`'s original module doc (still the fixture's own doc below) for why
//! this substitution (the network transport, nothing else) is sound.

use chia_protocol::{Bytes32, CoinSpend, SpendBundle};
use chia_puzzle_types::CoinProof;
use chia_puzzle_types::Memos;
use chia_puzzles::SETTLEMENT_PAYMENT_HASH;
use chia_sdk_driver::{
    sign_standard_transaction, Cat, Offer, RewardDistributorConstants, RewardDistributorType,
    SingleCatSpend, Spend, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_sdk_test::Simulator;
use chia_sdk_types::{Conditions, TESTNET11_CONSTANTS};
use clvm_traits::{clvm_quote, ToClvm};
use clvmr::NodePtr;
use dig_chainsource_interface::{CoinRecord, MockChainSource, SingletonLineage};
use dig_rewards_coin::comment::LaunchComment;
use dig_rewards_coin::constants::{
    MAX_SECONDS_OFFSET, PAYOUT_THRESHOLD_BASE_UNITS, WITHDRAWAL_SHARE_BPS,
};
use dig_rewards_coin::launch::launch_dig_distributor;

/// Small on purpose: the simulator's clock starts at zero.
pub const FIRST_EPOCH_START: u64 = 1_234;
/// A short epoch; these tests are about a report's/adapter's fields, not the epoch length.
pub const TEST_EPOCH_SECONDS: u64 = 1_000;
/// $DIG the funder mints for itself.
const MINTED_BASE_UNITS: u64 = 10_000_000_000;

/// A fixed, never-launched manager singleton launcher id: curried into the constants table for
/// shape only, never read back off chain by `read_distributor`.
const DUMMY_MANAGER_LAUNCHER_ID: Bytes32 = Bytes32::new([0x42; 32]);

/// The `store_id`/`root` this fixture's launch comment carries — asserted against by both
/// consumers of this fixture.
pub const LAUNCH_STORE_ID: Bytes32 = Bytes32::new([0xaa; 32]);
pub const LAUNCH_ROOT: Bytes32 = Bytes32::new([0xbb; 32]);

/// Everything a real launch produced, named rather than positional.
pub struct LaunchedFixture {
    pub sim: Simulator,
    pub launcher_id: Bytes32,
    pub security_coin_id: Bytes32,
    pub distributor_coin_id: Bytes32,
    pub reserve_coin_id: Bytes32,
    pub reserve_launch_id: Bytes32,
    pub reserve_parent_id: Bytes32,
    pub launch_comment: LaunchComment,
    pub constants: RewardDistributorConstants,
}

/// Mints a reward CAT, builds a launch offer, and launches a real DIG distributor via
/// `launch_dig_distributor` against a fresh `Simulator` — trimmed from
/// `dig-rewards-coin::tests::simulator::launch_harness_with_constants_builder`.
pub fn launch_fixture() -> Result<LaunchedFixture, Box<dyn std::error::Error>> {
    let ctx = &mut SpendContext::new();
    let mut sim = Simulator::new();

    let funder = sim.bls(MINTED_BASE_UNITS);
    let funder_p2 = StandardLayer::new(funder.pk);
    let (issue_cat, source_cats) = Cat::single_issuance(
        ctx,
        funder.coin.coin_id(),
        None,
        MINTED_BASE_UNITS,
        Conditions::new().create_coin(funder.puzzle_hash, MINTED_BASE_UNITS, Memos::None),
    )?;
    funder_p2.spend(ctx, funder.coin, issue_cat)?;
    let source_cat = source_cats[0];
    sim.spend_coins(ctx.take(), std::slice::from_ref(&funder.sk))?;

    let offer_amount = 1;
    let launcher_bls = sim.bls(offer_amount);
    let offer_spend = StandardLayer::new(launcher_bls.pk).spend_with_conditions(
        ctx,
        Conditions::new().create_coin(SETTLEMENT_PAYMENT_HASH.into(), offer_amount, Memos::None),
    )?;
    let puzzle_reveal = ctx.serialize(&offer_spend.puzzle)?;
    let solution = ctx.serialize(&offer_spend.solution)?;

    let cat_inner_puzzle = clvm_quote!(Conditions::new().create_coin(
        SETTLEMENT_PAYMENT_HASH.into(),
        source_cat.coin.amount,
        Memos::None
    ))
    .to_clvm(ctx)?;
    let cat_inner_spend = funder_p2.delegated_inner_spend(
        ctx,
        Spend {
            puzzle: cat_inner_puzzle,
            solution: NodePtr::NIL,
        },
    )?;
    source_cat.spend(
        ctx,
        SingleCatSpend {
            prev_coin_id: source_cat.coin.coin_id(),
            next_coin_proof: CoinProof {
                parent_coin_info: source_cat.coin.parent_coin_info,
                inner_puzzle_hash: funder.puzzle_hash,
                amount: source_cat.coin.amount,
            },
            prev_subtotal: 0,
            extra_delta: 0,
            p2_spend: cat_inner_spend,
            revoke: false,
        },
    )?;

    let spends = ctx.take();
    let cat_offer_spend = spends
        .iter()
        .find(|spend| spend.coin.coin_id() == source_cat.coin.coin_id())
        .expect("the CAT offer spend")
        .clone();
    for spend in spends {
        if spend.coin.coin_id() != source_cat.coin.coin_id() {
            ctx.insert(spend);
        }
    }

    let signature = sign_standard_transaction(
        ctx,
        launcher_bls.coin,
        offer_spend,
        &launcher_bls.sk,
        &TESTNET11_CONSTANTS,
    )?;
    let offer = Offer::from_spend_bundle(
        ctx,
        &SpendBundle {
            coin_spends: vec![
                CoinSpend::new(launcher_bls.coin, puzzle_reveal, solution),
                cat_offer_spend,
            ],
            aggregated_signature: signature,
        },
    )?;

    let constants = RewardDistributorConstants::without_launcher_id(
        RewardDistributorType::Managed {
            manager_singleton_launcher_id: DUMMY_MANAGER_LAUNCHER_ID,
        },
        funder.puzzle_hash,
        TEST_EPOCH_SECONDS,
        u64::MAX,
        MAX_SECONDS_OFFSET,
        // Deliberately NOT `PAYOUT_THRESHOLD_BASE_UNITS` (the distributor's default launch
        // value) -- #3347 mutation proof (iv) needs a fixture whose on-chain threshold DIFFERS
        // from the default, or a port that ignores the chain and returns the default constant
        // reads as correct by coincidence. See `reserve_asset_id_and_payout_threshold_are_read_from_chain`.
        PAYOUT_THRESHOLD_BASE_UNITS.saturating_add(1_000_000),
        false,
        0,
        WITHDRAWAL_SHARE_BPS,
        source_cat.info.asset_id,
    );

    let launch_comment = LaunchComment::new(LAUNCH_STORE_ID, LAUNCH_ROOT);

    let launched = launch_dig_distributor(
        ctx,
        &offer,
        FIRST_EPOCH_START,
        constants,
        &TESTNET11_CONSTANTS,
        launch_comment,
        // The simulator's clock starts at zero, so FIRST_EPOCH_START is in the future.
        0,
    )?;

    sim.spend_coins(
        ctx.take(),
        &[
            launcher_bls.sk.clone(),
            launched.security_coin_secret_key.clone(),
            funder.sk.clone(),
        ],
    )?;

    let launcher_id = launched.distributor.info.constants.launcher_id;
    let distributor_coin_id = launched.distributor.coin.coin_id();
    let reserve_launch_id = launched.distributor.reserve.coin.coin_id();
    let reserve_parent_id = launched.distributor.reserve.coin.parent_coin_info;
    let reserve_coin_id = launched.distributor.reserve.coin.coin_id();

    // The launcher's own parent (its "security coin") is what CREATES the launcher coin, i.e.
    // the spend `read_launch_comment` needs. Derived by looking the launcher's confirmed record
    // up after the fact, rather than tracking the security coin id through the launch machinery
    // by hand.
    let security_coin_id = sim
        .coin_state(launcher_id)
        .expect("the launcher coin was confirmed by the launch spend")
        .coin
        .parent_coin_info;

    Ok(LaunchedFixture {
        sim,
        launcher_id,
        security_coin_id,
        distributor_coin_id,
        reserve_coin_id,
        reserve_launch_id,
        reserve_parent_id,
        launch_comment,
        constants: launched.distributor.info.constants,
    })
}

/// Builds a `MockChainSource` over `fixture`'s real simulator state, loading exactly what
/// `read_distributor_guarded`/`read_launch_comment` read — mirrors
/// `dig-rewards-coin::tests::simulator::chain_source_with_gaps`.
pub fn mock_chain_source(fixture: &LaunchedFixture) -> MockChainSource {
    let singleton_members = [fixture.launcher_id, fixture.distributor_coin_id];

    // The eve coin: `read_distributor` needs the SPEND that consumed it, not any record it
    // named directly.
    let eve_coin_id = fixture
        .sim
        .children(fixture.launcher_id)
        .first()
        .map(|state| state.coin.coin_id());

    let extra_ids = [
        fixture.security_coin_id,
        fixture.reserve_launch_id,
        fixture.reserve_parent_id,
        fixture.reserve_coin_id,
    ];

    let mut source = MockChainSource::new();
    for id in singleton_members
        .iter()
        .copied()
        .chain(extra_ids.iter().copied())
        .chain(eve_coin_id)
    {
        if let Some(state) = fixture.sim.coin_state(id) {
            source = source.with_coin(id, CoinRecord::from_coin_state(state));
        }
        if let Some(spend) = fixture.sim.coin_spend(id) {
            source = source.with_spend(id, spend);
        }
    }

    source = source.with_lineage(
        fixture.launcher_id,
        SingletonLineage::new(
            fixture.distributor_coin_id,
            singleton_members.iter().copied(),
        ),
    );

    let peak = fixture.sim.height();
    for height in 0..=peak {
        source = source.with_timestamp(height, u64::from(height) * 1_000 + 1);
    }
    source.with_peak(peak)
}
