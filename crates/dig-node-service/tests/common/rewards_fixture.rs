//! A real DIG rewards distributor, launched once against `chia-sdk-test`'s peer simulator, and a
//! `MockChainSource` loaded from that real state — shared between
//! `tests/rewards_chain_port_a3.rs` (DIG-Network/dig_ecosystem#3310) and
//! `tests/rewards_claim_chain_port_3347.rs` (DIG-Network/dig_ecosystem#3347), which both need the
//! SAME real, decodable launch rather than two independently hand-rolled ones. See
//! `rewards_chain_port_a3.rs`'s original module doc (still the fixture's own doc below) for why
//! this substitution (the network transport, nothing else) is sound.

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use chia_puzzle_types::singleton::{SingletonArgs, SingletonSolution};
use chia_puzzle_types::CoinProof;
use chia_puzzle_types::Memos;
use chia_puzzle_types::{EveProof, LineageProof, Proof};
use chia_puzzles::{SETTLEMENT_PAYMENT_HASH, SINGLETON_LAUNCHER_HASH};
use chia_sdk_driver::{
    sign_standard_transaction, Cat, CatSpend, Launcher, Offer, RewardDistributorConstants,
    RewardDistributorType, SingleCatSpend, Slot, Spend, SpendContext, SpendWithConditions,
    StandardLayer,
};
use chia_sdk_test::Simulator;
use chia_sdk_types::puzzles::{RewardDistributorRewardSlotValue, RewardDistributorSlotNonce};
use chia_sdk_types::{Conditions, TESTNET11_CONSTANTS};
use clvm_traits::{clvm_quote, ToClvm};
use clvmr::NodePtr;
use dig_chainsource_interface::{CoinRecord, MockChainSource, SingletonLineage};
use dig_rewards_coin::comment::LaunchComment;
use dig_rewards_coin::constants::{
    MAX_SECONDS_OFFSET, PAYOUT_THRESHOLD_BASE_UNITS, WITHDRAWAL_SHARE_BPS,
};
use dig_rewards_coin::eligibility::{judge_candidate, EligibilityQuestion, MirrorCoinFacts};
use dig_rewards_coin::entries::{add_entry, ManagerAuthority};
use dig_rewards_coin::epoch::{start_next_distributor_epoch, sync_distributor};
use dig_rewards_coin::fund::commit_incentives_for_distributor_epoch;
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

// ---------------------------------------------------------------------------------------------
// A FUNDED, ADMITTED fixture -- DIG-Network/dig_ecosystem#3347's U2. `launch_fixture` above never
// spawns a real manager singleton (its `DUMMY_MANAGER_LAUNCHER_ID` is curried for shape only), so
// it cannot authorize an `AddEntry`. This second fixture launches a REAL manager singleton, commits
// incentives, admits one entry, rolls the epoch and syncs mid-epoch -- ported, line for line in
// spirit, from `dig-rewards-coin` 0.8.0's own
// `tests/simulator.rs::a_claim_built_entirely_from_a_chain_read_is_accepted` (the crate's own proof
// that a claim built entirely from a chain read is accepted by the simulator).
// ---------------------------------------------------------------------------------------------

/// $DIG committed to the first epoch -- the SAME figure `dig-rewards-coin`'s own golden test uses.
const COMMITTED_BASE_UNITS: u64 = 1_000_000;

/// The mirror-collateral epoch [`verdict_for`] judges against. Any ordinal will do; what matters is
/// that the same one is asked and advertised.
const TEST_MIRROR_COLLATERAL_EPOCH: u32 = 7;

/// A mirror coin that passes every eligibility check and pays out to one hash -- mirrors
/// `dig-rewards-coin`'s own `EligibleMirrorCoin` test double.
struct EligibleMirrorCoin {
    payout_puzzle_hash: Bytes32,
}

impl MirrorCoinFacts for EligibleMirrorCoin {
    fn advertises(&self, _store: Bytes32, _root: Bytes32, mirror_collateral_epoch: u32) -> bool {
        mirror_collateral_epoch == TEST_MIRROR_COLLATERAL_EPOCH
    }

    fn declares_peer(&self, _peer_id: Bytes32) -> bool {
        true
    }

    fn owner_puzzle_hash(&self) -> Bytes32 {
        self.payout_puzzle_hash
    }
}

/// Judge a candidate whose mirror coin pays out to `payout_puzzle_hash`, and take the verdict --
/// the only way `add_entry` can be handed a payout hash at all.
fn verdict_for(payout_puzzle_hash: Bytes32) -> dig_rewards_coin::eligibility::EligiblePayoutHash {
    let question = EligibilityQuestion {
        store_launcher_id: LAUNCH_STORE_ID,
        root_hash: LAUNCH_ROOT,
        mirror_collateral_epoch: TEST_MIRROR_COLLATERAL_EPOCH,
    };
    let coin = EligibleMirrorCoin { payout_puzzle_hash };

    judge_candidate(question, Bytes32::new([0xcc; 32]), Some(&coin))
        .expect("the epoch is established")
        .expect("every eligibility check passes")
}

/// A test manager singleton with an inner puzzle of `1` -- mirrors `dig-rewards-coin`'s own
/// `TestSingleton`. The cheapest singleton that can deliver conditions; nothing here depends on
/// which inner puzzle it is.
struct TestSingleton {
    launcher_id: Bytes32,
    coin: Coin,
    proof: Proof,
    inner_puzzle_hash: Bytes32,
    puzzle: NodePtr,
}

fn launch_test_singleton(
    ctx: &mut SpendContext,
    sim: &mut Simulator,
) -> Result<TestSingleton, Box<dyn std::error::Error>> {
    let launcher_coin = sim.new_coin(SINGLETON_LAUNCHER_HASH.into(), 1);
    let launcher = Launcher::new(launcher_coin.parent_coin_info, 1);
    let launcher_id = launcher.coin().coin_id();

    let inner_puzzle = ctx.alloc(&1)?;
    let inner_puzzle_hash = ctx.tree_hash(inner_puzzle);
    let (_, coin) = launcher.spend(ctx, inner_puzzle_hash.into(), ())?;

    let puzzle = ctx.curry(SingletonArgs::new(launcher_id, inner_puzzle))?;
    let proof = Proof::Eve(EveProof {
        parent_parent_coin_info: launcher_coin.parent_coin_info,
        parent_amount: launcher_coin.amount,
    });

    Ok(TestSingleton {
        launcher_id,
        coin,
        proof,
        inner_puzzle_hash: inner_puzzle_hash.into(),
        puzzle,
    })
}

/// Deliver `output_conditions` from the manager singleton, recreating it for the next spend --
/// mirrors `dig-rewards-coin`'s own `spend_manager_singleton`.
fn spend_manager_singleton(
    ctx: &mut SpendContext,
    singleton: &TestSingleton,
    output_conditions: Conditions<NodePtr>,
) -> Result<(Coin, Proof), Box<dyn std::error::Error>> {
    let inner_puzzle = ctx.alloc(&1)?;
    let inner_puzzle_hash: Bytes32 = ctx.tree_hash(inner_puzzle).into();

    let inner_solution = output_conditions
        .create_coin(inner_puzzle_hash, 1, Memos::None)
        .to_clvm(ctx)?;
    let solution = ctx.alloc(&SingletonSolution {
        lineage_proof: singleton.proof,
        amount: 1,
        inner_solution,
    })?;

    ctx.spend(singleton.coin, Spend::new(singleton.puzzle, solution))?;

    let next_proof = Proof::Lineage(LineageProof {
        parent_parent_coin_info: singleton.coin.parent_coin_info,
        parent_inner_puzzle_hash: inner_puzzle_hash,
        parent_amount: singleton.coin.amount,
    });
    let next_coin = Coin::new(singleton.coin.coin_id(), singleton.coin.puzzle_hash, 1);

    Ok((next_coin, next_proof))
}

/// Assert a permissionless action's conditions via a zero-value checker coin -- mirrors
/// `dig-rewards-coin`'s own `ensure_conditions_met`.
fn ensure_conditions_met(
    ctx: &mut SpendContext,
    sim: &mut Simulator,
    conditions: Conditions<NodePtr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let checker_puzzle = clvm_quote!(conditions).to_clvm(ctx)?;
    let checker_coin = sim.new_coin(ctx.tree_hash(checker_puzzle).into(), 0);
    ctx.spend(checker_coin, Spend::new(checker_puzzle, NodePtr::NIL))?;
    Ok(())
}

/// As [`ensure_conditions_met`], but for the OPTIONAL `Sync` conditions an entry-set write may or
/// may not carry.
fn ensure_optional_conditions_met(
    ctx: &mut SpendContext,
    sim: &mut Simulator,
    conditions: Option<Conditions<NodePtr>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match conditions {
        Some(conditions) => ensure_conditions_met(ctx, sim, conditions),
        None => Ok(()),
    }
}

/// A real launch, funded, with one admitted entry -- everything
/// `RealClaimChainPort::submit_initiate_payout` needs to build a claim the simulator will accept.
pub struct FundedFixture {
    pub sim: Simulator,
    pub launcher_id: Bytes32,
    /// Every singleton generation's coin id, launcher first, tip last -- what `mock_chain_source`
    /// needs to build a `SingletonLineage`.
    pub singleton_members: Vec<Bytes32>,
    pub reserve_launch_id: Bytes32,
    pub reserve_parent_id: Bytes32,
    pub reserve_tip_id: Bytes32,
    pub constants: RewardDistributorConstants,
    /// The payout puzzle hash the one admitted entry was added with -- the same hash the caller
    /// passed to [`launch_funded_admitted_fixture`].
    pub payout_puzzle_hash: Bytes32,
}

/// Launches a real manager singleton and distributor, mints `COMMITTED_BASE_UNITS` into the first
/// epoch, admits ONE entry at `payout_puzzle_hash`, rolls to the next epoch, then syncs at the
/// epoch's midpoint -- so the entry has accrued something, comfortably above
/// `PAYOUT_THRESHOLD_BASE_UNITS`, entirely from real puzzle arithmetic. Mirrors
/// `dig-rewards-coin` 0.8.0's own `a_claim_built_entirely_from_a_chain_read_is_accepted` harness.
pub fn launch_funded_admitted_fixture(
    payout_puzzle_hash: Bytes32,
) -> Result<FundedFixture, Box<dyn std::error::Error>> {
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
    let mut source_cat = source_cats[0];
    sim.spend_coins(ctx.take(), std::slice::from_ref(&funder.sk))?;

    let manager = launch_test_singleton(ctx, &mut sim)?;

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
            manager_singleton_launcher_id: manager.launcher_id,
        },
        funder.puzzle_hash,
        TEST_EPOCH_SECONDS,
        u64::MAX,
        MAX_SECONDS_OFFSET,
        PAYOUT_THRESHOLD_BASE_UNITS,
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
    let mut distributor = launched.distributor;
    let first_epoch_slot = launched.first_distributor_epoch_slot;
    source_cat = launched.refund_cat;

    let reserve_launch_id = distributor.reserve.coin.coin_id();
    let reserve_parent_id = distributor.reserve.coin.parent_coin_info;

    let mut singleton_members = vec![launcher_id, distributor.coin.coin_id()];

    // Commit COMMITTED_BASE_UNITS to the first epoch.
    let secure_conditions = commit_incentives_for_distributor_epoch(
        ctx,
        &mut distributor,
        first_epoch_slot,
        FIRST_EPOCH_START,
        funder.puzzle_hash,
        COMMITTED_BASE_UNITS,
    )?;

    let hint = ctx.hint(funder.puzzle_hash)?;
    let change = source_cat.coin.amount - COMMITTED_BASE_UNITS;
    let source_cat_spend = CatSpend::new(
        source_cat,
        StandardLayer::new(funder.pk).spend_with_conditions(
            ctx,
            secure_conditions.create_coin(funder.puzzle_hash, change, hint),
        )?,
    );

    let reward_slots: Vec<_> = distributor
        .pending_spend
        .created_reward_slots
        .iter()
        .map(|value| {
            distributor.created_slot_value_to_slot(*value, RewardDistributorSlotNonce::REWARD)
        })
        .collect();

    distributor = distributor
        .clone()
        .finish_spend(ctx, vec![source_cat_spend])?
        .0;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&funder.sk))?;
    singleton_members.push(distributor.coin.coin_id());

    // Admit one entry at `payout_puzzle_hash`.
    let authority = ManagerAuthority::new(manager.inner_puzzle_hash)?;
    let write = add_entry(
        ctx,
        &mut distributor,
        authority,
        verdict_for(payout_puzzle_hash),
        0,
    )?;
    distributor = distributor.clone().finish_spend(ctx, vec![])?.0;
    ensure_optional_conditions_met(ctx, &mut sim, write.sync_conditions)?;
    // The manager singleton's post-AddEntry generation is never spent again by this fixture, so
    // its returned coin/proof are discarded rather than threaded into an unused `mut` binding.
    let (_next_manager_coin, _next_manager_proof) =
        spend_manager_singleton(ctx, &manager, write.manager_conditions)?;
    sim.spend_coins(ctx.take(), &[])?;
    singleton_members.push(distributor.coin.coin_id());

    // Two more generations past AddEntry: roll to the next epoch, then sync at its midpoint --
    // the entry slot the claim later spends was created several generations before the tip.
    sim.set_next_timestamp(FIRST_EPOCH_START)?;
    let first_reward_slot: Slot<RewardDistributorRewardSlotValue> = reward_slots
        .into_iter()
        .find(|slot| slot.info.value.epoch_start == FIRST_EPOCH_START)
        .expect("a reward slot for the first epoch");
    let roll = start_next_distributor_epoch(ctx, &mut distributor, first_reward_slot)?;
    ensure_conditions_met(ctx, &mut sim, roll.conditions)?;
    distributor = distributor.clone().finish_spend(ctx, vec![])?.0;
    sim.spend_coins(ctx.take(), &[])?;
    singleton_members.push(distributor.coin.coin_id());

    let sync_time = FIRST_EPOCH_START + TEST_EPOCH_SECONDS / 2;
    sim.set_next_timestamp(sync_time)?;
    let sync_conditions = sync_distributor(ctx, &mut distributor, sync_time)?;
    ensure_conditions_met(ctx, &mut sim, sync_conditions)?;
    distributor = distributor.clone().finish_spend(ctx, vec![])?.0;
    sim.spend_coins(ctx.take(), &[])?;
    singleton_members.push(distributor.coin.coin_id());

    let reserve_tip_id = distributor.reserve.coin.coin_id();

    Ok(FundedFixture {
        sim,
        launcher_id,
        singleton_members,
        reserve_launch_id,
        reserve_parent_id,
        reserve_tip_id,
        constants: distributor.info.constants,
        payout_puzzle_hash,
    })
}

/// Builds a `MockChainSource` over `fixture`'s real, multi-generation simulator state -- the
/// general form `mock_chain_source` above cannot serve, since a funded/admitted fixture has more
/// than one post-launch generation. Mirrors `dig-rewards-coin`'s own `mock_chain_source` (the
/// general `sim`/`singleton_members`/`extra_coin_ids` form, `tests/simulator.rs`).
pub fn mock_chain_source_for_funded_fixture(fixture: &FundedFixture) -> MockChainSource {
    let eve_coin_id = fixture
        .sim
        .children(fixture.launcher_id)
        .first()
        .map(|state| state.coin.coin_id());

    let extra_ids = [
        fixture.reserve_launch_id,
        fixture.reserve_parent_id,
        fixture.reserve_tip_id,
    ];

    let mut source = MockChainSource::new();
    for id in fixture
        .singleton_members
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

    let tip = *fixture
        .singleton_members
        .last()
        .expect("a singleton chain always has at least the launcher");
    source = source.with_lineage(
        fixture.launcher_id,
        SingletonLineage::new(tip, fixture.singleton_members.iter().copied()),
    );

    let peak = fixture.sim.height();
    for height in 0..=peak {
        source = source.with_timestamp(height, u64::from(height) * 1_000 + 1);
    }
    source.with_peak(peak)
}
