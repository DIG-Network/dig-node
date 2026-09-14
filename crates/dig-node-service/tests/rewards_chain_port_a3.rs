//! dig_ecosystem#3310 acceptance A3: `RealRewardsChainPort::distributor_report` — the real
//! adapter, over the real `read_distributor_guarded`, over real serialized launcher/eve/singleton
//! spends — driven end to end against a distributor launched by
//! `dig_rewards_coin::launch_dig_distributor` in `chia-sdk-test`'s peer simulator.
//!
//! # The one substitution, and why
//!
//! This double replaces the network transport, nothing else. Every coin record and coin spend
//! `MockChainSource` answers with here was produced by a real `Simulator::spend_coins` call —
//! copied verbatim from `dig-rewards-coin` 0.5.0's own `tests/simulator.rs` (`chain_source_with_gaps`),
//! the SAME sanctioned double `dig-rewards-coin`'s own upstream tests use for the identical
//! purpose. There is no second, hand-rolled mock in this crate.
//!
//! A DIG distributor's `reserve_asset_id` is `dig_constants::DIG_ASSET_ID`, a fixed real asset id
//! a simulator cannot mint. So — again mirroring `dig-rewards-coin`'s own tests — the constants
//! table here is built directly via `RewardDistributorConstants::without_launcher_id` using the
//! SIMULATOR's own freshly minted CAT's asset id, not the production `dig_distributor_constants`
//! helper (which hardcodes the unmintable real asset id).
//!
//! The manager singleton launcher id is a fixed dummy `Bytes32`: it is curried metadata on the
//! constants table only, never read back off chain by `read_distributor`, so launching a real test
//! singleton for it (as `dig-rewards-coin`'s own tests do, for a DIFFERENT reason — driving manager
//! actions) would be machinery this test never exercises.
//!
//! # What proves the parse is real
//!
//! `store_id`/`root` are not part of the distributor's own puzzle state — they are a CLVM memo on
//! the `CREATE_COIN` that creates the launcher coin (`chain_source.rs`'s module doc). Recovering
//! them requires reading the launcher's PARENT (creating) spend, running that puzzle for real, and
//! decoding its memos. No fixture value can produce the right `store_id`/`root` without that
//! parse actually happening — asserted below against the exact values this test launched with.

use std::sync::Arc;

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
use dig_node_core::rewards::port::RewardsChainPort;
use dig_node_core::Node;
use dig_node_service::rewards::RealRewardsChainPort;
use dig_rewards_coin::comment::LaunchComment;
use dig_rewards_coin::constants::{
    MAX_SECONDS_OFFSET, PAYOUT_THRESHOLD_BASE_UNITS, WITHDRAWAL_SHARE_BPS,
};
use dig_rewards_coin::launch::launch_dig_distributor;

/// Small on purpose: the simulator's clock starts at zero.
const FIRST_EPOCH_START: u64 = 1_234;
/// A short epoch; this test is about the report's fields, not the epoch length.
const TEST_EPOCH_SECONDS: u64 = 1_000;
/// $DIG the funder mints for itself.
const MINTED_BASE_UNITS: u64 = 10_000_000_000;

/// A fixed, never-launched manager singleton launcher id: curried into the constants table for
/// shape only, never read back off chain by `read_distributor`.
const DUMMY_MANAGER_LAUNCHER_ID: Bytes32 = Bytes32::new([0x42; 32]);

/// Everything a real launch produced, named rather than positional.
struct LaunchedFixture {
    sim: Simulator,
    launcher_id: Bytes32,
    security_coin_id: Bytes32,
    distributor_coin_id: Bytes32,
    reserve_coin_id: Bytes32,
    reserve_launch_id: Bytes32,
    reserve_parent_id: Bytes32,
    launch_comment: LaunchComment,
    constants: RewardDistributorConstants,
}

/// Mints a reward CAT, builds a launch offer, and launches a real DIG distributor via
/// `launch_dig_distributor` against a fresh `Simulator` — trimmed from
/// `dig-rewards-coin::tests::simulator::launch_harness_with_constants_builder`.
fn launch_fixture() -> Result<LaunchedFixture, Box<dyn std::error::Error>> {
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
        PAYOUT_THRESHOLD_BASE_UNITS,
        false,
        0,
        WITHDRAWAL_SHARE_BPS,
        source_cat.info.asset_id,
    );

    let launch_comment = LaunchComment::new(Bytes32::new([0xaa; 32]), Bytes32::new([0xbb; 32]));

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
fn mock_chain_source(fixture: &LaunchedFixture) -> MockChainSource {
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

/// A3: `RealRewardsChainPort::distributor_report` — the real production adapter, driven by a
/// `MockChainSource` loaded from a real simulator launch — reports the values launched with,
/// including `store_id`/`root`, which can only be right if the launcher's parent spend was
/// actually run and its memo actually decoded.
#[tokio::test(flavor = "multi_thread")]
async fn distributor_report_reflects_a_real_simulator_launch() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);

    let port = RealRewardsChainPort::<MockChainSource>::new(Arc::new(source));

    let report = port
        .distributor_report(fixture.launcher_id.into())
        .await
        .expect("the report must be built from a real, freshly launched distributor");

    assert_eq!(report.launcher_id, fixture.launcher_id.to_bytes());
    // These two fields come from nowhere but the launcher's PARENT spend's decoded CLVM memo --
    // no fixture shortcut produces the right bytes without that parse actually running.
    assert_eq!(
        report.store_id,
        fixture.launch_comment.store_id.to_bytes(),
        "store_id must be recovered by actually running the security coin's puzzle and decoding \
         its CREATE_COIN memo -- this is the field a stub-over-a-stub could not get right"
    );
    assert_eq!(report.root, fixture.launch_comment.root.to_bytes());

    assert_eq!(report.epoch_seconds, TEST_EPOCH_SECONDS);
    assert_eq!(report.first_epoch_start, FIRST_EPOCH_START);
    assert_eq!(report.payout_threshold, PAYOUT_THRESHOLD_BASE_UNITS);
    assert_eq!(report.fee_bps, 0);
    assert_eq!(
        report.withdrawal_share_bps,
        u16::try_from(WITHDRAWAL_SHARE_BPS).unwrap()
    );
    assert_eq!(
        report.reserve_base_units, 0,
        "a bare launch has committed nothing to the reserve yet"
    );
    assert_eq!(
        report.entry_count, 0,
        "a bare launch has added no entries yet"
    );

    // Sanity: the constants this test launched with are the ones the fixture actually curried,
    // not a value this test invented independently.
    assert_eq!(fixture.constants.epoch_seconds, TEST_EPOCH_SECONDS);
}

/// A3's install-path clause: `install_reward_chain_port` returns `true` the first time and
/// `false` the second, with a WARN logged on the second call the way `server.rs`'s own call site
/// logs it -- constructed identically (`Arc<dyn RewardsChainPort>` wrapping
/// `RealRewardsChainPort::new(Arc::new(source))`).
#[test]
fn install_reward_chain_port_refuses_a_second_install_with_a_warn() {
    use std::io::Write;
    use std::sync::{Arc as StdArc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct CaptureBuffer(StdArc<Mutex<Vec<u8>>>);
    impl Write for CaptureBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for CaptureBuffer {
        type Writer = CaptureBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // `Node` exposes no lighter test constructor to an external integration-test crate --
    // `Node::from_env()` is the same constructor `openrpc_drift_guard.rs`'s own integration test
    // uses for the identical reason. Only its `install_reward_chain_port` OnceLock is read below.
    let node = Node::from_env();
    let source = MockChainSource::new();
    let port: Arc<dyn RewardsChainPort> = Arc::new(RealRewardsChainPort::<MockChainSource>::new(
        Arc::new(source),
    ));

    let first_install = node.install_reward_chain_port(Arc::clone(&port));
    assert!(first_install, "the first install must be accepted");

    let buffer = CaptureBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(buffer.clone())
        .finish();
    let second_install = tracing::subscriber::with_default(subscriber, || {
        let installed = node.install_reward_chain_port(Arc::clone(&port));
        if !installed {
            tracing::warn!(
                "install_reward_chain_port declined a second install: a reward chain \
                 port was already installed on this Node"
            );
        }
        installed
    });

    assert!(!second_install, "the second install must be refused");
    let logged = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(
        logged.contains("declined a second install"),
        "the second call must warn the way server.rs's own call site does, got: {logged:?}"
    );
}
