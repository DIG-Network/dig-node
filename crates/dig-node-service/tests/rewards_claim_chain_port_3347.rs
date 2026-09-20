//! DIG-Network/dig_ecosystem#3347 acceptance: `RealClaimChainPort` — the real claim-side adapter,
//! over the SAME real, decodable simulator launch `rewards_chain_port_a3.rs` uses (shared via
//! `tests/common/rewards_fixture.rs`).
//!
//! # What this proves, and what it does not
//!
//! Discovery (through an untrusted [`LauncherIndex`]), `reserve_asset_id`, and `payout_threshold`
//! are all real reads, proven end to end against a real launch. `own_entry` for an unknown payout
//! puzzle hash correctly reads `Ok(None)` (there is no entry keyed to a hash this fixture never
//! launched with). The accrued-amount and submit paths are proven separately, against a funded,
//! admitted distributor -- see this file's own DIG-Network/dig_ecosystem#3347 tests below.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::Bytes32;
use chia_puzzle_types::cat::CatArgs;
use dig_chainsource_interface::MockChainSource;
use dig_node_service::rewards_claim::{
    run_claim_driver_in, ClaimChainPort, ClaimLoopHandle, ClaimLoopState, ClaimPortError,
    LauncherIndex, RealClaimChainPort, RewardsClaimConfig,
};
use dig_rewards_coin::constants::PAYOUT_THRESHOLD_BASE_UNITS;
use dig_wallet::sage::spend::MockBroadcaster;

use common::rewards_fixture::{
    launch_fixture, launch_funded_admitted_fixture, mock_chain_source,
    mock_chain_source_for_funded_fixture,
};

/// An index that proposes exactly the ids it is built with -- no re-verification of its own; that
/// is `RealClaimChainPort::discover_distributors`'s job, which this file's tests exercise.
struct FixtureLauncherIndex(Vec<Bytes32>);

#[async_trait]
impl LauncherIndex for FixtureLauncherIndex {
    async fn launcher_ids(&self) -> Result<Vec<Bytes32>, ClaimPortError> {
        Ok(self.0.clone())
    }
}

/// The real launcher id discovers with the fixture's own `store_id`/`root` -- proving the SAME
/// memo-decode path `rewards_chain_port_a3.rs` proves for the funder-side adapter, now for the
/// claim-side one.
#[tokio::test(flavor = "multi_thread")]
async fn discover_distributors_returns_exactly_the_real_launch() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );

    let discovered = port
        .discover_distributors()
        .await
        .expect("a real launched distributor must discover");

    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].launcher_id, fixture.launcher_id);
    assert_eq!(discovered[0].store_id, fixture.launch_comment.store_id);
    assert_eq!(discovered[0].root, fixture.launch_comment.root);
}

/// SPEC 13.1 clause 2: an index only PROPOSES. A bogus id mixed in with the real one must be
/// dropped, silently, by discovery's own re-verification -- never echoed back and never an error
/// for the whole batch.
#[tokio::test(flavor = "multi_thread")]
async fn a_bogus_index_entry_is_dropped_not_echoed() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let bogus_id = Bytes32::from([0xEE; 32]);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![bogus_id, fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );

    let discovered = port
        .discover_distributors()
        .await
        .expect("a bogus id must be dropped, not fail the whole discovery");

    assert_eq!(
        discovered.len(),
        1,
        "an index lie must yield nothing for that id, and never overrule the real one"
    );
    assert_eq!(discovered[0].launcher_id, fixture.launcher_id);
}

/// `reserve_asset_id` and `payout_threshold` are real chain-curried reads, not the crate's own
/// default-launch literal -- both read from the fixture's OWN launched constants.
#[tokio::test(flavor = "multi_thread")]
async fn reserve_asset_id_and_payout_threshold_are_read_from_chain() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );

    let reserve_asset_id = port
        .reserve_asset_id(fixture.launcher_id)
        .await
        .expect("a real launched distributor's reserve asset id must read");
    assert_eq!(
        reserve_asset_id, fixture.constants.reserve_asset_id,
        "must be the fixture's OWN minted CAT asset id, not any literal"
    );

    let payout_threshold = port
        .payout_threshold(fixture.launcher_id)
        .await
        .expect("a real launched distributor's payout threshold must read");
    assert_eq!(
        payout_threshold, fixture.constants.payout_threshold,
        "must be the chain-curried value the fixture launched with (deliberately NOT \
         PAYOUT_THRESHOLD_BASE_UNITS, the default -- see rewards_fixture.rs), read via \
         dig_rewards_coin::payout::payout_threshold_base_units, never a literal"
    );
    assert_ne!(
        payout_threshold, PAYOUT_THRESHOLD_BASE_UNITS,
        "the fixture must diverge from the default, or a port that ignored the chain and \
         returned the default constant would read as correct by coincidence"
    );
}

/// `own_entry` for a payout puzzle hash this fixture never launched with reads `Ok(None)` --
/// "no entry", never a fabricated one and never an error.
#[tokio::test(flavor = "multi_thread")]
async fn own_entry_reads_none_for_an_unknown_payout_puzzle_hash() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );

    let entry = port
        .own_entry(fixture.launcher_id, Bytes32::from([0x42; 32]))
        .await
        .expect("a bare launch with no matching entry must read Ok(None), not an error");
    assert_eq!(entry, None);
}

/// The production adapter names itself -- never inherits `UnavailableClaimChainPort`'s name.
#[tokio::test(flavor = "multi_thread")]
async fn kind_names_the_real_adapter() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );
    assert_eq!(port.kind(), "real-corroborated");
}

/// A source that fails outright must surface `ClaimPortError::Unavailable` from every method,
/// never a silent empty answer that would misreport "the chain has nothing" instead of "the chain
/// could not be read".
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_source_reports_unavailable_everywhere() {
    let source =
        MockChainSource::new().fail_with(dig_chainsource_interface::ChainSourceError::Transport(
            "simulated transport failure".into(),
        ));
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![]),
        Arc::new(MockBroadcaster::default()),
    );

    let launcher_id = Bytes32::from([1u8; 32]);
    assert_eq!(
        port.reserve_asset_id(launcher_id).await,
        Err(ClaimPortError::Unavailable)
    );
    assert_eq!(
        port.payout_threshold(launcher_id).await,
        Err(ClaimPortError::Unavailable)
    );
    assert_eq!(
        port.own_entry(launcher_id, Bytes32::from([2u8; 32])).await,
        Err(ClaimPortError::Unavailable)
    );
    assert_eq!(
        port.resolve_launch_comment(launcher_id).await,
        Err(ClaimPortError::Unavailable)
    );
}

/// The 3347 acceptance proof itself: driving the REAL production body
/// (`run_claim_driver_in`, the same function [`dig_node_service::rewards_claim::spawn_claim_driver_from_config`]
/// spawns in production) with a real `RealClaimChainPort` over the fixture's real launch reaches
/// an actual chain read -- not `ClaimLoopState::ChainSourceUnavailable`, and it actually discovers
/// the one real distributor and its one (entry-less) cycle outcome. This is the one test in this
/// file that proves the WIRING, not just the adapter in isolation.
#[tokio::test(start_paused = true)]
async fn a_driven_cycle_over_the_real_adapter_reaches_a_real_chain_read() {
    let fixture = launch_fixture().expect("a real distributor launches cleanly in the simulator");
    let source = mock_chain_source(&fixture);
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        Arc::new(MockBroadcaster::default()),
    );

    let state_dir_guard = tempfile::tempdir().expect("a temp state dir");
    let state_dir = state_dir_guard.path().to_path_buf();
    let cfg = RewardsClaimConfig {
        enabled: true,
        cadence_seconds: 3_600,
        jitter_seconds: 0,
        ..RewardsClaimConfig::default()
    };
    cfg.save_to(&state_dir)
        .expect("the config must save before the driver reads it");

    let handle = ClaimLoopHandle::default();
    let handle_for_task = handle.clone();
    let own_payout_puzzle_hash = Bytes32::from([0x42; 32]);

    tokio::spawn(async move {
        run_claim_driver_in(
            &state_dir,
            own_payout_puzzle_hash,
            dig_mirror_coin::DIG_ASSET_ID,
            port,
            handle_for_task,
        )
        .await;
    });

    // Let the spawned task run far enough to register its first `sleep` BEFORE advancing the
    // virtual clock -- `tokio::time::advance` only fires timers already registered.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    // The driver's first pass sleeps `cadence_seconds + jitter` before running its first cycle
    // (see `driver.rs`'s own `drive` doc) -- jitter is pinned to 0 above, so this is exact.
    tokio::time::advance(std::time::Duration::from_secs(3_600)).await;
    // Let the woken task actually run its cycle (real chain reads go through
    // `tokio::task::spawn_blocking`, which runs on a real OS thread unaffected by the paused
    // virtual clock) before reading the handle back.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    let status = handle.status();
    // Per `rewards_chain_port_a3.rs`'s own module doc: this fixture's reserve asset is the
    // SIMULATOR's own freshly minted CAT, never the real (unmintable-in-a-simulator)
    // `dig_mirror_coin::DIG_ASSET_ID` -- this call passes that real asset id (the same value
    // `run_claim_driver` passes in production, since #3347's U3), so
    // the engine correctly reads this real distributor, sees its asset does not match, and drops
    // it as `NotOurs` (SPEC 9.3) BEFORE the entry-slot read -- it is never faulted, never
    // read as chain-unavailable, and never fabricated as claimable. That is still real proof the
    // production body reached a real chain read through `RealClaimChainPort`: a fabricated,
    // no-adapter or wrongly-wired path could not produce "discovered exactly one, asset mismatch,
    // cycle completed cleanly" -- it would read either zero known or chain-unavailable instead.
    assert_ne!(
        status.state,
        ClaimLoopState::ChainSourceUnavailable,
        "a real, launched fixture must not be read as chain-unavailable"
    );
    assert_eq!(
        status.distributors_known, 1,
        "discovery must find the one real distributor this fixture launched"
    );
    assert!(
        !status.fault_reported,
        "a real asset-id mismatch is a clean NotOurs drop, never a fault"
    );
    assert!(
        status.last_cycle_at.is_some(),
        "a cycle must have actually completed, not merely been scheduled"
    );
}

/// The 3347 closure proof at the adapter level: `submit_initiate_payout` over a real, funded,
/// admitted distributor builds a bundle the SIMULATOR actually accepts (never merely well-formed),
/// and the entry's own accrued figure -- read via `own_entry` -- is what the simulator pays out.
/// Ported from `dig-rewards-coin` 0.8.0's own
/// `tests/simulator.rs::a_claim_built_entirely_from_a_chain_read_is_accepted`, with the production
/// `RealClaimChainPort` (built with a `MockBroadcaster`) standing in for that test's hand-rolled
/// `initiate_payout` + `finish_spend` + `spend_coins` call sequence.
#[tokio::test(flavor = "multi_thread")]
async fn submit_initiate_payout_builds_a_bundle_the_simulator_accepts_and_pays_the_entry() {
    let payout_puzzle_hash = Bytes32::from([0x77; 32]);
    let mut fixture = launch_funded_admitted_fixture(payout_puzzle_hash)
        .expect("a funded, admitted distributor launches cleanly in the simulator");
    let source = mock_chain_source_for_funded_fixture(&fixture);
    let broadcaster = Arc::new(MockBroadcaster::default());
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        broadcaster.clone(),
    );

    assert_eq!(
        fixture.payout_puzzle_hash, payout_puzzle_hash,
        "the fixture must have admitted the same payout puzzle hash this test drives against"
    );

    let entry = port
        .own_entry(fixture.launcher_id, payout_puzzle_hash)
        .await
        .expect("the admitted entry must read")
        .expect("the fixture admitted exactly this payout puzzle hash");
    assert!(
        entry.accrued_base_units > 0,
        "half an epoch with one entry must have accrued something"
    );
    assert!(
        entry.accrued_base_units >= fixture.constants.payout_threshold,
        "the fixture must fund enough that the entry clears its own launched threshold"
    );

    port.submit_initiate_payout(fixture.launcher_id, payout_puzzle_hash, 0)
        .await
        .expect("a real accrued entry, submitted with zero fee, must build and broadcast");

    // Fee refused -- `required_fee_mojos` is 0 for this adapter and it has nowhere to pay one from.
    let fee_refusal = port
        .submit_initiate_payout(fixture.launcher_id, payout_puzzle_hash, 1)
        .await;
    assert!(
        matches!(fee_refusal, Err(ClaimPortError::Other(_))),
        "a non-zero fee must be refused by name, never silently dropped or paid"
    );

    let sent = broadcaster.sent.lock().expect("the broadcaster's own lock");
    assert_eq!(
        sent.len(),
        1,
        "exactly one bundle must have been broadcast -- the fee-refused call must never reach \
         the broadcaster"
    );
    let bundle = sent[0].clone();
    drop(sent);

    // The assertion the whole test exists for: a bundle built by the PRODUCTION adapter is
    // actually ACCEPTED by the simulator, never merely well-formed.
    fixture
        .sim
        .spend_coins(bundle.coin_spends.clone(), &[])
        .expect("the production adapter's bundle must be accepted by the simulator");

    let reserve_asset_id = fixture.constants.reserve_asset_id;
    let payee_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(reserve_asset_id, payout_puzzle_hash.into()).into();
    let children = fixture.sim.children(fixture.reserve_tip_id);
    let payee_coins: Vec<_> = children
        .iter()
        .filter(|state| state.coin.puzzle_hash == payee_puzzle_hash)
        .collect();
    assert_eq!(
        payee_coins.len(),
        1,
        "exactly one payee CAT coin must exist on chain at the entry's payout puzzle hash"
    );
    assert_eq!(
        payee_coins[0].coin.amount, entry.accrued_base_units,
        "the payee's on-chain CAT coin amount must equal the entry's own accrued figure"
    );
}

/// DIG-Network/dig_ecosystem#3347's CLOSURE ARTIFACT: drives the whole PRODUCTION BODY
/// (`run_claim_driver_in`, the same function `run_claim_driver` calls in production, over a real
/// `RealClaimChainPort`) against a real, funded, admitted distributor -- and asserts the payout
/// coin the simulator actually accepted, not merely `cycles_driven()`. Where
/// `a_driven_cycle_over_the_real_adapter_reaches_a_real_chain_read` above stops at a clean
/// `NotOurs` (asset mismatch) and
/// `submit_initiate_payout_builds_a_bundle_the_simulator_accepts_and_pays_the_entry` drives the
/// adapter directly, this test is the two combined: the production loop itself finds the entry,
/// builds and broadcasts the spend, and the simulator pays this peer.
#[tokio::test(start_paused = true)]
async fn a_driven_cycle_over_a_funded_admitted_distributor_pays_this_peer() {
    let payout_puzzle_hash = Bytes32::from([0x99; 32]);
    let mut fixture = launch_funded_admitted_fixture(payout_puzzle_hash)
        .expect("a funded, admitted distributor launches cleanly in the simulator");
    let source = mock_chain_source_for_funded_fixture(&fixture);
    let broadcaster = Arc::new(MockBroadcaster::default());
    let port = RealClaimChainPort::new(
        Arc::new(source),
        FixtureLauncherIndex(vec![fixture.launcher_id]),
        broadcaster.clone(),
    );

    // Read the entry's own accrued figure directly through the adapter, BEFORE handing `port` to
    // the driver -- this is the figure the driven cycle below must actually pay, independent of
    // whatever the engine does with it.
    let expected_accrued = port
        .own_entry(fixture.launcher_id, payout_puzzle_hash)
        .await
        .expect("the admitted entry must read")
        .expect("the fixture admitted exactly this payout puzzle hash")
        .accrued_base_units;
    assert!(
        expected_accrued > 0,
        "half an epoch with one entry must have accrued something"
    );

    let discovered = port
        .discover_distributors()
        .await
        .expect("discovery must not error");
    assert_eq!(
        discovered.len(),
        1,
        "discovery must find the one real distributor this fixture launched"
    );

    let state_dir_guard = tempfile::tempdir().expect("a temp state dir");
    let state_dir = state_dir_guard.path().to_path_buf();
    let cfg = RewardsClaimConfig {
        enabled: true,
        cadence_seconds: 3_600,
        jitter_seconds: 0,
        ..RewardsClaimConfig::default()
    };
    cfg.save_to(&state_dir)
        .expect("the config must save before the driver reads it");

    let handle = ClaimLoopHandle::default();
    let handle_for_task = handle.clone();
    let reserve_asset_id = fixture.constants.reserve_asset_id;

    tokio::spawn(async move {
        run_claim_driver_in(
            &state_dir,
            payout_puzzle_hash,
            reserve_asset_id,
            port,
            handle_for_task,
        )
        .await;
    });

    // Same settle pattern as `a_driven_cycle_over_the_real_adapter_reaches_a_real_chain_read`:
    // reach the driver's first `sleep` before advancing, then let the real chain read (a
    // `spawn_blocking`, unaffected by the paused virtual clock) actually complete.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(std::time::Duration::from_secs(3_600)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }

    let status = handle.status();
    assert_ne!(
        status.state,
        ClaimLoopState::ChainSourceUnavailable,
        "a real, funded, admitted distributor must not be read as chain-unavailable"
    );
    assert_eq!(
        status.claims_submitted, 1,
        "one cadence over one admitted, thresholded entry must submit exactly one claim"
    );
    assert_eq!(
        status.distributors_claimable, 1,
        "the one real distributor, with its entry cleared for payout, must count as claimable"
    );
    assert!(
        !status.fault_reported,
        "a real, correctly-built submission must never be reported as a fault"
    );

    let sent = broadcaster.sent.lock().expect("the broadcaster's own lock");
    assert_eq!(
        sent.len(),
        1,
        "the production driver must have broadcast exactly one bundle"
    );
    let bundle = sent[0].clone();
    drop(sent);

    fixture
        .sim
        .spend_coins(bundle.coin_spends.clone(), &[])
        .expect("the bundle the production driver broadcast must be accepted by the simulator");

    let payee_puzzle_hash: Bytes32 =
        CatArgs::curry_tree_hash(reserve_asset_id, payout_puzzle_hash.into()).into();
    let children = fixture.sim.children(fixture.reserve_tip_id);
    let payee_coins: Vec<_> = children
        .iter()
        .filter(|state| state.coin.puzzle_hash == payee_puzzle_hash)
        .collect();
    assert_eq!(
        payee_coins.len(),
        1,
        "exactly one payee CAT coin must exist on chain at this peer's payout puzzle hash"
    );
    assert_eq!(
        payee_coins[0].coin.amount, expected_accrued,
        "the payee's on-chain CAT coin amount must equal the entry's own accrued figure"
    );
}
