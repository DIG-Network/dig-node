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
//! decoding its memos, asserted below against the exact values this test launched with.
//!
//! One caveat on that claim: the asserted `store_id`/`root` (`[0xaa; 32]`, `[0xbb; 32]`) are
//! test-chosen low-entropy constants. They are unguessable-by-accident TODAY only because no
//! rival code path in this file could produce them — not because of any entropy in the fixture
//! itself. That is true of this test as written; it is not a structural guarantee, and would stop
//! being true the moment a second source of those fields is added here.

mod common;

use std::sync::Arc;

use dig_chainsource_interface::MockChainSource;
use dig_node_core::rewards::port::RewardsChainPort;
use dig_node_core::Node;
use dig_node_service::rewards::RealRewardsChainPort;
use dig_rewards_coin::constants::{PAYOUT_THRESHOLD_BASE_UNITS, WITHDRAWAL_SHARE_BPS};

use common::rewards_fixture::{
    launch_fixture, mock_chain_source, FIRST_EPOCH_START, TEST_EPOCH_SECONDS,
};

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

    let second_install = node.install_reward_chain_port(Arc::clone(&port));
    assert!(!second_install, "the second install must be refused");

    // R2 (dig_ecosystem#3310 gate leg 3, remedy R2): this test must not capture and assert
    // against a warn it emits ITSELF -- that is self-certifying (deleting `server.rs`'s real
    // warn would leave this test green, proving nothing about the production call site).
    // Instead it reads `server.rs`'s own shipped source and checks the warn string this
    // refusal is supposed to surface actually lives there, in the non-test region -- the same
    // shape `adapter_source_never_imports_withdraw_committed_incentives` already uses in
    // `chain_port.rs`. Mutation-proved: deleting `server.rs`'s warn line turns this assertion
    // red; restoring it turns it green again (see the PR description's RED/GREEN observation).
    //
    // NOTE this is a SOURCE-TEXT assertion, not a behavioural one: it proves the warn string is
    // written in `server.rs`, not that it is actually emitted when the second `if` branch runs at
    // runtime. A behavioural assertion (capturing tracing output from the real call site) is not
    // reachable here without either restructuring `server.rs`'s install block to be independently
    // callable from an integration test, or duplicating production control flow into the test --
    // both are new production surface this ticket does not need. Read this test as "the warn this
    // refusal depends on has not silently rotted out of the source", not as proof the call site
    // fires it on every run.
    let server_source = production_region(include_str!("../src/server.rs"));
    assert!(
        server_source.contains("declined a second install"),
        "server.rs's production install-path warn must contain \"declined a second install\", \
         so this refused-install path is not silently unlogged"
    );
}

/// The slice of a source file before its own `#[cfg(test)]` module -- i.e. what actually ships.
/// Mirrors `chain_port.rs`'s identical helper; duplicated here because this integration test is
/// a separate compilation unit and cannot import a private `#[cfg(test)]` helper from the crate
/// under test.
fn production_region(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(test_module_start) => &source[..test_module_start],
        None => source,
    }
}
