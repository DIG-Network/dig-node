//! DIG-Network/dig_ecosystem#3347 acceptance: `RealClaimChainPort` — the real claim-side adapter,
//! over the SAME real, decodable simulator launch `rewards_chain_port_a3.rs` uses (shared via
//! `tests/common/rewards_fixture.rs`).
//!
//! # What this proves, and what it does not
//!
//! Discovery (through an untrusted [`LauncherIndex`]), `reserve_asset_id`, and `payout_threshold`
//! are all real reads, proven end to end against a real launch. `own_entry` for an unknown payout
//! puzzle hash correctly reads `Ok(None)` (there is no entry keyed to a hash this fixture never
//! launched with). This file does NOT prove the accrued-amount or submit paths -- see
//! `chain_port.rs`'s own module doc for why both are structurally blocked on
//! DIG-Network/dig_ecosystem#3356 on `dig-rewards-coin` 0.7.0, and refuse by name rather than
//! guessing.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use chia_protocol::Bytes32;
use dig_chainsource_interface::MockChainSource;
use dig_node_service::rewards_claim::{
    ClaimChainPort, ClaimPortError, LauncherIndex, RealClaimChainPort,
};
use dig_rewards_coin::constants::PAYOUT_THRESHOLD_BASE_UNITS;

use common::rewards_fixture::{launch_fixture, mock_chain_source};

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
        payout_threshold, PAYOUT_THRESHOLD_BASE_UNITS,
        "must be the chain-curried value the fixture launched with, read via \
         dig_rewards_coin::payout::payout_threshold_base_units, never a literal"
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
    let port = RealClaimChainPort::new(Arc::new(source), FixtureLauncherIndex(vec![]));

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
