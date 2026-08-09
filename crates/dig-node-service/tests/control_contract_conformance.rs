//! The node's control surface against the PUBLISHED contract (dig_ecosystem#2376).
//!
//! `dig-node-control-interface` is the one published catalog: dig-node SERVES it and every consumer
//! CONFORMS to it. Nothing enforced that until this file — the node kept its own string constants
//! and the crate kept its own enum, so the two could disagree indefinitely and a consumer would be
//! the one to find out. These tests are the lockstep.
//!
//! The dependency is TEST-only on purpose: the node's `CONTROL_METHODS` remains the runtime source
//! of truth, and this pins it rather than replacing it.

use std::collections::BTreeSet;

use dig_node_control_interface::method::{Category, ControlMethod};
use dig_node_control_interface::params::WalletCoinByIdParams;
use dig_node_service::control::{
    is_open_control_read, wallet_coin_id_param_for_test, CONTROL_METHODS,
};
use serde_json::json;

/// Drift that PREDATES this gate, found by it on its first run (dig_ecosystem#2376).
///
/// Listed rather than silently tolerated, and listed EXPLICITLY rather than by a category filter,
/// so the set can only shrink: a newly-drifted method is not in here and fails the test. Closing
/// these is dig_ecosystem#2381's, not this ticket's — they are unrelated to the wallet surface and
/// fixing them blind would be a change nobody reviewed.
const KNOWN_PREEXISTING_DRIFT: &[&str] = &["control.peers.disconnect"];

/// Methods this node SERVES that the published contract does not declare (dig_ecosystem#2392).
///
/// Same shape and same reason as [`KNOWN_PREEXISTING_DRIFT`], in the opposite direction: listed
/// explicitly so the set can only shrink, and publishing them is its own reviewed change rather
/// than something this gate does blind.
const KNOWN_UNPUBLISHED: &[&str] = &["control.peers.ping"];

/// **Every `control.*` method the contract publishes is actually served.**
///
/// A published method the node does not resolve is worse than an absent one: a client reads the
/// catalog, calls it, and gets `METHOD_NOT_FOUND` from a node that claims to implement the contract.
#[test]
fn the_node_serves_every_control_method_the_contract_publishes() {
    let served: BTreeSet<&str> = CONTROL_METHODS.iter().copied().collect();
    let published: BTreeSet<&str> = ControlMethod::ALL
        .iter()
        .filter(|m| m.name().starts_with("control."))
        .map(|m| m.name())
        .collect();

    let missing: Vec<&str> = published
        .difference(&served)
        .copied()
        .filter(|m| !KNOWN_PREEXISTING_DRIFT.contains(m))
        .collect();
    assert!(
        missing.is_empty(),
        "the contract publishes methods this node does not serve: {missing:?}"
    );
}

/// **Every `control.*` method this node serves is one the contract publishes.**
///
/// The converse of the test above, and its absence is what let `control.wallet.coinById` ship
/// against a contract that had never declared it (dig_ecosystem#2392). Every assertion in this
/// file iterates the CONTRACT, so a method the pinned version does not know is not tested loosely
/// -- it is not tested at all, and the suite goes green having checked nothing about it. That is
/// invisible in a way the other direction is not: a published-but-unserved method breaks a client
/// loudly, while a served-but-unpublished one just means no consumer can discover it, and the
/// stale-pin case means the node's own CI cannot see its newest method.
///
/// Pinning the direction here is what makes the dependency's version range load-bearing: with the
/// requirement narrowed to a version predating a method, this test fails instead of passing
/// vacuously.
#[test]
fn the_contract_publishes_every_control_method_the_node_serves() {
    let published: BTreeSet<&str> = ControlMethod::ALL.iter().map(|m| m.name()).collect();

    let unpublished: Vec<&str> = CONTROL_METHODS
        .iter()
        .copied()
        .filter(|m| !published.contains(m))
        .filter(|m| !KNOWN_UNPUBLISHED.contains(m))
        .collect();
    assert!(
        unpublished.is_empty(),
        "this node serves methods the contract does not publish: {unpublished:?} -- \
         publish them in dig-node-control-interface, or add them to KNOWN_UNPUBLISHED with a ticket"
    );
}

/// The known-drift list stays HONEST: an entry that is no longer drifting must be deleted, or the
/// list rots into a permanent excuse that hides the next real drift behind it.
#[test]
fn the_known_drift_list_still_describes_real_drift() {
    let served: BTreeSet<&str> = CONTROL_METHODS.iter().copied().collect();
    for method in KNOWN_PREEXISTING_DRIFT {
        assert!(
            !served.contains(method),
            "{method} is served now -- remove it from KNOWN_PREEXISTING_DRIFT"
        );
    }
}

/// The same honesty rule for the other list: a method the contract has since published must leave
/// [`KNOWN_UNPUBLISHED`], or it becomes a standing excuse hiding the next unpublished method.
#[test]
fn the_unpublished_list_still_describes_real_drift() {
    let published: BTreeSet<&str> = ControlMethod::ALL.iter().map(|m| m.name()).collect();
    for method in KNOWN_UNPUBLISHED {
        assert!(
            !published.contains(method),
            "{method} is published now -- remove it from KNOWN_UNPUBLISHED"
        );
    }
}

/// **The node and the contract agree on which wallet methods need a token.**
///
/// The two sides state this independently — the node in `is_open_control_read`, the crate in
/// `ControlMethod::is_open_read` — and a disagreement is silent in both directions and expensive in
/// both: a read the node gates but the contract calls open sends a person hunting a permissions
/// fault that does not exist, and a PUSH the contract called open would invite a client to try
/// broadcasting without a token and read the refusal as "upgrade your node".
#[test]
fn the_node_and_the_contract_agree_on_the_token_less_wallet_surface() {
    for method in ControlMethod::ALL
        .iter()
        .filter(|m| m.category() == Category::Wallet)
    {
        assert_eq!(
            is_open_control_read(method.name()),
            method.is_open_read(),
            "{} disagrees on whether it needs the control token",
            method.name()
        );
    }
}

/// **The node's `coin_id` validator agrees with the published contract's `WalletCoinByIdParams::validated()` on every input.**
///
/// Both sides implement the same normative rule independently. This test pins them against a shared
/// corpus and asserts they agree on BOTH the accept/reject verdict AND the normalised output.
/// It FAILS if either side's rule changes alone — that is the property the reviewer requires.
///
/// The two implementations are kept separate on purpose: calling one from inside the other and then
/// asserting they match is circular and proves nothing. This test is the mechanical check.
#[test]
fn wallet_coin_id_param_agrees_with_published_contract() {
    const BARE: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    let corpus: &[(&str, bool)] = &[
        // (input, should_be_accepted)
        (BARE, true), // bare 64 lowercase-hex
        (
            "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            true,
        ), // 0x-prefixed
        (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
            false,
        ), // 63 hex chars
        (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2bb",
            false,
        ), // 65 hex chars
        (
            "0xa1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1",
            false,
        ), // 0x + 63 hex
        (
            "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            false,
        ), // all-uppercase
        (
            "A1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            false,
        ), // single uppercase in valid id
        (
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            false,
        ), // 64 non-hex chars
        ("", false),  // empty string
        (
            " a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            false,
        ), // whitespace-padded valid id
    ];

    for (input, expected_accept) in corpus {
        // Node's validator result.
        let node_result = wallet_coin_id_param_for_test(&json!(1), &json!({ "coin_id": input }));

        // Contract's validator result.
        let contract_result = WalletCoinByIdParams {
            coin_id: input.to_string(),
        }
        .validated();

        let node_accepted = node_result.is_ok();
        let contract_accepted = contract_result.is_ok();

        assert_eq!(
            node_accepted, contract_accepted,
            "input {:?}: node accepted={node_accepted} but contract accepted={contract_accepted}",
            input
        );
        assert_eq!(
            node_accepted, *expected_accept,
            "input {:?}: expected accepted={expected_accept} but got {node_accepted}",
            input
        );

        // When both accept, the normalised output must also agree.
        if node_accepted {
            let node_coin_id = node_result.unwrap();
            let contract_coin_id = contract_result.unwrap().coin_id;
            assert_eq!(
                node_coin_id, contract_coin_id,
                "input {:?}: node normalised to {node_coin_id:?} but contract normalised to {contract_coin_id:?}",
                input
            );
        }
    }
}
