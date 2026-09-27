//! dig_ecosystem#3292: `Node::install_funded_distributor_registry` has a real, non-test caller.
//!
//! Before this ticket the installer was `pub(crate)`, so `dig-node-service` -- the crate that
//! owns `state.state_dir` and constructs the real `Node` -- could not call it at all. This file
//! does not compile against the pre-fix source (a `pub(crate)` method is invisible to this
//! integration-test crate, a separate compilation unit), which is this ticket's RED.

use dig_node_core::rewards::funded::{FundedDistributorsRead, NotConfiguredReason};
use dig_node_core::Node;

/// Mirrors `rewards_chain_port_a3.rs`'s `install_reward_chain_port_refuses_a_second_install`
/// shape for the funder-ownership registry: install from a tempdir, once-only, and the read
/// after install is the correct "no record written yet" UNKNOWN -- never a reassuring empty
/// funded set (dig_ecosystem#3285's whole point; #3291's writer, not this ticket, is what would
/// ever populate it).
#[test]
fn install_funded_distributor_registry_installs_a_tempdir_backed_registry_once() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry =
        dig_node_core::rewards::funded::FundedDistributorRegistry::with_state_dir(dir.path());

    // Sanity on the registry itself, independent of `Node`: a fresh state dir with no record
    // file reads `NotConfigured(NoRecordWritten)`, not `FundsNothing` -- the property the
    // installer must not collapse.
    assert_eq!(
        registry.read(),
        FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoRecordWritten),
        "a fresh state dir with no record file must read as UNKNOWN, never a funded set"
    );

    // `Node` exposes no lighter test constructor to an external integration-test crate --
    // `Node::from_env()` is the same constructor `rewards_chain_port_a3.rs`'s own test uses for
    // the identical reason.
    let node = Node::from_env();

    let first_install = node.install_funded_distributor_registry(registry.clone());
    assert!(first_install, "the first install must be accepted");

    let second_install = node.install_funded_distributor_registry(registry);
    assert!(
        !second_install,
        "the second install must be refused, changing nothing"
    );
}

/// Proves the STARTUP call chain, not just that the installer is reachable: `server.rs`'s
/// production (non-test) source must call `install_funded_distributor_registry` against
/// `state.state_dir`, unconditionally (no `enable_chain_sync` gate -- this is local state, not a
/// chain read). A source-text assertion, the same shape `rewards_chain_port_a3.rs` uses to prove
/// its own sibling install site, because driving `serve_with_shutdown` itself is new production
/// surface this ticket does not need. Mutation-proved: deleting the call site below turns this
/// assertion red; restoring it turns it green again.
#[test]
fn server_startup_calls_install_funded_distributor_registry_in_production_code() {
    let server_source = production_region(include_str!("../src/server.rs"));
    assert!(
        server_source.contains("install_funded_distributor_registry"),
        "server.rs's production startup path must call \
         `Node::install_funded_distributor_registry`, or dig_ecosystem#3292 has regressed"
    );
    assert!(
        server_source.contains("state.state_dir"),
        "the production call must be built over the service's own hardened state dir, not an \
         ephemeral or test-only path"
    );
}

/// The slice of a source file before its own `#[cfg(test)]` module -- i.e. what actually ships.
/// Duplicated from `rewards_chain_port_a3.rs`'s identical helper because this integration test is
/// a separate compilation unit and cannot import a private helper from that file.
fn production_region(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(test_module_start) => &source[..test_module_start],
        None => source,
    }
}
