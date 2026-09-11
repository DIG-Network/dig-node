//! Fail-closed guard (dig_ecosystem#3269, binding #3261's rule node-side): every `Method` variant
//! whose wire name contains `Reward` MUST be `Tier::Control` and MUST NOT be peer-reachable.
//!
//! The companion check — absence from dig-node's OWN peer dispatch allowlist
//! (`is_peer_reachable_method`, `pub(crate)` in `src/peer.rs`, unreachable from an external
//! integration test) — is a sibling unit test inside `peer.rs`'s own `#[cfg(test)] mod tests`:
//! `reward_methods_are_absent_from_the_node_peer_allowlist`.
//!
//! #3261 (a `dig-rpc-protocol` ticket, not this crate's work) replaces that crate's four-member
//! reward-method enumeration with a prefix guard — but the enumeration it replaces lists exactly the
//! four methods that exist TODAY, so a FIFTH reward method added later would pass an enumeration test
//! simply by not being in the list: an enumeration test only proves the enumeration. This test proves
//! the RULE instead, over the live `Method::ALL` catalogue: it does not name any reward method, so a
//! reward method added after this test is written is caught automatically, at the wrong tier, the
//! moment it appears — rather than silently inheriting a wrong default.
//!
//! Promotion (widening a method's reach) is additive and reversible; demotion is breaking and breaks
//! exactly the anonymous callers nobody can enumerate. That asymmetry is why this fails closed: a
//! reward method that is NOT `Tier::Control`, or IS peer-reachable, fails loudly instead of quietly
//! granting a remote peer a money-adjacent read.

use dig_rpc_protocol::{Method, Tier};

/// Every catalogue member whose wire name contains `"Reward"` (case-sensitive — the wire is
/// camelCase, e.g. `dig.getRewardProverStatus`).
fn reward_methods() -> Vec<Method> {
    Method::ALL
        .iter()
        .copied()
        .filter(|m| m.name().contains("Reward"))
        .collect()
}

#[test]
fn reward_methods_exist_and_are_found_by_the_prefix_scan() {
    // A guard that silently matched zero methods would pass on a catalogue where every reward
    // method had been renamed out of its `Reward` name, proving nothing. Assert the scan actually
    // finds the surface it exists to police.
    let methods = reward_methods();
    assert!(
        !methods.is_empty(),
        "expected at least one Reward-prefixed method in Method::ALL; found none — the prefix scan \
         itself may be broken, or the wire naming convention changed"
    );
    // dig_ecosystem#3269 unit 3: pins the count so the guard cannot silently start policing FEWER
    // methods than actually exist (a non-empty check alone would still pass on 3 of 4, or on a
    // renamed variant the filter stopped matching). Update this number deliberately when
    // `dig-rpc-protocol` adds or removes a reward method.
    assert_eq!(
        methods.len(),
        4,
        "expected exactly 4 Reward-prefixed methods (dig.listRewardDistributors, \
         dig.getRewardProverStatus, dig.getRewardDistributor, \
         dig.listRewardDistributorCommitments); got {}",
        methods.len()
    );
}

#[test]
fn every_reward_method_is_tier_control() {
    for method in reward_methods() {
        assert_eq!(
            method.tier(),
            Tier::Control,
            "{} must be Tier::Control (dig_ecosystem#3269) — a reward RPC reachable at a lower tier \
             is a money hole",
            method.name()
        );
    }
}

#[test]
fn no_reward_method_is_peer_reachable() {
    for method in reward_methods() {
        assert!(
            !method.is_peer_reachable(),
            "{} must NOT be peer-reachable — reachable ONLY from the loopback admin / in-process FFI \
             dispatch, never over the mTLS peer surface",
            method.name()
        );
    }
}
