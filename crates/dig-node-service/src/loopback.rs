//! The DIG loopback allocation — one place that answers "which loopback address does a DIG
//! service bind?", so no call site ever re-derives it.
//!
//! # The rule
//!
//! **A DIG loopback service MUST NOT bind `127.0.0.1` (or a name that resolves to it).** The whole
//! of `127.0.0.0/8` is loopback, so DIG takes its own addresses out of that range and leaves
//! `127.0.0.1` — the address every other program on the machine assumes it can have — alone.
//!
//! # Why this is a rule and not a preference
//!
//! Binding `127.0.0.1` makes a DIG port collide with whatever else on the host wants that port,
//! and the collision is a *race*, not an error a user can read. dig-node bound `127.0.0.1:9257`
//! with an mTLS listener at every start — the port Sage's own wallet RPC uses. After a reboot
//! whichever service won the race broke the other, and the user saw
//! `sslv3 alert handshake failure` from what they believed was Sage but was actually dig-node.
//! Nothing in that symptom names DIG. The port moved to `9776` in v0.128.0, which fixed that one
//! instance; this module exists so the next binding does not re-create the class.
//!
//! # The allocation
//!
//! Extend this table, never collide with it. It is the same table recorded in the `canonical`
//! skill and `SYSTEM.md`; those three MUST agree.
//!
//! | Address | Owner | Purpose |
//! |---|---|---|
//! | `127.0.0.1` | **nobody — reserved for the rest of the machine** | never bound by a DIG service |
//! | `127.0.0.2` | dig-node | `dig.local` — the local content surface (`:80` plaintext, `:443` TLS) |
//! | `127.0.0.5` | dig-dns | the DNS responder (`:53`) and its HTTP gateway (`:80`) |
//!
//! # IPv6
//!
//! These are IPv4-only control planes, deliberately. §5.2's IPv6-first rule governs **peer**
//! networking — node-to-node traffic that crosses a real network — where address family is a
//! reachability question. A loopback control plane never leaves the host, so there is no
//! reachability to win, and IPv6 loopback offers no equivalent of the `127.0.0.0/8` range: `::1`
//! is a single address, so a per-service v6 allocation is not expressible. Services that also bind
//! `::1` do so as a SECOND listener for clients whose resolver prefers v6 (Windows resolves
//! `localhost` to `::1` first), never as the DIG-owned address.
//!
//! # Reach of the automated guard
//!
//! `tests/loopback_bind_guard.rs` fails the build when a NEW literal-loopback bind appears in
//! product source. It reads source text, so it sees a literal at the bind call and nothing else —
//! a bind of an address computed elsewhere is invisible to it. The one such site today is the
//! control/content listener, whose address comes from [`crate::config::Config::bind_addr`]; that
//! site is named in the guard's own declared-exception list rather than left to be noticed.

use std::net::{IpAddr, Ipv4Addr};

/// `dig.local` — the DIG-owned loopback address for dig-node's local surfaces.
///
/// The installer writes a hosts entry `127.0.0.2  dig.local`, which is what makes the name
/// resolve; the address is the contract, and the name is a convenience over it.
pub const DIG_NODE_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// dig-dns's DIG-owned loopback address (its `:53` responder and `:80` gateway).
///
/// Declared here — even though this crate never binds it — because the value of an allocation
/// table is that it is complete. A table that lists only the addresses one crate happens to use
/// cannot answer "is this address free?", which is the question a new service asks.
pub const DIG_DNS_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

/// The loopback address a dig-node service binds.
///
/// Call this instead of writing an address literal. It exists so the answer lives in one place:
/// a call site that spells `127.0.0.1` is making a decision it should not be making, and a call
/// site that spells `127.0.0.2` has re-derived a fact that can change.
pub fn dig_loopback() -> IpAddr {
    IpAddr::V4(DIG_NODE_LOOPBACK)
}

/// The address an ephemeral, short-lived local listener should bind, with the fall-back the host
/// may force on us.
///
/// Returns [`dig_loopback`] first and `127.0.0.1` second. **The fall-back is not a loophole** — it
/// is the macOS constraint: on macOS a `127.0.0.X` alias other than `127.0.0.1` does not exist
/// until someone runs `ifconfig lo0 alias 127.0.0.2`, so a bind of the DIG address fails outright
/// on a host where the installer has not created it. The same best-effort shape already governs
/// the `dig.local` listener, which logs and serves on without it.
///
/// A caller MUST try these in order and use the first that binds, so that a host WITH the alias
/// gets the DIG address (the rule's benefit) and a host without it still works (the user's
/// benefit). Reporting which one was taken is the caller's job — a silent fall-back to
/// `127.0.0.1` would hide exactly the collision this module exists to prevent.
pub fn ephemeral_bind_candidates() -> [IpAddr; 2] {
    [dig_loopback(), IpAddr::V4(Ipv4Addr::LOCALHOST)]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** the allocation never hands a DIG service `127.0.0.1`, and never hands two
    /// services the same address.
    ///
    /// Both halves matter and they fail differently: the first catches an edit that "simplifies"
    /// an entry back to the address the rule exists to avoid, and the second catches a new entry
    /// appended on top of an existing one — the collision this table exists to make impossible.
    #[test]
    fn the_allocation_avoids_127_0_0_1_and_has_no_duplicates() {
        let allocated = [DIG_NODE_LOOPBACK, DIG_DNS_LOOPBACK];

        for addr in allocated {
            assert!(
                addr.is_loopback(),
                "{addr} must be inside 127.0.0.0/8 — an allocation outside loopback would expose \
                 a local-only service to the network"
            );
            assert_ne!(
                addr,
                Ipv4Addr::LOCALHOST,
                "{addr}: 127.0.0.1 is reserved for the rest of the machine and is the one address \
                 no DIG service may take"
            );
        }

        for (i, a) in allocated.iter().enumerate() {
            for b in &allocated[i + 1..] {
                assert_ne!(
                    a, b,
                    "two DIG services were allocated the same loopback address"
                );
            }
        }
    }

    /// **Proves:** the ephemeral fall-back is ORDERED — the DIG address is attempted before
    /// `127.0.0.1`, never the other way round.
    ///
    /// Order is the entire property. A candidate list containing both addresses satisfies "there
    /// is a fall-back" in either order, but only one order actually applies the rule: reversed, a
    /// host that HAS the alias would still take `127.0.0.1` every time and the rule would be
    /// inert while looking implemented.
    #[test]
    fn the_dig_address_is_tried_before_the_127_0_0_1_fallback() {
        let candidates = ephemeral_bind_candidates();
        assert_eq!(
            candidates[0],
            IpAddr::V4(DIG_NODE_LOOPBACK),
            "the DIG loopback address must be attempted FIRST"
        );
        assert_eq!(
            candidates[1],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "127.0.0.1 is the LAST resort, for a macOS host with no lo0 alias"
        );
    }
}
