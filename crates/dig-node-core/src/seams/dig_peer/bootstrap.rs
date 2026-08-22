//! Bootstrap peers — the always-on anchors a node dials at startup so a fresh install is never
//! stranded with zero peers (dig_ecosystem#923).
//!
//! # Why a node needs this at all
//!
//! Every other way this node learns peers requires already having one. Peer exchange spreads the
//! peers a link's far end knows, the DHT answers queries routed through peers already in the table,
//! and a relay reservation only makes this node *reachable* — it never populates an address book.
//! So a node installed onto a machine that has never run one has nothing to dial, and reports
//! `connected_peers = 0` for as long as it runs. The bootstrap set is the one input that does not
//! presuppose its own output.
//!
//! # Why an address is not enough
//!
//! The node↔node interface is mTLS with the peer's certificate SPKI pinned against an EXPECTED
//! identity ([`dig_gossip::GossipHandle::connect_via_nat`]), so a dial needs the `peer_id` as well as
//! the address. An entry with no identity is SKIPPED rather than dialed unpinned: dialing unpinned
//! would accept whatever identity answered at that address, which is precisely what the pinning
//! exists to deny. Skipping costs a node that has no other peers nothing it had.

use std::time::Duration;

/// How long a single bootstrap dial may run before it is abandoned. The ladder tries each traversal
/// tier in turn, so this bounds one tier, not the whole attempt.
const BOOTSTRAP_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// The environment variable overriding the compiled-in bootstrap set: a comma-separated
/// `peer_id@host:port` list, or `off`/`disabled` for an air-gapped node.
const BOOTSTRAP_ENV: &str = "DIG_BOOTSTRAP_PEERS";

/// A bootstrap peer this node can actually dial: a pinned identity plus the authority it answers on.
///
/// Only entries carrying BOTH become a `BootstrapTarget`, so an unidentified entry is filtered out
/// once, here, rather than being re-checked at every use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTarget {
    /// The peer's 64-hex identity, pinned against the certificate the handshake presents.
    pub peer_id_hex: String,
    /// The `host:port` authority the peer answers on.
    pub authority: String,
}

/// The bootstrap targets for this process: the `DIG_BOOTSTRAP_PEERS` override when set, else the
/// canonical compiled-in set.
pub fn bootstrap_targets_from_env() -> Vec<BootstrapTarget> {
    resolve_bootstrap_targets(std::env::var(BOOTSTRAP_ENV).ok().as_deref())
}

/// Pure: resolve the bootstrap targets from an optional `DIG_BOOTSTRAP_PEERS` value.
///
/// An explicit `off`/`disabled` yields NO targets, and so — for now — does an unset value: see
/// [`compiled_in_targets`]. Malformed entries and entries with no identity are dropped, so the
/// result is exactly the set that can be dialed.
pub fn resolve_bootstrap_targets(env: Option<&str>) -> Vec<BootstrapTarget> {
    let configured = env.map(str::trim).filter(|s| !s.is_empty());
    match configured {
        Some(v) if is_disabled(v) => Vec::new(),
        Some(v) => v.split(',').filter_map(parse_bootstrap_target).collect(),
        None => compiled_in_targets(),
    }
}

/// The canonical compiled-in bootstrap set, from `dig_constants::DIG_BOOTSTRAP_PEERS`.
///
/// Read from the cross-repo SSOT rather than declared here, because a second repo hardcoding its own
/// copy of a shared literal is the drift class dig-constants exists to prevent — the same reason
/// `DIG_NODE_PORT` and `DIG_RELAY_URL` are not spelled out in this workspace either.
///
/// The canonical entries are written in the SAME `peer_id@host:port` syntax an operator would type
/// into `DIG_BOOTSTRAP_PEERS`, so they flow through [`parse_bootstrap_target`] unchanged. That is
/// deliberate: the default set and the override cannot diverge in how they are interpreted, because
/// there is only one interpretation. An entry the parser rejects is dropped here exactly as it would
/// be from the override — a malformed canonical entry yields no anchor rather than a mis-dialled one.
fn compiled_in_targets() -> Vec<BootstrapTarget> {
    dig_constants_net::DIG_BOOTSTRAP_PEERS
        .iter()
        .copied()
        .filter_map(parse_bootstrap_target)
        .collect()
}

/// Whether the value explicitly disables bootstrapping (mirrors `DIG_RELAY_URL`'s opt-out).
fn is_disabled(value: &str) -> bool {
    value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("disabled")
}

/// Pure: parse one `peer_id@host:port` entry, or `None` if it is malformed.
///
/// A malformed entry is dropped rather than defaulted. Guessing a value here would produce a target
/// the operator never wrote, and the failure would surface as an unreachable peer rather than as a
/// configuration error.
fn parse_bootstrap_target(entry: &str) -> Option<BootstrapTarget> {
    let (peer_id, authority) = entry.trim().split_once('@')?;
    let authority = authority.trim();
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    Some(BootstrapTarget {
        peer_id_hex: validated_peer_id(peer_id.trim())?.to_string(),
        authority: authority.to_string(),
    })
}

/// Pure: the identity if it is a well-formed 64-hex `peer_id`, else `None`.
fn validated_peer_id(peer_id_hex: &str) -> Option<&str> {
    let ok = peer_id_hex.len() == 64 && peer_id_hex.chars().all(|c| c.is_ascii_hexdigit());
    ok.then_some(peer_id_hex)
}

/// Dial every bootstrap target once, in the background, adopting each verified connection into the
/// connected-peer pool.
///
/// Spawned rather than awaited: bring-up must not block on a network round-trip to an anchor that
/// may be unreachable, and a node whose bootstrap dials all fail is still a working node in every
/// other respect. Each dial runs the FULL traversal ladder, so an anchor stays reachable from behind
/// a NAT that permits no direct path.
///
/// A target already in the pool is skipped: it is already the outcome the dial exists to produce,
/// and adopting a second connection for a live identity supersedes and tears down the existing
/// session (dig-gossip 0.17.12 onward), taking any transfer over it with it.
pub fn spawn_bootstrap_dials(
    handle: dig_gossip::GossipHandle,
    targets: Vec<BootstrapTarget>,
    stun_server: Option<std::net::SocketAddr>,
) {
    if targets.is_empty() {
        tracing::info!(
            "dig-node peer network: no bootstrap peers configured; first peers must come from the relay or peer exchange"
        );
        return;
    }
    let methods = crate::net::full_nat_config(BOOTSTRAP_DIAL_TIMEOUT, stun_server)
        .enabled_methods
        .clone();
    for target in targets {
        let Some(peer_id) = peer_id_from_hex(&target.peer_id_hex) else {
            continue;
        };
        let handle = handle.clone();
        let methods = methods.clone();
        tokio::spawn(async move {
            if handle.is_pool_peer(&peer_id) {
                return;
            }
            let addr = resolve_authority(&target.authority);
            match handle
                .connect_via_nat(peer_id, addr, &methods, BOOTSTRAP_DIAL_TIMEOUT)
                .await
            {
                Ok(conn) => {
                    // Re-check membership now the dial has resolved: it ran for up to
                    // BOOTSTRAP_DIAL_TIMEOUT, in which the identity may have joined the pool by
                    // another path, and adopting then would supersede that live session.
                    if handle.is_pool_peer(&peer_id) {
                        return;
                    }
                    let _ = handle.adopt_nat_connection(conn).await;
                    tracing::info!(peer = %peer_id, authority = %target.authority, "bootstrap peer connected");
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id, authority = %target.authority, error = %e, "bootstrap peer dial failed")
                }
            }
        });
    }
}

/// Resolve a `host:port` authority to ONE socket address, IPv6-first (§5.2).
///
/// `None` when the host does not resolve; the ladder can still reach the peer over the relay tier
/// using the pinned identity alone, so an unresolvable name is a lost direct path rather than a lost
/// peer.
fn resolve_authority(authority: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<_> = authority.to_socket_addrs().ok()?.collect();
    resolved
        .iter()
        .find(|a| a.is_ipv6())
        .or_else(|| resolved.first())
        .copied()
}

/// Parse a 64-hex identity into a dig-gossip [`PeerId`](dig_gossip::PeerId).
fn peer_id_from_hex(peer_id_hex: &str) -> Option<dig_gossip::PeerId> {
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(peer_id_hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(dig_gossip::PeerId::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic 64-hex identity, and a second one differing from it, so a test that must tell two
    /// bootstrap peers apart is not relying on a single fixture.
    fn peer_id_a() -> String {
        "a".repeat(64)
    }

    fn peer_id_b() -> String {
        "b".repeat(64)
    }

    // -- the override -----------------------------------------------------------------------------

    /// An explicit list is parsed into exactly its entries, in order.
    ///
    /// Two entries, not one: a single-entry fixture cannot distinguish "parses the list" from
    /// "parses the first element and stops", which is the nearest wrong implementation.
    #[test]
    fn env_list_parses_every_entry() {
        let env = format!(
            "{}@anchor.invalid:9444,{}@[::1]:9779",
            peer_id_a(),
            peer_id_b()
        );
        let targets = resolve_bootstrap_targets(Some(&env));
        assert_eq!(
            targets,
            vec![
                BootstrapTarget {
                    peer_id_hex: peer_id_a(),
                    authority: "anchor.invalid:9444".to_string()
                },
                BootstrapTarget {
                    peer_id_hex: peer_id_b(),
                    authority: "[::1]:9779".to_string()
                },
            ]
        );
    }

    /// `off` / `disabled` yield no targets at all — the air-gapped opt-out.
    #[test]
    fn explicit_off_disables_bootstrapping() {
        for value in ["off", "OFF", "disabled", " Disabled "] {
            assert!(
                resolve_bootstrap_targets(Some(value)).is_empty(),
                "{value} must disable bootstrapping"
            );
        }
    }

    /// A blank value is treated as UNSET — it falls back rather than disabling.
    ///
    /// Blank is distinguished from `off` because an empty string is what an unset variable becomes
    /// in most process managers: reading it as an explicit "no anchors" would make the fallback
    /// unreachable on those hosts for a reason nobody wrote down. The control is a populated value
    /// through the same argument position, so this cannot pass merely because both arms are empty
    /// today.
    #[test]
    fn a_blank_value_falls_back_rather_than_disabling() {
        assert_eq!(
            resolve_bootstrap_targets(Some("   ")),
            resolve_bootstrap_targets(None)
        );
        let populated = format!("{}@anchor.invalid:9444", peer_id_a());
        assert_eq!(
            resolve_bootstrap_targets(Some(&populated)).len(),
            1,
            "the same argument position must be able to yield a target"
        );
    }

    // -- malformed entries ------------------------------------------------------------------------

    /// A malformed entry is dropped WITHOUT taking its well-formed neighbours with it.
    ///
    /// Each bad entry is paired with a good one in the same list, because a list containing only bad
    /// entries yields an empty result either way — it cannot tell "drops the bad entry" from
    /// "rejects the whole list", and the second would strand a node over one typo.
    #[test]
    fn a_malformed_entry_is_dropped_without_discarding_the_list() {
        let good = format!("{}@anchor.invalid:9444", peer_id_a());
        let short_id = "b".repeat(63);
        let non_hex_id = "z".repeat(64);
        let malformed = [
            "anchor.invalid:9444".to_string(),         // no identity at all
            format!("{}@anchor.invalid", peer_id_b()), // no port
            format!("{}@anchor.invalid:99999", peer_id_b()), // port out of range
            format!("{}@:9778", peer_id_b()),          // empty host
            format!("{short_id}@anchor.invalid:9444"), // identity too short
            format!("{non_hex_id}@anchor.invalid:9444"), // identity not hex
        ];
        for bad in malformed {
            let targets = resolve_bootstrap_targets(Some(&format!("{bad},{good}")));
            assert_eq!(
                targets,
                vec![BootstrapTarget {
                    peer_id_hex: peer_id_a(),
                    authority: "anchor.invalid:9444".to_string()
                }],
                "{bad} must be dropped while its neighbour survives"
            );
        }
    }

    // -- the compiled-in set ----------------------------------------------------------------------

    /// A node with NO configuration at all is seeded with at least one dialable anchor.
    ///
    /// This is the whole point of #923: every other peer input (peer exchange, the DHT, the relay
    /// reservation) presupposes a peer this node already has, so if this set is empty a fresh
    /// install reports zero peers for as long as it runs. The PR that introduced this module shipped
    /// `compiled_in_targets` returning an empty vec, which every other test in this file tolerated —
    /// so the assertion is on NON-emptiness specifically, because that is the state that regressed.
    #[test]
    fn an_unconfigured_node_is_seeded_with_at_least_one_anchor() {
        assert!(
            !resolve_bootstrap_targets(None).is_empty(),
            "an unconfigured node must have an anchor to dial"
        );
    }

    /// The seeded anchor names the PEER host, never the CloudFront read gateway.
    ///
    /// `rpc.dig.net` terminates HTTPS at CloudFront and cannot carry the mTLS peer protocol; its
    /// :9444 is closed, while `node-rpc.dig.net` (its origin) answers. The two names differ by one
    /// label, so this asserts the gateway host is ABSENT rather than asserting some host is present:
    /// a test that only checked "an anchor exists" — which is what
    /// `an_unconfigured_node_is_seeded_with_at_least_one_anchor` above checks — passes with the
    /// closed-port host in it. The port is pinned for the same reason: `DIG_NODE_PORT` (9778) is the
    /// §5.3 client→node READ port and an anchor published there would never answer a peer dial.
    #[test]
    fn the_seeded_anchor_is_the_peer_host_and_port_not_the_read_gateway() {
        for target in resolve_bootstrap_targets(None) {
            let (host, port) = target.authority.rsplit_once(':').expect("explicit port");
            assert_ne!(
                host, "rpc.dig.net",
                "{target:?} dials the CloudFront gateway, whose peer ports are closed"
            );
            assert_eq!(host, "node-rpc.dig.net", "{target:?} is not the peer host");
            assert_eq!(port, "9444", "{target:?} is not on the peer port");
        }
    }

    /// Every seeded anchor carries a pinned identity that actually parses into a `PeerId`.
    ///
    /// A canonical entry the parser cannot use is worse than none: it would be silently dropped and
    /// the node would be back to zero anchors while the constant looked populated. Parsing all the
    /// way to `PeerId` — rather than only checking the string is 64 hex — is what makes this test
    /// see a value that is well-formed but unusable by the transport.
    #[test]
    fn every_seeded_anchor_has_a_usable_pinned_identity() {
        for target in resolve_bootstrap_targets(None) {
            assert!(
                peer_id_from_hex(&target.peer_id_hex).is_some(),
                "{target:?} carries an identity the transport cannot pin"
            );
        }
    }

    /// An entry without a USABLE identity is skipped, and one with a usable identity at the same
    /// authority is kept.
    ///
    /// Both ways an identity can be missing are covered, because they fail in different code and a
    /// fixture with only the first is blind to the second: an entry with no `@` never reaches
    /// identity validation at all, so it stays green even if validation is deleted outright (this
    /// was caught by reverting `validated_peer_id` to `Some(_)` — the no-`@` case alone did not
    /// notice). The identical authority across all three entries is deliberate: it forces the
    /// distinction to be the identity rather than the address.
    #[test]
    fn an_entry_without_a_usable_identity_is_skipped_and_a_usable_one_is_kept() {
        let unusable = [
            "anchor.invalid:9444".to_string(),
            "@anchor.invalid:9444".to_string(),
        ];
        for entry in unusable {
            let env = format!("{entry},{}@anchor.invalid:9444", peer_id_a());
            assert_eq!(
                resolve_bootstrap_targets(Some(&env)),
                vec![BootstrapTarget {
                    peer_id_hex: peer_id_a(),
                    authority: "anchor.invalid:9444".to_string()
                }],
                "{entry} carries no usable identity and must be skipped"
            );
        }
    }

    /// A 64-hex identity round-trips into a `PeerId`, and a malformed one yields `None`.
    ///
    /// The reject arm is what keeps an unpinned dial unreachable: if a malformed identity parsed to
    /// some default `PeerId`, the dial would proceed against an identity nobody configured.
    #[test]
    fn peer_id_parses_only_well_formed_hex() {
        assert!(peer_id_from_hex(&peer_id_a()).is_some());
        assert_ne!(
            peer_id_from_hex(&peer_id_a()),
            peer_id_from_hex(&peer_id_b()),
            "two distinct identities must not collapse to one PeerId"
        );
        for bad in ["", "zz", &"a".repeat(63), &"g".repeat(64)] {
            assert!(peer_id_from_hex(bad).is_none(), "{bad} must not parse");
        }
    }

    /// Resolution prefers IPv6 when the host offers both families (§5.2).
    ///
    /// `localhost` is used because it is the one name guaranteed to resolve without a network, and
    /// the assertion is conditional on it actually offering both families so the test cannot pass
    /// vacuously on a host that publishes only one.
    #[test]
    fn authority_resolution_prefers_ipv6() {
        use std::net::ToSocketAddrs;
        let all: Vec<_> = "localhost:9444"
            .to_socket_addrs()
            .map(|i| i.collect())
            .unwrap_or_default();
        if all.iter().any(|a| a.is_ipv6()) && all.iter().any(|a| a.is_ipv4()) {
            assert!(
                resolve_authority("localhost:9444")
                    .expect("resolves")
                    .is_ipv6(),
                "IPv6 must win when both families are available"
            );
        }
        assert_eq!(resolve_authority("no-such-host.invalid:9778"), None);
    }

    /// The dial timeout is a real bound, not an accidental zero.
    #[test]
    fn bootstrap_dial_timeout_is_bounded_and_nonzero() {
        assert!(BOOTSTRAP_DIAL_TIMEOUT > Duration::ZERO);
        assert!(BOOTSTRAP_DIAL_TIMEOUT <= Duration::from_secs(60));
    }
}
