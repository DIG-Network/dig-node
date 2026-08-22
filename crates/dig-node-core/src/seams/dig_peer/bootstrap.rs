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
/// An explicit `off`/`disabled` yields NO targets. An UNSET value yields the canonical compiled-in
/// set — see [`compiled_in_targets`] — which is the whole point of dig_ecosystem#923: a node with no
/// configuration must still have an anchor to dial. Malformed entries and entries with no identity
/// are dropped, so the result is exactly the set that can be dialed.
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
            let candidates = dial_candidates(&target.authority);
            let outcome = first_successful_dial(candidates, |addr| {
                let handle = handle.clone();
                let methods = methods.clone();
                async move {
                    handle
                        .connect_via_nat(peer_id, addr, &methods, BOOTSTRAP_DIAL_TIMEOUT)
                        .await
                }
            })
            .await;
            match outcome {
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

/// The dial candidates for a `host:port` authority, IPv6-first and IPv4-FALLBACK (§5.2).
///
/// §5.2 is IPv6-*first*, not IPv6-only, and the difference is load-bearing here. `node-rpc.dig.net`
/// publishes an AAAA record, so a host with IPv6 configured but not actually routable resolves to a
/// v6 address, dials into a black hole, and — if that were the only candidate — ends with zero peers
/// while a perfectly good IPv4 path sat unused. That is the exact outcome dig_ecosystem#923 exists to
/// prevent, so every resolved address is a candidate and the families are merely ORDERED.
///
/// The list always has at least one element: an unresolvable name yields `[None]`, which still runs
/// the traversal ladder — the relay tier can reach the peer from the pinned identity alone, so an
/// unresolvable name is a lost direct path rather than a lost peer.
fn dial_candidates(authority: &str) -> Vec<Option<std::net::SocketAddr>> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<_> = authority
        .to_socket_addrs()
        .map(|addrs| addrs.collect())
        .unwrap_or_default();
    let ordered = order_ipv6_first(resolved);
    if ordered.is_empty() {
        return vec![None];
    }
    ordered.into_iter().map(Some).collect()
}

/// Pure: every address, IPv6 ones first, each family keeping its resolver-given relative order.
///
/// Nothing is discarded — an implementation that returned only the v6 addresses would satisfy
/// "IPv6-first" while deleting the fallback this function exists to preserve.
fn order_ipv6_first(resolved: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = resolved.into_iter().partition(|a| a.is_ipv6());
    v6.into_iter().chain(v4).collect()
}

/// Run `dial` against each candidate in turn and return the first success, else the LAST failure.
///
/// Sequential rather than concurrent: a bootstrap dial adopts a session into the connected-peer pool,
/// and two racing dials to one identity would have the winner supersede and tear down the other.
///
/// An empty candidate list is dialled once with `None` rather than returning an error, so a caller
/// that resolved nothing still reaches the relay tier.
async fn first_successful_dial<T, E, F, Fut>(
    candidates: Vec<Option<std::net::SocketAddr>>,
    mut dial: F,
) -> Result<T, E>
where
    F: FnMut(Option<std::net::SocketAddr>) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let candidates = if candidates.is_empty() {
        vec![None]
    } else {
        candidates
    };
    let mut last_error = None;
    for candidate in candidates {
        match dial(candidate).await {
            Ok(connected) => return Ok(connected),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("the candidate list is non-empty, so at least one dial ran"))
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

    // -- IPv6-first WITH IPv4 fallback (§5.2) -------------------------------------------------------

    fn v6(last: u16) -> std::net::SocketAddr {
        format!("[2001:db8::{last:x}]:9444").parse().expect("v6")
    }

    fn v4(last: u8) -> std::net::SocketAddr {
        format!("192.0.2.{last}:9444").parse().expect("v4")
    }

    /// Ordering puts IPv6 first and KEEPS every IPv4 address as a fallback candidate.
    ///
    /// The fixture is synthetic and interleaved rather than a `localhost` lookup, because the
    /// resolver-backed version of this test is conditional on the host publishing both families and
    /// goes vacuous where it does not. Two addresses per family, interleaved, so the assertion
    /// distinguishes "IPv6 first" from all three nearest wrong implementations: returning only the
    /// v6 addresses (length would drop to 2), returning only the first address, and reversing the
    /// within-family order.
    #[test]
    fn ordering_puts_ipv6_first_without_discarding_ipv4() {
        let resolved = vec![v4(1), v6(1), v4(2), v6(2)];
        assert_eq!(
            order_ipv6_first(resolved),
            vec![v6(1), v6(2), v4(1), v4(2)],
            "IPv6 must lead, and every IPv4 address must survive as a fallback"
        );
    }

    /// An unresolvable name still yields exactly one candidate — `None`, the relay-tier dial.
    #[test]
    fn an_unresolvable_authority_still_yields_one_relay_tier_candidate() {
        assert_eq!(dial_candidates("no-such-host.invalid:9778"), vec![None]);
    }

    /// A host offering both families is dialled v6 first and v4 SECOND, when v6 is unreachable.
    ///
    /// This is the property the preference test could not see: preference says which address is
    /// tried first, and says nothing about whether the other family is tried AT ALL. The fixture is
    /// built so those two answers differ — the v6 candidate always fails (an unroutable-v6 host, the
    /// common shape where IPv6 is configured but has no egress) while the v4 candidate succeeds — so
    /// an implementation that dials only the preferred address returns Err here, and an
    /// implementation that dials v4 FIRST fails the recorded order.
    #[tokio::test]
    async fn an_unreachable_ipv6_candidate_is_followed_by_an_ipv4_attempt() {
        let attempted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let candidates = dial_candidates_from(vec![v6(1), v4(1)]);

        let recorder = attempted.clone();
        let outcome: Result<&str, &str> = first_successful_dial(candidates, move |addr| {
            let recorder = recorder.clone();
            async move {
                let addr = addr.expect("both candidates are resolved addresses");
                recorder.lock().expect("lock").push(addr);
                if addr.is_ipv6() {
                    Err("network unreachable")
                } else {
                    Ok("connected")
                }
            }
        })
        .await;

        assert_eq!(
            outcome,
            Ok("connected"),
            "a working IPv4 path must not be wasted because IPv6 resolved and failed"
        );
        assert_eq!(
            *attempted.lock().expect("lock"),
            vec![v6(1), v4(1)],
            "the v6 candidate must be tried first, and the v4 candidate must actually be tried"
        );
    }

    /// Every candidate failing surfaces an error rather than reporting a connection.
    #[tokio::test]
    async fn a_dial_that_fails_on_every_candidate_reports_failure() {
        let candidates = dial_candidates_from(vec![v6(1), v4(1)]);
        let outcome: Result<&str, &str> =
            first_successful_dial(candidates, |_| async { Err("unreachable") }).await;
        assert_eq!(outcome, Err("unreachable"));
    }

    /// The same ordering + wrapping the production path applies, over a supplied resolution.
    fn dial_candidates_from(resolved: Vec<std::net::SocketAddr>) -> Vec<Option<std::net::SocketAddr>> {
        order_ipv6_first(resolved).into_iter().map(Some).collect()
    }

    /// The dial timeout is a real bound, not an accidental zero.
    #[test]
    fn bootstrap_dial_timeout_is_bounded_and_nonzero() {
        assert!(BOOTSTRAP_DIAL_TIMEOUT > Duration::ZERO);
        assert!(BOOTSTRAP_DIAL_TIMEOUT <= Duration::from_secs(60));
    }
}
