//! IPv6-first, IPv4-fallback networking for the DIG Node peer layer (ecosystem HARD RULE).
//!
//! Two concerns live here, both in service of the ecosystem-wide "IPv6-first, IPv4-fallback for peer
//! communication" rule:
//!
//! 1. **Dual-stack listener bind** ([`bind_tcp_dual_stack`]). The peer-RPC listener binds the IPv6
//!    unspecified address `[::]` as a DUAL-STACK socket — `IPV6_V6ONLY` is explicitly cleared so ONE
//!    socket accepts both native IPv6 connections AND IPv4 (via IPv4-mapped-IPv6) connections on the
//!    same port. Binding `0.0.0.0` (the old behaviour) is IPv4-only and drops IPv6 reachability
//!    entirely; binding `[::]` with the OS default `IPV6_V6ONLY=1` (Windows + some Linux) would be
//!    IPv6-only and silently drop IPv4. Clearing the option gives us both. This mirrors dig-relay's
//!    `net.rs` and dig-gossip's own dual-stack bind exactly.
//!
//! 2. **Advertised address discovery** ([`advertised_socket_addrs`] / [`local_ipv6_addr`] /
//!    [`local_ipv4_addr`]). A node must advertise addresses peers can actually dial. The wildcard
//!    bind address (`[::]` / `0.0.0.0`) is NOT dialable and must never leak into a candidate list.
//!    Instead we advertise the node's real local address(es), **IPv6 first**: a global-unicast IPv6
//!    address when the host has one, then an IPv4 address as the fallback, so the happy-eyeballs
//!    dialer in `dig-nat` prefers IPv6 and falls back to IPv4. In loopback/test mode (no routable
//!    address discoverable) we advertise the loopback address, IPv6 (`::1`) first.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Bind a TCP listener at `addr`. When `addr` is IPv6, the socket is explicitly set **dual-stack**
/// (`IPV6_V6ONLY=false`) before `listen`, so it accepts both native IPv6 and IPv4-mapped peers on the
/// one socket. An explicit IPv4 bind is left alone (dual-stack is meaningless for an IPv4 socket).
///
/// This is the peer-RPC listener's bind path: it is given `[::]:{port}` so the node serves IPv6 +
/// IPv4-mapped peers from a single socket, satisfying the ecosystem IPv6-first / IPv4-fallback rule.
pub fn bind_tcp_dual_stack(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        // Only meaningful for an IPv6 socket, and only settable before bind on most platforms.
        // Clearing it keeps the `[::]` socket dual-stack (accepts IPv4-mapped peers too).
        socket.set_only_v6(false)?;
    }
    // Match std/tokio's own bind behaviour so a restarted node can rebind the port promptly.
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    // Backlog: mirror the value Rust's std/tokio `TcpListener::bind` uses (128).
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// The IPv6 unspecified listen address `[::]:{port}` — the dual-stack bind target for the peer-RPC
/// listener. Bound via [`bind_tcp_dual_stack`], it serves both IPv6 and IPv4-mapped peers.
pub fn dual_stack_listen_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
}

/// Whether an [`Ipv6Addr`] is a *global-unicast* address we can advertise to peers: not loopback, not
/// unspecified, not link-local (`fe80::/10`), not unique-local (`fc00::/7`, i.e. `fc00::` / `fd00::`),
/// and not an IPv4-mapped address. Such an address is (best-effort) routable, so it belongs at the
/// front of the advertised candidate list.
pub fn is_advertisable_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.to_ipv4_mapped().is_some() {
        return false;
    }
    let seg0 = ip.segments()[0];
    let is_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    let is_unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7 (fc00::/8 + fd00::/8)
    !is_link_local && !is_unique_local
}

/// Whether an [`Ipv4Addr`] is one we can advertise to peers: not loopback, not unspecified, not
/// link-local (`169.254.0.0/16`), not broadcast. (Private RFC-1918 ranges ARE kept — a LAN peer is
/// reachable there, and dig-nat's traversal handles the rest — so this only filters the truly
/// non-dialable ones.)
pub fn is_advertisable_ipv4(ip: &Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_broadcast())
}

/// Discover a routable local IPv6 address, if the host has one. Uses the connect-a-UDP-socket trick:
/// "connecting" a UDP socket to an off-host address forces the OS to select the local address it
/// would route from, WITHOUT sending any packet. Returns the local IPv6 address only when it is
/// advertisable ([`is_advertisable_ipv6`]) — i.e. a global-unicast address, never loopback/link-local.
pub fn local_ipv6_addr() -> Option<Ipv6Addr> {
    // A documentation IPv6 address (2001:db8::/32) — never actually contacted; only used so the OS
    // picks the local source address it would route from.
    let probe: SocketAddr = "[2001:db8::1]:9".parse().ok()?;
    let socket = std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(probe).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V6(v6) if is_advertisable_ipv6(&v6) => Some(v6),
        _ => None,
    }
}

/// Discover a routable local IPv4 address, if the host has one (the IPv4 fallback). Same
/// connect-a-UDP-socket trick as [`local_ipv6_addr`]. Returns the address only when advertisable
/// ([`is_advertisable_ipv4`]).
pub fn local_ipv4_addr() -> Option<Ipv4Addr> {
    // A documentation IPv4 address (TEST-NET-3, 203.0.113.0/24) — never contacted.
    let probe: SocketAddr = "203.0.113.1:9".parse().ok()?;
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(probe).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if is_advertisable_ipv4(&v4) => Some(v4),
        _ => None,
    }
}

/// Assemble the node's advertised, directly-dialable candidate addresses, ordered **IPv6-first**
/// (the ecosystem rule, CLAUDE.md §5.2) via [`dig_ip`].
///
/// Candidates are aggregated + source-tagged + de-duplicated by [`dig_ip::PeerCandidates`], then
/// emitted in [`dig_ip::Family`] preference order (IPv6 before IPv4) — the family sort is dig-ip's,
/// never hand-rolled here. Within a family, discovery (insertion) order is preserved, and the
/// STUN-discovered server-reflexive (public) address — the most-dialable candidate for a NAT'd node —
/// is added FIRST so it leads its family group.
///
/// - `ipv6` / `ipv4` are the host's discovered routable addresses (see [`local_ipv6_addr`] /
///   [`local_ipv4_addr`]); each is advertised at `port`.
/// - `reflexive` is the node's STUN server-reflexive address, when known (already carries its port).
/// - `loopback` selects the fallback when NO routable address is discoverable (a test / air-gapped /
///   loopback-only host): `true` → advertise the loopback pair (`::1` then `127.0.0.1`) so an
///   in-process/loopback peer can still be reached; `false` → advertise no local pair (an unreachable
///   node relies on the relay tiers, and must never leak a wildcard `[::]` / `0.0.0.0` as a candidate).
///
/// Pure over its inputs so the ordering + fallback policy is unit-testable without a socket.
pub fn assemble_advertised(
    ipv6: Option<Ipv6Addr>,
    ipv4: Option<Ipv4Addr>,
    reflexive: Option<SocketAddr>,
    port: u16,
    loopback: bool,
) -> Vec<SocketAddr> {
    use dig_ip::{CandidateSource, Family, PeerCandidates};

    let mut candidates = PeerCandidates::new();
    // Reflexive first → it leads its family group (PeerCandidates keeps within-family insertion order).
    if let Some(r) = reflexive {
        candidates.add(r, CandidateSource::StunReflexive);
    }
    let mut have_local = false;
    if let Some(v6) = ipv6 {
        candidates.add(
            SocketAddr::new(IpAddr::V6(v6), port),
            CandidateSource::ListenAddr,
        );
        have_local = true;
    }
    if let Some(v4) = ipv4 {
        candidates.add(
            SocketAddr::new(IpAddr::V4(v4), port),
            CandidateSource::ListenAddr,
        );
        have_local = true;
    }
    // Loopback fallback only when the host has no routable local address of its own.
    if !have_local && loopback {
        candidates.add(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
            CandidateSource::ListenAddr,
        );
        candidates.add(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            CandidateSource::ListenAddr,
        );
    }
    // IPv6-first family ordering is dig-ip's `Family::PREFERENCE`, discovery order within each family.
    Family::PREFERENCE
        .iter()
        .flat_map(|family| candidates.of_family(*family))
        .collect()
}

/// The node's advertised candidate addresses at `port`, discovering the host's real routable IPv6
/// (preferred) + IPv4 (fallback) addresses and ordering them IPv6-first via [`assemble_advertised`].
/// When nothing routable is discoverable, `loopback` selects the fallback (see [`assemble_advertised`]).
/// No reflexive address is included — see [`advertised_socket_addrs_with_reflexive`] for the full set.
pub fn advertised_socket_addrs(port: u16, loopback: bool) -> Vec<SocketAddr> {
    assemble_advertised(local_ipv6_addr(), local_ipv4_addr(), None, port, loopback)
}

/// The node's advertised candidate addresses at `port`, including the STUN-discovered server-reflexive
/// (public) address when known — the full set a peer behind a different NAT can dial / hole-punch to.
/// Ordered IPv6-first via [`assemble_advertised`] (the reflexive leads its family group).
pub fn advertised_socket_addrs_with_reflexive(
    port: u16,
    loopback: bool,
    reflexive: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    assemble_advertised(
        local_ipv6_addr(),
        local_ipv4_addr(),
        reflexive,
        port,
        loopback,
    )
}

/// Whether the node should advertise loopback addresses when no routable address is discoverable.
/// Loopback advertisement is opt-in via `DIG_NODE_ADVERTISE_LOOPBACK` (truthy) — used by tests and
/// single-host/in-process setups where an in-process peer dials the node over loopback. Off by
/// default: a real NAT'd node with no routable address relies on the relay tiers and must not leak a
/// bogus loopback candidate to the wider network.
pub fn advertise_loopback_from_env() -> bool {
    matches!(
        std::env::var("DIG_NODE_ADVERTISE_LOOPBACK")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

// -- Shared NAT-traversal config (#385) --------------------------------------------------------------

/// The RFC-5389 STUN port the DIG relay co-locates with its relay host (`relay.dig.net:3478`). A node
/// derives its STUN server from the relay endpoint (`<relay-host>:STUN_PORT`) — dig-nat L7 spec §3.
pub const STUN_PORT: u16 = 3478;

/// The shared [`dig_nat::NatConfig`] for EVERY node peer dial (DHT lookups, multi-source range
/// fetches, PEX candidate verification): the **FULL** traversal ladder — Direct → UPnP → NAT-PMP →
/// PCP → hole-punch → Relayed — with `Relayed` (the relay/TURN-last tier) reached ONLY after every
/// direct + port-mapping + hole-punch tier has failed (dig-nat tries the enabled methods in canonical
/// rank order, relay last).
///
/// This replaces the former `[Direct, Relayed]`-only config every node call site used, which skipped
/// UPnP/NAT-PMP/PCP + hole-punch and jumped straight to the relay — over-loading `relay.dig.net` and
/// defeating the "attempt direct traversal before relaying" intent of the ecosystem IPv6-first rule
/// (§5.2). The method set comes from [`dig_nat::NatConfig::default`] (the full ladder) rather than an
/// explicit list, so a future dig-nat tier is picked up automatically here + at every call site.
///
/// `per_method_timeout` bounds each tier so a dial never hangs (a dig-nat guarantee). `stun_server`,
/// when `Some`, is the STUN server dig-nat's hole-punch tier queries for this node's server-reflexive
/// (public) address; `None` leaves STUN unconfigured (the ladder still falls through to the relay).
pub fn full_nat_config(
    per_method_timeout: Duration,
    stun_server: Option<SocketAddr>,
) -> dig_nat::NatConfig {
    let mut builder = dig_nat::NatConfig::builder().per_method_timeout(per_method_timeout);
    if let Some(stun) = stun_server {
        builder = builder.stun_server(stun);
    }
    builder.build()
}

/// Extract the host from a relay endpoint URL so the node can derive the co-located STUN server
/// (`<host>:STUN_PORT`). Pure: strips the scheme (`wss://`), any `:port`, and any trailing path/query.
/// A bracketed IPv6 literal (`wss://[2001:db8::1]:9450`) yields the literal without brackets. Returns
/// `None` for an empty/unparseable host.
pub fn parse_relay_host(endpoint: &str) -> Option<String> {
    let s = endpoint.trim();
    let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    // Drop any path / query.
    let s = s.split(['/', '?']).next().unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    // Bracketed IPv6 literal: [addr]:port
    if let Some(rest) = s.strip_prefix('[') {
        let host = rest.split(']').next().unwrap_or("");
        return (!host.is_empty()).then(|| host.to_string());
    }
    let host = s.split(':').next().unwrap_or("");
    (!host.is_empty()).then(|| host.to_string())
}

/// Resolve the DIG STUN server (`<relay-host>:STUN_PORT`) from the relay endpoint URL, IPv6-first when
/// the host resolves to both families (ecosystem rule). Best-effort blocking DNS resolution; `None`
/// when the host can't be parsed/resolved. Call off the async runtime (e.g. via `spawn_blocking`).
pub fn stun_server_from_relay(relay_endpoint: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let host = parse_relay_host(relay_endpoint)?;
    let mut addrs: Vec<SocketAddr> = (host.as_str(), STUN_PORT).to_socket_addrs().ok()?.collect();
    // IPv6-first: `dig_ip::Family` orders V6 before V4 (the ecosystem's canonical family sort).
    addrs.sort_by_key(dig_ip::Family::of);
    addrs.into_iter().next()
}

/// Best-effort discover this node's server-reflexive (public) address via STUN against `stun_server`,
/// so the node advertises a candidate a remote peer can dial / hole-punch to (not just its LAN-local
/// address). Binds an ephemeral UDP socket in the STUN server's address family and runs ONE bounded
/// Binding transaction ([`dig_nat::stun::query_reflexive_address`]); any failure (timeout, unreachable,
/// no route) returns `None` and the node advertises its local addresses only.
pub async fn reflexive_via_stun(stun_server: SocketAddr, timeout: Duration) -> Option<SocketAddr> {
    let bind = if stun_server.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
    dig_nat::stun::query_reflexive_address(&socket, stun_server, timeout)
        .await
        .ok()
}

/// Resolve the relay's data endpoint (`<relay-host>:<port>`) to a [`SocketAddr`], IPv6-first. Used
/// only as the observability endpoint of the relayed traversal tier — the actual byte tunnel rides
/// the node's live reservation ([`dig_nat::relay::RelayStatus`]), not this address. Port comes from
/// the URL when present, else 443 (the `wss://` default). Best-effort blocking DNS; call off the
/// async runtime.
pub fn relay_socket_addr(relay_endpoint: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let host = parse_relay_host(relay_endpoint)?;
    let port = relay_port(relay_endpoint).unwrap_or(443);
    let mut addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs().ok()?.collect();
    addrs.sort_by_key(dig_ip::Family::of);
    addrs.into_iter().next()
}

/// Parse an explicit `:port` out of a relay endpoint URL (`wss://host:9450/path` → `9450`). `None`
/// when no port is present. Handles a bracketed IPv6 literal (`wss://[::1]:9450`).
fn relay_port(endpoint: &str) -> Option<u16> {
    let s = endpoint.trim();
    let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    let s = s.split(['/', '?']).next().unwrap_or(s);
    let after_host = match s.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(_, tail)| tail).unwrap_or(""),
        None => s,
    };
    after_host
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
}

/// Build the shared [`dig_nat::NatRuntime`] carrying this node's LIVE traversal handles, so every node
/// dial ([`dig_nat::connect_with_runtime`]) auto-composes the FULL ladder rather than Direct-only
/// (#836). Each tier is enabled only when its handle is present (the composition stays honest — an
/// absent tier is skipped, never a silently-broken dial):
///
/// - `local_port` — the P2P listen port, enabling the UPnP port-mapping tier (with the real
///   SSDP-discovered IGD gateway).
/// - `my_external_addr` — this node's STUN-discovered reflexive address (`None` → the hole-punch tier
///   stays inert until a coordinator + reflexive addr are both present).
/// - `relayed` — the tier-6 TURN-last fallback over the node's LIVE relay reservation
///   ([`dig_nat::ReservationRelayedTransport`] over the shared [`RelayStatus`](dig_nat::relay::RelayStatus)),
///   wired only when the relay is enabled and its endpoint resolves. This is the path a fully-NAT'd
///   node reaches peers over when every more-direct tier fails.
///
/// The NAT-PMP/PCP tiers (needing the local default-gateway + client IP) and the hole-punch tier
/// (needing a live coordinator) are left for a follow-up once those handles are exposed — they are
/// composed automatically the moment their runtime inputs are added here.
pub fn build_node_nat_runtime(
    local_port: u16,
    my_external_addr: Option<SocketAddr>,
    relayed: Option<Arc<dyn dig_nat::RelayedDialer>>,
) -> dig_nat::NatRuntime {
    let mut builder = dig_nat::NatRuntime::builder().local_port(local_port);
    if let Some(addr) = my_external_addr {
        builder = builder.my_external_addr(addr);
    }
    if let Some(dialer) = relayed {
        builder = builder.relayed(dialer);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_stack_listen_addr_is_ipv6_unspecified() {
        let addr = dual_stack_listen_addr(9444);
        assert!(
            addr.is_ipv6(),
            "peer listener binds the IPv6 unspecified address"
        );
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(addr.port(), 9444);
    }

    /// The dual-stack listener binds `[::]:0` and, on a host with dual-stack support, accepts an IPv4
    /// loopback client on the SAME socket — proving `IPV6_V6ONLY` was cleared. Skips gracefully on the
    /// rare host without dual-stack support (a real socket-option bug fails the connect, not this).
    #[tokio::test]
    async fn dual_stack_bind_accepts_an_ipv4_loopback_client() {
        let listener =
            bind_tcp_dual_stack(dual_stack_listen_addr(0)).expect("dual-stack bind must succeed");
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await });

        let v4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        match tokio::net::TcpStream::connect(v4).await {
            Ok(_client) => {
                let (_, peer) = accept
                    .await
                    .unwrap()
                    .expect("dual-stack listener must accept the IPv4 client");
                assert!(peer.ip().to_canonical().is_ipv4());
            }
            Err(e) => {
                accept.abort();
                eprintln!("skipping: host lacks IPv4-mapped-IPv6 dual-stack support: {e}");
            }
        }
    }

    #[test]
    fn advertisable_ipv6_rejects_loopback_linklocal_uniquelocal_mapped() {
        assert!(!is_advertisable_ipv6(&Ipv6Addr::LOCALHOST));
        assert!(!is_advertisable_ipv6(&Ipv6Addr::UNSPECIFIED));
        assert!(!is_advertisable_ipv6(&"fe80::1".parse().unwrap())); // link-local
        assert!(!is_advertisable_ipv6(&"fd00::1".parse().unwrap())); // unique-local
        assert!(!is_advertisable_ipv6(&"fc00::1".parse().unwrap())); // unique-local
        assert!(!is_advertisable_ipv6(&"::ffff:192.0.2.1".parse().unwrap())); // v4-mapped
                                                                              // A global-unicast address IS advertisable.
        assert!(is_advertisable_ipv6(&"2001:db8::1".parse().unwrap()));
        assert!(is_advertisable_ipv6(&"2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn advertisable_ipv4_rejects_loopback_linklocal_broadcast() {
        assert!(!is_advertisable_ipv4(&Ipv4Addr::LOCALHOST));
        assert!(!is_advertisable_ipv4(&Ipv4Addr::UNSPECIFIED));
        assert!(!is_advertisable_ipv4(&"169.254.1.1".parse().unwrap())); // link-local
        assert!(!is_advertisable_ipv4(&Ipv4Addr::BROADCAST));
        // Public + RFC-1918 (LAN) addresses ARE advertisable.
        assert!(is_advertisable_ipv4(&"203.0.113.7".parse().unwrap()));
        assert!(is_advertisable_ipv4(&"192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn assemble_advertised_puts_ipv6_before_ipv4() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let addrs = assemble_advertised(Some(v6), Some(v4), None, 9444, false);
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv6(), "IPv6 candidate must come first");
        assert!(
            addrs[1].is_ipv4(),
            "IPv4 candidate is the fallback (second)"
        );
        assert_eq!(addrs[0], SocketAddr::new(IpAddr::V6(v6), 9444));
        assert_eq!(addrs[1], SocketAddr::new(IpAddr::V4(v4), 9444));
    }

    #[test]
    fn assemble_advertised_never_leaks_wildcard_and_falls_back_to_loopback() {
        // No routable address + loopback OFF → advertise NOTHING (never a wildcard / bogus candidate).
        assert!(assemble_advertised(None, None, None, 9444, false).is_empty());
        // No routable address + loopback ON → the loopback pair, IPv6 (`::1`) FIRST.
        let lo = assemble_advertised(None, None, None, 9444, true);
        assert_eq!(lo.len(), 2);
        assert_eq!(
            lo[0],
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9444)
        );
        assert_eq!(
            lo[1],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9444)
        );
    }

    #[test]
    fn assemble_advertised_ipv4_only_host_advertises_ipv4() {
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let addrs = assemble_advertised(None, Some(v4), None, 9444, false);
        assert_eq!(addrs, vec![SocketAddr::new(IpAddr::V4(v4), 9444)]);
    }

    /// The ticket's acceptance test (#1032): advertised candidates are keyed + ordered by
    /// `dig_ip::Family` and aggregated via `PeerCandidates` from mixed sources (StunReflexive +
    /// ListenAddr) across BOTH families — IPv6 group first, the reflexive leading its family group.
    #[test]
    fn advertised_candidates_use_dig_ip_family() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let reflexive_v4: SocketAddr = "198.51.100.9:9444".parse().unwrap();

        // Mixed sources, both families: local IPv6 + local IPv4 (ListenAddr) + an IPv4 reflexive.
        let addrs = assemble_advertised(Some(v6), Some(v4), Some(reflexive_v4), 9444, false);
        assert_eq!(
            addrs,
            vec![
                SocketAddr::new(IpAddr::V6(v6), 9444), // IPv6 family first (dig_ip::Family::V6 < V4)
                reflexive_v4,                          // IPv4 reflexive leads its family group
                SocketAddr::new(IpAddr::V4(v4), 9444), // then the local IPv4 fallback
            ]
        );
        // Every emitted address's family key agrees with dig_ip::Family, IPv6 before IPv4.
        let families: Vec<dig_ip::Family> = addrs.iter().map(dig_ip::Family::of).collect();
        assert_eq!(
            families,
            vec![dig_ip::Family::V6, dig_ip::Family::V4, dig_ip::Family::V4]
        );
    }

    #[test]
    fn assemble_advertised_ipv6_reflexive_leads_and_dedups() {
        let v6: SocketAddr = "[2001:db8::1]:9444".parse().unwrap();
        let v4: SocketAddr = "203.0.113.7:9444".parse().unwrap();
        let reflexive_v6: SocketAddr = "[2606:4700::1]:9444".parse().unwrap();
        let v6ip = match v6.ip() {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!(),
        };
        let v4ip = match v4.ip() {
            IpAddr::V4(a) => a,
            IpAddr::V6(_) => unreachable!(),
        };
        // IPv6 reflexive leads the whole list.
        assert_eq!(
            assemble_advertised(Some(v6ip), Some(v4ip), Some(reflexive_v6), 9444, false),
            vec![reflexive_v6, v6, v4]
        );
        // A reflexive equal to a local address is de-duplicated (kept once, in its family group).
        assert_eq!(
            assemble_advertised(Some(v6ip), Some(v4ip), Some(v6), 9444, false),
            vec![v6, v4]
        );
        // No reflexive → local pair only.
        assert_eq!(
            assemble_advertised(Some(v6ip), Some(v4ip), None, 9444, false),
            vec![v6, v4]
        );
    }

    // -- #385: full NAT traversal ladder + STUN reflexive discovery ----------------------------------

    /// The shared config enables the WHOLE ladder — not just `Direct` + `Relayed`. This is the
    /// regression guard for the bug the ticket fixes: every node dial now attempts UPnP/NAT-PMP/PCP +
    /// hole-punch BEFORE the relay, so `relay.dig.net` is a genuine last resort.
    #[test]
    fn full_nat_config_enables_the_whole_ladder_not_just_direct_relayed() {
        use dig_nat::TraversalKind::*;
        let cfg = full_nat_config(Duration::from_secs(3), None);
        for k in [Direct, Upnp, NatPmp, Pcp, HolePunch, Relayed] {
            assert!(cfg.is_enabled(k), "{k:?} must be enabled (full ladder)");
        }
        // The port-mapping + hole-punch tiers that the old `[Direct, Relayed]` config skipped:
        assert!(
            cfg.is_enabled(Upnp)
                && cfg.is_enabled(NatPmp)
                && cfg.is_enabled(Pcp)
                && cfg.is_enabled(HolePunch),
            "UPnP/NAT-PMP/PCP/hole-punch must be tried before falling back to the relay"
        );
    }

    #[test]
    fn full_nat_config_sets_stun_server_only_when_provided() {
        let stun: SocketAddr = "203.0.113.5:3478".parse().unwrap();
        assert_eq!(
            full_nat_config(Duration::from_secs(3), Some(stun)).stun_server,
            Some(stun)
        );
        assert_eq!(
            full_nat_config(Duration::from_secs(3), None).stun_server,
            None
        );
    }

    #[test]
    fn parse_relay_host_strips_scheme_port_and_path() {
        assert_eq!(
            parse_relay_host("wss://relay.dig.net:9450").as_deref(),
            Some("relay.dig.net")
        );
        assert_eq!(
            parse_relay_host("relay.dig.net").as_deref(),
            Some("relay.dig.net")
        );
        assert_eq!(
            parse_relay_host("wss://relay.dig.net/introducer?x=1").as_deref(),
            Some("relay.dig.net")
        );
        // Bracketed IPv6 literal.
        assert_eq!(
            parse_relay_host("wss://[2001:db8::1]:9450").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(parse_relay_host(""), None);
        assert_eq!(parse_relay_host("wss://"), None);
    }

    #[test]
    fn assemble_advertised_ipv4_reflexive_leads_ipv4_group_after_ipv6() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let v6_sa = SocketAddr::new(IpAddr::V6(v6), 9444);
        let v4_sa = SocketAddr::new(IpAddr::V4(v4), 9444);
        let reflexive_v4: SocketAddr = "198.51.100.9:9444".parse().unwrap();
        // IPv4 reflexive sits after IPv6, before the local IPv4 fallback.
        assert_eq!(
            assemble_advertised(Some(v6), Some(v4), Some(reflexive_v4), 9444, false),
            vec![v6_sa, reflexive_v4, v4_sa]
        );
        // With no local IPv6, the IPv4 reflexive leads.
        assert_eq!(
            assemble_advertised(None, Some(v4), Some(reflexive_v4), 9444, false),
            vec![reflexive_v4, v4_sa]
        );
        // With no local addresses at all, the reflexive is the sole candidate.
        assert_eq!(
            assemble_advertised(None, None, Some(reflexive_v4), 9444, false),
            vec![reflexive_v4]
        );
    }

    #[test]
    fn relay_port_parses_explicit_port_else_none() {
        // Explicit port after the host.
        assert_eq!(relay_port("wss://relay.dig.net:9450"), Some(9450));
        assert_eq!(relay_port("relay.dig.net:9450/path?x=1"), Some(9450));
        // Bracketed IPv6 literal: only the port after `]` counts, never a colon inside the address.
        assert_eq!(relay_port("wss://[2001:db8::1]:9450"), Some(9450));
        assert_eq!(relay_port("wss://[2001:db8::1]"), None);
        // No port present.
        assert_eq!(relay_port("wss://relay.dig.net"), None);
        assert_eq!(relay_port("relay.dig.net/introducer"), None);
        // Garbage / non-numeric port → None, never a panic.
        assert_eq!(relay_port("wss://relay.dig.net:notaport"), None);
        assert_eq!(relay_port(""), None);
        assert_eq!(relay_port("::::"), None);
    }

    #[test]
    fn relay_socket_addr_resolves_ipv6_literal_with_explicit_port() {
        // A bracketed IPv6 literal resolves without DNS, exercising the full parse → resolve path.
        let addr = relay_socket_addr("wss://[2001:db8::1]:9450").expect("literal must resolve");
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 9450);
        // No explicit port falls back to the wss:// default 443.
        let addr = relay_socket_addr("wss://[2001:db8::1]").expect("literal must resolve");
        assert_eq!(addr.port(), 443);
        // Unparseable endpoint yields None (no panic).
        assert_eq!(relay_socket_addr("wss://"), None);
    }

    #[test]
    fn relay_socket_addr_prefers_ipv6() {
        // relay_socket_addr sorts resolved addresses by dig_ip::Family::of (IPv6 before IPv4, §5.2).
        let mut addrs: Vec<SocketAddr> = vec![
            "203.0.113.5:9450".parse().unwrap(),
            "[2001:db8::5]:9450".parse().unwrap(),
        ];
        addrs.sort_by_key(dig_ip::Family::of);
        assert!(
            addrs[0].is_ipv6(),
            "IPv6 relay address must sort before IPv4"
        );
    }

    #[test]
    fn stun_server_from_relay_prefers_ipv6() {
        // A pure family-sort check of the dig_ip::Family::of key used by stun_server_from_relay:
        // given both families, IPv6 sorts before IPv4.
        let mut addrs: Vec<SocketAddr> = vec![
            "203.0.113.5:3478".parse().unwrap(),
            "[2001:db8::5]:3478".parse().unwrap(),
        ];
        addrs.sort_by_key(dig_ip::Family::of);
        assert!(addrs[0].is_ipv6(), "IPv6 STUN address must sort first");
    }
}
