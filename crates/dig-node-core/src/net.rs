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

/// The node's advertised, directly-dialable candidate addresses at `port`, ordered **IPv6-first**
/// (the ecosystem rule): a routable IPv6 address (when discoverable) precedes the IPv4 fallback.
///
/// `loopback` selects the fallback when NO routable address is discoverable (a test / air-gapped /
/// loopback-only host): `true` → advertise the loopback pair (`::1` then `127.0.0.1`) so an
/// in-process/loopback peer can still be reached; `false` → advertise nothing (an unreachable node
/// relies on the relay tiers, and must never leak a wildcard `[::]` / `0.0.0.0` as a candidate).
///
/// This is a pure function of the discovered addresses so the ordering + fallback policy is
/// unit-testable without a socket (the real discovery lives in [`local_ipv6_addr`]/[`local_ipv4_addr`]).
pub fn order_advertised(
    ipv6: Option<Ipv6Addr>,
    ipv4: Option<Ipv4Addr>,
    port: u16,
    loopback: bool,
) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    if let Some(v6) = ipv6 {
        addrs.push(SocketAddr::new(IpAddr::V6(v6), port));
    }
    if let Some(v4) = ipv4 {
        addrs.push(SocketAddr::new(IpAddr::V4(v4), port));
    }
    if addrs.is_empty() && loopback {
        // Loopback/test fallback: IPv6 loopback FIRST, then IPv4 loopback.
        addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
        addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    addrs
}

/// The node's advertised candidate addresses at `port`, discovering the host's real routable IPv6
/// (preferred) + IPv4 (fallback) addresses and ordering them IPv6-first via [`order_advertised`].
/// When nothing routable is discoverable, `loopback` selects the fallback (see [`order_advertised`]).
pub fn advertised_socket_addrs(port: u16, loopback: bool) -> Vec<SocketAddr> {
    order_advertised(local_ipv6_addr(), local_ipv4_addr(), port, loopback)
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
    fn order_advertised_puts_ipv6_before_ipv4() {
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let addrs = order_advertised(Some(v6), Some(v4), 9444, false);
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
    fn order_advertised_never_leaks_wildcard_and_falls_back_to_loopback() {
        // No routable address + loopback OFF → advertise NOTHING (never a wildcard / bogus candidate).
        assert!(order_advertised(None, None, 9444, false).is_empty());
        // No routable address + loopback ON → the loopback pair, IPv6 (`::1`) FIRST.
        let lo = order_advertised(None, None, 9444, true);
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
    fn order_advertised_ipv4_only_host_advertises_ipv4() {
        let v4: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let addrs = order_advertised(None, Some(v4), 9444, false);
        assert_eq!(addrs, vec![SocketAddr::new(IpAddr::V4(v4), 9444)]);
    }
}
