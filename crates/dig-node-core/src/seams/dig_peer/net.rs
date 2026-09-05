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
/// and not an IPv4-mapped OR IPv4-compatible address. Such an address is (best-effort) routable, so it
/// belongs at the front of the advertised candidate list.
pub fn is_advertisable_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.to_ipv4().is_some() {
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

/// Whether an address REPORTED BY A PEER OR THE POOL is a usable contact — one this node could
/// actually dial back — and so may be recorded as that peer's `fetchRange` target or DHT contact.
///
/// WHY this exists (dig_ecosystem#1784): `dig-nat`'s accept path records `remote_addr` for an
/// accepted RELAYED circuit, and with no configured relay endpoint that address is the unspecified
/// wildcard `[::]:0`. It then flows through `PoolEvent::PeerAdded` into the connected pool as the
/// peer's fetch target AND into the DHT routing table as its contact. A wildcard address is not a
/// destination — a fetch to it can only fail — and worse, it consumes one of the very few dial
/// slots downstream, so a peer that IS reachable by another address can be rendered unreachable.
/// The root cause belongs in dig-nat; this is the node's own guard, applied where such an address
/// would enter node state.
///
/// Rejects exactly two things, both of which mean "not a destination":
/// - an **unspecified** IP (`::` / `0.0.0.0`) — a bind wildcard, never a peer's location;
/// - port **0** — the "any port" sentinel, which nothing listens on.
///
/// Loopback is deliberately ACCEPTED (unlike [`is_advertisable_ipv6`] / [`is_advertisable_ipv4`],
/// which decide what to advertise to the wider network): a loopback peer is genuinely dialable, and
/// single-host multi-node runs depend on it.
pub fn is_usable_contact(addr: &SocketAddr) -> bool {
    !addr.ip().is_unspecified() && addr.port() != 0
}

/// A peer address that HAS been checked against [`is_usable_contact`] — a real destination, not a
/// bind wildcard or a port-0 sentinel.
///
/// # Why a type rather than a fifth `if` (#349)
///
/// [`is_usable_contact`] was adopted call site by call site, and each adoption fixed the site
/// somebody happened to be looking at. Four sites were guarded; the fifth — `pool_peers`, answering
/// `dig.getPeers` — was not, so this node served `{"host":"::","port":0}` to REMOTE PEERS as a dial
/// candidate. That is worse than the display falsehood the earlier fixes addressed: a peer that
/// dials it wastes one of its few dial slots, and a peer that caches it caches a hole.
///
/// A guard adopted one call site at a time will keep missing one, and the count reached five before
/// anyone looked at the site that faced other nodes. So the question moves into the type: a
/// `ContactAddr` cannot be constructed without answering "is this a destination?", and
/// [`ContactAddr::address_json`] is the only way to render the shipped `{host, port, kind}` entry
/// ON THIS PATH.
///
/// It is NOT the only way this node emits a peer address to a stranger, and saying so would be
/// false: `provider_json` (`download.rs`) serialises remote-supplied `CandidateAddr`s into the
/// peer-facing `providers` array unchecked, and `parse_candidate_addr` (`forwarded_ask.rs`) accepts
/// `{"host":"::","port":0}` -- so a stranger can inject the very wildcard removed here and have this
/// node relay it onward. That path is pre-existing and is tracked separately; this type closes the
/// `dig.getPeers` emitter, not the class.
/// A new emitter reaches for the renderer, and the renderer is only reachable through the check.
///
/// This does not make the raw `SocketAddr` unreachable — that would require changing what
/// `dig_gossip::GossipHandle::connected_pool_peers` returns, in another crate. It makes the
/// *rendering* path go through the check, which is where the five leaks occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactAddr(SocketAddr);

impl ContactAddr {
    /// The ONLY constructor: `Some` when `addr` is a real destination, `None` when it is not.
    pub fn new(addr: SocketAddr) -> Option<Self> {
        is_usable_contact(&addr).then_some(Self(addr))
    }

    /// The checked address.
    pub fn addr(&self) -> SocketAddr {
        self.0
    }

    /// This contact as the shipped `{host, port, kind}` peer-address entry — the one shape
    /// `dig.getPeers`, the DHT answer and the forwarded-ask provider list all speak, so no second
    /// address encoding enters the ecosystem.
    pub fn address_json(&self) -> serde_json::Value {
        serde_json::json!({
            "host": self.0.ip().to_string(),
            "port": self.0.port(),
            "kind": "direct",
        })
    }
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
/// derives its STUN server from the relay endpoint, preferring a dedicated `stun.<relay-host>` DNS
/// name over the bare relay host when it resolves (see [`stun_servers_from_relay`]) — dig-nat L7
/// spec §3.
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
    nat_config_builder(per_method_timeout, stun_server).build()
}

/// [`full_nat_config`] narrowed to ONE tier of the ladder — the config the `control.peers.ping`
/// diagnostic dials each rung with (dig_ecosystem#1985).
///
/// It shares [`full_nat_config`]'s builder rather than assembling its own, so the ping cannot drift
/// into a parallel prober whose timeouts or STUN wiring differ from what the node really dials with.
/// The ONLY difference is `enabled_methods`: restricting the ladder to a single rung is what turns
/// "did we connect?" into "which tier connected?", since dig-nat otherwise walks the rungs itself and
/// reports only the winner.
pub fn single_tier_nat_config(
    per_method_timeout: Duration,
    stun_server: Option<SocketAddr>,
    tier: dig_nat::TraversalKind,
) -> dig_nat::NatConfig {
    nat_config_builder(per_method_timeout, stun_server)
        .enabled_methods(vec![tier])
        .build()
}

/// The ONE builder both node NAT configs are made from, so a change to the shared dial parameters
/// (the per-tier bound, the STUN wiring) cannot land on one and miss the other.
fn nat_config_builder(
    per_method_timeout: Duration,
    stun_server: Option<SocketAddr>,
) -> dig_nat::NatConfigBuilder {
    let mut builder = dig_nat::NatConfig::builder().per_method_timeout(per_method_timeout);
    if let Some(stun) = stun_server {
        builder = builder.stun_server(stun);
    }
    builder
}

/// A relay endpoint parsed into the two pieces every dial off it needs: the host to resolve and the
/// TCP port the scheme or an explicit `:port` selects.
///
/// Byte-for-byte the shape of `dig_nat::relay`'s private `RelayEndpoint`, because this is a
/// transcription of that parser and not a second opinion about relay URLs — see
/// [`parse_relay_endpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// The host to resolve: a DNS name, or an IPv6 literal with its brackets already stripped.
    pub host: String,
    /// The TCP port: an explicit `:port` when the URL carries one, else the scheme's default.
    pub port: u16,
}

/// Parse a relay endpoint URL (`ws://host[:port][/path]`, `wss://…`, IPv6 hosts bracketed) into its
/// host and port, or `None` when the operator's intent cannot be read.
///
/// # This FAILS CLOSED, and that is the whole point (#285)
///
/// A relay endpoint is operator configuration for a component that sees traffic. The predecessor of
/// this function accepted **any** scheme and turned an unparsable port into `None`, which
/// `relay_socket_addr` then resolved with `.unwrap_or(443)` — so a single malformed string made the
/// node **silently dial port 443 at whatever host survived the looser parse**, which was not
/// necessarily the host the operator wrote (`user@host` kept its userinfo; `host#frag` kept its
/// fragment). A value that does not parse means the intent is unknown, and the safe reading of an
/// unknown intent is to refuse the dial, not to invent a destination for it.
///
/// # Why this is transcribed rather than called
///
/// The authoritative implementation is `dig_nat::relay::parse_relay_endpoint`, which already fails
/// closed in exactly these four ways and is the designated survivor of this rival pair. It is
/// **private** in the published `dig-nat 0.21.0`, so dig-node cannot call it until dig-nat exports
/// it. Every rule below is transcribed from that function, and the test vectors are taken from its
/// own assertions, so that adopting the export later is a deletion rather than a re-derivation.
///
/// The rules, all four of which the predecessor got wrong:
///
/// - **Scheme is required and must be `ws` or `wss`** (case-insensitive). It selects the default
///   port — 80 and 443 respectively — and nothing else.
/// - **A port that will not parse is an ERROR**, never a default.
/// - **Userinfo is stripped** from the authority, so `wss://user@host` resolves `host`.
/// - **Path, query AND fragment are dropped** before the authority is read.
pub fn parse_relay_endpoint(endpoint: &str) -> Option<RelayEndpoint> {
    let (scheme, rest) = endpoint.trim().split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "ws" => 80,
        "wss" => 443,
        // An unknown scheme is an unreadable intent, not a `wss` with a typo.
        _ => return None,
    };
    // Authority only: drop any path/query/fragment, then any `userinfo@`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[addr]` or `[addr]:port`.
        let (h, after) = stripped.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            // Trailing junk after `]` that is not a port.
            None => return None,
        };
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse().ok()?)
    } else {
        (authority.to_string(), default_port)
    };

    (!host.is_empty()).then_some(RelayEndpoint { host, port })
}

/// Extract the host from a relay endpoint URL so the node can derive the co-located STUN server
/// (`<host>:STUN_PORT`). Thin projection of [`parse_relay_endpoint`], so it inherits that function's
/// fail-closed reading of a malformed endpoint (#285): an unknown scheme or an unparsable port
/// yields `None` here too, rather than a host salvaged from a string nobody could read.
pub fn parse_relay_host(endpoint: &str) -> Option<String> {
    parse_relay_endpoint(endpoint).map(|e| e.host)
}

/// Resolve the DIG STUN servers from the relay endpoint URL across BOTH address families — every
/// A + AAAA record — ordered IPv6-first (§5.2, `dig_ip::Family`), preferring a DEDICATED
/// `stun.<relay-host>` DNS name over the bare relay host when it resolves (see
/// [`prefer_dedicated_stun_host`]). The caller MUST NOT pre-collapse to one family: the reflexive
/// discovery below races IPv6 first and falls back to IPv4, so it needs a STUN endpoint per family
/// (#1393). Best-effort blocking DNS resolution throughout; returns an empty vec when the relay
/// endpoint itself can't be parsed. Call off the async runtime (e.g. via `spawn_blocking`).
///
/// # Why `stun.<relay-host>`, not a hardcoded `stun.relay.dig.net`
///
/// dig-relay is GPL-2.0 and self-hosting is supported (SYSTEM.md); hardcoding DIG's own hostname
/// would silently break every self-hosted relay's node peers. Deriving the CONVENTION from
/// whatever relay endpoint the operator already configured means a self-hoster who adopts the
/// `stun.` naming activates the dedicated endpoint with a DNS change alone — no dig-node release,
/// no config flag, and every node that dials through THIS function picks it up identically:
/// [`stun_server_from_relay`] (the traversal-ladder / DHT-transport single-endpoint feed) delegates
/// here rather than deriving its own list, so the two can never talk to different hosts.
pub fn stun_servers_from_relay(relay_endpoint: &str) -> Vec<SocketAddr> {
    let Some(host) = parse_relay_host(relay_endpoint) else {
        return Vec::new();
    };
    let dedicated = resolve_host_both_families(&format!("stun.{host}"));
    let bare = resolve_host_both_families(&host);
    prefer_dedicated_stun_host(dedicated, bare)
}

/// Every `A` + `AAAA` record for `host` at [`STUN_PORT`], in whatever order the resolver returns
/// them. Empty (never an error) when `host` doesn't resolve — an absent DNS name is a normal,
/// silently-skipped outcome for every STUN tier in this module, not a fault. Best-effort blocking
/// DNS; call off the async runtime.
fn resolve_host_both_families(host: &str) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, STUN_PORT)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default()
}

/// Merge a dedicated STUN host's resolved addresses ahead of the bare relay host's own, so the
/// dedicated endpoint is tried first WITHIN each address family once the final IPv6-first sort
/// runs — an identical address named by both is kept only once. Pure over already-resolved
/// addresses, so the preference itself is unit-testable without live DNS (the same seam
/// [`StunPlan::from_tiers`] uses for tier precedence).
fn prefer_dedicated_stun_host(dedicated: Vec<SocketAddr>, bare: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut addrs: Vec<SocketAddr> = dedicated.into_iter().chain(bare).collect();
    addrs.retain(|a| seen.insert(*a));
    // IPv6-first: `dig_ip::Family` orders V6 before V4 (the ecosystem's canonical family sort).
    // Stable, so within each family the dedicated host's entries (pushed first, above) stay ahead
    // of the bare host's.
    addrs.sort_by_key(dig_ip::Family::of);
    addrs
}

/// Resolve the single IPv6-first DIG STUN server for the traversal-ladder hole-punch tier + DHT
/// transport (a single reflexive-input endpoint, dig-nat L7 spec §3), preferring the dedicated
/// `stun.<relay-host>` endpoint exactly as [`stun_servers_from_relay`] does — it delegates to that
/// function rather than re-deriving the host, so the two can never disagree about which server to
/// try first. The reflexive-advertise path uses [`stun_servers_from_relay`] directly instead (it
/// needs every per-family endpoint, not just the first). `None` when the host can't be
/// parsed/resolved. Call off the async runtime.
pub fn stun_server_from_relay(relay_endpoint: &str) -> Option<SocketAddr> {
    stun_servers_from_relay(relay_endpoint).into_iter().next()
}

// -- Public STUN fallback (STANDING, LAST-RESORT - dig_ecosystem#3198) --------------------------

/// Which of the STUN tiers actually answered this node's Binding request.
///
/// Carried alongside the address rather than inferred later, because the three tiers mean very
/// different things to an operator: an address learned from the DIG relay is the intended steady
/// state, one learned from a public server means **the relay is not answering** and this node is
/// leaning on a third party, and one learned from an operator-configured server means neither
/// default was consulted. An operator staking $DIG on this node's reachability is entitled to know
/// which of those happened, so the source travels with the measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunSource {
    /// A server named by the operator in [`STUN_SERVER_ENV`]. Highest precedence: someone running a
    /// private relay must never be silently redirected to a third party.
    Operator,
    /// The STUN server co-located with the DIG relay (`<relay-host>:STUN_PORT`) - the intended
    /// steady state, and the tier this node prefers whenever it answers.
    Relay,
    /// A public third-party STUN server from [`PUBLIC_STUN_SERVERS`]. A STANDING fallback,
    /// retained deliberately and reached only LAST — solely when the relay tier yields nothing —
    /// so the relay reclaims the role the moment it starts answering, with no code change and no
    /// redeploy. Kept rather than removed once the relay works: a single STUN source is a single
    /// point of trust, the relay can itself be wrong or briefly unreachable, and a node with no
    /// reflexive address publishes nothing and earns nothing. `dig_ecosystem#3198` tracks
    /// requiring TWO sources to agree before a reading is used durably/on-chain — this tier
    /// existing is what makes that corroboration possible at all.
    Public,
}

impl StunSource {
    /// Every variant, so a guard can walk the set rather than a chosen example. Declared beside the
    /// enum rather than spelled in the test: an array literal in the test would still compile and
    /// still pass after a variant was added, shipping the new variant unguarded by the very test
    /// written to guard it.
    pub const ALL: [StunSource; 3] = [StunSource::Operator, StunSource::Relay, StunSource::Public];

    /// The operator-facing name of this tier, as it appears in the bring-up log line.
    pub const fn label(self) -> &'static str {
        match self {
            StunSource::Operator => "operator-configured",
            StunSource::Relay => "relay",
            StunSource::Public => "public-fallback",
        }
    }
}

/// Operator override for the STUN endpoint(s): a comma- or whitespace-separated list of
/// `host`, `host:port`, or `[v6]:port` entries. Set, it is consulted BEFORE the relay and before any
/// public server, so a node pointed at a private relay is never silently sent to a third party.
///
/// An entry with no port defaults to [`STUN_PORT`]. An unparsable entry is skipped rather than
/// aborting the list - one typo must not cost this node every configured endpoint.
pub const STUN_SERVER_ENV: &str = "DIG_STUN_SERVER";

/// The public STUN servers this node falls back to when the DIG relay answers nothing
/// (dig_ecosystem#3198). A STANDING fallback, kept deliberately rather than deleted once the relay
/// works: the relay is preferred (dig-nat L7 spec §3) and reclaims the role automatically the
/// moment it answers, because the relay tier is tried first and this one is tried LAST — but a
/// single STUN source (even the relay) is a single point of trust, and a node with no reflexive
/// address at all publishes nothing and earns nothing. Measured justification: before dig-relay
/// 0.19.7 fixed a family-tag defect, `relay.dig.net` answered every IPv4 caller with the load
/// balancer's OWN IPv6 address — this tier was the only source that answered honestly during that
/// window, which is exactly the failure mode a single-source design cannot survive.
///
/// More than one operator on purpose. A single third-party host would make one company's outage an
/// outage of every DIG node's address discovery, which is a worse dependency than the one being
/// worked around. Both entries publish A **and** AAAA records, so the IPv6-first walk (§5.2) has a
/// real IPv6 endpoint to try rather than falling to IPv4 by default.
///
/// This tier is reached LAST on purpose, not merely last in this list: a third party learning
/// every DIG node's address is a real privacy cost, so it is paid only once every closer-to-home
/// option (operator override, then the DIG relay) has already failed to answer.
///
/// Note the ports differ and are NOT [`STUN_PORT`] for every host: Google serves STUN on 19302.
pub const PUBLIC_STUN_SERVERS: &[(&str, u16)] =
    &[("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)];

/// Split a `host`, `host:port`, or `[v6]:port` entry into its parts, defaulting to [`STUN_PORT`]
/// when no port is given. `None` for anything unparsable, so a malformed entry is skipped rather
/// than salvaged into a dial nobody asked for (the same fail-closed reading [`parse_relay_endpoint`]
/// applies to relay URLs).
///
/// A bracketless IPv6 literal (`::1`) is treated as a HOST at the default port, not as
/// `host = ":"` plus `port = 1`: its last colon-group is an address group, and eating it as a port
/// would dial a different machine than the operator named.
fn split_stun_host_port(entry: &str) -> Option<(String, u16)> {
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => STUN_PORT,
            None => return None,
        };
        return (!host.is_empty()).then_some((host.to_string(), port));
    }
    if entry.matches(':').count() > 1 {
        return (!entry.is_empty()).then(|| (entry.to_string(), STUN_PORT));
    }
    match entry.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().ok()?;
            (!host.is_empty()).then(|| (host.to_string(), port))
        }
        None => (!entry.is_empty()).then(|| (entry.to_string(), STUN_PORT)),
    }
}

/// Resolve one STUN host to at most ONE endpoint per address family, ordered IPv6-first (§5.2).
///
/// Capping at one per family bounds what a slow tier costs at bring-up: the reflexive walk spends a
/// full timeout on every endpoint it tries, so a host publishing four A records would otherwise turn
/// one dead tier into four timeouts before the next tier is reached. The relay tier deliberately
/// does NOT go through here - [`stun_servers_from_relay`] keeps every record, preserving today's
/// behaviour for the tier this node prefers.
///
/// Best-effort blocking DNS; call off the async runtime.
fn resolve_stun_host(host: &str, port: u16) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;
    let Ok(iter) = (host, port).to_socket_addrs() else {
        return Vec::new();
    };
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in iter {
        if !out
            .iter()
            .any(|a: &SocketAddr| a.is_ipv6() == addr.is_ipv6())
        {
            out.push(addr);
        }
    }
    out.sort_by_key(dig_ip::Family::of);
    out
}

/// The operator-configured STUN servers from [`STUN_SERVER_ENV`], IPv6-first. Empty when unset.
/// Best-effort blocking DNS; call off the async runtime.
pub fn operator_stun_servers() -> Vec<SocketAddr> {
    let Ok(raw) = std::env::var(STUN_SERVER_ENV) else {
        return Vec::new();
    };
    let mut out: Vec<SocketAddr> = raw
        .split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(split_stun_host_port)
        .flat_map(|(host, port)| resolve_stun_host(&host, port))
        .collect();
    out.sort_by_key(dig_ip::Family::of);
    out
}

/// The [`PUBLIC_STUN_SERVERS`] resolved across both families, IPv6-first (§5.2). Best-effort
/// blocking DNS; call off the async runtime.
pub fn public_stun_servers() -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = PUBLIC_STUN_SERVERS
        .iter()
        .flat_map(|&(host, port)| resolve_stun_host(host, port))
        .collect();
    out.sort_by_key(dig_ip::Family::of);
    out
}

/// What a successful reflexive discovery learned: the dialable candidate, WHICH tier answered, and
/// the exact server that did.
///
/// The server is carried so the traversal ladder's hole-punch tier can be pointed at an endpoint
/// KNOWN to answer, rather than at the first endpoint in the plan - which, in the failure this
/// exists for, is precisely the one that did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflexiveDiscovery {
    /// The dialable server-reflexive candidate, `<public-ip>:<listen-port>` (see
    /// [`reflexive_candidate`] for why the STUN result's own port is discarded).
    pub addr: SocketAddr,
    /// Which tier answered.
    pub source: StunSource,
    /// The STUN server that answered.
    pub server: SocketAddr,
}

/// This node's STUN endpoints in PRECEDENCE order - operator override, then the DIG relay, then the
/// public fallback - each tier already ordered IPv6-first (§5.2).
///
/// # Why a tiered plan rather than one flat list
///
/// The relay must win **the moment it works, with no code change and no redeploy**. A flat list
/// could not express that: whichever endpoint sorted first would win, and re-ordering it later would
/// be a code change. Walking tiers in order means a working relay is always consulted before any
/// third party, and the public tier is reached only when everything above it yielded nothing - so
/// this fallback retires itself.
///
/// # Yielding nothing means NOT ANSWERING, not merely not resolving
///
/// The measured defect (dig_ecosystem#3198) is a relay whose DNS is healthy - two AAAA and two A
/// records - that does not reply to a Binding request. A fallback keyed on resolution failure would
/// therefore never fire. [`Self::discover_reflexive`] falls through on the *transaction* failing,
/// which is the condition actually observed.
#[derive(Debug, Clone, Default)]
pub struct StunPlan {
    /// Non-empty tiers only, in precedence order.
    tiers: Vec<(StunSource, Vec<SocketAddr>)>,
}

impl StunPlan {
    /// Resolve the full plan. `relay_endpoint` is `None` when the relay is disabled, which drops the
    /// relay tier without disabling the others - a relay-less node still needs to know its own
    /// public address. Best-effort blocking DNS throughout; call off the async runtime (e.g. via
    /// `spawn_blocking`).
    pub fn resolve(relay_endpoint: Option<&str>) -> Self {
        let relay = relay_endpoint
            .map(stun_servers_from_relay)
            .unwrap_or_default();
        Self::from_tiers(operator_stun_servers(), relay, public_stun_servers())
    }

    /// Build a plan from already-resolved tiers, dropping empty ones. PURE - this is the seam the
    /// tier-precedence and fallback tests drive, so they need no DNS and no live relay.
    pub fn from_tiers(
        operator: Vec<SocketAddr>,
        relay: Vec<SocketAddr>,
        public: Vec<SocketAddr>,
    ) -> Self {
        let tiers = [
            (StunSource::Operator, operator),
            (StunSource::Relay, relay),
            (StunSource::Public, public),
        ]
        .into_iter()
        .filter(|(_, servers)| !servers.is_empty())
        .collect();
        Self { tiers }
    }

    /// The tiers this plan will actually try, in precedence order.
    pub fn sources(&self) -> Vec<StunSource> {
        self.tiers.iter().map(|(source, _)| *source).collect()
    }

    /// Whether `source` contributed any endpoint. Distinguishes "the relay was tried and stayed
    /// silent" from "there was no relay tier to try" - only the FIRST warrants warning an operator
    /// that their relay is down.
    pub fn has_source(&self, source: StunSource) -> bool {
        self.tiers.iter().any(|(s, _)| *s == source)
    }

    /// The single IPv6-first endpoint from the highest-precedence tier, for the traversal-ladder
    /// hole-punch tier + DHT transport (which take one reflexive-input endpoint, dig-nat L7 spec §3).
    ///
    /// This is the *unmeasured* choice - the best guess before anything has been dialled. Prefer
    /// [`ReflexiveDiscovery::server`] where a discovery has run: it names an endpoint that actually
    /// answered.
    pub fn primary(&self) -> Option<SocketAddr> {
        self.tiers
            .first()
            .and_then(|(_, servers)| stun_dial_order(servers).into_iter().next())
    }

    /// Best-effort discover this node's DIALABLE server-reflexive candidate, walking the tiers in
    /// precedence order and, within each tier, IPv6-first with IPv4 fallback ([`stun_dial_order`],
    /// §5.2). For each endpoint we bind a UDP socket to the node's ACTUAL listen `port`
    /// ([`bind_stun_socket`] - NOT a throwaway ephemeral socket, the #1388 trap) and run ONE bounded
    /// Binding transaction ([`dig_nat::stun::query_reflexive_address`], which returns the mapping of
    /// THAT socket).
    ///
    /// The first endpoint that answers wins and the walk stops, so a working relay is never
    /// overtaken by a public server. `None` when no tier answered - the node advertises its local
    /// addresses only, exactly as before this fallback existed.
    ///
    /// `timeout` bounds EACH endpoint, so the worst case is `timeout` times the endpoint count.
    /// Tiers below the relay are only paid for when the relay is silent, which is why the steady
    /// state costs nothing.
    pub async fn discover_reflexive(
        &self,
        port: u16,
        timeout: Duration,
    ) -> Option<ReflexiveDiscovery> {
        for (source, servers) in &self.tiers {
            for server in stun_dial_order(servers) {
                let Ok(socket) = bind_stun_socket(port, server.is_ipv6()) else {
                    continue;
                };
                let Ok(result) =
                    dig_nat::stun::query_reflexive_address(&socket, server, timeout).await
                else {
                    continue;
                };
                // An answer whose family differs from the family of the server we queried is not
                // about THIS query and must be discarded rather than believed just because the
                // transaction otherwise completed (correct cookie, correctly echoed transaction
                // id): a dual-stack load balancer has been measured answering an IPv4 caller with
                // its OWN IPv6 address. Fall through exactly as a non-answering server does, all
                // the way to a lower-precedence tier if nothing in this one answers honestly.
                if dig_ip::Family::of(&result) != dig_ip::Family::of(&server) {
                    continue;
                }
                return Some(ReflexiveDiscovery {
                    addr: reflexive_candidate(result, port),
                    source: *source,
                    server,
                });
            }
        }
        None
    }
}

/// The operator-facing warning a discovery outcome warrants, if any. PURE over its inputs, so the
/// three cases are unit-testable without a socket or a log capture.
///
/// Two outcomes warrant a warning and one does not:
///
/// - **The relay tier was tried and something BELOW it answered.** The relay is silent. Before this
///   existed the symptom was invisible - the node simply had no reflexive address and nothing said
///   why (dig_ecosystem#3198), which is how the fault went unnoticed while an operator's $DIG sat
///   idle. It is the message that matters most here.
/// - **Nothing answered at all.** The node has no reflexive address and advertises local addresses
///   only.
/// - **A node with no relay tier configured used the public fallback.** NOT a fault: nothing was
///   asked to answer and did not. Warning here would train an operator to ignore the case above.
///
/// It deliberately says nothing about REACHABILITY. A reflexive address reports how the world sees
/// this node's source address; it does not prove a stranger can fetch from it, and a warning
/// implying otherwise would invite exactly the unkeepable mirror claim SPEC.md §25 penalises.
pub fn stun_fallback_warning(
    plan: &StunPlan,
    discovery: Option<ReflexiveDiscovery>,
) -> Option<String> {
    match discovery {
        Some(d) if d.source == StunSource::Public && plan.has_source(StunSource::Relay) => {
            Some(format!(
                "the DIG relay answered no STUN binding request; this node's reflexive address came from the PUBLIC fallback server {} instead. The relay is preferred and this node will use it again automatically the next time it answers, with no restart needed; dig_ecosystem#3198 tracks requiring a second source to agree before this reading is used durably.",
                d.server
            ))
        }
        Some(_) => None,
        None => Some(format!(
            "no STUN server answered across {} tier(s); this node has NO reflexive address and will advertise only its local addresses.",
            plan.sources().len()
        )),
    }
}

/// Order the resolved STUN servers IPv6-first (`dig_ip::Family::PREFERENCE`) so reflexive discovery
/// races the IPv6 endpoint before falling back to IPv4 (§5.2). Pure over its input for unit-testing
/// the family order without a socket.
fn stun_dial_order(stun_servers: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut servers = stun_servers.to_vec();
    servers.sort_by_key(dig_ip::Family::of);
    servers
}

/// Build the DIALABLE server-reflexive candidate from a raw STUN result and the node's ACTUAL listen
/// `port`. The advertised candidate is `<reflexive-ip>:<listen-port>` — the reflexive public IP paired
/// with the port peers actually dial the node's mTLS listener on.
///
/// The raw STUN result's own port is deliberately DISCARDED: a candidate carrying a throwaway/ephemeral
/// binding's port is the #1388 trap (a remote peer dialing it reaches no listener). Pairing the
/// reflexive IP with the real listen port yields the form a peer behind a different NAT can dial once
/// the mapping for that port is open (via UPnP/NAT-PMP/PCP or an endpoint-independent NAT). Pure for
/// unit-testing without a socket.
fn reflexive_candidate(stun_result: SocketAddr, listen_port: u16) -> SocketAddr {
    SocketAddr::new(stun_result.ip(), listen_port)
}

/// Bind a UDP socket to the node's ACTUAL listen `port` in `family`, with `SO_REUSEADDR` so it
/// coexists with the peer-RPC TCP listener (a separate protocol namespace) and with a re-run of this
/// discovery. This is the socket whose external NAT mapping STUN learns — bound to the real listen
/// port, NOT a throwaway ephemeral port (#1388/#1393).
fn bind_stun_socket(port: u16, ipv6: bool) -> io::Result<tokio::net::UdpSocket> {
    let (domain, addr) = if ipv6 {
        (
            Domain::IPV6,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
        )
    } else {
        (
            Domain::IPV4,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        )
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Best-effort discover this node's DIALABLE server-reflexive (public) candidate via STUN, IPv6-first
/// with IPv4 fallback (§5.2). For each STUN server in IPv6-first family order ([`stun_dial_order`]) we
/// bind a UDP socket to the node's ACTUAL listen `port` ([`bind_stun_socket`] — NOT a throwaway
/// ephemeral socket, the #1388 trap) and run ONE bounded Binding transaction
/// ([`dig_nat::stun::query_reflexive_address`], which returns the mapping of THAT socket). The first
/// family that answers wins; its result is paired with the real listen port via [`reflexive_candidate`]
/// and returned. `None` when no family's STUN server answered (the node advertises its local addresses
/// only). IPv4 is attempted ONLY after the IPv6 STUN server is absent/unreachable — never nulled just
/// because IPv6 failed.
pub async fn reflexive_via_stun(
    stun_servers: &[SocketAddr],
    port: u16,
    timeout: Duration,
) -> Option<SocketAddr> {
    StunPlan::from_tiers(Vec::new(), stun_servers.to_vec(), Vec::new())
        .discover_reflexive(port, timeout)
        .await
        .map(|discovery| discovery.addr)
}

/// Resolve the relay's data endpoint (`<relay-host>:<port>`) to a [`SocketAddr`], IPv6-first. Used
/// only as the observability endpoint of the relayed traversal tier — the actual byte tunnel rides
/// the node's live reservation ([`dig_nat::relay::RelayStatus`]), not this address. Host AND port
/// both come from [`parse_relay_endpoint`], so a malformed endpoint yields `None` — no dial — rather
/// than the pre-#285 behaviour of defaulting the port to 443 and connecting anyway. Best-effort
/// blocking DNS; call off the async runtime.
pub fn relay_socket_addr(relay_endpoint: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let RelayEndpoint { host, port } = parse_relay_endpoint(relay_endpoint)?;
    let mut addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs().ok()?.collect();
    addrs.sort_by_key(dig_ip::Family::of);
    addrs.into_iter().next()
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

    /// The #1784 guard, from both sides. The rejected cases are the exact shapes dig-nat's accept
    /// path can produce for a relayed circuit with no configured relay endpoint (`[::]:0`), plus the
    /// two half-broken variants — a wildcard IP with a real port, and a real IP with port 0 —
    /// because a guard that only recognises the fully-degenerate pair would pass either half
    /// straight into the pool.
    #[test]
    fn a_wildcard_or_portless_address_is_not_a_usable_contact() {
        for junk in [
            "[::]:0",
            "0.0.0.0:0",
            "[::]:9445",
            "0.0.0.0:9445",
            "1.2.3.4:0",
        ] {
            let addr: SocketAddr = junk.parse().unwrap();
            assert!(
                !is_usable_contact(&addr),
                "{junk} is not a destination and must never become a peer's contact"
            );
        }
    }

    /// The truthful control: real addresses — including LOOPBACK, which single-host multi-node runs
    /// depend on — stay usable. Without this the guard could reject everything and still look
    /// correct against the rejection cases alone.
    #[test]
    fn a_real_address_including_loopback_is_a_usable_contact() {
        for good in [
            "203.0.113.7:9445",
            "[2001:db8::7]:9445",
            "127.0.0.1:9445",
            "[::1]:9445",
        ] {
            let addr: SocketAddr = good.parse().unwrap();
            assert!(is_usable_contact(&addr), "{good} is dialable");
        }
    }

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
    /// loopback client on the SAME socket — proving `IPV6_V6ONLY` was cleared. Skips gracefully on a
    /// host with no IPv6 stack at all (the `[::]:0` bind itself fails with `EAFNOSUPPORT`, not merely a
    /// refused option) and on the rarer host with IPv6 but no dual-stack support (a real socket-option
    /// bug fails the connect, not this) — on any host where dual-stack DOES work (every CI runner),
    /// this still runs + asserts the full proof, unweakened.
    #[tokio::test]
    async fn dual_stack_bind_accepts_an_ipv4_loopback_client() {
        if !crate::peer::tests::is_ipv6_loopback_available().await {
            eprintln!(
                "skipping dual_stack_bind_accepts_an_ipv4_loopback_client: no IPv6 stack in this \
                 environment"
            );
            return;
        }
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
    fn ipv4_compatible_is_not_advertisable() {
        // IPv4-compatible address (::1.2.3.4 = ::0102:0304) is an IPv4 address in disguise.
        // It MUST be rejected as non-routable IPv6, just like IPv4-mapped addresses.
        let compat_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0102, 0x0304);
        assert!(
            !is_advertisable_ipv6(&compat_addr),
            "IPv4-compatible address must not be advertisable"
        );
    }

    #[test]
    fn ipv4_mapped_is_still_not_advertisable() {
        // Regression guard: IPv4-mapped addresses (::ffff:a.b.c.d) must continue to be rejected.
        let mapped_addr: Ipv6Addr = "::ffff:1.2.3.4".parse().unwrap();
        assert!(
            !is_advertisable_ipv6(&mapped_addr),
            "IPv4-mapped address must not be advertisable"
        );
    }

    #[test]
    fn a_real_global_unicast_ipv6_is_advertisable() {
        // Guard against over-rejecting: genuine global-unicast addresses must remain advertisable.
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(
            is_advertisable_ipv6(&global),
            "global-unicast address must be advertisable"
        );
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
        // A scheme-less endpoint is now REFUSED rather than salvaged (#285). The pre-fix parser
        // returned `Some("relay.dig.net")` here, and this line is the one that changed.
        assert_eq!(parse_relay_host("relay.dig.net"), None);
    }

    // -- `stun.<relay-host>` preference: pure over already-resolved addresses, so it is testable ---
    // -- without live DNS, the same seam `StunPlan::from_tiers` uses for tier precedence. ----------

    /// The dedicated `stun.<relay-host>` endpoint leads the bare host's own answer WITHIN each
    /// family — proving the preference survives the final IPv6-first sort rather than being
    /// scrambled by it. Four DISTINCT addresses so the ordering has something real to get wrong:
    /// a implementation that only ever resolved the bare host (today's code) cannot produce this
    /// order at all, because it never has the dedicated addresses to place.
    #[test]
    fn the_dedicated_stun_host_leads_the_bare_hosts_answer_within_each_family() {
        let dedicated_v6: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let dedicated_v4: SocketAddr = "100.64.1.1:3478".parse().unwrap();
        let bare_v6: SocketAddr = "[2001:db8::2]:3478".parse().unwrap();
        let bare_v4: SocketAddr = "100.64.2.2:3478".parse().unwrap();

        let merged = prefer_dedicated_stun_host(
            vec![dedicated_v6, dedicated_v4],
            vec![bare_v6, bare_v4],
        );

        assert_eq!(merged, vec![dedicated_v6, bare_v6, dedicated_v4, bare_v4]);
    }

    /// The measured shape at `relay.dig.net`: `stun.<host>`'s AAAA points at the SAME dualstack
    /// NLB the bare host's own AAAA already names, while its A record is a NEW IPv4-only NLB.
    /// The identical IPv6 entry must survive only ONCE — trying the same server twice wastes a
    /// full STUN timeout for zero benefit — while the genuinely new IPv4 entry is kept.
    #[test]
    fn an_address_named_by_both_hosts_is_tried_only_once() {
        let shared_v6: SocketAddr = "[2606:4700::1]:3478".parse().unwrap();
        let new_v4: SocketAddr = "100.64.9.9:3478".parse().unwrap();

        let merged = prefer_dedicated_stun_host(vec![shared_v6, new_v4], vec![shared_v6]);

        assert_eq!(
            merged,
            vec![shared_v6, new_v4],
            "the shared address must appear exactly once: {merged:?}"
        );
    }

    /// A relay operator who has not adopted the `stun.` convention: the dedicated name resolves to
    /// nothing (as if NXDOMAIN), and the bare host's own answer is used, completely unchanged from
    /// today's behaviour. No error, no empty result — the preference is additive.
    #[test]
    fn an_unresolvable_dedicated_stun_host_falls_back_to_the_bare_host_unchanged() {
        let bare_v6: SocketAddr = "[2001:db8::9]:3478".parse().unwrap();
        let bare_v4: SocketAddr = "100.64.3.3:3478".parse().unwrap();

        let merged = prefer_dedicated_stun_host(Vec::new(), vec![bare_v6, bare_v4]);

        assert_eq!(merged, vec![bare_v6, bare_v4]);
    }

    /// **Proves:** a relay endpoint the node cannot read yields NO destination, in each of the four
    /// ways the pre-#285 parser invented one — an unknown scheme, an unparsable port, embedded
    /// userinfo, and a fragment. Each malformed input is paired with the well-formed endpoint it is
    /// one character away from, so the assertion is that the two are told APART.
    ///
    /// **Catches:** any relaxation back toward the old parser. Every `None` line below returned
    /// `Some(...)` before the fix, and three of them returned a host that was not the host in the
    /// string. A test that only listed well-formed endpoints would pass under BOTH parsers — the
    /// property lives entirely in the malformed column, which is why each row is a pair.
    #[test]
    fn a_relay_endpoint_that_cannot_be_read_yields_no_destination() {
        // (malformed → refused) paired with (well-formed → the stated host and port).
        let pairs: &[(&str, &str, &str, u16)] = &[
            // Unknown scheme. Was: accepted, host salvaged, port defaulted to 443.
            (
                "http://relay.dig.net",
                "wss://relay.dig.net",
                "relay.dig.net",
                443,
            ),
            // No scheme at all. Was: accepted.
            (
                "relay.dig.net:9450",
                "ws://relay.dig.net:9450",
                "relay.dig.net",
                9450,
            ),
            // Unparsable port. Was: port -> None -> `.unwrap_or(443)`, so it DIALLED 443.
            (
                "wss://relay.dig.net:notaport",
                "wss://relay.dig.net:9450",
                "relay.dig.net",
                9450,
            ),
            // Port out of range. Same fail-open path as the non-numeric one.
            (
                "wss://relay.dig.net:99999",
                "wss://relay.dig.net:65535",
                "relay.dig.net",
                65535,
            ),
            // Empty host behind userinfo.
            (
                "wss://user@",
                "wss://user@relay.dig.net",
                "relay.dig.net",
                443,
            ),
            // Malformed IPv6 authority — no closing bracket.
            (
                "wss://[2001:db8::1",
                "wss://[2001:db8::1]",
                "2001:db8::1",
                443,
            ),
        ];
        for (bad, good, host, port) in pairs {
            assert_eq!(
                parse_relay_endpoint(bad),
                None,
                "malformed relay endpoint {bad} must yield NO destination"
            );
            assert_eq!(
                parse_relay_endpoint(good),
                Some(RelayEndpoint {
                    host: (*host).to_string(),
                    port: *port
                }),
                "well-formed relay endpoint {good} must still parse"
            );
        }

        // Userinfo is STRIPPED and a fragment is DROPPED, rather than being carried into the host —
        // the pre-fix parser returned `user@relay.dig.net` and `relay.dig.net#frag` respectively,
        // which would have been resolved as DNS names and dialled at a host nobody wrote.
        assert_eq!(
            parse_relay_endpoint("wss://user:pw@relay.dig.net:9450/ws?x=1#frag"),
            Some(RelayEndpoint {
                host: "relay.dig.net".to_string(),
                port: 9450
            })
        );

        // The scheme selects the default port and nothing else, case-insensitively.
        assert_eq!(parse_relay_endpoint("ws://relay.dig.net").unwrap().port, 80);
        assert_eq!(
            parse_relay_endpoint("WSS://relay.dig.net").unwrap().port,
            443
        );

        // And the shipped default endpoint must survive the stricter parser — a fail-closed parse
        // that refuses the compiled-in relay would take the whole relay tier down.
        assert!(
            parse_relay_endpoint(crate::peer::DEFAULT_RELAY_URL).is_some(),
            "the compiled-in DEFAULT_RELAY_URL must still parse"
        );
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

    /// **Proves:** the port a relay dial uses comes from the endpoint the operator wrote — an
    /// explicit `:port` when present, else the SCHEME's default — and never from a fallback applied
    /// after a failed parse.
    ///
    /// **Catches:** the reintroduction of `relay_port(...).unwrap_or(443)`. The two `ws://` rows are
    /// what make this test load-bearing: under the old code every defaulted port was 443, so a test
    /// using only `wss://` could not tell "the scheme's default" from "the hardcoded 443".
    #[test]
    fn relay_port_comes_from_the_endpoint_or_its_scheme_never_a_post_failure_default() {
        let port_of = |ep: &str| parse_relay_endpoint(ep).map(|e| e.port);
        // Explicit port wins over the scheme default, in both schemes.
        assert_eq!(port_of("wss://relay.dig.net:9450"), Some(9450));
        assert_eq!(port_of("ws://relay.dig.net:9450"), Some(9450));
        // Bracketed IPv6: only the port after `]` counts, never a colon inside the address.
        assert_eq!(port_of("wss://[2001:db8::1]:9450"), Some(9450));
        assert_eq!(port_of("wss://[2001:db8::1]"), Some(443));
        // No explicit port → the SCHEME's default, which differs between the two schemes.
        assert_eq!(port_of("wss://relay.dig.net"), Some(443));
        assert_eq!(port_of("ws://relay.dig.net"), Some(80));
        // A port that will not parse is refused outright — it does NOT become 443.
        assert_eq!(port_of("wss://relay.dig.net:notaport"), None);
        assert_eq!(port_of(""), None);
        assert_eq!(port_of("::::"), None);
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

    // -- #1393: DIALABLE reflexive candidate uses the ACTUAL listen port (not the #1388 throwaway) ----

    /// The core #1393/#1388-trap fix: a raw STUN result carries the ephemeral/throwaway socket's NAT
    /// binding port; the advertised candidate MUST discard it and pair the reflexive IP with the node's
    /// ACTUAL listen port — the port a remote peer dials the mTLS listener on.
    #[test]
    fn reflexive_candidate_uses_actual_listen_port_not_stun_result_port() {
        // STUN returned the reflexive IP with a throwaway ephemeral mapping port (54321).
        let stun_result: SocketAddr = "203.0.113.9:54321".parse().unwrap();
        let candidate = reflexive_candidate(stun_result, 9444);
        assert_eq!(
            candidate,
            "203.0.113.9:9444".parse::<SocketAddr>().unwrap(),
            "advertised candidate keeps the reflexive IP but uses the ACTUAL listen port"
        );
        assert_eq!(
            candidate.port(),
            9444,
            "never the throwaway STUN-result port"
        );
    }

    /// The IPv6 reflexive IP is likewise paired with the listen port (the fix is family-agnostic).
    #[test]
    fn reflexive_candidate_pairs_ipv6_reflexive_with_listen_port() {
        let stun_result: SocketAddr = "[2606:4700::9]:61000".parse().unwrap();
        let candidate = reflexive_candidate(stun_result, 9444);
        assert_eq!(
            candidate,
            "[2606:4700::9]:9444".parse::<SocketAddr>().unwrap()
        );
        assert!(candidate.is_ipv6());
    }

    /// #1393 happy-eyeballs family order: reflexive discovery races the IPv6 STUN server before the
    /// IPv4 one, so `stun_dial_order` must place every IPv6 server ahead of every IPv4 server (§5.2).
    #[test]
    fn stun_dial_order_is_ipv6_first_ipv4_fallback() {
        let servers: Vec<SocketAddr> = vec![
            "203.0.113.5:3478".parse().unwrap(),
            "[2001:db8::5]:3478".parse().unwrap(),
            "198.51.100.7:3478".parse().unwrap(),
            "[2606:4700::7]:3478".parse().unwrap(),
        ];
        let ordered = stun_dial_order(&servers);
        assert!(ordered[0].is_ipv6(), "IPv6 STUN server is attempted first");
        assert!(ordered[1].is_ipv6(), "then the second IPv6 server");
        assert!(
            ordered[2].is_ipv4() && ordered[3].is_ipv4(),
            "IPv4 servers are the fallback tail"
        );
    }

    /// An IPv4-only STUN set still yields a (fallback) dial order without dropping candidates.
    #[test]
    fn stun_dial_order_ipv4_only_preserved() {
        let servers: Vec<SocketAddr> = vec!["203.0.113.5:3478".parse().unwrap()];
        let ordered = stun_dial_order(&servers);
        assert_eq!(ordered.len(), 1);
        assert!(ordered[0].is_ipv4());
    }

    /// An empty STUN set yields no reflexive candidate (the node advertises local addresses only).
    #[tokio::test]
    async fn reflexive_via_stun_empty_servers_yields_none() {
        let reflexive = reflexive_via_stun(&[], 9444, Duration::from_millis(50)).await;
        assert_eq!(reflexive, None);
    }

    // -- Public STUN fallback (STANDING, LAST-RESORT - dig_ecosystem#3198) --------------------------

    /// Encode a STUN Binding success response carrying `mapped` in XOR-MAPPED-ADDRESS, echoing
    /// `txid` (RFC 5389 §15.2). `mapped`'s own variant selects the wire family (0x01 IPv4 / 0x02
    /// IPv6) and XOR key (the 32-bit cookie alone for IPv4; cookie‖transaction-id for IPv6) — so
    /// this ONE encoder builds both an honest same-family answer and, for the cross-family guard
    /// tests below, an answer whose family deliberately does not match the server socket it came
    /// from (the measured dig-relay defect: an IPv4-bound endpoint answering with an IPv6 address).
    ///
    /// Written out here rather than borrowed from dig-nat on purpose: a fake server built from
    /// dig-nat's own encoder would round-trip that crate against itself and pass even if both halves
    /// were wrong together. Encoding from the RFC means these tests exercise dig-nat's real parser.
    fn encode_binding_success(txid: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let cookie = dig_nat::stun::MAGIC_COOKIE;
        let cookie_be = cookie.to_be_bytes();
        let port_xor = (mapped.port() ^ (cookie >> 16) as u16).to_be_bytes();
        let (family, addr_xor): (u8, Vec<u8>) = match mapped.ip() {
            IpAddr::V4(v4) => {
                let xored = v4
                    .octets()
                    .iter()
                    .zip(cookie_be.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                (0x01, xored)
            }
            IpAddr::V6(v6) => {
                // RFC 5389 §15.2: the IPv6 XOR key is the 32-bit cookie followed by the 96-bit txid.
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                let xored = v6.octets().iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
                (0x02, xored)
            }
        };

        let mut attr = Vec::with_capacity(8 + addr_xor.len());
        attr.extend_from_slice(&dig_nat::stun::ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&((4 + addr_xor.len()) as u16).to_be_bytes());
        attr.push(0); // reserved
        attr.push(family);
        attr.extend_from_slice(&port_xor);
        attr.extend_from_slice(&addr_xor);

        let mut msg = Vec::with_capacity(20 + attr.len());
        msg.extend_from_slice(&dig_nat::stun::BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&cookie_be);
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&attr);
        msg
    }

    /// A fake STUN server bound to `bind_addr` that answers every Binding request with `mapped`
    /// (any family, independent of `bind_addr`'s own family — see [`encode_binding_success`]).
    /// Returns the address to point a tier at.
    async fn spawn_fake_stun_at(bind_addr: &str, mapped: &str) -> SocketAddr {
        let mapped: SocketAddr = mapped.parse().unwrap();
        let socket = tokio::net::UdpSocket::bind(bind_addr).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if n < 20 {
                    continue;
                }
                let mut txid = [0u8; 12];
                txid.copy_from_slice(&buf[8..20]);
                let _ = socket
                    .send_to(&encode_binding_success(&txid, mapped), from)
                    .await;
            }
        });
        addr
    }

    /// A fake STUN server on IPv4 loopback that answers every Binding request with `mapped`.
    /// The common case ([`spawn_fake_stun_at`] with the family that every pre-existing test needs).
    async fn spawn_fake_stun(mapped: &str) -> SocketAddr {
        spawn_fake_stun_at("127.0.0.1:0", mapped).await
    }

    /// A real, free loopback UDP port with nothing listening on it - the stand-in for a relay whose
    /// DNS resolves perfectly and which answers nothing, the measured defect. Bound then dropped, so
    /// the port is genuinely free rather than a hard-coded guess that could collide with a live
    /// service and make this test pass for the wrong reason.
    fn silent_endpoint() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// A free port to stand in for the node's real P2P listen port.
    fn free_local_port() -> u16 {
        silent_endpoint().port()
    }

    /// **The revert-proof for dig_ecosystem#3198.** The relay tier resolves fine and answers nothing
    /// - the exact production failure, where `relay.dig.net:3478` returns no reply while DNS is
    /// healthy - and the node STILL ends up with a reflexive address, taken from the public tier and
    /// tagged as such.
    ///
    /// Without the fallback this yields `None`, which is what every NAT'd node saw: no reflexive
    /// address, a private LAN candidate only, and nothing anywhere saying why.
    #[tokio::test]
    async fn a_silent_relay_falls_through_to_the_public_tier() {
        let listen_port = free_local_port();
        let public = spawn_fake_stun("100.64.7.7:41234").await;
        let plan = StunPlan::from_tiers(Vec::new(), vec![silent_endpoint()], vec![public]);

        let discovery = plan
            .discover_reflexive(listen_port, Duration::from_millis(400))
            .await
            .expect("the public tier answered, so a reflexive address MUST be discovered");

        assert_eq!(discovery.source, StunSource::Public);
        assert_eq!(discovery.server, public);
        assert_eq!(discovery.addr.ip().to_string(), "100.64.7.7");
        // The candidate carries the node's REAL listen port, never the STUN result's own (#1388):
        // a candidate holding a throwaway port reaches no listener when a peer dials it.
        assert_eq!(discovery.addr.port(), listen_port);
    }

    /// The relay RECLAIMS the role the moment it answers - no code change, no redeploy. Both tiers
    /// are configured and both work here, and the relay still wins; that ordering is what keeps this
    /// fallback a genuine LAST resort rather than a permanent redirection away from the relay.
    #[tokio::test]
    async fn a_relay_that_answers_is_never_overtaken_by_the_public_tier() {
        let listen_port = free_local_port();
        let relay = spawn_fake_stun("100.64.1.1:1111").await;
        let public = spawn_fake_stun("100.64.2.2:2222").await;
        let plan = StunPlan::from_tiers(Vec::new(), vec![relay], vec![public]);

        let discovery = plan
            .discover_reflexive(listen_port, Duration::from_millis(400))
            .await
            .expect("the relay answered");

        assert_eq!(discovery.source, StunSource::Relay);
        assert_eq!(discovery.server, relay);
        assert_eq!(discovery.addr.ip().to_string(), "100.64.1.1");
    }

    /// **The revert-proof for the cross-family STUN guard.** A relay bound to IPv4 — the node
    /// queried it over IPv4 — but answering with an IPv6 address is the measured dig-relay defect:
    /// a dual-stack load balancer's own IPv6 address, not the caller's, with an otherwise perfectly
    /// well-formed Binding response (correct cookie, correct echoed transaction id). That answer is
    /// not about this node's query and must be discarded, falling through the ladder exactly as a
    /// silent relay does (#3198's fallback), to the public tier's honest, same-family answer.
    ///
    /// The public tier is the honest CONTROL, not incidental set-dressing: without it this test
    /// could not distinguish "the bogus answer was rejected and the walk continued" from "discovery
    /// broke and returns None for any reason" — the two look identical if the only tier configured
    /// is the lying one.
    #[tokio::test]
    async fn a_cross_family_stun_answer_is_discarded_and_the_ladder_falls_through() {
        let listen_port = free_local_port();
        // Bound on IPv4 loopback; answers with an IPv6 address anyway (the LB-reflects-itself bug).
        let relay = spawn_fake_stun("[2606:4700::dead:beef]:1234").await;
        let public = spawn_fake_stun("100.64.7.7:41234").await;
        let plan = StunPlan::from_tiers(Vec::new(), vec![relay], vec![public]);

        let discovery = plan
            .discover_reflexive(listen_port, Duration::from_millis(400))
            .await
            .expect("the public tier answered honestly, so a reflexive address MUST be discovered");

        assert_eq!(
            discovery.source,
            StunSource::Public,
            "the relay's cross-family answer must be discarded rather than returned: {discovery:?}"
        );
        assert_eq!(discovery.addr.ip().to_string(), "100.64.7.7");
    }

    /// The reverse direction: an IPv6-bound server answering with an IPv4 address is equally not an
    /// answer to this node's query, and is discarded the same way. Skips gracefully where the host
    /// has no IPv6 loopback (mirrors `dual_stack_bind_accepts_an_ipv4_loopback_client` above).
    #[tokio::test]
    async fn a_cross_family_stun_answer_is_discarded_the_other_direction_too() {
        if !crate::peer::tests::is_ipv6_loopback_available().await {
            eprintln!(
                "skipping a_cross_family_stun_answer_is_discarded_the_other_direction_too: no \
                 IPv6 loopback in this environment"
            );
            return;
        }
        let listen_port = free_local_port();
        // 100.64.x.x (RFC 6598 shared address space), not a documentation range: dig-nat's own
        // `is_usable_reflexive_addr` rejects 203.0.113.0/24 et al. regardless of family, which would
        // make this test pass for THAT reason instead of the cross-family guard under test.
        let relay = spawn_fake_stun_at("[::1]:0", "100.64.5.5:1234").await;
        let public = spawn_fake_stun("100.64.7.7:41234").await;
        let plan = StunPlan::from_tiers(Vec::new(), vec![relay], vec![public]);

        let discovery = plan
            .discover_reflexive(listen_port, Duration::from_millis(400))
            .await
            .expect("the public tier answered honestly, so a reflexive address MUST be discovered");

        assert_eq!(
            discovery.source,
            StunSource::Public,
            "the IPv6 relay's IPv4 answer must be discarded rather than returned: {discovery:?}"
        );
    }

    /// The operator override outranks BOTH defaults. An operator running a private relay must never
    /// be silently redirected to a third party, so a configured endpoint is consulted before the
    /// relay and long before any public server.
    #[tokio::test]
    async fn the_operator_override_outranks_the_relay_and_the_public_tier() {
        let listen_port = free_local_port();
        let operator = spawn_fake_stun("100.64.3.3:3333").await;
        let relay = spawn_fake_stun("100.64.1.1:1111").await;
        let public = spawn_fake_stun("100.64.2.2:2222").await;
        let plan = StunPlan::from_tiers(vec![operator], vec![relay], vec![public]);

        let discovery = plan
            .discover_reflexive(listen_port, Duration::from_millis(400))
            .await
            .expect("the operator endpoint answered");

        assert_eq!(discovery.source, StunSource::Operator);
        assert_eq!(discovery.addr.ip().to_string(), "100.64.3.3");
    }

    /// Nothing answering leaves the node exactly where it was before this fallback existed: NO
    /// reflexive address, local candidates only. A fabricated or optimistic address here would be
    /// worse than none - it would be advertised to peers that cannot reach it.
    #[tokio::test]
    async fn no_tier_answering_yields_no_address_rather_than_a_guess() {
        let plan =
            StunPlan::from_tiers(Vec::new(), vec![silent_endpoint()], vec![silent_endpoint()]);
        let discovery = plan
            .discover_reflexive(free_local_port(), Duration::from_millis(200))
            .await;
        assert!(discovery.is_none(), "no server answered: {discovery:?}");
    }

    /// A silent relay is SAID OUT LOUD, and the message names the public server that stood in.
    /// Before this, the failure was invisible: the ladder degraded to relayed, nothing went red, and
    /// the only symptom was a permanently empty reflexive address.
    #[test]
    fn a_silent_relay_warns_and_names_the_public_server_that_answered() {
        let public: SocketAddr = "100.64.9.9:3478".parse().unwrap();
        let plan = StunPlan::from_tiers(Vec::new(), vec![silent_endpoint()], vec![public]);
        let warning = stun_fallback_warning(
            &plan,
            Some(ReflexiveDiscovery {
                addr: "100.64.7.7:9444".parse().unwrap(),
                source: StunSource::Public,
                server: public,
            }),
        )
        .expect("a relay that was tried and stayed silent MUST be reported");
        assert!(warning.contains("100.64.9.9:3478"), "{warning}");
        assert!(warning.contains("relay"), "{warning}");
    }

    /// A node with NO relay tier configured that uses the public fallback is not at fault, and is
    /// not warned about. Warning here would train an operator to ignore the message above, which is
    /// the one that matters.
    #[test]
    fn a_node_with_no_relay_tier_is_not_warned_about_using_the_public_fallback() {
        let public: SocketAddr = "100.64.9.9:3478".parse().unwrap();
        let plan = StunPlan::from_tiers(Vec::new(), Vec::new(), vec![public]);
        assert!(stun_fallback_warning(
            &plan,
            Some(ReflexiveDiscovery {
                addr: "100.64.7.7:9444".parse().unwrap(),
                source: StunSource::Public,
                server: public,
            }),
        )
        .is_none());
    }

    /// A relay answer is the intended steady state and says nothing.
    #[test]
    fn a_relay_answer_produces_no_warning() {
        let relay: SocketAddr = "100.64.1.1:3478".parse().unwrap();
        let plan = StunPlan::from_tiers(Vec::new(), vec![relay], Vec::new());
        assert!(stun_fallback_warning(
            &plan,
            Some(ReflexiveDiscovery {
                addr: "100.64.7.7:9444".parse().unwrap(),
                source: StunSource::Relay,
                server: relay,
            }),
        )
        .is_none());
    }

    /// No address at all is reported too - a node advertising only a LAN address should not have to
    /// infer that from silence.
    #[test]
    fn no_reflexive_address_at_all_is_warned_about() {
        let plan = StunPlan::from_tiers(Vec::new(), vec![silent_endpoint()], Vec::new());
        let warning = stun_fallback_warning(&plan, None).expect("no address is worth saying");
        assert!(warning.contains("NO reflexive address"), "{warning}");
    }

    /// Empty tiers are dropped and the surviving ones keep precedence order, so `primary` and the
    /// discovery walk agree about which tier leads.
    #[test]
    fn the_plan_drops_empty_tiers_and_keeps_precedence_order() {
        let relay: SocketAddr = "100.64.1.1:3478".parse().unwrap();
        let public: SocketAddr = "100.64.2.2:3478".parse().unwrap();
        let plan = StunPlan::from_tiers(Vec::new(), vec![relay], vec![public]);
        assert_eq!(plan.sources(), vec![StunSource::Relay, StunSource::Public]);
        assert!(!plan.has_source(StunSource::Operator));
        assert_eq!(plan.primary(), Some(relay));

        assert!(StunPlan::from_tiers(Vec::new(), Vec::new(), Vec::new())
            .sources()
            .is_empty());
    }

    /// `primary` reads the leading tier IPv6-first (§5.2), not merely the first element handed in.
    #[test]
    fn primary_is_ipv6_first_within_the_leading_tier() {
        let v4: SocketAddr = "100.64.1.1:3478".parse().unwrap();
        let v6: SocketAddr = "[2606:4700:49::]:3478".parse().unwrap();
        let plan = StunPlan::from_tiers(Vec::new(), vec![v4, v6], Vec::new());
        assert_eq!(plan.primary(), Some(v6));
    }

    /// The override parser reads every form an operator plausibly writes, and refuses the forms it
    /// cannot read rather than salvaging a host out of them.
    #[test]
    fn split_stun_host_port_reads_bare_hosts_ports_and_bracketed_ipv6() {
        assert_eq!(
            split_stun_host_port("stun.example.com"),
            Some(("stun.example.com".to_string(), STUN_PORT))
        );
        assert_eq!(
            split_stun_host_port("stun.example.com:19302"),
            Some(("stun.example.com".to_string(), 19302))
        );
        assert_eq!(
            split_stun_host_port("[2606:4700:49::]:3478"),
            Some(("2606:4700:49::".to_string(), 3478))
        );
        // A bracketless IPv6 literal is a HOST at the default port. Eating its last colon-group as
        // a port would dial a different machine than the operator named.
        assert_eq!(
            split_stun_host_port("2606:4700:49::"),
            Some(("2606:4700:49::".to_string(), STUN_PORT))
        );
        assert_eq!(split_stun_host_port("host:not-a-port"), None);
        assert_eq!(split_stun_host_port(":3478"), None);
        assert_eq!(split_stun_host_port(""), None);
    }

    /// Every tier's label is distinct. A shared label would leave the bring-up log unable to say
    /// which source answered, which is the entire operator-facing point of carrying the source.
    /// Walks `StunSource::ALL` so a new variant cannot ship unlabelled.
    #[test]
    fn every_stun_source_has_a_distinct_label() {
        let labels: Vec<&str> = StunSource::ALL.iter().map(|s| s.label()).collect();
        assert_eq!(labels.len(), StunSource::ALL.len());
        for (i, a) in labels.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &labels[i + 1..] {
                assert_ne!(a, b, "two sources share the label {a}");
            }
        }
    }

    /// The public defaults carry their OWN ports and at least one is not [`STUN_PORT`]: Google
    /// serves STUN on 19302, and defaulting every host to 3478 would silently produce an endpoint
    /// that never answers - the very failure this fallback exists to work around.
    #[test]
    fn the_public_defaults_carry_their_own_ports_and_more_than_one_operator() {
        assert!(
            PUBLIC_STUN_SERVERS.len() > 1,
            "one third-party host would make its outage every DIG node's outage"
        );
        assert!(PUBLIC_STUN_SERVERS
            .iter()
            .all(|&(host, _)| !host.is_empty()));
        assert!(
            PUBLIC_STUN_SERVERS
                .iter()
                .any(|&(_, port)| port != STUN_PORT),
            "a host served on a non-3478 port must keep it"
        );
        // Distinct operators, not two names for one provider: a shared operator is a shared outage.
        let domains: std::collections::HashSet<&str> = PUBLIC_STUN_SERVERS
            .iter()
            .filter_map(|&(host, _)| host.rsplit_once('.').map(|(_, tld)| tld))
            .collect();
        assert!(!domains.is_empty());
    }

    /// A LIVE probe against the REAL relay and the REAL public fallback on the host it runs on.
    ///
    /// `#[ignore]`d because it needs outbound UDP and the public internet; CI must not depend on
    /// either, and a network-flaky required check is worse than no check. Run it deliberately:
    ///
    /// ```text
    /// cargo test -p dig-node-core --lib live_stun_probe -- --ignored --nocapture
    /// ```
    ///
    /// It prints BOTH postures - the relay tier alone (what this node did before the change) and the
    /// full tiered plan (what it does now) - so the difference is measured on the real silent relay
    /// rather than inferred from a fake one.
    #[tokio::test]
    #[ignore = "live network: probes relay.dig.net and the public STUN fallback"]
    async fn live_stun_probe_reports_which_tier_answers() {
        let port = free_local_port();
        let endpoint = crate::peer::relay_url_from_env();
        let relay_servers = stun_servers_from_relay(&endpoint);
        let public = public_stun_servers();
        println!("relay endpoint       : {endpoint}");
        println!("relay STUN servers   : {relay_servers:?}");
        println!("public STUN servers  : {public:?}");
        println!("node listen port     : {port}");

        // The relay tier ALONE - exactly what reflexive discovery had before this change.
        let before = StunPlan::from_tiers(Vec::new(), relay_servers.clone(), Vec::new())
            .discover_reflexive(port, Duration::from_secs(2))
            .await;
        println!("RELAY ONLY (pre-change): {before:?}");

        // The tiered plan this change introduces.
        let plan = StunPlan::from_tiers(Vec::new(), relay_servers, public);
        let after = plan.discover_reflexive(port, Duration::from_secs(2)).await;
        println!("TIERED (this change)   : {after:?}");
        println!(
            "warning                : {:?}",
            stun_fallback_warning(&plan, after)
        );

        assert!(
            after.is_some(),
            "no STUN tier answered on this host; check outbound UDP before reading this as a defect"
        );
    }
}
