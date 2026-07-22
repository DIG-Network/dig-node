//! L7 DIG Node peer network (PHASE-2b, #162) — the node↔node peer-to-peer layer.
//!
//! This is the additive peer-to-peer layer that sits BESIDE the existing HTTP §21 read path
//! (rpc.dig.net) and the in-process FFI. It brings up [`dig_gossip`]'s connected **peer pool**
//! (introducer-backed auto-discovery via `relay.dig.net`), serves the **L7 peer RPC** over mTLS to
//! other nodes (`dig.getPeers` / `dig.announce` / `dig.getNetworkInfo` / `dig.getAvailability` /
//! `dig.listInventory` / `dig.fetchRange`), and can ISSUE the same RPC to pool peers (the
//! multi-source download seam).
//!
//! ## What replaced the old `relay.rs`
//!
//! The bespoke in-node relay client (`relay.rs`) is RETIRED. The relay connection now lives inside
//! [`dig_nat`] (the `connect()` NAT-traversal ladder's last-resort tier + the persistent
//! reservation) and [`dig_gossip`] (the introducer-backed pool). dig-node no longer hand-rolls the
//! `RelayMessage` WebSocket wire; it consumes the pool and routes relay reachability through it. The
//! `control.relayStatus` RPC is replaced by `control.peerStatus` (pool-oriented).
//!
//! ## Identity + mTLS (spec §1)
//!
//! All node↔node traffic is mutual-TLS with `peer_id = SHA-256(TLS SubjectPublicKeyInfo DER)`. The
//! TLS certificate is owned by the [`dig_gossip::GossipService`] (chia-ssl, generated once and reused
//! from a stable path under the cache dir), so the node presents ONE consistent `peer_id` on both the
//! pool links it dials and the inbound peer-RPC it serves. `dig-nat` enforces the peer_id on every
//! link; there is no unauthenticated peer channel.
//!
//! ## Where it runs
//!
//! Like the old relay task, the peer network runs ONLY in the standalone `dig-node` binary's
//! [`crate::run`]. The in-process FFI path (the browser) is a pure consumer and opens no peer network,
//! so the byte-exact §21/FFI contract is untouched. `control.peerStatus` is always safe to call (it
//! reports "not running" when no network is up).
//!
//! ## Content location — the dig-dht provider index (#163)
//!
//! Peer DISCOVERY here is the connected pool + `dig.getPeers` (the introducer/gossip sources). Content
//! LOCATION — "who holds capsule X?" beyond the local pool — is the **dig-dht provider index**, wired as
//! the live locator inside [`crate::download::NodeContent`] (`DhtProviderLocator` → `find_providers`);
//! the redirect-on-miss and multi-source fetch paths both resolve holders through it. There is exactly
//! ONE provider path — no separate pool-availability seam.
//!
//! ## Address-family policy — IPv6-first, IPv4-fallback (ecosystem HARD RULE)
//!
//! All peer communication is IPv6-first with IPv4 as the fallback, applied at three points (the
//! mechanics live in [`crate::net`]):
//!
//! - **Listener bind.** The mTLS peer-RPC listener binds the IPv6 unspecified address `[::]:{port}`
//!   as a DUAL-STACK socket (`IPV6_V6ONLY` cleared), so ONE socket serves both native IPv6 peers and
//!   IPv4-mapped peers on the same port. (It does NOT bind `0.0.0.0`, which is IPv4-only.)
//! - **Advertised addresses.** The node advertises its REAL routable candidate addresses (in the DHT
//!   provider record and `dig.getNetworkInfo`), ordered IPv6-first: a global-unicast IPv6 address
//!   (when the host has one) precedes the IPv4 fallback. The wildcard bind address (`[::]`/`0.0.0.0`)
//!   is never advertised (it is not dialable). A NAT'd node with no routable address advertises no
//!   direct candidate and relies on the relay tiers.
//! - **Dialing.** When dialing a discovered peer, the node passes that peer's FULL candidate list to
//!   `dig_nat::PeerTarget::with_addrs`, which orders it IPv6-first; dig-nat's happy-eyeballs dialer
//!   then tries the peer's IPv6 candidate(s) first and falls back to IPv4 (see [`crate::dht`]).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{CachedCapsule, CapsuleStore, KeyManager, PeerNetwork};

// -- Constants ---------------------------------------------------------------------------------------

/// Default relay endpoint (canonical public relay). Overridable with `DIG_RELAY_URL`; `off` disables
/// the reservation.
///
/// Single-sourced from `dig_constants::DIG_RELAY_URL` so the node dials the ONE canonical relay
/// endpoint and can never drift from it. The public relay serves the reservation wire on `:443`
/// (a hard-coded `:9450` here silently failed every stock node's reservation — the port is closed
/// on relay.dig.net; see the WU7 EC2 connect proof).
pub const DEFAULT_RELAY_URL: &str = dig_constants::DIG_RELAY_URL;

/// Default network id a node registers + discovers under (matches dig-gossip / the relay wire).
pub const DEFAULT_NETWORK_ID: &str = "DIG_MAINNET";

/// Default P2P listen port for the mTLS peer-RPC server (the L7 DIG peer RPC — what the node
/// advertises in `dig.getNetworkInfo`'s `listen_addr` and what the DHT hands out as this node's
/// dial address).
pub const DEFAULT_P2P_PORT: u16 = 9444;

/// Default listen port for the dig-gossip connected-peer pool.
///
/// The gossip pool and the mTLS peer-RPC server (`DEFAULT_P2P_PORT`) are TWO distinct listeners in
/// the SAME process serving TWO distinct protocols (the gossip wire vs the L7 DIG peer RPC), so they
/// MUST bind DIFFERENT ports. They both defaulted to `9444`: on Windows a dual-stack `SO_REUSEADDR`
/// bind let both sockets coexist, masking the clash, but on Linux the second bind fails with
/// `EADDRINUSE` and peer-RPC bring-up dies (#871). The pool takes `9444 + 1`; the mTLS peer-RPC keeps
/// the canonical `9444` (it is the advertised/dialed address, so it must not move).
pub const DEFAULT_GOSSIP_PORT: u16 = 9445;

/// Per-window ciphertext cap for a `dig.fetchRange` frame (bytes) — the node window (3 MiB), the same
/// cap the HTTP read path (`WINDOW`) uses.
pub const RANGE_WINDOW: usize = 3 * 1024 * 1024;

/// Maximum concurrent accepted mTLS peer CONNECTIONS the listener will serve at once (audit #179
/// HIGH). The accept loop acquires a permit before spawning each connection's serve task and drops
/// the connection when saturated, so an attacker cannot force unbounded connection tasks (each
/// holding a TLS session + FD + yamux session). Sheds load rather than buffering.
pub const MAX_INFLIGHT_PEER_CONNECTIONS: usize = 512;

/// Maximum concurrent in-flight logical STREAMS a single peer connection may have being served at
/// once (audit #179 HIGH). Each accepted yamux stream acquires a permit before its handler task is
/// spawned; a peer opening streams past this cap has the excess dropped (the stream is closed
/// without a handler) instead of spawning unbounded per-stream tasks. Keyed per connection so one
/// peer cannot starve the others.
pub const MAX_INFLIGHT_STREAMS_PER_CONNECTION: usize = 64;

/// Try to spawn `fut` holding a permit from `sem`; if the semaphore is saturated (no permit
/// available WITHOUT waiting), SHED the work by dropping it (returns `false`) rather than queuing
/// unboundedly. On success the spawned task holds the permit for its whole lifetime, so the live
/// task count can never exceed the semaphore's capacity. This is the single choke point the peer
/// accept loops use to bound concurrency (audit #179 HIGH).
fn spawn_with_permit<F>(sem: &Arc<tokio::sync::Semaphore>, fut: F) -> bool
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // try_acquire_owned never blocks: it returns Err the instant no permit is free, so a saturated
    // node sheds the connection/stream immediately instead of parking a task.
    match Arc::clone(sem).try_acquire_owned() {
        Ok(permit) => {
            tokio::spawn(async move {
                // The permit is moved into the task and released on drop when the task ends.
                let _permit = permit;
                fut.await;
            });
            true
        }
        Err(_) => false,
    }
}

// -- Peer-network status (replaces the old relay-only RelayStatus) -----------------------------------

/// Live, pool-oriented status of the node's peer network, shared (via `Arc`) between the peer-network
/// task and the `control.peerStatus` RPC handler. Cheap atomic reads so the RPC never blocks. This is
/// the pool-oriented successor to the retired relay-only status: it reports whether the peer network
/// is up, the node's own `peer_id`, the connected-pool size, and the relay reservation state.
#[derive(Debug, Default)]
pub struct PeerStatus {
    /// Whether the peer network (pool + peer-RPC server) is running.
    running: AtomicBool,
    /// Whether a relay reservation is currently held (NAT reachability via `relay.dig.net`).
    /// Sourced from `dig-nat`'s live [`dig_nat::relay::RelayStatus::is_connected`] — the REAL
    /// persistent-reservation state, not merely whether a relay is configured (#872).
    relay_reserved: AtomicBool,
    /// Size of the directly-connected peer pool (`GossipStats::connected_peers`).
    connected_peers: AtomicU64,
    /// Peers reachable via the relay reservation (`GossipStats::relay_peer_count`) — the peers
    /// `dig-nat` discovered over the held socket and folded into the pool (#870). Reported
    /// alongside `connected_peers` so `control.peerStatus` reflects relay-reachable peers.
    relay_peer_count: AtomicU64,
    /// The node's own `peer_id` (64-hex SHA-256 of its TLS SPKI DER), once the identity is known.
    peer_id: std::sync::Mutex<Option<String>>,
    /// The most recent peer-network error (best-effort diagnostics).
    last_error: std::sync::Mutex<Option<String>>,
}

impl PeerStatus {
    /// A fresh, not-running status.
    pub fn new() -> Arc<Self> {
        Arc::new(PeerStatus::default())
    }

    /// Mark the peer network running under `peer_id` (clears the last error).
    pub fn set_running(&self, peer_id: String) {
        self.running.store(true, Ordering::Relaxed);
        *self.peer_id.lock().unwrap() = Some(peer_id);
        *self.last_error.lock().unwrap() = None;
    }

    /// Update the connected-pool size, the relay-reachable peer count, and the real relay-reservation
    /// flag (called from the maintenance loop). `relay_reserved` is `dig-nat`'s live reservation state
    /// ([`dig_nat::relay::RelayStatus::is_connected`]), not a "relay configured" proxy (#872).
    pub fn set_pool(&self, connected_peers: u64, relay_peer_count: u64, relay_reserved: bool) {
        self.connected_peers
            .store(connected_peers, Ordering::Relaxed);
        self.relay_peer_count
            .store(relay_peer_count, Ordering::Relaxed);
        self.relay_reserved.store(relay_reserved, Ordering::Relaxed);
    }

    /// Record a peer-network error (best-effort; does not stop the node).
    pub fn set_error(&self, error: String) {
        *self.last_error.lock().unwrap() = Some(error);
    }

    /// Whether the peer network is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// A JSON snapshot for the `control.peerStatus` RPC. `genesis` is the effective L2 genesis
    /// challenge (64-hex) the node is running on, surfaced so an operator can see the REAL network a
    /// `DIG_NETWORK_GENESIS`-overridden node joined — not just the `network_id` label (#1372).
    pub fn snapshot_json(&self, endpoint: &str, network_id: &str, genesis: &str) -> Value {
        json!({
            "running": self.running.load(Ordering::Relaxed),
            "peer_id": self.peer_id.lock().unwrap().clone(),
            "network_id": network_id,
            "genesis": genesis,
            "relay": {
                "url": endpoint,
                "reserved": self.relay_reserved.load(Ordering::Relaxed),
                "peer_count": self.relay_peer_count.load(Ordering::Relaxed),
            },
            "connected_peers": self.connected_peers.load(Ordering::Relaxed),
            // (Reachability posture — direct vs relayed — is reported by `dig.getNetworkInfo`, which
            // reads this same relay-reservation flag; kept out of the terse status snapshot here.)
            "last_error": self.last_error.lock().unwrap().clone(),
        })
    }
}

// -- Per-peer enumeration for control.peerStatus (#929) ----------------------------------------------

/// The connected pool as a per-peer JSON array — one object per connected peer:
/// `{ peer_id, address, via, direction }`. This is the machine-checkable proof surface for a mutual
/// A↔B connection (each side lists the OTHER's `peer_id`), beyond the bare `connected_peers` count.
///
/// Sourced from [`connected_pool_peers`](dig_gossip::GossipHandle::connected_pool_peers) (dialable
/// socket `address` + `outbound`/`inbound` `direction`) joined by `peer_id` with the REAL transport
/// `via` from dig-gossip 0.3.0's
/// [`connected_pool_peers_with_via`](dig_gossip::GossipHandle::connected_pool_peers_with_via) (#924 B2):
/// a peer whose gossip rides the relay's RLY-002 forwarder reports `via = "relay"`, every other peer
/// `via = "direct"`. Addresses render with the family implicit in the socket string; the CLI orders
/// them IPv6-first (§5.2). Returns an empty vec when no peer network is running.
pub(crate) fn connected_peers_json(handle: &dig_gossip::GossipHandle) -> Vec<Value> {
    use dig_gossip::nat::peer_record::Via;
    // The real per-peer transport kind, keyed by peer_id — joined onto the address/direction rows.
    let via_by_peer: std::collections::HashMap<_, _> =
        handle.connected_pool_peers_with_via().into_iter().collect();
    handle
        .connected_pool_peers()
        .into_iter()
        .map(|(peer_id, addr, outbound)| {
            let via = match via_by_peer.get(&peer_id) {
                Some(Via::Relay) => "relay",
                _ => "direct",
            };
            json!({
                "peer_id": hex::encode(peer_id),
                "address": addr.to_string(),
                "via": via,
                "direction": if outbound { "outbound" } else { "inbound" },
            })
        })
        .collect()
}

/// The live pool's connectivity posture as a JSON object for `control.peerStatus` (#709/#846):
/// `{ connected, in_flight, target, min, max, backed_off, under_connected }`. This is the
/// peer-MANAGEMENT view an operator needs to reason about the pool — how many peers are connected
/// versus the configured `target`/`min`/`max`, how many dials are in flight, how many candidates are
/// currently backed off, and whether the pool is under-connected (below `min`) — sourced directly
/// from dig-gossip's [`pool_stats`](dig_gossip::GossipHandle::pool_stats). Returns `null` when no
/// peer network is running (the FFI path / before bring-up).
pub(crate) fn pool_stats_json(handle: &dig_gossip::GossipHandle) -> Value {
    let stats = handle.pool_stats();
    json!({
        "connected": stats.connected,
        "in_flight": stats.in_flight,
        "target": stats.target,
        "min": stats.min,
        "max": stats.max,
        "backed_off": stats.backed_off,
        "under_connected": stats.is_under_connected(),
    })
}

/// Dial a peer for `control.peers.connect` and return the connected peer's `peer_id` (64-hex).
///
/// The `peer` argument is EITHER a dialable socket address (`host:port`, IPv6 in brackets) OR a bare
/// `peer_id` (64-hex). An address is dialed directly over the full NAT ladder; a `peer_id` that is
/// ALREADY a connected pool member resolves immediately (idempotent). A bare `peer_id` that is NOT
/// yet connected has no dialable address here and is rejected with a deterministic error (dial it by
/// address, or wait for discovery to fold it into the pool). Fails deterministically — never panics.
pub(crate) async fn connect_peer(
    handle: &dig_gossip::GossipHandle,
    peer: &str,
) -> Result<String, String> {
    let peer = peer.trim();
    if let Ok(addr) = peer.parse::<std::net::SocketAddr>() {
        return handle
            .connect_to(addr)
            .await
            .map(hex::encode)
            .map_err(|e| format!("dial {addr}: {e}"));
    }
    // Not an address — treat it as a peer_id and honour it only if already connected (idempotent).
    let already_connected = handle
        .connected_pool_peers()
        .into_iter()
        .any(|(peer_id, _, _)| hex::encode(peer_id).eq_ignore_ascii_case(peer));
    if already_connected {
        return Ok(peer.to_ascii_lowercase());
    }
    Err(format!(
        "{peer:?} is neither a dialable address (host:port) nor an already-connected peer_id; \
         dial the peer by its address"
    ))
}

/// Drop a pooled peer for `control.peers.disconnect`, closing its link and letting the pool
/// replenish toward target.
///
/// The `peer` argument is a bare `peer_id` (64-hex, the `SHA-256(TLS SPKI DER)` a connect/peerStatus
/// reported). It is decoded into the gossip [`PeerId`](dig_gossip::PeerId) (a chia `Bytes32`) and
/// handed to [`disconnect`](dig_gossip::GossipHandle::disconnect), which closes the mTLS link and
/// publishes the pool-churn event. Idempotent: disconnecting a `peer_id` that is not (or no longer) a
/// pool member succeeds as a no-op — the post-state (that peer is not connected) is the same either
/// way. Fails deterministically on a malformed `peer_id`; never panics.
pub(crate) async fn disconnect_peer(
    handle: &dig_gossip::GossipHandle,
    peer: &str,
) -> Result<(), String> {
    let peer = peer.trim();
    let bytes = hex::decode(peer)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("{peer:?} is not a 64-hex peer_id"))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let peer_id = chia_protocol::Bytes32::new(arr);
    handle
        .disconnect(&peer_id)
        .await
        .map_err(|e| format!("disconnect {peer}: {e}"))
}

// -- Environment resolution (relay endpoint / network id / port) -------------------------------------

/// Resolve the relay endpoint: `DIG_RELAY_URL` if set + non-empty, else [`DEFAULT_RELAY_URL`]. Pure
/// core [`resolve_relay_url`] so the policy is unit-tested without touching process-global env.
pub fn relay_url_from_env() -> String {
    resolve_relay_url(std::env::var("DIG_RELAY_URL").ok().as_deref())
}

/// Pure: pick the relay endpoint from an optional `DIG_RELAY_URL` value.
fn resolve_relay_url(env: Option<&str>) -> String {
    env.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string())
}

/// Whether the relay reservation is enabled. Disabled when `DIG_RELAY_URL` is `off`/`disabled`
/// (case-insensitive) — an explicit opt-out for air-gapped/standalone nodes. Pure core
/// [`is_relay_enabled`].
pub fn relay_enabled() -> bool {
    is_relay_enabled(std::env::var("DIG_RELAY_URL").ok().as_deref())
}

/// Pure: is the relay enabled given an optional `DIG_RELAY_URL` value?
fn is_relay_enabled(env: Option<&str>) -> bool {
    match env {
        Some(v) => {
            let v = v.trim();
            !(v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("disabled"))
        }
        None => true,
    }
}

/// Whether the peer network (pool + peer-RPC server) is enabled. Disabled with `DIG_PEER_NETWORK=off`
/// — a named escape hatch for standalone nodes that only want the HTTP read path. Default: ENABLED.
/// Pure core [`is_peer_network_enabled`].
pub fn peer_network_enabled() -> bool {
    is_peer_network_enabled(std::env::var("DIG_PEER_NETWORK").ok().as_deref())
}

/// Pure: is the peer network enabled given an optional `DIG_PEER_NETWORK` value?
fn is_peer_network_enabled(env: Option<&str>) -> bool {
    !matches!(env, Some("off") | Some("0") | Some("false"))
}

/// The EFFECTIVE network label a node registers + discovers under — the string namespace shared by
/// the relay introducer, the relay reservation, the DHT/PEX discovery layers, and the reported
/// status. Resolves `DIG_NETWORK_ID` and `DIG_NETWORK_GENESIS` in precedence order; see
/// [`effective_network_label`] for the invariants. Pure core: [`effective_network_label`].
pub fn effective_network_label_from_env() -> String {
    effective_network_label(
        std::env::var("DIG_NETWORK_ID").ok().as_deref(),
        genesis_challenge_from_env(),
    )
}

/// Pure: resolve the effective network label from an optional explicit `DIG_NETWORK_ID` and the
/// already-resolved gossip genesis (`network_id` `Bytes32`), in precedence order:
///
/// - (a) No explicit `DIG_NETWORK_ID` AND the DEFAULT genesis (no/blank/invalid/zero
///   `DIG_NETWORK_GENESIS`, which [`genesis_challenge_from`] collapses to the canonical mainnet
///   genesis) → BYTE-IDENTICAL [`DEFAULT_NETWORK_ID`] (`"DIG_MAINNET"`).
/// - (b) Explicit `DIG_NETWORK_ID` set → that value verbatim (preserves today's operator override).
/// - (c) No explicit `DIG_NETWORK_ID` but a non-default genesis override → a deterministic label
///   [`derived_network_label`], DISTINCT from `"DIG_MAINNET"` and distinct per genesis.
///
/// WHY derive from the genesis (#1372): this label IS the relay introducer + reservation namespace —
/// a relay-matched string. If a genesis-overridden dev/test node kept `"DIG_MAINNET"`, it would
/// discover + be discovered by real mainnet peers through the relay (a test-isolation hazard AND a
/// config-plumbing bug: the override reached the gossip `network_id` but not the advertised
/// identity). Case (a) is a HARD backwards-compat requirement — the mainnet namespace MUST NOT
/// change or it would fork mainnet peer discovery.
fn effective_network_label(
    network_id_env: Option<&str>,
    genesis: chia_protocol::Bytes32,
) -> String {
    // (b) An explicit operator override always wins.
    if let Some(id) = network_id_env.map(str::trim).filter(|s| !s.is_empty()) {
        return id.to_string();
    }
    // (a) The default genesis maps back to the canonical mainnet label (byte-identical to today).
    if genesis == dig_constants::DIG_MAINNET.genesis_challenge() {
        return DEFAULT_NETWORK_ID.to_string();
    }
    // (c) A non-default genesis gets its own discovery namespace.
    derived_network_label(genesis)
}

/// A deterministic, per-genesis discovery namespace for a non-default genesis: `DIG_` + the first 16
/// hex chars (8 bytes) of the genesis challenge. Deterministic (same genesis → same label), distinct
/// per genesis, and never equal to `"DIG_MAINNET"` (which is non-hex, so the two forms can never
/// collide). 8 bytes is ample to separate dev/test networks without carrying the full 32-byte hash
/// in every discovery frame.
fn derived_network_label(genesis: chia_protocol::Bytes32) -> String {
    format!("DIG_{}", &hex::encode(genesis)[..16])
}

/// The gossip `GossipConfig.network_id` genesis-challenge: `DIG_NETWORK_GENESIS` (64-hex, 32
/// bytes) when set to a valid non-zero value, else `dig_constants::DIG_MAINNET.genesis_challenge()`
/// — the canonical DIG mainnet genesis, a REAL non-zero Chia mainnet header hash
/// (`0af981…1abf` @ height 9,021,277, pinned in dig-constants 0.4.0+). Because that default is
/// non-zero, a stock node's gossip pool starts cleanly: `dig-gossip` rejects only an ALL-ZERO
/// `network_id`. Setting the env var overrides the default for a dev/local network (#285). Pure
/// core [`genesis_challenge_from`].
pub fn genesis_challenge_from_env() -> chia_protocol::Bytes32 {
    genesis_challenge_from(std::env::var("DIG_NETWORK_GENESIS").ok().as_deref())
}

/// Pure: resolve an optional `DIG_NETWORK_GENESIS` value into the gossip `network_id` `Bytes32`,
/// falling back to the canonical `DIG_MAINNET` genesis for anything that isn't a valid non-zero
/// 64-hex 32-byte value (unset, blank, non-hex, wrong length, or all-zero). The fallback is a REAL
/// non-zero genesis (dig-constants 0.4.0+), so an unconfigured node still builds a valid, startable
/// gossip config — `dig-gossip` only rejects an all-zero `network_id`.
fn genesis_challenge_from(env: Option<&str>) -> chia_protocol::Bytes32 {
    let default_genesis = dig_constants::DIG_MAINNET.genesis_challenge();
    let Some(s) = env.map(str::trim).filter(|s| !s.is_empty()) else {
        return default_genesis;
    };
    if s.len() != 64 {
        return default_genesis;
    }
    let Ok(bytes) = hex::decode(s) else {
        return default_genesis;
    };
    let Ok(arr) = <[u8; 32]>::try_from(bytes) else {
        return default_genesis;
    };
    if arr == [0u8; 32] {
        return default_genesis;
    }
    chia_protocol::Bytes32::new(arr)
}

/// The P2P listen port: `DIG_PEER_PORT` if a valid u16, else [`DEFAULT_P2P_PORT`].
pub fn peer_port_from_env() -> u16 {
    std::env::var("DIG_PEER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_P2P_PORT)
}

/// The dig-gossip pool listen port: `DIG_GOSSIP_PORT` if a valid u16, else [`DEFAULT_GOSSIP_PORT`].
/// Kept distinct from [`peer_port_from_env`] so the two in-process listeners never clash (#871).
pub fn gossip_port_from_env() -> u16 {
    std::env::var("DIG_GOSSIP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GOSSIP_PORT)
}

/// The node's gossip listen candidates to advertise in the relay reservation's RLY-001 `Register`
/// (#870 B1, dig-nat 0.3.0 `Register.listen_addrs`). The gossip pool binds a dual-stack socket on
/// `gossip_port`; the node advertises that port on the IPv6 unspecified address FIRST, then the IPv4
/// unspecified address (§5.2 IPv6-first, IPv4-fallback). The relay performs reflexive-IP substitution
/// — it pairs the advertised PORT with the source IP it observes — so a peer behind a different NAT
/// receives a DIALABLE `<reflexive-ip>:<gossip-port>` candidate (SPEC §19.8).
pub fn gossip_listen_candidates(gossip_port: u16) -> Vec<std::net::SocketAddr> {
    use dig_ip::{CandidateSource, Family, PeerCandidates};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    // Aggregate + source-tag the two wildcard listen addresses, then emit them in dig_ip::Family
    // preference order (IPv6 before IPv4) — the family ordering is dig-ip's, not hand-rolled here.
    let mut candidates = PeerCandidates::new();
    candidates.add(
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, gossip_port)),
        CandidateSource::ListenAddr,
    );
    candidates.add(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, gossip_port)),
        CandidateSource::ListenAddr,
    );
    Family::PREFERENCE
        .iter()
        .flat_map(|family| candidates.of_family(*family))
        .collect()
}

// -- Local inventory → L7 availability / inventory / range -------------------------------------------
//
// The node serves the SAME content over the peer RPC that it serves over §21 / the HTTP read path:
// the capsules cached on disk (`<cache>/modules/<store>/<root>.module`). `cache_list_cached()` is the
// authoritative local inventory, so these pure helpers derive the peer-RPC answers from it.

/// Group a flat list of cached capsules into `store_id → [root, …]` (roots deduped, sorted). Pure so
/// the inventory/availability shaping is unit-tested without a node or a disk.
fn group_by_store(cached: &[CachedCapsule]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for c in cached {
        map.entry(c.store_id.clone())
            .or_default()
            .insert(c.root.clone());
    }
    map.into_iter()
        .map(|(store, roots)| (store, roots.into_iter().collect()))
        .collect()
}

/// The `dig.listInventory` result for the local inventory: the stores this node serves (when
/// `store_id` is `None`), or the roots it holds for one store (when `store_id` is `Some`). `limit`
/// caps the returned list. Pure over the cached-capsule list.
pub fn list_inventory(
    cached: &[CachedCapsule],
    store_id: Option<&str>,
    limit: Option<usize>,
) -> Value {
    let grouped = group_by_store(cached);
    match store_id {
        Some(store) => {
            let mut roots: Vec<String> = grouped.get(store).cloned().unwrap_or_default();
            if let Some(n) = limit {
                roots.truncate(n);
            }
            json!({ "store_id": store, "roots": roots })
        }
        None => {
            let mut stores: Vec<String> = grouped.keys().cloned().collect();
            if let Some(n) = limit {
                stores.truncate(n);
            }
            json!({ "stores": stores })
        }
    }
}

/// One `dig.getAvailability` answer for a single queried item against the local inventory. Granularity
/// is inferred from which fields the item carries (spec §9):
/// - `store_id` only → *has_store* (`roots` = the roots held, newest-first — here mtime-desc).
/// - `store_id` + `root` → *has_root* (does this node hold that capsule; `total_length`/`chunk_count`
///   are filled by [`Node`] from the served module — this pure helper reports presence only).
/// - `store_id` + `root` + `retrieval_key` → *has_resource* (presence at capsule granularity; the
///   resource-level totals come from serving the module).
///
/// This pure form answers presence + store-granularity `roots`; the resource/root totals
/// (`total_length`/`chunk_count`/`complete`) are enriched by the node from the actual module (see
/// [`crate::Node::availability_answer`]).
pub fn availability_presence(
    cached: &[CachedCapsule],
    store_id: &str,
    root: Option<&str>,
    _retrieval_key: Option<&str>,
) -> Value {
    // Roots held for the store, newest-first (by last-used mtime desc, matching the on-disk recency).
    let mut store_caps: Vec<&CachedCapsule> =
        cached.iter().filter(|c| c.store_id == store_id).collect();
    store_caps.sort_by_key(|c| std::cmp::Reverse(c.last_used_unix_ms));

    match root {
        None => {
            // STORE granularity: available iff any root is held; report the held roots newest-first.
            let roots: Vec<String> = store_caps.iter().map(|c| c.root.clone()).collect();
            json!({ "available": !roots.is_empty(), "roots": roots })
        }
        Some(want_root) => {
            // ROOT / RESOURCE granularity: available iff this exact capsule is held.
            let held = store_caps.iter().any(|c| c.root == want_root);
            json!({ "available": held })
        }
    }
}

// -- Peer-RPC dispatch over an accepted mTLS stream --------------------------------------------------
//
// A serving node accepts inbound logical streams (yamux over the mTLS link) and answers each. The wire
// on a stream is dig-nat's uniform framing: a `u32`-BE length prefix + a JSON body. We read one framed
// JSON value and dispatch by SHAPE — interoperable with BOTH dig-nat's typed client helpers
// (`open_range_stream` writes a bare `RangeRequest`; `query_availability` writes a bare
// `AvailabilityRequest`) AND a JSON-RPC 2.0 client (a `{jsonrpc,id,method,params}` request):
//   - `method` present  → JSON-RPC request → `handle_rpc` → framed JSON-RPC response.
//   - `length` present   → RangeRequest    → stream `RangeFrame`s.
//   - `items`  present   → AvailabilityRequest → one framed `AvailabilityResponse`.
// This keeps the node's peer surface identical whether an agent drives it via JSON-RPC or a peer node
// drives it via dig-nat's typed stream API.

/// Read a `u32`-BE length-prefixed JSON body from `r` (dig-nat's control framing). Returns `Ok(None)`
/// on a clean end-of-stream at a frame boundary so the accept loop can end quietly.
pub async fn read_framed<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // Guard against a hostile length prefix (mirrors dig-nat's MAX_FRAMED_BODY = 64 KiB for control
    // frames — a JSON-RPC request / RangeRequest / AvailabilityRequest is always small).
    if len > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "peer request frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    let v = serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(v))
}

/// Write `value` as a `u32`-BE length-prefixed JSON body (dig-nat's control framing). `?Sized` so it
/// accepts a `&mut dyn AsyncWrite` (the trait-object out-stream of [`PeerRpcResponder::stream_range`]).
pub async fn write_framed<W: AsyncWriteExt + Unpin + ?Sized>(
    w: &mut W,
    value: &Value,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(value)?;
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Classify one inbound peer-request frame by its shape.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PeerRequestKind {
    /// A JSON-RPC 2.0 request (`method` present).
    JsonRpc,
    /// A `dig.fetchRange` RangeRequest (`length` present, `method` absent).
    Range,
    /// A `dig.getAvailability` AvailabilityRequest (`items` present, `method` absent).
    Availability,
    /// Unrecognized — the server answers with a JSON-RPC invalid-request error.
    Unknown,
}

/// Dispatch an inbound frame by shape (pure — no I/O), so the stream-routing policy is unit-tested.
pub(crate) fn classify_request(v: &Value) -> PeerRequestKind {
    if v.get("method").and_then(Value::as_str).is_some() {
        PeerRequestKind::JsonRpc
    } else if v.get("length").is_some() {
        PeerRequestKind::Range
    } else if v.get("items").is_some() {
        PeerRequestKind::Availability
    } else {
        PeerRequestKind::Unknown
    }
}

// -- Deterministic mTLS identity from the node's persistent seed --------------------------------------
//
// `install_crypto_provider` + `load_or_generate_node_cert` moved to `crate::shared::identity`
// (#1285 W1a — this is cross-seam vocabulary, not peer-seam-private); re-exported here so the
// existing `peer::install_crypto_provider` / `peer::load_or_generate_node_cert` call paths (this
// module's own tests included) keep working unchanged.
pub use crate::shared::identity::{install_crypto_provider, load_or_generate_node_cert};

// -- Serving inbound peer streams over an established mTLS connection ---------------------------------

/// A thing that answers peer requests — implemented by [`crate::Node`]. The transport layer
/// ([`serve_peer_session`]) reads framed requests off each inbound stream and calls back into this to
/// produce the answer, so the transport is decoupled from the node internals (and unit-testable with a
/// stub responder over an in-memory duplex).
#[async_trait::async_trait]
pub trait PeerRpcResponder: Send + Sync {
    /// Answer a JSON-RPC 2.0 request (`dig.getPeers` / `dig.getNetworkInfo` / `dig.announce` /
    /// `dig.getAvailability` / `dig.listInventory`, etc.). Returns the JSON-RPC response value.
    async fn handle_json_rpc(&self, req: Value) -> Value;

    /// Answer a `dig.getAvailability` batch (the typed dig-nat control call). `items` is the raw
    /// AvailabilityItem array; returns the `{ "items": [AvailabilityAnswer, …] }` response value.
    async fn handle_availability(&self, items: Value) -> Value;

    /// Stream a `dig.fetchRange` response for `req` (the RangeRequest value) by writing framed
    /// [`dig_nat::mux::RangeFrame`]-shaped frames to `out`. Implementations write the first frame with
    /// the verification metadata + subsequent data frames, then return.
    ///
    /// `conn_key` is the authenticated caller's `peer_id` (64-hex; empty for a caller-less/test
    /// session) — the per-connection key the serve-side outbound rate limiter paces by (#1436), so one
    /// peer's burst cannot starve another's.
    async fn stream_range(
        &self,
        req: Value,
        conn_key: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()>;

    /// Answer an inbound DHT-RPC frame (#163): decode `frame` as a `dig_dht::DhtRequest`, dispatch it
    /// against the node's DHT service folding in the authenticated `caller` (so the routing table
    /// populates bidirectionally), and return the framed `dig_dht::DhtResponse` bytes to write back.
    ///
    /// `caller` is the DHT [`dig_dht::Contact`] built from the mTLS-verified peer_id + remote addr
    /// (never the wire body). The default is a "DHT not running" error frame, so a responder without a
    /// DHT (the base/FFI path, test stubs) needs no override; [`NodeResponder`] overrides it when the
    /// standalone peer network brought up a DHT.
    async fn handle_dht(&self, caller: Option<dig_dht::Contact>, frame: Value) -> Vec<u8> {
        let _ = caller;
        let _ = frame;
        dig_dht::DhtResponse::Error {
            code: 1,
            message: "DHT not running on this node".to_string(),
        }
        .encode()
    }
}

/// Serve peer requests over one established, mTLS-authenticated [`dig_nat::mux::PeerSession`] (the
/// SERVER role): accept inbound logical streams and answer each concurrently. Every stream is read as
/// one framed request, classified by shape, and answered — a JSON-RPC request via
/// [`PeerRpcResponder::handle_json_rpc`], an availability batch via
/// [`PeerRpcResponder::handle_availability`], a range fetch via [`PeerRpcResponder::stream_range`].
/// Returns when the peer closes the connection. The caller has already verified the remote `peer_id`
/// (dig-nat enforces it during the mTLS handshake), so every stream here is from an authenticated peer.
pub async fn serve_peer_session(
    mut session: dig_nat::mux::PeerSession,
    responder: Arc<dyn PeerRpcResponder>,
) {
    // No authenticated caller threaded here (the mTLS-verified caller is supplied by the listener via
    // `serve_peer_session_from`); a caller-less session still serves the JSON-RPC/range/availability
    // paths — only DHT routing-table population needs the caller.
    serve_peer_session_from(None, &mut session, responder).await
}

/// Like [`serve_peer_session`] but carrying the session's authenticated `caller` [`dig_dht::Contact`]
/// (from the mTLS handshake) so DHT frames on this session are dispatched with the verified caller.
pub async fn serve_peer_session_from(
    caller: Option<dig_dht::Contact>,
    session: &mut dig_nat::mux::PeerSession,
    responder: Arc<dyn PeerRpcResponder>,
) {
    serve_peer_session_from_with(caller, session, responder, None).await
}

/// Like [`serve_peer_session_from`] but also running the node↔node **PEX** exchange (#166) over this
/// session when `pex` is `Some`: before accepting inbound streams, the node opens ONE outgoing PEX
/// stream and drives its sending direction (handshake→snapshot→periodic deltas) on it; each accepted
/// stream whose first frame is a `pex_*` message is served as the peer's incoming PEX direction
/// ([`crate::pex::serve_inbound_stream`]) instead of the RPC dispatch. On teardown the PEX link state
/// is discarded ([`crate::pex::PexEngineHandle::link_down`]). PEX runs only when the session has an
/// authenticated `caller` (its mTLS `peer_id` is the link identity — never a wire field, SPEC §10.1).
pub async fn serve_peer_session_from_with(
    caller: Option<dig_dht::Contact>,
    session: &mut dig_nat::mux::PeerSession,
    responder: Arc<dyn PeerRpcResponder>,
    pex: Option<Arc<crate::pex::PexServing>>,
) {
    // PEX sending direction: open our own PEX logical stream on this session and drive it. The link
    // identity is the mTLS-verified caller peer_id (never the wire body).
    let pex_peer_id = pex
        .as_ref()
        .and_then(|_| caller.as_ref().map(|c| c.peer_id.clone()));
    if let (Some(pex), Some(peer_id)) = (pex.as_ref(), pex_peer_id.clone()) {
        match session.open_stream().await {
            Ok(stream) => {
                let engine = pex.engine.clone();
                tokio::spawn(crate::pex::run_send_direction(engine, peer_id, stream));
            }
            Err(e) => tracing::debug!(error = %e, "pex: could not open outgoing stream"),
        }
    }

    // Per-connection stream-concurrency cap (audit #179 HIGH): a single peer can open many yamux
    // logical streams, each spawning a handler that may read a whole module + wasmtime-decrypt or
    // make a chain/proxy call. Bound the concurrent handlers PER CONNECTION so one peer cannot spawn
    // unbounded tasks; streams opened past the cap are dropped (closed without a handler).
    let stream_permits = Arc::new(tokio::sync::Semaphore::new(
        MAX_INFLIGHT_STREAMS_PER_CONNECTION,
    ));
    while let Some(stream) = session.accept_stream().await {
        let responder = responder.clone();
        let caller = caller.clone();
        let pex = pex.clone();
        let spawned = spawn_with_permit(&stream_permits, async move {
            if let Err(e) = serve_one_stream_from_with(caller, stream, responder, pex).await {
                tracing::debug!(error = %e, "peer stream ended with an error");
            }
        });
        if !spawned {
            // At the per-connection stream cap: shed this stream (drop it — the peer must slow down).
            tracing::debug!("peer stream shed: per-connection concurrency cap reached");
        }
    }

    // The session closed: discard this link's PEX state so a reconnect starts fresh (SPEC §5.5).
    if let (Some(pex), Some(peer_id)) = (pex, pex_peer_id) {
        pex.engine.link_down(&peer_id).await;
    }
}

/// Handle exactly one inbound peer stream: read the request frame, dispatch by shape, write the
/// answer. Generic over the stream so it is driven directly by a loopback duplex in tests.
/// Test-only thin wrapper: serve one stream with no authenticated caller and no PEX (the
/// DHT-caller-less path). Production always goes through [`serve_one_stream_from_with`] with the
/// session's mTLS caller.
#[cfg(test)]
pub(crate) async fn serve_one_stream<S>(
    stream: S,
    responder: Arc<dyn PeerRpcResponder>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    serve_one_stream_from_with(None, stream, responder, None).await
}

/// Handle one inbound peer stream, carrying the session's authenticated `caller` so a DHT frame is
/// dispatched with the verified caller identity (#163). A DHT frame (its `type` is one of the four
/// DHT methods) is checked FIRST — it is disjoint from the JSON-RPC/range/availability shapes — and
/// routed to [`PeerRpcResponder::handle_dht`], which writes the framed `dig_dht::DhtResponse` back
/// (dig-dht's own framing, byte-identical to [`write_framed`]). Everything else dispatches by shape as
/// before. When `pex` is `Some` and the first frame is a `pex_*` message (a PEX stream self-identifies
/// by its first frame, SPEC §10.1), the stream is served as the peer's incoming PEX direction
/// ([`crate::pex::serve_inbound_stream`]) — which keeps reading subsequent PEX frames off it — instead
/// of the one-shot RPC dispatch. Generic over the stream so a loopback duplex drives it in tests.
pub(crate) async fn serve_one_stream_from_with<S>(
    caller: Option<dig_dht::Contact>,
    mut stream: S,
    responder: Arc<dyn PeerRpcResponder>,
    pex: Option<Arc<crate::pex::PexServing>>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    let Some(req) = read_framed(&mut stream).await? else {
        return Ok(()); // clean close before any request
    };
    // DHT frames are checked BEFORE the shape classifier: they carry `type` (never method/length/
    // items), so a DHT request never collides with the JSON-RPC/range/availability shapes.
    if crate::dht::is_dht_request(&req) {
        let bytes = responder.handle_dht(caller, req).await;
        stream.write_all(&bytes).await?;
        return stream.flush().await;
    }
    // A PEX stream self-identifies by a `pex_*` first frame (disjoint from the DHT + JSON-RPC/range/
    // availability shapes). Hand the whole stream to the PEX serving loop, which continues reading
    // this peer's incoming PEX direction (handshake→snapshot→deltas) off it.
    if let (Some(pex), true) = (pex.as_ref(), crate::pex::is_pex_first_frame(&req)) {
        if let Some(peer_id) = caller.as_ref().map(|c| c.peer_id.clone()) {
            // Reconstruct the typed first frame we already consumed; a malformed pex_* body is a
            // message-level violation the engine records via the serving loop's decode path.
            let first = serde_json::from_value::<dig_pex::PexMessage>(req).ok();
            crate::pex::serve_inbound_stream(
                pex.engine.clone(),
                pex.pool.clone(),
                peer_id,
                first,
                stream,
            )
            .await;
        }
        return Ok(());
    }
    match classify_request(&req) {
        PeerRequestKind::JsonRpc => {
            let resp = responder.handle_json_rpc(req).await;
            write_framed(&mut stream, &resp).await
        }
        PeerRequestKind::Availability => {
            let items = req.get("items").cloned().unwrap_or_else(|| json!([]));
            let resp = responder.handle_availability(items).await;
            write_framed(&mut stream, &resp).await
        }
        PeerRequestKind::Range => {
            // The per-connection rate-limit key is the mTLS-verified caller peer_id (empty when the
            // session carries no authenticated caller — a test/loopback path, #1436).
            let conn_key = caller
                .as_ref()
                .map(|c| c.peer_id.clone())
                .unwrap_or_default();
            responder.stream_range(req, &conn_key, &mut stream).await
        }
        PeerRequestKind::Unknown => {
            let resp = json!({"jsonrpc":"2.0","id":Value::Null,
                "error":{"code":-32600,"message":"unrecognized peer request frame"}});
            write_framed(&mut stream, &resp).await
        }
    }
}

/// Whether `method` may be answered over the **mTLS peer surface** (other DIG nodes).
///
/// The allowlist itself lives in ONE place — [`dig_rpc_protocol::Method::is_peer_reachable`],
/// the canonical node<->node contract crate both DIG node implementations share (#1075) —
/// so the peer surface can never drift between them. This function only adapts the wire
/// `&str` to that enum: an unknown method has no `Method` variant and is therefore never
/// peer-reachable (fail-closed).
///
/// It is an ALLOWLIST, not a denylist: the peer mTLS verifier accepts any well-formed
/// self-signed leaf ("authenticated" means only "derived some peer_id", never "authorized"),
/// so management/mutation methods (`cache.*`, `control.*`, `dig.stage`) MUST NOT be forwarded
/// to a remote peer — they stay reachable only from the loopback admin / in-process FFI
/// dispatch ([`crate::handle_rpc`]). See audit #179 (CRITICAL auth-bypass).
pub(crate) fn is_peer_reachable_method(method: &str) -> bool {
    dig_rpc_protocol::Method::from_name(method).is_some_and(|m| m.is_peer_reachable())
}

// -- The node's PeerRpcResponder — routes peer requests into the node's dispatch + inventory ----------

/// The node's implementation of [`PeerRpcResponder`]: JSON-RPC frames go through the SAME
/// [`crate::handle_rpc`] dispatch the §21/FFI path uses (so the peer surface is identical to the agent
/// surface); availability + range frames are answered from the node's local inventory. Wraps an
/// `Arc<Node>` so many inbound streams share one node, plus the live [`dig_gossip::GossipHandle`] so
/// `dig.getPeers` / `dig.getNetworkInfo` reflect the CONNECTED POOL (which `handle_rpc` alone cannot,
/// since the FFI-safe `Node` does not hold the gossip handle).
pub(crate) struct NodeResponder {
    node: Arc<crate::Node>,
    /// The live pool handle (standalone peer network only) — `None` in the base/FFI path.
    handle: Option<dig_gossip::GossipHandle>,
    /// The live content-location DHT (#163), when the standalone peer network brought one up.
    /// `None` disables inbound DHT serving (the default trait method returns a "not running" frame).
    dht: Option<Arc<crate::dht::DhtHandle>>,
    /// Serve-side FCFS outbound rate limiter (#1436): paces `dig.fetchRange` bytes per-connection +
    /// globally so a burst never overwhelms one peer or this node's uplink. Caps come from env
    /// (`0/0` = unlimited = behavior-preserving default). Keyed by the caller `peer_id`; the crate has
    /// no eviction API, so a distinct peer leaves at most one bucket entry (bounded footprint) —
    /// evicting on connection close is a tracked follow-up pending a `dig-download` `evict()` add.
    serve_limiter: Arc<dig_download::FcfsRateLimiter>,
}

impl NodeResponder {
    /// A responder backed by the node + the live pool handle (the standalone peer-RPC server).
    pub(crate) fn with_pool(node: Arc<crate::Node>, handle: dig_gossip::GossipHandle) -> Self {
        NodeResponder {
            node,
            handle: Some(handle),
            dht: None,
            serve_limiter: crate::seams::content::bandwidth::serve_rate_limiter_from_env(),
        }
    }

    /// A responder with NO live pool (the base peer surface): `dig.getPeers` returns this node's
    /// own empty pool view. Used where no `GossipHandle` is available (tests; a peer-RPC server
    /// brought up before the pool). The method allowlist (`is_peer_reachable_method`) applies
    /// identically regardless of whether a pool is wired.
    #[cfg(test)]
    pub(crate) fn without_pool(node: Arc<crate::Node>) -> Self {
        NodeResponder {
            node,
            handle: None,
            dht: None,
            serve_limiter: crate::seams::content::bandwidth::serve_rate_limiter_from_env(),
        }
    }

    /// Attach the live DHT so this responder answers inbound DHT RPCs (#163). Builder-style so the
    /// standalone bring-up wires the pool first, then the DHT once it is bootstrapped.
    pub(crate) fn with_dht(mut self, dht: Arc<crate::dht::DhtHandle>) -> Self {
        self.dht = Some(dht);
        self
    }

    /// The live pool's peers as L7 `PeerRecord`s (peer_id + candidate addresses), or an empty list
    /// when no pool is wired. `network_id` is echoed onto each record.
    fn pool_peers(&self, network_id: &str, limit: Option<usize>) -> Vec<Value> {
        let Some(handle) = &self.handle else {
            return Vec::new();
        };
        let mut peers: Vec<Value> = handle
            .connected_pool_peers()
            .into_iter()
            .map(|(peer_id, addr, _outbound)| {
                json!({
                    "peer_id": hex::encode(peer_id),
                    "addresses": [{
                        "host": addr.ip().to_string(),
                        "port": addr.port(),
                        "kind": "direct",
                    }],
                    "network_id": network_id,
                    "via": "direct",
                })
            })
            .collect();
        if let Some(n) = limit {
            peers.truncate(n);
        }
        peers
    }
}

#[async_trait::async_trait]
impl PeerRpcResponder for NodeResponder {
    async fn handle_json_rpc(&self, req: Value) -> Value {
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let id = req.get("id").cloned().unwrap_or(json!(1));
        // PEER-SURFACE ALLOWLIST (audit #179 CRITICAL). The mTLS verifier accepts any self-signed
        // leaf, so an "authenticated" peer is merely "some peer_id", NOT an authorized admin. Route
        // ONLY the intended L7 read/discovery/announce methods to the shared dispatch; return -32601
        // (method not found) for management/mutation methods (`cache.*`, `control.*`, `dig.stage`),
        // which stay reachable only from the loopback admin / in-process FFI path (crate::handle_rpc).
        // This gate runs BEFORE any dispatch so a mutation method never reaches handle_rpc.
        if !is_peer_reachable_method(method) {
            return json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32601,"message":"method not found"}});
        }
        // dig.getPeers is answered from the LIVE pool here (the base handle_rpc can't — it has no pool
        // handle). Everything else routes through the shared dispatch so the peer surface == the agent
        // surface (getAvailability / listInventory / fetchRange / getNetworkInfo / announce).
        if dig_rpc_protocol::Method::from_name(method) == Some(dig_rpc_protocol::Method::GetPeers) {
            let network_id = effective_network_label_from_env();
            let limit = req
                .get("params")
                .and_then(|p| p.get("limit"))
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let peers = self.pool_peers(&network_id, limit);
            return json!({"jsonrpc":"2.0","id":id,"result":{"peers": peers}});
        }
        crate::handle_rpc(&self.node, req).await
    }

    async fn handle_availability(&self, items: Value) -> Value {
        let items = items.as_array().cloned().unwrap_or_default();
        self.node.availability_batch(&items).await
    }

    async fn stream_range(
        &self,
        req: Value,
        conn_key: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        let store = req.get("store_id").and_then(Value::as_str).unwrap_or("");
        let root = req.get("root").and_then(Value::as_str).unwrap_or("");
        let rk = req
            .get("retrieval_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let offset = req.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let length = req
            .get("length")
            .and_then(Value::as_u64)
            .unwrap_or(RANGE_WINDOW as u64) as usize;
        // Stream node-window frames advancing offset until complete (the peer reassembles by offset).
        // A miss / bad range writes one error frame (JSON-RPC-shaped) so the caller can distinguish it.
        let mut off = offset;
        loop {
            match self
                .node
                .fetch_range_frame(store, root, rk, off, length)
                .await
            {
                Ok(frame) => {
                    let this_len =
                        frame.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
                    // OUTGOING-BANDWIDTH THROTTLE (#30): this is the node-to-node range-stream wire
                    // multi-source downloaders hammer — the busiest outgoing-bytes path. Redirect the
                    // caller to a known holder instead of streaming this frame over-budget (same #165
                    // redirect shape as a genuine miss); serve it anyway when no alternate is known
                    // (never drop a request the node could answer).
                    if this_len > 0 {
                        if let Some(content) = crate::download::range_content_id(&req) {
                            let depth = crate::download::redirect_depth(&req);
                            if let Some(obj) = self
                                .node
                                .bandwidth_redirect(&content, this_len as u64, depth)
                                .await
                            {
                                let errf = json!({"error": obj});
                                return write_framed(out, &errf).await;
                            }
                        }
                    }
                    self.node.record_outgoing_bytes(this_len as u64);
                    // FCFS outbound PACING (#1436): wait (in arrival order) until this frame's bytes
                    // fit the global + per-connection budget before writing it, so a burst never
                    // overwhelms one peer or this node's uplink. A `0/0` limiter returns instantly.
                    self.serve_limiter.acquire(conn_key, this_len as u64).await;
                    write_framed(out, &frame).await?;
                    let complete = frame
                        .get("complete")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    if complete || this_len == 0 {
                        return Ok(());
                    }
                    off += this_len;
                }
                Err((code, message)) => {
                    // A LOCAL MISS (-32004) over the peer stream: try the #165 P2P miss path first —
                    // stream the fetched-through frames (transparent to the caller), or write a
                    // redirect ERROR FRAME naming the holder(s) so the caller re-requests there. An
                    // empty engine / no provider falls back to the bare error frame (no silent miss
                    // when a provider exists). The redirect frame carries the SAME `-32008` +
                    // `data.redirect` shape as the JSON-RPC redirect (the read-tier redirect response).
                    if code == crate::download::RESOURCE_UNAVAILABLE {
                        if let Some(content) = crate::download::range_content_id(&req) {
                            let depth = crate::download::redirect_depth(&req);
                            match self.node.miss_outcome(&content, depth).await {
                                crate::download::MissOutcome::Fetched(f) => {
                                    return stream_fetched_range(
                                        out,
                                        &f,
                                        off,
                                        length,
                                        &self.serve_limiter,
                                        conn_key,
                                    )
                                    .await;
                                }
                                crate::download::MissOutcome::Redirect {
                                    providers,
                                    next_depth,
                                } => {
                                    let errf = json!({"error": crate::download::redirect_error_object(
                                        &content, &providers, next_depth)});
                                    return write_framed(out, &errf).await;
                                }
                                crate::download::MissOutcome::NotFound => {}
                            }
                        }
                    }
                    let errf = json!({"error": {"code": code, "message": message}});
                    return write_framed(out, &errf).await;
                }
            }
        }
    }

    async fn handle_dht(&self, caller: Option<dig_dht::Contact>, frame: Value) -> Vec<u8> {
        match &self.dht {
            // Dispatch into the live DHT, folding in the authenticated caller (routing-table fill).
            Some(dht) => crate::dht::handle_dht_frame(dht.service(), caller, &frame).await,
            // No DHT on this node → the default "not running" frame.
            None => dig_dht::DhtResponse::Error {
                code: 1,
                message: "DHT not running on this node".to_string(),
            }
            .encode(),
        }
    }
}

/// Stream a fetched-through resource (#165) over the peer range stream: write node-window
/// [`crate::download::FetchedResource::range_frame`]s advancing `offset` until complete, exactly like
/// the local-hold path streams `fetch_range_frame` — so a fetch-through serve is byte-shape-identical
/// to a locally-held one (first frame carries the verification metadata the caller checks against the
/// chain-anchored root). A bad range (offset past the resource) writes one error frame.
async fn stream_fetched_range(
    out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    fetched: &crate::download::FetchedResource,
    offset: usize,
    length: usize,
    limiter: &dig_download::FcfsRateLimiter,
    conn_key: &str,
) -> std::io::Result<()> {
    let mut off = offset;
    loop {
        match fetched.range_frame(off, length) {
            Ok(frame) => {
                let this_len = frame.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
                // Pace fetch-through frames on the SAME FCFS budget as locally-held serves (#1436).
                limiter.acquire(conn_key, this_len as u64).await;
                write_framed(out, &frame).await?;
                let complete = frame
                    .get("complete")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if complete || this_len == 0 {
                    return Ok(());
                }
                off += this_len;
            }
            Err((code, message)) => {
                let errf = json!({"error": {"code": code, "message": message}});
                return write_framed(out, &errf).await;
            }
        }
    }
}

// -- Peer-network bring-up: the connected pool + discovery + the mTLS peer-RPC server -----------------

/// Spawn the node's L7 peer network in the background (the OS-service bring-up calls this — #213;
/// the in-process FFI host never does): bring up
/// [`dig_gossip`]'s connected peer pool (introducer-backed auto-discovery via `relay.dig.net` + the
/// relay reservation) AND the mTLS peer-RPC server (answers the L7 peer RPC from other nodes). Both
/// use ONE TLS identity so the node presents a consistent `peer_id`. Best-effort: a failed bring-up
/// records the error on [`crate::Node::peer_status`] and returns; the node's HTTP read path keeps
/// serving. Never panics the node.
pub fn spawn_peer_network(node: Arc<crate::Node>) {
    tokio::spawn(async move {
        if let Err(e) = run_peer_network(node.clone()).await {
            eprintln!("dig-node: peer network bring-up failed: {e}");
            node.peer_status().set_error(e);
        }
    });
}

/// Feed the peer selector's registry (#178) from the dig-gossip connected pool: seed it with the
/// current pool snapshot, then forward every `PoolEvent` churn event so the selector always ranks
/// against the live peer set (SPEC §2.3). Each `dig_gossip::PoolEvent` is mapped 1:1 into the
/// selector's local `PoolEvent` (field-identical shapes — the selector mirrors the type locally to
/// avoid a dig-gossip dependency; see `crate::download::pool_event_to_selector`). Best-effort: a
/// subscribe failure logs + returns (the selector still learns from the DHT candidates passed to
/// `select` on each fetch); the task ends when the pool event channel closes.
fn spawn_selector_registry_feed(
    content: Arc<crate::download::NodeContent>,
    handle: dig_gossip::GossipHandle,
) {
    // Seed from the current snapshot so the registry is populated before the first fetch.
    for (peer_id, addr, _outbound) in handle.connected_pool_peers() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(peer_id.as_ref());
        let event = crate::download::pool_event_to_selector(
            bytes,
            crate::download::PoolEventKind::Added { addr },
        );
        content.on_pool_event(&event);
    }

    let mut rx = match handle.subscribe_pool_events() {
        Ok(rx) => rx,
        Err(e) => {
            tracing::debug!(error = %e, "selector registry feed: could not subscribe to pool events");
            return;
        }
    };
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let selector_event = map_gossip_pool_event(&ev);
                    content.on_pool_event(&selector_event);
                }
                // Lagged (slow consumer) — keep going; a missed add/remove is re-seeded by the pool.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                // Channel closed (service stopped) — the feed is done.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

/// Map a live `dig_gossip::PoolEvent` into the selector's local `PoolEvent` (the 1:1 field map —
/// SPEC §5.4). This is the boundary where dig-gossip's concrete type is in scope; it destructures the
/// event into the raw 32-byte peer id + a transport-free `PoolEventKind`, then defers the actual
/// construction to `crate::download::pool_event_to_selector` (which owns the identity byte-copy + the
/// removal-reason map, unit-tested there without dig-gossip in scope).
fn map_gossip_pool_event(ev: &dig_gossip::PoolEvent) -> dig_peer_selector::PoolEvent {
    match ev {
        dig_gossip::PoolEvent::PeerAdded { peer_id, addr } => {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(peer_id.as_ref());
            crate::download::pool_event_to_selector(
                bytes,
                crate::download::PoolEventKind::Added { addr: *addr },
            )
        }
        dig_gossip::PoolEvent::PeerRemoved { peer_id, reason } => {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(peer_id.as_ref());
            let reason = match reason {
                dig_gossip::PoolRemovalReason::Disconnected => {
                    crate::download::GossipRemovalReason::Disconnected
                }
                dig_gossip::PoolRemovalReason::Dead => crate::download::GossipRemovalReason::Dead,
                dig_gossip::PoolRemovalReason::Banned => {
                    crate::download::GossipRemovalReason::Banned
                }
            };
            crate::download::pool_event_to_selector(
                bytes,
                crate::download::PoolEventKind::Removed { reason },
            )
        }
    }
}

/// Wire the persistent relay reservation (#870) and share its status with the gossip pool.
///
/// Creates ONE [`dig_nat::relay::RelayStatus`], attaches it to the gossip `handle` (so the pool folds
/// the peers the reservation discovers into its address book — see
/// [`dig_gossip::GossipHandle::attach_relay_status`]), and — when the relay is enabled — spawns
/// `dig-nat`'s [`run_relay_connection`](dig_nat::relay::run_relay_connection) loop against that SAME
/// status. The gossip pool and the reservation loop therefore observe ONE shared status: without this
/// single shared `Arc`, discovered peers never reach the pool. When the relay is disabled
/// (`DIG_RELAY_URL=off`) the status is marked [`RelayStatus::set_disabled`] and no socket is opened.
/// Returns the shared status so the node can report the REAL reservation state (#872).
fn wire_relay_reservation(
    handle: &dig_gossip::GossipHandle,
    enabled: bool,
    endpoint: String,
    peer_id: String,
    network_id: String,
    listen_addrs: Vec<std::net::SocketAddr>,
) -> Arc<dig_nat::relay::RelayStatus> {
    let status = dig_nat::relay::RelayStatus::new();
    handle.attach_relay_status(status.clone());
    if enabled {
        let status = status.clone();
        tokio::spawn(async move {
            // B1 (#870): advertise the node's gossip listen candidates so the relay's reflexive
            // substitution can hand another peer a DIALABLE candidate for this node.
            dig_nat::relay::run_relay_connection(
                endpoint,
                peer_id,
                network_id,
                listen_addrs,
                status,
            )
            .await;
        });
    } else {
        status.set_disabled();
    }
    status
}

/// Bring up the peer network (the fallible body of [`spawn_peer_network`]).
async fn run_peer_network(node: Arc<crate::Node>) -> Result<(), String> {
    // Pin the rustls crypto provider (ring) before ANY TLS use (the pool + the mTLS listener + any
    // outbound dial), since aws-lc-rs is also in the graph and rustls won't auto-pick between them.
    install_crypto_provider();
    // Install the weak self-reference so a `&self` read handler can spawn an owned-`Arc` background
    // task — the capsule backfill on a read-from-another-node (SPEC §5.6). Weak: no self-keep-alive.
    node.set_self_ref(Arc::downgrade(&node));
    let status = node.peer_status();
    // The EFFECTIVE genesis (from `DIG_NETWORK_GENESIS`, else the canonical mainnet genesis) and the
    // effective network label derived from it — the ONE resolution shared by the gossip config, the
    // introducer/relay namespace, the discovery layers, and the operator-facing log below (#1372).
    let genesis = genesis_challenge_from_env();
    let network_id_str = effective_network_label_from_env();
    let relay_endpoint = relay_url_from_env();

    // 1. The node's stable mTLS identity, derived from its persistent §21 seed (so the peer_id is
    //    stable across restarts). Without a seed the node cannot present a stable identity; it still
    //    runs the HTTP read path but does not join the peer network.
    let seed = node
        .identity_seed_for_peer()
        .ok_or_else(|| "no identity seed; peer network needs a stable identity".to_string())?;
    // The node's PERSISTENT, CA-signed mTLS identity (#908, #1280): minted once from the node's own
    // BLS machine key (derived from the §21 seed) and persisted 0600 in the node's cert dir, so the
    // transport `peer_id` is stable across restarts and ONE cert is presented on every path (the DHT
    // dials, the peer-RPC server, the download transport all share this `Arc<NodeCert>`).
    let identity = load_or_generate_node_cert(node.node_cert_dir(), &seed)?;
    let peer_id_hex = identity.peer_id().to_hex();
    status.set_running(peer_id_hex.clone());
    println!(
        "dig-node peer network: peer_id {peer_id_hex} (network {network_id_str}, genesis {})",
        hex::encode(genesis)
    );

    // §14 autonomous sync — spawn the CHAIN-WATCH + GAP-FILL loop (SPEC §14.2 + §14.3) FIRST,
    // INDEPENDENTLY of the P2P layer below. The proactive pull path (`Node::gap_fill_generation` →
    // the authenticated §21 whole-store sync) needs NEITHER the connected pool NOR the DHT, so §14
    // MUST NOT be gated behind them: a failed pool/DHT bring-up (a network hiccup, or a misconfigured
    // all-zero `DIG_NETWORK_GENESIS` override the gossip config rejects — the DEFAULT genesis is a
    // real non-zero value that starts cleanly) must never silently disable autonomous sync — the
    // exact "declared complete but not running" gap (#213). The loop polls each
    // subscribed store's anchored root on its interval and pulls any confirmed generation it lacks,
    // verifying against the chain-anchored root; once the DHT is up (below) a successful pull also
    // refreshes the provider records via the inventory hook. The in-process FFI path never reaches
    // this bring-up, so it runs no watcher.
    crate::chainwatch::spawn_chain_watch(node.clone());
    println!(
        "dig-node peer network: chain-watch + gap-fill loop up (interval {:?})",
        crate::chainwatch::watch_interval_from_env()
    );

    // 2. Bring up the connected peer pool (dig-gossip) with discovery via the relay introducer + the
    //    relay reservation for NAT reachability. The GossipService owns its own chia-ssl TLS cert
    //    under the cache dir; the pool auto-discovers + maintains connected peers.
    let gossip_dir = node.peer_cert_dir();
    let _ = std::fs::create_dir_all(&gossip_dir);
    let mut cfg = dig_gossip::GossipConfig {
        network_id: genesis,
        cert_path: gossip_dir.join("node.cert").display().to_string(),
        key_path: gossip_dir.join("node.key").display().to_string(),
        peers_file_path: gossip_dir.join("peers.json"),
        peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
        // Bind the gossip pool on its OWN port, distinct from the mTLS peer-RPC listener below — they
        // are two listeners in one process and both defaulted to 9444, which fails on Linux (#871).
        listen_addr: crate::net::dual_stack_listen_addr(gossip_port_from_env()),
        ..Default::default()
    };
    if relay_enabled() {
        cfg.relay = Some(dig_gossip::RelayConfig {
            endpoint: relay_endpoint.clone(),
            enabled: true,
            ..Default::default()
        });
        // The introducer (peer discovery) rides the same relay host: the relay is the introducer.
        cfg.introducer = Some(dig_gossip::IntroducerConfig {
            endpoint: relay_endpoint.clone(),
            network_id: network_id_str.clone(),
            ..Default::default()
        });
    }

    let service = dig_gossip::GossipService::new(cfg).map_err(|e| format!("gossip config: {e}"))?;
    let handle = service
        .start()
        .await
        .map_err(|e| format!("gossip start: {e}"))?;
    println!("dig-node peer network: connected peer pool up (discovery via {relay_endpoint})");
    // Retain the pool handle on the node so the CONTROL surface can act on the live pool: dial a peer
    // (`control.peers.connect`) and enumerate the connected peers per-peer (`control.peerStatus`).
    node.set_gossip_handle(handle.clone());

    // 2b. Wire the PERSISTENT relay reservation (#870). `dig-nat` owns the transport: one long-lived
    //     WebSocket that registers once, keepalives, reconnects with backoff, AND discovers peers over
    //     the SAME socket (RLY-005 + pushes), exposing them via `RelayStatus::known_peers`. The node
    //     owns the reservation loop and shares the SAME `Arc<RelayStatus>` with the gossip pool via
    //     `attach_relay_status`, so those discovered peers flow into the pool's address book (the pool
    //     maintenance loop reads the attached status each pass). Without sharing ONE status, discovery
    //     never reaches the pool. Returns the shared status so the node reports the REAL reservation
    //     state (#872) rather than a "relay configured" proxy.
    let relay_status = wire_relay_reservation(
        &handle,
        relay_enabled(),
        relay_endpoint.clone(),
        peer_id_hex.clone(),
        network_id_str.clone(),
        gossip_listen_candidates(gossip_port_from_env()),
    );

    // 3. Keep the pool status fresh for `control.peerStatus`: the directly-connected count, the
    //    relay-reachable count (#870), and the REAL relay-reservation flag read from the shared
    //    `dig-nat` status (#872) — never the synthetic "relay configured" value it replaced.
    {
        let status = status.clone();
        let handle = handle.clone();
        let relay_status = relay_status.clone();
        tokio::spawn(async move {
            loop {
                let stats = handle.stats().await;
                status.set_pool(
                    stats.connected_peers as u64,
                    stats.relay_peer_count as u64,
                    relay_status.is_connected(),
                );
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }

    // 4. Bring up the content-location DHT (#163) over the SAME mTLS identity: it LOCATES which peers
    //    hold content this node wants, and keeps this node's OWN held-inventory provider records
    //    CURRENT so other nodes can find it. Best-effort — a DHT bring-up failure logs + leaves the
    //    node serving without the DHT (the pool + §21 read path still work).
    // Resolve the STUN server co-located with the relay (`<relay-host>:3478`) ONCE — it feeds both the
    // node's own reflexive-address discovery (advertised-candidate set) and the hole-punch tier of the
    // FULL NAT ladder every node dial now uses (#385). Blocking DNS resolution is moved off the async
    // runtime; a failure leaves STUN unconfigured (the ladder still falls through to the relay).
    // Resolve the STUN endpoints across BOTH address families (every A + AAAA record), IPv6-first: the
    // reflexive-advertise path races IPv6 before falling back to IPv4 and so needs a per-family endpoint
    // (#1393). The single IPv6-first server (`stun_servers.first()`) feeds the traversal-ladder
    // hole-punch tier + DHT transport, which take one reflexive-input endpoint.
    let stun_servers: Vec<std::net::SocketAddr> = if relay_enabled() {
        let ep = relay_endpoint.clone();
        tokio::task::spawn_blocking(move || crate::net::stun_servers_from_relay(&ep))
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let stun_server = stun_servers.first().copied();
    if let Some(stun) = stun_server {
        println!("dig-node peer network: STUN server for reflexive discovery: {stun}");
    }

    // The full-ladder runtime the DHT-lookup transport composes from (#836): the local listen port
    // (UPnP tier) + this node's STUN reflexive address (hole-punch input) + the relayed / TURN-last
    // tier over the node's LIVE relay reservation (`ReservationRelayedTransport` over the SAME
    // `Arc<RelayStatus>` shared with the pool). It powers BOTH the DHT-lookup ladder (`bring_up_dht`
    // below) AND the content/range-DOWNLOAD ladder (`NodeContent::for_dht` → `NatRangeTransport::
    // new_with_runtime`, #1439): the SAME shared `Arc<NatRuntime>` is threaded into both, so a range
    // fetch traverses direct → port-mapping → hole-punch → relay exactly like the DHT dial — a NAT'd
    // node reaches a holder over hole-punch/relay instead of DISCOVERING a provider it can only try
    // Direct against (dig-download 0.5's runtime-injecting dial API closes the prior #836 gap).
    let reflexive = crate::net::reflexive_via_stun(
        &stun_servers,
        peer_port_from_env(),
        std::time::Duration::from_secs(2),
    )
    .await;
    let relayed_dialer: Option<Arc<dyn dig_nat::RelayedDialer>> = if relay_enabled() {
        let ep = relay_endpoint.clone();
        let relay_addr = tokio::task::spawn_blocking(move || crate::net::relay_socket_addr(&ep))
            .await
            .ok()
            .flatten();
        relay_addr.map(|addr| {
            Arc::new(dig_nat::ReservationRelayedTransport::new(
                relay_status.clone(),
                addr,
            )) as Arc<dyn dig_nat::RelayedDialer>
        })
    } else {
        None
    };
    let nat_runtime = Arc::new(crate::net::build_node_nat_runtime(
        peer_port_from_env(),
        reflexive,
        relayed_dialer,
    ));

    // The durable, IPv6-first peer address book (#381): every PEX-learned + otherwise-learned candidate
    // accumulates here (incl. relay-only hints) instead of being dial-and-dropped, seeding future dials.
    // The selector-driven dial ranker (#384) is wired below once the content engine (the shared
    // selector) is up; until then dials keep the book's IPv6-first order.
    let address_book = Arc::new(crate::address_book::AddressBook::default());
    let mut dial_ranker: Option<Arc<dyn crate::pex::DialRanker>> = None;

    let dht = match bring_up_dht(
        &node,
        &identity,
        &nat_runtime,
        &network_id_str,
        &handle,
        &stun_servers,
    )
    .await
    {
        Ok(dht) => Some(dht),
        Err(e) => {
            tracing::warn!(error = %e, "dig-node DHT bring-up failed; continuing without the DHT");
            status.set_error(format!("dht: {e}"));
            None
        }
    };

    // 4b. Bring up the P2P CONTENT engine (#164/#165) over the live DHT + this node's mTLS identity: the
    //     dig-download multi-source fetch path (locate→confirm→fan ranges→verify→reassemble) plus the
    //     redirect-on-miss provider lookup. Attached to the node so a content miss on the peer/§21/agent
    //     surface REDIRECTS the caller to a holder (default) or FETCHES-THROUGH (`DIG_NODE_ON_MISS=fetch`)
    //     instead of dead-ending. Only wired when the DHT is up (it is the provider source); a startup
    //     GC sweep + interval reap abandoned `.download.tmp` staging files.
    if let Some(dht) = dht.clone() {
        let content = crate::download::NodeContent::for_dht(
            dht.service().clone(),
            identity.clone(),
            &network_id_str,
            crate::download::miss_mode_from_env(),
            Some(peer_id_hex.clone()),
            node.cache_dir_path(),
            stun_server,
            // #1439: the fetch leg rides the SAME shared NAT runtime as the DHT dial (hole-punch/relay).
            nat_runtime.clone(),
        );
        content.spawn_gc();
        // Feed the selector's registry from the connected pool (#178, SPEC §2.3): seed from the current
        // pool snapshot, then forward every pool churn event so the selector always ranks against the
        // live peer set. The selector already drives dig-download's source choice + learns from every
        // range outcome inside `NodeContent`; this keeps its candidate registry current.
        spawn_selector_registry_feed(content.clone(), handle.clone());
        // #384: the SAME self-optimizing selector that ranks download SOURCES also drives PEX dial
        // ORDERING — reuse the ONE selector instance (never a second) so a high-quality peer is dialed
        // before a low-quality one.
        dial_ranker = Some(Arc::new(crate::download::SelectorDialRanker::new(
            content.selector().clone(),
        )));
        node.set_p2p_content(content);
        println!(
            "dig-node peer network: P2P content engine up (selector-driven, miss mode: {:?})",
            crate::download::miss_mode_from_env()
        );
    }

    // 4c. Install the DHT inventory-refresh hook (SPEC §6.2). The hook lets the FFI-safe `Node`
    //     reconcile its DHT provider records against its cache inventory the moment a generation is
    //     gap-filled or a capsule is explicitly cached, so peers find the new holder without waiting
    //     for the maintenance loop. It is wired ONLY when the DHT is up (the DHT is the refresh
    //     target); with no hook installed the refresh is a documented no-op.
    if let Some(dht) = dht.clone() {
        let node_for_hook = node.clone();
        let dht_for_hook = dht.clone();
        node.set_inventory_refresher(Box::new(move || {
            let node = node_for_hook.clone();
            let dht = dht_for_hook.clone();
            Box::pin(async move {
                let cached = node.cache_list_cached().await;
                let (announced, withdrawn) = dht.refresh_inventory(&cached).await;
                if announced > 0 || withdrawn > 0 {
                    tracing::debug!(
                        announced,
                        withdrawn,
                        "dig-node DHT: refreshed provider records after an inventory change"
                    );
                }
            })
        }));
    }

    // (The chain-watch + gap-fill loop was spawned FIRST, above, independent of the pool/DHT — §14.)

    // Graceful shutdown: on ctrl-c, best-effort withdraw this node's provider records so peers stop
    // being told to dial a node that is going away (TTL expiry is the backstop if this does not reach
    // every replica). Spawned so it does not block the listener; a no-op when the DHT is not up.
    if let Some(dht) = dht.clone() {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let withdrawn = dht.withdraw_all().await;
                tracing::info!(
                    withdrawn,
                    "dig-node DHT: withdrew provider records on shutdown"
                );
            }
        });
    }

    // 5. Serve the L7 peer RPC over mTLS to other nodes: a dedicated mTLS listener using the SAME
    //    identity, requiring a client cert (peer_id enforced), each accepted connection muxed +
    //    served via `serve_peer_session`. Inbound DHT RPCs on those sessions are answered by the DHT
    //    (folding in the mTLS-verified caller) when it is up.
    //
    //    IPv6-first, IPv4-fallback (ecosystem HARD RULE): bind the IPv6 unspecified address `[::]` as a
    //    DUAL-STACK socket (IPV6_V6ONLY cleared) so this ONE socket serves both native IPv6 peers AND
    //    IPv4-mapped peers on the same port. (The old `0.0.0.0` bind was IPv4-only and dropped IPv6.)
    let port = peer_port_from_env();
    let addr = crate::net::dual_stack_listen_addr(port);
    let listener = crate::net::bind_tcp_dual_stack(addr)
        .map_err(|e| format!("bind dual-stack peer-RPC listener {addr}: {e}"))?;
    println!("dig-node peer network: mTLS peer-RPC listening on {addr} (dual-stack, IPv6-first)");
    // 6. Bring up the node↔node PEX peer-sharing layer (#166): one node-wide engine advertising this
    //    node's first-hand connected pool, a pool feeder mirroring pool churn into its advertise set,
    //    the ~1/s tick loop, and the production pool sink (candidates → dial+verify+adopt over dig-nat,
    //    violations → disconnect). Threaded onto the mTLS listener so each accepted peer connection
    //    runs both PEX directions. Additive + best-effort — the pool + DHT + §21 read path are
    //    unaffected if PEX is idle. (The in-process FFI path opens no listener, so it runs no PEX.)
    let pex_engine = crate::pex::PexEngineHandle::new(
        dig_pex::PexConfig::new(peer_id_hex.clone(), network_id_str.clone())
            .with_flags(vec![crate::pex::node_pex_flag().to_string()]),
    );
    crate::pex::spawn_pool_feeder(pex_engine.clone(), handle.clone(), network_id_str.clone());
    crate::pex::spawn_tick_loop(pex_engine.clone());
    let pex = crate::pex::PexServing::new(
        pex_engine,
        Arc::new(crate::pex::GossipPexPool::new(
            handle.clone(),
            stun_server,
            address_book,
            dial_ranker,
        )),
    );

    // The served responder carries the LIVE pool handle so `dig.getPeers` reflects connected peers,
    // and the DHT so inbound DHT RPCs are answered.
    let mut node_responder = NodeResponder::with_pool(node, handle);
    if let Some(dht) = dht {
        node_responder = node_responder.with_dht(dht);
    }
    let responder: Arc<dyn PeerRpcResponder> = Arc::new(node_responder);
    serve_peer_rpc_listener_with(listener, identity, responder, Some(pex)).await
}

/// Bring up the content-location DHT (#163) for a running node: build a [`crate::dht::NatDhtTransport`]
/// over the node's mTLS identity, create the [`dig_dht::DhtService`], BOOTSTRAP it from the dig-gossip
/// connected pool (which also carries relay-introducer-discovered peers), ANNOUNCE the node's current
/// inventory (so peers can immediately find what it holds), and spawn the maintenance loop
/// (`republish`/`refresh_buckets`/`gc`) so provider records never lapse while online. Returns the
/// [`crate::dht::DhtHandle`] the responder + inventory-change path use.
async fn bring_up_dht(
    node: &Arc<crate::Node>,
    node_cert: &Arc<dig_nat::NodeCert>,
    runtime: &Arc<dig_nat::NatRuntime>,
    network_id: &str,
    pool: &dig_gossip::GossipHandle,
    stun_servers: &[std::net::SocketAddr],
) -> Result<Arc<crate::dht::DhtHandle>, String> {
    use dig_dht::{CandidateAddr, DhtConfig, DhtService};

    // The single IPv6-first STUN server feeds the DHT transport's hole-punch tier (one reflexive-input
    // endpoint); the reflexive-advertise path below races the full per-family set (#1393).
    let stun_server = stun_servers.first().copied();
    let config = DhtConfig::default();
    // The transport dials peers as THIS node (client cert = our identity), scoping relay lookups to
    // our network id, bounding each RPC by the config's per-RPC timeout, over the FULL NAT ladder with
    // the relay's STUN server feeding its hole-punch tier (#385).
    let transport = Arc::new(
        crate::dht::NatDhtTransport::new(
            Arc::clone(node_cert),
            Arc::clone(runtime),
            network_id.to_string(),
            config.rpc_timeout,
        )
        .with_stun_server(stun_server),
    );
    // Our own advertised addresses: the node's REAL routable address(es) at the P2P listen port,
    // ordered IPv6-first (ecosystem HARD RULE) — a global-unicast IPv6 address (when the host has one)
    // precedes the IPv4 fallback, so a peer's happy-eyeballs dialer prefers IPv6. The wildcard bind
    // address (`[::]` / `0.0.0.0`) is NOT dialable and must never leak as a candidate. A NAT'd node
    // with no routable address advertises nothing here and stays reachable via the relay tiers dig-nat
    // composes; loopback/in-process setups opt into a loopback candidate via DIG_NODE_ADVERTISE_LOOPBACK.
    let port = peer_port_from_env();
    // This node's STUN-discovered server-reflexive (public) address (#385), so a remote peer behind a
    // different NAT can dial / hole-punch to it, not just to a LAN-local address. Best-effort +
    // bounded: a failure (no STUN server, timeout) advertises the local addresses only.
    let reflexive = crate::net::reflexive_via_stun(stun_servers, port, config.rpc_timeout).await;
    if let Some(r) = reflexive {
        println!(
            "dig-node peer network: STUN reflexive address {r} added to advertised candidates"
        );
    }
    // Assemble the advertised candidate set, IPv6-first via dig_ip::Family (the reflexive leads its
    // family group); see `crate::net::assemble_advertised`. The wildcard bind (`[::]` / `0.0.0.0`)
    // is never a candidate.
    let local_addresses: Vec<CandidateAddr> = crate::net::advertised_socket_addrs_with_reflexive(
        port,
        crate::net::advertise_loopback_from_env(),
        reflexive,
    )
    .into_iter()
    .map(|sa| CandidateAddr::direct(sa.ip().to_string(), sa.port()))
    .collect();
    let service = Arc::new(DhtService::new(
        node_cert.peer_id(),
        local_addresses,
        config.clone(),
        transport,
    ));

    // Bootstrap from the connected pool (+ relay-introducer peers discovered into it).
    let pool_peers: Vec<([u8; 32], std::net::SocketAddr)> = pool
        .connected_pool_peers()
        .into_iter()
        .map(|(peer_id, addr, _outbound)| {
            // dig-gossip's PeerId is a chia Bytes32; take its raw 32 bytes for the dig-nat PeerId.
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(peer_id.as_ref());
            (bytes, addr)
        })
        .collect();
    let bootstrap = crate::dht::bootstrap_peers_from_pool(&pool_peers);
    if let Err(e) = service.bootstrap(&bootstrap).await {
        // A failed bootstrap (no peers yet) is not fatal: local provider records still stand and the
        // maintenance loop re-attempts the PUT as the pool fills. Log + carry on.
        tracing::debug!(error = %e, "DHT bootstrap found no peers yet; records republish once the pool fills");
    }

    // Announce the node's CURRENT inventory so peers can immediately find the content it holds.
    let cached = node.cache_list_cached().await;
    let announced = crate::dht::announce_inventory(&service, &cached).await;
    let initial_ids = crate::dht::inventory_content_ids(&cached);
    println!(
        "dig-node peer network: DHT up — announced {announced} content id(s) for local inventory"
    );

    let dht = crate::dht::DhtHandle::new(service, initial_ids);

    // Spawn the maintenance loop: republish (records never lapse) + refresh buckets + gc, well inside
    // the provider TTL.
    {
        let dht = dht.clone();
        let interval = config.republish_interval;
        tokio::spawn(async move {
            crate::dht::run_maintenance(dht, interval).await;
        });
    }

    Ok(dht)
}

/// Run the mTLS peer-RPC accept loop over a pre-bound `listener`: accept inbound TLS connections
/// (client cert REQUIRED, remote `peer_id` = SHA-256(SPKI) derived at the handshake), wrap each in a
/// yamux server session, and [`serve_peer_session`] it against `responder`. This is the concrete
/// "serve the L7 peer RPC over mTLS (incoming, from other nodes)" path — no unauthenticated peer
/// traffic is ever processed (rustls drops a peer with no/invalid cert before any byte). Taking a
/// pre-bound listener + an injectable responder makes it drivable from a loopback integration test.
pub async fn serve_peer_rpc_listener(
    listener: tokio::net::TcpListener,
    node: Arc<dig_nat::NodeCert>,
    responder: Arc<dyn PeerRpcResponder>,
) -> Result<(), String> {
    serve_peer_rpc_listener_with(listener, node, responder, None).await
}

/// Like [`serve_peer_rpc_listener`] but additionally running the node↔node **PEX** peer-sharing layer
/// (#166) over each accepted mTLS connection when `pex` is `Some`: the node opens its outgoing PEX
/// stream (handshake→snapshot→deltas) and serves the peer's incoming PEX stream, feeding discovered
/// peers into the pool as dial candidates. `None` disables PEX (the FFI/base path + existing callers),
/// leaving the serve path byte-identical to before.
pub async fn serve_peer_rpc_listener_with(
    listener: tokio::net::TcpListener,
    node: Arc<dig_nat::NodeCert>,
    responder: Arc<dyn PeerRpcResponder>,
    pex: Option<Arc<crate::pex::PexServing>>,
) -> Result<(), String> {
    let server_config = build_server_tls_config(&node)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

    // Global accepted-connection concurrency cap (audit #179 HIGH). A permit is acquired BEFORE the
    // per-connection serve task is spawned — INCLUDING the mTLS handshake, so half-open/slowloris
    // handshakes count against the budget — and held until the connection is fully served. When
    // saturated the raw TCP socket is dropped immediately (load-shed) rather than spawning unbounded
    // connection tasks that each hold a TLS session + FD + yamux session.
    let conn_permits = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PEER_CONNECTIONS));

    loop {
        let (tcp, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "peer-RPC accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let responder = responder.clone();
        let pex = pex.clone();
        let spawned = spawn_with_permit(&conn_permits, async move {
            // mTLS handshake (client cert required by build_server_tls_config; a peer with no cert or
            // a failed handshake is dropped here — no unauthenticated peer traffic reaches the RPC).
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    // Derive the AUTHENTICATED caller identity from the client's leaf certificate
                    // (peer_id = SHA-256(SPKI DER)) + the socket it connected from, so inbound DHT
                    // RPCs on this session populate the routing table bidirectionally (#163). The
                    // peer_id comes from the certificate the mTLS layer just verified — never the wire
                    // body. `None` if (defensively) no client cert is present, which the verifier
                    // should already have rejected.
                    let caller = caller_from_tls(&tls, peer_addr);
                    let mut session = dig_nat::mux::PeerSession::server(tls);
                    serve_peer_session_from_with(caller, &mut session, responder, pex).await;
                }
                Err(e) => tracing::debug!(error = %e, "peer mTLS handshake failed; dropped"),
            }
        });
        if !spawned {
            // At the global connection cap: shed this connection. `tcp` was moved into the (dropped)
            // future, so it is closed here — the peer must retry later. Sheds instead of unbounded
            // spawning (audit #179 HIGH).
            tracing::debug!(%peer_addr, "peer connection shed: global connection cap reached");
        }
    }
}

/// Build the authenticated caller [`dig_dht::Contact`] from an accepted mTLS server connection: read
/// the client's leaf certificate, derive its `peer_id = SHA-256(SPKI DER)` (the SAME derivation
/// dig-nat enforces), and pair it with the remote socket address. Returns `None` if no client cert is
/// present or it does not parse (the client-cert verifier should already have rejected such a peer).
fn caller_from_tls(
    tls: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    remote_addr: std::net::SocketAddr,
) -> Option<dig_dht::Contact> {
    let (_io, conn) = tls.get_ref();
    let leaf = conn.peer_certificates()?.first()?;
    let peer_id = dig_nat::peer_id_from_leaf_cert_der(leaf.as_ref())?;
    Some(crate::dht::caller_contact(&peer_id, remote_addr))
}

/// Build the rustls `ServerConfig` for the mTLS peer-RPC listener from the node's CA-signed
/// [`NodeCert`](dig_nat::NodeCert): present its leaf + key and REQUIRE a client certificate chaining
/// to the shipped DigNetwork CA, with the #1204 BLS binding checked per the rollout policy
/// ([`BindingPolicy::Opportunistic`](dig_nat::BindingPolicy)). dig-tls's verifier derives the caller
/// `peer_id = SHA-256(SPKI DER)` during the handshake, so a peer presenting no/invalid cert is
/// rejected by rustls before any byte is processed.
fn build_server_tls_config(node: &dig_nat::NodeCert) -> Result<Arc<rustls::ServerConfig>, String> {
    dig_tls::server_config(node, dig_nat::BindingPolicy::Opportunistic)
        .map(|server_tls| server_tls.config)
        .map_err(|e| format!("server TLS config: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An opaque, representative genesis hex for the `snapshot_json` status tests (echoed verbatim
    /// by the snapshot; its value is not asserted except by the dedicated genesis-field test).
    const TEST_GENESIS_HEX: &str =
        "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff";

    fn cap(store: &str, root: &str, size: u64, mtime: u64) -> CachedCapsule {
        CachedCapsule {
            store_id: store.to_string(),
            root: root.to_string(),
            size_bytes: size,
            last_used_unix_ms: mtime,
        }
    }

    #[test]
    fn peer_status_reports_not_running_by_default() {
        let s = PeerStatus::new();
        assert!(!s.is_running());
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["running"], false);
        assert_eq!(v["peer_id"], Value::Null);
        assert_eq!(v["network_id"], DEFAULT_NETWORK_ID);
        assert_eq!(
            v["genesis"], TEST_GENESIS_HEX,
            "the status snapshot surfaces the effective genesis for operator observability (#1372)"
        );
        assert_eq!(v["relay"]["url"], DEFAULT_RELAY_URL);
        assert_eq!(v["relay"]["reserved"], false);
        assert_eq!(v["connected_peers"], 0);
    }

    #[test]
    fn peer_status_transitions_to_running_and_reports_pool() {
        let s = PeerStatus::new();
        s.set_running("ab".repeat(32));
        s.set_pool(5, 2, true);
        assert!(s.is_running());
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["running"], true);
        assert_eq!(v["peer_id"], json!("ab".repeat(32)));
        assert_eq!(v["connected_peers"], 5);
        assert_eq!(v["relay"]["reserved"], true);
        assert_eq!(v["relay"]["peer_count"], 2);
        s.set_error("relay dropped".into());
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["last_error"], json!("relay dropped"));
    }

    // #872: `relay.reserved` is the REAL persistent-reservation state, not a "relay configured" proxy.
    // A relay endpoint being present in the snapshot must NOT imply reserved — reserved flips only with
    // the actual reservation being held.
    #[test]
    fn peer_status_reserved_flag_is_independent_of_relay_being_configured() {
        let s = PeerStatus::new();
        // Relay configured (endpoint present) but reservation NOT held → reserved is false.
        s.set_pool(0, 0, false);
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["relay"]["url"], DEFAULT_RELAY_URL);
        assert_eq!(
            v["relay"]["reserved"], false,
            "a configured-but-unheld relay must report reserved=false"
        );
        // Reservation established → reserved flips true.
        s.set_pool(0, 3, true);
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["relay"]["reserved"], true);
        assert_eq!(v["relay"]["peer_count"], 3);
    }

    // #871 regression: the gossip pool and the mTLS peer-RPC server are two listeners in one process
    // and MUST bind different ports. The old code left both on 9444 (worked on Windows, EADDRINUSE on
    // Linux). This asserts the fix invariant — distinct default ports — and would FAIL on the old
    // shared-9444 build.
    #[test]
    fn gossip_pool_and_peer_rpc_use_distinct_ports() {
        assert_eq!(DEFAULT_P2P_PORT, 9444);
        assert_eq!(DEFAULT_GOSSIP_PORT, 9445);
        assert_ne!(
            DEFAULT_GOSSIP_PORT, DEFAULT_P2P_PORT,
            "gossip pool and mTLS peer-RPC must not share a listen port (#871)"
        );
        assert_ne!(
            gossip_port_from_env(),
            peer_port_from_env(),
            "resolved gossip + peer-RPC ports must differ"
        );
    }

    // #871: both listeners bind cleanly when given distinct ports — the fix. Binds the mTLS peer-RPC
    // dual-stack listener and starts a gossip pool on a DIFFERENT port, exactly as `run_peer_network`
    // does; both must succeed (on the old shared-9444 build the second bind fails on Linux).
    #[tokio::test]
    async fn gossip_pool_and_peer_rpc_bind_together_on_distinct_ports() {
        // The mTLS peer-RPC listener on an OS-assigned ephemeral port.
        let peer_rpc = crate::net::bind_tcp_dual_stack(crate::net::dual_stack_listen_addr(0))
            .expect("peer-RPC dual-stack bind must succeed");
        let peer_port = peer_rpc.local_addr().unwrap().port();

        // The gossip pool on its OWN OS-assigned ephemeral port (a different socket).
        let dir = std::env::temp_dir().join(format!("dig-node-wuc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dig_gossip::GossipConfig {
            network_id: chia_protocol::Bytes32::new([1u8; 32]),
            cert_path: dir.join("node.cert").display().to_string(),
            key_path: dir.join("node.key").display().to_string(),
            peers_file_path: dir.join("peers.json"),
            peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
            listen_addr: crate::net::dual_stack_listen_addr(0),
            ..Default::default()
        };
        let service = dig_gossip::GossipService::new(cfg).expect("gossip config");
        let handle = service.start().await.expect("gossip start must succeed");

        // Both listeners are up simultaneously — no port clash.
        assert!(peer_port != 0);
        let _ = handle.pool_stats();
    }

    // #870 + #872: the node shares ONE `Arc<RelayStatus>` between the relay-reservation loop and the
    // gossip pool. Proven by attaching the status returned from `wire_relay_reservation` and mutating
    // THAT status: the change is visible through the gossip handle's stats, so the pool observes the
    // same reservation the node drives.
    #[tokio::test]
    async fn wire_relay_reservation_shares_one_status_with_the_pool() {
        let dir = std::env::temp_dir().join(format!("dig-node-wuc-share-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dig_gossip::GossipConfig {
            network_id: chia_protocol::Bytes32::new([2u8; 32]),
            cert_path: dir.join("node.cert").display().to_string(),
            key_path: dir.join("node.key").display().to_string(),
            peers_file_path: dir.join("peers.json"),
            peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
            listen_addr: crate::net::dual_stack_listen_addr(0),
            ..Default::default()
        };
        let handle = dig_gossip::GossipService::new(cfg)
            .expect("gossip config")
            .start()
            .await
            .expect("gossip start");

        // Wire with the relay DISABLED so no real socket is opened; we drive the shared status by hand.
        let status = wire_relay_reservation(
            &handle,
            false,
            DEFAULT_RELAY_URL.to_string(),
            "ab".repeat(32),
            DEFAULT_NETWORK_ID.to_string(),
            gossip_listen_candidates(0),
        );

        // Before: no reservation held → the pool reports the relay disconnected.
        assert!(!handle.stats().await.relay_connected);

        // Drive the SAME status the node passes to `run_relay_connection`: the pool must see it.
        status.set_connected(4);
        assert!(status.is_connected());
        assert!(
            handle.stats().await.relay_connected,
            "the gossip pool must observe the reservation via the shared Arc<RelayStatus>"
        );
    }

    /// A fresh pool has no connected peers, so the per-peer array is empty (the honest "count only"
    /// state before any peer connects). Uses a real `GossipHandle` — the same type the node retains.
    #[tokio::test]
    async fn connected_peers_json_is_empty_for_a_fresh_pool() {
        let handle = fresh_pool_handle("cpjson-empty", [3u8; 32]).await;
        assert!(connected_peers_json(&handle).is_empty());
    }

    /// `control.peers.connect` rejects an argument that is neither a dialable `host:port` nor an
    /// already-connected `peer_id` — DETERMINISTICALLY (no dial attempt, no hang). Proves the error
    /// path the RPC arm returns as a control error.
    #[tokio::test]
    async fn connect_peer_rejects_a_non_address_non_peer_id_argument() {
        let handle = fresh_pool_handle("connect-bad-arg", [4u8; 32]).await;
        let err = connect_peer(&handle, "not-an-address").await.unwrap_err();
        assert!(err.contains("dialable address"), "got: {err}");
    }

    /// Whether the host has a usable IPv6 loopback stack. Some CI sandboxes disable IPv6 entirely,
    /// in which case a `[::1]` dial cannot be exercised; the two-node test skips rather than reporting
    /// a false failure unrelated to this crate's connect logic (mirrors dig-gossip's CON-002 guard).
    async fn host_has_ipv6_loopback() -> bool {
        tokio::net::TcpListener::bind("[::1]:0").await.is_ok()
    }

    /// Read a pooled peer's transport `via` from the per-peer JSON, or `None` if that `peer_id` is
    /// not in the pool. The mutual-connection proof surface for the A↔B check below.
    fn via_of(handle: &dig_gossip::GossipHandle, peer_id_hex: &str) -> Option<String> {
        connected_peers_json(handle)
            .into_iter()
            .find(|p| p["peer_id"] == peer_id_hex)
            .map(|p| p["via"].as_str().unwrap_or_default().to_string())
    }

    /// Poll `connected_peers_json` until it reports at least one peer (the inbound side registers the
    /// dial asynchronously after the handshake completes), up to a short deadline. Returns the
    /// per-peer rows once non-empty, else an empty vec on timeout.
    async fn await_any_peer(handle: &dig_gossip::GossipHandle) -> Vec<Value> {
        for _ in 0..50 {
            let peers = connected_peers_json(handle);
            if !peers.is_empty() {
                return peers;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Vec::new()
    }

    /// Whether the gossip inbound-accept path registers a loopback peer into the connected pool on
    /// this platform. Only asserted on Linux — the EC2 A↔B target and the CI test OS (`ubuntu-latest`).
    /// The Windows/macOS native-tls (SChannel/Security.framework) inbound loopback path does not fold
    /// an accepted peer into the pool the way OpenSSL does (the same `[::]`-v6only / native-tls class
    /// of dev-host quirk tracked for the extension-offline path), so on those hosts the MUTUAL half is
    /// skipped with a notice rather than reported as a false failure. A's OUTBOUND half + the
    /// `control.peerStatus` remote-peer_id instrument + `control.peers.disconnect` are proven on every
    /// platform.
    const POOL_REGISTERS_INBOUND_LOOPBACK: bool = cfg!(target_os = "linux");

    /// **The #853 bar in miniature (#980):** two real nodes handshake over loopback mTLS and each
    /// lists the OTHER in `control.peerStatus` — the machine-checkable proof of a MUTUAL A↔B
    /// connection, run locally BEFORE any EC2 time is spent. Node A dials node B IPv6-first
    /// (`[::1]:<port>`, §5.2); the returned `peer_id` is B's real cert id (solid on every platform —
    /// the server cert is always visible to the dialing client), and A's `connected_peers_json` (the
    /// exact source `control.peerStatus` serves — see `handle_rpc`) lists B's REMOTE peer_id + `via` +
    /// direction, proving the peerStatus instrument surfaces remote peers. On Linux (the CI + EC2
    /// target) B's pool lists A as an INBOUND peer whose `peer_id` equals A's `local_peer_id` — the
    /// full mutual-id proof. Then A disconnects B via `control.peers.disconnect` and its pool drops the
    /// link.
    #[tokio::test]
    async fn two_nodes_connect_over_loopback_and_each_sees_the_other() {
        if !host_has_ipv6_loopback().await {
            eprintln!("skipping: host has no usable IPv6 loopback stack");
            return;
        }
        // The gossip mTLS stack needs a process-global rustls crypto provider; install it up front so
        // this test is order-independent (production installs it during node bring-up).
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Same network_id on both — a mismatch would be rejected at handshake. B binds a concrete
        // IPv6 loopback (§5.2 IPv6-first) so the inbound accept registers on every platform.
        let loopback_v6 = "[::1]:0".parse().expect("parse [::1]:0");
        let node_a = fresh_pool_handle("loopback-a", [0x5au8; 32]).await;
        let node_b = fresh_pool_handle_on("loopback-b", [0x5au8; 32], loopback_v6).await;

        let a_peer_id = hex::encode(node_a.local_peer_id().expect("node A local_peer_id"));
        let b_port = node_b
            .__listen_bound_addr_for_tests()
            .expect("node B bound listen addr")
            .port();

        // A dials B on the IPv6 loopback (§5.2 IPv6-first); connect_peer returns B's observed peer_id.
        let b_addr = format!("[::1]:{b_port}");
        let b_peer_id = connect_peer(&node_a, &b_addr)
            .await
            .expect("node A dials node B over loopback mTLS");

        // A's pool lists B by B's real cert id (A initiated the dial → synchronous), over a DIRECT
        // transport, in the OUTBOUND direction — A's half of the mutual proof.
        let a_view = connected_peers_json(&node_a);
        let a_sees_b = a_view
            .iter()
            .find(|p| p["peer_id"] == b_peer_id)
            .expect("node A must list node B's peer_id");
        assert_eq!(a_sees_b["via"], "direct", "A→B is a direct-TLS link");
        assert_eq!(a_sees_b["direction"], "outbound", "A dialed B");

        // B's pool lists A once the inbound handshake registers (asynchronous) — the MUTUAL half.
        // Only the OpenSSL (Linux) native-tls path folds the accepted loopback peer into the pool.
        if POOL_REGISTERS_INBOUND_LOOPBACK {
            let b_view = await_any_peer(&node_b).await;
            assert_eq!(
                b_view.len(),
                1,
                "node B must list exactly one peer (node A) — proving a MUTUAL A↔B connection"
            );
            assert_eq!(b_view[0]["direction"], "inbound", "B accepted A's dial");
            assert_eq!(
                b_view[0]["peer_id"], a_peer_id,
                "node B must list node A's REAL peer_id — the full mutual-id #853 proof"
            );
        } else {
            eprintln!(
                "skipping the inbound MUTUAL half: this platform's native-tls does not register an \
                 accepted loopback peer into the pool (Linux/CI/EC2 enforces it)"
            );
        }

        // control.peers.disconnect: A drops B; A's pool loses the link.
        disconnect_peer(&node_a, &b_peer_id)
            .await
            .expect("node A disconnects node B");
        assert!(
            via_of(&node_a, &b_peer_id).is_none(),
            "after disconnect, node A must no longer list node B"
        );
        // Disconnecting an already-gone peer_id is an idempotent no-op (still Ok).
        disconnect_peer(&node_a, &b_peer_id)
            .await
            .expect("disconnect is idempotent");
    }

    /// `control.peers.disconnect` rejects a malformed `peer_id` DETERMINISTICALLY (not 64-hex),
    /// mirroring the connect arg-validation path — no network touch, no hang.
    #[tokio::test]
    async fn disconnect_peer_rejects_a_malformed_peer_id() {
        let handle = fresh_pool_handle("disconnect-bad-arg", [7u8; 32]).await;
        let err = disconnect_peer(&handle, "not-hex").await.unwrap_err();
        assert!(err.contains("64-hex peer_id"), "got: {err}");
    }

    /// #709/#846: `control.peerStatus`'s `pool` object reports the pool's connectivity posture. A
    /// freshly-started, unconnected pool has `connected == 0` and is `under_connected` (below the
    /// configured `min`), with a coherent `min <= target <= max` triple exposed for an operator to
    /// reason about the pool. Sourced from the live GossipHandle's `pool_stats` — no new RPC method
    /// (the new peer-management VERBS `setBan`/`setPoolConfig` need a dig-rpc-protocol `Method`
    /// variant, a cross-family contract release, so this PR extends the existing peerStatus surface).
    #[tokio::test]
    async fn pool_stats_json_reports_the_pool_posture() {
        let handle = fresh_pool_handle("pool-stats", [9u8; 32]).await;
        let stats = pool_stats_json(&handle);
        assert_eq!(stats["connected"], 0, "a fresh pool has no connected peers");
        assert_eq!(stats["in_flight"], 0, "no dials are in flight yet");
        let (min, target, max) = (
            stats["min"].as_u64().expect("min"),
            stats["target"].as_u64().expect("target"),
            stats["max"].as_u64().expect("max"),
        );
        assert!(
            min <= target && target <= max,
            "pool config triple must be ordered: {min} <= {target} <= {max}"
        );
        assert!(min >= 1, "a real pool wants at least one peer");
        assert_eq!(
            stats["under_connected"], true,
            "0 connected is below min, so the pool is under-connected"
        );
    }

    /// Build a real, freshly-started `GossipHandle` on the production-shaped dual-stack unspecified
    /// bind (`[::]:0`, §5.2) for the pool-handle tests.
    async fn fresh_pool_handle(tag: &str, network: [u8; 32]) -> dig_gossip::GossipHandle {
        fresh_pool_handle_on(tag, network, crate::net::dual_stack_listen_addr(0)).await
    }

    /// Build a freshly-started `GossipHandle` bound on an explicit `listen_addr`.
    ///
    /// The two-node loopback proof binds its LISTENER on a CONCRETE IPv6 loopback (`[::1]:0`) rather
    /// than the unspecified dual-stack `[::]:0`: on Windows a `[::]`-unspecified bind does not accept
    /// inbound loopback connections into the pool (the native-tls dual-stack accept quirk — the same
    /// family of `[::]`-v6only issue tracked for the extension-offline path), whereas a concrete
    /// loopback bind does, on every platform. Production still binds dual-stack `[::]` (`run_peer_network`).
    async fn fresh_pool_handle_on(
        tag: &str,
        network: [u8; 32],
        listen_addr: std::net::SocketAddr,
    ) -> dig_gossip::GossipHandle {
        let dir = std::env::temp_dir().join(format!("dig-node-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dig_gossip::GossipConfig {
            network_id: chia_protocol::Bytes32::new(network),
            cert_path: dir.join("node.cert").display().to_string(),
            key_path: dir.join("node.key").display().to_string(),
            peers_file_path: dir.join("peers.json"),
            peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
            listen_addr,
            ..Default::default()
        };
        dig_gossip::GossipService::new(cfg)
            .expect("gossip config")
            .start()
            .await
            .expect("gossip start")
    }

    #[test]
    fn relay_url_defaults_and_opt_out() {
        // Pure cores — no process-global env mutation (so no cross-test env race).
        assert_eq!(resolve_relay_url(None), DEFAULT_RELAY_URL);
        assert_eq!(
            resolve_relay_url(Some("   ")),
            DEFAULT_RELAY_URL,
            "blank → default"
        );
        assert_eq!(
            resolve_relay_url(Some("wss://my-relay:9450")),
            "wss://my-relay:9450"
        );
        assert!(is_relay_enabled(None), "unset → enabled");
        assert!(!is_relay_enabled(Some("off")));
        assert!(
            !is_relay_enabled(Some("DISABLED")),
            "case-insensitive opt-out"
        );
        assert!(is_relay_enabled(Some("wss://my-relay:9450")));
    }

    #[test]
    fn default_relay_is_canonical_443_endpoint() {
        // The default MUST be the canonical relay endpoint (`:443`, where relay.dig.net actually
        // serves the reservation wire) — never a drifted hard-coded port. Regression for the WU7
        // proof, where a stale `:9450` default silently failed every stock node's reservation.
        assert_eq!(DEFAULT_RELAY_URL, dig_constants::DIG_RELAY_URL);
        assert!(
            DEFAULT_RELAY_URL.ends_with(":443"),
            "canonical relay endpoint serves :443, got {DEFAULT_RELAY_URL}"
        );
    }

    // #285: DIG_NETWORK_GENESIS env override — unset/invalid/zero fall back to the canonical
    // `DIG_MAINNET` genesis; a valid non-zero 64-hex value is used verbatim as the gossip
    // `network_id`.
    #[test]
    fn genesis_challenge_env_override() {
        let default_genesis = dig_constants::DIG_MAINNET.genesis_challenge();

        // Unset → the canonical default genesis.
        assert_eq!(genesis_challenge_from(None), default_genesis);
        // Blank → default.
        assert_eq!(genesis_challenge_from(Some("   ")), default_genesis);

        // Valid 64-hex, non-zero → used verbatim.
        let hex64 = "11".repeat(32);
        assert_eq!(
            genesis_challenge_from(Some(&hex64)),
            chia_protocol::Bytes32::new([0x11u8; 32]),
            "a valid 64-hex genesis must be used as the gossip network_id"
        );
        // Leading/trailing whitespace is trimmed.
        assert_eq!(
            genesis_challenge_from(Some(&format!("  {hex64}  "))),
            chia_protocol::Bytes32::new([0x11u8; 32])
        );

        // All-zero 64-hex → default (the all-zero value is the one `network_id` gossip rejects).
        assert_eq!(
            genesis_challenge_from(Some(&"00".repeat(32))),
            default_genesis
        );
        // Too short → default.
        assert_eq!(genesis_challenge_from(Some("abcd")), default_genesis);
        // Too long → default.
        assert_eq!(
            genesis_challenge_from(Some(&"11".repeat(33))),
            default_genesis
        );
        // Non-hex → default.
        assert_eq!(
            genesis_challenge_from(Some(&"zz".repeat(32))),
            default_genesis
        );
    }

    /// #850 regression: the DEFAULT node's genesis (no `DIG_NETWORK_GENESIS` set) is a REAL,
    /// non-zero value — dig-constants 0.4.0+ pins the Chia mainnet header hash @ height 9,021,277.
    /// `dig-gossip` rejects an ALL-ZERO `network_id` ("network_id must be non-zero"), so this is the
    /// property that lets a stock, unconfigured node bring its gossip pool up: the fallback must
    /// never be the all-zero sentinel. Guards against a regression that re-introduces a zero default.
    #[test]
    fn default_genesis_is_non_zero_so_gossip_config_is_valid() {
        let default_genesis = genesis_challenge_from(None);
        assert_ne!(
            default_genesis,
            chia_protocol::Bytes32::new([0u8; 32]),
            "the default gossip network_id must be non-zero or gossip rejects it at start"
        );
        // The env resolver mirrors the pure core, so a stock node reads the same non-zero value.
        assert_eq!(genesis_challenge_from_env_uncontaminated(), default_genesis);
    }

    /// Read [`genesis_challenge_from_env`] only when `DIG_NETWORK_GENESIS` is unset, so the assertion
    /// reflects the STOCK default rather than a value another test/process left in the environment.
    fn genesis_challenge_from_env_uncontaminated() -> chia_protocol::Bytes32 {
        match std::env::var("DIG_NETWORK_GENESIS") {
            Ok(v) if !v.trim().is_empty() => genesis_challenge_from(None),
            _ => genesis_challenge_from_env(),
        }
    }

    // #1372: the effective network label — the relay introducer/reservation + discovery namespace —
    // must reflect a `DIG_NETWORK_GENESIS` override, while the DEFAULT stays byte-identical
    // `DIG_MAINNET` so mainnet peer discovery never forks.
    #[test]
    fn effective_network_label_invariants() {
        let default_genesis = dig_constants::DIG_MAINNET.genesis_challenge();
        let override_a = chia_protocol::Bytes32::new([0x11u8; 32]);
        let override_b = chia_protocol::Bytes32::new([0x22u8; 32]);

        // (a) No explicit id + the default genesis → BYTE-IDENTICAL `DIG_MAINNET` (hard back-compat).
        assert_eq!(
            effective_network_label(None, default_genesis),
            DEFAULT_NETWORK_ID,
            "the default (no override) MUST stay byte-identical DIG_MAINNET"
        );
        assert_eq!(
            effective_network_label(Some("   "), default_genesis),
            DEFAULT_NETWORK_ID
        );

        // (b) An explicit DIG_NETWORK_ID always wins — even over a non-default genesis override.
        assert_eq!(
            effective_network_label(Some("MY_NET"), default_genesis),
            "MY_NET"
        );
        assert_eq!(
            effective_network_label(Some("MY_NET"), override_a),
            "MY_NET",
            "explicit DIG_NETWORK_ID takes precedence over a genesis override"
        );

        // (c) A non-default genesis (no explicit id) → a derived label DISTINCT from DIG_MAINNET.
        let label_a = effective_network_label(None, override_a);
        assert_ne!(
            label_a, DEFAULT_NETWORK_ID,
            "an overridden network must not report DIG_MAINNET"
        );
        assert!(label_a.starts_with("DIG_"));
        // Deterministic: the same genesis always yields the same label.
        assert_eq!(label_a, effective_network_label(None, override_a));
        // Distinct per genesis: a different genesis yields a different label (true isolation).
        assert_ne!(
            label_a,
            effective_network_label(None, override_b),
            "distinct geneses must land on distinct discovery namespaces"
        );
    }

    #[test]
    fn peer_network_enabled_default_on_off_only_for_opt_out() {
        assert!(is_peer_network_enabled(None), "unset → enabled");
        for off in ["off", "0", "false"] {
            assert!(
                !is_peer_network_enabled(Some(off)),
                "DIG_PEER_NETWORK={off} disables"
            );
        }
        assert!(
            is_peer_network_enabled(Some("on")),
            "any other value → enabled"
        );
    }

    #[test]
    fn list_inventory_lists_stores_then_roots() {
        let cached = vec![
            cap("aa".repeat(32).as_str(), "11".repeat(32).as_str(), 10, 1),
            cap("aa".repeat(32).as_str(), "22".repeat(32).as_str(), 10, 2),
            cap("bb".repeat(32).as_str(), "33".repeat(32).as_str(), 10, 3),
        ];
        // No store_id → list the (deduped, sorted) stores.
        let stores = list_inventory(&cached, None, None);
        let arr = stores["stores"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "two distinct stores");
        assert_eq!(arr[0], json!("aa".repeat(32)));
        assert_eq!(arr[1], json!("bb".repeat(32)));
        // A store_id → list that store's roots.
        let roots = list_inventory(&cached, Some(&"aa".repeat(32)), None);
        assert_eq!(roots["store_id"], json!("aa".repeat(32)));
        let rarr = roots["roots"].as_array().unwrap();
        assert_eq!(rarr.len(), 2, "two roots for store aa");
        // An unknown store → empty roots (not an error).
        let none = list_inventory(&cached, Some(&"ff".repeat(32)), None);
        assert_eq!(none["roots"], json!([]));
    }

    #[test]
    fn list_inventory_honors_limit() {
        let cached = vec![
            cap("aa".repeat(32).as_str(), "11".repeat(32).as_str(), 10, 1),
            cap("bb".repeat(32).as_str(), "22".repeat(32).as_str(), 10, 2),
            cap("cc".repeat(32).as_str(), "33".repeat(32).as_str(), 10, 3),
        ];
        let stores = list_inventory(&cached, None, Some(2));
        assert_eq!(stores["stores"].as_array().unwrap().len(), 2, "capped to 2");
    }

    #[test]
    fn availability_store_granularity_reports_held_roots_newest_first() {
        let store = "aa".repeat(32);
        let cached = vec![
            cap(&store, &"11".repeat(32), 10, 100), // older
            cap(&store, &"22".repeat(32), 10, 300), // newest
            cap(&store, &"33".repeat(32), 10, 200),
        ];
        let a = availability_presence(&cached, &store, None, None);
        assert_eq!(a["available"], true);
        let roots = a["roots"].as_array().unwrap();
        // Newest-first by mtime: 22.. (300), 33.. (200), 11.. (100).
        assert_eq!(roots[0], json!("22".repeat(32)));
        assert_eq!(roots[1], json!("33".repeat(32)));
        assert_eq!(roots[2], json!("11".repeat(32)));
    }

    #[test]
    fn availability_store_granularity_unavailable_when_no_roots() {
        let a = availability_presence(&[], &"aa".repeat(32), None, None);
        assert_eq!(a["available"], false);
        assert_eq!(a["roots"], json!([]));
    }

    #[test]
    fn availability_root_granularity_presence() {
        let store = "aa".repeat(32);
        let root = "11".repeat(32);
        let cached = vec![cap(&store, &root, 10, 1)];
        // Held.
        let held = availability_presence(&cached, &store, Some(&root), None);
        assert_eq!(held["available"], true);
        // Not held (different root).
        let miss = availability_presence(&cached, &store, Some(&"99".repeat(32)), None);
        assert_eq!(miss["available"], false);
    }

    #[test]
    fn classify_request_dispatches_by_shape() {
        // JSON-RPC (method present) wins even if other fields are present.
        assert_eq!(
            classify_request(&json!({"jsonrpc":"2.0","id":1,"method":"dig.getPeers"})),
            PeerRequestKind::JsonRpc
        );
        // RangeRequest: length present, no method.
        assert_eq!(
            classify_request(&json!({"store_id":"aa","length":4096,"offset":0})),
            PeerRequestKind::Range
        );
        // AvailabilityRequest: items present, no method.
        assert_eq!(
            classify_request(&json!({"items":[{"store_id":"aa"}]})),
            PeerRequestKind::Availability
        );
        // Unknown.
        assert_eq!(
            classify_request(&json!({"foo":"bar"})),
            PeerRequestKind::Unknown
        );
    }

    #[tokio::test]
    async fn framed_roundtrip_over_a_duplex() {
        // read_framed/write_framed are the exact wire dig-nat uses; a value written by one is read
        // back identically by the other over an in-memory duplex (no network).
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = json!({"jsonrpc":"2.0","id":7,"method":"dig.getNetworkInfo"});
        write_framed(&mut a, &msg).await.unwrap();
        let got = read_framed(&mut b).await.unwrap().expect("a frame");
        assert_eq!(got, msg);
        // A clean EOF at a frame boundary → None (loop ends quietly).
        drop(a);
        let end = read_framed(&mut b).await.unwrap();
        assert!(end.is_none(), "clean EOF yields None");
    }

    #[tokio::test]
    async fn read_framed_rejects_an_oversized_length_prefix() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // A length prefix claiming 1 MiB (> the 64 KiB control cap) must be refused, not allocated.
        a.write_all(&(1024u32 * 1024).to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_framed(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // -- Persistent CA-signed NodeCert (#908 identity boundary, #1280) ----------------------------

    /// A deterministic 32-byte identity seed derived from a label — no hard-coded crypto literal
    /// (CodeQL flags integer-literal key material in crypto tests).
    fn node_seed(label: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(label.as_bytes()).into()
    }

    #[test]
    fn node_cert_peer_id_is_stable_across_restart() {
        // The node's machine identity must survive a restart: minting into a dir, then loading it
        // back from that SAME dir (a "restart"), yields the IDENTICAL peer_id. This is the property
        // the peer network relies on — a churning id would orphan the node from its reputation.
        let dir = tempfile::tempdir().expect("tempdir");
        let seed = node_seed("restart-stability");

        let first = load_or_generate_node_cert(dir.path(), &seed).expect("mint");
        // The cert + key are now persisted; a second call must LOAD them, not mint afresh.
        let second = load_or_generate_node_cert(dir.path(), &seed).expect("load");

        assert_eq!(
            first.peer_id().to_hex(),
            second.peer_id().to_hex(),
            "a restart (reload from the same dir) preserves the node peer_id"
        );
        assert_eq!(
            first.cert_pem(),
            second.cert_pem(),
            "the reloaded cert is byte-identical to the persisted one"
        );
    }

    #[test]
    fn node_cert_peer_id_matches_spki_derivation() {
        // peer_id MUST equal SHA-256(SPKI DER) — the identity every peer independently recomputes
        // from the leaf cert on the wire (§5.2/§5.3).
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = load_or_generate_node_cert(dir.path(), &node_seed("spki")).expect("mint");
        let recomputed = dig_tls::peer_id_from_tls_spki_der(cert.spki_der());
        assert_eq!(cert.peer_id().to_hex(), recomputed.to_hex());
    }

    #[test]
    fn node_cert_distinct_seeds_yield_distinct_peer_ids() {
        let a = tempfile::tempdir().expect("tempdir a");
        let b = tempfile::tempdir().expect("tempdir b");
        let ca = load_or_generate_node_cert(a.path(), &node_seed("alpha")).expect("mint a");
        let cb = load_or_generate_node_cert(b.path(), &node_seed("beta")).expect("mint b");
        assert_ne!(
            ca.peer_id().to_hex(),
            cb.peer_id().to_hex(),
            "different machine identity seeds → different peer_ids"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_cert_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        load_or_generate_node_cert(dir.path(), &node_seed("perms")).expect("mint");
        // dig-tls persists the leaf key as `node.key` (0600) — the node's long-lived transport
        // secret. Confirm no group/other bits leaked (a readable key = full identity theft).
        let key_path = dir.path().join("node.key");
        let mode = std::fs::metadata(&key_path)
            .expect("key file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "node private key must be owner-only 0600 (got {mode:o})"
        );
    }

    // -- Peer-RPC stream dispatch over a loopback (no network) ------------------------------------

    /// A stub responder that records what it was asked and returns canned answers, so the transport
    /// dispatch is tested in isolation from the node internals.
    struct StubResponder;

    #[async_trait::async_trait]
    impl PeerRpcResponder for StubResponder {
        async fn handle_json_rpc(&self, req: Value) -> Value {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            json!({"jsonrpc":"2.0","id":id,"result":{"echo_method": method}})
        }
        async fn handle_availability(&self, items: Value) -> Value {
            let n = items.as_array().map(|a| a.len()).unwrap_or(0);
            let answers: Vec<Value> = (0..n).map(|_| json!({"available": true})).collect();
            json!({"items": answers})
        }
        async fn stream_range(
            &self,
            _req: Value,
            _conn_key: &str,
            out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
        ) -> std::io::Result<()> {
            // One terminal frame with the stub bytes.
            let frame = json!({
                "offset": 0, "length": 3, "bytes": "AQID", "complete": true,
                "total_length": 3, "chunk_lens": [3], "chunk_index": 0,
            });
            write_framed(out, &frame).await
        }
    }

    #[tokio::test]
    async fn serve_one_stream_answers_a_json_rpc_request() {
        let (mut client, server) = tokio::io::duplex(8192);
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(StubResponder);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        let req = json!({"jsonrpc":"2.0","id":42,"method":"dig.getNetworkInfo"});
        write_framed(&mut client, &req).await.unwrap();
        let resp = read_framed(&mut client).await.unwrap().expect("a response");
        assert_eq!(resp["id"], json!(42));
        assert_eq!(resp["result"]["echo_method"], json!("dig.getNetworkInfo"));
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_one_stream_answers_an_availability_batch() {
        let (mut client, server) = tokio::io::duplex(8192);
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(StubResponder);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        // A bare AvailabilityRequest (dig-nat's typed client wire): { items: [...] }.
        let req = json!({"items":[{"store_id":"aa"},{"store_id":"bb","root":"11"}]});
        write_framed(&mut client, &req).await.unwrap();
        let resp = read_framed(&mut client).await.unwrap().expect("a response");
        assert_eq!(resp["items"].as_array().unwrap().len(), 2);
        assert_eq!(resp["items"][0]["available"], true);
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_one_stream_streams_a_range_frame() {
        let (mut client, server) = tokio::io::duplex(8192);
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(StubResponder);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        // A bare RangeRequest (dig-nat's typed client wire): has `length`, no `method`.
        let req = json!({"store_id":"aa","retrieval_key":"cc","length":4096,"offset":0});
        write_framed(&mut client, &req).await.unwrap();
        let frame = read_framed(&mut client).await.unwrap().expect("a frame");
        assert_eq!(frame["complete"], true);
        assert_eq!(frame["chunk_lens"], json!([3]));
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn serve_one_stream_rejects_an_unknown_frame() {
        let (mut client, server) = tokio::io::duplex(8192);
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(StubResponder);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        write_framed(&mut client, &json!({"nonsense": true}))
            .await
            .unwrap();
        let resp = read_framed(&mut client)
            .await
            .unwrap()
            .expect("an error response");
        assert_eq!(resp["error"]["code"], json!(-32600));
        srv.await.unwrap().unwrap();
    }

    // -- Concurrency cap: spawn_with_permit (audit #179 HIGH — unbounded task spawning) -----------

    #[tokio::test]
    async fn spawn_with_permit_sheds_work_past_the_capacity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Semaphore;

        // Capacity 2: the first two spawns take permits and PARK (holding them); the third is shed.
        let sem = Arc::new(Semaphore::new(2));
        let running = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());

        let mk = |running: Arc<AtomicUsize>, gate: Arc<tokio::sync::Notify>| async move {
            running.fetch_add(1, Ordering::SeqCst);
            gate.notified().await; // hold the permit until released
            running.fetch_sub(1, Ordering::SeqCst);
        };

        assert!(spawn_with_permit(&sem, mk(running.clone(), gate.clone())));
        assert!(spawn_with_permit(&sem, mk(running.clone(), gate.clone())));
        // Let the two tasks start + park so both permits are held.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            sem.available_permits(),
            0,
            "both permits held by parked tasks"
        );

        // Third spawn: no permit free → shed (not spawned), returns false.
        let shed = spawn_with_permit(&sem, mk(running.clone(), gate.clone()));
        assert!(!shed, "past capacity → work is shed, not spawned");
        assert_eq!(running.load(Ordering::SeqCst), 2, "only 2 tasks ever ran");

        // Release the parked tasks; permits return so new work is admitted again.
        gate.notify_waiters();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            sem.available_permits(),
            2,
            "permits released on task completion"
        );
        assert!(
            spawn_with_permit(&sem, async {}),
            "capacity freed → admits again"
        );
    }

    // -- Peer-surface method allowlist (SPEC §2.3/§7.4; audit #179 CRITICAL) -----------------------

    #[test]
    fn peer_surface_allows_only_the_intended_l7_read_and_announce_methods() {
        // The audit-CONFIRMED contract: the mTLS peer surface exposes ONLY the L7
        // read/discovery/announce subset. An anonymous peer (the verifier accepts any
        // self-signed cert) MUST NOT reach management/mutation methods.
        for m in [
            "dig.getContent",
            "dig.getAvailability",
            "dig.listInventory",
            "dig.fetchRange",
            "dig.getNetworkInfo",
            "dig.getPeers",
            "dig.announce",
            "dig.getAnchoredRoot",
            "dig.getCollection",
            "dig.listCollectionItems",
        ] {
            assert!(
                is_peer_reachable_method(m),
                "{m} is an intended L7 read/announce method and MUST be peer-reachable"
            );
        }
    }

    #[test]
    fn peer_surface_rejects_management_and_mutation_methods() {
        // Every cache.* / control.* mutation + dig.stage is loopback/in-process ONLY.
        for m in [
            "cache.clear",
            "cache.setCapBytes",
            "cache.removeCached",
            "cache.fetchAndCache",
            "cache.listCached",
            "cache.getConfig",
            "control.peerStatus",
            "dig.stage",
            "totally.unknown",
            "",
        ] {
            assert!(
                !is_peer_reachable_method(m),
                "{m} is management/mutation/unknown and MUST NOT be reachable over the peer surface"
            );
        }
    }

    /// **Proves:** delegating the peer allowlist to `dig_rpc_protocol` (#1075) preserves
    /// the EXACT set the node hand-rolled before — the ten L7 read/discovery/announce
    /// methods, no more, no fewer. This is the security-critical regression guard for the
    /// #179 auth-bypass surface: any method that gains or loses peer-reachability across the
    /// crate adoption fails here.
    /// **Catches:** a crate drift that adds a management method to the allowlist, or drops a
    /// read method the peer download path relies on.
    #[test]
    fn peer_allowlist_is_byte_identical_to_the_pre_adoption_set() {
        // The canonical set the hand-rolled `is_peer_reachable_method` matched verbatim.
        let mut expected = [
            "dig.getContent",
            "dig.getNetworkInfo",
            "dig.getPeers",
            "dig.announce",
            "dig.getAvailability",
            "dig.listInventory",
            "dig.fetchRange",
            "dig.getAnchoredRoot",
            "dig.getCollection",
            "dig.listCollectionItems",
        ];
        expected.sort_unstable();

        // The set the node now exposes, sourced entirely from the crate.
        let mut got = dig_rpc_protocol::Method::peer_reachable_names();
        got.sort_unstable();

        assert_eq!(
            got, expected,
            "the dig-rpc-protocol peer allowlist diverged from the node's pre-adoption set"
        );
        // And the str-adapting wrapper agrees for every name in the set.
        for m in expected {
            assert!(is_peer_reachable_method(m), "{m} must be peer-reachable");
        }
    }

    /// A→B peer RPC over REAL mTLS against the REAL node dispatch (#929): node B serves its
    /// `NodeResponder` on an mTLS listener; node A dials it (peer_id-pinned), opens a stream, and
    /// calls `dig.getNetworkInfo` — getting B's real dispatch result. The same channel REJECTS a
    /// control-plane method (`control.peerStatus`) with -32601, proving the peer surface exposes only
    /// the read/discovery allowlist even against a real node. This is the node half the WU7 EC2 proof
    /// relies on: a node can call another node's RPC over the existing mTLS peer surface.
    #[tokio::test]
    async fn peer_to_peer_rpc_round_trip_against_the_real_node_over_mtls() {
        use std::time::Duration;
        install_crypto_provider();

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let server_dir = tempfile::tempdir().expect("server cert dir");
        let server_identity =
            load_or_generate_node_cert(server_dir.path(), &node_seed("p2p-server"))
                .expect("server");
        let server_peer_id = server_identity.peer_id();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(NodeResponder::without_pool(node));
        let server = tokio::spawn(serve_peer_rpc_listener(
            listener,
            server_identity,
            responder,
        ));

        let client_dir = tempfile::tempdir().expect("client cert dir");
        let client_identity =
            load_or_generate_node_cert(client_dir.path(), &node_seed("p2p-client"))
                .expect("client");
        let target = dig_nat::PeerTarget::with_addr(server_peer_id, addr, "DIG_MAINNET");
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(5))
            .build();
        let mut conn = dig_nat::connect(&target, &client_identity, &config)
            .await
            .expect("A dials B over mTLS");

        // A read method reaches B's real dispatch and returns a result.
        {
            let mut stream = conn.session.open_stream().await.expect("open stream");
            write_framed(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":1,"method":"dig.getNetworkInfo"}),
            )
            .await
            .unwrap();
            let resp = read_framed(&mut stream).await.unwrap().expect("a frame");
            assert!(
                resp.get("result").is_some(),
                "real node served the read: {resp}"
            );
        }
        // A control-plane method is rejected -32601 over the peer channel.
        {
            let mut stream = conn.session.open_stream().await.expect("open stream");
            write_framed(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":2,"method":"control.peerStatus"}),
            )
            .await
            .unwrap();
            let resp = read_framed(&mut stream).await.unwrap().expect("a frame");
            assert_eq!(
                resp["error"]["code"],
                json!(-32601),
                "control method must be rejected: {resp}"
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn node_responder_returns_method_not_found_for_management_methods() {
        // End-to-end over the responder: a peer JSON-RPC frame naming a management/mutation
        // method is answered with -32601 (method not found) WITHOUT ever reaching the
        // node's `handle_rpc` dispatch (which would run the mutation). getPeers still works.
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let responder = NodeResponder::without_pool(node);
        for m in [
            "cache.clear",
            "cache.setCapBytes",
            "cache.removeCached",
            "cache.fetchAndCache",
            "dig.stage",
        ] {
            let req = json!({"jsonrpc":"2.0","id":1,"method":m,"params":{}});
            let resp = responder.handle_json_rpc(req).await;
            assert_eq!(
                resp["error"]["code"],
                json!(-32601),
                "{m} must be rejected -32601 on the peer surface"
            );
            assert!(
                resp.get("result").is_none(),
                "{m} must not return a result on the peer surface"
            );
        }
        // A legitimate peer read method is still dispatched (no -32601).
        let ok = responder
            .handle_json_rpc(json!({"jsonrpc":"2.0","id":1,"method":"dig.getNetworkInfo"}))
            .await;
        assert!(
            ok.get("result").is_some(),
            "dig.getNetworkInfo must still be served on the peer surface"
        );
        // getPeers is answered from the (empty) pool view, not -32601.
        let peers = responder
            .handle_json_rpc(json!({"jsonrpc":"2.0","id":1,"method":"dig.getPeers"}))
            .await;
        assert!(peers["result"]["peers"].is_array());
    }

    // -- OUTGOING-BANDWIDTH THROTTLE on the peer range-stream (dig_ecosystem #30) --------------------
    //
    // `stream_range` is the busiest node-to-node egress path (multi-source downloaders fan ranges
    // across it), so it gets the SAME bandwidth-redirect check as the `dig.getContent`/`dig.fetchRange`
    // JSON-RPC surface (see `lib.rs`'s `over_cap` test group). This proves the WIRING in `stream_range`
    // itself: a node that HOLDS the range but is over its configured outgoing-bandwidth cap answers a
    // redirect error frame (the same `-32008` shape) instead of streaming the frame, when a holder is
    // known.
    #[tokio::test]
    async fn stream_range_over_cap_with_a_provider_redirects_instead_of_streaming() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let store = digstore_core::Bytes32([0x31; 32]);
        let root = digstore_core::Bytes32([0x32; 32]);
        let rk = [0xcdu8; 32];
        // The node genuinely HOLDS this resource — 5000 bytes, well past a 10-byte cap. Seeded
        // directly into the in-memory content cache (no disk/wasmtime — only the throttle+redirect
        // decision is under test, mirroring lib.rs's `seed_local_resource`).
        node.content_cache.lock().unwrap().insert(
            (store.to_hex(), root.to_hex(), rk),
            Arc::new(digstore_core::wire::ContentResponse {
                ciphertext: vec![0xABu8; 5000],
                merkle_proof: digstore_core::merkle::MerkleProof {
                    leaf: digstore_core::Bytes32([0u8; 32]),
                    path: vec![],
                    root: digstore_core::Bytes32([0u8; 32]),
                },
                roothash: root,
                chunk_lens: vec![],
            }),
        );
        let mut node = node;
        Arc::get_mut(&mut node)
            .expect("sole owner right after construction")
            .outgoing_throttle = crate::bandwidth::OutgoingThrottle::new(10);
        // A holder for this EXACT content is known via the DHT.
        let cid = dig_dht::ContentId::resource(store.0, root.0, rk);
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(vec![
            dig_download::testkit::mock_provider(6, &cid),
        ]));
        let transport = Arc::new(dig_download::testkit::MockRangeTransport::new(
            dig_download::testkit::MockContent::even(10, 1),
        ));
        let pc = crate::download::NodeContent::new(
            locator,
            transport,
            crate::download::MissMode::Redirect,
            None,
            td.path(),
        );
        node.set_p2p_content(pc);

        let responder: Arc<dyn PeerRpcResponder> = Arc::new(NodeResponder::without_pool(node));
        let (mut client, server) = tokio::io::duplex(8192);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        // A bare RangeRequest (no `method`) for the held resource.
        let req = json!({
            "store_id": store.to_hex(), "root": root.to_hex(), "retrieval_key": hex::encode(rk),
            "length": 4096, "offset": 0,
        });
        write_framed(&mut client, &req).await.unwrap();
        let frame = read_framed(&mut client).await.unwrap().expect("a frame");
        assert_eq!(
            frame["error"]["code"],
            json!(crate::download::CONTENT_REDIRECT),
            "held locally but over the outgoing-bandwidth cap must redirect, not stream: {frame}"
        );
        assert_eq!(
            frame["error"]["data"]["redirect"]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(6))
        );
        srv.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stream_range_over_cap_with_no_provider_still_streams_the_frame() {
        // The graceful fallback on the peer surface too: no known alternate holder → stream the frame
        // anyway rather than drop the request.
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let store = digstore_core::Bytes32([0x41; 32]);
        let root = digstore_core::Bytes32([0x42; 32]);
        let rk = [0xefu8; 32];
        node.content_cache.lock().unwrap().insert(
            (store.to_hex(), root.to_hex(), rk),
            Arc::new(digstore_core::wire::ContentResponse {
                ciphertext: vec![0xCDu8; 5000],
                merkle_proof: digstore_core::merkle::MerkleProof {
                    leaf: digstore_core::Bytes32([0u8; 32]),
                    path: vec![],
                    root: digstore_core::Bytes32([0u8; 32]),
                },
                roothash: root,
                chunk_lens: vec![],
            }),
        );
        let mut node = node;
        Arc::get_mut(&mut node)
            .expect("sole owner right after construction")
            .outgoing_throttle = crate::bandwidth::OutgoingThrottle::new(10);
        // A P2P engine is attached but the DHT knows of NO holder for this content.
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(vec![]));
        let transport = Arc::new(dig_download::testkit::MockRangeTransport::new(
            dig_download::testkit::MockContent::even(10, 1),
        ));
        let pc = crate::download::NodeContent::new(
            locator,
            transport,
            crate::download::MissMode::Redirect,
            None,
            td.path(),
        );
        node.set_p2p_content(pc);

        let responder: Arc<dyn PeerRpcResponder> = Arc::new(NodeResponder::without_pool(node));
        let (mut client, server) = tokio::io::duplex(8192);
        let srv = tokio::spawn(serve_one_stream(server, responder));

        // Request length comfortably covers the whole 5000-byte resource in one frame.
        let req = json!({
            "store_id": store.to_hex(), "root": root.to_hex(), "retrieval_key": hex::encode(rk),
            "length": 8192, "offset": 0,
        });
        write_framed(&mut client, &req).await.unwrap();
        let frame = read_framed(&mut client).await.unwrap().expect("a frame");
        assert!(
            frame.get("error").is_none(),
            "no known alternate holder must NOT redirect, must stream: {frame}"
        );
        assert_eq!(frame["complete"], json!(true));
        srv.await.unwrap().unwrap();
    }

    // -- serve-side FCFS outbound rate limiting (#1436) ------------------------------------------------
    //
    // These exercise `stream_fetched_range`, the free function that writes framed serve bytes on the
    // fetch-through path and acquires the FCFS budget before EACH frame — the exact same
    // `limiter.acquire(conn_key, this_len)` wiring the local-hold `NodeResponder::stream_range` uses.
    // A tiny `length` forces many small frames over a small resource so pacing is observable, without
    // needing a >3 MiB resource. tokio's paused clock advances virtual time on the limiter's sleeps.

    /// A small fetched resource whose `range_frame` windows tile it into `frame_len`-byte frames.
    fn tiny_fetched(total: usize) -> crate::download::FetchedResource {
        crate::download::FetchedResource {
            bytes: vec![7u8; total],
            total_length: total as u64,
            chunk_lens: vec![total as u64],
            root: None,
            inclusion_proof: None,
        }
    }

    /// With a tight per-connection cap the serve path PACES: after the initial one-second burst, each
    /// further frame waits for a token refill, so streaming more than one budget's worth takes time.
    #[tokio::test(start_paused = true)]
    async fn stream_range_paces_each_frame_under_a_tight_cap() {
        // Per-conn cap 100 B/s (global unlimited); 300 bytes in 100-byte frames = 3 frames.
        let limiter = dig_download::FcfsRateLimiter::new(0, 100);
        let f = tiny_fetched(300);
        let mut out = tokio::io::sink();
        let start = tokio::time::Instant::now();
        stream_fetched_range(&mut out, &f, 0, 100, &limiter, "peerA")
            .await
            .unwrap();
        // First 100 B instant (burst); the next two 100-B frames each wait ~1s for a refill.
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(1500),
            "paced serve should wait for refills, waited {:?}",
            start.elapsed()
        );
    }

    /// An unlimited (0/0) limiter never paces — the default node serves at full speed.
    #[tokio::test(start_paused = true)]
    async fn stream_range_unlimited_cap_never_paces() {
        let limiter = dig_download::FcfsRateLimiter::new(0, 0);
        let f = tiny_fetched(1_000_000);
        let mut out = tokio::io::sink();
        let start = tokio::time::Instant::now();
        stream_fetched_range(&mut out, &f, 0, 1000, &limiter, "peerA")
            .await
            .unwrap();
        assert_eq!(
            start.elapsed(),
            std::time::Duration::ZERO,
            "no cap → no wait"
        );
    }

    /// Two peers have independent per-connection budgets: exhausting peer A's burst does not slow a
    /// first serve to peer B (keyed by the distinct `conn_key`).
    #[tokio::test(start_paused = true)]
    async fn stream_range_distinct_peers_have_independent_budgets() {
        let limiter = dig_download::FcfsRateLimiter::new(0, 1000);
        let f = tiny_fetched(1000);
        let mut out = tokio::io::sink();
        // Exhaust peer A's burst (one 1000-byte frame).
        stream_fetched_range(&mut out, &f, 0, 1000, &limiter, "peerA")
            .await
            .unwrap();
        // Peer B has its own fresh bucket → its first serve is instant.
        let start = tokio::time::Instant::now();
        stream_fetched_range(&mut out, &f, 0, 1000, &limiter, "peerB")
            .await
            .unwrap();
        assert_eq!(
            start.elapsed(),
            std::time::Duration::ZERO,
            "peer B's budget is independent of peer A's"
        );
    }
}
