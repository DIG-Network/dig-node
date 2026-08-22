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

use crate::seams::content::range_frame;
use crate::seams::dig_peer::serve_log;
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

/// The fixed port offset from the gossip listener down to the DHT/peer-RPC listener
/// (`DEFAULT_GOSSIP_PORT - DEFAULT_P2P_PORT`, i.e. 1). See [`dht_addr_from_gossip_addr`].
pub const GOSSIP_TO_DHT_PORT_OFFSET: u16 = DEFAULT_GOSSIP_PORT - DEFAULT_P2P_PORT;

/// Map a peer's GOSSIP address to its DHT/peer-RPC address (#1575 GAP 2).
///
/// `connected_pool_peers()` and `PoolEvent`s report a peer's GOSSIP endpoint (its `9445`), because the
/// pool link is a gossip connection. But the DHT routing table must hold the peer's DHT/peer-RPC
/// endpoint (its `9444`) — dialing the gossip port for a DHT RPC gets the gossip protocol on the wire
/// and fails with `received corrupt message InvalidContentType`, so every DHT dial silently dies and
/// `find_providers` finds nobody. Every node co-locates the two listeners with the gossip port exactly
/// [`GOSSIP_TO_DHT_PORT_OFFSET`] above the DHT port, so we recover the DHT port by shifting down by
/// that fixed offset. `saturating_sub` guards a pathological addr below the offset (never a real
/// gossip port, but avoids underflow).
pub fn dht_addr_from_gossip_addr(gossip: std::net::SocketAddr) -> std::net::SocketAddr {
    let mut dht_addr = gossip;
    dht_addr.set_port(gossip.port().saturating_sub(GOSSIP_TO_DHT_PORT_OFFSET));
    dht_addr
}

/// A pool-reported gossip address turned into the DHT contact to store for that peer, or `None` when
/// the result would not be a usable contact.
///
/// Composes the two things that must BOTH hold before an address enters the DHT routing table:
/// [`dht_addr_from_gossip_addr`]'s port shift, and [`crate::net::is_usable_contact`]'s "is this a
/// destination at all" check (dig_ecosystem#1784 — dig-nat reports `[::]:0` as the remote of an
/// accepted relayed circuit with no configured relay endpoint, and routing would otherwise store the
/// wildcard as that peer's contact, so every lookup seeded from it dead-ends).
///
/// The check is applied to the MAPPED address, not the raw one: the port shift is what determines the
/// port actually stored, so a gossip port at or below the offset maps to port 0 — unusable — even
/// though the input looked fine.
pub(crate) fn dht_contact_from_pool_addr(
    gossip: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    let dht = dht_addr_from_gossip_addr(gossip);
    crate::net::is_usable_contact(&dht).then_some(dht)
}

/// Per-window ciphertext cap for a `dig.fetchRange` frame (bytes) — the node window (3 MiB), the same
/// cap the HTTP read path (`WINDOW`) uses.
///
/// The framing ceiling this constant used to fight (dig_ecosystem#1640) is RESOLVED at `dig-nat`,
/// which is where it belonged: 0.13 made `RangeFrame::encode` FALLIBLE and payload-capped at the
/// sender and added the paged-prologue API (so #1577's per-frame verification metadata — `root`, the
/// `chunk_lens` array, `total_length`, the base64 `inclusion_proof` — is split across pages instead of
/// having to fit one frame), and 0.14 added the receiver-side `ChunkLensAssembler` validation. Both
/// fail CLOSED, so an over-ceiling frame is now a clean error at the boundary rather than a silent
/// decode failure mid-read.
///
/// This value therefore remains the node's per-frame SPLIT size, and stays the single source of truth
/// for it: the streaming loops that consume it never need to change if it moves.
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
    /// DIG peers this node has LEARNED OF — the size of dig-gossip's address manager, which holds
    /// every peer discovered by any route (relay introduction, PEX, `dig.getPeers`) whether or not
    /// a connection to it succeeded. A SUPERSET of `connected_peers`, and the number that separates
    /// "connected to nobody" from "nobody to connect to" (dig_ecosystem#2570).
    ///
    /// Held beside [`known_peers_sampled`](Self::known_peers_sampled) rather than as a sentinel
    /// value, because an unsampled count is UNKNOWN and every `u64` is a plausible count.
    known_peers: AtomicU64,
    /// Whether [`set_known_peers`](Self::set_known_peers) has ever run. Until it has, the node has
    /// not consulted its address book and `known_peers` reports `null` rather than a zero it never
    /// measured.
    known_peers_sampled: AtomicBool,
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

    /// Record the size of the discovered-peer address book (called from the maintenance loop
    /// alongside [`set_pool`](Self::set_pool), from the SAME `GossipStats` snapshot).
    ///
    /// Kept a separate setter from `set_pool` deliberately: this is a different question about a
    /// different structure, and folding it into the pool triple would invite the very aliasing the
    /// field exists to expose. The first call is also what turns the reported count from `null`
    /// (never looked) into a measurement.
    pub fn set_known_peers(&self, known_peers: u64) {
        self.known_peers.store(known_peers, Ordering::Relaxed);
        self.known_peers_sampled.store(true, Ordering::Relaxed);
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
            // `null` until the pool loop has sampled the address book: a count nobody took is not
            // a count of none (#2570).
            "known_peers": self
                .known_peers_sampled
                .load(Ordering::Relaxed)
                .then(|| self.known_peers.load(Ordering::Relaxed)),
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
// the capsules cached on disk (`<cache>/modules/<store>/<root>.dig`). `cache_list_cached()` is the
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
/// - `store_id` only → *has_store* (`roots` = the roots held, in a CANONICAL root-hex order).
/// - `store_id` + `root` → *has_root* (does this node hold that capsule; `total_length`/`chunk_count`
///   are filled by [`Node`] from the served module — this pure helper reports presence only).
/// - `store_id` + `root` + `retrieval_key` → *has_resource* (presence at capsule granularity; the
///   resource-level totals come from serving the module).
///
/// This pure form answers presence + store-granularity `roots`; the resource/root totals
/// (`total_length`/`chunk_count`/`complete`) are enriched by the node from the actual module (see
/// [`crate::Node::availability_answer`]).
///
/// # The answer is derived from the SERVABLE source, never from the inventory snapshot (#1592)
///
/// At ROOT/RESOURCE granularity the caller passes `capsule_servable` — whether the exact capsule
/// module exists on disk ([`crate::module_exists`], the same file [`serve_local_blocking`] reads to
/// serve a range). It is NOT re-derived from `cached`, because an inventory snapshot can lag the
/// servable state in BOTH directions and this answer is a read-killing gate: dig-download's
/// `locate_and_confirm` drops every provider whose answer is not `available` BEFORE any `fetchRange`,
/// so a capsule that landed after the snapshot (a gap-fill / §21 sync / fetch-through / pin write
/// concurrent with the peer-facing walk) would false-negative and drop a holder that would have
/// served the bytes — and a snapshot that lags an eviction would claim availability the node cannot
/// serve. Deriving the answer from the servable source makes both drifts impossible by construction.
///
/// `cached` remains the source for the STORE-granularity `roots` list (an enumeration, which a
/// single-path existence check cannot answer).
///
/// [`serve_local_blocking`]: crate::Node::availability_answer
pub fn availability_presence(
    cached: &[CachedCapsule],
    store_id: &str,
    root: Option<&str>,
    _retrieval_key: Option<&str>,
    capsule_servable: bool,
) -> Value {
    // Roots held for the store, in a CANONICAL order (by root hex, ascending) — NEVER by an
    // access-time field (#2022). The peer surface is permissionless (the mTLS verifier accepts any
    // self-signed leaf), so ANY ordering derived from `last_used_unix_ms` would leak this operator's
    // read behaviour to an arbitrary peer: it would disclose a total order over the operator's
    // interests plus approximate read times, and it would INVERT the tier-0 cover-caching privacy
    // design (never-read cover content sorts last, so genuinely-read entries surface first — adding
    // cover would make real reads MORE conspicuous). A canonical order carries no such signal: the
    // response is a set, presented deterministically.
    let mut roots_held: Vec<String> = cached
        .iter()
        .filter(|c| c.store_id == store_id)
        .map(|c| c.root.clone())
        .collect();
    roots_held.sort_unstable();

    match root {
        None => {
            // STORE granularity: available iff any root is held; report the held roots canonically.
            json!({ "available": !roots_held.is_empty(), "roots": roots_held })
        }
        Some(_want_root) => {
            // ROOT / RESOURCE granularity: available iff this exact capsule is SERVABLE right now —
            // the caller's on-disk check, not a snapshot lookup (see the note above, #1592).
            json!({ "available": capsule_servable })
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
    /// A `dig.fetchModuleRange` request — a JSON-RPC request whose response is a FRAME STREAM rather
    /// than one envelope, so it is classified ahead of the generic JSON-RPC case by its method name
    /// (#1576). Checked first because it is a strict subset of the JSON-RPC shape.
    ModuleRange,
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
    match v.get("method").and_then(Value::as_str) {
        // The one JSON-RPC method whose response is a frame stream (#1576) — checked before the generic
        // JSON-RPC case, which it is a subset of.
        Some(m) if m == dig_rpc_protocol::Method::FetchModuleRange.name() => {
            return PeerRequestKind::ModuleRange
        }
        Some(_) => return PeerRequestKind::JsonRpc,
        None => {}
    }
    if v.get("length").is_some() {
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

/// The `(cert_path, key_path)` the dig-gossip pool listener loads its TLS material from — the node's
/// OWN persisted [`NodeCert`](dig_tls::NodeCert) (`node.crt`/`node.key` under [`node_cert_dir`], the
/// files [`load_or_generate_node_cert`] writes), NOT a gossip-minted throwaway cert.
///
/// Sharing these files is what makes the pool's inbound listener present the node's ADVERTISED
/// identity, so `peer_id = SHA-256(SPKI DER)` is identical across every listener the node runs (the
/// peer-RPC server, the DHT dials, and the gossip pool). Without this the pool would present a cert
/// hashing to a different peer_id and every dial to this node fails closed with `peer_id mismatch`
/// (#1532). dig-gossip only READS these files (`dig_peer_protocol::load_ssl_cert`), so pointing at the
/// canonical identity files can never clobber them.
///
/// [`node_cert_dir`]: crate::seams::key_mgmt::key_manager::KeyManager::node_cert_dir
fn gossip_identity_paths(node_cert_dir: &std::path::Path) -> (String, String) {
    // `node.crt` / `node.key` are the stable, §5.1-additive file names dig-tls persists a NodeCert
    // under (also asserted by the node-cert permission test + documented on `node_cert_dir`).
    (
        node_cert_dir.join("node.crt").display().to_string(),
        node_cert_dir.join("node.key").display().to_string(),
    )
}

// -- Serving inbound peer streams over an established mTLS connection ---------------------------------

/// A thing that answers peer requests — implemented by [`crate::Node`]. The transport layer
/// ([`serve_peer_session`]) reads framed requests off each inbound stream and calls back into this to
/// produce the answer, so the transport is decoupled from the node internals (and unit-testable with a
/// stub responder over an in-memory duplex).
#[async_trait::async_trait]
pub trait PeerRpcResponder: Send + Sync {
    /// Answer a JSON-RPC 2.0 request (`dig.getPeers` / `dig.getNetworkInfo` / `dig.announce` /
    /// `dig.getAvailability` / `dig.listInventory`, etc.). Returns the JSON-RPC response value.
    ///
    /// `conn_key` is the authenticated caller's mTLS `peer_id` (64-hex; empty for a caller-less/test
    /// session) — threaded so the miss → DHT-lookup path's per-requestor rate limiter
    /// (dig_ecosystem#2007) keys a `dig.getContent`/`dig.fetchRange` JSON miss by the ASKING peer,
    /// not one shared peer bucket every peer could exhaust for the others.
    async fn handle_json_rpc(&self, req: Value, conn_key: &str) -> Value;

    /// Answer a `dig.getAvailability` batch (the typed dig-nat control call). `items` is the raw
    /// AvailabilityItem array; returns the `{ "items": [AvailabilityAnswer, …] }` response value.
    ///
    /// `conn_key` is the authenticated caller's mTLS `peer_id` (64-hex; empty for a caller-less/test
    /// session) — threaded so the not-held → DHT `find_providers` enrichment on this path is bounded
    /// by the SAME per-requestor miss-lookup budget as the single-item legs (dig_ecosystem#2007). A
    /// batch is the LARGEST amplification vector (up to `MAX_AVAILABILITY_ITEMS` lookups per request),
    /// so it must key by the ASKING peer, never one shared peer bucket every peer could exhaust.
    async fn handle_availability(&self, items: Value, conn_key: &str) -> Value;

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

    /// Stream a `dig.fetchModuleRange` response by writing framed `dig_nat::RangeFrame`-shaped frames
    /// for the requested window of a locally-held whole `.dig` module (#1576, the reshare leg).
    ///
    /// `params` is the request's `params` object (`store_id` / `root` / `offset` / `length`). A module
    /// this node does not hold answers with ONE error frame, so the caller distinguishes "not held" from
    /// a dropped stream instead of waiting for bytes that will never come.
    ///
    /// Defaults to "not held": a responder with no cache (the FFI path, test stubs) needs no override,
    /// and fail-closed is the right default for a serve — claiming to hold a module and then serving
    /// nothing is worse than declining.
    async fn stream_module_range(
        &self,
        params: Value,
        conn_key: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        let _ = (params, conn_key);
        write_framed(
            out,
            &crate::seams::dig_peer::module_serve::module_unavailable_frame(
                crate::download::RESOURCE_UNAVAILABLE,
            ),
        )
        .await
    }

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

/// Announces this node's inventory to the DHT after a capsule warm caches one — the step that makes a
/// freshly-held capsule DISCOVERABLE (#1576 + #1586).
///
/// Reuses `refresh_inventory`, the SAME reconcile the gap-fill / explicit-cache paths use, rather than
/// announcing the one new capsule directly: one announce path means the reshare leg can never advertise a
/// content id shape the rest of the node does not (and a withdrawal it should have made is not skipped).
struct DhtInventoryAnnouncer {
    node: Arc<crate::Node>,
    dht: Arc<crate::dht::DhtHandle>,
    /// The real-time opcode-222 flood, when this node can sign one (#1429).
    holdings: Option<HoldingsFlood>,
}

#[async_trait::async_trait]
impl crate::seams::dig_peer::AnnounceHolder for DhtInventoryAnnouncer {
    async fn announce_inventory(&self) {
        let delta = reconcile_and_flood(&self.node, &self.dht, self.holdings.as_ref()).await;
        tracing::info!(
            announced = delta.gained.len(),
            retracted = delta.lost.len(),
            "capsule warm: announced this node as a holder of the newly cached capsule"
        );
    }
}

/// The node's cache list, as the holdings layer's peer-presence announcer reads it (#1734).
struct NodeHoldingsInventory(Arc<crate::Node>);

#[async_trait::async_trait]
impl crate::seams::dig_peer::holdings::HoldingsInventory for NodeHoldingsInventory {
    async fn current(&self) -> Vec<crate::CachedCapsule> {
        self.0.cache_list_cached().await
    }
}

/// The signer plus the pool it floods to — everything needed to emit an opcode-222 announcement.
#[derive(Clone)]
struct HoldingsFlood {
    broadcaster: Arc<crate::seams::dig_peer::holdings::HoldingsBroadcaster>,
    pool: dig_gossip::GossipHandle,
}

/// The node's ONE reaction to an inventory change: reconcile the durable DHT provider records, then
/// flood the matching real-time opcode-222 announcement for exactly the ids that changed.
///
/// Both change hooks (the #1576 reshare warm and the generic inventory refresher) route through here,
/// so the flood is derived from the SAME delta that moved the records — a capsule can never be
/// announced as gained while its provider record says otherwise, and a retract can never be skipped.
async fn reconcile_and_flood(
    node: &Arc<crate::Node>,
    dht: &Arc<crate::dht::DhtHandle>,
    holdings: Option<&HoldingsFlood>,
) -> crate::dht::InventoryDelta {
    let cached = node.cache_list_cached().await;
    // Reading the inventory is this shell's job; the reconcile-plus-flood composition itself lives in
    // `holdings` so it can be tested against a real DhtService without a `Node`.
    crate::seams::dig_peer::holdings::reconcile_and_announce(
        dht,
        &cached,
        holdings.map(|f| {
            (
                f.broadcaster.as_ref(),
                &f.pool as &dyn crate::seams::dig_peer::holdings::AnnounceTransport,
            )
        }),
        crate::seams::dig_peer::holdings::now_unix_secs(),
    )
    .await
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
        PeerRequestKind::ModuleRange => {
            // Routed by METHOD NAME, not by request shape: this request's RESPONSE is a frame stream
            // rather than one envelope, and its shape (store_id/root/offset/length) cannot express that.
            // dig-peer's SPEC §3.5 records the same contract on the client side, so the two cannot drift.
            let conn_key = caller
                .as_ref()
                .map(|c| c.peer_id.clone())
                .unwrap_or_default();
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            responder
                .stream_module_range(params, &conn_key, &mut stream)
                .await
        }
        PeerRequestKind::JsonRpc => {
            // The authenticated caller peer_id keys the miss-path per-requestor rate limiter
            // (dig_ecosystem#2007); empty on a caller-less/test session.
            let conn_key = caller
                .as_ref()
                .map(|c| c.peer_id.clone())
                .unwrap_or_default();
            let resp = responder.handle_json_rpc(req, &conn_key).await;
            write_framed(&mut stream, &resp).await
        }
        PeerRequestKind::Availability => {
            // The authenticated caller peer_id keys the not-held → DHT `find_providers` enrichment's
            // per-requestor miss-lookup budget (dig_ecosystem#2007); empty on a caller-less/test session.
            let conn_key = caller
                .as_ref()
                .map(|c| c.peer_id.clone())
                .unwrap_or_default();
            let items = req.get("items").cloned().unwrap_or_else(|| json!([]));
            let resp = responder.handle_availability(items, &conn_key).await;
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
    // `dig.getProviderSnapshot` is a dig-node-LOCAL peer method (the anti-Sybil neighbourhood
    // provider-snapshot RPC, epic #1934 child 4a). It is not in the shared `dig-rpc-protocol`
    // allowlist because that crate is a crates.io pin this repo cannot extend; promoting it into the
    // canonical allowlist is a tracked cross-repo follow-up. Until then it is allowlisted HERE,
    // deliberately: it is a READ that exposes only AGGREGATE COUNTS (never provider identities) — the
    // same privacy stance as the RLY-009 relay DHT-records view — and mutates no node state, so it
    // widens no privilege beyond the existing discovery methods.
    if method == crate::seams::dig_peer::neighbourhood_probe::GET_PROVIDER_SNAPSHOT_METHOD {
        return true;
    }
    // `dig.resolveCapsule` is the SECOND dig-node-local peer method (epic #1934 flywheel live-wiring,
    // PR-1). It answers a sampled DHT content-key with the `(store_id, root, size)` PREIMAGE this node
    // ALREADY HOLDS — a READ that discloses only the preimages of stores this node is already a public
    // provider for (whose bytes `dig.getAvailability`/`dig.fetchRange` already serve), and mutates no
    // node state, so it widens no privilege. Local for the same reason as `getProviderSnapshot`: the
    // shared `dig-rpc-protocol` allowlist is a crates.io pin this repo cannot extend (promoting it is a
    // tracked cross-repo follow-up).
    if method == crate::seams::dig_peer::resolve_capsule::RESOLVE_CAPSULE_METHOD {
        return true;
    }
    // `cache.pushCapsule` is the publish→seed mutator (#1476). It is LOCAL-ONLY by default — like every
    // other `cache.*` method it must NOT be forwarded to a self-signed peer (audit #179). The operator
    // OPENS it to the peer surface with `DIG_NODE_PUSH_OPEN=true`; even then the handler still requires a
    // §21.9 authorized-writer signature for the target store, so "reachable" never means "unauthenticated
    // mutation" (see `seams::capsule::push_capsule`). Read live so the toggle needs no restart.
    if method == crate::seams::capsule::PUSH_CAPSULE_METHOD {
        return crate::seams::capsule::push_open_enabled();
    }
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
    /// (`0/0` = unlimited = behavior-preserving default).
    ///
    /// `None` on the DEFAULT (unlimited) config: the serve path then skips `acquire` entirely, so an
    /// unconfigured node creates NO per-connection accounting state at all — closing the
    /// memory-exhaustion DoS where a peer mints unlimited fresh mTLS peer_ids (dig-tls accepts any
    /// self-signed leaf) to grow the crate's attacker-keyed, never-evicted per-conn map.
    ///
    /// `Some` only when an operator explicitly configures a non-zero cap. In that opt-in case the map
    /// is keyed by the caller `peer_id` and the crate currently has no per-connection eviction, so the
    /// residual per-conn footprint is a tracked follow-up (dig_ecosystem #1495 — a `dig-download`
    /// `evict()`/skip-when-unlimited crate fix, release-first).
    serve_limiter: Option<Arc<dig_download::FcfsRateLimiter>>,
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
    async fn handle_json_rpc(&self, req: Value, conn_key: &str) -> Value {
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
        // dig.getProviderSnapshot is answered HERE, from this node's LIVE DHT provider store, for the
        // same reason as dig.getPeers below: the base handle_rpc (the FFI-safe Node) holds no DHT
        // handle, so only the NodeResponder can answer it. The result is COUNTS-ONLY (no provider
        // identities) — the anti-Sybil per-peer observation the neighbourhood probe consumes (#1934).
        if method == crate::seams::dig_peer::neighbourhood_probe::GET_PROVIDER_SNAPSHOT_METHOD {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let result = crate::seams::dig_peer::neighbourhood_probe::provider_snapshot_result(
                self.dht.as_ref(),
                &params,
            )
            .await;
            return json!({"jsonrpc":"2.0","id":id,"result":result});
        }
        // dig.resolveCapsule is answered HERE from this node's OWN holdings reverse index
        // (`cache_list_cached`): for each requested content-key it holds, it returns the
        // `(store_id, root, size)` PREIMAGE the key hashed from (epic #1934 flywheel live-wiring, PR-1).
        // A requested key this node does not hold is simply absent — the getAvailability not-held idiom.
        if method == crate::seams::dig_peer::resolve_capsule::RESOLVE_CAPSULE_METHOD {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let result = crate::seams::dig_peer::resolve_capsule::resolve_capsule_answer(
                &self.node, &params,
            )
            .await;
            return json!({"jsonrpc":"2.0","id":id,"result":result});
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
        // This is the peer-RPC server's OWN dispatch — a REMOTE peer's request, always (#179/#1576).
        // Provenance is FirstParty here: `landing_origin(Peer, FirstParty) == Peer`, so a peer-wire
        // read still never lands (the transport axis already denies it); the Sec-Fetch axis only ever
        // applies to browser-driven loopback requests, which never arrive here (#1956).
        crate::handle_rpc_as(
            &self.node,
            req,
            crate::download::ReadOrigin::Peer,
            crate::download::RequestProvenance::FirstParty,
            crate::rate_limit::RequestorId::Peer(conn_key.to_string()),
        )
        .await
    }

    async fn handle_availability(&self, items: Value, conn_key: &str) -> Value {
        let items = items.as_array().cloned().unwrap_or_default();
        // The verified mTLS peer_id (`conn_key`) keys the per-requestor miss-lookup budget, identical
        // to the range-stream miss on this same peer surface (dig_ecosystem#2007).
        let requestor = crate::rate_limit::RequestorId::Peer(conn_key.to_string());
        // This is the dig-nat MUX shape (`{items}`), and `dig_nat::mux::AvailabilityRequest` carries
        // NO hop counter — measured, not assumed. A request that cannot carry a budget cannot bound a
        // recursion, so this leg declares the budget already SPENT and forwards nothing
        // (dig_ecosystem#3128). Fail-closed on purpose: the alternative is an unbounded recursive ask
        // on the one shape that has no way to count hops. The JSON-RPC leg
        // (`seams/dig_rpc/dispatch.rs`) carries `redirect_depth` and is where forwarding happens.
        self.node
            .availability_batch(&items, &requestor, crate::download::HopBudget::spent())
            .await
    }

    /// Serve a window of a locally-held whole `.dig` module (#1576, the reshare leg).
    ///
    /// The module is read + framed on a blocking thread (a `.dig` is large, and a multi-MiB read must
    /// never stall the async runtime), then paced by the SAME FCFS outbound limiter `dig.fetchRange`
    /// uses — a whole-capsule pull is the largest thing this node ever serves, so exempting it would
    /// leave the biggest transfer as the one path that can starve every other peer.
    async fn stream_module_range(
        &self,
        params: Value,
        conn_key: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        use crate::seams::dig_peer::module_serve;

        let store = params
            .get("store_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let root = params
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let length = params
            .get("length")
            .and_then(Value::as_u64)
            .unwrap_or(module_serve::MAX_MODULE_WINDOW);
        module_serve::module_range_requested(conn_key, &store, &root, offset, length);
        // INBOUND DEMAND (#1990): a peer asking us for this module's window is direct evidence this
        // node's neighbourhood wants the store — tag it Tier1Demand + (opt-in) trigger a tier-1 cache.
        self.node.note_inbound_demand(&store, &root);

        let cache = self.node.cache_dir_path().to_path_buf();
        let (s, r) = (store.clone(), root.clone());
        let window = tokio::task::spawn_blocking(move || {
            module_serve::read_module_window(&cache, &s, &r, offset, length)
        })
        .await
        .unwrap_or(None);

        let Some(window) = window else {
            module_serve::module_range_outcome(conn_key, &store, &root, offset, None);
            return write_framed(
                out,
                &module_serve::module_unavailable_frame(crate::download::RESOURCE_UNAVAILABLE),
            )
            .await;
        };

        // OUTGOING-BANDWIDTH THROTTLE (#30/#1616): the module-range serve is the whole-capsule pull —
        // the largest transfer in the system — so it must respect the operator egress cap the same way
        // `stream_range` does, not only the FCFS `serve_limiter`. Checked ONCE before the first frame,
        // against the window this stream will actually serve. Over budget with a known alternate holder
        // → decline with the redirect frame (the puller then sources the window elsewhere, the SAME
        // `{"error": …}` shape as the not-held answer above); no alternate → serve anyway
        // (`bandwidth_redirect` returns `None`), never dropping a request only this node can answer.
        if let Some(content) = crate::download::availability_content_id(&store, Some(&root), None) {
            let depth = crate::download::redirect_depth(&params);
            if let Some(obj) = self
                .node
                .bandwidth_redirect(&content, window.len() as u64, depth)
                .await
            {
                module_serve::module_range_outcome(conn_key, &store, &root, offset, None);
                return write_framed(out, &json!({ "error": obj })).await;
            }
        }

        // One frame per FRAME PAYLOAD, so a large module rides many bounded frames. The puller decodes
        // these with `dig_nat::RangeFrame` (see `module_serve::module_frame`), so they are bound by the
        // SAME ceiling as `dig.fetchRange` frames — framing them on `RANGE_WINDOW` made every module
        // window over roughly 48 KiB undecodable, which is a whole-capsule pull, i.e. the reshare leg
        // (#1640/#1668).
        let total = window.len() as u64;
        let mut written = 0usize;
        let mut frames = 0u64;
        while written < window.len() {
            let take = range_frame::FRAME_PAYLOAD.min(window.len() - written);
            let complete = written + take == window.len();
            let frame = module_window_frame(
                offset + written as u64,
                &window[written..written + take],
                complete,
                total,
            );
            // Charge the REAL encoded size, before the write, and to BOTH throttles. The payload length
            // understates a metadata-carrying frame, and each frame is debited before it is written so a
            // peer that resets the stream mid-serve is still accounted for the bytes it already cost.
            let bytes = range_frame::encode_range_frame(&frame)?;
            if let Some(limiter) = &self.serve_limiter {
                limiter.acquire(conn_key, bytes.len() as u64).await;
            }
            self.node.record_outgoing_bytes(bytes.len() as u64);
            out.write_all(&bytes).await?;
            out.flush().await?;
            written += take;
            frames += 1;
        }
        if frames == 0 {
            // An empty window (an offset at/past the end) still needs a terminating frame, or the caller
            // waits forever for a `complete` that never arrives.
            let frame = module_window_frame(offset, &[], true, 0);
            let bytes = range_frame::encode_range_frame(&frame)?;
            self.node.record_outgoing_bytes(bytes.len() as u64);
            out.write_all(&bytes).await?;
            out.flush().await?;
            frames = 1;
        }
        module_serve::module_range_outcome(conn_key, &store, &root, offset, Some((total, frames)));
        Ok(())
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
        // A client that already holds the commitment for this root asks us not to resend the
        // resource-scaling metadata (SPEC §5.1.1). Absent or false preserves the pre-0.13.0 behaviour,
        // so a client that does not know the field is never broken by it.
        let skip_layout = req
            .get("skip_layout")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // The REQUESTED SPAN's exclusive end — the stream must never serve past it, however far the
        // resource itself continues (#1619). A resource's own exhaustion says nothing about "the
        // CALLER's requested span is satisfied", which is the bound this serve actually owes.
        let requested_end = offset.saturating_add(length);
        // #1595: announce the inbound request, then EVERY termination path below reports its outcome —
        // so "did the holder get it, and what did it answer?" is answerable from the log alone.
        let target = serve_log::ServeTarget::from_range_request(conn_key, &req);
        serve_log::range_requested(&target, offset, length);
        // INBOUND DEMAND (#1990): a peer's range request for this store is real demand from this
        // node's neighbourhood — tag it Tier1Demand + (opt-in) trigger a tier-1 whole-capsule cache.
        self.node.note_inbound_demand(store, root);

        // The resource is resolved ONCE for the whole stream, because the prologue's paging state
        // belongs to the stream rather than to any one frame (see `Node::range_source`).
        let resource = match self.node.range_source(store, root, rk).await {
            Ok(resource) => resource,
            Err((code, message)) => {
                // A LOCAL MISS (-32004) over the peer stream: try the #165 P2P miss path first —
                // stream the fetched-through frames (transparent to the caller), or write a
                // redirect ERROR FRAME naming the holder(s) so the caller re-requests there. An
                // empty engine / no provider falls back to the bare error frame (no silent miss
                // when a provider exists). The redirect frame carries the SAME `-32008` +
                // `data.redirect` shape as the JSON-RPC redirect (the read-tier redirect response).
                if code == crate::download::RESOURCE_UNAVAILABLE {
                    if let Some(content) = crate::download::range_content_id(&req) {
                        let budget = crate::download::HopBudget::from_params(&req);
                        let proxy = crate::download::proxy_requested(&req);
                        // A remote peer's own fetchRange stream miss (#179/#1576) — never local. The
                        // per-requestor miss-lookup rate limit (dig_ecosystem#2007) is keyed by this
                        // peer's mTLS-verified `peer_id` (`conn_key`), so one peer's burst cannot
                        // amplify this node's DHT lookups at another peer's expense.
                        let requestor = crate::rate_limit::RequestorId::Peer(conn_key.to_string());
                        match self
                            .node
                            .miss_outcome(
                                &content,
                                budget,
                                proxy,
                                crate::download::ReadOrigin::Peer,
                                &requestor,
                            )
                            .await
                        {
                            crate::download::MissOutcome::Fetched(f) => {
                                // Fetched-through: the bytes come from a holder but are served
                                // here, so the outcome is a serve (its frames carry the same
                                // verification metadata, #1577) — UNLESS the fetch-through itself
                                // refused the range, which it answers with an error frame rather
                                // than an `Err`. Reporting its own verdict keeps `served` meaning
                                // exactly one thing across both serve paths (#1595).
                                let node = self.node.clone();
                                let streamed = stream_fetched_range(
                                    out,
                                    &f,
                                    RangeStreamPlan {
                                        offset,
                                        requested_end: offset.saturating_add(length),
                                        skip_layout,
                                        limiter: self.serve_limiter.as_deref(),
                                        conn_key,
                                        egress: &|n| node.record_outgoing_bytes(n),
                                    },
                                )
                                .await?;
                                let outcome =
                                    streamed.as_serve_outcome(f.inclusion_proof.is_some());
                                serve_log::range_outcome(&target, offset, &outcome);
                                return Ok(());
                            }
                            crate::download::MissOutcome::Redirect {
                                providers,
                                next_depth,
                            } => {
                                serve_log::range_outcome(
                                    &target,
                                    offset,
                                    &serve_log::RangeOutcome::redirected(
                                        crate::download::CONTENT_REDIRECT,
                                        format!("{} holder(s) named", providers.len()),
                                    ),
                                );
                                let errf = json!({"error": crate::download::redirect_error_object(
                                    &content, &providers, next_depth)});
                                return write_framed(out, &errf).await;
                            }
                            crate::download::MissOutcome::RateLimited => {
                                // This peer is driving the miss→lookup path too fast: refuse with a
                                // rate-limit error frame (dig_ecosystem#2007) so it backs off. A
                                // DIFFERENT peer draws from its own bucket and is unaffected.
                                serve_log::range_outcome(
                                    &target,
                                    offset,
                                    &serve_log::RangeOutcome::from_error(
                                        crate::download::CONTENT_MISS_RATE_LIMITED,
                                        crate::download::MISS_RATE_LIMITED_MESSAGE.to_string(),
                                    ),
                                );
                                let errf = json!({"error": {
                                    "code": crate::download::CONTENT_MISS_RATE_LIMITED,
                                    "message": crate::download::MISS_RATE_LIMITED_MESSAGE,
                                }});
                                return write_framed(out, &errf).await;
                            }
                            crate::download::MissOutcome::NotFound => {}
                            // Absence unproven (dig-node#273): answer with the distinct code rather
                            // than falling through to the plain not-found below, so the peer that
                            // asked can tell a settled answer from an unanswered question — and, when
                            // that peer is a relaying hop, does not pass an absence downwards that
                            // nothing here established.
                            crate::download::MissOutcome::Inconclusive => {
                                let errf = json!({"error": {
                                    "code": crate::download::content_miss_inconclusive(),
                                    "message": crate::download::MISS_INCONCLUSIVE_MESSAGE,
                                }});
                                return write_framed(out, &errf).await;
                            }
                        }
                    }
                }
                // Nothing to serve and nowhere to point the caller: name the refusal (#1595) so
                // an unanswered read is never indistinguishable from a request never received.
                serve_log::range_outcome(
                    &target,
                    offset,
                    &serve_log::RangeOutcome::from_error(code, message.clone()),
                );
                let errf = json!({"error": {"code": code, "message": message}});
                return write_framed(out, &errf).await;
            }
        };

        // OUTGOING-BANDWIDTH THROTTLE (#30): this is the node-to-node range-stream wire multi-source
        // downloaders hammer — the busiest outgoing-bytes path. Redirect the caller to a known holder
        // instead of streaming over-budget (same #165 redirect shape as a genuine miss); serve it
        // anyway when no alternate is known (never drop a request the node could answer).
        //
        // Checked ONCE, before the first frame, against the span this stream will actually serve.
        // Previously it was re-checked per frame, which could only ever fire on the first frame in
        // practice — and a redirect written MID-stream, after real bytes have gone out, is not a
        // coherent answer to the caller anyway.
        let total = resource.ciphertext.len();
        let will_serve = requested_end.min(total).saturating_sub(offset.min(total)) as u64;
        if will_serve > 0 {
            if let Some(content) = crate::download::range_content_id(&req) {
                let depth = crate::download::redirect_depth(&req);
                if let Some(obj) = self
                    .node
                    .bandwidth_redirect(&content, will_serve, depth)
                    .await
                {
                    let code = obj
                        .get("code")
                        .and_then(Value::as_i64)
                        .unwrap_or(crate::download::CONTENT_REDIRECT);
                    serve_log::range_outcome(
                        &target,
                        offset,
                        &serve_log::RangeOutcome::redirected(
                            code,
                            "outgoing-bandwidth budget exceeded".to_string(),
                        ),
                    );
                    let errf = json!({"error": obj});
                    return write_framed(out, &errf).await;
                }
            }
        }

        let chunk_lens: Vec<u64> = resource.chunk_lens.iter().map(|&l| u64::from(l)).collect();
        let root_hex = resource.roothash.to_hex();
        let proof = {
            use base64::Engine as _;
            use digstore_core::codec::Encode as _;
            base64::engine::general_purpose::STANDARD.encode(resource.merkle_proof.to_bytes())
        };
        let streamed = stream_range_frames(
            out,
            &resource.ciphertext,
            range_frame::RangeVerification {
                total_length: total as u64,
                chunk_lens: &chunk_lens,
                root: Some(&root_hex),
                inclusion_proof: Some(&proof),
            },
            RangeStreamPlan {
                offset,
                requested_end,
                skip_layout,
                limiter: self.serve_limiter.as_deref(),
                conn_key,
                egress: &|n| self.node.record_outgoing_bytes(n),
            },
        )
        .await?;
        serve_log::range_outcome(&target, offset, &streamed.as_serve_outcome(!skip_layout));
        Ok(())
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
/// to a locally-held one (every frame carries the verification metadata the caller checks against the
/// chain-anchored root, #1577). A bad range (offset past the resource) writes one error frame.
///
/// Returns what the fetch-through actually did, so the caller reports a TRUTHFUL outcome (#1595):
/// the real frame count and byte total, and — because this path answers a bad range with an ERROR
/// frame rather than an `Err` — whether it refused instead of serving.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct StreamOutcome {
    /// RESOURCE bytes written across every data frame.
    pub(crate) bytes: u64,
    /// How many data frames those bytes were split into (zero when the range was refused outright).
    pub(crate) frames: u64,
    /// Total ENCODED wire bytes written — always >= `bytes`, and non-zero even for a frame whose
    /// payload is empty (a prologue page). This is the quantity the throttles are charged.
    pub(crate) encoded_bytes: u64,
    /// `Some((code, message))` when an error frame was written instead of completing the stream.
    pub(crate) refusal: Option<(i64, String)>,
}

impl StreamOutcome {
    /// The serve-log outcome this stream truthfully represents (#1595): the refusal it answered with,
    /// or a serve carrying the REAL frame and byte counts. `proof_attached` describes the fetched
    /// resource's frames, which is knowledge the streaming loop does not have.
    fn as_serve_outcome(&self, proof_attached: bool) -> serve_log::RangeOutcome {
        match &self.refusal {
            Some((code, message)) => serve_log::RangeOutcome::from_error(*code, message.clone()),
            None => serve_log::RangeOutcome::Served {
                bytes: self.bytes,
                frames: self.frames,
                proof_attached,
            },
        }
    }
}

pub(crate) async fn stream_fetched_range(
    out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    fetched: &crate::download::FetchedResource,
    plan: RangeStreamPlan<'_>,
) -> std::io::Result<StreamOutcome> {
    stream_range_frames(
        out,
        &fetched.bytes,
        range_frame::RangeVerification {
            total_length: fetched.total_length,
            chunk_lens: &fetched.chunk_lens,
            root: fetched.root.as_deref(),
            inclusion_proof: fetched.inclusion_proof.as_deref(),
        },
        plan,
    )
    .await
}

/// One `dig.fetchModuleRange` frame over a window of a locally-held `.dig` module.
///
/// The puller decodes these with `dig_nat::RangeFrame`, so they obey the same framing ceiling as
/// `dig.fetchRange` frames, and `total_length` — the served WINDOW's length — rides EVERY frame rather
/// than only the first. It is fixed-size, and it is what lets the puller size its staging file and
/// notice a holder describing a different window as frames arrive instead of after paying for the whole
/// capsule.
///
/// `total_length` is ASSIGNED, not built. `RangeFrame` has no `with_total_length` (only `with_identity`
/// sets it, and that needs a generation root, which a `.dig` window has none of — a capsule is
/// self-verifying against the chain anchor on install). The similarly-named `with_declared_length` sets
/// `length`, the frame's own payload length, and dig-nat documents that a serve path has no reason to
/// call it: a frame whose `length` disagrees with its payload is one the reader distrusts. No
/// `chunk_count` is emitted, because this leg carries no per-resource chunk layout to count — inventing
/// one would be a claim about a structure that is not there.
fn module_window_frame(
    offset: u64,
    bytes: &[u8],
    complete: bool,
    total_length: u64,
) -> dig_nat::RangeFrame {
    let mut frame = dig_nat::RangeFrame::data(offset, bytes.to_vec()).with_complete(complete);
    frame.total_length = Some(total_length);
    frame
}

/// What a range stream owes its caller: the span requested, whether the resource-scaling metadata was
/// waived, and the budget the bytes must be paced against.
///
/// Grouped rather than passed loose because these five travel together through every serve path, and
/// the two length-ish `usize`s are the pair a positional call site is most likely to transpose — the
/// span bound (#1619) and the frame ceiling (#1640) are already easy enough to confuse.
pub(crate) struct RangeStreamPlan<'a> {
    /// First byte of the requested span.
    pub(crate) offset: usize,
    /// Exclusive end of the requested span — never widened, however far the resource continues.
    pub(crate) requested_end: usize,
    /// The client already holds this root's commitment and waived `chunk_lens` + `inclusion_proof`.
    pub(crate) skip_layout: bool,
    /// FCFS outbound budget, or `None` for the default unlimited config (which touches no per-conn
    /// accounting state at all — #1495).
    pub(crate) limiter: Option<&'a dig_download::FcfsRateLimiter>,
    /// The connection this stream is serving, for per-connection pacing.
    pub(crate) conn_key: &'a str,
    /// Charged the REAL encoded size of each frame, immediately before that frame is written.
    ///
    /// A sink rather than a returned total, deliberately: a returned total is only added up if the
    /// stream runs to completion, and the case that matters is the one where it does NOT — a peer that
    /// reads a few frames and resets the stream has already cost real egress.
    pub(crate) egress: &'a (dyn Fn(u64) + Send + Sync),
}

/// Stream `[offset, requested_end)` of ONE resource as conforming `dig.fetchRange` frames.
///
/// This is the single framing loop behind BOTH serve paths — a locally-held resource and a
/// fetched-through one — because they owe the caller byte-identical frames, and two loops maintaining
/// one wire contract is the shape of defect that produced #1640 in the first place.
///
/// Three genuinely different bounds are enforced here:
///
/// * each frame's payload is at most [`range_frame::FRAME_PAYLOAD`], the per-FRAME cap — NOT
///   [`RANGE_WINDOW`], which bounds a whole REQUEST and is 96x larger;
/// * the stream never serves past `requested_end`, the caller's own requested span (#1619), a bound
///   the resource's own exhaustion cannot express;
/// * the stream does not END until the prologue is fully delivered, because a reader must discard a
///   partial `chunk_lens` entirely — it is a DECRYPT input whose entries must sum to `total_length`,
///   so a layout short even one entry is unusable rather than partially useful.
///
/// Frames are encoded by [`range_frame::encode_range_frame`] — the sole caller of dig-nat's own
/// encoder in this crate — so this path cannot emit a frame a conforming receiver must reject even
/// if a future change miscomputed a window.
async fn stream_range_frames(
    out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    bytes: &[u8],
    verification: range_frame::RangeVerification<'_>,
    plan: RangeStreamPlan<'_>,
) -> std::io::Result<StreamOutcome> {
    let RangeStreamPlan {
        offset,
        requested_end,
        skip_layout,
        limiter,
        conn_key,
        egress,
    } = plan;
    let total = bytes.len();
    let mut outcome = StreamOutcome::default();
    if offset > total {
        // Unsatisfiable range (spec -32007), answered with an error frame rather than an empty stream
        // so the caller can tell "refused" from "served nothing".
        let refusal = (
            -32007i64,
            format!("offset {offset} beyond resource length {total}"),
        );
        let errf = json!({"error": {"code": refusal.0, "message": refusal.1.clone()}});
        write_framed(out, &errf).await?;
        outcome.refusal = Some(refusal);
        return Ok(outcome);
    }

    let mut framer = range_frame::RangeStreamFramer::new(verification, skip_layout);
    let end_of_span = requested_end.min(total);
    let mut off = offset;
    loop {
        let take = range_frame::FRAME_PAYLOAD.min(end_of_span.saturating_sub(off));
        let window = bytes[off..off + take].to_vec();
        // A trailing prologue-only continuation frame carries NO data payload — only the next
        // `chunk_lens` page. It must be stamped with byte-offset 0, NOT the ascending cursor `off`
        // (which by now equals the resource length): the 0.17 reader's establish probe reads a 1-byte
        // span and rejects any frame whose `offset >= max_len`, so a page-only frame at `off == total`
        // would be refused before its layout could be reassembled. A zero-length window is never a real
        // byte position, so anchoring it at 0 loses nothing.
        let frame_start = if take == 0 { 0 } else { off as u64 };
        let frame = framer.next_frame(frame_start, window);
        // This frame is the FINAL one only when the bytes are done AND the prologue is fully sent.
        // The page this frame just took is already accounted for, so `prologue_pending` here answers
        // "are there pages still to come AFTER this frame".
        let bytes_done = off + take >= end_of_span || off + take >= total;
        let last = bytes_done && !framer.prologue_pending();
        let frame = frame.with_complete(last && off + take >= total);

        // Encode BEFORE charging anything, because the wire cost of a frame is its ENCODED size, not
        // its payload: a prologue page is ~14 KB of metadata on a frame whose payload may be zero, and
        // charging `take` would score that frame as free. A peer can ask for exactly that shape — a
        // one-byte span without `skip_layout`, which is a client-set flag it simply omits — so this is
        // a serve it can request, not a corner case.
        let encoded = match range_frame::encode_range_frame(&frame) {
            Ok(encoded) => encoded,
            Err(e) => {
                // This resource has NO conforming range stream from this holder (an inclusion proof
                // over `MAX_INCLUSION_PROOF_B64` is the real case). Name it with the catalogued
                // `-32009` instead of letting the error propagate: a propagated `Err` truncates the
                // stream with no frame and skips the serve-log outcome entirely, leaving a
                // `range_requested` with no verdict — the exact ambiguity #1595 exists to remove.
                let refusal = (
                    dig_rpc_protocol::ErrorCode::RangeMetadataUnrepresentable as i64,
                    format!("this holder cannot frame a conforming range for this resource: {e}"),
                );
                let errf = json!({"error": {"code": refusal.0, "message": refusal.1.clone()}});
                write_framed(out, &errf).await?;
                outcome.refusal = Some(refusal);
                return Ok(outcome);
            }
        };
        // FCFS outbound PACING (#1436): wait (in arrival order) until this frame's bytes fit the
        // global + per-connection budget before writing. `None` (the default/unlimited config) skips
        // `acquire` entirely — no per-conn map is touched (#1495 DoS guard).
        if let Some(limiter) = limiter {
            limiter.acquire(conn_key, encoded.len() as u64).await;
        }
        // Charged per frame, BEFORE the write. Accounting only after the whole stream returned means a
        // peer that requests a large span, reads a few frames and then resets the yamux stream causes
        // real egress recorded as zero — repeatable indefinitely, so the throttle never engages.
        egress(encoded.len() as u64);
        out.write_all(&encoded).await?;
        out.flush().await?;
        outcome.bytes += take as u64;
        outcome.encoded_bytes += encoded.len() as u64;
        outcome.frames += 1;
        serve_log::range_frame_served(off, take, frame.chunk_index);
        off += take;

        if last {
            return Ok(outcome);
        }
        // The remaining pages ride zero-payload frames once the bytes run out. That is bounded by the
        // page count (itself bounded by the layout), so a resource with a large layout and a tiny
        // requested span finishes its prologue instead of spinning.
        if take == 0 && !framer.prologue_pending() {
            return Ok(outcome);
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
    // Seed from the current snapshot so the registry is populated before the first fetch. The pool
    // reports each peer's GOSSIP addr (:9445); the download-side `PoolProviderLocator` must offer the
    // peer-RPC addr (:9444) — dialing the gossip port for a peer-RPC fetchRange gets the gossip
    // protocol on the wire (`InvalidContentType`) and the Tier-2 fetch silently dies. Map it down
    // BEFORE it enters the connected pool, exactly as the DHT routing feed does (#1575 GAP 2, #1590).
    for (peer_id, addr, _outbound) in handle.connected_pool_peers() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(peer_id.as_ref());
        let event = crate::download::pool_event_to_selector(
            bytes,
            crate::download::PoolEventKind::Added {
                addr: dht_addr_from_gossip_addr(addr),
            },
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

/// Feed the dig-dht routing table from the dig-gossip connected pool (#1574): seed it with the
/// current pool snapshot, then forward every `PoolEvent` churn event so routing populates LIVE as
/// peers connect — not just from the one-shot pre-connect `bootstrap` in [`bring_up_dht`].
///
/// This is the fix for the broken cross-node DISCOVER leg: `bootstrap` runs BEFORE any peer
/// connects, so in a freshly-formed network the pool is empty at that moment and routing stays
/// empty — `find_providers` then finds nobody even though a holder announced. Mirrors
/// [`spawn_selector_registry_feed`]'s shape (seed snapshot → subscribe → forward churn), but drives
/// the DHT routing table instead of the selector registry. `PeerAdded` inserts into routing;
/// `PeerRemoved` evicts so lookups never seed from a dead contact. Best-effort: a subscribe failure
/// logs + returns (bootstrap + the maintenance refresh still fill routing over time); the task ends
/// when the pool event channel closes.
fn spawn_dht_routing_feed(dht: Arc<crate::dht::DhtHandle>, handle: dig_gossip::GossipHandle) {
    // Seed from the current snapshot so routing is populated before the first lookup. The pool reports
    // each peer's GOSSIP addr; map it to the peer's DHT addr before seeding routing (#1575 GAP 2).
    for (peer_id, addr, _outbound) in handle.connected_pool_peers() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(peer_id.as_ref());
        // Skip a peer whose pool address is not a destination (#1784) — routing must never seed a
        // lookup from a wildcard contact.
        let Some(dht_addr) = dht_contact_from_pool_addr(addr) else {
            continue;
        };
        let dht = dht.clone();
        tokio::spawn(async move {
            dht.add_peer(bytes, dht_addr).await;
        });
    }

    let mut rx = match handle.subscribe_pool_events() {
        Ok(rx) => rx,
        Err(e) => {
            tracing::debug!(error = %e, "dht routing feed: could not subscribe to pool events");
            return;
        }
    };
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => match &ev {
                    dig_gossip::PoolEvent::PeerAdded { peer_id, addr } => {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(peer_id.as_ref());
                        // Map the peer's gossip addr to its DHT addr before seeding routing (GAP 2),
                        // dropping an address that is not a destination (#1784).
                        if let Some(dht_addr) = dht_contact_from_pool_addr(*addr) {
                            dht.add_peer(bytes, dht_addr).await;
                        }
                    }
                    dig_gossip::PoolEvent::PeerRemoved { peer_id, .. } => {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(peer_id.as_ref());
                        dht.remove_peer(bytes).await;
                    }
                },
                // Lagged (slow consumer) — keep going; a missed add/remove is re-seeded by the pool
                // snapshot on the next churn and by bucket-refresh maintenance.
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
pub(crate) fn map_gossip_pool_event(ev: &dig_gossip::PoolEvent) -> dig_peer_selector::PoolEvent {
    match ev {
        dig_gossip::PoolEvent::PeerAdded { peer_id, addr } => {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(peer_id.as_ref());
            // The pool reports the peer's GOSSIP addr (:9445); the connected pool must hold its
            // peer-RPC addr (:9444) so the download transport dials the fetchRange listener, not the
            // gossip listener (#1575 GAP 2, recurring in the selector-registry/pool feed for #1590).
            crate::download::pool_event_to_selector(
                bytes,
                crate::download::PoolEventKind::Added {
                    addr: dht_addr_from_gossip_addr(*addr),
                },
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
                dig_gossip::PoolRemovalReason::Reaped => {
                    crate::download::GossipRemovalReason::Reaped
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
/// Bind a [`GossipConfig`](dig_gossip::GossipConfig) to the node's ONE persistent `identity` so the
/// pool presents the SAME `peer_id = SHA-256(SPKI DER)` on EVERY transport (#1532/#1541):
///
/// * `peer_id` — the pool's advertised/handshake/self-dial-guard identity, derived from the persistent
///   NodeCert's SPKI (dig-gossip's own derivation, so the type + hashing match the pool's internal id).
/// * `nat_identity` — the persistent NodeCert INJECTED as the dig-nat transport identity. Without it
///   dig-gossip mints a RANDOM per-boot ephemeral NodeCert for its DigPeer/relay dials, so the
///   transport `peer_id` differed from the advertised/registered/pinned one and Leg B's relayed circuit
///   failed closed with `peer_id mismatch`. Injecting THIS `Arc<NodeCert>` — the same one the chia-ssl
///   path, the mTLS listener, the DHT dials, and the relay reservation present — makes ONE identity
///   span all transports, the invariant that closes the Leg-B mismatch.
///
/// Pure (mutates only the config), so the one-identity invariant is unit-tested without a live pool.
fn apply_persistent_identity(
    cfg: &mut dig_gossip::GossipConfig,
    identity: &Arc<dig_nat::NodeCert>,
) {
    cfg.peer_id = dig_gossip::peer_id_from_tls_spki_der(identity.spki_der());
    cfg.nat_identity = Some(identity.clone());
}

/// Returns the shared status so the node can report the REAL reservation state (#872), plus — when the
/// relay is enabled — the receiver of INTRODUCED inbound relay circuits (Leg B's responder half): the
/// accept path is turned on ([`RelayStatus::enable_accept`](dig_nat::relay::RelayStatus::enable_accept))
/// BEFORE the reservation loop starts registering, so no circuit a NAT'd peer relays to us is dropped as
/// unknown-peer before the accept channel exists. The caller drains it via [`spawn_relay_accept_loop`].
/// `None` when the relay is disabled (no reservation, so no inbound circuits).
fn wire_relay_reservation(
    handle: &dig_gossip::GossipHandle,
    enabled: bool,
    endpoint: String,
    peer_id: String,
    network_id: String,
    listen_addrs: Vec<std::net::SocketAddr>,
) -> (
    Arc<dig_nat::relay::RelayStatus>,
    Option<tokio::sync::mpsc::Receiver<dig_nat::relay::RelayTunnel>>,
) {
    let status = dig_nat::relay::RelayStatus::new();
    handle.attach_relay_status(status.clone());
    if enabled {
        // Enable the RESPONDER path first: install the accept channel so the reservation loop hands us
        // every introduced circuit from a peer we have no open outbound tunnel to (#1536, Leg B).
        let inbound = status.enable_accept();
        let reservation_status = status.clone();
        tokio::spawn(async move {
            // B1 (#870): advertise the node's gossip listen candidates so the relay's reflexive
            // substitution can hand another peer a DIALABLE candidate for this node.
            dig_nat::relay::run_relay_connection(
                endpoint,
                peer_id,
                network_id,
                listen_addrs,
                reservation_status,
            )
            .await;
        });
        (status, Some(inbound))
    } else {
        status.set_disabled();
        (status, None)
    }
}

/// Spawn the RESPONDER half of Leg B: for every INTRODUCED relay circuit surfaced by
/// [`RelayStatus::enable_accept`](dig_nat::relay::RelayStatus::enable_accept) (drained from `inbound`),
/// run the mTLS SERVER handshake ([`dig_nat::RelayAcceptor`], presenting THIS node's persistent
/// `identity`) and serve the resulting authenticated session exactly like a direct inbound connection
/// ([`serve_accepted_relay_conn`]). This is what lets a NAT'd peer's relayed circuit be ACCEPTED — the
/// missing counterpart to the dialer that closes Leg B (#1532/#1536).
///
/// Bounded by its own accepted-connection semaphore (mirroring the direct listener, audit #179): a
/// relay cannot make us spawn unbounded serve tasks. `relay_addr` (observability only) is recorded as
/// the accepted [`PeerConnection`](dig_nat::PeerConnection)'s remote address.
fn spawn_relay_accept_loop(
    mut inbound: tokio::sync::mpsc::Receiver<dig_nat::relay::RelayTunnel>,
    identity: Arc<dig_nat::NodeCert>,
    responder: Arc<dyn PeerRpcResponder>,
    relay_addr: Option<std::net::SocketAddr>,
) {
    let mut acceptor = dig_nat::RelayAcceptor::new(identity);
    if let Some(addr) = relay_addr {
        acceptor = acceptor.with_relay_endpoint(addr);
    }
    tokio::spawn(async move {
        let conn_permits = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_PEER_CONNECTIONS));
        while let Some(tunnel) = inbound.recv().await {
            let acceptor = acceptor.clone();
            let responder = responder.clone();
            let spawned = spawn_with_permit(&conn_permits, async move {
                match acceptor.accept(tunnel).await {
                    Ok(conn) => serve_accepted_relay_conn(conn, responder).await,
                    Err(e) => {
                        tracing::debug!(error = %e, "relayed circuit mTLS accept failed; dropped")
                    }
                }
            });
            if !spawned {
                tracing::debug!("relayed circuit shed: global connection cap reached");
            }
        }
    });
}

/// Serve one ACCEPTED relayed circuit exactly like a direct inbound connection: build the authenticated
/// caller [`dig_dht::Contact`] from the mTLS-verified `peer_id` + relay endpoint (identity comes from
/// the certificate the handshake verified, never the wire body), then serve the muxed session against
/// `responder` via [`serve_peer_session_from`]. Identical downstream handling to a direct inbound (§the
/// accepted [`PeerConnection`](dig_nat::PeerConnection) carries the SAME authentication), so a NAT'd
/// peer reaching us over a relay circuit gets the full L7 peer RPC (availability / range / DHT).
async fn serve_accepted_relay_conn(
    conn: dig_nat::PeerConnection,
    responder: Arc<dyn PeerRpcResponder>,
) {
    let dig_nat::PeerConnection {
        peer_id,
        mut session,
        ..
    } = conn;
    // A relayed peer is NAT'd and NOT directly dialable, and `remote_addr` here is the RELAY's socket
    // (shared across every relayed peer). Record a relay-typed caller with NO direct candidate so we
    // never fan the relay address network-wide as a bogus direct-dial target under this peer_id
    // (DiD-1 / #1532) — the peer stays reachable for response routing on the live session.
    let caller = Some(crate::dht::relayed_caller_contact(&peer_id));
    serve_peer_session_from(caller, &mut session, responder).await;
}

/// Bring up the peer network (the fallible body of [`spawn_peer_network`]).
async fn run_peer_network(node: Arc<crate::Node>) -> Result<(), String> {
    // Pin the rustls crypto provider (ring) before ANY TLS use (the pool + the mTLS listener + any
    // outbound dial), since aws-lc-rs is also in the graph and rustls won't auto-pick between them.
    install_crypto_provider();
    // Install the weak self-reference so a `&self` read handler can spawn an owned-`Arc` background
    // task — the capsule backfill on a read-from-another-node (SPEC §5.6). Weak: no self-keep-alive.
    node.set_self_ref(Arc::downgrade(&node));
    // Converge a cache written by a prior binary onto the unified `.dig` artifact BEFORE the first
    // inventory announce below (#1896): rename any legacy `<cache>/modules/<store>/*.module` to `.dig`.
    // Idempotent + crash-safe, and reader-tolerance serves either suffix meanwhile, so a legacy holder
    // is never dropped by the upgrade.
    crate::capsule_key::migrate_legacy_module_extensions(node.cache_dir_path());
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
    //    relay reservation for NAT reachability. The pool's inbound TLS listener MUST present the
    //    node's ONE advertised identity — the SAME CA-signed `NodeCert` (peer_id = SHA-256(SPKI DER))
    //    that the node registers with the relay, advertises, and the auto-dialer PINS. So we point the
    //    pool's cert/key at the persisted `NodeCert` files themselves (dig-gossip only READS them);
    //    letting the GossipService mint its OWN throwaway cert would hash to a DIFFERENT peer_id and
    //    every dial to this node fails closed with `peer_id mismatch` (#1532 — the identity split).
    //    `cfg.peer_id` is set to that same identity so the pool's self-dial guard + handshake agree.
    //    The address book (`peers.json`) stays under `peer-net/`; only the identity is shared.
    let gossip_dir = node.peer_cert_dir();
    let _ = std::fs::create_dir_all(&gossip_dir);
    let (gossip_cert_path, gossip_key_path) = gossip_identity_paths(&node.node_cert_dir());
    let mut cfg = dig_gossip::GossipConfig {
        network_id: genesis,
        cert_path: gossip_cert_path,
        key_path: gossip_key_path,
        peers_file_path: gossip_dir.join("peers.json"),
        peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
        // Bind the gossip pool on its OWN port, distinct from the mTLS peer-RPC listener below — they
        // are two listeners in one process and both defaulted to 9444, which fails on Linux (#871).
        listen_addr: crate::net::dual_stack_listen_addr(gossip_port_from_env()),
        ..Default::default()
    };
    // Bind the pool to the node's ONE persistent identity across every transport (#1532/#1541).
    apply_persistent_identity(&mut cfg, &identity);
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
    let (relay_status, relay_inbound) = wire_relay_reservation(
        &handle,
        relay_enabled(),
        relay_endpoint.clone(),
        peer_id_hex.clone(),
        network_id_str.clone(),
        gossip_listen_candidates(gossip_port_from_env()),
    );

    // 3. Keep the pool status fresh for `control.peerStatus`: the directly-connected count, the
    //    relay-reachable count (#870), the REAL relay-reservation flag read from the shared
    //    `dig-nat` status (#872) — never the synthetic "relay configured" value it replaced — and
    //    the DISCOVERED-peer count (#2570).
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
                // The DISCOVERED-peer count (#2570), from the same snapshot: dig-gossip's address
                // manager holds every peer this node has been introduced to by any route, which is
                // what makes "connected to nobody while knowing of many" reportable.
                status.set_known_peers(stats.known_addresses as u64);
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
    // The resolved relay socket address, shared by the relayed dialer (Leg B initiator) AND the relay
    // accept loop below (Leg B responder, observability-only remote addr on accepted circuits).
    let relay_socket_addr: Option<std::net::SocketAddr> = if relay_enabled() {
        let ep = relay_endpoint.clone();
        tokio::task::spawn_blocking(move || crate::net::relay_socket_addr(&ep))
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let relayed_dialer: Option<Arc<dyn dig_nat::RelayedDialer>> = relay_socket_addr.map(|addr| {
        Arc::new(dig_nat::ReservationRelayedTransport::new(
            relay_status.clone(),
            addr,
        )) as Arc<dyn dig_nat::RelayedDialer>
    });
    let nat_runtime = Arc::new(crate::net::build_node_nat_runtime(
        peer_port_from_env(),
        reflexive,
        relayed_dialer,
    ));

    // Hand the CONTROL surface everything `control.peers.ping` needs to walk the connection ladder
    // against one peer (dig_ecosystem#1985). It is installed HERE, the moment the NAT runtime exists,
    // rather than assembled on demand: a diagnostic that built its own dialer inputs could disagree
    // with the ones the node really dials with, and then it would be measuring a different ladder
    // than the one operators are asking about. The relayed rung in particular only works because this
    // is the SAME runtime that holds the live relay reservation.
    node.set_peer_ping_context(Arc::new(
        crate::seams::dig_peer::ping::PeerPingContext::new(
            identity.clone(),
            nat_runtime.clone(),
            network_id_str.clone(),
            stun_server,
            crate::dht::default_rpc_timeout(),
        ),
    ));

    // The durable, IPv6-first peer address book (#381): every PEX-learned + otherwise-learned candidate
    // accumulates here (incl. relay-only hints) instead of being dial-and-dropped, seeding future dials.
    // The selector-driven dial ranker (#384) is wired below once the content engine (the shared
    // selector) is up; until then dials keep the book's IPv6-first order.
    let address_book = Arc::new(crate::address_book::AddressBook::default());
    let mut dial_ranker: Option<Arc<dyn crate::pex::DialRanker>> = None;

    let (dht, holdings) = match bring_up_dht(
        &node,
        &identity,
        &nat_runtime,
        &network_id_str,
        &handle,
        &stun_servers,
    )
    .await
    {
        Ok((dht, holdings)) => (Some(dht), holdings),
        Err(e) => {
            tracing::warn!(error = %e, "dig-node DHT bring-up failed; continuing without the DHT");
            status.set_error(format!("dht: {e}"));
            (None, None)
        }
    };

    // RLY-009 (#1935): let the relay ASK this node what its DHT provider store holds, so
    // relay.dig.net/dht can show the network's CONTENT layer. The relay is not a DHT node and holds
    // no records; because a Kademlia node stores records for keys near its OWN peer_id, what this
    // answers describes MANY OTHER peers' content, and the union across connected nodes is a broad
    // slice of the real DHT.
    //
    // Registered only when the DHT is actually up. With no reader the node stays SILENT, which on the
    // wire is indistinguishable from a pre-RLY-009 node — the correct default for a feature that
    // publishes what this node knows about the network.
    //
    // The answer carries COUNTS, never provider identities: a provider record is a
    // (peer_id, content_key) pair, and publishing that linkage is what the relay's /map refuses to do.
    if let Some(dht_handle) = dht.as_ref() {
        let service = dht_handle.service().clone();
        relay_status.set_dht_records_provider(move |max_keys| {
            // The reader is sync but the snapshot is async, so hop onto the runtime. `block_in_place`
            // keeps this off the reservation socket's own poll: the relay's request must never be able
            // to stall the connection this node depends on for its reachability.
            let service = service.clone();
            let snapshot = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async move { service.provider_snapshot(max_keys).await })
            });
            dig_nat::relay::DhtRecordsAnswer {
                records: snapshot
                    .entries
                    .into_iter()
                    .map(|e| dig_nat::wire::DhtRecordEntry {
                        content_key: e.content_key,
                        providers: e.providers,
                    })
                    .collect(),
                total_keys: snapshot.total_keys,
                truncated: snapshot.truncated,
            }
        });
        tracing::info!("dig-node peer network: RLY-009 DHT-record answers enabled");
    }

    // The flood half of #1429, ready for both inventory-change hooks below: present only when the DHT
    // is up AND this node can sign an announcement (the DHT records are the durable fallback if not).
    let holdings_flood = holdings.map(|broadcaster| HoldingsFlood {
        broadcaster,
        pool: handle.clone(),
    });

    // Re-state the node's holdings the first time it sees a connected peer, and on every later
    // return-from-zero (#1734). Without this a node is only ever heard when its inventory CHANGES while
    // a peer happens to be listening: a pin at zero peers — and a restart, whose remembered inventory is
    // seeded from disk before any peer connects — moves the local records and leaves every later
    // reconcile a no-op, so the node holds the content, believes it announced, and is invisible.
    if let Some(flood) = holdings_flood.as_ref() {
        tokio::spawn(crate::seams::dig_peer::holdings::run_first_peer_announcer(
            handle.clone(),
            Arc::new(NodeHoldingsInventory(node.clone()))
                as Arc<dyn crate::seams::dig_peer::holdings::HoldingsInventory>,
            flood.broadcaster.clone(),
        ));
    }

    // 4a. Feed the DHT routing table LIVE from the gossip pool (#1574): bring_up_dht's one-shot
    //     bootstrap runs BEFORE any peer connects, so in a freshly-formed network routing starts empty
    //     and find_providers finds nobody. This forwards every PoolEvent (add → insert, remove →
    //     evict) into routing so cross-node discovery works as the pool fills.
    if let Some(dht) = dht.clone() {
        spawn_dht_routing_feed(dht.clone(), handle.clone());
        // 4a-ii. Publish this node's local inventory into the DHT — in the BACKGROUND, and only now
        //        that routing is being fed from the live pool (#1974). Two reasons for this position:
        //        bring-up must not wait on it (the listener bind is still ahead of us), and every
        //        announce run before the feed exists queries the empty table bootstrap left behind,
        //        so it times out instead of reaching the peers that would store the record.
        crate::dht::spawn_initial_inventory_announce(dht);
    }

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
        // 4b-ii. RESHARE (#1576) — wire the whole-capsule warm so a node that READS content ends up
        //        HOLDING and ANNOUNCING the whole capsule. This is what closes the content-replication
        //        flywheel: without it a reader gets faster while the network's copy count stays flat.
        //
        //        The anchored-root resolver is passed in explicitly and is the pull's ONLY root of trust:
        //        the generation root every assembled module is verified against is resolved from the
        //        CHAIN through it, never from the peer that served the module.
        content.wire_capsule_reshare(
            identity.clone(),
            crate::net::full_nat_config(crate::dht::default_rpc_timeout(), stun_server),
            &network_id_str,
            nat_runtime.clone(),
            crate::ChainSource::anchored_root_resolver_arc(node.as_ref()),
            Arc::new(DhtInventoryAnnouncer {
                node: node.clone(),
                dht: dht.clone(),
                holdings: holdings_flood.clone(),
            }),
            node.cache_dir_path(),
            // Share the node's ONE acquisition gate (#1614): the reshare warm and the §21 backfill leg
            // claim the SAME registry, so a read triggers at most one whole-capsule pull across both.
            node.capsule_acquisition_gate(),
            // The node's tier-aware modules-cache sweep (#2053): a reshare-warm land bounds
            // `<cache>/modules` through the SAME evictor the tier-0 precache loop uses.
            Arc::new(crate::tier0_live::NodeModulesEvictor::new(node.clone())),
        );
        // Anchor the inbound-demand proximity gate (§7.10d, #2014) to this node's own peer_id — the
        // SAME identity the tier-0 loop scores against below — so a peer-driven pull is admitted only
        // for content in this node's keyspace neighbourhood. Set unconditionally (inbound demand runs
        // even when tier-0 is skipped on a small disk).
        node.set_node_peer_id(*identity.peer_id().as_bytes());

        // 4b-iii. TIER-0 EAGER-PRECACHE (#1934, PR-3) — SPAWN the self-driven precache loop so a fleet
        //         node with an empty cache autonomously fills its tier-0 budget from the DHT, becomes a
        //         discoverable provider, and yields to tier-1 under real demand. Wired ONLY when the DHT
        //         is up (it is the sampling + provider source) AND the reshare warmer is installed (the
        //         precache reuses that ONE warmer for chain-anchored, byte-capped, merkle-verified pulls
        //         — never a second fetch/verify path). The chain-anchor gate + hard byte-cap are enforced
        //         inside the loop's fetcher; the small-disk no-op is checked once inside the spawn.
        if let Some(warmer) = content.capsule_warmer().cloned() {
            let probe: Arc<dyn crate::dht_sampling::NeighbourhoodProbe> = Arc::new(
                crate::seams::dig_peer::neighbourhood_probe::DhtNeighbourhoodProbe::new(
                    dht.service().clone(),
                    crate::seams::dig_peer::neighbourhood_probe::MtlsProviderSnapshotClient::new(
                        identity.clone(),
                        crate::net::full_nat_config(crate::dht::default_rpc_timeout(), stun_server),
                        network_id_str.clone(),
                    ),
                ),
            );
            let spawned = crate::tier0_live::spawn_tier0_precache(
                crate::tier0_live::Tier0Runtime::production(
                    node.clone(),
                    dht.service().clone(),
                    probe,
                    warmer,
                    crate::ChainSource::anchored_root_resolver_arc(node.as_ref()),
                    identity.clone(),
                    crate::net::full_nat_config(crate::dht::default_rpc_timeout(), stun_server),
                    &network_id_str,
                    *identity.peer_id().as_bytes(),
                    crate::cache_cap_bytes(),
                ),
            );
            println!(
                "dig-node peer network: tier-0 eager-precache loop {}",
                if spawned {
                    "up"
                } else {
                    "skipped (small-disk)"
                }
            );
        }

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
        let flood_for_hook = holdings_flood.clone();
        node.set_inventory_refresher(Box::new(move || {
            let node = node_for_hook.clone();
            let dht = dht_for_hook.clone();
            let flood = flood_for_hook.clone();
            Box::pin(async move {
                let delta = reconcile_and_flood(&node, &dht, flood.as_ref()).await;
                if !delta.is_empty() {
                    tracing::debug!(
                        announced = delta.gained.len(),
                        retracted = delta.lost.len(),
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
    // Bootstrap dials (#923): a fresh install knows no peers — peer exchange and the DHT can only
    // spread peers this node already has, and a relay reservation only makes this node reachable.
    // Dial the canonical anchors so `connected_peers` has a floor above zero on a node that can
    // reach the internet.
    //
    // SPAWNED, never awaited, and deliberately placed AFTER every other bring-up step: a fresh node
    // must start and keep working with every anchor unreachable. Making this blocking or fallible
    // would turn one host into a single point of failure for every fresh node in the network, which
    // is the opposite of what the anchors are for.
    crate::bootstrap::spawn_bootstrap_dials(
        handle.clone(),
        crate::bootstrap::bootstrap_targets_from_env(),
        stun_server,
    );

    let mut node_responder = NodeResponder::with_pool(node, handle);
    if let Some(dht) = dht {
        node_responder = node_responder.with_dht(dht);
    }
    let responder: Arc<dyn PeerRpcResponder> = Arc::new(node_responder);

    // Leg B responder half (#1532/#1536): drain the introduced relay circuits the reservation surfaces
    // and serve each — over THIS node's persistent identity — exactly like a direct inbound. Wired only
    // when the relay is enabled (else `relay_inbound` is `None`). This runs alongside the direct mTLS
    // listener below so a NAT'd peer that could only reach us over a relay circuit is now ACCEPTED.
    if let Some(inbound) = relay_inbound {
        spawn_relay_accept_loop(
            inbound,
            identity.clone(),
            responder.clone(),
            relay_socket_addr,
        );
    }

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
) -> Result<
    (
        Arc<crate::dht::DhtHandle>,
        Option<Arc<crate::seams::dig_peer::holdings::HoldingsBroadcaster>>,
    ),
    String,
> {
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
    // Kept as `SocketAddr`s first: the SAME advertised set feeds BOTH the DHT provider records and
    // the opcode-222 holdings announcements below, so the two discovery paths can never disagree
    // about where this node serves.
    let advertised: Vec<std::net::SocketAddr> = crate::net::advertised_socket_addrs_with_reflexive(
        port,
        crate::net::advertise_loopback_from_env(),
        reflexive,
    );
    let local_addresses: Vec<CandidateAddr> = advertised
        .iter()
        .map(|sa| CandidateAddr::direct(sa.ip().to_string(), sa.port()))
        .collect();
    let service = Arc::new(DhtService::new(
        node_cert.peer_id(),
        local_addresses,
        config.clone(),
        transport,
    ));

    // Bootstrap from the connected pool (+ relay-introducer peers discovered into it).
    //
    // Uses the SAME `dht_contact_from_pool_addr` the live routing feed uses, so all three paths that
    // publish a pool address into the DHT routing table apply one identical mapping-plus-guard: the
    // port shift (GAP 2) AND the "is this a destination at all" check (#1784). A pool-sourced address
    // that is not dialable — a relay-introducer-discovered peer whose circuit dig-nat reports as
    // `[::]:0` is the case seen in the wild — must never seed a lookup, and bootstrap seeds the very
    // same table the feed does.
    let pool_peers: Vec<([u8; 32], std::net::SocketAddr)> = pool
        .connected_pool_peers()
        .into_iter()
        .filter_map(|(peer_id, addr, _outbound)| {
            // dig-gossip's PeerId is a chia Bytes32; take its raw 32 bytes for the dig-nat PeerId.
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(peer_id.as_ref());
            Some((bytes, dht_contact_from_pool_addr(addr)?))
        })
        .collect();
    let bootstrap = crate::dht::bootstrap_peers_from_pool(&pool_peers);
    if let Err(e) = service.bootstrap(&bootstrap).await {
        // A failed bootstrap (no peers yet) is not fatal: local provider records still stand and the
        // maintenance loop re-attempts the PUT as the pool fills. Log + carry on.
        tracing::debug!(error = %e, "DHT bootstrap found no peers yet; records republish once the pool fills");
    }

    // Derive the node's CURRENT inventory and the content ids it provides, and record them on the
    // handle so every later reconcile diffs against the truth from the first moment.
    //
    // The ANNOUNCE itself — one Kademlia lookup + PUT per id, each RPC bounded by the DHT timeout —
    // is deliberately NOT run here. Awaiting it on the bring-up path is what left the mTLS peer-RPC
    // listener (bound near the end of `run_peer_network`) unbound for 12m40s on a node holding 44
    // capsules: undialable and undiscoverable, yet holding a relay reservation that advertised it as
    // up, and logging nothing for the whole window (dig_ecosystem#1974). The caller starts it in the
    // background via `spawn_initial_inventory_announce` once the pool→routing feed is live.
    let cached = node.cache_list_cached().await;
    let initial_ids = crate::dht::inventory_content_ids(&cached);
    println!(
        "dig-node peer network: DHT up — {} content id(s) to announce for local inventory",
        initial_ids.len()
    );

    let dht = crate::dht::DhtHandle::new(service, initial_ids);

    // The real-time holdings layer (#1429): flood a signed opcode-222 announcement whenever this
    // node's inventory changes, and fold every peer's verified announcement into our provider set.
    //
    // Signed by the node's OWN NodeCert leaf, because the wire derives `provider_peer_id` from the
    // signing key's SPKI — announcing under any other key would name an identity no peer can dial.
    // Advertising the SAME `local_addresses` the DHT records carry keeps the two discovery paths in
    // agreement about where this node serves.
    let holdings = match crate::seams::dig_peer::holdings::signer_from_node_cert(node_cert) {
        Ok(signer) => {
            let addresses = advertised
                .iter()
                .map(|sa| dig_gossip::CandidateAddr {
                    host: sa.ip().to_string(),
                    port: sa.port(),
                })
                .collect();
            // Seeded from the wall clock so a restart resumes ABOVE any seq peers already remember
            // (a from-zero restart would have its announcements dropped as replays until it caught
            // up). Persisting the counter is #1477's durable-state work.
            let broadcaster = Arc::new(crate::seams::dig_peer::holdings::HoldingsBroadcaster::new(
                signer,
                addresses,
                crate::seams::dig_peer::holdings::now_unix_secs(),
            ));
            match pool.inbound_receiver() {
                Ok(_) if !crate::seams::dig_peer::holdings::HoldingsIngress::ingest_enabled_from_env() => {
                    // Operator kill switch: keep ANNOUNCING (so this node stays discoverable in real
                    // time) but stop applying peers' announcements. Discovery falls back to the
                    // durable DHT records, which is a degradation, not an outage.
                    println!(
                        "dig-node peer network: holdings ingest DISABLED by \
                         DIG_HOLDINGS_INGEST; still announcing"
                    );
                }
                Ok(inbound) => {
                    let ingress = Arc::new(crate::seams::dig_peer::holdings::HoldingsIngress::new(
                        node_cert.peer_id().to_hex(),
                    ));
                    let sink = Arc::clone(dht.service());
                    tokio::spawn(crate::seams::dig_peer::holdings::run_holdings_ingest(
                        inbound, ingress, sink,
                    ));
                    println!("dig-node peer network: holdings announce (opcode 222) up");
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "holdings announce: no inbound receiver; this node still ANNOUNCES but will not \
                     ingest peers' announcements (DHT find_providers remains the fallback)"
                ),
            }
            Some(broadcaster)
        }
        Err(e) => {
            // Announce-only degradation, never fatal: without a signer this node stays discoverable
            // through the durable DHT provider records, just not in real time.
            tracing::warn!(error = %e, "holdings announce disabled: node cert leaf is not signable");
            None
        }
    };

    // Store-melt propagation (#1316, custody-critical): a SECOND inbound receiver drives the
    // receive → on-chain-verify → delete → rebroadcast-once handler (piece #3), and a holder watch
    // loop deletes + announces THIS node's own on-chain-melted stores (piece #4). Both share ONE
    // tombstone, so each store is propagated at most once and the epidemic quiesces. Every delete is
    // fail-closed on the chain (NC-9): a forged/replayed announcement or an unreachable chain deletes
    // nothing (see `store_melted`).
    //
    // Both loops are behind ONE operator kill switch (`DIG_NODE_STORE_MELT`, default ON). This is the
    // node's only path that irreversibly deletes content in response to chain state, and it
    // propagates — so an operator who suspects a fault needs to stop the deleting without downgrading
    // the node. Off means melted stores keep costing disk; nothing else depends on this having run.
    if !crate::seams::dig_peer::store_melted::store_melt_enabled() {
        println!(
            "dig-node peer network: store-melt propagation DISABLED (DIG_NODE_STORE_MELT) — this \
             node will not delete or relay melted stores"
        );
    } else {
        use crate::seams::dig_peer::store_melted as melt;
        let tombstone = melt::TombstoneSet::new();
        let chain: Arc<dyn melt::MeltChain> = Arc::new(melt::CoinsetMeltChain::new());
        let cache: Arc<dyn melt::MeltCache> = Arc::new(Arc::clone(node));
        let broadcaster: Arc<dyn melt::MeltBroadcast> = Arc::new(pool.clone());
        match pool.inbound_receiver() {
            Ok(inbound) => {
                tokio::spawn(melt::run_store_melted_ingest(
                    inbound,
                    Arc::clone(&chain),
                    Arc::clone(&cache),
                    Arc::clone(&broadcaster),
                    tombstone.clone(),
                ));
                println!("dig-node peer network: store-melt propagation (opcode 221) up");
            }
            Err(e) => tracing::warn!(
                error = %e,
                "store-melt ingest: no inbound receiver; this node still deletes + announces its OWN \
                 melted stores, but will not relay peers' melts"
            ),
        }
        // The holder watch: periodically re-check every held store's singleton and, on a stable
        // on-chain melt, delete + announce once. Signs with the node's identity; a node that cannot
        // sign still deletes on the receive path, it just cannot originate a melt announcement.
        match melt::signer_from_node(node) {
            Some(signer) => {
                let interval = crate::chainwatch::watch_interval_from_env();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        ticker.tick().await;
                        // A panic inside one tick is CONTAINED (#2067) so the watch survives to the
                        // next tick instead of silently dying for the process's lifetime. `tick()`
                        // stays outside the guard, so a persistently-panicking tick paces on the
                        // interval rather than hot-spinning. Abandoning a tick is fail-closed: the
                        // store is not tombstoned, so the next tick re-evaluates it from scratch.
                        //
                        // `melt_height` is an advisory hint only (receivers verify on-chain, never
                        // trust it); 0 is a safe placeholder until a peak observer feeds a real height.
                        let _ = crate::shared::catch_iteration(
                            "store_melt_holder_watch",
                            melt::run_melt_tick(
                                &*chain,
                                &*cache,
                                &*broadcaster,
                                &tombstone,
                                &signer,
                                0,
                            ),
                        )
                        .await;
                    }
                });
                println!("dig-node peer network: store-melt holder watch up");
            }
            None => tracing::warn!(
                "store-melt holder watch disabled: no signable node identity (receive path still deletes)"
            ),
        }
    }

    // Profile-body sync (epic #3008, W6): a THIRD inbound receiver drives the 223 announce ->
    // chain-confirm -> 224 request -> 225 accept -> persist -> re-announce exchange, and answers
    // peers' 224 requests from disk within an outbound budget.
    //
    // Wired exactly like holdings and store-melt above: one `inbound_receiver()`, one spawned task.
    // Bodies land in `<cache>/profiles/`, deliberately OUTSIDE `<cache>/modules/`, so
    // `refresh_inventory` never turns a profile into a DHT provider record.
    //
    // Behind ONE operator kill switch (`DIG_NODE_PROFILE_SYNC`, default ON). Off means profiles
    // stop syncing and nothing else changes -- a clean degradation, not an outage.
    if !crate::seams::dig_peer::profile_sync::profile_sync_enabled() {
        println!(
            "dig-node peer network: profile-body sync DISABLED (DIG_NODE_PROFILE_SYNC) -- this node will neither fetch nor serve profile bodies"
        );
    } else {
        match pool.inbound_receiver() {
            Ok(inbound) => {
                use crate::ChainSource as _;
                let ctx = crate::seams::dig_peer::profile_sync::context_from_node(
                    node.cache_dir_path().to_path_buf(),
                    node.anchored_root_resolver_arc(),
                    pool.clone(),
                );
                // The re-announce loop is what lets this exchange START. `accept_body`'s follow-on
                // announce only ever fires for a body ingested FROM a peer, so without this a node
                // holding a body from the control plane (or from before its peers connected) would
                // hold it silently and no peer could ever learn the root to ask for.
                tokio::spawn(
                    crate::seams::dig_peer::profile_sync::run_profile_announce_loop(
                        ctx.store.clone(),
                        ctx.transport.clone(),
                        crate::seams::dig_peer::profile_sync::ANNOUNCE_INTERVAL,
                    ),
                );
                tokio::spawn(
                    crate::seams::dig_peer::profile_sync::run_profile_sync_ingest(inbound, ctx),
                );
                println!("dig-node peer network: profile-body sync (opcodes 223/224/225) up");
            }
            Err(e) => tracing::warn!(
                error = %e,
                "profile-body sync: no inbound receiver; this node holds and serves profile bodies through the control plane only"
            ),
        }
    }

    // Spawn the maintenance loop: republish (records never lapse) + refresh buckets + gc, well inside
    // the provider TTL.
    {
        let dht = dht.clone();
        let interval = config.republish_interval;
        tokio::spawn(async move {
            crate::dht::run_maintenance(dht, interval).await;
        });
    }

    Ok((dht, holdings))
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
pub(crate) mod tests {
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

    /// **A known-peer count nobody has taken is `null`, never `0` (dig_ecosystem#2570).**
    ///
    /// The snapshot must be able to say "I have not looked" — a node whose pool loop has not yet
    /// sampled its address book has an UNKNOWN known-peer count, and reporting `0` there would
    /// claim it looked and found nothing. The fixture marks the node RUNNING before asserting,
    /// because running-with-no-sample-yet is the state a zero-default would silently mislabel; on a
    /// not-running node the control layer suppresses the count anyway, so that case could not tell
    /// a defaulted zero from a suppressed one.
    #[test]
    fn an_unsampled_known_peer_count_is_null_not_zero() {
        let s = PeerStatus::new();
        s.set_running("ab".repeat(32));
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(
            v["known_peers"],
            Value::Null,
            "a count never sampled is unknown; a zero would assert an empty address book"
        );
        s.set_known_peers(0);
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(
            v["known_peers"], 0,
            "an OBSERVED zero must be reported as a zero, distinctly from never having looked"
        );
    }

    /// **The known-peer count is a SEPARATE observation from the connected count (#2570).**
    ///
    /// The field exists to express "knows of peers, connected to none", so the nearest wrong
    /// implementation — sourcing it from the connected-pool size — must be visible. The fixture
    /// drives the two to DIFFERENT values through their two setters, keeping `connected_peers` at
    /// zero: an aliased implementation reports `0` known here and fails, while a fixture that set
    /// both to the same number could not tell the two apart at all.
    #[test]
    fn knowing_of_peers_while_connected_to_none_survives_the_snapshot() {
        let s = PeerStatus::new();
        s.set_running("ab".repeat(32));
        s.set_pool(0, 7, true);
        s.set_known_peers(41);
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID, TEST_GENESIS_HEX);
        assert_eq!(v["connected_peers"], 0, "connected to nobody");
        assert_eq!(v["known_peers"], 41, "while knowing of 41");
        assert_eq!(
            v["relay"]["peer_count"], 7,
            "and the RELAY's own view stays its own number, distinct from both"
        );
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

    // #1575 GAP 2 regression: the DHT routing candidate derived from a pool/PoolEvent addr must use
    // the peer's DHT/peer-RPC port (9444), NOT the gossip port (9445) the pool reports. On the old
    // build the gossip addr was fed straight into routing, so every DHT dial hit the gossip listener
    // and failed with `InvalidContentType`. This would FAIL on that build (it would keep 9445).
    #[test]
    fn dht_candidate_from_pool_addr_uses_dht_port_not_gossip_port() {
        let gossip: std::net::SocketAddr = "203.0.113.7:9445".parse().unwrap();
        let dht = dht_addr_from_gossip_addr(gossip);
        assert_eq!(
            dht.port(),
            9444,
            "DHT candidate must use the 9444 DHT port, not 9445 gossip"
        );
        assert_eq!(
            dht.ip(),
            gossip.ip(),
            "only the port shifts; the IP is preserved"
        );
        // IPv6 (ecosystem IPv6-first) maps identically.
        let gossip6: std::net::SocketAddr = "[2001:db8::1]:9445".parse().unwrap();
        assert_eq!(dht_addr_from_gossip_addr(gossip6).port(), 9444);
        // The offset is the single source of truth, so a custom gossip port maps consistently.
        let custom: std::net::SocketAddr = "203.0.113.7:19445".parse().unwrap();
        assert_eq!(
            dht_addr_from_gossip_addr(custom).port(),
            19445 - GOSSIP_TO_DHT_PORT_OFFSET
        );
    }

    // #1590 / #836 read-leg DATA gate: the selector-registry/pool feed seeds the download-side
    // connected pool from gossip `PoolEvent`s, which carry the peer's GOSSIP addr (:9445). If that raw
    // addr enters the pool, the `PoolProviderLocator` offers a :9445 candidate and the Tier-2
    // fetchRange dials the gossip listener → `InvalidContentType` → the read 404s despite a connected
    // holder (the SAME class of bug #1575 fixed for the DHT routing feed). This drives the REAL live
    // feed translation (`map_gossip_pool_event` → `on_pool_event`) and asserts the resulting locator
    // candidate carries the peer-RPC port (:9444). It FAILS on the pre-fix build (candidate = :9445).
    #[tokio::test]
    async fn selector_pool_feed_candidate_uses_peer_rpc_port_not_gossip_port() {
        use dig_download::testkit::{MockContent, MockProviderLocator, MockRangeTransport};
        use dig_download::ProviderLocator;

        let td = tempfile::tempdir().unwrap();
        // A NodeContent with a real connected pool + PoolProviderLocator wiring (DHT locator empty:
        // the connected pool is the only source, exactly the relayed/isolated-net DATA condition).
        let pc = crate::download::NodeContent::new(
            std::sync::Arc::new(MockProviderLocator::fixed(vec![])),
            std::sync::Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            crate::download::MissMode::FetchThrough,
            None,
            td.path(),
        );

        // A gossip `PoolEvent` reports the peer's GOSSIP endpoint (:9445) — drive it through the REAL
        // live-feed translation the selector-registry feed uses, NOT a hand-built :9444 pool entry (the
        // #1590 test's miss). `map_gossip_pool_event` is the feed's per-event boundary translation.
        let peer_id = dig_gossip::PeerId::from([7u8; 32]);
        let gossip_addr: std::net::SocketAddr = "203.0.113.9:9445".parse().unwrap();
        let selector_event = map_gossip_pool_event(&dig_gossip::PoolEvent::PeerAdded {
            peer_id,
            addr: gossip_addr,
        });
        pc.on_pool_event(&selector_event);

        // The download-side locator candidate for a resource MUST carry the peer-RPC port (:9444).
        let locator = crate::seams::dig_peer::PoolProviderLocator::new(pc.connected_pool());
        let content = dig_dht::ContentId::resource([9u8; 32], [8u8; 32], [7u8; 32]);
        let found = locator.find_providers(&content).await.expect("locate ok");

        assert_eq!(
            found.len(),
            1,
            "the fed pool peer is offered as a candidate"
        );
        let candidate = &found[0].addresses[0];
        assert_eq!(
            candidate.port, DEFAULT_P2P_PORT,
            "the pool candidate must dial the peer-RPC port (:9444), not the gossip port (:9445)"
        );
        assert_eq!(
            candidate.host,
            gossip_addr.ip().to_string(),
            "only the port is translated; the host is preserved"
        );
    }

    // #871: both listeners bind cleanly when given distinct ports — the fix. Binds the mTLS peer-RPC
    // dual-stack listener and starts a gossip pool on a DIFFERENT port, exactly as `run_peer_network`
    // does; both must succeed (on the old shared-9444 build the second bind fails on Linux).
    #[tokio::test]
    async fn gossip_pool_and_peer_rpc_bind_together_on_distinct_ports() {
        // The mTLS peer-RPC listener on an OS-assigned ephemeral port (dual-stack `[::]:0` where this
        // host's kernel supports IPv6 at all, else the IPv4 loopback fallback — this test proves two
        // DISTINCT ports bind without clashing, not dual-stack transport itself).
        let bind_addr = fresh_pool_listen_addr().await;
        let peer_rpc = crate::net::bind_tcp_dual_stack(bind_addr)
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
            listen_addr: fresh_pool_listen_addr().await,
            ..Default::default()
        };
        let service = dig_gossip::GossipService::new(cfg).expect("gossip config");
        let handle = service.start().await.expect("gossip start must succeed");

        // Both listeners are up simultaneously — no port clash.
        assert!(peer_port != 0);
        let _ = handle.pool_stats();
    }

    /// #923: a node whose bootstrap anchors are ALL unreachable still starts and still works.
    ///
    /// This is the property that matters most about the bootstrap set, because getting it wrong is
    /// invisible in the happy path and catastrophic in aggregate: if bring-up awaited or failed on an
    /// anchor dial, one unreachable host would become a single point of failure for every fresh node
    /// in the network — the exact opposite of what an anchor is for.
    ///
    /// # Why the fixture is an UNROUTABLE address and not a closed local port
    ///
    /// The nearest wrong implementation is awaiting the dial instead of spawning it. A closed
    /// loopback port cannot see that: the kernel refuses instantly, so awaited and spawned both
    /// return in microseconds and the test passes either way. `203.0.113.0/24` (RFC 5737 TEST-NET-3)
    /// is not routable, so a dial to it HANGS until the module's own 10s `BOOTSTRAP_DIAL_TIMEOUT`.
    /// That turns the distinction into a wall-clock one this test can actually observe, which is why
    /// the elapsed budget below is well under that timeout rather than merely "fast".
    ///
    /// # Why the anchor is well-formed
    ///
    /// A malformed entry would be dropped by the parser and never dialled at all, so the test would
    /// assert survival of an event that never happened. The identity is valid 64-hex and the
    /// authority parses; the ONLY thing wrong with this anchor is that nothing answers there.
    #[tokio::test]
    async fn a_node_survives_every_bootstrap_anchor_being_unreachable() {
        let dir = std::env::temp_dir().join(format!("dig-node-bootstrap-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg = dig_gossip::GossipConfig {
            network_id: chia_protocol::Bytes32::new([3u8; 32]),
            cert_path: dir.join("node.cert").display().to_string(),
            key_path: dir.join("node.key").display().to_string(),
            peers_file_path: dir.join("peers.json"),
            peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
            listen_addr: fresh_pool_listen_addr().await,
            ..Default::default()
        };
        let handle = dig_gossip::GossipService::new(cfg)
            .expect("gossip config")
            .start()
            .await
            .expect("gossip start");

        let unreachable = crate::bootstrap::resolve_bootstrap_targets(Some(&format!(
            "{}@203.0.113.1:9444,{}@203.0.113.2:9444",
            "a".repeat(64),
            "b".repeat(64)
        )));
        assert_eq!(
            unreachable.len(),
            2,
            "the fixture must actually produce anchors to dial, else survival is vacuous"
        );

        let started = std::time::Instant::now();
        crate::bootstrap::spawn_bootstrap_dials(handle.clone(), unreachable, None);
        let elapsed = started.elapsed();

        // Bring-up did not wait on the network. An awaited dial would sit here for the full 10s
        // BOOTSTRAP_DIAL_TIMEOUT per anchor before returning.
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "bring-up blocked on an unreachable anchor for {elapsed:?}"
        );

        // ...and the node is still a working node afterwards: the pool is queryable and the service
        // is still running. Asserted AFTER a pause long enough for the dial tasks to have failed and
        // logged, so this observes the post-failure state rather than a state that merely predates it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = handle.pool_stats();
        assert!(
            handle.health_check().await.is_ok(),
            "the node must still be healthy after every bootstrap anchor failed"
        );
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
            listen_addr: fresh_pool_listen_addr().await,
            ..Default::default()
        };
        let handle = dig_gossip::GossipService::new(cfg)
            .expect("gossip config")
            .start()
            .await
            .expect("gossip start");

        // Wire with the relay DISABLED so no real socket is opened; we drive the shared status by hand.
        let (status, inbound) = wire_relay_reservation(
            &handle,
            false,
            DEFAULT_RELAY_URL.to_string(),
            "ab".repeat(32),
            DEFAULT_NETWORK_ID.to_string(),
            gossip_listen_candidates(0),
        );
        // Relay disabled → no accept path is enabled (no reservation, so no inbound circuits).
        assert!(inbound.is_none());

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

    /// Build a `NatPeerConnection` over a loopback duplex with a chosen `peer_id`, remote address and
    /// traversal tier, so the node's adoption path can be exercised WITHOUT a real network (a real
    /// yamux session, just not over TLS). The returned [`dig_nat::PeerSession`] is the SERVER half:
    /// hold it to keep the session live, **drop it to kill the session** — which is how the test below
    /// makes a relay circuit genuinely dead rather than merely asserting about one.
    fn loopback_nat_conn(
        peer_id_bytes: [u8; 32],
        remote: std::net::SocketAddr,
        method: dig_nat::TraversalKind,
    ) -> (dig_gossip::NatPeerConnection, dig_nat::PeerSession) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let inner = dig_nat::PeerConnection {
            peer_id: dig_nat::PeerId::from_bytes(peer_id_bytes),
            method,
            remote_addr: remote,
            peer_bls_pub: None,
            session: dig_nat::PeerSession::client(client_io),
        };
        (
            dig_gossip::NatPeerConnection::new(inner),
            dig_nat::PeerSession::server(server_io),
        )
    }

    /// **dig_ecosystem#1771 — the supersession the dig-gossip v0.17.12 bump delivers is reachable from
    /// the node, and the node's own peer views report the re-adopted peer ONCE.**
    ///
    /// `adopt_nat_connection` is the single path every dig-nat connection is adopted through. Before
    /// v0.17.12 it refused a held slot outright, so a relay circuit that registered a slot and then
    /// died refused the DIRECT adoption that would have worked — the node reported `duplicate
    /// connection` while the peer reported zero connections (#1762, with #1691 inbound and #1703
    /// `connect_to` the two siblings). This test pins the property from the node's side: a stale
    /// RELAYED adoption followed by a DIRECT adoption of the SAME `peer_id` succeeds, and the two
    /// surfaces the node derives from the pool — [`pool_stats_json`] and [`connected_peers_json`] —
    /// each report exactly one peer, at the NEWEST address, over the NEWEST tier.
    ///
    /// Fixture design: only ONE actor varies (the tier + address of the same identity), and the second
    /// peer is a truthful control proving the surfaces can still count to two — a test that only
    /// asserted "1" would pass against a pool that had silently dropped the peer entirely. The `via`
    /// assertion is what distinguishes a genuine supersede from a guard that returns `Ok` while
    /// leaving the dead relayed slot in place, and every assertion is on observable pool state rather
    /// than a log line, which prints on the broken path too.
    #[tokio::test]
    async fn a_stale_relayed_slot_does_not_refuse_the_direct_adoption() {
        let handle = fresh_pool_handle("readopt-supersede", [11u8; 32]).await;
        let peer = [0xAB; 32];

        // A relayed adoption lands first, then its session DIES (the server half is dropped) — the
        // #1761 dead-circuit condition, with no reap to notice it.
        let (relayed, relayed_server) = loopback_nat_conn(
            peer,
            "203.0.113.7:9445".parse().unwrap(),
            dig_nat::TraversalKind::Relayed,
        );
        handle
            .adopt_nat_connection(relayed)
            .await
            .expect("the first adoption is uncontested");
        drop(relayed_server);

        // The direct dial that the pre-0.17.12 pool refused.
        let (direct, _direct_server) = loopback_nat_conn(
            peer,
            "203.0.113.7:9444".parse().unwrap(),
            dig_nat::TraversalKind::Direct,
        );
        let adopted = handle
            .adopt_nat_connection(direct)
            .await
            .expect("a stale slot must not refuse a newer verified session for the same identity");
        assert_eq!(adopted, dig_gossip::PeerId::from(peer));

        // The node's operator view: ONE peer, not two — the supersede replaced the slot.
        let stats = pool_stats_json(&handle);
        assert_eq!(stats["connected"], 1, "one identity holds one slot");

        // The node's per-peer view: the NEWEST session's address and tier, proving the dead relayed
        // slot was replaced rather than merely tolerated.
        let peers = connected_peers_json(&handle);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["address"], "203.0.113.7:9444");
        assert_eq!(peers[0]["via"], "direct");

        // Control: a genuinely DIFFERENT identity still occupies its own slot, so the assertions above
        // pin supersession and not a pool that quietly stopped admitting peers.
        let (other, _other_server) = loopback_nat_conn(
            [0xCD; 32],
            // A DIFFERENT /16: the outbound INT-006 diversity cap allows one outbound connection per
            // /16 group, so a control peer in 203.0.113.0/16 would be filtered for the wrong reason.
            "198.51.100.8:9444".parse().unwrap(),
            dig_nat::TraversalKind::Direct,
        );
        handle
            .adopt_nat_connection(other)
            .await
            .expect("a net-new identity is admitted");
        assert_eq!(pool_stats_json(&handle)["connected"], 2);
    }

    /// **#1771 — the node must not COUNT a re-adopted peer twice.** v0.17.12 republishes
    /// `PoolEvent::PeerAdded` on a supersede, so any consumer treating each `PeerAdded` as a distinct
    /// peer over-counts under reconnect churn. The node's download-side feed keys candidates by
    /// `peer_id`, so a second `PeerAdded` for the same identity UPSERTS: one candidate, at the newest
    /// address. The second identity is the control that proves the feed still counts distinct peers.
    #[tokio::test]
    async fn the_selector_pool_feed_upserts_a_readopted_peer_instead_of_counting_it_twice() {
        use dig_download::testkit::{MockContent, MockProviderLocator, MockRangeTransport};
        use dig_download::ProviderLocator;

        let td = tempfile::tempdir().unwrap();
        let pc = crate::download::NodeContent::new(
            std::sync::Arc::new(MockProviderLocator::fixed(vec![])),
            std::sync::Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            crate::download::MissMode::FetchThrough,
            None,
            td.path(),
        );
        let peer_id = dig_gossip::PeerId::from([0xAB; 32]);

        // The relayed adoption's PeerAdded, then the supersede's republished PeerAdded for the SAME
        // identity at a new address — driven through the real live-feed translation.
        for host in ["203.0.113.7", "203.0.113.70"] {
            pc.on_pool_event(&map_gossip_pool_event(&dig_gossip::PoolEvent::PeerAdded {
                peer_id,
                addr: format!("{host}:9445").parse().unwrap(),
            }));
        }

        let locator = crate::seams::dig_peer::PoolProviderLocator::new(pc.connected_pool());
        let content = dig_dht::ContentId::resource([9u8; 32], [8u8; 32], [7u8; 32]);
        let found = locator.find_providers(&content).await.expect("locate ok");
        assert_eq!(
            found.len(),
            1,
            "a re-adopted peer is ONE candidate, not two (PeerAdded upserts by peer_id)"
        );
        assert_eq!(
            found[0].addresses[0].host, "203.0.113.70",
            "the upsert carries the newest session's address"
        );

        // Control: a distinct identity is a distinct candidate.
        pc.on_pool_event(&map_gossip_pool_event(&dig_gossip::PoolEvent::PeerAdded {
            peer_id: dig_gossip::PeerId::from([0xCD; 32]),
            addr: "198.51.100.8:9445".parse().unwrap(),
        }));
        let found = locator.find_providers(&content).await.expect("locate ok");
        assert_eq!(found.len(), 2, "two identities are two candidates");
    }

    /// #1784, DHT-routing half: the routing feed does NOT pass through the connected pool, so it
    /// needs its own guard. A pool address that is not a destination yields no contact at all.
    ///
    /// `[::]:9446` and `203.0.113.7:9446` distinguish the two independent reasons an address can be
    /// unusable — a wildcard IP, and a port that becomes 0 only AFTER the gossip→DHT shift — and the
    /// latter is what proves the check runs on the MAPPED address: `203.0.113.7:1` looks perfectly
    /// dialable until the offset is applied.
    #[test]
    fn a_wildcard_or_unshiftable_pool_address_yields_no_dht_contact() {
        for junk in ["[::]:9446", "0.0.0.0:9446", "203.0.113.7:1", "[::]:0"] {
            let addr: std::net::SocketAddr = junk.parse().unwrap();
            assert_eq!(
                dht_contact_from_pool_addr(addr),
                None,
                "{junk} must not become a routing-table contact"
            );
        }
    }

    /// The control for the guard above: a real gossip address still yields the peer's DHT contact,
    /// with the port SHIFTED — so the guard cannot be satisfied by returning the raw address, and
    /// cannot be satisfied by rejecting everything.
    #[test]
    fn a_real_pool_address_yields_the_shifted_dht_contact() {
        let gossip: std::net::SocketAddr = "203.0.113.7:9445".parse().unwrap();
        let contact = dht_contact_from_pool_addr(gossip).expect("a real address is a contact");
        assert_eq!(contact.ip(), gossip.ip());
        assert_eq!(
            contact.port(),
            9445 - GOSSIP_TO_DHT_PORT_OFFSET,
            "routing stores the peer's DHT/peer-RPC port, not its gossip port (#1575 GAP 2)"
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

    /// Whether the host has a usable IPv6 loopback stack. Some sandboxes disable IPv6 entirely at the
    /// kernel level (`[::1]:0` fails with `EAFNOSUPPORT`, not merely a refused bind), in which case no
    /// `[::1]` dial or `[::]` listen can be exercised; callers that specifically assert dual-stack/IPv6
    /// behaviour skip cleanly rather than reporting a false failure unrelated to this crate's logic
    /// (mirrors dig-gossip's CON-002 guard). On any host where IPv6 loopback DOES work — every CI
    /// runner — this returns `true` and every caller runs its full assertion, unweakened.
    pub(crate) async fn is_ipv6_loopback_available() -> bool {
        tokio::net::TcpListener::bind("[::1]:0").await.is_ok()
    }

    /// The listen address the pool-handle test fixtures bind: the production-shaped dual-stack
    /// unspecified address (`[::]:0`, §5.2 IPv6-first) on a host with a working IPv6 stack, falling
    /// back to an IPv4 loopback bind (`127.0.0.1:0`) on a host where IPv6 is unavailable entirely.
    /// These fixtures back tests that assert pool/connect/disconnect semantics, not dual-stack
    /// transport itself, so a real bound listener on either family satisfies them fully — no skip
    /// needed here (dual-stack transport itself is proven separately, where it IS the point: see
    /// `crate::net::tests::dual_stack_bind_accepts_an_ipv4_loopback_client`).
    async fn fresh_pool_listen_addr() -> std::net::SocketAddr {
        if is_ipv6_loopback_available().await {
            crate::net::dual_stack_listen_addr(0)
        } else {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
        }
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
        if !is_ipv6_loopback_available().await {
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
    pub(crate) async fn fresh_pool_handle(
        tag: &str,
        network: [u8; 32],
    ) -> dig_gossip::GossipHandle {
        fresh_pool_handle_on(tag, network, fresh_pool_listen_addr().await).await
    }

    /// Build a freshly-started `GossipHandle` bound on an explicit `listen_addr`.
    ///
    /// The two-node loopback proof binds its LISTENER on a CONCRETE IPv6 loopback (`[::1]:0`) rather
    /// than the unspecified dual-stack `[::]:0`: on Windows a `[::]`-unspecified bind does not accept
    /// inbound loopback connections into the pool (the native-tls dual-stack accept quirk — the same
    /// family of `[::]`-v6only issue tracked for the extension-offline path), whereas a concrete
    /// loopback bind does, on every platform. Production still binds dual-stack `[::]` (`run_peer_network`).
    pub(crate) async fn fresh_pool_handle_on(
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

    /// **Proves (#2022):** the store-granularity `roots` list is ordered CANONICALLY (by root hex),
    /// NEVER by `last_used_unix_ms`. The response order must NOT vary with access recency, so the
    /// permissionless peer surface leaks no read-recency ranking of the operator's interests.
    /// **Catches:** any reintroduction of an access-time sort — the two cases below have IDENTICAL
    /// roots but INVERTED `last_used` stamps, and both must yield the same canonical order.
    #[test]
    fn availability_store_granularity_orders_roots_canonically_not_by_access_time() {
        let store = "aa".repeat(32);
        let expected = vec![
            json!("11".repeat(32)),
            json!("22".repeat(32)),
            json!("33".repeat(32)),
        ];

        // last_used stamps ascending with root hex.
        let cached_a = vec![
            cap(&store, &"11".repeat(32), 10, 100),
            cap(&store, &"22".repeat(32), 10, 200),
            cap(&store, &"33".repeat(32), 10, 300),
        ];
        // last_used stamps INVERTED vs root hex — a recency sort would flip the order.
        let cached_b = vec![
            cap(&store, &"11".repeat(32), 10, 300),
            cap(&store, &"22".repeat(32), 10, 200),
            cap(&store, &"33".repeat(32), 10, 100),
        ];

        for cached in [cached_a, cached_b] {
            let a = availability_presence(&cached, &store, None, None, false);
            assert_eq!(a["available"], true);
            assert_eq!(
                a["roots"].as_array().unwrap(),
                &expected,
                "roots must be canonically ordered regardless of last_used_unix_ms"
            );
        }
    }

    #[test]
    fn availability_store_granularity_unavailable_when_no_roots() {
        let a = availability_presence(&[], &"aa".repeat(32), None, None, false);
        assert_eq!(a["available"], false);
        assert_eq!(a["roots"], json!([]));
    }

    #[test]
    fn availability_root_granularity_answers_from_the_servable_flag_not_the_snapshot() {
        // #1592: at root granularity the answer is the caller's SERVABLE-on-disk check, so it agrees
        // with what a `fetchRange` would serve even when the inventory snapshot disagrees.
        let store = "aa".repeat(32);
        let root = "11".repeat(32);
        let stale_says_held = vec![cap(&store, &root, 10, 1)];

        // Servable → available, whatever the snapshot says (here it predates the capsule).
        let held = availability_presence(&[], &store, Some(&root), None, true);
        assert_eq!(held["available"], true, "servable on disk → available");

        // Not servable → not available, even though the (post-eviction stale) snapshot lists it.
        let miss = availability_presence(&stale_says_held, &store, Some(&root), None, false);
        assert_eq!(miss["available"], false, "not servable → not available");
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

    #[test]
    fn gossip_listener_presents_the_advertised_peer_id() {
        // #1532 regression — NODE IDENTITY SPLIT. The dig-gossip pool's inbound TLS listener loads
        // its cert/key from `gossip_identity_paths`, and it MUST present the SAME identity the node
        // advertises/registers/pins (the persistent NodeCert). If the pool listener's leaf hashed to
        // a DIFFERENT peer_id than the advertised one, every dial to this node fails closed with
        // `peer_id mismatch: expected <advertised>, got <gossip-cert>` — exactly the Leg B failure.
        //
        // Prove the invariant end-to-end the way the pool loads it: mint the NodeCert into its dir,
        // then reload the identity from the EXACT files `gossip_identity_paths` returns and confirm
        // the reloaded peer_id equals the advertised one.
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = load_or_generate_node_cert(dir.path(), &node_seed("1532-identity-split"))
            .expect("mint node cert");

        let (cert_path, key_path) = gossip_identity_paths(dir.path());
        let cert_pem = std::fs::read_to_string(&cert_path)
            .expect("the gossip pool loads its cert from the NodeCert file");
        let key_pem = std::fs::read_to_string(&key_path)
            .expect("the gossip pool loads its key from the NodeCert file");
        let listener_identity =
            dig_tls::NodeCert::from_pem(&cert_pem, &key_pem).expect("reload the listener identity");

        assert_eq!(
            listener_identity.peer_id().to_hex(),
            identity.peer_id().to_hex(),
            "the gossip pool listener must present the node's ADVERTISED peer_id (#1532)"
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
        async fn handle_json_rpc(&self, req: Value, _conn_key: &str) -> Value {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            json!({"jsonrpc":"2.0","id":id,"result":{"echo_method": method}})
        }
        async fn handle_availability(&self, items: Value, _conn_key: &str) -> Value {
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

    /// **Proves:** the dig-nat MUX availability shape — which has NO hop counter — forwards NOTHING,
    /// and that the same node with a readable budget DOES forward.
    ///
    /// **Catches a deleted MUST becoming a live defect.** `dig_nat::mux::AvailabilityRequest` carries
    /// no field that could hold a hop count, so a recursion started from it could not be bounded by
    /// anything. `handle_availability` therefore declares the budget already SPENT. Nothing in the
    /// suite guarded that: flipping `HopBudget::spent()` to `fresh()` there left the whole library
    /// green — and that flip is the SAME failure direction as the `.unwrap_or(0)` defect this branch
    /// exists to remove, granting full reach to a request whose reach cannot be bounded.
    ///
    /// **The control is the load-bearing half.** The fixture is built so the node genuinely WOULD
    /// forward — empty DHT, a connected pool peer, an installed asker — and the control drives the
    /// identical content through `availability_batch` with a readable budget and observes an ask go
    /// out. Without it the assertion cannot tell "the mux leg refuses" from "this fixture never
    /// forwards at all", which is exactly the fixture that would pass against a broken leg.
    #[tokio::test]
    async fn the_hop_counterless_mux_shape_forwards_nothing() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let store = [0xA1u8; 32];
        let root = [0xA2u8; 32];
        let rk = [0xA3u8; 32];
        let cid = dig_dht::ContentId::resource(store, root, rk);

        // This node holds nothing and its own DHT walk finds nobody, so any named holder can only
        // have come from the forwarded ask.
        let holder = dig_download::ProviderRecord::new(
            &cid.to_key(),
            &dig_dht::PeerId::from_bytes([9; 32]),
            vec![dig_dht::CandidateAddr::direct("10.0.0.9", 9444)],
            u64::MAX,
        );
        let ask = crate::forwarded_ask_tests::RecordingAsk::answering(vec![holder]);
        let pc = crate::download::NodeContent::new(
            Arc::new(dig_download::testkit::MockProviderLocator::fixed(Vec::new())),
            Arc::new(dig_download::testkit::MockRangeTransport::new(
                dig_download::testkit::MockContent::even(4, 1),
            )),
            crate::download::MissMode::Redirect,
            None,
            td.path(),
        );
        {
            let pool = pc.connected_pool();
            let mut guard = pool.lock().expect("pool lock");
            guard.insert(
                dig_download::testkit::mock_peer_hex(1),
                vec!["10.0.0.1:9444".parse().expect("test address")],
            );
        }
        pc.set_forwarded_ask(ask.clone(), crate::forwarded_ask_tests::recursion());
        node.set_p2p_content(pc);

        let items = json!([{
            "store_id": hex::encode(store),
            "root": hex::encode(root),
            "retrieval_key": hex::encode(rk),
        }]);

        // The MUX leg, over the real peer stream.
        let responder: Arc<dyn PeerRpcResponder> =
            Arc::new(NodeResponder::without_pool(node.clone()));
        let (mut client, server) = tokio::io::duplex(8192);
        let srv = tokio::spawn(serve_one_stream(server, responder));
        write_framed(&mut client, &json!({ "items": items }))
            .await
            .unwrap();
        let resp = read_framed(&mut client).await.unwrap().expect("a response");
        drop(client);
        let _ = srv.await;

        assert!(
            ask.asked().is_empty(),
            "the mux shape cannot carry a hop counter, so it MUST forward nothing; asked {:?}",
            ask.asked()
        );
        assert!(
            resp["items"][0]["providers"].is_null(),
            "and it names no forwarded holder: {resp}"
        );

        // The CONTROL: the same node, the same content, a READABLE budget — this forwards.
        let answered = node
            .availability_batch(
                items.as_array().expect("items"),
                &crate::rate_limit::RequestorId::Peer("caller".into()),
                crate::download::HopBudget::fresh(),
            )
            .await;
        assert_eq!(
            ask.asked().len(),
            1,
            "CONTROL: with a budget it CAN read this very node forwards, so the assertion above observed the mux leg's spent budget and not a fixture that never forwards"
        );
        assert_eq!(
            answered["items"][0]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(9)),
            "and the forwarded holder reaches the answer on that leg"
        );
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
            // #2071: dispatched by NAME (not yet a `dig_rpc_protocol::Method` variant), which is
            // precisely WHAT keeps it off this surface — `is_peer_reachable_method` ends in
            // `Method::from_name(..).is_some_and(..)`, so an uncatalogued name is filtered before
            // the peer transport reaches dispatch. It serves loopback / in-process / gateway only.
            // Promoting it into the shared crate must therefore be a DELIBERATE
            // `is_peer_reachable()` decision; inheriting one would silently widen a gateway-only
            // public read to the whole permissionless peer network. This assertion is what fails
            // if that promotion happens without the decision.
            "dig.getPublicManifest",
            "totally.unknown",
            "",
        ] {
            assert!(
                !is_peer_reachable_method(m),
                "{m} is management/mutation/unknown and MUST NOT be reachable over the peer surface"
            );
        }
    }

    /// **Proves:** the peer allowlist this node exposes is EXACTLY the enumerated
    /// read/discovery/announce set — no more, no fewer. This is the security-critical regression guard
    /// for the #179 auth-bypass surface: the peer mTLS verifier accepts any well-formed self-signed leaf,
    /// so "authenticated" never means "authorized", and a management/mutation method reaching this list
    /// is a privilege escalation. Any method that gains or loses peer-reachability fails here.
    /// **Catches:** a `dig-rpc-protocol` bump that quietly adds a method to the allowlist — which is
    /// precisely what happened when the module-pull methods landed, and the point of listing the set
    /// literally is that such an addition must be a DELIBERATE edit here, reviewed on its own merits,
    /// never an incidental consequence of a dependency bump.
    #[test]
    fn peer_allowlist_is_byte_identical_to_the_pre_adoption_set() {
        // The canonical set the hand-rolled `is_peer_reachable_method` matched verbatim, PLUS the two
        // whole-module-pull methods added deliberately in #1576.
        //
        // Both are READS of content this node already serves at resource granularity, so they widen no
        // privilege: `getModuleInfo` describes a capsule whose resources `getAvailability`/`fetchRange`
        // already expose, and `fetchModuleRange` serves bytes of that same public, content-addressed
        // `.dig`. Neither mutates any node state, and both are paced by the same outbound limiter as
        // `fetchRange`. They are what let a reader become a resharer (SPEC §21).
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
            "dig.getModuleInfo",
            "dig.fetchModuleRange",
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

    /// **Proves:** `dig.getProviderSnapshot` is peer-reachable as the ONE deliberate dig-node-LOCAL
    /// addition beyond the shared `dig-rpc-protocol` allowlist (epic #1934 child 4a) — it is not (yet)
    /// in that crate's set, so the wrapper allowlists it explicitly, and this test records that as an
    /// intentional decision rather than an accident. It is a counts-only READ (no provider identities,
    /// no mutation), so it widens no privilege beyond the existing discovery methods.
    /// **Catches:** a silent removal of the local allowlist entry (which would break the neighbourhood
    /// probe), and confirms the crate's own set still does NOT carry the method.
    #[test]
    fn get_provider_snapshot_is_the_one_local_peer_method_beyond_the_crate_allowlist() {
        assert!(
            is_peer_reachable_method(
                crate::seams::dig_peer::neighbourhood_probe::GET_PROVIDER_SNAPSHOT_METHOD
            ),
            "dig.getProviderSnapshot must be peer-reachable (the neighbourhood-probe RPC)"
        );
        assert!(
            dig_rpc_protocol::Method::from_name(
                crate::seams::dig_peer::neighbourhood_probe::GET_PROVIDER_SNAPSHOT_METHOD
            )
            .is_none(),
            "it is a dig-node-local method — the shared crate must not yet know it (promoting it is a \
             tracked cross-repo follow-up)"
        );
    }

    /// **Proves:** `dig.resolveCapsule` is peer-reachable as a DELIBERATE dig-node-LOCAL addition beyond
    /// the shared `dig-rpc-protocol` allowlist (epic #1934 flywheel live-wiring, PR-1) — the second such
    /// local method after `getProviderSnapshot`. It is a preimage READ of this node's own public
    /// holdings (no mutation, no other node's provider identity), so it widens no privilege.
    /// **Catches:** a silent removal of the local allowlist entry (which would break the tier-0 precache
    /// resolve), and confirms the shared crate's own set still does NOT carry the method.
    #[test]
    fn resolve_capsule_is_a_deliberate_local_peer_method_beyond_the_crate_allowlist() {
        assert!(
            is_peer_reachable_method(
                crate::seams::dig_peer::resolve_capsule::RESOLVE_CAPSULE_METHOD
            ),
            "dig.resolveCapsule must be peer-reachable (the tier-0 precache key→preimage resolve)"
        );
        assert!(
            dig_rpc_protocol::Method::from_name(
                crate::seams::dig_peer::resolve_capsule::RESOLVE_CAPSULE_METHOD
            )
            .is_none(),
            "it is a dig-node-local method — the shared crate must not yet know it (promoting it is a \
             tracked cross-repo follow-up)"
        );
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

    /// #1532/#1541 — injecting the persistent identity makes ONE `peer_id` span every transport.
    /// [`apply_persistent_identity`] must (a) set the advertised pool `peer_id` from the persistent
    /// NodeCert's SPKI AND (b) inject that SAME NodeCert as `nat_identity`, so the dig-nat transport
    /// presents the advertised id rather than a random per-boot ephemeral one — the invariant that
    /// closes the Leg-B `peer_id mismatch`.
    #[test]
    fn apply_persistent_identity_makes_one_identity_span_all_transports() {
        let dir = tempfile::tempdir().expect("cert dir");
        let identity = load_or_generate_node_cert(dir.path(), &node_seed("legb-identity"))
            .expect("persistent identity");

        let mut cfg = dig_gossip::GossipConfig::default();
        apply_persistent_identity(&mut cfg, &identity);

        // (a) The advertised pool peer_id is derived from the persistent NodeCert's SPKI.
        assert_eq!(
            cfg.peer_id,
            dig_gossip::peer_id_from_tls_spki_der(identity.spki_der())
        );
        // (b) The SAME NodeCert is injected as the dig-nat transport identity...
        let injected = cfg.nat_identity.as_ref().expect("nat_identity injected");
        assert!(
            Arc::ptr_eq(injected, &identity),
            "the transport identity must be the node's persistent NodeCert, not a copy/ephemeral"
        );
        // ...so the transport's peer_id == the advertised peer_id (one identity, all transports).
        assert_eq!(
            dig_gossip::peer_id_from_tls_spki_der(injected.spki_der()),
            cfg.peer_id
        );
    }

    /// Leg B responder half (#1532/#1536): an ACCEPTED relayed circuit is served exactly like a direct
    /// inbound. `RelayAcceptor::accept` (which needs a live relay circuit) yields a server-role
    /// [`dig_nat::PeerConnection`]; here we produce that SAME connection by running the identical mTLS
    /// SERVER handshake over a real TCP link, then serve it via [`serve_accepted_relay_conn`]. The
    /// client (dialing over dig-nat Direct) gets a real peer-RPC answer, proving the served session is a
    /// fully-authenticated peer channel — a NAT'd peer's relayed circuit gets the full L7 peer RPC.
    #[tokio::test]
    async fn serve_accepted_relay_conn_serves_a_peer_rpc_over_an_authenticated_session() {
        use std::time::Duration;
        install_crypto_provider();

        let server_dir = tempfile::tempdir().expect("server cert dir");
        let server_identity =
            load_or_generate_node_cert(server_dir.path(), &node_seed("legb-server"))
                .expect("server identity");
        let server_peer_id = server_identity.peer_id();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_cert = server_identity.clone();
        let server = tokio::spawn(async move {
            let (tcp, peer_addr) = listener.accept().await.unwrap();
            // The SAME server handshake `RelayAcceptor::accept` runs over an introduced circuit.
            let server_tls =
                dig_tls::server_config(&server_cert, dig_nat::BindingPolicy::Opportunistic)
                    .expect("server config");
            let captured = server_tls.captured_peer_id;
            let captured_bls = server_tls.captured_bls;
            let acceptor = tokio_rustls::TlsAcceptor::from(server_tls.config);
            let tls = acceptor.accept(tcp).await.expect("mtls accept");
            let verified = captured.get().expect("client presented a cert");
            let conn = dig_nat::PeerConnection {
                peer_id: verified,
                method: dig_nat::TraversalKind::Relayed,
                remote_addr: peer_addr,
                peer_bls_pub: captured_bls.get(),
                session: dig_nat::mux::PeerSession::server(tls),
            };
            let responder: Arc<dyn PeerRpcResponder> = Arc::new(StubResponder);
            serve_accepted_relay_conn(conn, responder).await;
        });

        let client_dir = tempfile::tempdir().expect("client cert dir");
        let client_identity =
            load_or_generate_node_cert(client_dir.path(), &node_seed("legb-client"))
                .expect("client identity");
        let target = dig_nat::PeerTarget::with_addr(server_peer_id, addr, "DIG_MAINNET");
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(5))
            .build();
        let mut conn = dig_nat::connect(&target, &client_identity, &config)
            .await
            .expect("client dials the accepted-circuit server");

        // Bound the whole client exchange in an explicit timeout so a mux/transport regression fails
        // LOUDLY (a clear timeout panic) instead of hanging the test — and CI — forever.
        let resp = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = conn.session.open_stream().await.expect("open stream");
            write_framed(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":7,"method":"dig.getNetworkInfo"}),
            )
            .await
            .unwrap();
            read_framed(&mut stream).await.unwrap().expect("a frame")
        })
        .await
        .expect("the accepted relayed circuit answered within 10s");
        assert_eq!(resp["id"], json!(7));
        assert_eq!(
            resp["result"]["echo_method"],
            json!("dig.getNetworkInfo"),
            "the accepted relayed circuit must serve the peer RPC like a direct inbound"
        );

        // Teardown: `serve_accepted_relay_conn` runs an inbound accept-loop that only returns once the
        // client session closes. Drop the client `conn` to close the mux session (its driver ends, the
        // server's `accept_stream` yields `None`, the serve loop returns), THEN bounded-join the
        // server task. Awaiting `server` while `conn` was still alive was the deadlock: the loop never
        // ended, so the test hung after the RPC had already succeeded.
        drop(conn);
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
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
            let resp = responder.handle_json_rpc(req, "").await;
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
            .handle_json_rpc(
                json!({"jsonrpc":"2.0","id":1,"method":"dig.getNetworkInfo"}),
                "",
            )
            .await;
        assert!(
            ok.get("result").is_some(),
            "dig.getNetworkInfo must still be served on the peer surface"
        );
        // getPeers is answered from the (empty) pool view, not -32601.
        let peers = responder
            .handle_json_rpc(json!({"jsonrpc":"2.0","id":1,"method":"dig.getPeers"}), "")
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

    /// Seed a raw `.dig` module on disk at the capsule's `module_path`, the shape
    /// `stream_module_range` seeks its window out of (mirrors lib.rs's `cache_module`).
    fn seed_module_on_disk(cache_dir: &std::path::Path, store: &str, root: &str, bytes: &[u8]) {
        let path = crate::CapsuleKey::parse(store, root)
            .expect("canonical ids")
            .module_path(cache_dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }

    /// #1616: the whole-capsule (`dig.fetchModuleRange`) serve is the largest transfer in the system,
    /// yet it used to consult only the FCFS `serve_limiter`, never the #30 egress budget — so an
    /// operator's configured cap was silently bypassed on exactly the path where it matters most. Over
    /// the cap with a known alternate holder, the module serve must now DECLINE with the redirect frame
    /// (same graceful shape as `stream_range`), so the caller sources the window elsewhere.
    #[tokio::test]
    async fn stream_module_range_over_cap_with_a_provider_declines_instead_of_streaming() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let store = digstore_core::Bytes32([0x51; 32]);
        let root = digstore_core::Bytes32([0x52; 32]);
        // A real on-disk module well past the 10-byte cap.
        seed_module_on_disk(td.path(), &store.to_hex(), &root.to_hex(), &[0xABu8; 5000]);

        let mut node = node;
        Arc::get_mut(&mut node)
            .expect("sole owner right after construction")
            .outgoing_throttle = crate::bandwidth::OutgoingThrottle::new(10);
        // A holder for this CAPSULE is known via the DHT (capsule-granularity content id).
        let cid = dig_dht::ContentId::capsule(store.0, root.0);
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

        let req = json!({"method":"dig.fetchModuleRange","params":{
            "store_id": store.to_hex(), "root": root.to_hex(), "offset": 0, "length": 4096}});
        write_framed(&mut client, &req).await.unwrap();
        let frame = read_framed(&mut client).await.unwrap().expect("a frame");
        assert_eq!(
            frame["error"]["code"],
            json!(crate::download::CONTENT_REDIRECT),
            "held on disk but over the egress cap must decline/redirect, not stream: {frame}"
        );
        assert_eq!(
            frame["error"]["data"]["redirect"]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(6))
        );
        srv.await.unwrap().unwrap();
    }

    /// #1616, the graceful fallback: over the cap but NO known alternate holder → serve the module
    /// window anyway rather than drop a request only this node can answer (mirrors the
    /// `stream_range_over_cap_with_no_provider_still_streams_the_frame` contract).
    #[tokio::test]
    async fn stream_module_range_over_cap_with_no_provider_still_streams() {
        let (node, td) = crate::test_support::test_node_for_peer_surface();
        let store = digstore_core::Bytes32([0x53; 32]);
        let root = digstore_core::Bytes32([0x54; 32]);
        seed_module_on_disk(td.path(), &store.to_hex(), &root.to_hex(), &[0xCDu8; 5000]);

        let mut node = node;
        Arc::get_mut(&mut node)
            .expect("sole owner right after construction")
            .outgoing_throttle = crate::bandwidth::OutgoingThrottle::new(10);
        // A P2P engine is attached but the DHT knows of NO holder for this capsule.
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

        let req = json!({"method":"dig.fetchModuleRange","params":{
            "store_id": store.to_hex(), "root": root.to_hex(), "offset": 0, "length": 4096}});
        write_framed(&mut client, &req).await.unwrap();
        let frame = read_framed(&mut client).await.unwrap().expect("a frame");
        assert!(
            frame.get("error").is_none(),
            "no known alternate holder must NOT redirect, must stream the module window: {frame}"
        );
        assert_eq!(
            frame["offset"],
            json!(0),
            "a real module window frame leads"
        );
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

    /// With a tight per-connection cap the serve path PACES: after the initial burst, a further frame
    /// waits for a token refill, so streaming more than one budget's worth takes time.
    ///
    /// Rebased on a request whose span genuinely spans MULTIPLE frames (#1619: a single
    /// `stream_fetched_range` call no longer streams past its requested `length`, so a request has to
    /// exceed one node window — [`crate::peer::RANGE_WINDOW`] — to observe more than one frame at
    /// all). A resource just over one window, requested in full, yields exactly two frames: one
    /// window-sized frame (admitted immediately — an oversized frame is never split, only debited)
    /// then a small tail frame that must wait out that debt at the tight per-connection rate.
    #[tokio::test(start_paused = true)]
    async fn stream_range_paces_each_frame_under_a_tight_cap() {
        let total = RANGE_WINDOW + 100;
        let limiter = dig_download::FcfsRateLimiter::new(0, 100); // 100 B/s per-conn (global unlimited)
        let f = tiny_fetched(total);
        let mut out = tokio::io::sink();
        let start = tokio::time::Instant::now();
        let streamed = stream_fetched_range(
            &mut out,
            &f,
            RangeStreamPlan {
                offset: 0,
                requested_end: total,
                skip_layout: false,
                limiter: Some(&limiter),
                conn_key: "peerA",
                egress: &|_| {},
            },
        )
        .await
        .unwrap();
        // The frame COUNT is derived from the payload ceiling, never written as a literal. This
        // assertion previously read `frames: 2` — one 3 MiB "window-sized frame" plus a tail — which
        // is what the serve path actually did and what no conforming receiver could decode. It stayed
        // green because this path writes into a sink, never through `RangeFrame::encode` (#1640/#1668).
        let expected_frames = total.div_ceil(range_frame::FRAME_PAYLOAD) as u64;
        assert_eq!(
            (streamed.bytes, streamed.frames, streamed.refusal.clone()),
            (total as u64, expected_frames, None),
            "the span must be tiled into ceiling-sized frames plus a short tail"
        );
        // The throttles are charged the ENCODED size, which is strictly larger than the payload (base64
        // plus the metadata every frame carries). Asserting the relation rather than a literal keeps
        // this honest without pinning it to a serialization detail.
        assert!(
            streamed.encoded_bytes > streamed.bytes,
            "encoded wire bytes ({}) must exceed payload bytes ({})",
            streamed.encoded_bytes,
            streamed.bytes
        );
        // Each frame is admitted only once its bytes fit the budget, so a tiny cap makes a
        // many-frame serve wait — the pacing property, now observed across real ceiling-sized frames
        // rather than one oversized one.
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(1500),
            "paced serve should wait for the window frame's debt to clear, waited {:?}",
            start.elapsed()
        );
    }

    /// The default node has NO serve limiter (`None`, #1495): the serve path skips `acquire` and never
    /// paces — full-speed serve, and no per-connection map is ever created.
    #[tokio::test(start_paused = true)]
    async fn stream_range_unlimited_cap_never_paces() {
        let f = tiny_fetched(1_000_000);
        let mut out = tokio::io::sink();
        let start = tokio::time::Instant::now();
        stream_fetched_range(
            &mut out,
            &f,
            RangeStreamPlan {
                offset: 0,
                requested_end: 1000,
                skip_layout: false,
                limiter: None,
                conn_key: "peerA",
                egress: &|_| {},
            },
        )
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
        stream_fetched_range(
            &mut out,
            &f,
            RangeStreamPlan {
                offset: 0,
                requested_end: 1000,
                skip_layout: false,
                limiter: Some(&limiter),
                conn_key: "peerA",
                egress: &|_| {},
            },
        )
        .await
        .unwrap();
        // Peer B has its own fresh bucket → its first serve is instant.
        let start = tokio::time::Instant::now();
        stream_fetched_range(
            &mut out,
            &f,
            RangeStreamPlan {
                offset: 0,
                requested_end: 1000,
                skip_layout: false,
                limiter: Some(&limiter),
                conn_key: "peerB",
                egress: &|_| {},
            },
        )
        .await
        .unwrap();
        assert_eq!(
            start.elapsed(),
            std::time::Duration::ZERO,
            "peer B's budget is independent of peer A's"
        );
    }

    // -- #1595 serve-side observability: a read is diagnosable from LOGS, never a packet capture ------
    //
    // During the #836 read-leg grind the holder served ~20 KB over `dig.fetchRange` and logged NOTHING,
    // so "did the holder even receive the request?" could only be answered with tcpdump on the
    // instance — which left "holder inbound = zero" ambiguous for many diagnosis rounds. These tests
    // capture the REAL emitted records and pin that every peer-facing serve announces its outcome, and
    // that no payload byte or proof ever reaches the log.

    /// An in-memory sink a `tracing_subscriber::fmt` layer writes formatted records into.
    #[derive(Clone, Default)]
    struct CaptureBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureBuffer {
        type Writer = CaptureBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `body` (an async serve) under a scoped capturing subscriber at `TRACE` and return
    /// everything it logged — i.e. exactly what an operator tailing the node log would see.
    async fn capture_logs<F: std::future::Future>(body: F) -> String {
        let buffer = CaptureBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false) // plain text: the assertions below read the fields as an operator would
            .with_writer(buffer.clone())
            .finish();
        {
            let _guard = tracing::subscriber::set_default(subscriber);
            body.await;
        }
        let captured = buffer.0.lock().unwrap().clone();
        String::from_utf8_lossy(&captured).into_owned()
    }

    /// The caller peer_id a test serve is attributed to (the mTLS-verified `conn_key`).
    fn test_caller() -> String {
        "1c".repeat(32)
    }

    #[tokio::test]
    async fn an_inbound_fetch_range_logs_who_asked_for_what_and_what_was_served() {
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let (resource, chunk_lens) = crate::test_support::multi_chunk_served_resource();
        let (store, root, rk) = crate::test_support::seed_served_resource(&node, resource.clone());
        let responder = NodeResponder::without_pool(node);
        let req = json!({
            "store_id": store, "root": root, "retrieval_key": rk,
            "offset": chunk_lens[0], "length": chunk_lens[1],
        });

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            responder
                .stream_range(req, &test_caller(), &mut out)
                .await
                .expect("served");
        })
        .await;

        assert!(logs.contains(&test_caller()), "the asking peer_id: {logs}");
        assert!(logs.contains(&store), "the store id: {logs}");
        assert!(logs.contains(&root), "the generation root: {logs}");
        assert!(logs.contains(&rk), "the retrieval key: {logs}");
        assert!(
            logs.contains("outcome=served"),
            "the served OUTCOME: {logs}"
        );
        // `stream_range` is bounded by the REQUESTED span (#1619), not the resource's end: a request
        // for exactly chunk 1's bytes serves exactly chunk 1's bytes, in one frame.
        assert!(
            logs.contains(&format!("served_bytes={}", chunk_lens[1])),
            "the byte count actually served: {logs}"
        );
        assert!(logs.contains("frames=1"), "the frame granularity: {logs}");
        assert!(
            logs.contains("proof_attached=true"),
            "whether a proof rode the frames: {logs}"
        );
    }

    /// **Proves, at the REAL wire (not a mocked/symmetric harness), that a `{offset:0, length:1}`
    /// probe against a multi-KiB held resource gets exactly ONE small frame — never the whole
    /// resource streamed to its end (#1619).** dig-download's own orchestrator sends exactly this
    /// probe on EVERY download (`orchestrator.rs:930`), so this pins the actual trigger, not a
    /// contrived one.
    ///
    /// This drives the PRODUCTION `NodeResponder::stream_range` over a real `tokio::io::duplex` —
    /// the caller side decodes with the same [`read_framed`] a real peer connection uses, looping
    /// until `complete`, so a regression that resumes streaming past the requested span would show
    /// up as MORE than one frame arriving on the wire, not merely a wrong assertion value on a
    /// hand-built struct.
    #[tokio::test]
    async fn a_one_byte_probe_gets_one_frame_not_the_whole_resource_over_the_real_wire() {
        use digstore_core::merkle::{resource_leaf, MerkleTree};

        // A real multi-KiB held resource — many times larger than the `{offset:0, length:1}` probe,
        // so "streamed to the end" and "bounded to the request" are unmistakably different outcomes.
        let ciphertext: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        let tree = MerkleTree::from_leaves(vec![resource_leaf(&ciphertext)]);
        let resource = Arc::new(digstore_core::wire::ContentResponse {
            merkle_proof: tree.prove(0).expect("single-leaf proof"),
            roothash: tree.root(),
            chunk_lens: vec![ciphertext.len() as u32],
            ciphertext,
        });

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let (store, root, rk) = crate::test_support::seed_served_resource(&node, resource);
        let responder = NodeResponder::without_pool(node);
        let req = json!({
            "store_id": store, "root": root, "retrieval_key": rk,
            "offset": 0, "length": 1,
        });

        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(async move {
            responder
                .stream_range(req, &test_caller(), &mut server)
                .await
        });

        // Join the serve task FIRST: `stream_range` returns only once it is done writing, and
        // dropping its `server` half on return is what closes the duplex's write end — so the
        // client's read-to-EOF below terminates on the real number of frames actually sent, never on
        // a `complete` flag this fix explicitly decouples from "the stream is over" (a bounded
        // request's LAST frame can legitimately carry `complete: false`, #1619).
        served.await.expect("serve task join").expect("served");

        // Read every frame the wire actually carried, exactly as a real peer caller would, until EOF.
        let mut frames = Vec::new();
        while let Some(frame) = read_framed(&mut client)
            .await
            .expect("no I/O error reading the frame stream")
        {
            frames.push(frame);
        }

        assert_eq!(
            frames.len(),
            1,
            "a length=1 probe must yield exactly one frame on the real wire, got: {frames:?}"
        );
        assert_eq!(frames[0]["length"], json!(1), "the probe's requested span");
        assert_eq!(
            frames[0]["complete"],
            json!(false),
            "the RESOURCE is far from exhausted — only the REQUEST was satisfied"
        );
    }

    /// **Proves the PAGED-prologue producer contract at the REAL wire (#2230).** A resource with more
    /// than [`dig_nat::MAX_CHUNK_LENS_PER_FRAME`] chunks cannot state its whole `chunk_lens` on one
    /// frame, so the serve path pages it: the layout rides several frames, and when the requested bytes
    /// run out before the layout is fully sent, the remaining pages travel on trailing PROLOGUE-ONLY
    /// frames (zero data payload).
    ///
    /// The two properties a conforming 0.17 reader depends on, asserted on the bytes actually written:
    ///
    /// * every prologue-only frame is stamped with byte-`offset 0` — NOT the ascending cursor, which by
    ///   then equals the resource length and would trip the reader's `offset >= max_len` establish
    ///   guard;
    /// * a prologue-only frame carries NO `chunk_index` — it begins no chunk, and a stale index would
    ///   trip the reader's ascending-index rewind guard.
    ///
    /// The stream must also NOT early-terminate: the full 2,049-entry layout is delivered across the
    /// frames, so a paged read reassembles it in full.
    #[tokio::test]
    async fn a_paged_prologue_rides_offset_zero_frames_with_no_chunk_index_over_the_real_wire() {
        // 2,049 chunks → one entry past the 2,048/page ceiling → exactly two prologue pages.
        let chunk_count = dig_nat::MAX_CHUNK_LENS_PER_FRAME + 1;
        let (resource, served_layout) =
            crate::test_support::many_chunk_served_resource(chunk_count, 8);

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let (store, root, rk) = crate::test_support::seed_served_resource(&node, resource);
        let responder = NodeResponder::without_pool(node);
        // A one-byte probe: the bytes run out on the first frame, forcing the second prologue page onto
        // a trailing data-less frame — the exact shape the offset-0 fix governs.
        let req = json!({
            "store_id": store, "root": root, "retrieval_key": rk,
            "offset": 0, "length": 1,
        });

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let served = tokio::spawn(async move {
            responder
                .stream_range(req, &test_caller(), &mut server)
                .await
        });
        served.await.expect("serve task join").expect("served");

        let mut frames = Vec::new();
        while let Some(frame) = read_framed(&mut client)
            .await
            .expect("no I/O error reading the frame stream")
        {
            frames.push(frame);
        }

        // A prologue-only frame carries a `chunk_lens` page but zero data bytes (`bytes` is base64, so
        // an empty payload serializes to the empty string).
        let prologue_only: Vec<&Value> = frames
            .iter()
            .filter(|f| f["bytes"].as_str() == Some("") && f.get("chunk_lens").is_some())
            .collect();
        assert!(
            !prologue_only.is_empty(),
            "a 2,049-chunk layout past the request span must trail a prologue-only frame: {frames:?}"
        );
        for frame in &prologue_only {
            assert_eq!(
                frame["offset"],
                json!(0),
                "a prologue-only frame must be stamped offset 0, not the ascending cursor: {frame:?}"
            );
            assert!(
                frame.get("chunk_index").is_none(),
                "a prologue-only frame begins no chunk, so it carries no chunk_index: {frame:?}"
            );
            assert!(
                frame["chunk_lens_offset"].is_u64(),
                "a prologue-only frame carries a located page: {frame:?}"
            );
        }

        // The stream did not early-terminate: reassembling every page's entries yields the whole layout.
        let mut reassembled: Vec<u64> = Vec::new();
        for frame in &frames {
            if let Some(page) = frame["chunk_lens"].as_array() {
                reassembled.extend(page.iter().map(|v| v.as_u64().expect("chunk_lens entry")));
            }
        }
        assert_eq!(
            reassembled, served_layout,
            "the paged prologue must reassemble to the full served layout, byte-for-byte"
        );
        assert!(
            frames
                .iter()
                .filter(|f| f.get("chunk_lens").is_some())
                .count()
                >= 2,
            "a 2,049-entry layout must span at least two prologue pages: {frames:?}"
        );
    }

    /// **The primary end-to-end proof (#2230): the paged-prologue PRODUCER against the SHIPPED 0.17
    /// reader.** Drives the production [`NodeResponder::stream_range`] over a real `tokio::io::duplex`
    /// and feeds the raw wire bytes into `dig_download::assemble_range_stream` — the actual reassembler
    /// a downloading peer runs — with the `max_len: 1` establish probe dig-download sends on every
    /// download.
    ///
    /// Pre-fix this FAILS for the right reason: the trailing prologue page rides a frame stamped with
    /// the ascending cursor (== the resource length), which the reader rejects as
    /// `offset >= max_len`. After the fix the reader reassembles the full 2,049-entry layout with no
    /// paged-prologue or offset error.
    #[tokio::test]
    async fn the_paged_prologue_producer_reads_end_to_end_through_the_shipped_reader() {
        let chunk_count = dig_nat::MAX_CHUNK_LENS_PER_FRAME + 1;
        let (resource, served_layout) =
            crate::test_support::many_chunk_served_resource(chunk_count, 8);

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let (store, root, rk) = crate::test_support::seed_served_resource(&node, resource);
        let responder = NodeResponder::without_pool(node);
        let req = json!({
            "store_id": store, "root": root, "retrieval_key": rk,
            "offset": 0, "length": 1,
        });

        let (mut client, mut server) = tokio::io::duplex(256 * 1024);
        let served = tokio::spawn(async move {
            responder
                .stream_range(req, &test_caller(), &mut server)
                .await
        });
        served.await.expect("serve task join").expect("served");

        // The 1-byte establish probe dig-download's orchestrator sends on every download.
        let (_bytes, meta) = dig_download::assemble_range_stream(&mut client, 1)
            .await
            .expect("the shipped 0.17 reader reassembles the paged prologue with no offset error");

        assert_eq!(
            meta.chunk_lens,
            Some(served_layout),
            "the reassembled layout must equal the full 2,049-entry served layout"
        );
    }

    #[tokio::test]
    async fn an_inbound_fetch_range_for_content_we_do_not_hold_logs_the_refusal() {
        // The ambiguity #1595 closes: a request the node cannot answer must say so in the log, so
        // "asked and refused" is never mistaken for "never asked".
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let responder = NodeResponder::without_pool(node);
        let req = json!({
            "store_id": "3d".repeat(32), "root": "4e".repeat(32),
            "retrieval_key": "5f".repeat(32), "offset": 0, "length": 16,
        });

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            responder
                .stream_range(req, &test_caller(), &mut out)
                .await
                .expect("an error frame is still a written answer");
        })
        .await;

        assert!(
            logs.contains("outcome=not-held"),
            "the not-held OUTCOME with its reason: {logs}"
        );
        assert!(
            logs.contains(&crate::download::RESOURCE_UNAVAILABLE.to_string()),
            "the catalogued error code the peer was given: {logs}"
        );
    }

    #[tokio::test]
    async fn an_inbound_availability_query_logs_the_answer_and_why() {
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let held = json!({
            "store_id": "3d".repeat(32), "root": "4e".repeat(32),
            "retrieval_key": "5f".repeat(32),
        });

        let logs = capture_logs(async {
            let answer = node
                .availability_answer(
                    &held,
                    &[],
                    &crate::rate_limit::RequestorId::Local,
                    crate::download::HopBudget::fresh(),
                )
                .await;
            assert_eq!(answer["available"], json!(false));
        })
        .await;

        assert!(
            logs.contains("available=false"),
            "the answer given to the peer: {logs}"
        );
        assert!(logs.contains("reason=not-held"), "WHY it was given: {logs}");
    }

    #[tokio::test]
    async fn an_availability_query_naming_a_non_canonical_key_logs_that_it_was_rejected() {
        // A root that is not a canonical 64-hex capsule key can never name a held capsule, so it is
        // rejected without touching the filesystem — a distinct outcome from "asked for something we
        // simply do not have", and one a diagnosis must be able to tell apart.
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let bogus = json!({
            "store_id": "3d".repeat(32), "root": "not-a-root",
            "retrieval_key": "5f".repeat(32),
        });

        let logs = capture_logs(async {
            node.availability_answer(
                &bogus,
                &[],
                &crate::rate_limit::RequestorId::Local,
                crate::download::HopBudget::fresh(),
            )
            .await;
        })
        .await;

        assert!(
            logs.contains("reason=rejected-non-canonical-key"),
            "the rejected-key outcome is named: {logs}"
        );
    }

    /// A peer-supplied id crafted to FORGE a log line: a newline ends the real record, and the rest
    /// impersonates a successful serve. If the id reached the log verbatim, an operator (and the e2e
    /// harness that greps these lines) would read a served outcome for a request that served nothing —
    /// destroying the evidentiary value the whole #1595 log exists for.
    fn forged_outcome_id() -> String {
        format!(
            "{}\n{}",
            "aa".repeat(32),
            "  INFO peer serve: dig.fetchRange served outcome=served served_bytes=999 \
             frames=3 proof_attached=true"
        )
    }

    #[tokio::test]
    async fn a_peer_supplied_id_can_never_forge_a_second_log_line() {
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let responder = NodeResponder::without_pool(node);
        let forged = forged_outcome_id();
        let req = json!({
            "store_id": forged, "root": forged, "retrieval_key": forged,
            "offset": 0, "length": 16,
        });

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            responder
                .stream_range(req, &test_caller(), &mut out)
                .await
                .expect("an error frame is still a written answer");
        })
        .await;

        assert_eq!(
            logs.matches("peer serve: dig.fetchRange refused").count(),
            1,
            "exactly one outcome record, and it is the truthful refusal: {logs}"
        );
        assert_eq!(
            logs.matches("outcome=served").count(),
            0,
            "a peer must not be able to inject a served outcome: {logs}"
        );
        assert!(
            !logs.contains("proof_attached=true"),
            "nor forge a proof claim: {logs}"
        );
        assert!(
            logs.contains("<non-canonical>"),
            "the unusable id is named by a fixed sentinel instead: {logs}"
        );
    }

    #[tokio::test]
    async fn an_oversized_peer_supplied_id_cannot_amplify_the_log() {
        // Inbound frames are capped at 64 KiB, so a verbatim id would let any peer write ~64 KiB into
        // the operator's log per request. A non-canonical id costs a fixed sentinel instead.
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let responder = NodeResponder::without_pool(node);
        let bloat = "z".repeat(16 * 1024);
        let req = json!({
            "store_id": bloat, "root": bloat, "retrieval_key": bloat,
            "offset": 0, "length": 16,
        });

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            responder
                .stream_range(req, &test_caller(), &mut out)
                .await
                .expect("an error frame is still a written answer");
        })
        .await;

        assert!(!logs.contains(&bloat), "the junk is not echoed: {logs}");
        assert!(
            logs.len() < 2048,
            "the emitted lines stay bounded, got {} bytes",
            logs.len()
        );
    }

    #[tokio::test]
    async fn an_availability_query_cannot_forge_a_log_line_either() {
        // The availability path is worse by construction: a non-canonical root is logged on the very
        // path that has ALREADY established the id can never name a capsule.
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let forged = forged_outcome_id();
        let item = json!({
            "store_id": forged, "root": forged, "retrieval_key": forged,
        });

        let logs = capture_logs(async {
            node.availability_answer(
                &item,
                &[],
                &crate::rate_limit::RequestorId::Local,
                crate::download::HopBudget::fresh(),
            )
            .await;
        })
        .await;

        assert!(
            logs.contains("reason=rejected-non-canonical-key"),
            "the truthful reason is still reported: {logs}"
        );
        assert_eq!(
            logs.matches("outcome=served").count(),
            0,
            "no forged serve line: {logs}"
        );
        assert!(
            !logs.contains(&forged),
            "the crafted id never reaches the log verbatim: {logs}"
        );
    }

    // The fetch-through serve path (#165) reports its outcome through the SAME two production steps the
    // `MissOutcome::Fetched` arm composes — `stream_fetched_range` then
    // `StreamOutcome::as_serve_outcome` — so these pin the real counts and the real verdict. Before
    // this, the arm logged a fixed `frames: 0` and reported `served` even for a range it had refused.

    /// A serve target naming canonical ids, as an inbound request would.
    fn canonical_target<'a>(req: &'a Value, peer: &'a str) -> serve_log::ServeTarget<'a> {
        serve_log::ServeTarget::from_range_request(peer, req)
    }

    fn canonical_range_request() -> Value {
        json!({
            "store_id": "3d".repeat(32), "root": "4e".repeat(32),
            "retrieval_key": "5f".repeat(32),
        })
    }

    #[tokio::test]
    async fn a_fetch_through_serve_logs_the_real_frame_and_byte_counts() {
        // A request for 100 bytes out of a 300-byte resource is satisfied by EXACTLY the requested
        // span — one 100-byte frame, never streamed on to the resource's own end (#1619: `length`
        // bounds the WHOLE stream, not just one frame's size).
        let f = tiny_fetched(300);
        let req = canonical_range_request();
        let caller = test_caller();

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            let streamed = stream_fetched_range(
                &mut out,
                &f,
                RangeStreamPlan {
                    offset: 0,
                    requested_end: 100,
                    skip_layout: false,
                    limiter: None,
                    conn_key: &caller,
                    egress: &|_| {},
                },
            )
            .await
            .expect("streamed");
            assert_eq!(
                (streamed.bytes, streamed.frames, streamed.refusal.clone()),
                (100, 1, None)
            );
            serve_log::range_outcome(
                &canonical_target(&req, &caller),
                0,
                &streamed.as_serve_outcome(f.inclusion_proof.is_some()),
            );
        })
        .await;

        assert!(logs.contains("outcome=served"), "{logs}");
        assert!(
            logs.contains("served_bytes=100"),
            "the real byte total: {logs}"
        );
        assert!(logs.contains("frames=1"), "the real frame count: {logs}");
    }

    /// **Proves:** a requested span that runs PAST the resource's end is clipped by the resource, not
    /// by the request — `offset=250, length=100` on a 300-byte resource serves only the 50 bytes that
    /// exist, the OTHER bound this streaming loop must respect (#1619).
    #[tokio::test]
    async fn a_fetch_through_serve_clips_a_request_that_overruns_the_resource() {
        let f = tiny_fetched(300);
        let mut out = tokio::io::sink();
        let streamed = stream_fetched_range(
            &mut out,
            &f,
            RangeStreamPlan {
                offset: 250,
                requested_end: 250 + 100,
                skip_layout: false,
                limiter: None,
                conn_key: &test_caller(),
                egress: &|_| {},
            },
        )
        .await
        .expect("streamed");
        assert_eq!(
            (streamed.bytes, streamed.frames, streamed.refusal.clone()),
            (50, 1, None)
        );
    }

    #[tokio::test]
    async fn a_fetch_through_bad_range_logs_a_refusal_not_a_serve() {
        // The ambiguity D2 closes: this path answers an unsatisfiable range with an ERROR FRAME and an
        // `Ok`, so a naive caller would log `served bytes=0` for a request that served nothing.
        let f = tiny_fetched(300);
        let req = canonical_range_request();
        let caller = test_caller();

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            let streamed = stream_fetched_range(
                &mut out,
                &f,
                RangeStreamPlan {
                    offset: 9_000,
                    requested_end: 9_000 + 100,
                    skip_layout: false,
                    limiter: None,
                    conn_key: &caller,
                    egress: &|_| {},
                },
            )
            .await
            .expect("an error frame is still a written answer");
            assert_eq!(streamed.bytes, 0);
            assert_eq!(streamed.frames, 0);
            assert!(streamed.refusal.is_some(), "the range was refused");
            serve_log::range_outcome(
                &canonical_target(&req, &caller),
                9_000,
                &streamed.as_serve_outcome(f.inclusion_proof.is_some()),
            );
        })
        .await;

        assert!(
            logs.contains("outcome=bad-range"),
            "a refused fetch-through range must not read as a serve: {logs}"
        );
        assert_eq!(logs.matches("outcome=served").count(), 0, "{logs}");
    }

    #[tokio::test]
    async fn serve_logs_carry_ids_counts_and_outcomes_but_never_payload_or_proof() {
        // The observability contract's hard boundary: the log is for DIAGNOSIS, so it carries ids,
        // counts, and outcomes — never a served byte and never a proof. A log that echoed the payload
        // would turn every operator log file into a copy of the served content.
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let (resource, _chunk_lens) = crate::test_support::multi_chunk_served_resource();
        let (store, root, rk) = crate::test_support::seed_served_resource(&node, resource.clone());
        let responder = NodeResponder::without_pool(node);
        let req = json!({
            "store_id": store, "root": root, "retrieval_key": rk,
            "offset": 0, "length": resource.ciphertext.len(),
        });

        let logs = capture_logs(async {
            let mut out = tokio::io::sink();
            responder
                .stream_range(req, &test_caller(), &mut out)
                .await
                .expect("served");
        })
        .await;

        use base64::Engine as _;
        use digstore_core::codec::Encode as _;
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&resource.ciphertext);
        let proof_b64 =
            base64::engine::general_purpose::STANDARD.encode(resource.merkle_proof.to_bytes());
        assert!(
            !logs.contains(&payload_b64),
            "no served payload may reach the log: {logs}"
        );
        assert!(
            !logs.contains(&proof_b64),
            "no proof may reach the log: {logs}"
        );
        // …while still proving the serve happened.
        assert!(logs.contains("outcome=served"), "{logs}");
    }
}
