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
//! ## The clean seam for #163 (dig-dht)
//!
//! Peer DISCOVERY here is pool + `dig.getPeers` (the introducer/gossip sources). The provider-lookup
//! seam — "who holds capsule X?" beyond the local pool — is [`PeerRpcClient::find_holders`], which
//! today queries the connected pool via availability; #163 (dig-dht) slots in as an additional
//! provider source behind the SAME interface without touching the serve path.
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

use crate::CachedCapsule;

// -- Constants ---------------------------------------------------------------------------------------

/// Default relay endpoint (canonical public relay). Overridable with `DIG_RELAY_URL`; `off` disables
/// the reservation. Mirrors `dig_constants::DIG_RELAY_URL` / the retired relay client's default so an
/// operator's existing `DIG_RELAY_URL` keeps working.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.dig.net:9450";

/// Default network id a node registers + discovers under (matches dig-gossip / the relay wire).
pub const DEFAULT_NETWORK_ID: &str = "DIG_MAINNET";

/// Default P2P listen port for the mTLS peer-RPC server (matches dig-gossip `DEFAULT_P2P_PORT`).
pub const DEFAULT_P2P_PORT: u16 = 9444;

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
    relay_reserved: AtomicBool,
    /// Size of the connected peer pool.
    connected_peers: AtomicU64,
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

    /// Update the connected-pool size + relay-reservation flag (called from the maintenance loop).
    pub fn set_pool(&self, connected_peers: u64, relay_reserved: bool) {
        self.connected_peers
            .store(connected_peers, Ordering::Relaxed);
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

    /// A JSON snapshot for the `control.peerStatus` RPC.
    pub fn snapshot_json(&self, endpoint: &str, network_id: &str) -> Value {
        json!({
            "running": self.running.load(Ordering::Relaxed),
            "peer_id": self.peer_id.lock().unwrap().clone(),
            "network_id": network_id,
            "relay": {
                "url": endpoint,
                "reserved": self.relay_reserved.load(Ordering::Relaxed),
            },
            "connected_peers": self.connected_peers.load(Ordering::Relaxed),
            // (Reachability posture — direct vs relayed — is reported by `dig.getNetworkInfo`, which
            // reads this same relay-reservation flag; kept out of the terse status snapshot here.)
            "last_error": self.last_error.lock().unwrap().clone(),
        })
    }
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

/// The network id a node registers/discovers under: `DIG_NETWORK_ID` if set, else the default.
pub fn network_id_from_env() -> String {
    std::env::var("DIG_NETWORK_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_NETWORK_ID.to_string())
}

/// The P2P listen port: `DIG_PEER_PORT` if a valid u16, else [`DEFAULT_P2P_PORT`].
pub fn peer_port_from_env() -> u16 {
    std::env::var("DIG_PEER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_P2P_PORT)
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

/// The fixed 16-byte ASN.1 prefix of an Ed25519 PKCS#8 v1 `OneAsymmetricKey`, before the 32-byte seed
/// (`SEQUENCE { version 0, AlgorithmIdentifier { 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }`).
/// Concatenated with the 32-byte seed it is exactly the DER `ring`/`rcgen` accept via
/// `Ed25519KeyPair::from_pkcs8_maybe_unchecked`. Making the key deterministic in the seed keeps the
/// node's `peer_id` STABLE across restarts (a fresh random cert every boot would churn the id).
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE (46 bytes)
    0x02, 0x01, 0x00, // INTEGER version = 0
    0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING (34 bytes)
    0x04, 0x20, // OCTET STRING (32 bytes) — the raw seed follows
];

/// Install the process-wide rustls crypto provider (ring), idempotently. rustls 0.23 refuses to
/// auto-pick a provider when BOTH `ring` and `aws-lc-rs` are present in the dependency graph (aws-lc-rs
/// arrives transitively via chia-sdk-client), so any TLS use — the mTLS listener AND `dig_nat::connect`
/// — must have a provider installed FIRST or it panics. Call this once before bringing up the peer
/// network (and at the top of any test that dials/serves mTLS). A no-op if a provider is already set.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a deterministic [`dig_nat::LocalIdentity`] (self-signed Ed25519 mTLS cert) from a 32-byte
/// seed, so the node's `peer_id = SHA-256(cert SPKI DER)` is STABLE across restarts and identical for
/// the pool links it dials and the peer-RPC it serves. Used when no GossipService-managed cert is
/// available (e.g. an isolated peer-RPC server or a test); the standalone `run()` prefers the
/// GossipService's own `nat_identity()` so the pool + the RPC server present ONE cert.
pub fn identity_from_seed(seed: &[u8; 32]) -> Result<dig_nat::LocalIdentity, String> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls_pki_types::PrivatePkcs8KeyDer;

    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    pkcs8.extend_from_slice(seed);

    let key =
        KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &PKCS_ED25519)
            .map_err(|e| format!("derive key from seed: {e}"))?;
    let params = CertificateParams::new(vec!["dig-node".to_string()])
        .map_err(|e| format!("cert params: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-sign cert: {e}"))?;
    let cert_der = cert.der().to_vec();
    let key_der = key.serialize_der();
    dig_nat::LocalIdentity::from_der(cert_der, key_der)
        .ok_or_else(|| "cert did not parse back to a peer_id".to_string())
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
    async fn handle_json_rpc(&self, req: Value) -> Value;

    /// Answer a `dig.getAvailability` batch (the typed dig-nat control call). `items` is the raw
    /// AvailabilityItem array; returns the `{ "items": [AvailabilityAnswer, …] }` response value.
    async fn handle_availability(&self, items: Value) -> Value;

    /// Stream a `dig.fetchRange` response for `req` (the RangeRequest value) by writing framed
    /// [`dig_nat::mux::RangeFrame`]-shaped frames to `out`. Implementations write the first frame with
    /// the verification metadata + subsequent data frames, then return.
    async fn stream_range(
        &self,
        req: Value,
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
        PeerRequestKind::Range => responder.stream_range(req, &mut stream).await,
        PeerRequestKind::Unknown => {
            let resp = json!({"jsonrpc":"2.0","id":Value::Null,
                "error":{"code":-32600,"message":"unrecognized peer request frame"}});
            write_framed(&mut stream, &resp).await
        }
    }
}

/// The methods reachable over the **mTLS peer surface** (other DIG nodes) — the L7
/// read / discovery / announce subset (SPEC §2.3.1/§2.3.3, §7.4). This is an ALLOWLIST,
/// not a denylist: any method not named here is loopback/in-process only.
///
/// The peer mTLS verifier accepts any well-formed self-signed leaf ("authenticated" means
/// only "derived some peer_id", never "authorized"), so the node MUST NOT forward
/// management/mutation methods (`cache.*`, `control.*`, `dig.stage`) to a remote peer —
/// those stay reachable only from the loopback admin / in-process FFI dispatch
/// ([`crate::handle_rpc`]). See audit #179 (CRITICAL auth-bypass).
///
/// Adding a new method here is a deliberate security decision: it exposes that method to any
/// remote peer. New read/discovery methods that are safe for untrusted peers go in the list;
/// anything that mutates node state or reads local resources stays OUT.
pub(crate) fn is_peer_reachable_method(method: &str) -> bool {
    matches!(
        method,
        // Content read (public-read tier) — self-verified client-side.
        "dig.getContent"
            // Peer discovery + posture + announce.
            | "dig.getNetworkInfo"
            | "dig.getPeers"
            | "dig.announce"
            // Availability + inventory + range fetch (the multi-source download surface).
            | "dig.getAvailability"
            | "dig.listInventory"
            | "dig.fetchRange"
            // Chain-anchored read helpers (public, owner-independent).
            | "dig.getAnchoredRoot"
            | "dig.getCollection"
            | "dig.listCollectionItems"
    )
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
}

impl NodeResponder {
    /// A responder backed by the node + the live pool handle (the standalone peer-RPC server).
    pub(crate) fn with_pool(node: Arc<crate::Node>, handle: dig_gossip::GossipHandle) -> Self {
        NodeResponder {
            node,
            handle: Some(handle),
            dht: None,
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
        if method == "dig.getPeers" {
            let network_id = network_id_from_env();
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
                                    return stream_fetched_range(out, &f, off, length).await;
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
) -> std::io::Result<()> {
    let mut off = offset;
    loop {
        match fetched.range_frame(off, length) {
            Ok(frame) => {
                write_framed(out, &frame).await?;
                let complete = frame
                    .get("complete")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let this_len = frame.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
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

// -- Outgoing L7 peer RPC (the multi-source download seam, #163 dig-dht clean seam) ------------------

/// Outcome of an availability check against one pool peer, for the multi-source download planner.
#[derive(Debug, Clone)]
pub struct PeerAvailability {
    /// The peer's `peer_id` (64-hex).
    pub peer_id: String,
    /// The raw availability answers (one per queried item), from the peer.
    pub answers: Vec<dig_nat::AvailabilityAnswer>,
}

/// ISSUE the L7 peer RPC to pool peers — the outgoing client path (multi-source download seam). Given
/// a running [`dig_gossip::GossipHandle`], this lets the node ASK pool peers for availability and
/// FETCH byte ranges of a resource it lacks, verifying each range against the chain-anchored root
/// before use. Today the provider set is the connected pool ([`dig_gossip::GossipHandle`]'s
/// `connected_pool_peers`) + `dig.getPeers`; #163 (dig-dht) plugs in as an additional provider source
/// behind [`Self::find_holders`] WITHOUT touching this fetch/verify path.
pub struct PeerRpcClient {
    handle: dig_gossip::GossipHandle,
    per_method_timeout: std::time::Duration,
}

impl PeerRpcClient {
    /// Build a client over a running gossip handle. `per_method_timeout` bounds each NAT-traversal
    /// tier so a dial never hangs (a dig-nat guarantee).
    pub fn new(handle: dig_gossip::GossipHandle, per_method_timeout: std::time::Duration) -> Self {
        PeerRpcClient {
            handle,
            per_method_timeout,
        }
    }

    /// Find pool peers that HOLD a capsule/resource by asking each connected peer for availability.
    /// This is the discovery step of the multi-source download flow; #163 (dig-dht) extends the
    /// candidate set behind this same signature. Returns per-peer availability answers.
    ///
    /// `items` is the availability batch (store/root/resource granularity items). Only currently
    /// connected pool peers are queried (already-authenticated mTLS links); a peer that errors is
    /// skipped (best-effort). Dial-and-query of not-yet-connected candidates is a follow-up seam.
    pub async fn find_holders(
        &self,
        items: Vec<dig_nat::AvailabilityItem>,
    ) -> Vec<PeerAvailability> {
        let mut out = Vec::new();
        for (peer_id, addr, _outbound) in self.handle.connected_pool_peers() {
            // Dial the peer over the NAT ladder (direct-first) and query availability. The pool peer
            // is already known + authenticated; this opens a control stream to it.
            match self
                .handle
                .connect_via_nat(
                    peer_id,
                    Some(addr),
                    &[
                        dig_nat::TraversalKind::Direct,
                        dig_nat::TraversalKind::Relayed,
                    ],
                    self.per_method_timeout,
                )
                .await
            {
                Ok(mut conn) => match conn.query_availability(items.clone()).await {
                    Ok(resp) => out.push(PeerAvailability {
                        // gossip PeerId is a chia Bytes32 (no to_hex) — render as 64-hex.
                        peer_id: hex::encode(peer_id),
                        answers: resp.items,
                    }),
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "availability query failed")
                    }
                },
                Err(e) => tracing::debug!(peer = %peer_id, error = %e, "connect_via_nat failed"),
            }
        }
        out
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

/// Bring up the peer network (the fallible body of [`spawn_peer_network`]).
async fn run_peer_network(node: Arc<crate::Node>) -> Result<(), String> {
    // Pin the rustls crypto provider (ring) before ANY TLS use (the pool + the mTLS listener + any
    // outbound dial), since aws-lc-rs is also in the graph and rustls won't auto-pick between them.
    install_crypto_provider();
    // Install the weak self-reference so a `&self` read handler can spawn an owned-`Arc` background
    // task — the capsule backfill on a read-from-another-node (SPEC §5.6). Weak: no self-keep-alive.
    node.set_self_ref(Arc::downgrade(&node));
    let status = node.peer_status();
    let network_id_str = network_id_from_env();
    let relay_endpoint = relay_url_from_env();

    // 1. The node's stable mTLS identity, derived from its persistent §21 seed (so the peer_id is
    //    stable across restarts). Without a seed the node cannot present a stable identity; it still
    //    runs the HTTP read path but does not join the peer network.
    let seed = node
        .identity_seed_for_peer()
        .ok_or_else(|| "no identity seed; peer network needs a stable identity".to_string())?;
    let identity = identity_from_seed(&seed)?;
    let peer_id_hex = identity.peer_id.to_hex();
    status.set_running(peer_id_hex.clone());
    println!("dig-node peer network: peer_id {peer_id_hex} (network {network_id_str})");

    // §14 autonomous sync — spawn the CHAIN-WATCH + GAP-FILL loop (SPEC §14.2 + §14.3) FIRST,
    // INDEPENDENTLY of the P2P layer below. The proactive pull path (`Node::gap_fill_generation` →
    // the authenticated §21 whole-store sync) needs NEITHER the connected pool NOR the DHT, so §14
    // MUST NOT be gated behind them: a failed pool/DHT bring-up (a network hiccup, or the pre-launch
    // placeholder network genesis the gossip config currently rejects) must never silently disable
    // autonomous sync — the exact "declared complete but not running" gap (#213). The loop polls each
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
        network_id: dig_constants::DIG_MAINNET.genesis_challenge(),
        cert_path: gossip_dir.join("node.cert").display().to_string(),
        key_path: gossip_dir.join("node.key").display().to_string(),
        peers_file_path: gossip_dir.join("peers.json"),
        peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
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

    // 3. Keep the pool status fresh for `control.peerStatus` (connected count + relay reservation).
    {
        let status = status.clone();
        let handle = handle.clone();
        tokio::spawn(async move {
            loop {
                let stats = handle.pool_stats();
                // A held relay reservation is implied by having a relay configured + the pool up; the
                // pool does not surface the reservation flag directly in this rev, so we report the
                // relay as reserved while the pool is running with a relay endpoint configured.
                status.set_pool(stats.connected as u64, relay_enabled());
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }

    // 4. Bring up the content-location DHT (#163) over the SAME mTLS identity: it LOCATES which peers
    //    hold content this node wants, and keeps this node's OWN held-inventory provider records
    //    CURRENT so other nodes can find it. Best-effort — a DHT bring-up failure logs + leaves the
    //    node serving without the DHT (the pool + §21 read path still work).
    let dht = match bring_up_dht(&node, &identity, &network_id_str, &handle).await {
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
        );
        content.spawn_gc();
        // Feed the selector's registry from the connected pool (#178, SPEC §2.3): seed from the current
        // pool snapshot, then forward every pool churn event so the selector always ranks against the
        // live peer set. The selector already drives dig-download's source choice + learns from every
        // range outcome inside `NodeContent`; this keeps its candidate registry current.
        spawn_selector_registry_feed(content.clone(), handle.clone());
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
        Arc::new(crate::pex::GossipPexPool::new(handle.clone())),
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
    identity: &dig_nat::LocalIdentity,
    network_id: &str,
    pool: &dig_gossip::GossipHandle,
) -> Result<Arc<crate::dht::DhtHandle>, String> {
    use dig_dht::{CandidateAddr, DhtConfig, DhtService};

    let config = DhtConfig::default();
    // The transport dials peers as THIS node (client cert = our identity), scoping relay lookups to
    // our network id, bounding each RPC by the config's per-RPC timeout.
    let transport = Arc::new(crate::dht::NatDhtTransport::new(
        identity.clone(),
        network_id.to_string(),
        config.rpc_timeout,
    ));
    // Our own advertised addresses: the node's REAL routable address(es) at the P2P listen port,
    // ordered IPv6-first (ecosystem HARD RULE) — a global-unicast IPv6 address (when the host has one)
    // precedes the IPv4 fallback, so a peer's happy-eyeballs dialer prefers IPv6. The wildcard bind
    // address (`[::]` / `0.0.0.0`) is NOT dialable and must never leak as a candidate. A NAT'd node
    // with no routable address advertises nothing here and stays reachable via the relay tiers dig-nat
    // composes; loopback/in-process setups opt into a loopback candidate via DIG_NODE_ADVERTISE_LOOPBACK.
    let port = peer_port_from_env();
    let local_addresses: Vec<CandidateAddr> =
        crate::net::advertised_socket_addrs(port, crate::net::advertise_loopback_from_env())
            .into_iter()
            .map(|sa| CandidateAddr::direct(sa.ip().to_string(), sa.port()))
            .collect();
    let service = Arc::new(DhtService::new(
        identity.peer_id,
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
    identity: dig_nat::LocalIdentity,
    responder: Arc<dyn PeerRpcResponder>,
) -> Result<(), String> {
    serve_peer_rpc_listener_with(listener, identity, responder, None).await
}

/// Like [`serve_peer_rpc_listener`] but additionally running the node↔node **PEX** peer-sharing layer
/// (#166) over each accepted mTLS connection when `pex` is `Some`: the node opens its outgoing PEX
/// stream (handshake→snapshot→deltas) and serves the peer's incoming PEX stream, feeding discovered
/// peers into the pool as dial candidates. `None` disables PEX (the FFI/base path + existing callers),
/// leaving the serve path byte-identical to before.
pub async fn serve_peer_rpc_listener_with(
    listener: tokio::net::TcpListener,
    identity: dig_nat::LocalIdentity,
    responder: Arc<dyn PeerRpcResponder>,
    pex: Option<Arc<crate::pex::PexServing>>,
) -> Result<(), String> {
    let server_config = Arc::new(build_server_tls_config(&identity)?);
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

/// Build the rustls ServerConfig for the mTLS peer-RPC listener: present the node's leaf cert + key
/// and REQUIRE a client certificate (`with_client_cert_verifier`), verified by
/// [`PeerIdClientVerifier`] (self-signed, key-is-identity — no CA). A peer presenting no/invalid cert
/// is rejected by rustls before any byte is processed.
fn build_server_tls_config(
    identity: &dig_nat::LocalIdentity,
) -> Result<rustls::ServerConfig, String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    // Install a process crypto provider (ring) once; ignore if already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = CertificateDer::from(identity.cert_der.clone());
    // `identity.key_der` is a `Zeroizing<Vec<u8>>`; take an owned `Vec<u8>` copy of the
    // inner bytes so `PrivatePkcs8KeyDer::from(Vec<u8>)` applies (the `From` impls are
    // for `Vec<u8>` / `&[u8]`, not the `Zeroizing` wrapper).
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_der.to_vec()));
    let verifier = Arc::new(PeerIdClientVerifier::new());
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| format!("server TLS config: {e}"))
}

/// A rustls [`ClientCertVerifier`](rustls::server::danger::ClientCertVerifier) for the DIG
/// self-authenticating overlay: it REQUIRES a client certificate but does NOT check a CA chain (DIG
/// certs are self-signed and the key IS the identity, mirroring dig-nat's server-side verifier). It
/// derives `peer_id = SHA-256(SPKI DER)` from the presented leaf (rejecting an unparseable cert) and
/// delegates the signature check to ring — so a peer must actually hold the private key. This is the
/// inbound counterpart to dig-nat's outbound `PeerIdPinningVerifier`.
#[derive(Debug)]
struct PeerIdClientVerifier {
    schemes: Vec<rustls::SignatureScheme>,
}

impl PeerIdClientVerifier {
    fn new() -> Self {
        PeerIdClientVerifier {
            schemes: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes(),
        }
    }
}

impl rustls::server::danger::ClientCertVerifier for PeerIdClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // The peer_id is derived (and thus authenticated by the mTLS signature check below); we accept
        // any well-formed self-signed leaf, exactly as the DIG overlay's key-is-identity model requires.
        dig_nat::peer_id_from_leaf_cert_der(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General(
                "client leaf certificate could not be parsed as X.509".to_string(),
            )
        })?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID);
        assert_eq!(v["running"], false);
        assert_eq!(v["peer_id"], Value::Null);
        assert_eq!(v["network_id"], DEFAULT_NETWORK_ID);
        assert_eq!(v["relay"]["url"], DEFAULT_RELAY_URL);
        assert_eq!(v["relay"]["reserved"], false);
        assert_eq!(v["connected_peers"], 0);
    }

    #[test]
    fn peer_status_transitions_to_running_and_reports_pool() {
        let s = PeerStatus::new();
        s.set_running("ab".repeat(32));
        s.set_pool(5, true);
        assert!(s.is_running());
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID);
        assert_eq!(v["running"], true);
        assert_eq!(v["peer_id"], json!("ab".repeat(32)));
        assert_eq!(v["connected_peers"], 5);
        assert_eq!(v["relay"]["reserved"], true);
        s.set_error("relay dropped".into());
        let v = s.snapshot_json(DEFAULT_RELAY_URL, DEFAULT_NETWORK_ID);
        assert_eq!(v["last_error"], json!("relay dropped"));
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

    // -- Deterministic mTLS identity --------------------------------------------------------------

    #[test]
    fn identity_from_seed_is_deterministic_and_yields_a_stable_peer_id() {
        // The SAME seed → the SAME peer_id every time (stable across restarts); a DIFFERENT seed →
        // a different peer_id. This is the property the mTLS layer relies on.
        let a1 = identity_from_seed(&[7u8; 32]).expect("id a1");
        let a2 = identity_from_seed(&[7u8; 32]).expect("id a2");
        assert_eq!(
            a1.peer_id.to_hex(),
            a2.peer_id.to_hex(),
            "same seed → same peer_id"
        );
        // peer_id is 64-hex.
        assert_eq!(a1.peer_id.to_hex().len(), 64);
        let b = identity_from_seed(&[8u8; 32]).expect("id b");
        assert_ne!(
            a1.peer_id.to_hex(),
            b.peer_id.to_hex(),
            "different seed → different peer_id"
        );
    }

    #[test]
    fn identity_from_seed_peer_id_matches_dig_nat_derivation() {
        // The peer_id must equal SHA-256(cert SPKI DER) as dig-nat/dig-gossip compute it — proving
        // the node presents an id peers will verify identically.
        let id = identity_from_seed(&[3u8; 32]).expect("id");
        let recomputed = dig_nat::peer_id_from_leaf_cert_der(&id.cert_der).expect("cert parses");
        assert_eq!(id.peer_id.to_hex(), recomputed.to_hex());
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
}
