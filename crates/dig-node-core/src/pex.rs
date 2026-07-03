//! L7 Peer Exchange (PEX, #166) — the continuous node↔node peer-sharing layer.
//!
//! This is the dig-nat-mux I/O adapter around the transport-agnostic, sans-IO [`dig_pex::PexEngine`]
//! (dig-pex `SPEC.md` §10.1 + Appendix A). It formalizes what the ad-hoc `dig.getPeers` polling did:
//! over each ESTABLISHED mTLS peer connection the node holds, a dedicated **PEX logical stream** on the
//! yamux mux exchanges delta-based **first-hand** known-peer sets (`pex_handshake` → `pex_snapshot` →
//! periodic `pex_delta`s), feeding discovered peers into the dig-gossip pool as **dial candidates**
//! (hints, verified by dialing — never trusted facts) and penalizing peers that misbehave.
//!
//! ## How the engine is embedded
//!
//! One [`PexEngine`](dig_pex::PexEngine) per node, wrapped in [`PexEngineHandle`] (an async-safe
//! `Arc<Mutex<…>>` that also owns a per-link outbound channel registry so the periodic
//! [`tick`](PexEngineHandle::tick) can route each link's `pex_delta` to the task writing that link's
//! stream). The four engine inputs map to four adapters:
//!
//! - **link events** — a connection's [`run_send_direction`] calls `link_up` (emitting our
//!   handshake+snapshot) on start; the connection driver calls `link_down` on close (SPEC §5.5).
//! - **inbound messages** — [`serve_inbound_stream`] decodes framed [`PexMessage`]s off the peer's PEX
//!   stream and feeds `on_message`, writing any `pex_error` replies back on the SAME stream (SPEC
//!   §10.1) and acting on the returned events.
//! - **local peer-set changes** — [`spawn_pool_feeder`] mirrors dig-gossip pool churn
//!   (`connected_pool_peers` + `subscribe_pool_events`) into `upsert_known` / `remove_known`, so the
//!   node advertises exactly its first-hand connected peers (SPEC §9.3 outbound).
//! - **clock ticks** — [`run_tick_loop`] drives `tick` ~1/s.
//!
//! And the two engine outputs map to the pool:
//!
//! - [`PexEvent::Candidates`](dig_pex::PexEvent::Candidates) → [`PexPool::offer_candidates`] — the
//!   production [`GossipPexPool`] dials+verifies each candidate over dig-nat and adopts the verified
//!   connection into the pool (the trust model: a PEX entry is a HINT, proven only by a completed mTLS
//!   handshake — SPEC §11.1). Never marked reachable on the entry alone.
//! - [`PexEvent::Violation`](dig_pex::PexEvent::Violation) `{ mute: true }` → [`PexPool::penalize`] —
//!   the misbehaving peer is disconnected (a version/network mismatch, code 2/5, is benign and does
//!   NOT tear down the connection — SPEC §5.2).
//!
//! ## Relationship to the existing discovery
//!
//! PEX is ADDITIVE and complements the relay introducer + `dig.getPeers`: the introducer/`getPeers`
//! give one-shot snapshots; PEX is the STANDING exchange that keeps address books warm without polling.
//! `dig.getPeers` (the observability/interop surface in [`crate::peer`]) is unchanged and still served
//! — PEX feeds the same pool it reads.
//!
//! ## Where it runs (and the outbound-session seam)
//!
//! PEX runs over the mTLS peer connections THIS node owns — the accepted connections of the peer-RPC
//! listener ([`crate::peer::serve_peer_rpc_listener_with`]). Over one accepted yamux connection BOTH
//! PEX directions run: we open our outbound PEX stream to write our direction, and we accept the peer's
//! PEX stream to read theirs. The in-process FFI path opens no peer network, so it runs no PEX.
//!
//! NOTE (seam for a follow-up): dig-gossip owns the node's OUTBOUND pool sessions internally and does
//! not surface them, so PEX cannot open a stream on a link WE dialed until dig-gossip exposes those
//! sessions (or an accept hook). Until then, PEX rides the accepted (inbound) links; in a mesh where
//! peers dial each other bidirectionally this covers every pair. The advertise set is still fed from
//! the FULL pool (both directions) via [`spawn_pool_feeder`], so what we advertise is complete.
//!
//! There is no `crate::dig-node/SPEC.md` yet (the #167 spec-sweep is paused); this module doc-comment
//! is the interim normative note for the PEX peer-sharing behavior.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use dig_pex::{
    Address, PeerEntry, PexConfig, PexEngine, PexErrorCode, PexEvent, PexMessage, Provenance,
};

/// The node's own PEX capability flag: it serves DIG content (answers the L7 content RPCs), so every
/// entry it advertises for itself/peers carries `storage` (SPEC §3.2).
const NODE_PEX_FLAG: &str = "storage";

/// The node's own PEX capability flag ([`NODE_PEX_FLAG`]) for the bring-up path to declare in the
/// engine handshake config, so what the node advertises for itself matches every entry it emits.
#[must_use]
pub fn node_pex_flag() -> &'static str {
    NODE_PEX_FLAG
}

/// The PEX message `type` tokens — the four `type`-tagged shapes on the wire (dig-pex `SPEC.md` §4). An
/// inbound peer frame opens a PEX stream iff its `type` is one of these (see [`is_pex_first_frame`]).
/// Disjoint from the DHT tokens ([`crate::dht`]) and the JSON-RPC/range/availability shapes, so PEX
/// stream routing never collides.
const PEX_MESSAGE_TYPES: [&str; 4] = ["pex_handshake", "pex_snapshot", "pex_delta", "pex_error"];

/// The tick cadence — drive [`PexEngine::tick`] about once per second (SPEC §6.1 / Appendix A step 3).
const TICK_PERIOD: Duration = Duration::from_secs(1);

/// Cap on how many PEX-learned candidates we dial-to-verify per inbound batch, so a chatty peer cannot
/// make us fan unbounded outbound dials (defense-in-depth beside the engine's per-message caps, §7).
const MAX_CANDIDATE_DIALS: usize = 8;

/// Per-dial NAT-traversal budget when verifying a PEX candidate (bounds each tier so a dial never
/// hangs — a dig-nat guarantee).
const CANDIDATE_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Unix time in **milliseconds** (the engine's timestamp unit — SPEC Appendix A).
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether an inbound peer-request frame opens a PEX stream (its `type` is one of the four PEX
/// messages). The peer-RPC listener calls this to route a first frame to the PEX serving path rather
/// than the DHT / JSON-RPC / availability / range dispatch. Pure so it is unit-tested directly.
#[must_use]
pub fn is_pex_first_frame(v: &Value) -> bool {
    v.get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| PEX_MESSAGE_TYPES.contains(&t))
}

// -- The pool sink (candidates + violations) ---------------------------------------------------------

/// The node's peer pool as PEX sees it: where validated candidates go and how a misbehaving peer is
/// penalized. Implemented by [`GossipPexPool`] over the live dig-gossip handle in production, and by a
/// capturing stub in tests. Every method is best-effort (PEX is an advisory overlay).
#[async_trait]
pub trait PexPool: Send + Sync {
    /// Offer validated PEX candidates to the pool as **dial candidates** (SPEC §9.3 inbound). They are
    /// HINTS — the sink dials+verifies each (mTLS handshake) before treating the peer as reachable; it
    /// MUST NOT mark a peer reachable on the entry alone (SPEC §11.1). `source_peer_id` is the link the
    /// hints arrived on (for per-source attribution / deprioritization).
    async fn offer_candidates(&self, source_peer_id: &str, candidates: Vec<PeerEntry>);

    /// A link committed a PEX violation (SPEC §11.2). `mute` is `true` once the incoming direction is
    /// muted — either the strike limit (misbehavior: code 1/3/4/6 → the sink SHOULD disconnect) or a
    /// benign version/network mismatch (code 2/5 → the sink MUST NOT tear the connection down).
    async fn penalize(&self, peer_id: &str, code: u16, mute: bool);

    /// The link's sender dropped these `peer_id`s (SPEC §8.3) — advisory. Default: no-op (the engine
    /// already unlisted the sender as their hint source). Override to deprioritize the source.
    async fn note_dropped(&self, source_peer_id: &str, peer_ids: Vec<String>) {
        let _ = (source_peer_id, peer_ids);
    }
}

// -- The async-safe engine handle --------------------------------------------------------------------

/// Internal state behind [`PexEngineHandle`]'s mutex: the sans-IO engine plus a per-link registry of
/// outbound channels so [`tick`](PexEngineHandle::tick) can route each link's `pex_delta` to the task
/// writing that link's PEX stream.
struct EngineInner {
    engine: PexEngine,
    /// `peer_id → sender` for the task writing our outbound PEX stream to that peer. Dropping the
    /// sender (on [`link_down`](PexEngineHandle::link_down)) ends that task's forward loop.
    links: HashMap<String, mpsc::UnboundedSender<PexMessage>>,
}

/// An async-safe handle to the one node-wide [`PexEngine`]. Cloneable (`Arc`); shared between the
/// per-connection send/recv tasks, the pool feeder, and the tick loop. All engine access is serialized
/// behind the mutex (PEX traffic is low-rate, so contention is negligible).
#[derive(Clone)]
pub struct PexEngineHandle {
    inner: Arc<Mutex<EngineInner>>,
}

impl PexEngineHandle {
    /// Build a handle around a fresh engine configured from `cfg` (SPEC Appendix A step 1).
    #[must_use]
    pub fn new(cfg: PexConfig) -> Self {
        PexEngineHandle {
            inner: Arc::new(Mutex::new(EngineInner {
                engine: PexEngine::new(cfg),
                links: HashMap::new(),
            })),
        }
    }

    /// Add/update a first-hand-known peer in the advertise set (SPEC §8.1, §9.3). The `Provenance`
    /// type structurally forbids a `"pex"` provenance, so a PEX-learned entry can never be
    /// re-advertised unverified.
    pub async fn upsert_known(&self, entry: PeerEntry) {
        self.inner.lock().await.engine.upsert_known(entry);
    }

    /// Remove a peer from the advertise set — it disconnected or went stale (SPEC §9.3).
    pub async fn remove_known(&self, peer_id: &str) {
        self.inner.lock().await.engine.remove_known(peer_id);
    }

    /// Register the outbound channel for a link and return its receiver (the send task drains it). A
    /// re-registration for the same `peer_id` replaces (and thus ends) the previous send task.
    pub async fn register_link(&self, peer_id: &str) -> mpsc::UnboundedReceiver<PexMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner
            .lock()
            .await
            .links
            .insert(peer_id.to_string(), tx);
        rx
    }

    /// Produce our outgoing direction for a fresh link — the `pex_handshake` + `pex_snapshot` to write
    /// on our PEX stream (SPEC §5.1, §6.1).
    pub async fn link_up_frames(&self, peer_id: &str, now_ms: u64) -> Vec<PexMessage> {
        self.inner.lock().await.engine.link_up(peer_id, now_ms)
    }

    /// Feed one decoded inbound message; returns the replies to write back + events to act on
    /// (SPEC §5.3, §6.4, §7, §11).
    pub async fn on_message(
        &self,
        peer_id: &str,
        msg: PexMessage,
        now_ms: u64,
    ) -> dig_pex::PexOutcome {
        self.inner
            .lock()
            .await
            .engine
            .on_message(peer_id, msg, now_ms)
    }

    /// Record a transport-detected violation the engine could not see (a frame-size overrun or an
    /// undecodable frame — SPEC §7.2, §7.3): counts a strike + mutes at the limit.
    pub async fn record_violation(
        &self,
        peer_id: &str,
        code: PexErrorCode,
        now_ms: u64,
    ) -> dig_pex::PexOutcome {
        self.inner
            .lock()
            .await
            .engine
            .record_violation(peer_id, code, now_ms)
    }

    /// A link went down: discard its per-link engine state and drop its outbound channel so the send
    /// task ends (SPEC §5.5).
    pub async fn link_down(&self, peer_id: &str) {
        let mut g = self.inner.lock().await;
        g.engine.link_down(peer_id);
        g.links.remove(peer_id);
    }

    /// Drive the send cadence once (call ~1/s via [`run_tick_loop`]): emit each link's due `pex_delta`
    /// and route it to that link's outbound channel (SPEC §6.1). Empty deltas are suppressed by the
    /// engine; a link with no registered channel (raced teardown) is skipped.
    pub async fn tick(&self, now_ms: u64) {
        let mut g = self.inner.lock().await;
        let pairs = g.engine.tick(now_ms);
        for (peer_id, msg) in pairs {
            if let Some(tx) = g.links.get(&peer_id) {
                let _ = tx.send(msg);
            }
        }
    }

    // ----- read-only accessors (observability / tests) -----

    /// Number of peers in the first-hand advertise set.
    pub async fn known_count(&self) -> usize {
        self.inner.lock().await.engine.known_count()
    }

    /// Number of live links the engine is tracking.
    pub async fn link_count(&self) -> usize {
        self.inner.lock().await.engine.link_count()
    }

    /// Whether the incoming direction of `peer_id`'s link is muted (SPEC §5.2, §11.2).
    pub async fn is_muted(&self, peer_id: &str) -> bool {
        self.inner.lock().await.engine.is_muted(peer_id)
    }

    /// The violation strike count on `peer_id`'s incoming direction (SPEC §11.2).
    pub async fn strikes(&self, peer_id: &str) -> u32 {
        self.inner.lock().await.engine.strikes(peer_id)
    }

    /// Whether an outbound channel is currently registered for `peer_id` (tests observe link teardown).
    pub async fn has_link_channel(&self, peer_id: &str) -> bool {
        self.inner.lock().await.links.contains_key(peer_id)
    }
}

// -- The bundle threaded into the peer-RPC listener --------------------------------------------------

/// The PEX serving context the peer-RPC listener threads onto each accepted connection: the shared
/// engine handle + the pool sink. Cloneable (`Arc` inside).
#[derive(Clone)]
pub struct PexServing {
    /// The node-wide engine handle.
    pub engine: PexEngineHandle,
    /// Where candidates go + how violations are penalized.
    pub pool: Arc<dyn PexPool>,
}

impl PexServing {
    /// Bundle an engine handle with a pool sink.
    #[must_use]
    pub fn new(engine: PexEngineHandle, pool: Arc<dyn PexPool>) -> Arc<Self> {
        Arc::new(PexServing { engine, pool })
    }
}

// -- Per-connection stream drivers (SPEC §10.1) ------------------------------------------------------

/// Our OUTGOING PEX direction on `stream` (the mux logical stream we opened toward `peer_id`): write
/// the `pex_handshake` + `pex_snapshot` (from [`link_up`](PexEngine::link_up)), then forward each
/// `pex_delta` the tick loop routes to this link until the link is torn down or the stream errors
/// (SPEC §5.1, §10.1). Registers the link's outbound channel first so no early tick delta is lost.
pub async fn run_send_direction<S>(engine: PexEngineHandle, peer_id: String, mut stream: S)
where
    S: AsyncWrite + Unpin,
{
    let mut rx = engine.register_link(&peer_id).await;
    for frame in engine.link_up_frames(&peer_id, now_ms()).await {
        if write_pex(&mut stream, &frame).await.is_err() {
            return;
        }
    }
    // Forward tick-scheduled deltas until link_down drops the sender (→ None) or the peer goes away.
    while let Some(msg) = rx.recv().await {
        if write_pex(&mut stream, &msg).await.is_err() {
            return;
        }
    }
}

/// Serve the peer's INCOMING PEX direction on `stream` (the mux logical stream THEY opened, identified
/// by its first frame being a `pex_*` message): decode framed [`PexMessage`]s, feed each to the engine,
/// write any `pex_error` replies back on the SAME stream (SPEC §10.1), and act on the events
/// (candidates → pool, violation-mute → penalize + stop). `first` is the frame the caller already
/// consumed to classify the stream (`None` when this driver reads from the very start, e.g. tests).
///
/// Returns when the stream ends (clean EOF), the direction is muted, or a frame is undecodable (a
/// frame-level violation closes the PEX stream per SPEC §7.2, without touching sibling streams).
pub async fn serve_inbound_stream<S>(
    engine: PexEngineHandle,
    pool: Arc<dyn PexPool>,
    peer_id: String,
    first: Option<PexMessage>,
    mut stream: S,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(msg) = first {
        if !dispatch_inbound(&engine, &pool, &peer_id, msg, &mut stream).await {
            return;
        }
    }
    loop {
        match PexMessage::decode(&mut stream).await {
            Ok(msg) => {
                if !dispatch_inbound(&engine, &pool, &peer_id, msg, &mut stream).await {
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return, // clean end
            Err(_) => {
                // A frame that is too large or not valid PEX JSON is a message-level violation
                // (SPEC §7.2/§7.3): count a strike and close the stream (framing sync may be lost).
                let outcome = engine
                    .record_violation(&peer_id, PexErrorCode::BadMessage, now_ms())
                    .await;
                for ev in outcome.events {
                    if let PexEvent::Violation { code, mute } = ev {
                        pool.penalize(&peer_id, code, mute).await;
                    }
                }
                return;
            }
        }
    }
}

/// Feed one inbound message to the engine, write its replies back on `stream`, and act on its events.
/// Returns `false` when the direction is now muted (the caller stops reading), `true` to keep reading.
async fn dispatch_inbound<S>(
    engine: &PexEngineHandle,
    pool: &Arc<dyn PexPool>,
    peer_id: &str,
    msg: PexMessage,
    stream: &mut S,
) -> bool
where
    S: AsyncWrite + Unpin,
{
    let outcome = engine.on_message(peer_id, msg, now_ms()).await;
    // Advisory replies (e.g. a `pex_error`) — best-effort back on the same stream (SPEC §10.1).
    for reply in &outcome.replies {
        let _ = write_pex(stream, reply).await;
    }
    let mut keep_reading = true;
    for ev in outcome.events {
        match ev {
            PexEvent::Candidates(candidates) => {
                pool.offer_candidates(peer_id, candidates).await;
            }
            PexEvent::Dropped { peer_ids } => {
                pool.note_dropped(peer_id, peer_ids).await;
            }
            PexEvent::Violation { code, mute } => {
                pool.penalize(peer_id, code, mute).await;
                if mute {
                    keep_reading = false;
                }
            }
        }
    }
    keep_reading
}

/// Write one framed [`PexMessage`] (u32-BE length prefix + JSON body — SPEC §4.1) and flush it.
async fn write_pex<W: AsyncWrite + Unpin>(w: &mut W, msg: &PexMessage) -> std::io::Result<()> {
    w.write_all(&msg.encode()).await?;
    w.flush().await
}

// -- The tick loop + the pool feeder -----------------------------------------------------------------

/// Drive [`PexEngineHandle::tick`] forever at [`TICK_PERIOD`] (~1/s), so due `pex_delta`s flow on each
/// link (SPEC §6.1). Spawn it once per node; it never returns.
pub async fn run_tick_loop(engine: PexEngineHandle) {
    let mut ticker = tokio::time::interval(TICK_PERIOD);
    loop {
        ticker.tick().await;
        engine.tick(now_ms()).await;
    }
}

/// Spawn the tick loop as a background task (bring-up convenience).
pub fn spawn_tick_loop(engine: PexEngineHandle) {
    tokio::spawn(run_tick_loop(engine));
}

/// A first-hand advertise entry for a connected pool peer: `via: Direct`, its dialable address, the
/// node's own `storage` flag capability. `last_seen` is now (we are connected to it — first-hand
/// evidence, SPEC §8.1/§8.2). Pure so the mapping is unit-tested without a live pool.
fn pool_peer_entry(peer_id_hex: String, addr: std::net::SocketAddr, network_id: &str) -> PeerEntry {
    PeerEntry::new(peer_id_hex, network_id, now_ms() / 1000, Provenance::Direct)
        .with_address(Address::direct(addr.ip().to_string(), addr.port()))
        .with_flag(NODE_PEX_FLAG)
}

/// Mirror the dig-gossip connected pool into the PEX advertise set (SPEC §9.3 outbound): seed from the
/// current pool, then follow churn ([`subscribe_pool_events`](dig_gossip::GossipHandle::subscribe_pool_events)) —
/// a peer added → `upsert_known` it (we now know it first-hand); removed → `remove_known` + `link_down`
/// (drop it from the advertise set and end any PEX link to it). Best-effort; ends if the event channel
/// closes.
pub fn spawn_pool_feeder(
    engine: PexEngineHandle,
    handle: dig_gossip::GossipHandle,
    network_id: String,
) {
    tokio::spawn(async move {
        // Seed: everything already in the pool is first-hand-known.
        for (peer_id, addr, _outbound) in handle.connected_pool_peers() {
            engine
                .upsert_known(pool_peer_entry(hex::encode(peer_id), addr, &network_id))
                .await;
        }
        // Follow churn.
        let mut rx = match handle.subscribe_pool_events() {
            Ok(rx) => rx,
            Err(e) => {
                tracing::debug!(error = %e, "pex pool feeder: no pool-event channel; advertise set is seed-only");
                return;
            }
        };
        use dig_gossip::PoolEvent;
        loop {
            match rx.recv().await {
                Ok(PoolEvent::PeerAdded { peer_id, addr }) => {
                    engine
                        .upsert_known(pool_peer_entry(hex::encode(peer_id), addr, &network_id))
                        .await;
                }
                Ok(PoolEvent::PeerRemoved { peer_id, .. }) => {
                    let id = hex::encode(peer_id);
                    engine.remove_known(&id).await;
                    engine.link_down(&id).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break, // channel closed — the service is shutting down
            }
        }
    });
}

// -- The production pool sink over the dig-gossip handle ----------------------------------------------

/// The production [`PexPool`]: validated candidates are dialed+verified over dig-nat and adopted into
/// the pool (the trust model — a PEX entry becomes real only when the mTLS handshake to it succeeds,
/// SPEC §11.1); a muted misbehaving peer is disconnected. All best-effort.
pub struct GossipPexPool {
    handle: dig_gossip::GossipHandle,
}

impl GossipPexPool {
    /// A sink over the live gossip handle.
    #[must_use]
    pub fn new(handle: dig_gossip::GossipHandle) -> Self {
        GossipPexPool { handle }
    }
}

#[async_trait]
impl PexPool for GossipPexPool {
    async fn offer_candidates(&self, _source_peer_id: &str, candidates: Vec<PeerEntry>) {
        for entry in candidates.into_iter().take(MAX_CANDIDATE_DIALS) {
            let (Some(peer_id), Some(addr)) = (
                parse_gossip_peer_id(&entry.peer_id),
                best_socket_addr(&entry),
            ) else {
                // Relay-only or unparseable candidate: nothing to dial directly here. (A relay-only
                // peer is reached via the relay tiers when the pool later selects it; the address book
                // already knows it through the introducer.)
                continue;
            };
            let handle = self.handle.clone();
            // Verify by DIALING (mTLS proves the peer_id) and adopt the verified connection into the
            // pool — exactly how the pool's own maintenance turns a candidate into a member. Spawned so
            // one slow dial never stalls the inbound PEX read loop.
            tokio::spawn(async move {
                match handle
                    .connect_via_nat(
                        peer_id,
                        Some(addr),
                        &[
                            dig_nat::TraversalKind::Direct,
                            dig_nat::TraversalKind::Relayed,
                        ],
                        CANDIDATE_DIAL_TIMEOUT,
                    )
                    .await
                {
                    Ok(conn) => {
                        // Adoption dedups + caps; a duplicate/full/banned result is fine (already known).
                        let _ = handle.adopt_nat_connection(conn).await;
                    }
                    Err(e) => {
                        tracing::debug!(peer = %peer_id, error = %e, "pex candidate dial failed (hint discarded)");
                    }
                }
            });
        }
    }

    async fn penalize(&self, peer_id: &str, code: u16, mute: bool) {
        tracing::debug!(peer = %peer_id, code, mute, "pex violation on link");
        // Only DISCONNECT on a strike-limit mute for actual misbehavior (codes 1/3/4/6). A benign
        // version/network mismatch (2/5) also mutes but MUST NOT tear the connection down (SPEC §5.2).
        let is_benign_mismatch = code == PexErrorCode::UnsupportedVersion.as_u16()
            || code == PexErrorCode::NetworkMismatch.as_u16();
        if mute && !is_benign_mismatch {
            if let Some(pid) = parse_gossip_peer_id(peer_id) {
                let _ = self.handle.disconnect(&pid).await;
            }
        }
    }
}

/// Parse a 64-hex `peer_id` into a dig-gossip [`PeerId`](dig_gossip::PeerId) (`Bytes32`), or `None` if
/// malformed. Pure so it is unit-tested without a handle.
fn parse_gossip_peer_id(peer_id_hex: &str) -> Option<dig_gossip::PeerId> {
    if peer_id_hex.len() != 64 {
        return None;
    }
    let bytes = hex::decode(peer_id_hex).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(dig_gossip::PeerId::from(arr))
}

/// The first dialable [`std::net::SocketAddr`] in a candidate's addresses (an IP literal + non-zero
/// port), or `None` for a relay-only / hostname-only entry. Pure so it is unit-tested without a socket.
fn best_socket_addr(entry: &PeerEntry) -> Option<std::net::SocketAddr> {
    for a in &entry.addresses {
        if a.port == 0 {
            continue;
        }
        if let Ok(ip) = a.host.parse::<std::net::IpAddr>() {
            return Some(std::net::SocketAddr::new(ip, a.port));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_pex::{AddressKind, PEX_VERSION};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn hexid(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    /// A capturing [`PexPool`] that records what PEX handed it, so the adapter is tested without a live
    /// pool or any network.
    #[derive(Default)]
    struct CapturePool {
        candidates: Mutex<Vec<(String, PeerEntry)>>,
        penalties: Mutex<Vec<(String, u16, bool)>>,
        dropped: Mutex<Vec<(String, String)>>,
        dial_count: AtomicUsize,
    }

    #[async_trait]
    impl PexPool for CapturePool {
        async fn offer_candidates(&self, source: &str, candidates: Vec<PeerEntry>) {
            let mut g = self.candidates.lock().await;
            for c in candidates {
                self.dial_count.fetch_add(1, Ordering::Relaxed);
                g.push((source.to_string(), c));
            }
        }
        async fn penalize(&self, peer_id: &str, code: u16, mute: bool) {
            self.penalties
                .lock()
                .await
                .push((peer_id.to_string(), code, mute));
        }
        async fn note_dropped(&self, source: &str, peer_ids: Vec<String>) {
            let mut g = self.dropped.lock().await;
            for id in peer_ids {
                g.push((source.to_string(), id));
            }
        }
    }

    fn handshake(net: &str) -> PexMessage {
        PexMessage::PexHandshake {
            version: PEX_VERSION,
            network_id: net.to_string(),
            interval: 30,
            flags: vec!["storage".into()],
        }
    }

    fn entry(id: &str, net: &str, last_seen: u64) -> PeerEntry {
        PeerEntry::new(id, net, last_seen, Provenance::Direct)
            .with_address(Address::direct("203.0.113.9", 9444))
            .with_flag("storage")
    }

    // -- classifier ------------------------------------------------------------------------------

    #[test]
    fn is_pex_first_frame_matches_the_four_pex_types_only() {
        for t in PEX_MESSAGE_TYPES {
            assert!(is_pex_first_frame(&serde_json::json!({ "type": t })), "{t}");
        }
        // Not the DHT / JSON-RPC / range / availability shapes.
        assert!(!is_pex_first_frame(
            &serde_json::json!({ "type": "find_node" })
        ));
        assert!(!is_pex_first_frame(
            &serde_json::json!({ "method": "dig.getPeers" })
        ));
        assert!(!is_pex_first_frame(&serde_json::json!({ "length": 4096 })));
        assert!(!is_pex_first_frame(&serde_json::json!({ "items": [] })));
        assert!(!is_pex_first_frame(
            &serde_json::json!({ "type": "unknown" })
        ));
    }

    // -- engine handle: local set + tick routing -------------------------------------------------

    #[tokio::test]
    async fn handle_advertises_upserted_peers_and_forgets_removed() {
        let me = hexid(0x01);
        let engine = PexEngineHandle::new(PexConfig::new(me, "mainnet").with_jitter(false));
        assert_eq!(engine.known_count().await, 0);
        engine
            .upsert_known(entry(&hexid(0x02), "mainnet", 1_000))
            .await;
        engine
            .upsert_known(entry(&hexid(0x03), "mainnet", 1_000))
            .await;
        assert_eq!(engine.known_count().await, 2);
        engine.remove_known(&hexid(0x02)).await;
        assert_eq!(engine.known_count().await, 1);
    }

    #[tokio::test]
    async fn link_up_emits_handshake_then_snapshot_of_first_hand_set() {
        let me = hexid(0x01);
        let peer = hexid(0x02);
        let engine = PexEngineHandle::new(
            PexConfig::new(me, "mainnet")
                .with_flags(vec!["storage".into()])
                .with_jitter(false),
        );
        engine
            .upsert_known(entry(&hexid(0x03), "mainnet", 1_000))
            .await;
        let frames = engine.link_up_frames(&peer, 1_000_000).await;
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0], PexMessage::PexHandshake { .. }));
        match &frames[1] {
            PexMessage::PexSnapshot { peers } => {
                assert_eq!(
                    peers.len(),
                    1,
                    "the one first-hand peer (self+partner excluded)"
                );
                assert_eq!(peers[0].peer_id, hexid(0x03));
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tick_routes_a_pending_delta_to_the_links_channel() {
        // A newly-known peer becomes an `added` delta on the next elapsed tick, routed to the link's
        // registered outbound channel (the send task's receiver).
        let me = hexid(0x01);
        let peer = hexid(0x02);
        let engine = PexEngineHandle::new(
            PexConfig::new(me, "mainnet")
                .with_interval(30)
                .with_jitter(false),
        );
        let mut rx = engine.register_link(&peer).await;
        // link_up establishes the snapshot baseline at t=0.
        let _ = engine.link_up_frames(&peer, 0).await;
        // A new first-hand peer AFTER the snapshot → pending change.
        engine
            .upsert_known(entry(&hexid(0x07), "mainnet", 1_000))
            .await;
        // Tick past the 30 s effective interval (ms).
        engine.tick(31_000).await;
        let msg = rx
            .try_recv()
            .expect("a delta was routed to the link channel");
        match msg {
            PexMessage::PexDelta { added, dropped } => {
                assert_eq!(added.len(), 1);
                assert_eq!(added[0].peer_id, hexid(0x07));
                assert!(dropped.is_empty());
            }
            other => panic!("expected a delta, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn link_down_drops_the_channel_and_clears_link_state() {
        let me = hexid(0x01);
        let peer = hexid(0x02);
        let engine = PexEngineHandle::new(PexConfig::new(me, "mainnet").with_jitter(false));
        let _rx = engine.register_link(&peer).await;
        let _ = engine.link_up_frames(&peer, 0).await;
        assert!(engine.has_link_channel(&peer).await);
        assert_eq!(engine.link_count().await, 1);
        engine.link_down(&peer).await;
        assert!(
            !engine.has_link_channel(&peer).await,
            "channel dropped → send task ends"
        );
        assert_eq!(
            engine.link_count().await,
            0,
            "per-link engine state cleared"
        );
    }

    // -- inbound stream: two mock nodes over an in-memory link -----------------------------------

    #[tokio::test]
    async fn inbound_stream_learns_a_pex_advertised_peer_as_a_candidate() {
        // NODE B advertises a peer to NODE A over an in-memory link (a tokio duplex standing in for the
        // mux PEX stream). A's engine surfaces it as a candidate; the pool sink receives it as a HINT
        // (offered for dial+verify, never a trusted fact).
        let a = hexid(0x0a);
        let b = hexid(0x0b);
        let learned = hexid(0x0c);
        let engine = PexEngineHandle::new(PexConfig::new(a, "mainnet").with_jitter(false));
        let pool = Arc::new(CapturePool::default());

        // Compose B's outgoing direction on the wire: handshake → snapshot(learned) → delta(added).
        let (mut b_write, a_read) = tokio::io::duplex(64 * 1024);
        write_pex(&mut b_write, &handshake("mainnet"))
            .await
            .unwrap();
        let now = now_ms() / 1000;
        write_pex(
            &mut b_write,
            &PexMessage::PexSnapshot {
                peers: vec![entry(&learned, "mainnet", now)],
            },
        )
        .await
        .unwrap();
        drop(b_write); // clean EOF after the snapshot

        serve_inbound_stream(engine.clone(), pool.clone(), b.clone(), None, a_read).await;

        let got = pool.candidates.lock().await;
        assert_eq!(
            got.len(),
            1,
            "exactly the one advertised peer surfaced as a candidate"
        );
        assert_eq!(got[0].0, b, "attributed to the link it arrived on");
        assert_eq!(got[0].1.peer_id, learned);
        // Trust model: it is a candidate offered for verification, not marked reachable here.
        assert_eq!(
            got[0].1.via,
            Provenance::Direct,
            "carries the advertiser's provenance (a hint)"
        );
    }

    #[tokio::test]
    async fn inbound_stream_penalizes_a_min_interval_rate_violation() {
        // Two deltas arriving back-to-back (well under the 30 s floor) → the SECOND is a rate violation
        // (SPEC §6.4). Three strikes mute the direction and the pool is told to penalize.
        let a = hexid(0x0a);
        let b = hexid(0x0b);
        let engine = PexEngineHandle::new(PexConfig::new(a, "mainnet").with_jitter(false));
        let pool = Arc::new(CapturePool::default());

        let (mut b_write, a_read) = tokio::io::duplex(64 * 1024);
        // handshake(interval=30) → snapshot(empty, starts the arrival clock) → 3 rapid deltas.
        write_pex(&mut b_write, &handshake("mainnet"))
            .await
            .unwrap();
        write_pex(&mut b_write, &PexMessage::PexSnapshot { peers: vec![] })
            .await
            .unwrap();
        for i in 0..3u8 {
            write_pex(
                &mut b_write,
                &PexMessage::PexDelta {
                    added: vec![entry(&hexid(0x20 + i), "mainnet", now_ms() / 1000)],
                    dropped: vec![],
                },
            )
            .await
            .unwrap();
        }
        drop(b_write);

        serve_inbound_stream(engine.clone(), pool.clone(), b.clone(), None, a_read).await;

        let penalties = pool.penalties.lock().await;
        assert!(!penalties.is_empty(), "a rate violation was penalized");
        assert!(
            penalties
                .iter()
                .all(|(_, code, _)| *code == PexErrorCode::RateViolation.as_u16()),
            "every strike here is a rate violation (code 3)"
        );
        assert!(
            penalties.iter().any(|(_, _, mute)| *mute),
            "reaching the strike limit muted the direction"
        );
        assert!(engine.is_muted(&b).await, "the incoming direction is muted");
    }

    #[tokio::test]
    async fn inbound_entries_are_hints_not_trusted_facts() {
        // A malformed entry (wrong network) inside an otherwise-valid snapshot is SKIPPED, not
        // trusted — proving inbound entries are validated candidates, never accepted verbatim.
        let a = hexid(0x0a);
        let b = hexid(0x0b);
        let engine = PexEngineHandle::new(PexConfig::new(a, "mainnet").with_jitter(false));
        let pool = Arc::new(CapturePool::default());

        let (mut b_write, a_read) = tokio::io::duplex(64 * 1024);
        write_pex(&mut b_write, &handshake("mainnet"))
            .await
            .unwrap();
        let now = now_ms() / 1000;
        write_pex(
            &mut b_write,
            &PexMessage::PexSnapshot {
                peers: vec![
                    entry(&hexid(0x30), "mainnet", now),  // valid → a candidate
                    entry(&hexid(0x31), "othernet", now), // wrong network → skipped
                ],
            },
        )
        .await
        .unwrap();
        drop(b_write);

        serve_inbound_stream(engine.clone(), pool.clone(), b.clone(), None, a_read).await;

        let got = pool.candidates.lock().await;
        assert_eq!(
            got.len(),
            1,
            "only the valid entry became a candidate; the junk was skipped"
        );
        assert_eq!(got[0].1.peer_id, hexid(0x30));
    }

    #[tokio::test]
    async fn dropped_delta_surfaces_the_id_to_the_pool_as_advisory() {
        // A snapshot tells A about a peer; a LATER delta (past the arrival floor) drops it. A surfaces
        // the drop as advisory to the pool (unlist the source), not a delete. Driven at explicit
        // timestamps so the delta clears the min-interval arrival floor (a back-to-back delta would be
        // a rate violation — covered separately); the event→pool routing is exactly the serving loop's
        // (`PexEvent::Dropped → pool.note_dropped`).
        let a = hexid(0x0a);
        let b = hexid(0x0b);
        let gone = hexid(0x40);
        let engine = PexEngineHandle::new(
            PexConfig::new(a, "mainnet")
                .with_interval(30)
                .with_jitter(false),
        );
        let pool = Arc::new(CapturePool::default());
        // A throwaway stream for any advisory replies (there are none on this happy path).
        let (mut sink, _peer) = tokio::io::duplex(4096);

        // t=0: handshake(interval=30) → snapshot advertising `gone` (validated → tracked as received).
        let t0 = 1_000_000_u64;
        engine.on_message(&b, handshake("mainnet"), t0).await;
        let snap = PexMessage::PexSnapshot {
            peers: vec![entry(&gone, "mainnet", t0 / 1000)],
        };
        let out = engine.on_message(&b, snap, t0).await;
        // The snapshot's entry surfaces as a candidate (proves it was tracked, so a later drop matches).
        assert!(out
            .events
            .iter()
            .any(|e| matches!(e, PexEvent::Candidates(_))));

        // t=30s later (past the 25 s arrival floor): a delta dropping `gone`.
        let t1 = t0 + 30_000;
        let delta = PexMessage::PexDelta {
            added: vec![],
            dropped: vec![gone.clone()],
        };
        let out = engine.on_message(&b, delta, t1).await;
        // Route the outcome through the SAME event→pool mapping the serving loop uses.
        for reply in &out.replies {
            let _ = write_pex(&mut sink, reply).await;
        }
        for ev in out.events {
            match ev {
                PexEvent::Dropped { peer_ids } => pool.note_dropped(&b, peer_ids).await,
                PexEvent::Candidates(c) => pool.offer_candidates(&b, c).await,
                PexEvent::Violation { code, mute } => pool.penalize(&b, code, mute).await,
            }
        }

        let dropped = pool.dropped.lock().await;
        assert_eq!(dropped.len(), 1, "the dropped id was reported once");
        assert_eq!(dropped[0], (b.clone(), gone));
    }

    // -- send + serve wired together (both directions of a link over two in-memory streams) ------

    #[tokio::test]
    async fn two_nodes_exchange_handshake_snapshot_over_in_memory_streams() {
        // Full node↔node exchange with NO real network: node A runs its send direction on one duplex;
        // node B serves that as its inbound direction and learns A's advertised peer.
        let a = hexid(0x0a);
        let b = hexid(0x0b);
        let a_advertises = hexid(0x0c);

        let a_engine = PexEngineHandle::new(
            PexConfig::new(a.clone(), "mainnet")
                .with_flags(vec!["storage".into()])
                .with_jitter(false),
        );
        a_engine
            .upsert_known(entry(&a_advertises, "mainnet", now_ms() / 1000))
            .await;

        let b_engine = PexEngineHandle::new(PexConfig::new(b, "mainnet").with_jitter(false));
        let b_pool = Arc::new(CapturePool::default());

        // A's outbound stream ↔ B's inbound stream.
        let (a_out, b_in) = tokio::io::duplex(64 * 1024);

        // A writes its direction (handshake + snapshot) then holds the link open.
        let a_send = tokio::spawn(run_send_direction(a_engine.clone(), a.clone(), a_out));
        // B serves A's direction until the stream ends.
        let b_serve = tokio::spawn(serve_inbound_stream(
            b_engine.clone(),
            b_pool.clone(),
            a.clone(),
            None,
            b_in,
        ));

        // Give the exchange a moment, then tear A's link down so its send loop ends and B sees EOF.
        tokio::time::sleep(Duration::from_millis(50)).await;
        a_engine.link_down(&a).await;
        let _ = a_send.await;
        let _ = b_serve.await;

        let got = b_pool.candidates.lock().await;
        assert_eq!(
            got.len(),
            1,
            "B learned A's one advertised peer via the snapshot"
        );
        assert_eq!(got[0].1.peer_id, a_advertises);
    }

    // -- pure helpers ----------------------------------------------------------------------------

    #[test]
    fn parse_gossip_peer_id_round_trips_and_rejects_bad() {
        let id = hexid(0xab);
        let pid = parse_gossip_peer_id(&id).expect("64-hex parses");
        assert_eq!(hex::encode(pid), id);
        assert!(parse_gossip_peer_id("short").is_none());
        assert!(parse_gossip_peer_id(&"zz".repeat(32)).is_none());
    }

    #[test]
    fn best_socket_addr_picks_first_dialable_ip() {
        let e = PeerEntry::new(hexid(0x01), "mainnet", 1, Provenance::Direct)
            .with_address(Address::new("not-an-ip", 9444, AddressKind::Direct))
            .with_address(Address::direct("198.51.100.7", 9444));
        assert_eq!(
            best_socket_addr(&e),
            Some("198.51.100.7:9444".parse().unwrap()),
            "skips the hostname, takes the IP literal"
        );
        // A relay-only / addressless entry has nothing to dial directly.
        let relay_only = PeerEntry::new(hexid(0x01), "mainnet", 1, Provenance::Direct);
        assert_eq!(best_socket_addr(&relay_only), None);
        // A zero port is not dialable.
        let zero = PeerEntry::new(hexid(0x01), "mainnet", 1, Provenance::Direct)
            .with_address(Address::new("198.51.100.7", 0, AddressKind::Direct));
        assert_eq!(best_socket_addr(&zero), None);
    }

    #[test]
    fn pool_peer_entry_is_first_hand_direct_with_storage_flag() {
        let addr: std::net::SocketAddr = "203.0.113.5:9444".parse().unwrap();
        let e = pool_peer_entry(hexid(0x02), addr, "mainnet");
        assert_eq!(e.peer_id, hexid(0x02));
        assert_eq!(
            e.via,
            Provenance::Direct,
            "we are connected → first-hand direct"
        );
        assert_eq!(e.network_id, "mainnet");
        assert_eq!(e.addresses[0].host, "203.0.113.5");
        assert_eq!(e.addresses[0].port, 9444);
        assert!(e.flags.iter().any(|f| f == NODE_PEX_FLAG));
    }
}
