//! L7 content-location DHT (PHASE-B, #163) — the node uses a Kademlia DHT to LOCATE which peers hold
//! content, and keeps its OWN held-inventory provider records CURRENT in the DHT.
//!
//! This layer sits ON TOP of the phase-2b peer network ([`crate::peer`]): the DHT rides the SAME
//! dig-nat mTLS transport the peer RPC uses (peer_id = SHA-256(TLS SPKI DER)), so there is no
//! unauthenticated DHT traffic. It composes three things dig-dht ([`dig_dht`]) leaves to the node:
//!
//! 1. **A [`DhtTransport`] over dig-nat** ([`NatDhtTransport`]): "send this [`DhtRequest`] to that
//!    peer, give me the [`DhtResponse`]." It dials a peer over dig-nat's NAT-traversal ladder (mTLS,
//!    peer_id pinned), opens ONE logical stream, writes `request.encode()`, reads `DhtResponse::decode`,
//!    bounded by an RPC timeout, mapping every failure to [`DhtError::transport`] (which the lookup
//!    treats as "that peer is unreachable" and moves on).
//! 2. **Bring-up + maintenance** ([`DhtHandle`], [`run_maintenance`]): construct a [`DhtService`] for
//!    this node (the standalone `run()` path wires it in [`crate::peer`]'s peer-network bring-up),
//!    bootstrap it from the dig-gossip peer pool + the relay introducer as [`BootstrapPeer`]s
//!    ([`bootstrap_peers_from_pool`]), then run the periodic maintenance loop (`republish` /
//!    `refresh_buckets` / `gc`) so provider records never lapse and the routing table stays fresh.
//! 3. **Inventory publishing** (the emphasized requirement): the node continuously keeps its provider
//!    records current — [`announce_inventory`] on startup for every held capsule (at store AND
//!    root/capsule granularity), [`sync_inventory`] on inventory change (announce new content,
//!    withdraw removed content), `republish()` before TTL via the maintenance loop, and a best-effort
//!    `withdraw_provider` sweep on graceful shutdown.
//!
//! ## Serving the inbound DHT RPC
//!
//! A node is both a DHT client and a DHT server. Inbound DHT logical streams are dispatched (by the
//! peer-RPC listener in [`crate::peer`]) to [`DhtService::handle_request_from`], passing the
//! mTLS-verified caller [`Contact`] so the routing table populates bidirectionally the way Kademlia
//! tables fill. This module owns the classification ([`is_dht_request`]) + the caller construction
//! ([`caller_contact`]) that the listener uses.
//!
//! ## The clean seam for #164 (dig-download)
//!
//! [`DhtHandle::locate_providers`] answers "who holds this ContentId?" by running `find_providers` and
//! returning the live [`ProviderRecord`]s; [`availability_item_for`] turns a located capsule
//! ContentId into the [`AvailabilityItem`] a finder confirms against a provider before fetching. That
//! is the clean locate→provider→availability→fetch seam the full multi-source range orchestration
//! (#164 dig-download) consumes — it takes exactly this provider set.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use dig_dht::{
    BootstrapPeer, CandidateAddr, Contact, DhtError, DhtRequest, DhtResponse, DhtService,
    DhtTransport, PeerId, ProviderRecord,
};
use dig_nat::mux::AvailabilityItem;

use crate::CachedCapsule;

/// The DHT wire request `type` tokens — the four Kademlia methods dig-dht speaks. An inbound peer
/// frame is a DHT request iff its `type` is one of these (see [`is_dht_request`]). Frozen wire
/// contract (must match dig-dht's `#[serde(rename_all = "snake_case")]` variants).
const DHT_REQUEST_TYPES: [&str; 4] = ["find_node", "find_providers", "add_provider", "ping"];

// -- DhtTransport over dig-nat -----------------------------------------------------------------------

/// Bounds one outbound DHT RPC (dial + stream write + response read). A DHT lookup fans α RPCs per
/// round; a slow/unreachable peer must not stall the round, so each RPC is capped. Matches the
/// dig-dht [`dig_dht::DhtConfig::rpc_timeout`] default (5s) unless the node overrides it.
const DEFAULT_DHT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// A [`DhtTransport`] implemented over dig-nat: each RPC dials the target peer over the NAT-traversal
/// ladder (mTLS, peer_id pinned + verified during the handshake), opens ONE logical stream on the
/// muxed connection, writes the length-prefixed [`DhtRequest`], and reads the framed [`DhtResponse`].
///
/// The DHT RPC therefore "rides" the exact same authenticated transport the content fetch uses — no
/// separate, unauthenticated DHT channel exists. A dial/stream/parse failure (or a timeout) becomes a
/// [`DhtError::transport`], which the iterative lookup treats as "that peer is unreachable" and skips.
///
/// One connection PER RPC (not pooled) keeps this adapter simple + correct; the DHT's traffic is low
/// (a handful of small RPCs per lookup, on the maintenance cadence). A pooled dialer is a transparent
/// future optimization behind this same trait.
pub struct NatDhtTransport {
    /// This node's mTLS identity — presented as the CLIENT cert on every dial, so the responder
    /// authenticates THIS node's peer_id from the certificate (never from the wire body).
    identity: dig_nat::LocalIdentity,
    /// The network id the target peers registered under (scopes relay-coordinated dials).
    network_id: String,
    /// Per-RPC timeout (dial + exchange).
    rpc_timeout: Duration,
}

impl NatDhtTransport {
    /// A transport that dials peers as `identity`, scoping relay lookups to `network_id`, bounding
    /// each RPC by `rpc_timeout`.
    pub fn new(
        identity: dig_nat::LocalIdentity,
        network_id: impl Into<String>,
        rpc_timeout: Duration,
    ) -> Self {
        NatDhtTransport {
            identity,
            network_id: network_id.into(),
            rpc_timeout,
        }
    }

    /// Build the dig-nat [`PeerTarget`](dig_nat::PeerTarget) for `peer`: its verified `peer_id` plus
    /// its FULL list of directly-dialable candidate addresses (via [`candidate_socket_addrs`]). The
    /// candidates are passed to [`PeerTarget::with_addrs`](dig_nat::PeerTarget::with_addrs), which
    /// stores them **IPv6-first** (ecosystem HARD RULE), so dig-nat's happy-eyeballs dialer tries the
    /// peer's IPv6 candidate(s) first and falls back to IPv4. A contact with NO dialable candidate
    /// becomes a `relay_only` target — dig-nat reaches it via the relay-coordinated tiers. `None` only
    /// if the contact's `peer_id` hex is malformed (unreachable).
    fn target_for(&self, peer: &Contact) -> Option<dig_nat::PeerTarget> {
        let peer_id = peer.peer_id()?;
        let addrs = candidate_socket_addrs(peer);
        if addrs.is_empty() {
            Some(dig_nat::PeerTarget::relay_only(
                peer_id,
                self.network_id.clone(),
            ))
        } else {
            // `with_addrs` sorts the candidates IPv6-first for us; we pass the full list so the
            // fallback ladder has every family to try, not just one collapsed address.
            Some(dig_nat::PeerTarget::with_addrs(
                peer_id,
                addrs,
                self.network_id.clone(),
            ))
        }
    }

    /// The dig-nat config for a DHT dial: bound each traversal method by the RPC timeout, and offer
    /// Direct + Relayed (a direct candidate is tried first, falling back to the relay for a NAT'd
    /// peer). Kept minimal + honest — the same tiers the peer-RPC client dials with.
    fn nat_config(&self) -> dig_nat::NatConfig {
        dig_nat::NatConfig::builder()
            .enabled_methods(vec![
                dig_nat::TraversalKind::Direct,
                dig_nat::TraversalKind::Relayed,
            ])
            .per_method_timeout(self.rpc_timeout)
            .build()
    }
}

#[async_trait]
impl DhtTransport for NatDhtTransport {
    async fn rpc(
        &self,
        _from: &Contact,
        peer: &Contact,
        request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        // `from` is authenticated by the mTLS certificate we present (this node's identity), NOT the
        // wire body — the responder derives our peer_id from the cert, so we do not send it here.
        let target = self
            .target_for(peer)
            .ok_or_else(|| DhtError::transport(format!("unreachable peer {}", peer.peer_id)))?;

        // The whole dial+exchange is bounded so a lookup round never stalls on one peer.
        let exchange = async {
            let mut conn = dig_nat::connect(&target, &self.identity, &self.nat_config())
                .await
                .map_err(|e| DhtError::transport(format!("connect {}: {e}", peer.peer_id)))?;
            let mut stream = conn
                .open_stream()
                .await
                .map_err(|e| DhtError::transport(format!("open stream {}: {e}", peer.peer_id)))?;
            write_dht_request(&mut stream, request)
                .await
                .map_err(|e| DhtError::transport(format!("write request {}: {e}", peer.peer_id)))?;
            read_dht_response(&mut stream)
                .await
                .map_err(|e| DhtError::transport(format!("read response {}: {e}", peer.peer_id)))
        };

        match tokio::time::timeout(self.rpc_timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(DhtError::transport(format!(
                "rpc to {} timed out after {:?}",
                peer.peer_id, self.rpc_timeout
            ))),
        }
    }
}

/// Write a [`DhtRequest`] to `w` using dig-dht's own framing (`request.encode()` = `u32`-BE length
/// prefix + JSON body — byte-identical to the peer-network control framing) and flush it.
async fn write_dht_request<W: AsyncWriteExt + Unpin + ?Sized>(
    w: &mut W,
    request: &DhtRequest,
) -> std::io::Result<()> {
    w.write_all(&request.encode()).await?;
    w.flush().await
}

/// Read + decode a [`DhtResponse`] from `r` using dig-dht's own framed decoder (bounded by
/// `dig_dht::wire::MAX_FRAMED_BODY` against a hostile length prefix).
async fn read_dht_response<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<DhtResponse> {
    DhtResponse::decode(r).await
}

/// Convert a dig-dht [`CandidateAddr`] to a dialable [`std::net::SocketAddr`], or `None` when it is a
/// relay-only marker or the host/port do not parse as an IP socket (a hostname candidate is not
/// directly dialable here — dig-nat resolves reachability, and a relay-only peer takes the relay
/// path). Pure so the address mapping is unit-tested without a socket.
fn candidate_to_socket_addr(c: &CandidateAddr) -> Option<std::net::SocketAddr> {
    if !c.kind.is_dialable() {
        return None;
    }
    let ip: std::net::IpAddr = c.host.parse().ok()?;
    Some(std::net::SocketAddr::new(ip, c.port))
}

/// All of a [`Contact`]'s directly-dialable candidate addresses, as [`SocketAddr`](std::net::SocketAddr)s,
/// preserving the contact's order (relay-only markers + non-IP hostnames dropped — see
/// [`candidate_to_socket_addr`]). Passed to `PeerTarget::with_addrs`, which re-orders them IPv6-first,
/// so the dig-nat dialer can try every candidate (IPv6 first, then the IPv4 fallback) rather than a
/// single collapsed address. Pure so the mapping is unit-tested without a socket or an identity.
fn candidate_socket_addrs(peer: &Contact) -> Vec<std::net::SocketAddr> {
    peer.addresses
        .iter()
        .filter_map(candidate_to_socket_addr)
        .collect()
}

// -- Inbound DHT-RPC classification + caller identity ------------------------------------------------

/// Whether an inbound peer-request frame is a DHT RPC (its `type` is one of the four DHT methods).
/// The peer-RPC listener calls this to route a frame to the DHT serving side rather than the
/// JSON-RPC / availability / range dispatch. Pure so the classification is unit-tested directly.
///
/// DHT frames carry `type` and never `method` (JSON-RPC) / `length` (range) / `items` (availability),
/// so this is disjoint from [`crate::peer::classify_request`]'s shapes — a DHT frame is checked FIRST.
pub fn is_dht_request(v: &Value) -> bool {
    v.get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| DHT_REQUEST_TYPES.contains(&t))
}

/// Build the DHT [`Contact`] for an authenticated caller from its mTLS-verified `peer_id` and the
/// remote socket address the connection runs over. The caller is fed to
/// [`DhtService::handle_request_from`] so every inbound DHT RPC teaches this node about the caller
/// (bidirectional routing-table population — the core Kademlia table-fill). The address is recorded
/// as a `direct` candidate (it is the endpoint we actually received the connection from).
///
/// `peer_id` MUST come from the authenticated transport (the certificate), never the request body —
/// identity is not self-asserted. Pure so the mapping is unit-tested without a live connection.
pub fn caller_contact(peer_id: &PeerId, remote_addr: std::net::SocketAddr) -> Contact {
    Contact::new(
        peer_id,
        vec![CandidateAddr::direct(
            remote_addr.ip().to_string(),
            remote_addr.port(),
        )],
    )
}

/// Decode + dispatch one inbound DHT-RPC frame against `dht`, folding the authenticated `caller` into
/// the routing table, and return the framed [`DhtResponse`] bytes ready to write back on the stream.
///
/// `frame` is the raw JSON value already read off the stream (dig-dht requests are `type`-tagged JSON,
/// the same framing the listener reads for every peer frame). A frame that does not deserialize to a
/// [`DhtRequest`] yields a `DhtResponse::Error` (advisory) rather than dropping the stream. This keeps
/// the serving side purely local (no outbound RPC), so it can never recurse or block on the network.
pub async fn handle_dht_frame(dht: &DhtService, caller: Option<Contact>, frame: &Value) -> Vec<u8> {
    let response = match serde_json::from_value::<DhtRequest>(frame.clone()) {
        Ok(req) => dht.handle_request_from(caller, req).await,
        Err(e) => DhtResponse::Error {
            code: 2,
            message: format!("malformed DHT request: {e}"),
        },
    };
    response.encode()
}

// -- Inventory → ContentId publishing ----------------------------------------------------------------

/// The set of [`ContentId`](dig_dht::ContentId)s this node should announce for its local inventory,
/// derived from the cached capsules ([`Node::cache_list_cached`](crate::Node::cache_list_cached)).
///
/// Announced at TWO granularities so lookups line up with the L7 `dig.getAvailability` item shapes:
/// - **store** (`ContentId::store(store_id)`) — "this node serves store X at all" (deduped per store),
/// - **root / capsule** (`ContentId::capsule(store_id, root)`) — "this node holds this exact
///   generation `store_id:root`".
///
/// Resource granularity (`+ retrieval_key`) is intentionally NOT announced from the capsule inventory:
/// a capsule holder serves EVERY resource in it, so a per-resource record would be redundant with the
/// capsule record and would explode the DHT write volume. A finder resolves store/capsule → provider,
/// then confirms the specific resource with `dig.getAvailability` against that provider.
///
/// Returns 64-hex-keyed [`dig_dht::ContentId`]s; a malformed (non-64-hex) store/root in the inventory
/// is skipped (it can never be a valid content key). Pure over the cached list so it is unit-tested
/// without a node or a disk.
pub fn inventory_content_ids(cached: &[CachedCapsule]) -> Vec<dig_dht::ContentId> {
    use std::collections::BTreeSet;
    let mut out = Vec::new();
    let mut seen_stores: BTreeSet<[u8; 32]> = BTreeSet::new();
    for c in cached {
        let (Some(store), Some(root)) = (hex64(&c.store_id), hex64(&c.root)) else {
            continue; // skip a malformed inventory entry (never a valid content key)
        };
        if seen_stores.insert(store) {
            out.push(dig_dht::ContentId::store(store));
        }
        out.push(dig_dht::ContentId::capsule(store, root));
    }
    out
}

/// Announce EVERY content id for the node's current inventory into the DHT (`announce_provider` per
/// id). Called on startup once the DHT is bootstrapped, so peers can immediately find the content this
/// node holds. Returns the number of content ids announced. Best-effort: a PUT that reaches no peers
/// (empty routing table) still stores the record locally + is retried by `republish`.
pub async fn announce_inventory(dht: &DhtService, cached: &[CachedCapsule]) -> usize {
    let ids = inventory_content_ids(cached);
    for id in &ids {
        let _ = dht.announce_provider(id).await;
    }
    ids.len()
}

/// The diff between a previous and a current inventory content-id set: `(to_announce, to_withdraw)`.
/// `to_announce` = ids present now but not before (new capsule committed / root advanced / content
/// added); `to_withdraw` = ids present before but gone now (content removed / store deleted). Pure so
/// the change-reaction policy is unit-tested directly.
pub fn inventory_diff(
    previous: &[dig_dht::ContentId],
    current: &[dig_dht::ContentId],
) -> (Vec<dig_dht::ContentId>, Vec<dig_dht::ContentId>) {
    use std::collections::HashSet;
    let prev: HashSet<_> = previous.iter().copied().collect();
    let cur: HashSet<_> = current.iter().copied().collect();
    let to_announce = current
        .iter()
        .copied()
        .filter(|c| !prev.contains(c))
        .collect();
    let to_withdraw = previous
        .iter()
        .copied()
        .filter(|c| !cur.contains(c))
        .collect();
    (to_announce, to_withdraw)
}

/// React to an inventory change: `announce_provider` newly-held content ids promptly (don't wait for
/// the periodic republish tick) and `withdraw_provider` ids the node no longer holds (they then age
/// out of the DHT via TTL). Returns `(announced, withdrawn)` counts. `previous` is the last-known
/// content-id set, `current` is derived from the fresh inventory.
pub async fn sync_inventory(
    dht: &DhtService,
    previous: &[dig_dht::ContentId],
    cached: &[CachedCapsule],
) -> (usize, usize) {
    let current = inventory_content_ids(cached);
    let (to_announce, to_withdraw) = inventory_diff(previous, &current);
    for id in &to_announce {
        let _ = dht.announce_provider(id).await;
    }
    for id in &to_withdraw {
        dht.withdraw_provider(id).await;
    }
    (to_announce.len(), to_withdraw.len())
}

// -- Bootstrap peers from the gossip pool ------------------------------------------------------------

/// Build the DHT [`BootstrapPeer`] set from the dig-gossip connected pool (`peer_id` + a direct
/// address per pooled peer). These are already mTLS-authenticated links the node maintains, so they
/// are the natural seed for the DHT routing table. The relay introducer contributes additional peers
/// through the SAME pool (dig-gossip discovers introducer peers into the pool), so this one source
/// covers both "the pool" and "relay-introducer peers" the task calls for.
///
/// `pool` is the `(peer_id_bytes, addr, _outbound)` triples from
/// [`dig_gossip::GossipHandle::connected_pool_peers`]. Pure over that list so it is unit-tested
/// without a live pool.
pub fn bootstrap_peers_from_pool(pool: &[([u8; 32], std::net::SocketAddr)]) -> Vec<BootstrapPeer> {
    pool.iter()
        .map(|(peer_id, addr)| {
            BootstrapPeer::direct(
                PeerId::from_bytes(*peer_id),
                addr.ip().to_string(),
                addr.port(),
            )
        })
        .collect()
}

// -- Bring-up + maintenance loop ---------------------------------------------------------------------

/// A running node's DHT: the [`DhtService`] plus the content-id set it last announced (so an inventory
/// change can be diffed). Cloneable by `Arc`; shared between the maintenance loop, the inbound-RPC
/// serving path, and inventory-change callers.
pub struct DhtHandle {
    service: Arc<DhtService>,
    /// The content ids currently announced, guarded so [`Self::refresh_inventory`] can diff + update
    /// atomically against concurrent maintenance.
    announced: tokio::sync::Mutex<Vec<dig_dht::ContentId>>,
}

impl DhtHandle {
    /// Wrap a bootstrapped [`DhtService`], recording the initial announced content-id set.
    pub fn new(service: Arc<DhtService>, initial: Vec<dig_dht::ContentId>) -> Arc<Self> {
        Arc::new(DhtHandle {
            service,
            announced: tokio::sync::Mutex::new(initial),
        })
    }

    /// The underlying service (for the inbound-RPC serving path + diagnostics).
    pub fn service(&self) -> &Arc<DhtService> {
        &self.service
    }

    /// Re-derive the inventory content-id set from `cached` and reconcile it with the DHT: announce
    /// new ids, withdraw gone ids (see [`sync_inventory`]). Updates the remembered set. Call whenever
    /// the node's inventory changes (a capsule cached, a root advanced, a store removed). Returns
    /// `(announced, withdrawn)`.
    pub async fn refresh_inventory(&self, cached: &[CachedCapsule]) -> (usize, usize) {
        let mut announced = self.announced.lock().await;
        let (a, w) = sync_inventory(&self.service, &announced, cached).await;
        *announced = inventory_content_ids(cached);
        (a, w)
    }

    /// Locate the peers holding `content` via the DHT (`find_providers`). The returned
    /// [`ProviderRecord`]s name the holders + candidate addresses; the node then connects to them over
    /// dig-nat and fetches over the L7 peer RPC. This is the locate seam #164 (dig-download) consumes.
    pub async fn locate_providers(
        &self,
        content: &dig_dht::ContentId,
    ) -> Result<Vec<ProviderRecord>, DhtError> {
        self.service.find_providers(content).await
    }

    /// Best-effort withdraw of every announced content id (graceful shutdown): stop advertising this
    /// node as a provider so peers don't dial a node that is going away. The records still age out via
    /// TTL if this does not reach every replica. Returns how many ids were withdrawn.
    pub async fn withdraw_all(&self) -> usize {
        let announced = self.announced.lock().await;
        for id in announced.iter() {
            self.service.withdraw_provider(id).await;
        }
        announced.len()
    }
}

/// Run the DHT maintenance loop until cancelled: on each tick, `republish()` the node's provider
/// records (so they never expire while it is online), `refresh_buckets()` (keep the routing table
/// fresh as peers churn), and `gc()` (drop expired records). Driven at `interval` (the caller passes
/// a value well inside the provider TTL, e.g. [`dig_dht::DhtConfig::republish_interval`]).
///
/// This is the online-holder half of the "records never lapse" guarantee; the on-change half is
/// [`DhtHandle::refresh_inventory`]. Never returns on its own — spawn it and abort on shutdown.
pub async fn run_maintenance(handle: Arc<DhtHandle>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick (bootstrap already announced); wait one interval before the first
    // republish so a just-announced record is not redundantly re-put on startup.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let dht = &handle.service;
        let republished = dht.republish().await;
        let refreshed = dht.refresh_buckets().await;
        let collected = dht.gc().await;
        tracing::debug!(
            republished,
            refreshed,
            collected,
            "dig-node DHT maintenance tick"
        );
    }
}

/// Build the [`AvailabilityItem`] for a capsule content id (`store_id` + `root`), used to confirm a
/// located provider actually still holds the wanted capsule before fetching. Only the capsule
/// granularity carries a concrete `(store_id, root)` to probe; a store-granularity id yields `None`
/// (the finder would first pick a concrete root). Pure so it is unit-tested without a connection.
pub fn availability_item_for(content: &dig_dht::ContentId) -> Option<AvailabilityItem> {
    match content {
        dig_dht::ContentId::Root { store_id, root } => Some(AvailabilityItem {
            store_id: hex::encode(store_id),
            root: Some(hex::encode(root)),
            retrieval_key: None,
        }),
        dig_dht::ContentId::Resource {
            store_id,
            root,
            retrieval_key,
        } => Some(AvailabilityItem {
            store_id: hex::encode(store_id),
            root: Some(hex::encode(root)),
            retrieval_key: Some(hex::encode(retrieval_key)),
        }),
        // Store granularity has no single concrete capsule to probe.
        dig_dht::ContentId::Store { .. } => None,
    }
}

/// The default per-RPC DHT timeout (exposed so bring-up + tests share the constant).
pub fn default_rpc_timeout() -> Duration {
    DEFAULT_DHT_RPC_TIMEOUT
}

/// Decode a 64-char hex string into 32 bytes, or `None` if the length/alphabet is wrong. Used to turn
/// an inventory `store_id`/`root` (lowercase 64-hex on disk) into the raw bytes a [`dig_dht::ContentId`]
/// keys over. `pub(crate)` so the download/redirect-on-miss path ([`crate::download`]) shares the exact
/// same hex→bytes mapping when deriving a [`dig_dht::ContentId`] from an RPC's store/root/retrieval_key.
pub(crate) fn hex64(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::ContentId;

    fn cap(store: &str, root: &str) -> CachedCapsule {
        CachedCapsule {
            store_id: store.to_string(),
            root: root.to_string(),
            size_bytes: 1,
            last_used_unix_ms: 1,
        }
    }

    // -- inventory_content_ids -----------------------------------------------------------------

    #[test]
    fn inventory_content_ids_covers_store_and_capsule_granularity() {
        let s = "aa".repeat(32);
        let r = "11".repeat(32);
        let ids = inventory_content_ids(&[cap(&s, &r)]);
        let sb = hex64(&s).unwrap();
        let rb = hex64(&r).unwrap();
        assert!(ids.contains(&ContentId::store(sb)), "announces the store");
        assert!(
            ids.contains(&ContentId::capsule(sb, rb)),
            "announces the capsule (store_id:root)"
        );
        assert_eq!(ids.len(), 2, "exactly store + capsule for one held capsule");
    }

    #[test]
    fn inventory_content_ids_dedupes_store_across_roots() {
        // One store, two roots → ONE store id + TWO capsule ids (store deduped).
        let s = "aa".repeat(32);
        let r1 = "11".repeat(32);
        let r2 = "22".repeat(32);
        let ids = inventory_content_ids(&[cap(&s, &r1), cap(&s, &r2)]);
        let sb = hex64(&s).unwrap();
        let store_count = ids.iter().filter(|c| **c == ContentId::store(sb)).count();
        assert_eq!(store_count, 1, "store id announced once across its roots");
        assert_eq!(ids.len(), 3, "1 store + 2 capsules");
    }

    #[test]
    fn inventory_content_ids_skips_malformed_entries() {
        // A non-64-hex store/root can never be a valid content key → skipped, not panicked.
        let ids = inventory_content_ids(&[cap("not-hex", "also-not-hex")]);
        assert!(ids.is_empty());
        // A valid capsule alongside a malformed one still yields the valid one.
        let s = "cc".repeat(32);
        let r = "dd".repeat(32);
        let ids = inventory_content_ids(&[cap("bad", "bad"), cap(&s, &r)]);
        assert_eq!(ids.len(), 2, "the one valid capsule → store + capsule");
    }

    #[test]
    fn inventory_content_ids_empty_for_empty_inventory() {
        assert!(inventory_content_ids(&[]).is_empty());
    }

    // -- inventory_diff (on-change reaction) ---------------------------------------------------

    #[test]
    fn inventory_diff_announces_new_and_withdraws_gone() {
        let sb = [1u8; 32];
        let r1 = [2u8; 32];
        let r2 = [3u8; 32];
        let previous = vec![ContentId::store(sb), ContentId::capsule(sb, r1)];
        // Root advanced: r1 gone, r2 added; store stays.
        let current = vec![ContentId::store(sb), ContentId::capsule(sb, r2)];
        let (to_announce, to_withdraw) = inventory_diff(&previous, &current);
        assert_eq!(to_announce, vec![ContentId::capsule(sb, r2)], "new capsule");
        assert_eq!(
            to_withdraw,
            vec![ContentId::capsule(sb, r1)],
            "old capsule withdrawn"
        );
    }

    #[test]
    fn inventory_diff_no_change_is_empty() {
        let sb = [5u8; 32];
        let r = [6u8; 32];
        let set = vec![ContentId::store(sb), ContentId::capsule(sb, r)];
        let (a, w) = inventory_diff(&set, &set);
        assert!(a.is_empty() && w.is_empty(), "steady state → nothing to do");
    }

    #[test]
    fn inventory_diff_store_removed_withdraws_all_its_ids() {
        let sb = [7u8; 32];
        let r = [8u8; 32];
        let previous = vec![ContentId::store(sb), ContentId::capsule(sb, r)];
        let current: Vec<ContentId> = vec![];
        let (to_announce, to_withdraw) = inventory_diff(&previous, &current);
        assert!(to_announce.is_empty());
        assert_eq!(to_withdraw.len(), 2, "store + its capsule both withdrawn");
    }

    // -- is_dht_request (inbound classification) -----------------------------------------------

    #[test]
    fn is_dht_request_matches_the_four_methods_only() {
        for t in ["find_node", "find_providers", "add_provider", "ping"] {
            assert!(
                is_dht_request(&serde_json::json!({ "type": t })),
                "{t} is a DHT request"
            );
        }
        // Non-DHT frames (the peer.rs shapes) are NOT DHT requests.
        assert!(!is_dht_request(
            &serde_json::json!({ "method": "dig.getPeers" })
        ));
        assert!(!is_dht_request(&serde_json::json!({ "length": 4096 })));
        assert!(!is_dht_request(&serde_json::json!({ "items": [] })));
        assert!(!is_dht_request(
            &serde_json::json!({ "type": "unknown_method" })
        ));
        assert!(!is_dht_request(&serde_json::json!({ "foo": "bar" })));
    }

    // -- caller_contact --------------------------------------------------------------------------

    #[test]
    fn caller_contact_records_the_authenticated_peer_and_its_addr() {
        let pid = PeerId::from_bytes([9u8; 32]);
        let addr: std::net::SocketAddr = "203.0.113.7:9444".parse().unwrap();
        let c = caller_contact(&pid, addr);
        assert_eq!(c.peer_id, pid.to_hex(), "peer_id from the certificate");
        let a = c.best_address().expect("a direct candidate");
        assert_eq!(a.host, "203.0.113.7");
        assert_eq!(a.port, 9444);
        assert!(a.kind.is_dialable());
    }

    // -- candidate_to_socket_addr --------------------------------------------------------------

    #[test]
    fn candidate_to_socket_addr_maps_dialable_ip_only() {
        let direct = CandidateAddr::direct("198.51.100.1", 9444);
        assert_eq!(
            candidate_to_socket_addr(&direct),
            Some("198.51.100.1:9444".parse().unwrap())
        );
        // A relay-only marker is not directly dialable.
        assert_eq!(
            candidate_to_socket_addr(&CandidateAddr::relay_marker()),
            None
        );
        // A hostname (not an IP literal) is not dialable via this pure mapping.
        let host = CandidateAddr::direct("peer.example", 9444);
        assert_eq!(candidate_to_socket_addr(&host), None);
    }

    // -- candidate_socket_addrs / target_for candidate list (IPv6-first) -----------------------

    #[test]
    fn candidate_socket_addrs_keeps_every_dialable_candidate() {
        // A contact advertising BOTH families (+ a relay marker + a bare hostname): the pure mapping
        // keeps only the two dialable IP candidates and drops the relay-marker + hostname. `Contact`
        // itself orders its addresses IPv6-first (ecosystem HARD RULE §5.2), so even though IPv4 is
        // advertised first on the wire, the IPv6 candidate comes first here.
        let contact = Contact::new(
            &PeerId::from_bytes([3u8; 32]),
            vec![
                CandidateAddr::direct("203.0.113.7", 9444), // IPv4 (advertised first on the wire)
                CandidateAddr::direct("2001:db8::7", 9444), // IPv6
                CandidateAddr::relay_marker(),              // dropped (not dialable)
                CandidateAddr::direct("peer.example", 9444), // dropped (not an IP literal)
            ],
        );
        let addrs = candidate_socket_addrs(&contact);
        assert_eq!(
            addrs,
            vec![
                "[2001:db8::7]:9444".parse().unwrap(),
                "203.0.113.7:9444".parse().unwrap(),
            ],
            "both dialable candidates kept (IPv6-first per Contact ordering); relay-marker + hostname dropped"
        );
    }

    #[test]
    fn candidate_socket_addrs_relay_only_contact_is_empty() {
        let contact = Contact::new(
            &PeerId::from_bytes([4u8; 32]),
            vec![CandidateAddr::relay_marker()],
        );
        assert!(
            candidate_socket_addrs(&contact).is_empty(),
            "a relay-only contact yields no direct candidates"
        );
    }

    /// The whole point of Part B: a peer advertising BOTH an IPv6 and an IPv4 candidate must yield a
    /// `PeerTarget` whose candidate list is IPv6-FIRST, so dig-nat's happy-eyeballs dialer prefers
    /// IPv6 and falls back to IPv4. Built through the real `NatDhtTransport::target_for` path.
    #[test]
    fn target_for_yields_ipv6_first_candidate_list() {
        let identity = crate::peer::identity_from_seed(&[7u8; 32]).expect("deterministic identity");
        let transport = NatDhtTransport::new(identity, "DIG_MAINNET", Duration::from_secs(1));
        // Advertised IPv4-BEFORE-IPv6 on the wire — target_for must still put IPv6 first.
        let contact = Contact::new(
            &PeerId::from_bytes([8u8; 32]),
            vec![
                CandidateAddr::direct("198.51.100.4", 9444), // IPv4 first on the wire
                CandidateAddr::direct("2001:db8::4", 9444),  // IPv6 second on the wire
            ],
        );
        let target = transport.target_for(&contact).expect("a reachable target");
        let ordered = target.direct_addrs();
        assert_eq!(ordered.len(), 2, "both families carried into the target");
        assert!(ordered[0].is_ipv6(), "IPv6 candidate is dialed first");
        assert!(ordered[1].is_ipv4(), "IPv4 is the fallback (second)");
        // The single-address accessor returns the IPv6-preferred candidate.
        assert!(
            target.direct_addr().expect("a best address").is_ipv6(),
            "direct_addr() is the IPv6-preferred candidate"
        );
    }

    #[test]
    fn target_for_relay_only_contact_has_no_direct_addrs() {
        let identity = crate::peer::identity_from_seed(&[9u8; 32]).expect("deterministic identity");
        let transport = NatDhtTransport::new(identity, "DIG_MAINNET", Duration::from_secs(1));
        let contact = Contact::new(
            &PeerId::from_bytes([10u8; 32]),
            vec![CandidateAddr::relay_marker()],
        );
        let target = transport.target_for(&contact).expect("a relay-only target");
        assert!(
            target.direct_addr().is_none(),
            "a relay-only contact becomes a relay_only target (no direct candidate)"
        );
    }

    // -- bootstrap_peers_from_pool -------------------------------------------------------------

    #[test]
    fn bootstrap_peers_from_pool_maps_each_pool_peer() {
        let pool = vec![
            ([1u8; 32], "203.0.113.1:9444".parse().unwrap()),
            ([2u8; 32], "203.0.113.2:9444".parse().unwrap()),
        ];
        let peers = bootstrap_peers_from_pool(&pool);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].peer_id, PeerId::from_bytes([1u8; 32]));
        assert_eq!(peers[0].addresses[0].host, "203.0.113.1");
        assert_eq!(peers[0].addresses[0].port, 9444);
    }

    #[test]
    fn bootstrap_peers_from_pool_empty_is_empty() {
        assert!(bootstrap_peers_from_pool(&[]).is_empty());
    }

    // -- availability_item_for -----------------------------------------------------------------

    #[test]
    fn availability_item_for_capsule_has_store_and_root() {
        let sb = [1u8; 32];
        let rb = [2u8; 32];
        let item = availability_item_for(&ContentId::capsule(sb, rb)).expect("a capsule item");
        assert_eq!(item.store_id, hex::encode(sb));
        assert_eq!(item.root, Some(hex::encode(rb)));
        assert_eq!(item.retrieval_key, None);
    }

    #[test]
    fn availability_item_for_resource_has_retrieval_key() {
        let sb = [1u8; 32];
        let rb = [2u8; 32];
        let rk = [3u8; 32];
        let item =
            availability_item_for(&ContentId::resource(sb, rb, rk)).expect("a resource item");
        assert_eq!(item.retrieval_key, Some(hex::encode(rk)));
    }

    #[test]
    fn availability_item_for_store_is_none() {
        assert!(availability_item_for(&ContentId::store([1u8; 32])).is_none());
    }

    // -- hex64 -----------------------------------------------------------------------------------

    #[test]
    fn hex64_round_trips_and_rejects_bad() {
        let s = "ab".repeat(32);
        assert_eq!(hex64(&s), Some([0xabu8; 32]));
        assert_eq!(hex64("short"), None);
        assert_eq!(hex64(&"zz".repeat(32)), None);
    }
}
