//! [`NatModuleTransport`] — the production [`ModuleTransport`] for the whole-`.dig`-module pull (#1576).
//!
//! [`dig_download::ModuleDownloader`] plans and attributes the pull; this adapter is the only part of
//! it that touches the network. It answers the engine's two calls —
//! [`get_module_info`](ModuleTransport::get_module_info) and
//! [`fetch_module_range`](ModuleTransport::fetch_module_range) — over the node's real peer client
//! ([`DigPeer`]) on the FULL NAT-traversal ladder, mirroring `dig-download`'s own
//! `NatRangeTransport` for the resource leg.
//!
//! # Resolving a `peer_id` back to an address
//!
//! The engine hands this transport a bare 64-hex `provider_peer_id` — it has already chosen WHICH
//! holder to ask, and does not re-supply that holder's addresses. So the transport resolves the
//! address itself, from the same two sources the resource leg uses, in the same order (#836): the LIVE
//! connected pool first (a connection-verified address), then DHT discovery (an untrusted, possibly
//! stale advertisement).
//!
//! # Dial order is IPv6-first, and never via string concatenation (§5.2, #1593)
//!
//! Candidates are ordered by [`dig_download::dial_candidates`] and turned into sockets by
//! [`dig_download::candidate_socket`] — the ONE place in the ecosystem that parses a candidate host as
//! an [`IpAddr`](std::net::IpAddr) and CONSTRUCTS the socket address. `format!("{host}:{port}")` +
//! `parse::<SocketAddr>()` is wrong for every IPv6 literal (the grammar needs brackets) and that exact
//! round trip blocked the whole read leg on a host advertising `::ffff:172.31.79.22` (#1593). This
//! adapter therefore never formats an address; it delegates, and every candidate is tried in order so
//! one unusable v6 candidate cannot mask a working v4 one.
//!
//! # Errors carry no peer-supplied text (#1603/#1609)
//!
//! A failure reason is composed from this node's own vocabulary plus the peer's SENTINELLED id. The
//! crate sanitizes at its `Display`/`Debug` layer; embedding raw peer text upstream of that would
//! defeat it, so the reasons here name the step, never echo the answer.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};
use dig_download::{
    candidate_socket, dial_candidates, DownloadError, ModuleTransport, ProviderLocator,
};
use dig_peer::DigPeer;
use dig_rpc_protocol::types::{FetchModuleRangeParams, GetModuleInfoParams, ModuleInfo};

use super::pool_locator::ConnectedPool;
use crate::download::BestEffort;

/// The peer-RPC transport the module pull rides.
///
/// Holds the node's mTLS identity + the shared live [`dig_nat::NatRuntime`] (so a dial composes the
/// same hole-punch/relay tiers the rest of the node's dials do), the connected-pool address map, and a
/// discovery locator for holders that are not currently connected.
pub struct NatModuleTransport {
    /// This node's CA-signed mTLS identity, presented on every dial.
    node_cert: Arc<dig_nat::NodeCert>,
    /// Traversal method + timeout selection.
    config: dig_nat::NatConfig,
    /// The network the peers are on (guards a cross-network dial).
    network_id: String,
    /// The live traversal handles: an empty runtime dials Direct only; the node's real runtime unlocks
    /// hole-punch + relay. Shared, so it is the SAME runtime the DHT + resource legs use.
    runtime: Arc<dig_nat::NatRuntime>,
    /// LIVE connection-verified addresses per `peer_id` — consulted FIRST (#836).
    connected: ConnectedPool,
    /// Discovery fallback for a holder that is not currently connected.
    locator: Arc<dyn ProviderLocator>,
    /// Which `(capsule, peer)` pairs have already had a plain descriptor round, so the relay opt-in
    /// is an escalation rather than a default. See [`RelayEscalation`].
    escalation: RelayEscalation,
}

impl NatModuleTransport {
    /// Build the transport from the node's identity + the shared live traversal runtime.
    pub fn new(
        node_cert: Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
        runtime: Arc<dig_nat::NatRuntime>,
        connected: ConnectedPool,
        locator: Arc<dyn ProviderLocator>,
    ) -> Self {
        NatModuleTransport {
            node_cert,
            config,
            network_id: network_id.into(),
            runtime,
            connected,
            locator,
            escalation: RelayEscalation::default(),
        }
    }

    /// Every way to reach `peer_hex` for this capsule, in dial order — the pool's connection-verified
    /// addresses first, then the capsule's DHT provider record, then relay-only reachability by
    /// identity.
    ///
    /// Ordering is deliberate and load-bearing: a live pool address is one this node has already
    /// connected over, while a DHT hint is an untrusted advertisement that may be stale. Leading with
    /// the stale hint is what dead-ended the read leg at HTTP 404 despite a connected, serving holder
    /// (#836).
    async fn dial_targets(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> Result<Vec<(String, dig_nat::PeerTarget)>, DownloadError> {
        let peer = PeerId::from_hex(peer_hex).ok_or_else(|| {
            DownloadError::transport(peer_hex, "malformed provider peer_id (not 64-hex)")
        })?;

        let mut record_addrs: Vec<CandidateAddr> = self.pool_candidates(peer_hex);
        record_addrs.extend(
            self.discovered_candidates(peer_hex, store_id, root)
                .await
                .for_finding(),
        );

        // Order + cap the merged candidate set through dig-download's ONE resolver: IPv6 before IPv4
        // (§5.2), and each socket CONSTRUCTED from a parsed IpAddr rather than a formatted string
        // (#1593). A record is the only shape `dial_candidates` accepts, so build one to order by.
        let record = ProviderRecord::new(
            &module_content_key(store_id, root)?,
            &peer,
            record_addrs,
            u64::MAX,
        );
        let mut targets: Vec<(String, dig_nat::PeerTarget)> = Vec::new();
        for candidate in dial_candidates(&record) {
            match candidate_socket(candidate) {
                Ok(socket) => targets.push((
                    socket.to_string(),
                    dig_nat::PeerTarget::with_addr(peer, socket, self.network_id.clone()),
                )),
                Err(e) => tracing::warn!(
                    peer = %super::serve_log::SafeId::new(peer_hex),
                    error = %e,
                    "module pull: skipping an unusable candidate address"
                ),
            }
        }
        // Relay-only last: reachable purely by identity when no address works.
        targets.push((
            "relay-only".to_string(),
            dig_nat::PeerTarget::relay_only(peer, self.network_id.clone()),
        ));
        Ok(targets)
    }

    /// The peer's LIVE connection-verified addresses from the connected pool (empty if not connected).
    fn pool_candidates(&self, peer_hex: &str) -> Vec<CandidateAddr> {
        let guard = self
            .connected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .get(peer_hex)
            .map(|addrs| {
                addrs
                    .iter()
                    .map(|a| CandidateAddr::direct(a.ip().to_string(), a.port()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The peer's advertised addresses from capsule-granularity discovery.
    ///
    /// Best-effort by design: the live pool addresses this enriches must never be lost to a DHT
    /// error. But the emptiness it can produce is ambiguous — a walk that failed and a walk that
    /// found no advertisement look identical as a bare `Vec` — so the failure is carried out in a
    /// [`BestEffort`] rather than discarded, and a caller can only read an absence from it through
    /// `absence_established()` (dig-node#296).
    async fn discovered_candidates(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> BestEffort<CandidateAddr> {
        let Some(content) = module_content_id(store_id, root) else {
            // A non-canonical id was never asked about, so nothing was found AND nothing failed:
            // this is a genuine "no advertisement", not an unreachable source.
            return BestEffort::found(Vec::new());
        };
        let Ok(records) = self.locator.find_providers(&content).await else {
            return BestEffort::source_failed();
        };
        BestEffort::found(
            records
                .into_iter()
                .find(|r| r.provider_peer_id == peer_hex)
                .map(|r| r.addresses)
                .unwrap_or_default(),
        )
    }

    /// Dial `peer_hex`, trying every candidate in order and reporting the LAST failure with the address
    /// that produced it, so an unreachable candidate is diagnosable rather than an anonymous timeout.
    async fn connect(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> Result<DigPeer, DownloadError> {
        let mut last_error = None;
        for (addr, target) in self.dial_targets(peer_hex, store_id, root).await? {
            match DigPeer::connect_with_runtime(
                &target,
                &self.node_cert,
                &self.config,
                &self.runtime,
            )
            .await
            {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    tracing::debug!(
                        peer = %super::serve_log::SafeId::new(peer_hex),
                        candidate = %addr,
                        error = %e,
                        "module pull: dial candidate failed; trying the next address"
                    );
                    last_error = Some(format!("dial {addr}: {e}"));
                }
            }
        }
        Err(DownloadError::transport(
            peer_hex,
            last_error.unwrap_or_else(|| "no dialable candidate address".to_string()),
        ))
    }
}

/// Remembers which `(capsule, peer)` pairs have already been asked PLAINLY, so the relay opt-in is a
/// second-pass escalation rather than a property of every request.
///
/// # Why the flag cannot be unconditional
///
/// `ask_with_proxy` used to set `proxy: true` on every module request. That was inert only because
/// the module pull's provider set was holders-only: every peer it asked had announced the capsule, so
/// asking one to relay was asking a holder to serve. Once the warm locator unions the CONNECTED POOL
/// (`NodeContent::warm_provider_locator`), the provider set becomes every connected peer — and an
/// unconditional flag would turn the very first descriptor probe to each of them into a request to
/// **fetch a whole capsule on this node's behalf**, before establishing that no reachable holder
/// exists. On the module path the descriptor probe IS the relay trigger, so the widening that makes
/// a holder reachable would also make every neighbour a courier.
///
/// # What it does NOT change
///
/// This decides WHEN gate (1) of [`module_relay::relay_capsule`](super::module_relay::relay_capsule)
/// is satisfied — never WHETHER it is checked. All three gates (the requestor asked, the operator
/// opted in, the requestor is inside its proxy-class allowance) run exactly as before on the far end.
///
/// # The bound
///
/// Entries are this node's own `(capsule, peer)` choices, so growth tracks this node's own pull
/// activity rather than anything a peer controls. It is still capped: at [`Self::MAX_ENTRIES`] the
/// oldest entry is evicted, which at worst re-sends one plain round for a capsule this node stopped
/// working on long ago.
#[derive(Default)]
struct RelayEscalation {
    /// Insertion-ordered keys, so eviction is FIFO and does not need a timestamp per entry.
    order: std::sync::Mutex<std::collections::VecDeque<String>>,
    /// The same keys as a set, for the O(1) membership test the hot path makes.
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl RelayEscalation {
    /// The ledger ceiling. Sized to cover the capsules and peers one node works with concurrently
    /// with room to spare; a node past it is pulling from more distinct pairs than any single warm
    /// generation involves.
    const MAX_ENTRIES: usize = 1024;

    /// Whether this node may ask `peer` to RELAY `(store_id, root)` — true once a PLAIN round for
    /// that exact pair has already been sent and did not produce a holder.
    ///
    /// Records the pair as asked, so the answer is `false` the first time and `true` afterwards. It
    /// is deliberately not conditioned on the plain round's OUTCOME: a plain ask that succeeded ends
    /// the pull, so this is only ever consulted again after one that did not.
    fn escalate_for(&self, store_id: &str, root: &str, peer_hex: &str) -> bool {
        let key = format!("{store_id}:{root}:{peer_hex}");
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if seen.contains(&key) {
            return true;
        }
        let mut order = self.order.lock().unwrap_or_else(|p| p.into_inner());
        if order.len() >= Self::MAX_ENTRIES {
            if let Some(oldest) = order.pop_front() {
                seen.remove(&oldest);
            }
        }
        order.push_back(key.clone());
        seen.insert(key);
        false
    }
}

/// The largest framed JSON body accepted for a module DESCRIPTOR answer.
///
/// The generic peer-request reader ([`crate::peer::read_framed`]) caps at 64 KiB, which is right for
/// a REQUEST and too small for this RESPONSE: a descriptor declares one 32-byte hash and one length
/// per chunk, so the largest permitted module runs to a few hundred kilobytes of JSON. This is still
/// a hard bound — a peer cannot make this node buffer an arbitrary body by declaring one.
const MAX_DESCRIPTOR_FRAME: usize = 8 * 1024 * 1024;

/// Ask `stream` a whole-`.dig` question as a framed JSON-RPC request, declaring whether this node is
/// asking the far end to RELAY the capsule on its behalf (dig-node#276).
///
/// # Why this node frames the request itself instead of calling dig-peer's typed method
///
/// `GetModuleInfoParams` / `FetchModuleRangeParams` live in `dig-rpc-protocol` and carry no `proxy`
/// field. Adding one is a level-00 crate change and a release-first cascade through `dig-peer` ->
/// `dig-download` -> this repo, for a single boolean on a request this repo both sends and serves.
/// dig-peer's own [`DigPeer::open_stream`] is the documented escape hatch for exactly this — a
/// consumer carrying its own wire shape over the authenticated mux — and the typed method it replaces
/// is itself only a `build_request` plus a framed write over that same stream.
///
/// The flag is ADDITIVE: a peer that does not implement the relay ignores an unknown params key and
/// answers precisely as it does today, so this is safe to send to every holder unconditionally.
async fn ask_with_proxy(
    stream: &mut dig_nat::PeerStream,
    method: dig_rpc_protocol::Method,
    mut params: serde_json::Value,
    proxy: bool,
) -> std::io::Result<()> {
    declare_proxy(&mut params, proxy);
    crate::peer::write_framed(
        stream,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method.name(),
            "params": params,
        }),
    )
    .await
}

/// Write the relay opt-in into a module request's params.
///
/// A whole-`.dig` download escalates to ONION mode on a SECOND pass: if no reachable peer holds the
/// capsule, we would rather a hop fetched it for us than be told "not found" by a peer sitting one
/// hop from someone who has it. The FIRST pass is plain — see [`RelayEscalation`]. Individual
/// RESOURCE requests are unaffected and still default to DIRECT (NC-4).
///
/// The flag is ALWAYS written, including `false`: absent means "unspecified" to a reader that has
/// its own default, and this node has a specific instruction to give on every request. Extracted so
/// the wire spelling of the key is pinned by a test rather than only by a live peer.
fn declare_proxy(params: &mut serde_json::Value, proxy: bool) {
    if let Some(object) = params.as_object_mut() {
        object.insert("proxy".to_string(), serde_json::Value::Bool(proxy));
    }
}

/// Read one framed JSON-RPC response body from `stream`, bounded by [`MAX_DESCRIPTOR_FRAME`].
async fn read_response_frame(
    stream: &mut dig_nat::PeerStream,
) -> std::io::Result<serde_json::Value> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_DESCRIPTOR_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "module descriptor frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// One `dig.getModuleInfo` over `peer`, decoded into a [`ModuleInfo`]. `proxy` declares whether this
/// ask permits the far end to fetch the capsule on this node's behalf.
///
/// `None` for every failure — a refused stream, an unwritable request, an unreadable frame, an error
/// envelope, or a body that is not a descriptor. The caller turns that into one transport error whose
/// text is this node's own, so a peer can never author what this node logs (#1603).
async fn descriptor_over(
    peer: &mut DigPeer,
    store_id: &str,
    root: &str,
    proxy: bool,
) -> Option<ModuleInfo> {
    let params = serde_json::to_value(GetModuleInfoParams {
        store_id: store_id.to_string(),
        root: root.to_string(),
    })
    .ok()?;
    let mut stream = peer.open_stream().await.ok()?;
    ask_with_proxy(
        &mut stream,
        dig_rpc_protocol::Method::GetModuleInfo,
        params,
        proxy,
    )
    .await
    .ok()?;
    let response = read_response_frame(&mut stream).await.ok()?;
    serde_json::from_value(response.get("result")?.clone()).ok()
}

/// Open a `dig.fetchModuleRange` frame stream over `peer`, at the phase `proxy` names.
///
/// The phase is the CALLER's to decide and is not re-derived here: a window sent through a hop must
/// carry the relay opt-in that hop expects, or it refuses at gate (1) and the pull stalls one frame
/// after it was admitted. See [`RelayEscalation::escalate_for`] for how the caller picks it.
async fn window_stream_over(
    peer: &mut DigPeer,
    store_id: &str,
    root: &str,
    offset: u64,
    length: u64,
    proxy: bool,
) -> Option<dig_nat::PeerStream> {
    let params = serde_json::to_value(FetchModuleRangeParams {
        store_id: store_id.to_string(),
        root: root.to_string(),
        offset: Some(offset),
        length,
    })
    .ok()?;
    let mut stream = peer.open_stream().await.ok()?;
    ask_with_proxy(
        &mut stream,
        dig_rpc_protocol::Method::FetchModuleRange,
        params,
        proxy,
    )
    .await
    .ok()?;
    Some(stream)
}

#[async_trait]
impl ModuleTransport for NatModuleTransport {
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        let mut peer = self.connect(provider_peer_id, store_id, root).await?;
        let proxy = self
            .escalation
            .escalate_for(store_id, root, provider_peer_id);
        let result = descriptor_over(&mut peer, store_id, root, proxy).await;
        peer.disconnect().await;
        // The reason names the STEP and the sentinelled peer; the peer's own answer text is never
        // embedded (#1603) — the crate sanitizes at its Display layer and upstream must not defeat it.
        result.ok_or_else(|| DownloadError::transport(provider_peer_id, "getModuleInfo failed"))
    }

    async fn fetch_module_range(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, DownloadError> {
        let mut peer = self.connect(provider_peer_id, store_id, root).await?;
        // Escalation LATCHES per `(capsule, peer)` pair rather than per request: `escalate_for`
        // records on its first read, so the pair's FIRST ask — its descriptor — goes plain and every
        // later ask for that pair, windows included, is escalated. That is the bound WU2 wants: one
        // plain round is spent per pair before any relay is asked of it, and a pair whose plain round
        // produced no holder does not spend a second one. A window therefore does NOT necessarily
        // ride at its own descriptor's phase, and must not be documented as if it did.
        let proxy = self
            .escalation
            .escalate_for(store_id, root, provider_peer_id);
        let bytes = match window_stream_over(&mut peer, store_id, root, offset, length, proxy).await
        {
            Some(mut stream) => read_module_window(&mut stream, provider_peer_id, length).await,
            None => Err(DownloadError::transport(
                provider_peer_id,
                "fetchModuleRange stream refused",
            )),
        };
        peer.disconnect().await;
        bytes
    }
}

/// Reassemble one requested window from the holder's `RangeFrame` stream.
///
/// A holder legitimately answers at its OWN frame granularity, so this reads until a frame reports
/// `complete` rather than trusting the first frame — and stops the moment `length` bytes have arrived,
/// so a holder cannot make the puller buffer more than it asked for by never setting `complete`.
async fn read_module_window(
    stream: &mut dig_nat::PeerStream,
    peer_hex: &str,
    length: u64,
) -> Result<Vec<u8>, DownloadError> {
    let mut assembled: Vec<u8> = Vec::new();
    loop {
        let frame = dig_nat::RangeFrame::decode(stream)
            .await
            .map_err(|_| DownloadError::transport(peer_hex, "malformed module range frame"))?
            .ok_or_else(|| {
                DownloadError::transport(peer_hex, "module range stream ended before completion")
            })?;
        assembled.extend_from_slice(&frame.bytes);
        // The `length` bound is what makes a never-`complete` holder harmless: an unbounded read here
        // would let one peer grow this buffer without limit for the cost of one request.
        if frame.complete || assembled.len() as u64 >= length {
            break;
        }
    }
    // Return whatever arrived. The engine clips an overshoot and rejects a short range against
    // `chunk_hashes` — attribution is ITS job, and duplicating the judgement here would let the two
    // disagree.
    Ok(assembled)
}

/// The capsule-granularity [`ContentId`] naming a `(store_id, root)` module, or `None` if either id is
/// not canonical 64-hex.
fn module_content_id(store_id: &str, root: &str) -> Option<ContentId> {
    Some(ContentId::capsule(decode_id(store_id)?, decode_id(root)?))
}

/// The DHT key of the capsule a module pull names, for building the `ProviderRecord` that
/// [`dial_candidates`] orders.
fn module_content_key(store_id: &str, root: &str) -> Result<dig_dht::Key, DownloadError> {
    module_content_id(store_id, root)
        .map(|c| c.to_key())
        .ok_or(DownloadError::NotDownloadable)
}

/// Decode a canonical 64-hex id into 32 raw bytes.
fn decode_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// A peer_id → addresses map in the shape [`ConnectedPool`] holds, for the wiring tests.
#[cfg(test)]
pub(crate) fn pool_of(entries: &[(&str, &str)]) -> ConnectedPool {
    let mut map = std::collections::HashMap::new();
    for (peer, addr) in entries {
        map.insert(
            (*peer).to_string(),
            vec![addr.parse::<std::net::SocketAddr>().expect("test addr")],
        );
    }
    Arc::new(std::sync::Mutex::new(map))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical 64-hex id built from a repeated byte, so a test id can never be the wrong length.
    fn id_of(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    fn store() -> String {
        id_of(0xaa)
    }

    fn root() -> String {
        id_of(0xbb)
    }

    fn peer_hex(n: u8) -> String {
        PeerId::from_bytes([n; 32]).to_hex()
    }

    /// A locator that offers `addrs` for the given peer at capsule granularity.
    struct StubLocator {
        peer: String,
        addrs: Vec<CandidateAddr>,
    }

    #[async_trait]
    impl ProviderLocator for StubLocator {
        async fn find_providers(
            &self,
            content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            let peer = PeerId::from_hex(&self.peer).expect("test peer id");
            Ok(vec![ProviderRecord::new(
                &content.to_key(),
                &peer,
                self.addrs.clone(),
                u64::MAX,
            )])
        }
    }

    fn transport(
        connected: ConnectedPool,
        locator: Arc<dyn ProviderLocator>,
    ) -> NatModuleTransport {
        let key = dig_tls::bls::SecretKey::from_seed(&[7u8; 32]);
        NatModuleTransport::new(
            Arc::new(dig_nat::NodeCert::generate_signed(&key).expect("cert")),
            dig_nat::NatConfig::default(),
            "DIG_TESTNET",
            Arc::new(dig_nat::NatRuntime::default()),
            connected,
            locator,
        )
    }

    /// **Proves:** an IPv6 candidate becomes a dialable target with its address BRACKETED — the exact
    /// bug that blocked the entire read leg, where `format!("{host}:{port}")` + `parse::<SocketAddr>()`
    /// failed with "invalid socket address syntax" before a socket was ever opened (#1593).
    /// **Catches:** any reintroduction of string-concatenated address construction on this leg.
    #[tokio::test]
    async fn an_ipv6_candidate_is_dialable_and_bracketed() {
        let peer = peer_hex(1);
        let t = transport(
            pool_of(&[(&peer, "[::ffff:172.31.79.22]:9444")]),
            Arc::new(StubLocator {
                peer: peer.clone(),
                addrs: vec![],
            }),
        );

        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        let addrs: Vec<&str> = targets.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            addrs
                .iter()
                .any(|a| a.starts_with('[') && a.contains("]:9444")),
            "the v6 candidate must be bracketed, got {addrs:?}"
        );
    }

    /// **Proves:** IPv6 candidates are dialed BEFORE IPv4 ones (§5.2 IPv6-first, IPv4-fallback), and a
    /// relay-only target is always available last so a holder with no working address is still
    /// reachable by identity.
    #[tokio::test]
    async fn ipv6_is_dialed_before_ipv4_and_relay_only_is_last() {
        let peer = peer_hex(2);
        let t = transport(
            pool_of(&[(&peer, "10.0.0.5:9444")]),
            Arc::new(StubLocator {
                peer: peer.clone(),
                addrs: vec![CandidateAddr::direct("2001:db8::1".to_string(), 9444)],
            }),
        );

        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        let addrs: Vec<String> = targets.iter().map(|(a, _)| a.clone()).collect();
        let v6 = addrs.iter().position(|a| a.contains("2001:db8"));
        let v4 = addrs.iter().position(|a| a.contains("10.0.0.5"));
        assert!(
            v6 < v4,
            "IPv6 must lead the dial order (§5.2), got {addrs:?}"
        );
        assert_eq!(
            addrs.last().map(String::as_str),
            Some("relay-only"),
            "relay-only reachability is the final fallback, got {addrs:?}"
        );
    }

    /// **Proves:** a malformed `provider_peer_id` is refused before any dial is attempted, rather than
    /// producing a connect attempt against a peer identity that cannot exist.
    #[tokio::test]
    async fn a_malformed_peer_id_is_refused_before_dialing() {
        let t = transport(
            pool_of(&[]),
            Arc::new(StubLocator {
                peer: peer_hex(3),
                addrs: vec![],
            }),
        );
        let err = t
            .dial_targets("not-a-peer-id", &store(), &root())
            .await
            .expect_err("refused");
        assert!(matches!(err, DownloadError::Transport { .. }), "got {err}");
    }

    /// **Proves:** a DHT locate failure never removes the LIVE pool address — discovery is best-effort,
    /// and losing a connection-verified address to a transient DHT error is exactly how a reachable
    /// holder becomes unreachable (#836).
    #[tokio::test]
    async fn a_failing_locator_does_not_lose_the_live_pool_address() {
        struct FailingLocator;
        #[async_trait]
        impl ProviderLocator for FailingLocator {
            async fn find_providers(
                &self,
                _content: &ContentId,
            ) -> Result<Vec<ProviderRecord>, DownloadError> {
                Err(DownloadError::NotDownloadable)
            }
        }

        let peer = peer_hex(4);
        let t = transport(
            pool_of(&[(&peer, "10.0.0.9:9444")]),
            Arc::new(FailingLocator),
        );
        let targets = t
            .dial_targets(&peer, &store(), &root())
            .await
            .expect("targets");
        assert!(
            targets.iter().any(|(a, _)| a == "10.0.0.9:9444"),
            "the pool address survived a locator failure"
        );
    }

    /// **Proves:** the FIRST module request to a `(capsule, peer)` pair is plain, and only a SECOND
    /// pass over the same pair escalates to the relay opt-in.
    ///
    /// **Catches:** the shipped `proxy: true` on every request. That was inert while the module
    /// pull's provider set was holders-only, and stops being inert the moment the warm locator
    /// unions the connected pool: A's first descriptor probe to every connected peer would become a
    /// request to fetch a whole capsule on A's behalf, before A had established that no reachable
    /// holder exists.
    ///
    /// **Fixture design — three actors, because the nearest wrong implementations differ only in
    /// what they key on.** A single ask/re-ask pair is satisfied by a ledger keyed on the peer alone
    /// (which would relay a DIFFERENT capsule to a peer already asked about another) and equally by
    /// one keyed on the capsule alone (which would relay to a peer never asked at all). Both are
    /// plausible, both widen exactly what this bounds, and only a second capsule and a second peer
    /// can see either.
    #[test]
    fn the_relay_opt_in_is_a_second_pass_escalation_per_capsule_and_peer() {
        let escalation = RelayEscalation::default();
        let (store, root, peer) = (store(), root(), peer_hex(1));

        assert!(
            !escalation.escalate_for(&store, &root, &peer),
            "the FIRST descriptor round must be plain: nothing yet establishes that no reachable \
             holder exists, so asking this peer to relay recruits a courier before looking"
        );
        assert!(
            escalation.escalate_for(&store, &root, &peer),
            "a SECOND pass over a pair a plain round did not answer is exactly when the relay is \
             worth asking for - without this the escalation never happens and the leg is dead"
        );

        assert!(
            !escalation.escalate_for(&store, &id_of(0xcc), &peer),
            "CONTROL: a DIFFERENT capsule to the same peer is a new question, so it starts plain. \
             A ledger keyed on the peer alone would relay it."
        );
        assert!(
            !escalation.escalate_for(&store, &root, &peer_hex(2)),
            "CONTROL: the same capsule to a peer never asked is a new question too. A ledger keyed \
             on the capsule alone would relay it - to a peer that may well be the holder."
        );
    }

    /// **Proves:** the decision reaches the WIRE under the key the far end reads, in both states.
    ///
    /// **Catches:** an escalation that is computed correctly and then dropped, or written as a
    /// present-vs-absent key. `relay_capsule`'s gate (1) reads `proxy` as a boolean; omitting it on
    /// the plain pass would leave the far end applying its own default rather than this node's
    /// instruction, and pinning only the `true` case cannot tell the two apart.
    #[test]
    fn the_escalation_reaches_the_wire_in_both_states() {
        let mut plain = serde_json::json!({ "store_id": store(), "root": root() });
        declare_proxy(&mut plain, false);
        assert_eq!(plain["proxy"], serde_json::json!(false));

        let mut relayed = serde_json::json!({ "store_id": store(), "root": root() });
        declare_proxy(&mut relayed, true);
        assert_eq!(relayed["proxy"], serde_json::json!(true));
    }

    /// **Proves:** the ledger stays bounded by evicting the OLDEST entry only — everything else
    /// keeps its escalation.
    ///
    /// **Fixture design — the survivor must be inserted BEFORE the overflow, not after it.** The
    /// first version of this test filled past the cap and then checked the LAST pair inserted, which
    /// a `clear()`-on-overflow implementation passes trivially: the clear happens at the overflowing
    /// insert, and every entry added afterwards is present again regardless. Confirmed by mutation —
    /// swapping the FIFO `pop_front` for a wholesale clear left that version green. The pair that
    /// distinguishes them is one added early enough to be inside the ledger at the moment of
    /// overflow and NOT the single entry FIFO removes; so the fixture inserts `oldest`, then
    /// `survivor`, fills to exactly the cap, and overflows by ONE.
    ///
    /// The bound is read from `RelayEscalation::MAX_ENTRIES` rather than restated, so the test moves
    /// with the constant instead of pinning a private copy of it.
    ///
    /// **Assertion ORDER is load-bearing too.** `escalate_for` RECORDS on a miss, so checking
    /// `oldest` re-inserts it, overflows the ledger a second time, and evicts `survivor` — the
    /// survivor assertion has to run first, or it measures the damage the line above it did.
    #[test]
    fn the_ledger_evicts_only_the_oldest_entry() {
        let escalation = RelayEscalation::default();
        let (store, root) = (store(), root());
        let oldest = format!("{:064x}", 0);
        let survivor = format!("{:064x}", 1);

        assert!(!escalation.escalate_for(&store, &root, &oldest));
        assert!(!escalation.escalate_for(&store, &root, &survivor));
        // Fill to EXACTLY the cap (the two above included), then overflow by one.
        for n in 2..RelayEscalation::MAX_ENTRIES {
            assert!(!escalation.escalate_for(&store, &root, &format!("{n:064x}")));
        }
        let overflowing = format!("{:064x}", RelayEscalation::MAX_ENTRIES);
        assert!(!escalation.escalate_for(&store, &root, &overflowing));

        assert!(
            escalation.escalate_for(&store, &root, &survivor),
            "a pair that was in the ledger at the moment of overflow and is not the oldest must \
             keep its escalation; discarding the whole ledger would disable the second pass for \
             every live pull at once"
        );
        assert!(
            !escalation.escalate_for(&store, &root, &oldest),
            "the OLDEST pair is the one evicted, so it starts plain again - one wasted plain round \
             for a capsule this node stopped working on, never an unbounded map"
        );
    }
}
