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
        record_addrs.extend(self.discovered_candidates(peer_hex, store_id, root).await);

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

    /// The peer's advertised addresses from capsule-granularity discovery (empty on any failure —
    /// discovery is best-effort; the pool addresses above must never be lost to a DHT error).
    async fn discovered_candidates(
        &self,
        peer_hex: &str,
        store_id: &str,
        root: &str,
    ) -> Vec<CandidateAddr> {
        let Some(content) = module_content_id(store_id, root) else {
            return Vec::new();
        };
        let Ok(records) = self.locator.find_providers(&content).await else {
            return Vec::new();
        };
        records
            .into_iter()
            .find(|r| r.provider_peer_id == peer_hex)
            .map(|r| r.addresses)
            .unwrap_or_default()
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

#[async_trait]
impl ModuleTransport for NatModuleTransport {
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        let mut peer = self.connect(provider_peer_id, store_id, root).await?;
        let result = peer
            .get_module_info(&GetModuleInfoParams {
                store_id: store_id.to_string(),
                root: root.to_string(),
            })
            .await;
        peer.disconnect().await;
        // The reason names the STEP and the sentinelled peer; the peer's own answer text is never
        // embedded (#1603) — the crate sanitizes at its Display layer and upstream must not defeat it.
        result.map_err(|_| DownloadError::transport(provider_peer_id, "getModuleInfo failed"))
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
        let stream = peer
            .fetch_module_range(&FetchModuleRangeParams {
                store_id: store_id.to_string(),
                root: root.to_string(),
                offset: Some(offset),
                length,
            })
            .await;
        let bytes = match stream {
            Ok(mut stream) => read_module_window(&mut stream, provider_peer_id, length).await,
            Err(_) => Err(DownloadError::transport(
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
}
