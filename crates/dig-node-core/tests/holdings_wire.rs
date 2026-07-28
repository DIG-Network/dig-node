//! REAL-WIRE conformance for the opcode-222 holdings flywheel (#1429).
//!
//! Everything here is genuine: two live `dig-gossip` services connected over a loopback **mTLS**
//! link, each presenting its own persisted `dig_tls::NodeCert`; a real signature produced by node A's
//! actual TLS leaf key; the real `frame_holdings_announce` encoder; a real transmit through the
//! connected pool; the real inbound receiver and decoder on node B; and a real `dig_dht::DhtService`
//! as the provider store `find_providers` is then queried against.
//!
//! Why this test exists as a SEPARATE layer from `holdings_ingress.rs`: a struct round-trip through a
//! helper both sides share can pass while the real wire is broken — this ecosystem has shipped exactly
//! that bug (a frame-count assertion written against `tokio::io::sink()` pinned a live defect as
//! correct). The properties only a real wire can establish are:
//!
//! 1. The announcing node's signature verifies under the SPKI its **TLS handshake** presented, so
//!    `provider_peer_id` is the same identity a peer would dial — not merely self-consistent.
//! 2. An announcement survives encode → transmit → decode across the opcode-222 frame intact.
//! 3. The ingested record is discoverable through the real `find_providers`, i.e. the flywheel's
//!    DISCOVER stage actually sees the new holder.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use dig_dht::{
    CandidateAddr, ContentId, DhtConfig, DhtError, DhtRequest, DhtResponse, DhtService,
    DhtTransport, PeerId,
};
use dig_gossip::{
    frame_holdings_announce, holdings_announce_payload, GossipConfig, GossipHandle, GossipService,
    HoldingsAnnounce, HoldingsDelta, PeerPoolConfig, HOLDINGS_ANNOUNCE,
};
use dig_node_core::peer::{install_crypto_provider, load_or_generate_node_cert};
use dig_node_core::seams::dig_peer::holdings::{
    announcement_for, reconcile_and_announce, run_first_peer_announcer, signer_from_node_cert,
    AnnounceTransport, HoldingsBroadcaster, HoldingsIngress, HoldingsInventory, PoolPresence,
};

/// The clock this test announces against — deliberately **real wall-clock**, unlike the pure-policy
/// suite in `holdings_ingress.rs` which pins an explicit `NOW`.
///
/// The distinction is load-bearing and was found the hard way: `dig_dht::DhtService` reads the system
/// clock to clamp and expire provider records, so a *pinned past* `NOW` makes every announced
/// `expires_at` already expired by the time it is ingested. The first draft of this test used a pinned
/// `NOW` and `find_providers` returned an empty set — it would have "proved" the flywheel closed while
/// only ever exercising the expired-record path. Any fixture time handed to a wall-clock API must be
/// the wall clock.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the system clock is after the Unix epoch")
        .as_secs()
}

/// A node identity plus the live gossip service presenting it.
struct WireNode {
    cert: Arc<dig_tls::NodeCert>,
    handle: GossipHandle,
    /// Kept alive so the persisted `node.crt`/`node.key` the pool listener reads are not unlinked.
    _dir: tempfile::TempDir,
}

impl WireNode {
    /// Start a pool whose TLS material IS the node's persisted `NodeCert`, exactly as production does
    /// (`gossip_identity_paths` points dig-gossip at `node.crt`/`node.key`). This is what makes the
    /// handshake identity and the announce-signing identity the SAME key — the property under test.
    async fn start(seed: [u8; 32], network: [u8; 32]) -> Self {
        let dir = tempfile::tempdir().expect("cert tempdir");
        let cert = load_or_generate_node_cert(dir.path(), &seed).expect("persist a NodeCert");
        let listen: SocketAddr = "[::1]:0".parse().expect("parse [::1]:0");
        let cfg = GossipConfig {
            network_id: chia_protocol::Bytes32::new(network),
            cert_path: dir.path().join("node.crt").display().to_string(),
            key_path: dir.path().join("node.key").display().to_string(),
            peers_file_path: dir.path().join("peers.json"),
            peer_pool: Some(PeerPoolConfig::default()),
            listen_addr: listen,
            ..Default::default()
        };
        let handle = GossipService::new(cfg)
            .expect("gossip config is valid")
            .start()
            .await
            .expect("gossip service starts");
        Self {
            cert,
            handle,
            _dir: dir,
        }
    }

    /// The `peer_id` this node's mTLS handshake presents, as 64-hex.
    ///
    /// Asserts on the way through that the handshake identity IS `SHA-256(NodeCert SPKI DER)` (§5.2),
    /// because that equality is the whole reason a holdings signature can stand in for mTLS
    /// attribution — if the pool ever presented a different cert, every announcement this node made
    /// would name an identity no peer could dial.
    fn peer_id_hex(&self) -> String {
        let handshake = hex_of(
            &self
                .handle
                .local_peer_id()
                .expect("a started service has a local peer_id"),
        );
        let from_spki = dig_tls::peer_id_from_tls_spki_der(self.cert.spki_der()).to_hex();
        assert_eq!(
            handshake, from_spki,
            "the pool must present the node's own NodeCert, so peer_id = SHA-256(SPKI DER)"
        );
        handshake
    }

    /// The loopback address a peer dials to reach this node's pool listener.
    fn dial_addr(&self) -> SocketAddr {
        let bound = self
            .handle
            .__listen_bound_addr_for_tests()
            .expect("a started pool has resolved its ephemeral port");
        format!("[::1]:{}", bound.port())
            .parse()
            .expect("loopback dial addr")
    }
}

/// Lowercase-hex a gossip `PeerId` (a chia `Bytes32`).
fn hex_of(peer_id: &dig_gossip::PeerId) -> String {
    hex::encode(peer_id.to_bytes())
}

/// Mint a persisted `NodeCert` from `seed` (its temp dir is dropped; the cert is self-contained).
fn node_cert_for(seed: [u8; 32]) -> Arc<dig_tls::NodeCert> {
    let dir = tempfile::tempdir().expect("cert tempdir");
    load_or_generate_node_cert(dir.path(), &seed).expect("NodeCert")
}

/// The pinned fixture clock for the reconcile tests — these never reach dig-dht's expiry clamp with a
/// past value, because they assert on the LOCAL provider store immediately after the reconcile.
const NOW: u64 = 1_782_000_000;

/// Records every announcement handed to the transport, in order.
#[derive(Default)]
struct RecordingTransport {
    sent: Mutex<Vec<HoldingsAnnounce>>,
}

#[async_trait::async_trait]
impl AnnounceTransport for RecordingTransport {
    async fn flood(&self, announce: &HoldingsAnnounce) -> usize {
        self.sent
            .lock()
            .expect("transport mutex")
            .push(announce.clone());
        1
    }
}

/// A transport that reaches nobody: the ingesting node's DHT only answers LOCAL queries here, so a
/// `find_providers` hit proves the record is in this node's own provider store rather than fetched
/// back off the network.
struct UnreachableTransport;

#[async_trait::async_trait]
impl DhtTransport for UnreachableTransport {
    async fn rpc(
        &self,
        _from: &dig_dht::Contact,
        _target: &dig_dht::Contact,
        _request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        Err(DhtError::Transport("unreachable in this test".to_string()))
    }
}

/// Poll until `handle` reports a connected pool peer, or the deadline elapses.
async fn await_connected(handle: &GossipHandle, deadline: Duration) -> usize {
    let start = std::time::Instant::now();
    loop {
        let n = handle.connected_pool_peers().len();
        if n >= 1 || start.elapsed() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// PROPERTY (the flywheel's RESHARE→DISCOVER hop, over the real wire): a holder's signed opcode-222
/// announcement, transmitted over a live mTLS gossip link, is verified against the identity its TLS
/// handshake presented and lands in the receiver's real DHT provider store, where `find_providers`
/// finds it.
///
/// The truthful control is the identity itself: node B verifies the announcement against
/// `SHA-256(SPKI)` recovered from the announcement, and the test asserts that value equals the
/// `peer_id` node A's **handshake** presented. A test that only checked internal self-consistency
/// would pass even if the announce were signed by an unrelated key.
#[tokio::test]
async fn a_signed_announcement_crosses_the_real_wire_and_becomes_discoverable() {
    install_crypto_provider();
    let network = [0x5au8; 32];
    let holder = WireNode::start([0x11u8; 32], network).await;
    let receiver = WireNode::start([0x22u8; 32], network).await;
    assert!(
        receiver.handle.connected_pool_peers().is_empty(),
        "a freshly started pool has no peers yet"
    );

    // -- Connect the two pools over loopback mTLS ------------------------------------------------
    let target = receiver.dial_addr();
    holder
        .handle
        .connect_to(target)
        .await
        .expect("holder dials the receiver over loopback mTLS");
    assert_eq!(
        await_connected(&receiver.handle, Duration::from_secs(10)).await,
        1,
        "the receiver accepted the inbound mTLS link"
    );

    // -- Subscribe BEFORE announcing so the frame cannot be missed -------------------------------
    let mut inbound = receiver
        .handle
        .inbound_receiver()
        .expect("a started service exposes its inbound receiver");

    // -- The holder signs with its REAL TLS leaf key and floods opcode 222 -----------------------
    let signer = signer_from_node_cert(&holder.cert).expect("the NodeCert leaf is ECDSA-P256");
    let capsule = ContentId::capsule([0xa1u8; 32], [0xb2u8; 32]);
    let serve_addr = dig_gossip::CandidateAddr {
        host: "::1".to_string(),
        port: 9_257,
    };
    let announce = announcement_for(&signer, 1, now_secs(), &[capsule], &[], &[serve_addr])
        .expect("the batch is within the protocol cap")
        .expect("a gained capsule produces an announcement");
    holder
        .handle
        .broadcast(frame_holdings_announce(&announce), None)
        .await
        .expect("the opcode-222 frame is broadcast to the connected pool");

    // -- The receiver reads the frame off the real wire ------------------------------------------
    let (sender, decoded) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (sender, msg) = inbound.recv().await.expect("inbound channel stays open");
            assert_eq!(
                msg.msg_type as u8, HOLDINGS_ANNOUNCE,
                "only the holdings frame was sent on this link"
            );
            if let Some(a) = holdings_announce_payload(&msg) {
                break (sender, a);
            }
        }
    })
    .await
    .expect("the opcode-222 frame arrives within the deadline");

    assert_eq!(
        decoded, announce,
        "the announcement survives encode -> transmit -> decode byte-for-byte"
    );
    assert_eq!(
        decoded.provider_peer_id,
        holder.peer_id_hex(),
        "the signed provider identity IS the peer_id the holder's mTLS handshake presented — so a \
         peer that discovers this record can actually dial the announcer"
    );

    // -- Verify + ingest into a REAL DhtService --------------------------------------------------
    let receiver_id = PeerId::from_hex(&receiver.peer_id_hex()).expect("64-hex peer id");
    let dht = Arc::new(DhtService::new(
        receiver_id,
        vec![CandidateAddr::direct("::1".to_string(), 9_258)],
        DhtConfig::default(),
        Arc::new(UnreachableTransport),
    ));
    let ingress = HoldingsIngress::new(receiver.peer_id_hex());
    let applied = ingress
        .accept(&dht, &hex_of(&sender), &decoded, now_secs())
        .await
        .expect("a genuinely signed announcement off the real wire is accepted");
    assert_eq!(applied.ingested, 1, "the add was ingested");

    // -- The flywheel's DISCOVER stage now sees the new holder -----------------------------------
    let providers = dht
        .find_providers(&capsule)
        .await
        .expect("a local provider-store hit needs no network");
    assert!(
        providers
            .iter()
            .any(|p| p.provider_peer_id == holder.peer_id_hex()),
        "find_providers must return the announcing holder — this is the read->cache->announce->\
         discover loop closing over the real wire; got {providers:?}"
    );

    let holders = dht
        .holders_of(&capsule)
        .await
        .expect("holders_of projects the same lookup");
    assert!(
        holders.iter().any(|h| h.to_hex() == holder.peer_id_hex()),
        "the holder-set query agrees with find_providers"
    );
}

/// PROPERTY (the RETRACT half, over the real wire): the holder's signed retract, transmitted on the
/// same real link, removes its own record from the receiver's real DHT — so an evicting node stops
/// being advertised in seconds instead of at TTL scale.
///
/// The truthful control is a SECOND, honest holder of the same capsule seeded into the receiver's DHT
/// through the ordinary serving-side path: it must still be discoverable afterwards. Without it,
/// "find_providers is now empty" would pass for a wrong implementation that wipes the whole key.
#[tokio::test]
async fn a_signed_retract_crosses_the_real_wire_and_spares_the_other_holder() {
    install_crypto_provider();
    let network = [0x5au8; 32];
    let holder = WireNode::start([0x33u8; 32], network).await;
    let receiver = WireNode::start([0x44u8; 32], network).await;

    let target = receiver.dial_addr();
    holder
        .handle
        .connect_to(target)
        .await
        .expect("holder dials the receiver");
    assert_eq!(
        await_connected(&receiver.handle, Duration::from_secs(10)).await,
        1,
        "the receiver accepted the inbound mTLS link"
    );
    let mut inbound = receiver
        .handle
        .inbound_receiver()
        .expect("inbound receiver");

    let receiver_id = PeerId::from_hex(&receiver.peer_id_hex()).expect("64-hex peer id");
    let dht = Arc::new(DhtService::new(
        receiver_id,
        vec![CandidateAddr::direct("::1".to_string(), 9_259)],
        DhtConfig::default(),
        Arc::new(UnreachableTransport),
    ));
    let ingress = HoldingsIngress::new(receiver.peer_id_hex());
    let capsule = ContentId::capsule([0xc3u8; 32], [0xd4u8; 32]);
    let signer = signer_from_node_cert(&holder.cert).expect("P-256 leaf");
    let serve_addr = dig_gossip::CandidateAddr {
        host: "::1".to_string(),
        port: 9_257,
    };

    // A truthful CONTROL holder of the same capsule, ingested through the same authenticated path.
    let other_dir = tempfile::tempdir().expect("control cert dir");
    let other_cert =
        load_or_generate_node_cert(other_dir.path(), &[0x55u8; 32]).expect("control NodeCert");
    let other_signer = signer_from_node_cert(&other_cert).expect("P-256 leaf");
    let other_id = dig_tls::peer_id_from_tls_spki_der(other_cert.spki_der()).to_hex();
    let control_add = announcement_for(
        &other_signer,
        1,
        now_secs(),
        &[capsule],
        &[],
        std::slice::from_ref(&serve_addr),
    )
    .expect("within cap")
    .expect("an add");
    ingress
        .accept(&dht, &holder.peer_id_hex(), &control_add, now_secs())
        .await
        .expect("the control holder's add is accepted");

    // The holder under test announces, then retracts, both across the real wire.
    for (seq, gained, lost) in [(1u64, vec![capsule], vec![]), (2, vec![], vec![capsule])] {
        let announce = announcement_for(
            &signer,
            seq,
            now_secs(),
            &gained,
            &lost,
            std::slice::from_ref(&serve_addr),
        )
        .expect("within cap")
        .expect("a non-empty delta");
        holder
            .handle
            .broadcast(frame_holdings_announce(&announce), None)
            .await
            .expect("frame broadcast");

        let (sender, decoded) = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (s, msg) = inbound.recv().await.expect("channel open");
                if let Some(a) = holdings_announce_payload(&msg) {
                    if a.seq == seq {
                        break (s, a);
                    }
                }
            }
        })
        .await
        .expect("the frame arrives");

        ingress
            .accept(&dht, &hex_of(&sender), &decoded, now_secs())
            .await
            .unwrap_or_else(|e| panic!("seq {seq} off the real wire must be accepted, got {e:?}"));
    }

    let providers = dht
        .find_providers(&capsule)
        .await
        .expect("local provider-store lookup");
    let ids: Vec<_> = providers
        .iter()
        .map(|p| p.provider_peer_id.clone())
        .collect();
    assert!(
        !ids.contains(&holder.peer_id_hex()),
        "the retracting holder must be gone from the provider set; got {ids:?}"
    );
    assert!(
        ids.contains(&other_id),
        "the OTHER honest holder of the same capsule must survive the retract; got {ids:?}"
    );
}

// =============================================================================================
// Inventory reconcile — the declared behaviour change, and the reconcile->flood COMPOSITION
// =============================================================================================
//
// These exercise a REAL `DhtService` through a real `DhtHandle`, because the two properties at stake
// are both about what the DHT ends up holding, and neither is visible from either half alone.

/// A cached-capsule inventory entry for `(store, root)`.
fn cached_capsule(store: u8, root: u8) -> dig_node_core::CachedCapsule {
    dig_node_core::CachedCapsule {
        store_id: hex::encode([store; 32]),
        root: hex::encode([root; 32]),
        size_bytes: 4_096,
        last_used_unix_ms: 1_782_000_000_000,
    }
}

/// A local-only DHT handle: its transport reaches nobody, so every `find_providers` answer comes from
/// this node's OWN provider store — which is exactly the state under test.
fn local_dht_handle(port: u16) -> Arc<dig_node_core::dht::DhtHandle> {
    let service = Arc::new(DhtService::new(
        PeerId::from_bytes([0x7eu8; 32]),
        vec![CandidateAddr::direct("::1".to_string(), port)],
        DhtConfig::default(),
        Arc::new(UnreachableTransport),
    ));
    dig_node_core::dht::DhtHandle::new(service, Vec::new())
}

/// PROPERTY (the declared MEDIUM behaviour change): losing a capsule must make this node STOP being
/// returned by `find_providers` IMMEDIATELY, not at TTL expiry.
///
/// This is the difference between `retract_own_provider` and the passive `withdraw_provider` it
/// replaced, and it is the whole justification for the change: `withdraw_provider` only unmarks the
/// key for republish and LEAVES the local record, so for the remainder of its TTL this node keeps
/// answering `find_providers` with itself for content it can no longer serve — one wasted dial per
/// reader. Reverting the call in `sync_inventory` reds this test on the final assertion.
#[tokio::test]
async fn losing_a_capsule_stops_this_node_being_returned_as_a_provider_at_once() {
    let dht = local_dht_handle(9_301);
    let capsule = ContentId::capsule([0x01u8; 32], [0x02u8; 32]);

    // GAIN: the node caches the capsule and reconciles.
    let gained = dht.reconcile_inventory(&[cached_capsule(0x01, 0x02)]).await;
    assert!(
        gained.gained.contains(&capsule),
        "the reconcile must report the capsule as gained; got {gained:?}"
    );
    let providers = dht
        .service()
        .find_providers(&capsule)
        .await
        .expect("local provider-store lookup");
    assert_eq!(
        providers.len(),
        1,
        "after caching, this node is discoverable as a holder"
    );

    // LOSE: the capsule leaves the inventory (an eviction, a cache-remove, a store deletion).
    let lost = dht.reconcile_inventory(&[]).await;
    assert!(
        lost.lost.contains(&capsule),
        "the reconcile must report the capsule as lost; got {lost:?}"
    );

    let after = dht
        .service()
        .find_providers(&capsule)
        .await
        .expect("local provider-store lookup");
    assert!(
        after.is_empty(),
        "a node that no longer holds a capsule must NOT still be returned as its provider — a \
         passive withdraw leaves the record to lapse via TTL and costs every reader a failed dial; \
         got {after:?}"
    );
}

/// PROPERTY (the COMPOSITION — the point of this feature): a reconcile that changes the inventory must
/// flood an announcement whose deltas are EXACTLY the ids the reconcile moved.
///
/// The two halves passing in isolation says nothing about the wiring between them. The fixture makes
/// the two directions distinguishable — one capsule GAINED while a different one is LOST in the SAME
/// reconcile — so an implementation that floods only adds, only removes, or the wrong id set is
/// observably different from a correct one.
#[tokio::test]
async fn a_reconcile_floods_exactly_the_deltas_it_moved() {
    let dht = local_dht_handle(9_302);
    let transport = RecordingTransport::default();
    let signer = signer_from_node_cert(&node_cert_for([0x64u8; 32])).expect("P-256 leaf");
    let broadcaster = HoldingsBroadcaster::new(signer, Vec::new(), 0);

    // Establish a first capsule, then reconcile to a DIFFERENT one: one gain plus one loss at once.
    let first = ContentId::capsule([0x11u8; 32], [0x12u8; 32]);
    let second = ContentId::capsule([0x21u8; 32], [0x22u8; 32]);
    reconcile_and_announce(
        &dht,
        &[cached_capsule(0x11, 0x12)],
        Some((&broadcaster, &transport)),
        NOW,
    )
    .await;
    transport.sent.lock().expect("mutex").clear();

    let delta = reconcile_and_announce(
        &dht,
        &[cached_capsule(0x21, 0x22)],
        Some((&broadcaster, &transport)),
        NOW,
    )
    .await;

    assert!(delta.gained.contains(&second), "the new capsule is gained");
    assert!(delta.lost.contains(&first), "the old capsule is lost");

    let sent = transport.sent.lock().expect("mutex");
    assert_eq!(sent.len(), 1, "one reconcile, one frame");
    let announced_adds: BTreeSet<_> = sent[0]
        .changes
        .iter()
        .filter_map(|c| match c {
            HoldingsDelta::Add { content_key, .. } => Some(*content_key),
            HoldingsDelta::Remove { .. } => None,
        })
        .collect();
    let announced_removes: BTreeSet<_> = sent[0]
        .changes
        .iter()
        .filter_map(|c| match c {
            HoldingsDelta::Remove { content_key } => Some(*content_key),
            HoldingsDelta::Add { .. } => None,
        })
        .collect();
    let expected_adds: BTreeSet<_> = delta
        .gained
        .iter()
        .map(|c| *c.to_key().as_bytes())
        .collect();
    let expected_removes: BTreeSet<_> = delta.lost.iter().map(|c| *c.to_key().as_bytes()).collect();

    assert_eq!(
        announced_adds, expected_adds,
        "the flooded Add deltas must be exactly the ids the reconcile gained"
    );
    assert_eq!(
        announced_removes, expected_removes,
        "the flooded Remove deltas must be exactly the ids the reconcile lost — a retract that the \
         DHT applied but the flood omitted leaves peers dialling a node that has evicted the capsule"
    );
}

/// PROPERTY (the DEGRADED bring-up branch): a node that cannot sign still reconciles its durable DHT
/// provider records — it loses only the real-time flood, never its discoverability.
///
/// `holdings: None` is the branch taken by a node whose leaf key cannot produce a P-256 holdings
/// signer, and the module documents it as "stays discoverable through the durable records alone".
/// That promise is the whole reason the flood is optional, and it was previously compile-checked only:
/// the two halves are guarded by ONE `if let (Some(..), false)` condition, so a mistake that makes the
/// missing signer short-circuit the RECONCILE too would silently make an unsigning node invisible to
/// `find_providers` — a discovery outage, not a freshness one.
///
/// The fixture therefore asserts the SURVIVING half positively (the record is really in the provider
/// store) rather than only the absent half; a test that checked "nothing was flooded" alone passes
/// identically whether or not the reconcile ran, which is precisely the defect it must exclude.
#[tokio::test]
async fn a_node_that_cannot_sign_still_reconciles_its_records_without_flooding() {
    let dht = local_dht_handle(9_304);
    let capsule = ContentId::capsule([0x41u8; 32], [0x42u8; 32]);

    let gained = reconcile_and_announce(&dht, &[cached_capsule(0x41, 0x42)], None, NOW).await;

    assert!(
        gained.gained.contains(&capsule),
        "the reconcile must run and report the gain even with no signer; got {gained:?}"
    );
    assert_eq!(
        dht.service()
            .find_providers(&capsule)
            .await
            .expect("local provider-store lookup")
            .len(),
        1,
        "a node that cannot sign an announcement must STILL be discoverable through its durable \
         provider record — losing the signer costs freshness, never discovery"
    );

    // And the loss direction, so the shared condition is exercised in both states of `delta`.
    let lost = reconcile_and_announce(&dht, &[], None, NOW).await;
    assert!(
        lost.lost.contains(&capsule),
        "the retract half must run without a signer too; got {lost:?}"
    );
    assert!(
        dht.service()
            .find_providers(&capsule)
            .await
            .expect("local provider-store lookup")
            .is_empty(),
        "an unsigning node must still stop advertising content it no longer holds"
    );
}

/// PROPERTY: a reconcile that changes nothing floods nothing, so a steady-state node is silent.
#[tokio::test]
async fn an_unchanged_reconcile_floods_nothing() {
    let dht = local_dht_handle(9_303);
    let transport = RecordingTransport::default();
    let signer = signer_from_node_cert(&node_cert_for([0x65u8; 32])).expect("P-256 leaf");
    let broadcaster = HoldingsBroadcaster::new(signer, Vec::new(), 0);
    let inventory = [cached_capsule(0x31, 0x32)];

    reconcile_and_announce(&dht, &inventory, Some((&broadcaster, &transport)), NOW).await;
    transport.sent.lock().expect("mutex").clear();

    let delta =
        reconcile_and_announce(&dht, &inventory, Some((&broadcaster, &transport)), NOW).await;

    assert!(delta.is_empty(), "an identical inventory changed nothing");
    assert!(
        transport.sent.lock().expect("mutex").is_empty(),
        "a no-op reconcile must not put a frame on the wire"
    );
}

// =============================================================================================
// The 0 -> N peer transition (#1734) — the ordering that made a holder invisible
// =============================================================================================

/// A fixed inventory, standing in for the node's cache list without a `Node` or a disk.
struct StubInventory(Vec<dig_node_core::CachedCapsule>);

#[async_trait::async_trait]
impl HoldingsInventory for StubInventory {
    async fn current(&self) -> Vec<dig_node_core::CachedCapsule> {
        self.0.clone()
    }
}

/// PROPERTY (#1734): content pinned while the pool is EMPTY reaches the first peer that connects —
/// without an unpin/repin dance and without a restart.
///
/// This is the P0 that made the live network show zero providers. The inventory-change reaction floods
/// only a NON-EMPTY delta diffed against the node's own local DHT records, and the pin at zero peers
/// moves those records — so the "announced" bookkeeping is already satisfied while nothing left the
/// box, and every later reconcile is a no-op. The node holds the capsule, believes it announced, and
/// is invisible to every peer.
///
/// WHERE THIS ASSERTS, and why it must: at the RECEIVING node's ingest, over a real two-node mTLS
/// wire. The sender's `flooded an opcode-222 announcement` log line **already prints on the broken
/// path** (with `peers=0`), so any assertion keyed on the sender passes against the defect. Only a
/// frame a peer actually decoded, verified and ingested distinguishes the two implementations.
///
/// The fixture drives the REAL ordering — pin at zero peers through the real `reconcile_and_announce`
/// with the real pool as the transport, THEN connect — because the whole defect is an ordering across
/// two nodes; a symmetric or mocked harness cannot see it. It also excludes the nearest wrong fix: an
/// announcer that re-runs the inventory RECONCILE on the peer edge computes an empty delta (the pin
/// already moved the records) and puts nothing on the wire, so this test reds for that variant too.
#[tokio::test]
async fn holdings_pinned_before_the_first_peer_reach_that_peer_when_it_connects() {
    install_crypto_provider();
    let network = [0x5bu8; 32];
    let holder = WireNode::start([0x66u8; 32], network).await;
    let receiver = WireNode::start([0x77u8; 32], network).await;
    let serve_addr = dig_gossip::CandidateAddr {
        host: "::1".to_string(),
        port: 9_257,
    };

    // -- The trap's ordering, step one: PIN while the pool is empty ------------------------------
    let inventory = vec![cached_capsule(0x9a, 0x9b)];
    let capsule = ContentId::capsule([0x9au8; 32], [0x9bu8; 32]);
    let dht = local_dht_handle(9_305);
    let signer = signer_from_node_cert(&holder.cert).expect("the NodeCert leaf is ECDSA-P256");
    let broadcaster = Arc::new(HoldingsBroadcaster::new(
        signer,
        vec![serve_addr.clone()],
        now_secs(),
    ));
    assert!(
        holder.handle.connected_pool_peers().is_empty(),
        "the defect's precondition: the pin happens with ZERO peers connected"
    );
    let pinned = reconcile_and_announce(
        &dht,
        &inventory,
        Some((
            broadcaster.as_ref(),
            &holder.handle as &dyn AnnounceTransport,
        )),
        now_secs(),
    )
    .await;
    assert!(
        pinned.gained.contains(&capsule),
        "the pin must move the node's own durable provider records — that is what poisons the diff \
         every later reconcile is computed against; got {pinned:?}"
    );

    // -- Subscribe the receiver BEFORE the link exists, so no frame can be missed ----------------
    let mut inbound = receiver
        .handle
        .inbound_receiver()
        .expect("a started service exposes its inbound receiver");

    // -- Step two: the node runs its peer-presence announcer, and a peer arrives -----------------
    let announcer = tokio::spawn(run_first_peer_announcer(
        holder.handle.clone(),
        Arc::new(StubInventory(inventory)) as Arc<dyn HoldingsInventory>,
        Arc::clone(&broadcaster),
    ));
    holder
        .handle
        .connect_to(receiver.dial_addr())
        .await
        .expect("the holder dials the receiver over loopback mTLS");

    // -- The assertion the defect cannot satisfy: the RECEIVER got the announcement --------------
    let holder_id = holder.peer_id_hex();
    let (sender, decoded) = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let (sender, msg) = inbound.recv().await.expect("inbound channel stays open");
            if let Some(a) = holdings_announce_payload(&msg) {
                if a.provider_peer_id == holder_id {
                    break (sender, a);
                }
            }
        }
    })
    .await
    .expect(
        "a capsule pinned before the first peer MUST be announced once a peer connects — no frame \
         arrived, so this holder is invisible to the peer it is connected to",
    );

    let receiver_id = PeerId::from_hex(&receiver.peer_id_hex()).expect("64-hex peer id");
    let receiver_dht = Arc::new(DhtService::new(
        receiver_id,
        vec![CandidateAddr::direct("::1".to_string(), 9_306)],
        DhtConfig::default(),
        Arc::new(UnreachableTransport),
    ));
    let ingress = HoldingsIngress::new(receiver.peer_id_hex());
    let applied = ingress
        .accept(&receiver_dht, &hex_of(&sender), &decoded, now_secs())
        .await
        .expect("the announcement off the real wire is genuinely signed and accepted");
    assert!(
        applied.ingested >= 1,
        "the receiver must INGEST the holder's pinned inventory; got {applied:?}"
    );
    let providers = receiver_dht
        .find_providers(&capsule)
        .await
        .expect("a local provider-store hit needs no network");
    assert!(
        providers.iter().any(|p| p.provider_peer_id == holder_id),
        "the peer must be able to DISCOVER the holder of the capsule it pinned before connecting; \
         got {providers:?}"
    );

    announcer.abort();
}

/// PROPERTY: peers dropping to zero and returning re-announces, because that transition is the same
/// invisibility as the first one — a node whose only peer restarts must not go silently undiscovered.
///
/// Asserted on the presence state machine rather than a wire, since the wire property above already
/// pins the announce itself; what is at stake here is only the EDGE definition. Both directions are
/// pinned: a rise fires, a further rise while peers are already present does NOT (that would re-flood
/// the whole inventory on every pool addition), and a fall to zero re-arms it.
#[test]
fn every_zero_to_nonzero_peer_transition_re_arms_the_announce() {
    let mut presence = PoolPresence::default();

    assert!(!presence.observe(0), "an empty pool announces nothing");
    assert!(presence.observe(1), "the first peer triggers the announce");
    assert!(
        !presence.observe(3),
        "growing an already-peered pool must not re-flood the whole inventory"
    );
    assert!(!presence.observe(0), "losing every peer announces nothing");
    assert!(
        presence.observe(1),
        "peers returning after a total loss must re-announce — the node was invisible again"
    );
}
