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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dig_dht::{
    CandidateAddr, ContentId, DhtConfig, DhtError, DhtRequest, DhtResponse, DhtService,
    DhtTransport, PeerId,
};
use dig_gossip::{
    frame_holdings_announce, holdings_announce_payload, GossipConfig, GossipHandle, GossipService,
    PeerPoolConfig, HOLDINGS_ANNOUNCE,
};
use dig_node_core::peer::{install_crypto_provider, load_or_generate_node_cert};
use dig_node_core::seams::dig_peer::holdings::{
    announcement_for, signer_from_node_cert, HoldingsIngress,
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
