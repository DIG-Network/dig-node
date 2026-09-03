//! Integration test for **dig_ecosystem#3124 — an ACCEPTED inbound peer must appear in
//! `connected_peers`.**
//!
//! ## The defect
//!
//! `serve_peer_rpc_listener_with` accepted an inbound mTLS connection, derived the authenticated
//! `peer_id`, wrapped it in a yamux session and served it — and registered it nowhere. The connected
//! pool is what every subsystem reads to answer "am I connected", so a node happily serving inbound
//! peers reported `connected_peers = 0`.
//!
//! ## Why this test drives a REAL connection
//!
//! The wiring under test sits between the mTLS handshake and the serve loop, on a code path reachable
//! only by accepting a socket. A unit test around the pool cannot see it — the pool was always able to
//! hold the slot; nothing was calling it. So this dials the real listener with a real `dig-nat` client
//! over loopback, exactly as a peer would.
//!
//! ## The three things asserted, and why none implies the next
//!
//! * **COUNTED** — the pool sees the peer. This was zero.
//! * **still SERVED** — the peer's L7 RPC still answers AFTER adoption. Registering by value would buy
//!   the count and silently stop serving the peer, which is strictly worse than being uncounted; the
//!   count alone cannot distinguish the two.
//! * **RELEASED** — the slot goes away when the peer does. A membership that is never released reports
//!   a peer count that only ever grows, which is a different lie from the one being fixed.
//!
//! ## What this test deliberately does NOT assert — REACHED-by-broadcast
//!
//! dig_ecosystem#3124 also names REACHED: an adopted peer should receive a broadcast. **This test does
//! not assert that, and the omission is stated here rather than left to silence, because silence would
//! imply the property holds.** It is currently UNMEASURABLE, for the same three reasons recorded at the
//! `adopt_direct_inbound_handle` call in `peer.rs`:
//!
//! 1. there is no wire frame for a broadcast — `write_framed` is JSON and a `DigMessage` is an opaque
//!    chia-protocol payload;
//! 2. a broadcast frame would misroute anyway — `classify_request` falls to `PeerRequestKind::Unknown`;
//! 3. there is no ingest path — dig-gossip's `inbound_tx` is crate-private and fed only by its own
//!    legacy DigLink listener.
//!
//! So every dig-nat adoption site passes a `None` broadcast sink, and any REACHED assertion written
//! today would be VACUOUS: it could only observe the absence of a mechanism that does not exist. When a
//! broadcast frame and its ingest path land, the assertion belongs here.

use std::sync::Arc;
use std::time::Duration;

use dig_node_core::peer::{
    load_or_generate_node_cert, serve_peer_rpc_listener_with, write_framed, PeerRpcResponder,
};
use serde_json::{json, Value};

/// A deterministic 32-byte identity seed derived from a label — no hard-coded key material.
fn node_seed(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(label.as_bytes()).into()
}

fn test_identity(label: &str) -> Arc<dig_tls::NodeCert> {
    let dir = tempfile::tempdir().expect("cert tempdir");
    load_or_generate_node_cert(dir.path(), &node_seed(label)).expect("node cert")
}

struct TestResponder;

#[async_trait::async_trait]
impl PeerRpcResponder for TestResponder {
    async fn handle_json_rpc(&self, req: Value, _conn_key: &str) -> Value {
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        json!({"jsonrpc":"2.0","id":id,"result":{"served_method": method}})
    }
    async fn handle_availability(&self, _items: Value, _conn_key: &str) -> Value {
        json!({"items": []})
    }
    async fn stream_range(
        &self,
        _req: Value,
        _conn_key: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        write_framed(out, &json!({"complete": true})).await
    }
}

/// Start a real gossip service with an EMPTY pool, on its own ephemeral port.
async fn running_gossip() -> (
    dig_gossip::GossipService,
    dig_gossip::GossipHandle,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("gossip tempdir");
    let cfg = dig_gossip::GossipConfig {
        network_id: chia_protocol::Bytes32::new([1u8; 32]),
        cert_path: dir.path().join("node.cert").display().to_string(),
        key_path: dir.path().join("node.key").display().to_string(),
        peers_file_path: dir.path().join("peers.json"),
        peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
        listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
        ..Default::default()
    };
    let service = dig_gossip::GossipService::new(cfg).expect("gossip config");
    let handle = service.start().await.expect("gossip start");
    (service, handle, dir)
}

/// Poll `peer_count` until it reaches `want`, or fail. Adoption happens on the listener's spawned
/// task, so it is concurrent with the client's `connect` returning — a bare read races it.
async fn await_peer_count(handle: &dig_gossip::GossipHandle, want: usize, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let got = handle.peer_count().await;
        if got == want {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: peer_count settled at {got}, expected {want}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// **#3124 end to end: a peer that DIALS this node becomes a counted pool member, keeps being served,
/// and is released when it leaves.**
#[tokio::test]
async fn an_accepted_inbound_peer_is_counted_served_and_released() {
    dig_node_core::peer::install_crypto_provider();

    let (service, gossip, _gdir) = running_gossip().await;
    assert_eq!(
        gossip.peer_count().await,
        0,
        "the pool starts empty, so any count below is caused by the inbound connection"
    );

    let server_identity = test_identity("3124-inbound-server");
    let server_peer_id = server_identity.peer_id();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let listen_addr = listener.local_addr().expect("local addr");

    let responder: Arc<dyn PeerRpcResponder> = Arc::new(TestResponder);
    let server = tokio::spawn(serve_peer_rpc_listener_with(
        listener,
        server_identity,
        responder,
        None,
        Some(gossip.clone()),
    ));

    // A peer DIALS this node — the direction that was never counted.
    let client_identity = test_identity("3124-inbound-client");
    let client_peer_id = client_identity.peer_id();
    let target = dig_nat::PeerTarget::with_addr(server_peer_id, listen_addr, "DIG_MAINNET");
    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(5))
        .build();
    let mut conn = dig_nat::connect(&target, &client_identity, &config)
        .await
        .expect("the peer connects over mTLS");

    // (a) COUNTED — this was zero for every inbound peer, on every node.
    await_peer_count(&gossip, 1, "after an inbound peer connects").await;

    let pool_id = dig_gossip::PeerId::from(*client_peer_id.as_bytes());
    assert!(
        gossip.is_pool_peer(&pool_id),
        "the slot is keyed on the identity the CLIENT's certificate proved, not the server's"
    );

    let detailed = gossip.connected_pool_peers_detailed();
    let peer = detailed
        .iter()
        .find(|p| p.peer_id == pool_id)
        .expect("the inbound peer is in the pool");
    assert!(
        !peer.is_outbound,
        "this node never dialed the peer, so the slot must not be charged outbound diversity"
    );
    assert_eq!(
        peer.dial_addr, None,
        "the peer's source port is ephemeral and must never be offered as a dial target"
    );
    assert_ne!(
        peer.session_addr.port(),
        listen_addr.port(),
        "the recorded address is the CLIENT's source port, which is exactly why it is not dialable"
    );
    assert!(
        gossip.dialable_pool_peers().is_empty(),
        "an accepted peer contributes no dial target to peer selection"
    );

    // (b) STILL SERVED — adopting must not cost the serve loop its session. A count-only assertion
    // passes against the shape that buys the count and stops answering the peer.
    {
        let mut stream = conn.session.open_stream().await.expect("open stream");
        let req = json!({"jsonrpc":"2.0","id":7,"method":"dig.getNetworkInfo"});
        write_framed(&mut stream, &req).await.expect("write");
        let resp = read_one_frame(&mut stream).await;
        assert_eq!(
            resp["result"]["served_method"], "dig.getNetworkInfo",
            "the node must still answer the peer it just registered"
        );
    }
    assert_eq!(
        gossip.peer_count().await,
        1,
        "serving the peer neither duplicates nor drops its slot"
    );

    // (c) RELEASED — the peer goes away and the pool stops counting it. A slot that is never released
    // makes `connected_peers` a high-water mark rather than a count.
    drop(conn);
    await_peer_count(&gossip, 0, "after the inbound peer disconnects").await;

    server.abort();
    service.stop().await.expect("stop");
}

/// Read one length-framed JSON value.
async fn read_one_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Value {
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len))
        .await
        .expect("frame header arrives")
        .expect("frame header reads");
    let n = u32::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body))
        .await
        .expect("frame body arrives")
        .expect("frame body reads");
    serde_json::from_slice(&body).expect("frame is JSON")
}

/// **The release must be SESSION-scoped, not identity-scoped.**
///
/// dig-gossip's only removal API is `disconnect(&peer_id)`, a bare `peers.remove` keyed on IDENTITY.
/// So a peer that reconnects gets a second slot which supersedes the first (newest-wins), and when the
/// FIRST serve loop then ends, an unconditional release deletes the slot belonging to the LIVE second
/// connection. That reintroduces exactly the served-but-uncounted state this file exists to fix — and
/// repeating the cycle drives the accounted count below the served count, which is what makes
/// `max_direct_inbound` / `max_inbound_total` bypassable.
///
/// The fixture varies ONE thing — the peer reconnects — and keeps the second connection as the honest
/// control: the assertion is that the SURVIVING session stays counted AND stays served, so a fix that
/// merely stopped counting would fail the second half.
#[tokio::test]
async fn a_reconnect_does_not_let_the_stale_session_evict_the_live_one() {
    dig_node_core::peer::install_crypto_provider();

    let (service, gossip, _gdir) = running_gossip().await;

    let server_identity = test_identity("3124-supersede-server");
    let server_peer_id = server_identity.peer_id();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let listen_addr = listener.local_addr().expect("local addr");

    let responder: Arc<dyn PeerRpcResponder> = Arc::new(TestResponder);
    let server = tokio::spawn(serve_peer_rpc_listener_with(
        listener,
        server_identity,
        responder,
        None,
        Some(gossip.clone()),
    ));

    let client_identity = test_identity("3124-supersede-client");
    let target = dig_nat::PeerTarget::with_addr(server_peer_id, listen_addr, "DIG_MAINNET");
    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(5))
        .build();

    let first = dig_nat::connect(&target, &client_identity, &config)
        .await
        .expect("the peer connects");
    await_peer_count(&gossip, 1, "after the first connection").await;

    // The SAME identity reconnects. dig-gossip's newest-wins admission supersedes the first slot with
    // this one; the first slot's serve loop is still running and will release when its socket dies.
    let mut second = dig_nat::connect(&target, &client_identity, &config)
        .await
        .expect("the peer reconnects");
    await_peer_count(&gossip, 1, "a reconnect supersedes rather than adds a slot").await;

    // Now end the STALE session. Its serve loop returns and releases — and must not touch the slot
    // that now belongs to `second`.
    drop(first);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        assert_eq!(
            gossip.peer_count().await,
            1,
            "the stale session's release evicted the LIVE connection's slot: the peer is served but \
             uncounted again, which is what makes the inbound caps bypassable"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The surviving connection is the control: it must still be SERVED, so a fix that keeps the count
    // right by refusing service would not pass here.
    let mut stream = second.session.open_stream().await.expect("open stream");
    let req = json!({"jsonrpc":"2.0","id":9,"method":"dig.getNetworkInfo"});
    write_framed(&mut stream, &req).await.expect("write");
    let resp = read_one_frame(&mut stream).await;
    assert_eq!(
        resp["result"]["served_method"], "dig.getNetworkInfo",
        "the surviving connection must still be answered"
    );

    server.abort();
    service.stop().await.expect("stop");
}
