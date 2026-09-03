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

/// Start a real gossip service with an EMPTY pool and the default `max_connections`, on its own
/// ephemeral port.
async fn running_gossip() -> (
    dig_gossip::GossipService,
    dig_gossip::GossipHandle,
    tempfile::TempDir,
) {
    running_gossip_with_max_connections(dig_gossip::GossipConfig::default().max_connections).await
}

/// Same as [`running_gossip`], with `max_connections` set explicitly so a test can put the
/// accepted-direct-inbound cap somewhere small enough to hit deliberately.
async fn running_gossip_with_max_connections(
    max_connections: usize,
) -> (
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
        max_connections,
        // GossipConfig::new/validate refuses target_outbound_count > max_connections (this node
        // never dials in this test, so the outbound target is irrelevant to what's under test).
        target_outbound_count: max_connections
            .min(dig_gossip::GossipConfig::default().target_outbound_count),
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

/// **The accepted-direct-inbound CAP still binds after a supersede + stale-release cycle.**
///
/// `a_reconnect_does_not_let_the_stale_session_evict_the_live_one` (above) proves the SURVIVOR's slot
/// is not evicted by the stale release. This test proves the more serious consequence named in that
/// test's own doc comment: if the stale release COULD evict a live slot, the accounted count would
/// fall below the served count, and the accepted-direct cap that `max_direct_inbound` /
/// `max_inbound_total` enforce would be bypassable by any peer willing to reconnect. This test drives
/// exactly that cycle once, then asks a NET-NEW peer to connect and checks the cap actually refuses
/// it — the discriminating question `a_reconnect_...` does not ask.
///
/// ## Why `max_connections: 2`
///
/// The caps are derived (crate-private, `dig-gossip/src/service/peer_pool.rs`) as:
///
/// * `reserving_a_quarter(n) = n - max(n/4, 1)`
/// * `max_inbound_total(2)   = reserving_a_quarter(2)                = 1`
/// * `max_direct_inbound(2)  = reserving_a_quarter(max_inbound_total(2)).max(1).min(max_inbound_total(2))`
///                           `= reserving_a_quarter(1).max(1).min(1) = 1`
/// * `max_direct_inbound_per_group(2) = max_direct_inbound(2).div_ceil(4).max(2) = 1.div_ceil(4).max(2) = 2`
///
/// So at `max_connections = 2` the accepted-direct cap is exactly **1**, and it is `max_direct_inbound`
/// / `max_inbound_total` doing the refusing — the per-source-group cap is 2 and is NOT what binds here,
/// so this fixture does not (and must not be read to) exercise that cap. `max_connections: 1` is not
/// usable instead: `max_inbound_total(1) = 0`, which denies the accepted-direct tier outright rather
/// than reserving it a single slot.
#[tokio::test]
async fn the_accepted_direct_cap_still_binds_after_a_supersede_and_stale_release() {
    dig_node_core::peer::install_crypto_provider();

    let (service, gossip, _gdir) = running_gossip_with_max_connections(2).await;

    let server_identity = test_identity("3124-cap-server");
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

    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(5))
        .build();

    // Peer A takes the single accepted-direct slot the cap allows.
    let a_identity = test_identity("3124-cap-peer-a");
    let a_peer_id = a_identity.peer_id();
    let target = dig_nat::PeerTarget::with_addr(server_peer_id, listen_addr, "DIG_MAINNET");
    let first = dig_nat::connect(&target, &a_identity, &config)
        .await
        .expect("peer A connects");
    await_peer_count(&gossip, 1, "after peer A's first connection").await;

    // A reconnects with the SAME identity. This is admitted for FREE — `replaces_accepted_direct`
    // (gossip_handle.rs:2054) exempts a slot that is itself an accepted-direct peer — so the cap is
    // never charged twice and the count stays at 1. The first session is now superseded but still
    // running; its serve loop has not yet noticed its socket is dead.
    let mut second = dig_nat::connect(&target, &a_identity, &config)
        .await
        .expect("peer A reconnects");
    await_peer_count(
        &gossip,
        1,
        "a same-identity reconnect supersedes rather than adds a slot",
    )
    .await;

    // End the STALE session and let its release run. This wait is load-bearing, not cosmetic: without
    // it, step 6 below could race ahead of the stale release and refuse peer B for the wrong reason
    // (the cap correctly still holding peer A's original session), passing the assertion vacuously
    // whether or not the fix at `peer.rs:3597` is present. Giving the release a full second to fire
    // means a subsequent refusal of B is caused by the cap seeing A's (single) survived slot, not by
    // timing luck.
    drop(first);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Peer B is a NET-NEW identity asking for the accepted-direct slot the cap says is full.
    let b_identity = test_identity("3124-cap-peer-b");
    let b_peer_id = b_identity.peer_id();
    let b_pool_id = dig_gossip::PeerId::from(*b_peer_id.as_bytes());
    let mut b_conn = dig_nat::connect(&target, &b_identity, &config)
        .await
        .expect(
            "B's transport-level connect succeeds even though the pool refuses to ADOPT it -- \n             adoption is best-effort accounting (see the file-level doc comment), and a refused \n             adoption must never refuse the underlying connection",
        );

    // Hold the assertions in a loop rather than checking once: under the defect, the stale release
    // (from `first` above) can land late and evict A's surviving slot AFTER B has already been let in
    // by the now-appearing headroom — a single-shot check taken too early would miss that.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        let a_pool_id = dig_gossip::PeerId::from(*a_peer_id.as_bytes());
        assert!(
            gossip.is_pool_peer(&a_pool_id),
            "peer A's surviving session must keep its slot — the stale session's release must not \
             evict the live one"
        );
        assert!(
            !gossip.is_pool_peer(&b_pool_id),
            "the accepted-direct cap is exactly 1 at max_connections=2 (see the doc comment above); \
             a net-new peer must be refused while A still holds the only slot, or the cap is \
             bypassable by reconnect-then-release"
        );
        assert_eq!(
            gossip.peer_count().await,
            1,
            "one accepted-direct slot is held; driving the count above the cap is the bypass this \
             test exists to catch"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Both A and B must still be SERVED -- this is the anti-vacuity check. Without it,
    // `is_pool_peer(B) == false` is equally satisfied by B never having connected at all, which would
    // prove nothing about the CAP specifically. Confirming B's RPC still answers while B stays outside
    // the pool demonstrates the real contract named in the file-level doc comment: adoption is
    // best-effort accounting, and a refused adoption must never cost the caller a working connection
    // to the peer it already holds.
    let mut a_stream = second.session.open_stream().await.expect("open stream");
    let a_req = json!({"jsonrpc":"2.0","id":11,"method":"dig.getNetworkInfo"});
    write_framed(&mut a_stream, &a_req).await.expect("write");
    let a_resp = read_one_frame(&mut a_stream).await;
    assert_eq!(
        a_resp["result"]["served_method"], "dig.getNetworkInfo",
        "A's surviving connection must still be answered while B sits outside the pool"
    );

    let mut b_stream = b_conn.session.open_stream().await.expect("open stream");
    let b_req = json!({"jsonrpc":"2.0","id":13,"method":"dig.getNetworkInfo"});
    write_framed(&mut b_stream, &b_req).await.expect("write");
    let b_resp = read_one_frame(&mut b_stream).await;
    assert_eq!(
        b_resp["result"]["served_method"], "dig.getNetworkInfo",
        "B's connection must still be served even though the pool refused to count it"
    );

    server.abort();
    service.stop().await.expect("stop");
}
