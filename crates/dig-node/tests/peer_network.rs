//! Integration test: the node's L7 peer-RPC server answers over REAL mTLS (peer_id = SHA-256(SPKI)).
//!
//! A dig-nat client dials the node's mTLS peer-RPC listener over loopback (strategy DIRECT), opens a
//! logical stream on the yamux-muxed connection, and drives the served L7 peer RPC:
//!   - a JSON-RPC `dig.getNetworkInfo` request → a framed JSON-RPC response,
//!   - a typed `dig.getAvailability` batch (dig-nat's `query_availability`) → a framed response,
//!   - a typed `dig.fetchRange` (dig-nat's `open_range_stream`) → streamed RangeFrame(s).
//!
//! This exercises the actual mTLS handshake + client-cert requirement (an unauthenticated peer is
//! rejected by rustls) end-to-end with NO real network — both endpoints are deterministic loopback
//! identities. It proves the node SERVES the peer RPC over mTLS and that the transport is
//! interoperable with dig-nat's typed client helpers.

use std::sync::Arc;
use std::time::Duration;

use dig_node::peer::{identity_from_seed, serve_peer_rpc_listener, write_framed, PeerRpcResponder};
use serde_json::{json, Value};

/// A minimal responder standing in for the node: it answers JSON-RPC + availability + range with
/// canned, well-formed values so the test focuses on the mTLS transport + framing, not node internals.
struct TestResponder;

#[async_trait::async_trait]
impl PeerRpcResponder for TestResponder {
    async fn handle_json_rpc(&self, req: Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        json!({"jsonrpc":"2.0","id":id,"result":{"served_method": method, "peers": []}})
    }
    async fn handle_availability(&self, items: Value) -> Value {
        let n = items.as_array().map(|a| a.len()).unwrap_or(0);
        let answers: Vec<Value> = (0..n)
            .map(|_| json!({"available": true, "total_length": 1024, "chunk_count": 1}))
            .collect();
        json!({"items": answers})
    }
    async fn stream_range(
        &self,
        _req: Value,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        let frame = json!({
            "offset": 0, "length": 4, "bytes": "AAECAw==", "complete": true,
            "total_length": 4, "chunk_lens": [4], "chunk_index": 0,
        });
        write_framed(out, &frame).await
    }
}

#[tokio::test]
async fn peer_rpc_is_served_over_mtls_end_to_end() {
    // rustls needs an explicit crypto provider (aws-lc-rs is also in the graph); install ring first.
    dig_node::peer::install_crypto_provider();
    // Server identity (stable, deterministic) + a loopback listener on an OS-assigned port.
    let server_identity = identity_from_seed(&[9u8; 32]).expect("server identity");
    let server_peer_id = server_identity.peer_id;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responder: Arc<dyn PeerRpcResponder> = Arc::new(TestResponder);
    let server = tokio::spawn(serve_peer_rpc_listener(
        listener,
        server_identity,
        responder,
    ));

    // Client dials the server over dig-nat DIRECT (mTLS; peer_id pinned to the server's).
    let client_identity = identity_from_seed(&[11u8; 32]).expect("client identity");
    let target = dig_nat::PeerTarget::with_addr(server_peer_id, addr, "DIG_MAINNET");
    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(5))
        .build();

    let mut conn = dig_nat::connect(&target, &client_identity, &config)
        .await
        .expect("client connects to the peer-RPC server over mTLS");
    // The mTLS handshake verified the server's peer_id.
    assert_eq!(
        conn.peer_id, server_peer_id,
        "server peer_id verified over mTLS"
    );

    // 1. A JSON-RPC control request over a fresh logical stream.
    {
        let mut stream = conn.session.open_stream().await.expect("open stream");
        let req = json!({"jsonrpc":"2.0","id":1,"method":"dig.getNetworkInfo"});
        write_framed(&mut stream, &req).await.unwrap();
        // Read the framed JSON-RPC response.
        let resp = read_one_frame(&mut stream).await;
        assert_eq!(resp["id"], json!(1));
        assert_eq!(resp["result"]["served_method"], json!("dig.getNetworkInfo"));
    }

    // 2. A typed availability batch via dig-nat's own client helper.
    {
        let items = vec![
            dig_nat::AvailabilityItem {
                store_id: "aa".repeat(32),
                root: None,
                retrieval_key: None,
            },
            dig_nat::AvailabilityItem {
                store_id: "bb".repeat(32),
                root: Some("11".repeat(32)),
                retrieval_key: None,
            },
        ];
        let resp = conn
            .query_availability(items)
            .await
            .expect("availability answered");
        assert_eq!(resp.items.len(), 2);
        assert!(resp.items[0].available);
    }

    // 3. A typed range fetch via dig-nat's own client helper; read the streamed RangeFrame.
    {
        let req = dig_nat::RangeRequest::resource("aa".repeat(32), "cc".repeat(32), 0, 4096);
        let mut stream = conn
            .session
            .open_range_stream(&req)
            .await
            .expect("open range stream");
        let frame = dig_nat::RangeFrame::decode(&mut stream)
            .await
            .expect("decode frame")
            .expect("one frame");
        assert!(frame.complete);
        assert_eq!(frame.total_length, Some(4));
        assert_eq!(frame.chunk_lens, Some(vec![4]));
    }

    server.abort();
}

/// Read one `u32`-BE length-prefixed JSON frame from a stream (the response side of the node wire).
async fn read_one_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Value {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn dialing_with_the_wrong_expected_peer_id_is_rejected() {
    dig_node::peer::install_crypto_provider();
    // mTLS peer identity is ENFORCED: a client that dials the server pinning a DIFFERENT expected
    // peer_id than the one the server presents must have `dig_nat::connect` FAIL (peer_id mismatch),
    // never establishing a session. This is the core "no impersonation / authenticated peer" property
    // — dig-nat verifies `peer_id = SHA-256(SPKI)` during the handshake against the pinned id.
    let server_identity = identity_from_seed(&[21u8; 32]).expect("server identity");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let responder: Arc<dyn PeerRpcResponder> = Arc::new(TestResponder);
    let server = tokio::spawn(serve_peer_rpc_listener(
        listener,
        server_identity,
        responder,
    ));

    // Pin the WRONG expected peer_id (a different identity's) — the handshake must be rejected.
    let wrong_peer_id = identity_from_seed(&[99u8; 32]).unwrap().peer_id;
    let client_identity = identity_from_seed(&[22u8; 32]).expect("client identity");
    let target = dig_nat::PeerTarget::with_addr(wrong_peer_id, addr, "DIG_MAINNET");
    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(3))
        .build();

    let result = dig_nat::connect(&target, &client_identity, &config).await;
    assert!(
        result.is_err(),
        "dialing with a mismatched expected peer_id must be rejected by mTLS verification"
    );
    server.abort();
}
