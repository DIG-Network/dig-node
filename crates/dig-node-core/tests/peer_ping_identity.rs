//! `control.peers.ping` against a REAL mTLS peer over loopback (dig_ecosystem#1985).
//!
//! The engine's unit tests grade hand-built `TierReport`s, which cannot prove two things that matter:
//! that the WRONG-PEER outcome is one the real dialer can actually produce, and that the
//! anti-amplification gate is wired into the production entry point rather than merely existing.
//!
//! Both were wrong once. The identity-mismatch verdict was previously unreachable in production —
//! dig-tls pins the expected `peer_id` inside its certificate verifier, so a mismatched certificate
//! aborts the handshake and no `PeerConnection` is ever produced, which meant a real impersonation
//! was reported as an UNREACHABLE peer while a unit test asserting the mismatch stayed green off a
//! `TierReport` the dialer could not emit. And deleting the gate claim from `ping_peer` left the
//! whole suite green, so the rate limit was mutation-survivable.
//!
//! These tests therefore drive `ping::ping_peer` — the real entry point — against a REAL
//! `serve_peer_rpc_listener` on loopback, through the real dig-nat/dig-tls handshake.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dig_node_core::peer::{install_crypto_provider, load_or_generate_node_cert, PeerRpcResponder};
use dig_node_core::seams::dig_peer::ping::{self, PeerPingContext, PingRefused};
use serde_json::{json, Value};

/// A responder that answers nothing useful. These tests assert on the HANDSHAKE, which completes (or
/// is refused) before any request is ever dispatched, so the peer's RPC behaviour is irrelevant.
struct SilentResponder;

#[async_trait]
impl PeerRpcResponder for SilentResponder {
    async fn handle_json_rpc(&self, _req: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "result": {} })
    }
    async fn handle_availability(&self, _items: Value) -> Value {
        json!({ "items": [] })
    }
    async fn stream_range(
        &self,
        _req: Value,
        _conn_key: &str,
        _out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        Ok(())
    }
}

/// Mint a CA-signed mTLS identity from `seed` into a throwaway dir, so its `peer_id` is a stable
/// function of the seed and two seeds give two genuinely different certificates.
fn identity_from(seed: &[u8; 32]) -> Arc<dig_tls::NodeCert> {
    let dir = tempfile::tempdir().expect("cert tempdir");
    load_or_generate_node_cert(dir.path(), seed).expect("node cert")
}

/// Start a real peer-RPC listener on loopback; returns its `peer_id` and bound address.
async fn start_peer(seed: [u8; 32]) -> (String, SocketAddr) {
    install_crypto_provider();
    let identity = identity_from(&seed);
    let peer_id = identity.peer_id().to_hex();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(dig_node_core::peer::serve_peer_rpc_listener(
        listener,
        identity,
        Arc::new(SilentResponder),
    ));
    (peer_id, addr)
}

/// A ping context wired like bring-up wires it, minus the parts a loopback direct dial does not need
/// (no STUN server, and a default `NatRuntime`, so only the direct rung composes).
fn ping_context(seed: [u8; 32]) -> PeerPingContext {
    PeerPingContext::new(
        identity_from(&seed),
        Arc::new(dig_nat::NatRuntime::default()),
        "DIG_MAINNET",
        None,
        Duration::from_secs(2),
    )
}

/// **Proves (#1985 acceptance criterion 3):** pinning the WRONG `peer_id` at an address that is
/// genuinely reachable reports an **identity mismatch**, over a real mTLS handshake — and names the
/// identity that actually answered.
///
/// **Catches** the defect this test replaced a mock for: dig-tls refuses the handshake on a pin
/// mismatch, so the wrong-identity case NEVER yields a connection and was being graded
/// `unreachable`. An impersonation, or a stale address-book entry, rendered as a dead peer. The
/// previous unit test hand-built a `Connected` report with a mismatched id — a shape the real dialer
/// cannot produce — so it passed throughout.
#[tokio::test]
async fn a_wrong_peer_id_at_a_reachable_address_reports_an_identity_mismatch() {
    let (real_peer_id, addr) = start_peer([0x51; 32]).await;
    // A different, real, well-formed identity that is NOT the one listening.
    let (impostor_expectation, _) = start_peer([0x52; 32]).await;
    assert_ne!(real_peer_id, impostor_expectation);

    let ctx = ping_context([0x53; 32]);
    let report = ping::ping_peer(
        &ctx,
        &addr.to_string(),
        Some(&impostor_expectation),
        &[],
        Duration::from_secs(20),
    )
    .await
    .expect("the first ping is within the gate's budget");

    assert_eq!(
        report["verdict"], "identity-mismatch",
        "a reachable address answering with the wrong certificate must not read as unreachable: \
         {report:#}"
    );
    assert_eq!(report["severity"], "error");
    assert!(
        report["summary"]
            .as_str()
            .is_some_and(|s| s.contains("WRONG PEER")),
        "the summary must say plainly who answered: {report:#}"
    );

    let direct = report["ladder"]
        .as_array()
        .expect("a ladder array")
        .iter()
        .find(|r| r["tier"] == "direct")
        .expect("the direct rung is reported");
    assert_eq!(direct["result"], "identity-mismatch", "{direct:#}");
    assert_eq!(
        direct["observed_peer_id"], real_peer_id,
        "the rung names the identity that actually answered: {direct:#}"
    );
}

/// **Proves (#1985 acceptance criterion 1, locally):** pinning the CORRECT `peer_id` at the same
/// address connects on the direct rung and grades green.
///
/// **Catches** an over-eager mismatch classifier that turns every dial into a wrong-peer report —
/// the inverse failure of the test above, and the one that would make the diagnostic useless.
#[tokio::test]
async fn the_right_peer_id_at_the_same_address_connects_on_the_direct_rung() {
    let (real_peer_id, addr) = start_peer([0x61; 32]).await;

    let ctx = ping_context([0x62; 32]);
    let report = ping::ping_peer(
        &ctx,
        &addr.to_string(),
        Some(&real_peer_id),
        &[],
        Duration::from_secs(20),
    )
    .await
    .expect("within the gate's budget");

    assert_eq!(report["verdict"], "direct", "{report:#}");
    assert_eq!(report["severity"], "ok");

    let direct = report["ladder"]
        .as_array()
        .expect("a ladder array")
        .iter()
        .find(|r| r["tier"] == "direct")
        .expect("the direct rung is reported");
    assert_eq!(direct["result"], "connected", "{direct:#}");
    assert_eq!(direct["observed_peer_id"], real_peer_id);
    assert_eq!(direct["family"], "ipv4", "loopback here is 127.0.0.1");
}

/// **Proves:** the anti-amplification gate is WIRED INTO `ping_peer`, not merely implemented — the
/// production entry point refuses once the window's budget is spent.
///
/// **Catches** exactly the mutation the gate review found survivable: deleting
/// `let _lease = ctx.gate.try_enter(...)?;` from `ping_peer` left all 1535 tests green, because the
/// five `PingGate` unit tests exercise the gate in isolation and nothing proved the entry point
/// consults it. Without this, the node's only bound on being used as a dialer is untested.
#[tokio::test]
async fn the_rate_limit_is_enforced_by_the_production_entry_point() {
    let (real_peer_id, addr) = start_peer([0x71; 32]).await;
    let ctx = ping_context([0x72; 32]);
    let target = addr.to_string();

    for i in 0..ping::MAX_PINGS_PER_WINDOW {
        ping::ping_peer(
            &ctx,
            &target,
            Some(&real_peer_id),
            &[],
            Duration::from_secs(20),
        )
        .await
        .unwrap_or_else(|e| panic!("ping {i} is within budget, got {e:?}"));
    }

    let refused = ping::ping_peer(
        &ctx,
        &target,
        Some(&real_peer_id),
        &[],
        Duration::from_secs(20),
    )
    .await;
    match refused {
        Err(PingRefused::RateLimited { retry_after }) => assert!(
            retry_after > Duration::ZERO,
            "the refusal must name a real wait, got {retry_after:?}"
        ),
        other => panic!(
            "ping {} must be refused by the rate limit, got {other:?}",
            ping::MAX_PINGS_PER_WINDOW + 1
        ),
    }
}

/// **Proves:** an argument that cannot be resolved costs NO rate budget — resolution runs before the
/// gate is claimed.
///
/// **Catches** a reordering that charges the window first, which would let a user who mistyped an
/// address a few times lock themselves out of the diagnostic for a minute. The stated ordering
/// property was previously unproven, as were all four `unresolved_json` branches.
#[tokio::test]
async fn an_unresolvable_argument_costs_no_rate_budget() {
    let ctx = ping_context([0x81; 32]);

    // Every resolution-failure branch: unparseable, an address with no known identity, and a
    // peer_id this node knows no address for.
    let cases = [
        "not-an-address".to_string(),
        "127.0.0.1:9444".to_string(),
        "aa".repeat(32),
    ];

    for _round in 0..4 {
        for peer in &cases {
            let report = ping::ping_peer(&ctx, peer, None, &[], Duration::from_secs(5))
                .await
                .expect("a resolution failure is a RESULT, never a refusal");
            assert_eq!(report["verdict"], "unresolved", "{report:#}");
            assert_eq!(report["severity"], "error");
            assert!(
                report["ladder"].as_array().expect("ladder").is_empty(),
                "nothing was dialed, so no rung is reported: {report:#}"
            );
        }
    }

    // 12 unresolvable calls later the budget is untouched: a real target still gets its full run.
    let (real_peer_id, addr) = start_peer([0x82; 32]).await;
    let report = ping::ping_peer(
        &ctx,
        &addr.to_string(),
        Some(&real_peer_id),
        &[],
        Duration::from_secs(20),
    )
    .await
    .expect("a mistyped argument must not lock the caller out");
    assert_eq!(report["verdict"], "direct", "{report:#}");
}
