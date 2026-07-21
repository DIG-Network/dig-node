//! Integration proof: two in-process gossip pools connect over loopback and each COUNTS the other.
//!
//! This is the crux of the dig-node connect leg (#870/#570/#836): the smallest machine-checkable
//! proof that the connect PATH actually folds a dialed peer into the pool, driven against the PUBLIC
//! `dig_gossip::GossipService`/`GossipHandle` surface (not the node's `pub(crate)` wrappers), so it
//! exercises the same plumbing `control.peers.connect` rides.
//!
//! Node B dials node A over the IPv6 loopback (§5.2 IPv6-first). The dialer always observes the
//! server's cert, so B counts A as a `Via::Direct` peer on EVERY platform. The inbound (A-sees-B)
//! half registers into the pool only on the OpenSSL path (Linux — the CI + EC2 target); the
//! Windows/macOS native-tls loopback accept does not fold an accepted peer in the same way (the
//! documented `[::]`-v6only / native-tls dev-host quirk), so the MUTUAL half is asserted on Linux and
//! skipped-with-notice elsewhere — mirroring the shipped in-module `two_nodes_connect_over_loopback`.
//!
//! Genesis-independent: a fixed non-zero `network_id` is used (a direct dial needs no real genesis;
//! the default genesis is non-zero anyway — see `default_genesis_is_non_zero_so_gossip_config_is_valid`).

use std::net::SocketAddr;
use std::time::Duration;

use dig_gossip::nat::peer_record::Via;
use dig_gossip::{GossipConfig, GossipHandle, GossipService, PeerPoolConfig};

/// Whether this platform folds an ACCEPTED loopback peer into the pool (the inbound/mutual half).
/// Only Linux's OpenSSL path does; asserted there (CI + EC2), skipped-with-notice elsewhere.
const POOL_REGISTERS_INBOUND_LOOPBACK: bool = cfg!(target_os = "linux");

/// Start a fresh gossip pool bound on `listen_addr` with a fixed non-zero `network_id`. Certs are
/// minted into a throwaway temp dir; the pool is otherwise a stock, discovery-free node.
async fn start_pool(tag: &str, network: [u8; 32], listen_addr: SocketAddr) -> GossipHandle {
    let dir = std::env::temp_dir().join(format!("dig-pool-connect-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cfg = GossipConfig {
        network_id: chia_protocol::Bytes32::new(network),
        cert_path: dir.join("node.cert").display().to_string(),
        key_path: dir.join("node.key").display().to_string(),
        peers_file_path: dir.join("peers.json"),
        peer_pool: Some(PeerPoolConfig::default()),
        listen_addr,
        ..Default::default()
    };
    GossipService::new(cfg)
        .expect("gossip config is valid (non-zero network_id)")
        .start()
        .await
        .expect("gossip pool starts")
}

/// The `Via` this handle records for `peer_id`, if it lists it as a connected pool member.
fn via_of(handle: &GossipHandle, peer_id: &dig_gossip::PeerId) -> Option<Via> {
    handle
        .connected_pool_peers_with_via()
        .into_iter()
        .find(|(pid, _)| pid == peer_id)
        .map(|(_, via)| via)
}

/// Poll until `handle` lists at least one connected pool peer (the inbound accept is asynchronous),
/// or the deadline elapses. Returns the connected-peer count observed.
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

#[tokio::test]
async fn two_pools_connect_over_loopback_and_count_each_other() {
    dig_node_core::peer::install_crypto_provider();

    // Same non-zero network_id on both — a mismatch is rejected at handshake. Concrete IPv6 loopback
    // binds so the inbound accept registers on every platform that supports it (§5.2 IPv6-first).
    let network = [0x5au8; 32];
    let loopback: SocketAddr = "[::1]:0".parse().expect("parse [::1]:0");
    let node_a = start_pool("a", network, loopback).await;
    let node_b = start_pool("b", network, loopback).await;

    let a_peer_id = node_a.local_peer_id().expect("node A local_peer_id");
    let b_peer_id = node_b.local_peer_id().expect("node B local_peer_id");
    let a_addr = node_a
        .__listen_bound_addr_for_tests()
        .expect("node A bound listen addr");
    // Dial the concrete loopback (the bound addr may report `[::]`; force `[::1]` for the dial).
    let a_dial: SocketAddr = format!("[::1]:{}", a_addr.port())
        .parse()
        .expect("A loopback dial addr");

    // B dials A: the connect PATH under proof. The returned peer_id is A's real cert id.
    let dialed = node_b
        .connect_to(a_dial)
        .await
        .expect("node B dials node A over loopback mTLS");
    assert_eq!(
        dialed, a_peer_id,
        "the dial returns node A's real cert peer_id"
    );

    // B's half — proven on EVERY platform: B counts >=1 connected peer, and it is A, via a DIRECT
    // transport (a loopback dial is never relayed).
    assert!(
        node_b.connected_pool_peers().len() >= 1,
        "node B must count at least one connected peer (node A)"
    );
    assert_eq!(
        via_of(&node_b, &a_peer_id),
        Some(Via::Direct),
        "B→A is a direct-TLS link, not relayed"
    );

    // A's half — the MUTUAL proof (asynchronous inbound accept). Only Linux's OpenSSL path folds an
    // accepted loopback peer into the pool; elsewhere the native-tls accept quirk skips it.
    if POOL_REGISTERS_INBOUND_LOOPBACK {
        let a_count = await_connected(&node_a, Duration::from_secs(5)).await;
        assert!(
            a_count >= 1,
            "node A must count at least one connected peer (node B) — the MUTUAL A↔B proof"
        );
        assert_eq!(
            via_of(&node_a, &b_peer_id),
            Some(Via::Direct),
            "A sees B over a direct transport too"
        );
    } else {
        eprintln!(
            "skipping the inbound MUTUAL half: this platform's native-tls does not fold an accepted \
             loopback peer into the pool (Linux/CI/EC2 enforces it)"
        );
    }
}

#[tokio::test]
async fn dialing_a_dead_port_never_counts_a_peer() {
    // The negative counterpart that keeps the proof HONEST (§2.1): if the connect path were broken —
    // here, B dials a port with no listener — the dial must FAIL and B must count ZERO peers. This is
    // the assertion that fails when connect is broken, proving the positive test above is real.
    dig_node_core::peer::install_crypto_provider();
    let node_b = start_pool(
        "dead",
        [0x5au8; 32],
        "[::1]:0".parse().expect("parse [::1]:0"),
    )
    .await;

    // Bind then immediately drop a listener to obtain a port that is (almost certainly) closed.
    let dead_port = {
        let l = std::net::TcpListener::bind("[::1]:0").expect("bind ephemeral");
        l.local_addr().expect("dead addr").port()
    };
    let dead: SocketAddr = format!("[::1]:{dead_port}")
        .parse()
        .expect("dead dial addr");

    let result = node_b.connect_to(dead).await;
    assert!(
        result.is_err(),
        "dialing a dead port must fail, not connect"
    );
    assert_eq!(
        node_b.connected_pool_peers().len(),
        0,
        "a failed dial must leave the pool with zero connected peers"
    );
}
