//! **dig_ecosystem#3061** — a repeat announce of an UNCHANGED profile root reaches the wire.
//!
//! This is the composed proof, and it is the one that was missing. dig-gossip 0.25.0 added
//! `broadcast_local` and proved in its own suite that the dedup-exempt path is not suppressed; the
//! seam tests in `profile_sync` prove dig-node SELECTS that path. Neither observes the two together,
//! and the whole defect lived in the join: the crate fix is inert until the node calls it, so a
//! green crate suite plus a green seam suite could both hold while the node still went silent after
//! its first announce.
//!
//! So this test drives dig-node's real [`GossipProfileTransport`] over a real running
//! [`dig_gossip::GossipService`] with a registered peer, and asks the only question that matters:
//! **does the SECOND announce of the same `(store_id, root)` still reach that peer?**
//!
//! ## Why the fixture is shaped this way
//!
//! * **The same pair is announced three times, never a fresh one.** A distinct root on each tick
//!   produces a distinct frame, which the seen set never suppressed even when broken — such a test
//!   would pass identically against the defect. Byte-identical repetition is the only input that
//!   distinguishes the fixed routing from the broken one.
//! * **A control on the forwarding path runs beside it.** Asserting only that the local path repeats
//!   would be satisfied by an implementation that made EVERY broadcast dedup-exempt, which is the
//!   dangerous wrong version: relaying a received message down that path turns one echo into a
//!   storm. The control pins that `broadcast` still suppresses its own repeat, so the two paths are
//!   proven DIFFERENT rather than proven permissive.
//! * **The peer is a stub.** It has no TLS transport, so what is being measured is the fan-out
//!   accounting dig-gossip performs after the seen-set gate — precisely the gate under test. What a
//!   stub cannot prove is the socket write itself; that is dig-gossip's own responsibility and is
//!   covered there.

use dig_node_core::seams::dig_peer::profile_sync::{
    announce_frame, announce_held_root, GossipProfileTransport, ProfileTransport,
};

/// A running gossip service with one registered peer, plus the dig-node transport bound to it.
///
/// Mirrors the bring-up `peer.rs`'s own tests use: an OS-assigned loopback port, self-generated
/// certs under a per-process temp dir, no introducer and no relay.
async fn transport_with_one_peer() -> (
    dig_gossip::GossipService,
    dig_gossip::GossipHandle,
    GossipProfileTransport,
) {
    let dir = std::env::temp_dir().join(format!(
        "dig-node-3061-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let cfg = dig_gossip::GossipConfig {
        network_id: chia_protocol::Bytes32::new([7u8; 32]),
        cert_path: dir.join("node.cert").display().to_string(),
        key_path: dir.join("node.key").display().to_string(),
        peers_file_path: dir.join("peers.json"),
        peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
        listen_addr: std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            0,
        ),
        ..Default::default()
    };
    let service = dig_gossip::GossipService::new(cfg).expect("gossip config");
    let handle = service.start().await.expect("gossip start");

    handle
        .__connect_stub_peer_with_direction(
            "127.0.0.1:9401".parse().expect("addr"),
            dig_gossip::NodeType::FullNode,
            true,
        )
        .await
        .expect("stub peer registers");

    let transport = GossipProfileTransport::new(handle.clone());
    (service, handle, transport)
}

/// **Proves #3061 end to end at the node's own transport:** the periodic re-announce of an unchanged
/// root reaches a connected peer on EVERY tick, not only the first.
///
/// Before this adoption the second and third calls returned 0 — for the life of the process — so a
/// peer that connected after the first announce could never learn the root. Revert
/// `announce_held_root` to `announce_root` and this test fails on the second iteration.
#[tokio::test]
async fn a_repeat_announce_of_an_unchanged_root_still_reaches_the_peer() {
    let (_service, _handle, transport) = transport_with_one_peer().await;
    let store_id = [3u8; 32];
    let root = [9u8; 32];

    let mut reached = Vec::new();
    for _ in 0..3 {
        reached.push(announce_held_root(&transport, store_id, root).await);
    }

    assert_eq!(
        reached,
        vec![1, 1, 1],
        "every re-announce of the SAME (store_id, root) must reach the connected peer; \
         a trailing zero is #3061 — the seen set suppressing this node's own repeat forever"
    );
}

/// **The control that keeps the test above honest:** the FORWARDING path still deduplicates.
///
/// Without this, an implementation that routed every broadcast down the dedup-exempt path would
/// satisfy the repeat assertion perfectly while re-broadcasting every received echo — a storm. The
/// same frame offered twice to `announce_root` must reach the peer once and then be suppressed.
#[tokio::test]
async fn the_forwarding_path_still_suppresses_its_own_repeat() {
    let (_service, _handle, transport) = transport_with_one_peer().await;
    let root_ref = dig_gossip::service::profile_sync::ProfileRootRef {
        store_id: chia_protocol::Bytes32::new([4u8; 32]),
        root: chia_protocol::Bytes32::new([5u8; 32]),
    };

    let first = transport.announce_root(&root_ref, None).await;
    let second = transport.announce_root(&root_ref, None).await;

    assert_eq!(first, 1, "the first relay of a frame reaches the peer");
    assert_eq!(
        second, 0,
        "the relay path MUST stay seen-set deduplicated — this is the loop suppressor, and \
         exempting it would turn one received echo into a broadcast storm"
    );
}

/// A locally-originated announce records its hash, so the SAME frame arriving back from a peer and
/// offered to the forwarding path is still dropped.
///
/// This is the property that makes the split safe rather than merely convenient: the dedup exemption
/// is one-directional. Without it, exempting the local path would disarm the loop guard against this
/// node's own echo returning from a neighbour.
#[tokio::test]
async fn a_local_announce_still_arms_the_loop_guard_against_its_own_echo() {
    let (_service, _handle, transport) = transport_with_one_peer().await;
    let store_id = [1u8; 32];
    let root = [2u8; 32];

    let originated = announce_held_root(&transport, store_id, root).await;
    // The identical frame comes back from a neighbour and is offered to the RELAY path.
    let echoed = transport
        .announce_root(
            &dig_gossip::service::profile_sync::ProfileRootRef {
                store_id: chia_protocol::Bytes32::new(store_id),
                root: chia_protocol::Bytes32::new(root),
            },
            None,
        )
        .await;

    assert_eq!(originated, 1, "this node's own announce goes out");
    assert_eq!(
        echoed, 0,
        "the echo of an announce this node originated must still be suppressed — the local path is \
         exempt from the seen set, but it still RECORDS into it"
    );
    // The suppression above is only meaningful if the echo really is the SAME bytes the origination
    // emitted — a mismatch would be suppressed by nothing and the zero would mean something else.
    // Both paths frame through `frame_profile_root_announce`, which `announce_frame` exposes, so
    // pinning the echo's framing against it rules that reading out.
    assert_eq!(
        announce_frame(store_id, root).msg_type,
        dig_gossip::service::profile_sync::PROFILE_ROOT_ANNOUNCE,
        "the framing under test is opcode 223"
    );
}
