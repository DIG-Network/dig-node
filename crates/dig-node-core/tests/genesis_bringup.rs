//! End-to-end proof that the peer-network bring-up reaches its DOWNSTREAM engines against the
//! REAL default DIG mainnet genesis, with no `DIG_NETWORK_GENESIS` override (dig-node#240).
//!
//! # What this asserts, and why it is the right decision point
//!
//! `run_peer_network` proceeds: derive the node identity -> `status.set_running` -> build the
//! `GossipConfig` with `network_id = <genesis>` -> `GossipService::new` -> `.start()` -> pool ->
//! DHT -> `set_p2p_content` -> `set_inventory_refresher` -> mTLS peer-RPC listener -> PEX.
//!
//! `running == true` is set BEFORE `GossipService::new` and so holds even when the pool, the DHT,
//! the content engine and PEX all fail. It is not evidence of anything downstream and is
//! deliberately NOT asserted here. Instead this test asserts the post-conditions that are strictly
//! downstream of a SUCCESSFUL `GossipService::new().start()`:
//!
//!   * `Node::gossip_handle()` is `Some` -- the pool started (step 3 is past the gossip-config
//!     validation the old "placeholder genesis" world failed at).
//!   * `Node::p2p_content()` is `Some` -- the P2P content engine is installed, which is wired ONLY
//!     when the DHT is up (steps 4a/4b).
//!   * `Node::has_inventory_refresher()` -- the DHT inventory-refresh hook is installed (step 4c).
//!   * the mTLS peer-RPC listener ACCEPTS a loopback TCP connection (step 5), which is bound after
//!     every step above.
//!
//! # What this does NOT prove, stated plainly
//!
//!   * **PEX behaviour.** `PexServing` is constructed and threaded onto the listener this test
//!     connects to, so it is built; no peer exchange happens with zero peers, and none is asserted.
//!   * **Peers, discovery, or provider records.** The run is hermetic: the relay/introducer is OFF
//!     (`DIG_RELAY_URL=off`, which also means no STUN and no relay reservation), so the pool has
//!     zero members, the DHT bootstrap finds nobody, and the initial inventory announce reaches
//!     nothing. The DHT COMES UP; it does not converge. Proving convergence needs more than one
//!     host and is the multi-node e2e's job, not this test's.
//!   * **The relay reservation and the relay accept loop**, which are not wired with the relay off.
//!
//! # Hermetic
//!
//! No real network: relay off, upstream pinned at an unroutable loopback port, identity + cert +
//! cache dirs in `TempDir`s (removed on unwind), listeners on OS-allocated free ports. Nothing here
//! reaches mainnet or any DIG host.
//!
//! # Env
//!
//! This file is its OWN test binary and holds exactly ONE test, so the process-global env it sets
//! cannot contaminate a sibling test. `DIG_NETWORK_GENESIS` is deliberately REMOVED rather than
//! set: the whole claim is about the DEFAULT.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dig_node_core::peer::{
    genesis_challenge_from_env, install_crypto_provider, spawn_peer_network,
};
use dig_node_core::seams::dig_peer::peer_network::PeerNetwork;
use dig_node_core::Node;

/// An OS-allocated free TCP port. Bound then dropped, so the port is free when the node claims it.
/// A racing binder could steal it; that would surface as a bring-up error, never as a false PASS.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port");
    let port = l.local_addr().expect("a bound addr").port();
    drop(l);
    port
}

/// Whether the mTLS peer-RPC listener accepts a plain TCP connection on `port`. A TCP connect is
/// enough: the question is whether the listener is BOUND (step 5), not what it speaks. Both
/// loopback families are tried because the listener is a dual-stack `[::]` bind.
fn listener_accepts(port: u16) -> bool {
    let timeout = Duration::from_millis(500);
    for addr in [
        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
        std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
    ] {
        if std::net::TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

/// **Proves (#240):** with the REAL default DIG mainnet genesis and NO `DIG_NETWORK_GENESIS`
/// override, the bring-up gets past gossip-config validation and installs every downstream engine
/// -- the gossip pool handle, the P2P content engine, the DHT inventory-refresh hook -- and binds
/// the mTLS peer-RPC listener.
///
/// **Catches:** the world this ticket was filed in, where the genesis was an all-zero placeholder
/// that `GossipService::new` rejects, so steps 3-8 never ran. It also catches any future change
/// that hands gossip an invalid `network_id` by default. It is NOT satisfied by
/// `control.peerStatus.running`, which is set before the pool exists.
#[test]
fn default_genesis_brings_up_the_pool_dht_content_engine_and_peer_rpc_listener() {
    let cache = tempfile::Builder::new()
        .prefix("dig-240-cache-")
        .tempdir()
        .expect("a cache dir");
    let identity = tempfile::Builder::new()
        .prefix("dig-240-identity-")
        .tempdir()
        .expect("an identity dir");

    let peer_port = free_port();
    let gossip_port = free_port();

    // Hermetic + mainnet-safe. The relay off-token also disables the introducer, STUN and the
    // relay reservation, so nothing in this run resolves or dials a DIG host.
    std::env::set_var("DIG_NODE_CACHE", cache.path());
    std::env::set_var("DIG_IDENTITY_DIR", identity.path());
    std::env::set_var("DIG_RELAY_URL", "off");
    std::env::set_var("DIG_BOOTSTRAP_PEERS", "off");
    std::env::set_var("DIG_NODE_UPSTREAM", "http://127.0.0.1:1/");
    std::env::set_var("DIG_PEER_PORT", peer_port.to_string());
    std::env::set_var("DIG_GOSSIP_PORT", gossip_port.to_string());
    // The claim under test is about the DEFAULT genesis, so the override must be ABSENT. Note that
    // an all-zero override would NOT reproduce the old failure anyway: `genesis_challenge_from`
    // collapses every invalid value, all-zero included, back to the real genesis.
    std::env::remove_var("DIG_NETWORK_GENESIS");
    std::env::remove_var("DIG_NETWORK_ID");
    std::env::remove_var("DIG_PEER_NETWORK"); // unset -> default ON

    // The precondition, restated at the point of use: the effective genesis really is the canonical
    // non-zero DIG mainnet value, so the gossip config this bring-up builds is a valid one.
    let genesis = genesis_challenge_from_env();
    assert_eq!(
        genesis,
        dig_constants::DIG_MAINNET.genesis_challenge(),
        "no override is set, so the effective genesis is the canonical DIG mainnet genesis"
    );
    assert_ne!(
        genesis.to_bytes(),
        [0u8; 32],
        "the canonical genesis is non-zero, and all-zero is the only network_id dig-gossip rejects"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    rt.block_on(async move {
        let node: Arc<Node> = Node::from_env();

        assert!(
            node.gossip_handle().is_none() && node.p2p_content().is_none(),
            "nothing is installed before the bring-up runs"
        );

        install_crypto_provider();
        spawn_peer_network(node.clone());

        // `run_peer_network` never returns (it ends in the accept loop), so poll the
        // post-conditions rather than awaiting it.
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut ready = false;
        while Instant::now() < deadline {
            if node.gossip_handle().is_some()
                && node.p2p_content().is_some()
                && node.has_inventory_refresher()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(
            ready,
            "the bring-up must install the pool handle, the P2P content engine and the DHT \
             inventory-refresh hook against the default genesis; pool={} content={} refresher={}",
            node.gossip_handle().is_some(),
            node.p2p_content().is_some(),
            node.has_inventory_refresher(),
        );

        // Step 5: the mTLS peer-RPC listener is bound AFTER every assertion above, so this is the
        // last observable point of the bring-up sequence.
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut bound = false;
        while Instant::now() < deadline {
            if listener_accepts(peer_port) {
                bound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            bound,
            "the mTLS peer-RPC listener must be bound on port {peer_port} once bring-up is past \
             the content engine"
        );
    });
}
