//! Integration tests for the dig-node ↔ dig-dht content-location DHT (#163 PHASE-B).
//!
//! Two layers are exercised with NO real network:
//!  1. The [`NatDhtTransport`] adapter + the inbound DHT-RPC serving path over a REAL loopback mTLS
//!     connection (peer_id = SHA-256(SPKI)). This proves a DHT RPC rides the same authenticated
//!     dig-nat transport the content fetch uses, and that the served side folds the mTLS-verified
//!     caller into the routing table.
//!  2. The DHT bring-up / bootstrap / find_providers / inventory-publishing behaviour over an
//!     in-process MOCK [`DhtTransport`] swarm (deterministic, socket-free), so the locate + announce
//!     semantics are tested without live peers (DIG_TEST_MNEMONIC / real network unavailable).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use dig_dht::{
    BootstrapPeer, CandidateAddr, Contact, ContentId, DhtConfig, DhtError, DhtRequest, DhtResponse,
    DhtService, DhtTransport, PeerId, ProviderRecord,
};
use dig_node_core::dht::{
    announce_inventory, bootstrap_peers_from_pool, caller_contact, inventory_content_ids,
    NatDhtTransport,
};
use dig_node_core::peer::{
    identity_from_seed, install_crypto_provider, serve_peer_rpc_listener, PeerRpcResponder,
};
use dig_node_core::CachedCapsule;
use serde_json::{json, Value};

// =====================================================================================================
// Layer 1 — NatDhtTransport + inbound DHT serving over REAL loopback mTLS
// =====================================================================================================

/// A peer-RPC responder that serves inbound DHT frames against a real [`DhtService`], recording the
/// caller identity of each inbound DHT RPC so the test can assert bidirectional routing-table fill.
struct DhtServingResponder {
    dht: Arc<DhtService>,
    seen_callers: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl PeerRpcResponder for DhtServingResponder {
    async fn handle_json_rpc(&self, req: Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(json!(1));
        json!({"jsonrpc":"2.0","id":id,"result":{}})
    }
    async fn handle_availability(&self, _items: Value) -> Value {
        json!({"items": []})
    }
    async fn stream_range(
        &self,
        _req: Value,
        _out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> std::io::Result<()> {
        Ok(())
    }
    async fn handle_dht(&self, caller: Option<Contact>, frame: Value) -> Vec<u8> {
        if let Some(c) = &caller {
            self.seen_callers.lock().await.push(c.peer_id.clone());
        }
        // Route into the real DHT service, folding in the authenticated caller (routing-table fill).
        let req: DhtRequest = serde_json::from_value(frame).expect("a DHT request frame");
        self.dht.handle_request_from(caller, req).await.encode()
    }
}

/// Spin up a node's mTLS peer-RPC listener backed by a real DHT service; return the server's peer_id,
/// its listen addr, the shared DHT service, and the seen-callers log.
async fn start_dht_server(
    seed: [u8; 32],
) -> (
    PeerId,
    std::net::SocketAddr,
    Arc<DhtService>,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    install_crypto_provider();
    let identity = identity_from_seed(&seed).expect("server identity");
    let peer_id = identity.peer_id;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // The server's DHT: it uses a transport that can't reach anyone (it only SERVES here), so its
    // find_* would be local-only; that's fine — we only drive its serving side.
    let config = DhtConfig::default();
    let server_dht = Arc::new(DhtService::new(
        peer_id,
        vec![CandidateAddr::direct(addr.ip().to_string(), addr.port())],
        config,
        Arc::new(UnreachableTransport),
    ));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let responder: Arc<dyn PeerRpcResponder> = Arc::new(DhtServingResponder {
        dht: server_dht.clone(),
        seen_callers: seen.clone(),
    });
    let join = tokio::spawn(serve_peer_rpc_listener(listener, identity, responder));
    (peer_id, addr, server_dht, seen, join)
}

/// A transport that never reaches anyone — for a service that only serves inbound RPC in a test.
struct UnreachableTransport;
#[async_trait]
impl DhtTransport for UnreachableTransport {
    async fn rpc(
        &self,
        _from: &Contact,
        peer: &Contact,
        _request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        Err(DhtError::transport(format!("unreachable {}", peer.peer_id)))
    }
}

#[tokio::test]
async fn dht_ping_round_trips_over_real_mtls() {
    install_crypto_provider();
    let (server_peer_id, addr, _dht, _seen, server) = start_dht_server([31u8; 32]).await;

    // A client transport dials the server over dig-nat DIRECT (mTLS, peer_id pinned).
    let client_identity = identity_from_seed(&[32u8; 32]).expect("client id");
    let transport = NatDhtTransport::new(client_identity, "DIG_MAINNET", Duration::from_secs(5));

    let from = client_contact([32u8; 32]);
    let peer = Contact::new(
        &server_peer_id,
        vec![CandidateAddr::direct(addr.ip().to_string(), addr.port())],
    );
    let resp = transport
        .rpc(&from, &peer, &DhtRequest::Ping { nonce: 4242 })
        .await
        .expect("ping answered over mTLS");
    assert_eq!(resp, DhtResponse::Pong { nonce: 4242 });
    server.abort();
}

#[tokio::test]
async fn dht_add_then_find_providers_over_real_mtls_and_caller_is_learned() {
    install_crypto_provider();
    let (server_peer_id, addr, server_dht, seen, server) = start_dht_server([33u8; 32]).await;

    let client_seed = [34u8; 32];
    let client_identity = identity_from_seed(&client_seed).expect("client id");
    let client_peer_id = client_identity.peer_id;
    let transport = NatDhtTransport::new(client_identity, "DIG_MAINNET", Duration::from_secs(5));
    let from = Contact::new(&client_peer_id, vec![CandidateAddr::direct("127.0.0.1", 1)]);
    let peer = Contact::new(
        &server_peer_id,
        vec![CandidateAddr::direct(addr.ip().to_string(), addr.port())],
    );

    // 1. AddProvider: the client announces that IT holds a capsule to the server. The
    //    DHT server enforces that a provider record's provider_peer_id matches the
    //    authenticated (mTLS) caller — a node may only announce content it itself holds,
    //    never a third party — so the holder here IS the client's own peer_id.
    let content = ContentId::capsule([7u8; 32], [8u8; 32]);
    let holder = client_peer_id;
    let record = ProviderRecord::new(
        &content.to_key(),
        &holder,
        vec![CandidateAddr::direct("203.0.113.9", 9444)],
        u64::MAX, // never expires within the test
    );
    let ok = transport
        .rpc(
            &from,
            &peer,
            &DhtRequest::AddProvider {
                record: record.clone(),
            },
        )
        .await
        .expect("add_provider answered");
    assert_eq!(ok, DhtResponse::AddProviderOk);

    // 2. FindProviders for that content key → the server returns the stored record.
    let found = transport
        .rpc(
            &from,
            &peer,
            &DhtRequest::FindProviders {
                content_key: content.to_key().to_hex(),
            },
        )
        .await
        .expect("find_providers answered");
    match found {
        DhtResponse::Providers { providers, .. } => {
            assert!(
                providers
                    .iter()
                    .any(|p| p.provider_peer_id == holder.to_hex()),
                "the announced holder is returned by find_providers"
            );
        }
        other => panic!("expected Providers, got {other:?}"),
    }

    // 3. The server LEARNED the client as an authenticated caller (bidirectional routing-table fill):
    //    the mTLS-verified client peer_id was folded in on every inbound RPC.
    let seen_callers = seen.lock().await.clone();
    assert!(
        seen_callers.iter().any(|c| c == &client_peer_id.to_hex()),
        "the server saw the mTLS-verified client peer_id as the caller"
    );
    // And the server's routing table now contains the client (find_node closest includes it).
    let closest = server_dht
        .known_closest(&dig_dht::Key::from_peer_id(&client_peer_id))
        .await;
    assert!(
        closest.iter().any(|c| c.peer_id == client_peer_id.to_hex()),
        "the client is now in the server's routing table"
    );
    server.abort();
}

#[tokio::test]
async fn dht_rpc_to_an_unreachable_peer_is_a_transport_error() {
    install_crypto_provider();
    // Dial an address with nothing listening → the adapter maps the failure to DhtError::Transport
    // (the lookup treats it as "that peer is unreachable" and moves on), never a panic/hang.
    let client_identity = identity_from_seed(&[40u8; 32]).expect("client id");
    let transport = NatDhtTransport::new(client_identity, "DIG_MAINNET", Duration::from_secs(2));
    let from = client_contact([40u8; 32]);
    // 127.0.0.1:1 is (almost certainly) not accepting — a fast connection refusal.
    let dead = Contact::new(
        &PeerId::from_bytes([250u8; 32]),
        vec![CandidateAddr::direct("127.0.0.1", 1)],
    );
    let err = transport
        .rpc(&from, &dead, &DhtRequest::Ping { nonce: 1 })
        .await;
    assert!(
        matches!(err, Err(DhtError::Transport(_))),
        "an unreachable peer is a transport error, got {err:?}"
    );
}

fn client_contact(seed: [u8; 32]) -> Contact {
    let id = identity_from_seed(&seed).unwrap().peer_id;
    Contact::new(&id, vec![CandidateAddr::direct("127.0.0.1", 1)])
}

// =====================================================================================================
// Layer 2 — bring-up / bootstrap / find_providers / inventory publishing over a MOCK swarm
// =====================================================================================================

/// An in-process swarm of virtual DHT nodes: peer_id (64-hex) → that node's own DhtService, so an
/// `rpc(peer, req)` dispatches to that node's `handle_request_from` with NO sockets. This mirrors
/// dig-dht's own (crate-private) memory harness so the locate + announce semantics are testable here.
#[derive(Clone, Default)]
struct Swarm {
    nodes: Arc<Mutex<HashMap<String, Arc<DhtService>>>>,
}

impl Swarm {
    fn new() -> Self {
        Swarm::default()
    }
    async fn register(&self, service: Arc<DhtService>) {
        self.nodes
            .lock()
            .await
            .insert(service.local_id().to_hex(), service);
    }
    fn transport(&self) -> SwarmTransport {
        SwarmTransport {
            swarm: self.clone(),
        }
    }
}

/// A [`DhtTransport`] over the [`Swarm`]: dispatch `rpc` to the target node's serving side, supplying
/// the CALLER (`from`) as the authenticated caller — exactly what a real mTLS transport does.
struct SwarmTransport {
    swarm: Swarm,
}

#[async_trait]
impl DhtTransport for SwarmTransport {
    async fn rpc(
        &self,
        from: &Contact,
        peer: &Contact,
        request: &DhtRequest,
    ) -> Result<DhtResponse, DhtError> {
        let target = {
            let nodes = self.swarm.nodes.lock().await;
            nodes.get(&peer.peer_id).cloned()
        };
        match target {
            Some(svc) => Ok(svc
                .handle_request_from(Some(from.clone()), request.clone())
                .await),
            None => Err(DhtError::transport(format!("no route to {}", peer.peer_id))),
        }
    }
}

/// Build a service for a virtual node with `seed`-derived id, sharing the swarm transport.
fn node(swarm: &Swarm, seed: u8) -> Arc<DhtService> {
    let id = PeerId::from_bytes([seed; 32]);
    Arc::new(DhtService::new(
        id,
        vec![CandidateAddr::direct(format!("10.0.0.{seed}"), 9444)],
        DhtConfig::default(),
        Arc::new(swarm.transport()),
    ))
}

fn bootstrap_of(svc: &Arc<DhtService>, seed: u8) -> BootstrapPeer {
    BootstrapPeer::direct(*svc.local_id(), format!("10.0.0.{seed}"), 9444)
}

#[tokio::test]
async fn announce_then_another_node_finds_the_provider_via_the_dht() {
    // Node A holds a capsule and announces it; node B bootstraps off A and find_providers locates A.
    let swarm = Swarm::new();
    let a = node(&swarm, 1);
    let b = node(&swarm, 2);
    swarm.register(a.clone()).await;
    swarm.register(b.clone()).await;

    // Both know each other (bootstrap).
    a.bootstrap(&[bootstrap_of(&b, 2)]).await.ok();
    b.bootstrap(&[bootstrap_of(&a, 1)]).await.ok();

    let content = ContentId::capsule([0xAAu8; 32], [0xBBu8; 32]);
    let accepted = a.announce_provider(&content).await.expect("announce");
    assert!(accepted >= 1, "announce PUT reached at least node B");

    // Node B locates node A as a provider of the content.
    let providers = b.find_providers(&content).await.expect("find_providers");
    assert!(
        providers
            .iter()
            .any(|p| p.provider_peer_id == a.local_id().to_hex()),
        "node B finds node A as the provider"
    );
}

#[tokio::test]
async fn startup_announce_publishes_every_held_capsule() {
    // announce_inventory over a bootstrapped node publishes store + capsule for each held capsule, and
    // a peer's find_providers then locates this node for that content.
    let swarm = Swarm::new();
    let holder = node(&swarm, 3);
    let finder = node(&swarm, 4);
    swarm.register(holder.clone()).await;
    swarm.register(finder.clone()).await;
    holder.bootstrap(&[bootstrap_of(&finder, 4)]).await.ok();
    finder.bootstrap(&[bootstrap_of(&holder, 3)]).await.ok();

    let store = "aa".repeat(32);
    let root = "11".repeat(32);
    let cached = vec![CachedCapsule {
        store_id: store.clone(),
        root: root.clone(),
        size_bytes: 10,
        last_used_unix_ms: 1,
    }];
    let n = announce_inventory(&holder, &cached).await;
    assert_eq!(n, 2, "store + capsule announced for one held capsule");

    // The finder locates the holder at BOTH granularities.
    let sb: [u8; 32] = <[u8; 32]>::try_from(hex::decode(&store).unwrap()).unwrap();
    let rb: [u8; 32] = <[u8; 32]>::try_from(hex::decode(&root).unwrap()).unwrap();
    let by_store = finder
        .find_providers(&ContentId::store(sb))
        .await
        .expect("find by store");
    assert!(
        by_store
            .iter()
            .any(|p| p.provider_peer_id == holder.local_id().to_hex()),
        "found by store granularity"
    );
    let by_capsule = finder
        .find_providers(&ContentId::capsule(sb, rb))
        .await
        .expect("find by capsule");
    assert!(
        by_capsule
            .iter()
            .any(|p| p.provider_peer_id == holder.local_id().to_hex()),
        "found by capsule granularity"
    );
}

#[tokio::test]
async fn withdraw_stops_republishing_removed_content() {
    // announce, then withdraw: withdraw_provider returns true (it was announced) and the content drops
    // out of the local announcement set (so republish no longer re-puts it).
    let swarm = Swarm::new();
    let n = node(&swarm, 5);
    swarm.register(n.clone()).await;

    let content = ContentId::capsule([1u8; 32], [2u8; 32]);
    n.announce_provider(&content).await.ok();
    assert!(
        n.withdraw_provider(&content).await,
        "withdraw reports it was being announced"
    );
    // Republish now announces nothing (the withdrawn content is no longer in the local set).
    assert_eq!(n.republish().await, 0, "nothing left to republish");
}

#[tokio::test]
async fn bootstrap_from_pool_seeds_the_routing_table() {
    // bootstrap_peers_from_pool → bootstrap fills the routing table with the pool peers.
    let swarm = Swarm::new();
    let joining = node(&swarm, 6);
    let seed_a = node(&swarm, 7);
    let seed_b = node(&swarm, 8);
    swarm.register(joining.clone()).await;
    swarm.register(seed_a.clone()).await;
    swarm.register(seed_b.clone()).await;

    let pool = vec![
        (
            *seed_a.local_id().as_bytes(),
            "10.0.0.7:9444".parse().unwrap(),
        ),
        (
            *seed_b.local_id().as_bytes(),
            "10.0.0.8:9444".parse().unwrap(),
        ),
    ];
    let bootstrap = bootstrap_peers_from_pool(&pool);
    let known = joining.bootstrap(&bootstrap).await.expect("bootstrap");
    assert!(known >= 2, "the routing table learned the pool peers");
}

#[test]
fn caller_contact_and_inventory_helpers_are_consistent() {
    // caller_contact records the peer + addr; inventory_content_ids yields store + capsule.
    let pid = PeerId::from_bytes([9u8; 32]);
    let addr: std::net::SocketAddr = "198.51.100.4:9444".parse().unwrap();
    let c = caller_contact(&pid, addr);
    assert_eq!(c.peer_id, pid.to_hex());

    let cached = vec![CachedCapsule {
        store_id: "cc".repeat(32),
        root: "dd".repeat(32),
        size_bytes: 1,
        last_used_unix_ms: 1,
    }];
    assert_eq!(inventory_content_ids(&cached).len(), 2);
}
