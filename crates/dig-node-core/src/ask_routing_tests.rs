//! The forwarded ask, ROUTED — dig-sex 0.5's ranking driven through the real
//! [`NodeContent::locate_holders`] path (dig_ecosystem#3129 WU2).
//!
//! [`crate::forwarded_ask_tests`] pins WHETHER and WITH WHAT BUDGET an ask is forwarded. This module
//! pins WHO it is forwarded to, and that the answers come back into this node's routing memory. The
//! two are separated because the ranking is the only part of the decision dig-node supplies, and it is
//! the only part the crate's own tests structurally cannot cover.
//!
//! Every test here drives the production seam rather than [`crate::seams::dig_peer::AskRoutingState`]
//! directly: the ordering unit tests next to that type prove the ranking is correct, and these prove
//! it is REACHED. An adoption that ranked perfectly in a module nothing called would pass the former
//! and fail the latter, which is exactly the inert-adoption failure this work unit has to exclude.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_download::testkit::mock_peer_hex;

use crate::download::HopBudget;
use crate::forwarded_ask_tests::{content, engine_for_routing, provider};
use crate::rate_limit::RequestorId;
use crate::seams::dig_peer::{AskId, AskOutcome, ForwardedAsk, RoutedPeer};

/// A [`ForwardedAsk`] double that answers each peer according to a rule, recording who it asked.
///
/// Deliberately WIDER than [`RecordingAsk`](crate::forwarded_ask_tests), which answers every peer
/// identically: a double that can only say one thing to everybody cannot express "this peer answers
/// and that one does not", which is the only input a ranking has to work with. A uniform double would
/// leave every ranking assertion resting on a distinction the fixture never made.
struct PerPeerAsk {
    /// The peers that answer with a holder. Everyone else is unreachable.
    answering: HashSet<String>,
    asked: Mutex<Vec<String>>,
}

impl PerPeerAsk {
    fn answering_only(peers: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            answering: peers.iter().copied().map(mock_peer_hex).collect(),
            asked: Mutex::new(Vec::new()),
        })
    }

    /// Nobody answers — every peer is observed silent. The fixture for the round-to-round test, where
    /// the point is that the SECOND round must move on rather than that any peer is good.
    fn silent() -> Arc<Self> {
        Self::answering_only(&[])
    }

    /// The peers asked since the last [`Self::drain`], in arrival order.
    fn drain(&self) -> Vec<String> {
        std::mem::take(&mut *self.asked.lock().expect("recorder lock"))
    }
}

#[async_trait]
impl ForwardedAsk for PerPeerAsk {
    async fn ask(
        &self,
        peer: &str,
        _addrs: &[SocketAddr],
        content: &ContentId,
        _next_depth: u64,
        _budget: Duration,
        _ask_id: AskId,
    ) -> AskOutcome {
        self.asked.lock().expect("recorder lock").push(peer.into());
        if self.answering.contains(peer) {
            AskOutcome::Answered(vec![provider(99, content)])
        } else {
            AskOutcome::Unreachable
        }
    }
}

/// A pool large enough that the fan-out cannot cover it twice over — the precondition the
/// round-to-round test needs, since a fan-out that reaches every peer makes "asked someone else"
/// impossible to express.
const POOL: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

/// **THE test for this work unit: the ranked slate REACHES `decide_forward`.**
///
/// **The property:** the peers a second forwarded ask goes to depend on what the FIRST one observed.
///
/// **Why this fixture and not an easier one.** A prefix of the connected-pool `HashMap` — the shipped
/// 0.4 behaviour — is arbitrary but *stable*, so it returns the SAME peers on every round for the life
/// of the process. A ranking cannot: the round-one peers are now observed silent, scoring below the
/// unobserved baseline, so round two must move to peers it has never tried. Asserting DISJOINTNESS
/// between the two rounds therefore separates the two implementations **without depending on the
/// `HashMap`'s order at all** — which matters, because that order is not something a test can control
/// and any assertion resting on it would be pinning a coincidence.
///
/// An assertion that merely counted asks, or checked that some peer was asked, is satisfied
/// identically by the prefix implementation and would have let an inert adoption ship.
#[tokio::test]
async fn a_second_ask_avoids_the_peers_the_first_one_found_silent() {
    let cid = content();
    let ask = PerPeerAsk::silent();
    let (pc, _dir) = engine_for_routing(POOL, ask.clone());

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;
    let first: HashSet<String> = ask.drain().into_iter().collect();
    assert!(
        !first.is_empty(),
        "the first round must actually forward, or there is nothing to observe"
    );

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;
    let second: HashSet<String> = ask.drain().into_iter().collect();

    assert_eq!(
        second.len(),
        first.len(),
        "the fan-out is unchanged; only WHO it reaches moves"
    );
    assert!(
        first.is_disjoint(&second),
        "a peer observed silent must not be re-asked while untried peers remain \
         (first={first:?}, second={second:?})"
    );
}

/// **Proves the recording leg is wired at all:** an exchange this node completed leaves an observation
/// behind, and it leaves the RIGHT one.
///
/// **Both classes are present in one fixture**, one peer answering with a holder and the rest
/// unreachable, because a store that recorded every outcome as the same value would satisfy a
/// presence-only assertion. The scores are compared rather than read as literals: the exact numbers
/// are `dig-sex`'s to choose, and pinning them here would make this test fail on a re-weighting that
/// broke nothing.
#[tokio::test]
async fn a_completed_exchange_leaves_the_outcome_it_earned_in_the_routing_memory() {
    let cid = content();
    // Peer 1 is in the pool of two, so the default fan-out reaches both and each is observed once.
    let ask = PerPeerAsk::answering_only(&[1]);
    let (pc, _dir) = engine_for_routing(&[1, 2], ask.clone());

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;

    let asked = ask.drain();
    assert_eq!(asked.len(), 2, "both pool peers were asked: {asked:?}");

    let routing = pc.ask_routing();
    let answerer = RoutedPeer::from_pool_key(&mock_peer_hex(1)).expect("a mock peer id is 64-hex");
    let silent = RoutedPeer::from_pool_key(&mock_peer_hex(2)).expect("a mock peer id is 64-hex");

    assert!(
        !routing.is_unobserved(answerer) && !routing.is_unobserved(silent),
        "every completed exchange is recorded, not only the successful one"
    );
    assert!(
        routing.quality_of(answerer) > routing.quality_of(silent),
        "the peer that named a holder outranks the peer that could not be reached"
    );
}

/// **Proves the bound:** the routing memory holds only peers presently in the pool, so it is never
/// keyed by anything untrusted and cannot grow while the pool does not.
///
/// A peer is dropped from the pool BETWEEN two asks. The surviving peer is kept in place so a `retain`
/// that cleared the whole map — which would satisfy "the departed peer is gone" vacuously — fails just
/// as loudly as one that kept it.
#[tokio::test]
async fn a_peer_dropped_from_the_pool_is_forgotten_at_that_moment() {
    let cid = content();
    let ask = PerPeerAsk::silent();
    let (pc, _dir) = engine_for_routing(&[1, 2], ask.clone());

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;
    assert_eq!(pc.ask_routing().observed_len(), 2, "both peers observed");

    {
        let pool = pc.connected_pool();
        let mut guard = pool.lock().expect("pool lock");
        guard.remove(&mock_peer_hex(2));
    }
    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;

    let routing = pc.ask_routing();
    assert_eq!(
        routing.observed_len(),
        1,
        "the departed peer is dropped and the remaining one is not"
    );
    assert!(routing.is_unobserved(
        RoutedPeer::from_pool_key(&mock_peer_hex(2)).expect("a mock peer id is 64-hex")
    ));
    assert!(!routing.is_unobserved(
        RoutedPeer::from_pool_key(&mock_peer_hex(1)).expect("a mock peer id is 64-hex")
    ));
}
