//! The forwarded availability ask, tested at the seam it merges into (dig_ecosystem#3128).
//!
//! Every test here drives [`NodeContent::locate_holders`] — the ONE place the recursive ask happens,
//! and therefore the one place both miss legs (the `-32008` redirect and the `dig.getAvailability`
//! enrichment) inherit their behaviour from. Driving anything shallower would pin a copy of the policy
//! rather than the policy.
//!
//! The asker is a double, so the fixtures can express the thing a real peer cannot be asked to
//! express on demand: a hostile answer, a silent peer, a specific fan-out.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId};
use dig_download::testkit::{mock_peer_hex, MockContent, MockProviderLocator, MockRangeTransport};
use dig_download::ProviderRecord;

use crate::download::{
    DiscoveryCache, MissMode, NodeContent, FORWARDED_ASK_FANOUT, MAX_REDIRECT_PROVIDERS,
    REDIRECT_HOP_CAP,
};
use crate::rate_limit::RequestorId;
use crate::seams::dig_peer::ForwardedAsk;

/// A [`ForwardedAsk`] double that answers every peer with `answer`, recording each ask it received.
///
/// It records the `next_depth` it was handed as well as the peer, because the hop budget is the bound
/// under test in half these cases and a double that could not observe it would leave that assertion
/// resting on the absence of a call rather than on its content.
struct RecordingAsk {
    answer: Vec<ProviderRecord>,
    asked: Mutex<Vec<(String, u64)>>,
}

impl RecordingAsk {
    fn answering(answer: Vec<ProviderRecord>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            asked: Mutex::new(Vec::new()),
        })
    }

    fn silent() -> Arc<Self> {
        Self::answering(Vec::new())
    }

    fn asked(&self) -> Vec<(String, u64)> {
        self.asked.lock().expect("recorder lock").clone()
    }
}

#[async_trait]
impl ForwardedAsk for RecordingAsk {
    async fn ask(
        &self,
        peer: &str,
        _addrs: &[SocketAddr],
        _content: &ContentId,
        next_depth: u64,
    ) -> Vec<ProviderRecord> {
        self.asked
            .lock()
            .expect("recorder lock")
            .push((peer.to_string(), next_depth));
        self.answer.clone()
    }
}

/// A [`DiscoveryCache`] double that records every key it was asked to forget.
struct RecordingCache {
    forgotten: Mutex<Vec<String>>,
}

impl RecordingCache {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            forgotten: Mutex::new(Vec::new()),
        })
    }

    fn forgotten(&self) -> Vec<String> {
        self.forgotten.lock().expect("cache lock").clone()
    }
}

#[async_trait]
impl DiscoveryCache for RecordingCache {
    async fn forget_discovered(&self, content: &ContentId) -> usize {
        self.forgotten
            .lock()
            .expect("cache lock")
            .push(content.to_key().to_hex());
        1
    }
}

/// A provider record for the peer numbered `n`, keyed to `content` — the same shape dig-download's
/// testkit mints, but for an arbitrary content id.
fn provider(n: u8, content: &ContentId) -> ProviderRecord {
    ProviderRecord::new(
        &content.to_key(),
        &PeerId::from_bytes([n; 32]),
        vec![CandidateAddr::direct(format!("10.0.0.{n}"), 9444)],
        u64::MAX,
    )
}

fn content() -> ContentId {
    ContentId::resource([0xC0; 32], [0xC1; 32], [0xC2; 32])
}

/// An engine whose DHT discovery answers with `dht_providers`, connected to `pool_peers`, and (when
/// `ask` is given) able to forward. Returns the engine plus the tempdir that must outlive it.
fn engine(
    dht_providers: Vec<ProviderRecord>,
    pool_peers: &[u8],
    ask: Option<Arc<dyn ForwardedAsk>>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = NodeContent::new(
        Arc::new(MockProviderLocator::fixed(dht_providers)),
        Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
        MissMode::Redirect,
        None,
        dir.path(),
    );
    {
        let pool = content.connected_pool();
        let mut guard = pool.lock().expect("pool lock");
        for n in pool_peers {
            guard.insert(
                mock_peer_hex(*n),
                vec![format!("10.0.0.{n}:9444")
                    .parse::<SocketAddr>()
                    .expect("test address")],
            );
        }
    }
    if let Some(ask) = ask {
        content.set_forwarded_ask(ask);
    }
    (content, dir)
}

fn peer_ids(providers: &[ProviderRecord]) -> Vec<String> {
    providers
        .iter()
        .map(|p| p.provider_peer_id.clone())
        .collect()
}

// -- The capability itself ------------------------------------------------------------------------

/// **Proves:** a holder NO DHT walk from this node can find is still named in the answer, because a
/// connected pool peer knew about it.
///
/// **The fixture is the whole point:** the DHT locator answers EMPTY. That is the partitioned network
/// this epic exists for — before this change the answer here was "nobody holds it", for content that
/// is genuinely two hops away.
#[tokio::test]
async fn a_holder_only_a_peer_knows_about_reaches_the_answer() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;

    assert_eq!(
        peer_ids(&found),
        vec![mock_peer_hex(9)],
        "the peer's holder is named even though this node's own lookup found nobody"
    );
    assert_eq!(
        ask.asked(),
        vec![(mock_peer_hex(1), 1)],
        "the connected peer was asked, at depth 0 + 1"
    );
}

/// **Proves:** with no forwarded-ask leg installed — the FFI/base path — the answer is exactly this
/// node's own DHT findings, unchanged.
///
/// **Catches:** a change that makes the enrichment mandatory. The base constructor has no identity and
/// no NAT runtime, so a miss there must degrade to shipped behaviour rather than fail.
#[tokio::test]
async fn without_the_leg_the_answer_is_the_shipped_dht_answer() {
    let cid = content();
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2, 3], None);

    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;

    assert_eq!(peer_ids(&found), vec![mock_peer_hex(1)]);
}

// -- Ordering: the property a placement bug would break ------------------------------------------

/// **Proves:** this node's OWN DHT findings lead the answer and the forwarded ones follow, AND that
/// the [`MAX_REDIRECT_PROVIDERS`] truncation therefore falls on the forwarded tail.
///
/// **Catches the placement, not just the outcome.** A test that only asserted "the DHT holder is
/// present" would pass just as happily with the forwarded records prepended. So the fixture makes the
/// peer answer with a FULL slate — `MAX_REDIRECT_PROVIDERS` fabricated holders — against a single
/// honest DHT holder, and asserts the honest one both LEADS and SURVIVES. Prepending would evict it
/// entirely at the cap; appending in the wrong position would move it. Either mutation is visible
/// here, and neither is visible to a presence assertion.
///
/// This is the reason ordering is a contract rather than an implementation detail: the requestor dials
/// in list order, so the head of this list is the candidate it actually tries.
#[tokio::test]
async fn a_hostile_slate_of_forwarded_holders_cannot_displace_our_own() {
    let cid = content();
    let fabricated: Vec<ProviderRecord> = (100..100 + MAX_REDIRECT_PROVIDERS as u8)
        .map(|n| provider(n, &cid))
        .collect();
    let ask = RecordingAsk::answering(fabricated);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(ask));

    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;

    assert_eq!(
        found[0].provider_peer_id,
        mock_peer_hex(1),
        "our own DHT holder leads, so it is the first candidate the requestor dials"
    );
    let named = crate::download::providers_json(&found);
    let named = named.as_array().expect("providers array");
    assert_eq!(named.len(), MAX_REDIRECT_PROVIDERS, "the cap still applies");
    assert_eq!(
        named[0]["peer_id"],
        mock_peer_hex(1),
        "and the cap truncated the forwarded TAIL, never our own holder"
    );
}

/// **Proves:** a forwarded record naming a peer this node already found is dropped, keeping the FIRST
/// (DHT) occurrence and its position.
///
/// **Catches:** a duplicate consuming a second slot under [`MAX_REDIRECT_PROVIDERS`], which is a free
/// way for one peer to halve the number of distinct holders a requestor is offered.
#[tokio::test]
async fn a_forwarded_duplicate_does_not_take_a_second_slot() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(1, &cid), provider(7, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(ask));

    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;

    assert_eq!(
        peer_ids(&found),
        vec![mock_peer_hex(1), mock_peer_hex(7)],
        "peer 1 appears exactly once (ordering is pinned separately, above)"
    );
}

// -- Depth: the bound that stops a question circulating forever ----------------------------------

/// **Proves:** a request that has already consumed the whole hop budget forwards NOTHING, and still
/// answers from the DHT.
///
/// **Catches:** the unbounded recursion. Without this the same question loops around a ring of nodes
/// for as long as they keep answering.
///
/// Pinned from BOTH sides — at the cap must not forward, one under the cap must — because a bound
/// tested only from one side can only confirm itself.
#[tokio::test]
async fn the_hop_budget_is_pinned_from_both_sides() {
    let cid = content();

    let at_cap = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(at_cap.clone()));
    let found = pc
        .locate_holders(&cid, REDIRECT_HOP_CAP, &RequestorId::Peer("caller".into()))
        .await;
    assert!(at_cap.asked().is_empty(), "at the cap: nobody is asked");
    assert_eq!(
        peer_ids(&found),
        vec![mock_peer_hex(1)],
        "at the cap: the DHT answer still stands (the request is answered, not refused)"
    );

    let under_cap = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(under_cap.clone()));
    let found = pc
        .locate_holders(
            &cid,
            REDIRECT_HOP_CAP - 1,
            &RequestorId::Peer("caller".into()),
        )
        .await;
    assert_eq!(
        under_cap.asked(),
        vec![(mock_peer_hex(2), REDIRECT_HOP_CAP)],
        "one under the cap: the ask goes out carrying the SPENT budget, so the next hop stops"
    );
    assert!(peer_ids(&found).contains(&mock_peer_hex(9)));
}

// -- Breadth + loop safety -----------------------------------------------------------------------

/// **Proves:** at most [`FORWARDED_ASK_FANOUT`] peers are asked, however large the connected pool is.
///
/// **Catches:** the fan-out becoming the pool size, which turns one admitted miss into a pool-wide
/// broadcast — and, recursively, into `pool_size ^ REDIRECT_HOP_CAP` work.
///
#[tokio::test]
async fn the_fan_out_is_capped_regardless_of_pool_size() {
    let cid = content();
    let ask = RecordingAsk::silent();
    let pool: Vec<u8> = (1..=20).collect();
    let (pc, _dir) = engine(Vec::new(), &pool, Some(ask.clone()));

    pc.locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;

    assert_eq!(
        ask.asked().len(),
        FORWARDED_ASK_FANOUT,
        "the fan-out bounds the ask, not the pool"
    );
}

/// **Proves:** the peer that asked is never asked back.
///
/// **Catches:** the tightest loop this path can form — A asks B, B asks A, and the hop counter alone
/// would happily let that bounce to the cap, spending four round-trips to learn nothing.
///
/// The fixture keeps a SECOND, innocent peer in the pool so the assertion distinguishes "excluded the
/// requestor" from "excluded everyone" — the same test with only the requestor connected would pass
/// against an implementation that had simply stopped forwarding.
#[tokio::test]
async fn the_asking_peer_is_never_asked_back() {
    let cid = content();
    let ask = RecordingAsk::silent();
    let (pc, _dir) = engine(Vec::new(), &[1, 2], Some(ask.clone()));

    pc.locate_holders(&cid, 0, &RequestorId::Peer(mock_peer_hex(1)))
        .await;

    let asked: Vec<String> = ask.asked().into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        asked,
        vec![mock_peer_hex(2)],
        "the innocent peer is asked; the requestor is not"
    );
}

// -- The relay bucket ----------------------------------------------------------------------------

/// **Proves:** the outbound fan-out is charged to a SEPARATE per-requestor bucket, and an exhausted
/// relay allowance stops the forwarding without touching the answer's DHT half.
///
/// **Catches:** the budget-laundering S5 named. `RequestorId` keys by the IMMEDIATE caller, so a
/// relaying hop's fan-out lands on that hop's own allowance at its peers — one admitted inbound frame
/// spending a victim's budget across every peer it holds. A shared bucket would also let a caller
/// convert cheap-lookup tokens into fan-out at third parties.
///
/// The fixture drives the SECOND caller with the first one's bucket already drained, and asserts the
/// second caller is untouched — a single-caller test could not tell a per-requestor bound from a
/// global one.
#[tokio::test]
async fn the_relay_allowance_is_per_requestor_and_separate_from_the_lookup_budget() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(ask.clone()));
    // A fixed pool of ONE, no refill: the second forward from the same requestor must be refused
    // without waiting on wall-clock time.
    pc.set_relay_rate_limit(1.0, 0.0);

    let abuser = RequestorId::Peer("abuser".into());
    pc.locate_holders(&cid, 0, &abuser).await;
    let second = pc.locate_holders(&cid, 0, &abuser).await;

    assert_eq!(
        ask.asked().len(),
        1,
        "the abuser's relay allowance is spent"
    );
    assert_eq!(
        peer_ids(&second),
        vec![mock_peer_hex(1)],
        "and the answer degrades to the DHT half rather than failing"
    );

    let honest = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("honest".into()))
        .await;
    assert!(
        peer_ids(&honest).contains(&mock_peer_hex(9)),
        "a DIFFERENT caller still forwards — the bound is per requestor, not global"
    );

    // And the lookup budget was never the thing spent: it is still willing to admit a miss.
    assert!(
        pc.allow_miss_lookup(&abuser),
        "the relay leg draws from its OWN bucket, never the cheap-lookup allowance"
    );
}

/// **Proves:** the node-wide ceiling refuses a forward when every slot is held, and the miss still
/// answers.
///
/// **Catches:** the amplification the per-requestor buckets structurally cannot see — many requestors
/// each inside their own budget, summing to hundreds of concurrent outbound dials.
#[tokio::test]
async fn the_node_wide_ceiling_refuses_a_forward_when_every_slot_is_held() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(ask.clone()));

    let held = pc.hold_every_forwarded_ask_slot();

    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;
    assert!(ask.asked().is_empty(), "no forward while the node is full");
    assert_eq!(peer_ids(&found), vec![mock_peer_hex(1)], "still answered");

    drop(held);
    let found = pc
        .locate_holders(&cid, 0, &RequestorId::Peer("caller".into()))
        .await;
    assert!(
        peer_ids(&found).contains(&mock_peer_hex(9)),
        "and forwarding resumes once the slots are released — the ceiling gates, never latches"
    );
}

// -- dig-dht SPEC 6.8: the escape from a sticky lookup answer -------------------------------------

/// **Proves:** a download that reaches none of its located candidates forgets the cached lookup
/// answer, so the next attempt runs a real walk.
///
/// **Catches:** the unwired MUST. dig-dht's lookup early-exits on the first on-key answer, so a lying
/// first hop can return a fabricated provider set; the discovery cache makes that answer STICKY for 15
/// minutes, and this call is the only escape from it. With no caller, a poisoned answer persists for
/// the full TTL and every retry replays the identical unreachable set.
#[tokio::test]
async fn a_download_that_reaches_nobody_forgets_the_cached_lookup_answer() {
    let cid = content();
    // No providers at all, so the download cannot complete — the "reached none of them" state.
    let (pc, _dir) = engine(Vec::new(), &[], None);
    let cache = RecordingCache::new();
    pc.set_discovery_cache(cache.clone());

    let outcome = pc
        .fetch_resource(&cid, crate::download::ReadOrigin::Local)
        .await;

    assert!(
        outcome.is_err(),
        "the fetch failed, which is the precondition"
    );
    assert_eq!(
        cache.forgotten(),
        vec![cid.to_key().to_hex()],
        "the cached answer for THAT key was dropped"
    );
}

/// **Proves:** a SUCCESSFUL download does not forget anything.
///
/// **Catches:** wiring the call on the wrong edge. Forgetting on every fetch would discard a working
/// answer on the happy path and turn the cache — requirement 7's whole point — back into the
/// per-request Kademlia walk it was built to remove. This is the control that makes the test above a
/// statement about failure rather than about fetching.
#[tokio::test]
async fn a_successful_download_forgets_nothing() {
    let mock = crate::download::tests::anchored_mock_content(4, 1);
    let cid = crate::download::tests::anchored_cid_for(&mock);
    let dir = tempfile::tempdir().expect("tempdir");
    let pc = NodeContent::new(
        Arc::new(MockProviderLocator::fixed(vec![provider(1, &cid)])),
        Arc::new(MockRangeTransport::new(mock)),
        MissMode::FetchThrough,
        None,
        dir.path(),
    );
    let cache = RecordingCache::new();
    pc.set_discovery_cache(cache.clone());

    pc.fetch_resource(&cid, crate::download::ReadOrigin::Local)
        .await
        .expect("the download succeeds");

    assert!(
        cache.forgotten().is_empty(),
        "a working candidate set is kept — forgetting it would undo the lookup cache entirely"
    );
}
