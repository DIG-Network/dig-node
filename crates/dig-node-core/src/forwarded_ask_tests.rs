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
use std::time::Duration;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId};
use dig_download::testkit::{mock_peer_hex, MockContent, MockProviderLocator, MockRangeTransport};
use dig_download::ProviderRecord;

use crate::download::{
    DiscoveryCache, HopBudget, MissMode, MissOutcome, NodeContent, MAX_REDIRECT_PROVIDERS,
};
use dig_sex::discovery::RecursionConfig;

/// The recursion bounds every test here runs under: the canonical crate's, switched ON.
///
/// Taken from `RecursionConfig::default()` rather than restated, so a change to the canonical
/// `fan_out` or `hop_cap` moves these tests with it instead of leaving them pinning a private copy of
/// numbers the node no longer uses. Only `enabled` is overridden — the default is OFF, which is the
/// production posture and is asserted separately in `download.rs`.
pub(crate) fn recursion() -> RecursionConfig {
    RecursionConfig {
        enabled: true,
        ..Default::default()
    }
}
use crate::rate_limit::RequestorId;
use crate::seams::dig_peer::{AskId, AskOutcome, ForwardedAsk, MAX_FORWARDED_ASK_BUDGET};

/// A [`ForwardedAsk`] double that answers every peer with `answer`, recording each ask it received.
///
/// It records the `next_depth` it was handed as well as the peer, because the hop budget is the bound
/// under test in half these cases and a double that could not observe it would leave that assertion
/// resting on the absence of a call rather than on its content.
pub(crate) struct RecordingAsk {
    answer: Vec<ProviderRecord>,
    asked: Mutex<Vec<(String, u64)>>,
    /// The wall-clock budget each ask was granted, in arrival order — so a test can assert the
    /// budget a hop HANDS DOWN rather than only that it asked. Without this the budget arithmetic
    /// would rest on a call's absence instead of its content.
    budgets: Mutex<Vec<Duration>>,
    /// The ask identity each ask was forwarded under, in arrival order.
    ask_ids: Mutex<Vec<AskId>>,
}

impl RecordingAsk {
    pub(crate) fn answering(answer: Vec<ProviderRecord>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            asked: Mutex::new(Vec::new()),
            budgets: Mutex::new(Vec::new()),
            ask_ids: Mutex::new(Vec::new()),
        })
    }

    fn silent() -> Arc<Self> {
        Self::answering(Vec::new())
    }

    pub(crate) fn asked(&self) -> Vec<(String, u64)> {
        self.asked.lock().expect("recorder lock").clone()
    }

    /// The budgets granted, in arrival order.
    fn budgets(&self) -> Vec<Duration> {
        self.budgets.lock().expect("recorder lock").clone()
    }

    /// The ask identities forwarded under, in arrival order. Recorded because the identity is the
    /// one field a hop must ECHO rather than choose, and a hop that mints a fresh one is
    /// indistinguishable from a correct hop at every other observation point.
    fn ask_ids(&self) -> Vec<AskId> {
        self.ask_ids.lock().expect("recorder lock").clone()
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
        budget: Duration,
        ask_id: AskId,
    ) -> AskOutcome {
        self.budgets.lock().expect("recorder lock").push(budget);
        self.ask_ids.lock().expect("recorder lock").push(ask_id);
        self.asked
            .lock()
            .expect("recorder lock")
            .push((peer.to_string(), next_depth));
        AskOutcome::Answered(self.answer.clone())
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
pub(crate) fn provider(n: u8, content: &ContentId) -> ProviderRecord {
    ProviderRecord::new(
        &content.to_key(),
        &PeerId::from_bytes([n; 32]),
        vec![CandidateAddr::direct(format!("10.0.0.{n}"), 9444)],
        u64::MAX,
    )
}

pub(crate) fn content() -> ContentId {
    ContentId::resource([0xC0; 32], [0xC1; 32], [0xC2; 32])
}

/// An engine wired for a ROUTING test: no DHT findings at all, so the answer is whatever the
/// forwarded leg produces, and a pool of `pool_peers` to route among.
///
/// Shares this module's builder rather than restating it, so the two test modules cannot drift into
/// exercising differently-configured nodes and reporting the difference as a behaviour change.
pub(crate) fn engine_for_routing(
    pool_peers: &[u8],
    ask: Arc<dyn ForwardedAsk>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    engine(Vec::new(), pool_peers, Some(ask))
}

/// An engine whose DHT discovery answers with `dht_providers`, connected to `pool_peers`, and (when
/// `ask` is given) able to forward. Returns the engine plus the tempdir that must outlive it.
fn engine(
    dht_providers: Vec<ProviderRecord>,
    pool_peers: &[u8],
    ask: Option<Arc<dyn ForwardedAsk>>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    engine_identified(dht_providers, pool_peers, ask, None)
}

/// As [`engine`], but the node KNOWS its own `peer_id` — the precondition every self-exclusion
/// assertion needs, since a node with no resolved identity has nothing to exclude.
fn engine_identified(
    dht_providers: Vec<ProviderRecord>,
    pool_peers: &[u8],
    ask: Option<Arc<dyn ForwardedAsk>>,
    self_peer_id: Option<String>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = NodeContent::new(
        Arc::new(MockProviderLocator::fixed(dht_providers)),
        Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
        MissMode::Redirect,
        self_peer_id,
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
        content.set_forwarded_ask(ask, recursion());
    }
    (content, dir)
}

/// A [`ProviderLocator`] that answers with a fixed slate and COUNTS how often it was walked.
///
/// The stock `MockProviderLocator` cannot report its call count, which is what forced an earlier
/// version of the cache test onto a proxy assertion. Counting the walk directly is the difference
/// between proving "rediscovery was skipped" and proving "something was skipped".
#[derive(Clone)]
struct CountingLocator {
    answer: Vec<ProviderRecord>,
    lookups: Arc<Mutex<usize>>,
}

impl CountingLocator {
    fn answering(answer: Vec<ProviderRecord>) -> Self {
        Self {
            answer,
            lookups: Arc::new(Mutex::new(0)),
        }
    }

    fn lookups(&self) -> usize {
        *self.lookups.lock().expect("counter lock")
    }
}

#[async_trait]
impl dig_download::ProviderLocator for CountingLocator {
    async fn find_providers(
        &self,
        _content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, dig_download::DownloadError> {
        *self.lookups.lock().expect("counter lock") += 1;
        Ok(self.answer.clone())
    }
}

/// As [`engine`], but over a caller-supplied locator so the DHT walk itself is observable.
fn engine_with_locator(
    locator: CountingLocator,
    pool_peers: &[u8],
    ask: Option<Arc<dyn ForwardedAsk>>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = NodeContent::new(
        Arc::new(locator),
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
        content.set_forwarded_ask(ask, recursion());
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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
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

/// **Proves (NC-12, `seams::dig_peer::holder_cache` module doc):** a peer's HEARSAY never enters the
/// first-hand holder cache, even though it is perfectly welcome in the answer.
///
/// **Why this is the sharpest thing to pin about that cache.** `FirstHandHolderCache::remember` says
/// in its own doc that "the caller is responsible for passing first-hand records only", so the
/// property is a discipline of `locate_holders` rather than an invariant the type enforces. The
/// module doc names exactly what it buys: a cache that stored hearsay would let one lying hop plant a
/// fabricated holder that this node then re-serves as its OWN knowledge for the whole TTL -- "a far
/// better attack than lying once", because it converts a single lie into an hour of this node
/// repeating it to everyone who asks.
///
/// **Fixture design -- two DISTINGUISHABLE records, one per leg, and the inequality is the test.**
/// The DHT names peer 1 and the forwarded leg names peer 9. Both are required: with an empty DHT the
/// cache would be empty because `remember` declines an empty slate, which is a DIFFERENT reason and
/// would let this test pass under an implementation that cached hearsay happily. With one shared
/// record there would be nothing to tell "cached mine" from "cached theirs" apart. So the answer must
/// contain BOTH and the cache must contain ONLY the first-hand one.
///
/// **On the revert:** add `self.holder_cache.remember(content, &forwarded.records);` after the
/// forwarded leg in `NodeContent::locate_holders` -- one line -- and the cache assertion fires.
#[tokio::test]
async fn a_peers_hearsay_reaches_the_answer_but_never_the_first_hand_cache() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(ask.clone()));

    let found = pc
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
        .await;

    // The control: BOTH legs genuinely contributed, so the cache assertion below is comparing two
    // populated sources rather than observing one empty one.
    assert_eq!(
        peer_ids(&found),
        vec![mock_peer_hex(1), mock_peer_hex(9)],
        "fixture precondition: the answer must carry this node's own finding AND the peer's \
         hearsay, first-hand ahead of hearsay"
    );

    let cached = pc
        .holder_cache()
        .get(&cid)
        .expect("a completed walk that found a holder is remembered");
    assert_eq!(
        peer_ids(&cached),
        vec![mock_peer_hex(1)],
        "only THIS node's own lookup may be remembered; caching the peer's hearsay would let one \
         lying hop plant a holder this node re-serves as its own for the whole TTL"
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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
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
    let cap = u64::from(recursion().hop_cap);

    let at_cap = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(at_cap.clone()));
    let found = pc
        .locate_holder_candidates(
            &cid,
            HopBudget::at_depth(cap),
            &RequestorId::Peer("caller".into()),
        )
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
        .locate_holder_candidates(
            &cid,
            HopBudget::at_depth(cap - 1),
            &RequestorId::Peer("caller".into()),
        )
        .await;
    assert_eq!(
        under_cap.asked(),
        vec![(mock_peer_hex(2), cap)],
        "one under the cap: the ask goes out carrying the SPENT budget, so the next hop stops"
    );
    assert!(peer_ids(&found).contains(&mock_peer_hex(9)));
}

/// **Proves:** a request whose hop budget is PRESENT but cannot be read forwards nothing — the
/// consolidation's headline behaviour change (dig-node#281, dig-node#272).
///
/// **Catches:** the exact defect dig-node's own copy had. It parsed the budget with
/// `.and_then(Value::as_u64).unwrap_or(0)`, so an unreadable value became `0` — *the most permissive
/// value the field has* — and a request whose reach could not be bounded was granted the whole
/// budget, at every hop, forever.
///
/// **The fixture distinguishes the property from its nearest wrong implementation.** The DHT leg
/// answers with an honest holder, so "nothing was forwarded" cannot be satisfied by "the whole answer
/// collapsed" — which is what a fixture with an empty DHT leg would have accepted. And the control
/// below it is the SAME request with a readable budget, which must forward, so the test cannot pass
/// against an implementation that simply stopped forwarding altogether.
#[tokio::test]
async fn an_unreadable_hop_budget_forwards_nothing_while_a_readable_one_forwards() {
    let cid = content();

    let unreadable = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(unreadable.clone()));
    let found = pc
        .locate_holder_candidates(
            &cid,
            HopBudget::from_params(&serde_json::json!({"redirect_depth": "0"})),
            &RequestorId::Peer("caller".into()),
        )
        .await;
    assert!(
        unreadable.asked().is_empty(),
        "an unreadable budget must be REFUSED, never read as a full one"
    );
    assert_eq!(
        peer_ids(&found),
        vec![mock_peer_hex(1)],
        "and the request is still answered from this node's own lookup"
    );

    let readable = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(vec![provider(1, &cid)], &[2], Some(readable.clone()));
    pc.locate_holder_candidates(
        &cid,
        HopBudget::from_params(&serde_json::json!({"redirect_depth": 0})),
        &RequestorId::Peer("caller".into()),
    )
    .await;
    assert_eq!(
        readable.asked().len(),
        1,
        "the CONTROL: the same request with a readable budget does forward"
    );
}

// -- Breadth + loop safety -----------------------------------------------------------------------

/// **Proves:** at most the canonical `fan_out` peers are asked, however large the connected pool is.
///
/// **Catches:** the fan-out becoming the pool size, which turns one admitted miss into a pool-wide
/// broadcast — and, recursively, into `pool_size ^ hop_cap` work. It also catches the rival's own
/// bound surviving the consolidation: dig-node fanned out to 4 over a cap of 4, about 1,360 dials per
/// admitted frame, against the crate's 9.
#[tokio::test]
async fn the_fan_out_is_capped_regardless_of_pool_size() {
    let cid = content();
    let ask = RecordingAsk::silent();
    let pool: Vec<u8> = (1..=20).collect();
    let (pc, _dir) = engine(Vec::new(), &pool, Some(ask.clone()));

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer("caller".into()),
    )
    .await;

    assert_eq!(
        ask.asked().len(),
        usize::from(recursion().fan_out),
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

    pc.locate_holder_candidates(
        &cid,
        HopBudget::fresh(),
        &RequestorId::Peer(mock_peer_hex(1)),
    )
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
    pc.locate_holder_candidates(&cid, HopBudget::fresh(), &abuser)
        .await;
    let second = pc
        .locate_holder_candidates(&cid, HopBudget::fresh(), &abuser)
        .await;

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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("honest".into()),
        )
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
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
        .await;
    assert!(ask.asked().is_empty(), "no forward while the node is full");
    assert_eq!(peer_ids(&found), vec![mock_peer_hex(1)], "still answered");

    drop(held);
    let found = pc
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("caller".into()),
        )
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

// -- Self-exclusion: the SPEC states it of EVERY source (dig-node#261) ----------------------------

/// **Proves:** a provider record naming THIS node, arriving by the FORWARDED path, never reaches the
/// merged answer — the rule `SPEC.md` §19.3 states of every source, honoured on the source that did
/// not honour it.
///
/// **This is NOT the exclusion `decide_forward` performs, and the difference is why the test stays.**
/// The crate excludes self from the peers this node ASKS. Nothing stops a peer from ANSWERING with a
/// record that names us, and `merge_answers` does not filter one out. The two rules travel in
/// opposite directions and adopting the crate discharges only one of them.
///
/// **The fixture distinguishes the property from its nearest wrong implementation.** The peer answers
/// with TWO records — self and an honest third party — so "self was excluded" cannot be satisfied by
/// "the forwarded leg returned nothing", which is what a fixture naming only self would have
/// accepted. The DHT leg answers EMPTY, so the surviving record can only have come through the
/// forwarded path.
#[tokio::test]
async fn a_forwarded_record_naming_this_node_never_reaches_the_answer() {
    let cid = content();
    let me = mock_peer_hex(9);
    let honest = provider(7, &cid);
    let ask = RecordingAsk::answering(vec![provider(9, &cid), honest.clone()]);
    let (pc, _dir) = engine_identified(Vec::new(), &[1], Some(ask), Some(me.clone()));

    let found = pc
        .locate_holder_candidates(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    let ids = peer_ids(&found);
    assert!(
        !ids.contains(&me),
        "a forwarded record naming this node must be dropped, got {ids:?}"
    );
    assert_eq!(
        ids,
        vec![honest.provider_peer_id.clone()],
        "and ONLY self is dropped — the honest third party the same answer named survives"
    );
}

/// **The control for the test above:** the IDENTICAL record arriving by the DHT leg is dropped too.
///
/// Without this, `a_forwarded_record_naming_this_node_never_reaches_the_answer` cannot tell
/// "self is excluded from every source" apart from "the forwarded leg is broken and drops things", and
/// it would stay green under a change that silently disabled forwarding altogether.
#[tokio::test]
async fn the_same_record_arriving_by_the_dht_leg_is_dropped_by_the_same_rule() {
    let cid = content();
    let me = mock_peer_hex(9);
    let honest = provider(7, &cid);
    let (pc, _dir) = engine_identified(
        vec![provider(9, &cid), honest.clone()],
        &[],
        None,
        Some(me.clone()),
    );

    let found = pc
        .locate_holder_candidates(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert_eq!(
        peer_ids(&found),
        vec![honest.provider_peer_id.clone()],
        "self is excluded on the DHT leg as well, and the honest holder survives"
    );
}

// -- A to B to C: the capability this epic exists for, observed end to end -------------------------

/// An asker that forwards into a REAL second [`NodeContent`] instead of answering from a fixture —
/// node B, standing between the requestor and the holder.
///
/// This is what makes the round-trip below evidence rather than a restatement: the middle hop runs the
/// SAME consolidated decision, against its own peers and its own budget, and the answer that comes
/// back is one it genuinely had to recurse to find.
struct ChainedAsk {
    next_hop: Arc<NodeContent>,
}

#[async_trait]
impl ForwardedAsk for ChainedAsk {
    async fn ask(
        &self,
        _peer: &str,
        _addrs: &[SocketAddr],
        content: &ContentId,
        next_depth: u64,
        budget: Duration,
        ask_id: AskId,
    ) -> AskOutcome {
        // The wire carries hops CONSUMED and the time budget separately, so the receiving node
        // reconstructs both — exactly as the real inbound path does via `HopBudget::from_params`.
        //
        // **The timeout is REAL, and that is the point.** This double previously had none, which made
        // it structurally unable to exhibit the defect dig-node#273 fixed: a child granted less time
        // than its own subtree needs times out at its parent, and the parent then reports a confident
        // not-found. A fixture with no clock cannot see that, so the property read as proven while the
        // arithmetic was wrong. Enforcing the granted budget here is what makes the two-hop tests
        // evidence.
        let upstream = RequestorId::Peer("upstream".into());
        let onward = self.next_hop.locate_holders(
            content,
            HopBudget::at_depth(next_depth)
                .with_time(budget)
                .with_ask_id(ask_id),
            &upstream,
        );
        match tokio::time::timeout(budget, onward).await {
            Ok(located) if located.establishes_absence() => {
                AskOutcome::Answered(located.into_candidates())
            }
            // The subtree answered, but not completely — its own absence is unproven, so this hop must
            // not launder it into one.
            Ok(located) if !located.is_empty() => AskOutcome::Answered(located.into_candidates()),
            Ok(_) => AskOutcome::Unreachable,
            Err(_) => AskOutcome::TimedOut,
        }
    }
}

/// A [`ForwardedAsk`] double that never answers inside the budget it is granted.
///
/// It sleeps for strictly longer than the budget and then reports the truth, so a caller that honours
/// the budget observes a real [`AskOutcome::TimedOut`] against a real clock rather than a hard-coded
/// verdict. `tokio`'s test clock makes the sleep instantaneous, so this costs no wall time.
struct StallingAsk;

#[async_trait]
impl ForwardedAsk for StallingAsk {
    async fn ask(
        &self,
        _peer: &str,
        _addrs: &[SocketAddr],
        _content: &ContentId,
        _next_depth: u64,
        budget: Duration,
        _ask_id: AskId,
    ) -> AskOutcome {
        tokio::time::sleep(budget + Duration::from_secs(1)).await;
        AskOutcome::TimedOut
    }
}

/// **Proves the capability, end to end:** content that NO node in the chain can find on its own is
/// located by A through B, because B recursed to C. Two real hops, one question, one answer that
/// comes back.
///
/// **Catches:** a consolidation that left the recursion working only one hop deep. Every other test
/// here drives a single node against a fixture, so a middle hop that answered from its own inventory
/// but never forwarded would pass all of them. This is the closest thing this epic has to observed
/// evidence, and it is the reason it is carried rather than dropped.
///
/// **The control is the load-bearing half.** The same topology with B's onward leg REMOVED must find
/// nobody. Without it the test cannot tell "the middle hop recursed" from "the middle hop happened to
/// know the holder", and it would stay green against an implementation that never forwarded past the
/// first hop at all.
#[tokio::test]
async fn a_holder_two_hops_away_is_reached_through_the_middle_node() {
    let cid = content();
    let holder = provider(9, &cid);

    // C answers B. B knows nobody itself; A knows nobody itself.
    let c = RecordingAsk::answering(vec![holder.clone()]);
    let (b, _b_dir) = engine(Vec::new(), &[3], Some(c.clone()));
    let (a, _a_dir) = engine(
        Vec::new(),
        &[2],
        Some(Arc::new(ChainedAsk {
            next_hop: b.clone(),
        })),
    );

    let found = a
        .locate_holder_candidates(
            &cid,
            HopBudget::fresh(),
            &RequestorId::Peer("reader".into()),
        )
        .await;

    assert_eq!(
        peer_ids(&found),
        vec![holder.provider_peer_id.clone()],
        "the holder reached A, and it was reachable ONLY through B"
    );
    assert_eq!(
        c.asked(),
        vec![(mock_peer_hex(3), u64::from(recursion().hop_cap))],
        "B forwarded on, carrying the budget A spent one hop of — so the chain terminates"
    );

    // The control: B with no onward leg cannot answer, so A gets nothing.
    let (b_alone, _b2_dir) = engine(Vec::new(), &[3], None);
    let (a2, _a2_dir) = engine(
        Vec::new(),
        &[2],
        Some(Arc::new(ChainedAsk { next_hop: b_alone })),
    );

    assert!(
        a2.locate_holder_candidates(&cid, HopBudget::fresh(), &RequestorId::Peer("reader".into()))
            .await
            .is_empty(),
        "CONTROL: without B recursing to C the holder is unreachable, so the test above observed the second hop and not the first"
    );
}

// -- What the search ESTABLISHED, not merely what it found (dig-node#273) --------------------------

/// **Proves:** a peer that does not answer inside its budget leaves the answer INCONCLUSIVE, so an
/// empty result is not reported as an absence.
///
/// **Fixture design — the timeout is real and the clock is paused.** `StallingAsk` sleeps past
/// whatever budget it is granted, so the `TimedOut` comes from the production timeout expiring rather
/// than from a double asserting its own verdict. `start_paused` makes that instantaneous. A fixture
/// with no clock — which is what `ChainedAsk` used to be — cannot exhibit this at all, which is
/// exactly why the collapse survived so long while its tests passed.
///
/// **Catches:** the shipped behaviour, in which a timeout became `Vec::new()` and then
/// `MissOutcome::NotFound`. One slow peer became proof that content does not exist.
#[tokio::test(start_paused = true)]
async fn a_peer_that_times_out_leaves_the_absence_unproven() {
    let cid = content();
    let (pc, _dir) = engine(Vec::new(), &[1], Some(Arc::new(StallingAsk)));

    let located = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert!(located.is_empty(), "the stalling peer named nobody");
    assert!(
        !located.establishes_absence(),
        "and because it never answered, this node has NOT established that nobody holds it - \
         reporting a not-found here is the defect dig-node#273 fixes"
    );
}

/// **Proves:** a peer that genuinely answers "nobody" DOES establish an absence.
///
/// **Fixture design — this is the truthful CONTROL for the test above, and it is load-bearing.**
/// Without it, an implementation that marked every search inconclusive would pass every other
/// assertion here while making every miss on the network unanswerable. The two tests differ in
/// exactly one thing: whether the peer answered.
#[tokio::test]
async fn a_peer_that_answers_nobody_does_establish_an_absence() {
    let cid = content();
    let (pc, _dir) = engine(Vec::new(), &[1], Some(RecordingAsk::answering(Vec::new())));

    let located = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert!(located.is_empty());
    assert!(
        located.establishes_absence(),
        "the peer looked and reported nobody, which is a real answer"
    );
}

/// **Proves:** a node with recursion REFUSED still reports a plain absence, not an inconclusive one.
///
/// **Why this is not redundant with the control above:** recursion ships DISABLED, so a refusal is the
/// ordinary case on almost every node. An implementation that treated "did not ask" as "could not
/// tell" would turn every miss on every default-configured node into an error, which is a different
/// lie in the opposite direction and a far more visible regression than the one being fixed.
#[tokio::test]
async fn a_node_that_never_asked_still_answers_a_plain_absence() {
    let cid = content();
    // No forwarded asker installed at all: the DHT leg is the whole search.
    let (pc, _dir) = engine(Vec::new(), &[1], None);

    let located = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert!(located.is_empty());
    assert!(
        located.establishes_absence(),
        "not asking establishes nothing new, so the answer stands on the DHT leg exactly as it did \
         before the recursion existed"
    );
}

/// **Proves:** an inconclusive search reaches the WIRE as its own code, distinct from a not-found.
///
/// **Catches:** a fix that stops at the internal type. The cascade requirement is that a hop's "I
/// could not tell" travels back DOWN the hops - so if the outcome learns the difference and the
/// JSON-RPC envelope discards it, the next hop down is exactly as misled as before.
///
/// **Fixture design - a not-found is asserted in the SAME test, from the same function.** Asserting
/// only that an inconclusive outcome produces an error would pass against an implementation that
/// errored on every miss, which would break every honest not-found on the network. The pair is what
/// pins the distinction rather than the presence of a code.
#[test]
fn an_inconclusive_outcome_answers_with_its_own_wire_code_and_a_not_found_stays_silent() {
    let id = serde_json::json!(7);

    let inconclusive = crate::download::miss_refusal_envelope(&id, &MissOutcome::Inconclusive)
        .expect("an inconclusive miss must be reported, not swallowed");
    assert_eq!(
        inconclusive["error"]["code"],
        serde_json::json!(crate::download::content_miss_inconclusive()),
        "a caller must be able to tell 'unanswered' from 'not found': the first is worth retrying          and the second is not"
    );

    assert!(
        crate::download::miss_refusal_envelope(&id, &MissOutcome::NotFound).is_none(),
        "a genuine not-found is still silent here, so the caller's own not-found stands"
    );
}

// -- The time budget is carried DOWN and decremented (dig-node#273) --------------------------------

/// **Proves:** a hop that may still forward is granted MORE than one leaf timeout - the inequality
/// whose violation made the recursion depth-1 in practice.
///
/// **Fixture design - the numbers are read off the protocol, not restated.** `fan_out` comes from the
/// live `RecursionConfig`, and the bound is checked against `FORWARDED_ASK_LEAF_TIMEOUT` rather than
/// against a literal, so this moves with the crate instead of pinning a private copy. The originator
/// has `hop_cap` hops to spend, so the budget it hands its first peer must cover that peer's own
/// fan-out.
#[tokio::test]
async fn the_budget_handed_to_a_peer_covers_that_peers_own_fan_out() {
    let cid = content();
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    pc.locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    let granted = ask.budgets();
    assert_eq!(granted.len(), 1, "exactly the one pool peer was asked");
    let config = recursion();
    assert!(
        granted[0]
            >= crate::seams::dig_peer::forwarded_ask::FORWARDED_ASK_LEAF_TIMEOUT
                * u32::from(config.fan_out),
        "a peer that may itself ask {} peers sequentially cannot be given one leaf timeout; it was \
         granted {:?}",
        config.fan_out,
        granted[0],
    );
    assert!(
        granted[0] <= MAX_FORWARDED_ASK_BUDGET,
        "and it is still clamped, so no configuration buys unbounded wall clock"
    );
}

/// **Proves:** the budget a hop hands DOWNWARDS is never larger than the budget it was granted.
///
/// **Fixture design:** the inbound budget is set EXPLICITLY and well below what this node would derive
/// for itself, so a node that restated its own derived budget instead of decrementing the granted one
/// would hand down more than it had and fail here. A fixture that let the node derive its own budget
/// could not tell the two apart - it is the gap between granted and derived that makes this visible.
#[tokio::test]
async fn a_hop_never_hands_down_more_time_than_it_was_granted() {
    let cid = content();
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let granted_to_us = Duration::from_secs(2);
    pc.locate_holders(
        &cid,
        HopBudget::fresh().with_time(granted_to_us),
        &RequestorId::Local,
    )
    .await;

    let handed_on = ask.budgets();
    assert_eq!(handed_on.len(), 1);
    assert!(
        handed_on[0] <= granted_to_us,
        "this node was given {granted_to_us:?} and handed its peer {:?} - a child must never be \
         granted more time than its parent has, or the parent times out on work it authorised",
        handed_on[0],
    );
}

/// **Proves:** a budget arriving from a peer is CLAMPED, so one hop cannot hold this node's inbound
/// request open for as long as it likes.
///
/// **Fixture design - pinned from BOTH sides.** An absurd wire value is clamped DOWN to the ceiling,
/// and a modest value passes through UNCHANGED. Testing only the clamp would pass against an
/// implementation that ignored the wire field entirely and always used its own derived budget, which
/// would defeat the decrement this whole mechanism rests on.
#[test]
fn a_wire_budget_is_clamped_at_ingress_but_a_modest_one_passes_through() {
    let absurd = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 600_000,
    }));
    assert_eq!(
        absurd.time_budget(0, 3),
        MAX_FORWARDED_ASK_BUDGET,
        "a ten-minute claim buys the ceiling and no more"
    );

    let modest = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 1_500,
    }));
    assert_eq!(
        modest.time_budget(0, 3),
        Duration::from_millis(1_500),
        "a budget inside the ceiling is honoured exactly, which is what makes the budget CARRIED \
         rather than re-derived at every hop"
    );
}

/// **Proves:** `budget_ms` carries THREE distinct meanings and none of them is collapsed into
/// another - absent means unbudgeted, `0` means exhausted, and any other value is the granted
/// allowance.
///
/// **Fixture design - the three states are asserted against DIFFERENT expected values, so no two can
/// be satisfied by one implementation.** The nearest wrong implementation reads the field with
/// `unwrap_or(0)`, which makes absent and `0` indistinguishable; that version passes any test that
/// only exercises a present, non-zero budget. So the absent case is pinned to the DERIVED budget
/// (which is non-zero) and the `0` case to zero: a collapse in either direction fails one of them.
///
/// `Some(0)` being READABLE and zero is the point - it is a granted allowance that has run out, which
/// `dig_sex` names distinctly from a budget it could not read at all. A hop MUST NOT spend time it was
/// not given.
#[test]
fn budget_ms_keeps_absent_distinct_from_zero_and_from_a_granted_value() {
    let derived = crate::seams::dig_peer::ask_budget(0, 3);
    assert!(
        !derived.is_zero(),
        "the derived budget must be non-zero or the absent and zero cases below could not differ"
    );

    let unbudgeted = HopBudget::from_params(&serde_json::json!({"redirect_depth": 0}));
    assert_eq!(
        unbudgeted.time_budget(0, 3),
        derived,
        "an ABSENT budget is an originating question: this node derives its own allowance"
    );

    let exhausted = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 0,
    }));
    assert_eq!(
        exhausted.time_budget(0, 3),
        Duration::ZERO,
        "a budget of 0 is EXHAUSTED, not absent - a hop granted no time must not derive itself some"
    );

    let granted = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 4_000,
    }));
    assert_eq!(
        granted.time_budget(0, 3),
        Duration::from_millis(4_000),
        "a readable allowance inside the ceiling is honoured exactly"
    );

    assert_ne!(
        unbudgeted.time_budget(0, 3),
        exhausted.time_budget(0, 3),
        "absent and exhausted MUST NOT be the same allowance; collapsing them lets a spent budget          silently buy a fresh one at every hop"
    );
}

/// **Proves:** `budget_ms: 0` is an INSTRUCTION, not merely a small number — a hop granted no time
/// asks nobody, and says so by refusing to claim the absence.
///
/// **Fixture design — ONE actor varies, and the control is truthful.** Both arms are the same node,
/// the same content, the same peer, the same identity-free request; the only difference is the
/// budget on the wire. The granted arm is the control that proves the node WOULD have asked, so the
/// exhausted arm's silence is a decision rather than a node that never forwards at all — which is
/// the shape a fixture without a control cannot tell apart, and the stock posture is "never
/// forwards", so that confusion is the likely one rather than an exotic one.
///
/// **Side effects are asserted BEFORE the outcome.** The ask count comes first: an implementation
/// that asked onward with no time and then reported inconclusive because everything timed out would
/// satisfy the conclusiveness assertion while doing precisely the thing an exhausted budget forbids
/// — spending a downstream peer's bandwidth on time it was never granted.
#[tokio::test]
async fn an_exhausted_budget_asks_nobody_and_does_not_claim_the_absence() {
    let cid = content();

    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));
    let exhausted = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 0,
    }));
    let located = pc
        .locate_holders(&cid, exhausted, &RequestorId::Local)
        .await;

    assert_eq!(
        ask.asked().len(),
        0,
        "a hop granted zero time must not ask onward - relaying on time it was never given is the          amplification the budget exists to bound"
    );
    assert!(
        !located.establishes_absence(),
        "and having asked nobody, it has established nothing: reporting a proven absence here turns          one exhausted hop into an authoritative not-found for every reader below it"
    );

    // CONTROL: the same node, the same everything, a budget that is merely SMALL rather than spent.
    let control_ask = RecordingAsk::answering(Vec::new());
    let (control, _dir2) = engine(Vec::new(), &[1], Some(control_ask.clone()));
    let granted = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "budget_ms": 4_000,
    }));
    control
        .locate_holders(&cid, granted, &RequestorId::Local)
        .await;
    assert_eq!(
        control_ask.asked().len(),
        1,
        "the node DOES forward when granted time, so the exhausted arm above measured a decision          and not a node that simply never asks"
    );
}

// -- The same ask is walked once (dig-node#273) ----------------------------------------------------

/// **Proves:** the same ask arriving twice by different paths is forwarded only once.
///
/// **Fixture design - two arrivals of ONE identity, against a node with a peer it would otherwise
/// ask.** The second call carries the SAME `ask_id`, which is what a diamond in the graph produces.
/// A second, DIFFERENT identity is then asked to prove the node is not simply refusing everything
/// after its first forward - without that third call this test would pass against a node that
/// forwarded exactly once in its lifetime.
#[tokio::test]
async fn the_same_ask_arriving_twice_is_forwarded_once() {
    let cid = content();
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let diamond = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "ask_id": "0102030405060708090a0b0c0d0e0f10",
    }));
    pc.locate_holders(&cid, diamond, &RequestorId::Local).await;
    pc.locate_holders(&cid, diamond, &RequestorId::Local).await;

    assert_eq!(
        ask.asked().len(),
        1,
        "the second arrival of the same question must not re-walk the graph"
    );

    let unrelated = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "ask_id": "aabbccddeeff00112233445566778899",
    }));
    pc.locate_holders(&cid, unrelated, &RequestorId::Local)
        .await;

    assert_eq!(
        ask.asked().len(),
        2,
        "a genuinely different question is still answered - the dedup is per-ask, not a one-shot"
    );
}

/// **Proves:** a request carrying no identity is treated as a NEW question rather than as a duplicate
/// of the last one.
///
/// **Catches:** a dedup keyed on a defaulted-to-zero identity, which would make every older peer's
/// request collide with every other older peer's request - a free way to suppress the entire forwarded
/// leg by simply omitting a field.
#[tokio::test]
async fn requests_without_an_identity_do_not_collide_with_each_other() {
    let cid = content();
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let anonymous = serde_json::json!({"redirect_depth": 0});
    pc.locate_holders(
        &cid,
        HopBudget::from_params(&anonymous),
        &RequestorId::Local,
    )
    .await;
    pc.locate_holders(
        &cid,
        HopBudget::from_params(&anonymous),
        &RequestorId::Local,
    )
    .await;

    assert_eq!(
        ask.asked().len(),
        2,
        "two separate questions from peers on an older build are two questions"
    );
}

// -- The first-hand holder cache (dig-node#275) ----------------------------------------------------

/// **Proves:** a second request inside the TTL reuses the remembered holders instead of re-walking
/// the DHT - requirement 7's stated acceptance test.
///
/// **Fixture design - the DHT LOOKUP is counted directly, which is the thing the requirement is
/// about.** An earlier version of this test counted FORWARDED asks as a proxy for "discovery ran",
/// and that proxy was wrong in a way that mattered: it passed against an implementation that
/// short-circuited the entire search on a cache hit, which silently disabled the recursive
/// enrichment and made two shipped bounds look as though they latched. Counting the locator is the
/// only fixture that distinguishes "skipped rediscovery" from "skipped everything".
#[tokio::test]
async fn a_second_request_inside_the_ttl_skips_rediscovery() {
    let cid = content();
    let locator = CountingLocator::answering(vec![provider(4, &cid)]);
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine_with_locator(locator.clone(), &[1], Some(ask.clone()));

    let first = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(!first.is_empty(), "the first lookup found the holder");
    assert_eq!(locator.lookups(), 1, "by walking the DHT once");

    let second = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert_eq!(
        peer_ids(&second.candidates()),
        peer_ids(&first.candidates()),
        "the same holder comes back"
    );
    assert_eq!(
        locator.lookups(),
        1,
        "and the DHT was NOT walked again - which is the entire point of remembering it"
    );
    assert_eq!(
        ask.asked().len(),
        2,
        "while the forwarded leg still ran, because a cache hit is a discovery shortcut and never \
         a substitute for asking peers"
    );
}

/// **Proves:** an unreachable remembered slate is forgotten, so the next request runs a real walk.
///
/// **Catches:** a cache with no invalidation, which would replay the exact candidates just proven
/// unreachable for the rest of the TTL - the sticky-answer exposure the DHT's own SPEC 6.8 caller
/// exists to close, reintroduced one cache over.
#[tokio::test]
async fn a_slate_that_reached_nobody_is_walked_again() {
    let cid = content();
    let locator = CountingLocator::answering(vec![provider(4, &cid)]);
    let (pc, _dir) = engine_with_locator(locator.clone(), &[], None);

    pc.locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert_eq!(locator.lookups(), 1);

    pc.forget_stale_discovery_for_test(&cid).await;

    pc.locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert_eq!(
        locator.lookups(),
        2,
        "the remembered slate was dropped, so discovery ran again rather than replaying holders \
         that reached nobody"
    );
}

/// **Proves:** HEARSAY is never cached, so a hop cannot plant a holder this node then re-serves as its
/// own knowledge for the whole TTL.
///
/// **Fixture design - the DHT leg answers EMPTY and the forwarded leg answers with a holder.** That
/// is the only arrangement in which the record under test is unambiguously hearsay: with a first-hand
/// record present too, a cache that stored everything would look identical to one that stored only
/// first-hand records. The second lookup then re-runs the forwarded ask, which is the observable proof
/// that nothing was retained.
///
/// **Catches:** the natural implementation - cache the merged answer - which is what would amend SPEC
/// 10.4.4 by accident and hand one lying hop an hour of laundered authority.
#[tokio::test]
async fn hearsay_is_never_remembered() {
    let cid = content();
    let ask = RecordingAsk::answering(vec![provider(9, &cid)]);
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let first = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(!first.is_empty(), "the hop named a holder");

    pc.locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert_eq!(
        ask.asked().len(),
        2,
        "the forwarded leg ran AGAIN, proving the hop's claim was not retained between the two \
         requests (SPEC 10.4.4 - forwarded records MUST NOT be stored)"
    );
}

// -- The gate round: the distinction has to exist on the paths that RUN --------------------------

/// A [`dig_download::ProviderLocator`] whose walk FAILS.
///
/// **Why this double had to be added.** Every locator double in this file answers `Ok`, so the error
/// arm of `find_providers` was structurally invisible to the whole suite: no fixture could exhibit a
/// locate failure, and the code that laundered one into an established absence passed every test.
/// A double that cannot express the failure cannot witness the fix.
#[derive(Clone)]
struct FailingLocator;

#[async_trait]
impl dig_download::ProviderLocator for FailingLocator {
    async fn find_providers(
        &self,
        _content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, dig_download::DownloadError> {
        // A locate FAILURE, not an empty result: `ProviderLocator` states the two are different and
        // this double exists to produce the one dig-node used to discard. `Transport` is the walk's
        // own failure shape - no reachable DHT peer answered - and the sentinel provider says the
        // failure belongs to the walk rather than to any one holder.
        Err(dig_download::DownloadError::Transport {
            provider: "dht".into(),
            reason: "the DHT walk reached nobody".into(),
        })
    }
}

/// An engine over an arbitrary locator, with no forwarded leg — the stock posture (recursion ships
/// disabled), which is exactly the configuration in which `absence_established` was a constant.
fn engine_over<L: dig_download::ProviderLocator + 'static>(
    locator: L,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = NodeContent::new(
        Arc::new(locator),
        Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
        MissMode::Redirect,
        None,
        dir.path(),
    );
    (content, dir)
}

/// [`engine_over`] for a locator chain that is already an `Arc<dyn ProviderLocator>` — the shape
/// [`crate::download::NodeContent::provider_locator_chain`] returns, which the generic form cannot take.
fn engine_over_chain(
    locator: Arc<dyn dig_download::ProviderLocator>,
) -> (Arc<NodeContent>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = NodeContent::new(
        locator,
        Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
        MissMode::Redirect,
        None,
        dir.path(),
    );
    (content, dir)
}

/// A [`ForwardedAsk`] double that answers each peer DIFFERENTLY.
///
/// The stock `RecordingAsk` answers every peer identically, which cannot express a merge: a fixture
/// in which every actor behaves the same way cannot distinguish a parent that merges its children's
/// outcomes from one that simply echoes the last it saw.
struct PerPeerAsk {
    answers: Vec<(String, AskOutcome)>,
    asked: Mutex<Vec<String>>,
}

impl PerPeerAsk {
    fn new(answers: Vec<(String, AskOutcome)>) -> Self {
        Self {
            answers,
            asked: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ForwardedAsk for PerPeerAsk {
    async fn ask(
        &self,
        peer: &str,
        _addrs: &[SocketAddr],
        _content: &ContentId,
        _next_depth: u64,
        _budget: Duration,
        _ask_id: AskId,
    ) -> AskOutcome {
        self.asked
            .lock()
            .expect("recorder lock")
            .push(peer.to_string());
        self.answers
            .iter()
            .find(|(known, _)| known == peer)
            .map(|(_, outcome)| outcome.clone())
            .unwrap_or(AskOutcome::Unreachable)
    }
}

/// **Proves:** a DHT walk that ERRORED does not establish an absence, while a walk that genuinely
/// returned nobody does.
///
/// **Fixture design — ONE actor varies, and there is a truthful control.** Both arms ask about the
/// same content on a node with no forwarded leg; the only difference is whether the locator returns
/// `Err` or `Ok(vec![])`. Asserting only the failing arm would pass against an implementation that
/// reported EVERY miss as inconclusive, which is the opposite lie; the control is what makes the
/// assertion a distinction rather than a constant.
///
/// **On the revert** (restoring `.unwrap_or_default()`), the FIRST assertion fires: the errored walk
/// reads as an established absence.
#[tokio::test]
async fn a_failed_dht_walk_is_not_an_established_absence() {
    let cid = content();

    let (failing, _d1) = engine_over(FailingLocator);
    let errored = failing
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(
        !errored.establishes_absence(),
        "a locate that FAILED establishes nothing; reporting it as a proven absence tells the \
         reader to stop looking for content that may well exist"
    );

    let (honest, _d2) = engine_over(MockProviderLocator::fixed(Vec::new()));
    let looked = honest
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(
        looked.establishes_absence(),
        "a walk that completed and found nobody DID establish the absence - without this control \
         the assertion above is satisfied by reporting every miss as inconclusive"
    );
    assert!(
        errored.is_empty() && looked.is_empty(),
        "neither named a holder"
    );
}

/// **Proves:** a failed DHT walk stays unproven THROUGH THE PRODUCTION LOCATOR CHAIN — the union,
/// the self-exclusion and the capsule fallback that `NodeContent::for_dht` actually installs.
///
/// **Why this test and not the one above.** `a_failed_dht_walk_is_not_an_established_absence` hands
/// its double straight to `NodeContent::new`, so it drives a one-layer locator production never
/// builds. Two layers below it, [`UnionLocator`] skipped a failed source (`let Ok(records) = result
/// else { continue }`) and [`CapsuleFallbackLocator`] called `.unwrap_or_default()` twice — so a
/// failed walk reached `walk_for_providers` as `Ok(vec![])`, `first_hand_conclusive` was `true`, and
/// the round-1 fix at the `Err` arm was unreachable code in production. On a stock node, where
/// recursion ships OFF, that broken conjunct is the WHOLE search: a start-up, a partition or an
/// eclipsed routing table answered `absence_established: true` for content that exists, and a hop
/// relays that answer onward. No forged message required.
///
/// **Fixture design — the chain is the subject, so the chain is what is built.** Both arms go
/// through [`crate::download::NodeContent::provider_locator_chain`]; the ONLY difference is whether its DHT leg
/// errors or honestly returns nobody. The control is load-bearing twice over: it proves the chain
/// still reports a genuine negative (collapsing every empty result to inconclusive would trade this
/// bug for a never-conclusive one), and it proves the failing arm's verdict comes from the FAILURE
/// rather than from the emptiness.
///
/// **On the revert** (restoring either swallow), the first assertion fires while the control stays
/// green — which is what makes the failure attributable to the layer that swallowed.
#[tokio::test]
async fn a_failed_dht_walk_stays_unproven_through_the_production_locator_chain() {
    let cid = content();

    let chain =
        crate::download::NodeContent::provider_locator_chain(Arc::new(FailingLocator), None);
    let (failing, _d1) = engine_over_chain(chain);
    let errored = failing
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(
        !errored.establishes_absence(),
        "the union and the capsule fallback swallowed the walk failure into Ok(vec![]), so the          node claimed a proven absence for content it never managed to look for"
    );

    let honest = crate::download::NodeContent::provider_locator_chain(
        Arc::new(MockProviderLocator::fixed(Vec::new())),
        None,
    );
    let (looked, _d2) = engine_over_chain(honest);
    let negative = looked
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(
        negative.establishes_absence(),
        "a chain whose every source completed and found nobody STILL establishes the absence -          without this the fix above is satisfied by never concluding anything"
    );
    assert!(
        errored.is_empty() && negative.is_empty(),
        "neither named a holder"
    );
}

/// **Proves:** a REFUSAL to forward is distinguishable from a genuine not-found, while recursion
/// being switched off is not.
///
/// **Fixture design — the two refusals differ in ONE property and nothing else.** Both arms have a
/// dialable peer; the spent-budget arm carries a hop budget with nothing left, the control arm
/// carries a fresh one against a node whose recursion is not installed at all. Testing only the spent
/// arm would pass against a node that marked everything inconclusive.
///
/// **On the revert** (making every unasked path conclusive again), the FIRST assertion fires.
#[tokio::test]
async fn a_refusal_to_forward_leaves_the_absence_unproven() {
    let cid = content();

    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));
    let refused = pc
        .locate_holders(&cid, HopBudget::spent(), &RequestorId::Local)
        .await;
    assert!(
        !refused.establishes_absence(),
        "the hop budget ran out with peers unasked - dig-node#273 requires a refusal to be \
         distinguishable from a not-found"
    );
    assert!(
        ask.asked().is_empty(),
        "and it refused by NOT asking, which is what makes the absence unproven"
    );

    let (disabled, _d2) = engine(Vec::new(), &[1], None);
    let off = disabled
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;
    assert!(
        off.establishes_absence(),
        "recursion switched OFF is not a refusal: asking was never part of this node's answer, so \
         the DHT leg stands alone exactly as it did before the recursion existed"
    );
}

/// **Proves:** one hop reporting an unproven absence stops its PARENT reporting a proven one, even
/// when a sibling hop answered honestly and found nobody.
///
/// **Fixture design — two peers, and only ONE of them is unhelpful.** An all-peers-hostile fixture
/// would be the blindest possible arrangement here: with no honest answer in the set, a parent that
/// simply forwards the last outcome it saw looks identical to one that merges correctly. Varying one
/// actor and keeping a truthful sibling is what makes this test see the MERGE rule rather than a
/// coincidence.
///
/// **On the revert** (classifying any `result` frame as a conclusive answer), the assertion on
/// `establishes_absence` fires; the sibling assertion on the named holder stays green, which is how
/// the failure is attributable.
#[tokio::test]
async fn one_inconclusive_child_defeats_a_sibling_that_found_nobody() {
    let cid = content();
    let ask = Arc::new(PerPeerAsk::new(vec![
        (mock_peer_hex(1), AskOutcome::Answered(Vec::new())),
        (
            mock_peer_hex(2),
            AskOutcome::AnsweredInconclusive(vec![provider(9, &cid)]),
        ),
    ]));
    let (pc, _dir) = engine(Vec::new(), &[1, 2], Some(ask.clone()));

    let located = pc
        .locate_holders(&cid, HopBudget::fresh(), &RequestorId::Local)
        .await;

    assert!(
        !located.establishes_absence(),
        "a parent holding one Inconclusive child and one NotFound child MUST NOT report NotFound \
         upward - a single stalled node two hops away would otherwise manufacture an absence"
    );
    assert_eq!(
        peer_ids(&located.candidates()),
        vec![mock_peer_hex(9)],
        "and the records the inconclusive child DID name are still carried, because a partial \
         answer is more useful than none"
    );
}

/// **Proves:** the seen-set is claimed per QUESTION-AND-CONTENT, so a multi-item request forwards for
/// every item rather than only the first.
///
/// **Fixture design — no attacker, and this is the documented normal path.** `availability_batch`
/// hands ONE `HopBudget` (it is `Copy`) to every item in the batch, so the second item onwards used
/// to lose the claim and take the not-asked path — emitting an established absence having asked
/// nobody. Two distinct contents under one identity is the smallest fixture that exhibits it; a
/// second call with the SAME content must still be deduplicated, which
/// `the_same_ask_arriving_twice_is_forwarded_once` pins from the other side.
///
/// **On the revert** (keying the seen-set on the ask id alone), the first assertion fires: only one
/// of the two items is ever forwarded for.
#[tokio::test]
async fn one_identity_over_two_items_forwards_for_both() {
    let first = content();
    let second = ContentId::resource([0xD0; 32], [0xD1; 32], [0xD2; 32]);
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let batch = HopBudget::from_params(&serde_json::json!({
        "redirect_depth": 0,
        "ask_id": "1111111111111111ffffffffffffffff",
    }));

    let one = pc.locate_holders(&first, batch, &RequestorId::Local).await;
    let two = pc.locate_holders(&second, batch, &RequestorId::Local).await;

    assert_eq!(ask.asked().len(), 2, "both items were forwarded for");
    assert!(
        one.establishes_absence() && two.establishes_absence(),
        "and both absences rest on a peer that actually answered, not on a lost claim"
    );
}

/// **Proves:** the ask identity this node forwards under is the one it RECEIVED, on the wire, in the
/// emitted request body.
///
/// **Fixture design — the assertion is on the EMITTED frame, not on a literal this test wrote.** The
/// existing identity tests hand a hex string straight into `HopBudget::from_params` and then observe
/// the seen-set, which structurally cannot notice that nothing ever put `ask_id` on the wire. Here
/// the double captures the identity the production code chose to forward under, that identity is
/// rendered through the real request builder, and the rendered frame is parsed BACK through
/// `from_params`. Wire out, wire in: an emitter that omits the field cannot survive the round trip.
///
/// **On the revert** (dropping `ask_id` from `forwarded_request`), the final assertion fires — the
/// re-parsed identity is a freshly minted one and does not match.
#[tokio::test]
async fn the_identity_a_hop_received_is_the_identity_it_emits() {
    let cid = content();
    let ask = RecordingAsk::answering(Vec::new());
    let (pc, _dir) = engine(Vec::new(), &[1], Some(ask.clone()));

    let inbound = serde_json::json!({
        "redirect_depth": 0,
        "ask_id": "0f0e0d0c0b0a09080706050403020100",
    });
    let budget = HopBudget::from_params(&inbound);
    pc.locate_holders(&cid, budget, &RequestorId::Local).await;

    let forwarded_under = ask
        .ask_ids()
        .first()
        .copied()
        .expect("the peer was asked, so an identity was chosen");
    assert_eq!(
        forwarded_under,
        budget.ask_id(),
        "the hop forwards under the identity it was given, not a fresh one"
    );

    let emitted =
        crate::seams::dig_peer::forwarded_request(&cid, 1, Duration::from_secs(5), forwarded_under);
    let reparsed = HopBudget::from_params(emitted.get("params").expect("params"));
    assert_eq!(
        reparsed.ask_id(),
        budget.ask_id(),
        "and the identity SURVIVES the wire: a request body that omits ask_id makes the next hop \
         mint a fresh one, and the diamond dedup this whole mechanism rests on never fires"
    );
}
