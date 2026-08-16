//! Tests for the corroborated arbitrary chain reads (dig_ecosystem#3032).
//!
//! # How the fixtures are built, and why
//!
//! Each test names ONE property and is built around the input that separates it from the NEAREST
//! WRONG implementation, because the failure mode here is not a wrong assertion — it is a true
//! assertion on a fixture that cannot exhibit the property:
//!
//! * A round where EVERY peer lies cannot see a missed vote — there is no honest answer left to
//!   prefer. So the dissent tests vary ONE peer and keep an honest majority as the control.
//! * "The answer came back empty" is satisfied identically by a guard at the wrong layer. So the
//!   cache tests draw ZERO peers: a read that reached the peers at all cannot produce an answer,
//!   which makes "where the value came from" observable rather than inferred.
//! * A TTL tested only from below confirms itself. [`UNSPENT_CACHE_TTL_SECS`] is pinned from both
//!   sides — one second under must serve, exactly at the bound must not.
//! * Wall-clock time is never consulted: every cache test pins an explicit `NOW`.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A fixed instant every cache test is written against, so no test depends on when it runs.
const NOW: i64 = 1_700_000_000;

/// A coin id spelled as the reads take it: 64 lowercase hex characters.
const COIN_ID: &str = "aa00000000000000000000000000000000000000000000000000000000000001";

/// A clock pinned to one instant.
struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.0
    }
}

/// A coin record. `amount` is the field the dissent fixtures vary, because it is part of the coin
/// id's preimage — so two coins differing in it are genuinely different claims about one id, which
/// is exactly the contradiction a quorum exists to catch.
fn coin(amount: u64, spent_height: Option<u32>) -> FallbackCoin {
    FallbackCoin {
        coin_id: COIN_ID.to_string(),
        parent_coin_info: "bb".repeat(32),
        puzzle_hash: "cc".repeat(32),
        amount,
        created_height: Some(9_000_000),
        spent_height,
        created_timestamp: Some(1_600_000_000),
        spent_timestamp: spent_height.map(|_| 1_650_000_000),
    }
}

/// A spend. `solution` is what the dissent fixture varies: it is the half of a spend that says
/// what the coin BECAME, so two peers differing in it disagree about the next lineage generation.
fn spend(solution: &str) -> FallbackCoinSpend {
    FallbackCoinSpend {
        coin_id: COIN_ID.to_string(),
        parent_coin_info: "bb".repeat(32),
        puzzle_hash: "cc".repeat(32),
        amount: 1,
        puzzle_reveal: "ff01".to_string(),
        solution: solution.to_string(),
    }
}

/// What one peer will say, including refusing to say anything.
#[derive(Clone)]
enum Voice {
    Record(Option<FallbackCoin>),
    Spend(Option<FallbackCoinSpend>),
    /// The peer fails to answer at all — absent from the tally, never a vote.
    Silent,
}

/// A peer that says one thing, and counts how often it was asked.
struct ScriptedPeer {
    id: String,
    voice: Voice,
    asked: Arc<AtomicUsize>,
}

#[async_trait]
impl CoinPeer for ScriptedPeer {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<FallbackCoin>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match &self.voice {
            Voice::Record(r) => Ok(r.clone()),
            Voice::Spend(_) => Ok(None),
            Voice::Silent => Err(Error::internal("peer did not answer")),
        }
    }

    async fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<FallbackCoinSpend>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match &self.voice {
            Voice::Spend(s) => Ok(s.clone()),
            Voice::Record(_) => Ok(None),
            Voice::Silent => Err(Error::internal("peer did not answer")),
        }
    }
}

/// A draw of scripted peers, each with a DISTINCT id — one voice each, never one voice repeated.
struct ScriptedSample {
    voices: Vec<Voice>,
    asked: Arc<AtomicUsize>,
}

impl ScriptedSample {
    fn new(voices: Vec<Voice>) -> Self {
        Self {
            voices,
            asked: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl PeerSample for ScriptedSample {
    async fn draw(&self) -> Vec<Arc<dyn CoinPeer>> {
        self.voices
            .iter()
            .enumerate()
            .map(|(i, voice)| {
                Arc::new(ScriptedPeer {
                    id: format!("10.0.0.{i}:8444"),
                    voice: voice.clone(),
                    asked: self.asked.clone(),
                }) as Arc<dyn CoinPeer>
            })
            .collect()
    }
}

/// A reads surface over a fresh in-memory wallet DB, the given voices, and the pinned clock.
async fn reads_over(voices: Vec<Voice>) -> (PeerCorroboratedReads, WalletDb, Arc<AtomicUsize>) {
    let db = WalletDb::open_in_memory().await.unwrap();
    let sample = Arc::new(ScriptedSample::new(voices));
    let asked = sample.asked.clone();
    let reads =
        PeerCorroboratedReads::new(sample, db.clone()).with_clock(Arc::new(FixedClock(NOW)));
    (reads, db, asked)
}

/// `n` peers all reporting the same coin.
fn agreeing_records(n: usize, amount: u64, spent: Option<u32>) -> Vec<Voice> {
    (0..n)
        .map(|_| Voice::Record(Some(coin(amount, spent))))
        .collect()
}

// ---------------------------------------------------------------------------
// NC-12: never one source
// ---------------------------------------------------------------------------

/// ONE peer, however confident, decides nothing.
///
/// The control below is the same fixture with a second AGREEING peer, differing in exactly the
/// dimension under test — the number of independent voices — so this pair cannot be satisfied by
/// an implementation that simply refuses everything.
#[tokio::test]
async fn a_single_peer_never_decides_a_coin_record() {
    let (reads, _db, _) = reads_over(agreeing_records(1, 42, None)).await;
    let err = reads.coin_record_by_id(COIN_ID).await.unwrap_err();
    assert!(
        err.message.contains("could not be corroborated"),
        "a lone peer must produce UNKNOWN, got: {}",
        err.message
    );
}

/// The control for the test above: two agreeing peers reach [`quorum::CORROBORATION_FLOOR`].
#[tokio::test]
async fn two_agreeing_peers_are_authoritative() {
    let (reads, _db, _) = reads_over(agreeing_records(2, 42, None)).await;
    let answer = reads.coin_record_by_id(COIN_ID).await.unwrap();
    assert_eq!(answer, Some(coin(42, None)));
}

/// A peer that will not answer lowers the round's confidence; it does not discard a round the
/// peers that DID answer can settle.
///
/// Three honest voices and one silent one: the silent peer is ABSENT from the tally rather than a
/// vote against, so the round still resolves.
#[tokio::test]
async fn a_silent_peer_does_not_discard_the_round() {
    let mut voices = agreeing_records(3, 7, None);
    voices.push(Voice::Silent);
    let (reads, _db, _) = reads_over(voices).await;
    assert_eq!(
        reads.coin_record_by_id(COIN_ID).await.unwrap(),
        Some(coin(7, None))
    );
}

// ---------------------------------------------------------------------------
// Dissent: outvoted, never believed; a real split is UNKNOWN
// ---------------------------------------------------------------------------

/// ONE lying peer among three honest ones is outvoted, and the honest answer is returned.
///
/// The fixture varies exactly one actor and keeps a truthful control majority, because an
/// all-hostile round is the fixture that CANNOT see a missed vote: with no honest answer present,
/// returning the liar's coin and returning nothing are indistinguishable.
#[tokio::test]
async fn one_dissenting_peer_is_outvoted_not_believed() {
    // The dissenter is drawn FIRST, deliberately. With it last, an implementation that simply
    // believed whichever peer answered first would still return the honest coin and this test
    // would pass while proving nothing about the tally.
    let mut voices = vec![Voice::Record(Some(coin(999_999, None)))];
    voices.extend(agreeing_records(3, 100, None));
    let (reads, _db, _) = reads_over(voices).await;

    let answer = reads.coin_record_by_id(COIN_ID).await.unwrap();
    assert_eq!(
        answer,
        Some(coin(100, None)),
        "the honest majority's coin must win over the dissenter's"
    );
}

/// A genuine split is UNKNOWN — an `Err` — and specifically NOT `Ok(None)`.
///
/// This is the fail-closed direction that matters: a lineage walk reads absence as *this coin is
/// the tip*, so a round that collapsed a disagreement into "no such coin" would silently end the
/// walk one generation early. Two-versus-two clears
/// [`quorum::CORROBORATION_FLOOR`] and misses [`quorum::required_agreement`], so the round is
/// refused for DISAGREEMENT rather than for reachability — and the message says so.
#[tokio::test]
async fn a_split_round_is_unknown_and_never_absence() {
    let mut voices = agreeing_records(2, 1, None);
    voices.extend(agreeing_records(2, 2, None));
    let (reads, _db, _) = reads_over(voices).await;

    let result = reads.coin_record_by_id(COIN_ID).await;
    assert!(result.is_err(), "a split must not resolve to an answer");
    let message = result.unwrap_err().message;
    assert!(
        message.contains("disagreed"),
        "a split must be reported as disagreement, not as reachability: {message}"
    );
    assert!(
        message.contains("not the same as no such coin"),
        "the refusal must state that UNKNOWN is not absence: {message}"
    );
}

/// Too few answers is reported as REACHABILITY, not as disagreement — a node that reached one peer
/// is alone, not under attack, and the two demand different remedies.
#[tokio::test]
async fn too_few_answers_is_reported_as_reachability() {
    let (reads, _db, _) = reads_over(vec![Voice::Silent, Voice::Silent, Voice::Silent]).await;
    let message = reads.coin_record_by_id(COIN_ID).await.unwrap_err().message;
    assert!(
        message.contains("answered at all"),
        "an unanswered round must be reported as reachability: {message}"
    );
}

/// A corroborated ABSENCE is an answer: `Ok(None)`, distinct from the `Err` above.
#[tokio::test]
async fn a_corroborated_absence_is_ok_none() {
    let (reads, _db, _) = reads_over(vec![Voice::Record(None), Voice::Record(None)]).await;
    assert_eq!(reads.coin_record_by_id(COIN_ID).await.unwrap(), None);
}

// ---------------------------------------------------------------------------
// The cache, and the spent/unspent asymmetry
// ---------------------------------------------------------------------------

/// A corroborated read is WRITTEN to the cache, and the cache is what serves the next read.
///
/// The second read draws ZERO peers. That is the point of the fixture: an implementation that
/// reached the peer round at all could not produce an answer, so a `Some` here can only have come
/// from the cache — the placement is observable rather than inferred from an equal value.
#[tokio::test]
async fn a_corroborated_record_is_cached_and_served_without_peers() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let clock: Arc<dyn Clock> = Arc::new(FixedClock(NOW));

    let live = PeerCorroboratedReads::new(
        Arc::new(ScriptedSample::new(agreeing_records(
            2,
            55,
            Some(9_000_100),
        ))),
        db.clone(),
    )
    .with_clock(clock.clone());
    assert_eq!(
        live.coin_record_by_id(COIN_ID).await.unwrap(),
        Some(coin(55, Some(9_000_100)))
    );

    let peerless =
        PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db).with_clock(clock);
    assert_eq!(
        peerless.coin_record_by_id(COIN_ID).await.unwrap(),
        Some(coin(55, Some(9_000_100))),
        "a cached spent record must be served with no peers at all"
    );
}

/// A SPENT record stays usable however long ago it was cached: the coin is gone and its record
/// cannot change again.
///
/// A decade later, against a peerless draw — so nothing but the cache can answer.
#[tokio::test]
async fn a_spent_record_is_cached_forever() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let live = PeerCorroboratedReads::new(
        Arc::new(ScriptedSample::new(agreeing_records(2, 3, Some(9_000_200)))),
        db.clone(),
    )
    .with_clock(Arc::new(FixedClock(NOW)));
    live.coin_record_by_id(COIN_ID).await.unwrap();

    let a_decade_later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + 10 * 365 * 24 * 3600)));
    assert_eq!(
        a_decade_later.coin_record_by_id(COIN_ID).await.unwrap(),
        Some(coin(3, Some(9_000_200)))
    );
}

/// An UNSPENT record EXPIRES, and the expiry is load-bearing: past the bound, a peerless draw can
/// no longer answer.
///
/// Without this, "the cache works" would be satisfied by a cache that never expires anything —
/// which is precisely the implementation that makes a profile look permanently stale.
#[tokio::test]
async fn an_unspent_record_expires_and_is_re_asked() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let live = PeerCorroboratedReads::new(
        Arc::new(ScriptedSample::new(agreeing_records(2, 3, None))),
        db.clone(),
    )
    .with_clock(Arc::new(FixedClock(NOW)));
    live.coin_record_by_id(COIN_ID).await.unwrap();

    let later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + UNSPENT_CACHE_TTL_SECS)));
    assert!(
        later.coin_record_by_id(COIN_ID).await.is_err(),
        "an expired unspent entry must be re-asked, not served"
    );
}

/// The unspent TTL, pinned from BOTH sides: one second under the bound serves from the cache, and
/// exactly at the bound it does not.
///
/// A bound tested only from below can only confirm itself.
#[test]
fn the_unspent_ttl_is_pinned_from_both_sides() {
    assert!(
        cache_entry_is_usable(None, NOW, NOW + UNSPENT_CACHE_TTL_SECS - 1),
        "one second under the bound must still be usable"
    );
    assert!(
        !cache_entry_is_usable(None, NOW, NOW + UNSPENT_CACHE_TTL_SECS),
        "exactly at the bound must not be usable"
    );
    assert!(
        cache_entry_is_usable(Some(9_000_000), NOW, NOW + UNSPENT_CACHE_TTL_SECS * 1_000),
        "a spent entry ignores the bound entirely"
    );
}

/// A clock that moved BACKWARDS makes an UNSPENT entry unusable rather than arbitrarily fresh.
///
/// The control beside it is the spent entry, which a backwards clock does not touch: its
/// usability never depended on time in the first place, so this pair separates "fails closed on a
/// bad clock" from "refuses everything".
#[test]
fn a_backwards_clock_does_not_extend_freshness() {
    assert!(
        !cache_entry_is_usable(None, NOW, NOW - 1),
        "a negative age must send the read back to the peers"
    );
    assert!(
        cache_entry_is_usable(Some(9_000_000), NOW, NOW - 1),
        "a spent entry never depended on the clock"
    );
}

/// An ABSENCE is NEVER cached.
///
/// The nearest wrong implementation caches every corroborated answer including `None`; under it,
/// the peerless second read would answer `Ok(None)` — a coin declared permanently non-existent
/// because it had not landed yet.
#[tokio::test]
async fn a_corroborated_absence_is_not_cached() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let live = PeerCorroboratedReads::new(
        Arc::new(ScriptedSample::new(vec![
            Voice::Record(None),
            Voice::Record(None),
        ])),
        db.clone(),
    )
    .with_clock(Arc::new(FixedClock(NOW)));
    assert_eq!(live.coin_record_by_id(COIN_ID).await.unwrap(), None);

    let peerless = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW)));
    assert!(
        peerless.coin_record_by_id(COIN_ID).await.is_err(),
        "an absence must not be cached: the second read must ask again, not answer None"
    );
}

/// A usable cache HIT asks no peer at all — the round trip is genuinely saved, which is what makes
/// a lineage walk affordable rather than merely repeatable.
#[tokio::test]
async fn a_cache_hit_asks_no_peer() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let sample = Arc::new(ScriptedSample::new(agreeing_records(2, 3, Some(9_000_300))));
    let asked = sample.asked.clone();
    let reads = PeerCorroboratedReads::new(sample, db).with_clock(Arc::new(FixedClock(NOW)));

    reads.coin_record_by_id(COIN_ID).await.unwrap();
    let after_first = asked.load(Ordering::SeqCst);
    assert_eq!(after_first, 2, "the first read must ask both peers");

    reads.coin_record_by_id(COIN_ID).await.unwrap();
    assert_eq!(
        asked.load(Ordering::SeqCst),
        after_first,
        "a cached read must not reach the peers"
    );
}

// ---------------------------------------------------------------------------
// Spends
// ---------------------------------------------------------------------------

/// A dissenting peer cannot decide what a coin BECAME.
///
/// The dimension varied is the solution, which is the half of a spend that names the next lineage
/// generation: believing the dissenter would hand a walk a forged branch.
#[tokio::test]
async fn a_dissenting_peer_cannot_decide_what_a_coin_became() {
    // The dissenter first, for the same reason as the record case: a fixture whose first voice is
    // honest cannot tell a tally from "believe whoever answered first".
    let mut voices: Vec<Voice> = vec![Voice::Spend(Some(spend("ff")))];
    voices.extend((0..3).map(|_| Voice::Spend(Some(spend("80")))));
    let (reads, _db, _) = reads_over(voices).await;

    assert_eq!(
        reads.coin_spend(COIN_ID).await.unwrap(),
        Some(spend("80")),
        "the majority's spend must win"
    );
}

/// A spend that could not be corroborated is UNKNOWN, never "unspent".
///
/// This is the single most expensive collapse available to this module: a walk reads `Ok(None)` as
/// *this coin is the tip* and stops, so an uncorroborated round served as absence produces a spend
/// built against a singleton that has already moved on.
#[tokio::test]
async fn an_uncorroborated_spend_is_unknown_never_unspent() {
    let (reads, _db, _) = reads_over(vec![Voice::Spend(Some(spend("80")))]).await;
    let result = reads.coin_spend(COIN_ID).await;
    assert!(
        result.is_err(),
        "one peer's spend claim must not become an answer"
    );
    assert!(result.unwrap_err().message.contains("coin spend"));
}

/// A cached spend is served forever with no peers, because a spend cannot un-happen.
#[tokio::test]
async fn a_cached_spend_is_permanent() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let live = PeerCorroboratedReads::new(
        Arc::new(ScriptedSample::new(vec![
            Voice::Spend(Some(spend("80"))),
            Voice::Spend(Some(spend("80"))),
        ])),
        db.clone(),
    )
    .with_clock(Arc::new(FixedClock(NOW)));
    live.coin_spend(COIN_ID).await.unwrap();

    let a_decade_later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + 10 * 365 * 24 * 3600)));
    assert_eq!(
        a_decade_later.coin_spend(COIN_ID).await.unwrap(),
        Some(spend("80"))
    );
}

/// A malformed coin id is refused before any peer is dialled — a `400`, not a quorum failure.
#[tokio::test]
async fn a_malformed_coin_id_is_refused_without_asking_anyone() {
    let (reads, _db, asked) = reads_over(agreeing_records(4, 1, None)).await;
    assert!(reads.coin_record_by_id("not-hex").await.is_err());
    assert!(reads.coin_record_by_id("aabb").await.is_err());
    assert_eq!(asked.load(Ordering::SeqCst), 0);
}

/// The `0x` prefix and upper case are the same coin id, so a cache written under one spelling is
/// found under the other. Otherwise the cache silently misses and every walk re-queries.
#[tokio::test]
async fn the_cache_key_is_spelling_insensitive() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let sample = Arc::new(ScriptedSample::new(agreeing_records(2, 3, Some(9_000_400))));
    let asked = sample.asked.clone();
    let reads = PeerCorroboratedReads::new(sample, db).with_clock(Arc::new(FixedClock(NOW)));

    reads.coin_record_by_id(COIN_ID).await.unwrap();
    let after_first = asked.load(Ordering::SeqCst);

    let shouted = format!("0x{}", COIN_ID.to_ascii_uppercase());
    assert_eq!(
        reads.coin_record_by_id(&shouted).await.unwrap(),
        Some(coin(3, Some(9_000_400)))
    );
    assert_eq!(asked.load(Ordering::SeqCst), after_first);
}
