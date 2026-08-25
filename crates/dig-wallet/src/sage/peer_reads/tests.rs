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

/// The parent every fixture coin is created by.
const FIXTURE_PARENT: &str = "bb";

/// The puzzle hash every fixture coin record carries.
const FIXTURE_PUZZLE_HASH: &str = "cc";

/// The coin id the fixture record with `amount` genuinely has.
///
/// DERIVED, never pasted, because a coin id IS `SHA256(parent | puzzle_hash | amount)` and the
/// cached read path now checks exactly that (dig_ecosystem#3035). A hand-picked constant would
/// make every cache fixture a row that could not exist on chain, and a fixture that cannot survive
/// the real check is a fixture that hides the check going missing.
fn coin_id_for(amount: u64) -> String {
    hex::encode(
        chia::protocol::Coin {
            parent_coin_info: hex32(&FIXTURE_PARENT.repeat(32)),
            puzzle_hash: hex32(&FIXTURE_PUZZLE_HASH.repeat(32)),
            amount,
        }
        .coin_id(),
    )
}

/// The coin id the fixture SPEND is a spend of. Its puzzle hash is the reveal's tree hash, not the
/// records' `cc..`, so it is a different coin.
fn spend_coin_id() -> String {
    hex::encode(
        chia::protocol::Coin {
            parent_coin_info: hex32(&FIXTURE_PARENT.repeat(32)),
            puzzle_hash: hex32(&reveal_tree_hash(REVEAL)),
            amount: 1,
        }
        .coin_id(),
    )
}

/// 64 hex characters as the 32 bytes a coin is made of.
fn hex32(hex_str: &str) -> Bytes32 {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .expect("a fixture hash is hex")
        .try_into()
        .expect("a fixture hash is 32 bytes");
    Bytes32::from(bytes)
}

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
        coin_id: coin_id_for(amount),
        parent_coin_info: FIXTURE_PARENT.repeat(32),
        puzzle_hash: FIXTURE_PUZZLE_HASH.repeat(32),
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
        coin_id: spend_coin_id(),
        parent_coin_info: FIXTURE_PARENT.repeat(32),
        puzzle_hash: reveal_tree_hash(REVEAL),
        amount: 1,
        puzzle_reveal: REVEAL.to_string(),
        solution: solution.to_string(),
    }
}

/// A real, minimal CLVM program: the nil atom.
///
/// It has to be a program that actually parses, because the reveal check tree-hashes it. The
/// previous fixture used `ff01` — a truncated cons — with an unrelated `cc..` puzzle hash, and only
/// passed because the cached read path skipped the verification the live path applies. A fixture
/// that cannot survive the real check is a fixture that hides the check going missing.
const REVEAL: &str = "80";

/// The puzzle hash `REVEAL` actually tree-hashes to, computed rather than pasted.
///
/// Derived so the fixture is self-consistent by construction: a hard-coded pair drifts the moment
/// either half is edited, and the drift shows up as an unrelated-looking parse failure.
fn reveal_tree_hash(reveal: &str) -> String {
    let bytes = hex::decode(reveal).expect("the fixture reveal is hex");
    let hash = chia::clvm_utils::tree_hash_from_bytes(&bytes).expect("the fixture reveal is CLVM");
    hex::encode(hash.to_bytes())
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
    /// What this peer claims the chain tip is, or `None` for a peer that announces none.
    ///
    /// Separate from [`Voice`] because a peer answers coin questions and peak questions
    /// independently, and a double that can vary only one of them cannot express a peer that is
    /// honest about coins while lying about the tip.
    peak: Option<super::super::quorum::PeakClaim>,
    asked: Arc<AtomicUsize>,
}

#[async_trait]
impl CoinPeer for ScriptedPeer {
    fn id(&self) -> String {
        self.id.clone()
    }

    async fn peak_claim(&self) -> Option<super::super::quorum::PeakClaim> {
        self.peak
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
    /// One claimed tip per voice, positionally. Empty means every peer announces none.
    peaks: Vec<Option<super::super::quorum::PeakClaim>>,
    asked: Arc<AtomicUsize>,
}

impl ScriptedSample {
    fn new(voices: Vec<Voice>) -> Self {
        Self {
            voices,
            peaks: Vec::new(),
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
                    peak: self.peaks.get(i).copied().flatten(),
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
    let err = reads.coin_record_by_id(&coin_id_for(42)).await.unwrap_err();
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
    let answer = reads.coin_record_by_id(&coin_id_for(42)).await.unwrap();
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
        reads.coin_record_by_id(&coin_id_for(7)).await.unwrap(),
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

    let answer = reads.coin_record_by_id(&coin_id_for(100)).await.unwrap();
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

    let result = reads.coin_record_by_id(&coin_id_for(1)).await;
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
    let message = reads
        .coin_record_by_id(&coin_id_for(1))
        .await
        .unwrap_err()
        .message;
    assert!(
        message.contains("answered at all"),
        "an unanswered round must be reported as reachability: {message}"
    );
}

/// A corroborated ABSENCE is an answer: `Ok(None)`, distinct from the `Err` above.
#[tokio::test]
async fn a_corroborated_absence_is_ok_none() {
    let (reads, _db, _) = reads_over(vec![Voice::Record(None), Voice::Record(None)]).await;
    assert_eq!(
        reads.coin_record_by_id(&coin_id_for(1)).await.unwrap(),
        None
    );
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
        live.coin_record_by_id(&coin_id_for(55)).await.unwrap(),
        Some(coin(55, Some(9_000_100)))
    );

    let peerless =
        PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db).with_clock(clock);
    assert_eq!(
        peerless.coin_record_by_id(&coin_id_for(55)).await.unwrap(),
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
    live.coin_record_by_id(&coin_id_for(3)).await.unwrap();

    let a_decade_later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + 10 * 365 * 24 * 3600)));
    assert_eq!(
        a_decade_later
            .coin_record_by_id(&coin_id_for(3))
            .await
            .unwrap(),
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
    live.coin_record_by_id(&coin_id_for(3)).await.unwrap();

    let later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + UNSPENT_CACHE_TTL_SECS)));
    assert!(
        later.coin_record_by_id(&coin_id_for(3)).await.is_err(),
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
    assert_eq!(live.coin_record_by_id(&coin_id_for(1)).await.unwrap(), None);

    let peerless = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW)));
    assert!(
        peerless.coin_record_by_id(&coin_id_for(1)).await.is_err(),
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

    reads.coin_record_by_id(&coin_id_for(3)).await.unwrap();
    let after_first = asked.load(Ordering::SeqCst);
    assert_eq!(after_first, 2, "the first read must ask both peers");

    reads.coin_record_by_id(&coin_id_for(3)).await.unwrap();
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
        reads.coin_spend(&spend_coin_id()).await.unwrap(),
        Some(spend("80")),
        "the majority's spend must win"
    );
}

/// **A unanimous quorum cannot answer a question nobody asked.**
///
/// The attack the vote structurally cannot see: every peer in the sample agrees, so `tally` returns
/// `Unanimous` — but they agree about a DIFFERENT coin than the one requested. Two colluding peers
/// are already a full quorum (`required_agreement(2) == 2`), so this needs no majority of the
/// network.
///
/// Recomputing the id from the coin the peer sent does not catch it, which is why the check has to
/// compare against the REQUESTED id: a coin's id is the hash of its own fields, so deriving it from
/// the answer binds the coin to itself, and every coin satisfies that.
///
/// The harm is not only the wrong answer. The walk continues down a substituted lineage — rendering
/// someone else's profile as the user's — and the round writes a cache row that outlives it.
#[tokio::test]
async fn a_unanimous_sample_cannot_substitute_a_different_coin() {
    let other = FallbackCoin {
        coin_id: "ee".repeat(32),
        ..coin(1, Some(100))
    };
    assert_ne!(other.coin_id, coin_id_for(1), "the fixture must substitute");

    // EVERY peer agrees — this is not a dissent case. The tally is unanimous and still wrong.
    let voices: Vec<Voice> = (0..4).map(|_| Voice::Record(Some(other.clone()))).collect();
    let (reads, db, _) = reads_over(voices).await;

    let outcome = reads.coin_record_by_id(&coin_id_for(1)).await;
    assert!(
        outcome.is_err(),
        "a unanimous answer about another coin was accepted: {outcome:?}"
    );

    // And nothing was written. A row keyed on the answer's id would be a permanent entry for a
    // question nobody asked, later served with no corroboration at all.
    assert!(
        db.cached_chain_read(&other.coin_id, NOW)
            .await
            .unwrap()
            .is_none(),
        "the substituted coin was cached"
    );
    assert!(
        db.cached_chain_read(&coin_id_for(1), NOW)
            .await
            .unwrap()
            .is_none(),
        "a row was written for the requested id from a substituted answer"
    );
}

/// The same binding for a spend, where the stakes are higher.
///
/// `verified_reveal_hex` ties the puzzle reveal to a puzzle hash, but the SOLUTION is bound by
/// nothing — and the solution is the half that says what the coin became. Spend rows also have no
/// TTL, because a spend is immutable once it exists, so a row accepted here is permanent.
#[tokio::test]
async fn a_unanimous_sample_cannot_substitute_a_different_spend() {
    let other = FallbackCoinSpend {
        coin_id: "ee".repeat(32),
        ..spend("80")
    };

    let voices: Vec<Voice> = (0..4).map(|_| Voice::Spend(Some(other.clone()))).collect();
    let (reads, db, _) = reads_over(voices).await;

    let outcome = reads.coin_spend(&spend_coin_id()).await;
    assert!(
        outcome.is_err(),
        "a unanimous spend of another coin was accepted: {outcome:?}"
    );
    assert!(
        db.cached_chain_spend(&spend_coin_id(), NOW)
            .await
            .unwrap()
            .is_none(),
        "a permanent spend row was written from a substituted answer"
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
    let result = reads.coin_spend(&spend_coin_id()).await;
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
    live.coin_spend(&spend_coin_id()).await.unwrap();

    let a_decade_later = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW + 10 * 365 * 24 * 3600)));
    assert_eq!(
        a_decade_later.coin_spend(&spend_coin_id()).await.unwrap(),
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

    reads.coin_record_by_id(&coin_id_for(3)).await.unwrap();
    let after_first = asked.load(Ordering::SeqCst);

    let shouted = format!("0x{}", coin_id_for(3).to_ascii_uppercase());
    assert_eq!(
        reads.coin_record_by_id(&shouted).await.unwrap(),
        Some(coin(3, Some(9_000_400)))
    );
    assert_eq!(asked.load(Ordering::SeqCst), after_first);
}

// ---------------------------------------------------------------------------
// What a cached row must survive on the way OUT (dig_ecosystem#3035)
// ---------------------------------------------------------------------------
//
// Every test below writes its row STRAIGHT TO THE TABLE. That is the whole point: before this,
// no test seeded a cache row directly, so every check on the cached path was reachable only
// through the write path that had already validated the same facts — and deleting one of those
// checks failed nothing. A check no test can kill is a check that disappears in the next
// refactor, and these rows never expire.

use super::super::db::{ChainCacheBudgets, ChainCacheTable};

/// A spend row whose puzzle reveal does not tree-hash to its puzzle hash is REFUSED, not served.
///
/// The row is otherwise impeccable — its parent, puzzle hash and amount hash to exactly the key it
/// is stored under — so the ONLY thing that can refuse it is the reveal check on the cached branch.
/// That is what makes this test load-bearing for that one line rather than for the read in general.
///
/// The draw is peerless, so a `Some` could only have come from the cache and an `Err` could only
/// have come from the check.
#[tokio::test]
async fn a_cached_spend_whose_reveal_does_not_hash_to_its_puzzle_hash_is_refused() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let key = coin_id_for(1);
    db.put_chain_spend(
        &ChainSpendCacheRow {
            coin_id: key.clone(),
            parent_coin_info: FIXTURE_PARENT.repeat(32),
            // The RECORD puzzle hash, which `REVEAL` does not tree-hash to — and the field the key
            // is derived from, so the row is self-consistent in every way except this one.
            puzzle_hash: FIXTURE_PUZZLE_HASH.repeat(32),
            amount: "1".into(),
            puzzle_reveal: REVEAL.to_string(),
            solution: "80".into(),
        },
        NOW,
    )
    .await
    .unwrap();

    let peerless = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW)));
    let outcome = peerless.coin_spend(&key).await;
    assert!(
        outcome.is_err(),
        "a cached spend whose reveal does not match its puzzle hash was served: {outcome:?}"
    );
    assert!(
        outcome.unwrap_err().message.contains("tree-hashes to"),
        "the refusal must name the reveal check that produced it"
    );
}

/// A spend row filed under a coin id its own fields do not hash to is REFUSED.
///
/// This is the check that replaced comparing the row's `coin_id` to the lookup key — a comparison
/// that could not fail, because the row's `coin_id` IS the key it was selected by. This one can:
/// the fixture's reveal matches its puzzle hash (so the reveal check passes and cannot be what
/// refuses it), and only the coin id's own arithmetic separates the row from the question asked.
#[tokio::test]
async fn a_cached_spend_filed_under_a_foreign_coin_id_is_refused() {
    let db = WalletDb::open_in_memory().await.unwrap();
    // Some OTHER coin's id — the key a second writer, or a keying change, could file a row under.
    let foreign_key = coin_id_for(999);
    db.put_chain_spend(
        &ChainSpendCacheRow {
            coin_id: foreign_key.clone(),
            parent_coin_info: FIXTURE_PARENT.repeat(32),
            puzzle_hash: reveal_tree_hash(REVEAL),
            amount: "1".into(),
            puzzle_reveal: REVEAL.to_string(),
            solution: "80".into(),
        },
        NOW,
    )
    .await
    .unwrap();

    let peerless = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW)));
    let outcome = peerless.coin_spend(&foreign_key).await;
    assert!(
        outcome.is_err(),
        "a spend row whose fields hash to another coin was served: {outcome:?}"
    );
    assert!(
        outcome.unwrap_err().message.contains("hash to"),
        "the refusal must name the binding that produced it"
    );
}

/// The same for a coin RECORD: a row whose three fields do not hash to its key is refused.
///
/// The honest control sits in the same test — the identical fields under the key they really hash
/// to — so this separates "refuses a foreign row" from "refuses everything cached".
#[tokio::test]
async fn a_cached_record_whose_fields_do_not_hash_to_its_key_is_refused() {
    let db = WalletDb::open_in_memory().await.unwrap();
    let honest = coin_id_for(7);
    let foreign = coin_id_for(8);

    // The row's fields are those of the amount-7 coin; the key says amount 8.
    let mut foreign_row = read_row(7, NOW);
    foreign_row.coin_id = foreign.clone();
    db.put_chain_read(&foreign_row, NOW).await.unwrap();
    db.put_chain_read(&read_row(7, NOW), NOW).await.unwrap();

    let peerless = PeerCorroboratedReads::new(Arc::new(ScriptedSample::new(vec![])), db)
        .with_clock(Arc::new(FixedClock(NOW)));
    assert!(
        peerless.coin_record_by_id(&foreign).await.is_err(),
        "a record row whose fields hash to another coin was served"
    );
    assert!(
        peerless.coin_record_by_id(&honest).await.unwrap().is_some(),
        "the honest control row must still be served"
    );
}

// ---------------------------------------------------------------------------
// The budget (dig_ecosystem#3035)
// ---------------------------------------------------------------------------

/// A record row for the coin of `amount`, ready to write.
fn read_row(amount: u64, now: i64) -> ChainReadCacheRow {
    ChainReadCacheRow {
        coin_id: coin_id_for(amount),
        parent_coin_info: FIXTURE_PARENT.repeat(32),
        puzzle_hash: FIXTURE_PUZZLE_HASH.repeat(32),
        amount: amount.to_string(),
        created_height: Some(9_000_000),
        // SPENT, so the row is usable however long ago it was written and no test here depends on
        // the TTL.
        spent_height: Some(9_000_050),
        created_timestamp: None,
        spent_timestamp: None,
        cached_at: now,
    }
}

/// The record cache stops growing at its budget, pinned from BOTH sides: exactly at the budget
/// nothing is evicted, one over evicts exactly one row.
///
/// A budget tested only by over-filling it is satisfied identically by an implementation that
/// evicts eagerly and keeps far less than it promises.
#[tokio::test]
async fn the_record_cache_holds_exactly_its_budget() {
    let db = WalletDb::open_in_memory()
        .await
        .unwrap()
        .with_chain_cache_budgets(ChainCacheBudgets {
            reads: 3,
            spends: 3,
        });

    for amount in 1..=3u64 {
        db.put_chain_read(&read_row(amount, NOW), NOW + amount as i64)
            .await
            .unwrap();
    }
    assert_eq!(
        db.chain_cache_len(ChainCacheTable::Reads).await.unwrap(),
        3,
        "at the budget nothing may be evicted"
    );

    db.put_chain_read(&read_row(4, NOW), NOW + 4).await.unwrap();
    assert_eq!(
        db.chain_cache_len(ChainCacheTable::Reads).await.unwrap(),
        3,
        "one row over the budget must evict exactly one row"
    );
}

/// Eviction ranks by recency of USE, not of insertion — the property the whole budget turns on.
///
/// The fixture separates the two orders deliberately: the OLDEST-written row is the one re-read,
/// so a cache that evicted by insertion order would drop exactly the row a lineage walk is still
/// walking. That is the nearest wrong implementation, and it is the one this test kills.
#[tokio::test]
async fn a_re_read_row_outlives_a_newer_one_that_was_never_used_again() {
    let db = WalletDb::open_in_memory()
        .await
        .unwrap()
        .with_chain_cache_budgets(ChainCacheBudgets {
            reads: 2,
            spends: 2,
        });

    db.put_chain_read(&read_row(1, NOW), NOW).await.unwrap();
    db.put_chain_read(&read_row(2, NOW), NOW + 1).await.unwrap();

    // The walk comes back to the FIRST row. Reading it is what marks it used.
    assert!(db
        .cached_chain_read(&coin_id_for(1), NOW + 2)
        .await
        .unwrap()
        .is_some());

    // A third row pushes the table over its budget.
    db.put_chain_read(&read_row(3, NOW), NOW + 3).await.unwrap();

    assert!(
        db.cached_chain_read(&coin_id_for(1), NOW + 4)
            .await
            .unwrap()
            .is_some(),
        "the re-read row must survive: it is the one a walk is still using"
    );
    assert!(
        db.cached_chain_read(&coin_id_for(2), NOW + 4)
            .await
            .unwrap()
            .is_none(),
        "the row nobody came back to must be the one evicted"
    );
}

/// The spend cache is bounded the same way, and a flood of DISTINCT coin ids — the shape
/// `control.wallet.coinById` hands an unauthenticated caller — cannot push it past its budget.
#[tokio::test]
async fn a_flood_of_distinct_ids_cannot_grow_the_spend_cache_past_its_budget() {
    let db = WalletDb::open_in_memory()
        .await
        .unwrap()
        .with_chain_cache_budgets(ChainCacheBudgets {
            reads: 5,
            spends: 5,
        });

    for amount in 1..=200u64 {
        db.put_chain_spend(
            &ChainSpendCacheRow {
                coin_id: coin_id_for(amount),
                parent_coin_info: FIXTURE_PARENT.repeat(32),
                puzzle_hash: reveal_tree_hash(REVEAL),
                amount: amount.to_string(),
                puzzle_reveal: REVEAL.to_string(),
                solution: "80".into(),
            },
            NOW + amount as i64,
        )
        .await
        .unwrap();
    }

    assert_eq!(
        db.chain_cache_len(ChainCacheTable::Spends).await.unwrap(),
        5,
        "the spend cache must stay at its budget however many distinct ids are asked for"
    );
}

/// The shipped budgets, stated so a change to either is a deliberate edit to a test that says what
/// the number means (roughly 20 MiB of records and 40 MiB of spends — see their doc comments).
#[test]
fn the_shipped_budgets_are_what_the_docs_claim() {
    assert_eq!(super::super::db::CHAIN_READ_CACHE_MAX_ROWS, 50_000);
    assert_eq!(super::super::db::CHAIN_SPEND_CACHE_MAX_ROWS, 10_000);
}

// ---------------------------------------------------------------------------
// The corroborated peak (dig_ecosystem#2790)
// ---------------------------------------------------------------------------

/// A claimed tip. The header hash is derived from the height so two peers claiming the same height
/// claim the same thing, and two claiming different heights are distinguishable.
fn tip(height: u32) -> super::super::quorum::PeakClaim {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&height.to_be_bytes());
    super::super::quorum::PeakClaim {
        height,
        header_hash: chia::protocol::Bytes32::from(hash),
    }
}

/// Reads over peers that are silent about coins and each claim their own tip.
///
/// The coin voice is deliberately `Silent` throughout: it isolates the peak round, so a passing
/// assertion cannot be explained by a coin answer.
async fn peak_reads_over(peaks: Vec<Option<super::super::quorum::PeakClaim>>) -> PeerCorroboratedReads {
    let db = WalletDb::open_in_memory().await.unwrap();
    let sample = Arc::new(ScriptedSample {
        voices: vec![Voice::Silent; peaks.len()],
        peaks,
        asked: Arc::new(AtomicUsize::new(0)),
    });
    PeerCorroboratedReads::new(sample, db).with_clock(Arc::new(FixedClock(NOW)))
}

/// The control. Every refusal below is otherwise satisfied by a round that always refuses.
#[tokio::test]
async fn several_agreeing_peers_settle_a_peak() {
    let reads = peak_reads_over(vec![
        Some(tip(9_000_000)),
        Some(tip(9_000_000)),
        Some(tip(9_000_000)),
        Some(tip(9_000_000)),
    ])
    .await;

    assert_eq!(
        reads.peak_height().await,
        Some(9_000_000 - super::super::quorum::SETTLED_LAG),
        "four peers agreeing about the tip must produce a settled height"
    );
}

/// The property the whole change exists for, asserted where the node actually reads it.
///
/// A sample that has collapsed to ONE voice is what a node reading from a single hostile source
/// sees, and it is also what a node whose corroboration silently stopped working sees. Neither may
/// produce a number.
#[tokio::test]
async fn a_peak_round_that_collapses_to_one_peer_reports_no_height() {
    let reads = peak_reads_over(vec![Some(tip(9_000_000))]).await;

    assert_eq!(
        reads.peak_height().await,
        None,
        "one peer decided this node's view of the chain: the round consulted a single voice and \
         believed it"
    );
}

/// Silence narrows a round, and a round narrowed to one voice refuses just as a one-peer draw does.
///
/// This is the case a draw-size check alone would miss: four peers were drawn, so any assertion
/// about the SAMPLE still holds, and only one of them actually claimed anything.
#[tokio::test]
async fn three_silent_peers_leave_one_voice_and_that_is_not_agreement() {
    let reads = peak_reads_over(vec![Some(tip(9_000_000)), None, None, None]).await;

    assert_eq!(
        reads.peak_height().await,
        None,
        "three peers said nothing and the fourth was believed anyway"
    );
}

/// A liar among honest peers is outvoted at the read, not merely at the pure function.
#[tokio::test]
async fn a_lying_peer_does_not_move_the_peak_the_node_reports() {
    let honest = vec![
        Some(tip(9_000_000)),
        Some(tip(9_000_000)),
        Some(tip(9_000_000)),
    ];
    let mut with_liar = honest.clone();
    with_liar.push(Some(tip(u32::MAX)));

    let truthful = peak_reads_over(honest).await.peak_height().await;
    let attacked = peak_reads_over(with_liar).await.peak_height().await;

    assert!(
        truthful.is_some(),
        "fixture: the honest set must settle, or the equality below holds because both refused"
    );
    assert_eq!(
        attacked, truthful,
        "a peer claiming an absurd tip changed the height this node reports"
    );
}
