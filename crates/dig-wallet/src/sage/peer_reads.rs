//! ARBITRARY chain reads, served by the node's own Chia peers and believed only on agreement
//! (dig_ecosystem#3032).
//!
//! # The hole this fills
//!
//! dig-node's wallet replica covers the addresses it subscribes to, and nothing else. Reading a
//! **dig-profile** means walking a store singleton's lineage — `coin_record` by coin id, then the
//! `coin_spend` that moved it, generation after generation — over coins that are nobody's watched
//! address. Those reads are *arbitrary*, so the replica structurally cannot answer them, and until
//! this module they fell through to a third-party HTTP oracle. On a node with no upstream
//! configured that fallthrough was an error, which is why a healthy, fully-synced node with five
//! peers told its owner it *"could not reach the blockchain to read your profile"*.
//!
//! Configuring an upstream is not the fix. An endpoint that answers arbitrary chain reads is a
//! trusted peer by another name, and every profile anybody read would be whatever that endpoint
//! said. The node already holds peers; the answer is to ask them.
//!
//! # Why a coin read is a BETTER quorum question than a peak
//!
//! [`super::quorum`] was built for the peak-height problem and its module docs explain the hard
//! part: Chia produces a block roughly every 18.75s, so honest peers hold DIFFERENT tips at any
//! instant and a naive vote on the tip splits almost always. That whole difficulty is absent here.
//! A **confirmed coin record is stable** — its id is the hash of its own three fields, and its
//! creation height does not move — so agreement is the normal case rather than a race, and a peer
//! that contradicts the others about a settled coin is not merely behind.
//!
//! [`super::quorum::tally`] is generic over the answer type, so this module supplies a coin as the
//! answer and inherits [`super::quorum::CORROBORATION_FLOOR`] (never one source) and
//! [`super::quorum::required_agreement`] (the shipped agreement ratio) unchanged. Nothing about
//! peer trust is invented here.
//!
//! # Fail closed, in the direction that matters
//!
//! Three outcomes, never two:
//!
//! * `Ok(Some(..))` — enough independently drawn peers gave the SAME answer.
//! * `Ok(None)` — enough independently drawn peers agreed the coin (or the spend) does not exist.
//! * `Err(..)` — too few peers answered, or they disagreed. **UNKNOWN, never absence.**
//!
//! The collapse this refuses is the third into the second. A caller walking a lineage reads "no
//! spend" as *this coin is the tip* and stops there, so an unreachable network served as absence
//! produces a spend built against a singleton that has already moved on.
//!
//! # What is cached, and the one asymmetry that decides it
//!
//! **A spent coin's record is immutable; an unspent one can become spent.** A coin id is
//! `SHA256(parent ‖ puzzle_hash ‖ amount)`, so those three fields can never be wrong for their key
//! — the only fields a cache entry can go stale in are `spent_height`/`spent_timestamp`, and they
//! only ever change once, in one direction. So:
//!
//! * a record showing the coin SPENT is cached forever ([`cache_entry_is_usable`]);
//! * a record showing it UNSPENT expires after [`UNSPENT_CACHE_TTL_SECS`], because caching
//!   "unspent" indefinitely would make a profile look permanently stale — and on a money surface
//!   that is the wrong direction to fail;
//! * a SPEND is cached forever with no timestamp at all, because a spend cannot un-happen.
//!
//! That asymmetry is what makes the walk affordable rather than merely faster: a lineage walk
//! touches a spent coin at every generation but the last, so the permanent half of the cache
//! covers almost the whole walk, and only its tip is ever re-asked.
//!
//! **An absence is never cached.** A coin that does not exist yet may exist in a minute, and an
//! entry saying otherwise would outlive the truth.

use std::sync::Arc;

use async_trait::async_trait;
use chia::protocol::Bytes32;

use super::db::{ChainReadCacheRow, ChainSpendCacheRow, WalletDb};
use super::fallback::{FallbackCoin, FallbackCoinSpend};
use super::quorum;
use super::{Error, Result};

/// How long a record showing an UNSPENT coin may be served from the cache, in seconds.
///
/// Short on purpose, and the two ways of getting it wrong are not symmetric. Too long makes a coin
/// that has since been spent look live, which on the money surfaces this feeds is the expensive
/// direction. Too short only costs a round trip. Sized to roughly three Chia blocks, so a walk
/// completes on one set of answers while a coin's spentness cannot go unnoticed for long.
pub const UNSPENT_CACHE_TTL_SECS: i64 = 60;

/// Whether a cached coin RECORD may still be served.
///
/// A pure function of the two facts that decide it, so the rule can be tested from both sides
/// without a database or a clock: `spent_height` (is this entry immutable?) and the entry's age.
///
/// * SPENT — usable forever. The record cannot change again; the coin is gone.
/// * UNSPENT — usable for [`UNSPENT_CACHE_TTL_SECS`]. It can become spent at any block.
///
/// A `now` earlier than `cached_at` — a clock that moved backwards — makes the entry UNUSABLE
/// rather than usable. A negative age is a fact about the clock and not about the coin, and of the
/// two ways to read it, "ask the peers again" costs a round trip while "serve it" would extend an
/// unspent entry's life by however far the clock jumped.
#[must_use]
pub const fn cache_entry_is_usable(spent_height: Option<i64>, cached_at: i64, now: i64) -> bool {
    if spent_height.is_some() {
        return true;
    }
    let age = now.saturating_sub(cached_at);
    age >= 0 && age < UNSPENT_CACHE_TTL_SECS
}

/// ONE peer the round may put its question to.
///
/// A trait rather than a concrete connection because the properties worth testing here — that a
/// lone peer never decides anything, that a dissenting peer is outvoted rather than believed, that
/// a silent peer lowers confidence instead of failing the round — are all properties of how MANY
/// peers say WHAT, and none of them are reachable through a real mainnet dial.
#[async_trait]
pub trait CoinPeer: Send + Sync {
    /// How the round names this peer. Distinctness of these ids is what makes four opinions four
    /// opinions rather than one counted four times.
    fn id(&self) -> String;

    /// This peer's coin record for `coin_id`: `Ok(None)` is its claim that no such coin exists,
    /// `Err` is a failure to get any claim at all.
    async fn coin_record(&self, coin_id: Bytes32) -> Result<Option<FallbackCoin>>;

    /// This peer's spend of `coin_id`: `Ok(None)` is its claim that the coin is unspent or unknown.
    async fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<FallbackCoinSpend>>;
}

/// Draws the independently-chosen peers one round asks.
///
/// Separate from [`CoinPeer`] because independence is a property of the DRAW, not of any peer:
/// whoever implements this decides whether the round hears several voices or one voice several
/// times.
#[async_trait]
pub trait PeerSample: Send + Sync {
    /// The peers for one round. An empty or single-peer draw is a legitimate answer — the tally
    /// refuses it as [`quorum::Verdict::Insufficient`] rather than the draw pretending otherwise.
    async fn draw(&self) -> Vec<Arc<dyn CoinPeer>>;
}

/// Reads the clock the cache ages entries against. A seam so a cache test pins an explicit `NOW`
/// instead of racing wall-clock time.
pub trait Clock: Send + Sync {
    /// The current time in Unix seconds.
    fn now_unix(&self) -> i64;
}

/// The production clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// Arbitrary chain reads: the cache first, then a corroborated round of the node's own peers.
pub struct PeerCorroboratedReads {
    sample: Arc<dyn PeerSample>,
    db: WalletDb,
    clock: Arc<dyn Clock>,
}

impl PeerCorroboratedReads {
    /// Reads served by `sample`, cached in `db`, aged against the system clock.
    pub fn new(sample: Arc<dyn PeerSample>, db: WalletDb) -> Self {
        Self {
            sample,
            db,
            clock: Arc::new(SystemClock),
        }
    }

    /// The same, against an explicit clock — the seam the cache-expiry tests pin `NOW` through.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// One coin by id: the cache if it holds a usable entry, else a corroborated peer round.
    ///
    /// `Ok(None)` means the peers AGREED there is no such coin. Failing to assemble agreement is
    /// an `Err`.
    pub async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        let id = normalized(coin_id);
        let parsed = parse_coin_id(&id)?;

        let now = self.clock.now_unix();
        if let Some(row) = self
            .db
            .cached_chain_read(&id, now)
            .await
            .map_err(|e| Error::internal(format!("chain-read cache read failed: {e}")))?
        {
            if cache_entry_is_usable(row.spent_height, row.cached_at, now) {
                let coin = coin_from_cache(&row)?;
                // The row is re-checked on the way OUT, not merely on the way in
                // (dig_ecosystem#3035). Today the only production writer of this table binds at
                // write time, so the row cannot be foreign — but that is a property of the current
                // call graph, not of this read, and a second writer would arrive silently.
                // Recomputing the id from the row's own three fields is arithmetic no writer can
                // outrank, and it costs one hash of bytes already in hand.
                //
                // What it does NOT cover is deliberate: `spent_height` and `cached_at` are outside
                // the id, and they are exactly the fields [`cache_entry_is_usable`] governs above.
                bind_fields_to_key(
                    &coin.parent_coin_info,
                    &coin.puzzle_hash,
                    coin.amount,
                    &id,
                    "cached coin record",
                )?;
                return Ok(Some(coin));
            }
        }

        let peers = self.sample.draw().await;
        let mut responses = Vec::with_capacity(peers.len());
        for peer in &peers {
            // A peer that will not answer is simply ABSENT from the tally: it lowers the round's
            // confidence rather than discarding a round the peers that DID answer could settle.
            if let Ok(answer) = peer.coin_record(parsed).await {
                responses.push(quorum::Response {
                    peer: peer.id(),
                    answer,
                });
            }
        }

        let verdict = quorum::tally(&responses);
        let Some(answer) = verdict.corroborated() else {
            return Err(no_corroboration("coin record", &id, &verdict));
        };

        if let Some(coin) = answer {
            // **The answer must be about the coin that was ASKED for.** A vote settles which answer
            // the peers agree on; it cannot settle whether they answered the right question, and
            // `quorum.rs` says so directly: a majority "would let a majority of peers overrule a
            // check that cannot be wrong."
            //
            // Without this, two colluding peers — a full quorum, since `required_agreement(2) == 2`
            // — answer a request for X with a `CoinState` for any coin Y they choose, agree with
            // each other, and the walk continues down a substituted lineage. Recomputing the id
            // from the coin the peer sent does NOT catch it: that binds the coin to itself, which
            // every coin satisfies.
            //
            // Cheap and absolute, because a coin id IS the coin's hash — arithmetic no vote can
            // outrank.
            bind_to_request(coin, &id, "coin record")?;
            self.db
                // Keyed on the REQUESTED id, never the answer's: a row written under the answer's
                // id would be a permanent entry for a question nobody asked, served later without
                // corroboration.
                .put_chain_read(&cache_row(coin, &id, now), now)
                .await
                .map_err(|e| Error::internal(format!("chain-read cache write failed: {e}")))?;
        }
        // A corroborated ABSENCE is deliberately not cached: a coin that does not exist yet may
        // exist in a minute, and an entry saying otherwise would outlive the truth.
        Ok(answer.clone())
    }

    /// The spend that spent one coin: the cache, else a corroborated peer round.
    ///
    /// `Ok(None)` means the peers AGREED the coin is unspent or unknown. Failing to assemble
    /// agreement is an `Err`, because a lineage walk reads absence as *this is the tip*.
    pub async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        let id = normalized(coin_id);
        let parsed = parse_coin_id(&id)?;

        let now = self.clock.now_unix();
        // No freshness test: a cached spend is immutable by construction.
        if let Some(row) = self
            .db
            .cached_chain_spend(&id, now)
            .await
            .map_err(|e| Error::internal(format!("chain-spend cache read failed: {e}")))?
        {
            let spend = spend_from_cache(&row)?;
            // The cached path re-runs the SAME reveal check the live path applies per peer. A check
            // that only guards the wire is a check an attacker routes around by getting one row
            // written — and spend rows never expire, so a bad row would be served, uncorroborated,
            // forever. Cheap: a hash of bytes already in hand.
            super::fallback::verified_reveal_hex(&spend.puzzle_reveal, &spend.puzzle_hash)?;
            // And the coin's own three fields must hash to the key the row was found under
            // (dig_ecosystem#3035). Note what this REPLACES: comparing `row.coin_id` to the lookup
            // key, which is what the live path does, cannot fail here — the row's `coin_id` IS the
            // key it was selected by, so that comparison read as a guard while being none. This one
            // can fail, and it is the same arithmetic the live binding relies on.
            bind_fields_to_key(
                &spend.parent_coin_info,
                &spend.puzzle_hash,
                spend.amount,
                &id,
                "cached coin spend",
            )?;
            return Ok(Some(spend));
        }

        let peers = self.sample.draw().await;
        let mut responses = Vec::with_capacity(peers.len());
        for peer in &peers {
            if let Ok(answer) = peer.coin_spend(parsed).await {
                responses.push(quorum::Response {
                    peer: peer.id(),
                    answer,
                });
            }
        }

        let verdict = quorum::tally(&responses);
        let Some(answer) = verdict.corroborated() else {
            return Err(no_corroboration("coin spend", &id, &verdict));
        };

        if let Some(spend) = answer {
            // The same binding, and it matters more here: `verified_reveal_hex` ties the puzzle
            // reveal to a puzzle hash, but **the solution is bound by nothing**. So a spend accepted
            // for the wrong coin persists a forged solution indefinitely — the spend rows have no
            // TTL, because a spend is immutable once it exists.
            bind_spend_to_request(spend, &id)?;
            self.db
                .put_chain_spend(&spend_row(spend, &id), now)
                .await
                .map_err(|e| Error::internal(format!("chain-spend cache write failed: {e}")))?;
        }
        Ok(answer.clone())
    }
}

/// The error a refused round produces: UNKNOWN, stated as unknown.
///
/// It carries the verdict's shape because the two refusals demand different remedies and a caller
/// staring at one line of log deserves to know which it hit: too few peers answered (a
/// reachability problem — the node is alone, not under attack), or the peers that answered
/// disagreed (which at a coin id, whose fields are its own hash, is not ordinary lag).
fn no_corroboration<A>(read: &str, coin_id: &str, verdict: &quorum::Verdict<A>) -> Error {
    let why = match verdict {
        quorum::Verdict::Insufficient { answered, required } => {
            format!("only {answered} of the required {required} peers answered at all")
        }
        quorum::Verdict::Split { tallies } => format!(
            "the peers that answered disagreed (vote counts {tallies:?}); a coin id is the hash \
             of the coin's own fields, so this is not ordinary lag"
        ),
        _ => "corroborated".to_string(),
    };
    Error::internal(format!(
        "{read} for {coin_id} could not be corroborated: {why}. The answer is UNKNOWN, which is \
         not the same as no such coin"
    ))
}

/// Lowercase, `0x`-stripped hex — the one spelling the cache is keyed on.
fn normalized(coin_id: &str) -> String {
    coin_id
        .strip_prefix("0x")
        .unwrap_or(coin_id)
        .to_ascii_lowercase()
}

/// The coin id as the 32 bytes the peer protocol takes.
fn parse_coin_id(id: &str) -> Result<Bytes32> {
    let bytes = hex::decode(id).map_err(|_| Error::api("coin id is not hex"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::api("coin id is not 32 bytes"))?;
    Ok(Bytes32::from(array))
}

/// Refuse an answer that is not about the coin that was asked for.
///
/// # Why a vote cannot cover this
///
/// `quorum::tally` settles which answer the peers agree on. It cannot settle whether they answered
/// the right question — and `quorum.rs` names that hazard outright: a majority "would let a majority
/// of peers overrule a check that cannot be wrong."
///
/// A coin id IS the coin's hash, so this is arithmetic. Two colluding peers are a full quorum
/// (`required_agreement(2) == 2`), so without it they can answer a request for X with a coin of
/// their choosing and be believed unanimously.
///
/// Note what does NOT work: recomputing the id from the coin the peer sent. That binds the coin to
/// itself, which every coin satisfies. The comparison has to be against the REQUESTED id.
fn bind_to_request(coin: &FallbackCoin, requested: &str, what: &str) -> Result<()> {
    if normalized(&coin.coin_id) == requested {
        return Ok(());
    }
    Err(Error::internal(format!(
        "{what}: peers agreed on a coin that is not the one asked for (requested {requested}, \
         answered {})",
        normalized(&coin.coin_id)
    )))
}

/// The same binding for a spend.
fn bind_spend_to_request(spend: &FallbackCoinSpend, requested: &str) -> Result<()> {
    if normalized(&spend.coin_id) == requested {
        return Ok(());
    }
    Err(Error::internal(format!(
        "coin spend: peers agreed on a spend of a coin that is not the one asked for (requested \
         {requested}, answered {})",
        normalized(&spend.coin_id)
    )))
}

/// Refuse a CACHED row whose own fields do not hash to the key it was stored under.
///
/// The cached counterpart of [`bind_to_request`], and it has to be spelled differently. A cached
/// row's `coin_id` column is the key the row was SELECTed by, so comparing the two is a tautology;
/// what can still be checked is the coin id's definition —
/// `SHA256(parent ‖ puzzle_hash ‖ amount)` — against that key. Any row whose fields were altered,
/// or written under someone else's id, fails it.
///
/// This is what stands in for the write-time binding on the read path, so a second writer of either
/// cache table cannot appear unnoticed and be believed (dig_ecosystem#3035).
fn bind_fields_to_key(
    parent_coin_info: &str,
    puzzle_hash: &str,
    amount: u64,
    key: &str,
    what: &str,
) -> Result<()> {
    let coin = chia::protocol::Coin {
        parent_coin_info: parse_coin_id(&normalized(parent_coin_info))?,
        puzzle_hash: parse_coin_id(&normalized(puzzle_hash))?,
        amount,
    };
    let computed = hex::encode(coin.coin_id());
    if computed == key {
        return Ok(());
    }
    Err(Error::internal(format!(
        "{what}: the cached row's fields hash to {computed}, not to the coin id {key} it is stored          under"
    )))
}

/// A corroborated coin, as the cache stores it.
fn cache_row(coin: &FallbackCoin, requested: &str, now: i64) -> ChainReadCacheRow {
    ChainReadCacheRow {
        // The REQUESTED id, so a row can only ever answer the question it was asked.
        coin_id: requested.to_string(),
        parent_coin_info: coin.parent_coin_info.clone(),
        puzzle_hash: coin.puzzle_hash.clone(),
        // Decimal string, matching `coins.amount`: SQLite's INTEGER is signed, so a mojo count
        // near the u64 ceiling does not survive a round trip through it.
        amount: coin.amount.to_string(),
        created_height: coin.created_height.map(i64::from),
        spent_height: coin.spent_height.map(i64::from),
        created_timestamp: coin.created_timestamp.and_then(|t| i64::try_from(t).ok()),
        spent_timestamp: coin.spent_timestamp.and_then(|t| i64::try_from(t).ok()),
        cached_at: now,
    }
}

/// A cached coin, back as the read's answer.
fn coin_from_cache(row: &ChainReadCacheRow) -> Result<FallbackCoin> {
    Ok(FallbackCoin {
        coin_id: row.coin_id.clone(),
        parent_coin_info: row.parent_coin_info.clone(),
        puzzle_hash: row.puzzle_hash.clone(),
        amount: row
            .amount
            .parse::<u64>()
            .map_err(|_| Error::internal("cached coin amount is not a number".to_string()))?,
        created_height: row.created_height.and_then(|h| u32::try_from(h).ok()),
        spent_height: row.spent_height.and_then(|h| u32::try_from(h).ok()),
        created_timestamp: row.created_timestamp.and_then(|t| u64::try_from(t).ok()),
        spent_timestamp: row.spent_timestamp.and_then(|t| u64::try_from(t).ok()),
    })
}

/// A corroborated spend, as the cache stores it.
fn spend_row(spend: &FallbackCoinSpend, requested: &str) -> ChainSpendCacheRow {
    ChainSpendCacheRow {
        // The REQUESTED id. Spend rows have no TTL, so a row under the wrong key is permanent.
        coin_id: requested.to_string(),
        parent_coin_info: spend.parent_coin_info.clone(),
        puzzle_hash: spend.puzzle_hash.clone(),
        amount: spend.amount.to_string(),
        puzzle_reveal: spend.puzzle_reveal.clone(),
        solution: spend.solution.clone(),
    }
}

/// A cached spend, back as the read's answer.
fn spend_from_cache(row: &ChainSpendCacheRow) -> Result<FallbackCoinSpend> {
    Ok(FallbackCoinSpend {
        coin_id: row.coin_id.clone(),
        parent_coin_info: row.parent_coin_info.clone(),
        puzzle_hash: row.puzzle_hash.clone(),
        amount: row
            .amount
            .parse::<u64>()
            .map_err(|_| Error::internal("cached spend amount is not a number".to_string()))?,
        puzzle_reveal: row.puzzle_reveal.clone(),
        solution: row.solution.clone(),
    })
}

pub mod dialed;

pub use dialed::DialedPeerSample;

#[cfg(test)]
mod tests;
