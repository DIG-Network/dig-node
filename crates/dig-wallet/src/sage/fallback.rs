//! The fallback tier (design **B.5**): `chia-query` (coinset.org + non-subscribing peer
//! point-reads) reused **as-is**, behind the [`ChainFallback`] trait.
//!
//! This tier is used ONLY (a) while the wallet DB is still syncing — so a caller never
//! waits for the subscription replica to converge — and (b) for chain reads outside the
//! wallet's own tracked data / not in the DB. It is **never** the primary path: the
//! primary path is the direct-peer subscription sync ([`crate::sage::sync`]) feeding the
//! local DB ([`crate::sage::db`]). The B.3 subscription loop is deliberately NOT added to
//! `chia-query` (separation of concerns, design C.2) — `chia-query` provides only the
//! point-read + coinset substrate underneath.
//!
//! The trait is the seam the routing layer ([`crate::sage::routing`]) depends on, so its
//! decisions are unit-testable with a mock (the concrete [`CoinsetFallback`] talks to the
//! live network and is exercised in the higher integration tiers, not unit tests).

use async_trait::async_trait;

use super::{Error, Result};

/// A blockchain coin normalized from the fallback source into the shape the RPC layer
/// maps to a Sage `CoinRecord`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackCoin {
    /// The coin id (hex, no `0x`).
    pub coin_id: String,
    /// The parent coin id (hex).
    pub parent_coin_info: String,
    /// The puzzle hash (hex).
    pub puzzle_hash: String,
    /// The amount in mojos / base units.
    pub amount: u64,
    /// The created block height, if confirmed.
    pub created_height: Option<u32>,
    /// The spent block height, if spent.
    pub spent_height: Option<u32>,
    /// The created timestamp.
    pub created_timestamp: Option<u64>,
    /// The spent timestamp.
    pub spent_timestamp: Option<u64>,
}

/// A coin's SPEND normalized from the fallback source: the coin that was consumed, plus the two
/// programs that consumed it (dig_ecosystem#2572).
///
/// Deliberately NOT a [`FallbackCoin`]: a spend read tells you what a coin BECAME, and carries no
/// heights at all — the source answers with a bare `(coin, puzzle_reveal, solution)` triple. Giving
/// this type `created_height`/`spent_height` fields would invite a mapper to fill them with `None`
/// and a caller to read that as "unconfirmed", when the truth is "this read never asked". The
/// heights come from a SEPARATE coin-record read, composed one layer up
/// ([`super::rpc::WalletBackend::coin_spend`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackCoinSpend {
    /// The spent coin's id (hex, no `0x`), RECOMPUTED from the returned coin rather than echoed
    /// from the request — see [`ChainFallback::coin_spend`] for why that distinction is the whole
    /// point.
    pub coin_id: String,
    /// The spent coin's parent coin id (hex).
    pub parent_coin_info: String,
    /// The spent coin's puzzle hash (hex). The [`Self::puzzle_reveal`] tree-hashes to this.
    pub puzzle_hash: String,
    /// The spent coin's amount in mojos / base units.
    pub amount: u64,
    /// The puzzle reveal: hex of the serialized CLVM program, no `0x`.
    pub puzzle_reveal: String,
    /// The solution the puzzle ran with: hex of the serialized CLVM, no `0x`.
    pub solution: String,
}

/// The fallback chain-read surface (design B.5). Small on purpose: only the reads the
/// core wallet-data endpoints need while syncing or for out-of-DB lookups.
#[async_trait]
pub trait ChainFallback: Send + Sync {
    /// Coins currently at the given puzzle hashes (unspent + recently spent).
    async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>>;
    /// Coins hinted to the given hints (CAT association).
    async fn coin_records_by_hints(&self, hints: &[String]) -> Result<Vec<FallbackCoin>>;
    /// A single coin by id (out-of-DB / arbitrary lookup).
    async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>>;

    /// The SPEND that spent `coin_id`, or `Ok(None)` when a chain ANSWERED that no such spend
    /// exists — the coin is unspent, or unknown (dig_ecosystem#2572).
    ///
    /// # Three values, never two
    ///
    /// A spend, a legitimate absence, and a failure to read are three DIFFERENT answers. `Ok(None)`
    /// is the middle one only. Collapsing a failure into it is a money lie in the direction that
    /// costs the most: a caller following a singleton forward reads "no spend" as *this coin is the
    /// tip* and builds its next spend against a coin that has in fact already been spent, which the
    /// mempool then rejects — or, on a mint poll, reads a dropped connection as "the funding coin is
    /// still there" and funds the same mint twice.
    ///
    /// # The answer is BOUND to the question
    ///
    /// An implementation MUST recompute the returned coin's id — `SHA256(parent ‖ puzzle_hash ‖
    /// amount)`, self-certifying — and return `Err` when it is not the id asked for, exactly as
    /// [`Self::coin_record_by_id`] does. It MUST also verify that the puzzle reveal tree-hashes to
    /// the spent coin's own puzzle hash, and fail closed when it does not or when the reveal will
    /// not parse. Both checks are local and need no second source; without them a single hostile
    /// peer decides what a caller believes a coin became.
    async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>>;

    /// The DIRECT children created by spending `parent_coin_id` — ONE hop, never a walk
    /// (dig_ecosystem#2572).
    ///
    /// An empty vector means a chain ANSWERED and that parent created no children it knows of
    /// (typically: the parent is unspent). Every failure to reach a chain is an `Err` — an empty
    /// list returned for an outage reads as "that spend created nothing", which terminates a lineage
    /// walk early and silently.
    ///
    /// An implementation MUST assert that every returned child's `parent_coin_info` is the parent
    /// asked for, and return `Err` on any that is not: an unrelated coin admitted here becomes a
    /// forged branch of somebody's lineage.
    async fn coin_records_by_parent(&self, parent_coin_id: &str) -> Result<Vec<FallbackCoin>>;

    /// Whether this fallback can actually reach a chain source. `true` for a live tier
    /// ([`CoinsetFallback`]); `false` for the graceful no-network [`EmptyFallback`], whose
    /// every read is a silent empty. A read that MUST consult the chain (an arbitrary,
    /// non-wallet address, or a wallet address whose DB has not synced) uses this to tell
    /// "chain says zero" apart from "no chain source to ask" — the difference between a
    /// truthful `0` and an honest error (#1851).
    fn is_live(&self) -> bool {
        false
    }

    /// The chain peak height this tier can see, or `Ok(None)` when it tracks none.
    ///
    /// The default is `Ok(None)`, which is the truthful answer for a tier with no chain behind it
    /// ([`EmptyFallback`]). `None` means UNKNOWN and MUST NOT be read as height zero — every block
    /// is above zero, so a "is it buried yet" comparison against zero silently succeeds.
    async fn peak_height(&self) -> Result<Option<u32>> {
        Ok(None)
    }
}

/// The production fallback: `chia_query::ChiaQuery` (coinset.org + peer point-reads),
/// reused as-is. Holds a shared [`std::sync::Arc`] so ONE `ChiaQuery` client backs the fallback
/// reads, the live broadcaster, the confirmer, and the lineage source together (§18.12).
pub struct CoinsetFallback {
    query: std::sync::Arc<chia_query::ChiaQuery>,
}

impl CoinsetFallback {
    /// Wrap a shared [`chia_query::ChiaQuery`] — the SAME client the broadcaster/confirmer/lineage
    /// share, so the live wallet uses one connection pool.
    pub fn new(query: std::sync::Arc<chia_query::ChiaQuery>) -> Self {
        Self { query }
    }

    /// Normalize hex (strip an optional `0x` prefix, lowercase).
    fn norm_hex(s: &str) -> String {
        s.strip_prefix("0x").unwrap_or(s).to_ascii_lowercase()
    }

    /// Normalize a hash/hint to the canonical Chia-RPC QUERY form: a lowercased, **`0x`-prefixed**
    /// hex string. `chia_query`'s coinset tier forwards these verbatim to coinset.org, whose
    /// full-node RPC matches ONLY `0x`-prefixed hex — so a bare-hex query silently returns zero
    /// coins. That was the live "have 0 $DIG" bug (#430): the wallet coin-DB sync
    /// ([`super::rpc::WalletBackend::refresh_tracked_coins`]) builds its tracked puzzle hashes with
    /// bare `hex::encode`, which the tolerant peer tier accepted (it strips an optional `0x`) but
    /// the coinset fallback tier dropped — so a bring-up that fell through to coinset saw an empty
    /// balance and could not select $DIG. Prefixing satisfies BOTH tiers.
    fn query_hash(s: &str) -> String {
        format!("0x{}", Self::norm_hex(s))
    }

    /// [`Self::query_hash`] over a slice (the puzzle-hash / hint list a query takes).
    fn query_hashes(items: &[String]) -> Vec<String> {
        items.iter().map(|s| Self::query_hash(s)).collect()
    }

    /// Compute a coin id from a coinset [`chia_query::Coin`].
    fn coin_id_of(coin: &chia_query::Coin) -> Result<String> {
        let parent = Self::norm_hex(&coin.parent_coin_info);
        let ph = Self::norm_hex(&coin.puzzle_hash);
        let parent_bytes: [u8; 32] = hex::decode(&parent)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Error::internal("fallback: bad parent_coin_info hex"))?;
        let ph_bytes: [u8; 32] = hex::decode(&ph)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Error::internal("fallback: bad puzzle_hash hex"))?;
        let c = chia_protocol::Coin {
            parent_coin_info: parent_bytes.into(),
            puzzle_hash: ph_bytes.into(),
            amount: coin.amount,
        };
        Ok(hex::encode(c.coin_id()))
    }

    /// Verify a puzzle reveal against the puzzle hash it claims to reveal, yielding the reveal's
    /// canonical bare-hex form.
    ///
    /// A puzzle reveal arrives from an unauthenticated peer, and a peer can send any program at
    /// all. The check is purely local because a puzzle hash IS the reveal's CLVM tree hash: a
    /// substituted program cannot hash to the coin's own puzzle hash. Skipping it would let a peer
    /// dictate what a caller believes a coin's puzzle was — and a caller reconstructing a singleton
    /// lineage curries that program forward, so the forgery propagates into the spend it builds.
    ///
    /// Fails CLOSED on both a mismatch and an unparseable reveal, because "I could not check it" and
    /// "it failed the check" oblige the same refusal.
    fn verified_reveal(puzzle_reveal: &str, puzzle_hash: &str) -> Result<String> {
        let reveal_hex = Self::norm_hex(puzzle_reveal);
        let bytes = hex::decode(&reveal_hex)
            .map_err(|e| Error::internal(format!("fallback spend read: puzzle_reveal hex: {e}")))?;
        let tree_hash = chia::clvm_utils::tree_hash_from_bytes(&bytes).map_err(|e| {
            Error::internal(format!(
                "fallback spend read: puzzle_reveal is not a parseable CLVM program: {e}"
            ))
        })?;
        let claimed = Self::norm_hex(puzzle_hash);
        let actual = hex::encode(tree_hash.to_bytes());
        if actual != claimed {
            return Err(Error::internal(format!(
                "fallback spend read: the puzzle reveal tree-hashes to {actual}, not to the spent \
                 coin's puzzle hash {claimed}"
            )));
        }
        Ok(reveal_hex)
    }

    fn map_record(r: &chia_query::CoinRecord) -> Result<FallbackCoin> {
        Ok(FallbackCoin {
            coin_id: Self::coin_id_of(&r.coin)?,
            parent_coin_info: Self::norm_hex(&r.coin.parent_coin_info),
            puzzle_hash: Self::norm_hex(&r.coin.puzzle_hash),
            amount: r.coin.amount,
            created_height: (r.confirmed_block_index > 0).then_some(r.confirmed_block_index),
            spent_height: (r.spent && r.spent_block_index > 0).then_some(r.spent_block_index),
            created_timestamp: (r.timestamp > 0).then_some(r.timestamp),
            spent_timestamp: None,
        })
    }
}

#[async_trait]
impl ChainFallback for CoinsetFallback {
    async fn peak_height(&self) -> Result<Option<u32>> {
        self.query
            .peak_height_opt()
            .await
            .map_err(|e| Error::internal(format!("peak-height read failed: {e}")))
    }

    /// A real coinset/peer connection: a genuinely live chain source (#1851).
    fn is_live(&self) -> bool {
        true
    }

    async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>> {
        let phs = Self::query_hashes(phs);
        let records = self
            .query
            .get_coin_records_by_puzzle_hashes(&phs, None, None, true)
            .await
            .map_err(|e| Error::internal(format!("fallback puzzle-hash read: {e}")))?;
        records.iter().map(Self::map_record).collect()
    }

    async fn coin_records_by_hints(&self, hints: &[String]) -> Result<Vec<FallbackCoin>> {
        let hints = Self::query_hashes(hints);
        let records = self
            .query
            .get_coin_records_by_hints(&hints, None, None, true)
            .await
            .map_err(|e| Error::internal(format!("fallback hint read: {e}")))?;
        records.iter().map(Self::map_record).collect()
    }

    /// `Ok(None)` ONLY when a chain source ANSWERED and reported no such coin; every failure to
    /// read is an `Err` (dig_ecosystem#2392).
    ///
    /// `Ok(None)` is NOT yet proof of absence: `chia-query` 0.6 mints it from ONE peer's empty
    /// coin-state list without consulting coinset, so a peer that is a block behind, mid-reorg,
    /// pruning or hostile produces it. Requiring corroboration is dig_ecosystem#2456, one crate
    /// down. Callers polling a mint read `None` as "not seen yet", never as "never happened".
    ///
    /// The absence-aware `_opt` variant carries that distinction (a `success: true` envelope with a
    /// null record is absence; a transport/API failure is not), so this method must not re-decide
    /// it. Collapsing an unreachable chain into "no such coin" is a money lie: a caller polling a
    /// mint would read a dropped connection as "your coin does not exist", so a pending mint stays
    /// awaiting forever and a spent funding coin can never report failure.
    ///
    /// The returned record is bound to the coin that was ASKED for: a coin id is self-certifying
    /// (`SHA256(parent ‖ puzzle_hash ‖ amount)`), and the tier underneath answers from one
    /// unauthenticated, DNS-discovered peer that never hashes what it forwards. A record for a
    /// different coin is therefore a read FAILURE — not this coin's record (which would let a
    /// substituted coin read as "the mint landed") and not absence (which is the lie above).
    async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        let record = self
            .query
            .get_coin_record_by_name_opt(&Self::query_hash(coin_id))
            .await
            .map_err(|e| Error::internal(format!("fallback coin-id read: {e}")))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let coin = Self::map_record(&record)?;
        if coin.coin_id != Self::norm_hex(coin_id) {
            return Err(Error::internal(format!(
                "fallback coin-id read: source answered with a different coin ({} for a request \
                 for {})",
                coin.coin_id,
                Self::norm_hex(coin_id)
            )));
        }
        Ok(Some(coin))
    }

    /// `Ok(None)` ONLY when a chain ANSWERED that the coin has no spend; every failure is an `Err`
    /// (dig_ecosystem#2572).
    ///
    /// Uses `chia-query`'s absence-aware `get_coin_spend_opt`, whose `Ok(None)` is a `success: true`
    /// envelope carrying a null `coin_solution`. The nearby [`ChiaQueryLineage::parent_spend`]
    /// deliberately does NOT share this path: it maps EVERY error to `Ok(None)`, which is precisely
    /// the collapse this method must not make.
    ///
    /// Both bindings from the trait contract are enforced here, and they check different things: the
    /// coin-id recomputation says WHICH coin the answer describes, and the reveal's tree hash says
    /// the program really is that coin's puzzle. A substitution passing one still fails the other.
    async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        let spend = self
            .query
            .get_coin_spend_opt(&Self::query_hash(coin_id))
            .await
            .map_err(|e| Error::internal(format!("fallback coin-spend read: {e}")))?;
        let Some(spend) = spend else {
            return Ok(None);
        };
        let answered_id = Self::coin_id_of(&spend.coin)?;
        let asked_id = Self::norm_hex(coin_id);
        if answered_id != asked_id {
            return Err(Error::internal(format!(
                "fallback coin-spend read: source answered with the spend of a different coin \
                 ({answered_id} for a request for {asked_id})"
            )));
        }
        let puzzle_hash = Self::norm_hex(&spend.coin.puzzle_hash);
        let puzzle_reveal = Self::verified_reveal(&spend.puzzle_reveal, &puzzle_hash)?;
        Ok(Some(FallbackCoinSpend {
            coin_id: answered_id,
            parent_coin_info: Self::norm_hex(&spend.coin.parent_coin_info),
            puzzle_hash,
            amount: spend.coin.amount,
            puzzle_reveal,
            solution: Self::norm_hex(&spend.solution),
        }))
    }

    /// The parent's DIRECT children. An empty vector is an ANSWER; every failure is an `Err`
    /// (dig_ecosystem#2572).
    ///
    /// `include_spent_coins: true` because a child that has since been spent is still a child — a
    /// lineage walk follows exactly those, so filtering them out would hide every hop but the last.
    /// No height window, for the same reason: a caller naming a parent has not named a height, and
    /// inventing one would silently drop children outside it.
    ///
    /// Every child is checked to actually name the requested parent. Unlike a coin id, a
    /// parent-child link is NOT self-certifying from the child alone, so this check is a
    /// consistency assertion on what the source said rather than a cryptographic proof — but it is
    /// what stops an unrelated coin being admitted as somebody's descendant, which a caller would
    /// then walk forward as if it were theirs.
    async fn coin_records_by_parent(&self, parent_coin_id: &str) -> Result<Vec<FallbackCoin>> {
        let asked = Self::norm_hex(parent_coin_id);
        let records = self
            .query
            .get_coin_records_by_parent_ids(&[Self::query_hash(parent_coin_id)], None, None, true)
            .await
            .map_err(|e| Error::internal(format!("fallback children read: {e}")))?;
        records
            .iter()
            .map(|r| {
                let child = Self::map_record(r)?;
                if child.parent_coin_info != asked {
                    return Err(Error::internal(format!(
                        "fallback children read: source answered with a child of {} for a request \
                         for the children of {asked}",
                        child.parent_coin_info
                    )));
                }
                Ok(child)
            })
            .collect()
    }
}

/// The production lineage source (§18.12): resolves a parent coin's spend (puzzle reveal +
/// solution) via `chia_query::get_puzzle_and_solution`, so CAT/singleton reconstruction (the
/// `$DIG` attribution + `send_cat` input resolution) works over live chain reads. Shares the SAME
/// [`std::sync::Arc`]`<`[`chia_query::ChiaQuery`]`>` the fallback/broadcaster use.
pub struct ChiaQueryLineage {
    query: std::sync::Arc<chia_query::ChiaQuery>,
}

impl ChiaQueryLineage {
    /// Wrap the shared `ChiaQuery` client.
    pub fn new(query: std::sync::Arc<chia_query::ChiaQuery>) -> Self {
        Self { query }
    }
}

#[async_trait]
impl super::singleton::LineageSource for ChiaQueryLineage {
    async fn parent_spend(
        &self,
        parent_coin_id: &str,
        spent_height: u32,
    ) -> Result<Option<super::singleton::ParentSpend>> {
        let coin_id = format!("0x{}", CoinsetFallback::norm_hex(parent_coin_id));
        let cs = match self
            .query
            .get_puzzle_and_solution(&coin_id, Some(spent_height))
            .await
        {
            Ok(cs) => cs,
            // The parent spend is not available (unspent / not found) — a clean "no lineage".
            Err(_) => return Ok(None),
        };
        let decode = |field: &str, s: &str| -> Result<Vec<u8>> {
            hex::decode(s.strip_prefix("0x").unwrap_or(s))
                .map_err(|e| Error::internal(format!("lineage {field} hex: {e}")))
        };
        let parent = super::singleton::bytes32_from_hex(&cs.coin.parent_coin_info)?;
        let puzzle_hash = super::singleton::bytes32_from_hex(&cs.coin.puzzle_hash)?;
        Ok(Some(super::singleton::ParentSpend {
            coin: chia_protocol::Coin {
                parent_coin_info: parent,
                puzzle_hash,
                amount: cs.coin.amount,
            },
            puzzle_reveal: decode("puzzle_reveal", &cs.puzzle_reveal)?,
            solution: decode("solution", &cs.solution)?,
        }))
    }
}

/// A graceful no-network fallback (#368): every read returns empty / not-found rather than
/// erroring. It is the default fallback for the shipped node's served backend BEFORE the
/// direct-peer sync loop is wired (SPEC §18.12): a wallet-scoped read of an unsynced DB then
/// reports an honest empty result (matching the pushed `syncing` state) instead of a `500`, and
/// the node never blocks bring-up on network/TLS setup. Replaced by [`CoinsetFallback`] once the
/// live sync loop is attached.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyFallback;

#[async_trait]
impl ChainFallback for EmptyFallback {
    async fn coin_records_by_puzzle_hashes(&self, _phs: &[String]) -> Result<Vec<FallbackCoin>> {
        Ok(Vec::new())
    }
    async fn coin_records_by_hints(&self, _hints: &[String]) -> Result<Vec<FallbackCoin>> {
        Ok(Vec::new())
    }
    async fn coin_record_by_id(&self, _coin_id: &str) -> Result<Option<FallbackCoin>> {
        Ok(None)
    }
    async fn coin_spend(&self, _coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
        Ok(None)
    }
    async fn coin_records_by_parent(&self, _parent_coin_id: &str) -> Result<Vec<FallbackCoin>> {
        Ok(Vec::new())
    }
    /// No network: not a live chain source (#1851).
    ///
    /// This is what keeps the silent empties above from ever being SERVED as absence: every caller
    /// checks [`Self::is_live`] first and answers `WALLET_NO_CHAIN_SOURCE` instead.
    fn is_live(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod empty_fallback_tests {
    use super::*;

    /// Regression (#430): the coinset tier of `chia_query` forwards puzzle hashes / hints to
    /// coinset.org verbatim, and that RPC matches only `0x`-prefixed hex. [`CoinsetFallback`]
    /// MUST therefore normalize its bare-hex inputs (the form `refresh_tracked_coins` produces
    /// via `hex::encode`) to lowercased `0x`-prefixed hex before the query — otherwise a
    /// bring-up that falls through to coinset reads back zero coins ("have 0 $DIG").
    #[test]
    fn query_hash_prefixes_0x_and_lowercases() {
        assert_eq!(CoinsetFallback::query_hash("ABcd"), "0xabcd");
        assert_eq!(
            CoinsetFallback::query_hash("0xABcd"),
            "0xabcd",
            "existing 0x is not doubled"
        );
        assert_eq!(
            CoinsetFallback::query_hashes(&["aa".into(), "0xBB".into()]),
            vec!["0xaa".to_string(), "0xbb".to_string()],
        );
    }

    #[tokio::test]
    async fn empty_fallback_returns_empty_never_errors() {
        let fb = EmptyFallback;
        assert!(fb
            .coin_records_by_puzzle_hashes(&["00".repeat(32)])
            .await
            .unwrap()
            .is_empty());
        assert!(fb
            .coin_records_by_hints(&["ab".into()])
            .await
            .unwrap()
            .is_empty());
        assert!(fb.coin_record_by_id("cc").await.unwrap().is_none());
    }
}

#[cfg(test)]
mod chain_failure_tests {
    //! The money-critical mapping: a chain that could not be READ is an error, and only a chain
    //! that PROVABLY has no such coin is `Ok(None)` (dig_ecosystem#2392).
    //!
    //! Both directions are pinned together on purpose. Either one alone is satisfiable by
    //! collapsing the other — an implementation that always errors passes the first, one that
    //! always answers `Ok(None)` passes the second.
    //!
    //! The fixture is a real [`chia_query::ChiaQuery`] over a REAL socket, because the mapping
    //! under test lives in how `chia-query` classifies a transport outcome; a double that returns
    //! a pre-decided `Result` would assert the test's own opinion instead. `max_peers: 0` keeps it
    //! deterministic and offline: the peer tier has nothing to dial (and never refills, so it
    //! performs no DNS), so every read falls through to the local coinset stand-in below.

    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A `ChiaQuery` whose only reachable tier is the coinset URL given.
    async fn fallback_against(coinset_base_url: String) -> CoinsetFallback {
        let query = chia_query::ChiaQuery::new(chia_query::ChiaQueryConfig {
            coinset_base_url,
            max_peers: 0,
            coinset_fallback_enabled: true,
            coinset_request_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        })
        .await
        .expect("a zero-peer client with the coinset fallback enabled always constructs");
        CoinsetFallback::new(Arc::new(query))
    }

    /// A base URL nothing listens on: bind a port, learn it, then release it. More reliable than
    /// guessing an unused port number.
    async fn dead_base_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    }

    /// A one-shot coinset stand-in that answers every POST with `body`, and its base URL.
    async fn serve_json(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// A coin id the fixtures ask for. Its value is irrelevant — what varies is the SOURCE.
    const SOME_COIN_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// The coin record [`KNOWN_COIN_RECORD`] describes, as JSON.
    const KNOWN_COIN_RECORD: &str = r#"{"success":true,"coin_record":{
                "coin":{"parent_coin_info":"0x2222222222222222222222222222222222222222222222222222222222222222",
                        "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                        "amount":7},
                "confirmed_block_index":100,"spent_block_index":140,"spent":true,
                "coinbase":false,"timestamp":1700000000}}"#;

    /// The id of the coin in [`KNOWN_COIN_RECORD`]: `SHA256(parent ‖ puzzle_hash ‖ amount)` over
    /// `0x22…22`, `0x33…33` and the minimal big-endian encoding of `7` (`0x07`).
    ///
    /// Pinned as a literal computed independently of this crate, so a mistake in the production
    /// coin-id derivation cannot make the fixture agree with itself.
    const KNOWN_COIN_ID: &str = "626443fb96579ab5eb3cbd9d75a39d8e428356af2fce9077ae5b4f7db4e72f9f";

    /// **A chain that could not answer MUST NOT report "no such coin".**
    ///
    /// A dropped connection, a `500`, a TLS failure and a rate-limit are all "we do not know".
    /// Reporting them as absence tells a caller polling a mint that its coin does not exist — so a
    /// pending mint reads as still-awaiting forever, and a genuinely-spent funding coin can never
    /// report failure either. Both are money lies.
    #[tokio::test]
    async fn an_unreachable_chain_is_an_error_never_a_missing_coin() {
        let fallback = fallback_against(dead_base_url().await).await;

        let result = fallback.coin_record_by_id(SOME_COIN_ID).await;

        assert!(
            result.is_err(),
            "an unreachable chain must surface as an error, got {result:?}"
        );
        assert!(
            !matches!(result, Ok(None)),
            "an unreachable chain must NEVER be reported as a missing coin"
        );
    }

    /// **The paired direction: a chain that ANSWERED "no such coin" is `Ok(None)`, not an error.**
    ///
    /// coinset spells a reported absence as a `success: true` envelope with a null record. Without
    /// this half, the fix above could be satisfied by erroring on everything — which would make a
    /// never-minted coin indistinguishable from an outage, the same lie in the other direction.
    #[tokio::test]
    async fn an_absent_coin_is_ok_none_not_an_error() {
        let base = serve_json(r#"{"success":true,"coin_record":null}"#).await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_record_by_id(SOME_COIN_ID).await;

        assert!(
            matches!(result, Ok(None)),
            "a chain that answered 'no such coin' is Ok(None), got {result:?}"
        );
    }

    /// A coin the chain DOES know is mapped through, spent height and all — the value
    /// `control.wallet.coinById` exists to carry.
    #[tokio::test]
    async fn a_known_coin_is_mapped_through_with_its_spent_height() {
        let base = serve_json(KNOWN_COIN_RECORD).await;
        let fallback = fallback_against(base).await;

        let coin = fallback
            .coin_record_by_id(KNOWN_COIN_ID)
            .await
            .expect("a reachable chain answers")
            .expect("the chain knows this coin");

        assert_eq!(coin.amount, 7);
        assert_eq!(coin.created_height, Some(100));
        assert_eq!(
            coin.spent_height,
            Some(140),
            "a spent coin carries its real spent height"
        );
    }

    /// **A record for a DIFFERENT coin is a read failure — never this coin's record, and never
    /// absence.**
    ///
    /// The peer tier takes the first coin state a peer returns and never hashes it, and the pool is
    /// unauthenticated DNS-discovered mainnet nodes. So a single hostile peer can answer a lookup
    /// for X with any other real coin. Served as X's record it is a money lie in the worst
    /// direction: a caller polling a mint reads "coin present" as "the mint landed" and records a
    /// DID that is not on chain. Reported as absence it would be the #2392 lie again.
    ///
    /// A coin id is self-certifying — `SHA256(parent ‖ puzzle_hash ‖ amount)` — so the substitution
    /// is detectable locally, with no second source needed. The fixture serves the coin whose id is
    /// [`KNOWN_COIN_ID`] in answer to a request for [`SOME_COIN_ID`].
    #[tokio::test]
    async fn a_record_for_a_different_coin_is_an_error_never_this_coins_record() {
        let base = serve_json(KNOWN_COIN_RECORD).await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_record_by_id(SOME_COIN_ID).await;

        assert!(
            result.is_err(),
            "a source that answered with a different coin must surface as a read failure, \
             got {result:?}"
        );
        assert!(
            !matches!(result, Ok(None)),
            "a substituted coin must NEVER be reported as a missing coin"
        );
    }

    // ---- coin_spend + coin_records_by_parent (dig_ecosystem#2572) ----------------------

    /// The puzzle reveal used by the spend fixtures: the serialized CLVM atom `0x01`.
    ///
    /// A real, parseable program rather than arbitrary bytes, because the verification under test
    /// PARSES the reveal — a garbage value would be rejected for being unparseable and the tests
    /// would never reach the hash comparison they exist to exercise.
    const A_PUZZLE_REVEAL: &str = "01";

    /// `A_PUZZLE_REVEAL`'s CLVM tree hash — `SHA256(0x01 ‖ 0x01)` — pinned as a literal computed
    /// OUTSIDE this crate.
    ///
    /// A fixture that asked the production code for this value would agree with a broken production
    /// code path by construction, which is the one thing a verification test must not do.
    const A_PUZZLE_HASH: &str = "9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2";

    /// The id of the coin the spend fixtures describe: parent `0x22…22`, puzzle hash
    /// [`A_PUZZLE_HASH`], amount 7. Also computed independently of this crate.
    const SPENT_COIN_ID: &str = "3191419897f34473b9b63d60f35f8984c0bc2e74da6c074b50df72f41a4383a3";

    /// A coinset `get_puzzle_and_solution` answer for [`SPENT_COIN_ID`], whose reveal really does
    /// tree-hash to the coin's puzzle hash.
    const HONEST_SPEND: &str = r#"{"success":true,"coin_solution":{
                "coin":{"parent_coin_info":"0x2222222222222222222222222222222222222222222222222222222222222222",
                        "puzzle_hash":"0x9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2",
                        "amount":7},
                "puzzle_reveal":"0x01","solution":"0x80"}}"#;

    /// **An unreachable chain is an ERROR, never "this coin has no spend".**
    ///
    /// The three-valued rule, on the read where collapsing it costs the most. A caller walking a
    /// singleton forward reads "no spend" as *this coin is the tip* and builds its next spend
    /// against it; served for an outage, that spend is invalid because the singleton has in fact
    /// already moved on. **Catches** the shape of [`ChiaQueryLineage::parent_spend`], four hundred
    /// lines up, which maps every error to `Ok(None)` — the tempting thing to copy.
    #[tokio::test]
    async fn an_unreachable_chain_is_an_error_never_a_missing_spend() {
        let fallback = fallback_against(dead_base_url().await).await;

        let result = fallback.coin_spend(SOME_COIN_ID).await;

        assert!(result.is_err(), "an outage must be an error, got {result:?}");
        assert!(
            !matches!(result, Ok(None)),
            "an unreachable chain must NEVER be reported as 'this coin is unspent'"
        );
    }

    /// **The paired direction: a chain that ANSWERED "no spend" is `Ok(None)`, not an error.**
    ///
    /// Without this half, the test above is satisfied by an implementation that errors on
    /// everything — which would make an unspent coin indistinguishable from an outage, the same
    /// collapse in the other direction. coinset spells a reported absence as `success: true` with a
    /// null `coin_solution`.
    #[tokio::test]
    async fn an_unspent_coin_is_ok_none_not_an_error() {
        let base = serve_json(r#"{"success":true,"coin_solution":null}"#).await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_spend(SOME_COIN_ID).await;

        assert!(
            matches!(result, Ok(None)),
            "a chain that answered 'no spend' is Ok(None), got {result:?}"
        );
    }

    /// **An honest spend is mapped through: the reveal and the solution both arrive, normalized.**
    ///
    /// The value the whole method exists to carry — a coin record says a coin is gone, and only
    /// these two fields say what it became. **Catches** a mapper that drops the solution (the field
    /// with no verification attached to it, and therefore the easy one to lose), and one that leaves
    /// the `0x` prefix on: the contract's hex wire form is bare, and a consumer decoding `0x01` as
    /// hex gets a parse error rather than a program.
    #[tokio::test]
    async fn an_honest_spend_is_mapped_through_with_its_reveal_and_solution() {
        let base = serve_json(HONEST_SPEND).await;
        let fallback = fallback_against(base).await;

        let spend = fallback
            .coin_spend(SPENT_COIN_ID)
            .await
            .expect("a reachable chain answers")
            .expect("the chain knows this spend");

        assert_eq!(spend.coin_id, SPENT_COIN_ID);
        assert_eq!(spend.puzzle_hash, A_PUZZLE_HASH);
        assert_eq!(spend.parent_coin_info, "22".repeat(32));
        assert_eq!(spend.amount, 7);
        assert_eq!(spend.puzzle_reveal, A_PUZZLE_REVEAL, "no 0x prefix survives");
        assert_eq!(spend.solution, "80", "the solution travels, unprefixed");
    }

    /// **A spend of a DIFFERENT coin is a read failure — never this coin's spend, never absence.**
    ///
    /// The same substitution attack [`a_record_for_a_different_coin_is_an_error_never_this_coins_record`]
    /// covers for coin records, on the read where the consequence is worse: a caller handed somebody
    /// else's spend curries somebody else's puzzle forward as its own lineage.
    ///
    /// The fixture serves the (internally consistent, genuinely honest) spend of [`SPENT_COIN_ID`]
    /// in answer to a request for [`SOME_COIN_ID`]. Nothing about the payload is malformed — the
    /// reveal even verifies against its own coin — so the ONLY thing that can reject it is the
    /// binding to what was asked.
    #[tokio::test]
    async fn a_spend_of_a_different_coin_is_an_error_never_this_coins_spend() {
        let base = serve_json(HONEST_SPEND).await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_spend(SOME_COIN_ID).await;

        assert!(
            result.is_err(),
            "a source answering with another coin's spend must be a read failure, got {result:?}"
        );
        assert!(
            !matches!(result, Ok(None)),
            "a substituted spend must NEVER be reported as 'unspent'"
        );
    }

    /// **A puzzle reveal that does not tree-hash to the coin's puzzle hash is REFUSED.**
    ///
    /// The second, independent binding. A peer supplies the reveal, and a peer can send any program
    /// at all; a coin's puzzle hash IS its reveal's CLVM tree hash, so the lie is locally
    /// detectable with no second source. Without this check a peer decides what a caller believes a
    /// coin's puzzle was, and a caller reconstructing a singleton curries that forged program into
    /// the spend it then signs.
    ///
    /// **This test is why the coin-id binding is not sufficient on its own.** The fixture's coin id
    /// is genuine — it is the real id of a coin at puzzle hash `0x33…33` — so the request is for
    /// exactly the coin that comes back and the id check PASSES. Only the hash comparison can
    /// reject it. Swap the fixture's puzzle hash for a matching one and this is the honest case.
    #[tokio::test]
    async fn a_reveal_that_does_not_hash_to_the_coins_puzzle_is_refused() {
        // Coin `626443fb…` really does live at puzzle hash 0x33…33 (it is `KNOWN_COIN_ID`), so the
        // ONLY defect here is the reveal: `0x01` hashes to A_PUZZLE_HASH, not to 0x33…33.
        let base = serve_json(
            r#"{"success":true,"coin_solution":{
                "coin":{"parent_coin_info":"0x2222222222222222222222222222222222222222222222222222222222222222",
                        "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                        "amount":7},
                "puzzle_reveal":"0x01","solution":"0x80"}}"#,
        )
        .await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_spend(KNOWN_COIN_ID).await;

        assert!(
            result.is_err(),
            "a reveal that does not hash to the coin's puzzle hash must be refused, got {result:?}"
        );
        assert!(
            !matches!(result, Ok(None)),
            "an unverifiable reveal must NEVER be reported as 'unspent'"
        );
    }

    /// **A reveal that will not PARSE is refused, and refused the same way.**
    ///
    /// "I could not check it" and "it failed the check" oblige the same refusal, but they take
    /// different code paths — the parse happens before any comparison — so a fail-open `unwrap_or`
    /// on the parse would leave this case admitted while the test above stayed green. `0xff` is a
    /// CLVM prefix byte that introduces bytes never supplied.
    #[tokio::test]
    async fn an_unparseable_reveal_is_refused_rather_than_waved_through() {
        let base = serve_json(
            r#"{"success":true,"coin_solution":{
                "coin":{"parent_coin_info":"0x2222222222222222222222222222222222222222222222222222222222222222",
                        "puzzle_hash":"0x9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2",
                        "amount":7},
                "puzzle_reveal":"0xff","solution":"0x80"}}"#,
        )
        .await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_spend(SPENT_COIN_ID).await;

        assert!(
            result.is_err(),
            "an unparseable reveal must be refused, got {result:?}"
        );
    }

    /// **An unreachable chain is an ERROR, never "that parent created no children".**
    ///
    /// An empty child list terminates a lineage walk: the caller concludes the branch ends there.
    /// Serving an outage as one turns a transient network fault into a permanent, silent wrong
    /// answer about the shape of somebody's lineage.
    #[tokio::test]
    async fn an_unreachable_chain_is_an_error_never_a_childless_parent() {
        let fallback = fallback_against(dead_base_url().await).await;

        let result = fallback.coin_records_by_parent(SOME_COIN_ID).await;

        assert!(result.is_err(), "an outage must be an error, got {result:?}");
        assert!(
            !matches!(result, Ok(ref v) if v.is_empty()),
            "an unreachable chain must NEVER be reported as a childless parent"
        );
    }

    /// **The paired direction: a chain that ANSWERED "no children" is an empty `Ok`.**
    ///
    /// Pins the other half so the rule above cannot be satisfied by erroring on everything, which
    /// would make an unspent parent unreadable.
    #[tokio::test]
    async fn a_parent_with_no_children_is_an_empty_ok_not_an_error() {
        let base = serve_json(r#"{"success":true,"coin_records":[]}"#).await;
        let fallback = fallback_against(base).await;

        let children = fallback
            .coin_records_by_parent(SOME_COIN_ID)
            .await
            .expect("a chain that answered is not an error");

        assert!(children.is_empty(), "got {children:?}");
    }

    /// **A "child" that names a different parent is a read failure — the whole page, not just that
    /// row.**
    ///
    /// Unlike a coin id, a parent-child link cannot be verified from the child alone, so this is a
    /// consistency check on what the source said. Admitting the row would graft an unrelated coin
    /// onto somebody's lineage, and the caller would walk it forward as its own.
    ///
    /// **The fixture is deliberately MIXED — one genuine child, one foreign one — and asserts the
    /// call fails.** An all-foreign fixture would also pass against an implementation that returned
    /// only the rows it liked, silently dropping the rest; that implementation is the nearest wrong
    /// one here, because a silently filtered page is exactly the hole in a lineage this method must
    /// not produce. With a genuine child present, "filter it out" and "refuse the answer" give
    /// different observable results.
    #[tokio::test]
    async fn a_child_of_another_parent_fails_the_whole_read() {
        let base = serve_json(
            r#"{"success":true,"coin_records":[
                {"coin":{"parent_coin_info":"0x1111111111111111111111111111111111111111111111111111111111111111",
                         "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                         "amount":7},
                 "confirmed_block_index":100,"spent_block_index":0,"spent":false,
                 "coinbase":false,"timestamp":1700000000},
                {"coin":{"parent_coin_info":"0x9999999999999999999999999999999999999999999999999999999999999999",
                         "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                         "amount":9},
                 "confirmed_block_index":101,"spent_block_index":0,"spent":false,
                 "coinbase":false,"timestamp":1700000001}]}"#,
        )
        .await;
        let fallback = fallback_against(base).await;

        let result = fallback.coin_records_by_parent(SOME_COIN_ID).await;

        assert!(
            result.is_err(),
            "a page containing a foreign child must fail, not be quietly filtered: got {result:?}"
        );
    }

    /// **Genuine children are mapped through with their heights.**
    ///
    /// The positive control for the test above: without it, "refuse everything" passes that one.
    /// The two children differ in spent state, so a mapper that inherited the address-scoped reads'
    /// unspent filter would return one row here instead of two — and a lineage walk needs precisely
    /// the SPENT children, since those are the ones with a next hop.
    #[tokio::test]
    async fn genuine_children_are_mapped_through_spent_and_unspent_alike() {
        let base = serve_json(
            r#"{"success":true,"coin_records":[
                {"coin":{"parent_coin_info":"0x1111111111111111111111111111111111111111111111111111111111111111",
                         "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                         "amount":7},
                 "confirmed_block_index":100,"spent_block_index":140,"spent":true,
                 "coinbase":false,"timestamp":1700000000},
                {"coin":{"parent_coin_info":"0x1111111111111111111111111111111111111111111111111111111111111111",
                         "puzzle_hash":"0x3333333333333333333333333333333333333333333333333333333333333333",
                         "amount":9},
                 "confirmed_block_index":101,"spent_block_index":0,"spent":false,
                 "coinbase":false,"timestamp":1700000001}]}"#,
        )
        .await;
        let fallback = fallback_against(base).await;

        let children = fallback
            .coin_records_by_parent(SOME_COIN_ID)
            .await
            .expect("a reachable chain answers");

        assert_eq!(children.len(), 2, "a spent child is still a child");
        assert!(children.iter().all(|c| c.parent_coin_info == SOME_COIN_ID));
        assert_eq!(children[0].spent_height, Some(140));
        assert_eq!(children[1].spent_height, None);
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A deterministic in-memory [`ChainFallback`] for routing/RPC unit tests.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Records how many times each method was hit so tests can assert the fallback was
    /// (or was not) consulted.
    #[derive(Default)]
    pub struct MockFallback {
        pub coins: Vec<FallbackCoin>,
        /// The spends this double knows, keyed by their spent coin's id (dig_ecosystem#2572).
        pub spends: Vec<FallbackCoinSpend>,
        pub calls: Arc<AtomicUsize>,
    }

    impl MockFallback {
        pub fn with_coins(coins: Vec<FallbackCoin>) -> Self {
            Self {
                coins,
                spends: Vec::new(),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
        /// Add the spends this double will answer with. Kept SEPARATE from `coins` so a fixture can
        /// express a coin that exists with no spend, and a spend whose coin record is missing —
        /// two states the composed read must tell apart.
        pub fn with_spends(mut self, spends: Vec<FallbackCoinSpend>) -> Self {
            self.spends = spends;
            self
        }
        pub fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChainFallback for MockFallback {
        /// The test double stands in for a genuinely live chain source (unit tests that want
        /// the "no chain source" path use a dedicated non-live double instead, #1851).
        fn is_live(&self) -> bool {
            true
        }

        async fn coin_records_by_puzzle_hashes(&self, phs: &[String]) -> Result<Vec<FallbackCoin>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .coins
                .iter()
                .filter(|c| phs.contains(&c.puzzle_hash))
                .cloned()
                .collect())
        }
        async fn coin_records_by_hints(&self, _hints: &[String]) -> Result<Vec<FallbackCoin>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.coins.iter().find(|c| c.coin_id == coin_id).cloned())
        }
        async fn coin_spend(&self, coin_id: &str) -> Result<Option<FallbackCoinSpend>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.spends.iter().find(|s| s.coin_id == coin_id).cloned())
        }
        async fn coin_records_by_parent(&self, parent_coin_id: &str) -> Result<Vec<FallbackCoin>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .coins
                .iter()
                .filter(|c| c.parent_coin_info == parent_coin_id)
                .cloned()
                .collect())
        }
    }
}
