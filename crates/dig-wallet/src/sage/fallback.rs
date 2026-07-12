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

    async fn coin_record_by_id(&self, coin_id: &str) -> Result<Option<FallbackCoin>> {
        match self
            .query
            .get_coin_record_by_name(&Self::query_hash(coin_id))
            .await
        {
            Ok(r) => Ok(Some(Self::map_record(&r)?)),
            // A missing coin surfaces as an error from coinset; treat as "not found".
            Err(_) => Ok(None),
        }
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
        pub calls: Arc<AtomicUsize>,
    }

    impl MockFallback {
        pub fn with_coins(coins: Vec<FallbackCoin>) -> Self {
            Self {
                coins,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
        pub fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ChainFallback for MockFallback {
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
    }
}
