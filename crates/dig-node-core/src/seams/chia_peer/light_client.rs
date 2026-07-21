//! Seam 1's Chia **light-client** provider (#1314): a subscribing wallet-protocol light client
//! (`chia-peer`) that gives the node CONFIRMATION + PEAK observability — the current peak height and
//! the coin/puzzle-hash state for the coins it SUBSCRIBES to (DataStore/DataLayer singleton coins,
//! collateral, treasury/tip coins; store-owner + collateral puzzle hashes). Its read side is a
//! [`dig_chainsource_interface::ChainSourceProvider`] registered into `chia-query`'s aggregating
//! [`ProviderRegistry`] at priority 20 (dependency injection), alongside the coinset / local-node /
//! DIG-peers providers.
//!
//! ## What this is NOT (the seam-1 boundary lock)
//!
//! - It is **not** the DataStore content-root path. Content-root resolution STAYS on the coinset
//!   `sync_datastore` singleton walk ([`CoinsetResolver`](super::CoinsetResolver), seam 1's
//!   [`AnchoredRootResolver`](crate::shared::chain_view::AnchoredRootResolver)) — UNCHANGED. The
//!   light client never resolves content roots.
//! - It does **not** serve singleton-lineage or block-timestamp reads. `chia-peer`'s provider returns
//!   [`ChainSourceError::Unsupported`] for both BY DESIGN — a subscribing light client is not an
//!   archival index — and the registry composes providers so those reads fall through to a source
//!   that does support them (chia-query's coinset provider). No trait method is added or changed.
//! - It does **not** move the money-path anchored-root verification. `submit_spend` is wired for the
//!   seam-1 write path, but anchored-root verification stays on the coinset path.
//!
//! ## Lifecycle
//!
//! Construct the client on node start with the node's EXISTING tokio runtime (call from within it;
//! [`ChiaPeerProvider`](chia_peer::ChiaPeerProvider) drives its synchronous reads on a
//! [`Handle`](tokio::runtime::Handle) — never a second runtime). Arm its subscription set, then hand
//! the registry the provider via [`register_light_client_provider`].

use chia_peer::{ChiaLightClient, ChiaPeerConfig, ChiaPeerError, SubmitOutcome};
use chia_protocol::{Bytes32, CoinStateFilters, SpendBundle};
use chia_query::provider_registry::ProviderRegistry;
use dig_chainsource_interface::{ChainSourceError, ChainSourceProvider};

/// The independence group the chia-peer provider registers under: a single subscribing light client
/// is ONE source of failure/agreement, distinct from coinset.org or the DIG peer network. Two
/// providers sharing a group are never counted as independent in a custody quorum.
pub const CHIA_PEER_INDEPENDENCE_GROUP: &str = "chia-peer";

/// The set of on-chain identifiers the node's light client subscribes to for confirmation + peak
/// observability.
///
/// `coins` are the singleton/collateral/treasury coins whose confirmations the node tracks;
/// `puzzle_hashes` are the store-owner + collateral puzzle hashes whose coins the node watches as they
/// come and go. Both may be empty (a node with no stores yet subscribes to nothing — [`arm`](Self::arm)
/// is then a no-op).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChiaPeerSubscriptions {
    /// DataStore/DataLayer singleton coins + collateral + treasury/tip coins to track by coin id.
    pub coins: Vec<Bytes32>,
    /// Store-owner + collateral puzzle hashes to watch (every coin paying to them).
    pub puzzle_hashes: Vec<Bytes32>,
}

impl ChiaPeerSubscriptions {
    /// Whether this set subscribes to nothing (both lists empty), so arming is a no-op.
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty() && self.puzzle_hashes.is_empty()
    }

    /// Arms the set on `client`: subscribes to the coins and puzzle hashes (each only if non-empty),
    /// seeding the client's reorg-aware cache. Puzzle-hash subscriptions include both spent and
    /// unspent, hinted coins (the node must observe a collateral/treasury coin being spent, not only
    /// its creation).
    pub async fn arm(&self, client: &ChiaLightClient) -> Result<(), ChiaPeerError> {
        if !self.coins.is_empty() {
            client.subscribe_coins(self.coins.clone()).await?;
        }
        if !self.puzzle_hashes.is_empty() {
            client
                .subscribe_puzzle_hashes(self.puzzle_hashes.clone(), watch_all_filters())
                .await?;
        }
        Ok(())
    }
}

/// The coin-state filter for a puzzle-hash subscription: watch EVERY coin paying to the hash —
/// created or spent, including hinted coins — so the node observes the full lifecycle of a
/// collateral/treasury coin, not only its creation.
fn watch_all_filters() -> CoinStateFilters {
    CoinStateFilters {
        include_spent: true,
        include_unspent: true,
        include_hinted: true,
        min_amount: 0,
    }
}

/// Connects a light client per `config`, arms `subs`, and returns the ready client.
///
/// Call this from WITHIN the node's existing tokio runtime — it spawns no second runtime. On success
/// the client's drive-loop keeps its subscription cache current from the peer's push stream; register
/// its provider with [`register_light_client_provider`] to expose those reads.
pub async fn connect_light_client(
    config: ChiaPeerConfig,
    subs: ChiaPeerSubscriptions,
) -> Result<ChiaLightClient, ChiaPeerError> {
    let client = ChiaLightClient::connect(config).await?;
    subs.arm(&client).await?;
    Ok(client)
}

/// Submits `bundle` for the seam-1 write path, mapping the node's ack to a typed [`SubmitOutcome`].
///
/// This is the light client's WRITE leg — deliberately separate from the reads-only `ChainSource`
/// surface. Anchored-root verification on the money path stays on the coinset walk; this only relays
/// an already-built, already-signed bundle to the network.
pub async fn submit_spend(
    client: &ChiaLightClient,
    bundle: SpendBundle,
) -> Result<SubmitOutcome, ChiaPeerError> {
    client.submit_spend(bundle).await
}

/// Registers a light-client-backed `provider` into `registry` under the
/// [`CHIA_PEER_INDEPENDENCE_GROUP`], returning the extended registry.
///
/// The provider carries its OWN try-order priority — `chia-peer`'s
/// [`DEFAULT_PROVIDER_PRIORITY`](chia_peer::DEFAULT_PROVIDER_PRIORITY) = 20 — so it is tried after a
/// priority-0 operator-trusted local node but ahead of a higher-numbered coinset tier. Trust is left
/// to default from the provider's [`ProviderKind`](dig_chainsource_interface::ProviderKind)
/// (`LocalNode` -> trusted, `Custom` -> untrusted); custody reads still gate on that trust in
/// chia-query's fail-closed custody view. Public-quorum custody is left OFF (the registry's safe
/// default) — this seam adds a single-provider observability source, not a trust quorum.
///
/// Dependency injection (a boxed provider) keeps this unit-testable without a live Chia node and
/// keeps the seam from owning connection policy.
pub fn register_light_client_provider(
    registry: ProviderRegistry,
    provider: Box<dyn ChainSourceProvider<Error = ChainSourceError>>,
) -> ProviderRegistry {
    registry.register(provider, None, CHIA_PEER_INDEPENDENCE_GROUP)
}

/// The confirmation depth of a coin confirmed at `confirmed_height` given the current `peak`, using
/// SATURATING subtraction.
///
/// A coin read in the one-block window before the drive-loop processes the matching `NewPeakWallet`
/// can momentarily report a height at (or above) the known peak. Plain `peak - confirmed_height`
/// would underflow that into a spurious ~4.29-billion depth on a money path (#1326/#1346);
/// `saturating_sub` yields 0 (the conservative, understating direction) instead.
pub fn confirmation_depth(peak: u32, confirmed_height: u32) -> u32 {
    peak.saturating_sub(confirmed_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Coin, CoinSpend};
    use chia_query::provider_registry::{CoinsetProvider, CustomProvider, ProviderRegistry};
    use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
    use std::sync::Mutex;

    fn coin_id(seed: u8) -> Bytes32 {
        Coin::new(Bytes32::new([seed; 32]), Bytes32::new([seed ^ 1; 32]), 1).coin_id()
    }

    fn record(id: Bytes32, confirmed: u32) -> CoinRecord {
        CoinRecord {
            coin: Coin::new(id, Bytes32::new([0x22; 32]), 1),
            confirmed_height: Some(confirmed),
            spent_height: None,
            timestamp: None,
            coinbase: false,
        }
    }

    /// A configurable `ChainSource` stand-in whose per-method answers are scripted, so the registry
    /// wiring + fall-through can be exercised with no live node. It records how many times each read
    /// was invoked, so a test can prove which provider actually answered.
    #[derive(Default)]
    struct FakeSource {
        peak: Option<u32>,
        coin: Option<CoinRecord>,
        lineage: Option<SingletonLineage>,
        timestamp: Option<u64>,
        /// When set, lineage/timestamp return `Unsupported` (chia-peer's light-client behaviour).
        unsupported_lineage_and_timestamp: bool,
        lineage_reads: Mutex<u32>,
        timestamp_reads: Mutex<u32>,
    }

    impl ChainSource for FakeSource {
        type Error = ChainSourceError;

        fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(self.coin.clone())
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(self.coin.clone().into_iter().collect())
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(vec![])
        }

        fn coin_spend(&self, _coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
            Ok(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            *self.lineage_reads.lock().unwrap() += 1;
            if self.unsupported_lineage_and_timestamp {
                return Err(ChainSourceError::Unsupported(
                    "singleton lineage resolution is not provided by the light-client source",
                ));
            }
            Ok(self.lineage.clone())
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(self.peak)
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            *self.timestamp_reads.lock().unwrap() += 1;
            if self.unsupported_lineage_and_timestamp {
                return Err(ChainSourceError::Unsupported(
                    "block timestamps are not indexed by the light-client source",
                ));
            }
            Ok(self.timestamp)
        }
    }

    /// A chia-peer stand-in: `Custom` kind at priority 20, peak + coin observability, but
    /// `Unsupported` for lineage/timestamp — exactly chia-peer 0.1.3's `ChiaPeerProvider` contract.
    fn light_client_stand_in(peak: u32, coin: Option<CoinRecord>) -> CustomProvider<FakeSource> {
        CustomProvider::new(
            "chia-peer",
            chia_peer::DEFAULT_PROVIDER_PRIORITY,
            FakeSource {
                peak: Some(peak),
                coin,
                unsupported_lineage_and_timestamp: true,
                ..Default::default()
            },
        )
    }

    /// A coinset stand-in that DOES answer lineage + timestamp, registered at a higher (later) number.
    fn coinset_stand_in(lineage: SingletonLineage, timestamp: u64) -> CoinsetProvider<FakeSource> {
        CoinsetProvider::new(
            "coinset.org",
            40,
            FakeSource {
                lineage: Some(lineage),
                timestamp: Some(timestamp),
                ..Default::default()
            },
        )
    }

    #[test]
    fn chia_peer_default_priority_is_twenty_1314() {
        // The seam registers at chia-peer's own priority; the lock pins it to 20.
        assert_eq!(chia_peer::DEFAULT_PROVIDER_PRIORITY, 20);
    }

    #[test]
    fn register_light_client_provider_uses_priority_twenty_1314() {
        let id = coin_id(0x01);
        let registry = register_light_client_provider(
            ProviderRegistry::new(),
            Box::new(light_client_stand_in(1_000, Some(record(id, 999)))),
        );
        // With only the priority-20 chia-peer provider registered, discovery answers from it.
        assert_eq!(registry.any().peak_height().unwrap(), Some(1_000));
    }

    #[test]
    fn light_client_provider_serves_peak_and_coin_observability_1314() {
        let id = coin_id(0x02);
        let registry = register_light_client_provider(
            ProviderRegistry::new(),
            Box::new(light_client_stand_in(2_000, Some(record(id, 1_990)))),
        );
        assert_eq!(registry.any().peak_height().unwrap(), Some(2_000));
        assert_eq!(
            registry
                .any()
                .coin_record(id)
                .unwrap()
                .unwrap()
                .confirmed_height,
            Some(1_990)
        );
    }

    #[test]
    fn lineage_and_timestamp_fall_through_to_coinset_1314() {
        let launcher = Bytes32::new([0x77; 32]);
        let lineage = SingletonLineage::single(launcher);
        // chia-peer registered FIRST (priority 20), coinset SECOND (priority 40).
        let registry = register_light_client_provider(
            ProviderRegistry::new(),
            Box::new(light_client_stand_in(3_000, None)),
        )
        .register(
            Box::new(coinset_stand_in(lineage.clone(), 1_700)),
            None,
            "coinset.org",
        );

        // chia-peer returns Unsupported for both → the registry falls through to coinset.
        assert_eq!(
            registry.any().resolve_singleton_lineage(launcher).unwrap(),
            Some(lineage)
        );
        assert_eq!(registry.any().block_timestamp(100).unwrap(), Some(1_700));
        // ...while peak observability is still answered by the priority-20 light client.
        assert_eq!(registry.any().peak_height().unwrap(), Some(3_000));
    }

    #[test]
    fn confirmation_depth_saturates_at_peak_1314() {
        assert_eq!(confirmation_depth(1_000, 900), 100);
        // Coin reported AT the peak → 0 confirmations, never underflow.
        assert_eq!(confirmation_depth(1_000, 1_000), 0);
        // Coin reported ABOVE the peak (one-block lag window) → clamps to 0, never ~4.29e9.
        assert_eq!(confirmation_depth(1_000, 1_001), 0);
    }

    #[test]
    fn empty_subscription_set_is_a_noop_1314() {
        let subs = ChiaPeerSubscriptions::default();
        assert!(subs.is_empty());
    }

    #[test]
    fn subscription_set_reports_non_empty_1314() {
        let subs = ChiaPeerSubscriptions {
            coins: vec![coin_id(0x03)],
            puzzle_hashes: vec![],
        };
        assert!(!subs.is_empty());
    }
}
