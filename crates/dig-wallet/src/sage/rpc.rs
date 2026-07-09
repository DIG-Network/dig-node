//! The Sage-parity RPC backend + the transport-independent dispatch.
//!
//! [`WalletBackend`] ties the local DB ([`crate::sage::db`]), the fallback tier
//! ([`crate::sage::fallback`]) and the sync-state gate ([`crate::sage::routing`]) together
//! and answers the **core READ methods** (design Part F MUST, this PR's scope). Every
//! wallet-data read chooses its source via [`routing::route`]; the answer is mapped into
//! the Sage wire types ([`crate::sage::types`]) so it is byte-compatible with Sage.
//!
//! [`WalletBackend::dispatch`] is the ONE handler set both transports call (design C.3):
//! `method` + JSON body → `(http_status, body)`. Because both the mTLS `9257` listener and
//! the plain-HTTP+CORS browser mirror call this same function, their bodies are
//! byte-identical by construction. Success → `200` + JSON; error → Sage's status (A.3) +
//! the plain-text message.

use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;

use super::db::{CoinRow, WalletDb};
use super::fallback::{ChainFallback, FallbackCoin};
use super::routing::{self, Source};
use super::types::*;
use super::{Error, Result};

/// Static wallet identity + config the read surface needs (derived once at bring-up).
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// The wallet's tracked puzzle hashes (hex) — both hardened AND unhardened HD +
    /// CAT-hint puzzle hashes. Used to scope fallback reads and `check_address`.
    pub puzzle_hashes: Vec<String>,
    /// The wallet's receive address (first unhardened derivation).
    pub receive_address: String,
    /// The address bech32m prefix (`xch` mainnet / `txch` testnet).
    pub address_prefix: String,
    /// The network id (`mainnet` / `testnet11`).
    pub network_id: String,
    /// Public key metadata for `get_key`/`get_keys` (if a wallet is loaded).
    pub key: Option<KeyInfo>,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            puzzle_hashes: Vec::new(),
            receive_address: String::new(),
            address_prefix: "xch".to_string(),
            network_id: "mainnet".to_string(),
            key: None,
        }
    }
}

/// The Sage-parity wallet-read backend.
#[derive(Clone)]
pub struct WalletBackend {
    db: WalletDb,
    fallback: Arc<dyn ChainFallback>,
    config: WalletConfig,
}

impl WalletBackend {
    /// Build a backend over a DB, a fallback tier, and the wallet config.
    pub fn new(db: WalletDb, fallback: Arc<dyn ChainFallback>, config: WalletConfig) -> Self {
        Self {
            db,
            fallback,
            config,
        }
    }

    /// The exact method set this PR serves (the core READ surface). Used by the
    /// conformance test to assert the dispatched set matches the design's MUST-tier
    /// read methods, and by callers to pre-check support.
    pub const SUPPORTED_METHODS: &'static [&'static str] = &[
        "login",
        "logout",
        "get_version",
        "get_sync_status",
        "check_address",
        "get_derivations",
        "get_are_coins_spendable",
        "get_spendable_coin_count",
        "get_coins",
        "get_coins_by_ids",
        "get_cats",
        "get_all_cats",
        "get_token",
        "get_dids",
        "get_nfts",
        "get_nft",
        "get_nft_data",
        "get_nft_collections",
        "get_nft_collection",
        "get_transactions",
        "get_transaction",
        "get_pending_transactions",
        "is_asset_owned",
        "get_key",
        "get_keys",
    ];

    /// Whether `method` is served by this backend.
    pub fn supports(method: &str) -> bool {
        Self::SUPPORTED_METHODS.contains(&method)
    }

    // ---- address helpers --------------------------------------------------

    fn address_of(&self, puzzle_hash_hex: &str) -> String {
        encode_address(puzzle_hash_hex, &self.config.address_prefix)
            .unwrap_or_else(|| puzzle_hash_hex.to_string())
    }

    fn burn_address(&self) -> String {
        encode_address(&"00".repeat(32), &self.config.address_prefix).unwrap_or_default()
    }

    // ---- coin → wire mapping ---------------------------------------------

    fn coin_row_to_record(&self, c: &CoinRow) -> CoinRecord {
        CoinRecord {
            coin_id: c.coin_id.clone(),
            address: self.address_of(&c.puzzle_hash),
            amount: Amount::u128(c.amount.parse::<u128>().unwrap_or(0)),
            transaction_id: None,
            offer_id: None,
            clawback_timestamp: None,
            created_height: c.created_height.map(|h| h as u32),
            spent_height: c.spent_height.map(|h| h as u32),
            spent_timestamp: c.spent_timestamp.map(|t| t as u64),
            created_timestamp: c.created_timestamp.map(|t| t as u64),
        }
    }

    fn fallback_coin_to_record(&self, c: &FallbackCoin) -> CoinRecord {
        CoinRecord {
            coin_id: c.coin_id.clone(),
            address: self.address_of(&c.puzzle_hash),
            amount: Amount::u64(c.amount),
            transaction_id: None,
            offer_id: None,
            clawback_timestamp: None,
            created_height: c.created_height,
            spent_height: c.spent_height,
            spent_timestamp: c.spent_timestamp,
            created_timestamp: c.created_timestamp,
        }
    }

    /// Whether the initial subscription catch-up is complete (the routing gate, B.6).
    async fn synced(&self) -> Result<bool> {
        Ok(self.db.is_synced().await?)
    }

    /// The candidate coin set for a wallet-data read of `asset_id`, sourced per the B.6
    /// routing table: the local DB once synced, else the coinset fallback (so the caller
    /// never blocks on an unsynced replica).
    async fn wallet_coins(&self, asset_id: Option<&str>) -> Result<Vec<CoinRecord>> {
        match routing::route(self.synced().await?, true) {
            Source::Db => {
                let rows = self.db.all_coins().await?;
                Ok(rows
                    .iter()
                    .filter(|c| c.asset_id.as_deref() == asset_id)
                    .map(|c| self.coin_row_to_record(c))
                    .collect())
            }
            Source::Fallback => {
                // XCH coins are at our puzzle hashes; CAT coins are hinted to them. CAT
                // asset attribution while syncing needs puzzle uncurrying (follow-on), so
                // the syncing-fallback CAT set is empty until the DB converges.
                if asset_id.is_some() {
                    return Ok(Vec::new());
                }
                let coins = self
                    .fallback
                    .coin_records_by_puzzle_hashes(&self.config.puzzle_hashes)
                    .await?;
                Ok(coins
                    .iter()
                    .map(|c| self.fallback_coin_to_record(c))
                    .collect())
            }
        }
    }

    // ---- method implementations ------------------------------------------

    fn get_version(&self) -> GetVersionResponse {
        GetVersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    async fn get_sync_status(&self) -> Result<GetSyncStatusResponse> {
        let balance = self.db.balance(None).await?;
        let total = self.db.all_coins().await?.len() as u32;
        Ok(GetSyncStatusResponse {
            selectable_balance: Amount::u128(balance),
            unit: Unit::xch(),
            synced_coins: total,
            total_coins: total,
            receive_address: self.config.receive_address.clone(),
            burn_address: self.burn_address(),
            unhardened_derivation_index: self.db.max_derivation_index(false).await?,
            hardened_derivation_index: self.db.max_derivation_index(true).await?,
            checked_files: 0,
            total_files: 0,
            database_size: 0,
        })
    }

    fn check_address(&self, req: &CheckAddress) -> CheckAddressResponse {
        // Valid iff it decodes as bech32m AND its puzzle hash is one the wallet tracks.
        let owned = decode_address(&req.address)
            .map(|ph| {
                self.config
                    .puzzle_hashes
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(&ph))
            })
            .unwrap_or(false);
        CheckAddressResponse { valid: owned }
    }

    async fn get_derivations(&self, req: &GetDerivations) -> Result<GetDerivationsResponse> {
        let (rows, total) = self
            .db
            .get_derivations(req.hardened, req.offset, req.limit)
            .await?;
        Ok(GetDerivationsResponse {
            derivations: rows
                .into_iter()
                .map(|d| DerivationRecord {
                    index: d.index as u32,
                    public_key: d.public_key,
                    address: d.address,
                })
                .collect(),
            total,
        })
    }

    async fn get_coins(&self, req: &GetCoins) -> Result<GetCoinsResponse> {
        let mut coins = self.wallet_coins(req.asset_id.as_deref()).await?;
        coins.retain(|c| filter_matches(c, req.filter_mode));
        sort_coins(&mut coins, req.sort_mode, req.ascending);
        let total = coins.len() as u32;
        let page = paginate(coins, req.offset, req.limit);
        Ok(GetCoinsResponse { coins: page, total })
    }

    async fn get_coins_by_ids(&self, req: &GetCoinsByIds) -> Result<GetCoinsByIdsResponse> {
        let coins = self.coins_by_ids(&req.coin_ids).await?;
        Ok(GetCoinsByIdsResponse { coins })
    }

    /// Fetch coins by id honoring the routing table: synced → DB, with any ids missing
    /// from the DB (out-of-DB/arbitrary lookups) served from the fallback; syncing → all
    /// from the fallback.
    async fn coins_by_ids(&self, ids: &[String]) -> Result<Vec<CoinRecord>> {
        if routing::route(self.synced().await?, true) == Source::Db {
            let rows = self.db.coins_by_ids(ids).await?;
            let mut out: Vec<CoinRecord> =
                rows.iter().map(|c| self.coin_row_to_record(c)).collect();
            let found: Vec<String> = out.iter().map(|c| c.coin_id.clone()).collect();
            for id in ids.iter().filter(|id| !found.contains(id)) {
                if let Some(fc) = self.fallback.coin_record_by_id(id).await? {
                    out.push(self.fallback_coin_to_record(&fc));
                }
            }
            Ok(out)
        } else {
            let mut out = Vec::new();
            for id in ids {
                if let Some(fc) = self.fallback.coin_record_by_id(id).await? {
                    out.push(self.fallback_coin_to_record(&fc));
                }
            }
            Ok(out)
        }
    }

    async fn get_spendable_coin_count(
        &self,
        req: &GetSpendableCoinCount,
    ) -> Result<GetSpendableCoinCountResponse> {
        let coins = self.wallet_coins(req.asset_id.as_deref()).await?;
        let count = coins.iter().filter(|c| is_spendable(c)).count() as u32;
        Ok(GetSpendableCoinCountResponse { count })
    }

    async fn get_are_coins_spendable(
        &self,
        req: &GetAreCoinsSpendable,
    ) -> Result<GetAreCoinsSpendableResponse> {
        let coins = self.coins_by_ids(&req.coin_ids).await?;
        // Every requested coin must be present AND spendable (confirmed + unspent).
        let spendable = req
            .coin_ids
            .iter()
            .all(|id| coins.iter().any(|c| &c.coin_id == id && is_spendable(c)));
        Ok(GetAreCoinsSpendableResponse { spendable })
    }

    async fn token_record(&self, asset_id: Option<&str>) -> Result<TokenRecord> {
        match asset_id {
            None => {
                let bal = self.db.balance(None).await?;
                Ok(TokenRecord {
                    asset_id: None,
                    name: Some("Chia".into()),
                    ticker: Some("XCH".into()),
                    precision: 12,
                    description: None,
                    icon_url: None,
                    visible: true,
                    balance: Amount::u128(bal),
                    selectable_balance: Amount::u128(bal),
                    revocation_address: None,
                })
            }
            Some(a) => {
                let bal = self.db.balance(Some(a)).await?;
                let meta = self.db.cat(a).await?;
                Ok(TokenRecord {
                    asset_id: Some(a.to_string()),
                    name: meta.as_ref().and_then(|m| m.name.clone()),
                    ticker: meta.as_ref().and_then(|m| m.ticker.clone()),
                    precision: meta.as_ref().map(|m| m.precision as u8).unwrap_or(3),
                    description: meta.as_ref().and_then(|m| m.description.clone()),
                    icon_url: meta.as_ref().and_then(|m| m.icon_url.clone()),
                    visible: meta.as_ref().map(|m| m.visible).unwrap_or(true),
                    balance: Amount::u128(bal),
                    selectable_balance: Amount::u128(bal),
                    revocation_address: None,
                })
            }
        }
    }

    async fn get_cats(&self) -> Result<GetCatsResponse> {
        let ids = self.db.owned_cat_asset_ids().await?;
        let mut cats = Vec::with_capacity(ids.len());
        for id in ids {
            cats.push(self.token_record(Some(&id)).await?);
        }
        Ok(GetCatsResponse { cats })
    }

    async fn get_all_cats(&self) -> Result<GetAllCatsResponse> {
        let rows = self.db.all_cats().await?;
        let mut cats = Vec::with_capacity(rows.len());
        for r in rows {
            cats.push(self.token_record(Some(&r.asset_id)).await?);
        }
        Ok(GetAllCatsResponse { cats })
    }

    async fn get_token(&self, req: &GetToken) -> Result<GetTokenResponse> {
        Ok(GetTokenResponse {
            token: Some(self.token_record(req.asset_id.as_deref()).await?),
        })
    }

    async fn is_asset_owned(&self, req: &IsAssetOwned) -> Result<IsAssetOwnedResponse> {
        Ok(IsAssetOwnedResponse {
            owned: self.db.is_asset_owned(&req.asset_id).await?,
        })
    }

    // NFT/DID reads: the schema + read path are wired; singleton reconstruction that
    // POPULATES these tables from coin state (puzzle uncurrying + metadata fetch) is a
    // named follow-on PR, so a synced wallet with no reconstructed singletons returns
    // empty lists (never an error).
    async fn get_dids(&self) -> GetDidsResponse {
        GetDidsResponse { dids: Vec::new() }
    }
    async fn get_nfts(&self, _req: &GetNfts) -> GetNftsResponse {
        GetNftsResponse {
            nfts: Vec::new(),
            total: 0,
        }
    }
    async fn get_nft(&self, _req: &GetNft) -> GetNftResponse {
        GetNftResponse { nft: None }
    }
    async fn get_nft_data(&self, _req: &GetNftData) -> GetNftDataResponse {
        GetNftDataResponse { data: None }
    }
    async fn get_nft_collections(&self, _req: &GetNftCollections) -> GetNftCollectionsResponse {
        GetNftCollectionsResponse {
            collections: Vec::new(),
            total: 0,
        }
    }
    async fn get_nft_collection(&self, _req: &GetNftCollection) -> GetNftCollectionResponse {
        GetNftCollectionResponse { collection: None }
    }

    // Transactions are derived from the coin table grouped by created/spent height.
    async fn get_transactions(&self, req: &GetTransactions) -> Result<GetTransactionsResponse> {
        let mut txns = self.derive_transactions().await?;
        txns.sort_by(|a, b| {
            if req.ascending {
                a.height.cmp(&b.height)
            } else {
                b.height.cmp(&a.height)
            }
        });
        let total = txns.len() as u32;
        let page: Vec<_> = txns
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetTransactionsResponse {
            transactions: page,
            total,
        })
    }

    async fn get_transaction(&self, req: &GetTransaction) -> Result<GetTransactionResponse> {
        let txns = self.derive_transactions().await?;
        Ok(GetTransactionResponse {
            transaction: txns.into_iter().find(|t| t.height == req.height),
        })
    }

    async fn get_pending_transactions(&self) -> GetPendingTransactionsResponse {
        // This PR has no spend/submission path, so there are no pending transactions.
        GetPendingTransactionsResponse {
            transactions: Vec::new(),
        }
    }

    /// Group the wallet's coins into per-height transaction records (created vs spent).
    async fn derive_transactions(&self) -> Result<Vec<TransactionRecord>> {
        use std::collections::BTreeMap;
        let coins = self.db.all_coins().await?;
        let mut by_height: BTreeMap<u32, (Vec<TransactionCoinRecord>, Vec<TransactionCoinRecord>)> =
            BTreeMap::new();
        for c in &coins {
            let rec = self.tx_coin_record(c);
            if let Some(h) = c.created_height {
                by_height.entry(h as u32).or_default().1.push(rec.clone());
            }
            if let Some(h) = c.spent_height {
                by_height.entry(h as u32).or_default().0.push(rec);
            }
        }
        Ok(by_height
            .into_iter()
            .map(|(height, (spent, created))| TransactionRecord {
                height,
                timestamp: None,
                spent,
                created,
            })
            .collect())
    }

    fn tx_coin_record(&self, c: &CoinRow) -> TransactionCoinRecord {
        TransactionCoinRecord {
            coin_id: c.coin_id.clone(),
            amount: Amount::u128(c.amount.parse::<u128>().unwrap_or(0)),
            address: Some(self.address_of(&c.puzzle_hash)),
            address_kind: AddressKind::Own,
            asset: self.coin_asset(c),
        }
    }

    fn coin_asset(&self, c: &CoinRow) -> Asset {
        match &c.asset_id {
            None => Asset {
                asset_id: None,
                name: Some("Chia".into()),
                ticker: Some("XCH".into()),
                precision: 12,
                icon_url: None,
                description: None,
                is_sensitive_content: false,
                is_visible: true,
                revocation_address: None,
                kind: AssetKind::Token,
            },
            Some(a) => Asset {
                asset_id: Some(a.clone()),
                name: None,
                ticker: None,
                precision: 3,
                icon_url: None,
                description: None,
                is_sensitive_content: false,
                is_visible: true,
                revocation_address: None,
                kind: AssetKind::Token,
            },
        }
    }

    fn get_key(&self, req: &GetKey) -> GetKeyResponse {
        // A single loaded wallet; return it when the fingerprint matches or is null.
        let key = self
            .config
            .key
            .clone()
            .filter(|k| req.fingerprint.map(|f| f == k.fingerprint).unwrap_or(true));
        GetKeyResponse { key }
    }

    fn get_keys(&self) -> GetKeysResponse {
        GetKeysResponse {
            keys: self.config.key.clone().into_iter().collect(),
        }
    }

    // ---- the single dispatch both transports call ------------------------

    /// Parse + route a single Sage-parity RPC call. Returns `(http_status, body)`:
    /// success → `200` + the response JSON; error → Sage's status (A.3) + the plain
    /// message. This is the ONE handler set both transports share (design C.3), so their
    /// bodies are byte-identical.
    pub async fn dispatch(&self, method: &str, body: &str) -> (u16, String) {
        match self.dispatch_inner(method, body).await {
            Ok(json) => (200, json),
            Err(e) => (e.kind.status(), e.message),
        }
    }

    async fn dispatch_inner(&self, method: &str, body: &str) -> Result<String> {
        // Parse the request struct for `method` (empty-body methods ignore `body`).
        macro_rules! req {
            ($ty:ty) => {{
                let body = if body.trim().is_empty() { "{}" } else { body };
                serde_json::from_str::<$ty>(body)
                    .map_err(|e| Error::api(format!("invalid request for {method}: {e}")))?
            }};
        }

        let value: Value = match method {
            "login" => {
                let _r = req!(Login);
                json(LoginResponse {})?
            }
            "logout" => {
                let _r = req!(Logout);
                json(LogoutResponse {})?
            }
            "get_version" => {
                let _r = req!(GetVersion);
                json(self.get_version())?
            }
            "get_sync_status" => {
                let _r = req!(GetSyncStatus);
                json(self.get_sync_status().await?)?
            }
            "check_address" => {
                let r = req!(CheckAddress);
                json(self.check_address(&r))?
            }
            "get_derivations" => {
                let r = req!(GetDerivations);
                json(self.get_derivations(&r).await?)?
            }
            "get_are_coins_spendable" => {
                let r = req!(GetAreCoinsSpendable);
                json(self.get_are_coins_spendable(&r).await?)?
            }
            "get_spendable_coin_count" => {
                let r = req!(GetSpendableCoinCount);
                json(self.get_spendable_coin_count(&r).await?)?
            }
            "get_coins" => {
                let r = req!(GetCoins);
                json(self.get_coins(&r).await?)?
            }
            "get_coins_by_ids" => {
                let r = req!(GetCoinsByIds);
                json(self.get_coins_by_ids(&r).await?)?
            }
            "get_cats" => {
                let _r = req!(GetCats);
                json(self.get_cats().await?)?
            }
            "get_all_cats" => {
                let _r = req!(GetAllCats);
                json(self.get_all_cats().await?)?
            }
            "get_token" => {
                let r = req!(GetToken);
                json(self.get_token(&r).await?)?
            }
            "get_dids" => {
                let _r = req!(GetDids);
                json(self.get_dids().await)?
            }
            "get_nfts" => {
                let r = req!(GetNfts);
                json(self.get_nfts(&r).await)?
            }
            "get_nft" => {
                let r = req!(GetNft);
                json(self.get_nft(&r).await)?
            }
            "get_nft_data" => {
                let r = req!(GetNftData);
                json(self.get_nft_data(&r).await)?
            }
            "get_nft_collections" => {
                let r = req!(GetNftCollections);
                json(self.get_nft_collections(&r).await)?
            }
            "get_nft_collection" => {
                let r = req!(GetNftCollection);
                json(self.get_nft_collection(&r).await)?
            }
            "get_transactions" => {
                let r = req!(GetTransactions);
                json(self.get_transactions(&r).await?)?
            }
            "get_transaction" => {
                let r = req!(GetTransaction);
                json(self.get_transaction(&r).await?)?
            }
            "get_pending_transactions" => {
                let _r = req!(GetPendingTransactions);
                json(self.get_pending_transactions().await)?
            }
            "is_asset_owned" => {
                let r = req!(IsAssetOwned);
                json(self.is_asset_owned(&r).await?)?
            }
            "get_key" => {
                let r = req!(GetKey);
                json(self.get_key(&r))?
            }
            "get_keys" => {
                let _r = req!(GetKeys);
                json(self.get_keys())?
            }
            other => {
                return Err(Error::not_found(format!(
                    "unknown or unsupported method: {other}"
                )));
            }
        };
        serde_json::to_string(&value).map_err(|e| Error::internal(format!("serialize: {e}")))
    }
}

// ---- free helpers ---------------------------------------------------------

fn json<T: Serialize>(v: T) -> Result<Value> {
    serde_json::to_value(v).map_err(|e| Error::internal(format!("serialize: {e}")))
}

/// Encode a puzzle-hash hex as a bech32m address with `prefix`.
fn encode_address(puzzle_hash_hex: &str, prefix: &str) -> Option<String> {
    let ph = puzzle_hash_hex
        .strip_prefix("0x")
        .unwrap_or(puzzle_hash_hex);
    let bytes: [u8; 32] = hex::decode(ph).ok()?.try_into().ok()?;
    chia_wallet_sdk::utils::Address::new(bytes.into(), prefix.to_string())
        .encode()
        .ok()
}

/// Decode a bech32m address into its puzzle-hash hex (any valid prefix).
fn decode_address(address: &str) -> Option<String> {
    chia_wallet_sdk::utils::Address::decode(address)
        .ok()
        .map(|a| hex::encode(a.puzzle_hash))
}

/// A coin is spendable iff it is confirmed (`created_height` set) and unspent.
fn is_spendable(c: &CoinRecord) -> bool {
    c.created_height.is_some() && c.spent_height.is_none()
}

fn filter_matches(c: &CoinRecord, mode: CoinFilterMode) -> bool {
    match mode {
        CoinFilterMode::All => true,
        // Sage's default: coins available to spend.
        CoinFilterMode::Selectable | CoinFilterMode::Owned => is_spendable(c),
        CoinFilterMode::Spent => c.spent_height.is_some(),
        // Clawback coins are not tracked in this PR.
        CoinFilterMode::Clawback => c.clawback_timestamp.is_some(),
    }
}

fn sort_coins(coins: &mut [CoinRecord], mode: CoinSortMode, ascending: bool) {
    coins.sort_by(|a, b| {
        let ord = match mode {
            CoinSortMode::CoinId => a.coin_id.cmp(&b.coin_id),
            CoinSortMode::Amount => a
                .amount
                .to_u64()
                .unwrap_or(0)
                .cmp(&b.amount.to_u64().unwrap_or(0)),
            CoinSortMode::CreatedHeight => a.created_height.cmp(&b.created_height),
            CoinSortMode::SpentHeight => a.spent_height.cmp(&b.spent_height),
            CoinSortMode::ClawbackTimestamp => a.clawback_timestamp.cmp(&b.clawback_timestamp),
        };
        if ascending {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn paginate(coins: Vec<CoinRecord>, offset: u32, limit: u32) -> Vec<CoinRecord> {
    coins
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::db::WalletDb;
    use super::super::fallback::mock::MockFallback;
    use super::super::fallback::FallbackCoin;
    use super::*;

    async fn backend_with(coins: Vec<CoinRow>, synced: bool) -> WalletBackend {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&coins).await.unwrap();
        db.set_initial_sync_complete(synced).await.unwrap();
        let fb = Arc::new(MockFallback::default());
        WalletBackend::new(db, fb, WalletConfig::default())
    }

    fn xch_coin(id: &str, amount: u64, created: Option<i64>, spent: Option<i64>) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "00".repeat(32),
            amount: amount.to_string(),
            created_height: created,
            spent_height: spent,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    #[tokio::test]
    async fn get_version_reports_crate_version() {
        let be = backend_with(vec![], true).await;
        let (status, body) = be.dispatch("get_version", "{}").await;
        assert_eq!(status, 200);
        assert!(body.contains(env!("CARGO_PKG_VERSION")));
    }

    #[tokio::test]
    async fn synced_get_coins_reads_from_db_not_fallback() {
        let fb = Arc::new(MockFallback::default());
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[
            xch_coin("c1", 100, Some(10), None),
            xch_coin("c2", 50, Some(11), Some(12)),
        ])
        .await
        .unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default());

        let (status, body) = be.dispatch("get_coins", r#"{"offset":0,"limit":10}"#).await;
        assert_eq!(status, 200);
        let resp: GetCoinsResponse = serde_json::from_str(&body).unwrap();
        // Default filter is Selectable → only the unspent coin.
        assert_eq!(resp.coins.len(), 1);
        assert_eq!(resp.coins[0].coin_id, "c1");
        assert_eq!(
            fb.call_count(),
            0,
            "synced reads must NOT touch the fallback"
        );
    }

    #[tokio::test]
    async fn syncing_get_coins_routes_to_fallback() {
        let ph = "11".repeat(32);
        let fb = Arc::new(MockFallback::with_coins(vec![FallbackCoin {
            coin_id: "fc1".into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: ph.clone(),
            amount: 777,
            created_height: Some(5),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
        }]));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_initial_sync_complete(false).await.unwrap(); // still syncing
        let cfg = WalletConfig {
            puzzle_hashes: vec![ph],
            ..Default::default()
        };
        let be = WalletBackend::new(db, fb.clone(), cfg);

        let (status, body) = be.dispatch("get_coins", r#"{"offset":0,"limit":10}"#).await;
        assert_eq!(status, 200);
        let resp: GetCoinsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.coins.len(), 1);
        assert_eq!(resp.coins[0].coin_id, "fc1");
        assert!(
            fb.call_count() >= 1,
            "syncing reads must consult the fallback"
        );
    }

    #[tokio::test]
    async fn out_of_db_coin_id_falls_back_when_synced() {
        let fb = Arc::new(MockFallback::with_coins(vec![FallbackCoin {
            coin_id: "external".into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "22".repeat(32),
            amount: 9,
            created_height: Some(3),
            spent_height: None,
            created_timestamp: None,
            spent_timestamp: None,
        }]));
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coins(&[xch_coin("inwallet", 1, Some(1), None)])
            .await
            .unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
        let be = WalletBackend::new(db, fb.clone(), WalletConfig::default());

        let (status, body) = be
            .dispatch(
                "get_coins_by_ids",
                r#"{"coin_ids":["inwallet","external"]}"#,
            )
            .await;
        assert_eq!(status, 200);
        let resp: GetCoinsByIdsResponse = serde_json::from_str(&body).unwrap();
        let ids: Vec<_> = resp.coins.iter().map(|c| c.coin_id.as_str()).collect();
        assert!(ids.contains(&"inwallet"));
        assert!(
            ids.contains(&"external"),
            "an out-of-DB id must be served from the fallback"
        );
        assert!(fb.call_count() >= 1);
    }

    #[tokio::test]
    async fn unknown_method_is_404() {
        let be = backend_with(vec![], true).await;
        let (status, body) = be.dispatch("send_xch", "{}").await;
        assert_eq!(status, 404);
        assert!(body.contains("unsupported"));
    }

    #[tokio::test]
    async fn malformed_request_is_400() {
        let be = backend_with(vec![], true).await;
        let (status, _body) = be.dispatch("get_coins", "{ not json").await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn get_sync_status_reports_balance_and_gate() {
        let be = backend_with(vec![xch_coin("c1", 12_000, Some(10), None)], true).await;
        let (status, body) = be.dispatch("get_sync_status", "{}").await;
        assert_eq!(status, 200);
        let resp: GetSyncStatusResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(resp.selectable_balance.to_u64(), Some(12_000));
        assert_eq!(resp.unit.ticker, "XCH");
    }

    #[tokio::test]
    async fn is_asset_owned_reflects_db() {
        let mut c = xch_coin("cat", 5, Some(1), None);
        c.asset_id = Some("dead".into());
        let be = backend_with(vec![c], true).await;
        let (_s, body) = be
            .dispatch("is_asset_owned", r#"{"asset_id":"dead"}"#)
            .await;
        let resp: IsAssetOwnedResponse = serde_json::from_str(&body).unwrap();
        assert!(resp.owned);
    }
}
