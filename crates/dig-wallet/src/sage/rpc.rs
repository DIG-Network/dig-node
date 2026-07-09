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

use std::collections::HashSet;
use std::sync::Arc;

use chia_protocol::{Bytes32, Coin, CoinSpend, SpendBundle};
use serde::Serialize;
use serde_json::Value;

use chia_wallet_sdk::driver::Cat;

use super::db::{CoinRow, OfferDbRow, WalletDb};
use super::fallback::{ChainFallback, FallbackCoin};
use super::routing::{self, Source};
use super::singleton::{self, LineageSource, ParentSpend};
use super::spend::{self, Broadcaster, WalletSigner};
use super::types::*;
use super::{mint, offers};
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

/// The Sage-parity wallet backend.
#[derive(Clone)]
pub struct WalletBackend {
    db: WalletDb,
    fallback: Arc<dyn ChainFallback>,
    config: WalletConfig,
    /// The wallet's signing keys (node-custodied). `None` when no wallet is loaded — spend
    /// building/signing then returns an error (C.6: the extension self-custodies and never
    /// uses this path).
    signer: Option<Arc<WalletSigner>>,
    /// The network broadcaster. `None` in tests/CI so a built spend is NEVER auto-broadcast.
    broadcaster: Option<Arc<dyn Broadcaster>>,
    /// The lineage source for CAT-send input resolution (parent-spend reads).
    lineage: Option<Arc<dyn LineageSource>>,
}

impl WalletBackend {
    /// Build a read-only backend over a DB, a fallback tier, and the wallet config. Spend
    /// methods are disabled until a signer/broadcaster are attached (see [`Self::with_signer`]).
    pub fn new(db: WalletDb, fallback: Arc<dyn ChainFallback>, config: WalletConfig) -> Self {
        Self {
            db,
            fallback,
            config,
            signer: None,
            broadcaster: None,
            lineage: None,
        }
    }

    /// Attach the node-custodied signing keys (enables spend building + signing).
    pub fn with_signer(mut self, signer: Arc<WalletSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach the network broadcaster (enables `auto_submit` + `submit_transaction`).
    pub fn with_broadcaster(mut self, broadcaster: Arc<dyn Broadcaster>) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Attach the lineage source used to resolve input CAT coins for `send_cat`.
    pub fn with_lineage(mut self, lineage: Arc<dyn LineageSource>) -> Self {
        self.lineage = Some(lineage);
        self
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
        // #216 send/spend group.
        "send_xch",
        "bulk_send_xch",
        "send_cat",
        "bulk_send_cat",
        "combine",
        "split",
        "multi_send",
        "sign_coin_spends",
        "view_coin_spends",
        "submit_transaction",
        // #218 offer suite.
        "make_offer",
        "take_offer",
        "view_offer",
        "combine_offers",
        "get_offers",
        "get_offer",
        "cancel_offer",
        // #218 DID/NFT mint + transfer.
        "create_did",
        "bulk_mint_nfts",
        "transfer_nfts",
        "transfer_dids",
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

    // NFT/DID reads: served from the tables the sync reconstruction populates
    // ([`crate::sage::singleton`]). A wallet with no such assets returns an empty list.
    async fn get_dids(&self) -> Result<GetDidsResponse> {
        let rows = self.db.all_dids().await?;
        let dids = rows
            .iter()
            .filter_map(|r| serde_json::from_str::<DidRecord>(&r.record_json).ok())
            .collect();
        Ok(GetDidsResponse { dids })
    }

    async fn get_nfts(&self, req: &GetNfts) -> Result<GetNftsResponse> {
        let rows = self.db.all_nfts().await?;
        let matches = |r: &super::db::NftDbRow| -> bool {
            let coll_ok = match &req.collection_id {
                Some(c) => r.collection_id.as_deref() == Some(c.as_str()),
                None => true,
            };
            let minter_ok = match &req.minter_did_id {
                Some(m) => r.minter_did.as_deref() == Some(m.as_str()),
                None => true,
            };
            let owner_ok = match &req.owner_did_id {
                Some(o) => r.owner_did.as_deref() == Some(o.as_str()),
                None => true,
            };
            let name_ok = match &req.name {
                Some(n) => r
                    .name
                    .as_deref()
                    .map(|rn| rn.contains(n.as_str()))
                    .unwrap_or(false),
                None => true,
            };
            coll_ok && minter_ok && owner_ok && name_ok
        };
        let mut nfts: Vec<NftRecord> = rows
            .iter()
            .filter(|r| req.include_hidden || r.visible)
            .filter(|r| matches(r))
            .filter_map(|r| serde_json::from_str::<NftRecord>(&r.record_json).ok())
            .collect();
        match req.sort_mode {
            NftSortMode::Name => nfts.sort_by(|a, b| a.name.cmp(&b.name)),
            NftSortMode::Recent => nfts.sort_by_key(|n| std::cmp::Reverse(n.created_height)),
        }
        let total = nfts.len() as u32;
        let page = nfts
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetNftsResponse { nfts: page, total })
    }

    async fn get_nft(&self, req: &GetNft) -> Result<GetNftResponse> {
        let launcher = normalize_singleton_id(&req.nft_id);
        let nft = self
            .db
            .nft(&launcher)
            .await?
            .and_then(|r| serde_json::from_str::<NftRecord>(&r.record_json).ok());
        Ok(GetNftResponse { nft })
    }

    async fn get_nft_data(&self, req: &GetNftData) -> Result<GetNftDataResponse> {
        let launcher = normalize_singleton_id(&req.nft_id);
        let Some(_row) = self.db.nft(&launcher).await? else {
            return Ok(GetNftDataResponse { data: None });
        };
        // The off-chain data blob + CHIP-0015 metadata JSON are fetched opportunistically; a
        // synced wallet always knows the on-chain URIs/hashes (in the NftRecord). When the
        // metadata JSON has been fetched, surface it; the raw blob fetch is a follow-on.
        let metadata_json = self.db.nft_metadata_json(&launcher).await?;
        Ok(GetNftDataResponse {
            data: Some(NftData {
                blob: None,
                mime_type: None,
                hash_matches: false,
                metadata_hash_matches: metadata_json.is_some(),
                metadata_json,
            }),
        })
    }

    async fn get_nft_collections(
        &self,
        req: &GetNftCollections,
    ) -> Result<GetNftCollectionsResponse> {
        let rows = self.db.all_nft_collections().await?;
        let all: Vec<NftCollectionRecord> = rows
            .iter()
            .filter(|r| req.include_hidden || r.visible)
            .filter_map(|r| serde_json::from_str::<NftCollectionRecord>(&r.record_json).ok())
            .collect();
        let total = all.len() as u32;
        let collections = all
            .into_iter()
            .skip(req.offset as usize)
            .take(req.limit as usize)
            .collect();
        Ok(GetNftCollectionsResponse { collections, total })
    }

    async fn get_nft_collection(&self, req: &GetNftCollection) -> Result<GetNftCollectionResponse> {
        let collection = match &req.collection_id {
            Some(id) => self
                .db
                .nft_collection(id)
                .await?
                .and_then(|r| serde_json::from_str::<NftCollectionRecord>(&r.record_json).ok()),
            None => None,
        };
        Ok(GetNftCollectionResponse { collection })
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

    // ---- send/spend method group (#216) ----------------------------------

    /// The wallet's tracked p2 puzzle hashes (for summary "receiving" flags).
    fn wallet_puzzle_hashes(&self) -> HashSet<Bytes32> {
        if let Some(s) = &self.signer {
            return s.puzzle_hashes();
        }
        self.config
            .puzzle_hashes
            .iter()
            .filter_map(|h| singleton::bytes32_from_hex(h).ok())
            .collect()
    }

    /// The signer, or a locked-wallet error (C.6: spends need node-custodied keys).
    fn require_signer(&self) -> Result<&WalletSigner> {
        self.signer
            .as_deref()
            .ok_or_else(|| Error::internal("wallet is locked: no signing key available"))
    }

    /// The change puzzle hash (the wallet's first receive address).
    fn change_ph(&self) -> Result<Bytes32> {
        if let Some(ph) = self.signer.as_ref().and_then(|s| s.change_puzzle_hash()) {
            return Ok(ph);
        }
        match self.config.puzzle_hashes.first() {
            Some(h) => singleton::bytes32_from_hex(h),
            None => Err(Error::internal("no change address available")),
        }
    }

    /// Decode a destination address to its puzzle hash.
    fn decode_ph(&self, address: &str) -> Result<Bytes32> {
        let hex = decode_address(address)
            .ok_or_else(|| Error::api(format!("invalid address: {address}")))?;
        singleton::bytes32_from_hex(&hex)
    }

    /// The spendable coins for an asset (`None` = XCH), as `chia_protocol::Coin`s.
    async fn spendable_coins(&self, asset_id: Option<&str>) -> Result<Vec<Coin>> {
        let rows = self.db.unspent_coins(asset_id).await?;
        rows.iter().map(singleton::coin_from_row).collect()
    }

    /// Fetch specific coins by id (all must exist), as `chia_protocol::Coin`s.
    async fn coins_from_ids(&self, ids: &[String]) -> Result<Vec<Coin>> {
        let rows = self.db.coins_by_ids(ids).await?;
        if rows.len() != ids.len() {
            return Err(Error::not_found(
                "one or more coins not found in the wallet",
            ));
        }
        rows.iter().map(singleton::coin_from_row).collect()
    }

    /// Validate (dig-clvm), summarize, optionally sign+broadcast (only when a broadcaster is
    /// attached — NEVER in CI), and return the Sage `TransactionResponse`.
    async fn finalize_spend(
        &self,
        coin_spends: Vec<CoinSpend>,
        auto_submit: bool,
    ) -> Result<TransactionResponse> {
        spend::run_and_validate(&coin_spends)?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if auto_submit {
            if let (Some(signer), Some(bc)) = (self.signer.as_ref(), self.broadcaster.as_ref()) {
                let sig = signer.sign(&coin_spends)?;
                bc.broadcast(&SpendBundle::new(coin_spends.clone(), sig))
                    .await?;
            }
        }
        let coin_spends_json = coin_spends
            .iter()
            .map(spend::coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(TransactionResponse {
            summary,
            coin_spends: coin_spends_json,
        })
    }

    async fn send_xch(&self, req: &SendXch) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let inputs = spend::select_coins(
            self.spendable_coins(None).await?,
            amount.saturating_add(fee),
        )?;
        let coin_spends =
            spend::build_xch_send(signer, &inputs, dest, amount, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_send_xch(&self, req: &BulkSendXch) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dests = req
            .addresses
            .iter()
            .map(|a| self.decode_ph(a))
            .collect::<Result<Vec<_>>>()?;
        let target = amount
            .saturating_mul(dests.len() as u64)
            .saturating_add(fee);
        let inputs = spend::select_coins(self.spendable_coins(None).await?, target)?;
        let coin_spends =
            spend::build_bulk_xch_send(signer, &inputs, &dests, amount, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn combine(&self, req: &Combine) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let inputs = self.coins_from_ids(&req.coin_ids).await?;
        let coin_spends = spend::build_combine(signer, &inputs, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn split(&self, req: &Split) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let inputs = self.coins_from_ids(&req.coin_ids).await?;
        let coin_spends =
            spend::build_split(signer, &inputs, req.output_count, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn multi_send(&self, req: &MultiSend) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let mut payments = Vec::with_capacity(req.payments.len());
        for p in &req.payments {
            if p.asset_id.is_some() {
                return Err(Error::api(
                    "CAT payments in multi_send are not yet supported (use send_cat)",
                ));
            }
            payments.push(spend::MultiPayment {
                dest: self.decode_ph(&p.address)?,
                amount: amount_u64(&p.amount)?,
            });
        }
        let target = payments
            .iter()
            .map(|p| p.amount)
            .fold(0u64, u64::saturating_add)
            .saturating_add(fee);
        let inputs = spend::select_coins(self.spendable_coins(None).await?, target)?;
        let coin_spends =
            spend::build_multi_send(signer, &inputs, &payments, fee, self.change_ph()?)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    /// Resolve the spendable input `Cat`s covering `amount` of `asset_id`, and the XCH fee
    /// coins covering `fee`, via the attached lineage source.
    async fn select_cats(
        &self,
        asset_id: &str,
        amount: u64,
        fee: u64,
    ) -> Result<(Vec<chia_wallet_sdk::driver::Cat>, Vec<Coin>)> {
        let lineage = self
            .lineage
            .as_deref()
            .ok_or_else(|| Error::internal("CAT send requires a lineage source"))?;
        let rows = select_cat_rows(self.db.unspent_coins(Some(asset_id)).await?, amount)?;
        let mut cats = Vec::with_capacity(rows.len());
        for row in &rows {
            let created = row
                .created_height
                .ok_or_else(|| Error::internal("CAT coin missing created height"))?
                as u32;
            let parent = lineage
                .parent_spend(&row.parent_coin_info, created)
                .await?
                .ok_or_else(|| Error::internal("CAT parent spend unavailable"))?;
            let child = singleton::coin_from_row(row)?;
            let cat = singleton::resolve_cat(&parent, child)?
                .ok_or_else(|| Error::internal("could not resolve CAT lineage"))?;
            cats.push(cat);
        }
        let xch_fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        Ok((cats, xch_fee_coins))
    }

    async fn send_cat(&self, req: &SendCat) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let (cats, xch_fee_coins) = self.select_cats(&req.asset_id, amount, fee).await?;
        let coin_spends = spend::build_cat_send(
            signer,
            &cats,
            dest,
            amount,
            self.change_ph()?,
            req.include_hint,
            fee,
            &xch_fee_coins,
        )?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_send_cat(&self, req: &BulkSendCat) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let amount = amount_u64(&req.amount)?;
        let fee = amount_u64(&req.fee)?;
        let outputs = req
            .addresses
            .iter()
            .map(|a| self.decode_ph(a).map(|ph| (ph, amount)))
            .collect::<Result<Vec<_>>>()?;
        let total = amount.saturating_mul(req.addresses.len() as u64);
        let (cats, xch_fee_coins) = self.select_cats(&req.asset_id, total, fee).await?;
        let coin_spends = spend::build_cat_send_multi(
            signer,
            &cats,
            &outputs,
            self.change_ph()?,
            req.include_hint,
            fee,
            &xch_fee_coins,
        )?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn sign_coin_spends(&self, req: &SignCoinSpends) -> Result<SignCoinSpendsResponse> {
        let signer = self.require_signer()?;
        let coin_spends = req
            .coin_spends
            .iter()
            .map(spend::coin_spend_from_json)
            .collect::<Result<Vec<_>>>()?;
        let signature = signer.sign(&coin_spends)?;
        let bundle = SpendBundle::new(coin_spends, signature);
        if req.auto_submit {
            if let Some(bc) = self.broadcaster.as_ref() {
                bc.broadcast(&bundle).await?;
            }
        }
        Ok(SignCoinSpendsResponse {
            spend_bundle: spend::spend_bundle_to_json(&bundle)?,
        })
    }

    async fn view_coin_spends(&self, req: &ViewCoinSpends) -> Result<ViewCoinSpendsResponse> {
        let coin_spends = req
            .coin_spends
            .iter()
            .map(spend::coin_spend_from_json)
            .collect::<Result<Vec<_>>>()?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        Ok(ViewCoinSpendsResponse { summary })
    }

    async fn submit_transaction(
        &self,
        req: &SubmitTransaction,
    ) -> Result<SubmitTransactionResponse> {
        let bundle = spend::spend_bundle_from_json(&req.spend_bundle)?;
        // Fail-closed: structural + CLVM validation before broadcast.
        spend::run_and_validate(&bundle.coin_spends)?;
        let bc = self
            .broadcaster
            .as_ref()
            .ok_or_else(|| Error::internal("no broadcaster configured"))?;
        bc.broadcast(&bundle).await?;
        Ok(SubmitTransactionResponse {})
    }

    // ---- offer suite + DID/NFT mint & transfer (#218) --------------------

    /// The lineage source, or an error when none is attached — CAT/singleton spends need
    /// parent-spend reads to reconstruct their spendable driver objects.
    fn require_lineage(&self) -> Result<&dyn LineageSource> {
        self.lineage
            .as_deref()
            .ok_or_else(|| Error::internal("this operation requires a lineage source"))
    }

    /// Resolve a coin's parent spend + the current coin, from the wallet DB + lineage — the
    /// input a singleton (NFT/DID) spend reconstruction needs.
    async fn singleton_parent_child(&self, coin_id: &str) -> Result<(ParentSpend, Coin)> {
        let lineage = self.require_lineage()?;
        let row = self
            .db
            .coins_by_ids(&[coin_id.to_string()])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_found("coin not tracked in the wallet"))?;
        let created =
            row.created_height
                .ok_or_else(|| Error::internal("coin missing created height"))? as u32;
        let parent = lineage
            .parent_spend(&row.parent_coin_info, created)
            .await?
            .ok_or_else(|| Error::internal("parent spend unavailable"))?;
        let child = singleton::coin_from_row(&row)?;
        Ok((parent, child))
    }

    /// Resolve `nft_id` (hex/bech32m) to its current coin's (parent spend, coin).
    async fn nft_parent_child(&self, nft_id: &str) -> Result<(ParentSpend, Coin)> {
        let launcher = normalize_singleton_id(nft_id);
        let row = self
            .db
            .nft(&launcher)
            .await?
            .ok_or_else(|| Error::not_found("NFT not tracked in the wallet"))?;
        self.singleton_parent_child(&row.coin_id).await
    }

    /// Resolve `did_id` (hex/bech32m) to its current coin's (parent spend, coin).
    async fn did_parent_child(&self, did_id: &str) -> Result<(ParentSpend, Coin)> {
        let launcher = normalize_singleton_id(did_id);
        let row = self
            .db
            .all_dids()
            .await?
            .into_iter()
            .find(|d| d.launcher_id == launcher)
            .ok_or_else(|| Error::not_found("DID not tracked in the wallet"))?;
        self.singleton_parent_child(&row.coin_id).await
    }

    /// Reconstruct the spendable [`chia_wallet_sdk::driver::Did`] for `did_id` (a simple DID's
    /// metadata is `NIL`, so it is safe to hand to the mint builder's own context).
    async fn resolve_did(&self, did_id: &str) -> Result<chia_wallet_sdk::driver::Did> {
        let (parent, child) = self.did_parent_child(did_id).await?;
        let mut ctx = chia_wallet_sdk::driver::SpendContext::new();
        singleton::parse_did_in(&mut ctx, &parent, child)?
            .ok_or_else(|| Error::internal("could not reconstruct the minting DID"))
    }

    /// The spendable CAT coins of `asset_id` covering `amount` (with lineage proofs).
    async fn resolve_offer_cats(&self, asset_id: &str, amount: u64) -> Result<Vec<Cat>> {
        let (cats, _fee) = self.select_cats(asset_id, amount, 0).await?;
        Ok(cats)
    }

    async fn make_offer(&self, req: &MakeOffer) -> Result<MakeOfferResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let receive_ph = match &req.receive_address {
            Some(a) => self.decode_ph(a)?,
            None => self.change_ph()?,
        };
        let change = self.change_ph()?;

        let mut inputs = offers::OfferInputs::default();
        let mut offered_legs = Vec::with_capacity(req.offered_assets.len());
        let mut any_xch_offered = false;
        for a in &req.offered_assets {
            let amount = amount_u64(&a.amount)?;
            match &a.asset_id {
                None => any_xch_offered = true,
                Some(id) => inputs
                    .cats
                    .extend(self.resolve_offer_cats(id, amount).await?),
            }
            offered_legs.push(offers::OfferLeg {
                asset_id: opt_asset_id(&a.asset_id)?,
                amount,
            });
        }
        if any_xch_offered {
            inputs.xch = self.spendable_coins(None).await?;
        }
        let requested_legs = req
            .requested_assets
            .iter()
            .map(|a| {
                Ok(offers::OfferLeg {
                    asset_id: opt_asset_id(&a.asset_id)?,
                    amount: amount_u64(&a.amount)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let (offer_str, offer_id) = offers::build_make_offer(
            signer,
            &inputs,
            &offered_legs,
            &requested_legs,
            receive_ph,
            change,
            fee,
        )?;

        if req.auto_import {
            let summary = offers::summarize_offer(&offer_str)?;
            self.db
                .upsert_offer(&OfferDbRow {
                    offer_id: offer_id.clone(),
                    offer: offer_str.clone(),
                    status: "active".into(),
                    creation_timestamp: now_secs() as i64,
                    summary_json: serde_json::to_string(&summary).unwrap_or_default(),
                })
                .await?;
        }
        Ok(MakeOfferResponse {
            offer: offer_str,
            offer_id,
        })
    }

    async fn take_offer(&self, req: &TakeOffer) -> Result<TakeOfferResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let change = self.change_ph()?;

        // The taker pays the maker's requested assets — fund exactly those.
        let summary = offers::summarize_offer(&req.offer)?;
        let mut inputs = offers::OfferInputs::default();
        let mut need_xch = fee > 0;
        for a in &summary.taker {
            let amount = a.amount.to_u64().unwrap_or(0);
            match &a.asset.asset_id {
                None => need_xch = true,
                Some(id) => inputs
                    .cats
                    .extend(self.resolve_offer_cats(id, amount).await?),
            }
        }
        if need_xch {
            inputs.xch = self.spendable_coins(None).await?;
        }

        let bundle = offers::build_take_offer(signer, &req.offer, &inputs, change, fee)?;
        spend::run_and_validate(&bundle.coin_spends)?;
        let tx_summary = spend::summarize(
            &bundle.coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if req.auto_submit {
            if let Some(bc) = self.broadcaster.as_ref() {
                bc.broadcast(&bundle).await?;
            }
        }
        Ok(TakeOfferResponse {
            summary: tx_summary,
            spend_bundle: spend::spend_bundle_to_json(&bundle)?,
            transaction_id: offers::offer_id_of_str(&req.offer)?,
        })
    }

    fn view_offer_summary(&self, req: &ViewOffer) -> Result<OfferSummary> {
        offers::summarize_offer(&req.offer)
    }

    async fn view_offer(&self, req: &ViewOffer) -> Result<ViewOfferResponse> {
        let summary = self.view_offer_summary(req)?;
        let offer_id = offers::offer_id_of_str(&req.offer)?;
        let status = match self.db.offer(&offer_id).await? {
            Some(r) => parse_offer_status(&r.status),
            None => OfferRecordStatus::Active,
        };
        Ok(ViewOfferResponse {
            offer: summary,
            status,
        })
    }

    fn combine_offers(&self, req: &CombineOffers) -> Result<CombineOffersResponse> {
        Ok(CombineOffersResponse {
            offer: offers::combine_offers(&req.offers)?,
        })
    }

    async fn get_offers(&self) -> Result<GetOffersResponse> {
        let rows = self.db.all_offers().await?;
        Ok(GetOffersResponse {
            offers: rows.iter().filter_map(offer_row_to_record).collect(),
        })
    }

    async fn get_offer(&self, req: &GetOffer) -> Result<GetOfferResponse> {
        let row = self
            .db
            .offer(&req.offer_id)
            .await?
            .ok_or_else(|| Error::not_found("offer not found"))?;
        Ok(GetOfferResponse {
            offer: offer_row_to_record(&row)
                .ok_or_else(|| Error::internal("corrupt stored offer record"))?,
        })
    }

    async fn cancel_offer(&self, req: &CancelOffer) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let change = self.change_ph()?;
        let row = self
            .db
            .offer(&req.offer_id)
            .await?
            .ok_or_else(|| Error::not_found("offer not found"))?;
        let coin_spends = offers::build_cancel_offer(signer, &row.offer, change, fee)?;
        let resp = self.finalize_spend(coin_spends, req.auto_submit).await?;
        self.db.set_offer_status(&req.offer_id, "cancelled").await?;
        Ok(resp)
    }

    async fn create_did(&self, req: &CreateDid) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let inputs =
            spend::select_coins(self.spendable_coins(None).await?, 1u64.saturating_add(fee))?;
        let (coin_spends, _launcher) =
            mint::build_create_did(signer, &inputs, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn bulk_mint_nfts(&self, req: &BulkMintNfts) -> Result<BulkMintNftsResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let did = self.resolve_did(&req.did_id).await?;
        let default_owner = self.change_ph()?;
        let mut plans = Vec::with_capacity(req.mints.len());
        for m in &req.mints {
            let owner_ph = match &m.address {
                Some(a) => self.decode_ph(a)?,
                None => default_owner,
            };
            let royalty_ph = match &m.royalty_address {
                Some(a) => self.decode_ph(a)?,
                None => owner_ph,
            };
            let metadata = mint::nft_metadata(
                m.data_uris.clone(),
                m.data_hash.as_deref(),
                m.metadata_uris.clone(),
                m.metadata_hash.as_deref(),
                m.license_uris.clone(),
                m.license_hash.as_deref(),
                m.edition_number,
                m.edition_total,
            )?;
            plans.push(mint::NftMintPlan {
                metadata,
                owner_ph,
                royalty_ph,
                royalty_basis_points: m.royalty_ten_thousandths,
            });
        }
        let n = plans.len() as u64;
        let funding =
            spend::select_coins(self.spendable_coins(None).await?, n.saturating_add(fee))?;
        let (coin_spends, launcher_ids) =
            mint::build_bulk_mint(signer, did, &plans, &funding, self.change_ph()?, fee)?;
        spend::run_and_validate(&coin_spends)?;
        let summary = spend::summarize(
            &coin_spends,
            &self.config.address_prefix,
            &self.wallet_puzzle_hashes(),
        )?;
        if req.auto_submit {
            if let (Some(s), Some(bc)) = (self.signer.as_ref(), self.broadcaster.as_ref()) {
                let sig = s.sign(&coin_spends)?;
                bc.broadcast(&SpendBundle::new(coin_spends.clone(), sig))
                    .await?;
            }
        }
        let coin_spends_json = coin_spends
            .iter()
            .map(spend::coin_spend_to_json)
            .collect::<Result<Vec<_>>>()?;
        Ok(BulkMintNftsResponse {
            nft_ids: launcher_ids.iter().map(hex::encode).collect(),
            summary,
            coin_spends: coin_spends_json,
        })
    }

    async fn transfer_nfts(&self, req: &TransferNfts) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let mut nfts = Vec::with_capacity(req.nft_ids.len());
        for id in &req.nft_ids {
            nfts.push(self.nft_parent_child(id).await?);
        }
        let fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        let coin_spends =
            mint::build_nft_transfer(signer, &nfts, dest, &fee_coins, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
    }

    async fn transfer_dids(&self, req: &TransferDids) -> Result<TransactionResponse> {
        let signer = self.require_signer()?;
        let fee = amount_u64(&req.fee)?;
        let dest = self.decode_ph(&req.address)?;
        let mut dids = Vec::with_capacity(req.did_ids.len());
        for id in &req.did_ids {
            dids.push(self.did_parent_child(id).await?);
        }
        let fee_coins = if fee > 0 {
            spend::select_coins(self.spendable_coins(None).await?, fee)?
        } else {
            Vec::new()
        };
        let coin_spends =
            mint::build_did_transfer(signer, &dids, dest, &fee_coins, self.change_ph()?, fee)?;
        self.finalize_spend(coin_spends, req.auto_submit).await
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
                json(self.get_dids().await?)?
            }
            "get_nfts" => {
                let r = req!(GetNfts);
                json(self.get_nfts(&r).await?)?
            }
            "get_nft" => {
                let r = req!(GetNft);
                json(self.get_nft(&r).await?)?
            }
            "get_nft_data" => {
                let r = req!(GetNftData);
                json(self.get_nft_data(&r).await?)?
            }
            "get_nft_collections" => {
                let r = req!(GetNftCollections);
                json(self.get_nft_collections(&r).await?)?
            }
            "get_nft_collection" => {
                let r = req!(GetNftCollection);
                json(self.get_nft_collection(&r).await?)?
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
            "send_xch" => {
                let r = req!(SendXch);
                json(self.send_xch(&r).await?)?
            }
            "bulk_send_xch" => {
                let r = req!(BulkSendXch);
                json(self.bulk_send_xch(&r).await?)?
            }
            "send_cat" => {
                let r = req!(SendCat);
                json(self.send_cat(&r).await?)?
            }
            "bulk_send_cat" => {
                let r = req!(BulkSendCat);
                json(self.bulk_send_cat(&r).await?)?
            }
            "combine" => {
                let r = req!(Combine);
                json(self.combine(&r).await?)?
            }
            "split" => {
                let r = req!(Split);
                json(self.split(&r).await?)?
            }
            "multi_send" => {
                let r = req!(MultiSend);
                json(self.multi_send(&r).await?)?
            }
            "sign_coin_spends" => {
                let r = req!(SignCoinSpends);
                json(self.sign_coin_spends(&r).await?)?
            }
            "view_coin_spends" => {
                let r = req!(ViewCoinSpends);
                json(self.view_coin_spends(&r).await?)?
            }
            "submit_transaction" => {
                let r = req!(SubmitTransaction);
                json(self.submit_transaction(&r).await?)?
            }
            "make_offer" => {
                let r = req!(MakeOffer);
                json(self.make_offer(&r).await?)?
            }
            "take_offer" => {
                let r = req!(TakeOffer);
                json(self.take_offer(&r).await?)?
            }
            "view_offer" => {
                let r = req!(ViewOffer);
                json(self.view_offer(&r).await?)?
            }
            "combine_offers" => {
                let r = req!(CombineOffers);
                json(self.combine_offers(&r)?)?
            }
            "get_offers" => {
                let _r = req!(GetOffers);
                json(self.get_offers().await?)?
            }
            "get_offer" => {
                let r = req!(GetOffer);
                json(self.get_offer(&r).await?)?
            }
            "cancel_offer" => {
                let r = req!(CancelOffer);
                json(self.cancel_offer(&r).await?)?
            }
            "create_did" => {
                let r = req!(CreateDid);
                json(self.create_did(&r).await?)?
            }
            "bulk_mint_nfts" => {
                let r = req!(BulkMintNfts);
                json(self.bulk_mint_nfts(&r).await?)?
            }
            "transfer_nfts" => {
                let r = req!(TransferNfts);
                json(self.transfer_nfts(&r).await?)?
            }
            "transfer_dids" => {
                let r = req!(TransferDids);
                json(self.transfer_dids(&r).await?)?
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

/// Parse a wire [`Amount`] to `u64` (rejecting values beyond `u64`).
fn amount_u64(a: &Amount) -> Result<u64> {
    a.to_u64()
        .ok_or_else(|| Error::api("amount exceeds u64 range".to_string()))
}

/// Parse a wire asset id (`None` = XCH) to a 32-byte hash.
fn opt_asset_id(id: &Option<String>) -> Result<Option<Bytes32>> {
    match id {
        None => Ok(None),
        Some(s) => Ok(Some(singleton::bytes32_from_hex(s)?)),
    }
}

/// The current unix time in seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a stored status token into an [`OfferRecordStatus`] (unknown → `Active`).
fn parse_offer_status(s: &str) -> OfferRecordStatus {
    match s {
        "pending" => OfferRecordStatus::Pending,
        "completed" => OfferRecordStatus::Completed,
        "cancelled" => OfferRecordStatus::Cancelled,
        "expired" => OfferRecordStatus::Expired,
        _ => OfferRecordStatus::Active,
    }
}

/// Render a stored [`OfferDbRow`] as the Sage [`OfferRecord`] wire shape (`None` if the
/// stored summary JSON is corrupt).
fn offer_row_to_record(row: &OfferDbRow) -> Option<OfferRecord> {
    let summary: OfferSummary = serde_json::from_str(&row.summary_json).ok()?;
    Some(OfferRecord {
        offer_id: row.offer_id.clone(),
        offer: row.offer.clone(),
        status: parse_offer_status(&row.status),
        creation_timestamp: row.creation_timestamp as u64,
        summary,
    })
}

/// Normalize a Sage `nft_id`/`did_id` to the stored hex launcher id: a bech32m singleton
/// address decodes to its 32-byte launcher id; a hex id is used as-is (lowercased).
fn normalize_singleton_id(id: &str) -> String {
    if let Some(ph) = decode_address(id) {
        return ph;
    }
    id.strip_prefix("0x").unwrap_or(id).to_ascii_lowercase()
}

/// Greedily select CAT coin rows (largest first) covering `target`. Errors if they cannot.
fn select_cat_rows(mut rows: Vec<CoinRow>, target: u64) -> Result<Vec<CoinRow>> {
    rows.sort_by(|a, b| {
        b.amount
            .parse::<u64>()
            .unwrap_or(0)
            .cmp(&a.amount.parse::<u64>().unwrap_or(0))
            .then(a.coin_id.cmp(&b.coin_id))
    });
    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for r in rows {
        if total >= target {
            break;
        }
        total += r.amount.parse::<u64>().unwrap_or(0);
        selected.push(r);
    }
    if total < target {
        return Err(Error::api(format!(
            "insufficient CAT balance: have {total}, need {target}"
        )));
    }
    Ok(selected)
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
        // `get_secret_key` is a real Sage endpoint but not served here (secret-touching,
        // never exposed) — an unsupported method → 404.
        let (status, body) = be.dispatch("get_secret_key", "{}").await;
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

    // ---- send/spend dispatch (#216) --------------------------------------

    use super::super::db::NftDbRow;
    use super::super::spend::{MockBroadcaster, WalletSigner};
    use chia_sdk_test::BlsPair;

    /// A backend with a signer over a single test key, a coin funded at that key's puzzle
    /// hash, and a mock broadcaster — enough to drive the send/spend surface off-chain.
    async fn spend_backend(fund: u64) -> (WalletBackend, std::sync::Arc<MockBroadcaster>, Bytes32) {
        let pair = BlsPair::new(1);
        let signer = Arc::new(WalletSigner::new(vec![pair.sk], Bytes32::new([0u8; 32])));
        let ph = *signer.puzzle_hashes().iter().next().unwrap();
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&CoinRow {
            coin_id: "coin1".into(),
            parent_coin_info: "11".repeat(32),
            puzzle_hash: hex::encode(ph),
            amount: fund.to_string(),
            created_height: Some(1),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        })
        .await
        .unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
        let bc = Arc::new(MockBroadcaster::default());
        let cfg = WalletConfig {
            puzzle_hashes: vec![hex::encode(ph)],
            address_prefix: "txch".into(),
            ..Default::default()
        };
        let be = WalletBackend::new(db, Arc::new(MockFallback::default()), cfg)
            .with_signer(signer)
            .with_broadcaster(bc.clone());
        (be, bc, ph)
    }

    #[tokio::test]
    async fn send_xch_dispatch_builds_validates_and_broadcasts() {
        let (be, bc, _ph) = spend_backend(1_000).await;
        let dest = encode_address(&"22".repeat(32), "txch").unwrap();
        let body = format!(r#"{{"address":"{dest}","amount":600,"fee":10,"auto_submit":true}}"#);
        let (status, resp) = be.dispatch("send_xch", &body).await;
        assert_eq!(status, 200, "{resp}");
        let tr: TransactionResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(tr.summary.fee.to_u64(), Some(10));
        assert!(!tr.coin_spends.is_empty());
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "auto_submit broadcasts once"
        );
    }

    #[tokio::test]
    async fn spend_without_signer_is_locked_error() {
        // No signer attached → spend building must fail (C.6), not panic.
        let be = backend_with(vec![], true).await;
        let dest = encode_address(&"22".repeat(32), "xch").unwrap();
        let body = format!(r#"{{"address":"{dest}","amount":1,"fee":0}}"#);
        let (status, body) = be.dispatch("send_xch", &body).await;
        assert_eq!(status, 500);
        assert!(body.contains("locked") || body.contains("signing key"));
    }

    #[tokio::test]
    async fn view_and_sign_and_submit_round_trip() {
        let (be, bc, _ph) = spend_backend(1_000).await;
        // Build (no broadcast) to get coin_spends.
        let dest = encode_address(&"33".repeat(32), "txch").unwrap();
        let build_body =
            format!(r#"{{"address":"{dest}","amount":500,"fee":0,"auto_submit":false}}"#);
        let (s, resp) = be.dispatch("send_xch", &build_body).await;
        assert_eq!(s, 200, "{resp}");
        let built: TransactionResponse = serde_json::from_str(&resp).unwrap();
        let cs_json = serde_json::to_string(&built.coin_spends).unwrap();

        // view_coin_spends summarizes the same spends.
        let (s, resp) = be
            .dispatch(
                "view_coin_spends",
                &format!(r#"{{"coin_spends":{cs_json}}}"#),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let view: ViewCoinSpendsResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(view.summary.inputs.len(), 1);

        // sign_coin_spends returns a bundle; submit_transaction broadcasts it.
        let (s, resp) = be
            .dispatch(
                "sign_coin_spends",
                &format!(r#"{{"coin_spends":{cs_json},"auto_submit":false}}"#),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let signed: SignCoinSpendsResponse = serde_json::from_str(&resp).unwrap();
        let bundle_json = serde_json::to_string(&signed.spend_bundle).unwrap();
        let (s, _resp) = be
            .dispatch(
                "submit_transaction",
                &format!(r#"{{"spend_bundle":{bundle_json}}}"#),
            )
            .await;
        assert_eq!(s, 200);
        assert_eq!(
            bc.sent.lock().unwrap().len(),
            1,
            "submit broadcasts the bundle"
        );
    }

    #[tokio::test]
    async fn offer_and_did_dispatch_end_to_end() {
        // A single wallet backend with a signer + a large funding coin drives the offer +
        // DID dispatch surface: make_offer stores an offer, get_offers/get_offer/view_offer
        // read it, cancel_offer flips its status, create_did builds a valid DID spend. No
        // broadcast reaches the network (MockBroadcaster).
        let (be, _bc, ph) = spend_backend(1_000_000).await;
        let addr = encode_address(&hex::encode(ph), "txch").unwrap();

        // make_offer: OFFER 300 XCH, REQUEST 500 XCH to our own address (auto_import).
        let body = format!(
            r#"{{"offered_assets":[{{"asset_id":null,"amount":300}}],"requested_assets":[{{"asset_id":null,"amount":500}}],"fee":0,"receive_address":"{addr}"}}"#
        );
        let (s, resp) = be.dispatch("make_offer", &body).await;
        assert_eq!(s, 200, "{resp}");
        let mo: MakeOfferResponse = serde_json::from_str(&resp).unwrap();
        assert!(mo.offer.starts_with("offer1"), "got {}", mo.offer);
        assert_eq!(mo.offer_id.len(), 64);

        // get_offers returns the stored offer (auto_import defaulted true).
        let (s, resp) = be.dispatch("get_offers", "{}").await;
        assert_eq!(s, 200);
        let go: GetOffersResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(go.offers.len(), 1);
        assert_eq!(go.offers[0].offer_id, mo.offer_id);
        assert!(matches!(go.offers[0].status, OfferRecordStatus::Active));

        // view_offer summarizes it: maker gives 300, taker pays 500.
        let vo_body = format!(
            r#"{{"offer":{}}}"#,
            serde_json::to_string(&mo.offer).unwrap()
        );
        let (s, resp) = be.dispatch("view_offer", &vo_body).await;
        assert_eq!(s, 200, "{resp}");
        let vo: ViewOfferResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(vo.offer.maker[0].amount.to_u64(), Some(300));
        assert_eq!(vo.offer.taker[0].amount.to_u64(), Some(500));

        // create_did builds + validates a DID creation (no broadcast: auto_submit default false).
        let (s, resp) = be.dispatch("create_did", r#"{"name":"me","fee":0}"#).await;
        assert_eq!(s, 200, "{resp}");
        let tr: TransactionResponse = serde_json::from_str(&resp).unwrap();
        assert!(!tr.coin_spends.is_empty());

        // cancel_offer flips the stored offer to cancelled.
        let (s, resp) = be
            .dispatch(
                "cancel_offer",
                &format!(r#"{{"offer_id":"{}","fee":0}}"#, mo.offer_id),
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let (_s, resp) = be
            .dispatch("get_offer", &format!(r#"{{"offer_id":"{}"}}"#, mo.offer_id))
            .await;
        let one: GetOfferResponse = serde_json::from_str(&resp).unwrap();
        assert!(matches!(one.offer.status, OfferRecordStatus::Cancelled));
    }

    #[tokio::test]
    async fn transfer_without_signer_is_locked_and_combine_needs_two() {
        // Secret-custody gate (C.6): a spend method with no signer attached fails locked.
        let be = backend_with(vec![], true).await;
        let (status, body) = be
            .dispatch(
                "transfer_nfts",
                r#"{"nft_ids":["aa"],"address":"xch1x","fee":0}"#,
            )
            .await;
        assert_eq!(status, 500);
        assert!(body.contains("locked") || body.contains("signing key"));

        // combine_offers needs at least two offers → 400.
        let (status, _b) = be
            .dispatch("combine_offers", r#"{"offers":["offer1abc"]}"#)
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn get_nfts_and_get_dids_return_reconstructed_rows() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
        let nft = NftRecord {
            launcher_id: "aa".repeat(32),
            collection_id: None,
            collection_name: None,
            minter_did: None,
            owner_did: None,
            visible: true,
            sensitive_content: false,
            name: Some("Test".into()),
            created_height: Some(5),
            coin_id: "bb".repeat(32),
            address: "xch1".into(),
            royalty_address: "xch1".into(),
            royalty_ten_thousandths: 300,
            data_uris: vec!["u".into()],
            data_hash: None,
            metadata_uris: vec![],
            metadata_hash: None,
            license_uris: vec![],
            license_hash: None,
            edition_number: Some(1),
            edition_total: Some(1),
            icon_url: None,
            created_timestamp: None,
            special_use_type: None,
        };
        db.upsert_nft(&NftDbRow {
            launcher_id: nft.launcher_id.clone(),
            coin_id: nft.coin_id.clone(),
            collection_id: None,
            minter_did: None,
            owner_did: None,
            name: nft.name.clone(),
            visible: true,
            created_height: Some(5),
            record_json: serde_json::to_string(&nft).unwrap(),
        })
        .await
        .unwrap();
        let be = WalletBackend::new(
            db,
            Arc::new(MockFallback::default()),
            WalletConfig::default(),
        );

        let (s, resp) = be
            .dispatch(
                "get_nfts",
                r#"{"offset":0,"limit":10,"sort_mode":"name","include_hidden":false}"#,
            )
            .await;
        assert_eq!(s, 200, "{resp}");
        let got: GetNftsResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(got.total, 1);
        assert_eq!(got.nfts[0].launcher_id, nft.launcher_id);

        // get_nft by hex launcher id.
        let (_s, resp) = be
            .dispatch("get_nft", &format!(r#"{{"nft_id":"{}"}}"#, nft.launcher_id))
            .await;
        let one: GetNftResponse = serde_json::from_str(&resp).unwrap();
        assert!(one.nft.is_some());
    }
}
