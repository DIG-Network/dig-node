//! The Sage wire contract (pinned **v0.12.11**, commit `a84d7dfc`).
//!
//! These are the `endpoints.json` request/response shapes a Sage RPC client sees. They
//! are re-implemented to match `sage-api` **byte-for-byte** so a client can point at
//! either Sage or the dig-node interchangeably (design Part A). The parity invariants:
//!
//! - **[`Amount`]** serializes as a JSON **number** when `<= MAX_JS_SAFE_INTEGER`, else a
//!   JSON **string** (JS clients depend on this exact threshold). `#[serde(untagged)]`.
//! - **snake_case** field names (Rust idents are already snake_case; no `rename_all` on
//!   structs). Enums carry `#[serde(rename_all = "snake_case")]`.
//! - **`Option<T>` fields serialize as `null`** when `None` (Sage does NOT skip them) —
//!   so we do not add `skip_serializing_if`, to keep the bytes identical.
//! - **field order == declaration order** (serde emits keys in declaration order), so the
//!   field order here mirrors `sage-api` exactly.
//!
//! Only the subset needed by the core READ surface (design Part F MUST, this PR's scope)
//! is modeled; spend/offer/option types are follow-on PRs.

#![allow(clippy::struct_excessive_bools)]

use serde::{Deserialize, Serialize};

// =============================================================================
// Shared scalar types (sage-api `types/`)
// =============================================================================

/// The largest integer a JSON number can carry losslessly in JS (`Number.MAX_SAFE_INTEGER`).
/// Amounts at or below this serialize as a number; larger ones as a string.
pub const MAX_JS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// A blockchain amount in an asset's smallest unit (mojos for XCH). Serializes as a JSON
/// number when it fits `MAX_JS_SAFE_INTEGER`, otherwise as a decimal string. Deserializes
/// from either. Byte-identical to `sage_api::Amount`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Amount {
    /// A string-encoded amount (used when the value exceeds `MAX_JS_SAFE_INTEGER`).
    String(String),
    /// A number-encoded amount (used when the value fits `MAX_JS_SAFE_INTEGER`).
    Number(u64),
}

impl Amount {
    /// Build an `Amount` from a `u64`, choosing the number/string variant by the Sage
    /// threshold so the emitted JSON matches Sage byte-for-byte.
    pub fn u64(value: u64) -> Self {
        if value > MAX_JS_SAFE_INTEGER {
            Self::String(value.to_string())
        } else {
            Self::Number(value)
        }
    }

    /// Build an `Amount` from a `u128` (CAT balances can exceed `u64`).
    pub fn u128(value: u128) -> Self {
        if value > u128::from(MAX_JS_SAFE_INTEGER) {
            Self::String(value.to_string())
        } else {
            Self::Number(value as u64)
        }
    }

    /// The numeric value, if it parses (a `u64`).
    pub fn to_u64(&self) -> Option<u64> {
        match self {
            Self::String(v) => v.parse().ok(),
            Self::Number(v) => Some(*v),
        }
    }
}

/// The display unit of an asset: a ticker + decimal precision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    /// The ticker symbol (e.g. `XCH`, `Mojos`, a CAT ticker).
    pub ticker: String,
    /// Decimal precision (XCH = 12, Mojos = 0, CATs default 3).
    pub precision: u8,
}

impl Unit {
    /// The canonical XCH unit (precision 12).
    pub fn xch() -> Self {
        Self {
            ticker: "XCH".to_string(),
            precision: 12,
        }
    }
    /// The raw mojos unit (precision 0).
    pub fn mojos() -> Self {
        Self {
            ticker: "Mojos".to_string(),
            precision: 0,
        }
    }
    /// A CAT unit (default precision 3).
    pub fn cat(ticker: String) -> Self {
        Self {
            ticker,
            precision: 3,
        }
    }
}

/// A wallet asset descriptor (token / NFT / DID / option).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    /// The asset id (hex), or `None` for XCH.
    pub asset_id: Option<String>,
    /// Human-readable name.
    pub name: Option<String>,
    /// Ticker symbol.
    pub ticker: Option<String>,
    /// Decimal precision.
    pub precision: u8,
    /// Icon URL.
    pub icon_url: Option<String>,
    /// Description text.
    pub description: Option<String>,
    /// Whether the content is flagged sensitive.
    pub is_sensitive_content: bool,
    /// Whether the asset is visible in the wallet UI.
    pub is_visible: bool,
    /// The revocation address for a revocable CAT, if any.
    pub revocation_address: Option<String>,
    /// The asset kind.
    pub kind: AssetKind,
}

/// The kind of a wallet asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    /// A CAT / XCH token.
    Token,
    /// A non-fungible token.
    Nft,
    /// A decentralized identifier.
    Did,
    /// An option contract.
    Option,
}

/// How an address relates to the wallet (used in transaction records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    /// An address owned by this wallet.
    Own,
    /// The burn address.
    Burn,
    /// A singleton launcher address.
    Launcher,
    /// A settlement/offer address.
    Offer,
    /// An external (not-owned) address.
    External,
    /// Kind could not be determined.
    Unknown,
}

/// Public metadata about a wallet key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Display name.
    pub name: String,
    /// The 32-bit key fingerprint.
    pub fingerprint: u32,
    /// The master public key (hex).
    pub public_key: String,
    /// The key scheme.
    pub kind: KeyKind,
    /// Whether the secret key / mnemonic is stored.
    pub has_secrets: bool,
    /// The network id the key is scoped to.
    pub network_id: String,
    /// An optional emoji identifier.
    pub emoji: Option<String>,
}

/// The cryptographic scheme of a wallet key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// A BLS (Chia) key.
    Bls,
}

// =============================================================================
// Records (sage-api `records/`)
// =============================================================================

/// A wallet coin record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinRecord {
    /// The coin id (hex).
    pub coin_id: String,
    /// The address the coin's puzzle hash encodes.
    pub address: String,
    /// The coin amount.
    pub amount: Amount,
    /// The id of a pending transaction creating/spending this coin, if any.
    pub transaction_id: Option<String>,
    /// The offer id locking this coin, if any.
    pub offer_id: Option<String>,
    /// A clawback expiry timestamp, if the coin is a clawback coin.
    pub clawback_timestamp: Option<u64>,
    /// The block height the coin was created at.
    pub created_height: Option<u32>,
    /// The block height the coin was spent at.
    pub spent_height: Option<u32>,
    /// The timestamp the coin was spent at.
    pub spent_timestamp: Option<u64>,
    /// The timestamp the coin was created at.
    pub created_timestamp: Option<u64>,
}

/// A token (XCH or CAT) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    /// The asset id (hex), or `None` for XCH.
    pub asset_id: Option<String>,
    /// Human-readable name.
    pub name: Option<String>,
    /// Ticker symbol.
    pub ticker: Option<String>,
    /// Decimal precision.
    pub precision: u8,
    /// Description text.
    pub description: Option<String>,
    /// Icon URL.
    pub icon_url: Option<String>,
    /// Whether the token is visible in the wallet UI.
    pub visible: bool,
    /// Total balance (unspent) in the smallest unit.
    pub balance: Amount,
    /// The currently spendable balance in the smallest unit.
    pub selectable_balance: Amount,
    /// The revocation address for a revocable CAT, if any.
    pub revocation_address: Option<String>,
}

/// Whether an NFT is put to a special use (e.g. a theme).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NftSpecialUseType {
    /// No special use.
    #[default]
    None,
    /// A UI theme NFT.
    Theme,
}

/// An NFT record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftRecord {
    /// The launcher (singleton) id.
    pub launcher_id: String,
    /// The collection id, if part of a collection.
    pub collection_id: Option<String>,
    /// The collection name.
    pub collection_name: Option<String>,
    /// The minter DID.
    pub minter_did: Option<String>,
    /// The current owner DID.
    pub owner_did: Option<String>,
    /// Whether the NFT is visible in the wallet UI.
    pub visible: bool,
    /// Whether the content is flagged sensitive.
    pub sensitive_content: bool,
    /// Human-readable name.
    pub name: Option<String>,
    /// The block height the current coin was created at.
    pub created_height: Option<u32>,
    /// The current coin id (hex).
    pub coin_id: String,
    /// The address the current coin encodes.
    pub address: String,
    /// The royalty payout address.
    pub royalty_address: String,
    /// The royalty share in ten-thousandths.
    pub royalty_ten_thousandths: u16,
    /// Data file URIs.
    pub data_uris: Vec<String>,
    /// Data file content hash.
    pub data_hash: Option<String>,
    /// Metadata file URIs.
    pub metadata_uris: Vec<String>,
    /// Metadata file content hash.
    pub metadata_hash: Option<String>,
    /// License file URIs.
    pub license_uris: Vec<String>,
    /// License file content hash.
    pub license_hash: Option<String>,
    /// The edition number within the collection.
    pub edition_number: Option<u32>,
    /// The total edition count.
    pub edition_total: Option<u32>,
    /// A resolved icon URL.
    pub icon_url: Option<String>,
    /// The creation timestamp.
    pub created_timestamp: Option<u64>,
    /// A special-use classification.
    pub special_use_type: Option<NftSpecialUseType>,
}

/// The resolved data blob + metadata for an NFT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftData {
    /// The base64-encoded data blob.
    pub blob: Option<String>,
    /// The blob MIME type.
    pub mime_type: Option<String>,
    /// Whether the blob hash matches `data_hash`.
    pub hash_matches: bool,
    /// The metadata JSON text.
    pub metadata_json: Option<String>,
    /// Whether the metadata hash matches `metadata_hash`.
    pub metadata_hash_matches: bool,
}

/// A DID record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidRecord {
    /// The launcher (singleton) id.
    pub launcher_id: String,
    /// Human-readable name.
    pub name: Option<String>,
    /// Whether the DID is visible in the wallet UI.
    pub visible: bool,
    /// The current coin id (hex).
    pub coin_id: String,
    /// The address the current coin encodes.
    pub address: String,
    /// The coin amount.
    pub amount: Amount,
    /// The recovery list hash, if set.
    pub recovery_hash: Option<String>,
    /// The block height the current coin was created at.
    pub created_height: Option<u32>,
}

/// An NFT collection record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCollectionRecord {
    /// The collection id.
    pub collection_id: String,
    /// The DID that minted the collection.
    pub did_id: String,
    /// The metadata collection id.
    pub metadata_collection_id: String,
    /// Whether the collection is visible in the wallet UI.
    pub visible: bool,
    /// Human-readable name.
    pub name: Option<String>,
    /// A resolved icon URL.
    pub icon: Option<String>,
}

/// A confirmed transaction grouped by block height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    /// The block height.
    pub height: u32,
    /// The block timestamp.
    pub timestamp: Option<u64>,
    /// Coins spent in this transaction.
    pub spent: Vec<TransactionCoinRecord>,
    /// Coins created in this transaction.
    pub created: Vec<TransactionCoinRecord>,
}

/// A coin that participated in a transaction (spent or created).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCoinRecord {
    /// The coin id (hex).
    pub coin_id: String,
    /// The coin amount.
    pub amount: Amount,
    /// The address, if resolvable.
    pub address: Option<String>,
    /// How the address relates to the wallet.
    pub address_kind: AddressKind,
    /// The asset the coin holds.
    pub asset: Asset,
}

/// A transaction awaiting confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransactionRecord {
    /// The transaction id (hex).
    pub transaction_id: String,
    /// The fee.
    pub fee: Amount,
    /// The submission timestamp.
    pub submitted_at: Option<u64>,
}

/// A single HD derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivationRecord {
    /// The derivation index.
    pub index: u32,
    /// The derived public key (hex).
    pub public_key: String,
    /// The derived address.
    pub address: String,
}

/// A connected peer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// The peer IP address.
    pub ip_addr: String,
    /// The peer port.
    pub port: u16,
    /// The peer's reported peak height.
    pub peak_height: u32,
    /// Whether the peer was added manually by the user.
    pub user_managed: bool,
}

// =============================================================================
// Request query enums (sage-api `requests/data.rs`)
// =============================================================================

/// How to sort a `get_coins` result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoinSortMode {
    /// By coin id.
    CoinId,
    /// By amount.
    Amount,
    /// By created height (default).
    #[default]
    CreatedHeight,
    /// By spent height.
    SpentHeight,
    /// By clawback timestamp.
    ClawbackTimestamp,
}

/// Which coins to include in a `get_coins` result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoinFilterMode {
    /// All coins.
    All,
    /// Spendable coins (default).
    #[default]
    Selectable,
    /// Owned (unspent) coins.
    Owned,
    /// Spent coins.
    Spent,
    /// Clawback coins.
    Clawback,
}

/// How to sort a `get_nfts` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NftSortMode {
    /// By name.
    Name,
    /// Most recent first.
    Recent,
}

// =============================================================================
// Endpoint request/response structs (the core READ surface — this PR's scope)
// =============================================================================

/// `login` request: authenticate a wallet by fingerprint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Login {
    /// The wallet fingerprint to log in.
    pub fingerprint: u32,
}
/// `login` response (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LoginResponse {}

/// `logout` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Logout {}
/// `logout` response (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LogoutResponse {}

/// `get_version` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetVersion {}
/// `get_version` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    /// The semantic version string.
    pub version: String,
}

/// `get_sync_status` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetSyncStatus {}
/// `get_sync_status` response (design A.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSyncStatusResponse {
    /// The currently spendable XCH balance.
    pub selectable_balance: Amount,
    /// The balance unit.
    pub unit: Unit,
    /// The number of coins synced.
    pub synced_coins: u32,
    /// The total number of coins known.
    pub total_coins: u32,
    /// The wallet's receive address.
    pub receive_address: String,
    /// The network burn address.
    pub burn_address: String,
    /// The current unhardened derivation index.
    pub unhardened_derivation_index: u32,
    /// The current hardened derivation index.
    pub hardened_derivation_index: u32,
    /// The number of NFT files checked.
    pub checked_files: u32,
    /// The total NFT files to check.
    pub total_files: u32,
    /// The wallet database size in bytes.
    pub database_size: u64,
}

/// `check_address` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAddress {
    /// The address to validate.
    pub address: String,
}
/// `check_address` response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CheckAddressResponse {
    /// Whether the address is valid (and belongs to this wallet).
    pub valid: bool,
}

/// `get_derivations` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetDerivations {
    /// Whether to return hardened derivations.
    #[serde(default)]
    pub hardened: bool,
    /// Pagination offset.
    pub offset: u32,
    /// Page size.
    pub limit: u32,
}
/// `get_derivations` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDerivationsResponse {
    /// The derivation records.
    pub derivations: Vec<DerivationRecord>,
    /// The total number of derivations available.
    pub total: u32,
}

/// `get_are_coins_spendable` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAreCoinsSpendable {
    /// The coin ids to check.
    pub coin_ids: Vec<String>,
}
/// `get_are_coins_spendable` response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetAreCoinsSpendableResponse {
    /// Whether all the requested coins are spendable.
    pub spendable: bool,
}

/// `get_spendable_coin_count` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSpendableCoinCount {
    /// The asset id to filter by (`None` for XCH).
    pub asset_id: Option<String>,
}
/// `get_spendable_coin_count` response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetSpendableCoinCountResponse {
    /// The number of spendable coins.
    pub count: u32,
}

/// `get_coins` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCoins {
    /// The asset id to filter by (`None` for XCH).
    #[serde(default)]
    pub asset_id: Option<String>,
    /// Pagination offset.
    pub offset: u32,
    /// Page size.
    pub limit: u32,
    /// Sort mode.
    #[serde(default)]
    pub sort_mode: CoinSortMode,
    /// Filter mode.
    #[serde(default)]
    pub filter_mode: CoinFilterMode,
    /// Whether to sort ascending.
    #[serde(default)]
    pub ascending: bool,
}
/// `get_coins` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCoinsResponse {
    /// The coin records for this page.
    pub coins: Vec<CoinRecord>,
    /// The total number of coins matching the filter.
    pub total: u32,
}

/// `get_coins_by_ids` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCoinsByIds {
    /// The coin ids to fetch.
    pub coin_ids: Vec<String>,
}
/// `get_coins_by_ids` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCoinsByIdsResponse {
    /// The matching coin records.
    pub coins: Vec<CoinRecord>,
}

/// `get_cats` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetCats {}
/// `get_cats` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCatsResponse {
    /// The wallet's CAT tokens.
    pub cats: Vec<TokenRecord>,
}

/// `get_all_cats` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetAllCats {}
/// `get_all_cats` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAllCatsResponse {
    /// All known CAT tokens.
    pub cats: Vec<TokenRecord>,
}

/// `get_token` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetToken {
    /// The asset id (`None` for XCH).
    pub asset_id: Option<String>,
}
/// `get_token` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTokenResponse {
    /// The token, if found.
    pub token: Option<TokenRecord>,
}

/// `get_dids` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetDids {}
/// `get_dids` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDidsResponse {
    /// The wallet's DIDs.
    pub dids: Vec<DidRecord>,
}

/// `get_pending_transactions` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetPendingTransactions {}
/// `get_pending_transactions` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPendingTransactionsResponse {
    /// The pending transactions.
    pub transactions: Vec<PendingTransactionRecord>,
}

/// `get_transaction` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetTransaction {
    /// The block height identifying the transaction.
    pub height: u32,
}
/// `get_transaction` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionResponse {
    /// The transaction, if found.
    pub transaction: Option<TransactionRecord>,
}

/// `get_transactions` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactions {
    /// Pagination offset.
    pub offset: u32,
    /// Page size.
    pub limit: u32,
    /// Whether to sort ascending by height.
    pub ascending: bool,
    /// An optional search value.
    pub find_value: Option<String>,
}
/// `get_transactions` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    /// The transaction records for this page.
    pub transactions: Vec<TransactionRecord>,
    /// The total number of transactions.
    pub total: u32,
}

/// `get_nft_collections` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetNftCollections {
    /// Pagination offset.
    pub offset: u32,
    /// Page size.
    pub limit: u32,
    /// Whether to include hidden collections.
    pub include_hidden: bool,
}
/// `get_nft_collections` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftCollectionsResponse {
    /// The collection records for this page.
    pub collections: Vec<NftCollectionRecord>,
    /// The total number of collections.
    pub total: u32,
}

/// `get_nft_collection` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftCollection {
    /// The collection id (`None` for the uncollected pseudo-collection).
    pub collection_id: Option<String>,
}
/// `get_nft_collection` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftCollectionResponse {
    /// The collection, if found.
    pub collection: Option<NftCollectionRecord>,
}

/// `get_nfts` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNfts {
    /// Filter by collection id.
    #[serde(default)]
    pub collection_id: Option<String>,
    /// Filter by minter DID.
    #[serde(default)]
    pub minter_did_id: Option<String>,
    /// Filter by owner DID.
    #[serde(default)]
    pub owner_did_id: Option<String>,
    /// Filter by name search.
    #[serde(default)]
    pub name: Option<String>,
    /// Pagination offset.
    pub offset: u32,
    /// Page size.
    pub limit: u32,
    /// Sort mode.
    pub sort_mode: NftSortMode,
    /// Whether to include hidden NFTs.
    pub include_hidden: bool,
}
/// `get_nfts` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftsResponse {
    /// The NFT records for this page.
    pub nfts: Vec<NftRecord>,
    /// The total number of NFTs matching the filter.
    pub total: u32,
}

/// `get_nft` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNft {
    /// The NFT id.
    pub nft_id: String,
}
/// `get_nft` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftResponse {
    /// The NFT, if found.
    pub nft: Option<NftRecord>,
}

/// `get_nft_data` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftData {
    /// The NFT id.
    pub nft_id: String,
}
/// `get_nft_data` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNftDataResponse {
    /// The NFT data, if available.
    pub data: Option<NftData>,
}

/// `is_asset_owned` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsAssetOwned {
    /// The asset id to check.
    pub asset_id: String,
}
/// `is_asset_owned` response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct IsAssetOwnedResponse {
    /// Whether the asset is owned by this wallet.
    pub owned: bool,
}

/// `get_key` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetKey {
    /// The fingerprint (uses the logged-in key if `None`).
    #[serde(default)]
    pub fingerprint: Option<u32>,
}
/// `get_key` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeyResponse {
    /// The key, if found.
    pub key: Option<KeyInfo>,
}

/// `get_keys` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetKeys {}
/// `get_keys` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetKeysResponse {
    /// All wallet keys.
    pub keys: Vec<KeyInfo>,
}

// =============================================================================
// Spend / transaction wire types (sage-api `records/transaction_summary.rs`)
// =============================================================================

/// The serde default for `auto_submit` / `include_hint` (Sage's `#[serde(default = "yes")]`).
fn default_true() -> bool {
    true
}

/// A coin as it appears inside a `CoinSpend` (design A.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinJson {
    /// The parent coin id (hex).
    pub parent_coin_info: String,
    /// The puzzle hash (hex).
    pub puzzle_hash: String,
    /// The coin amount.
    pub amount: Amount,
}

/// A single coin spend: the coin plus its hex-encoded serialized CLVM puzzle + solution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinSpendJson {
    /// The coin being spent.
    pub coin: CoinJson,
    /// The hex-encoded serialized CLVM puzzle reveal.
    pub puzzle_reveal: String,
    /// The hex-encoded serialized CLVM solution.
    pub solution: String,
}

/// A full spend bundle: coin spends + the aggregated BLS signature (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendBundleJson {
    /// The coin spends.
    pub coin_spends: Vec<CoinSpendJson>,
    /// The aggregated BLS signature (hex).
    pub aggregated_signature: String,
}

/// One output produced by a transaction input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// The created coin id (hex).
    pub coin_id: String,
    /// The output amount.
    pub amount: Amount,
    /// The receiving address.
    pub address: String,
    /// Whether this output is received by the wallet.
    pub receiving: bool,
    /// Whether this output is a burn.
    pub burning: bool,
}

/// One input coin of a transaction and the outputs it produces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    /// The spent coin id (hex).
    pub coin_id: String,
    /// The input amount.
    pub amount: Amount,
    /// The address the input coin encodes.
    pub address: String,
    /// The asset the input holds (XCH when `None`).
    pub asset: Option<Asset>,
    /// The outputs this input produces.
    pub outputs: Vec<TransactionOutput>,
}

/// A human-readable summary of a spend (design A.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    /// The network fee reserved by the spend.
    pub fee: Amount,
    /// The transaction inputs + their outputs.
    pub inputs: Vec<TransactionInput>,
}

/// The shared response of every spend-builder endpoint (the `pub type …Response =
/// TransactionResponse` aliases): a summary + the built (unsigned) coin spends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResponse {
    /// The spend summary.
    pub summary: TransactionSummary,
    /// The built coin spends (unsigned).
    pub coin_spends: Vec<CoinSpendJson>,
}

// =============================================================================
// Spend-builder request/response structs (design A.5 — this PR's send/spend group)
// =============================================================================

/// `send_xch` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendXch {
    /// The destination address.
    pub address: String,
    /// The amount to send.
    pub amount: Amount,
    /// The network fee.
    pub fee: Amount,
    /// Coin memos.
    #[serde(default)]
    pub memos: Vec<String>,
    /// An optional clawback timeout (seconds).
    #[serde(default)]
    pub clawback: Option<u64>,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `bulk_send_xch` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSendXch {
    /// The destination addresses (each receives `amount`).
    pub addresses: Vec<String>,
    /// The amount to send to each address.
    pub amount: Amount,
    /// The network fee.
    pub fee: Amount,
    /// Coin memos.
    #[serde(default)]
    pub memos: Vec<String>,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `combine` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Combine {
    /// The coin ids to combine.
    pub coin_ids: Vec<String>,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `split` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Split {
    /// The coin ids to split.
    pub coin_ids: Vec<String>,
    /// The number of output coins to produce.
    pub output_count: u32,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `send_cat` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendCat {
    /// The CAT asset id (hex).
    pub asset_id: String,
    /// The destination address.
    pub address: String,
    /// The amount to send (in CAT base units).
    pub amount: Amount,
    /// The network fee (paid from XCH).
    pub fee: Amount,
    /// Whether to include the destination puzzle-hash hint.
    #[serde(default = "default_true")]
    pub include_hint: bool,
    /// Coin memos.
    #[serde(default)]
    pub memos: Vec<String>,
    /// An optional clawback timeout (seconds).
    #[serde(default)]
    pub clawback: Option<u64>,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `bulk_send_cat` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSendCat {
    /// The CAT asset id (hex).
    pub asset_id: String,
    /// The destination addresses (each receives `amount`).
    pub addresses: Vec<String>,
    /// The amount to send to each address.
    pub amount: Amount,
    /// The network fee (paid from XCH).
    pub fee: Amount,
    /// Whether to include the destination puzzle-hash hint.
    #[serde(default = "default_true")]
    pub include_hint: bool,
    /// Coin memos.
    #[serde(default)]
    pub memos: Vec<String>,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// A single payment in a `multi_send` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// The asset id (`None` = XCH).
    #[serde(default)]
    pub asset_id: Option<String>,
    /// The destination address.
    pub address: String,
    /// The amount to send.
    pub amount: Amount,
    /// Coin memos.
    #[serde(default)]
    pub memos: Vec<String>,
}

/// `multi_send` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSend {
    /// The payments to make.
    pub payments: Vec<Payment>,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
}

/// `sign_coin_spends` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCoinSpends {
    /// The coin spends to sign.
    pub coin_spends: Vec<CoinSpendJson>,
    /// Whether to broadcast the signed bundle immediately.
    #[serde(default = "default_true")]
    pub auto_submit: bool,
    /// Whether a partial signature (not all required sigs present) is acceptable.
    #[serde(default)]
    pub partial: bool,
}

/// `sign_coin_spends` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignCoinSpendsResponse {
    /// The signed spend bundle.
    pub spend_bundle: SpendBundleJson,
}

/// `view_coin_spends` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewCoinSpends {
    /// The coin spends to summarize.
    pub coin_spends: Vec<CoinSpendJson>,
}

/// `view_coin_spends` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewCoinSpendsResponse {
    /// The spend summary.
    pub summary: TransactionSummary,
}

/// `submit_transaction` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransaction {
    /// The signed spend bundle to broadcast.
    pub spend_bundle: SpendBundleJson,
}

/// `submit_transaction` response (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {}

// =============================================================================
// Offer suite + DID/NFT mint & transfer (design A.5/A.6 — #218 PR3)
// =============================================================================

/// The lifecycle status of a stored offer (Sage `OfferRecordStatus`). Wire values are
/// snake_case (`pending`/`active`/`completed`/`cancelled`/`expired`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferRecordStatus {
    /// Created but not yet observed on-chain / imported.
    Pending,
    /// Live and takeable.
    Active,
    /// Settled (taken).
    Completed,
    /// Cancelled by the maker.
    Cancelled,
    /// Past its expiry.
    Expired,
}

/// The royalty leg carried by an NFT asset in an offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftRoyalty {
    /// The royalty payout address.
    pub royalty_address: String,
    /// The royalty share in ten-thousandths (300 = 3%).
    pub royalty_basis_points: u16,
}

/// One side's asset leg in an [`OfferSummary`]: the asset, its amount, and any royalty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferAsset {
    /// The asset descriptor.
    pub asset: Asset,
    /// The amount in the asset's smallest unit.
    pub amount: Amount,
    /// The royalty amount owed on this leg (0 when none).
    pub royalty: Amount,
    /// The NFT royalty config, if this leg is an NFT.
    pub nft_royalty: Option<NftRoyalty>,
    /// Option-contract assets, if this leg is an option (out of scope this PR — always
    /// `null`; kept for wire-shape parity).
    pub option_assets: Option<serde_json::Value>,
}

/// A two-sided summary of an offer: what the maker gives (`maker`) and what the taker
/// must pay (`taker`), plus the fee and expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferSummary {
    /// The network fee reserved by the offer.
    pub fee: Amount,
    /// The assets the maker offers (the taker receives).
    pub maker: Vec<OfferAsset>,
    /// The assets the maker requests (the taker pays).
    pub taker: Vec<OfferAsset>,
    /// The block height the offer expires at, if bounded.
    pub expiration_height: Option<u32>,
    /// The timestamp the offer expires at, if bounded.
    pub expiration_timestamp: Option<u64>,
}

/// A stored offer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferRecord {
    /// The offer id (hex).
    pub offer_id: String,
    /// The bech32m `offer1…` string.
    pub offer: String,
    /// The offer's lifecycle status.
    pub status: OfferRecordStatus,
    /// The creation timestamp (unix seconds).
    pub creation_timestamp: u64,
    /// The two-sided summary.
    pub summary: OfferSummary,
}

/// A single asset amount in a `make_offer` requested/offered list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferAmount {
    /// The asset id (hex), or `None` for XCH.
    pub asset_id: Option<String>,
    /// The amount in the asset's smallest unit.
    pub amount: Amount,
}

/// `make_offer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeOffer {
    /// The assets the maker requests (the taker will pay these).
    pub requested_assets: Vec<OfferAmount>,
    /// The assets the maker offers (the taker will receive these).
    pub offered_assets: Vec<OfferAmount>,
    /// The network fee.
    pub fee: Amount,
    /// The address requested payments are sent to (defaults to the wallet's receive
    /// address).
    #[serde(default)]
    pub receive_address: Option<String>,
    /// An optional expiry (unix seconds).
    #[serde(default)]
    pub expires_at_second: Option<u64>,
    /// Whether to store the built offer in the wallet's offer list (default true).
    #[serde(default = "default_true")]
    pub auto_import: bool,
}
/// `make_offer` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeOfferResponse {
    /// The bech32m `offer1…` string.
    pub offer: String,
    /// The offer id (hex).
    pub offer_id: String,
}

/// `take_offer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeOffer {
    /// The bech32m `offer1…` string to take.
    pub offer: String,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}
/// `take_offer` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeOfferResponse {
    /// The spend summary of the combined take.
    pub summary: TransactionSummary,
    /// The combined (maker + taker), signed spend bundle.
    pub spend_bundle: SpendBundleJson,
    /// The transaction id (the bundle's name, hex).
    pub transaction_id: String,
}

/// `combine_offers` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombineOffers {
    /// The bech32m `offer1…` strings to combine.
    pub offers: Vec<String>,
}
/// `combine_offers` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombineOffersResponse {
    /// The combined bech32m `offer1…` string.
    pub offer: String,
}

/// `view_offer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewOffer {
    /// The bech32m `offer1…` string to inspect.
    pub offer: String,
}
/// `view_offer` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewOfferResponse {
    /// The two-sided summary.
    pub offer: OfferSummary,
    /// The offer's lifecycle status.
    pub status: OfferRecordStatus,
}

/// `get_offers` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetOffers {}
/// `get_offers` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOffersResponse {
    /// The wallet's stored offers.
    pub offers: Vec<OfferRecord>,
}

/// `get_offer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOffer {
    /// The offer id (hex).
    pub offer_id: String,
}
/// `get_offer` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOfferResponse {
    /// The stored offer.
    pub offer: OfferRecord,
}

/// `cancel_offer` request (returns [`TransactionResponse`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelOffer {
    /// The offer id (hex) to cancel.
    pub offer_id: String,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// `create_did` request (returns [`TransactionResponse`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDid {
    /// The DID's display name.
    pub name: String,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// A single NFT to mint in `bulk_mint_nfts` (Sage `NftMint`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMint {
    /// The address the minted NFT is created for (defaults to the wallet's receive
    /// address).
    #[serde(default)]
    pub address: Option<String>,
    /// The edition number within the collection.
    #[serde(default)]
    pub edition_number: Option<u32>,
    /// The total edition count.
    #[serde(default)]
    pub edition_total: Option<u32>,
    /// The data file content hash (hex).
    #[serde(default)]
    pub data_hash: Option<String>,
    /// The data file URIs.
    #[serde(default)]
    pub data_uris: Vec<String>,
    /// The metadata file content hash (hex).
    #[serde(default)]
    pub metadata_hash: Option<String>,
    /// The metadata file URIs.
    #[serde(default)]
    pub metadata_uris: Vec<String>,
    /// The license file content hash (hex).
    #[serde(default)]
    pub license_hash: Option<String>,
    /// The license file URIs.
    #[serde(default)]
    pub license_uris: Vec<String>,
    /// The royalty payout address (defaults to the mint address).
    #[serde(default)]
    pub royalty_address: Option<String>,
    /// The royalty share in ten-thousandths (300 = 3%).
    #[serde(default)]
    pub royalty_ten_thousandths: u16,
}

/// `bulk_mint_nfts` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkMintNfts {
    /// The NFTs to mint.
    pub mints: Vec<NftMint>,
    /// The minting DID's launcher id (hex or bech32m).
    pub did_id: String,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}
/// `bulk_mint_nfts` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkMintNftsResponse {
    /// The launcher ids of the minted NFTs (hex).
    pub nft_ids: Vec<String>,
    /// The spend summary.
    pub summary: TransactionSummary,
    /// The built coin spends (unsigned).
    pub coin_spends: Vec<CoinSpendJson>,
}

/// `transfer_nfts` request (returns [`TransactionResponse`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferNfts {
    /// The NFT ids to transfer (hex or bech32m).
    pub nft_ids: Vec<String>,
    /// The destination address.
    pub address: String,
    /// The network fee.
    pub fee: Amount,
    /// An optional clawback timeout (seconds).
    #[serde(default)]
    pub clawback: Option<u64>,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// `transfer_dids` request (returns [`TransactionResponse`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDids {
    /// The DID ids to transfer (hex or bech32m).
    pub did_ids: Vec<String>,
    /// The destination address.
    pub address: String,
    /// The network fee.
    pub fee: Amount,
    /// An optional clawback timeout (seconds).
    #[serde(default)]
    pub clawback: Option<u64>,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

// =============================================================================
// Options (design A.5 "Transactions" option-suite methods, #205 PR4).
// `get_options`/`get_option`/`mint_option`/`transfer_options` are served (`sage::options`);
// `exercise_options` is a documented follow-on (see `sage::options` module docs).
// =============================================================================

/// One side's asset spec in `mint_option` (Sage `OptionAsset`): the underlying or the
/// strike, by asset id (`None` = XCH) + amount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionAsset {
    /// The asset id (hex), or `None` for XCH.
    #[serde(default)]
    pub asset_id: Option<String>,
    /// The amount in the asset's smallest unit.
    pub amount: Amount,
}

/// `mint_option` request. This backend mints an XCH-underlying option (the underlying lock
/// coin holds plain XCH); the strike may be XCH or a CAT. See `sage::options` module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintOption {
    /// Seconds until the option expires (from the current time).
    pub expiration_seconds: u64,
    /// The underlying asset locked by the option (this backend: XCH only).
    pub underlying: OptionAsset,
    /// The asset the exerciser must pay to claim the underlying (XCH or CAT).
    pub strike: OptionAsset,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}
/// `mint_option` response (a distinct shape, like `bulk_mint_nfts`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintOptionResponse {
    /// The minted option's id (hex launcher id).
    pub option_id: String,
    /// The spend summary.
    pub summary: TransactionSummary,
    /// The built coin spends (unsigned).
    pub coin_spends: Vec<CoinSpendJson>,
}

/// `transfer_options` request (returns [`TransactionResponse`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOptions {
    /// The option ids to transfer (hex or bech32m).
    pub option_ids: Vec<String>,
    /// The destination address.
    pub address: String,
    /// The network fee.
    pub fee: Amount,
    /// An optional clawback timeout (seconds).
    #[serde(default)]
    pub clawback: Option<u64>,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// `exercise_options` request — accepted on the wire; the backend returns a clear
/// "not yet implemented" error (see `sage::options` module docs) rather than silently
/// mis-building a spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseOptions {
    /// The option ids to exercise (hex or bech32m).
    pub option_ids: Vec<String>,
    /// The network fee.
    pub fee: Amount,
    /// Whether to broadcast immediately (Sage default: false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// How to sort a `get_options` result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionSortMode {
    /// By name.
    Name,
    /// Most recent first (default).
    #[default]
    Recent,
}

/// A tracked option-contract record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionRecord {
    /// The option id (hex launcher id). Verified against the pinned v0.12.11 generated
    /// OpenAPI (design A.10): the real field is `launcher_id`, not `option_id` (this replica
    /// initially guessed `option_id` before the real schema was available — corrected).
    pub launcher_id: String,
    /// Whether visible in the wallet UI.
    pub visible: bool,
    /// The current coin id (hex).
    pub coin_id: String,
    /// The current owner (p2) address.
    pub address: String,
    /// The option singleton coin's own amount (1 mojo for a simple option).
    pub amount: Amount,
    /// The locked underlying asset descriptor.
    pub underlying_asset: Asset,
    /// The locked underlying amount.
    pub underlying_amount: Amount,
    /// The underlying-lock coin's id (hex).
    pub underlying_coin_id: String,
    /// The strike asset descriptor the exerciser must pay.
    pub strike_asset: Asset,
    /// The strike amount the exerciser must pay.
    pub strike_amount: Amount,
    /// Seconds until expiration (from mint time).
    pub expiration_seconds: u64,
    /// A display name, if set.
    #[serde(default)]
    pub name: Option<String>,
    /// The block height the current coin was created at.
    pub created_height: Option<u32>,
    /// The creation timestamp (unix seconds), if known.
    #[serde(default)]
    pub created_timestamp: Option<u64>,
}

/// `get_options` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOptions {
    /// Pagination offset.
    pub offset: u32,
    /// Pagination limit.
    pub limit: u32,
    /// Sort mode.
    #[serde(default)]
    pub sort_mode: OptionSortMode,
    /// Ascending order.
    #[serde(default)]
    pub ascending: bool,
    /// An optional free-text filter (matched against nothing yet — reserved for parity).
    #[serde(default)]
    pub find_value: Option<String>,
    /// Whether to include hidden options.
    #[serde(default)]
    pub include_hidden: bool,
}
/// `get_options` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOptionsResponse {
    /// The page of options.
    pub options: Vec<OptionRecord>,
    /// The total (unpaginated) count.
    pub total: u32,
}

/// `get_option` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOption {
    /// The option id (hex or bech32m).
    pub option_id: String,
}
/// `get_option` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetOptionResponse {
    /// The option, if tracked.
    pub option: Option<OptionRecord>,
}

// =============================================================================
// Actions — record-update methods (design A.5 "Actions", #205 PR4).
// =============================================================================

/// `resync_cat` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResyncCat {
    /// The CAT asset id (hex).
    pub asset_id: String,
}

/// `update_cat` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCat {
    /// The CAT record to persist (`asset_id` must be set).
    pub record: TokenRecord,
}

/// `update_did` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDid {
    /// The DID id (hex or bech32m).
    pub did_id: String,
    /// The new display name, if changing it.
    #[serde(default)]
    pub name: Option<String>,
    /// The new visibility.
    pub visible: bool,
}

/// `update_option` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOption {
    /// The option id (hex or bech32m).
    pub option_id: String,
    /// The new visibility.
    pub visible: bool,
}

/// `update_nft` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNft {
    /// The NFT id (hex or bech32m).
    pub nft_id: String,
    /// The new visibility.
    pub visible: bool,
}

/// `update_nft_collection` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNftCollection {
    /// The collection id.
    pub collection_id: String,
    /// The new visibility.
    pub visible: bool,
}

/// `redownload_nft` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedownloadNft {
    /// The NFT id (hex or bech32m).
    pub nft_id: String,
}

/// `increase_derivation_index` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncreaseDerivationIndex {
    /// Raise the hardened-tree floor.
    #[serde(default)]
    pub hardened: Option<bool>,
    /// Raise the unhardened-tree floor.
    #[serde(default)]
    pub unhardened: Option<bool>,
    /// The index to guarantee coverage up to.
    pub index: u32,
}

/// An empty response shared by every action method above (`{}`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ActionResponse {}

// =============================================================================
// Themes — the Sage-desktop-UI theme store (design A.5 "Themes", #205 PR4).
// =============================================================================

/// `get_user_themes` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetUserThemes {}
/// `get_user_themes` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserThemesResponse {
    /// Every NFT id with a saved theme.
    pub themes: Vec<String>,
}

/// `get_user_theme` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserTheme {
    /// The NFT id the theme is themed after.
    pub nft_id: String,
}
/// `get_user_theme` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetUserThemeResponse {
    /// The saved theme, if any.
    pub theme: Option<String>,
}

/// `save_user_theme` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveUserTheme {
    /// The NFT id the theme is themed after. Verified against the pinned v0.12.11 generated
    /// OpenAPI (design A.10): the real request carries ONLY `nft_id` — Sage derives the
    /// theme from the NFT's own artwork rather than accepting caller-supplied content (this
    /// replica initially guessed a `theme: String` field before the real schema was
    /// available — corrected; see `crate::sage::themes` module docs for what this backend
    /// stores in lieu of real color-extraction).
    pub nft_id: String,
}

/// `delete_user_theme` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserTheme {
    /// The NFT id whose theme to delete.
    pub nft_id: String,
}

// =============================================================================
// Network / peers / settings (design A.5, #205 PR4).
// =============================================================================

/// `get_peers` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetPeers {}
/// `get_peers` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPeersResponse {
    /// The tracked (non-banned) peers.
    pub peers: Vec<PeerRecord>,
}

/// `add_peer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPeer {
    /// The peer's IP address.
    pub ip: String,
}

/// `remove_peer` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePeer {
    /// The peer's IP address.
    pub ip: String,
    /// Whether to ban the peer (kept, but excluded from `get_peers`) instead of forgetting it.
    #[serde(default)]
    pub ban: bool,
}

/// `set_discover_peers` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SetDiscoverPeers {
    /// Whether peer discovery (DNS introducers) is enabled.
    pub discover_peers: bool,
}

/// `set_target_peers` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SetTargetPeers {
    /// The target number of connected peers.
    pub target_peers: u32,
}

/// `set_network` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNetwork {
    /// The network id to switch to (e.g. `mainnet`/`testnet11`).
    pub name: String,
}

/// `set_network_override` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetNetworkOverride {
    /// The wallet fingerprint the override applies to (one active wallet in this backend).
    pub fingerprint: u32,
    /// The network id override, or `None` to clear it.
    #[serde(default)]
    pub name: Option<String>,
}

/// A known Chia network's connection parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// The network id (`mainnet`/`testnet11`).
    pub name: String,
    /// The native asset ticker.
    pub ticker: String,
    /// The bech32m address prefix.
    pub address_prefix: String,
    /// Decimal precision.
    pub precision: u8,
    /// The default full-node peer port.
    pub default_port: u16,
}

/// Whether a network is the production mainnet or a test network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    /// The production Chia network.
    Mainnet,
    /// A test network.
    Testnet,
    /// An unrecognized/unconfigured network id. Verified against the pinned v0.12.11
    /// generated OpenAPI (design A.10): the real enum has three variants, not two.
    Unknown,
}

/// `get_networks` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetNetworks {}
/// `get_networks` response (Sage's `NetworkList`): every known network by id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkList {
    /// Known networks, keyed by network id.
    pub networks: std::collections::BTreeMap<String, Network>,
}

/// `get_network` request (empty).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetNetwork {}
/// `get_network` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNetworkResponse {
    /// The currently-active network.
    pub network: Network,
    /// Its kind.
    pub kind: NetworkKind,
}

/// `set_delta_sync` request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SetDeltaSync {
    /// Whether delta-sync is enabled.
    pub delta_sync: bool,
}

/// `set_delta_sync_override` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetDeltaSyncOverride {
    /// The wallet fingerprint the override applies to.
    pub fingerprint: u32,
    /// The delta-sync override, or `None` to clear it.
    #[serde(default)]
    pub delta_sync: Option<bool>,
}

/// `set_change_address` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetChangeAddress {
    /// The wallet fingerprint the override applies to.
    pub fingerprint: u32,
    /// The change-address override, or `None` to clear it (use the wallet's own).
    #[serde(default)]
    pub change_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_serializes_number_below_threshold() {
        // A normal mojo amount is a bare JSON number.
        assert_eq!(
            serde_json::to_string(&Amount::u64(1_000_000)).unwrap(),
            "1000000"
        );
        // Exactly at the threshold is still a number.
        assert_eq!(
            serde_json::to_string(&Amount::u64(MAX_JS_SAFE_INTEGER)).unwrap(),
            "9007199254740991"
        );
    }

    #[test]
    fn amount_serializes_string_above_threshold() {
        // One above the threshold flips to a JSON string (JS-safe).
        assert_eq!(
            serde_json::to_string(&Amount::u64(MAX_JS_SAFE_INTEGER + 1)).unwrap(),
            "\"9007199254740992\""
        );
    }

    #[test]
    fn amount_deserializes_from_number_and_string() {
        let n: Amount = serde_json::from_str("42").unwrap();
        assert_eq!(n.to_u64(), Some(42));
        let s: Amount = serde_json::from_str("\"9007199254740992\"").unwrap();
        assert_eq!(s.to_u64(), Some(9_007_199_254_740_992));
    }

    #[test]
    fn enums_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&AssetKind::Token).unwrap(),
            "\"token\""
        );
        assert_eq!(serde_json::to_string(&AssetKind::Nft).unwrap(), "\"nft\"");
        assert_eq!(
            serde_json::to_string(&AddressKind::External).unwrap(),
            "\"external\""
        );
        assert_eq!(
            serde_json::to_string(&CoinFilterMode::Selectable).unwrap(),
            "\"selectable\""
        );
        assert_eq!(
            serde_json::to_string(&NftSortMode::Recent).unwrap(),
            "\"recent\""
        );
        assert_eq!(serde_json::to_string(&KeyKind::Bls).unwrap(), "\"bls\"");
    }

    #[test]
    fn coin_record_emits_null_for_none_fields_in_declaration_order() {
        // Sage does NOT skip None — byte-parity requires emitting `null` in field order.
        let rec = CoinRecord {
            coin_id: "aa".into(),
            address: "xch1".into(),
            amount: Amount::u64(5),
            transaction_id: None,
            offer_id: None,
            clawback_timestamp: None,
            created_height: Some(100),
            spent_height: None,
            spent_timestamp: None,
            created_timestamp: Some(1234),
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert_eq!(
            json,
            r#"{"coin_id":"aa","address":"xch1","amount":5,"transaction_id":null,"offer_id":null,"clawback_timestamp":null,"created_height":100,"spent_height":null,"spent_timestamp":null,"created_timestamp":1234}"#
        );
    }

    #[test]
    fn empty_request_response_is_empty_object() {
        assert_eq!(serde_json::to_string(&LoginResponse {}).unwrap(), "{}");
        assert_eq!(serde_json::to_string(&GetSyncStatus {}).unwrap(), "{}");
    }

    #[test]
    fn coin_query_enums_default_to_sage_defaults() {
        assert_eq!(CoinSortMode::default(), CoinSortMode::CreatedHeight);
        assert_eq!(CoinFilterMode::default(), CoinFilterMode::Selectable);
    }

    #[test]
    fn get_coins_request_omits_defaultable_fields() {
        // A minimal request (only the required offset/limit) deserializes with defaults.
        let req: GetCoins = serde_json::from_str(r#"{"offset":0,"limit":10}"#).unwrap();
        assert_eq!(req.sort_mode, CoinSortMode::CreatedHeight);
        assert_eq!(req.filter_mode, CoinFilterMode::Selectable);
        assert!(!req.ascending);
        assert!(req.asset_id.is_none());
    }

    #[test]
    fn coin_spend_json_round_trips_byte_identically() {
        let cs = CoinSpendJson {
            coin: CoinJson {
                parent_coin_info: "aa".into(),
                puzzle_hash: "bb".into(),
                amount: Amount::u64(7),
            },
            puzzle_reveal: "ff01".into(),
            solution: "80".into(),
        };
        assert_eq!(
            serde_json::to_string(&cs).unwrap(),
            r#"{"coin":{"parent_coin_info":"aa","puzzle_hash":"bb","amount":7},"puzzle_reveal":"ff01","solution":"80"}"#
        );
    }

    #[test]
    fn transaction_response_matches_sage_shape() {
        let resp = TransactionResponse {
            summary: TransactionSummary {
                fee: Amount::u64(10),
                inputs: vec![TransactionInput {
                    coin_id: "c0".into(),
                    amount: Amount::u64(100),
                    address: "xch1a".into(),
                    asset: None,
                    outputs: vec![TransactionOutput {
                        coin_id: "c1".into(),
                        amount: Amount::u64(90),
                        address: "xch1b".into(),
                        receiving: false,
                        burning: false,
                    }],
                }],
            },
            coin_spends: vec![],
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"summary":{"fee":10,"inputs":[{"coin_id":"c0","amount":100,"address":"xch1a","asset":null,"outputs":[{"coin_id":"c1","amount":90,"address":"xch1b","receiving":false,"burning":false}]}]},"coin_spends":[]}"#
        );
    }

    #[test]
    fn send_xch_request_defaults_auto_submit_true_and_empty_memos() {
        let r: SendXch = serde_json::from_str(r#"{"address":"xch1x","amount":5,"fee":0}"#).unwrap();
        assert!(r.auto_submit, "auto_submit defaults to true (Sage parity)");
        assert!(r.memos.is_empty());
        assert!(r.clawback.is_none());
    }

    #[test]
    fn send_cat_request_defaults_include_hint_true() {
        let r: SendCat = serde_json::from_str(
            r#"{"asset_id":"dead","address":"xch1x","amount":5,"fee":0,"auto_submit":false}"#,
        )
        .unwrap();
        assert!(r.include_hint, "include_hint defaults to true");
        assert!(!r.auto_submit);
    }

    #[test]
    fn empty_submit_transaction_response_is_empty_object() {
        assert_eq!(
            serde_json::to_string(&SubmitTransactionResponse {}).unwrap(),
            "{}"
        );
    }

    // ---- #205 PR4: options/actions/themes/network wire shapes ----------------

    #[test]
    fn option_sort_mode_is_snake_case_and_defaults_to_recent() {
        assert_eq!(
            serde_json::to_string(&OptionSortMode::Name).unwrap(),
            "\"name\""
        );
        assert_eq!(OptionSortMode::default(), OptionSortMode::Recent);
    }

    #[test]
    fn mint_option_request_defaults_auto_submit_false() {
        let r: MintOption = serde_json::from_str(
            r#"{"expiration_seconds":3600,"underlying":{"amount":1000},"strike":{"amount":500},"fee":0}"#,
        )
        .unwrap();
        assert!(r.underlying.asset_id.is_none());
        assert!(r.strike.asset_id.is_none());
        assert!(
            !r.auto_submit,
            "auto_submit defaults to false (Sage parity)"
        );
    }

    #[test]
    fn mint_option_response_matches_distinct_shape() {
        let resp = MintOptionResponse {
            option_id: "abc".into(),
            summary: TransactionSummary {
                fee: Amount::u64(0),
                inputs: vec![],
            },
            coin_spends: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.starts_with(r#"{"option_id":"abc","summary""#));
    }

    #[test]
    fn action_response_is_empty_object() {
        assert_eq!(serde_json::to_string(&ActionResponse {}).unwrap(), "{}");
    }

    #[test]
    fn increase_derivation_index_request_omits_defaultable_fields() {
        let r: IncreaseDerivationIndex = serde_json::from_str(r#"{"index":5}"#).unwrap();
        assert!(r.hardened.is_none());
        assert!(r.unhardened.is_none());
        assert_eq!(r.index, 5);
    }

    #[test]
    fn theme_requests_round_trip() {
        // Verified against the pinned v0.12.11 generated OpenAPI: `save_user_theme`'s
        // request carries ONLY `nft_id` (no caller-supplied theme content).
        let save: SaveUserTheme = serde_json::from_str(r#"{"nft_id":"n1"}"#).unwrap();
        assert_eq!(save.nft_id, "n1");
        let resp = GetUserThemesResponse {
            themes: vec!["n1".into()],
        };
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            r#"{"themes":["n1"]}"#
        );
    }

    #[test]
    fn network_kind_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&NetworkKind::Mainnet).unwrap(),
            "\"mainnet\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkKind::Testnet).unwrap(),
            "\"testnet\""
        );
        // Verified against the pinned v0.12.11 generated OpenAPI: the real enum has a third
        // `unknown` variant.
        assert_eq!(
            serde_json::to_string(&NetworkKind::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn remove_peer_request_defaults_ban_false() {
        let r: RemovePeer = serde_json::from_str(r#"{"ip":"1.2.3.4"}"#).unwrap();
        assert!(!r.ban);
    }

    #[test]
    fn get_peers_response_shape() {
        let resp = GetPeersResponse {
            peers: vec![PeerRecord {
                ip_addr: "1.2.3.4".into(),
                port: 8444,
                peak_height: 0,
                user_managed: true,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ip_addr\":\"1.2.3.4\""));
        assert!(json.contains("\"user_managed\":true"));
    }
}
