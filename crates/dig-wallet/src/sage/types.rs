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
}
