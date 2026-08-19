//! The local SQLite wallet database (design **B.6**).
//!
//! Mirrors `sage-wallet`'s relational store: coins/CATs/NFTs/DIDs/derivations + the
//! synced peak, keyed by the wallet's hardened AND unhardened HD puzzle hashes (+ CAT
//! hints). SQLite via `sqlx` (NOT RocksDB — B.6): the workload is relational, multi-index
//! and small (one wallet). Indexes on `puzzle_hash`, `asset_id`, a **partial** index on
//! unspent (`spent_height IS NULL`), and `created_height`; WAL enabled for file DBs.
//!
//! This is the source of truth for a *synced* wallet's data ([`crate::sage::routing`]
//! gates reads on [`WalletDb::is_synced`]). The [`crate::sage::sync`] loop is the only
//! writer of chain state; reorgs call [`WalletDb::rollback_above`].
//!
//! Amounts are stored as **decimal TEXT** (full `u64`/`u128` range, no `i64` overflow);
//! heights/timestamps as INTEGER (`i64`) and narrowed to `u32`/`u64` at the wire boundary.

use std::str::FromStr;

use dig_node_control_interface::params::MAX_BANNED_CHIA_PEERS;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use super::arrivals::{classify, Arrival, ArrivalBaseline, Verdict};
use super::coverage::CoveredSet;
use super::sync::AdmittedPeak;

/// A handle to the local wallet database.
#[derive(Clone)]
pub struct WalletDb {
    pool: SqlitePool,
    /// The row budgets the two chain caches are evicted back to on every write
    /// (dig_ecosystem#3035). A field rather than a constant read at the call site so a test can
    /// pin a SMALL budget and prove both sides of the bound — at budget nothing is evicted, one
    /// over evicts exactly the least-recently-used row — without writing fifty thousand rows to
    /// find out.
    chain_cache_budgets: ChainCacheBudgets,
}

/// The synced chain state gating [`crate::sage::routing`].
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// The highest block height the wallet DB has processed for its puzzle hashes.
    pub peak_height: Option<u32>,
    /// The header hash at `peak_height`.
    pub header_hash: Option<String>,
    /// Whether the initial puzzle-state catch-up has completed. Until this is `true`,
    /// wallet-data reads route to the coinset fallback so the caller never waits.
    pub initial_sync_complete: bool,
    /// The puzzle-hash set the completed catch-up actually COVERED
    /// ([`crate::sage::coverage::CoveredSet`]), or `None` where no sync has recorded one.
    ///
    /// `initial_sync_complete` says a catch-up finished; this says over WHICH addresses. The read
    /// router needs both, because the followed set can widen after a catch-up completes
    /// (dig_ecosystem#2871). `None` — a pre-#2871 replica — covers nothing: fail closed.
    pub covered: Option<CoveredSet>,
}

/// A coin row (chain state for one coin the wallet tracks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinRow {
    /// The coin id (hex, 64 chars).
    pub coin_id: String,
    /// The parent coin id (hex).
    pub parent_coin_info: String,
    /// The puzzle hash (hex).
    pub puzzle_hash: String,
    /// The amount, decimal string.
    pub amount: String,
    /// The created block height, if confirmed.
    pub created_height: Option<i64>,
    /// The spent block height, if spent.
    pub spent_height: Option<i64>,
    /// The CAT asset id (hex), or `None` for XCH.
    pub asset_id: Option<String>,
    /// The coin's hint (hex), used to associate CAT coins with a puzzle hash.
    pub hint: Option<String>,
    /// The created timestamp.
    pub created_timestamp: Option<i64>,
    /// The spent timestamp.
    pub spent_timestamp: Option<i64>,
}

/// One coin's cached ARBITRARY chain read: the record, and the spend if the coin is spent
/// (dig_ecosystem#3032).
///
/// Separate from [`CoinRow`] on purpose. `coins` is the wallet's REPLICA — coins at the addresses
/// this node subscribes to, maintained by the sync supervisor, and authoritative for balances.
/// This table is a cache of coins the node does NOT watch, learned by asking peers, and it must
/// never be mistaken for the replica: a lineage walk reaches strangers' coins, and a balance
/// computed over them would be somebody else's money.
///
/// # Keyed on the coin id, which is the coin's own hash
///
/// `SHA256(parent ‖ puzzle_hash ‖ amount)`. So an entry cannot be WRONG for its key — those three
/// fields are the key — it can only be absent, or stale in the two fields the key does not cover:
/// `spent_height` and `spent_timestamp`. That is why freshness is judged on spentness alone; see
/// [`super::peer_reads::cache_entry_is_usable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReadCacheRow {
    /// The coin id (lowercase hex, no `0x`) — the cache key.
    pub coin_id: String,
    /// The parent coin id (hex).
    pub parent_coin_info: String,
    /// The puzzle hash (hex).
    pub puzzle_hash: String,
    /// The amount, decimal string (as `coins.amount`, so a u64 near the ceiling survives SQLite).
    pub amount: String,
    /// The created block height, if confirmed.
    pub created_height: Option<i64>,
    /// The spent block height, if spent. `None` is what makes this entry perishable.
    pub spent_height: Option<i64>,
    /// The created timestamp.
    pub created_timestamp: Option<i64>,
    /// The spent timestamp.
    pub spent_timestamp: Option<i64>,
    /// Unix seconds at which this entry was written — the input to the perishable-entry rule.
    pub cached_at: i64,
}

/// One coin's cached SPEND: the coin that was consumed and the two programs that consumed it
/// (dig_ecosystem#3032).
///
/// It carries NO timestamp because it needs none. A spend is immutable — the coin is gone, and the
/// puzzle and solution that spent it are fixed forever — so unlike [`ChainReadCacheRow`] there is
/// nothing here that can become stale. This is the asymmetry the ticket turns on: a lineage walk
/// touches a spent coin at every generation but the last, so almost the whole walk is permanently
/// cacheable and only its tip must be re-asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSpendCacheRow {
    /// The spent coin's id (lowercase hex, no `0x`) — the cache key.
    pub coin_id: String,
    /// The spent coin's parent coin id (hex).
    pub parent_coin_info: String,
    /// The spent coin's puzzle hash (hex).
    pub puzzle_hash: String,
    /// The spent coin's amount, decimal string.
    pub amount: String,
    /// The puzzle reveal: hex of the serialized CLVM program, no `0x`.
    pub puzzle_reveal: String,
    /// The solution the puzzle ran with: hex of the serialized CLVM, no `0x`.
    pub solution: String,
}

/// A CAT metadata row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatRow {
    /// The asset id (hex).
    pub asset_id: String,
    /// Human-readable name.
    pub name: Option<String>,
    /// Ticker symbol.
    pub ticker: Option<String>,
    /// Decimal precision.
    pub precision: i64,
    /// Description.
    pub description: Option<String>,
    /// Icon URL.
    pub icon_url: Option<String>,
    /// Whether visible in the wallet UI.
    pub visible: bool,
}

/// A single HD derivation the wallet has registered/subscribed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationRow {
    /// Whether this is a hardened derivation.
    pub hardened: bool,
    /// The derivation index.
    pub index: i64,
    /// The derived public key (hex).
    pub public_key: String,
    /// The derived puzzle hash (hex).
    pub puzzle_hash: String,
    /// The derived address (bech32m).
    pub address: String,
}

/// A reconstructed NFT row: filter columns + the full serialized `NftRecord` wire JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftDbRow {
    /// The launcher (singleton) id (hex).
    pub launcher_id: String,
    /// The current coin id (hex).
    pub coin_id: String,
    /// The collection id, if resolved.
    pub collection_id: Option<String>,
    /// The minter DID, if known.
    pub minter_did: Option<String>,
    /// The current owner DID, if assigned.
    pub owner_did: Option<String>,
    /// Human-readable name, if known.
    pub name: Option<String>,
    /// Whether visible in the wallet UI.
    pub visible: bool,
    /// The block height the current coin was created at.
    pub created_height: Option<i64>,
    /// The serialized `NftRecord` (the Sage wire record) for byte-parity reads.
    pub record_json: String,
}

/// A reconstructed DID row: the launcher/coin + the full serialized `DidRecord` wire JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidDbRow {
    /// The launcher (singleton) id (hex).
    pub launcher_id: String,
    /// The current coin id (hex).
    pub coin_id: String,
    /// Human-readable name, if assigned.
    pub name: Option<String>,
    /// Whether visible in the wallet UI.
    pub visible: bool,
    /// The block height the current coin was created at.
    pub created_height: Option<i64>,
    /// The serialized `DidRecord` (the Sage wire record) for byte-parity reads.
    pub record_json: String,
}

/// An NFT-collection row: the id/DID + the full serialized `NftCollectionRecord` wire JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCollectionDbRow {
    /// The collection id.
    pub collection_id: String,
    /// The DID that minted the collection.
    pub did_id: String,
    /// The metadata collection id.
    pub metadata_collection_id: String,
    /// Human-readable name.
    pub name: Option<String>,
    /// Whether visible in the wallet UI.
    pub visible: bool,
    /// The serialized `NftCollectionRecord` (the Sage wire record) for byte-parity reads.
    pub record_json: String,
}

/// A stored offer row: the `offer1…` string + its status + the full serialized
/// `OfferSummary` wire JSON (so `get_offers`/`get_offer` reads are byte-parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferDbRow {
    /// The offer id (hex).
    pub offer_id: String,
    /// The bech32m `offer1…` string.
    pub offer: String,
    /// The offer's lifecycle status (snake_case wire token).
    pub status: String,
    /// The creation timestamp (unix seconds).
    pub creation_timestamp: i64,
    /// The serialized `OfferSummary` (the Sage wire summary) for byte-parity reads.
    pub summary_json: String,
}

/// A saved Sage-desktop-UI theme, keyed by the NFT id it is themed after (#205 PR4 §18.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeRow {
    /// The NFT id (hex launcher id) the theme is themed after.
    pub nft_id: String,
    /// The theme content (an opaque string; the desktop UI's own encoding).
    pub theme: String,
}

/// A stored option-contract row: the singleton/coin identity + the full serialized
/// `OptionRecord`-equivalent wire JSON (#205 PR4 §18.15/options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionDbRow {
    /// The option launcher (singleton) id (hex).
    pub option_id: String,
    /// The current coin id (hex).
    pub coin_id: String,
    /// The underlying-lock coin's id (hex) — what the option, once exercised, releases.
    pub underlying_coin_id: String,
    /// The underlying delegated-puzzle tree hash (hex) — part of the option's on-chain info.
    pub underlying_delegated_puzzle_hash: String,
    /// The current p2 (owner) puzzle hash (hex).
    pub p2_puzzle_hash: String,
    /// Whether visible in the wallet UI.
    pub visible: bool,
    /// The block height the current coin was created at.
    pub created_height: Option<i64>,
    /// The serialized wire record (`OptionRecord`-shaped JSON) for byte-parity reads.
    pub record_json: String,
}

/// A tracked peer (#205 PR4 §18.16). Manually added (`add_peer`) peers persist here across
/// restarts, mirroring Sage's `user_managed` peers; `peak_height` is 0 until this node's
/// bring-up wires live per-peer telemetry (SPEC §18.16) — never fabricated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    /// The peer's IP address.
    pub ip_addr: String,
    /// The peer's port.
    pub port: i64,
    /// The peer's last-known peak height (0 if unknown).
    pub peak_height: i64,
    /// Whether the peer was added manually by the user (`add_peer`).
    pub user_managed: bool,
    /// Whether the peer is banned (`remove_peer { ban: true }`) — excluded from `get_peers`.
    pub banned: bool,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    peak_height INTEGER,
    header_hash TEXT,
    initial_sync_complete INTEGER NOT NULL DEFAULT 0,
    arrival_baseline_height INTEGER,
    covered_puzzle_hashes TEXT
);
INSERT OR IGNORE INTO sync_state (id, peak_height, header_hash, initial_sync_complete)
    VALUES (0, NULL, NULL, 0);

CREATE TABLE IF NOT EXISTS arrivals (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    coin_id TEXT NOT NULL UNIQUE,
    puzzle_hash TEXT NOT NULL,
    amount TEXT NOT NULL,
    asset_id TEXT,
    confirmed_height INTEGER NOT NULL,
    recorded_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS arrival_pending (
    coin_id TEXT PRIMARY KEY,
    created_height INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS derivations (
    hardened INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    puzzle_hash TEXT NOT NULL,
    address TEXT NOT NULL,
    PRIMARY KEY (hardened, idx)
);
CREATE INDEX IF NOT EXISTS idx_derivations_ph ON derivations (puzzle_hash);

CREATE TABLE IF NOT EXISTS coins (
    coin_id TEXT PRIMARY KEY,
    parent_coin_info TEXT NOT NULL,
    puzzle_hash TEXT NOT NULL,
    amount TEXT NOT NULL,
    created_height INTEGER,
    spent_height INTEGER,
    asset_id TEXT,
    hint TEXT,
    created_timestamp INTEGER,
    spent_timestamp INTEGER
);
CREATE INDEX IF NOT EXISTS idx_coins_ph ON coins (puzzle_hash);
CREATE INDEX IF NOT EXISTS idx_coins_asset ON coins (asset_id);
CREATE INDEX IF NOT EXISTS idx_coins_unspent ON coins (asset_id) WHERE spent_height IS NULL;
CREATE INDEX IF NOT EXISTS idx_coins_created_height ON coins (created_height);

CREATE TABLE IF NOT EXISTS cats (
    asset_id TEXT PRIMARY KEY,
    name TEXT,
    ticker TEXT,
    precision INTEGER NOT NULL DEFAULT 3,
    description TEXT,
    icon_url TEXT,
    visible INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS nfts (
    launcher_id TEXT PRIMARY KEY,
    coin_id TEXT NOT NULL,
    collection_id TEXT,
    minter_did TEXT,
    owner_did TEXT,
    name TEXT,
    metadata_json TEXT,
    visible INTEGER NOT NULL DEFAULT 1,
    created_height INTEGER,
    record_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_nfts_collection ON nfts (collection_id);

CREATE TABLE IF NOT EXISTS dids (
    launcher_id TEXT PRIMARY KEY,
    coin_id TEXT NOT NULL,
    name TEXT,
    visible INTEGER NOT NULL DEFAULT 1,
    created_height INTEGER,
    record_json TEXT
);

CREATE TABLE IF NOT EXISTS nft_collections (
    collection_id TEXT PRIMARY KEY,
    did_id TEXT NOT NULL,
    metadata_collection_id TEXT NOT NULL,
    name TEXT,
    icon TEXT,
    visible INTEGER NOT NULL DEFAULT 1,
    record_json TEXT
);

CREATE TABLE IF NOT EXISTS offers (
    offer_id TEXT PRIMARY KEY,
    offer TEXT NOT NULL,
    status TEXT NOT NULL,
    creation_timestamp INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_offers_created ON offers (creation_timestamp);

CREATE TABLE IF NOT EXISTS user_themes (
    nft_id TEXT PRIMARY KEY,
    theme TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS options (
    option_id TEXT PRIMARY KEY,
    coin_id TEXT NOT NULL,
    underlying_coin_id TEXT NOT NULL,
    underlying_delegated_puzzle_hash TEXT NOT NULL,
    p2_puzzle_hash TEXT NOT NULL,
    visible INTEGER NOT NULL DEFAULT 1,
    created_height INTEGER,
    record_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
    ip_addr TEXT PRIMARY KEY,
    port INTEGER NOT NULL,
    peak_height INTEGER NOT NULL DEFAULT 0,
    user_managed INTEGER NOT NULL DEFAULT 0,
    banned INTEGER NOT NULL DEFAULT 0,
    banned_at INTEGER
);

CREATE TABLE IF NOT EXISTS network_settings (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    discover_peers INTEGER NOT NULL DEFAULT 1,
    target_peers INTEGER NOT NULL DEFAULT 3,
    network_override TEXT,
    delta_sync INTEGER NOT NULL DEFAULT 1,
    delta_sync_override INTEGER,
    change_address TEXT,
    derivation_floor_hardened INTEGER NOT NULL DEFAULT 0,
    derivation_floor_unhardened INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO network_settings (id) VALUES (0);

CREATE TABLE IF NOT EXISTS chain_read_cache (
    coin_id TEXT PRIMARY KEY,
    parent_coin_info TEXT NOT NULL,
    puzzle_hash TEXT NOT NULL,
    amount TEXT NOT NULL,
    created_height INTEGER,
    spent_height INTEGER,
    created_timestamp INTEGER,
    spent_timestamp INTEGER,
    cached_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chain_spend_cache (
    coin_id TEXT PRIMARY KEY,
    parent_coin_info TEXT NOT NULL,
    puzzle_hash TEXT NOT NULL,
    amount TEXT NOT NULL,
    puzzle_reveal TEXT NOT NULL,
    solution TEXT NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0
);
"#;

/// Additive column migrations for wallet DBs created before #216 (§5.1 additive-only): the
/// singleton-record tables gained a `record_json` column holding the full serialized Sage
/// wire record. `CREATE TABLE IF NOT EXISTS` does not add columns to a pre-existing table,
/// so these `ALTER TABLE … ADD COLUMN` statements run idempotently (a duplicate-column error
/// on an already-migrated DB is ignored).
const ADD_COLUMN_MIGRATIONS: &[&str] = &[
    "ALTER TABLE nfts ADD COLUMN record_json TEXT",
    "ALTER TABLE dids ADD COLUMN record_json TEXT",
    "ALTER TABLE nft_collections ADD COLUMN record_json TEXT",
    // dig_ecosystem#2548. A pre-#2548 wallet DB has coins but no arrival baseline, and the column
    // arrives NULL — which is exactly right: an existing replica has never established a line
    // between history and news, so it records nothing until the next completed catch-up arms it.
    "ALTER TABLE sync_state ADD COLUMN arrival_baseline_height INTEGER",
    // dig_ecosystem#2871. A pre-#2871 wallet DB may hold `initial_sync_complete = 1` from a
    // catch-up whose covered set was never recorded, and the column arrives NULL. That is the
    // fail-closed answer: coverage is unknown, so no address is treated as replica-backed until
    // the next catch-up records the set it ran over.
    "ALTER TABLE sync_state ADD COLUMN covered_puzzle_hashes TEXT",
    // dig_ecosystem#3035. A wallet DB written by #3032 has cache rows but no record of when each
    // was last USED, and the column arrives at its `0` default — the oldest possible last-use, so
    // pre-existing rows are the first evicted. That is the right direction: nothing in the old
    // shape tells us which of them a lineage walk still re-reads, and re-asking the peers costs a
    // round trip while keeping the wrong rows costs the budget.
    "ALTER TABLE chain_read_cache ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE chain_spend_cache ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0",
    // When a ban was recorded, so the bounded ban list (dig-node-control-interface's
    // `MAX_BANNED_CHIA_PEERS`) can evict its OLDEST entry rather than refuse the newest. NULL on
    // rows banned before this column existed, which sorts them first and so evicts them first --
    // the right order, since they are by definition the oldest bans on the machine.
    "ALTER TABLE peers ADD COLUMN banned_at INTEGER",
];

/// Indexes that depend on a column [`ADD_COLUMN_MIGRATIONS`] may only just have added, so they
/// cannot live in [`SCHEMA`]: on a legacy DB the index would be created against a column that does
/// not exist yet, and `SCHEMA` is executed strictly, before the migrations.
const POST_MIGRATION_INDEXES: &[&str] = &[
    // The eviction order is `ORDER BY last_used_at`, run on every cache write (dig_ecosystem#3035).
    "CREATE INDEX IF NOT EXISTS idx_chain_read_cache_last_used ON chain_read_cache (last_used_at)",
    "CREATE INDEX IF NOT EXISTS idx_chain_spend_cache_last_used ON chain_spend_cache (last_used_at)",
];

// ---- chain-read cache budget (dig_ecosystem#3035) -------------------------
//
// `control.wallet.coinById` is an OPEN, token-less method — remotely reachable under
// `DIG_NODE_ALLOW_REMOTE` — and every distinct coin id it is asked for writes a cache row. The rate
// limiter bounds the RATE, never the TOTAL, so without a budget sustained querying grows the wallet
// DB without limit on a node that is otherwise careful about disk.
//
// Shortening the TTLs is the wrong lever and is deliberately not used: a lineage walk touches a
// SPENT coin at every generation but the last, and the permanence of those rows is the property
// that makes the walk affordable. The budget bounds the SIZE instead, and evicts by recency of
// USE — the rows worth keeping are the ones a walk re-reads, not the ones most recently written.

/// How many coin RECORDS the chain-read cache keeps.
///
/// A row is a handful of hex fields and two integers — call it 400 bytes with SQLite's overhead —
/// so 50 000 rows is roughly **20 MiB**. Deliberately small beside the node's other on-disk caches
/// so the three read together: the capsule cache defaults to 1 GiB (`DIG_NODE_CACHE_CAP`) and the
/// content cache to 256 MiB. This cache stores answers that can always be re-asked in one round
/// trip, so it gets the smallest share.
pub const CHAIN_READ_CACHE_MAX_ROWS: i64 = 50_000;

/// How many SPENDS the chain-spend cache keeps.
///
/// A fifth of the record budget for the same total, because a spend row is dominated by its puzzle
/// reveal and solution — CLVM programs in hex, commonly a few KiB — so 10 000 rows is roughly
/// **40 MiB**. Together the two tables are bounded by about **60 MiB**, a quarter of the content
/// cache and a sixteenth of the capsule cache.
pub const CHAIN_SPEND_CACHE_MAX_ROWS: i64 = 10_000;

/// The row budgets the two chain caches are held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainCacheBudgets {
    /// Rows kept in `chain_read_cache`.
    pub reads: i64,
    /// Rows kept in `chain_spend_cache`.
    pub spends: i64,
}

impl Default for ChainCacheBudgets {
    fn default() -> Self {
        Self {
            reads: CHAIN_READ_CACHE_MAX_ROWS,
            spends: CHAIN_SPEND_CACHE_MAX_ROWS,
        }
    }
}

/// Which of the two chain caches a size question is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainCacheTable {
    /// `chain_read_cache` — coin records.
    Reads,
    /// `chain_spend_cache` — coin spends.
    Spends,
}

/// Mark a cache row as used NOW, so eviction ranks it by recency of USE rather than of insertion.
///
/// `table` is one of two literals chosen by this module, never caller input: the column set differs
/// between the two tables, so they cannot share a prepared statement, and a table name cannot be
/// bound as a parameter.
async fn touch(
    pool: &sqlx::SqlitePool,
    table: &'static str,
    coin_id: &str,
    now: i64,
) -> sqlx::Result<()> {
    let sql = match table {
        "chain_read_cache" => "UPDATE chain_read_cache SET last_used_at = ? WHERE coin_id = ?",
        _ => "UPDATE chain_spend_cache SET last_used_at = ? WHERE coin_id = ?",
    };
    sqlx::query(sql)
        .bind(now)
        .bind(coin_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Drop the least-recently-USED rows until `table` holds at most `budget` of them.
///
/// Run on every write rather than on a timer: the growth this bounds is driven by writes, so the
/// write is exactly where the budget can never be outrun. `LIMIT` is computed by SQLite from the
/// table's own count, so a table already inside its budget deletes nothing.
async fn evict_to_budget(
    pool: &sqlx::SqlitePool,
    table: &'static str,
    budget: i64,
) -> sqlx::Result<()> {
    let sql = match table {
        "chain_read_cache" => {
            "DELETE FROM chain_read_cache WHERE coin_id IN (SELECT coin_id FROM chain_read_cache              ORDER BY last_used_at ASC, coin_id ASC LIMIT MAX(0, (SELECT COUNT(*) FROM              chain_read_cache) - ?))"
        }
        _ => {
            "DELETE FROM chain_spend_cache WHERE coin_id IN (SELECT coin_id FROM chain_spend_cache              ORDER BY last_used_at ASC, coin_id ASC LIMIT MAX(0, (SELECT COUNT(*) FROM              chain_spend_cache) - ?))"
        }
    };
    sqlx::query(sql).bind(budget).execute(pool).await?;
    Ok(())
}

/// Evidence that a full address-history catch-up ran to COMPLETION.
///
/// The only thing [`WalletDb::complete_catch_up`] accepts, and therefore the only way the arrival
/// baseline can be armed (dig_ecosystem#2548). It carries the two facts a completed catch-up has and
/// a point read against the coinset oracle does not: the height the peer reported when it finally
/// answered `is_finished`, and that block's header hash.
///
/// Naming those as a type rather than passing a loose `u32` is the point. A caller that has replayed
/// no history has no header hash to offer and no finishing height that means anything, so arming
/// from a partial view is something an author has to fabricate deliberately rather than something a
/// plausible-looking call does by accident — which is exactly how the oracle-tier refresh came to
/// arm a zero baseline in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Its constructor, [`CatchUpReplay::finished_at`], lives in [`crate::sage::sync`] rather than
/// here: it is where the refusal policy belongs (beside the other peer bounds), and this module is
/// the persistence layer.
pub struct CatchUpReplay {
    pub(super) peak_height: u32,
    pub(super) header_hash: String,
    /// The puzzle-hash set this replay actually ran over.
    ///
    /// Carried on the replay rather than passed beside it so the completion write cannot describe
    /// addresses the catch-up did not cover: the value is built from the subscription itself, and
    /// there is no way to record a completion without one (dig_ecosystem#2871).
    pub(super) covered: CoveredSet,
}

impl CatchUpReplay {
    /// The height the catch-up finished at.
    pub fn peak_height(&self) -> u32 {
        self.peak_height
    }

    /// The header hash of the block it finished at.
    pub fn header_hash(&self) -> &str {
        &self.header_hash
    }

    /// The puzzle-hash set this replay covered.
    pub fn covered(&self) -> &CoveredSet {
        &self.covered
    }
}

impl WalletDb {
    /// Open (creating if needed) a wallet DB at `path`, with WAL enabled, and apply the
    /// schema/migrations.
    pub async fn open(path: &str) -> sqlx::Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        Self::from_options(opts).await
    }

    /// Open an ephemeral in-memory wallet DB (tests). A single connection keeps the
    /// `:memory:` database alive for the pool's lifetime.
    pub async fn open_in_memory() -> sqlx::Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        let db = Self {
            pool,
            chain_cache_budgets: ChainCacheBudgets::default(),
        };
        db.migrate().await?;
        Ok(db)
    }

    async fn from_options(opts: SqliteConnectOptions) -> sqlx::Result<Self> {
        let pool = SqlitePoolOptions::new().connect_with(opts).await?;
        let db = Self {
            pool,
            chain_cache_budgets: ChainCacheBudgets::default(),
        };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> sqlx::Result<()> {
        // The schema is a batch of idempotent `CREATE TABLE IF NOT EXISTS` statements.
        let mut conn = self.pool.acquire().await?;
        for stmt in SCHEMA.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                sqlx::query(stmt).execute(&mut *conn).await?;
            }
        }
        // Additive column migrations for pre-#216 DBs; ignore "duplicate column" on DBs the
        // updated CREATE TABLE already covers (a fresh DB, or one already migrated).
        for stmt in ADD_COLUMN_MIGRATIONS {
            let _ = sqlx::query(stmt).execute(&mut *conn).await;
        }
        // Only now can an index name a migrated column.
        for stmt in POST_MIGRATION_INDEXES {
            sqlx::query(stmt).execute(&mut *conn).await?;
        }
        Ok(())
    }

    // ---- sync state -------------------------------------------------------

    /// Read the current sync state.
    pub async fn sync_state(&self) -> sqlx::Result<SyncState> {
        let row = sqlx::query(
            "SELECT peak_height, header_hash, initial_sync_complete, covered_puzzle_hashes              FROM sync_state WHERE id = 0",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(SyncState {
            peak_height: row.get::<Option<i64>, _>("peak_height").map(|h| h as u32),
            header_hash: row.get::<Option<String>, _>("header_hash"),
            initial_sync_complete: row.get::<i64, _>("initial_sync_complete") != 0,
            covered: row
                .get::<Option<String>, _>("covered_puzzle_hashes")
                .map(|stored| CoveredSet::from_storage(&stored)),
        })
    }

    /// Whether the initial catch-up has completed (the routing gate, B.6).
    pub async fn is_synced(&self) -> sqlx::Result<bool> {
        Ok(self.sync_state().await?.initial_sync_complete)
    }

    /// Advance the synced peak to a height the session's writer is entitled to claim.
    ///
    /// The only way production code writes this column. [`AdmittedPeak`] is built solely by
    /// [`super::sync::SessionState::admit_peak`], so a new peak-carrying frame cannot reach the
    /// database without meeting the [`super::sync::PeakCeiling`] — which is what the raw setter
    /// below allowed, and what dig_ecosystem#2851 exploited.
    pub async fn record_peak(&self, peak: AdmittedPeak, header_hash: &str) -> sqlx::Result<()> {
        self.write_peak(peak.height(), header_hash).await
    }

    /// Advance the synced peak to an arbitrary height, checked against nothing.
    ///
    /// Test-only on purpose: a fixture needs to place the replica at a height directly, and
    /// production must not be able to. Reach for [`Self::record_peak`] instead — if you have no
    /// [`AdmittedPeak`] to pass it, the height has not been judged yet.
    #[cfg(test)]
    pub async fn set_peak(&self, height: u32, header_hash: &str) -> sqlx::Result<()> {
        self.write_peak(height, header_hash).await
    }

    /// The one statement that moves the peak column forward, private to the persistence layer so
    /// the judgement above cannot be routed around from outside it.
    async fn write_peak(&self, height: u32, header_hash: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE sync_state SET peak_height = ?, header_hash = ? WHERE id = 0")
            .bind(i64::from(height))
            .bind(header_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark the initial catch-up complete (or not). Sets the FLAG and nothing else.
    ///
    /// # This deliberately cannot arm the arrival baseline (dig_ecosystem#2548)
    ///
    /// It used to, in the same statement, and that was wrong for one of its two callers.
    /// [`super::rpc::WalletBackend::refresh_tracked_coins`] latches this flag from the coinset
    /// ORACLE tier after a point read of the wallet's own puzzle hashes — it replays no history and
    /// on a fresh install can complete with `coins` empty and no peak at all. Arming from that arms
    /// the baseline at ZERO, and because arming is permanent the LATER, genuine catch-up leaves it
    /// there; every historical coin then sits above the watermark and the first live update
    /// announces the wallet's whole receive history as incoming payments.
    ///
    /// So arming moved to [`Self::complete_catch_up`], which takes a [`CatchUpReplay`] — a value
    /// only the terminal answer of a full address-history catch-up produces. A caller that has not
    /// replayed history has nothing to build one out of, which is what makes the unsafe arming hard
    /// to write rather than merely discouraged.
    pub async fn set_initial_sync_complete(&self, complete: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE sync_state SET initial_sync_complete = ? WHERE id = 0")
            .bind(i64::from(complete))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record the puzzle-hash set a NON-catch-up sync path covered — the oracle-tier refresh
    /// ([`crate::sage::rpc::WalletBackend::refresh_tracked_coins`]), which fetches coins for a set
    /// of addresses by point read and latches `initial_sync_complete` without replaying history.
    ///
    /// Deliberately separate from [`Self::complete_catch_up`], which is the only thing that may arm
    /// the arrival baseline and the only thing that takes a [`CatchUpReplay`]. This path has
    /// replayed nothing and has no terminal height to offer; what it CAN say honestly is which
    /// addresses it fetched, and that is all this records.
    pub async fn record_coverage(&self, covered: &CoveredSet) -> sqlx::Result<()> {
        sqlx::query("UPDATE sync_state SET covered_puzzle_hashes = ? WHERE id = 0")
            .bind(covered.to_storage())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record that a full address-history catch-up finished: advance the peak, mark the replica
    /// authoritative, and ARM the arrival baseline — all in one transaction.
    ///
    /// # Why arming lives here and only here
    ///
    /// The catch-up replays every coin the wallet's addresses ever held through
    /// [`Self::upsert_coins`], so any arrival recorder keyed on "a row appeared" would fire once per
    /// historical coin. The defence is that the recorder refuses without a baseline
    /// ([`crate::sage::arrivals::Verdict::NoBaseline`]) and a baseline can only come into existence
    /// at the end of a replay — at or above everything that replay just wrote.
    ///
    /// Arming is `COALESCE`d, so it happens exactly once per wallet. A later catch-up (a restart, a
    /// reconnect — each of which replays from the genesis challenge) finds the baseline already set
    /// and leaves it alone, which is what makes coins received while the node was OFF still count as
    /// arrivals while the history below the baseline never does.
    ///
    /// The armed value is the greater of the replay's own peak and the highest confirmed coin
    /// height present, because either can lead: a batch can land at a height the terminal response
    /// has not caught up to, and a coin above the watermark would otherwise be announced on the very
    /// next pass.
    ///
    /// Clearing the flag (a reorg, a backwards move) deliberately does NOT disarm the baseline —
    /// [`Self::rollback_above`] walks it back to the fork instead, so the coins that were undone
    /// become eligible again and nothing below the fork does.
    pub async fn complete_catch_up(&self, replay: &CatchUpReplay) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE sync_state SET
                 peak_height = ?,
                 header_hash = ?,
                 initial_sync_complete = 1,
                 covered_puzzle_hashes = ?,
                 arrival_baseline_height = COALESCE(
                     arrival_baseline_height,
                     MAX(?, COALESCE((SELECT MAX(created_height) FROM coins), 0))
                 )
             WHERE id = 0",
        )
        .bind(i64::from(replay.peak_height()))
        .bind(replay.header_hash())
        .bind(replay.covered().to_storage())
        .bind(i64::from(replay.peak_height()))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The arrival baseline: the height at or below which a confirmed coin is BACKFILL.
    ///
    /// `None` means no catch-up has ever completed, and the recorder announces nothing at all.
    pub async fn arrival_baseline(&self) -> sqlx::Result<ArrivalBaseline> {
        let row = sqlx::query("SELECT arrival_baseline_height FROM sync_state WHERE id = 0")
            .fetch_one(&self.pool)
            .await?;
        Ok(row
            .get::<Option<i64>, _>("arrival_baseline_height")
            .map(|h| h as u32))
    }

    // ---- derivations ------------------------------------------------------

    /// Insert or replace an HD derivation.
    pub async fn upsert_derivation(&self, d: &DerivationRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO derivations (hardened, idx, public_key, puzzle_hash, address)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(hardened, idx) DO UPDATE SET
                public_key = excluded.public_key,
                puzzle_hash = excluded.puzzle_hash,
                address = excluded.address",
        )
        .bind(d.hardened)
        .bind(d.index)
        .bind(&d.public_key)
        .bind(&d.puzzle_hash)
        .bind(&d.address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A page of derivations for one HD tree, plus the total count.
    pub async fn get_derivations(
        &self,
        hardened: bool,
        offset: u32,
        limit: u32,
    ) -> sqlx::Result<(Vec<DerivationRow>, u32)> {
        let total: i64 = sqlx::query("SELECT COUNT(*) AS n FROM derivations WHERE hardened = ?")
            .bind(hardened)
            .fetch_one(&self.pool)
            .await?
            .get("n");
        let rows = sqlx::query(
            "SELECT hardened, idx, public_key, puzzle_hash, address FROM derivations
             WHERE hardened = ? ORDER BY idx ASC LIMIT ? OFFSET ?",
        )
        .bind(hardened)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        let out = rows
            .into_iter()
            .map(|r| DerivationRow {
                hardened: r.get::<i64, _>("hardened") != 0,
                index: r.get("idx"),
                public_key: r.get("public_key"),
                puzzle_hash: r.get("puzzle_hash"),
                address: r.get("address"),
            })
            .collect();
        Ok((out, total as u32))
    }

    /// The highest derivation index seen for one HD tree (for `get_sync_status`), floored by
    /// any `increase_derivation_index` request (§18.16 `actions`) so the reported index never
    /// regresses below what the caller asked the wallet to guarantee coverage up to.
    pub async fn max_derivation_index(&self, hardened: bool) -> sqlx::Result<u32> {
        let n: Option<i64> =
            sqlx::query("SELECT MAX(idx) AS m FROM derivations WHERE hardened = ?")
                .bind(hardened)
                .fetch_one(&self.pool)
                .await?
                .get("m");
        let from_rows = n.map(|v| v as u32 + 1).unwrap_or(0);
        let floor = self.derivation_floor(hardened).await?;
        Ok(from_rows.max(floor))
    }

    /// Raise the derivation-index floor for one HD tree (`increase_derivation_index`,
    /// §18.16) — [`Self::max_derivation_index`] never reports less than this afterward, even
    /// if no derivation rows exist yet at that index. Never lowers an existing floor.
    pub async fn raise_derivation_floor(&self, hardened: bool, index: u32) -> sqlx::Result<()> {
        let col = if hardened {
            "derivation_floor_hardened"
        } else {
            "derivation_floor_unhardened"
        };
        sqlx::query(&format!(
            "UPDATE network_settings SET {col} = MAX({col}, ?) WHERE id = 0"
        ))
        .bind(i64::from(index))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn derivation_floor(&self, hardened: bool) -> sqlx::Result<u32> {
        let col = if hardened {
            "derivation_floor_hardened"
        } else {
            "derivation_floor_unhardened"
        };
        let v: i64 = sqlx::query(&format!(
            "SELECT {col} AS v FROM network_settings WHERE id = 0"
        ))
        .fetch_one(&self.pool)
        .await?
        .get("v");
        Ok(v as u32)
    }

    // ---- coins ------------------------------------------------------------

    /// Insert or update a coin's chain state (the `coin_state_update` upsert). A coin is
    /// keyed by `coin_id`; a later update (e.g. a spend) overwrites the mutable fields.
    pub async fn upsert_coin(&self, c: &CoinRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO coins
                (coin_id, parent_coin_info, puzzle_hash, amount, created_height,
                 spent_height, asset_id, hint, created_timestamp, spent_timestamp)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(coin_id) DO UPDATE SET
                created_height = excluded.created_height,
                spent_height = excluded.spent_height,
                created_timestamp = excluded.created_timestamp,
                spent_timestamp = excluded.spent_timestamp,
                asset_id = COALESCE(excluded.asset_id, coins.asset_id),
                hint = COALESCE(excluded.hint, coins.hint)",
        )
        .bind(&c.coin_id)
        .bind(&c.parent_coin_info)
        .bind(&c.puzzle_hash)
        .bind(&c.amount)
        .bind(c.created_height)
        .bind(c.spent_height)
        .bind(&c.asset_id)
        .bind(&c.hint)
        .bind(c.created_timestamp)
        .bind(c.spent_timestamp)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Apply a batch of coin updates in one transaction.
    pub async fn upsert_coins(&self, coins: &[CoinRow]) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        for c in coins {
            sqlx::query(
                "INSERT INTO coins
                    (coin_id, parent_coin_info, puzzle_hash, amount, created_height,
                     spent_height, asset_id, hint, created_timestamp, spent_timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(coin_id) DO UPDATE SET
                    created_height = excluded.created_height,
                    spent_height = excluded.spent_height,
                    created_timestamp = excluded.created_timestamp,
                    spent_timestamp = excluded.spent_timestamp,
                    asset_id = COALESCE(excluded.asset_id, coins.asset_id),
                    hint = COALESCE(excluded.hint, coins.hint)",
            )
            .bind(&c.coin_id)
            .bind(&c.parent_coin_info)
            .bind(&c.puzzle_hash)
            .bind(&c.amount)
            .bind(c.created_height)
            .bind(c.spent_height)
            .bind(&c.asset_id)
            .bind(&c.hint)
            .bind(c.created_timestamp)
            .bind(c.spent_timestamp)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Roll back chain state above `height` after a reorg (design B.3):
    /// - coins **created** above `height` never existed → delete them;
    /// - coins **spent** above `height` are unspent again → clear the spend;
    /// - reset the synced peak to `height`.
    ///
    /// # Arrivals are unmade with the coins (dig_ecosystem#2548)
    ///
    /// An arrival above the fork describes money that, after the rollback, never arrived — so it
    /// is deleted by the SAME predicate that deletes the coin, in the SAME transaction. Any other
    /// arrangement leaves the ledger asserting a receipt at a height the chain no longer has.
    ///
    /// The baseline is walked back to the fork too, so a coin that re-confirms after the reorg is
    /// eligible again rather than silently swallowed. A re-confirmed coin therefore CAN be
    /// recorded a second time: a reorg is a genuinely new confirmation, and the alternative —
    /// keeping a ledger row for a coin the replica has deleted — is the dishonest one. `seq` is
    /// `AUTOINCREMENT`, so a deleted row's cursor position is never reused and a client's cursor
    /// stays valid across the rollback.
    pub async fn rollback_above(&self, height: u32) -> sqlx::Result<()> {
        let h = i64::from(height);
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM coins WHERE created_height IS NOT NULL AND created_height > ?")
            .bind(h)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM arrivals WHERE confirmed_height > ?")
            .bind(h)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM arrival_pending WHERE created_height > ?")
            .bind(h)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE sync_state SET arrival_baseline_height = ?
             WHERE id = 0 AND arrival_baseline_height > ?",
        )
        .bind(h)
        .bind(h)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE coins SET spent_height = NULL, spent_timestamp = NULL
             WHERE spent_height IS NOT NULL AND spent_height > ?",
        )
        .bind(h)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE sync_state SET peak_height = ? WHERE id = 0")
            .bind(h)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    fn coin_from_row(r: &sqlx::sqlite::SqliteRow) -> CoinRow {
        CoinRow {
            coin_id: r.get("coin_id"),
            parent_coin_info: r.get("parent_coin_info"),
            puzzle_hash: r.get("puzzle_hash"),
            amount: r.get("amount"),
            created_height: r.get("created_height"),
            spent_height: r.get("spent_height"),
            asset_id: r.get("asset_id"),
            hint: r.get("hint"),
            created_timestamp: r.get("created_timestamp"),
            spent_timestamp: r.get("spent_timestamp"),
        }
    }

    /// All coins (used by higher layers that sort/paginate in Rust).
    pub async fn all_coins(&self) -> sqlx::Result<Vec<CoinRow>> {
        let rows = sqlx::query("SELECT * FROM coins")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::coin_from_row).collect())
    }

    /// Fetch specific coins by id (order not guaranteed).
    pub async fn coins_by_ids(&self, ids: &[String]) -> sqlx::Result<Vec<CoinRow>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(r) = sqlx::query("SELECT * FROM coins WHERE coin_id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
            {
                out.push(Self::coin_from_row(&r));
            }
        }
        Ok(out)
    }

    // ---- arbitrary-chain-read cache (dig_ecosystem#3032) ------------------

    /// The cached arbitrary chain read for `coin_id`, or `None` where nothing is cached.
    ///
    /// Deliberately returns the row WITHOUT judging its freshness: whether an entry may be used is
    /// a rule about spentness ([`super::peer_reads::cache_entry_is_usable`]) that a caller needs
    /// to be able to test without a database.
    pub async fn cached_chain_read(
        &self,
        coin_id: &str,
        now: i64,
    ) -> sqlx::Result<Option<ChainReadCacheRow>> {
        let Some(r) = sqlx::query("SELECT * FROM chain_read_cache WHERE coin_id = ?")
            .bind(coin_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        touch(&self.pool, "chain_read_cache", coin_id, now).await?;
        Ok(Some(ChainReadCacheRow {
            coin_id: r.get("coin_id"),
            parent_coin_info: r.get("parent_coin_info"),
            puzzle_hash: r.get("puzzle_hash"),
            amount: r.get("amount"),
            created_height: r.get("created_height"),
            spent_height: r.get("spent_height"),
            created_timestamp: r.get("created_timestamp"),
            spent_timestamp: r.get("spent_timestamp"),
            cached_at: r.get("cached_at"),
        }))
    }

    /// The cached SPEND of `coin_id`, or `None` where none is cached.
    ///
    /// It carries no `cached_at` and needs none: a spend that happened cannot un-happen, and the
    /// four fields it records are bound to the coin id by the coin id's own definition. This is
    /// the half of the lineage walk that is permanently cacheable, and a walk visits a spent coin
    /// at every hop but the last.
    pub async fn cached_chain_spend(
        &self,
        coin_id: &str,
        now: i64,
    ) -> sqlx::Result<Option<ChainSpendCacheRow>> {
        let Some(r) = sqlx::query("SELECT * FROM chain_spend_cache WHERE coin_id = ?")
            .bind(coin_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        touch(&self.pool, "chain_spend_cache", coin_id, now).await?;
        Ok(Some(ChainSpendCacheRow {
            coin_id: r.get("coin_id"),
            parent_coin_info: r.get("parent_coin_info"),
            puzzle_hash: r.get("puzzle_hash"),
            amount: r.get("amount"),
            puzzle_reveal: r.get("puzzle_reveal"),
            solution: r.get("solution"),
        }))
    }

    /// Record one coin's SPEND, then evict back to [`CHAIN_SPEND_CACHE_MAX_ROWS`].
    pub async fn put_chain_spend(&self, row: &ChainSpendCacheRow, now: i64) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO chain_spend_cache (coin_id, parent_coin_info, puzzle_hash, \
             amount, puzzle_reveal, solution, last_used_at) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(&row.coin_id)
        .bind(&row.parent_coin_info)
        .bind(&row.puzzle_hash)
        .bind(&row.amount)
        .bind(&row.puzzle_reveal)
        .bind(&row.solution)
        .bind(now)
        .execute(&self.pool)
        .await?;
        evict_to_budget(
            &self.pool,
            "chain_spend_cache",
            self.chain_cache_budgets.spends,
        )
        .await?;
        Ok(())
    }

    /// Record (or replace) one coin's cached arbitrary chain read.
    ///
    /// A REPLACE rather than an insert-if-absent: the one thing that legitimately changes about a
    /// coin is that it becomes spent, and re-learning that is the entire reason an unspent entry
    /// is allowed to expire.
    pub async fn put_chain_read(&self, row: &ChainReadCacheRow, now: i64) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO chain_read_cache (coin_id, parent_coin_info, puzzle_hash, \
             amount, created_height, spent_height, created_timestamp, spent_timestamp, \
             cached_at, last_used_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&row.coin_id)
        .bind(&row.parent_coin_info)
        .bind(&row.puzzle_hash)
        .bind(&row.amount)
        .bind(row.created_height)
        .bind(row.spent_height)
        .bind(row.created_timestamp)
        .bind(row.spent_timestamp)
        .bind(row.cached_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        evict_to_budget(
            &self.pool,
            "chain_read_cache",
            self.chain_cache_budgets.reads,
        )
        .await?;
        Ok(())
    }

    /// The same DB held to SMALLER chain-cache budgets — the seam the eviction tests pin.
    #[must_use]
    pub fn with_chain_cache_budgets(mut self, budgets: ChainCacheBudgets) -> Self {
        self.chain_cache_budgets = budgets;
        self
    }

    /// How many rows one of the two chain-cache tables currently holds.
    ///
    /// Public because a budget is only a budget if a test can watch it hold under a flood of
    /// distinct coin ids, which is the evidence dig_ecosystem#3035 asks for.
    pub async fn chain_cache_len(&self, table: ChainCacheTable) -> sqlx::Result<i64> {
        let row = sqlx::query(match table {
            ChainCacheTable::Reads => "SELECT COUNT(*) AS n FROM chain_read_cache",
            ChainCacheTable::Spends => "SELECT COUNT(*) AS n FROM chain_spend_cache",
        })
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("n"))
    }

    // ---- arrivals (dig_ecosystem#2548) ------------------------------------

    /// Examine every candidate coin and record the ones that are ARRIVALS, then advance the
    /// baseline to `through_height`. Returns how many arrivals were newly recorded.
    ///
    /// `watched_p2_hashes` are the wallet's own bare p2 puzzle hashes (lowercase hex) — the set
    /// the chain subscription was taken over. A coin sitting at one of them with no `asset_id` is
    /// XCH by construction; see [`crate::sage::arrivals::classify`] for the rest of the judgement.
    ///
    /// # Called AFTER the coins are committed, never during the write
    ///
    /// A parent and its change coin arrive in the SAME `coin_state_update` batch and are written
    /// in one transaction in whatever order the peer chose. Deciding "is this coin's parent ours?"
    /// inside that write would race the batch and read the user's own change as an incoming
    /// payment — the exact false positive dig_ecosystem#2548 exists to prevent. Running here,
    /// after the batch has landed, makes the ordering irrelevant.
    ///
    /// # Why the whole write is one transaction
    ///
    /// The ledger insert and the baseline advance must commit together: a crash between them
    /// either re-examines coins already recorded (harmless — the `UNIQUE` coin id makes the second
    /// insert a no-op) or, in the other order, skips coins it never recorded (money the user is
    /// never told about). Only one of those is acceptable, so only one is expressible.
    pub async fn record_arrivals(
        &self,
        watched_p2_hashes: &[String],
        through_height: u32,
    ) -> sqlx::Result<usize> {
        let watched: std::collections::HashSet<String> = watched_p2_hashes
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        let mut tx = self.pool.begin().await?;

        // Self-cleaning: a deferred coin the replica no longer has (a reorg deleted it) is not
        // waiting for anything.
        sqlx::query("DELETE FROM arrival_pending WHERE coin_id NOT IN (SELECT coin_id FROM coins)")
            .execute(&mut *tx)
            .await?;

        let baseline: Option<i64> =
            sqlx::query("SELECT arrival_baseline_height FROM sync_state WHERE id = 0")
                .fetch_one(&mut *tx)
                .await?
                .get("arrival_baseline_height");
        let Some(baseline_h) = baseline else {
            // TRAP 1, fail closed. No catch-up has completed, so every coin present is history the
            // wallet cannot distinguish from news. Record nothing, and do NOT arm the baseline
            // here — arming belongs to `set_initial_sync_complete`, which is the one place that
            // knows the catch-up actually finished.
            tx.commit().await?;
            return Ok(0);
        };

        // Candidates: everything confirmed above the baseline, everything not yet confirmed at
        // all, and everything a previous pass HELD.
        //
        // The last two are what keep the watermark from swallowing real money. A coin sighted in
        // the mempool is unconfirmed now and may confirm AT the height this pass is about to
        // advance the baseline to; an unattributed CAT sits below the baseline as soon as the
        // watermark moves. Both are re-examined every pass and exempted from the height window
        // (`already_deferred`) until they settle. This query is therefore never NARROWER than
        // [`crate::sage::arrivals::classify`], which remains the sole authority on the verdict.
        let pending_ids: std::collections::HashSet<String> =
            sqlx::query("SELECT coin_id FROM arrival_pending")
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|r| r.get::<String, _>("coin_id"))
                .collect();
        let candidates: Vec<CoinRow> = sqlx::query(
            "SELECT * FROM coins
             WHERE created_height IS NULL
                OR created_height > ?
                OR coin_id IN (SELECT coin_id FROM arrival_pending)",
        )
        .bind(baseline_h)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(Self::coin_from_row)
        .collect();

        let mut recorded = 0usize;
        for c in &candidates {
            let parent_is_ours = sqlx::query("SELECT 1 FROM coins WHERE coin_id = ?")
                .bind(&c.parent_coin_info)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
            let verdict = classify(
                c,
                Some(baseline_h as u32),
                pending_ids.contains(&c.coin_id),
                parent_is_ours,
                &watched,
            );
            recorded += Self::apply_verdict(&mut tx, c, verdict, baseline_h).await?;
        }

        // Forward only. A caller with a lower `through_height` (the oracle-tier refresh, which has
        // no peak of its own) must never walk the watermark back and re-open history.
        sqlx::query(
            "UPDATE sync_state SET arrival_baseline_height = MAX(arrival_baseline_height, ?)
             WHERE id = 0",
        )
        .bind(i64::from(through_height))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(recorded)
    }

    /// Write one coin's [`Verdict`] into the ledger or the held set. Returns 1 if an arrival was
    /// newly recorded, 0 otherwise.
    ///
    /// `held_height_fallback` is the height stored for an UNCONFIRMED held coin, which has none of
    /// its own. It bounds only the reorg cleanup of `arrival_pending`; the coin's REAL confirmed
    /// height is read back from `coins` when it settles, so nothing is ever fabricated into an
    /// arrival.
    async fn apply_verdict(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        coin: &CoinRow,
        verdict: Verdict,
        held_height_fallback: i64,
    ) -> sqlx::Result<usize> {
        match verdict {
            Verdict::Arrival(asset_id) => {
                // TRAP 2. `INSERT OR IGNORE` against a `UNIQUE` coin id: a replayed coin cannot
                // become a second arrival even if every height check upstream were removed, and
                // the constraint is on disk, so it survives a restart.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_default();
                let done = sqlx::query(
                    "INSERT OR IGNORE INTO arrivals
                         (coin_id, puzzle_hash, amount, asset_id, confirmed_height, recorded_at)
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&coin.coin_id)
                .bind(&coin.puzzle_hash)
                .bind(&coin.amount)
                .bind(&asset_id)
                .bind(coin.created_height)
                .bind(now)
                .execute(&mut **tx)
                .await?;
                Self::release_hold(tx, &coin.coin_id).await?;
                Ok(done.rows_affected() as usize)
            }
            // Held: seen, deliberately not judged, and re-examined next pass.
            Verdict::Deferred | Verdict::Unconfirmed => {
                sqlx::query(
                    "INSERT OR IGNORE INTO arrival_pending (coin_id, created_height) VALUES (?, ?)",
                )
                .bind(&coin.coin_id)
                .bind(coin.created_height.unwrap_or(held_height_fallback))
                .execute(&mut **tx)
                .await?;
                Ok(0)
            }
            // Settled as not-an-arrival: stop holding it.
            Verdict::OwnChange | Verdict::Backfill | Verdict::NoBaseline => {
                Self::release_hold(tx, &coin.coin_id).await?;
                Ok(0)
            }
        }
    }

    async fn release_hold(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        coin_id: &str,
    ) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM arrival_pending WHERE coin_id = ?")
            .bind(coin_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Arrivals strictly after cursor position `after_seq`, oldest first, at most `limit`.
    ///
    /// The cursor is `AUTOINCREMENT`, so it is monotonic and never reused: a client that stores
    /// the last `seq` it saw resumes exactly where it left off, and a reorg that deletes rows
    /// cannot make an old cursor point at a different arrival.
    pub async fn arrivals_since(&self, after_seq: i64, limit: i64) -> sqlx::Result<Vec<Arrival>> {
        let rows = sqlx::query(
            "SELECT seq, coin_id, puzzle_hash, amount, asset_id, confirmed_height
             FROM arrivals WHERE seq > ? ORDER BY seq ASC LIMIT ?",
        )
        .bind(after_seq)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| Arrival {
                seq: r.get("seq"),
                coin_id: r.get("coin_id"),
                puzzle_hash: r.get("puzzle_hash"),
                amount: r.get("amount"),
                asset_id: r.get("asset_id"),
                confirmed_height: r.get::<i64, _>("confirmed_height") as u32,
            })
            .collect())
    }

    /// The newest cursor position, or 0 when nothing has been recorded — what a client asks for to
    /// start "from now" rather than replaying the whole ledger on first run.
    pub async fn arrival_cursor(&self) -> sqlx::Result<i64> {
        let row = sqlx::query("SELECT COALESCE(MAX(seq), 0) AS v FROM arrivals")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("v"))
    }

    /// The unspent coins for an asset (`None` = XCH). Used for balance + spendable count.
    pub async fn unspent_coins(&self, asset_id: Option<&str>) -> sqlx::Result<Vec<CoinRow>> {
        let rows = match asset_id {
            Some(a) => {
                sqlx::query(
                    "SELECT * FROM coins WHERE spent_height IS NULL
                     AND created_height IS NOT NULL AND asset_id = ?",
                )
                .bind(a)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(
                    "SELECT * FROM coins WHERE spent_height IS NULL
                     AND created_height IS NOT NULL AND asset_id IS NULL",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows.iter().map(Self::coin_from_row).collect())
    }

    /// The number of unspent (spendable) coins for an asset.
    pub async fn spendable_coin_count(&self, asset_id: Option<&str>) -> sqlx::Result<u32> {
        Ok(self.unspent_coins(asset_id).await?.len() as u32)
    }

    /// Whether every given coin id is currently unspent (confirmed, `spent_height IS NULL`).
    pub async fn are_coins_spendable(&self, ids: &[String]) -> sqlx::Result<bool> {
        for id in ids {
            let row = sqlx::query(
                "SELECT 1 AS ok FROM coins
                 WHERE coin_id = ? AND spent_height IS NULL AND created_height IS NOT NULL",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
            if row.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The unspent balance (sum of amounts) for an asset, as `u128` to avoid overflow.
    pub async fn balance(&self, asset_id: Option<&str>) -> sqlx::Result<u128> {
        let coins = self.unspent_coins(asset_id).await?;
        Ok(coins
            .iter()
            .filter_map(|c| c.amount.parse::<u128>().ok())
            .sum())
    }

    // ---- identity-scoped reads (#407) -------------------------------------
    //
    // The node answers balance/token/coin reads for the CLIENT's connected wallet, scoped
    // by that wallet's PUBLIC puzzle hashes (never the node's own coins, never a private
    // key — #217). XCH coins sit AT the owner's p2 puzzle hash, so they are scoped by
    // `puzzle_hash`; CAT coins sit at the outer CAT puzzle hash and are HINTED to the
    // owner p2, so they are scoped by `hint`. An empty identity matches nothing (the node
    // is not tracking that wallet) — the caller reports the explicit not-tracking state.

    /// Build `n` comma-separated `?` placeholders for an `IN (...)` clause.
    fn placeholders(n: usize) -> String {
        vec!["?"; n].join(",")
    }

    /// Unspent coins for `asset_id` scoped to `puzzle_hashes` (XCH by `puzzle_hash`, CAT by
    /// `hint`). Returns empty when the identity is empty (nothing tracked).
    pub async fn unspent_coins_scoped(
        &self,
        asset_id: Option<&str>,
        puzzle_hashes: &[String],
    ) -> sqlx::Result<Vec<CoinRow>> {
        if puzzle_hashes.is_empty() {
            return Ok(vec![]);
        }
        let ph = Self::placeholders(puzzle_hashes.len());
        let (scope_col, asset_clause) = match asset_id {
            Some(_) => ("hint", "AND asset_id = ?"),
            None => ("puzzle_hash", "AND asset_id IS NULL"),
        };
        let sql = format!(
            "SELECT * FROM coins WHERE spent_height IS NULL AND created_height IS NOT NULL \
             AND {scope_col} IN ({ph}) {asset_clause}"
        );
        let mut q = sqlx::query(&sql);
        for p in puzzle_hashes {
            q = q.bind(p.to_ascii_lowercase());
        }
        if let Some(a) = asset_id {
            q = q.bind(a.to_ascii_lowercase());
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::coin_from_row).collect())
    }

    /// The unspent balance for `asset_id` scoped to `puzzle_hashes` (the connected wallet).
    pub async fn balance_scoped(
        &self,
        asset_id: Option<&str>,
        puzzle_hashes: &[String],
    ) -> sqlx::Result<u128> {
        let coins = self.unspent_coins_scoped(asset_id, puzzle_hashes).await?;
        Ok(coins
            .iter()
            .filter_map(|c| c.amount.parse::<u128>().ok())
            .sum())
    }

    /// The PENDING balance for `asset_id` scoped to `puzzle_hashes`: the sum of coins that
    /// are unspent AND not yet confirmed on-chain (`spent_height IS NULL AND created_height
    /// IS NULL` — a coin the wallet has created/received but that has not landed in a block).
    /// Distinct from [`Self::balance_scoped`], which counts ONLY confirmed unspent coins
    /// (`created_height IS NOT NULL`). Used by the `control.wallet.balance` read (#1851) to
    /// report `{ balance, pending }` separately so a caller never conflates in-flight value
    /// with spendable value.
    pub async fn pending_scoped(
        &self,
        asset_id: Option<&str>,
        puzzle_hashes: &[String],
    ) -> sqlx::Result<u128> {
        if puzzle_hashes.is_empty() {
            return Ok(0);
        }
        let ph = Self::placeholders(puzzle_hashes.len());
        let (scope_col, asset_clause) = match asset_id {
            Some(_) => ("hint", "AND asset_id = ?"),
            None => ("puzzle_hash", "AND asset_id IS NULL"),
        };
        let sql = format!(
            "SELECT * FROM coins WHERE spent_height IS NULL AND created_height IS NULL \
             AND {scope_col} IN ({ph}) {asset_clause}"
        );
        let mut q = sqlx::query(&sql);
        for p in puzzle_hashes {
            q = q.bind(p.to_ascii_lowercase());
        }
        if let Some(a) = asset_id {
            q = q.bind(a.to_ascii_lowercase());
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(Self::coin_from_row)
            .filter_map(|c| c.amount.parse::<u128>().ok())
            .sum())
    }

    /// Whether `puzzle_hash` belongs to one of the wallet's own HD derivations — the
    /// `scoped_to_wallet` axis of the B.6 routing gate ([`crate::sage::routing::route`]).
    /// A derivation match means the local DB is authoritative for this address once synced;
    /// a non-match is an arbitrary chain address that only the fallback tier can answer
    /// (#1851). `puzzle_hash` is matched case-insensitively against the stored `hex::encode`
    /// form.
    pub async fn derivation_exists(&self, puzzle_hash: &str) -> sqlx::Result<bool> {
        let row = sqlx::query("SELECT 1 FROM derivations WHERE puzzle_hash = ? LIMIT 1")
            .bind(puzzle_hash.to_ascii_lowercase())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// All coins (any spent state) for `asset_id` scoped to `puzzle_hashes`. Used by
    /// `get_coins`, which applies its own spent/filter modes over the returned set.
    pub async fn coins_scoped(
        &self,
        asset_id: Option<&str>,
        puzzle_hashes: &[String],
    ) -> sqlx::Result<Vec<CoinRow>> {
        if puzzle_hashes.is_empty() {
            return Ok(vec![]);
        }
        let ph = Self::placeholders(puzzle_hashes.len());
        let (scope_col, asset_clause) = match asset_id {
            Some(_) => ("hint", "AND asset_id = ?"),
            None => ("puzzle_hash", "AND asset_id IS NULL"),
        };
        let sql = format!("SELECT * FROM coins WHERE {scope_col} IN ({ph}) {asset_clause}");
        let mut q = sqlx::query(&sql);
        for p in puzzle_hashes {
            q = q.bind(p.to_ascii_lowercase());
        }
        if let Some(a) = asset_id {
            q = q.bind(a.to_ascii_lowercase());
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::coin_from_row).collect())
    }

    /// Count of confirmed, unspent coins (XCH + CAT) tracked for `puzzle_hashes` — the
    /// number of coins the wallet holds for the connected identity. Zero when the identity
    /// is empty (not tracking). Used to report the honest sync count.
    pub async fn coin_count_scoped(&self, puzzle_hashes: &[String]) -> sqlx::Result<u32> {
        if puzzle_hashes.is_empty() {
            return Ok(0);
        }
        let ph = Self::placeholders(puzzle_hashes.len());
        let sql = format!(
            "SELECT COUNT(*) AS n FROM coins WHERE spent_height IS NULL \
             AND created_height IS NOT NULL AND (puzzle_hash IN ({ph}) OR hint IN ({ph}))"
        );
        let mut q = sqlx::query(&sql);
        // bound twice — once for the puzzle_hash IN, once for the hint IN
        for p in puzzle_hashes.iter().chain(puzzle_hashes.iter()) {
            q = q.bind(p.to_ascii_lowercase());
        }
        let row = q.fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>("n") as u32)
    }

    /// Distinct CAT asset ids with at least one unspent coin HINTED to `puzzle_hashes` —
    /// the CATs the connected wallet owns. Empty when the identity is empty.
    pub async fn owned_cat_asset_ids_scoped(
        &self,
        puzzle_hashes: &[String],
    ) -> sqlx::Result<Vec<String>> {
        if puzzle_hashes.is_empty() {
            return Ok(vec![]);
        }
        let ph = Self::placeholders(puzzle_hashes.len());
        let sql = format!(
            "SELECT DISTINCT asset_id FROM coins \
             WHERE asset_id IS NOT NULL AND spent_height IS NULL AND created_height IS NOT NULL \
             AND hint IN ({ph}) ORDER BY asset_id"
        );
        let mut q = sqlx::query(&sql);
        for p in puzzle_hashes {
            q = q.bind(p.to_ascii_lowercase());
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows
            .iter()
            .map(|r| r.get::<String, _>("asset_id"))
            .collect())
    }

    // ---- CATs -------------------------------------------------------------

    /// Insert or update CAT metadata.
    pub async fn upsert_cat(&self, c: &CatRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO cats (asset_id, name, ticker, precision, description, icon_url, visible)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(asset_id) DO UPDATE SET
                name = excluded.name, ticker = excluded.ticker,
                precision = excluded.precision, description = excluded.description,
                icon_url = excluded.icon_url, visible = excluded.visible",
        )
        .bind(&c.asset_id)
        .bind(&c.name)
        .bind(&c.ticker)
        .bind(c.precision)
        .bind(&c.description)
        .bind(&c.icon_url)
        .bind(c.visible)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn cat_from_row(r: &sqlx::sqlite::SqliteRow) -> CatRow {
        CatRow {
            asset_id: r.get("asset_id"),
            name: r.get("name"),
            ticker: r.get("ticker"),
            precision: r.get("precision"),
            description: r.get("description"),
            icon_url: r.get("icon_url"),
            visible: r.get::<i64, _>("visible") != 0,
        }
    }

    /// All known CAT metadata rows.
    pub async fn all_cats(&self) -> sqlx::Result<Vec<CatRow>> {
        let rows = sqlx::query("SELECT * FROM cats ORDER BY asset_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::cat_from_row).collect())
    }

    /// One CAT's metadata by asset id.
    pub async fn cat(&self, asset_id: &str) -> sqlx::Result<Option<CatRow>> {
        Ok(sqlx::query("SELECT * FROM cats WHERE asset_id = ?")
            .bind(asset_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Self::cat_from_row))
    }

    /// The distinct CAT asset ids that have at least one unspent coin in the wallet.
    pub async fn owned_cat_asset_ids(&self) -> sqlx::Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT DISTINCT asset_id FROM coins
             WHERE asset_id IS NOT NULL AND spent_height IS NULL AND created_height IS NOT NULL
             ORDER BY asset_id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| r.get::<String, _>("asset_id"))
            .collect())
    }

    /// Whether the wallet owns any unspent coin / NFT / DID for `asset_id`.
    pub async fn is_asset_owned(&self, asset_id: &str) -> sqlx::Result<bool> {
        let coin = sqlx::query(
            "SELECT 1 AS ok FROM coins
             WHERE asset_id = ? AND spent_height IS NULL AND created_height IS NOT NULL LIMIT 1",
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?;
        if coin.is_some() {
            return Ok(true);
        }
        let nft = sqlx::query("SELECT 1 AS ok FROM nfts WHERE launcher_id = ? LIMIT 1")
            .bind(asset_id)
            .fetch_optional(&self.pool)
            .await?;
        if nft.is_some() {
            return Ok(true);
        }
        let did = sqlx::query("SELECT 1 AS ok FROM dids WHERE launcher_id = ? LIMIT 1")
            .bind(asset_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(did.is_some())
    }

    // ---- CAT attribution (sync-time, #216) --------------------------------

    /// Attribute a synced coin to a CAT asset id (and record its hint) once the sync loop
    /// has uncurried the coin's CAT layer. Only updates an existing coin row.
    pub async fn attribute_cat_coin(
        &self,
        coin_id: &str,
        asset_id: &str,
        hint: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query("UPDATE coins SET asset_id = ?, hint = COALESCE(?, hint) WHERE coin_id = ?")
            .bind(asset_id)
            .bind(hint)
            .bind(coin_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- NFTs -------------------------------------------------------------

    /// Insert or update a reconstructed NFT (keyed by launcher id; a later coin overwrites
    /// the mutable fields — the current coin, owner, and wire record).
    pub async fn upsert_nft(&self, n: &NftDbRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO nfts
                (launcher_id, coin_id, collection_id, minter_did, owner_did, name,
                 visible, created_height, record_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(launcher_id) DO UPDATE SET
                coin_id = excluded.coin_id,
                collection_id = excluded.collection_id,
                minter_did = excluded.minter_did,
                owner_did = excluded.owner_did,
                name = excluded.name,
                created_height = excluded.created_height,
                record_json = excluded.record_json",
        )
        .bind(&n.launcher_id)
        .bind(&n.coin_id)
        .bind(&n.collection_id)
        .bind(&n.minter_did)
        .bind(&n.owner_did)
        .bind(&n.name)
        .bind(n.visible)
        .bind(n.created_height)
        .bind(&n.record_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn nft_from_row(r: &sqlx::sqlite::SqliteRow) -> NftDbRow {
        NftDbRow {
            launcher_id: r.get("launcher_id"),
            coin_id: r.get("coin_id"),
            collection_id: r.get("collection_id"),
            minter_did: r.get("minter_did"),
            owner_did: r.get("owner_did"),
            name: r.get("name"),
            visible: r.get::<i64, _>("visible") != 0,
            created_height: r.get("created_height"),
            record_json: r
                .get::<Option<String>, _>("record_json")
                .unwrap_or_default(),
        }
    }

    /// All reconstructed NFTs (higher layers filter/paginate in Rust — one small wallet).
    pub async fn all_nfts(&self) -> sqlx::Result<Vec<NftDbRow>> {
        let rows = sqlx::query("SELECT * FROM nfts ORDER BY launcher_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::nft_from_row).collect())
    }

    /// One reconstructed NFT by launcher id.
    pub async fn nft(&self, launcher_id: &str) -> sqlx::Result<Option<NftDbRow>> {
        Ok(sqlx::query("SELECT * FROM nfts WHERE launcher_id = ?")
            .bind(launcher_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Self::nft_from_row))
    }

    /// Store/refresh an NFT's off-chain metadata JSON (CHIP-0015) once fetched.
    pub async fn set_nft_metadata_json(&self, launcher_id: &str, json: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE nfts SET metadata_json = ? WHERE launcher_id = ?")
            .bind(json)
            .bind(launcher_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// An NFT's stored off-chain metadata JSON, if fetched.
    pub async fn nft_metadata_json(&self, launcher_id: &str) -> sqlx::Result<Option<String>> {
        let row = sqlx::query("SELECT metadata_json FROM nfts WHERE launcher_id = ?")
            .bind(launcher_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.get::<Option<String>, _>("metadata_json")))
    }

    // ---- DIDs -------------------------------------------------------------

    /// Insert or update a reconstructed DID (keyed by launcher id).
    pub async fn upsert_did(&self, d: &DidDbRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO dids (launcher_id, coin_id, name, visible, created_height, record_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(launcher_id) DO UPDATE SET
                coin_id = excluded.coin_id,
                name = COALESCE(excluded.name, dids.name),
                created_height = excluded.created_height,
                record_json = excluded.record_json",
        )
        .bind(&d.launcher_id)
        .bind(&d.coin_id)
        .bind(&d.name)
        .bind(d.visible)
        .bind(d.created_height)
        .bind(&d.record_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn did_from_row(r: &sqlx::sqlite::SqliteRow) -> DidDbRow {
        DidDbRow {
            launcher_id: r.get("launcher_id"),
            coin_id: r.get("coin_id"),
            name: r.get("name"),
            visible: r.get::<i64, _>("visible") != 0,
            created_height: r.get("created_height"),
            record_json: r
                .get::<Option<String>, _>("record_json")
                .unwrap_or_default(),
        }
    }

    /// All reconstructed DIDs.
    pub async fn all_dids(&self) -> sqlx::Result<Vec<DidDbRow>> {
        let rows = sqlx::query("SELECT * FROM dids ORDER BY launcher_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::did_from_row).collect())
    }

    // ---- NFT collections --------------------------------------------------

    /// Insert or update an NFT collection (keyed by collection id).
    pub async fn upsert_nft_collection(&self, c: &NftCollectionDbRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO nft_collections
                (collection_id, did_id, metadata_collection_id, name, visible, record_json)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(collection_id) DO UPDATE SET
                did_id = excluded.did_id,
                metadata_collection_id = excluded.metadata_collection_id,
                name = excluded.name,
                record_json = excluded.record_json",
        )
        .bind(&c.collection_id)
        .bind(&c.did_id)
        .bind(&c.metadata_collection_id)
        .bind(&c.name)
        .bind(c.visible)
        .bind(&c.record_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn collection_from_row(r: &sqlx::sqlite::SqliteRow) -> NftCollectionDbRow {
        NftCollectionDbRow {
            collection_id: r.get("collection_id"),
            did_id: r.get("did_id"),
            metadata_collection_id: r.get("metadata_collection_id"),
            name: r.get("name"),
            visible: r.get::<i64, _>("visible") != 0,
            record_json: r
                .get::<Option<String>, _>("record_json")
                .unwrap_or_default(),
        }
    }

    /// All NFT collections.
    pub async fn all_nft_collections(&self) -> sqlx::Result<Vec<NftCollectionDbRow>> {
        let rows = sqlx::query("SELECT * FROM nft_collections ORDER BY collection_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::collection_from_row).collect())
    }

    /// One NFT collection by id.
    pub async fn nft_collection(
        &self,
        collection_id: &str,
    ) -> sqlx::Result<Option<NftCollectionDbRow>> {
        Ok(
            sqlx::query("SELECT * FROM nft_collections WHERE collection_id = ?")
                .bind(collection_id)
                .fetch_optional(&self.pool)
                .await?
                .as_ref()
                .map(Self::collection_from_row),
        )
    }

    // ---- offers (#218) ----------------------------------------------------

    /// Insert or update a stored offer (keyed by offer id). A later write (e.g. a
    /// status change) overwrites the mutable fields.
    pub async fn upsert_offer(&self, o: &OfferDbRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO offers (offer_id, offer, status, creation_timestamp, summary_json)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(offer_id) DO UPDATE SET
                offer = excluded.offer,
                status = excluded.status,
                creation_timestamp = excluded.creation_timestamp,
                summary_json = excluded.summary_json",
        )
        .bind(&o.offer_id)
        .bind(&o.offer)
        .bind(&o.status)
        .bind(o.creation_timestamp)
        .bind(&o.summary_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn offer_from_row(r: &sqlx::sqlite::SqliteRow) -> OfferDbRow {
        OfferDbRow {
            offer_id: r.get("offer_id"),
            offer: r.get("offer"),
            status: r.get("status"),
            creation_timestamp: r.get("creation_timestamp"),
            summary_json: r.get("summary_json"),
        }
    }

    /// All stored offers, newest first.
    pub async fn all_offers(&self) -> sqlx::Result<Vec<OfferDbRow>> {
        let rows = sqlx::query("SELECT * FROM offers ORDER BY creation_timestamp DESC, offer_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::offer_from_row).collect())
    }

    /// One stored offer by id.
    pub async fn offer(&self, offer_id: &str) -> sqlx::Result<Option<OfferDbRow>> {
        Ok(sqlx::query("SELECT * FROM offers WHERE offer_id = ?")
            .bind(offer_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Self::offer_from_row))
    }

    /// Update a stored offer's lifecycle status (e.g. to `cancelled`). No-op if the
    /// offer is not stored.
    pub async fn set_offer_status(&self, offer_id: &str, status: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE offers SET status = ? WHERE offer_id = ?")
            .bind(status)
            .bind(offer_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- user themes (#205 PR4, `sage::themes`) ---------------------------

    /// Every NFT id with a saved theme (`get_user_themes`).
    pub async fn all_theme_nft_ids(&self) -> sqlx::Result<Vec<String>> {
        let rows = sqlx::query("SELECT nft_id FROM user_themes ORDER BY nft_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|r| r.get("nft_id")).collect())
    }

    /// One NFT's saved theme, if any (`get_user_theme`).
    pub async fn user_theme(&self, nft_id: &str) -> sqlx::Result<Option<String>> {
        Ok(
            sqlx::query("SELECT theme FROM user_themes WHERE nft_id = ?")
                .bind(nft_id)
                .fetch_optional(&self.pool)
                .await?
                .map(|r| r.get("theme")),
        )
    }

    /// Save (insert or overwrite) an NFT's theme (`save_user_theme`).
    pub async fn save_user_theme(&self, nft_id: &str, theme: &str) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO user_themes (nft_id, theme) VALUES (?, ?)
             ON CONFLICT(nft_id) DO UPDATE SET theme = excluded.theme",
        )
        .bind(nft_id)
        .bind(theme)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete an NFT's saved theme (`delete_user_theme`; a no-op if absent).
    pub async fn delete_user_theme(&self, nft_id: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM user_themes WHERE nft_id = ?")
            .bind(nft_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- record-update actions (#205 PR4, `sage::actions`) ----------------

    /// Reset a CAT's cached metadata (name/ticker/description/icon_url) to unknown, forcing a
    /// future re-fetch (`resync_cat`). Balance/coins are untouched — this only clears the
    /// display metadata cache.
    pub async fn clear_cat_metadata(&self, asset_id: &str) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE cats SET name = NULL, ticker = NULL, description = NULL, icon_url = NULL
             WHERE asset_id = ?",
        )
        .bind(asset_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a CAT's stored metadata (`update_cat`; upserts if the CAT has no row yet).
    #[allow(clippy::too_many_arguments)]
    pub async fn update_cat_metadata(
        &self,
        asset_id: &str,
        name: Option<&str>,
        ticker: Option<&str>,
        description: Option<&str>,
        icon_url: Option<&str>,
        visible: bool,
    ) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO cats (asset_id, name, ticker, description, icon_url, visible)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(asset_id) DO UPDATE SET
                name = excluded.name, ticker = excluded.ticker,
                description = excluded.description, icon_url = excluded.icon_url,
                visible = excluded.visible",
        )
        .bind(asset_id)
        .bind(name)
        .bind(ticker)
        .bind(description)
        .bind(icon_url)
        .bind(visible)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update a DID's display name and/or visibility (`update_did`), patching both the
    /// indexed columns and the stored wire-record JSON's matching fields so `get_dids`
    /// reflects the change immediately.
    pub async fn update_did_fields(
        &self,
        did_id: &str,
        name: Option<&str>,
        visible: bool,
    ) -> sqlx::Result<()> {
        sqlx::query("UPDATE dids SET name = COALESCE(?, name), visible = ? WHERE launcher_id = ?")
            .bind(name)
            .bind(visible)
            .bind(did_id)
            .execute(&self.pool)
            .await?;
        self.patch_record_json("dids", "launcher_id", did_id, |v| {
            if let Some(n) = name {
                v["name"] = serde_json::Value::String(n.to_string());
            }
            v["visible"] = serde_json::Value::Bool(visible);
        })
        .await
    }

    /// Update an NFT's visibility (`update_nft`).
    pub async fn update_nft_visible(&self, nft_id: &str, visible: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE nfts SET visible = ? WHERE launcher_id = ?")
            .bind(visible)
            .bind(nft_id)
            .execute(&self.pool)
            .await?;
        self.patch_record_json("nfts", "launcher_id", nft_id, |v| {
            v["visible"] = serde_json::Value::Bool(visible);
        })
        .await
    }

    /// Update an NFT collection's visibility (`update_nft_collection`).
    pub async fn update_nft_collection_visible(
        &self,
        collection_id: &str,
        visible: bool,
    ) -> sqlx::Result<()> {
        sqlx::query("UPDATE nft_collections SET visible = ? WHERE collection_id = ?")
            .bind(visible)
            .bind(collection_id)
            .execute(&self.pool)
            .await?;
        self.patch_record_json("nft_collections", "collection_id", collection_id, |v| {
            v["visible"] = serde_json::Value::Bool(visible);
        })
        .await
    }

    /// Update an option's visibility (`update_option`).
    pub async fn update_option_visible(&self, option_id: &str, visible: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE options SET visible = ? WHERE option_id = ?")
            .bind(visible)
            .bind(option_id)
            .execute(&self.pool)
            .await?;
        self.patch_record_json("options", "option_id", option_id, |v| {
            v["visible"] = serde_json::Value::Bool(visible);
        })
        .await
    }

    /// Clear an NFT's cached off-chain metadata JSON, forcing a future re-fetch
    /// (`redownload_nft`).
    pub async fn clear_nft_metadata_json(&self, nft_id: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE nfts SET metadata_json = NULL WHERE launcher_id = ?")
            .bind(nft_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Patch the `record_json` column of `table` (keyed by `id_col = id`) via `patch`;
    /// silently does nothing for a missing row or corrupt/absent JSON (nothing sane to
    /// patch) — `table`/`id_col` are always internal constants, never caller-supplied.
    async fn patch_record_json(
        &self,
        table: &str,
        id_col: &str,
        id: &str,
        patch: impl FnOnce(&mut serde_json::Value),
    ) -> sqlx::Result<()> {
        let row = sqlx::query(&format!(
            "SELECT record_json FROM {table} WHERE {id_col} = ?"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(()) };
        let Some(json_str) = row.get::<Option<String>, _>("record_json") else {
            return Ok(());
        };
        let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&json_str) else {
            return Ok(());
        };
        patch(&mut value);
        let Ok(new_json) = serde_json::to_string(&value) else {
            return Ok(());
        };
        sqlx::query(&format!(
            "UPDATE {table} SET record_json = ? WHERE {id_col} = ?"
        ))
        .bind(new_json)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---- options (#205 PR4, `sage::options`) -------------------------------

    /// Insert or update a tracked option contract (keyed by option id).
    pub async fn upsert_option(&self, o: &OptionDbRow) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO options
                (option_id, coin_id, underlying_coin_id, underlying_delegated_puzzle_hash,
                 p2_puzzle_hash, visible, created_height, record_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(option_id) DO UPDATE SET
                coin_id = excluded.coin_id,
                underlying_coin_id = excluded.underlying_coin_id,
                underlying_delegated_puzzle_hash = excluded.underlying_delegated_puzzle_hash,
                p2_puzzle_hash = excluded.p2_puzzle_hash,
                created_height = excluded.created_height,
                record_json = excluded.record_json",
        )
        .bind(&o.option_id)
        .bind(&o.coin_id)
        .bind(&o.underlying_coin_id)
        .bind(&o.underlying_delegated_puzzle_hash)
        .bind(&o.p2_puzzle_hash)
        .bind(o.visible)
        .bind(o.created_height)
        .bind(&o.record_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn option_from_row(r: &sqlx::sqlite::SqliteRow) -> OptionDbRow {
        OptionDbRow {
            option_id: r.get("option_id"),
            coin_id: r.get("coin_id"),
            underlying_coin_id: r.get("underlying_coin_id"),
            underlying_delegated_puzzle_hash: r.get("underlying_delegated_puzzle_hash"),
            p2_puzzle_hash: r.get("p2_puzzle_hash"),
            visible: r.get::<i64, _>("visible") != 0,
            created_height: r.get("created_height"),
            record_json: r.get("record_json"),
        }
    }

    /// All tracked options (`get_options`; higher layers filter/paginate/sort in Rust).
    pub async fn all_options(&self) -> sqlx::Result<Vec<OptionDbRow>> {
        let rows = sqlx::query("SELECT * FROM options ORDER BY option_id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::option_from_row).collect())
    }

    /// One tracked option by id (`get_option`).
    pub async fn option(&self, option_id: &str) -> sqlx::Result<Option<OptionDbRow>> {
        Ok(sqlx::query("SELECT * FROM options WHERE option_id = ?")
            .bind(option_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(Self::option_from_row))
    }

    // ---- peers (#205 PR4, `sage::network`) ---------------------------------

    /// Every tracked peer that is NOT banned — the set this node may actually talk to.
    ///
    /// This is the DIALLING read: the sync supervisor walks it to choose a full node. A banned
    /// peer must never appear here, and the exclusion has to happen in the query rather than at a
    /// caller, because a ban applied to a peer that was previously `user_managed` leaves that flag
    /// set — so a filter on `user_managed` alone would dial the very peer an operator banned.
    ///
    /// `peak_height` is 0 until live per-peer telemetry is wired (SPEC §18.16) — never fabricated.
    /// See [`super::network::get_peers`] for why that 0 is reported as "unobserved".
    pub async fn unbanned_peers(&self) -> sqlx::Result<Vec<PeerRow>> {
        let rows = sqlx::query(
            "SELECT ip_addr, port, peak_height, user_managed, banned FROM peers
             WHERE banned = 0 ORDER BY ip_addr",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(Self::peer_from_row).collect())
    }

    /// Every tracked peer INCLUDING the banned ones — the control-plane enumeration.
    ///
    /// Separate from [`Self::unbanned_peers`] on purpose, and the separation is the point:
    /// `control.chiaPeers.list` MUST show banned entries because it is the only way to enumerate
    /// them, and a blocklist a person cannot read is a blocklist they cannot correct. Serving that
    /// requirement by relaxing [`Self::unbanned_peers`] would have fed banned peers straight to
    /// the dialler, so the two reads stay distinct and only the control plane calls this one.
    pub async fn all_peers_including_banned(&self) -> sqlx::Result<Vec<PeerRow>> {
        let rows = sqlx::query(
            "SELECT ip_addr, port, peak_height, user_managed, banned FROM peers
             ORDER BY ip_addr",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(Self::peer_from_row).collect())
    }

    fn peer_from_row(r: &sqlx::sqlite::SqliteRow) -> PeerRow {
        PeerRow {
            ip_addr: r.get("ip_addr"),
            port: r.get("port"),
            peak_height: r.get("peak_height"),
            user_managed: r.get::<i64, _>("user_managed") != 0,
            banned: r.get::<i64, _>("banned") != 0,
        }
    }

    /// Add (or un-ban + refresh the port of) a user-managed peer (`add_peer`).
    ///
    /// Returns whether the entry ENDED UP trusted — read back from the row, not assumed from the
    /// request. The two differ in a case that really occurs: the upsert clears `banned` and
    /// refreshes the port but deliberately leaves `user_managed` alone, so adding a peer that was
    /// previously BANNED un-bans it WITHOUT granting the corroboration bypass. `add` is not
    /// allowed to launder a ban into trust — un-banning is `remove { ban: false }`, which grants
    /// nothing — and the caller must be told the trust it asked for was not conferred, because
    /// otherwise an operator believes they configured a trusted node and is silently still
    /// depending on corroboration they were told they had bypassed.
    pub async fn add_peer(&self, ip_addr: &str, port: i64) -> sqlx::Result<bool> {
        sqlx::query(
            "INSERT INTO peers (ip_addr, port, peak_height, user_managed, banned, banned_at)
             VALUES (?, ?, 0, 1, 0, NULL)
             ON CONFLICT(ip_addr) DO UPDATE SET
                 port = excluded.port, banned = 0, banned_at = NULL",
        )
        .bind(ip_addr)
        .bind(port)
        .execute(&self.pool)
        .await?;

        let trusted: i64 = sqlx::query_scalar("SELECT user_managed FROM peers WHERE ip_addr = ?")
            .bind(ip_addr)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(0);
        Ok(trusted != 0)
    }

    /// Remove a peer (`remove_peer { ban: false }`, deletes the row) or ban it
    /// (`remove_peer { ban: true }`, kept but excluded from [`Self::unbanned_peers`]).
    ///
    /// Returns whether an entry MATCHED the address. `remove` is the only way to un-trust a peer
    /// that is believed without corroboration, so a remedy that cannot report its own failure is
    /// worse than no remedy — an operator who is told "removed" when nothing matched believes
    /// they revoked custody-grade trust and did not. The usual cause is an address spelled
    /// differently from the stored one, which is why callers canonicalise first.
    ///
    /// Banning is still permitted for an address this node does not hold (a pre-emptive ban is a
    /// legitimate operator act), and the return value stays honest about it: nothing matched, so
    /// nothing was un-trusted, even though a ban row now exists.
    pub async fn remove_peer(&self, ip_addr: &str, ban: bool) -> sqlx::Result<bool> {
        let existed: Option<i64> = sqlx::query_scalar("SELECT 1 FROM peers WHERE ip_addr = ?")
            .bind(ip_addr)
            .fetch_optional(&self.pool)
            .await?;

        if ban {
            sqlx::query(
                "INSERT INTO peers (ip_addr, port, peak_height, user_managed, banned, banned_at)
                 VALUES (?, 0, 0, 0, 1, ?)
                 ON CONFLICT(ip_addr) DO UPDATE SET
                     banned = 1, user_managed = 0, banned_at = excluded.banned_at",
            )
            .bind(ip_addr)
            .bind(Self::now_millis())
            .execute(&self.pool)
            .await?;
            self.evict_oldest_bans_beyond_cap().await?;
        } else {
            sqlx::query("DELETE FROM peers WHERE ip_addr = ?")
                .bind(ip_addr)
                .execute(&self.pool)
                .await?;
        }
        Ok(existed.is_some())
    }

    /// Hold the ban list to [`MAX_BANNED_CHIA_PEERS`], discarding the OLDEST bans first.
    ///
    /// A ban is a row written at the request of one small control call and kept across restarts,
    /// so without a ceiling the blocklist is at-rest state a caller can grow for free. The
    /// direction matters as much as the bound: a full list that REFUSED the newest ban would turn
    /// the ceiling into a denial of the ban facility itself, exactly when an operator is trying to
    /// exclude a peer that is misbehaving now. Forgetting the oldest is recoverable; refusing the
    /// newest is not.
    async fn evict_oldest_bans_beyond_cap(&self) -> sqlx::Result<()> {
        sqlx::query(
            "DELETE FROM peers WHERE ip_addr IN (
                 SELECT ip_addr FROM peers WHERE banned = 1
                 ORDER BY banned_at IS NOT NULL, banned_at, ip_addr
                 LIMIT MAX(0, (SELECT COUNT(*) FROM peers WHERE banned = 1) - ?)
             )",
        )
        .bind(i64::try_from(MAX_BANNED_CHIA_PEERS).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Wall-clock milliseconds, used only to ORDER bans against each other for eviction.
    fn now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    // ---- network / sync settings (#205 PR4, `sage::network`) ---------------

    /// Read the current network/sync settings row.
    pub async fn network_settings(&self) -> sqlx::Result<NetworkSettingsRow> {
        let row = sqlx::query(
            "SELECT discover_peers, target_peers, network_override, delta_sync,
                    delta_sync_override, change_address FROM network_settings WHERE id = 0",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(NetworkSettingsRow {
            discover_peers: row.get::<i64, _>("discover_peers") != 0,
            target_peers: row.get::<i64, _>("target_peers") as u32,
            network_override: row.get("network_override"),
            delta_sync: row.get::<i64, _>("delta_sync") != 0,
            delta_sync_override: row
                .get::<Option<i64>, _>("delta_sync_override")
                .map(|v| v != 0),
            change_address: row.get("change_address"),
        })
    }

    /// `set_discover_peers`.
    pub async fn set_discover_peers(&self, on: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET discover_peers = ? WHERE id = 0")
            .bind(on)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `set_target_peers`.
    pub async fn set_target_peers(&self, n: u32) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET target_peers = ? WHERE id = 0")
            .bind(i64::from(n))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `set_network` / `set_network_override` (one active wallet, so both map to the same
    /// stored override — a per-fingerprint override is a follow-on for multi-key support).
    pub async fn set_network_override(&self, name: Option<&str>) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET network_override = ? WHERE id = 0")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `set_delta_sync`.
    pub async fn set_delta_sync(&self, on: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET delta_sync = ? WHERE id = 0")
            .bind(on)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `set_delta_sync_override`.
    pub async fn set_delta_sync_override(&self, on: Option<bool>) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET delta_sync_override = ? WHERE id = 0")
            .bind(on.map(i64::from))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `set_change_address`.
    pub async fn set_change_address(&self, address: Option<&str>) -> sqlx::Result<()> {
        sqlx::query("UPDATE network_settings SET change_address = ? WHERE id = 0")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// The current network/sync settings (design A.5 network/peers/settings group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSettingsRow {
    /// Whether peer discovery (DNS introducers) is enabled.
    pub discover_peers: bool,
    /// The target number of connected peers.
    pub target_peers: u32,
    /// An explicit active-network override (`None` = the node's configured default).
    pub network_override: Option<String>,
    /// Whether delta-sync is enabled.
    pub delta_sync: bool,
    /// A per-wallet delta-sync override (`None` = use `delta_sync`).
    pub delta_sync_override: Option<bool>,
    /// An explicit change-address override (`None` = the wallet's own change address).
    pub change_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(id: &str, amount: u64, created: Option<i64>, spent: Option<i64>) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "pp".into(),
            puzzle_hash: "ph".into(),
            amount: amount.to_string(),
            created_height: created,
            spent_height: spent,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    // ---- arrivals (dig_ecosystem#2548) ------------------------------------
    //
    // Each of the four traps gets a test that fails for the RIGHT reason, plus a positive control
    // beside it: a recorder that refuses everything would satisfy every negative assertion here,
    // so each negative is paired with a coin that differs in exactly the tested dimension and IS
    // recorded.

    /// The wallet's own watched p2 puzzle hashes, as the recorder takes them.
    fn watched() -> Vec<String> {
        vec!["ph".to_string()]
    }

    /// A confirmed coin at our own address with a FOREIGN parent — the plain arrival shape.
    fn incoming(id: &str, amount: u64, created: i64) -> CoinRow {
        let mut c = coin(id, amount, Some(created), None);
        c.parent_coin_info = format!("foreign_parent_of_{id}");
        c
    }

    /// TRAP 1 — a first catch-up replays the whole address history through the write point. None
    /// of it may be announced, and completing the catch-up must not retroactively announce it.
    #[tokio::test]
    async fn a_first_sync_records_no_arrivals() {
        let db = WalletDb::open_in_memory().await.unwrap();
        for (i, h) in [10i64, 20, 30].iter().enumerate() {
            db.upsert_coin(&incoming(&format!("hist{i}"), 100, *h))
                .await
                .unwrap();
        }
        db.set_peak(30, "hh").await.unwrap();

        // During the catch-up there is no baseline, so nothing is an arrival.
        assert_eq!(db.arrival_baseline().await.unwrap(), None);
        assert_eq!(db.record_arrivals(&watched(), 30).await.unwrap(), 0);

        // Completing the catch-up arms the baseline at the history it just wrote...
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 30, "hh", &[]).unwrap())
            .await
            .unwrap();
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(30));
        // ...and re-running the recorder over that same history still announces nothing.
        assert_eq!(db.record_arrivals(&watched(), 30).await.unwrap(), 0);
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());

        // POSITIVE CONTROL: the very next coin, one block higher, IS an arrival. Without this the
        // assertions above would hold against a recorder that never records anything.
        db.upsert_coin(&incoming("fresh", 100, 31)).await.unwrap();
        assert_eq!(db.record_arrivals(&watched(), 31).await.unwrap(), 1);
    }

    /// TRAP 2 — a restart replays every coin again. Dedup must be DURABLE, and it is durable
    /// twice: the persisted height watermark, and the `UNIQUE` coin id underneath it.
    #[tokio::test]
    async fn a_restart_replaying_the_same_coins_re_announces_nothing() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();
        db.upsert_coin(&incoming("paid", 500, 101)).await.unwrap();
        assert_eq!(db.record_arrivals(&watched(), 101).await.unwrap(), 1);

        // A restart: the catch-up replays from the genesis challenge and re-upserts everything.
        db.upsert_coin(&incoming("paid", 500, 101)).await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 101, "hh2", &[]).unwrap())
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 101).await.unwrap(), 0);
        assert_eq!(db.arrivals_since(0, 100).await.unwrap().len(), 1);

        // And with the watermark defeated outright — the second line of defence on its own.
        sqlx::query("UPDATE sync_state SET arrival_baseline_height = 0 WHERE id = 0")
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 101).await.unwrap(), 0);
        assert_eq!(db.arrivals_since(0, 100).await.unwrap().len(), 1);
    }

    /// TRAP 3 — a mempool sighting is not money. Only `created_height` is a confirmation.
    #[tokio::test]
    async fn an_unconfirmed_coin_is_never_recorded_as_an_arrival() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();

        let mut pending = incoming("in_mempool", 700, 0);
        pending.created_height = None;
        db.upsert_coin(&pending).await.unwrap();
        assert_eq!(db.record_arrivals(&watched(), 105).await.unwrap(), 0);

        // POSITIVE CONTROL: the same coin, once confirmed, IS an arrival.
        db.upsert_coin(&incoming("in_mempool", 700, 105))
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 105).await.unwrap(), 1);
    }

    /// TRAP 4 — the user's own change lands at the user's own address. The parent coin id is the
    /// only signal the write point has, and it is checked AFTER the batch commits so a parent and
    /// its change arriving together cannot race.
    #[tokio::test]
    async fn our_own_change_is_not_announced_as_an_arrival() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();

        // The wallet holds `funding`; spending it creates `change` back at our own address, and a
        // stranger's payment `gift` lands at the same address in the same batch.
        let funding = incoming("funding", 1_000, 90);
        let mut change = coin("change", 400, Some(101), None);
        change.parent_coin_info = "funding".into();
        let gift = incoming("gift", 250, 101);
        db.upsert_coins(&[funding, change, gift]).await.unwrap();

        assert_eq!(db.record_arrivals(&watched(), 101).await.unwrap(), 1);
        let ids: Vec<String> = db
            .arrivals_since(0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.coin_id)
            .collect();
        assert_eq!(ids, vec!["gift".to_string()]);
    }

    /// The batch-ordering hazard, isolated: the change coin is written BEFORE its parent within
    /// the same batch (peers choose the order). The recorder must still see the parent.
    #[tokio::test]
    async fn change_is_refused_even_when_it_is_written_before_its_parent() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();

        let mut change = coin("change", 400, Some(101), None);
        change.parent_coin_info = "funding".into();
        db.upsert_coins(&[change, incoming("funding", 1_000, 101)])
            .await
            .unwrap();

        // `funding` itself is an arrival (foreign parent); `change` is not.
        let ids: Vec<String> = {
            db.record_arrivals(&watched(), 101).await.unwrap();
            db.arrivals_since(0, 100)
                .await
                .unwrap()
                .into_iter()
                .map(|a| a.coin_id)
                .collect()
        };
        assert_eq!(ids, vec!["funding".to_string()]);
    }

    /// A CAT arrival carries its asset id, and an UNATTRIBUTED coin away from our p2 hashes is
    /// held rather than announced as XCH — then promoted once attribution names its asset.
    #[tokio::test]
    async fn a_cat_arrival_carries_its_asset_id_and_waits_until_attributed() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();

        // A hinted CAT coin lands at a curried puzzle hash with no asset id yet.
        let mut cat = incoming("catcoin", 300, 101);
        cat.puzzle_hash = "curried_cat_hash".into();
        db.upsert_coin(&cat).await.unwrap();
        assert_eq!(db.record_arrivals(&watched(), 101).await.unwrap(), 0);
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());

        // Attribution fills in the asset; the deferred coin is promoted on the next pass, even
        // though the baseline has since advanced past its height.
        db.attribute_cat_coin("catcoin", "a406d3a9", Some("ph"))
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 120).await.unwrap(), 1);
        let a = &db.arrivals_since(0, 100).await.unwrap()[0];
        assert_eq!(a.coin_id, "catcoin");
        assert_eq!(a.asset_id.as_deref(), Some("a406d3a9"));
        assert_eq!(a.confirmed_height, 101);
        assert_eq!(a.amount, "300");
    }

    /// A reorg unmakes the coins above the fork, so it must unmake their arrivals with them and
    /// walk the baseline back — otherwise the ledger asserts a receipt the chain no longer has.
    #[tokio::test]
    async fn a_reorg_unmakes_the_arrivals_it_unmakes_the_coins_for() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();
        db.upsert_coins(&[incoming("kept", 1, 101), incoming("orphaned", 2, 110)])
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 110).await.unwrap(), 2);

        db.rollback_above(105).await.unwrap();
        let ids: Vec<String> = db
            .arrivals_since(0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.coin_id)
            .collect();
        assert_eq!(ids, vec!["kept".to_string()]);
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(105));
    }

    /// The cursor is monotonic and survives a deletion: a client's stored `seq` never comes to
    /// point at a different arrival.
    #[tokio::test]
    async fn the_arrival_cursor_is_monotonic_and_never_reused() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();
        db.upsert_coin(&incoming("a", 1, 101)).await.unwrap();
        db.record_arrivals(&watched(), 101).await.unwrap();
        let first = db.arrival_cursor().await.unwrap();
        assert!(first > 0);

        db.rollback_above(100).await.unwrap();
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());

        db.upsert_coin(&incoming("b", 2, 101)).await.unwrap();
        db.record_arrivals(&watched(), 101).await.unwrap();
        let page = db.arrivals_since(first, 100).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].coin_id, "b");
        assert!(page[0].seq > first);
    }

    /// Money received while the node was OFF is news, not history: a later catch-up leaves the
    /// baseline alone (it is armed once), so coins above it are still announced exactly once.
    #[tokio::test]
    async fn funds_received_while_offline_are_announced_once_on_the_next_sync() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(100));

        // Offline. The node comes back and its catch-up replays history plus what it missed.
        db.upsert_coins(&[incoming("old", 1, 50), incoming("missed", 9, 150)])
            .await
            .unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 150, "hh2", &[]).unwrap())
            .await
            .unwrap();
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(100));

        assert_eq!(db.record_arrivals(&watched(), 150).await.unwrap(), 1);
        assert_eq!(
            db.arrivals_since(0, 100).await.unwrap()[0].coin_id,
            "missed"
        );
        // The watermark advances to what this pass examined, so the next pass need not re-read
        // history. It is the SCAN BOUND, not the dedup: trap 2 is held by the `UNIQUE` coin id
        // underneath (see the restart test), and this assertion exists so the bound cannot quietly
        // stop advancing and turn every pass into a full-table scan.
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(150));
        // And not again on the next pass.
        assert_eq!(db.record_arrivals(&watched(), 151).await.unwrap(), 0);
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(151));
    }

    /// TRAP 1, the hole a caller opens rather than the one a coin walks through: the ORACLE-tier
    /// refresh must not be able to arm the arrival baseline.
    ///
    /// `refresh_tracked_coins` is a point read against the coinset oracle for the wallet's own
    /// puzzle hashes, and it latches `initial_sync_complete` so wallet reads flip to the local DB.
    /// It has replayed no history — on a fresh install it can complete with `coins` empty and no
    /// peak at all. Arming a baseline from that arms it at ZERO, and because arming is permanent
    /// the LATER, genuine catch-up leaves it there. Every historical coin the catch-up then writes
    /// sits above zero, and the first live update afterwards announces the wallet's entire receive
    /// history as incoming payments — the exact burst the baseline exists to prevent.
    ///
    /// The fixture is that sequence verbatim, and it deliberately gives the oracle path NOTHING to
    /// arm from: an empty `coins` table and an unset peak, which is what a fresh install has. The
    /// positive control at the end is what stops this passing against a wallet that simply stopped
    /// announcing anything.
    #[tokio::test]
    async fn the_oracle_refresh_cannot_arm_the_baseline_so_no_burst_follows_the_real_catch_up() {
        let db = WalletDb::open_in_memory().await.unwrap();

        // What `refresh_tracked_coins` does on a fresh install with nothing in the DB yet.
        db.set_initial_sync_complete(true).await.unwrap();
        assert_eq!(
            db.arrival_baseline().await.unwrap(),
            None,
            "a caller that replayed no history armed the baseline"
        );

        // The genuine catch-up now runs and replays ten years of receipts.
        let history: Vec<CoinRow> = (1..=8)
            .map(|i| incoming(&format!("hist{i}"), 100, i * 1_000))
            .collect();
        db.upsert_coins(&history).await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 8_000, "hh", &[]).unwrap())
            .await
            .unwrap();
        assert_eq!(db.arrival_baseline().await.unwrap(), Some(8_000));

        // The first live update after the catch-up. Nothing new has arrived.
        assert_eq!(
            db.record_arrivals(&watched(), 8_001).await.unwrap(),
            0,
            "the wallet's whole receive history was announced as incoming payments"
        );
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());

        // POSITIVE CONTROL: a coin above the armed baseline still arrives.
        db.upsert_coin(&incoming("fresh", 100, 8_002))
            .await
            .unwrap();
        assert_eq!(db.record_arrivals(&watched(), 8_002).await.unwrap(), 1);
    }

    /// The catch-up's completion carries the peak it finished at, so the baseline and the peak
    /// cannot be armed from different facts.
    ///
    /// The fixture puts a coin ABOVE the reported peak, which happens when a batch lands at a
    /// height the terminal response has not caught up to. The armed baseline must cover it, or that
    /// coin is announced as an arrival on the very next pass.
    #[tokio::test]
    async fn completing_a_catch_up_arms_the_baseline_over_everything_it_wrote() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&incoming("high", 1, 220)).await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 200, "hh", &[]).unwrap())
            .await
            .unwrap();

        assert_eq!(db.arrival_baseline().await.unwrap(), Some(220));
        let state = db.sync_state().await.unwrap();
        assert_eq!(
            state.peak_height,
            Some(200),
            "the peak is the peer's, not the coin's"
        );
        assert!(state.initial_sync_complete);
        assert_eq!(db.record_arrivals(&watched(), 220).await.unwrap(), 0);
    }

    /// The DB-level refusal that actually implements trap 1, isolated from the classifier's own
    /// (redundant) [`Verdict::NoBaseline`] arm: with no baseline the recorder must not even reach
    /// the candidate scan, and must NOT arm the baseline itself — arming belongs to the statement
    /// that knows a catch-up completed.
    #[tokio::test]
    async fn the_recorder_refuses_and_arms_nothing_when_no_catch_up_has_completed() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.set_peak(500, "hh").await.unwrap();
        db.upsert_coin(&incoming("whatever", 42, 501))
            .await
            .unwrap();

        assert_eq!(db.record_arrivals(&watched(), 501).await.unwrap(), 0);
        assert!(db.arrivals_since(0, 100).await.unwrap().is_empty());
        assert_eq!(
            db.arrival_baseline().await.unwrap(),
            None,
            "the recorder armed a baseline it has no business arming"
        );
    }

    #[tokio::test]
    async fn migrations_create_the_single_sync_state_row() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let s = db.sync_state().await.unwrap();
        assert_eq!(s.peak_height, None);
        assert!(!s.initial_sync_complete);
    }

    #[tokio::test]
    async fn peak_and_sync_flag_round_trip() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 500, "deadbeef", &[]).unwrap())
            .await
            .unwrap();
        let s = db.sync_state().await.unwrap();
        assert_eq!(s.peak_height, Some(500));
        assert_eq!(s.header_hash.as_deref(), Some("deadbeef"));
        assert!(s.initial_sync_complete);
        assert!(db.is_synced().await.unwrap());
    }

    #[tokio::test]
    async fn upsert_coin_then_spend_updates_in_place() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 1);
        assert_eq!(db.balance(None).await.unwrap(), 100);
        // A later update spends it.
        db.upsert_coin(&coin("c1", 100, Some(10), Some(20)))
            .await
            .unwrap();
        assert_eq!(db.spendable_coin_count(None).await.unwrap(), 0);
        assert_eq!(db.balance(None).await.unwrap(), 0);
        assert!(!db.are_coins_spendable(&["c1".into()]).await.unwrap());
    }

    #[tokio::test]
    async fn reorg_rollback_undoes_creates_and_spends_above_height() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("keep", 5, Some(10), None))
            .await
            .unwrap();
        db.upsert_coin(&coin("spent_late", 7, Some(10), Some(30)))
            .await
            .unwrap();
        db.upsert_coin(&coin("created_late", 9, Some(40), None))
            .await
            .unwrap();
        db.set_peak(40, "hh").await.unwrap();

        // Reorg to height 25: `created_late` (created@40) vanishes; `spent_late`
        // (spent@30) becomes unspent again; `keep` (created@10, unspent) is untouched.
        db.rollback_above(25).await.unwrap();

        let ids: Vec<String> = db
            .all_coins()
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.coin_id)
            .collect();
        assert!(ids.contains(&"keep".to_string()));
        assert!(ids.contains(&"spent_late".to_string()));
        assert!(!ids.contains(&"created_late".to_string()));
        // keep (5) + spent_late (7, now unspent) = 12
        assert_eq!(db.balance(None).await.unwrap(), 12);
        assert_eq!(db.sync_state().await.unwrap().peak_height, Some(25));
    }

    #[tokio::test]
    async fn cat_coins_and_metadata_track_by_asset() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = coin("cat1", 300, Some(10), None);
        c.asset_id = Some("abc123".into());
        c.hint = Some("ph".into());
        db.upsert_coin(&c).await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: "abc123".into(),
            name: Some("Test CAT".into()),
            ticker: Some("TST".into()),
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
        })
        .await
        .unwrap();

        assert_eq!(db.balance(Some("abc123")).await.unwrap(), 300);
        assert_eq!(db.balance(None).await.unwrap(), 0); // not an XCH coin
        assert_eq!(
            db.owned_cat_asset_ids().await.unwrap(),
            vec!["abc123".to_string()]
        );
        assert!(db.is_asset_owned("abc123").await.unwrap());
        assert!(!db.is_asset_owned("nope").await.unwrap());
        assert_eq!(db.all_cats().await.unwrap().len(), 1);
        assert_eq!(
            db.cat("abc123").await.unwrap().unwrap().ticker.as_deref(),
            Some("TST")
        );
    }

    #[tokio::test]
    async fn derivations_paginate_and_count() {
        let db = WalletDb::open_in_memory().await.unwrap();
        for i in 0..5 {
            db.upsert_derivation(&DerivationRow {
                hardened: false,
                index: i,
                public_key: format!("pk{i}"),
                puzzle_hash: format!("ph{i}"),
                address: format!("xch{i}"),
            })
            .await
            .unwrap();
        }
        let (page, total) = db.get_derivations(false, 1, 2).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].index, 1);
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 5);
        assert_eq!(db.max_derivation_index(true).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn coins_by_ids_returns_only_matches() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("a", 1, Some(1), None)).await.unwrap();
        db.upsert_coin(&coin("b", 2, Some(1), None)).await.unwrap();
        let got = db
            .coins_by_ids(&["a".into(), "missing".into()])
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].coin_id, "a");
    }

    #[tokio::test]
    async fn attribute_cat_coin_sets_asset_and_makes_it_owned() {
        let db = WalletDb::open_in_memory().await.unwrap();
        // A coin arrives from sync with no asset attribution yet.
        db.upsert_coin(&coin("catcoin", 300, Some(10), None))
            .await
            .unwrap();
        assert!(!db.is_asset_owned("abc").await.unwrap());
        // The sync loop uncurries its CAT layer and attributes it.
        db.attribute_cat_coin("catcoin", "abc", Some("hint1"))
            .await
            .unwrap();
        assert_eq!(db.balance(Some("abc")).await.unwrap(), 300);
        assert_eq!(db.balance(None).await.unwrap(), 0);
        assert_eq!(
            db.owned_cat_asset_ids().await.unwrap(),
            vec!["abc".to_string()]
        );
        assert!(db.is_asset_owned("abc").await.unwrap());
    }

    #[tokio::test]
    async fn nft_upsert_read_and_overwrite_on_new_coin() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_nft(&NftDbRow {
            launcher_id: "l1".into(),
            coin_id: "c1".into(),
            collection_id: Some("col1".into()),
            minter_did: Some("did1".into()),
            owner_did: None,
            name: Some("Cool NFT".into()),
            visible: true,
            created_height: Some(100),
            record_json: r#"{"launcher_id":"l1"}"#.into(),
        })
        .await
        .unwrap();
        assert_eq!(db.all_nfts().await.unwrap().len(), 1);
        assert_eq!(db.nft("l1").await.unwrap().unwrap().coin_id, "c1");
        // A later coin for the same launcher overwrites the current coin id.
        db.upsert_nft(&NftDbRow {
            launcher_id: "l1".into(),
            coin_id: "c2".into(),
            collection_id: Some("col1".into()),
            minter_did: Some("did1".into()),
            owner_did: Some("did9".into()),
            name: Some("Cool NFT".into()),
            visible: true,
            created_height: Some(200),
            record_json: r#"{"launcher_id":"l1","v":2}"#.into(),
        })
        .await
        .unwrap();
        assert_eq!(db.all_nfts().await.unwrap().len(), 1);
        let n = db.nft("l1").await.unwrap().unwrap();
        assert_eq!(n.coin_id, "c2");
        assert_eq!(n.owner_did.as_deref(), Some("did9"));

        db.set_nft_metadata_json("l1", r#"{"name":"Cool NFT"}"#)
            .await
            .unwrap();
        assert_eq!(
            db.nft_metadata_json("l1").await.unwrap().as_deref(),
            Some(r#"{"name":"Cool NFT"}"#)
        );
    }

    #[tokio::test]
    async fn did_and_collection_upsert_read() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_did(&DidDbRow {
            launcher_id: "did1".into(),
            coin_id: "dc1".into(),
            name: None,
            visible: true,
            created_height: Some(50),
            record_json: r#"{"launcher_id":"did1"}"#.into(),
        })
        .await
        .unwrap();
        assert_eq!(db.all_dids().await.unwrap().len(), 1);
        assert!(db.is_asset_owned("did1").await.unwrap());

        db.upsert_nft_collection(&NftCollectionDbRow {
            collection_id: "col1".into(),
            did_id: "did1".into(),
            metadata_collection_id: "meta-col".into(),
            name: Some("My Collection".into()),
            visible: true,
            record_json: r#"{"collection_id":"col1"}"#.into(),
        })
        .await
        .unwrap();
        assert_eq!(db.all_nft_collections().await.unwrap().len(), 1);
        assert_eq!(
            db.nft_collection("col1")
                .await
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("My Collection")
        );
    }

    // ---- user themes (#205 PR4) --------------------------------------------

    #[tokio::test]
    async fn user_themes_save_get_delete_round_trip() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert!(db.user_theme("nft1").await.unwrap().is_none());
        assert!(db.all_theme_nft_ids().await.unwrap().is_empty());

        db.save_user_theme("nft1", "dark-purple").await.unwrap();
        assert_eq!(
            db.user_theme("nft1").await.unwrap().as_deref(),
            Some("dark-purple")
        );
        assert_eq!(db.all_theme_nft_ids().await.unwrap(), vec!["nft1"]);

        // Overwrite.
        db.save_user_theme("nft1", "light-blue").await.unwrap();
        assert_eq!(
            db.user_theme("nft1").await.unwrap().as_deref(),
            Some("light-blue")
        );

        db.delete_user_theme("nft1").await.unwrap();
        assert!(db.user_theme("nft1").await.unwrap().is_none());
    }

    // ---- record-update actions (#205 PR4) ------------------------------------

    #[tokio::test]
    async fn resync_cat_clears_cached_metadata_only() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: "a1".into(),
            name: Some("Old Name".into()),
            ticker: Some("OLD".into()),
            precision: 3,
            description: Some("stale".into()),
            icon_url: Some("http://x".into()),
            visible: true,
        })
        .await
        .unwrap();
        db.clear_cat_metadata("a1").await.unwrap();
        let cat = db.cat("a1").await.unwrap().unwrap();
        assert!(cat.name.is_none());
        assert!(cat.ticker.is_none());
        assert!(cat.description.is_none());
        assert!(cat.icon_url.is_none());
        assert!(cat.visible, "visible flag is untouched by resync");
    }

    #[tokio::test]
    async fn update_cat_metadata_upserts() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.update_cat_metadata(
            "a2",
            Some("New Name"),
            Some("NEW"),
            Some("desc"),
            Some("http://icon"),
            false,
        )
        .await
        .unwrap();
        let cat = db.cat("a2").await.unwrap().unwrap();
        assert_eq!(cat.name.as_deref(), Some("New Name"));
        assert!(!cat.visible);
    }

    #[tokio::test]
    async fn update_did_fields_patches_column_and_json() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_did(&DidDbRow {
            launcher_id: "didX".into(),
            coin_id: "c1".into(),
            name: Some("Old".into()),
            visible: true,
            created_height: Some(1),
            record_json: r#"{"launcher_id":"didX","name":"Old","visible":true}"#.into(),
        })
        .await
        .unwrap();

        db.update_did_fields("didX", Some("New"), false)
            .await
            .unwrap();

        let row = db.all_dids().await.unwrap().into_iter().next().unwrap();
        assert_eq!(row.name.as_deref(), Some("New"));
        assert!(!row.visible);
        let json: serde_json::Value = serde_json::from_str(&row.record_json).unwrap();
        assert_eq!(json["name"], "New");
        assert_eq!(json["visible"], false);
    }

    #[tokio::test]
    async fn update_nft_visible_patches_column_and_json() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_nft(&NftDbRow {
            launcher_id: "nftX".into(),
            coin_id: "c1".into(),
            collection_id: None,
            minter_did: None,
            owner_did: None,
            name: Some("N".into()),
            visible: true,
            created_height: Some(1),
            record_json: r#"{"launcher_id":"nftX","visible":true}"#.into(),
        })
        .await
        .unwrap();

        db.update_nft_visible("nftX", false).await.unwrap();

        let row = db.nft("nftX").await.unwrap().unwrap();
        assert!(!row.visible);
        let json: serde_json::Value = serde_json::from_str(&row.record_json).unwrap();
        assert_eq!(json["visible"], false);
    }

    #[tokio::test]
    async fn update_nft_collection_visible_patches_column_and_json() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_nft_collection(&NftCollectionDbRow {
            collection_id: "colX".into(),
            did_id: "didX".into(),
            metadata_collection_id: "mc".into(),
            name: Some("Coll".into()),
            visible: true,
            record_json: r#"{"collection_id":"colX","visible":true}"#.into(),
        })
        .await
        .unwrap();

        db.update_nft_collection_visible("colX", false)
            .await
            .unwrap();

        let row = db.nft_collection("colX").await.unwrap().unwrap();
        assert!(!row.visible);
        let json: serde_json::Value = serde_json::from_str(&row.record_json).unwrap();
        assert_eq!(json["visible"], false);
    }

    #[tokio::test]
    async fn redownload_nft_clears_metadata_json_only() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_nft(&NftDbRow {
            launcher_id: "nftY".into(),
            coin_id: "c1".into(),
            collection_id: None,
            minter_did: None,
            owner_did: None,
            name: Some("N".into()),
            visible: true,
            created_height: Some(1),
            record_json: r#"{"launcher_id":"nftY"}"#.into(),
        })
        .await
        .unwrap();
        db.set_nft_metadata_json("nftY", r#"{"cached":true}"#)
            .await
            .unwrap();
        assert!(db.nft_metadata_json("nftY").await.unwrap().is_some());

        db.clear_nft_metadata_json("nftY").await.unwrap();
        assert!(db.nft_metadata_json("nftY").await.unwrap().is_none());
        // The record itself is untouched.
        assert!(db.nft("nftY").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn increase_derivation_index_raises_floor_never_lowers() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 0);

        db.raise_derivation_floor(false, 50).await.unwrap();
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 50);

        // A lower floor request never regresses the reported index.
        db.raise_derivation_floor(false, 10).await.unwrap();
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 50);

        // A real derivation row above the floor still wins.
        db.upsert_derivation(&DerivationRow {
            hardened: false,
            index: 99,
            public_key: "pk".into(),
            puzzle_hash: "ph".into(),
            address: "xch1x".into(),
        })
        .await
        .unwrap();
        assert_eq!(db.max_derivation_index(false).await.unwrap(), 100);

        // Hardened and unhardened floors are independent.
        assert_eq!(db.max_derivation_index(true).await.unwrap(), 0);
    }

    // ---- options (#205 PR4) ---------------------------------------------------

    #[tokio::test]
    async fn options_upsert_list_get_update_visible() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_option(&OptionDbRow {
            option_id: "opt1".into(),
            coin_id: "c1".into(),
            underlying_coin_id: "u1".into(),
            underlying_delegated_puzzle_hash: "dph".into(),
            p2_puzzle_hash: "p2".into(),
            visible: true,
            created_height: Some(5),
            record_json: r#"{"option_id":"opt1","visible":true}"#.into(),
        })
        .await
        .unwrap();

        assert_eq!(db.all_options().await.unwrap().len(), 1);
        assert!(db.option("opt1").await.unwrap().is_some());
        assert!(db.option("missing").await.unwrap().is_none());

        db.update_option_visible("opt1", false).await.unwrap();
        let row = db.option("opt1").await.unwrap().unwrap();
        assert!(!row.visible);
        let json: serde_json::Value = serde_json::from_str(&row.record_json).unwrap();
        assert_eq!(json["visible"], false);
    }

    // ---- peers (#205 PR4) ------------------------------------------------------

    #[tokio::test]
    async fn add_remove_and_ban_peer() {
        let db = WalletDb::open_in_memory().await.unwrap();
        assert!(db.unbanned_peers().await.unwrap().is_empty());

        db.add_peer("1.2.3.4", 8444).await.unwrap();
        let peers = db.unbanned_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip_addr, "1.2.3.4");
        assert_eq!(peers[0].port, 8444);
        assert!(peers[0].user_managed);

        // Removing without ban deletes it outright.
        db.remove_peer("1.2.3.4", false).await.unwrap();
        assert!(db.unbanned_peers().await.unwrap().is_empty());

        // Adding then banning excludes it from the list (but a subsequent add un-bans it).
        db.add_peer("5.6.7.8", 8444).await.unwrap();
        db.remove_peer("5.6.7.8", true).await.unwrap();
        assert!(db.unbanned_peers().await.unwrap().is_empty());
        db.add_peer("5.6.7.8", 8444).await.unwrap();
        assert_eq!(db.unbanned_peers().await.unwrap().len(), 1);
    }

    /// **Adding a BANNED peer un-bans it and does NOT grant trust, and says so (#254 item 4).**
    ///
    /// The fixture varies ONE thing — whether the address was already held as banned — and keeps
    /// an honest control (`fresh`) in the same test, because a test that only exercised the banned
    /// path could not tell "always reports false" from "reports the truth". Both calls SUCCEED;
    /// what differs is the trust that resulted, which is exactly the distinction a constant `true`
    /// used to erase.
    #[tokio::test]
    async fn adding_a_banned_peer_unbans_it_without_granting_trust() {
        let db = WalletDb::open_in_memory().await.unwrap();

        let fresh = db.add_peer("1.1.1.1", 8444).await.unwrap();
        assert!(fresh, "an ordinary add DOES confer the corroboration bypass");

        db.remove_peer("2.2.2.2", true).await.unwrap();
        let unbanned = db.add_peer("2.2.2.2", 8444).await.unwrap();
        assert!(
            !unbanned,
            "add cleared the ban but left user_managed alone, so the peer is NOT trusted -- \
             reporting otherwise tells an operator they configured a trusted node while they are \
             still depending on corroboration they were told they had bypassed"
        );

        // And the un-ban really happened: the peer is dialable again, just not trusted.
        let rows = db.unbanned_peers().await.unwrap();
        let row = rows.iter().find(|p| p.ip_addr == "2.2.2.2").expect("unbanned");
        assert!(!row.banned && !row.user_managed);
    }

    /// **The control-plane list shows banned peers; the dialling read never does (#254 item 5).**
    ///
    /// Two reads, one fixture, and the difference between them is the whole point: `list` is the
    /// ONLY enumeration of the ban set, so hiding bans there leaves a blocklist a person cannot
    /// correct — while surfacing them in the DIALLING read would hand the dialler the very peer
    /// the operator banned. A single relaxed query cannot satisfy both, which is why they are
    /// separate functions and why this test asserts them together.
    #[tokio::test]
    async fn banned_peers_are_listed_for_the_operator_but_never_dialled() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.add_peer("3.3.3.3", 8444).await.unwrap();
        db.add_peer("4.4.4.4", 8444).await.unwrap();
        db.remove_peer("4.4.4.4", true).await.unwrap();

        let dialable: Vec<String> = db
            .unbanned_peers()
            .await
            .unwrap()
            .into_iter()
            .map(|p| p.ip_addr)
            .collect();
        assert_eq!(dialable, ["3.3.3.3"], "a banned peer reached the dialler");

        let listed = db.all_peers_including_banned().await.unwrap();
        assert_eq!(listed.len(), 2, "the ban list must be enumerable");
        let banned = listed.iter().find(|p| p.ip_addr == "4.4.4.4").expect("row");
        assert!(banned.banned, "the entry must say WHY it is excluded");

        // Un-banning via `remove { ban: false }` restores dialability and grants no trust.
        db.remove_peer("4.4.4.4", false).await.unwrap();
        assert!(db
            .all_peers_including_banned()
            .await
            .unwrap()
            .iter()
            .all(|p| p.ip_addr != "4.4.4.4"));
    }

    /// **The ban list is bounded, and it forgets its OLDEST entry rather than refusing the newest
    /// (#254 item 9).**
    ///
    /// The bound is pinned from BOTH sides: at exactly `MAX_BANNED_CHIA_PEERS` nothing is evicted,
    /// and one over evicts exactly one. A test that only filled past the cap could not tell a
    /// correct bound from one that is off by one or that truncates aggressively.
    ///
    /// The DIRECTION is asserted too, and it is the half that matters: a full list that refused
    /// the newest ban would turn the ceiling into a denial of the ban facility itself, precisely
    /// when an operator is trying to exclude a peer that is misbehaving right now.
    #[tokio::test]
    async fn the_ban_list_is_bounded_and_evicts_the_oldest_ban() {
        let db = WalletDb::open_in_memory().await.unwrap();
        async fn banned_count(db: &WalletDb) -> usize {
            db.all_peers_including_banned()
                .await
                .unwrap()
                .iter()
                .filter(|p| p.banned)
                .count()
        }

        for i in 0..MAX_BANNED_CHIA_PEERS {
            db.remove_peer(&format!("10.0.{}.{}", i / 256, i % 256), true)
                .await
                .unwrap();
        }
        assert_eq!(
            banned_count(&db).await,
            MAX_BANNED_CHIA_PEERS,
            "at the cap nothing may be evicted"
        );

        let oldest = "10.0.0.0";
        db.remove_peer("198.51.100.1", true).await.unwrap();
        assert_eq!(
            banned_count(&db).await,
            MAX_BANNED_CHIA_PEERS,
            "one over the cap must evict exactly one"
        );

        let rows = db.all_peers_including_banned().await.unwrap();
        assert!(
            rows.iter().any(|p| p.ip_addr == "198.51.100.1" && p.banned),
            "the NEWEST ban must survive -- refusing it would deny the ban facility when it is \
             most needed"
        );
        assert!(
            !rows.iter().any(|p| p.ip_addr == oldest),
            "the OLDEST ban is the one that gets forgotten"
        );
    }

    // ---- network / sync settings (#205 PR4) ------------------------------------

    #[tokio::test]
    async fn network_settings_defaults_and_setters() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let s = db.network_settings().await.unwrap();
        assert!(s.discover_peers);
        assert_eq!(s.target_peers, 3);
        assert!(s.network_override.is_none());
        assert!(s.delta_sync);
        assert!(s.delta_sync_override.is_none());
        assert!(s.change_address.is_none());

        db.set_discover_peers(false).await.unwrap();
        db.set_target_peers(7).await.unwrap();
        db.set_network_override(Some("testnet11")).await.unwrap();
        db.set_delta_sync(false).await.unwrap();
        db.set_delta_sync_override(Some(true)).await.unwrap();
        db.set_change_address(Some("xch1change")).await.unwrap();

        let s2 = db.network_settings().await.unwrap();
        assert!(!s2.discover_peers);
        assert_eq!(s2.target_peers, 7);
        assert_eq!(s2.network_override.as_deref(), Some("testnet11"));
        assert!(!s2.delta_sync);
        assert_eq!(s2.delta_sync_override, Some(true));
        assert_eq!(s2.change_address.as_deref(), Some("xch1change"));
    }
}
