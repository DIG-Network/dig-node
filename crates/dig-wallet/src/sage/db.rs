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

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// A handle to the local wallet database.
#[derive(Clone)]
pub struct WalletDb {
    pool: SqlitePool,
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

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    peak_height INTEGER,
    header_hash TEXT,
    initial_sync_complete INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sync_state (id, peak_height, header_hash, initial_sync_complete)
    VALUES (0, NULL, NULL, 0);

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
];

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
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn from_options(opts: SqliteConnectOptions) -> sqlx::Result<Self> {
        let pool = SqlitePoolOptions::new().connect_with(opts).await?;
        let db = Self { pool };
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
        Ok(())
    }

    // ---- sync state -------------------------------------------------------

    /// Read the current sync state.
    pub async fn sync_state(&self) -> sqlx::Result<SyncState> {
        let row = sqlx::query(
            "SELECT peak_height, header_hash, initial_sync_complete FROM sync_state WHERE id = 0",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(SyncState {
            peak_height: row.get::<Option<i64>, _>("peak_height").map(|h| h as u32),
            header_hash: row.get::<Option<String>, _>("header_hash"),
            initial_sync_complete: row.get::<i64, _>("initial_sync_complete") != 0,
        })
    }

    /// Whether the initial catch-up has completed (the routing gate, B.6).
    pub async fn is_synced(&self) -> sqlx::Result<bool> {
        Ok(self.sync_state().await?.initial_sync_complete)
    }

    /// Advance the synced peak.
    pub async fn set_peak(&self, height: u32, header_hash: &str) -> sqlx::Result<()> {
        sqlx::query("UPDATE sync_state SET peak_height = ?, header_hash = ? WHERE id = 0")
            .bind(i64::from(height))
            .bind(header_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Mark the initial catch-up complete (or not).
    pub async fn set_initial_sync_complete(&self, complete: bool) -> sqlx::Result<()> {
        sqlx::query("UPDATE sync_state SET initial_sync_complete = ? WHERE id = 0")
            .bind(i64::from(complete))
            .execute(&self.pool)
            .await?;
        Ok(())
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

    /// The highest derivation index seen for one HD tree (for `get_sync_status`).
    pub async fn max_derivation_index(&self, hardened: bool) -> sqlx::Result<u32> {
        let n: Option<i64> =
            sqlx::query("SELECT MAX(idx) AS m FROM derivations WHERE hardened = ?")
                .bind(hardened)
                .fetch_one(&self.pool)
                .await?
                .get("m");
        Ok(n.map(|v| v as u32 + 1).unwrap_or(0))
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
    pub async fn rollback_above(&self, height: u32) -> sqlx::Result<()> {
        let h = i64::from(height);
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM coins WHERE created_height IS NOT NULL AND created_height > ?")
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
        db.set_peak(500, "deadbeef").await.unwrap();
        db.set_initial_sync_complete(true).await.unwrap();
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
}
