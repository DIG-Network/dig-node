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
    banned INTEGER NOT NULL DEFAULT 0
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

    /// Every non-banned tracked peer (`get_peers`). `peak_height` is 0 until live per-peer
    /// telemetry is wired (SPEC §18.16) — never fabricated.
    pub async fn all_peers(&self) -> sqlx::Result<Vec<PeerRow>> {
        let rows = sqlx::query(
            "SELECT ip_addr, port, peak_height, user_managed, banned FROM peers
             WHERE banned = 0 ORDER BY ip_addr",
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
    pub async fn add_peer(&self, ip_addr: &str, port: i64) -> sqlx::Result<()> {
        sqlx::query(
            "INSERT INTO peers (ip_addr, port, peak_height, user_managed, banned)
             VALUES (?, ?, 0, 1, 0)
             ON CONFLICT(ip_addr) DO UPDATE SET port = excluded.port, banned = 0",
        )
        .bind(ip_addr)
        .bind(port)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove a peer (`remove_peer { ban: false }`, deletes the row) or ban it
    /// (`remove_peer { ban: true }`, kept but excluded from [`Self::all_peers`]).
    pub async fn remove_peer(&self, ip_addr: &str, ban: bool) -> sqlx::Result<()> {
        if ban {
            sqlx::query(
                "INSERT INTO peers (ip_addr, port, peak_height, user_managed, banned)
                 VALUES (?, 0, 0, 0, 1)
                 ON CONFLICT(ip_addr) DO UPDATE SET banned = 1",
            )
            .bind(ip_addr)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query("DELETE FROM peers WHERE ip_addr = ?")
                .bind(ip_addr)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
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
        assert!(db.all_peers().await.unwrap().is_empty());

        db.add_peer("1.2.3.4", 8444).await.unwrap();
        let peers = db.all_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].ip_addr, "1.2.3.4");
        assert_eq!(peers[0].port, 8444);
        assert!(peers[0].user_managed);

        // Removing without ban deletes it outright.
        db.remove_peer("1.2.3.4", false).await.unwrap();
        assert!(db.all_peers().await.unwrap().is_empty());

        // Adding then banning excludes it from the list (but a subsequent add un-bans it).
        db.add_peer("5.6.7.8", 8444).await.unwrap();
        db.remove_peer("5.6.7.8", true).await.unwrap();
        assert!(db.all_peers().await.unwrap().is_empty());
        db.add_peer("5.6.7.8", 8444).await.unwrap();
        assert_eq!(db.all_peers().await.unwrap().len(), 1);
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
