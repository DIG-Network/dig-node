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

use std::collections::HashSet;
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

/// A spend bundle this node pushed that has not yet been observed settling, together with the
/// coins it committed (dig_ecosystem#2763).
///
/// This is the record the wallet previously did not keep. Without it a broadcast marked nothing,
/// so a second send inside the confirmation window re-selected the same coin and was refused by
/// the mempool for a reason the caller could not act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransactionRow {
    /// The spend bundle's id (`SpendBundle::name`, hex) — the transaction id a caller polls by.
    pub transaction_id: String,
    /// The complete signed bundle, hex-encoded, so a bundle accepted and then dropped from the
    /// mempool can be re-pushed BYTE-IDENTICALLY rather than rebuilt (a rebuild would be a
    /// different transaction, and the node cannot rebuild a bundle it did not sign).
    ///
    /// Not a secret: these exact bytes were broadcast to a public mempool. Storing them adds no
    /// disclosure, and a bundle whose push was definitively refused is deleted rather than kept.
    pub bundle_hex: String,
    /// The bundle's fee in mojos, as the consensus computes it (inputs minus outputs), or `None`
    /// when this node could not compute it.
    ///
    /// Optional because the node relays bundles it did not build and did not sign (§908). The fee
    /// is recovered by running the spends through `dig-clvm`, which can legitimately fail for a
    /// bundle that is still perfectly valid to relay. `None` is then the honest answer, and it is
    /// kept as `None` all the way to the caller rather than being flattened to zero — a fee of
    /// zero is a claim about money, and this row exists because the surface above it was making
    /// claims it could not support (dig_ecosystem#2764).
    pub fee: Option<String>,
    /// When the bundle was first pushed, ms since the Unix epoch.
    pub submitted_at: i64,
    /// When the reservation lapses, ms since the Unix epoch. A reservation ALWAYS expires: a
    /// release path that fails to run must not be able to strand a coin permanently.
    pub expires_at: i64,
    /// How many times this bundle has been pushed (1 on first broadcast).
    pub attempts: i64,
    /// The coin ids the bundle spends — the coins held out of further selection while it is live.
    pub reserved_coin_ids: Vec<String>,
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

/// How many discovered-but-unproven CAT coins the staging table holds.
///
/// A staged row is a dozen short hex fields — call it 400 bytes with SQLite's overhead — so
/// 20 000 rows is roughly **8 MiB**, comfortably below the chain caches this file already budgets
/// (`CHAIN_READ_CACHE_MAX_ROWS` alone is ~20 MiB) because a staged row is strictly shorter-lived.
///
/// The number is chosen from what an ATTACKER must spend, not from what a wallet needs. Every
/// staged row costs its creator at least one `CREATE_COIN` and one mojo, and a legitimate wallet
/// stages one row per genuinely-received CAT coin — so 20 000 is several orders of magnitude
/// above any honest backlog while still bounding the table against a spend crafted to fill it.
pub const CAT_ADMISSION_PENDING_MAX_ROWS: i64 = 20_000;

/// Which singleton table a proven staged coin belongs in.
///
/// Borrowed rather than owned because the caller already holds the reconstructed row and the write
/// is the last thing done with it.
#[derive(Debug, Clone, Copy)]
pub enum PromotedSingleton<'a> {
    /// Write the coin to `nfts`.
    Nft(&'a NftDbRow),
    /// Write the coin to `dids`.
    Did(&'a DidDbRow),
}

/// A discovered CAT coin awaiting a lineage proof.
///
/// Deliberately NOT a [`CoinRow`]. The two types describe different claims: a `CoinRow` is a coin
/// the wallet BELIEVES it owns as the asset it is typed with, and every balance, coin-selection
/// and arrival-notification read is entitled to trust it. A `StagedCatRow` is a coin the wallet has
/// merely FOUND at a hash it derived, together with the derivation that found it — a hypothesis.
/// Sharing one type between the two would make the difference a field rather than a table, which
/// is exactly the shape this design rejects.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StagedCatRow {
    /// The coin id (hex, 64 chars).
    pub coin_id: String,
    /// The parent coin id (hex) — what promotion reads the spend of.
    pub parent_coin_info: String,
    /// The outer puzzle hash the coin sits at (hex).
    pub puzzle_hash: String,
    /// The amount, decimal string.
    pub amount: String,
    /// The created block height, if confirmed.
    pub created_height: Option<i64>,
    /// The spent block height, if spent.
    pub spent_height: Option<i64>,
    /// The created timestamp.
    pub created_timestamp: Option<i64>,
    /// The spent timestamp.
    pub spent_timestamp: Option<i64>,
    /// The asset id whose derived hash this coin was found at — the CLAIM promotion must confirm
    /// against the parent spend, never a fact.
    pub derived_asset_id: String,
    /// The owner p2 hash the derivation curried — likewise a claim, confirmed at promotion.
    pub derived_owner_p2: String,
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

CREATE TABLE IF NOT EXISTS cat_admission_pending (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    coin_id TEXT NOT NULL UNIQUE,
    parent_coin_info TEXT NOT NULL,
    puzzle_hash TEXT NOT NULL,
    amount TEXT NOT NULL,
    created_height INTEGER,
    spent_height INTEGER,
    created_timestamp INTEGER,
    spent_timestamp INTEGER,
    derived_asset_id TEXT NOT NULL,
    derived_owner_p2 TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_cat_admission_pending_created
    ON cat_admission_pending (created_height);
-- The promotion queue's ORDER BY. Fewest attempts first, then arrival order: a row that keeps
-- failing sinks, so it can never hold the queue head against a row that has never been tried.
CREATE INDEX IF NOT EXISTS idx_cat_admission_pending_queue
    ON cat_admission_pending (attempts, seq);

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

CREATE TABLE IF NOT EXISTS pending_transactions (
    transaction_id TEXT PRIMARY KEY,
    bundle_hex TEXT NOT NULL,
    fee TEXT,
    submitted_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS coin_reservations (
    coin_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL
        REFERENCES pending_transactions (transaction_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_coin_reservations_tx ON coin_reservations (transaction_id);

-- Coins held for a client that has SELECTED them but has not yet pushed a bundle
-- (dig_ecosystem#3127). Deliberately NOT a row in `coin_reservations`: that table's rows are
-- children of a `pending_transactions` row, and a client reservation has no bundle yet. Faking a
-- pending transaction to reuse it would make `pending_transactions()` report an in-flight spend
-- that does not exist.
--
-- `coin_id` is the PRIMARY KEY, and that is the atomicity guarantee rather than a tidiness one:
-- two callers racing for the same coin cannot both insert it, whatever either of them read first.
CREATE TABLE IF NOT EXISTS client_coin_reservations (
    coin_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_client_coin_reservations_id
    ON client_coin_reservations (reservation_id);

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
    // The CAT staging queue's attempt accounting (dig-node#394). A replica that ran an earlier
    // build of this branch already has the table without them.
    "ALTER TABLE cat_admission_pending ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE cat_admission_pending ADD COLUMN last_attempt_at INTEGER",
];

// ---- one-shot data-migration ladder ---------------------------------------
//
// [`ADD_COLUMN_MIGRATIONS`] above are idempotent DDL and cost nothing to re-run, so they need no
// bookkeeping. A DATA migration is different: it reads and rewrites rows, so re-running it on
// every open is unbounded work on a hot path for a job that only ever needs doing once. The
// applied level is kept in SQLite's own `PRAGMA user_version` — a database that predates this
// ladder reads 0, which is exactly right, since nothing has been applied to it.

/// Ladder step 1: the `offers` table is keyed by the canonical offer id (dig-node#283) rather
/// than by a value derived from the offered coin set.
const OFFERS_KEYED_BY_CANONICAL_ID: i64 = 1;

/// Ladder step 2: every hex identity in `coins` is stored lower-case (dig-node#293), and the
/// tables that key rows by a coin id agree with it.
const COINS_STORED_LOWER_CASE: i64 = 2;

/// Every table whose rows are keyed by a coin id, and which [`COINS_STORED_LOWER_CASE`] must
/// therefore normalise together.
///
/// `arrival_pending` and `arrivals` hold copies of `coins.coin_id` and are compared against it
/// raw, so normalising one table without the others is a desync, not a partial fix.
const COIN_ID_TABLES: [&str; 3] = ["coins", "arrival_pending", "arrivals"];

/// Ladder step 3: every hex value the wallet SCOPES or KEYS on is stored lower-case
/// (dig-node#298) — the three `coins` scoping columns and the two hex columns outside it.
const SCOPED_HEX_STORED_LOWER_CASE: i64 = 3;

/// Every `(table, column)` holding a hex value that a lower-cased bind is compared against, and
/// which [`SCOPED_HEX_STORED_LOWER_CASE`] therefore normalises.
///
/// **None of these columns is a key**, which is what makes them a plain `UPDATE`: two spellings
/// of one puzzle hash are two legitimate rows, not a uniqueness violation, so there is nothing to
/// collide and nothing to drop. `cats.asset_id` is the sole exception and is handled separately
/// by [`WalletDb::merge_cat_case_collisions`], because it IS a `PRIMARY KEY`.
///
/// `arrivals` and the two chain caches are included even though their own writers copy already-
/// normalised values out of `coins`: a row written by a PRE-fix build is on disk regardless of
/// what the current writer does, and `arrivals.puzzle_hash` is reported to the user as the
/// address a payment landed at.
const SCOPED_HEX_COLUMNS: [(&str, &str); 8] = [
    ("coins", "puzzle_hash"),
    ("coins", "asset_id"),
    ("coins", "hint"),
    ("derivations", "puzzle_hash"),
    ("arrivals", "puzzle_hash"),
    ("arrivals", "asset_id"),
    ("chain_read_cache", "puzzle_hash"),
    ("chain_spend_cache", "puzzle_hash"),
];

/// The highest ladder step this build knows how to apply.
const SCHEMA_VERSION: i64 = SCOPED_HEX_STORED_LOWER_CASE;

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
        // One-shot data migrations, gated on the ladder so they cost nothing on an opened-again
        // database. Read the mark before releasing the connection.
        let applied: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *conn)
            .await?;
        drop(conn);

        if applied < OFFERS_KEYED_BY_CANONICAL_ID {
            self.rekey_offers_to_canonical_ids().await?;
        }
        if applied < COINS_STORED_LOWER_CASE {
            self.normalise_stored_coin_hex().await?;
        }
        if applied < SCOPED_HEX_STORED_LOWER_CASE {
            self.normalise_stored_scoped_hex().await?;
        }

        // Marked only after every step above SUCCEEDED, so a migration that failed part-way is
        // retried on the next open rather than being recorded as done.
        if applied < SCHEMA_VERSION {
            sqlx::query(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Lower-case the hex identities of coins written before the writer normalised (dig-node#293).
    ///
    /// Fixing [`Self::upsert_coin`] does nothing for rows already on disk, so a fix without this
    /// step would appear to work on a fresh database and leave every existing one untouched.
    ///
    /// # No in-tree writer can have produced an upper-case identity
    ///
    /// Every path that reaches the `coins` table already emits lower-case hex and did so before
    /// this migration existed: the subscription writer builds ids with `hex::encode`
    /// (`sync.rs::coin_state_to_row`), the coinset fallback normalises in `map_record`
    /// (`fallback.rs`), the dialled-peer read uses `hex::encode` (`peer_reads/dialed.rs`), and the
    /// read cache replays whatever those three stored (`peer_reads.rs::coin_from_cache`). So on
    /// any wallet this ecosystem has ever written, the statements below match ZERO rows.
    ///
    /// What they defend against is a THIRD-PARTY implementation. `ChainFallback` and `CoinPeer`
    /// are public traits, and `refresh_tracked_coins` passes a `FallbackCoin` into the table
    /// verbatim (`rpc.rs::fallback_coin_to_row`), so an out-of-tree impl that emits upper-case hex
    /// is the one way such a row can exist. That is also why the collision rule below does NOT
    /// claim to keep the fresher row: the verbatim path is the point-read used precisely BECAUSE
    /// the subscription replica is behind, so an upper-case row would be the fresher observation,
    /// not the staler one. Case carries no recency information at all, in either direction.
    ///
    /// # The collision rule
    ///
    /// `coin_id` is unique in all three tables, so lower-casing several spellings of one id into
    /// each other is a uniqueness violation that aborts the whole step — and because the retry on
    /// the next open is byte-for-byte identical, an aborted step means [`Self::migrate`] fails
    /// forever and the wallet never opens again. Collisions are therefore resolved BEFORE the
    /// update, by [`Self::drop_case_collisions`], for any number of spellings rather than the
    /// two-spelling case alone.
    ///
    /// # Dependent tables move with it
    ///
    /// `arrival_pending.coin_id` and `arrivals.coin_id` are copies of `coins.coin_id` and are
    /// compared against it raw. Normalising `coins` alone would desync them, and both shipped
    /// consequences lose money-visible state: `record_arrivals` prunes every `arrival_pending` row
    /// whose id is no longer in `coins`, and a pruned hold stops exempting a deferred coin from
    /// the baseline watermark, so an arrival is swallowed; and `INSERT OR IGNORE INTO arrivals`
    /// stops recognising an id it already recorded, so a coin is announced to the user twice.
    ///
    /// One transaction, so any failure rolls every table back together and the ladder mark — which
    /// is written only after this returns — stays unset for the next open to retry.
    async fn normalise_stored_coin_hex(&self) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        for table in COIN_ID_TABLES {
            Self::drop_case_collisions(&mut tx, table).await?;
            // `table` is a compile-time constant from `COIN_ID_TABLES`, never caller input, so
            // interpolating it is not an injection surface. SQLite cannot bind an identifier.
            sqlx::query(&format!(
                "UPDATE {table} SET coin_id = LOWER(coin_id) WHERE coin_id <> LOWER(coin_id)"
            ))
            .execute(&mut *tx)
            .await?;
        }
        // `parent_coin_info` is not a key of anything, so it cannot collide.
        sqlx::query(
            "UPDATE coins SET parent_coin_info = LOWER(parent_coin_info)
             WHERE parent_coin_info <> LOWER(parent_coin_info)",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reduce every set of coin ids that differ only in case to ONE row, so the lower-casing that
    /// follows cannot violate the table's unique coin id.
    ///
    /// The alternative is not "a slightly wrong row survives" — it is a `UNIQUE` violation that
    /// rolls the migration back, deterministically, on every subsequent open, leaving the wallet
    /// permanently unopenable. Any deterministic survivor beats that.
    ///
    /// Deletion is safe here in a way it would not be elsewhere: all three tables are derived from
    /// chain state, so the worst case is a coin re-observed on the next sync. The dropped rows are
    /// logged at WARN with the id and the surviving spelling, because in this codebase a collision
    /// can only mean a non-conforming `ChainFallback`/`CoinPeer` implementation wrote to the
    /// replica — a fact worth surfacing rather than silently repairing.
    async fn drop_case_collisions(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        table: &str,
    ) -> sqlx::Result<()> {
        // Normally zero rows: only ids that have a case-twin are read back.
        let spellings: Vec<String> = sqlx::query(&format!(
            "SELECT coin_id FROM {table}
             WHERE LOWER(coin_id) IN (
                 SELECT LOWER(coin_id) FROM {table}
                 GROUP BY LOWER(coin_id) HAVING COUNT(*) > 1
             )"
        ))
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("coin_id"))
        .collect();

        for (canonical, group) in &Self::case_groups(spellings) {
            let Some(survivor) = Self::surviving_spelling(group) else {
                continue;
            };
            for loser in group.iter().filter(|s| s.as_str() != survivor) {
                sqlx::query(&format!("DELETE FROM {table} WHERE coin_id = ?"))
                    .bind(loser)
                    .execute(&mut **tx)
                    .await?;
            }
            tracing::warn!(
                table,
                coin_id = %canonical,
                kept = %survivor,
                dropped = group.len() - 1,
                "legacy replica held one coin id under several hex spellings; keeping one"
            );
        }
        Ok(())
    }

    /// Which spelling of one coin id survives a case collision.
    ///
    /// Prefer the spelling that is ALREADY canonical, because it is the one every conforming
    /// writer produces and the one every reader will look for; a group can hold at most one such
    /// spelling, since two would be the same string. Failing that — two or more mixed-case
    /// spellings and no lower-case one — take the lexicographically smallest, which is arbitrary
    /// but total and stable, and is chosen for exactly that reason.
    ///
    /// Recency is deliberately NOT a tie-break: the columns are identical apart from case, so the
    /// table carries no evidence of which spelling was written last.
    fn surviving_spelling(group: &[String]) -> Option<&str> {
        group
            .iter()
            .find(|s| !s.bytes().any(|b| b.is_ascii_uppercase()))
            .or_else(|| group.iter().min())
            .map(String::as_str)
    }

    /// Lower-case every hex value the wallet SCOPES or KEYS on, for rows written before the
    /// writer normalised (dig-node#298).
    ///
    /// Fixing the writers does nothing for rows already on disk, and a populated replica is
    /// exactly the one holding the user's coins — so without this step the fix would appear to
    /// work on a fresh database and leave every existing one reporting a balance of zero.
    ///
    /// # dig-node#293's warrant does NOT transfer, which is why this is not defence-in-depth
    ///
    /// The identity migration could argue that every in-tree writer already emitted `hex::encode`
    /// output, so the statements matched zero rows on any wallet this ecosystem had written, and
    /// the step defended only against a third-party `ChainFallback`/`CoinPeer` implementation.
    ///
    /// That argument holds for the three `coins` scoping columns and for `derivations`, whose
    /// writers are the same `hex::encode` paths. **It fails for `cats.asset_id`**:
    /// [`super::actions::update_cat`] persists a CALLER-SUPPLIED `TokenRecord`, so the
    /// `update_cat` RPC is an in-tree, shipped, reachable way to write a shouted asset id today,
    /// with no out-of-tree implementation required. A `cats` row written that way is unreachable
    /// by every canonical lookup, and its name, ticker and icon are not derivable from chain.
    ///
    /// So this step is a genuine repair for at least one column, not a belt-and-braces pass.
    ///
    /// # Eight plain updates and one collision
    ///
    /// None of [`SCOPED_HEX_COLUMNS`] is a key, so two spellings of one value are two legitimate
    /// rows and the update has nothing to collide with. `cats.asset_id` is a `PRIMARY KEY` and is
    /// therefore resolved first, by [`Self::merge_cat_case_collisions`].
    ///
    /// `<> LOWER(col)` is NULL-safe: for a NULL `asset_id` or `hint` the predicate evaluates to
    /// NULL, the row is not matched, and absence survives as absence. That matters more than it
    /// looks — `asset_id IS NULL` is how an XCH coin is told from a CAT coin.
    ///
    /// One transaction, so any failure rolls every table back together and the ladder mark —
    /// written only after this returns — stays unset for the next open to retry.
    async fn normalise_stored_scoped_hex(&self) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        for (table, column) in SCOPED_HEX_COLUMNS {
            // Both identifiers are compile-time constants from `SCOPED_HEX_COLUMNS`, never caller
            // input, so interpolating them is not an injection surface. SQLite cannot bind an
            // identifier.
            sqlx::query(&format!(
                "UPDATE {table} SET {column} = LOWER({column}) WHERE {column} <> LOWER({column})"
            ))
            .execute(&mut *tx)
            .await?;
        }
        Self::merge_cat_case_collisions(&mut tx).await?;
        sqlx::query("UPDATE cats SET asset_id = LOWER(asset_id) WHERE asset_id <> LOWER(asset_id)")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reduce every set of CAT asset ids that differ only in case to ONE row, carrying the losers'
    /// metadata onto the survivor, so the lower-casing that follows cannot violate the primary key.
    ///
    /// The alternative is not "a slightly wrong row survives" — it is a `UNIQUE` violation that
    /// rolls the migration back, deterministically, on every subsequent open, leaving the wallet
    /// permanently unopenable.
    ///
    /// # Merged, not dropped
    ///
    /// [`Self::drop_case_collisions`] deletes its losers outright, and justifies that by all three
    /// of its tables being derived from chain state: the worst case is a coin re-observed on the
    /// next sync. **A `cats` row is not derived from chain.** Its name, ticker, description, icon
    /// and visibility come from a token registry or from the user, and nothing on chain would put
    /// them back — so the losers' non-NULL fields are COALESCEd onto the survivor before the row
    /// goes. `precision` and `visible` are NOT NULL, so the survivor's own values stand.
    ///
    /// The group is the COMPLETE lower-value equivalence class, for any number of spellings rather
    /// than the two-spelling case alone — a merge scoped to "rows whose lower-casing already
    /// exists" would leave `AAbb` and `aAbb` untouched and collide them a statement later.
    async fn merge_cat_case_collisions(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> sqlx::Result<()> {
        // Normally zero rows: only asset ids that have a case-twin are read back.
        let spellings: Vec<String> = sqlx::query(
            "SELECT asset_id FROM cats
             WHERE LOWER(asset_id) IN (
                 SELECT LOWER(asset_id) FROM cats
                 GROUP BY LOWER(asset_id) HAVING COUNT(*) > 1
             )",
        )
        .fetch_all(&mut **tx)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("asset_id"))
        .collect();

        for (canonical, group) in Self::case_groups(spellings) {
            let Some(survivor) = Self::surviving_spelling(&group) else {
                continue;
            };
            let survivor = survivor.to_string();
            for loser in group.iter().filter(|s| **s != survivor) {
                sqlx::query(
                    "UPDATE cats SET
                        name = COALESCE(name, (SELECT name FROM cats WHERE asset_id = ?1)),
                        ticker = COALESCE(ticker, (SELECT ticker FROM cats WHERE asset_id = ?1)),
                        description = COALESCE(
                            description, (SELECT description FROM cats WHERE asset_id = ?1)),
                        icon_url = COALESCE(
                            icon_url, (SELECT icon_url FROM cats WHERE asset_id = ?1))
                     WHERE asset_id = ?2",
                )
                .bind(loser)
                .bind(&survivor)
                .execute(&mut **tx)
                .await?;
                sqlx::query("DELETE FROM cats WHERE asset_id = ?")
                    .bind(loser)
                    .execute(&mut **tx)
                    .await?;
            }
            tracing::warn!(
                asset_id = %canonical,
                kept = %survivor,
                merged = group.len() - 1,
                "legacy replica held one CAT under several hex spellings; merging into one"
            );
        }
        Ok(())
    }

    /// Group hex spellings by the canonical value they all lower-case to.
    ///
    /// Shared by both collision resolvers so they cannot come to disagree about what a collision
    /// IS. The group must be the complete equivalence class, not a pair — that is the property
    /// that keeps a three-way collision from surviving the resolver and aborting the update.
    fn case_groups(spellings: Vec<String>) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut groups: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for spelling in spellings {
            groups
                .entry(spelling.to_ascii_lowercase())
                .or_default()
                .push(spelling);
        }
        groups
    }

    /// Re-key stored offers onto the canonical offer id (dig-node#283).
    ///
    /// Offers written before #283 are keyed by a value derived solely from the OFFERED COIN SET,
    /// which is not the id Sage, dexie, or this node's RPC now report. Left alone, every such row
    /// would become unreachable: `view_offer`, `get_offer` and `cancel_offer` all look an offer up
    /// by the canonical id, and none of them would find it.
    ///
    /// No data is at risk, because the row stores the full `offer1…` string beside its key — the
    /// canonical id is recomputable from the row itself, so this is a rename, not a rebuild. That
    /// matters: an offer the user made is not derivable from chain, so dropping the table would
    /// genuinely lose it.
    ///
    /// Idempotent — a second run recomputes the same id for every row and rewrites nothing. A row
    /// whose offer string will not decode is left exactly as it is: an oddly-keyed offer is still
    /// recoverable by the user, and a deleted one is not.
    ///
    /// **The whole re-key is ONE transaction**, and that is the load-bearing property rather than
    /// a tidiness point. Moving a row means deleting it from under its old key and writing it
    /// under the new one; if those commit separately, a crash, a lock timeout, or any driver error
    /// in the window between them destroys the offer outright. That would be strictly worse than
    /// the defect this migration repairs — an unreachable row can be recovered by a later fix, and
    /// a deleted one cannot, because an offer the user made is not rebuildable from chain. Wrapped
    /// as one unit, any failure rolls the whole thing back and every row stays under its old key,
    /// where the next open will find it and try again.
    async fn rekey_offers_to_canonical_ids(&self) -> sqlx::Result<()> {
        let rows = self.all_offers().await?;
        let mut tx = self.pool.begin().await?;
        for row in rows {
            let Ok(canonical) = crate::sage::offers::offer_id(&row.offer) else {
                continue;
            };
            if canonical == row.offer_id {
                continue;
            }
            sqlx::query("DELETE FROM offers WHERE offer_id = ?")
                .bind(&row.offer_id)
                .execute(&mut *tx)
                .await?;
            // Written through the same transaction as the delete, so `upsert_offer` (which holds
            // its own pool connection) deliberately is not reused here.
            sqlx::query(
                "INSERT INTO offers (offer_id, offer, status, creation_timestamp, summary_json)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(offer_id) DO UPDATE SET
                    offer = excluded.offer,
                    status = excluded.status,
                    creation_timestamp = excluded.creation_timestamp,
                    summary_json = excluded.summary_json",
            )
            .bind(&canonical)
            .bind(&row.offer)
            .bind(&row.status)
            .bind(row.creation_timestamp)
            .bind(&row.summary_json)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
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
        .bind(Self::normalise_hex(&d.puzzle_hash))
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

    /// **Every hex value the `coins` table stores is stored LOWER-CASE, and this is the property
    /// every lookup and every scope comparison depends on** (dig-node#293, widened by #298).
    ///
    /// The scope is now all five hex columns the wallet keys or scopes on: the two COIN
    /// IDENTITIES `coin_id` and `parent_coin_info`, and the three SCOPING values `puzzle_hash`,
    /// `asset_id` and `hint` — here, in [`Self::upsert_coins`] and in
    /// [`Self::attribute_cat_coin`] — plus `derivations.puzzle_hash` and `cats.asset_id`, which
    /// are compared against the same values from their own tables.
    ///
    /// The chain source hands over whatever case it likes, and the read layer was already written
    /// as though it did not. #293 closed the identity half: `reserve_spend` normalises the ids it
    /// writes and `reserved_coin_ids` lower-cases what it reads back, and both are correct ONLY
    /// if the writer normalised first.
    ///
    /// Three raw comparisons were reachable through the identity columns, and they failed in
    /// different directions: a settled bundle never retired and stranded its own inputs for a
    /// full TTL; `are_coins_spendable` reported a genuinely spendable coin unspendable to a
    /// Sage-parity caller; and `record_arrivals` failed to recognise the wallet's own parent coin,
    /// so its own change was announced to the user as an incoming payment.
    ///
    /// # The scoping half is the user's BALANCE (dig-node#298)
    ///
    /// The three scoping columns failed more simply and more visibly. Six readers —
    /// [`Self::unspent_coins_scoped`], [`Self::balance_scoped`], [`Self::pending_scoped`],
    /// [`Self::coins_scoped`], [`Self::coin_count_scoped`] and
    /// [`Self::owned_cat_asset_ids_scoped`] — bind a lower-cased value against these columns, so
    /// a coin whose puzzle hash, asset id or hint arrived shouted matched NOTHING and the wallet
    /// reported a balance of zero. That is the same "have 0 $DIG" failure recorded at
    /// `fallback.rs`, arriving through the scope instead of through the identity.
    ///
    /// Normalising HERE rather than at each reader is what makes the class closed rather than
    /// enumerated — a seventh reader added later inherits the guarantee instead of having to
    /// remember it.
    ///
    /// # It also keeps every index usable, which the alternative does not
    ///
    /// The tempting shape is `LOWER(column)` in each predicate. It is the wrong one twice over:
    /// `coin_id` and `cats.asset_id` are PRIMARY KEYs and `puzzle_hash`, `asset_id` and
    /// `derivations.puzzle_hash` are INDEXED (`idx_coins_ph`, `idx_coins_asset`,
    /// `idx_coins_unspent`, `idx_derivations_ph`), and SQLite cannot use an index through a
    /// function call — so every scoped balance read would degrade to a full scan of `coins`. The
    /// binds already lower-case the VALUE, which costs nothing and reads straight down the index.
    /// Normalising the writer therefore fixes all six readers AND leaves every index intact.
    fn normalise_hex(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    /// [`Self::normalise_hex`] for an optional column.
    ///
    /// `asset_id` and `hint` are nullable, and their NULL is load-bearing: `asset_id IS NULL` is
    /// how an XCH coin is told from a CAT coin, and both upsert statements `COALESCE` an incoming
    /// NULL onto the stored value rather than erasing it. So absence must survive normalisation
    /// unchanged — a helper that turned `None` into `Some("")` would silently reclassify every
    /// XCH coin as a CAT of the empty asset.
    fn normalise_hex_opt(s: Option<&str>) -> Option<String> {
        s.map(Self::normalise_hex)
    }

    /// Insert or update a coin's chain state (the `coin_state_update` upsert). A coin is
    /// keyed by `coin_id`; a later update (e.g. a spend) overwrites the mutable fields.
    ///
    /// `coin_id`, `parent_coin_info`, `puzzle_hash`, `asset_id` and `hint` are all normalised on
    /// the way in — see [`Self::normalise_hex`]. The last three are what every scoped balance read
    /// compares against, so storing them verbatim reported a funded wallet as empty (#298).
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
        .bind(Self::normalise_hex(&c.coin_id))
        .bind(Self::normalise_hex(&c.parent_coin_info))
        .bind(Self::normalise_hex(&c.puzzle_hash))
        .bind(&c.amount)
        .bind(c.created_height)
        .bind(c.spent_height)
        .bind(Self::normalise_hex_opt(c.asset_id.as_deref()))
        .bind(Self::normalise_hex_opt(c.hint.as_deref()))
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
            .bind(Self::normalise_hex(&c.coin_id))
            .bind(Self::normalise_hex(&c.parent_coin_info))
            .bind(Self::normalise_hex(&c.puzzle_hash))
            .bind(&c.amount)
            .bind(c.created_height)
            .bind(c.spent_height)
            .bind(Self::normalise_hex_opt(c.asset_id.as_deref()))
            .bind(Self::normalise_hex_opt(c.hint.as_deref()))
            .bind(c.created_timestamp)
            .bind(c.spent_timestamp)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // ---- CAT admission staging (dig-node#380) -----------------------------
    //
    // A coin sitting at `cat_puzzle_hash(our_p2, asset_id)` is DISCOVERED, not BELIEVED. The
    // derivation is injective and proves only "if this coin is ever spent, only this wallet can
    // spend it, as this asset" — it does NOT prove the coin is a unit of that asset, because
    // `CREATE_COIN` is unconstrained in its destination. Anyone holding the victim's public
    // address can therefore place a coin at the derived hash for 1 mojo per displayed base unit.
    //
    // So discovered coins land HERE and never in `coins`. Only [`Self::promote_cat_admission`],
    // which runs off the frame path after a lineage proof, moves one across. Every one of the 22
    // production readers of `coins` is thereby clean by ABSENCE rather than by a predicate each of
    // them has to remember — the distinction that matters, because the enumeration of those
    // readers has already been found incomplete twice in this family.

    /// Stage discovered derived-hash coins, then hold the table to
    /// [`CAT_ADMISSION_PENDING_MAX_ROWS`] by evicting the OLDEST rows first.
    ///
    /// # Why eviction rather than refusal
    ///
    /// A single spend may carry many `CREATE_COIN`s, so an attacker chooses how many rows arrive.
    /// The bound must therefore exist — but it must **delay**, never **error**: a staging insert
    /// that could fail would sit on the peer frame path, and a peer able to fail a frame can deny
    /// a catch-up. An evicted row is a coin that is *absent*, which is the stated and acceptable
    /// failure direction; an errored frame is a session kill, which is not.
    ///
    /// A re-pushed coin re-stages, so eviction is recoverable rather than terminal.
    pub async fn stage_cat_admissions(&self, rows: &[StagedCatRow]) -> sqlx::Result<()> {
        let mut tx = self.pool.begin().await?;
        for r in rows {
            sqlx::query(
                "INSERT INTO cat_admission_pending
                    (coin_id, parent_coin_info, puzzle_hash, amount, created_height,
                     spent_height, created_timestamp, spent_timestamp,
                     derived_asset_id, derived_owner_p2)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(coin_id) DO UPDATE SET
                    created_height = excluded.created_height,
                    spent_height = excluded.spent_height,
                    created_timestamp = excluded.created_timestamp,
                    spent_timestamp = excluded.spent_timestamp",
            )
            .bind(Self::normalise_hex(&r.coin_id))
            .bind(Self::normalise_hex(&r.parent_coin_info))
            .bind(Self::normalise_hex(&r.puzzle_hash))
            .bind(&r.amount)
            .bind(r.created_height)
            .bind(r.spent_height)
            .bind(r.created_timestamp)
            .bind(r.spent_timestamp)
            .bind(Self::normalise_hex(&r.derived_asset_id))
            .bind(Self::normalise_hex(&r.derived_owner_p2))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "DELETE FROM cat_admission_pending WHERE seq NOT IN
                (SELECT seq FROM cat_admission_pending ORDER BY seq DESC LIMIT ?)",
        )
        .bind(CAT_ADMISSION_PENDING_MAX_ROWS)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The promotion pass's work queue: up to `limit` staged rows, FEWEST ATTEMPTS FIRST, and
    /// only rows not tried since `retry_cutoff`.
    ///
    /// # Why the ordering is attempts-then-arrival rather than arrival alone (dig-node#394)
    ///
    /// Arrival order alone is a denial primitive. A promotion that cannot conclude leaves its row
    /// staged — deliberately, because deleting on an unreadable parent would let a source that is
    /// merely behind erase real money — so `limit` rows whose parents never resolve occupy the
    /// head of an arrival-ordered queue permanently. Every later pass re-reads the same `limit`
    /// rows and no honest coin behind them is ever reached. The gate reproduced it: `deferred: 64`
    /// on every pass, reads climbing 64, 128, ... unbounded, and the victim's $DIG balance zero
    /// for ever, bought for 64 mojos.
    ///
    /// Ordering by `attempts` first fixes both halves at once. A row that has never been tried
    /// always precedes one that has, so nothing can hold the head; and a row that keeps failing
    /// sinks below every other row at its attempt level, so the reads an attacker buys are spread
    /// across the whole table rather than concentrated on their own coins.
    ///
    /// # Why the cutoff, on top of the ordering
    ///
    /// The ordering removes starvation but not amplification: with a table of only poisoned rows,
    /// every pass would still spend `limit` reads on them. `retry_cutoff` bounds a row to one read
    /// per cooldown, so the total read rate an attacker can buy is `rows / cooldown` — bounded,
    /// and independent of how often a pass runs.
    ///
    /// A row is never deleted for failing. Absence is the accepted failure direction here;
    /// erasing a coin because a source was briefly behind is not.
    pub async fn staged_cat_admissions(
        &self,
        limit: i64,
        retry_cutoff: i64,
    ) -> sqlx::Result<Vec<StagedCatRow>> {
        sqlx::query_as::<_, StagedCatRow>(
            "SELECT coin_id, parent_coin_info, puzzle_hash, amount, created_height,
                    spent_height, created_timestamp, spent_timestamp,
                    derived_asset_id, derived_owner_p2
             FROM cat_admission_pending
             WHERE last_attempt_at IS NULL OR last_attempt_at <= ?
             ORDER BY attempts ASC, seq ASC LIMIT ?",
        )
        .bind(retry_cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Record that a promotion pass SPENT A READ on `coin_id` at `now` and could not conclude.
    ///
    /// Called on every inconclusive outcome — an unreadable parent, a source-reported absence, an
    /// unconfirmed coin — because the resource being metered is the read, not the verdict.
    /// A conclusive outcome deletes the row instead, so it never needs an attempt recorded.
    pub async fn record_promotion_attempt(&self, coin_id: &str, now: i64) -> sqlx::Result<()> {
        sqlx::query(
            "UPDATE cat_admission_pending
                SET attempts = attempts + 1, last_attempt_at = ?
              WHERE coin_id = ?",
        )
        .bind(now)
        .bind(Self::normalise_hex(coin_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Which of `coin_ids` already have a row in `coins`.
    ///
    /// The routing question for an already-PROMOTED coin: once a coin has cleared promotion its
    /// spend must update `coins` normally, exactly as `origin/main` does, or a promoted coin would
    /// stay unspent in the replica forever and be re-selected after it was spent.
    ///
    /// ONE query, not one per coin. This sits on the peer frame path, where the batch size is
    /// chosen by the peer, so a round trip per coin hands that peer a knob on the wallet's own
    /// database. Nothing here reads the chain — the frame path's zero-chain-reads property is
    /// unaffected either way — but a bounded number of local round trips is worth having when the
    /// bound costs one query.
    pub async fn existing_coin_ids(&self, coin_ids: &[String]) -> sqlx::Result<HashSet<String>> {
        if coin_ids.is_empty() {
            return Ok(HashSet::new());
        }
        let placeholders = std::iter::repeat_n("?", coin_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("SELECT coin_id FROM coins WHERE coin_id IN ({placeholders})");
        let mut query = sqlx::query_scalar::<_, String>(&sql);
        for id in coin_ids {
            query = query.bind(Self::normalise_hex(id));
        }
        Ok(query.fetch_all(&self.pool).await?.into_iter().collect())
    }

    /// Move one staged coin into `coins`, FULLY ATTRIBUTED, and drop its staging row — in one
    /// transaction, so no reader can ever observe the coin in both tables or in neither.
    ///
    /// `asset_id` and `hint` come from the parent spend's own reconstruction, never from the
    /// derivation that discovered the coin. That is the whole content of the proof: the derivation
    /// said where to look, the parent spend says what the coin IS.
    ///
    /// # The DELETE comes first, and its row count is the gate
    ///
    /// Promotion spans a network round trip: the row is read, a parent spend is fetched, and only
    /// then is this called. A reorg rollback can delete the staged row inside that window, and
    /// deleting it is the rollback saying the coin no longer exists at that height. Inserting
    /// first and deleting afterwards would write a coin the replica had just decided to forget,
    /// and the delete would then quietly remove nothing.
    ///
    /// So the delete runs first and `Ok(false)` is returned when it removed nothing: no staged
    /// row, no promotion. The whole thing is one transaction, so a concurrent rollback either
    /// happens entirely before this (the row is gone, and nothing is written) or entirely after
    /// (the rollback removes the promoted coin by the same predicate).
    pub async fn promote_cat_admission(
        &self,
        row: &StagedCatRow,
        asset_id: &str,
        hint: &str,
    ) -> sqlx::Result<bool> {
        let mut tx = self.pool.begin().await?;
        let claimed = sqlx::query("DELETE FROM cat_admission_pending WHERE coin_id = ?")
            .bind(Self::normalise_hex(&row.coin_id))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if claimed != 1 {
            // Rolled back underneath us. Nothing to promote, and nothing to undo.
            tx.rollback().await?;
            return Ok(false);
        }
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
        .bind(Self::normalise_hex(&row.coin_id))
        .bind(Self::normalise_hex(&row.parent_coin_info))
        .bind(Self::normalise_hex(&row.puzzle_hash))
        .bind(&row.amount)
        .bind(row.created_height)
        .bind(row.spent_height)
        .bind(Self::normalise_hex(asset_id))
        .bind(Self::normalise_hex(hint))
        .bind(row.created_timestamp)
        .bind(row.spent_timestamp)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Promote a staged coin the parent spend proved is an owned NFT or DID singleton.
    ///
    /// The twin of [`WalletDb::promote_cat_admission`], and it claims the staging row FIRST for the
    /// same reason: the DELETE's `rows_affected` is what decides whether this promotion still owns
    /// the coin, so a reorg rollback that lands mid-read loses the race rather than being
    /// overwritten by it. `false` means the row was already gone — nothing was written.
    ///
    /// # Why the coin does NOT enter `coins`
    ///
    /// A singleton sits at its own puzzle hash, not one of the wallet's p2 hashes, and carries no
    /// asset id — so a row for it in `coins` would read as XCH and inflate the spendable balance by
    /// its (odd, ~1 mojo) amount while being unselectable. `nfts`/`dids` are keyed by launcher id
    /// and are the tables that describe it truthfully.
    pub async fn promote_singleton_admission(
        &self,
        coin_id: &str,
        singleton: &PromotedSingleton<'_>,
    ) -> sqlx::Result<bool> {
        let mut tx = self.pool.begin().await?;
        let claimed = sqlx::query("DELETE FROM cat_admission_pending WHERE coin_id = ?")
            .bind(Self::normalise_hex(coin_id))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if claimed != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        match singleton {
            PromotedSingleton::Nft(n) => Self::upsert_nft_on(&mut *tx, n).await?,
            PromotedSingleton::Did(d) => Self::upsert_did_on(&mut *tx, d).await?,
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Drop a staged coin that a SUCCESSFUL parent read proved is not a unit of the derived asset.
    ///
    /// Terminal, and that is what bounds the read cost: a refused coin is never read again, so an
    /// attacker's amplification is ~1x against a coin they had to pay at least 1 mojo to create.
    /// Never called for an UNAVAILABLE read — an unavailable answer leaves the row staged, because
    /// deleting on "I could not tell" would let a peer that withholds parent spends erase real money.
    pub async fn discard_cat_admission(&self, coin_id: &str) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM cat_admission_pending WHERE coin_id = ?")
            .bind(Self::normalise_hex(coin_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// How many coins are currently staged (diagnostics + tests).
    pub async fn staged_cat_admission_count(&self) -> sqlx::Result<i64> {
        sqlx::query_scalar("SELECT COUNT(*) FROM cat_admission_pending")
            .fetch_one(&self.pool)
            .await
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
        // A staged CAT admission is UNMADE with the coin it describes, by the same predicate and
        // in the same transaction (dig-node#380).
        //
        // A staged row is not a record of money; it is a record of an OBSERVATION — "the chain
        // showed me a coin at a hash I derived". A rollback deletes the chain state that
        // observation was made against, so the row's justification is gone even though the row
        // would survive. Left behind, it is later promoted against a fork the chain no longer has,
        // and promotion writes into `coins` — so a coin enters the believed set on the strength of
        // history that was undone. That is the same defect class as everything else this table
        // exists to prevent: a check trusting a value whose meaning it never established.
        //
        // Nothing is lost by deleting. A coin that re-confirms after the reorg is pushed again by
        // the peer and re-staged, exactly as `coins` is re-populated.
        sqlx::query(
            "DELETE FROM cat_admission_pending
             WHERE created_height IS NOT NULL AND created_height > ?",
        )
        .bind(h)
        .execute(&mut *tx)
        .await?;
        // A staged coin SPENT above the fork is unspent again. The spend is cleared rather than
        // the row deleted: the coin itself is still confirmed at or below the fork, so it is still
        // a legitimate promotion candidate, and deleting it here would lose a real coin to a reorg
        // that did not touch its creation.
        sqlx::query(
            "UPDATE cat_admission_pending
                SET spent_height = NULL, spent_timestamp = NULL
             WHERE spent_height > ?",
        )
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
                .bind(Self::normalise_hex(a))
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
    ///
    /// The ids come from the caller (the Sage-parity `get_are_coins_spendable` endpoint), so they
    /// are normalised to the case the table stores — see [`Self::normalise_hex`].
    pub async fn are_coins_spendable(&self, ids: &[String]) -> sqlx::Result<bool> {
        for id in ids {
            let row = sqlx::query(
                "SELECT 1 AS ok FROM coins
                 WHERE coin_id = ? AND spent_height IS NULL AND created_height IS NOT NULL",
            )
            .bind(Self::normalise_hex(id))
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

    // ---- in-flight spends (dig_ecosystem#2763) ----------------------------
    //
    // A broadcast used to mark nothing. The DB only learned a coin was spent when a peer pushed a
    // `coin_state_update`, tens of seconds later, and every selection inside that window re-picked
    // the same coin. These four methods are the record that closes it: what was pushed, which
    // coins it committed, and when the commitment lapses.
    //
    // Three properties are deliberate:
    //
    // * **The reservation always expires.** `expires_at` is not a tidy-up convenience — it is the
    //   guarantee that a release path which never runs (a crash between push and confirmation, a
    //   bundle the mempool silently dropped) cannot strand the user's coin forever. The failure
    //   direction that matters here is "the wallet refuses to spend money it owns", and only an
    //   unconditional expiry rules it out.
    // * **Reservation narrows SELECTION, never BALANCE.** A reserved coin is still the user's
    //   money until the spend confirms, so [`Self::balance`] and [`Self::unspent_coins`] are left
    //   exactly as they were and only [`Self::unreserved_unspent_coins`] is new. Netting an
    //   in-flight send out of the balance would report money as gone before the chain says so,
    //   which is the same class of lie in the opposite direction.
    // * **A reserved coin that is already observed spent is not held.** Release is driven by the
    //   coin's own `spent_height`, so confirmation retires the reservation without anything having
    //   to remember to call a release.

    /// Record a pushed bundle and reserve the coins it spends.
    ///
    /// Idempotent on the transaction id: re-pushing the same bundle updates its expiry and attempt
    /// count rather than duplicating it, because a resubmission is the same transaction.
    pub async fn reserve_spend(&self, tx: &PendingTransactionRow) -> sqlx::Result<()> {
        let mut conn = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO pending_transactions
                (transaction_id, bundle_hex, fee, submitted_at, expires_at, attempts)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(transaction_id) DO UPDATE SET
                expires_at = excluded.expires_at,
                attempts = pending_transactions.attempts + 1",
        )
        .bind(&tx.transaction_id)
        .bind(&tx.bundle_hex)
        .bind(&tx.fee)
        .bind(tx.submitted_at)
        .bind(tx.expires_at)
        .bind(tx.attempts)
        .execute(&mut *conn)
        .await?;
        for coin_id in &tx.reserved_coin_ids {
            // A coin can only back ONE in-flight bundle. `INSERT OR REPLACE` would silently move
            // the reservation to a newer transaction; `DO NOTHING` keeps the first claim, which is
            // the one the mempool will honour.
            sqlx::query(
                "INSERT INTO coin_reservations (coin_id, transaction_id) VALUES (?, ?)
                 ON CONFLICT(coin_id) DO NOTHING",
            )
            .bind(coin_id.to_ascii_lowercase())
            .bind(&tx.transaction_id)
            .execute(&mut *conn)
            .await?;
        }
        conn.commit().await?;
        Ok(())
    }

    /// Drop every reservation whose bundle has lapsed, settled, or become unspendable, and return
    /// how many bundles were retired.
    ///
    /// `now_ms` is passed in rather than read from the clock so a test can drive the expiry edge
    /// exactly instead of sleeping through it.
    ///
    /// Three retirement conditions, all of which mean the reservation no longer protects anything:
    ///
    /// 1. `expires_at <= now_ms` — the unconditional lapse.
    /// 2. every reserved coin is now recorded spent — the spend settled, which is the outcome the
    ///    reservation was waiting for.
    /// 3. a reserved coin is recorded spent by SOMETHING ELSE while others are not — the bundle
    ///    can never be included now, so holding its remaining inputs only strands them.
    ///
    /// Conditions 2 and 3 are the same SQL: any reserved coin observed spent retires the bundle.
    /// They are named separately because they are different events and a reader should not have to
    /// infer that the code treats them alike on purpose.
    ///
    /// The join compares the two ids RAW, and that is now correct rather than a latent bug: both
    /// sides are normalised by their writers ([`Self::reserve_spend`] and [`Self::normalise_hex`]),
    /// so there is no case left for the predicate to disagree about.
    ///
    /// The first version of this fix wrapped the coin side in `LOWER()` instead. That worked, but
    /// it was a normaliser applied to a `PRIMARY KEY`: SQLite cannot use an index through a
    /// function call, so the join degraded to a full scan of `coins` for every reservation row,
    /// and it repaired exactly one of the three readers that compared raw. Normalising at the
    /// writer fixes all three AND leaves the key usable, so keeping the `LOWER()` beside it would
    /// buy nothing but the scan. It is deliberately NOT retained as belt-and-braces.
    pub async fn prune_reservations(&self, now_ms: i64) -> sqlx::Result<u64> {
        let n = sqlx::query(
            "DELETE FROM pending_transactions WHERE expires_at <= ?
             OR transaction_id IN (
                SELECT r.transaction_id FROM coin_reservations r
                JOIN coins c ON c.coin_id = r.coin_id
                WHERE c.spent_height IS NOT NULL
             )",
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await?
        .rows_affected();

        // The same two retirement conditions, applied to the CLIENT holds (dig_ecosystem#3127).
        // They live in a separate table with no foreign key, so the cascade above cannot reach
        // them and they would otherwise outlive both their lifetime and their coin.
        //
        // Not added to `n`: the returned count means "bundles retired", and a client hold is not a
        // bundle. Folding them together would inflate a figure callers read as in-flight spends.
        sqlx::query(
            "DELETE FROM client_coin_reservations WHERE expires_at_ms <= ?
             OR coin_id IN (
                SELECT c.coin_id FROM coins c
                WHERE c.spent_height IS NOT NULL
             )",
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await?;

        Ok(n)
    }

    /// Every live in-flight bundle, oldest submission first, with the coins it reserved.
    pub async fn pending_transactions(&self) -> sqlx::Result<Vec<PendingTransactionRow>> {
        let rows = sqlx::query(
            "SELECT transaction_id, bundle_hex, fee, submitted_at, expires_at, attempts
             FROM pending_transactions ORDER BY submitted_at ASC, transaction_id ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let transaction_id: String = r.get("transaction_id");
            let coins = sqlx::query(
                "SELECT coin_id FROM coin_reservations WHERE transaction_id = ? ORDER BY coin_id",
            )
            .bind(&transaction_id)
            .fetch_all(&self.pool)
            .await?;
            out.push(PendingTransactionRow {
                transaction_id,
                bundle_hex: r.get("bundle_hex"),
                fee: r.get("fee"),
                submitted_at: r.get("submitted_at"),
                expires_at: r.get("expires_at"),
                attempts: r.get("attempts"),
                reserved_coin_ids: coins.into_iter().map(|c| c.get("coin_id")).collect(),
            });
        }
        Ok(out)
    }

    /// The unspent coins for an asset MINUS any coin committed to a live in-flight bundle — the
    /// set a new spend may select from (dig_ecosystem#2763).
    ///
    /// Deliberately a SEPARATE method from [`Self::unspent_coins`] rather than a filter added to
    /// it: the two answer different questions. "What do I own" must keep counting a coin whose
    /// spend has not settled; "what may I spend next" must not.
    pub async fn unreserved_unspent_coins(
        &self,
        asset_id: Option<&str>,
    ) -> sqlx::Result<Vec<CoinRow>> {
        let coins = self.unspent_coins(asset_id).await?;
        let reserved = self.reserved_coin_ids().await?;
        Ok(coins
            .into_iter()
            .filter(|c| !reserved.contains(&c.coin_id.to_ascii_lowercase()))
            .collect())
    }

    /// Every coin id currently held out of selection, lower-cased.
    ///
    /// The UNION of both reservation kinds: coins committed to a pushed bundle
    /// ([`Self::reserve_spend`]) and coins a client is building against
    /// ([`Self::reserve_client_coins`]). A selector must narrow against both or the cross-process
    /// window this union exists to close reopens.
    ///
    /// Reads the client table RAW, without filtering on an expiry, because this method has no
    /// clock. A lapsed hold therefore keeps blocking its coin until [`Self::prune_reservations`]
    /// runs. That is the SAFE direction and is chosen deliberately: over-reserving costs a delayed
    /// spend, under-reserving costs an invalid bundle built after the money moved. Every caller of
    /// this method prunes first, so the delay is not observable in practice.
    pub async fn reserved_coin_ids(&self) -> sqlx::Result<std::collections::HashSet<String>> {
        let rows = sqlx::query(
            "SELECT coin_id FROM coin_reservations
             UNION
             SELECT coin_id FROM client_coin_reservations",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("coin_id").to_ascii_lowercase())
            .collect())
    }

    /// Every p2 puzzle hash the replica has seen ANY coin at — the gap-limit scan's evidence that
    /// an HD index is in use (dig_ecosystem#2762).
    ///
    /// Deliberately includes SPENT coins. A coin that arrived at index 400 and was then spent is
    /// still proof the wallet handed out index 400, and the addresses the user is about to be paid
    /// at are the ones just past it. Restricting this to unspent coins would let a wallet that had
    /// swept itself collapse its own window back to the default and lose sight of its next
    /// receive addresses.
    ///
    /// Returns PUBLIC puzzle hashes only. Nothing here is a key and nothing here widens what the
    /// node may sign — it decides only how far a wallet looks for its own money.
    pub async fn occupied_puzzle_hashes(&self) -> sqlx::Result<std::collections::HashSet<String>> {
        let rows = sqlx::query("SELECT DISTINCT puzzle_hash FROM coins")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("puzzle_hash").to_ascii_lowercase())
            .collect())
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
        .bind(Self::normalise_hex(&c.asset_id))
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
            .bind(Self::normalise_hex(asset_id))
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
        .bind(Self::normalise_hex(asset_id))
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
            .bind(Self::normalise_hex(asset_id))
            .bind(Self::normalise_hex_opt(hint))
            .bind(Self::normalise_hex(coin_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- NFTs -------------------------------------------------------------

    /// Insert or update a reconstructed NFT (keyed by launcher id; a later coin overwrites
    /// the mutable fields — the current coin, owner, and wire record).
    pub async fn upsert_nft(&self, n: &NftDbRow) -> sqlx::Result<()> {
        Self::upsert_nft_on(&self.pool, n).await
    }

    /// The NFT upsert, against any executor, so a promotion can run it inside the SAME
    /// transaction that claims the staging row (see [`WalletDb::promote_singleton_admission`]).
    async fn upsert_nft_on<'e, E>(exec: E, n: &NftDbRow) -> sqlx::Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
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
        .execute(exec)
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
        Self::upsert_did_on(&self.pool, d).await
    }

    /// The DID upsert, against any executor (the twin of [`WalletDb::upsert_nft_on`]).
    async fn upsert_did_on<'e, E>(exec: E, d: &DidDbRow) -> sqlx::Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
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
        .execute(exec)
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
        .bind(Self::normalise_hex(asset_id))
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
        .bind(Self::normalise_hex(asset_id))
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

/// The longest lifetime this node will grant a client coin reservation, in milliseconds.
///
/// A ceiling rather than a suggestion. The lifetime is the ONLY thing standing between a client
/// that crashes between reserving and building, and a coin held out of selection forever — so a
/// caller does not get to ask for a hold this node would not itself clean up.
pub const CLIENT_RESERVATION_MAX_TTL_MS: i64 = 600_000;

/// The lifetime applied when a caller names none, in milliseconds.
///
/// Five minutes: long enough to build, sign and push a bundle across a process boundary, short
/// enough that an abandoned hold is a nuisance rather than a lockout.
///
/// This is deliberately dig-account's `DEFAULT_RESERVATION_TTL_SECS` (300 s), while the ceiling
/// above is dig-node's own post-broadcast `RESERVATION_TTL_MS` (600 s). The two crates had
/// disagreed harmlessly because they covered disjoint phases of one lifecycle; they meet here, so
/// the disagreement is resolved rather than inherited — the shorter figure becomes the DEFAULT and
/// the longer one the CEILING, which is the only reading under which neither crate is overruled.
/// Whatever a caller asks for, [`ClientReservation::expires_at_ms`] reports what was APPLIED.
pub const CLIENT_RESERVATION_DEFAULT_TTL_MS: i64 = 300_000;

/// A hold this node granted to a client, and the handle that releases it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientReservation {
    /// The OPAQUE handle. 256 bits of OS randomness, hex-encoded.
    ///
    /// Unpredictable so it cannot be DERIVED — but it is **not a capability, and it is not the
    /// access control** on release. `control.wallet.reservations.held` publishes every live handle
    /// to any caller holding the control token, so anyone who can call `release` can already read
    /// the handle to pass it.
    ///
    /// The access control is the CONTROL TOKEN, and that is the whole of it. What randomness buys
    /// is narrower and worth stating exactly: a handle nobody can GUESS means a caller cannot free
    /// a hold it never observed, and two holds can never collide.
    ///
    /// Publishing them is deliberate rather than an oversight — `held` is the operator's recovery
    /// lever, the thing that turns a stuck lease into `dign wallet release <id>` instead of a wait.
    /// Withholding the field to make this doc true would trade a documentation error for a real
    /// lockout.
    pub reservation_id: String,
    /// The coins held, lower-cased. Exactly what was asked for, because acquisition is all-or-none.
    pub coin_ids: Vec<String>,
    /// When the hold lapses, ms since the Unix epoch.
    ///
    /// The lifetime ACTUALLY applied, which may be shorter than the one requested. A caller told
    /// its own requested figure would wait on a schedule this node does not keep.
    pub expires_at_ms: i64,
    /// That same applied lifetime as a DURATION, ms.
    ///
    /// Carried beside the deadline rather than left for a caller to subtract, because the only
    /// clock a caller could subtract with is its OWN. Under clock skew that yields a lifetime this
    /// node never granted, and a client scheduling its release against it would either release
    /// early or hold past the lapse.
    pub ttl_ms: i64,
}

/// One held coin, as reported by [`WalletDb::held_reservations`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedCoinRow {
    /// The held coin id, lower-cased.
    pub coin_id: String,
    /// The handle holding it.
    pub reservation_id: String,
    /// When the hold lapses, ms since the Unix epoch.
    pub expires_at_ms: i64,
    /// Which phase of the lifecycle is holding the coin.
    pub phase: ReservationPhase,
}

/// Which phase of one spend lifecycle is holding a coin.
///
/// Not two competing reservation systems — two stages of the same one. A coin is leased while its
/// spend is being built, and committed once that spend has been pushed. Naming the phase keeps a
/// reader from concluding the second table is a rival implementation of the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationPhase {
    /// Held before broadcast, by a client that has selected coins and is building a spend.
    ///
    /// Releasable on demand: nothing has been pushed, so the holder still owns the decision.
    Lease,
    /// Held after broadcast, by a bundle this node pushed.
    ///
    /// NOT releasable on demand, and deliberately so: the bundle may still be included, and
    /// freeing its inputs would invite a second spend of a coin that is already committed. The
    /// chain ends this hold, via [`WalletDb::prune_reservations`], not a caller.
    Broadcast,
}

/// Why a client reservation was refused.
///
/// The two variants demand OPPOSITE actions from a caller and are deliberately never collapsed.
/// [`Self::Reserved`] means "wait"; [`Self::Unavailable`] means "do not spend". A caller that
/// cannot tell them apart either double-selects or blocks a legitimate send.
#[derive(Debug)]
pub enum ReserveClientCoinsError {
    /// One or more named coins are already committed to a live spend, and NOTHING was reserved.
    ///
    /// Deliberately distinct from any shortfall: the user has the money, it is briefly committed,
    /// and it returns when that spend settles or its hold lapses. Reporting a shortfall here sends
    /// someone to an exchange to solve a five-minute wait.
    Reserved {
        /// The coins that clashed. Named so a caller can say WHICH coins to wait for.
        coin_ids: Vec<String>,
    },
    /// The reservation set could not be read or written, so what is in flight is UNKNOWN.
    ///
    /// Never reported as "nothing is reserved". A guard that fails open is not a guard.
    Unavailable(sqlx::Error),
}

impl std::fmt::Display for ReserveClientCoinsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reserved { coin_ids } => write!(
                f,
                "{} coin(s) are committed to a live spend; nothing was reserved",
                coin_ids.len()
            ),
            Self::Unavailable(e) => write!(f, "the coin-reservation set could not be read: {e}"),
        }
    }
}

impl std::error::Error for ReserveClientCoinsError {}

impl From<sqlx::Error> for ReserveClientCoinsError {
    fn from(e: sqlx::Error) -> Self {
        Self::Unavailable(e)
    }
}

impl WalletDb {
    /// Hold a named set of coins for a client that has not built its bundle yet
    /// (dig_ecosystem#3127).
    ///
    /// # Why this exists beside [`Self::reserve_spend`]
    ///
    /// [`Self::reserve_spend`] reserves at PUSH time, as a child of a `pending_transactions` row.
    /// That is too late to close the cross-process window: a client selects coins, then builds and
    /// signs, and only then pushes. The whole build interval is unprotected, and a second process
    /// sharing the wallet selects the same coins inside it.
    ///
    /// So this is a SEPARATE table rather than a synthetic pending transaction. Inventing a
    /// `pending_transactions` row with no bundle would make [`Self::pending_transactions`] report
    /// an in-flight spend that does not exist, which is a claim about money the node cannot
    /// support.
    ///
    /// # All-or-none, and what actually guarantees it
    ///
    /// Every named coin is taken or none is. Reading the held set, selecting, then reserving is
    /// check-then-act: two callers both see a coin free and both take it.
    ///
    /// **The guarantee is the WRITE-BEFORE-READ ordering below, not the `coin_id` PRIMARY KEY.**
    /// That is measured rather than assumed, because the obvious reading is the wrong one. With 8
    /// barrier-synchronised callers contending for one coin on a file-backed WAL pool:
    ///
    /// | build | result |
    /// |---|---|
    /// | PRIMARY KEY defeated (`INSERT OR REPLACE`), ordering kept | still exactly ONE winner |
    /// | ordering defeated (lapsed-row DELETE moved outside the transaction), PRIMARY KEY kept | **FAILS** |
    ///
    /// So the key is a backstop that is never reached in practice, and removing the ordering is
    /// not merely a lost optimisation. Without it the transaction is read-then-write and DEFERRED:
    /// a losing racer collides while UPGRADING to a write lock, which surfaces as `SQLITE_BUSY`
    /// rather than a uniqueness violation, and therefore maps to
    /// [`ReserveClientCoinsError::Unavailable`] — telling the caller "I cannot read the set, do
    /// not spend" when the truth is "wait, somebody holds it". That is the money-honesty failure
    /// this type exists to prevent, produced by contention alone.
    ///
    /// The pre-check earns its cost twice over: it names WHICH coins clashed, and it is the ONLY
    /// thing that can see a clash against [`Self::reserve_spend`]'s table, whose rows share no key
    /// with this one.
    ///
    /// # Ordering inside the transaction
    ///
    /// Retiring lapsed rows is a WRITE, and it is done FIRST on purpose: it takes SQLite's write
    /// lock before anything is read, which is what `BEGIN IMMEDIATE` would buy. Every read below
    /// it therefore happens under an exclusive lock, which is what makes the pre-check sound.
    ///
    /// # §908
    ///
    /// Bookkeeping only. A coin id is a public chain fact; nothing here is or implies key
    /// material, and this method authorizes nothing.
    ///
    /// `now_ms` is passed in rather than read from the clock so a test can drive the expiry edge
    /// exactly instead of sleeping through it.
    pub async fn reserve_client_coins(
        &self,
        coin_ids: &[String],
        ttl_ms: Option<i64>,
        now_ms: i64,
    ) -> std::result::Result<ClientReservation, ReserveClientCoinsError> {
        let wanted: Vec<String> = coin_ids.iter().map(|c| c.to_ascii_lowercase()).collect();
        // Clamped, never trusted. `max(0)` because a negative or zero request must still produce a
        // hold that lapses rather than one already expired at birth, which would read to a caller
        // as a hold that was granted and instantly vanished.
        let ttl = ttl_ms
            .unwrap_or(CLIENT_RESERVATION_DEFAULT_TTL_MS)
            .clamp(1, CLIENT_RESERVATION_MAX_TTL_MS);
        let expires_at_ms = now_ms.saturating_add(ttl);
        let reservation_id = new_reservation_id().map_err(ReserveClientCoinsError::Unavailable)?;

        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM client_coin_reservations WHERE expires_at_ms <= ?")
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;

        let mut clashes = Vec::new();
        for id in &wanted {
            let held: Option<(String,)> = sqlx::query_as(
                "SELECT coin_id FROM client_coin_reservations WHERE coin_id = ?
                 UNION ALL
                 SELECT coin_id FROM coin_reservations WHERE coin_id = ?
                 LIMIT 1",
            )
            .bind(id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            if held.is_some() {
                clashes.push(id.clone());
            }
        }
        if !clashes.is_empty() {
            // Dropping the transaction rolls it back, including the lapsed-row cleanup above.
            // That is deliberate: a refused call must leave the table exactly as it found it, so a
            // caller can never observe a side effect of an acquisition that did not happen.
            return Err(ReserveClientCoinsError::Reserved { coin_ids: clashes });
        }

        for id in &wanted {
            let inserted = sqlx::query(
                "INSERT INTO client_coin_reservations (coin_id, reservation_id, expires_at_ms)
                 VALUES (?, ?, ?)",
            )
            .bind(id)
            .bind(&reservation_id)
            .bind(expires_at_ms)
            .execute(&mut *tx)
            .await;
            if let Err(e) = inserted {
                // The PRIMARY KEY refused it, so a concurrent caller took this coin between our
                // pre-check and now. That is a clash, not an unreadable set, and the rollback on
                // drop means nothing partial survives.
                return Err(if is_unique_violation(&e) {
                    ReserveClientCoinsError::Reserved {
                        coin_ids: vec![id.clone()],
                    }
                } else {
                    ReserveClientCoinsError::Unavailable(e)
                });
            }
        }

        tx.commit().await?;
        Ok(ClientReservation {
            reservation_id,
            coin_ids: wanted,
            expires_at_ms,
            ttl_ms: ttl,
        })
    }

    /// Free a client hold ahead of its lifetime, returning the coins it released.
    ///
    /// The explicit half of the release path. The TTL alone is not enough: once a spend is known
    /// settled or known dead, holding its inputs for the rest of the window keeps a person out of
    /// their own money over a question the chain has already answered.
    ///
    /// Releasing a handle that names no live hold is a SUCCESS reporting an empty list, NOT an
    /// error. A client releasing on confirmation cannot know whether the TTL got there first, and
    /// making the ordinary outcome an error teaches callers to discard the result.
    ///
    /// Frees every coin of the hold or none: one statement, one predicate.
    ///
    /// Only [`ReservationPhase::Lease`] holds are releasable. A post-broadcast handle reports
    /// `false` because the chain, not the caller, ends that hold — see [`ReservationPhase`]. In
    /// practice a caller never possesses such a handle: handles are only ever HANDED OUT by
    /// [`Self::reserve_client_coins`].
    pub async fn release_client_reservation(
        &self,
        reservation_id: &str,
    ) -> sqlx::Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query("SELECT coin_id FROM client_coin_reservations WHERE reservation_id = ? ORDER BY coin_id")
            .bind(reservation_id)
            .fetch_all(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM client_coin_reservations WHERE reservation_id = ?")
            .bind(reservation_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(|r| r.get("coin_id")).collect())
    }

    /// Every hold that is still LIVE at `now_ms`, of BOTH phases, in coin order.
    ///
    /// # One answer, one handle namespace
    ///
    /// A coin can be held in either of two phases of the same lifecycle: a PRE-broadcast lease
    /// taken by [`Self::reserve_client_coins`], or a POST-broadcast commitment taken by
    /// [`Self::reserve_spend`] when a bundle was pushed. They live in different tables because the
    /// second is a child of a `pending_transactions` row and the first has no bundle yet.
    ///
    /// A caller must not have to know which phase a hold is in — it asked "may I spend this coin",
    /// and both answers are "no". So both are reported here under one `reservation_id` namespace,
    /// with the phase carried alongside for the callers that do care.
    ///
    /// Filters on the instant rather than trusting either table to have been pruned: a lapsed hold
    /// reported as live would have a caller waiting for a coin that is already free.
    ///
    /// The caller does not supply this time on the wire — the node reads its own clock. A
    /// caller-supplied `now` would be a lapse oracle, since a far-future value makes every live
    /// hold read as expired. It is a parameter HERE so a test can drive the edge exactly.
    pub async fn held_reservations(&self, now_ms: i64) -> sqlx::Result<Vec<ReservedCoinRow>> {
        let mut out = Vec::new();

        let leases = sqlx::query(
            "SELECT coin_id, reservation_id, expires_at_ms FROM client_coin_reservations
             WHERE expires_at_ms > ?",
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        for r in leases {
            out.push(ReservedCoinRow {
                coin_id: r.get("coin_id"),
                reservation_id: r.get("reservation_id"),
                expires_at_ms: r.get("expires_at_ms"),
                phase: ReservationPhase::Lease,
            });
        }

        // The post-broadcast half. Its lifetime lives on the parent transaction, so the join is
        // what makes an expiry visible at all; a reservation row alone carries no clock.
        let broadcast = sqlx::query(
            "SELECT r.coin_id AS coin_id, r.transaction_id AS reservation_id,
                    p.expires_at AS expires_at_ms
             FROM coin_reservations r
             JOIN pending_transactions p ON p.transaction_id = r.transaction_id
             WHERE p.expires_at > ?",
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        for r in broadcast {
            out.push(ReservedCoinRow {
                coin_id: r.get("coin_id"),
                reservation_id: r.get("reservation_id"),
                expires_at_ms: r.get("expires_at_ms"),
                phase: ReservationPhase::Broadcast,
            });
        }

        out.sort_by(|a, b| a.coin_id.cmp(&b.coin_id));
        Ok(out)
    }
}

/// 256 bits of OS randomness, hex-encoded — a reservation handle a caller cannot derive.
///
/// The OS CSPRNG directly rather than a seeded userspace generator, for two properties that are
/// NOT access control: collision resistance across concurrent holds, and unpredictability, so a
/// caller cannot free a hold it never observed.
///
/// **Guarding [`WalletDb::release_client_reservation`] is the control token's job, not this
/// value's.** Every live handle is published by `control.wallet.reservations.held`, so any caller
/// authorized to release can already read the handle it would pass. An earlier version of this
/// comment claimed unguessability WAS the access control; it was false the moment `held` shipped,
/// and it is recorded here because a doc that oversells a control is worse than no doc — it retires
/// the suspicion of the next person to read it.
fn new_reservation_id() -> sqlx::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| {
        sqlx::Error::Protocol(format!("reservation id randomness unavailable: {e}"))
    })?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether a SQLite error is the PRIMARY KEY refusing a second claim on one coin.
///
/// Matched on the driver's own constraint classification rather than on message text, so a phrasing
/// change in SQLite cannot silently turn a clash into an unreadable set — which would flip the
/// failure direction from "wait" to "do not spend" for every racing caller.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.is_unique_violation())
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
        assert!(
            fresh,
            "an ordinary add DOES confer the corroboration bypass"
        );

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
        let row = rows
            .iter()
            .find(|p| p.ip_addr == "2.2.2.2")
            .expect("unbanned");
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

    // ---- offers re-keyed onto the canonical id (dig-node#283) --------------
    //
    // A wallet DB written before #283 keys its offers by the offered coin set. Every read path
    // now asks for the canonical id, so without this migration those rows exist but cannot be
    // found — which is the same thing as losing them, from the user's side.

    /// A real, encoded offer plus its canonical id.
    fn an_offer() -> (String, String) {
        an_offer_requesting(500)
    }

    /// As [`an_offer`], but requesting `requested` — so several fixtures can differ in their TERMS
    /// while the builder stays otherwise identical, which is what makes their ids differ.
    fn an_offer_requesting(requested: u64) -> (String, String) {
        use crate::sage::offers::{build_make_offer, OfferInputs, OfferLeg};
        use crate::sage::spend::WalletSigner;
        use chia_wallet_sdk::types::TESTNET11_CONSTANTS;

        let mut sim = chia_sdk_test::Simulator::new();
        let maker = sim.bls(1_000);
        let signer = WalletSigner::new(
            vec![maker.sk.clone()],
            TESTNET11_CONSTANTS.agg_sig_me_additional_data,
        );
        build_make_offer(
            &signer,
            &OfferInputs {
                xch: vec![maker.coin],
                cats: vec![],
            },
            &[OfferLeg {
                asset_id: None,
                amount: 300,
            }],
            &[OfferLeg {
                asset_id: None,
                amount: requested,
            }],
            maker.puzzle_hash,
            maker.puzzle_hash,
            0,
        )
        .unwrap()
    }

    /// Put a freshly-opened database back into the state a PRE-#283 one is in. `open_in_memory`
    /// has already run the ladder and marked it, so a fixture that only plants a legacy-keyed row
    /// would be testing an already-migrated database — which is not the case under test.
    async fn mark_unmigrated(db: &WalletDb) {
        sqlx::query("PRAGMA user_version = 0")
            .execute(&db.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_legacy_keyed_offer_is_rekeyed_onto_its_canonical_id() {
        let db = WalletDb::open_in_memory().await.unwrap();
        mark_unmigrated(&db).await;
        let (offer, canonical_id) = an_offer();

        // The shape a pre-#283 node wrote: the same offer under a coin-set-derived key.
        let legacy_id = "0".repeat(64);
        assert_ne!(legacy_id, canonical_id, "the fixture must exercise a REKEY");
        db.upsert_offer(&OfferDbRow {
            offer_id: legacy_id.clone(),
            offer: offer.clone(),
            status: "active".into(),
            creation_timestamp: 77,
            summary_json: "{\"legacy\":true}".into(),
        })
        .await
        .unwrap();

        db.migrate().await.unwrap();

        assert!(
            db.offer(&legacy_id).await.unwrap().is_none(),
            "the legacy key must not survive, or the offer would exist twice"
        );
        let row = db
            .offer(&canonical_id)
            .await
            .unwrap()
            .expect("the offer must be reachable under its canonical id after migration");
        // A rename, not a rebuild: every field the user's offer carried is still here.
        assert_eq!(row.offer, offer);
        assert_eq!(row.status, "active");
        assert_eq!(row.creation_timestamp, 77);
        assert_eq!(row.summary_json, "{\"legacy\":true}");
        assert_eq!(db.all_offers().await.unwrap().len(), 1);
    }

    /// A row already under its canonical id must come through the re-key unchanged.
    ///
    /// This test does NOT prove the `continue` that skips such a row: a delete-and-reinsert of the
    /// identical row is indistinguishable from a skip at this seam. It is kept for what it does
    /// catch — an implementation that drops the row it just re-keyed — and idempotence is carried
    /// instead by [`the_ladder_mark_stops_the_migration_running_again`], which observes the skip
    /// directly.
    #[tokio::test]
    async fn an_already_canonical_offer_survives_the_rekey_unchanged() {
        let db = WalletDb::open_in_memory().await.unwrap();
        mark_unmigrated(&db).await;
        let (offer, canonical_id) = an_offer();
        db.upsert_offer(&OfferDbRow {
            offer_id: canonical_id.clone(),
            offer,
            status: "active".into(),
            creation_timestamp: 77,
            summary_json: "{}".into(),
        })
        .await
        .unwrap();

        db.migrate().await.unwrap();
        db.migrate().await.unwrap();

        assert_eq!(db.all_offers().await.unwrap().len(), 1);
        assert!(db.offer(&canonical_id).await.unwrap().is_some());
    }

    /// A row whose offer string will not decode cannot be re-keyed. It must be LEFT, not dropped:
    /// an oddly-keyed offer is still recoverable by the user; a deleted one is not.
    #[tokio::test]
    async fn an_undecodable_offer_row_is_left_untouched() {
        let db = WalletDb::open_in_memory().await.unwrap();
        mark_unmigrated(&db).await;
        db.upsert_offer(&OfferDbRow {
            offer_id: "1".repeat(64),
            offer: "not-an-offer".into(),
            status: "active".into(),
            creation_timestamp: 1,
            summary_json: "{}".into(),
        })
        .await
        .unwrap();

        db.migrate().await.unwrap();

        assert!(db.offer(&"1".repeat(64)).await.unwrap().is_some());
    }

    /// The ladder mark is what stops a one-shot data migration re-reading and re-decoding every
    /// stored offer on every open, forever.
    ///
    /// Observed directly rather than inferred: plant a legacy-keyed row in an ALREADY-marked
    /// database and require that a further `migrate()` leaves it exactly where it is. Without a
    /// mark the row would be re-keyed and this fails — which is the point, since "it did nothing"
    /// is otherwise indistinguishable from "it did the work again and reached the same answer".
    #[tokio::test]
    async fn the_ladder_mark_stops_the_migration_running_again() {
        let db = WalletDb::open_in_memory().await.unwrap();
        // Deliberately NOT `mark_unmigrated`: opening already ran and marked the ladder.
        let (offer, canonical_id) = an_offer();
        let legacy_id = "2".repeat(64);
        db.upsert_offer(&OfferDbRow {
            offer_id: legacy_id.clone(),
            offer,
            status: "active".into(),
            creation_timestamp: 5,
            summary_json: "{}".into(),
        })
        .await
        .unwrap();

        db.migrate().await.unwrap();

        assert!(
            db.offer(&legacy_id).await.unwrap().is_some(),
            "a marked database must not run the re-key again"
        );
        assert!(db.offer(&canonical_id).await.unwrap().is_none());
    }

    /// The re-key moves rows by deleting them from under the old key and writing them under the
    /// new one. Committed separately, a failure between those two steps would DESTROY the offer —
    /// strictly worse than the unreachable-row defect the migration exists to repair, because an
    /// offer the user made is not rebuildable from chain. So the whole re-key is one transaction.
    ///
    /// What this asserts is the observable half: a multi-row re-key lands completely, with every
    /// offer accounted for and none lost in the move. The crash-mid-transaction half is a
    /// structural property of `pool.begin()` / `commit()` and is NOT proven here — forcing a
    /// driver failure at that instant would need failure injection this seam does not have.
    #[tokio::test]
    async fn a_multi_row_rekey_lands_completely_with_no_offer_lost() {
        let db = WalletDb::open_in_memory().await.unwrap();
        mark_unmigrated(&db).await;

        let mut expected = Vec::new();
        for (i, requested) in [500u64, 700, 900].iter().enumerate() {
            let (offer, canonical_id) = an_offer_requesting(*requested);
            db.upsert_offer(&OfferDbRow {
                offer_id: format!("{i}").repeat(64),
                offer,
                status: "active".into(),
                creation_timestamp: i as i64,
                summary_json: format!("{{\"requested\":{requested}}}"),
            })
            .await
            .unwrap();
            expected.push((canonical_id, *requested));
        }
        assert_eq!(db.all_offers().await.unwrap().len(), 3);

        db.migrate().await.unwrap();

        assert_eq!(
            db.all_offers().await.unwrap().len(),
            3,
            "no offer may be lost in the move"
        );
        for (canonical_id, requested) in expected {
            let row = db
                .offer(&canonical_id)
                .await
                .unwrap()
                .expect("every row must have landed under its canonical id");
            assert_eq!(row.summary_json, format!("{{\"requested\":{requested}}}"));
        }
    }

    // ---- in-flight spend reservations (dig_ecosystem#2763) ----------------

    /// A reservation over `coin_ids`, submitted at `submitted_at` and lapsing at `expires_at`.
    fn reservation(
        tx: &str,
        coin_ids: &[&str],
        submitted_at: i64,
        expires_at: i64,
    ) -> PendingTransactionRow {
        PendingTransactionRow {
            transaction_id: tx.into(),
            bundle_hex: format!("bundle-of-{tx}"),
            fee: Some("10".into()),
            submitted_at,
            expires_at,
            attempts: 1,
            reserved_coin_ids: coin_ids.iter().map(|c| (*c).to_string()).collect(),
        }
    }

    /// **The defect, at the DB layer.** A coin committed to a pushed, unsettled bundle must not be
    /// offered to the next selection — while still counting as money the wallet owns, because the
    /// chain has not said otherwise yet.
    #[tokio::test]
    async fn a_reserved_coin_leaves_selection_but_not_the_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.upsert_coin(&coin("c2", 50, Some(10), None))
            .await
            .unwrap();

        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 60_000))
            .await
            .unwrap();

        let selectable: Vec<String> = db
            .unreserved_unspent_coins(None)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.coin_id)
            .collect();
        assert_eq!(
            selectable,
            vec!["c2".to_string()],
            "a coin already in flight was offered for selection again"
        );
        assert_eq!(
            db.balance(None).await.unwrap(),
            150,
            "an in-flight spend has not settled, so the coin is still the user's money"
        );
    }

    /// Coin ids compare case-insensitively, as every other hex column here does. A caller that
    /// reserves an upper-case id must not get the coin back from selection.
    #[tokio::test]
    async fn reservation_matching_is_case_insensitive() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("abcd", 100, Some(10), None))
            .await
            .unwrap();

        db.reserve_spend(&reservation("tx1", &["ABCD"], 1_000, 60_000))
            .await
            .unwrap();

        assert!(
            db.unreserved_unspent_coins(None).await.unwrap().is_empty(),
            "an upper-case reservation failed to hold its coin"
        );
    }

    /// **The reservation ALWAYS lapses.** This keeps a release path that never runs from stranding
    /// the user's coin permanently — the failure direction that would be worse than the bug.
    #[tokio::test]
    async fn an_expired_reservation_releases_its_coin() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 60_000))
            .await
            .unwrap();

        assert_eq!(
            db.prune_reservations(59_999).await.unwrap(),
            0,
            "pruned before the deadline"
        );
        assert!(db.unreserved_unspent_coins(None).await.unwrap().is_empty());

        assert_eq!(
            db.prune_reservations(60_000).await.unwrap(),
            1,
            "the deadline itself must lapse"
        );
        assert_eq!(db.unreserved_unspent_coins(None).await.unwrap().len(), 1);
        assert!(db.pending_transactions().await.unwrap().is_empty());
    }

    /// Settlement retires the reservation without anything having to remember to release it: the
    /// coin's own `spent_height` is the signal.
    #[tokio::test]
    async fn observing_a_reserved_coin_spent_retires_its_bundle() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.upsert_coin(&coin("c2", 50, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1", "c2"], 1_000, 60_000))
            .await
            .unwrap();

        db.upsert_coin(&coin("c1", 100, Some(10), Some(11)))
            .await
            .unwrap();

        assert_eq!(db.prune_reservations(2_000).await.unwrap(), 1);
        assert!(
            db.pending_transactions().await.unwrap().is_empty(),
            "a bundle whose input is spent can never be included, so it must stop holding the rest"
        );
        let selectable: Vec<String> = db
            .unreserved_unspent_coins(None)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.coin_id)
            .collect();
        assert_eq!(
            selectable,
            vec!["c2".to_string()],
            "c2 stayed stranded behind a bundle that can never be included"
        );
    }
    /// **A coin recorded in UPPER-case hex retires its bundle like any other.**
    ///
    /// `reserve_spend` normalises the ids it writes; `coins` stores whatever hex the chain source
    /// handed over. The retirement join compared the two RAW, so an upper-case coin never matched
    /// its own reservation: the settled bundle stayed pending and held its other inputs out of
    /// selection for the entire TTL — a self-inflicted freeze on money the chain had already moved.
    ///
    /// FIXTURE DESIGN. Case is the ONLY axis varied from
    /// [`observing_a_reserved_coin_spent_retires_its_bundle`], which stays green as the lower-case
    /// control; both coins here are upper-case, so the assertion cannot be satisfied by a
    /// normalisation applied to only one of the two comparison sides. The second coin is what makes
    /// the stranding visible: with one coin, "retired" and "nothing was ever reserved" look alike.
    #[tokio::test]
    async fn an_upper_case_coin_id_still_retires_its_settled_bundle() {
        const UPPER: &str = "AABB";
        const OTHER: &str = "CCDD";
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin(UPPER, 100, Some(10), None))
            .await
            .unwrap();
        db.upsert_coin(&coin(OTHER, 50, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &[UPPER, OTHER], 1_000, 60_000))
            .await
            .unwrap();

        db.upsert_coin(&coin(UPPER, 100, Some(10), Some(11)))
            .await
            .unwrap();

        assert_eq!(
            db.prune_reservations(2_000).await.unwrap(),
            1,
            "a settled bundle whose coin id is upper-case was never retired"
        );
        assert!(
            db.pending_transactions().await.unwrap().is_empty(),
            "the bundle stayed in flight after the chain settled it"
        );
        assert_eq!(
            db.unreserved_unspent_coins(None).await.unwrap().len(),
            1,
            "the settled bundle's other input stayed stranded until its TTL"
        );
    }

    // ---- the `coins` table stores lower-case hex (dig-node#293 round 2) ----
    //
    // These three cover the three raw `coin_id` comparisons that survived the first fix. Each
    // varies ONE axis — the case the chain source happened to hand over — and each carries a
    // control that a blanket "match everything" implementation would fail, so none of them can be
    // satisfied by a comparison that stopped discriminating.

    /// **A coin stored in upper-case hex is still spendable when asked about in lower case.**
    ///
    /// `are_coins_spendable` backs the Sage-parity `get_are_coins_spendable` endpoint, whose ids
    /// come straight from the caller. Comparing raw made an upper-case row invisible, so a
    /// genuinely spendable coin was reported unspendable. It fails CLOSED — a refusal, not a
    /// theft — but it is still a wrong answer about money given to a parity consumer.
    ///
    /// CONTROL: an id that names no coin at all must still answer `false`. Without it the
    /// assertion would also hold for an implementation that answered `true` unconditionally.
    #[tokio::test]
    async fn a_coin_stored_upper_case_is_spendable_under_a_lower_case_id() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("AABB", 100, Some(10), None))
            .await
            .unwrap();

        assert!(
            db.are_coins_spendable(&["aabb".to_string()]).await.unwrap(),
            "a spendable coin read as unspendable because its stored hex was upper-case"
        );
        assert!(
            db.are_coins_spendable(&["AABB".to_string()]).await.unwrap(),
            "the same coin stopped being found under the exact hex it was written with"
        );
        assert!(
            !db.are_coins_spendable(&["ffff".to_string()]).await.unwrap(),
            "CONTROL: an unknown coin id was reported spendable"
        );
    }

    /// **The wallet's own change is not announced as an incoming payment when the two sides of the
    /// parent link disagree on case.**
    ///
    /// `record_arrivals` answers `parent_is_ours` with `SELECT 1 FROM coins WHERE coin_id = ?`
    /// bound to the child's `parent_coin_info`. Compared raw, a parent written `AABB` does not
    /// match a child pointing at `aabb`, `classify` sees a foreign parent, and the wallet's own
    /// change comes back to the user as money that arrived from someone else — the same family of
    /// money-display lie as dig-node#293 itself.
    ///
    /// FIXTURE DESIGN. The two sides are written in DIFFERENT cases on purpose: a fixture where
    /// both are upper-case matches raw and cannot see this defect at all, and a fix applied to
    /// only one of the two comparison sides would satisfy it. The foreign-parent coin beside it is
    /// the control — it must STILL be announced, so the test cannot be passed by a recorder that
    /// has simply stopped announcing arrivals.
    #[tokio::test]
    async fn own_change_is_not_announced_as_incoming_across_a_case_mismatch() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.complete_catch_up(&CatchUpReplay::finished_at(None, 100, "hh", &[]).unwrap())
            .await
            .unwrap();

        // BOTH directions of the mismatch, because they are repaired by DIFFERENT normalisations
        // and a fixture carrying only one cannot tell them apart. Parent stored upper / child
        // pointing lower is fixed by normalising the stored `coin_id`; parent stored lower / child
        // pointing upper is fixed by normalising the stored `parent_coin_info`. With only the
        // first, an implementation that normalises `coin_id` alone passes — which is exactly what
        // the first version of this test did.
        db.upsert_coin(&coin("AABB", 500, Some(50), Some(101)))
            .await
            .unwrap();
        let mut change_lower = coin("change_lower", 400, Some(101), None);
        change_lower.parent_coin_info = "aabb".into();
        db.upsert_coin(&change_lower).await.unwrap();

        db.upsert_coin(&coin("ccdd", 500, Some(50), Some(101)))
            .await
            .unwrap();
        let mut change_upper = coin("change_upper", 300, Some(101), None);
        change_upper.parent_coin_info = "CCDD".into();
        db.upsert_coin(&change_upper).await.unwrap();

        // CONTROL: a coin at our address from a parent we genuinely do not hold.
        db.upsert_coin(&incoming("paid", 700, 101)).await.unwrap();

        assert_eq!(
            db.record_arrivals(&watched(), 101).await.unwrap(),
            1,
            "the wallet's own change was announced as an incoming payment"
        );
        let announced: Vec<String> = db
            .arrivals_since(0, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.coin_id)
            .collect();
        assert_eq!(
            announced,
            vec!["paid".to_string()],
            "CONTROL: the genuinely foreign payment stopped being announced"
        );
    }

    /// Insert a coin row past the normalising accessors, exactly as a pre-#293 build did.
    /// `amount` is the tag that tells otherwise-identical case twins apart.
    async fn insert_legacy_coin(db: &WalletDb, coin_id: &str, parent: &str, amount: &str) {
        sqlx::query(
            "INSERT OR REPLACE INTO coins
                (coin_id, parent_coin_info, puzzle_hash, amount, created_height)
             VALUES (?, ?, 'ph', ?, 10)",
        )
        .bind(coin_id)
        .bind(parent)
        .bind(amount)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    /// Re-arm the ladder so the coin-hex step runs again on an already-open database.
    async fn rearm_coin_hex_migration(db: &WalletDb) {
        sqlx::query(&format!(
            "PRAGMA user_version = {}",
            COINS_STORED_LOWER_CASE - 1
        ))
        .execute(&db.pool)
        .await
        .unwrap();
    }

    async fn coin_ids(db: &WalletDb) -> Vec<String> {
        sqlx::query("SELECT coin_id FROM coins ORDER BY coin_id")
            .fetch_all(&db.pool)
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<String, _>("coin_id"))
            .collect()
    }

    async fn amount_of(db: &WalletDb, coin_id: &str) -> String {
        sqlx::query("SELECT amount FROM coins WHERE coin_id = ?")
            .bind(coin_id)
            .fetch_one(&db.pool)
            .await
            .unwrap()
            .get::<String, _>("amount")
    }

    /// **A database written before the writer normalised is repaired on open.**
    ///
    /// Fixing the writer does nothing for rows already on disk, and those rows are exactly the
    /// ones the three defects above were found on. The ladder step lower-cases them once.
    ///
    /// The duplicate pair is the case that would otherwise abort the migration: `AABB` and `aabb`
    /// are the same coin under a unique coin id that cannot hold both. The two twins are given
    /// DIFFERENT amounts so the assertion can name WHICH one survived — with identical rows a
    /// migration that kept the wrong twin would pass this test unchanged.
    #[tokio::test]
    async fn a_legacy_database_has_its_coin_hex_normalised_on_open() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy_coin(&db, "CCDD", "EEFF", "1").await;
        insert_legacy_coin(&db, "AABB", "0011", "upper").await;
        insert_legacy_coin(&db, "aabb", "0011", "lower").await;
        rearm_coin_hex_migration(&db).await;

        db.migrate().await.unwrap();

        assert_eq!(
            coin_ids(&db).await,
            vec!["aabb".to_string(), "ccdd".to_string()],
            "legacy upper-case coin ids survived the migration"
        );
        assert_eq!(
            amount_of(&db, "aabb").await,
            "lower",
            "the ALREADY-CANONICAL spelling is the one that survives a case collision"
        );
        let parents: Vec<String> =
            sqlx::query("SELECT parent_coin_info FROM coins ORDER BY coin_id")
                .fetch_all(&db.pool)
                .await
                .unwrap()
                .iter()
                .map(|r| r.get::<String, _>("parent_coin_info"))
                .collect();
        assert_eq!(
            parents,
            vec!["0011".to_string(), "eeff".to_string()],
            "legacy upper-case parent links survived the migration"
        );
    }

    /// **A coin id stored under several NON-canonical spellings does not brick the wallet.**
    ///
    /// This is the failure the two-spelling collision rule could not see. `AAbb` and `aAbb` are
    /// both unequal to their own lower-casing, so a DELETE scoped to "upper-case rows whose
    /// lower-casing already exists" removes neither, and the UPDATE then collides them onto one
    /// unique key. The transaction rolls back, `migrate` returns `Err`, `WalletDb::open` returns
    /// `Err` — and the retry on the next open is byte-for-byte identical, so the wallet never
    /// opens again. A rollback is only a safe failure when the retry can succeed.
    ///
    /// The survivor is the lexicographically smallest spelling, `AAbb`, since neither is
    /// canonical. That choice is arbitrary; being TOTAL and DETERMINISTIC is the point.
    #[tokio::test]
    async fn a_coin_id_stored_under_many_case_twins_does_not_brick_the_wallet() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy_coin(&db, "AAbb", "0011", "first").await;
        insert_legacy_coin(&db, "aAbb", "0011", "second").await;
        rearm_coin_hex_migration(&db).await;

        db.migrate()
            .await
            .expect("a collision between non-canonical spellings must not fail the migration");

        assert_eq!(
            coin_ids(&db).await,
            vec!["aabb".to_string()],
            "the collided spellings were reduced to exactly one canonical row"
        );
        assert_eq!(
            amount_of(&db, "aabb").await,
            "first",
            "with no canonical spelling present, the smallest survives"
        );
    }

    /// **The tables that key rows by a coin id are normalised WITH it, in the same open.**
    ///
    /// `arrival_pending` and `arrivals` hold copies of `coins.coin_id` and are compared against it
    /// raw. Left behind, a held row is pruned by `record_arrivals` — and losing the hold is how a
    /// deferred coin falls below the baseline watermark and is never announced — while an
    /// already-recorded arrival stops matching its `INSERT OR IGNORE` and is announced twice.
    #[tokio::test]
    async fn the_dependent_coin_id_tables_are_normalised_with_the_coin_table() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy_coin(&db, "AABB", "0011", "1").await;
        sqlx::query("INSERT INTO arrival_pending (coin_id, created_height) VALUES ('AABB', 10)")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO arrivals
                (coin_id, puzzle_hash, amount, asset_id, confirmed_height, recorded_at)
             VALUES ('AABB', 'ph', '1', NULL, 10, 0)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        rearm_coin_hex_migration(&db).await;

        db.migrate().await.unwrap();

        for table in ["arrival_pending", "arrivals"] {
            let ids: Vec<String> = sqlx::query(&format!("SELECT coin_id FROM {table}"))
                .fetch_all(&db.pool)
                .await
                .unwrap()
                .iter()
                .map(|r| r.get::<String, _>("coin_id"))
                .collect();
            assert_eq!(
                ids,
                vec!["aabb".to_string()],
                "{table} still keys its row by the un-normalised coin id"
            );
        }
    }

    /// **Retiring a bundle leaves NO orphan reservation.** The `coin_reservations` rows go with it,
    /// via the foreign-key cascade rather than a second delete a future caller could forget.
    ///
    /// This is the property `release_spend` used to prove. That method was removed because it had
    /// no production caller and could never gain a correct one: a refusal reserves nothing
    /// ([`WalletBackend::push_signed_bundle`] guards on `accepted`), and a settlement is retired by
    /// [`WalletDb::prune_reservations`] — so every definitive outcome was already covered, and a
    /// third release path on a custody-adjacent table was reachable only by mistake. The cascade it
    /// depended on is real and still load-bearing, so it is asserted here through the retirement
    /// path that actually runs.
    #[tokio::test]
    async fn retiring_a_bundle_cascades_away_its_reservations() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 60_000))
            .await
            .unwrap();
        assert_eq!(
            db.reserved_coin_ids().await.unwrap().len(),
            1,
            "the fixture must start with a live reservation, or the assertions below are vacuous"
        );

        assert_eq!(db.prune_reservations(60_000).await.unwrap(), 1);

        assert_eq!(db.unreserved_unspent_coins(None).await.unwrap().len(), 1);
        assert!(
            db.reserved_coin_ids().await.unwrap().is_empty(),
            "the cascade left an orphan reservation"
        );
    }

    /// A resubmission is the SAME transaction: it refreshes the expiry and counts the attempt,
    /// never appearing twice and never moving a coin's reservation onto a new row.
    #[tokio::test]
    async fn resubmitting_the_same_bundle_updates_it_in_place() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 60_000))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 120_000))
            .await
            .unwrap();

        let pending = db.pending_transactions().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attempts, 2);
        assert_eq!(pending[0].expires_at, 120_000);
        assert_eq!(
            pending[0].submitted_at, 1_000,
            "the FIRST submission time is what a caller has been polling against"
        );
        assert_eq!(pending[0].reserved_coin_ids, vec!["c1".to_string()]);
    }

    /// A coin already committed to one in-flight bundle keeps that commitment. The first claim is
    /// the one the mempool will honour, so a later bundle must not silently take the coin over.
    #[tokio::test]
    async fn a_coin_backs_only_the_first_bundle_that_claimed_it() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&coin("c1", 100, Some(10), None))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx1", &["c1"], 1_000, 60_000))
            .await
            .unwrap();
        db.reserve_spend(&reservation("tx2", &["c1"], 2_000, 60_000))
            .await
            .unwrap();

        let pending = db.pending_transactions().await.unwrap();
        assert_eq!(
            pending.len(),
            2,
            "both bundles were pushed, so both are in flight"
        );
        let tx1 = pending.iter().find(|p| p.transaction_id == "tx1").unwrap();
        let tx2 = pending.iter().find(|p| p.transaction_id == "tx2").unwrap();
        assert_eq!(tx1.reserved_coin_ids, vec!["c1".to_string()]);
        assert!(
            tx2.reserved_coin_ids.is_empty(),
            "the second bundle took over the first bundle's coin"
        );
    }

    /// The pending set is what `get_pending_transactions` reports, so its ORDER and fields must be
    /// stable: oldest submission first, carrying the fee and submission time a caller displays.
    #[tokio::test]
    async fn pending_transactions_report_oldest_first_with_fee_and_submission_time() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.reserve_spend(&reservation("later", &[], 5_000, 60_000))
            .await
            .unwrap();
        db.reserve_spend(&reservation("earlier", &[], 1_000, 60_000))
            .await
            .unwrap();

        let pending = db.pending_transactions().await.unwrap();
        let ids: Vec<&str> = pending.iter().map(|p| p.transaction_id.as_str()).collect();
        assert_eq!(ids, vec!["earlier", "later"]);
        assert_eq!(pending[0].fee.as_deref(), Some("10"));
        assert_eq!(pending[0].submitted_at, 1_000);
        assert_eq!(pending[0].bundle_hex, "bundle-of-earlier");
    }
    // ---- cross-process client coin reservations (dig_ecosystem#3127) ------
    //
    // Fixture discipline for this group. Every expiry here is driven from a PINNED `NOW` rather
    // than the wall clock. A small literal such as `100` passed through an epoch-milliseconds API
    // is ~1.8 trillion ms in the PAST, so a group written that way would assert acquisition while
    // exercising only the already-lapsed path: the reservations would be dead on arrival and every
    // "it is held" assertion would be testing nothing.
    const NOW: i64 = 1_800_000_000_000;

    /// Reserve helper: the common case, one caller, the node's default lifetime.
    async fn hold(db: &WalletDb, ids: &[&str], now_ms: i64) -> ClientReservation {
        db.reserve_client_coins(
            &ids.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
            None,
            now_ms,
        )
        .await
        .expect("reservation should have been granted")
    }

    async fn selectable(db: &WalletDb) -> Vec<String> {
        let mut ids: Vec<String> = db
            .unreserved_unspent_coins(None)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.coin_id)
            .collect();
        ids.sort();
        ids
    }

    /// Two unspent coins, so every test below has a TRUTHFUL CONTROL: a coin that is NOT reserved
    /// and must stay selectable. Asserting only that a held coin disappears cannot distinguish a
    /// working filter from one that hides everything, which is the nearest wrong implementation.
    async fn two_coin_wallet() -> WalletDb {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db.upsert_coins(&[
            coin("aa", 1_000, Some(10), None),
            coin("bb", 2_000, Some(10), None),
        ])
        .await
        .unwrap();
        db
    }

    #[tokio::test]
    async fn a_client_reservation_narrows_selection_and_leaves_its_neighbour_alone() {
        let db = two_coin_wallet().await;
        hold(&db, &["aa"], NOW).await;

        assert_eq!(
            selectable(&db).await,
            vec!["bb".to_string()],
            "the held coin must leave the selectable set and the unheld one must remain in it"
        );
    }

    #[tokio::test]
    async fn a_reservation_narrows_selection_but_never_the_balance() {
        let db = two_coin_wallet().await;
        let before = db.balance(None).await.unwrap();
        hold(&db, &["aa"], NOW).await;

        assert_eq!(
            db.balance(None).await.unwrap(),
            before,
            "a reserved coin is still the user money; netting it out would report money as gone \
             before the chain has said so"
        );
    }

    // ---- all-or-none acquisition ----------------------------------------

    #[tokio::test]
    async fn a_clash_reserves_nothing_at_all() {
        let db = two_coin_wallet().await;
        hold(&db, &["aa"], NOW).await;

        // Ask for the held coin AND a free one. The free one is the load-bearing half: an
        // implementation that returns the error but has already inserted `bb` satisfies an
        // assertion about the error alone, and would silently strand `bb`.
        let err = db
            .reserve_client_coins(&["aa".into(), "bb".into()], None, NOW)
            .await
            .expect_err("a clash must refuse");

        match err {
            ReserveClientCoinsError::Reserved { coin_ids } => {
                assert_eq!(
                    coin_ids,
                    vec!["aa".to_string()],
                    "the clashing coin is named"
                );
            }
            other => panic!("a clash must be Reserved, not {other:?}"),
        }
        assert_eq!(
            selectable(&db).await,
            vec!["bb".to_string()],
            "the coin that did NOT clash must not have been taken by the failed call"
        );
    }

    #[tokio::test]
    async fn a_clash_against_a_bundle_backed_reservation_also_refuses() {
        // The two reservation kinds live in DIFFERENT tables, so the coin-id PRIMARY KEY cannot
        // detect this collision for us. Without an explicit cross-table check a client would be
        // handed a coin that a pushed bundle is already spending.
        let db = two_coin_wallet().await;
        db.reserve_spend(&PendingTransactionRow {
            transaction_id: "tx1".into(),
            bundle_hex: "ff".into(),
            fee: None,
            submitted_at: NOW,
            expires_at: NOW + 600_000,
            attempts: 1,
            reserved_coin_ids: vec!["aa".into()],
        })
        .await
        .unwrap();

        let err = db
            .reserve_client_coins(&["aa".into()], None, NOW)
            .await
            .expect_err("a coin committed to a pushed bundle must not be re-reservable");
        assert!(
            matches!(err, ReserveClientCoinsError::Reserved { .. }),
            "a bundle-backed clash is still a WAIT, not an unavailable set: {err:?}"
        );
    }

    /// How many callers contend for one coin per round.
    ///
    /// More than two on purpose. A non-atomic implementation does not fail every time; widening
    /// the field raises the chance that at least two callers are genuinely inside the critical
    /// section together, which is the only condition under which the defect is observable.
    const RACERS: usize = 8;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn racing_reservations_of_one_coin_produce_exactly_one_winner() {
        // Read-then-write is check-then-act, and every caller sees the coin free. Only atomic
        // acquisition makes exactly one of them win.
        //
        // Three things make this fixture able to SEE a non-atomic implementation, and it was blind
        // without all three:
        //
        // 1. **A file-backed DB.** `open_in_memory` is `max_connections(1)`, so tasks against it
        //    are serialized by the connection pool and no race can occur at all. A file DB opens
        //    the ordinary multi-connection WAL pool that production uses.
        // 2. **A barrier.** Spawning tasks that each do a few fast statements lets the first finish
        //    before the last begins; they never overlap and the test passes against anything. The
        //    barrier releases every caller into the critical section at once.
        // 3. **A multi-threaded runtime.** On the single-threaded runtime the barrier only
        //    interleaves at await points on one core.
        //
        // Measured against a deliberately broken build (`INSERT OR REPLACE`, plus the lapsed-row
        // DELETE moved outside the transaction so the pre-check no longer runs under the write
        // lock): this shape reports multiple winners, while the earlier two-task in-memory version
        // reported exactly one and looked healthy.
        let dir = tempfile::tempdir().unwrap();
        for round in 0..12 {
            let path = dir.path().join(format!("race{round}.sqlite"));
            let db = std::sync::Arc::new(WalletDb::open(path.to_str().unwrap()).await.unwrap());
            let id = format!("race{round}");
            db.upsert_coins(&[coin(&id, 1_000, Some(10), None)])
                .await
                .unwrap();

            let gate = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
            let mut tasks = Vec::with_capacity(RACERS);
            for _ in 0..RACERS {
                let (db, gate, id) = (db.clone(), gate.clone(), id.clone());
                tasks.push(tokio::spawn(async move {
                    gate.wait().await;
                    db.reserve_client_coins(&[id], None, NOW).await
                }));
            }
            let mut outcomes = Vec::with_capacity(RACERS);
            for t in tasks {
                outcomes.push(t.await.unwrap());
            }

            let winners = outcomes.iter().filter(|o| o.is_ok()).count();
            assert_eq!(
                winners, 1,
                "round {round}: {winners} of {RACERS} callers were handed the same coin — 0 is a \
                 coin nobody can spend, and more than 1 is the double-select this table exists to \
                 prevent"
            );

            // Every loser must REFUSE, and the refusal must stay readable as a WAIT rather than as
            // an unreadable set: a caller told the set is unavailable stops spending altogether,
            // where a clash only asks it to wait. Contention is exactly when that distinction is
            // load-bearing, so it is asserted here and not only on the uncontended path.
            for outcome in outcomes.iter().filter(|o| o.is_err()) {
                match outcome {
                    Err(ReserveClientCoinsError::Reserved { coin_ids }) => {
                        assert_eq!(coin_ids, &vec![id.clone()], "round {round}");
                    }
                    other => {
                        panic!("round {round}: a contended clash must be Reserved, got {other:?}")
                    }
                }
            }

            // And the winner's hold is real rather than merely reported.
            assert!(
                db.reserved_coin_ids().await.unwrap().contains(&id),
                "round {round}: a reservation was granted but nothing is held"
            );
        }
    }

    #[tokio::test]
    async fn an_empty_reservation_succeeds_and_holds_nothing() {
        let db = two_coin_wallet().await;
        let r = db.reserve_client_coins(&[], None, NOW).await.unwrap();

        assert!(r.coin_ids.is_empty());
        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string(), "bb".to_string()],
            "an empty selection is legitimate and must not look malformed"
        );
    }

    // ---- the release path, all four ways a hold can end ------------------
    //
    // An acquire-only battery is vacuous: a reservation with no release path is a wallet that
    // locks itself out of its own funds, which is WORSE than the double-select it prevents. Each
    // of the four endings gets its own test.

    #[tokio::test]
    async fn release_1_of_4_explicit_release_frees_the_coin_immediately() {
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;

        let freed = db
            .release_client_reservation(&r.reservation_id)
            .await
            .unwrap();

        assert_eq!(freed, vec!["aa".to_string()], "release names what it freed");
        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string(), "bb".to_string()],
            "an explicitly released coin is selectable again without waiting out the TTL"
        );
    }

    #[tokio::test]
    async fn release_2_of_4_a_confirmed_spend_retires_the_hold_with_no_release_call() {
        // The confirm path must not depend on anyone remembering to call release: the client that
        // would have called it may be gone by the time the chain answers.
        let db = two_coin_wallet().await;
        hold(&db, &["aa"], NOW).await;

        db.upsert_coins(&[coin("aa", 1_000, Some(10), Some(11))])
            .await
            .unwrap();
        db.prune_reservations(NOW).await.unwrap();

        assert!(
            !db.reserved_coin_ids().await.unwrap().contains("aa"),
            "a coin the chain reports SPENT is not being held for anything"
        );
    }

    #[tokio::test]
    async fn release_3_of_4_a_lapsed_hold_is_retired_by_the_ttl_alone() {
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;

        // One millisecond BEFORE the expiry the hold is still live. Without this half the test
        // would pass against an implementation that expires everything instantly.
        db.prune_reservations(r.expires_at_ms - 1).await.unwrap();
        assert_eq!(
            selectable(&db).await,
            vec!["bb".to_string()],
            "the hold lapsed early, so the TTL is not being honoured"
        );

        db.prune_reservations(r.expires_at_ms).await.unwrap();
        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string(), "bb".to_string()],
            "the hold outlived its TTL, which is a funds lockout"
        );
    }

    #[tokio::test]
    async fn release_4_of_4_an_abandoned_hold_cannot_strand_a_coin_forever() {
        // Process death: the reserving client never calls release and never comes back. Nothing in
        // the system knows its handle. Only the unconditional expiry recovers the coin.
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;
        drop(r); // the handle is gone; no one can ever release it explicitly

        db.prune_reservations(NOW + CLIENT_RESERVATION_MAX_TTL_MS + 1)
            .await
            .unwrap();

        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string(), "bb".to_string()],
            "an abandoned reservation stranded the user coin permanently"
        );
    }

    #[tokio::test]
    async fn releasing_an_unknown_handle_is_a_success_that_freed_nothing() {
        // A client releasing on confirmation cannot know whether the TTL got there first. Making
        // that an error teaches callers to ignore the result of release, which is worse.
        let db = two_coin_wallet().await;
        let freed = db
            .release_client_reservation(&"0".repeat(64))
            .await
            .unwrap();
        assert!(
            freed.is_empty(),
            "an unknown handle freed nothing, and that is not an error"
        );
    }

    #[tokio::test]
    async fn release_frees_every_coin_of_a_multi_coin_hold() {
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa", "bb"], NOW).await;

        let mut freed = db
            .release_client_reservation(&r.reservation_id)
            .await
            .unwrap();
        freed.sort();
        assert_eq!(freed, vec!["aa".to_string(), "bb".to_string()]);
        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string(), "bb".to_string()]
        );
    }

    // ---- expiry must not defeat the spent check (the epic own invariant) ----

    #[tokio::test]
    async fn a_lapsed_reservation_does_not_resurrect_a_spent_coin() {
        // The registry is a filter LAYERED ON the chain read, never a replacement for it. If a
        // lapsed hold could make a spent coin selectable again, expiry would have become a way to
        // build a bundle over money that is already gone.
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;
        db.upsert_coins(&[coin("aa", 1_000, Some(10), Some(11))])
            .await
            .unwrap();

        db.prune_reservations(r.expires_at_ms + 1).await.unwrap();

        assert_eq!(
            selectable(&db).await,
            vec!["bb".to_string()],
            "a SPENT coin became selectable once its reservation lapsed"
        );
    }

    // ---- the lifetime the node actually applied --------------------------

    #[tokio::test]
    async fn an_over_long_ttl_is_clamped_to_the_node_maximum() {
        let db = two_coin_wallet().await;
        let day_ms = 86_400_000;
        let r = db
            .reserve_client_coins(&["aa".into()], Some(day_ms), NOW)
            .await
            .unwrap();

        assert_eq!(
            r.expires_at_ms,
            NOW + CLIENT_RESERVATION_MAX_TTL_MS,
            "a caller was told nothing would wait on a schedule the node does not keep"
        );
        assert_eq!(
            r.ttl_ms, CLIENT_RESERVATION_MAX_TTL_MS,
            "the reported duration must be the applied one, not the requested one"
        );
        assert_ne!(r.ttl_ms, day_ms, "the request was echoed back unclamped");
    }

    #[tokio::test]
    async fn a_shorter_ttl_than_the_maximum_is_honoured_as_asked() {
        // The clamp must be a ceiling, not a flat override; otherwise the test above passes
        // against an implementation that ignores `ttl_ms` entirely.
        let db = two_coin_wallet().await;
        let r = db
            .reserve_client_coins(&["aa".into()], Some(30_000), NOW)
            .await
            .unwrap();
        assert_eq!(r.expires_at_ms, NOW + 30_000);
    }

    #[tokio::test]
    async fn the_default_lifetime_is_applied_when_none_is_asked_for() {
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;
        assert_eq!(r.expires_at_ms, NOW + CLIENT_RESERVATION_DEFAULT_TTL_MS);
    }

    // ---- the handle -------------------------------------------------------

    #[tokio::test]
    async fn reservation_handles_are_distinct_and_unpredictable() {
        // A handle a caller can derive lets it release a reservation it does not own, which is the
        // double-select reached through the front door.
        let db = two_coin_wallet().await;
        let a = hold(&db, &["aa"], NOW).await;
        let b = hold(&db, &["bb"], NOW).await;

        assert_ne!(a.reservation_id, b.reservation_id);
        assert_eq!(
            a.reservation_id.len(),
            64,
            "256 bits of handle, hex-encoded"
        );
        assert!(a.reservation_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            a.reservation_id.chars().any(|c| c != '0'),
            "an all-zero handle would mean the generator never ran"
        );
    }

    #[tokio::test]
    async fn releasing_one_hold_leaves_another_holder_coin_alone() {
        let db = two_coin_wallet().await;
        let a = hold(&db, &["aa"], NOW).await;
        let _b = hold(&db, &["bb"], NOW).await;

        db.release_client_reservation(&a.reservation_id)
            .await
            .unwrap();

        assert_eq!(
            selectable(&db).await,
            vec!["aa".to_string()],
            "releasing one handle must not free a coin held under a different one"
        );
    }

    // ---- the held set ------------------------------------------------------

    #[tokio::test]
    async fn the_held_set_reports_live_holds_and_omits_lapsed_ones() {
        let db = two_coin_wallet().await;
        let r = hold(&db, &["aa"], NOW).await;

        let live = db.held_reservations(NOW).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].coin_id, "aa");
        assert_eq!(live[0].reservation_id, r.reservation_id);
        assert_eq!(live[0].expires_at_ms, r.expires_at_ms);
        assert_eq!(live[0].phase, ReservationPhase::Lease);

        assert!(
            db.held_reservations(r.expires_at_ms)
                .await
                .unwrap()
                .is_empty(),
            "a lapsed hold must not be reported as live, or a caller waits for nothing"
        );
    }

    #[tokio::test]
    async fn the_held_set_reports_both_phases_under_one_namespace() {
        // A caller asked "may I spend this coin". Both phases answer no, so both must appear in
        // ONE answer. Reporting only the lease table would tell a client that a coin committed to
        // an already-pushed bundle is free — the exact double-select this serves to prevent, and
        // the failure a lease-only reader would produce while passing every test above.
        let db = two_coin_wallet().await;
        hold(&db, &["aa"], NOW).await;
        db.reserve_spend(&PendingTransactionRow {
            transaction_id: "tx-broadcast".into(),
            bundle_hex: "ff".into(),
            fee: None,
            submitted_at: NOW,
            expires_at: NOW + 600_000,
            attempts: 1,
            reserved_coin_ids: vec!["bb".into()],
        })
        .await
        .unwrap();

        let live = db.held_reservations(NOW).await.unwrap();
        let seen: Vec<(String, ReservationPhase)> =
            live.iter().map(|r| (r.coin_id.clone(), r.phase)).collect();
        assert_eq!(
            seen,
            vec![
                ("aa".to_string(), ReservationPhase::Lease),
                ("bb".to_string(), ReservationPhase::Broadcast),
            ],
            "both phases of one lifecycle belong in one held answer"
        );
    }

    #[tokio::test]
    async fn a_post_broadcast_hold_is_not_releasable_by_a_caller() {
        // The bundle may still be included. Freeing its inputs on request would invite a second
        // spend of a coin that is already committed, which is worse than the wait it saves.
        let db = two_coin_wallet().await;
        db.reserve_spend(&PendingTransactionRow {
            transaction_id: "tx-broadcast".into(),
            bundle_hex: "ff".into(),
            fee: None,
            submitted_at: NOW,
            expires_at: NOW + 600_000,
            attempts: 1,
            reserved_coin_ids: vec!["aa".into()],
        })
        .await
        .unwrap();

        let freed = db.release_client_reservation("tx-broadcast").await.unwrap();

        assert!(
            freed.is_empty(),
            "release must not reach a post-broadcast hold"
        );
        assert_eq!(
            selectable(&db).await,
            vec!["bb".to_string()],
            "the pushed bundle's input stayed held"
        );
    }
}

/// **Hex CASE is not part of a stored value's identity** (dig-node#298).
///
/// dig-node#293 normalised the two COIN IDENTITIES at the writer and deliberately left the three
/// SCOPING columns — `coins.puzzle_hash`, `coins.asset_id`, `coins.hint` — plus the two hex
/// columns keyed on elsewhere (`derivations.puzzle_hash`, `cats.asset_id`) storing whatever case
/// their source spelled. Every scoped reader binds a lower-cased value against them, so an
/// upper-case spelling made a coin invisible and reported the user a balance of ZERO.
///
/// # Why every writer gets its OWN test
///
/// `upsert_coin` and `upsert_coins` are two independent statements with two independent sets of
/// binds, and `attribute_cat_coin` is a third. #293's fix was very nearly shipped with one of its
/// binds unnormalised, because a fixture that varied SEVERAL fields at once stayed green when a
/// single bind was reverted — the other mismatched field kept the row invisible for the wrong
/// reason, and the assertion could not tell the two apart.
///
/// So each test below varies the case of EXACTLY ONE column and spells every other column
/// canonically. Reverting the normalisation on that one bind is then the only change that can
/// turn it red, which is what makes it a proof rather than a coincidence.
#[cfg(test)]
mod stored_hex_is_case_insensitive {
    use super::*;

    /// A lower-case 32-byte hex puzzle hash and a lower-case 32-byte asset id. Both are spelled
    /// canonically here; each test shouts exactly one of them at exactly one writer.
    const PH: &str = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";
    const ASSET: &str = "1234abcd5678ef901234abcd5678ef901234abcd5678ef901234abcd5678ef90";

    fn upper(s: &str) -> String {
        s.to_ascii_uppercase()
    }

    /// A confirmed, unspent coin — the only shape `balance_scoped` counts.
    fn spendable(id: &str, amount: u64) -> CoinRow {
        CoinRow {
            coin_id: id.into(),
            parent_coin_info: "00".repeat(32),
            puzzle_hash: PH.into(),
            amount: amount.to_string(),
            created_height: Some(10),
            spent_height: None,
            asset_id: None,
            hint: None,
            created_timestamp: None,
            spent_timestamp: None,
        }
    }

    // ---- `upsert_coin`: one test per bind ---------------------------------

    /// The headline failure: an XCH coin at a shouted puzzle hash reads as no money at all.
    #[tokio::test]
    async fn an_upper_case_puzzle_hash_still_counts_toward_the_xch_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 1_599_000_000_000);
        c.puzzle_hash = upper(PH);
        db.upsert_coin(&c).await.unwrap();

        assert_eq!(
            db.balance_scoped(None, &[PH.to_string()]).await.unwrap(),
            1_599_000_000_000,
            "a funded wallet read as empty because its puzzle hash was spelled in upper case"
        );
    }

    /// The asset bind alone: hint and puzzle hash are canonical, so only `asset_id = ?` can miss.
    #[tokio::test]
    async fn an_upper_case_asset_id_still_counts_toward_the_cat_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(upper(ASSET));
        c.hint = Some(PH.into());
        db.upsert_coin(&c).await.unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "a CAT balance read as zero because its asset id was spelled in upper case"
        );
    }

    /// The hint bind alone: the CAT scope column, with asset id and puzzle hash canonical.
    #[tokio::test]
    async fn an_upper_case_hint_still_counts_toward_the_cat_balance() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(ASSET.into());
        c.hint = Some(upper(PH));
        db.upsert_coin(&c).await.unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "a CAT balance read as zero because its owner hint was spelled in upper case"
        );
    }

    // ---- `upsert_coins`: the SAME three binds, in a different statement ----
    //
    // The batch writer is the one the subscription loop actually uses, and it repeats every bind
    // rather than delegating to the single-coin writer. Normalising one statement and not the
    // other is a live defect that the three tests above cannot see.

    #[tokio::test]
    async fn the_batch_writer_also_normalises_an_upper_case_puzzle_hash() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 4_200);
        c.puzzle_hash = upper(PH);
        db.upsert_coins(&[c]).await.unwrap();

        assert_eq!(
            db.balance_scoped(None, &[PH.to_string()]).await.unwrap(),
            4_200,
            "the batch writer stored a puzzle hash verbatim while the single writer normalised"
        );
    }

    #[tokio::test]
    async fn the_batch_writer_also_normalises_an_upper_case_asset_id() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(upper(ASSET));
        c.hint = Some(PH.into());
        db.upsert_coins(&[c]).await.unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "the batch writer stored an asset id verbatim while the single writer normalised"
        );
    }

    #[tokio::test]
    async fn the_batch_writer_also_normalises_an_upper_case_hint() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(ASSET.into());
        c.hint = Some(upper(PH));
        db.upsert_coins(&[c]).await.unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "the batch writer stored a hint verbatim while the single writer normalised"
        );
    }

    // ---- `attribute_cat_coin`: the sync loop's own two binds ---------------
    //
    // This is the path a CAT coin really acquires its asset id on: the coin lands unattributed,
    // and the uncurrying pass writes both columns afterwards. A fix confined to the two upsert
    // statements leaves this third writer storing verbatim.

    #[tokio::test]
    async fn cat_attribution_normalises_an_upper_case_asset_id() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&spendable("c1", 300)).await.unwrap();
        db.attribute_cat_coin("c1", &upper(ASSET), Some(PH))
            .await
            .unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "the CAT uncurrying pass stored its asset id verbatim"
        );
    }

    #[tokio::test]
    async fn cat_attribution_normalises_an_upper_case_hint() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_coin(&spendable("c1", 300)).await.unwrap();
        db.attribute_cat_coin("c1", ASSET, Some(&upper(PH)))
            .await
            .unwrap();

        assert_eq!(
            db.balance_scoped(Some(ASSET), &[PH.to_string()])
                .await
                .unwrap(),
            300,
            "the CAT uncurrying pass stored its owner hint verbatim"
        );
    }

    // ---- the two hex columns OUTSIDE `coins` ------------------------------

    /// `derivation_exists` is the `scoped_to_wallet` axis of the routing gate, so a false answer
    /// sends a read this replica could serve to a third-party oracle instead.
    #[tokio::test]
    async fn an_upper_case_derivation_puzzle_hash_is_still_recognised_as_ours() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_derivation(&DerivationRow {
            hardened: false,
            index: 0,
            public_key: "bb".repeat(48),
            puzzle_hash: upper(PH),
            address: "xch1example".into(),
        })
        .await
        .unwrap();

        assert!(
            db.derivation_exists(PH).await.unwrap(),
            "the wallet stopped recognising its own address because the row shouted it"
        );
    }

    /// `cats.asset_id` is a PRIMARY KEY, and `update_cat` writes it from a CALLER-SUPPLIED
    /// `TokenRecord` — so unlike the `coins` columns this one has a reachable non-canonical
    /// source in-tree today, with no third-party implementation required.
    #[tokio::test]
    async fn cat_metadata_written_under_an_upper_case_asset_id_is_still_found() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: upper(ASSET),
            name: Some("Test CAT".into()),
            ticker: Some("TST".into()),
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
        })
        .await
        .unwrap();

        assert_eq!(
            db.cat(ASSET).await.unwrap().and_then(|c| c.ticker),
            Some("TST".to_string()),
            "CAT metadata written under a shouted asset id became unreachable"
        );
    }

    #[tokio::test]
    async fn cat_metadata_updated_under_an_upper_case_asset_id_is_still_found() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.update_cat_metadata(&upper(ASSET), Some("Renamed"), None, None, None, true)
            .await
            .unwrap();

        assert_eq!(
            db.cat(ASSET).await.unwrap().and_then(|c| c.name),
            Some("Renamed".to_string()),
            "`update_cat` wrote a row that no canonical lookup can reach"
        );
    }

    /// The unscoped asset reader takes its asset id from the CALLER and bound it verbatim. Once
    /// the column is canonical, a caller that shouts must still be answered.
    #[tokio::test]
    async fn an_upper_case_asset_id_from_a_caller_still_reads_its_coins() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(ASSET.into());
        db.upsert_coin(&c).await.unwrap();

        assert_eq!(
            db.balance(Some(&upper(ASSET))).await.unwrap(),
            300,
            "a caller asking for its CAT in upper case was told it holds none"
        );
    }

    /// **CONTROL.** Every assertion above is also satisfied by a reader that ignores its scope
    /// and counts everything — which would be a far worse defect than the one being fixed, since
    /// it would report one wallet another wallet's money. This is the test that refuses that
    /// shortcut.
    #[tokio::test]
    async fn a_coin_at_a_genuinely_foreign_puzzle_hash_still_counts_for_nothing() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 1_599_000_000_000);
        c.puzzle_hash = "ff".repeat(32);
        db.upsert_coin(&c).await.unwrap();

        assert_eq!(
            db.balance_scoped(None, &[PH.to_string()]).await.unwrap(),
            0,
            "case-insensitivity was bought by making the scope match anything"
        );
    }

    // ---- the reader binds a CALLER supplies -------------------------------
    //
    // Normalising the writer is only half of a case-insensitive column. Every reader that takes
    // its key from the CALLER rather than from the scope list bound that key verbatim, so once
    // the column is canonical a caller that shouts is answered "not found" about a row that is
    // sitting right there. The tests above cannot see this: they all shout at the WRITER and then
    // read back canonically, which is exactly the direction a verbatim reader bind still gets
    // right. These three shout at the reader instead.

    #[tokio::test]
    async fn a_caller_asking_for_cat_metadata_in_upper_case_is_still_answered() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: ASSET.into(),
            name: Some("Test CAT".into()),
            ticker: Some("TST".into()),
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
        })
        .await
        .unwrap();

        assert_eq!(
            db.cat(&upper(ASSET)).await.unwrap().and_then(|c| c.ticker),
            Some("TST".to_string()),
            "a caller that spelled its asset id in upper case was told the CAT is unknown"
        );
    }

    #[tokio::test]
    async fn a_caller_clearing_cat_metadata_in_upper_case_still_clears_it() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.upsert_cat(&CatRow {
            asset_id: ASSET.into(),
            name: Some("Stale".into()),
            ticker: Some("TST".into()),
            precision: 3,
            description: None,
            icon_url: None,
            visible: true,
        })
        .await
        .unwrap();

        db.clear_cat_metadata(&upper(ASSET)).await.unwrap();

        assert_eq!(
            db.cat(ASSET).await.unwrap().and_then(|c| c.name),
            None,
            "`resync_cat` silently cleared nothing because the caller shouted the asset id"
        );
    }

    #[tokio::test]
    async fn a_caller_asking_whether_an_upper_case_asset_is_owned_is_still_answered() {
        let db = WalletDb::open_in_memory().await.unwrap();
        let mut c = spendable("c1", 300);
        c.asset_id = Some(ASSET.into());
        db.upsert_coin(&c).await.unwrap();

        assert!(
            db.is_asset_owned(&upper(ASSET)).await.unwrap(),
            "a held CAT reported as not owned because the caller shouted its asset id"
        );
    }

    // ---- rows already on disk (the ladder step) ---------------------------
    //
    // Fixing the writer does nothing for a replica that is already populated, and a wallet that
    // has been running is exactly the one holding the coins. Everything below drives the ladder
    // step over rows inserted PAST the normalising accessors, the way a pre-fix build wrote them.

    /// Insert past every normalising accessor, exactly as a pre-#298 build did.
    async fn insert_legacy(db: &WalletDb, sql: &str) {
        sqlx::query(sql).execute(&db.pool).await.unwrap();
    }

    /// Re-arm the ladder so the scoped-hex step runs again on an already-open database.
    async fn rearm(db: &WalletDb) {
        sqlx::query(&format!(
            "PRAGMA user_version = {}",
            SCOPED_HEX_STORED_LOWER_CASE - 1
        ))
        .execute(&db.pool)
        .await
        .unwrap();
    }

    async fn column(db: &WalletDb, sql: &str) -> Vec<String> {
        sqlx::query(sql)
            .fetch_all(&db.pool)
            .await
            .unwrap()
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect()
    }

    /// **A wallet written before the writer normalised is repaired on open, in EVERY column.**
    ///
    /// Asserted column by column rather than by a single balance read: a balance assertion is
    /// satisfied by normalising `coins` alone, and would leave `derivations`, `arrivals` and the
    /// two chain caches shouting — with `derivations` deciding whether a read routes to the local
    /// replica or to a third-party oracle, and `arrivals.puzzle_hash` shown to the user as the
    /// address a payment landed at.
    #[tokio::test]
    async fn a_legacy_database_has_every_scoped_hex_column_normalised_on_open() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy(
            &db,
            "INSERT INTO coins (coin_id, parent_coin_info, puzzle_hash, amount, created_height, \
             asset_id, hint) VALUES ('c1', 'pp', 'AABB', '300', 10, 'CCDD', 'EEFF')",
        )
        .await;
        insert_legacy(
            &db,
            "INSERT INTO derivations (hardened, idx, public_key, puzzle_hash, address) \
             VALUES (0, 0, 'pk', 'AABB', 'xch1x')",
        )
        .await;
        insert_legacy(
            &db,
            "INSERT INTO arrivals (coin_id, puzzle_hash, amount, asset_id, confirmed_height, \
             recorded_at) VALUES ('c1', 'AABB', '300', 'CCDD', 10, 0)",
        )
        .await;
        insert_legacy(
            &db,
            "INSERT INTO chain_read_cache (coin_id, parent_coin_info, puzzle_hash, amount, \
             cached_at, last_used_at) VALUES ('c1', 'pp', 'AABB', '300', 0, 0)",
        )
        .await;
        insert_legacy(
            &db,
            "INSERT INTO chain_spend_cache (coin_id, parent_coin_info, puzzle_hash, amount, \
             puzzle_reveal, solution) VALUES ('c1', 'pp', 'AABB', '300', 'ff', 'ff')",
        )
        .await;
        rearm(&db).await;

        db.migrate().await.unwrap();

        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM coins").await,
            vec!["aabb".to_string()],
            "coins.puzzle_hash"
        );
        assert_eq!(
            column(&db, "SELECT asset_id FROM coins").await,
            vec!["ccdd".to_string()],
            "coins.asset_id"
        );
        assert_eq!(
            column(&db, "SELECT hint FROM coins").await,
            vec!["eeff".to_string()],
            "coins.hint"
        );
        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM derivations").await,
            vec!["aabb".to_string()],
            "derivations.puzzle_hash"
        );
        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM arrivals").await,
            vec!["aabb".to_string()],
            "arrivals.puzzle_hash"
        );
        assert_eq!(
            column(&db, "SELECT asset_id FROM arrivals").await,
            vec!["ccdd".to_string()],
            "arrivals.asset_id"
        );
        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM chain_read_cache").await,
            vec!["aabb".to_string()],
            "chain_read_cache.puzzle_hash"
        );
        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM chain_spend_cache").await,
            vec!["aabb".to_string()],
            "chain_spend_cache.puzzle_hash"
        );
    }

    /// **A NULL asset id or hint survives the migration as NULL.**
    ///
    /// `asset_id IS NULL` is how an XCH coin is told from a CAT coin, so a migration that
    /// coerced NULL to the empty string would reclassify every XCH coin the user holds — a
    /// larger balance failure than the one being fixed. `<> LOWER(col)` is NULL-safe, and this
    /// test is what says so out loud.
    #[tokio::test]
    async fn the_migration_leaves_a_null_asset_id_and_hint_null() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy(
            &db,
            "INSERT INTO coins (coin_id, parent_coin_info, puzzle_hash, amount, created_height) \
             VALUES ('c1', 'pp', 'AABB', '300', 10)",
        )
        .await;
        rearm(&db).await;

        db.migrate().await.unwrap();

        assert_eq!(
            db.balance_scoped(None, &["aabb".to_string()])
                .await
                .unwrap(),
            300,
            "a legacy XCH coin stopped being XCH, or stopped being found"
        );
    }

    /// **Two case spellings of one CAT do not brick the wallet, and lose no metadata.**
    ///
    /// `cats.asset_id` is a `PRIMARY KEY`, so lower-casing two spellings into each other is a
    /// uniqueness violation that aborts the step — and because the retry on the next open is
    /// byte-for-byte identical, an aborted step means `WalletDb::open` returns `Err` FOREVER.
    /// That is the failure dig-node#293's first version shipped.
    ///
    /// The `coins` rule of "delete the losers" is deliberately NOT reused here. It is justified
    /// there by the table being derived from chain state, so a dropped row is re-observed on the
    /// next sync. A `cats` row is not: its name, ticker, icon and visibility come from a token
    /// registry or from the user, and nothing on chain would put them back. So the losers are
    /// MERGED into the survivor first.
    #[tokio::test]
    async fn colliding_cat_spellings_neither_brick_the_wallet_nor_lose_metadata() {
        let db = WalletDb::open_in_memory().await.unwrap();
        insert_legacy(
            &db,
            "INSERT INTO cats (asset_id, name, ticker, precision, visible) \
             VALUES ('aabb', 'Canonical', NULL, 3, 1)",
        )
        .await;
        insert_legacy(
            &db,
            "INSERT INTO cats (asset_id, name, ticker, precision, visible) \
             VALUES ('AABB', 'Shouted', 'TST', 3, 1)",
        )
        .await;
        rearm(&db).await;

        db.migrate()
            .await
            .expect("a case collision on the CAT primary key must not fail the migration");

        let cat = db.cat("aabb").await.unwrap().expect("the CAT survived");
        assert_eq!(
            cat.name.as_deref(),
            Some("Canonical"),
            "the ALREADY-CANONICAL spelling is the one that survives"
        );
        assert_eq!(
            cat.ticker.as_deref(),
            Some("TST"),
            "the loser's ticker was DROPPED rather than merged; nothing on chain restores it"
        );
        assert_eq!(
            column(&db, "SELECT asset_id FROM cats").await,
            vec!["aabb".to_string()],
            "the collided spellings were reduced to exactly one canonical row"
        );
    }

    /// **Several NON-canonical spellings also do not brick the wallet.**
    ///
    /// The case a two-spelling collision rule cannot see: `AAbb` and `aAbb` are both unequal to
    /// their own lower-casing, so a fix scoped to "rows whose lower-casing already exists"
    /// removes neither, and the `UPDATE` then collides them onto one key. The collision group
    /// must be the COMPLETE lower-value equivalence class, so the update has nothing left to
    /// collide with.
    #[tokio::test]
    async fn many_non_canonical_cat_spellings_do_not_brick_the_wallet() {
        let db = WalletDb::open_in_memory().await.unwrap();
        for (spelling, name) in [("AAbb", "first"), ("aAbb", "second"), ("AAbB", "third")] {
            insert_legacy(
                &db,
                &format!(
                    "INSERT INTO cats (asset_id, name, precision, visible) \
                     VALUES ('{spelling}', '{name}', 3, 1)"
                ),
            )
            .await;
        }
        rearm(&db).await;

        db.migrate()
            .await
            .expect("a three-way collision between non-canonical spellings must not fail");

        assert_eq!(
            column(&db, "SELECT asset_id FROM cats").await,
            vec!["aabb".to_string()],
            "three spellings were not reduced to one canonical row"
        );
        assert_eq!(
            db.cat("aabb")
                .await
                .unwrap()
                .and_then(|c| c.name)
                .as_deref(),
            Some("third"),
            "with no canonical spelling present the survivor is the lexicographically smallest \
             by BYTE, which puts `AAbB` ahead of `AAbb` because upper-case sorts first. That \
             choice is arbitrary; being TOTAL and DETERMINISTIC is the whole of the point"
        );
    }

    /// **The ladder mark stops the step running again.**
    ///
    /// A data migration reads and rewrites rows, so re-running it on every open is unbounded work
    /// on a hot path for a job that only ever needs doing once.
    #[tokio::test]
    async fn the_ladder_mark_stops_the_scoped_hex_step_running_again() {
        let db = WalletDb::open_in_memory().await.unwrap();
        db.migrate().await.unwrap();
        insert_legacy(
            &db,
            "INSERT INTO coins (coin_id, parent_coin_info, puzzle_hash, amount, created_height) \
             VALUES ('c1', 'pp', 'AABB', '300', 10)",
        )
        .await;

        db.migrate().await.unwrap();

        assert_eq!(
            column(&db, "SELECT puzzle_hash FROM coins").await,
            vec!["AABB".to_string()],
            "the step ran a second time on an already-marked database"
        );
    }
}
