//! The **tipping subsystem** (#378, child of the auto-tip epic #377).
//!
//! The dig-node OWNS tipping: it holds the wallet/keys and builds+signs+broadcasts the $DIG
//! spend. The extension (#379/#380) only CONFIGURES + DISPLAYS it over the WS wallet/control
//! transport (SPEC §4.8). This module is the node-side engine:
//!
//! - **Owner-PH lookup** — resolve a store's on-chain OWNER puzzle hash from its singleton
//!   (the launcher id), cached per store ([`OwnerResolver`]).
//! - **Auto-tip policy engine** — a persisted [`TippingConfig`] (creator + dev-account policies)
//!   with HARD budget caps (per-site/day AND a daily total) enforced FAIL-CLOSED, and
//!   idempotency per `(site, day)` so a crash+retry never double-tips ([`TippingEngine`]).
//! - **Creator auto-tip is DEFAULT-ON** (a real on-chain-resolved recipient always exists).
//! - **DIG dev-account daily tip** — the SAME engine, a SEPARATE toggle. Recipient = the canonical
//!   DIG treasury inner puzzle hash (the existing per-capsule-payment shared contract, sourced from
//!   `digstore_chain::dig::treasury_inner_puzzle_hash()` via `dig_treasury_ph_hex`, never
//!   re-hardcoded). A REAL recipient, so it is DEFAULT-ON with a small daily amount + the same caps.
//! - **Unattended execution** — when enabled + within budget the engine builds+signs+broadcasts
//!   with NO user interaction, and skips cleanly when disabled/over-budget/already-tipped.
//! - **On-demand manual tip** — one-tap tip to a store's owner (explicit user consent; not
//!   bounded by the auto caps, not subject to the once-per-day idempotency).
//! - **Tip ledger** — every reservation/tip is recorded (`recipient / amount / ts / txid /
//!   auto|manual / creator|dev / status`), persisted, exposed via `get_ledger`, and PUSHED over
//!   the WS wallet/control surface via a dedicated [`TipEventBus`] (kept OUT of the Sage-parity
//!   `SyncEvent` union, [`super::events`]).
//!
//! ## Money-safety design (real mainnet $DIG)
//!
//! The engine is the single authorization+consent gate for a tip. Two properties are enforced
//! FAIL-CLOSED — a bug skips the tip, never over-spends:
//!
//! 1. **Hard caps** — a per-site/day cap AND a daily total cap (spanning creator + dev). Reserved
//!    (pending), confirmed, AND ambiguous-failed amounts all count toward the caps, so an
//!    in-flight or unknown-outcome tip can never be double-counted into an over-spend.
//! 2. **Crash-safe idempotency** — the ledger reservation (a `Pending` entry) is persisted to disk
//!    IMMEDIATELY BEFORE the broadcast; the broadcast is the only money-moving step. So a crash at
//!    ANY point leaves at most one reserved entry for a `(site, day)`, and on restart the engine
//!    (re-loaded from the ledger file) treats that `(site, day)` as already tipped and SKIPS — it
//!    errs toward under-tipping, never a double-spend. A definitively PRE-broadcast failure
//!    (locked wallet / not-yet-synced / insufficient $DIG — [`TipSpendOutcome::NotExecutable`])
//!    rolls the reservation back so it can retry later; an AMBIGUOUS broadcast error keeps the
//!    reservation (as `Failed`) so it is never retried that day.
//!
//! Broadcasting goes through the [`TipSpender`] seam. Tests inject a recording mock (or drive the
//! `chia-sdk-test` simulator via the underlying [`super::spend`] builders) — a real mainnet
//! broadcast is NEVER reached from a test.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};

use super::{Error, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Dev-account recipient — the existing canonical DIG treasury shared contract
// ─────────────────────────────────────────────────────────────────────────────

/// The DIG treasury / dev-fee recipient the dev-account daily tip pays: the SAME canonical
/// shared-contract puzzle hash that receives every per-capsule $DIG payment
/// (`digstore_chain::dig::treasury_inner_puzzle_hash()`, decoded from `TREASURY_ADDRESS`
/// `xch1a37rq3cgcl2ecpudttsf35x75qzdan68lgw2l6ajvmqs44jxdn5qv6pk3y` =
/// `ec7c304708c7d59c078d5ae098d0dea004decf47fa1cafebb266c10ad6466ce8`; mirrored byte-identical in
/// chip35 + dighub-core). It is a REAL recipient, so the dev-account daily tip is DEFAULT-ON (#377)
/// with the same hard caps as creator tips. Sourced from the shared contract — NEVER re-hardcoded
/// here — so a payment-critical value can't drift into a 4th copy. The tip's CAT spend targets this
/// inner PH exactly as the per-capsule payment does (`Cat::spend_all` CAT-wraps it).
fn dig_treasury_ph_hex() -> String {
    hex::encode(digstore_chain::dig::treasury_inner_puzzle_hash())
}

// ─────────────────────────────────────────────────────────────────────────────
// Sensible small default amounts ($DIG has 3 decimals — 1 DIG = 1000 base units)
// ─────────────────────────────────────────────────────────────────────────────

/// Base units per whole $DIG (`digstore_chain::dig::DIG_DECIMALS == 3`).
pub const DIG_BASE_UNITS: u64 = 1_000;

/// Default creator tip per site/day = 0.1 $DIG.
pub const DEFAULT_CREATOR_TIP: u64 = DIG_BASE_UNITS / 10;
/// Default per-site/day cap for creator tips = 0.1 $DIG.
pub const DEFAULT_PER_SITE_CAP: u64 = DIG_BASE_UNITS / 10;
/// Default daily TOTAL cap across ALL auto tips (creator + dev) = 1 $DIG.
pub const DEFAULT_DAILY_TOTAL_CAP: u64 = DIG_BASE_UNITS;
/// Default dev-account daily tip = 0.1 $DIG.
pub const DEFAULT_DEV_TIP: u64 = DIG_BASE_UNITS / 10;
/// Default XCH fee per tip spend (0 — a low-priority tip needs no fee at normal congestion; the
/// user can raise it in config).
pub const DEFAULT_TIP_FEE: u64 = 0;

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

/// How an auto-tip policy meters spending across a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TipMode {
    /// Tip each consumed site at most once per day, `dig_amount` each, bounded by the per-site
    /// cap AND the daily total cap.
    PerSitePerDay,
    /// A single daily budget pool: tip each consumed site once per day drawing from the pool
    /// until the daily total cap is exhausted (the per-site cap is not separately enforced).
    DailyBudget,
}

/// One auto-tip policy (creator OR dev). The two share the top-level [`TippingConfig::daily_total_cap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTipPolicy {
    /// Whether this policy tips automatically (unattended).
    pub enabled: bool,
    /// The tip amount per site/day, in $DIG base units.
    pub dig_amount: u64,
    /// How the policy meters spend across a day.
    pub mode: TipMode,
    /// The hard per-site/day ceiling in base units (enforced in [`TipMode::PerSitePerDay`]).
    pub per_site_cap: u64,
    /// Per-site amount overrides (site key = owner puzzle-hash hex → base units).
    #[serde(default)]
    pub per_site_overrides: HashMap<String, u64>,
}

/// The persisted tipping configuration. Both creator AND dev-account auto-tip are DEFAULT-ON (#377):
/// each has a real recipient — the creator's is the on-chain-resolved store owner PH, the
/// dev-account's is the existing DIG treasury inner PH shared contract
/// (`digstore_chain::dig::treasury_inner_puzzle_hash()`), never a placeholder. Safe out of the box
/// paired with the honest-default disclosure + one-click-off (§6.0, #207).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TippingConfig {
    /// Creator auto-tip (pays the on-chain-resolved store owner).
    pub creator: AutoTipPolicy,
    /// DIG dev-account daily tip (pays the DIG treasury shared contract, `dig_treasury_ph_hex`).
    pub dev: AutoTipPolicy,
    /// The HARD daily total cap in base units, spanning creator + dev auto tips.
    pub daily_total_cap: u64,
    /// The XCH fee applied to each tip spend.
    pub fee: u64,
}

impl Default for TippingConfig {
    fn default() -> Self {
        Self {
            creator: AutoTipPolicy {
                enabled: true, // DEFAULT-ON (#377): a real on-chain recipient always exists.
                dig_amount: DEFAULT_CREATOR_TIP,
                mode: TipMode::PerSitePerDay,
                per_site_cap: DEFAULT_PER_SITE_CAP,
                per_site_overrides: HashMap::new(),
            },
            dev: AutoTipPolicy {
                // DEFAULT-ON (#377): the recipient is the REAL DIG treasury shared contract, so a
                // small daily "support DIG itself" tip is safe out of the box (hard caps + ledger).
                enabled: true,
                dig_amount: DEFAULT_DEV_TIP,
                mode: TipMode::PerSitePerDay,
                per_site_cap: DEFAULT_DEV_TIP,
                per_site_overrides: HashMap::new(),
            },
            daily_total_cap: DEFAULT_DAILY_TOTAL_CAP,
            fee: DEFAULT_TIP_FEE,
        }
    }
}

impl TippingConfig {
    /// The FAIL-CLOSED config: both policies DISABLED. Used when the persisted config is present
    /// but unreadable — a corrupt/locked config file must NEVER silently fall back to the
    /// DEFAULT-ON config (which would move real $DIG against a user who had disabled auto-tip).
    fn disabled() -> Self {
        let mut c = Self::default();
        c.creator.enabled = false;
        c.dev.enabled = false;
        c
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ledger
// ─────────────────────────────────────────────────────────────────────────────

/// Which policy a ledger entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipKind {
    /// A tip to a content creator (store owner).
    Creator,
    /// A tip to the DIG dev account.
    Dev,
}

/// Whether a tip was fired by the auto policy or by an explicit user tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipTrigger {
    /// Unattended auto-tip (governed by caps + idempotency).
    Auto,
    /// Explicit one-tap manual tip (user consent; not bounded by the auto caps/idempotency).
    Manual,
}

/// The lifecycle status of a ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipStatus {
    /// Reserved before broadcast (money may or may not have moved). Counts toward caps + blocks a
    /// same-day retry — the crash-safety reservation.
    Pending,
    /// The broadcast was accepted by the network. `txid` is set.
    Confirmed,
    /// An AMBIGUOUS broadcast failure (the tx may have entered a mempool). Kept, counts toward
    /// caps, and is NOT retried that day (fail-closed — never double-spend).
    Failed,
}

/// One tip ledger entry (`recipient / amount / ts / txid / auto|manual / creator|dev / status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipLedgerEntry {
    /// A stable, monotonically-increasing id (the extension can key rows by it).
    pub id: u64,
    /// The recipient puzzle hash (lowercase hex, no `0x`).
    pub recipient_ph: String,
    /// The store the tip was for (launcher-id hex); `None` for a dev-account tip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    /// The tip amount in $DIG base units.
    pub dig_amount: u64,
    /// Unix seconds when the entry was reserved.
    pub ts: u64,
    /// The UTC day bucket (`YYYY-MM-DD`) — the idempotency key alongside `recipient_ph`/`kind`.
    pub day: String,
    /// The broadcast transaction id (spend-bundle name hex); `None` until confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Auto vs manual.
    pub trigger: TipTrigger,
    /// Creator vs dev.
    pub kind: TipKind,
    /// The lifecycle status.
    pub status: TipStatus,
}

/// The result of a tip decision — either a tip happened or it was skipped (with a machine-stable
/// reason so the extension can render "already tipped today", "over budget", etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum TipOutcome {
    /// A tip was built, signed, and broadcast. Money moved.
    Tipped {
        /// The broadcast transaction id.
        txid: String,
        /// The amount tipped, in base units.
        dig_amount: u64,
        /// The recipient puzzle hash (hex).
        recipient_ph: String,
    },
    /// No tip happened. `reason` is a stable machine token.
    Skipped {
        /// Why the tip was skipped.
        reason: String,
    },
}

impl TipOutcome {
    fn skipped(reason: impl Into<String>) -> Self {
        TipOutcome::Skipped {
            reason: reason.into(),
        }
    }
}

/// The outcome of the wallet's attempt to build+broadcast a tip spend (the [`TipSpender`] result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TipSpendOutcome {
    /// The spend was built, signed, validated, and BROADCAST. Money moved. `txid` = bundle name.
    Broadcast {
        /// The broadcast transaction id (spend-bundle name hex).
        txid: String,
        /// Whether the spend was CONFIRMED on-chain within the confirmer's window (§18.12). `true`
        /// ⇒ a block included it (ledger status `Confirmed`); `false` ⇒ accepted into the mempool
        /// but not yet confirmed (ledger status `Pending`, txid set — money moved, confirmation is
        /// asynchronous, and the reservation blocks a same-day retry either way).
        confirmed: bool,
    },
    /// The wallet cannot currently build/broadcast the tip (locked / not-yet-synced / no lineage /
    /// insufficient $DIG). Definitively PRE-broadcast — no money moved; the caller may retry later.
    NotExecutable {
        /// A human-readable reason.
        reason: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Seams (traits) — injected so the money-safety logic is testable without a chain
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves a store's on-chain OWNER puzzle hash from its singleton (launcher id).
#[async_trait]
pub trait OwnerResolver: Send + Sync {
    /// Return the owner puzzle hash (lowercase hex, no `0x`) of the store `store_id_hex`
    /// (launcher-id hex), or `None` when the store singleton cannot be found on chain.
    async fn resolve_owner(&self, store_id_hex: &str) -> Result<Option<String>>;
}

/// Builds+signs+validates+broadcasts a $DIG tip. The ONLY component that moves money.
///
/// Every caller has already enforced enabled + caps + idempotency (and the fail-closed
/// unreadable-state guard); the ledger reservation is persisted BEFORE this is invoked
/// (crash-safety). The contract:
/// `Ok(Broadcast)` = accepted by the network; `Ok(NotExecutable)` = definitively pre-broadcast
/// (safe to retry); `Err` = an AMBIGUOUS broadcast failure (the engine keeps the reservation and
/// does not retry that day — fail-closed).
#[async_trait]
pub trait TipSpender: Send + Sync {
    /// Send `amount` base units of $DIG to `recipient_ph_hex` with an XCH `fee`.
    async fn send_dig_tip(
        &self,
        recipient_ph_hex: &str,
        amount: u64,
        fee: u64,
    ) -> Result<TipSpendOutcome>;
}

/// A wall clock (injected so tests can pin "today").
pub trait Clock: Send + Sync {
    /// Current unix time in seconds.
    fn now_unix(&self) -> u64;
    /// Today's UTC date as `YYYY-MM-DD` (the idempotency day bucket).
    fn today_utc(&self) -> String {
        unix_to_utc_date(self.now_unix())
    }
}

/// The production system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Convert unix seconds to a UTC `YYYY-MM-DD` string (Howard Hinnant's civil-from-days algorithm —
/// dependency-free, so the day boundary needs no `chrono`).
fn unix_to_utc_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64; // days since 1970-01-01 (UTC)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tip event bus (WS push) — SEPARATE from the Sage-parity SyncEvent union
// ─────────────────────────────────────────────────────────────────────────────

/// A tip event pushed to connected WS clients when a tip is recorded (SPEC §4.8 `{type:"tip"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipEvent {
    /// The recorded ledger entry.
    pub entry: TipLedgerEntry,
}

/// An in-process publish/subscribe bus for [`TipEvent`]s. Deliberately DISTINCT from the
/// Sage-parity [`super::events::EventBus`] so DIG-specific tip events never leak into the
/// byte-parity Sage `SyncEvent` stream (`GET /events`). Cheap to clone; a publish with no
/// subscribers is a harmless no-op.
#[derive(Clone)]
pub struct TipEventBus {
    tx: broadcast::Sender<TipEvent>,
}

impl TipEventBus {
    /// A bus with the given per-subscriber buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }
    /// Publish to every current subscriber (no-op with no listeners).
    pub fn publish(&self, event: TipEvent) {
        let _ = self.tx.send(event);
    }
    /// Subscribe to future tip events.
    pub fn subscribe(&self) -> broadcast::Receiver<TipEvent> {
        self.tx.subscribe()
    }
    /// The current subscriber count (test/diagnostic).
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for TipEventBus {
    fn default() -> Self {
        Self::with_capacity(64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

/// The in-memory config + ledger, guarded as one unit so idempotency + cap checks and the
/// reservation write are atomic.
#[derive(Debug, Default)]
struct TippingState {
    config: TippingConfig,
    ledger: Vec<TipLedgerEntry>,
    next_id: u64,
}

impl TippingState {
    /// Sum of the amounts of all reserved/attempted AUTO entries on `day` (any kind) — the daily
    /// total cap basis. Pending/Confirmed/Failed all count (fail-closed).
    fn auto_spent_today(&self, day: &str) -> u64 {
        self.ledger
            .iter()
            .filter(|e| e.trigger == TipTrigger::Auto && e.day == day)
            .map(|e| e.dig_amount)
            .fold(0, u64::saturating_add)
    }

    /// Sum of reserved/attempted AUTO amounts for one `(kind, recipient, day)` — the per-site cap
    /// basis.
    fn auto_site_spent_today(&self, kind: TipKind, recipient: &str, day: &str) -> u64 {
        self.ledger
            .iter()
            .filter(|e| {
                e.trigger == TipTrigger::Auto
                    && e.kind == kind
                    && e.recipient_ph == recipient
                    && e.day == day
            })
            .map(|e| e.dig_amount)
            .fold(0, u64::saturating_add)
    }

    /// Whether an AUTO tip for `(kind, recipient, day)` has already been reserved/attempted (the
    /// once-per-site-per-day idempotency invariant).
    fn auto_already_reserved(&self, kind: TipKind, recipient: &str, day: &str) -> bool {
        self.ledger.iter().any(|e| {
            e.trigger == TipTrigger::Auto
                && e.kind == kind
                && e.recipient_ph == recipient
                && e.day == day
        })
    }

    /// Push a reservation and return its id.
    fn reserve(&mut self, mut entry: TipLedgerEntry) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;
        self.ledger.push(entry);
        id
    }

    fn entry_mut(&mut self, id: u64) -> Option<&mut TipLedgerEntry> {
        self.ledger.iter_mut().find(|e| e.id == id)
    }

    fn remove(&mut self, id: u64) {
        self.ledger.retain(|e| e.id != id);
    }
}

/// The persisted-on-disk ledger shape (a versioned wrapper so future fields are additive).
#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerFile {
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    entries: Vec<TipLedgerEntry>,
}

/// The node-side tipping engine (SPEC §18.23). Owns the persisted config + ledger, the owner
/// resolver (cached per store), the tip spender, and the tip-event bus.
pub struct TippingEngine {
    config_path: PathBuf,
    ledger_path: PathBuf,
    state: Mutex<TippingState>,
    owner: Box<dyn OwnerResolver>,
    spender: Box<dyn TipSpender>,
    clock: Box<dyn Clock>,
    events: std::sync::Arc<TipEventBus>,
    owner_cache: Mutex<HashMap<String, String>>,
    /// FAIL-CLOSED poison: `Some(reason)` when the persisted config OR ledger was present on disk
    /// but could not be read/parsed at load. A money ledger that can't be read MUST NEVER degrade
    /// to "empty → tip freely" (that would reset the cap + idempotency accounting and re-tip the
    /// full daily budget on every restart, double-spending sites already tipped). While poisoned,
    /// EVERY tip (auto + manual) and config mutation is REFUSED until the operator resolves the
    /// file and restarts. Set only at [`Self::load`]; immutable thereafter (no lock needed).
    poison: Option<String>,
}

impl TippingEngine {
    /// Load the engine from `<config_dir>` (reading `tipping-config.json` + `tip-ledger.json`),
    /// wiring the owner resolver, tip spender, clock, and tip-event bus.
    ///
    /// FAIL-CLOSED distinction: a file that is ABSENT is a genuine first run (config → DEFAULT-ON,
    /// ledger → empty). A file that is PRESENT but unreadable/unparseable POISONS the engine — the
    /// config falls back to DISABLED (never re-enables auto-tip) and every tip/mutation is refused
    /// until the operator resolves it. A transiently-locked or corrupt/truncated ledger can thus
    /// never silently reset the caps + idempotency accounting.
    pub fn load(
        config_dir: &Path,
        owner: Box<dyn OwnerResolver>,
        spender: Box<dyn TipSpender>,
        clock: Box<dyn Clock>,
        events: std::sync::Arc<TipEventBus>,
    ) -> Self {
        let config_path = config_dir.join("tipping-config.json");
        let ledger_path = config_dir.join("tip-ledger.json");
        let mut poison: Option<String> = None;

        // Config: absent → DEFAULT-ON (genuine first run). Present-but-unreadable → FAIL CLOSED
        // (DISABLED) + poison, so a corrupt config never silently re-enables auto-tip.
        let config = match read_json_strict::<TippingConfig>(&config_path) {
            Ok(Some(c)) => c,
            Ok(None) => TippingConfig::default(),
            Err(e) => {
                eprintln!(
                    "dig-node: WARN tipping config present but unreadable — auto-tip DISABLED \
                     (fail-closed) until resolved: {e}"
                );
                add_poison(&mut poison, format!("config unreadable: {e}"));
                TippingConfig::disabled()
            }
        };

        // Ledger: absent → empty (first run). Present-but-unreadable → FAIL CLOSED + poison, so the
        // caps + idempotency accounting can NEVER reset to "empty → tip freely".
        let (ledger, next_id) = match read_json_strict::<LedgerFile>(&ledger_path) {
            Ok(Some(f)) => {
                let next_id = f
                    .entries
                    .iter()
                    .map(|e| e.id + 1)
                    .chain(std::iter::once(f.next_id))
                    .max()
                    .unwrap_or(0);
                (f.entries, next_id)
            }
            Ok(None) => (Vec::new(), 0),
            Err(e) => {
                eprintln!(
                    "dig-node: WARN tip ledger present but unreadable — ALL tips REFUSED \
                     (fail-closed) until resolved: {e}"
                );
                add_poison(&mut poison, format!("ledger unreadable: {e}"));
                (Vec::new(), 0)
            }
        };

        let state = TippingState {
            config,
            ledger,
            next_id,
        };
        Self {
            config_path,
            ledger_path,
            state: Mutex::new(state),
            owner,
            spender,
            clock,
            events,
            owner_cache: Mutex::new(HashMap::new()),
            poison,
        }
    }

    /// If the engine is poisoned (unreadable persisted state at load), the machine-stable skip
    /// reason; else `None`. Every spend/mutation path consults this FIRST and fails closed.
    fn poisoned(&self) -> Option<TipOutcome> {
        self.poison
            .as_ref()
            .map(|r| TipOutcome::skipped(format!("state-unreadable: {r}")))
    }

    /// The tip-event bus WS sessions subscribe to (SPEC §4.8 `{type:"tip"}` push).
    pub fn events(&self) -> &std::sync::Arc<TipEventBus> {
        &self.events
    }

    /// The current tipping configuration.
    pub async fn get_config(&self) -> TippingConfig {
        self.state.lock().await.config.clone()
    }

    /// Replace + persist the tipping configuration. REFUSED while poisoned — writing a fresh config
    /// over an unreadable persisted state would mask the problem (and could clobber a ledger whose
    /// contents we could not read); the operator must resolve the file and restart.
    pub async fn set_config(&self, config: TippingConfig) -> Result<()> {
        if let Some(reason) = &self.poison {
            return Err(Error::internal(format!(
                "tipping state is unreadable ({reason}); resolve the file and restart before \
                 changing config"
            )));
        }
        let mut st = self.state.lock().await;
        st.config = config;
        write_json(&self.config_path, &st.config)
    }

    /// The tip ledger, newest first. `since_ts` (unix seconds) optionally filters older entries.
    pub async fn get_ledger(&self, since_ts: Option<u64>) -> Vec<TipLedgerEntry> {
        let st = self.state.lock().await;
        let mut out: Vec<TipLedgerEntry> = st
            .ledger
            .iter()
            .filter(|e| match since_ts {
                Some(t) => e.ts >= t,
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| b.ts.cmp(&a.ts).then(b.id.cmp(&a.id)));
        out
    }

    /// Resolve `store_id_hex`'s owner puzzle hash (hex), caching the result per store.
    async fn resolve_owner_cached(&self, store_id_hex: &str) -> Result<Option<String>> {
        let key = normalize_hex(store_id_hex);
        if let Some(ph) = self.owner_cache.lock().await.get(&key).cloned() {
            return Ok(Some(ph));
        }
        match self.owner.resolve_owner(&key).await? {
            Some(ph) => {
                let ph = normalize_hex(&ph);
                self.owner_cache.lock().await.insert(key, ph.clone());
                Ok(Some(ph))
            }
            None => Ok(None),
        }
    }

    /// Run the CREATOR auto-tip for a consumed store. Resolves the owner, then tips per the creator
    /// policy — idempotent per `(owner, day)`, fail-closed on the per-site + daily caps. A no-op
    /// (clean `Skipped`) when disabled / over-budget / already-tipped / owner-unresolvable.
    pub async fn auto_tip_for_store(&self, store_id_hex: &str) -> Result<TipOutcome> {
        // FAIL CLOSED: unreadable persisted state → refuse (never re-tip a possibly-already-tipped
        // site with a reset ledger).
        if let Some(skip) = self.poisoned() {
            return Ok(skip);
        }
        let (enabled, amount, per_site_cap, mode, daily_total_cap) = {
            let st = self.state.lock().await;
            let c = &st.config.creator;
            (
                c.enabled,
                c.dig_amount,
                c.per_site_cap,
                c.mode,
                st.config.daily_total_cap,
            )
        };
        if !enabled {
            return Ok(TipOutcome::skipped("disabled"));
        }
        let Some(owner) = self
            .resolve_owner_cached(store_id_hex)
            .await
            .unwrap_or(None)
        else {
            return Ok(TipOutcome::skipped("owner-unresolved"));
        };
        let amount = {
            let st = self.state.lock().await;
            *st.config
                .creator
                .per_site_overrides
                .get(&owner)
                .unwrap_or(&amount)
        };
        self.reserve_and_spend(ReserveArgs {
            kind: TipKind::Creator,
            trigger: TipTrigger::Auto,
            recipient: owner,
            store_id: Some(normalize_hex(store_id_hex)),
            amount,
            per_site_cap,
            mode,
            daily_total_cap,
        })
        .await
    }

    /// Run the DIG dev-account daily tip — the "support DIG itself" contribution. Recipient = the
    /// canonical DIG treasury shared contract (`dig_treasury_ph_hex`); idempotent per day, bounded
    /// by the daily total cap. A no-op when disabled / over-budget / already-tipped-today, and
    /// fail-closed while the persisted state is unreadable.
    pub async fn dev_daily_tip(&self) -> Result<TipOutcome> {
        if let Some(skip) = self.poisoned() {
            return Ok(skip);
        }
        let (enabled, amount, mode, daily_total_cap) = {
            let st = self.state.lock().await;
            let d = &st.config.dev;
            (d.enabled, d.dig_amount, d.mode, st.config.daily_total_cap)
        };
        if !enabled {
            return Ok(TipOutcome::skipped("disabled"));
        }
        self.reserve_and_spend(ReserveArgs {
            kind: TipKind::Dev,
            trigger: TipTrigger::Auto,
            recipient: dig_treasury_ph_hex(),
            store_id: None,
            amount,
            per_site_cap: u64::MAX, // the dev tip is bounded only by the daily total cap.
            mode,
            daily_total_cap,
        })
        .await
    }

    /// A one-tap MANUAL tip to a store's owner. Explicit user consent: NOT bounded by the auto
    /// caps and NOT subject to the once-per-day idempotency (a user may tip repeatedly). Still
    /// recorded + crash-safe (reservation before broadcast).
    pub async fn manual_tip(&self, store_id_hex: &str) -> Result<TipOutcome> {
        // FAIL CLOSED even for a manual tip: an unreadable ledger means we can't safely append
        // (we'd clobber entries we couldn't read); refuse until resolved.
        if let Some(skip) = self.poisoned() {
            return Ok(skip);
        }
        let Some(owner) = self
            .resolve_owner_cached(store_id_hex)
            .await
            .unwrap_or(None)
        else {
            return Ok(TipOutcome::skipped("owner-unresolved"));
        };
        let (amount, fee) = {
            let st = self.state.lock().await;
            (st.config.creator.dig_amount, st.config.fee)
        };
        let amount = {
            let st = self.state.lock().await;
            *st.config
                .creator
                .per_site_overrides
                .get(&owner)
                .unwrap_or(&amount)
        };
        // Reserve (always — no idempotency/caps for a manual tip), then spend + reconcile.
        let day = self.clock.today_utc();
        let ts = self.clock.now_unix();
        let id = {
            let mut st = self.state.lock().await;
            let id = st.reserve(TipLedgerEntry {
                id: 0,
                recipient_ph: owner.clone(),
                store_id: Some(normalize_hex(store_id_hex)),
                dig_amount: amount,
                ts,
                day,
                txid: None,
                trigger: TipTrigger::Manual,
                kind: TipKind::Creator,
                status: TipStatus::Pending,
            });
            self.persist_ledger(&st)?;
            id
        };
        self.spend_and_reconcile(id, owner, amount, fee).await
    }

    /// The shared auto-tip reserve→spend→reconcile path: authoritative idempotency + cap checks
    /// under the lock, a persisted PENDING reservation BEFORE the broadcast, then reconcile.
    async fn reserve_and_spend(&self, args: ReserveArgs) -> Result<TipOutcome> {
        let day = self.clock.today_utc();
        let ts = self.clock.now_unix();
        let fee = { self.state.lock().await.config.fee };
        let id = {
            let mut st = self.state.lock().await;
            // Idempotency (never double-tip a site in a day) — authoritative under the lock.
            if st.auto_already_reserved(args.kind, &args.recipient, &day) {
                return Ok(TipOutcome::skipped("already-tipped-today"));
            }
            // Per-site cap (PerSitePerDay mode only) — fail-closed.
            if args.mode == TipMode::PerSitePerDay {
                let site = st.auto_site_spent_today(args.kind, &args.recipient, &day);
                if site.saturating_add(args.amount) > args.per_site_cap {
                    return Ok(TipOutcome::skipped("over-per-site-cap"));
                }
            }
            // Daily total cap (creator + dev) — fail-closed.
            let total = st.auto_spent_today(&day);
            if total.saturating_add(args.amount) > args.daily_total_cap {
                return Ok(TipOutcome::skipped("over-daily-cap"));
            }
            let id = st.reserve(TipLedgerEntry {
                id: 0,
                recipient_ph: args.recipient.clone(),
                store_id: args.store_id.clone(),
                dig_amount: args.amount,
                ts,
                day: day.clone(),
                txid: None,
                trigger: args.trigger,
                kind: args.kind,
                status: TipStatus::Pending,
            });
            // Persist the reservation BEFORE the broadcast (crash-safety).
            self.persist_ledger(&st)?;
            id
        };
        self.spend_and_reconcile(id, args.recipient, args.amount, fee)
            .await
    }

    /// Broadcast the reserved tip (money moves here) and reconcile the reservation: confirm on a
    /// broadcast, roll back on a definitively-pre-broadcast NotExecutable (retryable), or keep as
    /// Failed on an ambiguous error (fail-closed — never retried that day).
    async fn spend_and_reconcile(
        &self,
        id: u64,
        recipient: String,
        amount: u64,
        fee: u64,
    ) -> Result<TipOutcome> {
        let outcome = self.spender.send_dig_tip(&recipient, amount, fee).await;
        let mut st = self.state.lock().await;
        match outcome {
            Ok(TipSpendOutcome::Broadcast { txid, confirmed }) => {
                if let Some(e) = st.entry_mut(id) {
                    // Confirm-before-marking-confirmed (§18.12): a broadcast that was included in a
                    // block is `Confirmed`; one accepted into the mempool but not yet confirmed
                    // stays `Pending` with its txid (money moved — the reservation still blocks a
                    // same-day retry, and Pending amounts count toward the caps, so this never
                    // enables a double-spend).
                    e.status = if confirmed {
                        TipStatus::Confirmed
                    } else {
                        TipStatus::Pending
                    };
                    e.txid = Some(txid.clone());
                }
                self.persist_ledger(&st)?;
                let entry = st.ledger.iter().find(|e| e.id == id).cloned();
                drop(st);
                if let Some(entry) = entry {
                    self.events.publish(TipEvent { entry });
                }
                Ok(TipOutcome::Tipped {
                    txid,
                    dig_amount: amount,
                    recipient_ph: recipient,
                })
            }
            Ok(TipSpendOutcome::NotExecutable { reason }) => {
                // No money moved → roll the reservation back so it can retry later.
                st.remove(id);
                self.persist_ledger(&st)?;
                Ok(TipOutcome::skipped(format!("wallet-unavailable: {reason}")))
            }
            Err(e) => {
                // Ambiguous broadcast failure → keep the reservation (Failed) so this (site, day)
                // is NEVER retried (fail-closed: never double-spend).
                if let Some(entry) = st.entry_mut(id) {
                    entry.status = TipStatus::Failed;
                }
                self.persist_ledger(&st)?;
                Ok(TipOutcome::skipped(format!(
                    "spend-failed-not-retried: {e}"
                )))
            }
        }
    }

    /// Persist the ledger atomically (temp file + rename) while the state lock is held.
    fn persist_ledger(&self, st: &TippingState) -> Result<()> {
        let file = LedgerFile {
            next_id: st.next_id,
            entries: st.ledger.clone(),
        };
        write_json(&self.ledger_path, &file)
    }
}

/// Arguments for [`TippingEngine::reserve_and_spend`] (grouped to keep the signature honest).
struct ReserveArgs {
    kind: TipKind,
    trigger: TipTrigger,
    recipient: String,
    store_id: Option<String>,
    amount: u64,
    per_site_cap: u64,
    mode: TipMode,
    daily_total_cap: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Small helpers (hex normalization + atomic JSON persistence)
// ─────────────────────────────────────────────────────────────────────────────

/// Normalize a puzzle-hash / store-id hex to lowercase without a `0x` prefix.
fn normalize_hex(s: &str) -> String {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
        .to_ascii_lowercase()
}

/// Accumulate a poison reason (comma-joined) so BOTH an unreadable config AND an unreadable ledger
/// are recorded.
fn add_poison(poison: &mut Option<String>, reason: String) {
    *poison = Some(match poison.take() {
        Some(p) => format!("{p}; {reason}"),
        None => reason,
    });
}

/// Read + deserialize a JSON file, distinguishing ABSENT from PRESENT-BUT-UNREADABLE (FAIL-CLOSED,
/// the money-safety contract):
/// - `Ok(None)` — the file does not exist (a genuine first run: caller defaults/empties).
/// - `Ok(Some(T))` — the file exists and parsed.
/// - `Err(_)` — the file EXISTS but could not be read (locked/permission/IO) OR could not be parsed
///   (corrupt/truncated/forward-incompatible). The caller MUST fail closed — NEVER treat this as
///   "empty/default", which would reset caps + idempotency (over-spend) or re-enable a disabled
///   auto-tip. `unwrap_or_default()` on this result would reintroduce the fail-open bug.
fn read_json_strict<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice(&bytes).map_err(|e| {
                Error::internal(format!(
                    "{} is present but unparseable: {e}",
                    path.display()
                ))
            })?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::internal(format!(
            "{} is present but unreadable: {e}",
            path.display()
        ))),
    }
}

/// Serialize + write a JSON file DURABLY: write a temp file in the same dir, `fsync` it, atomically
/// `rename` it into place, then best-effort `fsync` the parent directory — so a crash/power-loss
/// can never leave a truncated/zero-length money ledger (which would then hit the fail-closed
/// read path on the next load). Owner-only best effort. The wallet crate carries its own helper
/// (the node's `control::write_atomic` lives in the service crate).
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::internal(format!("serialize {}: {e}", path.display())))?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("tmp-{}-{nanos}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| Error::internal(format!("create {}: {e}", tmp.display())))?;
        f.write_all(&bytes)
            .map_err(|e| Error::internal(format!("write {}: {e}", tmp.display())))?;
        // fsync the file contents BEFORE the rename so the rename can only ever expose a fully
        // durable file.
        f.sync_all()
            .map_err(|e| Error::internal(format!("fsync {}: {e}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::internal(format!("rename into {}: {e}", path.display())))?;
    // Best-effort fsync of the parent dir so the rename itself is durable (a no-op / not permitted
    // on some platforms — e.g. opening a directory as a file on Windows — hence best-effort).
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Production seam implementations
// ─────────────────────────────────────────────────────────────────────────────

/// The production owner resolver: resolves a store's owner puzzle hash from its on-chain CHIP-0035
/// singleton via `digstore_chain::singleton::sync_datastore` — the SAME DataStore parser the node
/// already uses for store sync (never re-parsing a singleton by hand). The chain client is a
/// [`digstore_chain::coinset::ChainReads`] (coinset.org, [`Coinset::mainnet`]); it is a swappable
/// seam — a `chia-query`-backed `ChainReads` (decentralized peers + coinset fallback), which already
/// backs the node's coin-read fallback tier, is a drop-in when a full `ChainReads` over it lands.
pub struct ChainOwnerResolver {
    chain: std::sync::Arc<dyn digstore_chain::coinset::ChainReads>,
}

impl ChainOwnerResolver {
    /// Resolve owners against mainnet coinset.org.
    pub fn mainnet() -> Self {
        Self {
            chain: std::sync::Arc::new(digstore_chain::coinset::Coinset::mainnet()),
        }
    }

    /// Resolve owners against a supplied chain client (tests / a custom substrate).
    pub fn with_chain(chain: std::sync::Arc<dyn digstore_chain::coinset::ChainReads>) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl OwnerResolver for ChainOwnerResolver {
    async fn resolve_owner(&self, store_id_hex: &str) -> Result<Option<String>> {
        let launcher = super::singleton::bytes32_from_hex(store_id_hex)?;
        match digstore_chain::singleton::sync_datastore(self.chain.as_ref(), launcher).await {
            Ok(store) => Ok(Some(hex::encode(store.info.owner_puzzle_hash))),
            // A not-yet-minted / unknown store is a clean "no owner" (the engine skips, never spends).
            Err(e) => Err(Error::api(format!("owner lookup failed: {e}"))),
        }
    }
}

/// The production tip spender: builds+signs+validates+broadcasts via the node-custodied
/// [`super::rpc::WalletBackend`] (`build_and_broadcast_dig_tip`) with an injected broadcaster.
///
/// The broadcaster is `None` on the offline-safe shipped bring-up (the wallet spend path's live
/// sync/lineage/broadcaster is the documented remaining integration, SPEC §18.12); until then a
/// tip cleanly reports [`TipSpendOutcome::NotExecutable`] (the engine skips — money never moves).
/// When the wallet spend bring-up attaches a real broadcaster (a `ChiaQueryBroadcaster`), tips
/// execute unchanged.
pub struct NodeTipSpender {
    backend: std::sync::Arc<super::rpc::WalletBackend>,
    broadcaster: Option<std::sync::Arc<dyn super::spend::Broadcaster>>,
    /// The on-chain confirmer (§18.12). `None` ⇒ a broadcast tip is recorded `Pending` (accepted,
    /// not confirmed); `Some` ⇒ the tip waits for on-chain inclusion and is recorded `Confirmed`
    /// once a block includes it. Shares the SAME `chia_query` client as the broadcaster.
    confirmer: Option<std::sync::Arc<dyn super::spend::Confirmer>>,
}

impl NodeTipSpender {
    /// Build a spender over `backend`. The `backend` MUST NOT itself hold this engine (pass a clone
    /// taken before `with_tipping`) to avoid a reference cycle. `broadcaster`/`confirmer` are
    /// `None` on the offline-safe shipped bring-up (a tip then reports `NotExecutable` and money
    /// never moves) and `Some` when live broadcast is enabled (§18.12).
    pub fn new(
        backend: std::sync::Arc<super::rpc::WalletBackend>,
        broadcaster: Option<std::sync::Arc<dyn super::spend::Broadcaster>>,
        confirmer: Option<std::sync::Arc<dyn super::spend::Confirmer>>,
    ) -> Self {
        Self {
            backend,
            broadcaster,
            confirmer,
        }
    }
}

#[async_trait]
impl TipSpender for NodeTipSpender {
    async fn send_dig_tip(
        &self,
        recipient_ph_hex: &str,
        amount: u64,
        fee: u64,
    ) -> Result<TipSpendOutcome> {
        let Some(bc) = self.broadcaster.as_ref() else {
            return Ok(TipSpendOutcome::NotExecutable {
                reason: "no broadcaster configured (wallet spend path not yet wired)".into(),
            });
        };
        // Point-read live sync before selecting (§18.12): refresh the wallet DB from the fallback so
        // coin selection runs over current chain state. Best-effort — a sync failure is not a spend
        // failure: `build_and_broadcast_dig_tip` then reports NotExecutable if no $DIG is selectable
        // (retryable), never a false spend.
        if let Err(e) = self.backend.refresh_tracked_coins().await {
            eprintln!(
                "dig-node: WARN tip pre-spend coin sync failed (continuing best-effort): {e}"
            );
        }
        let recipient = super::singleton::bytes32_from_hex(recipient_ph_hex)?;
        self.backend
            .build_and_broadcast_dig_tip(
                recipient,
                amount,
                fee,
                bc.as_ref(),
                self.confirmer.as_deref(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    // ── test doubles (no chain — money-safe by construction) ──────────────

    /// Behaviour of a mock spend attempt.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SpendBehaviour {
        /// Accept + confirm on-chain: a fresh txid, `confirmed: true` (ledger `Confirmed`).
        Broadcast,
        /// Accept into the mempool but NOT confirmed within the window: a fresh txid,
        /// `confirmed: false` (ledger `Pending`, txid set — §18.12).
        BroadcastUnconfirmed,
        /// Definitively pre-broadcast (locked/no-coins) — retryable.
        NotExecutable,
        /// Ambiguous broadcast error — fail-closed, no retry.
        Ambiguous,
    }

    /// A recording spender that NEVER touches a chain — the money-safety proofs run against it.
    struct MockSpender {
        calls: StdMutex<Vec<(String, u64)>>,
        behaviour: StdMutex<SpendBehaviour>,
        seq: AtomicU64,
    }
    impl MockSpender {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: StdMutex::new(Vec::new()),
                behaviour: StdMutex::new(SpendBehaviour::Broadcast),
                seq: AtomicU64::new(0),
            })
        }
        fn calls(&self) -> Vec<(String, u64)> {
            self.calls.lock().unwrap().clone()
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        fn set(&self, b: SpendBehaviour) {
            *self.behaviour.lock().unwrap() = b;
        }
    }
    #[async_trait]
    impl TipSpender for Arc<MockSpender> {
        async fn send_dig_tip(
            &self,
            recipient_ph_hex: &str,
            amount: u64,
            _fee: u64,
        ) -> Result<TipSpendOutcome> {
            self.calls
                .lock()
                .unwrap()
                .push((recipient_ph_hex.to_string(), amount));
            match *self.behaviour.lock().unwrap() {
                SpendBehaviour::NotExecutable => Ok(TipSpendOutcome::NotExecutable {
                    reason: "locked".into(),
                }),
                SpendBehaviour::Ambiguous => Err(Error::internal("network rejected")),
                SpendBehaviour::Broadcast => {
                    let n = self.seq.fetch_add(1, Ordering::SeqCst);
                    Ok(TipSpendOutcome::Broadcast {
                        txid: format!("tx{n}"),
                        confirmed: true,
                    })
                }
                SpendBehaviour::BroadcastUnconfirmed => {
                    let n = self.seq.fetch_add(1, Ordering::SeqCst);
                    Ok(TipSpendOutcome::Broadcast {
                        txid: format!("tx{n}"),
                        confirmed: false,
                    })
                }
            }
        }
    }

    /// A fixed owner resolver returning a preset ph (or `None`), counting calls (to prove caching).
    struct MockOwner {
        ph: Option<String>,
        calls: AtomicU64,
    }
    impl MockOwner {
        fn some(ph: &str) -> Arc<Self> {
            Arc::new(Self {
                ph: Some(ph.to_string()),
                calls: AtomicU64::new(0),
            })
        }
        fn none() -> Arc<Self> {
            Arc::new(Self {
                ph: None,
                calls: AtomicU64::new(0),
            })
        }
        fn count(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl OwnerResolver for Arc<MockOwner> {
        async fn resolve_owner(&self, _store_id_hex: &str) -> Result<Option<String>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.ph.clone())
        }
    }

    /// A clock pinned to a fixed unix time (settable to advance days).
    struct FixedClock(AtomicU64);
    impl FixedClock {
        fn at(secs: u64) -> Arc<Self> {
            Arc::new(Self(AtomicU64::new(secs)))
        }
        fn set(&self, secs: u64) {
            self.0.store(secs, Ordering::SeqCst);
        }
    }
    impl Clock for Arc<FixedClock> {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn owner_hex() -> String {
        "11".repeat(32)
    }
    const STORE: &str = "0xabc"; // arbitrary store id (normalized to "abc")
    const DAY0: u64 = 1_700_000_000; // 2023-11-14 (a stable day)
    const DAY1: u64 = DAY0 + 86_400; // the next day

    fn scratch() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dig-tip-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Build an engine over `dir` and seed its config (persisted).
    async fn make(
        dir: &Path,
        owner: impl OwnerResolver + 'static,
        spender: Arc<MockSpender>,
        clock: Arc<FixedClock>,
        config: TippingConfig,
    ) -> TippingEngine {
        let eng = TippingEngine::load(
            dir,
            Box::new(owner),
            Box::new(spender),
            Box::new(clock),
            Arc::new(TipEventBus::default()),
        );
        eng.set_config(config).await.unwrap();
        eng
    }

    /// A config with small, cap-friendly numbers for deterministic tests.
    fn test_config() -> TippingConfig {
        let mut c = TippingConfig::default();
        c.creator.dig_amount = 100;
        c.creator.per_site_cap = 100;
        c.daily_total_cap = 250;
        c.dev.dig_amount = 100;
        c
    }

    // ── unix_to_utc_date ─────────────────────────────────────────────────

    #[test]
    fn utc_date_epoch_and_known_days() {
        assert_eq!(unix_to_utc_date(0), "1970-01-01");
        assert_eq!(unix_to_utc_date(86_399), "1970-01-01");
        assert_eq!(unix_to_utc_date(86_400), "1970-01-02");
        assert_eq!(unix_to_utc_date(DAY0), "2023-11-14");
        assert_eq!(unix_to_utc_date(DAY1), "2023-11-15");
    }

    /// The canonical DIG treasury inner puzzle hash (the per-capsule-payment recipient) — the
    /// dev-account tip's recipient. Byte-identical to the shared contract.
    const TREASURY: &str = "ec7c304708c7d59c078d5ae098d0dea004decf47fa1cafebb266c10ad6466ce8";

    // ── defaults + dev recipient ─────────────────────────────────────────

    #[test]
    fn creator_and_dev_default_on() {
        let c = TippingConfig::default();
        assert!(c.creator.enabled, "creator auto-tip is DEFAULT-ON (#377)");
        assert!(
            c.dev.enabled,
            "dev-account tip is DEFAULT-ON (#377) — real treasury recipient"
        );
        assert!(c.creator.dig_amount > 0 && c.daily_total_cap >= c.creator.dig_amount);
    }

    #[test]
    fn dev_recipient_is_the_dig_treasury_shared_contract() {
        // Sourced from digstore-chain (never re-hardcoded); must equal the per-capsule-payment PH.
        assert_eq!(dig_treasury_ph_hex(), TREASURY);
    }

    // ── owner-PH lookup (cached) ─────────────────────────────────────────

    #[tokio::test]
    async fn owner_lookup_is_cached_per_store() {
        let dir = scratch();
        let owner = MockOwner::some(&owner_hex());
        let sp = MockSpender::new();
        let eng = make(&dir, owner.clone(), sp, FixedClock::at(DAY0), test_config()).await;

        // Two auto-tips for the same store on the same day: the first tips, the second is an
        // idempotent skip — but the owner is resolved only ONCE (cached).
        eng.auto_tip_for_store(STORE).await.unwrap();
        eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(owner.count(), 1, "owner resolution is cached per store");
    }

    #[tokio::test]
    async fn auto_tip_skips_when_owner_unresolved() {
        let dir = scratch();
        let sp = MockSpender::new();
        let eng = make(
            &dir,
            MockOwner::none(),
            sp.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(out, TipOutcome::skipped("owner-unresolved"));
        assert_eq!(sp.call_count(), 0, "no spend without a recipient");
    }

    // ── disabled → skip ──────────────────────────────────────────────────

    #[tokio::test]
    async fn disabled_creator_skips_without_spending() {
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.enabled = false;
        let sp = MockSpender::new();
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            cfg,
        )
        .await;
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(out, TipOutcome::skipped("disabled"));
        assert_eq!(sp.call_count(), 0);
    }

    // ── the happy path: a creator auto-tip, recorded + pushed ────────────

    #[tokio::test]
    async fn creator_auto_tip_spends_records_and_pushes() {
        let dir = scratch();
        let sp = MockSpender::new();
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        let mut rx = eng.events().subscribe();

        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        match out {
            TipOutcome::Tipped {
                dig_amount,
                recipient_ph,
                ..
            } => {
                assert_eq!(dig_amount, 100);
                assert_eq!(recipient_ph, owner_hex());
            }
            other => panic!("expected Tipped, got {other:?}"),
        }
        assert_eq!(sp.calls(), vec![(owner_hex(), 100)]);

        // Ledger records one confirmed creator/auto entry with a txid.
        let ledger = eng.get_ledger(None).await;
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].status, TipStatus::Confirmed);
        assert_eq!(ledger[0].kind, TipKind::Creator);
        assert_eq!(ledger[0].trigger, TipTrigger::Auto);
        assert!(ledger[0].txid.is_some());

        // A tip event was pushed over the WS bus.
        let ev = rx.try_recv().expect("a tip event was published");
        assert_eq!(ev.entry.recipient_ph, owner_hex());
        assert_eq!(ev.entry.status, TipStatus::Confirmed);
    }

    // ── idempotency: never double-tip a site in a day ─────────────────────

    #[tokio::test]
    async fn same_day_same_site_is_tipped_only_once() {
        let dir = scratch();
        let sp = MockSpender::new();
        let clock = FixedClock::at(DAY0);
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            clock.clone(),
            test_config(),
        )
        .await;

        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        let second = eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(second, TipOutcome::skipped("already-tipped-today"));
        assert_eq!(sp.call_count(), 1, "spent exactly once for the site/day");

        // A NEW day tips again.
        clock.set(DAY1);
        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert_eq!(sp.call_count(), 2);
    }

    // ── crash-retry: reload from the persisted ledger → no double-spend ──

    #[tokio::test]
    async fn crash_retry_does_not_double_spend() {
        let dir = scratch();
        // Engine 1 tips once (reservation + confirm persisted to tip-ledger.json).
        {
            let sp = MockSpender::new();
            let eng = make(
                &dir,
                MockOwner::some(&owner_hex()),
                sp.clone(),
                FixedClock::at(DAY0),
                test_config(),
            )
            .await;
            assert!(matches!(
                eng.auto_tip_for_store(STORE).await.unwrap(),
                TipOutcome::Tipped { .. }
            ));
            assert_eq!(sp.call_count(), 1);
        }
        // Engine 2 (simulating a restart) reloads the SAME dir + same day → the (site, day) is
        // already reserved → SKIP, never a second spend.
        let sp2 = MockSpender::new();
        let eng2 = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp2.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        let out = eng2.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(out, TipOutcome::skipped("already-tipped-today"));
        assert_eq!(
            sp2.call_count(),
            0,
            "a restart never re-spends a reserved day"
        );
    }

    // ── caps fail closed ─────────────────────────────────────────────────

    #[tokio::test]
    async fn per_site_cap_blocks_over_the_ceiling() {
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.dig_amount = 100;
        cfg.creator.per_site_cap = 100; // one tip fits; a second would exceed
        cfg.daily_total_cap = 10_000; // not the binding constraint here
        let sp = MockSpender::new();
        let clock = FixedClock::at(DAY0);
        let eng = make(&dir, MockOwner::some(&owner_hex()), sp.clone(), clock, cfg).await;

        // First store → owner tipped. A DIFFERENT store with the SAME owner the same day would
        // exceed the per-site cap (idempotency already blocks the same store; force a manual-style
        // second reservation by using the cap path directly): the second auto for the same owner
        // via a different store id still maps to the same owner → idempotency skip. To isolate the
        // per-site cap we set the amount ABOVE the cap so even the first tip is blocked.
        let mut cfg2 = test_config();
        cfg2.creator.dig_amount = 200;
        cfg2.creator.per_site_cap = 100; // 200 > 100 → blocked
        let sp2 = MockSpender::new();
        let eng2 = make(
            &scratch(),
            MockOwner::some(&owner_hex()),
            sp2.clone(),
            FixedClock::at(DAY0),
            cfg2,
        )
        .await;
        let out = eng2.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(out, TipOutcome::skipped("over-per-site-cap"));
        assert_eq!(sp2.call_count(), 0, "over-cap fails closed — nothing spent");
        let _ = (eng, sp);
    }

    #[tokio::test]
    async fn daily_total_cap_blocks_across_sites() {
        // daily_total_cap = 250, each tip = 100 → the 3rd distinct site is blocked.
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.dig_amount = 100;
        cfg.creator.per_site_cap = 100_000; // not binding
        cfg.daily_total_cap = 250;
        let clock = FixedClock::at(DAY0);
        let sp = MockSpender::new();
        // Three different owners for three different stores.
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        // Resolver maps each store to a distinct owner.
        struct Multi(Vec<(String, String)>);
        #[async_trait]
        impl OwnerResolver for Multi {
            async fn resolve_owner(&self, store: &str) -> Result<Option<String>> {
                Ok(self
                    .0
                    .iter()
                    .find(|(s, _)| *s == super::normalize_hex(store))
                    .map(|(_, o)| o.clone()))
            }
        }
        let resolver = Multi(vec![
            ("s1".into(), a.clone()),
            ("s2".into(), b.clone()),
            ("s3".into(), c.clone()),
        ]);
        let eng = make(&dir, resolver, sp.clone(), clock, cfg).await;

        assert!(matches!(
            eng.auto_tip_for_store("s1").await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert!(matches!(
            eng.auto_tip_for_store("s2").await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        let third = eng.auto_tip_for_store("s3").await.unwrap();
        assert_eq!(third, TipOutcome::skipped("over-daily-cap"));
        assert_eq!(
            sp.call_count(),
            2,
            "the daily total cap fails closed on the 3rd"
        );
    }

    // ── dev-account tip: pays the real DIG treasury, once per day ────────

    #[tokio::test]
    async fn dev_daily_tip_pays_the_treasury_once_per_day() {
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.enabled = false; // isolate the dev tip
        cfg.dev.enabled = true;
        cfg.dev.dig_amount = 100;
        cfg.daily_total_cap = 1_000;
        let sp = MockSpender::new();
        let clock = FixedClock::at(DAY0);
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            clock.clone(),
            cfg,
        )
        .await;

        // The dev tip pays the REAL DIG treasury shared-contract PH.
        match eng.dev_daily_tip().await.unwrap() {
            TipOutcome::Tipped {
                recipient_ph,
                dig_amount,
                ..
            } => {
                assert_eq!(recipient_ph, TREASURY, "dev tip pays the DIG treasury PH");
                assert_eq!(dig_amount, 100);
            }
            other => panic!("expected Tipped to the treasury, got {other:?}"),
        }
        assert_eq!(sp.calls(), vec![(TREASURY.to_string(), 100)]);

        // Idempotent: a second dev tick the same day is a no-op (never double-tip the treasury/day).
        assert_eq!(
            eng.dev_daily_tip().await.unwrap(),
            TipOutcome::skipped("already-tipped-today")
        );
        assert_eq!(sp.call_count(), 1);

        // A new day tips again.
        clock.set(DAY1);
        assert!(matches!(
            eng.dev_daily_tip().await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert_eq!(sp.call_count(), 2);

        // The ledger records dev-kind entries.
        let ledger = eng.get_ledger(None).await;
        assert!(ledger.iter().all(|e| e.kind == TipKind::Dev));
        assert_eq!(ledger.len(), 2);
    }

    /// **Proves:** the daily total cap spans creator + dev — a dev tip counts against the same
    /// budget, so the two together can never exceed the daily cap (fail-closed).
    #[tokio::test]
    async fn daily_total_cap_spans_creator_and_dev() {
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.enabled = true;
        cfg.creator.dig_amount = 100;
        cfg.creator.per_site_cap = 100_000; // not binding
        cfg.dev.enabled = true;
        cfg.dev.dig_amount = 100;
        cfg.daily_total_cap = 150; // one 100 tip fits; the second (creator OR dev) is blocked
        let sp = MockSpender::new();
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            cfg,
        )
        .await;

        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        // The dev tip would push the day's total to 200 > 150 → blocked (creator already spent 100).
        let dev = eng.dev_daily_tip().await.unwrap();
        assert_eq!(dev, TipOutcome::skipped("over-daily-cap"));
        assert_eq!(
            sp.call_count(),
            1,
            "the shared daily cap fails closed across creator + dev"
        );
    }

    // ── NotExecutable → rolled back (retryable); Ambiguous → kept (no retry)

    #[tokio::test]
    async fn not_executable_rolls_back_and_is_retryable() {
        let dir = scratch();
        let sp = MockSpender::new();
        sp.set(SpendBehaviour::NotExecutable);
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert!(matches!(out, TipOutcome::Skipped { .. }));
        assert!(
            eng.get_ledger(None).await.is_empty(),
            "a pre-broadcast skip leaves no reservation"
        );
        // Now the wallet becomes executable → the same store/day tips (it was rolled back).
        sp.set(SpendBehaviour::Broadcast);
        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert_eq!(sp.call_count(), 2);
    }

    #[tokio::test]
    async fn ambiguous_broadcast_error_is_not_retried_that_day() {
        let dir = scratch();
        let sp = MockSpender::new();
        sp.set(SpendBehaviour::Ambiguous);
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert!(matches!(out, TipOutcome::Skipped { .. }));
        // The reservation is KEPT as Failed (fail-closed: never double-spend on an ambiguous error).
        let ledger = eng.get_ledger(None).await;
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].status, TipStatus::Failed);
        // A retry the same day is refused (no second broadcast attempt).
        sp.set(SpendBehaviour::Broadcast);
        let retry = eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(retry, TipOutcome::skipped("already-tipped-today"));
        assert_eq!(sp.call_count(), 1, "an ambiguous day is never retried");
    }

    /// A broadcast that was accepted into the mempool but NOT confirmed on-chain within the window
    /// (§18.12) records the tip as `Pending` (money moved — outcome is `Tipped`, txid set), and the
    /// reservation still blocks a same-day retry (Pending counts toward the caps + idempotency).
    #[tokio::test]
    async fn unconfirmed_broadcast_is_pending_with_txid_and_blocks_retry() {
        let dir = scratch();
        let sp = MockSpender::new();
        sp.set(SpendBehaviour::BroadcastUnconfirmed);
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            test_config(),
        )
        .await;
        // Money moved (broadcast accepted) → the outcome is Tipped with a txid.
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert!(matches!(out, TipOutcome::Tipped { .. }));
        // But the ledger status is Pending (not yet confirmed on-chain) with the txid recorded.
        let ledger = eng.get_ledger(None).await;
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].status, TipStatus::Pending);
        assert!(ledger[0].txid.is_some(), "the broadcast txid is recorded");
        // A same-day retry is refused: the Pending reservation blocks re-tipping (no double-spend).
        sp.set(SpendBehaviour::Broadcast);
        let retry = eng.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(retry, TipOutcome::skipped("already-tipped-today"));
        assert_eq!(
            sp.call_count(),
            1,
            "a pending (unconfirmed) tip is never re-broadcast"
        );
    }

    // ── manual tip: bypasses idempotency + caps, always executes ─────────

    #[tokio::test]
    async fn manual_tip_bypasses_idempotency_and_caps() {
        let dir = scratch();
        let mut cfg = test_config();
        cfg.creator.enabled = false; // even with auto off, a manual tip works
        cfg.daily_total_cap = 0; // and it ignores the auto daily cap
        let sp = MockSpender::new();
        let eng = make(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
            cfg,
        )
        .await;

        assert!(matches!(
            eng.manual_tip(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert!(matches!(
            eng.manual_tip(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert_eq!(
            sp.call_count(),
            2,
            "manual tips repeat freely (explicit consent)"
        );
        let ledger = eng.get_ledger(None).await;
        assert_eq!(ledger.len(), 2);
        assert!(ledger.iter().all(|e| e.trigger == TipTrigger::Manual));
    }

    // ── config persistence ───────────────────────────────────────────────

    #[tokio::test]
    async fn config_persists_across_reload() {
        let dir = scratch();
        let sp = MockSpender::new();
        let mut cfg = test_config();
        cfg.creator.dig_amount = 777;
        {
            let eng = make(
                &dir,
                MockOwner::some(&owner_hex()),
                sp.clone(),
                FixedClock::at(DAY0),
                cfg,
            )
            .await;
            assert_eq!(eng.get_config().await.creator.dig_amount, 777);
        }
        // A fresh engine over the same dir reads the persisted config.
        let eng2 = TippingEngine::load(
            &dir,
            Box::new(MockOwner::some(&owner_hex())),
            Box::new(sp),
            Box::new(FixedClock::at(DAY0)),
            Arc::new(TipEventBus::default()),
        );
        assert_eq!(eng2.get_config().await.creator.dig_amount, 777);
    }

    // ── FAIL-CLOSED on unreadable persisted state (money-safety regression) ──

    /// Load an engine over `dir` WITHOUT seeding config (so a poisoned load is observable — the
    /// poison guard would reject `set_config`).
    fn load_only(
        dir: &Path,
        owner: impl OwnerResolver + 'static,
        spender: Arc<MockSpender>,
        clock: Arc<FixedClock>,
    ) -> TippingEngine {
        TippingEngine::load(
            dir,
            Box::new(owner),
            Box::new(spender),
            Box::new(clock),
            Arc::new(TipEventBus::default()),
        )
    }

    /// **Proves (HIGH regression):** a PRESENT-but-corrupt `tip-ledger.json` FAILS CLOSED — the
    /// engine does NOT reset the ledger to empty and re-tip. Without the fix, the corrupt ledger
    /// would read as empty → `auto_already_reserved`=false → re-tip the full daily budget.
    #[tokio::test]
    async fn present_but_corrupt_ledger_fails_closed_no_retip() {
        let dir = scratch();
        std::fs::write(dir.join("tip-ledger.json"), b"{ this is not valid json ]").unwrap();
        let sp = MockSpender::new();
        let eng = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
        );
        let out = eng.auto_tip_for_store(STORE).await.unwrap();
        assert!(
            matches!(&out, TipOutcome::Skipped { reason } if reason.starts_with("state-unreadable")),
            "a corrupt ledger must fail closed: {out:?}"
        );
        assert_eq!(
            sp.call_count(),
            0,
            "no spend while the ledger is unreadable"
        );
        // A manual tip is refused too (it would clobber the unreadable ledger).
        assert_eq!(sp.call_count(), 0);
        assert!(matches!(
            eng.manual_tip(STORE).await.unwrap(),
            TipOutcome::Skipped { .. }
        ));
        assert_eq!(sp.call_count(), 0);
    }

    /// **Proves (HIGH regression):** a truncated / zero-length ledger (an interrupted write / power-
    /// loss artifact) is PRESENT-but-unparseable → fails closed, no re-tip.
    #[tokio::test]
    async fn truncated_zero_length_ledger_fails_closed() {
        let dir = scratch();
        std::fs::write(dir.join("tip-ledger.json"), b"").unwrap(); // zero-length
        let sp = MockSpender::new();
        let eng = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
        );
        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Skipped { .. }
        ));
        assert_eq!(sp.call_count(), 0);
    }

    /// **Proves (HIGH regression):** a real prior tip, then a CORRUPTED ledger on the next boot →
    /// the reloaded engine REFUSES (fail closed) rather than double-spending the already-tipped
    /// site. This is the concrete double-spend scenario the fail-open bug enabled.
    #[tokio::test]
    async fn corrupt_ledger_after_a_tip_prevents_double_spend() {
        let dir = scratch();
        {
            let sp = MockSpender::new();
            let eng = make(
                &dir,
                MockOwner::some(&owner_hex()),
                sp.clone(),
                FixedClock::at(DAY0),
                test_config(),
            )
            .await;
            assert!(matches!(
                eng.auto_tip_for_store(STORE).await.unwrap(),
                TipOutcome::Tipped { .. }
            ));
            assert_eq!(sp.call_count(), 1);
        }
        // Corrupt the persisted ledger (e.g. AV/indexer lock recovery, partial write).
        std::fs::write(dir.join("tip-ledger.json"), b"\x00\x00corrupt").unwrap();
        let sp2 = MockSpender::new();
        let eng2 = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp2.clone(),
            FixedClock::at(DAY0),
        );
        let out = eng2.auto_tip_for_store(STORE).await.unwrap();
        assert!(
            matches!(&out, TipOutcome::Skipped { reason } if reason.starts_with("state-unreadable")),
            "a corrupt ledger after a tip must not re-tip: {out:?}"
        );
        assert_eq!(
            sp2.call_count(),
            0,
            "NEVER double-spend on an unreadable ledger"
        );
    }

    /// **Proves (HIGH regression):** a PRESENT-but-corrupt `tipping-config.json` does NOT silently
    /// fall back to the DEFAULT-ON config — auto-tip is treated as DISABLED (never moves $DIG
    /// against a user who had turned it off) and the engine is poisoned.
    #[tokio::test]
    async fn present_but_corrupt_config_does_not_reenable_autotip() {
        let dir = scratch();
        std::fs::write(dir.join("tipping-config.json"), b"{ not: valid").unwrap();
        let sp = MockSpender::new();
        let eng = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
        );
        // The effective config is fail-closed DISABLED (not the DEFAULT-ON default).
        let cfg = eng.get_config().await;
        assert!(
            !cfg.creator.enabled,
            "corrupt config must NOT re-enable creator auto-tip"
        );
        assert!(!cfg.dev.enabled);
        // And any auto-tip is refused (poisoned).
        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Skipped { .. }
        ));
        assert_eq!(sp.call_count(), 0);
        // set_config is refused while poisoned (resolve the file + restart).
        assert!(eng.set_config(test_config()).await.is_err());
    }

    /// **Proves:** ABSENT files are a genuine first run — NOT poison. The engine tips normally
    /// (creator DEFAULT-ON), so the fail-closed distinction doesn't over-block real first boots.
    #[tokio::test]
    async fn absent_files_are_a_clean_first_run_and_tip() {
        let dir = scratch(); // fresh, empty dir — no config or ledger files
        let sp = MockSpender::new();
        let eng = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp.clone(),
            FixedClock::at(DAY0),
        );
        // DEFAULT-ON config (absent config → default, not disabled).
        assert!(eng.get_config().await.creator.enabled);
        assert!(matches!(
            eng.auto_tip_for_store(STORE).await.unwrap(),
            TipOutcome::Tipped { .. }
        ));
        assert_eq!(sp.call_count(), 1, "a genuine first run still tips");
    }

    /// **Proves:** `write_json` produces a durable, re-readable file (the fsync path doesn't
    /// corrupt output) — a tipped ledger reloads cleanly and is treated as already-tipped.
    #[tokio::test]
    async fn durable_write_reloads_cleanly() {
        let dir = scratch();
        {
            let sp = MockSpender::new();
            let eng = make(
                &dir,
                MockOwner::some(&owner_hex()),
                sp.clone(),
                FixedClock::at(DAY0),
                test_config(),
            )
            .await;
            assert!(matches!(
                eng.auto_tip_for_store(STORE).await.unwrap(),
                TipOutcome::Tipped { .. }
            ));
        }
        // Reload: the persisted ledger parses (not poisoned) and the day is already tipped.
        let sp2 = MockSpender::new();
        let eng2 = load_only(
            &dir,
            MockOwner::some(&owner_hex()),
            sp2.clone(),
            FixedClock::at(DAY0),
        );
        let out = eng2.auto_tip_for_store(STORE).await.unwrap();
        assert_eq!(out, TipOutcome::skipped("already-tipped-today"));
        assert_eq!(sp2.call_count(), 0);
    }

    // ── event bus does not leak the Sage SyncEvent union ─────────────────

    #[test]
    fn tip_event_bus_publish_with_no_subscribers_is_noop() {
        let bus = TipEventBus::default();
        bus.publish(TipEvent {
            entry: TipLedgerEntry {
                id: 0,
                recipient_ph: owner_hex(),
                store_id: None,
                dig_amount: 1,
                ts: 0,
                day: "1970-01-01".into(),
                txid: None,
                trigger: TipTrigger::Auto,
                kind: TipKind::Dev,
                status: TipStatus::Pending,
            },
        });
        assert_eq!(bus.subscriber_count(), 0);
    }
}
