//! The automated-spend audit record (#376) — this node's source of truth for money it moved
//! WITHOUT per-transaction user approval.
//!
//! # Why this exists, and why it is not a log
//!
//! The node is permitted to sign certain spends automatically, because a recurring per-store cycle
//! cannot be gated on a human pressing approve. **This record is what replaces authorization with
//! accountability.** It is the audit trail for money moved without individual consent, and on a
//! headless install it is the ONLY surface on which that automation is visible at all. That is also
//! why it lives in the node rather than in dig-app: a record owned by the app would leave a headless
//! node spending a person's money with no trail. One record, two views — `dign` and the app's
//! Activity tab both READ this — never two records that must agree.
//!
//! # It models a SPEND, generically
//!
//! Mirror coins are the first producer, not the subject. A record shaped around mirror coins grows a
//! second shape for the second producer, and the person loses the one property that makes automatic
//! signing defensible: a single place where everything spent on their behalf is visible. So a record
//! answers, for any spend: what · when · how much · which asset · on whose authority · what for ·
//! confirmed or failed · and a chain reference that resolves in an explorer.
//!
//! # Three honesty rules the shape enforces, each from a measured legacy defect
//!
//! 1. **Failures are entries, not omissions.** A spend that did not happen because funds were short
//!    is precisely what the person needs to see; a record listing only successes makes a blocked
//!    node look idle. [`SpendJournal::begin`] writes the entry BEFORE the producer can sign, so the
//!    entry cannot be conditional on success.
//! 2. **Never claim what the chain did not confirm.** The legacy TypeScript wrote its record before
//!    confirmation in one path (`ServerCoin.ts:81-86`) and again after in another (`:336-354`), so
//!    its own bookkeeping listed coins that may never have existed. Here only
//!    [`SpendJournal::confirmed`] can produce [`SpendStatus::Confirmed`], and it takes a
//!    [`TargetCoinId`] — the coin the spend CREATED. The legacy `waitForConfirmation` waited for the
//!    FUNDING coin to be spent (`:347`), which a competing spend satisfies identically without the
//!    target ever existing; [`FundingCoinId`] and [`TargetCoinId`] are distinct types precisely so
//!    that confusion cannot be written.
//! 3. **A dropped spend degrades to unresolved, never to silence.** [`RecordedSpend`] settles itself
//!    on [`Drop`]: a producer that returns early, panics, or simply forgets leaves
//!    [`SpendStatus::Unresolved`] behind — an honest "this node signed something and does not know
//!    how it ended", which reconciliation can then chase — rather than a `Pending` entry that reads
//!    like an operation still in flight.
//!
//! # Local state is checked against the chain, never trusted alone
//!
//! The legacy `.json` was authoritative and unrecoverable if lost, and losing it stranded the money.
//! [`reconcile`] takes a [`ChainInventory`] — a chain-side listing of the coins an owner actually
//! holds — and reports both directions of disagreement. The direction that matters most is
//! [`ReconcileReport::unrecorded_on_chain`]: a coin this node's automation should have produced an
//! entry for and did not is invisible money movement, which is the failure this whole feature exists
//! to make impossible. `dig-mirror-coin`'s `query::list`, keyed on the owner puzzle hash with
//! ownership read from the lineage proof, is the intended implementation of that trait; the seam is
//! built now so #377 plugs a producer in without reshaping the record.
//!
//! # Storage
//!
//! An append-only JSONL file in the machine-wide state dir ([`crate::state::state_dir`]). Each line
//! is a full snapshot of one record at one `revision`; the current ledger is the fold that keeps the
//! highest revision per `id`. Append-only means a terminal outcome never rewrites the line that
//! recorded the attempt, so the file is a history rather than a mutable claim. A line that cannot be
//! parsed is COUNTED and reported ([`SpendLedger::unreadable_lines`]) rather than silently dropped:
//! a corrupt audit trail that reads as an empty one is the same lie as a missing entry.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// The audit file's name inside the state dir.
pub const SPEND_AUDIT_FILE: &str = "spend-audit.jsonl";

/// Well-known [`SpendKind`] values. A kind is an open string so a new producer needs no change to
/// this module, but the ones the node ships are named here so the CLI, the app and a script filter
/// on the SAME spelling instead of three guesses.
pub mod kinds {
    /// A mirror coin created or renewed to advertise that this node holds a store (dig-node#377).
    pub const MIRROR_COIN: &str = "mirror-coin";
    /// A test/diagnostic spend. Never produced by an automatic cycle.
    pub const DIAGNOSTIC: &str = "diagnostic";
}

/// What the spend was FOR, as a stable machine-filterable token (see [`kinds`]).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpendKind(String);

impl SpendKind {
    /// Wrap a kind token.
    pub fn new(kind: impl Into<String>) -> Self {
        SpendKind(kind.into())
    }

    /// The token, for filtering and display.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which asset moved. `amount_mojos` on a record is denominated in THIS asset's base units, so an
/// amount is never readable without its asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "asset", rename_all = "snake_case")]
pub enum Asset {
    /// Chia itself.
    Xch,
    /// The $DIG CAT.
    Dig,
    /// Any other CAT, identified by its asset id (lowercase 64-hex).
    Cat {
        /// The CAT's asset id.
        asset_id: String,
    },
}

impl fmt::Display for Asset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asset::Xch => f.write_str("XCH"),
            Asset::Dig => f.write_str("DIG"),
            Asset::Cat { asset_id } => write!(f, "CAT:{asset_id}"),
        }
    }
}

/// ON WHOSE AUTHORITY the node signed without asking.
///
/// Two fields rather than one because a person auditing an unapproved spend asks two different
/// questions: WHO holds the standing permission, and WHICH standing permission was it. A single
/// prose sentence answers neither in a way a filter or a revocation can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authority {
    /// The principal whose funds moved and whose consent is being relied on — an account id, a
    /// profile id, or `"node"` for the node's own operating wallet.
    pub principal: String,
    /// The standing grant relied on, in a form the operator can go and revoke: a setting name, a
    /// policy id, a pairing token id.
    pub grant: String,
}

/// The id of a coin this spend CONSUMED.
///
/// Distinct from [`TargetCoinId`] as a TYPE, not as a convention. The legacy implementation waited
/// for the funding coin to disappear and called that confirmation, which a competing spend of the
/// same coin satisfies identically while the intended coin never exists. Two types make that
/// substitution a compile error instead of a code-review question.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FundingCoinId(pub String);

/// The id of the coin this spend CREATED — the thing whose existence confirms the spend happened.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TargetCoinId(pub String);

impl fmt::Display for TargetCoinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for FundingCoinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where an attempt died. Kept coarse and stable: the point is which STEP failed, because that is
/// what tells a person whether their money is at risk (a broadcast failure may still land) versus
/// definitely untouched (a signing failure cannot have moved anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    /// The spend could not be built or signed — nothing reached the network, no coin moved.
    Signing,
    /// The signed bundle was rejected by the mempool.
    Broadcast,
    /// The bundle went out and the chain then reported it could not succeed.
    Confirmation,
}

impl fmt::Display for FailureStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FailureStage::Signing => "signing",
            FailureStage::Broadcast => "broadcast",
            FailureStage::Confirmation => "confirmation",
        })
    }
}

/// The lifecycle of one automated spend.
///
/// `Confirmed` is reachable ONLY through [`SpendJournal::confirmed`], and carries the height and the
/// created coin INSIDE the variant, so a record cannot hold a confirmation height without a
/// confirmation. That is the shape rule behind honesty rule 2 in the module docs: there is no field
/// to optimistically fill in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SpendStatus {
    /// Recorded, not yet handed to the network. Written before the producer may sign.
    Pending,
    /// A signed bundle was accepted by the mempool. NOT a claim that it will confirm.
    Submitted,
    /// The chain shows the coin this spend created.
    Confirmed {
        /// The height at which the created coin was confirmed.
        height: u32,
        /// The coin the spend created — the chain reference a person can paste into an explorer.
        coin_id: TargetCoinId,
    },
    /// The attempt ended without moving the money it intended to.
    Failed {
        /// Which step failed.
        stage: FailureStage,
        /// One line a person can act on.
        reason: String,
    },
    /// The node signed, and does not know how it ended — a timeout, a restart mid-flight, or a
    /// producer that dropped the spend. Deliberately NOT `Failed`: money may well have moved, and
    /// saying "failed" about a spend that landed is the same class of lie as claiming an
    /// unconfirmed success. [`reconcile`] is how one of these gets resolved.
    Unresolved {
        /// Why the outcome is unknown.
        reason: String,
    },
}

impl SpendStatus {
    /// The stable lowercase token used by `--json`, by the CLI's `--status` filter, and by the app.
    pub fn token(&self) -> &'static str {
        match self {
            SpendStatus::Pending => "pending",
            SpendStatus::Submitted => "submitted",
            SpendStatus::Confirmed { .. } => "confirmed",
            SpendStatus::Failed { .. } => "failed",
            SpendStatus::Unresolved { .. } => "unresolved",
        }
    }

    /// Is this a terminal outcome — one no further observation is expected to change?
    ///
    /// `Unresolved` is NOT terminal: it is the state whose whole purpose is to be chased.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SpendStatus::Confirmed { .. } | SpendStatus::Failed { .. }
        )
    }
}

/// A chain reference a person can check, paired with whether this node actually OBSERVED it.
///
/// The `confirmed` flag is not decoration. Before confirmation the node knows the coin id it INTENDS
/// to create — it is derivable from the spend — and printing that bare id next to the others would
/// present an intention as a fact. The two are surfaced together so the CLI and the app can render
/// "expected" differently from "on chain" without either having to re-derive the distinction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReference {
    /// The coin id to look up.
    pub coin_id: String,
    /// True when this node observed the coin on chain; false when it is only the intended result.
    pub confirmed: bool,
}

/// Everything a producer must state BEFORE it is allowed to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendIntent {
    /// What this spend is for ([`kinds`]).
    pub kind: SpendKind,
    /// One human sentence: why this happened without asking.
    pub purpose: String,
    /// The standing consent being relied on.
    pub authority: Authority,
    /// Which asset moves.
    pub asset: Asset,
    /// How much, in that asset's base units.
    pub amount_mojos: u64,
    /// The network fee, in mojos of XCH.
    pub fee_mojos: u64,
    /// The store this spend serves, when it serves one. Filterable.
    pub store_id: Option<String>,
}

/// One entry in the audit record: a full snapshot of one spend at one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRecord {
    /// Stable id for this spend, assigned at [`SpendJournal::begin`].
    pub id: String,
    /// Monotonic per-spend revision. The ledger is the highest revision per `id`.
    pub revision: u32,
    /// What it was for.
    pub kind: SpendKind,
    /// Why it happened without asking.
    pub purpose: String,
    /// Whose standing consent was relied on.
    pub authority: Authority,
    /// Which asset.
    pub asset: Asset,
    /// How much, in the asset's base units.
    pub amount_mojos: u64,
    /// Network fee in mojos.
    pub fee_mojos: u64,
    /// The store served, when any.
    pub store_id: Option<String>,
    /// When the node decided to spend (unix ms).
    pub initiated_ms: u64,
    /// When this revision was written (unix ms).
    pub updated_ms: u64,
    /// Where in its life it is.
    pub status: SpendStatus,
    /// The coins consumed, once known.
    pub funding_coin_ids: Vec<FundingCoinId>,
    /// The coin the spend is EXPECTED to create. A claim until `status` is `Confirmed`.
    pub intended_coin_id: Option<TargetCoinId>,
}

impl SpendRecord {
    /// The chain reference to show, and whether it was observed. `None` before the node knows any
    /// coin id at all — which is honest: there is nothing to look up yet.
    pub fn chain_reference(&self) -> Option<ChainReference> {
        match &self.status {
            SpendStatus::Confirmed { coin_id, .. } => Some(ChainReference {
                coin_id: coin_id.0.clone(),
                confirmed: true,
            }),
            _ => self.intended_coin_id.as_ref().map(|c| ChainReference {
                coin_id: c.0.clone(),
                confirmed: false,
            }),
        }
    }
}

/// Filters over the record. Every field is an AND; an unset field constrains nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendQuery {
    /// Only spends initiated at or after this unix-ms instant.
    pub since_ms: Option<u64>,
    /// Only spends initiated strictly before this unix-ms instant.
    pub until_ms: Option<u64>,
    /// Only spends serving this store id.
    pub store_id: Option<String>,
    /// Only this kind.
    pub kind: Option<String>,
    /// Only this status token ([`SpendStatus::token`]).
    pub status: Option<String>,
    /// Cap the number of rows returned, newest first. `None` = every match.
    pub limit: Option<usize>,
}

impl SpendQuery {
    /// Does one record satisfy every set filter?
    pub fn matches(&self, r: &SpendRecord) -> bool {
        if self.since_ms.is_some_and(|t| r.initiated_ms < t) {
            return false;
        }
        if self.until_ms.is_some_and(|t| r.initiated_ms >= t) {
            return false;
        }
        if let Some(store) = &self.store_id {
            if r.store_id.as_deref() != Some(store.as_str()) {
                return false;
            }
        }
        if self.kind.as_deref().is_some_and(|k| r.kind.as_str() != k) {
            return false;
        }
        if self
            .status
            .as_deref()
            .is_some_and(|s| r.status.token() != s)
        {
            return false;
        }
        true
    }
}

/// The folded record, plus how much of the file could not be read.
///
/// `unreadable_lines` is part of the answer rather than a log line: an audit trail that lost entries
/// to corruption and reads as a shorter, tidy list is indistinguishable from one where those spends
/// never happened. The CLI prints it, so a person is told their trail is incomplete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendLedger {
    /// One row per spend — the highest revision seen — newest-initiated first.
    pub records: Vec<SpendRecord>,
    /// Lines in the file that could not be parsed as a record.
    pub unreadable_lines: usize,
}

/// The append-only audit file.
#[derive(Debug, Clone)]
pub struct SpendLog {
    path: PathBuf,
}

impl SpendLog {
    /// A log at an explicit path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        SpendLog { path: path.into() }
    }

    /// The node's own log: `<state_dir>/spend-audit.jsonl`. The state dir is the machine-wide one
    /// (#501), so the daemon and the operator's `dign` resolve the SAME file even when the service
    /// runs under another account — the property that makes a headless node auditable at all.
    pub fn in_state_dir() -> Self {
        SpendLog::at(crate::state::state_dir().join(SPEND_AUDIT_FILE))
    }

    /// The file backing this log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one revision. Never rewrites an earlier line.
    pub fn append(&self, record: &SpendRecord) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            crate::state::ensure_dir_restricted(dir)?;
        }
        let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        f.flush()?;
        crate::control::restrict_permissions(&self.path);
        Ok(())
    }

    /// Read and fold the file. A missing file is an EMPTY ledger, not an error: a node that has
    /// never spent automatically is the ordinary case.
    pub fn ledger(&self) -> std::io::Result<SpendLedger> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SpendLedger::default()),
            Err(e) => return Err(e),
        };
        Ok(fold(&text))
    }

    /// The ledger, filtered. Newest-initiated first, then `limit` applied.
    pub fn query(&self, q: &SpendQuery) -> std::io::Result<SpendLedger> {
        let mut ledger = self.ledger()?;
        ledger.records.retain(|r| q.matches(r));
        if let Some(n) = q.limit {
            ledger.records.truncate(n);
        }
        Ok(ledger)
    }
}

/// Fold JSONL text into the current ledger: highest revision per id wins, newest-initiated first.
fn fold(text: &str) -> SpendLedger {
    let mut newest: BTreeMap<String, SpendRecord> = BTreeMap::new();
    let mut unreadable = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SpendRecord>(line) {
            Ok(rec) => match newest.get(&rec.id) {
                Some(existing) if existing.revision >= rec.revision => {}
                _ => {
                    newest.insert(rec.id.clone(), rec);
                }
            },
            Err(_) => unreadable += 1,
        }
    }
    let mut records: Vec<SpendRecord> = newest.into_values().collect();
    // Newest first, with the id as a tiebreak so equal-millisecond entries have a stable order
    // rather than one that changes between reads of the same file.
    records.sort_by(|a, b| {
        b.initiated_ms
            .cmp(&a.initiated_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    SpendLedger {
        records,
        unreadable_lines: unreadable,
    }
}

/// Proof that a durable audit entry exists for a spend that has not been signed yet.
///
/// This is the structural guard. A producer's signing entry point takes `&RecordedSpend`, and the
/// only way to obtain one is [`SpendJournal::begin`], which has already appended a `Pending` entry
/// by the time it returns. So "record as you sign" is not a rule a future producer has to remember —
/// it is the shape of the call. There is no public constructor and no `Default`.
///
/// On [`Drop`] without a settled outcome it appends [`SpendStatus::Unresolved`]. A producer that
/// returns early, panics, or forgets therefore leaves an honest "this node signed something and does
/// not know how it ended" rather than a `Pending` row that reads like work still in progress.
pub struct RecordedSpend {
    id: String,
    log: Arc<SpendLog>,
    /// The CURRENT state of the record, carried forward across revisions.
    ///
    /// Carried forward, not re-cloned from the opening entry: a revision is a full snapshot, so
    /// rebuilding each one from the `Pending` entry would silently drop everything an earlier
    /// revision learned — the coin ids recorded at `submitted` would vanish the moment the spend
    /// settled, leaving a terminal entry with no chain reference to check.
    snapshot: RefCell<SpendRecord>,
    settled: Cell<bool>,
}

impl RecordedSpend {
    /// The audit id of this spend, for correlating with logs and with the CLI.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Append the next revision with a new status.
    fn write(&self, status: SpendStatus, now_ms: u64, mutate: impl FnOnce(&mut SpendRecord)) {
        let rec = {
            let mut cur = self.snapshot.borrow_mut();
            cur.revision += 1;
            cur.updated_ms = now_ms;
            cur.status = status;
            mutate(&mut cur);
            cur.clone()
        };
        // A failed append must not abort the spend that is already in flight, but it MUST be loud:
        // the audit trail is the whole point, and a silently unwritten outcome is the invisible
        // money movement this module exists to prevent.
        if let Err(e) = self.log.append(&rec) {
            tracing::error!(
                target: "spend_audit",
                spend_id = %self.id,
                status = rec.status.token(),
                error = %e,
                "FAILED to append an automated-spend audit entry"
            );
        }
    }
}

impl fmt::Debug for RecordedSpend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedSpend")
            .field("id", &self.id)
            .field("settled", &self.settled.get())
            .finish()
    }
}

impl Drop for RecordedSpend {
    fn drop(&mut self) {
        if self.settled.get() {
            return;
        }
        self.write(
            SpendStatus::Unresolved {
                reason: "the producer ended without recording an outcome".to_string(),
            },
            now_ms(),
            |_| {},
        );
    }
}

/// What a producer learned when it handed a signed bundle to the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// The coin the spend is expected to create — recorded as an EXPECTATION, and only promoted to
    /// a confirmed chain reference by [`SpendJournal::confirmed`].
    pub intended_coin_id: TargetCoinId,
    /// The coins consumed.
    pub funding_coin_ids: Vec<FundingCoinId>,
}

/// The one path an automated spend takes, and the only place `Confirmed` can be produced.
#[derive(Clone)]
pub struct SpendJournal {
    log: Arc<SpendLog>,
    clock: fn() -> u64,
}

impl fmt::Debug for SpendJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendJournal")
            .field("path", &self.log.path())
            .finish()
    }
}

impl SpendJournal {
    /// A journal over a log, using the wall clock.
    pub fn new(log: SpendLog) -> Self {
        SpendJournal {
            log: Arc::new(log),
            clock: now_ms,
        }
    }

    /// A journal with an injected clock, so a test pins time instead of inheriting wall-clock
    /// instants that make every fixture expiry meaningless.
    pub fn with_clock(log: SpendLog, clock: fn() -> u64) -> Self {
        SpendJournal {
            log: Arc::new(log),
            clock,
        }
    }

    /// The log this journal writes, for readers.
    pub fn log(&self) -> &SpendLog {
        &self.log
    }

    /// Record the intent and hand back the permission to sign.
    ///
    /// The `Pending` entry is on disk before this returns, so a crash between here and the network
    /// leaves evidence that the node was ABOUT to move money — which, for a spend nobody approved,
    /// is information the person is entitled to.
    pub fn begin(&self, intent: SpendIntent) -> RecordedSpend {
        let now = (self.clock)();
        let id = new_spend_id(now);
        let record = SpendRecord {
            id: id.clone(),
            revision: 1,
            kind: intent.kind,
            purpose: intent.purpose,
            authority: intent.authority,
            asset: intent.asset,
            amount_mojos: intent.amount_mojos,
            fee_mojos: intent.fee_mojos,
            store_id: intent.store_id,
            initiated_ms: now,
            updated_ms: now,
            status: SpendStatus::Pending,
            funding_coin_ids: Vec::new(),
            intended_coin_id: None,
        };
        if let Err(e) = self.log.append(&record) {
            tracing::error!(
                target: "spend_audit",
                spend_id = %id,
                error = %e,
                "FAILED to append the pending automated-spend audit entry"
            );
        }
        RecordedSpend {
            id,
            log: Arc::clone(&self.log),
            snapshot: RefCell::new(record),
            settled: Cell::new(false),
        }
    }

    /// The signed bundle reached the mempool. Records the coins consumed and the coin EXPECTED.
    pub fn submitted(&self, spend: &RecordedSpend, submission: Submission) {
        spend.write(SpendStatus::Submitted, (self.clock)(), |rec| {
            rec.funding_coin_ids = submission.funding_coin_ids;
            rec.intended_coin_id = Some(submission.intended_coin_id);
        });
    }

    /// The chain shows the coin the spend CREATED.
    ///
    /// `coin_id` is a [`TargetCoinId`] and nothing else will type-check. Confirming against the
    /// funding coin — the legacy bug — is not expressible here: a competing spend of the same
    /// funding coin satisfies "the funding coin is gone" identically while the intended coin never
    /// exists, so that observation proves nothing about this spend.
    pub fn confirmed(&self, spend: &RecordedSpend, coin_id: TargetCoinId, height: u32) {
        spend.settled.set(true);
        spend.write(
            SpendStatus::Confirmed {
                height,
                coin_id: coin_id.clone(),
            },
            (self.clock)(),
            |rec| rec.intended_coin_id = Some(coin_id),
        );
    }

    /// The attempt ended without moving money.
    pub fn failed(&self, spend: &RecordedSpend, stage: FailureStage, reason: impl Into<String>) {
        spend.settled.set(true);
        spend.write(
            SpendStatus::Failed {
                stage,
                reason: reason.into(),
            },
            (self.clock)(),
            |_| {},
        );
    }

    /// The node signed and cannot tell how it ended. Settles the entry so [`Drop`] does not write a
    /// second, less specific one over the top of this reason.
    pub fn unresolved(&self, spend: &RecordedSpend, reason: impl Into<String>) {
        spend.settled.set(true);
        spend.write(
            SpendStatus::Unresolved {
                reason: reason.into(),
            },
            (self.clock)(),
            |_| {},
        );
    }
}

/// A chain-side listing of the coins an owner actually holds — the check that local bookkeeping is
/// honest.
///
/// `dig-mirror-coin`'s `query::list`, keyed on the owner puzzle hash with ownership read from the
/// lineage proof, is the intended implementation; the crate is being uplifted in parallel, so the
/// seam is a trait now and the producer plugs in at #377 without reshaping anything here.
pub trait ChainInventory {
    /// Every coin id this owner holds on chain, for the kinds this inventory covers.
    fn owned_coin_ids(&self, owner_puzzle_hash: &str) -> Result<Vec<String>, String>;
}

/// What the local record and the chain disagree about.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileReport {
    /// Confirmed entries whose coin the chain still shows. The healthy case.
    pub agreed: Vec<String>,
    /// Confirmed entries whose coin the chain does NOT show — a coin that was spent since, or a
    /// confirmation this node should never have written.
    pub missing_on_chain: Vec<String>,
    /// Coins the chain shows that NO entry accounts for. **The direction that matters most:** money
    /// this node's automation moved with no audit entry is invisible money movement.
    pub unrecorded_on_chain: Vec<String>,
    /// Entries the node never resolved, still awaiting an answer.
    pub unresolved: Vec<String>,
}

impl ReconcileReport {
    /// Does anything here need a person's attention?
    pub fn is_clean(&self) -> bool {
        self.missing_on_chain.is_empty()
            && self.unrecorded_on_chain.is_empty()
            && self.unresolved.is_empty()
    }
}

/// Compare the local record against the chain for one owner.
///
/// Only entries with a CONFIRMED coin are matched against the chain: a pending or failed entry makes
/// no claim about a coin existing, so counting it as missing would manufacture a discrepancy out of
/// an honest record.
pub fn reconcile(
    ledger: &SpendLedger,
    inventory: &dyn ChainInventory,
    owner_puzzle_hash: &str,
) -> Result<ReconcileReport, String> {
    let on_chain: std::collections::BTreeSet<String> = inventory
        .owned_coin_ids(owner_puzzle_hash)?
        .into_iter()
        .collect();

    let mut report = ReconcileReport::default();
    let mut accounted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for rec in &ledger.records {
        match &rec.status {
            SpendStatus::Confirmed { coin_id, .. } => {
                accounted.insert(coin_id.0.clone());
                if on_chain.contains(&coin_id.0) {
                    report.agreed.push(coin_id.0.clone());
                } else {
                    report.missing_on_chain.push(coin_id.0.clone());
                }
            }
            SpendStatus::Unresolved { .. } => {
                // An unresolved entry may well have landed; its intended coin therefore ACCOUNTS for
                // a chain coin even though it does not confirm one. Without this, chasing an
                // unresolved spend would report its own coin as unrecorded — the alarm that is
                // supposed to mean "money moved with no entry" would fire on money that has one.
                if let Some(c) = &rec.intended_coin_id {
                    accounted.insert(c.0.clone());
                }
                report.unresolved.push(rec.id.clone());
            }
            SpendStatus::Submitted => {
                if let Some(c) = &rec.intended_coin_id {
                    accounted.insert(c.0.clone());
                }
            }
            SpendStatus::Pending | SpendStatus::Failed { .. } => {}
        }
    }

    report.unrecorded_on_chain = on_chain.difference(&accounted).cloned().collect();
    Ok(report)
}

/// Unix milliseconds now.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A sortable, collision-resistant spend id: the millisecond, a process-wide counter, and the pid.
///
/// The counter is what makes two spends begun in the same millisecond distinct ids; without it the
/// fold would treat them as revisions of one spend and one of the two would vanish from the record.
fn new_spend_id(now_ms: u64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("sp_{now_ms:013}_{:06}_{}", n % 1_000_000, std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pinned instant. Fixture time never rides the wall clock: a record written "now" and
    /// filtered against a hard-coded `since` is a test of the machine's date, not of the filter.
    const NOW: u64 = 1_767_225_600_000;

    fn clock() -> u64 {
        NOW
    }

    fn tmp_log() -> SpendLog {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "dig-node-spend-audit-{}-{}-{}",
            std::process::id(),
            now_ms(),
            n
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        SpendLog::at(dir.join(SPEND_AUDIT_FILE))
    }

    fn intent() -> SpendIntent {
        SpendIntent {
            kind: SpendKind::new(kinds::MIRROR_COIN),
            purpose: "advertise that this node holds the store".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "settings.autoMirror".to_string(),
            },
            asset: Asset::Xch,
            amount_mojos: 1_000,
            fee_mojos: 10,
            store_id: Some("store-a".to_string()),
        }
    }

    /// **A pending entry is durable BEFORE the producer can sign.**
    ///
    /// The fixture reads the file from INSIDE the signing step rather than after it, because the
    /// nearest wrong implementation — buffer the entry and write it when the outcome is known —
    /// passes any assertion made afterwards. Only an observation taken mid-flight can tell "recorded
    /// as it signs" apart from "recorded once it finished".
    #[test]
    fn the_entry_is_on_disk_before_the_producer_signs() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        let recorded = journal.begin(intent());

        // This is the producer's signing step.
        let seen_mid_flight = journal.log().ledger().expect("ledger");
        assert_eq!(seen_mid_flight.records.len(), 1);
        assert_eq!(seen_mid_flight.records[0].status, SpendStatus::Pending);
        assert_eq!(seen_mid_flight.records[0].id, recorded.id());

        journal.failed(&recorded, FailureStage::Signing, "insufficient funds");
    }

    /// **A spend that never happened is an ENTRY, not an omission.**
    ///
    /// A node blocked on funds must not read as an idle node.
    #[test]
    fn a_failed_spend_is_recorded_with_its_stage_and_reason() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        let recorded = journal.begin(intent());
        journal.failed(&recorded, FailureStage::Signing, "insufficient funds");
        drop(recorded);

        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(ledger.records.len(), 1, "one spend, folded to one row");
        assert_eq!(
            ledger.records[0].status,
            SpendStatus::Failed {
                stage: FailureStage::Signing,
                reason: "insufficient funds".to_string(),
            }
        );
    }

    /// **Confirming the FUNDING coin does not confirm the spend.**
    ///
    /// The legacy `waitForConfirmation` waited for the funding coin to be spent, which a competing
    /// spend satisfies identically. The fixture varies ONE actor — a competitor consumes the funding
    /// coin, the target coin never appears — and keeps the honest control below, because a fixture
    /// where nothing lands cannot tell a correct confirmation apart from a broken one.
    #[test]
    fn a_competing_spend_of_the_funding_coin_never_confirms_this_spend() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        let recorded = journal.begin(intent());
        journal.submitted(
            &recorded,
            Submission {
                intended_coin_id: TargetCoinId("target-coin".to_string()),
                funding_coin_ids: vec![FundingCoinId("funding-coin".to_string())],
            },
        );

        // The chain says: funding coin gone (a competitor took it), target coin absent. The producer
        // can therefore observe no target, and the only thing it can honestly write is unresolved.
        journal.unresolved(&recorded, "the target coin did not appear within the window");
        drop(recorded);

        let ledger = journal.log().ledger().expect("ledger");
        let rec = &ledger.records[0];
        assert_eq!(rec.status.token(), "unresolved");
        assert_eq!(
            rec.chain_reference(),
            Some(ChainReference {
                coin_id: "target-coin".to_string(),
                confirmed: false,
            }),
            "an intended coin is reported as a CLAIM, never as an observation"
        );
    }

    /// The honest control for the test above: when the target coin DOES appear, the record confirms
    /// and its chain reference is marked observed.
    #[test]
    fn observing_the_created_coin_confirms_the_spend() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        let recorded = journal.begin(intent());
        journal.submitted(
            &recorded,
            Submission {
                intended_coin_id: TargetCoinId("target-coin".to_string()),
                funding_coin_ids: vec![FundingCoinId("funding-coin".to_string())],
            },
        );
        journal.confirmed(&recorded, TargetCoinId("target-coin".to_string()), 9_000_001);
        drop(recorded);

        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(
            ledger.records[0].status,
            SpendStatus::Confirmed {
                height: 9_000_001,
                coin_id: TargetCoinId("target-coin".to_string()),
            }
        );
        assert_eq!(
            ledger.records[0].chain_reference(),
            Some(ChainReference {
                coin_id: "target-coin".to_string(),
                confirmed: true,
            })
        );
    }

    /// **A producer that forgets cannot leave silence.** Dropping without settling degrades the
    /// entry to `unresolved` — not `pending` (which reads as still in flight) and never `confirmed`.
    #[test]
    fn a_dropped_spend_settles_itself_as_unresolved() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        {
            let recorded = journal.begin(intent());
            journal.submitted(
                &recorded,
                Submission {
                    intended_coin_id: TargetCoinId("target-coin".to_string()),
                    funding_coin_ids: vec![],
                },
            );
            // The producer forgets to settle and returns.
        }
        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(ledger.records[0].status.token(), "unresolved");
    }

    /// A settled entry is not overwritten by the drop guard.
    #[test]
    fn dropping_a_settled_spend_does_not_overwrite_its_outcome() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        {
            let recorded = journal.begin(intent());
            journal.confirmed(&recorded, TargetCoinId("c".to_string()), 5);
        }
        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(ledger.records[0].status.token(), "confirmed");
    }

    /// The file is append-only: every revision survives, and the fold reports the newest.
    #[test]
    fn the_file_keeps_every_revision_and_the_fold_reports_the_newest() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);
        let recorded = journal.begin(intent());
        journal.submitted(
            &recorded,
            Submission {
                intended_coin_id: TargetCoinId("c".to_string()),
                funding_coin_ids: vec![],
            },
        );
        journal.confirmed(&recorded, TargetCoinId("c".to_string()), 7);
        drop(recorded);

        let raw = std::fs::read_to_string(log.path()).expect("file");
        assert_eq!(raw.lines().count(), 3, "pending + submitted + confirmed");
        let ledger = log.ledger().expect("ledger");
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(ledger.records[0].revision, 3);
    }

    /// A corrupt line is COUNTED, never silently dropped — an audit trail that lost entries must not
    /// read as a tidy shorter one.
    #[test]
    fn an_unparseable_line_is_counted_rather_than_hidden() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);
        let recorded = journal.begin(intent());
        journal.failed(&recorded, FailureStage::Broadcast, "rejected");
        drop(recorded);

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .expect("open");
        f.write_all(b"{not json at all\n").expect("write");

        let ledger = log.ledger().expect("ledger");
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(ledger.unreadable_lines, 1);
    }

    /// Two spends begun in the SAME millisecond stay two spends. Without the counter in the id they
    /// would fold into one and the record would quietly lose money movement.
    #[test]
    fn two_spends_in_the_same_millisecond_are_two_records() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);
        let a = journal.begin(intent());
        let b = journal.begin(intent());
        journal.failed(&a, FailureStage::Signing, "a");
        journal.failed(&b, FailureStage::Signing, "b");
        drop(a);
        drop(b);

        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(ledger.records.len(), 2);
    }

    /// A missing file is an empty ledger, not an error.
    #[test]
    fn a_node_that_never_spent_reads_as_an_empty_ledger() {
        let log = SpendLog::at(std::env::temp_dir().join("dig-node-spend-audit-absent/none.jsonl"));
        let ledger = log.ledger().expect("ledger");
        assert!(ledger.records.is_empty());
        assert_eq!(ledger.unreadable_lines, 0);
    }

    fn record_at(id: &str, initiated_ms: u64, kind: &str, store: Option<&str>) -> SpendRecord {
        SpendRecord {
            id: id.to_string(),
            revision: 1,
            kind: SpendKind::new(kind),
            purpose: "p".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "g".to_string(),
            },
            asset: Asset::Dig,
            amount_mojos: 1,
            fee_mojos: 0,
            store_id: store.map(str::to_string),
            initiated_ms,
            updated_ms: initiated_ms,
            status: SpendStatus::Pending,
            funding_coin_ids: vec![],
            intended_coin_id: None,
        }
    }

    /// The time window is inclusive at `since` and exclusive at `until` — pinned from BOTH sides, so
    /// an off-by-one in either direction fails rather than merely confirming itself.
    #[test]
    fn the_time_window_includes_since_and_excludes_until() {
        let q = SpendQuery {
            since_ms: Some(100),
            until_ms: Some(200),
            ..Default::default()
        };
        assert!(!q.matches(&record_at("a", 99, "k", None)), "before since");
        assert!(q.matches(&record_at("b", 100, "k", None)), "at since");
        assert!(q.matches(&record_at("c", 199, "k", None)), "inside");
        assert!(!q.matches(&record_at("d", 200, "k", None)), "at until");
    }

    /// Store, kind and status filters each narrow independently, and a record must satisfy ALL of
    /// them. The fixture varies one field at a time against a row that otherwise matches, so a
    /// filter that is simply ignored fails instead of passing on the neighbours' account.
    #[test]
    fn store_kind_and_status_filters_all_bind() {
        let base = record_at("a", 100, kinds::MIRROR_COIN, Some("store-a"));

        let by_store = SpendQuery {
            store_id: Some("store-a".to_string()),
            ..Default::default()
        };
        assert!(by_store.matches(&base));
        assert!(!by_store.matches(&record_at("b", 100, kinds::MIRROR_COIN, Some("store-b"))));
        assert!(
            !by_store.matches(&record_at("c", 100, kinds::MIRROR_COIN, None)),
            "a storeless spend does not match a store filter"
        );

        let by_kind = SpendQuery {
            kind: Some(kinds::MIRROR_COIN.to_string()),
            ..Default::default()
        };
        assert!(by_kind.matches(&base));
        assert!(!by_kind.matches(&record_at("d", 100, kinds::DIAGNOSTIC, Some("store-a"))));

        let by_status = SpendQuery {
            status: Some("failed".to_string()),
            ..Default::default()
        };
        assert!(!by_status.matches(&base), "base is pending");
        let mut failed = base.clone();
        failed.status = SpendStatus::Failed {
            stage: FailureStage::Broadcast,
            reason: "r".to_string(),
        };
        assert!(by_status.matches(&failed));
    }

    struct FakeChain(Vec<String>);
    impl ChainInventory for FakeChain {
        fn owned_coin_ids(&self, _owner: &str) -> Result<Vec<String>, String> {
            Ok(self.0.clone())
        }
    }

    /// **A coin on chain that no entry accounts for is the alarm.** The fixture keeps THREE distinct
    /// coins — one agreed, one confirmed-but-gone, one on chain with no entry — because a fixture
    /// with a single coin cannot tell the three buckets apart: any implementation that puts
    /// everything in one bucket would satisfy a one-coin assertion.
    #[test]
    fn reconciliation_reports_both_directions_of_disagreement() {
        let ledger = SpendLedger {
            records: vec![
                {
                    let mut r = record_at("agreed", 100, kinds::MIRROR_COIN, None);
                    r.status = SpendStatus::Confirmed {
                        height: 1,
                        coin_id: TargetCoinId("coin-agreed".to_string()),
                    };
                    r
                },
                {
                    let mut r = record_at("gone", 100, kinds::MIRROR_COIN, None);
                    r.status = SpendStatus::Confirmed {
                        height: 1,
                        coin_id: TargetCoinId("coin-gone".to_string()),
                    };
                    r
                },
            ],
            unreadable_lines: 0,
        };
        let chain = FakeChain(vec![
            "coin-agreed".to_string(),
            "coin-nobody-recorded".to_string(),
        ]);

        let report = reconcile(&ledger, &chain, "owner-ph").expect("reconcile");
        assert_eq!(report.agreed, vec!["coin-agreed".to_string()]);
        assert_eq!(report.missing_on_chain, vec!["coin-gone".to_string()]);
        assert_eq!(
            report.unrecorded_on_chain,
            vec!["coin-nobody-recorded".to_string()],
            "money this node moved with no entry is the alarm this whole record exists for"
        );
        assert!(!report.is_clean());
    }

    /// An UNRESOLVED entry accounts for its intended coin. Otherwise chasing an unresolved spend
    /// would report that spend's own coin as unrecorded — the alarm would fire on money that has an
    /// entry, and the real alarm would be lost in the noise.
    #[test]
    fn an_unresolved_entry_accounts_for_its_intended_coin() {
        let mut r = record_at("u", 100, kinds::MIRROR_COIN, None);
        r.status = SpendStatus::Unresolved {
            reason: "timed out".to_string(),
        };
        r.intended_coin_id = Some(TargetCoinId("coin-u".to_string()));
        let ledger = SpendLedger {
            records: vec![r],
            unreadable_lines: 0,
        };

        let report = reconcile(&ledger, &FakeChain(vec!["coin-u".to_string()]), "ph")
            .expect("reconcile");
        assert!(
            report.unrecorded_on_chain.is_empty(),
            "an unresolved entry's own coin is accounted for, not an alarm"
        );
        assert_eq!(report.unresolved, vec!["u".to_string()]);
        assert!(!report.is_clean(), "unresolved still needs attention");
    }

    /// A pending or failed entry claims no coin, so reconciliation must not manufacture a
    /// discrepancy from it.
    #[test]
    fn a_failed_entry_creates_no_discrepancy() {
        let mut r = record_at("f", 100, kinds::MIRROR_COIN, None);
        r.status = SpendStatus::Failed {
            stage: FailureStage::Signing,
            reason: "no funds".to_string(),
        };
        let ledger = SpendLedger {
            records: vec![r],
            unreadable_lines: 0,
        };
        let report = reconcile(&ledger, &FakeChain(vec![]), "ph").expect("reconcile");
        assert!(report.is_clean());
    }

    /// The status tokens are the CLI's `--status` values and the app's filter values. Pinned so a
    /// rename cannot silently break both consumers at once.
    #[test]
    fn status_tokens_are_stable() {
        assert_eq!(SpendStatus::Pending.token(), "pending");
        assert_eq!(SpendStatus::Submitted.token(), "submitted");
        assert_eq!(
            SpendStatus::Confirmed {
                height: 1,
                coin_id: TargetCoinId("c".to_string())
            }
            .token(),
            "confirmed"
        );
        assert_eq!(
            SpendStatus::Failed {
                stage: FailureStage::Signing,
                reason: String::new()
            }
            .token(),
            "failed"
        );
        assert_eq!(
            SpendStatus::Unresolved {
                reason: String::new()
            }
            .token(),
            "unresolved"
        );
    }

    /// The wire field names are a published contract read by `dign --json` and by the app. A rename
    /// here is a breaking change for both, so the shape is pinned rather than left to drift.
    #[test]
    fn the_json_field_names_are_the_published_shape() {
        let mut r = record_at("id-1", NOW, kinds::MIRROR_COIN, Some("store-a"));
        r.status = SpendStatus::Confirmed {
            height: 42,
            coin_id: TargetCoinId("coin-1".to_string()),
        };
        let v = serde_json::to_value(&r).expect("serialize");
        for field in [
            "id",
            "revision",
            "kind",
            "purpose",
            "authority",
            "asset",
            "amount_mojos",
            "fee_mojos",
            "store_id",
            "initiated_ms",
            "updated_ms",
            "status",
            "funding_coin_ids",
            "intended_coin_id",
        ] {
            assert!(v.get(field).is_some(), "missing field {field}");
        }
        assert_eq!(v["status"]["state"], "confirmed");
        assert_eq!(v["status"]["height"], 42);
        assert_eq!(v["status"]["coin_id"], "coin-1");
        assert_eq!(v["asset"]["asset"], "dig", "the fixture spends DIG");
        assert_eq!(v["kind"], kinds::MIRROR_COIN);

        // Round-trips, so an older line written by a previous build still folds.
        let back: SpendRecord = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, r);
    }
}
