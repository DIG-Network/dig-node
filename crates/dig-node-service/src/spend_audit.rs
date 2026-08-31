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
//! Activity tab — never two records that must agree.
//!
//! **This crate is the only reader of the file.** The app's view goes through `dign spends --json`
//! (SPEC §23), so the file's name, location and encoding stay implementation detail and the CLI's
//! JSON envelope is the published contract. A second process parsing this file directly would be a
//! second implementation of one format, which is how two views of "what did the node spend" start
//! disagreeing — on the one subject where disagreeing is least affordable.
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
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// The audit file's name inside the state dir.
///
/// **Node-private, and deliberately not a canonical cross-repo constant.** Only this crate resolves
/// the path; every other view of the record — dig-app's Activity tab included — reads it through
/// `dign spends --json` (SPEC §23). The published contract is the CLI's JSON envelope and the status
/// tokens, not this file name, so a second implementation has nothing here to drift from.
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
///
/// That difference is not commentary — it is load-bearing, and [`Self::money_may_have_moved`] is the
/// ONE place it is decided. Every consumer asks the stage rather than re-listing the variants, so
/// the "it didn't happen" claim cannot be re-attached to a stage that never earned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    /// The spend could not be built or signed — nothing reached the network, no coin moved.
    Signing,
    /// The signed bundle was rejected by the mempool — as far as THIS node saw. A bundle it holds
    /// may still have reached the network by another route, or been accepted after the rejection it
    /// observed.
    Broadcast,
    /// The bundle went out and the chain then reported it could not succeed.
    Confirmation,
}

impl FailureStage {
    /// Could the money have moved anyway, despite the attempt failing at this stage?
    ///
    /// `Signing` is the only stage that answers NO, and it answers it structurally: no signed bundle
    /// ever existed, so there was nothing that could reach a mempool. `Broadcast` and `Confirmation`
    /// both happen AFTER a valid signed bundle exists, and neither observation is a proof of
    /// absence — a rejection this node saw does not bind a network it does not fully observe.
    ///
    /// Written as an exhaustive `match` rather than a negated `matches!` so that adding a stage is a
    /// compile error here, forcing whoever adds it to decide which side it falls on. Guessing that
    /// side wrong is what makes an audit record lie about money.
    pub fn money_may_have_moved(&self) -> bool {
        match self {
            FailureStage::Signing => false,
            FailureStage::Broadcast | FailureStage::Confirmation => true,
        }
    }
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
/// `Confirmed` carries the height and the created coin INSIDE the variant, so a record cannot hold a
/// confirmation height without a confirmation. That is the shape rule behind honesty rule 2 in the
/// module docs: there is no field to optimistically fill in.
///
/// [`SpendJournal::confirmed`] is the only producer of the variant in this crate, and the write path
/// it uses ([`SpendLog::append`]) is private to this module — so no code outside `spend_audit` can
/// put a `Confirmed` line in the file by any route. Within the module the invariant is held by
/// reading these few hundred lines, not by a claim in a doc comment.
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
    /// The attempt ended in a failure this node observed.
    ///
    /// **This is NOT uniformly a claim that the money stayed put.** Only a `Signing` failure carries
    /// that claim; at [`FailureStage::Broadcast`] and [`FailureStage::Confirmation`] a signed bundle
    /// already existed and the outcome is genuinely UNKNOWN. Ask
    /// [`FailureStage::money_may_have_moved`] before treating any `Failed` entry as settled — such an
    /// entry is neither [terminal](Self::is_terminal) nor ignored by [`reconcile`].
    Failed {
        /// Which step failed — and, through [`FailureStage::money_may_have_moved`], whether this
        /// entry claims the money is untouched or merely records where the attempt died.
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
    /// `Unresolved` is NOT terminal: it is the state whose whole purpose is to be chased. Neither is
    /// a `Failed` entry whose stage [may have moved money](FailureStage::money_may_have_moved) — it
    /// is an unknown wearing a failure's name, and calling it settled is how a spend that actually
    /// landed stops being chased.
    /// May this spend's bundle have REACHED THE NETWORK — i.e. is it worth asking the chain about?
    ///
    /// Distinct from [`is_terminal`](Self::is_terminal), and the distinction is the whole point.
    /// `Pending` is NOT terminal (nothing has settled it) but also never left this node, so no coin
    /// can be attributed to it; resolving one would confirm a spend that was never broadcast.
    /// `Failed { stage: Broadcast }` is the mirror case — a failure by name, but the bundle may
    /// already sit in a mempool, so it MUST stay chaseable.
    ///
    /// Written as an exhaustive `match`, like
    /// [`FailureStage::money_may_have_moved`](FailureStage::money_may_have_moved) and for the same
    /// reason: a new variant must be a compile error here, forcing whoever adds it to decide which
    /// side it falls on. A `matches!` at a call site routes around that, which is exactly how
    /// `Failed { stage: Broadcast }` came to be dropped from the resolver's open set.
    pub fn may_have_reached_the_network(&self) -> bool {
        match self {
            SpendStatus::Submitted | SpendStatus::Unresolved { .. } => true,
            SpendStatus::Failed { stage, .. } => stage.money_may_have_moved(),
            SpendStatus::Pending | SpendStatus::Confirmed { .. } => false,
        }
    }

    pub fn is_terminal(&self) -> bool {
        match self {
            SpendStatus::Confirmed { .. } => true,
            SpendStatus::Failed { stage, .. } => !stage.money_may_have_moved(),
            SpendStatus::Pending | SpendStatus::Submitted | SpendStatus::Unresolved { .. } => false,
        }
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

/// The exact bond a mirror-coin spend is FOR: `(store, root, epoch)`.
///
/// Recorded structurally, beside `store_id`, so the in-flight ledger can be re-derived from the
/// record ALONE after a restart. `purpose` names the same three things in a sentence, and parsing
/// that sentence would make the suppression rule depend on prose nobody promised to keep stable.
///
/// `store_id` alone is not enough and the difference is not academic: suppressing per store would
/// withhold a legitimate create for a DIFFERENT root of the same store while an unrelated one is in
/// flight, which is a bond the node holds and does not advertise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditedBond {
    /// Generation root hash (lowercase 64-hex).
    pub root: String,
    /// The mirror epoch this spend bonds.
    pub epoch: i64,
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
    /// The `(root, epoch)` half of a bond, for spends that bond one. `None` for every other kind.
    #[serde(default)]
    pub bond: Option<AuditedBond>,
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
    /// The `(root, epoch)` this spend bonds, when it bonds one.
    ///
    /// Carried through from the intent so a pass reading the record back — after a restart, with no
    /// memory of what it submitted — can tell which `(store, root, epoch)` create is already in
    /// flight (`SPEC.md` §25.4.6). `#[serde(default)]` so records written before this field existed
    /// still parse: an older entry answers `None`, which suppresses nothing, and the pass then makes
    /// a duplicate-free decision from the chain instead.
    #[serde(default)]
    pub bond: Option<AuditedBond>,
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

    /// Does this record still hold its funding coins out of selection, as of `now_ms`?
    ///
    /// Two conditions, and they answer different questions. The status must be non-terminal — the
    /// bundle's outcome is genuinely unsettled, so its coins may still be consumed. AND the hold
    /// must not have lapsed: see [`FUNDING_RESERVATION_WINDOW_MS`] for why a status alone cannot
    /// bound this, and how the window is derived.
    ///
    /// Measured from `updated_ms`, the instant of the LAST revision, rather than from
    /// `initiated_ms`. The two differ for a spend that was resolved and then reopened, and it is the
    /// last OBSERVATION that says how long the node has been waiting — restarting the clock on new
    /// information is the honest reading, and it is also the one that holds longer.
    ///
    /// `saturating_sub` so a record dated in the future stays HELD rather than lapsing instantly.
    pub fn reserves_funding_at(&self, now_ms: u64) -> bool {
        !self.status.is_terminal()
            && now_ms.saturating_sub(self.updated_ms) < FUNDING_RESERVATION_WINDOW_MS
    }
}

/// How long the audit record holds a spend's funding coins out of selection, measured from the last
/// thing this node OBSERVED about that spend (dig-node#471).
///
/// # Why a bound is needed at all, when `is_terminal` already answers the question
///
/// [`SpendStatus::is_terminal`] answers "is any further observation expected to change this", and
/// that is the right question for a spend whose outcome eventually ARRIVES. The resolver added in
/// dig-node#457 promotes only POSITIVELY — on observing the created coin — so a `Submitted` or
/// `Unresolved` spend whose coin never appears is never settled by anything, and a predicate keyed
/// on status alone therefore withholds its coins forever. A genuinely funded operator wallet then
/// reports `Insufficient` permanently.
///
/// That is reachable with no attacker present: a hard kill between
/// [`SpendJournal::begin`] and any outcome, or a `Submitted` bundle evicted from a mempool without
/// confirming. And unlike §25.4.6's create suppression — keyed on the bond's epoch, so it self-clears
/// at the rollover — nothing here lapses on its own.
///
/// # How the figure is DERIVED, and where the derivation stops
///
/// Two named quantities, neither invented here:
///
/// * **The chain-side figure is ten minutes.** `dig_wallet`'s own post-broadcast
///   `RESERVATION_TTL_MS` holds a pushed bundle's inputs for `10 * 60 * 1000` ms, and its rationale
///   is written out in that crate: Chia blocks are ~52 s apart, so ten minutes is roughly a dozen
///   chances for the spend to land — past the point where a still-unconfirmed bundle is more likely
///   dropped than pending. This module covers the SAME phase of the same lifecycle, so it takes the
///   same figure rather than inventing a second one. Two lifetimes for one phase is the
///   disagreement `CLIENT_RESERVATION_DEFAULT_TTL_MS` was written to resolve, not to repeat.
///
/// * **This hold is re-evaluated only once per `MIRROR_ROUND_LENGTH_MS`**, which is also ten
///   minutes. A threshold equal to the poll interval aliases badly: a record could be released by
///   the very first pass at which the resolver is even ELIGIBLE to have observed its confirmation.
///   The smallest window that leaves a full round of chain observation AFTER the chain-side figure
///   has elapsed is therefore two rounds.
///
/// **Twenty minutes, i.e. N = 2 passes.** The second round is the part that is this module's
/// judgement rather than dig-wallet's, and it is stated so nobody reads the whole figure as derived.
///
/// # Which direction it fails in
///
/// Releasing too EARLY re-opens dig-node#348's double-select: a second create draws a coin the first
/// bundle can still spend, and the mempool refuses one of them. Releasing too LATE strands spendable
/// money in a wallet that reports `Insufficient`. Neither is free, which is why this is a window and
/// not a flag — but note the two are not symmetric here, because §25.4.6 still suppresses a second
/// create for the SAME `(store, root, epoch)` while the record is open. A released coin can only be
/// re-drawn by a create for a DIFFERENT bond, and that collision fails CLOSED at the mempool.
///
/// # What this must NOT be confused with
///
/// It is emphatically not a shortening of `RESERVATION_TTL_MS`, which the wallet's own docs record
/// as trading a double-select for a LOCKOUT — the strictly worse failure, and the one dig-node#471
/// is an instance of arriving by another route.
pub const FUNDING_RESERVATION_WINDOW_MS: u64 = 2 * dig_constants::MIRROR_ROUND_LENGTH_MS as u64;

/// The audit record could not be read, so which coins are already committed is UNKNOWN.
///
/// Its own type rather than an `io::Error` because the two conditions it covers are different and
/// both are refusals: the file could not be read at all, and the file was read but LOST LINES. A
/// reservation set that silently shrinks is worse than none — the lost lines may be exactly the ones
/// naming a committed coin — so a partial read is an error here and never a shorter answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentsUnreadable(pub String);

impl fmt::Display for CommitmentsUnreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let CommitmentsUnreadable(detail) = self;
        write!(
            f,
            "the spend audit record is unreadable ({detail}), so which coins are already committed \
             to an in-flight bundle is unknown; no coin is selected"
        )
    }
}

impl std::error::Error for CommitmentsUnreadable {}

/// The coins this node has committed to a bundle whose outcome is not yet settled AND whose hold
/// has not yet lapsed (dig-node#421, bounded by dig-node#471).
///
/// Read from the audit record rather than a side table, because the audit record survives a restart
/// and the window this guards is measured in confirmation times, which outlast a process.
///
/// # The hold is a TIME BOX, not a status
///
/// A record whose hold lapses is not rewritten, not settled, and not failed. It stays exactly the
/// `Submitted` or `Unresolved` it was, and stays chaseable by
/// [`SpendJournal::resolve_landed`] and [`reconcile`] indefinitely — `Unresolved` means "this node
/// signed and does not know what happened", and that remains true after the coins are released.
/// Writing a fabricated failure to tidy the bookkeeping would be the money lie `Confirmed`'s shape,
/// which carries its height and coin id INSIDE the variant, exists to make inexpressible.
///
/// # `now_ms` is a parameter, deliberately
///
/// One pass takes ONE reading of the clock, in the same way it takes one reading of the disk, the
/// balance and the chain. It is also what lets a test pin fixture time explicitly instead of passing
/// a small number through a wall-clock API and silently exercising only the already-lapsed path.
///
/// A record dated in the FUTURE — clock skew, or a file written by a machine ahead of this one —
/// yields a saturated elapsed time of zero and stays held. That is the closed direction.
pub fn committed_funding_coin_ids(
    log: &SpendLog,
    now_ms: u64,
) -> Result<HashSet<String>, CommitmentsUnreadable> {
    let ledger = log
        .ledger()
        .map_err(|e| CommitmentsUnreadable(e.to_string()))?;
    if ledger.unreadable_lines > 0 {
        return Err(CommitmentsUnreadable(format!(
            "{} entries could not be parsed",
            ledger.unreadable_lines
        )));
    }
    Ok(ledger
        .records
        .iter()
        .filter(|r| r.reserves_funding_at(now_ms))
        .flat_map(|r| r.funding_coin_ids.iter().map(|c| c.0.clone()))
        .collect())
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
    /// Resume STRICTLY AFTER this audit id, in the read's documented order. `None` starts at the
    /// newest matching row.
    ///
    /// Positional, not a filter, which is why [`SpendQuery::matches`] does not consider it: it
    /// names a place in an ordering rather than a property of a record. Resuming by TIME instead
    /// would drop every spend sharing the boundary millisecond, and automated spends are issued by
    /// a cycle, so several routinely share one.
    pub after_id: Option<String>,
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
    /// Is this the WHOLE matching set, or was it TRUNCATED?
    ///
    /// Stated rather than inferred from the row count. A caller cannot tell "there are no more
    /// spends" from "we stopped telling you" by length alone -- a matching set that is an exact
    /// multiple of the page size makes the last full page indistinguishable from a truncated one --
    /// and on an audit record those two read the same and mean opposite things.
    ///
    /// Spelled positively so that the reading a caller falls into when the field is defaulted is
    /// the SAFE one: `false` means "there may be more", which costs at worst one redundant request,
    /// whereas a `truncated` flag would default to "this is everything" and end a walk early.
    pub complete: bool,
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
    ///
    /// Deliberately PRIVATE to this module. It takes an arbitrary [`SpendRecord`], so a public
    /// version would be a second way to produce any status — including `Confirmed` — bypassing
    /// [`SpendJournal`] entirely and making every honesty rule in the module docs advisory. The
    /// journal is the only writer; this is how that is enforced rather than merely documented.
    fn append(&self, record: &SpendRecord) -> std::io::Result<()> {
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
            // A node that has never spent automatically is the ordinary case, and its answer is
            // COMPLETE -- `SpendLedger::default()` alone would say "there may be more", which is
            // the safe default for a page but the wrong answer for the whole record.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SpendLedger {
                    complete: true,
                    ..SpendLedger::default()
                })
            }
            Err(e) => return Err(e),
        };
        Ok(fold(&text))
    }

    /// One PAGE of the ledger: filtered, ordered, resumed from `after_id`, then capped by `limit`.
    ///
    /// The returned [`SpendLedger::complete`] states whether the page is the whole matching set.
    /// It is computed from whether rows were actually withheld, never from whether the page came
    /// out full, because a matching set that is an exact multiple of the page size fills the last
    /// page and would read as truncated forever.
    ///
    /// # An unknown cursor is an ERROR, not an empty page and not a restart
    ///
    /// A caller passing an `after_id` that is not in the matching set has lost its place. Silently
    /// restarting from the newest row would repeat rows it has already seen, and returning an empty
    /// page would either end its walk early (with `complete`) or leave it with no cursor to advance
    /// (without), i.e. looping forever. Refusing says what happened and terminates.
    pub fn query(&self, q: &SpendQuery) -> std::io::Result<SpendLedger> {
        let mut ledger = self.ledger()?;
        ledger.records.retain(|r| q.matches(r));

        if let Some(after) = &q.after_id {
            let Some(at) = ledger.records.iter().position(|r| &r.id == after) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown cursor {after:?}: no matching spend has that id"),
                ));
            };
            ledger.records.drain(..=at);
        }

        if let Some(n) = q.limit {
            ledger.complete = ledger.records.len() <= n;
            ledger.records.truncate(n);
        }
        Ok(ledger)
    }

    /// The id to resume this page from -- the id of the last row actually HANDED to the caller, or
    /// `None` for an empty page.
    ///
    /// A method on the log rather than on the ledger's caller so that the cursor and the ordering
    /// cannot be defined in two places. It is never a marker for where the record "got to".
    pub fn cursor_of(ledger: &SpendLedger) -> Option<String> {
        ledger.records.last().map(|r| r.id.clone())
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
        // The whole file was folded, so this is the entire record by construction. Paging narrows
        // it afterwards, in `SpendLog::query`, which is the only place that can withhold a row.
        complete: true,
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
    ///
    /// `None` where the producer cannot DERIVE the created coin — a mirror create takes its output
    /// coin's parent from whichever input the builder draws it from, and this node does not know
    /// which. Optional rather than absent because the two facts a submission carries are
    /// independent: the coins CONSUMED are read from the signed bundle and are always known, while
    /// the coin CREATED sometimes is not. Coupling them — the shape this replaced — meant a
    /// producer with no derivable target had no way to record the consumed coins either, so the
    /// reservation set in [`crate::mirror::funding`] was silently never fed by the create path.
    pub intended_coin_id: Option<TargetCoinId>,
    /// The coins consumed. Read from the signed bundle, so this is known on every submission.
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
            bond: intent.bond,
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
    ///
    /// Called on EVERY successful broadcast, including one whose created coin the producer cannot
    /// derive. Reaching the mempool is a thing the node observed, so `Submitted` is the truthful
    /// status for it; not knowing the resulting coin id is a separate, narrower ignorance, and it
    /// is recorded as `intended_coin_id: None` rather than by withholding the whole entry. The
    /// difference is load-bearing: the consumed coins are what
    /// [`crate::mirror::funding::committed_funding_coin_ids`] reserves against, so an unrecorded
    /// submission lets the next pass re-select the very coins this bundle is spending.
    pub fn submitted(&self, spend: &RecordedSpend, submission: Submission) {
        spend.write(SpendStatus::Submitted, (self.clock)(), |rec| {
            rec.funding_coin_ids = submission.funding_coin_ids;
            rec.intended_coin_id = submission.intended_coin_id;
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

/// What an id-keyed resolution attempt did.
///
/// Four outcomes rather than a `bool`, because three of them are "nothing was written" for reasons
/// that call for different responses: a missing id is a bug in the caller, an already-terminal
/// record is the ordinary case on a second pass, and a record that never reached the network is a
/// refusal. Collapsing them would make the one that matters — a resolver silently writing nothing,
/// forever — indistinguishable from the healthy case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// A `Confirmed` revision was appended.
    Recorded,
    /// No record in the ledger carries that id.
    NoSuchSpend,
    /// The record is settled already, or never left this node. Nothing was written.
    NotOpen,
}

impl SpendJournal {
    /// Resolve a spend recorded in an EARLIER pass to [`SpendStatus::Confirmed`], keyed by its
    /// audit id.
    ///
    /// # Why this exists AT ALL, and why it is here rather than in the producer
    ///
    /// [`RecordedSpend`] is the only handle [`Self::confirmed`] accepts, and a mirror pass drops
    /// every handle it opened when the pass ends. A mirror spend is broadcast in one pass and
    /// confirms during the NEXT one, so by the time the chain can answer, the handle that could
    /// have recorded the answer no longer exists — which is why `confirmed` had zero production
    /// callers and every successfully broadcast mirror spend settled as
    /// [`SpendStatus::Unresolved`] on drop (dig-node#412). This is the id-keyed entry point that a
    /// later pass can use.
    ///
    /// It is INSIDE this module by necessity, not by preference. [`SpendLog::append`] is
    /// module-private, and `Confirmed` is producible only through this type — so a resolver living
    /// anywhere else could not write the file at all, and making the write path public to let it
    /// would be a second producer of `Confirmed`, which is the one status the module's honesty
    /// rules are built around.
    ///
    /// # What it will NOT do
    ///
    /// `height` and `coin_id` are the caller's OBSERVATION of the chain, exactly as they are for
    /// [`Self::confirmed`], and this method adds no inference of its own. It refuses:
    ///
    /// - an id it cannot find — [`Resolution::NoSuchSpend`], never an append that invents a record;
    /// - a record that is already `Confirmed` or `Failed`, so a terminal outcome is never rewritten;
    /// - a record still `Pending` — nothing was handed to the network, so no coin of this spend can
    ///   be on chain, and a confirmation against one would be attributing a stranger's coin.
    ///
    /// That leaves exactly [`SpendStatus::Submitted`] and [`SpendStatus::Unresolved`]: the two
    /// states in which a signed bundle exists and its fate is genuinely unknown.
    ///
    /// An `Err` is an I/O failure reading or appending. It resolves nothing, which is the direction
    /// that costs a retry rather than a false confirmation.
    pub fn resolve_landed(
        &self,
        id: &str,
        coin_id: TargetCoinId,
        height: u32,
    ) -> std::io::Result<Resolution> {
        let ledger = self.log.ledger()?;
        let Some(current) = ledger.records.iter().find(|r| r.id == id) else {
            return Ok(Resolution::NoSuchSpend);
        };
        // OPEN here means "the bundle may have reached the network", which is NOT the same question
        // as `is_terminal`. See `SpendStatus::may_have_reached_the_network`.
        if !current.status.may_have_reached_the_network() {
            return Ok(Resolution::NotOpen);
        }

        // A full snapshot at the next revision, carried forward from the record on disk — the same
        // rule `RecordedSpend::write` follows. Rebuilding it from anything narrower would drop the
        // funding coin ids this spend consumed, and those are what the next pass reserves against.
        let mut next = current.clone();
        next.revision += 1;
        next.updated_ms = (self.clock)();
        next.status = SpendStatus::Confirmed {
            height,
            coin_id: coin_id.clone(),
        };
        next.intended_coin_id = Some(coin_id);
        self.log.append(&next)?;
        Ok(Resolution::Recorded)
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
    /// Entries whose outcome this node does not know, still awaiting an answer — every
    /// [`SpendStatus::Unresolved`] entry, AND every [`SpendStatus::Failed`] one whose stage
    /// [may have moved money](FailureStage::money_may_have_moved). The two are one bucket because
    /// they are one situation: a signed bundle exists and the chain has not told us how it ended.
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
/// Only entries with a CONFIRMED coin are matched against the chain: a pending entry, or one that
/// failed before anything was signed, makes no claim about a coin existing, so counting it as
/// missing would manufacture a discrepancy out of an honest record.
///
/// The other direction is the one that matters. An entry whose outcome is UNKNOWN — `Unresolved`,
/// or `Failed` at a stage that [may have moved money](FailureStage::money_may_have_moved) — accounts
/// for its intended coin, so finding that coin on chain does not fire the
/// [`ReconcileReport::unrecorded_on_chain`] alarm. That alarm means "money moved with no audit
/// entry"; an entry exists here, and it says the outcome is unknown, which is the truth.
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
            // A failure at a stage that may still have moved money is an UNKNOWN, not a settled
            // "it didn't happen". It therefore behaves exactly like `Unresolved` here: its intended
            // coin ACCOUNTS for a chain coin, and the entry is reported as awaiting an answer.
            // Without this, a broadcast-failed spend that actually landed puts its own coin in
            // `unrecorded_on_chain` — the field that means "money moved with no audit entry" —
            // while an entry for it sits in the file saying the opposite.
            SpendStatus::Failed { stage, .. } if stage.money_may_have_moved() => {
                if let Some(c) = &rec.intended_coin_id {
                    accounted.insert(c.0.clone());
                }
                report.unresolved.push(rec.id.clone());
            }
            // Everything left claims no coin: `Pending` never signed, and the only `Failed` stage
            // still reaching here is one that could not have moved anything.
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
    format!(
        "sp_{now_ms:013}_{:06}_{}",
        n % 1_000_000,
        std::process::id()
    )
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
            bond: None,
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
                intended_coin_id: Some(TargetCoinId("target-coin".to_string())),
                funding_coin_ids: vec![FundingCoinId("funding-coin".to_string())],
            },
        );

        // The chain says: funding coin gone (a competitor took it), target coin absent. The producer
        // can therefore observe no target, and the only thing it can honestly write is unresolved.
        journal.unresolved(
            &recorded,
            "the target coin did not appear within the window",
        );
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
                intended_coin_id: Some(TargetCoinId("target-coin".to_string())),
                funding_coin_ids: vec![FundingCoinId("funding-coin".to_string())],
            },
        );
        journal.confirmed(
            &recorded,
            TargetCoinId("target-coin".to_string()),
            9_000_001,
        );
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
                    intended_coin_id: Some(TargetCoinId("target-coin".to_string())),
                    funding_coin_ids: vec![],
                },
            );
            // The producer forgets to settle and returns.
        }
        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(ledger.records[0].status.token(), "unresolved");
    }

    /// **A producer that PANICS mid-spend still leaves an honest unknown, not silence.**
    ///
    /// The forgetful-producer test above returns normally, which a guard implemented as an explicit
    /// call at the end of the happy path would also satisfy. Only an unwind distinguishes "the guard
    /// is `Drop`" from "the guard is the last statement" — and a panic between signing and settling
    /// is exactly when the record matters most, because that is when the node has handed a bundle to
    /// the network and then lost track of it.
    ///
    /// The assertions also pin what the guard carries FORWARD: exactly one entry, and the
    /// `intended_coin_id` learned at `submitted` still present. A guard that rebuilt the record from
    /// the opening `Pending` entry would write an unresolved row with no coin to chase, which is
    /// silence wearing an entry's clothes.
    #[test]
    fn a_producer_that_panics_still_leaves_an_unresolved_entry_with_its_coin() {
        let journal = SpendJournal::with_clock(tmp_log(), clock);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let recorded = journal.begin(intent());
            journal.submitted(
                &recorded,
                Submission {
                    intended_coin_id: Some(TargetCoinId("target-coin".to_string())),
                    funding_coin_ids: vec![FundingCoinId("funding-coin".to_string())],
                },
            );
            panic!("the producer blew up after handing the bundle to the network");
        }));
        assert!(panicked.is_err(), "the fixture must actually unwind");

        let ledger = journal.log().ledger().expect("ledger");
        assert_eq!(
            ledger.records.len(),
            1,
            "one spend, one current row — the guard must not double-write"
        );
        let rec = &ledger.records[0];
        assert_eq!(
            rec.status.token(),
            "unresolved",
            "a panic between signing and settling is an unknown outcome, never silence and never a \
             pending row that reads as work in flight"
        );
        assert_eq!(
            rec.intended_coin_id,
            Some(TargetCoinId("target-coin".to_string())),
            "the coin learned at submitted must survive into the unresolved row, or there is \
             nothing for reconciliation to chase"
        );
        assert_eq!(
            rec.funding_coin_ids,
            vec![FundingCoinId("funding-coin".to_string())]
        );
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
                intended_coin_id: Some(TargetCoinId("c".to_string())),
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
            bond: None,
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
            // A hand-built whole record, not a page.
            complete: true,
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
            // A hand-built whole record, not a page.
            complete: true,
        };

        let report =
            reconcile(&ledger, &FakeChain(vec!["coin-u".to_string()]), "ph").expect("reconcile");
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
            // A hand-built whole record, not a page.
            complete: true,
        };
        let report = reconcile(&ledger, &FakeChain(vec![]), "ph").expect("reconcile");
        assert!(report.is_clean());
    }

    /// **A BROADCAST failure is an unknown, not a settled "it didn't happen" — and reconciliation
    /// must account for it.**
    ///
    /// The property: a spend that failed at a stage where money may still have moved must (a) not be
    /// terminal, (b) account for its intended coin so that coin is not reported as untracked money
    /// movement, and (c) be surfaced as still awaiting an answer.
    ///
    /// The nearest wrong implementation is the collapse this test exists to exclude: treat every
    /// `Failed` alike — terminal, and accounted for by nothing. Under it, `coin-broadcast` (which IS
    /// on chain) lands in `unrecorded_on_chain`, the field documented as money moved with NO audit
    /// entry, while an entry for it sits in the file saying the opposite.
    ///
    /// The fixture varies one actor and keeps two truthful controls, because the assertions that
    /// matter here are all about a set being empty or not, and an implementation that simply
    /// suppressed the alarm would satisfy a one-actor version identically:
    ///
    /// * `coin-nobody-recorded` is on chain with no entry at all and MUST still raise the alarm — so
    ///   a fix that empties `unrecorded_on_chain` wholesale fails.
    /// * a SIGNING failure MUST stay terminal and silent — so a fix that reclassifies every failure
    ///   as an unknown fails too.
    #[test]
    fn a_broadcast_failure_is_unresolved_and_accounts_for_its_intended_coin() {
        let broadcast_failed = {
            let mut r = record_at("b", 100, kinds::MIRROR_COIN, None);
            r.status = SpendStatus::Failed {
                stage: FailureStage::Broadcast,
                reason: "mempool rejected".to_string(),
            };
            r.intended_coin_id = Some(TargetCoinId("coin-broadcast".to_string()));
            r
        };
        // Control: nothing was ever signed, so this one genuinely did not happen.
        let signing_failed = {
            let mut r = record_at("s", 100, kinds::MIRROR_COIN, None);
            r.status = SpendStatus::Failed {
                stage: FailureStage::Signing,
                reason: "insufficient funds".to_string(),
            };
            r.intended_coin_id = Some(TargetCoinId("coin-never-signed".to_string()));
            r
        };

        assert!(
            !broadcast_failed.status.is_terminal(),
            "a broadcast failure may have landed, so it is an unknown to be chased, not a settled \
             outcome"
        );
        assert!(
            signing_failed.status.is_terminal(),
            "a signing failure genuinely did not happen — reclassifying it would make every \
             failure an unknown and the distinction useless"
        );

        let ledger = SpendLedger {
            records: vec![broadcast_failed, signing_failed],
            unreadable_lines: 0,
            // A hand-built whole record, not a page.
            complete: true,
        };
        // The broadcast-failed spend DID land; a coin nobody recorded is also present.
        let chain = FakeChain(vec![
            "coin-broadcast".to_string(),
            "coin-nobody-recorded".to_string(),
        ]);

        let report = reconcile(&ledger, &chain, "owner-ph").expect("reconcile");

        assert_eq!(
            report.unrecorded_on_chain,
            vec!["coin-nobody-recorded".to_string()],
            "a broadcast-failed spend that landed has an ENTRY, so its coin is not untracked money \
             movement; the coin with no entry at all still is"
        );
        assert_eq!(
            report.unresolved,
            vec!["b".to_string()],
            "the broadcast failure is still awaiting an answer; the signing failure is not"
        );
        assert!(
            !report.is_clean(),
            "an outcome the node does not know needs a person's attention"
        );
    }

    /// Every stage's answer to "could the money have moved?" is pinned, from BOTH sides. A predicate
    /// tested only where it says `false` can only confirm itself.
    #[test]
    fn only_a_signing_failure_claims_the_money_stayed_put() {
        assert!(
            !FailureStage::Signing.money_may_have_moved(),
            "no signed bundle ever existed"
        );
        assert!(
            FailureStage::Broadcast.money_may_have_moved(),
            "a rejection this node saw is not a proof of absence on the network"
        );
        assert!(
            FailureStage::Confirmation.money_may_have_moved(),
            "the bundle went out before the chain reported it could not succeed"
        );
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

    /// Six spends across THREE distinct timestamps, two sharing a millisecond.
    ///
    /// The shared millisecond is the whole point: automated spends are issued by a cycle, so
    /// several routinely land in one instant, and a cursor that resumed by TIME rather than by id
    /// would drop one of a tied pair. A fixture whose timestamps were all distinct could not tell a
    /// correct cursor from a time-based one.
    ///
    /// The kinds and store ids are varied too, so a filter that ignored its argument would be
    /// visible rather than vacuously satisfied.
    fn paging_log() -> (tempfile::TempDir, SpendLog) {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let rows = [
            ("a", 300u64, kinds::MIRROR_COIN, Some("store-1")),
            ("b", 200, kinds::MIRROR_COIN, Some("store-1")),
            ("c", 200, kinds::MIRROR_COIN, Some("store-2")),
            ("d", 100, "profile-mint", Some("store-2")),
            ("e", 100, kinds::MIRROR_COIN, None),
            ("f", 100, kinds::MIRROR_COIN, Some("store-1")),
        ];
        for (id, ms, kind, store) in rows {
            let rec = record_at(id, ms, kind, store);
            log.append(&rec).expect("append");
        }
        (dir, log)
    }

    /// Walk the whole record one page at a time, as a client would.
    fn walk(log: &SpendLog, page: usize) -> (Vec<String>, usize) {
        let mut seen = Vec::new();
        let mut after = None;
        let mut requests = 0;
        loop {
            let q = SpendQuery {
                after_id: after.clone(),
                limit: Some(page),
                ..SpendQuery::default()
            };
            let ledger = log.query(&q).expect("page");
            requests += 1;
            seen.extend(ledger.records.iter().map(|r| r.id.clone()));
            if ledger.complete {
                return (seen, requests);
            }
            after = SpendLog::cursor_of(&ledger);
            assert!(
                after.is_some(),
                "an incomplete page must hand back a cursor"
            );
            assert!(requests < 20, "walk did not terminate");
        }
    }

    #[test]
    fn the_documented_order_is_newest_first_then_id_ascending() {
        let (_dir, log) = paging_log();
        let all = log.query(&SpendQuery::default()).expect("all");
        // 300 first; then the 200-tie broken by ASCENDING id (b before c); then the 100-tie
        // (d, e, f). A descending-id tiebreak would give c,b and f,e,d and is the nearest wrong
        // implementation this ordering has.
        assert_eq!(
            all.records
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "c", "d", "e", "f"]
        );
    }

    #[test]
    fn a_walk_visits_every_row_exactly_once_across_a_tied_millisecond() {
        let (_dir, log) = paging_log();
        // Page size 2 puts a boundary INSIDE the 100ms tie (d|e), which is precisely where a
        // time-based cursor loses or repeats a row. A page size of 6 would see nothing.
        let (seen, requests) = walk(&log, 2);
        assert_eq!(seen, ["a", "b", "c", "d", "e", "f"]);
        assert!(
            requests > 1,
            "page size 2 over 6 rows must take several requests"
        );
        // And an odd page size, so the last page is PARTIAL rather than exactly full.
        assert_eq!(walk(&log, 4).0, ["a", "b", "c", "d", "e", "f"]);
    }

    #[test]
    fn complete_is_not_inferred_from_a_full_page() {
        let (_dir, log) = paging_log();
        // Six rows, page size 3: the first page is exactly full AND truncated, the second is
        // exactly full AND the end. Any implementation deriving `complete` from
        // `records.len() < limit` reports both as incomplete and walks forever.
        let first = log
            .query(&SpendQuery {
                limit: Some(3),
                ..SpendQuery::default()
            })
            .expect("first");
        assert_eq!(first.records.len(), 3);
        assert!(!first.complete, "rows were withheld");

        let second = log
            .query(&SpendQuery {
                after_id: SpendLog::cursor_of(&first),
                limit: Some(3),
                ..SpendQuery::default()
            })
            .expect("second");
        assert_eq!(second.records.len(), 3);
        assert!(
            second.complete,
            "an exactly-full LAST page is still complete"
        );
        assert_eq!(walk(&log, 3).1, 2, "the walk must stop after two requests");
    }

    #[test]
    fn an_unlimited_read_and_an_empty_record_are_both_complete() {
        let (_dir, log) = paging_log();
        assert!(log.query(&SpendQuery::default()).expect("all").complete);
        // A node that has never spent automatically: an empty COMPLETE answer, never a defaulted
        // "there may be more" that would send a client back for a second look forever.
        let empty = SpendLog::at(
            tempfile::tempdir()
                .expect("tempdir")
                .path()
                .join("never-written.jsonl"),
        );
        let page = empty.query(&SpendQuery::default()).expect("empty");
        assert!(page.records.is_empty());
        assert!(page.complete);
        assert_eq!(SpendLog::cursor_of(&page), None);
    }

    #[test]
    fn the_cursor_is_the_last_row_handed_over_not_the_end_of_the_record() {
        let (_dir, log) = paging_log();
        let first = log
            .query(&SpendQuery {
                limit: Some(2),
                ..SpendQuery::default()
            })
            .expect("first");
        // "b", the last row the caller was HANDED -- not "f", where the record got to.
        assert_eq!(SpendLog::cursor_of(&first), Some("b".to_string()));
    }

    #[test]
    fn a_cursor_narrowed_by_a_filter_still_names_a_position_in_that_filtered_order() {
        let (_dir, log) = paging_log();
        // store-1 holds a, b, f. Resuming after "b" within that filter must give exactly [f] --
        // not [c, d, e, f], which is what a cursor resolved against the UNFILTERED order returns.
        let page = log
            .query(&SpendQuery {
                store_id: Some("store-1".to_string()),
                after_id: Some("b".to_string()),
                ..SpendQuery::default()
            })
            .expect("filtered page");
        assert_eq!(
            page.records
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["f"]
        );
        assert!(page.complete);
    }

    #[test]
    fn an_unknown_cursor_is_refused_rather_than_restarting_or_ending_the_walk() {
        let (_dir, log) = paging_log();
        // "d" exists in the record but NOT in the store-1 matching set, so this is the realistic
        // form of a lost place rather than an obviously bogus id -- an implementation that only
        // rejected ids absent from the whole file would accept it and silently restart.
        let err = log
            .query(&SpendQuery {
                store_id: Some("store-1".to_string()),
                after_id: Some("d".to_string()),
                ..SpendQuery::default()
            })
            .expect_err("an unknown cursor must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("cursor"), "{err}");
    }

    #[test]
    fn unreadable_lines_survive_paging_and_are_not_a_page_count() {
        let (_dir, log) = paging_log();
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .expect("open");
        writeln!(f, "{{not json").expect("write");
        writeln!(f, "also not json").expect("write");
        drop(f);

        // Reported on EVERY page, and it counts the whole record -- a corrupt entry has no parsed
        // timestamp and no parsed id, so it cannot be attributed to a page. A per-page count would
        // read as "two rows are missing from THIS page", which is a different and false claim.
        let page = log
            .query(&SpendQuery {
                limit: Some(1),
                ..SpendQuery::default()
            })
            .expect("page");
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.unreadable_lines, 2);
        assert!(!page.complete);
    }

    /// **A stuck spend's funding coins are released once its hold lapses — and its record is not
    /// touched** (dig-node#471).
    ///
    /// The fixture varies ONE thing: the OBSERVER's clock. Fixture time is pinned at `NOW` through
    /// `with_clock`, so both records are written at exactly the same instant and every difference
    /// below is the elapsed time being asked about. Passing a small number through a wall-clock API
    /// is how a test group asserts the establishment path while exercising only the expired one.
    ///
    /// The control is deliberate and it is a SECOND submitted record, not a confirmed one. A
    /// confirmed control would be released by the pre-#471 predicate too, so a fix that released
    /// EVERYTHING immediately would pass. Two records in the same status, distinguished only by how
    /// long ago they were observed, cannot be satisfied that way.
    #[test]
    fn a_stuck_spend_releases_its_funding_coins_once_the_hold_lapses() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let stuck = journal.begin(intent());
        journal.submitted(
            &stuck,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("11".repeat(32))],
            },
        );
        std::mem::forget(stuck);

        let inside = journal.begin(intent());
        journal.submitted(
            &inside,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("22".repeat(32))],
            },
        );
        std::mem::forget(inside);

        // One millisecond before the window closes, BOTH are held. This is the half most fixes get
        // wrong: without it, a fix that releases every coin unconditionally passes the release
        // assertion below and nothing notices.
        let at_bound =
            committed_funding_coin_ids(&log, NOW + FUNDING_RESERVATION_WINDOW_MS - 1)
                .expect("readable");
        assert!(
            at_bound.contains(&"11".repeat(32)) && at_bound.contains(&"22".repeat(32)),
            "a coin committed to a spend still inside the confirmation window must NOT be \
             released; releasing it re-opens the double-select dig-node#348 closed"
        );

        // One millisecond after, both lapse. Two passes at MIRROR_ROUND_LENGTH_MS: N = 2.
        let lapsed = committed_funding_coin_ids(&log, NOW + FUNDING_RESERVATION_WINDOW_MS)
            .expect("readable");
        assert!(
            lapsed.is_empty(),
            "a spend that never lands must not withhold its funding coins forever; got {lapsed:?}"
        );

        // AND the records are untouched. Releasing the coins is not declaring the spend failed:
        // `Unresolved` means "this node signed and does not know what happened", which stays true.
        let ledger = log.ledger().expect("readable");
        assert_eq!(ledger.records.len(), 2);
        assert!(
            ledger
                .records
                .iter()
                .all(|r| r.status == SpendStatus::Submitted),
            "the hold lapsed; nothing may have written an outcome this node never observed"
        );
        assert!(
            ledger
                .records
                .iter()
                .all(|r| r.status.may_have_reached_the_network()),
            "a released record stays chaseable by resolve_landed and reconcile"
        );
    }

    /// **A record dated in the FUTURE stays held.**
    ///
    /// Clock skew, or an audit file written by a machine ahead of this one. `saturating_sub` makes
    /// the elapsed time zero rather than wrapping to ~584 million years, which would read as
    /// long-lapsed and release a coin that was committed moments ago. The closed direction.
    #[test]
    fn a_record_dated_in_the_future_keeps_its_hold() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let spend = journal.begin(intent());
        journal.submitted(
            &spend,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("33".repeat(32))],
            },
        );
        std::mem::forget(spend);

        let committed = committed_funding_coin_ids(&log, NOW - 1).expect("readable");
        assert!(
            committed.contains(&"33".repeat(32)),
            "a record from the future is not a lapsed record"
        );
    }

    /// **A terminal record releases immediately; the window never EXTENDS a hold.**
    ///
    /// The window bounds a hold from above. It must not become a second reason to withhold a coin
    /// that `is_terminal` already released — a `Confirmed` spend's coins are spent on chain, and a
    /// `Failed { stage: Signing }` spend never moved money.
    #[test]
    fn the_window_never_extends_a_hold_a_terminal_status_already_released() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let confirmed = journal.begin(intent());
        journal.submitted(
            &confirmed,
            Submission {
                intended_coin_id: Some(TargetCoinId("aa".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("11".repeat(32))],
            },
        );
        journal.confirmed(&confirmed, TargetCoinId("aa".repeat(32)), 100);

        let never_signed = journal.begin(intent());
        journal.submitted(
            &never_signed,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("22".repeat(32))],
            },
        );
        journal.failed(&never_signed, FailureStage::Signing, "no key");

        // The control: an open record written at the same instant, still inside its window. Without
        // it, an implementation that released everything at `NOW` would satisfy the two assertions
        // above and look correct.
        let open = journal.begin(intent());
        journal.submitted(
            &open,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("33".repeat(32))],
            },
        );
        std::mem::forget(open);

        let committed = committed_funding_coin_ids(&log, NOW).expect("readable");
        assert_eq!(
            committed,
            HashSet::from(["33".repeat(32)]),
            "only the open, unlapsed record withholds anything"
        );
    }

    /// **A lost line refuses the whole answer, and the window does not change that.**
    ///
    /// The lost lines may be exactly the ones naming a committed coin, so a reservation set that
    /// silently shrinks is worse than none. The fixture keeps a readable, held record beside the
    /// corruption: without it, an implementation that returned an empty set on corruption would be
    /// indistinguishable from one that refused.
    #[test]
    fn a_lost_line_refuses_the_committed_set() {
        let log = tmp_log();
        let journal = SpendJournal::with_clock(log.clone(), clock);

        let spend = journal.begin(intent());
        journal.submitted(
            &spend,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("44".repeat(32))],
            },
        );
        std::mem::forget(spend);

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(log.path())
                .expect("the log");
            writeln!(f, "not-json").expect("append");
        }

        let refused = committed_funding_coin_ids(&log, NOW).expect_err("a lost line refuses");
        assert_eq!(
            refused,
            CommitmentsUnreadable("1 entries could not be parsed".to_string())
        );
    }
}
