//! What one reconcile pass DOES — the impure half of `SPEC.md` §25.4 (dig-node#412).
//!
//! [`super::pass`] is the pure decision (§25.4 step 3). This is steps 1, 2, 4, 5 and 6: it observes
//! disk and chain, derives the in-flight set from the audit record, asks [`super::pass::decide`]
//! what to do, and then does it — reclaims first, creates second, stopping cleanly at the end of
//! what the wallet can pay for.
//!
//! # Everything that can fail is behind ONE trait, and the order is not
//!
//! [`MirrorEffects`] holds the chain, the wallet and the disk. What it deliberately does NOT hold is
//! the ORDER those effects happen in, the funds gating, or the in-flight suppression — those live
//! here, in ordinary code, over a trait a test can implement in twenty lines.
//!
//! That split is the whole reason this file is testable. The three rules below each fail in an
//! expensive direction and each is a property of the SEQUENCE rather than of any one effect, so a
//! test that could only observe the effects individually could not see any of them:
//!
//! 1. **Reclaims run before creates, and are never gated on funds.** A reclaim returns collateral,
//!    which may fund the creates behind it. A recording double proves the order; a double that only
//!    counted calls could not.
//! 2. **Creates stop CLEANLY.** At the end of the affordable prefix, or at the first create that
//!    errors: no partial spend, no retry loop, no second attempt in the same pass. The next pass
//!    re-derives everything from disk and chain, so added funds are picked up without any resumption
//!    state — which is why stopping is safe and why retrying here would be worse than useless.
//! 3. **A `Relayed` capsule never reaches the create path.** §25.1 excludes it, and this is the one
//!    place in the lifecycle where an attacker has any influence at all over what the node spends
//!    its OWN money on: a stranger chooses what this node relays. The exclusion is applied by
//!    [`split_by_provenance`] at the point of observation and expressed in the types thereafter —
//!    `PassInputs::held` and `::relayed` are different fields, so nothing downstream is in a position
//!    to confuse them. A pre-filtered set handed in by a caller would be a promise; this is a shape.
//!
//! # The audit record is the in-flight ledger, and it survives a restart
//!
//! §25.4.6 allows at most one in-flight create per `(store, root, epoch)`. The set is re-derived
//! from the [`SpendLog`] on every pass rather than remembered, so a node that has just restarted
//! suppresses exactly what a node that has been up for a week does. That is only possible because
//! the record carries the bond STRUCTURALLY ([`AuditedBond`](crate::spend_audit::AuditedBond)):
//! reading the three terms back out of the `purpose` sentence would make a money decision depend on
//! prose nobody promised to keep stable.
//!
//! A record written before that field existed answers `None` and suppresses nothing. That is the
//! safe direction by a wide margin — suppressing nothing risks one duplicate coin, which the planner
//! reclaims at rollover as `EpochEnded`, while suppressing wrongly leaves a held bond permanently
//! uncollateralised and the node undiscoverable for that capsule.

use dig_node_core::CapsuleProvenance;

use crate::spend_audit::{SpendLog, SpendStatus};

use super::pass::{self, BondState, PassDecision, PassInputs};
use super::plan::{Bond, HeldMirror, ReclaimReason};

/// One capsule as the disk scan sees it: which bond it is, and whether this node may advertise it.
///
/// Carries [`CapsuleProvenance`] itself rather than a local `bool` or a locally-defined enum. The
/// provenance decision is dig-node-core's — read from a durable sidecar by the one scan that owns it
/// — and a second spelling of it here would be a rival definition of the rule that decides what this
/// node spends money advertising.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCapsule {
    /// The `(store, root)` this capsule is.
    pub bond: Bond,
    /// Whether it may be advertised, or only served.
    pub provenance: CapsuleProvenance,
}

/// Why a pass could not complete a step. Carries no key material and no puzzle hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassError {
    /// The disk could not be scanned.
    Disk(String),
    /// The chain source could not answer, so the owned-coin set is UNKNOWN.
    ///
    /// Distinct from "this node owns no coins", which is a definite answer and reaches the planner.
    /// Reading an unreadable chain as an empty inventory would plan a create for every held bond
    /// while every one of them may already have a coin.
    Chain(String),
    /// The wallet could not be read, or a spend could not be made.
    Wallet(String),
    /// A create could not be FUNDED, carried structurally rather than as a message (dig-node#463).
    ///
    /// The refusal reaches this type already classified — shortfall, too-fragmented, unreadable —
    /// and flattening it to a string here would mean the only surface that can tell an operator
    /// what to DO about it would have to recover the classification by matching on prose. That is
    /// the shape that reports a chain outage as an empty wallet, so the variant is kept whole and
    /// [`FundingObservation::from_error`] reads it directly.
    ///
    /// `Display` delegates, so every existing consumer that only renders a `PassError` is
    /// unaffected: the message an operator sees is the `FundingError`'s own.
    Funding(super::funding::FundingError),
    /// This node cannot yet name ITSELF, so a create would lock uncreditable collateral.
    ///
    /// Its own variant rather than a [`PassError::Wallet`] because the wallet is fine and the
    /// operator has nothing to fix: the peer network has simply not reported an identity yet, and
    /// the next pass usually has one. Rendering it as a wallet failure would send an operator to
    /// debug a wallet that is working (dig-node#501, security round 1).
    Identity(String),
}

impl std::fmt::Display for PassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassError::Disk(cause) => write!(f, "the capsule cache could not be scanned: {cause}"),
            PassError::Chain(cause) => write!(f, "the chain source could not be read: {cause}"),
            PassError::Wallet(cause) => write!(f, "the operator wallet could not act: {cause}"),
            PassError::Funding(cause) => write!(f, "{cause}"),
            PassError::Identity(cause) => {
                write!(f, "this node cannot declare its own peer identity: {cause}")
            }
        }
    }
}

impl std::error::Error for PassError {}

/// The chain, the wallet and the disk, as one pass needs them.
///
/// Every method here either observes something or spends something. Nothing here decides anything:
/// the ordering, the funds gating and the in-flight suppression are [`PassRunner`]'s, so an
/// implementation of this trait cannot get those rules wrong by being written differently.
pub trait MirrorEffects {
    /// Every capsule settled on disk, WITH its provenance.
    ///
    /// Provenance is required rather than optional, and the set is unfiltered on purpose. A
    /// `held_bonds()`-shaped method would put §25.1's exclusion inside an implementation, where a
    /// second implementation could quietly disagree with it. The filter belongs at exactly one
    /// place, and this trait's job is to make that place unavoidable.
    fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError>;

    /// The mirror coins this wallet owns — `dig_mirror_coin::list(source, owner_puzzle_hash)`.
    fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError>;

    /// What the chain says about `coin_id`, for resolving a spend this node broadcast in an
    /// EARLIER pass (dig-node#412 step 6).
    ///
    /// **Three answers, and they must stay three.** `Ok(Some(height))` is the chain showing the
    /// coin in a block — the only answer that may confirm anything. `Ok(None)` is the chain not
    /// showing it, or showing it with no height yet, which are the same instruction: wait. `Err` is
    /// the chain failing to ANSWER, which is not a verdict about the coin at all — folding it into
    /// `Ok(None)` would turn an outage into a fleet-wide "nothing confirmed", and folding it the
    /// other way would confirm spends on no evidence.
    ///
    /// Deliberately keyed on a coin id rather than shaped as "did my spend land": the caller
    /// derives the coin id positively (see [`super::resolve`]), and an implementation that decided
    /// landedness for itself would be a second answer to the one question this record exists to
    /// answer honestly.
    fn coin_confirmation(&self, coin_id: &str) -> Result<Option<u32>, PassError>;

    /// Spendable $DIG, in base units.
    fn dig_balance_base_units(&self) -> Result<u64, PassError>;

    /// Build, sign, journal and broadcast a reclaim of `mirror`.
    ///
    /// Attempted with `fee = 0` when no XCH is selectable (§25.4.4). A zero-fee reclaim may not be
    /// admitted under fee pressure; that is retried by the NEXT pass and never escalated here.
    fn reclaim(&self, mirror: &HeldMirror, reason: ReclaimReason) -> Result<(), PassError>;

    /// Build, sign, journal and broadcast a create for `bond` at `amount_dig_base_units`.
    ///
    /// The amount is a parameter because it is derived ONCE per pass from the epoch's requirement
    /// (§25.3) and must be identical for every create in that pass. An implementation that re-derived
    /// it per call could price two coins of one pass differently.
    fn create(&self, bond: &Bond, epoch: i64, amount_dig_base_units: u64) -> Result<(), PassError>;
}

/// What a pass consults that this module does not observe for itself.
///
/// The epoch, the requirement, the margin and the switch are passed in rather than read here, for
/// the same reason [`super::pass::decide`] takes them: one pass must see ONE epoch and ONE
/// requirement throughout, and a value re-read mid-pass could change underneath it.
#[derive(Debug, Clone)]
pub struct PassContext {
    /// Wall clock, for the presence debounce (§25.5).
    pub now_unix_ms: u64,
    /// The epoch in force.
    pub current_epoch: i64,
    /// This epoch's requirement, or the named reason it is unknown (§24.2).
    pub requirement: dig_node_control_interface::results::CollateralRequirementResult,
    /// The local safety margin, in basis points.
    pub margin_bp: u64,
    /// §25.7's switch. Gates creates only; reclaims ignore it.
    pub creates_enabled: bool,
    /// Whether this node has anywhere to advertise FROM (SPEC.md §25.10, dig-node#426).
    ///
    /// `false` makes `MirrorEffects::create` refuse every bond by name before any chain read, so
    /// the pass must not plan or price creates it cannot attempt. Read once at bring-up beside the
    /// advertised URL list itself, because a coin's URLs are fixed at create for the whole epoch.
    pub can_advertise: bool,
}

/// What one pass actually did.
///
/// Reported rather than logged and discarded, because "the pass ran" and "the pass achieved
/// something" are different facts and §25.8's surface needs the second one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Reclaims that were broadcast, in the order made.
    pub reclaimed: Vec<HeldMirror>,
    /// Creates that were broadcast, in the order made.
    pub created: Vec<Bond>,
    /// Reclaims that could not be made. Recorded, never retried within this pass.
    pub reclaim_failures: Vec<(HeldMirror, PassError)>,
    /// The create the pass stopped at, when it stopped early because one failed.
    ///
    /// `None` when the pass ran the whole affordable prefix — INCLUDING when that prefix was empty
    /// because the wallet is short. Being unfunded is not a failure and must not read as one; the
    /// shortfall is reported per bond in [`Self::states`], where a person can act on it.
    pub stopped_at: Option<(Bond, PassError)>,
    /// One state per bond, for §25.8.
    pub states: Vec<(Bond, BondState)>,
    /// The margined per-epoch amount each create locked, when one was known.
    pub per_coin_dig_base_units: Option<u64>,
    /// Every DIG base unit this wallet has locked in mirror coins, over the WHOLE owned set.
    ///
    /// Computed here, from the one place that has seen the entire chain observation, precisely so
    /// that §25.8's surface cannot compute it by summing a page. A page sum under-reports locked
    /// money on every node with more bonds than fit in one page, and under-reporting locked money
    /// shows unspendable funds as available — wrong in the reassuring direction, which is the one
    /// direction a money figure must never be wrong in. dig-app#289 renders this figure.
    ///
    /// **Coins being reclaimed are INCLUDED.** A reclaim that has been broadcast has not confirmed,
    /// and the collateral is locked until it does. Excluding them would report money as free while
    /// it is still on chain, which is the same lie one round earlier.
    ///
    /// Read from each coin's own `collateral_dig_base_units` rather than from this epoch's
    /// requirement: a coin created under a previous requirement locks the previous amount.
    pub locked_dig_base_units: u64,
    /// The message to put in front of a person, when THIS pass changed the funding story
    /// (dig-node#463).
    ///
    /// `None` on the overwhelming majority of passes, and that is the feature: the pass runs every
    /// ten minutes, so a field that were `Some` whenever funding is short would be 144 notifications
    /// a day and would train an operator to ignore the one that mattered. The gate deciding this is
    /// [`FundingAlertGate`], and it is carried ACROSS runners for the same reason the presence
    /// tracker is -- a gate rebuilt each round has no memory of having spoken, and would speak every
    /// round.
    pub funding_alert: Option<super::funding::FundingAlert>,
}

/// Runs reconcile passes. Long-lived: it owns the presence tracker and the funding alert gate, the
/// only state a pass carries between runs.
pub struct PassRunner<E> {
    effects: E,
    presence: super::presence::PresenceTracker,
    log: SpendLog,
    /// The one writer of the audit record, for resolving spends an earlier pass broadcast.
    ///
    /// Held beside `log` rather than replacing it: the in-flight suppression READS the ledger and
    /// wants nothing else, while resolution WRITES it, and keeping the reader unable to write is
    /// what stops a future change to the suppression rule from acquiring a write path by accident.
    journal: crate::spend_audit::SpendJournal,
    settling_window_ms: u64,
    /// Decides when a funding shortfall is worth telling a person about (dig-node#463).
    funding_alerts: super::funding::FundingAlertGate,
}

impl<E: MirrorEffects> PassRunner<E> {
    /// Build a runner over `effects`, reading its in-flight ledger from `log`.
    pub fn new(effects: E, log: SpendLog) -> Self {
        Self {
            effects,
            presence: super::presence::PresenceTracker::new(),
            journal: crate::spend_audit::SpendJournal::new(log.clone()),
            log,
            settling_window_ms: super::presence::SETTLING_WINDOW_MS,
            funding_alerts: super::funding::FundingAlertGate::default(),
        }
    }

    /// Adopt an existing funding alert gate, so dig-node#463's once-per-transition rule survives
    /// across runners.
    ///
    /// Exactly the reason [`Self::with_presence`] exists, and exactly the same failure without it:
    /// the scheduler rebuilds the runner every round, and a gate that starts empty every round has
    /// never spoken, so it speaks. The dedup would then be a no-op that every unit test still
    /// passes, because a unit test drives ONE gate over many observations.
    pub fn with_funding_gate(mut self, gate: super::funding::FundingAlertGate) -> Self {
        self.funding_alerts = gate;
        self
    }

    /// Hand the funding alert gate back, for the next round's runner.
    ///
    /// Takes `&mut self` rather than `self`, unlike [`Self::into_presence`], because the scheduler
    /// needs BOTH pieces of carried state out of the same runner and two by-value takers cannot
    /// both be called. This one goes first and the by-value one last.
    pub fn take_funding_gate(&mut self) -> super::funding::FundingAlertGate {
        std::mem::take(&mut self.funding_alerts)
    }

    /// Adopt an existing presence tracker, so §25.5's debounce survives across runners.
    ///
    /// A production scheduler rebuilds its [`MirrorEffects`] every round — the chain source is
    /// per-round and does not outlive it — so the runner is rebuilt too. Without this, each round
    /// would begin with a FRESH tracker, and a fresh tracker suppresses every capsule it has ever
    /// seen exactly once: no bond would ever settle, and the node would never create a coin while
    /// looking like it was reconciling normally. Carrying the tracker is what makes the debounce a
    /// window in wall-clock time rather than a window per runner.
    pub fn with_presence(mut self, presence: super::presence::PresenceTracker) -> Self {
        self.presence = presence;
        self
    }

    /// Hand the presence tracker back, for the next round's runner.
    pub fn into_presence(self) -> super::presence::PresenceTracker {
        self.presence
    }

    /// Write the audit record through `journal` instead of the default one over this runner's log.
    ///
    /// Exists so a test can pin the clock. A journal over a DIFFERENT log would make the runner
    /// read one record and write another, so callers pass a journal over the same path.
    pub fn with_journal(mut self, journal: crate::spend_audit::SpendJournal) -> Self {
        self.journal = journal;
        self
    }

    /// Use a non-default settling window (§25.5).
    pub fn with_settling_window_ms(mut self, window_ms: u64) -> Self {
        self.settling_window_ms = window_ms;
        self
    }

    /// Run one pass: observe, plan, then reclaim and create.
    ///
    /// Returns `Err` only when an OBSERVATION failed, because a pass that cannot see disk or chain
    /// has nothing to decide from and must do nothing at all. A failure to SPEND is reported inside
    /// [`PassReport`] and does not abort the pass: a reclaim that could not be made must not prevent
    /// the reclaim behind it, which is money that would otherwise stay locked for a whole round.
    pub fn run(&mut self, ctx: &PassContext) -> Result<PassReport, PassError> {
        let observed = self.effects.observe_disk()?;
        let (on_disk_held, relayed) = split_by_provenance(&observed);

        // Debounce only the advertisable half. A capsule that flips `Held` -> `Relayed` reads here
        // as a disappearance, which is exactly right: the node must stop advertising it, and it does
        // so through the ordinary reclaim path rather than through a special case.
        let held = self
            .presence
            .observe(&on_disk_held, ctx.now_unix_ms, self.settling_window_ms);

        let on_chain = self.effects.observe_chain()?;

        // BEFORE the in-flight set is derived, so a create this sweep confirms stops suppressing
        // itself in the same pass rather than one pass later. Never `?`: resolution is bookkeeping
        // about spends that have already happened, and a sweep that could not complete must not
        // stop the pass from reclaiming money that is sitting on chain.
        super::resolve::resolve_landed_spends(&self.journal, &self.effects, &on_chain);

        let in_flight = in_flight_creates(&self.log, ctx.current_epoch);
        // NOT `?`. The balance prices creates and nothing else, so a wallet that cannot report its
        // $DIG must degrade the create half rather than abort the pass — aborting here would leave a
        // node unable to advertise AND unable to recover what it has already locked, which is rule 1
        // (`pass.rs`) defeated through the funds READ instead of through the funds gate. §25.4.4's
        // zero-fee reclaim exists for exactly this degraded state.
        let dig_balance_base_units = match self.effects.dig_balance_base_units() {
            Ok(balance) => Some(balance),
            Err(e) => {
                tracing::warn!(
                    target: "mirror",
                    error = %e,
                    "the wallet could not report its $DIG; creates are deferred this pass and reclaims proceed"
                );
                None
            }
        };

        // Over the WHOLE observation, before the plan splits it into keeps and reclaims. Summed
        // here rather than from the plan, because the plan does not carry the coins it leaves alone.
        let locked_dig_base_units = on_chain
            .iter()
            .map(|c| c.collateral_dig_base_units)
            .fold(0u64, u64::saturating_add);

        let decision = pass::decide(&PassInputs {
            held: &held,
            relayed: &relayed,
            on_chain: &on_chain,
            in_flight: &in_flight,
            current_epoch: ctx.current_epoch,
            requirement: &ctx.requirement,
            margin_bp: ctx.margin_bp,
            dig_balance_base_units,
            creates_enabled: ctx.creates_enabled,
            can_advertise: ctx.can_advertise,
        });

        Ok(self.execute(decision, ctx.current_epoch, locked_dig_base_units))
    }

    /// Step 4 and step 5: reclaims first, then creates, stopping cleanly.
    fn execute(
        &mut self,
        decision: PassDecision,
        current_epoch: i64,
        locked_dig_base_units: u64,
    ) -> PassReport {
        let PassDecision {
            reclaim,
            create,
            per_coin_dig_base_units,
            states,
            funding_shortfall: decision_shortfall,
        } = decision;

        let mut reclaimed = Vec::new();
        let mut reclaim_failures = Vec::new();

        // EVERY reclaim is attempted, and one that fails does not stop the next. These are the only
        // spends here that RETURN money, so the cost of skipping one is a round of locked collateral
        // — whereas the cost of attempting one that fails is a log line.
        for (mirror, reason) in reclaim {
            match self.effects.reclaim(&mirror, reason) {
                Ok(()) => reclaimed.push(mirror),
                Err(e) => reclaim_failures.push((mirror, e)),
            }
        }

        let mut created = Vec::new();
        let mut stopped_at = None;

        // `create` is ALREADY the affordable prefix, in `(store_id, root)` order: `decide` did the
        // funds split, so there is no balance arithmetic here and no way for this loop to disagree
        // with the states reported beside it.
        //
        // `per_coin` being `None` means the requirement is unknown, and `create` is then empty — so
        // this loop cannot run without an amount, and no default is ever substituted for one.
        if let Some(per_coin) = per_coin_dig_base_units {
            for bond in create {
                match self.effects.create(&bond, current_epoch, per_coin) {
                    Ok(()) => created.push(bond),
                    Err(e) => {
                        // Stop, cleanly. Not a retry and not a skip-and-continue: every bond in
                        // this loop needs the SAME per-coin amount, and a create that could not be
                        // funded has left the wallet no richer — its own funding coins are now
                        // reserved for the pass if it broadcast, and untouched if it did not. So
                        // the next bond fails identically, and the next pass re-derives the whole
                        // answer anyway.
                        //
                        // The reservation is what makes that reasoning sound rather than merely
                        // plausible: without it the next bond would re-select the coin this one
                        // just spent and succeed at SELECTION, failing later at the mempool as a
                        // double-spend. See `lifecycle::NodeMirrorEffects::committed_coin_ids`.
                        stopped_at = Some((bond, e));
                        break;
                    }
                }
            }
        }

        // What THIS pass learned about the operator wallet, in the three shapes the gate decides
        // on. Read off the structured refusal rather than off a message, which is why
        // `PassError::Funding` carries the `FundingError` whole.
        let observation = match &stopped_at {
            Some((_, PassError::Funding(cause))) => {
                super::funding::FundingObservation::from_error(cause)
            }
            // A create stopped for a reason that is not about funding -- no advertised URL, an
            // unparseable id, a builder or broadcast failure. It is a real failure and it is
            // reported in `stopped_at`, but it is not evidence about the wallet, and letting it
            // CLEAR a live shortfall would tell an operator their funding recovered on the strength
            // of an unrelated error.
            Some(_) => super::funding::FundingObservation::Unknown,
            // Nothing stopped, and the wallet could not afford every create the pass priced. This
            // is the ORDINARY shortfall -- a wallet holding less than one create's collateral --
            // and it never reaches `stopped_at` at all, because the create loop is handed the
            // affordable prefix and an empty prefix simply does not iterate.
            //
            // Classifying it `Healthy` (dig-node#469) left the Short alert with no producer for the
            // commonest real case, and worse: a pass that could afford nothing CLEARED a live
            // shortfall and announced a recovery that had not happened. A pass that never asked the
            // wallet for money is not evidence that the wallet has any.
            //
            // It is `Unmeasured`, NOT `Short`, and the difference is the whole of dig-node#469 one
            // surface along. A `Short` quotes a spendable total, and the only total this arm has is
            // `dig_balance_base_units` -- the raw sum over `dig_cat_puzzle_hash(owner)`, which
            // neither balance tier authenticates. That address is publicly derivable, so a stranger
            // who plants one coin just large enough to push the reported balance to a hair under
            // one create's cost has the operator told they are 0.001 DIG short when they are 0.500
            // short; they top up the 0.001, and `grew_materially` then suppresses the correction as
            // immaterial. SPEC 25.11 -- authentication precedes every figure the operator is told.
            //
            // The SHORT classification itself is sound and is kept: authentication only ever
            // REMOVES candidates, so the authenticated total is at most the reported one, and a
            // reported total that cannot fund a create proves the real one cannot either. It is the
            // AMOUNT that no honest figure exists for on this path, because no candidate here was
            // ever authenticated -- the create loop is handed an empty affordable prefix and never
            // iterates, so `authenticate` is never called at all.
            None if decision_shortfall.is_some() => {
                let shortfall = decision_shortfall.expect("matched Some directly above");
                super::funding::FundingObservation::Unmeasured(
                    super::funding::UnmeasuredFunding::NoCreateAffordable {
                        // The requirement, never the wallet. `need` is derived from the epoch
                        // collateral and the plan, so it is the one figure in this arm that no
                        // stranger can move.
                        need_dig_base_units: shortfall.need_dig_base_units,
                    },
                )
            }
            // Nothing stopped and nothing was unaffordable. `per_coin` is `Some` exactly when the
            // requirement was known, so this is a pass that funded every create it planned --
            // including a pass that planned none, which is the healthy state a node with nothing
            // new to bond sits in.
            None if per_coin_dig_base_units.is_some() => {
                super::funding::FundingObservation::Healthy
            }
            // The requirement itself was unknown, so no create was priced and none was refused.
            // Silent, and it does not clear a shortfall either.
            None => super::funding::FundingObservation::Unknown,
        };
        let funding_alert = self.funding_alerts.observe(&observation);

        // Logged HERE as well as returned, because the return value reaches a surface only if
        // something renders it, and this line reaches an operator's stderr on a node whose state
        // dir it cannot even write (dig-node#440). No coin id and no address: the same rule that
        // shapes the alert body, for the same reason.
        if let Some(alert) = &funding_alert {
            tracing::warn!(
                target: "mirror",
                title = %alert.title,
                remedy = ?alert.remedy,
                "{}",
                alert.body
            );
        }

        PassReport {
            reclaimed,
            created,
            reclaim_failures,
            stopped_at,
            states,
            per_coin_dig_base_units,
            locked_dig_base_units,
            funding_alert,
        }
    }
}

/// Split observed capsules into the advertisable and the merely-served (§25.1).
///
/// The ONE place the `Relayed` exclusion is applied. A free function over the observation rather
/// than a step inside a [`MirrorEffects`] implementation, so that there is exactly one of it: a
/// second implementation of this rule is a second answer to "what may this node spend its own money
/// advertising", and the two would not stay equal.
pub(super) fn split_by_provenance(observed: &[ObservedCapsule]) -> (Vec<Bond>, Vec<Bond>) {
    let mut held = Vec::new();
    let mut relayed = Vec::new();
    for capsule in observed {
        let bond = canonical(&capsule.bond);
        match capsule.provenance {
            CapsuleProvenance::Held => held.push(bond),
            CapsuleProvenance::Relayed => relayed.push(bond),
        }
    }
    (held, relayed)
}

/// A bond in the ONE form every ordering downstream assumes: lowercase, unprefixed, 64 hex.
///
/// `Bond`'s `Ord` is derived over the raw `String`s, and `dig-node-control-interface`'s
/// `MirrorBondKey` orders the same way — so the canonical form is what makes the two derives agree.
/// Two nodes that sorted differently would page §25.8's surface differently, and a paging walk that
/// disagrees with its server does not error: it SKIPS or REPEATS rows. On the surface feeding
/// dig-app#289's locked total, a skipped row is wrong in the reassuring direction, which is the one
/// direction a money figure must never be wrong in.
///
/// Normalising HERE rather than trusting the observer is the point. `CachedCapsule` documents its
/// ids as lowercase 64-hex and today they are, but that is a property of one producer, and this is
/// the boundary where a second one would arrive. Normalising costs an allocation per capsule per
/// pass and removes a whole class of disagreement that shows up as a wrong number rather than as an
/// error.
fn canonical(bond: &Bond) -> Bond {
    fn hex(value: &str) -> String {
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value)
            .to_ascii_lowercase()
    }

    Bond::new(hex(&bond.store_id), hex(&bond.root))
}

/// The bonds whose CURRENT-epoch create is open and unresolved (§25.4.6).
///
/// Read from the audit record, which is the in-flight ledger. Only `Pending` and `Submitted` count:
/// a `Confirmed` create has a coin the chain observation already sees, and a `Failed` one did not
/// happen.
///
/// `Unresolved` deserves its name here, because it is the tempting one to include. It means the node
/// signed and does not know what happened, so there may well be a coin. It does NOT suppress: a
/// suppression that never lifts leaves the bond permanently uncollateralised, whereas the duplicate
/// it risks is reclaimed at the next rollover as `EpochEnded`. Both directions cost something; only
/// one of them is permanent.
fn in_flight_creates(log: &SpendLog, current_epoch: i64) -> Vec<Bond> {
    let ledger = match log.ledger() {
        Ok(ledger) => ledger,
        Err(e) => {
            // Suppress nothing rather than everything. An unreadable ledger read as "everything is
            // in flight" would silently stop the node collateralising anything at all, with no
            // surface saying why.
            tracing::warn!(
                target: "mirror",
                error = %e,
                "the spend audit record could not be read; no in-flight create is suppressed this pass"
            );
            return Vec::new();
        }
    };

    ledger
        .records
        .iter()
        .filter(|r| r.kind.as_str() == crate::spend_audit::kinds::MIRROR_COIN)
        .filter(|r| matches!(r.status, SpendStatus::Pending | SpendStatus::Submitted))
        .filter_map(|r| {
            let bond = r.bond.as_ref()?;
            let store_id = r.store_id.as_ref()?;
            (bond.epoch == current_epoch).then(|| Bond::new(store_id.clone(), bond.root.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_audit::{
        kinds, Asset, AuditedBond, Authority, FailureStage, SpendIntent, SpendJournal, SpendKind,
    };
    use dig_node_control_interface::results::{
        CollateralRequirementResult, CollateralUnknownReason,
    };
    use std::cell::RefCell;

    fn id(tag: &str) -> String {
        let mut s = tag.to_string();
        while s.len() < 64 {
            s.push('0');
        }
        s.truncate(64);
        s
    }

    fn bond(store: &str, root: &str) -> Bond {
        Bond::new(id(store), id(root))
    }

    fn coin(tag: &str, store: &str, root: &str, epoch: i64, amount: u64) -> HeldMirror {
        HeldMirror {
            coin_id: id(tag),
            store_id: id(store),
            root: id(root),
            epoch,
            collateral_dig_base_units: amount,
        }
    }

    const NOW_EPOCH: i64 = 100;
    const REQUIRED: u64 = 1_000;

    /// Every effect a pass performed, in the order it performed them.
    ///
    /// ONE list rather than one per operation. The rule under test is that reclaims come BEFORE
    /// creates, which is a statement about a single sequence — two separate counters can each be
    /// correct while the interleaving between them is wrong, and no assertion over them could see it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Effect {
        Reclaim(HeldMirror),
        Create(Bond, i64, u64),
    }

    #[derive(Default)]
    struct FakeEffects {
        disk: Vec<ObservedCapsule>,
        chain: Vec<HeldMirror>,
        balance: u64,
        calls: RefCell<Vec<Effect>>,
        /// Bonds whose create must fail, so a pass can be made to stop part-way.
        create_fails: Vec<Bond>,
        /// Coins whose reclaim must fail, so a failing reclaim can be shown not to stop the next.
        reclaim_fails: Vec<String>,
        /// Make the BALANCE READ itself fail. Without this the `PassError::Wallet` arm of the
        /// balance observation is unreachable from any fixture, and an error path no double can
        /// take reads as covered while never having been run once.
        balance_fails: bool,
        /// Heights the chain reports per coin id, for the landed-spend resolver.
        confirmations: std::collections::HashMap<String, u32>,
        /// Coin ids the chain cannot be ASKED about, kept apart from ones it reports absent.
        confirmation_fails: Vec<String>,
        /// The refusal a failing create returns, so a fixture can distinguish a create that failed
        /// for want of FUNDS from one that failed for any other reason.
        ///
        /// `None` keeps the ordinary non-funding failure the other fixtures rely on. Without this
        /// the `PassError::Funding` arm of the alert wiring is unreachable from any double, and an
        /// operator-facing path no test can take reads as covered while never having run.
        create_funding_failure: Option<super::super::funding::FundingError>,
    }

    impl MirrorEffects for FakeEffects {
        fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
            Ok(self.disk.clone())
        }

        fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
            Ok(self.chain.clone())
        }

        fn coin_confirmation(&self, coin_id: &str) -> Result<Option<u32>, PassError> {
            if self.confirmation_fails.iter().any(|c| c == coin_id) {
                return Err(PassError::Chain("the chain could not be asked".to_string()));
            }
            Ok(self.confirmations.get(coin_id).copied())
        }

        fn dig_balance_base_units(&self) -> Result<u64, PassError> {
            if self.balance_fails {
                return Err(PassError::Wallet("the wallet is locked".to_string()));
            }
            Ok(self.balance)
        }

        fn reclaim(&self, mirror: &HeldMirror, _reason: ReclaimReason) -> Result<(), PassError> {
            self.calls
                .borrow_mut()
                .push(Effect::Reclaim(mirror.clone()));
            if self.reclaim_fails.contains(&mirror.coin_id) {
                return Err(PassError::Wallet("no fee coin".to_string()));
            }
            Ok(())
        }

        fn create(
            &self,
            bond: &Bond,
            epoch: i64,
            amount_dig_base_units: u64,
        ) -> Result<(), PassError> {
            self.calls.borrow_mut().push(Effect::Create(
                bond.clone(),
                epoch,
                amount_dig_base_units,
            ));
            if self.create_fails.contains(bond) {
                return Err(match &self.create_funding_failure {
                    Some(cause) => PassError::Funding(cause.clone()),
                    None => PassError::Wallet("no selectable coin".to_string()),
                });
            }
            Ok(())
        }
    }

    fn held(bonds: &[Bond]) -> Vec<ObservedCapsule> {
        bonds
            .iter()
            .map(|b| ObservedCapsule {
                bond: b.clone(),
                provenance: CapsuleProvenance::Held,
            })
            .collect()
    }

    fn known() -> CollateralRequirementResult {
        CollateralRequirementResult::Known {
            epoch: NOW_EPOCH as u64,
            protocol_version: 1,
            required_per_store_dig_base_units: REQUIRED,
            stores: 1,
            owners: 1,
            multiplier_micros: 1_000_000,
            handicap_dig_base_units: 0,
        }
    }

    fn ctx() -> PassContext {
        PassContext {
            now_unix_ms: 1_000_000,
            current_epoch: NOW_EPOCH,
            requirement: known(),
            margin_bp: 0,
            creates_enabled: true,
            can_advertise: true,
        }
    }

    fn journal(dir: &std::path::Path) -> (SpendJournal, SpendLog) {
        let log = SpendLog::at(dir.join("spend-audit.jsonl"));
        (SpendJournal::new(log.clone()), log)
    }

    /// A runner whose presence tracker settles immediately, so a fixture is one pass rather than two.
    ///
    /// The debounce itself is proven in `presence.rs`; repeating it here would test that module
    /// twice and this one not at all.
    fn runner(effects: FakeEffects, log: SpendLog) -> PassRunner<FakeEffects> {
        PassRunner::new(effects, log).with_settling_window_ms(0)
    }

    /// **The funding alert reaches the pass report, once, and CARRIES between runners.**
    ///
    /// **Proves** the wiring dig-node#463 is actually about. [`FundingAlertGate`] is a pure decision
    /// with unit tests of its own, and every one of them drives ONE gate over many observations — so
    /// all nine stay green against a node that constructs a fresh gate per pass and notifies 144
    /// times a day. The gate being correct and the gate being USED are different claims, and only
    /// this test makes the second one.
    ///
    /// **Catches** two regressions that are invisible on every other signal:
    ///
    /// * dropping [`PassRunner::with_funding_gate`] from the scheduler, exactly as
    ///   `the_presence_tracker_carries_between_runners_and_a_fresh_one_suppresses` catches the same
    ///   omission for the presence tracker;
    /// * flattening the refusal to a string on the way out of `MirrorEffects::create`. The
    ///   observation is read from `PassError::Funding`'s payload, so a `PassError::Wallet` carrying
    ///   the same prose produces no alert at all — asserted below as the third pass.
    ///
    /// The three passes are asserted as a SEQUENCE, and only the sequence discriminates. Pass one
    /// alone is satisfied by a gate that speaks every time; pass two alone by a gate that never
    /// speaks after the first ever call, whatever it is fed.
    #[test]
    fn a_funding_shortfall_alerts_once_across_rebuilt_runners_and_never_from_a_stringly_refusal() {
        use super::super::funding::{FundingAlertGate, FundingError, FundingRemedy};

        let capsule = bond("aa", "11");
        // Short by exactly one base unit, so the refusal is unambiguously a shortfall rather than
        // an artefact of a wallet with nothing in it.
        let shortfall = FundingError::Insufficient {
            have_dig_base_units: REQUIRED - 1,
            need_dig_base_units: REQUIRED,
        };
        // A funded wallet, so the PLAN reaches a create and the only refusal is the one the fixture
        // injects. A pass that never planned a create could not alert, and would pass vacuously.
        let effects = |funding: Option<FundingError>| FakeEffects {
            disk: held(std::slice::from_ref(&capsule)),
            balance: REQUIRED * 10,
            create_fails: vec![capsule.clone()],
            create_funding_failure: funding,
            ..FakeEffects::default()
        };

        // One EMPTY audit log, shared: the fake effects never journal, so no pass suppresses the
        // next through the in-flight set, and every pass reaches the same create for the same reason.
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let run = |gate, funding| {
            let mut pass = runner(effects(funding), log.clone()).with_funding_gate(gate);
            let report = pass.run(&ctx()).expect("the pass observes");
            (report.funding_alert, pass.take_funding_gate())
        };

        // Pass 1: the transition into short. The operator has not been told, so they are told.
        let (first, gate) = run(FundingAlertGate::default(), Some(shortfall.clone()));
        let first = first.expect("the transition into a funding shortfall must reach the operator");
        assert_eq!(
            first.remedy,
            Some(FundingRemedy::TopUp),
            "a wallet that is genuinely short is told to add $DIG, not to consolidate"
        );

        // Pass 2: the SAME shortfall, a REBUILT runner. Silent only because the gate was carried.
        let (second, _gate) = run(gate, Some(shortfall.clone()));
        assert_eq!(
            second, None,
            concat!(
                "the second consecutive short pass alerted again, so the gate did not survive the ",
                "runner being rebuilt; on the ten-minute pass timer that is 144 notifications a day"
            )
        );

        // Pass 3: the same wallet condition, refused WITHOUT structure. Nothing is alerted, because
        // nothing can be classified -- which is why `funding_refusal` keeps the error whole.
        let (third, _) = run(FundingAlertGate::default(), None);
        assert_eq!(
            third, None,
            concat!(
                "a refusal carrying only prose was classified as a shortfall; the observation must ",
                "be read from the structured error, never recovered by matching on a message"
            )
        );
    }

    /// **A wallet that can afford NOTHING alerts Short, and never announces a false recovery.**
    ///
    /// **Proves** the producer dig-node#463's Short alert was missing for its commonest real case.
    /// A pass reaches `PassError::Funding` only when a create was ATTEMPTED and refused — but a
    /// wallet holding less than one create's collateral never attempts one at all: `decide` hands
    /// `execute` the affordable prefix, and an empty prefix simply does not iterate. Nothing stops,
    /// so the pass classified itself `Healthy` (dig-node#469 finding 2).
    ///
    /// **Catches** two things, and only the sequence catches the second:
    ///
    /// * an empty wallet reporting `Healthy`, so the ordinary shortfall is never reported at all;
    /// * worse, that same pass CLEARING a live shortfall and announcing *"collateral resumed …
    ///   your content is being bonded"*. Both clauses are false, and the recovery message is the
    ///   one an operator acts on by stopping work. It needs no attacker: coins committed to an
    ///   in-flight bundle are withheld from selection but counted by the balance oracle, so pass N
    ///   alerts Short and pass N+1 reads a balance under one create and announces recovery.
    ///
    /// # The control is a pass that genuinely DID recover
    ///
    /// The third pass funds the create for real. Without it this test is equally green against an
    /// implementation that simply never recovers — which would leave an operator who fixed their
    /// wallet permanently told it is broken. Varying only the balance between passes two and three
    /// is what makes the distinction the wallet's rather than the gate's.
    #[test]
    fn a_wallet_that_can_afford_nothing_alerts_short_and_never_announces_a_false_recovery() {
        use super::super::funding::{FundingAlertGate, FundingRemedy};

        let capsule = bond("aa", "11");
        // The pass is otherwise ORDINARY: a held bond, a known requirement, nothing injected. The
        // only variable is what the wallet holds.
        let effects = |balance: u64| FakeEffects {
            disk: held(std::slice::from_ref(&capsule)),
            balance,
            ..FakeEffects::default()
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let run = |gate, balance| {
            let mut pass = runner(effects(balance), log.clone()).with_funding_gate(gate);
            let report = pass.run(&ctx()).expect("the pass observes");
            (report, pass.take_funding_gate())
        };

        // Pass 1: a wallet holding nothing, and a bond waiting to be collateralised.
        let (first, gate) = run(FundingAlertGate::default(), 0);
        assert!(
            first.created.is_empty(),
            "the fixture must genuinely afford nothing, or the shortfall below is not the one \
             under test"
        );
        let alert = first.funding_alert.expect(concat!(
            "a wallet that cannot afford a single create raised no alert; this is the commonest ",
            "real shortfall there is, and it was being reported as a healthy node"
        ));
        assert_eq!(
            alert.remedy,
            Some(FundingRemedy::TopUp),
            "an empty wallet is told to add $DIG"
        );

        // Pass 2: the same empty wallet again. Silent -- the operator has already been told, and
        // nothing about the shortfall has changed. Silence is what a persisting shortfall sounds
        // like; a RECOVERY is what the old classification announced here.
        let (second, gate) = run(gate, 0);
        assert_eq!(
            second.funding_alert, None,
            concat!(
                "the shortfall was CLEARED by a pass that never asked the wallet for anything, ",
                "and the operator was told their content is being bonded again"
            )
        );

        // Pass 3: the wallet is funded and the create is made. NOW a recovery is the truth.
        let (third, _) = run(gate, REQUIRED * 10);
        assert_eq!(
            third.created,
            vec![capsule.clone()],
            "the control must genuinely fund the create"
        );
        let recovery = third
            .funding_alert
            .expect("an operator who fixed their wallet must be told it worked");
        assert_eq!(
            recovery.remedy, None,
            "a recovery asks for nothing; reporting one only when the wallet really recovered is \
             the half of this that keeps the fix from silencing recoveries altogether"
        );
    }

    /// **A pass that authenticated nothing never quotes a spendable total to the operator.**
    ///
    /// **Proves** SPEC §25.11 on the path §25.12 calls the commonest real case. The pass that can
    /// afford no create never invokes selection at all, so no candidate is ever authenticated —
    /// and the only total available to it is `dig_balance_base_units`, the raw sum over
    /// `dig_cat_puzzle_hash(owner)`, which neither balance tier proves lineage for.
    ///
    /// **Catches** the nearest wrong implementation exactly: classifying this pass as `Short` and
    /// rendering `balance % per_coin` as *"the operator wallet holds X DIG that it can spend"*. It
    /// is the same defect this PR fixes inside selection, one surface along.
    ///
    /// # The fixture is the attack, not merely an empty wallet
    ///
    /// The operator holds NOTHING. A stranger pays `REQUIRED - 1` into the publicly derivable scan
    /// address — 999 base units, well under a cent — and the coin has no valid $DIG lineage, so
    /// nobody can ever spend it. The reported balance is now 999 against a requirement of 1,000.
    ///
    /// The wrong version tells the operator they are **0.001 DIG short** when they are **1.000
    /// short**, and the attacker chose that figure. They top up the 0.001, the shortfall persists,
    /// and `grew_materially` suppresses the correction as immaterial — so the lie is not merely
    /// told once, it is latched.
    ///
    /// An empty wallet would NOT catch this: at a balance of zero the wrong version renders *"holds
    /// 0.000 DIG"*, which is true, and the test would pass under the defect. Varying the one thing
    /// a stranger controls is what makes this fixture load-bearing.
    ///
    /// # The control, without which this test is satisfied by saying nothing anywhere
    ///
    /// The second half drives the AUTHENTICATED shortfall — `FundingError::Insufficient`, whose
    /// figures come from `authenticate` — and asserts it DOES quote the spendable total. An
    /// implementation that simply stripped every amount from every funding message passes the first
    /// half and fails this one.
    #[test]
    fn a_pass_that_authenticated_nothing_quotes_no_spendable_total() {
        use super::super::funding::{FundingAlertGate, FundingError, FundingRemedy};

        const PLANTED: u64 = REQUIRED - 1;
        /// The clause that asserts a spendable total. Its presence IS the defect.
        const SPENDABLE_CLAIM: &str = "that it can spend";

        let capsule = bond("aa", "11");
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));

        // The attacked pass: the operator's own $DIG is zero, and every base unit the balance
        // oracle reports was put there by somebody else.
        let mut pass = runner(
            FakeEffects {
                disk: held(std::slice::from_ref(&capsule)),
                balance: PLANTED,
                ..FakeEffects::default()
            },
            log.clone(),
        )
        .with_funding_gate(FundingAlertGate::default());
        let report = pass.run(&ctx()).expect("the pass observes");

        assert!(
            report.created.is_empty(),
            "the fixture must afford no create, or the path under test is not the one taken"
        );
        let alert = report.funding_alert.expect(concat!(
            "a node blocked from bonding raised nothing at all; refusing to quote an ",
            "unauthenticated figure must not become refusing to speak"
        ));
        assert!(
            !alert.body.contains(SPENDABLE_CLAIM),
            "the operator was told what their wallet can spend, off a total no candidate was \
             authenticated for; a stranger paying 999 base units into a public address chose it. \
             Body was: {}",
            alert.body
        );
        assert!(
            !alert.body.contains("0.001"),
            "the deficit quoted is the attacker's arithmetic, not the operator's: they are 1.000 \
             DIG short and were told 0.001. Body was: {}",
            alert.body
        );
        assert!(
            alert.body.contains("1.000"),
            "the requirement is the one figure here no stranger can move, and dropping it leaves \
             an operator with nothing to act on. Body was: {}",
            alert.body
        );
        assert_eq!(
            alert.remedy,
            Some(FundingRemedy::TopUp),
            "the direction IS established even where the amount is not: this wallet could not fund \
             a single create"
        );

        // The control: an AUTHENTICATED shortfall still states its figures. `Insufficient` is
        // produced by `authenticate` over proven candidates, so its total is the operator's own.
        let mut authenticated = runner(
            FakeEffects {
                disk: held(std::slice::from_ref(&capsule)),
                balance: REQUIRED * 10,
                create_fails: vec![capsule.clone()],
                create_funding_failure: Some(FundingError::Insufficient {
                    have_dig_base_units: PLANTED,
                    need_dig_base_units: REQUIRED,
                }),
                ..FakeEffects::default()
            },
            log,
        )
        .with_funding_gate(FundingAlertGate::default());
        let control = authenticated.run(&ctx()).expect("the pass observes");
        let control_alert = control
            .funding_alert
            .expect("an authenticated shortfall must still alert");
        assert!(
            control_alert.body.contains(SPENDABLE_CLAIM),
            "an authenticated total is exactly the figure an operator SHOULD be given; silencing \
             every amount is not the fix. Body was: {}",
            control_alert.body
        );
    }

    /// **Exhausting the authentication budget TELLS the operator, and still clears nothing.**
    ///
    /// **Proves** the second half of SPEC §25.11's truncated-walk rule. Refusing to quote a total
    /// from a truncated walk is right; refusing to say anything is a different thing, and it is the
    /// steady state a stranger drives this node into: bury the honest coins under
    /// `MAX_AUTHENTICATION_ATTEMPTS` larger unauthenticatable ones and every pass, forever, ends in
    /// `CandidatesUnverifiable`.
    ///
    /// **Catches** the mapping that sent that condition to `Unknown` — where `observe` returns
    /// `None`, so even the `tracing::warn!` in `execute`, gated on the alert being `Some`, never
    /// fired. The alert channel said nothing, ever, about a node that had stopped bonding.
    ///
    /// # Why the sequence, and not one pass
    ///
    /// Pass 1 latches a real, authenticated shortfall. Pass 2 is the truncated walk. This composes
    /// the two findings: without the fix the operator's last word is the pass-1 figure, the
    /// correction can never arrive because a truncated pass is silent, and the gate stays latched
    /// on it. So the test asserts pass 2 SPEAKS and that its message quotes no total — and pass 3,
    /// a repeat of the same truncation, is silent, because once per entry is the policy and 144
    /// messages a day is how an operator learns to ignore them.
    #[test]
    fn a_truncated_authentication_walk_tells_the_operator_without_quoting_a_total() {
        use super::super::funding::{FundingAlertGate, FundingError};

        let capsule = bond("aa", "11");
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let run = |gate, failure: FundingError| {
            let mut pass = runner(
                FakeEffects {
                    disk: held(std::slice::from_ref(&capsule)),
                    balance: REQUIRED * 10,
                    create_fails: vec![capsule.clone()],
                    create_funding_failure: Some(failure),
                    ..FakeEffects::default()
                },
                log.clone(),
            )
            .with_funding_gate(gate);
            let report = pass.run(&ctx()).expect("the pass observes");
            (report.funding_alert, pass.take_funding_gate())
        };

        let truncated = || FundingError::CandidatesUnverifiable {
            attempted: super::super::funding::MAX_AUTHENTICATION_ATTEMPTS,
            skipped: super::super::funding::MAX_AUTHENTICATION_ATTEMPTS,
            need_dig_base_units: REQUIRED,
        };

        // Pass 1: a genuine, authenticated shortfall. The operator is told a figure.
        let (first, gate) = run(
            FundingAlertGate::default(),
            FundingError::Insufficient {
                have_dig_base_units: REQUIRED - 1,
                need_dig_base_units: REQUIRED,
            },
        );
        assert!(first.is_some(), "the control shortfall must latch the gate");

        // Pass 2: the walk is truncated. This is the pass that was silent.
        let (second, gate) = run(gate, truncated());
        let alert = second.expect(concat!(
            "the authentication budget was exhausted and the operator was told NOTHING -- not by ",
            "the alert, and not by the log line the alert gates. A node that has stopped bonding ",
            "because a stranger filled its scan address must say so"
        ));
        assert!(
            !alert.body.contains("short"),
            "a truncated walk measured nothing, so it must not describe the wallet as short by \
             any amount. Body was: {}",
            alert.body
        );
        assert!(
            alert.body.contains("UNKNOWN"),
            "the operator must be told the figure is unknown rather than low, or they will buy \
             $DIG that cannot help. Body was: {}",
            alert.body
        );
        assert_eq!(
            alert.remedy, None,
            concat!(
                "a truncated walk establishes no remedy: TopUp is the wrong instruction because ",
                "adding money need not help, and Consolidate asserts the wallet holds enough, ",
                "which is exactly what was not established"
            )
        );

        // Pass 3: the same truncation persists. Silence -- the operator has been told.
        let (third, _) = run(gate, truncated());
        assert_eq!(
            third, None,
            "the attacker's steady state must not become 144 identical messages a day"
        );
    }

    /// **A create that failed for a NON-funding reason does not clear a live shortfall.**
    ///
    /// **Proves** the `Some(_) => Unknown` arm of the wiring. A pass that stopped because no URL is
    /// advertised, or because the builder refused, is a real failure and is reported in
    /// `stopped_at` — but it is not evidence about the wallet.
    ///
    /// **Catches** the plausible simplification that treats "did not stop for funding" as healthy.
    /// That version reports a RECOVERY off the back of an unrelated error, telling an operator their
    /// funding is fixed when it is not, and then alerts afresh on the next short pass. The recovery
    /// message is the one an operator acts on by stopping work, so a false one is worse than silence.
    #[test]
    fn a_non_funding_create_failure_neither_alerts_nor_clears_a_live_shortfall() {
        use super::super::funding::{FundingAlertGate, FundingError};

        let capsule = bond("aa", "11");
        let shortfall = FundingError::Insufficient {
            have_dig_base_units: REQUIRED - 1,
            need_dig_base_units: REQUIRED,
        };
        let effects = |funding: Option<FundingError>| FakeEffects {
            disk: held(std::slice::from_ref(&capsule)),
            balance: REQUIRED * 10,
            create_fails: vec![capsule.clone()],
            create_funding_failure: funding,
            ..FakeEffects::default()
        };

        // One EMPTY audit log, shared: the fake effects never journal, so no pass suppresses the
        // next through the in-flight set, and every pass reaches the same create for the same reason.
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let run = |gate, funding| {
            let mut pass = runner(effects(funding), log.clone()).with_funding_gate(gate);
            let report = pass.run(&ctx()).expect("the pass observes");
            (report.funding_alert, pass.take_funding_gate())
        };

        let (_, gate) = run(FundingAlertGate::default(), Some(shortfall.clone()));
        // A create that fails without a funding cause: `PassError::Wallet`, the fixture default.
        let (during, gate) = run(gate, None);
        assert_eq!(
            during, None,
            "an unrelated create failure is not a recovery and must not be announced as one"
        );
        // The shortfall then persists. If the pass above had CLEARED the state this alerts again.
        let (after, _) = run(gate, Some(shortfall));
        assert_eq!(
            after, None,
            concat!(
                "the shortfall was re-announced, so the unrelated failure cleared the gate's ",
                "memory; the operator is told about a shortfall that never went away"
            )
        );
    }

    /// The presence tracker CARRIES between runners, and a fresh one on the second pass suppresses.
    ///
    /// **Proves** the reason [`PassRunner::with_presence`] exists. The production scheduler rebuilds
    /// its [`MirrorEffects`] every round — the chain source is per-round and does not outlive it —
    /// so the runner is rebuilt too. §25.5's window is wall-clock, not per-runner, and a fresh
    /// tracker restarts every bond's window at the moment it is built.
    ///
    /// **Catches** the regression that drops the carry from the scheduler. It compiles, it passes
    /// every other test, and it produces a node that never settles a bond and never creates a coin
    /// **while looking like it is reconciling normally** — the runner's own doc says the failure is
    /// invisible on every other signal, which is exactly why it needs a test naming it.
    ///
    /// The two halves are asserted as a PAIR, and only the pair discriminates. The carried run
    /// alone is satisfied by an implementation with no debounce at all — one that settles
    /// everything immediately would pass it — so the fresh-tracker half is what proves the window
    /// is real and that the first half's success came from the CARRY rather than from its absence.
    #[test]
    fn the_presence_tracker_carries_between_runners_and_a_fresh_one_suppresses() {
        use super::super::presence::SETTLING_WINDOW_MS;

        const FIRST_SEEN_MS: u64 = 1_000_000;
        let capsule = bond("aa", "11");

        // A pass whose ONLY reason not to create is the debounce: the wallet is funded, the
        // requirement is known, creates are on, and nothing is on chain. So a create appearing or
        // not appearing is a statement about the presence window and about nothing else.
        let effects = || FakeEffects {
            disk: held(std::slice::from_ref(&capsule)),
            balance: REQUIRED * 10,
            ..FakeEffects::default()
        };
        let at = |now_unix_ms| PassContext {
            now_unix_ms,
            ..ctx()
        };
        let created = |report: &PassReport| report.created.clone();

        // A real, EMPTY audit log per runner. Empty matters: an in-flight create recorded for this
        // (store, root, epoch) would suppress the create through §25.4.6 instead, and the test
        // would then pass for a reason that has nothing to do with the presence window.
        let dir = tempfile::tempdir().expect("a temp dir");
        let log = |tag: &str| SpendLog::at(dir.path().join(format!("{tag}.jsonl")));

        // Pass 1 — the capsule has just appeared. Nothing settles, so nothing is created. This is
        // the control: it shows the window is doing something before the carry is tested at all.
        let mut first = PassRunner::new(effects(), log("first"));
        let opening = first
            .run(&at(FIRST_SEEN_MS))
            .expect("the observation succeeds");
        assert!(
            created(&opening).is_empty(),
            "a capsule seen for the first time has not settled, so no coin is created: {:?}",
            created(&opening)
        );

        // Pass 2, CARRYING the tracker, one full window later. The bond's window began at
        // FIRST_SEEN_MS and has now elapsed, so it settles and the create happens.
        let mut carried =
            PassRunner::new(effects(), log("carried")).with_presence(first.into_presence());
        let settled = carried
            .run(&at(FIRST_SEEN_MS + SETTLING_WINDOW_MS))
            .expect("the observation succeeds");
        assert_eq!(
            created(&settled),
            vec![capsule.clone()],
            "the carried tracker remembers when the capsule appeared, so one window later it \
             settles and is bonded: {:?}",
            created(&settled)
        );

        // The SAME second pass, at the SAME instant, with a FRESH tracker. The bond's window
        // restarts now, so it cannot have elapsed, and nothing is created. This is the regression
        // itself, reproduced.
        let mut restarted = PassRunner::new(effects(), log("restarted"));
        let stalled = restarted
            .run(&at(FIRST_SEEN_MS + SETTLING_WINDOW_MS))
            .expect("the observation succeeds");
        assert!(
            created(&stalled).is_empty(),
            "a fresh tracker restarts the window, so the identical pass creates nothing — this is \
             the silent stall the carry exists to prevent: {:?}",
            created(&stalled)
        );
    }

    /// An audit intent for a mirror create of `(store, root, epoch)`.
    fn create_intent(store: &str, root: &str, epoch: i64) -> SpendIntent {
        SpendIntent {
            kind: SpendKind::new(kinds::MIRROR_COIN),
            purpose: "create a mirror coin".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "mirror-collateral".to_string(),
            },
            asset: Asset::Dig,
            amount_mojos: REQUIRED,
            fee_mojos: 0,
            store_id: Some(id(store)),
            bond: Some(AuditedBond {
                root: id(root),
                epoch,
            }),
        }
    }

    /// Rule 1 again, reached through the funds READ rather than the funds gate.
    ///
    /// A wallet that can be talked to but cannot report its $DIG used to abort the pass, so a node
    /// in that state could neither advertise nor recover what it had already locked -- the legacy
    /// defect exactly, entered by a different door. The balance prices creates and nothing else.
    ///
    /// The fixture needs the widened double: every other `FakeEffects` returns `Ok` for the balance,
    /// so `PassError::Wallet` on that call was unreachable from any fixture and the arm read as
    /// covered while having never run. It also carries a bond WANTING a create, because the second
    /// half of the assertion is about what the node SAYS -- `FundsUnknown`, not `Unfunded`, which
    /// would send a person hunting for $DIG when what is broken is the wallet the node asks.
    #[test]
    fn an_unreadable_balance_defers_creates_and_still_reclaims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());
        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: vec![coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED)],
            balance_fails: true,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner
            .run(&ctx())
            .expect("an unreadable balance is not a reason to abandon locked money");

        assert_eq!(
            report.reclaimed.len(),
            1,
            "last epoch's coin still comes home: {report:?}"
        );
        assert!(
            report.created.is_empty(),
            "and nothing is bought at an unknown price: {report:?}"
        );
        assert_eq!(
            report.states,
            vec![(bond("aa", "11"), BondState::FundsUnknown)],
            "not `Unfunded` -- this pass has no evidence the wallet is short, only that it could not be read"
        );
    }

    /// Rule 1, and the whole reason step 4 states an order: reclaims are never gated on funds.
    ///
    /// The fixture is adversarial about the wallet — the balance is ZERO, and there is a held bond
    /// wanting a create. An implementation that gated reclaims on funds, which is the legacy defect,
    /// makes no reclaim at all here and both `Reclaim` entries are simply absent.
    #[test]
    fn reclaims_are_not_gated_on_funds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: vec![
                coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED),
                coin("gone", "zz", "99", NOW_EPOCH, REQUIRED),
            ],
            // Not one base unit of $DIG. A funds-gated reclaim path does nothing at all here.
            balance: 0,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            report.reclaimed.len(),
            2,
            "both coins come home on a wallet holding no $DIG at all: {report:?}"
        );
        assert!(
            report.created.is_empty(),
            "and nothing is created, because nothing can be paid for"
        );
        assert!(
            runner
                .effects
                .calls
                .borrow()
                .iter()
                .all(|c| matches!(c, Effect::Reclaim(_))),
            "no create was even attempted"
        );
    }

    /// The ORDER, on a fixture that has both — a reclaim and an affordable create.
    ///
    /// This is the placement assertion the test above cannot make: a fixture with only reclaims
    /// cannot show that creates come second. The pass reclaims last epoch's coin AND creates this
    /// epoch's bond, and the reclaim must be first, because its returned collateral is what the
    /// create behind it may be spending.
    #[test]
    fn the_reclaim_precedes_the_create_in_the_same_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: vec![coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED)],
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            *runner.effects.calls.borrow(),
            vec![
                Effect::Reclaim(coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED)),
                Effect::Create(bond("aa", "11"), NOW_EPOCH, REQUIRED),
            ],
            "epoch n-1's collateral comes home before epoch n's is locked, which is the whole reason \
             rollover is a re-create rather than a top-up"
        );
    }

    /// A reclaim that FAILS does not stop the reclaim behind it.
    ///
    /// The failing coin is deliberately FIRST, with an honest second coin behind it. A fixture where
    /// every reclaim fails could not tell "stopped at the failure" from "attempted them all", and one
    /// where the failure is last could not either.
    #[test]
    fn a_failed_reclaim_does_not_stop_the_next_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: Vec::new(),
            chain: vec![
                coin("aaaa", "aa", "11", NOW_EPOCH, REQUIRED),
                coin("bbbb", "bb", "22", NOW_EPOCH, REQUIRED),
            ],
            balance: 0,
            reclaim_fails: vec![id("aaaa")],
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(report.reclaim_failures.len(), 1, "the first one failed");
        assert_eq!(
            report.reclaimed,
            vec![coin("bbbb", "bb", "22", NOW_EPOCH, REQUIRED)],
            "and the money behind it still came home"
        );
    }

    /// A shortfall stops at a DETERMINISTIC PREFIX, and is not reported as a failure.
    ///
    /// Three held bonds, two coins' worth of $DIG. The prefix must be the first two in
    /// `(store_id, root)` order — the same two on every run — and `stopped_at` must stay `None`,
    /// because being short of money is a state a person can act on, not an error to alarm about.
    #[test]
    fn a_shortfall_creates_a_deterministic_prefix_and_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            // Deliberately out of order on disk, so passing requires the sort rather than the
            // accident of iteration order.
            disk: held(&[bond("cc", "33"), bond("aa", "11"), bond("bb", "22")]),
            chain: Vec::new(),
            balance: 2 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            report.created,
            vec![bond("aa", "11"), bond("bb", "22")],
            "the first two by (store_id, root), never an arbitrary two"
        );
        assert_eq!(
            *runner.effects.calls.borrow(),
            vec![
                Effect::Create(bond("aa", "11"), NOW_EPOCH, REQUIRED),
                Effect::Create(bond("bb", "22"), NOW_EPOCH, REQUIRED),
            ],
            "the third is not even attempted: no partial spend, no retry loop"
        );
        assert_eq!(
            report.stopped_at, None,
            "an unfunded pass is not a failed pass"
        );
        assert!(
            report.states.contains(&(
                bond("cc", "33"),
                BondState::Unfunded {
                    short_dig_base_units: REQUIRED
                }
            )),
            "and the bond that did not fit says how short it is: {:?}",
            report.states
        );
    }

    /// A create that FAILS stops the pass cleanly, and the bond behind it is not attempted.
    ///
    /// The failing bond is first with an affordable one behind it, so "stopped" is distinguishable
    /// from "ran them all and one errored".
    #[test]
    fn a_failed_create_stops_the_pass_and_the_next_bond_is_not_attempted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11"), bond("bb", "22")]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            create_fails: vec![bond("aa", "11")],
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            report.stopped_at.map(|(b, _)| b),
            Some(bond("aa", "11")),
            "the pass names where it stopped"
        );
        assert!(report.created.is_empty());
        assert_eq!(
            runner.effects.calls.borrow().len(),
            1,
            "the affordable bond behind the failure was NOT attempted"
        );
    }

    /// An in-flight create is suppressed, and the audit record is the only ledger consulted.
    ///
    /// The record is written by an ordinary `SpendJournal::begin`, and the runner is then built
    /// FRESH over that log with no memory of it — which is what a restarted node is. A runner that
    /// remembered its own submissions in memory would pass a test that reused one instance, and fail
    /// this one.
    ///
    /// The fixture carries a SECOND held bond with no record, so an implementation that suppressed
    /// everything whenever any record existed is red here rather than green.
    #[test]
    fn an_in_flight_create_is_suppressed_across_a_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());

        let _open = journal.begin(create_intent("aa", "11", NOW_EPOCH));

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11"), bond("bb", "22")]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            report.created,
            vec![bond("bb", "22")],
            "the bond with an open record is not created a second time; the other one is"
        );
        assert!(
            report
                .states
                .contains(&(bond("aa", "11"), BondState::Pending)),
            "and it reports pending rather than unfunded: {:?}",
            report.states
        );
    }

    /// Suppression LAPSES. A record that has resolved suppresses nothing.
    ///
    /// The same fixture as above but for the record's status, so the difference asserted is the
    /// status and nothing else. Without this, an implementation suppressing on the mere EXISTENCE of
    /// a mirror-coin record would pass the test above and leave the bond uncollateralised forever.
    #[test]
    fn a_resolved_record_no_longer_suppresses_the_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());

        let open = journal.begin(create_intent("aa", "11", NOW_EPOCH));
        journal.failed(&open, FailureStage::Signing, "no key");

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        assert_eq!(
            runner.run(&ctx()).expect("the pass runs").created,
            vec![bond("aa", "11")],
            "a create that failed at signing did not happen, so it must not suppress the retry"
        );
    }

    /// An open record for a PREVIOUS EPOCH suppresses nothing.
    ///
    /// One of the two reasons the bond key is three terms rather than one. Keyed on `store_id`
    /// alone — the only thing the record carried before this change — last epoch's open entry would
    /// suppress this epoch's create and the node would stop rolling over entirely.
    #[test]
    fn an_open_record_for_a_previous_epoch_does_not_suppress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let _open = journal.begin(create_intent("aa", "11", NOW_EPOCH - 1));

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        assert_eq!(
            runner.run(&ctx()).expect("the pass runs").created,
            vec![bond("aa", "11")],
        );
    }

    /// An open record for ANOTHER ROOT of the SAME STORE suppresses nothing.
    ///
    /// The other reason, and the one a store-keyed implementation gets wrong while passing the epoch
    /// test above. Getting it wrong withholds a bond the node genuinely holds.
    #[test]
    fn an_open_record_for_another_root_of_the_same_store_does_not_suppress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (journal, log) = journal(dir.path());
        let _open = journal.begin(create_intent("aa", "99", NOW_EPOCH));

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        assert_eq!(
            runner.run(&ctx()).expect("the pass runs").created,
            vec![bond("aa", "11")],
            "one root of a store being in flight says nothing about another root of it"
        );
    }

    /// An unknown requirement defers CREATES and leaves RECLAIMS alone.
    ///
    /// The fixture carries both a bond wanting a create and a coin wanting a reclaim, so an
    /// implementation that returned early on an unknown requirement — stranding collateral for as
    /// long as the census is behind — is red rather than green.
    #[test]
    fn a_requirement_unknown_defers_creates_but_not_reclaims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: vec![coin("gone", "zz", "99", NOW_EPOCH, REQUIRED)],
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let mut ctx = ctx();
        ctx.requirement = CollateralRequirementResult::Unknown {
            reason: CollateralUnknownReason::BehindFinalityDepth,
        };

        let report = runner.run(&ctx).expect("the pass runs");

        assert_eq!(report.reclaimed.len(), 1, "the reclaim is unaffected");
        assert!(report.created.is_empty(), "and no create is priced");
        assert_eq!(
            report.per_coin_dig_base_units, None,
            "no amount is guessed -- a create at the wrong amount locks money and advertises nothing"
        );
        assert!(
            report.states.contains(&(
                bond("aa", "11"),
                BondState::Deferred {
                    reason: CollateralUnknownReason::BehindFinalityDepth
                }
            )),
            "and the reason is the requirement's own, not an out-of-funds alarm: {:?}",
            report.states
        );
    }

    /// The switch OFF reclaims EVERYTHING and creates nothing.
    ///
    /// Two live coins and two held bonds. OFF must RELEASE the locked collateral rather than freeze
    /// it: a revocation that stranded the user's $DIG behind their own decision to stop would invert
    /// the meaning of revoking.
    #[test]
    fn the_switch_off_reclaims_everything_and_creates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11"), bond("bb", "22")]),
            chain: vec![
                coin("c1", "aa", "11", NOW_EPOCH, REQUIRED),
                coin("c2", "bb", "22", NOW_EPOCH, REQUIRED),
            ],
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let mut ctx = ctx();
        ctx.creates_enabled = false;

        let report = runner.run(&ctx).expect("the pass runs");

        assert_eq!(report.reclaimed.len(), 2, "every live coin comes home");
        assert!(report.created.is_empty());
        assert!(
            runner
                .effects
                .calls
                .borrow()
                .iter()
                .all(|c| matches!(c, Effect::Reclaim(_))),
            "and no create was attempted at all"
        );
    }

    /// A `Relayed` capsule buys no coin, and is reported as withheld rather than omitted.
    ///
    /// This is the one place an attacker influences what the node spends its own money on: a
    /// stranger chooses what this node relays. The fixture carries a `Held` bond alongside, so an
    /// implementation that dropped every relayed capsule silently is red — it creates one coin
    /// (correct) and reports one state (wrong).
    #[test]
    fn a_relayed_capsule_never_reaches_the_create_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let mut disk = held(&[bond("aa", "11")]);
        disk.push(ObservedCapsule {
            bond: bond("zz", "99"),
            provenance: CapsuleProvenance::Relayed,
        });

        let effects = FakeEffects {
            disk,
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(
            report.created,
            vec![bond("aa", "11")],
            "a capsule a stranger chose buys nothing"
        );
        assert!(
            report
                .states
                .contains(&(bond("zz", "99"), BondState::Withheld)),
            "and it is accounted for as withheld on purpose, not silently absent: {:?}",
            report.states
        );
    }

    /// An unreadable chain aborts the pass. It is NOT read as "this node owns no coins".
    ///
    /// The distinction is the whole reason `run` returns a `Result` at all: an empty inventory is a
    /// definite answer that plans a create for every held bond, and doing that while every one of
    /// them may already have a coin would lock a second epoch's collateral against each.
    #[test]
    fn an_unreadable_chain_makes_the_pass_spend_nothing() {
        struct BlindChain;
        impl MirrorEffects for BlindChain {
            fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
                Ok(vec![ObservedCapsule {
                    bond: Bond::new("a".repeat(64), "1".repeat(64)),
                    provenance: CapsuleProvenance::Held,
                }])
            }
            fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
                Err(PassError::Chain("no source".to_string()))
            }
            fn coin_confirmation(&self, _: &str) -> Result<Option<u32>, PassError> {
                panic!("a pass that cannot see the chain resolves nothing")
            }
            fn dig_balance_base_units(&self) -> Result<u64, PassError> {
                Ok(u64::MAX)
            }
            fn reclaim(&self, _: &HeldMirror, _: ReclaimReason) -> Result<(), PassError> {
                panic!("a pass that cannot see the chain must spend nothing")
            }
            fn create(&self, _: &Bond, _: i64, _: u64) -> Result<(), PassError> {
                panic!("a pass that cannot see the chain must spend nothing")
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());
        let mut runner = PassRunner::new(BlindChain, log).with_settling_window_ms(0);

        assert_eq!(
            runner.run(&ctx()).err(),
            Some(PassError::Chain("no source".to_string())),
            "an unknown chain is not an empty chain"
        );
    }
    /// The observation is normalised BEFORE it is sorted, so a producer that spells an id
    /// differently cannot change the order of the surface.
    ///
    /// The fixture varies the two axes independently — one bond upper-case, one `0x`-prefixed — so a
    /// normaliser that handled only case or only the prefix is red rather than green. It also puts
    /// them in an order that the raw strings would sort DIFFERENTLY from the canonical ones: `0x…`
    /// sorts before every hex digit and `AA…` sorts before `aa…`, so an implementation that sorted
    /// first and normalised afterwards produces a different sequence here.
    #[test]
    fn bond_ids_are_canonicalised_before_anything_orders_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: vec![
                ObservedCapsule {
                    bond: Bond::new(id("bb").to_ascii_uppercase(), id("22").to_ascii_uppercase()),
                    provenance: CapsuleProvenance::Held,
                },
                ObservedCapsule {
                    bond: Bond::new(format!("0x{}", id("aa")), format!("0x{}", id("11"))),
                    provenance: CapsuleProvenance::Held,
                },
            ],
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        assert_eq!(
            runner.run(&ctx()).expect("the pass runs").created,
            vec![bond("aa", "11"), bond("bb", "22")],
            "both spellings reduce to the canonical form, and the order is the canonical one"
        );
    }
    /// The locked total spans the WHOLE owned set, including coins being reclaimed.
    ///
    /// Three coins: one kept, one reclaimed because its `.dig` is gone, one reclaimed because its
    /// epoch ended — and each locks a DIFFERENT amount, so no pair sums to the same figure as
    /// another and a partial sum cannot coincide with the right answer. That last part is what makes
    /// the assertion load-bearing: with three coins of 1_000 each, "kept only" and "all three" are
    /// distinguishable, but "kept plus one reclaim" and any other pair are not.
    ///
    /// Excluding the reclaiming coins would report 300 base units as free while 2_400 of them are
    /// still on chain — unspendable money shown as available, which is the shape of the lie
    /// dig-app#289 renders this figure to avoid.
    #[test]
    fn the_locked_total_includes_coins_that_are_being_reclaimed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let effects = FakeEffects {
            disk: held(&[bond("aa", "11")]),
            chain: vec![
                coin("kept", "aa", "11", NOW_EPOCH, 300),
                coin("gone", "zz", "99", NOW_EPOCH, 900),
                coin("old", "yy", "88", NOW_EPOCH - 1, 1_500),
            ],
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let mut runner = runner(effects, log);

        let report = runner.run(&ctx()).expect("the pass runs");

        assert_eq!(report.reclaimed.len(), 2, "two coins are on their way home");
        assert_eq!(
            report.locked_dig_base_units,
            300 + 900 + 1_500,
            "a broadcast reclaim has not confirmed, so its collateral is still locked"
        );
    }
}
