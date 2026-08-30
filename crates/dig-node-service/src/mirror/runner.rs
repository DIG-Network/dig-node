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
}

impl std::fmt::Display for PassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassError::Disk(cause) => write!(f, "the capsule cache could not be scanned: {cause}"),
            PassError::Chain(cause) => write!(f, "the chain source could not be read: {cause}"),
            PassError::Wallet(cause) => write!(f, "the operator wallet could not act: {cause}"),
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
}

/// Runs reconcile passes. Long-lived: it owns the presence tracker, which is the only state a pass
/// carries between runs.
pub struct PassRunner<E> {
    effects: E,
    presence: super::presence::PresenceTracker,
    log: SpendLog,
    settling_window_ms: u64,
}

impl<E: MirrorEffects> PassRunner<E> {
    /// Build a runner over `effects`, reading its in-flight ledger from `log`.
    pub fn new(effects: E, log: SpendLog) -> Self {
        Self {
            effects,
            presence: super::presence::PresenceTracker::new(),
            log,
            settling_window_ms: super::presence::SETTLING_WINDOW_MS,
        }
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
        });

        Ok(self.execute(decision, ctx.current_epoch, locked_dig_base_units))
    }

    /// Step 4 and step 5: reclaims first, then creates, stopping cleanly.
    fn execute(
        &self,
        decision: PassDecision,
        current_epoch: i64,
        locked_dig_base_units: u64,
    ) -> PassReport {
        let PassDecision {
            reclaim,
            create,
            per_coin_dig_base_units,
            states,
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
                        // Stop, cleanly. Not a retry and not a skip-and-continue: a create that
                        // failed for want of a coin will fail identically for the next bond, and the
                        // next pass re-derives the whole answer anyway.
                        stopped_at = Some((bond, e));
                        break;
                    }
                }
            }
        }

        PassReport {
            reclaimed,
            created,
            reclaim_failures,
            stopped_at,
            states,
            per_coin_dig_base_units,
            locked_dig_base_units,
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
    }

    impl MirrorEffects for FakeEffects {
        fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
            Ok(self.disk.clone())
        }

        fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
            Ok(self.chain.clone())
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
                return Err(PassError::Wallet("no selectable coin".to_string()));
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
            disk: held(&[capsule.clone()]),
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
            "not `Unfunded` -- this pass has no evidence the wallet is short, only that it could              not be read"
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

    /// The presence tracker CARRIED between rounds is what lets a bond ever settle.
    ///
    /// The scheduler rebuilds its effects — and therefore its runner — every round, because the
    /// chain source is per-round and does not outlive it. `with_presence` / `into_presence` are the
    /// only thing that survives that rebuild. Drop the carry and every round begins with a fresh
    /// tracker; a fresh tracker has never seen the bond before, so it is never stable, so no create
    /// is ever made — **while the node logs a completed pass each round and looks like it is
    /// reconciling normally**. Nothing else in the suite goes red for that, which is precisely why
    /// this test exists.
    ///
    /// The assertion is a PAIR over the same two passes, because only the pair discriminates. "The
    /// second pass creates" alone is satisfied by an implementation with no debounce whatsoever, and
    /// "a fresh tracker suppresses" alone is satisfied by an implementation that suppresses forever.
    /// Carried settles, fresh does not — that is the property, and it needs both halves.
    ///
    /// The window is REAL here (`SETTLING_WINDOW_MS`) rather than the zero the shared `runner`
    /// helper uses, since a zero window makes every tracker settle immediately and the carry
    /// unobservable — the shape of fixture that would let this defect through while reading as
    /// thorough.
    #[test]
    fn dropping_the_presence_carry_between_rounds_silently_stops_every_create() {
        use super::super::presence::{PresenceTracker, SETTLING_WINDOW_MS};

        let dir = tempfile::tempdir().expect("tempdir");
        let (_journal, log) = journal(dir.path());

        let settling = bond("aa", "11");
        // One round's fixture: the same capsule on disk, funded, nothing on chain yet.
        let effects = || FakeEffects {
            disk: held(&[settling.clone()]),
            chain: Vec::new(),
            balance: 10 * REQUIRED,
            ..Default::default()
        };
        let at = |now_unix_ms: u64| PassContext {
            now_unix_ms,
            ..ctx()
        };

        const FIRST: u64 = 1_000_000;
        let second = FIRST + SETTLING_WINDOW_MS + 1;

        // Round one, from nothing: the bond has just been seen for the first time, so it is not yet
        // stable and buys nothing. This is the state the carry has to transport.
        let mut round_one = PassRunner::new(effects(), log.clone())
            .with_settling_window_ms(SETTLING_WINDOW_MS)
            .with_presence(PresenceTracker::new());
        let first_report = round_one.run(&at(FIRST)).expect("the pass runs");
        assert!(
            first_report.created.is_empty(),
            "a bond seen once has not been stable for a window, so it must buy nothing yet: {:?}",
            first_report.created
        );
        let carried = round_one.into_presence();

        // Round two WITH the carry, a full window later: the bond has now held one state across the
        // window, so it settles and the create is made.
        let mut carried_round = PassRunner::new(effects(), log.clone())
            .with_settling_window_ms(SETTLING_WINDOW_MS)
            .with_presence(carried);
        let carried_report = carried_round.run(&at(second)).expect("the pass runs");
        assert_eq!(
            carried_report.created,
            vec![settling.clone()],
            "carrying the tracker is what makes the window wall-clock time rather than per-runner"
        );

        // The SAME round two with a FRESH tracker — the exact regression a dropped
        // `.with_presence(...)` produces. Same capsule, same clock, same funds, and nothing settles.
        let mut fresh_round = PassRunner::new(effects(), log)
            .with_settling_window_ms(SETTLING_WINDOW_MS)
            .with_presence(PresenceTracker::new());
        let fresh_report = fresh_round.run(&at(second)).expect("the pass runs");
        assert!(
            fresh_report.created.is_empty(),
            "a fresh tracker each round re-observes the bond as new forever, so no bond ever \
             settles and no coin is ever created -- with every pass still reporting success: {:?}",
            fresh_report.created
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
