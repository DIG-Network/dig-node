//! Convergence of the mirror lifecycle (dig-node#464) — the two headline invariants, proven as
//! PROPERTIES OVER SUCCESSIVE PASSES rather than as the outcome of one.
//!
//! # What these tests assert that the rest of the suite does not
//!
//! Every other test here asserts what ONE pass decides. That is the right unit for a decision, and
//! it is the wrong unit for self-healing: a test that drives a failure and asserts the failure has
//! proven the failure, not the healing. The claim this ticket makes is about the SECOND pass —
//! *"even if the first attempt failed"* — so every test below runs the pass again, after the
//! failure, and asserts the desired state is reached.
//!
//! The two invariants, stated as convergence:
//!
//! * a `.dig` store on disk with no coin gets a coin, N passes later;
//! * a mirror coin with no matching store on disk is spent, N passes later.
//!
//! # Why N is small, and where it stops being small
//!
//! **N = 2 for every hazard driven here**, and that is not a tuning choice — it falls out of the
//! architecture. A pass is a pure function of two observations (`observe_disk`, `observe_chain`)
//! and re-derives the whole desired state each round, so a failed attempt is not remembered as a
//! failure: it simply is not in the observation next time, and the same decision is taken again.
//! Nothing carries a retry counter because nothing needs one; the pass IS the retry.
//!
//! The one place N is larger is the in-flight suppression (§25.4.6), which is deliberately keyed on
//! an audit record rather than on an observation — because a broadcast create is invisible on chain
//! for a confirmation window, and a second pass inside that window would pay for a duplicate coin.
//! That suppression is bounded by the EPOCH, not by the round: see
//! [`a_stuck_open_record_suppresses_only_until_the_epoch_rolls`], which pins the bound from both
//! sides.
//!
//! # The double is a WORLD, not a recorder
//!
//! [`World`] applies effects to its own chain: a successful create makes a coin appear, a
//! successful reclaim makes one disappear. A recording double cannot express convergence at all —
//! it answers the same thing on pass 2 as on pass 1, so "the coin exists now" is unassertable and
//! the strongest available assertion degrades to "it tried again", which is the weaker claim this
//! ticket exists to reject.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::plan::{Bond, HeldMirror, ReclaimReason};
use super::runner::{MirrorEffects, ObservedCapsule, PassContext, PassError, PassRunner};
use crate::spend_audit::{
    kinds, Asset, AuditedBond, Authority, SpendIntent, SpendJournal, SpendKind, SpendLog,
};
use dig_node_control_interface::results::CollateralRequirementResult;
use dig_node_core::CapsuleProvenance;

const NOW_EPOCH: i64 = 100;
const REQUIRED: u64 = 1_000;

/// A confirmation height that is not zero, not an epoch, and not any other literal in this file, so
/// an implementation that reused one of those could not accidentally agree with an assertion.
const LANDED_HEIGHT: u32 = 9_224_641;

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

fn coin(tag: &str, store: &str, root: &str, epoch: i64) -> HeldMirror {
    HeldMirror {
        coin_id: id(tag),
        store_id: id(store),
        root: id(root),
        epoch,
        collateral_dig_base_units: REQUIRED,
    }
}

/// A chain and a disk that CHANGE when the node acts on them.
///
/// The failure schedules are counters rather than id lists on purpose: the interesting fixture is
/// "the first attempt fails and the next one does not", which is a statement about attempt ORDER.
/// An id list would fail every attempt on that id forever, and a test built on one could only ever
/// assert that the node kept trying — never that it arrived.
#[derive(Default)]
struct World {
    disk: RefCell<Vec<ObservedCapsule>>,
    chain: RefCell<Vec<HeldMirror>>,
    balance: Cell<u64>,
    /// Make the BALANCE READ fail while this is positive, decremented per pass that reads it.
    balance_read_failures: Cell<usize>,
    /// Fail this many create attempts before the first one is allowed to succeed.
    create_failures: Cell<usize>,
    /// Fail this many reclaim attempts before the first one is allowed to succeed.
    reclaim_failures: Cell<usize>,
    /// Distinguishes the coins successive creates produce, so a duplicate is visible as a duplicate.
    minted: Cell<usize>,
}

impl World {
    fn holding(bonds: &[Bond]) -> Rc<Self> {
        let world = World::default();
        *world.disk.borrow_mut() = bonds
            .iter()
            .map(|b| ObservedCapsule {
                bond: b.clone(),
                provenance: CapsuleProvenance::Held,
            })
            .collect();
        world.balance.set(REQUIRED * 100);
        Rc::new(world)
    }

    fn with_coins(self: Rc<Self>, coins: &[HeldMirror]) -> Rc<Self> {
        *self.chain.borrow_mut() = coins.to_vec();
        self
    }

    /// Does the chain show a coin bonding this `(store, root)` for `epoch`?
    fn has_coin_for(&self, bond: &Bond, epoch: i64) -> bool {
        self.chain
            .borrow()
            .iter()
            .any(|c| c.store_id == bond.store_id && c.root == bond.root && c.epoch == epoch)
    }

    fn coin_count(&self) -> usize {
        self.chain.borrow().len()
    }
}

impl MirrorEffects for World {
    fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
        Ok(self.disk.borrow().clone())
    }

    fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
        Ok(self.chain.borrow().clone())
    }

    fn coin_confirmation(&self, coin_id: &str) -> Result<Option<u32>, PassError> {
        Ok(self
            .chain
            .borrow()
            .iter()
            .any(|c| c.coin_id == coin_id)
            .then_some(LANDED_HEIGHT))
    }

    fn dig_balance_base_units(&self) -> Result<u64, PassError> {
        let remaining = self.balance_read_failures.get();
        if remaining > 0 {
            self.balance_read_failures.set(remaining - 1);
            return Err(PassError::Wallet("the wallet is locked".to_string()));
        }
        Ok(self.balance.get())
    }

    fn reclaim(&self, mirror: &HeldMirror, _reason: ReclaimReason) -> Result<(), PassError> {
        let remaining = self.reclaim_failures.get();
        if remaining > 0 {
            self.reclaim_failures.set(remaining - 1);
            return Err(PassError::Wallet("no fee coin".to_string()));
        }
        self.chain
            .borrow_mut()
            .retain(|c| c.coin_id != mirror.coin_id);
        Ok(())
    }

    fn create(&self, bond: &Bond, epoch: i64, amount: u64) -> Result<(), PassError> {
        let remaining = self.create_failures.get();
        if remaining > 0 {
            self.create_failures.set(remaining - 1);
            return Err(PassError::Wallet("no selectable coin".to_string()));
        }
        let minted = self.minted.get() + 1;
        self.minted.set(minted);
        self.chain.borrow_mut().push(HeldMirror {
            coin_id: id(&format!("c{minted}")),
            store_id: bond.store_id.clone(),
            root: bond.root.clone(),
            epoch,
            collateral_dig_base_units: amount,
        });
        Ok(())
    }
}

/// The runner OWNS its effects and exposes no accessor, so a test that must both drive the world
/// and read it afterwards shares one through an [`Rc`]. Delegating rather than adding an accessor
/// keeps the production type's surface unchanged: an accessor would exist only for tests, and the
/// next reader could not tell that from a capability something else relies on.
impl MirrorEffects for Rc<World> {
    fn observe_disk(&self) -> Result<Vec<ObservedCapsule>, PassError> {
        World::observe_disk(self)
    }

    fn observe_chain(&self) -> Result<Vec<HeldMirror>, PassError> {
        World::observe_chain(self)
    }

    fn coin_confirmation(&self, coin_id: &str) -> Result<Option<u32>, PassError> {
        World::coin_confirmation(self, coin_id)
    }

    fn dig_balance_base_units(&self) -> Result<u64, PassError> {
        World::dig_balance_base_units(self)
    }

    fn reclaim(&self, mirror: &HeldMirror, reason: ReclaimReason) -> Result<(), PassError> {
        World::reclaim(self, mirror, reason)
    }

    fn create(&self, bond: &Bond, epoch: i64, amount: u64) -> Result<(), PassError> {
        World::create(self, bond, epoch, amount)
    }
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

fn ctx_at(epoch: i64) -> PassContext {
    PassContext {
        now_unix_ms: 1_000_000,
        current_epoch: epoch,
        requirement: known(),
        margin_bp: 0,
        creates_enabled: true,
    }
}

fn ctx() -> PassContext {
    ctx_at(NOW_EPOCH)
}

/// A runner over a real, empty audit log, with the presence debounce already satisfied.
///
/// The log is REAL rather than absent so the in-flight suppression is genuinely exercised: a test
/// whose ledger could not be read would suppress nothing for the wrong reason, and would then pass
/// under an implementation that suppressed forever.
fn runner(world: &Rc<World>, log: SpendLog) -> PassRunner<Rc<World>> {
    PassRunner::new(Rc::clone(world), log).with_settling_window_ms(0)
}

fn log_at(dir: &std::path::Path, tag: &str) -> SpendLog {
    SpendLog::at(dir.join(format!("{tag}.jsonl")))
}

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

/// **INVARIANT 1, after a failed create: a held store gets a coin, and N is 2.**
///
/// The first create is refused outright, exactly as an unselectable funding coin refuses it. The
/// second pass is the assertion: nothing recorded the refusal, so the same bond is decided again
/// from the same two observations and the coin appears.
///
/// The control that makes this discriminating is the SECOND held bond, whose create is never
/// refused. Without it, an implementation that created everything twice — or that ignored the
/// failure entirely — would look identical to one that healed.
#[test]
fn a_refused_create_is_retried_by_the_next_pass_and_the_store_ends_bonded() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let refused = bond("aa", "11");
    let control = bond("bb", "22");

    let world = World::holding(&[refused.clone(), control.clone()]);
    world.create_failures.set(1);
    let mut runner = runner(&world, log_at(dir.path(), "refused-create"));

    let first = runner.run(&ctx()).expect("the pass observes");
    assert_eq!(
        first.created,
        Vec::<Bond>::new(),
        "the pass stops cleanly at the refused create rather than continuing past it: {first:?}"
    );
    assert!(
        !world.has_coin_for(&refused, NOW_EPOCH),
        "and the refused bond genuinely has no coin after pass 1"
    );

    let second = runner.run(&ctx()).expect("the pass observes");

    assert_eq!(
        second.created,
        vec![refused.clone(), control.clone()],
        "pass 2 re-derives both creates from the same observations; the failure was not remembered"
    );
    assert!(
        world.has_coin_for(&refused, NOW_EPOCH),
        "N = 2: the store whose first create failed is bonded on the very next pass"
    );
    assert!(
        world.has_coin_for(&control, NOW_EPOCH),
        "and the control bond, which was never refused, is bonded too"
    );

    let third = runner.run(&ctx()).expect("the pass observes");
    assert_eq!(
        third.created,
        Vec::<Bond>::new(),
        "and the node then STOPS: a coin the chain shows is not paid for twice. An implementation \
         that retried from a record instead of from the observation is red here, not above: \
         {third:?}"
    );
    assert_eq!(
        world.coin_count(),
        2,
        "two stores, two coins, no duplicate bought by the retry"
    );
}

/// **INVARIANT 2, after a failed reclaim: an orphaned coin is spent, and N is 2.**
///
/// A reclaim consults no ledger, no balance, no requirement and no switch — it is decided from the
/// disk and the chain alone — so the retry needs nothing to lift. This test pins that: the first
/// reclaim fails, and the second pass spends the coin with no intervening change of any kind.
///
/// The control is the SECOND orphaned coin, whose reclaim is never refused, asserting the failing
/// one did not stop it. A single-coin fixture cannot see that.
#[test]
fn a_failed_reclaim_is_retried_by_the_next_pass_and_the_orphan_ends_spent() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let orphan = coin("dd", "aa", "11", NOW_EPOCH);
    let other = coin("ee", "bb", "22", NOW_EPOCH);

    // Nothing on disk: both coins bond stores this node no longer holds.
    let world = World::holding(&[]).with_coins(&[orphan.clone(), other.clone()]);
    world.reclaim_failures.set(1);
    let mut runner = runner(&world, log_at(dir.path(), "failed-reclaim"));

    let first = runner.run(&ctx()).expect("the pass observes");
    assert_eq!(
        first.reclaim_failures.len(),
        1,
        "the first reclaim failed, as the fixture arranged: {first:?}"
    );
    assert_eq!(
        first.reclaimed,
        vec![other.clone()],
        "and the failure did not stop the reclaim behind it"
    );
    assert_eq!(
        world.coin_count(),
        1,
        "so exactly one coin is still on chain after pass 1"
    );

    let second = runner.run(&ctx()).expect("the pass observes");

    assert_eq!(
        second.reclaimed,
        vec![orphan.clone()],
        "N = 2: the coin whose reclaim failed is spent on the very next pass, with nothing changed"
    );
    assert_eq!(
        world.coin_count(),
        0,
        "and no mirror coin outlives the store it advertises"
    );

    let third = runner.run(&ctx()).expect("the pass observes");
    assert!(
        third.reclaimed.is_empty() && third.reclaim_failures.is_empty(),
        "a coin already spent is not re-spent: the retry is driven by the chain, not by a record"
    );
}

/// **A shortfall heals when the money arrives, and nothing records the shortfall.**
///
/// `funding.rs` refuses the whole create when short, and `plan::split_by_funds` stops at the first
/// unaffordable bond. Neither writes anything: the refusal happens before a record is opened, so
/// there is nothing that could suppress the retry. This asserts the whole of that as one property —
/// the wallet is topped up between passes and the bond converges at N = 2.
#[test]
fn an_unfunded_bond_is_created_on_the_pass_after_the_money_arrives() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let waiting = bond("aa", "11");

    let world = World::holding(std::slice::from_ref(&waiting));
    world.balance.set(REQUIRED - 1); // short by one base unit, and by nothing else
    let mut runner = runner(&world, log_at(dir.path(), "unfunded"));

    let first = runner.run(&ctx()).expect("the pass observes");
    assert!(
        first.created.is_empty(),
        "a wallet one base unit short creates nothing: {first:?}"
    );
    assert!(
        first.stopped_at.is_none(),
        "and being short is not reported as a failure of the pass"
    );

    world.balance.set(REQUIRED);
    let second = runner.run(&ctx()).expect("the pass observes");

    assert_eq!(
        second.created,
        vec![waiting.clone()],
        "N = 2: the pass after the money arrives creates the coin, with no operator action"
    );
    assert!(world.has_coin_for(&waiting, NOW_EPOCH));
}

/// **An unreadable WALLET degrades the create half only, and heals; reclaims never waited.**
///
/// The balance read is what prices creates, so a wallet that cannot be read must not abort the
/// pass — rule 1 of `pass.rs` reached through the observation instead of through the gate. The
/// fixture holds BOTH halves at once: an orphaned coin to reclaim and a held store to bond. Pass 1
/// must reclaim and not create; pass 2, with the wallet readable, must create.
///
/// Asserting only the create half would pass under an implementation that returned `Err` from the
/// whole pass, which is the regression that strands collateral on an exhausted node.
#[test]
fn an_unreadable_wallet_defers_creates_reclaims_anyway_and_heals_next_pass() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let waiting = bond("aa", "11");
    let orphan = coin("dd", "bb", "22", NOW_EPOCH);

    let world =
        World::holding(std::slice::from_ref(&waiting)).with_coins(std::slice::from_ref(&orphan));
    world.balance_read_failures.set(1);
    let mut runner = runner(&world, log_at(dir.path(), "wallet-unreadable"));

    let first = runner
        .run(&ctx())
        .expect("an unreadable WALLET is not an unreadable pass");
    assert_eq!(
        first.reclaimed,
        vec![orphan],
        "the orphan comes home even though the wallet could not be read: {first:?}"
    );
    assert!(
        first.created.is_empty(),
        "and nothing is created, because nothing could be priced against a balance"
    );

    let second = runner.run(&ctx()).expect("the pass observes");
    assert_eq!(
        second.created,
        vec![waiting.clone()],
        "N = 2: the pass after the wallet answers creates the coin"
    );
    assert!(world.has_coin_for(&waiting, NOW_EPOCH));
}

/// **A failed broadcast retries, and the retry is safe because the CHAIN decides — not the record.**
///
/// A broadcast failure is an unknown wearing a failure's name: the bundle may already sit in a
/// mempool. So the retry must be safe for a reason stronger than "the record says it failed", and
/// the reason is that a coin which DID land is visible in `observe_chain` and covers the bond
/// through `plan`, leaving nothing to create.
///
/// Both directions are driven, because only the pair discriminates. A one-sided test would pass
/// under an implementation that never retried at all.
#[test]
fn a_broadcast_failure_retries_when_no_coin_landed_and_stands_down_when_one_did() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let subject = bond("aa", "11");

    // Direction 1: the bundle really did not land. Nothing is on chain, so the bond is uncovered
    // and the next pass creates it.
    let world = World::holding(std::slice::from_ref(&subject));
    world.create_failures.set(1);
    let mut nothing_landed = runner(&world, log_at(dir.path(), "broadcast-nothing-landed"));
    nothing_landed.run(&ctx()).expect("the pass observes");
    let retried = nothing_landed.run(&ctx()).expect("the pass observes");
    assert_eq!(
        retried.created,
        vec![subject.clone()],
        "no coin landed, so the bond is still uncovered and is created again: {retried:?}"
    );

    // Direction 2: the bundle DID land, in the window between the failure and this pass. The coin
    // is in the observation, and the same code must now decide NOT to create.
    let world = World::holding(std::slice::from_ref(&subject))
        .with_coins(&[coin("dd", "aa", "11", NOW_EPOCH)]);
    let mut it_landed = runner(&world, log_at(dir.path(), "broadcast-it-landed"));
    let report = it_landed.run(&ctx()).expect("the pass observes");
    assert!(
        report.created.is_empty(),
        "a coin the chain shows covers the bond, whatever a record says of the attempt: {report:?}"
    );
    assert_eq!(
        world.coin_count(),
        1,
        "and the wallet did not pay for a second coin"
    );
}

/// **The one suppression that is NOT re-derived from observation, bounded from both sides.**
///
/// §25.4.6 suppresses a create whose audit record is open (`Pending` or `Submitted`) for the
/// current epoch. That record is a ledger entry, not an observation, so it does NOT lift when the
/// next pass looks at the chain — and if the bundle never lands, nothing settles it. This is the
/// one hazard in dig-node#464 whose N is not 2.
///
/// **N is bounded by the EPOCH, not by the round.** The suppression is keyed on the record's own
/// epoch, so it lapses at the rollover: `MIRROR_EPOCH_LENGTH_MS / MIRROR_ROUND_LENGTH_MS`
/// = 1,008 passes in the worst case — seven days of an uncollateralised store, then healing with no
/// operator action.
///
/// Pinned from BOTH sides, because a bound tested only from below can only confirm itself: the
/// create is suppressed WITHIN the epoch (so the test is not vacuous) and taken at the NEXT epoch
/// (so the bound is real rather than infinite). An implementation whose suppression never lifted
/// would pass the first assertion and fail the second.
#[test]
fn a_stuck_open_record_suppresses_only_until_the_epoch_rolls() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let log = log_at(dir.path(), "stuck-record");
    let journal = SpendJournal::new(log.clone());
    let stuck = bond("aa", "11");

    // An open record for this epoch that nothing will ever settle — the shape a hard kill leaves
    // between `begin` and any outcome, and the shape a `Submitted` bundle that never confirms
    // leaves indefinitely. Held alive so no `Drop` resolves it.
    let _open = journal.begin(create_intent("aa", "11", NOW_EPOCH));

    let world = World::holding(std::slice::from_ref(&stuck));
    let mut runner = runner(&world, log);

    let within = runner.run(&ctx()).expect("the pass observes");
    assert!(
        within.created.is_empty(),
        "within the epoch the open record suppresses the create, by design: {within:?}"
    );

    // Not a shorter round and not a retry counter: the same node, one epoch later.
    let after = runner
        .run(&ctx_at(NOW_EPOCH + 1))
        .expect("the pass observes");
    assert_eq!(
        after.created,
        vec![stuck.clone()],
        "the suppression LAPSES at the rollover, so the bound is one epoch rather than forever"
    );
    assert!(world.has_coin_for(&stuck, NOW_EPOCH + 1));
}
