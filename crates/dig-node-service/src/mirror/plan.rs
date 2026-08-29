//! The reconcile PLAN — what the chain must be made to look like, given what is on disk.
//!
//! This module is pure. It takes two snapshots — the capsules this node holds on disk, and the
//! mirror coins the chain says this node owns — and returns the work that would make them agree. It
//! reads no file, opens no socket, holds no key and consults no clock: the epoch is a parameter.
//!
//! Keeping it pure is what makes the hostile cases testable at all. Every interesting situation here
//! is a disagreement between two observations — a coin whose `.dig` is gone, a `.dig` whose coin was
//! never created, both epochs live across a rollover — and each of those is a two-line fixture
//! against a function, rather than a filesystem and a chain that must be induced into a state.
//!
//! # Local bookkeeping is never a third source of truth
//!
//! The legacy implementation kept an authoritative `.json` and stranded the money when it was lost
//! (measured on dig-node#377). There is no equivalent here, by construction: the planner's inputs are
//! the disk and the chain, and nothing it writes feeds back into what it reads. Handed a stale view
//! of either, it produces a plan that is wrong for that call and correct again on the next pass.

use std::collections::BTreeSet;

/// A `(store, root)` pair this node holds and is willing to advertise — one prospective mirror.
///
/// "Willing to advertise" is not the same as "present on disk". A capsule pulled on a stranger's
/// behalf is marked `Relayed` and is deliberately never advertised (dig-node#276), so it is not a
/// bond: locking collateral on it would be paying for an advertisement that is never published.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bond {
    /// Store launcher id, lowercase 64-hex.
    pub store_id: String,
    /// Generation root hash, lowercase 64-hex.
    pub root: String,
}

impl Bond {
    /// A bond over two ids.
    pub fn new(store_id: impl Into<String>, root: impl Into<String>) -> Self {
        Bond {
            store_id: store_id.into(),
            root: root.into(),
        }
    }
}

/// One mirror coin the chain says this node owns.
///
/// Produced from `dig_mirror_coin::list`, whose ownership comes from the coin's lineage proof rather
/// than from a hint — so a coin appearing here is one this node can actually spend, not one a
/// stranger hinted at it for the price of a dust coin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HeldMirror {
    /// The coin id, for the audit record and for the reclaim.
    pub coin_id: String,
    /// The store this coin declares it bonds.
    pub store_id: String,
    /// The root this coin declares it bonds.
    pub root: String,
    /// The epoch this coin declares it bonds.
    pub epoch: i64,
    /// The $DIG locked, in CAT mojos.
    pub collateral_dig_base_units: u64,
}

impl HeldMirror {
    /// The bond this coin claims to cover.
    fn bond(&self) -> Bond {
        Bond::new(&self.store_id, &self.root)
    }
}

/// Why a held coin is being reclaimed. Recorded because the two reasons are very different
/// situations, and an operator reading the audit record needs to know which one they are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReclaimReason {
    /// The `.dig` this coin bonds is no longer on disk, and the coin is for the CURRENT epoch.
    ///
    /// **This is the penalised state**, and it is why reclaim is loss avoidance rather than cleanup:
    /// a live coin advertising a capsule the node cannot serve is penalised later. It is also the
    /// one reclaim a crash can leave behind, because the file event that would have triggered it is
    /// exactly what a crash loses — which is why the start-up reconcile matters more than the
    /// watcher does.
    NoLongerHeld,
    /// The coin bonds an epoch that has already ended.
    ///
    /// The legacy had this as an operational step a human ran, and dig-node has no operator — so
    /// leaving it manual would strand one epoch's collateral per store, forever, with nobody to notice.
    EpochEnded,
}

/// What must happen to make the chain agree with the disk.
///
/// Reclaims are listed first and executed first, deliberately: a reclaim RETURNS money and may fund
/// the creates behind it, and a reclaim withheld because the wallet is short is the legacy defect
/// where a wallet at zero could neither advertise nor recover what it had already locked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MirrorPlan {
    /// Coins to spend back to the owner, with the reason each is being released.
    pub reclaim: Vec<(HeldMirror, ReclaimReason)>,
    /// Bonds with no coin for the current epoch, to be created.
    pub create: Vec<Bond>,
}

impl MirrorPlan {
    /// Is there nothing to do? The steady state on a node whose disk has not changed within an epoch.
    pub fn is_empty(&self) -> bool {
        self.reclaim.is_empty() && self.create.is_empty()
    }
}

/// Diff the disk against the chain for `current_epoch`.
///
/// `held` is what this node is willing to advertise; `on_chain` is what it actually owns.
///
/// | held coin | on disk | action |
/// |---|---|---|
/// | `epoch == current` | yes | keep |
/// | `epoch == current` | no | reclaim ([`ReclaimReason::NoLongerHeld`]) |
/// | `epoch < current` | either | reclaim ([`ReclaimReason::EpochEnded`]) |
/// | `epoch > current` | either | **keep** |
///
/// The last row is a decision, not a gap. The epoch clock is wall-clock with no chain input
/// (`dig_constants::mirror_epoch_at_unix_ms`), so a node whose clock runs slow sees a legitimately
/// created next-epoch coin as belonging to the future. Reclaiming on that reading would burn a fee
/// and destroy a valid bond on the strength of this machine's clock being wrong — and the coin
/// becomes ordinary at the next tick anyway. Keeping is the direction whose failure is recoverable.
///
/// Duplicate coins for one `(store, root, epoch)` are ALL kept while the bond is still held. Only
/// one is needed, but choosing which of two valid bonds to destroy is a decision this function does
/// not have the information to make, and destroying the wrong one costs a real advertisement. They
/// stop being duplicates at the next rollover, when both are reclaimed as `EpochEnded`.
///
/// `in_flight` is the set of bonds whose CURRENT-epoch create has already been submitted and has not
/// yet resolved — a `pending` or `submitted` mirror-coin entry in the audit record (`SPEC.md`
/// §25.4.6). They are excluded from the create set, and only from it: an in-flight create says
/// nothing about whether a DIFFERENT coin should be reclaimed, so passing a bond here can never
/// withhold a reclaim.
///
/// The suppression is necessary because a create is not visible on chain until it confirms, and a
/// pass that ran in that window would see the bond as uncovered and pay for a second coin. The
/// chain and the disk remain the only STEADY-STATE truths; this is the in-flight ledger, and it is
/// consulted for nothing else.
///
/// Suppressing is the fail-safe direction: a wrongly-suppressed create leaves money in the wallet
/// and the node undiscoverable for one pass (§25.9), while a wrongly-permitted one locks a second
/// epoch's collateral against a bond that already has a coin.
pub fn plan(
    held: &[Bond],
    on_chain: &[HeldMirror],
    current_epoch: i64,
    in_flight: &[Bond],
) -> MirrorPlan {
    let held_set: BTreeSet<&Bond> = held.iter().collect();

    let mut reclaim = Vec::new();
    let mut covered: BTreeSet<Bond> = BTreeSet::new();

    for coin in on_chain {
        match coin.epoch.cmp(&current_epoch) {
            std::cmp::Ordering::Less => {
                reclaim.push((coin.clone(), ReclaimReason::EpochEnded));
            }
            std::cmp::Ordering::Equal => {
                let bond = coin.bond();
                if held_set.contains(&bond) {
                    covered.insert(bond);
                } else {
                    reclaim.push((coin.clone(), ReclaimReason::NoLongerHeld));
                }
            }
            // A coin bonding a FUTURE epoch. Left alone — see the doc comment.
            std::cmp::Ordering::Greater => {}
        }
    }

    let in_flight_set: BTreeSet<&Bond> = in_flight.iter().collect();

    let mut create: Vec<Bond> = held
        .iter()
        .filter(|b| !covered.contains(*b) && !in_flight_set.contains(*b))
        .cloned()
        .collect();

    // Deterministic order, so a partially funded pass creates the same prefix on every run rather
    // than a different arbitrary subset each time — which would make an out-of-funds node's
    // behaviour unreproducible exactly when someone is trying to understand it.
    create.sort();
    create.dedup();
    reclaim.sort();

    MirrorPlan { reclaim, create }
}

/// How far down [`MirrorPlan::create`] the wallet can pay, and what is left short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSplit {
    /// The creates the wallet can pay for, in plan order.
    pub affordable: Vec<Bond>,
    /// The creates it cannot — what the node must report as uncollateralised.
    pub short: Vec<Bond>,
    /// How many more DIG base units would cover [`Self::short`] entirely.
    pub shortfall_dig_base_units: u64,
}

impl FundingSplit {
    /// Is anything going uncollateralised for want of funds?
    pub fn is_funded(&self) -> bool {
        self.short.is_empty()
    }
}

/// Split `create` at the point the balance runs out.
///
/// Creates STOP at the first unaffordable one rather than skipping it to take a cheaper later one. A
/// mirror coin is all-or-nothing at the epoch's required amount — there is no partial
/// collateralisation — so there is no
/// cheaper one to find, and hunting for an affordable subset would only make which stores get
/// advertised depend on the balance in a way nobody could predict or explain.
///
/// Funds are deliberately NOT consulted for reclaims. A reclaim returns collateral; gating it on the
/// balance is the legacy defect where a wallet at zero could neither advertise nor recover what it
/// had already locked.
///
/// `per_coin` is the CURRENT epoch's requirement in DIG base units —
/// `apply_safety_margin(required_per_store, margin_bp)` (`SPEC.md` §25.3), never a constant and never
/// a whole-$DIG figure. Whole $DIG is 1,000x smaller than base units and would make everything look
/// affordable; `dig-constants` removed its fixed `MIRROR_COIN_COLLATERAL_DIG = 20` in 0.13.0 for
/// exactly that class of error.
pub fn split_by_funds(create: &[Bond], balance_dig_base_units: u64, per_coin: u64) -> FundingSplit {
    // A zero per-coin collateral would make every bond free and the split meaningless. The crate
    // refuses a zero-collateral mirror anyway, so treat it as "nothing is affordable" rather than
    // dividing by it and reporting infinite capacity.
    let affordable_count = if per_coin == 0 {
        0
    } else {
        ((balance_dig_base_units / per_coin) as usize).min(create.len())
    };

    let (affordable, short) = create.split_at(affordable_count);
    FundingSplit {
        affordable: affordable.to_vec(),
        short: short.to_vec(),
        shortfall_dig_base_units: (short.len() as u64).saturating_mul(per_coin),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A stand-in for one epoch's requirement, in DIG base units: 1.000 DIG, the schedule's
    /// starting value. It is a TEST constant, deliberately not imported from anywhere — the
    /// production amount is derived per epoch (`SPEC.md` §25.3), so a test that pinned it to a
    /// library constant would go green against an implementation that had hard-coded one.
    const PER_COIN: u64 = 1_000;

    /// A DIFFERENT requirement, used to prove the split is genuinely parameterised rather than
    /// agreeing with [`PER_COIN`] by coincidence. The requirement moves in both directions as the
    /// network's state moves, so any fixture that only ever exercises one amount cannot tell a
    /// parameter from a constant.
    const PER_COIN_RAISED: u64 = 2_500;

    /// A distinguishable 64-hex id. Real ids are opaque, and tests that use short strings hide
    /// length assumptions in the path builders that consume them.
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
            collateral_dig_base_units: PER_COIN,
        }
    }

    /// The epoch every fixture below is "now" in. Pinned rather than computed from the wall clock:
    /// a fixture whose epoch comes from `SystemTime::now()` exercises whichever branch today
    /// happens to select, and passes for the wrong reason on most days.
    const NOW_EPOCH: i64 = 100;

    /// The ordinary case: nothing submitted and awaiting confirmation.
    ///
    /// Named rather than written as a bare `&[]` at every call site so that a reader can tell the
    /// "no creates are in flight" fixtures from the ones that deliberately exercise suppression.
    const NOT_IN_FLIGHT: &[Bond] = &[];

    #[test]
    fn a_held_capsule_with_no_coin_is_created() {
        let plan = plan(&[bond("aa", "11")], &[], NOW_EPOCH, NOT_IN_FLIGHT);
        assert_eq!(plan.create, vec![bond("aa", "11")]);
        assert!(plan.reclaim.is_empty());
    }

    #[test]
    fn a_coin_covering_a_held_capsule_this_epoch_is_left_alone() {
        let plan = plan(
            &[bond("aa", "11")],
            &[coin("c1", "aa", "11", NOW_EPOCH)],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );
        assert!(plan.is_empty(), "steady state must be a no-op: {plan:?}");
    }

    /// The penalised state, and the case the whole feature exists to avoid.
    ///
    /// The fixture keeps a SECOND store that is still held, and asserts it is untouched. Without
    /// that control an implementation that reclaims every coin it sees passes identically — the
    /// "strongest" fixture, one where nothing is held, is the one that cannot see the difference.
    #[test]
    fn a_coin_whose_capsule_is_gone_is_reclaimed_and_the_still_held_one_is_not() {
        let plan = plan(
            &[bond("aa", "11")],
            &[
                coin("c1", "aa", "11", NOW_EPOCH),
                coin("c2", "bb", "22", NOW_EPOCH),
            ],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("c2", "bb", "22", NOW_EPOCH), ReclaimReason::NoLongerHeld)],
            "only the coin whose capsule is gone may be reclaimed"
        );
        assert!(
            plan.create.is_empty(),
            "the still-held capsule is already covered"
        );
    }

    /// The automatic `meltOutdatedEpochs` the legacy left to a human.
    ///
    /// The previous epoch's coin bonds a capsule that is STILL on disk, so a planner that only
    /// reclaimed no-longer-held coins would leave it stranded forever. That is the actual legacy
    /// defect, and a fixture where the capsule had also been deleted could not tell the two rules
    /// apart.
    #[test]
    fn last_epochs_coin_is_reclaimed_even_though_its_capsule_is_still_held() {
        let plan = plan(
            &[bond("aa", "11")],
            &[coin("old", "aa", "11", NOW_EPOCH - 1)],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("old", "aa", "11", NOW_EPOCH - 1), ReclaimReason::EpochEnded)]
        );
        assert_eq!(
            plan.create,
            vec![bond("aa", "11")],
            "the still-held capsule needs a coin for the CURRENT epoch"
        );
    }

    /// Rollover with both epochs live: the previous coin comes back and the new one goes out, in
    /// the same pass. A node that did one but not the other is either uncollateralised or paying
    /// twice.
    #[test]
    fn an_epoch_rollover_reclaims_the_old_coin_and_creates_the_new_one() {
        let plan = plan(
            &[bond("aa", "11")],
            &[
                coin("old", "aa", "11", NOW_EPOCH - 1),
                coin("new", "aa", "11", NOW_EPOCH),
            ],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("old", "aa", "11", NOW_EPOCH - 1), ReclaimReason::EpochEnded)]
        );
        assert!(
            plan.create.is_empty(),
            "the current epoch is already covered — creating again would pay twice"
        );
    }

    /// A coin bonding a FUTURE epoch is kept.
    ///
    /// The control matters here: the same fixture carries a coin one epoch in the PAST, which must
    /// be reclaimed. A planner that simply ignored every epoch mismatch would pass a
    /// future-only fixture and strand the past coin, which is the expensive direction.
    #[test]
    fn a_future_epoch_coin_is_kept_while_a_past_epoch_coin_is_reclaimed() {
        let plan = plan(
            &[bond("aa", "11")],
            &[
                coin("future", "aa", "11", NOW_EPOCH + 1),
                coin("past", "aa", "11", NOW_EPOCH - 1),
            ],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("past", "aa", "11", NOW_EPOCH - 1), ReclaimReason::EpochEnded)],
            "a coin from the future must survive a slow local clock"
        );
        assert_eq!(
            plan.create,
            vec![bond("aa", "11")],
            "the future coin does not cover the current epoch"
        );
    }

    /// Two roots of ONE store are two independent bonds — the per-store-plus-root shape. A coin for
    /// the old root does not cover the new one, and the publisher may fund either.
    #[test]
    fn two_roots_of_one_store_are_two_independent_bonds() {
        let plan = plan(
            &[bond("aa", "11"), bond("aa", "22")],
            &[coin("c1", "aa", "11", NOW_EPOCH)],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.create,
            vec![bond("aa", "22")],
            "the second root needs its own coin"
        );
        assert!(
            plan.reclaim.is_empty(),
            "the first root's coin still covers a held capsule"
        );
    }

    /// A store whose root MOVED: the old root's capsule is gone, the new root's is held. Both
    /// halves must happen, and a planner keyed on the store alone — the legacy shape — would see no
    /// change at all.
    #[test]
    fn a_root_that_moved_reclaims_the_old_bond_and_creates_the_new_one() {
        let plan = plan(
            &[bond("aa", "22")],
            &[coin("c1", "aa", "11", NOW_EPOCH)],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("c1", "aa", "11", NOW_EPOCH), ReclaimReason::NoLongerHeld)]
        );
        assert_eq!(plan.create, vec![bond("aa", "22")]);
    }

    /// Duplicate coins for one bond are both kept while it is held — and both reclaimed once the
    /// capsule goes, rather than one being silently abandoned.
    #[test]
    fn duplicate_coins_for_one_bond_are_kept_while_held_and_both_reclaimed_when_it_goes() {
        let held = plan(
            &[bond("aa", "11")],
            &[
                coin("c1", "aa", "11", NOW_EPOCH),
                coin("c2", "aa", "11", NOW_EPOCH),
            ],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );
        assert!(held.is_empty(), "neither duplicate is destroyed while held");

        let gone = plan(
            &[],
            &[
                coin("c1", "aa", "11", NOW_EPOCH),
                coin("c2", "aa", "11", NOW_EPOCH),
            ],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );
        assert_eq!(
            gone.reclaim.len(),
            2,
            "both duplicates come back, or one is stranded: {gone:?}"
        );
    }

    /// A duplicated bond on disk yields ONE create, not two. A capsule listed twice by a scan that
    /// saw both a legacy and a migrated artifact must not pay 40 $DIG for one advertisement.
    #[test]
    fn a_bond_listed_twice_on_disk_is_created_once() {
        let plan = plan(&[bond("aa", "11"), bond("aa", "11")], &[], NOW_EPOCH, NOT_IN_FLIGHT);
        assert_eq!(plan.create, vec![bond("aa", "11")]);
    }

    #[test]
    fn creates_are_ordered_deterministically_regardless_of_scan_order() {
        let forward = plan(
            &[bond("aa", "11"), bond("bb", "22"), bond("cc", "33")],
            &[],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );
        let reversed = plan(
            &[bond("cc", "33"), bond("bb", "22"), bond("aa", "11")],
            &[],
            NOW_EPOCH,
            NOT_IN_FLIGHT,
        );
        assert_eq!(
            forward.create, reversed.create,
            "a partially funded pass must fund the same prefix on every run"
        );
    }

    #[test]
    fn a_fully_funded_wallet_creates_everything_and_is_short_nothing() {
        let creates = vec![bond("aa", "11"), bond("bb", "22")];
        let split = split_by_funds(
            &creates,
            2 * PER_COIN,
            PER_COIN,
        );

        assert!(split.is_funded());
        assert_eq!(split.affordable, creates);
        assert_eq!(split.shortfall_dig_base_units, 0);
    }

    /// The bound from BOTH sides. Exactly one coin's worth funds exactly one coin, and one mojo
    /// under funds none — a split tested only from above would pass while silently rounding up.
    #[test]
    fn the_collateral_bound_is_exact_in_both_directions() {
        let creates = vec![bond("aa", "11")];

        let at_bound = split_by_funds(
            &creates,
            PER_COIN,
            PER_COIN,
        );
        assert!(
            at_bound.is_funded(),
            "exactly one requirement's worth funds exactly one coin"
        );

        let one_under = split_by_funds(
            &creates,
            PER_COIN - 1,
            PER_COIN,
        );
        assert!(
            !one_under.is_funded(),
            "one mojo short must not collateralise anything"
        );
        assert_eq!(one_under.shortfall_dig_base_units, PER_COIN);
    }

    /// The wallet that reads as rich because someone passed a WHOLE-$DIG figure where base units
    /// were meant.
    ///
    /// A balance of 5 whole $DIG is 5_000 base units and would fund five coins at the starting
    /// requirement; expressed as the bare number 5 it funds none. The fixture asserts BOTH halves,
    /// because asserting only the underfunded half is satisfied by an implementation that funds
    /// nothing at all.
    #[test]
    fn a_whole_dig_figure_used_where_base_units_were_meant_funds_nothing() {
        let creates = vec![bond("aa", "11")];
        let whole_dig = 5_u64;

        let mistaken = split_by_funds(&creates, whole_dig, PER_COIN);
        assert!(
            !mistaken.is_funded(),
            "5 base units is 0.005 $DIG and collateralises nothing"
        );

        let correct = split_by_funds(
            &creates,
            whole_dig * dig_constants::CAT_MOJOS_PER_DIG,
            PER_COIN,
        );
        assert!(
            correct.is_funded(),
            "the same figure in base units funds the bond, so the test is not vacuously red"
        );
    }

    /// The requirement is a PARAMETER, not a constant: the same balance and the same bonds split
    /// differently when the epoch's requirement moves.
    ///
    /// This is the assertion that would go red against an implementation that ignored `per_coin`
    /// and used a hard-coded figure — which is precisely the defect `dig-constants` 0.13.0 removed
    /// a constant to prevent, and which no single-amount fixture can see.
    #[test]
    fn a_raised_requirement_funds_fewer_bonds_from_the_same_balance() {
        let creates = vec![bond("aa", "11"), bond("bb", "22")];
        let balance = 2 * PER_COIN;

        let at_start = split_by_funds(&creates, balance, PER_COIN);
        assert_eq!(at_start.affordable.len(), 2, "both bonds fit at 1.000 DIG each");

        let raised = split_by_funds(&creates, balance, PER_COIN_RAISED);
        assert_eq!(
            raised.affordable,
            vec![bond("aa", "11")],
            "at 2.500 DIG each the same balance funds only the first bond"
        );
        assert_eq!(raised.short, vec![bond("bb", "22")]);
        assert_eq!(raised.shortfall_dig_base_units, PER_COIN_RAISED);
    }

    /// Partial funding stops at the first unaffordable create and reports the rest, rather than
    /// skipping ahead. The fixture has THREE bonds and funds for two, so a "take everything you can
    /// afford in any order" implementation and a "stop at the first miss" one are distinguishable.
    #[test]
    fn a_partially_funded_wallet_stops_at_the_first_unaffordable_create() {
        let creates = vec![bond("aa", "11"), bond("bb", "22"), bond("cc", "33")];
        let split = split_by_funds(
            &creates,
            2 * PER_COIN,
            PER_COIN,
        );

        assert_eq!(split.affordable, vec![bond("aa", "11"), bond("bb", "22")]);
        assert_eq!(split.short, vec![bond("cc", "33")]);
        assert_eq!(split.shortfall_dig_base_units, PER_COIN);
    }

    /// An empty wallet is short everything and creates nothing — and, crucially, this says nothing
    /// about reclaims: [`split_by_funds`] never sees them, which is how a wallet at zero still
    /// recovers what it has already locked.
    #[test]
    fn an_empty_wallet_creates_nothing_and_reports_the_whole_shortfall() {
        let creates = vec![bond("aa", "11"), bond("bb", "22")];
        let split = split_by_funds(&creates, 0, PER_COIN);

        assert!(split.affordable.is_empty());
        assert_eq!(split.short, creates);
        assert_eq!(
            split.shortfall_dig_base_units,
            2 * PER_COIN
        );
    }

    /// An empty wallet with coins to reclaim still reclaims them. This is the assertion that makes
    /// the funds/reclaim independence load-bearing rather than incidental: the legacy could neither
    /// advertise nor recover at zero balance, and that is what stranded the money.
    #[test]
    fn a_wallet_at_zero_still_reclaims_what_it_already_locked() {
        let plan = plan(&[], &[coin("c1", "aa", "11", NOW_EPOCH)], NOW_EPOCH, NOT_IN_FLIGHT);
        let split = split_by_funds(&plan.create, 0, PER_COIN);

        assert_eq!(
            plan.reclaim,
            vec![(coin("c1", "aa", "11", NOW_EPOCH), ReclaimReason::NoLongerHeld)],
            "reclaim must not be gated on the balance"
        );
        assert!(split.affordable.is_empty());
    }

    /// A create already submitted and awaiting confirmation is not paid for twice.
    ///
    /// The window is real: a create is invisible on chain until it confirms, so a pass that ran
    /// between submission and confirmation sees the bond as uncovered. The control is a SECOND held
    /// bond with nothing in flight, which must still be created — without it, an implementation
    /// that suppressed every create whenever anything was in flight passes identically, and that
    /// implementation would stall collateralisation of the whole node behind one slow confirmation.
    #[test]
    fn a_bond_whose_create_is_in_flight_is_not_created_again() {
        let plan = plan(
            &[bond("aa", "11"), bond("bb", "22")],
            &[],
            NOW_EPOCH,
            &[bond("aa", "11")],
        );

        assert_eq!(
            plan.create,
            vec![bond("bb", "22")],
            "only the bond with a create in flight is suppressed"
        );
    }

    /// In-flight suppression touches CREATES only. A bond whose create is in flight, whose capsule
    /// has since gone, still has its EXISTING coin reclaimed.
    ///
    /// This is the assertion that keeps the suppression from becoming a way to withhold money: the
    /// two coins are different coins, and a filter written over the plan rather than over the create
    /// set would silently swallow the reclaim.
    #[test]
    fn an_in_flight_create_never_suppresses_a_reclaim() {
        let plan = plan(
            &[],
            &[coin("c1", "aa", "11", NOW_EPOCH)],
            NOW_EPOCH,
            &[bond("aa", "11")],
        );

        assert_eq!(
            plan.reclaim,
            vec![(coin("c1", "aa", "11", NOW_EPOCH), ReclaimReason::NoLongerHeld)],
            "a reclaim is never gated on an unrelated create being in flight"
        );
        assert!(plan.create.is_empty());
    }

    /// Suppression is keyed on the BOND, not on the store. Two roots of one store are two coins,
    /// and a create in flight for one must not withhold the other.
    ///
    /// A store-keyed implementation passes every fixture above and fails only this one, which is
    /// why it is here: the whole point of the per-root shape is that the two are funded separately.
    #[test]
    fn an_in_flight_create_for_one_root_does_not_suppress_another_root_of_the_same_store() {
        let plan = plan(
            &[bond("aa", "11"), bond("aa", "22")],
            &[],
            NOW_EPOCH,
            &[bond("aa", "11")],
        );

        assert_eq!(plan.create, vec![bond("aa", "22")]);
    }

    /// A bond that is in flight AND already covered on chain is simply covered — suppression adds
    /// nothing and removes nothing. Recorded because the two exclusions compose, and a reader
    /// should not have to reason about whether one masks the other.
    #[test]
    fn a_covered_bond_that_is_also_in_flight_is_still_a_no_op() {
        let plan = plan(
            &[bond("aa", "11")],
            &[coin("c1", "aa", "11", NOW_EPOCH)],
            NOW_EPOCH,
            &[bond("aa", "11")],
        );
        assert!(plan.is_empty());
    }
}
