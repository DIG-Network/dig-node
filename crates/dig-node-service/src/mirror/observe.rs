//! §25.8's OBSERVATION: what this node's bonds are, without doing anything about them
//! (dig-node#412 step 7).
//!
//! [`super::states`] renders an answer and [`super::runner`] acts on one. This is the step between:
//! it turns four already-gathered readings — the capsules on disk, the mirror coins on chain, this
//! node's own open creates, and the $DIG it can spend — into the
//! [`BondObservation`](super::states::BondObservation) the surface pages.
//!
//! # It cannot spend, and that is a property of the module rather than a rule about it
//!
//! [`super::runner::MirrorEffects`] holds both halves of the lifecycle: three reads and two spends.
//! A read surface built over it would hold a `create` and a `reclaim` it merely promised never to
//! call, and §25.8 is reachable from the token-gated control plane. So nothing here takes that
//! trait. [`observe`] is a **pure function over values**: it has no wallet, no signer, no chain
//! handle and no `&self`, so there is no unattended spend for a later edit to reach by accident.
//!
//! The same reasoning decides where the I/O lives. The caller performs the four reads and hands the
//! results in, which is what lets every property below be a fixture and a literal rather than a run
//! against a chain.
//!
//! # Nothing here recomputes what the decision already knows
//!
//! The states come from [`super::pass::decide`] — the same pure decision a real pass takes — rather
//! than from a second derivation written for the read path. A second derivation is a second answer
//! to "is this bond covered", and the two would drift in the direction nobody tests: the surface
//! would say `bonded` about a pair the pass was about to create a coin for, or `unfunded` about one
//! it had already covered. `decide`'s plan half is discarded here precisely because taking it is
//! step 8's act, not this one's.
//!
//! # The locked total is summed over the WHOLE chain observation
//!
//! Over every owned coin, before the plan splits it into keeps and reclaims, and including coins
//! being reclaimed — a broadcast reclaim has not confirmed, and the collateral is locked until it
//! does. It is read from each coin's own amount rather than from this epoch's requirement, because a
//! coin created under a previous requirement locks the previous amount. Summing the plan instead
//! would omit every coin the plan leaves alone, which is most of them on a healthy node, and would
//! report locked money as free — the one direction a money figure must never be wrong in.
//!
//! # The disk set is NOT presence-debounced, deliberately
//!
//! [`super::presence`]'s settling window exists to stop the node SPENDING on a capsule that may
//! vanish (§25.5). It is a spend suppressor, and a read surface is not a spend. Applying it here
//! would make a freshly-arrived capsule absent from its own node's bond list, which reads as a
//! missing capsule rather than as a deliberate wait — and a fresh tracker, which is all a stateless
//! read can build, suppresses everything it has ever seen exactly once. So this reports what is on
//! disk now. The cost is bounded and states itself: a capsule that arrived moments ago is reported
//! with the state it has right now, which for an uncovered pair is `unfunded` or `deferred` until
//! the next pass covers it.

use dig_mirror_coin::MirrorInventory;
use num_bigint::BigInt;

use dig_node_control_interface::results::CollateralRequirementResult;

use super::pass::{self, PassInputs};
use super::plan::{Bond, HeldMirror};
use super::runner::ObservedCapsule;
use super::states::BondObservation;

/// What an observation consults that it does not read for itself.
///
/// The epoch, the requirement, the margin and the switch are parameters for the same reason
/// [`pass::decide`] takes them: one observation must see ONE epoch and ONE requirement throughout,
/// and a value re-read partway through could change underneath it — producing a page whose rows
/// were priced against two different requirements while claiming to describe one moment.
#[derive(Debug, Clone)]
pub struct ObserveContext {
    /// The epoch in force.
    pub current_epoch: i64,
    /// This epoch's requirement, or the named reason it is unknown (§24.2).
    pub requirement: CollateralRequirementResult,
    /// The local safety margin, in basis points.
    pub margin_bp: u64,
    /// §25.7's switch. Reported because a node with creates OFF describes its bonds differently.
    pub creates_enabled: bool,
}

/// The whole §25.8 answer before paging, from four readings and a context.
///
/// `dig_balance_base_units` is `Option` and `None` is **not zero**: a wallet that could not be read
/// is UNKNOWN, and reading it as zero reports every uncovered bond as `unfunded` — an out-of-funds
/// alarm about a wallet nobody read, which is the dig-app#300 conflation this surface exists to
/// remove. `None` yields `deferred{balance_unreadable}` on the affected rows and leaves every
/// `bonded`, `withheld` and `reclaiming` row untouched, because none of those three depends on the
/// balance.
pub fn observe(
    observed: &[ObservedCapsule],
    on_chain: &[HeldMirror],
    in_flight: &[Bond],
    dig_balance_base_units: Option<u64>,
    ctx: &ObserveContext,
) -> BondObservation {
    let (held, relayed) = super::runner::split_by_provenance(observed);

    // Over the WHOLE observation, not over the plan: see the module doc. `saturating_add` rather
    // than a wrapping sum, because a total that wrapped would report a large locked figure as a
    // small one.
    let locked_dig_base_units = on_chain
        .iter()
        .map(|coin| coin.collateral_dig_base_units)
        .fold(0u64, u64::saturating_add);

    let decision = pass::decide(&PassInputs {
        held: &held,
        relayed: &relayed,
        on_chain,
        in_flight,
        current_epoch: ctx.current_epoch,
        requirement: &ctx.requirement,
        margin_bp: ctx.margin_bp,
        dig_balance_base_units,
        creates_enabled: ctx.creates_enabled,
    });

    BondObservation {
        states: decision.states,
        locked_dig_base_units,
        epoch: ctx.current_epoch,
    }
}

/// The mirror coins an inventory says this node owns, in the planner's vocabulary.
///
/// A coin whose declared epoch does not fit an `i64` is DROPPED rather than clamped. The epoch is a
/// `BigInt` on the wire because the hint morph is arithmetic over unbounded integers, so a stranger
/// can place a coin declaring any epoch at all for the price of a dust coin. Clamping such a value
/// would make that coin claim to bond the current epoch — a stranger choosing what this node reports
/// about its own bonds. Dropping it costs nothing: `dig_mirror_coin::list` already authenticates
/// ownership from the lineage proof, so a coin here is one this node controls, and one it controls
/// with an unrepresentable epoch is one no pass could ever act on anyway.
///
/// [`MirrorInventory::skipped`] and [`MirrorInventory::complete`] are the caller's to inspect; this
/// maps only the coins the scan resolved.
pub fn held_mirrors(inventory: &MirrorInventory) -> Vec<HeldMirror> {
    inventory
        .coins()
        .iter()
        .filter_map(|coin| {
            Some(HeldMirror {
                coin_id: hex::encode(coin.coin().coin_id()),
                store_id: hex::encode(coin.store_launcher_id()),
                root: hex::encode(coin.root_hash()),
                epoch: epoch_as_i64(coin.epoch())?,
                collateral_dig_base_units: coin.collateral(),
            })
        })
        .collect()
}

/// A declared epoch as an `i64`, or `None` when it does not fit.
///
/// Separated so the drop-rather-than-clamp rule above is a named, testable step rather than a
/// `try_into` buried in a closure.
fn epoch_as_i64(epoch: &BigInt) -> Option<i64> {
    i64::try_from(epoch).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_core::CapsuleProvenance;

    use super::super::pass::BondState;

    /// A store/root pair spelled out to 64 hex, so the canonicalisation downstream has real input.
    fn bond(store: &str, root: &str) -> Bond {
        Bond::new(store.repeat(32), root.repeat(32))
    }

    fn capsule(store: &str, root: &str, provenance: CapsuleProvenance) -> ObservedCapsule {
        ObservedCapsule {
            bond: bond(store, root),
            provenance,
        }
    }

    /// A coin whose id is DISTINCT per `(store, root)`.
    ///
    /// One shared id across every fixture coin would make `coin_id` useless as a discriminator:
    /// an assertion about "the coin bonding aa/11" would hold just as well against the coin bonding
    /// bb/22, so a `Bonded` row that named the wrong coin would still pass.
    fn coin(store: &str, root: &str, epoch: i64, collateral: u64) -> HeldMirror {
        HeldMirror {
            coin_id: format!("{store}{root}").repeat(16),
            store_id: store.repeat(32),
            root: root.repeat(32),
            epoch,
            collateral_dig_base_units: collateral,
        }
    }

    const REQUIRED: u64 = 1_000;

    fn ctx() -> ObserveContext {
        ObserveContext {
            current_epoch: 7,
            requirement: CollateralRequirementResult::Known {
                epoch: 7,
                protocol_version: 1,
                required_per_store_dig_base_units: REQUIRED,
                stores: 10,
                owners: 3,
                multiplier_micros: 1_000_000,
                handicap_dig_base_units: 0,
            },
            margin_bp: 0,
            creates_enabled: true,
        }
    }

    /// The locked total spans EVERY owned coin, including one the plan will reclaim.
    ///
    /// The fixture is deliberately not "all coins are keepers": the second coin bonds a capsule that
    /// is NOT on disk, so the plan reclaims it, and a total summed from the plan's keep list — or
    /// from the page — would report `600` rather than `1000`. Money reported as free while it is on
    /// chain is the one direction this figure must never be wrong in, and a fixture where every coin
    /// is kept cannot tell the two implementations apart.
    #[test]
    fn the_locked_total_includes_a_coin_the_plan_is_about_to_reclaim() {
        let observed = [capsule("aa", "11", CapsuleProvenance::Held)];
        let on_chain = [coin("aa", "11", 7, 600), coin("bb", "22", 7, 400)];

        let observation = observe(&observed, &on_chain, &[], Some(10_000), &ctx());

        assert_eq!(
            observation.locked_dig_base_units, 1_000,
            "both owned coins are locked; the reclaimed one has not confirmed"
        );
        // Asserted on the PAYLOAD, not merely on the variant. `Bonded` carries the coin a person
        // looks up and the amount that coin locks, and a row naming the other coin — or this
        // epoch's requirement instead of the coin's own 600 — is exactly the plausible wrong answer
        // a bare variant check cannot see.
        assert!(
            observation
                .states
                .iter()
                .any(|(b, s)| *b == bond("aa", "11")
                    && matches!(
                        s,
                        BondState::Bonded { coin_id, epoch, amount_dig_base_units }
                            if *coin_id == format!("{}{}", "aa", "11").repeat(16)
                                && *epoch == 7
                                && *amount_dig_base_units == 600
                    )),
            "the covered capsule is bonded by its OWN coin, for the amount that coin locks: \
             {:?}",
            observation.states
        );
    }

    /// A `Relayed` capsule is reported as `Withheld` rather than omitted.
    ///
    /// Two capsules with DIFFERENT provenance and neither on chain, so the assertion distinguishes
    /// "the relayed half reached the states list" from "everything reached it". A fixture with only
    /// a relayed capsule would pass against an implementation that reported every capsule as
    /// withheld, which is the nearest wrong thing this split can do.
    #[test]
    fn a_relayed_capsule_is_withheld_and_a_held_one_is_not() {
        let observed = [
            capsule("aa", "11", CapsuleProvenance::Held),
            capsule("bb", "22", CapsuleProvenance::Relayed),
        ];

        let observation = observe(&observed, &[], &[], Some(10_000), &ctx());

        let state_of = |b: Bond| {
            observation
                .states
                .iter()
                .find(|(k, _)| *k == b)
                .map(|(_, s)| s.clone())
        };
        assert_eq!(state_of(bond("bb", "22")), Some(BondState::Withheld));
        assert_ne!(
            state_of(bond("aa", "11")),
            Some(BondState::Withheld),
            "the held capsule is this node's own bond, not a withheld one"
        );
    }

    /// An unreadable balance defers the rows it prices and leaves the rest alone.
    ///
    /// The fixture carries one COVERED bond beside one uncovered bond, so a `None` balance that
    /// wrongly blanked the whole answer — or wrongly reported the uncovered row as `unfunded` — is
    /// visible. An all-uncovered fixture could not tell `FundsUnknown` from a call-level failure.
    #[test]
    fn an_unreadable_balance_defers_only_the_rows_it_prices() {
        let observed = [
            capsule("aa", "11", CapsuleProvenance::Held),
            capsule("bb", "22", CapsuleProvenance::Held),
        ];
        let on_chain = [coin("aa", "11", 7, REQUIRED)];

        let observation = observe(&observed, &on_chain, &[], None, &ctx());

        let state_of = |b: Bond| {
            observation
                .states
                .iter()
                .find(|(k, _)| *k == b)
                .map(|(_, s)| s.clone())
        };
        assert!(
            matches!(state_of(bond("aa", "11")), Some(BondState::Bonded { .. })),
            "a covered bond does not depend on the balance, so an unreadable wallet must not \
             disturb it: {:?}",
            state_of(bond("aa", "11"))
        );
        assert_eq!(
            state_of(bond("bb", "22")),
            Some(BondState::FundsUnknown),
            "an uncovered bond is UNKNOWN, never a fabricated shortfall"
        );
    }

    /// The epoch reported is the context's, not one derived from the coins.
    ///
    /// A node whose coins are all from a previous epoch still describes the epoch in force; deriving
    /// it from the inventory would make a node with no coins have no epoch, and a node holding stale
    /// coins report a past one as current.
    #[test]
    fn the_reported_epoch_is_the_one_in_force_not_the_coins() {
        let on_chain = [coin("aa", "11", 3, 500)];

        let observation = observe(&[], &on_chain, &[], Some(0), &ctx());

        assert_eq!(observation.epoch, 7);
    }

    /// An epoch that does not fit an `i64` is DROPPED, never clamped.
    ///
    /// Asserted on the conversion directly, because the value cannot be built through `HeldMirror`:
    /// its field is already an `i64`, so the only place the decision is observable is here. Both
    /// bounds are checked from BOTH sides — `i64::MAX` must convert and `i64::MAX + 1` must not —
    /// since a conversion tested only from below would confirm itself.
    #[test]
    fn an_out_of_range_declared_epoch_does_not_become_a_valid_one() {
        assert_eq!(epoch_as_i64(&BigInt::from(i64::MAX)), Some(i64::MAX));
        assert_eq!(epoch_as_i64(&BigInt::from(i64::MIN)), Some(i64::MIN));
        assert_eq!(epoch_as_i64(&(BigInt::from(i64::MAX) + 1)), None);
        assert_eq!(epoch_as_i64(&(BigInt::from(i64::MIN) - 1)), None);
    }
}
