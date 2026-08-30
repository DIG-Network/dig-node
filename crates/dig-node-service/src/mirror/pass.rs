//! What one reconcile pass DECIDES — the whole of `SPEC.md` §25.4 and §25.7, as a pure function.
//!
//! # Why the decision is separated from the doing
//!
//! A pass observes two things (the settled disk, the owned coins), consults three more (the epoch's
//! requirement, the wallet balance, the enable switch), and produces a list of spends to make plus a
//! state to report for every bond. Only the *making* needs a chain, a wallet and a clock; the
//! deciding needs none of them.
//!
//! Keeping the deciding pure is what makes the hostile cases testable at all. "The requirement is
//! unknown and there are coins to reclaim", "the switch is off and two coins are live", "$DIG is
//! short but XCH is not" are each a handful of literals against [`decide`], rather than a chain and a
//! wallet that must be induced into a state and then observed through a socket.
//!
//! # The three rules that are easy to get backwards
//!
//! Each of these fails in an expensive direction, so each is stated here and asserted below.
//!
//! 1. **Reclaims are never withheld.** Not for want of $DIG, not for want of XCH, not because the
//!    requirement is unknown, and not because collateralisation is switched off. A reclaim RETURNS
//!    money; withholding one is the legacy defect where a wallet at zero could neither advertise nor
//!    recover what it had already locked. A reclaim's amount comes from the coin being reclaimed, so
//!    it needs no requirement to be known.
//! 2. **The switch gates CREATES only.** Turning collateralisation off must RELEASE what is locked,
//!    not freeze it — a revocation that stranded funds inverts the point of revoking. It does that
//!    with no new machinery: OFF forces the desired bond set empty, and the ordinary plan then
//!    reclaims every live coin.
//! 3. **An unknown requirement defers creates and reports why.** Deferring is not the same as being
//!    unfunded, and conflating them produces an out-of-funds alarm about a wallet that is fine
//!    (dig-app#300). A missed create fails safe — the money stays in the wallet.

use dig_mirror_collateral::margin::apply_safety_margin;

use crate::collateral::{CollateralRequirementResult, CollateralUnknownReason};

use super::plan::{plan, Bond, FundingSplit, HeldMirror, MirrorPlan, ReclaimReason};

/// What one pass has decided to do, and what to report for every bond it considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassDecision {
    /// Coins to spend back to the owner, in plan order — reclaims first, always.
    pub reclaim: Vec<(HeldMirror, ReclaimReason)>,
    /// Creates to make, in deterministic order, each at [`Self::per_coin_dig_base_units`].
    pub create: Vec<Bond>,
    /// The margined per-epoch requirement these creates lock, when it is known.
    ///
    /// `None` exactly when [`Self::create`] is empty for want of a requirement — never a figure the
    /// pass guessed. A caller MUST NOT substitute a default: a create at the wrong amount is a coin
    /// that locks money and advertises nothing a verifier will accept.
    pub per_coin_dig_base_units: Option<u64>,
    /// One state per bond the node holds, for the §25.8 surface.
    pub states: Vec<(Bond, BondState)>,
}

/// What the node can say about one bond right now.
///
/// The variants exist to keep three genuinely different situations apart. "I am out of money",
/// "I do not yet know the price", and "this coin is already in the mempool" all mean "no coin yet"
/// and call for entirely different responses from a person — and collapsing the first two is what
/// produces an hourly out-of-funds alarm about a perfectly funded node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondState {
    /// A coin for this bond and epoch is on chain.
    Bonded {
        /// The coin a person can look up.
        coin_id: String,
        /// The epoch it bonds.
        epoch: i64,
        /// What it locks, read from the coin rather than from this epoch's requirement — a coin
        /// created under a previous requirement locks the previous amount.
        amount_dig_base_units: u64,
    },
    /// A create for this bond has been submitted and has not yet confirmed.
    Pending,
    /// The wallet cannot cover this create.
    Unfunded {
        /// How many more DIG base units this bond alone needs.
        short_dig_base_units: u64,
    },
    /// The epoch's requirement is not known, so no create may be priced. NOT an out-of-funds state.
    Deferred {
        /// Why the requirement is unknown, verbatim from the requirement machinery so this surface
        /// cannot invent a reason of its own.
        reason: CollateralUnknownReason,
    },
    /// Collateralisation is switched off. The node holds the capsule and is deliberately not
    /// advertising it; any coin it already had is being reclaimed.
    Withheld,
}

/// Everything a pass consults, gathered once so the decision can be taken without further I/O.
#[derive(Debug, Clone)]
pub struct PassInputs<'a> {
    /// The SETTLED `Held` bonds on disk (§25.5) — what this node is willing to advertise.
    pub held: &'a [Bond],
    /// The mirror coins this wallet owns, from `dig_mirror_coin::list`.
    pub on_chain: &'a [HeldMirror],
    /// Bonds whose current-epoch create is submitted and unconfirmed (§25.4.6).
    pub in_flight: &'a [Bond],
    /// The epoch in force by the wall clock.
    pub current_epoch: i64,
    /// This epoch's requirement, or the named reason it is unknown.
    pub requirement: &'a CollateralRequirementResult,
    /// The local safety margin, in basis points (`collateral.json`).
    pub margin_bp: u64,
    /// Spendable $DIG, in base units.
    pub dig_balance_base_units: u64,
    /// Whether creates are enabled (§25.7). Reclaims ignore this.
    pub creates_enabled: bool,
}

/// Decide one pass.
///
/// Pure: no clock, no chain, no wallet, no file. Every input that varies is a parameter, so a fixture
/// is a handful of literals and the answer is the same on every machine on every day.
pub fn decide(inputs: &PassInputs<'_>) -> PassDecision {
    // Rule 2. OFF forces the DESIRED set empty rather than short-circuiting the pass, so the ordinary
    // plan reclaims every live coin. A `return` here would freeze the locked collateral instead of
    // releasing it, which is the failure that inverts the meaning of "revoke".
    let desired: &[Bond] = if inputs.creates_enabled {
        inputs.held
    } else {
        &[]
    };

    let MirrorPlan { reclaim, create } = plan(
        desired,
        inputs.on_chain,
        inputs.current_epoch,
        inputs.in_flight,
    );

    // Rule 3. The requirement is consulted only to PRICE creates. Note it is read after the plan is
    // taken, never before it: nothing about an unknown price may reach the reclaim list.
    let per_coin = match inputs.requirement {
        CollateralRequirementResult::Known {
            required_per_store_dig_base_units,
            ..
        } => Some(apply_safety_margin(
            *required_per_store_dig_base_units,
            inputs.margin_bp,
        )),
        CollateralRequirementResult::Unknown { .. } => None,
    };

    let (affordable, split) = match per_coin {
        Some(per_coin) => {
            let split = super::plan::split_by_funds(
                &create,
                inputs.dig_balance_base_units,
                per_coin,
            );
            (split.affordable.clone(), Some(split))
        }
        None => (Vec::new(), None),
    };

    let states = bond_states(inputs, &affordable, split.as_ref(), per_coin);

    PassDecision {
        reclaim,
        create: affordable,
        per_coin_dig_base_units: per_coin,
        states,
    }
}

/// One state per HELD bond — what the node would say about each if asked right now.
///
/// Keyed on what is on disk rather than on what the plan produced, because a bond the plan had
/// nothing to do about is exactly the one whose state a person most wants ("it is bonded") and the
/// one a plan-derived list would omit entirely.
fn bond_states(
    inputs: &PassInputs<'_>,
    affordable: &[Bond],
    split: Option<&FundingSplit>,
    per_coin: Option<u64>,
) -> Vec<(Bond, BondState)> {
    let mut states: Vec<(Bond, BondState)> = Vec::new();

    for bond in inputs.held {
        // The chain first: a coin that exists outranks every reason a coin might not.
        let coin = inputs
            .on_chain
            .iter()
            .find(|c| c.epoch == inputs.current_epoch && c.store_id == bond.store_id && c.root == bond.root);

        let state = if let Some(coin) = coin {
            BondState::Bonded {
                coin_id: coin.coin_id.clone(),
                epoch: coin.epoch,
                amount_dig_base_units: coin.collateral_dig_base_units,
            }
        } else if !inputs.creates_enabled {
            BondState::Withheld
        } else if inputs.in_flight.contains(bond) {
            BondState::Pending
        } else {
            match (per_coin, split) {
                (Some(per_coin), Some(split)) => {
                    if affordable.contains(bond) {
                        // Selected for this pass but not yet submitted. `Pending` is the honest
                        // reading: the node has decided to make it and nothing is short.
                        BondState::Pending
                    } else if split.short.contains(bond) {
                        BondState::Unfunded {
                            short_dig_base_units: per_coin,
                        }
                    } else {
                        // Neither affordable nor short: the plan did not want a create, which at this
                        // point can only mean a duplicate entry already accounted for.
                        BondState::Pending
                    }
                }
                _ => BondState::Deferred {
                    reason: unknown_reason(inputs.requirement),
                },
            }
        };

        states.push((bond.clone(), state));
    }

    states.sort_by(|a, b| a.0.cmp(&b.0));
    states.dedup_by(|a, b| a.0 == b.0);
    states
}

/// The reason a requirement is unknown, for the surface.
///
/// A `Known` requirement can never reach here — [`decide`] only asks once `per_coin` is `None` — so
/// the fallback is unreachable in practice. It is `NotCensused` rather than a panic because a state
/// surface that aborts the pass is worse than one that names the most common cause.
fn unknown_reason(requirement: &CollateralRequirementResult) -> CollateralUnknownReason {
    match requirement {
        CollateralRequirementResult::Unknown { reason } => *reason,
        CollateralRequirementResult::Known { .. } => CollateralUnknownReason::NotCensused,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    /// The schedule's starting requirement, PRE-margin: 1.000 DIG.
    const REQUIRED: u64 = 1_000;

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

    fn unknown(reason: CollateralUnknownReason) -> CollateralRequirementResult {
        CollateralRequirementResult::Unknown { reason }
    }

    /// A fully funded, switched-on node with the requirement known — the baseline every hostile
    /// fixture below varies exactly one field of.
    fn inputs<'a>(
        held: &'a [Bond],
        on_chain: &'a [HeldMirror],
        requirement: &'a CollateralRequirementResult,
    ) -> PassInputs<'a> {
        PassInputs {
            held,
            on_chain,
            in_flight: &[],
            current_epoch: NOW_EPOCH,
            requirement,
            margin_bp: 0,
            dig_balance_base_units: 1_000_000,
            creates_enabled: true,
        }
    }

    #[test]
    fn a_held_capsule_on_a_funded_node_is_created_at_the_margined_requirement() {
        let held = [bond("aa", "11")];
        let req = known();
        let mut i = inputs(&held, &[], &req);
        i.margin_bp = 500; // +5%

        let d = decide(&i);

        assert_eq!(d.create, vec![bond("aa", "11")]);
        assert_eq!(
            d.per_coin_dig_base_units,
            Some(apply_safety_margin(REQUIRED, 500)),
            "the amount is the margined requirement, not the bare one and not a constant"
        );
        assert_ne!(
            d.per_coin_dig_base_units,
            Some(REQUIRED),
            "a 5% margin must actually change the figure, or the margin is being ignored"
        );
    }

    /// Rule 3: an unknown requirement defers creates and never touches reclaims.
    ///
    /// The fixture carries BOTH a bond needing a create and a coin needing a reclaim. Without the
    /// coin, an implementation that returned an empty decision on an unknown requirement would pass
    /// — and that implementation strands collateral for as long as the census is behind.
    #[test]
    fn an_unknown_requirement_defers_creates_and_still_reclaims() {
        let held = [bond("aa", "11")];
        let req = unknown(CollateralUnknownReason::BehindFinalityDepth);
        let on_chain = [coin("gone", "bb", "22", NOW_EPOCH, REQUIRED)];
        let i = inputs(&held, &on_chain, &req);

        let d = decide(&i);

        assert!(d.create.is_empty(), "no create may be priced");
        assert_eq!(d.per_coin_dig_base_units, None, "and no amount is guessed");
        assert_eq!(
            d.reclaim,
            vec![(
                coin("gone", "bb", "22", NOW_EPOCH, REQUIRED),
                ReclaimReason::NoLongerHeld
            )],
            "a reclaim's amount comes from its own coin, so it needs no requirement"
        );
        assert_eq!(
            d.states,
            vec![(
                bond("aa", "11"),
                BondState::Deferred {
                    reason: CollateralUnknownReason::BehindFinalityDepth
                }
            )],
            "and the reason is reported verbatim, not as an out-of-funds alarm"
        );
    }

    /// Rule 1: a wallet at zero still reclaims, and reports the shortfall rather than the deferral.
    ///
    /// The two "no coin yet" states must stay distinguishable — this asserts `Unfunded`, and the
    /// test above asserts `Deferred`, on fixtures identical but for the one field.
    #[test]
    fn a_wallet_at_zero_reclaims_and_reports_unfunded_not_deferred() {
        let held = [bond("aa", "11")];
        let req = known();
        let on_chain = [coin("gone", "bb", "22", NOW_EPOCH, REQUIRED)];
        let mut i = inputs(&held, &on_chain, &req);
        i.dig_balance_base_units = 0;

        let d = decide(&i);

        assert!(d.create.is_empty());
        assert_eq!(d.reclaim.len(), 1, "a reclaim is never gated on the balance");
        assert_eq!(
            d.states,
            vec![(
                bond("aa", "11"),
                BondState::Unfunded {
                    short_dig_base_units: REQUIRED
                }
            )]
        );
    }

    /// Rule 2: the switch OFF releases what is locked rather than freezing it.
    ///
    /// Two live coins go back and nothing is created. The `Withheld` state is asserted too, because
    /// a node that reported `Unfunded` while switched off would send a person hunting for money they
    /// do not need.
    #[test]
    fn switching_creates_off_reclaims_every_live_coin_and_creates_none() {
        let held = [bond("aa", "11"), bond("bb", "22")];
        let req = known();
        let on_chain = [
            coin("c1", "aa", "11", NOW_EPOCH, REQUIRED),
            coin("c2", "bb", "22", NOW_EPOCH, REQUIRED),
        ];
        let mut i = inputs(&held, &on_chain, &req);
        i.creates_enabled = false;

        let d = decide(&i);

        assert!(d.create.is_empty(), "the switch gates creates");
        assert_eq!(
            d.reclaim.len(),
            2,
            "and OFF must RELEASE the locked collateral, not freeze it: {d:?}"
        );
        assert!(d
            .reclaim
            .iter()
            .all(|(_, why)| *why == ReclaimReason::NoLongerHeld));
        assert!(d
            .states
            .iter()
            .all(|(_, s)| *s == BondState::Withheld));
    }

    /// The switch OFF must still reclaim a PRIOR epoch's coin, which is a different plan row.
    ///
    /// Recorded separately because the two reclaim reasons come from different branches, and an
    /// implementation that emptied the desired set but skipped the epoch comparison would leave last
    /// epoch's money locked forever on a node whose owner had switched the feature off.
    #[test]
    fn switching_creates_off_also_reclaims_a_prior_epochs_coin() {
        let held = [bond("aa", "11")];
        let req = known();
        let on_chain = [coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED)];
        let mut i = inputs(&held, &on_chain, &req);
        i.creates_enabled = false;

        let d = decide(&i);
        assert_eq!(
            d.reclaim,
            vec![(
                coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED),
                ReclaimReason::EpochEnded
            )]
        );
    }

    /// A bond already on chain reports the amount ITS OWN COIN locks, not this epoch's requirement.
    ///
    /// The fixture deliberately makes the two differ: a coin created when the requirement was 1.000
    /// DIG, read in an epoch whose requirement has risen to 2.500. Reporting the current requirement
    /// would tell a person they have more locked than they do, and there is no fixture where the two
    /// are equal that could tell the difference.
    #[test]
    fn a_bonded_coin_reports_what_it_locks_rather_than_todays_requirement() {
        let held = [bond("aa", "11")];
        let req = CollateralRequirementResult::Known {
            required_per_store_dig_base_units: 2_500,
            ..known()
        };
        let on_chain = [coin("c1", "aa", "11", NOW_EPOCH, 1_000)];
        let i = inputs(&held, &on_chain, &req);

        let d = decide(&i);

        assert_eq!(
            d.states,
            vec![(
                bond("aa", "11"),
                BondState::Bonded {
                    coin_id: id("c1"),
                    epoch: NOW_EPOCH,
                    amount_dig_base_units: 1_000,
                }
            )]
        );
        assert!(d.create.is_empty());
    }

    /// A create in flight reports `Pending` rather than `Unfunded`, even on a wallet that could not
    /// afford a second one. Without this, a node mid-confirmation looks broke.
    #[test]
    fn an_in_flight_create_reports_pending_on_an_empty_wallet() {
        let held = [bond("aa", "11")];
        let req = known();
        let in_flight = [bond("aa", "11")];
        let mut i = inputs(&held, &[], &req);
        i.in_flight = &in_flight;
        i.dig_balance_base_units = 0;

        let d = decide(&i);

        assert!(d.create.is_empty(), "it is already in flight");
        assert_eq!(d.states, vec![(bond("aa", "11"), BondState::Pending)]);
    }

    /// A partially funded node creates the affordable prefix and reports the rest as short — the two
    /// halves in one decision, so the states and the create list cannot drift apart.
    #[test]
    fn a_partially_funded_node_creates_a_prefix_and_reports_the_rest_short() {
        let held = [bond("aa", "11"), bond("bb", "22"), bond("cc", "33")];
        let req = known();
        let mut i = inputs(&held, &[], &req);
        i.dig_balance_base_units = 2 * REQUIRED;

        let d = decide(&i);

        assert_eq!(d.create, vec![bond("aa", "11"), bond("bb", "22")]);
        assert_eq!(
            d.states.last().map(|(_, s)| s.clone()),
            Some(BondState::Unfunded {
                short_dig_base_units: REQUIRED
            }),
            "the third bond is the one that did not fit"
        );
    }
}
