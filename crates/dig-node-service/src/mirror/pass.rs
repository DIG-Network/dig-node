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

// From the control interface's published contract rather than re-exported through
// `crate::collateral`: these are the same types the §25.8 surface serves, and naming their
// owner keeps one definition rather than a local alias that could drift from it.
use dig_node_control_interface::results::{CollateralRequirementResult, CollateralUnknownReason};

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
    /// What this pass could NOT afford to create, when the wallet was readable and came up short.
    ///
    /// `Some` exactly when at least one create was priced and left uncreated for want of funds —
    /// [`BondState::Unfunded`]'s condition, carried in a shape the alert gate can decide on. `None`
    /// means every planned create was affordable, which includes the ordinary case of a node with
    /// nothing new to bond.
    ///
    /// It exists because "this pass created nothing" has two opposite causes, and the pass that
    /// created nothing because it could afford nothing is precisely the shortfall dig-node#463 was
    /// built to report. Reading it off the create loop cannot tell them apart; reading it off the
    /// funds split can (dig-node#469).
    pub funding_shortfall: Option<FundingShortfall>,
}

/// A pass that could not afford every create it planned, in the two figures an operator needs.
///
/// Both are stated from the SAME funds split that caused the refusal, so the message cannot
/// disagree with the decision it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingShortfall {
    /// The $DIG left over after the affordable creates were funded — what is still spendable
    /// towards the ones that were not, in base units.
    ///
    /// Not the wallet balance: a balance that funded three of five creates is not money available
    /// for the remaining two, and quoting it would overstate what the operator has to work with.
    pub have_dig_base_units: u64,
    /// What the creates left uncreated would cost together, in the same units.
    pub need_dig_base_units: u64,
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
    /// The WALLET could not be read, so whether this create is affordable is unknown.
    ///
    /// Third of the three "no coin yet" answers, and distinct from both its neighbours: `Unfunded`
    /// asserts the wallet is short, which this pass has no evidence for, and `Deferred` blames the
    /// requirement, which may be perfectly well known. The remedy differs too — a person told they
    /// are short goes looking for $DIG, when what is broken is the wallet the node asks.
    ///
    /// Reclaims are unaffected while this is reported: a coin coming home needs no balance.
    FundsUnknown,
    /// The epoch's requirement is not known, so no create may be priced. NOT an out-of-funds state.
    Deferred {
        /// Why the requirement is unknown, verbatim from the requirement machinery so this surface
        /// cannot invent a reason of its own.
        reason: CollateralUnknownReason,
    },
    /// Collateralisation is switched off NODE-WIDE (§25.7). The node holds the capsule and is
    /// deliberately not advertising it; any coin it already had is being reclaimed.
    ///
    /// Distinct from [`Self::Withheld`] in SCOPE — one switch for the whole node, not one capsule's
    /// provenance — and decisively in REMEDY: an operator told "withheld" about a disabled node goes
    /// looking at content when they should be looking for a switch.
    Disabled,
    /// This capsule is `Relayed` (§25.1): held on a stranger's behalf, served, and never advertised.
    ///
    /// Not a failure and not a shortfall. There is no remedy because nothing is wrong — which is
    /// exactly why it must not be reported as `Unfunded`, the conflation dig-app#300 exists to fix.
    ///
    /// Reachable only from a producer that enumerates the SERVED set. A `Held`-keyed derivation
    /// cannot emit it, because a `Relayed` capsule is by construction absent from the desired-bond
    /// set — see [`bond_states`], which takes the served set for this reason.
    Withheld,
    /// A reclaim for this bond is in flight. The money is STILL LOCKED until it confirms.
    ///
    /// Kept apart from [`Self::Disabled`] and [`Self::Withheld`] because those two describe a node
    /// that is not spending, while this one describes money in motion — and from `Bonded`, which
    /// would tell a person their collateral is advertising something when it is on its way back.
    ///
    /// Carries the coin it is ABOUT, for the same reason `Bonded` does: a person told their money is
    /// moving needs to know which coin and how much, and a payload-free variant leaves the §25.8
    /// surface unable to say. It also makes the identity of the coin part of the state, so a
    /// predicate that matched the wrong one could not report a plausible-looking answer.
    Reclaiming {
        /// The coin being spent home — the one a person can look up.
        coin_id: String,
        /// The epoch it bonded.
        epoch: i64,
        /// What it still locks until the reclaim confirms.
        amount_dig_base_units: u64,
    },
}

/// Everything a pass consults, gathered once so the decision can be taken without further I/O.
#[derive(Debug, Clone)]
pub struct PassInputs<'a> {
    /// The SETTLED `Held` bonds on disk (§25.5) — what this node is willing to advertise.
    ///
    /// `Held` provenance ONLY. §25.1's exclusion of `Relayed` capsules is enforced by the SPLIT
    /// itself: a relayed capsule arrives in [`Self::relayed`] instead, so nothing on the create path
    /// can reach one. That matters beyond tidiness — what this node bonds is what it spends its own
    /// money on, and a stranger chooses what it relays.
    pub held: &'a [Bond],
    /// The SETTLED `Relayed` bonds on disk (§25.1) — served, never advertised, never bonded.
    ///
    /// Present so the §25.8 surface can say `withheld` about them. Omitting them would leave the
    /// surface answering "no such row" exactly where the contract promises "withheld on purpose",
    /// which reads to a person as a missing capsule rather than a deliberate policy.
    pub relayed: &'a [Bond],
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
    /// Spendable $DIG in base units, or `None` when the wallet could not report it.
    ///
    /// `None` is NOT zero. A wallet that cannot be read is UNKNOWN, and reading it as zero would
    /// report every uncovered bond as `Unfunded` — an out-of-funds alarm about a wallet that may be
    /// perfectly funded, which is the conflation dig-app#300 exists to prevent. It reaches the
    /// pricing of creates and NOTHING else: rule 1 says a reclaim is never withheld for want of
    /// funds, and a reclaim withheld because the BALANCE READ failed is the same defect reached
    /// through the observation instead of through the gate.
    pub dig_balance_base_units: Option<u64>,
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

    // Rule 1, continued: the balance is read AFTER the plan too, and an unknown balance prices no
    // create rather than aborting anything. `reclaim` above is already decided and is untouched by
    // either arm below.
    let (affordable, split) = match (per_coin, inputs.dig_balance_base_units) {
        (Some(per_coin), Some(balance)) => {
            let split = super::plan::split_by_funds(&create, balance, per_coin);
            (split.affordable.clone(), Some(split))
        }
        _ => (Vec::new(), None),
    };

    let states = bond_states(inputs, &affordable, split.as_ref(), per_coin, &reclaim);

    // The shortfall is read off the split rather than off the states, because the split is what
    // decided it: `short` is non-empty exactly when a priced create went unmade for want of funds.
    // `have` is the remainder after the affordable prefix was funded — `balance % per_coin` — so
    // the deficit these two imply is the money that must actually be ADDED, not the whole cost of
    // the unmade creates.
    let funding_shortfall = match (per_coin, split.as_ref(), inputs.dig_balance_base_units) {
        // `per_coin` of zero is refused as a create everywhere else in this crate, and would make
        // the remainder below a division by zero. It reports no shortfall rather than panicking:
        // a requirement of zero is a caller defect, not an empty wallet.
        (Some(per_coin), Some(split), Some(balance)) if per_coin > 0 && !split.is_funded() => {
            Some(FundingShortfall {
                have_dig_base_units: balance % per_coin,
                need_dig_base_units: split.shortfall_dig_base_units,
            })
        }
        _ => None,
    };

    PassDecision {
        reclaim,
        create: affordable,
        per_coin_dig_base_units: per_coin,
        states,
        funding_shortfall,
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
    reclaim: &[(HeldMirror, ReclaimReason)],
) -> Vec<(Bond, BondState)> {
    let mut states: Vec<(Bond, BondState)> = Vec::new();

    // The served-but-never-advertised half first, so `Withheld` has a producer at all. Keyed on the
    // RELAYED set rather than derived from the held one: a relayed capsule is absent from `held` by
    // construction, so a held-keyed loop could never emit this variant however it was written.
    for bond in inputs.relayed {
        states.push((bond.clone(), BondState::Withheld));
    }

    for bond in inputs.held {
        // The chain first, scoped to the CURRENT epoch: those are the only coins that can be
        // collateralising this bond right now. A prior-epoch coin for the same `(store, root)` is
        // always being reclaimed at a rollover (`plan`'s `EpochEnded` row) and says nothing about
        // whether this bond is covered.
        let current_epoch_coins = inputs.on_chain.iter().filter(|c| {
            c.epoch == inputs.current_epoch && c.store_id == bond.store_id && c.root == bond.root
        });

        // A reclaim in flight outranks the coin IT is reclaiming — matched by `coin_id`, never by
        // `(store, root)`. Reporting `Bonded` for a coin on its way home would tell a person their
        // collateral is advertising this capsule while the money is leaving; reporting `Reclaiming`
        // because some OTHER coin is leaving tells them the inverse lie about a coin that is posted
        // and working. Both are false money statements, so the precedence is kept and narrowed.
        let mut reclaiming: Option<&HeldMirror> = None;
        let mut coin = None;
        for candidate in current_epoch_coins {
            if reclaim.iter().any(|(c, _)| c.coin_id == candidate.coin_id) {
                reclaiming = reclaiming.or(Some(candidate));
            } else {
                coin = Some(candidate);
                break;
            }
        }

        let state = if let Some(coin) = coin {
            BondState::Bonded {
                coin_id: coin.coin_id.clone(),
                epoch: coin.epoch,
                amount_dig_base_units: coin.collateral_dig_base_units,
            }
        } else if let Some(going) = reclaiming {
            // Every current-epoch coin for this bond is on its way home — the switch-off and
            // `NoLongerHeld` cases. The money is still locked until the reclaim confirms, so this
            // outranks both the switch and the plan's intentions, exactly as before.
            BondState::Reclaiming {
                coin_id: going.coin_id.clone(),
                epoch: going.epoch,
                amount_dig_base_units: going.collateral_dig_base_units,
            }
        } else if !inputs.creates_enabled {
            BondState::Disabled
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
                // Order matters between the two unknowns: an unreadable wallet is reported as
                // itself even when the requirement is also unknown, because it is the one that
                // needs a person to look at this node rather than at the chain.
                _ if inputs.dig_balance_base_units.is_none() => BondState::FundsUnknown,
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
        known_at(REQUIRED)
    }

    /// A `Known` requirement at an arbitrary per-store figure.
    ///
    /// Spelled as a function rather than `..known()` because `Known` is an enum VARIANT, and
    /// functional-update syntax does not apply to one.
    fn known_at(required_per_store_dig_base_units: u64) -> CollateralRequirementResult {
        CollateralRequirementResult::Known {
            epoch: NOW_EPOCH as u64,
            protocol_version: 1,
            required_per_store_dig_base_units,
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
            relayed: &[],
            on_chain,
            in_flight: &[],
            current_epoch: NOW_EPOCH,
            requirement,
            margin_bp: 0,
            dig_balance_base_units: Some(1_000_000),
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
        i.dig_balance_base_units = Some(0);

        let d = decide(&i);

        assert!(d.create.is_empty());
        assert_eq!(
            d.reclaim.len(),
            1,
            "a reclaim is never gated on the balance"
        );
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

    /// Rule 2: the switch OFF releases what is locked rather than freezing it — and says so
    /// truthfully while the release is still in flight.
    ///
    /// The fixture carries THREE bonds under OFF: two with a live coin, one without. That third
    /// bond is what makes the assertion about placement rather than about outcome. A `Bonded` coin
    /// is a fact of the chain and it outranks the switch, because the money is still locked and
    /// still penalisable until the reclaim confirms; a person told `Withheld` about a coin that
    /// exists cannot see either. But a bond with NO coin under OFF is genuinely withheld, and
    /// reporting it as `Unfunded` or `Deferred` would send that person hunting for money they do
    /// not need.
    ///
    /// A switch-first implementation — one that checked `creates_enabled` before the chain — reports
    /// all three as `Withheld` and hides two live locked coins. This fixture is red against it;
    /// a two-bond fixture with coins on both is not.
    #[test]
    fn switching_creates_off_reclaims_every_live_coin_and_creates_none() {
        let held = [bond("aa", "11"), bond("bb", "22"), bond("cc", "33")];
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

        let state = |store: &str, root: &str| {
            d.states
                .iter()
                .find(|(b, _)| *b == bond(store, root))
                .map(|(_, s)| s.clone())
                .expect("every held bond is reported")
        };

        assert_eq!(
            state("aa", "11"),
            BondState::Reclaiming {
                coin_id: id("c1"),
                epoch: NOW_EPOCH,
                amount_dig_base_units: REQUIRED,
            },
            "the coin is still on chain and still locking money, switch or no switch -- and the              reclaim carrying it home is the more precise thing to say than `Bonded`"
        );
        assert_eq!(
            state("bb", "22"),
            BondState::Reclaiming {
                coin_id: id("c2"),
                epoch: NOW_EPOCH,
                amount_dig_base_units: REQUIRED,
            }
        );
        assert_eq!(
            state("cc", "33"),
            BondState::Disabled,
            "the bond with no coin is the one the switch actually disables"
        );
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

    /// At a rollover a bond holds coins for TWO epochs at once, and only the OLD one is leaving.
    ///
    /// The window is the ordinary case, not a contrived one: the new epoch's coin confirms before
    /// the old one's reclaim does, so every pass in between sees both. The fixture varies the EPOCH
    /// term — the one term no other fixture here varies — because a `(store, root)`-keyed reclaim
    /// predicate is satisfied by the departing coin and reports a posted, advertising capsule as
    /// `Reclaiming`: the inverse of the false money statement `Reclaiming` was added to prevent.
    ///
    /// `bb` is the control, and it is what makes this about the epoch rather than about the count:
    /// it holds ONLY a prior-epoch coin, so it must NOT read as `Bonded` — a predicate that dropped
    /// the epoch term from the chain lookup instead would pass on `aa` alone.
    #[test]
    fn a_current_epoch_coin_is_bonded_while_its_prior_epoch_sibling_reclaims() {
        let held = [bond("aa", "11"), bond("bb", "22")];
        let req = known();
        let on_chain = [
            coin("aa-old", "aa", "11", NOW_EPOCH - 1, REQUIRED),
            coin("aa-now", "aa", "11", NOW_EPOCH, REQUIRED),
            coin("bb-old", "bb", "22", NOW_EPOCH - 1, REQUIRED),
        ];
        let i = inputs(&held, &on_chain, &req);

        let d = decide(&i);

        let state = |store: &str, root: &str| {
            d.states
                .iter()
                .find(|(b, _)| *b == bond(store, root))
                .map(|(_, s)| s.clone())
                .expect("every held bond is reported")
        };

        assert_eq!(
            state("aa", "11"),
            BondState::Bonded {
                coin_id: id("aa-now"),
                epoch: NOW_EPOCH,
                amount_dig_base_units: REQUIRED,
            },
            "this capsule's collateral is posted and advertising; only last epoch's coin is leaving"
        );
        assert_eq!(
            state("bb", "22"),
            BondState::Pending,
            "a prior-epoch coin collateralises nothing, so this bond still needs its create"
        );

        let reclaimed: Vec<String> = d.reclaim.iter().map(|(c, _)| c.coin_id.clone()).collect();
        assert_eq!(
            reclaimed,
            vec![id("aa-old"), id("bb-old")],
            "the prior-epoch coins are what reclaim, and the current-epoch one is untouched"
        );
        assert!(d
            .reclaim
            .iter()
            .all(|(_, why)| *why == ReclaimReason::EpochEnded));
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
        let req = known_at(2_500);
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
        i.dig_balance_base_units = Some(0);

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
        i.dig_balance_base_units = Some(2 * REQUIRED);

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
    /// A `Relayed` capsule is never bonded, and is reported as `withheld` rather than omitted.
    ///
    /// Two things at once, and both matter. The create list must not contain it — this node does not
    /// spend its own money advertising content a stranger chose, which is the one place in this
    /// lifecycle an attacker has any influence over what the node buys. And the surface must still
    /// SAY something about it: a capsule a person can see on disk, absent from the bond list, reads
    /// as a bug or a missing capsule rather than as the deliberate policy it is.
    ///
    /// The fixture carries a held bond ALONGSIDE the relayed one, so an implementation that simply
    /// dropped every relayed capsule on the floor is red here: it creates one coin (correct) and
    /// reports one state (wrong).
    #[test]
    fn a_relayed_capsule_is_never_created_and_is_reported_withheld() {
        let held = [bond("aa", "11")];
        let relayed = [bond("zz", "99")];
        let req = known();
        let mut i = inputs(&held, &[], &req);
        i.relayed = &relayed;

        let d = decide(&i);

        assert_eq!(
            d.create,
            vec![bond("aa", "11")],
            "the relayed capsule buys no coin"
        );
        assert!(
            d.states.contains(&(bond("zz", "99"), BondState::Withheld)),
            "and it is still accounted for, as withheld on purpose: {:?}",
            d.states
        );
        assert_eq!(d.states.len(), 2, "both capsules are reported");
    }

    /// A rollover where BOTH epochs' coins are on chain reports `Bonded` — the defect this fixture
    /// exists for.
    ///
    /// `plan` reclaims every `epoch < current` coin unconditionally, so on any pass after the new
    /// coin has confirmed and before the old reclaim has, the live coin and the outgoing one coexist.
    /// A `Reclaiming` predicate scoped to `(store, root)` rather than to the coin it is actually
    /// reclaiming reports this correctly-collateralised capsule as money on its way home — the same
    /// class of false money statement the variant exists to prevent, pointing the other way, and it
    /// hides a real `Bonded` row from the surface dig-app#289 renders.
    ///
    /// **Neither other fixture can see this**, which is why it is its own test: the switch-off case
    /// holds only current-epoch coins and the case below holds only a prior-epoch one, so the epoch
    /// term is never varied against a fixture holding both. The two coins carry DIFFERENT amounts so
    /// the assertion also proves which of them was read.
    #[test]
    fn a_bond_with_both_epochs_on_chain_is_bonded_not_reclaiming() {
        let held = [bond("aa", "11")];
        let req = known();
        let on_chain = [
            coin("new", "aa", "11", NOW_EPOCH, 700),
            coin("old", "aa", "11", NOW_EPOCH - 1, 1_500),
        ];
        let i = inputs(&held, &on_chain, &req);

        let d = decide(&i);

        assert_eq!(
            d.reclaim,
            vec![(
                coin("old", "aa", "11", NOW_EPOCH - 1, 1_500),
                ReclaimReason::EpochEnded
            )],
            "last epoch's coin is still going home -- that is what makes the two coexist"
        );
        assert_eq!(
            d.states,
            vec![(
                bond("aa", "11"),
                BondState::Bonded {
                    coin_id: id("new"),
                    epoch: NOW_EPOCH,
                    amount_dig_base_units: 700,
                }
            )],
            "the capsule IS collateralised and advertising; the outgoing coin is a different coin"
        );
    }

    /// With only a PRIOR epoch's coin on chain, the bond is not collateralised for this epoch, and
    /// the honest answer is about the create being made rather than about the coin leaving.
    ///
    /// `Reclaiming` is deliberately NOT the answer here. It is reserved for the case where the coin
    /// that would otherwise read `Bonded` is itself on its way home — the switch-off and
    /// `NoLongerHeld` paths, pinned by `switching_creates_off_reclaims_every_live_coin_and_creates_none`.
    /// Saying `Reclaiming` about a bond whose current-epoch create is in progress describes last
    /// epoch's money while a person is asking about this epoch's capsule.
    #[test]
    fn a_bond_with_only_last_epochs_coin_reports_the_create_not_the_reclaim() {
        let held = [bond("aa", "11")];
        let req = known();
        let on_chain = [coin("old", "aa", "11", NOW_EPOCH - 1, REQUIRED)];
        let i = inputs(&held, &on_chain, &req);

        let d = decide(&i);

        assert_eq!(d.reclaim.len(), 1, "last epoch's coin comes home");
        assert_eq!(
            d.create,
            vec![bond("aa", "11")],
            "and this epoch's coin is being made in the same pass"
        );
        assert_eq!(
            d.states,
            vec![(bond("aa", "11"), BondState::Pending)],
            "not `Bonded` -- nothing is advertising it yet -- and not `Reclaiming`, which would              describe last epoch's money while the question is about this epoch's capsule"
        );
    }
}
