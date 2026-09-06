//! The mirror-coin URL reconcile DECISION — `SPEC.md` §25.13, dig-node#570.
//!
//! A mirror coin's advertised URL is fixed in its memos at creation and can never be updated in
//! place — the user decided this explicitly (dig-node#570, dig_ecosystem#3203) rather than leave it
//! an open question. So the only way to change what a bond advertises is to **reclaim the old coin
//! and create a new one**, and this module decides WHETHER to, never how — the actual reclaim rides
//! the ordinary pass's own execution (`super::pass::decide`, `super::runner::PassRunner::execute`),
//! exactly as an ordinary `NoLongerHeld`/`EpochEnded` reclaim does. Keeping this pure is what makes
//! the money-critical cases testable at all: every gate below is a handful of literals against
//! [`decide`], never a chain and a wallet induced into a state.
//!
//! # The invariant that outranks everything else here
//!
//! **Size the plan to the affordable prefix `K` BEFORE any reclaim; reclaim exactly `K`; leave
//! `n − K` bonded as they were.** With no in-place update, a reclaim this module could not price a
//! recreate for would leave the node holding fewer bonds than before it started, having paid to get
//! there — strictly worse than the stale state, which is at least still bonded. So sizing happens
//! entirely BEFORE [`ReconcileDirective`] names a single coin id, and a refusal always means the
//! directive is absent, never present-and-empty.
//!
//! # Two triggers, one function
//!
//! The daily detector and (once wired) `control.mirror.reconcile` both call [`decide`]. Building the
//! decision twice, with two independently-written guards, is the rival-implementation shape
//! CLAUDE.md's "centralize rival implementations" rule exists to prevent — and where two such rivals
//! disagree, one of them is wrong and it is usually the one that shipped. What DOES differ between
//! the triggers — hysteresis and the epoch cap — lives one layer up, in [`super::schedule`], and is
//! applied BEFORE this function is even called: by the time `decide` runs, "should we attempt this
//! at all" has already been answered, and this module only ever answers "can we, right now".

use std::collections::BTreeSet;

use dig_node_control_interface::results::{CollateralRequirementResult, CollateralUnknownReason};

use super::advertise::{AdvertiseState, Effective};
use super::plan::{self, Bond};
use super::runner::DeclaredBond;

/// Why [`decide`] refused to act. Every variant means the spend count is exactly zero — enforcing
/// that is this module's whole job, and this type is only how it explains itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// Gate 1 (`SPEC.md` §25.13.4 row 1). This node has nowhere to advertise from right now — the
    /// SAME `SPEC.md` §25.10 state label an ordinary pass logs, carried rather than collapsed into
    /// one token: the four states have four different remedies, and a reset onto an
    /// [`AdvertiseState::Uncorroborated`] address is a reset onto nothing.
    AdvertiseNotPublishing(AdvertiseState),
    /// Gate 2. `SPEC.md` §25.7's switch is off. The operator's own choice, never a fault.
    Disabled,
    /// Gate 4a. This node holds no current-epoch mirror coin for any bond still on disk.
    NoMirrorCoins,
    /// Gate 4b. Every current-epoch coin already declares the URL set this node would advertise
    /// now. The no-op case, and the overwhelmingly common one on a healthy, stable-address node.
    UrlUnchanged,
    /// Gate 5. This epoch's collateral requirement is not known, so no recreate could be priced.
    RequirementUnknown(CollateralUnknownReason),
    /// Gate 7. The operator wallet's balance could not be read, so affordability is UNKNOWN — not a
    /// shortfall, which would claim evidence this call does not have.
    FundsUnmeasured,
    /// Gate 8. The wallet cannot fund even the FIRST stale bond's recreate after every stale coin's
    /// collateral is folded back in. The SAME two figures `SPEC.md` §25.12 quotes for an ordinary
    /// create, so an operator sees one number for "short" everywhere it appears.
    InsufficientFunds {
        have_dig_base_units: u64,
        need_dig_base_units: u64,
    },
    /// Gate 9. Another `UrlStale` reclaim from an earlier call has not yet resolved.
    ReconcileInProgress,
}

impl RefusalReason {
    /// The wire spelling `SPEC.md` §25.13.4 and `dig-node-control-interface` declare.
    pub fn label(&self) -> String {
        match self {
            RefusalReason::AdvertiseNotPublishing(state) => state.label().to_string(),
            RefusalReason::Disabled => "disabled".to_string(),
            RefusalReason::NoMirrorCoins => "no_mirror_coins".to_string(),
            RefusalReason::UrlUnchanged => "url_unchanged".to_string(),
            RefusalReason::RequirementUnknown(_) => "requirement_unknown".to_string(),
            RefusalReason::FundsUnmeasured => "funds_unmeasured".to_string(),
            RefusalReason::InsufficientFunds { .. } => "insufficient_funds".to_string(),
            RefusalReason::ReconcileInProgress => "reconcile_in_progress".to_string(),
        }
    }
}

/// What to reclaim this pass, already sized to the affordable prefix (`SPEC.md` §25.13.5).
///
/// Carries coin ids rather than [`super::plan::HeldMirror`]s: the runner already holds the full
/// records from its own chain observation, and threading ids rather than a second copy of them is
/// what makes it impossible for this directive to disagree with that observation about amounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileDirective {
    /// Coin ids to reclaim this pass, in canonical order, exactly `K` of them.
    pub coin_ids: Vec<String>,
    /// How many stale bonds (`n − K`) are left untouched for want of funds. Zero in the common
    /// case (`SPEC.md` §25.13.5: `Rᵢ = C` for every coin created this epoch, so `K = n` whenever
    /// the wallet holds the fee XCH).
    pub left_unaffordable: usize,
    /// Which caller asked — carried through to the audit record (`SPEC.md` §F) so an operator can
    /// tell a scheduled check from a button they pressed. Not consulted by any gate above: `decide`
    /// answers identically for either trigger (`SPEC.md` §25.13.2's table), and this is echoed
    /// straight from [`ReconcileInputs::trigger`] purely for attribution.
    pub trigger: plan::Trigger,
}

/// Everything [`decide`] consults, gathered once so the decision needs no further I/O.
pub struct ReconcileInputs<'a> {
    /// Which caller is asking. Not a gate input — see [`ReconcileDirective::trigger`].
    pub trigger: plan::Trigger,
    /// What this node would advertise THIS pass — the SAME [`Effective`] an ordinary pass computes,
    /// never re-derived here. Its `urls` is §25.13.3's target.
    pub advertised: &'a Effective,
    /// `SPEC.md` §25.7's switch. Gate 2.
    pub mirror_enabled: bool,
    /// The settled `Held` bonds on disk — a coin's bond must be in THIS set to be reconciled here;
    /// a bond that left disk is `NoLongerHeld`'s business, not this module's (`SPEC.md` §25.13's
    /// scope note).
    pub held_bonds: &'a [Bond],
    /// Every mirror coin this wallet owns, together with the URL set each one declares
    /// (`super::runner::MirrorEffects::observe_bonded_urls`).
    pub bonded: &'a [DeclaredBond],
    /// The epoch in force.
    pub current_epoch: i64,
    /// This epoch's requirement, or the named reason it is unknown. Gate 5.
    pub requirement: &'a CollateralRequirementResult,
    /// The local safety margin, in basis points.
    pub margin_bp: u64,
    /// Spendable $DIG in base units, or `None` when the wallet could not report it. Gates 7 and 8.
    pub dig_balance_base_units: Option<u64>,
    /// Whether an earlier `UrlStale` reclaim from this node has not yet resolved. Gate 9.
    pub reconcile_in_progress: bool,
}

/// The stale set (`SPEC.md` §25.13.3): every bonded coin that is for the CURRENT epoch, whose bond
/// is STILL held on disk, and whose declared URL set differs from `target` — compared as sets, order
/// ignored, because an operator's own order (with a derived IPv6 candidate placed first) is not a
/// change.
///
/// Ordered by the CANONICAL key `(store_id, root)` — deliberately NOT [`DeclaredBond`]'s derived
/// `Ord`, which would sort by `coin_id` first. "The affordable prefix" must name the same coins on
/// every machine regardless of which coin id a chain happened to assign, so the order is the bond's
/// own identity, not the coin's.
fn stale_set(
    bonded: &[DeclaredBond],
    held_bonds: &[Bond],
    current_epoch: i64,
    target: &[String],
) -> Vec<DeclaredBond> {
    let held: BTreeSet<&Bond> = held_bonds.iter().collect();
    let target_set: BTreeSet<&String> = target.iter().collect();

    let mut candidates: Vec<DeclaredBond> = bonded
        .iter()
        .filter(|d| d.held.epoch == current_epoch)
        .filter(|d| held.contains(&Bond::new(&d.held.store_id, &d.held.root)))
        .cloned()
        .collect();
    candidates
        .sort_by(|a, b| (&a.held.store_id, &a.held.root).cmp(&(&b.held.store_id, &b.held.root)));

    candidates
        .into_iter()
        .filter(|d| {
            let urls: BTreeSet<&String> = d.urls.iter().collect();
            urls != target_set
        })
        .collect()
}

/// Decide whether to reconcile, and what.
///
/// Pure: no clock, no chain, no wallet, no file. Every gate is evaluated in `SPEC.md` §25.13.4's
/// order and the FIRST failure is the reported reason, so a caller sees the most fundamental
/// blocker rather than an incidental one.
///
/// Three of the nine gates the full spec names are handled OUTSIDE this function, by construction
/// rather than by a redundant check here: gate 3 (the chain observation is complete) is structural
/// — [`super::runner::PassRunner::run`] only reaches this call after its own chain read succeeded,
/// exactly as an ordinary pass's create pricing does; gate 6 (a signer is open and broadcast is
/// enabled) is left to the SAME reclaim/create effects an ordinary pass already degrades through
/// when a wallet is unavailable, rather than a second copy of that capability check; and the
/// automatic-only pre-conditions (the switch, hysteresis, the epoch cap) are `super::schedule`'s,
/// evaluated before this function is even called (`SPEC.md` §25.13.4's own text: they are "not a
/// refusal in the wire sense because nothing was asked").
pub fn decide(inputs: &ReconcileInputs<'_>) -> Result<ReconcileDirective, RefusalReason> {
    // Gate 1.
    if !inputs.advertised.can_advertise() {
        return Err(RefusalReason::AdvertiseNotPublishing(
            inputs.advertised.state,
        ));
    }
    // Gate 2.
    if !inputs.mirror_enabled {
        return Err(RefusalReason::Disabled);
    }

    // Gate 4a: at least one current-epoch, still-held coin exists at all.
    let held: BTreeSet<&Bond> = inputs.held_bonds.iter().collect();
    let candidate_count = inputs
        .bonded
        .iter()
        .filter(|d| d.held.epoch == inputs.current_epoch)
        .filter(|d| held.contains(&Bond::new(&d.held.store_id, &d.held.root)))
        .count();
    if candidate_count == 0 {
        return Err(RefusalReason::NoMirrorCoins);
    }

    // Gate 4b: at least one of those candidates is actually stale.
    let stale = stale_set(
        inputs.bonded,
        inputs.held_bonds,
        inputs.current_epoch,
        &inputs.advertised.urls,
    );
    if stale.is_empty() {
        return Err(RefusalReason::UrlUnchanged);
    }

    // Gate 5. The SAME lookup an ordinary create prices with (`plan::per_coin_dig_base_units`),
    // never a second copy of the arithmetic.
    let per_coin = match inputs.requirement {
        CollateralRequirementResult::Unknown { reason } => {
            return Err(RefusalReason::RequirementUnknown(*reason));
        }
        CollateralRequirementResult::Known { .. } => {
            plan::per_coin_dig_base_units(inputs.requirement, inputs.margin_bp)
                .expect("a Known requirement always prices")
        }
    };

    // Gate 7.
    let Some(balance) = inputs.dig_balance_base_units else {
        return Err(RefusalReason::FundsUnmeasured);
    };

    // Gate 8 and §25.13.5's sizing, together: `plan::split_by_funds` is the SAME split an ordinary
    // create prices with, called with the balance augmented by exactly the collateral the stale
    // set's own reclaims would return — never a second, hand-written arithmetic over it.
    let reclaimable_total: u64 = stale
        .iter()
        .map(|d| d.held.collateral_dig_base_units)
        .fold(0u64, u64::saturating_add);
    let augmented_balance = balance.saturating_add(reclaimable_total);
    let stale_bonds: Vec<Bond> = stale
        .iter()
        .map(|d| Bond::new(&d.held.store_id, &d.held.root))
        .collect();
    let split = plan::split_by_funds(&stale_bonds, augmented_balance, per_coin);
    if split.affordable.is_empty() {
        return Err(RefusalReason::InsufficientFunds {
            have_dig_base_units: augmented_balance,
            need_dig_base_units: per_coin,
        });
    }

    // Gate 9.
    if inputs.reconcile_in_progress {
        return Err(RefusalReason::ReconcileInProgress);
    }

    let k = split.affordable.len();
    Ok(ReconcileDirective {
        coin_ids: stale[..k].iter().map(|d| d.held.coin_id.clone()).collect(),
        left_unaffordable: stale.len() - k,
        trigger: inputs.trigger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::plan::HeldMirror;

    const NOW_EPOCH: i64 = 100;
    const PER_COIN: u64 = 1_000;

    /// A distinguishable 64-hex id, following this crate's own idiom: real ids are opaque, and a
    /// short literal would hide a length assumption a path builder relies on.
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

    fn old_urls() -> Vec<String> {
        vec!["https://old.example:9444".to_string()]
    }

    fn new_urls() -> Vec<String> {
        vec!["https://new.example:9444".to_string()]
    }

    fn declared(tag: &str, store: &str, root: &str, urls: Vec<String>) -> DeclaredBond {
        declared_at(tag, store, root, urls, PER_COIN)
    }

    /// A declared bond whose OWN locked collateral differs from [`PER_COIN`] — the ONLY way `K < n`
    /// or an `InsufficientFunds` refusal can arise for a SINGLE-coin case: a stale coin whose own
    /// collateral equals the CURRENT price always funds its own recreate on reclaim alone, whatever
    /// the rest of the wallet holds (`SPEC.md` §25.13.5's "common case Rᵢ = C" — locked in here so a
    /// fixture cannot silently drift back to the case that can never be short).
    fn declared_at(
        tag: &str,
        store: &str,
        root: &str,
        urls: Vec<String>,
        collateral_dig_base_units: u64,
    ) -> DeclaredBond {
        DeclaredBond {
            held: HeldMirror {
                coin_id: id(tag),
                store_id: id(store),
                root: id(root),
                epoch: NOW_EPOCH,
                collateral_dig_base_units,
            },
            urls,
        }
    }

    fn advertised_at(urls: Vec<String>) -> Effective {
        Effective {
            urls,
            state: AdvertiseState::Derived,
            rejected: Vec::new(),
        }
    }

    fn requirement_known() -> CollateralRequirementResult {
        CollateralRequirementResult::Known {
            epoch: NOW_EPOCH as u64,
            protocol_version: 1,
            required_per_store_dig_base_units: PER_COIN,
            stores: 1,
            owners: 1,
            multiplier_micros: 1_000_000,
            handicap_dig_base_units: 0,
        }
    }

    struct Fixture {
        advertised: Effective,
        mirror_enabled: bool,
        held_bonds: Vec<Bond>,
        bonded: Vec<DeclaredBond>,
        requirement: CollateralRequirementResult,
        dig_balance_base_units: Option<u64>,
        reconcile_in_progress: bool,
    }

    impl Fixture {
        fn holding_one_stale_bond() -> Self {
            Fixture {
                advertised: advertised_at(new_urls()),
                mirror_enabled: true,
                held_bonds: vec![bond("s1", "r1")],
                bonded: vec![declared("c1", "s1", "r1", old_urls())],
                requirement: requirement_known(),
                dig_balance_base_units: Some(PER_COIN * 100),
                reconcile_in_progress: false,
            }
        }

        fn inputs(&self) -> ReconcileInputs<'_> {
            ReconcileInputs {
                trigger: plan::Trigger::Daily,
                advertised: &self.advertised,
                mirror_enabled: self.mirror_enabled,
                held_bonds: &self.held_bonds,
                bonded: &self.bonded,
                current_epoch: NOW_EPOCH,
                requirement: &self.requirement,
                margin_bp: 0,
                dig_balance_base_units: self.dig_balance_base_units,
                reconcile_in_progress: self.reconcile_in_progress,
            }
        }
    }

    // --- refusal table, in gate order ------------------------------------------------------------

    #[test]
    fn gate1_refuses_when_the_address_is_uncorroborated() {
        let mut f = Fixture::holding_one_stale_bond();
        f.advertised = Effective {
            urls: Vec::new(),
            state: AdvertiseState::Uncorroborated,
            rejected: Vec::new(),
        };
        assert_eq!(
            decide(&f.inputs()),
            Err(RefusalReason::AdvertiseNotPublishing(
                AdvertiseState::Uncorroborated
            ))
        );
    }

    #[test]
    fn gate1_carries_the_actual_state_not_a_collapsed_token() {
        // Distinguishes the four §25.10 states from each other -- a refusal that collapsed them
        // into one "advertise_off" token would pass a fixture asserting only ONE of these.
        for state in [
            AdvertiseState::Off,
            AdvertiseState::NoPublicAddress,
            AdvertiseState::Uncorroborated,
            AdvertiseState::NoRelay,
        ] {
            let mut f = Fixture::holding_one_stale_bond();
            f.advertised = Effective {
                urls: Vec::new(),
                state,
                rejected: Vec::new(),
            };
            assert_eq!(
                decide(&f.inputs()),
                Err(RefusalReason::AdvertiseNotPublishing(state))
            );
        }
    }

    #[test]
    fn gate2_refuses_when_the_operator_switch_is_off() {
        let mut f = Fixture::holding_one_stale_bond();
        f.mirror_enabled = false;
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::Disabled));
    }

    #[test]
    fn gate4a_refuses_when_no_current_epoch_coin_is_held() {
        let mut f = Fixture::holding_one_stale_bond();
        f.bonded = Vec::new();
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::NoMirrorCoins));
    }

    /// **Distinguishes this property from the nearest wrong implementation**: a filter that forgot
    /// the disk-provenance check would see this coin as reconcilable (it exists on chain) — this
    /// fixture has a coin whose bond is NOT held on disk at all, so a correct implementation reports
    /// `no_mirror_coins`, matching `SPEC.md` §25.13's scope note that a bond off disk is
    /// `NoLongerHeld`'s business, never this module's.
    #[test]
    fn a_coin_whose_bond_left_disk_is_not_this_module_s_business() {
        let mut f = Fixture::holding_one_stale_bond();
        f.held_bonds = Vec::new();
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::NoMirrorCoins));
    }

    #[test]
    fn gate4b_refuses_as_a_no_op_when_every_coin_already_matches() {
        let mut f = Fixture::holding_one_stale_bond();
        f.bonded = vec![declared("c1", "s1", "r1", new_urls())];
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::UrlUnchanged));
    }

    #[test]
    fn a_reordered_url_list_is_url_unchanged_not_stale() {
        let mut f = Fixture::holding_one_stale_bond();
        f.advertised = advertised_at(vec!["https://a".into(), "https://b".into()]);
        f.bonded = vec![declared(
            "c1",
            "s1",
            "r1",
            vec!["https://b".into(), "https://a".into()],
        )];
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::UrlUnchanged));
    }

    #[test]
    fn gate5_refuses_when_the_requirement_is_unknown() {
        let mut f = Fixture::holding_one_stale_bond();
        f.requirement = CollateralRequirementResult::Unknown {
            reason: CollateralUnknownReason::NotCensused,
        };
        assert_eq!(
            decide(&f.inputs()),
            Err(RefusalReason::RequirementUnknown(
                CollateralUnknownReason::NotCensused
            ))
        );
    }

    #[test]
    fn gate7_refuses_when_the_balance_is_unmeasured() {
        let mut f = Fixture::holding_one_stale_bond();
        f.dig_balance_base_units = None;
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::FundsUnmeasured));
    }

    /// **The bound pinned from BOTH sides** (CLAUDE.md's fixture-design rule): one base unit short
    /// of affording the first recreate must refuse; exactly enough must proceed. A bound tested only
    /// from below could pass an implementation that is off by one in the expensive direction.
    ///
    /// The stale coin's OWN collateral is set BELOW [`PER_COIN`] — the mid-epoch-margin-raise case
    /// `SPEC.md` §25.13.5 names — because a coin locked at exactly the current price always funds
    /// its own recreate on reclaim alone, whatever the rest of the wallet holds; that case can never
    /// exercise this refusal and a fixture that used it would pass for the wrong reason.
    #[test]
    fn gate8_insufficient_funds_bound_from_below_refuses() {
        const OLD_COLLATERAL: u64 = PER_COIN - 200;
        let mut f = Fixture::holding_one_stale_bond();
        f.bonded = vec![declared_at("c1", "s1", "r1", old_urls(), OLD_COLLATERAL)];
        f.dig_balance_base_units = Some(199); // augmented = 199 + 800 = 999, one short of 1_000
        assert_eq!(
            decide(&f.inputs()),
            Err(RefusalReason::InsufficientFunds {
                have_dig_base_units: 199 + OLD_COLLATERAL,
                need_dig_base_units: PER_COIN,
            })
        );
    }

    #[test]
    fn gate8_insufficient_funds_bound_from_above_at_exactly_the_requirement_proceeds() {
        const OLD_COLLATERAL: u64 = PER_COIN - 200;
        let mut f = Fixture::holding_one_stale_bond();
        f.bonded = vec![declared_at("c1", "s1", "r1", old_urls(), OLD_COLLATERAL)];
        f.dig_balance_base_units = Some(200); // augmented = 200 + 800 = 1_000, exactly enough
        let directive = decide(&f.inputs()).expect("exactly enough must be affordable");
        assert_eq!(directive.coin_ids, vec![id("c1")]);
        assert_eq!(directive.left_unaffordable, 0);
    }

    #[test]
    fn gate9_refuses_when_a_reconcile_is_already_in_progress() {
        let mut f = Fixture::holding_one_stale_bond();
        f.reconcile_in_progress = true;
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::ReconcileInProgress));
    }

    // --- the directive itself --------------------------------------------------------------------

    #[test]
    fn names_every_stale_coin_when_funds_allow() {
        let mut f = Fixture::holding_one_stale_bond();
        f.held_bonds = vec![bond("s1", "r1"), bond("s2", "r2")];
        f.bonded = vec![
            declared("c1", "s1", "r1", old_urls()),
            declared("c2", "s2", "r2", old_urls()),
        ];
        let directive = decide(&f.inputs()).unwrap();
        assert_eq!(
            directive.coin_ids,
            vec![id("c1"), id("c2")],
            "canonical (store, root) order"
        );
        assert_eq!(directive.left_unaffordable, 0);
    }

    /// A coin that already matches is left OUT of the directive entirely, even though a sibling in
    /// the same call is stale — distinguishes "reconcile the stale set" from "reconcile everything
    /// held", which the single-stale-coin fixtures above cannot tell apart.
    #[test]
    fn a_matching_coin_is_never_named_while_a_sibling_is_stale() {
        let mut f = Fixture::holding_one_stale_bond();
        f.held_bonds = vec![bond("s1", "r1"), bond("s2", "r2")];
        f.bonded = vec![
            declared("c1", "s1", "r1", old_urls()), // stale
            declared("c2", "s2", "r2", new_urls()), // already current
        ];
        let directive = decide(&f.inputs()).unwrap();
        assert_eq!(directive.coin_ids, vec![id("c1")]);
    }

    /// **The property that outranks the rest**: with funds for only ONE of two stale recreates, the
    /// directive names exactly the affordable prefix and reports the rest as left, rather than
    /// naming all of them (which would reclaim a bond this call cannot afford to recreate).
    #[test]
    fn names_only_the_affordable_prefix_when_funds_are_short() {
        // Both stale coins locked BELOW the current price -- the mid-epoch-margin-raise case
        // (SPEC.md §25.13.5): a coin locked at exactly today's price always funds its own recreate
        // on reclaim alone, so `K < n` cannot arise unless at least one coin locked less than that.
        const OLD_COLLATERAL: u64 = PER_COIN - 200;
        let mut f = Fixture::holding_one_stale_bond();
        f.held_bonds = vec![bond("s1", "r1"), bond("s2", "r2")];
        f.bonded = vec![
            declared_at("c1", "s1", "r1", old_urls(), OLD_COLLATERAL),
            declared_at("c2", "s2", "r2", old_urls(), OLD_COLLATERAL),
        ];
        // augmented = 200 + 2*800 = 1_800 -- funds exactly one recreate at PER_COIN (1_000), not two.
        f.dig_balance_base_units = Some(200);
        let directive = decide(&f.inputs()).unwrap();
        assert_eq!(
            directive.coin_ids,
            vec![id("c1")],
            "only the affordable prefix is named"
        );
        assert_eq!(directive.left_unaffordable, 1);
    }

    /// A coin bonding a FUTURE epoch is never stale, whatever its URLs say -- the same "keep" rule
    /// an ordinary pass applies to a future-epoch coin (a slow local clock must not burn a fee and
    /// destroy a coin that becomes ordinary at the next tick anyway).
    #[test]
    fn a_future_epoch_coin_is_never_stale() {
        let mut f = Fixture::holding_one_stale_bond();
        f.bonded = vec![DeclaredBond {
            held: HeldMirror {
                coin_id: id("c1"),
                store_id: id("s1"),
                root: id("r1"),
                epoch: NOW_EPOCH + 1,
                collateral_dig_base_units: PER_COIN,
            },
            urls: old_urls(),
        }];
        assert_eq!(decide(&f.inputs()), Err(RefusalReason::NoMirrorCoins));
    }

    /// The directive echoes whichever trigger asked, for the audit record (`SPEC.md` §F) — it is
    /// not itself a gate input, so this is the one property no gate-refusal fixture above proves.
    #[test]
    fn the_directive_carries_the_trigger_that_asked() {
        let f = Fixture::holding_one_stale_bond();
        let mut inputs = f.inputs();
        inputs.trigger = plan::Trigger::Manual;
        assert_eq!(decide(&inputs).unwrap().trigger, plan::Trigger::Manual);
    }
}
