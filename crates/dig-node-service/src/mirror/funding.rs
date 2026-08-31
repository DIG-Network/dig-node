//! Operator-scoped $DIG selection — where a mirror create's collateral comes from (dig-node#421).
//!
//! # The wallet this reads is not the wallet the node serves
//!
//! A mirror create locks money belonging to the §16.4 OPERATOR wallet — the key
//! [`super::signer::MirrorSigner`] signs with. The only $DIG selector this process previously had
//! was `WalletBackend::select_cats`, which selects over the node-custodied replica's own coin table
//! (`db.unreserved_unspent_coins`). Those are two different wallets holding two different sets of
//! coins, and funding a mirror coin from the replica's set would be a real spend of the wrong
//! wallet's money that returns `Ok` and looks entirely successful.
//!
//! So this module does not read a coin TABLE at all. It reads the chain, at one puzzle hash derived
//! from the operator's own: [`dig_cat_puzzle_hash`]. That derivation is what makes the scope a
//! structural property rather than a convention — there is no filter to forget, because a coin at
//! any other owner's puzzle hash is never read in the first place.
//!
//! # Lineage is the authentication, not a formality
//!
//! A `Cat` is only spendable with a lineage proof, and the proof comes from the spend that CREATED
//! the coin. Anyone may pay a coin to any puzzle hash, so a record returned by the scan is a
//! CANDIDATE: it becomes a spendable $DIG coin only once its creating spend has been executed and
//! `Cat::parse_children` has produced a child matching it. A candidate whose creating spend cannot
//! be read, or does not yield it, is REFUSED — the whole selection, not just that coin.
//!
//! # A shortfall refuses; it never funds a smaller coin
//!
//! `SPEC.md` §25: a mirror coin below the epoch's requirement is collateral that is genuinely locked
//! and does not satisfy the bond — strictly worse than not creating one. Every failure here is
//! therefore a refusal of the whole create, and the pass reports it in `stopped_at`.
//!
//! # Reservations, without a reservation table
//!
//! The wallet's own selector prunes reservations and reads the UNRESERVED unspent set
//! (dig_ecosystem#2763), so a coin committed to an in-flight bundle cannot fund a second one. The
//! chain cannot offer that: a broadcast coin stays unspent in the chain's view for the whole
//! confirmation window, and the mirror pass runs on a round timer inside it.
//!
//! The equivalent record already exists and is durable — [`SpendJournal`](crate::spend_audit) writes
//! the `funding_coin_ids` of every bundle it submits, and
//! [`SpendStatus::is_terminal`](crate::spend_audit::SpendStatus::is_terminal) already answers
//! exactly the right question: whether any further observation is expected to change the outcome. A
//! non-terminal record's funding coins may still be consumed, so they are withheld. See
//! [`committed_funding_coin_ids`].

use std::collections::HashSet;

use chia_protocol::Bytes32;
use chia_puzzle_types::cat::CatArgs;
use chia_sdk_driver::Cat;
use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::DIG_ASSET_ID;
use dig_wallet::sage::selection::select_largest_first;
use dig_wallet::sage::singleton::{resolve_cat, ParentSpend};

use crate::spend_audit::SpendLog;

/// Why a create could not be funded. Every variant is a REFUSAL of the whole create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingError {
    /// The chain could not answer. The coin set is UNKNOWN, never empty.
    Chain(String),
    /// The operator wallet does not hold enough spendable, uncommitted $DIG.
    Insufficient {
        /// What the scan found at the operator puzzle hash, less anything committed in flight.
        have_dig_base_units: u64,
        /// The margined requirement the create needs.
        need_dig_base_units: u64,
    },
    /// A selected candidate could not be proven to be a spendable $DIG coin of this operator.
    Unauthenticated {
        /// The candidate, so an operator can look it up.
        coin_id: String,
        /// What could not be established.
        reason: String,
    },
    /// The audit record could not be read, so what is already committed is UNKNOWN.
    ///
    /// Fails closed for the reason the whole module does: an unreadable reservation set is
    /// indistinguishable from an empty one, and treating it as empty is what double-commits a coin.
    CommitmentsUnreadable(String),
    /// Covering the create needs more inputs than a single bundle may draw
    /// ([`MAX_SELECTED_FUNDING_COINS`]).
    ///
    /// Its own variant rather than an `Insufficient`, because the two send an operator to opposite
    /// places: `Insufficient` says *find more $DIG*, and this says *you have the money, it is in
    /// too many pieces*. Telling a funded operator they are short is the money-lie class this
    /// module is built to avoid.
    TooManyInputs {
        /// How many coins largest-first selection needed to reach the target.
        needed: usize,
        /// The bound.
        limit: usize,
        /// What the operator can spend, in $DIG base units. Carried because this refusal is the
        /// only producer of [`FundingRemedy::Consolidate`], and an operator-facing message that
        /// says *you have enough, it is in too many pieces* has to be able to say how much.
        have_dig_base_units: u64,
        /// The margined requirement, in the same units. Never greater than `have` here: selection
        /// COVERED the target and was refused for the shape of the cover, not its size.
        need_dig_base_units: u64,
    },
    /// A create was asked for at zero collateral.
    ///
    /// Refused HERE, ahead of the builder, because zero is the one target for which selection
    /// legitimately returns an empty set — and an empty `Vec<Cat>` is precisely the short funding
    /// set this module exists to never produce.
    ZeroCollateral,
}

impl std::fmt::Display for FundingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FundingError::Chain(e) => {
                write!(f, "the operator wallet's $DIG coins are unreadable: {e}")
            }
            FundingError::Insufficient {
                have_dig_base_units,
                need_dig_base_units,
            } => write!(
                f,
                "the operator wallet holds {have_dig_base_units} uncommitted DIG base units and \
                 the create needs {need_dig_base_units}; no spend was attempted"
            ),
            FundingError::Unauthenticated { coin_id, reason } => write!(
                f,
                "coin {coin_id} at the operator address could not be proven spendable $DIG \
                 ({reason}), so the whole selection is refused"
            ),
            FundingError::CommitmentsUnreadable(e) => write!(
                f,
                "the spend audit record is unreadable ({e}), so which coins are already committed \
                 to an in-flight bundle is unknown; no coin is selected"
            ),
            FundingError::TooManyInputs { needed, limit, .. } => write!(
                f,
                "covering this create needs {needed} $DIG coins and a mirror create may draw at most {limit}; the wallet is not short, its $DIG is in too many pieces. No coin was authenticated and no spend was attempted; consolidating the operator's $DIG into fewer coins clears it"
            ),
            FundingError::ZeroCollateral => {
                f.write_str("a create at zero collateral stakes nothing and is refused")
            }
        }
    }
}

/// The most $DIG coins one mirror create may draw as inputs (dig-node#427).
///
/// # Why a bound is REQUIRED here specifically
///
/// The address selection scans — [`dig_cat_puzzle_hash`] of the operator hash — is **publicly
/// derivable**: the operator puzzle hash is a public value and the CAT curry is canonical, so any
/// stranger can compute where this node's $DIG lives and pay dust to it. Every input that survives
/// selection then costs one `coin_spend` chain read in [`authenticate`], because a candidate's
/// lineage is executed from the spend that created it. Unbounded, that makes the number of chain
/// reads one automated pass performs a function of what an attacker chose to send — a cost this
/// node pays, on a timer, forever.
///
/// Largest-first selection is not itself the defence. It is the reason the bound is rarely reached
/// on a healthy wallet, but a wallet whose genuine $DIG has been ground into dust reaches it for
/// entirely innocent reasons, and an attacker who out-values the honest coins reaches it on
/// purpose.
///
/// # Which direction it fails in, stated deliberately
///
/// It fails **CLOSED**: the create is refused, the bond is not collateralised this pass, and
/// [`FundingError::TooManyInputs`] names the reason and the remedy. That is recoverable — the next
/// pass retries, and consolidating the operator's coins fixes it permanently. Failing open would
/// mean a stranger can make this node perform thousands of chain reads per pass at the price of
/// dust, which is not recoverable by anything the operator can do.
///
/// The refusal happens AFTER selection and BEFORE authentication, which is the only placement that
/// achieves the point: selection is in-memory over rows already fetched, so it is free, while
/// authentication is the per-input chain read being bounded. Bounding the CANDIDATE set instead
/// would refuse a perfectly fundable create because a stranger sent dust this node never selected.
/// UNMEASURED JUDGEMENT, stated so nobody reads it as a derived limit: nobody has measured how many
/// $DIG coins a real operator wallet holds. 32 is chosen to bound the per-create chain reads, and if
/// a legitimate wallet routinely exceeds it this fails CLOSED on that operator -- they see
/// `TooManyInputs` and consolidate, rather than a spend going wrong. That direction is the safe one,
/// and an attacker cannot cheaply force it (see dig-node#461 for the cheap attack that DOES exist on
/// this path, which is the abort-on-unauthenticatable coin, not this bound).
pub const MAX_SELECTED_FUNDING_COINS: usize = 32;

/// The puzzle hash the operator's ordinary $DIG coins sit at.
///
/// $DIG is a CAT, so the operator's coins are NEVER at the bare owner puzzle hash: they sit at the
/// canonical CAT wrapping of it under [`DIG_ASSET_ID`]. Scanning the unwrapped hash would find XCH
/// and nothing else — a confident empty answer, which reads as "this wallet has no $DIG".
///
/// One derivation, used by both directions of the money: the coins a create SPENDS are found here,
/// and the coin a reclaim CREATES is named here. Two copies of a CAT curry is the shape that
/// produces a puzzle hash nobody can spend.
pub fn dig_cat_puzzle_hash(owner_puzzle_hash: Bytes32) -> Bytes32 {
    let inner: clvm_utils::TreeHash = owner_puzzle_hash.into();
    CatArgs::curry_tree_hash(DIG_ASSET_ID, inner).into()
}

/// The coins this node has already committed to a bundle whose outcome is not yet settled.
///
/// Read from the audit record rather than from a side table, because the audit record is the thing
/// that survives a restart — and the window this guards against is measured in confirmation times,
/// which comfortably outlast a process.
///
/// The predicate is [`SpendStatus::is_terminal`](crate::spend_audit::SpendStatus::is_terminal),
/// reused rather than restated. It already means "no further observation is expected to change
/// this", which is exactly the question being asked: a `Submitted` spend may still consume its
/// coins, an `Unresolved` one may already have, and a `Failed` one at a stage that
/// [may have moved money](crate::spend_audit::FailureStage::money_may_have_moved) is an unknown
/// wearing a failure's name. Only a `Confirmed` spend, or one that failed before signing, releases
/// its coins — and a `Confirmed` spend's coins are spent on chain anyway, so the scan never offers
/// them.
///
/// A record with unreadable lines is a refusal, not a shorter answer: the lost lines may be exactly
/// the ones naming a committed coin, and a reservation set that silently shrinks is worse than none.
pub fn committed_funding_coin_ids(log: &SpendLog) -> Result<HashSet<String>, FundingError> {
    let ledger = log
        .ledger()
        .map_err(|e| FundingError::CommitmentsUnreadable(e.to_string()))?;
    if ledger.unreadable_lines > 0 {
        return Err(FundingError::CommitmentsUnreadable(format!(
            "{} entries could not be parsed",
            ledger.unreadable_lines
        )));
    }
    Ok(ledger
        .records
        .iter()
        .filter(|r| !r.status.is_terminal())
        .flat_map(|r| r.funding_coin_ids.iter().map(|c| c.0.clone()))
        .collect())
}

/// A candidate that was passed over, and why — the counted, reportable half of a selection.
///
/// Carried out of the selection rather than only logged, so that a caller (and a test) can assert
/// how many candidates were passed over. A skip that is invisible to its caller is the silence this
/// type exists to break: the same code path that passes over a stranger's coin also passes over a
/// coin this node genuinely owns when lineage handling has a bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedCandidate {
    /// The candidate's coin id, hex-encoded, so an operator can look it up on chain.
    pub coin_id: String,
    /// What could not be established about it.
    pub reason: String,
}

/// The outcome of a funding selection: the coins to spend, and the candidates passed over.
#[derive(Debug, Clone)]
pub struct FundingSelection {
    /// The authenticated, spendable $DIG coins covering the requirement.
    pub cats: Vec<Cat>,
    /// Candidates at the operator's address that could not be authenticated, in the order walked.
    pub skipped: Vec<SkippedCandidate>,
}

/// Select spendable $DIG `Cat`s of the OPERATOR wallet covering `need_dig_base_units`.
///
/// The `Vec<Cat>` half of [`select_operator_dig_cats_detailed`], for callers that fund a spend and
/// have nothing to say about the candidates that were passed over.
pub fn select_operator_dig_cats<S: ChainSource>(
    source: &S,
    owner_puzzle_hash: Bytes32,
    need_dig_base_units: u64,
    committed: &HashSet<String>,
) -> Result<Vec<Cat>, FundingError> {
    select_operator_dig_cats_detailed(source, owner_puzzle_hash, need_dig_base_units, committed)
        .map(|selection| selection.cats)
}

/// Select spendable $DIG `Cat`s of the OPERATOR wallet, reporting what was passed over.
///
/// `need_dig_base_units` is $DIG in base units (1 DIG = 1_000, never mojos) and is the epoch's
/// derived requirement — `apply_safety_margin(required_per_store, margin_bp)`, `SPEC.md` §25.3 —
/// carried in from the planner. Nothing here re-derives it: this function selects coins to cover a
/// number, and has no opinion about what the number should be.
///
/// `committed` is the output of [`committed_funding_coin_ids`], passed in rather than read here so
/// that one pass takes one reading of the audit record, in the same way it takes one reading of the
/// disk and one of the balance.
///
/// # An unauthenticatable candidate is SKIPPED, not fatal (dig-node#461)
///
/// The scan address is `dig_cat_puzzle_hash(owner)`, derivable by anyone from the operator's public
/// owner puzzle hash, and anyone may pay a coin to any puzzle hash. Noise at a public address is the
/// normal condition of a public address, so a candidate that cannot be authenticated is not this
/// operator's coin and costs one authentication attempt and nothing else.
///
/// Refusing the whole selection on the first such candidate — which this function used to do —
/// composed with two other facts into a denial of service that cost the attacker dust: selection is
/// largest-first, so a coin with a large declared amount is walked FIRST, and one unspent coin of
/// that shape at the public address meant no honest coin was ever reached, on any pass, forever.
///
/// Two properties keep the skip from becoming a different failure:
///
/// * **A skip is counted and reported**, never swallowed. The same path covers a genuine defect in
///   lineage handling, and a selection that quietly discarded the operator's own coins while
///   reporting a shortfall would be indistinguishable from an empty wallet.
/// * **A skip costs no selection budget.** Candidates are authenticated against the POOL, and a
///   failed one is removed from the pool before the requirement is covered again — so the coins
///   handed back are honest coins only, and their number is a function of the honest set alone. An
///   attacker who could spend an input slot per dust coin would reinstate the same denial in a
///   slower form.
///
/// A chain that cannot ANSWER is still fatal, and deliberately so: an unreadable source is not a
/// verdict about a coin, and treating it as one would silently shrink the wallet.
pub fn select_operator_dig_cats_detailed<S: ChainSource>(
    source: &S,
    owner_puzzle_hash: Bytes32,
    need_dig_base_units: u64,
    committed: &HashSet<String>,
) -> Result<FundingSelection, FundingError> {
    if need_dig_base_units == 0 {
        return Err(FundingError::ZeroCollateral);
    }

    let records = source
        .coin_records_by_puzzle_hash(dig_cat_puzzle_hash(owner_puzzle_hash), false)
        .map_err(|e| FundingError::Chain(e.to_string()))?;

    // `include_spent: false` is asked for above; `is_spent` is re-checked because a source that
    // honours the flag and one that ignores it are indistinguishable from the returned rows, and
    // selecting a spent coin produces a bundle the mempool rejects for reasons that look nothing
    // like this.
    let mut pool: Vec<_> = records
        .into_iter()
        .filter(|r| !r.is_spent())
        .filter(|r| !committed.contains(&hex::encode(r.coin.coin_id())))
        .collect();

    // Authenticating a candidate costs a chain read, so each is authenticated at most once however
    // many times the requirement is covered again.
    let mut authenticated: Vec<(String, Cat)> = Vec::new();
    let mut skipped: Vec<SkippedCandidate> = Vec::new();

    loop {
        let available = pool
            .iter()
            .fold(0u64, |sum, r| sum.saturating_add(r.coin.amount));

        let selected = select_largest_first(pool.clone(), need_dig_base_units, |r| {
            (r.coin.amount, r.coin.coin_id())
        })
        .map_err(|_| FundingError::Insufficient {
            // The honest total: every candidate proven unauthenticatable has already left the pool,
            // so this is what the operator can actually spend rather than what the address happens
            // to hold. Reporting the latter would tell an operator their wallet holds money that is
            // not theirs.
            have_dig_base_units: available,
            need_dig_base_units,
        })?;

        // The bound (dig-node#427) is applied to the CURRENT selection, which by construction
        // contains no candidate already proven unauthenticatable -- those left the pool. So a
        // skipped coin costs no input slot, and an attacker cannot reinstate dig-node#461 in a
        // slower form by dusting the address until the bound alone refuses every create.
        if selected.len() > MAX_SELECTED_FUNDING_COINS {
            return Err(FundingError::TooManyInputs {
                needed: selected.len(),
                limit: MAX_SELECTED_FUNDING_COINS,
                have_dig_base_units: available,
                need_dig_base_units,
            });
        }

        let mut rejected: Option<Bytes32> = None;
        let mut cats = Vec::with_capacity(selected.len());
        for record in &selected {
            let candidate_id = hex::encode(record.coin.coin_id());
            if let Some((_, cat)) = authenticated.iter().find(|(id, _)| id == &candidate_id) {
                cats.push(*cat);
                continue;
            }
            match authenticate(source, record, owner_puzzle_hash) {
                Ok(cat) => {
                    authenticated.push((candidate_id, cat));
                    cats.push(cat);
                }
                Err(FundingError::Unauthenticated { coin_id, reason }) => {
                    tracing::warn!(
                        coin_id = %coin_id,
                        reason = %reason,
                        concat!(
                            "a coin at the operator's $DIG address could not be proven spendable ",
                            "and was passed over; if it is one of this node's own coins, its ",
                            "lineage is not readable from the chain"
                        )
                    );
                    skipped.push(SkippedCandidate { coin_id, reason });
                    rejected = Some(record.coin.coin_id());
                    break;
                }
                // A source that cannot answer is not a verdict about the coin.
                Err(fatal) => return Err(fatal),
            }
        }

        match rejected {
            // The rejected candidate leaves the POOL, so it can neither be walked again nor occupy
            // an input slot, and the requirement is covered again from what remains.
            Some(coin_id) => pool.retain(|r| r.coin.coin_id() != coin_id),
            None => return Ok(FundingSelection { cats, skipped }),
        }
    }
}

/// What an operator must actually DO about a funding shortfall.
///
/// Two remedies, because they are different actions and telling an operator the wrong one wastes
/// their money or their afternoon: a wallet holding too little $DIG needs topping up, and a wallet
/// holding enough $DIG in too many pieces needs consolidating. A message that said only "funding
/// failed" would leave both operators guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingRemedy {
    /// The wallet does not hold enough $DIG. Add funds.
    TopUp,
    /// The wallet holds enough, in too many coins to spend in one bundle. Consolidate them.
    Consolidate,
}

/// A message for a person, raised when the funding state of the mirror pass CHANGES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingAlert {
    /// A one-line headline.
    pub title: String,
    /// The body: what happened, in what amounts, and what to do about it.
    pub body: String,
    /// The action this alert is asking for, or `None` when it reports a recovery.
    pub remedy: Option<FundingRemedy>,
}

/// What one mirror pass observed about funding — the input the alert gate decides on.
///
/// Deliberately only three shapes. A pass that could not READ the balance is not a pass that found
/// it short, and is not represented here at all: reporting a shortfall on no evidence is precisely
/// the money lie this crate refuses elsewhere, so the caller maps an unreadable balance to
/// [`FundingObservation::Unknown`], which never alerts and never clears the state either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingObservation {
    /// A create was funded, or none was needed. The operator wallet is not blocking anything.
    Healthy,
    /// A create was refused for want of funds.
    Short {
        /// What the operator can spend, in $DIG base units.
        have_dig_base_units: u64,
        /// What the create needed, in the same units.
        need_dig_base_units: u64,
        /// The action that would clear it.
        remedy: FundingRemedy,
    },
    /// The funding state could not be established this pass.
    Unknown,
}

impl FundingObservation {
    /// Read a pass's funding outcome off the error the selection refused with.
    ///
    /// The match is exhaustive on purpose. A new [`FundingError`] variant — the bounded-input
    /// refusal in flight is one — will not compile until someone decides whether it is a shortfall
    /// an operator can act on, and if so which remedy it names. A wildcard arm here would silently
    /// classify every future refusal as unknown, which is the shape that ships a surface reporting
    /// nothing about a condition it was built to report.
    pub fn from_error(error: &FundingError) -> Self {
        match error {
            FundingError::Insufficient {
                have_dig_base_units,
                need_dig_base_units,
            } => FundingObservation::Short {
                have_dig_base_units: *have_dig_base_units,
                need_dig_base_units: *need_dig_base_units,
                remedy: FundingRemedy::TopUp,
            },
            // A funded wallet whose $DIG is in too many pieces (dig-node#427). It IS a shortfall
            // an operator can act on, and it is the ONLY producer of `Consolidate` -- before this
            // arm existed that remedy was reachable in tests and by nothing else, so the branch of
            // `shortfall_alert` telling an operator to consolidate could never be shown to one.
            //
            // `have >= need` here, so the deficit is zero, and that is correct rather than a
            // degenerate case: the operator is not missing money, and an alert that quoted a
            // deficit would send them to buy $DIG they already hold.
            FundingError::TooManyInputs {
                have_dig_base_units,
                need_dig_base_units,
                ..
            } => FundingObservation::Short {
                have_dig_base_units: *have_dig_base_units,
                need_dig_base_units: *need_dig_base_units,
                remedy: FundingRemedy::Consolidate,
            },
            // Not shortfalls. An unreadable chain or audit record says nothing about the balance,
            // and a create asked for at zero collateral is a caller defect, not an empty wallet.
            FundingError::Chain(_) | FundingError::CommitmentsUnreadable(_) => {
                FundingObservation::Unknown
            }
            FundingError::Unauthenticated { .. } | FundingError::ZeroCollateral => {
                FundingObservation::Unknown
            }
        }
    }
}

/// Decides WHEN the operator is told their node has stopped bonding content (dig-node#463).
///
/// # The policy, stated here because "how often does this fire" is the whole design
///
/// The mirror pass runs unattended every ten minutes. A notification per pass is 144 a day, which
/// trains an operator to dismiss them and loses the one that mattered inside the noise. So:
///
/// * **On the TRANSITION into a funding-short state — once.** Consecutive short passes after that
///   raise nothing.
/// * **While short, again only on a MATERIAL change**: the remedy changes (topping up and
///   consolidating are different actions, so an operator following the old one is being misled), or
///   the deficit grows by at least [`MATERIAL_DEFICIT_GROWTH_PERCENT`] over the deficit last
///   alerted on. Growth by a fixed proportion is self-limiting — each further alert needs a deficit
///   half again as large as the last — so a steadily worsening shortfall cannot become a stream.
/// * **Once on RECOVERY**, so an operator who acted learns it worked without having to watch for it.
/// * **Never on [`FundingObservation::Unknown`]**, which also does not CLEAR the state: an
///   unreadable pass is not evidence of recovery, and treating it as one would re-alert on the next
///   short pass for a shortfall that never went away.
///
/// The gate holds one pass of state and no clock. It is deliberately not the delivery mechanism:
/// it answers whether to speak, and the caller decides how.
#[derive(Debug, Default)]
pub struct FundingAlertGate {
    /// The shortfall the last alert was raised for, or `None` while not in the short state.
    alerted: Option<(FundingRemedy, u64)>,
}

/// How much a deficit must grow, in percent of the last alerted deficit, to speak again.
///
/// 50% rather than a few percent: this fires while an operator has already been told, and the
/// question it answers is "has this become a materially different problem", not "has the number
/// moved". A small threshold turns a slowly worsening shortfall back into the per-pass stream this
/// gate exists to prevent.
pub const MATERIAL_DEFICIT_GROWTH_PERCENT: u64 = 50;

impl FundingAlertGate {
    /// Feed one pass's observation, and get back the alert to raise — or nothing.
    pub fn observe(&mut self, observation: &FundingObservation) -> Option<FundingAlert> {
        match observation {
            FundingObservation::Unknown => None,
            FundingObservation::Healthy => self.alerted.take().map(|_| FundingAlert {
                title: "DIG mirror collateral resumed".into(),
                body: concat!(
                    "The operator wallet can fund mirror collateral again. Your content is being ",
                    "bonded on the next pass."
                )
                .into(),
                remedy: None,
            }),
            FundingObservation::Short {
                have_dig_base_units,
                need_dig_base_units,
                remedy,
            } => {
                let deficit = need_dig_base_units.saturating_sub(*have_dig_base_units);
                let speak = match self.alerted {
                    None => true,
                    Some((last_remedy, last_deficit)) => {
                        last_remedy != *remedy || grew_materially(last_deficit, deficit)
                    }
                };
                if !speak {
                    return None;
                }
                self.alerted = Some((*remedy, deficit));
                Some(shortfall_alert(
                    *have_dig_base_units,
                    *need_dig_base_units,
                    *remedy,
                ))
            }
        }
    }
}

/// Whether `deficit` is materially worse than the one already reported.
///
/// A deficit of zero is reachable and means something specific: [`FundingRemedy::Consolidate`], a
/// wallet that holds enough $DIG in too many pieces. Zero stays zero under this arithmetic, so a
/// consolidate state alerts once on entry and then stays quiet however many passes it persists for
/// — which is the intended behaviour, since the remedy never changes while the coins do not.
fn grew_materially(last_deficit: u64, deficit: u64) -> bool {
    let threshold = last_deficit
        .saturating_add(last_deficit.saturating_mul(MATERIAL_DEFICIT_GROWTH_PERCENT) / 100);
    deficit > threshold
}

/// The operator-facing text for a shortfall.
///
/// $DIG is rendered in whole DIG (1 DIG = 1_000 base units) because that is the unit an operator
/// buys and holds; base units would be a true figure nobody can act on. No coin id and no address
/// appears — a desktop notification is read over a shoulder and shown on a lock screen, and neither
/// figure helps the operator do the thing this message is asking for.
fn shortfall_alert(
    have_dig_base_units: u64,
    need_dig_base_units: u64,
    remedy: FundingRemedy,
) -> FundingAlert {
    let short = need_dig_base_units.saturating_sub(have_dig_base_units);
    let body = match remedy {
        FundingRemedy::TopUp => format!(
            concat!(
                "Your node cannot bond content: it needs {} DIG of collateral for this epoch and ",
                "the operator wallet holds {} DIG that it can spend, so it is {} DIG short. Add ",
                "$DIG to the operator wallet. Until then no new content is collateralised and it ",
                "earns nothing."
            ),
            whole_dig(need_dig_base_units),
            whole_dig(have_dig_base_units),
            whole_dig(short)
        ),
        FundingRemedy::Consolidate => format!(
            concat!(
                "Your node cannot bond content: the operator wallet holds enough $DIG for the {} ",
                "DIG this epoch requires, but in too many separate coins to spend at once. ",
                "Consolidate the wallet's $DIG into fewer coins — adding more will not help."
            ),
            whole_dig(need_dig_base_units)
        ),
    };
    FundingAlert {
        title: "DIG node cannot bond content".into(),
        body,
        remedy: Some(remedy),
    }
}

/// Render $DIG base units as whole DIG with three decimal places (1 DIG = 1_000 base units).
fn whole_dig(base_units: u64) -> String {
    format!("{}.{:03}", base_units / 1_000, base_units % 1_000)
}

/// Turn one candidate record into a spendable [`Cat`], or refuse.
///
/// The lineage proof is reconstructed from the spend that CREATED the coin — which is the spend that
/// SPENT its parent, hence the read on `parent_coin_info`. Executing that spend and matching a child
/// by coin id is what proves the candidate is a real CAT rather than a coin somebody paid to this
/// puzzle hash.
///
/// The two identity checks after resolution are not redundant with the scan. The scan proves the
/// coin sits at a hash currying $DIG around this operator's inner puzzle; these assert that the
/// resolved CAT AGREES about both. They can only ever fire if the CAT construction and this module's
/// derivation have drifted apart, and that is precisely the condition under which a selection would
/// otherwise hand the builder coins it cannot spend.
fn authenticate<S: ChainSource>(
    source: &S,
    record: &dig_chainsource_interface::CoinRecord,
    owner_puzzle_hash: Bytes32,
) -> Result<Cat, FundingError> {
    let coin_id = hex::encode(record.coin.coin_id());
    let refuse = |reason: &str| FundingError::Unauthenticated {
        coin_id: coin_id.clone(),
        reason: reason.to_string(),
    };

    let creating = source
        .coin_spend(record.coin.parent_coin_info)
        // An `Err` is the source failing to answer, which is a CHAIN failure and not a verdict about
        // the coin. Kept distinct so an operator is not told their coin is forged when the truth is
        // that the read timed out.
        .map_err(|e| FundingError::Chain(e.to_string()))?
        .ok_or_else(|| refuse("its creating spend is not on chain"))?;

    let parent = ParentSpend {
        coin: creating.coin,
        puzzle_reveal: creating.puzzle_reveal.into(),
        solution: creating.solution.into(),
    };
    let cat = resolve_cat(&parent, record.coin)
        .map_err(|e| refuse(&format!("its lineage could not be executed: {e}")))?
        .ok_or_else(|| refuse("its creating spend produced no matching CAT child"))?;

    if cat.info.asset_id != DIG_ASSET_ID {
        return Err(refuse("the resolved CAT is not $DIG"));
    }
    if cat.info.p2_puzzle_hash != owner_puzzle_hash {
        return Err(refuse(
            "the resolved CAT is owned by a different puzzle hash",
        ));
    }
    Ok(cat)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short pass, repeated. The operator hears about it ONCE.
    fn short(have: u64) -> FundingObservation {
        FundingObservation::Short {
            have_dig_base_units: have,
            need_dig_base_units: 100_000,
            remedy: FundingRemedy::TopUp,
        }
    }

    /// **Ten consecutive short passes raise exactly one alert.**
    ///
    /// The pass runs every ten minutes, so the failure this asserts against is not a wrong message
    /// but 144 correct ones a day, which is how the one that matters gets dismissed with the rest.
    /// The count is asserted rather than "the first one alerts", because an implementation that
    /// alerted on passes one and seven satisfies the weaker claim.
    #[test]
    fn consecutive_short_passes_alert_once_rather_than_once_per_pass() {
        let mut gate = FundingAlertGate::default();
        let raised: Vec<FundingAlert> = (0..10)
            .filter_map(|_| gate.observe(&short(60_000)))
            .collect();
        assert_eq!(
            raised.len(),
            1,
            "one transition into the short state is one alert: {raised:?}"
        );
        assert_eq!(raised[0].remedy, Some(FundingRemedy::TopUp));
        assert!(
            raised[0].body.contains("40.000"),
            "the operator is told how much they are short: {}",
            raised[0].body
        );
    }

    /// **Recovering and falling short again alerts again.**
    ///
    /// The pairing matters: a gate that simply latched forever would pass the test above and leave
    /// an operator who fixed the problem, and then hit it again, permanently unwarned. Three
    /// distinct outcomes are asserted from one sequence — the recovery speaks, and the second
    /// shortfall speaks again.
    #[test]
    fn a_recovery_then_a_second_shortfall_alerts_again() {
        let mut gate = FundingAlertGate::default();
        assert!(gate.observe(&short(60_000)).is_some(), "the transition in");
        assert!(gate.observe(&short(60_000)).is_none(), "still short");

        let recovered = gate
            .observe(&FundingObservation::Healthy)
            .expect("recovery");
        assert_eq!(recovered.remedy, None, "a recovery asks for no action");
        assert!(
            gate.observe(&FundingObservation::Healthy).is_none(),
            "a healthy pass after a healthy pass is not news"
        );

        assert!(
            gate.observe(&short(60_000)).is_some(),
            "falling short again is a new transition and must be reported"
        );
    }

    /// **An unreadable pass neither alerts nor clears the state.**
    ///
    /// Two properties in one sequence, and the second is the one an implementation is likely to
    /// miss: treating "unknown" as recovery would re-alert on the very next short pass for a
    /// shortfall that never went away, turning an unstable chain read into a notification stream.
    #[test]
    fn an_unknown_funding_state_is_silent_and_does_not_count_as_a_recovery() {
        let mut gate = FundingAlertGate::default();
        assert!(gate.observe(&short(60_000)).is_some());
        assert!(
            gate.observe(&FundingObservation::Unknown).is_none(),
            "a pass that could not read the balance has nothing to report"
        );
        assert!(
            gate.observe(&short(60_000)).is_none(),
            "the shortfall never went away, so it must not be announced a second time"
        );
    }

    /// **A materially worse shortfall speaks; a slightly worse one does not.**
    ///
    /// Both sides of the bound, from one starting point, because a threshold tested only from below
    /// confirms nothing but its own existence. At a 40_000 deficit the bound is 60_000: 59_000 is
    /// silent and 61_000 speaks.
    #[test]
    fn the_deficit_must_grow_materially_before_it_is_reported_again() {
        let mut gate = FundingAlertGate::default();
        assert!(gate.observe(&short(60_000)).is_some(), "deficit 40_000");
        assert!(
            gate.observe(&short(41_000)).is_none(),
            "a deficit of 59_000 is under the 50% bound and is not a new problem"
        );
        assert!(
            gate.observe(&short(39_000)).is_some(),
            "a deficit of 61_000 is over the bound and is worth interrupting for"
        );
    }

    /// **A changed remedy speaks even when the deficit has not moved.**
    ///
    /// Top up and consolidate are opposite instructions. An operator acting on a stale one adds
    /// money to a wallet that already had enough, so the remedy is reported on its own account
    /// rather than only when an amount crosses a threshold.
    #[test]
    fn a_changed_remedy_is_reported_even_at_an_unchanged_deficit() {
        let mut gate = FundingAlertGate::default();
        assert!(gate.observe(&short(60_000)).is_some());
        let switched = gate
            .observe(&FundingObservation::Short {
                have_dig_base_units: 60_000,
                need_dig_base_units: 100_000,
                remedy: FundingRemedy::Consolidate,
            })
            .expect("the remedy changed, so the previous instruction is now wrong");
        assert!(
            switched.body.contains("Consolidate"),
            "the message must name the action that now applies: {}",
            switched.body
        );
    }

    /// **An unreadable balance is never classified as a shortfall.**
    ///
    /// `BalanceUnreadable` exists because "we could not read it" and "you do not have enough" are
    /// one `Ok` apart and mean opposite things. This asserts the classification at the boundary the
    /// alert gate reads from, so a chain blip can never produce a message telling an operator to
    /// spend money.
    #[test]
    fn an_unreadable_source_is_not_reported_to_the_operator_as_a_shortfall() {
        assert_eq!(
            FundingObservation::from_error(&FundingError::Chain("timeout".into())),
            FundingObservation::Unknown
        );
        assert_eq!(
            FundingObservation::from_error(&FundingError::CommitmentsUnreadable("torn".into())),
            FundingObservation::Unknown
        );
        assert_eq!(
            FundingObservation::from_error(&FundingError::Insufficient {
                have_dig_base_units: 1,
                need_dig_base_units: 2,
            }),
            FundingObservation::Short {
                have_dig_base_units: 1,
                need_dig_base_units: 2,
                remedy: FundingRemedy::TopUp,
            },
            "a genuine shortfall must still reach the operator"
        );
    }

    /// **No coin id and no address reaches a desktop notification.**
    ///
    /// The test looks for an identifier's SHAPE — a long unbroken run of hex — rather than for a
    /// particular string, so it still fires if someone later interpolates a coin id that no fixture
    /// here happens to name. Prose is full of hex letters, which is why the run length is what
    /// discriminates.
    #[test]
    fn an_alert_never_carries_a_coin_id_or_an_address() {
        let mut gate = FundingAlertGate::default();
        let alert = gate.observe(&short(60_000)).expect("the transition in");
        let text = format!("{} {}", alert.title, alert.body);
        for token in text.split_whitespace() {
            let hexish = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            assert!(
                hexish.len() < 16 || !hexish.chars().all(|c| c.is_ascii_hexdigit()),
                "an alert is shown on a lock screen and must carry no identifier: {text}"
            );
        }
    }
    use crate::spend_audit::{
        kinds, Asset, Authority, FailureStage, FundingCoinId, SpendIntent, SpendJournal, SpendKind,
        Submission, TargetCoinId,
    };

    fn owner(seed: u8) -> Bytes32 {
        Bytes32::new([seed; 32])
    }

    /// The CAT wrapping is APPLIED, and it is applied around the owner — both halves.
    ///
    /// Two comparisons rather than one: against the bare owner hash, which catches a derivation that
    /// forgot to wrap; and between two different owners, which catches one that wraps a constant.
    /// Either mistake alone yields a puzzle hash that scans clean and finds nothing, and neither is
    /// visible from a single equality.
    #[test]
    fn the_operator_scan_hash_wraps_dig_around_this_owner_specifically() {
        let a = owner(0x11);
        let b = owner(0x22);
        assert_ne!(
            dig_cat_puzzle_hash(a),
            a,
            "an unwrapped owner hash holds XCH, and scanning it reports no $DIG at all"
        );
        assert_ne!(
            dig_cat_puzzle_hash(a),
            dig_cat_puzzle_hash(b),
            "two operators must not share a scan hash, or one would fund from the other's coins"
        );
        assert_eq!(
            dig_cat_puzzle_hash(a),
            CatArgs::curry_tree_hash(DIG_ASSET_ID, clvm_utils::TreeHash::from(a)).into(),
            "the canonical CAT curry, never a hand-rolled one"
        );
    }

    /// A create at zero collateral is refused before any coin is read.
    #[test]
    fn zero_collateral_is_refused_rather_than_selected_as_an_empty_set() {
        struct Unusable;
        impl ChainSource for Unusable {
            type Error = std::io::Error;
            fn coin_record(&self, _: Bytes32) -> Result<Option<_CoinRecord>, Self::Error> {
                unreachable!("no chain read may happen at zero collateral")
            }
            fn coin_records_by_puzzle_hash(
                &self,
                _: Bytes32,
                _: bool,
            ) -> Result<Vec<_CoinRecord>, Self::Error> {
                unreachable!("no chain read may happen at zero collateral")
            }
            fn coin_records_by_parent(&self, _: Bytes32) -> Result<Vec<_CoinRecord>, Self::Error> {
                unreachable!()
            }
            fn coin_spend(
                &self,
                _: Bytes32,
            ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
                unreachable!()
            }
            fn resolve_singleton_lineage(
                &self,
                _: Bytes32,
            ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error>
            {
                unreachable!()
            }
            fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
                unreachable!()
            }
            fn block_timestamp(&self, _: u32) -> Result<Option<u64>, Self::Error> {
                unreachable!()
            }
        }
        type _CoinRecord = dig_chainsource_interface::CoinRecord;

        assert_eq!(
            select_operator_dig_cats(&Unusable, owner(0x11), 0, &HashSet::new()),
            Err(FundingError::ZeroCollateral)
        );
    }

    /// **Proves:** a create needing more inputs than [`MAX_SELECTED_FUNDING_COINS`] is refused
    /// BEFORE any lineage read, and refused as `TooManyInputs` rather than as a shortfall.
    ///
    /// **Catches:** the unbounded selection of dig-node#427. The scan address is publicly derivable
    /// — the operator puzzle hash is public and the CAT curry is canonical — so any stranger can pay
    /// dust to it, and every input that survives selection costs one `coin_spend` in
    /// [`authenticate`]. Unbounded, the number of chain reads one automated pass performs is chosen
    /// by whoever sent the dust, on a timer, forever.
    ///
    /// # The fixture is built from the bound itself, from BOTH sides
    ///
    /// A single "lots of dust" case cannot tell a bound from a coincidence, and a case only over
    /// the limit cannot tell a correct bound from one that refuses everything. So the same wallet
    /// is asked for two amounts, chosen from `MAX_SELECTED_FUNDING_COINS` rather than picked to
    /// look large:
    ///
    /// - **at the bound** — exactly `MAX_SELECTED_FUNDING_COINS` coins cover it, and selection must
    ///   pass through to authentication (observable as a `coin_spend` having happened);
    /// - **one over** — one more coin is needed, and it must be refused with the count and the
    ///   limit, having read no lineage at all.
    ///
    /// The at-bound case is what makes this test load-bearing: `selected.len() >= LIMIT`, the
    /// off-by-one, is green against an over-only fixture and red here.
    ///
    /// `coin_spend` answers `Ok(None)` rather than panicking, so reaching authentication produces
    /// an ordinary `Unauthenticated` refusal. A panic would prove the same thing about the over
    /// case and make the at-bound case unable to report anything but a crash.
    #[test]
    fn a_create_needing_more_inputs_than_the_bound_is_refused_before_any_lineage_read() {
        use std::cell::RefCell;
        type _CoinRecord = dig_chainsource_interface::CoinRecord;

        /// A wallet whose $DIG is in `count` coins of one base unit each.
        struct Dusted {
            count: u64,
            owner: Bytes32,
            lineage_reads: RefCell<usize>,
        }

        impl ChainSource for Dusted {
            type Error = std::io::Error;
            fn coin_record(&self, _: Bytes32) -> Result<Option<_CoinRecord>, Self::Error> {
                unreachable!("selection reads by puzzle hash, never by coin id")
            }
            fn coin_records_by_puzzle_hash(
                &self,
                puzzle_hash: Bytes32,
                _: bool,
            ) -> Result<Vec<_CoinRecord>, Self::Error> {
                assert_eq!(
                    puzzle_hash,
                    dig_cat_puzzle_hash(self.owner),
                    "the scan must be the CAT-wrapped operator hash, which is what makes it \
                     publicly derivable and therefore dustable"
                );
                Ok((0..self.count)
                    .map(|i| {
                        let mut parent = [0u8; 32];
                        parent[..8].copy_from_slice(&i.to_be_bytes());
                        _CoinRecord {
                            coin: chia_protocol::Coin::new(Bytes32::new(parent), puzzle_hash, 1),
                            confirmed_height: Some(1),
                            spent_height: None,
                            timestamp: None,
                            coinbase: false,
                        }
                    })
                    .collect())
            }
            fn coin_records_by_parent(&self, _: Bytes32) -> Result<Vec<_CoinRecord>, Self::Error> {
                unreachable!()
            }
            fn coin_spend(
                &self,
                _: Bytes32,
            ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
                *self.lineage_reads.borrow_mut() += 1;
                Ok(None)
            }
            fn resolve_singleton_lineage(
                &self,
                _: Bytes32,
            ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error>
            {
                unreachable!()
            }
            fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
                unreachable!()
            }
            fn block_timestamp(&self, _: u32) -> Result<Option<u64>, Self::Error> {
                unreachable!()
            }
        }

        let owner = owner(0x33);
        let at_bound = MAX_SELECTED_FUNDING_COINS as u64;
        let over_bound = at_bound + 1;

        // Plenty of coins available either way: the wallet is NOT short, which is the whole point.
        let source = Dusted {
            count: over_bound + 10,
            owner,
            lineage_reads: RefCell::new(0),
        };

        let over = select_operator_dig_cats(&source, owner, over_bound, &HashSet::new());
        assert_eq!(
            over,
            Err(FundingError::TooManyInputs {
                needed: over_bound as usize,
                limit: MAX_SELECTED_FUNDING_COINS,
                have_dig_base_units: source.count,
                need_dig_base_units: over_bound,
            }),
            "a funded wallet whose $DIG is in too many pieces is refused for THAT reason; \
             reporting a shortfall would send the operator looking for money they already have"
        );
        assert_eq!(
            *source.lineage_reads.borrow(),
            0,
            "the refusal must happen before authentication, or the bound does not bound the chain \
             reads it exists to bound"
        );

        // The at-bound half asserts what it can now that dig-node#461 landed: an unauthenticatable
        // candidate is SKIPPED rather than aborting the selection, so this fixture -- in which
        // `coin_spend` answers `Ok(None)` for every coin -- can no longer come back
        // `Unauthenticated`. It walks the pool, skips all of it, and ends short. What still
        // discriminates the off-by-one is that the bound did NOT speak and that authentication WAS
        // reached: under `selected.len() >= LIMIT` this returns `TooManyInputs` having read no
        // lineage at all, and both assertions below go red.
        let at = select_operator_dig_cats(&source, owner, at_bound, &HashSet::new());
        assert!(
            !matches!(at, Err(FundingError::TooManyInputs { .. })),
            concat!(
                "exactly at the bound the selection must PASS THROUGH to authentication; it ",
                "refused with {:?} instead, so the bound is off by one and rejects a fundable ",
                "create"
            ),
            at
        );
        assert!(
            *source.lineage_reads.borrow() > 0,
            concat!(
                "reaching authentication is observed rather than assumed: no lineage read ",
                "happened, so the bound refused before the coins were ever examined"
            )
        );
    }

    /// An in-flight spend's funding coins are WITHHELD; a settled one's are released.
    ///
    /// The fixture varies ONE thing — the terminal status of the second spend — and keeps a truthful
    /// control: a `Confirmed` spend beside a `Submitted` one. A fixture in which every spend were
    /// in flight would read as the harsher case and is exactly the one that cannot show a release,
    /// because there would be nothing left to release.
    #[test]
    fn only_non_terminal_spends_withhold_their_funding_coins() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let journal = SpendJournal::new(log.clone());

        let in_flight = journal.begin(intent("in-flight"));
        journal.submitted(
            &in_flight,
            Submission {
                intended_coin_id: Some(TargetCoinId("aa".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("11".repeat(32))],
            },
        );

        let settled = journal.begin(intent("settled"));
        journal.submitted(
            &settled,
            Submission {
                intended_coin_id: Some(TargetCoinId("bb".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("22".repeat(32))],
            },
        );
        journal.confirmed(&settled, TargetCoinId("bb".repeat(32)), 100);

        let refused_before_signing = journal.begin(intent("never-signed"));
        journal.submitted(
            &refused_before_signing,
            Submission {
                intended_coin_id: Some(TargetCoinId("cc".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("33".repeat(32))],
            },
        );
        journal.failed(&refused_before_signing, FailureStage::Signing, "no key");

        let committed = committed_funding_coin_ids(&log).expect("readable");
        assert!(
            committed.contains(&"11".repeat(32)),
            "a submitted spend may still consume its coins, so they are withheld"
        );
        assert!(
            !committed.contains(&"22".repeat(32)),
            "a confirmed spend has settled; its coins are spent on chain and are not withheld twice"
        );
        assert!(
            !committed.contains(&"33".repeat(32)),
            "a failure BEFORE signing claims the money stayed put, so its coins are free again"
        );
        assert_eq!(committed.len(), 1);
    }

    /// A spend whose CREATED coin is underivable still withholds the coins it CONSUMED.
    ///
    /// This is the create path's shape: `sign_and_broadcast` passes `intended: None` because a
    /// mirror create's output coin takes its parent from whichever input the builder drew it from,
    /// which this node does not derive. The coins consumed are a different fact, read from the
    /// signed bundle, and are known.
    ///
    /// The fixture varies ONE thing — whether the target coin is derivable — and keeps a truthful
    /// control beside it: a reclaim-shaped spend that DOES name its target. The nearest wrong
    /// implementation is the one this replaced, which recorded a submission only when a target was
    /// derivable; it returns `{11…}` here, and a test carrying only the create would be unable to
    /// tell that from a completely broken reader returning nothing. Two entries are the minimum
    /// that distinguishes "creates are omitted" from "everything is omitted".
    #[test]
    fn a_spend_with_no_derivable_target_still_withholds_its_funding_coins() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let journal = SpendJournal::new(log.clone());

        let reclaim = journal.begin(intent("reclaim, target derivable"));
        journal.submitted(
            &reclaim,
            Submission {
                intended_coin_id: Some(TargetCoinId("aa".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("11".repeat(32))],
            },
        );

        let create = journal.begin(intent("create, target underivable"));
        journal.submitted(
            &create,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("22".repeat(32))],
            },
        );

        let committed = committed_funding_coin_ids(&log).expect("readable");
        assert!(
            committed.contains(&"22".repeat(32)),
            "the create consumed this coin; a second create in the same confirmation window must \
             not re-select it and broadcast a conflicting bundle"
        );
        assert!(
            committed.contains(&"11".repeat(32)),
            "the control: a derivable target was never what made a coin committed"
        );
        assert_eq!(committed.len(), 2);
    }

    /// An underivable target is recorded as UNKNOWN, never as a guessed coin.
    ///
    /// The companion to the test above, and the reason the two facts are recorded independently:
    /// making the create feed the reservation must not be paid for by inventing a target. A named
    /// coin here would let §23.5's reconcile confirm this spend against a coin it never created —
    /// the legacy defect `TargetCoinId` exists to make inexpressible — and would make
    /// `chain_reference()` offer an operator a coin id to look up that can never appear.
    #[test]
    fn recording_a_creates_funding_coins_does_not_invent_a_target_coin() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let journal = SpendJournal::new(log.clone());

        let create = journal.begin(intent("create, target underivable"));
        journal.submitted(
            &create,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: vec![FundingCoinId("22".repeat(32))],
            },
        );

        let ledger = log.ledger().expect("readable");
        let rec = ledger
            .records
            .iter()
            .find(|r| r.purpose == "create, target underivable")
            .expect("the create is on record");
        assert_eq!(
            rec.intended_coin_id, None,
            "this node cannot derive the created coin, so it names none"
        );
        assert!(
            rec.chain_reference().is_none(),
            "offering an operator a coin id to look up that can never exist is a chain claim the \
             node has not earned"
        );
        assert_eq!(
            rec.funding_coin_ids,
            vec![FundingCoinId("22".repeat(32))],
            "the consumed coins are known independently of the created one"
        );
    }

    /// A corrupt audit record REFUSES rather than reporting a smaller committed set.
    ///
    /// The discriminating fixture is a file with one GOOD line and one bad one: an implementation
    /// that skips unparseable lines returns a plausible non-empty set here and would pass a test
    /// that only checked "the good coin is present".
    #[test]
    fn an_unreadable_audit_record_refuses_rather_than_shrinking_the_reservation_set() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("spend-audit.jsonl");
        let log = SpendLog::at(path.clone());
        let journal = SpendJournal::new(log.clone());
        let spend = journal.begin(intent("in-flight"));
        journal.submitted(
            &spend,
            Submission {
                intended_coin_id: Some(TargetCoinId("aa".repeat(32))),
                funding_coin_ids: vec![FundingCoinId("11".repeat(32))],
            },
        );

        let mut text = std::fs::read_to_string(&path).expect("written");
        text.push_str("{ this is not a spend record\n");
        std::fs::write(&path, text).expect("rewritten");

        assert!(
            matches!(
                committed_funding_coin_ids(&log),
                Err(FundingError::CommitmentsUnreadable(_))
            ),
            "a lost line may be the one naming a committed coin; a silently smaller reservation \
             set is how one coin funds two bundles"
        );
    }

    /// A never-written audit record is an EMPTY commitment set, not a refusal.
    ///
    /// The ordinary case for a node that has never spent automatically. Refusing here would make
    /// the very first create on every node impossible.
    #[test]
    fn a_node_that_has_never_spent_commits_nothing() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        assert_eq!(
            committed_funding_coin_ids(&log).expect("a missing file is an empty record"),
            HashSet::new()
        );
    }

    fn intent(purpose: &str) -> SpendIntent {
        SpendIntent {
            kind: SpendKind::new(kinds::MIRROR_COIN),
            purpose: purpose.to_string(),
            authority: Authority {
                principal: "node".into(),
                grant: "test".into(),
            },
            asset: Asset::Dig,
            amount_mojos: 1_000,
            fee_mojos: 0,
            store_id: None,
            bond: None,
        }
    }
}
