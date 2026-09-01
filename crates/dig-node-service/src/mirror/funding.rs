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
    /// The authentication budget ran out before the requirement was covered, so how much the
    /// operator can spend is UNKNOWN.
    ///
    /// Carries no total, deliberately. Every other refusal here can state one because it walked the
    /// whole candidate pool; this one stopped early, so any total it quoted would be the total of a
    /// truncated walk — understated by an amount chosen by whoever paid the coins that consumed the
    /// budget. An understated total sends an operator to buy $DIG they already hold, and
    /// `grew_materially` then suppresses the correction, so silence about the amount is the only
    /// honest option (dig-node#469).
    CandidatesUnverifiable {
        /// How many candidates were authenticated before the budget ran out.
        attempted: usize,
        /// How many of those could not be proven spendable.
        skipped: usize,
        /// The margined requirement that was not reached, in $DIG base units.
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
                 ({reason}), so it was passed over"
            ),
            FundingError::CandidatesUnverifiable {
                attempted,
                skipped,
                need_dig_base_units,
            } => write!(
                f,
                "the operator address holds more coins than one pass may authenticate: \
                 {attempted} were checked and {skipped} could not be proven spendable, without \
                 reaching the {need_dig_base_units} DIG base units this create needs. How much \
                 the operator can spend is UNKNOWN, not low; no spend was attempted"
            ),
            FundingError::CommitmentsUnreadable(e) => write!(
                f,
                "the spend audit record is unreadable ({e}), so which coins are already committed \
                 to an in-flight bundle is unknown; no coin is selected"
            ),
            FundingError::TooManyInputs { needed, limit, .. } => write!(
                f,
                "covering this create needs {needed} authenticated $DIG coins and a mirror create \
                 may draw at most {limit}; the wallet is not short, its $DIG is in too many \
                 pieces. No spend was attempted; consolidating the operator's $DIG into fewer \
                 coins clears it"
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
/// The refusal happens over the AUTHENTICATED candidates only, and never over the raw scan. The
/// scan address is public, so the count of rows at it is chosen by whoever last paid a coin to it;
/// a bound applied to that count is a bound an attacker sets, and the refusal it produces is an
/// operator-facing money statement (`FundingRemedy::Consolidate`) that the same attacker therefore
/// chooses. Authentication is what turns a row into one of this operator's coins, so it runs first
/// and the bound is applied to what survives it (dig-node#469).
///
/// The per-pass chain reads that ordering could otherwise cost are bounded separately and
/// explicitly, by [`MAX_AUTHENTICATION_ATTEMPTS`] — a constant, rather than a function of how many
/// coins a stranger sent.
///
/// UNMEASURED JUDGEMENT, stated so nobody reads it as a derived limit: nobody has measured how many
/// $DIG coins a real operator wallet holds. 32 is chosen to bound the inputs one bundle draws, and
/// if a legitimate wallet routinely exceeds it this fails CLOSED on that operator -- they see
/// `TooManyInputs` and consolidate, rather than a spend going wrong.
pub const MAX_SELECTED_FUNDING_COINS: usize = 32;

/// The most candidates one selection may authenticate — the per-pass chain-read bound
/// (dig-node#469).
///
/// # Why the input bound cannot serve as this bound
///
/// [`MAX_SELECTED_FUNDING_COINS`] bounds how many coins one bundle SPENDS. It says nothing about
/// how many were examined to find them, and the two diverge exactly under attack: a stranger who
/// pays N coins into the publicly derivable operator address adds N candidates that must each be
/// authenticated — one chain round trip apiece — while contributing nothing to any selection. The
/// input bound is unreached the whole time, because the coins that fail authentication never enter
/// a selection at all.
///
/// So the read count was previously a function of N, which is attacker-chosen and unbounded, and
/// the pass body runs under `tokio::task::block_in_place` — a worker is held for the whole walk and
/// the next pass cannot start inside it.
///
/// # Why a constant, and why this one
///
/// A constant is the property that matters: whatever a stranger pays into the address, one
/// SELECTION costs at most this many reads.
///
/// **Per selection, not per pass, and the difference is not cosmetic (dig-node#469).** `create` is
/// called once per bond (`lifecycle::NodeMirrorEffects::create`), each with its own budget, so a
/// pass planning K creates costs up to K x this many reads. The create loop breaks on the first
/// FAILURE, which bounds a pass that cannot fund itself to one selection — but it does not bound
/// the case that matters here: a stranger who plants `MAX_AUTHENTICATION_ATTEMPTS - 1` coins
/// ranked above the honest ones leaves every create still SUCCEEDING, so nothing breaks, while each
/// one pays the full wasted walk, on the pass timer, indefinitely, from a one-time dust spend.
///
/// That is amplification of a bounded factor rather than an unbounded one — K is the node's own
/// bond count, not an attacker's choice — so it is recorded here rather than silently untrue, and a
/// per-PASS budget shared across the create loop is filed as follow-up rather than taken inside
/// this change.
///
/// 128 is four times the input bound, so a wallet fragmented right
/// up to the point where [`FundingError::TooManyInputs`] is the correct answer still reaches that
/// answer with room for noise, while a wallet with nothing planted in it never comes close — the
/// walk stops the moment the requirement is covered, so a healthy pass pays for the coins it
/// spends and not for this bound.
///
/// # Which direction it fails in
///
/// CLOSED, and silently about the AMOUNT but not about the condition. Exhausting the budget yields
/// [`FundingError::CandidatesUnverifiable`], which states no total and maps to
/// [`FundingObservation::Unmeasured`] — so the pass quotes no figure and clears no live shortfall,
/// and it does tell the operator once that the walk was truncated. That is the honest reading: the
/// walk stopped early, so the wallet was not measured, and an operator whose node has stopped
/// bonding needs to hear that even when no number can be attached to it. An attacker who buries the
/// honest coins under 128 larger unauthenticatable ones can stop this node bonding, which is a
/// denial of service and is reported as one; what they cannot do is make the node tell its operator
/// something false about their money, or keep it quiet about the stoppage (dig-node#469).
pub const MAX_AUTHENTICATION_ATTEMPTS: usize = 128;

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
/// * **A skip costs no selection budget.** Candidates are authenticated BEFORE anything is
///   selected, so a candidate that fails is never in a selection, never occupies an input slot and
///   never contributes to a total. An attacker who could spend an input slot per dust coin would
///   reinstate the same denial in a slower form.
///
/// A chain that cannot ANSWER is still fatal, and deliberately so: an unreadable source is not a
/// verdict about a coin, and treating it as one would silently shrink the wallet.
///
/// # Authentication comes FIRST, and is itself bounded (dig-node#469)
///
/// Two figures leave this function and become sentences shown to an operator: the total they are
/// told they can spend, and whether their money is merely in too many pieces. Both were previously
/// computed over the raw scan — a set of rows at a PUBLIC puzzle hash, whose size and whose
/// declared amounts are chosen by whoever paid the last coin into it. So an attacker chose which of
/// two opposite instructions the operator was given, and could tell an operator holding nothing
/// that they held enough and that adding more would not help.
///
/// The order is therefore: authenticate, then decide. Every candidate that reaches a total, a
/// selection or the input bound has had its creating spend executed and its lineage matched, so
/// every figure this function reports is a figure about this operator's own coins.
///
/// That ordering moves the cost, so the cost is bounded in its own right.
/// [`MAX_AUTHENTICATION_ATTEMPTS`] caps the chain reads one call may make, and the walk stops as
/// soon as the authenticated total covers the requirement — so a funded wallet pays for the coins
/// it spends and nothing more, and an unfunded one pays a constant. A cheap pre-filter on the
/// candidate set would have bounded the work while leaving both figures attacker-chosen, which is
/// the half of the defect that is a money lie rather than a cost.
///
/// When the cap is reached with the requirement still uncovered, this refuses with
/// [`FundingError::CandidatesUnverifiable`] and states NO total, because it does not have one:
/// coins remain unexamined, and a figure computed from a truncated walk is exactly the understated
/// total this ordering exists to remove.
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

    // Walked largest-first, the same order `select_largest_first` selects in, so the coins
    // authenticated are the coins a covering selection would draw and the walk can stop the moment
    // the requirement is covered.
    pool.sort_by(|a, b| {
        b.coin
            .amount
            .cmp(&a.coin.amount)
            .then_with(|| a.coin.coin_id().cmp(&b.coin.coin_id()))
    });

    let mut authenticated: Vec<(dig_chainsource_interface::CoinRecord, Cat)> = Vec::new();
    let mut authenticated_total: u64 = 0;
    let mut skipped: Vec<SkippedCandidate> = Vec::new();
    let mut attempts: usize = 0;
    let mut walked_whole_pool = true;

    for record in &pool {
        // Enough of this operator's own money is proven spendable. Every further authentication is
        // a chain read that cannot change the answer.
        if authenticated_total >= need_dig_base_units {
            break;
        }
        if attempts >= MAX_AUTHENTICATION_ATTEMPTS {
            walked_whole_pool = false;
            break;
        }
        attempts += 1;
        match authenticate(source, record, owner_puzzle_hash) {
            Ok(cat) => {
                authenticated_total = authenticated_total.saturating_add(record.coin.amount);
                authenticated.push((record.clone(), cat));
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
            }
            // A source that cannot answer is not a verdict about the coin.
            Err(fatal) => return Err(fatal),
        }
    }

    // The walk was truncated and the requirement is uncovered, so the honest total is UNKNOWN
    // rather than low. Refused as its own condition, which reports no amount at all — see the note
    // above on why an understated total is worse than silence.
    if !walked_whole_pool && authenticated_total < need_dig_base_units {
        return Err(FundingError::CandidatesUnverifiable {
            attempted: attempts,
            skipped: skipped.len(),
            need_dig_base_units,
        });
    }

    // From here every input is an authenticated coin of this operator, so both figures below are
    // statements about this operator's own money.
    let cats = select_within_input_bound(
        authenticated
            .into_iter()
            .map(|(record, cat)| (record.coin.amount, record.coin.coin_id(), cat))
            .collect(),
        need_dig_base_units,
    )?;

    Ok(FundingSelection { cats, skipped })
}

/// Cover `need_dig_base_units` from AUTHENTICATED coins, or refuse with the reason and the amount.
///
/// Split out from [`select_operator_dig_cats_detailed`] because it is where both operator-facing
/// money figures are decided — the total in [`FundingError::Insufficient`] and the *you have enough,
/// it is in too many pieces* of [`FundingError::TooManyInputs`] — and because the caller's
/// authenticated coins cannot be fabricated in a test. A [`Cat`] is only produced by executing a
/// real lineage, so a test driving the whole function can only ever supply candidates that FAIL
/// authentication, and the bound would then be provable from one side and by accident.
///
/// The input is `(amount, coin_id, payload)` per coin, already proven spendable by the caller.
/// Nothing here re-checks that, and nothing here reads the chain: the ordering that makes these
/// figures honest is the caller's, and this function's job is only to state them.
fn select_within_input_bound<T>(
    authenticated: Vec<(u64, Bytes32, T)>,
    need_dig_base_units: u64,
) -> Result<Vec<T>, FundingError> {
    let authenticated_total = authenticated
        .iter()
        .fold(0u64, |sum, (amount, _, _)| sum.saturating_add(*amount));

    let selected = select_largest_first(authenticated, need_dig_base_units, |(amount, id, _)| {
        (*amount, *id)
    })
    .map_err(|shortfall| FundingError::Insufficient {
        // Every coin the chain would prove has been offered, so this is what the operator can
        // actually spend rather than what the address happens to hold.
        have_dig_base_units: shortfall.have,
        need_dig_base_units,
    })?;

    if selected.len() > MAX_SELECTED_FUNDING_COINS {
        return Err(FundingError::TooManyInputs {
            needed: selected.len(),
            limit: MAX_SELECTED_FUNDING_COINS,
            have_dig_base_units: authenticated_total,
            need_dig_base_units,
        });
    }

    Ok(selected
        .into_iter()
        .map(|(_, _, payload)| payload)
        .collect())
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
    /// The action this alert is asking for, or `None` when no single action is being claimed —
    /// a recovery, or a blocked pass whose remedy is not established (see [`unmeasured_alert`]).
    pub remedy: Option<FundingRemedy>,
}

/// Why a pass knows bonding is blocked but cannot say by how much (dig-node#469).
///
/// # Why this is a shape of its own rather than an amount of zero, or silence
///
/// Two conditions stop this node bonding without ever producing an AUTHENTICATED total, and each
/// used to resolve to one of the two available lies:
///
/// * quoting the figure that WAS available — the unauthenticated address total, which a stranger
///   chooses by paying a coin into the publicly derivable scan address, understating the deficit
///   and then having [`FundingAlertGate`] suppress the correction as immaterial; or
/// * saying nothing at all, which leaves an operator whose node has silently stopped bonding with
///   no message on any pass, forever.
///
/// The truthful third answer is to name the condition and NOT the amount. So an `Unmeasured`
/// observation alerts once on entry, quotes no spendable total, and — like
/// [`FundingObservation::Unknown`] — never clears a live shortfall, because a pass that could not
/// measure the wallet is not evidence that the wallet recovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmeasuredFunding {
    /// The pass priced a create and could afford none of them, so no candidate was ever
    /// authenticated.
    ///
    /// The SHORT classification is sound even though the amount is not: authentication can only
    /// ever REMOVE candidates, so the authenticated total is at most the reported one, and a
    /// reported total below one create's cost proves the real one is too. What it does not prove
    /// is the size of the gap — which is the figure an operator would act on.
    NoCreateAffordable {
        /// What one create needs, in $DIG base units. Derived from the epoch requirement and the
        /// plan, never from the wallet, so it is a figure no stranger can move.
        need_dig_base_units: u64,
    },
    /// The authentication walk hit [`MAX_AUTHENTICATION_ATTEMPTS`] before covering the requirement.
    AuthenticationTruncated {
        /// How many candidates were authenticated before the budget ran out.
        attempted: usize,
        /// How many of those could not be proven spendable.
        skipped: usize,
    },
}

/// What one mirror pass observed about funding — the input the alert gate decides on.
///
/// A pass that could not READ the balance is not a pass that found it short: reporting a shortfall
/// on no evidence is precisely the money lie this crate refuses elsewhere, so the caller maps an
/// unreadable balance to [`FundingObservation::Unknown`], which never alerts and never clears the
/// state either. [`FundingObservation::Unmeasured`] sits between the two — bonding is known to be
/// blocked, and by how much is not.
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
    /// Bonding is blocked and the amount is not established. See [`UnmeasuredFunding`].
    Unmeasured(UnmeasuredFunding),
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
            // A truncated walk is not a measurement of the wallet. `Short` would have to quote a
            // total, and the only total available is the one from the coins that happened to be
            // walked -- understated by however many the budget did not reach. Reporting it would
            // send an operator to buy $DIG they already hold, and `grew_materially` would then
            // suppress the correction.
            //
            // But saying nothing about the AMOUNT and saying nothing AT ALL are different, and the
            // second is its own money lie by omission (dig-node#469): a stranger who buries the
            // honest coins under `MAX_AUTHENTICATION_ATTEMPTS` larger unauthenticatable ones stops
            // this node bonding on every pass, indefinitely, and the operator is never told. Worse,
            // it is the state a latched understated shortfall would never be corrected out of. So
            // this speaks -- once, naming the truncation and quoting no total -- and still clears
            // nothing.
            FundingError::CandidatesUnverifiable {
                attempted,
                skipped,
                ..
            } => {
                FundingObservation::Unmeasured(UnmeasuredFunding::AuthenticationTruncated {
                    attempted: *attempted,
                    skipped: *skipped,
                })
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
/// * **Once on entering an [`FundingObservation::Unmeasured`] state**, which names the condition
///   and no amount. It is latched separately from the short state and CLEARS neither it nor
///   itself, because a pass that could not measure the wallet is not evidence of recovery.
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
    /// The unmeasured condition last alerted on, or `None` while not in one.
    ///
    /// Separate from `alerted` because the two are not alternatives: a wallet can be latched short
    /// on an authenticated figure AND then become unmeasurable, and that transition is exactly the
    /// one an operator must hear about — it is the pass on which the correction they were waiting
    /// for stops being possible.
    unmeasured: Option<UnmeasuredFunding>,
}

/// How much a deficit must grow, in percent of the last alerted deficit, to speak again.
///
/// 50% rather than a few percent: this fires while an operator has already been told, and the
/// question it answers is "has this become a materially different problem", not "has the number
/// moved". A small threshold turns a slowly worsening shortfall back into the per-pass stream this
/// gate exists to prevent.
pub const MATERIAL_DEFICIT_GROWTH_PERCENT: u64 = 50;

impl FundingAlertGate {
    /// Drop every blocked state and announce the recovery, if the node was in one.
    ///
    /// Both latches clear together because a funded pass is evidence about the wallet as a whole:
    /// the walk completed and the money was there, which is the answer to a truncated walk as much
    /// as to a plain shortfall.
    fn clear_and_announce_recovery(&mut self) -> Option<FundingAlert> {
        // Both takes run before the test: `||` would short-circuit and leave the second latch set,
        // which would swallow the next alert about a condition that has in fact just ended.
        let was_short = self.alerted.take().is_some();
        let was_unmeasured = self.unmeasured.take().is_some();
        (was_short || was_unmeasured).then(|| FundingAlert {
            title: "DIG mirror collateral resumed".into(),
            body: concat!(
                "The operator wallet can fund mirror collateral again. Your content is being ",
                "bonded on the next pass."
            )
            .into(),
            remedy: None,
        })
    }

    /// Feed one pass's observation, and get back the alert to raise — or nothing.
    pub fn observe(&mut self, observation: &FundingObservation) -> Option<FundingAlert> {
        match observation {
            FundingObservation::Unknown => None,
            // Once per entry. Consecutive unmeasured passes are the attacker's steady state, so a
            // per-pass message would be 144 a day; a single one that stays true is the signal.
            FundingObservation::Unmeasured(reason) => {
                if self.unmeasured == Some(*reason) {
                    return None;
                }
                self.unmeasured = Some(*reason);
                Some(unmeasured_alert(*reason))
            }
            FundingObservation::Healthy => self.clear_and_announce_recovery(),
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

/// The operator-facing text for a blocked pass whose amount is not established (dig-node#469).
///
/// # The one rule this text obeys
///
/// It states no spendable total and no deficit, because neither is known — and it says so, rather
/// than leaving an operator to infer an amount from a message that mentions none. A figure here
/// would be the address total or a truncated walk's total, both of which a stranger chooses.
///
/// It still names an action, because "your node has stopped bonding and we cannot tell you why in
/// numbers" is not something an operator can do anything with. Both conditions are cleared by the
/// same thing — enough of the operator's OWN, spendable $DIG at the operator wallet — so both ask
/// for that, and the truncated case adds the fact that the address is carrying coins that are not
/// theirs, which is what a consolidation into a fresh wallet would resolve.
fn unmeasured_alert(reason: UnmeasuredFunding) -> FundingAlert {
    let body = match reason {
        UnmeasuredFunding::NoCreateAffordable {
            need_dig_base_units,
        } => format!(
            concat!(
                "Your node cannot bond content: it needs {} DIG of collateral for this epoch and ",
                "the operator wallet could not fund one. How much of the wallet's $DIG is ",
                "actually spendable has not been established this pass, so no figure for the ",
                "shortfall is given. Add $DIG to the operator wallet. Until then no new content ",
                "is collateralised and it earns nothing."
            ),
            whole_dig(need_dig_base_units)
        ),
        UnmeasuredFunding::AuthenticationTruncated { attempted, skipped } => format!(
            concat!(
                "Your node cannot bond content: the operator address holds more coins than one ",
                "pass may check, and {attempted} were checked with {skipped} of them not ",
                "provably yours before the budget ran out. How much the wallet can spend is ",
                "UNKNOWN, not low, so no figure is given — and adding $DIG may not clear it. ",
                "Consolidate the operator wallet's own $DIG into fewer coins. Until then no new ",
                "content is collateralised and it earns nothing."
            ),
            attempted = attempted,
            skipped = skipped
        ),
    };
    FundingAlert {
        title: "DIG node cannot bond content".into(),
        body,
        // No remedy is claimed for the truncated case beyond the body's own words: `TopUp` would be
        // the wrong instruction (adding money need not help) and `Consolidate` asserts the wallet
        // holds enough, which is exactly what was not established. `NoCreateAffordable` does know
        // the direction — the wallet could not fund one create — so it names `TopUp`.
        remedy: match reason {
            UnmeasuredFunding::NoCreateAffordable { .. } => Some(FundingRemedy::TopUp),
            UnmeasuredFunding::AuthenticationTruncated { .. } => None,
        },
    }
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

    /// A wallet at the operator's $DIG address, whose coins never authenticate.
    ///
    /// Every candidate a test can build is one that FAILS authentication — `coin_spend` answers
    /// `Ok(None)`, so no lineage resolves — and that is not a limitation of the fixture but of what
    /// a coin IS: a `Cat` exists only once a real creating spend has been executed against it. That
    /// is exactly the population an attacker supplies, so it is the right fixture for what a
    /// stranger's coins are worth; the honest side of every claim below is asserted separately
    /// against [`select_within_input_bound`], which takes authenticated coins directly.
    struct Planted {
        /// How many coins sit at the address.
        count: u64,
        /// What each one declares.
        amount: u64,
        owner: Bytes32,
        /// Every `coin_spend` this source was asked for — the per-pass chain-read count.
        lineage_reads: std::cell::RefCell<usize>,
    }

    impl Planted {
        fn new(count: u64, amount: u64, owner: Bytes32) -> Self {
            Planted {
                count,
                amount,
                owner,
                lineage_reads: std::cell::RefCell::new(0),
            }
        }

        fn reads(&self) -> usize {
            *self.lineage_reads.borrow()
        }
    }

    impl ChainSource for Planted {
        type Error = std::io::Error;
        fn coin_record(
            &self,
            _: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::CoinRecord>, Self::Error> {
            unreachable!("selection reads by puzzle hash, never by coin id")
        }
        fn coin_records_by_puzzle_hash(
            &self,
            puzzle_hash: Bytes32,
            _: bool,
        ) -> Result<Vec<dig_chainsource_interface::CoinRecord>, Self::Error> {
            assert_eq!(
                puzzle_hash,
                dig_cat_puzzle_hash(self.owner),
                "the scan must be the CAT-wrapped operator hash, which is what makes it publicly \
                 derivable and therefore plantable"
            );
            Ok((0..self.count)
                .map(|i| {
                    let mut parent = [0u8; 32];
                    parent[..8].copy_from_slice(&i.to_be_bytes());
                    dig_chainsource_interface::CoinRecord {
                        coin: chia_protocol::Coin::new(
                            Bytes32::new(parent),
                            puzzle_hash,
                            self.amount,
                        ),
                        confirmed_height: Some(1),
                        spent_height: None,
                        timestamp: None,
                        coinbase: false,
                    }
                })
                .collect())
        }
        fn coin_records_by_parent(
            &self,
            _: Bytes32,
        ) -> Result<Vec<dig_chainsource_interface::CoinRecord>, Self::Error> {
            unreachable!()
        }
        fn coin_spend(&self, _: Bytes32) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            *self.lineage_reads.borrow_mut() += 1;
            Ok(None)
        }
        fn resolve_singleton_lineage(
            &self,
            _: Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            unreachable!()
        }
        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            unreachable!()
        }
        fn block_timestamp(&self, _: u32) -> Result<Option<u64>, Self::Error> {
            unreachable!()
        }
    }

    /// An authenticated coin for [`select_within_input_bound`], identified by its amount.
    ///
    /// The payload is the amount rather than a `Cat`, because the bound and the totals are decided
    /// on `(amount, coin_id)` alone and a real `Cat` would add nothing an assertion could read.
    fn proven(amount: u64, tag: u8) -> (u64, Bytes32, u64) {
        let mut id = [0u8; 32];
        id[0] = tag;
        id[1..9].copy_from_slice(&amount.to_be_bytes());
        (amount, Bytes32::new(id), amount)
    }

    /// **Proves:** the input bound is decided over AUTHENTICATED coins, from both sides of the
    /// limit, and the total it quotes is theirs.
    ///
    /// **Catches:** the off-by-one (`>=` for `>`), which refuses a create that exactly fits and
    /// sends a fundable operator to consolidate a wallet that needs nothing done to it.
    ///
    /// # Why this is asserted here and not through the whole selection (dig-node#469)
    ///
    /// It used to be driven through `select_operator_dig_cats` over a wallet of unauthenticatable
    /// dust, which is precisely the shape the bound must no longer respond to — a stranger's coins
    /// are not this operator's money, so they cannot make the node say *you have enough*. Driving
    /// the bound through candidates that fail authentication could only ever prove the defect.
    ///
    /// The fixture is built FROM the bound: exactly `MAX_SELECTED_FUNDING_COINS` coins must pass,
    /// and one more must be refused with the count, the limit, and the operator's real total. An
    /// over-only fixture is green against the off-by-one; the at-bound half is what discriminates.
    #[test]
    fn the_input_bound_is_decided_over_authenticated_coins_and_holds_from_both_sides() {
        let at_bound = MAX_SELECTED_FUNDING_COINS;
        let over_bound = at_bound + 1;

        // One base unit each, so covering N base units takes exactly N coins.
        let coins =
            |n: usize| -> Vec<(u64, Bytes32, u64)> { (0..n).map(|i| proven(1, i as u8)).collect() };

        let at = select_within_input_bound(coins(at_bound), at_bound as u64);
        assert_eq!(
            at.as_deref().map(<[u64]>::len),
            Ok(at_bound),
            concat!(
                "a create that exactly fits the bound must be funded; refusing it sends an ",
                "operator to consolidate a wallet that is already spendable"
            )
        );

        let over = select_within_input_bound(coins(over_bound), over_bound as u64);
        assert_eq!(
            over.err(),
            Some(FundingError::TooManyInputs {
                needed: over_bound,
                limit: MAX_SELECTED_FUNDING_COINS,
                have_dig_base_units: over_bound as u64,
                need_dig_base_units: over_bound as u64,
            }),
            "one coin over the bound is refused for the SHAPE of the cover, quoting the total the \
             operator genuinely holds"
        );
    }

    /// **Proves:** an operator holding nothing is never told they hold enough, however many coins a
    /// stranger pays into their publicly derivable $DIG address.
    ///
    /// **Catches:** the dig-node#469 finding 1 — the input bound returning BEFORE authentication
    /// began, so a selection composed entirely of unchecked coins produced
    /// [`FundingRemedy::Consolidate`] and the message *"the operator wallet holds enough $DIG …
    /// adding more will not help"*. An attacker paying 33 small coins to an address anyone can
    /// derive chose which of two OPPOSITE instructions the operator was given, and the state does
    /// not converge: no planted coin is ever authenticated, so none is ever removed, so the same
    /// wrong message is the answer on every pass forever.
    ///
    /// # The fixture varies ONE actor and keeps a truthful control
    ///
    /// Two wallets are asked the same question: one with nothing at the address at all, and one
    /// with `MAX_SELECTED_FUNDING_COINS + 1` planted coins. The operator's own holdings are
    /// identical — nothing — in both, so the ONLY difference is what a stranger did, and the
    /// assertion is that it made no difference to what the operator is told. An assertion that the
    /// planted case merely "is not `TooManyInputs`" would also pass on an implementation that
    /// refused everything; requiring the two to AGREE pins the property to the stranger's coins
    /// being worth exactly zero rather than to a blanket refusal.
    #[test]
    fn coins_a_stranger_planted_never_become_a_statement_about_the_operators_money() {
        let owner = owner(0x44);
        // One base unit each and a requirement of one more than the bound, so covering it takes
        // more coins than a bundle may draw -- the exact shape that produced `Consolidate`.
        let need = MAX_SELECTED_FUNDING_COINS as u64 + 1;

        let planted = Planted::new(need, 1, owner);
        let refusal = select_operator_dig_cats(&planted, owner, need, &HashSet::new())
            .expect_err("no coin here is spendable by this operator");

        let empty = Planted::new(0, 1, owner);
        let control = select_operator_dig_cats(&empty, owner, need, &HashSet::new())
            .expect_err("an empty address funds nothing");

        assert_eq!(
            refusal, control,
            concat!(
                "a stranger changed what this node tells its operator about their own money; ",
                "the planted address must be worth exactly what the empty one is"
            )
        );
        assert_eq!(
            refusal,
            FundingError::Insufficient {
                have_dig_base_units: 0,
                need_dig_base_units: need,
            },
            "and the truthful answer is that the operator can spend nothing"
        );
        assert_eq!(
            FundingObservation::from_error(&refusal),
            FundingObservation::Short {
                have_dig_base_units: 0,
                need_dig_base_units: need,
                remedy: FundingRemedy::TopUp,
            },
            concat!(
                "the operator must be sent to ADD $DIG; `Consolidate` here tells someone holding ",
                "nothing that adding more will not help, and it is an attacker who chose it"
            )
        );
        assert!(
            planted.reads() > 0,
            concat!(
                "every planted coin must be authenticated and rejected; a refusal reached without ",
                "reading any lineage is a verdict about rows a stranger wrote"
            )
        );
    }

    /// **Proves:** the reported spendable total counts only coins the chain PROVED, never the
    /// address total.
    ///
    /// **Catches:** the dig-node#469 finding 4 — `available` summed the pool at the top of the
    /// iteration, before anything in it was authenticated, so the first-iteration shortfall (the
    /// ordinary case) quoted what the address held. An operator who adds the amount they were told
    /// is still short, and `grew_materially` then suppresses the correction, so the node goes quiet
    /// while they believe they fixed it.
    ///
    /// # Both directions, because one alone is satisfiable by a constant
    ///
    /// The planted half asserts an address total of 30,000 base units reports ZERO, which is red
    /// against the old arithmetic. On its own it is also green against an implementation that
    /// always reports zero — so the honest half asserts, over the same figures, that authenticated
    /// coins totalling 20,000 report 20,000. Together they pin the total to the authenticated set.
    #[test]
    fn the_reported_total_is_what_the_chain_proved_not_what_the_address_holds() {
        let owner = owner(0x55);
        let need = 40_000;

        // Three coins of 10,000 at the address, none of them this operator's.
        let planted = Planted::new(3, 10_000, owner);
        assert_eq!(
            select_operator_dig_cats(&planted, owner, need, &HashSet::new()).err(),
            Some(FundingError::Insufficient {
                have_dig_base_units: 0,
                need_dig_base_units: need,
            }),
            concat!(
                "the address total was reported as the operator's spendable total; they would be ",
                "told to add 10,000 when they are 40,000 short, and the correction is then ",
                "suppressed as immaterial"
            )
        );
        assert_eq!(
            planted.reads(),
            3,
            "the honest total is established by reading, not by summing rows"
        );

        // The same shortfall with coins that ARE the operator's: the figure must be theirs.
        assert_eq!(
            select_within_input_bound(vec![proven(10_000, 1), proven(10_000, 2)], need).err(),
            Some(FundingError::Insufficient {
                have_dig_base_units: 20_000,
                need_dig_base_units: need,
            }),
            "a proven 20,000 must be reported as 20,000, or the total is a constant rather than a \
             measurement"
        );
    }

    /// **Proves:** the chain reads one selection performs are bounded by a CONSTANT, whatever a
    /// stranger pays into the address.
    ///
    /// **Catches:** the dig-node#469 finding 3 — one network round trip per planted coin, per pass,
    /// forever. Measured on the pre-fix tree at 11, 51 and 201 reads for 10, 50 and 200 planted
    /// coins: linear in an attacker-chosen number, on a ten-minute timer, under
    /// `tokio::task::block_in_place` so the worker is held for the whole walk.
    ///
    /// # Two sizes, because one cannot tell a bound from a coincidence
    ///
    /// The pool is grown well past [`MAX_AUTHENTICATION_ATTEMPTS`] and then DOUBLED. A single large
    /// fixture is green against any limit at or above it; requiring the two counts to be EQUAL is
    /// what distinguishes a bound from a fixture that merely did not reach one.
    ///
    /// The refusal is asserted too. Exhausting the budget leaves the wallet unmeasured, so it must
    /// state no total and must classify as [`FundingObservation::Unmeasured`] — an amount taken
    /// from a truncated walk is the understated total this whole ordering exists to remove, and it
    /// would raise a wrong alert AND suppress the right one. It must NOT classify as
    /// [`FundingObservation::Unknown`] either, which alerts on nothing: that left an operator whose
    /// node had permanently stopped bonding with no message on any surface.
    #[test]
    fn authentication_is_bounded_by_a_constant_however_many_coins_a_stranger_sends() {
        let owner = owner(0x66);
        let planted_count = (MAX_AUTHENTICATION_ATTEMPTS * 2) as u64;
        let need = planted_count;

        let smaller = Planted::new(planted_count, 1, owner);
        let refusal = select_operator_dig_cats(&smaller, owner, need, &HashSet::new())
            .expect_err("nothing here is spendable");

        let larger = Planted::new(planted_count * 2, 1, owner);
        let _ = select_operator_dig_cats(&larger, owner, need, &HashSet::new())
            .expect_err("nothing here is spendable");

        assert_eq!(
            smaller.reads(),
            MAX_AUTHENTICATION_ATTEMPTS,
            "one pass must never read more than the budget"
        );
        assert_eq!(
            larger.reads(),
            smaller.reads(),
            concat!(
                "doubling what a stranger planted doubled the chain reads, so the cost of one ",
                "pass is still chosen by the attacker rather than by this node"
            )
        );

        assert_eq!(
            refusal,
            FundingError::CandidatesUnverifiable {
                attempted: MAX_AUTHENTICATION_ATTEMPTS,
                skipped: MAX_AUTHENTICATION_ATTEMPTS,
                need_dig_base_units: need,
            },
            "a truncated walk refuses as itself, stating no total"
        );
        assert_eq!(
            FundingObservation::from_error(&refusal),
            FundingObservation::Unmeasured(UnmeasuredFunding::AuthenticationTruncated {
                attempted: MAX_AUTHENTICATION_ATTEMPTS,
                skipped: MAX_AUTHENTICATION_ATTEMPTS,
            }),
            concat!(
                "an unmeasured wallet must not quote a total and must not clear a live shortfall ",
                "-- and must not be SILENT either, which is what `Unknown` here meant: a node ",
                "stopped from bonding indefinitely, with no message on any surface"
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
