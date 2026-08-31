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
            FundingError::TooManyInputs { needed, limit } => write!(
                f,
                "covering this create needs {needed} $DIG coins and a mirror create may draw at                  most {limit}; the wallet is not short, its $DIG is in too many pieces. No coin                  was authenticated and no spend was attempted; consolidating the operator's $DIG                  into fewer coins clears it"
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

/// Select spendable $DIG `Cat`s of the OPERATOR wallet covering `need_dig_base_units`.
///
/// `need_dig_base_units` is $DIG in base units (1 DIG = 1_000, never mojos) and is the epoch's
/// derived requirement — `apply_safety_margin(required_per_store, margin_bp)`, `SPEC.md` §25.3 —
/// carried in from the planner. Nothing here re-derives it: this function selects coins to cover a
/// number, and has no opinion about what the number should be.
///
/// `committed` is the output of [`committed_funding_coin_ids`], passed in rather than read here so
/// that one pass takes one reading of the audit record, in the same way it takes one reading of the
/// disk and one of the balance.
pub fn select_operator_dig_cats<S: ChainSource>(
    source: &S,
    owner_puzzle_hash: Bytes32,
    need_dig_base_units: u64,
    committed: &HashSet<String>,
) -> Result<Vec<Cat>, FundingError> {
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
    let candidates: Vec<_> = records
        .into_iter()
        .filter(|r| !r.is_spent())
        .filter(|r| !committed.contains(&hex::encode(r.coin.coin_id())))
        .collect();

    let available = candidates
        .iter()
        .fold(0u64, |sum, r| sum.saturating_add(r.coin.amount));

    let selected = select_largest_first(candidates, need_dig_base_units, |r| {
        (r.coin.amount, r.coin.coin_id())
    })
    .map_err(|_| FundingError::Insufficient {
        have_dig_base_units: available,
        need_dig_base_units,
    })?;

    if selected.len() > MAX_SELECTED_FUNDING_COINS {
        return Err(FundingError::TooManyInputs {
            needed: selected.len(),
            limit: MAX_SELECTED_FUNDING_COINS,
        });
    }

    let mut cats = Vec::with_capacity(selected.len());
    for record in &selected {
        cats.push(authenticate(source, record, owner_puzzle_hash)?);
    }
    Ok(cats)
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
