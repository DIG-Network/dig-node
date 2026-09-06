//! Recovering a bond the live chain scan came back short on, from what this node itself recorded
//! creating (dig-node#574).
//!
//! # The gap this closes
//!
//! [`super::observe`] and [`super::plan`] both key a bond's `Bonded` state on ONE reading:
//! [`super::runner::MirrorEffects::observe_chain`], a live scan of every mirror coin this wallet
//! owns. A restart, a cold replica still catching up, or a chain source that answers "no coins"
//! instead of erroring all render identically here — a bond with a real, confirmed, unspent coin
//! reports as if it had never been created at all.
//!
//! That is not only a display defect. [`super::plan::plan`] treats an uncovered held bond as one to
//! CREATE, and the in-flight suppression it also consults is keyed on the audit record's `Pending`/
//! `Submitted` rows — which a CONFIRMED create has already left. So the same short scan that empties
//! the read surface also clears the one thing that would have stopped a second coin being paid for
//! collateral that already exists.
//!
//! # The fix is a candidate, re-verified — never a belief
//!
//! [`recheck_missing_bonds`] does not trust the audit record. For each held bond the live scan
//! missed, it asks `crate::spend_audit::confirmed_mirror_bond` what this node last confirmed
//! creating for that exact triple, and — only if something answers — asks
//! [`super::runner::MirrorEffects::recheck_bond`] to verify that SPECIFIC coin against chain
//! directly, independent of what the record says. Only a fresh `Bonded` verdict is promoted; anything
//! else (`Unbonded`, `Unverified`) is left alone, and the caller falls through to its ordinary
//! behaviour — which, for a genuinely-reclaimed coin, is correctly to create a fresh one.
//!
//! # Cost is bounded by what is actually missing
//!
//! A bond the live scan already covers is never looked up here at all: the filter that selects
//! "bonds needing a recheck" runs BEFORE any ledger read or chain call. On a healthy node — the
//! overwhelming majority of passes — this makes zero extra calls of any kind.

use crate::spend_audit::{confirmed_mirror_bond, SpendLedger};

use super::plan::{Bond, HeldMirror};
use super::runner::MirrorEffects;

use dig_node_core::mirror_bond::BondVerdict;

/// For every bond in `held` that `on_chain` does not cover at `current_epoch`, recover it from the
/// audit record and a fresh chain re-check, when both agree it is still genuinely bonded.
///
/// Returns only the RECOVERED coins — the caller extends its own `on_chain` with them before
/// handing it to [`super::pass::decide`], so a recovered bond flows through the ordinary `Bonded`
/// classification rather than a new, parallel one.
pub(super) fn recheck_missing_bonds<E: MirrorEffects + ?Sized>(
    effects: &E,
    ledger: &SpendLedger,
    held: &[Bond],
    on_chain: &[HeldMirror],
    current_epoch: i64,
) -> Vec<HeldMirror> {
    held.iter()
        .filter(|bond| !covered(on_chain, bond, current_epoch))
        .filter_map(|bond| recover_one(effects, ledger, bond, current_epoch))
        .collect()
}

/// Does the live scan already show a current-epoch coin for this bond?
fn covered(on_chain: &[HeldMirror], bond: &Bond, current_epoch: i64) -> bool {
    on_chain
        .iter()
        .any(|c| c.epoch == current_epoch && c.store_id == bond.store_id && c.root == bond.root)
}

/// Recover ONE missing bond, or decide there is nothing to recover.
fn recover_one<E: MirrorEffects + ?Sized>(
    effects: &E,
    ledger: &SpendLedger,
    bond: &Bond,
    current_epoch: i64,
) -> Option<HeldMirror> {
    let candidate = confirmed_mirror_bond(ledger, &bond.store_id, &bond.root, current_epoch)?;

    let verdict = effects.recheck_bond(
        &bond.store_id,
        &bond.root,
        current_epoch,
        &candidate.coin_id.0,
    );

    match verdict {
        BondVerdict::Bonded => Some(HeldMirror {
            coin_id: candidate.coin_id.0,
            store_id: bond.store_id.clone(),
            root: bond.root.clone(),
            epoch: current_epoch,
            // The record's OWN amount, never today's requirement: a coin created under a previous
            // requirement locks what it actually locked (SPEC.md §25.3), exactly as the ordinary
            // live-scan path already reports it.
            collateral_dig_base_units: candidate.amount_dig_base_units,
        }),
        // A stale, reclaimed, or otherwise no-longer-valid record. Falling through here is what
        // lets the ordinary plan create a fresh coin instead of one this function invented.
        BondVerdict::Unbonded | BondVerdict::Unverified => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_audit::{
        kinds, Asset, AuditedBond, Authority, SpendIntent, SpendJournal, SpendKind, SpendLog,
        Submission, TargetCoinId,
    };
    use std::cell::RefCell;

    /// A distinguishable 64-hex id, by construction rather than by counting characters.
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

    const EPOCH: i64 = 105;

    /// A ledger holding one CONFIRMED mirror-coin record for `(store, root, EPOCH)`.
    fn ledger_with_confirmed_bond(store: &str, root: &str, coin_id: &str, amount: u64) -> SpendLedger {
        let dir = tempfile::tempdir().expect("temp dir");
        let log = SpendLog::at(dir.path().join("spend-audit.jsonl"));
        let journal = SpendJournal::new(log.clone());
        let recorded = journal.begin(SpendIntent {
            kind: SpendKind::new(kinds::MIRROR_COIN),
            purpose: "create a mirror coin".to_string(),
            authority: Authority {
                principal: "node".to_string(),
                grant: "mirror-collateral".to_string(),
            },
            asset: Asset::Dig,
            amount_mojos: amount,
            fee_mojos: 0,
            store_id: Some(id(store)),
            bond: Some(AuditedBond {
                root: id(root),
                epoch: EPOCH,
            }),
            advertised_urls: Vec::new(),
        });
        journal.submitted(
            &recorded,
            Submission {
                intended_coin_id: None,
                funding_coin_ids: Vec::new(),
            },
        );
        journal.confirmed(&recorded, TargetCoinId(id(coin_id)), 1);
        log.ledger().expect("ledger")
    }

    /// A double that records every [`MirrorEffects::recheck_bond`] call it receives and answers a
    /// fixed verdict — every OTHER trait method is unreachable, because [`recheck_missing_bonds`]
    /// never calls anything else. A call reaching one of them is this test catching the function
    /// under test doing more I/O than its own contract promises.
    struct FakeRecheck {
        verdict: BondVerdict,
        calls: RefCell<Vec<(String, String, i64, String)>>,
    }

    impl FakeRecheck {
        fn answering(verdict: BondVerdict) -> Self {
            FakeRecheck {
                verdict,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl MirrorEffects for FakeRecheck {
        fn observe_disk(&self) -> Result<Vec<super::super::runner::ObservedCapsule>, super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds must not scan disk")
        }
        fn observe_chain(&self) -> Result<Vec<HeldMirror>, super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds must not re-scan the chain broadly")
        }
        fn coin_confirmation(&self, _coin_id: &str) -> Result<Option<u32>, super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds must ask recheck_bond, never coin_confirmation")
        }
        fn dig_balance_base_units(&self) -> Result<u64, super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds is not a funds decision")
        }
        fn reclaim(
            &self,
            _mirror: &HeldMirror,
            _reason: super::super::plan::ReclaimReason,
        ) -> Result<(), super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds never spends")
        }
        fn create(
            &self,
            _bond: &Bond,
            _epoch: i64,
            _amount_dig_base_units: u64,
        ) -> Result<(), super::super::runner::PassError> {
            unreachable!("recheck_missing_bonds never spends")
        }
        fn recheck_bond(&self, store_id: &str, root: &str, epoch: i64, coin_id: &str) -> BondVerdict {
            self.calls.borrow_mut().push((
                store_id.to_string(),
                root.to_string(),
                epoch,
                coin_id.to_string(),
            ));
            self.verdict
        }
    }

    /// **A bond the live scan ALREADY covers is never looked up here, and never rechecked.**
    ///
    /// The nearest wrong implementation rechecks every held bond unconditionally and is satisfied
    /// identically by an empty RESULT — so the call log, not the return value, is what this test
    /// asserts on: a healthy node making a chain call it does not need is the cost this function
    /// exists to avoid.
    #[test]
    fn a_bond_the_live_scan_covers_is_never_rechecked() {
        let effects = FakeRecheck::answering(BondVerdict::Bonded);
        let ledger = SpendLedger::default();
        let held = [bond("aa", "11")];
        let on_chain = [coin("c1", "aa", "11", EPOCH, 1_000)];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &on_chain, EPOCH);

        assert!(recovered.is_empty());
        assert!(
            effects.calls.borrow().is_empty(),
            "a covered bond must not even be asked about: {:?}",
            effects.calls.borrow()
        );
    }

    /// **A bond with NO local record is left alone, and never rechecked.**
    ///
    /// Proves the ledger lookup gates the chain call, not merely the eventual answer: a wrong
    /// implementation that rechecks with an empty or invented coin id would pass on RESULT alone,
    /// since this fixture's ledger has nothing to promote either way.
    #[test]
    fn a_bond_with_no_local_record_is_never_rechecked() {
        let effects = FakeRecheck::answering(BondVerdict::Bonded);
        let ledger = SpendLedger::default();
        let held = [bond("aa", "11")];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &[], EPOCH);

        assert!(recovered.is_empty());
        assert!(
            effects.calls.borrow().is_empty(),
            "nothing durable exists for this bond, so nothing should be looked up: {:?}",
            effects.calls.borrow()
        );
    }

    /// **A bond missing from the live scan, WITH a confirmed local record chain re-verifies as
    /// `Bonded`, is recovered with the RECORD's own coin id, amount and epoch.**
    ///
    /// This is the double-create fix and the display fix in one property: without it, `plan()`
    /// would see this bond as uncovered and create a second coin for collateral that already
    /// exists. Each of the three recovered fields is given a distinct, recognisable value so a
    /// wrong wiring — swapping which field feeds which, or substituting a hardcoded stand-in —
    /// cannot pass by accident.
    #[test]
    fn a_missing_bond_with_a_reverified_local_record_is_recovered() {
        let effects = FakeRecheck::answering(BondVerdict::Bonded);
        let ledger = ledger_with_confirmed_bond("aa", "11", "the-real-coin", 4_242);
        let held = [bond("aa", "11")];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &[], EPOCH);

        assert_eq!(recovered.len(), 1);
        let got = &recovered[0];
        assert_eq!(got.coin_id, id("the-real-coin"));
        assert_eq!(got.store_id, id("aa"));
        assert_eq!(got.root, id("11"));
        assert_eq!(got.epoch, EPOCH);
        assert_eq!(got.collateral_dig_base_units, 4_242);

        let calls = effects.calls.borrow();
        assert_eq!(calls.len(), 1, "exactly one candidate needed exactly one re-check");
        assert_eq!(calls[0].3, id("the-real-coin"), "the CANDIDATE coin id must be the one asked about");
    }

    /// **THE constraint this whole module exists to hold: a local record chain re-verifies as
    /// `Unbonded` is NOT recovered — the record is never believed over a fresh chain answer.**
    ///
    /// Without this test, an implementation that promoted any candidate with a local record —
    /// regardless of what `recheck_bond` actually answered — would pass every test above
    /// identically, since none of them varies the verdict away from `Bonded`. This is the fixture
    /// that makes "in addition to chain" a different claim from "instead of chain".
    #[test]
    fn a_missing_bond_whose_local_coin_chain_says_is_unbonded_is_not_recovered() {
        let effects = FakeRecheck::answering(BondVerdict::Unbonded);
        let ledger = ledger_with_confirmed_bond("aa", "11", "a-reclaimed-coin", 1_000);
        let held = [bond("aa", "11")];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &[], EPOCH);

        assert!(
            recovered.is_empty(),
            "a coin chain disproves must not be reported as bonded, however durably it was once \
             recorded: {recovered:?}"
        );
    }

    /// The THIRD verdict, proven separately from `Unbonded`: "nothing could be established" must
    /// also NOT promote. An implementation that only guarded against `Unbonded` — treating anything
    /// non-`Unbonded` as good enough — would pass the test above and fail this one.
    #[test]
    fn a_missing_bond_whose_recheck_is_unverified_is_not_recovered() {
        let effects = FakeRecheck::answering(BondVerdict::Unverified);
        let ledger = ledger_with_confirmed_bond("aa", "11", "some-coin", 1_000);
        let held = [bond("aa", "11")];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &[], EPOCH);

        assert!(
            recovered.is_empty(),
            "an unverified re-check must never be promoted to bonded by default: {recovered:?}"
        );
    }

    /// **A confirmed record from a PRIOR epoch does not cover the CURRENT epoch's bond.**
    ///
    /// A rollover legitimately leaves a previous epoch's coin on chain while this epoch has none
    /// yet; recovering it here would tell the plan a stale coin covers a live requirement it does
    /// not, and the bond would never get a fresh coin of its own.
    #[test]
    fn a_confirmed_record_from_a_prior_epoch_does_not_cover_the_current_one() {
        let effects = FakeRecheck::answering(BondVerdict::Bonded);
        // Recorded confirmed at EPOCH, asked about at a LATER epoch.
        let ledger = ledger_with_confirmed_bond("aa", "11", "last-epoch-coin", 1_000);
        let held = [bond("aa", "11")];

        let recovered = recheck_missing_bonds(&effects, &ledger, &held, &[], EPOCH + 1);

        assert!(recovered.is_empty());
        assert!(
            effects.calls.borrow().is_empty(),
            "a different-epoch record is not even a candidate, so no re-check is attempted: {:?}",
            effects.calls.borrow()
        );
    }
}
