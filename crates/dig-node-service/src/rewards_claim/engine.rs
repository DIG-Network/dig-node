//! The claim loop's one tick: discover, evaluate, claim — driven against [`ClaimChainPort`] and
//! [`DistributorHintSource`], never against a concrete chain client (see the module doc's "chain
//! seam" section).

use chia_protocol::Bytes32;

use super::hints::DistributorHintSource;
use super::port::{ClaimChainPort, ClaimPortError};
use super::types::{ClaimLoopState, ClaimOutcome, ClaimStatus};

/// Drives one claim cycle for this node against a [`ClaimChainPort`] + [`DistributorHintSource`]
/// and the anti-silence status surface across calls to [`Self::run_cycle`].
///
/// # No permanent "no entry slot" blacklist (Defect B)
/// An earlier version of this engine cached a launcher id in a process-lifetime `terminal_no_entry`
/// set the first time `own_entry` returned `None`, and never re-checked it. That is wrong in two
/// reachable cases: SPEC §12.5 clause 2's re-entry path (a peer evicted, re-challenged and
/// legitimately re-admitted would never claim again until the process restarted), and a peer that
/// discovers a distributor before the funder's `AddEntry` lands (blacklisted on its very first
/// cycle, never paid at all). SPEC §12.5 clause 3 — re-read the entry slot before every claim,
/// never cache one across cycles — argues directly against caching an absence forever too. The fix:
/// no blacklist at all. `own_entry` is a cheap chain READ, so it is re-issued every cycle for every
/// candidate; `ClaimOutcome::NoEntrySlot` stays the reported outcome (still non-error, still no
/// spend, still no chain fault), but it is now a per-cycle observation, not a lifetime sentence.
pub struct ClaimEngine<P, H> {
    port: P,
    hints: H,
    own_payout_puzzle_hash: Bytes32,
    max_fee_mojos: u64,
    /// Defect C2: the per-cycle aggregate fee budget — bounds what this node will spend across ALL
    /// claims in one cycle, independent of the per-claim ceiling. See [`super::config`]'s module doc
    /// for the attacker-cost reasoning that makes this necessary in addition to `max_fee_mojos`.
    cycle_fee_budget_mojos: u64,
    dig_asset_id: Bytes32,
    status: ClaimStatus,
}

impl<P: ClaimChainPort, H: DistributorHintSource> ClaimEngine<P, H> {
    pub fn new(
        port: P,
        hints: H,
        own_payout_puzzle_hash: Bytes32,
        max_fee_mojos: u64,
        cycle_fee_budget_mojos: u64,
        dig_asset_id: Bytes32,
    ) -> Self {
        ClaimEngine {
            port,
            hints,
            own_payout_puzzle_hash,
            max_fee_mojos,
            cycle_fee_budget_mojos,
            dig_asset_id,
            status: ClaimStatus::default(),
        }
    }

    #[must_use]
    pub fn status(&self) -> ClaimStatus {
        self.status
    }

    /// Run one cycle: discover candidates (chain + re-derived hints), evaluate each against SPEC
    /// §9.3/§8.3/§12.5, and submit a claim for every one that clears the per-claim threshold, the
    /// per-claim fee ceiling AND the per-cycle aggregate fee budget. Returns every outcome, one per
    /// evaluated distributor.
    pub async fn run_cycle(&mut self, now: u64) -> Vec<ClaimOutcome> {
        // Defect A1/A4: per-cycle fields are reset here, not carried over — a fault or a claim count
        // from a PAST cycle must never leak into this cycle's reading of `compute_state()`.
        self.status.fault_reported = false;
        self.status.last_attempt_at = Some(now);
        let mut spent_this_cycle_mojos = 0u64;
        let mut budget_exhausted = false;

        let mut discovery_failed = false;
        let discovered = match self.port.discover_distributors().await {
            Ok(v) => v,
            Err(ClaimPortError::Unavailable) => {
                self.status.state = ClaimLoopState::ChainSourceUnavailable;
                return Vec::new();
            }
            Err(ClaimPortError::Other(_)) => {
                // Defect A4: do NOT stamp `last_discovery_at` here — a reader relies on this
                // timestamp going stale to notice a wedged discovery path.
                self.status.fault_reported = true;
                discovery_failed = true;
                Vec::new()
            }
        };
        if !discovery_failed {
            self.status.last_discovery_at = Some(now);
        }

        let mut candidates: Vec<Bytes32> = discovered.iter().map(|d| d.launcher_id).collect();

        // SPEC §13.2: a hint only ADDS a candidate; every property is re-derived from chain before
        // it counts, and a hint that fails re-derivation is dropped, never trusted.
        for hint in self.hints.hints().await {
            if candidates.contains(&hint.launcher_id) {
                continue;
            }
            match self.port.resolve_launch_comment(hint.launcher_id).await {
                Ok(Some(_)) => candidates.push(hint.launcher_id),
                Ok(None) => {}
                Err(ClaimPortError::Unavailable) => {}
                Err(ClaimPortError::Other(_)) => self.status.fault_reported = true,
            }
        }

        self.status.distributors_known = candidates.len() as u32;
        let any_candidates = !candidates.is_empty();

        let mut outcomes = Vec::new();
        let mut with_entry = 0u32;
        let mut claimable = 0u32;
        let mut faulted = 0u32;
        let mut submitted_this_cycle = 0u64;
        let mut no_entry_this_cycle = 0u32;

        for launcher_id in candidates {
            // Defect B: no permanent blacklist skip here — every candidate is re-evaluated every
            // cycle, including one that reported `NoEntrySlot` on a prior cycle.
            match self
                .evaluate_one(
                    launcher_id,
                    &mut spent_this_cycle_mojos,
                    &mut budget_exhausted,
                )
                .await
            {
                EvalResult::Fault => {
                    faulted += 1;
                }
                EvalResult::Outcome(outcome, entry_seen, was_claimable) => {
                    if entry_seen {
                        with_entry += 1;
                    }
                    if was_claimable {
                        claimable += 1;
                    }
                    match &outcome {
                        ClaimOutcome::NoEntrySlot { .. } => no_entry_this_cycle += 1,
                        ClaimOutcome::Submitted { .. } => submitted_this_cycle += 1,
                        _ => {}
                    }
                    outcomes.push(outcome);
                }
                EvalResult::ChainUnavailable => {
                    self.status.state = ClaimLoopState::ChainSourceUnavailable;
                    return outcomes;
                }
            }
        }

        // Defect A4: an all-faulted cycle (candidates existed, discovery succeeded, but every one of
        // them faulted) must not stamp `last_cycle_at` either — same staleness reasoning as above.
        let all_faulted_cycle = any_candidates && outcomes.is_empty() && self.status.fault_reported;

        self.status.distributors_with_own_entry = with_entry;
        self.status.distributors_claimable = claimable;
        self.status.distributors_faulted = faulted;
        self.status.claims_submitted += submitted_this_cycle;
        self.status.claims_submitted_this_cycle = submitted_this_cycle;
        self.status.terminal_no_entry_slot = no_entry_this_cycle;
        self.status.consecutive_faulted_cycles = if self.status.fault_reported {
            self.status.consecutive_faulted_cycles + 1
        } else {
            0
        };
        if !discovery_failed && !all_faulted_cycle {
            self.status.last_cycle_at = Some(now);
        }
        if self.status.state != ClaimLoopState::ChainSourceUnavailable {
            self.status.state = self.status.compute_state();
        }
        outcomes
    }

    async fn evaluate_one(
        &mut self,
        launcher_id: Bytes32,
        spent_this_cycle_mojos: &mut u64,
        budget_exhausted: &mut bool,
    ) -> EvalResult {
        let asset = match self.port.reserve_asset_id(launcher_id).await {
            Ok(a) => a,
            Err(ClaimPortError::Unavailable) => return EvalResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return EvalResult::Fault;
            }
        };
        if asset != self.dig_asset_id {
            // SPEC §9.3: not ours, dropped — not counted as known/claimable.
            return EvalResult::Outcome(ClaimOutcome::NotOurs { launcher_id }, false, false);
        }

        // SPEC §12.5 clause 3: re-read the entry slot fresh on EVERY call — never cached.
        let entry = match self
            .port
            .own_entry(launcher_id, self.own_payout_puzzle_hash)
            .await
        {
            Ok(Some(e)) => e,
            Ok(None) => {
                return EvalResult::Outcome(
                    ClaimOutcome::NoEntrySlot { launcher_id },
                    false,
                    false,
                );
            }
            Err(ClaimPortError::Unavailable) => return EvalResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return EvalResult::Fault;
            }
        };

        if entry.payout_puzzle_hash != self.own_payout_puzzle_hash {
            // Defect E: the port handed back an entry for a puzzle hash that is not this node's own.
            // Submitting against it would pay someone else. Refuse -- never substitute our own hash
            // and proceed -- and surface it as a fault, since a divergent entry means the port is
            // confused or hostile, not that there is nothing to claim.
            self.status.fault_reported = true;
            self.status.claims_refused_payout_mismatch += 1;
            return EvalResult::Outcome(
                ClaimOutcome::PayoutPuzzleHashMismatch { launcher_id },
                true,
                false,
            );
        }

        let threshold = match self.port.payout_threshold(launcher_id).await {
            Ok(t) => t,
            Err(ClaimPortError::Unavailable) => return EvalResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return EvalResult::Fault;
            }
        };

        if entry.accrued_base_units < threshold {
            self.status.claims_skipped_below_threshold += 1;
            return EvalResult::Outcome(
                ClaimOutcome::SkippedBelowThreshold {
                    launcher_id,
                    accrued: entry.accrued_base_units,
                    threshold,
                },
                true,
                false,
            );
        }

        let fee = match self.port.required_fee_mojos(launcher_id).await {
            Ok(f) => f,
            Err(ClaimPortError::Unavailable) => return EvalResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return EvalResult::Fault;
            }
        };

        if fee > self.max_fee_mojos {
            self.status.claims_skipped_fee_ceiling += 1;
            return EvalResult::Outcome(
                ClaimOutcome::SkippedFeeAboveCeiling {
                    launcher_id,
                    fee_mojos: fee,
                    ceiling_mojos: self.max_fee_mojos,
                },
                true,
                true,
            );
        }

        // Defect C2: the per-claim ceiling alone does not bound what K distributors can collectively
        // force this node to spend in one cycle. Once the cycle budget is gone, every remaining
        // candidate is skipped the same way, not spent past it.
        if *budget_exhausted || *spent_this_cycle_mojos + fee > self.cycle_fee_budget_mojos {
            *budget_exhausted = true;
            self.status.claims_skipped_cycle_budget += 1;
            return EvalResult::Outcome(
                ClaimOutcome::SkippedCycleBudgetExhausted {
                    launcher_id,
                    fee_mojos: fee,
                    budget_mojos: self.cycle_fee_budget_mojos,
                },
                true,
                true,
            );
        }

        match self
            .port
            .submit_initiate_payout(launcher_id, entry.payout_puzzle_hash, fee)
            .await
        {
            Ok(()) => {
                *spent_this_cycle_mojos += fee;
                EvalResult::Outcome(ClaimOutcome::Submitted { launcher_id }, true, true)
            }
            Err(ClaimPortError::Unavailable) => EvalResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                EvalResult::Fault
            }
        }
    }
}

enum EvalResult {
    /// `(outcome, entry_slot_was_present, was_claimable)`.
    Outcome(ClaimOutcome, bool, bool),
    Fault,
    ChainUnavailable,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::rewards_claim::hints::{DistributorHint, NoHintSource};
    use crate::rewards_claim::parser::parse_launch_comment;
    use crate::rewards_claim::types::DiscoveredDistributor;

    const DIG_ASSET_ID: Bytes32 = Bytes32::new([9u8; 32]);
    const OUR_PAYOUT_PUZZLE_HASH: Bytes32 = Bytes32::new([1u8; 32]);
    const FEE_CEILING: u64 = 1_000_000_000;
    const CYCLE_BUDGET: u64 = 1_000_000_000;

    #[derive(Clone)]
    struct FakeDistributor {
        launcher_id: Bytes32,
        store_id: Bytes32,
        root: Bytes32,
        reserve_asset_id: Bytes32,
        payout_threshold: u64,
        entry: Option<super::super::types::OwnEntry>,
        fee_mojos: u64,
    }

    /// A full in-memory fake standing in for the real chain adapter (see the module doc's "chain
    /// seam" section) — the ONLY thing #3249 landing changes is which struct implements this trait.
    struct FakeChainPort {
        distributors: Mutex<HashMap<Bytes32, FakeDistributor>>,
        submitted: Mutex<Vec<(Bytes32, Bytes32, u64)>>,
        own_entry_reads: Mutex<u32>,
    }

    impl FakeChainPort {
        fn new(distributors: Vec<FakeDistributor>) -> Self {
            FakeChainPort {
                distributors: Mutex::new(
                    distributors
                        .into_iter()
                        .map(|d| (d.launcher_id, d))
                        .collect(),
                ),
                submitted: Mutex::new(Vec::new()),
                own_entry_reads: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl ClaimChainPort for FakeChainPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            Ok(self
                .distributors
                .lock()
                .unwrap()
                .values()
                .map(|d| DiscoveredDistributor {
                    launcher_id: d.launcher_id,
                    store_id: d.store_id,
                    root: d.root,
                })
                .collect())
        }

        async fn resolve_launch_comment(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            Ok(self
                .distributors
                .lock()
                .unwrap()
                .get(&launcher_id)
                .map(|d| DiscoveredDistributor {
                    launcher_id: d.launcher_id,
                    store_id: d.store_id,
                    root: d.root,
                }))
        }

        async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            self.distributors
                .lock()
                .unwrap()
                .get(&launcher_id)
                .map(|d| d.reserve_asset_id)
                .ok_or(ClaimPortError::Other("unknown distributor".into()))
        }

        async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.distributors
                .lock()
                .unwrap()
                .get(&launcher_id)
                .map(|d| d.payout_threshold)
                .ok_or(ClaimPortError::Other("unknown distributor".into()))
        }

        async fn own_entry(
            &self,
            launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
        ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
            *self.own_entry_reads.lock().unwrap() += 1;
            self.distributors
                .lock()
                .unwrap()
                .get(&launcher_id)
                .map(|d| d.entry)
                .ok_or(ClaimPortError::Other("unknown distributor".into()))
        }

        async fn required_fee_mojos(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.distributors
                .lock()
                .unwrap()
                .get(&launcher_id)
                .map(|d| d.fee_mojos)
                .ok_or(ClaimPortError::Other("unknown distributor".into()))
        }

        async fn submit_initiate_payout(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
            fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            self.submitted
                .lock()
                .unwrap()
                .push((launcher_id, payout_puzzle_hash, fee_mojos));
            Ok(())
        }
    }

    fn one_distributor(
        entry: Option<super::super::types::OwnEntry>,
        payout_threshold: u64,
        fee_mojos: u64,
    ) -> FakeDistributor {
        FakeDistributor {
            launcher_id: Bytes32::new([2u8; 32]),
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold,
            entry,
            fee_mojos,
        }
    }

    fn engine(port: FakeChainPort) -> ClaimEngine<FakeChainPort, NoHintSource> {
        ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
    }

    /// ACCEPTANCE 1 — the anti-green test. A loop that runs and claims nothing MUST fail this.
    #[tokio::test]
    async fn one_tick_submits_exactly_one_claim_for_an_above_threshold_entry() {
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let launcher_id = d.launcher_id;
        let port = FakeChainPort::new(vec![d]);
        let mut e = engine(port);

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(outcomes, vec![ClaimOutcome::Submitted { launcher_id }]);
        assert_eq!(e.status().claims_submitted, 1);
        assert_eq!(e.port.submitted.lock().unwrap().len(), 1);
        let (submitted_launcher, submitted_ppz, _fee) = e.port.submitted.lock().unwrap()[0];
        assert_eq!(submitted_launcher, launcher_id);
        assert_eq!(submitted_ppz, OUR_PAYOUT_PUZZLE_HASH);
    }

    /// ACCEPTANCE 3 — below threshold is skipped, never an error, never a spend.
    #[tokio::test]
    async fn below_threshold_is_skipped_not_failed_and_spends_nothing() {
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 500,
            }),
            1_000,
            10,
        );
        let launcher_id = d.launcher_id;
        let port = FakeChainPort::new(vec![d]);
        let mut e = engine(port);

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::SkippedBelowThreshold {
                launcher_id,
                accrued: 500,
                threshold: 1_000,
            }]
        );
        assert_eq!(e.status().claims_submitted, 0);
        assert_eq!(e.status().claims_skipped_below_threshold, 1);
        assert!(e.port.submitted.lock().unwrap().is_empty());
    }

    /// ACCEPTANCE 4 — the threshold is read from chain, not hardcoded.
    #[tokio::test]
    async fn threshold_other_than_1000_is_honoured() {
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 2_500,
            }),
            5_000,
            10,
        );
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::SkippedBelowThreshold {
                launcher_id,
                accrued: 2_500,
                threshold: 5_000,
            }]
        );
    }

    /// ACCEPTANCE 5 — a required fee above the ceiling is skipped, zero submissions.
    #[tokio::test]
    async fn fee_above_ceiling_is_skipped() {
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            FEE_CEILING + 1,
        );
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::SkippedFeeAboveCeiling {
                launcher_id,
                fee_mojos: FEE_CEILING + 1,
                ceiling_mojos: FEE_CEILING,
            }]
        );
        assert_eq!(e.status().claims_submitted, 0);
        assert!(e.port.submitted.lock().unwrap().is_empty());
    }

    /// Defect B regression: `NoEntrySlot` is non-error and reports neither a chain fault nor a lost
    /// payment, but it is NO LONGER a permanent blacklist — the second tick re-checks the same
    /// distributor (SPEC §12.5 clause 3: re-read fresh before every claim, never cache).
    #[tokio::test]
    async fn no_entry_slot_is_non_terminal_and_re_checked_every_cycle() {
        let d = one_distributor(None, 1_000, 10);
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));

        let first = e.run_cycle(1_000).await;
        assert_eq!(first, vec![ClaimOutcome::NoEntrySlot { launcher_id }]);
        assert_eq!(e.status().terminal_no_entry_slot, 1);
        assert!(!e.status().fault_reported, "no chain fault reported");
        assert_eq!(e.status().claims_submitted, 0, "no lost payment claimed");

        let reads_after_first = *e.port.own_entry_reads.lock().unwrap();
        let second = e.run_cycle(2_000).await;
        assert_eq!(
            second,
            vec![ClaimOutcome::NoEntrySlot { launcher_id }],
            "still no entry, so still reported -- but re-evaluated, not silently skipped"
        );
        assert_eq!(
            *e.port.own_entry_reads.lock().unwrap(),
            reads_after_first + 1,
            "the second tick re-reads the entry slot rather than trusting a cached absence"
        );
    }

    /// Defect B — the fix's whole point: SPEC §12.5 clause 2's re-entry path. A distributor with no
    /// entry slot on cycle 1 (never admitted yet, or evicted) that gains one before cycle 2 (legit
    /// re-admission, or a discovery-vs-`AddEntry` race resolving) must produce a claim on cycle 2 —
    /// the old process-lifetime blacklist made this permanently unreachable.
    #[tokio::test]
    async fn no_entry_slot_then_re_admitted_produces_a_claim_on_the_later_cycle() {
        let d = one_distributor(None, 1_000, 10);
        let launcher_id = d.launcher_id;
        let port = FakeChainPort::new(vec![d]);
        let mut e = engine(port);

        let first = e.run_cycle(1_000).await;
        assert_eq!(first, vec![ClaimOutcome::NoEntrySlot { launcher_id }]);

        // The distributor admits our entry between cycle 1 and cycle 2.
        e.port
            .distributors
            .lock()
            .unwrap()
            .get_mut(&launcher_id)
            .unwrap()
            .entry = Some(super::super::types::OwnEntry {
            payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
            counter: 0,
            accrued_base_units: 5_000,
        });

        let second = e.run_cycle(2_000).await;
        assert_eq!(second, vec![ClaimOutcome::Submitted { launcher_id }]);
        assert_eq!(e.status().claims_submitted, 1);
    }

    /// ACCEPTANCE 7 — two consecutive ticks perform two fresh entry-slot reads; no cached slot.
    #[tokio::test]
    async fn consecutive_ticks_re_read_the_entry_slot_fresh() {
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 500,
            }),
            1_000,
            10,
        );
        let mut e = engine(FakeChainPort::new(vec![d]));

        e.run_cycle(1_000).await;
        e.run_cycle(2_000).await;

        assert_eq!(*e.port.own_entry_reads.lock().unwrap(), 2);
    }

    /// ACCEPTANCE 10 — SPEC §9.3: a distributor whose reserve asset is not DIG_ASSET_ID is dropped.
    #[tokio::test]
    async fn non_dig_reserve_asset_distributor_is_dropped() {
        let mut d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        d.reserve_asset_id = Bytes32::new([0xFFu8; 32]);
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(outcomes, vec![ClaimOutcome::NotOurs { launcher_id }]);
        assert_eq!(e.status().claims_submitted, 0);
        assert!(e.port.submitted.lock().unwrap().is_empty());
    }

    /// ACCEPTANCE 11a/11c — a hint ADDS a candidate the chain sweep did not already return, and
    /// `NoHintSource` changes no outcome versus the chain-only path (every other test here uses
    /// `NoHintSource` already; this test is the direct A/B).
    #[tokio::test]
    async fn a_hint_adds_a_candidate_the_chain_sweep_alone_would_miss() {
        struct OneHint(Bytes32);
        #[async_trait]
        impl DistributorHintSource for OneHint {
            async fn hints(&self) -> Vec<DistributorHint> {
                vec![DistributorHint {
                    launcher_id: self.0,
                }]
            }
        }

        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let launcher_id = d.launcher_id;

        // Chain-only sweep never returns this distributor -- only resolve_launch_comment does,
        // simulating "known to exist on chain but not enumerated by the discovery sweep yet".
        struct HintOnlyPort(FakeChainPort);
        #[async_trait]
        impl ClaimChainPort for HintOnlyPort {
            async fn discover_distributors(
                &self,
            ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
                Ok(Vec::new())
            }
            async fn resolve_launch_comment(
                &self,
                launcher_id: Bytes32,
            ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
                self.0.resolve_launch_comment(launcher_id).await
            }
            async fn reserve_asset_id(&self, l: Bytes32) -> Result<Bytes32, ClaimPortError> {
                self.0.reserve_asset_id(l).await
            }
            async fn payout_threshold(&self, l: Bytes32) -> Result<u64, ClaimPortError> {
                self.0.payout_threshold(l).await
            }
            async fn own_entry(
                &self,
                l: Bytes32,
                p: Bytes32,
            ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
                self.0.own_entry(l, p).await
            }
            async fn required_fee_mojos(&self, l: Bytes32) -> Result<u64, ClaimPortError> {
                self.0.required_fee_mojos(l).await
            }
            async fn submit_initiate_payout(
                &self,
                l: Bytes32,
                p: Bytes32,
                f: u64,
            ) -> Result<(), ClaimPortError> {
                self.0.submit_initiate_payout(l, p, f).await
            }
        }

        let port = HintOnlyPort(FakeChainPort::new(vec![d]));
        let mut e = ClaimEngine::new(
            port,
            OneHint(launcher_id),
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;
        assert_eq!(outcomes, vec![ClaimOutcome::Submitted { launcher_id }]);
    }

    /// ACCEPTANCE 11b — a hint whose chain re-derivation fails (resolve_launch_comment -> None) is
    /// dropped, never becomes a candidate, never a claim's authority.
    #[tokio::test]
    async fn a_hint_that_fails_chain_rederivation_is_dropped() {
        struct BogusHint;
        #[async_trait]
        impl DistributorHintSource for BogusHint {
            async fn hints(&self) -> Vec<DistributorHint> {
                vec![DistributorHint {
                    launcher_id: Bytes32::new([0xEEu8; 32]),
                }]
            }
        }

        let port = FakeChainPort::new(Vec::new());
        let mut e = ClaimEngine::new(
            port,
            BogusHint,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;
        assert!(outcomes.is_empty());
        assert_eq!(e.status().distributors_known, 0);
    }

    /// A port whose discovery call always returns a real (non-`Unavailable`) chain fault, every
    /// cycle -- the failure Defect A1 describes.
    struct AlwaysFaultingDiscoveryPort;
    #[async_trait]
    impl ClaimChainPort for AlwaysFaultingDiscoveryPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            Err(ClaimPortError::Other("simulated chain fault".into()))
        }
        async fn resolve_launch_comment(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            Ok(None)
        }
        async fn reserve_asset_id(&self, _launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            Err(ClaimPortError::Other("unreachable".into()))
        }
        async fn payout_threshold(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Err(ClaimPortError::Other("unreachable".into()))
        }
        async fn own_entry(
            &self,
            _launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
        ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
            Err(ClaimPortError::Other("unreachable".into()))
        }
        async fn required_fee_mojos(&self, _launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            Err(ClaimPortError::Other("unreachable".into()))
        }
        async fn submit_initiate_payout(
            &self,
            _launcher_id: Bytes32,
            _payout_puzzle_hash: Bytes32,
            _fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            Err(ClaimPortError::Other("unreachable".into()))
        }
    }

    /// Defect A1/A2 regression -- THE anti-green test for this defect: a port that errors on
    /// discovery every cycle must NEVER read `Nominal`. Before the fix, `fault_reported` had no
    /// fault-bearing state to fall through to and this laundered into `Nominal` forever.
    #[tokio::test]
    async fn repeated_discovery_faults_never_read_as_nominal() {
        let mut e = ClaimEngine::new(
            AlwaysFaultingDiscoveryPort,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        for cycle in 1..=3u32 {
            e.run_cycle(u64::from(cycle) * 1_000).await;
            assert_ne!(
                e.status().state,
                ClaimLoopState::Nominal,
                "cycle {cycle}: a reported fault must never read as Nominal"
            );
            assert_eq!(
                e.status().state,
                ClaimLoopState::Faulted { cycles: cycle },
                "cycle {cycle}: consecutive fault count must track the streak"
            );
        }
    }

    /// Defect A4 regression: a failed discovery must leave `last_discovery_at` unchanged (a reader
    /// depends on that timestamp going stale to notice a wedged discovery path).
    #[tokio::test]
    async fn failed_discovery_leaves_last_discovery_at_unchanged() {
        let mut e = ClaimEngine::new(
            AlwaysFaultingDiscoveryPort,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        e.run_cycle(1_000).await;
        assert_eq!(e.status().last_discovery_at, None);
        e.run_cycle(2_000).await;
        assert_eq!(
            e.status().last_discovery_at,
            None,
            "still unchanged after a second failed discovery"
        );
        assert_eq!(
            e.status().last_attempt_at,
            Some(2_000),
            "last_attempt_at still proves the loop is alive"
        );
    }

    /// Defect C2 regression: K distributors each individually under the per-claim ceiling must NOT
    /// collectively spend past the per-cycle aggregate budget.
    #[tokio::test]
    async fn distributors_each_under_ceiling_do_not_collectively_exceed_the_cycle_budget() {
        const PER_CLAIM_FEE: u64 = 10;
        const BUDGET: u64 = 25; // only 2 of 4 distributors can be paid out of this budget
        let distributors: Vec<FakeDistributor> = (0..4u8)
            .map(|i| FakeDistributor {
                launcher_id: Bytes32::new([i + 10; 32]),
                store_id: Bytes32::new([3u8; 32]),
                root: Bytes32::new([4u8; 32]),
                reserve_asset_id: DIG_ASSET_ID,
                payout_threshold: 1_000,
                entry: Some(super::super::types::OwnEntry {
                    payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                    counter: 0,
                    accrued_base_units: 5_000,
                }),
                fee_mojos: PER_CLAIM_FEE,
            })
            .collect();
        let mut e = ClaimEngine::new(
            FakeChainPort::new(distributors),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING, // each individual fee (10) is far under the per-claim ceiling
            BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;

        let submitted = outcomes
            .iter()
            .filter(|o| matches!(o, ClaimOutcome::Submitted { .. }))
            .count();
        let budget_skipped = outcomes
            .iter()
            .filter(|o| matches!(o, ClaimOutcome::SkippedCycleBudgetExhausted { .. }))
            .count();
        assert_eq!(
            submitted, 2,
            "only 2 claims fit inside the 25-mojo budget at 10 each"
        );
        assert_eq!(
            budget_skipped, 2,
            "the remaining 2 are skipped, not spent past the budget"
        );
        assert_eq!(e.status().claims_submitted, 2);
        assert_eq!(e.status().claims_skipped_cycle_budget, 2);
    }

    /// Defect E regression: a port returning an entry whose `payout_puzzle_hash` diverges from this
    /// node's own must produce ZERO submissions and a reported fault -- never pay whoever the port
    /// named instead.
    #[tokio::test]
    async fn entry_for_a_different_payout_puzzle_hash_is_refused_not_paid() {
        let wrong_hash = Bytes32::new([0x77u8; 32]);
        assert_ne!(wrong_hash, OUR_PAYOUT_PUZZLE_HASH);
        let d = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: wrong_hash,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::PayoutPuzzleHashMismatch { launcher_id }]
        );
        assert_eq!(e.status().claims_submitted, 0, "never paid the wrong hash");
        assert!(e.port.submitted.lock().unwrap().is_empty());
        assert!(
            e.status().fault_reported,
            "a divergent entry is a fault, not a routine skip"
        );
        assert_eq!(e.status().claims_refused_payout_mismatch, 1);
    }

    /// ACCEPTANCE 12 — with `UnavailableClaimChainPort` wired, the engine reports the named state
    /// `ChainSourceUnavailable` and runs zero cycles: no discovery outcome, no fault flag, no
    /// claim, never a silent no-op (see the module doc's "chain seam" + "HONESTY" sections).
    #[tokio::test]
    async fn unavailable_port_reports_chain_source_unavailable_and_runs_zero_cycles() {
        let mut e = ClaimEngine::new(
            crate::rewards_claim::port::UnavailableClaimChainPort,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;

        assert!(outcomes.is_empty(), "zero cycles ran");
        assert_eq!(e.status().state, ClaimLoopState::ChainSourceUnavailable);
        assert_eq!(e.status().claims_submitted, 0);
        assert_eq!(e.status().distributors_known, 0);
        assert!(e.status().last_cycle_at.is_none(), "no cycle completed");
    }

    /// The launch-comment parser wired end-to-end: what `resolve_launch_comment` would produce for
    /// a real chain reply, confirming the two modules compose (not a duplicate of parser.rs's own
    /// table-driven unit tests).
    #[test]
    fn parser_output_feeds_discovered_distributor_shape() {
        let store = "a".repeat(64);
        let root = "b".repeat(64);
        let comment = format!("dig-rewards:v1:{store}:{root}");
        let d = parse_launch_comment(Bytes32::new([5u8; 32]), &comment).expect("parses");
        assert_eq!(d.launcher_id, Bytes32::new([5u8; 32]));
    }
}
