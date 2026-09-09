//! The claim loop's one tick: discover, evaluate, claim — driven against [`ClaimChainPort`] and
//! [`DistributorHintSource`], never against a concrete chain client (see the module doc's "chain
//! seam" section).

use std::collections::HashSet;

use chia_protocol::Bytes32;

use super::hints::DistributorHintSource;
use super::port::{ClaimChainPort, ClaimPortError};
use super::types::{ClaimLoopState, ClaimOutcome, ClaimStatus};

/// Drives one claim cycle for this node against a [`ClaimChainPort`] + [`DistributorHintSource`],
/// holding the terminal "no entry slot" set (SPEC §12.5 clause 1) and the anti-silence status
/// surface across calls to [`Self::run_cycle`].
pub struct ClaimEngine<P, H> {
    port: P,
    hints: H,
    own_payout_puzzle_hash: Bytes32,
    max_fee_mojos: u64,
    dig_asset_id: Bytes32,
    terminal_no_entry: HashSet<Bytes32>,
    status: ClaimStatus,
}

impl<P: ClaimChainPort, H: DistributorHintSource> ClaimEngine<P, H> {
    pub fn new(
        port: P,
        hints: H,
        own_payout_puzzle_hash: Bytes32,
        max_fee_mojos: u64,
        dig_asset_id: Bytes32,
    ) -> Self {
        ClaimEngine {
            port,
            hints,
            own_payout_puzzle_hash,
            max_fee_mojos,
            dig_asset_id,
            terminal_no_entry: HashSet::new(),
            status: ClaimStatus::default(),
        }
    }

    #[must_use]
    pub fn status(&self) -> ClaimStatus {
        self.status
    }

    /// Run one cycle: discover candidates (chain + re-derived hints), evaluate each against SPEC
    /// §9.3/§8.3/§12.5, and submit a claim for every one that clears both the threshold and the fee
    /// ceiling. Returns every outcome, one per evaluated distributor.
    pub async fn run_cycle(&mut self, now: u64) -> Vec<ClaimOutcome> {
        let discovered = match self.port.discover_distributors().await {
            Ok(v) => v,
            Err(ClaimPortError::Unavailable) => {
                self.status.state = ClaimLoopState::ChainSourceUnavailable;
                return Vec::new();
            }
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                Vec::new()
            }
        };
        self.status.last_discovery_at = Some(now);

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

        let mut outcomes = Vec::new();
        let mut with_entry = 0u32;
        let mut claimable = 0u32;

        for launcher_id in candidates {
            if self.terminal_no_entry.contains(&launcher_id) {
                continue;
            }

            match self.evaluate_one(launcher_id).await {
                EvalResult::Fault => continue,
                EvalResult::Outcome(outcome, entry_seen, was_claimable) => {
                    if entry_seen {
                        with_entry += 1;
                    }
                    if was_claimable {
                        claimable += 1;
                    }
                    if matches!(outcome, ClaimOutcome::NoEntrySlot { .. }) {
                        self.terminal_no_entry.insert(launcher_id);
                        self.status.terminal_no_entry_slot += 1;
                    }
                    outcomes.push(outcome);
                }
                EvalResult::ChainUnavailable => {
                    self.status.state = ClaimLoopState::ChainSourceUnavailable;
                    return outcomes;
                }
            }
        }

        self.status.distributors_with_own_entry = with_entry;
        self.status.distributors_claimable = claimable;
        self.status.last_cycle_at = Some(now);
        if self.status.state != ClaimLoopState::ChainSourceUnavailable {
            self.status.state = self.status.compute_state();
        }
        outcomes
    }

    async fn evaluate_one(&mut self, launcher_id: Bytes32) -> EvalResult {
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

        match self
            .port
            .submit_initiate_payout(launcher_id, entry.payout_puzzle_hash, fee)
            .await
        {
            Ok(()) => {
                self.status.claims_submitted += 1;
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

    /// ACCEPTANCE 6 — no entry slot is terminal, non-error, and reports neither a chain fault nor
    /// a lost payment; the SECOND tick performs zero retries against that distributor.
    #[tokio::test]
    async fn no_entry_slot_is_terminal_and_not_retried() {
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
        assert!(
            second.is_empty(),
            "terminal distributor is skipped, not retried"
        );
        assert_eq!(
            *e.port.own_entry_reads.lock().unwrap(),
            reads_after_first,
            "zero retries on the next tick"
        );
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
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;
        assert!(outcomes.is_empty());
        assert_eq!(e.status().distributors_known, 0);
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
