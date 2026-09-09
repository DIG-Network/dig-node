//! The claim loop's one tick: discover, evaluate, claim — driven against [`ClaimChainPort`] and
//! [`DistributorHintSource`], never against a concrete chain client (see the module doc's "chain
//! seam" section).

use std::path::{Path, PathBuf};

use chia_protocol::Bytes32;

use super::config::RewardsClaimConfig;
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
    /// Defect B2: which launcher id the per-cycle budget cut off LAST, so the next cycle gives that
    /// one first crack instead of it being permanently outranked. This only breaks TIES among
    /// candidates with equal accrued value (see [`Self::order_for_budget`]) — it can never let a
    /// lower-accrued distributor (an attacker's dust) jump ahead of a genuinely higher-earning one,
    /// because accrued value is always the primary sort key. `None` until a cycle first defers
    /// someone for budget. Persisted alongside [`super::config::RewardsClaimConfig`] (via
    /// [`Self::with_rotation_cursor`] / [`Self::rotation_cursor`]) so a restart does not re-arm a
    /// fresh queue and starve the tail forever.
    rotation_cursor: Option<Bytes32>,

    /// F7: when `Some`, this engine persists [`Self::fee_window_start_unix`],
    /// [`Self::fee_spent_in_window_mojos`] and [`Self::last_cycle_completed_at`] into
    /// [`RewardsClaimConfig`] in this directory -- see [`Self::with_persisted_fee_window`]. `None`
    /// keeps the engine purely in-memory, the behaviour every test before F7 relies on.
    fee_window_state_dir: Option<PathBuf>,
    /// F7: the cadence length the persisted budget window and the cadence gate are measured
    /// against. Deliberately a constructor argument of [`Self::with_persisted_fee_window`], never
    /// read from [`RewardsClaimConfig::cadence_seconds`] directly -- the engine has no other
    /// dependency on the rest of that config, and the caller (which already loaded it) is the one
    /// place that should decide what "the cadence" means.
    cadence_seconds: u64,
    /// F7: the start (unix seconds) of the current aggregate-fee-budget window -- see
    /// [`super::config::RewardsClaimConfig::fee_window_start_unix`].
    fee_window_start_unix: Option<u64>,
    /// F7: fee mojos already spent inside the current window -- the field that actually bounds a
    /// crash-restart loop. See [`super::config::RewardsClaimConfig::fee_spent_in_window_mojos`].
    fee_spent_in_window_mojos: u64,
    /// F7: when the last cycle that ran to completion finished -- the cadence gate's clock. See
    /// [`super::config::RewardsClaimConfig::last_cycle_completed_at`].
    last_cycle_completed_at: Option<u64>,
    /// F8/F10: set by [`Self::with_persisted_fee_window`] when the loaded
    /// [`RewardsClaimConfig`] was [`RewardsClaimConfig::corrupt`] (unreadable, unparsable, or a
    /// spend exceeding its own budget), OR discovered at the top of [`Self::run_cycle`] when
    /// either persisted clock reads AFTER `now` (a future-dated clock is corrupt state exactly
    /// the same way, F10). Either way this fails CLOSED: the window reads as fully spent and no
    /// candidate is evaluated, rather than silently loading [`RewardsClaimConfig::default`] and
    /// re-granting a budget (F8) or silently freezing forever under a healthy-looking state (the
    /// pre-F9 reading of F10).
    fee_window_poisoned: bool,
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
            rotation_cursor: None,
            fee_window_state_dir: None,
            cadence_seconds: 0,
            fee_window_start_unix: None,
            fee_spent_in_window_mojos: 0,
            last_cycle_completed_at: None,
            fee_window_poisoned: false,
        }
    }

    /// Restores the per-cycle budget rotation cursor (Defect B2) from persisted state — the
    /// production wiring (DIG-Network/dig_ecosystem#3268) loads it from
    /// [`super::config::RewardsClaimConfig`] alongside the rest of this loop's preferences.
    #[must_use]
    pub fn with_rotation_cursor(mut self, cursor: Option<Bytes32>) -> Self {
        self.rotation_cursor = cursor;
        self
    }

    /// The current budget rotation cursor (Defect B2) — persist this after every `run_cycle` so a
    /// restart resumes the rotation instead of restarting it and re-starving the same tail.
    #[must_use]
    pub fn rotation_cursor(&self) -> Option<Bytes32> {
        self.rotation_cursor
    }

    /// F7: restores the persisted aggregate-fee-budget window and cadence clock from `dir` and
    /// arms this engine to keep persisting them there after every submission and every completed
    /// cycle (never batched to cycle end — see [`Self::run_cycle`]'s "F7" doc section for why).
    ///
    /// `cadence_seconds` is both the window length and the cadence gate's threshold: the same
    /// number [`super::config::RewardsClaimConfig::cadence_seconds`] carries, passed in explicitly
    /// because this engine has no other dependency on the rest of that config.
    ///
    /// Without this call, the engine is exactly as it was before F7: a fresh
    /// [`Self::cycle_fee_budget_mojos`] and no cadence gate on every construction. That is
    /// deliberately still true for a caller that has not opted in (every pre-F7 test), but it is
    /// also the defect this method exists to close for production use: nothing here is wired into
    /// node startup yet (`crate::rewards_claim`'s module doc, "Not yet wired into node startup"),
    /// so the production wiring (#3268) is the one place expected to call this.
    /// F10 (§8.6 floor): also applied here, not just in [`RewardsClaimConfig::load_from`] --
    /// this is a constructor argument, independent of whatever the config file says, and the same
    /// hot-loop hazard applies to whatever caller passes it a degenerate value directly.
    #[must_use]
    pub fn with_persisted_fee_window(mut self, dir: &Path, cadence_seconds: u64) -> Self {
        let cfg = RewardsClaimConfig::load_from(dir);
        self.fee_window_state_dir = Some(dir.to_path_buf());
        self.cadence_seconds = cadence_seconds.max(super::config::CLAIM_CADENCE_FLOOR_SECONDS);
        self.fee_window_poisoned = cfg.corrupt;
        self.fee_window_start_unix = cfg.fee_window_start_unix;
        self.fee_spent_in_window_mojos = cfg.fee_spent_in_window_mojos;
        self.last_cycle_completed_at = cfg.last_cycle_completed_at;
        self
    }

    /// F7: read-modify-write the fee-window fields into whatever `RewardsClaimConfig` currently
    /// sits on disk at [`Self::fee_window_state_dir`], leaving every other field (including
    /// [`Self::rotation_cursor`], which this engine does not own writing to disk for) exactly as
    /// it was read. A failed write is logged, never fatal — the same survivable-degradation
    /// posture [`super::config::RewardsClaimConfig::load_from`] already uses for a read.
    ///
    /// # F8: never overwrites a corrupt file with defaults
    /// If the file on disk has gone corrupt SINCE this engine last read it (a concurrent write, or
    /// disk damage between calls), the fresh `load_from` above returns [`RewardsClaimConfig`] with
    /// `corrupt: true` -- writing our in-memory fee-window fields into that value and saving it
    /// would silently paper over the corruption with a value that looks clean (defaulted `enabled`,
    /// a dropped `rotation_cursor`, exactly the "worse" half of the F8 finding). Refuse instead:
    /// leave the corrupt file exactly as it is on disk and let the NEXT `run_cycle` observe
    /// `corrupt` itself and report [`ClaimLoopState::PersistedStateCorrupt`].
    fn persist_fee_window(&self) {
        let Some(dir) = &self.fee_window_state_dir else {
            return;
        };
        let mut cfg = RewardsClaimConfig::load_from(dir);
        if cfg.corrupt {
            tracing::warn!(
                path = %dir.display(),
                "the rewards-claim preference file is corrupt on disk; refusing to overwrite it \
                 with a fee-window update"
            );
            return;
        }
        cfg.fee_window_start_unix = self.fee_window_start_unix;
        cfg.fee_spent_in_window_mojos = self.fee_spent_in_window_mojos;
        cfg.last_cycle_completed_at = self.last_cycle_completed_at;
        if let Err(e) = cfg.save_to(dir) {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "the rewards-claim fee-budget window could not be persisted"
            );
        }
    }

    #[must_use]
    pub fn status(&self) -> ClaimStatus {
        self.status
    }

    /// Run one cycle: discover candidates (chain + re-derived hints), evaluate each against SPEC
    /// §9.3/§8.3/§12.5, then claim from the above-threshold set in DESCENDING ACCRUED-VALUE ORDER
    /// (Defect B2) within the per-claim ceiling AND the per-cycle aggregate fee budget. Returns
    /// every outcome, one per evaluated distributor.
    pub async fn run_cycle(&mut self, now: u64) -> Vec<ClaimOutcome> {
        // Defect A1/A4/F1/F3: EVERY per-cycle field is reset here, at the TOP, before any early
        // return — a fault, a claim count or a stale distributor tally from a PAST cycle must never
        // leak into this cycle's reading, including on the `ChainUnavailable` early-return paths
        // below that skip the end-of-function assignment block entirely (F3: those paths used to
        // leave last cycle's `distributors_claimable` / `claims_submitted_this_cycle` /
        // `distributors_faulted` / `no_entry_slot_this_cycle` sitting stale under this cycle's
        // freshly-stamped `last_attempt_at`).
        self.status.fault_reported = false;
        self.status.chain_unavailable_this_cycle = false;
        self.status.payout_hash_mismatches_this_cycle = 0;
        self.status.distributors_known = 0;
        self.status.distributors_with_own_entry = 0;
        self.status.distributors_claimable = 0;
        self.status.distributors_faulted = 0;
        self.status.claims_submitted_this_cycle = 0;
        self.status.no_entry_slot_this_cycle = 0;
        self.status.last_attempt_at = Some(now);

        // F7: the cadence gate and the persisted budget window -- both keyed off
        // `self.fee_window_state_dir`, so a caller that never opted in via
        // `with_persisted_fee_window` sees no change at all (every pre-F7 test).
        if self.fee_window_state_dir.is_some() {
            // F8/F10: a corrupt persisted file, or either persisted clock reading AFTER `now` (a
            // future-dated clock is corrupt state exactly the same way a torn write is -- an
            // ordinary NTP step or clock glitch would otherwise freeze the window forever, F10),
            // must never be treated as a fresh start. Fail CLOSED: submit nothing, report it by
            // name, and -- critically -- return BEFORE the cadence gate and the window-roll logic
            // below, which would otherwise happily manufacture a brand-new zeroed window out of
            // untrustworthy state.
            let future_dated_clock = self.last_cycle_completed_at.is_some_and(|t| t > now)
                || self.fee_window_start_unix.is_some_and(|t| t > now);
            if self.fee_window_poisoned || future_dated_clock {
                self.fee_window_poisoned = true;
                self.status.state = ClaimLoopState::PersistedStateCorrupt;
                return Vec::new();
            }
            // Refuse to START a cycle until the cadence has elapsed since the last one that ran
            // to completion -- stops a restart loop from immediately re-running a cycle that
            // already ran, independent of whether the fee window below has room left.
            //
            // F9: this is a DELIBERATE skip, not a fault and not silence -- name it, so it can
            // never read as "healthy and idle" (a stale `state` from whatever cycle last computed
            // one would otherwise stand here forever, since this path never reaches
            // `compute_state` below).
            if let Some(last_completed) = self.last_cycle_completed_at {
                if now.saturating_sub(last_completed) < self.cadence_seconds {
                    self.status.state = ClaimLoopState::CadenceNotElapsed;
                    return Vec::new();
                }
            }
            // The aggregate budget is enforced against this window, never a per-`run_cycle`
            // local: roll a fresh window only once the cadence has elapsed since it opened,
            // otherwise keep accumulating into what is already spent in it.
            let window_still_open = self
                .fee_window_start_unix
                .is_some_and(|start| now.saturating_sub(start) < self.cadence_seconds);
            if !window_still_open {
                self.fee_window_start_unix = Some(now);
                self.fee_spent_in_window_mojos = 0;
                self.persist_fee_window();
            }
        }
        let mut spent_this_cycle_mojos = if self.fee_window_state_dir.is_some() {
            self.fee_spent_in_window_mojos
        } else {
            0
        };
        let mut budget_exhausted = false;

        let mut discovery_failed = false;
        let discovered = match self.port.discover_distributors().await {
            Ok(v) => v,
            Err(ClaimPortError::Unavailable) => {
                // F1: per-cycle only — never a latch. See `ClaimStatus::chain_unavailable_this_cycle`.
                self.status.chain_unavailable_this_cycle = true;
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
        // F4: a real adapter can plausibly return the same launcher id twice (one distributor
        // reachable via two of the §1.3 launch comments this node scans, across the
        // `(store_id, root)` pairs it mirrors). Without this, phase 2 would evaluate it twice and
        // submit `InitiatePayout` twice against one entry slot in one cycle -- the second spend is
        // invalid (counter already incremented) but the fee is paid anyway, double-charging the
        // cycle budget for a single distributor.
        candidates.sort_unstable();
        candidates.dedup();

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
        let mut faulted = 0u32;
        let mut submitted_this_cycle = 0u64;
        let mut no_entry_this_cycle = 0u32;
        let mut eligible: Vec<EligibleClaim> = Vec::new();

        // Phase 1: everything up to (and including) the payout-threshold check, for every
        // candidate — none of this touches the per-cycle budget. Above-threshold candidates become
        // `Eligible` and move to phase 2 instead of being decided here.
        for launcher_id in candidates {
            // Defect B: no permanent blacklist skip here — every candidate is re-evaluated every
            // cycle, including one that reported `NoEntrySlot` on a prior cycle.
            match self.evaluate_pre_budget(launcher_id).await {
                PreBudgetResult::Fault => faulted += 1,
                PreBudgetResult::ChainUnavailable => {
                    self.status.chain_unavailable_this_cycle = true;
                    self.status.state = ClaimLoopState::ChainSourceUnavailable;
                    return outcomes;
                }
                PreBudgetResult::Eligible {
                    launcher_id,
                    accrued_base_units,
                } => {
                    with_entry += 1;
                    eligible.push(EligibleClaim {
                        launcher_id,
                        accrued_base_units,
                    });
                }
                PreBudgetResult::Outcome(outcome, entry_seen) => {
                    if entry_seen {
                        with_entry += 1;
                    }
                    if let ClaimOutcome::NoEntrySlot { .. } = &outcome {
                        no_entry_this_cycle += 1;
                    }
                    outcomes.push(outcome);
                }
            }
        }

        // Defect B1/E: every `Eligible` candidate is claimable regardless of what phase 2 later
        // decides for it (submitted, ceiling-skipped or budget-skipped all count) — matching what
        // `distributors_claimable` always meant here.
        let claimable = u32::try_from(eligible.len()).unwrap_or(u32::MAX);

        // Phase 2: order by accrued value DESCENDING (Defect B2) — an attacker's dust distributors
        // (our own entry there accrues little to nothing) always sort behind a victim's genuine
        // earnings, regardless of the fee the attacker sets. The persisted rotation cursor only
        // breaks TIES within an accrued-value tier, so it can never let a lower-value distributor
        // displace a higher-value one; see `Self::order_for_budget`.
        let ordered = self.order_for_budget(eligible);
        let mut first_deferred_this_cycle: Option<Bytes32> = None;
        for claim in &ordered {
            match self
                .evaluate_budget_phase(claim, &mut spent_this_cycle_mojos, &mut budget_exhausted)
                .await
            {
                BudgetPhaseResult::Fault => faulted += 1,
                BudgetPhaseResult::ChainUnavailable => {
                    self.status.chain_unavailable_this_cycle = true;
                    self.status.state = ClaimLoopState::ChainSourceUnavailable;
                    return outcomes;
                }
                BudgetPhaseResult::Outcome(outcome) => {
                    match &outcome {
                        ClaimOutcome::Submitted { .. } => submitted_this_cycle += 1,
                        ClaimOutcome::SkippedCycleBudgetExhausted { .. }
                            if first_deferred_this_cycle.is_none() =>
                        {
                            first_deferred_this_cycle = Some(claim.launcher_id);
                        }
                        _ => {}
                    }
                    outcomes.push(outcome);
                }
            }
        }
        // Defect B2: advance the rotation cursor to whoever the budget cut off FIRST this cycle, so
        // that one gets first crack next cycle instead of the same tail being dropped every time.
        if let Some(deferred) = first_deferred_this_cycle {
            self.rotation_cursor = Some(deferred);
        }

        // Defect A4: an all-faulted cycle (candidates existed, discovery succeeded, but every one of
        // them faulted) must not stamp `last_cycle_at` either — same staleness reasoning as above.
        let all_faulted_cycle = any_candidates && outcomes.is_empty() && self.status.fault_reported;

        self.status.distributors_with_own_entry = with_entry;
        self.status.distributors_claimable = claimable;
        self.status.distributors_faulted = faulted;
        self.status.claims_submitted += submitted_this_cycle;
        self.status.claims_submitted_this_cycle = submitted_this_cycle;
        self.status.no_entry_slot_this_cycle = no_entry_this_cycle;
        self.status.consecutive_faulted_cycles = if self.status.fault_reported {
            self.status.consecutive_faulted_cycles + 1
        } else {
            0
        };
        if !discovery_failed && !all_faulted_cycle {
            self.status.last_cycle_at = Some(now);
        }
        // F7: this cycle ran to completion (every early return above -- ChainUnavailable -- skips
        // this line, which is exactly right: those never reached the cadence gate's definition of
        // "ran" -- F9: neither does the `CadenceNotElapsed` / `PersistedStateCorrupt` early
        // returns above, for the same reason: none of these ever reached the point where a cycle
        // is considered to have run). Stamp and persist unconditionally, including a fault-only or
        // all-faulted cycle -- an operator restarting to work around a wedged cycle must still get
        // the cadence gate's protection, not a loophole that lets a fault re-arm an immediate
        // retry.
        if self.fee_window_state_dir.is_some() {
            self.last_cycle_completed_at = Some(now);
            self.persist_fee_window();
        }
        // F1: unconditional now -- `compute_state` reads `chain_unavailable_this_cycle` (reset at
        // the top of this function), never `self.state`, so the old "don't overwrite a latch" guard
        // is gone along with the latch itself.
        self.status.state = self.status.compute_state();
        outcomes
    }

    /// Everything up to and including the payout-threshold check (SPEC §9.3, §12.5, §8.6) — none of
    /// it depends on, or affects, the per-cycle budget. An above-threshold, hash-matching entry
    /// becomes `Eligible` and is decided in [`Self::evaluate_budget_phase`] instead.
    async fn evaluate_pre_budget(&mut self, launcher_id: Bytes32) -> PreBudgetResult {
        let asset = match self.port.reserve_asset_id(launcher_id).await {
            Ok(a) => a,
            Err(ClaimPortError::Unavailable) => return PreBudgetResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return PreBudgetResult::Fault;
            }
        };
        if asset != self.dig_asset_id {
            // SPEC §9.3: not ours, dropped — not counted as known/claimable.
            return PreBudgetResult::Outcome(ClaimOutcome::NotOurs { launcher_id }, false);
        }

        // SPEC §12.5 clause 3: re-read the entry slot fresh on EVERY call — never cached.
        let entry = match self
            .port
            .own_entry(launcher_id, self.own_payout_puzzle_hash)
            .await
        {
            Ok(Some(e)) => e,
            Ok(None) => {
                return PreBudgetResult::Outcome(ClaimOutcome::NoEntrySlot { launcher_id }, false);
            }
            Err(ClaimPortError::Unavailable) => return PreBudgetResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return PreBudgetResult::Fault;
            }
        };

        if entry.payout_puzzle_hash != self.own_payout_puzzle_hash {
            // Defect E: the port handed back an entry for a puzzle hash that is not this node's own.
            // Submitting against it would pay someone else. Refuse -- never substitute our own hash
            // and proceed.
            //
            // Defect B3: this is a PER-DISTRIBUTOR problem, not a cycle-wide one -- it must never
            // set `fault_reported` (that pins the whole surface at `Faulted`, permanently, since the
            // refusal is deliberately non-terminal and recurs every cycle). Count it instead, both
            // lifetime and per-cycle, and let `ClaimableButNotClaiming` (or `Nominal`, if everything
            // else claimed) surface it.
            self.status.claims_refused_payout_mismatch += 1;
            self.status.payout_hash_mismatches_this_cycle += 1;
            return PreBudgetResult::Outcome(
                ClaimOutcome::PayoutPuzzleHashMismatch { launcher_id },
                true,
            );
        }

        let threshold = match self.port.payout_threshold(launcher_id).await {
            Ok(t) => t,
            Err(ClaimPortError::Unavailable) => return PreBudgetResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return PreBudgetResult::Fault;
            }
        };

        if entry.accrued_base_units < threshold {
            self.status.claims_skipped_below_threshold += 1;
            return PreBudgetResult::Outcome(
                ClaimOutcome::SkippedBelowThreshold {
                    launcher_id,
                    accrued: entry.accrued_base_units,
                    threshold,
                },
                true,
            );
        }

        PreBudgetResult::Eligible {
            launcher_id,
            accrued_base_units: entry.accrued_base_units,
        }
    }

    /// Orders the above-threshold candidates for the budget pass (Defect B2): primarily by accrued
    /// value DESCENDING, so an attacker's dust distributors — where this node's own entry accrues
    /// little to nothing — always sort behind a victim's genuine earnings no matter what fee the
    /// attacker sets. The persisted [`Self::rotation_cursor`] only breaks ties WITHIN an equal-value
    /// tier: it rebuilds a byte-order canonical ranking of the candidates present this cycle, then
    /// rotates that ranking so the cursor's own launcher id sorts first — guaranteeing a genuinely
    /// tied, budget-exceeding honest tail eventually reaches the front, without ever letting a
    /// lower-value candidate outrank a higher-value one.
    fn order_for_budget(&self, mut eligible: Vec<EligibleClaim>) -> Vec<EligibleClaim> {
        let mut canonical: Vec<Bytes32> = eligible.iter().map(|c| c.launcher_id).collect();
        canonical.sort();
        let cursor_index = self
            .rotation_cursor
            .and_then(|cursor| canonical.iter().position(|id| *id == cursor))
            .unwrap_or(0);
        let len = canonical.len();
        let rotation_key = |id: &Bytes32| -> usize {
            let pos = canonical.iter().position(|x| x == id).unwrap_or(0);
            if len == 0 {
                0
            } else {
                (pos + len - cursor_index) % len
            }
        };
        eligible.sort_by(|a, b| {
            b.accrued_base_units
                .cmp(&a.accrued_base_units)
                .then_with(|| rotation_key(&a.launcher_id).cmp(&rotation_key(&b.launcher_id)))
        });
        eligible
    }

    /// The fee ceiling, per-cycle budget and submission for one already-`Eligible` candidate (SPEC
    /// §8.3, Defect C1/C2). The payout puzzle hash is `self.own_payout_puzzle_hash` unconditionally
    /// — [`Self::evaluate_pre_budget`] already refused any entry that diverged from it.
    async fn evaluate_budget_phase(
        &mut self,
        claim: &EligibleClaim,
        spent_this_cycle_mojos: &mut u64,
        budget_exhausted: &mut bool,
    ) -> BudgetPhaseResult {
        let launcher_id = claim.launcher_id;
        let fee = match self.port.required_fee_mojos(launcher_id).await {
            Ok(f) => f,
            Err(ClaimPortError::Unavailable) => return BudgetPhaseResult::ChainUnavailable,
            Err(ClaimPortError::Other(_)) => {
                self.status.fault_reported = true;
                return BudgetPhaseResult::Fault;
            }
        };

        if fee > self.max_fee_mojos {
            self.status.claims_skipped_fee_ceiling += 1;
            return BudgetPhaseResult::Outcome(ClaimOutcome::SkippedFeeAboveCeiling {
                launcher_id,
                fee_mojos: fee,
                ceiling_mojos: self.max_fee_mojos,
            });
        }

        // Defect C2: the per-claim ceiling alone does not bound what K distributors can collectively
        // force this node to spend in one cycle. Once the cycle budget is gone, every remaining
        // candidate is skipped the same way, not spent past it.
        //
        // F14: `saturating_add`, never a bare `+` -- `spent_this_cycle_mojos` is seeded from a
        // persisted value (`RewardsClaimConfig::fee_spent_in_window_mojos`) on the very first
        // candidate of a cycle. `config::RewardsClaimConfig::load_from` now rejects a spend
        // exceeding its own budget at load time (fails closed, see F8), but this comparison must
        // not ALSO be able to panic on a `u64` overflow if that guard is ever bypassed -- the
        // workspace enables `overflow-checks` in release, so an unchecked add here is a live
        // panic-on-corrupt-input path, not just a debug-build lint.
        if *budget_exhausted
            || spent_this_cycle_mojos.saturating_add(fee) > self.cycle_fee_budget_mojos
        {
            *budget_exhausted = true;
            self.status.claims_skipped_cycle_budget += 1;
            return BudgetPhaseResult::Outcome(ClaimOutcome::SkippedCycleBudgetExhausted {
                launcher_id,
                fee_mojos: fee,
                budget_mojos: self.cycle_fee_budget_mojos,
            });
        }

        // F7: write-then-spend, never spend-then-write. If persistence is armed, the fee this
        // submission is about to cost is committed to disk BEFORE the chain call, not after --
        // so a crash between "we decided to spend" and the chain call returning can never leave
        // an unpersisted spend that a restart would repeat. This pre-commit is deliberately
        // conservative: a genuine crash mid-`await` never returns to the `match` below at all, so
        // the only way to protect against THAT case is to have already written the spend before
        // making the call.
        if self.fee_window_state_dir.is_some() {
            self.fee_spent_in_window_mojos = self.fee_spent_in_window_mojos.saturating_add(fee);
            self.persist_fee_window();
        }

        match self
            .port
            .submit_initiate_payout(launcher_id, self.own_payout_puzzle_hash, fee)
            .await
        {
            Ok(()) => {
                *spent_this_cycle_mojos += fee;
                BudgetPhaseResult::Outcome(ClaimOutcome::Submitted { launcher_id })
            }
            // F12: the call HAS resolved here, with a definite answer -- unlike the crash case
            // above, "no" means the fee was never broadcast (`ClaimPortError::Unavailable`: never
            // even reached the network; `Other(_)`: the network is reachable but the submission
            // was rejected). Charging the persisted window for a fee that never left would let an
            // attacker exhaust this node's per-cycle budget for free with K always-failing
            // submissions, suppressing a victim's real claims for the rest of the window at zero
            // cost -- reverse the pre-commit now that we know it did not consume a fee.
            Err(ClaimPortError::Unavailable) => {
                self.uncommit_fee(fee);
                BudgetPhaseResult::ChainUnavailable
            }
            Err(ClaimPortError::Other(_)) => {
                self.uncommit_fee(fee);
                self.status.fault_reported = true;
                BudgetPhaseResult::Fault
            }
        }
    }

    /// F12: reverses a pre-committed persisted spend once [`Self::evaluate_budget_phase`]'s
    /// submission call has DEFINITELY returned without broadcasting -- see that method's "F12"
    /// doc comment for why the pre-commit itself must stay conservative for a genuine crash
    /// mid-call, which never reaches this method at all.
    fn uncommit_fee(&mut self, fee: u64) {
        if self.fee_window_state_dir.is_some() {
            self.fee_spent_in_window_mojos = self.fee_spent_in_window_mojos.saturating_sub(fee);
            self.persist_fee_window();
        }
    }
}

/// An above-threshold, hash-matching candidate waiting for the budget pass (Defect B2).
struct EligibleClaim {
    launcher_id: Bytes32,
    accrued_base_units: u64,
}

/// The outcome of [`ClaimEngine::evaluate_pre_budget`].
enum PreBudgetResult {
    /// `(outcome, entry_slot_was_present)`.
    Outcome(ClaimOutcome, bool),
    /// Above threshold, hash matches — proceeds to [`ClaimEngine::evaluate_budget_phase`].
    Eligible {
        launcher_id: Bytes32,
        accrued_base_units: u64,
    },
    Fault,
    ChainUnavailable,
}

/// The outcome of [`ClaimEngine::evaluate_budget_phase`].
enum BudgetPhaseResult {
    Outcome(ClaimOutcome),
    Fault,
    ChainUnavailable,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
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
        /// F12: launcher ids whose `submit_initiate_payout` must return
        /// `Err(ClaimPortError::Other(_))` -- simulates a submission that definitely never
        /// broadcast.
        fail_submit_for: Mutex<std::collections::HashSet<Bytes32>>,
        /// F15: when set, `submit_initiate_payout` snapshots the persisted spend at this
        /// directory into `submit_snapshots` BEFORE returning -- proving the write already
        /// landed on disk before the chain call resolves, not just before `run_cycle` returns.
        submit_snapshot_dir: Mutex<Option<std::path::PathBuf>>,
        submit_snapshots: Mutex<Vec<u64>>,
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
                fail_submit_for: Mutex::new(std::collections::HashSet::new()),
                submit_snapshot_dir: Mutex::new(None),
                submit_snapshots: Mutex::new(Vec::new()),
            }
        }

        /// F12: makes `submit_initiate_payout` for `id` return `Err(Other(_))` instead of `Ok`.
        fn fail_submit_for(&self, id: Bytes32) {
            self.fail_submit_for.lock().unwrap().insert(id);
        }

        /// F15: arms the pre-submit snapshot hook against `dir`.
        fn arm_submit_snapshot(&self, dir: std::path::PathBuf) {
            *self.submit_snapshot_dir.lock().unwrap() = Some(dir);
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
            if let Some(dir) = self.submit_snapshot_dir.lock().unwrap().clone() {
                let snapshot = RewardsClaimConfig::load_from(&dir).fee_spent_in_window_mojos;
                self.submit_snapshots.lock().unwrap().push(snapshot);
            }
            if self.fail_submit_for.lock().unwrap().contains(&launcher_id) {
                return Err(ClaimPortError::Other("simulated submission failure".into()));
            }
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
        assert_eq!(e.status().no_entry_slot_this_cycle, 1);
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

    /// **Defect B2 (blocking) -- the anti-suppression test.** Ten attacker-funded dust distributors
    /// (our own entry there accrues almost nothing, but each demands a fee big enough that ONE of
    /// them alone exhausts the cycle budget) must NOT prevent a genuinely high-accrual distributor
    /// from being claimed in the same cycle, no matter what order the chain sweep happens to return
    /// them in (`FakeChainPort` stores candidates in a `HashMap`, so discovery order here is exactly
    /// as arbitrary as a real chain sweep's).
    #[tokio::test]
    async fn dust_distributors_do_not_suppress_a_high_accrual_claim_in_the_same_cycle() {
        const DUST_FEE: u64 = 100;
        let victim = FakeDistributor {
            launcher_id: Bytes32::new([0xFFu8; 32]),
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold: 1_000,
            entry: Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 100_000, // genuinely high accrual
            }),
            fee_mojos: DUST_FEE,
        };
        let victim_id = victim.launcher_id;
        let mut distributors = vec![victim];
        for i in 0..10u8 {
            distributors.push(FakeDistributor {
                launcher_id: Bytes32::new([i; 32]),
                store_id: Bytes32::new([3u8; 32]),
                root: Bytes32::new([4u8; 32]),
                reserve_asset_id: DIG_ASSET_ID,
                payout_threshold: 1_000,
                entry: Some(super::super::types::OwnEntry {
                    payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                    counter: 0,
                    accrued_base_units: 1_100, // just above threshold -- dust, not zero
                }),
                fee_mojos: DUST_FEE, // funder-controlled: attacker sets this at will
            });
        }
        // The budget fits exactly ONE distributor's fee -- first-come order would let any dust
        // distributor that sorts ahead of the victim consume it entirely.
        let mut e = ClaimEngine::new(
            FakeChainPort::new(distributors),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            DUST_FEE,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, ClaimOutcome::Submitted { launcher_id } if *launcher_id == victim_id))
                .count(),
            1,
            "the high-accrual victim must be the one claimed, regardless of discovery order"
        );
        assert_eq!(
            e.status().claims_submitted,
            1,
            "the budget fits exactly one claim"
        );
        assert_eq!(
            e.status().claims_skipped_cycle_budget,
            10,
            "every dust distributor is deferred, never the victim"
        );
    }

    /// **Defect B2 (blocking) -- the fairness half.** A persisted rotation cursor must advance
    /// across cycles so a genuinely tied, budget-exceeding honest tail is not the same distributor
    /// dropped every cycle forever.
    #[tokio::test]
    async fn the_rotation_cursor_advances_so_a_tied_starved_tail_is_eventually_served() {
        const FEE: u64 = 10;
        const BUDGET: u64 = 20; // only 2 of 3 equal-value distributors fit per cycle
        let distributors: Vec<FakeDistributor> = (0..3u8)
            .map(|i| FakeDistributor {
                launcher_id: Bytes32::new([i + 1; 32]),
                store_id: Bytes32::new([3u8; 32]),
                root: Bytes32::new([4u8; 32]),
                reserve_asset_id: DIG_ASSET_ID,
                payout_threshold: 1_000,
                entry: Some(super::super::types::OwnEntry {
                    payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                    counter: 0,
                    accrued_base_units: 5_000, // EQUAL for all three -- a genuine tie
                }),
                fee_mojos: FEE,
            })
            .collect();
        let mut e = ClaimEngine::new(
            FakeChainPort::new(distributors),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            BUDGET,
            DIG_ASSET_ID,
        );

        let mut deferred_across_cycles: std::collections::HashSet<Bytes32> =
            std::collections::HashSet::new();
        for cycle in 1..=3u32 {
            let outcomes = e.run_cycle(u64::from(cycle) * 1_000).await;
            for outcome in &outcomes {
                if let ClaimOutcome::SkippedCycleBudgetExhausted { launcher_id, .. } = outcome {
                    deferred_across_cycles.insert(*launcher_id);
                }
            }
        }

        assert!(
            deferred_across_cycles.len() > 1,
            "the same distributor must not be the only one ever deferred across cycles -- got {deferred_across_cycles:?}"
        );
        assert!(
            e.rotation_cursor().is_some(),
            "the cursor must have advanced at least once"
        );
    }

    /// Defect B2: `with_rotation_cursor` / `rotation_cursor` are the seam a persisted config uses
    /// to survive a restart -- proves the getter reflects what the setter installed before any
    /// cycle has run.
    #[test]
    fn rotation_cursor_round_trips_through_the_engine_accessors() {
        let cursor = Bytes32::new([0x42u8; 32]);
        let e = engine(FakeChainPort::new(Vec::new())).with_rotation_cursor(Some(cursor));
        assert_eq!(e.rotation_cursor(), Some(cursor));
    }

    /// F7: a distributor whose required fee alone equals the whole cycle budget, so ONE submitted
    /// claim exhausts it completely -- makes every F7 test below unambiguous about whether a
    /// SECOND full budget was granted.
    fn budget_consuming_distributor(launcher_id: Bytes32, fee_mojos: u64) -> FakeDistributor {
        FakeDistributor {
            launcher_id,
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold: 1_000,
            entry: Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            fee_mojos,
        }
    }

    /// **F7 (blocking) — the restart reproducer.** Before the fix, a fresh [`ClaimEngine`] has an
    /// empty in-memory budget and cadence clock no matter what a PRIOR process already spent, so
    /// this must FAIL before the fix: the second engine submits its claim too, spending a second
    /// full [`CYCLE_BUDGET`] inside the same window a prior process already exhausted.
    #[tokio::test]
    async fn f7_restart_reproducer_a_second_engine_from_the_same_directory_refuses_to_overspend() {
        const CYCLE_BUDGET: u64 = 1_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f7-reproducer-")
            .tempdir()
            .expect("a scratch dir");

        let mut first = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(
                Bytes32::new([0x10u8; 32]),
                CYCLE_BUDGET,
            )]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let first_outcomes = first.run_cycle(1_000).await;
        assert_eq!(
            first_outcomes,
            vec![ClaimOutcome::Submitted {
                launcher_id: Bytes32::new([0x10u8; 32])
            }],
            "the first cycle must actually spend the whole budget, or this reproduces nothing"
        );
        drop(first);

        // A NEW process, seconds later — nowhere near CADENCE_SECONDS away — reconstructs the
        // engine from the SAME directory and faces a DIFFERENT distributor that also costs the
        // whole budget.
        let mut second = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(
                Bytes32::new([0x20u8; 32]),
                CYCLE_BUDGET,
            )]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let second_outcomes = second.run_cycle(1_010).await;

        let second_submitted = second_outcomes
            .iter()
            .filter(|o| matches!(o, ClaimOutcome::Submitted { .. }))
            .count();
        assert_eq!(
            second_submitted, 0,
            "a restart inside the same budget window must not be able to spend a second full \
             cycle budget -- a process restart is not a fresh peer"
        );
    }

    /// F7: ten simulated restarts inside ONE window must not collectively exceed the aggregate
    /// budget, however many of those restarts each try to spend a full budget's worth.
    #[tokio::test]
    async fn f7_ten_restarts_inside_one_window_never_collectively_exceed_the_budget() {
        const CYCLE_BUDGET: u64 = 1_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f7-ten-restarts-")
            .tempdir()
            .expect("a scratch dir");

        let mut total_submitted_mojos = 0u64;
        for i in 0..10u8 {
            let launcher_id = Bytes32::new([0x30 + i; 32]);
            let mut e = ClaimEngine::new(
                FakeChainPort::new(vec![budget_consuming_distributor(
                    launcher_id,
                    CYCLE_BUDGET,
                )]),
                NoHintSource,
                OUR_PAYOUT_PUZZLE_HASH,
                FEE_CEILING,
                CYCLE_BUDGET,
                DIG_ASSET_ID,
            )
            .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
            let outcomes = e.run_cycle(1_000 + u64::from(i)).await;
            if outcomes
                .iter()
                .any(|o| matches!(o, ClaimOutcome::Submitted { .. }))
            {
                total_submitted_mojos += CYCLE_BUDGET;
            }
        }

        assert!(
            total_submitted_mojos <= CYCLE_BUDGET,
            "ten restarts inside one window spent {total_submitted_mojos} mojos, over the \
             {CYCLE_BUDGET}-mojo budget"
        );
    }

    /// F7: once the window has genuinely elapsed, a restart MUST be allowed a fresh budget — the
    /// fix bounds a crash-restart loop, it does not starve a node that legitimately restarts
    /// between cadence periods.
    #[tokio::test]
    async fn f7_a_restart_after_the_window_elapsed_gets_a_fresh_budget() {
        const CYCLE_BUDGET: u64 = 1_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f7-window-elapsed-")
            .tempdir()
            .expect("a scratch dir");

        let mut first = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(
                Bytes32::new([0x40u8; 32]),
                CYCLE_BUDGET,
            )]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let first_outcomes = first.run_cycle(1_000).await;
        assert_eq!(
            first_outcomes,
            vec![ClaimOutcome::Submitted {
                launcher_id: Bytes32::new([0x40u8; 32])
            }]
        );
        drop(first);

        // Well past both the window AND the cadence gate.
        let later = 1_000 + CADENCE_SECONDS + 1;
        let mut second = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(
                Bytes32::new([0x50u8; 32]),
                CYCLE_BUDGET,
            )]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let second_outcomes = second.run_cycle(later).await;

        assert_eq!(
            second_outcomes,
            vec![ClaimOutcome::Submitted {
                launcher_id: Bytes32::new([0x50u8; 32])
            }],
            "a restart after the window elapsed must be granted a fresh budget"
        );
    }

    /// F7: a restart immediately after a completed cycle must not even START another cycle before
    /// the cadence elapses — independent of the fee-window check, this stops a fast restart loop
    /// from re-running full cycles (with their own chain reads) back to back.
    #[tokio::test]
    async fn f7_a_restart_immediately_after_a_completed_cycle_does_not_run_another() {
        const CYCLE_BUDGET: u64 = 1_000_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f7-cadence-gate-")
            .tempdir()
            .expect("a scratch dir");
        let launcher_id = Bytes32::new([0x60u8; 32]);

        let mut first = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let first_outcomes = first.run_cycle(1_000).await;
        assert_eq!(
            first_outcomes,
            vec![ClaimOutcome::Submitted { launcher_id }],
            "the first cycle must complete normally, or this proves nothing about a restart"
        );
        drop(first);

        let mut second = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let second_outcomes = second.run_cycle(1_050).await;

        assert_eq!(
            second_outcomes,
            Vec::new(),
            "a restart 50 seconds after a completed cycle must not run another before the \
             86,400-second cadence elapses"
        );
    }

    /// F7: a crash after a submission but before the cycle finishes must still leave that spend
    /// recorded on disk — proves the write happens PER SUBMISSION, never batched to cycle end.
    /// Simulated by reading the persisted config directly after a cycle that submits more than one
    /// claim, rather than waiting for `run_cycle` to return.
    #[tokio::test]
    async fn f7_a_spend_is_persisted_per_submission_not_batched_to_cycle_end() {
        const CYCLE_BUDGET: u64 = 30;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f7-per-submission-")
            .tempdir()
            .expect("a scratch dir");

        let distributors = vec![
            budget_consuming_distributor(Bytes32::new([0x70u8; 32]), 10),
            budget_consuming_distributor(Bytes32::new([0x71u8; 32]), 10),
        ];
        let mut e = ClaimEngine::new(
            FakeChainPort::new(distributors),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);

        let outcomes = e.run_cycle(1_000).await;
        let submitted: u64 = outcomes
            .iter()
            .filter(|o| matches!(o, ClaimOutcome::Submitted { .. }))
            .count() as u64
            * 10;
        assert_eq!(submitted, 20, "both distributors must have been submitted");

        // Read the file directly rather than through `e` -- proves the write already landed on
        // disk, not just in the engine's own in-memory mirror.
        let persisted = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(
            persisted.fee_spent_in_window_mojos, 20,
            "each submission must persist its own spend immediately, not wait for cycle end"
        );
    }

    /// F15: `f7_a_spend_is_persisted_per_submission_not_batched_to_cycle_end` above only reads the
    /// file AFTER `run_cycle` returns, which a cycle-end-batched persist would also satisfy --
    /// exactly the vacuous-test class F11 named. This test snapshots the file DURING each
    /// submission's own chain call, before that call (or `run_cycle`) has returned: the second
    /// distributor's snapshot can only show the first distributor's 10-mojo spend already on disk
    /// if persistence genuinely happens per submission. Must go red with the pre-commit in
    /// `evaluate_budget_phase` moved to after the `.await` (or to cycle end).
    #[tokio::test]
    async fn f15_a_spend_is_visible_on_disk_before_the_submission_call_resolves() {
        const CYCLE_BUDGET: u64 = 1_000_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f15-")
            .tempdir()
            .expect("a scratch dir");

        let distributors = vec![
            budget_consuming_distributor(Bytes32::new([0x72u8; 32]), 10),
            budget_consuming_distributor(Bytes32::new([0x73u8; 32]), 10),
        ];
        let port = FakeChainPort::new(distributors);
        port.arm_submit_snapshot(dir.path().to_path_buf());
        let mut e = ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);

        let outcomes = e.run_cycle(1_000).await;
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, ClaimOutcome::Submitted { .. }))
                .count(),
            2,
            "both distributors must have been submitted, or this proves nothing"
        );

        let snapshots = e.port.submit_snapshots.lock().unwrap().clone();
        assert_eq!(
            snapshots,
            vec![10, 20],
            "the first submission's own snapshot must already see ITS OWN pre-committed 10-mojo \
             spend (write-then-spend), and the second must see BOTH -- a cycle-end batch would \
             show 0 for both, since neither had landed on disk yet when these calls ran"
        );
    }

    /// F11: the two restart tests above (`f7_restart_reproducer_...` and `f7_ten_restarts_...`)
    /// advance the clock by ≤10s, so the CADENCE GATE alone makes them pass -- delete the window
    /// enforcement entirely and they still go green. This test satisfies the gate (no prior
    /// completed cycle at all, so it never even runs) and instead binds the window accumulator
    /// directly: a cycle the gate permits, entering a window that already carries a full persisted
    /// spend, must still be refused by the budget. Must go red with only the window-seeding line
    /// in `with_persisted_fee_window` (`self.fee_spent_in_window_mojos = cfg.fee_spent_in_window_
    /// mojos`) reverted to always start at `0`.
    #[tokio::test]
    async fn f11_a_gate_permitted_cycle_is_still_refused_by_an_already_full_persisted_window() {
        const CYCLE_BUDGET: u64 = 1_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f11-window-binds-")
            .tempdir()
            .expect("a scratch dir");

        // Simulate a crash mid-window: a prior process opened this window and spent it in full,
        // but never recorded a completed cycle (a real crash never gets that far either).
        let seeded = RewardsClaimConfig {
            fee_window_start_unix: Some(1_000),
            fee_spent_in_window_mojos: CYCLE_BUDGET,
            last_cycle_completed_at: None, // no completed cycle on record -- the gate is satisfied
            ..RewardsClaimConfig::default()
        };
        seeded.save_to(dir.path()).expect("seed the window");

        let launcher_id = Bytes32::new([0x74u8; 32]);
        let mut e = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);

        // Still well inside the seeded window (`1_000 + 5 - 1_000 = 5 < CADENCE_SECONDS`), so the
        // gate cannot be what refuses this -- only the window accumulator can.
        let outcomes = e.run_cycle(1_005).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::SkippedCycleBudgetExhausted {
                launcher_id,
                fee_mojos: 10,
                budget_mojos: CYCLE_BUDGET,
            }],
            "a window seeded as already fully spent must refuse every claim, even though the \
             cadence gate itself was satisfied"
        );
    }

    /// F9 regression: a deliberately-skipped cycle must report its OWN named condition, never a
    /// stale reading left over from the last cycle that actually ran. Must go red with only the
    /// `self.status.state = ClaimLoopState::CadenceNotElapsed;` assignment on the cadence-gate
    /// early return removed.
    #[tokio::test]
    async fn f9_a_cadence_skipped_cycle_reports_its_own_state_not_a_stale_one() {
        const CYCLE_BUDGET: u64 = 1_000_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f9-cadence-state-")
            .tempdir()
            .expect("a scratch dir");
        let launcher_id = Bytes32::new([0x75u8; 32]);

        let mut first = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let first_outcomes = first.run_cycle(1_000).await;
        assert_eq!(
            first_outcomes,
            vec![ClaimOutcome::Submitted { launcher_id }],
            "the first cycle must actually run and claim, or its state proves nothing to skip past"
        );
        assert_eq!(
            first.status().state,
            ClaimLoopState::Nominal,
            "sanity: the first cycle's OWN state must be something other than CadenceNotElapsed"
        );
        drop(first);

        let mut second = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);
        let second_outcomes = second.run_cycle(1_010).await;

        assert_eq!(
            second_outcomes,
            Vec::new(),
            "the cadence gate must still refuse to run"
        );
        assert_eq!(
            second.status().state,
            ClaimLoopState::CadenceNotElapsed,
            "a deliberately-skipped cycle must name itself, never read as the previous cycle's \
             Nominal (or any other stale) state"
        );
    }

    /// F10 regression: a future-dated `last_cycle_completed_at` (an NTP step, a clock glitch, or
    /// corrupt state) must not silently freeze the loop forever while reading healthy -- it must
    /// be a REPORTED condition. Must go red with only the `future_dated_clock` check removed (the
    /// old behaviour: `saturating_sub` yields 0, the cadence gate blocks the cycle, and — with F9
    /// fixed — that reads as `CadenceNotElapsed`, never `PersistedStateCorrupt` as asserted here).
    #[tokio::test]
    async fn f10_a_future_dated_clock_is_reported_not_silent() {
        const CYCLE_BUDGET: u64 = 1_000_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f10-future-clock-")
            .tempdir()
            .expect("a scratch dir");

        let far_future = 9_999_999_999u64;
        let seeded = RewardsClaimConfig {
            last_cycle_completed_at: Some(far_future),
            ..RewardsClaimConfig::default()
        };
        seeded
            .save_to(dir.path())
            .expect("seed a future-dated clock");

        let launcher_id = Bytes32::new([0x76u8; 32]);
        let mut e = ClaimEngine::new(
            FakeChainPort::new(vec![budget_consuming_distributor(launcher_id, 10)]),
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            Vec::new(),
            "a future-dated clock must submit nothing this cycle"
        );
        assert_eq!(
            e.status().state,
            ClaimLoopState::PersistedStateCorrupt,
            "a future-dated clock must be its own reported condition, never silent, and never \
             read as CadenceNotElapsed (which is what the old unvalidated saturating_sub bug \
             would produce once F9 is fixed)"
        );
    }

    /// F12 regression: a submission that DEFINITELY failed (the call returned `Err`, so it never
    /// broadcast) must not permanently inflate the persisted window -- that is free denial-of-
    /// service for an attacker running K always-failing submissions. Must go red with the
    /// `uncommit_fee` calls on the `Err` branches of `evaluate_budget_phase`'s `match` removed.
    #[tokio::test]
    async fn f12_a_failed_submission_does_not_inflate_the_persisted_window() {
        const CYCLE_BUDGET: u64 = 1_000_000;
        const CADENCE_SECONDS: u64 = 86_400;
        let dir = tempfile::Builder::new()
            .prefix("dig-node-f12-failed-submit-")
            .tempdir()
            .expect("a scratch dir");

        let failing = Bytes32::new([0x78u8; 32]);
        let d = budget_consuming_distributor(failing, 10);
        let port = FakeChainPort::new(vec![d]);
        port.fail_submit_for(failing);
        let mut e = ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        )
        .with_persisted_fee_window(dir.path(), CADENCE_SECONDS);

        let outcomes = e.run_cycle(1_000).await;
        assert_eq!(
            outcomes.len(),
            1,
            "the one candidate must have been evaluated, or this proves nothing about its fee"
        );
        assert!(matches!(outcomes[0], ClaimOutcome::PayoutPuzzleHashMismatch { .. }).not(),);

        let persisted = RewardsClaimConfig::load_from(dir.path());
        assert_eq!(
            persisted.fee_spent_in_window_mojos, 0,
            "a submission that definitely never broadcast must leave the persisted window \
             exactly as it was, not charged for a fee that was never spent"
        );
    }

    /// F14 regression: the per-cycle budget comparison must never panic on a corrupted or
    /// otherwise near-`u64::MAX` in-cycle spend total -- the workspace enables `overflow-checks`
    /// in release, so a bare `+` here is a live panic-on-corrupt-input path, not just a debug
    /// lint. Must go red (panic) with `saturating_add` reverted to a bare `+` in
    /// `evaluate_budget_phase`'s budget comparison.
    #[tokio::test]
    async fn f14_a_near_max_spent_value_does_not_panic_the_budget_comparison() {
        let d = budget_consuming_distributor(Bytes32::new([0x80u8; 32]), 10);
        let launcher_id = d.launcher_id;
        let mut e = engine(FakeChainPort::new(vec![d]));
        let mut spent_this_cycle_mojos = u64::MAX - 5;
        let mut budget_exhausted = false;
        let claim = EligibleClaim {
            launcher_id,
            accrued_base_units: 5_000,
        };

        let result = e
            .evaluate_budget_phase(&claim, &mut spent_this_cycle_mojos, &mut budget_exhausted)
            .await;

        assert!(
            matches!(
                result,
                BudgetPhaseResult::Outcome(ClaimOutcome::SkippedCycleBudgetExhausted { .. })
            ),
            "a near-overflow spent value must read as budget-exhausted, never panic and never \
             submit"
        );
    }

    /// Defect E regression: a port returning an entry whose `payout_puzzle_hash` diverges from this
    /// node's own must produce ZERO submissions -- never pay whoever the port named instead --
    /// counted both lifetime and per-cycle.
    ///
    /// Defect B3 regression: this used to also assert `fault_reported`, which set the CYCLE-WIDE
    /// `Faulted` state for a PER-DISTRIBUTOR problem -- see `a_payout_mismatch_never_sets_the_cycle_
    /// wide_fault_or_masks_other_distributors` below for the exploit this enabled.
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
            !e.status().fault_reported,
            "Defect B3: a per-distributor mismatch must never set the cycle-wide fault"
        );
        assert_eq!(e.status().claims_refused_payout_mismatch, 1);
        assert_eq!(e.status().payout_hash_mismatches_this_cycle, 1);
    }

    /// **Defect B3 (blocking) -- the exploit the review found.** A single hostile/buggy entry row
    /// (a payout-hash mismatch on one launcher) must NOT pin the whole surface at `Faulted` and
    /// must NOT bury the `ClaimableButNotClaiming` signal for every OTHER, healthy distributor.
    #[tokio::test]
    async fn a_payout_mismatch_never_sets_the_cycle_wide_fault_or_masks_other_distributors() {
        let wrong_hash = Bytes32::new([0x77u8; 32]);
        let mismatched = FakeDistributor {
            launcher_id: Bytes32::new([0xAAu8; 32]),
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold: 1_000,
            entry: Some(super::super::types::OwnEntry {
                payout_puzzle_hash: wrong_hash,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            fee_mojos: 10,
        };
        // A second, healthy distributor whose claim would exceed the budget alongside the
        // mismatched one's fee, so a fault-flag leak would be free to hide behind
        // `ClaimableButNotClaiming` too -- proving the precedence fix, not just the flag.
        let healthy = FakeDistributor {
            launcher_id: Bytes32::new([0xBBu8; 32]),
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold: 1_000,
            entry: Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            fee_mojos: 10,
        };
        let mut e = engine(FakeChainPort::new(vec![mismatched, healthy]));

        for cycle in 1..=3u32 {
            e.run_cycle(u64::from(cycle) * 1_000).await;
            assert!(
                !matches!(e.status().state, ClaimLoopState::Faulted { .. }),
                "cycle {cycle}: a per-distributor mismatch must never read as the cycle-wide Faulted"
            );
        }
        // F2 inversion: this assertion used to read `ClaimLoopState::Nominal` (an A2-class test
        // pinning the defect as intended behaviour). A live payout-hash mismatch is a real,
        // per-cycle shortfall exactly like an unmet `claimable` -- the healthy distributor
        // claiming does NOT make the surface healthy while the mismatched one is still refused
        // every cycle. `distributors_claimable` counts only the healthy one (1); the mismatch
        // never enters `eligible` so it is not in `claimable` either, but it IS folded into the
        // shortfall predicate's denominator, so `submitted (1) < claimable (1) + mismatches (1)`.
        assert_eq!(
            e.status().state,
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 1,
                submitted: 1
            },
            "an ongoing payout-hash mismatch is a real, per-cycle shortfall -- it must never read \
             as Nominal just because the OTHER distributor claimed"
        );
        assert_eq!(
            e.status().claims_submitted,
            3,
            "the healthy one claimed all 3 cycles"
        );
        assert_eq!(e.status().claims_refused_payout_mismatch, 3);
    }

    /// **F2 -- all-K-distributors mismatching must read as a shortfall, never `Nominal`.** Before
    /// the fix, a mismatch never entered `eligible`, so `claims_submitted_this_cycle` (0) and
    /// `distributors_claimable` (0) were BOTH zero and the magnitude comparison read healthy --
    /// the exact case the F2 brief calls out: "what if every distributor refuses for the same
    /// reason." This must be a shortfall (`ClaimableButNotClaiming`), and it must NOT reintroduce
    /// Defect B3 by setting the cycle-wide `Faulted`.
    #[tokio::test]
    async fn all_distributors_mismatching_is_a_shortfall_not_nominal() {
        let wrong_hash = Bytes32::new([0x77u8; 32]);
        let mismatched = FakeDistributor {
            launcher_id: Bytes32::new([0xAAu8; 32]),
            store_id: Bytes32::new([3u8; 32]),
            root: Bytes32::new([4u8; 32]),
            reserve_asset_id: DIG_ASSET_ID,
            payout_threshold: 1_000,
            entry: Some(super::super::types::OwnEntry {
                payout_puzzle_hash: wrong_hash,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            fee_mojos: 10,
        };
        let mut e = engine(FakeChainPort::new(vec![mismatched]));

        e.run_cycle(1_000).await;

        assert_eq!(
            e.status().distributors_claimable,
            0,
            "the mismatched distributor never enters eligible"
        );
        assert_eq!(e.status().claims_submitted_this_cycle, 0);
        assert!(
            !matches!(e.status().state, ClaimLoopState::Faulted { .. }),
            "a per-distributor mismatch must never set the cycle-wide Faulted (Defect B3)"
        );
        assert_eq!(
            e.status().state,
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 0,
                submitted: 0
            },
            "all-K-distributors mismatching is a real, systemic shortfall -- it must never read \
             as Nominal just because nothing entered `eligible`"
        );
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

    /// A discovery port that answers `Unavailable` on its FIRST call only, then delegates every
    /// call (including later `discover_distributors` calls) to a healthy inner `FakeChainPort` --
    /// modelling a node still syncing, or one dropped connection, exactly as F1 describes.
    struct FlakyThenHealthyPort {
        // An atomic counter, not a `Mutex<u32>` -- a guard held across the `.await` below would
        // make this port's future not `Send`, which `#[async_trait]`'s generated signature
        // requires. Nothing here needs a lock: it is a single counter, never held past its own
        // increment.
        calls: AtomicU32,
        inner: FakeChainPort,
    }

    #[async_trait]
    impl ClaimChainPort for FlakyThenHealthyPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            let call_number = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_number == 1 {
                return Err(ClaimPortError::Unavailable);
            }
            self.inner.discover_distributors().await
        }
        async fn resolve_launch_comment(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            self.inner.resolve_launch_comment(launcher_id).await
        }
        async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            self.inner.reserve_asset_id(launcher_id).await
        }
        async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.inner.payout_threshold(launcher_id).await
        }
        async fn own_entry(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
        ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
            self.inner.own_entry(launcher_id, payout_puzzle_hash).await
        }
        async fn required_fee_mojos(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.inner.required_fee_mojos(launcher_id).await
        }
        async fn submit_initiate_payout(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
            fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            self.inner
                .submit_initiate_payout(launcher_id, payout_puzzle_hash, fee_mojos)
                .await
        }
    }

    /// **F1 regression -- the anti-latch test.** `ChainSourceUnavailable` must be a PER-CYCLE
    /// reading, never a process-lifetime latch. Cycle 1 hits the transient `Unavailable` port path
    /// and must report it honestly; cycle 2, once the chain answers again, MUST read `Nominal` --
    /// not the stale `ChainSourceUnavailable` from cycle 1 -- because a real claim submits.
    #[tokio::test]
    async fn a_transient_unavailable_cycle_does_not_latch_state_for_the_rest_of_the_process() {
        let distributor = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let launcher_id = distributor.launcher_id;
        let port = FlakyThenHealthyPort {
            calls: AtomicU32::new(0),
            inner: FakeChainPort::new(vec![distributor]),
        };
        let mut e = ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;
        assert!(outcomes.is_empty(), "cycle 1: no chain, no outcomes");
        assert_eq!(
            e.status().state,
            ClaimLoopState::ChainSourceUnavailable,
            "cycle 1: the transient unavailability must be reported honestly"
        );

        let outcomes = e.run_cycle(2_000).await;
        assert_eq!(
            outcomes,
            vec![ClaimOutcome::Submitted { launcher_id }],
            "cycle 2: the chain is healthy and a real claim is submitted"
        );
        assert_eq!(
            e.status().state,
            ClaimLoopState::Nominal,
            "cycle 2 MUST NOT still read ChainSourceUnavailable -- that is a process-lifetime \
             latch on the very state whose whole point is to be a live reading"
        );
    }

    /// A discovery port that answers healthily on its FIRST call, then `Unavailable` on every call
    /// after that -- the inverse of `FlakyThenHealthyPort`, for F3's staleness scenario.
    struct HealthyThenUnavailablePort {
        // Atomic, not `Mutex<u32>` -- see `FlakyThenHealthyPort`'s comment: a guard held across
        // the `.await` below would make this port's future not `Send`.
        calls: AtomicU32,
        inner: FakeChainPort,
    }

    #[async_trait]
    impl ClaimChainPort for HealthyThenUnavailablePort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            let call_number = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_number == 1 {
                return self.inner.discover_distributors().await;
            }
            Err(ClaimPortError::Unavailable)
        }
        async fn resolve_launch_comment(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            self.inner.resolve_launch_comment(launcher_id).await
        }
        async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            self.inner.reserve_asset_id(launcher_id).await
        }
        async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.inner.payout_threshold(launcher_id).await
        }
        async fn own_entry(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
        ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
            self.inner.own_entry(launcher_id, payout_puzzle_hash).await
        }
        async fn required_fee_mojos(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.inner.required_fee_mojos(launcher_id).await
        }
        async fn submit_initiate_payout(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
            fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            self.inner
                .submit_initiate_payout(launcher_id, payout_puzzle_hash, fee_mojos)
                .await
        }
    }

    /// **F3 regression -- staleness under a fresh timestamp.** Cycle 1 is healthy and submits a
    /// real claim (`distributors_claimable == 1`, `claims_submitted_this_cycle == 1`). Cycle 2 hits
    /// the `ChainUnavailable` early-return path, which skips the end-of-function assignment block
    /// entirely. Before the fix, cycle 1's counts stayed on `self.status` while `last_attempt_at`
    /// was stamped fresh for cycle 2 -- exactly the stale-count-under-a-fresh-timestamp §2.4
    /// forbids. Every per-cycle counter must read as this cycle's true zero.
    #[tokio::test]
    async fn a_chain_unavailable_cycle_does_not_leave_prior_cycles_counters_stale() {
        let distributor = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let port = HealthyThenUnavailablePort {
            calls: AtomicU32::new(0),
            inner: FakeChainPort::new(vec![distributor]),
        };
        let mut e = ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        e.run_cycle(1_000).await;
        assert_eq!(
            e.status().distributors_claimable,
            1,
            "cycle 1: healthy and claimable"
        );
        assert_eq!(
            e.status().claims_submitted_this_cycle,
            1,
            "cycle 1: submitted"
        );

        e.run_cycle(2_000).await;
        assert_eq!(e.status().state, ClaimLoopState::ChainSourceUnavailable);
        assert_eq!(
            e.status().distributors_claimable,
            0,
            "F3: cycle 1's claimable count must not survive under cycle 2's fresh last_attempt_at"
        );
        assert_eq!(
            e.status().claims_submitted_this_cycle,
            0,
            "F3: cycle 1's submission count must not survive into cycle 2"
        );
        assert_eq!(e.status().distributors_faulted, 0);
        assert_eq!(e.status().no_entry_slot_this_cycle, 0);
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
    /// A discovery port that returns the SAME launcher id twice from one `discover_distributors`
    /// call -- plausible for a real adapter scanning §1.3 launch comments across every
    /// `(store_id, root)` pair this node mirrors, when one distributor is reachable via two of
    /// them.
    struct DuplicatingDiscoveryPort(FakeChainPort);

    #[async_trait]
    impl ClaimChainPort for DuplicatingDiscoveryPort {
        async fn discover_distributors(
            &self,
        ) -> Result<Vec<DiscoveredDistributor>, ClaimPortError> {
            let mut v = self.0.discover_distributors().await?;
            let doubled = v.clone();
            v.extend(doubled);
            Ok(v)
        }
        async fn resolve_launch_comment(
            &self,
            launcher_id: Bytes32,
        ) -> Result<Option<DiscoveredDistributor>, ClaimPortError> {
            self.0.resolve_launch_comment(launcher_id).await
        }
        async fn reserve_asset_id(&self, launcher_id: Bytes32) -> Result<Bytes32, ClaimPortError> {
            self.0.reserve_asset_id(launcher_id).await
        }
        async fn payout_threshold(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.0.payout_threshold(launcher_id).await
        }
        async fn own_entry(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
        ) -> Result<Option<super::super::types::OwnEntry>, ClaimPortError> {
            self.0.own_entry(launcher_id, payout_puzzle_hash).await
        }
        async fn required_fee_mojos(&self, launcher_id: Bytes32) -> Result<u64, ClaimPortError> {
            self.0.required_fee_mojos(launcher_id).await
        }
        async fn submit_initiate_payout(
            &self,
            launcher_id: Bytes32,
            payout_puzzle_hash: Bytes32,
            fee_mojos: u64,
        ) -> Result<(), ClaimPortError> {
            self.0
                .submit_initiate_payout(launcher_id, payout_puzzle_hash, fee_mojos)
                .await
        }
    }

    /// **F4 (non-blocking, cheap) -- a duplicated launcher id must submit EXACTLY ONCE.** Without
    /// dedup, phase 2 evaluates the same candidate twice and pays the fee twice against one entry
    /// slot in one cycle; the second spend is invalid (`counter` already incremented) but the fee
    /// is spent anyway.
    #[tokio::test]
    async fn a_duplicated_launcher_id_submits_exactly_once() {
        let distributor = one_distributor(
            Some(super::super::types::OwnEntry {
                payout_puzzle_hash: OUR_PAYOUT_PUZZLE_HASH,
                counter: 0,
                accrued_base_units: 5_000,
            }),
            1_000,
            10,
        );
        let launcher_id = distributor.launcher_id;
        let port = DuplicatingDiscoveryPort(FakeChainPort::new(vec![distributor]));
        let mut e = ClaimEngine::new(
            port,
            NoHintSource,
            OUR_PAYOUT_PUZZLE_HASH,
            FEE_CEILING,
            CYCLE_BUDGET,
            DIG_ASSET_ID,
        );

        let outcomes = e.run_cycle(1_000).await;

        assert_eq!(
            outcomes,
            vec![ClaimOutcome::Submitted { launcher_id }],
            "exactly one submission for one distributor, even though discovery reported it twice"
        );
        assert_eq!(e.status().claims_submitted, 1);
        assert_eq!(
            e.status().distributors_known,
            1,
            "dedup collapses the duplicate"
        );
    }
}
