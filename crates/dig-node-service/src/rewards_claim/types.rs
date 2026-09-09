//! The data shapes the claim loop moves — deliberately named apart from #3250's `port.rs`
//! (`DistributorRef` / `EntrySlot`) because this side carries discovery provenance the funder side
//! has no concept of.

use chia_protocol::Bytes32;

/// A distributor this node has located on-chain and confirmed is ours (SPEC §1.3, §9.3): its launch
/// comment parsed and its reserve asset is `dig_constants::DIG_ASSET_ID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveredDistributor {
    pub launcher_id: Bytes32,
    pub store_id: Bytes32,
    pub root: Bytes32,
}

/// This node's own entry slot on one distributor (SPEC §10.2): keyed by a payout PUZZLE HASH, never
/// a pubkey, re-read fresh before every claim (SPEC §12.5 clause 3) and never cached across cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnEntry {
    pub payout_puzzle_hash: Bytes32,
    /// The slot's replay guard; `InitiatePayout` writes `counter + 1` (SPEC §10.2 clause 3).
    pub counter: u64,
    /// What this entry has accrued and not yet claimed, in $DIG base units.
    pub accrued_base_units: u64,
}

/// What one distributor's evaluation this cycle produced — never silently nothing.
///
/// Not `Copy` since [`Self::Faulted`] carries a `String` (the chain port's own bounded error text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// `InitiatePayout` was submitted for this launcher id.
    Submitted { launcher_id: Bytes32 },
    /// SPEC §8.6 final sentence: skipped, not failed — no spend, no fee.
    SkippedBelowThreshold {
        launcher_id: Bytes32,
        accrued: u64,
        threshold: u64,
    },
    /// The fee ceiling (`crate::mirror::signer::MIRROR_SPEND_FEE_CEILING_MOJOS`-derived, see
    /// [`super::config`]) would be exceeded — skipped, not failed.
    SkippedFeeAboveCeiling {
        launcher_id: Bytes32,
        fee_mojos: u64,
        ceiling_mojos: u64,
    },
    /// SPEC v0.1.3 §12.5: no entry slot for our puzzle hash this cycle — terminal for THIS claim
    /// attempt only, never for the distributor. Eviction already settled everything owed (SPEC
    /// §6.4), but §12.5 forbids caching an absence any more than a value and forbids a permanent
    /// per-distributor exclusion set: the loop keeps observing this distributor on §8.6's cadence,
    /// because a peer can re-enter after eviction (§12.5 clause 2's re-entry path).
    NoEntrySlot { launcher_id: Bytes32 },
    /// SPEC §9.3: the distributor's reserve asset is not `DIG_ASSET_ID` — not ours, dropped.
    NotOurs { launcher_id: Bytes32 },
    /// Defect C2: the per-cycle aggregate fee budget (`RewardsClaimConfig::max_cycle_fee_budget_mojos`)
    /// is exhausted — skipped, not failed, and every later candidate this cycle is skipped the same
    /// way rather than spent past the budget. Bounds what an attacker funding many distributors over
    /// a widely mirrored store can force this node to spend in one cycle.
    SkippedCycleBudgetExhausted {
        launcher_id: Bytes32,
        fee_mojos: u64,
        budget_mojos: u64,
    },
    /// Defect E: the port's `own_entry` returned an entry whose `payout_puzzle_hash` does not equal
    /// THIS node's own (`ClaimEngine::own_payout_puzzle_hash`). Paying it would send funds to
    /// somewhere that is not this node, so the claim is REFUSED — not corrected by substituting our
    /// own hash and proceeding. A mismatch means the port is confused or hostile, so it counts as a
    /// fault, never a routine skip.
    PayoutPuzzleHashMismatch { launcher_id: Bytes32 },
    /// The seventh case, added because the other six could only say a peer was legitimately not
    /// paid, never that something went wrong: a chain call for this launcher id returned
    /// `ClaimPortError::Other(_)` this cycle -- the chain answered but the call itself failed.
    /// Distinct from `ClaimPortError::Unavailable` (no chain reached at all -- a cycle-wide
    /// condition, surfaced as [`ClaimLoopState::ChainSourceUnavailable`], never per-launcher). Every
    /// one of `evaluate_pre_budget`'s three chain reads and `evaluate_budget_phase`'s two can
    /// produce this outcome; only the last of those five (`submit_initiate_payout` itself) is a
    /// genuine "we tried to pay you and the chain said no" -- the earlier four never got far enough
    /// to read a fee or attempt a spend. For a peer's money this is still the one fact worth
    /// reporting either way: nothing legitimate happened to this distributor this cycle, and unlike
    /// every variant above, it is not a deliberate, correct non-payment.
    ///
    /// The current [`super::port::ClaimPortError`] shape cannot distinguish "definitely never
    /// landed" from "landed, fate unknown" any further than this: `Other(_)` IS the chain giving a
    /// resolved answer (see `evaluate_budget_phase`'s "F12" doc comment), so every site that
    /// produces this outcome already knows the call did not succeed and, by construction, that no
    /// fee is left committed for it (either none was ever read, or it was read, pre-committed to
    /// the persisted window, and reversed by `ClaimEngine::uncommit_fee` before this outcome was
    /// built). There is no "fate unknown" case reachable today; if one is ever added (e.g. a
    /// request that times out with no chain answer at all), it needs its own variant rather than
    /// being folded in here, because it could not carry the same "no money moved" guarantee.
    Faulted {
        launcher_id: Bytes32,
        /// `Some(fee)` only when a fee was pre-committed to the persisted fee window and then
        /// reversed before this outcome was produced (the `submit_initiate_payout` failure path) --
        /// proof the fee did not stay spent despite the pre-commit. `None` means no fee was ever
        /// read for this attempt, so there was nothing to commit or reverse. Either way the
        /// persisted window reflects zero net spend for this launcher id this cycle (see
        /// `f12_a_failed_submission_does_not_inflate_the_persisted_window`).
        reversed_fee_mojos: Option<u64>,
        /// The chain port's own words for why (`ClaimPortError::Other`'s payload), bounded to 200
        /// chars before it is stored or logged -- it originates from a chain port and so is
        /// attacker-adjacent, the same discipline `service::summarize_stderr` applies to a tool's
        /// own stderr.
        reason: String,
    },
}

/// The closed set of states this loop can be in. Never a health boolean (SPEC §2.4) — each name
/// maps to a different fact an operator can act on.
///
/// # Precedence: `ChainSourceUnavailable` > `Faulted` > `ClaimableButNotClaiming` > `Idle` >
/// `Nominal` (Defect A1, refined by Defect B3)
/// `ChainSourceUnavailable` outranks everything (no chain at all). Next, `Faulted` outranks
/// `Nominal` and `ClaimableButNotClaiming`: a cycle where a chain call returned
/// `ClaimPortError::Other(_)` is never allowed to read as healthy just because nothing else in
/// the cycle happened to be claimable. Only once no fault is live can `ClaimableButNotClaiming`
/// or `Nominal` apply.
///
/// # F1: `ChainSourceUnavailable` is a per-cycle reading, never a latch
/// This used to be decided by comparing against `self.state` -- LAST cycle's computed reading --
/// so once any cycle took an `Unavailable` port path, every later cycle's `compute_state` saw its
/// own prior verdict and re-asserted it forever, even after the chain came back and real claims
/// were submitting. [`ClaimStatus::chain_unavailable_this_cycle`] fixes this: reset to `false` at
/// the top of every `run_cycle`, set `true` only on a cycle that actually took the `Unavailable`
/// path this cycle. `compute_state` reads that flag, never `self.state`.
///
/// # Defect B3: a per-distributor problem must never set the cycle-wide fault
/// `Faulted` used to also fire on [`ClaimOutcome::PayoutPuzzleHashMismatch`] — a single hostile or
/// buggy ENTRY ROW pinned the whole surface at `Faulted` indefinitely (non-terminal, so it recurred
/// every cycle) and buried the `ClaimableButNotClaiming` signal this ticket exists to produce. A
/// payout-hash mismatch is now a per-distributor COUNTED refusal (see
/// [`ClaimStatus::payout_hash_mismatches_this_cycle`] and
/// [`Self::claims_refused_payout_mismatch`]), never [`Self::fault_reported`]. `Faulted` is reserved
/// for a genuinely cycle-wide failure: discovery itself failing, or a chain-port call returning
/// `ClaimPortError::Other(_)`.
///
/// # F8/F9/F10: `PersistedStateCorrupt` and `CadenceNotElapsed` are assigned DIRECTLY, never via
/// [`ClaimStatus::compute_state`]
/// Both are written by [`super::engine::ClaimEngine::run_cycle`] on an early return that happens
/// BEFORE any of this cycle's own numbers exist to compute a reading from — there is no
/// "claimable" or "faulted" count to rank against `compute_state`'s ladder, because no candidate
/// was ever evaluated. F9's finding was exactly this gap: an early return that assigned NEITHER a
/// direct state NOR fell through to `compute_state` left whatever `self.state` a PAST cycle
/// computed sitting there, stamped with a fresh `last_attempt_at` that made a deliberate skip read
/// as "healthy and idle". Every exit out of `run_cycle` now sets `state` one of these two ways —
/// directly here, or through `compute_state` at the bottom — never neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaimLoopState {
    /// No cycle has ever been attempted yet.
    #[default]
    Idle,
    /// The chain seam reported [`super::port::ClaimPortError::Unavailable`] — see the module doc's
    /// "chain seam" section. Zero cycles ran; this is the true state, not a silent no-op.
    ChainSourceUnavailable,
    /// F8/F10, fund-safety: the persisted rewards-claim state (`RewardsClaimConfig`) was
    /// unreadable, unparsable, carried a spend exceeding its own budget (F14), or carried a
    /// future-dated clock (F10) — corrupt state, not a fresh peer. The engine treats the window
    /// as fully spent and submits nothing until an operator fixes or removes the file; this state
    /// exists so that refusal is visible rather than a silent, permanent freeze that reads as
    /// `Nominal` (the pre-F9 shape of the F10 defect).
    PersistedStateCorrupt,
    /// F9: the cadence has not yet elapsed since the last cycle that ran to completion — a
    /// DELIBERATE skip, its own named condition rather than the absence of one. Without this, the
    /// gate's early return left a stale `self.state` from whatever a PAST cycle computed standing
    /// under this cycle's freshly-stamped `last_attempt_at`, indistinguishable from a healthy idle
    /// loop (the fourth relocation of this error class — see [`super::engine::ClaimEngine`]'s
    /// module doc for the first three).
    CadenceNotElapsed,
    /// A chain call this cycle returned `ClaimPortError::Other(_)` — a real fault, distinct from
    /// `ChainSourceUnavailable` (no chain at all). `cycles` is the number of CONSECUTIVE cycles a
    /// fault has now been observed on, so an operator can tell a one-off blip from a wedged loop.
    /// Defect A1: this state exists precisely so a reported fault can never be laundered into
    /// `Nominal` for lack of anywhere else to fall through to.
    Faulted { cycles: u32 },
    /// The silent-failure case this ticket exists to prevent: fewer distributors were claimed THIS
    /// CYCLE than were claimable, and no fault is live. Carries both numbers so a reader sees the
    /// SIZE of the gap, not just its existence. Computed, never asserted by a writer about itself —
    /// see [`ClaimStatus::compute_state`].
    ///
    /// # Defect B1: a zero-test masked a partial shortfall
    /// This used to fire only when `claims_submitted_this_cycle == 0` — a magnitude comparison
    /// disguised as an existence check. `claimable = 10, submitted_this_cycle = 1` read `Nominal`:
    /// one submission (e.g. a distributor whose fee happened to sort first) masked nine same-cycle
    /// skips. Reachable precisely because [`super::engine::ClaimEngine`]'s per-cycle budget
    /// (Defect C2) is the first thing that can skip a claimable distributor while another one
    /// submits in the same cycle. Fixed to a true magnitude comparison: fires whenever
    /// `submitted < claimable`, whatever the non-zero submitted count is.
    ClaimableButNotClaiming { claimable: u32, submitted: u32 },
    /// A cycle completed, nothing above is true.
    Nominal,
}

/// The anti-silence status surface (requirement 4): what an operator or a monitor reads to know
/// whether this loop is actually doing anything, never a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimStatus {
    /// F1: set when THIS cycle actually took an `Unavailable` port path -- reset to `false` at the
    /// top of every `run_cycle`, never latched. See [`ClaimLoopState`]'s "F1" doc section.
    pub chain_unavailable_this_cycle: bool,
    pub distributors_known: u32,
    pub distributors_with_own_entry: u32,
    /// Computed independently of whether a submission actually happened this cycle — an
    /// entry that accrued at least `payout_threshold` with a fee at or under the ceiling. THIS
    /// CYCLE's snapshot, overwritten every `run_cycle`, and compared against
    /// [`Self::claims_submitted_this_cycle`] (also per-cycle) — never against the cumulative
    /// [`Self::claims_submitted`], which only ever grows and would let one success in the process's
    /// life mask every later broken cycle (Defect A3).
    pub distributors_claimable: u32,
    /// Defect C3/A3: distributors whose evaluation THIS cycle returned `ClaimPortError::Other(_)`.
    /// A faulted distributor is not counted in [`Self::distributors_claimable`] — a fault must never
    /// silently shrink that denominator into looking healthier than it is.
    pub distributors_faulted: u32,
    /// Only stamped on a discovery call that actually SUCCEEDED (Defect A4) — a reader uses this as
    /// an independent staleness signal, so refreshing it on a failed discovery would destroy the one
    /// reading that would have exposed the fault. See [`Self::last_attempt_at`] for "the loop is
    /// still alive" instead.
    pub last_discovery_at: Option<u64>,
    /// Only stamped on a cycle that was not a failed discovery and not all-faulted (Defect A4) — same
    /// reasoning as [`Self::last_discovery_at`].
    pub last_cycle_at: Option<u64>,
    /// Stamped every time `run_cycle` is invoked, success or failure — proves the loop is still
    /// running even across a run of all-faulted cycles, without polluting the staleness signal the
    /// other two timestamps carry (Defect A4).
    pub last_attempt_at: Option<u64>,
    /// Lifetime total — a useful counter, kept cumulative on purpose. NOT the predicate for
    /// [`ClaimLoopState::ClaimableButNotClaiming`]; see [`Self::claims_submitted_this_cycle`].
    pub claims_submitted: u64,
    /// THIS CYCLE's submission count, overwritten every `run_cycle` (Defect A3) — the correct half
    /// of the `ClaimableButNotClaiming` predicate.
    pub claims_submitted_this_cycle: u64,
    pub claims_skipped_below_threshold: u64,
    pub claims_skipped_fee_ceiling: u64,
    /// Defect C2: lifetime count of claims skipped because the per-cycle aggregate fee budget was
    /// already exhausted this cycle.
    pub claims_skipped_cycle_budget: u64,
    /// Defect E: lifetime count of claims REFUSED because the port returned an entry for a puzzle
    /// hash other than this node's own — see [`ClaimOutcome::PayoutPuzzleHashMismatch`]. A
    /// per-distributor counted fault (Defect B3), never [`Self::fault_reported`].
    pub claims_refused_payout_mismatch: u64,
    /// Defect B3: THIS CYCLE's twin of [`Self::claims_refused_payout_mismatch`] — without it a
    /// reader could not tell an ONGOING misdirection from an old, no-longer-recurring one, the same
    /// per-cycle-vs-lifetime gap Defect A3 named for the other counters.
    pub payout_hash_mismatches_this_cycle: u32,
    /// THIS CYCLE's count of distributors observed with no entry slot (Defect B) — no longer a
    /// lifetime blacklist size, because the engine no longer blacklists a launcher id permanently;
    /// see [`super::engine::ClaimEngine`]'s module doc.
    ///
    /// # Defect R2: renamed from `terminal_no_entry_slot`
    /// That name quoted SPEC §12.5 clause 1's "terminal, non-error" language to justify behaviour
    /// that is deliberately non-terminal since the Defect B fix — a doc claim born false in the
    /// commit that fixed the code. Renamed before #3268 publishes it over RPC.
    ///
    /// SPEC v0.1.3 §12.5 (the amendment R1 flagged as pending is now merged and tagged) confirms
    /// this reading directly: an absent entry slot is terminal for ONE claim attempt, never for the
    /// distributor, MUST NOT be cached, and MUST NOT accumulate into a permanent exclusion set —
    /// this field satisfies v0.1.3 clause 6's "surfaced, not silently absorbed" requirement without
    /// a tenth named [`ClaimLoopState`] variant: it is a per-cycle count, dated by
    /// [`Self::last_attempt_at`] -- the field stamped unconditionally every cycle, the true
    /// analogue of §2.3's `observed_at` -- and reset at the TOP of every `run_cycle` alongside the
    /// other per-cycle counters, before any early return, so a stalled writer can never leave a
    /// stale count sitting under a fresh timestamp (never a lifetime latch).
    pub no_entry_slot_this_cycle: u32,
    /// Set when a chain call THIS CYCLE returned `ClaimPortError::Other(_)` — reset at the start of
    /// every `run_cycle` (Defect A1: this used to latch true for the rest of the process's life,
    /// which would have permanently suppressed every other state once tripped once).
    pub fault_reported: bool,
    /// Consecutive cycles (including this one, if `fault_reported`) that have reported a fault —
    /// resets to 0 the moment a cycle reports no fault. Surfaced via [`ClaimLoopState::Faulted`].
    pub consecutive_faulted_cycles: u32,
    pub state: ClaimLoopState,
}

impl Default for ClaimStatus {
    fn default() -> Self {
        ClaimStatus {
            chain_unavailable_this_cycle: false,
            distributors_known: 0,
            distributors_with_own_entry: 0,
            distributors_claimable: 0,
            distributors_faulted: 0,
            last_discovery_at: None,
            last_cycle_at: None,
            last_attempt_at: None,
            claims_submitted: 0,
            claims_submitted_this_cycle: 0,
            claims_skipped_below_threshold: 0,
            claims_skipped_fee_ceiling: 0,
            claims_skipped_cycle_budget: 0,
            claims_refused_payout_mismatch: 0,
            payout_hash_mismatches_this_cycle: 0,
            no_entry_slot_this_cycle: 0,
            fault_reported: false,
            consecutive_faulted_cycles: 0,
            state: ClaimLoopState::Idle,
        }
    }
}

impl ClaimStatus {
    /// Derives [`ClaimLoopState`] from the status fields alone — a pure computation, so a test can
    /// assert `ClaimableButNotClaiming` (or `Faulted`) directly against hand-built fields without
    /// driving a whole engine cycle, and so a stalled writer can never manufacture a healthier state
    /// than its own numbers support (SPEC §2.4's reasoning, applied to this loop's own surface).
    ///
    /// Precedence, most urgent first: `ChainSourceUnavailable` > `Faulted` >
    /// `ClaimableButNotClaiming` > `Idle` > `Nominal`. See [`ClaimLoopState`]'s doc for why a fault
    /// must never be absorbed into `Nominal` (Defect A1) and why a per-distributor fault (Defect B3)
    /// must never set it.
    ///
    /// # F1: reads `chain_unavailable_this_cycle`, never `self.state`
    /// The old guard compared against `self.state` -- last cycle's OWN computed output -- which
    /// made `ChainSourceUnavailable` a process-lifetime latch (see [`ClaimLoopState`]'s "F1" doc
    /// section). `chain_unavailable_this_cycle` is reset every cycle, so this reading is live.
    #[must_use]
    pub fn compute_state(&self) -> ClaimLoopState {
        if self.chain_unavailable_this_cycle {
            return ClaimLoopState::ChainSourceUnavailable;
        }
        if self.last_attempt_at.is_none() && self.last_cycle_at.is_none() {
            return ClaimLoopState::Idle;
        }
        if self.fault_reported {
            return ClaimLoopState::Faulted {
                cycles: self.consecutive_faulted_cycles.max(1),
            };
        }
        // Defect B1: a magnitude comparison, not a zero-test -- `claims_submitted_this_cycle < 10`
        // fires just as much when 1 of 10 claimable was submitted as when 0 were; a partial
        // shortfall must never be masked by whichever claims did go through.
        //
        // F2: `payout_hash_mismatches_this_cycle` folds into the RIGHT side of the comparison. A
        // mismatching distributor never enters `eligible`, so it is counted in NEITHER
        // `claims_submitted_this_cycle` NOR `distributors_claimable` -- the shortfall was in
        // neither term of this comparison. All-K-mismatching used to read `submitted = 0,
        // claimable = 0` -> healthy. An ongoing mismatch is a real per-cycle shortfall exactly like
        // an unmet `claimable`, so it belongs in the same predicate, never a separate signal
        // nothing reads.
        let shortfall_denominator = u64::from(self.distributors_claimable)
            + u64::from(self.payout_hash_mismatches_this_cycle);
        if self.claims_submitted_this_cycle < shortfall_denominator {
            // F13: report the SAME quantity the predicate above just used, not the un-folded
            // `distributors_claimable` alone. Before this fix, all-K-mismatching produced
            // `ClaimableButNotClaiming { claimable: 0, submitted: 0 }` -- the name was right (F2
            // already folded mismatches into firing the state at all) but the payload said
            // nothing was wrong, because it reported the term the mismatches were never counted
            // in. The payload must carry the full shortfall the name is claiming, or it is a
            // state whose numbers contradict its own name.
            return ClaimLoopState::ClaimableButNotClaiming {
                claimable: u32::try_from(shortfall_denominator).unwrap_or(u32::MAX),
                submitted: u32::try_from(self.claims_submitted_this_cycle).unwrap_or(u32::MAX),
            };
        }
        ClaimLoopState::Nominal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimable_but_not_claiming_is_computed_from_fields_alone() {
        let status = ClaimStatus {
            distributors_claimable: 3,
            claims_submitted_this_cycle: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 3,
                submitted: 0
            }
        );
    }

    /// Defect B1 regression: a magnitude comparison, not a zero-test. `claimable = 10,
    /// submitted_this_cycle = 1` used to read `Nominal` because the old predicate only checked
    /// `submitted_this_cycle == 0` -- one submission masked nine same-cycle skips.
    #[test]
    fn a_partial_shortfall_is_claimable_but_not_claiming_not_nominal() {
        let status = ClaimStatus {
            distributors_claimable: 10,
            claims_submitted_this_cycle: 1,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 10,
                submitted: 1
            },
            "1 of 10 claimable submitted must still read the shortfall, never Nominal"
        );
    }

    /// Defect B1 regression: the other half of the fix -- every claimable distributor submitted
    /// must read `Nominal`, not a false-positive shortfall.
    #[test]
    fn claiming_every_claimable_distributor_is_nominal() {
        let status = ClaimStatus {
            distributors_claimable: 10,
            claims_submitted_this_cycle: 10,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::Nominal);
    }

    /// Defect A1/A2: this test used to assert `Nominal` here, encoding the bug (a reported fault
    /// was silently absorbed into the healthy state) as intended behaviour. Inverted per the fix
    /// brief: a fault must surface its own named state, never masquerade as either
    /// `ClaimableButNotClaiming` or `Nominal`.
    #[test]
    fn a_reported_fault_surfaces_as_faulted_not_nominal() {
        let status = ClaimStatus {
            distributors_claimable: 3,
            claims_submitted_this_cycle: 0,
            fault_reported: true,
            consecutive_faulted_cycles: 1,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::Faulted { cycles: 1 }
        );
    }

    /// Defect A3 regression: `distributors_claimable` is a per-cycle snapshot and
    /// `claims_submitted` (cumulative) only ever grows, so comparing the two lets one success in
    /// the process's lifetime mask every later cycle where the submit path has since broken. The
    /// fix compares against `claims_submitted_this_cycle` instead.
    #[test]
    fn a_lifetime_submission_does_not_mask_a_later_cycle_that_submits_nothing() {
        let status = ClaimStatus {
            distributors_claimable: 1,
            claims_submitted: 7, // non-zero lifetime total from an earlier successful cycle
            claims_submitted_this_cycle: 0, // but THIS cycle submitted nothing
            fault_reported: false,
            last_cycle_at: Some(2),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 1,
                submitted: 0
            }
        );
    }

    #[test]
    fn nothing_claimable_and_nothing_submitted_is_nominal() {
        let status = ClaimStatus {
            distributors_claimable: 0,
            claims_submitted_this_cycle: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(status.compute_state(), ClaimLoopState::Nominal);
    }

    #[test]
    fn chain_source_unavailable_wins_over_every_other_reading() {
        let status = ClaimStatus {
            distributors_claimable: 5,
            claims_submitted: 0,
            fault_reported: false,
            last_cycle_at: Some(1),
            chain_unavailable_this_cycle: true,
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::ChainSourceUnavailable
        );
    }

    /// F1 regression at the `compute_state` level: a PAST cycle's `ChainSourceUnavailable` must
    /// never leak into THIS cycle's reading once `chain_unavailable_this_cycle` is false again --
    /// proving the fix reads the per-cycle flag, never `self.state` (which this struct literal
    /// deliberately still carries as `ChainSourceUnavailable`, simulating what a stale `self.state`
    /// would look like if the old guard were still in place).
    #[test]
    fn a_past_cycles_chain_unavailable_state_does_not_latch_the_next_computation() {
        let status = ClaimStatus {
            distributors_claimable: 1,
            claims_submitted_this_cycle: 1,
            fault_reported: false,
            last_cycle_at: Some(2),
            chain_unavailable_this_cycle: false,
            state: ClaimLoopState::ChainSourceUnavailable,
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::Nominal,
            "chain_unavailable_this_cycle is false this cycle -- a stale self.state must not win"
        );
    }

    /// Defect B3 regression: a per-distributor payout-hash mismatch count, with no cycle-wide
    /// `fault_reported`, must read the `ClaimableButNotClaiming` shortfall it actually represents,
    /// never `Faulted` -- `engine.rs` is the one that decides `fault_reported`, but this proves the
    /// state computation itself no longer has any path from "a mismatch happened" to `Faulted`.
    #[test]
    fn a_payout_mismatch_count_alone_does_not_force_faulted() {
        let status = ClaimStatus {
            distributors_claimable: 2,
            claims_submitted_this_cycle: 1,
            payout_hash_mismatches_this_cycle: 1,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            // F13: `claimable` is now the FOLDED shortfall (2 claimable + 1 mismatch = 3), not
            // the un-folded `distributors_claimable` alone -- see the F13 regression below for
            // the case (all-K-mismatching) that made the un-folded reading actively misleading.
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 3,
                submitted: 1
            }
        );
    }

    /// F13 regression: all-K-mismatching must report the shortfall it actually represents, not a
    /// payload that contradicts its own state name. Before the fix, this read `claimable: 0,
    /// submitted: 0` -- a name saying something is wrong next to numbers saying nothing is. Must
    /// go red with only the `claimable: shortfall_denominator` fix reverted to
    /// `claimable: self.distributors_claimable`.
    #[test]
    fn all_k_mismatching_reports_the_folded_shortfall_not_zero() {
        let status = ClaimStatus {
            distributors_claimable: 0,
            claims_submitted_this_cycle: 0,
            payout_hash_mismatches_this_cycle: 4,
            fault_reported: false,
            last_cycle_at: Some(1),
            ..ClaimStatus::default()
        };
        assert_eq!(
            status.compute_state(),
            ClaimLoopState::ClaimableButNotClaiming {
                claimable: 4,
                submitted: 0
            },
            "the payload must carry the same shortfall the predicate fired on, never 0"
        );
    }
}
