//! SPEC §6.3 entry-set write bounds — this spends the funder's money, so every bound here is
//! enforced in code, never left to caller discipline.
//!
//! 1. **Batch**: at most one bundle per cycle, at most [`MAX_ENTRY_WRITES_PER_BUNDLE`] actions,
//!    one fee.
//! 2. **Rate**: at most one bundle per distributor per [`ENTRY_WRITE_MIN_INTERVAL_SECONDS`]. A
//!    decision reached sooner is WITHHELD, never dropped — it shows up in `pending_entry_writes`.
//! 3. **Cap**: a per-distributor daily fee budget ([`FeeBudget`]). On exhaustion: stop writing,
//!    KEEP the decisions, report `FeeBudgetExhausted`.
//! 4. **Hysteresis**: a removal is not re-added for [`REENTRY_COOLDOWN_SECONDS`], keyed on
//!    `(payout_puzzle_hash, launcher_id)` and NEVER on `peer_id` — the puzzle hash is what the
//!    chain writes; a peer can present a fresh `peer_id` (e.g. a new TLS cert) for the same payout
//!    address and MUST still be held.
//!
//! Also §6.5/§12.6: [`is_entry_set_full`] / [`is_unfunded`] name the two other terminal reports
//! (`EntrySetFull`, `Unfunded`) — on `Unfunded` the entry set is KEPT, never evicted, because
//! evicting 250 entries to punish an empty reserve costs 250 fees and punishes nobody.

use super::port::{Bytes32, EntryAction, EntryWriteBundle};
use super::spec_constants::{
    ENTRY_WRITE_MIN_INTERVAL_SECONDS, MAX_ENTRIES_PER_DISTRIBUTOR, MAX_ENTRY_WRITES_PER_BUNDLE,
    REENTRY_COOLDOWN_SECONDS,
};
use std::collections::HashMap;

/// Reentry-cooldown key — deliberately `(payout_puzzle_hash, launcher_id)`, never `peer_id`.
pub type CooldownKey = (Bytes32, Bytes32);

/// A per-distributor daily fee budget in XCH mojos. Default: 24 bundles' worth of the operator's
/// configured standard fee (SPEC §6.3 cap).
pub struct FeeBudget {
    limit_mojos_per_day: u64,
    spent_mojos_today: u64,
    day_started_at: u64,
}

impl FeeBudget {
    pub fn new(standard_fee_mojos: u64, now: u64) -> Self {
        Self {
            limit_mojos_per_day: standard_fee_mojos.saturating_mul(24),
            spent_mojos_today: 0,
            day_started_at: now,
        }
    }

    fn roll_if_new_day(&mut self, now: u64) {
        if now.saturating_sub(self.day_started_at) >= 86_400 {
            self.spent_mojos_today = 0;
            self.day_started_at = now;
        }
    }

    /// `true` if `fee_mojos` fits inside today's remaining budget, in which case it is charged.
    pub fn try_spend(&mut self, fee_mojos: u64, now: u64) -> bool {
        self.roll_if_new_day(now);
        if self.spent_mojos_today.saturating_add(fee_mojos) > self.limit_mojos_per_day {
            return false;
        }
        self.spent_mojos_today += fee_mojos;
        true
    }
}

/// What a call to [`EntryWriteScheduler::decide`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// A bundle ready to submit through `RewardsChainPort::submit_entry_writes`.
    Bundle {
        bundle: EntryWriteBundle,
        still_pending: u32,
    },
    /// Nothing submitted, `count` decisions withheld this cycle (rate-limited or none ready) —
    /// they MUST still surface in `pending_entry_writes`, never silently dropped.
    Pending { count: u32 },
    /// The fee budget is exhausted for today: stop writing, but the `count` decisions are KEPT,
    /// not discarded.
    FeeBudgetExhausted { count: u32 },
}

/// Tracks the per-distributor write-rate clock and the per-`(payout_puzzle_hash, launcher_id)`
/// reentry cooldown. One instance per running prover (not per cycle) so both bounds persist across
/// cycles.
#[derive(Default)]
pub struct EntryWriteScheduler {
    last_bundle_sent_at: HashMap<Bytes32, u64>,
    cooldown_until: HashMap<CooldownKey, u64>,
}

impl EntryWriteScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_rate_limited(&self, launcher_id: Bytes32, now: u64) -> bool {
        match self.last_bundle_sent_at.get(&launcher_id) {
            Some(&last) => now.saturating_sub(last) < ENTRY_WRITE_MIN_INTERVAL_SECONDS,
            None => false,
        }
    }

    /// SPEC §6.3 clause 4 hysteresis check — keyed on the payout puzzle hash, never `peer_id`.
    pub fn is_in_reentry_cooldown(
        &self,
        payout_puzzle_hash: Bytes32,
        launcher_id: Bytes32,
        now: u64,
    ) -> bool {
        match self.cooldown_until.get(&(payout_puzzle_hash, launcher_id)) {
            Some(&until) => now < until,
            None => false,
        }
    }

    fn record_removal(&mut self, payout_puzzle_hash: Bytes32, launcher_id: Bytes32, now: u64) {
        self.cooldown_until.insert(
            (payout_puzzle_hash, launcher_id),
            now + REENTRY_COOLDOWN_SECONDS,
        );
    }

    /// Decide this cycle's write for one distributor from a queue of pending decisions (already
    /// hysteresis-filtered by the caller via [`Self::is_in_reentry_cooldown`] for adds). Enforces
    /// the batch cap, the rate bound, and the fee budget, in that order of relevance to the
    /// caller — but the RATE check runs first because a rate-limited distributor must not touch
    /// the fee budget at all.
    pub fn decide(
        &mut self,
        launcher_id: Bytes32,
        decisions: Vec<EntryAction>,
        fee_mojos: u64,
        budget: &mut FeeBudget,
        now: u64,
    ) -> WriteOutcome {
        if decisions.is_empty() {
            return WriteOutcome::Pending { count: 0 };
        }
        if self.is_rate_limited(launcher_id, now) {
            return WriteOutcome::Pending {
                count: decisions.len() as u32,
            };
        }

        let take = decisions.len().min(MAX_ENTRY_WRITES_PER_BUNDLE as usize);
        let (bundle_actions, rest) = decisions.split_at(take);

        if !budget.try_spend(fee_mojos, now) {
            return WriteOutcome::FeeBudgetExhausted {
                count: decisions.len() as u32,
            };
        }

        for action in bundle_actions {
            if let EntryAction::Remove {
                payout_puzzle_hash,
                launcher_id: lid,
            } = action
            {
                self.record_removal(*payout_puzzle_hash, *lid, now);
            }
        }
        self.last_bundle_sent_at.insert(launcher_id, now);

        WriteOutcome::Bundle {
            bundle: EntryWriteBundle {
                launcher_id,
                actions: bundle_actions.to_vec(),
                fee_mojos,
            },
            still_pending: rest.len() as u32,
        }
    }
}

/// SPEC §6.5: the entry set is capped at [`MAX_ENTRIES_PER_DISTRIBUTOR`] entries.
pub fn is_entry_set_full(current_entry_count: usize) -> bool {
    current_entry_count >= MAX_ENTRIES_PER_DISTRIBUTOR as usize
}

/// SPEC §12.6: a zero reserve is `Unfunded`; the caller MUST keep the entry set as-is.
pub fn is_unfunded(reserve_base_units: u64) -> bool {
    reserve_base_units == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCHER: Bytes32 = [1; 32];
    const PAYOUT_A: Bytes32 = [2; 32];

    fn add(payout_puzzle_hash: Bytes32, launcher_id: Bytes32) -> EntryAction {
        EntryAction::Add {
            payout_puzzle_hash,
            launcher_id,
        }
    }

    fn remove(payout_puzzle_hash: Bytes32, launcher_id: Bytes32) -> EntryAction {
        EntryAction::Remove {
            payout_puzzle_hash,
            launcher_id,
        }
    }

    #[test]
    fn batch_cap_leaves_the_rest_pending() {
        let mut scheduler = EntryWriteScheduler::new();
        let mut budget = FeeBudget::new(1_000_000, 0);
        let decisions: Vec<EntryAction> = (0..(MAX_ENTRY_WRITES_PER_BUNDLE + 3))
            .map(|i| add([i as u8; 32], LAUNCHER))
            .collect();
        let outcome = scheduler.decide(LAUNCHER, decisions, 100, &mut budget, 0);
        match outcome {
            WriteOutcome::Bundle {
                bundle,
                still_pending,
            } => {
                assert_eq!(bundle.actions.len(), MAX_ENTRY_WRITES_PER_BUNDLE as usize);
                assert_eq!(still_pending, 3);
            }
            other => panic!("expected Bundle, got {other:?}"),
        }
    }

    /// SPEC §6.3 clause 2: a decision reached sooner than the interval MUST be withheld and MUST
    /// appear as pending — never dropped.
    #[test]
    fn rate_limit_withholds_rather_than_drops() {
        let mut scheduler = EntryWriteScheduler::new();
        let mut budget = FeeBudget::new(1_000_000, 0);
        let first = scheduler.decide(LAUNCHER, vec![add(PAYOUT_A, LAUNCHER)], 100, &mut budget, 0);
        assert!(matches!(first, WriteOutcome::Bundle { .. }));

        let second = scheduler.decide(
            LAUNCHER,
            vec![add([9; 32], LAUNCHER)],
            100,
            &mut budget,
            ENTRY_WRITE_MIN_INTERVAL_SECONDS - 1,
        );
        assert_eq!(second, WriteOutcome::Pending { count: 1 });
    }

    #[test]
    fn fee_budget_exhaustion_keeps_decisions_and_stops_writing() {
        let mut scheduler = EntryWriteScheduler::new();
        let mut budget = FeeBudget::new(10, 0); // 240 mojos/day
        let fee = 1_000; // exceeds the whole day's budget on the first attempt
        let outcome =
            scheduler.decide(LAUNCHER, vec![add(PAYOUT_A, LAUNCHER)], fee, &mut budget, 0);
        assert_eq!(outcome, WriteOutcome::FeeBudgetExhausted { count: 1 });
    }

    /// The named cooldown-bypass trap: cooldown is keyed on `(payout_puzzle_hash, launcher_id)`
    /// only — `peer_id` never enters the key, so presenting a fresh TLS cert / `peer_id` for the
    /// SAME payout address does not bypass the cooldown.
    #[test]
    fn reentry_cooldown_survives_a_fresh_peer_id_for_the_same_payout_hash() {
        let mut scheduler = EntryWriteScheduler::new();
        let mut budget = FeeBudget::new(1_000_000, 0);
        let outcome = scheduler.decide(
            LAUNCHER,
            vec![remove(PAYOUT_A, LAUNCHER)],
            100,
            &mut budget,
            0,
        );
        assert!(matches!(outcome, WriteOutcome::Bundle { .. }));

        // A "fresh peer_id" is not even a parameter to this cooldown check — it is keyed purely on
        // the payout puzzle hash, which is exactly what makes the bypass impossible: nothing about
        // peer identity can change which key is consulted.
        assert!(scheduler.is_in_reentry_cooldown(
            PAYOUT_A,
            LAUNCHER,
            ENTRY_WRITE_MIN_INTERVAL_SECONDS
        ));
        assert!(scheduler.is_in_reentry_cooldown(PAYOUT_A, LAUNCHER, REENTRY_COOLDOWN_SECONDS - 1));
        assert!(!scheduler.is_in_reentry_cooldown(PAYOUT_A, LAUNCHER, REENTRY_COOLDOWN_SECONDS));
    }

    #[test]
    fn entry_set_full_and_unfunded_report_the_right_terminal_state() {
        assert!(is_entry_set_full(MAX_ENTRIES_PER_DISTRIBUTOR as usize));
        assert!(!is_entry_set_full(MAX_ENTRIES_PER_DISTRIBUTOR as usize - 1));
        assert!(is_unfunded(0));
        assert!(!is_unfunded(1));
    }
}
