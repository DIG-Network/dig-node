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

    /// Record a bundle's removals as reentry-cooldown-blocked. Call this ONLY after
    /// `RewardsChainPort::submit_entry_writes` has returned `Ok` for this exact bundle — recording
    /// the cooldown before the chain confirms would hold an honest mirror out for the full
    /// [`REENTRY_COOLDOWN_SECONDS`] window on a submit that never actually reached the chain (e.g.
    /// a network error, a rejected spend). [`Self::decide`] deliberately does NOT do this itself.
    pub fn record_submitted(&mut self, bundle: &EntryWriteBundle, now: u64) {
        for action in &bundle.actions {
            if let EntryAction::Remove {
                payout_puzzle_hash,
                launcher_id,
            } = action
            {
                self.record_removal(*payout_puzzle_hash, *launcher_id, now);
            }
        }
    }
}

/// SPEC §12.1 clause 2: cooldowns and fee budgets MUST persist across a restart. Without this, a
/// restart loop resets `last_bundle_sent_at` to empty, `spent_mojos_today` to zero and
/// `cooldown_until` to empty — an unbounded per-restart spend of the operator's XCH and repeated
/// reserve settlements via re-eviction, invisible because it looks like ordinary bounded operation
/// each time. One `WriteBoundState` covers a single `launcher_id` (the caller keys storage by
/// distributor); `spent_mojos_today` carries the day it refers to so a loaded state past midnight
/// UTC-relative-to-`day_started_at` rolls over exactly like the in-memory [`FeeBudget`] does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBoundState {
    pub last_bundle_sent_at: Option<u64>,
    pub spent_mojos_today: u64,
    pub day_started_at: u64,
    pub cooldown_until: HashMap<CooldownKey, u64>,
}

/// Why a [`WriteBoundStore`] call could not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

/// The persistence seam SPEC §12.1 clause 2 requires. Narrow on purpose — one `launcher_id` at a
/// time, load-then-save — so a real backend (a file, a small embedded DB) is a thin adapter, not a
/// redesign.
pub trait WriteBoundStore: Send + Sync {
    fn load(&self, launcher_id: Bytes32) -> Result<WriteBoundState, StoreError>;
    fn save(&self, launcher_id: Bytes32, state: &WriteBoundState) -> Result<(), StoreError>;
}

/// The fail-closed default until a real backend is wired: every call errors, so
/// [`PersistedEntryWriter::decide`] refuses to submit anything rather than run the write bounds
/// unbounded across a restart. This is deliberately the production default TODAY — the chain port
/// itself is `UnavailableChainPort` until #3249 lands, so this adapter costs nothing operationally
/// yet and closes the money hole the moment either seam is wired.
pub struct NoPersistence;

impl WriteBoundStore for NoPersistence {
    fn load(&self, _launcher_id: Bytes32) -> Result<WriteBoundState, StoreError> {
        Err(StoreError(
            "no write-bound persistence backend configured".to_string(),
        ))
    }

    fn save(&self, _launcher_id: Bytes32, _state: &WriteBoundState) -> Result<(), StoreError> {
        Err(StoreError(
            "no write-bound persistence backend configured".to_string(),
        ))
    }
}

/// What [`PersistedEntryWriter::decide`] produced, in place of [`WriteOutcome`] once persistence is
/// in the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedWriteOutcome {
    Bundle {
        bundle: EntryWriteBundle,
        still_pending: u32,
    },
    Pending {
        count: u32,
    },
    FeeBudgetExhausted {
        count: u32,
    },
    /// The write-bound store could not be loaded for this distributor. No bundle is computed or
    /// returned — the caller MUST NOT submit anything this cycle and MUST report this
    /// distributor's `ProverState` as `ChainSourceUnavailable`.
    ///
    /// `FeeBudgetExhausted` was considered and rejected: that state means "a real budget exists
    /// and is spent," which asserts something this code does not know when the store itself is
    /// unreachable. `ChainSourceUnavailable` already means "a dependency this decision needs is
    /// not reachable, and this is a prover-side fault, never a peer-attributable one" (see
    /// `admission.rs`'s D5 use of the same state for the analogous gate-unavailable case) — which
    /// is exactly what an unreachable persistence backend is. Inventing a tenth `ProverState`
    /// would need a SPEC amendment (§2.3 pins the set to nine); this does not.
    PersistenceUnavailable,
}

/// Wraps [`EntryWriteScheduler`]'s decision with the SPEC §12.1 clause 2 persistence gate: bounds
/// are loaded before deciding and persisted only after a caller-confirmed successful submit
/// ([`Self::commit`]) — never inside `decide` itself, for the same before/after-success reason
/// [`EntryWriteScheduler::record_submitted`] documents.
pub struct PersistedEntryWriter<'a> {
    store: &'a dyn WriteBoundStore,
}

impl<'a> PersistedEntryWriter<'a> {
    pub fn new(store: &'a dyn WriteBoundStore) -> Self {
        Self { store }
    }

    /// Load this distributor's persisted bounds, then decide this cycle's write. Returns the
    /// updated (not-yet-persisted) state alongside every non-refusal outcome; the caller MUST
    /// call [`Self::commit`] with that state after the chain confirms a `Bundle` outcome's submit
    /// succeeded. Nothing here submits to the chain.
    pub fn decide(
        &self,
        launcher_id: Bytes32,
        decisions: Vec<EntryAction>,
        fee_mojos: u64,
        standard_fee_mojos: u64,
        now: u64,
    ) -> (PersistedWriteOutcome, Option<WriteBoundState>) {
        let mut state = match self.store.load(launcher_id) {
            Ok(state) => state,
            Err(_) => return (PersistedWriteOutcome::PersistenceUnavailable, None),
        };

        if now.saturating_sub(state.day_started_at) >= 86_400 {
            state.spent_mojos_today = 0;
            state.day_started_at = now;
        }

        if decisions.is_empty() {
            return (PersistedWriteOutcome::Pending { count: 0 }, Some(state));
        }

        let rate_limited = state
            .last_bundle_sent_at
            .is_some_and(|last| now.saturating_sub(last) < ENTRY_WRITE_MIN_INTERVAL_SECONDS);
        if rate_limited {
            return (
                PersistedWriteOutcome::Pending {
                    count: decisions.len() as u32,
                },
                Some(state),
            );
        }

        let daily_limit_mojos = standard_fee_mojos.saturating_mul(24);
        if state.spent_mojos_today.saturating_add(fee_mojos) > daily_limit_mojos {
            return (
                PersistedWriteOutcome::FeeBudgetExhausted {
                    count: decisions.len() as u32,
                },
                Some(state),
            );
        }

        let take = decisions.len().min(MAX_ENTRY_WRITES_PER_BUNDLE as usize);
        let (bundle_actions, rest) = decisions.split_at(take);

        state.last_bundle_sent_at = Some(now);
        state.spent_mojos_today += fee_mojos;
        for action in bundle_actions {
            if let EntryAction::Remove {
                payout_puzzle_hash,
                launcher_id: lid,
            } = action
            {
                state
                    .cooldown_until
                    .insert((*payout_puzzle_hash, *lid), now + REENTRY_COOLDOWN_SECONDS);
            }
        }

        (
            PersistedWriteOutcome::Bundle {
                bundle: EntryWriteBundle {
                    launcher_id,
                    actions: bundle_actions.to_vec(),
                    fee_mojos,
                },
                still_pending: rest.len() as u32,
            },
            Some(state),
        )
    }

    /// Persist the state [`Self::decide`] returned, once the caller has confirmed the chain
    /// accepted the bundle. On `Err`, the caller MUST treat the NEXT cycle as
    /// `PersistenceUnavailable` too — a save failure means the bounds this submit just advanced
    /// are not durable, so trusting them in memory afterward would reopen the exact hole this
    /// seam exists to close.
    pub fn commit(&self, launcher_id: Bytes32, state: &WriteBoundState) -> Result<(), StoreError> {
        self.store.save(launcher_id, state)
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
        EntryAction::Add(super::super::admission::AdmittedPeer::for_test(
            payout_puzzle_hash,
            launcher_id,
        ))
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
        let bundle = match outcome {
            WriteOutcome::Bundle { bundle, .. } => bundle,
            other => panic!("expected Bundle, got {other:?}"),
        };
        // Cooldown is recorded only once the chain confirms the submit — never inside `decide`.
        scheduler.record_submitted(&bundle, 0);

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

    /// Regression for the "cooldown recorded before the submit is confirmed" defect: `decide`
    /// alone MUST NOT hold the payout hash in cooldown — only `record_submitted` may.
    #[test]
    fn decide_alone_does_not_record_a_cooldown() {
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
        assert!(!scheduler.is_in_reentry_cooldown(PAYOUT_A, LAUNCHER, 0));
    }

    #[test]
    fn entry_set_full_and_unfunded_report_the_right_terminal_state() {
        assert!(is_entry_set_full(MAX_ENTRIES_PER_DISTRIBUTOR as usize));
        assert!(!is_entry_set_full(MAX_ENTRIES_PER_DISTRIBUTOR as usize - 1));
        assert!(is_unfunded(0));
        assert!(!is_unfunded(1));
    }

    /// A trivial in-process store, standing in for a real backend (a file, an embedded DB) — the
    /// point under test is `PersistedEntryWriter`'s contract, not any particular backend.
    #[derive(Default)]
    struct FakeStore {
        states: std::sync::Mutex<HashMap<Bytes32, WriteBoundState>>,
    }

    impl WriteBoundStore for FakeStore {
        fn load(&self, launcher_id: Bytes32) -> Result<WriteBoundState, StoreError> {
            Ok(self
                .states
                .lock()
                .unwrap()
                .get(&launcher_id)
                .cloned()
                .unwrap_or_default())
        }

        fn save(&self, launcher_id: Bytes32, state: &WriteBoundState) -> Result<(), StoreError> {
            self.states
                .lock()
                .unwrap()
                .insert(launcher_id, state.clone());
            Ok(())
        }
    }

    /// SPEC §12.1 clause 2, fail-closed side: with no persistence backend wired, the writer MUST
    /// submit zero bundles and report `ChainSourceUnavailable` — not run the write bounds
    /// unbounded because nothing durable exists to bound them against.
    #[test]
    fn no_persistence_writer_submits_zero_bundles() {
        let writer = PersistedEntryWriter::new(&NoPersistence);
        let (outcome, state) =
            writer.decide(LAUNCHER, vec![add(PAYOUT_A, LAUNCHER)], 100, 1_000_000, 0);
        assert_eq!(outcome, PersistedWriteOutcome::PersistenceUnavailable);
        assert!(
            state.is_none(),
            "no bundle-tracking state may be produced without a store"
        );
    }

    /// THE money-bug regression: without persistence, restarting the process resets every bound to
    /// its zero value, so a restart loop would write one bundle per restart with no interval, no
    /// daily cap and no cooldown. This fails without `PersistedEntryWriter` reloading state from
    /// the store on every `decide` call.
    #[test]
    fn restart_still_enforces_rate_daily_cap_and_cooldown_across_the_store() {
        let store = FakeStore::default();

        // Cycle 1 ("before restart"): first bundle for the day goes through and is persisted.
        let writer = PersistedEntryWriter::new(&store);
        let (outcome, state) = writer.decide(
            LAUNCHER,
            vec![remove(PAYOUT_A, LAUNCHER)],
            100,
            1_000_000,
            0,
        );
        let bundle = match outcome {
            PersistedWriteOutcome::Bundle { bundle, .. } => bundle,
            other => panic!("expected Bundle, got {other:?}"),
        };
        writer
            .commit(LAUNCHER, &state.expect("decide returns state on success"))
            .unwrap();

        // "Restart": a brand-new `PersistedEntryWriter` (fresh in-memory scheduler state), backed
        // by the SAME store — this is the whole point of the seam.
        let writer_after_restart = PersistedEntryWriter::new(&store);

        // Rate bound survives the restart: a second attempt one second later is still withheld.
        let (rate_outcome, _) =
            writer_after_restart.decide(LAUNCHER, vec![add([9; 32], LAUNCHER)], 100, 1_000_000, 1);
        assert_eq!(rate_outcome, PersistedWriteOutcome::Pending { count: 1 });

        // Reentry cooldown survives the restart too: the just-removed payout hash is still held,
        // even though the scheduler that decided the removal no longer exists in memory.
        let post_restart_state = store.load(LAUNCHER).unwrap();
        assert!(post_restart_state
            .cooldown_until
            .contains_key(&(PAYOUT_A, LAUNCHER)));
        assert_eq!(bundle.actions.len(), 1);

        // Daily cap survives the restart: jump past the rate window but stay inside the same day,
        // with a fee that would exceed the remaining daily budget already spent pre-restart.
        let writer_later = PersistedEntryWriter::new(&store);
        let (cap_outcome, _) = writer_later.decide(
            LAUNCHER,
            vec![add([7; 32], LAUNCHER)],
            1_000_000, // exceeds the day's whole 1_000_000-mojo budget on top of the 100 already spent
            1_000_000,
            ENTRY_WRITE_MIN_INTERVAL_SECONDS + 2,
        );
        assert_eq!(
            cap_outcome,
            PersistedWriteOutcome::FeeBudgetExhausted { count: 1 }
        );
    }
}
