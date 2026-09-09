//! SPEC §12.4: entry-set staleness, derived ONLY from chain-observed state — never a prover
//! self-report. See [`is_entry_set_stale`].
//!
//! This value MUST NOT appear on the prover status record (SPEC §2.4 — no precomputed staleness
//! anywhere on that record); it belongs only on the distributor's own chain read
//! (`dig.getRewardDistributor`'s `entry_set_stale`), derived fresh by the reader every time.

use super::port::DistributorChainState;
use super::spec_constants::STALE_ENTRY_SET_SECONDS;

/// SPEC §12.4: an entry set is stale when BOTH conjuncts hold:
/// 1. the distributor's reserve is non-zero (a zero reserve is `Unfunded` — a different report,
///    §6.5/§12.6 — and the entry set is kept regardless of staleness); and
/// 2. the last CHAIN-OBSERVED entry write (`DistributorChainState::last_entry_write_at`, the
///    singleton's own spend history) is at least `STALE_ENTRY_SET_SECONDS` old.
///
/// `last_entry_write_at == None` means the entry set has never been written to. That is not
/// "unknown" — it is maximally stale the moment the distributor itself has existed at least the
/// bound: "never written" cannot be more current than "written a long time ago".
pub fn is_entry_set_stale(
    state: &DistributorChainState,
    now: u64,
    distributor_created_at: u64,
) -> bool {
    if state.reserve_base_units == 0 {
        return false;
    }
    match state.last_entry_write_at {
        Some(last_write) => now.saturating_sub(last_write) >= STALE_ENTRY_SET_SECONDS,
        None => now.saturating_sub(distributor_created_at) >= STALE_ENTRY_SET_SECONDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::port::EntrySlot;

    fn state(reserve: u64, last_entry_write_at: Option<u64>) -> DistributorChainState {
        DistributorChainState {
            reserve_base_units: reserve,
            entries: Vec::<EntrySlot>::new(),
            current_distributor_epoch: 0,
            last_entry_write_at,
            total_paid_out_base_units: 0,
        }
    }

    #[test]
    fn zero_reserve_is_never_stale_regardless_of_write_age() {
        let s = state(0, Some(0));
        assert!(!is_entry_set_stale(&s, STALE_ENTRY_SET_SECONDS * 10, 0));
    }

    #[test]
    fn fresh_write_with_reserve_is_not_stale() {
        let s = state(100, Some(1_000));
        assert!(!is_entry_set_stale(
            &s,
            1_000 + STALE_ENTRY_SET_SECONDS - 1,
            0
        ));
    }

    #[test]
    fn write_older_than_bound_with_reserve_is_stale() {
        let s = state(100, Some(1_000));
        assert!(is_entry_set_stale(&s, 1_000 + STALE_ENTRY_SET_SECONDS, 0));
    }

    /// SPEC §12.4: a distributor whose entry set was NEVER written, funded, and at least as old as
    /// the bound is stale too — "never written" is maximally stale, not an unknown/false default.
    #[test]
    fn never_written_entry_set_with_reserve_and_old_enough_distributor_is_stale() {
        let s = state(100, None);
        let created_at = 500;
        assert!(is_entry_set_stale(
            &s,
            created_at + STALE_ENTRY_SET_SECONDS,
            created_at
        ));
    }

    #[test]
    fn never_written_entry_set_but_distributor_still_young_is_not_stale() {
        let s = state(100, None);
        let created_at = 500;
        assert!(!is_entry_set_stale(
            &s,
            created_at + STALE_ENTRY_SET_SECONDS - 1,
            created_at
        ));
    }
}
