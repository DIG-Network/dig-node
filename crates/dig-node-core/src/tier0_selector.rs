//! Tier-0 speculative-precache selector: given a set of candidate stores each
//! carrying a size and a [`relevance`](crate::relevance::relevance) score, pick
//! the subset worth speculatively caching under a small sub-budget carved out
//! of the node's whole [`crate::DIG_NODE_CACHE_CAP`] (never the whole cap —
//! Tier0 is opportunistic precache, and MUST leave the overwhelming majority
//! of the cache free for real Tier1 demand and Tier2 paid retention).
//!
//! PURE and deterministic: no clock, no I/O, no network. This module only
//! decides WHICH candidates to select and whether a fresh candidate is worth
//! displacing an incumbent — it does not sample the DHT (that is a later
//! child of epic #1934), fetch anything, or touch the live cache.

use crate::relevance::{should_displace, RelevanceValue};

/// The fraction of the whole node cache cap set aside for Tier0 speculative
/// precache. Deliberately small and conservative: Tier0 content is a bet, not
/// a request, and `evict_key` (crate::relevance) already sacrifices it first
/// under cross-tier pressure — but reserving only a slice of the cap up front
/// keeps that pressure from ever needing to bite in typical operation.
pub const TIER0_BUDGET_FRACTION: f64 = 0.10;

/// Anti-thrash margin for tier-0 re-selection hysteresis (see
/// [`select_with_hysteresis`]): a fresh candidate must beat an incumbent's
/// relevance by strictly more than this before it displaces it. Mirrors the
/// margin concept `should_displace` (crate::relevance) already defines; this
/// constant is the tier-0 selector's own default, tunable independently of
/// whatever margin a caller elsewhere in the cache picks.
pub const DEFAULT_HYSTERESIS_MARGIN: f64 = 0.05;

/// Compute the tier-0 sub-budget (bytes) from the whole node cache cap.
///
/// Pure arithmetic over a caller-supplied cap — this module never reads
/// `DIG_NODE_CACHE_CAP`/config itself (that lookup is I/O, owned by
/// [`crate::cache_cap_bytes`]). Rounds down, so the sub-budget never exceeds
/// the intended fraction of the whole cap.
#[must_use]
pub fn tier0_budget_bytes(whole_cache_cap_bytes: u64) -> u64 {
    ((whole_cache_cap_bytes as f64) * TIER0_BUDGET_FRACTION) as u64
}

/// One candidate the tier-0 selector may choose to precache: its identity is
/// the caller's concern (an index/content-id the caller correlates back to),
/// this selector only needs its size and its already-computed relevance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate {
    /// Size of the store on disk, in bytes. Zero is handled defensively (see
    /// [`select_within_budget`]) rather than treated as an error — a caller
    /// that hasn't yet learned a size should simply not nominate the
    /// candidate, but this selector doesn't assume that discipline.
    pub size_bytes: u64,
    /// The candidate's relevance score, computed by
    /// [`crate::relevance::relevance`]. Not recomputed here — the caller
    /// supplies it so this module stays free of the scoring inputs/weights.
    pub relevance: RelevanceValue,
}

/// Select the value-density-optimal subset of `candidates` whose total size
/// fits within `budget_bytes`.
///
/// ## Why greedy-by-density, not dynamic-programming knapsack
/// This is deliberately the greedy fractional-knapsack heuristic (sort by
/// `relevance / size_bytes` descending, take while it fits) rather than an
/// exact 0/1 DP. A DP knapsack is `O(n * budget)` — at a GiB-scale tier0
/// budget that is billions of table cells, wildly disproportionate to what
/// "worth speculatively caching" needs. Greedy is `O(n log n)`, runs every
/// sweep without a scaling concern, and is near-optimal in practice: it can
/// only under-fill the last unit of budget by at most one candidate's size,
/// which is immaterial at real store sizes against a real budget. Precision
/// perfection here would be optimizing a guess.
///
/// Zero-size candidates are treated as maximally dense (free to keep, so they
/// sort first) and are always included as long as any budget remains — a size
/// of 0 cannot make selection worse, and dividing by it would be undefined.
#[must_use]
pub fn select_within_budget(candidates: &[Candidate], budget_bytes: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by(|&a, &b| {
        density(&candidates[a])
            .partial_cmp(&density(&candidates[b]))
            .unwrap_or(std::cmp::Ordering::Equal)
            .reverse() // descending: densest first
    });

    let mut selected = Vec::new();
    let mut used = 0u64;
    for idx in order {
        let size = candidates[idx].size_bytes;
        match used.checked_add(size) {
            Some(next) if next <= budget_bytes => {
                used = next;
                selected.push(idx);
            }
            _ => continue, // doesn't fit; skip and keep trying smaller/later candidates
        }
    }
    selected
}

/// Value density (relevance per byte) used to rank candidates in
/// [`select_within_budget`]. A zero-size candidate is defined as
/// `f64::INFINITY` density — free to keep, so it always sorts first and is
/// never divided-by-zero.
fn density(candidate: &Candidate) -> f64 {
    if candidate.size_bytes == 0 {
        f64::INFINITY
    } else {
        candidate.relevance.get() / (candidate.size_bytes as f64)
    }
}

/// Hysteresis gate for tier-0 re-selection: should `candidate` replace
/// `incumbent` in the held tier-0 set?
///
/// Thin, named wrapper over [`should_displace`] (crate::relevance) — reused
/// rather than reimplemented, per this module's contract. Kept here (rather
/// than calling `should_displace` directly at call sites) so the tier-0
/// selector's OWN default margin ([`DEFAULT_HYSTERESIS_MARGIN`]) is the
/// obvious thing a caller reaches for, while still allowing an explicit
/// override via `margin`.
#[must_use]
pub fn should_displace_tier0(
    incumbent: RelevanceValue,
    candidate: RelevanceValue,
    margin: f64,
) -> bool {
    should_displace(incumbent, candidate, margin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(relevance: f64, size_bytes: u64) -> Candidate {
        Candidate {
            size_bytes,
            relevance: RelevanceValue(relevance),
        }
    }

    #[test]
    fn tier0_budget_is_a_fraction_of_the_whole_cache_cap() {
        assert_eq!(tier0_budget_bytes(1_000_000_000), 100_000_000);
        assert_eq!(tier0_budget_bytes(0), 0);
    }

    #[test]
    fn greedy_picks_the_density_optimal_subset_within_budget() {
        // Densities: A = 10/10 = 1.0, B = 9/5 = 1.8, C = 1/1 = 1.0.
        // Budget 6 bytes: B (5, density 1.8) then C (1, density 1.0) fits in
        // 6; A (10) never fits at all. Greedy must pick B, then C.
        let candidates = vec![
            candidate(10.0, 10), // A
            candidate(9.0, 5),   // B
            candidate(1.0, 1),   // C
        ];
        let selected = select_within_budget(&candidates, 6);
        assert_eq!(selected, vec![1, 2], "expected B then C by density order");
    }

    #[test]
    fn selected_set_never_exceeds_the_sub_budget() {
        let candidates = vec![
            candidate(5.0, 100),
            candidate(4.0, 100),
            candidate(3.0, 100),
            candidate(2.0, 100),
        ];
        let budget = 250;
        let selected = select_within_budget(&candidates, budget);
        let total: u64 = selected.iter().map(|&i| candidates[i].size_bytes).sum();
        assert!(
            total <= budget,
            "selected total {total} exceeds budget {budget}"
        );
        // Densest-first greedy: candidate 0 (density .05) then 1 (.04) fit in
        // 200; candidate 2 would push to 300 > 250 so it's skipped, and so is
        // candidate 3 (still 300 > 250 alone with the running total).
        assert_eq!(selected, vec![0, 1]);
    }

    #[test]
    fn zero_size_candidates_are_always_included_and_never_divide_by_zero() {
        let candidates = vec![candidate(1.0, 0), candidate(1.0, 0)];
        let selected = select_within_budget(&candidates, 0);
        assert_eq!(selected.len(), 2, "free candidates must all be selected");
    }

    #[test]
    fn marginally_better_candidate_does_not_displace_within_the_margin() {
        let incumbent = RelevanceValue(1.0);
        let margin = DEFAULT_HYSTERESIS_MARGIN;

        // Within the margin: stays.
        assert!(!should_displace_tier0(
            incumbent,
            RelevanceValue(1.0 + margin),
            margin
        ));
        // Beyond the margin: displaces.
        assert!(should_displace_tier0(
            incumbent,
            RelevanceValue(1.0 + margin + 0.001),
            margin
        ));
    }
}
