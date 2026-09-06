//! The **personal day** — dig-node#570's daily reflexive-address check, spread across the network
//! without a synchronised spike, and the hysteresis + epoch cap that keep it from spending on a flap.
//!
//! # Derived, never drawn — the failure this avoids
//!
//! The user asked for a random daily time so the whole network does not hit the STUN tier at once
//! (dig-node#570, 2026-09-05: *"daily at a random time so the whole network doesnt hit the stun
//! server at once"*). The obvious implementation — draw a random offset once, at start-up or once
//! ever, and persist it — has a silent failure mode: a node that restarts before its slot re-rolls
//! (start-up draw) or loses its state file (persisted draw) and can go indefinitely without a single
//! check while every log line looks normal. A THUNDERING HERD IS AT LEAST VISIBLE; A NODE THAT
//! SILENTLY NEVER CHECKS IS NOT.
//!
//! So the offset is a pure function of the node's own `peer_id` (`SPEC.md` §25.13.7.1):
//!
//! ```text
//! offset_secs = u64::from_be_bytes(SHA-256(TAG ‖ peer_id)[0..8]) mod 86_400
//! ```
//!
//! This has no state to lose. A restart recomputes the SAME offset from the SAME identity, so a
//! node that restarts daily still checks daily — it just does so within its personal day, wherever
//! that day's boundary already was, rather than re-rolling a coin toss on every boot. It is random
//! ACROSS the network (peer ids are hashes, so offsets are uniform) without being random over TIME
//! for any one node — which is the only kind of randomness the requirement actually needs.
//!
//! # What deriving from a public value gives away, bounded
//!
//! A peer id is not secret, so a third party who knows one knows that node's slot. What that buys
//! is the ability to time a STUN-tier outage or a flood of dissenting readings at a node's check —
//! which makes the check INCONCLUSIVE (fails toward staleness, never toward a spend) and cannot
//! itself cause a reclaim: a spend requires agreement across independent source classes
//! (`dig_stun::establish`, NC-12), which timing does not provide. The offset MUST NOT be derived
//! from any address or reading, precisely so the schedule cannot correlate with what it measures.

/// One personal day is 24 hours, exactly — the period the offset subdivides `00:00 UTC` into.
const PERSONAL_DAY_SECS: u64 = 86_400;

/// The domain-separation tag for the offset derivation (`SPEC.md` §25.13.7.1). Versioned so a future
/// change to the derivation is a new tag, never a silent reinterpretation of the old one — which
/// would move every node's slot on the same night without anyone deciding to.
const PERSONAL_DAY_TAG: &[u8] = b"dig-node/mirror-url-reconcile/personal-day/v1";

/// `SPEC.md` §25.13.7.5: at most one automatic reconcile per mirror epoch. Rollover already costs
/// every bonded capsule one reclaim and one create per epoch; this cap means the automatic URL
/// reconcile adds at most one more pair — the lifecycle's unattended spend count is at most
/// DOUBLED, never unbounded, however often an address actually changes.
pub const URL_RECONCILE_MAX_AUTO_PER_EPOCH: u32 = 1;

/// Derive this node's personal-day offset from its 32-byte `peer_id`.
///
/// Pure and reproducible: the same `peer_id` always yields the same offset, on every machine, on
/// every day — which is what lets `dign mirror bond-states` print it and an operator verify it by
/// hand (`SPEC.md` §C). Never persisted; there is nothing here to lose.
///
/// A node with no `peer_id` yet (the peer network disabled or not up) has no identity to derive
/// from and gets offset zero — the caller's problem to interpret (`SPEC.md` §25.13.7.1: such a node
/// gathers no readings and cannot be part of a STUN herd, so the spreading buys nothing there).
pub fn personal_day_offset_secs(peer_id: &[u8]) -> u64 {
    let mut hasher = chia_sha2::Sha256::new();
    hasher.update(PERSONAL_DAY_TAG);
    hasher.update(peer_id);
    let digest = hasher.finalize();

    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[0..8]);
    u64::from_be_bytes(first8) % PERSONAL_DAY_SECS
}

/// The personal-day index of `now_unix_secs`, floored toward negative infinity.
///
/// Floor-toward-negative-infinity (not truncation) matters on day zero: an instant that precedes
/// the offset by a few seconds must resolve to day **-1**, not wrap to a huge positive index via
/// unsigned subtraction. `i64` arithmetic throughout keeps that representable.
pub fn personal_day_index(now_unix_secs: i64, offset_secs: u64) -> i64 {
    (now_unix_secs - offset_secs as i64).div_euclid(PERSONAL_DAY_SECS as i64)
}

/// Is a check due? Four consequences fall out of this one comparison (`SPEC.md` §25.13.7.2), each
/// stated because each is easy to get backwards:
///
/// * **At most one check per personal day** — `d(now) == last_completed` is not due.
/// * **A clock that moves BACKWARD never makes a check due** — `d(now) < last_completed` is not due
///   either; the node waits for real time to catch back up rather than re-checking on the way down.
/// * **A clock that jumps FORWARD by `N` days makes exactly one check due**, not `N`: this predicate
///   only ever answers yes/no for THIS instant, and the caller marks the day completed on any
///   outcome (conclusive or not), so the very next evaluation — even one second later, after a
///   multi-day jump — already reads `d(now) == last_completed` and refuses to double up.
/// * **`None` (never observed) is always due.**
pub fn is_due(now_unix_secs: i64, offset_secs: u64, last_completed_day: Option<i64>) -> bool {
    let today = personal_day_index(now_unix_secs, offset_secs);
    match last_completed_day {
        None => true,
        Some(last) => today > last,
    }
}

/// One CONCLUSIVE observation of what this node would advertise, taken on one personal day.
///
/// `urls` is compared as a SET (order ignored) everywhere this type is consulted — `SPEC.md`
/// §25.13.3's reason applies here identically: an operator's URL list is published in the order
/// they set it, with a derived IPv6 candidate placed first, so a reorder is not a change.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    /// The personal day this observation was taken on.
    pub personal_day: i64,
    /// The URL set this node would have advertised, had it reconciled right then.
    pub urls: Vec<String>,
}

/// Two URL sets, compared the way every clause in this module compares them: as sets, order
/// ignored. A private helper rather than a `HashSet` at the call site, so every comparison in this
/// module (and nowhere else) shares one definition of "the same address".
fn same_url_set(a: &[String], b: &[String]) -> bool {
    let a: std::collections::BTreeSet<&String> = a.iter().collect();
    let b: std::collections::BTreeSet<&String> = b.iter().collect();
    a == b
}

/// `SPEC.md` §25.13.7.4 — is `target` STABLE against the two most recent conclusive observations?
///
/// Stable means both recorded observations agree with `target` (set equality) AND were taken on two
/// DISTINCT personal days. A single observation is never enough — that would spend on the first
/// STUN answer after a network blip — and two observations on the SAME day (which [`is_due`] should
/// never produce, but this function does not trust that) are one measurement wearing two dates.
///
/// Feeding this fewer than two observations, or two that disagree, or two on the same day, all
/// answer `false` — the safe direction: hysteresis fails toward NOT spending.
pub fn is_stable(observations: &[Observation], target: &[String]) -> bool {
    let [a, b] = observations else { return false };
    a.personal_day != b.personal_day
        && same_url_set(&a.urls, target)
        && same_url_set(&b.urls, target)
}

/// `SPEC.md` §25.13.7.5 — may the automatic trigger reconcile in `current_epoch`?
///
/// `false` exactly when this epoch already has one accepted automatic reconcile recorded. The cap
/// is keyed on the epoch the reconcile ran in, not on a rolling window, so it resets for free at
/// every rollover — the same boundary that already closes any remaining drift at no cost.
pub fn epoch_cap_allows(last_auto_reconcile_epoch: Option<i64>, current_epoch: i64) -> bool {
    last_auto_reconcile_epoch != Some(current_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- personal_day_offset_secs: golden vectors ---------------------------------------------

    /// **Golden vector.** `python3 -c "import hashlib; print(int.from_bytes(hashlib.sha256(b'dig-node/mirror-url-reconcile/personal-day/v1' + bytes(range(32))).digest()[:8],'big') % 86400)"`
    /// prints `78322`. Pinned so a change to the derivation (tag, byte order, truncation) is caught
    /// as a broken vector rather than silently moving every node's slot on the same night.
    #[test]
    fn golden_vector_sequential_peer_id() {
        let peer_id: Vec<u8> = (0u8..32).collect();
        assert_eq!(personal_day_offset_secs(&peer_id), 78_322);
    }

    /// **A second vector, with a DIFFERENT identity.** Distinguishes "the derivation depends on
    /// `peer_id`" from "the derivation returns a fixed constant that happens to satisfy the first
    /// vector" — a fixture the first vector alone cannot rule out.
    #[test]
    fn golden_vector_all_ff_peer_id_differs_from_sequential() {
        let peer_id = [0xFFu8; 32];
        assert_eq!(personal_day_offset_secs(&peer_id), 43_202);
    }

    #[test]
    fn offset_is_reproducible_for_the_same_identity() {
        let peer_id = b"some-32-byte-peer-id-000000000!!".to_vec();
        assert_eq!(peer_id.len(), 32);
        assert_eq!(
            personal_day_offset_secs(&peer_id),
            personal_day_offset_secs(&peer_id),
            "a restart must recompute the SAME slot from the SAME identity"
        );
    }

    #[test]
    fn offset_is_always_within_one_day() {
        for seed in 0u8..20 {
            let peer_id = [seed; 32];
            assert!(personal_day_offset_secs(&peer_id) < PERSONAL_DAY_SECS);
        }
    }

    // --- personal_day_index ---------------------------------------------------------------------

    #[test]
    fn day_index_at_exactly_the_offset_is_zero() {
        assert_eq!(personal_day_index(1_000, 1_000), 0);
    }

    /// **The property this fixture exists to prove**: an instant a few seconds BEFORE the offset,
    /// on day zero, is day **-1** — not a huge positive index from an unsigned wraparound. A naive
    /// `(now - offset) / 86_400` in unsigned arithmetic would panic or wrap here; a naive truncating
    /// signed division would round toward zero and report day 0, one day too late.
    #[test]
    fn day_index_just_before_the_offset_on_day_zero_is_negative_one() {
        assert_eq!(personal_day_index(999, 1_000), -1);
    }

    #[test]
    fn day_index_advances_by_one_per_86400_seconds() {
        let offset = 12_345;
        let day0_start = offset as i64;
        assert_eq!(personal_day_index(day0_start, offset), 0);
        assert_eq!(personal_day_index(day0_start + 86_399, offset), 0);
        assert_eq!(personal_day_index(day0_start + 86_400, offset), 1);
        assert_eq!(personal_day_index(day0_start - 1, offset), -1);
    }

    // --- is_due: the four clock consequences, each pinned -------------------------------------

    #[test]
    fn never_observed_is_always_due() {
        assert!(is_due(0, 0, None));
        assert!(is_due(1_000_000_000, 54_321, None));
    }

    #[test]
    fn same_personal_day_is_not_due_twice() {
        let offset = 100;
        let today = personal_day_index(50_000, offset);
        assert!(!is_due(50_000, offset, Some(today)));
    }

    #[test]
    fn the_next_personal_day_is_due() {
        let offset = 100;
        let today = personal_day_index(50_000, offset);
        assert!(is_due(50_000 + 86_400, offset, Some(today)));
    }

    /// **A clock moving backward must never make a check due.** An NTP correction that steps the
    /// clock back must not be read as "a new day arrived" — the node waits for real time to catch
    /// back up rather than re-checking (and potentially re-spending) on the way down.
    #[test]
    fn a_backward_clock_is_never_due() {
        let offset = 100;
        let today = personal_day_index(200_000, offset);
        assert!(!is_due(150_000, offset, Some(today)));
    }

    /// **A forward jump of N days is due exactly once, not N times** — evaluating `is_due` again
    /// immediately after marking the (post-jump) day completed must read as NOT due, proving the
    /// predicate cannot be tricked into re-firing for the days it skipped over.
    #[test]
    fn a_forward_jump_of_several_days_is_due_exactly_once() {
        let offset = 0;
        let last = personal_day_index(0, offset); // day 0
        let after_jump = 10 * 86_400; // +10 days
        assert!(is_due(after_jump, offset, Some(last)));

        // The caller marks TODAY (the post-jump day) completed, not day 1 -- and the next
        // evaluation, even moments later, must not re-fire.
        let now_completed = personal_day_index(after_jump, offset);
        assert!(!is_due(after_jump + 1, offset, Some(now_completed)));
    }

    // --- is_stable: hysteresis --------------------------------------------------------------------

    fn obs(day: i64, url: &str) -> Observation {
        Observation {
            personal_day: day,
            urls: vec![url.to_string()],
        }
    }

    #[test]
    fn zero_or_one_observation_is_never_stable() {
        assert!(!is_stable(&[], &[]));
        assert!(!is_stable(
            &[obs(1, "https://a")],
            &["https://a".to_string()]
        ));
    }

    /// **The exact property named in the ticket**: `A, B, A` across three days — two DIFFERENT
    /// readings among the three — is not stable, because the two most recent (`B`, `A`) disagree.
    /// This is the flap the hysteresis rule exists to wait out, and it is the fixture that
    /// distinguishes "compares the two most recent" from "compares any two", which a weaker
    /// implementation (checking membership in a set of ever-seen addresses) would satisfy.
    #[test]
    fn a_b_a_across_three_days_is_not_stable() {
        let observations = vec![obs(2, "https://b"), obs(3, "https://a")];
        assert!(!is_stable(&observations, &["https://a".to_string()]));
    }

    /// **`A, inconclusive, A` establishes `A` on the third day** — an inconclusive day is never
    /// RECORDED as an observation at all (the caller only pushes conclusive ones), so the two most
    /// recent conclusive observations are `A` (day 1) and `A` (day 3): different days, same set.
    #[test]
    fn two_conclusive_agreements_on_distinct_days_are_stable_even_with_a_gap() {
        let observations = vec![obs(1, "https://a"), obs(3, "https://a")];
        assert!(is_stable(&observations, &["https://a".to_string()]));
    }

    #[test]
    fn two_observations_on_the_same_day_are_never_stable() {
        // Defensive: `is_due` should prevent this from ever being recorded, but `is_stable` does
        // not trust that -- a same-day pair is one measurement, not two, however it got here.
        let observations = vec![obs(5, "https://a"), obs(5, "https://a")];
        assert!(!is_stable(&observations, &["https://a".to_string()]));
    }

    /// A reorder of the operator's own URL list is not a change (`SPEC.md` §25.13.3) -- proven here
    /// too, since hysteresis must not see a reorder as instability.
    #[test]
    fn a_reordered_url_list_is_still_the_same_set() {
        let observations = vec![
            Observation {
                personal_day: 1,
                urls: vec!["https://a".to_string(), "https://b".to_string()],
            },
            Observation {
                personal_day: 2,
                urls: vec!["https://b".to_string(), "https://a".to_string()],
            },
        ];
        assert!(is_stable(
            &observations,
            &["https://a".to_string(), "https://b".to_string()]
        ));
    }

    // --- epoch_cap_allows ---------------------------------------------------------------------

    #[test]
    fn never_reconciled_allows_this_epoch() {
        assert!(epoch_cap_allows(None, 42));
    }

    #[test]
    fn a_reconcile_already_recorded_this_epoch_refuses_a_second() {
        assert!(!epoch_cap_allows(Some(42), 42));
    }

    #[test]
    fn a_reconcile_recorded_in_a_DIFFERENT_epoch_allows_this_one() {
        assert!(epoch_cap_allows(Some(41), 42));
    }
}
