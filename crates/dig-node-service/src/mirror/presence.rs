//! Debounce — deciding when a `.dig` on disk has been there long enough to be worth 20 $DIG.
//!
//! # What this does NOT guard against
//!
//! A capsule this node pulls for itself is never observed half-written: it stages under the
//! downloads directory as `<store>-<root>.dig` and is only renamed into
//! `<cache>/modules/<store>/<root>.dig` after it verifies. The inventory scan reads the second
//! location, so the node's own writes are already atomic from the scan's point of view.
//!
//! The case that remains is the one a person creates: a `.dig` copied in by hand, moved across a
//! filesystem boundary, or written by an unrelated tool — and, symmetrically, one deleted and
//! restored while a pass was mid-flight. For those, a file that exists is not yet a file that is
//! being served.
//!
//! # Stability, not a timer after an event
//!
//! The rule is that a bond must be observed in the SAME state across a settling window before that
//! state is acted on. That is deliberately not "wait N seconds after the last event": an event-timer
//! is reset by each new event, so a directory being rewritten repeatedly never settles, and it also
//! cannot see a change that produced no event at all — which is every change that happened while the
//! process was not running.
//!
//! Observing state instead means a restart re-derives everything it needs from two scans, and a
//! capsule that appears and vanishes within the window is never acted on in either direction: it was
//! never stable, so neither the create nor the reclaim it would have implied is reached.
//!
//! # The asymmetry is deliberate
//!
//! Both directions are debounced, but they are not equally dangerous, and the window makes that
//! explicit. Acting early on an APPEARANCE locks 20 $DIG against a capsule that may be gone in a
//! second. Acting late on a DISAPPEARANCE leaves a coin live without its `.dig`, which is the
//! penalised state. So the settling window is a floor on how long a bond must be stable, and the
//! start-up reconcile — which has no window, because a scan at start-up IS the settled state —
//! remains the reliable path for the direction that costs money.

use std::collections::BTreeMap;

use super::plan::Bond;

/// How long a bond must hold a state before that state is acted on.
///
/// Chosen to be comfortably longer than a hand-copy of a large `.dig` across a filesystem boundary
/// and far shorter than the epoch, so a bond that settles is always acted on within its own epoch.
/// It is a floor on stability rather than a delay: a bond that has been stable for an hour is acted
/// on at the next pass, not an extra 30 seconds later.
pub const SETTLING_WINDOW_MS: u64 = 30_000;

/// Tracks how long each bond has held its current presence state.
///
/// The tracker is fed a full SNAPSHOT of what is on disk on each observation, never individual
/// events. That is what makes it survive a restart and a missed event identically: both are just an
/// observation whose previous state is unknown, and an unknown previous state is simply not yet
/// stable.
#[derive(Debug, Clone, Default)]
pub struct PresenceTracker {
    /// For each bond ever seen: whether it was present at the last observation, and the instant that
    /// state was first observed.
    seen: BTreeMap<Bond, Observation>,
}

/// One bond's last-observed state and when it entered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    present: bool,
    since_ms: u64,
}

impl PresenceTracker {
    /// A tracker that has observed nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record what is on disk at `now_ms`, and return the bonds whose presence has been stable for
    /// at least `window_ms`.
    ///
    /// The returned set is the SETTLED disk view — exactly what the planner should be handed as
    /// `held`. A bond that has appeared but not yet settled is absent from it, and so is one that
    /// has disappeared but not yet settled — which is why an appear-then-vanish inside the window
    /// produces no action in either direction.
    ///
    /// Bonds that have been absent and settled are forgotten, so the map does not grow without bound
    /// on a node whose cache churns. Forgetting is safe precisely because the tracker is
    /// snapshot-driven: a forgotten bond that reappears is simply a new appearance, and starts its
    /// window again.
    pub fn observe(&mut self, on_disk: &[Bond], now_ms: u64, window_ms: u64) -> Vec<Bond> {
        let current: std::collections::BTreeSet<&Bond> = on_disk.iter().collect();

        for bond in on_disk {
            match self.seen.get(bond) {
                Some(o) if o.present => {}
                _ => {
                    self.seen.insert(
                        bond.clone(),
                        Observation {
                            present: true,
                            since_ms: now_ms,
                        },
                    );
                }
            }
        }

        let vanished: Vec<Bond> = self
            .seen
            .iter()
            .filter(|(bond, o)| o.present && !current.contains(bond))
            .map(|(bond, _)| bond.clone())
            .collect();
        for bond in vanished {
            self.seen.insert(
                bond,
                Observation {
                    present: false,
                    since_ms: now_ms,
                },
            );
        }

        let settled: Vec<Bond> = self
            .seen
            .iter()
            .filter(|(_, o)| o.present && now_ms.saturating_sub(o.since_ms) >= window_ms)
            .map(|(bond, _)| bond.clone())
            .collect();

        self.seen
            .retain(|_, o| o.present || now_ms.saturating_sub(o.since_ms) < window_ms);

        settled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// An explicit instant. Every fixture below advances from it by hand rather than reading the
    /// wall clock, so the window under test is the one in the test and not however long the test
    /// happened to take.
    const T0: u64 = 1_700_000_000_000;
    const WINDOW: u64 = SETTLING_WINDOW_MS;

    #[test]
    fn a_newly_appeared_capsule_is_not_yet_settled() {
        let mut tracker = PresenceTracker::new();
        assert!(tracker.observe(&[bond("aa", "11")], T0, WINDOW).is_empty());
    }

    #[test]
    fn a_capsule_present_across_the_window_settles() {
        let mut tracker = PresenceTracker::new();
        tracker.observe(&[bond("aa", "11")], T0, WINDOW);
        assert_eq!(
            tracker.observe(&[bond("aa", "11")], T0 + WINDOW, WINDOW),
            vec![bond("aa", "11")]
        );
    }

    /// The bound from both sides: one millisecond under the window must NOT settle, and exactly at
    /// it must. A window tested only from above passes for an implementation with no window at all.
    #[test]
    fn the_settling_window_is_exact_in_both_directions() {
        let mut under = PresenceTracker::new();
        under.observe(&[bond("aa", "11")], T0, WINDOW);
        assert!(
            under
                .observe(&[bond("aa", "11")], T0 + WINDOW - 1, WINDOW)
                .is_empty(),
            "one millisecond short of the window is not settled"
        );

        let mut at = PresenceTracker::new();
        at.observe(&[bond("aa", "11")], T0, WINDOW);
        assert_eq!(
            at.observe(&[bond("aa", "11")], T0 + WINDOW, WINDOW),
            vec![bond("aa", "11")],
            "exactly at the window is settled"
        );
    }

    /// The hostile case the debounce exists for: a `.dig` that appears and vanishes inside the
    /// window locks nothing.
    ///
    /// The fixture carries a SECOND capsule that is present the whole time and must settle. Without
    /// it, a tracker that never settles anything at all passes — which is the failure mode a
    /// debounce most easily degrades into, and the one that would leave every store
    /// uncollateralised forever while looking cautious.
    #[test]
    fn a_capsule_that_appears_and_vanishes_inside_the_window_never_settles() {
        let mut tracker = PresenceTracker::new();
        let steady = bond("aa", "11");
        let flapping = bond("bb", "22");

        tracker.observe(&[steady.clone()], T0, WINDOW);
        tracker.observe(&[steady.clone(), flapping.clone()], T0 + 1_000, WINDOW);
        let settled = tracker.observe(&[steady.clone()], T0 + WINDOW, WINDOW);

        assert_eq!(
            settled,
            vec![steady],
            "the steady capsule settles and the flapping one never does"
        );
    }

    /// A capsule removed and restored inside the window is still the same settled presence, so a
    /// brief disappearance does not force a reclaim-and-recreate round trip — two fees and two
    /// confirmation waits for nothing, which is legacy melt/create churn.
    #[test]
    fn a_brief_disappearance_inside_the_window_does_not_unsettle_a_capsule() {
        let mut tracker = PresenceTracker::new();
        let b = bond("aa", "11");

        tracker.observe(&[b.clone()], T0, WINDOW);
        assert_eq!(tracker.observe(&[b.clone()], T0 + WINDOW, WINDOW), vec![b.clone()]);

        // Gone for one observation, back for the next, both inside a fresh window.
        tracker.observe(&[], T0 + WINDOW + 1_000, WINDOW);
        let settled = tracker.observe(&[b.clone()], T0 + WINDOW + 2_000, WINDOW);

        assert!(
            settled.is_empty(),
            "the capsule restarts its window rather than staying settled through a gap"
        );
        assert_eq!(
            tracker.observe(&[b.clone()], T0 + 2 * WINDOW + 2_000, WINDOW),
            vec![b],
            "and settles again once it has been stably present for a full window"
        );
    }

    /// A capsule that stays gone leaves the settled set, so the planner sees it as no longer held
    /// and reclaims its coin. The control is a capsule that stays.
    #[test]
    fn a_capsule_that_stays_gone_leaves_the_settled_set() {
        let mut tracker = PresenceTracker::new();
        let staying = bond("aa", "11");
        let leaving = bond("bb", "22");

        tracker.observe(&[staying.clone(), leaving.clone()], T0, WINDOW);
        assert_eq!(
            tracker.observe(&[staying.clone(), leaving.clone()], T0 + WINDOW, WINDOW),
            vec![staying.clone(), leaving]
        );

        assert_eq!(
            tracker.observe(&[staying.clone()], T0 + 2 * WINDOW, WINDOW),
            vec![staying],
            "the departed capsule is no longer held, which is what drives its reclaim"
        );
    }

    /// A bond that has been absent for longer than the window is forgotten, so a churning cache
    /// does not grow the tracker without bound.
    #[test]
    fn a_long_absent_bond_is_forgotten_and_reappears_as_new() {
        let mut tracker = PresenceTracker::new();
        let b = bond("aa", "11");

        tracker.observe(&[b.clone()], T0, WINDOW);
        tracker.observe(&[], T0 + WINDOW, WINDOW);
        tracker.observe(&[], T0 + 3 * WINDOW, WINDOW);

        assert!(
            tracker.seen.is_empty(),
            "a settled absence is forgotten rather than retained forever"
        );
        assert!(
            tracker.observe(&[b], T0 + 4 * WINDOW, WINDOW).is_empty(),
            "and a reappearance starts a fresh window rather than settling instantly"
        );
    }

    /// A restart is indistinguishable from a first observation, so nothing is acted on until the
    /// window has passed since the node came up. That is the honest reading: a fresh process knows
    /// how long a file has been on disk only by watching it.
    #[test]
    fn a_fresh_tracker_settles_nothing_on_its_first_observation() {
        let mut tracker = PresenceTracker::new();
        assert!(tracker
            .observe(&[bond("aa", "11"), bond("bb", "22")], T0, WINDOW)
            .is_empty());
    }
}
