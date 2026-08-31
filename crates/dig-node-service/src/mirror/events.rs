//! Event-driven wakes for the §25 mirror pass — an accelerant over the round timer (dig-node#465).
//!
//! # Events buy latency. They never buy correctness.
//!
//! [`super`]'s module doc rejects a file watcher **as the correctness mechanism**, and that stands:
//! *"a watcher's event is exactly what a crash loses; a scan at start-up re-derives the whole answer
//! from two observations that survive anything."* Nothing here weakens it. The round timer and the
//! start-up reconcile are untouched — not deleted, and deliberately not lengthened to compensate for
//! having events, which would trade the correctness floor for responsiveness.
//!
//! So the invariant this module is built to keep is: **no behaviour depends on an event arriving.**
//! A wake decides only *when* the next pass runs, never *whether* one runs and never what it
//! concludes. Silence every source forever and the node converges exactly as it does today, one
//! round later. That is asserted rather than intended — see the silencing test below.
//!
//! # Why a disk watcher, and why NOT a chain subscription
//!
//! **Disk** is where the latency is. A create is decided from capsule presence, and a capsule
//! landing is otherwise invisible until the next scan.
//!
//! **Chain events do not trigger a pass, on purpose.** Three reasons, in order of weight:
//!
//! 1. A new peak arrives roughly every 18.75 seconds. Each pass reads chain and may *spend money*,
//!    so peaks are the single largest amplification source available on this path — the trigger most
//!    worth suppressing rather than adding.
//! 2. Chain activity cannot make a create newly correct. Creates are decided from disk presence;
//!    chain is read to learn what is already bonded.
//! 3. The reclaim deadline the chain seems to imply — an epoch rolling over — is *wall-clock*, not a
//!    chain event: `crate::collateral::current_epoch_now` derives it locally. A peak subscription
//!    would be new integration bought to obtain a signal the node already has.
//!
//! Chain therefore stays observed inside the pass, on the round timer, where one round (10 minutes)
//! already bounds reclaim latency far inside an epoch.
//!
//! # Two wakes per burst, and why it is two rather than one
//!
//! [`super::presence`] settles a bond by observing it in the SAME state across
//! [`super::presence::SETTLING_WINDOW_MS`], and `since_ms` is stamped at the first *observation* —
//! not at the moment the file appeared. A single wake would therefore only ever RECORD the
//! appearance; something has to look again, later, for it to be acted on.
//!
//! So one burst of writes produces at most two passes, whatever its size:
//!
//! * an **observing** wake once writes have been quiet for [`QUIET_PERIOD_MS`], which stamps the
//!   bond, and
//! * one **settling** wake [`super::presence::SETTLING_WINDOW_MS`] later, which is the earliest
//!   instant the tracker can act on it.
//!
//! The settling wake does not re-arm, so the sequence terminates: N events in a quiet window cause
//! exactly one observing pass and exactly one settling pass, never N of either.
//!
//! Latency for a capsule copied in by hand goes from up to two round timers (~20 minutes, because
//! the first round only stamps it) to roughly `QUIET_PERIOD_MS + SETTLING_WINDOW_MS` — about 35
//! seconds — without any figure in the settling contract changing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Notify;

/// How long disk writes must be quiet before the observing wake fires.
///
/// A debounce, not a delay: it exists so that copying a large `.dig` in — which lands as a long
/// stream of write events — causes one pass when the copy finishes rather than one per event.
///
/// Short on purpose, and NOT the settling window. Settling is a stability requirement on the
/// CAPSULE, enforced by [`super::presence`] regardless of what this module does. This is only how
/// long the waker waits to be reasonably sure the writing has stopped; lengthening it would delay
/// the observing pass without making any decision safer.
pub const QUIET_PERIOD_MS: u64 = 5_000;

/// The floor on how often events may cause a pass, whatever arrives.
///
/// The bound that matters for money: a pass reads chain and may spend, so a pathological tool — or
/// anything with write access to the cache directory — must not be able to drive the pass rate.
///
/// It is one **settling window**, and that figure is derived rather than picked. A pass can only act
/// on a change once [`super::presence`] has seen that change hold for a settling window, so two
/// event-driven passes closer together than one window cannot reach a decision the later of them
/// would not have reached alone — the extra passes are pure amplification.
///
/// [`QUIET_PERIOD_MS`] alone does NOT bound this, which is why the floor is not redundant: writes
/// arriving just slower than the quiet period quiesce every time, and would otherwise wake a pass
/// every few seconds indefinitely.
pub const MIN_EVENT_PASS_INTERVAL_MS: u64 = super::presence::SETTLING_WINDOW_MS;

/// Decides WHEN disk events are allowed to become a pass. Pure, so the bound is testable.
///
/// Holds no clock and no channel: every method takes `now_ms`, exactly as
/// [`super::presence::PresenceTracker`] does, so a test measures the window written in the test
/// rather than however long the test happened to take.
#[derive(Debug, Clone, Default)]
pub struct WakeCoalescer {
    /// When the most recent event arrived, while a wake is still owed for it.
    last_event_ms: Option<u64>,
    /// A settling wake scheduled by a previous observing wake, and its instant.
    follow_up_ms: Option<u64>,
    /// When the last wake was taken, for the [`MIN_EVENT_PASS_INTERVAL_MS`] floor.
    last_wake_ms: Option<u64>,
}

impl WakeCoalescer {
    /// A coalescer that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that something changed under the capsule cache.
    ///
    /// Collapsing rather than queueing is the whole point: the state is one instant, not a list, so
    /// a burst of any size — including one that arrives while a pass is running, or while one is
    /// wedged — occupies the same fixed space and produces the same single owed wake.
    pub fn record_event(&mut self, now_ms: u64) {
        self.last_event_ms = Some(now_ms);
    }

    /// The instant at which a wake is next owed, if one is.
    ///
    /// `None` means nothing is pending and the caller waits on the round timer alone.
    pub fn due_at_ms(&self) -> Option<u64> {
        let quiet = self.last_event_ms.map(|at| at + QUIET_PERIOD_MS);
        let due = match (quiet, self.follow_up_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }?;
        Some(match self.last_wake_ms {
            Some(last) => due.max(last + MIN_EVENT_PASS_INTERVAL_MS),
            None => due,
        })
    }

    /// Take the owed wake if it is due at `now_ms`.
    ///
    /// Taking an OBSERVING wake schedules the one settling wake the module doc describes. Taking
    /// that settling wake schedules nothing, so the sequence terminates and a burst can never
    /// sustain itself.
    pub fn take_due(&mut self, now_ms: u64) -> bool {
        match self.due_at_ms() {
            Some(due) if now_ms >= due => {
                let was_observing = self.last_event_ms.is_some();
                self.last_event_ms = None;
                self.follow_up_ms = if was_observing {
                    Some(now_ms + super::presence::SETTLING_WINDOW_MS)
                } else {
                    None
                };
                self.last_wake_ms = Some(now_ms);
                true
            }
            _ => false,
        }
    }
}

/// A live source of disk events, and the signal a waiting pass loop selects on.
///
/// Held as an `Option` by the caller, so `None` is a node with no event source at all — the
/// configuration the convergence assertion runs in.
pub struct DiskEvents {
    signal: Arc<Notify>,
    /// Kept alive for as long as events are wanted; dropping it stops the watcher.
    _watcher: Box<dyn std::any::Any + Send + Sync>,
}

impl DiskEvents {
    /// Wait for the next disk event. Cancel-safe, so it composes with `tokio::select!`.
    pub async fn changed(&self) {
        self.signal.notified().await;
    }
}

/// Watch `cache_dir` for capsules appearing and disappearing.
///
/// Watching the directory rather than hooking the code that writes into it is deliberate: it sees a
/// `.dig` copied in by hand or written by an unrelated tool, which is precisely the case
/// [`super::presence`] says the settling window exists for, and it needs no cooperation from any
/// write path.
///
/// Returns `None` when no watcher can be established — an unsupported filesystem, a missing
/// directory, a platform limit. That is a latency loss and nothing more, which is why it is an
/// `Option` rather than an error worth failing bring-up over.
pub fn watch_capsule_cache(cache_dir: &Path) -> Option<DiskEvents> {
    use notify::Watcher as _;

    let signal = Arc::new(Notify::new());
    let sink = Arc::clone(&signal);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        // Any event under the cache is a hint that the capsule set MAY have changed. Deliberately
        // unfiltered by path or kind: the pass re-derives the whole answer from a scan anyway, so a
        // false hint costs one early pass and a missed one costs only latency.
        if res.is_ok() {
            sink.notify_one();
        }
    })
    .ok()?;
    watcher
        .watch(cache_dir, notify::RecursiveMode::Recursive)
        .ok()?;

    Some(DiskEvents {
        signal,
        _watcher: Box::new(watcher),
    })
}

/// Where capsules land — `<cache>/modules`, the directory the inventory scan reads.
pub fn capsule_cache_dir(cache_root: &Path) -> PathBuf {
    cache_root.join("modules")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::presence::SETTLING_WINDOW_MS;

    /// An explicit instant, for the same reason `presence.rs` pins one: the window under test must
    /// be the one written here, not however long the test took to run.
    const T0: u64 = 1_700_000_000_000;

    /// The round timer, for comparison. A wake is only worth anything if it is far inside this.
    const ROUND_MS: u64 = dig_constants::MIRROR_ROUND_LENGTH_MS as u64;

    #[test]
    fn a_capsule_appearing_wakes_a_pass_far_inside_the_round_timer() {
        let mut c = WakeCoalescer::new();
        c.record_event(T0);

        let due = c.due_at_ms().expect("an event owes a wake");
        let delay = due - T0;

        // The DELAY is the assertion, not that a wake happened: a wake arriving at the round
        // boundary would satisfy the latter and be worth nothing.
        assert_eq!(delay, QUIET_PERIOD_MS);
        assert!(
            delay * 20 < ROUND_MS,
            "an event-driven wake must be an order of magnitude inside the round timer, \
             but {delay}ms is not far inside {ROUND_MS}ms"
        );
        assert!(c.take_due(T0 + delay));
    }

    #[test]
    fn a_burst_of_events_in_one_window_produces_exactly_one_observing_pass() {
        let mut c = WakeCoalescer::new();

        // 200 events spread across a settling window — a large `.dig` being copied in. Recorded
        // and drained in the SAME loop, as they arrive in production: a fixture that recorded them
        // all up front would only ever see the last one and could not tell coalescing from luck.
        let step = SETTLING_WINDOW_MS / 200;
        let last_event = T0 + 199 * step;

        let mut passes = 0;
        let mut now = T0;
        // Up to the last event's quiet period plus one step, which is still well before the settling
        // wake the observing pass schedules, so only observing passes are counted here.
        while now <= last_event + QUIET_PERIOD_MS + step {
            if now <= last_event && (now - T0) % step == 0 {
                c.record_event(now);
            }
            if c.take_due(now) {
                passes += 1;
            }
            now += step;
        }

        assert_eq!(
            passes, 1,
            "200 events in one window must cause ONE observing pass, not one per event"
        );
    }

    #[test]
    fn a_burst_produces_a_settling_pass_and_then_stops() {
        let mut c = WakeCoalescer::new();
        c.record_event(T0);

        let observing = c.due_at_ms().unwrap();
        assert!(c.take_due(observing));

        // The settling wake is owed exactly one settling window later — the earliest instant
        // `PresenceTracker` can act on a bond first stamped by the observing pass.
        let settling = c
            .due_at_ms()
            .expect("an observing pass owes one settling pass");
        assert_eq!(settling - observing, SETTLING_WINDOW_MS);
        assert!(c.take_due(settling));

        // And then nothing. If this re-armed, one write would drive the pass forever.
        assert_eq!(
            c.due_at_ms(),
            None,
            "the settling wake must not re-arm, or a single event sustains passes indefinitely"
        );
        assert!(!c.take_due(settling + ROUND_MS));
    }

    #[test]
    fn events_arriving_during_a_pass_collapse_into_one_pending_wake() {
        let mut c = WakeCoalescer::new();
        c.record_event(T0);
        let observing = c.due_at_ms().unwrap();
        assert!(c.take_due(observing));

        // The pass is now running. Thousands of events land while it does.
        for i in 0..5_000u64 {
            c.record_event(observing + i);
        }

        // Exactly one further wake is owed over the next settling window. Not 5,000, and not one
        // per event drained as a burst once the pass finishes.
        let mut passes = 0;
        let mut now = observing;
        while now <= observing + SETTLING_WINDOW_MS + 1_000 {
            if c.take_due(now) {
                passes += 1;
            }
            now += 250;
        }
        assert_eq!(
            passes, 1,
            "events arriving during a pass must collapse into ONE owed wake, not queue"
        );
    }

    #[test]
    fn no_two_event_driven_passes_are_closer_than_the_floor() {
        let mut c = WakeCoalescer::new();
        let mut taken: Vec<u64> = Vec::new();

        // The fixture that actually reaches the floor: writes spaced just LONGER than the quiet
        // period, so every one of them quiesces and owes a wake. A continuous write storm would not
        // test this — it never goes quiet, so it never wakes a pass at all, and the round timer is
        // the only thing that runs. This is the case the floor exists for.
        let spacing = QUIET_PERIOD_MS + 1_000;
        let mut now = T0;
        while now < T0 + ROUND_MS {
            if (now - T0) % spacing == 0 {
                c.record_event(now);
            }
            if c.take_due(now) {
                taken.push(now);
            }
            now += 250;
        }

        assert!(
            taken.len() >= 2,
            "the fixture must actually produce passes, or the floor is untested"
        );
        // Without the floor these would land one `spacing` apart. State it, so a later edit that
        // drops the floor fails here rather than silently multiplying the pass rate.
        assert!(
            MIN_EVENT_PASS_INTERVAL_MS > spacing,
            "the fixture must write faster than the floor permits"
        );
        for pair in taken.windows(2) {
            assert!(
                pair[1] - pair[0] >= MIN_EVENT_PASS_INTERVAL_MS,
                "a pass at {} followed one at {}, closer than the {}ms floor",
                pair[1],
                pair[0],
                MIN_EVENT_PASS_INTERVAL_MS
            );
        }
    }

    #[test]
    fn silencing_every_event_source_leaves_the_timer_untouched() {
        // A coalescer that is never fed owes nothing, ever. This is the assertion that keeps events
        // an accelerant: with no source the loop has only the round timer to wait on, which is
        // exactly the behaviour that shipped before this module existed.
        let mut c = WakeCoalescer::new();
        let mut now = T0;
        while now < T0 + ROUND_MS * 3 {
            assert_eq!(c.due_at_ms(), None);
            assert!(!c.take_due(now));
            now += 1_000;
        }

        // And the constant the backstop is built from is unchanged — an events change must never
        // lengthen the timer to compensate.
        assert_eq!(ROUND_MS, 10 * 60 * 1_000);
    }

    /// The watcher itself, against a real directory: a file appearing must signal, promptly.
    ///
    /// Measures the DELAY rather than asserting a signal eventually arrived, and bounds it well
    /// inside the round timer. No `tokio::time::pause()` here on purpose — a paused clock would
    /// auto-advance past the very wall-clock interval being measured.
    #[tokio::test]
    async fn a_file_appearing_signals_well_before_the_round_timer() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let Some(events) = watch_capsule_cache(dir.path()) else {
            // No watcher on this platform is a latency loss, not a failure; the timer still holds.
            return;
        };

        let started = std::time::Instant::now();
        let path = dir.path().join("0f.dig");
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::fs::write(&path, b"capsule").expect("write the capsule");
        });

        let signalled = tokio::time::timeout(std::time::Duration::from_secs(20), events.changed())
            .await
            .is_ok();
        let elapsed = started.elapsed();

        assert!(signalled, "a file appearing under the cache must signal");
        assert!(
            (elapsed.as_millis() as u64) * 10 < ROUND_MS,
            "the watcher signalled after {elapsed:?}, which is not far inside the {ROUND_MS}ms round"
        );
    }
}
