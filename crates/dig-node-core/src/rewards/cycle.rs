//! SPEC §2.5: the always-on per-distributor prover cycle — and the honesty properties that keep
//! a wedged loop from looking healthy.
//!
//! Three mechanisms, each with its own test below because an always-on loop is trivially easy to
//! keep green while it never actually runs:
//! 1. [`run_cycle_with_deadline`] enforces the `PROVER_CYCLE_DEADLINE_SECONDS` hard deadline —
//!    a cycle that never resolves is ABANDONED, counted as a failure, and reported; it never
//!    silently advances `last_cycle_completed_at`.
//! 2. [`heartbeat_tick`] / [`heartbeat_loop`] refresh `observed_at` at least every
//!    `PROVER_HEARTBEAT_SECONDS`, including while `Idle` — that is what makes "the process is
//!    gone" distinguishable from "the process is between cycles" (§2.5 clause 1).
//! 3. [`is_wedged`] is the READER-side derivation a caller (e.g. the RPC handler) uses to detect a
//!    stalled writer: it compares `observed_at` against the reader's OWN clock, never a flag the
//!    writer set — a wedged writer cannot make this reassuring because it cannot touch it.

use super::spec_constants::{
    PROVER_CYCLE_DEADLINE_SECONDS, PROVER_CYCLE_PERIOD_SECONDS, PROVER_HEARTBEAT_SECONDS,
};
use super::state::{Clock, ProverState, StatusHandle};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::timeout;

/// Run ONE cycle attempt against a hard deadline (SPEC §2.5 clause 2). `cycle_fn` is the actual
/// cycle work (chain reads, admission, challenges, writes) as a future; this wrapper enforces the
/// deadline and updates the status record honestly regardless of outcome — it does not know or
/// care what the work does.
///
/// Returns `true` if the cycle completed within the deadline, `false` if it was abandoned.
pub async fn run_cycle_with_deadline<F, Fut>(
    status: &StatusHandle,
    clock: &dyn Clock,
    cycle_fn: F,
) -> bool
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let started_at = clock.now_unix_seconds();
    status.update(|s| {
        s.prover_state = ProverState::Running;
        s.last_cycle_started_at = Some(started_at);
        s.observed_at = started_at;
    });

    match timeout(
        Duration::from_secs(PROVER_CYCLE_DEADLINE_SECONDS),
        cycle_fn(),
    )
    .await
    {
        Ok(()) => {
            let completed_at = clock.now_unix_seconds();
            status.update(|s| {
                s.prover_state = ProverState::Idle;
                s.last_cycle_completed_at = Some(completed_at);
                s.next_cycle_due_at = Some(completed_at + PROVER_CYCLE_PERIOD_SECONDS);
                s.consecutive_cycle_failures = 0;
                s.observed_at = completed_at;
            });
            true
        }
        Err(_elapsed) => {
            // SPEC §2.5 clause 2: abandon, count as a failure, report — never leave pending, and
            // NEVER advance `last_cycle_completed_at`: this cycle did not complete.
            let now = clock.now_unix_seconds();
            status.update(|s| {
                s.prover_state = ProverState::Idle;
                s.consecutive_cycle_failures += 1;
                s.observed_at = now;
            });
            false
        }
    }
}

/// One heartbeat: refresh `observed_at` from the clock. Exposed separately from
/// [`heartbeat_loop`] so the "refreshed at least every `PROVER_HEARTBEAT_SECONDS`, including
/// while `Idle`" property (SPEC §2.5 clause 1) has a deterministic, non-timing-dependent test.
pub fn heartbeat_tick(status: &StatusHandle, clock: &dyn Clock) {
    status.update(|s| s.observed_at = clock.now_unix_seconds());
}

/// The heartbeat loop: calls [`heartbeat_tick`] every `PROVER_HEARTBEAT_SECONDS` until `stop`
/// carries `true`. Runs independently of whether a cycle is in progress — SPEC §2.5 clause 1 is
/// explicit that this MUST fire "including while `Idle`".
pub async fn heartbeat_loop(
    status: StatusHandle,
    clock: Arc<dyn Clock>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(PROVER_HEARTBEAT_SECONDS)) => {
                heartbeat_tick(&status, clock.as_ref());
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
        }
    }
}

/// The READER-side wedge derivation (SPEC §2.4/§2.5): `observed_at` is the ONLY staleness signal
/// this engine exposes. A reader compares it against ITS OWN clock — never a writer-set flag,
/// which is exactly the honesty property §2.4 forbids violating.
pub fn is_wedged(observed_at: u64, reader_now: u64) -> bool {
    reader_now.saturating_sub(observed_at) > PROVER_HEARTBEAT_SECONDS * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards::state::{idle_status, TestClock};

    fn status_at(now: u64) -> StatusHandle {
        StatusHandle::new(idle_status([0; 32], [0; 32], [0; 32], now))
    }

    /// A cycle that blocks forever is abandoned at the deadline, counted as a failure, and MUST
    /// NOT advance `last_cycle_completed_at`. Under `start_paused`, tokio auto-advances virtual
    /// time to the timeout's own timer once nothing else can make progress — the wedged
    /// `cycle_fn` (a `pending()` future) never does.
    #[tokio::test(start_paused = true)]
    async fn wedged_cycle_is_abandoned_at_the_deadline_and_does_not_fake_completion() {
        let clock = TestClock::new(1_000);
        let status = status_at(1_000);

        let completed =
            run_cycle_with_deadline(&status, &clock, std::future::pending::<()>).await;

        assert!(
            !completed,
            "a cycle that never resolves must be reported as abandoned"
        );
        let snap = status.snapshot();
        assert_eq!(snap.consecutive_cycle_failures, 1);
        assert_eq!(
            snap.last_cycle_completed_at, None,
            "an abandoned cycle must never advance last_cycle_completed_at"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_cycle_that_finishes_in_time_completes_normally() {
        let clock = TestClock::new(1_000);
        let status = status_at(1_000);

        let completed = run_cycle_with_deadline(&status, &clock, || async {}).await;

        assert!(completed);
        let snap = status.snapshot();
        assert_eq!(snap.consecutive_cycle_failures, 0);
        assert_eq!(snap.last_cycle_completed_at, Some(1_000));
        assert_eq!(
            snap.next_cycle_due_at,
            Some(1_000 + PROVER_CYCLE_PERIOD_SECONDS)
        );
    }

    /// SPEC §2.5 clause 1: a heartbeat fires even while the prover is sitting `Idle` between
    /// cycles — this is what distinguishes "gone" from "between cycles" (deterministic: drives
    /// the tick directly rather than the timer).
    #[test]
    fn heartbeat_tick_advances_observed_at_while_idle() {
        let clock = TestClock::new(1_000);
        let status = status_at(1_000);
        assert_eq!(status.snapshot().prover_state, ProverState::Idle);

        clock.advance(PROVER_HEARTBEAT_SECONDS);
        heartbeat_tick(&status, &clock);

        let snap = status.snapshot();
        assert_eq!(snap.observed_at, 1_000 + PROVER_HEARTBEAT_SECONDS);
        assert_eq!(
            snap.prover_state,
            ProverState::Idle,
            "a heartbeat must not touch prover_state"
        );
    }

    /// The wedged-loop reader-side property: `observed_at` stops advancing while a cycle is stuck
    /// (started but never completed, and no heartbeat fired), so a reader comparing it against its
    /// own clock detects the wedge WITHOUT any writer-set flag existing to lie about it.
    #[test]
    fn a_stalled_observed_at_is_detected_by_the_readers_own_clock() {
        let clock = TestClock::new(1_000);
        let status = status_at(1_000);
        status.update(|s| {
            s.prover_state = ProverState::Running;
            s.observed_at = clock.now_unix_seconds();
        });

        // The writer never ticks again (that IS the wedge). The reader's own notion of "now"
        // keeps moving regardless.
        let reader_now = 1_000 + PROVER_HEARTBEAT_SECONDS * 3;
        assert!(is_wedged(status.snapshot().observed_at, reader_now));
    }

    #[test]
    fn a_recently_heartbeat_status_is_not_wedged() {
        let clock = TestClock::new(1_000);
        let status = status_at(1_000);
        heartbeat_tick(&status, &clock);
        let reader_now = 1_000 + PROVER_HEARTBEAT_SECONDS; // within bound, one missed tick at most
        assert!(!is_wedged(status.snapshot().observed_at, reader_now));
    }

    /// The real async heartbeat loop actually fires on its own timer, not only via the
    /// deterministic direct-call test above.
    #[tokio::test(start_paused = true)]
    async fn heartbeat_loop_fires_on_its_own_timer() {
        let clock = Arc::new(TestClock::new(1_000));
        let status = status_at(1_000);
        let (tx, rx) = watch::channel(false);

        let loop_status = status.clone();
        let loop_clock: Arc<dyn Clock> = clock.clone();
        let handle = tokio::spawn(heartbeat_loop(loop_status, loop_clock, rx));

        // Let the loop reach its `sleep` and REGISTER its timer before virtual time moves. Without
        // this, `advance` jumps over a timer that does not exist yet and the loop then sleeps from the
        // far side of the jump — the test would fail while the loop is behaving correctly.
        tokio::task::yield_now().await;

        clock.advance(PROVER_HEARTBEAT_SECONDS);
        tokio::time::advance(Duration::from_secs(PROVER_HEARTBEAT_SECONDS)).await;
        tokio::task::yield_now().await;

        assert!(status.snapshot().observed_at >= 1_000 + PROVER_HEARTBEAT_SECONDS);

        tx.send(true).expect("stop channel open");
        handle.await.expect("heartbeat loop task");
    }
}
