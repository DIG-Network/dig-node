//! Stopping the service, reliably (dig_ecosystem#2880).
//!
//! # The failure this exists to prevent
//!
//! A host was left with `sc.exe ControlService FAILED 1061`
//! (`ERROR_SERVICE_CANNOT_ACCEPT_CTRL`) on every update attempt, while the SAME node answered
//! `dign wallet sync-status` normally over the loopback port and reported a climbing Chia peak.
//! The process was alive and serving; it just could not be stopped. The machine ended up with the
//! on-disk binary at one version and the running process at another, and `dig-updater run` looped
//! forever reporting `Deferred` and exiting `0` — a component stuck, behind a clean pass.
//!
//! **A service the OS cannot stop, that is nonetheless serving requests, is one the user cannot
//! turn off.** That is worse than a crash: a crash is visible and recoverable.
//!
//! # Which of the two usual causes it was: NEITHER
//!
//! `1061` normally means the service never reached `Running`, or never reported an
//! accepted-controls mask. Measured against this code, neither holds: `win_service.rs` reports
//! `Running` with `ServiceControlAccept::STOP` before it serves, and the SCM caches that.
//!
//! The defect is one layer in, in how the accepted control was **acted on**. The stop signal was
//! bridged from the control handler into the async serve future with
//! `spawn_blocking(move || shutdown_rx.recv())` — a task on tokio's **blocking pool**. That pool is
//! bounded and shared with every blocking call the node makes, including the wallet replica's
//! synchronous database work. On the wedged host the replica was frozen with `watched_addresses:
//! null` and a static `peak_height`, which is the shape of a saturated blocking pool. With no
//! thread free the receiving task **never ran**, so the accepted stop was recorded and then never
//! observed: the service kept reporting `Running`, kept serving, and never stopped. The correlation
//! with the frozen replica that the ticket asks about is therefore not a coincidence — it is the
//! mechanism, and one blocked resource produced both symptoms.
//!
//! This module removes the dependency. The stop path uses [`tokio::sync::watch`], delivered by the
//! async runtime itself with no blocking thread, and a stop that cannot complete gracefully is
//! bounded by a deadline instead of waited on forever.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// How long a graceful shutdown is given before the service reports `Stopped` regardless.
///
/// Windows' own patience is the reference point: the SCM's default stop timeout is 30s, after which
/// it reports the service as hung anyway. Finishing inside that window means the SCM always learns
/// the truthful outcome from us rather than inferring one.
pub const GRACEFUL_STOP_DEADLINE: Duration = Duration::from_secs(20);

/// A stop request that can be raised from a service-control handler and awaited anywhere.
///
/// Cloneable and idempotent, because the SCM may deliver `Stop` more than once and a control
/// handler is a `Fn`, not an `FnOnce` — a one-shot channel cannot be sent from one.
///
/// **The important property is what raising a stop does NOT touch:** no lock a request handler can
/// hold, and no thread the blocking pool can starve. Awaiting one is driven by the async runtime
/// directly. Both halves must stay that way, or the wedge described in the module docs returns.
#[derive(Clone)]
pub struct StopSignal {
    tx: Arc<watch::Sender<bool>>,
}

impl StopSignal {
    /// Create a stop signal that has not yet been requested.
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        StopSignal { tx: Arc::new(tx) }
    }

    /// Request a stop.
    ///
    /// Never blocks and never fails, including when no waiter exists — a control handler must be
    /// able to answer the SCM promptly whatever the rest of the process is doing, so there is
    /// deliberately no error for it to handle and nothing for it to wait on.
    pub fn request(&self) {
        let _ = self.tx.send(true);
    }

    /// Whether a stop has already been requested.
    pub fn is_requested(&self) -> bool {
        *self.tx.borrow()
    }

    /// A waiter for this signal. Any number may exist — the serve body and the shutdown supervisor
    /// each hold one.
    pub fn waiter(&self) -> StopWaiter {
        StopWaiter {
            rx: self.tx.subscribe(),
        }
    }
}

impl Default for StopSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// A waiter for a [`StopSignal`].
pub struct StopWaiter {
    rx: watch::Receiver<bool>,
}

impl StopWaiter {
    /// Resolve once a stop has been requested — immediately if it already has been.
    ///
    /// The already-requested check is not an optimisation. `watch::Receiver::changed` reports only
    /// changes made AFTER it is called, so a bare `changed()` would wait forever past a stop that
    /// arrived during start-up — which is exactly when an update tool sends one.
    pub async fn wait(mut self) {
        if *self.rx.borrow() {
            return;
        }
        // An error means every sender was dropped, which no live service does. Treating it as a stop
        // makes a programming error degrade into a shutdown rather than into a wedge.
        let _ = self.rx.changed().await;
    }
}

/// How shutdown ended.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StopOutcome {
    /// The serve future finished on its own.
    Graceful,
    /// The serve future had not finished when the deadline elapsed, so shutdown was declared anyway.
    ///
    /// This branch is what keeps the service stoppable. Without it a serve future blocked on a
    /// wedged internal leaves the service `Running` forever and the user cannot turn it off.
    Forced,
}

/// Run `serve` to completion, or declare shutdown `deadline` after a stop is requested.
///
/// Returns the serve result — `None` on a forced stop, where there is no result — alongside how
/// shutdown ended, so the caller can report a truthful service status.
///
/// `serve` is expected to observe the same stop signal and wind itself down; the deadline is the
/// backstop for when it cannot.
pub async fn run_until_stopped<F, T>(
    serve: F,
    stop: StopWaiter,
    deadline: Duration,
) -> (Option<T>, StopOutcome)
where
    F: std::future::Future<Output = T>,
{
    let mut serve = std::pin::pin!(serve);

    // Race the body against the stop request. A body that finishes first needs no deadline; only a
    // stop the body has not yet acted on does.
    tokio::select! {
        result = &mut serve => return (Some(result), StopOutcome::Graceful),
        () = stop.wait() => {}
    }

    // A stop was requested and the body is still running. Give it the deadline, then declare
    // shutdown regardless — a body that will not wind down must not hold the service `Running`.
    match tokio::time::timeout(deadline, serve).await {
        Ok(result) => (Some(result), StopOutcome::Graceful),
        Err(_) => (None, StopOutcome::Forced),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// **Proves the fix (dig_ecosystem#2880):** a stop is observed even when tokio's blocking pool
    /// is completely saturated.
    ///
    /// # Why the fixture is built this way
    ///
    /// This is the assertion that fails against the pre-fix implementation, and it fails for the
    /// right reason. The pre-fix bridge was `spawn_blocking(move || shutdown_rx.recv())`, so with
    /// every blocking thread occupied the receiving task is queued and never polled and the stop is
    /// never seen. Nothing about the signal's *semantics* changed in this fix — only which executor
    /// delivers it — so a fixture that did NOT starve the blocking pool would pass against both
    /// implementations and prove nothing at all.
    ///
    /// The runtime is therefore built with `max_blocking_threads(1)` and that one thread is held by
    /// a task that parks until released. That is the smallest unambiguous saturation: against the
    /// default pool of 512 the test would need 512 parked tasks, and any miscount would make it
    /// pass for the wrong reason.
    ///
    /// The occupying task is released at the end rather than leaked, because a leaked blocking
    /// thread would make a LATER test in the same binary flaky — a false red bought with a true
    /// green.
    #[test]
    fn a_stop_is_observed_while_the_blocking_pool_is_saturated() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("build runtime");

        let release = Arc::new(AtomicBool::new(false));
        let observed = rt.block_on(async {
            let hog_release = release.clone();
            // Occupy the ONLY blocking thread. Until `release` flips, nothing else runs there.
            tokio::task::spawn_blocking(move || {
                while !hog_release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            // Let the hog actually take the thread; otherwise the pool might still be free when the
            // stop is awaited and the test would pass vacuously.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let signal = StopSignal::new();
            let waiter = signal.waiter();
            signal.request();

            // Generous relative to the 5ms hog loop: this must resolve because the signal needs no
            // blocking thread, not because it got lucky on timing.
            tokio::time::timeout(Duration::from_secs(2), waiter.wait())
                .await
                .is_ok()
        });
        release.store(true, Ordering::SeqCst);

        assert!(
            observed,
            "the stop signal must be delivered by the async runtime, never by a task queued on the \
             blocking pool — a saturated pool is precisely the state the wedged host was in, and a \
             stop that cannot be observed there is a service the user cannot turn off"
        );
    }

    /// **Proves:** a stop raised BEFORE anyone waits is still seen.
    ///
    /// A bare `watch::Receiver::changed()` is the nearest wrong implementation: it reports only
    /// changes made after the call, so it fails exactly for a stop that arrives during start-up,
    /// which is when an update tool sends one. Ordering the request before the wait is what
    /// distinguishes the two — a test that requested after waiting would pass against both.
    #[test]
    fn a_stop_requested_before_the_wait_is_not_missed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        let seen = rt.block_on(async {
            let signal = StopSignal::new();
            let waiter = signal.waiter();
            signal.request();
            assert!(
                signal.is_requested(),
                "the request must be readable at once"
            );
            tokio::time::timeout(Duration::from_secs(1), waiter.wait())
                .await
                .is_ok()
        });

        assert!(
            seen,
            "a stop requested before the waiter runs must resolve immediately — otherwise a service \
             stopped during start-up hangs, which is the same wedge in a different disguise"
        );
    }

    /// **Proves:** every waiter sees the stop, not just the first.
    ///
    /// The serve body and the shutdown supervisor each hold one, so a signal that woke only one of
    /// them would leave the body running while the supervisor declared shutdown — a forced stop
    /// reported for a body that was never actually told to stop.
    #[test]
    fn every_waiter_sees_the_same_stop() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        let (first, second) = rt.block_on(async {
            let signal = StopSignal::new();
            let a = signal.waiter();
            let b = signal.waiter();
            signal.request();
            (
                tokio::time::timeout(Duration::from_secs(1), a.wait())
                    .await
                    .is_ok(),
                tokio::time::timeout(Duration::from_secs(1), b.wait())
                    .await
                    .is_ok(),
            )
        });

        assert!(first && second, "both waiters must observe the stop");
    }

    /// **Proves:** a serve body that never winds down still yields a stop verdict, bounded.
    ///
    /// The assertion is on the OUTCOME being `Forced`, not merely on the call returning: a call
    /// that returned `Graceful` here would be reporting a clean shutdown that did not happen — the
    /// same class of lie as the updater's `Deferred` behind exit code 0.
    #[test]
    fn a_serve_body_that_never_finishes_is_stopped_by_the_deadline() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        let (result, outcome) = rt.block_on(async {
            let signal = StopSignal::new();
            let waiter = signal.waiter();
            signal.request();
            let never = std::future::pending::<()>();
            run_until_stopped(never, waiter, Duration::from_millis(100)).await
        });

        assert_eq!(
            outcome,
            StopOutcome::Forced,
            "a body that ignores the stop must be reported as FORCED, never as a graceful stop"
        );
        assert!(
            result.is_none(),
            "a forced stop has no serve result to report"
        );
    }

    /// **The truthful control:** a body that DOES wind down is reported as graceful.
    ///
    /// Without this, `run_until_stopped` could return `Forced` unconditionally and the test above
    /// would still pass.
    #[test]
    fn a_serve_body_that_winds_down_is_reported_as_graceful() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build runtime");

        let (result, outcome) = rt.block_on(async {
            let signal = StopSignal::new();
            let waiter = signal.waiter();
            signal.request();
            run_until_stopped(async { 7u8 }, waiter, Duration::from_secs(5)).await
        });

        assert_eq!(outcome, StopOutcome::Graceful);
        assert_eq!(
            result,
            Some(7),
            "a graceful stop must carry the body's own result through"
        );
    }
}
