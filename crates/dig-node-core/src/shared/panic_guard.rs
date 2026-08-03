//! Per-iteration panic containment for long-lived background loops (#2067, generalizing #2044).
//!
//! Every long-lived `tokio::spawn` background LOOP in the node (the chain-watch + gap-fill loop, the
//! PEX tick loop, the DHT maintenance loop, the tier-0 precache loop) drives a whole subsystem for the
//! process's lifetime. If a single iteration panics, the unwind escapes the spawned task and the task
//! ENDS — the node stays up, but that subsystem dies SILENTLY until the next process restart. The
//! first such bug (#2044, the tier-0 flywheel) proved the failure mode is real and invisible.
//!
//! [`catch_iteration`] is the one shared combinator every such loop wraps its PER-ITERATION body in:
//! it runs the iteration future to completion transparently on the happy path, and turns a panic into
//! a fixed-shape `WARN` + a `None`, so the caller simply proceeds to its next tick. It intercepts ONLY
//! panics (unwinds) — a normal `Result`/outcome flows straight through, so a loop's own error handling
//! is untouched.
//!
//! # `AssertUnwindSafe` — the per-call soundness obligation
//!
//! [`catch_iteration`] asserts the iteration future is unwind-safe, which the compiler cannot verify.
//! It is the CALLER's responsibility to only wrap an iteration whose state carried across the catch
//! boundary holds NO lock/`MutexGuard` across the await: a panic mid-iteration must not leave a
//! half-updated shared structure observable to the next iteration. This holds for a loop that carries
//! only plain values + `Arc` handles (whose own locks are acquired-and-released INSIDE the awaited
//! call, never held across this boundary) — the shape of every loop guarded under #2067.

/// Run one background-loop iteration to completion, CONTAINING a panic so the loop survives it (#2067).
///
/// On the happy path this is fully transparent: it returns `Some(output)` with the iteration's value.
/// When the iteration panics, the unwind is caught, a bounded fixed-shape `WARN` is logged (the loop
/// name + NEVER the panic payload — log-hygiene, #1603), and `None` is returned so the caller skips to
/// its next tick instead of dying.
///
/// `loop_name` is a stable, non-sensitive identifier for the loop (e.g. `"chain_watch"`), used only
/// for the log line.
///
/// # Soundness
///
/// See the module docs: the caller MUST only pass an iteration that holds no lock/guard across the
/// catch boundary, since [`AssertUnwindSafe`](std::panic::AssertUnwindSafe) suppresses the compiler's
/// unwind-safety check.
pub(crate) async fn catch_iteration<F, T>(loop_name: &'static str, iteration: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    use futures::FutureExt;
    match std::panic::AssertUnwindSafe(iteration).catch_unwind().await {
        Ok(output) => Some(output),
        Err(_payload) => {
            // Fixed-shape message only — never the panic payload / untrusted bytes (log-hygiene #1603).
            tracing::warn!(
                loop_name,
                "background loop iteration panicked; continuing to next iteration"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_completed_iteration_passes_its_value_through_unchanged() {
        // The guard is transparent on the happy path: a normal iteration's output flows straight out.
        let out = catch_iteration("test_loop", async { 42u32 }).await;
        assert_eq!(
            out,
            Some(42),
            "a non-panicking iteration returns Some(value)"
        );
    }

    #[tokio::test]
    async fn a_panicking_iteration_is_contained_as_none() {
        // NON-VACUOUS: delete the `catch_unwind` in `catch_iteration` and this test unwinds/aborts
        // instead of returning — proving the combinator, not the harness, contains the panic.
        let out: Option<()> = catch_iteration("test_loop", async {
            panic!("injected iteration panic");
        })
        .await;
        assert_eq!(
            out, None,
            "a panicking iteration must be contained as None, never propagated"
        );
    }

    #[tokio::test]
    async fn a_normal_error_value_is_not_intercepted() {
        // The guard catches ONLY panics — a plain `Err` outcome is passed through untouched, so a
        // loop's own error handling keeps working exactly as before.
        let out: Option<Result<u32, &str>> =
            catch_iteration("test_loop", async { Err("recoverable") }).await;
        assert_eq!(
            out,
            Some(Err("recoverable")),
            "a normal Err flows through the guard as Some(Err(..)), never swallowed"
        );
    }
}
