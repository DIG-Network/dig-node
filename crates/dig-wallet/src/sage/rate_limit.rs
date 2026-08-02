//! A minimal, self-contained token-bucket rate limiter (#1957).
//!
//! It bounds the RATE at which an OPEN, externally-dependent read may reach an
//! expensive downstream — specifically the coinset fallback behind
//! [`super::rpc::WalletBackend::balance_for_address`]. `control.wallet.balance`
//! is an unauthenticated loopback read of any public address; the on-chain data
//! is public (no confidentiality risk), but an unbounded open read is a cheap
//! amplification/oracle surface — a caller can sweep many arbitrary addresses and
//! hammer the coinset fallback. This gate caps that abuse WITHOUT touching the
//! cheap, legitimate local-DB fast path.
//!
//! The limiter is GLOBAL (one bucket per backend), not per-source: on the
//! loopback control plane every caller is `127.0.0.1`, so a per-source bound is
//! meaningless — the thing worth bounding is the aggregate fallback call rate.

use std::sync::Mutex;
use std::time::Instant;

/// A classic token bucket: it holds up to `capacity` tokens, refills at
/// `refill_per_sec`, and each admitted call spends one token. A burst up to
/// `capacity` passes immediately; sustained traffic is capped at the refill
/// rate; when empty, [`TokenBucket::try_acquire`] refuses (returns `false`) so
/// the caller can back off rather than block.
///
/// All state lives behind an internal [`Mutex`]; the critical section is a few
/// arithmetic ops with NO `.await`, so it can never deadlock or be held across a
/// yield point.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// A bucket that starts FULL (`capacity` tokens) and refills at
    /// `refill_per_sec`. A `refill_per_sec` of `0.0` makes the bucket a fixed
    /// pool that never replenishes (used by the fast, deterministic unit tests).
    ///
    /// `capacity` is clamped to be non-negative; a capacity of `0.0` refuses
    /// every call (useful to prove a code path bypasses the gate entirely).
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        let capacity = capacity.max(0.0);
        Self {
            capacity,
            refill_per_sec: refill_per_sec.max(0.0),
            state: Mutex::new(BucketState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to spend one token. Returns `true` when the call is admitted (a token
    /// was available and consumed), `false` when the bucket is empty and the
    /// caller should back off.
    pub fn try_acquire(&self) -> bool {
        // A poisoned lock (a prior panic while held) must not wedge the read
        // path; recover the guard and carry on — the arithmetic below fully
        // reinitialises the accounting from `Instant::now()`.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bucket_admits_up_to_capacity_then_refuses() {
        let bucket = TokenBucket::new(3.0, 0.0); // no refill: a fixed pool of 3
        assert!(bucket.try_acquire(), "1st admitted");
        assert!(bucket.try_acquire(), "2nd admitted");
        assert!(bucket.try_acquire(), "3rd admitted");
        assert!(!bucket.try_acquire(), "4th refused — pool exhausted");
        assert!(!bucket.try_acquire(), "stays refused");
    }

    #[test]
    fn a_zero_capacity_bucket_refuses_everything() {
        let bucket = TokenBucket::new(0.0, 0.0);
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn refill_replenishes_tokens_over_time() {
        // 0 capacity start would never admit; use a tiny capacity fully drained,
        // then a high refill rate so a real sleep restores at least one token.
        let bucket = TokenBucket::new(1.0, 1_000.0);
        assert!(bucket.try_acquire(), "the single starting token");
        assert!(!bucket.try_acquire(), "drained");
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(bucket.try_acquire(), "refilled after the elapsed time");
    }

    #[test]
    fn negative_inputs_are_clamped_to_zero() {
        let bucket = TokenBucket::new(-5.0, -1.0);
        assert!(!bucket.try_acquire(), "negative capacity behaves as empty");
    }
}
