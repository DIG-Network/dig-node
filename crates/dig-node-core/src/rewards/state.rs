//! The per-distributor status record (SPEC §2.3) and its closed state set (§2.3, §2.4).
//!
//! # No health boolean, ever
//!
//! SPEC §2.4: "An implementation MUST NOT expose a `healthy`, `ok`, `up`, or `running` boolean, and
//! MUST NOT expose a pre-computed staleness." A wedged loop cannot report its own wedging — whatever
//! it last wrote stays there, so any field a stalled writer could set to a reassuring value is a
//! lie waiting to happen. The reader derives liveness itself from `last_cycle_completed_at` against
//! `observed_at` and its own clock; nothing here does that derivation for it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// The closed set of prover states (SPEC §2.3). An implementation MUST use exactly this set, MUST
/// NOT add a state without adding it here first, and MUST NOT collapse two of these into one
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProverState {
    Idle,
    Running,
    LocalCopyMissing,
    ChainSourceUnavailable,
    Unfunded,
    FeeBudgetExhausted,
    EntrySetFull,
    Paused,
    Stopped,
}

/// SPEC §2.3 `counters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProverCounters {
    pub mirrors_seen: u64,
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    pub challenges_failed: u64,
    pub entries_added: u64,
    pub entries_removed: u64,
    pub entry_count: u32,
    pub reserve_base_units: u64,
    pub total_paid_out_base_units: u64,
}

/// The SPEC §2.3 status record, verbatim field-for-field. Deliberately carries no boolean and no
/// precomputed staleness (§2.4) — a `#[test]` below asserts the serialized form has none.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardProverStatus {
    pub launcher_id: [u8; 32],
    pub store_id: [u8; 32],
    pub root: [u8; 32],
    pub prover_state: ProverState,
    pub prover_state_since: u64,
    pub last_cycle_started_at: Option<u64>,
    pub last_cycle_completed_at: Option<u64>,
    pub next_cycle_due_at: Option<u64>,
    pub last_entry_write_at: Option<u64>,
    pub consecutive_cycle_failures: u32,
    /// SPEC §6.3 clause 2: decisions withheld by the write-rate bound, not dropped.
    pub pending_entry_writes: u32,
    /// SPEC §2.3: "chain view this record reflects" — refreshed at least every
    /// `PROVER_HEARTBEAT_SECONDS` (§2.5 clause 1). The reader's only staleness signal: compare this
    /// against `last_cycle_completed_at` and the reader's own clock.
    pub observed_at: u64,
    pub counters: ProverCounters,
}

/// A shared, mutable status record a loop writes to and a reader (e.g. the RPC handler) reads from
/// without racing it. Plain `RwLock` over the whole record: writes are infrequent (at most once per
/// heartbeat) and reads must never block a cycle, so a lock is simpler and just as sound as a channel
/// here.
#[derive(Clone)]
pub struct StatusHandle(Arc<RwLock<RewardProverStatus>>);

impl StatusHandle {
    pub fn new(initial: RewardProverStatus) -> Self {
        Self(Arc::new(RwLock::new(initial)))
    }

    pub fn snapshot(&self) -> RewardProverStatus {
        self.0.read().expect("status lock poisoned").clone()
    }

    /// Apply an update. The closure receives `&mut RewardProverStatus` so a caller can update
    /// several fields as one atomic step (e.g. `prover_state` and `prover_state_since` together).
    pub fn update(&self, f: impl FnOnce(&mut RewardProverStatus)) {
        let mut guard = self.0.write().expect("status lock poisoned");
        f(&mut guard);
    }
}

/// A monotonically-advancing clock the loop uses for `observed_at`. A trait rather than
/// `SystemTime::now()` directly so a test can drive it (or refuse to), which is exactly what
/// proves a wedged loop stops advancing it (see `cycle.rs`'s wedged-loop test).
pub trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> u64;
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs()
    }
}

/// A clock a test can advance by hand, and — critically — can also NOT advance, to prove that a
/// stalled loop's `observed_at` truly stops.
#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn new(start: u64) -> Self {
        Self(Arc::new(AtomicU64::new(start)))
    }

    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn new_status(
    launcher_id: [u8; 32],
    store_id: [u8; 32],
    root: [u8; 32],
    now: u64,
) -> RewardProverStatus {
    RewardProverStatus {
        launcher_id,
        store_id,
        root,
        prover_state: ProverState::Idle,
        prover_state_since: now,
        last_cycle_started_at: None,
        last_cycle_completed_at: None,
        next_cycle_due_at: None,
        last_entry_write_at: None,
        consecutive_cycle_failures: 0,
        pending_entry_writes: 0,
        observed_at: now,
        counters: ProverCounters::default(),
    }
}

/// Build a fresh `Idle` status record for a distributor, as SPEC §12.1 clause 3 requires on
/// restart, before the first cycle completes.
pub fn idle_status(
    launcher_id: [u8; 32],
    store_id: [u8; 32],
    root: [u8; 32],
    now: u64,
) -> RewardProverStatus {
    new_status(launcher_id, store_id, root, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The closed set of keys SPEC §2.4 forbids anywhere in the record. This asserts over object
    /// *keys*, never over substrings of the serialized string: `ProverState::Running` legitimately
    /// serializes the *value* `"running"`, so a substring test would fail on honest input while
    /// still passing a smuggled `isRunning` **key**. Keep it key-based; a "simplification" back to
    /// a substring check both breaks honest serialization and stops catching the real defect.
    const FORBIDDEN_HEALTH_KEYS: &[&str] = &[
        "healthy",
        "ok",
        "up",
        "running",
        "isRunning",
        "stale",
        "isStale",
        "staleness",
        "secondsSinceLastRun",
        "lastRunSecondsAgo",
        "uptime",
        "alive",
        "live",
    ];

    /// Walk a `serde_json::Value` depth-first, asserting no object at ANY depth carries a forbidden
    /// key. A top-level-only check would miss a forbidden key smuggled into a nested struct (e.g. a
    /// future field added inside `counters`) — this recurses through objects and arrays so a
    /// smuggled key at any depth still fails the test.
    fn assert_no_forbidden_health_keys(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for forbidden in FORBIDDEN_HEALTH_KEYS {
                    assert!(
                        !map.contains_key(*forbidden),
                        "status record must not carry a {forbidden:?} key at any depth (SPEC §2.4)"
                    );
                }
                for nested in map.values() {
                    assert_no_forbidden_health_keys(nested);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_forbidden_health_keys(item);
                }
            }
            _ => {}
        }
    }

    /// SPEC §2.4: no `healthy`/`ok`/`up`/`running`/... key, and no precomputed staleness field,
    /// anywhere in the serialized record — recursively, not just at the top level.
    #[test]
    fn serialized_status_has_no_health_or_staleness_key() {
        let status = idle_status([1; 32], [2; 32], [3; 32], 1000);
        let json = serde_json::to_value(&status).unwrap();
        assert_no_forbidden_health_keys(&json);
    }

    #[test]
    fn status_handle_reads_do_not_mutate() {
        let status = idle_status([0; 32], [0; 32], [0; 32], 5);
        let handle = StatusHandle::new(status.clone());
        assert_eq!(handle.snapshot(), status);
        handle.update(|s| s.observed_at = 6);
        assert_eq!(handle.snapshot().observed_at, 6);
    }

    #[test]
    fn test_clock_that_is_never_advanced_never_advances() {
        let clock = TestClock::new(42);
        assert_eq!(clock.now_unix_seconds(), 42);
        assert_eq!(clock.now_unix_seconds(), 42);
    }
}
