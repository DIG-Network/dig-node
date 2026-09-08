//! SPEC §3: possession-challenge window selection, the fail-closed pass/fail decision, and the
//! §3.6 strike accounting the decision feeds.
//!
//! **Scope cut, deliberate**: this module holds the SOUNDNESS logic — which windows to pick, and
//! whether a response is honest — behind the narrow [`ChallengeTransport`] seam, tested against an
//! in-memory fake. The concrete `dig.fetchRange` transport adapter (`skip_layout: true,
//! capsule: false`, the §3.7 deadlines) is a FOLLOW-UP, not built here. Soundness in, transport
//! out.

use super::port::Bytes32;
use super::spec_constants::{CHALLENGE_NO_REPEAT_CYCLES, CHALLENGE_STRIKES_TO_EVICT, CHALLENGE_WINDOW_BYTES};
use async_trait::async_trait;
use std::collections::HashMap;

/// One resource this distributor's peer set is challenged over (SPEC §3.1): an id and its total
/// byte length, used only for the length-proportional pick below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    pub id: Bytes32,
    pub length: u64,
}

/// A concrete window request: which resource, what byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowPlan {
    pub resource_index: usize,
    pub offset: u64,
    pub length: u64,
}

/// A CSPRNG-drawn `u64` in `[0, bound)`. SPEC §3.2 clause 4: MUST NOT be derived from a counter, a
/// timestamp, a peer id, a store id, a root, a cycle index, or any hash of those — `getrandom`
/// draws from the OS CSPRNG and touches none of those inputs.
fn csprng_u64_below(bound: u64) -> u64 {
    if bound == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    u64::from_le_bytes(buf) % bound
}

/// Remembers, per `(peer_id, launcher_id)`, the `(cycle_index, resource_id, offset)` windows
/// issued in the last [`CHALLENGE_NO_REPEAT_CYCLES`] cycles (SPEC §3.2 clause 5).
#[derive(Default)]
pub struct NoRepeatMemory {
    recent: HashMap<(Bytes32, Bytes32), Vec<(u32, Bytes32, u64)>>,
}

impl NoRepeatMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_repeat(&self, peer_id: Bytes32, launcher_id: Bytes32, resource_id: Bytes32, offset: u64, cycle_index: u32) -> bool {
        self.recent
            .get(&(peer_id, launcher_id))
            .is_some_and(|windows| {
                windows.iter().any(|(cyc, rid, off)| {
                    *rid == resource_id && *off == offset && cycle_index.saturating_sub(*cyc) < CHALLENGE_NO_REPEAT_CYCLES
                })
            })
    }

    pub fn record(&mut self, peer_id: Bytes32, launcher_id: Bytes32, resource_id: Bytes32, offset: u64, cycle_index: u32) {
        self.recent
            .entry((peer_id, launcher_id))
            .or_default()
            .push((cycle_index, resource_id, offset));
    }
}

/// SPEC §3.2: pick ONE window — resource choice length-proportional (uniform-over-resources is
/// exploitable: a peer can discard the large resources, most of the bytes, and still pass),
/// offset uniform in `[0, total_length - length]`, length clamped down for a smaller resource,
/// and skipping any pick the no-repeat memory has already issued this peer within the window.
/// Returns `None` only when every resource is empty or repeats exhaust the retry budget.
pub fn select_window(
    resources: &[Resource],
    peer_id: Bytes32,
    launcher_id: Bytes32,
    cycle_index: u32,
    memory: &mut NoRepeatMemory,
) -> Option<WindowPlan> {
    let total_length: u64 = resources.iter().map(|r| r.length).sum();
    if resources.is_empty() || total_length == 0 {
        return None;
    }

    for _attempt in 0..16 {
        let pick = csprng_u64_below(total_length);
        let mut cumulative = 0u64;
        let resource_index = resources
            .iter()
            .position(|r| {
                cumulative += r.length;
                pick < cumulative
            })
            .unwrap_or(resources.len() - 1);
        let resource = &resources[resource_index];
        let length = CHALLENGE_WINDOW_BYTES.min(resource.length);
        let max_offset = resource.length - length;
        let offset = csprng_u64_below(max_offset + 1);

        if !memory.is_repeat(peer_id, launcher_id, resource.id, offset, cycle_index) {
            memory.record(peer_id, launcher_id, resource.id, offset, cycle_index);
            return Some(WindowPlan {
                resource_index,
                offset,
                length,
            });
        }
    }
    None
}

/// Why one challenge window failed (SPEC §3.5 — fail-closed on every one of these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeFailure {
    Transport,
    PeerIdMismatch,
    Timeout,
    RpcError(String),
    FrameLengthMismatch,
    OffsetMismatch,
    LayoutMismatch,
    DecodeError,
}

/// One raw window response, before comparison against the locally-known bytes.
#[derive(Debug, Clone)]
pub struct ChallengeResponse {
    pub bytes: Vec<u8>,
}

/// The narrow transport seam this module drives — soundness only, no `dig.fetchRange` wiring here
/// (see module docs).
#[async_trait]
pub trait ChallengeTransport: Send + Sync {
    async fn fetch_window(
        &self,
        peer_id: Bytes32,
        resource_id: Bytes32,
        offset: u64,
        length: u64,
    ) -> Result<ChallengeResponse, ChallengeFailure>;
}

/// SPEC §3.5: a single window passes only when the transport succeeds AND the returned bytes
/// match the locally-known bytes exactly. Every failure — transport, protocol, or a byte
/// difference — collapses to `false`; a valid-but-wrong-bytes response fails exactly as loudly as
/// no response (SPEC §3.4: a relayable inclusion proof MUST NOT be accepted as possession).
pub async fn run_window(
    transport: &dyn ChallengeTransport,
    peer_id: Bytes32,
    resource_id: Bytes32,
    offset: u64,
    length: u64,
    expected_bytes: &[u8],
) -> bool {
    match transport.fetch_window(peer_id, resource_id, offset, length).await {
        Ok(response) => response.bytes == expected_bytes,
        Err(_) => false,
    }
}

/// SPEC §3.5: a cycle passes only if ALL windows match — no partial credit.
pub async fn run_cycle(transport: &dyn ChallengeTransport, peer_id: Bytes32, windows: &[(Bytes32, u64, u64, Vec<u8>)]) -> bool {
    for (resource_id, offset, length, expected) in windows {
        if !run_window(transport, peer_id, *resource_id, *offset, *length, expected).await {
            return false;
        }
    }
    true
}

/// SPEC §3.6 per-`(peer_id, launcher_id)` strike accounting. A pass resets to zero; three
/// CONSECUTIVE genuine peer-caused failures schedule a `RemoveEntry`. Strikes reset entirely on
/// prover restart (§12.1).
#[derive(Default)]
pub struct StrikeTracker {
    consecutive_failures: HashMap<(Bytes32, Bytes32), u32>,
}

impl StrikeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a genuinely peer-caused challenge-cycle outcome. Returns `true` when this outcome
    /// crosses [`CHALLENGE_STRIKES_TO_EVICT`] and a `RemoveEntry` MUST now be scheduled.
    ///
    /// MUST NEVER be called for a cycle abandoned through the prover's own fault — see
    /// [`Self::record_prover_fault`], which exists precisely so that path cannot reach this one.
    pub fn record_peer_outcome(&mut self, peer_id: Bytes32, launcher_id: Bytes32, passed: bool) -> bool {
        let key = (peer_id, launcher_id);
        if passed {
            self.consecutive_failures.insert(key, 0);
            false
        } else {
            let count = self.consecutive_failures.entry(key).or_insert(0);
            *count += 1;
            *count >= CHALLENGE_STRIKES_TO_EVICT
        }
    }

    /// SPEC §3.6 clause 4: `LocalCopyMissing`, `ChainSourceUnavailable`, the prover's own cycle
    /// deadline, or a reorg — none of these is the peer's fault, so none of them may touch a
    /// strike counter. This function is intentionally a no-op; it exists so a caller reaches for a
    /// NAMED prover-fault path instead of `record_peer_outcome`, which is the mistake that would
    /// strike every peer for one broken node.
    pub fn record_prover_fault(&self, _peer_id: Bytes32, _launcher_id: Bytes32) {}

    pub fn consecutive_failures(&self, peer_id: Bytes32, launcher_id: Bytes32) -> u32 {
        self.consecutive_failures
            .get(&(peer_id, launcher_id))
            .copied()
            .unwrap_or(0)
    }

    /// SPEC §12.1 clause 3: strikes reset to zero on prover restart.
    pub fn reset_all(&mut self) {
        self.consecutive_failures.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Bytes32 = [1; 32];
    const LAUNCHER: Bytes32 = [2; 32];
    const RESOURCE: Bytes32 = [3; 32];

    struct FakeTransport {
        bytes: Vec<u8>,
        fail: Option<ChallengeFailure>,
    }

    #[async_trait]
    impl ChallengeTransport for FakeTransport {
        async fn fetch_window(
            &self,
            _peer_id: Bytes32,
            _resource_id: Bytes32,
            _offset: u64,
            _length: u64,
        ) -> Result<ChallengeResponse, ChallengeFailure> {
            if let Some(f) = &self.fail {
                return Err(f.clone());
            }
            Ok(ChallengeResponse {
                bytes: self.bytes.clone(),
            })
        }
    }

    #[tokio::test]
    async fn matching_bytes_pass() {
        let t = FakeTransport {
            bytes: vec![1, 2, 3],
            fail: None,
        };
        assert!(run_window(&t, PEER, RESOURCE, 0, 3, &[1, 2, 3]).await);
    }

    #[tokio::test]
    async fn wrong_bytes_fail_as_loudly_as_no_response() {
        let t = FakeTransport {
            bytes: vec![9, 9, 9],
            fail: None,
        };
        assert!(!run_window(&t, PEER, RESOURCE, 0, 3, &[1, 2, 3]).await);
    }

    #[tokio::test]
    async fn transport_error_fails_closed() {
        let t = FakeTransport {
            bytes: vec![],
            fail: Some(ChallengeFailure::Timeout),
        };
        assert!(!run_window(&t, PEER, RESOURCE, 0, 3, &[1, 2, 3]).await);
    }

    /// SPEC §3.5: no partial credit — one bad window fails the whole cycle.
    #[tokio::test]
    async fn one_mismatched_window_fails_the_whole_cycle() {
        let t = FakeTransport {
            bytes: vec![1, 2, 3],
            fail: None,
        };
        let windows = vec![
            (RESOURCE, 0, 3, vec![1, 2, 3]),
            (RESOURCE, 3, 3, vec![9, 9, 9]), // this one will mismatch: transport always returns [1,2,3]
        ];
        assert!(!run_cycle(&t, PEER, &windows).await);
    }

    #[test]
    fn window_offset_and_length_stay_within_the_resource() {
        let resources = [Resource {
            id: RESOURCE,
            length: 10,
        }];
        let mut memory = NoRepeatMemory::new();
        let plan = select_window(&resources, PEER, LAUNCHER, 0, &mut memory).expect("a window");
        assert_eq!(plan.resource_index, 0);
        assert!(plan.length <= 10);
        assert!(plan.offset + plan.length <= 10);
    }

    #[test]
    fn no_repeat_memory_blocks_the_same_window_within_the_bound() {
        let mut memory = NoRepeatMemory::new();
        assert!(!memory.is_repeat(PEER, LAUNCHER, RESOURCE, 5, 0));
        memory.record(PEER, LAUNCHER, RESOURCE, 5, 0);
        assert!(memory.is_repeat(PEER, LAUNCHER, RESOURCE, 5, CHALLENGE_NO_REPEAT_CYCLES - 1));
        assert!(!memory.is_repeat(PEER, LAUNCHER, RESOURCE, 5, CHALLENGE_NO_REPEAT_CYCLES));
    }

    #[test]
    fn three_consecutive_peer_failures_schedule_a_removal() {
        let mut strikes = StrikeTracker::new();
        assert!(!strikes.record_peer_outcome(PEER, LAUNCHER, false));
        assert!(!strikes.record_peer_outcome(PEER, LAUNCHER, false));
        assert!(strikes.record_peer_outcome(PEER, LAUNCHER, false));
        assert_eq!(strikes.consecutive_failures(PEER, LAUNCHER), 3);
    }

    #[test]
    fn a_pass_resets_the_strike_count() {
        let mut strikes = StrikeTracker::new();
        strikes.record_peer_outcome(PEER, LAUNCHER, false);
        strikes.record_peer_outcome(PEER, LAUNCHER, false);
        strikes.record_peer_outcome(PEER, LAUNCHER, true);
        assert_eq!(strikes.consecutive_failures(PEER, LAUNCHER), 0);
    }

    /// The prover-fault case (D-equivalent to §3.6 clause 4): a chain outage MUST NOT strike any
    /// peer. Simulates the fault path failing to strike every peer in a set of several.
    #[tokio::test]
    async fn prover_fault_never_increments_any_peer_strike() {
        let mut strikes = StrikeTracker::new();
        let peers: [Bytes32; 3] = [[10; 32], [11; 32], [12; 32]];
        for peer in peers {
            strikes.record_prover_fault(peer, LAUNCHER);
        }
        for peer in peers {
            assert_eq!(strikes.consecutive_failures(peer, LAUNCHER), 0);
        }
    }
}
