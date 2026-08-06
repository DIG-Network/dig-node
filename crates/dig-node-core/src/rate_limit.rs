//! Per-requestor rate limiting for the miss → DHT-lookup path (dig_ecosystem#2007).
//!
//! When a content RPC (`dig.getContent` / `dig.fetchRange` / the peer range stream) asks for content
//! this node does NOT hold, the miss handler ([`crate::Node::miss_outcome`]) runs a DHT
//! `find_providers` lookup (and, on `proxy`, a full multi-source fetch). The `dig.getAvailability`
//! batch's not-held → holder-hint enrichment ([`crate::Node::availability_answer`]) runs the SAME
//! `find_providers` lookup per not-held item, admitting through the SAME per-requestor budget (via
//! [`crate::download::NodeContent::allow_miss_lookup`], ONE token per not-held item — a batch is the
//! largest amplification vector, up to `MAX_AVAILABILITY_ITEMS` lookups per request). All are
//! network-amplifying: a caller who cannot name any concrete content it wants can still spend this
//! node's DHT bandwidth by naming arbitrary `(store, root, retrieval_key)` triples. This gate bounds
//! that spend PER REQUESTOR, so one abusive caller cannot drive the aggregate lookup rate while a
//! well-behaved caller is untouched.
//!
//! # The primitive
//!
//! [`TokenBucket`] MIRRORS the sanctioned #1957 pattern (`dig-wallet`'s
//! `sage::rate_limit::TokenBucket`) byte-for-byte — the same classic bucket, the same
//! poison-recovery, the same `try_acquire` contract. It is mirrored rather than shared because
//! `dig-node-core` does not (and should not) depend on `dig-wallet`, and the primitive is a
//! dependency-free handful of `std`-only arithmetic; consolidating both copies into a lower
//! shared crate is a tracked follow-up (dig_ecosystem#2007 Realizations). Keeping it identical
//! is the contract until then.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Who is asking for a read, for the purpose of the per-requestor miss-lookup bucket. The KEY the
/// bucket map is keyed by; NEVER a value a remote caller can spoof — it is derived at each
/// transport's own call site from the mTLS-verified `peer_id` or the accepted connection's IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestorId {
    /// This node's OWN operator (loopback HTTP / in-process FFI / the control surface). One shared
    /// bucket — the operator is trusted, and a single high-capacity bucket is enough to bound a
    /// runaway local client without ever throttling ordinary operator reads.
    Local,
    /// A remote peer over the mTLS peer wire, keyed by its verified `peer_id` (64-hex,
    /// `SHA-256(TLS SPKI DER)`). This is the amplification vector the bucket exists to bound.
    Peer(String),
    /// An anonymous / gateway HTTP caller (no node identity), keyed by the accepted connection's
    /// IP. A shared public gateway (rpc.dig.net) collapses its users onto one bucket — an accepted
    /// coarseness, the same disclosure a shared egress IP already implies.
    Anonymous(String),
}

impl RequestorId {
    /// Derive the coarse requestor from the transport [`ReadOrigin`](crate::download::ReadOrigin)
    /// ALONE, for callers that carry no finer identity: a `Local` transport is the operator; a
    /// `Peer` transport with no threaded identity collapses onto ONE shared peer bucket
    /// (`Peer("")`). The real peer server threads the verified `peer_id` instead
    /// (`RequestorId::Peer(conn_key)`), so this fallback only applies where no identity exists.
    pub fn from_origin(origin: crate::download::ReadOrigin) -> Self {
        match origin {
            crate::download::ReadOrigin::Local => RequestorId::Local,
            crate::download::ReadOrigin::Peer => RequestorId::Peer(String::new()),
        }
    }

    /// Whether this is the node's OWN trusted operator ([`RequestorId::Local`]). The operator is
    /// exempt from the tighter PROXY-fetch allowance (dig_ecosystem#2189): that bound targets the
    /// REMOTE amplification vector, mirroring the lookup limiter's "the operator is trusted" rationale.
    pub fn is_local(&self) -> bool {
        matches!(self, RequestorId::Local)
    }

    /// The stable map key for this requestor. Distinct requestors MUST map to distinct keys (that is
    /// the whole point — one abuser's exhausted bucket must never refuse a different requestor), and
    /// the same requestor MUST map to the same key across calls.
    fn key(&self) -> String {
        match self {
            RequestorId::Local => "local".to_string(),
            RequestorId::Peer(id) => format!("peer:{id}"),
            RequestorId::Anonymous(ip) => format!("anon:{ip}"),
        }
    }
}

/// A classic token bucket (MIRROR of `dig-wallet`'s #1957 `TokenBucket`): it holds up to `capacity`
/// tokens, refills at `refill_per_sec`, and each admitted call spends one token. A burst up to
/// `capacity` passes immediately; sustained traffic is capped at the refill rate; when empty,
/// [`TokenBucket::try_acquire`] refuses (returns `false`) so the caller backs off rather than blocks.
///
/// All state lives behind an internal [`Mutex`]; the critical section is a few arithmetic ops with
/// NO `.await`, so it can never deadlock or be held across a yield point.
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
    /// A bucket that starts FULL (`capacity` tokens) and refills at `refill_per_sec`. A
    /// `refill_per_sec` of `0.0` makes the bucket a fixed pool that never replenishes (used by the
    /// fast, deterministic unit tests). `capacity`/`refill_per_sec` are clamped non-negative; a
    /// capacity of `0.0` refuses every call.
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

    /// Try to spend one token. Returns `true` when admitted (a token was available and consumed),
    /// `false` when the bucket is empty and the caller should back off.
    pub fn try_acquire(&self) -> bool {
        // A poisoned lock (a prior panic while held) must not wedge the read path; recover the guard
        // and carry on — the arithmetic below fully reinitialises the accounting from `Instant::now()`.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::refill(&mut state, self.capacity, self.refill_per_sec);
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether the bucket is currently at capacity after refilling (an IDLE requestor). A full bucket
    /// admits identically whether kept or dropped-and-recreated, so a full bucket is the ONLY entry
    /// [`MissRateLimiter`] may evict without weakening the bound.
    fn is_full(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::refill(&mut state, self.capacity, self.refill_per_sec);
        state.tokens >= self.capacity
    }

    fn refill(state: &mut BucketState, capacity: f64, refill_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * refill_per_sec).min(capacity);
        state.last_refill = now;
    }
}

/// The default per-requestor burst: how many miss lookups a single requestor may fire back-to-back
/// before the refill rate governs. A legitimate reader following a few redirect hops, or loading a
/// page of several resources whose capsule this node does not yet hold, issues a small handful of
/// misses; this absorbs that without ever touching an honest read.
///
/// It is the SIBLING of the #1985 ping anti-amplification bound (`MAX_PINGS_PER_WINDOW = 6` / 60 s):
/// a miss lookup is cheaper and more naturally frequent than an identity ping, so its burst is larger
/// and its window shorter, but the shape — a per-source token bucket in front of a network-amplifying
/// operation — is the same.
pub const DEFAULT_MISS_LOOKUP_BURST: f64 = 16.0;

/// The default sustained miss-lookup rate (tokens per second) a single requestor is refilled at once
/// its burst is spent.
pub const DEFAULT_MISS_LOOKUP_REFILL_PER_SEC: f64 = 4.0;

/// The default per-requestor burst for the PROXY fetch-through leg (dig_ecosystem#2189). A
/// `proxy:true` miss does NOT run a cheap DHT lookup — it pulls a FULL multi-source capsule from the
/// holders and serves the bytes directly (large egress + merkle crypto), an order of magnitude
/// costlier than the [`DEFAULT_MISS_LOOKUP_BURST`] lookup this node's miss budget is sized for. Drawing
/// expensive proxy fetches from that lookup budget lets a caller convert cheap-lookup allowance into
/// egress; so the proxy leg gets its OWN, tighter per-requestor allowance — a QUARTER the lookup burst.
/// A legitimate NAT-blocked reader proxying a handful of resources is absorbed; sustained proxy spam is
/// capped independently of, and far below, the lookup rate.
pub const DEFAULT_PROXY_FETCH_BURST: f64 = 4.0;

/// The default sustained PROXY fetch-through rate (tokens per second) a single requestor is refilled at
/// once its proxy burst is spent — a QUARTER of [`DEFAULT_MISS_LOOKUP_REFILL_PER_SEC`], i.e. ~one full
/// capsule fetch per second per requestor after the burst, calibrated against the per-fetch egress + CPU
/// cost being ~an order of magnitude that of a cheap lookup.
pub const DEFAULT_PROXY_FETCH_REFILL_PER_SEC: f64 = 1.0;

/// The most distinct requestors tracked at once. Bounds the bucket map so a caller cycling identities
/// (fresh mTLS leaves / spoofed source IPs) cannot grow it without bound. When full, only IDLE
/// (full-bucket) entries are evicted to make room — dropping a full bucket is a no-op for the bound
/// (it recreates identically) — and if EVERY tracked requestor is actively rate-limited, a brand-new
/// requestor is refused (fail-closed): under a saturating flood the node protects its lookup budget
/// rather than its table.
pub const MAX_TRACKED_REQUESTORS: usize = 4096;

/// A registry of per-requestor [`TokenBucket`]s in front of the miss → DHT-lookup path
/// (dig_ecosystem#2007). One abusive requestor's exhausted bucket refuses only ITS OWN further
/// lookups; every other requestor draws from its own independent bucket.
#[derive(Debug)]
pub struct MissRateLimiter {
    /// Per-requestor bucket parameters + the live bucket map, together behind ONE lock so a test can
    /// reconfigure the bound and the map atomically. The critical section is bucket arithmetic only
    /// (no `.await`), so holding it is always brief.
    state: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    capacity: f64,
    refill_per_sec: f64,
    buckets: HashMap<String, TokenBucket>,
}

impl MissRateLimiter {
    /// A limiter with an explicit per-requestor `capacity` + `refill_per_sec` (the deterministic
    /// tests use `refill_per_sec = 0.0` for a fixed pool).
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                capacity,
                refill_per_sec,
                buckets: HashMap::new(),
            }),
        }
    }

    /// A limiter at the production defaults ([`DEFAULT_MISS_LOOKUP_BURST`] /
    /// [`DEFAULT_MISS_LOOKUP_REFILL_PER_SEC`]).
    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_MISS_LOOKUP_BURST,
            DEFAULT_MISS_LOOKUP_REFILL_PER_SEC,
        )
    }

    /// A limiter at the PROXY fetch-through defaults ([`DEFAULT_PROXY_FETCH_BURST`] /
    /// [`DEFAULT_PROXY_FETCH_REFILL_PER_SEC`]) — the tighter, independent bound on the expensive proxy
    /// leg (dig_ecosystem#2189), separate from the cheap miss-lookup budget.
    pub fn with_proxy_defaults() -> Self {
        Self::new(
            DEFAULT_PROXY_FETCH_BURST,
            DEFAULT_PROXY_FETCH_REFILL_PER_SEC,
        )
    }

    /// Reconfigure the per-requestor bound, clearing any existing buckets so the new bound applies
    /// cleanly. Test-only (the enforcement tests pin a small no-refill pool); production stands on the
    /// constructor's parameters.
    #[cfg(test)]
    pub fn reconfigure(&self, capacity: f64, refill_per_sec: f64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.capacity = capacity;
        state.refill_per_sec = refill_per_sec;
        state.buckets.clear();
    }

    /// Admit one miss lookup for `requestor`, or refuse it (`false`) when that requestor's bucket is
    /// exhausted. The bound is PER REQUESTOR: a refused requestor never affects a different one.
    pub fn check(&self, requestor: &RequestorId) -> bool {
        let key = requestor.key();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if !state.buckets.contains_key(&key) && state.buckets.len() >= MAX_TRACKED_REQUESTORS {
            // Table saturated: reclaim only IDLE (full) buckets — dropping a full bucket recreates it
            // identically, so it cannot weaken any active limit. If none are idle (every tracked
            // requestor is under active limiting), refuse the newcomer rather than evict a live bound.
            state.buckets.retain(|_, bucket| !bucket.is_full());
            if state.buckets.len() >= MAX_TRACKED_REQUESTORS {
                return false;
            }
        }

        let (capacity, refill_per_sec) = (state.capacity, state.refill_per_sec);
        state
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(capacity, refill_per_sec))
            .try_acquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_bucket_admits_up_to_capacity_then_refuses() {
        let bucket = TokenBucket::new(3.0, 0.0);
        assert!(bucket.try_acquire(), "1st admitted");
        assert!(bucket.try_acquire(), "2nd admitted");
        assert!(bucket.try_acquire(), "3rd admitted");
        assert!(!bucket.try_acquire(), "4th refused — pool exhausted");
    }

    #[test]
    fn refill_replenishes_over_time() {
        let bucket = TokenBucket::new(1.0, 1_000.0);
        assert!(bucket.try_acquire(), "the single starting token");
        assert!(!bucket.try_acquire(), "drained");
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(bucket.try_acquire(), "refilled after the elapsed time");
    }

    #[test]
    fn is_full_is_true_only_when_untouched() {
        let bucket = TokenBucket::new(2.0, 0.0);
        assert!(bucket.is_full(), "a fresh bucket is at capacity");
        assert!(bucket.try_acquire());
        assert!(!bucket.is_full(), "a spent token drops it below capacity");
    }

    /// The load-bearing property (dig_ecosystem#2007 Unit A): one requestor's exhausted bucket
    /// refuses only ITS OWN lookups; a DIFFERENT requestor draws from an independent bucket.
    ///
    /// Fixture design: TWO distinct peers, an honest CONTROL kept truthful. A single-actor test (or a
    /// global bucket) would false-green a bound that is actually shared — the second peer proves the
    /// key isolation, not just that a bucket empties.
    #[test]
    fn a_saturating_requestor_never_starves_a_different_one() {
        let limiter = MissRateLimiter::new(2.0, 0.0); // fixed pool of 2 per requestor
        let abuser = RequestorId::Peer("aaaa".to_string());
        let control = RequestorId::Peer("bbbb".to_string());

        assert!(limiter.check(&abuser), "abuser 1st");
        assert!(limiter.check(&abuser), "abuser 2nd");
        assert!(
            !limiter.check(&abuser),
            "abuser 3rd refused — its own bucket is spent"
        );
        // The control peer is completely unaffected by the abuser exhausting its bucket.
        assert!(limiter.check(&control), "control 1st still admitted");
        assert!(limiter.check(&control), "control 2nd still admitted");
        assert!(
            !limiter.check(&control),
            "control 3rd refused by its OWN bucket, not the abuser's"
        );
    }

    /// dig_ecosystem#2189: the PROXY fetch-through allowance is strictly TIGHTER than the cheap
    /// miss-lookup budget, so expensive proxy fetches drain far faster than cheap lookups. Pins the
    /// calibration from the constants so a future loosening that erased the separation reds here.
    #[test]
    fn proxy_fetch_allowance_is_tighter_than_the_lookup_budget() {
        // Compile-time so a future edit that erased the separation FAILS the build, not just a run.
        const _: () = assert!(
            DEFAULT_PROXY_FETCH_BURST < DEFAULT_MISS_LOOKUP_BURST,
            "proxy burst must be smaller than the lookup burst"
        );
        const _: () = assert!(
            DEFAULT_PROXY_FETCH_REFILL_PER_SEC < DEFAULT_MISS_LOOKUP_REFILL_PER_SEC,
            "proxy refill must be slower than the lookup refill"
        );
    }

    #[test]
    fn local_is_local_and_remote_requestors_are_not() {
        assert!(RequestorId::Local.is_local());
        assert!(!RequestorId::Peer("aaaa".to_string()).is_local());
        assert!(!RequestorId::Anonymous("10.0.0.1".to_string()).is_local());
    }

    #[test]
    fn local_and_peer_and_anon_are_distinct_buckets() {
        let limiter = MissRateLimiter::new(1.0, 0.0);
        assert!(limiter.check(&RequestorId::Local));
        assert!(limiter.check(&RequestorId::Peer(String::new())));
        assert!(limiter.check(&RequestorId::Anonymous("10.0.0.1".to_string())));
        // Each independently exhausted; none bled into another.
        assert!(!limiter.check(&RequestorId::Local));
        assert!(!limiter.check(&RequestorId::Peer(String::new())));
        assert!(!limiter.check(&RequestorId::Anonymous("10.0.0.1".to_string())));
    }
}
