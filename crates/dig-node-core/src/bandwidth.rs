//! Outgoing-bandwidth throttle (dig_ecosystem issue #30): a fixed-window byte budget on the
//! node's OUTGOING serve traffic, so a saturated node redirects the overflow to another holder
//! (reusing the #165 redirect-on-miss mechanism, `crate::download`) instead of serving over-budget
//! or dropping the request. See `crate::bandwidth_redirect` (defined on `crate::Node` in this
//! module) for the decision that ties the throttle to the redirect.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` unset / `0` / unparsable ⇒ UNLIMITED — the throttle is
/// opt-in, so an unconfigured node serves exactly as it did before this feature.
pub const UNLIMITED: u64 = 0;

/// Pure parse of the `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` value: a positive integer is the cap
/// (bytes/second); anything else (absent, `0`, non-numeric) is [`UNLIMITED`]. Pure so the env
/// contract is unit-tested without touching process-global env (mirrors
/// `download::resolve_miss_mode`).
fn parse_cap(v: Option<&str>) -> u64 {
    v.and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(UNLIMITED)
}

/// Resolve the outgoing-bandwidth cap (bytes/second) from `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC`.
pub fn max_outgoing_bytes_per_sec_from_env() -> u64 {
    parse_cap(
        std::env::var("DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC")
            .ok()
            .as_deref(),
    )
}

/// The throttle's mutable accounting, behind a mutex (the serve path is multi-request-concurrent).
struct ThrottleState {
    /// When the current 1-second accounting window started.
    window_start: Instant,
    /// Bytes served (or force-recorded) so far in the current window.
    served_bytes: u64,
}

/// A fixed-1-second-window outgoing-bandwidth throttle.
///
/// The serve path asks, BEFORE writing a chunk, "would `bytes` more push this second's outgoing
/// total over the cap?" ([`Self::would_exceed`]) — a peek, not a reservation — then records what it
/// actually sent ([`Self::record_served`]). A fixed window (not a token bucket / leaky bucket) is
/// deliberately the simplest thing that works: the serve path only needs a yes/no answer for "right
/// now", never smoothed pacing, and a fixed window is trivial to reason about and to unit-test — the
/// `*_at` variants take the instant explicitly, so tests roll the window forward by constructing a
/// later `Instant` (`now + Duration`) instead of sleeping or injecting a fake-clock trait.
///
/// `cap_bytes_per_sec == 0` is UNLIMITED: [`Self::would_exceed`] always returns `false` and
/// [`Self::record_served`] is a no-op (no accounting overhead when the feature is not configured).
pub struct OutgoingThrottle {
    cap_bytes_per_sec: u64,
    state: Mutex<ThrottleState>,
}

impl OutgoingThrottle {
    /// Build a throttle capped at `cap_bytes_per_sec` bytes/second (`0` = [`UNLIMITED`]).
    pub fn new(cap_bytes_per_sec: u64) -> Self {
        OutgoingThrottle {
            cap_bytes_per_sec,
            state: Mutex::new(ThrottleState {
                window_start: Instant::now(),
                served_bytes: 0,
            }),
        }
    }

    /// Build a throttle from `DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC` ([`UNLIMITED`] if unset).
    pub fn from_env() -> Self {
        Self::new(max_outgoing_bytes_per_sec_from_env())
    }

    /// The configured cap (`0` = unlimited).
    pub fn cap_bytes_per_sec(&self) -> u64 {
        self.cap_bytes_per_sec
    }

    /// Roll the window if `now` is a full second past `window_start`.
    fn roll(state: &mut ThrottleState, now: Instant) {
        if now.saturating_duration_since(state.window_start) >= Duration::from_secs(1) {
            state.window_start = now;
            state.served_bytes = 0;
        }
    }

    /// Would serving `bytes` more push this second's outgoing total over the cap, as of `now`? A
    /// PEEK — rolls an elapsed window but does not reserve/record. [`UNLIMITED`] never exceeds.
    pub fn would_exceed_at(&self, bytes: u64, now: Instant) -> bool {
        if self.cap_bytes_per_sec == 0 {
            return false;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Self::roll(&mut state, now);
        state.served_bytes.saturating_add(bytes) > self.cap_bytes_per_sec
    }

    /// [`Self::would_exceed_at`] at the current instant.
    pub fn would_exceed(&self, bytes: u64) -> bool {
        self.would_exceed_at(bytes, Instant::now())
    }

    /// Record that `bytes` were actually served, as of `now` (rolls an elapsed window first).
    /// Called on EVERY serve — including the graceful over-cap fallback when no alternate holder is
    /// known — so the accounting stays honest even when a request was not redirected. A no-op when
    /// [`UNLIMITED`].
    pub fn record_served_at(&self, bytes: u64, now: Instant) {
        if self.cap_bytes_per_sec == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        Self::roll(&mut state, now);
        state.served_bytes = state.served_bytes.saturating_add(bytes);
    }

    /// [`Self::record_served_at`] at the current instant.
    pub fn record_served(&self, bytes: u64) {
        self.record_served_at(bytes, Instant::now());
    }
}

// -- Node integration: bandwidth-redirect (extends #165 redirect-on-miss to "held but saturated") --

impl crate::Node {
    /// Decide whether serving `bytes` more of `content` right now would push this node's outgoing
    /// traffic over its configured cap and, if so, whether a known alternate holder exists to
    /// redirect to instead — the SAME [`crate::download::CONTENT_REDIRECT`] error object shape and
    /// hop-cap discipline the #165 redirect-on-miss path uses ([`crate::download::redirect_error_object`],
    /// [`crate::download::REDIRECT_HOP_CAP`]), so a caller (JSON-RPC or the peer stream) handles a
    /// bandwidth-redirect exactly like a miss-redirect.
    ///
    /// Returns `None` — serve the request now — when: under budget; no P2P content engine is
    /// attached (the in-process FFI/browser path has nothing to redirect to); the hop budget is
    /// already exhausted (never loop callers between saturated nodes); or no alternate holder is
    /// known. The last case is the GRACEFUL FALLBACK the issue calls for: a throttle that redirects
    /// when it can, never one that fails closed — an over-budget serve with no alternate still goes
    /// out rather than being dropped.
    pub(crate) async fn bandwidth_redirect(
        &self,
        content: &dig_dht::ContentId,
        bytes: u64,
        depth: u64,
    ) -> Option<serde_json::Value> {
        if !self.outgoing_throttle.would_exceed(bytes) {
            return None;
        }
        let pc = self.p2p_content()?;
        if depth >= crate::download::REDIRECT_HOP_CAP {
            return None;
        }
        let providers = pc.find_providers(content).await;
        if providers.is_empty() {
            return None;
        }
        Some(crate::download::redirect_error_object(
            content,
            &providers,
            depth + 1,
        ))
    }

    /// [`Self::bandwidth_redirect`] keyed by a resource's raw hex identity (store/root/retrieval_key)
    /// — the shape every `dig.getContent` local-serve call site shares (mirrors
    /// `crate::download::miss_content_for`). `None` when the identity is not concrete hex (the
    /// bandwidth-redirect path is inapplicable then, same as the miss path) or when
    /// [`Self::bandwidth_redirect`] itself returns `None`.
    pub(crate) async fn bandwidth_redirect_for(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
        bytes: u64,
        depth: u64,
    ) -> Option<serde_json::Value> {
        let content = crate::download::miss_content_for(store_hex, root_hex, rk_hex)?;
        self.bandwidth_redirect(&content, bytes, depth).await
    }

    /// Record `bytes` actually sent over the outgoing-bandwidth throttle's accounting window.
    pub(crate) fn record_outgoing_bytes(&self, bytes: u64) {
        self.outgoing_throttle.record_served(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- env parsing (pure) -------------------------------------------------------------------------

    #[test]
    fn env_cap_defaults_to_unlimited() {
        assert_eq!(parse_cap(None), UNLIMITED, "unset → unlimited");
        assert_eq!(parse_cap(Some("0")), UNLIMITED, "explicit 0 → unlimited");
        assert_eq!(
            parse_cap(Some("not-a-number")),
            UNLIMITED,
            "unparsable → unlimited"
        );
        assert_eq!(parse_cap(Some("")), UNLIMITED, "empty → unlimited");
    }

    #[test]
    fn env_cap_parses_a_positive_value() {
        assert_eq!(parse_cap(Some("500000")), 500_000);
        assert_eq!(parse_cap(Some(" 1024 ")), 1024, "trimmed");
    }

    // -- the throttle's window accounting -------------------------------------------------------------

    #[test]
    fn unlimited_never_exceeds_and_never_accounts() {
        let t = OutgoingThrottle::new(UNLIMITED);
        assert!(!t.would_exceed(u64::MAX));
        t.record_served(u64::MAX);
        assert!(
            !t.would_exceed(u64::MAX),
            "recording is a no-op when unlimited"
        );
    }

    #[test]
    fn under_cap_does_not_exceed() {
        let t = OutgoingThrottle::new(1000);
        assert!(!t.would_exceed(500));
    }

    #[test]
    fn exactly_at_cap_is_allowed_one_more_byte_tips_it_over() {
        let t = OutgoingThrottle::new(1000);
        t.record_served(900);
        assert!(!t.would_exceed(100), "900 + 100 == cap, allowed");
        assert!(t.would_exceed(101), "900 + 101 > cap, exceeds");
    }

    #[test]
    fn would_exceed_is_a_peek_that_does_not_reserve() {
        let t = OutgoingThrottle::new(100);
        assert!(t.would_exceed(150), "over cap without ever recording");
        // Peeking again gives the SAME answer — the peek did not consume/reserve anything.
        assert!(t.would_exceed(150));
        assert_eq!(t.cap_bytes_per_sec(), 100, "cap is reported as configured");
    }

    #[test]
    fn window_rolls_over_after_a_second_refreshing_the_budget() {
        let t = OutgoingThrottle::new(1000);
        let start = Instant::now();
        t.record_served_at(1000, start);
        assert!(
            t.would_exceed_at(1, start),
            "still saturated within the same window"
        );
        let just_before = start + Duration::from_millis(999);
        assert!(
            t.would_exceed_at(1, just_before),
            "window has not rolled yet"
        );
        let after = start + Duration::from_secs(1);
        assert!(
            !t.would_exceed_at(999, after),
            "window rolled at the 1s boundary, budget refreshed"
        );
    }

    #[test]
    fn record_served_rolls_an_elapsed_window_before_adding() {
        let t = OutgoingThrottle::new(100);
        let start = Instant::now();
        t.record_served_at(100, start);
        assert!(t.would_exceed_at(1, start));
        // A new window: recording here must NOT accumulate onto the stale window's 100 bytes.
        let later = start + Duration::from_secs(2);
        t.record_served_at(50, later);
        assert!(
            !t.would_exceed_at(50, later),
            "50 + 50 == cap in the FRESH window, not 100 + 50 + 50 carried over"
        );
    }
}
