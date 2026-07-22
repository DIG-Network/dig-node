//! [`SelectorAdapter`] — the @30↔@30 bridge that makes the self-optimizing **dig-peer-selector**
//! the brain behind **dig-download**'s source choice (#1442).
//!
//! # Why an adapter here, in dig-node
//!
//! dig-download and dig-peer-selector are BOTH level-30 crates, so neither may depend on the other
//! (reference-DOWN only — no same-level edge, CLAUDE.md Appendix B). dig-download therefore exposes a
//! minimal [`SourceSelector`] seam with its OWN DTOs, and dig-peer-selector exposes its richer
//! learning engine; the two never meet. dig-node — one level UP, the composition root that already
//! owns the single [`PeerSelector`] instance — is the place that wires them together: this adapter
//! IMPLEMENTS dig-download's [`SourceSelector`] by delegating every `select`/`record` to the shared
//! selector. There is exactly ONE learning loop for the whole node (the same instance that also
//! drives PEX dial ordering and is fed pool churn), never a second competing brain.
//!
//! # Content-agnostic learning (the synthetic ContentId)
//!
//! dig-download's `SelectRequest::content_key` is the 64-hex of a content's DHT key — a one-way hash,
//! NOT reversible to a [`ContentId`]. That is fine: dig-peer-selector's model is **per-peer and
//! global** — `record_outcome` never reads `outcome.content`, and `select` scores a peer purely on
//! its measured throughput/reliability/saturation across ALL transfers (SPEC §3, §9.2). So this
//! adapter passes a single fixed synthetic [`ContentId`] on every call ([`learning_content`]); the
//! selector's decisions are identical to what a real (unrecoverable) content id would produce, and
//! one node-wide quality model informs every download.

use std::sync::Arc;

use dig_download::{RangeOutcome, RangeResult, SelectPlan, SelectRequest, SourceSelector};
use dig_peer_selector::{
    Candidate, CandidateAddr, ContentId, ContentRequest, FailureReason, OutcomeKind, OutcomeResult,
    PeerId, PeerSelector, TransferOutcome,
};

/// The most parallel sources the adapter ever asks the selector to rank in one pass — matches the
/// dig-download default `max_concurrency` (8) so the ranked subset is wide enough to feed the
/// executor's fan-out without over-selecting a low-quality tail.
const MAX_PARALLELISM: usize = 8;

/// Bridges dig-download's [`SourceSelector`] seam onto the node's shared [`PeerSelector`] (#1442).
///
/// Holds the SAME `Arc<PeerSelector>` instance [`crate::download::NodeContent`] owns, so the source
/// ranking dig-download sees and the quality the node learns (from pool churn + PEX + every range
/// outcome) are one and the same model.
pub(crate) struct SelectorAdapter {
    selector: Arc<PeerSelector>,
}

impl SelectorAdapter {
    /// Wrap the shared selector as a dig-download source-selection brain.
    pub(crate) fn new(selector: Arc<PeerSelector>) -> Self {
        SelectorAdapter { selector }
    }
}

impl SourceSelector for SelectorAdapter {
    fn select(&self, req: &SelectRequest) -> SelectPlan {
        // Map dig-download's candidate refs → selector candidates, DROPPING any whose peer_id is not
        // valid 64-hex (an unaddressable provider is not a candidate — dig-peer-selector attributes
        // only to transport-verified identities, SPEC §9.1).
        let candidates: Vec<Candidate> = req
            .candidates
            .iter()
            .filter_map(|c| candidate_from_ref(&c.peer_id, &c.addrs))
            .collect();

        // Ask the selector to rank a subset, bounded by how many ranges still need a source (never
        // more than MAX_PARALLELISM). effective_parallelism clamps to >= 1 internally.
        let parallelism = req.ranges_needed.clamp(1, MAX_PARALLELISM);
        let request = ContentRequest::new(learning_content(), parallelism);
        let selection = self.selector.select(&request, &candidates);

        if selection.is_empty() {
            // The selector abstained (no eligible candidate / none worth using). NEVER starve a fetch
            // that has holders: pass every candidate the request offered through, in the given order,
            // so the executor still has sources — exactly the SelectorLocator abstain behavior (#178).
            return SelectPlan::ordered(req.candidates.iter().map(|c| c.peer_id.clone()).collect());
        }

        // The selector's ranked subset, best-first, as 64-hex peer_ids the executor schedules against.
        SelectPlan::ordered(selection.peers.iter().map(|p| p.peer_id.to_hex()).collect())
    }

    fn record(&self, outcome: &RangeOutcome) {
        // Attribute only to a transport-verified identity: a malformed peer_id records nothing.
        let Some(peer_id) = PeerId::from_hex(&outcome.peer_id) else {
            return;
        };
        let transfer = TransferOutcome {
            peer_id,
            content: learning_content(),
            // The selector needs range identity to attribute a saturation observation; dig-download's
            // RangeOutcome carries no plan index/offset, so index/offset are 0 and `length` is the
            // measured bytes (index is the attribution key — SPEC §6.5; the model is per-peer global).
            kind: OutcomeKind::Range {
                index: 0,
                offset: 0,
                length: outcome.bytes,
            },
            result: map_range_result(outcome.result),
            bytes: outcome.bytes,
            duration_ms: outcome.elapsed.as_millis() as u64,
            rtt_ms: None,
            at: now_unix(),
        };
        self.selector.record_outcome(&transfer);
    }
}

/// The fixed synthetic [`ContentId`] every delegated call carries. dig-peer-selector's model is
/// per-peer and content-agnostic (`record_outcome` never reads `content`; `select` scores peers, not
/// content), so a single stable id is correct and keeps dig-download's one-way `content_key` out of
/// the seam. See the module docs for the full rationale.
fn learning_content() -> ContentId {
    ContentId::store([0u8; 32])
}

/// Map a dig-download [`RangeResult`] to a dig-peer-selector [`OutcomeResult`]. A transport failure
/// and a timeout are reported DISTINCTLY (a too-slow peer is down-ranked differently from a broken
/// one, SPEC §6.2); neither is the hard `VerificationFailed` signal — dig-download verifies a range's
/// bytes itself and reports a verification failure as `Failed`, but at this seam we cannot tell a
/// transport `Failed` from a verify `Failed`, so it maps to the softer `Transport` class (a verify
/// failure additionally triggers dig-download's own source penalty/backoff).
fn map_range_result(result: RangeResult) -> OutcomeResult {
    match result {
        RangeResult::Ok => OutcomeResult::Success,
        RangeResult::Failed => OutcomeResult::Failure {
            reason: FailureReason::Transport,
        },
        RangeResult::TimedOut => OutcomeResult::Failure {
            reason: FailureReason::Timeout,
        },
    }
}

/// Build a selector [`Candidate`] from a dig-download candidate's 64-hex `peer_id` + dial addresses,
/// or `None` if the peer_id is malformed hex. Addresses that don't parse are skipped (the selector
/// ranks on identity + learned quality, not the address strings, so a partial address list is fine).
fn candidate_from_ref(peer_id_hex: &str, addrs: &[String]) -> Option<Candidate> {
    let peer_id = PeerId::from_hex(peer_id_hex)?;
    let addresses = addrs.iter().filter_map(|a| parse_addr(a)).collect();
    Some(Candidate::new(peer_id, addresses))
}

/// Parse a dig-download `host:port` address string into a [`CandidateAddr`]. Tries a full
/// [`SocketAddr`](std::net::SocketAddr) parse first (handles bracketed IPv6), falling back to a
/// right-split on the last `:` for a bare `host:port`.
fn parse_addr(s: &str) -> Option<CandidateAddr> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Some(CandidateAddr::direct(sa.ip().to_string(), sa.port()));
    }
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    Some(CandidateAddr::direct(host, port))
}

/// Current unix seconds (the `at` timestamp on a [`TransferOutcome`]).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_download::CandidateRef;
    use dig_peer_selector::SelectorConfig;
    use std::time::Duration;

    fn peer_hex(b: u8) -> String {
        PeerId::from_bytes([b; 32]).to_hex()
    }

    fn adapter() -> SelectorAdapter {
        // Deterministic selector so the ranking under test is reproducible.
        SelectorAdapter::new(Arc::new(PeerSelector::new(SelectorConfig::deterministic(
            1000, 7,
        ))))
    }

    fn candidate_ref(b: u8) -> CandidateRef {
        CandidateRef::new(peer_hex(b), vec![format!("10.0.0.{b}:9444")])
    }

    /// A stable content-key string for the request under test (dig-download passes the content's DHT
    /// key hex; the adapter never uses it — the selector model is per-peer/content-agnostic).
    const CONTENT_KEY: &str = "abababababababababababababababababababababababababababababababab";

    fn request(candidates: &[CandidateRef], ranges_needed: usize) -> SelectRequest<'_> {
        SelectRequest {
            content_key: CONTENT_KEY,
            candidates,
            ranges_needed,
            inflight: 0,
        }
    }

    /// select maps the candidate refs to selector candidates and returns the selector's chosen order —
    /// a non-empty subset drawn only from the offered candidates, and the selector registers them
    /// (proving it was consulted, not bypassed).
    #[test]
    fn select_maps_candidates_and_returns_selector_order() {
        let a = adapter();
        let cands = vec![candidate_ref(1), candidate_ref(2), candidate_ref(3)];
        let plan = a.select(&request(&cands, 3));

        assert!(!plan.ordered.is_empty(), "selector chose at least one source");
        let offered: std::collections::HashSet<String> =
            cands.iter().map(|c| c.peer_id.clone()).collect();
        for id in &plan.ordered {
            assert!(offered.contains(id), "a chosen source came from the offered set");
        }
        assert!(
            a.selector.registry_size() >= plan.ordered.len(),
            "the selector registered the candidates it ranked"
        );
    }

    /// When no candidate maps to a valid identity the selector abstains; the adapter must NOT starve
    /// the fetch — it passes every offered candidate through, in order.
    #[test]
    fn select_abstain_passes_candidates_through() {
        let a = adapter();
        // All malformed → the mapped candidate set is empty → the selector returns an empty selection.
        let cands = vec![
            CandidateRef::new("not-hex", vec!["10.0.0.1:9444".into()]),
            CandidateRef::new("also-bad", vec!["10.0.0.2:9444".into()]),
        ];
        let plan = a.select(&request(&cands, 4));
        assert_eq!(
            plan.ordered,
            vec!["not-hex".to_string(), "also-bad".to_string()],
            "abstain passes the raw offered candidates through (never starve)"
        );
    }

    /// A malformed candidate hex is dropped from the ranked set (the selector never sees it), while the
    /// valid candidates are still ranked and returned.
    #[test]
    fn select_drops_malformed_peer_id_hex() {
        let a = adapter();
        let cands = vec![
            candidate_ref(1),
            CandidateRef::new("xyz", vec!["10.0.0.9:9444".into()]),
            candidate_ref(2),
        ];
        let plan = a.select(&request(&cands, 3));
        assert!(!plan.ordered.is_empty());
        assert!(
            !plan.ordered.iter().any(|id| id == "xyz"),
            "the malformed candidate is never ranked/returned"
        );
        let valid: std::collections::HashSet<String> = [peer_hex(1), peer_hex(2)].into();
        for id in &plan.ordered {
            assert!(valid.contains(id), "only the valid candidates are ranked");
        }
    }

    /// A successful range outcome feeds a Success into the selector — the peer acquires a measured
    /// sample (proving record delegated to the learning loop).
    #[test]
    fn record_ok_feeds_success_outcome() {
        let a = adapter();
        a.record(&RangeOutcome {
            peer_id: peer_hex(5),
            bytes: 100_000,
            elapsed: Duration::from_millis(200),
            result: RangeResult::Ok,
        });
        let snap = a
            .selector
            .peer_snapshot(&PeerId::from_bytes([5; 32]))
            .expect("peer registered by the recorded outcome");
        assert!(snap.samples >= 1, "the success was folded into the model");
    }

    /// Failed and TimedOut map to distinct selector failure reasons (transport vs timeout), and Ok to
    /// success — the mapping dig-download's learning loop depends on.
    #[test]
    fn record_timeout_and_failed_map_distinctly() {
        assert_eq!(map_range_result(RangeResult::Ok), OutcomeResult::Success);
        assert_eq!(
            map_range_result(RangeResult::Failed),
            OutcomeResult::Failure {
                reason: FailureReason::Transport
            }
        );
        assert_eq!(
            map_range_result(RangeResult::TimedOut),
            OutcomeResult::Failure {
                reason: FailureReason::Timeout
            }
        );
    }

    /// A malformed peer_id records nothing (no panic, no phantom registry entry).
    #[test]
    fn record_ignores_malformed_peer_id() {
        let a = adapter();
        a.record(&RangeOutcome {
            peer_id: "not-a-peer".into(),
            bytes: 1,
            elapsed: Duration::from_millis(1),
            result: RangeResult::Ok,
        });
        assert_eq!(a.selector.registry_size(), 0, "nothing recorded for a bad id");
    }

    /// The address parser handles bare host:port and bracketed IPv6.
    #[test]
    fn parse_addr_handles_ipv4_and_ipv6() {
        assert!(parse_addr("10.0.0.1:9444").is_some());
        assert!(parse_addr("[2001:db8::1]:9444").is_some());
        assert!(parse_addr("garbage").is_none());
    }
}
