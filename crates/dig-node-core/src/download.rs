//! P2P content orchestration — dig-download as the node's multi-source content-FETCH path (#164)
//! and REDIRECT-ON-MISS (#165).
//!
//! This module is the final wire-up of the DIG Node P2P content epic. It composes the pieces the
//! earlier phases left as seams:
//!
//! 1. **The fetch path (#164)** — [`NodeContent`] builds a [`dig_download::Downloader`] from the
//!    node's LIVE runtime pieces exactly as dig-download's implementers' note prescribes:
//!    [`DhtProviderLocator`] over the node's [`dig_dht::DhtService`] (the locate seam
//!    [`crate::dht::DhtHandle::locate_providers`] pointed at), [`NatRangeTransport`] over the node's
//!    mTLS identity + NAT config + network id, [`MerkleVerifier::with_proof_verifier`] bound to the
//!    **digstore** merkle-proof byte format ([`DigstoreProofVerifier`] — the store crate owns the
//!    proof encoding, so the whole-resource check binds to the chain-anchored root), a per-download
//!    [`FileSink`] staging under the node's cache, and a [`FileStateStore`] so interrupted downloads
//!    resume. [`NodeContent::fetch_resource`] is the content-acquisition entry point: derive the
//!    [`ContentId`], `download(...)`, drive progress, and land the verified bytes in the node
//!    (in-memory, served like a locally-held resource). Stale `.download.tmp` staging files are
//!    reaped by [`NodeContent::spawn_gc`] (startup sweep + interval, like the DHT gc/republish loop).
//!
//! 2. **Redirect-on-miss (#165)** — when a content RPC (`dig.getContent` / `dig.fetchRange` / the
//!    peer range stream / `dig.getAvailability`) asks for content this node does NOT hold, the miss
//!    handler ([`crate::Node::miss_outcome`]) locates the holders via the DHT and — by default —
//!    RETURNS A REDIRECT naming them ([`CONTENT_REDIRECT`], JSON-RPC error `-32008` whose
//!    `data.redirect` carries the providers' `peer_id` + candidate addresses), so the caller
//!    re-requests against a holder instead of dead-ending on a bare not-found. Hops are BOUNDED: the
//!    caller echoes `redirect_depth` on the re-request and a node at/over [`REDIRECT_HOP_CAP`]
//!    answers the plain not-found (no redirect loops). With `DIG_NODE_ON_MISS=fetch` the node
//!    instead FETCHES-THROUGH: it pulls the resource from the holders via dig-download (multi-source,
//!    verified), caches it, and serves it directly — and if the fetch fails it still falls back to
//!    the redirect, so a provider-held resource is never silently 404'd.
//!
//! The engine is constructed ONLY by the standalone peer-network bring-up
//! ([`crate::peer::spawn_peer_network`]); the in-process FFI path (the browser) never sets it, so
//! every existing hit path — local module serve, §21 sync, response cache, upstream proxy — and the
//! FFI contract are byte-identical to before (the miss handler is a no-op without the engine).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use serde_json::{json, Value};

use dig_dht::ContentId;
use dig_download::{
    download_key, DhtProviderLocator, DownloadConfig, DownloadError, DownloadEvent,
    DownloadOptions, Downloader, FileSink, FileStateStore, GcConfig, MerkleVerifier,
    NatRangeTransport, ProofVerifier, ProviderLocator, ProviderRecord, RangeTransport, StateStore,
};
use dig_peer_selector::{
    Candidate, ContentRequest, FailureReason, OutcomeKind, OutcomeResult, PeerId, PeerSelector,
    PoolEvent, PoolRemovalReason, RangePlanDelta, SelectorConfig, TransferOutcome, TraversalKind,
};
use digstore_core::codec::Decode;

use crate::dht::hex64;

/// How many parallel sources the node asks the selector to rank for a content fetch. Matches the
/// dig-download default `max_concurrency` (8) so the selector's ranked subset is wide enough to feed
/// the executor's fan-out without over-selecting a low-quality tail.
const SELECT_PARALLELISM: usize = 8;

/// JSON-RPC error code: the content is NOT held by this node, but the DHT located peers that DO
/// hold it — the `error.data.redirect` names them (peer_id + candidate addresses) so the caller
/// re-requests against a holder. Catalogued in docs.dig.net (L7 peer-network spec + error catalog).
pub const CONTENT_REDIRECT: i64 = -32008;

/// The redirect hop bound (#165): a request that has already been redirected this many times is
/// answered with the plain not-found instead of another redirect, so a set of nodes can never
/// bounce a caller in a loop. The caller echoes the served `redirect_depth` on its re-request.
pub const REDIRECT_HOP_CAP: u64 = 4;

/// The catalogued "not held at the requested root" code the miss path intercepts (shared with the
/// existing L7 range/content serve — see docs.dig.net error catalog).
pub(crate) const RESOURCE_UNAVAILABLE: i64 = -32004;

/// How many fetched-through resources are retained in memory for re-serving (windows of the same
/// resource, immediate re-reads). Small by design: fetch-through is a miss-path cache, not the
/// module cache — the LRU module cache stays the durable store.
const FETCHED_CACHE_CAP: usize = 8;

// -- Miss-mode configuration ---------------------------------------------------------------------

/// What the node does on a content miss when providers exist (#165).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissMode {
    /// DEFAULT: answer with the [`CONTENT_REDIRECT`] error naming the holders — cheap, stateless,
    /// and exactly what the requester needs to re-request against a holder.
    Redirect,
    /// `DIG_NODE_ON_MISS=fetch`: pull the resource from the holders via dig-download
    /// (multi-source, verified), cache it, and serve it directly — transparent to the caller.
    /// Falls back to the redirect if the fetch fails.
    FetchThrough,
}

/// Resolve the miss mode from the `DIG_NODE_ON_MISS` environment variable (unset → redirect).
pub fn miss_mode_from_env() -> MissMode {
    resolve_miss_mode(std::env::var("DIG_NODE_ON_MISS").ok().as_deref())
}

/// Pure core of [`miss_mode_from_env`]: `fetch` / `fetch-through` / `fetch_through`
/// (case-insensitive) selects fetch-through; anything else (including unset) is the default
/// redirect. Pure so the policy is unit-tested without touching process-global env.
fn resolve_miss_mode(v: Option<&str>) -> MissMode {
    match v.map(str::trim) {
        Some(s)
            if s.eq_ignore_ascii_case("fetch")
                || s.eq_ignore_ascii_case("fetch-through")
                || s.eq_ignore_ascii_case("fetch_through") =>
        {
            MissMode::FetchThrough
        }
        _ => MissMode::Redirect,
    }
}

/// Whether background capsule backfill (§5.6) is enabled: when a resource read is satisfied FROM
/// ANOTHER NODE (a redirect or a fetch-through miss for a concrete `(store, root)`), the node ALSO
/// pulls the whole `.dig` capsule for that generation in the background and caches it, so the NEXT
/// read of that store is served locally. Resolved from `DIG_NODE_BACKFILL_ON_MISS`; **default ON** —
/// only an explicit `off`/`0`/`false`/`no` disables it. Distinct from `DIG_NODE_ON_MISS` (which
/// chooses redirect vs. fetch-through for the CURRENT read): backfill is the behind-the-scenes
/// whole-capsule warm-up that applies under BOTH miss modes.
pub fn backfill_on_miss_enabled() -> bool {
    resolve_backfill_on_miss(std::env::var("DIG_NODE_BACKFILL_ON_MISS").ok().as_deref())
}

/// Pure core of [`backfill_on_miss_enabled`]: default ON; only an explicit falsy value
/// (`off`/`0`/`false`/`no`, case-insensitive) disables it. Pure so the policy is unit-tested without
/// touching process-global env.
fn resolve_backfill_on_miss(v: Option<&str>) -> bool {
    !matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("off") | Some("0") | Some("false") | Some("no")
    )
}

// -- The digstore-bound proof verifier -------------------------------------------------------------

/// The REAL [`ProofVerifier`] for dig-download's whole-resource check: decodes the digstore
/// [`MerkleProof`](digstore_core::MerkleProof) byte format (base64 on the wire, exactly what the
/// node serves in `inclusion_proof`) and requires that `resource_leaf` IS the proof's leaf, the
/// proof folds to its root, and that root IS the download's committed generation root. This binds a
/// multi-source reassembly to the chain-anchored root — no peer mix can forge the resource.
///
/// A capsule fetch carries no per-resource proof (`None`/`None`) and self-verifies on install →
/// accepted here; a HALF-specified binding (proof without root or vice versa) fails closed.
pub struct DigstoreProofVerifier;

impl ProofVerifier for DigstoreProofVerifier {
    fn verify_inclusion(
        &self,
        resource_leaf: &[u8; 32],
        inclusion_proof: Option<&str>,
        root: Option<&str>,
    ) -> bool {
        match (inclusion_proof, root) {
            // A capsule fetch carries no per-resource proof; it self-verifies on install → accept.
            (None, None) => true,
            // A half-specified binding (proof without a root to check it against, or a root with no
            // proof) fails closed — we never accept a claim we cannot fully verify.
            (Some(_), None) | (None, Some(_)) => false,
            (Some(proof_b64), Some(root_hex)) => {
                // 1. Decode the base64 wire form → the digstore MerkleProof bytes → the proof.
                let Ok(proof_bytes) = base64::engine::general_purpose::STANDARD.decode(proof_b64)
                else {
                    return false;
                };
                let Ok(proof) = digstore_core::MerkleProof::from_bytes(&proof_bytes) else {
                    return false;
                };
                // 2. The proof's leaf MUST be exactly the served resource's leaf (SHA-256 of the
                //    reassembled ciphertext) — a wrong/corrupt resource has a different leaf.
                if proof.leaf.0 != *resource_leaf {
                    return false;
                }
                // 3. The proof MUST fold from leaf → its own root.
                if !proof.verify() {
                    return false;
                }
                // 4. That root MUST be the download's committed generation root (the chain-anchored
                //    root the caller pinned) — binding the multi-source reassembly to the on-chain root.
                proof.root.to_hex() == root_hex
            }
        }
    }
}

// -- The fetched-resource shape (fetch-through serving) --------------------------------------------

/// A resource acquired via the multi-source fetch path: the verified ciphertext plus the
/// first-frame verification metadata (the download's [`ResourceCommitment`]
/// (dig_download::ResourceCommitment) fields), so the node can serve it exactly like a
/// locally-held resource — `dig.fetchRange` frames and `dig.getContent` windows both carry the
/// proof + chunk layout the caller verifies against the chain-anchored root.
#[derive(Debug, Clone)]
pub struct FetchedResource {
    /// The whole, verified resource ciphertext.
    pub bytes: Vec<u8>,
    /// The committed full-resource length (== `bytes.len()`).
    pub total_length: u64,
    /// Per-chunk ciphertext lengths of the whole resource, in order.
    pub chunk_lens: Vec<u64>,
    /// The chain-anchored generation root (64-hex) the resource verified against.
    pub root: Option<String>,
    /// The whole-resource merkle inclusion proof (base64, digstore byte format).
    pub inclusion_proof: Option<String>,
}

impl FetchedResource {
    /// Build one `dig.fetchRange` frame over the fetched bytes — the same window/verification
    /// shape as [`crate::Node::fetch_range_frame`] over a locally-held resource (first frame
    /// carries `total_length`/`chunk_lens`/`chunk_index`/`inclusion_proof`/`root`). `-32007` for an
    /// offset beyond the resource, mirroring the local path.
    pub fn range_frame(&self, offset: usize, length: usize) -> Result<Value, (i64, String)> {
        let total = self.bytes.len();
        if offset > total {
            return Err((
                -32007,
                format!("offset {offset} beyond resource length {total}"),
            ));
        }
        let start = offset.min(total);
        let end = (start + length.min(crate::peer::RANGE_WINDOW)).min(total);
        let window = &self.bytes[start..end];
        let complete = end >= total;
        let mut frame = json!({
            "offset": start,
            "length": window.len(),
            "bytes": base64::engine::general_purpose::STANDARD.encode(window),
            "complete": complete,
        });
        if start == 0 {
            if let Some(obj) = frame.as_object_mut() {
                obj.insert("total_length".into(), json!(self.total_length));
                obj.insert("chunk_lens".into(), json!(self.chunk_lens));
                obj.insert("chunk_index".into(), json!(0));
                if let Some(proof) = &self.inclusion_proof {
                    obj.insert("inclusion_proof".into(), json!(proof));
                }
                if let Some(root) = &self.root {
                    obj.insert("root".into(), json!(root));
                }
            }
        }
        Ok(frame)
    }

    /// Build one `dig.getContent` result window over the fetched bytes — the same shape as the
    /// node's `build_result` over a served [`ContentResponse`](digstore_core::wire::ContentResponse)
    /// (ciphertext window + `root` + `complete`/`next_offset`, proof + `chunk_lens` on the first
    /// window only), so a fetch-through serve is indistinguishable in shape from a local one.
    pub fn content_result(&self, offset: usize) -> Value {
        let total = self.bytes.len();
        let start = offset.min(total);
        let end = (start + crate::WINDOW).min(total);
        let window = &self.bytes[start..end];
        let complete = end >= total;
        let mut result = json!({
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(window),
            "root": self.root.clone().unwrap_or_default(),
            "complete": complete,
        });
        if !complete {
            result["next_offset"] = json!(end);
        }
        if start == 0 {
            if let Some(proof) = &self.inclusion_proof {
                result["inclusion_proof"] = json!(proof);
            }
            result["chunk_lens"] = json!(self.chunk_lens);
        }
        result
    }
}

// -- The self-optimizing peer selector (#178) — the brain between discovery and download ------------
//
// The selector (dig-peer-selector) is the DECISION + LEARNING layer that sits between dig-dht
// discovery and dig-download execution (its SPEC §1, §6.1, §7.4): of the providers `find_providers`
// returns, WHICH subset should serve this content and in what order — learned from the REAL measured
// outcome of every range it influenced. dig-node owns the wiring (the selector crate defines only the
// contract): it feeds the registry (pool churn + connection classes), drives source choice through the
// [`SelectorLocator`] seam below, and streams every completed/failed range back via `record_outcome`.

/// Map a `dig_gossip::PoolEvent` into the selector's local [`PoolEvent`] (SPEC §5.4 — the shapes are
/// byte-identical; the selector mirrors the type LOCALLY rather than depending on dig-gossip, so the
/// host maps it 1:1). `dig-gossip`'s `peer_id` is a `chia_protocol::Bytes32` (32 bytes); the selector
/// re-uses `dig_nat::PeerId` (also SHA-256(SPKI DER), 32 bytes) — the SAME identity, so the map is a
/// byte copy through [`PeerId::from_bytes`]. Generic over the 32-byte peer-id representation so the
/// caller passes gossip's `Bytes32` (which derefs / `Into`s `[u8; 32]`).
pub(crate) fn pool_event_to_selector(peer_id: [u8; 32], event: PoolEventKind) -> PoolEvent {
    let peer_id = PeerId::from_bytes(peer_id);
    match event {
        PoolEventKind::Added { addr } => PoolEvent::PeerAdded { peer_id, addr },
        PoolEventKind::Removed { reason } => PoolEvent::PeerRemoved {
            peer_id,
            reason: pool_removal_reason(reason),
        },
    }
}

/// The 1:1 field map of `dig_gossip::PoolRemovalReason` → the selector's local [`PoolRemovalReason`]
/// (identical variants; `Banned` makes the peer ineligible until re-added, SPEC §9.4).
pub(crate) fn pool_removal_reason(reason: GossipRemovalReason) -> PoolRemovalReason {
    match reason {
        GossipRemovalReason::Disconnected => PoolRemovalReason::Disconnected,
        GossipRemovalReason::Dead => PoolRemovalReason::Dead,
        GossipRemovalReason::Banned => PoolRemovalReason::Banned,
    }
}

/// The kind of a pool churn event, extracted from `dig_gossip::PoolEvent` at the call site so this
/// module does not depend on dig-gossip's concrete type. The caller (`crate::peer`) destructures the
/// gossip event into this + the raw 32-byte peer id, keeping the 1:1 map explicit and testable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolEventKind {
    /// A peer joined the connected pool at `addr`.
    Added {
        /// The remote endpoint the connection runs over.
        addr: std::net::SocketAddr,
    },
    /// A peer left the connected pool for `reason`.
    Removed {
        /// Why it left.
        reason: GossipRemovalReason,
    },
}

/// A local, dig-gossip-free mirror of `dig_gossip::PoolRemovalReason` so the 1:1 map
/// ([`pool_removal_reason`]) is expressed + tested WITHOUT this module importing dig-gossip. The
/// caller in `crate::peer` (which DOES have the gossip type in scope) converts the real
/// `dig_gossip::PoolRemovalReason` into this at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GossipRemovalReason {
    /// A normal disconnect.
    Disconnected,
    /// Evicted dead / unresponsive.
    Dead,
    /// Banned for misbehaviour.
    Banned,
}

/// The [`ProviderLocator`] seam that makes the selector DRIVE dig-download's source choice (SPEC
/// §6.1). dig-download picks sources from whatever its injected locator returns; this wrapper
/// intercepts each `find_providers` call, runs the DHT-located providers through the shared
/// [`PeerSelector`], and returns them **filtered to the ranked subset and ordered best-first** — so
/// the executor fans byte-ranges across the peers the selector chose, not a blind least-loaded pick.
///
/// The FIRST `find_providers` for a content uses `select` (the initial ranking); a SUBSEQUENT call
/// (dig-download's relocate, fired when live sources run low — its `ProvidersRefreshed`) uses
/// `rebalance`, which re-queries the up-to-the-moment models (reflecting every `record_outcome`
/// streamed back so far) and de-ranks the peers already active, so the selector DRIVES the
/// replacement-source choice too (SPEC §5.5). Peers the selector omits (a low-quality / bad tail) are
/// dropped from the set the executor sees.
///
/// When the DHT locate returns no providers, or the selector chooses none, the raw located set is
/// passed through unchanged (never fewer than what discovery found when the selector abstains), so the
/// selector can only REFINE the executor's source set, never starve a fetch that has holders.
pub(crate) struct SelectorLocator {
    /// The real discovery locator (the DHT in production, a mock in tests).
    inner: Arc<dyn ProviderLocator>,
    /// The shared selector — the same instance fed by pool churn + `record_outcome`.
    selector: Arc<PeerSelector>,
    /// Per-content call state: has this content been `select`ed yet? Drives select-vs-rebalance and
    /// tracks the active (already-selected) peers a rebalance must de-rank. Keyed by content DHT key.
    state: Mutex<HashMap<String, Vec<PeerId>>>,
}

impl SelectorLocator {
    /// Wrap the real locator + the shared selector.
    pub(crate) fn new(inner: Arc<dyn ProviderLocator>, selector: Arc<PeerSelector>) -> Arc<Self> {
        Arc::new(SelectorLocator {
            inner,
            selector,
            state: Mutex::new(HashMap::new()),
        })
    }

    /// Order + filter `located` providers by the selector's decision for `content`. Pure over the
    /// selector's current models (no I/O) so the select→order transformation is unit-tested directly.
    /// Returns the located records reordered best-first and filtered to the selected subset; if the
    /// selector returns an empty selection (e.g. abstains), the raw located set is returned unchanged.
    fn rank(&self, content: &ContentId, located: Vec<ProviderRecord>) -> Vec<ProviderRecord> {
        if located.is_empty() {
            return located;
        }
        let key = download_key(content);
        // Map located providers → selector candidates (a record whose peer_id is malformed hex is not
        // addressable; it is dropped from the candidate set but kept as a raw fallback below).
        let candidates: Vec<Candidate> = located
            .iter()
            .filter_map(Candidate::from_provider_record)
            .collect();

        // Decide select (first call for this content) vs rebalance (a relocate re-query).
        let mut state = self.state.lock().expect("selector-locator mutex poisoned");
        let first_time = !state.contains_key(&key);
        let selection = if first_time {
            let req = ContentRequest::new(*content, SELECT_PARALLELISM);
            self.selector.select(&req, &candidates)
        } else {
            // A relocate: rebalance over the still-needed ranges, de-ranking the peers already active.
            let active = state.get(&key).cloned().unwrap_or_default();
            let req = ContentRequest::new(*content, SELECT_PARALLELISM);
            let need = RangePlanDelta::of_count(SELECT_PARALLELISM);
            self.selector.rebalance(&req, &active, &need)
        };

        if selection.is_empty() {
            // The selector abstained (all candidates ineligible / none worth using). Record the raw
            // located peers as active (so a later rebalance de-ranks them) and pass discovery through.
            state.insert(
                key,
                candidates.iter().map(|c| c.peer_id).collect::<Vec<_>>(),
            );
            return located;
        }

        // Record the selected peers as active for this content (a later rebalance de-ranks them).
        state.insert(key, selection.peers.iter().map(|p| p.peer_id).collect());

        // Reorder `located` best-first, keeping only records whose peer_id the selector chose. A
        // located record with the same peer_id keeps its addresses (the selector carries none of its
        // own transport detail — it only decides identity + order).
        let mut ordered = Vec::with_capacity(selection.peers.len());
        for sp in &selection.peers {
            let hex = sp.peer_id.to_hex();
            if let Some(rec) = located.iter().find(|r| r.provider_peer_id == hex) {
                ordered.push(rec.clone());
            }
        }
        // A selected peer with no matching located record (should not happen — candidates come FROM
        // `located`) is simply skipped; if that emptied the set, fall back to the raw located set so a
        // fetch with holders is never starved by a ranking edge case.
        if ordered.is_empty() {
            located
        } else {
            ordered
        }
    }
}

#[async_trait]
impl ProviderLocator for SelectorLocator {
    async fn find_providers(
        &self,
        content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let located = self.inner.find_providers(content).await?;
        Ok(self.rank(content, located))
    }
}

// -- Selector-driven DIAL ordering (#384) ------------------------------------------------------------

/// A [`DialRanker`](crate::pex::DialRanker) over the shared [`PeerSelector`] — so the SAME learned
/// peer-quality model that ranks download SOURCES also drives which PEX candidates the node DIALS
/// first (#384). Reuses the one `PeerSelector` instance in [`NodeContent`]; a second is never spun up.
///
/// The dial score is CONTENT-AGNOSTIC (dialing is not per-content), read from the selector's per-peer
/// [`peer_snapshot`](PeerSelector::peer_snapshot): a banned peer sinks to the bottom; a measured peer
/// scores by reliability (primary) blended with normalized throughput (secondary); a cold peer (no
/// measured outcomes yet) returns `None` so the dialer explores it at a neutral rank (SPEC §5.2 — in
/// PRIVACY mode the selector does not apply; the onion path uses its own selector, so this ranker is
/// simply not wired there).
pub struct SelectorDialRanker {
    selector: Arc<PeerSelector>,
}

impl SelectorDialRanker {
    /// Wrap the shared selector as a dial ranker.
    #[must_use]
    pub fn new(selector: Arc<PeerSelector>) -> Self {
        SelectorDialRanker { selector }
    }
}

impl crate::pex::DialRanker for SelectorDialRanker {
    fn score(&self, peer_id_hex: &str) -> Option<f64> {
        // 64-hex → the selector's 32-byte PeerId (SHA-256(SPKI DER), same identity as dig-nat/gossip).
        let bytes = hex::decode(peer_id_hex).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        let snapshot = self.selector.peer_snapshot(&PeerId::from_bytes(arr))?;
        if snapshot.banned {
            // Proven-bad: dial only after every neutral/good peer.
            return Some(f64::MIN);
        }
        if snapshot.samples == 0 {
            // Cold peer — no measured model yet; let the dialer explore it at the neutral rank.
            return None;
        }
        let reliability = snapshot.reliability.unwrap_or(0.0);
        // Normalize throughput to [0,1] with a ~1 MB/s midpoint (bps / (bps + 1e6)); missing → 0.
        let throughput = snapshot.throughput_bps.unwrap_or(0.0);
        let throughput_norm = (throughput / (throughput + 1_000_000.0)).clamp(0.0, 1.0);
        Some(reliability * 0.8 + throughput_norm * 0.2)
    }
}

/// Current unix seconds (the `at` timestamp on a [`TransferOutcome`]).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Map a `dig-download` `RangeFailed.reason` (stable text) to a selector [`FailureReason`] (SPEC §6.2,
/// §6.3). A verify/integrity/merkle/decrypt reason is a HARD [`FailureReason::VerificationFailed`] (a
/// bad/hostile source the selector drives below cold peers); a timeout/unavailable maps to its own
/// class; everything else is a soft transport failure. Pure so the mapping is unit-tested.
pub(crate) fn failure_reason_of(reason: &str) -> FailureReason {
    let r = reason.to_ascii_lowercase();
    if r.contains("verif")
        || r.contains("integrity")
        || r.contains("merkle")
        || r.contains("decrypt")
    {
        FailureReason::VerificationFailed
    } else if r.contains("timeout") || r.contains("timed out") {
        FailureReason::Timeout
    } else if r.contains("unavailable") || r.contains("not found") || r.contains("no provider") {
        FailureReason::Unavailable
    } else if r.contains("cancel") {
        FailureReason::Cancelled
    } else {
        FailureReason::Transport
    }
}

/// Build a `Range`-granularity [`TransferOutcome`] for `provider` (a 64-hex `peer_id`), or `None` if
/// the provider hex is malformed (then no outcome is recorded — the selector attributes only to
/// transport-verified identities, SPEC §9.1). `bytes`/`duration_ms` are the executor's MEASURED
/// values; the selector derives throughput strictly from them (SPEC §9.3).
fn range_outcome(
    content: &ContentId,
    provider: &str,
    range: usize,
    bytes: u64,
    duration_ms: u64,
    result: OutcomeResult,
) -> Option<TransferOutcome> {
    let peer_id = PeerId::from_hex(provider)?;
    Some(TransferOutcome {
        peer_id,
        content: *content,
        kind: OutcomeKind::Range {
            index: range,
            // The selector needs range identity (index) to attribute the outcome; the exact offset/
            // length is not carried on the dig-download event, so it is left 0 (index is the key —
            // SPEC §6.5). `bytes` is what actually transferred (the measured throughput input).
            offset: 0,
            length: bytes,
        },
        result,
        bytes,
        duration_ms,
        rtt_ms: None,
        at: now_unix(),
    })
}

// -- The node's P2P content engine ------------------------------------------------------------------

/// The standalone node's P2P content engine: the dig-download [`Downloader`] wired from the node's
/// live pieces (the #164 fetch path) plus the provider lookup the redirect-on-miss handler uses
/// (#165). Constructed by the peer-network bring-up and attached to the node
/// ([`crate::Node::set_p2p_content`]); absent in the FFI path, where every miss behaves exactly as
/// before.
pub struct NodeContent {
    /// "Which peers hold this content?" — the DHT in production, a mock in tests. This is the RAW
    /// discovery locator (unfiltered): the redirect-on-miss path names EVERY holder here, not the
    /// selector's ranked subset (a redirect should offer the caller all known holders).
    locator: Arc<dyn ProviderLocator>,
    /// The self-optimizing peer selector (#178) — the decision + learning brain between discovery and
    /// download. It ranks the located providers (driving the [`Downloader`]'s source choice via
    /// [`SelectorLocator`]) and learns from every range outcome streamed back in [`Self::fetch_resource`].
    /// Fed the pool churn + connection classes by the node ([`Self::on_pool_event`],
    /// [`Self::on_connection_class`]).
    selector: Arc<PeerSelector>,
    /// The multi-source download engine (locate → confirm → fan out → verify → reassemble). Its
    /// injected locator is a [`SelectorLocator`] wrapping `locator` + `selector`, so the executor fans
    /// ranges across the selector's ranked subset instead of picking sources blindly.
    downloader: Downloader,
    /// The resume-state store the downloader checkpoints into, wrapped so the last-known commitment
    /// (chunk layout + root + proof) is captured BEFORE the download clears it on completion — a
    /// fetch-through serve reads it back to shape verifiable `dig.fetchRange`/`dig.getContent`.
    state_store: Arc<CapturingStateStore>,
    /// Where downloads stage (`<cache>/downloads`): `.download.tmp` files + resume state.
    downloads_dir: PathBuf,
    /// Redirect (default) or fetch-through on a content miss.
    miss_mode: MissMode,
    /// This node's own `peer_id` (64-hex), excluded from redirect targets (never redirect a caller
    /// back to the node that just missed).
    self_peer_id: Option<String>,
    /// Recently fetched-through resources, re-served without re-downloading (windows/frames of the
    /// same resource). Bounded at [`FETCHED_CACHE_CAP`].
    fetched: tokio::sync::Mutex<HashMap<String, Arc<FetchedResource>>>,
    /// Serializes fetch-through downloads (one at a time keeps the staging/state simple; the
    /// download itself is internally multi-source concurrent).
    fetch_lock: tokio::sync::Mutex<()>,
}

/// A [`StateStore`] wrapper over a [`FileStateStore`] that SNAPSHOTS every saved [`DownloadState`]
/// in memory (keyed by download key) before delegating. dig-download clears a download's checkpoint
/// on successful completion, so the resource commitment (`total_length`/`chunk_lens`/`root`/
/// `inclusion_proof`) would be gone by the time [`NodeContent::fetch_resource`] wants to serve the
/// fetched bytes. This captures the LAST commitment-bearing state so the fetch-through serve can shape
/// verifiable frames without a second network probe. Persistence + resume are unchanged (all calls
/// delegate to the inner file store).
struct CapturingStateStore {
    inner: FileStateStore,
    /// The last saved state per download key (holds the commitment: chunk_lens/root/proof).
    last: tokio::sync::Mutex<HashMap<String, dig_download::DownloadState>>,
}

impl CapturingStateStore {
    fn new(inner: FileStateStore) -> Self {
        CapturingStateStore {
            inner,
            last: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The last-captured commitment-bearing state for `key`, if a download established one.
    async fn captured(&self, key: &str) -> Option<dig_download::DownloadState> {
        self.last.lock().await.get(key).cloned()
    }
}

#[async_trait::async_trait]
impl StateStore for CapturingStateStore {
    async fn load(
        &self,
        key: &str,
    ) -> Result<Option<dig_download::DownloadState>, dig_download::DownloadError> {
        self.inner.load(key).await
    }

    async fn save(
        &self,
        state: &dig_download::DownloadState,
    ) -> Result<(), dig_download::DownloadError> {
        // Snapshot only commitment-bearing states (chunk layout established) so we retain the shape a
        // fetch-through serve needs even after the checkpoint is cleared on completion.
        if !state.chunk_lens.is_empty() {
            self.last
                .lock()
                .await
                .insert(state.key.clone(), state.clone());
        }
        self.inner.save(state).await
    }

    async fn clear(&self, key: &str) -> Result<(), dig_download::DownloadError> {
        // Keep the captured commitment (do NOT drop it on clear) — clear only the on-disk checkpoint.
        self.inner.clear(key).await
    }
}

impl NodeContent {
    /// Build the engine from injected locate + transport seams (the constructor tests use with the
    /// dig-download [`testkit`](dig_download::testkit) mocks; production goes through
    /// [`Self::for_dht`]). Wires the [`Downloader`] per dig-download's implementers' note:
    /// digstore-bound [`MerkleVerifier`], [`FileStateStore`] under `<cache_dir>/downloads`.
    pub fn new(
        locator: Arc<dyn ProviderLocator>,
        transport: Arc<dyn RangeTransport>,
        miss_mode: MissMode,
        self_peer_id: Option<String>,
        cache_dir: &Path,
    ) -> Arc<Self> {
        let downloads_dir = cache_dir.join("downloads");
        let _ = std::fs::create_dir_all(&downloads_dir);
        let state_store = Arc::new(CapturingStateStore::new(FileStateStore::new(
            downloads_dir.join("state"),
        )));
        let verifier = Arc::new(MerkleVerifier::with_proof_verifier(Arc::new(
            DigstoreProofVerifier,
        )));
        // One selector per engine, wiring-only config (no behavior knobs — every tradeoff is learned).
        // Deterministic across runs so a node's ranking is reproducible for a given outcome stream.
        let selector = Arc::new(PeerSelector::new(SelectorConfig::default()));
        // The Downloader's locator is the selector-driven wrapper: each `find_providers` (initial +
        // relocate) is ranked/filtered by the selector, so the executor fans ranges across the chosen
        // subset (SPEC §6.1). The RAW `locator` stays on the engine for the redirect-on-miss path.
        let select_locator = SelectorLocator::new(locator.clone(), selector.clone());
        let downloader = Downloader::new(
            select_locator,
            transport,
            verifier,
            state_store.clone(),
            DownloadConfig::default(),
        );
        Arc::new(NodeContent {
            locator,
            selector,
            downloader,
            state_store,
            downloads_dir,
            miss_mode,
            self_peer_id,
            fetched: tokio::sync::Mutex::new(HashMap::new()),
            fetch_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// The PRODUCTION constructor — wire the engine from the live DHT + the node's mTLS identity,
    /// exactly as dig-download's implementers' note prescribes: [`DhtProviderLocator`] over the
    /// bootstrapped [`DhtService`](dig_dht::DhtService), [`NatRangeTransport`] dialing providers
    /// over the FULL NAT traversal ladder (Direct → UPnP → NAT-PMP → PCP → hole-punch → Relayed) the
    /// rest of the peer network now uses, so a range fetch reaches a NAT'd provider directly whenever
    /// possible and relays only as the last resort (#385). `stun_server` (when `Some`) feeds the
    /// hole-punch tier's reflexive-address discovery.
    pub fn for_dht(
        dht: Arc<dig_dht::DhtService>,
        node: Arc<dig_nat::NodeCert>,
        network_id: &str,
        miss_mode: MissMode,
        self_peer_id: Option<String>,
        cache_dir: &Path,
        stun_server: Option<std::net::SocketAddr>,
    ) -> Arc<Self> {
        let locator = Arc::new(DhtProviderLocator::new(dht));
        let nat_config =
            crate::net::full_nat_config(crate::dht::default_rpc_timeout(), stun_server);
        let transport = Arc::new(NatRangeTransport::new(node, nat_config, network_id));
        Self::new(locator, transport, miss_mode, self_peer_id, cache_dir)
    }

    /// The configured miss behavior (redirect by default; fetch-through when opted in).
    pub fn miss_mode(&self) -> MissMode {
        self.miss_mode
    }

    /// The staging directory downloads run in (`<cache>/downloads`).
    pub fn downloads_dir(&self) -> &Path {
        &self.downloads_dir
    }

    /// The active-download registry protecting live/paused staging files from GC (exposed so the
    /// GC tests — and any embedder-managed sweep — share the downloader's own registry).
    pub fn active_downloads(&self) -> Arc<dig_download::ActiveDownloads> {
        self.downloader.active_downloads()
    }

    /// The shared peer selector (for the registry-feed hooks + observability). Exposed so the
    /// standalone peer-network bring-up can forward pool churn + connection classes into it.
    pub fn selector(&self) -> &Arc<PeerSelector> {
        &self.selector
    }

    /// Feed one pool churn event into the selector's registry (SPEC §2.3, §5.4). The caller
    /// (`crate::peer`) maps the live `dig_gossip::PoolEvent` into the selector's local [`PoolEvent`]
    /// via [`pool_event_to_selector`] before calling this — the shapes are byte-identical, so the map
    /// is 1:1. A `PeerAdded` upserts (provenance Gossip, preserving learned quality); a `PeerRemoved`
    /// marks disconnected (retaining history) or, for `Banned`, ineligible until re-added.
    pub fn on_pool_event(&self, event: &PoolEvent) {
        self.selector.on_pool_event(event);
    }

    /// Feed a `dig-nat` connection class for a peer into the selector (SPEC §5.4, §7.3), seeding its
    /// per-class saturation prior + the relayed-penalty prior. Observational only — subordinate to the
    /// peer's measured outcomes.
    pub fn on_connection_class(&self, peer: &PeerId, class: TraversalKind) {
        self.selector.on_connection_class(peer, class);
    }

    /// Locate the peers holding `content` via the DHT (best-effort: a locate failure is an empty
    /// set), excluding this node itself — a redirect must never point the caller back at the node
    /// that just missed.
    pub async fn find_providers(&self, content: &ContentId) -> Vec<ProviderRecord> {
        let found = self
            .locator
            .find_providers(content)
            .await
            .unwrap_or_default();
        match &self.self_peer_id {
            Some(me) => found
                .into_iter()
                .filter(|p| &p.provider_peer_id != me)
                .collect(),
            None => found,
        }
    }

    /// The #164 content-acquisition path: multi-source download `content` (locate → confirm → fan
    /// ranges across providers → verify per range + whole-resource against the chain-anchored root
    /// → reassemble), returning the verified resource ready to serve. Recently fetched resources
    /// are served from the bounded in-memory cache without re-downloading.
    pub async fn fetch_resource(
        &self,
        content: &ContentId,
    ) -> Result<Arc<FetchedResource>, String> {
        let key = download_key(content);

        // 1. Serve from the bounded in-memory cache if we recently fetched this resource.
        if let Some(hit) = self.fetched.lock().await.get(&key).cloned() {
            return Ok(hit);
        }

        // 2. Serialize downloads (one at a time keeps the staging/state simple). Re-check the cache
        //    under the lock in case a concurrent caller just finished the same fetch.
        let _serial = self.fetch_lock.lock().await;
        if let Some(hit) = self.fetched.lock().await.get(&key).cloned() {
            return Ok(hit);
        }

        // 3. Stage into a per-download final path under `<downloads>` (the FileSink writes
        //    `<final>.download.tmp` then atomically renames onto `<final>` on finalize).
        let final_path = self.downloads_dir.join(format!("{key}.bin"));
        let _ = std::fs::remove_file(&final_path); // a stale prior artifact must not shadow this fetch
        let sink: Arc<dyn dig_download::Sink> = Arc::new(FileSink::new(final_path.clone()));

        // 4. Run the multi-source download to completion (locate → confirm → fan ranges → verify per
        //    range + whole-resource against the chain-anchored root → reassemble → finalize),
        //    STREAMING every range outcome back into the selector in real time so the models learn and
        //    the next select()/rebalance() is smarter (#178, SPEC §6.2).
        let handle = self
            .downloader
            .download(*content, sink, DownloadOptions::default());
        self.drive_download(content, handle)
            .await
            .map_err(|e| format!("download failed: {e}"))?;

        // 5. Read the verified, reassembled bytes back off the finalized staging file …
        let bytes =
            std::fs::read(&final_path).map_err(|e| format!("read finalized download: {e}"))?;
        // … and the commitment (chunk_lens/root/inclusion_proof) captured before the checkpoint was
        //    cleared, so the fetch-through serve can shape frames the caller verifies against the root.
        let commitment = self
            .state_store
            .captured(&key)
            .await
            .ok_or_else(|| "download completed without a captured commitment".to_string())?;

        let fetched = Arc::new(FetchedResource {
            total_length: commitment.total_length.max(bytes.len() as u64),
            chunk_lens: commitment.chunk_lens.clone(),
            root: commitment.root.clone(),
            inclusion_proof: commitment.inclusion_proof.clone(),
            bytes,
        });

        // 6. Insert into the bounded cache (evict an arbitrary old entry when at cap — a miss just
        //    re-fetches, never corrupts) and clean up the on-disk staging artifact (it lives in the
        //    in-memory cache now; the durable copy is the module cache, populated elsewhere).
        {
            let mut cache = self.fetched.lock().await;
            if cache.len() >= FETCHED_CACHE_CAP {
                if let Some(k) = cache.keys().next().cloned() {
                    cache.remove(&k);
                }
            }
            cache.insert(key, fetched.clone());
        }
        let _ = std::fs::remove_file(&final_path);

        Ok(fetched)
    }

    /// Drive a running download's [`DownloadEvent`] stream, translating each event into a selector
    /// [`TransferOutcome`] (or a `rebalance`) IN REAL TIME (SPEC §6.2), then await the terminal result.
    ///
    /// This is the node-side adapter that closes the `select → execute → record_outcome → rebalance`
    /// loop (the selector crate defines no `dig-download` dependency, so the mapping lives here):
    /// - `RangeCompleted { range, provider, progress }` → a `Range` `Success` outcome. The MEASURED
    ///   `bytes` are the resource-byte delta since this provider's previous event, and `duration_ms` is
    ///   the wall-clock since then — the throughput the executor actually observed on the wire (never a
    ///   self-reported rate, SPEC §9.3).
    /// - `RangeFailed { range, provider, reason }` → a `Failure` outcome; a verify/integrity reason maps
    ///   to [`FailureReason::VerificationFailed`] (a HARD signal, SPEC §6.3), everything else to a soft
    ///   transport/timeout failure the selector re-routes around.
    /// - `ProvidersRefreshed` → the executor is relocating (its live sources ran low); the next
    ///   `find_providers` through the [`SelectorLocator`] is a `rebalance` — the selector DRIVES the
    ///   replacement-source choice (SPEC §5.5). (No quality change here; that comes from the per-range
    ///   failures already recorded.)
    /// - `Paused` is NOT a failure — no outcome is recorded (SPEC §6.4).
    /// - `Completed { total_length }` → an aggregate `Request` outcome for whole-request (P99) learning
    ///   (SPEC §4.4-C), attributed to the last provider that served a range.
    async fn drive_download(
        &self,
        content: &ContentId,
        mut handle: dig_download::DownloadHandle,
    ) -> Result<u64, DownloadError> {
        // Per-provider clock for deriving MEASURED per-range throughput from the cumulative progress
        // stream: bytes = Δ(progress.bytes_done) since this provider's previous event; duration =
        // wall-clock since then. Falls back to the download start for a provider's first completion.
        let start = Instant::now();
        let mut last_event_at: HashMap<String, Instant> = HashMap::new();
        let mut last_bytes_done: u64 = 0;
        let mut last_provider: Option<String> = None;

        // Consume the event stream to exhaustion (it closes when the task ends), feeding the selector.
        while let Some(event) = handle.next_event().await {
            match event {
                DownloadEvent::RangeCompleted {
                    range,
                    provider,
                    progress,
                } => {
                    let bytes = progress.bytes_done.saturating_sub(last_bytes_done);
                    last_bytes_done = progress.bytes_done;
                    let since = last_event_at.get(&provider).copied().unwrap_or(start);
                    let duration_ms = since.elapsed().as_millis() as u64;
                    last_event_at.insert(provider.clone(), Instant::now());
                    last_provider = Some(provider.clone());
                    if let Some(outcome) = range_outcome(
                        content,
                        &provider,
                        range,
                        bytes,
                        duration_ms,
                        OutcomeResult::Success,
                    ) {
                        self.selector.record_outcome(&outcome);
                    }
                }
                DownloadEvent::RangeFailed {
                    range,
                    provider,
                    reason,
                } => {
                    let since = last_event_at.get(&provider).copied().unwrap_or(start);
                    let duration_ms = since.elapsed().as_millis() as u64;
                    last_event_at.insert(provider.clone(), Instant::now());
                    let result = OutcomeResult::Failure {
                        reason: failure_reason_of(&reason),
                    };
                    if let Some(outcome) =
                        range_outcome(content, &provider, range, 0, duration_ms, result)
                    {
                        self.selector.record_outcome(&outcome);
                    }
                }
                DownloadEvent::Completed { total_length } => {
                    // Aggregate whole-request outcome for P99 learning (attributed to the last server).
                    if let Some(provider) = last_provider.clone() {
                        if let Some(peer_id) = PeerId::from_hex(&provider) {
                            let outcome = TransferOutcome {
                                peer_id,
                                content: *content,
                                kind: OutcomeKind::Request { total_length },
                                result: OutcomeResult::Success,
                                bytes: total_length,
                                duration_ms: start.elapsed().as_millis() as u64,
                                rtt_ms: None,
                                at: now_unix(),
                            };
                            self.selector.record_outcome(&outcome);
                        }
                    }
                }
                // ProvidersRefreshed → the executor relocated; the next SelectorLocator::find_providers
                // is a rebalance (that is where the selector drives the replacement choice). Paused/
                // Resumed/Planned/Failed carry no per-range quality signal beyond what is recorded above.
                _ => {}
            }
        }

        handle.join().await
    }

    /// One staging-file GC sweep now: reap `.download.tmp` files older than `ttl` that no
    /// live/paused download owns (their sidecar resume state goes with them). Returns how many
    /// were removed.
    pub async fn gc_once(&self, ttl: Duration) -> usize {
        self.downloader
            .gc(self.downloads_dir.clone(), ttl)
            .await
            .unwrap_or(0)
    }

    /// Run the staging GC on startup and then on an interval (mirroring the DHT gc/republish
    /// loop), with the default [`GcConfig`] cadence (1 h staleness TTL, 10 min sweeps). Never
    /// returns on its own — spawned as a background task for the life of the node.
    pub fn spawn_gc(self: &Arc<Self>) {
        let this = self.clone();
        let cfg = GcConfig::new(this.downloads_dir.clone());
        tokio::spawn(async move {
            let reaped = this.gc_once(cfg.ttl).await;
            tracing::debug!(reaped, "dig-node download GC startup sweep");
            let mut ticker = tokio::time::interval(cfg.interval);
            ticker.tick().await; // consume the immediate tick (the startup sweep just ran)
            loop {
                ticker.tick().await;
                let reaped = this.gc_once(cfg.ttl).await;
                tracing::debug!(reaped, "dig-node download GC sweep");
            }
        });
    }
}

// -- The miss handler (#165) -------------------------------------------------------------------------

/// What the node does about a content miss, decided by [`crate::Node::miss_outcome`].
pub(crate) enum MissOutcome {
    /// Fetch-through succeeded: serve this verified resource directly.
    Fetched(Arc<FetchedResource>),
    /// Providers exist: redirect the caller to them (the `next_depth` is served back so the caller
    /// echoes it on the re-request, keeping the hop budget monotone).
    Redirect {
        /// The located holders (self excluded).
        providers: Vec<ProviderRecord>,
        /// The redirect depth the caller carries forward (incoming depth + 1).
        next_depth: u64,
    },
    /// No engine / no providers / hop budget exhausted: the caller's own not-found stands.
    NotFound,
}

impl crate::Node {
    /// Attach the P2P content engine (the standalone peer-network bring-up calls this once; the
    /// FFI path never does). Idempotent — a second set is ignored.
    pub(crate) fn set_p2p_content(&self, content: Arc<NodeContent>) {
        let _ = self.p2p_content.set(content);
    }

    /// The attached P2P content engine, if the peer network brought one up.
    pub(crate) fn p2p_content(&self) -> Option<&Arc<NodeContent>> {
        self.p2p_content.get()
    }

    /// Background CAPSULE BACKFILL (SPEC §5.6): when a resource read for `(store_hex, root_hex)` is
    /// being satisfied FROM ANOTHER NODE (a redirect or a fetch-through miss), also pull the WHOLE
    /// `.dig` capsule for that generation in the background and cache it, so the NEXT read of this
    /// store is served locally. Configurable (`DIG_NODE_BACKFILL_ON_MISS`, default ON).
    ///
    /// Fire-and-forget: it spawns a detached task and returns immediately so the current read is never
    /// delayed. It is a NO-OP when: backfill is disabled; there is no P2P content engine (the
    /// in-process FFI consumer — it has no upstream/peer network to pull a whole capsule from); the
    /// capsule is already held locally; or a backfill for this exact capsule is already in flight
    /// (deduped via [`Node::backfilling`], so a burst of resource reads for the same not-yet-held store
    /// triggers ONE whole-`.dig` pull, not one per read). The pull reuses
    /// [`gap_fill_generation`](crate::Node::gap_fill_generation) — the authenticated §21 whole-store
    /// sync, chain-anchored-root pinned + DHT-announced — so a backfilled capsule is verified exactly
    /// like every other cached generation.
    pub(crate) fn maybe_backfill_capsule(&self, store_hex: &str, root_hex: &str) {
        // Config gate (default on) + only where a peer network / upstream exists to pull from.
        if !backfill_on_miss_enabled() || self.p2p_content().is_none() {
            return;
        }
        // Need an owned `Arc<Node>` to spawn the detached pull. Installed by the standalone
        // peer-network bring-up; `None` on the FFI path (which also has no p2p_content, so we already
        // returned above) or during teardown.
        let Some(node) = self.arc_self() else {
            return;
        };
        // Need a concrete, valid (store, root). `hex64` validates AND decodes; a rootless/`"latest"`
        // read (no concrete capsule) or a malformed value yields `None` and is skipped — the read
        // path resolves the tip separately.
        let (Some(store_id), Some(root_bytes)) =
            (crate::dht::hex64(store_hex), crate::dht::hex64(root_hex))
        else {
            return;
        };
        // Already held → nothing to warm up.
        if crate::module_exists(self.cache_dir_path(), store_hex, root_hex) {
            return;
        }
        let key = format!("{store_hex}:{root_hex}");
        // Dedup: claim the in-flight slot; if another read already claimed it, do nothing (a burst of
        // resource reads for the same not-yet-held store triggers ONE whole-capsule pull).
        {
            let mut inflight = self.backfilling.lock().unwrap_or_else(|p| p.into_inner());
            if !inflight.insert(key.clone()) {
                return; // a backfill for this capsule is already running
            }
        }
        let root = crate::Bytes32(root_bytes);
        tokio::spawn(async move {
            match node.gap_fill_generation(store_id, root).await {
                Ok(()) => tracing::debug!(
                    capsule = %key,
                    "backfill: cached the whole capsule after a resource read from another node"
                ),
                Err(e) => tracing::debug!(
                    capsule = %key,
                    error = %e,
                    "backfill: whole-capsule pull did not complete (will re-attempt on the next miss)"
                ),
            }
            // Release the in-flight slot so a later miss can re-attempt if this one failed.
            node.backfilling
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&key);
        });
    }

    /// Decide the #165 miss outcome for `content` at redirect depth `depth`: fetch-through when
    /// configured (falling back to redirect if the fetch fails), else locate + redirect within the
    /// hop budget, else not-found. NEVER a silent 404 while a provider exists.
    pub(crate) async fn miss_outcome(&self, content: &ContentId, depth: u64) -> MissOutcome {
        // No P2P content engine (the in-process FFI path) → the caller's own not-found stands.
        let Some(pc) = self.p2p_content() else {
            return MissOutcome::NotFound;
        };

        // Fetch-through (opt-in): pull the resource from the holders via dig-download, serve it
        // directly. On any failure, fall through to the redirect so a provider-held resource is never
        // silently 404'd.
        if pc.miss_mode() == MissMode::FetchThrough {
            if let Ok(fetched) = pc.fetch_resource(content).await {
                return MissOutcome::Fetched(fetched);
            }
        }

        // Redirect (default): locate the holders and name them so the caller re-requests there.
        // BOUND the hops — a request already redirected [`REDIRECT_HOP_CAP`] times is answered with
        // the plain not-found instead of another redirect, so nodes can never bounce a caller in a
        // loop. (The check is here, not on the providers, so an exhausted budget short-circuits the
        // DHT lookup too.)
        if depth >= REDIRECT_HOP_CAP {
            return MissOutcome::NotFound;
        }
        let providers = pc.find_providers(content).await;
        if providers.is_empty() {
            // No provider anywhere → a genuine not-found (the caller's -32004 stands).
            return MissOutcome::NotFound;
        }
        MissOutcome::Redirect {
            providers,
            next_depth: depth + 1,
        }
    }

    /// Shape the miss outcome for a `dig.fetchRange` JSON-RPC call: `Some(envelope)` when the P2P
    /// layer can answer (a fetched frame or a redirect), `None` to fall back to the caller's own
    /// not-found.
    pub(crate) async fn range_miss_envelope(
        &self,
        id: &Value,
        content: &ContentId,
        depth: u64,
        offset: usize,
        length: usize,
    ) -> Option<Value> {
        match self.miss_outcome(content, depth).await {
            MissOutcome::Fetched(f) => Some(match f.range_frame(offset, length) {
                Ok(frame) => json!({"jsonrpc":"2.0","id":id,"result":frame}),
                Err((code, message)) => crate::rpc_err(id, code, &message),
            }),
            MissOutcome::Redirect {
                providers,
                next_depth,
            } => Some(json!({"jsonrpc":"2.0","id":id,
                "error": redirect_error_object(content, &providers, next_depth)})),
            MissOutcome::NotFound => None,
        }
    }

    /// Shape the miss outcome for a `dig.getContent` call: `Some(envelope)` when the P2P layer can
    /// answer, `None` to fall back to the caller's own response. A fetched-through resource is
    /// served ONLY when its committed root matches the pinned chain-anchored root (`pinned_root_hex`
    /// — #127: peers are never the root authority); on a mismatch the fallback stands.
    pub(crate) async fn content_miss_envelope(
        &self,
        id: &Value,
        content: &ContentId,
        depth: u64,
        offset: usize,
        pinned_root_hex: Option<&str>,
    ) -> Option<Value> {
        match self.miss_outcome(content, depth).await {
            MissOutcome::Fetched(f) => {
                let root_ok = match pinned_root_hex {
                    Some(pin) => f.root.as_deref() == Some(pin),
                    None => true,
                };
                if !root_ok {
                    return None;
                }
                let mut result = f.content_result(offset);
                // Fetched from the network (peers), not this device's cache — tag honestly.
                if let Some(obj) = result.as_object_mut() {
                    obj.insert("source".into(), json!("remote"));
                }
                Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
            }
            MissOutcome::Redirect {
                providers,
                next_depth,
            } => Some(json!({"jsonrpc":"2.0","id":id,
                "error": redirect_error_object(content, &providers, next_depth)})),
            MissOutcome::NotFound => None,
        }
    }
}

// -- Redirect shaping (pure) --------------------------------------------------------------------------

/// The redirect depth a request has already consumed: `params.redirect_depth` (default 0). The
/// caller echoes the depth a redirect served it, so the budget is monotone across hops.
pub(crate) fn redirect_depth(params: &Value) -> u64 {
    params
        .get("redirect_depth")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Build the [`CONTENT_REDIRECT`] JSON-RPC error OBJECT (the `error` member): the catalogued code,
/// a human message, and `data.redirect` naming the content, the located providers (peer_id +
/// candidate addresses, byte-compatible with `dig.getPeers`/DHT shapes), the `redirect_depth` the
/// caller must echo on the re-request, and the hop cap. Pure so the wire shape is unit-tested.
pub(crate) fn redirect_error_object(
    content: &ContentId,
    providers: &[ProviderRecord],
    next_depth: u64,
) -> Value {
    json!({
        "code": CONTENT_REDIRECT,
        "message": "content not held by this node; re-request against a provider in data.redirect",
        "data": { "redirect": {
            "content": content_id_json(content),
            "providers": providers.iter().map(provider_json).collect::<Vec<Value>>(),
            "redirect_depth": next_depth,
            "max_redirects": REDIRECT_HOP_CAP,
        }}
    })
}

/// One redirect provider entry: the holder's `peer_id` + its candidate addresses (the dig-dht
/// `{host, port, kind}` shape, byte-compatible with `dig.getPeers` addresses).
fn provider_json(p: &ProviderRecord) -> Value {
    json!({ "peer_id": p.provider_peer_id, "addresses": p.addresses })
}

/// The `providers` array for an enriched `dig.getAvailability` miss answer.
pub(crate) fn providers_json(providers: &[ProviderRecord]) -> Value {
    Value::Array(providers.iter().map(provider_json).collect())
}

/// Render a [`ContentId`] as the `data.redirect.content` object (`store_id` [+ `root`
/// [+ `retrieval_key`]], lowercase 64-hex) — the exact item the caller re-requests.
pub(crate) fn content_id_json(content: &ContentId) -> Value {
    match content {
        ContentId::Store { store_id } => json!({ "store_id": hex::encode(store_id) }),
        ContentId::Root { store_id, root } => json!({
            "store_id": hex::encode(store_id),
            "root": hex::encode(root),
        }),
        ContentId::Resource {
            store_id,
            root,
            retrieval_key,
        } => json!({
            "store_id": hex::encode(store_id),
            "root": hex::encode(root),
            "retrieval_key": hex::encode(retrieval_key),
        }),
    }
}

/// The resource [`ContentId`] for a `dig.getContent` / resource `dig.fetchRange` miss, or `None`
/// when any component is not a concrete 64-hex value (then the miss path is inapplicable and the
/// caller's own response stands).
pub(crate) fn miss_content_for(store_hex: &str, root_hex: &str, rk_hex: &str) -> Option<ContentId> {
    Some(ContentId::resource(
        hex64(store_hex)?,
        hex64(root_hex)?,
        hex64(rk_hex)?,
    ))
}

/// The [`ContentId`] for a `dig.getAvailability` item at whatever granularity it names: a resource
/// (`store_id` + `root` + `retrieval_key`), a capsule (`store_id` + `root`), or a store (`store_id`
/// only). `None` when `store_id` is not a concrete 64-hex value or a present component is malformed —
/// then the miss path is inapplicable and the plain not-available answer stands. Used by the
/// availability redirect-on-miss hint.
pub(crate) fn availability_content_id(
    store_hex: &str,
    root_hex: Option<&str>,
    rk_hex: Option<&str>,
) -> Option<ContentId> {
    let store = hex64(store_hex)?;
    match (root_hex, rk_hex) {
        (Some(r), Some(k)) => Some(ContentId::resource(store, hex64(r)?, hex64(k)?)),
        (Some(r), None) => Some(ContentId::capsule(store, hex64(r)?)),
        // A retrieval_key without a root is not a well-formed content id; fall back to store level.
        (None, _) => Some(ContentId::store(store)),
    }
}

/// The [`ContentId`] named by a peer RangeRequest frame (`store_id`/`root`/`retrieval_key`/
/// `capsule`), or `None` when it does not name concrete content. Used by the peer range-stream
/// miss path.
pub(crate) fn range_content_id(req: &Value) -> Option<ContentId> {
    let store = hex64(req.get("store_id").and_then(Value::as_str).unwrap_or(""))?;
    let root = hex64(req.get("root").and_then(Value::as_str).unwrap_or(""))?;
    if req.get("capsule").and_then(Value::as_bool).unwrap_or(false) {
        return Some(ContentId::capsule(store, root));
    }
    let rk = hex64(
        req.get("retrieval_key")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )?;
    Some(ContentId::resource(store, root, rk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_download::testkit::{
        mock_content_id, mock_peer_hex, mock_provider, MockContent, MockProviderLocator,
        MockRangeTransport,
    };
    use digstore_core::codec::Encode;

    /// MockContent whose `root`/`inclusion_proof` are a REAL digstore merkle proof over its bytes,
    /// so the chain-binding [`DigstoreProofVerifier`] passes for honest bytes (and fails for
    /// corrupt ones) — the same proof shape the node serves from a local module.
    pub(crate) fn anchored_mock_content(n: usize, chunks: usize) -> MockContent {
        let mut content = MockContent::even(n, chunks);
        let leaf = digstore_core::resource_leaf(&content.bytes);
        let tree = digstore_core::MerkleTree::from_leaves(vec![leaf]);
        let proof = tree.prove(0).expect("single-leaf proof");
        content.root = tree.root().to_hex();
        content.inclusion_proof =
            Some(base64::engine::general_purpose::STANDARD.encode(Encode::to_bytes(&proof)));
        content
    }

    /// The [`ContentId`] a test must request for an [`anchored_mock_content`]: its `root` MUST equal
    /// the root the transport reports in each range's first frame, because the download orchestrator
    /// now cross-checks the peer-reported root against the content-id root (dig-download #179 HIGH).
    /// Store id + retrieval key match `mock_content_id` (`[1;32]` / `[3;32]`); only the root is bound
    /// to the anchored content's real merkle root so an honest download proceeds.
    pub(crate) fn anchored_cid_for(content: &MockContent) -> ContentId {
        let root_bytes: [u8; 32] = digstore_core::Bytes32::from_hex(&content.root)
            .expect("anchored content root is 64-hex")
            .0;
        ContentId::resource([1; 32], root_bytes, [3; 32])
    }

    // -- miss-mode resolution --------------------------------------------------------------------

    #[test]
    fn miss_mode_defaults_to_redirect_and_opts_into_fetch_through() {
        assert_eq!(
            resolve_miss_mode(None),
            MissMode::Redirect,
            "unset → redirect"
        );
        assert_eq!(resolve_miss_mode(Some("redirect")), MissMode::Redirect);
        assert_eq!(resolve_miss_mode(Some("junk")), MissMode::Redirect);
        for v in [
            "fetch",
            "FETCH",
            "fetch-through",
            "Fetch_Through",
            " fetch ",
        ] {
            assert_eq!(
                resolve_miss_mode(Some(v)),
                MissMode::FetchThrough,
                "DIG_NODE_ON_MISS={v} → fetch-through"
            );
        }
    }

    /// **Proves:** capsule backfill (§5.6) defaults ON and only an explicit falsy value disables it.
    /// **Catches:** a default-off regression (the user wants backfill on by default) or a parser that
    /// misreads a truthy/absent value as disabled.
    #[test]
    fn backfill_defaults_on_and_opts_out_only_on_falsy() {
        assert!(resolve_backfill_on_miss(None), "unset → ON (default)");
        assert!(resolve_backfill_on_miss(Some("on")));
        assert!(resolve_backfill_on_miss(Some("1")));
        assert!(resolve_backfill_on_miss(Some("anything")), "unknown → ON");
        for v in ["off", "0", "false", "no", "OFF", "False", " no "] {
            assert!(
                !resolve_backfill_on_miss(Some(v)),
                "DIG_NODE_BACKFILL_ON_MISS={v} → disabled"
            );
        }
    }

    // -- redirect shaping --------------------------------------------------------------------------

    #[test]
    fn redirect_depth_defaults_to_zero() {
        assert_eq!(redirect_depth(&json!({})), 0);
        assert_eq!(redirect_depth(&json!({"redirect_depth": 3})), 3);
        assert_eq!(redirect_depth(&json!({"redirect_depth": "x"})), 0);
    }

    #[test]
    fn redirect_error_object_names_code_providers_depth_and_cap() {
        let cid = ContentId::resource([1; 32], [2; 32], [3; 32]);
        let provider = mock_provider(7, &cid);
        let err = redirect_error_object(&cid, &[provider], 2);
        assert_eq!(err["code"], json!(CONTENT_REDIRECT));
        let r = &err["data"]["redirect"];
        assert_eq!(r["providers"][0]["peer_id"], json!(mock_peer_hex(7)));
        assert_eq!(r["providers"][0]["addresses"][0]["host"], json!("10.0.0.7"));
        assert_eq!(r["providers"][0]["addresses"][0]["port"], json!(9444));
        assert_eq!(r["providers"][0]["addresses"][0]["kind"], json!("direct"));
        assert_eq!(r["redirect_depth"], json!(2));
        assert_eq!(r["max_redirects"], json!(REDIRECT_HOP_CAP));
        assert_eq!(r["content"]["store_id"], json!("01".repeat(32)));
        assert_eq!(r["content"]["root"], json!("02".repeat(32)));
        assert_eq!(r["content"]["retrieval_key"], json!("03".repeat(32)));
    }

    #[test]
    fn content_id_json_matches_granularity() {
        let store = content_id_json(&ContentId::store([1; 32]));
        assert!(store.get("root").is_none());
        let capsule = content_id_json(&ContentId::capsule([1; 32], [2; 32]));
        assert_eq!(capsule["root"], json!("02".repeat(32)));
        assert!(capsule.get("retrieval_key").is_none());
    }

    #[test]
    fn miss_content_for_requires_concrete_hex() {
        assert!(miss_content_for(&"11".repeat(32), &"22".repeat(32), &"33".repeat(32)).is_some());
        assert!(miss_content_for("", &"22".repeat(32), &"33".repeat(32)).is_none());
        assert!(miss_content_for(&"11".repeat(32), "latest", &"33".repeat(32)).is_none());
        assert!(miss_content_for(&"11".repeat(32), &"22".repeat(32), "").is_none());
    }

    #[test]
    fn range_content_id_maps_resource_and_capsule() {
        let resource = range_content_id(&json!({
            "store_id": "11".repeat(32), "root": "22".repeat(32),
            "retrieval_key": "33".repeat(32), "length": 4096}))
        .expect("resource id");
        assert!(matches!(resource, ContentId::Resource { .. }));
        let capsule = range_content_id(&json!({
            "store_id": "11".repeat(32), "root": "22".repeat(32),
            "capsule": true, "length": 4096}))
        .expect("capsule id");
        assert!(matches!(capsule, ContentId::Root { .. }));
        assert!(range_content_id(&json!({"store_id": "xx", "length": 1})).is_none());
    }

    // -- the digstore-bound proof verifier ---------------------------------------------------------

    #[test]
    fn digstore_proof_verifier_binds_leaf_and_root() {
        let content = anchored_mock_content(30, 3);
        let leaf = digstore_core::resource_leaf(&content.bytes);
        let v = DigstoreProofVerifier;
        // Honest bytes verify against the served proof + root.
        assert!(v.verify_inclusion(
            &leaf.0,
            content.inclusion_proof.as_deref(),
            Some(&content.root)
        ));
        // A different resource leaf (corrupt bytes) fails.
        let wrong = digstore_core::resource_leaf(b"not the resource");
        assert!(!v.verify_inclusion(
            &wrong.0,
            content.inclusion_proof.as_deref(),
            Some(&content.root)
        ));
        // A different root (wrong generation) fails.
        assert!(!v.verify_inclusion(
            &leaf.0,
            content.inclusion_proof.as_deref(),
            Some(&"ee".repeat(32))
        ));
        // A capsule fetch (no per-resource binding) self-verifies on install → accepted here.
        assert!(v.verify_inclusion(&leaf.0, None, None));
        // A half-specified binding fails closed.
        assert!(!v.verify_inclusion(&leaf.0, content.inclusion_proof.as_deref(), None));
        assert!(!v.verify_inclusion(&leaf.0, None, Some(&content.root)));
        // Garbage proof bytes fail, never panic.
        assert!(!v.verify_inclusion(&leaf.0, Some("!!not-base64!!"), Some(&content.root)));
    }

    // -- fetched-resource serving shapes ----------------------------------------------------------

    fn fetched(n: usize, chunks: usize) -> (FetchedResource, MockContent) {
        let content = anchored_mock_content(n, chunks);
        (
            FetchedResource {
                bytes: content.bytes.clone(),
                total_length: content.bytes.len() as u64,
                chunk_lens: content.chunk_lens.clone(),
                root: Some(content.root.clone()),
                inclusion_proof: content.inclusion_proof.clone(),
            },
            content,
        )
    }

    #[test]
    fn range_frame_first_window_carries_verification_metadata() {
        let (f, content) = fetched(30, 3);
        let frame = f.range_frame(0, 4096).expect("frame");
        assert_eq!(frame["offset"], json!(0));
        assert_eq!(frame["length"], json!(30));
        assert_eq!(frame["complete"], json!(true));
        assert_eq!(frame["total_length"], json!(30));
        assert_eq!(frame["chunk_lens"], json!(content.chunk_lens));
        assert_eq!(frame["root"], json!(content.root));
        assert_eq!(frame["inclusion_proof"], json!(content.inclusion_proof));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(frame["bytes"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, content.bytes);
    }

    #[test]
    fn range_frame_later_window_omits_metadata_and_bounds_offset() {
        let (f, content) = fetched(30, 3);
        let frame = f.range_frame(10, 10).expect("frame");
        assert_eq!(frame["offset"], json!(10));
        assert_eq!(frame["complete"], json!(false));
        assert!(
            frame.get("chunk_lens").is_none(),
            "meta on first frame only"
        );
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(frame["bytes"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, content.bytes[10..20]);
        // Beyond the resource → the catalogued -32007 (mirrors the local serve path).
        let err = f.range_frame(31, 1).unwrap_err();
        assert_eq!(err.0, -32007);
    }

    #[test]
    fn content_result_mirrors_the_get_content_window_shape() {
        let (f, content) = fetched(30, 3);
        let result = f.content_result(0);
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["root"], json!(content.root));
        assert_eq!(result["chunk_lens"], json!(content.chunk_lens));
        assert_eq!(result["inclusion_proof"], json!(content.inclusion_proof));
        assert!(result.get("next_offset").is_none());
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(result["ciphertext"].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes, content.bytes);
    }

    // -- the #164 fetch path (Downloader construction + reassembly, mock DHT + transport) ---------

    #[tokio::test]
    async fn fetch_resource_downloads_reassembles_and_caches() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        // The content-id root MUST equal the transport-reported root (dig-download #179 cross-check).
        let cid = anchored_cid_for(&content);
        let transport = Arc::new(MockRangeTransport::new(content.clone()));
        let locator = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
        ]));
        let pc = NodeContent::new(
            locator,
            transport.clone(),
            MissMode::FetchThrough,
            None,
            td.path(),
        );

        let f = pc.fetch_resource(&cid).await.expect("download succeeds");
        assert_eq!(f.bytes, content.bytes, "reassembled bytes match the source");
        assert_eq!(f.total_length, 30);
        assert_eq!(f.chunk_lens, content.chunk_lens);
        assert_eq!(f.root.as_deref(), Some(content.root.as_str()));
        assert_eq!(f.inclusion_proof, content.inclusion_proof);

        // A second fetch is served from the in-memory cache — no new peer fetches.
        let attempts_before = transport.attempts_for(&mock_peer_hex(1)).await
            + transport.attempts_for(&mock_peer_hex(2)).await;
        let f2 = pc.fetch_resource(&cid).await.expect("cache hit");
        assert_eq!(f2.bytes, f.bytes);
        let attempts_after = transport.attempts_for(&mock_peer_hex(1)).await
            + transport.attempts_for(&mock_peer_hex(2)).await;
        assert_eq!(
            attempts_before, attempts_after,
            "no re-download on a cache hit"
        );
    }

    #[tokio::test]
    async fn fetch_resource_fails_cleanly_with_no_providers() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(content)),
            MissMode::FetchThrough,
            None,
            td.path(),
        );
        assert!(pc.fetch_resource(&mock_content_id()).await.is_err());
    }

    #[tokio::test]
    async fn find_providers_excludes_self() {
        let td = tempfile::tempdir().unwrap();
        let cid = mock_content_id();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![
                mock_provider(1, &cid),
                mock_provider(2, &cid),
            ])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            Some(mock_peer_hex(1)), // this node IS provider 1
            td.path(),
        );
        let got = pc.find_providers(&cid).await;
        assert_eq!(got.len(), 1, "own record excluded");
        assert_eq!(got[0].provider_peer_id, mock_peer_hex(2));
    }

    // -- staging-file GC (the .download.tmp reaper) ------------------------------------------------

    #[tokio::test]
    async fn gc_reaps_stale_tmp_but_never_a_protected_one() {
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let dir = pc.downloads_dir().to_path_buf();
        let two_hours_ago = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - Duration::from_secs(7200),
        );
        // A stale orphan (crashed/abandoned download) → reaped.
        let stale = dir.join("dead.res.download.tmp");
        std::fs::write(&stale, b"x").unwrap();
        filetime::set_file_mtime(&stale, two_hours_ago).unwrap();
        // An equally-old but PROTECTED staging file (a paused-resumable download) → kept.
        let live = dir.join("live.res.download.tmp");
        std::fs::write(&live, b"y").unwrap();
        filetime::set_file_mtime(&live, two_hours_ago).unwrap();
        pc.active_downloads().register(live.clone()).await;

        let removed = pc.gc_once(Duration::from_secs(3600)).await;
        assert_eq!(removed, 1, "exactly the stale orphan is reaped");
        assert!(!stale.exists(), "stale orphan removed");
        assert!(live.exists(), "protected staging file kept");
    }

    // -- the peer selector (#178): the discovery → select → download → record_outcome loop ----------

    /// The gossip → selector `PoolEvent` map is a byte-identical 1:1 (SPEC §5.4): the peer id is the
    /// same 32 bytes and the removal reasons map variant-for-variant.
    #[test]
    fn pool_event_map_is_1_to_1() {
        let addr: std::net::SocketAddr = "203.0.113.7:9444".parse().unwrap();
        let added = pool_event_to_selector([9u8; 32], PoolEventKind::Added { addr });
        assert_eq!(
            added,
            PoolEvent::PeerAdded {
                peer_id: PeerId::from_bytes([9u8; 32]),
                addr
            }
        );
        for (g, s) in [
            (
                GossipRemovalReason::Disconnected,
                PoolRemovalReason::Disconnected,
            ),
            (GossipRemovalReason::Dead, PoolRemovalReason::Dead),
            (GossipRemovalReason::Banned, PoolRemovalReason::Banned),
        ] {
            assert_eq!(pool_removal_reason(g), s);
            assert_eq!(
                pool_event_to_selector([1u8; 32], PoolEventKind::Removed { reason: g }),
                PoolEvent::PeerRemoved {
                    peer_id: PeerId::from_bytes([1u8; 32]),
                    reason: s
                }
            );
        }
    }

    /// The failure-reason classifier maps a verify/integrity reason to the HARD signal and other
    /// reasons to their soft classes (SPEC §6.3).
    #[test]
    fn failure_reason_classification() {
        assert_eq!(
            failure_reason_of("range verification failed"),
            FailureReason::VerificationFailed
        );
        assert_eq!(
            failure_reason_of("merkle proof mismatch"),
            FailureReason::VerificationFailed
        );
        assert_eq!(
            failure_reason_of("request timed out"),
            FailureReason::Timeout
        );
        assert_eq!(
            failure_reason_of("provider unavailable"),
            FailureReason::Unavailable
        );
        assert_eq!(
            failure_reason_of("connection reset"),
            FailureReason::Transport
        );
    }

    /// The `SelectorLocator` CONSULTS the selector before download: given a fixed provider set, its
    /// `find_providers` returns the located records ordered by the selector's ranking (all healthy
    /// candidates chosen on the first, exploratory pass). This is the seam that makes the selector
    /// drive the executor's source choice (SPEC §6.1).
    #[tokio::test]
    async fn selector_locator_consults_selector_and_returns_ranked_subset() {
        let cid = mock_content_id();
        let inner = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
            mock_provider(3, &cid),
        ]));
        let selector = Arc::new(PeerSelector::new(SelectorConfig::deterministic(1000, 7)));
        let loc = SelectorLocator::new(inner, selector.clone());

        let ranked = loc.find_providers(&cid).await.expect("locate ok");
        // Every located holder is a candidate; on the cold pass the selector picks a subset (bounded by
        // the exploration cap) — non-empty and drawn only from the located set.
        assert!(!ranked.is_empty(), "selector chose at least one source");
        let located_ids: std::collections::HashSet<String> =
            [1u8, 2, 3].iter().map(|n| mock_peer_hex(*n)).collect();
        for r in &ranked {
            assert!(
                located_ids.contains(&r.provider_peer_id),
                "ranked source came from the located set"
            );
        }
        // The selector's registry now knows the candidates (select registered them) — proving it was
        // consulted, not bypassed.
        let snap = selector.snapshot();
        assert!(
            snap.registry_size >= ranked.len(),
            "selector registered the candidates it ranked"
        );
    }

    /// The full loop end-to-end: a multi-source fetch over the mock DHT + transport drives the
    /// selector — `select` is consulted (the download only sees the ranked subset) AND `record_outcome`
    /// is fed for the completed ranges, so the selector has learned a measured quality for the peer(s)
    /// that served the transfer. Deterministic (fixed seed + mock transport).
    #[tokio::test]
    async fn fetch_feeds_record_outcome_and_selector_learns() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(60, 6);
        // The content-id root MUST equal the transport-reported root (dig-download #179 cross-check).
        let cid = anchored_cid_for(&content);
        let transport = Arc::new(MockRangeTransport::new(content.clone()));
        let locator = Arc::new(MockProviderLocator::fixed(vec![
            mock_provider(1, &cid),
            mock_provider(2, &cid),
        ]));
        let pc = NodeContent::new(locator, transport, MissMode::FetchThrough, None, td.path());

        // Before any fetch the selector has learned nothing.
        let before = pc.selector().snapshot();
        assert_eq!(before.measured_peers, 0, "no measured peers before a fetch");

        let f = pc.fetch_resource(&cid).await.expect("download succeeds");
        assert_eq!(f.bytes, content.bytes, "reassembled bytes match the source");

        // After the fetch the selector has folded in measured outcomes for the peer(s) that served the
        // ranges — proving record_outcome was fed in real time from the download event stream.
        let after = pc.selector().snapshot();
        assert!(
            after.measured_peers >= 1,
            "record_outcome fed at least one peer's measured quality (got {})",
            after.measured_peers
        );
        // At least one of the two providers now carries a positive sample count from the served ranges.
        let learned = [1u8, 2].iter().any(|n| {
            pc.selector()
                .peer_snapshot(&PeerId::from_bytes([*n; 32]))
                .map(|p| p.samples > 0)
                .unwrap_or(false)
        });
        assert!(learned, "a served peer acquired measured samples");
    }

    /// The registry-feed hooks the node calls: a pool `PeerAdded` upserts a candidate; a `Banned`
    /// removal makes it ineligible; a connection class attaches without error (SPEC §2.3, §5.4).
    #[tokio::test]
    async fn registry_feed_hooks_are_wired() {
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let peer = PeerId::from_bytes([42u8; 32]);
        let addr: std::net::SocketAddr = "203.0.113.42:9444".parse().unwrap();
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: peer,
            addr,
        });
        pc.on_connection_class(&peer, TraversalKind::Direct);
        assert_eq!(
            pc.selector().snapshot().registry_size,
            1,
            "pool add registered the peer"
        );
        // A ban makes the peer ineligible (retained but not selectable).
        pc.on_pool_event(&PoolEvent::PeerRemoved {
            peer_id: peer,
            reason: PoolRemovalReason::Banned,
        });
        let snap = pc.selector().peer_snapshot(&peer).expect("peer retained");
        assert!(snap.banned, "banned peer is retained but ineligible");
    }
}
