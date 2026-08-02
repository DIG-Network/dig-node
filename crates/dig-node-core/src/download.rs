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
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};

use dig_dht::ContentId;
use dig_download::{
    download_key, DhtProviderLocator, DownloadConfig, DownloadError, DownloadOptions, Downloader,
    FileSink, FileStateStore, GcConfig, MerkleVerifier, NatRangeTransport, ProofVerifier,
    ProviderLocator, ProviderRecord, RangeTransport, StateStore,
};
use dig_peer_selector::{
    PeerId, PeerSelector, PoolEvent, PoolRemovalReason, SelectorConfig, TraversalKind,
};
use digstore_core::codec::Decode;

use crate::dht::hex64;
use crate::seams::dig_peer::{
    CapsuleFallbackLocator, ConnectedPool, EmptyLocator, PoolProviderLocator, SelectorAdapter,
    SelfExcludingLocator, UnionLocator,
};

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

/// The hard ceiling on total bytes held in whole-capsule staging (`<downloads>/modules`), enforced by
/// [`NodeContent::enforce_staging_cap`] (#1615).
///
/// DERIVED from the two bounds that already govern a warm rather than chosen: at most
/// [`DEFAULT_MAX_CONCURRENT_WARMS`] generations may pull at once, and each is capped at
/// [`DEFAULT_MAX_MODULE_SIZE`](dig_download::DEFAULT_MAX_MODULE_SIZE). The ceiling must therefore sit
/// ABOVE what legitimate concurrent pulls need, or the cap would spend its time evicting healthy
/// in-flight work; one extra generation's worth is the headroom that absorbs scratch abandoned by a pull
/// that has only just died and is not yet TTL-stale.
///
/// Deriving it this way means raising either underlying bound raises this one automatically, instead of
/// leaving a literal behind that silently becomes too small.
const MAX_MODULE_STAGING_BYTES: u64 = (crate::seams::dig_peer::DEFAULT_MAX_CONCURRENT_WARMS as u64
    + 1)
    * dig_download::DEFAULT_MAX_MODULE_SIZE;

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

// -- Where a read request came from — the reshare trigger's ONLY gate ------------------------------

/// Who asked for this read: this node's OWN operator (loopback HTTP / in-process FFI / the
/// node-internal control surface), or a REMOTE peer over the peer wire protocol.
///
/// This is the guard that keeps the reshare leg (#1576) from being a remotely-triggerable
/// amplification primitive: "a reader that reads becomes a holder" means a LOCAL user's read, never
/// a remote peer's `dig.fetchRange`/`dig.getContent` miss served through this node. `handle_rpc` is
/// the one dispatch entry every transport shares (loopback HTTP, FFI, AND the peer-RPC server), so
/// this is threaded through it EXPLICITLY from each transport's own call site — never inferred from
/// an address, a header, or any other heuristic a remote caller could spoof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOrigin {
    /// This node's own operator, via the loopback HTTP shell, the in-process FFI, or the
    /// node-internal control/subscription surface.
    Local,
    /// A remote peer, via the peer-RPC server or the peer stream's own miss handling.
    Peer,
}

/// Whether an HTTP read is a FIRST-PARTY navigation (the user's own top-level request, a same-site
/// subresource, or a non-browser client) or a CROSS-SITE subresource driven by some OTHER origin's
/// page. This is a SECOND axis, ORTHOGONAL to [`ReadOrigin`]: `ReadOrigin` is the TRANSPORT the
/// request arrived on (loopback/FFI vs the peer wire), while `RequestProvenance` describes WITHIN a
/// loopback HTTP request whether the browser tells us another site drove it.
///
/// It exists because "the peer address is loopback" is NOT "the operator authorized this": a
/// malicious web page can make a cross-site `GET dig.local/s/<capsule>` and — while the bytes are
/// harmless to serve — the LANDING side effect (cache write → this node becomes a DHT holder,
/// SPEC §14.3/§21.3) is a durable, remotely-triggerable amplification. Gating landing on first-party
/// provenance closes that CSRF door WITHOUT ever throttling the read: the bytes always serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestProvenance {
    /// A first-party request: the user's own navigation, a same-origin/same-site subresource, a
    /// direct address-bar hit, OR any non-browser client (CLI/SDK send no `Sec-Fetch-*` header).
    FirstParty,
    /// A cross-site subresource: the browser explicitly reported `Sec-Fetch-Site: cross-site`,
    /// meaning some OTHER origin's page drove this request. The read still serves; landing does not.
    CrossSite,
}

/// Classify a request's provenance from its `Sec-Fetch-Site` header value (already extracted from
/// the header map; `None` when the header is absent).
///
/// ONLY an explicit, case-insensitive `cross-site` denies landing. Everything else — `same-origin`,
/// `same-site`, `none`, an unknown value, AND (critically) an ABSENT header — is [`FirstParty`], so
/// non-browser clients that never send `Sec-Fetch-*` (the CLI, the SDK) are never mistaken for a
/// cross-site attacker. Absence must NEVER map to `CrossSite`.
///
/// [`FirstParty`]: RequestProvenance::FirstParty
pub fn from_sec_fetch_site(hdr: Option<&str>) -> RequestProvenance {
    match hdr.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("cross-site") => RequestProvenance::CrossSite,
        _ => RequestProvenance::FirstParty,
    }
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
    /// shape as [`crate::Node::fetch_range_frame`] over a locally-held resource: EVERY frame carries
    /// `total_length`/`chunk_lens`/`root`/`inclusion_proof` plus `first_chunk_index` when the window
    /// starts on a chunk boundary (see
    /// [`range_frame`](crate::seams::content::range_frame)). `-32007` for an offset beyond the
    /// resource, mirroring the local path.
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
        // Byte-shape-identical to the locally-held path: every frame carries its own verification
        // metadata (#1577), so a fetch-through serve is indistinguishable from a local one.
        crate::seams::content::range_frame::attach_verification(
            &mut frame,
            &crate::seams::content::range_frame::RangeVerification {
                total_length: self.total_length,
                chunk_lens: &self.chunk_lens,
                root: self.root.as_deref(),
                inclusion_proof: self.inclusion_proof.as_deref(),
            },
            start as u64,
        );
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
// contract): it feeds the registry (pool churn + connection classes) and bridges dig-download's
// [`SourceSelector`] seam onto the selector via [`SelectorAdapter`](crate::seams::dig_peer::SelectorAdapter)
// (#1442), so dig-download DELEGATES peer choice + reports every range outcome to the ONE shared brain
// — dig-download 0.5 records outcomes internally through the seam (no node-side event translation).

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

/// Maps `dig_gossip::PoolRemovalReason` → the selector's local [`PoolRemovalReason`]
/// (`Banned` makes the peer ineligible until re-added, SPEC §9.4).
///
/// `Reaped` has no selector counterpart, so it must fold into one of the three the selector knows.
/// It folds to `Disconnected` rather than `Dead` because a reaped peer's transport was *provably
/// closed* — a departure, which is what `Disconnected` names — whereas `Dead` names a keepalive
/// finding a peer unresponsive. What makes the choice safe rather than merely tidy: the selector
/// distinguishes only `Banned` behaviourally (`engine.rs` matches on it alone to mark a peer
/// ineligible) and treats `Disconnected`/`Dead` identically, so this fold is observability-only and
/// cannot change eligibility. Folding it to `Banned` would be the real error — it would make an
/// honestly-departed peer ineligible and bias the node toward unremembered peers, which is a sybil.
pub(crate) fn pool_removal_reason(reason: GossipRemovalReason) -> PoolRemovalReason {
    match reason {
        GossipRemovalReason::Disconnected | GossipRemovalReason::Reaped => {
            PoolRemovalReason::Disconnected
        }
        GossipRemovalReason::Dead => PoolRemovalReason::Dead,
        GossipRemovalReason::Banned => PoolRemovalReason::Banned,
    }
}

/// The most addresses the connected pool keeps for ONE `peer_id`.
///
/// WHY 8 (dig_ecosystem#1782): it is `dig-dht`'s own `MAX_ADDRESSES_PER_RECORD`, the limit every
/// address list this pool feeds is eventually cut to. Matching it means the pool never holds an
/// address that could not be published anyway.
///
/// WHY a cap at all: `PeerAdded` is republished each time a fresh verified session supersedes a
/// stale slot for the same identity, and a supersede fires NO `PeerRemoved` — so without a cap the
/// list grows by one entry per distinct `SocketAddr` ever seen for that peer, forever (measured:
/// 5000 `PeerAdded` events → 5000 entries). Three independent guards downstream stop a remote peer
/// from driving that today, which makes this defence-in-depth rather than a live leak; the point of
/// the cap is that relaxing any ONE of those guards later must not turn this into a remote memory
/// sink.
pub(crate) const MAX_POOL_ADDRS_PER_PEER: usize = 8;

/// Cut `addrs` (newest-first) down to at most `limit` entries, evicting the OLDEST address of
/// whichever address family currently has the most entries.
///
/// WHY not a plain `truncate` (dig_ecosystem#1782, secondary): the tail is where the other address
/// FAMILY ends up. A peer reached over IPv6 that then becomes reachable over IPv4 accumulates fresh
/// IPv6 sessions; a blind truncate drops the lone IPv4 address off the end, and since the downstream
/// dial ladder is both IPv6-first and very short, losing it can make an otherwise-reachable peer
/// unreachable. Evicting from the larger family keeps at least one address of each family for as
/// long as the cap allows, which is what the IPv6-first/IPv4-FALLBACK rule (§5.2) actually requires:
/// IPv6 is preferred, not exclusive.
fn retain_newest_per_family(addrs: &mut Vec<std::net::SocketAddr>, limit: usize) {
    while addrs.len() > limit {
        let ipv6_count = addrs.iter().filter(|a| a.is_ipv6()).count();
        let evict_ipv6 = ipv6_count * 2 >= addrs.len();
        // Newest-first ordering means the LAST entry of a family is its oldest.
        let victim = addrs
            .iter()
            .rposition(|a| a.is_ipv6() == evict_ipv6)
            .expect("the majority family has at least one member");
        addrs.remove(victim);
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
    /// Swept up by dig-gossip's departed-peer reaper: the transport was provably closed, but the
    /// slot is keepalive-less so nothing else observed the departure.
    Reaped,
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

// -- The node's P2P content engine ------------------------------------------------------------------

/// The standalone node's P2P content engine: the dig-download [`Downloader`] wired from the node's
/// live pieces (the #164 fetch path) plus the provider lookup the redirect-on-miss handler uses
/// (#165). Constructed by the peer-network bring-up and attached to the node
/// ([`crate::Node::set_p2p_content`]); absent in the FFI path, where every miss behaves exactly as
/// before.
pub struct NodeContent {
    /// "Which peers hold this content?" — the DHT in production, a mock in tests. This is the RAW
    /// discovery locator: the redirect-on-miss path names EVERY holder here, not the selector's ranked
    /// subset (a redirect should offer the caller all known holders). In production it is wrapped in a
    /// [`SelfExcludingLocator`] (#1584), so discovery is already self-filtered — this node's own
    /// `peer_id` never appears as a holder — but is otherwise unranked.
    locator: Arc<dyn ProviderLocator>,
    /// The self-optimizing peer selector (#178) — the decision + learning brain between discovery and
    /// download. It ranks the download sources (bridged into dig-download's [`SourceSelector`] seam by
    /// [`SelectorAdapter`], #1442) and learns from every range outcome dig-download reports back
    /// through that seam. Fed the pool churn + connection classes by the node ([`Self::on_pool_event`],
    /// [`Self::on_connection_class`]).
    selector: Arc<PeerSelector>,
    /// The multi-source download engine (locate → confirm → fan out → verify → reassemble). Its
    /// injected `config.selector` is a [`SelectorAdapter`] over the shared [`PeerSelector`], so the
    /// executor fans ranges across the selector's ranked subset — and records every outcome back to it —
    /// instead of picking sources blindly.
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
    /// The live set of currently-connected pool peers (64-hex `peer_id` → observed addresses), fed
    /// from gossip pool churn ([`Self::on_pool_event`]). A [`PoolProviderLocator`] over this map is
    /// unioned into the DOWNLOAD locator (#1590) so a fetch also tries the peers the node is already
    /// connected to — reaching a holder whose DHT record is unreachable on a relayed net. NOT part of
    /// the raw discovery `locator` (a redirect must name announced holders, not every connected peer).
    connected_pool: ConnectedPool,
    /// The reshare leg (#1576): after a resource read completes, this pulls the WHOLE `.dig` capsule so
    /// the reader becomes a discoverable holder of it — the step that makes each read leave the content
    /// more available than it found it.
    ///
    /// Installed by the composition root once the peer stack is up
    /// ([`Self::set_capsule_warmer`]), because the warmer needs the same live transport + DHT the engine
    /// uses. `None` until then, and permanently `None` on the FFI/base path — a read behaves identically
    /// with or without the reshare leg.
    capsule_warmer: std::sync::OnceLock<Arc<crate::seams::dig_peer::CapsuleWarmer>>,
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

    // Bad-descriptor reputation (#1611) must reach the inner file store, NOT the trait's forgetful
    // no-op defaults: a holder demoted for serving a lying descriptor stays demoted across a restart,
    // so a later call/process never re-pays for the same lie. This wrapper only adds commitment
    // capture — it delegates reputation verbatim.
    async fn record_bad_descriptor(
        &self,
        target_key: &str,
        peer_id: &str,
    ) -> Result<(), dig_download::DownloadError> {
        self.inner.record_bad_descriptor(target_key, peer_id).await
    }

    async fn bad_descriptor_peers(
        &self,
        target_key: &str,
    ) -> Result<Vec<String>, dig_download::DownloadError> {
        self.inner.bad_descriptor_peers(target_key).await
    }
}

/// A [`RangeTransport`] wrapper that BYPASSES the `getAvailability` confirm probe for a holder the node
/// is already CONNECTED to in the gossip pool (#836 read-leg confirm-gate fix).
///
/// dig-download's `locate_and_confirm` keeps only providers whose `query_availability` answer is
/// `available`, dropping the rest before any `fetchRange`. For a DHT-discovered provider that probe is a
/// useful pre-filter. But for a CONNECTED-POOL holder it is actively harmful: the peer is a live,
/// connection-verified holder offered specifically because we hold a connection to it, and its
/// self-reported availability flag can be a false negative on a relayed/isolated net (a cache-inventory
/// lag, a resource-vs-capsule granularity quirk) or its probe can transiently fail — either of which
/// drops the holder and dead-ends the read at a 404 with ZERO `fetchRange` issued, even though the holder
/// holds and would serve the bytes. The whole-resource merkle verify (not the availability flag) is the
/// real integrity gate, so skipping the probe for a connected peer is safe: a genuine non-holder simply
/// fails its ranges and is dropped there.
///
/// So `query_availability` short-circuits to `available = true` (no network round-trip) for any provider
/// whose `peer_id` is currently in the connected pool, and delegates to the inner transport for every
/// other (DHT-only) provider. `fetch_range` always delegates unchanged, with DEBUG tracing of the dial
/// target so a live e2e run shows exactly which holder each range reached (#836 observability).
struct PoolConfirmTransport {
    inner: Arc<dyn RangeTransport>,
    connected_pool: ConnectedPool,
}

impl PoolConfirmTransport {
    fn new(inner: Arc<dyn RangeTransport>, connected_pool: ConnectedPool) -> Self {
        PoolConfirmTransport {
            inner,
            connected_pool,
        }
    }

    /// Whether `peer_id_hex` is a currently-connected pool peer (a live, connection-verified holder).
    fn is_connected(&self, peer_id_hex: &str) -> bool {
        self.connected_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(peer_id_hex)
    }
}

#[async_trait::async_trait]
impl RangeTransport for PoolConfirmTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<dig_nat::AvailabilityItem>,
    ) -> Result<dig_nat::AvailabilityResponse, DownloadError> {
        // A connected-pool holder is confirmed by the live connection itself — skip the probe (which can
        // false-negative on a relayed net) and let the fetch + merkle verify be the gate.
        if self.is_connected(&provider.provider_peer_id) {
            tracing::debug!(
                peer = %provider.provider_peer_id,
                "pool confirm bypass: connected holder skips the getAvailability probe (#836)"
            );
            // Built through the constructors, not struct literals: these types are
            // `#[non_exhaustive]`, which is what makes every future additive wire field a PATCH for
            // this crate rather than a break (dig-nat SPEC §5.1.1).
            let answers = items
                .iter()
                .map(|_| dig_nat::AvailabilityAnswer::available())
                .collect();
            return Ok(dig_nat::AvailabilityResponse::new(answers));
        }
        self.inner.query_availability(provider, items).await
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &dig_nat::RangeRequest,
    ) -> Result<dig_download::FetchedRange, DownloadError> {
        tracing::debug!(
            peer = %provider.provider_peer_id,
            offset = req.offset,
            length = req.length,
            "fetch_range: dialing holder for a range (#836)"
        );
        self.inner.fetch_range(provider, req).await
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
        // Bridge the shared selector into dig-download's SourceSelector seam (#1442): the executor
        // delegates peer choice + ORDER to it and reports every range outcome back through it, so the
        // ONE self-tuning brain informs every transfer. The Downloader's own locator is the RAW
        // `locator` (the SelfExcludingLocator-wrapped UnionLocator in production, #1584) — discovery is
        // already self-filtered but otherwise unranked; the selector refines the SOURCE choice at
        // schedule time, not the discovered set. The same RAW `locator` stays on the engine for the
        // redirect-on-miss path (a redirect offers ALL known non-self holders).
        // dig-download 0.12 marked `DownloadConfig` `#[non_exhaustive]`, so it is built by mutating a
        // default rather than by a struct literal — every future field stays a minor bump for us.
        let mut config = DownloadConfig::default();
        config.selector = Some(Arc::new(SelectorAdapter::new(selector.clone())));
        // The DOWNLOAD locator (#1590) = a [`PoolProviderLocator`] over the live connected-pool set
        // UNIONed with the raw discovery `locator`. So a fetch's locate step also offers the peers the
        // node is ALREADY CONNECTED to — reaching a holder whose DHT provider record is unreachable on
        // a relayed net (the #836 read-leg blocker). dig-download's confirm step filters connected peers
        // that do not hold the content, and the whole-resource merkle check binds every byte to the
        // chain-anchored root, so a connected non-holder is a safe, bounded probe. The redirect-on-miss
        // path keeps the RAW `locator` (below) — a redirect must name announced holders, never every
        // connected peer.
        //
        // #836 dial-order (arbiter e2e c0954369): the pool source MUST be FIRST in the union. The real
        // content transport dials a SINGLE address — `provider.best_address()` = the FIRST *dialable*
        // candidate in list order (dig-dht `record.rs`, `is_dialable` = Direct/Mapped/Reflexive) — NOT
        // "any reachable address". The union merges same-peer_id address hints onto the FIRST-seen
        // record (extend, order-preserving; the cap does NOT sort). So whichever source is queried first
        // leads the address list and thus WINS `best_address()`. A pool entry is a LIVE,
        // connection-verified address; a DHT hint is an untrusted, possibly-stale advertisement. Putting
        // the pool FIRST makes the connection-verified address lead → `best_address()` selects the
        // reachable :9444, so confirm/fetchRange dial the address that actually connects. (Pool-second —
        // the prior order — left the stale DHT address leading, so every dial hit the unreachable hint
        // and the read 404'd despite a connected, dialable holder.) This orders ONLY the download union;
        // the DISCOVERY leg (`self.locator`, used by find_providers/redirect) is untouched.
        let connected_pool: ConnectedPool = Arc::new(std::sync::Mutex::new(HashMap::new()));
        // #836/#92: the fetch-dial candidate set MUST exclude self, exactly like the DISCOVERY leg
        // (#1584). #1584 self-excluded only the raw discovery `locator`; the DOWNLOAD locator adds the
        // [`PoolProviderLocator`] over the connected pool, and a relay-introduced self-connection can
        // surface THIS node in that pool (peer_id == local). Offered as a fetch candidate it becomes a
        // self-dial (Direct → own IP → connection refused; Relayed → refused self-dial) that starves
        // the download's confirm round and dead-ends the read at HTTP 404 despite a reachable holder
        // being connected (run e2e-836-arb-20260725-084501). Wrap the WHOLE download locator so NO
        // source — DHT or pool — can ever offer self on the fetch/dial path.
        let download_locator: Arc<dyn ProviderLocator> = SelfExcludingLocator::new(
            UnionLocator::new(vec![
                // Pool FIRST: a live connection-verified address must lead so `best_address()` (the
                // first dialable candidate) selects the reachable :9444, not a stale DHT hint (#836).
                PoolProviderLocator::new(connected_pool.clone()),
                locator.clone(),
            ]),
            self_peer_id.clone(),
        );
        // #836 read-leg confirm-gate fix: wrap the real transport so a CONNECTED-POOL holder skips the
        // separate `getAvailability` confirm probe. dig-download's `locate_and_confirm` drops any provider
        // whose availability answer is not `available` — but a pool peer was offered specifically because
        // the node is ALREADY CONNECTED to it (a live, connection-verified holder), and the whole-resource
        // merkle verify — not the peer's self-reported availability flag — is the real integrity gate. On a
        // relayed/isolated net a connected holder can answer availability=not-available (a cache-inventory
        // lag, a granularity quirk) or have its probe transiently fail, and the confirm gate then drops it
        // → ZERO fetchRange issued → the read 404s despite a connected, serving holder. Bypassing the probe
        // for pool peers lets the fetch reach them; a genuine non-holder simply fails its ranges and is
        // dropped there (bounded, safe). DHT-only providers still go through the real availability confirm.
        let confirm_transport: Arc<dyn RangeTransport> =
            Arc::new(PoolConfirmTransport::new(transport, connected_pool.clone()));
        let downloader = Downloader::new(
            download_locator,
            confirm_transport,
            verifier,
            state_store.clone(),
            config,
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
            connected_pool,
            capsule_warmer: std::sync::OnceLock::new(),
        })
    }

    /// The PRODUCTION constructor — wire the engine from the live DHT + the node's mTLS identity,
    /// exactly as dig-download's implementers' note prescribes. Discovery is a [`UnionLocator`] (#1443)
    /// over the live [`DhtProviderLocator`] plus DORMANT PEX + relay-introducer placeholders, so a
    /// later source swap needs no wiring churn. The [`NatRangeTransport`] dials providers over the FULL
    /// NAT traversal ladder (Direct → UPnP → NAT-PMP → PCP → hole-punch → Relayed) composed from the
    /// SHARED live [`NatRuntime`](dig_nat::NatRuntime) `runtime` — the SAME handle carrier the node's
    /// DHT-side dial uses (#1439) — so a range fetch reaches a NAT'd provider over hole-punch/relay, not
    /// just Direct, instead of DISCOVERING a holder it can never FETCH from. `stun_server` (when `Some`)
    /// feeds the hole-punch tier's reflexive-address discovery.
    #[allow(clippy::too_many_arguments)]
    pub fn for_dht(
        dht: Arc<dig_dht::DhtService>,
        node: Arc<dig_nat::NodeCert>,
        network_id: &str,
        miss_mode: MissMode,
        self_peer_id: Option<String>,
        cache_dir: &Path,
        stun_server: Option<std::net::SocketAddr>,
        runtime: Arc<dig_nat::NatRuntime>,
    ) -> Arc<Self> {
        // The provider union: dig-dht is live today; PEX + relay-introducer are wired-but-empty seams
        // (#1443, real sources land in #1440 part B). Best-effort — a dormant source adds nothing.
        let dht_locator: Arc<dyn ProviderLocator> = Arc::new(DhtProviderLocator::new(dht));
        let union: Arc<dyn ProviderLocator> = UnionLocator::new(vec![
            dht_locator,
            Arc::new(EmptyLocator), // PEX-as-provider-source (dormant)
            Arc::new(EmptyLocator), // relay-introducer (dormant)
        ]);
        // #1584 belt-and-suspenders: never discover THIS node as its own provider. dig-gossip is the
        // authoritative guard (no self entry enters the pool → selector), but a self-`peer_id` record
        // could still reach discovery from another source (a stale self-published DHT `add_provider`
        // record, a future PEX/relay-introducer source, a replay). Filter it at the INNERMOST source so
        // the exclusion covers every granularity, including CapsuleFallbackLocator's non-resource
        // pass-through — otherwise the reader self-dials (own IP → refused) and dead-ends the read (404).
        let union = SelfExcludingLocator::new(union, self_peer_id.clone());
        // #1580: holders announce STORE + CAPSULE granularity only (never per-resource — see
        // `dht::inventory_content_ids`), but a `/s` resource read locates by a RESOURCE content id.
        // Bridge the two so a resource lookup also resolves the announced parent capsule holder;
        // otherwise Tier-2 peer fetch finds nobody and the read 404s despite a discoverable holder.
        let locator = CapsuleFallbackLocator::new(union);
        let nat_config =
            crate::net::full_nat_config(crate::dht::default_rpc_timeout(), stun_server);
        // The fetch leg composes the SAME NAT ladder as the DHT dial from the shared runtime (#1439):
        // an empty runtime would be Direct-only, silently unable to reach hole-punch/relay holders.
        let transport = Arc::new(NatRangeTransport::new_with_runtime(
            node, nat_config, network_id, runtime,
        ));
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
        // Never register THIS node as its own source (#836/#92). A relay-introduced self-connection can
        // surface self in gossip pool churn (peer_id == local); a self entry then becomes a fetch
        // candidate that self-dials (own IP → connection refused; relayed → refused self-dial) and
        // dead-ends the read. Drop a self `PeerAdded` at the source, before it reaches EITHER the
        // selector registry or the download-side connected pool. (The download locator is also
        // self-excluded above — belt-and-suspenders; this keeps the selector ranking clean too.)
        if let PoolEvent::PeerAdded { peer_id, .. } = event {
            if self.self_peer_id.as_deref() == Some(peer_id.to_hex().as_str()) {
                return;
            }
        }
        self.selector.on_pool_event(event);
        // Mirror the churn into the connected-pool set the download-side PoolProviderLocator reads
        // (#1590): a joined peer becomes a fetch candidate (over the connection we already hold); a
        // departed/banned peer is dropped so a stale entry never keeps offering an unreachable peer.
        let mut pool = self
            .connected_pool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match event {
            PoolEvent::PeerAdded { peer_id, addr } => {
                // A wildcard / port-0 address is not a destination (#1784): dig-nat reports `[::]:0`
                // as the remote of an accepted relayed circuit when no relay endpoint is configured.
                // SKIP the event outright rather than record-then-filter, so a peer that already has
                // a working address does not have it displaced from the front of the dial order by
                // an address nothing can be reached at.
                if !crate::seams::dig_peer::net::is_usable_contact(addr) {
                    return;
                }
                // The NEWEST session's address leads the candidate's dial order, older ones trailing
                // as fallbacks (#1771). dig-gossip republishes `PeerAdded` when a fresh verified
                // session supersedes a stale slot for the same identity (#1691/#1703/#1762), which is
                // typically a MOVE — a dead relay circuit replaced by a direct dial. Appending would
                // leave the dead address first and spend a failed dial on it for every later fetch,
                // and dropping the older ones would discard a still-working fallback.
                //
                // Newest-first holds within the POOL's list; the eventual dial order additionally
                // prefers IPv6 over IPv4 (dig-download's `dial_candidates` sorts by family first,
                // per the ecosystem IPv6-first rule §5.2), so a freshly-adopted IPv4 address leads
                // only the IPv4 group, not the whole ladder (#1785d).
                let addrs = pool.entry(peer_id.to_hex()).or_default();
                addrs.retain(|known| known != addr);
                addrs.insert(0, *addr);
                retain_newest_per_family(addrs, MAX_POOL_ADDRS_PER_PEER);
            }
            PoolEvent::PeerRemoved { peer_id, .. } => {
                pool.remove(&peer_id.to_hex());
            }
        }
    }

    /// The live connected-pool map the download-side [`PoolProviderLocator`] reads (#1590). Exposed to
    /// tests so the gossip→pool feed's port translation can be exercised end-to-end (a `PoolEvent` fed
    /// through the real feed must land as a peer-RPC candidate, #836).
    #[cfg(test)]
    pub(crate) fn connected_pool(&self) -> ConnectedPool {
        self.connected_pool.clone()
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
        origin: ReadOrigin,
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

        // Tier-2 observability (#836): the read-leg fetch was invisible for six iterations because it
        // emitted no tracing — a live-but-misdialing path looked like "never invoked". Log the located
        // provider count (DHT ∪ connected pool) up front so a DATA miss shows whether locate found
        // anyone at all, and the terminal result below shows whether the fetch itself succeeded.
        // Gated on DEBUG being enabled (and placed after both cache-hit checks above) so a cached
        // re-serve — the common case — never pays this locate's cost; only an actual cache-miss
        // download does, and only when someone is watching at DEBUG.
        if tracing::enabled!(tracing::Level::DEBUG) {
            let located = self.find_providers(content).await.len();
            let pool_size = self
                .connected_pool
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len();
            tracing::debug!(
                content = %key,
                located,
                connected_pool = pool_size,
                "fetch_resource: located providers before download"
            );
        }

        // 3. Stage into a per-download final path under `<downloads>` (the FileSink writes
        //    `<final>.download.tmp` then atomically renames onto `<final>` on finalize).
        let final_path = self.downloads_dir.join(format!("{key}.bin"));
        let _ = std::fs::remove_file(&final_path); // a stale prior artifact must not shadow this fetch
        let sink: Arc<dyn dig_download::Sink> = Arc::new(FileSink::new(final_path.clone()));

        // 4. Run the multi-source download to completion (locate → confirm → fan ranges → verify per
        //    range + whole-resource against the chain-anchored root → reassemble → finalize). The
        //    injected SourceSelector seam (#1442) records every range outcome into the shared selector
        //    internally, so the models learn and the next select() is smarter — this just drains the
        //    progress stream + awaits the terminal result.
        let handle = self
            .downloader
            .download(*content, sink, DownloadOptions::default());
        self.drive_download(handle)
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
            cache.insert(key.clone(), fetched.clone());
        }
        let _ = std::fs::remove_file(&final_path);

        tracing::debug!(
            content = %key,
            bytes = fetched.bytes.len(),
            "fetch_resource: download complete"
        );

        // 7. RESHARE (#1576) — the step that closes the content-replication flywheel. The read above
        //    fetched only the bytes asked for, which leaves this node faster but the NETWORK no stronger:
        //    a `.dig` is served whole, so a node holding one resource can serve nothing. Kick a
        //    background pull of the ENTIRE capsule so this reader becomes a discoverable HOLDER of it,
        //    and every read makes the content MORE available than it found it.
        //
        //    Deliberately fire-and-forget: the read's latency is user-facing and a whole-capsule pull is
        //    orders of magnitude larger than the resource that revealed it, so the read never waits and a
        //    failed warm never fails the read. See `seams::dig_peer::module_reshare`.
        self.spawn_capsule_reshare(content, origin);
        Ok(fetched)
    }

    /// Start a background whole-capsule pull for the capsule `content` belongs to, if a
    /// [`CapsuleWarmer`](crate::seams::dig_peer::CapsuleWarmer) is wired.
    ///
    /// Refuses on any of three gates, each independently sufficient to skip the warm:
    /// - **`origin != Local`.** A REMOTE peer's `dig.fetchRange`/`dig.getContent` miss must NEVER
    ///   trigger a whole-capsule pull: unauthenticated (any well-formed self-signed mTLS leaf is
    ///   accepted, #179) and effectively free for the peer, it would let a stranger drive this node
    ///   into pulling + caching + DHT-announcing capsules of the ATTACKER'S choosing — a few hundred
    ///   bytes in for an entire capsule's worth of bandwidth + disk out, an attacker-shaped holder
    ///   inventory, and eviction pressure on the operator's own content (LRU evicts oldest-mtime
    ///   first, so a freshly-promoted attacker capsule outlives what it displaced). "A reader that
    ///   reads becomes a holder" means THIS node's own operator read, never a peer's.
    /// - **`!backfill_on_miss_enabled()`.** The documented, default-on, operator-facing
    ///   `DIG_NODE_BACKFILL_ON_MISS` kill switch — this leg is more of the SAME background
    ///   whole-capsule warm-up `maybe_backfill_capsule` already gates on it, so an operator who
    ///   turned it off must not have it silently re-enabled through a different code path.
    /// - **no warmer wired** — the FFI/base path, and any deployment that has not opted into
    ///   resharing; a read must work identically with or without the reshare leg.
    fn spawn_capsule_reshare(&self, content: &ContentId, origin: ReadOrigin) {
        if origin != ReadOrigin::Local || !backfill_on_miss_enabled() {
            return;
        }
        let Some(warmer) = self.capsule_warmer.get() else {
            return;
        };
        // Only a GENERATION-bearing id names a capsule to reshare. A store-granularity read does not say
        // WHICH generation to pull, and guessing (the chain tip, say) would reshare a capsule nobody
        // asked for.
        let (store, root) = match content {
            ContentId::Root { store_id, root } => (*store_id, *root),
            ContentId::Resource { store_id, root, .. } => (*store_id, *root),
            ContentId::Store { .. } => return,
        };
        crate::seams::dig_peer::spawn_capsule_warm(
            Arc::clone(warmer),
            hex::encode(store),
            hex::encode(root),
        );
    }

    /// Install the capsule warmer (the reshare leg, #1576). Called once by the composition root after
    /// the peer stack is up, since the warmer needs the live transport + DHT the engine also uses.
    ///
    /// Idempotent by `OnceLock`: a second install is ignored rather than swapping the warmer under a
    /// pull that is already in flight.
    pub fn set_capsule_warmer(&self, warmer: Arc<crate::seams::dig_peer::CapsuleWarmer>) {
        let _ = self.capsule_warmer.set(warmer);
    }

    /// Build + install the reshare leg from the pieces only the composition root has (#1576): this
    /// node's mTLS identity + shared NAT runtime, the CHAIN's root resolver, and the announce hook.
    ///
    /// Everything else — the discovery locator, the resume-state store, the live connected pool, the
    /// staging directory — is taken from the engine itself, so the reshare pull discovers and dials
    /// through exactly the same machinery the resource read does. Two independent locators would be two
    /// things to keep in sync, and the read leg's history is a catalogue of what happens when a dial path
    /// diverges from the one that was debugged (#836/#1590).
    ///
    /// `cache_dir` is the node's cache root; a promoted module lands at
    /// `<cache_dir>/modules/<store>/<root>.dig`, the path whose existence IS this node's holder claim.
    #[allow(clippy::too_many_arguments)]
    pub fn wire_capsule_reshare(
        self: &Arc<Self>,
        node_cert: Arc<dig_nat::NodeCert>,
        nat_config: dig_nat::NatConfig,
        network_id: &str,
        runtime: Arc<dig_nat::NatRuntime>,
        anchor_resolver: Arc<dyn crate::shared::AnchoredRootResolver>,
        announce: Arc<dyn crate::seams::dig_peer::AnnounceHolder>,
        cache_dir: &Path,
        // The node's SHARED single-flight acquisition gate (#1614). Passed in — NOT freshly created —
        // so this reshare warm claims the SAME registry the §21 backfill leg does; the two transports
        // for one capsule then dedup against each other instead of each pulling the whole `.dig`.
        capsule_acquisition: Arc<crate::seams::dig_peer::WarmRegistry>,
    ) {
        let transport = Arc::new(crate::seams::dig_peer::NatModuleTransport::new(
            node_cert,
            nat_config,
            network_id,
            runtime,
            self.connected_pool.clone(),
            self.locator.clone(),
        ));
        self.set_capsule_warmer(crate::seams::dig_peer::CapsuleWarmer::new(
            self.locator.clone(),
            transport,
            self.state_store.clone(),
            anchor_resolver,
            crate::seams::dig_peer::WarmPaths {
                // Stage under the downloads dir, NOT the cache: a module file at the cache path is
                // already this node's holder claim, so a partial pull must never live there.
                staging_dir: self.downloads_dir.clone(),
                cache_dir: cache_dir.to_path_buf(),
            },
            announce,
            capsule_acquisition,
            dig_download::ModuleDownloadConfig::default(),
        ));
    }

    /// Drain a running download's progress [`DownloadEvent`](dig_download::DownloadEvent) stream to
    /// exhaustion, then await the terminal result.
    ///
    /// dig-download 0.5 records every range outcome INTERNALLY through the injected
    /// [`SourceSelector`](dig_download::SourceSelector) seam ([`SelectorAdapter`], #1442) — the node no
    /// longer translates progress events into selector outcomes here. But the events channel is bounded,
    /// so the download task blocks on a full channel if nothing drains it; this loop consumes (and
    /// discards) events purely to keep the task making progress, then joins for the terminal result.
    async fn drive_download(
        &self,
        mut handle: dig_download::DownloadHandle,
    ) -> Result<u64, DownloadError> {
        while handle.next_event().await.is_some() {
            // Events are drained (not translated): the SourceSelector seam records outcomes internally.
        }
        handle.join().await
    }

    /// One staging-file GC sweep now: reap `.download.tmp` files older than `ttl` that no
    /// live/paused download owns (their sidecar resume state goes with them). Returns how many
    /// were removed.
    ///
    /// Sweeps BOTH staging locations, because dig-download's sweeper lists a single directory and does
    /// not recurse (#1615): resource downloads stage directly in `<downloads>/`, while whole-capsule
    /// warms stage in `<downloads>/modules/`. Sweeping only the former left every capsule pull that
    /// crashed mid-flight on disk permanently — growth an ordinary breadth of reads is enough to drive,
    /// with no attacker needed.
    ///
    /// Reaping is by AGE and by OWNERSHIP only: a staging file registered as live or paused-resumable is
    /// never touched, whatever its age. It therefore cannot interrupt a pull in progress, and — because
    /// it acts on download SCRATCH and never on a cached capsule — it can never evict content this node
    /// holds.
    pub async fn gc_once(&self, ttl: Duration) -> usize {
        let mut reaped = 0usize;
        for dir in [self.downloads_dir.clone(), self.module_staging_dir()] {
            reaped += self.downloader.gc(dir, ttl).await.unwrap_or(0);
        }
        // Age alone bounds staging only by what one TTL window can accumulate; the cap makes the
        // ceiling a fixed byte count (see [`Self::enforce_staging_cap`] for what it may and may not
        // evict).
        reaped + self.enforce_staging_cap().await
    }

    /// Where whole-capsule warms stage — `<downloads>/modules`, the subdirectory
    /// [`crate::seams::dig_peer::WarmPaths`] pulls into.
    fn module_staging_dir(&self) -> PathBuf {
        self.downloads_dir
            .join(crate::capsule_key::MODULE_STAGING_SUBDIR)
    }

    /// Bring total capsule-staging bytes back under [`MAX_MODULE_STAGING_BYTES`], reaping the OLDEST
    /// unprotected staging files first. Returns how many were removed.
    ///
    /// This is the bound the age sweep cannot give. Reaping at a TTL means staging is bounded by how
    /// much a caller can start within one TTL window, which breadth of reads alone can make large; this
    /// makes the ceiling a fixed number of bytes regardless of arrival rate.
    ///
    /// # What this policy does and does not permit
    ///
    /// Oldest-first eviction is safe HERE, and would not be one directory up. Everything this touches is
    /// whole-capsule download SCRATCH: an unprotected `.download.tmp` is an abandoned partial pull, and
    /// re-fetching it costs bandwidth and nothing else. So the worst a peer can achieve by driving reads
    /// is the deletion of incomplete scratch, which is re-derivable from the network.
    ///
    /// It specifically CANNOT reach two things. It never touches `<cache>/modules/` — the operator's
    /// held capsules — so a peer cannot use staging pressure to evict content this node hosts. And it
    /// never touches a staging file the registry reports as live or paused-resumable, so it cannot
    /// cancel a pull that is making progress. Those two exclusions are what make oldest-first acceptable
    /// here: applied to CACHED content, the same ordering would let a peer walk an operator's own oldest
    /// capsules off the disk simply by reading a lot of other ones.
    async fn enforce_staging_cap(&self) -> usize {
        self.reap_staging_over(MAX_MODULE_STAGING_BYTES).await
    }

    /// [`Self::enforce_staging_cap`] against an explicit `cap`, so the ordering + protection behaviour is
    /// testable without staging gigabytes.
    async fn reap_staging_over(&self, cap: u64) -> usize {
        let mut staging = Vec::new();
        let Ok(entries) = std::fs::read_dir(self.module_staging_dir()) else {
            return 0;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_staging = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".download.tmp"));
            if !is_staging {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            staging.push((path, modified, meta.len()));
        }

        let mut total: u64 = staging.iter().map(|(_, _, len)| *len).sum();
        if total <= cap {
            return 0;
        }
        staging.sort_by_key(|(_, modified, _)| *modified); // oldest first

        let mut removed = 0usize;
        for (path, _, len) in staging {
            if total <= cap {
                break;
            }
            if self.active_downloads().is_protected(&path).await {
                continue; // a pull in progress is never sacrificed to the cap
            }
            if std::fs::remove_file(&path).is_err() {
                continue;
            }
            let _ = std::fs::remove_file(path.with_extension("tmp.state"));
            total = total.saturating_sub(len);
            removed += 1;
        }
        if removed > 0 {
            tracing::info!(
                removed,
                remaining_bytes = total,
                cap_bytes = cap,
                "capsule staging over cap: reaped abandoned partial pulls"
            );
        }
        removed
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

    /// Whether the peer (Tier-2) content path is consultable RIGHT NOW (#1763).
    ///
    /// The peer network attaches ~30 s after the HTTP surface starts answering, so this is
    /// [`PeerTier::Unattached`](crate::content_serve::PeerTier::Unattached) for the whole
    /// cold-start window — and permanently on the FFI/in-process path, which brings up no peer
    /// network. It is reported per read (`X-Dig-Peer-Tier`) and on `GET /health`, which is what
    /// lets a caller wait for the peer tier deterministically instead of sleeping a guessed
    /// interval and hoping.
    pub fn peer_tier(&self) -> crate::content_serve::PeerTier {
        match self.p2p_content() {
            Some(_) => crate::content_serve::PeerTier::Attached,
            None => crate::content_serve::PeerTier::Unattached,
        }
    }

    /// Decide the #165 miss outcome for `content` at redirect depth `depth`: fetch-through when
    /// configured (falling back to redirect if the fetch fails), else locate + redirect within the
    /// hop budget, else not-found. NEVER a silent 404 while a provider exists.
    pub(crate) async fn miss_outcome(
        &self,
        content: &ContentId,
        depth: u64,
        origin: ReadOrigin,
    ) -> MissOutcome {
        // No P2P content engine (the in-process FFI path) → the caller's own not-found stands.
        let Some(pc) = self.p2p_content() else {
            return MissOutcome::NotFound;
        };

        // Fetch-through (opt-in): pull the resource from the holders via dig-download, serve it
        // directly. On any failure, fall through to the redirect so a provider-held resource is never
        // silently 404'd.
        if pc.miss_mode() == MissMode::FetchThrough {
            if let Ok(fetched) = pc.fetch_resource(content, origin).await {
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
        origin: ReadOrigin,
    ) -> Option<Value> {
        match self.miss_outcome(content, depth, origin).await {
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
        origin: ReadOrigin,
    ) -> Option<Value> {
        match self.miss_outcome(content, depth, origin).await {
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
pub(crate) mod tests {
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

    // -- connected-pool address bookkeeping (#1782 cap, #1784 wildcard guard) --------------------

    /// A `NodeContent` with no real transport — enough to drive `on_pool_event` and read the pool
    /// back. The download machinery is never exercised, so the mocks can be trivial.
    fn pool_only_content(dir: &std::path::Path) -> Arc<NodeContent> {
        NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(4, 1))),
            MissMode::FetchThrough,
            None,
            dir,
        )
    }

    /// Feed one `PeerAdded` for `peer` at `addr` through the real event path.
    fn feed_added(content: &NodeContent, peer: [u8; 32], addr: &str) {
        content.on_pool_event(&pool_event_to_selector(
            peer,
            PoolEventKind::Added {
                addr: addr.parse().expect("test address parses"),
            },
        ));
    }

    /// The addresses the pool currently holds for `peer`, newest first.
    fn pool_addrs(content: &NodeContent, peer: [u8; 32]) -> Vec<std::net::SocketAddr> {
        let pool = content.connected_pool();
        let guard = pool.lock().unwrap();
        guard.get(&hex::encode(peer)).cloned().unwrap_or_default()
    }

    /// #1782: a supersede republishes `PeerAdded` and fires NO `PeerRemoved`, so the address list
    /// must be capped rather than growing once per distinct `SocketAddr` ever seen. 5000 is the
    /// figure the security gate measured growing unbounded — well past `MAX_ADDRESSES_PER_RECORD`,
    /// so the cap cannot pass by accident of a small fixture.
    #[test]
    fn a_peer_that_supersedes_forever_never_exceeds_the_address_cap() {
        let td = tempfile::tempdir().unwrap();
        let content = pool_only_content(td.path());
        let peer = [0xA1; 32];

        for port in 10_000..15_000u16 {
            feed_added(&content, peer, &format!("203.0.113.7:{port}"));
        }

        let addrs = pool_addrs(&content, peer);
        assert_eq!(
            addrs.len(),
            MAX_POOL_ADDRS_PER_PEER,
            "5000 superseding sessions must leave at most the cap, not 5000 entries"
        );
        assert_eq!(
            addrs[0].port(),
            14_999,
            "the newest session still leads the pool's dial order"
        );
    }

    /// #1782 secondary: the ONE IPv4 address of a mostly-IPv6 peer must survive continued IPv6
    /// churn. A plain `truncate` keeps the newest 8 — all IPv6 here — and silently drops the only
    /// address of the fallback family, which the very short IPv6-first dial ladder downstream then
    /// cannot recover. The IPv4 address is adopted BEFORE the churn precisely so a
    /// newest-first-wins implementation cannot pass this by keeping it for recency.
    #[test]
    fn ipv6_churn_cannot_evict_a_peers_only_ipv4_address() {
        let td = tempfile::tempdir().unwrap();
        let content = pool_only_content(td.path());
        let peer = [0xB2; 32];

        feed_added(&content, peer, "203.0.113.7:9444");
        for n in 0..64 {
            feed_added(&content, peer, &format!("[2001:db8::{n:x}]:9444"));
        }

        let addrs = pool_addrs(&content, peer);
        assert_eq!(addrs.len(), MAX_POOL_ADDRS_PER_PEER);
        assert!(
            addrs.iter().any(|a| a.is_ipv4()),
            "the IPv4 fallback must survive IPv6 churn; got {addrs:?}"
        );
        assert!(
            addrs.iter().filter(|a| a.is_ipv6()).count() >= MAX_POOL_ADDRS_PER_PEER - 1,
            "IPv6 still fills the rest of the list — IPv6 is PREFERRED, not evicted (§5.2)"
        );
    }

    /// #1784: `[::]:0` — dig-nat's remote address for an accepted relayed circuit with no configured
    /// relay endpoint — must never become a peer's contact.
    ///
    /// The peer is given a WORKING address first and the assertion is that the working address is
    /// still there, still FIRST. That is what makes this test see the difference between skipping
    /// the event and recording-then-filtering: a filter applied when the pool is READ would leave
    /// the wildcard sitting at the head of the stored list, displacing the reachable address, and
    /// would still satisfy a bare "the wildcard is not returned" assertion.
    #[test]
    fn a_wildcard_relay_address_never_displaces_a_peers_real_address() {
        let td = tempfile::tempdir().unwrap();
        let content = pool_only_content(td.path());
        let peer = [0xC3; 32];

        feed_added(&content, peer, "203.0.113.7:9444");
        feed_added(&content, peer, "[::]:0");

        let addrs = pool_addrs(&content, peer);
        assert_eq!(
            addrs,
            vec!["203.0.113.7:9444".parse::<std::net::SocketAddr>().unwrap()],
            "the wildcard is dropped at the event, leaving the real address untouched and leading"
        );
    }

    /// #1784, control: a peer whose ONLY reported address is the wildcard is absent from the pool
    /// entirely — it must not appear as a fetch candidate with an unreachable target. Paired with
    /// the test above so "absent" cannot be achieved by dropping every peer.
    #[test]
    fn a_peer_known_only_by_a_wildcard_address_is_not_a_pool_candidate() {
        let td = tempfile::tempdir().unwrap();
        let content = pool_only_content(td.path());
        let wildcard_only = [0xD4; 32];
        let reachable = [0xE5; 32];

        feed_added(&content, wildcard_only, "[::]:0");
        feed_added(&content, reachable, "203.0.113.9:9444");

        assert!(
            pool_addrs(&content, wildcard_only).is_empty(),
            "an unreachable-only peer is not a candidate"
        );
        assert_eq!(
            pool_addrs(&content, reachable).len(),
            1,
            "a reachable peer in the same pool is unaffected"
        );
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
    fn range_frame_later_window_still_carries_metadata_and_bounds_offset() {
        // #1577: a fetch-through frame at a later offset carries its OWN verification metadata (the
        // metadata used to ride the first frame only, leaving later ranges with no declared root to
        // check them against). Byte-shape-identical to the locally-held serve path.
        let (f, content) = fetched(30, 3);
        let frame = f.range_frame(10, 10).expect("frame");
        assert_eq!(frame["offset"], json!(10));
        assert_eq!(frame["complete"], json!(false));
        assert_eq!(
            frame["chunk_lens"],
            json!(f.chunk_lens),
            "every frame declares the resource layout"
        );
        assert_eq!(frame["total_length"], json!(f.total_length));
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

        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("download succeeds");
        assert_eq!(f.bytes, content.bytes, "reassembled bytes match the source");
        assert_eq!(f.total_length, 30);
        assert_eq!(f.chunk_lens, content.chunk_lens);
        assert_eq!(f.root.as_deref(), Some(content.root.as_str()));
        assert_eq!(f.inclusion_proof, content.inclusion_proof);

        // A second fetch is served from the in-memory cache — no new peer fetches.
        let attempts_before = transport.attempts_for(&mock_peer_hex(1)).await
            + transport.attempts_for(&mock_peer_hex(2)).await;
        let f2 = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("cache hit");
        assert_eq!(f2.bytes, f.bytes);
        let attempts_after = transport.attempts_for(&mock_peer_hex(1)).await
            + transport.attempts_for(&mock_peer_hex(2)).await;
        assert_eq!(
            attempts_before, attempts_after,
            "no re-download on a cache hit"
        );
    }

    /// #1590 regression (the #836 read-leg blocker, run e2e-1062-20260725-043357): a capsule holder
    /// the reader is ALREADY CONNECTED to in the gossip pool — but whose DHT provider record the
    /// reader cannot dial (a direct address unreachable on a relayed/isolated net) — must still be a
    /// FETCH source. Before the fix the download's locate saw only the (empty/unreachable) DHT set and
    /// gave up, so Tier-2 peer fetch failed and the read fell through to the §21 upstream backfill →
    /// 404 despite a discoverable + connected holder. The connected pool peer is now offered to the
    /// downloader, so the fetch reaches it.
    #[tokio::test]
    async fn fetch_resource_uses_a_connected_pool_holder_when_dht_has_none() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        // The content-id root MUST equal the transport-reported root (dig-download #179 cross-check).
        let cid = anchored_cid_for(&content);
        let transport = Arc::new(MockRangeTransport::new(content.clone()));
        // DISCOVER via the DHT finds NOBODY reachable (the relayed-net holder's advertised record is
        // absent/undialable) — the exact e2e condition.
        let locator = Arc::new(MockProviderLocator::fixed(vec![]));
        let pc = NodeContent::new(
            locator,
            transport.clone(),
            MissMode::FetchThrough,
            None,
            td.path(),
        );

        // CONNECT ✅: the reader IS connected to the holder (peer 1) in the gossip pool.
        let holder = PeerId::from_bytes([1u8; 32]);
        let addr: std::net::SocketAddr = "10.0.0.1:9444".parse().unwrap();
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: holder,
            addr,
        });

        // DATA: the fetch must now reach the connected holder (was Err → 404 before the fix).
        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("fetch from the connected-pool holder");
        assert_eq!(f.bytes, content.bytes, "served bytes match the source");
        assert!(
            transport.attempts_for(&mock_peer_hex(1)).await >= 1,
            "the connected pool holder was actually fetched from"
        );
    }

    /// A [`RangeTransport`] that RECORDS the peer_id of EVERY dial it is asked to make (availability
    /// AND fetch), delegating the bytes to an inner [`MockRangeTransport`]. This closes the test gap
    /// that hid the #836 self-dial for nine iterations: a mock that serves bytes regardless of target
    /// cannot distinguish a holder-dial from a self-dial, so a fetch that dialed self could still
    /// "pass". Recording the target lets the test assert the dial went to the HOLDER, never self.
    struct TargetRecordingTransport {
        inner: MockRangeTransport,
        dialed: tokio::sync::Mutex<Vec<String>>,
    }

    impl TargetRecordingTransport {
        fn new(content: MockContent) -> Self {
            TargetRecordingTransport {
                inner: MockRangeTransport::new(content),
                dialed: tokio::sync::Mutex::new(Vec::new()),
            }
        }
        async fn was_dialed(&self, peer: &str) -> bool {
            self.dialed.lock().await.iter().any(|p| p == peer)
        }
    }

    #[async_trait::async_trait]
    impl RangeTransport for TargetRecordingTransport {
        async fn query_availability(
            &self,
            provider: &ProviderRecord,
            items: Vec<dig_nat::AvailabilityItem>,
        ) -> Result<dig_nat::AvailabilityResponse, DownloadError> {
            self.dialed
                .lock()
                .await
                .push(provider.provider_peer_id.clone());
            self.inner.query_availability(provider, items).await
        }
        async fn fetch_range(
            &self,
            provider: &ProviderRecord,
            req: &dig_nat::RangeRequest,
        ) -> Result<dig_download::FetchedRange, DownloadError> {
            self.dialed
                .lock()
                .await
                .push(provider.provider_peer_id.clone());
            self.inner.fetch_range(provider, req).await
        }
    }

    /// #836/#92 regression (run e2e-836-arb-20260725-084501): a reader whose OWN peer_id has leaked
    /// into the connected pool (a relay-introduced self-connection) must NEVER dial itself on the
    /// fetch path, and MUST dial the real connected holder. Before the fix the download locator's
    /// [`PoolProviderLocator`] was not self-excluded, so self was offered as a fetch candidate → the
    /// confirm dialed self (own IP → connection refused; relayed → refused self-dial), starving the
    /// round and dead-ending the read at 404 despite a reachable holder. The transport RECORDS every
    /// dial target, so a self-dial is caught even though a target-blind mock would have "passed".
    #[tokio::test]
    async fn fetch_never_dials_self_and_reaches_the_connected_holder() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        let cid = anchored_cid_for(&content);
        let transport = Arc::new(TargetRecordingTransport::new(content.clone()));

        // This node's own identity — and the self peer_id the engine must exclude on the fetch path.
        let self_id = mock_peer_hex(9);
        // The DHT discovers nobody reachable (the exact relayed-net condition).
        let locator = Arc::new(MockProviderLocator::fixed(vec![]));
        let pc = NodeContent::new(
            locator,
            transport.clone(),
            MissMode::FetchThrough,
            Some(self_id.clone()),
            td.path(),
        );

        // Model the e2e defect: BOTH the real holder (peer 1) AND this node itself (peer 9, via a
        // relay-introduced self-connection) appear in the connected pool.
        let holder = PeerId::from_bytes([1u8; 32]);
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: holder,
            addr: "10.0.0.1:9444".parse().unwrap(),
        });
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: PeerId::from_bytes([9u8; 32]),
            addr: "10.0.0.9:9444".parse().unwrap(),
        });

        // The fetch must succeed by reaching the holder — never self.
        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("fetch reaches the connected holder");
        assert_eq!(f.bytes, content.bytes, "served bytes match the source");

        assert!(
            !transport.was_dialed(&self_id).await,
            "the reader must NEVER dial itself on the fetch path (self-dial dead-ends the read)"
        );
        assert!(
            transport.was_dialed(&mock_peer_hex(1)).await,
            "the fetch must dial the real connected holder"
        );
    }

    /// A [`RangeTransport`] that models a REAL dial FAITHFULLY: the real content transport dials a
    /// SINGLE address — `provider.best_address()`, the FIRST *dialable* candidate in list order
    /// (dig-dht `record.rs`; `NatRangeTransport::provider_to_target`) — so it connects IFF that ONE
    /// address is the reachable one, NOT if ANY advertised address happens to be reachable. (A `.any()`
    /// model is the false-green trap: it "passes" whenever the reachable address is present ANYWHERE in
    /// the list, even when `best_address()` — the address actually dialed — is the unreachable one.)
    /// Records the peer_id of every `fetch_range` it actually served so a test can assert the fetch
    /// reached the holder over its reachable address.
    struct AddressAwareTransport {
        inner: MockRangeTransport,
        reachable: std::net::SocketAddr,
        served_fetch: tokio::sync::Mutex<Vec<String>>,
    }

    impl AddressAwareTransport {
        fn new(content: MockContent, reachable: std::net::SocketAddr) -> Self {
            AddressAwareTransport {
                inner: MockRangeTransport::new(content),
                reachable,
                served_fetch: tokio::sync::Mutex::new(Vec::new()),
            }
        }

        /// Whether the SINGLE address the real transport would dial — `best_address()`, the first
        /// dialable candidate in list order (dig-dht `record.rs`) — is the reachable one (IPv4-mapped
        /// IPv6 forms normalised). NOT `.any()`: a dial connects only to the one chosen address.
        fn is_reachable(&self, provider: &ProviderRecord) -> bool {
            let want_ip = self.reachable.ip().to_string();
            let want_port = self.reachable.port();
            // Mirror dig-dht `ProviderRecord::best_address`: the first candidate whose kind is dialable.
            match provider.addresses.iter().find(|a| a.kind.is_dialable()) {
                Some(best) => {
                    let host = best.host.trim_start_matches("::ffff:");
                    host == want_ip && best.port == want_port
                }
                None => false,
            }
        }

        async fn served_fetch_from(&self, peer: &str) -> bool {
            self.served_fetch.lock().await.iter().any(|p| p == peer)
        }
    }

    #[async_trait::async_trait]
    impl RangeTransport for AddressAwareTransport {
        async fn query_availability(
            &self,
            provider: &ProviderRecord,
            items: Vec<dig_nat::AvailabilityItem>,
        ) -> Result<dig_nat::AvailabilityResponse, DownloadError> {
            if !self.is_reachable(provider) {
                return Err(DownloadError::transport(
                    &provider.provider_peer_id,
                    "mock: unreachable address (dial refused)",
                ));
            }
            self.inner.query_availability(provider, items).await
        }
        async fn fetch_range(
            &self,
            provider: &ProviderRecord,
            req: &dig_nat::RangeRequest,
        ) -> Result<dig_download::FetchedRange, DownloadError> {
            if !self.is_reachable(provider) {
                return Err(DownloadError::transport(
                    &provider.provider_peer_id,
                    "mock: unreachable address (dial refused)",
                ));
            }
            self.served_fetch
                .lock()
                .await
                .push(provider.provider_peer_id.clone());
            self.inner.fetch_range(provider, req).await
        }
    }

    /// #1590/#836 regression (arbiter e2e c0954369, run e2e-836-arb-20260725-094734): the reader is
    /// CONNECTED to the capsule holder in the gossip pool at its REACHABLE address, but the DHT names
    /// the SAME peer_id at a DIFFERENT, UNREACHABLE address (a stale/relayed-net provider hint). The
    /// download locator unions the connected-pool source with the DHT source; the real transport dials
    /// a SINGLE address — `best_address()`, the FIRST dialable candidate in the merged list. Both a
    /// merge (so the reachable address is PRESENT) AND the right ORDER (so the reachable address LEADS)
    /// are required: with the pool source SECOND the merge appended the reachable :9444 AFTER the stale
    /// DHT hint, so `best_address()` still returned the unreachable address → every dial refused →
    /// `NoProviders`/`NotFound` → the read fell through to §21 upstream → DATA 404 despite a connected,
    /// dialable holder. The fix puts the connection-verified POOL source FIRST so its reachable address
    /// leads the list and `best_address()` selects the :9444 that actually connects. The
    /// [`AddressAwareTransport`] models `best_address()` (not `.any()`), so this test is RED under the
    /// old append-order and GREEN once the pool leads — it is the test that predicts the e2e DATA-green.
    #[tokio::test]
    async fn resource_fetch_uses_the_reachable_pool_address_when_the_dht_hint_is_unreachable() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        let cid = anchored_cid_for(&content);
        let reachable: std::net::SocketAddr = "10.0.0.1:9444".parse().unwrap();
        let transport = Arc::new(AddressAwareTransport::new(content.clone(), reachable));

        // DISCOVER: the DHT names the holder (peer 1) at an UNREACHABLE address (the exact e2e
        // condition — the advertised provider record carries an address the reader cannot dial).
        let holder = dig_dht::PeerId::from_bytes([1u8; 32]);
        let dht_record = ProviderRecord::new(
            &cid.to_key(),
            &holder,
            vec![dig_dht::CandidateAddr::direct("10.9.9.9", 1)],
            u64::MAX,
        );
        let locator = Arc::new(MockProviderLocator::fixed(vec![dht_record]));
        let pc = NodeContent::new(
            locator,
            transport.clone(),
            MissMode::FetchThrough,
            None,
            td.path(),
        );

        // CONNECT ✅: the reader IS connected to the SAME peer at the REACHABLE address in the pool.
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addr: reachable,
        });

        // DATA: the fetch must reach the holder over its reachable pool address (was Err → 404 before).
        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("fetch reaches the holder at its reachable pool address");
        assert_eq!(f.bytes, content.bytes, "served bytes match the source");
        assert!(
            transport.served_fetch_from(&mock_peer_hex(1)).await,
            "a fetchRange must reach the holder over its reachable pool address"
        );
    }

    /// A [`RangeTransport`] modelling a connected holder that ANSWERS `getAvailability` = NOT-available
    /// for the resource, yet WOULD serve the bytes if a `fetchRange` reached it. This is the read-leg
    /// sub-cause the address fix (#97) did NOT cover: the holder is connected AND reachable, `find_providers`
    /// offers it, but dig-download's `locate_and_confirm` drops every provider whose `query_availability`
    /// answer is not `available` — so NO `fetchRange` is ever issued and the read 404s, even though the
    /// holder holds (and would serve) the resource. Records the peer_id of every `fetch_range` served, so a
    /// test can assert whether a `fetchRange` was actually issued (the exact e2e symptom: a dial for the
    /// availability probe, then zero `fetchRange`).
    struct AvailabilityFalseButServesTransport {
        inner: MockRangeTransport,
        avail_calls: tokio::sync::Mutex<Vec<String>>,
        fetch_calls: tokio::sync::Mutex<Vec<String>>,
    }

    impl AvailabilityFalseButServesTransport {
        fn new(content: MockContent) -> Self {
            AvailabilityFalseButServesTransport {
                inner: MockRangeTransport::new(content),
                avail_calls: tokio::sync::Mutex::new(Vec::new()),
                fetch_calls: tokio::sync::Mutex::new(Vec::new()),
            }
        }
        async fn fetched_from(&self, peer: &str) -> bool {
            self.fetch_calls.lock().await.iter().any(|p| p == peer)
        }
        async fn availability_probed(&self, peer: &str) -> bool {
            self.avail_calls.lock().await.iter().any(|p| p == peer)
        }
    }

    #[async_trait::async_trait]
    impl RangeTransport for AvailabilityFalseButServesTransport {
        async fn query_availability(
            &self,
            provider: &ProviderRecord,
            items: Vec<dig_nat::AvailabilityItem>,
        ) -> Result<dig_nat::AvailabilityResponse, DownloadError> {
            self.avail_calls
                .lock()
                .await
                .push(provider.provider_peer_id.clone());
            // The holder answers NOT-available for every queried item (the confirm-says-no sub-cause).
            let answers = items
                .iter()
                .map(|_| dig_nat::AvailabilityAnswer::unavailable())
                .collect();
            Ok(dig_nat::AvailabilityResponse::new(answers))
        }
        async fn fetch_range(
            &self,
            provider: &ProviderRecord,
            req: &dig_nat::RangeRequest,
        ) -> Result<dig_download::FetchedRange, DownloadError> {
            self.fetch_calls
                .lock()
                .await
                .push(provider.provider_peer_id.clone());
            self.inner.fetch_range(provider, req).await
        }
    }

    /// #836 read-leg GROUND TRUTH (the confirm-gate sub-cause, arbiter e2e d1d1f728): the reader is
    /// CONNECTED to the capsule holder in the gossip pool at its REACHABLE address and `find_providers`
    /// offers it — but the holder's `getAvailability` answer for the resource is NOT-available, so
    /// dig-download's `locate_and_confirm` drops it and issues ZERO `fetchRange` (the exact e2e symptom:
    /// the availability probe dials :9444, then no `fetchRange`, then §21 upstream 400 → DATA 404). A
    /// connected-pool holder must NOT be gated behind a separate availability probe: it was specifically
    /// offered as a holder over a live connection, and the whole-resource merkle verify — not the
    /// self-reported availability flag — is the real integrity gate. This test drives the REAL
    /// fetch_resource→Downloader handoff and asserts a `fetchRange` reaches the connected holder. It is
    /// RED before the pool-confirm bypass (no `fetchRange` issued) and GREEN after.
    #[tokio::test]
    async fn connected_pool_holder_is_fetched_even_when_it_answers_availability_false() {
        let td = tempfile::tempdir().unwrap();
        let content = anchored_mock_content(30, 3);
        let cid = anchored_cid_for(&content);
        let transport = Arc::new(AvailabilityFalseButServesTransport::new(content.clone()));

        // The DHT discovers nobody reachable (the exact relayed-net condition) — the ONLY source of the
        // holder is the live connected pool.
        let locator = Arc::new(MockProviderLocator::fixed(vec![]));
        let pc = NodeContent::new(
            locator,
            transport.clone(),
            MissMode::FetchThrough,
            None,
            td.path(),
        );

        // CONNECT ✅: the reader IS connected to the holder (peer 1) in the pool at a reachable address.
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addr: "10.0.0.1:9444".parse().unwrap(),
        });

        // DATA: the fetch must reach the connected holder despite its availability=false answer.
        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("a connected-pool holder is fetched even when it answers availability=false");
        assert_eq!(f.bytes, content.bytes, "served bytes match the source");
        assert!(
            transport.fetched_from(&mock_peer_hex(1)).await,
            "a fetchRange MUST reach the connected holder (the exact e2e miss: zero fetchRange issued)"
        );
        // Sanity: the connected-pool holder's availability probe is bypassed (we go straight to fetch),
        // so a not-available answer can never drop a peer we are already connected to.
        assert!(
            !transport.availability_probed(&mock_peer_hex(1)).await,
            "a connected-pool holder must not be gated behind a separate availability probe"
        );
    }

    /// #836/#92: a self `PeerAdded` (relay-introduced self-connection) is dropped at the pool feed —
    /// it never enters the download-side connected pool, so it can never be offered as a fetch
    /// candidate. A genuine peer add is still recorded.
    #[tokio::test]
    async fn on_pool_event_drops_a_self_peer_added() {
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            Some(mock_peer_hex(9)),
            td.path(),
        );
        // A self add is ignored — neither the connected pool nor the selector registry learns it.
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: PeerId::from_bytes([9u8; 32]),
            addr: "10.0.0.9:9444".parse().unwrap(),
        });
        assert!(
            pc.connected_pool()
                .lock()
                .unwrap()
                .get(&mock_peer_hex(9))
                .is_none(),
            "a self entry must never enter the connected pool"
        );
        assert_eq!(
            pc.selector().snapshot().registry_size,
            0,
            "self is never registered as a selectable source"
        );
        // A genuine, non-self peer is still recorded.
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: PeerId::from_bytes([1u8; 32]),
            addr: "10.0.0.1:9444".parse().unwrap(),
        });
        assert!(
            pc.connected_pool()
                .lock()
                .unwrap()
                .get(&mock_peer_hex(1))
                .is_some(),
            "a genuine peer still enters the connected pool"
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
        assert!(pc
            .fetch_resource(&mock_content_id(), ReadOrigin::Local)
            .await
            .is_err());
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

    /// **Proves:** abandoned WHOLE-CAPSULE staging under `<downloads>/modules/` is reaped, sidecar and
    /// all, and a protected one there is not (#1615).
    ///
    /// **Catches:** sweeping only the top-level downloads directory. dig-download's `TmpGc::sweep_at`
    /// lists ONE directory and does not recurse, while module staging lives in the `modules/`
    /// SUBDIRECTORY — so a crash mid-pull left `<store>-<root>.dig.download.tmp` plus its `.state`
    /// sidecar on disk **forever**, unbounded and remote-triggerable.
    ///
    /// The fixture puts a stale orphan in EACH directory and a protected file alongside the subdirectory
    /// orphan. That shape matters: a sweep that reached only the top level would still reap one file and
    /// satisfy a bare "something was reaped" assertion, so the test names WHICH files survive.
    #[tokio::test]
    async fn gc_reaps_abandoned_module_staging_in_the_subdirectory_too() {
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let downloads = pc.downloads_dir().to_path_buf();
        let modules = downloads.join("modules");
        std::fs::create_dir_all(&modules).unwrap();
        let two_hours_ago = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - Duration::from_secs(7200),
        );
        let age = |p: &Path| filetime::set_file_mtime(p, two_hours_ago).unwrap();

        // A resource-level orphan at the top level (the case already covered) …
        let resource_orphan = downloads.join("dead.res.download.tmp");
        std::fs::write(&resource_orphan, b"x").unwrap();
        age(&resource_orphan);

        // … and an abandoned whole-capsule staging pair in the SUBDIRECTORY. Both paths are derived from
        // the FINAL capsule path the way the real warm derives them (`staging_path_for`), so the fixture
        // cannot drift from the names dig-download actually writes.
        let capsule_final = modules.join(format!("{}-{}.dig", "aa".repeat(32), "bb".repeat(32)));
        let capsule_orphan = dig_download::staging_path_for(&capsule_final);
        std::fs::write(&capsule_orphan, b"partial capsule").unwrap();
        age(&capsule_orphan);
        let sidecar = capsule_orphan.with_extension("tmp.state");
        std::fs::write(&sidecar, b"resume state").unwrap();
        age(&sidecar);

        // A capsule pull still in flight, equally old, in the same subdirectory.
        let capsule_live = dig_download::staging_path_for(&modules.join(format!(
            "{}-{}.dig",
            "cc".repeat(32),
            "dd".repeat(32)
        )));
        std::fs::write(&capsule_live, b"in flight").unwrap();
        age(&capsule_live);
        pc.active_downloads().register(capsule_live.clone()).await;

        let removed = pc.gc_once(Duration::from_secs(3600)).await;

        assert!(
            !capsule_orphan.exists(),
            "abandoned capsule staging in modules/ must be reaped"
        );
        assert!(
            !sidecar.exists(),
            "its .state sidecar goes with it, or the resume state outlives the staging it describes"
        );
        assert!(
            capsule_live.exists(),
            "an in-flight capsule pull must never be reaped out from under itself"
        );
        assert!(
            !resource_orphan.exists(),
            "the top-level orphan is still reaped"
        );
        assert_eq!(removed, 2, "both orphans counted, the protected pull not");
    }

    /// **Proves:** the staging cap is DERIVED from the bounds that govern a warm, so it always sits above
    /// what the maximum number of legitimate concurrent pulls needs (#1615).
    ///
    /// **Catches:** a hand-picked literal ceiling that a later raise of either underlying bound would
    /// leave too small — at which point the cap would evict healthy in-flight pulls on every sweep. Pinned
    /// from BOTH sides: strictly above the concurrent-warm worst case, and not absurdly above it.
    #[test]
    fn the_staging_cap_sits_above_the_worst_case_of_legitimate_concurrent_warms() {
        let concurrent_worst_case = crate::seams::dig_peer::DEFAULT_MAX_CONCURRENT_WARMS as u64
            * dig_download::DEFAULT_MAX_MODULE_SIZE;
        assert!(
            MAX_MODULE_STAGING_BYTES > concurrent_worst_case,
            "the cap ({MAX_MODULE_STAGING_BYTES}) must exceed what {} concurrent warms may legitimately \
             stage ({concurrent_worst_case}), or the cap fights the concurrency limit",
            crate::seams::dig_peer::DEFAULT_MAX_CONCURRENT_WARMS
        );
        assert!(
            MAX_MODULE_STAGING_BYTES
                <= concurrent_worst_case + dig_download::DEFAULT_MAX_MODULE_SIZE,
            "the headroom above the worst case is one generation, not an unbounded margin"
        );
    }

    /// **Proves:** when capsule staging exceeds the byte cap, the OLDEST unprotected partial pulls are
    /// reaped until it is back under — and an in-flight pull is never sacrificed, however old (#1615).
    ///
    /// **Catches:** a cap that evicts by arrival order without consulting the registry, which would let
    /// staging pressure cancel a pull that is actively making progress.
    ///
    /// The cap is driven with an injected ceiling rather than the 2.5 GiB production value, so the test
    /// does not have to write gigabytes; the ordering + protection logic under test is the same code.
    #[tokio::test]
    async fn the_staging_cap_reaps_the_oldest_abandoned_pull_but_never_a_live_one() {
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(10, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let modules = pc.downloads_dir().join("modules");
        std::fs::create_dir_all(&modules).unwrap();

        // Three staging files, ages strictly ordered oldest → newest, all YOUNGER than any TTL so the age
        // sweep cannot be what removes them. The oldest is also the PROTECTED one, so a cap that ignored
        // the registry would take it first and the assertion below would catch that specifically.
        let now = std::time::SystemTime::now();
        let mut paths = Vec::new();
        for (index, minutes) in [("old-live", 3u64), ("mid", 2), ("new", 1)] {
            let path = dig_download::staging_path_for(&modules.join(format!("{index}.dig")));
            std::fs::write(&path, vec![0u8; 4096]).unwrap();
            std::fs::write(path.with_extension("tmp.state"), b"resume").unwrap();
            filetime::set_file_mtime(
                &path,
                filetime::FileTime::from_system_time(now - Duration::from_secs(minutes * 60)),
            )
            .unwrap();
            paths.push(path);
        }
        let (live, mid, new) = (paths[0].clone(), paths[1].clone(), paths[2].clone());
        pc.active_downloads().register(live.clone()).await;

        // A cap of 8 KiB against 12 KiB staged: exactly one file must go.
        let removed = pc.reap_staging_over(8192).await;

        assert_eq!(
            removed, 1,
            "one 4 KiB file brings 12 KiB under an 8 KiB cap"
        );
        assert!(
            live.exists(),
            "the oldest file is an in-flight pull and must survive the cap"
        );
        assert!(
            !mid.exists(),
            "the oldest UNPROTECTED partial pull is the one reaped"
        );
        assert!(
            !mid.with_extension("tmp.state").exists(),
            "its resume sidecar goes with it, or the state outlives the staging it describes"
        );
        assert!(new.exists(), "the newest partial pull is kept");
    }

    // -- the peer selector (#178): the discovery → select → download → record_outcome loop ----------

    /// The gossip → selector `PoolEvent` map preserves identity and removal semantics (SPEC §5.4):
    /// the peer id is the same 32 bytes, the three reasons the selector shares map
    /// variant-for-variant, and `Reaped` — which the selector has no variant for — folds to the
    /// non-punitive `Disconnected`.
    #[test]
    fn pool_event_map_preserves_identity_and_removal_semantics() {
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
            // `Reaped` has no selector counterpart and folds to `Disconnected`. Pinned here so the
            // fold is a decision the suite states, not an accident a later edit can quietly change
            // into `Banned` — which would make an honestly-departed peer ineligible.
            (GossipRemovalReason::Reaped, PoolRemovalReason::Disconnected),
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

        let f = pc
            .fetch_resource(&cid, ReadOrigin::Local)
            .await
            .expect("download succeeds");
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

    // -- #1586 read-leg: the REAL transport against a loopback mTLS holder -------------------------

    /// A [`crate::peer::PeerRpcResponder`] standing in for a CONNECTED HOLDER on a real loopback mTLS
    /// listener. It serves `content` over `dig.fetchRange` in the SAME frame shape the node serves
    /// (`NodeContent`'s `fetch_range_frame`: first frame carries `total_length`/`chunk_lens`/`root`/
    /// `inclusion_proof`) and RECORDS every fetchRange it receives — so a test can assert the RPC was
    /// actually TRANSMITTED, not merely that a provider was located.
    /// The holder frames its answer in windows of this many bytes (the node's `RANGE_WINDOW`, scaled
    /// down) so the test exercises MULTI-FRAME reassembly, not just a one-frame answer.
    const HOLDER_FRAME_LEN: u64 = 8;

    struct RecordingHolder {
        content: MockContent,
        fetch_ranges: Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    }

    #[async_trait::async_trait]
    impl crate::peer::PeerRpcResponder for RecordingHolder {
        async fn handle_json_rpc(&self, req: Value) -> Value {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            json!({"jsonrpc":"2.0","id":id,"result":{}})
        }

        async fn handle_availability(&self, items: Value) -> Value {
            let n = items.as_array().map(|a| a.len()).unwrap_or(0);
            let answers: Vec<Value> = (0..n).map(|_| json!({"available": true})).collect();
            json!({"items": answers})
        }

        async fn stream_range(
            &self,
            req: Value,
            _conn_key: &str,
            out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
        ) -> std::io::Result<()> {
            let offset = req.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let length = req.get("length").and_then(Value::as_u64).unwrap_or(0);
            self.fetch_ranges.lock().unwrap().push((offset, length));
            let total = self.content.bytes.len() as u64;
            let requested_end = (offset + length).min(total);
            // Frame the window exactly as the node does: successive frames of at most
            // `HOLDER_FRAME_LEN` bytes, each carrying its own offset, the last one `complete`.
            let mut start = offset.min(total);
            loop {
                let end = (start + HOLDER_FRAME_LEN).min(requested_end);
                let window = &self.content.bytes[start as usize..end as usize];
                let complete = end >= requested_end;
                let mut frame = json!({
                    "offset": start,
                    "length": window.len(),
                    "bytes": base64::engine::general_purpose::STANDARD.encode(window),
                    "complete": complete,
                });
                if start == 0 {
                    if let Some(obj) = frame.as_object_mut() {
                        obj.insert("total_length".into(), json!(total));
                        obj.insert("chunk_lens".into(), json!(self.content.chunk_lens));
                        obj.insert("chunk_index".into(), json!(0));
                        obj.insert("root".into(), json!(self.content.root));
                        if let Some(proof) = &self.content.inclusion_proof {
                            obj.insert("inclusion_proof".into(), json!(proof));
                        }
                    }
                }
                crate::peer::write_framed(out, &frame).await?;
                if complete {
                    return Ok(());
                }
                start = end;
            }
        }
    }

    /// A deterministic 32-byte identity seed from a label (no hard-coded crypto literal).
    fn keytrace_seed(label: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(label.as_bytes()).into()
    }

    fn keytrace_identity(label: &str) -> Arc<dig_tls::NodeCert> {
        let dir = tempfile::tempdir().expect("cert tempdir");
        crate::peer::load_or_generate_node_cert(dir.path(), &keytrace_seed(label)).expect("cert")
    }

    /// #1586 read-leg GROUND TRUTH over the REAL transport: the reader is CONNECTED to the holder in
    /// the gossip pool, and the fetch must TRANSMIT a `dig.fetchRange` RPC to it. Every prior #836
    /// regression test asserted at a MOCK `RangeTransport` — so the whole real leg (dig-download's
    /// `NatRangeTransport` → dig-peer mTLS → the holder's range stream → frame reassembly) was
    /// unexercised, and the arbiter e2e kept failing with ZERO inbound at the holder. This drives the
    /// production wiring end-to-end over a loopback mTLS listener and asserts the HOLDER SAW the RPC.
    #[tokio::test]
    async fn connected_pool_holder_receives_a_real_fetch_range_rpc_over_mtls() {
        crate::peer::install_crypto_provider();
        let content = anchored_mock_content(30, 3);
        let cid = anchored_cid_for(&content);
        let fetch_ranges = Arc::new(std::sync::Mutex::new(Vec::new()));

        // HOLDER: a real mTLS peer-RPC listener on loopback serving the anchored content.
        let holder_identity = keytrace_identity("keytrace-holder");
        let holder_peer_id = holder_identity.peer_id();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder: Arc<dyn crate::peer::PeerRpcResponder> = Arc::new(RecordingHolder {
            content: content.clone(),
            fetch_ranges: fetch_ranges.clone(),
        });
        let server = tokio::spawn(crate::peer::serve_peer_rpc_listener(
            listener,
            holder_identity,
            responder,
        ));

        // READER: the PRODUCTION download wiring over the REAL dig-nat/dig-peer transport.
        let td = tempfile::tempdir().unwrap();
        let reader_identity = keytrace_identity("keytrace-reader");
        let nat_config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(5))
            .build();
        let transport: Arc<dyn RangeTransport> = Arc::new(NatRangeTransport::new(
            reader_identity,
            nat_config,
            "DIG_MAINNET",
        ));
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            transport,
            MissMode::FetchThrough,
            None,
            td.path(),
        );

        // CONNECT: the holder is in the reader's connected pool at its real loopback address.
        pc.on_pool_event(&PoolEvent::PeerAdded {
            peer_id: holder_peer_id,
            addr,
        });

        let fetched = pc.fetch_resource(&cid, ReadOrigin::Local).await;

        // The load-bearing assertion: the RPC LEFT THE MACHINE and the holder SAW it.
        let seen = fetch_ranges.lock().unwrap().clone();
        assert!(
            !seen.is_empty(),
            "a dig.fetchRange RPC must be TRANSMITTED to the connected holder (holder saw none; \
             fetch result: {:?})",
            fetched.as_ref().map(|_| "ok").map_err(|e| e.clone())
        );
        let bytes = fetched
            .expect("the connected holder serves the resource")
            .bytes
            .clone();
        assert_eq!(
            bytes, content.bytes,
            "served bytes match the holder's content"
        );
        server.abort();
    }

    // -- spawn_capsule_reshare's ReadOrigin gate — exercised, not merely present (#1619 follow-up) --
    //
    // A guard nothing ever fails to satisfy is a guard a later refactor can drop or invert with every
    // existing test staying green. These prove each term of `origin != Local ||
    // !backfill_on_miss_enabled()` independently, and are designed to fail LOUDLY (not merely time
    // out) if either term is deleted: `spawn_capsule_reshare_would_start_a_warm_when_gated_open`
    // below is the control that proves the harness itself can observe a started warm at all.

    /// A resolver whose `anchored_root` NEVER completes. Wiring this onto a [`CapsuleWarmer`] parks
    /// any started `warm()` inside its first await point for the life of the test — turning "did a
    /// warm even start" from a race against a fast mock success/failure into a STABLE fact: the
    /// registry claim (synchronous, the very first thing `warm()` does) either happened before the
    /// parked await, or it never happened at all.
    struct HangingResolver;

    #[async_trait::async_trait]
    impl crate::shared::AnchoredRootResolver for HangingResolver {
        async fn anchored_root(
            &self,
            _store_id: &[u8; 32],
        ) -> Result<Option<digstore_core::Bytes32>, String> {
            std::future::pending().await
        }
    }

    /// An [`AnnounceHolder`](crate::seams::dig_peer::AnnounceHolder) that is never reached (the
    /// hanging resolver means no warm in these tests ever gets past its first await).
    struct UnreachedAnnounce;

    #[async_trait::async_trait]
    impl crate::seams::dig_peer::AnnounceHolder for UnreachedAnnounce {
        async fn announce_inventory(&self) {
            unreachable!("no warm in this test should ever reach an announce")
        }
    }

    /// Wire a permanently-parked [`CapsuleWarmer`] onto `pc` and return its [`WarmRegistry`] plus the
    /// exact generation key `warm()` claims — so a test can poll `registry.is_warming(&key)` to learn
    /// whether `spawn_capsule_reshare` actually reached the point of starting a pull.
    pub(crate) fn wire_hanging_warmer(
        pc: &NodeContent,
        td: &tempfile::TempDir,
    ) -> (Arc<crate::seams::dig_peer::WarmRegistry>, ContentId, String) {
        let registry = Arc::new(crate::seams::dig_peer::WarmRegistry::new());
        let warmer = crate::seams::dig_peer::CapsuleWarmer::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(dig_download::testkit::MockModuleTransport::serving(
                &hex::encode([0xaa; 32]),
                &hex::encode([0xbb; 32]),
                vec![],
                8,
            )),
            Arc::new(FileStateStore::new(td.path().join("warm-state"))),
            Arc::new(HangingResolver),
            crate::seams::dig_peer::WarmPaths {
                staging_dir: td.path().join("warm-staging"),
                cache_dir: td.path().join("warm-cache"),
            },
            Arc::new(UnreachedAnnounce),
            Arc::clone(&registry),
            dig_download::ModuleDownloadConfig::default(),
        );
        pc.set_capsule_warmer(warmer);
        let content = ContentId::resource([0xaa; 32], [0xbb; 32], [0xcc; 32]);
        let key = format!("{}:{}", hex::encode([0xaa; 32]), hex::encode([0xbb; 32]));
        (registry, content, key)
    }

    /// Poll `registry.is_warming(key)` for up to `bound` for it to become `true`, so a positive
    /// assertion never races a `tokio::spawn`'s scheduling latency. Returns whether it was observed.
    pub(crate) async fn wait_for_warm_started(
        registry: &crate::seams::dig_peer::WarmRegistry,
        key: &str,
        bound: std::time::Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + bound;
        while tokio::time::Instant::now() < deadline {
            if registry.is_warming(key) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        registry.is_warming(key)
    }

    /// **The control:** with the gate wide open (`Local`, backfill on), `spawn_capsule_reshare` DOES
    /// start a warm — proving the harness above can observe a started warm at all, so the two refusal
    /// tests below are not merely "nothing ever happens here regardless".
    #[tokio::test]
    async fn spawn_capsule_reshare_would_start_a_warm_when_gated_open() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default ON
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(1, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let (registry, content, key) = wire_hanging_warmer(&pc, &td);

        pc.spawn_capsule_reshare(&content, ReadOrigin::Local);
        drop(_g); // the env decision is already made (synchronously, above) — never held across an await

        assert!(
            wait_for_warm_started(&registry, &key, std::time::Duration::from_millis(500)).await,
            "the control case must observe a started warm, or the two refusal tests below prove nothing"
        );
    }

    /// **Proves:** a `Peer`-origin read NEVER starts a capsule warm, however long the harness waits —
    /// the exact defect this PR's security gate closes (a remote peer driving this node into pulling,
    /// caching, and DHT-announcing a capsule of the PEER'S choosing).
    /// **Catches:** `origin != ReadOrigin::Local` being dropped or inverted from `spawn_capsule_reshare`
    /// — deleting that term made this test the ONLY one in the crate that fails (verified: RED).
    #[tokio::test]
    async fn spawn_capsule_reshare_refuses_a_peer_origin() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default ON — origin alone must refuse
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(1, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let (registry, content, key) = wire_hanging_warmer(&pc, &td);

        pc.spawn_capsule_reshare(&content, ReadOrigin::Peer);
        drop(_g); // the env decision is already made (synchronously, above) — never held across an await

        assert!(
            !wait_for_warm_started(&registry, &key, std::time::Duration::from_millis(500)).await,
            "a Peer-origin read must never start a capsule warm"
        );
    }

    /// **Proves:** the `DIG_NODE_BACKFILL_ON_MISS` kill switch refuses a warm even at `Local` origin —
    /// the operator-facing off switch must not be silently bypassed by the reshare leg.
    /// **Catches:** `!backfill_on_miss_enabled()` being dropped from `spawn_capsule_reshare` —
    /// deleting that term made this test the ONLY one in the crate that fails (verified: RED).
    #[tokio::test]
    async fn spawn_capsule_reshare_refuses_when_backfill_is_disabled() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_BACKFILL_ON_MISS", "off");
        let td = tempfile::tempdir().unwrap();
        let pc = NodeContent::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            Arc::new(MockRangeTransport::new(MockContent::even(1, 1))),
            MissMode::Redirect,
            None,
            td.path(),
        );
        let (registry, content, key) = wire_hanging_warmer(&pc, &td);

        pc.spawn_capsule_reshare(&content, ReadOrigin::Local);
        drop(_g); // the env decision is already made (synchronously, above) — never held across an await

        let started =
            wait_for_warm_started(&registry, &key, std::time::Duration::from_millis(500)).await;
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        assert!(
            !started,
            "DIG_NODE_BACKFILL_ON_MISS=off must refuse even a Local-origin read"
        );
    }

    #[tokio::test]
    async fn capturing_state_store_persists_bad_descriptor_reputation_across_restart() {
        // #1629: `CapturingStateStore` wraps `FileStateStore` but must DELEGATE the bad-descriptor
        // reputation methods, not inherit the trait's forgetful no-op defaults — otherwise a holder
        // that served a lying descriptor is re-asked from scratch after every restart, paying the
        // same wasted pull attempts again (#1611). Record a verdict through one wrapper, then read it
        // back through a FRESH wrapper over the SAME on-disk store (a simulated process restart): the
        // verdict must survive. Without delegation this returns empty, because the record went to the
        // no-op default and never reached the file store.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let target = "a".repeat(64);
        let peer = "b".repeat(64);

        let before = CapturingStateStore::new(FileStateStore::new(state_dir.clone()));
        before.record_bad_descriptor(&target, &peer).await.unwrap();

        let after = CapturingStateStore::new(FileStateStore::new(state_dir));
        let peers = after.bad_descriptor_peers(&target).await.unwrap();
        assert_eq!(
            peers,
            vec![peer],
            "a recorded bad-descriptor verdict must persist across a restart"
        );
    }

    // -- RequestProvenance::from_sec_fetch_site (Sec-Fetch-Site → landing-gate axis) ---------------

    #[test]
    fn sec_fetch_site_cross_site_is_cross_site() {
        assert_eq!(
            from_sec_fetch_site(Some("cross-site")),
            RequestProvenance::CrossSite,
            "an explicit cross-site fetch must be classified CrossSite so landing is suppressed"
        );
    }

    #[test]
    fn sec_fetch_site_first_party_values_are_first_party() {
        for value in ["same-origin", "same-site", "none"] {
            assert_eq!(
                from_sec_fetch_site(Some(value)),
                RequestProvenance::FirstParty,
                "{value} is a first-party fetch and must land normally"
            );
        }
    }

    #[test]
    fn sec_fetch_site_absent_is_first_party() {
        // LOAD-BEARING: non-browser clients (CLI/SDK) send no Sec-Fetch-* header. Absence must map
        // to FirstParty, never CrossSite — otherwise every CLI/SDK read would stop landing.
        assert_eq!(
            from_sec_fetch_site(None),
            RequestProvenance::FirstParty,
            "an absent Sec-Fetch-Site header must be treated as first-party"
        );
    }

    #[test]
    fn sec_fetch_site_is_case_insensitive_and_trims() {
        assert_eq!(
            from_sec_fetch_site(Some("  Cross-Site ")),
            RequestProvenance::CrossSite,
            "the header match must be trimmed + case-insensitive"
        );
    }

    #[test]
    fn sec_fetch_site_unknown_value_is_first_party() {
        // Only an explicit "cross-site" denies landing; an unrecognized value fails OPEN (serves +
        // lands) so a future/odd Sec-Fetch-Site value never silently breaks landing.
        assert_eq!(
            from_sec_fetch_site(Some("wat")),
            RequestProvenance::FirstParty,
            "an unknown Sec-Fetch-Site value must default to first-party"
        );
    }
}
