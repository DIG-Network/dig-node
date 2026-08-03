//! dig-node — the DIG Browser's local node sidecar.
//!
//! A loopback JSON-RPC server implementing the SAME `dig.getContent` contract as
//! rpc.dig.net, but LOCAL-FIRST: a `dig://` request is served from a locally
//! cached `.dig` store module (via `digstore_host::serve_blind`, which
//! instantiates the compiled module and returns a `ContentResponse` =
//! ciphertext + merkle proof + chunk_lens), and only on a cache miss is it
//! proxied to rpc.dig.net. The browser points its dig handler at this node, so
//! once a store is cached locally every resource in it is served without leaving
//! the machine. Cached store modules under `<cache>/modules` are bounded by a
//! TIER-AWARE size-cap LRU (default 1 GiB, [`cache_cap_bytes`]): under disk
//! pressure the self-driven `Tier0Precache` lands are evicted FIRST, so
//! demand-driven / pinned capsules survive a precache sweep ([`Node::evict_modules_if_needed`]).
//!
//! Native Rust so the compiled-module serve path (BLS, wasmtime) works.
//!
//! Cache layout: `<cache_dir>/modules/<store_id_hex>/<root_hex>.dig` — the compiled
//! module bytes for that store at that root. The browser sends a concrete root
//! (rootless URNs are resolved to the singleton tip by dig-resolver first), so a
//! module is keyed by (store_id, root).
//!
//! Authenticated whole-store sync (§21.9): on a local cache miss for a concrete
//! (store, root), the node fetches the WHOLE `.dig` module from rpc.dig.net's §21
//! `GET /stores/{id}/module` endpoint and caches it, then serves every subsequent
//! resource in that store locally. That endpoint is dighub-auth gated (it 401s for
//! anonymous clients), so the node carries a native Chia identity signer (paper
//! §21.9): it stamps `X-Dig-Identity/-Timestamp/-Nonce/-Auth` on the request using
//! the SAME persistent identity key the digstore CLI uses
//! ([`digstore_remote::identity`]). The signer is best-effort — if no identity key
//! is available the node simply skips the authenticated sync and falls back to the
//! per-resource proxy below, so it still serves whatever modules are already
//! present (e.g. the user's own digstore stores) and proxies the rest.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use base64::Engine;
use capsule_key::{is_canonical_hex_id, CapsuleKey};
use digstore_chain::singleton::sync_datastore;
use digstore_core::codec::{Decode, Encode};
use digstore_core::Bytes32;
use digstore_host::{serve_blind, BlindServeConfig};
use digstore_remote::{identity, DigClient};
use fs4::FileExt;
use serde_json::{json, Value};
use shared::ContentResponse;
use tokio::sync::Mutex;

mod capsule_key;
pub mod chainwatch;
pub mod chat;
pub mod dht_sampling;
pub mod download;
pub mod inbound_demand;
mod module_tier_tag;
pub mod peer;
pub mod relevance;
/// The 7 architecturally-separated seams (#1285/#1303), populated incrementally across the
/// W1b sub-PR sequence. Modules re-exported below at their ORIGINAL crate-root path keep
/// every existing `crate::net`/`crate::pex`/… reference working unchanged (W1b-0 is a pure
/// relocation — no behaviour change, no caller updates required).
pub mod seams;
pub mod tier0_live;
pub mod tier0_prefetch;
pub mod tier0_selector;
/// The `CapsuleStore` trait is seam 6's public surface (#1285 W1b-4) — bring it into scope to call
/// `cache_list_cached`/`cache_remove_cached`/`cache_fetch_and_cache`/`gap_fill_generation`/
/// `maybe_backfill_capsule`/`set_self_ref`/`arc_self` on a `Node`.
pub use seams::capsule::CapsuleStore;
pub(crate) use seams::chia_peer::{default_anchored_resolver, resolution_coinset};
/// The `ChainSource` trait is seam 1's public surface (#1285 W1b-3) — bring it into scope to call
/// `anchored_root_resolver_arc` on a `Node`. `CoinsetResolver` is public (production impl callers
/// may reference); `default_anchored_resolver`/`resolution_coinset` stay crate-internal, as before.
pub use seams::chia_peer::{ChainSource, CoinsetResolver};
/// Local plaintext content-serve (#289/#290): server-side verify+decrypt for the loopback
/// `GET /s/...` surface the service shell exposes to a same-machine browser (SPEC §4.6). The
/// `ContentServer` trait is this seam's public surface (#1285 W1b-1) — bring it into scope to
/// call `serve_content_plaintext`/`manifest_paths`/`resource_generation` on a `Node`.
pub use seams::content::content_serve;
pub use seams::content::{bandwidth, verification_ledger, ContentServer};
/// The `PeerNetwork` trait is seam 2's public surface (#1285 W1b-2) — bring it into scope to
/// call `peer_status`/`set_inventory_refresher`/`set_gossip_handle`/`gossip_handle`/
/// `refresh_dht_inventory` on a `Node`.
pub use seams::dig_peer::{address_book, dht, net, pex, session, PeerNetwork};
/// The `RpcDispatch` trait is seam 4's public surface (#1285 W1b-5) — the crate-root
/// `handle_rpc`/`handle_rpc_json` free functions delegate to it; most callers keep using those
/// stable entry points and never need this trait in scope directly.
pub use seams::dig_rpc::RpcDispatch;
/// The `KeyManager` trait is seam 7's public surface (#1285 W1b-6) — bring it into scope to call
/// `peer_id_hex`/`identity_seed_for_peer`/`peer_cert_dir`/`node_cert_dir` on a `Node`. #908
/// boundary: this seam holds ONLY the node's machine identity — never a user key.
pub use seams::key_mgmt::KeyManager;
/// Cross-seam shared vocabulary (#1285 W1a) — the ONLY types the node's seams (peer, wallet, rpc,
/// local-content, capsule, chain, key-management) are allowed to share; see the module doc.
pub mod shared;
pub mod subscription;

// The one place the per-range verification contract of a `dig.fetchRange` frame is built (#1577).
use seams::content::range_frame;
// Serve-side observability vocabulary for the peer-facing read surface (#1595).
use seams::dig_peer::serve_log;

/// The node engine library's own crate version (its `Cargo.toml` `version`), for
/// programmatic use by host shells. Host shells report the SHIPPED node version to
/// consumers as the single canonical `version` field, and pin the exact engine source
/// via the build `commit` (this engine is an in-repo sibling crate), so this crate
/// version is NOT surfaced under a second status key (#586 removed the former
/// `dig_node_version`).
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON-RPC error code: the served/requested root is NOT the store's
/// chain-anchored root (gap #127). A content read is gated on this: it serves
/// against the CHIP-0035 singleton's current on-chain root or it FAILS CLOSED
/// with this code — a compromised upstream/host can never pick which generation
/// is served, and a module that carries no on-chain anchor is rejected (not
/// silently downgraded to a no-op). Catalogued in docs.dig.net error tables and
/// uniform with the CLI clone/pull pin (which fails closed with the same
/// "chain is the authority" semantics).
pub(crate) const ROOT_NOT_ANCHORED: i64 = -32005;

/// The resource is not available at the requested root — this node does not hold it and no other
/// tier produced it. Catalogued as `RESOURCE_NOT_AVAILABLE_AT_ROOT` (dig-node `SPEC.md` error table)
/// and already the code the read path returns for content it does not have.
///
/// Named here (#1997) because the read path now reaches it in a NEW way: with no upstream configured
/// — the default — a miss that no peer served ends here rather than at an upstream error. That
/// distinction is the point. `-32000 "upstream: …"` tells a caller the node's configuration failed;
/// `-32004` tells them the resource is not available, which is the true and actionable answer.
pub(crate) const RESOURCE_NOT_AVAILABLE: i64 = -32004;

// -- Canonical control-plane error taxonomy (dig-rpc-types §10, #200) ------------------------------
//
// The control-plane errors adopt the CANONICAL numbering + machine codes from the `dig-rpc-types`
// crate (`ErrorCode::Unauthorized`/`NotSupported`/`ControlError`), which is the single source of
// truth both DIG node implementations track. These renumber the control-plane errors CLEAR of the
// onion codes: `-32020`/`-32021`/`-32022` are RESERVED for the onion (private-retrieval) failures
// (SPEC §2.6), so the control-plane codes are `-32030`/`-32031`/`-32032`. Kept as byte-identical
// constants (rather than a crate dep) because `dig-rpc-types` is a private sibling repo the digstore
// CI cannot fetch — the numbers + machine strings mirror it exactly, and the shared value is the
// wire contract (asserted in `control_error_codes_match_dig_rpc_types`). Full type-level adoption of
// the `dig-rpc-types` `RpcError` struct is a tracked follow-up (#200b) gated on that repo being
// public / a workspace vendoring.

/// `UNAUTHORIZED` — a control-plane call is not authorized (loopback / token gate). `data.code` =
/// `"UNAUTHORIZED"`, `data.origin` = `"control"`.
const CONTROL_UNAUTHORIZED: i64 = -32030;
/// `NOT_SUPPORTED` — a control-plane method is recognized but not supported on this node. `data.code`
/// = `"NOT_SUPPORTED"`, `data.origin` = `"control"`.
#[allow(dead_code)]
const CONTROL_NOT_SUPPORTED: i64 = -32031;
/// `CONTROL_ERROR` — a control-plane runtime error (subscription persistence, config write, sync
/// trigger). `data.code` = `"CONTROL_ERROR"`, `data.origin` = `"control"`.
const CONTROL_ERROR: i64 = -32032;

/// Build a control-plane JSON-RPC error carrying the canonical `{code, message, data:{code, origin}}`
/// envelope (`dig-rpc-types` §10) — `data.code` is the stable `UPPER_SNAKE_CASE` machine key an agent
/// branches on, `data.origin` is `"control"`. Used by the loopback/in-process control methods
/// (`control.subscribe` / `control.unsubscribe` / …) so their errors are machine-branchable + never
/// drift from the canonical taxonomy.
fn control_err(id: &Value, code: i64, message: &str) -> Value {
    let machine = match code {
        CONTROL_UNAUTHORIZED => "UNAUTHORIZED",
        CONTROL_NOT_SUPPORTED => "NOT_SUPPORTED",
        _ => "CONTROL_ERROR",
    };
    json!({"jsonrpc":"2.0","id":id,"error":{
        "code": code,
        "message": message,
        "data": { "code": machine, "origin": "control" }
    }})
}

/// The upstream a node uses when `DIG_NODE_UPSTREAM` is unset: **none** (#1997).
///
/// This was `https://rpc.dig.net/`, which made every embedder of this crate — including the DIG
/// Browser's in-process node, which calls [`Node::from_env`] directly and never goes through the
/// service shell — fall back to one well-known host for any read it could not satisfy. That is the
/// structurally-special-node property the ticket removed, and leaving it here would have kept it
/// alive for every consumer that is not the `dig-node` binary.
const RPC_FALLBACK: &str = "";
/// Per-window ciphertext cap (bytes) when paging the JSON-RPC response.
const WINDOW: usize = 3 * 1024 * 1024;
/// Default LRU cap for the on-disk module cache.
const DEFAULT_CACHE_CAP: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Hard cap on the number of `launcher_ids` accepted by `dig.getCollection` /
/// `dig.listCollectionItems` (audit #179 HIGH). These are peer-reachable and each launcher id
/// costs one chain (coinset.org) read, so an uncapped array is an outbound-fanout amplifier;
/// an over-cap request is rejected before any chain read. Chosen generously (a large collection
/// still fits) while bounding the per-request fanout. `dig.listCollectionItems` still paginates
/// within this at ≤200 per page.
const MAX_LAUNCHER_IDS: usize = 10_000;

/// Hard cap on the number of `items` a single `dig.getAvailability` batch answers (audit #179).
/// This is a peer-reachable path with a caller-controlled item count; each held-resource item can
/// also read+decrypt a module, so an uncapped batch is a fanout amplifier. Items past the cap are
/// not answered (the aligned result array stops at the cap).
const MAX_AVAILABILITY_ITEMS: usize = 512;

/// Soft budget (bytes) for the in-memory decoded-content LRU (audit #179). Serving a resource
/// window re-reads + wasmtime-decrypts the WHOLE module per window; caching the decoded
/// [`ContentResponse`] lets successive windows of the same resource slice from RAM (O(n) instead
/// of O(n²) over a streamed resource). Bounded so the cache can never grow without limit — the
/// least-recently-used entries are evicted once the total cached ciphertext exceeds this. 256 MiB
/// comfortably holds a few large resources' decoded ciphertext while capping node memory.
const CONTENT_CACHE_MAX_BYTES: u64 = 256 * 1024 * 1024;

// -- Session cache telemetry (#279) ------------------------------------------
//
// Process-global counters surfaced by the OPEN `cache.stats` RPC so a controller
// (the dig-chrome-extension control panel) can show how the LRU cap is behaving:
// how much the disk cache has evicted this run, and the decoded-content cache's
// hit/miss ratio. They are cheap `Relaxed` atomics (no ordering coupling to any
// other state) reset to zero each process start — "since the node started"
// telemetry, never persisted. Additive-only (§5.1): a new read surface, no
// change to any existing field.

/// Count of disk-cache files the LRU cap has evicted since process start.
static CACHE_EVICTED_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Bytes reclaimed by disk-cache LRU eviction since process start.
static CACHE_EVICTED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Decoded-content-cache lookups that HIT (served a resource window from RAM).
static CONTENT_CACHE_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Decoded-content-cache lookups that MISSED (had to re-decode the module).
static CONTENT_CACHE_MISSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Whole-capsule NETWORK lands since process start — a real refetch (bytes pulled over the wire
/// and written to disk), distinct from a RAM decode-cache miss (#1991, epic #1934). There are
/// exactly TWO landing write paths in this crate, and each bumps this counter at its own
/// successful write so together they cover every genuine re-download with no overlap:
/// [`Node::sync_module_from`] (on-demand `cache.fetchAndCache`, chain gap-fill, fetch-side
/// backfill — all funnel through this one function) and
/// [`seams::dig_peer::module_reshare::promote_into_cache`] (the reshare-warm land, a SEPARATE
/// write-then-rename that never calls `sync_module_from`). A failed sync/promotion never
/// increments it.
static CACHE_REFETCH_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The [`ContentCache`] key: `(store_hex, root_hex, retrieval_key)` identifying one served resource.
type ContentCacheKey = (String, String, [u8; 32]);

/// A bounded, LRU decoded-content cache: `(store, root, retrieval_key) → decoded ContentResponse`.
/// Keeps the total cached ciphertext under [`CONTENT_CACHE_MAX_BYTES`], evicting the
/// least-recently-used entries on overflow. Entries are `Arc`-shared so a hit is a cheap pointer
/// clone (no ciphertext copy). Guarded by a `std::sync::Mutex` — the critical section is a map
/// get/insert only (no `.await` while held). See [`Node::serve_local_cached`].
#[derive(Default)]
struct ContentCache {
    /// key → (response, a monotonically increasing "last used" tick for LRU ordering).
    entries: std::collections::HashMap<ContentCacheKey, (Arc<ContentResponse>, u64)>,
    /// Monotonic clock for recency; bumped on every get/insert.
    tick: u64,
    /// Running sum of cached `ciphertext.len()` for the byte budget.
    bytes: u64,
}

impl ContentCache {
    /// Look up a decoded response, bumping its recency on a hit.
    fn get(&mut self, key: &ContentCacheKey) -> Option<Arc<ContentResponse>> {
        self.tick += 1;
        let tick = self.tick;
        match self.entries.get_mut(key) {
            Some(entry) => {
                entry.1 = tick;
                // #279 telemetry: a RAM hit (no re-decode of the module).
                CONTENT_CACHE_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(entry.0.clone())
            }
            None => {
                CONTENT_CACHE_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a decoded response, then evict least-recently-used entries until the total cached
    /// ciphertext is under [`CONTENT_CACHE_MAX_BYTES`]. A single response larger than the budget is
    /// still cached (so the current stream benefits) but immediately evicts everything else.
    fn insert(&mut self, key: ContentCacheKey, resp: Arc<ContentResponse>) {
        self.tick += 1;
        let size = resp.ciphertext.len() as u64;
        if let Some((old, _)) = self.entries.insert(key, (resp, self.tick)) {
            self.bytes = self.bytes.saturating_sub(old.ciphertext.len() as u64);
        }
        self.bytes = self.bytes.saturating_add(size);
        while self.bytes > CONTENT_CACHE_MAX_BYTES && self.entries.len() > 1 {
            // Evict the least-recently-used entry (smallest tick).
            if let Some(lru_key) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            {
                if let Some((old, _)) = self.entries.remove(&lru_key) {
                    self.bytes = self.bytes.saturating_sub(old.ciphertext.len() as u64);
                }
            } else {
                break;
            }
        }
    }
}

/// The DIG node state. Public so `dig-runtime` can construct one ([`Node::from_env`])
/// and drive it via [`handle_rpc`] in-process inside the browser. Fields stay
/// private — callers only need the constructor + the dispatch.
pub struct Node {
    cache_dir: PathBuf,
    http: reqwest::Client,
    /// Upstream base URL for the JSON-RPC proxy and the §21 module sync. EMPTY by default
    /// (#1997) — there is no well-known fallback; set by `DIG_NODE_UPSTREAM` (a node-specific
    /// name, distinct from the browser's own `DIG_RPC_ENDPOINT`, which points the browser AT this
    /// node — reusing that name would make the node proxy to itself).
    upstream: String,
    /// Cleared for good once the upstream is PROVEN to route back to this node (#1997).
    ///
    /// Separate from `upstream` being empty, because the two are different facts: "no upstream was
    /// configured" and "the configured upstream turned out to be us". Both must stop an outbound
    /// call, so [`Node::has_upstream`] requires both.
    ///
    /// This exists because the loop latch previously lived ONLY in the service shell's
    /// `RelayGuard`, which gates the method-passthrough relay — one of THREE legs that reach an
    /// upstream. The other two carry content (`dig.getContent`'s miss proxy and the `/s/*` Tier 3
    /// whole-content fetch) and live here in the engine, where they consulted `upstream` directly.
    /// A node that had detected and announced a loop would therefore still recurse on any
    /// anonymous `dig.getContent` for content it does not hold — the original outage, on the more
    /// expensive path, behind a log line claiming it was closed.
    upstream_looped_back: std::sync::atomic::AtomicBool,
    /// Serialize cache mutation (eviction) so concurrent requests don't race.
    cache_lock: Mutex<()>,
    /// The persistent §21.9 identity SEED, loaded once at startup. `Some` enables
    /// authenticated whole-store sync (the node mints a fresh `RequestIdentity`
    /// per request via `identity::identity_from_seed`); `None` disables it (the
    /// node falls back to the per-resource proxy). The 32-byte seed — not the
    /// reconstructed BLS key — is held so the signer closure stays `Send + Sync`.
    identity_seed: Option<[u8; 32]>,
    /// Resolver for the store's CHIP-0035 chain-anchored root — the trusted-root
    /// source for the MANDATORY read-path pin (#127). Production is
    /// [`CoinsetResolver`] (the live singleton walk); tests inject a deterministic
    /// one so the fail-closed gate is unit-tested without a chain.
    anchored_root_resolver: Arc<dyn AnchoredRootResolver>,
    /// Live, pool-oriented status of the node's L7 peer network (the connected peer pool + the
    /// mTLS peer-RPC server). Shared with the background peer-network task spawned by the standalone
    /// [`run`]; surfaced via `control.peerStatus`. In the in-process FFI path (the browser) no peer
    /// network runs, so this stays "not running" — the browser is a consumer, not a reachable peer.
    /// (Replaces the retired bespoke relay-connection status; relay reachability now lives in
    /// dig-nat/dig-gossip and is reported here as the pool's relay-reservation flag.)
    peer_status: Arc<peer::PeerStatus>,
    /// The P2P content engine (#164/#165): the dig-download multi-source fetch path + the
    /// redirect-on-miss provider lookup. Set ONCE by the standalone peer-network bring-up
    /// ([`peer::spawn_peer_network`]) via [`Node::set_p2p_content`]; NEVER set in the in-process FFI
    /// path (the browser is a pure consumer), so a content miss there behaves exactly as before (no
    /// redirect/fetch-through — the miss handler is a no-op without this). See [`crate::download`].
    p2p_content: OnceLock<Arc<download::NodeContent>>,
    /// Bounded in-memory LRU of decoded [`ContentResponse`]s keyed by (store, root, retrieval_key)
    /// (audit #179). Serving one resource window re-reads + wasmtime-decrypts the whole module;
    /// this lets successive windows of the same resource slice from RAM instead of re-decrypting,
    /// turning a streamed resource from O(n²) into O(n) work. Bounded by [`CONTENT_CACHE_MAX_BYTES`].
    content_cache: std::sync::Mutex<ContentCache>,
    /// Hook the standalone peer-network bring-up installs so the node can refresh its DHT provider
    /// records when its inventory changes (a gap-filled generation, a `cache.fetchAndCache`) — so
    /// peers find it as a NEW holder without waiting for the maintenance loop (SPEC §14.1). Set ONCE by
    /// [`peer::spawn_peer_network`] via [`Node::set_inventory_refresher`]; NEVER set on the FFI path
    /// (the browser is a consumer with no DHT), where an inventory-change refresh is a no-op. Kept off
    /// the `Node` struct's DHT-handle dependency (the node stays FFI-safe) by taking a boxed async hook.
    inventory_refresher: OnceLock<InventoryRefresher>,
    /// The ONE single-flight gate every whole-capsule acquisition claims against, keyed
    /// `store_hex:root_hex` (#1614). A read miss can pull the same `(store, root)` capsule down TWO
    /// transports — the §21 authenticated whole-store backfill ([`Node::maybe_backfill_capsule`] →
    /// [`Node::gap_fill_generation`]) and the #1576 P2P reshare warm ([`crate::seams::dig_peer::CapsuleWarmer`]).
    /// They are two transports for the SAME artifact, so they share this gate: whichever leg claims the
    /// key first runs the pull, the other refuses, and a burst of resource reads across one not-yet-held
    /// store starts exactly ONE whole-`.dig` pull. The reshare warmer is wired with a clone of this same
    /// `Arc` ([`crate::download::NodeContent::wire_capsule_reshare`]), so both legs test-and-set one
    /// registry. The registry's distinct-generation cap ([`crate::seams::dig_peer::DEFAULT_MAX_CONCURRENT_WARMS`])
    /// therefore bounds concurrent acquisitions across BOTH legs, not each in isolation.
    capsule_acquisition: Arc<crate::seams::dig_peer::WarmRegistry>,
    /// A WEAK self-reference, installed by the standalone peer-network bring-up (which holds the
    /// `Arc<Node>`), so a `&self` read handler can spawn a detached background task that needs an owned
    /// `Arc<Node>` — the capsule backfill (§14.3). `Weak` (not `Arc`) so the node's refcount is
    /// unaffected (no self-keep-alive cycle). NEVER set on the FFI path, so a backfill there upgrades
    /// to `None` and is a no-op (the browser consumer has no peer network to pull a capsule from).
    self_ref: OnceLock<std::sync::Weak<Node>>,
    /// The live [`dig_gossip::GossipHandle`] for the node's connected peer pool, retained by the
    /// standalone peer-network bring-up ([`peer::run_peer_network`]) so the CONTROL surface can act on
    /// the pool: dial a peer (`control.peers.connect`), drop one (`control.peers.disconnect`), and
    /// enumerate the connected peers per-peer (`control.peerStatus` → the `peers` array). Set ONCE via
    /// [`Node::set_gossip_handle`]; NEVER set
    /// on the in-process FFI path (the browser is a pure consumer with no pool), where the connect verb
    /// reports "no peer network" and the peer list is empty.
    gossip: OnceLock<dig_gossip::GossipHandle>,
    /// The outgoing-bandwidth throttle (dig_ecosystem issue #30): tracks bytes served this second
    /// against a configurable cap (`DIG_NODE_MAX_OUTGOING_BYTES_PER_SEC`, unlimited by default) so
    /// the serve path can redirect an over-budget request to a known alternate holder instead of
    /// serving over-cap or dropping it. See [`bandwidth::OutgoingThrottle`] and
    /// [`Node::bandwidth_redirect`].
    outgoing_throttle: bandwidth::OutgoingThrottle,
    /// The server-side VERIFICATION LEDGER (#307): a bounded, short-TTL, in-memory record of the
    /// per-resource verify verdict + Merkle inclusion-proof data the `/s/` serve path already
    /// computes, keyed by `store:root`. The loopback service shell exposes it read-only at
    /// `GET /verify/<store>[:<root>]` so the extension can render the page-level "Verified by Chia"
    /// badge + proof-inspection modal. Populated on the existing verify step (never re-verified),
    /// fail-closed unchanged. See [`verification_ledger::VerificationLedger`].
    verification_ledger: verification_ledger::VerificationLedger,
    /// The chat subsystem state (epic #793): the inbound-message inbox `chat.poll` drains and the
    /// monotonic anti-replay counter each outbound `chat.send` stamps. The node is the chat TRANSPORT
    /// only — it seals an app-supplied opaque `DIGCHAT1` envelope and dig-gossip directed-sends it; it
    /// never parses chat content. See [`chat`].
    chat: chat::ChatState,
    /// The live INBOUND-DEMAND ledger (#1990, epic #1934): the FIRST live tier-tagging. Records which
    /// stores a remote PEER has asked this node to serve and tags each `Tier1Demand`, so a peer's
    /// request — direct evidence this node's neighbourhood wants the content — assigns the
    /// `Tier1Demand` tier (via [`Node::module_tier`]) that gives the store eviction precedence over
    /// speculative `Tier0Precache`.
    /// In-memory + process-lifetime; additive over the on-disk cache. See [`inbound_demand`].
    inbound_demand: inbound_demand::InboundDemand,
    /// This node's own 32-byte `peer_id` (= its DHT node id — both are the SHA-256 SPKI value, one
    /// keyspace), the XOR-distance REFERENCE point the inbound-demand pull's proximity admission scores
    /// against (§7.10d, #2014). Installed ONCE by the standalone peer-network bring-up
    /// ([`peer::spawn_peer_network`]) via [`Node::set_node_peer_id`], the same source the tier-0 loop
    /// takes its `NodeContext.peer_id` from — so the two paths share ONE reference identity. NEVER set
    /// on the FFI/consumer path (no peer network, no inbound peer demand), where the gate reads `None`
    /// and fails CLOSED (no peer-driven pull without a known identity to anchor the neighbourhood to).
    node_peer_id: OnceLock<[u8; 32]>,
}

/// A boxed async hook that reconciles the node's DHT provider records with its current cache
/// inventory (announce new capsules, withdraw gone ones). Installed by the standalone peer-network
/// bring-up ([`peer::spawn_peer_network`]); the FFI path installs none. The closure is `Send + Sync`
/// and returns a boxed future so the async DHT `refresh_inventory` call can be driven from the
/// FFI-safe [`Node`] without the node holding the DHT handle directly.
pub(crate) type InventoryRefresher =
    Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// An in-memory [`dig_download::ModuleReader`] over a freshly-synced capsule, so the chain-anchored
/// verifier can inspect bytes the node holds in RAM (the sync path never stages to disk before the
/// verify — an unverified capsule must not touch the cache, whose mere presence is an announcement).
struct InMemoryModule(Vec<u8>);

#[async_trait::async_trait]
impl dig_download::ModuleReader for InMemoryModule {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, dig_download::DownloadError> {
        let start = (offset as usize).min(self.0.len());
        let end = start.saturating_add(len as usize).min(self.0.len());
        Ok(self.0[start..end].to_vec())
    }
}

/// The CANONICAL (shared) cache dir — the one the DIG Browser's in-process
/// dig-node AND the standalone dig-node/dig-companion both resolve to, so they
/// share a `.dig` cache by construction (#96). Precedence:
///
/// 1. `DIG_NODE_CACHE` env override (the installer points both the browser launch
///    env and the standalone service at one dir) — UNCHANGED.
/// 2. Otherwise the per-OS base dir resolved via the `directories` crate (correct
///    on Windows/macOS/Linux even when the raw env vars are unset), suffixed
///    `DigNode/cache`.
/// 3. As a last resort (no home dir resolvable) `./DigNode/cache`.
///
/// To stay byte-identical to dig-companion's `cache_dir()` (so the two keep
/// sharing), Windows uses `data_local_dir()` (= `%LOCALAPPDATA%`) and Unix/macOS
/// use `home_dir()` + `DigNode/cache` — NOT XDG / `Application Support`.
///
/// This is the *intended* shared location; whether it is actually writable (and
/// thus used) is decided by [`resolve_cache_dir`].
fn canonical_cache_dir() -> PathBuf {
    if let Some(env) = std::env::var("DIG_NODE_CACHE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return PathBuf::from(env);
    }
    let base = directories::BaseDirs::new().map(|b| {
        if cfg!(windows) {
            b.data_local_dir().to_path_buf()
        } else {
            // Preserve the historic `$HOME/DigNode/cache` default on Unix/macOS
            // so the path is byte-identical to dig-companion (shared cache).
            b.home_dir().to_path_buf()
        }
    });
    let root = base
        .or_else(|| std::env::var("LOCALAPPDATA").ok().map(PathBuf::from))
        .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    root.join("DigNode").join("cache")
}

/// A deterministic process-private fallback cache dir, used only when the
/// canonical shared dir is unwritable. Keyed by PID so it is stable for the
/// process lifetime (every call returns the same path) but isolated from other
/// processes — a degraded, un-shared mode that never fails the node.
fn private_fallback_dir() -> PathBuf {
    std::env::temp_dir()
        .join(format!("DigNode-{}", std::process::id()))
        .join("cache")
}

/// Has the unwritable-canonical-dir warning already been logged this process?
/// (So the structured fallback warning is emitted once, not on every resolve.)
static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Is the canonical cache dir writable? Probes by ensuring the dir exists and
/// writing+removing a tiny temp file in it. A miss (read-only volume, perms)
/// means we must fall back to a private dir.
///
/// The probe name is unique PER CALL (pid + a monotonic counter), NOT per-pid:
/// `resolve_cache_dir` runs on every `cache_dir()`/`config_path()`/`lockfile_path()`
/// call, so two threads of one process probe concurrently. A shared probe name
/// let one thread's `remove_file` race the other's `write` (a transient
/// sharing-violation `Err` on Windows), spuriously reporting the dir UNwritable
/// → that one call returned the private-fallback dir → its `config_path()` pointed
/// at a DIFFERENT file → a lost config update. A unique name makes the probe
/// race-free, so resolution is stable under concurrency.
fn dir_is_writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".write-probe-{}-{}", std::process::id(), seq));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolve the EFFECTIVE cache dir and whether it is the canonical shared one.
/// Returns `(dir, shared)`: the canonical dir with `shared = true` when it is
/// writable, else the process-private fallback with `shared = false` (logging a
/// structured one-shot warning). Re-resolved on each call (so a `DIG_NODE_CACHE`
/// change or a settings-driven path takes effect without a restart) — the
/// fallback path is deterministic, so all callers within a process agree.
fn resolve_cache_dir() -> (PathBuf, bool) {
    let canonical = canonical_cache_dir();
    if dir_is_writable(&canonical) {
        return (canonical, true);
    }
    let fallback = private_fallback_dir();
    if !FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "dig-node: WARN canonical cache dir {} is not writable; \
             falling back to a process-private dir {} (cache NOT shared with \
             other DIG processes this session)",
            canonical.display(),
            fallback.display()
        );
    }
    let _ = std::fs::create_dir_all(&fallback);
    (fallback, false)
}

/// The effective cache dir (canonical shared dir if writable, else a private
/// fallback). See [`resolve_cache_dir`].
fn cache_dir() -> PathBuf {
    resolve_cache_dir().0
}

/// Whether the effective [`cache_dir`] is the canonical dir shared with the
/// standalone dig-node / dig-companion (`true`), or a process-private fallback
/// because the canonical dir was unwritable (`false`). Surfaced additively in
/// `cache.getConfig`.
pub fn cache_dir_is_shared() -> bool {
    resolve_cache_dir().1
}

/// Path to the shared DIG node config (cache cap, etc.) — next to the cache dir.
pub fn config_path() -> PathBuf {
    let dir = cache_dir();
    dir.parent()
        .map(|p| p.join("config.json"))
        .unwrap_or_else(|| dir.join("config.json"))
}

/// Name of the cross-process advisory lockfile, kept at the ROOT of the cache
/// dir (next to `modules/`, `responses/`, and `config.json`). One lockfile
/// coordinates BOTH the config read-modify-write and cache eviction across every
/// DIG process sharing this cache (the in-process browser node, the standalone
/// dig-node, dig-companion).
const LOCKFILE_NAME: &str = ".dignode.lock";

/// Path to the cross-process lockfile for the effective cache dir.
fn lockfile_path() -> PathBuf {
    cache_dir().join(LOCKFILE_NAME)
}

/// A held cross-process advisory lock. Dropping it (or the process exiting)
/// releases the OS-level `flock`. The inner `File` is kept alive solely to hold
/// the lock — it is never read or written.
struct CacheLockGuard {
    _file: std::fs::File,
}

/// Acquire the cross-process advisory lock on `<cache>/.dignode.lock`, blocking
/// briefly until it is free. Best-effort: if the lockfile can't be created or
/// locked (e.g. a filesystem without `flock`), returns `None` and the caller
/// proceeds WITHOUT the cross-process guarantee rather than failing — the
/// in-process mutex + atomic writes still hold, so this only degrades the
/// two-process lost-update protection, it never breaks single-process use.
fn acquire_cache_lock() -> Option<CacheLockGuard> {
    let path = lockfile_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .ok()?;
    // Blocking exclusive lock — config RMW and eviction are short, and two DIG
    // processes contending here is rare, so blocking (vs. spin) is fine. Use
    // fs4's portable advisory lock explicitly (fully-qualified so it's the fs4
    // implementation, not std's inherent `File::lock`) so the behaviour is the
    // same flock/LockFileEx across the toolchains CI runs.
    FileExt::lock(&file).ok()?;
    Some(CacheLockGuard { _file: file })
}

/// In-process serializer for the config read-modify-write. The cross-process
/// `flock` (`.dignode.lock`) is NOT sufficient on its own: on Windows
/// `LockFileEx` is per-handle and does NOT block a SECOND lock taken by the SAME
/// process (two threads each open their own handle and both acquire), so two
/// threads of one process can still interleave read/read/write/write and lose an
/// increment. This process-global mutex makes the RMW atomic *within* this
/// process; the flock makes it atomic *across* processes. Together they give the
/// lost-update-free guarantee the doc above promises, on every OS.
static CONFIG_RMW_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read-modify-write the config JSON under both an in-process mutex and the
/// cross-process lock so neither two threads nor two processes can lose each
/// other's update (the lost-update race). Reads the current config, applies
/// `mutate`, and writes it back atomically (temp + rename) — all while holding
/// both locks. Pretty-prints to keep the on-disk `config.json` schema
/// byte-compatible with the prior writer.
fn update_config_locked(mutate: impl FnOnce(&mut Value)) -> std::io::Result<()> {
    let path = config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Serialize this PROCESS's RMWs (recover from a poisoned lock — a prior
    // panicker left the guarded config in a consistent on-disk state, so the
    // poison carries no broken invariant we must honor).
    let _in_proc = CONFIG_RMW_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Hold the cross-process lock across the read AND the write so a concurrent
    // PROCESS can't read-then-clobber between our read and our write.
    let _lock = acquire_cache_lock();
    let mut v: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({}));
    mutate(&mut v);
    let bytes = serde_json::to_vec_pretty(&v).unwrap_or_default();
    write_atomic(&path, &bytes)
}

/// Atomically write `bytes` to `path` via a temp file in the SAME directory +
/// `fs::rename` (atomic on NTFS and POSIX). A reader (this or another process)
/// therefore never observes a torn/partial file — it sees either the old
/// contents or the fully-written new ones. Used for content-addressed module
/// bytes (immutable per capsule, so concurrent writers converge) and for the
/// config read-modify-write.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    // Unique temp name in the same dir so `rename` stays within one filesystem
    // (cross-device rename would fail). PID + nanos + a per-process monotonic
    // counter keeps concurrent writers (even on a coarse clock) from colliding
    // on the temp path.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".tmp-{}-{}-{}", std::process::id(), nanos, seq));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Clean up the temp file on a failed rename so we don't leak it.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The local-cache size cap in bytes. Read from config.json (set via the DIG
/// settings page), falling back to `DIG_NODE_CACHE_CAP`, then the 1 GiB default.
/// Read dynamically so a settings change takes effect without a restart.
pub fn cache_cap_bytes() -> u64 {
    if let Ok(txt) = std::fs::read_to_string(config_path()) {
        if let Ok(v) = serde_json::from_str::<Value>(&txt) {
            if let Some(cap) = v.get("cache_cap_bytes").and_then(|c| c.as_u64()) {
                if cap > 0 {
                    return cap;
                }
            }
        }
    }
    std::env::var("DIG_NODE_CACHE_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CACHE_CAP)
}

/// Persist the cache size cap (bytes) to config.json (the DIG settings page).
/// Read-modify-write under the cross-process lock so a concurrent writer (e.g.
/// dig-companion setting `wc_project_id`) can't lose this update or vice-versa.
pub fn set_cache_cap_bytes(cap: u64) -> std::io::Result<()> {
    update_config_locked(|v| {
        v["cache_cap_bytes"] = json!(cap);
    })
}

/// How the local cache's bytes are split between the two things it holds.
///
/// The split exists because the totals looked contradictory without it (#1886): a node can report
/// megabytes of `used_bytes` while `cache.listCached` returns an EMPTY list, and both are correct
/// — `listCached` enumerates whole `.dig` capsules, and until one has been synced the bytes on
/// disk are all per-resource response windows. Reporting the breakdown makes "content cached but
/// no capsule held" — precisely the broken-flywheel state — readable instead of baffling.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheUsage {
    /// Bytes in whole `.dig` capsules under `<cache>/modules/` — what makes this node a HOLDER
    /// and what `cache.listCached` enumerates.
    pub capsule_bytes: u64,
    /// Bytes in cached per-resource response windows under `<cache>/responses/` — served reads,
    /// which make this node no one's provider.
    pub response_bytes: u64,
    /// Everything else in the cache tree (config-adjacent files, in-progress temporaries).
    pub other_bytes: u64,
}

impl CacheUsage {
    /// Total bytes held, i.e. what [`cache_used_bytes`] reports.
    pub fn total(&self) -> u64 {
        self.capsule_bytes
            .saturating_add(self.response_bytes)
            .saturating_add(self.other_bytes)
    }
}

/// Bytes currently held in the local cache, split by kind. See [`CacheUsage`].
pub fn cache_usage() -> CacheUsage {
    fn walk(p: &Path, total: &mut u64) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, total);
                } else if let Ok(md) = e.metadata() {
                    *total += md.len();
                }
            }
        }
    }
    let root = cache_dir();
    let mut usage = CacheUsage::default();
    walk(&root.join("modules"), &mut usage.capsule_bytes);
    walk(&root.join("responses"), &mut usage.response_bytes);
    // Whatever else lives in the tree: total the whole thing, then subtract the two known
    // subtrees, so a future cache directory is never silently unaccounted for.
    let mut everything = 0u64;
    walk(&root, &mut everything);
    usage.other_bytes = everything
        .saturating_sub(usage.capsule_bytes)
        .saturating_sub(usage.response_bytes);
    usage
}

/// Total bytes currently held in the local cache (capsules + response windows + the rest).
/// [`cache_usage`] reports the same total broken down by kind.
pub fn cache_used_bytes() -> u64 {
    cache_usage().total()
}

/// Delete all locally cached DIG content (the settings "clear cache" action).
pub fn clear_cache() {
    let _ = std::fs::remove_dir_all(cache_dir());
}

/// The config key for the WalletConnect projectId (the native wallet acts as a
/// WC responder; the relay needs a Reown/WalletConnect Cloud projectId).
const WC_PROJECT_ID_KEY: &str = "wc_project_id";

/// Resolve the effective WalletConnect projectId from the two sources, in
/// precedence order: a persisted config value wins; otherwise the
/// `DIG_WALLET_WC_PROJECT_ID` env var is the initial/default; otherwise none.
///
/// Pure (no disk/env) so the precedence policy is unit-tested directly. A blank
/// persisted value is treated as "unset" so it falls through to the env default
/// rather than pinning an empty id.
fn resolve_wc_project_id(persisted: Option<&str>, env: Option<&str>) -> Option<String> {
    let clean = |s: &str| {
        let t = s.trim();
        (!t.is_empty()).then(|| t.to_string())
    };
    persisted.and_then(clean).or_else(|| env.and_then(clean))
}

/// The projectId persisted in config.json, if any (blank → `None`).
fn persisted_wc_project_id() -> Option<String> {
    let txt = std::fs::read_to_string(config_path()).ok()?;
    let v: Value = serde_json::from_str(&txt).ok()?;
    v.get(WC_PROJECT_ID_KEY)
        .and_then(|p| p.as_str())
        .map(str::to_string)
}

/// The effective WalletConnect projectId: persisted config value if set, else the
/// `DIG_WALLET_WC_PROJECT_ID` env var, else `None`. Read dynamically so a settings
/// change applies without restarting the browser.
pub fn wc_project_id() -> Option<String> {
    let persisted = persisted_wc_project_id();
    let env = std::env::var("DIG_WALLET_WC_PROJECT_ID").ok();
    resolve_wc_project_id(persisted.as_deref(), env.as_deref())
}

/// Persist the WalletConnect projectId to config.json (the DIG settings page).
/// A blank value clears the persisted override (falling back to the env default).
/// Read-modify-write under the cross-process lock so a concurrent writer (e.g.
/// the cache-cap setter) can't lose this update or vice-versa.
pub fn set_wc_project_id(id: &str) -> std::io::Result<()> {
    let trimmed = id.trim().to_string();
    update_config_locked(|v| {
        if trimmed.is_empty() {
            if let Some(obj) = v.as_object_mut() {
                obj.remove(WC_PROJECT_ID_KEY);
            }
        } else {
            v[WC_PROJECT_ID_KEY] = json!(trimmed);
        }
    })
}

// -- Subscription set (SPEC §6) — persisted, cross-process-locked ---------------------------------
//
// The node's OWN set of subscribed stores (the stores it actively watches + gap-fills) lives in
// `<cache>/subscriptions.json`, distinct from the durable capsule inventory (the `.dig` modules).
// All the add/remove/list policy is pure in `crate::subscription`; these thin wrappers add the disk
// path + the cross-process-locked read-modify-write (the SAME `.dignode.lock` the config RMW uses),
// so two DIG processes sharing the cache can't lose each other's subscription updates.

/// The subscriptions file for the effective cache dir (`<cache>/subscriptions.json`).
fn subscriptions_path() -> PathBuf {
    subscription::subscriptions_path(&cache_dir())
}

/// Load the persisted subscription set from the effective cache dir (empty if none/unreadable).
pub fn load_subscriptions() -> subscription::SubscriptionSet {
    subscription::load(&cache_dir())
}

/// Read-modify-write the subscription set under the in-process mutex + cross-process advisory lock
/// (mirroring [`update_config_locked`]), applying `mutate` to the loaded set and persisting it
/// atomically (temp + rename). Returns whatever `mutate` returns so the caller can report
/// added/removed. A `mutate` that returns `Err` aborts the write (nothing is persisted).
fn update_subscriptions_locked<T>(
    mutate: impl FnOnce(&mut subscription::SubscriptionSet) -> Result<T, String>,
) -> Result<T, String> {
    let path = subscriptions_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // Serialize this PROCESS's RMWs (recover from a poisoned lock — the guarded file is always left
    // in a consistent on-disk state, so a prior panic carries no broken invariant).
    let _in_proc = CONFIG_RMW_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Hold the cross-process lock across the read AND the write so another PROCESS can't read then
    // clobber our update.
    let _lock = acquire_cache_lock();
    let mut set = subscription::load(&cache_dir());
    let out = mutate(&mut set)?;
    let bytes = subscription::encode(&set);
    write_atomic(&path, &bytes).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Subscribe to `store_id` (persisted). `Ok(true)` = newly added, `Ok(false)` = already subscribed,
/// `Err` = malformed id / write failure.
pub fn subscribe_store(store_id: &str) -> Result<bool, String> {
    update_subscriptions_locked(|set| set.add(store_id))
}

/// Unsubscribe from `store_id` (persisted). `Ok(true)` = removed, `Ok(false)` = was not subscribed,
/// `Err` = malformed id / write failure.
pub fn unsubscribe_store(store_id: &str) -> Result<bool, String> {
    update_subscriptions_locked(|set| set.remove(store_id))
}

/// Whether the module for `(store_id, root)` is held locally under `dir` — the "is this generation
/// missing?" check the chain-watch gap-fill loop keys on (SPEC §14.2). Thin over
/// [`CapsuleKey::module_path`] so the loop's held-check seam ([`chainwatch::HeldCheck`]) has one
/// source of truth.
///
/// A non-canonical key is NOT HELD, without a filesystem call: it could never have named a module this
/// node wrote, so "not held" is the honest answer and the only one that requires no path to exist
/// (#1599).
pub(crate) fn module_exists(dir: &Path, store_hex: &str, root_hex: &str) -> bool {
    CapsuleKey::parse(store_hex, root_hex).is_some_and(|key| key.resolve_cached_path(dir).exists())
}

/// Hard bound on the total bytes [`walk_dir_files`] will read into memory before aborting.
/// A staging walk buffers every file's bytes; without a running budget an attacker-chosen
/// directory (e.g. a filesystem root) would recurse the whole tree into RAM before the
/// downstream `MAX_STORE_BYTES` compile cap ever runs. Slightly above `MAX_STORE_BYTES` so
/// a legitimately-at-the-cap store is read (then rejected by the compile cap with the precise
/// `-32013`), but an unbounded tree aborts here. See audit #179 (HIGH — peer-reachable
/// dig.stage reads an attacker-chosen local tree into memory; the allowlist §7.4a already
/// bars peers, this bounds the local caller too).
const WALK_MAX_TOTAL_BYTES: u64 = digstore_core::MAX_STORE_BYTES.saturating_add(64 * 1024 * 1024);

/// Hard bound on the number of files [`walk_dir_files`] will read before aborting — caps the
/// entry count independently of total bytes (many tiny files also exhaust memory + time).
const WALK_MAX_FILES: usize = 1_000_000;

/// Hard bound on directory-recursion depth in [`walk_dir_files`] — stops a pathological /
/// deliberately-deep tree (and bounds stack use) before it exhausts resources.
const WALK_MAX_DEPTH: usize = 256;

/// Recursively read every file under `root` into `(resource_key, bytes)`, where
/// the key is the file path relative to `root`, FORWARD-SLASHED — the exact key
/// convention the CLI `add` walk uses (`ops::walk::key_for`), so the same folder
/// produces the same capsule root through the CLI and the in-process node.
/// Sorted by key for deterministic staging order. Used by the `dig.stage` RPC
/// (#95 Pass C); a symlink loop or unreadable entry is skipped best-effort.
///
/// The walk is BOUNDED (audit #179): it aborts with an error the moment the running total
/// exceeds [`WALK_MAX_TOTAL_BYTES`], the file count exceeds [`WALK_MAX_FILES`], or the
/// recursion depth exceeds [`WALK_MAX_DEPTH`] — so a caller cannot point `dir` at an
/// arbitrarily large tree and force the whole tree into memory before the downstream
/// `MAX_STORE_BYTES` compile cap runs.
fn walk_dir_files(root: &Path) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    walk_dir_files_bounded(root, WALK_MAX_TOTAL_BYTES, WALK_MAX_FILES, WALK_MAX_DEPTH)
}

/// The bounded walk core (see [`walk_dir_files`]). The caps are parameters so the abort
/// behaviour is unit-testable with tiny bounds; production uses the module constants. Aborts
/// with `InvalidInput` the moment the byte budget, file-count cap, or recursion-depth cap is
/// exceeded — never buffering the whole tree first.
fn walk_dir_files_bounded(
    root: &Path,
    max_total_bytes: u64,
    max_files: usize,
    max_depth: usize,
) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    fn oversize(msg: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
    }
    #[allow(clippy::too_many_arguments)]
    fn rec(
        base: &Path,
        dir: &Path,
        depth: usize,
        max_total_bytes: u64,
        max_files: usize,
        max_depth: usize,
        total: &mut u64,
        out: &mut Vec<(String, Vec<u8>)>,
    ) -> std::io::Result<()> {
        if depth > max_depth {
            return Err(oversize(
                "staging directory nested deeper than the recursion cap",
            ));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                rec(
                    base,
                    &path,
                    depth + 1,
                    max_total_bytes,
                    max_files,
                    max_depth,
                    total,
                    out,
                )?;
            } else if ft.is_file() {
                if out.len() >= max_files {
                    return Err(oversize("staging directory has more files than the cap"));
                }
                // Enforce the byte budget BEFORE reading: stat the entry and abort if this file
                // would push the running total over the cap, so we never buffer past the bound.
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if total.saturating_add(size) > max_total_bytes {
                    return Err(oversize(
                        "staging directory exceeds the maximum total size read into memory",
                    ));
                }
                // Key = path relative to base, forward-slashed (URN-safe).
                let rel = path.strip_prefix(base).unwrap_or(&path);
                let key = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                let bytes = std::fs::read(&path)?;
                // Guard against a file that grew between stat and read (TOCTOU) — re-check the
                // real read length against the budget so the bound holds regardless of races.
                *total = total.saturating_add(bytes.len() as u64);
                if *total > max_total_bytes {
                    return Err(oversize(
                        "staging directory exceeds the maximum total size read into memory",
                    ));
                }
                out.push((key, bytes));
            }
            // Symlinks / other types are skipped (not staged).
        }
        Ok(())
    }
    let mut out = Vec::new();
    let mut total = 0u64;
    rec(
        root,
        root,
        0,
        max_total_bytes,
        max_files,
        max_depth,
        &mut total,
        &mut out,
    )?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Filesystem-safe filename for one cached proxy-response window, keyed by
/// (store, root, retrieval_key, offset). All inputs are hex (or empty), so the
/// only sanitizing needed is to reject anything non-hex defensively and bound
/// the length — a key collision would only mean a cache miss, never corruption,
/// because the browser merkle-verifies every response.
fn response_key(store: &str, root: &str, rk: &str, offset: usize) -> String {
    fn hexish(s: &str) -> &str {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            s
        } else {
            "x"
        }
    }
    format!(
        "{}_{}_{}_{}.json",
        hexish(store),
        hexish(root),
        hexish(rk),
        offset
    )
}

/// Is this request a candidate for authenticated whole-store sync? Only when we
/// have BOTH a concrete store id and a concrete generation root, each a canonical
/// 32-byte (64-hex) value. A rootless request (`root` empty, or the `"latest"`
/// sentinel, or anything non-hex) is NOT eligible: the browser resolves rootless
/// URNs to a concrete root via dig-resolver *before* calling, so a non-concrete
/// root here means the synced module could not be keyed deterministically.
fn sync_eligible(store_hex: &str, root_hex: &str) -> bool {
    CapsuleKey::parse(store_hex, root_hex).is_some()
}

/// Decide which cached files to evict so total bytes fit under `cap`. LRU:
/// evict oldest (smallest mtime) first, stopping as soon as the remaining total
/// is at/under `cap`. `entries` is (path, mtime, size); returns paths to delete.
fn plan_eviction(entries: &[(PathBuf, std::time::SystemTime, u64)], cap: u64) -> Vec<PathBuf> {
    let total: u64 = entries.iter().map(|(_, _, sz)| *sz).sum();
    if total <= cap {
        return Vec::new();
    }
    let mut sorted: Vec<&(PathBuf, std::time::SystemTime, u64)> = entries.iter().collect();
    sorted.sort_by_key(|(_, t, _)| *t); // oldest first
    let mut running = total;
    let mut victims = Vec::new();
    for (path, _, sz) in sorted {
        if running <= cap {
            break;
        }
        victims.push(path.clone());
        running = running.saturating_sub(*sz);
    }
    victims
}

/// Decide which cached `.dig` MODULES to evict so `<cache>/modules` fits under `cap`, TIER-AWARE.
///
/// Unlike [`plan_eviction`] (pure LRU over response windows), whole-capsule modules carry a
/// [`CacheTier`](crate::relevance::CacheTier): the self-driven tier-0 precache loop (#1934) must be the
/// SACRIFICIAL tier, so under disk pressure a `Tier0Precache` module is evicted BEFORE a
/// `Tier1Demand`/pin module — [`evict_key`](crate::relevance::evict_key) gives exactly that order
/// (tier ascending, then oldest-first within a tier). A demand read that promoted a store to Tier1 thus
/// survives a tier-0 sweep; a purely-precached store is reclaimed first. Returns the `(path, store_hex)`
/// victims, oldest-lowest-tier first, stopping as soon as the remaining total is at/under `cap`.
fn plan_module_eviction(
    entries: &[(PathBuf, String, crate::relevance::CacheEntry, u64)],
    cap: u64,
) -> Vec<(PathBuf, String)> {
    let total: u64 = entries.iter().map(|(_, _, _, sz)| *sz).sum();
    if total <= cap {
        return Vec::new();
    }
    let mut sorted: Vec<&(PathBuf, String, crate::relevance::CacheEntry, u64)> =
        entries.iter().collect();
    sorted.sort_by_key(|(_, _, entry, _)| crate::relevance::evict_key(entry));
    let mut running = total;
    let mut victims = Vec::new();
    for (path, store_hex, _, sz) in sorted {
        if running <= cap {
            break;
        }
        victims.push((path.clone(), store_hex.clone()));
        running = running.saturating_sub(*sz);
    }
    victims
}

/// The number of raw ciphertext bytes the WINDOW-based `dig.getContent` window at `offset` serves
/// for a resource of `total` bytes — the same slicing [`build_result`] performs, exposed standalone
/// so the outgoing-bandwidth throttle (#30) can decide BEFORE building the result whether serving it
/// would exceed the cap.
fn content_window_len(total: usize, offset: usize) -> usize {
    let start = offset.min(total);
    let end = (start + WINDOW).min(total);
    end - start
}

/// Build the JSON-RPC `result` object for one window of a decoded ContentResponse.
fn build_result(resp: &ContentResponse, offset: usize) -> Value {
    let total = resp.ciphertext.len();
    let start = offset.min(total);
    let end = (start + WINDOW).min(total);
    let window = &resp.ciphertext[start..end];
    let complete = end >= total;

    let mut result = json!({
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(window),
        "root": resp.roothash.to_hex(),
        "complete": complete,
    });
    if !complete {
        result["next_offset"] = json!(end);
    }
    // The proof + chunk_lens are sent on the FIRST window only (the client keeps
    // the first non-empty proof). Match rpc.dig.net / the digstore client.
    if start == 0 {
        result["inclusion_proof"] =
            json!(base64::engine::general_purpose::STANDARD.encode(resp.merkle_proof.to_bytes()));
        result["chunk_lens"] = json!(resp.chunk_lens);
    }
    result
}

/// Decode a locally cached module into a [`ContentResponse`] (whole-module `fs::read` + wasmtime
/// `serve_blind`). A free function (not a `Node` method) so it can be moved into a `spawn_blocking`
/// closure with only the cache dir + request keys, never a `Node` borrow (audit #179). Returns
/// `None` on a cache miss / decode failure. Touches the module file for on-disk LRU recency.
fn serve_local_blocking(
    cache_dir: &Path,
    key: &CapsuleKey,
    retrieval_key: &[u8; 32],
) -> Option<ContentResponse> {
    // Reader-tolerance (#1896): serve the current `.dig`, or a legacy `.module` a prior binary wrote.
    let path = key.resolve_cached_path(cache_dir);
    let module = std::fs::read(&path).ok()?;
    let store_id = Bytes32::from_hex(key.store()).ok()?;
    // Ephemeral host key: the browser verifies the merkle proof against the chain-anchored root, not
    // a host signature, so the serve key is local-only.
    let cfg = BlindServeConfig::from_seed(store_id, &[0u8; 32]);
    let bytes = serve_blind(&module, retrieval_key, cfg).ok()?;
    let resp = ContentResponse::from_bytes(&bytes).ok()?;
    touch(&path); // LRU recency
    Some(resp)
}

/// Load + decode the embedded [`PublicManifest`](digstore_core::PublicManifest) (data-section
/// id 13, #176 Phase C) from a locally cached compiled module. A free function (not a `Node`
/// method) so it moves into a `spawn_blocking` closure with only the cache dir + request keys,
/// mirroring [`serve_local_blocking`] (audit #179). Unlike `serve_local_blocking` this does NOT
/// instantiate the module in wasmtime: the manifest is PUBLIC, unencrypted data embedded
/// directly in the module's wasm data section, so extracting it is a pure binary-format parse
/// ([`digstore_compiler::extract_data_section_blob`]) with no `serve_blind` decrypt.
///
/// Returns:
/// - `Ok(Some(Some(manifest)))` — the module is held and carries a `PublicManifest` section.
/// - `Ok(Some(None))` — the module is held but carries NO `PublicManifest` section (an older
///   `.dig`, or a private store whose paths must stay opaque — store-format §5.1, additive).
/// - `Ok(None)` — this node does not hold the requested capsule at all (a cache miss).
/// - `Err(_)` — the on-disk module's data section is corrupt/malformed.
fn read_public_manifest_blocking(
    cache_dir: &Path,
    key: &CapsuleKey,
) -> Result<Option<Option<digstore_core::PublicManifest>>, String> {
    // Reader-tolerance (#1896): a manifest read tolerates a legacy `.module` cache like every serve.
    let path = key.resolve_cached_path(cache_dir);
    let module = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    let blob = digstore_compiler::extract_data_section_blob(&module)
        .map_err(|e| format!("malformed module data section: {e}"))?;
    digstore_core::datasection::read_public_manifest(&blob)
        .map(Some)
        .map_err(|e| format!("malformed public manifest section: {e:?}"))
}

impl Node {
    /// The async, MEMOIZED content-serve path used by every async caller (getContent windows,
    /// fetchRange frames, resource-granularity availability). On a hit in the bounded in-memory
    /// [`ContentCache`] it returns the decoded [`ContentResponse`] (as an `Arc`, a cheap clone) with
    /// NO disk read or decrypt. On a miss it runs the blocking decode on a `spawn_blocking` thread
    /// (so the fs::read + wasmtime decrypt never stalls the async runtime), then caches the result so
    /// successive windows of the same resource slice from RAM — turning a window-by-window streamed
    /// resource from O(n²) re-decrypts into O(n) (audit #179).
    /// This is also the ONE place caller-supplied capsule ids become a [`CapsuleKey`] on the async
    /// serve surface (#1599). Validating here rather than at each entry point means every async caller
    /// — `dig.fetchRange` frames, `dig.getContent` windows, resource-granularity availability — is
    /// covered by construction, and a future caller cannot be added without it: below this line the ids
    /// exist only as a validated key, and there is no path builder that would accept anything else.
    async fn serve_local_cached(
        &self,
        store_hex: &str,
        root_hex: &str,
        retrieval_key: &[u8; 32],
    ) -> Option<Arc<ContentResponse>> {
        let capsule = CapsuleKey::parse(store_hex, root_hex)?;
        let key = (store_hex.to_string(), root_hex.to_string(), *retrieval_key);
        // Fast path: an in-memory hit (no disk, no decrypt).
        if let Some(hit) = self.content_cache.lock().unwrap().get(&key) {
            return Some(hit);
        }
        // Miss: read + decrypt off the async runtime (spawn_blocking), then memoize. Only the cache
        // dir + key are moved into the closure, so no Node borrow escapes into the blocking thread.
        let cache_dir = self.cache_dir.clone();
        let rk = *retrieval_key;
        let decoded =
            tokio::task::spawn_blocking(move || serve_local_blocking(&cache_dir, &capsule, &rk))
                .await
                .ok()
                .flatten()?;
        let arc = Arc::new(decoded);
        self.content_cache.lock().unwrap().insert(key, arc.clone());
        Some(arc)
    }

    /// Invalidate any cached decoded content for a capsule (store, root) — all retrieval keys under
    /// it. Called when the underlying module is removed/replaced so a stale decode is never served
    /// from the in-memory cache after the on-disk module changes.
    fn invalidate_content_cache(&self, store_hex: &str, root_hex: &str) {
        let mut cache = self.content_cache.lock().unwrap();
        let victims: Vec<_> = cache
            .entries
            .keys()
            .filter(|(s, r, _)| s == store_hex && r == root_hex)
            .cloned()
            .collect();
        for v in victims {
            if let Some((old, _)) = cache.entries.remove(&v) {
                cache.bytes = cache.bytes.saturating_sub(old.ciphertext.len() as u64);
            }
        }
    }

    /// Drop the entire in-memory decoded-content cache (used by `cache.clear`).
    fn clear_content_cache(&self) {
        let mut cache = self.content_cache.lock().unwrap();
        cache.entries.clear();
        cache.bytes = 0;
    }

    fn responses_dir(&self) -> PathBuf {
        self.cache_dir.join("responses")
    }

    /// Return a previously-proxied JSON-RPC `result` for this exact request
    /// window, if cached. Touches the file for LRU recency on a hit.
    fn serve_cached_response(&self, key: &str) -> Option<Value> {
        let path = self.responses_dir().join(key);
        let bytes = std::fs::read(&path).ok()?;
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        touch(&path);
        Some(v)
    }

    /// Persist a proxied `result` window to the response cache, then evict
    /// oldest entries (LRU) until the cache is under its size cap.
    async fn store_response(&self, key: &str, result: &Value) {
        let dir = self.responses_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        if let Ok(bytes) = serde_json::to_vec(result) {
            let _ = std::fs::write(dir.join(key), bytes);
        }
        // Serialize eviction so concurrent writers don't race the size scan.
        let _guard = self.cache_lock.lock().await;
        self.evict_if_needed(&dir);
    }

    /// LRU-evict cached response windows until total bytes fit under the cap.
    ///
    /// Held under the cross-process lock for the whole scan→plan→delete so two
    /// DIG processes sharing the cache can't both scan the same set and
    /// double-evict (or race a concurrent write into a torn size accounting).
    /// The in-process `cache_lock` (held by the caller) serializes this process's
    /// own writers; the file lock serializes across processes.
    fn evict_if_needed(&self, dir: &Path) {
        let _xproc = acquire_cache_lock();
        let mut entries = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if let Ok(md) = e.metadata() {
                    let mtime = md.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    entries.push((e.path(), mtime, md.len()));
                }
            }
        }
        // Read the cap dynamically so changes from the DIG settings page apply
        // without restarting the browser. `self.cache_cap` is the startup default.
        let cap = cache_cap_bytes();
        for victim in plan_eviction(&entries, cap) {
            // Size of the victim, looked up from the scan, so the reclaimed-bytes
            // counter is accurate even though the file is about to be unlinked.
            let size = entries
                .iter()
                .find(|(p, _, _)| *p == victim)
                .map(|(_, _, s)| *s)
                .unwrap_or(0);
            if std::fs::remove_file(&victim).is_ok() {
                // #279 telemetry: record the LRU eviction (count + reclaimed bytes).
                CACHE_EVICTED_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                CACHE_EVICTED_BYTES.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// The effective [`CacheTier`](crate::relevance::CacheTier) of a cached MODULE for eviction.
    ///
    /// MAX across the THREE sources that hold an opinion (`effective_tier`): the in-memory inbound-demand
    /// ledger (a store it tags `Tier1Demand` is protected), the in-memory tier-0 precache ledger (a store
    /// ONLY there is `Tier0Precache`, sacrificed first), and the PERSISTED on-disk tag
    /// ([`crate::module_tier_tag`]). A store none of them names (a hosted pin / subscription gap-fill, or
    /// a legacy cache with no sidecar) defaults to `Tier1Demand` — fail-SAFE, so the tier-0 sweep can
    /// never evict genuinely-demanded content it simply has not labelled. A precached store later
    /// demanded is promoted (max) to `Tier1Demand`.
    ///
    /// The persisted tag is what makes precedence survive a RESTART (#2015): both in-memory ledgers are
    /// process-lifetime, so on a fresh node they are empty and this MAX would collapse to the
    /// `Tier1Demand` default for every on-disk module — losing the tier-0-sacrifice-first order until
    /// content is re-precached. Folding the on-disk tag in as a third source restores that order the
    /// moment the node comes back up.
    fn module_tier(&self, store_hex: &str) -> crate::relevance::CacheTier {
        let demand = self.inbound_demand.tier(store_hex);
        let precache = crate::tier0_live::is_tier0_precache(store_hex)
            .then_some(crate::relevance::CacheTier::Tier0Precache);
        let persisted = crate::module_tier_tag::read_tier_tag(&self.cache_dir, store_hex);
        crate::tier0_prefetch::effective_tier(demand.into_iter().chain(precache).chain(persisted))
            .unwrap_or(crate::relevance::CacheTier::Tier1Demand)
    }

    /// TIER-AWARE size-cap LRU eviction over `<cache>/modules` — the STANDING-OCCUPANCY bound that keeps
    /// the self-driven tier-0 precache loop (#1934) from growing whole-capsule storage to disk
    /// exhaustion. Run after a capsule lands so the modules cache plateaus at [`cache_cap_bytes`]:
    /// `Tier0Precache` modules are sacrificed before `Tier1Demand`/pin modules, oldest-first within a
    /// tier ([`plan_module_eviction`]). Best-effort + idempotent — nothing to evict is a cheap scan.
    pub(crate) async fn evict_modules_if_needed(&self) {
        // Serialize against this process's other cache writers, exactly like `evict_if_needed`.
        let _guard = self.cache_lock.lock().await;
        self.evict_modules_locked();
    }

    /// The scan→plan→delete core of [`Node::evict_modules_if_needed`], held under the cross-process
    /// advisory lock so two DIG processes sharing the cache cannot double-evict or race a torn scan.
    fn evict_modules_locked(&self) {
        let _xproc = acquire_cache_lock();
        let cap = cache_cap_bytes();
        let modules_root = self.cache_dir.join("modules");
        let mut entries = Vec::new();
        let Ok(stores) = std::fs::read_dir(&modules_root) else {
            return; // no modules cached yet — nothing to bound
        };
        for store_entry in stores.flatten() {
            if !store_entry.path().is_dir() {
                continue;
            }
            let Some(store_hex) = store_entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let tier = self.module_tier(&store_hex);
            // Persist the just-computed tier so tier-aware precedence survives a restart (#2015): a
            // sweep runs after every land, so this keeps the on-disk tag tracking the in-memory tier.
            crate::module_tier_tag::write_tier_tag(&self.cache_dir, &store_hex, tier);
            let Ok(modules) = std::fs::read_dir(store_entry.path()) else {
                continue;
            };
            for m in modules.flatten() {
                let path = m.path();
                // Only real capsules are eviction candidates — skip the `.tier` sidecar (and any
                // stray `.tmp-*` write-atomic scratch file), which carry no capsule extension.
                let is_capsule = m
                    .file_name()
                    .to_str()
                    .and_then(crate::capsule_key::cached_root_stem)
                    .is_some();
                if !is_capsule {
                    continue;
                }
                let Ok(md) = m.metadata() else { continue };
                if !md.is_file() {
                    continue;
                }
                // mtime-as-ticks: seconds since the epoch, so oldest = smallest = evicted first (LRU
                // within a tier). `touch` on serve refreshes it, matching the response cache's recency.
                let last_access_ticks = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                entries.push((
                    path,
                    store_hex.clone(),
                    crate::relevance::CacheEntry {
                        tier,
                        last_access_ticks,
                    },
                    md.len(),
                ));
            }
        }
        for (victim, store_hex) in plan_module_eviction(&entries, cap) {
            let size = entries
                .iter()
                .find(|(p, _, _, _)| *p == victim)
                .map(|(_, _, _, s)| *s)
                .unwrap_or(0);
            if std::fs::remove_file(&victim).is_ok() {
                CACHE_EVICTED_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                CACHE_EVICTED_BYTES.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                // Drop any decoded content for the evicted generation so a removed module is never
                // still served from the in-memory content cache (audit #179).
                if let Some(root_hex) = victim
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(crate::capsule_key::cached_root_stem)
                {
                    self.invalidate_content_cache(&store_hex, root_hex);
                }
                // Forget the tier-0 tag so the ledger cannot grow unbounded across precache→evict churn.
                crate::tier0_live::forget_tier0_land(&store_hex);
            }
        }
    }

    /// Whole-store sync against the configured upstream. Returns `true` when the synced
    /// module's served root matches the requested root, so the caller can now serve the
    /// request locally. The REASON for a `false` is available from
    /// [`Node::sync_module_from`] — this thin wrapper exists for the read path, which only
    /// needs to know whether it may now serve locally.
    async fn sync_module(&self, store_hex: &str, root_hex: &str) -> bool {
        self.sync_module_from(&self.upstream, store_hex, root_hex)
            .await
            .is_ok_and(|served| served.to_hex() == root_hex)
    }

    /// [`Node::sync_module`] followed by the tier-aware size-cap sweep, for the read path.
    ///
    /// The read-path §21 whole-store sync lands a WHOLE `.dig` on a module-cache miss, but — unlike
    /// the tier-0 precache loop (#1934) and `cache.fetchAndCache` ([`CapsuleStore::cache_fetch_and_cache`],
    /// which sweep at their own land sites) — nothing else bounds THIS path. Without a sweep here the
    /// `<cache>/modules` bound would hold only WHILE one of those loops happened to run, so a
    /// remotely-triggered read-path backfill could grow the cache unbounded with tier-0 disabled and no
    /// `cache.fetchAndCache` traffic (#2041). Sweeping right after the land makes the bound hold
    /// independent of any background loop's state.
    ///
    /// The sweep runs after EVERY sync ATTEMPT, not only when the caller may serve locally. A sync
    /// whose served root differs from the requested one (the upstream's head advanced) returns `false`
    /// yet STILL lands a whole (chain-anchored) capsule under the served root ([`Node::sync_module_from`]),
    /// so gating the sweep on the `true` return would let repeated head-advance lands grow the cache
    /// unbounded. The sweep is a bounded, idempotent best-effort dir-scan, so the extra scan on the
    /// `false`/`Err` path (where nothing landed) is cheap and finds nothing to evict.
    ///
    /// The read-path call site holds NO `cache_lock`, so this uses the async
    /// [`Node::evict_modules_if_needed`] (which takes `cache_lock` fresh) — NOT the locked core, which
    /// assumes the lock is already held (as `cache_fetch_and_cache` calls it, holding the lock). The
    /// choke-point [`Node::sync_module_from`] itself is deliberately NOT swept: `cache_fetch_and_cache`
    /// also funnels through it while holding `cache_lock`, so sweeping there would double-sweep and
    /// risk a lock inversion. Returns whatever [`Node::sync_module`] returned — whether the caller may
    /// now serve locally.
    async fn sync_module_and_bound(&self, store_hex: &str, root_hex: &str) -> bool {
        let may_serve_locally = self.sync_module(store_hex, root_hex).await;
        self.evict_modules_if_needed().await;
        may_serve_locally
    }

    /// Core of [`Node::sync_module`], parameterized by the upstream base URL (tests point it
    /// at a local mock). Downloads the WHOLE `.dig` module for `(store, root)` and writes it
    /// to `module_path(store, served_root)`, so `serve_local` then serves it — and every
    /// other resource in the store — without further network. Returns the SERVED root.
    ///
    /// # Two download paths, tried in this order
    ///
    /// 1. **The chunked `dig.getCapsule` JSON-RPC.** The public gateway caps a single
    ///    response at ~6 MB, so a real (~135 MB) capsule can only cross it in windows; this
    ///    is the gateway's own whole-capsule interface and it needs no identity (#1886).
    /// 2. **The §21.9 authenticated clone** (`GET /stores/{id}/module`), when an identity is
    ///    configured. Retained for §21 hosts that expose no `dig` JSON-RPC, and it is the
    ///    only path that carries the operator's identity.
    ///
    /// A capsule too large for path 2 is the COMMON case against the public gateway, which
    /// is why path 1 leads rather than serving as a fallback.
    ///
    /// The synced module is bound to the store's CHAIN-ANCHORED generation before it lands
    /// ([`verify_synced_capsule_is_chain_anchored`](Self::verify_synced_capsule_is_chain_anchored)).
    /// Landing a capsule is what makes this node a DISCOVERABLE holder of it (§14.1): the read-side
    /// serve gate downstream is not enough, because a capsule the node advertises poisons holder
    /// reputation and multiplies through the reshare flywheel (#1576) whether or not any later read
    /// verifies it. So this is the SAME chain-anchored check the reshare leg applies at its own seam
    /// (#1623): resolve the generation root from the chain, re-hash the module, and refuse anything
    /// that is not the store's confirmed generation — the module never reaches disk, so it is never
    /// announced.
    ///
    /// # Errors
    /// The returned string names what ACTUALLY failed — the upstream's HTTP status, its
    /// JSON-RPC error, a dishonest length, or a local write failure. It is surfaced to
    /// operators verbatim, so it must never become a list of causes that were not checked.
    async fn sync_module_from(
        &self,
        base_url: &str,
        store_hex: &str,
        root_hex: &str,
    ) -> Result<Bytes32, String> {
        if !sync_eligible(store_hex, root_hex) {
            return Err("store id and root must each be 64-hex".to_string());
        }
        let (Ok(store_id), Ok(want_root)) =
            (Bytes32::from_hex(store_hex), Bytes32::from_hex(root_hex))
        else {
            return Err("store id and root must each be 64-hex".to_string());
        };

        let (served_root, bytes) = match self
            .download_capsule(base_url, store_hex, root_hex, want_root)
            .await
        {
            Ok(v) => v,
            Err(rpc_error) => {
                tracing::debug!(
                    store = %store_hex,
                    error = %rpc_error,
                    "whole-store sync: the chunked dig.getCapsule path failed; trying the §21 clone"
                );
                self.clone_whole_store(base_url, &store_id, store_hex, &rpc_error)
                    .await?
            }
        };

        tracing::info!(
            store = %store_hex,
            served_root = %served_root.to_hex(),
            bytes = bytes.len(),
            "whole-store sync downloaded a capsule"
        );

        // Chain-anchored verify BEFORE the module lands (#1623): landing is announcing (§14.1), so an
        // unverified capsule that reaches disk turns this node into an advertised holder of content no
        // chain confirmed. Refuse anything that is not the store's chain-anchored generation — the same
        // fail-closed gate the reshare leg applies at its own seam.
        self.verify_synced_capsule_is_chain_anchored(&store_id, &served_root, &bytes)
            .await?;

        // Cache under the SERVED root (which may differ from want_root if the
        // remote head advanced between resolve and sync).
        //
        // ATOMIC + CONTENT-ADDRESSED: a module is keyed by capsule
        // (storeId:rootHash) and its bytes are immutable, so two writers (the
        // browser's in-process node + the standalone node sharing this cache)
        // produce identical bytes. `write_atomic` (temp + rename) guarantees a
        // reader never observes a torn/partial file and that the two writers
        // converge on the same final file.
        //
        // The SERVED root (not the requested one) keys the write, and both components are re-validated
        // here: `store_hex` came from the caller, and re-parsing costs nothing next to the write it
        // guards (#1599).
        let served_hex = served_root.to_hex();
        let served_key = CapsuleKey::parse(store_hex, &served_hex)
            .ok_or("the upstream served a root that is not 64-hex")?;
        let path = served_key.module_path(&self.cache_dir);
        write_atomic(&path, &bytes).map_err(|e| format!("could not write the capsule: {e}"))?;
        // #1991 telemetry: this is the choke-point every ON-DEMAND landing path funnels through —
        // `cache.fetchAndCache`, chain gap-fill, and fetch-side backfill all call down to here — so
        // counting here (rather than at any one caller) captures all three without double-counting.
        // The reshare-warm land is a SEPARATE write path (`module_reshare::promote_into_cache`,
        // never calls this function) and counts itself at its own successful write.
        CACHE_REFETCH_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(served_root)
    }

    /// Path 1: the chunked `dig.getCapsule` download. The served root is the REQUESTED root —
    /// the RPC pins the generation on the way in, so there is no server-chosen "latest" here.
    async fn download_capsule(
        &self,
        base_url: &str,
        store_hex: &str,
        root_hex: &str,
        want_root: Bytes32,
    ) -> Result<(Bytes32, Vec<u8>), String> {
        let bytes = seams::capsule::download_capsule_via_rpc(
            &self.http,
            base_url,
            store_hex,
            root_hex,
            seams::capsule::CAPSULE_WINDOW_BYTES,
        )
        .await?;
        Ok((want_root, bytes))
    }

    /// Path 2: the §21.9 authenticated whole-store clone. `rpc_error` is the reason path 1
    /// gave up, carried into the failure message so an operator sees BOTH attempts rather
    /// than only the last one.
    async fn clone_whole_store(
        &self,
        base_url: &str,
        store_id: &Bytes32,
        store_hex: &str,
        rpc_error: &str,
    ) -> Result<(Bytes32, Vec<u8>), String> {
        let Some(seed) = self.identity_seed else {
            return Err(format!(
                "dig.getCapsule failed ({rpc_error}) and the §21 clone needs an identity key, \
                 which this node has none"
            ));
        };
        // Reuse the node's reqwest client; attach a fresh §21.9 identity (the
        // client takes it by value) minted from the in-memory seed.
        let client = DigClient::with_client(base_url, self.http.clone())
            .with_identity(identity::identity_from_seed(seed));
        let verify = |bytes: &[u8], _served: &Bytes32| -> Result<(), String> {
            if bytes.is_empty() {
                Err("empty module".into())
            } else {
                Ok(())
            }
        };
        client
            .clone_store(store_id, verify, None)
            .await
            .map_err(|e| {
                tracing::warn!(
                    store = %store_hex,
                    rpc_error = %rpc_error,
                    clone_error = %e,
                    "whole-store sync failed on BOTH the dig.getCapsule and §21 clone paths"
                );
                format!("dig.getCapsule failed ({rpc_error}); the §21 clone failed ({e})")
            })
    }

    /// Prove a freshly-synced capsule is the store's chain-anchored generation, before it lands.
    ///
    /// A synced capsule comes from an UPSTREAM the node does not trust, and the act of landing it makes
    /// this node a discoverable holder (§14.1). So the bytes are bound to the CHAIN here, exactly as the
    /// #1576 reshare leg binds its own pull (`ChainAnchoredModuleVerifier`): the generation root is
    /// resolved through the chain — never taken from the serving peer — and the module is re-hashed
    /// against it. Reusing that one verifier keeps a single verification shape across every seam that
    /// admits a capsule.
    ///
    /// Fail-CLOSED, matching the reshare leg: any failure to ESTABLISH the anchor rejects the sync (the
    /// caller never writes the module, so it is never announced). The rejections, each an `Err`:
    /// - the store has no chain-confirmed generation, or the chain read failed;
    /// - the upstream served a root that is not the chain-anchored generation (a moved/forged head);
    /// - the bytes do not commit the store + the chain-anchored root.
    async fn verify_synced_capsule_is_chain_anchored(
        &self,
        store_id: &Bytes32,
        served_root: &Bytes32,
        bytes: &[u8],
    ) -> Result<(), String> {
        let chain_root = self
            .anchored_root_resolver
            .anchored_root(&store_id.0)
            .await
            .map_err(|e| format!("could not resolve the chain-anchored root: {e}"))?
            .ok_or("the store has no chain-confirmed generation to anchor the synced capsule to")?;

        // The served generation must BE the chain's. The verifier re-checks this against the module's
        // committed root, but naming it here gives an operator the exact reason a moved upstream head is
        // refused rather than a generic "not anchored".
        if *served_root != chain_root {
            return Err(format!(
                "the upstream served root {} is not the store's chain-anchored root {}",
                served_root.to_hex(),
                chain_root.to_hex()
            ));
        }

        let verifier = crate::seams::dig_peer::ChainAnchoredModuleVerifier::for_generation(
            *store_id, chain_root,
        );
        let reader = InMemoryModule(bytes.to_vec());
        match dig_download::ModuleAnchorVerifier::verify_module_anchor(
            &verifier,
            &reader,
            &store_id.to_hex(),
            &served_root.to_hex(),
        )
        .await
        {
            dig_download::ModuleAnchor::Anchored => Ok(()),
            dig_download::ModuleAnchor::NotAnchored => {
                Err("the synced module is not the store's chain-anchored .dig".to_string())
            }
            dig_download::ModuleAnchor::Unavailable(reason) => Err(format!(
                "could not verify the synced capsule's anchor: {reason}"
            )),
        }
    }

    /// Whether an upstream is configured at all (#1997). `false` is the DEFAULT, not a fault.
    ///
    /// Call this to SKIP an upstream leg rather than to attempt one and report the failure: "no
    /// upstream" is a statement about this node's configuration, and turning it into a per-request
    /// error would tell a caller their read failed for a reason that has nothing to do with their
    /// read. A miss with no upstream is a miss.
    pub fn has_upstream(&self) -> bool {
        !self.upstream.trim().is_empty()
            && !self
                .upstream_looped_back
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that this node's upstream has been PROVEN to route back to itself, and stop every
    /// outbound upstream call for the life of the process (#1997).
    ///
    /// Called by the host shell when its bring-up loop probe comes back to its own dispatcher. It
    /// must reach the engine, not just the shell: the shell's guard covers the method-passthrough
    /// relay, while the two legs that carry CONTENT — the `dig.getContent` miss proxy and the
    /// `/s/*` Tier 3 fetch — are here, and those are the expensive ones to leave looping.
    ///
    /// Never reset: an upstream cannot stop pointing at us without a configuration change, and a
    /// configuration change restarts the node.
    pub fn disable_upstream_after_loop(&self) {
        self.upstream_looped_back
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Proxy the raw JSON-RPC body to the configured upstream and return its response.
    ///
    /// Fails immediately when no upstream is configured — the default since #1997. A node with no
    /// upstream answers from what it holds; it does not forward a caller's request, with that
    /// caller's params, to a host its operator never chose. Callers on a read path should gate on
    /// [`Self::has_upstream`] first so the absence becomes a clean miss rather than this error.
    async fn proxy(&self, body: &Value) -> Result<Value, String> {
        if !self.has_upstream() {
            return Err("no upstream is configured".to_string());
        }
        let resp = self
            .http
            .post(&self.upstream)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        resp.json::<Value>().await.map_err(|e| e.to_string())
    }

    /// `dig.getAnchoredRoot`: resolve a store's CHIP-0035 chain-anchored TIP root by
    /// walking its DataStore singleton lineage on coinset.org — NEVER from the
    /// serving node (`digstore_chain::singleton::sync_datastore`). This is the
    /// trusted-root source for the browser's mandatory dig:// root pinning: a
    /// rootless `dig://` URN must verify `proof.root == anchored_root` instead of
    /// trusting the rpc-served "latest" root (which a compromised rpc could forge —
    /// the dig:// verifier must never fail open). Returns a JSON-RPC envelope with
    /// `result.root` (64-hex) on success, or a `-32602`/`-32000` error.
    async fn anchored_root(&self, params: &Value, id: Value) -> Value {
        let Ok(store_id) = parse_store_id_arg(params) else {
            return json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32602,
                "message":"params.store_id must be a 32-byte (64-hex) launcher id"}});
        };
        match sync_datastore(&resolution_coinset(), store_id).await {
            Ok(store) => json!({"jsonrpc":"2.0","id":id,"result":{
                "store_id": hex::encode(store_id),
                "root": hex::encode(store.info.metadata.root_hash)}}),
            Err(e) => json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32000,
                "message":format!("resolve anchored root: {e}")}}),
        }
    }

    /// `dig.getModuleInfo` (#1576, the reshare leg): the transfer descriptor for a whole `.dig` module
    /// this node HOLDS — the handshake a peer reads before range-pulling the entire capsule so it can
    /// become a resharer of it.
    ///
    /// Params `{store_id, root}` (both 64-hex), matching the other capsule-scoped read methods. The
    /// blocking module read + hashing runs on a `spawn_blocking` thread (a `.dig` is large; hashing it
    /// must never stall the async runtime), mirroring [`Self::get_manifest`].
    ///
    /// - Module held → `result` is the [`ModuleInfo`](dig_rpc_protocol::types::ModuleInfo) descriptor.
    /// - Module NOT held (or a 0-byte file, which is not a module) → the same
    ///   `RESOURCE_UNAVAILABLE` code `dig.fetchRange` reports on a miss. Declining is the honest answer:
    ///   describing a module this node cannot serve would advertise a capsule it does not have.
    async fn get_module_info(&self, params: &Value, id: Value) -> Value {
        let store_hex = params
            .get("store_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let root_hex = params
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !is_canonical_hex_id(&store_hex) || !is_canonical_hex_id(&root_hex) {
            return rpc_err(
                &id,
                -32602,
                "dig.getModuleInfo requires store_id + root (64-hex each)",
            );
        }
        let cache_dir = self.cache_dir.clone();
        let (store, root) = (store_hex.clone(), root_hex.clone());
        let info = tokio::task::spawn_blocking(move || {
            seams::dig_peer::module_serve::describe_module(&cache_dir, &store, &root)
        })
        .await
        .unwrap_or(None);
        // The serve log records both outcomes with sentinelled ids, so "was this holder asked for the
        // descriptor, and did it have it?" is answerable from the log alone (#1595).
        seams::dig_peer::module_serve::module_info_answered(
            "",
            &store_hex,
            &root_hex,
            info.as_ref(),
        );
        match info {
            Some(info) => match serde_json::to_value(&info) {
                Ok(value) => json!({"jsonrpc":"2.0","id":id,"result": value}),
                Err(_) => rpc_err(&id, -32000, "could not encode the module descriptor"),
            },
            None => rpc_err(
                &id,
                download::RESOURCE_UNAVAILABLE,
                "module not held locally at the requested root",
            ),
        }
    }

    /// `dig.fetchModuleRange` (#1576) over the request/response surface: ONE frame carrying the
    /// requested window of a held `.dig` module.
    ///
    /// The PEER surface streams this method (many frames until `complete`); a JSON-RPC envelope cannot
    /// express a stream, so the loopback / in-process surface answers with a single frame in `result`.
    /// The frame shape is identical either way, so an agent reads a module through the plain
    /// request/response form without implementing the frame protocol (§6.2) — it simply issues one call
    /// per window, advancing `offset` until a frame reports `complete`.
    ///
    /// Params `{store_id, root, offset?, length}`; the window is clamped to the serve cap. A module this
    /// node does not hold answers the same `RESOURCE_UNAVAILABLE` code the streaming form reports.
    async fn fetch_module_range_frame(&self, params: &Value, id: Value) -> Value {
        use seams::dig_peer::module_serve;

        let store_hex = params
            .get("store_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let root_hex = params
            .get("root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !is_canonical_hex_id(&store_hex) || !is_canonical_hex_id(&root_hex) {
            return rpc_err(
                &id,
                -32602,
                "dig.fetchModuleRange requires store_id + root (64-hex each)",
            );
        }
        let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let length = params
            .get("length")
            .and_then(Value::as_u64)
            .unwrap_or(module_serve::MAX_MODULE_WINDOW);

        let cache_dir = self.cache_dir.clone();
        let (store, root) = (store_hex.clone(), root_hex.clone());
        let window = tokio::task::spawn_blocking(move || {
            module_serve::read_module_window(&cache_dir, &store, &root, offset, length)
        })
        .await
        .unwrap_or(None);

        match window {
            Some(bytes) => {
                // `complete` is honest about THIS call: the window ends the module only when it reached
                // the module's end, which is exactly when fewer bytes came back than were asked for.
                let complete = (bytes.len() as u64) < length.min(module_serve::MAX_MODULE_WINDOW);
                let frame = module_serve::module_frame(offset, &bytes, complete, None);
                module_serve::module_range_outcome(
                    "",
                    &store_hex,
                    &root_hex,
                    offset,
                    Some((bytes.len() as u64, 1)),
                );
                json!({"jsonrpc":"2.0","id":id,"result": frame})
            }
            None => {
                module_serve::module_range_outcome("", &store_hex, &root_hex, offset, None);
                rpc_err(
                    &id,
                    download::RESOURCE_UNAVAILABLE,
                    "module not held locally at the requested root",
                )
            }
        }
    }

    /// `dig.getManifest` (#176 Phase C): resolve the normalized [`PublicManifest`](digstore_core::PublicManifest)
    /// (data-section id 13) embedded in a locally held CAPSULE's compiled `.dig` module.
    ///
    /// Params `{store_id, root}` (both 64-hex) — a capsule identifier
    /// (`storeId:rootHash`), matching the shape of the other capsule-scoped read
    /// methods (`dig.getAvailability`/`dig.fetchRange`). No `retrieval_key`: the
    /// manifest is PUBLIC, unencrypted data, so no decrypt is needed.
    ///
    /// The blocking module read + wasm data-section extraction runs on a
    /// `spawn_blocking` thread (mirrors [`serve_local_blocking`], audit #179) so it
    /// never stalls the async runtime.
    ///
    /// - Module held, section present → `result` is the manifest JSON
    ///   (`{schema_version, entries: [...]}`, digstore SPEC.md § the `.dig` format).
    /// - Module held, section ABSENT (an older `.dig`, or a PRIVATE store whose
    ///   paths must stay opaque) → `result: null` — **never an error** (store-format
    ///   §5.1: an optional section's absence is a normal, backwards-compatible
    ///   outcome).
    /// - Module NOT held locally at all → `-32004` (the same "not available at this
    ///   root" code [`dig.fetchRange`](Self::fetch_range_frame) reports on a miss).
    /// - A corrupt on-disk module → `-32000`.
    async fn get_manifest(&self, params: &Value, id: Value) -> Value {
        let store_hex = params.get("store_id").and_then(Value::as_str).unwrap_or("");
        let root_hex = params.get("root").and_then(Value::as_str).unwrap_or("");
        let Some(capsule) = CapsuleKey::parse(store_hex, root_hex) else {
            return rpc_err(
                &id,
                -32602,
                "dig.getManifest requires store_id + root (64-hex each)",
            );
        };
        let cache_dir = self.cache_dir.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            read_public_manifest_blocking(&cache_dir, &capsule)
        })
        .await;
        match outcome {
            // Module held, PublicManifest section present.
            Ok(Ok(Some(Some(pm)))) => {
                // Reuse `PublicManifest::to_json` (the SAME renderer digstore's CLI/wasm
                // readers use) so the shape is byte-for-byte identical across the ecosystem,
                // then parse it back into a `Value` for the JSON-RPC `result` field.
                let value = serde_json::from_str::<Value>(&pm.to_json()).unwrap_or_else(
                    |_| json!({"schema_version": pm.schema_version, "entries": []}),
                );
                json!({"jsonrpc":"2.0","id":id,"result": value})
            }
            // Module held, no PublicManifest section — tolerate absence, never an error.
            Ok(Ok(Some(None))) => json!({"jsonrpc":"2.0","id":id,"result": Value::Null}),
            // This node does not hold the requested capsule at all.
            Ok(Ok(None)) => rpc_err(
                &id,
                download::RESOURCE_UNAVAILABLE,
                "capsule not held locally at the requested root",
            ),
            // The on-disk module's data section is corrupt/malformed.
            Ok(Err(msg)) => rpc_err(&id, -32000, &msg),
            Err(join_err) => rpc_err(
                &id,
                -32000,
                &format!("manifest read task failed: {join_err}"),
            ),
        }
    }

    /// dig.stage (#95 Pass C): turn a local folder into a CAPSULE (`.dig` module)
    /// in process — the staging/compile half of a local deploy.
    ///
    /// This drives the SHARED stage→compile engine ([`digstore_stage`]) the CLI
    /// `commit`/`compile` use, so the produced module + root are byte-identical to
    /// a CLI build of the same files. It is build-only: NO wallet, NO chain, NO
    /// §21 push. The browser then signs the on-chain root advance with the Pass B
    /// `chia_advanceStore` wallet method and §21-pushes `module_path`.
    ///
    /// Params:
    /// - `dir` (required): absolute path to the folder to publish.
    /// - `store_id` (optional 64-hex): the EXISTING store's launcher id this
    ///   capsule advances. Absent ⇒ an EPHEMERAL, content-derived store id
    ///   (`sha256(fresh host pubkey)`, like `digstore init`) — a preview capsule
    ///   that NEVER advances or impersonates a real store (`ephemeral:true`).
    /// - `salt` (optional 64-hex): present ⇒ a PRIVATE store (retrieval keys are
    ///   derived from `urn + salt`); absent ⇒ public.
    /// - `metadata` (optional): the dighub `Manifest` JSON embedded in the module.
    ///
    /// Result `{capsule, store_id, root, module_path, size, content_address,
    /// files, ephemeral}`. Catalogued errors: `-32602` invalid params,
    /// `-32011` dir not a readable directory, `-32012` no files staged,
    /// `-32013` over the store size cap, `-32014` compile/IO failure.
    fn stage(&self, params: &Value, id: Value) -> Value {
        let err = |code: i64, msg: String| -> Value {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
        };

        // 1. The folder to publish (required, must be a readable directory).
        let Some(dir) = params
            .get("dir")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        else {
            return err(
                -32602,
                "params.dir is required (absolute folder path)".into(),
            );
        };
        let dir = std::path::PathBuf::from(dir);
        if !dir.is_dir() {
            return err(-32011, format!("not a directory: {}", dir.display()));
        }

        // 2. Optional store id (advance an EXISTING store) or ephemeral preview id.
        let store_id_arg = match params.get("store_id").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() => match Bytes32::from_hex(h.trim_start_matches("0x")) {
                Ok(b) => Some(b),
                Err(_) => return err(-32602, "params.store_id must be 64-hex".into()),
            },
            _ => None,
        };

        // 3. Optional secret salt ⇒ a private store.
        let visibility = match params.get("salt").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() => match Bytes32::from_hex(h.trim_start_matches("0x")) {
                Ok(b) => digstore_core::Visibility::Private(digstore_core::SecretSalt(b.0)),
                Err(_) => return err(-32602, "params.salt must be 64-hex".into()),
            },
            _ => digstore_core::Visibility::Public,
        };

        // 4. Fresh host BLS identity for the compiled module's trusted/serving key
        //    (mirrors `digstore init`: a content-authoring key, persisted nowhere
        //    here — the browser's wallet signs the on-chain advance, and the §21
        //    push is authenticated by the node's own §21 identity, not this key).
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS CSPRNG must be available for the stage key");
        let host_pubkey = digstore_crypto::bls::SecretKey::from_seed(&seed)
            .public_key()
            .to_bytes();

        // Ephemeral store id is content-derived (= `sha256(host pubkey)`, exactly
        // like `init_store`); a supplied store_id is used verbatim.
        let ephemeral = store_id_arg.is_none();
        let store_id = store_id_arg.unwrap_or_else(|| digstore_crypto::sha256(&host_pubkey.0));

        // 5. Walk the folder into (resource_key, bytes), keys relative to `dir`.
        let files = match walk_dir_files(&dir) {
            Ok(f) => f,
            Err(e) => return err(-32011, format!("read folder {}: {e}", dir.display())),
        };
        if files.is_empty() {
            return err(-32012, format!("no files to stage under {}", dir.display()));
        }

        // 6. Optional metadata manifest (the dighub `Manifest` JSON); else empty.
        //    Reuses the SHARED parser the CLI `compile` uses (no fork).
        let metadata = match params.get("metadata") {
            Some(v) if !v.is_null() => digstore_stage::manifest_from_json(v),
            _ => digstore_stage::empty_manifest(),
        };

        // 7. Scratch data dir under the cache: `<cache>/staging/<store>-<pid>-<ns>`.
        //    The compiled module lands in `<scratch>/modules/`; the browser §21-pushes it.
        let scratch = self.cache_dir.join("staging").join(format!(
            "{}-{}-{}",
            store_id.to_hex(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        let opts = digstore_stage::FinalizeOptions {
            data_dir: scratch,
            trusted_keys: vec![digstore_core::TrustedHostKey {
                public_key: host_pubkey.0,
                label: format!("dig-host-key-v1:{}", host_pubkey.to_hex()),
            }],
            store_pubkey: host_pubkey,
            metadata,
            chain_state: None,
            auth: digstore_stage::no_auth(),
            // Embed the normalized PublicManifest section (id 13, #176 Phase A) only for
            // PUBLIC stores — a private store's file paths must stay opaque (§5.1 / privacy
            // model), matching the CLI's own `finalize_commit` rule.
            include_public_manifest: matches!(visibility, digstore_core::Visibility::Public),
        };

        // 8. Stage → compile (generation 0; the browser advances the on-chain root).
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let compiled = match digstore_stage::stage_and_compile(
            &files,
            store_id,
            &visibility,
            digstore_core::MAX_STORE_BYTES,
            false,
            0,
            timestamp,
            &opts,
        ) {
            Ok(c) => c,
            Err(digstore_stage::StageError::EmptyStaging) => {
                return err(-32012, format!("no files to stage under {}", dir.display()))
            }
            Err(e @ digstore_stage::StageError::OverCap { .. }) => {
                return err(-32013, e.to_string())
            }
            Err(e) => return err(-32014, format!("stage/compile failed: {e}")),
        };

        let root_hex = compiled.root.to_hex();
        let store_hex = store_id.to_hex();
        json!({"jsonrpc":"2.0","id":id,"result":{
            // The canonical capsule identity (storeId:rootHash) — the unit the
            // browser advances on-chain + §21-pushes.
            "capsule": format!("{store_hex}:{root_hex}"),
            "store_id": store_hex,
            "root": root_hex,
            "module_path": compiled.module_path.display().to_string(),
            "size": compiled.size,
            // The chia:// content-open address for this capsule (the user-facing
            // scheme the DIG Browser/extension register; matches deploy --preview).
            "content_address": format!("chia://{store_hex}:{root_hex}/"),
            "files": compiled.files(),
            // true ⇒ a preview capsule with a content-derived id (NOT a real store).
            "ephemeral": ephemeral,
        }})
    }

    // -- Public collection reads (#39) -----------------------------------------
    //
    // Owner-independent, third-party-indexer-free reads of an NFT collection from
    // DIG's own coinset data. Read-only: NO spend bundles are built or pushed. The
    // item set is the NFT launcher ids the collection mint produced — the stable,
    // owner-independent anchor (a DID-attributed NFT is hinted to its OWNER at mint,
    // not to the creator DID, so launcher ids — not the DID — are the discovery key;
    // see digstore_chain::collection_index). Each launcher is resolved to its CURRENT
    // on-chain owner + royalty + CHIP-0007 metadata by walking the singleton lineage
    // forward to the unspent tip, so the reported owner is always live, not mint-time.

    /// Parse `params.launcher_ids` (an array of 64-hex strings) into canonical
    /// [`chia_protocol::Bytes32`] launcher ids, preserving order (the result is
    /// deterministic in input order). `Err(bad_value)` names the first malformed id.
    ///
    /// The array length is CAPPED at [`MAX_LAUNCHER_IDS`] (audit #179 HIGH): `dig.getCollection`
    /// / `dig.listCollectionItems` are peer-reachable and each launcher id costs one chain
    /// (coinset.org) read, so an uncapped array is an outbound-fanout amplifier. An over-cap
    /// array is rejected here (before any chain read) rather than resolved. `dig.getCollection`
    /// resolves the WHOLE array, so the cap is the collection's hard item ceiling per call;
    /// `dig.listCollectionItems` additionally paginates within it (≤200 per page).
    fn parse_launcher_ids(params: &Value) -> Result<Vec<chia_protocol::Bytes32>, String> {
        let arr = params
            .get("launcher_ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                "params.launcher_ids must be an array of 64-hex launcher ids".to_string()
            })?;
        if arr.len() > MAX_LAUNCHER_IDS {
            return Err(format!(
                "too many launcher_ids: {} (max {MAX_LAUNCHER_IDS})",
                arr.len()
            ));
        }
        let mut out = Vec::with_capacity(arr.len());
        for v in arr {
            let s = v
                .as_str()
                .ok_or_else(|| "each launcher id must be a 64-hex string".to_string())?;
            let h = s.trim_start_matches("0x");
            let bytes = hex::decode(h).map_err(|_| format!("launcher id is not hex: {s}"))?;
            let a: [u8; 32] = bytes
                .try_into()
                .map_err(|_| format!("launcher id must be 32 bytes (64 hex): {s}"))?;
            out.push(chia_protocol::Bytes32::new(a));
        }
        Ok(out)
    }

    /// Render one resolved [`IndexedNft`](digstore_chain::collection_index::IndexedNft)
    /// as the stable JSON-RPC item shape. Field names mirror the asset CLI
    /// (`launcher_id`/`coin_id`/`owner_did`/`royalty_*`/`owner_puzzle_hash`), with the
    /// decoded on-chain CHIP-0007 metadata under `metadata` (null when it does not
    /// decode). The on-chain `NftMetadata` (CLVM struct) carries no serde derive, so
    /// the metadata object is rendered field-by-field with stable names + lowercase-hex
    /// 32-byte hashes — a self-describing, agent-consumable shape.
    fn item_json(item: &digstore_chain::collection_index::IndexedNft) -> Value {
        let metadata = item
            .metadata
            .as_ref()
            .map(|m| {
                json!({
                    "edition_number": m.edition_number,
                    "edition_total": m.edition_total,
                    "data_uris": m.data_uris,
                    "data_hash": m.data_hash.map(hex::encode),
                    "metadata_uris": m.metadata_uris,
                    "metadata_hash": m.metadata_hash.map(hex::encode),
                    "license_uris": m.license_uris,
                    "license_hash": m.license_hash.map(hex::encode),
                })
            })
            .unwrap_or(Value::Null);
        json!({
            "launcher_id": hex::encode(item.launcher_id),
            "coin_id": hex::encode(item.coin_id),
            "owner_did": item.owner_did.map(hex::encode),
            "royalty_puzzle_hash": hex::encode(item.royalty_puzzle_hash),
            "royalty_basis_points": item.royalty_basis_points,
            "owner_puzzle_hash": hex::encode(item.owner_puzzle_hash),
            "metadata": metadata,
        })
    }

    /// `dig.getCollection` — collection-level facts for a given item set.
    ///
    /// Params: `launcher_ids` (required array of 64-hex), optional `did` (64-hex; the
    /// collection's creator DID, echoed + used as the expected attribution). Resolves
    /// every launcher to its current state, then derives the shared creator DID (if
    /// uniform), the resolved item count, and the uniform royalty.
    ///
    /// Result: `{ did, declared_did, item_count, resolved_count, royalty_basis_points }`.
    /// Errors: `-32602` invalid params.
    async fn get_collection(params: &Value, id: Value) -> Value {
        let launcher_ids = match Self::parse_launcher_ids(params) {
            Ok(v) => v,
            Err(msg) => {
                return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":msg}})
            }
        };
        // Optional declared creator DID (echoed back; the source of truth is the
        // items' on-chain attribution).
        let declared_did = params
            .get("did")
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches("0x").to_string());

        let chain = resolution_coinset();
        let items =
            match digstore_chain::collection_index::index_collection_items(&chain, &launcher_ids)
                .await
            {
                Ok(items) => items,
                Err(e) => {
                    return json!({"jsonrpc":"2.0","id":id,"error":{
                    "code":-32000,"message":format!("read collection: {e}")}})
                }
            };
        let summary = digstore_chain::collection_index::summarize_collection(&items);
        json!({"jsonrpc":"2.0","id":id,"result":{
            // The creator DID the items AGREE on (None if mixed/none), lowercase hex.
            "did": summary.did.map(hex::encode),
            // The DID the caller declared (echoed; may be null).
            "declared_did": declared_did,
            // How many launcher ids were requested vs how many resolved to a live NFT.
            "item_count": launcher_ids.len(),
            "resolved_count": summary.item_count,
            // The royalty every item agrees on (basis points), or null when mixed.
            "royalty_basis_points": summary.royalty_basis_points,
        }})
    }

    /// `dig.listCollectionItems` — a deterministic, paginated page of a collection's
    /// items resolved to their CURRENT on-chain state.
    ///
    /// Params: `launcher_ids` (required array of 64-hex; the authoritative item set),
    /// optional `offset` (default 0) + `limit` (default 50, capped 200). Pagination is
    /// applied over the launcher-id list BEFORE resolution, so only the requested page
    /// is read from chain. Order is the input order (stable).
    ///
    /// Result: `{ items: [ {launcher_id, coin_id, owner_did, royalty_puzzle_hash,
    /// royalty_basis_points, owner_puzzle_hash, metadata} ], offset, limit, total,
    /// next_offset }`. `next_offset` is null on the last page. Errors: `-32602`.
    async fn list_collection_items(params: &Value, id: Value) -> Value {
        let launcher_ids = match Self::parse_launcher_ids(params) {
            Ok(v) => v,
            Err(msg) => {
                return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":msg}})
            }
        };
        let total = launcher_ids.len();
        let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        // Default page 50, capped at 200 so one call can't fan out unbounded chain reads.
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.min(200))
            .unwrap_or(50) as usize;

        let page: Vec<chia_protocol::Bytes32> = launcher_ids
            .iter()
            .skip(offset)
            .take(limit)
            .copied()
            .collect();

        let chain = resolution_coinset();
        let resolved =
            match digstore_chain::collection_index::index_collection_items(&chain, &page).await {
                Ok(items) => items,
                Err(e) => {
                    return json!({"jsonrpc":"2.0","id":id,"error":{
                    "code":-32000,"message":format!("list collection items: {e}")}})
                }
            };
        let items: Vec<Value> = resolved.iter().map(Self::item_json).collect();
        // next_offset points past this page unless we have reached the end of the input.
        let consumed = offset.saturating_add(page.len());
        let next_offset = if consumed < total {
            json!(consumed)
        } else {
            Value::Null
        };
        json!({"jsonrpc":"2.0","id":id,"result":{
            "items": items,
            "offset": offset,
            "limit": limit,
            "total": total,
            "next_offset": next_offset,
        }})
    }

    // -- Cached-store management (the DIG-settings cache manager, task #32) -----
    //
    // Every cached module is one CAPSULE — the canonical `(store_id, root_hash)`
    // identity (`digstore_core::Capsule`, rendered `storeId:rootHash`). The
    // on-disk cache key IS that capsule: each module lives at
    // `module_path(store_hex, root_hex)` = `<cache>/modules/<storeId>/<root>.dig`,
    // so listing/removing/fetching are all keyed by capsule identity.

    // -- L7 peer RPC (PHASE-2b, #162) — serving the node's LOCAL inventory ------
    //
    // The node serves the SAME content over the peer network that it serves over §21 / the HTTP read
    // path: the capsules cached on disk. These build the L7 answers (`dig.getAvailability`,
    // `dig.listInventory`, `dig.fetchRange`, `dig.getNetworkInfo`) from `cache_list_cached()` +
    // `serve_local`. They are pure reads of local state (no chain, no upstream), so a peer only ever
    // learns what this node already holds. Every byte a peer fetches carries its own merkle proof
    // (verified by the caller against the chain-anchored root), so the node is never the trust anchor.

    /// `dig.getAvailability` — answer one queried item against the local inventory, enriching the
    /// pure presence answer (`peer::availability_presence`) with the per-resource `total_length` +
    /// `chunk_count` when the item is at resource granularity (`store_id` + `root` + `retrieval_key`)
    /// and the resource is actually served locally. Returns one `AvailabilityAnswer` value.
    ///
    /// Takes a `cached` inventory SNAPSHOT (audit #179) used for the STORE-granularity `roots`
    /// enumeration only: the caller ([`Node::availability_batch`]) walks the cache directory at most
    /// ONCE per batch and passes the slice in, so an N-item batch does O(1) directory walks.
    ///
    /// ROOT/RESOURCE granularity does NOT consult that snapshot (#1592): the held answer is
    /// [`module_exists`] — a single on-disk existence check of the very file
    /// [`serve_local_blocking`] reads — so the answer cannot drift from what the node can serve in
    /// either direction (a capsule landing after the snapshot is immediately available; an evicted
    /// one immediately is not). One `stat` per item is also strictly cheaper than the walk on this
    /// peer-facing path.
    async fn availability_answer(&self, item: &Value, cached: &[CachedCapsule]) -> Value {
        let store = item.get("store_id").and_then(Value::as_str).unwrap_or("");
        let root = item.get("root").and_then(Value::as_str);
        let rk = item.get("retrieval_key").and_then(Value::as_str);
        // The peer supplies `store`/`root`, so the keys are validated canonical 64-hex BEFORE any path
        // is built from them (the same guard `cache_remove_cached` applies) — a non-canonical key can
        // never name a held capsule, so it answers not-available without touching the filesystem.
        let canonical_root = root.filter(|r| CapsuleKey::parse(store, r).is_some());
        let servable = canonical_root
            .map(|r| module_exists(&self.cache_dir, store, r))
            .unwrap_or(false);
        let mut answer = peer::availability_presence(cached, store, root, rk, servable);

        // #1595: name the answer AND why it was given, so a read diagnosis can tell "we do not hold
        // it" apart from "that key could never name a capsule" — the availability gate a
        // DHT-discovered holder must pass is otherwise silent.
        let reason = match (root, canonical_root, servable) {
            (None, _, _) => serve_log::AvailabilityReason::StoreRoots {
                held: answer["roots"].as_array().map(Vec::len).unwrap_or(0),
            },
            (Some(_), None, _) => serve_log::AvailabilityReason::RejectedNonCanonicalKey,
            (Some(_), Some(_), true) => serve_log::AvailabilityReason::Held,
            (Some(_), Some(_), false) => serve_log::AvailabilityReason::NotHeld,
        };
        serve_log::availability_answered(
            store,
            root,
            rk,
            answer["available"].as_bool().unwrap_or(false),
            &reason,
        );

        // Resource granularity: if we hold this capsule AND can serve the resource, report its
        // ciphertext length + chunk count so the caller can plan ranges without a probe fetch.
        if let (Some(root_hex), Some(rk_hex)) = (root, rk) {
            if answer["available"].as_bool() == Some(true) {
                if let Ok(rk_bytes) = decode_rk(rk_hex) {
                    if let Some(resp) = self.serve_local_cached(store, root_hex, &rk_bytes).await {
                        if let Some(obj) = answer.as_object_mut() {
                            obj.insert("total_length".into(), json!(resp.ciphertext.len()));
                            obj.insert("chunk_count".into(), json!(chunk_count_for(&resp)));
                            obj.insert("complete".into(), json!(true));
                        }
                    }
                }
            }
        }

        // NOT-HELD → REDIRECT-ON-MISS hint (#165, read tier): if this node lacks the item but its P2P
        // engine locates holders in the DHT, name them in a `providers` array so the caller re-requests
        // against a holder instead of dead-ending — the availability-shaped counterpart to the
        // getContent/fetchRange redirect. No engine / no provider → the plain not-available answer
        // stands (the field is simply absent). Self is excluded by `find_providers`.
        if answer["available"].as_bool() != Some(true) {
            if let Some(pc) = self.p2p_content() {
                if let Some(content) = download::availability_content_id(store, root, rk) {
                    let providers = pc.find_providers(&content).await;
                    if !providers.is_empty() {
                        if let Some(obj) = answer.as_object_mut() {
                            obj.insert("providers".into(), download::providers_json(&providers));
                        }
                    }
                }
            }
        }
        answer
    }

    /// `dig.getAvailability` — batch answer for `items` (positionally aligned). Wraps
    /// [`Node::availability_answer`] per item into the `{ "items": [...] }` result shape.
    ///
    /// The cache inventory is snapshotted at most ONCE here and shared across every item (audit
    /// #179): each answer used to walk the whole `<cache>/modules` directory, so an N-item batch did
    /// N full directory walks. Since #1592 the walk is needed ONLY to enumerate the `roots` of a
    /// STORE-granularity item (`root` absent) — root/resource items answer from a single
    /// [`module_exists`] check — so a batch of root/resource items (what a downloading peer actually
    /// sends) does ZERO directory walks. That matters here: this is a peer-reachable path (§7.4), and
    /// a per-request walk of the whole cache is a cost amplifier a peer controls.
    ///
    /// The batch is CAPPED at [`MAX_AVAILABILITY_ITEMS`] — the item count is caller-controlled — with
    /// the excess simply not answered (the result array is aligned to the answered prefix).
    pub async fn availability_batch(&self, items: &[Value]) -> Value {
        let capped = &items[..items.len().min(MAX_AVAILABILITY_ITEMS)];
        // At most one directory walk for the whole batch, and none at all unless some item asks at
        // STORE granularity (the only answer that needs the held-roots enumeration).
        let needs_inventory = capped
            .iter()
            .any(|i| i.get("root").and_then(Value::as_str).is_none());
        let cached = if needs_inventory {
            self.cache_list_cached().await
        } else {
            Vec::new()
        };
        let mut answers = Vec::with_capacity(capped.len());
        for item in capped {
            answers.push(self.availability_answer(item, &cached).await);
        }
        json!({ "items": answers })
    }

    /// `dig.fetchRange` — build ONE range frame (the node window is a single frame; the caller streams
    /// further windows by advancing `offset`). Serves the resource's ciphertext from a locally cached
    /// module and slices `[offset, offset+length)` (clamped to the node window) — exactly the span
    /// asked for, never widened. EVERY frame carries the verification metadata (`total_length`,
    /// `chunk_lens`, `root`, `inclusion_proof`, and `first_chunk_index`/`chunk_index` when the window
    /// starts on a chunk boundary) so a range fetched at ANY offset from ANY holder is independently
    /// checkable against the chain-anchored root on arrival — see
    /// [`range_frame`](crate::seams::content::range_frame) for the contract, and for why no per-CHUNK
    /// proof is served. Returns `Err((code, message))` with the catalogued `-32004`/`-32007` on a miss / bad
    /// range. (Capsule fetches — `capsule: true` — are not yet served here; that lands with the whole
    /// `.dig` streaming path and returns `-32004` for now, a clean seam.)
    /// The locally-held resource a `dig.fetchRange` stream serves, or the catalogued refusal
    /// (`-32602` for a malformed retrieval key, `-32004` for a resource this node does not hold).
    ///
    /// Split out of [`fetch_range_frame`](Self::fetch_range_frame) so a STREAM resolves its resource
    /// ONCE and then frames it. That matters beyond efficiency: the prologue's paging state — which
    /// `chunk_lens` page is next, whether the inclusion proof has gone out — belongs to the STREAM,
    /// and a per-frame lookup has nowhere to keep it. It is the concrete reason the layout could
    /// previously only ever ride the first frame, and therefore why a layout too large for one frame
    /// had no representation at all (#1668).
    pub(crate) async fn range_source(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
    ) -> Result<Arc<ContentResponse>, (i64, String)> {
        let rk = decode_rk(rk_hex).map_err(|_| {
            (
                -32602,
                "retrieval_key must be 32 bytes (64-hex)".to_string(),
            )
        })?;
        self.serve_local_cached(store_hex, root_hex, &rk)
            .await
            .ok_or((
                -32004,
                "resource not held at the requested root".to_string(),
            ))
    }

    pub async fn fetch_range_frame(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
        offset: usize,
        length: usize,
    ) -> Result<Value, (i64, String)> {
        let resp = self.range_source(store_hex, root_hex, rk_hex).await?;

        let total = resp.ciphertext.len();
        // offset past the end is unsatisfiable (spec -32007). offset == total is the empty terminal.
        if offset > total {
            return Err((
                -32007,
                format!("offset {offset} beyond resource length {total}"),
            ));
        }
        let start = offset.min(total);
        // Clamped to the per-FRAME payload cap, not [`peer::RANGE_WINDOW`] (the per-REQUEST window,
        // 96x larger). A caller streams further windows by advancing `offset`; sizing one frame by the
        // request window is what made every read over roughly 48 KiB unserveable (#1640/#1668).
        let end = (start + length.min(range_frame::FRAME_PAYLOAD)).min(total);
        let window = resp.ciphertext[start..end].to_vec();
        let complete = end >= total;

        let mut frame = json!({
            "offset": start,
            "length": window.len(),
            "bytes": base64::engine::general_purpose::STANDARD.encode(&window),
            "complete": complete,
        });
        // EVERY frame carries the per-range verification metadata (#1577, L7 SPEC §9) so a range
        // fetched at any offset from any holder is checkable on arrival — see the `range_frame`
        // module for the contract and for why no per-CHUNK proof is (or can be) served.
        let chunk_lens: Vec<u64> = resp.chunk_lens.iter().map(|&l| u64::from(l)).collect();
        let root = resp.roothash.to_hex();
        let proof = base64::engine::general_purpose::STANDARD.encode(resp.merkle_proof.to_bytes());
        range_frame::attach_verification(
            &mut frame,
            &range_frame::RangeVerification {
                total_length: total as u64,
                chunk_lens: &chunk_lens,
                root: Some(&root),
                inclusion_proof: Some(&proof),
            },
            start as u64,
        );
        Ok(frame)
    }

    /// `dig.getNetworkInfo` — this node's own network posture: its `peer_id`, network id, listen
    /// address, candidate addresses, reachability, and relay-reservation state. Reads the shared
    /// [`peer::PeerStatus`] so it reflects the live pool/relay state (or "not running" in the FFI
    /// path). Never touches the chain or an upstream.
    pub fn network_info(&self) -> Value {
        let peer_id = self.peer_id_hex();
        let network_id = peer::effective_network_label_from_env();
        let genesis = hex::encode(peer::genesis_challenge_from_env());
        let endpoint = peer::relay_url_from_env();
        let port = peer::peer_port_from_env();
        // The node's REAL advertised candidate addresses, ordered IPv6-first (ecosystem HARD RULE):
        // a routable IPv6 address (when discoverable) precedes the IPv4 fallback. `listen_addr` reports
        // the primary (IPv6-preferred) advertised endpoint — a dialable address, NOT the wildcard bind
        // address (`[::]` / `0.0.0.0`) the listener binds. (The listener itself binds `[::]` dual-stack;
        // that wildcard is a bind target, never a dialable candidate to report to peers.)
        let candidates = net::advertised_socket_addrs(port, net::advertise_loopback_from_env());
        let candidate_addresses: Vec<String> = candidates.iter().map(|a| a.to_string()).collect();
        let listen = candidate_addresses
            .first()
            .cloned()
            .unwrap_or_else(|| format!("[::]:{port}"));
        let snap = self
            .peer_status
            .snapshot_json(&endpoint, &network_id, &genesis);
        let reserved = snap["relay"]["reserved"].as_bool().unwrap_or(false);
        // Conservative, honest reachability: while a relay reservation is held we report "relayed"
        // (a NAT'd node reached via the relay). A confirmed direct inbound mapping (UPnP/NAT-PMP/PCP)
        // is not yet surfaced by the pool, so "direct" is reported only when no relay is in use rather
        // than claimed without evidence. (A future mapping-probe upgrades this to "direct".)
        let reachability = if reserved { "relayed" } else { "direct" };
        json!({
            "peer_id": peer_id,
            "network_id": network_id,
            // The effective L2 genesis (64-hex) this node is running on — surfaced so an operator can
            // see the REAL network a `DIG_NETWORK_GENESIS`-overridden node joined, not just the label
            // (#1372). Byte-identical to the canonical mainnet genesis when unconfigured.
            "genesis": genesis,
            "listen_addr": listen,
            "reflexive_addr": Value::Null,
            "candidate_addresses": candidate_addresses,
            "reachability": reachability,
            "relay": snap["relay"],
        })
    }
}

/// The number of chunks a served [`ContentResponse`] carries: the length of `chunk_lens`, or `1` for
/// a single-chunk resource (which omits `chunk_lens`). Pure over the response.
fn chunk_count_for(resp: &ContentResponse) -> usize {
    if resp.chunk_lens.is_empty() {
        1
    } else {
        resp.chunk_lens.len()
    }
}

/// One cached capsule, as returned by [`Node::cache_list_cached`]. Identity is the
/// `(store_id, root)` capsule (`digstore_core::Capsule`, `storeId:rootHash`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CachedCapsule {
    /// Store id (lowercase 64-hex) — the directory name under `<cache>/modules/`.
    pub store_id: String,
    /// Generation root hash (lowercase 64-hex) — the `<root>.dig` file stem.
    pub root: String,
    /// On-disk size of the cached module, in bytes.
    pub size_bytes: u64,
    /// Last-used time (file mtime, the LRU recency stamp) in Unix epoch ms.
    pub last_used_unix_ms: u64,
}

/// Bump a file's mtime to "now" so the LRU treats it as freshly used.
fn touch(path: &Path) {
    let _ = filetime::set_file_mtime(path, filetime::FileTime::now());
}

// `AnchoredRootResolver` + `AnchoredStoreState` moved to `crate::shared::chain_view` (#1285 W1a —
// this is cross-seam vocabulary the local-content seam and `chainwatch` both depend on, not
// content-serve-private); re-exported below so the existing `crate::AnchoredRootResolver` /
// `crate::AnchoredStoreState` paths keep working unchanged.
pub use shared::chain_view::{AnchoredRootResolver, AnchoredStoreState};

/// Whether the mandatory read-path root pin is enforced. Default: ENFORCED
/// (fail-closed). The ONLY opt-out is the explicit `DIG_NODE_PIN=off`
/// environment variable for offline/local development — a deliberate, named
/// escape hatch, never the default. Any other value (or unset) enforces the pin.
///
/// This mirrors the CLI's stance (the pin is on; offline tests opt out via the
/// `DIGSTORE_ANCHOR_MOCK*` envs): a read either resolves against the
/// chain-anchored root or refuses to serve.
fn pin_enforced() -> bool {
    !matches!(
        std::env::var("DIG_NODE_PIN").ok().as_deref(),
        Some("off") | Some("0") | Some("false")
    )
}

/// Outcome of the read-path anchored-root pin for one `dig.getContent` call.
enum PinDecision {
    /// Serve against this concrete root (the chain-anchored tip). For an
    /// explicit-root request this equals the requested root; for a rootless
    /// request it is the resolved tip.
    ServeAt(Bytes32),
    /// Pinning is disabled (`DIG_NODE_PIN=off`); serve against the requested root
    /// as-is. The browser/SDK client still verifies the proof against its own
    /// trust root, so this only relaxes the NODE-side gate for local dev.
    Unpinned,
    /// Fail closed with this JSON-RPC error code + message (mismatch / chain
    /// unreachable / no confirmed generation / rootless under enforcement).
    Reject(i64, String),
}

/// Decide what root a `dig.getContent` call may serve against, enforcing the
/// mandatory chain-anchored pin (#127). Pure over its inputs (the resolved
/// `anchored` value), so the policy is unit-tested directly:
///
/// - pin disabled → [`PinDecision::Unpinned`].
/// - chain unreachable (`Err`) → reject (fail closed; never serve a root the
///   chain could not confirm).
/// - no confirmed generation (`Ok(None)`) → reject.
/// - explicit `requested` root present → it MUST equal the anchored root, else
///   reject; on match, serve at the anchored root.
/// - rootless request (`requested` is `None`) → serve at the resolved anchored
///   root (the chain tip is the authority — NEVER an upstream "latest").
fn decide_pin(
    enforced: bool,
    requested: Option<Bytes32>,
    anchored: Result<Option<Bytes32>, String>,
) -> PinDecision {
    if !enforced {
        return PinDecision::Unpinned;
    }
    let anchored = match anchored {
        Ok(Some(root)) => root,
        Ok(None) => {
            return PinDecision::Reject(
                ROOT_NOT_ANCHORED,
                "store has no confirmed on-chain generation (chain is the authority)".into(),
            )
        }
        Err(e) => {
            return PinDecision::Reject(
                ROOT_NOT_ANCHORED,
                format!("could not read the store's on-chain root: {e} (chain is the authority)"),
            )
        }
    };
    match requested {
        Some(req) if req != anchored => PinDecision::Reject(
            ROOT_NOT_ANCHORED,
            format!(
                "served root {} does not match the store's on-chain root {} (chain is the authority)",
                req.to_hex(),
                anchored.to_hex()
            ),
        ),
        // Explicit root matches the chain tip, or rootless → serve at the tip.
        _ => PinDecision::ServeAt(anchored),
    }
}

/// Parse a `params.store_id` field into a canonical 32-byte (64-hex) launcher id
/// (`chia_protocol::Bytes32`, as `sync_datastore` expects). Returns `Err(())` for a
/// missing, mis-sized, or non-hex value.
fn parse_store_id_arg(params: &Value) -> Result<chia_protocol::Bytes32, ()> {
    let s = params.get("store_id").and_then(|v| v.as_str()).ok_or(())?;
    if s.len() != 64 {
        return Err(());
    }
    let bytes = hex::decode(s).map_err(|_| ())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    Ok(chia_protocol::Bytes32::new(arr))
}

/// String-in / string-out convenience over [`handle_rpc`] for FFI callers
/// (`dig-runtime`): parse the JSON-RPC request text, dispatch, return the
/// response as JSON text. Keeps serde out of the FFI crate so the browser side
/// is a plain `*const c_char -> *mut c_char` call.
pub async fn handle_rpc_json(
    node: &Node,
    req_json: &str,
    origin: crate::download::ReadOrigin,
    provenance: crate::download::RequestProvenance,
) -> String {
    let req: Value = match serde_json::from_str(req_json) {
        Ok(v) => v,
        Err(e) => {
            return json!({"jsonrpc":"2.0","id":null,
                "error":{"code":-32700,"message":format!("parse error: {e}")}})
            .to_string()
        }
    };
    handle_rpc(node, req, origin, provenance).await.to_string()
}

/// Build a JSON-RPC 2.0 error response envelope. A free function (not the local `err` closure inside
/// [`handle_rpc`]'s getContent section) so the early peer-RPC handlers can report catalogued errors
/// before that closure is in scope.
fn rpc_err(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

/// Core JSON-RPC dispatch — the actual DIG node. Takes the request Value and
/// returns the response Value. This is the single source of truth shared by the
/// service shell's HTTP transport (`dig-node-service`) AND the in-process FFI
/// (`dig-runtime`), so the browser process can *be* the node: its dig:// handler
/// calls this directly, no HTTP, no socket, no sidecar.
///
/// A thin, STABLE free-function entry point (#1285 W1b-5): the actual dispatch body lives on
/// [`RpcDispatch::dispatch`] (seam 4's public surface, `seams/dig_rpc/dispatch.rs`) — relocated
/// unchanged. Kept as a free function (rather than requiring every caller to import a trait) so
/// no external caller (`dig-node-service`, `dig-runtime`, the peer-RPC server) needed to change.
pub async fn handle_rpc(
    node: &Node,
    req: Value,
    origin: crate::download::ReadOrigin,
    provenance: crate::download::RequestProvenance,
) -> Value {
    RpcDispatch::dispatch(node, req, origin, provenance).await
}

/// Return a clone of the JSON-RPC `req` with `params.root` forced to `root_hex`
/// (the pinned chain-anchored root). Used so a proxied `dig.getContent` asks the
/// upstream for the chain-anchored generation, never the caller's (possibly
/// rootless or stale) root.
fn pin_request_root(req: &Value, root_hex: &str) -> Value {
    let mut out = req.clone();
    if let Some(obj) = out.as_object_mut() {
        let params = obj.entry("params").or_insert_with(|| json!({}));
        if let Some(p) = params.as_object_mut() {
            p.insert("root".into(), json!(root_hex));
        }
    }
    out
}

fn decode_rk(hex_str: &str) -> Result<[u8; 32], ()> {
    let v = hex::decode(hex_str).map_err(|_| ())?;
    if v.len() != 32 {
        return Err(());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

impl Node {
    /// The node's ONE whole-capsule single-flight gate (#1614), shared by the §21 backfill leg
    /// ([`Node::maybe_backfill_capsule`]) and the #1576 reshare warm. Handed to
    /// [`crate::download::NodeContent::wire_capsule_reshare`] so both legs claim the same registry and a
    /// read triggers at most one whole-capsule acquisition.
    pub(crate) fn capsule_acquisition_gate(&self) -> Arc<crate::seams::dig_peer::WarmRegistry> {
        self.capsule_acquisition.clone()
    }

    /// Build a node from the environment (cache dir/cap, §21 identity, upstream).
    /// Used by both the standalone bin's [`run`] and the in-process `dig-runtime`.
    pub fn from_env() -> Arc<Node> {
        let dir = cache_dir();
        let _ = std::fs::create_dir_all(&dir);
        // Load the persistent §21.9 identity (best-effort). Present → authenticated
        // whole-store sync is enabled; absent → the node still serves local modules
        // and proxies per-resource.
        let identity_seed = match identity::load_or_create_seed() {
            Ok((seed, pk)) => {
                println!(
                    "dig-node identity {} (authenticated §21 whole-store sync enabled)",
                    pk.to_hex()
                );
                Some(seed)
            }
            Err(e) => {
                eprintln!("dig-node: no identity key ({e}); authenticated §21 sync disabled");
                None
            }
        };
        Arc::new(Node {
            cache_dir: dir,
            http: reqwest::Client::builder()
                .user_agent("dig-node/0.1")
                // An upstream call must not be able to hold a connection open indefinitely
                // (#1997). Without this, a misconfigured or hostile upstream — including one that
                // loops back here — keeps every level of the chain alive for as long as the far
                // end will hold it, turning one request into unbounded in-flight work. A ceiling
                // is not a substitute for the loop latch above; it bounds what any single
                // outbound call can cost while the latch removes the cause.
                .timeout(std::time::Duration::from_secs(120))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("http client"),
            upstream: std::env::var("DIG_NODE_UPSTREAM")
                .unwrap_or_else(|_| RPC_FALLBACK.to_string()),
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed,
            anchored_root_resolver: default_anchored_resolver(),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::from_env(),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        })
    }

    /// The node's cache dir root — the data root the P2P content engine's download staging
    /// (`<cache>/downloads`) + `.download.tmp` GC live under (shares the node's writability handling).
    pub fn cache_dir_path(&self) -> &Path {
        &self.cache_dir
    }

    /// Distinct stores currently held in the inbound-demand ledger — the live `Tier1Demand`
    /// occupancy figure `cache.stats` (#1991) reports. It is the ledger's own bounded-LRU size
    /// (§7.10d), so it needs no cache wiring to be an honest number.
    pub(crate) fn inbound_demand_entry_count(&self) -> usize {
        self.inbound_demand.entry_count()
    }

    /// The INBOUND-DEMAND tier-1 cache trigger (#1990): a remote PEER just asked this node to serve a
    /// resource from `(store_hex, root_hex)`. That request is real demand, so:
    ///
    /// 1. **Always** record it in the [`inbound_demand`] ledger — tagging the store `Tier1Demand` and
    ///    bumping its demand count. This is free of the amplification concern (it holds no content and
    ///    pulls nothing), so it runs unconditionally; it feeds relevance + eviction precedence.
    /// 2. **Opt-in** (default OFF, `DIG_NODE_INBOUND_DEMAND_CACHE`) trigger a whole-`.dig` backfill of
    ///    the store — reusing the SAME machinery the fetch-side backfill uses
    ///    ([`Node::spawn_capsule_backfill`]) — so a subsequent request is served locally. Gated OFF by
    ///    default because a peer-triggered pull is an amplification primitive until the tier-0/1
    ///    selector's XOR-proximity admission is live-wired; see
    ///    [`crate::download::inbound_demand_cache_enabled`].
    ///
    /// A non-canonical `store_hex` is ignored (records nothing) — a serve path may hand a placeholder
    /// or `"latest"`-shaped value, and only a real store id names demand to record.
    pub(crate) fn note_inbound_demand(&self, store_hex: &str, root_hex: &str) {
        if !is_canonical_hex_id(store_hex) {
            return;
        }
        // Mark real inbound activity so the tier-0 eager-precache loop (#1934) yields to demand: a
        // speculative precache round backs off entirely while the node is serving real reads.
        crate::tier0_live::mark_inbound_activity();
        self.inbound_demand.record(store_hex);
        // Persist the (now at-least-`Tier1Demand`) tier so the demand tag outlives a restart (#2015).
        // Guarded on the store already being cached, so recording demand for a not-yet-held store does
        // not leave an orphan sidecar with no module beside it.
        crate::module_tier_tag::write_tier_tag_if_cached(
            &self.cache_dir,
            store_hex,
            self.module_tier(store_hex),
        );
        // The pull is gated TWICE: the operator opt-in (default OFF) AND the XOR-proximity admission
        // below. Both must pass — the proximity gate binds even when the flag is on, so enabling the
        // feature never lets a peer drive caching of content OUTSIDE this node's keyspace neighbourhood.
        if crate::download::inbound_demand_cache_enabled()
            && self.inbound_demand_pull_admitted(store_hex, root_hex)
        {
            // Tier1Demand is asserted in the ledger above; the on-disk pull reuses the fetch-side
            // machinery, which lands + announces the capsule exactly as every other cache path does.
            self.spawn_capsule_backfill(store_hex, root_hex);
        }
    }

    /// The ANTI-AMPLIFICATION admission for the inbound-demand pull (§7.10d, #2014): may a remote
    /// peer's request drive this node to fetch + cache + DHT-announce the `(store_hex, root_hex)`
    /// capsule? Only when the capsule's keyspace key lies within THIS node's neighbourhood — near our
    /// own `peer_id` in XOR distance — so a peer can steer caching only toward keys near content this
    /// node is naturally responsible for, NEVER toward an arbitrary far-keyspace target (an attacker
    /// cannot move our `peer_id`). This gate binds WHERE a peer can steer caching; it does not make
    /// naming a near key costly — a near key that names no real store just finds no DHT providers and
    /// the pull fails cheaply there. Actually becoming a cached HOLDER binds later: the pull is
    /// merkle-verified against `root` and is never served as current unless `root` equals the
    /// chain-anchored tip (the serve-time read-path pin), so the worst outcome on an opted-in node is a
    /// bounded pull of REAL near-neighbourhood content, never fabricated or out-of-neighbourhood junk.
    ///
    /// Fails CLOSED: an unknown self-identity (`None` on the FFI/consumer path) or a
    /// non-canonical/malformed `(store, root)` denies the pull. The neighbourhood test itself is
    /// [`crate::relevance::in_keyspace_neighbourhood`], anchored to the SAME `xor_proximity` primary +
    /// reference `peer_id` the tier-0 precache selector scores against.
    fn inbound_demand_pull_admitted(&self, store_hex: &str, root_hex: &str) -> bool {
        let Some(peer_id) = self.node_peer_id.get() else {
            return false; // no known self-identity → no anchor for "our neighbourhood" → no pull
        };
        let (Some(store_id), Some(root)) =
            (crate::dht::hex64(store_hex), crate::dht::hex64(root_hex))
        else {
            return false; // a rootless/`"latest"`/malformed key names no concrete capsule to place
        };
        let capsule_key = dig_dht::ContentId::capsule(store_id, root).to_key();
        crate::relevance::in_keyspace_neighbourhood(capsule_key.as_bytes(), peer_id)
    }

    /// Install this node's own `peer_id` — the XOR-distance reference the inbound-demand proximity gate
    /// anchors on (see [`Node::node_peer_id`]). Called ONCE by the peer-network bring-up with the same
    /// `peer_id` the tier-0 loop uses. A second call is ignored (`OnceLock`), so the reference identity
    /// is stable for the node's life.
    pub(crate) fn set_node_peer_id(&self, peer_id: [u8; 32]) {
        let _ = self.node_peer_id.set(peer_id);
    }
}

/// The COMPOSITION-ROOT upcasts (#1285 W1c — the locked "Option A" shape). `Node` stays ONE
/// concrete struct implementing all 7 seam traits (unchanged from W1b); these methods hand a
/// caller a trait-object HANDLE to exactly one seam — a self-referential upcast of the SAME
/// `Arc<Node>`, not a separate object (no `Arc::new_cyclic`, no possibility of the seam-4↔5 /
/// 5↔6 cross-seam cycles the W1b carves left in place — see #1285's W1c design recon).
///
/// This is what makes the outer shape genuinely composition-root-like: a consumer (the
/// `dig-node-service` binary, a test, the FFI/browser path) can hold `Arc<dyn ContentServer>`
/// instead of `Arc<Node>` — an injectable seam boundary — and W2-W5 can later repoint ONE such
/// handle at a genuinely different concrete type (e.g. a `dig-peer`-backed `PeerNetwork`) without
/// touching the other 6. The INNER cross-seam reaches (`self.proxy`, `self.p2p_content()`, the
/// direct `self.anchored_root_resolver` field read, …) are UNCHANGED by this pass — de-tangling
/// them into true per-seam structs is deferred to the follow-up epic **#1357**, sequenced after
/// W2-W5 reshape those exact edges (de-tangling now risks redoing the same work again once a
/// seam's concrete implementation actually changes).
///
/// `wallet` (seam 3) has no upcast here — W1b left it a placeholder (the embedded `dig-wallet`
/// stays external; its trait/handle is W5's job, the seam-3 custody cutover).
impl Node {
    /// Seam 1 (Chia peer connectivity) handle.
    pub fn as_chain_source(self: &Arc<Self>) -> Arc<dyn ChainSource> {
        Arc::clone(self) as Arc<dyn ChainSource>
    }

    /// Seam 2 (DIG peer connectivity) handle.
    pub fn as_peer_network(self: &Arc<Self>) -> Arc<dyn PeerNetwork> {
        Arc::clone(self) as Arc<dyn PeerNetwork>
    }

    /// Seam 4 (dig RPC server) handle.
    pub fn as_rpc_dispatch(self: &Arc<Self>) -> Arc<dyn RpcDispatch> {
        Arc::clone(self) as Arc<dyn RpcDispatch>
    }

    /// Seam 5 (local content server) handle.
    pub fn as_content_server(self: &Arc<Self>) -> Arc<dyn ContentServer> {
        Arc::clone(self) as Arc<dyn ContentServer>
    }

    /// Seam 6 (capsule management) handle.
    pub fn as_capsule_store(self: &Arc<Self>) -> Arc<dyn CapsuleStore> {
        Arc::clone(self) as Arc<dyn CapsuleStore>
    }

    /// Seam 7 (key management) handle.
    pub fn as_key_manager(self: &Arc<Self>) -> Arc<dyn KeyManager> {
        Arc::clone(self) as Arc<dyn KeyManager>
    }
}

/// Crate-internal test helpers shared across module test suites (e.g. the peer-surface
/// tests in [`crate::peer`] need a lightweight [`Node`]). Not compiled into the release build.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Serializes every test in the crate (any module, not just [`crate::tests`]) that mutates
    /// PROCESS-GLOBAL env (`DIG_NODE_CACHE`, `DIG_NODE_ON_MISS`, `DIG_NODE_BACKFILL_ON_MISS`, …),
    /// since cargo runs tests in parallel threads of one process and the env is process-wide.
    /// Acquire with `.unwrap_or_else(|p| p.into_inner())` so one test's failure (which poisons the
    /// mutex) does not cascade into spurious failures of every other env-touching test.
    pub(crate) static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A minimal in-memory [`Node`] over a fresh temp cache dir, with an unroutable upstream
    /// and the production anchored-root resolver (peer-surface tests never reach the chain).
    /// Returned with its [`tempfile::TempDir`] so the cache dir outlives the node. Used to
    /// exercise the peer-RPC method allowlist without a live pool/network.
    pub(crate) fn test_node_for_peer_surface() -> (Arc<Node>, tempfile::TempDir) {
        let td = tempfile::tempdir().expect("tempdir");
        let node = Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: "http://127.0.0.1:1/".to_string(),
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed: None,
            anchored_root_resolver: default_anchored_resolver(),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        };
        (Arc::new(node), td)
    }

    /// A REAL multi-chunk served resource: three chunk ciphertexts concatenated, committed under a
    /// single-leaf generation root, carrying the genuine digstore inclusion proof for that leaf.
    /// This is what a decoded, locally-held `.dig` resource looks like to the serve path, so tests
    /// exercise `fetch_range_frame`'s real metadata contract instead of a hand-built frame.
    pub(crate) fn multi_chunk_served_resource() -> (Arc<ContentResponse>, Vec<u64>) {
        use digstore_core::merkle::{resource_leaf, MerkleTree};

        let chunks: Vec<Vec<u8>> = vec![vec![0xa1; 40], vec![0xb2; 25], vec![0xc3; 17]];
        let ciphertext: Vec<u8> = chunks.iter().flatten().copied().collect();
        let tree = MerkleTree::from_leaves(vec![resource_leaf(&ciphertext)]);
        let resp = ContentResponse {
            merkle_proof: tree.prove(0).expect("single-leaf proof"),
            roothash: tree.root(),
            chunk_lens: chunks.iter().map(|c| c.len() as u32).collect(),
            ciphertext,
        };
        let chunk_lens = resp.chunk_lens.iter().map(|&l| u64::from(l)).collect();
        (Arc::new(resp), chunk_lens)
    }

    /// A REAL served resource whose ciphertext is deliberately LARGER than the range wire's own
    /// ceilings, chunked into `chunk_len`-byte chunks, committed under a single-leaf generation root
    /// with its genuine digstore inclusion proof.
    ///
    /// # Why the size is computed from the protocol's constants
    ///
    /// Every bound here is read from dig-nat rather than written as a round number, because a fixture
    /// that happens to sit UNDER a limit cannot detect a sender that ignores the limit. That is not a
    /// hypothetical: the read-leg end-to-end proofs that passed while the serve path framed on a 3 MiB
    /// window served 20,477 B and 27,067 B — both below the ceiling, so both were satisfied by the
    /// unbounded encoder they were meant to catch (#1640).
    ///
    /// `frame_payloads` full [`dig_nat::MAX_RANGE_FRAME_PAYLOAD`] payloads plus a deliberate partial
    /// tail therefore guarantees three things at once:
    ///
    /// * the ciphertext exceeds [`dig_nat::MAX_FRAMED_BODY`], so serving it as ONE frame is refused by
    ///   any conforming receiver — `bytes` travels base64, so a payload over ~48 KiB already overflows
    ///   the 64 KiB body ceiling;
    /// * a conforming serve MUST tile it into several frames, so single-frame framing cannot pass; and
    /// * the last frame is SHORT, so "tiles exactly" is tested against a partial tail rather than a
    ///   suspiciously even division.
    pub(crate) fn oversized_served_resource(
        frame_payloads: usize,
        tail: usize,
        chunk_len: usize,
    ) -> (Arc<ContentResponse>, Vec<u64>) {
        use digstore_core::merkle::{resource_leaf, MerkleTree};

        let total = dig_nat::MAX_RANGE_FRAME_PAYLOAD * frame_payloads + tail;
        assert!(
            total > dig_nat::MAX_FRAMED_BODY,
            "a fixture at or below MAX_FRAMED_BODY cannot exhibit the multi-frame contract"
        );
        // Byte i is `i mod 251` (a prime, so the pattern never aligns with a chunk or frame boundary):
        // reassembling frames in the wrong ORDER, or dropping one, changes the bytes. A constant fill
        // would let a mis-ordered reassembly still compare equal.
        let ciphertext: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let chunk_lens: Vec<u32> = std::iter::repeat_n(chunk_len as u32, total / chunk_len)
            .chain((!total.is_multiple_of(chunk_len)).then_some((total % chunk_len) as u32))
            .collect();
        debug_assert_eq!(
            chunk_lens.iter().map(|&l| l as usize).sum::<usize>(),
            total,
            "chunk_lens must sum to the ciphertext length (it is a DECRYPT input)"
        );
        let tree = MerkleTree::from_leaves(vec![resource_leaf(&ciphertext)]);
        let resp = ContentResponse {
            merkle_proof: tree.prove(0).expect("single-leaf proof"),
            roothash: tree.root(),
            chunk_lens,
            ciphertext,
        };
        let chunk_lens = resp.chunk_lens.iter().map(|&l| u64::from(l)).collect();
        (Arc::new(resp), chunk_lens)
    }

    /// Seed `resource` into `node`'s memoized serve cache so [`Node::fetch_range_frame`] serves it,
    /// and return the `(store_id, root, retrieval_key)` hex triple that names it.
    pub(crate) fn seed_served_resource(
        node: &Node,
        resource: Arc<ContentResponse>,
    ) -> (String, String, String) {
        let (store, rk) = ("7e".repeat(32), [0x9fu8; 32]);
        let root = resource.roothash.to_hex();
        node.content_cache
            .lock()
            .unwrap()
            .insert((store.clone(), root.clone(), rk), resource);
        (store, root, hex::encode(rk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    /// The cached-module path for a capsule named by hex ids, for fixtures that seed or inspect the
    /// cache directly.
    ///
    /// Panics on a non-canonical id BY DESIGN: production code cannot build a path from unvalidated ids
    /// at all (that is [`CapsuleKey`]'s whole purpose), so a test that wants a hostile path must go
    /// through the surface under test — never around it via a fixture helper that would quietly
    /// re-create the hole.
    fn module_path(dir: &Path, store_hex: &str, root_hex: &str) -> PathBuf {
        CapsuleKey::parse(store_hex, root_hex)
            .expect("a fixture names a capsule with canonical ids")
            .module_path(dir)
    }

    #[test]
    fn response_key_is_stable_and_safe() {
        let k = response_key("aa", "bb", "cc", 0);
        assert_eq!(k, "aa_bb_cc_0.json");
        // Different offset → different file (so windows don't collide).
        assert_ne!(k, response_key("aa", "bb", "cc", 100));
        // Non-hex input is neutralized (no path traversal in the filename).
        let bad = response_key("../../etc", "bb", "cc", 0);
        assert!(!bad.contains('/'));
        assert!(!bad.contains(".."));
    }

    #[test]
    fn wc_project_id_precedence_persisted_over_env_over_none() {
        // Persisted value wins over the env default.
        assert_eq!(
            resolve_wc_project_id(Some("persisted"), Some("from_env")),
            Some("persisted".to_string())
        );
        // No persisted value → fall back to the env default.
        assert_eq!(
            resolve_wc_project_id(None, Some("from_env")),
            Some("from_env".to_string())
        );
        // A blank persisted value is treated as unset (falls through to env),
        // never pinning an empty id.
        assert_eq!(
            resolve_wc_project_id(Some("   "), Some("from_env")),
            Some("from_env".to_string())
        );
        // Nothing configured anywhere → None (the "not configured" UI state).
        assert_eq!(resolve_wc_project_id(None, None), None);
        assert_eq!(resolve_wc_project_id(Some(""), Some("")), None);
        // Values are trimmed.
        assert_eq!(
            resolve_wc_project_id(Some("  abc  "), None),
            Some("abc".to_string())
        );
    }

    #[test]
    fn evicts_nothing_when_under_cap() {
        let t = UNIX_EPOCH + Duration::from_secs(10);
        let entries = vec![(PathBuf::from("a"), t, 100), (PathBuf::from("b"), t, 100)];
        assert!(plan_eviction(&entries, 1000).is_empty());
    }

    #[test]
    fn evicts_oldest_first_until_under_cap() {
        let old = UNIX_EPOCH + Duration::from_secs(1);
        let mid = UNIX_EPOCH + Duration::from_secs(2);
        let new = UNIX_EPOCH + Duration::from_secs(3);
        // total 300, cap 150 → must drop 'old' (100) and 'mid' (100) → 100 left.
        let entries = vec![
            (PathBuf::from("new"), new, 100),
            (PathBuf::from("old"), old, 100),
            (PathBuf::from("mid"), mid, 100),
        ];
        let victims = plan_eviction(&entries, 150);
        assert_eq!(victims, vec![PathBuf::from("old"), PathBuf::from("mid")]);
    }

    #[test]
    fn stops_as_soon_as_under_cap() {
        let old = UNIX_EPOCH + Duration::from_secs(1);
        let new = UNIX_EPOCH + Duration::from_secs(2);
        // total 300, cap 250 → dropping just 'old' (100) leaves 200 ≤ 250.
        let entries = vec![
            (PathBuf::from("old"), old, 100),
            (PathBuf::from("new"), new, 200),
        ];
        assert_eq!(plan_eviction(&entries, 250), vec![PathBuf::from("old")]);
    }

    // -- Tier-aware modules-cache eviction (#1934 disk-exhaustion bound) --------

    /// A module entry for the tier-aware planner: `(path, store_hex, tier, mtime-ticks, size)`.
    fn module_entry(
        name: &str,
        tier: crate::relevance::CacheTier,
        ticks: u64,
        size: u64,
    ) -> (PathBuf, String, crate::relevance::CacheEntry, u64) {
        (
            PathBuf::from(name),
            name.to_string(),
            crate::relevance::CacheEntry {
                tier,
                last_access_ticks: ticks,
            },
            size,
        )
    }

    #[test]
    fn a_tier0_land_past_cap_evicts_an_older_tier0_and_stays_under_cap() {
        use crate::relevance::CacheTier;
        // Three tier-0 precache modules of 100 each, cap 250: the loop just landed the newest, so the
        // OLDEST tier-0 is evicted and the modules total plateaus at ≤ cap (the standing-occupancy bound
        // — the direct regression for the disk-exhaustion finding).
        let entries = vec![
            module_entry("newest", CacheTier::Tier0Precache, 3, 100),
            module_entry("oldest", CacheTier::Tier0Precache, 1, 100),
            module_entry("middle", CacheTier::Tier0Precache, 2, 100),
        ];
        let victims = plan_module_eviction(&entries, 250);
        assert_eq!(
            victims,
            vec![(PathBuf::from("oldest"), "oldest".to_string())],
            "the oldest tier-0 land is evicted first; the modules cache stays at cap"
        );
        // Post-eviction the remaining two (200) are under the 250 cap.
        let remaining: u64 = 300 - 100;
        assert!(
            remaining <= 250,
            "modules cache is bounded at cap after eviction"
        );
    }

    #[test]
    fn a_demand_promoted_entry_survives_while_tier0_entries_remain() {
        use crate::relevance::CacheTier;
        // A tier-1 (demand-promoted) module sits alongside tier-0 precache lands, all 100, cap 150.
        // The tier-0 entries MUST be sacrificed first — the demand content survives (tier integrity).
        let entries = vec![
            // The demand entry is the OLDEST by mtime — proving tier precedence beats LRU: a Tier1
            // module older than a Tier0 module is still protected.
            module_entry("demand", CacheTier::Tier1Demand, 1, 100),
            module_entry("precache_a", CacheTier::Tier0Precache, 2, 100),
            module_entry("precache_b", CacheTier::Tier0Precache, 3, 100),
        ];
        let victims = plan_module_eviction(&entries, 150);
        let victim_names: Vec<String> = victims.into_iter().map(|(_, s)| s).collect();
        assert!(
            !victim_names.contains(&"demand".to_string()),
            "a demand-promoted (tier-1) module must NOT be evicted while tier-0 entries remain"
        );
        assert!(
            victim_names.contains(&"precache_a".to_string()),
            "tier-0 precache is the sacrificial tier, evicted first"
        );
    }

    // -- Authenticated whole-store sync (§21.9) --------------------------------

    #[test]
    fn sync_eligible_requires_concrete_store_and_root() {
        let h = "ab".repeat(32); // 64 hex
        assert!(sync_eligible(&h, &h));
        assert!(!sync_eligible(&h, "")); // rootless
        assert!(!sync_eligible(&h, "latest")); // sentinel, not a concrete root
        assert!(!sync_eligible("", &h)); // no store id
        assert!(!sync_eligible(&h, &"zz".repeat(32))); // right length, non-hex
        assert!(!sync_eligible(&h, &"ab".repeat(31))); // too short
    }

    /// A deterministic [`AnchoredRootResolver`] for tests: maps each store id hex
    /// to its anchored-root resolution outcome so the read-path pin can be
    /// exercised without a live chain. `Ok(Some(root))` = a confirmed tip;
    /// `Ok(None)` = no confirmed generation; `Err(msg)` = chain unreachable.
    struct MockResolver {
        outcomes: std::collections::HashMap<String, Result<Option<Bytes32>, String>>,
        /// Optional owner puzzle hash `anchored_state` reports alongside the root (#486 test
        /// support). `None` ⇒ the trait's default owner-less wrapping (most tests don't need it).
        owner: Option<Bytes32>,
        /// Optional INDEPENDENT outcome for the bounded [`verify_pinned_root`](AnchoredRootResolver::verify_pinned_root)
        /// (#747). `None` ⇒ the trait's DEFAULT walk-based fallback (tip equality via `anchored_root`).
        /// `Some(..)` decouples the bounded verify from the (possibly broken) full-lineage walk, so a
        /// test can model #747: the walk (`anchored_root`) errors ("missing child") while the bounded
        /// verify still succeeds — exactly what `CoinsetResolver` does on chain.
        verify_outcome: Option<Result<(), String>>,
    }

    impl MockResolver {
        /// One store that resolves to `root`.
        fn one(store_hex: &str, root: Bytes32) -> Arc<dyn AnchoredRootResolver> {
            let mut outcomes = std::collections::HashMap::new();
            outcomes.insert(store_hex.to_string(), Ok(Some(root)));
            Arc::new(MockResolver {
                outcomes,
                owner: None,
                verify_outcome: None,
            })
        }
        /// A resolver whose full-lineage walk (`anchored_root`) yields `walk` but whose BOUNDED
        /// `verify_pinned_root` INDEPENDENTLY yields `verify` — models the #747 split (the walk can
        /// be broken while the bounded verify succeeds, and vice versa). `walk` applies to `*`.
        fn with_verify(
            walk: Result<Option<Bytes32>, String>,
            verify: Result<(), String>,
        ) -> Arc<dyn AnchoredRootResolver> {
            let mut outcomes = std::collections::HashMap::new();
            outcomes.insert("*".to_string(), walk);
            Arc::new(MockResolver {
                outcomes,
                owner: None,
                verify_outcome: Some(verify),
            })
        }
        /// Like [`one`](Self::one) but ALSO reports `owner` from `anchored_state` (#486): the
        /// content-serve `X-Dig-Owner-Puzzle-Hash` tests need a resolver that supplies both the
        /// root and the owner, mirroring `CoinsetResolver`'s single-chain-read shape.
        fn one_with_owner(
            store_hex: &str,
            root: Bytes32,
            owner: Bytes32,
        ) -> Arc<dyn AnchoredRootResolver> {
            let mut outcomes = std::collections::HashMap::new();
            outcomes.insert(store_hex.to_string(), Ok(Some(root)));
            Arc::new(MockResolver {
                outcomes,
                owner: Some(owner),
                verify_outcome: None,
            })
        }
        /// A resolver whose every lookup is `outcome` (e.g. chain-unreachable).
        fn always(outcome: Result<Option<Bytes32>, String>) -> Arc<dyn AnchoredRootResolver> {
            Arc::new(MockResolver {
                outcomes: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("*".to_string(), outcome);
                    m
                },
                owner: None,
                verify_outcome: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl AnchoredRootResolver for MockResolver {
        async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
            let hex = hex::encode(store_id);
            self.outcomes
                .get(&hex)
                .or_else(|| self.outcomes.get("*"))
                .cloned()
                .unwrap_or(Ok(None))
        }

        async fn anchored_state(
            &self,
            store_id: &[u8; 32],
        ) -> Result<Option<AnchoredStoreState>, String> {
            Ok(self
                .anchored_root(store_id)
                .await?
                .map(|root| AnchoredStoreState {
                    root,
                    owner_puzzle_hash: self.owner,
                }))
        }

        async fn verify_pinned_root(
            &self,
            store_id: &[u8; 32],
            pinned_root: Bytes32,
        ) -> Result<(), String> {
            match &self.verify_outcome {
                // Model the bounded on-chain verify INDEPENDENTLY of the (possibly broken) walk.
                Some(outcome) => outcome.clone(),
                // No explicit bounded outcome ⇒ mirror the trait's DEFAULT walk-based fallback
                // (tip equality via `anchored_root`), so a test that doesn't override it keeps the
                // walk semantics (this is what the existing #127 pin tests rely on).
                None => match self.anchored_root(store_id).await? {
                    Some(tip) if tip == pinned_root => Ok(()),
                    Some(_) | None => Err("pinned root is not the current on-chain root".into()),
                },
            }
        }
    }

    /// Build a `Node` with a throwaway cache dir and an optional identity seed. The
    /// returned `TempDir` must be kept alive for the duration of the test.
    ///
    /// The anchored-root resolver defaults to "no confirmed generation" for every
    /// store, so any `dig.getContent` test that does not explicitly inject a tip
    /// fails closed under the pin — make the pin policy explicit per test via
    /// [`test_node_with_resolver`] or by disabling the pin (`DIG_NODE_PIN=off`).
    /// **Proves:** `has_upstream` requires BOTH a configured upstream and no proven loop, and the
    /// latch is one-way.
    /// **Catches:** a `has_upstream` that reads only the string — which is exactly the shape the
    /// security audit found, where the shell latched a detected loop but the engine's two content
    /// legs kept using the upstream anyway.
    #[test]
    fn a_proven_loop_stops_the_engine_using_its_upstream() {
        let (mut node, _td) = test_node(None);

        node.upstream = String::new();
        assert!(!node.has_upstream(), "no upstream configured");

        node.upstream = "http://127.0.0.1:9999".to_string();
        assert!(node.has_upstream(), "a configured upstream is usable");

        node.disable_upstream_after_loop();
        assert!(
            !node.has_upstream(),
            "a PROVEN loop must stop the engine using the upstream, not just the shell"
        );

        // One-way: the latch is not cleared by reconfiguring, because an upstream cannot stop
        // pointing at us without a restart.
        node.upstream = "http://127.0.0.1:8888".to_string();
        assert!(
            !node.has_upstream(),
            "the latch is not reset by a new value"
        );
    }

    fn test_node(identity_seed: Option<[u8; 32]>) -> (Node, tempfile::TempDir) {
        test_node_with_resolver(identity_seed, MockResolver::always(Ok(None)))
    }

    /// Like [`test_node`] but with an explicit anchored-root resolver (the pin's
    /// trusted-root source) so the fail-closed read-path gate can be unit-tested.
    fn test_node_with_resolver(
        identity_seed: Option<[u8; 32]>,
        anchored_root_resolver: Arc<dyn AnchoredRootResolver>,
    ) -> (Node, tempfile::TempDir) {
        let td = tempfile::tempdir().unwrap();
        let node = Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            // Default to an UNROUTABLE upstream so a proxy fallback fails fast and
            // hermetically (no live rpc.dig.net). Tests needing a real upstream set
            // `node.upstream` explicitly (e.g. fetch_and_cache_*).
            upstream: "http://127.0.0.1:1/".to_string(),
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed,
            anchored_root_resolver,
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        };
        (node, td)
    }

    /// Spawn the REAL §21 `RemoteServer` (auth REQUIRED by default) over an
    /// in-memory backend seeded with one store whose module is `module` at root
    /// 0x10. Returns `(base_url, store_id_hex)`. Unlike the header-recording mock
    /// below, this exercises the actual §21.9 auth middleware end-to-end.
    async fn spawn_authed_remote(module: Vec<u8>) -> (String, String) {
        use digstore_core::Bytes48;
        use digstore_remote::{InMemoryBackend, RemoteServer};
        let be = Arc::new(InMemoryBackend::new());
        let store_id = Bytes32([1u8; 32]);
        be.add_store(
            store_id,
            Bytes48([2u8; 48]),
            Bytes32([0x10; 32]),
            module,
            None,
        );
        let app = RemoteServer::new(be).router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), store_id.to_hex())
    }

    #[tokio::test]
    async fn authed_identity_syncs_module_from_authed_remote() {
        // The native §21.9 identity is admitted by an auth-REQUIRED §21 server, the
        // whole module is synced, and it lands in the on-disk cache for local-first.
        let store = Bytes32([1u8; 32]); // the id spawn_authed_remote seeds
        let root = Bytes32([0x10; 32]); // its served genesis root
        let module = chain_anchored_module(store.0, root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (node, _td) =
            test_node_with_resolver(Some([5u8; 32]), MockResolver::one(&store_hex, root));
        let root_hex = root.to_hex();
        let served = node
            .sync_module_from(&base, &store_hex, &root_hex)
            .await
            .expect("authed sync succeeds");
        assert_eq!(served.to_hex(), root_hex, "served root == requested root");
        let cached = std::fs::read(module_path(&node.cache_dir, &store_hex, &root_hex)).unwrap();
        assert_eq!(cached, module, "served module must be cached locally");
    }

    /// **Proves:** `gap_fill_generation` ACTIVELY PULLS a missing generation end-to-end (SPEC §14.3) —
    /// the node holds nothing for `(store, root)`, `gap_fill_generation` fetches the whole module from
    /// a real auth-required §21 remote, verifies + lands it under `(store, root)`, and a second call is
    /// an idempotent no-op. This is the "actively seek other nodes to pull the missing generations"
    /// behavior the chain-watch loop drives.
    /// **Catches:** a gap-fill that doesn't pull, lands the module at the wrong key, or re-pulls.
    #[tokio::test]
    async fn gap_fill_pulls_a_missing_generation_from_a_remote() {
        // The remote's served genesis root.
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let store_id: [u8; 32] = Bytes32::from_hex(&store_hex).unwrap().0;
        // A node with a §21 identity whose UPSTREAM is the authed remote (gap-fill pulls via upstream).
        let td = tempfile::tempdir().unwrap();
        let node = Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: base,
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed: Some([5u8; 32]),
            anchored_root_resolver: MockResolver::one(&store_hex, root),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        };

        // Missing before the pull.
        assert!(!module_exists(&node.cache_dir, &store_hex, &root.to_hex()));

        // Gap-fill pulls + verifies + lands the module under (store, root).
        assert_eq!(node.gap_fill_generation(store_id, root).await, Ok(()));
        let cached =
            std::fs::read(module_path(&node.cache_dir, &store_hex, &root.to_hex())).unwrap();
        assert_eq!(
            cached, module,
            "the pulled generation is cached under (store, root)"
        );

        // A second gap-fill is an idempotent no-op (already held → cheap success).
        assert_eq!(node.gap_fill_generation(store_id, root).await, Ok(()));
    }

    /// **Proves:** the chain-watch loop's PRODUCTION seams (`NodeGapFiller` + `NodeHeldCheck`) wire the
    /// node's real pull path — one `run_tick` over a subscribed store whose confirmed tip is missing
    /// pulls it from the §21 remote and marks it held. This exercises the full §14.2→§14.3 loop with the
    /// real node actuator (only the chain resolver is a deterministic mock).
    /// **Catches:** a mis-wired production seam (held-check or gap-filler pointed at the wrong path).
    #[tokio::test]
    async fn chain_watch_tick_gap_fills_a_subscribed_store_end_to_end() {
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let td = tempfile::tempdir().unwrap();
        let node = Arc::new(Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: base,
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed: Some([5u8; 32]),
            anchored_root_resolver: MockResolver::one(&store_hex, root),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        });

        // Build the loop's deps from the PRODUCTION seams, with a fixed one-store subscription set.
        let subs = {
            let store_hex = store_hex.clone();
            Arc::new(move || {
                let mut s = subscription::SubscriptionSet::new();
                s.add(&store_hex).unwrap();
                s
            }) as Arc<dyn Fn() -> subscription::SubscriptionSet + Send + Sync>
        };
        let deps = chainwatch::WatchDeps {
            subscriptions: subs,
            resolver: node.anchored_root_resolver_arc(),
            held: Arc::new(chainwatch::NodeHeldCheck::new(node.cache_dir.clone())),
            filler: Arc::new(chainwatch::NodeGapFiller::new(node.clone())),
        };

        assert!(!module_exists(&node.cache_dir, &store_hex, &root.to_hex()));
        let summary = chainwatch::run_tick(&deps).await;
        assert_eq!(
            (summary.checked, summary.attempted, summary.filled),
            (1, 1, 1),
            "one subscribed store, one missing generation, one filled"
        );
        assert!(
            module_exists(&node.cache_dir, &store_hex, &root.to_hex()),
            "the watched store's missing generation is now held"
        );
    }

    /// **Proves (#213):** driving the REAL peer-network bring-up the OS service now invokes
    /// ([`peer::spawn_peer_network`]) starts the §14 chain-watch loop, which PROACTIVELY pulls a
    /// subscribed store's missing generation from a local "peer" (a real auth-required §21 remote)
    /// with NO client read triggering the miss — EVEN THOUGH the P2P pool/DHT bring-up cannot come up
    /// in this env (the pre-launch placeholder network genesis makes the gossip config invalid). That
    /// is the whole point of the §14 decoupling: autonomous sync must run regardless of the P2P
    /// layer's health. Hermetic + mainnet-safe: relay OFF, ephemeral peer port, a deterministic mock
    /// anchored-root resolver, a 1 s watch tick, the upstream a real §21 remote holding the generation.
    /// **Catches:** the exact #213 gap — chain-watch gated behind a pool/DHT bring-up that fails, so
    /// autonomous sync never actually runs even after the service wires the call.
    //
    // NB: like the other env-touching tests, these mutate the PROCESS-GLOBAL `DIG_NODE_CACHE` (the
    // subscription set + `cache_dir()`), so they hold `ENV_GUARD` for the whole body and are plain
    // `#[test]` fns driving a current-thread runtime via `block_on` (not `#[tokio::test]`) — the std
    // guard is then never held across an `.await` (clippy `await_holding_lock`).
    #[test]
    fn spawn_peer_network_proactively_gap_fills_even_when_the_p2p_layer_cannot_come_up() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let root = Bytes32([0x10; 32]);
            let module = chain_anchored_module([1u8; 32], root.0);
            let (base, store_hex) = spawn_authed_remote(module.clone()).await;
            let td = tempfile::tempdir().unwrap();

            // The chain-watch loop reads the PROCESS-GLOBAL subscription set + cache dir (via
            // `cache_dir()`), so pin DIG_NODE_CACHE at the node's cache dir, then persist a
            // subscription for the store. Relay OFF + an ephemeral peer port keep the bring-up
            // hermetic (no relay/introducer reach); a 1 s tick makes the first poll prompt.
            std::env::set_var("DIG_NODE_CACHE", td.path());
            std::env::set_var("DIG_RELAY_URL", "off");
            std::env::set_var("DIG_PEER_PORT", "0");
            std::env::set_var("DIG_NODE_WATCH_INTERVAL", "1");
            std::env::remove_var("DIG_PEER_NETWORK"); // unset → default ON
            subscribe_store(&store_hex).unwrap();

            let node = Arc::new(Node {
                cache_dir: td.path().to_path_buf(),
                http: reqwest::Client::new(),
                upstream: base,
                upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
                cache_lock: Mutex::new(()),
                identity_seed: Some([5u8; 32]),
                anchored_root_resolver: MockResolver::one(&store_hex, root),
                peer_status: peer::PeerStatus::new(),
                p2p_content: OnceLock::new(),
                content_cache: std::sync::Mutex::new(ContentCache::default()),
                inventory_refresher: OnceLock::new(),
                capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
                verification_ledger: verification_ledger::VerificationLedger::new(),
                self_ref: OnceLock::new(),
                gossip: OnceLock::new(),
                outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
                chat: chat::ChatState::new(),
                inbound_demand: inbound_demand::InboundDemand::new(),
                node_peer_id: OnceLock::new(),
            });

            assert!(!module_exists(&node.cache_dir, &store_hex, &root.to_hex()));

            peer::install_crypto_provider();
            peer::spawn_peer_network(node.clone());

            // Poll until the watcher PROACTIVELY pulls + lands the missing generation. No client read
            // is ever issued here, so a landed module can ONLY be the background chain-watch loop.
            let mut landed = false;
            for _ in 0..200 {
                if module_exists(&node.cache_dir, &store_hex, &root.to_hex()) {
                    landed = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(
                landed,
                "chain-watch must proactively pull the subscribed store's missing generation, \
                 independent of the (unavailable) P2P pool/DHT"
            );

            std::env::remove_var("DIG_NODE_CACHE");
            std::env::remove_var("DIG_RELAY_URL");
            std::env::remove_var("DIG_PEER_PORT");
            std::env::remove_var("DIG_NODE_WATCH_INTERVAL");
        });
    }

    /// **Proves (#213, robust/hermetic):** the §14 chain-watch loop the bring-up spawns
    /// ([`chainwatch::spawn_chain_watch`], the exact call `run_peer_network` makes) PROACTIVELY pulls
    /// a subscribed store's missing generation from a local §21 "peer" with NO client read — the
    /// autonomous-sync behavior, isolated from the gossip/DHT bring-up so it never depends on the
    /// network. **Catches:** a chain-watch spawn that never actually drives the pull.
    #[test]
    fn chain_watch_loop_proactively_gap_fills_without_a_read() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let root = Bytes32([0x10; 32]);
            let module = chain_anchored_module([1u8; 32], root.0);
            let (base, store_hex) = spawn_authed_remote(module.clone()).await;
            let td = tempfile::tempdir().unwrap();

            std::env::set_var("DIG_NODE_CACHE", td.path());
            std::env::set_var("DIG_NODE_WATCH_INTERVAL", "1");
            subscribe_store(&store_hex).unwrap();

            let node = Arc::new(Node {
                cache_dir: td.path().to_path_buf(),
                http: reqwest::Client::new(),
                upstream: base,
                upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
                cache_lock: Mutex::new(()),
                identity_seed: Some([5u8; 32]),
                anchored_root_resolver: MockResolver::one(&store_hex, root),
                peer_status: peer::PeerStatus::new(),
                p2p_content: OnceLock::new(),
                content_cache: std::sync::Mutex::new(ContentCache::default()),
                inventory_refresher: OnceLock::new(),
                capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
                verification_ledger: verification_ledger::VerificationLedger::new(),
                self_ref: OnceLock::new(),
                gossip: OnceLock::new(),
                outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
                chat: chat::ChatState::new(),
                inbound_demand: inbound_demand::InboundDemand::new(),
                node_peer_id: OnceLock::new(),
            });

            assert!(!module_exists(&node.cache_dir, &store_hex, &root.to_hex()));
            chainwatch::spawn_chain_watch(node.clone());

            let mut landed = false;
            for _ in 0..100 {
                if module_exists(&node.cache_dir, &store_hex, &root.to_hex()) {
                    landed = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            assert!(
                landed,
                "the spawned chain-watch loop must proactively pull the missing generation"
            );

            std::env::remove_var("DIG_NODE_CACHE");
            std::env::remove_var("DIG_NODE_WATCH_INTERVAL");
        });
    }

    /// **Proves (#1614):** the §21 backfill leg and the #1576 reshare leg claim against ONE shared
    /// single-flight gate, so a single read triggers AT MOST ONE whole-capsule acquisition. This stub
    /// asserts the gate is reachable as `Node::capsule_acquisition`; the full dedup pins follow.
    #[tokio::test]
    async fn capsule_acquisition_gate_is_a_single_shared_registry() {
        let (node, _td) = test_node(Some([5u8; 32]));
        let key = format!("{}:{}", "ab".repeat(32), "cd".repeat(32));
        // A fresh node has claimed nothing on the shared gate.
        assert!(!node.capsule_acquisition.is_warming(&key));
    }

    /// **Proves:** capsule backfill (§14.3) is a safe NO-OP on the FFI/consumer path — a node with no
    /// P2P content engine + no installed self-ref (the browser's in-process node) never spawns a pull
    /// and never records an in-flight entry, so a resource read there is unchanged.
    /// **Catches:** a backfill that panics without a runtime self-ref, or that pulls on the consumer
    /// path (which has no upstream/peer network and must not).
    #[tokio::test]
    async fn backfill_is_a_noop_without_a_peer_network() {
        let (node, _td) = test_node(Some([5u8; 32]));
        let store_hex = "ab".repeat(32);
        let root_hex = "cd".repeat(32);
        // No p2p_content and no self_ref installed (FFI path) → must be an immediate no-op.
        node.maybe_backfill_capsule(&store_hex, &root_hex, crate::download::ReadOrigin::Local);
        // Nothing pulled, nothing left in-flight.
        assert!(!module_exists(&node.cache_dir, &store_hex, &root_hex));
        let key = format!("{store_hex}:{root_hex}");
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "no in-flight backfill claimed on the consumer path"
        );
    }

    /// **Proves:** backfill skips a capsule already held locally (no redundant whole-`.dig` pull) even
    /// when the config is on. Uses a bare node (no peer network) so we only assert the held-skip guard
    /// short-circuits before the peer-network gate. **Catches:** a backfill that re-pulls held content.
    #[tokio::test]
    async fn backfill_skips_an_already_held_capsule() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default on
        let (node, _td) = test_node(Some([5u8; 32]));
        let store_hex = "ab".repeat(32);
        let root_hex = "cd".repeat(32);
        seed_module(&node, &store_hex, &root_hex, b"already-here");
        node.maybe_backfill_capsule(&store_hex, &root_hex, crate::download::ReadOrigin::Local);
        let key = format!("{store_hex}:{root_hex}");
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "an already-held capsule claims no in-flight backfill slot"
        );
    }

    /// **Proves (#1990):** a peer's inbound request records demand for the store — bumping its count
    /// and tagging it `Tier1Demand` — so the demand assigns the tier that gives eviction precedence.
    /// This is the always-on, amplification-free half of the trigger (it holds no content, pulls nothing).
    /// **Catches:** a demand record that fails to tag Tier1 or fails to accumulate.
    #[tokio::test]
    async fn inbound_demand_records_and_tags_tier1() {
        let (node, _td) = test_node(None);
        let store_hex = "ab".repeat(32);
        let root_hex = "cd".repeat(32);
        assert_eq!(node.inbound_demand.count(&store_hex), 0, "undemanded → 0");
        node.note_inbound_demand(&store_hex, &root_hex);
        node.note_inbound_demand(&store_hex, &root_hex);
        assert_eq!(node.inbound_demand.count(&store_hex), 2, "two requests → 2");
        assert_eq!(
            node.inbound_demand.tier(&store_hex),
            Some(crate::relevance::CacheTier::Tier1Demand),
            "inbound demand tags Tier1Demand"
        );
    }

    /// **Proves (#1990):** a non-canonical store id (a placeholder / `"latest"`-shaped value a serve
    /// path may hand in) records NO demand — only a real store id names demand.
    /// **Catches:** the ledger accumulating junk keys that would skew relevance.
    #[tokio::test]
    async fn inbound_demand_ignores_a_noncanonical_store() {
        let (node, _td) = test_node(None);
        node.note_inbound_demand("not-a-store", &"cd".repeat(32));
        assert_eq!(node.inbound_demand.count("not-a-store"), 0);
    }

    /// **Proves (#2013, #1990):** an inbound-DEMANDED module survives a size-cap eviction sweep that
    /// sacrifices an OLDER-by-mtime tier-0 precache module — through the LIVE
    /// `module_tier` → `evict_modules_locked` → `plan_module_eviction` path, not just the pure
    /// `evict_key` unit test. Tier precedence (`Tier0Precache` before `Tier1Demand`) OVERRIDES recency.
    ///
    /// **Non-vacuous:** the demanded store A is made the OLDER file and the tier-0 store B the NEWER
    /// one, so if `module_tier` were ignored (both defaulting to `Tier1Demand`, pure LRU-by-mtime) the
    /// sweep would evict A and keep B — the exact OPPOSITE of what is asserted. The assertion can only
    /// pass because tier beats mtime.
    /// **Catches:** a regression that stops stamping the demand tier into the cache entry, or sorts
    /// eviction by recency alone.
    #[test]
    fn inbound_demanded_module_survives_tier0_eviction_sweep() {
        // A plain `#[test]` (not `#[tokio::test]`) so `ENV_GUARD` — a std `Mutex` guarding the
        // process-global `DIG_NODE_CACHE`/cap config — is never held across an `.await`.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let (node, _td) = test_node(None);

        // Isolate the config the cap is read from, then pin a tiny cap: two ~1 KiB modules exceed it,
        // so the sweep must evict exactly one.
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(config_path());
        set_cache_cap_bytes(1_500).unwrap();

        // Store A: inbound-demanded → tagged `Tier1Demand`. Store B: a tier-0 precache land.
        let store_a = "ab".repeat(32);
        let store_b = "ba".repeat(32);
        let root = "cd".repeat(32);
        node.note_inbound_demand(&store_a, &root);
        crate::tier0_live::mark_tier0_land(&store_b);

        let path_a = module_path(&node.cache_dir, &store_a, &root);
        let path_b = module_path(&node.cache_dir, &store_b, &root);
        for p in [&path_a, &path_b] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, vec![0u8; 1_024]).unwrap();
        }
        // A is OLDER, B is NEWER — pure LRU-by-mtime would sacrifice A, so keeping A proves tier wins.
        filetime::set_file_mtime(&path_a, filetime::FileTime::from_unix_time(1_000, 0)).unwrap();
        filetime::set_file_mtime(&path_b, filetime::FileTime::from_unix_time(2_000, 0)).unwrap();

        pin_test_rt().block_on(node.evict_modules_if_needed());

        assert!(
            path_a.exists(),
            "the inbound-DEMANDED (Tier1) module must survive though it is the older file"
        );
        assert!(
            !path_b.exists(),
            "the tier-0 precache module must be evicted first despite being the newer file"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves (#2015):** tier-aware eviction precedence SURVIVES a restart. A persisted on-disk tier
    /// tag alone — with BOTH in-memory ledgers empty (a fresh `Node`, exactly as after a restart) —
    /// drives the sweep to sacrifice the `Tier0Precache` module and keep the `Tier1Demand` one.
    ///
    /// **Non-vacuous:** the persisted-Tier0 store B is made the OLDER file and the persisted-Tier1 store
    /// A the NEWER one, so pure mtime-LRU (the pre-persistence behaviour, both defaulting to
    /// `Tier1Demand`) would evict B's-older... — precisely, with no tag both would be `Tier1Demand` and
    /// the sweep would evict the OLDER file B and could keep A regardless; to force a genuine
    /// discriminator we make the sacrificial one (B) the NEWER file so that ONLY the persisted tier can
    /// explain evicting it. Under pure mtime the newer B would survive and the older A be evicted — the
    /// OPPOSITE of what is asserted, so the assertion can only pass because the persisted tag is read.
    /// **Catches:** a regression where `module_tier` stops consulting the on-disk tag, collapsing
    /// post-restart eviction back to tier-blind mtime-LRU.
    #[test]
    fn persisted_tier_tag_drives_eviction_precedence_after_restart() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let (node, _td) = test_node(None);

        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(config_path());
        set_cache_cap_bytes(1_500).unwrap();

        // Store A: persisted Tier1Demand (protected). Store B: persisted Tier0Precache (sacrificial).
        // NOTHING is recorded in the in-memory ledgers — the node is fresh, simulating a restart where
        // only the on-disk tags remain.
        let store_a = "a1".repeat(32);
        let store_b = "b2".repeat(32);
        let root = "cd".repeat(32);
        let path_a = module_path(&node.cache_dir, &store_a, &root);
        let path_b = module_path(&node.cache_dir, &store_b, &root);
        for p in [&path_a, &path_b] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, vec![0u8; 1_024]).unwrap();
        }
        crate::module_tier_tag::write_tier_tag(
            &node.cache_dir,
            &store_a,
            crate::relevance::CacheTier::Tier1Demand,
        );
        crate::module_tier_tag::write_tier_tag(
            &node.cache_dir,
            &store_b,
            crate::relevance::CacheTier::Tier0Precache,
        );
        // Confirm the ledgers really are empty — the tag is the ONLY tier signal in play.
        assert_eq!(node.inbound_demand.count(&store_a), 0);
        assert!(!crate::tier0_live::is_tier0_precache(&store_b));

        // Make the SACRIFICIAL (Tier0) module the NEWER file: pure mtime-LRU would keep it, so evicting
        // it can only be explained by the persisted tier.
        filetime::set_file_mtime(&path_a, filetime::FileTime::from_unix_time(1_000, 0)).unwrap();
        filetime::set_file_mtime(&path_b, filetime::FileTime::from_unix_time(2_000, 0)).unwrap();

        pin_test_rt().block_on(node.evict_modules_if_needed());

        assert!(
            path_a.exists(),
            "the persisted-Tier1 module must survive across restart"
        );
        assert!(
            !path_b.exists(),
            "the persisted-Tier0 module must be evicted first even though it is the newer file"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves (#2041):** the `<cache>/modules` size-cap bound holds on the READ-PATH §21 whole-store
    /// sync land, INDEPENDENT of the tier-0 precache loop. With tier-0 NOT running and no
    /// `cache.fetchAndCache` traffic, a real read-path `sync_module` land past the cap must ITSELF
    /// trigger the tier-aware eviction sweep (through `sync_module_and_bound`) — so a remotely-triggered
    /// backfill cannot grow the cache unbounded.
    ///
    /// **Non-vacuous:** the pre-existing tier-0 module B is the ONLY thing over the cap, and nothing but
    /// the read-path land's OWN sweep runs here — no tier-0 loop, no `cache.fetchAndCache`. Before the
    /// fix `sync_module` landed A WITHOUT sweeping, so B survived (unbounded growth); the assertion that
    /// B is evicted can only pass because the land now sweeps at its call site.
    /// **Catches:** a regression that drops the read-path sweep, letting the modules cache grow
    /// unbounded whenever the background precache loop is idle.
    #[test]
    fn read_path_sync_module_land_bounds_modules_cache_without_tier0_loop() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(config_path());
        set_cache_cap_bytes(100_000).unwrap();

        // Store A: synced on the read path from a live mock upstream (chain-anchored so the verify gate
        // admits it) — an untagged Tier1Demand land. Store B: a PRE-EXISTING tier-0 precache module,
        // oversized so the cache is over the cap the instant A lands.
        let store_a = Bytes32([0x2au8; 32]);
        let root = Bytes32([0x2bu8; 32]);
        let store_b = "bb".repeat(32);
        let capsule = chain_anchored_module(store_a.0, root.0);
        assert!(
            (capsule.len() as u64) < 100_000,
            "the synced capsule must fit UNDER the cap so ONLY the tier-0 module is the eviction victim"
        );

        let (mut node, _td) =
            test_node_with_resolver(None, MockResolver::one(&store_a.to_hex(), root));

        let path_b = module_path(&node.cache_dir, &store_b, &root.to_hex());
        std::fs::create_dir_all(path_b.parent().unwrap()).unwrap();
        std::fs::write(&path_b, vec![0u8; 200_000]).unwrap();
        crate::tier0_live::mark_tier0_land(&store_b);

        pin_test_rt().block_on(async {
            let base = spawn_capsule_rpc_upstream(
                capsule.clone(),
                4096,
                axum::http::StatusCode::BAD_REQUEST,
            )
            .await;
            node.upstream = base;
            // The read-path land: no tier-0 loop, no `cache.fetchAndCache` — only this sync runs.
            assert!(
                node.sync_module_and_bound(&store_a.to_hex(), &root.to_hex())
                    .await,
                "the read-path sync landed the chain-anchored capsule and may serve locally"
            );
        });

        let path_a = module_path(&node.cache_dir, &store_a.to_hex(), &root.to_hex());
        assert!(
            path_a.exists(),
            "the just-synced Tier1 module survives its own sweep"
        );
        assert!(
            !path_b.exists(),
            "the pre-existing tier-0 module is evicted by the read-path land's OWN sweep — the bound \
             holds with NO tier-0 loop and no cache.fetchAndCache"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves (#2041, the served≠requested residual):** a read-path §21 sync whose SERVED root differs
    /// from the requested one (the upstream's head advanced) still lands a chain-anchored capsule under
    /// the served root and `sync_module` returns `false` — yet the modules-cache bound MUST still hold,
    /// because that land grew the cache. The sweep runs after every sync ATTEMPT, so the oversized
    /// pre-existing tier-0 module is evicted even on the `false` return.
    ///
    /// **Non-vacuous:** `sync_module` returns `false` here (served AA.. != requested BB..), so a sweep
    /// gated on the `true` return — the pre-fix shape — would NOT run and the tier-0 module B would
    /// survive (unbounded growth). The eviction of B can only be explained by the now-unconditional sweep.
    /// **Catches:** a regression that re-gates the read-path sweep on the `sync_module` bool.
    #[test]
    fn read_path_sync_land_under_served_root_bounds_cache_even_when_served_ne_requested() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(config_path());
        set_cache_cap_bytes(100_000).unwrap();

        // The upstream serves the SERVED generation (chain-anchored via the resolver); the read requests
        // a DIFFERENT root, so the capsule lands under `served` and `sync_module` returns false.
        let seed = [1u8; 32];
        let store = Bytes32([0x3au8; 32]);
        let served = Bytes32([0xAAu8; 32]);
        let requested = Bytes32([0xBBu8; 32]);
        let store_b = "cc".repeat(32);
        let module = chain_anchored_module(store.0, served.0);
        assert!(
            (module.len() as u64) < 100_000,
            "the synced capsule must fit UNDER the cap so ONLY the tier-0 module is the eviction victim"
        );

        let (mut node, _td) =
            test_node_with_resolver(Some(seed), MockResolver::one(&store.to_hex(), served));

        let path_b = module_path(&node.cache_dir, &store_b, &served.to_hex());
        std::fs::create_dir_all(path_b.parent().unwrap()).unwrap();
        std::fs::write(&path_b, vec![0u8; 200_000]).unwrap();
        crate::tier0_live::mark_tier0_land(&store_b);

        pin_test_rt().block_on(async {
            // The §21 clone path serves the served root via its ETag; no `dig.getCapsule` route exists on
            // this mock, so path 1 fails and the clone path (which carries the served/requested mismatch)
            // is taken.
            let captured = Arc::new(std::sync::Mutex::new(None));
            let url = spawn_mock_module_server(captured, served, module.clone()).await;
            node.upstream = url;
            // The read-path land attempt: served != requested, so `sync_module` returns false — but a
            // whole capsule DID land under the served root, so the sweep must still fire.
            assert!(
                !node
                    .sync_module_and_bound(&store.to_hex(), &requested.to_hex())
                    .await,
                "served (AA..) != requested (BB..), so the caller may NOT serve locally"
            );
        });

        // The capsule landed under the SERVED root …
        let served_path = module_path(&node.cache_dir, &store.to_hex(), &served.to_hex());
        assert!(
            served_path.exists(),
            "the chain-anchored capsule landed under the served root"
        );
        // … and the sweep — which ran despite the `false` return — evicted the oversized tier-0 module.
        assert!(
            !path_b.exists(),
            "the pre-existing tier-0 module is evicted by the land's sweep even on a served≠requested \
             (false) sync — the bound holds regardless of the return value"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves (#2015):** a legacy cache entry with NO `.tier` sidecar defaults FAIL-SAFE. `module_tier`
    /// returns the protected `Tier1Demand`, and a sweep handles the untagged module without error.
    /// **Catches:** a regression that treats a missing tag as `Tier0Precache` (wrongly sacrificial) or
    /// panics on the absent sidecar.
    #[test]
    fn a_legacy_untagged_module_defaults_fail_safe() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let (node, _td) = test_node(None);

        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(config_path());
        set_cache_cap_bytes(10_000).unwrap(); // roomy — nothing is evicted, we assert the default + no panic

        let store = "77".repeat(32);
        let root = "cd".repeat(32);
        let path = module_path(&node.cache_dir, &store, &root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![0u8; 1_024]).unwrap();

        assert_eq!(
            node.module_tier(&store),
            crate::relevance::CacheTier::Tier1Demand,
            "an untagged legacy module is the PROTECTED tier, never sacrificial tier-0"
        );
        // The sweep must not error or drop the untagged module (cap is roomy).
        pin_test_rt().block_on(node.evict_modules_if_needed());
        assert!(
            path.exists(),
            "the untagged module survives a no-pressure sweep"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves (#1990):** the inbound-demand PULL is OFF by default — a peer's request records demand
    /// but spawns NO whole-capsule backfill even with a live peer network + provider. This preserves
    /// the amplification invariant: a stranger cannot drive an uncached pull until an operator opts in.
    /// **Catches:** a default-on regression that would re-open the peer-triggered amplification vector.
    #[test]
    fn inbound_demand_pull_is_off_by_default() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        std::env::remove_var("DIG_NODE_INBOUND_DEMAND_CACHE"); // default OFF
        let rt = pin_test_rt();
        let (store, tip, _rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        let (s, r) = (store.to_hex(), tip.to_hex());
        rt.block_on(async { node.note_inbound_demand(&s, &r) });
        assert_eq!(node.inbound_demand.count(&s), 1, "demand is still recorded");
        let key = format!("{s}:{r}");
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "inbound-demand pull must be OFF by default — no backfill without opt-in"
        );
    }

    /// **Proves (#1990):** with the operator opt-in ON, a peer's request for an UNCACHED store spawns
    /// a tier-1 whole-capsule backfill (the same single-flight machinery the fetch-side leg uses).
    /// **Catches:** the opt-in gate failing to reach the shared pull body, or the demand trigger not
    /// caching an uncached store.
    #[test]
    fn inbound_demand_opt_in_spawns_a_backfill_for_an_uncached_store() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        std::env::set_var("DIG_NODE_INBOUND_DEMAND_CACHE", "on");
        let rt = pin_test_rt();
        let (store, tip, _rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        // Anchor this node IN the demanded capsule's keyspace neighbourhood so the proximity gate
        // (#2014) admits the pull — this test exercises the opt-in reaching the shared pull body, not
        // the proximity denial (which has its own test below).
        node.set_node_peer_id(capsule_neighbourhood_peer_id(store.0, tip.0));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        let (s, r) = (store.to_hex(), tip.to_hex());
        rt.block_on(async { node.note_inbound_demand(&s, &r) });
        let key = format!("{s}:{r}");
        let warming = node.capsule_acquisition.is_warming(&key);
        std::env::remove_var("DIG_NODE_INBOUND_DEMAND_CACHE");
        assert!(
            warming,
            "an opt-in inbound-demand request for an uncached store must spawn a tier-1 backfill"
        );
    }

    /// **Proves (#1990):** even with the opt-in ON, a peer's request for an ALREADY-HELD store spawns
    /// no redundant pull — demand is recorded, but the shared held-skip guard short-circuits.
    /// **Catches:** a demand trigger that double-pulls content it already holds.
    #[test]
    fn inbound_demand_opt_in_skips_an_already_held_store() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        std::env::set_var("DIG_NODE_INBOUND_DEMAND_CACHE", "on");
        let rt = pin_test_rt();
        let (store, tip, _rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        node.set_node_peer_id(capsule_neighbourhood_peer_id(store.0, tip.0));
        let (s, r) = (store.to_hex(), tip.to_hex());
        seed_module(&node, &s, &r, b"already-here");
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        rt.block_on(async { node.note_inbound_demand(&s, &r) });
        let key = format!("{s}:{r}");
        let warming = node.capsule_acquisition.is_warming(&key);
        std::env::remove_var("DIG_NODE_INBOUND_DEMAND_CACHE");
        assert_eq!(node.inbound_demand.count(&s), 1, "demand still recorded");
        assert!(!warming, "an already-held store claims no backfill slot");
    }

    /// A `peer_id` that lands the `(store, root)` capsule INSIDE this node's keyspace neighbourhood:
    /// the capsule's DHT key verbatim (XOR distance 0 → proximity 1.0), so the #2014 proximity gate
    /// admits it. Its bitwise complement ([`capsule_far_peer_id`]) lands it in the FAR half.
    fn capsule_neighbourhood_peer_id(store_id: [u8; 32], root: [u8; 32]) -> [u8; 32] {
        *dig_dht::ContentId::capsule(store_id, root)
            .to_key()
            .as_bytes()
    }

    /// A `peer_id` FAR from the `(store, root)` capsule key — the complement of the key, so its top
    /// bit differs and XOR proximity is 0 (well below the midpoint bar). See #2014.
    fn capsule_far_peer_id(store_id: [u8; 32], root: [u8; 32]) -> [u8; 32] {
        capsule_neighbourhood_peer_id(store_id, root).map(|b| !b)
    }

    /// **Proves (#2014):** with the opt-in ON, the inbound-demand pull is admitted ONLY when the
    /// demanded capsule lies in THIS node's keyspace neighbourhood. A node whose `peer_id` is NEAR the
    /// capsule key spawns the tier-1 backfill; a node whose `peer_id` is FAR does NOT — the read is
    /// still served, but a stranger cannot drive caching of content outside the node's neighbourhood.
    /// **Catches:** the amplification primitive re-opening (a far/attacker-chosen capsule driving a
    /// peer-triggered pull) if the proximity gate is dropped or inverted.
    #[test]
    fn inbound_demand_pull_gated_on_keyspace_proximity() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        std::env::set_var("DIG_NODE_INBOUND_DEMAND_CACHE", "on");
        let rt = pin_test_rt();
        let (store, tip, _rk) = miss_setup();
        let (s, r) = (store.to_hex(), tip.to_hex());
        let key = format!("{s}:{r}");
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);

        // A node whose peer_id anchors it FAR from the capsule key — the pull is DENIED.
        let (far_node, far_td) = test_node(None);
        let far_node = Arc::new(far_node);
        far_node.set_self_ref(Arc::downgrade(&far_node));
        far_node.set_node_peer_id(capsule_far_peer_id(store.0, tip.0));
        attach_p2p(
            &far_node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &far_td,
        );
        rt.block_on(async { far_node.note_inbound_demand(&s, &r) });
        assert_eq!(
            far_node.inbound_demand.count(&s),
            1,
            "demand is still recorded regardless of proximity"
        );
        assert!(
            !far_node.capsule_acquisition.is_warming(&key),
            "a capsule OUTSIDE this node's neighbourhood must not drive a peer-triggered pull"
        );

        // A node whose peer_id anchors it NEAR the capsule key — the same request is ADMITTED.
        let (near_node, near_td) = test_node(None);
        let near_node = Arc::new(near_node);
        near_node.set_self_ref(Arc::downgrade(&near_node));
        near_node.set_node_peer_id(capsule_neighbourhood_peer_id(store.0, tip.0));
        attach_p2p(
            &near_node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &near_td,
        );
        rt.block_on(async { near_node.note_inbound_demand(&s, &r) });
        std::env::remove_var("DIG_NODE_INBOUND_DEMAND_CACHE");
        assert!(
            near_node.capsule_acquisition.is_warming(&key),
            "a capsule INSIDE this node's neighbourhood is admitted for the tier-1 pull"
        );
    }

    /// **Proves (#2014):** the proximity gate fails CLOSED when this node has no known self-identity
    /// (the FFI/consumer path never calls `set_node_peer_id`): even with the opt-in ON and a NEAR-by
    /// store, an unset `node_peer_id` admits NO pull — there is no anchor to define "our neighbourhood".
    /// **Catches:** a gate that treats a missing identity as "admit".
    #[test]
    fn inbound_demand_pull_denied_without_a_known_self_identity() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        std::env::set_var("DIG_NODE_INBOUND_DEMAND_CACHE", "on");
        let rt = pin_test_rt();
        let (store, tip, _rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        // Deliberately DO NOT set_node_peer_id — the consumer path has no peer identity.
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        let (s, r) = (store.to_hex(), tip.to_hex());
        rt.block_on(async { node.note_inbound_demand(&s, &r) });
        std::env::remove_var("DIG_NODE_INBOUND_DEMAND_CACHE");
        assert!(
            !node.capsule_acquisition.is_warming(&format!("{s}:{r}")),
            "no known self-identity → no anchor → the pull fails closed"
        );
    }

    #[tokio::test]
    async fn anonymous_request_rejected_by_authed_remote() {
        // Prove the auth gate is real (not an open server) — so the test above is
        // meaningful: a client carrying NO §21.9 identity is rejected.
        let (base, store_hex) = spawn_authed_remote(b"m".to_vec()).await;
        let store_id = Bytes32::from_hex(&store_hex).unwrap();
        let anon = DigClient::new(base);
        let r = anon.clone_store(&store_id, |_b, _r| Ok(()), None).await;
        assert!(
            r.is_err(),
            "anonymous clone must be rejected by the auth-required remote"
        );
    }

    /// Spawn a mock §21 host serving `GET /stores/:id/module`: it records the
    /// request headers into `captured` and replies 200 with `body` + an ETag of
    /// `root` (the wire form `clone_store` expects). Returns the base URL.
    async fn spawn_mock_module_server(
        captured: Arc<std::sync::Mutex<Option<axum::http::HeaderMap>>>,
        root: Bytes32,
        body: Vec<u8>,
    ) -> String {
        use axum::body::Body;
        use axum::http::{header, HeaderMap};
        use axum::response::Response;
        use axum::routing::get;
        use axum::Router;

        let handler = move |headers: HeaderMap| {
            let captured = captured.clone();
            let body = body.clone();
            async move {
                *captured.lock().unwrap() = Some(headers);
                Response::builder()
                    .header(header::ETAG, digstore_remote::etag::etag_for_root(&root))
                    .body(Body::from(body))
                    .unwrap()
            }
        };
        let app = Router::new().route("/stores/:id/module", get(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Spawn a mock upstream that speaks the `dig.getCapsule` JSON-RPC on `POST /` and
    /// REJECTS the §21 `GET /stores/:id/module` clone with `status` — the shape of the real
    /// gateway, which requires a `root` query on that route and answers 400 without one
    /// (#1886). `capsule` is streamed in `window`-sized pieces.
    async fn spawn_capsule_rpc_upstream(
        capsule: Vec<u8>,
        window: usize,
        clone_status: axum::http::StatusCode,
    ) -> String {
        use axum::{routing::get, routing::post, Json, Router};
        use serde_json::Value;

        let rpc = move |Json(body): Json<Value>| {
            let capsule = capsule.clone();
            async move {
                let offset = body["params"]["offset"].as_u64().unwrap_or(0) as usize;
                let end = (offset + window).min(capsule.len());
                let chunk = capsule.get(offset..end).unwrap_or(&[]);
                let complete = end >= capsule.len();
                Json(json!({"jsonrpc":"2.0","id":1,"result":{
                    "ciphertext": base64::engine::general_purpose::STANDARD.encode(chunk),
                    "total_length": capsule.len(),
                    "offset": offset,
                    "length": chunk.len(),
                    "complete": complete,
                    "next_offset": if complete { Value::Null } else { json!(end) },
                }}))
            }
        };
        let app = Router::new().route("/", post(rpc)).route(
            "/stores/:id/module",
            get(move || async move { (clone_status, "{\"error\":\"invalid_request\"}") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/")
    }

    /// **#1886, the flywheel's first hop.** A capsule LARGER than one JSON-RPC window lands in
    /// the cache from an upstream whose §21 clone route refuses the request — which is exactly
    /// the live gateway, where that route both requires a `root` query the client never sends
    /// and cannot carry a real capsule inside one response.
    ///
    /// The fixture spans three windows so a single-response implementation cannot pass, and the
    /// assertion is on the cached BYTES, so landing a truncated capsule cannot pass either.
    #[tokio::test]
    async fn whole_store_sync_lands_a_multi_window_capsule_when_the_clone_route_refuses() {
        let store = Bytes32([0x21u8; 32]);
        let root = Bytes32([0x22u8; 32]);
        let window = 4096;
        // A REAL chain-anchored capsule (so the verify-before-land gate admits it) padded past three
        // windows by a large filler section, so a single-response implementation still cannot pass.
        let capsule = chain_anchored_module_with_filler(store.0, root.0, window * 2 + 101);
        assert!(
            capsule.len() > window * 2,
            "the fixture must span >2 windows"
        );
        let base = spawn_capsule_rpc_upstream(
            capsule.clone(),
            window,
            axum::http::StatusCode::BAD_REQUEST,
        )
        .await;

        // No identity: the chunked path is anonymous, so whole-store sync no longer depends on
        // the node holding a §21 identity key.
        let (node, _td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), root));
        let served = node
            .sync_module_from(&base, &store.to_hex(), &root.to_hex())
            .await
            .expect("the chunked dig.getCapsule path syncs the capsule");

        assert_eq!(served, root);
        let cached = std::fs::read(module_path(
            &node.cache_dir,
            &store.to_hex(),
            &root.to_hex(),
        ))
        .unwrap();
        assert_eq!(
            cached, capsule,
            "the WHOLE capsule is cached, byte for byte"
        );
    }

    /// **#1886, the diagnosability half.** When both download paths fail, the reported reason
    /// carries the upstream's ACTUAL status. The message this replaced named three causes it
    /// had not checked ("no §21 identity, not authorized, or served root differs") and the
    /// truth was none of them — a plain HTTP 400 — which cost days of investigation aimed at
    /// authorization.
    #[tokio::test]
    async fn a_failed_fetch_reports_the_upstream_status_not_a_list_of_guesses() {
        use axum::{routing::get, routing::post, Router};
        // BOTH routes reject, with DIFFERENT statuses, so the message is pinned to the real
        // status of each attempt rather than to any single hardcoded number.
        let app = Router::new()
            .route(
                "/",
                post(|| async { (axum::http::StatusCode::IM_A_TEAPOT, "no") }),
            )
            .route(
                "/stores/:id/module",
                get(|| async { (axum::http::StatusCode::BAD_REQUEST, "no") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (mut node, _td) = test_node(Some([5u8; 32]));
        node.upstream = format!("http://{addr}/");
        let store_hex = Bytes32([0x31u8; 32]).to_hex();
        let root_hex = Bytes32([0x32u8; 32]).to_hex();

        let err = node
            .cache_fetch_and_cache(&store_hex, &root_hex)
            .await
            .expect_err("both paths refused");

        assert!(err.contains("418"), "carries the RPC path's status: {err}");
        assert!(
            err.contains("400"),
            "carries the clone path's status: {err}"
        );
        assert!(
            !err.contains("not authorized"),
            "no longer guesses at authorization: {err}"
        );
    }

    #[tokio::test]
    async fn authed_module_sync_carries_verifiable_identity() {
        let seed = [7u8; 32];
        let store = Bytes32([3u8; 32]);
        let root = Bytes32([9u8; 32]);
        let module = chain_anchored_module(store.0, root.0);
        let captured = Arc::new(std::sync::Mutex::new(None));
        let url = spawn_mock_module_server(captured.clone(), root, module).await;

        let (node, _td) =
            test_node_with_resolver(Some(seed), MockResolver::one(&store.to_hex(), root));
        let served = node
            .sync_module_from(&url, &store.to_hex(), &root.to_hex())
            .await
            .expect("authed sync succeeds");
        assert_eq!(served, root, "served root == requested root");

        let headers = captured
            .lock()
            .unwrap()
            .take()
            .expect("server saw a request");
        let id_hex = headers.get("x-dig-identity").unwrap().to_str().unwrap();
        let ts: u64 = headers
            .get("x-dig-timestamp")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let nonce_hex = headers.get("x-dig-nonce").unwrap().to_str().unwrap();
        let auth_hex = headers.get("x-dig-auth").unwrap().to_str().unwrap();

        // The identity must be exactly the one derived from our seed.
        assert_eq!(id_hex, identity::identity_from_seed(seed).pubkey_hex);

        // And the signature must verify for method "module" over (store, ts, nonce),
        // so a §21 remote will accept it (and it can't be replayed as another op).
        let pk = digstore_crypto::bls::PublicKey::from_bytes(
            &digstore_core::Bytes48::from_hex(id_hex).unwrap(),
        )
        .unwrap();
        let mut nonce = [0u8; 32];
        hex::decode_to_slice(nonce_hex, &mut nonce).unwrap();
        let sig = digstore_core::Bytes96(
            <[u8; 96]>::try_from(hex::decode(auth_hex).unwrap().as_slice()).unwrap(),
        );
        assert!(digstore_crypto::verify_request(
            &pk, "module", &store, ts, &nonce, &sig
        ));
    }

    #[tokio::test]
    async fn sync_caches_module_under_served_root_and_reports_mismatch() {
        let seed = [1u8; 32];
        let store = Bytes32([2u8; 32]);
        let served = Bytes32([0xAA; 32]); // the chain-anchored generation the upstream serves
        let requested = Bytes32([0xBB; 32]); // differs from served
        let module = chain_anchored_module(store.0, served.0);
        let captured = Arc::new(std::sync::Mutex::new(None));
        let url = spawn_mock_module_server(captured, served, module.clone()).await;

        // The chain confirms the SERVED root, so the capsule the upstream lands is genuinely anchored —
        // the served/requested mismatch is orthogonal to chain-anchoring (the upstream's head advanced).
        let (node, _td) =
            test_node_with_resolver(Some(seed), MockResolver::one(&store.to_hex(), served));
        let served = node
            .sync_module_from(&url, &store.to_hex(), &requested.to_hex())
            .await
            .expect("the sync itself succeeds — it just landed a different generation");
        assert_ne!(served, requested, "served (AA..) != requested (BB..)");

        // The module is cached under the SERVED root with the served bytes …
        let served_path = module_path(&node.cache_dir, &store.to_hex(), &served.to_hex());
        assert_eq!(std::fs::read(&served_path).unwrap(), module);
        // … and nothing is cached under the (unmatched) requested root.
        assert!(!module_path(&node.cache_dir, &store.to_hex(), &requested.to_hex()).exists());
    }

    // -- Chain-anchored verify before announce (#1623) ------------------------------------------

    /// A minimal chain-anchored `.dig` data section committing `(store, root)` — the shape the reshare
    /// leg's [`ChainAnchoredModuleVerifier`] admits, so a test upstream can serve a capsule that is
    /// genuinely the store's generation.
    fn chain_anchored_module(store: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        use digstore_core::datasection::{encode_blob, SectionId};
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
        ])
    }

    /// A chain-anchored module (as above) padded past `min_len` bytes with a filler section, for the
    /// multi-window capsule fixture — the padding lives in an extra section the verifier ignores, so the
    /// module still commits exactly `(store, root)`.
    fn chain_anchored_module_with_filler(
        store: [u8; 32],
        root: [u8; 32],
        min_len: usize,
    ) -> Vec<u8> {
        use digstore_core::datasection::{encode_blob, SectionId};
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::Filler as u16, vec![0x5a; min_len]),
        ])
    }

    /// Install an inventory-refresher spy that records whether the node announced itself a holder, so a
    /// test can prove an announce did — or did NOT — happen (§14.1: `refresh_dht_inventory` IS the announce).
    fn install_announce_spy(node: &Node, announced: Arc<AtomicBool>) {
        use crate::seams::dig_peer::peer_network::PeerNetwork;
        node.set_inventory_refresher(Box::new(move || {
            let announced = announced.clone();
            Box::pin(async move {
                announced.store(true, Ordering::SeqCst);
            })
        }));
    }

    /// **Proves (#1623):** a capsule synced from an upstream whose served root is NOT the store's
    /// chain-anchored generation never makes this node announce itself a holder — the module does not
    /// land, so `refresh_dht_inventory` is never reached. Without the chain-anchored verify-before-land
    /// gate the node would advertise unverified content, poisoning holder reputation and multiplying
    /// unverified copies through the reshare flywheel (#1576).
    /// **Catches:** landing + announcing a capsule bound only to a peer-served root.
    #[tokio::test]
    async fn a_capsule_whose_root_is_not_chain_confirmed_is_never_announced() {
        let store = Bytes32([1u8; 32]); // the id spawn_authed_remote seeds
        let served_root = Bytes32([0x10; 32]); // the genesis root it serves at
        let module = chain_anchored_module(store.0, served_root.0);
        let (base, store_hex) = spawn_authed_remote(module).await;

        // The chain has NO confirmed generation for this store, so the served root is unverifiable.
        let (mut node, _td) =
            test_node_with_resolver(Some([5u8; 32]), MockResolver::always(Ok(None)));
        node.upstream = base;
        let announced = Arc::new(AtomicBool::new(false));
        install_announce_spy(&node, announced.clone());

        let outcome = node
            .cache_fetch_and_cache(&store_hex, &served_root.to_hex())
            .await;

        assert!(
            outcome.is_err(),
            "an unconfirmed capsule must not be fetched-and-cached: {outcome:?}"
        );
        assert!(
            !module_exists(&node.cache_dir, &store_hex, &served_root.to_hex()),
            "the unverified capsule must not land in the cache"
        );
        assert!(
            !announced.load(Ordering::SeqCst),
            "the node must NOT announce itself a holder of an unverified capsule"
        );
    }

    /// **Proves (#1623):** a capsule whose served root IS the store's chain-anchored generation lands
    /// and the node announces itself a holder — the verify gate admits genuine content, so the flywheel
    /// still turns for chain-confirmed capsules (the gate is fail-closed, not fail-shut).
    #[tokio::test]
    async fn a_chain_confirmed_capsule_lands_and_is_announced() {
        let store = Bytes32([1u8; 32]);
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module(store.0, root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;

        let (mut node, _td) =
            test_node_with_resolver(Some([5u8; 32]), MockResolver::one(&store_hex, root));
        node.upstream = base;
        let announced = Arc::new(AtomicBool::new(false));
        install_announce_spy(&node, announced.clone());

        let (len, _root) = node
            .cache_fetch_and_cache(&store_hex, &root.to_hex())
            .await
            .expect("a chain-confirmed capsule is fetched and cached");

        assert_eq!(len as usize, module.len());
        assert!(module_exists(&node.cache_dir, &store_hex, &root.to_hex()));
        assert!(
            announced.load(Ordering::SeqCst),
            "a verified holder announces itself to the DHT"
        );
    }

    // -- Anchored-root resolution (dig.getAnchoredRoot) ------------------------

    #[test]
    fn parse_store_id_arg_accepts_only_canonical_launcher_ids() {
        let ok = json!({ "store_id": "ab".repeat(32) });
        assert!(parse_store_id_arg(&ok).is_ok());
        assert!(parse_store_id_arg(&json!({})).is_err()); // missing
        assert!(parse_store_id_arg(&json!({ "store_id": "ab".repeat(31) })).is_err()); // short
        assert!(parse_store_id_arg(&json!({ "store_id": "zz".repeat(32) })).is_err()); // non-hex
        assert!(parse_store_id_arg(&json!({ "store_id": 123 })).is_err()); // wrong type
    }

    #[tokio::test]
    async fn anchored_root_rejects_bad_store_id_without_touching_chain() {
        // A malformed store_id is rejected with a JSON-RPC -32602 BEFORE any chain
        // read, so the trusted-root endpoint validates input up front.
        let (node, _td) = test_node(None);
        let resp = node
            .anchored_root(&json!({ "store_id": "nope" }), json!(7))
            .await;
        assert_eq!(resp["id"], json!(7));
        assert_eq!(resp["error"]["code"], json!(-32602));
        assert!(resp.get("result").is_none());
    }

    // -- #1576 the whole-module serve surface (no network, no chain) -------------

    /// Write `bytes` as this node's cached module for `(store, root)`.
    fn cache_module(node: &Node, store: &str, root: &str, bytes: &[u8]) {
        let path = module_path(&node.cache_dir, store, root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }

    fn id_hex(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// **Proves:** `dig.getModuleInfo` describes a HELD module over the real dispatch, and reports the
    /// held/not-held distinction with the same `-32004` a resource miss uses — so a puller can tell
    /// "this holder does not have it" from "something went wrong".
    #[tokio::test]
    async fn get_module_info_describes_a_held_module_and_declines_an_unheld_one() {
        let (node, _td) = test_node(None);
        let (store, root) = (id_hex(0x11), id_hex(0x22));
        let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        cache_module(&node, &store, &root, &bytes);

        let held = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getModuleInfo",
                   "params":{"store_id":store,"root":root}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(held["result"]["total_size"], json!(bytes.len() as u64));
        assert_eq!(
            held["result"]["chunk_hashes"].as_array().unwrap().len(),
            held["result"]["chunk_lens"].as_array().unwrap().len(),
            "the descriptor must cover every chunk it declares a length for"
        );

        let missing = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"dig.getModuleInfo",
                   "params":{"store_id":id_hex(0x99),"root":root}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            missing["error"]["code"],
            json!(download::RESOURCE_UNAVAILABLE)
        );
    }

    /// **Proves (#2022):** `dig.listInventory` with `store_id` omitted — the whole-inventory
    /// enumeration ("a free map of everything this node holds") — is REFUSED over the permissionless
    /// peer surface (`ReadOrigin::Peer`) with -32601, yet still answered from the loopback/control
    /// path (`ReadOrigin::Local`), and the per-store form stays peer-reachable.
    /// **Catches:** a regression that lets an arbitrary peer enumerate the operator's full holdings,
    /// or one that breaks the operator's own consent-surface enumeration / the honest per-store query.
    #[tokio::test]
    async fn list_inventory_whole_enumeration_is_loopback_only() {
        let (node, _td) = test_node(None);
        let (store, root) = (id_hex(0x11), id_hex(0x22));
        cache_module(&node, &store, &root, b"held bytes");

        let whole_inventory =
            json!({"jsonrpc":"2.0","id":1,"method":"dig.listInventory","params":{}});

        // A remote peer MUST NOT be able to enumerate the whole inventory.
        let peer = handle_rpc(
            &node,
            whole_inventory.clone(),
            crate::download::ReadOrigin::Peer,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            peer["error"]["code"],
            json!(-32601),
            "whole-inventory enumeration must be refused on the peer surface"
        );
        assert!(peer.get("result").is_none());

        // The operator's own node (loopback) still sees what it advertises (#1934/#2006 consent).
        let local = handle_rpc(
            &node,
            whole_inventory,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(local["result"]["stores"], json!([store]));

        // The per-store query — the ONLY inventory question an honest peer needs — still works.
        let per_store = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"dig.listInventory",
                   "params":{"store_id":store}}),
            crate::download::ReadOrigin::Peer,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(per_store["result"]["store_id"], json!(store));
        assert_eq!(per_store["result"]["roots"], json!([root]));
    }

    /// **Proves:** the request/response form of `dig.fetchModuleRange` returns the EXACT requested
    /// window in the same frame shape the streaming peer form emits, so an agent can read a module by
    /// advancing `offset` without implementing the frame protocol (§6.2).
    /// **Catches:** the catalogue claiming `served: local` for a method the read path answers with
    /// -32601 — a discovery document that describes a method the node does not actually resolve.
    #[tokio::test]
    async fn fetch_module_range_answers_one_frame_over_json_rpc() {
        let (node, _td) = test_node(None);
        let (store, root) = (id_hex(0x33), id_hex(0x44));
        let bytes: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        cache_module(&node, &store, &root, &bytes);

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"dig.fetchModuleRange",
                   "params":{"store_id":store,"root":root,"offset":100,"length":50}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let frame = &resp["result"];
        assert_eq!(frame["offset"], json!(100));
        assert_eq!(frame["length"], json!(50));
        // The frame decodes as a real RangeFrame, so producer + puller agree on the encoding — the
        // #836 class of skew (base64 vs raw bytes) fails here rather than on a live network.
        let decoded: dig_nat::RangeFrame =
            serde_json::from_value(frame.clone()).expect("decodes as a RangeFrame");
        assert_eq!(decoded.bytes, bytes[100..150]);
    }

    /// **Proves:** a non-canonical id on either module method is a -32602 that never reaches the
    /// filesystem — a store id concatenated into a path would be a traversal primitive.
    #[tokio::test]
    async fn the_module_methods_reject_non_canonical_ids() {
        let (node, _td) = test_node(None);
        for method in ["dig.getModuleInfo", "dig.fetchModuleRange"] {
            let resp = handle_rpc(
                &node,
                json!({"jsonrpc":"2.0","id":4,"method":method,
                       "params":{"store_id":"../../etc/passwd","root":id_hex(1),"length":8}}),
                crate::download::ReadOrigin::Local,
                crate::download::RequestProvenance::FirstParty,
            )
            .await;
            assert_eq!(resp["error"]["code"], json!(-32602), "{method}");
        }
    }

    // -- #39 public collection reads (param validation + pagination, no chain) --
    //
    // These exercise dig.getCollection / dig.listCollectionItems through the real
    // handle_rpc router WITHOUT touching the network: a bad/empty launcher_ids list
    // is handled before any coinset read (an empty set resolves to zero items
    // immediately), so the dispatch, param parsing, and pagination math are verified
    // offline. (The lineage resolution itself is proven on the in-process Chia
    // simulator in digstore_chain::collection_index.)

    #[tokio::test]
    async fn list_collection_items_rejects_missing_launcher_ids() {
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"dig.listCollectionItems","params":{}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["id"], json!(3));
        assert_eq!(resp["error"]["code"], json!(-32602));
        assert!(resp.get("result").is_none());
    }

    #[tokio::test]
    async fn list_collection_items_rejects_non_hex_launcher_id() {
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"dig.listCollectionItems",
                   "params":{"launcher_ids":["nope"]}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[tokio::test]
    async fn list_collection_items_empty_set_is_a_deterministic_empty_page() {
        // An empty item set resolves to an empty page with no chain reads, and the
        // pagination envelope (offset/limit/total/next_offset) is well-formed.
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":5,"method":"dig.listCollectionItems",
                   "params":{"launcher_ids":[], "offset":0, "limit":10}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let result = &resp["result"];
        assert_eq!(result["items"], json!([]));
        assert_eq!(result["total"], json!(0));
        assert_eq!(result["offset"], json!(0));
        assert_eq!(result["limit"], json!(10));
        assert_eq!(
            result["next_offset"],
            Value::Null,
            "no next page past an empty set"
        );
    }

    #[tokio::test]
    async fn list_collection_items_caps_limit_at_200() {
        // A caller-supplied limit above the 200 cap is clamped (so one call can't
        // fan out unbounded chain reads); with an empty set the page is still empty.
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":6,"method":"dig.listCollectionItems",
                   "params":{"launcher_ids":[], "limit":100000}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["result"]["limit"], json!(200), "limit clamped to 200");
    }

    #[tokio::test]
    async fn get_collection_empty_set_resolves_to_zero_items() {
        // dig.getCollection over an empty set: zero resolved items, no uniform DID or
        // royalty, the declared DID echoed back, item_count == requested length.
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":8,"method":"dig.getCollection",
                   "params":{"launcher_ids":[], "did":"ab".repeat(32)}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let result = &resp["result"];
        assert_eq!(result["item_count"], json!(0));
        assert_eq!(result["resolved_count"], json!(0));
        assert_eq!(result["did"], Value::Null);
        assert_eq!(result["declared_did"], json!("ab".repeat(32)));
        assert_eq!(result["royalty_basis_points"], Value::Null);
    }

    #[tokio::test]
    async fn get_collection_rejects_bad_launcher_ids() {
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.getCollection",
                   "params":{"launcher_ids":"not-an-array"}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[tokio::test]
    async fn sync_skipped_without_identity_makes_no_request() {
        let (node, _td) = test_node(None);
        let store = Bytes32([2u8; 32]);
        let root = Bytes32([3u8; 32]);
        // No identity → must short-circuit to false WITHOUT touching the network
        // (the URL is intentionally unroutable; the call returns immediately).
        let failure = node
            .sync_module_from("http://127.0.0.1:1", &store.to_hex(), &root.to_hex())
            .await
            .expect_err("no identity and an unroutable upstream cannot sync");
        assert!(
            failure.contains("identity key"),
            "names the missing identity: {failure}"
        );
        assert!(!module_path(&node.cache_dir, &store.to_hex(), &root.to_hex()).exists());
    }

    // -- cache.* RPC (the chrome://settings DIG section) -----------------------

    /// Regression guard for the cache config RPC the browser's Mojo handler calls
    /// (cache.getConfig / cache.setCapBytes / cache.clear). Points the global
    /// cache dir at a throwaway tempdir via DIG_NODE_CACHE — no other test reads
    /// that env or `cache_dir()`, so the process-global set is safe here.
    // NB: this and `get_config_shape_*` mutate the PROCESS-GLOBAL `DIG_NODE_CACHE`
    // env and so hold `ENV_GUARD` for the whole body. They are plain `#[test]`
    // fns driving a current-thread runtime via `block_on` (not `#[tokio::test]`)
    // so the std mutex guard is never held across an `.await` (clippy
    // `await_holding_lock`), while still serializing against the other env tests.
    #[test]
    fn cache_rpc_config_roundtrip_and_clear() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        std::env::remove_var("DIG_NODE_CACHE_CAP");
        let (node, _td) = test_node(None);

        // setCapBytes persists the cap and echoes the effective value.
        let five_gib = 5u64 * 1024 * 1024 * 1024;
        let set = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.setCapBytes",
                   "params":{"cap_bytes": five_gib}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(set["result"]["cap_bytes"].as_u64(), Some(five_gib));

        // getConfig reflects the persisted cap and reports a used figure.
        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"cache.getConfig"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(got["result"]["cap_bytes"].as_u64(), Some(five_gib));
        assert!(got["result"]["used_bytes"].as_u64().is_some());

        // A below-floor request is clamped up to the 64 MiB minimum (a stray 0
        // must never disable caching).
        let low = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"cache.setCapBytes",
                   "params":{"cap_bytes": 1}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(low["result"]["cap_bytes"].as_u64(), Some(64 * 1024 * 1024));

        // clear succeeds with an empty result object.
        let cleared = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"cache.clear"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(cleared["result"].is_object());

        std::env::remove_var("DIG_NODE_CACHE");
    }

    // -- Peer connect + status control RPCs (#929) ------------------------------

    /// **Proves:** `control.peers.connect` on a node with NO peer network running (the FFI path / before
    /// bring-up — no retained gossip handle) returns a control error, never a panic or a false success.
    /// **Catches:** a connect arm that dereferences an absent pool handle.
    #[test]
    fn peers_connect_without_a_pool_reports_no_peer_network() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (node, _td) = test_node(None);
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"control.peers.connect",
                   "params":{"peer":"[::1]:9444"}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(resp.get("result").is_none());
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("no peer network"),
            "expected a no-peer-network control error: {resp}"
        );
    }

    /// **Proves:** `control.peerStatus` on a node with no peer network omits the per-peer array (there
    /// is no live pool to enumerate) while still returning the running/relay snapshot.
    /// **Catches:** a status handler that fabricates a `peers` array without a pool handle.
    #[test]
    fn peer_status_without_a_pool_omits_the_per_peer_array() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (node, _td) = test_node(None);
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"control.peerStatus"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(resp["result"].is_object());
        assert!(
            resp["result"].get("peers").is_none(),
            "no pool handle → no per-peer array: {resp}"
        );
    }

    // -- Subscription management control RPCs (SPEC §6) -------------------------
    //
    // `control.subscribe` / `control.unsubscribe` / `control.listSubscriptions` manage the node's
    // OWN persisted subscribed-store set. Like the cache.* config tests they mutate the PROCESS-GLOBAL
    // `DIG_NODE_CACHE` (the subscription file lives at `<cache>/subscriptions.json`), so they hold
    // `ENV_GUARD` for the whole body and drive a current-thread runtime via `block_on` (no std mutex
    // held across an `.await`).

    /// **Proves:** subscribe → list → unsubscribe round-trips through the real dispatch AND persists to
    /// disk (a fresh `load_subscriptions` sees the change); add/remove report newly-added/removed.
    /// **Catches:** a control RPC that doesn't persist, or a list that doesn't reflect the set.
    #[test]
    fn subscription_control_rpc_roundtrip_and_persistence() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        let (node, _td) = test_node(None);
        let store = "ab".repeat(32);

        // Initially no subscriptions.
        let empty = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"control.listSubscriptions"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(empty["result"]["count"], json!(0));
        assert_eq!(empty["result"]["subscriptions"], json!([]));

        // Subscribe → newly added.
        let sub = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"control.subscribe",
                   "params":{"store_id": store}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(sub["result"]["subscribed"], json!(true));
        assert_eq!(sub["result"]["added"], json!(true));

        // Re-subscribe → idempotent (added:false).
        let again = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"control.subscribe",
                   "params":{"store_id": store}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(again["result"]["added"], json!(false));

        // List reflects it, AND it is persisted (a fresh load sees it).
        let listed = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"control.listSubscriptions"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(listed["result"]["count"], json!(1));
        assert_eq!(listed["result"]["subscriptions"], json!([store]));
        assert!(load_subscriptions().contains(&store), "persisted to disk");

        // Unsubscribe → removed, and the set is empty again.
        let unsub = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":5,"method":"control.unsubscribe",
                   "params":{"store_id": store}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(unsub["result"]["removed"], json!(true));
        assert!(
            !load_subscriptions().contains(&store),
            "unsubscribe persisted"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves:** subscribing a malformed store id returns the CANONICAL control-plane error
    /// (`-32032` CONTROL_ERROR) with the `data.code`/`data.origin` envelope (dig-rpc-types §10).
    /// **Catches:** a control error that drifts off the taxonomy or drops the machine-branchable data.
    #[test]
    fn subscribe_bad_id_uses_canonical_control_error() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        let (node, _td) = test_node(None);

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"control.subscribe",
                   "params":{"store_id": "not-hex"}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTROL_ERROR), "-32032");
        assert_eq!(resp["error"]["data"]["code"], json!("CONTROL_ERROR"));
        assert_eq!(resp["error"]["data"]["origin"], json!("control"));
        assert!(resp.get("result").is_none());
        // Nothing was persisted.
        assert!(load_subscriptions().is_empty());

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// **Proves:** the control-plane taxonomy constants match dig-rpc-types §10 byte-for-byte (the
    /// shared wire contract): control errors are `-32030`/`-32031`/`-32032`, clear of the onion codes
    /// `-32020`/`-32021`/`-32022`. **Catches:** a renumber that reintroduces the historical collision.
    #[test]
    fn control_error_codes_match_dig_rpc_types() {
        assert_eq!(CONTROL_UNAUTHORIZED, -32030);
        assert_eq!(CONTROL_NOT_SUPPORTED, -32031);
        assert_eq!(CONTROL_ERROR, -32032);
        // Disjoint from the reserved onion codes (SPEC §2.6).
        for onion in [-32020, -32021, -32022] {
            assert_ne!(CONTROL_UNAUTHORIZED, onion);
            assert_ne!(CONTROL_NOT_SUPPORTED, onion);
            assert_ne!(CONTROL_ERROR, onion);
        }
    }

    /// **Proves:** the subscription control methods are NOT peer-reachable (SPEC §7.4a) — a remote
    /// peer that names one gets `-32601`, exactly like `cache.*`. **Catches:** a new control method
    /// accidentally exposed to untrusted peers.
    #[test]
    fn subscription_methods_are_not_peer_reachable() {
        for m in [
            "control.subscribe",
            "control.unsubscribe",
            "control.listSubscriptions",
            // The peer-management + status control methods stay loopback/in-process only: a remote
            // mTLS peer must NOT be able to drive a dial (`control.peers.connect`), drop a peer
            // (`control.peers.disconnect`), or read the local pool snapshot (`control.peerStatus`) —
            // the allowlist-by-construction property (#929).
            "control.peers.connect",
            "control.peers.disconnect",
            "control.peerStatus",
        ] {
            assert!(
                !peer::is_peer_reachable_method(m),
                "{m} must be loopback/in-process only"
            );
        }
    }

    /// **Proves:** `gap_fill_generation` is a cheap no-op when the generation is already held (no
    /// network, `Ok(())`). **Catches:** a gap-fill that re-pulls an already-held generation.
    #[tokio::test]
    async fn gap_fill_is_noop_when_already_held() {
        let (node, _td) = test_node(None);
        let store = [7u8; 32];
        let root = Bytes32([9u8; 32]);
        // Seed the module so the generation is "held".
        seed_module(&node, &hex::encode(store), &root.to_hex(), b"already-here");
        // Upstream is unroutable in test_node, so a real pull would fail; an already-held
        // generation must succeed WITHOUT touching it.
        assert_eq!(node.gap_fill_generation(store, root).await, Ok(()));
    }

    // -- Cached-store management RPCs (the DIG-settings cache manager, task #32) -

    /// Write a fake cached module for capsule (store, root) at the real
    /// `module_path` location so the management primitives see it. Returns the
    /// path written.
    fn seed_module(node: &Node, store_hex: &str, root_hex: &str, bytes: &[u8]) -> PathBuf {
        let path = module_path(&node.cache_dir, store_hex, root_hex);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Seed a capsule at the LEGACY `<root>.module` path a prior binary wrote (#1896) — the legacy
    /// corpus the reader-tolerance + startup-migration guarantees are proven against.
    fn seed_legacy_module(node: &Node, store_hex: &str, root_hex: &str, bytes: &[u8]) -> PathBuf {
        let path = node
            .cache_dir
            .join("modules")
            .join(store_hex)
            .join(format!("{root_hex}.module"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn a_landed_capsule_is_written_with_the_dig_extension() {
        // #1896: a fresh land is a `.dig`, never a `.module`.
        let (node, _td) = test_node(None);
        let store = "aa".repeat(32);
        let root = "11".repeat(32);
        let path = seed_module(&node, &store, &root, b"landed");
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("dig"));
        assert!(
            !node
                .cache_dir
                .join("modules")
                .join(&store)
                .join(format!("{root}.module"))
                .exists(),
            "no legacy `.module` is written for a fresh land"
        );
    }

    #[tokio::test]
    async fn cache_list_cached_discovers_a_legacy_dot_module_file() {
        // HOLDER-CONTINUITY GUARD (#1896): a cache written by a PRIOR binary (`.module`, no `.dig`) must
        // stay discoverable — listed, held, and thus announced (refresh_dht_inventory derives its
        // announcement from exactly this list). RED before the dual-suffix scan (which stripped only
        // `.module`... this seeds the inverse legacy case the new scan must also accept).
        let (node, _td) = test_node(None);
        let store = "cc".repeat(32);
        let root = "33".repeat(32);
        seed_legacy_module(&node, &store, &root, b"legacy-capsule");

        let cached = node.cache_list_cached().await;
        assert_eq!(cached.len(), 1, "the legacy capsule is enumerated");
        assert_eq!(cached[0].store_id, store);
        assert_eq!(cached[0].root, root);
        assert!(
            module_exists(&node.cache_dir, &store, &root),
            "a legacy `.module` still makes this node a holder"
        );
    }

    #[tokio::test]
    async fn cache_list_cached_discovers_a_new_dot_dig_file() {
        let (node, _td) = test_node(None);
        let store = "dd".repeat(32);
        let root = "44".repeat(32);
        seed_module(&node, &store, &root, b"dig-capsule");

        let cached = node.cache_list_cached().await;
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].root, root);
        assert!(module_exists(&node.cache_dir, &store, &root));
    }

    #[tokio::test]
    async fn serve_and_held_check_resolve_a_legacy_dot_module() {
        // #1896: the SERVE path (serve_local_blocking, via resolve_cached_path) reads a legacy
        // `.module`, and the held-check agrees — so an upgraded node keeps serving a legacy cache.
        let (node, _td) = test_node(None);
        let store = "ee".repeat(32);
        let root = "55".repeat(32);
        let key = CapsuleKey::parse(&store, &root).expect("canonical");
        let bytes = b"the-on-disk-module-bytes";
        seed_legacy_module(&node, &store, &root, bytes);

        assert!(module_exists(&node.cache_dir, &store, &root));
        // resolve_cached_path (the read authority) points at the legacy artifact, and reading it yields
        // the seeded bytes — the guarantee the whole serve path rests on.
        assert_eq!(
            std::fs::read(key.resolve_cached_path(&node.cache_dir)).unwrap(),
            bytes
        );
    }

    #[tokio::test]
    async fn mid_upgrade_partial_rename_loses_no_holder() {
        // #1896: mid-migration a cache is half `.dig`, half `.module`. The scan must return the FULL set
        // so a crash between renames never drops a holder.
        let (node, _td) = test_node(None);
        let store = "ff".repeat(32);
        let root_dig = "66".repeat(32);
        let root_legacy = "77".repeat(32);
        seed_module(&node, &store, &root_dig, b"new");
        seed_legacy_module(&node, &store, &root_legacy, b"old");

        let mut roots: Vec<_> = node
            .cache_list_cached()
            .await
            .into_iter()
            .map(|c| c.root)
            .collect();
        roots.sort();
        let mut expected = vec![root_dig, root_legacy];
        expected.sort();
        assert_eq!(roots, expected);
    }

    #[tokio::test]
    async fn cache_remove_removes_either_suffix() {
        // #1896: removal clears the holder claim whether the artifact is `.dig` or a legacy `.module`.
        let (node, _td) = test_node(None);
        let store = "ab".repeat(32);

        let root_dig = "88".repeat(32);
        seed_module(&node, &store, &root_dig, b"new");
        assert_eq!(node.cache_remove_cached(&store, &root_dig).await, Ok(true));
        assert!(!module_exists(&node.cache_dir, &store, &root_dig));

        let root_legacy = "99".repeat(32);
        seed_legacy_module(&node, &store, &root_legacy, b"old");
        assert_eq!(
            node.cache_remove_cached(&store, &root_legacy).await,
            Ok(true)
        );
        assert!(!module_exists(&node.cache_dir, &store, &root_legacy));
    }

    #[tokio::test]
    async fn list_cached_reports_capsules_with_size_and_mtime() {
        // cache.listCached enumerates every cached `.dig` (or legacy `.module`) as a capsule
        // (storeId:rootHash) with its on-disk size and last-used time.
        let (node, _td) = test_node(None);
        let store_a = "aa".repeat(32);
        let root_a = "11".repeat(32);
        let store_b = "bb".repeat(32);
        let root_b = "22".repeat(32);
        seed_module(&node, &store_a, &root_a, b"module-a-bytes"); // 14 bytes
        seed_module(&node, &store_b, &root_b, b"bb"); // 2 bytes

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.listCached"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let items = resp["result"]["cached"].as_array().unwrap();
        assert_eq!(items.len(), 2, "both cached capsules are listed");

        // Find capsule A and assert its identity + stats.
        let a = items
            .iter()
            .find(|c| c["store_id"].as_str() == Some(store_a.as_str()))
            .expect("capsule A present");
        assert_eq!(a["root"].as_str(), Some(root_a.as_str()));
        assert_eq!(a["size_bytes"].as_u64(), Some(14));
        assert!(a["last_used_unix_ms"].as_u64().is_some());
        // The canonical capsule string identity is carried verbatim.
        assert_eq!(
            a["capsule"].as_str(),
            Some(format!("{store_a}:{root_a}").as_str())
        );
    }

    #[tokio::test]
    async fn list_cached_is_empty_when_no_modules() {
        let (node, _td) = test_node(None);
        let cached = node.cache_list_cached().await;
        assert!(cached.is_empty(), "no modules → empty capsule list");
    }

    #[tokio::test]
    async fn list_cached_reports_lru_rank_ordered_by_recency() {
        // #279: each cache.listCached entry carries an `lru_rank` — 0 = the
        // least-recently-used capsule (the NEXT one the LRU cap would evict),
        // increasing with recency. The rank is a strict 0..n permutation and its
        // ordering agrees with `last_used_unix_ms`, so a controller can render the
        // eviction order without re-deriving it.
        let (node, _td) = test_node(None);
        for i in 0u8..3 {
            let store = format!("{:02x}", i).repeat(32);
            let root = format!("{:02x}", i + 0x40).repeat(32);
            seed_module(&node, &store, &root, b"x");
        }

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.listCached"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let items = resp["result"]["cached"].as_array().unwrap().clone();
        assert_eq!(items.len(), 3);

        // Every entry has an lru_rank; the set of ranks is exactly {0,1,2}.
        let mut ranks: Vec<u64> = items
            .iter()
            .map(|c| c["lru_rank"].as_u64().expect("lru_rank present"))
            .collect();
        ranks.sort_unstable();
        assert_eq!(ranks, vec![0, 1, 2], "ranks are a 0..n permutation");

        // Ordering by lru_rank agrees with ordering by last_used_unix_ms.
        let mut by_rank = items.clone();
        by_rank.sort_by_key(|c| c["lru_rank"].as_u64().unwrap());
        let last_used: Vec<u64> = by_rank
            .iter()
            .map(|c| c["last_used_unix_ms"].as_u64().unwrap())
            .collect();
        assert!(
            last_used.windows(2).all(|w| w[0] <= w[1]),
            "rank order must be non-decreasing in last_used (rank 0 = oldest = next evicted)"
        );

        // The rank-0 entry is (one of) the least-recently-used.
        let min_used = last_used.iter().copied().min().unwrap();
        let rank0 = items
            .iter()
            .find(|c| c["lru_rank"].as_u64() == Some(0))
            .unwrap();
        assert_eq!(rank0["last_used_unix_ms"].as_u64(), Some(min_used));
    }

    #[tokio::test]
    async fn cache_stats_reports_totals_and_counters() {
        // #279: cache.stats is an OPEN telemetry method — reserved cap, live used
        // bytes, the cached-capsule count + their total bytes, plus session eviction
        // + content-cache hit/miss counters. Additive-only (§5.1).
        let (node, _td) = test_node(None);
        let store = "ab".repeat(32);
        let root = "cd".repeat(32);
        seed_module(&node, &store, &root, b"twelve-bytes"); // 12 bytes

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.stats"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let r = &resp["result"];
        assert!(r["cap_bytes"].as_u64().is_some(), "cap_bytes");
        assert!(r["used_bytes"].as_u64().is_some(), "used_bytes");
        assert_eq!(r["entry_count"].as_u64(), Some(1), "one cached capsule");
        assert_eq!(r["total_bytes"].as_u64(), Some(12), "sum of capsule sizes");
        // Session counters are present (exact values are process-global, so only
        // their presence/type is asserted — never a cross-test-contaminated count).
        assert!(r["evicted_count"].as_u64().is_some(), "evicted_count");
        assert!(r["evicted_bytes"].as_u64().is_some(), "evicted_bytes");
        assert!(r["content_cache"]["hits"].as_u64().is_some(), "cc hits");
        assert!(r["content_cache"]["misses"].as_u64().is_some(), "cc misses");
        // #1991: refetch_count is present (process-global, so presence/type only), and the
        // per-tier occupancy shape is fixed — tier1 is REAL (backed by the inbound-demand
        // ledger); tier0 is now LIVE (#1934 PR-3) and its `wired`/`occupancy` are process-global
        // (another test may spawn the loop), so only presence/type is asserted; tier2 stays stubbed.
        assert!(r["refetch_count"].as_u64().is_some(), "refetch_count");
        assert_eq!(r["tiers"]["tier1_demand"]["wired"].as_bool(), Some(true));
        assert_eq!(r["tiers"]["tier1_demand"]["occupancy"].as_u64(), Some(0));
        assert!(
            r["tiers"]["tier0_precache"]["wired"].as_bool().is_some(),
            "tier0 wired is a bool"
        );
        assert!(
            r["tiers"]["tier0_precache"]["occupancy"].as_u64().is_some(),
            "tier0 occupancy is a u64"
        );
        assert_eq!(r["tiers"]["tier2_bribed"]["wired"].as_bool(), Some(false));
        assert_eq!(r["tiers"]["tier2_bribed"]["occupancy"].as_u64(), Some(0));
    }

    #[tokio::test]
    async fn cache_stats_tier1_occupancy_reflects_inbound_demand_ledger() {
        // #1991: tier1_demand.occupancy tracks the inbound-demand ledger's live entry count —
        // it must rise as distinct stores are demanded, not just report a placeholder zero.
        let (node, _td) = test_node(None);
        let store_a = "11".repeat(32);
        let store_b = "22".repeat(32);
        let root = "cd".repeat(32);
        node.note_inbound_demand(&store_a, &root);
        node.note_inbound_demand(&store_b, &root);

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.stats"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            resp["result"]["tiers"]["tier1_demand"]["occupancy"].as_u64(),
            Some(2),
            "two distinct demanded stores → occupancy 2"
        );
    }

    #[tokio::test]
    async fn cache_stats_refetch_count_does_not_bump_on_a_failed_sync() {
        // #1991: refetch_count must be a REAL counter, not a decoration — a sync that never reaches an
        // upstream must never be miscounted as a network land.
        //
        // `refetch_count` is a PROCESS-GLOBAL atomic, and `cargo test`/`cargo llvm-cov` run every test
        // in this crate's suite in parallel on the same process — including ~8 other pre-existing
        // tests that land real capsules (gap-fill, backfill, reshare-warm), any of which can bump the
        // counter between this test's OWN before/after reads. So this test proves the invariant
        // directly at its root cause instead of through the shared counter: `write_atomic` (the only
        // thing that could have bumped the counter) is never reached on a failed sync, so the module
        // simply never lands on disk. That is deterministic regardless of what any other test does to
        // the global counter.
        let (node, _td) = test_node(None);
        let store = "33".repeat(32);
        let root = "44".repeat(32);
        let result = node
            .sync_module_from("http://unreachable.invalid", &store, &root)
            .await;
        assert!(result.is_err(), "no upstream reachable → the sync fails");
        assert!(
            !module_path(&node.cache_dir, &store, &root).exists(),
            "a failed sync must never write the module — the only thing that could bump refetch_count"
        );
    }

    #[tokio::test]
    async fn cache_stats_refetch_count_increments_on_a_successful_network_land() {
        // #1991: the positive case — a REAL whole-capsule land against a live mock upstream must bump
        // `refetch_count` by AT LEAST one. Reuses the `gap_fill_pulls_a_missing_generation_from_a_remote`
        // mock-remote pattern: `gap_fill_generation` → `cache_fetch_and_cache` → `sync_module_from`,
        // the choke-point this counter is placed at.
        //
        // `>=` rather than exact `==`: `refetch_count` is a PROCESS-GLOBAL atomic shared with ~8 other
        // pre-existing tests that land real capsules, any of which may run concurrently in the same
        // `cargo test`/`cargo llvm-cov` process and bump it between this test's reads. A concurrent
        // land can only make the delta BIGGER, never smaller, so `>= before + 1` is the strongest claim
        // that stays deterministic under full-suite parallelism — this test's OWN land is guaranteed to
        // contribute at least one, which is exactly what it exists to prove.
        //
        // `spawn_authed_remote` always seeds store [1u8; 32] served at root [0x10; 32]
        // (its own backend, isolated per test on an ephemeral port) — matched here exactly as
        // `gap_fill_pulls_a_missing_generation_from_a_remote` does.
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let store_id: [u8; 32] = Bytes32::from_hex(&store_hex).unwrap().0;
        let td = tempfile::tempdir().unwrap();
        let node = Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: base,
            upstream_looped_back: std::sync::atomic::AtomicBool::new(false),
            cache_lock: Mutex::new(()),
            identity_seed: Some([5u8; 32]),
            anchored_root_resolver: MockResolver::one(&store_hex, root),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            capsule_acquisition: Arc::new(crate::seams::dig_peer::WarmRegistry::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
        };

        let before = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.stats"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await["result"]["refetch_count"]
            .as_u64()
            .unwrap();

        assert_eq!(node.gap_fill_generation(store_id, root).await, Ok(()));

        let after = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.stats"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await["result"]["refetch_count"]
            .as_u64()
            .unwrap();
        assert!(
            after > before,
            "one real network land → refetch_count rose by at least 1 (before={before}, after={after})"
        );

        // A second gap-fill of the SAME (already-held) generation is a no-op — it must NOT perform
        // another network land. Proved directly (not via the shared counter, for the same reason as
        // above): the cached bytes are exactly the original module, unchanged by the repeat call.
        assert_eq!(node.gap_fill_generation(store_id, root).await, Ok(()));
        let cached =
            std::fs::read(module_path(&node.cache_dir, &store_hex, &root.to_hex())).unwrap();
        assert_eq!(
            cached, module,
            "an already-held generation is an idempotent no-op — no second land"
        );
    }

    // -- dig.stage (#95 Pass C): in-process capsule staging/compile -------------
    //
    // The browser links `dig_runtime.dll` and reaches dig-node only through this
    // FFI JSON-RPC; a method/field rename silently breaks it at runtime (no
    // compile error across the FFI boundary). These tests LOCK the additive
    // `dig.stage` request params, the success result shape, and the catalogued
    // error codes (SYSTEM.md change-impact rule for the in-process dig-node FFI).

    #[tokio::test]
    async fn dig_stage_returns_the_capsule_result_shape() {
        let (node, _td) = test_node(None);
        // A folder to publish (nested, to exercise forward-slashed relative keys).
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("index.html"), b"<h1>hi</h1>").unwrap();
        std::fs::create_dir_all(src.path().join("assets")).unwrap();
        std::fs::write(src.path().join("assets").join("app.js"), b"console.log(1)").unwrap();

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":7,"method":"dig.stage",
                "params":{"dir": src.path().display().to_string()}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;

        assert_eq!(resp["id"], 7, "id round-trips: {resp}");
        let r = &resp["result"];
        // capsule == storeId:rootHash (canonical capsule identity).
        let capsule = r["capsule"].as_str().expect("capsule string");
        let (store_hex, root_hex) = capsule.split_once(':').expect("storeId:rootHash");
        assert_eq!(store_hex.len(), 64, "store id is 64-hex: {resp}");
        assert_eq!(root_hex.len(), 64, "root is 64-hex: {resp}");
        assert_eq!(r["store_id"].as_str(), Some(store_hex));
        assert_eq!(r["root"].as_str(), Some(root_hex));
        // content_address is the chia:// open address for the capsule.
        assert_eq!(
            r["content_address"].as_str(),
            Some(format!("chia://{store_hex}:{root_hex}/").as_str())
        );
        // module_path points at a real on-disk .dig module.
        let module_path = r["module_path"].as_str().expect("module_path");
        assert!(
            std::path::Path::new(module_path).exists(),
            "module written to disk: {module_path}"
        );
        assert!(
            r["size"].as_u64().unwrap_or(0) > 0,
            "module non-empty: {resp}"
        );
        assert_eq!(r["files"].as_u64(), Some(2), "two staged files: {resp}");
        // No store_id supplied ⇒ an ephemeral (preview) capsule.
        assert_eq!(r["ephemeral"], true, "no store_id ⇒ ephemeral: {resp}");
    }

    #[tokio::test]
    async fn dig_stage_honors_a_supplied_store_id_and_is_not_ephemeral() {
        let (node, _td) = test_node(None);
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("index.html"), b"x").unwrap();
        let store = "ab".repeat(32);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.stage",
                "params":{"dir": src.path().display().to_string(), "store_id": store}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        let r = &resp["result"];
        assert_eq!(
            r["store_id"].as_str(),
            Some(store.as_str()),
            "store id verbatim: {resp}"
        );
        assert_eq!(
            r["ephemeral"], false,
            "supplied store_id ⇒ not ephemeral: {resp}"
        );
    }

    #[tokio::test]
    async fn dig_stage_missing_dir_is_invalid_params() {
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.stage","params":{}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            resp["error"]["code"], -32602,
            "missing dir ⇒ -32602: {resp}"
        );
    }

    #[tokio::test]
    async fn dig_stage_nonexistent_dir_is_catalogued_error() {
        let (node, _td) = test_node(None);
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.stage",
                "params":{"dir":"/no/such/folder/xyzzy"}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["error"]["code"], -32011, "bad dir ⇒ -32011: {resp}");
    }

    #[tokio::test]
    async fn dig_stage_empty_folder_is_catalogued_error() {
        let (node, _td) = test_node(None);
        let src = tempfile::tempdir().unwrap();
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.stage",
                "params":{"dir": src.path().display().to_string()}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            resp["error"]["code"], -32012,
            "empty folder ⇒ -32012: {resp}"
        );
    }

    #[tokio::test]
    async fn dig_stage_bad_store_id_hex_is_invalid_params() {
        let (node, _td) = test_node(None);
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("index.html"), b"x").unwrap();
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.stage",
                "params":{"dir": src.path().display().to_string(), "store_id":"nothex"}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            resp["error"]["code"], -32602,
            "bad store_id ⇒ -32602: {resp}"
        );
    }

    #[tokio::test]
    async fn remove_cached_deletes_the_capsule_module() {
        let (node, _td) = test_node(None);
        let store = "cc".repeat(32);
        let root = "33".repeat(32);
        let path = seed_module(&node, &store, &root, b"to-be-removed");
        assert!(path.exists());

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.removeCached",
                   "params":{"store_id": store, "root": root}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert!(resp["result"]["removed"].as_bool() == Some(true));
        assert!(!path.exists(), "the module file is unlinked");
    }

    #[tokio::test]
    async fn remove_cached_rejects_a_non_canonical_key_at_the_validator() {
        // A non-hex store id is refused by the 64-hex validator (`CapsuleKey::parse`) BEFORE any path
        // is built — so it never reaches the containment guard below. This pins the validator gate;
        // `remove_cached_containment_guard_refuses_a_symlink_escape` pins the guard that follows it.
        let (node, _td) = test_node(None);
        let err = node
            .cache_remove_cached("../../etc", &"33".repeat(32))
            .await
            .unwrap_err();
        assert!(
            err.contains("invalid") || err.contains("hex"),
            "a non-canonical key is rejected as invalid input, got: {err}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_cached_containment_guard_refuses_a_symlink_escape() {
        // The 64-hex validator can only pass keys whose bytes contain no `.`/`/`, so a valid key can
        // never escape `<cache>/modules` on its own — the canonicalize + `starts_with(cache)` guard is
        // defense-in-depth against a compromised cache LAYOUT. Exercise it directly: plant a symlink
        // inside the cache whose target is a real file OUTSIDE the cache, then a well-formed remove
        // must REFUSE it and leave the outside file intact. Delete the guard and this unlinks the
        // outside file instead — so the assertions below fail without it (the test pins the guard).
        let (node, _td) = test_node(None);
        let store = "aa".repeat(32);
        let root = "bb".repeat(32);

        // A real file outside the cache dir that must survive the refused remove.
        let outside = tempfile::tempdir().unwrap();
        let protected = outside.path().join(format!("{root}.module"));
        std::fs::write(&protected, b"must-not-be-deleted").unwrap();

        // <cache>/modules/<store> -> <outside>, so <cache>/modules/<store>/<root>.module resolves,
        // through the symlink, to the protected file above.
        let modules = node.cache_dir_path().join("modules");
        std::fs::create_dir_all(&modules).unwrap();
        std::os::unix::fs::symlink(outside.path(), modules.join(&store)).unwrap();

        let err = node.cache_remove_cached(&store, &root).await.unwrap_err();
        assert!(
            err.contains("outside the cache"),
            "a symlink escape is refused by the containment guard, got: {err}"
        );
        assert!(
            protected.exists(),
            "the containment guard must leave the out-of-cache file intact"
        );
    }

    #[tokio::test]
    async fn remove_cached_missing_module_is_not_an_error() {
        // Removing a capsule that isn't cached is a no-op success (removed:false),
        // so the settings manager can call it idempotently.
        let (node, _td) = test_node(None);
        let removed = node
            .cache_remove_cached(&"dd".repeat(32), &"44".repeat(32))
            .await
            .unwrap();
        assert!(!removed, "absent capsule → removed:false");
    }

    #[tokio::test]
    async fn fetch_and_cache_syncs_a_capsule_on_demand() {
        // cache.fetchAndCache pulls a whole store over the §21 authed sync path and
        // lands it in the cache, reporting the served root + size.
        let root = Bytes32([0x10; 32]); // the served genesis root
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (mut node, _td) =
            test_node_with_resolver(Some([5u8; 32]), MockResolver::one(&store_hex, root));
        node.upstream = base; // point the on-demand fetch at the authed remote
        let root_hex = root.to_hex();

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.fetchAndCache",
                   "params":{"store_id": store_hex, "root": root_hex}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["result"]["status"].as_str(), Some("cached"));
        assert_eq!(
            resp["result"]["served_root"].as_str(),
            Some(root_hex.as_str())
        );
        assert_eq!(
            resp["result"]["size_bytes"].as_u64(),
            Some(module.len() as u64)
        );

        let cached = std::fs::read(module_path(&node.cache_dir, &store_hex, &root_hex)).unwrap();
        assert_eq!(cached, module, "fetched module is cached for local-first");

        // A second fetch of the now-present capsule reports already_cached without
        // re-downloading.
        let again = node
            .cache_fetch_and_cache(&store_hex, &root_hex)
            .await
            .unwrap();
        assert_eq!(again.0, module.len() as u64);
        let again_resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"cache.fetchAndCache",
                   "params":{"store_id": store_hex, "root": root_hex}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(
            again_resp["result"]["status"].as_str(),
            Some("already_cached")
        );
    }

    #[tokio::test]
    async fn fetch_and_cache_announces_dht_inventory_once_on_fresh_land() {
        // #1586 reshare/flywheel invariant: landing a capsule at runtime (via ANY
        // caller of cache_fetch_and_cache — hosted_pin, backfill-cache, the RPC,
        // gap-fill) makes this node a DISCOVERABLE holder. So a fresh cache MUST
        // fire the DHT inventory refresh exactly once; an already-cached call must
        // NOT re-announce (unchanged inventory).
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (mut node, _td) =
            test_node_with_resolver(Some([7u8; 32]), MockResolver::one(&store_hex, root));
        node.upstream = base;
        let root_hex = root.to_hex();

        let announces = Arc::new(AtomicUsize::new(0));
        let counter = announces.clone();
        node.set_inventory_refresher(Box::new(move || {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        }));

        // Fresh land → exactly one announce.
        node.cache_fetch_and_cache(&store_hex, &root_hex)
            .await
            .unwrap();
        assert_eq!(
            announces.load(Ordering::SeqCst),
            1,
            "a freshly-landed capsule announces its DHT inventory once"
        );

        // Already cached → no re-announce (dedupe; inventory unchanged).
        node.cache_fetch_and_cache(&store_hex, &root_hex)
            .await
            .unwrap();
        assert_eq!(
            announces.load(Ordering::SeqCst),
            1,
            "an already-cached fetch does not re-announce"
        );
    }

    #[tokio::test]
    async fn gap_fill_announces_exactly_once_no_double_announce() {
        // gap_fill_generation lands a capsule via cache_fetch_and_cache, which now
        // owns the announce. The previously-explicit refresh at the gap_fill site is
        // removed, so a gap-fill announces EXACTLY once — not twice.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root = Bytes32([0x10; 32]);
        let module = chain_anchored_module([1u8; 32], root.0);
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (mut node, _td) =
            test_node_with_resolver(Some([8u8; 32]), MockResolver::one(&store_hex, root));
        node.upstream = base;
        let root_hex = root.to_hex();

        let announces = Arc::new(AtomicUsize::new(0));
        let counter = announces.clone();
        node.set_inventory_refresher(Box::new(move || {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
            })
        }));

        let store_id: [u8; 32] = hex::decode(&store_hex).unwrap().try_into().unwrap();
        let root = digstore_core::Bytes32::from_hex(&root_hex).unwrap();
        node.gap_fill_generation(store_id, root).await.unwrap();
        assert_eq!(
            announces.load(Ordering::SeqCst),
            1,
            "gap-fill announces exactly once (announce centralized in cache_fetch_and_cache)"
        );
    }

    #[tokio::test]
    async fn fetch_and_cache_without_identity_fails() {
        // No §21 identity → the authed sync can't run, so the fetch reports failed
        // rather than silently succeeding.
        let (node, _td) = test_node(None);
        let store = "ee".repeat(32);
        let root = "55".repeat(32);
        let err = node.cache_fetch_and_cache(&store, &root).await.unwrap_err();
        assert!(!err.is_empty(), "fetch without identity surfaces an error");

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.fetchAndCache",
                   "params":{"store_id": store, "root": root}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["result"]["status"].as_str(), Some("failed"));
    }

    // -- Shared .dig cache (#96) -----------------------------------------------
    //
    // Tests that drive the PROCESS-GLOBAL `cache_dir()` (via the `DIG_NODE_CACHE`
    // env) must not run concurrently with each other or with
    // `cache_rpc_config_roundtrip_and_clear`, since cargo runs tests in parallel
    // threads of one process. `ENV_GUARD` (now crate-shared, `test_support::ENV_GUARD`, so
    // `download`'s env-touching tests serialize against these too) handles that.
    use test_support::ENV_GUARD;

    // Item 1 — Atomic content-addressed module writes.

    #[test]
    fn write_atomic_leaves_no_partial_and_overwrites_cleanly() {
        // A module written via write_atomic appears in full or not at all, never
        // as a torn temp file, and a second write of (immutable) bytes converges.
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("modules").join("aa").join("bb.module");
        write_atomic(&path, b"capsule-bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"capsule-bytes");
        // No leftover temp files in the target dir (rename consumed it).
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "no .tmp-* partial files left behind");
        // Re-writing identical immutable bytes converges to the same content.
        write_atomic(&path, b"capsule-bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"capsule-bytes");
    }

    #[tokio::test]
    async fn concurrent_module_writers_converge_with_no_partial_observed() {
        // Two "writers" race to write the SAME capsule module concurrently; a
        // reader polling in parallel must only ever see the full bytes (never a
        // partial), and the final file is exactly the module bytes.
        use std::sync::atomic::{AtomicBool, Ordering};
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().to_path_buf();
        let store = "ab".repeat(32);
        let root = "cd".repeat(32);
        let module: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let path = module_path(&dir, &store, &root);

        let stop = Arc::new(AtomicBool::new(false));
        let saw_partial = Arc::new(AtomicBool::new(false));
        // Reader: while writers run, every readable version must equal `module`.
        let reader = {
            let path = path.clone();
            let module = module.clone();
            let stop = stop.clone();
            let saw_partial = saw_partial.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(bytes) = std::fs::read(&path) {
                        if bytes != module {
                            saw_partial.store(true, Ordering::Relaxed);
                        }
                    }
                }
            })
        };

        // Two writers of the identical (immutable) module bytes.
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let module = module.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..20 {
                    write_atomic(&path, &module).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().unwrap();

        assert!(
            !saw_partial.load(Ordering::Relaxed),
            "a reader observed a torn/partial module — atomic write violated"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            module,
            "writers converge on the full module bytes"
        );
    }

    // Item 2 — Cross-process advisory lock (config lost-update + eviction).

    #[test]
    fn concurrent_config_rmw_loses_no_update() {
        // The canonical lost-update test: two "processes" each increment a shared
        // counter key via the config read-modify-write N times. Each increment is
        // read-current → +1 → write. WITHOUT the cross-process lock, interleaved
        // read/read/write/write loses increments and the final count is < 2N;
        // WITH the lock every increment is serialized and the count is EXACTLY 2N.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        let _ = std::fs::remove_file(config_path());

        const N: u64 = 100;
        fn bump() {
            for _ in 0..N {
                update_config_locked(|v| {
                    let cur = v.get("counter").and_then(|c| c.as_u64()).unwrap_or(0);
                    v["counter"] = json!(cur + 1);
                })
                .unwrap();
            }
        }
        let a = std::thread::spawn(bump);
        let b = std::thread::spawn(bump);
        a.join().unwrap();
        b.join().unwrap();

        let txt = std::fs::read_to_string(config_path()).unwrap();
        let v: Value = serde_json::from_str(&txt).expect("config.json is valid JSON");
        assert_eq!(
            v["counter"].as_u64(),
            Some(2 * N),
            "no increments lost — every read-modify-write was serialized"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    #[test]
    fn concurrent_setters_keep_both_keys() {
        // The two real config setters (cache cap vs wc projectId) run concurrently;
        // both keys survive in a single valid config.json (no clobber, no torn file).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        let _ = std::fs::remove_file(config_path());

        let cap = std::thread::spawn(|| {
            for i in 0..100 {
                set_cache_cap_bytes(64 * 1024 * 1024 + i).unwrap();
            }
        });
        let wc = std::thread::spawn(|| {
            for i in 0..100 {
                set_wc_project_id(&format!("proj-{i}")).unwrap();
            }
        });
        cap.join().unwrap();
        wc.join().unwrap();

        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(config_path()).unwrap()).unwrap();
        assert!(v.get("cache_cap_bytes").and_then(|x| x.as_u64()).is_some());
        assert!(v.get("wc_project_id").and_then(|x| x.as_str()).is_some());

        std::env::remove_var("DIG_NODE_CACHE");
    }

    #[test]
    fn cache_lock_is_exclusive_then_released() {
        // The advisory lock is genuinely exclusive: while one guard is held a
        // direct try_lock on the same file would block (WouldBlock); once dropped
        // it can be re-acquired. Proves eviction/config RMW are actually serialized.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));

        let guard = acquire_cache_lock().expect("first lock acquires");
        // A second, independent handle on the same lockfile must NOT acquire.
        let path = lockfile_path();
        let other = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        assert!(
            FileExt::try_lock(&other).is_err(),
            "a held lock must block a concurrent try_lock"
        );
        drop(guard);
        assert!(
            FileExt::try_lock(&other).is_ok(),
            "after release the lock is re-acquirable"
        );
        let _ = FileExt::unlock(&other);

        std::env::remove_var("DIG_NODE_CACHE");
    }

    // Item 3 — Robust dir resolver + writability fallback.

    #[test]
    fn canonical_cache_dir_honors_env_override() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        let want = td.path().join("custom-cache");
        std::env::set_var("DIG_NODE_CACHE", &want);
        assert_eq!(canonical_cache_dir(), want);
        std::env::remove_var("DIG_NODE_CACHE");
    }

    #[test]
    fn canonical_cache_dir_default_ends_in_dignode_cache() {
        // With no override the default path keeps the historic, byte-exact
        // `.../DigNode/cache` suffix (the shared-cache contract with dig-companion).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_CACHE");
        let dir = canonical_cache_dir();
        assert!(
            dir.ends_with("DigNode/cache") || dir.ends_with("DigNode\\cache"),
            "default cache dir must end in DigNode/cache, got {}",
            dir.display()
        );
        // On Windows the base is %LOCALAPPDATA%; on Unix/macOS it is $HOME — both
        // matching dig-companion so the cache is shared by construction.
    }

    #[test]
    fn resolve_cache_dir_reports_shared_for_writable_canonical() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        let (dir, shared) = resolve_cache_dir();
        assert!(shared, "a writable canonical dir is reported as shared");
        assert!(dir.starts_with(td.path()), "uses the canonical (env) dir");
        std::env::remove_var("DIG_NODE_CACHE");
    }

    #[test]
    fn resolve_cache_dir_falls_back_to_private_when_unwritable() {
        // Point the canonical dir at a path that cannot be created (a child of a
        // regular FILE), forcing the writability probe to fail → private fallback.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        let file = td.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let unwritable = file.join("cache"); // can't mkdir under a file
        std::env::set_var("DIG_NODE_CACHE", &unwritable);

        let (dir, shared) = resolve_cache_dir();
        assert!(
            !shared,
            "an unwritable canonical dir falls back, shared=false"
        );
        assert_eq!(dir, private_fallback_dir(), "uses the process-private dir");
        assert_ne!(dir, unwritable, "does not use the unwritable canonical dir");

        std::env::remove_var("DIG_NODE_CACHE");
    }

    // Item 4 — Additive cache.getConfig FFI shape (regression guard).

    #[test]
    fn get_config_shape_is_additive_existing_fields_intact_plus_new() {
        // FFI change-impact rule (SYSTEM.md): cache.getConfig must keep its
        // existing fields and ONLY add `cache_dir` + `shared`. This pins the shape
        // so a rename/removal of cap_bytes/used_bytes breaks the build, not the
        // browser silently at runtime.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        std::env::remove_var("DIG_NODE_CACHE_CAP");
        let (node, _node_td) = test_node(None);

        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":42,"method":"cache.getConfig"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        let result = got["result"].as_object().expect("result is an object");

        // EXISTING fields (must remain, same types).
        assert!(
            result.get("cap_bytes").and_then(|v| v.as_u64()).is_some(),
            "cap_bytes still present (u64)"
        );
        assert!(
            result.get("used_bytes").and_then(|v| v.as_u64()).is_some(),
            "used_bytes still present (u64)"
        );
        // NEW additive fields.
        let dir = result
            .get("cache_dir")
            .and_then(|v| v.as_str())
            .expect("cache_dir present (string)");
        assert!(!dir.is_empty(), "cache_dir is the effective resolved path");
        let shared = result
            .get("shared")
            .and_then(|v| v.as_bool())
            .expect("shared present (bool)");
        assert!(shared, "a writable env-set cache dir is shared");
        // Envelope intact.
        assert_eq!(got["id"], json!(42));
        assert_eq!(got["jsonrpc"], json!("2.0"));

        std::env::remove_var("DIG_NODE_CACHE");
    }

    #[test]
    fn control_peer_status_reports_not_running_by_default() {
        // The peer-status RPC is read-only and safe with NO peer network running (the in-process FFI
        // path): it reports `running:false` + the resolved relay endpoint + network id.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_RELAY_URL");
        std::env::remove_var("DIG_NETWORK_ID");
        std::env::remove_var("DIG_NETWORK_GENESIS");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (node, _td) = test_node(None);
        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":7,"method":"control.peerStatus"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        let result = got["result"].as_object().expect("result object");
        assert_eq!(result["running"], json!(false));
        assert_eq!(
            result["relay"]["url"],
            json!(peer::DEFAULT_RELAY_URL),
            "defaults to relay.dig.net when DIG_RELAY_URL unset"
        );
        assert_eq!(result["network_id"], json!(peer::DEFAULT_NETWORK_ID));
        assert_eq!(
            result["genesis"],
            json!(hex::encode(dig_constants::DIG_MAINNET.genesis_challenge())),
            "the default node's status surfaces the canonical mainnet genesis (#1372)"
        );
        assert_eq!(result["connected_peers"], json!(0));
        assert_eq!(got["id"], json!(7));
        assert_eq!(got["jsonrpc"], json!("2.0"));
    }

    #[test]
    fn control_peer_status_attaches_the_pool_posture_when_a_pool_is_running() {
        // #709/#846: with a live gossip pool retained on the node, `control.peerStatus` attaches a
        // `pool` object (connected/in_flight/target/min/max/backed_off/under_connected) — the
        // operator's connectivity posture, sourced from `GossipHandle::pool_stats`. A freshly-started
        // pool has zero connected peers and is under-connected, with an ordered min<=target<=max.
        use crate::seams::dig_peer::peer_network::PeerNetwork;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        peer::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (node, _td) = test_node(None);
        // A real, freshly-started gossip pool on a concrete loopback bind (no discovery, no peers).
        // Prefer the IPv6 loopback (§5.2 IPv6-first); fall back to IPv4 on a host where IPv6 is
        // unavailable entirely — this test asserts the `peerStatus` pool-posture surface, not
        // dual-stack transport itself, so either family satisfies it fully.
        let handle = rt.block_on(async {
            let dir = tempfile::tempdir().expect("gossip dir");
            let listen_addr: std::net::SocketAddr =
                if peer::tests::is_ipv6_loopback_available().await {
                    "[::1]:0".parse().unwrap()
                } else {
                    "127.0.0.1:0".parse().unwrap()
                };
            let cfg = dig_gossip::GossipConfig {
                network_id: chia_protocol::Bytes32::new([0x33u8; 32]),
                cert_path: dir.path().join("node.cert").display().to_string(),
                key_path: dir.path().join("node.key").display().to_string(),
                peers_file_path: dir.path().join("peers.json"),
                peer_pool: Some(dig_gossip::PeerPoolConfig::default()),
                listen_addr,
                ..Default::default()
            };
            dig_gossip::GossipService::new(cfg)
                .expect("gossip config")
                .start()
                .await
                .expect("gossip start")
        });
        node.set_gossip_handle(handle);

        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":8,"method":"control.peerStatus"}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        let pool = got["result"]["pool"]
            .as_object()
            .expect("peerStatus attaches a pool object when a pool is running");
        assert_eq!(pool["connected"], json!(0), "a fresh pool has no peers");
        assert_eq!(pool["under_connected"], json!(true));
        let (min, target, max) = (
            pool["min"].as_u64().expect("min"),
            pool["target"].as_u64().expect("target"),
            pool["max"].as_u64().expect("max"),
        );
        assert!(min <= target && target <= max, "{min}<={target}<={max}");
    }

    // -- #127 MANDATORY anchored-root pin on the read path ----------------------
    //
    // Every `dig.getContent` resolves the store's CHIP-0035 chain-anchored TIP
    // root and serves against IT, or fails closed with `ROOT_NOT_ANCHORED`
    // (-32005). A compromised upstream/host can never choose which generation is
    // served; a rootless URN resolves to the chain tip; an explicit root must
    // equal the tip. These tests pin the policy (pure `decide_pin`) and the
    // fail-closed read-path behavior (end-to-end through `handle_rpc`).

    #[test]
    fn decide_pin_serves_the_tip_for_a_rootless_request() {
        // Rootless (no requested root) → serve at the resolved chain tip.
        let tip = Bytes32([0xAA; 32]);
        match decide_pin(true, None, Ok(Some(tip))) {
            PinDecision::ServeAt(root) => assert_eq!(root, tip),
            _ => panic!("rootless under a confirmed tip must ServeAt the tip"),
        }
    }

    #[test]
    fn decide_pin_serves_when_explicit_root_matches_the_tip() {
        let tip = Bytes32([0xAA; 32]);
        match decide_pin(true, Some(tip), Ok(Some(tip))) {
            PinDecision::ServeAt(root) => assert_eq!(root, tip),
            _ => panic!("explicit root == tip must ServeAt"),
        }
    }

    #[test]
    fn decide_pin_rejects_when_explicit_root_differs_from_the_tip() {
        let tip = Bytes32([0xAA; 32]);
        let other = Bytes32([0xBB; 32]);
        match decide_pin(true, Some(other), Ok(Some(tip))) {
            PinDecision::Reject(code, msg) => {
                assert_eq!(code, ROOT_NOT_ANCHORED);
                assert!(msg.contains("chain is the authority"), "{msg}");
            }
            _ => panic!("explicit root != tip must fail closed"),
        }
    }

    #[test]
    fn decide_pin_fails_closed_when_chain_unreachable() {
        match decide_pin(true, None, Err("coinset down".into())) {
            PinDecision::Reject(code, _) => assert_eq!(code, ROOT_NOT_ANCHORED),
            _ => panic!("unreachable chain must fail closed, never serve"),
        }
    }

    #[test]
    fn decide_pin_fails_closed_when_no_confirmed_generation() {
        match decide_pin(true, None, Ok(None)) {
            PinDecision::Reject(code, _) => assert_eq!(code, ROOT_NOT_ANCHORED),
            _ => panic!("no confirmed generation must fail closed"),
        }
    }

    #[test]
    fn decide_pin_is_unpinned_only_when_enforcement_is_off() {
        let other = Bytes32([0xBB; 32]);
        // Even a mismatch is allowed through when the pin is explicitly disabled.
        match decide_pin(false, Some(other), Ok(Some(Bytes32([0xAA; 32])))) {
            PinDecision::Unpinned => {}
            _ => panic!("pin off → Unpinned regardless of mismatch"),
        }
    }

    #[test]
    fn pin_enforced_is_default_on_and_off_only_for_explicit_opt_out() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        assert!(pin_enforced(), "default (unset) → ENFORCED");
        for off in ["off", "0", "false"] {
            std::env::set_var("DIG_NODE_PIN", off);
            assert!(!pin_enforced(), "DIG_NODE_PIN={off} → disabled");
        }
        std::env::set_var("DIG_NODE_PIN", "on");
        assert!(pin_enforced(), "any non-opt-out value → ENFORCED");
        std::env::remove_var("DIG_NODE_PIN");
    }

    /// A valid 32-byte retrieval key hex (so the request reaches the serve path,
    /// not a -32602 param rejection) — content is never actually served in the
    /// fail-closed tests because the pin rejects first.
    fn any_rk_hex() -> String {
        "cd".repeat(32)
    }

    /// A current-thread runtime for the env-mutating pin tests. These hold the
    /// std `ENV_GUARD` (so the process-global `DIG_NODE_PIN` is stable for the
    /// test) and must NOT hold it across an `.await` (clippy `await_holding_lock`),
    /// so they are plain `#[test]` fns driving the async dispatch via `block_on` —
    /// the same pattern the cache.* env tests use.
    fn pin_test_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn get_content_rejects_explicit_root_that_is_not_the_anchored_root() {
        // The classic #127 attack: a caller (or a compromised resolver upstream)
        // asks for a specific generation that is NOT the chain tip. The node MUST
        // refuse rather than serve the attacker-chosen generation.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([1u8; 32]);
        let tip = Bytes32([0xAA; 32]);
        let attacker_root = Bytes32([0xBB; 32]);
        let (node, _td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": attacker_root.to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));

        assert_eq!(
            resp["error"]["code"], ROOT_NOT_ANCHORED,
            "a non-anchored explicit root must fail closed: {resp}"
        );
        assert!(resp.get("result").is_none(), "no content served: {resp}");
    }

    #[test]
    fn get_content_fails_closed_when_chain_is_unreachable() {
        // The chain (the authority) cannot be reached → the node must NOT fall back
        // to serving an unverified root; it fails closed.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([2u8; 32]);
        let (node, _td) =
            test_node_with_resolver(None, MockResolver::always(Err("coinset 503".into())));

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": Bytes32([0xAA; 32]).to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));

        assert_eq!(resp["error"]["code"], ROOT_NOT_ANCHORED, "{resp}");
        assert!(resp.get("result").is_none());
    }

    #[test]
    fn get_content_rooted_read_fails_closed_when_walk_broken_and_bounded_verify_rejects_747() {
        // Regression for #747/#841 anti-rollback: when the full lineage walk is BROKEN ("parse next
        // store: missing child") the rooted pin falls back to the BOUNDED verify — which must still
        // FAIL CLOSED for a root that is not the current on-chain generation. Both the walk and the
        // bounded fallback reject here, so the read must never serve an unanchored root.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([7u8; 32]);
        let req = Bytes32([0xAA; 32]);
        let (node, _td) = test_node_with_resolver(
            None,
            // walk broken (#747) AND the bounded verify rejects the pinned root ⇒ fail closed.
            MockResolver::with_verify(
                Err("parse next store: missing child".into()),
                Err("pinned root is not the current on-chain root".into()),
            ),
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": req.to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));

        assert_eq!(
            resp["error"]["code"], ROOT_NOT_ANCHORED,
            "a broken walk + rejecting bounded verify must fail closed: {resp}"
        );
        assert!(resp.get("result").is_none(), "no content served: {resp}");
    }

    #[tokio::test]
    async fn bounded_verify_pinned_root_succeeds_when_the_lineage_walk_is_broken_747() {
        // The heart of the #747 fix: on chain a store can have an unparseable intermediate
        // generation that aborts the full lineage walk ("parse next store: missing child"), yet the
        // CURRENT pinned root is perfectly valid. The bounded verify (one launcher-hint query) must
        // still ACCEPT it — decoupled from the broken walk. `CoinsetResolver` gets this from
        // `digstore_chain::verify_pinned_root`; here the mock models the same split.
        let resolver = MockResolver::with_verify(
            Err("parse next store: missing child".into()), // the walk is broken (#747)
            Ok(()),                                        // the bounded verify still anchors it
        );
        let store = [9u8; 32];
        let pinned = Bytes32([0x11; 32]);

        // The walk aborts...
        assert!(
            resolver.anchored_root(&store).await.is_err(),
            "the lineage walk is broken in this scenario (#747)"
        );
        // ...but the bounded verify still anchors the pinned root.
        assert!(
            resolver.verify_pinned_root(&store, pinned).await.is_ok(),
            "the bounded verify must succeed despite the broken walk (#747)"
        );
    }

    #[tokio::test]
    async fn default_verify_pinned_root_falls_back_to_walk_equality() {
        // A resolver that does NOT override `verify_pinned_root` (e.g. a deterministic test mock)
        // gets the trait's DEFAULT: tip-equality via the walk. Ok only when the pinned root equals
        // the walk's tip; Err on a mismatch or no confirmed generation.
        struct WalkOnly(Option<Bytes32>);
        #[async_trait::async_trait]
        impl AnchoredRootResolver for WalkOnly {
            async fn anchored_root(&self, _: &[u8; 32]) -> Result<Option<Bytes32>, String> {
                Ok(self.0)
            }
        }
        let tip = Bytes32([0x22; 32]);
        let store = [3u8; 32];

        assert!(WalkOnly(Some(tip))
            .verify_pinned_root(&store, tip)
            .await
            .is_ok());
        assert!(WalkOnly(Some(tip))
            .verify_pinned_root(&store, Bytes32([0x33; 32]))
            .await
            .is_err());
        assert!(WalkOnly(None)
            .verify_pinned_root(&store, tip)
            .await
            .is_err());
    }

    #[test]
    fn get_content_fails_closed_when_store_has_no_confirmed_generation() {
        // A store with no confirmed on-chain generation has no anchored root to pin
        // to → fail closed (never serve a forgeable/unanchored generation).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([3u8; 32]);
        let (node, _td) = test_node_with_resolver(None, MockResolver::always(Ok(None)));

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": Bytes32([0xAA; 32]).to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));

        assert_eq!(resp["error"]["code"], ROOT_NOT_ANCHORED, "{resp}");
    }

    #[test]
    fn get_content_rejects_a_bad_store_id_before_touching_the_chain() {
        // Param validation precedes the chain read (a -32602, not a pin error).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let (node, _td) = test_node(None);
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"dig.getContent","params":{
                "store_id": "nope",
                "root": Bytes32([0xAA; 32]).to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(-32602), "{resp}");
    }

    /// Stage a real `.dig` module from `files` for `store`, returning its root and
    /// the on-disk module bytes — used to seed the local cache for a serve test.
    fn stage_real_module(
        node: &Node,
        store: &Bytes32,
        files: &[(&str, &[u8])],
    ) -> (Bytes32, Vec<u8>) {
        let src = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            let p = src.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, bytes).unwrap();
        }
        let resp = node.stage(
            &json!({"dir": src.path().display().to_string(), "store_id": store.to_hex()}),
            json!(1),
        );
        let r = &resp["result"];
        let root = Bytes32::from_hex(r["root"].as_str().expect("root")).unwrap();
        let module = std::fs::read(r["module_path"].as_str().expect("module_path")).unwrap();
        (root, module)
    }

    // -- Content cache: memoized decode + bounded LRU (audit #179 optimization) -------------------

    fn cc_resp(ciphertext_len: usize) -> Arc<ContentResponse> {
        Arc::new(ContentResponse {
            ciphertext: vec![0u8; ciphertext_len],
            merkle_proof: digstore_core::merkle::MerkleProof {
                leaf: Bytes32([0u8; 32]),
                path: vec![],
                root: Bytes32([0u8; 32]),
            },
            roothash: Bytes32([0u8; 32]),
            chunk_lens: vec![],
        })
    }

    #[test]
    fn content_cache_hit_returns_the_same_arc_without_reload() {
        let mut cache = ContentCache::default();
        let key = ("aa".repeat(32), "bb".repeat(32), [1u8; 32]);
        let resp = cc_resp(10);
        cache.insert(key.clone(), resp.clone());
        let got = cache.get(&key).expect("hit");
        assert!(
            Arc::ptr_eq(&got, &resp),
            "hit returns the cached Arc, no reload"
        );
    }

    #[test]
    fn content_cache_evicts_least_recently_used_over_the_byte_budget() {
        // A tiny cache that holds ~2 entries; the third insert must evict the LRU one.
        let mut cache = ContentCache::default();
        let a = ("a".repeat(64), "r".repeat(64), [0u8; 32]);
        let b = ("b".repeat(64), "r".repeat(64), [0u8; 32]);
        let c = ("c".repeat(64), "r".repeat(64), [0u8; 32]);
        // Each entry ~ (budget/2)+1 bytes so any two exceed the budget.
        let sz = (CONTENT_CACHE_MAX_BYTES / 2 + 1) as usize;
        cache.insert(a.clone(), cc_resp(sz));
        // Touch A so B becomes the LRU when we overflow.
        let _ = cache.get(&a);
        cache.insert(b.clone(), cc_resp(sz)); // now over budget → evicts the LRU (A was just touched, so B stays and A... )
                                              // After inserting B, total = 2*sz > budget → the LRU (A, older tick before the get bumped it?
                                              // get bumped A to a newer tick than B's pre-insert, but insert bumps tick for B). Assert the
                                              // cache never holds more than fits: only one of {A,B} survives.
        let a_present = cache.get(&a).is_some();
        let b_present = cache.get(&b).is_some();
        assert!(
            a_present ^ b_present,
            "exactly one entry fits under the byte budget"
        );
        // A third insert still keeps the invariant.
        cache.insert(c.clone(), cc_resp(sz));
        let present = [
            cache.get(&a).is_some(),
            cache.get(&b).is_some(),
            cache.get(&c).is_some(),
        ]
        .iter()
        .filter(|p| **p)
        .count();
        assert_eq!(present, 1, "the byte budget holds exactly one such entry");
    }

    #[tokio::test]
    async fn serve_local_cached_serves_a_memoized_decode_without_touching_disk() {
        // Prove the fast path: with a decoded response already in the in-memory cache and NO module
        // file on disk, serve_local_cached returns the cached decode (never reads/decrypts disk).
        let (node, _td) = test_node(None);
        let store = "5a".repeat(32);
        let root = "6b".repeat(32);
        let rk = [7u8; 32];
        // No module file exists on disk — a cold serve would miss.
        let cold = node.serve_local_cached(&store, &root, &rk).await;
        assert!(cold.is_none(), "no module on disk → cold serve misses");

        // Seed the in-memory cache directly (a prior successful decode).
        let seeded = cc_resp(42);
        node.content_cache
            .lock()
            .unwrap()
            .insert((store.clone(), root.clone(), rk), seeded.clone());

        // Now serve_local_cached returns it from RAM even though no file exists — memoized.
        let hit = node
            .serve_local_cached(&store, &root, &rk)
            .await
            .expect("memoized hit");
        assert_eq!(hit.ciphertext.len(), 42, "served the cached decode");

        // Invalidating this capsule drops the entry → serve misses again (still no file).
        node.invalidate_content_cache(&store, &root);
        let after = node.serve_local_cached(&store, &root, &rk).await;
        assert!(after.is_none(), "invalidated → no longer served from RAM");
    }

    #[tokio::test]
    async fn clear_content_cache_drops_all_entries() {
        let (node, _td) = test_node(None);
        node.content_cache
            .lock()
            .unwrap()
            .insert(("aa".repeat(32), "bb".repeat(32), [1u8; 32]), cc_resp(10));
        node.content_cache
            .lock()
            .unwrap()
            .insert(("cc".repeat(32), "dd".repeat(32), [2u8; 32]), cc_resp(20));
        node.clear_content_cache();
        let c = node.content_cache.lock().unwrap();
        assert!(c.entries.is_empty(), "all entries dropped");
        assert_eq!(c.bytes, 0, "byte accounting reset");
    }

    // -- availability_batch: single-walk snapshot + item cap (audit #179 optimization) -----------

    #[tokio::test]
    async fn availability_batch_answers_each_item_from_one_inventory_snapshot() {
        // Seed two real cached capsules, then ask a batch spanning both + a miss. Each answer must
        // reflect the shared snapshot (held vs not), proving the per-item directory walk was removed
        // without changing the per-item result. (availability_batch does not consult DIG_NODE_PIN, so
        // no ENV_GUARD is needed.)
        let (node, _td) = test_node(None);
        let store_a = Bytes32([0xa1; 32]);
        let store_b = Bytes32([0xb2; 32]);
        // Stage each module then seed it into the SERVED cache (module_path), so the inventory walk
        // sees it as held (staging alone lands the module in a scratch dir, not the served cache).
        let seed = |store: &Bytes32, files: &[(&str, &[u8])]| -> Bytes32 {
            let (root, module) = stage_real_module(&node, store, files);
            let path = module_path(&node.cache_dir, &store.to_hex(), &root.to_hex());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &module).unwrap();
            root
        };
        let root_a = seed(&store_a, &[("a.html", b"A")]);
        let root_b = seed(&store_b, &[("b.html", b"B")]);

        let items = vec![
            json!({ "store_id": store_a.to_hex(), "root": root_a.to_hex() }),
            json!({ "store_id": store_b.to_hex(), "root": root_b.to_hex() }),
            json!({ "store_id": "cc".repeat(32), "root": "dd".repeat(32) }), // a miss
        ];
        let resp = node.availability_batch(&items).await;
        let arr = resp["items"].as_array().expect("items array");
        assert_eq!(arr.len(), 3, "positionally aligned with the request");
        assert_eq!(arr[0]["available"], true, "store A root held");
        assert_eq!(arr[1]["available"], true, "store B root held");
        assert_eq!(arr[2]["available"], false, "unknown capsule is a miss");
    }

    #[tokio::test]
    async fn availability_batch_caps_the_item_count() {
        let (node, _td) = test_node(None);
        // One past the cap → the answer array is aligned to the capped prefix, not the full request.
        let items: Vec<Value> = (0..(MAX_AVAILABILITY_ITEMS + 1))
            .map(|_| json!({ "store_id": "ee".repeat(32) }))
            .collect();
        let resp = node.availability_batch(&items).await;
        assert_eq!(
            resp["items"].as_array().unwrap().len(),
            MAX_AVAILABILITY_ITEMS,
            "batch is capped at MAX_AVAILABILITY_ITEMS"
        );
    }

    // -- #1592: the availability answer MUST agree with what the node can SERVE -------------------
    //
    // `dig.getAvailability` is the gate a DHT-discovered holder must pass: dig-download's
    // `locate_and_confirm` drops every provider whose answer is not `available` BEFORE any
    // `fetchRange`. So an answer that lags the servable state is a read-killing false negative for a
    // holder that would serve the bytes (and, in the other direction, a lie that costs a round trip).
    // These tests pin the invariant at the capsule granularity that matters: the answer is derived
    // from the SAME on-disk module `serve_local_blocking` reads, never from an inventory snapshot.

    /// Seed a real compiled module into the SERVED cache (`module_path`) and return its root — the
    /// state that makes a capsule genuinely servable by [`serve_local_blocking`].
    fn seed_served_capsule(node: &Node, store: &Bytes32, files: &[(&str, &[u8])]) -> Bytes32 {
        let (root, module) = stage_real_module(node, store, files);
        let path = module_path(&node.cache_dir, &store.to_hex(), &root.to_hex());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &module).unwrap();
        root
    }

    /// **Proves:** the peer-facing `dig.fetchRange` serve refuses a capsule key that would name a file
    /// OUTSIDE `<cache>/modules/<store>/`, and refuses it without reading that file (#1599).
    ///
    /// **Catches:** removing the key validation from the serve chokepoint. The fixture is built so the
    /// escape is OBSERVABLE rather than merely attempted: the only copy of a real, decodable module is
    /// planted outside the modules tree, and the traversal is in the ROOT component. That matters —
    /// the blind serve derives its decode key from the STORE id alone and never consults the root, so
    /// with the store id left canonical the escaped file decodes and STREAMS. Unguarded, this call
    /// returns served bytes; guarded, it cannot.
    ///
    /// The `serves_the_same_module_from_its_legitimate_path` control below is half of this proof: it
    /// shows the fixture can express a SUCCESSFUL serve, so the `Err` asserted here is the guard's doing
    /// and not some unrelated failure the fixture would have produced anyway.
    #[tokio::test]
    async fn fetch_range_refuses_a_capsule_key_that_escapes_the_modules_directory() {
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc3; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"secret bytes")]);
        let rk = content_serve::derive_retrieval_key(&store, "index.html").0;

        // Move the ONLY copy of the module outside the modules tree, and point a traversal at it. A
        // pass therefore cannot come from the legitimate file: it no longer exists.
        let legitimate = module_path(&node.cache_dir, &store.to_hex(), &root.to_hex());
        let escaped = node
            .cache_dir
            .join("outside")
            .join(format!("{}.module", root.to_hex()));
        std::fs::create_dir_all(escaped.parent().unwrap()).unwrap();
        std::fs::rename(&legitimate, &escaped).unwrap();

        // Both traversal grammars a platform might honour, each pointed at the SAME planted module, so
        // the guard is pinned against the CLASS of separator rather than against one spelling of it.
        for hostile_root in [
            format!("../../outside/{}", root.to_hex()),
            format!("..\\..\\outside\\{}", root.to_hex()),
        ] {
            // Precondition: this traversal really does resolve to the planted module. Without it the
            // test would assert a refusal of a path that named nothing — which every implementation,
            // guarded or not, passes.
            let would_reach = node
                .cache_dir
                .join("modules")
                .join(store.to_hex())
                .join(format!("{hostile_root}.module"));
            let Ok(reached) = std::fs::canonicalize(&would_reach) else {
                // This platform does not honour this separator, so the traversal cannot name the module
                // here and the case proves nothing on it. Skipping is honest; asserting would be a
                // false green.
                continue;
            };
            assert_eq!(
                reached,
                std::fs::canonicalize(&escaped).unwrap(),
                "the fixture's traversal must name the planted module, or it proves nothing"
            );

            let served = node
                .fetch_range_frame(&store.to_hex(), &hostile_root, &hex::encode(rk), 0, 4096)
                .await;
            assert!(
                served.is_err(),
                "a key escaping <cache>/modules/<store>/ must never be served ({hostile_root}): {served:?}"
            );
            assert_eq!(
                served.unwrap_err().0,
                -32004,
                "the refusal is the ordinary not-held answer, so a peer learns nothing about the path"
            );
        }
    }

    /// The control for the escape test above: with the SAME module at its LEGITIMATE path and a
    /// canonical key, the same call serves bytes. Without this, an `Err` in that test could mean the
    /// fixture was simply unservable.
    #[tokio::test]
    async fn fetch_range_serves_the_same_module_from_its_legitimate_path() {
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc3; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"secret bytes")]);
        let rk = content_serve::derive_retrieval_key(&store, "index.html").0;

        let frame = node
            .fetch_range_frame(&store.to_hex(), &root.to_hex(), &hex::encode(rk), 0, 4096)
            .await
            .expect("the capsule at its canonical path is servable");
        assert!(
            frame["length"].as_u64().unwrap_or(0) > 0,
            "the control must actually serve bytes: {frame}"
        );
    }

    /// **Proves:** no non-canonical key in the class is ever SERVED, in either component — absolute
    /// paths, UNC roots, wrong length, wrong alphabet, control characters (#1599).
    ///
    /// **Catches:** a guard narrowed to `..`-rejection that then serves an absolute or UNC key.
    ///
    /// **Does NOT on its own pin the path guard**, and is documented as such deliberately: most shapes
    /// here name no existing file, so they refuse whether or not the guard is present (verified — this
    /// test stays green with the guard reverted). The load-bearing proof is
    /// `fetch_range_refuses_a_capsule_key_that_escapes_the_modules_directory`, whose fixture plants a
    /// real decodable module at the escape target so an unguarded serve SUCCEEDS. This test's job is
    /// breadth of the rejected alphabet, not depth on the escape.
    #[tokio::test]
    async fn fetch_range_refuses_every_non_canonical_capsule_key() {
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc3; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hello")]);
        let (store_hex, root_hex) = (store.to_hex(), root.to_hex());
        let rk = hex::encode(content_serve::derive_retrieval_key(&store, "index.html").0);

        let hostile = [
            "..".to_string(),
            format!("../../{root_hex}"),
            format!("..\\..\\{root_hex}"),
            format!("/etc/{root_hex}"),
            format!("C:\\Windows\\{root_hex}"),
            format!("\\\\host\\share\\{root_hex}"),
            format!("{root_hex}\ninjected"),
            root_hex[..63].to_string(),
            format!("{root_hex}a"),
            String::new(),
            "z".repeat(64),
        ];
        for bad in hostile {
            for (s, r) in [
                (store_hex.as_str(), bad.as_str()),
                (bad.as_str(), root_hex.as_str()),
            ] {
                let served = node.fetch_range_frame(s, r, &rk, 0, 4096).await;
                assert!(
                    served.is_err(),
                    "non-canonical key ({:?}, {:?}) must be refused",
                    &s[..s.len().min(40)],
                    &r[..r.len().min(40)]
                );
            }
        }
        // And the canonical key still works after all of that — the guard rejects, it does not wedge.
        assert!(node
            .fetch_range_frame(&store_hex, &root_hex, &rk, 0, 4096)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn availability_answer_reports_a_capsule_that_landed_after_the_inventory_snapshot() {
        // REGRESSION (#1592): a capsule that lands AFTER the batch took its inventory snapshot — a
        // gap-fill / §21 sync / fetch-through / pin write concurrent with the peer-facing walk — is
        // immediately servable, so it MUST be reported available. Answering from the snapshot made
        // this a false negative that dropped the holder before any fetchRange.
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc3; 32]);

        // The snapshot the batch would have taken BEFORE the capsule landed.
        let stale_snapshot = node.cache_list_cached().await;
        assert!(stale_snapshot.is_empty(), "nothing held at snapshot time");

        // The capsule lands (post-snapshot) and is genuinely servable.
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hello")]);
        let rk = content_serve::derive_retrieval_key(&store, "index.html").0;
        assert!(
            node.serve_local_cached(&store.to_hex(), &root.to_hex(), &rk)
                .await
                .is_some(),
            "precondition: the landed capsule is servable on disk"
        );

        let item = json!({
            "store_id": store.to_hex(),
            "root": root.to_hex(),
            "retrieval_key": hex::encode(rk),
        });
        let answer = node.availability_answer(&item, &stale_snapshot).await;
        assert_eq!(
            answer["available"], true,
            "a servable capsule must be reported available even if the snapshot predates it"
        );
        assert!(
            answer.get("total_length").is_some(),
            "the resource totals come from the same served module the answer agrees with"
        );
    }

    #[tokio::test]
    async fn availability_answer_reports_not_available_when_the_snapshot_lags_an_eviction() {
        // The OTHER direction (#1592): a snapshot that still lists a capsule the node no longer has
        // on disk must NOT make the node claim availability it cannot serve.
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc4; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hello")]);

        // Snapshot while held, then evict — the snapshot is now stale in the "claims held" direction.
        let stale_snapshot = node.cache_list_cached().await;
        assert_eq!(stale_snapshot.len(), 1, "held at snapshot time");
        assert!(
            node.cache_remove_cached(&store.to_hex(), &root.to_hex())
                .await
                .unwrap(),
            "capsule evicted"
        );

        let item = json!({ "store_id": store.to_hex(), "root": root.to_hex() });
        let answer = node.availability_answer(&item, &stale_snapshot).await;
        assert_eq!(
            answer["available"], false,
            "an evicted capsule must not be reported available"
        );
    }

    #[tokio::test]
    async fn availability_batch_reports_a_capsule_landed_at_runtime_and_stops_after_eviction() {
        // The public peer-facing path: land a capsule at runtime → available; evict it → not
        // available; a capsule never held → not available.
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc5; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hi")]);
        let item = json!({ "store_id": store.to_hex(), "root": root.to_hex() });
        let never_held = json!({ "store_id": "ab".repeat(32), "root": "cd".repeat(32) });

        let resp = node
            .availability_batch(&[item.clone(), never_held.clone()])
            .await;
        assert_eq!(resp["items"][0]["available"], true, "landed → available");
        assert_eq!(
            resp["items"][1]["available"], false,
            "never held → not available"
        );

        node.cache_remove_cached(&store.to_hex(), &root.to_hex())
            .await
            .unwrap();
        let resp = node.availability_batch(&[item]).await;
        assert_eq!(
            resp["items"][0]["available"], false,
            "evicted → no longer available"
        );
    }

    #[tokio::test]
    async fn availability_batch_rejects_a_non_canonical_key_without_touching_the_filesystem() {
        // The keys are PEER-supplied and now feed a path (`module_exists`), so a non-64-hex key must
        // answer not-available via the canonical-key guard — never escape `<cache>/modules`.
        let (node, td) = test_node(None);
        let store = Bytes32([0xc6; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hi")]);
        // A real file ONE LEVEL ABOVE `<cache>/modules/` — `module_path` joins
        // `<cache>/modules/<store_id>/<root>.module`, so a `..` in EITHER `store_id` or `root`
        // collapses that join back to exactly this file (verified: `store_id=".."` cancels the
        // `modules` segment; `store_id="."` + a leading `../` in `root` does the same one level
        // later). Without the canonical-key guard, either traversal below would stat this file and
        // answer `available:true`.
        let outside = td.path().join("secret.module");
        std::fs::write(&outside, b"not a capsule").unwrap();

        let traversal_via_store = json!({ "store_id": "..", "root": "secret" });
        let traversal_via_root = json!({ "store_id": ".", "root": "../secret" });
        let resp = node
            .availability_batch(&[
                traversal_via_store,
                traversal_via_root,
                json!({ "store_id": "zz".repeat(32) }),
            ])
            .await;
        assert_eq!(
            resp["items"][0]["available"], false,
            "a `store_id=\"..\"` traversal is never available"
        );
        assert_eq!(
            resp["items"][1]["available"], false,
            "a `root=\"../secret\"` traversal is never available"
        );
        assert_eq!(
            resp["items"][2]["available"], false,
            "a non-hex store id holds nothing"
        );
        // The genuine capsule still answers correctly beside the rejected keys.
        let ok = node
            .availability_batch(&[json!({ "store_id": store.to_hex(), "root": root.to_hex() })])
            .await;
        assert_eq!(ok["items"][0]["available"], true);
    }

    #[tokio::test]
    async fn availability_batch_null_root_still_takes_the_inventory_snapshot() {
        // REGRESSION: `availability_batch`'s `needs_inventory` gate and `availability_answer`'s
        // granularity switch both key off `root`, and MUST agree on what counts as "absent" — an
        // item shaped `{ "root": null }` (or any non-string root) has `Value::get("root")` return
        // `Some(Value::Null)`, so a predicate that only checks `.is_none()` misses it and skips the
        // inventory snapshot, while `availability_answer` still treats it as STORE granularity (its
        // `and_then(Value::as_str)` collapses null to `None`). The result was a false
        // `available:false, roots:[]` for a store the node genuinely holds.
        let (node, _td) = test_node(None);
        let store = Bytes32([0xc7; 32]);
        let root = seed_served_capsule(&node, &store, &[("index.html", b"hi")]);

        let null_root = json!({ "store_id": store.to_hex(), "root": Value::Null });
        let resp = node.availability_batch(&[null_root]).await;
        assert_eq!(
            resp["items"][0]["available"], true,
            "a null root asks store granularity, not a specific (missing) root"
        );
        assert_eq!(
            resp["items"][0]["roots"].as_array().unwrap(),
            &[json!(root.to_hex())],
            "the held root is enumerated once the snapshot the store answer needs is actually taken"
        );

        let numeric_root = json!({ "store_id": store.to_hex(), "root": 1 });
        let resp = node.availability_batch(&[numeric_root]).await;
        assert_eq!(
            resp["items"][0]["available"], true,
            "a non-string root is likewise store granularity, not a servable-root miss"
        );
    }

    // -- launcher_ids cap (audit #179 HIGH — peer-triggered unbounded chain fanout) ---------------

    #[test]
    fn parse_launcher_ids_accepts_a_reasonable_array() {
        let ids: Vec<String> = (0..3).map(|_| "ab".repeat(32)).collect();
        let params = json!({ "launcher_ids": ids });
        let out = Node::parse_launcher_ids(&params).expect("within cap");
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn parse_launcher_ids_rejects_an_over_cap_array_before_any_chain_read() {
        // One past the cap → rejected at parse time (no chain resolution attempted).
        let ids: Vec<String> = (0..(MAX_LAUNCHER_IDS + 1))
            .map(|_| "ab".repeat(32))
            .collect();
        let params = json!({ "launcher_ids": ids });
        let err = Node::parse_launcher_ids(&params).expect_err("must reject over-cap");
        assert!(err.contains("too many launcher_ids"), "got: {err}");
    }

    #[tokio::test]
    async fn get_collection_rejects_an_over_cap_launcher_array() {
        let ids: Vec<String> = (0..(MAX_LAUNCHER_IDS + 1))
            .map(|_| "ab".repeat(32))
            .collect();
        let resp = Node::get_collection(&json!({ "launcher_ids": ids }), json!(1)).await;
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    #[tokio::test]
    async fn list_collection_items_rejects_an_over_cap_launcher_array() {
        let ids: Vec<String> = (0..(MAX_LAUNCHER_IDS + 1))
            .map(|_| "ab".repeat(32))
            .collect();
        let resp = Node::list_collection_items(&json!({ "launcher_ids": ids }), json!(1)).await;
        assert_eq!(resp["error"]["code"], json!(-32602));
    }

    // -- walk_dir_files bounds (audit #179 HIGH — dig.stage memory exhaustion) --------------------

    #[test]
    fn walk_dir_files_reads_a_small_tree_within_bounds() {
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join("a.txt"), b"aaa").unwrap();
        std::fs::create_dir(td.path().join("sub")).unwrap();
        std::fs::write(td.path().join("sub").join("b.txt"), b"bb").unwrap();
        let files = walk_dir_files_bounded(td.path(), 1024, 100, 16).expect("within bounds");
        // Deterministic key order, forward-slashed relative keys.
        let keys: Vec<&str> = files.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["a.txt", "sub/b.txt"]);
    }

    #[test]
    fn walk_dir_files_aborts_when_total_bytes_exceed_the_budget() {
        // Two 100-byte files with a 150-byte budget: the SECOND file pushes past the cap and
        // the walk aborts instead of buffering both — a proxy for an attacker-chosen huge tree.
        let td = tempfile::tempdir().unwrap();
        std::fs::write(td.path().join("a.bin"), vec![0u8; 100]).unwrap();
        std::fs::write(td.path().join("b.bin"), vec![0u8; 100]).unwrap();
        let err = walk_dir_files_bounded(td.path(), 150, 100, 16).expect_err("must abort");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn walk_dir_files_aborts_when_file_count_exceeds_the_cap() {
        let td = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(td.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        // Cap of 2 files → the third file aborts the walk.
        let err = walk_dir_files_bounded(td.path(), 1 << 20, 2, 16).expect_err("must abort");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn walk_dir_files_aborts_when_recursion_exceeds_the_depth_cap() {
        // Build a chain of nested dirs deeper than the cap; the walk aborts before reading.
        let td = tempfile::tempdir().unwrap();
        let mut p = td.path().to_path_buf();
        for i in 0..5 {
            p = p.join(format!("d{i}"));
            std::fs::create_dir(&p).unwrap();
        }
        std::fs::write(p.join("deep.txt"), b"z").unwrap();
        let err = walk_dir_files_bounded(td.path(), 1 << 20, 100, 2).expect_err("must abort");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn get_content_does_not_serve_a_cached_stale_generation_as_current() {
        // Defense in depth: a module for an OLD generation (root R) is in the local
        // cache, but the chain tip has advanced to R'. A read pinned to R' must NOT
        // serve the cached R module — the cache key is the anchored root, so the
        // stale module is simply not found at R', and the read does not return it.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        // Upstream is unroutable (test_node default) → after the local miss the read
        // falls through to a proxy attempt that errors out (no fabricated content).
        let store = Bytes32([7u8; 32]);
        let advanced_tip = Bytes32([0x99; 32]); // R' — what the chain says is current
        let (node, _td) =
            test_node_with_resolver(None, MockResolver::one(&store.to_hex(), advanced_tip));

        // Seed a real cached module at its REAL (old) root R != R'.
        let (old_root, module) =
            stage_real_module(&node, &store, &[("index.html", b"<h1>old</h1>")]);
        assert_ne!(old_root, advanced_tip, "the cached generation is stale");
        let seeded = module_path(&node.cache_dir, &store.to_hex(), &old_root.to_hex());
        std::fs::create_dir_all(seeded.parent().unwrap()).unwrap();
        std::fs::write(&seeded, &module).unwrap();

        // Request the (advanced) tip generation. The pin serves at R'; the stale R
        // module is at a different cache key, so serve_local misses and the node
        // never returns the old generation's content. With no upstream it errors —
        // crucially NOT a success carrying the stale module.
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":5,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": advanced_tip.to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        // It must not have served the stale cached module as the current generation.
        let served_local = resp["result"]["source"].as_str() == Some("local");
        assert!(
            !served_local,
            "a stale cached generation must never be served as the anchored tip: {resp}"
        );
    }

    #[test]
    fn get_content_unpinned_mode_serves_the_requested_root_as_before() {
        // With the pin explicitly disabled (offline/local dev), the node serves the
        // requested root as-is (legacy behavior) — the resolver is never consulted.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_PIN", "off");
        let rt = pin_test_rt();
        let store = Bytes32([8u8; 32]);
        // A resolver that would FAIL if consulted — proving the unpinned path skips it.
        let (node, _td) =
            test_node_with_resolver(None, MockResolver::always(Err("must not be called".into())));

        // No module cached, unroutable upstream → the call reaches the proxy and
        // errors, but crucially it is an UPSTREAM error (-32000), NOT a pin rejection.
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":6,"method":"dig.getContent","params":{
                "store_id": store.to_hex(),
                "root": Bytes32([0xAA; 32]).to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        std::env::remove_var("DIG_NODE_PIN");
        assert_ne!(
            resp["error"]["code"], ROOT_NOT_ANCHORED,
            "pin off → no pin rejection: {resp}"
        );
    }

    #[test]
    fn pin_request_root_forces_params_root() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent",
            "params":{"store_id":"aa","root":"old","retrieval_key":"rk"}});
        let pinned = pin_request_root(&req, "newroot");
        assert_eq!(pinned["params"]["root"], json!("newroot"));
        // Other params are preserved.
        assert_eq!(pinned["params"]["store_id"], json!("aa"));
        assert_eq!(pinned["params"]["retrieval_key"], json!("rk"));
    }

    // -- #1577 per-range verification metadata on EVERY fetchRange frame ---------------------------
    //
    // The chain-anchored generation tree commits RESOURCES, not chunks
    // (`digstore_core::merkle::resource_leaf` = SHA-256 of the WHOLE resource ciphertext, folded by
    // `MerkleTree::from_leaves`), so no proof can bind a single chunk to the root — see the
    // `range_frame` module header. What a frame CAN carry, and what these tests pin, is its own
    // complete verification metadata: the generation `root`, `chunk_lens`, `total_length`, the
    // whole-resource `inclusion_proof`, and the TRUE chunk index the frame starts at — on every
    // frame, so a range fetched from any peer at any offset is checkable on arrival.
    //
    // Every assertion here runs the REAL client verifier (dig-download's `MerkleVerifier` over the
    // node's own `DigstoreProofVerifier`), never a hand-rolled re-implementation of the check.

    // The client-side range/resource checks these tests drive live on this trait.
    use dig_download::Verifier as _;

    use test_support::{multi_chunk_served_resource, seed_served_resource};

    /// The real client verifier: dig-download's `MerkleVerifier` bound to the node's
    /// `DigstoreProofVerifier`, i.e. exactly what a downloading peer checks a served frame with.
    fn real_client_verifier() -> impl dig_download::Verifier {
        dig_download::MerkleVerifier::with_proof_verifier(Arc::new(
            crate::download::DigstoreProofVerifier,
        ))
    }

    /// Build the client's `ResourceCommitment` from ONE served frame's metadata — the whole point of
    /// #1577: any frame, not just the first, must be able to establish the commitment.
    fn commitment_from_frame(frame: &Value) -> dig_download::ResourceCommitment {
        dig_download::ResourceCommitment::from_first_frame(
            frame["total_length"].as_u64().expect("total_length served"),
            frame["chunk_lens"]
                .as_array()
                .expect("chunk_lens served")
                .iter()
                .map(|l| l.as_u64().unwrap())
                .collect(),
            frame["root"].as_str().map(str::to_string),
            frame["inclusion_proof"].as_str().map(str::to_string),
        )
        .expect("the served metadata is self-consistent")
    }

    fn frame_bytes(frame: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(frame["bytes"].as_str().expect("bytes served"))
            .expect("base64 window")
    }

    #[tokio::test]
    async fn a_mid_resource_frame_carries_metadata_the_real_client_verifier_accepts() {
        // The #1577 gap: metadata used to ride the `offset == 0` frame ONLY, so a peer serving a
        // mid-resource range declared no root and the client had nothing to check it against. Now the
        // frame for chunk 1 alone is a self-describing, verifiable unit.
        let (node, _td) = test_node(None);
        let (resource, chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource.clone());

        let (offset, length) = (chunk_lens[0] as usize, chunk_lens[1] as usize);
        let frame = node
            .fetch_range_frame(&store, &root, &rk, offset, length)
            .await
            .expect("chunk 1 is servable");

        assert_eq!(frame["root"], json!(root), "every frame declares its root");
        assert_eq!(frame["chunk_lens"], json!(chunk_lens));
        assert_eq!(frame["total_length"], json!(resource.ciphertext.len()));
        assert!(
            frame["inclusion_proof"].is_string(),
            "the whole-resource proof rides every frame: {frame}"
        );
        assert_eq!(
            frame["first_chunk_index"],
            json!(1),
            "the TRUE first chunk index of the served span, not a hardcoded 0: {frame}"
        );
        assert_eq!(
            frame["chunk_index"], frame["first_chunk_index"],
            "the legacy `chunk_index` field agrees (§5.1: same meaning, now truthful)"
        );

        // The REAL client verifier accepts this frame as a verifiable range.
        let commitment = commitment_from_frame(&frame);
        real_client_verifier()
            .verify_range(
                &commitment,
                frame["first_chunk_index"].as_u64().unwrap(),
                length as u64,
                &frame_bytes(&frame),
            )
            .expect("the real verifier accepts the served range");
    }

    #[tokio::test]
    async fn the_served_proof_binds_the_assembled_resource_to_the_generation_root() {
        // End-to-end on the serve side: stream every frame, assemble, and let the REAL verifier bind
        // the result to the chain-anchored root through the proof the node served.
        let (node, _td) = test_node(None);
        let (resource, chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource.clone());

        let mut assembled = Vec::new();
        let mut commitment = None;
        for (index, &len) in chunk_lens.iter().enumerate() {
            let frame = node
                .fetch_range_frame(&store, &root, &rk, assembled.len(), len as usize)
                .await
                .expect("each chunk-aligned span is servable");
            assert_eq!(frame["first_chunk_index"], json!(index as u64));
            commitment.get_or_insert_with(|| commitment_from_frame(&frame));
            assembled.extend(frame_bytes(&frame));
        }

        let commitment = commitment.expect("at least one frame");
        real_client_verifier()
            .verify_resource(&commitment, &assembled)
            .expect("the served proof binds the assembled bytes to the generation root");
        assert_eq!(assembled, resource.ciphertext);
    }

    #[tokio::test]
    async fn a_tampered_range_fails_closed_against_the_served_proof() {
        // Fail-closed: the served proof must REJECT bytes that are not the committed resource. A
        // proof that accepted tampered content would be worse than no proof at all.
        let (node, _td) = test_node(None);
        let (resource, _chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource.clone());

        let frame = node
            .fetch_range_frame(&store, &root, &rk, 0, resource.ciphertext.len())
            .await
            .expect("the whole resource is servable in one frame");
        let commitment = commitment_from_frame(&frame);
        let verifier = real_client_verifier();

        let mut tampered = frame_bytes(&frame);
        tampered[0] ^= 0xff;
        assert!(
            verifier.verify_resource(&commitment, &tampered).is_err(),
            "a flipped byte must fail the served inclusion proof"
        );

        // …and a frame whose proof is stripped cannot be verified either (half-specified binding).
        let unproven = dig_download::ResourceCommitment::from_first_frame(
            commitment.total_length,
            commitment.layout.chunk_lens().to_vec(),
            commitment.root.clone(),
            None,
        )
        .expect("self-consistent metadata");
        assert!(
            verifier
                .verify_resource(&unproven, &frame_bytes(&frame))
                .is_err(),
            "a root with no proof to check it against must fail closed"
        );
    }

    #[tokio::test]
    async fn a_wrong_generation_mid_resource_frame_is_now_detectable() {
        // The integrity win of serving metadata on every frame: a peer serving a mid-resource range
        // from a DIFFERENT generation declares that root, so the client's consistency check catches
        // it on arrival. Before #1577 such a frame declared nothing and passed unchallenged.
        let (node, _td) = test_node(None);
        let (resource, chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource.clone());

        let frame = node
            .fetch_range_frame(&store, &root, &rk, chunk_lens[0] as usize, 1)
            .await
            .expect("servable");
        let committed_to_another_generation = dig_download::ResourceCommitment::from_first_frame(
            resource.ciphertext.len() as u64,
            chunk_lens.clone(),
            Some("ab".repeat(32)),
            None,
        )
        .expect("self-consistent metadata");

        let err = committed_to_another_generation.check_consistent(
            frame["total_length"].as_u64(),
            frame["chunk_lens"].as_array().map(|_| &chunk_lens[..]),
            frame["root"].as_str(),
        );
        assert!(
            err.is_err(),
            "a mid-resource frame declaring a different root is rejected: {frame}"
        );
    }

    #[tokio::test]
    async fn an_unaligned_offset_asserts_no_chunk_index_rather_than_a_false_one() {
        // A frame starting mid-chunk is not a chunk-aligned verifiable unit, so the node reports NO
        // chunk index rather than a wrong one — the client must never be handed an alignment claim
        // that its own `verify_range` would then contradict.
        let (node, _td) = test_node(None);
        let (resource, _chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource);

        let frame = node
            .fetch_range_frame(&store, &root, &rk, 7, 4)
            .await
            .expect("servable");
        assert!(frame.get("first_chunk_index").is_none(), "{frame}");
        assert!(frame.get("chunk_index").is_none(), "{frame}");
        assert!(
            frame["root"].is_string(),
            "the generation binding still rides an unaligned frame: {frame}"
        );
    }

    #[tokio::test]
    async fn the_frame_data_fields_are_unchanged_for_a_client_that_ignores_the_new_metadata() {
        // §5.1 additive: a pre-#1577 client reads only offset/length/bytes/complete. Those must be
        // byte-identical to what v0.58.10 served — the clip contract dig-download 0.7.4 verifies
        // against (`verify_range` fails closed on any length that is not the PLANNED one).
        let (node, _td) = test_node(None);
        let (resource, chunk_lens) = multi_chunk_served_resource();
        let (store, root, rk) = seed_served_resource(&node, resource.clone());

        let requested = chunk_lens[1] as usize;
        let frame = node
            .fetch_range_frame(&store, &root, &rk, chunk_lens[0] as usize, requested)
            .await
            .expect("servable");
        assert_eq!(frame["offset"], json!(chunk_lens[0]));
        assert_eq!(
            frame["length"],
            json!(requested),
            "the served span is exactly what was asked for — never widened to a chunk boundary"
        );
        assert_eq!(frame["complete"], json!(false));
        assert_eq!(
            frame_bytes(&frame),
            resource.ciphertext[chunk_lens[0] as usize..][..requested],
            "the window bytes are unchanged"
        );
    }

    // -- #126 honest read-path: real inclusion proof + chain root, NO mock proof --
    //
    // The dig-node read path must never present a forgeable/mock proof AS verified.
    // On `dig.getContent` the trust-bearing fields are REAL — the guest-computed
    // merkle inclusion proof + the chain-anchored root (#127) — and there is no
    // execution attestation on the wire to fake: `ContentResponse`/`build_result`
    // carry no execution-proof field, and the node does not implement
    // `dig.getProof` (it returns -32601 rather than a fabricated mock receipt). A
    // real, verified execution attestation is gated on the RISC0 toolchain
    // (SECURITY.md residual #3) and is honestly absent here, never faked.

    #[test]
    fn get_content_result_carries_real_inclusion_proof_and_no_execution_proof() {
        use digstore_core::wire::ContentResponse;
        // A minimal real ContentResponse: a single-leaf merkle proof rooted at a
        // concrete root (the shape the guest serves). build_result renders it.
        let root = Bytes32([0x42; 32]);
        let resp = ContentResponse {
            ciphertext: vec![1, 2, 3, 4],
            merkle_proof: digstore_core::merkle::MerkleProof {
                leaf: root,
                path: Vec::new(),
                root,
            },
            roothash: root,
            chunk_lens: vec![4],
        };
        let result = build_result(&resp, 0);

        // The REAL inclusion proof + chain-verifiable root are present.
        assert!(
            result.get("inclusion_proof").is_some(),
            "real merkle inclusion proof is on the wire: {result}"
        );
        assert_eq!(
            result["root"].as_str(),
            Some(root.to_hex().as_str()),
            "the served root is reported (chain-pinned by #127): {result}"
        );
        // NO execution-attestation field is fabricated — the node never reports a
        // mock/absent execution proof AS a verified attestation (#126/#134).
        for forbidden in [
            "execution_proof",
            "execution_proof_status",
            "attestation",
            "proof_status",
            "receipt",
            "trusted",
        ] {
            assert!(
                result.get(forbidden).is_none(),
                "dig.getContent must not carry a (mock) `{forbidden}` field: {result}"
            );
        }
    }

    #[test]
    fn get_proof_is_not_served_as_a_verified_proof_by_the_node() {
        // dig-node does not implement dig.getProof — it returns the catalogued
        // -32601 (method not found) rather than fabricating a mock execution
        // proof. (The standalone node has no upstream here, so the dispatch's own
        // method-not-found is observed directly.)
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let (node, _td) = test_node(None);
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.getProof","params":{
                "store_id": Bytes32([1u8; 32]).to_hex(),
                "retrieval_key": any_rk_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(
            resp["error"]["code"],
            json!(-32601),
            "dig.getProof must be method-not-found on the node, never a fabricated proof: {resp}"
        );
        assert!(
            resp.get("result").is_none(),
            "no proof result is fabricated: {resp}"
        );
    }

    #[test]
    fn passthrough_alias_methods_are_method_not_found_on_the_node() {
        // The node resolves dig.getContent locally but does NOT resolve the passthrough
        // aliases dig.getCapsule / dig.listCapsules — it returns the catalogued -32601
        // (method not found), which is the shell's cue to relay the ORIGINAL request
        // verbatim to the upstream (SPEC §5.4/§5.5). This pins that classification at
        // the dispatch level so a future read-path change that starts resolving one of
        // them locally (and would therefore need its catalogue entry flipped to
        // served=local) is caught here, mirroring the dig.getProof guard.
        //
        // dig.getManifest is EXCLUDED from this list as of #176 Phase C: it moved from
        // passthrough to served=local (see the dig_get_manifest_* tests below and the
        // updated catalogue in dig-node-service's meta.rs).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let (node, _td) = test_node(None);
        let store_id = Bytes32([1u8; 32]).to_hex();
        // Representative params per method; the node must still report method-not-found.
        let cases = [
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getCapsule","params":{
                "store_id": store_id, "retrieval_key": any_rk_hex(),
            }}),
            json!({"jsonrpc":"2.0","id":2,"method":"dig.listCapsules","params":{
                "store_id": store_id,
            }}),
        ];
        for req in cases {
            let method = req["method"].as_str().unwrap().to_string();
            let resp = rt.block_on(handle_rpc(
                &node,
                req,
                crate::download::ReadOrigin::Local,
                crate::download::RequestProvenance::FirstParty,
            ));
            assert_eq!(
                resp["error"]["code"],
                json!(-32601),
                "{method} must be method-not-found on the node (the passthrough cue): {resp}"
            );
            assert!(
                resp.get("result").is_none(),
                "{method} must not be resolved locally by the node: {resp}"
            );
        }
    }

    /// Build a real compiled `.dig` module (via the SAME `digstore_stage::stage_and_compile`
    /// engine `Node::stage`/the CLI use) so `dig.getManifest` tests exercise the real
    /// data-section extraction + decode, not a mock. Returns `(root, module_bytes)`.
    fn compile_fixture_module(
        store_id: Bytes32,
        visibility: digstore_core::Visibility,
        include_public_manifest: bool,
        files: &[(String, Vec<u8>)],
    ) -> (Bytes32, Vec<u8>) {
        let scratch = tempfile::tempdir().unwrap();
        let secret = digstore_crypto::bls::SecretKey::from_seed(&[42u8; 32]);
        let pubkey = secret.public_key().to_bytes();
        let opts = digstore_stage::FinalizeOptions {
            data_dir: scratch.path().to_path_buf(),
            trusted_keys: vec![digstore_core::TrustedHostKey {
                public_key: pubkey.0,
                label: "test-fixture".to_string(),
            }],
            store_pubkey: pubkey,
            metadata: digstore_stage::empty_manifest(),
            chain_state: None,
            auth: digstore_stage::no_auth(),
            include_public_manifest,
        };
        let compiled = digstore_stage::stage_and_compile(
            files,
            store_id,
            &visibility,
            digstore_core::MAX_STORE_BYTES,
            false,
            0,
            0,
            &opts,
        )
        .expect("stage + compile a fixture module");
        let bytes = std::fs::read(&compiled.module_path).expect("read compiled module bytes");
        (compiled.root, bytes)
    }

    /// Write `module_bytes` into the node's canonical on-disk cache location for
    /// `(store_hex, root_hex)`, so `dig.getManifest` (and any other local-cache-hit
    /// method) finds it via [`module_path`].
    fn seed_cached_module(cache_dir: &Path, store_hex: &str, root_hex: &str, module_bytes: &[u8]) {
        let path = module_path(cache_dir, store_hex, root_hex);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, module_bytes).unwrap();
    }

    #[tokio::test]
    async fn dig_get_manifest_returns_embedded_manifest_json_when_present() {
        // A PUBLIC store's compiled module embeds the PublicManifest section (#176 Phase A);
        // dig.getManifest (Phase C) reads it back and returns the exact JSON shape.
        let (node, _td) = test_node(None);
        let store_id = Bytes32([9u8; 32]);
        let files = vec![
            ("index.html".to_string(), b"<h1>hi</h1>".to_vec()),
            ("assets/app.js".to_string(), b"console.log(1)".to_vec()),
        ];
        let (root, module_bytes) =
            compile_fixture_module(store_id, digstore_core::Visibility::Public, true, &files);
        seed_cached_module(
            &node.cache_dir,
            &store_id.to_hex(),
            &root.to_hex(),
            &module_bytes,
        );

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getManifest","params":{
                "store_id": store_id.to_hex(), "root": root.to_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert!(resp.get("error").is_none(), "unexpected error: {resp}");
        let result = &resp["result"];
        assert_eq!(result["schema_version"], json!(1));
        let entries = result["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 2);
        let paths: Vec<&str> = entries
            .iter()
            .map(|e| e["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["assets/app.js", "index.html"]);
        for e in entries {
            assert_eq!(e["latest_root"], json!(root.to_hex()));
            assert_eq!(e["generation_index"], json!(0));
            assert_eq!(e["version_count"], json!(1));
            assert!(e["sha256_latest"].as_str().unwrap().len() == 64);
        }
    }

    #[tokio::test]
    async fn dig_get_manifest_returns_null_when_section_absent() {
        // A PRIVATE store's compiled module carries NO PublicManifest section (its paths must
        // stay opaque). dig.getManifest MUST tolerate the absence: `result: null`, never an
        // error — store-format §5.1, an optional section's absence is normal + backwards
        // compatible (an older `.dig` hits this same path).
        let (node, _td) = test_node(None);
        let store_id = Bytes32([10u8; 32]);
        let files = vec![("secret.txt".to_string(), b"top secret".to_vec())];
        let (root, module_bytes) = compile_fixture_module(
            store_id,
            digstore_core::Visibility::Private(digstore_core::SecretSalt([1u8; 32])),
            false,
            &files,
        );
        seed_cached_module(
            &node.cache_dir,
            &store_id.to_hex(),
            &root.to_hex(),
            &module_bytes,
        );

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getManifest","params":{
                "store_id": store_id.to_hex(), "root": root.to_hex(),
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert!(
            resp.get("error").is_none(),
            "absence of a PublicManifest section must NEVER be an error: {resp}"
        );
        assert_eq!(
            resp["result"],
            Value::Null,
            "absent manifest -> null result: {resp}"
        );
    }

    #[tokio::test]
    async fn dig_get_manifest_reports_unavailable_when_capsule_not_held() {
        // The node holds nothing for this (store, root) at all — a genuine cache miss, distinct
        // from "held but no manifest section". Reports the same -32004 dig.fetchRange uses for
        // an unheld resource, not method-not-found and not a fabricated null.
        let (node, _td) = test_node(None);
        let store_hex = Bytes32([11u8; 32]).to_hex();
        let root_hex = Bytes32([12u8; 32]).to_hex();
        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getManifest","params":{
                "store_id": store_hex, "root": root_hex,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(resp["error"]["code"], json!(-32004), "unexpected: {resp}");
        assert!(resp.get("result").is_none());
    }

    #[tokio::test]
    async fn dig_get_manifest_rejects_malformed_params_without_touching_disk() {
        // Missing/invalid store_id or root is a param-validation error (-32602), returned
        // before any filesystem access — never -32601 (this method IS served locally) and
        // never a panic on absent params.
        let (node, _td) = test_node(None);
        let empty = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getManifest","params":{}}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(empty["error"]["code"], json!(-32602), "{empty}");

        let bad_root = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"dig.getManifest","params":{
                "store_id": Bytes32([1u8; 32]).to_hex(), "root": "not-hex",
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        )
        .await;
        assert_eq!(bad_root["error"]["code"], json!(-32602), "{bad_root}");
    }

    // -- LOCAL PLAINTEXT CONTENT-SERVE (#289/#290) — serve_content_plaintext + manifest_paths --------
    //
    // These drive the NEW server-side verify+decrypt path against a REAL compiled `.dig` module
    // (via `compile_fixture_module`), the injected anchored-root resolver as the trusted root, and the
    // test node's unroutable upstream — so a LOCAL hit proves no-network local-first serve. They pin
    // the fail-closed root check (#127) and the ecosystem key derivation (byte-identical plaintext).

    /// **Proves:** a synced+verified public `.dig` module is served LOCAL-FIRST as decrypted plaintext
    /// (no network), the empty resource defaults to `index.html`, and the tier/root/verified provenance
    /// is reported. **Catches:** a serve that returns ciphertext, mis-derives the key, or hits the
    /// network on a local hit.
    #[test]
    fn serve_content_plaintext_serves_local_first_decrypted() {
        use crate::content_serve::{PlaintextOutcome, ServeSource};
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN"); // enforce the chain-anchored pin (the default)
        let rt = pin_test_rt();
        let store = Bytes32([21u8; 32]);
        let files = vec![
            ("index.html".to_string(), b"<h1>hi</h1>".to_vec()),
            ("assets/app.js".to_string(), b"console.log(1)".to_vec()),
        ];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);
        let (node, _td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), root));
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);

        // index.html, decrypted, from the local module — the test node's upstream is unroutable, so a
        // Served result PROVES it came from disk.
        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        match out {
            PlaintextOutcome::Served {
                bytes,
                root_hex,
                verified,
                source,
                peer_tier,
                owner_puzzle_hash,
                generation,
            } => {
                assert_eq!(bytes, b"<h1>hi</h1>");
                assert_eq!(root_hex, root.to_hex());
                assert!(
                    verified,
                    "the chain-anchored pin is enforced → verified=true"
                );
                assert_eq!(source, ServeSource::Local);
                // No peer network is brought up on this node, so the read skipped Tier 2 (#1763) —
                // reported honestly even though the bytes came from disk and never needed a peer.
                assert_eq!(peer_tier, crate::content_serve::PeerTier::Unattached);
                // The injected resolver (`MockResolver::one`) reports no owner (#486) — the header
                // must be OMITTED, never guessed.
                assert_eq!(owner_puzzle_hash, None);
                // The fixture module embeds a PublicManifest (single commit) → generation 0.
                assert_eq!(generation, Some(0));
            }
            other => panic!("expected a local Served, got {other:?}"),
        }

        // A nested asset decrypts to its exact bytes.
        let js = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "assets/app.js",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(
            matches!(js, PlaintextOutcome::Served { ref bytes, .. } if bytes == b"console.log(1)"),
            "expected the js asset, got {js:?}"
        );

        // The EMPTY resource resolves to the default view index.html (same bytes).
        let bare = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(
            matches!(bare, PlaintextOutcome::Served { ref bytes, .. } if bytes == b"<h1>hi</h1>"),
            "empty resource must default to index.html, got {bare:?}"
        );

        // Verification ledger (#307): every served resource was recorded local + verified against the
        // chain-anchored root, so the page-level aggregate is "Verified by Chia". `index.html` (served
        // twice — explicitly and via the empty default) is deduped to ONE entry, so the two distinct
        // resources (`index.html`, `assets/app.js`) yield two ledger entries, both local + verified.
        let snap = node.verification_ledger_snapshot(&store.to_hex(), Some(&root.to_hex()));
        assert_eq!(snap.store_id, store.to_hex());
        assert_eq!(snap.root, root.to_hex());
        assert_eq!(
            snap.resources.len(),
            2,
            "index.html deduped; index + app.js"
        );
        assert!(
            snap.aggregate.verified,
            "all local + chain-anchored → verified"
        );
        assert!(!snap.aggregate.any_rpc_failed);
        assert_eq!(snap.aggregate.counts.total, 2);
        assert_eq!(snap.aggregate.counts.verified, 2);
        assert_eq!(snap.aggregate.counts.by_source.local, 2);
        let idx = snap
            .resources
            .iter()
            .find(|e| e.resource_key == "index.html")
            .expect("index.html recorded");
        assert!(idx.verified);
        assert_eq!(idx.source, "local");
        assert_eq!(idx.root, root.to_hex());
        // Proof data is present + ties to the anchored root (leaf hash + fold root serialized).
        assert_eq!(idx.proof.proof_root, root.to_hex());
        assert!(!idx.proof.leaf_hash.is_empty());
        assert!(idx.fail_reason.is_none());

        // A no-root query returns the same (most-recent) page session.
        let latest = node.verification_ledger_snapshot(&store.to_hex(), None);
        assert_eq!(latest.root, root.to_hex());
        assert_eq!(latest.resources.len(), 2);
    }

    /// **Regression (#1763):** `peer_tier` reports whether the P2P content engine was ATTACHED when
    /// a read was routed — a fact about the node, independent of which tier ended up serving. Before
    /// this fix nothing carried it, so a read taken inside the ~30 s cold-start window looked exactly
    /// like a read taken after attach and any peer-replication conclusion drawn from it was unfounded.
    ///
    /// **The fixture varies ONE actor.** Both arms drive the IDENTICAL locally-seeded, chain-anchored
    /// capsule and both are served from disk (`ServeSource::Local`) — the only difference is whether an
    /// engine is attached. That is deliberate: the nearest wrong implementation derives the value from
    /// the SERVE SOURCE (`peer_tier = if source == Rpc { Unattached } else { Attached }`), which is
    /// indistinguishable from the real thing on a gateway-serve fixture, and which this pair kills from
    /// both directions — arm 1 is Local-and-Unattached (that impl says Attached) while arm 2 is
    /// Local-and-Attached, so it cannot be satisfied by any constant either.
    ///
    /// The end-to-end cold-start case — a real gateway serve inside the window, reported over HTTP —
    /// is `dig-node-service`'s `cold_start_gateway_serve_reports_the_peer_tier_as_unattached`.
    #[test]
    fn serve_reports_peer_tier_attachment_independently_of_the_serving_tier() {
        use crate::content_serve::{PeerTier, PlaintextOutcome, ServeSource};
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN"); // enforce the chain-anchored pin (the default)
        let rt = pin_test_rt();
        let store = Bytes32([23u8; 32]);
        let files = vec![("index.html".to_string(), b"<h1>local</h1>".to_vec())];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);

        for attach in [false, true] {
            let (node, td) =
                test_node_with_resolver(None, MockResolver::one(&store.to_hex(), root));
            seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);
            if attach {
                // An engine with NO providers: the peer tier EXISTS but holds nothing, so the read is
                // still served from disk. Attachment, not peer availability, is what is under test.
                let (content, _unrelated_root, _pt) =
                    anchored_sealed_content(Bytes32([24u8; 32]), "index.html", b"elsewhere");
                attach_p2p(&node, vec![], content, MissMode::FetchThrough, &td);
            }

            // The node-level accessor `/health` reads (#1763) must flip with attachment too — the
            // header path and the health path share this one source of truth, so a `peer_tier()`
            // pinned to either arm is caught here rather than only at whichever surface has coverage.
            assert_eq!(
                node.peer_tier(),
                if attach {
                    PeerTier::Attached
                } else {
                    PeerTier::Unattached
                },
                "attach={attach}: Node::peer_tier must track engine attachment"
            );

            let out = rt.block_on(node.serve_content_plaintext(
                &store.to_hex(),
                &root.to_hex(),
                "index.html",
                None,
                crate::download::ReadOrigin::Local,
                crate::download::RequestProvenance::FirstParty,
            ));
            match out {
                PlaintextOutcome::Served {
                    source, peer_tier, ..
                } => {
                    assert_eq!(
                        source,
                        ServeSource::Local,
                        "attach={attach}: both arms serve from disk — the serving tier is the CONTROL"
                    );
                    assert_eq!(
                        peer_tier,
                        if attach {
                            PeerTier::Attached
                        } else {
                            PeerTier::Unattached
                        },
                        "attach={attach}: peer_tier must track engine attachment, not the serve source"
                    );
                }
                other => panic!("attach={attach}: expected a local Served, got {other:?}"),
            }
        }
    }

    /// **Proves:** the serve-metadata `X-Dig-Owner-Puzzle-Hash` source (#486) — when the chain-anchored
    /// pin is ENFORCED and the resolver reports the store's on-chain owner, `serve_content_plaintext`
    /// surfaces it on the `Served` outcome, resolved from the SAME chain read as the root pin (no second
    /// coinset call). **Catches:** the owner silently staying `None` when the resolver DOES supply it,
    /// or the field being guessed/fabricated rather than sourced from the resolver.
    #[test]
    fn serve_content_plaintext_reports_the_resolver_owner_puzzle_hash_when_pin_enforced() {
        use crate::content_serve::PlaintextOutcome;
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN"); // enforce the chain-anchored pin (the default)
        let rt = pin_test_rt();
        let store = Bytes32([23u8; 32]);
        let owner = Bytes32([0xaa; 32]);
        let files = vec![("index.html".to_string(), b"<h1>owned</h1>".to_vec())];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);
        let (node, _td) = test_node_with_resolver(
            None,
            MockResolver::one_with_owner(&store.to_hex(), root, owner),
        );
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        match out {
            PlaintextOutcome::Served {
                owner_puzzle_hash,
                generation,
                ..
            } => {
                assert_eq!(
                    owner_puzzle_hash,
                    Some(owner.to_hex()),
                    "the resolver's owner puzzle hash must be surfaced verbatim"
                );
                assert_eq!(generation, Some(0));
            }
            other => panic!("expected a local Served, got {other:?}"),
        }
    }

    /// **Proves:** `X-Dig-Owner-Puzzle-Hash` is OMITTED (never a placeholder) when the chain-anchored
    /// pin did not run (`DIG_NODE_PIN=off`) — the owner is genuinely unknowable without a chain read, so
    /// the serve-metadata source (#486) must not guess. The LOCAL-only generation lookup is unaffected
    /// (it never calls the chain) and still resolves.
    #[test]
    fn serve_content_plaintext_omits_owner_puzzle_hash_when_pin_is_off() {
        use crate::content_serve::PlaintextOutcome;
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_PIN", "off");
        let rt = pin_test_rt();
        let store = Bytes32([24u8; 32]);
        let owner = Bytes32([0xbb; 32]);
        let files = vec![("index.html".to_string(), b"<h1>unpinned</h1>".to_vec())];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);
        // Even though the resolver COULD supply an owner, the pin being off means it is never consulted.
        let (node, _td) = test_node_with_resolver(
            None,
            MockResolver::one_with_owner(&store.to_hex(), root, owner),
        );
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        match out {
            PlaintextOutcome::Served {
                owner_puzzle_hash,
                generation,
                ..
            } => {
                assert_eq!(
                    owner_puzzle_hash, None,
                    "pin off ⇒ owner is unknowable, never guessed"
                );
                assert_eq!(
                    generation,
                    Some(0),
                    "the local manifest lookup is independent of the chain pin"
                );
            }
            other => panic!("expected a local Served, got {other:?}"),
        }
        std::env::remove_var("DIG_NODE_PIN");
    }

    /// **Proves:** `X-Dig-Generation` is OMITTED when the served module carries NO `PublicManifest`
    /// section (a private store, or an older `.dig` compiled before #176) — the generation is genuinely
    /// unknowable from the module alone, never fabricated.
    #[test]
    fn serve_content_plaintext_omits_generation_when_manifest_absent() {
        use crate::content_serve::PlaintextOutcome;
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([25u8; 32]);
        let files = vec![("secret.txt".to_string(), b"top secret".to_vec())];
        // include_public_manifest = false: no PublicManifest section embedded (a public store here,
        // so the resource still decrypts with no salt — only the manifest presence is under test).
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, false, &files);
        let (node, _td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), root));
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "secret.txt",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        match out {
            PlaintextOutcome::Served { generation, .. } => {
                assert_eq!(
                    generation, None,
                    "no manifest section ⇒ generation is unknowable, never fabricated"
                );
            }
            other => panic!("expected a local Served, got {other:?}"),
        }
    }

    /// **Proves:** the #747/#841 fix end-to-end — a ROOTED local `/s` read whose full singleton-lineage
    /// walk is BROKEN ("parse next store: missing child") STILL serves, because the pin falls back to the
    /// bounded `verify_pinned_root` (which anchors the valid pinned root without the walk). **Catches:** a
    /// regression to the old behaviour where a single unparseable intermediate generation made a perfectly
    /// valid capsule unreadable. Owner is OMITTED here (the walk that carries it is broken) — the read
    /// itself must succeed.
    #[test]
    fn serve_content_plaintext_rooted_read_survives_a_broken_lineage_walk_747() {
        use crate::content_serve::PlaintextOutcome;
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN"); // enforce the pin (the default)
        let rt = pin_test_rt();
        let store = Bytes32([27u8; 32]);
        let files = vec![("index.html".to_string(), b"<h1>survived</h1>".to_vec())];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);
        // The walk is broken (#747), but the BOUNDED verify accepts the pinned root — exactly the
        // on-chain scenario the fix targets.
        let (node, _td) = test_node_with_resolver(
            None,
            MockResolver::with_verify(Err("parse next store: missing child".into()), Ok(())),
        );
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        match out {
            PlaintextOutcome::Served {
                bytes,
                root_hex,
                verified,
                owner_puzzle_hash,
                ..
            } => {
                assert_eq!(bytes, b"<h1>survived</h1>");
                assert_eq!(root_hex, root.to_hex());
                assert!(verified, "the pin ran (bounded verify) ⇒ verified");
                assert_eq!(
                    owner_puzzle_hash, None,
                    "owner is omitted when the owner-carrying walk is broken (#486 note)"
                );
            }
            other => panic!("expected a local Served via the bounded fallback, got {other:?}"),
        }
        std::env::remove_var("DIG_NODE_PIN");
    }

    /// **Proves:** the serve path fails CLOSED when the requested root is not the chain-anchored tip
    /// (#127) — never decrypting/serving a generation the chain did not confirm. **Catches:** a serve
    /// that trusts the caller's root over the chain.
    #[test]
    fn serve_content_plaintext_rejects_a_non_anchored_root() {
        use crate::content_serve::PlaintextOutcome;
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([22u8; 32]);
        let anchored = Bytes32([0x33; 32]);
        let (node, _td) =
            test_node_with_resolver(None, MockResolver::one(&store.to_hex(), anchored));
        let wrong = Bytes32([0x44; 32]).to_hex();
        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &wrong,
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert!(
            matches!(out, PlaintextOutcome::RootError { .. }),
            "a non-anchored requested root must fail closed, got {out:?}"
        );
    }

    /// **Proves:** `manifest_paths` lists the store's public file paths when the capsule is held with a
    /// manifest, and is `None` when the capsule is not held (drives the shell's SPA-vs-404 decision).
    #[tokio::test]
    async fn manifest_paths_lists_public_paths_when_held_and_none_when_not() {
        use crate::ContentServer;
        let (node, _td) = test_node(None);
        let store = Bytes32([23u8; 32]);
        let files = vec![
            ("index.html".to_string(), b"x".to_vec()),
            ("assets/app.js".to_string(), b"y".to_vec()),
        ];
        let (root, module) =
            compile_fixture_module(store, digstore_core::Visibility::Public, true, &files);
        seed_cached_module(&node.cache_dir, &store.to_hex(), &root.to_hex(), &module);
        let paths = node
            .manifest_paths(&store.to_hex(), &root.to_hex())
            .await
            .expect("held capsule with a manifest → Some(paths)");
        assert!(paths.contains(&"index.html".to_string()));
        assert!(paths.contains(&"assets/app.js".to_string()));

        // A capsule this node does not hold → None (the shell then uses the extension-less heuristic).
        let absent = node
            .manifest_paths(&Bytes32([24u8; 32]).to_hex(), &Bytes32([25u8; 32]).to_hex())
            .await;
        assert!(
            absent.is_none(),
            "an unheld capsule yields no manifest paths"
        );
    }

    // -- REDIRECT-ON-MISS (#165) — the content-orchestration miss handler wired into the RPC ----------
    //
    // These drive the REAL `dig.getContent` / `dig.fetchRange` dispatch on a node that does NOT hold the
    // requested resource but has a P2P content engine attached (the standalone peer path). With a mock
    // DHT locator + mock range transport (dig-download's testkit — no real network) they assert: a
    // holder exists → REDIRECT (not not-found); no holder → proper not-found; the hop cap is honored;
    // and `DIG_NODE_ON_MISS=fetch` fetches-through and serves the bytes. The pin resolver returns the
    // tip so the read gets past the anchored-root gate into the miss path.

    use crate::download::{MissMode, NodeContent, CONTENT_REDIRECT, REDIRECT_HOP_CAP};
    use dig_download::ContentId;

    /// A `MockContent` whose `root`/`inclusion_proof` are a REAL digstore merkle proof over its bytes,
    /// so the chain-binding `DigstoreProofVerifier` (and the download's whole-resource verify) pass for
    /// honest bytes — the same construction `download::tests::anchored_mock_content` uses.
    fn anchored_mock_content(n: usize, chunks: usize) -> dig_download::testkit::MockContent {
        use digstore_core::codec::Encode;
        let mut content = dig_download::testkit::MockContent::even(n, chunks);
        let leaf = digstore_core::resource_leaf(&content.bytes);
        let tree = digstore_core::MerkleTree::from_leaves(vec![leaf]);
        let proof = tree.prove(0).expect("single-leaf proof");
        content.root = tree.root().to_hex();
        content.inclusion_proof =
            Some(base64::engine::general_purpose::STANDARD.encode(Encode::to_bytes(&proof)));
        content
    }

    /// The `ContentId` to request for an [`anchored_mock_content`]: its `root` MUST equal the root the
    /// transport reports in each range frame, because the download orchestrator now cross-checks the
    /// peer-reported root against the content-id root (dig-download #179 HIGH). Store id + retrieval
    /// key match `mock_content_id` (`[1;32]` / `[3;32]`); only the root is bound to the content.
    fn anchored_cid_for(content: &dig_download::testkit::MockContent) -> ContentId {
        let root: [u8; 32] = Bytes32::from_hex(&content.root)
            .expect("anchored content root is 64-hex")
            .0;
        ContentId::resource([1; 32], root, [3; 32])
    }

    /// Attach a P2P content engine to `node` with a mock locator (the given providers) + a mock
    /// transport serving `content`, in `mode`. Returns nothing — the engine lives on the node.
    fn attach_p2p(
        node: &Node,
        providers: Vec<dig_download::ProviderRecord>,
        content: dig_download::testkit::MockContent,
        mode: MissMode,
        td: &tempfile::TempDir,
    ) {
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(providers));
        let transport = Arc::new(dig_download::testkit::MockRangeTransport::new(content));
        let pc = NodeContent::new(locator, transport, mode, None, td.path());
        node.set_p2p_content(pc);
    }

    /// A store + its chain tip, with a request that resolves past the pin into the miss path.
    fn miss_setup() -> (Bytes32, Bytes32, String) {
        (Bytes32([0x21; 32]), Bytes32([0x22; 32]), any_rk_hex())
    }

    #[test]
    fn get_content_miss_with_a_provider_redirects_not_notfound() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        // A holder exists in the DHT for this content.
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(3, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        // Not held locally, but a provider exists → a REDIRECT (never a silent miss/upstream error).
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "expected redirect: {resp}"
        );
        let redirect = &resp["error"]["data"]["redirect"];
        assert_eq!(
            redirect["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(3))
        );
        assert_eq!(redirect["redirect_depth"], json!(1), "depth advanced 0 → 1");
        assert_eq!(redirect["max_redirects"], json!(REDIRECT_HOP_CAP));
        assert_eq!(redirect["content"]["store_id"], json!(store.to_hex()));
    }

    #[test]
    fn get_content_miss_with_no_provider_is_notfound_not_redirect() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        // NO provider in the DHT for this content.
        attach_p2p(
            &node,
            vec![],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        // No provider anywhere → NOT a redirect. The engine yields None and the request falls through
        // to the upstream proxy, which (unroutable in tests) returns a -32000 upstream error, never a
        // -32008 redirect.
        assert_ne!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "no provider must NOT redirect: {resp}"
        );
    }

    #[test]
    fn get_content_miss_honors_the_redirect_hop_cap() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(3, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        // A request already redirected up to the cap → NO further redirect (loop guard), even though a
        // provider exists.
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "redirect_depth": REDIRECT_HOP_CAP,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_ne!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "at the hop cap the node must not redirect again: {resp}"
        );
    }

    #[test]
    fn fetch_range_miss_with_a_provider_redirects() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );
        // dig.fetchRange for a resource the node does not hold → redirect (fetchRange has no pin gate).
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":7,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "fetchRange miss → redirect: {resp}"
        );
        assert_eq!(
            resp["error"]["data"]["redirect"]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(5))
        );
    }

    /// **Proves:** a `Peer`-origin `dig.fetchRange` miss WITH A LIVE PROVIDER — the exact condition
    /// that makes the miss envelope `Some` and reaches `maybe_backfill_capsule` at `dispatch.rs` —
    /// spawns NO background backfill. This is the sibling call site the reshare leg's `origin` gate
    /// had not yet reached: a remote peer must not be able to make this node pull, cache, and
    /// DHT-announce a capsule of the peer's own choosing via the PRE-EXISTING backfill mechanism
    /// either, not just via the new reshare leg.
    /// **Catches:** `maybe_backfill_capsule`'s own origin check being dropped or inverted — verified
    /// RED against `97914fab` by deleting that check (the only two failures in the crate were this
    /// test and its `Local`-origin control below).
    #[test]
    fn a_peer_origin_fetch_range_miss_with_a_provider_spawns_no_backfill() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default ON
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Peer,
            crate::download::RequestProvenance::FirstParty,
        ));
        // The miss genuinely redirected — proving a live provider made the envelope `Some`, the exact
        // precondition for `maybe_backfill_capsule` being called at all.
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "the miss must genuinely redirect for this test to mean anything: {resp}"
        );

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "a Peer-origin miss must never spawn a background backfill"
        );
    }

    /// **The control:** the identical miss at `Local` origin DOES spawn a backfill — proving the
    /// harness above can observe a spawned backfill at all, so the refusal test is not merely
    /// "nothing ever happens here regardless".
    #[test]
    fn a_local_origin_fetch_range_miss_with_a_provider_spawns_a_backfill() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTENT_REDIRECT), "{resp}");

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            node.capsule_acquisition.is_warming(&key),
            "a Local-origin miss (the control) must spawn a background backfill"
        );
    }

    /// **Proves (#1614):** the §21 backfill leg and the #1576 reshare leg claim the ONE shared gate, so a
    /// read triggers AT MOST ONE whole-capsule pull. Here the reshare leg has already won the race and
    /// holds the capsule's single-flight slot; the §21 backfill for the SAME `(store, root)` must then
    /// find the slot taken and start NO second pull.
    /// **Catches:** the pre-#1614 two-registries defect, where `maybe_backfill` used its own
    /// `Node::backfilling` set — blind to the reshare claim — and fired a redundant whole-`.dig` pull.
    #[test]
    fn backfill_defers_to_an_in_flight_reshare_on_the_shared_gate() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        // The reshare leg wins the race first: it claims the capsule on the node's SHARED gate.
        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        let reshare_claim = node
            .capsule_acquisition_gate()
            .claim(key.clone())
            .expect("the reshare leg claims the fresh gate");

        // Now drive the identical Local read: the §21 backfill sees the slot already taken.
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTENT_REDIRECT), "{resp}");

        // The only claim on the gate is the reshare leg's: dropping it must free the slot completely,
        // proving the backfill did NOT add a second, independent claim.
        drop(reshare_claim);
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "the §21 backfill must NOT hold its own slot once the reshare claim is released — one pull, \
             one gate"
        );
    }

    /// **Proves (#1614):** once the §21 backfill leg holds the shared gate, the #1576 reshare leg,
    /// claiming the SAME `Arc<WarmRegistry>` (via [`Node::capsule_acquisition_gate`]), is refused — the
    /// two legs are wired to ONE registry instance, not two blind ones.
    /// **Catches:** the reshare warmer being wired with a fresh `WarmRegistry` (the pre-#1614 shape).
    #[test]
    fn reshare_defers_to_an_in_flight_backfill_on_the_shared_gate() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        // The §21 backfill leg wins the race first (a Local read claims the shared gate).
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTENT_REDIRECT), "{resp}");

        // The reshare leg, claiming the SAME instance, is refused — proof it shares one registry.
        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            node.capsule_acquisition.is_warming(&key),
            "the §21 backfill must hold the shared slot",
        );
        assert!(
            node.capsule_acquisition_gate().claim(key).is_none(),
            "the reshare leg, claiming the SAME gate, must be refused while the backfill holds it",
        );
    }

    // -- #1956: the JSON-RPC POST landing legs gate on request PROVENANCE (Sec-Fetch-Site) ----------
    //
    // The transport-axis (`ReadOrigin`) tests above prove a PEER-origin miss never lands. These prove
    // the SECOND axis: a same-origin capsule page that `POST`s `dig.getContent`/`dig.fetchRange` over
    // the LOOPBACK transport (origin = Local) still cannot drive landing when the browser reports the
    // request was CROSS-SITE — matching the #1654 `/s/` serve gate. The read is NEVER altered: the
    // redirect envelope (the served bytes' locator) is returned identically; only the durable holder
    // side effect (backfill/reshare warm) is withheld. Each mirrors the `origin`-axis control exactly,
    // varying ONLY the `provenance` argument, so a dropped `land_origin` fold at ANY of the four
    // landing sites turns one of these RED.

    /// **Proves (#1956):** a CROSS-SITE `dig.fetchRange` POST over the loopback transport still SERVES
    /// (the miss redirects to the provider — the bytes' locator) but spawns NO background backfill —
    /// the CSRF door the `origin` axis alone left open on the JSON-RPC path.
    /// **Catches:** the `land_origin` fold being dropped at the fetchRange landing sites
    /// (`range_miss_envelope` and/or `maybe_backfill_capsule`) — then a cross-site page drives landing.
    #[test]
    fn cross_site_post_fetchrange_serves_but_does_not_land() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default ON
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(5, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::CrossSite,
        ));
        // The read STILL serves — a cross-site request is never throttled, only its landing is denied.
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "a cross-site fetchRange must still serve (redirect to the provider): {resp}"
        );

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "a cross-site fetchRange POST must NOT spawn a backfill, even over the loopback transport"
        );
    }

    /// **Proves (#1956):** a CROSS-SITE `dig.getContent` POST still serves the miss (redirect) but
    /// spawns NO backfill — the sibling handler, whose miss-envelope leg forwards origin into the
    /// reshare chain, is gated identically.
    /// **Catches:** the `land_origin` fold being dropped at the getContent landing sites
    /// (`content_miss_envelope` and/or `maybe_backfill_capsule`).
    #[test]
    fn cross_site_post_getcontent_serves_but_does_not_land() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(3, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::CrossSite,
        ));
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "a cross-site getContent must still serve (redirect to the provider): {resp}"
        );

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "a cross-site getContent POST must NOT spawn a backfill"
        );
    }

    /// **The control (#1956):** the identical `dig.getContent` miss at FIRST-PARTY provenance DOES
    /// spawn a backfill — proving the fold does not simply disable landing, and that a legitimate
    /// same-site / CLI / SDK read (no `Sec-Fetch-*` header ⇒ FirstParty) still lands (frictionless).
    #[test]
    fn first_party_post_getcontent_still_lands() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(3, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTENT_REDIRECT), "{resp}");

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            node.capsule_acquisition.is_warming(&key),
            "a first-party local getContent miss (the control) must still land"
        );
    }

    /// **Proves (#1956):** a PEER-transport `dig.getContent` miss is unaffected by the provenance axis —
    /// `landing_origin(Peer, FirstParty) == Peer`, so it serves but never lands, exactly as before. The
    /// two axes compose; provenance can only ever tighten landing, never loosen the transport denial.
    #[test]
    fn peer_transport_post_getcontent_unaffected() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        let node = Arc::new(node);
        node.set_self_ref(Arc::downgrade(&node));
        let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(3, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
            }}),
            crate::download::ReadOrigin::Peer,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["error"]["code"], json!(CONTENT_REDIRECT), "{resp}");

        let key = format!("{}:{}", store.to_hex(), tip.to_hex());
        assert!(
            !node.capsule_acquisition.is_warming(&key),
            "a peer-transport getContent miss must never land, regardless of provenance"
        );
    }

    /// **Proves (#1956):** the SERVED response is byte-identical whether the request is FirstParty or
    /// CrossSite — provenance touches ONLY the landing side effect, never the read. Two fresh nodes run
    /// the identical getContent miss under the two provenances; the returned envelopes must be equal.
    /// **Catches:** provenance ever leaking onto the serve/response path (the frictionless-read trap).
    #[test]
    fn read_bytes_identical_regardless_of_provenance() {
        fn serve_miss(provenance: crate::download::RequestProvenance) -> Value {
            let rt = pin_test_rt();
            let (store, tip, rk) = miss_setup();
            let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
            let node = Arc::new(node);
            node.set_self_ref(Arc::downgrade(&node));
            let cid = ContentId::resource(store.0, tip.0, [0xcd; 32]);
            attach_p2p(
                &node,
                vec![dig_download::testkit::mock_provider(3, &cid)],
                dig_download::testkit::MockContent::even(10, 1),
                MissMode::Redirect,
                &td,
            );
            rt.block_on(handle_rpc(
                &node,
                json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                    "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk,
                }}),
                crate::download::ReadOrigin::Local,
                provenance,
            ))
        }

        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS");
        let first_party = serve_miss(crate::download::RequestProvenance::FirstParty);
        let cross_site = serve_miss(crate::download::RequestProvenance::CrossSite);
        assert_eq!(
            first_party, cross_site,
            "the served response must be identical across provenance — only landing differs"
        );
    }

    #[test]
    fn fetch_through_pulls_from_the_holder_and_serves_the_bytes() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk) = miss_setup();
        let (node, td) = test_node(None);
        // A holder serves an ANCHORED resource (real digstore proof over its bytes) so the download's
        // whole-resource verify against the chain-anchored root passes. The content id root MUST equal
        // the transport-reported root (dig-download #179 cross-check).
        let content = anchored_mock_content(30, 3);
        let cid = anchored_cid_for(&content);
        attach_p2p(
            &node,
            vec![
                dig_download::testkit::mock_provider(1, &cid),
                dig_download::testkit::mock_provider(2, &cid),
            ],
            content.clone(),
            MissMode::FetchThrough,
            &td,
        );
        // fetch-through: the node pulls the resource from the holders and serves it directly. The
        // request's content id must be the mock content id the holders serve.
        let (store_hex, tip_hex, rk_hex) = match &cid {
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => (
                hex::encode(store_id),
                hex::encode(root),
                hex::encode(retrieval_key),
            ),
            _ => unreachable!("mock_content_id is a resource"),
        };
        let _ = (store, tip, rk);
        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":9,"method":"dig.fetchRange","params":{
                "store_id": store_hex, "root": tip_hex, "retrieval_key": rk_hex,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        // A fetched-through frame is served (NOT a redirect, NOT a miss): the first frame carries the
        // reassembled bytes + verification metadata.
        assert!(
            resp.get("result").is_some(),
            "fetch-through serves a frame: {resp}"
        );
        let frame = &resp["result"];
        assert_eq!(frame["complete"], json!(true));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(frame["bytes"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            bytes, content.bytes,
            "fetch-through serves the holder's bytes"
        );
        assert_eq!(frame["root"], json!(content.root));
    }

    /// Build an anchored, SEALED single-chunk resource for `(store, resource_key)` the loopback serve
    /// path (`serve_content_plaintext`) can verify + decrypt: the bytes are the REAL per-URN ciphertext
    /// (so `verify_and_decrypt` opens them), the inclusion proof folds `resource_leaf(ciphertext)` to a
    /// single-leaf root, and `MockContent.root` is that root — matching the dig-download #179 content-id
    /// cross-check. Returns `(content, root, plaintext)`.
    fn anchored_sealed_content(
        store: Bytes32,
        resource_key: &str,
        plaintext: &[u8],
    ) -> (dig_download::testkit::MockContent, Bytes32, Vec<u8>) {
        use digstore_core::codec::Encode;
        use digstore_core::crypto::{derive_decryption_key, encrypt_chunk};
        use digstore_core::merkle::{resource_leaf, MerkleTree};
        let urn = digstore_core::Urn {
            chain: digstore_core::CHAIN.to_string(),
            store_id: store,
            root_hash: None,
            resource_key: Some(resource_key.to_string()),
        };
        let key = derive_decryption_key(&urn.canonical(), None);
        let ciphertext = encrypt_chunk(&key, plaintext);
        let leaf = resource_leaf(&ciphertext);
        let tree = MerkleTree::from_leaves(vec![leaf]);
        let root = tree.root();
        let proof = tree.prove(0).expect("single-leaf proof");
        let mut content = dig_download::testkit::MockContent::new(
            ciphertext.clone(),
            vec![ciphertext.len() as u64],
        );
        content.root = root.to_hex();
        content.inclusion_proof =
            Some(base64::engine::general_purpose::STANDARD.encode(Encode::to_bytes(&proof)));
        (content, root, plaintext.to_vec())
    }

    /// **Regression (#1586):** a loopback `/s/` read that MISSES locally, whose §21 upstream is
    /// UNREACHABLE, but for which a P2P provider holds the resource, MUST fetch + merkle-verify + decrypt
    /// the bytes FROM THE PROVIDER and serve them (`ServeSource::Peer`) — never dead-end at the upstream
    /// backfill. Proves the read leg completes PURELY P2P on an isolated network (the #836 blocker): the
    /// e2e showed this 404 because the read reached only rpc.dig.net, never the discovered holder.
    #[test]
    fn serve_content_plaintext_fetches_from_peer_when_upstream_unreachable() {
        use crate::content_serve::{derive_retrieval_key, PlaintextOutcome, ServeSource};
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_PIN", "off"); // isolate the tier routing from the chain pin
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let store = Bytes32([0x51; 32]);
        let plaintext = b"<h1>served over p2p</h1>";
        let (content, root, _pt) = anchored_sealed_content(store, "index.html", plaintext);
        let (node, td) = test_node(None); // unroutable upstream — a Served result can only be P2P
                                          // The provider advertises the resource content id the serve path derives (store, root,
                                          // retrieval_key = SHA-256(rootless URN)); the mock locator returns it for any query.
        let rk = derive_retrieval_key(&store, "index.html");
        let cid = ContentId::resource(store.0, root.0, rk.0);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(1, &cid)],
            content,
            MissMode::FetchThrough,
            &td,
        );

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        std::env::remove_var("DIG_NODE_PIN");
        match out {
            PlaintextOutcome::Served {
                bytes,
                source,
                peer_tier,
                ..
            } => {
                assert_eq!(source, ServeSource::Peer, "must serve from the P2P holder");
                assert_eq!(bytes, plaintext, "the decrypted P2P bytes match the source");
                // The post-attach half of #1763: a read that genuinely reached a peer reports the
                // tier as attached, so it is distinguishable from a cold-start read that could not.
                assert_eq!(
                    peer_tier,
                    crate::content_serve::PeerTier::Attached,
                    "a peer-served read was routed with the engine up"
                );
            }
            other => panic!("expected a peer Served (no upstream), got {other:?}"),
        }
    }

    /// **Proves:** a `/s/` resource read that arrived from a NON-LOOPBACK connection is still SERVED,
    /// but starts NO whole-capsule warm — so a stranger cannot spend this node's bandwidth, disk, and
    /// DHT holder-inventory on a capsule of the STRANGER'S choosing (#1576). The read reaches the P2P
    /// tier (`ServeSource::Peer`), which is exactly the leg whose `fetch_resource` fires
    /// `spawn_capsule_reshare`, so "no warm" here is a fact about the gate rather than about a read
    /// that never got far enough to matter.
    ///
    /// **The paired control** (the `Local` arm below) drives the IDENTICAL fixture with the only
    /// difference being the origin label and observes a warm that DID start — without it, "no warm
    /// observed" would be satisfied just as well by a harness that can never observe one.
    ///
    /// **Catches:** `peer_serve_plaintext` hardcoding `ReadOrigin::Local` into `fetch_resource`
    /// instead of carrying the caller's origin (the state this test was written RED against), and any
    /// later regression that re-asserts an origin inside the serve path.
    #[test]
    fn serve_content_plaintext_starts_no_capsule_warm_for_a_peer_origin_read() {
        use crate::content_serve::{derive_retrieval_key, PlaintextOutcome, ServeSource};
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_PIN", "off"); // isolate the tier routing from the chain pin
        std::env::remove_var("DIG_NODE_ON_MISS");
        std::env::remove_var("DIG_NODE_BACKFILL_ON_MISS"); // default ON — the ORIGIN alone must refuse
        let rt = pin_test_rt();

        // One fixture, driven twice: `Peer` (the defect's entry point) then `Local` (the control).
        for (origin, expect_warm) in [
            (crate::download::ReadOrigin::Peer, false),
            (crate::download::ReadOrigin::Local, true),
        ] {
            let store = Bytes32([0x52; 32]);
            let plaintext = b"<h1>served to a stranger</h1>";
            let (content, root, _pt) = anchored_sealed_content(store, "index.html", plaintext);
            let (node, td) = test_node(None); // unroutable upstream — a Served result can only be P2P
            let rk = derive_retrieval_key(&store, "index.html");
            let cid = ContentId::resource(store.0, root.0, rk.0);
            attach_p2p(
                &node,
                vec![dig_download::testkit::mock_provider(1, &cid)],
                content,
                MissMode::FetchThrough,
                &td,
            );
            // A permanently-parked warmer: "a warm started" stays observable instead of racing a fast
            // mock outcome. The registry key is this capsule's own generation key.
            let (registry, _unused_content, _unused_key) =
                crate::download::tests::wire_hanging_warmer(
                    node.p2p_content().expect("p2p attached above"),
                    &td,
                );
            let key = format!("{}:{}", store.to_hex(), root.to_hex());

            let out = rt.block_on(node.serve_content_plaintext(
                &store.to_hex(),
                &root.to_hex(),
                "index.html",
                None,
                origin,
                crate::download::RequestProvenance::FirstParty,
            ));
            match out {
                PlaintextOutcome::Served { bytes, source, .. } => {
                    assert_eq!(
                        source,
                        ServeSource::Peer,
                        "{origin:?}: the read must reach the P2P tier — the leg that fires the reshare"
                    );
                    assert_eq!(
                        bytes, plaintext,
                        "{origin:?}: a peer-origin read is still SERVED"
                    );
                }
                other => panic!("{origin:?}: expected a peer Served (no upstream), got {other:?}"),
            }

            let started = rt.block_on(crate::download::tests::wait_for_warm_started(
                &registry,
                &key,
                std::time::Duration::from_millis(500),
            ));
            assert_eq!(
                started, expect_warm,
                "{origin:?}: expected warm-started == {expect_warm} for this origin                  (Peer must effect nothing; the Local control must prove a warm is observable)"
            );
        }
        std::env::remove_var("DIG_NODE_PIN");
    }

    /// A [`RangeTransport`](dig_download::RangeTransport) that a provider can only reach at the peer-RPC
    /// port (:9444). It delegates to an inner [`MockRangeTransport`](dig_download::testkit::MockRangeTransport)
    /// ONLY when the provider record's dial address carries the peer-RPC port; a provider offered at any
    /// other port (e.g. the gossip :9445) answers "not held" and every fetch fails — modelling the real
    /// wire, where dialing the gossip listener for a `dig.fetchRange` stream dies with `InvalidContentType`.
    /// This makes the connected-pool candidate PORT load-bearing in a test (the gap the #1590 mock had:
    /// its transport ignored the port entirely, so the wrong-port bug slipped through six iterations).
    struct PeerRpcPortGatingTransport {
        inner: dig_download::testkit::MockRangeTransport,
    }

    impl PeerRpcPortGatingTransport {
        fn new(content: dig_download::testkit::MockContent) -> Self {
            Self {
                inner: dig_download::testkit::MockRangeTransport::new(content),
            }
        }

        /// True when the provider is dialable at the peer-RPC port (:9444) — the only port a real
        /// `dig.fetchRange` stream is served on.
        fn reachable_at_peer_rpc(provider: &dig_download::ProviderRecord) -> bool {
            provider
                .addresses
                .iter()
                .any(|a| a.port == peer::DEFAULT_P2P_PORT)
        }
    }

    #[async_trait::async_trait]
    impl dig_download::RangeTransport for PeerRpcPortGatingTransport {
        async fn query_availability(
            &self,
            provider: &dig_download::ProviderRecord,
            items: Vec<dig_nat::AvailabilityItem>,
        ) -> Result<dig_nat::AvailabilityResponse, dig_download::DownloadError> {
            if !Self::reachable_at_peer_rpc(provider) {
                // Reached at the wrong port (the gossip listener) → the availability probe never gets a
                // valid answer; report "not held" so the orchestrator drops this (mis-dialed) source.
                let answers = items
                    .iter()
                    .map(|_| dig_nat::AvailabilityAnswer::unavailable())
                    .collect();
                return Ok(dig_nat::AvailabilityResponse::new(answers));
            }
            self.inner.query_availability(provider, items).await
        }

        async fn fetch_range(
            &self,
            provider: &dig_download::ProviderRecord,
            req: &dig_nat::RangeRequest,
        ) -> Result<dig_download::FetchedRange, dig_download::DownloadError> {
            if !Self::reachable_at_peer_rpc(provider) {
                return Err(dig_download::DownloadError::transport(
                    &provider.provider_peer_id,
                    "mock: gossip-port dial gets InvalidContentType (wrong listener)",
                ));
            }
            self.inner.fetch_range(provider, req).await
        }
    }

    /// Attach a P2P engine whose ONLY source is the connected gossip pool (no DHT provider), with the
    /// holder fed in THROUGH the real selector-registry feed translation
    /// ([`crate::peer::map_gossip_pool_event`]) from its GOSSIP address — so the connected-pool
    /// candidate's port is whatever the feed produces, not a hand-planted value. The transport is
    /// port-gated to the peer-RPC listener, making the translation load-bearing for the serve.
    fn attach_p2p_pool_via_gossip(
        node: &Node,
        content: dig_download::testkit::MockContent,
        gossip_addr: std::net::SocketAddr,
        td: &tempfile::TempDir,
    ) {
        let locator = Arc::new(dig_download::testkit::MockProviderLocator::fixed(vec![]));
        let transport = Arc::new(PeerRpcPortGatingTransport::new(content));
        let pc = NodeContent::new(locator, transport, MissMode::FetchThrough, None, td.path());
        // Drive the REAL live-feed translation: a gossip PoolEvent carrying the peer's :9445 endpoint.
        let peer_id = dig_gossip::PeerId::from([1u8; 32]);
        let selector_event =
            crate::peer::map_gossip_pool_event(&dig_gossip::PoolEvent::PeerAdded {
                peer_id,
                addr: gossip_addr,
            });
        pc.on_pool_event(&selector_event);
        node.set_p2p_content(pc);
    }

    /// **Regression (#1590 / #836 read-leg DATA gate):** a loopback `/s/` read that MISSES locally, whose
    /// §21 upstream is UNREACHABLE, served by a holder the reader knows ONLY through the connected gossip
    /// pool (its DHT record is unreachable) — where the holder's fetchRange listener is the peer-RPC port
    /// (:9444) while the pool reports its gossip port (:9445) — MUST still fetch + verify + decrypt + serve
    /// (`ServeSource::Peer`). Unlike the #1586/#1590 tests, the holder is fed through the REAL gossip→pool
    /// feed translation and the transport is PORT-GATED to :9444, so the read only succeeds when the feed
    /// correctly translates :9445 → :9444. On the pre-fix build the pool candidate keeps :9445, the gated
    /// transport refuses it, Tier-2 misses, and the unroutable upstream yields NOT `Served{Peer}` → RED.
    #[test]
    fn serve_content_plaintext_reaches_pool_holder_at_peer_rpc_port() {
        use crate::content_serve::{PlaintextOutcome, ServeSource};
        use crate::ContentServer;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("DIG_NODE_PIN", "off"); // isolate the tier routing from the chain pin
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let store = Bytes32([0x52; 32]);
        let plaintext = b"<h1>served from a connected pool holder</h1>";
        let (content, root, _pt) = anchored_sealed_content(store, "index.html", plaintext);
        let (node, td) = test_node(None); // unroutable upstream — a Served result can only be P2P
                                          // The holder is a CONNECTED pool peer whose gossip endpoint is :9445 (its peer-RPC
                                          // listener is one below, :9444) — exactly what a real pool reports.
        let gossip_addr: std::net::SocketAddr = "203.0.113.5:9445".parse().unwrap();
        attach_p2p_pool_via_gossip(&node, content, gossip_addr, &td);

        let out = rt.block_on(node.serve_content_plaintext(
            &store.to_hex(),
            &root.to_hex(),
            "index.html",
            None,
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        std::env::remove_var("DIG_NODE_PIN");
        match out {
            PlaintextOutcome::Served { bytes, source, .. } => {
                assert_eq!(
                    source,
                    ServeSource::Peer,
                    "must serve from the connected-pool holder over its peer-RPC port"
                );
                assert_eq!(bytes, plaintext, "the decrypted P2P bytes match the source");
            }
            other => panic!(
                "expected a peer Served via the :9444-gated pool holder, got {other:?} \
                 (a :9445 candidate means the gossip→pool feed did not translate the port)"
            ),
        }
    }

    // -- OUTGOING-BANDWIDTH THROTTLE + REDIRECT-ON-SATURATION (dig_ecosystem #30) --------------------
    //
    // These extend the #165 redirect-on-miss drives above to "the node DOES hold the content, but
    // serving it now would blow its configured outgoing-bandwidth cap": with a tiny cap and a known
    // holder, the node redirects (the SAME -32008 shape) instead of serving over-budget; with no known
    // holder (no provider, or no P2P engine at all — the FFI/browser path) it serves anyway (the
    // graceful fallback — never drop a request the node could have answered). Content is seeded
    // directly into the in-memory `content_cache` (mirrors
    // `serve_local_cached_serves_a_memoized_decode_without_touching_disk` above) so these tests never
    // touch disk/wasmtime — only the throttle + redirect decision is under test.

    /// Seed `node`'s in-memory content cache with a resource genuinely HELD at `(store, root, rk)`,
    /// `len` ciphertext bytes, roothash == `root` (so it passes the #127 anchored-root pin).
    fn seed_local_resource(node: &Node, store: Bytes32, root: Bytes32, rk: [u8; 32], len: usize) {
        let resp = ContentResponse {
            ciphertext: vec![0xABu8; len],
            merkle_proof: digstore_core::merkle::MerkleProof {
                leaf: Bytes32([0u8; 32]),
                path: vec![],
                root: Bytes32([0u8; 32]),
            },
            roothash: root,
            chunk_lens: vec![],
        };
        node.content_cache
            .lock()
            .unwrap()
            .insert((store.to_hex(), root.to_hex(), rk), Arc::new(resp));
    }

    #[test]
    fn get_content_over_cap_with_a_provider_redirects_instead_of_local_serve() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        // This node genuinely HOLDS the resource — 5000 bytes, well past a 10-byte cap.
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(10),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };
        // A holder for this EXACT content is known via the DHT.
        let cid = ContentId::resource(store.0, tip.0, rk);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(9, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "held locally but over the outgoing-bandwidth cap must redirect, not serve: {resp}"
        );
        assert_eq!(
            resp["error"]["data"]["redirect"]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(9))
        );
        assert_eq!(
            resp["error"]["data"]["redirect"]["redirect_depth"],
            json!(1)
        );
    }

    #[test]
    fn get_content_over_cap_with_no_provider_still_serves_locally() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(10),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };
        // A P2P engine is attached but the DHT knows of NO holder for this content — the graceful
        // fallback: serve anyway rather than drop the request.
        attach_p2p(
            &node,
            vec![],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_ne!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "no known alternate holder must NOT redirect: {resp}"
        );
        assert_eq!(
            resp["result"]["source"],
            json!("local"),
            "served from local cache despite being over the soft cap: {resp}"
        );
    }

    #[test]
    fn get_content_over_cap_with_no_p2p_engine_still_serves_locally() {
        // The in-process FFI/browser path never attaches a P2P content engine at all — the throttle
        // must not fail closed there either (nothing to redirect to, so it serves).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, _td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(10),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["result"]["source"], json!("local"), "{resp}");
    }

    #[test]
    fn get_content_under_cap_serves_locally_not_redirect() {
        // A generous cap the 5000-byte resource fits comfortably under, even though a holder IS known
        // — proves the throttle does not over-fire when the request is well within budget.
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(1_000_000),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };
        let cid = ContentId::resource(store.0, tip.0, rk);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(9, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(resp["result"]["source"], json!("local"), "{resp}");
    }

    #[test]
    fn get_content_over_cap_honors_the_redirect_hop_cap() {
        // A bandwidth-redirect reuses the SAME hop budget as miss-redirect (#165) — a request already
        // redirected up to the cap must not be redirected again, even though it is over budget and a
        // holder is known (loop prevention across saturated nodes).
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(10),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };
        let cid = ContentId::resource(store.0, tip.0, rk);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(9, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
                "redirect_depth": REDIRECT_HOP_CAP,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_ne!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "at the hop cap the node must not redirect again: {resp}"
        );
    }

    #[test]
    fn fetch_range_over_cap_with_a_provider_redirects() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        std::env::remove_var("DIG_NODE_ON_MISS");
        let rt = pin_test_rt();
        let (store, tip, rk_hex) = miss_setup();
        let rk = decode_rk(&rk_hex).expect("valid rk");
        let (node, td) = test_node_with_resolver(None, MockResolver::one(&store.to_hex(), tip));
        seed_local_resource(&node, store, tip, rk, 5000);
        let node = Node {
            outgoing_throttle: bandwidth::OutgoingThrottle::new(10),
            chat: chat::ChatState::new(),
            inbound_demand: inbound_demand::InboundDemand::new(),
            node_peer_id: OnceLock::new(),
            ..node
        };
        let cid = ContentId::resource(store.0, tip.0, rk);
        attach_p2p(
            &node,
            vec![dig_download::testkit::mock_provider(4, &cid)],
            dig_download::testkit::MockContent::even(10, 1),
            MissMode::Redirect,
            &td,
        );

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":7,"method":"dig.fetchRange","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
                "length": 4096, "offset": 0,
            }}),
            crate::download::ReadOrigin::Local,
            crate::download::RequestProvenance::FirstParty,
        ));
        assert_eq!(
            resp["error"]["code"],
            json!(CONTENT_REDIRECT),
            "held locally but over the outgoing-bandwidth cap must redirect: {resp}"
        );
        assert_eq!(
            resp["error"]["data"]["redirect"]["providers"][0]["peer_id"],
            json!(dig_download::testkit::mock_peer_hex(4))
        );
    }

    /// `dig.getNetworkInfo` must never report the wildcard bind address as a dialable endpoint, and
    /// its candidate list must be IPv6-first (ecosystem HARD RULE). The exact addresses are
    /// host-dependent (real local-address discovery), so this asserts the host-independent invariants:
    /// no `0.0.0.0` / `[::]` leaks, and any IPv4 candidate follows every IPv6 candidate.
    #[test]
    fn network_info_reports_ipv6_first_dialable_addrs_never_the_wildcard() {
        let (node, _td) = test_node(Some([5u8; 32]));
        let info = node.network_info();

        let listen = info["listen_addr"].as_str().expect("listen_addr string");
        assert!(
            !listen.starts_with("0.0.0.0:") && !listen.starts_with("[::]:"),
            "listen_addr must be a dialable address, never the wildcard bind address: {listen}"
        );

        let candidates: Vec<std::net::SocketAddr> = info["candidate_addresses"]
            .as_array()
            .expect("candidate_addresses array")
            .iter()
            .map(|v| v.as_str().unwrap().parse().expect("a socket addr"))
            .collect();
        // No wildcard address ever appears as an advertised candidate.
        for c in &candidates {
            assert!(!c.ip().is_unspecified(), "no wildcard candidate: {c}");
        }
        // IPv6-first: once an IPv4 candidate appears, no later candidate may be IPv6.
        let mut seen_ipv4 = false;
        for c in &candidates {
            if c.is_ipv4() {
                seen_ipv4 = true;
            } else {
                assert!(
                    !seen_ipv4,
                    "IPv6 candidate must not follow an IPv4 one: {candidates:?}"
                );
            }
        }
    }
}
