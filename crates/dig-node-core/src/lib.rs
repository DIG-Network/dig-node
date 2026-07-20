//! dig-node — the DIG Browser's local node sidecar.
//!
//! A loopback JSON-RPC server implementing the SAME `dig.getContent` contract as
//! rpc.dig.net, but LOCAL-FIRST: a `dig://` request is served from a locally
//! cached `.dig` store module (via `digstore_host::serve_blind`, which
//! instantiates the compiled module and returns a `ContentResponse` =
//! ciphertext + merkle proof + chunk_lens), and only on a cache miss is it
//! proxied to rpc.dig.net. The browser points its dig handler at this node, so
//! once a store is cached locally every resource in it is served without leaving
//! the machine. Cached store modules are evicted with an LRU size cap (default
//! 1 GiB).
//!
//! Native Rust so the compiled-module serve path (BLS, wasmtime) works.
//!
//! Cache layout: `<cache_dir>/<store_id_hex>/<root_hex>.module` — the compiled
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
use digstore_chain::coinset::Coinset;
use digstore_chain::singleton::sync_datastore;
use digstore_core::codec::{Decode, Encode};
use digstore_core::wire::ContentResponse;
use digstore_core::Bytes32;
use digstore_host::{serve_blind, BlindServeConfig};
use digstore_remote::{identity, DigClient};
use fs4::FileExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;

pub mod address_book;
pub mod bandwidth;
pub mod chainwatch;
/// Local plaintext content-serve (#289/#290): server-side verify+decrypt for the loopback
/// `GET /s/...` surface the service shell exposes to a same-machine browser (SPEC §4.6).
pub mod content_serve;
pub mod dht;
pub mod download;
pub mod net;
pub mod peer;
pub mod pex;
/// The engine side of the identity-authenticated IPC session (NODE-1 / U2, #908): the
/// `control.session.*` handshake registry + the `sign`-callback domain-separated verify, consumed from
/// the canonical `dig-ipc-protocol` contract crate (the SSOT shared with dig-app), plus the engine's
/// own **production** on-chain `DidSigningKeyResolver`. The engine holds NO user key — it only VERIFIES
/// that an attaching dig-app holds the profile's chain-published slot-`0x0010` identity key (SPEC §5.3).
pub mod session;
pub mod subscription;
/// Server-side verification ledger (#307): the bounded, short-TTL record of the per-resource
/// verify verdict + Merkle inclusion-proof data the `/s/` serve path (#289) computes, exposed
/// read-only on the loopback browser surface (`GET /verify/...`).
pub mod verification_ledger;

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
const ROOT_NOT_ANCHORED: i64 = -32005;

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

const RPC_FALLBACK: &str = "https://rpc.dig.net/";
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
    /// Upstream rpc.dig.net base URL for the JSON-RPC proxy and the §21 module
    /// sync. Defaults to [`RPC_FALLBACK`]; overridden by `DIG_NODE_UPSTREAM` (a
    /// node-specific name, distinct from the browser's own `DIG_RPC_ENDPOINT`
    /// which points the browser AT this node — reusing that name would make the
    /// node proxy to itself).
    upstream: String,
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
    /// Capsules whose background backfill (§14.3) is currently in flight, keyed `store_hex:root_hex`,
    /// so a burst of resource reads for the same not-yet-held store spawns ONE whole-`.dig` pull, not
    /// one per read. An entry is inserted before the pull spawns and removed when it finishes.
    backfilling: std::sync::Mutex<std::collections::HashSet<String>>,
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
}

/// A boxed async hook that reconciles the node's DHT provider records with its current cache
/// inventory (announce new capsules, withdraw gone ones). Installed by the standalone peer-network
/// bring-up ([`peer::spawn_peer_network`]); the FFI path installs none. The closure is `Send + Sync`
/// and returns a boxed future so the async DHT `refresh_inventory` call can be driven from the
/// FFI-safe [`Node`] without the node holding the DHT handle directly.
type InventoryRefresher =
    Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

impl Node {
    /// Install the DHT inventory-refresh hook (the standalone peer-network bring-up calls this once;
    /// the FFI path never does). Idempotent — a second install is ignored.
    pub(crate) fn set_inventory_refresher(&self, refresher: InventoryRefresher) {
        let _ = self.inventory_refresher.set(refresher);
    }

    /// Retain the live gossip pool handle (the standalone peer-network bring-up calls this once with
    /// the [`dig_gossip::GossipHandle`] it starts; the FFI path never does). Idempotent — a second
    /// install is ignored. Enables the control surface to dial peers + enumerate the connected pool.
    pub(crate) fn set_gossip_handle(&self, handle: dig_gossip::GossipHandle) {
        let _ = self.gossip.set(handle);
    }

    /// The live gossip pool handle, if the peer network is running. `None` on the FFI path (no pool)
    /// and before bring-up — callers degrade honestly (empty peer list; "no peer network" on connect).
    pub(crate) fn gossip_handle(&self) -> Option<&dig_gossip::GossipHandle> {
        self.gossip.get()
    }

    /// Refresh the node's DHT provider records against its current inventory, if a peer network is
    /// running (SPEC §14.1). A no-op on the FFI path (no hook installed) or before bring-up.
    pub(crate) async fn refresh_dht_inventory(&self) {
        if let Some(refresh) = self.inventory_refresher.get() {
            refresh().await;
        }
    }

    /// Install the WEAK self-reference (the standalone peer-network bring-up calls this once with the
    /// `Arc<Node>` it holds). Enables `&self` read handlers to spawn owned-`Arc` background tasks — the
    /// capsule backfill (§14.3). Idempotent; never set on the FFI path.
    pub(crate) fn set_self_ref(&self, weak: std::sync::Weak<Node>) {
        let _ = self.self_ref.set(weak);
    }

    /// Upgrade the weak self-reference to an owned `Arc<Node>`, if the standalone bring-up installed
    /// one and the node is still alive. `None` on the FFI path / before bring-up / during teardown.
    pub(crate) fn arc_self(&self) -> Option<Arc<Node>> {
        self.self_ref.get().and_then(std::sync::Weak::upgrade)
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
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

/// Total bytes currently held in the local cache (modules + response windows).
pub fn cache_used_bytes() -> u64 {
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
    let mut total = 0u64;
    walk(&cache_dir(), &mut total);
    total
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

/// Path of a cached store module for (store_id, root), if present. Modules live
/// under `<cache>/modules/` — populated out-of-band (a local digstore store, or
/// authed whole-store sync) and served via `serve_blind`.
fn module_path(dir: &Path, store_hex: &str, root_hex: &str) -> PathBuf {
    dir.join("modules")
        .join(store_hex)
        .join(format!("{root_hex}.module"))
}

/// Whether the module for `(store_id, root)` is held locally under `dir` — the "is this generation
/// missing?" check the chain-watch gap-fill loop keys on (SPEC §14.2). Thin over
/// [`module_path`] so the loop's held-check seam ([`chainwatch::HeldCheck`]) has one source of truth.
pub(crate) fn module_exists(dir: &Path, store_hex: &str, root_hex: &str) -> bool {
    module_path(dir, store_hex, root_hex).exists()
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
    fn is_hex64(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }
    is_hex64(store_hex) && is_hex64(root_hex)
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
    store_hex: &str,
    root_hex: &str,
    retrieval_key: &[u8; 32],
) -> Option<ContentResponse> {
    let path = module_path(cache_dir, store_hex, root_hex);
    let module = std::fs::read(&path).ok()?;
    let store_id = Bytes32::from_hex(store_hex).ok()?;
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
    store_hex: &str,
    root_hex: &str,
) -> Result<Option<Option<digstore_core::PublicManifest>>, String> {
    let path = module_path(cache_dir, store_hex, root_hex);
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
    async fn serve_local_cached(
        &self,
        store_hex: &str,
        root_hex: &str,
        retrieval_key: &[u8; 32],
    ) -> Option<Arc<ContentResponse>> {
        let key = (store_hex.to_string(), root_hex.to_string(), *retrieval_key);
        // Fast path: an in-memory hit (no disk, no decrypt).
        if let Some(hit) = self.content_cache.lock().unwrap().get(&key) {
            return Some(hit);
        }
        // Miss: read + decrypt off the async runtime (spawn_blocking), then memoize. Only the cache
        // dir + key are moved into the closure, so no Node borrow escapes into the blocking thread.
        let cache_dir = self.cache_dir.clone();
        let (store_owned, root_owned, rk) =
            (store_hex.to_string(), root_hex.to_string(), *retrieval_key);
        let decoded = tokio::task::spawn_blocking(move || {
            serve_local_blocking(&cache_dir, &store_owned, &root_owned, &rk)
        })
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

    /// Authenticated whole-store sync (§21.9) against the configured upstream §21
    /// host. Returns `true` when the synced module's served root matches the
    /// requested root, so the caller can now serve the request locally.
    async fn sync_module(&self, store_hex: &str, root_hex: &str) -> bool {
        self.sync_module_from(&self.upstream, store_hex, root_hex)
            .await
    }

    /// Core of [`Node::sync_module`], parameterized by the §21 host base URL (tests
    /// point it at a local mock). It is a no-op (returns `false`) unless an
    /// identity is configured AND the request is sync-eligible. On success it
    /// fetches the WHOLE `.dig` module from `GET /stores/{id}/module` — stamping
    /// the §21.9 `X-Dig-Identity/-Timestamp/-Nonce/-Auth` headers via the loaded
    /// identity seed — and writes it to `module_path(store, served_root)`, so
    /// `serve_local` then serves it (and every other resource in the store)
    /// without further network.
    ///
    /// The synced module is NOT cryptographically trusted here: every response the
    /// node later serves from it carries its merkle proof, which the browser
    /// verifies against the chain-anchored root — a tampered module fails THAT
    /// gate, not this sync. Sync-time verification is therefore a minimal
    /// non-empty check.
    async fn sync_module_from(&self, base_url: &str, store_hex: &str, root_hex: &str) -> bool {
        let Some(seed) = self.identity_seed else {
            return false;
        };
        if !sync_eligible(store_hex, root_hex) {
            return false;
        }
        let (Ok(store_id), Ok(want_root)) =
            (Bytes32::from_hex(store_hex), Bytes32::from_hex(root_hex))
        else {
            return false;
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
        let (served_root, bytes) = match client.clone_store(&store_id, verify, None).await {
            Ok(v) => v,
            Err(e) => {
                // Best-effort: log WHY (e.g. a §21 401/403 = the identity is not
                // authorized to clone this store) so the silent fallback to the
                // per-resource proxy is diagnosable, then give up on the sync.
                eprintln!("dig-node: §21 whole-store sync for {store_hex} skipped: {e}");
                return false;
            }
        };
        eprintln!(
            "dig-node: §21 whole-store sync for {store_hex} ok — served root {} ({} bytes)",
            served_root.to_hex(),
            bytes.len()
        );

        // Cache under the SERVED root (which may differ from want_root if the
        // remote head advanced between resolve and sync). Best-effort.
        //
        // ATOMIC + CONTENT-ADDRESSED: a module is keyed by capsule
        // (storeId:rootHash) and its bytes are immutable, so two writers (the
        // browser's in-process node + the standalone node sharing this cache)
        // produce identical bytes. `write_atomic` (temp + rename) guarantees a
        // reader never observes a torn/partial file and that the two writers
        // converge on the same final file.
        let path = module_path(&self.cache_dir, store_hex, &served_root.to_hex());
        if write_atomic(&path, &bytes).is_err() {
            return false;
        }
        served_root == want_root
    }

    /// Proxy the raw JSON-RPC body to the upstream rpc.dig.net and return its response.
    async fn proxy(&self, body: &Value) -> Result<Value, String> {
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
        fn is_hex64(s: &str) -> bool {
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        if !is_hex64(store_hex) || !is_hex64(root_hex) {
            return rpc_err(
                &id,
                -32602,
                "dig.getManifest requires store_id + root (64-hex each)",
            );
        }
        let cache_dir = self.cache_dir.clone();
        let store = store_hex.to_string();
        let root = root_hex.to_string();
        let outcome = tokio::task::spawn_blocking(move || {
            read_public_manifest_blocking(&cache_dir, &store, &root)
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
    // `module_path(store_hex, root_hex)` = `<cache>/modules/<storeId>/<root>.module`,
    // so listing/removing/fetching are all keyed by capsule identity.

    /// List every cached capsule (`storeId:rootHash`) with its on-disk size and
    /// last-used time. Walks `<cache>/modules/<storeId_hex>/<root_hex>.module`
    /// (the same layout `module_path`/`serve_local`/`sync_module_from` use),
    /// reusing the directory-enumerate pattern from [`cache_used_bytes`] and
    /// [`Node::evict_if_needed`]. `last_used_unix_ms` is the file mtime (the LRU
    /// recency stamp bumped by [`touch`] on every local serve), in Unix epoch ms.
    pub async fn cache_list_cached(&self) -> Vec<CachedCapsule> {
        let modules_root = self.cache_dir.join("modules");
        let mut out = Vec::new();
        // Outer level: one directory per store id (hex). Inner: `<root>.module`.
        let Ok(stores) = std::fs::read_dir(&modules_root) else {
            return out; // no modules cached yet
        };
        for store_entry in stores.flatten() {
            if !store_entry.path().is_dir() {
                continue;
            }
            let Some(store_hex) = store_entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(modules) = std::fs::read_dir(store_entry.path()) else {
                continue;
            };
            for m in modules.flatten() {
                let path = m.path();
                // A capsule module is `<root_hex>.module`; skip anything else.
                let Some(root_hex) = path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .and_then(|f| f.strip_suffix(".module"))
                    .map(str::to_string)
                else {
                    continue;
                };
                let Ok(md) = m.metadata() else { continue };
                let last_used_unix_ms = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                out.push(CachedCapsule {
                    store_id: store_hex.clone(),
                    root: root_hex,
                    size_bytes: md.len(),
                    last_used_unix_ms,
                });
            }
        }
        out
    }

    /// Remove one cached capsule's module by `(store_id_hex, root_hex)`. Returns
    /// `Ok(true)` if a module was unlinked, `Ok(false)` if it was already absent
    /// (idempotent), or `Err` for invalid input.
    ///
    /// PATH-TRAVERSAL DEFENSE: the hex inputs are validated 64-hex (mirroring the
    /// `response_key`/`sync_eligible` sanitization), then the resolved path is
    /// canonicalized and asserted to live UNDER the cache dir before any unlink —
    /// so a crafted `store_id`/`root` can never delete a file outside the cache.
    /// Holds the existing `cache_lock` for the unlink so it can't race eviction.
    /// (Async because that lock is a `tokio::sync::Mutex`, acquired with `.await`.)
    pub async fn cache_remove_cached(
        &self,
        store_id_hex: &str,
        root_hex: &str,
    ) -> Result<bool, String> {
        fn is_hex64(s: &str) -> bool {
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        if !is_hex64(store_id_hex) {
            return Err(format!("invalid store_id (want 64-hex): {store_id_hex}"));
        }
        if !is_hex64(root_hex) {
            return Err(format!("invalid root (want 64-hex): {root_hex}"));
        }
        let path = module_path(&self.cache_dir, store_id_hex, root_hex);

        let _guard = self.cache_lock.lock().await;
        if !path.exists() {
            return Ok(false); // nothing to remove — idempotent no-op
        }
        // Canonicalize and confirm the target is contained by the cache dir. With
        // 64-hex inputs this always holds; the check is defense-in-depth so the
        // unlink can never reach outside the cache even if the layout changes.
        let canon = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
        let cache_canon = std::fs::canonicalize(&self.cache_dir).map_err(|e| e.to_string())?;
        if !canon.starts_with(&cache_canon) {
            return Err("refusing to remove a path outside the cache dir".to_string());
        }
        std::fs::remove_file(&canon).map_err(|e| e.to_string())?;
        // Drop any in-memory decoded content for this capsule so a removed module can never still be
        // served from the content cache (audit #179).
        self.invalidate_content_cache(store_id_hex, root_hex);
        Ok(true)
    }

    /// Fetch and cache one capsule on demand over the §21 authenticated
    /// whole-store sync path (the same `sync_module_from` / `DigClient::clone_store`
    /// the local-first miss path uses, signed with the startup `identity_seed`).
    /// Returns `(size_bytes, served_root_hex)` on success.
    ///
    /// If the capsule is already cached it returns its size without re-downloading
    /// (the RPC reports `already_cached`). The cache write itself happens inside
    /// `sync_module_from`, which already serializes via the module path; this also
    /// holds the `cache_lock` around the call so concurrent on-demand fetches of
    /// the same capsule don't race each other.
    pub async fn cache_fetch_and_cache(
        &self,
        store_id_hex: &str,
        root_hex: &str,
    ) -> Result<(u64, String), String> {
        // Already cached → report its size, no network.
        let existing = module_path(&self.cache_dir, store_id_hex, root_hex);
        if let Ok(md) = std::fs::metadata(&existing) {
            return Ok((md.len(), root_hex.to_string()));
        }
        // Serialize on-demand writes so two fetches of the same capsule don't race.
        let _guard = self.cache_lock.lock().await;
        // sync_module_from returns true only when the served root == requested
        // root; either way the module lands under its SERVED root, so we read the
        // file back to report size + confirm the capsule is now present.
        let matched = self
            .sync_module_from(&self.upstream, store_id_hex, root_hex)
            .await;
        let path = module_path(&self.cache_dir, store_id_hex, root_hex);
        match std::fs::metadata(&path) {
            Ok(md) => Ok((md.len(), root_hex.to_string())),
            Err(_) if matched => {
                // matched but no file: should not happen, surface it.
                Err("sync reported a match but the module is not cached".to_string())
            }
            Err(_) => Err(format!(
                "could not fetch capsule {store_id_hex}:{root_hex} (no §21 identity, \
                 not authorized, or served root differs)"
            )),
        }
    }

    /// GAP-FILL one missing generation (SPEC §14.3): pull the whole `.dig` module for
    /// `(store_id, root)` down from other nodes, verify it against the chain-anchored root, land it in
    /// the local cache, and (best-effort) refresh the DHT provider records so peers immediately find
    /// this node as a NEW holder of the just-synced capsule (§14.1). Idempotent — an already-held
    /// generation is a cheap success with no network.
    ///
    /// The pull reuses the authenticated whole-store sync ([`Self::cache_fetch_and_cache`] →
    /// `sync_module_from`), which lands the module keyed by capsule `(store, root)`. The
    /// VERIFICATION INVARIANT (SPEC §14.3) is upheld at every SERVE: a gap-filled module is never served
    /// as current unless its root equals the chain-anchored tip (the read-path pin, §14.4), so a
    /// tampered or wrong-generation pull can never be served — the same guarantee whether the module
    /// arrived via a client read, a §21 sync, or this proactive gap-fill.
    ///
    /// `root` is passed as [`Bytes32`] (the chain-anchored tip the watcher resolved), so gap-fill
    /// always targets a chain-confirmed generation — never a caller-chosen root.
    pub async fn gap_fill_generation(
        &self,
        store_id: [u8; 32],
        root: Bytes32,
    ) -> Result<(), String> {
        let store_hex = hex::encode(store_id);
        let root_hex = root.to_hex();
        // Already held → nothing to pull (idempotent).
        if module_exists(&self.cache_dir, &store_hex, &root_hex) {
            return Ok(());
        }
        // Pull + cache the whole module under (store, root) via the authenticated §21 whole-store sync.
        // `cache_fetch_and_cache` serializes concurrent pulls of the same capsule and reports the
        // failure reason (no identity / not authorized / served root differs) on error.
        self.cache_fetch_and_cache(&store_hex, &root_hex).await?;

        // Confirm the generation actually landed (a sync whose served root differed leaves it absent).
        if !module_exists(&self.cache_dir, &store_hex, &root_hex) {
            return Err(format!(
                "gap-fill for {store_hex}:{root_hex} pulled a module but not at the confirmed root"
            ));
        }

        // Best-effort: refresh the DHT provider records so peers find this node as a holder of the
        // newly-synced capsule (§14.1). The peer-network bring-up installs the announce hook; when no
        // peer network is running (FFI path) this is a no-op.
        self.refresh_dht_inventory().await;
        Ok(())
    }

    // -- L7 peer RPC (PHASE-2b, #162) — serving the node's LOCAL inventory ------
    //
    // The node serves the SAME content over the peer network that it serves over §21 / the HTTP read
    // path: the capsules cached on disk. These build the L7 answers (`dig.getAvailability`,
    // `dig.listInventory`, `dig.fetchRange`, `dig.getNetworkInfo`) from `cache_list_cached()` +
    // `serve_local`. They are pure reads of local state (no chain, no upstream), so a peer only ever
    // learns what this node already holds. Every byte a peer fetches carries its own merkle proof
    // (verified by the caller against the chain-anchored root), so the node is never the trust anchor.

    /// The node's own `peer_id` (64-hex) = SHA-256(SPKI DER) of its PERSISTENT, CA-signed
    /// [`NodeCert`](dig_nat::NodeCert), or `None` if no identity seed is configured. This is the mTLS
    /// identity the node presents on every peer path (loaded from — or minted into — the node's cert
    /// dir, so it is stable across restarts; see [`peer::load_or_generate_node_cert`]).
    pub fn peer_id_hex(&self) -> Option<String> {
        let seed = self.identity_seed?;
        peer::load_or_generate_node_cert(self.node_cert_dir(), &seed)
            .ok()
            .map(|cert| cert.peer_id().to_hex())
    }

    /// `dig.getAvailability` — answer one queried item against the local inventory, enriching the
    /// pure presence answer (`peer::availability_presence`) with the per-resource `total_length` +
    /// `chunk_count` when the item is at resource granularity (`store_id` + `root` + `retrieval_key`)
    /// and the resource is actually served locally. Returns one `AvailabilityAnswer` value.
    ///
    /// Takes a `cached` inventory SNAPSHOT (audit #179): the caller
    /// ([`Node::availability_batch`]) walks the cache directory ONCE per batch and passes the slice
    /// in, so an N-item batch does O(1) directory walks instead of O(N).
    async fn availability_answer(&self, item: &Value, cached: &[CachedCapsule]) -> Value {
        let store = item.get("store_id").and_then(Value::as_str).unwrap_or("");
        let root = item.get("root").and_then(Value::as_str);
        let rk = item.get("retrieval_key").and_then(Value::as_str);
        let mut answer = peer::availability_presence(cached, store, root, rk);

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
    /// The cache inventory is snapshotted ONCE here and shared across every item (audit #179): each
    /// answer used to walk the whole `<cache>/modules` directory, so an N-item batch did N full
    /// directory walks; it now does one. The batch is CAPPED at [`MAX_AVAILABILITY_ITEMS`] — this is
    /// a peer-reachable path (§7.4) and the item count is caller-controlled — with the excess simply
    /// not answered (the result array is aligned to the answered prefix).
    pub async fn availability_batch(&self, items: &[Value]) -> Value {
        let capped = &items[..items.len().min(MAX_AVAILABILITY_ITEMS)];
        // One directory walk for the whole batch (was one per item).
        let cached = self.cache_list_cached().await;
        let mut answers = Vec::with_capacity(capped.len());
        for item in capped {
            answers.push(self.availability_answer(item, &cached).await);
        }
        json!({ "items": answers })
    }

    /// `dig.fetchRange` — build ONE range frame (the node window is a single frame; the caller streams
    /// further windows by advancing `offset`). Serves the resource's ciphertext from a locally cached
    /// module and slices `[offset, offset+length)` (clamped to the node window). The FIRST frame
    /// (`offset == 0`) carries the verification metadata (`total_length`, `chunk_lens`, `chunk_index`,
    /// `inclusion_proof`, `root`) so the range is independently verifiable against the chain-anchored
    /// root. Returns `Err((code, message))` with the catalogued `-32004`/`-32007` on a miss / bad
    /// range. (Capsule fetches — `capsule: true` — are not yet served here; that lands with the whole
    /// `.dig` streaming path and returns `-32004` for now, a clean seam.)
    pub async fn fetch_range_frame(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
        offset: usize,
        length: usize,
    ) -> Result<Value, (i64, String)> {
        let rk = decode_rk(rk_hex).map_err(|_| {
            (
                -32602,
                "retrieval_key must be 32 bytes (64-hex)".to_string(),
            )
        })?;
        let resp = self
            .serve_local_cached(store_hex, root_hex, &rk)
            .await
            .ok_or((
                -32004,
                "resource not held at the requested root".to_string(),
            ))?;

        let total = resp.ciphertext.len();
        // offset past the end is unsatisfiable (spec -32007). offset == total is the empty terminal.
        if offset > total {
            return Err((
                -32007,
                format!("offset {offset} beyond resource length {total}"),
            ));
        }
        let start = offset.min(total);
        let end = (start + length.min(peer::RANGE_WINDOW)).min(total);
        let window = resp.ciphertext[start..end].to_vec();
        let complete = end >= total;

        let mut frame = json!({
            "offset": start,
            "length": window.len(),
            "bytes": base64::engine::general_purpose::STANDARD.encode(&window),
            "complete": complete,
        });
        // First frame carries the per-range verification metadata (spec §9).
        if start == 0 {
            if let Some(obj) = frame.as_object_mut() {
                obj.insert("total_length".into(), json!(total));
                obj.insert("chunk_lens".into(), json!(resp.chunk_lens));
                obj.insert("chunk_index".into(), json!(0));
                obj.insert(
                    "inclusion_proof".into(),
                    json!(base64::engine::general_purpose::STANDARD
                        .encode(resp.merkle_proof.to_bytes())),
                );
                obj.insert("root".into(), json!(resp.roothash.to_hex()));
            }
        }
        Ok(frame)
    }

    /// `dig.getNetworkInfo` — this node's own network posture: its `peer_id`, network id, listen
    /// address, candidate addresses, reachability, and relay-reservation state. Reads the shared
    /// [`peer::PeerStatus`] so it reflects the live pool/relay state (or "not running" in the FFI
    /// path). Never touches the chain or an upstream.
    pub fn network_info(&self) -> Value {
        let peer_id = self.peer_id_hex();
        let network_id = peer::network_id_from_env();
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
        let snap = self.peer_status.snapshot_json(&endpoint, &network_id);
        let reserved = snap["relay"]["reserved"].as_bool().unwrap_or(false);
        // Conservative, honest reachability: while a relay reservation is held we report "relayed"
        // (a NAT'd node reached via the relay). A confirmed direct inbound mapping (UPnP/NAT-PMP/PCP)
        // is not yet surfaced by the pool, so "direct" is reported only when no relay is in use rather
        // than claimed without evidence. (A future mapping-probe upgrades this to "direct".)
        let reachability = if reserved { "relayed" } else { "direct" };
        json!({
            "peer_id": peer_id,
            "network_id": network_id,
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
    /// Generation root hash (lowercase 64-hex) — the `<root>.module` file stem.
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

/// Coinset client used to resolve chain-anchored roots. `DIG_NODE_COINSET`
/// overrides the API base (tests / alternate endpoints); defaults to mainnet
/// (api.coinset.org).
fn resolution_coinset() -> Coinset {
    match std::env::var("DIG_NODE_COINSET") {
        Ok(url) if !url.is_empty() => Coinset::with_url(url),
        _ => Coinset::mainnet(),
    }
}

/// Resolve a store's CHIP-0035 chain-anchored TIP root. This is the trusted-root
/// source for the MANDATORY read-path pin (#127): a content read serves against
/// the on-chain current root or fails closed — it never trusts an upstream-/
/// host-reported root.
///
/// Implemented as a trait so the read-path pin is unit-testable without a live
/// chain: production uses [`CoinsetResolver`] (walks the singleton lineage on
/// coinset.org); tests inject a deterministic resolver. `Ok(Some(root))` = the
/// resolved tip; `Ok(None)` = the store is not minted / has no confirmed
/// generation (treated as fail-closed by the caller); `Err` = the chain was
/// unreachable (also fail-closed).
#[async_trait::async_trait]
pub trait AnchoredRootResolver: Send + Sync {
    /// Resolve `store_id`'s current on-chain root, or `None` if the store has no
    /// confirmed generation yet, or `Err` if the chain is unreachable.
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String>;

    /// The richer form of [`anchored_root`](Self::anchored_root): the SAME resolution, ALSO
    /// carrying the store's current on-chain OWNER puzzle hash — the future tip recipient
    /// surfaced by the local content-serve path as `X-Dig-Owner-Puzzle-Hash` (#486). Default
    /// impl wraps `anchored_root` with `owner_puzzle_hash: None` (used by resolvers — e.g. test
    /// mocks — that only know the root). [`CoinsetResolver`] overrides this to capture BOTH
    /// fields from the single `sync_datastore` walk it already performs, so content-serve never
    /// needs a second coinset round trip to learn the owner.
    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        Ok(self
            .anchored_root(store_id)
            .await?
            .map(|root| AnchoredStoreState {
                root,
                owner_puzzle_hash: None,
            }))
    }
}

/// The store's on-chain DataStore singleton state, as resolved by walking its lineage to the
/// unspent tip (`sync_datastore`): its CURRENT content root (the read-path anchor, #127) and its
/// CURRENT owner puzzle hash (the tip recipient, #486). Bundled because both come from the SAME
/// chain read — no second coinset call is needed to serve owner metadata alongside the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoredStoreState {
    pub root: Bytes32,
    /// `None` when the resolver cannot supply it (see [`AnchoredRootResolver::anchored_state`]'s
    /// default impl) — content-serve OMITS `X-Dig-Owner-Puzzle-Hash` rather than guess.
    pub owner_puzzle_hash: Option<Bytes32>,
}

/// Production resolver: walks the store's DataStore singleton lineage on
/// coinset.org (`digstore_chain::singleton::sync_datastore`) to the unspent tip
/// and returns its metadata root — exactly the source `dig.getAnchoredRoot` and
/// `dig-resolver` already use, and the same authority the CLI clone/pull pin
/// resolves against (`current_root`). NEVER consults the serving node.
struct CoinsetResolver;

#[async_trait::async_trait]
impl AnchoredRootResolver for CoinsetResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(self.anchored_state(store_id).await?.map(|s| s.root))
    }

    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        let launcher = chia_protocol::Bytes32::new(*store_id);
        match sync_datastore(&resolution_coinset(), launcher).await {
            Ok(store) => {
                // Convert chia_protocol::Bytes32 → digstore_core::Bytes32 (the
                // node's content-root type), mirroring the CLI clone/pull pin.
                let mut a = [0u8; 32];
                a.copy_from_slice(store.info.metadata.root_hash.as_ref());
                let mut o = [0u8; 32];
                o.copy_from_slice(store.info.owner_puzzle_hash.as_ref());
                Ok(Some(AnchoredStoreState {
                    root: Bytes32(a),
                    owner_puzzle_hash: Some(Bytes32(o)),
                }))
            }
            Err(e) => {
                // A "not minted yet" / "launcher unspent" lineage error is a
                // legitimate absence (no confirmed generation), distinct from an
                // unreachable chain. Either way the read FAILS CLOSED at the
                // caller; we only distinguish them for a clearer error message.
                let msg = e.to_string();
                if msg.contains("not minted") || msg.contains("unspent") {
                    Ok(None)
                } else {
                    Err(msg)
                }
            }
        }
    }
}

/// The default anchored-root resolver (production coinset walk).
fn default_anchored_resolver() -> Arc<dyn AnchoredRootResolver> {
    Arc::new(CoinsetResolver)
}

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
pub async fn handle_rpc_json(node: &Node, req_json: &str) -> String {
    let req: Value = match serde_json::from_str(req_json) {
        Ok(v) => v,
        Err(e) => {
            return json!({"jsonrpc":"2.0","id":null,
                "error":{"code":-32700,"message":format!("parse error: {e}")}})
            .to_string()
        }
    };
    handle_rpc(node, req).await.to_string()
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
pub async fn handle_rpc(node: &Node, req: Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(json!(1));
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    use dig_rpc_protocol::Method;
    // Dispatch on the canonical Method enum (dig-rpc-protocol, #1075) instead of
    // string literals, so the served method names cannot drift from the shared
    // node<->node contract. A name this core engine does not serve — the shell's
    // discovery aliases (dig.getCapsule / dig.getProof / …) or an unknown method —
    // falls to the `_` arm's method-not-found; dig.getContent falls through to the
    // read block after the match.
    match Method::from_name(method) {
        // dig.getAnchoredRoot: resolve a store's chain-anchored tip root (the TRUSTED
        // root for the browser's mandatory dig:// root-pinning — see anchored_root).
        Some(Method::GetAnchoredRoot) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            return node.anchored_root(&params, id).await;
        }
        // dig.getManifest (#176 Phase C): the normalized PublicManifest (data-section id 13)
        // embedded in a specific CAPSULE's (store_id:root) compiled `.dig` module — the store's
        // complete public file surface (latest version per path) as of that commit. PUBLIC,
        // unencrypted data, so no retrieval_key is needed. Served LOCALLY now (was a blind
        // passthrough alias before #176): see `Node::get_manifest`.
        Some(Method::GetManifest) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            return node.get_manifest(&params, id).await;
        }
        // dig.stage (#95 Pass C): turn a local folder into a capsule (.dig module) IN
        // PROCESS — the staging/compile half of a local deploy. The DIG Browser's
        // in-process node calls this (no CLI binary) to produce the artifact, then
        // signs the on-chain root advance via the Pass B `chia_advanceStore` wallet
        // method and §21-pushes the module. ADDITIVE — no existing method is touched.
        Some(Method::Stage) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            return node.stage(&params, id);
        }
        // dig.getCollection / dig.listCollectionItems (#39): PUBLIC, owner-independent
        // collection reads computed from DIG's own coinset data — no third-party indexer.
        // Read-only (no spend bundles). The item set is the NFT launcher ids the mint
        // produced (the authoritative, owner-independent anchor; see
        // digstore_chain::collection_index for why launcher ids, not the creator DID
        // hint, are the discovery key). Each item is resolved to its CURRENT on-chain
        // owner + royalty + CHIP-0007 metadata by walking the singleton lineage forward.
        Some(Method::GetCollection) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            return Node::get_collection(&params, id).await;
        }
        Some(Method::ListCollectionItems) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            return Node::list_collection_items(&params, id).await;
        }
        // -- L7 peer RPC (PHASE-2b, #162) — the node-profile peer-network methods -----------------------
        //
        // Additive JSON-RPC methods that expose the peer network over the node's RPC surface, so an agent
        // (or the peer transport's JSON-RPC stream path) drives discovery + availability + range fetch
        // without speaking the binary peer protocol. They are served here (over §21/FFI AND over an
        // inbound mTLS peer stream, which routes JSON-RPC frames through this same dispatch). See
        // docs.dig.net → L7 · DIG Node peer network + openrpc-node.json.
        Some(Method::GetNetworkInfo) => {
            // This node's own posture (identity, reachability, candidate addrs, relay reservation).
            return json!({"jsonrpc":"2.0","id":id,"result": node.network_info()});
        }
        Some(Method::GetPeers) => {
            // The peers this node currently knows (peer-exchange over RPC). The connected-pool source is
            // owned by the live GossipService in the standalone run(); the node struct here does not hold
            // the gossip handle (it stays FFI-safe), so this base dispatch returns the node's own view:
            // an empty peer list when no pool is wired. The standalone peer-network task answers inbound
            // `dig.getPeers` from the live pool via its own responder override (see peer::PoolResponder).
            return json!({"jsonrpc":"2.0","id":id,"result": {"peers": []}});
        }
        Some(Method::Announce) => {
            // Accept an announcement (peer_id + candidate addresses). The base node has no pool to fold it
            // into, so it acknowledges without growing a peer view; the live peer-network task overrides
            // this to register the announced peer with the pool/introducer. Validates the required params.
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let peer_id_ok = params
                .get("peer_id")
                .and_then(Value::as_str)
                .map(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .unwrap_or(false);
            let has_addrs = params
                .get("addresses")
                .map(Value::is_array)
                .unwrap_or(false);
            if !peer_id_ok || !has_addrs {
                return rpc_err(
                    &id,
                    -32602,
                    "dig.announce requires peer_id (64-hex) + addresses (array)",
                );
            }
            return json!({"jsonrpc":"2.0","id":id,"result": {"accepted": true, "known_peers": 0}});
        }
        Some(Method::GetAvailability) => {
            // Batch-answer whether this node holds the queried stores/roots/capsules (from local
            // inventory), so a downloader confirms holders + plans ranges before any fetch.
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let items = match params.get("items").and_then(Value::as_array) {
                Some(items) => items.clone(),
                None => {
                    return rpc_err(
                        &id,
                        -32602,
                        "dig.getAvailability requires params.items (array)",
                    )
                }
            };
            return json!({"jsonrpc":"2.0","id":id,"result": node.availability_batch(&items).await});
        }
        Some(Method::ListInventory) => {
            // Enumerate what this node serves: its stores, or the roots it holds for a given store.
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_id = params.get("store_id").and_then(Value::as_str);
            if let Some(s) = store_id {
                if !(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
                    return rpc_err(&id, -32602, "store_id must be 64-hex");
                }
            }
            let limit = params
                .get("limit")
                .and_then(Value::as_u64)
                .map(|n| n as usize);
            let cached = node.cache_list_cached().await;
            return json!({"jsonrpc":"2.0","id":id,
            "result": peer::list_inventory(&cached, store_id, limit)});
        }
        Some(Method::FetchRange) => {
            // A single range frame of a resource this node holds (the JSON-RPC face of the streamed
            // peer-transport range fetch; the caller advances `offset` for further windows). The frame
            // carries the per-range verification metadata on the first window.
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_hex = params.get("store_id").and_then(Value::as_str).unwrap_or("");
            let root_hex = params.get("root").and_then(Value::as_str).unwrap_or("");
            let rk_hex = params
                .get("retrieval_key")
                .and_then(Value::as_str)
                .unwrap_or("");
            let capsule = params
                .get("capsule")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
            let length = params.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
            if store_hex.len() != 64 || length == 0 {
                return rpc_err(
                    &id,
                    -32602,
                    "dig.fetchRange requires store_id (64-hex) + length (>0)",
                );
            }
            if capsule {
                // Whole-capsule streaming is a clean follow-up seam (the .dig streaming path); resource
                // range fetch is served now. Report the catalogued unavailable code for capsule mode.
                return rpc_err(
                    &id,
                    -32004,
                    "capsule range fetch not served by this node yet (use resource retrieval_key)",
                );
            }
            if rk_hex.len() != 64 || root_hex.len() != 64 {
                return rpc_err(
                    &id,
                    -32602,
                    "resource fetchRange requires retrieval_key + root (64-hex each)",
                );
            }
            return match node
                .fetch_range_frame(store_hex, root_hex, rk_hex, offset, length)
                .await
            {
                Ok(frame) => {
                    // OUTGOING-BANDWIDTH THROTTLE (#30): this node HOLDS the range, but serving it now
                    // may push it over its configured cap — redirect to a known holder instead (same
                    // #165 redirect shape) with a graceful serve-anyway fallback when none is known.
                    let bytes = frame.get("length").and_then(Value::as_u64).unwrap_or(0);
                    let depth = download::redirect_depth(&params);
                    if let Some(obj) = node
                        .bandwidth_redirect_for(store_hex, root_hex, rk_hex, bytes, depth)
                        .await
                    {
                        return json!({"jsonrpc":"2.0","id":id,"error":obj});
                    }
                    node.record_outgoing_bytes(bytes);
                    json!({"jsonrpc":"2.0","id":id,"result": frame})
                }
                // A LOCAL MISS (-32004): try the #165 P2P miss path — redirect to a holder (default) or
                // fetch-through via dig-download — before returning the bare not-found. An empty engine
                // (FFI path) or no provider yields `None` and the original error stands (no silent 404
                // when a provider exists). Other errors (e.g. -32007 bad range) pass through unchanged.
                Err((code, message)) => {
                    if code == download::RESOURCE_UNAVAILABLE {
                        if let Some(content) =
                            download::miss_content_for(store_hex, root_hex, rk_hex)
                        {
                            let depth = download::redirect_depth(&params);
                            if let Some(envelope) = node
                                .range_miss_envelope(&id, &content, depth, offset, length)
                                .await
                            {
                                // Served from another node — background-backfill the whole capsule so the
                                // next read is local (SPEC §14.3). Deduped + detached; no delay here.
                                node.maybe_backfill_capsule(store_hex, root_hex);
                                return envelope;
                            }
                        }
                    }
                    rpc_err(&id, code, &message)
                }
            };
        }
        // cache.* — the local-cache config for the chrome://settings DIG section.
        // The browser's Mojo handler reaches these via the in-process CallDigRpc FFI;
        // dig-node owns the cache, so it is the single source of truth (same fns the
        // dig-wallet /api/dig-config endpoint uses).
        Some(Method::CacheGetConfig) => {
            // ADDITIVE fields (#96): `cache_dir` = the effective resolved cache path,
            // `shared` = whether that path is the canonical dir shared with the
            // standalone dig-node / dig-companion (`false` = a process-private
            // fallback because the canonical dir was unwritable). Existing
            // `cap_bytes`/`used_bytes` are UNCHANGED — the FFI contract is
            // additive-only (see SYSTEM.md change-impact + the regression test).
            let (dir, shared) = resolve_cache_dir();
            return json!({"jsonrpc":"2.0","id":id,"result":{
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
            "cache_dir": dir.display().to_string(),
            "shared": shared}});
        }
        // control.peerStatus — live, pool-oriented status of the node's L7 peer network (the connected
        // peer pool + the relay reservation for NAT reachability). Read-only; safe before/without a peer
        // network running (then `running:false`). Replaces the retired `control.relayStatus`: relay
        // reachability now lives in dig-nat/dig-gossip and is reported here as the pool's relay flag.
        Some(Method::ControlPeerStatus) => {
            let endpoint = peer::relay_url_from_env();
            let network_id = peer::network_id_from_env();
            let mut snapshot = node.peer_status.snapshot_json(&endpoint, &network_id);
            // Attach the per-peer array so the A↔B mutual-connection proof is machine-checkable (each
            // side lists the OTHER's peer_id), not just a count. Sourced from the live pool handle; empty
            // (and omitted-as-`[]`) on the FFI path / before bring-up. See `peer::connected_peers_json`.
            if let Some(handle) = node.gossip_handle() {
                snapshot["peers"] = Value::Array(peer::connected_peers_json(handle));
            }
            return json!({"jsonrpc":"2.0","id":id, "result": snapshot});
        }
        // control.peers.connect — dial a peer by address (or resolve an already-connected peer_id) via the
        // live gossip pool, turning a relay-DISCOVERED peer into a COUNTED, RPC-reachable connected peer
        // (#929). CONTROL-plane: reachable ONLY from the loopback admin / in-process FFI dispatch, NEVER
        // over the mTLS peer surface (absent from `is_peer_reachable_method`). Deterministic success /
        // failure; a no-op "no peer network" on the FFI path (no pool handle retained).
        Some(Method::ControlPeersConnect) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let peer = params.get("peer").and_then(Value::as_str).unwrap_or("");
            let Some(handle) = node.gossip_handle() else {
                return control_err(
                    &id,
                    CONTROL_ERROR,
                    "no peer network is running on this node",
                );
            };
            return match peer::connect_peer(handle, peer).await {
                Ok(peer_id) => json!({"jsonrpc":"2.0","id":id,
                "result": {"connected": true, "peer_id": peer_id}}),
                Err(e) => control_err(&id, CONTROL_ERROR, &format!("connect failed: {e}")),
            };
        }
        // control.peers.disconnect — drop a pooled peer by peer_id, closing its mTLS link (the inverse of
        // control.peers.connect). CONTROL-plane: loopback admin / in-process FFI ONLY, NEVER over the mTLS
        // peer surface (absent from `is_peer_reachable_method`). Idempotent: disconnecting a peer that is
        // not connected succeeds as a no-op. A no-op "no peer network" on the FFI path.
        Some(Method::ControlPeersDisconnect) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let peer = params.get("peer").and_then(Value::as_str).unwrap_or("");
            let Some(handle) = node.gossip_handle() else {
                return control_err(
                    &id,
                    CONTROL_ERROR,
                    "no peer network is running on this node",
                );
            };
            return match peer::disconnect_peer(handle, peer).await {
                Ok(()) => json!({"jsonrpc":"2.0","id":id,
                "result": {"disconnected": true, "peer_id": peer.trim().to_ascii_lowercase()}}),
                Err(e) => control_err(&id, CONTROL_ERROR, &format!("disconnect failed: {e}")),
            };
        }
        // control.subscribe / control.unsubscribe / control.listSubscriptions (SPEC §6) — manage the
        // node's OWN persisted set of subscribed stores (the stores it actively watches + gap-fills). These
        // are CONTROL-plane methods: reachable ONLY from the loopback admin server / in-process FFI
        // dispatch, NEVER over the mTLS peer surface (they are absent from `is_peer_reachable_method`, so
        // the peer responder answers `-32601` before dispatch). Errors carry the canonical control-plane
        // taxonomy (`-32030`/`-32032`, `data.code`/`data.origin`; dig-rpc-types §10).
        Some(Method::ControlSubscribe) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_id = params.get("store_id").and_then(Value::as_str).unwrap_or("");
            return match subscribe_store(store_id) {
                Ok(added) => {
                    // A newly-subscribed store is reconciled promptly (the watch loop also polls it on its
                    // interval); a refresh of the DHT inventory is not needed here (subscription != held).
                    json!({"jsonrpc":"2.0","id":id,"result":{
                    "subscribed": true,
                    "added": added,
                    // Echo the CANONICAL persisted id (trimmed + lower-cased), so the response can
                    // never disagree with control.listSubscriptions.
                    "store_id": subscription::normalize_store_id(store_id)}})
                }
                Err(e) => control_err(&id, CONTROL_ERROR, &format!("subscribe failed: {e}")),
            };
        }
        Some(Method::ControlUnsubscribe) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_id = params.get("store_id").and_then(Value::as_str).unwrap_or("");
            return match unsubscribe_store(store_id) {
                Ok(removed) => json!({"jsonrpc":"2.0","id":id,"result":{
                "subscribed": false,
                "removed": removed,
                "store_id": subscription::normalize_store_id(store_id)}}),
                Err(e) => control_err(&id, CONTROL_ERROR, &format!("unsubscribe failed: {e}")),
            };
        }
        Some(Method::ControlListSubscriptions) => {
            let set = load_subscriptions();
            return json!({"jsonrpc":"2.0","id":id,"result":{
            "subscriptions": set.stores(),
            "count": set.len()}});
        }
        Some(Method::CacheSetCapBytes) => {
            let requested = req
                .get("params")
                .and_then(|p| p.get("cap_bytes"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // Floor at 64 MiB so a stray 0 can't disable caching (mirrors dig-wallet).
            let cap = requested.max(64 * 1024 * 1024);
            return match set_cache_cap_bytes(cap) {
                Ok(()) => json!({"jsonrpc":"2.0","id":id,"result":{"cap_bytes": cap}}),
                // A config write failure is a control-plane runtime error (canonical taxonomy §10).
                Err(e) => control_err(&id, CONTROL_ERROR, &e.to_string()),
            };
        }
        Some(Method::CacheClear) => {
            clear_cache();
            // Also drop the in-memory decoded-content cache so a cleared capsule can't still be served
            // from RAM (audit #179).
            node.clear_content_cache();
            return json!({"jsonrpc":"2.0","id":id,"result":{}});
        }
        // cache.listCached / removeCached / fetchAndCache — the cached-store manager
        // (task #32). Each cached module is a CAPSULE (storeId:rootHash), so these are
        // keyed by capsule identity (`digstore_core::Capsule`).
        Some(Method::CacheListCached) => {
            let list = node.cache_list_cached().await;
            // #279: attach `lru_rank` to each entry so a controller can render the
            // eviction order without re-deriving it. Rank 0 = the LEAST-recently-used
            // capsule (the NEXT one the size cap would evict), increasing with recency
            // — the same oldest-mtime-first order `plan_eviction` uses. Computed here
            // (a view concept) rather than on `CachedCapsule` (kept a plain fact).
            let mut order: Vec<usize> = (0..list.len()).collect();
            order.sort_by_key(|&i| (list[i].last_used_unix_ms, i));
            let mut rank_of = vec![0u64; list.len()];
            for (rank, &i) in order.iter().enumerate() {
                rank_of[i] = rank as u64;
            }
            let cached: Vec<Value> = list
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    json!({
                        // The canonical capsule string identity (storeId:rootHash),
                        // identical to digstore_core::Capsule::canonical().
                        "capsule": format!("{}:{}", c.store_id, c.root),
                        "store_id": c.store_id,
                        "root": c.root,
                        "size_bytes": c.size_bytes,
                        "last_used_unix_ms": c.last_used_unix_ms,
                        // #279: LRU/eviction order — 0 = next to be evicted.
                        "lru_rank": rank_of[i],
                    })
                })
                .collect();
            return json!({"jsonrpc":"2.0","id":id,"result":{"cached": cached}});
        }
        Some(Method::CacheStats) => {
            // #279: OPEN cache telemetry beside `cache.getConfig` — the reserved cap +
            // live usage, the cached-capsule count and their total on-disk bytes, and
            // the session eviction + decoded-content hit/miss counters. All additive.
            let list = node.cache_list_cached().await;
            let entry_count = list.len() as u64;
            let total_bytes: u64 = list.iter().map(|c| c.size_bytes).sum();
            use std::sync::atomic::Ordering::Relaxed;
            return json!({"jsonrpc":"2.0","id":id,"result":{
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
            "entry_count": entry_count,
            "total_bytes": total_bytes,
            "evicted_count": CACHE_EVICTED_COUNT.load(Relaxed),
            "evicted_bytes": CACHE_EVICTED_BYTES.load(Relaxed),
            "content_cache": {
                "hits": CONTENT_CACHE_HITS.load(Relaxed),
                "misses": CONTENT_CACHE_MISSES.load(Relaxed),
            }}});
        }
        Some(Method::CacheRemoveCached) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_hex = params
                .get("store_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
            return match node.cache_remove_cached(store_hex, root_hex).await {
                Ok(removed) => json!({"jsonrpc":"2.0","id":id,"result":{"removed": removed}}),
                Err(e) => json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32602,"message": e}}),
            };
        }
        Some(Method::CacheFetchAndCache) => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let store_hex = params
                .get("store_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
            // Was it already present before this call? (so we can report
            // already_cached vs a fresh cached, per the spec's status field.)
            let already = module_path(&node.cache_dir, store_hex, root_hex).exists();
            return match node.cache_fetch_and_cache(store_hex, root_hex).await {
                Ok((size_bytes, served_root)) => {
                    // A freshly-cached capsule entered the served set — refresh the DHT provider records so
                    // peers immediately find this node as a holder (§14.1). No-op on the FFI path / before
                    // peer-network bring-up. (Already-cached is unchanged inventory, so skip the refresh.)
                    if !already {
                        node.refresh_dht_inventory().await;
                    }
                    json!({"jsonrpc":"2.0","id":id,"result":{
                    "status": if already { "already_cached" } else { "cached" },
                    "size_bytes": size_bytes,
                    "served_root": served_root}})
                }
                // A failed fetch is reported in-band (status:"failed") so the settings
                // manager can show it without treating it as a transport error.
                Err(e) => json!({"jsonrpc":"2.0","id":id,"result":{
                "status": "failed",
                "message": e}}),
            };
        }
        // dig.getContent is the canonical local read — the default branch, handled by the
        // block below the match. Everything the crate catalogues but this core engine does
        // not serve locally (the shell's passthrough aliases: getCapsule / getModule /
        // getMetadata / getProof / getProofStatus / listCapsules / health / methods /
        // rpc.discover) AND any unknown method fall through to method-not-found — exactly
        // the pre-adoption behaviour (the shell relays those to the upstream on a -32601).
        Some(Method::GetContent) => {}
        _ => {
            return json!({"jsonrpc":"2.0","id":id,
            "error":{"code":-32601,"message":"method not found"}});
        }
    }
    let params = req.get("params").cloned().unwrap_or(json!({}));
    let store_hex = params
        .get("store_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let requested_root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
    let rk_hex = params
        .get("retrieval_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let err = |id: &Value, code: i64, msg: String| -> Value {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
    };

    // -- MANDATORY anchored-root pin (#127) ------------------------------------
    //
    // Before serving ANY content (local module, §21 sync, cached window, or an
    // upstream proxy), resolve the store's CHIP-0035 chain-anchored TIP root and
    // require the served generation to BE that root, or FAIL CLOSED. The chain —
    // not the request, the cached module, or the upstream — is the authority over
    // which generation is served. A rootless request resolves to the chain tip; an
    // explicit root must equal it. This is the same pin the CLI clone/pull enforce,
    // now uniform across the node read path (a compromised upstream can no longer
    // choose the served generation).
    let store_id_arr = match parse_store_id_arg(&params) {
        Ok(b) => b.into(),
        Err(()) => {
            return err(
                &id,
                -32602,
                "params.store_id must be a 32-byte (64-hex) launcher id".into(),
            )
        }
    };
    // A concrete, valid requested root (non-empty, 64-hex). The `"latest"`
    // sentinel and any malformed value are treated as ROOTLESS (resolve the tip).
    let requested_root = Bytes32::from_hex(requested_root_hex).ok();
    let pinned_root: Option<Bytes32> = if pin_enforced() {
        let anchored = node
            .anchored_root_resolver
            .anchored_root(&store_id_arr)
            .await;
        match decide_pin(true, requested_root, anchored) {
            PinDecision::ServeAt(root) => Some(root),
            PinDecision::Reject(code, msg) => return err(&id, code, msg),
            // `decide_pin(true, ..)` never returns Unpinned.
            PinDecision::Unpinned => requested_root,
        }
    } else {
        // Pin disabled (DIG_NODE_PIN=off, offline/local dev): serve against the
        // requested root as-is; the client still verifies against its trust root.
        requested_root
    };

    // The concrete root hash everything below serves against. With the pin on this
    // is the chain-anchored tip; with it off it is the requested root (or empty).
    let root_hex = pinned_root
        .map(|r| r.to_hex())
        .unwrap_or_else(|| requested_root_hex.to_string());

    // Tag the result with where it was served from so the browser can show a
    // "local" chip: "local" = from this device's cache (a compiled module or a
    // previously-cached window), "remote" = freshly fetched from rpc.dig.net.
    let local = |id: &Value, mut result: Value| -> Value {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("source".into(), json!("local"));
        }
        json!({"jsonrpc":"2.0","id":id,"result":result})
    };

    // 1. LOCAL-FIRST: serve from a cached compiled module (no network at all). The
    //    served module's own root MUST equal the pinned chain-anchored root — a
    //    cached module whose generation is not the anchored tip is rejected (it is
    //    not served as if current).
    // OUTGOING-BANDWIDTH THROTTLE (dig_ecosystem #30): before serving a LOCAL-FIRST hit, check
    // whether the window's bytes would push this node's outgoing traffic over its configured cap;
    // if so and a holder is known, redirect there instead (extends #165 redirect-on-miss from "not
    // held" to "held but saturated") — else the graceful fallback: serve anyway.
    let depth = download::redirect_depth(&params);

    if let (Ok(rk), false) = (decode_rk(rk_hex), root_hex.is_empty()) {
        if let Some(resp) = node.serve_local_cached(store_hex, &root_hex, &rk).await {
            if let Some(pin) = pinned_root {
                if resp.roothash != pin {
                    return err(
                        &id,
                        ROOT_NOT_ANCHORED,
                        format!(
                            "served module root {} does not match the store's on-chain root {} (chain is the authority)",
                            resp.roothash.to_hex(),
                            pin.to_hex()
                        ),
                    );
                }
            }
            let bytes = content_window_len(resp.ciphertext.len(), offset) as u64;
            if let Some(obj) = node
                .bandwidth_redirect_for(store_hex, &root_hex, rk_hex, bytes, depth)
                .await
            {
                return json!({"jsonrpc":"2.0","id":id,"error":obj});
            }
            node.record_outgoing_bytes(bytes);
            return local(&id, build_result(&resp, offset));
        }
        // 1b. AUTHENTICATED WHOLE-STORE SYNC (§21.9): on a module-cache miss, pull
        //     the whole `.dig` from rpc.dig.net's auth-gated §21 endpoint, cache
        //     it, then serve locally. Best-effort — a failed/disabled sync just
        //     falls through to the per-resource proxy below. `sync_module` returns
        //     true only when the SERVED root == the requested (= pinned) root, so a
        //     synced module is keyed by the anchored root before we serve it.
        if node.sync_module(store_hex, &root_hex).await {
            // The sync just wrote/replaced the on-disk module; drop any stale decoded entry so the
            // cache reflects the newly-synced module rather than a prior decode.
            node.invalidate_content_cache(store_hex, &root_hex);
            if let Some(resp) = node.serve_local_cached(store_hex, &root_hex, &rk).await {
                if pinned_root.map(|p| resp.roothash == p).unwrap_or(true) {
                    let bytes = content_window_len(resp.ciphertext.len(), offset) as u64;
                    if let Some(obj) = node
                        .bandwidth_redirect_for(store_hex, &root_hex, rk_hex, bytes, depth)
                        .await
                    {
                        return json!({"jsonrpc":"2.0","id":id,"error":obj});
                    }
                    node.record_outgoing_bytes(bytes);
                    return local(&id, build_result(&resp, offset));
                }
            }
        }
    }

    // 2. RESPONSE CACHE: a window we previously proxied for this exact request.
    //    Keyed by the PINNED root, so a window cached for a stale/mismatched root
    //    is never replayed for the anchored read.
    let key = response_key(store_hex, &root_hex, rk_hex, offset);
    if let Some(result) = node.serve_cached_response(&key) {
        return local(&id, result);
    }

    // 2b. P2P REDIRECT-ON-MISS (#165): this node does NOT hold the content locally. If it runs a P2P
    //     content engine (the standalone peer network — never the in-process FFI/browser path) and the
    //     DHT locates a holder, answer with a REDIRECT to that holder (default) or FETCH-THROUGH via
    //     dig-download (`DIG_NODE_ON_MISS=fetch`) instead of dead-ending — never a silent miss while a
    //     provider exists. A bounded `redirect_depth` (echoed by the caller) prevents redirect loops.
    //     Applies only to a concrete resource (store+root+retrieval_key); an empty engine or no
    //     provider falls through to the upstream proxy below (byte-identical to before).
    if let Some(content) = download::miss_content_for(store_hex, &root_hex, rk_hex) {
        let depth = download::redirect_depth(&params);
        let pin_hex = pinned_root.map(|r| r.to_hex());
        if let Some(envelope) = node
            .content_miss_envelope(&id, &content, depth, offset, pin_hex.as_deref())
            .await
        {
            // This resource is being served FROM ANOTHER NODE (a redirect/fetch-through). In the
            // background, ALSO pull the whole `.dig` capsule for this generation so the NEXT read of
            // the store is served locally (SPEC §14.3, `DIG_NODE_BACKFILL_ON_MISS`, default on). This
            // does not delay the current response — it spawns a deduped detached pull and returns.
            node.maybe_backfill_capsule(store_hex, &root_hex);
            return envelope;
        }
    }

    // 3. MISS: proxy to rpc.dig.net, then cache the result window (LRU-capped)
    //    so the next load of this resource is served locally. (rpc.dig.net is the
    //    remote DIG network, not a local server — the in-process node IS local.)
    //
    //    The upstream request is pinned to the anchored root (rewriting/forcing
    //    `params.root`), and the upstream-returned root is re-checked against the
    //    pin — so even on the proxy path the node never serves a generation the
    //    chain did not confirm.
    let upstream_req = pinned_root
        .map(|pin| pin_request_root(&req, &pin.to_hex()))
        .unwrap_or_else(|| req.clone());
    match node.proxy(&upstream_req).await {
        Ok(mut v) => {
            // Verify the upstream served the pinned root before trusting/caching it.
            if let Some(pin) = pinned_root {
                let served = v
                    .get("result")
                    .and_then(|r| r.get("root"))
                    .and_then(|r| r.as_str())
                    .and_then(|s| Bytes32::from_hex(s).ok());
                if let Some(served) = served {
                    if served != pin {
                        return err(
                            &id,
                            ROOT_NOT_ANCHORED,
                            format!(
                                "upstream served root {} does not match the store's on-chain root {} (chain is the authority)",
                                served.to_hex(),
                                pin.to_hex()
                            ),
                        );
                    }
                }
            }
            if let Some(result) = v.get("result") {
                node.store_response(&key, result).await;
            }
            // Mark this window as freshly fetched from the network.
            if let Some(result) = v.get_mut("result").and_then(|r| r.as_object_mut()) {
                result.insert("source".into(), json!("remote"));
            }
            v
        }
        Err(e) => json!({"jsonrpc":"2.0","id":id,
            "error":{"code":-32000,"message":format!("upstream: {e}")}}),
    }
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
                .build()
                .expect("http client"),
            upstream: std::env::var("DIG_NODE_UPSTREAM")
                .unwrap_or_else(|_| RPC_FALLBACK.to_string()),
            cache_lock: Mutex::new(()),
            identity_seed,
            anchored_root_resolver: default_anchored_resolver(),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::from_env(),
        })
    }

    /// The shared peer-network status (for the standalone `run` to hand to the peer-network task and
    /// for `control.peerStatus`).
    pub fn peer_status(&self) -> Arc<peer::PeerStatus> {
        self.peer_status.clone()
    }

    /// The node's persistent identity seed, if configured — the source of the STABLE mTLS `peer_id`
    /// for the L7 peer network (see [`peer::load_or_generate_node_cert`]). `None` disables the peer network
    /// (the node still serves the HTTP read path).
    pub fn identity_seed_for_peer(&self) -> Option<[u8; 32]> {
        self.identity_seed
    }

    /// The directory the L7 peer network keeps its TLS cert/key + peer address book under (a
    /// `peer-net/` subdir of the cache dir, so it shares the node's data root + writability handling).
    pub fn peer_cert_dir(&self) -> PathBuf {
        self.cache_dir.join("peer-net")
    }

    /// The directory the node's PERSISTENT, CA-signed [`NodeCert`](dig_nat::NodeCert) identity
    /// (`node.crt` + `node.key`, 0600) lives under — an `identity/` subdir of [`Self::peer_cert_dir`],
    /// kept SEPARATE from dig-gossip's own `node.key` in `peer-net/` so the two never clobber each
    /// other. This is the node's stable machine transport identity (#908, #1280); its `peer_id`
    /// survives restarts because the cert is loaded back from here.
    pub fn node_cert_dir(&self) -> PathBuf {
        self.peer_cert_dir().join("identity")
    }

    /// The node's cache dir root — the data root the P2P content engine's download staging
    /// (`<cache>/downloads`) + `.download.tmp` GC live under (shares the node's writability handling).
    pub fn cache_dir_path(&self) -> &Path {
        &self.cache_dir
    }

    /// The node's anchored-root resolver (the trusted-root source for the read-path pin AND the
    /// chain-watch loop). Cloned `Arc` so the chain-watch loop shares the SAME resolver the read path
    /// uses — production coinset walk, or a deterministic one in tests.
    pub fn anchored_root_resolver_arc(&self) -> Arc<dyn AnchoredRootResolver> {
        self.anchored_root_resolver.clone()
    }
}

/// Crate-internal test helpers shared across module test suites (e.g. the peer-surface
/// tests in [`crate::peer`] need a lightweight [`Node`]). Not compiled into the release build.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

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
            cache_lock: Mutex::new(()),
            identity_seed: None,
            anchored_root_resolver: default_anchored_resolver(),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
        };
        (Arc::new(node), td)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

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
    }

    impl MockResolver {
        /// One store that resolves to `root`.
        fn one(store_hex: &str, root: Bytes32) -> Arc<dyn AnchoredRootResolver> {
            let mut outcomes = std::collections::HashMap::new();
            outcomes.insert(store_hex.to_string(), Ok(Some(root)));
            Arc::new(MockResolver {
                outcomes,
                owner: None,
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
    }

    /// Build a `Node` with a throwaway cache dir and an optional identity seed. The
    /// returned `TempDir` must be kept alive for the duration of the test.
    ///
    /// The anchored-root resolver defaults to "no confirmed generation" for every
    /// store, so any `dig.getContent` test that does not explicitly inject a tip
    /// fails closed under the pin — make the pin policy explicit per test via
    /// [`test_node_with_resolver`] or by disabling the pin (`DIG_NODE_PIN=off`).
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
            cache_lock: Mutex::new(()),
            identity_seed,
            anchored_root_resolver,
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
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
        let module = b"compiled-module-bytes".to_vec();
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (node, _td) = test_node(Some([5u8; 32]));
        let root_hex = "10".repeat(32); // served genesis root
        let matched = node.sync_module_from(&base, &store_hex, &root_hex).await;
        assert!(matched, "authed sync to served root 0x10 should match");
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
        let module = b"gap-filled-module-bytes".to_vec();
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let store_id: [u8; 32] = Bytes32::from_hex(&store_hex).unwrap().0;
        // The remote's served genesis root.
        let root = Bytes32([0x10; 32]);
        // A node with a §21 identity whose UPSTREAM is the authed remote (gap-fill pulls via upstream).
        let td = tempfile::tempdir().unwrap();
        let node = Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: base,
            cache_lock: Mutex::new(()),
            identity_seed: Some([5u8; 32]),
            anchored_root_resolver: MockResolver::one(&store_hex, root),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
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
        let module = b"watched-store-module".to_vec();
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let root = Bytes32([0x10; 32]);
        let td = tempfile::tempdir().unwrap();
        let node = Arc::new(Node {
            cache_dir: td.path().to_path_buf(),
            http: reqwest::Client::new(),
            upstream: base,
            cache_lock: Mutex::new(()),
            identity_seed: Some([5u8; 32]),
            anchored_root_resolver: MockResolver::one(&store_hex, root),
            peer_status: peer::PeerStatus::new(),
            p2p_content: OnceLock::new(),
            content_cache: std::sync::Mutex::new(ContentCache::default()),
            inventory_refresher: OnceLock::new(),
            backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
            verification_ledger: verification_ledger::VerificationLedger::new(),
            self_ref: OnceLock::new(),
            gossip: OnceLock::new(),
            outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
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
            let module = b"proactively-pulled-generation".to_vec();
            let (base, store_hex) = spawn_authed_remote(module.clone()).await;
            let root = Bytes32([0x10; 32]);
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
                cache_lock: Mutex::new(()),
                identity_seed: Some([5u8; 32]),
                anchored_root_resolver: MockResolver::one(&store_hex, root),
                peer_status: peer::PeerStatus::new(),
                p2p_content: OnceLock::new(),
                content_cache: std::sync::Mutex::new(ContentCache::default()),
                inventory_refresher: OnceLock::new(),
                backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
                verification_ledger: verification_ledger::VerificationLedger::new(),
                self_ref: OnceLock::new(),
                gossip: OnceLock::new(),
                outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
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
            let module = b"chain-watch-pulled".to_vec();
            let (base, store_hex) = spawn_authed_remote(module.clone()).await;
            let root = Bytes32([0x10; 32]);
            let td = tempfile::tempdir().unwrap();

            std::env::set_var("DIG_NODE_CACHE", td.path());
            std::env::set_var("DIG_NODE_WATCH_INTERVAL", "1");
            subscribe_store(&store_hex).unwrap();

            let node = Arc::new(Node {
                cache_dir: td.path().to_path_buf(),
                http: reqwest::Client::new(),
                upstream: base,
                cache_lock: Mutex::new(()),
                identity_seed: Some([5u8; 32]),
                anchored_root_resolver: MockResolver::one(&store_hex, root),
                peer_status: peer::PeerStatus::new(),
                p2p_content: OnceLock::new(),
                content_cache: std::sync::Mutex::new(ContentCache::default()),
                inventory_refresher: OnceLock::new(),
                backfilling: std::sync::Mutex::new(std::collections::HashSet::new()),
                verification_ledger: verification_ledger::VerificationLedger::new(),
                self_ref: OnceLock::new(),
                gossip: OnceLock::new(),
                outgoing_throttle: bandwidth::OutgoingThrottle::new(0),
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
        node.maybe_backfill_capsule(&store_hex, &root_hex);
        // Nothing pulled, nothing left in-flight.
        assert!(!module_exists(&node.cache_dir, &store_hex, &root_hex));
        assert!(
            node.backfilling
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
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
        node.maybe_backfill_capsule(&store_hex, &root_hex);
        assert!(
            node.backfilling
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "an already-held capsule claims no in-flight backfill slot"
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

    #[tokio::test]
    async fn authed_module_sync_carries_verifiable_identity() {
        let seed = [7u8; 32];
        let store = Bytes32([3u8; 32]);
        let root = Bytes32([9u8; 32]);
        let captured = Arc::new(std::sync::Mutex::new(None));
        let url = spawn_mock_module_server(captured.clone(), root, b"MODULE".to_vec()).await;

        let (node, _td) = test_node(Some(seed));
        let matched = node
            .sync_module_from(&url, &store.to_hex(), &root.to_hex())
            .await;
        assert!(matched, "served root == requested root");

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
        let served = Bytes32([0xAA; 32]);
        let requested = Bytes32([0xBB; 32]); // differs from served
        let captured = Arc::new(std::sync::Mutex::new(None));
        let url = spawn_mock_module_server(captured, served, b"DIGMODULE".to_vec()).await;

        let (node, _td) = test_node(Some(seed));
        let matched = node
            .sync_module_from(&url, &store.to_hex(), &requested.to_hex())
            .await;
        assert!(!matched, "served (AA..) != requested (BB..)");

        // The module is cached under the SERVED root with the served bytes …
        let served_path = module_path(&node.cache_dir, &store.to_hex(), &served.to_hex());
        assert_eq!(std::fs::read(&served_path).unwrap(), b"DIGMODULE");
        // … and nothing is cached under the (unmatched) requested root.
        assert!(!module_path(&node.cache_dir, &store.to_hex(), &requested.to_hex()).exists());
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
        let matched = node
            .sync_module_from("http://127.0.0.1:1", &store.to_hex(), &root.to_hex())
            .await;
        assert!(!matched);
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
        ));
        assert_eq!(set["result"]["cap_bytes"].as_u64(), Some(five_gib));

        // getConfig reflects the persisted cap and reports a used figure.
        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"cache.getConfig"}),
        ));
        assert_eq!(got["result"]["cap_bytes"].as_u64(), Some(five_gib));
        assert!(got["result"]["used_bytes"].as_u64().is_some());

        // A below-floor request is clamped up to the 64 MiB minimum (a stray 0
        // must never disable caching).
        let low = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"cache.setCapBytes",
                   "params":{"cap_bytes": 1}}),
        ));
        assert_eq!(low["result"]["cap_bytes"].as_u64(), Some(64 * 1024 * 1024));

        // clear succeeds with an empty result object.
        let cleared = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"cache.clear"}),
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
        ));
        assert_eq!(empty["result"]["count"], json!(0));
        assert_eq!(empty["result"]["subscriptions"], json!([]));

        // Subscribe → newly added.
        let sub = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"control.subscribe",
                   "params":{"store_id": store}}),
        ));
        assert_eq!(sub["result"]["subscribed"], json!(true));
        assert_eq!(sub["result"]["added"], json!(true));

        // Re-subscribe → idempotent (added:false).
        let again = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":3,"method":"control.subscribe",
                   "params":{"store_id": store}}),
        ));
        assert_eq!(again["result"]["added"], json!(false));

        // List reflects it, AND it is persisted (a fresh load sees it).
        let listed = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":4,"method":"control.listSubscriptions"}),
        ));
        assert_eq!(listed["result"]["count"], json!(1));
        assert_eq!(listed["result"]["subscriptions"], json!([store]));
        assert!(load_subscriptions().contains(&store), "persisted to disk");

        // Unsubscribe → removed, and the set is empty again.
        let unsub = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":5,"method":"control.unsubscribe",
                   "params":{"store_id": store}}),
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

    #[tokio::test]
    async fn list_cached_reports_capsules_with_size_and_mtime() {
        // cache.listCached enumerates every cached `.module` as a capsule
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
        )
        .await;
        assert!(resp["result"]["removed"].as_bool() == Some(true));
        assert!(!path.exists(), "the module file is unlinked");
    }

    #[tokio::test]
    async fn remove_cached_rejects_path_traversal() {
        // A non-hex store id that tries to escape the cache dir is refused and
        // never deletes anything outside it.
        let (node, _td) = test_node(None);
        let err = node
            .cache_remove_cached("../../etc", &"33".repeat(32))
            .await
            .unwrap_err();
        assert!(
            err.contains("invalid") || err.contains("hex"),
            "traversal attempt rejected as invalid input, got: {err}"
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
        let module = b"freshly-fetched-module".to_vec();
        let (base, store_hex) = spawn_authed_remote(module.clone()).await;
        let (mut node, _td) = test_node(Some([5u8; 32]));
        node.upstream = base; // point the on-demand fetch at the authed remote
        let root_hex = "10".repeat(32); // the served genesis root

        let resp = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"cache.fetchAndCache",
                   "params":{"store_id": store_hex, "root": root_hex}}),
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
        )
        .await;
        assert_eq!(
            again_resp["result"]["status"].as_str(),
            Some("already_cached")
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
        )
        .await;
        assert_eq!(resp["result"]["status"].as_str(), Some("failed"));
    }

    // -- Shared .dig cache (#96) -----------------------------------------------
    //
    // Tests that drive the PROCESS-GLOBAL `cache_dir()` (via the `DIG_NODE_CACHE`
    // env) must not run concurrently with each other or with
    // `cache_rpc_config_roundtrip_and_clear`, since cargo runs tests in parallel
    // threads of one process. `ENV_GUARD` serializes them. Acquire it with
    // `.unwrap_or_else(|p| p.into_inner())` so that ONE test's failure (which
    // poisons the mutex) does not cascade into spurious failures of every other
    // env-touching test — each failure should stand on its own.
    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (node, _td) = test_node(None);
        let got = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":7,"method":"control.peerStatus"}),
        ));
        let result = got["result"].as_object().expect("result object");
        assert_eq!(result["running"], json!(false));
        assert_eq!(
            result["relay"]["url"],
            json!(peer::DEFAULT_RELAY_URL),
            "defaults to relay.dig.net when DIG_RELAY_URL unset"
        );
        assert_eq!(result["network_id"], json!(peer::DEFAULT_NETWORK_ID));
        assert_eq!(result["connected_peers"], json!(0));
        assert_eq!(got["id"], json!(7));
        assert_eq!(got["jsonrpc"], json!("2.0"));
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
        ));

        assert_eq!(resp["error"]["code"], ROOT_NOT_ANCHORED, "{resp}");
        assert!(resp.get("result").is_none());
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
            let resp = rt.block_on(handle_rpc(&node, req));
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
        )
        .await;
        assert_eq!(empty["error"]["code"], json!(-32602), "{empty}");

        let bad_root = handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":2,"method":"dig.getManifest","params":{
                "store_id": Bytes32([1u8; 32]).to_hex(), "root": "not-hex",
            }}),
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
        ));
        match out {
            PlaintextOutcome::Served {
                bytes,
                root_hex,
                verified,
                source,
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
        ));
        assert!(
            matches!(js, PlaintextOutcome::Served { ref bytes, .. } if bytes == b"console.log(1)"),
            "expected the js asset, got {js:?}"
        );

        // The EMPTY resource resolves to the default view index.html (same bytes).
        let bare =
            rt.block_on(node.serve_content_plaintext(&store.to_hex(), &root.to_hex(), "", None));
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

    /// **Proves:** the serve-metadata `X-Dig-Owner-Puzzle-Hash` source (#486) — when the chain-anchored
    /// pin is ENFORCED and the resolver reports the store's on-chain owner, `serve_content_plaintext`
    /// surfaces it on the `Served` outcome, resolved from the SAME chain read as the root pin (no second
    /// coinset call). **Catches:** the owner silently staying `None` when the resolver DOES supply it,
    /// or the field being guessed/fabricated rather than sourced from the resolver.
    #[test]
    fn serve_content_plaintext_reports_the_resolver_owner_puzzle_hash_when_pin_enforced() {
        use crate::content_serve::PlaintextOutcome;
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

    /// **Proves:** the serve path fails CLOSED when the requested root is not the chain-anchored tip
    /// (#127) — never decrypting/serving a generation the chain did not confirm. **Catches:** a serve
    /// that trusts the caller's root over the chain.
    #[test]
    fn serve_content_plaintext_rejects_a_non_anchored_root() {
        use crate::content_serve::PlaintextOutcome;
        let _g = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        std::env::remove_var("DIG_NODE_PIN");
        let rt = pin_test_rt();
        let store = Bytes32([22u8; 32]);
        let anchored = Bytes32([0x33; 32]);
        let (node, _td) =
            test_node_with_resolver(None, MockResolver::one(&store.to_hex(), anchored));
        let wrong = Bytes32([0x44; 32]).to_hex();
        let out =
            rt.block_on(node.serve_content_plaintext(&store.to_hex(), &wrong, "index.html", None));
        assert!(
            matches!(out, PlaintextOutcome::RootError { .. }),
            "a non-anchored requested root must fail closed, got {out:?}"
        );
    }

    /// **Proves:** `manifest_paths` lists the store's public file paths when the capsule is held with a
    /// manifest, and is `None` when the capsule is not held (drives the shell's SPA-vs-404 decision).
    #[tokio::test]
    async fn manifest_paths_lists_public_paths_when_held_and_none_when_not() {
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
            ..node
        };

        let resp = rt.block_on(handle_rpc(
            &node,
            json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store.to_hex(), "root": tip.to_hex(), "retrieval_key": rk_hex,
            }}),
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
