//! The dig-node service's HTTP server: `/health`, CORS, and `POST /` → the embedded
//! dig-node read path's `handle_rpc`.
//!
//! This is the localhost endpoint the DIG Chrome extension points its `server.host`
//! setting at. It speaks the SAME wire contract as rpc.dig.net (because it routes
//! to `dig_node_core::handle_rpc`), so the extension's `fetchContentViaRPC` pipeline —
//! `dig.getContent` → verify → decrypt, all done in the extension — works against
//! it byte-for-byte, with the bonus that resources are served local-first from any
//! `.dig` modules the node has cached.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{Body, Bytes},
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Request, State,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dig_node_core::content_serve::{PeerTier, PlaintextOutcome, ServeSource};
use dig_node_core::{cache_cap_bytes, cache_used_bytes, ContentServer, Node};
use dig_wallet::sage::events::{SyncEvent, SyncLifecycle, SyncStatus};
use dig_wallet::sage::rpc::WalletBackend;
use dig_wallet::sage::service::WalletService;
use dig_wallet::sage::transport::{SharedCert, DEFAULT_MTLS_PORT};
use serde_json::{json, Value};
use tower_http::cors::{AllowMethods, AllowOrigin, CorsLayer};

use crate::config::{host_is_allowed, Config};
use crate::content::{
    content_type_for, inject_html_head, is_html, is_static_asset_path, parse_store_path,
    parse_verify_path, reroot_via_referer, store_base_href, StorePath, STORE_CSP,
};
use crate::control::{self, ControlCtx};
use crate::meta;
use crate::meta::ErrorCode;
use crate::pairing;
use crate::rpc::{normalize_request, request_id, rpc_error};
use crate::wallet_authz;

/// The dig-node binary version, surfaced by `/health`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Shared server state: the embedded dig-node plus the resolved upstream and an
/// HTTP client for the passthrough fallback. The `Node` owns the cache + its own
/// upstream client + §21 identity; the client here is only for relaying methods
/// dig-node does not resolve (see [`rpc`]).
#[derive(Clone)]
pub struct AppState {
    node: Arc<Node>,
    /// The seam-5 (local content server) HANDLE — a composition-root upcast of the SAME
    /// `Arc<Node>` above (#1285 W1c), not a separate object. This is the outer, injectable
    /// seam boundary: a test/FFI caller can hold `Arc<dyn ContentServer>` instead of the
    /// concrete `Node`, and W2-W5 can later repoint this ONE handle at a different concrete
    /// implementation without touching `node` or the service's other seam calls.
    content_server: Arc<dyn ContentServer>,
    /// The resolved upstream, and whether an unimplemented method is relayed to it, and the bring-up probe
    /// that proves that upstream is not this node itself (#1997). Shared across every request so a
    /// proven loop takes effect on the very next relay decision.
    relay: Arc<crate::relay::RelayGuard>,
    http: reqwest::Client,
    /// The loopback `host:port` the server is bound to, surfaced in `/health` and
    /// the well-known document so an agent learns where the node serves.
    addr: String,
    /// The node's config.json path — where the service's pin registry + upstream
    /// override live (the CONTROL plane reads/writes here).
    config_path: std::path::PathBuf,
    /// The machine-wide daemon STATE dir (#501) — where the control token +
    /// `paired-tokens.json` live, resolved IDENTICALLY by the daemon and the operator
    /// CLI regardless of OS user (see [`crate::state`]). Distinct from `config_path`:
    /// the bulk per-user cache + `config.json` stay per-user; only the auth state moves here.
    state_dir: std::path::PathBuf,
    /// The local control token: a same-host controller must present it on every
    /// `control.*` call. Generated at startup into `<state_dir>/control-token`
    /// (loopback-only + locally-authorized gate — see [`crate::control`]).
    control_token: String,
    /// Whether authenticated §21 whole-store sync is available (a §21 identity is
    /// loaded). `Node::from_env` creates/loads the §21.9 identity at construction, so
    /// this is normally `true`; the AUTHORITATIVE per-capsule result is still
    /// reported in-band by the sync/pin operations.
    sync_available: bool,
    /// Process start instant, for `control.status` uptime.
    started: Instant,
    /// In-memory pending-pairing set (#280) — shared across every request so the
    /// OPEN `pairing.request`/`pairing.poll` and the gated `control.pairing.*`
    /// handlers see one consistent set of in-flight pairings.
    pairings: Arc<std::sync::Mutex<crate::pairing::PendingPairings>>,
    /// The SERVED Sage-parity wallet backend (#368): one live [`WalletBackend`] (wallet DB +
    /// fallback tier + shared [`EventBus`] + node custody) dispatched by BOTH the loopback
    /// `POST /{method}` HTTP mirror the extension targets AND the bidirectional `/ws` wallet+control
    /// transport (#369). Custody-backed, so a paired `wallet.unlock` enables signing at runtime.
    wallet: Arc<WalletBackend>,
    /// The shared self-signed cert the wallet mTLS listener presents (Sage byte-parity, node-class
    /// clients). Held so [`serve_with_shutdown`] can bring up that sibling listener.
    wallet_cert: SharedCert,
    /// The node's ONE chain transport, shared with the wallet rather than built beside it.
    ///
    /// Held so the collateral census (#400) can take a
    /// [`ChainSource`](dig_chainsource_interface::ChainSource) view of the same peer pool the
    /// wallet's reads ride. Building a second one would give a live node two independent pools with
    /// two notions of the peak — the defect dig_ecosystem#2761 removed.
    wallet_chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    /// The per-source INGRESS bound on OPEN, token-less `control.*` reads (dig_ecosystem#3051).
    ///
    /// The open reads present no credential, so before this existed an anonymous caller could
    /// drive unbounded SQLite work — `control.wallet.coinById`/`.coinSpend` each run up to two
    /// lookups plus an LRU `UPDATE` — simply by asking, repeatedly, for free.
    ///
    /// Shared across every request so the bound is per SOURCE and not per connection: reconnecting
    /// must not mint a fresh budget, or the bound is decorative against exactly the caller it is
    /// for. [`MissRateLimiter`](dig_node_core::rate_limit::MissRateLimiter) is reused rather than
    /// re-implemented — it is already a per-[`RequestorId`] token-bucket registry with the
    /// identity-cycling table bound this needs.
    control_ingress: Arc<dig_node_core::rate_limit::MissRateLimiter>,
    /// §25.8's bond observation, as the last mirror pass published it (dig-node#412 step 7).
    ///
    /// Held on the shared state rather than rebuilt per request precisely so the control surface
    /// cannot be made to do chain work by asking: the mirror pass observes on its own round timer
    /// and writes here, and `control.mirror.bondStates` only ever reads.
    mirror_bonds: crate::mirror::lifecycle::BondSnapshot,
}

/// Per-source burst for OPEN control reads (dig_ecosystem#3051): how many token-less reads one
/// source may fire back-to-back before [`CONTROL_INGRESS_REFILL_PER_SEC`] governs. Sized for a UI
/// that opens a pane and issues a handful of reads at once — a lineage walk of a few generations is
/// a couple of dozen — while a flood is capped within a second.
const CONTROL_INGRESS_BURST: f64 = 32.0;

/// Sustained per-source rate for OPEN control reads once the burst is spent. Comfortably above any
/// human-driven refresh and far below what it takes to make the SQLite work matter.
const CONTROL_INGRESS_REFILL_PER_SEC: f64 = 8.0;

/// The burst MUST absorb an ordinary lineage walk back-to-back.
///
/// Resolving a dig-profile follows a DID singleton forward at two reads per generation
/// (`.coinById` + `.coinSpend`), so a six-generation walk is twelve reads with no pause between
/// them. A burst below that would refuse an ORDINARY profile read, which arrives as "the profile
/// pane is broken" rather than as a rate-limit report.
///
/// Asserted at COMPILE TIME rather than in a test: the relationship is between two constants, so
/// lowering the burst should fail the BUILD, not wait for someone to run the right test.
const _: () = assert!(CONTROL_INGRESS_BURST >= 12.0);

/// dig-node's "method not found" error code. `handle_rpc` resolves only
/// `dig.getContent` / `dig.getAnchoredRoot` / `cache.*` and returns this for
/// anything else; this service treats that as the cue to blind-passthrough the
/// request to the upstream.
const METHOD_NOT_FOUND: i64 = ErrorCode::MethodNotFound.code();

impl AppState {
    /// Re-attach the wallet backend reporting `peers` Chia peers HELD and `peers` subscription
    /// peers, WITHOUT starting a supervisor or building a chain transport (so no test dials
    /// mainnet).
    ///
    /// The integration harness runs `enable_chain_sync: false` and never builds the chain
    /// transport, which leaves every Chia peer count `null` — and a `null == null` comparison
    /// cannot see `control.peerCounts` and `control.wallet.syncStatus` drifting onto different
    /// sources, which dig-node-control-interface 0.8.0 makes a conformance MUST. This seam gives
    /// the counts a distinctive value so the two answers become distinguishable.
    ///
    /// BOTH counts are injected because since dig_ecosystem#2806 they are different facts:
    /// `chia_peer_count` is the transport's held peer pool and `subscription_peer_count` is the
    /// replica's session. Injecting only one would leave the other `null` and put the harness
    /// back in the blind spot this seam exists to remove.
    #[doc(hidden)]
    pub fn with_chia_peer_count_for_tests(mut self, peers: u32) -> Self {
        let handle = dig_wallet::sage::sync_supervisor::SyncHandle::detached_for_tests(peers);
        let tier = dig_wallet::sage::fallback::ChainPeerTier {
            peer_count: Some(peers),
            peak_height: None,
        };
        self.wallet = Arc::new(
            (*self.wallet)
                .clone()
                .with_sync_handle(handle)
                .with_chain_peer_tier_for_tests(tier),
        );
        self
    }
}

/// Build the dig-node service's axum router. Beside `POST /` (JSON-RPC) and `GET /health`
/// it exposes the self-describing discovery surface so an agent can introspect the
/// node with zero out-of-band knowledge:
///   * `GET /version`                    — build/commit/version fingerprint
///   * `GET /openrpc.json`               — the OpenRPC method+error spec
///   * `GET /.well-known/dig-node.json`  — addr + cache + methods + errors + spec links
///   * `GET /ws/status`                  — WebSocket status/liveness channel (#239)
///
/// Split out from [`serve`] so it can be exercised by an in-process test without
/// binding a port.
pub fn router(state: AppState) -> Router {
    // The extension calls from a `chrome-extension://` origin; a same-machine page
    // calls from `http://localhost`, `http://dig.local`, or a loopback IP (#91 —
    // the dual listener means a page can be served from any of the canonical local
    // names). Reflect those so the browser's CORS preflight passes. The node binds
    // loopback-only by default (a non-loopback DIG_NODE_HOST is refused unless
    // DIG_NODE_ALLOW_REMOTE=1, #1662), so reflecting these local origins is not a
    // public-exposure risk.
    // #702: the predicate is evaluated per REQUEST, not once for the router, so the app-origin
    // family can be scoped to content reads while the local web/extension family keeps the whole
    // surface. `parts` carries the path and the method (and, on a preflight, the method the
    // browser is asking about) — everything `reflects_origin` needs to decide.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            |origin: &HeaderValue, parts: &axum::http::request::Parts| {
                let method = effective_method(parts);
                origin
                    .to_str()
                    .map(|o| reflects_origin(o, &method, parts.uri.path()))
                    .unwrap_or(false)
            },
        ))
        // MIRROR the requested method rather than declaring a static set. tower-http emits
        // `Access-Control-Allow-Methods` on EVERY preflight, independent of the origin verdict, so
        // a static `[GET, POST, OPTIONS]` answers a legitimately-approved GET preflight from an
        // app origin by ALSO advertising `POST` — seeding the browser's preflight cache with a
        // `POST` entry that lets a later `POST /` skip its preflight entirely and reach the node.
        // Mirroring keeps the advertised method equal to the one the origin predicate actually
        // judged (#702).
        .allow_methods(AllowMethods::mirror_request())
        // CONTENT_TYPE for the JSON body; the control-token header so a same-host
        // controller (the DIG Browser "My Node" UI) can authorize control.* calls.
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-dig-control-token"),
        ])
        // #669: EXPOSE the `X-Dig-*` verification/provenance headers to a cross-origin browser
        // client (dig-urn-resolver's node-first path). By default a browser can read only a short
        // safelist of response headers from a cross-origin fetch; without this the resolver cannot
        // see `X-Dig-Verified` (and the Merkle-proof headers on the ciphertext path) and so fails
        // CLOSED — silently dropping from the fast node tier to the verified rpc tier. Loopback-only
        // and read-only provenance metadata, so exposing them broadens nothing but readability.
        .expose_headers(EXPOSED_DIG_HEADERS.map(HeaderName::from_static))
        // #285: Chrome's Private Network Access blocks a page/extension-context request to a
        // private IP (127.0.0.1) unless the preflight response carries
        // `Access-Control-Allow-Private-Network: true` (sent only when the preflight itself
        // carries `Access-Control-Request-Private-Network: true` — tower_http gates this
        // itself, see `is_local_origin`'s callers). Without it Chrome silently blocks every
        // extension→node request and the extension (correctly) reports the node offline, even
        // though `/health` answers fine to a direct curl/fetch from a non-PNA-checked context.
        // The node binds loopback-only (enforced — non-loopback DIG_NODE_HOST refused unless
        // DIG_NODE_ALLOW_REMOTE=1, #1662), so allowing this to every reflected local origin is not
        // a public-exposure risk (mirrors the existing origin-reflection trust boundary above).
        .allow_private_network(true);

    Router::new()
        .route("/", get(health).post(rpc))
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/openrpc.json", get(openrpc))
        .route("/.well-known/dig-node.json", get(well_known))
        // `GET /ws/status` (#239): a WebSocket liveness/status channel for a browser
        // client's SW — the OPEN SOCKET is itself the liveness signal, with a
        // heartbeat detecting a half-open connection. See [`ws_status`].
        .route("/ws/status", get(ws_status))
        // `GET /ws` (#369): the BIDIRECTIONAL wallet+control transport. A thin client drives every
        // wallet read + `control.*`/wallet mutation over this ONE socket (correlated request →
        // response), and the node PUSHES sync-status transitions + sync events proactively —
        // subsuming the SSE stream + per-call HTTP polling. Paired-token gated for mutations +
        // `control.*` (§7.12); reads open. See [`ws_wallet`]. Resolver/content transport untouched.
        .route("/ws", get(ws_wallet))
        // `POST /{method}` (#368): the Sage-parity wallet RPC surface the extension's `node-wallet`
        // client targets (`POST {base}/{method}`, snake_case Sage body). Served by the live
        // node-custodied [`WalletBackend`]; mutations + `wallet.*` are paired-token gated and NEVER
        // relayed upstream. A one-segment GET (a root-absolute store subresource) still reaches the
        // content-serve path via the method-router `.get` arm, so this never shadows content serving.
        .route("/:method", post(wallet_rpc).get(fallback_serve))
        // `GET /s/<storeId>[:<root>]/<path>` (#289): the LOCAL plaintext content-serve
        // surface — the node decrypts server-side and returns the real website over
        // loopback, DISTINCT from the blind-ciphertext JSON-RPC `POST /` above. See
        // [`store_serve`]. A root-absolute subresource (`GET /foo.js`) misses this
        // route and lands in the fallback, which reroots it via `Referer`.
        .route("/s/*path", get(store_serve))
        // `GET /verify/<storeId>[:<root>]` (#307): the read-only verification-ledger surface on the
        // SAME loopback browser surface as `/s/` (host-guard + CORS). Returns the per-resource verify
        // verdicts + Merkle proof data the serve path recorded, plus the page-level aggregate the
        // extension's "Verified by Chia" badge consumes. Loopback-only, no secrets. See [`verify_ledger`].
        .route("/verify/*path", get(verify_ledger))
        .fallback(fallback_serve)
        // Host-header allowlist (#91): both loopback listeners share this router,
        // so a single guard accepts the canonical local names (dig.local /
        // localhost / 127.0.0.1 / 127.0.0.2 [+ :port]) and rejects a foreign Host
        // (the DNS-rebinding vector) before any handler runs. Applied UNDER the CORS
        // layer so a CORS preflight (OPTIONS) is still answered for an allowed host.
        .layer(middleware::from_fn(host_guard))
        .layer(cors)
        .with_state(state)
}

/// The `X-Dig-*` verification/provenance response headers a cross-origin browser client (the
/// dig-urn-resolver node-first path) must be able to READ (#669). Exposed via
/// `Access-Control-Expose-Headers` so a cross-origin fetch can see the "Verified by Chia"
/// attestation + the Merkle-proof/chunk-length headers on the ciphertext path — without which the
/// resolver fails closed and drops to the verified rpc tier. Lowercase (header names are
/// case-insensitive; `HeaderName::from_static` requires lowercase).
const EXPOSED_DIG_HEADERS: [&str; 11] = [
    "x-dig-verified",
    "x-dig-root",
    "x-dig-inclusion-proof",
    "x-dig-chunk-lens",
    "x-dig-source",
    "x-dig-peer-tier",
    "x-dig-store-id",
    "x-dig-capsule",
    "x-dig-resource-key",
    "x-dig-owner-puzzle-hash",
    "x-dig-generation",
];

/// Whether this node reflects `origin` for a request carrying `method` to `path`.
///
/// CORS here is **scoped by route AND method** (#702), not router-wide. Two origin families with
/// deliberately different reach, both loopback-only trust (the node binds loopback only — a
/// non-loopback `DIG_NODE_HOST` is refused unless `DIG_NODE_ALLOW_REMOTE=1`, #1662; CORS is not an
/// auth boundary):
///
/// - **Same-machine web/extension origins** ([`is_local_origin`]) — the extension's
///   `chrome-extension://` scheme + `http://` pages served from a canonical local name (#91).
///   Reflected on the WHOLE surface, unchanged: this is the subset the extension and the local
///   `/ws` trust surface already share.
/// - **Desktop-app origins** ([`is_app_origin`]) — Tauri's origins + the operator's
///   [`APP_ORIGINS_ENV`] allowlist (#669). Reflected for **content reads ONLY**.
///
/// # Why the split is by method and not by route alone
///
/// A route-scoped split cannot express this policy, because two routes serve both families of
/// traffic: `POST /` multiplexes content reads AND the open wallet-read methods onto one JSON-RPC
/// endpoint, and `/{method}` is a method-router serving the Sage-parity wallet RPC on `POST` and
/// content on `GET`. Reflecting an app origin on either route as a whole would hand a local
/// browser-reachable program cross-origin READ access to wallet data (balances, addresses, coins),
/// which is exactly the exposure #693 documented and deferred.
///
/// So the discriminator is the **effective method**: an app origin is reflected for read-only
/// content verbs and for nothing else. Every wallet-read method the node exposes is reached by
/// `POST` (`POST /` JSON-RPC and `POST /{method}`), and every content read a cross-origin browser
/// client makes — dig-urn-resolver's node-first tier, which is the whole reason #669 widened the
/// origin set — is a `GET`/`HEAD` that carries the `X-Dig-*` provenance headers. The split
/// therefore preserves #669 intact while removing the wallet-read reach.
///
/// `/ws` and `/ws/status` are excluded from the app family for the same reason and independently of
/// their own `Origin` check (§4.5/§4.8): a WebSocket handshake is not gated by CORS, so the socket
/// validates `Origin` itself against the local subset. Denying it here as well keeps the two
/// statements of the same policy from drifting apart.
///
/// PURE so the policy is unit-testable without binding a port.
fn reflects_origin(origin: &str, method: &Method, path: &str) -> bool {
    if is_local_origin(origin) {
        return true;
    }
    is_app_origin(origin) && is_content_read(method, path)
}

/// Whether a request is a **content read** — the only traffic class desktop-app origins are
/// reflected for (#702).
///
/// Read-only by verb (`GET`/`HEAD`), and not the WebSocket upgrade paths. `HEAD` is included
/// because axum dispatches it to the registered `GET` handler, so a `HEAD /s/...` is the same
/// content read with the body stripped — and it still carries the `X-Dig-*` provenance headers a
/// resolver reads.
fn is_content_read(method: &Method, path: &str) -> bool {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return false;
    }
    !is_websocket_path(path)
}

/// The `/ws` and `/ws/status` upgrade paths, which no desktop-app origin reaches (§4.5/§4.8).
///
/// Matched on the exact paths the router registers rather than a prefix, so an unrelated future
/// route beginning with those bytes is not silently swept into the WebSocket trust carve-out.
fn is_websocket_path(path: &str) -> bool {
    matches!(path, "/ws" | "/ws/status")
}

/// The method a CORS decision must be made against.
///
/// For a real request that is the request's own method. For a **preflight** (`OPTIONS`) the real
/// request has not been sent yet, so the browser declares its intent in
/// `Access-Control-Request-Method` — and THAT is what the policy must judge, or a preflight for a
/// wallet `POST` would be evaluated as a harmless `OPTIONS`, pass, and only then be refused on the
/// actual request. Judging the declared method keeps the preflight answer and the real answer the
/// same.
///
/// A preflight with no declared method is not a preflight a browser sends; it is judged as
/// `OPTIONS` itself, which is not a content read, so it fails CLOSED for the app family.
fn effective_method(parts: &axum::http::request::Parts) -> Method {
    if parts.method != Method::OPTIONS {
        return parts.method.clone();
    }
    parts
        .headers
        .get(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Method::from_bytes(v.as_bytes()).ok())
        .unwrap_or(Method::OPTIONS)
}

/// Environment allowlist of extra desktop-app CORS origins (#669) — a comma/semicolon-separated
/// list of exact origins an operator opts in (e.g. a custom Tauri/Electron scheme). Absent by
/// default; the built-in Tauri origins need no configuration.
pub const APP_ORIGINS_ENV: &str = "DIG_NODE_CORS_APP_ORIGINS";

/// The built-in desktop-app origins reflected without configuration: Tauri's two canonical origins
/// (`tauri://localhost` on Linux/Windows, `https://tauri.localhost` on macOS/Windows).
const BUILTIN_APP_ORIGINS: [&str; 2] = ["tauri://localhost", "https://tauri.localhost"];

/// Whether `origin` is an allowed desktop-app origin (#669): a built-in Tauri origin, or an exact
/// match in the [`APP_ORIGINS_ENV`] opt-in allowlist. Kept loopback-trust only — a desktop app runs
/// on the same machine as the node it reaches.
fn is_app_origin(origin: &str) -> bool {
    if BUILTIN_APP_ORIGINS.contains(&origin) {
        return true;
    }
    std::env::var(APP_ORIGINS_ENV).is_ok_and(|list| {
        list.split([',', ';'])
            .map(str::trim)
            .any(|allowed| !allowed.is_empty() && allowed == origin)
    })
}

/// Whether a CORS `Origin` is a same-machine local WEB origin we reflect (#91): the
/// extension's `chrome-extension://` scheme, or an `http://` page served from one
/// of the canonical local names (`localhost` / `dig.local` / `127.0.0.1` /
/// `127.0.0.2`, with or without a `:port`). PURE so the policy is unit-testable.
fn is_local_origin(origin: &str) -> bool {
    if origin.starts_with("chrome-extension://") {
        return true;
    }
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    // `rest` is `host[:port]`. An empty host is not a valid origin (host_is_allowed
    // treats a blank Host as "no header" and allows it; for an Origin that is wrong).
    if rest.trim().is_empty() {
        return false;
    }
    host_is_allowed(Some(rest))
}

/// Axum middleware enforcing the [`host_is_allowed`] allowlist (#91). A request
/// whose `Host` header is not a canonical local name is rejected `421 Misdirected
/// Request` with a catalogued JSON-RPC-style error body, so even though the node
/// binds loopback-only (enforced — a non-loopback DIG_NODE_HOST is refused unless
/// DIG_NODE_ALLOW_REMOTE=1, #1662) it never serves a foreign-named (rebinding) request. Allowed
/// requests pass through untouched. `OPTIONS` (CORS preflight) is exempt so the
/// browser's preflight to an allowed origin always succeeds.
async fn host_guard(req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    if host_is_allowed(host) {
        return next.run(req).await;
    }
    (
        StatusCode::MISDIRECTED_REQUEST,
        Json(rpc_error(
            Value::Null,
            ErrorCode::InvalidRequest,
            "dig-node: Host not allowed — this loopback node answers only to \
             dig.local / localhost / 127.0.0.1 / 127.0.0.2 / ::1",
        )),
    )
        .into_response()
}

/// Construct the shared state from config: apply the upstream to dig-node's env,
/// then build the node from the environment (cache dir/cap, §21 identity), and
/// generate/load the local control token into the machine-wide state dir (#501).
/// Resolve the machine-wide state dir + the control token, applying the #501 hardening on a
/// SERVICE run and FAILING CLOSED when the machine dir cannot be secured.
///
/// - **Service run:** [`crate::state::ensure_service_state_dir`] hardens + readback-verifies
///   the machine dir (owner→SYSTEM, purge foreign ACEs, protected DACL, no Users/Everyone
///   ACE) BEFORE the token is written. If it cannot be secured, the node does NOT write the
///   token there — it falls back to an ephemeral, unshared dir + a random in-memory token so
///   the control plane is unauthorizable (never served from an attacker-controlled dir).
/// - **CLI / dev run:** unchanged — resolve (read an existing machine dir, else the legacy
///   per-user dir), never harden. A persist failure also fails closed to the in-memory token.
fn resolve_state_dir_and_token() -> (std::path::PathBuf, String) {
    // The ephemeral fail-closed fallback: an unshared temp dir + a random in-memory token
    // that nothing can present → the control plane is unauthorizable.
    let ephemeral = || {
        let dir =
            std::env::temp_dir().join(format!("dig-node-control-token-{}", std::process::id()));
        let token = control::load_or_create_token_at(&dir.join(control::CONTROL_TOKEN_FILE))
            .unwrap_or_default();
        (dir, token)
    };

    if crate::state::running_as_service() {
        match crate::state::ensure_service_state_dir() {
            Ok(dir) => {
                match control::load_or_create_token_at(&dir.join(control::CONTROL_TOKEN_FILE)) {
                    Ok(token) => (dir, token),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "could not persist the control token in the secured state dir; using \
                             an in-memory token (control.* unauthorizable)"
                        );
                        ephemeral()
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    remedy = %control::control_token_remedy(),
                    "could not secure the machine state dir; refusing to serve the control plane \
                     from it"
                );
                ephemeral()
            }
        }
    } else {
        let dir = crate::state::state_dir();
        match control::load_or_create_token() {
            Ok(token) => (dir, token),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not persist control token; using an in-memory token (control.* will be \
                     unauthorizable until the state dir is writable)"
                );
                ephemeral()
            }
        }
    }
}

pub async fn build_state(config: &Config) -> AppState {
    config.apply_to_env();
    let node = Node::from_env();
    let config_path = dig_node_core::config_path();
    // Assemble the SERVED wallet under the node config dir (#368): the live wallet DB + custody +
    // shared event bus + mTLS cert. Never blocks on network (graceful fallback tier).
    let config_dir = config_path.parent().unwrap_or(&config_path).to_path_buf();
    // Pass the live-broadcast flag (§18.12, #428): OFF ⇒ offline-safe (no $DIG moves); ON ⇒ real
    // mainnet broadcast + confirm for node-custodied spends.
    let wallet_service = WalletService::build_with(
        &config_dir,
        dig_wallet::sage::service::WalletServiceConfig {
            enable_live_broadcast: config.enable_live_broadcast,
            // Chain sync is a READ into the node's own replica, so it runs on every install —
            // deliberately NOT gated on the spend flag above (#2501). It is separately
            // switchable because starting it dials the network, which an integration harness
            // must be able to decline (see `Config::enable_chain_sync`).
            enable_chain_sync: config.enable_chain_sync,
        },
    )
    .await;
    // Resolve the machine-wide state dir the control token + paired-token store live in
    // (#501). On a SERVICE run this HARDENS + readback-verifies the machine dir per the
    // security contract BEFORE the token is written into it (owner→SYSTEM, purge foreign
    // ACEs, protected DACL, no Users/Everyone ACE) — closing the ProgramData squatting hole
    // where a low-priv user pre-creates C:\ProgramData\DigNode and keeps CREATOR OWNER /
    // WRITE_DAC. If the dir cannot be secured, the node MUST NOT write the token there:
    // it fails closed onto an ephemeral, unshared dir + an in-memory token so the control
    // plane is unauthorizable rather than served from an attacker-controlled dir. The read
    // plane is unaffected either way. The CLI (non-service) never hardens — it only reads.
    let (state_dir, control_token) = resolve_state_dir_and_token();
    AppState {
        content_server: node.as_content_server(),
        node,
        relay: Arc::new(crate::relay::RelayGuard::new(&config.upstream)),
        http: reqwest::Client::builder()
            .user_agent(concat!("dig-node/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("dig-node: build http client"),
        addr: config.bind_addr().to_string(),
        config_path,
        state_dir,
        control_token,
        // Node::from_env loads/creates the §21.9 identity, enabling authenticated
        // whole-store sync; we report it available and let the per-capsule fetch
        // surface a real NOT_SUPPORTED/failure in-band if a given store isn't served.
        sync_available: true,
        started: Instant::now(),
        pairings: Arc::new(std::sync::Mutex::new(
            crate::pairing::PendingPairings::default(),
        )),
        wallet: wallet_service.backend,
        wallet_cert: wallet_service.cert,
        wallet_chain: wallet_service.chain,
        mirror_bonds: crate::mirror::lifecycle::new_snapshot(),
        control_ingress: Arc::new(dig_node_core::rate_limit::MissRateLimiter::new(
            CONTROL_INGRESS_BURST,
            CONTROL_INGRESS_REFILL_PER_SEC,
        )),
    }
}

impl AppState {
    /// The served node-custodied wallet backend (#368). Exposed so a caller that built the state
    /// (e.g. an integration test, or the bring-up that spawns the mTLS listener) can share the SAME
    /// backend + its event bus the router dispatches to.
    pub fn wallet_backend(&self) -> Arc<WalletBackend> {
        self.wallet.clone()
    }

    /// This node's loop-probe request (#1997) — the exact body [`crate::relay`] sends to the
    /// configured upstream at bring-up.
    ///
    /// TEST-CONSTRUCTION ONLY, behind `testkit` so it is genuinely absent from a production build.
    /// Exposed because the loop breaker's whole value is what happens when this request comes back
    /// to THIS node, and a test cannot stage that without knowing the id the node generated. The
    /// alternative — trusting the unit tests and asserting nothing end-to-end — is how a correct
    /// guard ends up wired to nothing.
    #[cfg(any(test, feature = "testkit"))]
    pub fn loop_probe_request(&self) -> Value {
        self.relay.probe_request()
    }

    /// Whether this node would relay an unimplemented method right now (#1997).
    ///
    /// TEST-CONSTRUCTION ONLY, behind `testkit`. Lets a test observe the loop breaker's state
    /// transition directly rather than inferring it from a downstream side effect.
    #[cfg(any(test, feature = "testkit"))]
    pub fn would_relay(&self) -> bool {
        self.relay.should_relay()
    }

    /// Whether the ENGINE would still make an outbound upstream call (#1997).
    ///
    /// TEST-CONSTRUCTION ONLY, behind `testkit`. Distinct from [`Self::would_relay`] on purpose:
    /// that reports the shell's method-passthrough guard, this reports `dig-node-core`, which owns
    /// the two CONTENT legs. The security audit found the loop latch wired to the first and not the
    /// second, so a test must be able to tell them apart rather than infer one from the other.
    #[cfg(any(test, feature = "testkit"))]
    pub fn engine_would_use_upstream(&self) -> bool {
        self.node.has_upstream()
    }

    /// Repoint the seam-5 content-server handle (#1285 W1c) at another implementation, leaving every
    /// other field of the built state intact.
    ///
    /// This is the injectable boundary the [`content_server`](AppState::content_server) field
    /// documents: a caller holding a built state can substitute an `Arc<dyn ContentServer>` — a
    /// recording double in a test, or a different concrete server in a later composition root —
    /// without reaching into the node.
    ///
    /// TEST-CONSTRUCTION ONLY (#1664a): `pub` solely so integration tests can inject a recording
    /// double. Gated behind the `testkit` feature rather than `#[doc(hidden)]` (#1609): hiding a symbol
    /// from the documentation leaves it entirely callable, so it hides the seam from readers without
    /// closing it — the feature flag makes it genuinely absent from a production build, which is what
    /// "test-only" has to mean to be worth stating.
    #[cfg(any(test, feature = "testkit"))]
    pub fn with_content_server(mut self, content_server: Arc<dyn ContentServer>) -> Self {
        self.content_server = content_server;
        self
    }
}

/// The [`ControlCtx`] for one request — borrows the long-lived node + config and
/// snapshots the per-state fields the control plane needs.
fn control_ctx(state: &AppState) -> ControlCtx {
    ControlCtx {
        node: state.node.clone(),
        config_path: state.config_path.clone(),
        state_dir: state.state_dir.clone(),
        addr: state.addr.clone(),
        upstream: state.relay.upstream().to_string(),
        started: state.started,
        sync_available: state.sync_available,
        pairings: state.pairings.clone(),
        wallet: state.wallet.clone(),
        mirror_bonds: state.mirror_bonds.clone(),
    }
}

/// The status fields shared by `GET /health` and `GET /ws/status` (#239): service
/// identity, mode, the bound `addr`, `upstream`, cache stats, and §21 sync
/// availability. Pulled out so the two unauthenticated liveness surfaces can never
/// silently drift from each other.
fn status_fields(state: &AppState) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("service".into(), json!(meta::SERVICE_NAME));
    m.insert("version".into(), json!(VERSION));
    m.insert("commit".into(), json!(meta::GIT_SHA));
    m.insert("mode".into(), json!("local-node"));
    m.insert("addr".into(), json!(state.addr));
    m.insert("upstream".into(), json!(state.relay.upstream()));
    m.insert(
        "cache".into(),
        json!({
            "dir": meta::cache_dir().display().to_string(),
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
            // #96: whether the cache is the shared canonical dir (the dir the DIG
            // Browser's in-process node also uses) or a process-private fallback.
            "shared": meta::cache_shared(),
        }),
    );
    // §21 whole-store sync availability (whether a §21.9 identity is loaded) — the
    // "sync state" a live client wants alongside version/addr (#239).
    m.insert("sync".into(), json!({ "available": state.sync_available }));
    // Peer-tier readiness (#1763). The HTTP surface answers content reads ~30 s BEFORE the peer
    // network attaches, so "the node responds" has never implied "the node can reach peers". This
    // is the checkable signal for the difference: an acceptance test polls `peer_tier.attached`
    // until it is true instead of sleeping a guessed interval, and a read taken before then is
    // known to be a gateway measurement rather than assumed to be a P2P one.
    m.insert("peer_tier".into(), peer_tier_status(state.node.peer_tier()));
    m
}

/// The `/health` `peer_tier` object for a given tier — the ONE place the wire spelling of
/// peer-tier readiness is decided, so both directions are assertable without standing up a peer
/// network (attachment itself is only settable inside `dig-node-core`).
///
/// `attached: true` is the signal SPEC.md §6.1/§7.8 tell every harness to POLL instead of sleeping,
/// so a field that never reports `true` turns the documented wait into an infinite one with the
/// same observable signature as the legitimate cold-start window.
fn peer_tier_status(tier: PeerTier) -> Value {
    json!({ "attached": tier == PeerTier::Attached })
}

/// The `dig.health` result — the PUBLIC liveness body (#1997).
///
/// Deliberately a small, hand-picked set rather than [`status_fields`], and the difference matters:
/// `GET /health` is reachable only over loopback, whereas `dig.health` is on the rpc.dig.net
/// public-read allowlist, so **this body is readable anonymously from the internet**. Serving the
/// operational body there would newly publish the node's absolute cache path (which contains the OS
/// account name), its configured upstream (which can name internal infrastructure), its bound
/// address, and its exact commit — none of which a content reader needs, and each of which helps
/// someone targeting the host.
///
/// What remains is what the `dig_rpc_protocol::types::Health` contract is actually for: is this node
/// alive, what version is it, and what does it serve. The operational detail stays on the
/// loopback-only `GET /health` and the token-gated `control.status`, which is where it was before
/// this method existed.
fn public_health() -> Value {
    json!({
        "status": "ok",
        "version": VERSION,
        "methods": meta::public_method_names(),
    })
}

/// `GET /health` (and `GET /`) — liveness + mode + cache stats + discovery hooks.
/// Shape extends the Node reference server's health body (existing probes keep parsing
/// `status`/`version`/`mode`/`upstream`/`cache`) with agent-friendly additions:
/// `service` (the canonical `dig-node` name), `commit`, the bound `addr`, the
/// cache `dir` + `shared` flag (#96 — is the cache the shared canonical dir or a
/// private fallback), and the `methods` catalogue — so a single `/health` fetch
/// reveals what the node is and what it serves.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = status_fields(&state);
    body.insert("status".into(), json!("ok"));
    body.insert("methods".into(), json!(meta::method_names()));
    Json(Value::Object(body))
}

/// Heartbeat cadence for `GET /ws/status` (#239): short enough that a half-open
/// connection (dead TCP with no FIN — e.g. sleep/network-change) is noticed
/// within one interval, on both sides of the socket.
const WS_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// If no pong (nor any other client frame) has been observed within this long,
/// the connection is treated as half-open and closed server-side — 4x the
/// heartbeat interval, a generous margin for scheduling jitter while still
/// "detected promptly" (#239 acceptance #2).
const WS_PONG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// `GET /ws/status` (#239) — upgrade to a WebSocket status/liveness channel. The
/// `Origin` header is checked against the SAME [`is_local_origin`] allowlist the
/// CORS layer reflects: unlike `fetch`, a WebSocket handshake is not blocked by
/// the browser based on CORS response headers, so the server itself must reject
/// a disallowed Origin (Cross-Site WebSocket Hijacking defense). A request with
/// NO Origin header (a non-browser client, e.g. this repo's own tests, or a CLI)
/// is allowed — loopback-only binding (enforced — a non-loopback DIG_NODE_HOST is
/// refused unless DIG_NODE_ALLOW_REMOTE=1, #1662) is that caller's defense.
async fn ws_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !is_local_origin(origin) {
            return (
                StatusCode::FORBIDDEN,
                Json(rpc_error(
                    Value::Null,
                    ErrorCode::InvalidRequest,
                    "dig-node: Origin not allowed for /ws/status",
                )),
            )
                .into_response();
        }
    }
    ws.on_upgrade(move |socket| ws_status_session(socket, state))
}

/// Drive one `/ws/status` connection (#239): send the initial `status` snapshot,
/// then loop pushing a `heartbeat` (a refreshed snapshot + `ts`) every
/// [`WS_HEARTBEAT_INTERVAL`] alongside a transport-level WS ping, while watching
/// for the client's pong/close/disconnect. Any status change (cache usage, sync
/// availability) is visible within one heartbeat — there is no separate
/// change-detection push in this version (the simplest thing that works). If no
/// frame from the client is observed for [`WS_PONG_TIMEOUT`], the connection is
/// treated as half-open and closed from this side so the client reconnects.
async fn ws_status_session(mut socket: WebSocket, state: AppState) {
    let mut snapshot = status_fields(&state);
    snapshot.insert("type".into(), json!("status"));
    if socket
        .send(Message::Text(Value::Object(snapshot).to_string()))
        .await
        .is_err()
    {
        return; // client gone before the first send
    }

    let mut ticker = tokio::time::interval(WS_HEARTBEAT_INTERVAL);
    ticker.tick().await; // consume the immediate first tick (the snapshot above already went out)
    let mut last_seen = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if last_seen.elapsed() > WS_PONG_TIMEOUT {
                    let _ = socket.send(Message::Close(None)).await;
                    return;
                }
                let mut hb = status_fields(&state);
                hb.insert("type".into(), json!("heartbeat"));
                hb.insert(
                    "ts".into(),
                    json!(std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64),
                );
                if socket.send(Message::Text(Value::Object(hb).to_string())).await.is_err() {
                    return;
                }
                // A transport-level ping the client's WS implementation auto-pongs
                // (browsers do this at the protocol layer, invisible to page JS —
                // only the socket's eventual open/close state is observable there).
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    return;
                }
            }
            msg = socket.recv() => {
                match msg {
                    // Echo the Close frame back (the WS closing handshake) before
                    // dropping the socket — otherwise the peer sees an abrupt reset
                    // rather than a clean close.
                    Some(Ok(Message::Close(_))) => {
                        let _ = socket.send(Message::Close(None)).await;
                        return;
                    }
                    // ANY other frame from the client (pong, or otherwise) is evidence
                    // the round trip is alive.
                    Some(Ok(_)) => { last_seen = tokio::time::Instant::now(); }
                    Some(Err(_)) | None => return,
                }
            }
        }
    }
}

/// `GET /version` — the build/commit/version fingerprint, so an agent can correlate
/// a running node to an exact source revision (see [`meta::build_info`]).
async fn version() -> impl IntoResponse {
    Json(meta::build_info())
}

/// `GET /openrpc.json` — the OpenRPC document for the node's JSON-RPC surface,
/// generated from the method catalogue + error enum (see [`meta::openrpc_document`]).
async fn openrpc() -> impl IntoResponse {
    Json(meta::openrpc_document())
}

/// `GET /.well-known/dig-node.json` — the canonical discovery document: service
/// identity, bound addr, cache dir + live stats, the method + error catalogues,
/// and pointers to the OpenRPC/health/version endpoints.
async fn well_known(State(state): State<AppState>) -> impl IntoResponse {
    Json(meta::well_known_document(
        &state.addr,
        state.relay.upstream(),
        cache_cap_bytes(),
        cache_used_bytes(),
    ))
}

/// The [`ReadOrigin`](dig_node_core::download::ReadOrigin) label for one accepted connection,
/// derived SOLELY from that connection's real remote address: a loopback peer is this node's own
/// operator (`Local`); anything else is a stranger on the wire (`Peer`).
///
/// This is a SECURITY LABEL (#1619 follow-up), and the derivation is deliberately the ONLY way any
/// handler obtains one — a handler must never assert an origin from "this endpoint is the loopback
/// server". The bind IS loopback-only by default, and a `DIG_NODE_HOST` override off loopback is
/// refused at startup unless the operator sets `DIG_NODE_ALLOW_REMOTE=1` ([`crate::config::host_override_refusal`],
/// #1662) — but the Host-header allowlist is a DNS-rebinding defense rather than an origin one (a
/// remote client can still send `Host: localhost`), and an operator MAY deliberately opt into a
/// remote bind. So the label is derived from the connection's real remote address, not the bind:
/// a deliberately-remote operator gets a CORRECT `Peer` label for remote callers, never a
/// silently-forged `Local` one.
///
/// The loopback check is [`crate::config::is_loopback_addr`], which correctly treats an IPv4-mapped
/// IPv6 loopback (`::ffff:127.0.0.1`, seen on a `::` dual-stack bind) as `Local` (#1664b) — the bare
/// `Ipv6Addr::is_loopback` (`== ::1` only) would misclassify it as `Peer`. A remote IPv4-mapped
/// address is still non-loopback, and a failure to extract
/// [`ConnectInfo`](axum::extract::ConnectInfo) is an axum REJECTION (`500`), never a defaulted `Local`.
fn read_origin_for(peer_addr: &SocketAddr) -> dig_node_core::download::ReadOrigin {
    // Use the SHARED loopback predicate (#1664b): on a `::` dual-stack bind an IPv4
    // loopback client arrives as the IPv4-mapped form `::ffff:127.0.0.1`, which the bare
    // `IpAddr::is_loopback` misclassifies as non-loopback (`Ipv6Addr::is_loopback` is
    // `== ::1` only) — silently mislabelling the operator's OWN reads as `Peer` and
    // disabling the local warm-up flywheel. `is_loopback_addr` unwraps the mapping.
    if crate::config::is_loopback_addr(&peer_addr.ip()) {
        dig_node_core::download::ReadOrigin::Local
    } else {
        dig_node_core::download::ReadOrigin::Peer
    }
}

/// The [`RequestorId`](dig_node_core::rate_limit::RequestorId) that keys the miss-path per-requestor
/// rate limiter (dig_ecosystem#2007) for an HTTP JSON-RPC caller: the operator's own loopback reads
/// share the trusted [`Local`](dig_node_core::rate_limit::RequestorId::Local) bucket; a non-loopback
/// caller (an anonymous/gateway client with no node identity) is keyed by its connection IP, so one
/// abusive source's exhausted miss-lookup budget never refuses a different source.
fn requestor_for(peer_addr: &SocketAddr) -> dig_node_core::rate_limit::RequestorId {
    if crate::config::is_loopback_addr(&peer_addr.ip()) {
        dig_node_core::rate_limit::RequestorId::Local
    } else {
        dig_node_core::rate_limit::RequestorId::Anonymous(peer_addr.ip().to_string())
    }
}

/// Whether an OPEN, token-less `control.*` read is admitted at INGRESS for `requestor`
/// (dig_ecosystem#3051).
///
/// # The operator is exempt, and that is the whole design
///
/// [`RequestorId::Local`](dig_node_core::rate_limit::RequestorId::Local) — the node's own loopback
/// operator — is admitted unconditionally, mirroring the PROXY fetch-through limiter's documented
/// rationale (`download.rs`: the bound targets the REMOTE amplification vector; the operator is
/// trusted). Two reasons, and the second is the load-bearing one:
///
/// 1. The exposure dig_ecosystem#3051 names is the ANONYMOUS caller — a control surface made
///    network-reachable and unauthenticated by `DIG_NODE_ALLOW_REMOTE=1`. That caller presents no
///    credential, so nothing else bounds it. It arrives here as
///    [`Anonymous`](dig_node_core::rate_limit::RequestorId::Anonymous), keyed by connection IP.
/// 2. Throttling the operator would REINTRODUCE the failure this whole family exists to fix. A
///    polling dig-app already drained the wallet's egress limiter and left a user's own profile
///    read refused for days; the remedy was to stop charging reads that cost nothing. An ingress
///    bound on loopback would produce the same user-visible refusal from the other side, and a
///    per-frame poller sits exactly at the edge of any burst small enough to be worth setting.
///
/// # State plainly what this does NOT bound
///
/// Under the DEFAULT posture the bind is loopback-only, so every caller is `Local` and this gate
/// admits everything. That is intended — it is the `DIG_NODE_ALLOW_REMOTE` exposure being bounded,
/// exactly as dig_ecosystem#3051 scoped it ("size the work accordingly") — but it means a RUNAWAY
/// LOCAL client is still unbounded here, and remains so deliberately. Bounding it is a UX decision
/// about the operator's own software, not a defense against an untrusted party, and it is the
/// decision that just cost a user several days.
fn control_ingress_admits(
    limiter: &dig_node_core::rate_limit::MissRateLimiter,
    requestor: &dig_node_core::rate_limit::RequestorId,
) -> bool {
    requestor.is_local() || limiter.check(requestor)
}

/// Classify a request's landing PROVENANCE (#1654/#1956) from its `Sec-Fetch-Site` header — the
/// second landing axis over [`read_origin_for`], applied identically to the `/s/` plaintext serve
/// path AND the `POST /` JSON-RPC path (`dig.getContent`/`dig.fetchRange`). A loopback address proves
/// the CONNECTION is local,
/// but not that the operator authorized the request: a malicious web page can drive a cross-site
/// `GET dig.local/s/<capsule>`, and the durable LANDING side effect (cache write → DHT holder,
/// SPEC §14.3/§21.3) would then be remotely triggerable. The browser reports the driving origin in
/// `Sec-Fetch-Site`; a `cross-site` value folds landing to `Peer` while the bytes still serve. A
/// non-browser client (CLI/SDK) sends no header ⇒ first-party. See
/// [`dig_node_core::download::from_sec_fetch_site`].
fn provenance_for(headers: &HeaderMap) -> dig_node_core::download::RequestProvenance {
    dig_node_core::download::from_sec_fetch_site(
        headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()),
    )
}

/// `POST /` — JSON-RPC. Normalises the request params for dig-node, dispatches via
/// `handle_rpc`, and returns the node's JSON-RPC envelope. A non-object body (e.g.
/// a batch array, which dig-node does not handle) is rejected in-band so the client
/// sees a JSON-RPC error rather than a transport failure.
///
/// Blind-passthrough fallback: dig-node resolves only `dig.getContent` /
/// `dig.getAnchoredRoot` / `dig.getManifest` / `cache.*` (plus the collection/L7-peer/
/// `dig.stage` surface) and returns `-32601 method not found` for everything else. For
/// those (e.g. `dig.getProof`, `dig.listCapsules`) this service relays the ORIGINAL
/// request to the upstream so it stays a correct transparent proxy — matching the Node
/// reference server and the surface clients expect from an rpc.dig.net endpoint.
async fn rpc(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> impl IntoResponse {
    let origin = read_origin_for(&peer_addr);
    let requestor = requestor_for(&peer_addr);
    // Classify the SECOND landing axis (#1956): the `/s/` serve path (#1654) already gates on
    // Sec-Fetch-Site so a cross-site page cannot drive capsule landing; the JSON-RPC POST path must
    // gate identically, or a same-origin capsule page could `POST dig.getContent`/`dig.fetchRange`
    // and drive this node into becoming a holder. WITHOUT this classification the gate is a no-op.
    let provenance = provenance_for(&headers);
    if !req.is_object() {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        return (
            StatusCode::OK,
            Json(rpc_error(
                id,
                ErrorCode::InvalidRequest,
                "dig-node: expected a single JSON-RPC request object",
            )),
        );
    }
    let id = request_id(&req);
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    // Per-request diagnostics (SPEC §6). Routed through a helper that takes ONLY the method name
    // so the request body — which for a control/pairing call carries tokens (§7 never-log) — is
    // structurally unable to reach a log field. DEBUG keeps the per-request trail off the default
    // INFO operator view.
    crate::logging::log_rpc_dispatch(&method);

    // `rpc.discover` is answered by the shell itself (the standard OpenRPC
    // method-discovery method): return the OpenRPC document so an agent can
    // introspect the whole surface over the wire with no out-of-band knowledge.
    if method == "rpc.discover" {
        return (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": meta::openrpc_document(),
            })),
        );
    }

    // A request carrying THIS node's loop-probe id proves the configured upstream leads back here
    // (#1997), whatever DNS/CDN/gateway sits in between. Recorded before the answer so the very
    // next relay decision already sees it. The probe is still ANSWERED normally below — it is an
    // ordinary `dig.health` call, and replying keeps the sender's own bookkeeping honest.
    if state.relay.is_own_probe(&id) {
        state.relay.disable_after_loop();
        // ALSO latch the engine (#1997). The guard above stops the shell's method-passthrough
        // relay, which is only ONE of the three legs that reach an upstream; the other two carry
        // content (`dig.getContent`'s miss proxy and the `/s/*` Tier 3 fetch) and live inside
        // dig-node-core, gated on `Node::has_upstream`. Latching only the shell would leave a node
        // that has DETECTED and LOGGED a loop still recursing on any anonymous `dig.getContent`
        // for content it does not hold — the original outage, on the more expensive path, behind a
        // log line claiming the loop was closed.
        state.node.disable_upstream_after_loop();
    }

    // `dig.health` / `dig.methods` are answered by the shell, from the SAME catalogue and status
    // body `GET /health` uses (#1997). A node states its own liveness and its own method list on
    // its own authority: needing an upstream to answer either is what made an unconfigured node
    // unable to describe itself at all.
    if method == "dig.health" {
        return (
            StatusCode::OK,
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": public_health() })),
        );
    }
    if method == "dig.methods" {
        return (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "methods": meta::public_method_names() },
            })),
        );
    }

    // `dig.getCollateralEpoch` — the gossip serve half of the per-epoch collateral record
    // (dig-node#387). A peer asking about a PAST epoch is answered from this node's own store
    // rather than sent off to re-census a week of chain history.
    //
    // Answered by the shell, like `dig.health`, and for the same reason: a node states what it
    // holds on its own authority, and needing an upstream to answer would make a node that has
    // recorded an epoch unable to say so.
    //
    // A record this build cannot interpret is NOT served as a record. It is served as a refusal
    // naming the version, so the caller learns the useful fact — this node is behind the ruleset —
    // instead of receiving figures neither end can vouch for.
    if method == "dig.getCollateralEpoch" {
        let result = collateral_epoch_answer(req.get("params").unwrap_or(&Value::Null));
        return (
            StatusCode::OK,
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
        );
    }

    // PAIRING plane (#280): `pairing.request` / `pairing.poll` are OPEN (no token) —
    // an MV3 extension can't read the control-token file, so it bootstraps a scoped
    // credential here. They are NOT under `control.` (so the gate below leaves them
    // open) and are answered by the shell (not the read path). The scoped token they
    // yield is minted only after LOCAL operator approval via the gated
    // `control.pairing.approve` (see [`crate::pairing`]).
    if method == "pairing.request" || method == "pairing.poll" {
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let resp = if method == "pairing.request" {
            pairing::request(&state.pairings, id, &params)
        } else {
            pairing::poll(&state.pairings, id, &params)
        };
        return (StatusCode::OK, Json(resp));
    }

    // CONTROL plane: the `control.*` (admin/management) methods are gated fail-closed on a
    // presented token — the REAL protection (#1663). A same-host controller must present the
    // local control token (the X-Dig-Control-Token header or params._control_token) or a valid
    // paired token; an unauthorized call is rejected below regardless of where it arrives from.
    // The loopback bind (enforced — a non-loopback DIG_NODE_HOST is refused unless
    // DIG_NODE_ALLOW_REMOTE=1, #1662) is defense-in-depth beneath this gate, not the gate itself.
    // The READ methods below are NOT token-gated.
    if control::is_control_method(&method) {
        // An OPEN control READ (`control.wallet.balance`, #1851) is a public-address chain read
        // with no custody — served WITHOUT the control token, like the other reads, while still
        // routing through the control dispatcher below. Every other control method is token-gated.
        // An open read presents NO credential, so nothing above this point has cost the caller
        // anything — and `control.wallet.coinById`/`.coinSpend` each run up to two SQLite lookups
        // (plus an LRU `UPDATE` on a hit) inside the dispatch below. That work is unbounded per
        // request, so it is bounded HERE, at ingress, before the dispatcher is entered
        // (dig_ecosystem#3051).
        //
        // This is a SEPARATE bound from the wallet's coinset-fallback limiter, on purpose. That one
        // bounds EGRESS and exists to protect the third-party oracle; this one bounds REQUESTS and
        // exists to protect this process. They fire for different reasons, so they refuse with
        // different codes (`CONTROL_INGRESS_LIMITED` vs `WALLET_RATE_LIMITED`) — conflating them is
        // what would leave the next person debugging a refusal unable to tell which one fired.
        if control::is_open_control_read(&method) {
            if !control_ingress_admits(&state.control_ingress, &requestor) {
                return (
                    StatusCode::OK,
                    Json(control::control_error(
                        id,
                        ErrorCode::ControlIngressLimited,
                        "open control reads are rate-limited per source; back off and retry. \
                         This is the INGRESS bound on requests to this node, not the chain-egress \
                         bound (WALLET_RATE_LIMITED).",
                    )),
                );
            }
        } else {
            let header_tok = headers
                .get(control::CONTROL_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok());
            let presented = control::presented_token(header_tok, &req);
            // Authorization is granted by EITHER the master control token OR — for a method
            // OUTSIDE the master tier — a valid PAIRED token (#280). The master tier is every
            // method whose effect outlives the token that invoked it: pairing administration
            // (so a paired controller can neither mint more tokens nor revoke itself) and
            // `chiaPeers.add`/`.remove` (so it cannot install a peer that keeps unbounded
            // authority over the wallet replica after revocation). The tier is read from the
            // contract, never restated here — see `control::requires_master_token`.
            //
            // This gate covers the `control.*` plane only. The SAME capabilities are reachable by
            // their Sage-parity names (`add_peer`/`remove_peer`) on the wallet plane below, which
            // resolves the identical tier through `wallet_authz` — a tier enforced on one plane
            // and not the other is not enforced.
            let master_ok =
                control::is_authorized(&method, presented.as_deref(), &state.control_token);
            let paired_ok = !control::requires_master_token(&method)
                && presented.as_deref().is_some_and(|tok| {
                    pairing::is_paired_token(&pairing::paired_tokens_path(&state.state_dir), tok)
                });
            if !(master_ok || paired_ok) {
                return (
                    StatusCode::OK,
                    Json(control::control_error(
                        id,
                        ErrorCode::Unauthorized,
                        format!(
                            "control.* requires the local control token (X-Dig-Control-Token \
                             header or params._control_token, from {}), or a paired controller \
                             token (see `dig-node pair`). {}",
                            control::control_token_path().display(),
                            control::control_token_remedy()
                        ),
                    )),
                );
            }
        }
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let ctx = control_ctx(&state);
        let resp = control::dispatch_control(&ctx, id, &method, &params).await;
        return (StatusCode::OK, Json(resp));
    }

    // WALLET plane (#370, §7.12): custody-lifecycle (`wallet.*`) + wallet MUTATION methods
    // (sign/spend/offer/mint/transfer + state-changing actions) are paired-token gated over this
    // authorized surface AND are NEVER relayed upstream — a signing/custody request must not leave
    // the loopback node. Authorization is the master control token OR a valid paired token (#280);
    // an unauthorized caller (no/wrong/revoked token) is -32030. An authorized call is served
    // locally by the node-custodied wallet once that surface is wired on this transport
    // (#368/#369); until then it returns a catalogued method-not-served error rather than leaking a
    // spend/custody op to the public gateway.
    if wallet_authz::requires_authorization(&method) {
        let header_tok = headers
            .get(control::CONTROL_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok());
        let presented = control::presented_token(header_tok, &req);
        let paired_path = pairing::paired_tokens_path(&state.state_dir);
        let authorized =
            wallet_authz::authorize(&method, presented.as_deref(), &state.control_token, |tok| {
                pairing::is_paired_token(&paired_path, tok)
            });
        if !authorized {
            return (
                StatusCode::OK,
                Json(rpc_error(
                    id,
                    ErrorCode::Unauthorized,
                    "this wallet method requires the local control token (X-Dig-Control-Token \
                     header or params._control_token) or a paired controller token (see \
                     `dig-node pair`); it is never relayed upstream",
                )),
            );
        }
        // Authorized: serve via the node-custodied wallet backend (#368) — the JSON-RPC `params`
        // object IS the Sage request body. A signing/custody request is NEVER relayed upstream.
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let body = serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string());
        let (status, out) = state.wallet.dispatch(&method, &body).await;
        return (
            StatusCode::OK,
            Json(wallet_result_to_jsonrpc(id, status, out)),
        );
    }

    // LANDING gate (#1654/#1476/#2108): the holder-revealing `cache.*` methods over the HTTP surface.
    // `cache.fetchAndCache` (fetch + cache + DHT-announce a capsule of the CALLER'S choosing) and
    // `cache.pushCapsule` (accept + cache + DHT-announce capsule BYTES the caller supplies) both make
    // this node a durable holder — the same holder side effect (SPEC §14.3/§21.3). `cache.listCached`
    // ENUMERATES the operator's full cached-capsule inventory (storeId:rootHash, sizes, LRU order),
    // which deanonymizes what content the user has consumed (#2108) — a read, but a HOLDINGS-revealing
    // one, so it is gated identically. Over the HTTP surface a loopback address does not prove the
    // operator authorized the call (a cross-site page can POST to `dig.local` — DNS-rebinding /
    // local-service attack), so each requires the control token exactly like `control.*`: the master
    // control token OR a valid paired token. The in-process FFI `cache.*` path stays open (SYSTEM.md) —
    // it never reaches this HTTP `rpc` handler. Anonymous public CONTENT reads remain ungated; only
    // these holder-/holdings-revealing methods are gated. (WS parity: `cache.*` is not routable over
    // `/ws` — the wallet-backend fall-through has no `cache.*` arm — asserted in the server tests.)
    if method == "cache.fetchAndCache"
        || method == "cache.pushCapsule"
        || method == "cache.listCached"
    {
        let header_tok = headers
            .get(control::CONTROL_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok());
        let presented = control::presented_token(header_tok, &req);
        // Direct constant-time compare (NOT `control::is_authorized`, which fails OPEN for any
        // non-`control.*` method): either the master control token or a valid paired token.
        let master_ok = presented
            .as_deref()
            .is_some_and(|tok| control::ct_eq(tok, &state.control_token));
        let paired_ok = presented.as_deref().is_some_and(|tok| {
            pairing::is_paired_token(&pairing::paired_tokens_path(&state.state_dir), tok)
        });
        if !(master_ok || paired_ok) {
            return (
                StatusCode::OK,
                Json(rpc_error(
                    id,
                    ErrorCode::Unauthorized,
                    "cache.fetchAndCache / cache.pushCapsule / cache.listCached require the local \
                     control token (X-Dig-Control-Token header or params._control_token) or a paired \
                     controller token (see `dig-node pair`): fetchAndCache/pushCapsule make this node \
                     a durable DHT holder of the requested capsule, and listCached enumerates the \
                     operator's cached-capsule inventory (deanonymizing consumed content) — none is a \
                     public read",
                )),
            );
        }
    }

    // CHAT gate (F1, #1946): `chat.send` seals + BLS-signs a directed message as this node's OWN
    // 0x0010 identity, and `chat.poll` DRAINS the inbound inbox — both wield node-owned crypto/state,
    // so they require the control token exactly like `control.*` mutations. A loopback address alone
    // does not prove the paired chat app (any local process can POST here), so an unauthorized caller
    // is rejected BEFORE the seal/send or inbox drain runs. Authorization is the master control token
    // OR a valid paired token (#280). The same gate binds the WS transport ([`ws_dispatch`]).
    if is_gated_chat_method(&method) {
        let header_tok = headers
            .get(control::CONTROL_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok());
        let presented = control::presented_token(header_tok, &req);
        let paired_path = pairing::paired_tokens_path(&state.state_dir);
        let authorized = chat_call_authorized(presented.as_deref(), &state.control_token, |tok| {
            pairing::is_paired_token(&paired_path, tok)
        });
        if !authorized {
            return (
                StatusCode::OK,
                Json(rpc_error(
                    id,
                    ErrorCode::Unauthorized,
                    "chat.send/chat.poll require the local control token (X-Dig-Control-Token \
                     header or params._control_token) or a paired controller token (see \
                     `dig-node pair`): they wield the node's own signing identity and inbox",
                )),
            );
        }
    }

    // Keep the original request for a possible passthrough relay (the upstream must
    // see exactly what the client sent, not the dig-node-normalised form).
    let original = req.clone();
    let normalized = normalize_request(req);

    // handle_rpc never panics on a malformed request — it returns an error
    // envelope — but guard the dispatch anyway so a future change can't take the
    // server down on one bad request.
    let node = state.node.clone();
    // `origin` was derived above from the ACCEPTING CONNECTION'S remote address, not assumed.
    let resp = match tokio::task::spawn(async move {
        dig_node_core::handle_rpc_as(&node, normalized, origin, provenance, requestor).await
    })
    .await
    {
        Ok(v) => v,
        Err(e) => rpc_error(
            id.clone(),
            ErrorCode::DispatchFailed,
            format!("dig-node: dispatch failed: {e}"),
        ),
    };

    // A method dig-node did not resolve is relayed to the upstream — but ONLY when an operator
    // configured one and it has not been proven to lead back here (#1997). With no upstream the
    // node returns dig-node's own `-32601`, which is the truthful answer for a method it genuinely
    // does not implement, and is what keeps an unrecognised method (and its params) from being
    // forwarded to a host the operator never chose.
    if resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
        == Some(METHOD_NOT_FOUND)
        && state.relay.should_relay()
    {
        let relayed = proxy(&state.http, state.relay.upstream(), &original)
            .await
            .unwrap_or_else(|e| {
                rpc_error(
                    id,
                    ErrorCode::UpstreamError,
                    format!("dig-node upstream error: {e}"),
                )
            });
        return (StatusCode::OK, Json(relayed));
    }

    (StatusCode::OK, Json(resp))
}

/// Relay a raw JSON-RPC request to the upstream DIG RPC and return its parsed
/// JSON envelope. Used for the passthrough fallback only.
async fn proxy(http: &reqwest::Client, upstream: &str, req: &Value) -> Result<Value, String> {
    let resp = http
        .post(upstream)
        .json(req)
        .send()
        .await
        .map_err(|e| format!("upstream unreachable: {e}"))?;
    resp.json::<Value>()
        .await
        .map_err(|e| format!("upstream returned non-JSON: {e}"))
}

// -- Served wallet surface (#368) + bidirectional WS wallet+control transport (#369) -------------

/// Wrap a Sage `dispatch` `(http_status, body)` into a JSON-RPC envelope: a `200` body becomes the
/// `result` (parsed JSON); a non-`200` plain-text body becomes `error.message` with the Sage HTTP
/// status mapped to a catalogued JSON-RPC error code.
fn wallet_result_to_jsonrpc(id: Value, status: u16, body: String) -> Value {
    if status == 200 {
        let result: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        json!({ "jsonrpc": "2.0", "id": id, "result": result })
    } else {
        let code = match status {
            400 => ErrorCode::InvalidParams,
            401 => ErrorCode::Unauthorized,
            404 => ErrorCode::MethodNotFound,
            _ => ErrorCode::DispatchFailed,
        };
        rpc_error(id, code, body)
    }
}

/// The token a wallet/control caller presented on the loopback surface: the `X-Dig-Control-Token`
/// header, else a `_control_token` field in the (Sage/JSON) body.
fn presented_wallet_token(headers: &HeaderMap, body: &str) -> Option<String> {
    if let Some(t) = headers
        .get(control::CONTROL_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    serde_json::from_str::<Value>(body).ok().and_then(|v| {
        v.get("_control_token")
            .and_then(|t| t.as_str())
            .map(String::from)
    })
}

/// The chat RPC methods gated behind the control token (F1, #1946). `chat.send` makes the node seal +
/// BLS-sign a directed message as its OWN `0x0010` identity — it wields the node's cryptographic
/// identity like a `control.*` mutation — and `chat.poll` DRAINS (deletes) the inbound inbox, which an
/// unauthorized local process could otherwise use to steal/delete another app's queued ciphertext.
/// A loopback address alone does not prove the paired chat app (any local process can reach the RPC
/// plane), so both require the control token. PURE.
fn is_gated_chat_method(method: &str) -> bool {
    matches!(method, "chat.send" | "chat.poll")
}

/// Whether `token` authorizes a gated chat call (F1, #1946): the master control token (constant-time)
/// OR a valid paired controller token — the same master-or-paired policy that gates `control.*` and
/// the wallet surface. Fails CLOSED on an empty master (the in-memory CSPRNG-failure sentinel) so a
/// blank token can never match a blank master. PURE — the paired-store lookup is injected for testing.
fn chat_call_authorized(
    token: Option<&str>,
    master: &str,
    is_paired: impl Fn(&str) -> bool,
) -> bool {
    if master.is_empty() {
        return false;
    }
    match token {
        Some(tok) => control::ct_eq(tok, master) || is_paired(tok),
        None => false,
    }
}

/// Whether a wallet-surface caller presenting `token` is authorized for `method` (§7.12): reads are
/// open; every custody-lifecycle + mutation method needs the master control token OR a paired token.
fn wallet_call_authorized(state: &AppState, method: &str, token: Option<&str>) -> bool {
    let paired_path = pairing::paired_tokens_path(&state.state_dir);
    wallet_authz::authorize(method, token, &state.control_token, |t| {
        pairing::is_paired_token(&paired_path, t)
    })
}

/// `POST /{method}` (#368) — the Sage-parity wallet RPC surface. Dispatches to the node-custodied
/// [`WalletBackend`], reproducing Sage's response model: `200` + JSON on success, or the mapped
/// status with a plain-text message on error. Custody + mutation methods are paired-token gated
/// (§7.12) and are never relayed upstream; wallet reads are open to local consumers.
async fn wallet_rpc(
    State(state): State<AppState>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body_str = String::from_utf8_lossy(&body).into_owned();
    if wallet_authz::requires_authorization(&method) {
        let token = presented_wallet_token(&headers, &body_str);
        if !wallet_call_authorized(&state, &method, token.as_deref()) {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!(
                    "401: {method} requires the local control token (X-Dig-Control-Token header) \
                     or a paired controller token (see `dig-node pair`)"
                ),
            )
                .into_response();
        }
    }
    let (status, out) = state.wallet.dispatch(&method, &body_str).await;
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = if status == 200 {
        "application/json"
    } else {
        "text/plain; charset=utf-8"
    };
    (code, [(header::CONTENT_TYPE, content_type)], out).into_response()
}

/// `GET /ws` (#369) — upgrade to the bidirectional wallet+control WebSocket. Same CSWSH `Origin`
/// allowlist as `/ws/status`: a disallowed browser Origin is rejected server-side (a WS handshake
/// is not gated by CORS); a request with NO Origin (a non-browser client) is allowed.
async fn ws_wallet(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !is_local_origin(origin) {
            return (
                StatusCode::FORBIDDEN,
                Json(rpc_error(
                    Value::Null,
                    ErrorCode::InvalidRequest,
                    "dig-node: Origin not allowed for /ws",
                )),
            )
                .into_response();
        }
    }
    ws.on_upgrade(move |socket| ws_wallet_session(socket, state))
}

/// Build the `sync_status` PUSH frame from a [`SyncStatus`] (adds the `type` tag).
fn status_push_frame(status: &SyncStatus) -> Value {
    let mut v = serde_json::to_value(status).unwrap_or_else(|_| json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.insert("type".into(), json!("sync_status"));
    }
    v
}

/// A WS error response frame (correlated by `id`).
fn ws_err(id: Value, code: ErrorCode, msg: &str) -> Value {
    json!({ "id": id, "type": "response", "ok": false, "error": { "code": code.code(), "message": msg } })
}

/// Normalize a `control.*`/`pairing.*` JSON-RPC envelope into the uniform WS response frame.
fn ws_from_jsonrpc(id: Value, env: Value) -> Value {
    if let Some(err) = env.get("error") {
        json!({ "id": id, "type": "response", "ok": false, "error": err.clone() })
    } else {
        json!({ "id": id, "type": "response", "ok": true, "result": env.get("result").cloned().unwrap_or(Value::Null) })
    }
}

/// Dispatch ONE correlated WS request → the uniform response frame. Routes `control.*` (token-gated,
/// pairing-admin needs the master token), the OPEN `pairing.request`/`pairing.poll`, and the wallet
/// surface (reads open; custody + mutations paired-token gated, §7.12). Wallet/custody ops are
/// served by the node-custodied backend and never relayed upstream.
async fn ws_dispatch(
    state: &AppState,
    id: Value,
    method: &str,
    params: Value,
    token: Option<&str>,
) -> Value {
    if control::is_control_method(method) {
        let master_ok = control::is_authorized(method, token, &state.control_token);
        let paired_ok = !control::requires_master_token(method)
            && token.is_some_and(|t| {
                pairing::is_paired_token(&pairing::paired_tokens_path(&state.state_dir), t)
            });
        if !(master_ok || paired_ok) {
            return ws_err(
                id,
                ErrorCode::Unauthorized,
                "control.* requires the local control token or a paired controller token",
            );
        }
        let ctx = control_ctx(state);
        let env = control::dispatch_control(&ctx, id.clone(), method, &params).await;
        return ws_from_jsonrpc(id, env);
    }
    if method == "pairing.request" || method == "pairing.poll" {
        let env = if method == "pairing.request" {
            pairing::request(&state.pairings, id.clone(), &params)
        } else {
            pairing::poll(&state.pairings, id.clone(), &params)
        };
        return ws_from_jsonrpc(id, env);
    }
    // CHAT gate (F1, #1946): bind the same control-token requirement as the HTTP path on this
    // transport, so a chat method wired to `/ws` can never bypass the gate (the #2032 lesson — the WS
    // path needs its own check, not just HTTP). Master control token OR a valid paired token.
    if is_gated_chat_method(method) {
        let paired_path = pairing::paired_tokens_path(&state.state_dir);
        let authorized = chat_call_authorized(token, &state.control_token, |tok| {
            pairing::is_paired_token(&paired_path, tok)
        });
        if !authorized {
            return ws_err(
                id,
                ErrorCode::Unauthorized,
                "chat.send/chat.poll require the local control token or a paired controller token",
            );
        }
    }
    if wallet_authz::requires_authorization(method) && !wallet_call_authorized(state, method, token)
    {
        return ws_err(
            id,
            ErrorCode::Unauthorized,
            "this wallet method requires a paired controller token (see `dig-node pair`)",
        );
    }
    let body = serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string());
    let (status, out) = state.wallet.dispatch(method, &body).await;
    if status == 200 {
        let result: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
        json!({ "id": id, "type": "response", "ok": true, "result": result })
    } else {
        json!({ "id": id, "type": "response", "ok": false, "error": { "code": status, "message": out } })
    }
}

/// The authorization token carried on a WS `request` frame, or `None`. A BLANK token is
/// treated as absent — matching the HTTP path ([`control::presented_token`]) — so a
/// `{"token":""}` frame never reaches the gate as `Some("")`. Defense in depth beneath the
/// empty-`expected` guard in [`control::is_authorized`]/[`wallet_authz::authorize`]: a blank
/// token must never be a credential, especially in the fail-closed empty-token state. PURE.
fn ws_token(frame: &Value) -> Option<&str> {
    frame
        .get("token")
        .and_then(|t| t.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Parse one client text frame and, if it is a `request`, dispatch it to a response frame. Non-request
/// frames (client-side keepalives, unknown types) are ignored (`None`).
async fn ws_handle_text(state: &AppState, txt: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(txt).ok()?;
    let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("request");
    if ty != "request" {
        return None;
    }
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if method.is_empty() {
        return Some(ws_err(id, ErrorCode::InvalidRequest, "missing method"));
    }
    let params = v.get("params").cloned().unwrap_or_else(|| json!({}));
    let token = ws_token(&v);
    Some(ws_dispatch(state, id, method, params, token).await)
}

/// Drive one `/ws` connection (#369). On connect the client is subscribed to the node's push
/// stream: the current `sync_status` snapshot is pushed immediately, then every sync event is
/// forwarded (`{type:"event",...}`) and any resulting sync-status transition is pushed
/// (`{type:"sync_status",...}`) — a `SyncEvent::Stop` pushes `disconnected`. Client `request`
/// frames are dispatched to correlated `response` frames. A transport heartbeat + pong-timeout
/// closes a half-open socket.
async fn ws_wallet_session(mut socket: WebSocket, state: AppState) {
    use tokio::sync::broadcast::error::RecvError;

    let mut rx = state.wallet.events().subscribe();
    let mut bus_open = true;
    // The tip-event stream (#378): a DISTINCT bus from the Sage `SyncEvent` bus, forwarded as
    // `{type:"tip", tip:<entry>}` frames (SPEC §4.8) so tip pushes never pollute the Sage stream.
    let mut tip_rx = state.wallet.tip_events().subscribe();
    let mut tip_open = true;

    // Initial sync-status snapshot so the client can render syncing/synced immediately.
    let mut last: Option<SyncStatus> = state.wallet.sync_status().await.ok();
    if let Some(s) = &last {
        if socket
            .send(Message::Text(status_push_frame(s).to_string()))
            .await
            .is_err()
        {
            return;
        }
    }

    let mut ticker = tokio::time::interval(WS_HEARTBEAT_INTERVAL);
    ticker.tick().await;
    let mut last_seen = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if last_seen.elapsed() > WS_PONG_TIMEOUT {
                    let _ = socket.send(Message::Close(None)).await;
                    return;
                }
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    return;
                }
            }
            ev = rx.recv(), if bus_open => {
                match ev {
                    Ok(event) => {
                        // Forward the raw sync event (subsumes the SSE stream).
                        let frame = json!({ "type": "event", "event": event });
                        if socket.send(Message::Text(frame.to_string())).await.is_err() {
                            return;
                        }
                        // Recompute the tri-state and push on transition; Stop ⇒ disconnected.
                        let cur = if matches!(event, SyncEvent::Stop) {
                            SyncStatus {
                                state: SyncLifecycle::Disconnected,
                                peak_height: last.as_ref().and_then(|s| s.peak_height),
                                target_height: last.as_ref().and_then(|s| s.target_height),
                            }
                        } else {
                            state.wallet.sync_status().await.unwrap_or(SyncStatus {
                                state: SyncLifecycle::Syncing,
                                peak_height: None,
                                target_height: None,
                            })
                        };
                        if last.as_ref() != Some(&cur) {
                            if socket
                                .send(Message::Text(status_push_frame(&cur).to_string()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            last = Some(cur);
                        }
                    }
                    // A lagging subscriber skips the gap; a closed bus stops the push arm but the
                    // request/response side keeps serving.
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => { bus_open = false; }
                }
            }
            tev = tip_rx.recv(), if tip_open => {
                match tev {
                    Ok(tip) => {
                        let frame = json!({ "type": "tip", "tip": tip.entry });
                        if socket.send(Message::Text(frame.to_string())).await.is_err() {
                            return;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => { tip_open = false; }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(txt))) => {
                        last_seen = tokio::time::Instant::now();
                        if let Some(frame) = ws_handle_text(&state, &txt).await {
                            if socket.send(Message::Text(frame.to_string())).await.is_err() {
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        let _ = socket.send(Message::Close(None)).await;
                        return;
                    }
                    Some(Ok(_)) => { last_seen = tokio::time::Instant::now(); }
                    Some(Err(_)) | None => return,
                }
            }
        }
    }
}

// -- Local plaintext content-serve (#289/#290) ---------------------------------------------------
//
// `GET /s/<storeId>[:<root>]/<path>` decrypts server-side and returns the real website over
// LOOPBACK — DISTINCT from the blind-ciphertext JSON-RPC `POST /`. The resolve→verify→decrypt core
// (local-first → peer → public-RPC, chain-anchored-root pinned, #127/#290) is
// `dig_node_core::Node::serve_content_plaintext`; the pure HTTP helpers (route parse, base/Referer
// rerooting, content-type, CSP, SPA classifier) are in [`crate::content`]. Plaintext only ever
// crosses loopback (the Host allowlist + CORS answer only loopback names), never the public gateway.

/// `GET /s/<storeId>[:<root>]/<path>` — serve a store resource as decrypted plaintext.
async fn store_serve(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    match parse_store_path(&path) {
        Some(sp) => {
            serve_resource(
                &state,
                sp,
                read_origin_for(&peer_addr),
                provenance_for(&headers),
            )
            .await
        }
        None => not_found(),
    }
}

/// `GET /verify/<storeId>[:<root>]` (#307) — the read-only verification-ledger snapshot for a
/// `(store, root)` page session: the per-resource verify verdicts + Merkle inclusion-proof data the
/// `/s/` serve path recorded, plus the page-level `aggregate` the extension's "Verified by Chia"
/// badge consumes. `root` omitted → the store's most-recently-served session. Always `200` with a
/// valid (possibly empty) JSON body; a malformed path is `404`. Loopback-only (shared host-guard +
/// CORS with `/s/`), no secrets.
async fn verify_ledger(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    match parse_verify_path(&path) {
        Some((store_id, root)) => {
            let snapshot = state
                .node
                .verification_ledger_snapshot(&store_id, root.as_deref());
            (StatusCode::OK, Json(snapshot)).into_response()
        }
        None => not_found(),
    }
}

/// Router fallback: a ROOT-ABSOLUTE subresource request (`GET /foo.js`) whose store the browser
/// dropped from the path. Reroot it into its store via the same-origin `Referer` a store page
/// carries (`<meta name="referrer" content="same-origin">` guarantees it is sent); an unattributable
/// request is a plain `404` (an asset) or is SPA-handled inside [`serve_resource`] (a route). Any
/// non-store / non-GET request lands here too and 404s.
async fn fallback_serve(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    match reroot_via_referer(referer, uri.path()) {
        Some(sp) => {
            serve_resource(
                &state,
                sp,
                read_origin_for(&peer_addr),
                provenance_for(&headers),
            )
            .await
        }
        None => not_found(),
    }
}

/// Resolve → verify → decrypt one store resource and shape the HTTP response, applying the
/// SPA-fallback-vs-404 decision on a miss.
///
/// `origin` is the calling connection's [`read_origin_for`] label, carried down to the read so the
/// network-effecting legs a miss can trigger (whole-capsule warm/reshare, DHT holder-announce) stay
/// gated on the read being THIS node's operator rather than a stranger's request.
async fn serve_resource(
    state: &AppState,
    sp: StorePath,
    origin: dig_node_core::download::ReadOrigin,
    provenance: dig_node_core::download::RequestProvenance,
) -> Response {
    let root = sp.root.as_deref().unwrap_or("");
    // Public stores only for now (salt = None): a private store's secret salt is not yet provisioned
    // to the local serve surface, so such a store fails closed at decrypt (a documented follow-up).
    match state
        .content_server
        .serve_content_plaintext(&sp.store_id, root, &sp.resource, None, origin, provenance)
        .await
    {
        PlaintextOutcome::Served {
            bytes,
            root_hex,
            verified,
            source,
            peer_tier,
            owner_puzzle_hash,
            generation,
        } => served_response(
            &sp,
            &sp.resource,
            bytes,
            &root_hex,
            ServeProvenance {
                verified,
                source,
                peer_tier,
                owner_puzzle_hash: owner_puzzle_hash.as_deref(),
                generation,
            },
        ),
        PlaintextOutcome::NotFound { root_hex } => {
            serve_miss(state, &sp, &root_hex, origin, provenance).await
        }
        PlaintextOutcome::InvalidParams { message } => {
            error_response(StatusCode::BAD_REQUEST, &message)
        }
        // The chain-anchored-root pin failed closed, or the fetched bytes could not be verified/
        // decrypted — a gateway-class error, never a silently-served failure (#127 fail-closed).
        PlaintextOutcome::RootError { message, .. }
        | PlaintextOutcome::Unreadable { message, .. } => {
            error_response(StatusCode::BAD_GATEWAY, &message)
        }
    }
}

/// The SPA-fallback-vs-404 decision on a content miss (#144 MIME rule):
/// - a known static ASSET that misses → honest `404` (never `text/html`);
/// - a KNOWN file (in the store's public manifest) missing at this root → honest `404`;
/// - otherwise a ROUTE (or a store with no manifest) → serve the store's `index.html` (`200`,
///   `text/html`) so an SPA client-side deep link boots.
async fn serve_miss(
    state: &AppState,
    sp: &StorePath,
    root_hex: &str,
    origin: dig_node_core::download::ReadOrigin,
    provenance: dig_node_core::download::RequestProvenance,
) -> Response {
    if is_static_asset_path(&sp.resource) {
        return not_found();
    }
    if let Some(paths) = state
        .content_server
        .manifest_paths(&sp.store_id, root_hex)
        .await
    {
        if paths.iter().any(|p| p == &sp.resource) {
            return not_found();
        }
    }
    // SPA fallback: the store's default view, served against the SAME resolved root.
    match state
        .content_server
        .serve_content_plaintext(
            &sp.store_id,
            root_hex,
            "index.html",
            None,
            origin,
            provenance,
        )
        .await
    {
        PlaintextOutcome::Served {
            bytes,
            root_hex,
            verified,
            source,
            peer_tier,
            owner_puzzle_hash,
            generation,
        } => served_response(
            sp,
            "index.html",
            bytes,
            &root_hex,
            ServeProvenance {
                verified,
                source,
                peer_tier,
                owner_puzzle_hash: owner_puzzle_hash.as_deref(),
                generation,
            },
        ),
        _ => not_found(),
    }
}

/// Everything a served response reports ABOUT its bytes rather than the bytes themselves — grouped
/// so [`served_response`] takes one self-describing argument instead of a positional run of five
/// that a caller can silently transpose.
struct ServeProvenance<'a> {
    /// Whether the bytes were verified against the CHAIN-ANCHORED root (`X-Dig-Verified`).
    verified: bool,
    /// Which tier the bytes came from (`X-Dig-Source`).
    source: ServeSource,
    /// Whether the peer tier was attached when the read was routed (`X-Dig-Peer-Tier`, #1763) —
    /// which is what distinguishes "the gateway answered because no peer held this" from "the
    /// gateway answered because there was no peer tier yet".
    peer_tier: PeerTier,
    /// The store's on-chain owner puzzle hash, when resolvable (`X-Dig-Owner-Puzzle-Hash`).
    owner_puzzle_hash: Option<&'a str>,
    /// The commit ordinal that last wrote the resource, when known (`X-Dig-Generation`).
    generation: Option<u64>,
}

/// Build the `200` response for a served resource: the ecosystem content-type + `nosniff`, the
/// `X-Dig-Verified`/`X-Dig-Root`/`X-Dig-Source`/`X-Dig-Peer-Tier` provenance headers (#292, #1763),
/// the serve-metadata HEAD
/// (#486: `X-Dig-Store-Id`/`X-Dig-Capsule`/`X-Dig-Resource-Key` always, `X-Dig-Owner-Puzzle-Hash`/
/// `X-Dig-Generation` when resolvable), and — for HTML — the injected store-root
/// `<base>`/`<meta referrer>` plus the hardened store CSP.
///
/// The serve-metadata headers describe THIS response's MAIN resource; a HEAD request lands on the
/// SAME handler (axum dispatches `HEAD` to the registered `GET` route and strips the body), so the
/// full header set is present with an empty body — no separate HEAD code path is needed.
///
/// `owner_puzzle_hash`/`generation` are OMITTED (not an empty placeholder) when unknowable — see
/// [`PlaintextOutcome::Served`]'s field docs.
fn served_response(
    sp: &StorePath,
    resource: &str,
    bytes: Vec<u8>,
    root_hex: &str,
    provenance: ServeProvenance<'_>,
) -> Response {
    let ServeProvenance {
        verified,
        source,
        peer_tier,
        owner_puzzle_hash,
        generation,
    } = provenance;
    let content_type = content_type_for(resource);
    // The MAIN resource actually served: an empty key (a bare store-root request) resolved to the
    // default view `index.html` internally, so the header reports that, never a blank string.
    let resource_key = if resource.is_empty() {
        "index.html"
    } else {
        resource
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Dig-Verified", if verified { "true" } else { "false" })
        .header("X-Dig-Root", root_hex)
        .header("X-Dig-Source", source.as_str())
        .header("X-Dig-Peer-Tier", peer_tier.as_str())
        .header("X-Dig-Store-Id", sp.store_id.as_str())
        .header("X-Dig-Capsule", format!("{}:{}", sp.store_id, root_hex))
        .header("X-Dig-Resource-Key", resource_key);
    if let Some(owner) = owner_puzzle_hash {
        builder = builder.header("X-Dig-Owner-Puzzle-Hash", owner);
    }
    if let Some(gen) = generation {
        builder = builder.header("X-Dig-Generation", gen.to_string());
    }

    let body = if is_html(content_type) {
        builder = builder.header(header::CONTENT_SECURITY_POLICY, STORE_CSP);
        let html = String::from_utf8_lossy(&bytes);
        inject_html_head(&html, &store_base_href(sp)).into_bytes()
    } else {
        bytes
    };
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A plain-text error response (never `text/html`, so a browser never renders a store error as a
/// page) carrying `nosniff`.
fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("x-content-type-options", "nosniff"),
        ],
        format!("{}: {message}", status.as_u16()),
    )
        .into_response()
}

/// A plain-text `404` for an asset miss / unattributable request.
fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

/// Run the dig-node HTTP server until the process is asked to stop. Binds the
/// configured loopback address and serves until Ctrl-C / SIGTERM (so the OS
/// service manager's stop is graceful). This is the body of `dig-node run`
/// and the unix-service entrypoint (systemd/launchd send SIGTERM to stop).
pub async fn serve(config: Config) -> std::io::Result<()> {
    serve_with_shutdown(config, shutdown_signal()).await
}

/// Like [`serve`], but the caller supplies the shutdown future. The Windows
/// service entrypoint uses this to drive graceful shutdown from the SCM `Stop`
/// control event (which is not a unix signal), instead of the OS-signal future.
///
/// ## Loopback listeners (#91, #288)
///
/// The node opens UP TO THREE loopback listeners for the SAME app:
///
/// 1. **`127.0.0.1:<port>`** (default 9778, #132) — `http://localhost:<port>` on
///    IPv4. **Always on** (unprivileged, conflict-free). A failure to bind this is
///    FATAL — the node has no endpoint, so `serve` returns the error (mapped to
///    `BIND_FAILED`).
/// 2. **`[::1]:<port>`** — the SAME `localhost:<port>` on IPv6 (§5.2 dual-stack
///    loopback). **Best-effort**: some systems resolve `localhost` to `::1` FIRST
///    (Windows by default), so without this listener such a client cannot reach
///    the node and reports it offline even though `127.0.0.1` answers fine. A bind
///    failure here (IPv6 loopback unavailable/disabled) logs a structured warning
///    and the node continues IPv4-only — it NEVER aborts for this. Skipped
///    entirely when an explicit `DIG_NODE_HOST` override is set
///    ([`Config::bind_addr_v6`]) — the override REPLACES the default dual bind
///    with exactly that one address.
/// 3. **`127.0.0.2:80`** — bare `http://dig.local` (no port), matching the
///    dig-installer hosts entry. **Best-effort**: binding the privileged port 80
///    (and, on macOS, the `127.0.0.2` loopback alias) may fail; if so the node logs
///    a structured warning and serves localhost-only — it NEVER aborts for this.
///    Skipped entirely when `DIG_NODE_DIGLOCAL=0` ([`Config::dig_local`]).
///
/// No listener ever binds `0.0.0.0` or the IPv6 wildcard `[::]` — every one is a
/// loopback address, so the node is never LAN-exposed. The shared shutdown future
/// drives every bound listener to a graceful stop.
pub async fn serve_with_shutdown<F>(config: Config, shutdown: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Fail CLOSED on an unauthorized non-loopback bind (#1662): a `DIG_NODE_HOST`
    // pointing off loopback without the explicit `DIG_NODE_ALLOW_REMOTE=1` escape hatch
    // would expose the local RPC/content API to the network, silently falsifying the
    // ~25 "loopback-only / never peer-reachable" invariants this service relies on. A
    // deliberate remote bind (e.g. a remote-API test rig) sets the flag; everything else
    // is a hard startup error — never a silent LAN exposure.
    if let Some(msg) = crate::config::host_override_refusal(config.host, config.allow_remote) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg));
    }

    let addr = config.bind_addr();
    let state = build_state(&config).await;

    // Grab the wallet backend + mTLS cert before the router consumes `state` (#368): the served
    // wallet rides the loopback HTTP surface (`POST /{method}`) AND a sibling wallet mTLS listener
    // for node-class/Sage-drop-in parity (§5.3 transport).
    let wallet_backend = state.wallet.clone();
    let wallet_cert = state.wallet_cert.clone();

    // Bring the per-epoch collateral record store up (dig-node#387). Two steps, both cheap and
    // both synchronous, because a node that answered `dig.getCollateralEpoch` before its own
    // genesis record existed would report "not recorded" for an epoch it can derive from nothing.
    //
    // This is the store's PRODUCTION WRITER. Until it existed the store was written only by its
    // own tests, so `control.collateral.requirement` answered `unknown / not_censused` on every
    // node in the network — a correct answer, and a permanently unchanging one.
    bring_up_collateral_records();

    // The CENSUS half (#400). `bring_up_collateral_records` writes epoch 1, which is derivable
    // from nothing; this is what lets the node record epoch n. It runs detached and on a timer
    // because a census depends on the chain having moved: an epoch that has begun by the clock is
    // not yet censusable until a block carries its start instant and the census height is buried.
    //
    // Gated on `enable_chain_sync` for the same reason the wallet's sync is: that flag already
    // means "this node talks to the Chia network", and an integration harness sets it false
    // precisely so nothing dials.
    if config.enable_chain_sync {
        spawn_collateral_census(state.wallet_chain.clone());
        spawn_mirror_passes(
            state.node.clone(),
            state.wallet.clone(),
            state.wallet_chain.clone(),
            state.mirror_bonds.clone(),
            config.enable_live_broadcast,
        );
    }

    // §14 autonomous sync (#213): bring up the L7 peer network — the connected peer
    // pool, the content-location DHT + P2P content engine, PEX, and the chain-watch +
    // generation gap-fill loop — so a running node tracks the chain and PROACTIVELY
    // pulls the generations of its subscribed stores, not merely reacts to reads. The
    // MACHINERY lives in dig-node-core (`peer::spawn_peer_network` → `run_peer_network`,
    // which installs the P2P content engine + the inventory refresher and spawns the
    // chain-watch loop); this shell only makes the call that was missing. Best-effort +
    // detached: a bring-up failure is recorded on `control.peerStatus` and never blocks
    // the HTTP read path. Gated by the existing `DIG_PEER_NETWORK` switch (default ON;
    // `off`/`0`/`false` opts out for a standalone read-only node). The in-process FFI
    // path (`dig-runtime`) never routes through `serve_with_shutdown`, so the browser's
    // node keeps installing no P2P content — its in-process trust boundary is unchanged.
    if dig_node_core::peer::peer_network_enabled() {
        // The untrusted mirror-coin pointers every DHT announce attaches (dig-node#435), installed
        // BEFORE the bring-up reads them. The DHT lives in dig-node-core and the mirror lifecycle
        // that knows which coin bonds which capsule lives here, so this shell is the one place that
        // can join them. Until it did, the pointer mechanism was built, unit tested, and fed only by
        // a test double: every live announce published no coin id at all.
        //
        // Installed unconditionally rather than behind the broadcast switch. The pointer is read
        // from the observation a pass publishes, so a node that creates no coins simply has no
        // `Bonded` row and answers `None` — the ordinary, fully supported case — while a node whose
        // coins were created before the switch was turned off still points at them correctly.
        state.node.set_mirror_coin_pointers(std::sync::Arc::new(
            crate::mirror::pointers::SnapshotMirrorPointers::new(state.mirror_bonds.clone()),
        ));
        dig_node_core::peer::spawn_peer_network(state.node.clone());
        // #466: nothing anywhere read a peer's claimed mirror coin against a chain, so the
        // collateral economy's one guarantee was unenforced end to end. Installed HERE because this
        // is where both halves exist at once -- the content engine the peer network is bringing up,
        // and this node's chain transport. Gated on `enable_chain_sync` for the reason the census
        // is: that flag already means "this node talks to the Chia network", and a harness sets it
        // false precisely so nothing dials.
        if config.enable_chain_sync {
            crate::mirror::bond_verify::spawn_bond_verifier_install(
                state.node.clone(),
                state.wallet_chain.clone(),
            );
        }
    }

    // Prove the configured upstream is not this node (#1997). Fire-and-forget: the evidence is the
    // probe ARRIVING BACK at this node's own dispatcher, which the request path notices — nothing
    // here waits on or inspects a reply. A no-op when no upstream is configured, which is the
    // default. See [`crate::relay`] for why the marker rides in the JSON-RPC `id`.
    {
        let http = state.http.clone();
        let relay = state.relay.clone();
        tokio::spawn(async move {
            crate::relay::probe_upstream_for_loop(&http, &relay).await;
        });
    }

    // Always-on self-heal driver (#584 beacon re-arm + #651 ext-forcelist reconcile): on a
    // privileged SERVICE run, periodically re-arm a drifted auto-update schedule (`dig-updater
    // schedule ensure`, opt-out-respecting) and re-apply the extension force-install policy
    // (`dig-installer --set-ext-forcelist-channel`). Gated to a service run — its repairs need
    // elevation, and a dev/CLI run must not attempt privileged sibling spawns. Detached +
    // best-effort: it never blocks or fails the serve path. The service-gate lives inside the seam
    // (a tested unit, #1864) so it cannot be silently flipped to always- or never-spawn.
    crate::self_heal::spawn_driver_if_service();

    // Best-effort wallet mTLS listener (#368, Sage byte-parity, node-class clients, §5.3). Binds
    // loopback only on [`DEFAULT_MTLS_PORT`], which is deliberately NOT Sage's own RPC port
    // (dig-node#260). A bind failure is NON-FATAL — the wallet stays reachable over the plain-HTTP
    // `POST /{method}` surface + the `/ws` transport, which is what the extension uses — but it is
    // no longer SILENT: `crate::wallet_mtls` logs it and publishes it on `control.status`. The
    // listener stops when the process exits with the rest of the node.
    //
    // The listener is GATED by the same `wallet_authz` policy the HTTP and `/ws` planes use
    // (dig-node#257): the shared client certificate authenticates the transport, it does not
    // authorize a capability.
    crate::wallet_mtls::spawn(
        DEFAULT_MTLS_PORT,
        wallet_backend.clone(),
        wallet_cert.clone(),
        std::sync::Arc::new(crate::wallet_mtls::NodeWalletGate::new(
            state.control_token.clone(),
            &state.state_dir,
        )),
    );

    let app = router(state);

    // (1) The ALWAYS-ON localhost listener (IPv4). A failure here is fatal: no endpoint.
    let localhost = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("dig-node: cannot bind {addr}: {e}")))?;

    // (2) The BEST-EFFORT IPv6 loopback listener (`[::1]:<port>`, #288, §5.2): the
    // SAME localhost:<port> on the other loopback family, so a client whose
    // resolver returns `::1` before `127.0.0.1` for `localhost` (Windows' default)
    // still reaches the node. `bind_addr_v6` is `None` when an explicit
    // `DIG_NODE_HOST` override replaced the default dual bind — nothing to try in
    // that case. A bind failure (IPv6 loopback unavailable/disabled) is
    // non-fatal: warn and continue IPv4-only, mirroring the `dig_local` pattern.
    let ipv6 = match config.bind_addr_v6() {
        Some(v6_addr) => match tokio::net::TcpListener::bind(&v6_addr).await {
            Ok(l) => Some((v6_addr, l)),
            Err(e) => {
                warn_ipv6_bind_failed(v6_addr, &e);
                None
            }
        },
        None => None,
    };

    // (3) The BEST-EFFORT bare-dig.local listener (127.0.0.2:80). Try to bind; on
    // failure, log a structured warning and continue with localhost-only.
    let dig_local = match config.dig_local_addr() {
        Some(dl_addr) => match tokio::net::TcpListener::bind(&dl_addr).await {
            Ok(l) => {
                tracing::info!(addr = %dl_addr, "bare http://dig.local enabled");
                Some((dl_addr, l))
            }
            Err(e) => {
                warn_dig_local_bind_failed(dl_addr, &e);
                None
            }
        },
        None => {
            // A deliberately-disabled surface (DIG_NODE_DIGLOCAL=0) — a developer-diagnosis detail,
            // not operator narrative, so DEBUG.
            tracing::debug!("bare http://dig.local listener disabled (DIG_NODE_DIGLOCAL=0)");
            None
        }
    };

    // Operational log line → stderr, so `run --json` leaves stdout for the single
    // structured object (prose-to-stderr convention). Lists every address actually
    // bound (#288: an agent/operator can see at a glance which loopback families
    // are live, not just assume the IPv4 default).
    let mut bound_addrs = vec![format!("http://{addr}")];
    if let Some((v6_addr, _)) = &ipv6 {
        bound_addrs.push(format!("http://{v6_addr}"));
    }
    if dig_local.is_some() {
        bound_addrs.push("http://dig.local (no port)".to_string());
    }
    tracing::info!(
        version = VERSION,
        addrs = %bound_addrs.join(", "),
        upstream = %config.upstream,
        extension_host = %addr,
        "dig-node (local-node) listening"
    );

    // A single shutdown signal fanned out to every listener: when it fires, all
    // axum::serve loops stop gracefully. (The caller's future resolves once; we
    // notify every server from it.)
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    {
        let n = shutdown_notify.clone();
        tokio::spawn(async move {
            shutdown.await;
            n.notify_waiters();
        });
    }

    // (4) Local HTTPS for `https://dig.local` (#624, the #620 epic): the SAME app served over
    // TLS on `127.0.0.2:443` (plus the best-effort IPv6 loopback `[::1]:443`, §5.2), backed by a
    // dig-cert leaf with live rotation. GATED on a leaf being present — fail-soft to plaintext
    // when the installer (#623) has not provisioned the CA yet. Best-effort like the mTLS +
    // bare-dig.local listeners: a bind failure logs and is non-fatal; the plaintext surface above
    // keeps serving. Runs as spawned tasks driven to graceful stop by the shared shutdown signal.
    bring_up_local_https(&config, &app, &shutdown_notify);

    // `into_make_service_with_connect_info::<SocketAddr>()` — NOT the plain `app` — is what makes
    // `ConnectInfo<SocketAddr>` extractable in `rpc()` at all: a bare `axum::serve(listener, router)`
    // never populates it (`Router<()>`'s `Service<IncomingStream>` impl ignores the incoming stream's
    // address entirely), so without this every request would fail that extraction. This is the
    // ONLY thing that makes the `ReadOrigin` label in `rpc()` a REAL fact about the accepting
    // connection rather than an assumption baked in at the call site (#1619 follow-up).
    let localhost_srv = {
        let app = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        let n = shutdown_notify.clone();
        axum::serve(localhost, app).with_graceful_shutdown(async move { n.notified().await })
    };

    let ipv6_srv = ipv6.map(|(_, l)| {
        let app = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        let n = shutdown_notify.clone();
        axum::serve(l, app).with_graceful_shutdown(async move { n.notified().await })
    });

    let dig_local_srv = dig_local.map(|(_, l)| {
        let app = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        let n = shutdown_notify.clone();
        axum::serve(l, app).with_graceful_shutdown(async move { n.notified().await })
    });

    // Drive every bound listener concurrently; return the first error (there
    // normally is none — they run until the shared shutdown). Best-effort
    // listeners that failed to bind are simply absent from the join.
    match (ipv6_srv, dig_local_srv) {
        (Some(v6), Some(dl)) => tokio::try_join!(localhost_srv, v6, dl).map(|_| ()),
        (Some(v6), None) => tokio::try_join!(localhost_srv, v6).map(|_| ()),
        (None, Some(dl)) => tokio::try_join!(localhost_srv, dl).map(|_| ()),
        (None, None) => localhost_srv.await,
    }
}

/// Log the structured warning when the best-effort `[::1]:<port>` (IPv6 loopback)
/// bind fails (#288). Split out so the message is one place and the policy — warn
/// and continue IPv4-only, never abort — is obvious at the call site. An IPv6
/// loopback bind failure is uncommon (most OSes always provide `::1`) but not
/// impossible: IPv6 disabled at the kernel/network-stack level, or a sandboxed/
/// restricted environment without it.
fn warn_ipv6_bind_failed(v6_addr: SocketAddr, e: &std::io::Error) {
    tracing::warn!(
        addr = %v6_addr,
        error = %e,
        "could not bind the IPv6 loopback listener; continuing IPv4-only on the sibling 127.0.0.1 \
         address (non-fatal). A client whose `localhost` resolves to `::1` first (e.g. Windows) may \
         need to use 127.0.0.1 explicitly until IPv6 loopback is available on this system"
    );
}

/// Log the structured warning when the best-effort `127.0.0.2:80` (dig.local) bind
/// fails (#91). Split out so the message is one place and the policy ("warn +
/// continue, never abort") is obvious at the call site. The hint is platform-aware:
/// `:80` is privileged on Linux (root / CAP_NET_BIND_SERVICE) and on macOS also
/// needs the `127.0.0.2` loopback alias.
fn warn_dig_local_bind_failed(dl_addr: SocketAddr, e: &std::io::Error) {
    tracing::warn!(
        addr = %dl_addr,
        error = %e,
        "could not bind bare http://dig.local; continuing with localhost-only (http via the \
         configured port). Non-fatal. Causes: privileged port 80 needs elevation (Linux: run as \
         root or grant CAP_NET_BIND_SERVICE; the installed service runs elevated), the port is in \
         use, or — on macOS — the 127.0.0.2 loopback alias is missing (sudo ifconfig lo0 alias \
         127.0.0.2). Set DIG_NODE_DIGLOCAL=0 to silence this and skip the attempt"
    );
}

/// Bring up the local HTTPS listeners for `https://dig.local` (#624). Fail-soft: when
/// `dig_local` is disabled, the TLS root cannot be resolved, or no dig-cert leaf is present
/// yet, this does NOTHING (the node keeps serving plaintext) — HTTPS is never required to
/// start. When a leaf IS present it builds the reloadable rustls config once, spawns the
/// leaf-rotation loop (dig-cert renewal manager, hot-reloading the shared resolver), and
/// spawns a best-effort TLS listener on `127.0.0.2:443` and the IPv6 loopback `[::1]:443`,
/// each serving `app` and stopped gracefully by `shutdown_notify`.
fn bring_up_local_https(config: &Config, app: &Router, shutdown_notify: &Arc<tokio::sync::Notify>) {
    // Only attempt HTTPS on the bare-dig.local surface (shares the `dig_local` toggle).
    let Some(https_addr) = config.dig_local_https_addr() else {
        return;
    };

    let paths = match dig_cert::TlsPaths::machine() {
        Ok(paths) => paths,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cannot resolve the TLS material root; https://dig.local disabled, serving \
                 plaintext only"
            );
            return;
        }
    };

    // Fail-soft when the installer (#623) has not provisioned a CA + leaf yet.
    let Some(material) = crate::tls::load_https_material(paths) else {
        return;
    };

    // Drive leaf rotation off the SHARED resolver so a renewal hot-reloads every listener
    // built from this config; the CA anchor is never auto-rotated (see `crate::tls`).
    crate::tls::spawn_leaf_rotation(material.paths.clone(), material.resolver.clone());

    // ONE rustls config shared by both loopback-family listeners: its cert resolver is the
    // shared `ReloadableCertResolver`, so a rotation reload is served on both at once.
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(material.config));

    // (4a) The IPv4 dig.local alias `127.0.0.2:443` — the name `https://dig.local` resolves to.
    spawn_https_listener(
        https_addr,
        rustls_config.clone(),
        app.clone(),
        shutdown_notify,
    );

    // (4b) The best-effort IPv6 loopback sibling `[::1]:443` (§5.2), covered by the leaf SAN.
    if let Some(v6_addr) = config.dig_local_https_addr_v6() {
        spawn_https_listener(v6_addr, rustls_config, app.clone(), shutdown_notify);
    }
}

/// Bind `addr` and spawn a best-effort TLS listener serving `app`. A bind failure logs a
/// structured warning and is non-fatal (the plaintext surface keeps serving), mirroring the
/// bare-`http://dig.local` policy — `:443` is privileged (the installed service runs elevated).
fn spawn_https_listener(
    addr: SocketAddr,
    rustls_config: axum_server::tls_rustls::RustlsConfig,
    app: Router,
    shutdown_notify: &Arc<tokio::sync::Notify>,
) {
    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
            tracing::info!(addr = %addr, "HTTPS (https://dig.local) listening");
            let shutdown = shutdown_notify.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_https(listener, rustls_config, app, shutdown).await {
                    tracing::warn!(addr = %addr, error = %e, "HTTPS listener exited");
                }
            });
        }
        Err(e) => tracing::warn!(
            addr = %addr,
            error = %e,
            "could not bind https://dig.local; non-fatal — plaintext keeps serving. `:443` is \
             privileged (run elevated / grant CAP_NET_BIND_SERVICE; the installed service runs \
             elevated) and the 127.0.0.2 / ::1 loopback address must exist (macOS: sudo ifconfig \
             lo0 alias 127.0.0.2)"
        ),
    }
}

/// Serve `app` over TLS on a pre-bound listener until `shutdown` fires, then stop gracefully.
///
/// Uses the same `axum-server` TLS stack as the wallet mTLS listener, fed the reloadable
/// rustls config so a leaf rotation is picked up live (no restart, no dropped connections).
/// `pub` so the HTTPS integration test can drive it against an ephemeral loopback port.
pub async fn serve_https(
    listener: std::net::TcpListener,
    rustls_config: axum_server::tls_rustls::RustlsConfig,
    app: Router,
    shutdown: Arc<tokio::sync::Notify>,
) -> std::io::Result<()> {
    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            shutdown.notified().await;
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
    }
    axum_server::from_tcp_rustls(listener, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
}

/// Resolve when the process receives Ctrl-C (all platforms) or SIGTERM (unix),
/// which is how a service manager stops the service — letting `serve` shut down
/// gracefully instead of being killed mid-request.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("dig-node shutting down");
}

/// Answer `dig.getCollateralEpoch` from this node's own record store.
///
/// # Every non-answer is a NAMED refusal, never a shaped-like-success zero
///
/// The four ways this can fail to produce a record — an unreadable epoch parameter, an epoch never
/// recorded, a line that cannot be read, and a record governed by a ruleset this build does not
/// implement — are four different facts with four different remedies, and each is returned as
/// `record: null` beside its own `reason` token. This node's own read path pays for that
/// distinction already (`crate::collateral::StoredEpoch`), and discarding it at the wire boundary
/// would hand every caller the same unactionable sentence.
///
/// It matters more here than locally, because the caller is a peer deciding whether to re-census a
/// week of chain history. "I never recorded it" means ask someone else; "I cannot read my copy"
/// means this node is broken and should not be asked again; "your ruleset is newer than mine"
/// means the fault is not the caller's at all.
///
/// # Why the read is unauthenticated, and what bounds it
///
/// An epoch record is a recomputable consensus value carrying nothing secret, and a caller
/// verifies it by re-derivation whatever its source — so authenticating the server would buy
/// nothing. The cost is one read of the record file per request. That file holds one line per
/// epoch and an epoch is a week, so it is on the order of tens of lines even under the default
/// keep-everything retention; it is bounded by the calendar rather than by anything a caller
/// controls.
fn collateral_epoch_answer(params: &Value) -> Value {
    use crate::collateral::{EpochRecordStore, StoredEpoch};

    // Read typed and refuse what will not decode. A `params.epoch` that is absent, negative, or
    // not a number must NOT fall through to a default — epoch 0 is not an epoch, and epoch 1 is a
    // real record that a defaulting reader would serve in answer to a question nobody asked.
    let Some(epoch) = params
        .get("epoch")
        .and_then(Value::as_u64)
        .filter(|e| *e >= 1)
    else {
        return json!({
            "record": Value::Null,
            "reason": "invalid_epoch",
            "detail": "params.epoch is required and is a one-based epoch number",
        });
    };

    match EpochRecordStore::in_state_dir().get(epoch) {
        // The protocol-version ceiling, applied on the SERVE side too. A record this build cannot
        // interpret is one it cannot vouch for, and passing it on unremarked would launder an
        // unverifiable record through a node that never checked it.
        StoredEpoch::Found(record) if !record.is_interpretable() => json!({
            "record": Value::Null,
            "reason": "unimplemented_ruleset",
            "protocol_version": record.record.protocol_version.0,
        }),
        StoredEpoch::Found(record) => match serde_json::to_value(*record) {
            Ok(record) => json!({ "record": record }),
            Err(e) => json!({
                "record": Value::Null,
                "reason": "record_unreadable",
                "detail": e.to_string(),
            }),
        },
        StoredEpoch::Absent => json!({ "record": Value::Null, "reason": "not_recorded" }),
        StoredEpoch::Unreadable => json!({ "record": Value::Null, "reason": "record_unreadable" }),
    }
}

/// Seed the collateral record store and apply the operator's retention preference.
///
/// Best-effort and never fatal: a node that cannot write its record store still serves content,
/// and taking the whole node down over it would trade a missing figure for an outage. Every
/// failure is logged at WARN rather than swallowed, because the observable symptom otherwise is
/// `control.collateral.requirement` answering `unknown` forever with no stated cause.
fn bring_up_collateral_records() {
    use crate::collateral::{
        current_epoch_now, ensure_bootstrap, CollateralConfig, CurrentEpoch, EpochRecordStore,
        PutOutcome,
    };

    let store = EpochRecordStore::in_state_dir();
    match ensure_bootstrap(&store) {
        Ok(PutOutcome::Written) => {
            tracing::info!(path = %store.path().display(), "recorded the genesis collateral epoch")
        }
        Ok(PutOutcome::AlreadyPresent) => {}
        // A genesis record that disagrees with this build's own `EpochRecord::bootstrap` is not a
        // write to retry — it means the node's history was written under different rules, or was
        // tampered with. It is kept and reported; overwriting it is the one thing that must not
        // happen quietly.
        Ok(PutOutcome::Conflict { held }) => tracing::warn!(
            path = %store.path().display(),
            held_protocol_version = held.record.protocol_version.0,
            "the stored genesis collateral epoch differs from this build's; keeping the stored one"
        ),
        Err(e) => tracing::warn!(
            path = %store.path().display(),
            error = %e,
            "could not record the genesis collateral epoch"
        ),
    }

    // Retention. `KeepEverything` — the default — reads nothing and writes nothing, so a node that
    // never opted in never rewrites this file at all.
    let policy = CollateralConfig::load().retention();
    if let CurrentEpoch::Final(epoch) = current_epoch_now() {
        match store.prune(policy, epoch) {
            Ok(0) => {}
            Ok(dropped) => tracing::info!(
                dropped,
                policy = ?policy,
                "truncated the collateral record history at the operator's configured retention"
            ),
            Err(e) => tracing::warn!(error = %e, "could not apply the collateral retention policy"),
        }
    }
}

/// Report one recorded epoch, including what its census EXAMINED and why it excluded what it did.
///
/// # Why the exclusion counts are on the line and not only the figure
///
/// A `stores` of zero is produced identically by three situations with opposite remedies: an empty
/// network, a source answering at a puzzle hash other than the one it was asked for
/// (`excluded_foreign_puzzle`), and a source that could not supply its candidates' creating spends
/// (`excluded_unreadable`). Only the first is a fact about the network; the other two are a broken
/// instrument rendering a reassuring answer, on the path that decides how much collateral this node
/// posts. `examined` alone separates "nothing was there" from "everything was dropped", and the
/// per-rule counts say which rule dropped it.
///
/// A free function so the line an operator actually reads can be asserted against, rather than
/// living only inside the timer loop where nothing can reach it.
pub(crate) fn log_census_observation(observed: &crate::collateral_census::CensusObservation) {
    tracing::info!(
        epoch = observed.epoch,
        census_height = observed.census_height,
        stores = observed.stores,
        examined = observed.examined,
        excluded_foreign_puzzle = observed.excluded.foreign_puzzle,
        excluded_unreadable = observed.excluded.unreadable,
        excluded_unattributed = observed.excluded.unattributed,
        excluded_wrong_epoch = observed.excluded.wrong_epoch,
        excluded_not_yet_created = observed.excluded.not_yet_created,
        excluded_spent_by_census_height = observed.excluded.spent_by_census_height,
        excluded_undated = observed.excluded.undated,
        excluded_block_reward = observed.excluded.block_reward,
        excluded_below_requirement_unauthenticated =
            observed.excluded.below_requirement_unauthenticated,
        excluded_superseded = observed.excluded.superseded,
        "censused the collateral network and recorded the epoch"
    );
}

/// How often the census runner re-attempts a catch-up.
///
/// One mirror ROUND, taken from the schedule rather than written as a duration: the round is the
/// grain the mirror model already moves on, and a retune of it should carry this with it. It is
/// also comfortably shorter than the finality depth a `BehindFinalityDepth` stop waits out, so a
/// node that was a few blocks early records the epoch on its next pass rather than at the next
/// epoch.
///
/// Re-attempting once a node is current costs one census of the CURRENT epoch, and none of any
/// earlier one: `catch_up` re-censuses the target so a record written under a briefly degraded
/// chain view cannot stay sealed (dig-node#405).
const COLLATERAL_CENSUS_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(dig_constants::MIRROR_ROUND_LENGTH_MS as u64);

/// The interval between mirror reconcile passes — §25.4's round.
///
/// The SAME constant the collateral census uses, and deliberately so: a pass prices its creates from
/// the epoch record the census writes, so a mirror round that ran faster than the census would keep
/// re-deriving an answer from a record that had not moved.
const MIRROR_PASS_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(dig_constants::MIRROR_ROUND_LENGTH_MS as u64);

/// Run the §25 mirror-coin reconcile pass on the round timer, and publish what each pass observed.
///
/// Detached and best-effort, exactly like the collateral census beside it: a node that cannot
/// observe still serves content, and every outcome is logged rather than swallowed.
///
/// # The operator wallet is opened ONCE, here, and never again on a read path
///
/// [`crate::mirror::lifecycle::open_signer`] unseals the §16.4 seed under the device key a single
/// time at bring-up. The public puzzle hash it yields is held for the life of the task and used by
/// every pass, so no request — and no later edit to a request path — can cause a second unseal. A
/// `Locked` or `Orphaned` wallet yields no signer, and the lifecycle then OBSERVES without spending
/// rather than degrading into a node that reports nothing.
///
/// # Every pass re-reads everything; nothing is carried between rounds but the presence tracker
///
/// The epoch, the requirement and the margin are read per pass for the same reason the census reads
/// its target per pass: this task outlives an epoch boundary, and a value captured at start-up would
/// leave the node permanently one epoch behind from the moment the schedule rolled over. The
/// [`PassRunner`](crate::mirror::runner::PassRunner) is long-lived only because §25.5's presence
/// debounce is, by definition, memory between rounds — so it is built once, outside the loop.
fn spawn_mirror_passes(
    node: Arc<dig_node_core::Node>,
    wallet: Arc<dig_wallet::sage::rpc::WalletBackend>,
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    snapshot: crate::mirror::lifecycle::BondSnapshot,
    live_broadcast: bool,
) {
    use crate::collateral::{current_epoch_now, CurrentEpoch, EpochRecordStore};
    use crate::mirror::lifecycle::{self, NodeMirrorEffects, SpendCapability};
    use crate::mirror::runner::{PassContext, PassRunner};

    tokio::spawn(async move {
        let paths = dig_wallet::autoseed::default_paths();
        let (signer, capability) = lifecycle::open_signer(&paths, live_broadcast, &chain).await;

        // The owner puzzle hash comes from the SIGNER when there is one, so the key a spend is built
        // for and the address its bonds are observed under cannot be two different values. Without a
        // signer it is derived on its own — a public value, and the observation half needs it even
        // when nothing may spend.
        let Some(owner_puzzle_hash) = signer
            .as_ref()
            .map(|s| s.owner_puzzle_hash())
            .or_else(|| dig_wallet::operator_wallet::operator_puzzle_hash(&paths))
        else {
            tracing::warn!(
                target: "mirror",
                capability = ?capability,
                "no operator wallet is available, so this node cannot observe or bond its own \
                 capsules; SPEC.md §25.8 reports unknown until one exists"
            );
            return;
        };

        match capability {
            SpendCapability::Available => tracing::info!(
                target: "mirror",
                "the mirror lifecycle is live: this node may create and reclaim collateral"
            ),
            SpendCapability::BroadcastDisabled => tracing::info!(
                target: "mirror",
                "the mirror lifecycle OBSERVES only: DIG_WALLET_ENABLE_LIVE_BROADCAST is off, the \
                 money-safe default, so no mirror spend is sent"
            ),
            SpendCapability::WalletUnavailable => tracing::warn!(
                target: "mirror",
                "the mirror lifecycle OBSERVES only: the operator wallet (SPEC.md §16.4) did not open"
            ),
            // Deliberately NOT phrased as a flag to set: the operator has already set
            // DIG_WALLET_ENABLE_LIVE_BROADCAST to reach this arm at all.
            SpendCapability::ChainClientUnavailable => tracing::warn!(
                target: "mirror",
                "the mirror lifecycle OBSERVES only: the wallet opened and live broadcast is on, \
                 but this node could not build the shared chain client a broadcaster is made from, \
                 so a reclaim is planned and reported and no spend is sent"
            ),
        }

        // Read ONCE, for the life of the task, beside the wallet above. The value is an operator
        // configuration rather than an observation, and a coin's URLs are fixed at create for the
        // whole epoch — so re-reading it per pass would buy nothing and would let the list a
        // warning was emitted about drift from the list actually published.
        let advertised_urls = crate::mirror::advertise::configured_urls();

        let journal = lifecycle::journal();
        let mut presence = crate::mirror::presence::PresenceTracker::new();

        loop {
            let epoch = match current_epoch_now() {
                CurrentEpoch::Final(epoch) => epoch as i64,
                // No epoch in force means no requirement and no amount, so a pass could plan
                // nothing. Waiting is the whole action.
                _ => {
                    tokio::time::sleep(MIRROR_PASS_INTERVAL).await;
                    continue;
                }
            };
            let requirement = crate::collateral::requirement(
                &EpochRecordStore::in_state_dir(),
                current_epoch_now(),
            );
            let config = crate::collateral::CollateralConfig::load();

            // The two asynchronous readings, taken BEFORE the pass so the pass itself is
            // synchronous and sees one disk state and one balance throughout.
            let capsules = lifecycle::observe_disk(&node).await;
            let dig_balance = lifecycle::observe_dig_balance(&wallet, owner_puzzle_hash).await;

            // dig-node#286: the ONLY caller of the funded latch. `latch_ever_funded` was written,
            // persisted and tested, and nothing invoked it — so in the shipped build a funded
            // auto-created wallet was still described as disposable, for ever.
            //
            // This pass is the observation point because it already reads the operator wallet's
            // own balance on a timer, so the latch costs no extra chain read and cannot drift from
            // the figure the node acts on. `synced` gates ONLY the zero case (see
            // `FundingObservation::should_latch`), so a stale or fallback answer showing money
            // still latches immediately.
            {
                use crate::wallet_funded::FundingObservation;
                let synced = wallet
                    .wallet_sync_status()
                    .await
                    .is_ok_and(|s| s.phase == dig_wallet::sage::sync_supervisor::SyncPhase::Synced);
                let observation = match &dig_balance {
                    Ok(base_units) => {
                        FundingObservation::classify(u128::from(*base_units), 0, synced)
                    }
                    // An unreadable balance is not a zero balance. It says nothing, and the latch
                    // is monotonic, so the next pass that CAN read decides.
                    Err(_) => FundingObservation::CannotSay,
                };
                crate::wallet_funded::observe(&paths, observation);
            }
            // ONE reading of what is already committed, for the whole pass — the analogue of the
            // wallet selector's reservation prune (dig_ecosystem#2763), which the chain cannot
            // offer: a broadcast coin stays unspent in the chain's view for the entire confirmation
            // window, and this loop runs inside it. An `Err` defers creates and never reclaims.
            let committed = crate::mirror::funding::committed_funding_coin_ids(
                &crate::spend_audit::SpendLog::in_state_dir(),
            )
            .map_err(|e| crate::mirror::runner::PassError::Wallet(e.to_string()));

            match chain.chain_source(tokio::runtime::Handle::current()).await {
                Ok(source) => {
                    // Re-read per pass, deliberately: `ChainTransport::broadcaster` does not
                    // cache a failure, so a node that started offline can broadcast the moment
                    // its network returns. Holding one built at bring-up would silently make
                    // that node one that never broadcasts again.
                    let broadcast = lifecycle::production_broadcaster(&chain, live_broadcast).await;
                    let runtime = tokio::runtime::Handle::current();
                    let signer_ref = signer.as_ref();
                    let ctx = PassContext {
                        now_unix_ms: lifecycle::now_unix_ms(),
                        current_epoch: epoch,
                        requirement,
                        margin_bp: config.margin_bp,
                        creates_enabled: config.mirror_enabled,
                    };
                    // `block_in_place` rather than `spawn_blocking`: the runner borrows the signer,
                    // the journal and the chain source, none of which is `'static`, and moving them
                    // into a task would mean opening the wallet per pass — the second unseal route
                    // this design exists to remove.
                    let outcome = tokio::task::block_in_place(|| {
                        let effects = NodeMirrorEffects::new(
                            capsules,
                            dig_balance,
                            committed,
                            // The operator's own list (SPEC.md 25.10, dig-node#426), read ONCE
                            // at bring-up above. Empty when nothing is configured or nothing
                            // configured is publishable, and `create` then refuses by name before
                            // any chain read rather than staking collateral on an advertisement
                            // nobody can act on.
                            advertised_urls.clone(),
                            &source,
                            owner_puzzle_hash,
                            signer_ref,
                            &journal,
                            // The SAME seam `open_signer` derived the reported capability from, so
                            // what this node says it can do and what a spend can actually reach
                            // cannot be two different answers (dig-node#424).
                            broadcast.broadcaster(),
                            runtime,
                        );
                        let mut pass =
                            PassRunner::new(effects, crate::spend_audit::SpendLog::in_state_dir())
                                .with_presence(std::mem::take(&mut presence));
                        let report = pass.run(&ctx);
                        (report, pass.into_presence())
                    });
                    let (outcome, carried) = outcome;
                    presence = carried;

                    match outcome {
                        Ok(report) => {
                            lifecycle::publish(&snapshot, &report, epoch);
                            log_mirror_pass(&report, epoch);
                        }
                        // NOT published. An observation that failed is not a smaller observation:
                        // publishing an empty one would tell an operator this node holds no bonds
                        // and locks no money, which is a definite claim it is in no position to
                        // make. The surface keeps saying `unknown`, and any previous pass's answer
                        // is left in place rather than replaced by a worse one.
                        Err(e) => tracing::warn!(
                            target: "mirror",
                            error = %e,
                            "the mirror pass could not observe; SPEC.md §25.8 keeps its previous answer"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    target: "mirror",
                    error = %e,
                    "no chain source for the mirror pass this round"
                ),
            }

            tokio::time::sleep(MIRROR_PASS_INTERVAL).await;
        }
    });
}

/// Report what one mirror pass did, to whoever is reading the node's log.
///
/// A free function so the lines an operator actually reads can be asserted against, rather than
/// living only inside the timer loop where nothing can reach them.
fn log_mirror_pass(report: &crate::mirror::runner::PassReport, epoch: i64) {
    tracing::debug!(
        target: "mirror",
        epoch,
        bonds = report.states.len(),
        locked_dig_base_units = report.locked_dig_base_units,
        reclaimed = report.reclaimed.len(),
        created = report.created.len(),
        "mirror pass complete"
    );

    // At `warn!`, and naming the cause, because the DURABLE copy of a failed create's reason goes
    // to the spend-audit log under the state dir -- which a non-elevated node cannot write. This
    // line goes to stderr, so it survives exactly the case where the audit copy does not
    // (dig-node#440). Without it a create that failed reports nothing at any level: the line above
    // counts what SUCCEEDED, so a pass that created nothing and a pass that stopped on an error
    // render identically.
    if let Some((bond, cause)) = &report.stopped_at {
        tracing::warn!(
            target: "mirror",
            epoch,
            store_id = %bond.store_id,
            root = %bond.root,
            error = %cause,
            "the mirror pass stopped at a create that failed; later creates were not attempted"
        );
    }

    // Separate from the stop above because they are separate outcomes: a reclaim failure does not
    // end the pass, so a report can carry several of them alongside a perfectly successful set of
    // creates. One line each -- an aggregate count would name no coin, and the coin id is what a
    // person needs to look the spend up on chain.
    for (mirror, cause) in &report.reclaim_failures {
        tracing::warn!(
            target: "mirror",
            epoch,
            coin_id = %mirror.coin_id,
            store_id = %mirror.store_id,
            root = %mirror.root,
            error = %cause,
            "a mirror reclaim could not be made; its collateral stays locked"
        );
    }
}

/// Run the collateral census on a timer, against the node's own chain transport.
///
/// Detached and best-effort, exactly like the record bring-up above: a node that cannot census
/// still serves content, and every outcome is logged rather than swallowed. **A failure records
/// nothing** — `control.collateral.requirement` then answers `unknown` with its reason, which is
/// the honest answer and the one this node can defend.
///
/// The provider's reads are synchronous, so each pass runs inside [`tokio::task::spawn_blocking`]
/// and never occupies an async worker.
fn spawn_collateral_census(chain: Arc<dig_wallet::sage::chain::ChainTransport>) {
    use crate::collateral::{current_epoch_now, CurrentEpoch, EpochRecordStore};

    tokio::spawn(async move {
        loop {
            // Read the epoch on EVERY pass, not once: this task outlives an epoch boundary, and a
            // target captured at start-up would leave the node permanently one epoch behind from
            // the moment the schedule rolled over.
            let CurrentEpoch::Final(target) = current_epoch_now() else {
                tokio::time::sleep(COLLATERAL_CENSUS_INTERVAL).await;
                continue;
            };

            match chain.chain_source(tokio::runtime::Handle::current()).await {
                Ok(source) => {
                    let pass = tokio::task::spawn_blocking(move || {
                        crate::collateral_census::catch_up(
                            &source,
                            &EpochRecordStore::in_state_dir(),
                            target,
                        )
                    })
                    .await;

                    match pass {
                        Ok(outcome) => {
                            for observed in &outcome.recorded {
                                log_census_observation(observed);
                            }
                            // A repair, not a routine record: this node's chain view had been
                            // showing it a SMALLER network than the chain holds, and the
                            // requirement it derived was correspondingly low. WARN, because the
                            // figure it replaces was served to the operator in the meantime.
                            if let Some(repaired) = &outcome.superseded {
                                tracing::warn!(
                                    epoch = repaired.epoch,
                                    census_height = repaired.census_height,
                                    stores = repaired.stores,
                                    "a re-census of the current epoch counted MORE stores than the record this node held; the earlier, lower answer was superseded"
                                );
                                log_census_observation(repaired);
                            }
                            if let Some(stop) = outcome.stopped {
                                // WARN rather than ERROR: several stops — an epoch the chain has
                                // not reached, a census height not yet buried — are ordinary
                                // states whose remedy is to wait. The variant says which.
                                tracing::warn!(
                                    target_epoch = target,
                                    reason = ?stop,
                                    "the collateral census stopped short of the current epoch; \
                                     no record was written"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "the collateral census task did not complete"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "no chain source for the collateral census; the requirement stays unknown"
                ),
            }

            tokio::time::sleep(COLLATERAL_CENSUS_INTERVAL).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        chat_call_authorized, control_ingress_admits, is_app_origin, is_gated_chat_method,
        is_local_origin, peer_tier_status, provenance_for, read_origin_for, reflects_origin,
        requestor_for, served_response, ws_token, ServeProvenance, StorePath, APP_ORIGINS_ENV,
        EXPOSED_DIG_HEADERS,
    };
    use axum::http::{HeaderMap, Method};
    use dig_node_core::content_serve::{PeerTier, ServeSource};
    use dig_node_core::download::{ReadOrigin, RequestProvenance};
    use dig_node_core::rate_limit::{MissRateLimiter, RequestorId};
    use serde_json::{json, Value};
    use std::net::{Ipv4Addr, SocketAddr};

    // ---- the INGRESS bound on open, token-less control reads (dig_ecosystem#3051) ----------

    /// An anonymous caller at some IP — what a remote reader looks like once an operator has set
    /// `DIG_NODE_ALLOW_REMOTE=1` and the open control reads became network-reachable.
    fn anon(ip: &str) -> RequestorId {
        RequestorId::Anonymous(ip.to_string())
    }

    /// **An anonymous flood is refused AT INGRESS once its burst is spent.**
    ///
    /// The bound the ticket exists for: the open reads carry no token, so before this gate an
    /// unauthenticated caller could drive unbounded SQLite work — two lookups plus an LRU `UPDATE`
    /// per `coinById` — for free, simply by asking repeatedly.
    ///
    /// The pool never refills (`refill_per_sec = 0.0`), so the boundary is exact rather than timing
    /// dependent: three admitted, the fourth refused.
    #[test]
    fn an_anonymous_flood_is_refused_at_ingress_once_its_burst_is_spent() {
        let limiter = MissRateLimiter::new(3.0, 0.0);
        let caller = anon("203.0.113.7");

        for i in 0..3 {
            assert!(
                control_ingress_admits(&limiter, &caller),
                "read {i} is within the burst and must be admitted"
            );
        }
        assert!(
            !control_ingress_admits(&limiter, &caller),
            "the burst is spent: further token-less reads are refused BEFORE any SQLite work"
        );
    }

    /// **One flooding source never refuses a different one.**
    ///
    /// The property that makes the bound usable rather than a shared fuse: a single abusive IP
    /// exhausts only ITS OWN budget. Without it the gate becomes a denial-of-service primitive
    /// pointed at every other reader.
    #[test]
    fn one_flooding_source_never_refuses_another() {
        let limiter = MissRateLimiter::new(1.0, 0.0);
        let abuser = anon("203.0.113.7");
        let bystander = anon("198.51.100.4");

        assert!(control_ingress_admits(&limiter, &abuser));
        assert!(
            !control_ingress_admits(&limiter, &abuser),
            "the abuser's own budget is spent"
        );
        assert!(
            control_ingress_admits(&limiter, &bystander),
            "a different source draws from its own bucket and is untouched"
        );
    }

    /// **The node's OWN operator is NEVER refused at ingress — deliberately.**
    ///
    /// The limiter here has ZERO capacity, so it refuses every requestor it is actually consulted
    /// for. `Local` is admitted anyway, which is the only way this passes: the exemption is real,
    /// not an artifact of a generous bound.
    ///
    /// This test exists to FAIL if someone later "tightens" the gate onto loopback. Throttling the
    /// operator here would reproduce, from the ingress side, exactly the failure this family was
    /// opened to fix — a polling dig-app draining a bound until the user's own profile read was
    /// refused for days. See `control_ingress_admits` for the full rationale.
    #[test]
    fn the_operator_is_never_refused_at_ingress() {
        let refuses_everything = MissRateLimiter::new(0.0, 0.0);

        for i in 0..64 {
            assert!(
                control_ingress_admits(&refuses_everything, &RequestorId::Local),
                "the trusted operator's read {i} must never be throttled at ingress"
            );
        }
        assert!(
            !control_ingress_admits(&refuses_everything, &anon("203.0.113.7")),
            "the same limiter DOES refuse an anonymous caller — so the exemption above is the \
             reason Local passed, not a limiter that admits everyone"
        );
    }

    /// **A loopback caller resolves to the exempt identity, and a remote one does not.**
    ///
    /// Joins `requestor_for` to the gate above: the exemption is only correct if the thing it
    /// exempts really is the operator. A remote caller must never be classified `Local` and so can
    /// never inherit the exemption.
    #[test]
    fn loopback_is_the_operator_and_a_remote_caller_is_not() {
        assert!(
            requestor_for(&SocketAddr::from((Ipv4Addr::LOCALHOST, 9778))).is_local(),
            "a loopback caller is the operator"
        );
        let remote = requestor_for(&SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 9444)));
        assert!(
            !remote.is_local(),
            "a remote caller is NOT the operator and is subject to the ingress bound"
        );
        assert_eq!(
            remote,
            anon("203.0.113.7"),
            "and is keyed by its own address"
        );
    }

    /// **The ingress bound and the chain-egress bound are INDEPENDENTLY OBSERVABLE.**
    ///
    /// The ticket's stated bar. The two limits protect different things — this process versus the
    /// third-party oracle — and have different remedies, so a caller (and the next person debugging
    /// a refusal) must be able to tell which one fired without reading the message prose.
    #[test]
    fn the_ingress_and_egress_bounds_refuse_with_distinct_codes() {
        use crate::meta::ErrorCode;
        assert_ne!(
            ErrorCode::ControlIngressLimited.code(),
            ErrorCode::WalletRateLimited.code(),
            "a shared numeric code would make the two bounds indistinguishable on the wire"
        );
        assert_ne!(
            ErrorCode::ControlIngressLimited.name(),
            ErrorCode::WalletRateLimited.name(),
            "and the stable symbol a client branches on must differ too"
        );
        assert_eq!(ErrorCode::ControlIngressLimited.code(), -32033);
        assert_eq!(
            ErrorCode::ControlIngressLimited.name(),
            "CONTROL_INGRESS_LIMITED"
        );
    }

    /// **Regression (#1763):** the `X-Dig-Peer-Tier` wire value for BOTH tiers, asserted on the real
    /// response builder rather than on the enum alone.
    ///
    /// SPEC.md §4.3/§4.6 make this header's value set a cross-repo contract with dig-urn-resolver, so
    /// the literal is the contract. The only prior HTTP coverage exercised `unattached`, which the
    /// `dig-node-service` integration suite cannot escape: every test builds state via `build_state`,
    /// which never attaches an engine, so the `Attached` arm was unreachable there BY CONSTRUCTION and
    /// spelling it `"unattached"` in core kept the whole workspace green.
    ///
    /// **The fixture varies ONE actor.** Both arms build the IDENTICAL served response — same store
    /// path, same bytes, same `ServeSource::Local` — and differ only in the peer tier, with the
    /// `unattached` arm kept as the truthful control. Asserting both spellings also kills the
    /// swap/alias mutants (either arm returning the other's literal, or both returning one constant)
    /// that a single-direction assertion cannot see.
    /// Fail-closed regression: the WS transport treats a BLANK `token` as ABSENT, exactly
    /// like the HTTP `presented_token` path. Before this, `{"token":""}` reached the gate
    /// as `Some("")`; combined with the empty in-memory control token after a CSPRNG
    /// failure and `ct_eq("", "")` being `true`, a cross-origin page reaching `ws://` could
    /// have driven `control.*`/`wallet.*`. `ws_token` now yields `None` for a blank/absent
    /// token, so the gate sees no credential and denies (the empty-`expected` guard in
    /// `is_authorized`/`wallet_authz::authorize` is the transport-independent primary close).
    /// F1 (#1946): the chat control-token predicate. `chat.send` (seal + BLS-sign as the node's own
    /// 0x0010 identity) and `chat.poll` (drain the inbound inbox) are the ONLY gated chat methods; a
    /// caller is authorized only with the master control token or a valid paired token, fail-closed on
    /// an empty master (the CSPRNG-failure sentinel) so a blank token never matches a blank master.
    #[test]
    fn chat_gate_classifies_and_authorizes_like_a_control_mutation() {
        const MASTER: &str = "master-token-value";
        const PAIRED: &str = "paired-token-value";
        let is_paired = |t: &str| t == PAIRED;

        // Only chat.send + chat.poll are gated chat methods.
        assert!(is_gated_chat_method("chat.send"));
        assert!(is_gated_chat_method("chat.poll"));
        assert!(!is_gated_chat_method("chat.status"));
        assert!(!is_gated_chat_method("dig.getContent"));

        // No token / a wrong token → denied; the master or a paired token → allowed.
        assert!(!chat_call_authorized(None, MASTER, is_paired), "no token");
        assert!(
            !chat_call_authorized(Some("nope"), MASTER, is_paired),
            "wrong token"
        );
        assert!(
            chat_call_authorized(Some(MASTER), MASTER, is_paired),
            "master"
        );
        assert!(
            chat_call_authorized(Some(PAIRED), MASTER, is_paired),
            "paired"
        );

        // Fail closed on an empty master: no token — not even a blank one — is ever authorized.
        assert!(
            !chat_call_authorized(Some(""), "", is_paired),
            "blank vs blank"
        );
        assert!(!chat_call_authorized(Some("anything"), "", is_paired));
        assert!(!chat_call_authorized(Some(PAIRED), "", is_paired));
        assert!(!chat_call_authorized(None, "", is_paired));
    }

    #[test]
    fn ws_token_treats_a_blank_token_as_absent() {
        assert_eq!(ws_token(&json!({ "token": "" })), None);
        assert_eq!(ws_token(&json!({ "token": "   " })), None);
        assert_eq!(ws_token(&json!({})), None);
        assert_eq!(ws_token(&json!({ "token": Value::Null })), None);
        assert_eq!(ws_token(&json!({ "token": 123 })), None);
        // A real token is preserved verbatim (trimmed), so authorization still works.
        assert_eq!(ws_token(&json!({ "token": "deadbeef" })), Some("deadbeef"));
        assert_eq!(ws_token(&json!({ "token": "  tok  " })), Some("tok"));
    }

    #[test]
    fn served_response_reports_both_peer_tier_wire_values() {
        let sp = StorePath {
            store_id: "ab".repeat(32),
            root: None,
            resource: "data.bin".to_string(),
        };
        for (tier, expected) in [
            (PeerTier::Attached, "attached"),
            (PeerTier::Unattached, "unattached"),
        ] {
            let resp = served_response(
                &sp,
                "data.bin",
                b"payload".to_vec(),
                &"cd".repeat(32),
                ServeProvenance {
                    verified: true,
                    source: ServeSource::Local,
                    peer_tier: tier,
                    owner_puzzle_hash: None,
                    generation: None,
                },
            );
            assert_eq!(
                resp.headers()
                    .get("X-Dig-Peer-Tier")
                    .map(|v| v.to_str().expect("ascii header")),
                Some(expected),
                "{tier:?} must serialize as {expected:?} on the wire (#1763)"
            );
            // The serving tier is the CONTROL: it is Local in both arms, so a mutant that derives the
            // peer tier from the serve source cannot satisfy this pair.
            assert_eq!(
                resp.headers().get("X-Dig-Source").map(|v| v.to_str().ok()),
                Some(Some("local")),
                "{tier:?}: the serve source is the control and must not vary"
            );
        }
    }

    /// **Regression (#1763):** `/health`'s `peer_tier.attached` reports BOTH directions.
    ///
    /// The `true` direction is the one that matters asymmetrically: SPEC.md §6.1/§7.8 tell every
    /// harness to POLL `peer_tier.attached` until it is true instead of sleeping, so a field pinned at
    /// `false` turns the documented wait into an infinite one with exactly the observable signature of
    /// the legitimate readiness window (`status: "ok"` + `attached: false`). Only the `false` arm had
    /// coverage, because `build_state` never attaches an engine and attachment is settable only inside
    /// `dig-node-core` — hence the assertion sits on the pure mapping that `status_fields` delegates to,
    /// which is reachable on the CI host with no peer network and no widened production visibility.
    #[test]
    fn health_peer_tier_status_reports_both_directions() {
        assert_eq!(
            peer_tier_status(PeerTier::Attached),
            json!({ "attached": true }),
            "an attached engine must report attached: true — the value harnesses poll for"
        );
        assert_eq!(
            peer_tier_status(PeerTier::Unattached),
            json!({ "attached": false }),
            "no engine must report attached: false — the truthful control"
        );
    }

    /// **Proves (#1956):** the `POST /` JSON-RPC path derives its landing provenance from the SAME
    /// `Sec-Fetch-Site` classifier the `/s/` serve path uses — a `cross-site` header denies landing, an
    /// ABSENT header (a CLI/SDK client, or a same-origin navigation) is first-party so it still lands.
    /// This is the load-bearing wiring: without `provenance_for` on the POST handler the whole gate is
    /// a no-op (constant FirstParty). The `rpc` handler passes exactly this value into `handle_rpc`.
    #[test]
    fn provenance_is_read_on_the_post_path() {
        let mut cross = HeaderMap::new();
        cross.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert_eq!(
            provenance_for(&cross),
            RequestProvenance::CrossSite,
            "a cross-site POST must classify as CrossSite so its landing legs are denied"
        );

        // No Sec-Fetch-Site header (a non-browser client, or a same-origin request) ⇒ first-party.
        assert_eq!(
            provenance_for(&HeaderMap::new()),
            RequestProvenance::FirstParty,
            "an absent header must be first-party — a CLI/SDK read must never be mistaken for cross-site"
        );

        let mut same = HeaderMap::new();
        same.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert_eq!(
            provenance_for(&same),
            RequestProvenance::FirstParty,
            "a same-origin POST still lands — only an explicit cross-site value denies landing"
        );
    }

    #[test]
    fn read_origin_for_classifies_ipv4_mapped_loopback_as_local() {
        // #1664b: on a `::` dual-stack bind an IPv4 loopback client arrives as the
        // IPv4-mapped form `::ffff:127.0.0.1`, which the bare `Ipv6Addr::is_loopback`
        // (== ::1 only) would misclassify as `Peer` — silently disabling the operator's
        // own warm-up flywheel. The shared `is_loopback_addr` helper unwraps the mapping.
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:9778".parse().unwrap();
        assert_eq!(read_origin_for(&mapped), ReadOrigin::Local);

        // Native loopback of both families is Local too.
        assert_eq!(
            read_origin_for(&SocketAddr::from((Ipv4Addr::LOCALHOST, 9778))),
            ReadOrigin::Local
        );
        assert_eq!(
            read_origin_for(&"[::1]:9778".parse().unwrap()),
            ReadOrigin::Local
        );

        // A real remote address — and an IPv4-mapped NON-loopback — stay `Peer`.
        assert_eq!(
            read_origin_for(&SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 9444))),
            ReadOrigin::Peer
        );
        assert_eq!(
            read_origin_for(&"[::ffff:203.0.113.7]:9444".parse().unwrap()),
            ReadOrigin::Peer
        );
    }

    #[test]
    fn tauri_desktop_app_origins_are_allowed_for_cors() {
        // #669: a native app (Tauri) consuming dig-urn-resolver must reach the node-first tier.
        for ok in ["tauri://localhost", "https://tauri.localhost"] {
            assert!(
                is_app_origin(ok),
                "{ok:?} (Tauri) must be an allowed app origin"
            );
            assert!(
                reflects_origin(ok, &Method::GET, "/health"),
                "{ok:?} must pass the CORS allow predicate for a content read"
            );
        }
    }

    #[test]
    fn app_origin_allowlist_env_opts_in_extra_origins() {
        // A serialized guard is unnecessary here: this is the only test touching this env var.
        std::env::set_var(APP_ORIGINS_ENV, "app://my-desktop-app , electron://dig ");
        assert!(is_app_origin("app://my-desktop-app"));
        assert!(is_app_origin("electron://dig"));
        assert!(!is_app_origin("app://not-listed"));
        std::env::remove_var(APP_ORIGINS_ENV);
        // With the env cleared, a non-built-in origin is no longer allowed.
        assert!(!is_app_origin("app://my-desktop-app"));
    }

    #[test]
    fn non_app_origins_are_not_allowed() {
        for bad in [
            "https://evil.example.com",
            "tauri://not-localhost",
            "http://evil.com",
        ] {
            assert!(
                !is_app_origin(bad),
                "{bad:?} must NOT be an allowed app origin"
            );
        }
    }

    #[test]
    fn verification_headers_are_exposed_to_cross_origin_readers() {
        // #669: the resolver's browser node-first path reads these; a missing exposed header makes
        // it fail closed → drop to rpc. The four the ticket names MUST be present.
        for required in [
            "x-dig-verified",
            "x-dig-root",
            "x-dig-inclusion-proof",
            "x-dig-chunk-lens",
        ] {
            assert!(
                EXPOSED_DIG_HEADERS.contains(&required),
                "{required} must be exposed via Access-Control-Expose-Headers"
            );
        }
        // #1763: the peer-tier readiness header is part of the SAME cross-origin contract — a
        // browser-side resolver that cannot READ it cannot tell a cold-start gateway serve from a
        // genuine peer miss, and loses that distinction SILENTLY (the header is still sent).
        assert!(
            EXPOSED_DIG_HEADERS.contains(&"x-dig-peer-tier"),
            "x-dig-peer-tier must be exposed via Access-Control-Expose-Headers (#1763)"
        );
        // Every entry is a valid lowercase HeaderName (from_static panics otherwise) — this asserts
        // the const stays constructible, the exact shape the CORS layer relies on.
        for h in EXPOSED_DIG_HEADERS {
            let _ = axum::http::HeaderName::from_static(h);
        }
    }

    #[test]
    fn local_origins_are_reflected_for_cors() {
        // The extension + every canonical local page origin (#91) is reflected.
        for ok in [
            "chrome-extension://abcdefghijklmnop",
            "http://localhost",
            "http://localhost:9778",
            "http://dig.local",
            "http://dig.local:80",
            "http://127.0.0.1:9778",
            "http://127.0.0.2",
            // #288: a page served from the IPv6 loopback (a client whose
            // `localhost` resolves to `::1` first) is reflected too.
            "http://[::1]:9778",
            "http://[::1]",
        ] {
            assert!(
                is_local_origin(ok),
                "{ok:?} must be a reflected local origin"
            );
        }
    }

    #[test]
    fn non_local_origins_are_not_reflected() {
        for bad in [
            "http://evil.example.com",
            "https://localhost", // https scheme is not a local http page origin
            "http://",           // empty host
            "http://dig.local.evil.com",
            "ws://localhost",
            "http://[::2]", // non-loopback IPv6 literal
            "",
        ] {
            assert!(!is_local_origin(bad), "{bad:?} must NOT be reflected");
        }
    }

    // ---- what a mirror pass SAYS when a create fails (dig-node#440) ---------------------

    /// Render one pass report through a real subscriber at its DEFAULT level, and return the text.
    ///
    /// Default level deliberately: the durable copy of a failure cause goes to the spend-audit log,
    /// which a non-elevated node cannot write — so the property under test is that the cause reaches
    /// an operator running an ordinary node, not that it exists somewhere at `debug`.
    fn rendered_mirror_pass_log(report: &crate::mirror::runner::PassReport) -> String {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Captured(Arc<Mutex<Vec<u8>>>);

        impl Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("the capture buffer")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
            type Writer = Captured;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buffer = Captured(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            super::log_mirror_pass(report, 104);
        });

        let bytes = buffer.0.lock().expect("the capture buffer").clone();
        String::from_utf8(bytes).expect("the rendered lines are utf-8")
    }

    /// A report carrying nothing but what each test varies.
    fn empty_report() -> crate::mirror::runner::PassReport {
        crate::mirror::runner::PassReport {
            reclaimed: Vec::new(),
            created: Vec::new(),
            reclaim_failures: Vec::new(),
            stopped_at: None,
            states: Vec::new(),
            per_coin_dig_base_units: None,
            locked_dig_base_units: 0,
        }
    }

    /// **The store, the root and the cause of a failed create all reach the log.**
    ///
    /// The fixture carries a SUCCESSFUL create beside the failed one, with different ids, so a line
    /// that names "a store" cannot pass by naming the wrong one — which is what an implementation
    /// logging `report.created` instead of `report.stopped_at` would do.
    #[test]
    fn a_create_that_failed_is_logged_with_its_store_root_and_cause() {
        use crate::mirror::plan::Bond;
        use crate::mirror::runner::PassError;

        let mut report = empty_report();
        report.created = vec![Bond::new("aaaa1111", "bbbb2222")];
        report.stopped_at = Some((
            Bond::new("4e904b3f", "6b420246"),
            PassError::Wallet("Access is denied. (os error 5)".to_string()),
        ));

        let line = rendered_mirror_pass_log(&report);
        println!("{line}");

        for field in [
            "WARN",
            "4e904b3f",
            "6b420246",
            "the operator wallet could not act: Access is denied. (os error 5)",
        ] {
            assert!(
                line.contains(field),
                "a failed create is silent about {field}: {line:?}"
            );
        }
    }

    /// **A reclaim that could not be made is logged with its coin, its bond and its cause.**
    ///
    /// Separate from the create above because they are separate fields: an implementation that logs
    /// only `stopped_at` satisfies the previous test and drops every reclaim failure on the floor.
    #[test]
    fn a_reclaim_that_failed_is_logged_with_its_coin_and_cause() {
        use crate::mirror::plan::HeldMirror;
        use crate::mirror::runner::PassError;

        let mut report = empty_report();
        report.reclaim_failures = vec![(
            HeldMirror {
                coin_id: "c0117777".to_string(),
                store_id: "5e5e5e5e".to_string(),
                root: "7a7a7a7a".to_string(),
                epoch: 103,
                collateral_dig_base_units: 1010,
            },
            PassError::Chain("no peer answered".to_string()),
        )];

        let line = rendered_mirror_pass_log(&report);
        println!("{line}");

        for field in [
            "WARN",
            "c0117777",
            "5e5e5e5e",
            "7a7a7a7a",
            "the chain source could not be read: no peer answered",
        ] {
            assert!(
                line.contains(field),
                "a failed reclaim is silent about {field}: {line:?}"
            );
        }
    }

    /// **A pass that failed nothing warns about nothing.**
    ///
    /// The truthful control. Without it, an implementation that warns on every pass — including the
    /// ordinary one where the wallet is simply short, which §25.8 is explicit is NOT a failure —
    /// passes both tests above while training an operator to ignore the line.
    #[test]
    fn a_pass_with_no_failures_emits_no_warning() {
        use crate::mirror::plan::Bond;

        let mut report = empty_report();
        report.created = vec![Bond::new("aaaa1111", "bbbb2222")];

        let line = rendered_mirror_pass_log(&report);

        assert!(
            !line.contains("WARN"),
            "a clean pass warned, so the warning carries no information: {line:?}"
        );
    }
}
