//! The dig-node service's HTTP server: `/health`, CORS, and `POST /` → the embedded
//! dig-node read path's `handle_rpc`.
//!
//! This is the localhost endpoint the DIG Chrome extension points its `server.host`
//! setting at. It speaks the SAME wire contract as rpc.dig.net (because it routes
//! to `dig_node_core::handle_rpc`), so the extension's `fetchContentViaRPC` pipeline —
//! `dig.getContent` → verify → decrypt, all done in the extension — works against
//! it byte-for-byte, with the bonus that resources are served local-first from any
//! `.dig` modules the node has cached.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{Body, Bytes},
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Request, State,
    },
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dig_node_core::content_serve::{PlaintextOutcome, ServeSource};
use dig_node_core::{cache_cap_bytes, cache_used_bytes, handle_rpc, Node};
use dig_wallet::sage::events::{SyncEvent, SyncLifecycle, SyncStatus};
use dig_wallet::sage::rpc::WalletBackend;
use dig_wallet::sage::service::WalletService;
use dig_wallet::sage::transport::{serve_mtls, SharedCert, DEFAULT_MTLS_PORT};
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};

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
    upstream: String,
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
    /// The shared self-signed cert the mTLS `9257` listener presents (Sage byte-parity, node-class
    /// clients). Held so [`serve_with_shutdown`] can bring up that sibling listener.
    wallet_cert: SharedCert,
}

/// dig-node's "method not found" error code. `handle_rpc` resolves only
/// `dig.getContent` / `dig.getAnchoredRoot` / `cache.*` and returns this for
/// anything else; this service treats that as the cue to blind-passthrough the
/// request to the upstream.
const METHOD_NOT_FOUND: i64 = ErrorCode::MethodNotFound.code();

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
    // names). Reflect those so the browser's CORS preflight passes. The node is
    // loopback-only, so reflecting these local origins is not a public-exposure risk.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _req| {
            origin.to_str().map(is_allowed_origin).unwrap_or(false)
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
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
        // The node is loopback-only, so allowing this to every reflected local origin is not a
        // public-exposure risk (mirrors the existing origin-reflection trust boundary above).
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
const EXPOSED_DIG_HEADERS: [&str; 10] = [
    "x-dig-verified",
    "x-dig-root",
    "x-dig-inclusion-proof",
    "x-dig-chunk-lens",
    "x-dig-source",
    "x-dig-store-id",
    "x-dig-capsule",
    "x-dig-resource-key",
    "x-dig-owner-puzzle-hash",
    "x-dig-generation",
];

/// Whether a CORS `Origin` is one this loopback node reflects. Two families, both loopback-only
/// trust (the node binds loopback only; CORS is not an auth boundary):
///
/// - **Same-machine web/extension origins** ([`is_local_origin`]) — the extension's
///   `chrome-extension://` scheme + `http://` pages served from a canonical local name (#91).
/// - **Desktop-app origins** ([`is_app_origin`]) — Tauri's `tauri://localhost` /
///   `https://tauri.localhost` + any origin in the operator-configured [`APP_ORIGINS_ENV`]
///   allowlist (#669), so a native app consuming dig-urn-resolver reaches the node-first tier.
///
/// PURE so the policy is unit-testable.
fn is_allowed_origin(origin: &str) -> bool {
    is_local_origin(origin) || is_app_origin(origin)
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
/// binds loopback-only it never serves a foreign-named (rebinding) request. Allowed
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
        node,
        upstream: config.upstream.clone(),
        http: reqwest::Client::builder()
            .user_agent(concat!("dig-node/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("dig-node: build http client"),
        addr: config.bind_addr(),
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
    }
}

impl AppState {
    /// The served node-custodied wallet backend (#368). Exposed so a caller that built the state
    /// (e.g. an integration test, or the bring-up that spawns the mTLS listener) can share the SAME
    /// backend + its event bus the router dispatches to.
    pub fn wallet_backend(&self) -> Arc<WalletBackend> {
        self.wallet.clone()
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
        upstream: state.upstream.clone(),
        started: state.started,
        sync_available: state.sync_available,
        pairings: state.pairings.clone(),
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
    m.insert("upstream".into(), json!(state.upstream));
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
    m
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
/// is allowed — loopback-only binding is that caller's defense.
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
        &state.upstream,
        cache_cap_bytes(),
        cache_used_bytes(),
    ))
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
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> impl IntoResponse {
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

    // CONTROL plane: the `control.*` (admin/management) methods are loopback-only
    // (the whole server binds 127.0.0.1) AND locally authorized — a same-host
    // controller must present the local control token (the X-Dig-Control-Token
    // header or params._control_token). The READ methods below are NOT gated.
    if control::is_control_method(&method) {
        let header_tok = headers
            .get(control::CONTROL_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok());
        let presented = control::presented_token(header_tok, &req);
        // Authorization is granted by EITHER the master control token OR — for a
        // NON-administrative control method — a valid PAIRED token (#280). Pairing
        // administration (list/approve/revoke) requires the MASTER token only, so a
        // paired controller can neither mint more tokens nor revoke itself.
        let master_ok = control::is_authorized(&method, presented.as_deref(), &state.control_token);
        let paired_ok = !control::is_pairing_admin_method(&method)
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

    // Keep the original request for a possible passthrough relay (the upstream must
    // see exactly what the client sent, not the dig-node-normalised form).
    let original = req.clone();
    let normalized = normalize_request(req);

    // handle_rpc never panics on a malformed request — it returns an error
    // envelope — but guard the dispatch anyway so a future change can't take the
    // server down on one bad request.
    let node = state.node.clone();
    let resp = match tokio::task::spawn(async move { handle_rpc(&node, normalized).await }).await {
        Ok(v) => v,
        Err(e) => rpc_error(
            id.clone(),
            ErrorCode::DispatchFailed,
            format!("dig-node: dispatch failed: {e}"),
        ),
    };

    // If dig-node didn't resolve the method, relay it blindly to the upstream.
    if resp
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
        == Some(METHOD_NOT_FOUND)
    {
        let relayed = proxy(&state.http, &state.upstream, &original)
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
        let paired_ok = !control::is_pairing_admin_method(method)
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
    let token = v.get("token").and_then(|t| t.as_str());
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
async fn store_serve(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    match parse_store_path(&path) {
        Some(sp) => serve_resource(&state, sp).await,
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
async fn fallback_serve(State(state): State<AppState>, headers: HeaderMap, uri: Uri) -> Response {
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    match reroot_via_referer(referer, uri.path()) {
        Some(sp) => serve_resource(&state, sp).await,
        None => not_found(),
    }
}

/// Resolve → verify → decrypt one store resource and shape the HTTP response, applying the
/// SPA-fallback-vs-404 decision on a miss.
async fn serve_resource(state: &AppState, sp: StorePath) -> Response {
    let root = sp.root.as_deref().unwrap_or("");
    // Public stores only for now (salt = None): a private store's secret salt is not yet provisioned
    // to the local serve surface, so such a store fails closed at decrypt (a documented follow-up).
    match state
        .node
        .serve_content_plaintext(&sp.store_id, root, &sp.resource, None)
        .await
    {
        PlaintextOutcome::Served {
            bytes,
            root_hex,
            verified,
            source,
            owner_puzzle_hash,
            generation,
        } => served_response(
            &sp,
            &sp.resource,
            bytes,
            &root_hex,
            verified,
            source,
            owner_puzzle_hash.as_deref(),
            generation,
        ),
        PlaintextOutcome::NotFound { root_hex } => serve_miss(state, &sp, &root_hex).await,
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
async fn serve_miss(state: &AppState, sp: &StorePath, root_hex: &str) -> Response {
    if is_static_asset_path(&sp.resource) {
        return not_found();
    }
    if let Some(paths) = state.node.manifest_paths(&sp.store_id, root_hex).await {
        if paths.iter().any(|p| p == &sp.resource) {
            return not_found();
        }
    }
    // SPA fallback: the store's default view, served against the SAME resolved root.
    match state
        .node
        .serve_content_plaintext(&sp.store_id, root_hex, "index.html", None)
        .await
    {
        PlaintextOutcome::Served {
            bytes,
            root_hex,
            verified,
            source,
            owner_puzzle_hash,
            generation,
        } => served_response(
            sp,
            "index.html",
            bytes,
            &root_hex,
            verified,
            source,
            owner_puzzle_hash.as_deref(),
            generation,
        ),
        _ => not_found(),
    }
}

/// Build the `200` response for a served resource: the ecosystem content-type + `nosniff`, the
/// `X-Dig-Verified`/`X-Dig-Root`/`X-Dig-Source` provenance headers (#292), the serve-metadata HEAD
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
#[allow(clippy::too_many_arguments)]
fn served_response(
    sp: &StorePath,
    resource: &str,
    bytes: Vec<u8>,
    root_hex: &str,
    verified: bool,
    source: ServeSource,
    owner_puzzle_hash: Option<&str>,
    generation: Option<u64>,
) -> Response {
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
    let addr = config.bind_addr();
    let state = build_state(&config).await;

    // Grab the wallet backend + mTLS cert before the router consumes `state` (#368): the served
    // wallet rides the loopback HTTP surface (`POST /{method}`) AND a sibling mTLS 9257 listener
    // for node-class/Sage-drop-in parity (§5.3 transport).
    let wallet_backend = state.wallet.clone();
    let wallet_cert = state.wallet_cert.clone();

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
        dig_node_core::peer::spawn_peer_network(state.node.clone());
    }

    // Always-on self-heal driver (#584 beacon re-arm + #651 ext-forcelist reconcile): on a
    // privileged SERVICE run, periodically re-arm a drifted auto-update schedule (`dig-updater
    // schedule ensure`, opt-out-respecting) and re-apply the extension force-install policy
    // (`dig-installer --set-ext-forcelist-channel`). Gated to a service run — its repairs need
    // elevation, and a dev/CLI run must not attempt privileged sibling spawns. Detached +
    // best-effort: it never blocks or fails the serve path. See [`crate::self_heal`].
    if crate::state::running_as_service() {
        crate::self_heal::spawn_driver();
    }

    // Best-effort mTLS `9257` listener (#368, Sage byte-parity, node-class clients, §5.3). Binds
    // loopback only; a bind failure (port in use) is NON-FATAL — the wallet stays reachable over
    // the plain-HTTP `POST /{method}` surface + the `/ws` transport, which is what the extension
    // uses. The listener stops when the process exits with the rest of the node.
    match std::net::TcpListener::bind(("127.0.0.1", DEFAULT_MTLS_PORT)) {
        Ok(l) => {
            let _ = l.set_nonblocking(true);
            let backend = wallet_backend.clone();
            let cert = wallet_cert.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_mtls(backend, l, &cert).await {
                    tracing::warn!(error = %e, "wallet mTLS listener exited");
                }
            });
            tracing::info!(
                addr = %format!("127.0.0.1:{DEFAULT_MTLS_PORT}"),
                "wallet mTLS (Sage-parity) listening"
            );
        }
        Err(e) => tracing::warn!(
            error = %e,
            addr = %format!("127.0.0.1:{DEFAULT_MTLS_PORT}"),
            "could not bind the wallet mTLS listener; node-class Sage-parity clients unavailable \
             (non-fatal). The wallet is still served on the loopback HTTP surface + /ws"
        ),
    }

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
                warn_ipv6_bind_failed(&v6_addr, &e);
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
                warn_dig_local_bind_failed(&dl_addr, &e);
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

    let localhost_srv = {
        let app = app.clone();
        let n = shutdown_notify.clone();
        axum::serve(localhost, app).with_graceful_shutdown(async move { n.notified().await })
    };

    let ipv6_srv = ipv6.map(|(_, l)| {
        let app = app.clone();
        let n = shutdown_notify.clone();
        axum::serve(l, app).with_graceful_shutdown(async move { n.notified().await })
    });

    let dig_local_srv = dig_local.map(|(_, l)| {
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
fn warn_ipv6_bind_failed(v6_addr: &str, e: &std::io::Error) {
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
fn warn_dig_local_bind_failed(dl_addr: &str, e: &std::io::Error) {
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
        &https_addr,
        rustls_config.clone(),
        app.clone(),
        shutdown_notify,
    );

    // (4b) The best-effort IPv6 loopback sibling `[::1]:443` (§5.2), covered by the leaf SAN.
    if let Some(v6_addr) = config.dig_local_https_addr_v6() {
        spawn_https_listener(&v6_addr, rustls_config, app.clone(), shutdown_notify);
    }
}

/// Bind `addr` and spawn a best-effort TLS listener serving `app`. A bind failure logs a
/// structured warning and is non-fatal (the plaintext surface keeps serving), mirroring the
/// bare-`http://dig.local` policy — `:443` is privileged (the installed service runs elevated).
fn spawn_https_listener(
    addr: &str,
    rustls_config: axum_server::tls_rustls::RustlsConfig,
    app: Router,
    shutdown_notify: &Arc<tokio::sync::Notify>,
) {
    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
            tracing::info!(addr = %addr, "HTTPS (https://dig.local) listening");
            let shutdown = shutdown_notify.clone();
            let addr = addr.to_string();
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
        .serve(app.into_make_service())
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

#[cfg(test)]
mod tests {
    use super::{
        is_allowed_origin, is_app_origin, is_local_origin, APP_ORIGINS_ENV, EXPOSED_DIG_HEADERS,
    };

    #[test]
    fn tauri_desktop_app_origins_are_allowed_for_cors() {
        // #669: a native app (Tauri) consuming dig-urn-resolver must reach the node-first tier.
        for ok in ["tauri://localhost", "https://tauri.localhost"] {
            assert!(
                is_app_origin(ok),
                "{ok:?} (Tauri) must be an allowed app origin"
            );
            assert!(
                is_allowed_origin(ok),
                "{ok:?} must pass the CORS allow predicate"
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
}
