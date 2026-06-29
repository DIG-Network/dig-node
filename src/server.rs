//! The companion's HTTP server: `/health`, CORS, and `POST /` → the embedded
//! dig-node's `handle_rpc`.
//!
//! This is the localhost endpoint the DIG Chrome extension points its `server.host`
//! setting at. It speaks the SAME wire contract as rpc.dig.net (because it routes
//! to `dig_node::handle_rpc`), so the extension's `fetchContentViaRPC` pipeline —
//! `dig.getContent` → verify → decrypt, all done in the extension — works against
//! it byte-for-byte, with the bonus that resources are served local-first from any
//! `.dig` modules the node has cached.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use dig_node::{cache_cap_bytes, cache_used_bytes, handle_rpc, Node};
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::config::Config;
use crate::control::{self, ControlCtx};
use crate::meta;
use crate::meta::ErrorCode;
use crate::rpc::{normalize_request, request_id, rpc_error};

/// The companion binary version, surfaced by `/health`.
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
    /// The node's config.json path — where the companion's pin registry + upstream
    /// override live (the CONTROL plane reads/writes here).
    config_path: std::path::PathBuf,
    /// The local control token: a same-host controller must present it on every
    /// `control.*` call. Generated at startup into `<config_dir>/control-token`
    /// (loopback-only + locally-authorized gate — see [`crate::control`]).
    control_token: String,
    /// Whether authenticated §21 whole-store sync is available (a §21 identity is
    /// loaded). `Node::from_env` creates/loads the §21.9 identity at construction, so
    /// this is normally `true`; the AUTHORITATIVE per-capsule result is still
    /// reported in-band by the sync/pin operations.
    sync_available: bool,
    /// Process start instant, for `control.status` uptime.
    started: Instant,
}

/// dig-node's "method not found" error code. `handle_rpc` resolves only
/// `dig.getContent` / `dig.getAnchoredRoot` / `cache.*` and returns this for
/// anything else; the companion treats that as the cue to blind-passthrough the
/// request to the upstream.
const METHOD_NOT_FOUND: i64 = ErrorCode::MethodNotFound.code();

/// Build the companion's axum router. Beside `POST /` (JSON-RPC) and `GET /health`
/// it exposes the self-describing discovery surface so an agent can introspect the
/// node with zero out-of-band knowledge:
///   * `GET /version`                    — build/commit/version fingerprint
///   * `GET /openrpc.json`               — the OpenRPC method+error spec
///   * `GET /.well-known/dig-node.json`  — addr + cache + methods + errors + spec links
///
/// Split out from [`serve`] so it can be exercised by an in-process test without
/// binding a port.
pub fn router(state: AppState) -> Router {
    // The extension calls from a `chrome-extension://` origin; a same-machine dev
    // page calls from `http://localhost`. Reflect those (and any origin in dev) so
    // the browser's CORS preflight passes. The companion is loopback-only, so a
    // permissive reflected origin here is not a public-exposure risk.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _req| {
            origin
                .to_str()
                .map(|o| o.starts_with("chrome-extension://") || o.starts_with("http://localhost"))
                .unwrap_or(false)
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        // CONTENT_TYPE for the JSON body; the control-token header so a same-host
        // controller (the DIG Browser "My Node" UI) can authorize control.* calls.
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-dig-control-token"),
        ]);

    Router::new()
        .route("/", get(health).post(rpc))
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/openrpc.json", get(openrpc))
        .route("/.well-known/dig-node.json", get(well_known))
        .layer(cors)
        .with_state(state)
}

/// Construct the shared state from config: apply the upstream to dig-node's env,
/// then build the node from the environment (cache dir/cap, §21 identity), and
/// generate/load the local control token into the node's config dir.
pub fn build_state(config: &Config) -> AppState {
    config.apply_to_env();
    let node = Node::from_env();
    let config_path = dig_node::config_path();
    // Generate (or read) the control token into <config_dir>/control-token. A
    // failure to persist it (e.g. unwritable dir) is non-fatal: fall back to an
    // in-memory token so the control plane is still gated (a controller that can't
    // read the file simply can't authorize — fail-closed). The read plane is
    // unaffected either way.
    let control_token = control::load_or_create_token().unwrap_or_else(|e| {
        eprintln!(
            "dig-node: WARN could not persist control token ({e}); using an in-memory \
             token (control.* will be unauthorizable until the config dir is writable)"
        );
        // A random in-memory token nothing can present → control plane fails closed.
        control::load_or_create_token_at(
            &std::env::temp_dir().join(format!("dig-node-control-token-{}", std::process::id())),
        )
        .unwrap_or_default()
    });
    AppState {
        node,
        upstream: config.upstream.clone(),
        http: reqwest::Client::builder()
            .user_agent(concat!("dig-companion/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("dig-companion: build http client"),
        addr: config.bind_addr(),
        config_path,
        control_token,
        // Node::from_env loads/creates the §21.9 identity, enabling authenticated
        // whole-store sync; we report it available and let the per-capsule fetch
        // surface a real NOT_SUPPORTED/failure in-band if a given store isn't served.
        sync_available: true,
        started: Instant::now(),
    }
}

/// The [`ControlCtx`] for one request — borrows the long-lived node + config and
/// snapshots the per-state fields the control plane needs.
fn control_ctx(state: &AppState) -> ControlCtx {
    ControlCtx {
        node: state.node.clone(),
        config_path: state.config_path.clone(),
        addr: state.addr.clone(),
        upstream: state.upstream.clone(),
        started: state.started,
        sync_available: state.sync_available,
    }
}

/// `GET /health` (and `GET /`) — liveness + mode + cache stats + discovery hooks.
/// Shape extends the Node companion's health body (existing probes keep parsing
/// `status`/`version`/`mode`/`upstream`/`cache`) with agent-friendly additions:
/// `service` (the canonical `dig-node` name), `commit`, the bound `addr`, the
/// cache `dir` + `shared` flag (#96 — is the cache the shared canonical dir or a
/// private fallback), and the `methods` catalogue — so a single `/health` fetch
/// reveals what the node is and what it serves.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": meta::SERVICE_NAME,
        "version": VERSION,
        "commit": meta::GIT_SHA,
        "mode": "local-node",
        "addr": state.addr,
        "upstream": state.upstream,
        "cache": {
            "dir": meta::cache_dir().display().to_string(),
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
            // #96: whether the cache is the shared canonical dir (the dir the DIG
            // Browser's in-process node also uses) or a process-private fallback.
            "shared": meta::cache_shared(),
        },
        "methods": meta::method_names(),
    }))
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
/// `dig.getAnchoredRoot` / `cache.*` and returns `-32601 method not found` for
/// everything else. For those (e.g. `dig.getProof`, `dig.listCapsules`,
/// `dig.getManifest`) the companion relays the ORIGINAL request to the upstream so
/// it stays a correct transparent proxy — matching the Node reference server and
/// the surface clients expect from an rpc.dig.net endpoint.
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

    // CONTROL plane: the `control.*` (admin/management) methods are loopback-only
    // (the whole server binds 127.0.0.1) AND locally authorized — a same-host
    // controller must present the local control token (the X-Dig-Control-Token
    // header or params._control_token). The READ methods below are NOT gated.
    if control::is_control_method(&method) {
        let header_tok = headers
            .get(control::CONTROL_TOKEN_HEADER)
            .and_then(|v| v.to_str().ok());
        let presented = control::presented_token(header_tok, &req);
        if !control::is_authorized(&method, presented.as_deref(), &state.control_token) {
            return (
                StatusCode::OK,
                Json(control::control_error(
                    id,
                    ErrorCode::Unauthorized,
                    "control.* requires the local control token (X-Dig-Control-Token \
                     header or params._control_token, from <config_dir>/control-token)",
                )),
            );
        }
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let ctx = control_ctx(&state);
        let resp = control::dispatch_control(&ctx, id, &method, &params).await;
        return (StatusCode::OK, Json(resp));
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

/// Run the companion HTTP server until the process is asked to stop. Binds the
/// configured loopback address and serves until Ctrl-C / SIGTERM (so the OS
/// service manager's stop is graceful). This is the body of `dig-companion run`
/// and the unix-service entrypoint (systemd/launchd send SIGTERM to stop).
pub async fn serve(config: Config) -> std::io::Result<()> {
    serve_with_shutdown(config, shutdown_signal()).await
}

/// Like [`serve`], but the caller supplies the shutdown future. The Windows
/// service entrypoint uses this to drive graceful shutdown from the SCM `Stop`
/// control event (which is not a unix signal), instead of the OS-signal future.
pub async fn serve_with_shutdown<F>(config: Config, shutdown: F) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let addr = config.bind_addr();
    let state = build_state(&config);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("dig-node: cannot bind {addr}: {e}")))?;
    // Operational log line → stderr, so `run --json` leaves stdout for the single
    // structured object (prose-to-stderr convention).
    eprintln!(
        "dig-node v{VERSION} (local-node) listening on http://{addr}\n  \
         upstream: {}\n  Point the DIG Chrome extension's \"server host\" at {addr}.",
        config.upstream
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
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
    eprintln!("dig-node: shutting down");
}
