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

use axum::{
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use dig_node::{cache_cap_bytes, cache_used_bytes, handle_rpc, Node};
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::config::Config;
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
}

/// dig-node's "method not found" error code. `handle_rpc` resolves only
/// `dig.getContent` / `dig.getAnchoredRoot` / `cache.*` and returns this for
/// anything else; the companion treats that as the cue to blind-passthrough the
/// request to the upstream.
const METHOD_NOT_FOUND: i64 = -32601;

/// Build the companion's axum router (health + RPC + CORS). Split out from
/// [`serve`] so it can be exercised by an in-process test without binding a port.
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
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    Router::new()
        .route("/", get(health).post(rpc))
        .route("/health", get(health))
        .layer(cors)
        .with_state(state)
}

/// Construct the shared state from config: apply the upstream to dig-node's env,
/// then build the node from the environment (cache dir/cap, §21 identity).
pub fn build_state(config: &Config) -> AppState {
    config.apply_to_env();
    AppState {
        node: Node::from_env(),
        upstream: config.upstream.clone(),
        http: reqwest::Client::builder()
            .user_agent(concat!("dig-companion/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("dig-companion: build http client"),
    }
}

/// `GET /health` (and `GET /`) — liveness + mode + cache stats. Shape mirrors the
/// Node companion's health body so existing probes keep parsing it.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "version": VERSION,
        "mode": "local-node",
        "upstream": state.upstream,
        "cache": {
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
        },
    }))
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
async fn rpc(State(state): State<AppState>, Json(req): Json<Value>) -> impl IntoResponse {
    if !req.is_object() {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        return (
            StatusCode::OK,
            Json(rpc_error(
                id,
                -32600,
                "dig-companion: expected a single JSON-RPC request object",
            )),
        );
    }
    let id = request_id(&req);
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
            -32000,
            format!("dig-companion: dispatch failed: {e}"),
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
                rpc_error(id, -32010, format!("dig-companion upstream error: {e}"))
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

    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        std::io::Error::new(e.kind(), format!("dig-companion: cannot bind {addr}: {e}"))
    })?;
    println!(
        "dig-companion v{VERSION} (local-node) listening on http://{addr}\n  \
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
    println!("dig-companion: shutting down");
}
