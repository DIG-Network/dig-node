//! End-to-end server tests: spin up the companion's axum app in-process (no OS
//! service, no real network) and exercise `/health`, CORS, the cache.* RPC, and
//! blind passthrough against a mock upstream DIG RPC.
//!
//! These mirror the Node reference server's `rpc-integration` / `server` tests so
//! the Rust binary's behaviour is verified to match the contract the extension
//! relies on. The content read path itself (ciphertext + proof + decrypt) lives in
//! dig-node and is covered by digstore's own tests; here we verify the companion
//! shell: it serves health, applies CORS, and routes RPC to the node.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

/// dig-node reads `DIG_NODE_UPSTREAM` (and the cache-dir env) ONCE, at
/// `Node::from_env()` construction, from the process-global environment. Tests run
/// concurrently in one process, so without serialization one test's `set_var`
/// could be clobbered by another's between set and construct — a TOCTOU race that
/// wires a node to the wrong mock upstream. This mutex makes "set env → build node"
/// atomic across tests; it is held only for that brief construction window.
fn env_guard() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Start a mock upstream DIG RPC on a random loopback port. It records every
/// request and answers `dig.getAnchoredRoot` / `dig.listCapsules` / echoes the
/// rest — enough to assert delegation + passthrough. Returns (base_url, calls).
async fn start_mock_upstream() -> (String, Arc<Mutex<Vec<Value>>>) {
    let calls: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let calls_for_handler = calls.clone();

    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let calls = calls_for_handler.clone();
            async move {
                calls.lock().unwrap().push(req.clone());
                let id = req.get("id").cloned().unwrap_or(json!(1));
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let result = match method {
                    "dig.getAnchoredRoot" => json!({
                        "store_id": req["params"]["store_id"],
                        "root": "f".repeat(64),
                    }),
                    "dig.listCapsules" => json!({ "capsules": ["passthrough-ok"] }),
                    _ => json!({ "echoed": method }),
                };
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), calls)
}

/// Start the companion app on a random loopback port pointed at the given upstream
/// and an isolated cache dir. Returns the companion's base URL.
async fn start_companion(upstream: &str) -> SocketAddr {
    let config = dig_companion::Config {
        upstream: upstream.to_string(),
        port: 0, // bind ephemeral
        ..dig_companion::Config::default()
    };

    // Build the node under the env lock so set-env → from_env() is atomic w.r.t.
    // other concurrent tests (see env_guard). build_state both applies the upstream
    // to DIG_NODE_UPSTREAM and constructs the node, so the whole call is guarded.
    let state = {
        let _g = env_guard().lock().unwrap();
        // Isolate dig-node's on-disk cache so the test never touches the real cache,
        // and pin a small cap (must be set before from_env reads it).
        let tmp = std::env::temp_dir().join(format!("dig-companion-test-{}", std::process::id()));
        std::env::set_var("DIG_NODE_CACHE", &tmp);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        dig_companion::server::build_state(&config)
    };
    let app = dig_companion::server::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

#[tokio::test]
async fn health_reports_ok_version_mode_and_cache() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], json!("ok"));
    assert_eq!(resp["mode"], json!("local-node"));
    assert_eq!(resp["version"], json!(dig_companion::VERSION));
    assert_eq!(resp["upstream"], json!(upstream));
    assert!(resp["cache"]["cap_bytes"].as_u64().is_some());
    assert!(resp["cache"]["used_bytes"].as_u64().is_some());
    // Agent-friendly additions: service name, commit, configured addr, cache dir, methods.
    // (`addr` reflects the configured bind addr — the test binds an ephemeral port via
    // config.port=0, so it is "127.0.0.1:0", distinct from the live socket `addr`.)
    assert_eq!(resp["service"], json!("dig-node"));
    assert!(resp["commit"].is_string());
    assert_eq!(resp["addr"], json!("127.0.0.1:0"));
    assert!(resp["cache"]["dir"].is_string());
    let methods = resp["methods"].as_array().expect("methods array");
    assert!(methods.iter().any(|m| m == &json!("dig.getContent")));
    assert!(methods.iter().any(|m| m == &json!("rpc.discover")));
}

#[tokio::test]
async fn version_endpoint_reports_build_fingerprint() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .get(format!("http://{addr}/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["service"], json!("dig-node"));
    assert_eq!(resp["version"], json!(dig_companion::VERSION));
    assert!(resp["commit"].is_string());
    assert!(resp["dig_node_version"].is_string());
    assert_eq!(resp["protocol"], json!("21"));
}

#[tokio::test]
async fn well_known_document_is_a_discovery_surface() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .get(format!("http://{addr}/.well-known/dig-node.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["service"], json!("dig-node"));
    assert_eq!(resp["addr"], json!("127.0.0.1:0"));
    assert!(resp["cache"]["dir"].is_string());
    assert!(resp["methods"].is_array());
    assert!(resp["errors"].is_array());
    assert_eq!(resp["rpc"]["openrpc"], json!("/openrpc.json"));
    assert_eq!(resp["rpc"]["discover"], json!("rpc.discover"));
}

#[tokio::test]
async fn openrpc_endpoint_serves_the_spec() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .get(format!("http://{addr}/openrpc.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["openrpc"], json!("1.2.6"));
    let methods = resp["methods"].as_array().expect("methods");
    assert!(methods.iter().any(|m| m["name"] == json!("dig.getContent")));
    assert!(methods.iter().any(|m| m["name"] == json!("rpc.discover")));
}

#[tokio::test]
async fn rpc_discover_returns_the_openrpc_document() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "rpc.discover" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Answered by the shell (not relayed to the upstream), returns the spec.
    assert_eq!(resp["id"], json!(1));
    assert_eq!(resp["result"]["openrpc"], json!("1.2.6"));
    assert!(resp["result"]["methods"].is_array());
}

#[tokio::test]
async fn cors_reflects_chrome_extension_origin() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let origin = "chrome-extension://abcdefghijklmnop";
    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("http://{addr}/"))
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .unwrap();

    let allow = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        allow, origin,
        "the chrome-extension origin must be reflected"
    );
}

#[tokio::test]
async fn cache_get_config_reports_cap_and_used() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "cache.getConfig" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(resp["result"]["cap_bytes"].as_u64().is_some());
    assert!(resp["result"]["used_bytes"].as_u64().is_some());
}

#[tokio::test]
async fn anchored_root_and_passthrough_relay_to_upstream() {
    let (upstream, calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    // Unknown method → blind passthrough to the upstream, relayed verbatim.
    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 9, "method": "dig.listCapsules", "params": {}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["result"]["capsules"], json!(["passthrough-ok"]));

    // The upstream actually saw the relayed call.
    let seen = calls.lock().unwrap();
    assert!(
        seen.iter()
            .any(|c| c["method"] == json!("dig.listCapsules")),
        "passthrough must reach the upstream"
    );
}

#[tokio::test]
async fn non_object_body_returns_jsonrpc_error_not_transport_error() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    let resp = client()
        .post(format!("http://{addr}/"))
        .json(&json!([{ "jsonrpc": "2.0", "id": 1, "method": "cache.getConfig" }]))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], json!(-32600));
    // The error carries the stable symbolic code an agent branches on.
    assert_eq!(body["error"]["data"]["code"], json!("INVALID_REQUEST"));
    assert_eq!(body["error"]["data"]["origin"], json!("shell"));
}
