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
    start_companion_full(upstream).await.0
}

/// Like [`start_companion`] but also returns the local control token the server
/// generated, so the control-plane tests can authorize `control.*` calls (a same-
/// host controller reads it from `<config_dir>/control-token`; here the test reads
/// the same on-disk token the server wrote, mirroring exactly that controller flow).
async fn start_companion_full(upstream: &str) -> (SocketAddr, String) {
    let config = dig_companion::Config {
        upstream: upstream.to_string(),
        port: 0, // bind ephemeral
        ..dig_companion::Config::default()
    };

    // Build the node under the env lock so set-env → from_env() is atomic w.r.t.
    // other concurrent tests (see env_guard). build_state both applies the upstream
    // to DIG_NODE_UPSTREAM and constructs the node, so the whole call is guarded.
    let (state, token) = {
        let _g = env_guard().lock().unwrap();
        // Isolate dig-node's on-disk cache so the test never touches the real cache,
        // and pin a small cap (must be set before from_env reads it).
        let tmp = std::env::temp_dir().join(format!("dig-companion-test-{}", std::process::id()));
        std::env::set_var("DIG_NODE_CACHE", &tmp);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        let state = dig_companion::server::build_state(&config);
        // The token the server wrote (read from disk, exactly as a real controller
        // would). config_path() resolves under the temp DIG_NODE_CACHE we just set.
        let token = dig_companion::control::load_or_create_token().unwrap();
        (state, token)
    };
    let app = dig_companion::server::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, token)
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
    // #96: health reflects whether the cache is the shared canonical dir (true) or
    // a process-private fallback (false) — sourced from dig-node's resolver.
    assert!(
        resp["cache"]["shared"].is_boolean(),
        "cache.shared must be a bool"
    );
    let methods = resp["methods"].as_array().expect("methods array");
    assert!(methods.iter().any(|m| m == &json!("dig.getContent")));
    assert!(methods.iter().any(|m| m == &json!("rpc.discover")));
}

#[tokio::test]
async fn cache_get_config_reports_dir_and_shared_from_dig_node() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    // #96 additive fields on the dig-node `cache.getConfig` RPC: the effective
    // resolved cache dir + whether it is the shared canonical one. The companion
    // routes this straight to dig_node::handle_rpc, so this asserts the new crate
    // contract reaches clients through the companion unchanged.
    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "cache.getConfig" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(resp["result"]["cache_dir"].is_string());
    assert!(resp["result"]["shared"].is_boolean());
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

// ===========================================================================
// #91 — Host-header allowlist + the bare-dig.local dual listener.
// The node binds loopback-only and answers to dig.local / localhost / 127.0.0.1
// / 127.0.0.2 (the four canonical local names) so http://dig.local (no port) and
// http://localhost:<port> both work; a foreign Host (the DNS-rebinding vector) is
// rejected even on loopback.
// ===========================================================================

#[tokio::test]
async fn host_allowlist_accepts_dig_local_and_localhost() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    // Each canonical local Host (the loopback bind makes the actual socket the
    // same; we override the Host header to prove the allowlist accepts the name).
    for host in [
        "dig.local",
        "dig.local:80",
        "localhost:8080",
        "127.0.0.1",
        "127.0.0.2:80",
    ] {
        let resp = client()
            .get(format!("http://{addr}/health"))
            .header("Host", host)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "Host {host:?} must be served, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn host_allowlist_rejects_a_foreign_host() {
    let (upstream, _calls) = start_mock_upstream().await;
    let addr = start_companion(&upstream).await;

    // A foreign Host (e.g. a public name rebinding-pointed at the loopback bind)
    // is rejected with 421 + a catalogued error body, before any handler runs.
    let resp = client()
        .get(format!("http://{addr}/health"))
        .header("Host", "evil.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 421, "foreign Host must be rejected");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["data"]["code"], json!("INVALID_REQUEST"));
}

#[tokio::test]
async fn dual_listener_serves_localhost_when_dig_local_bind_fails() {
    // The bind-fallback contract: with dig.local ENABLED the node tries to bind the
    // privileged 127.0.0.2:80 — which fails in CI (no privilege / no loopback alias
    // / possibly in use) — and MUST still serve on localhost rather than aborting.
    let (upstream, _calls) = start_mock_upstream().await;

    // Grab a free loopback port, then hand it to serve_with_shutdown explicitly so
    // we know where to probe (serve_with_shutdown binds config.bind_addr directly).
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free); // release it so the server can bind the same port

    let config = dig_companion::Config {
        upstream: upstream.to_string(),
        port,
        dig_local: true, // attempt the privileged 127.0.0.2:80 bind (expected to fail in CI)
        ..dig_companion::Config::default()
    };

    // Drive serve under the env lock (build_state reads env at node construction).
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_for_server = stop.clone();
    let server = {
        let _g = env_guard().lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("dig-companion-dual-{}", std::process::id()));
        std::env::set_var("DIG_NODE_CACHE", &tmp);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        tokio::spawn(async move {
            dig_companion::server::serve_with_shutdown(config, async move {
                stop_for_server.notified().await;
            })
            .await
        })
    };

    // Poll until localhost is serving (the server starts asynchronously).
    let url = format!("http://127.0.0.1:{port}/health");
    let mut served = false;
    for _ in 0..50 {
        if let Ok(r) = client().get(&url).send().await {
            if r.status().is_success() {
                served = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    assert!(
        served,
        "localhost must keep serving even when the dig.local (:80) bind fails"
    );

    // Clean shutdown.
    stop.notify_waiters();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
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

// ===========================================================================
// CONTROL plane (#101a) — loopback-only + locally-authorized admin RPC.
// The gate contract: a control.* call WITHOUT the token is rejected; WITH it,
// allowed; READ calls are unaffected (no token needed).
// ===========================================================================

/// POST a JSON-RPC request, optionally with the control-token header. Returns the
/// parsed response body.
async fn post_rpc(addr: &SocketAddr, body: Value, token: Option<&str>) -> Value {
    let mut req = client().post(format!("http://{addr}/")).json(&body);
    if let Some(t) = token {
        req = req.header("X-Dig-Control-Token", t);
    }
    req.send().await.unwrap().json().await.unwrap()
}

#[tokio::test]
async fn control_method_without_token_is_rejected_with_unauthorized() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        None, // no token
    )
    .await;

    assert_eq!(resp["error"]["code"], json!(-32020));
    assert_eq!(resp["error"]["data"]["code"], json!("UNAUTHORIZED"));
    assert_eq!(resp["error"]["data"]["origin"], json!("shell"));
    assert!(resp.get("result").is_none(), "no result on a rejected call");
}

#[tokio::test]
async fn control_method_with_wrong_token_is_rejected() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        Some("the-wrong-token"),
    )
    .await;
    assert_eq!(resp["error"]["data"]["code"], json!("UNAUTHORIZED"));
}

#[tokio::test]
async fn control_status_with_token_returns_rich_status() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "control.status" }),
        Some(&token),
    )
    .await;

    assert_eq!(resp["id"], json!(7));
    let r = &resp["result"];
    assert_eq!(r["running"], json!(true));
    assert_eq!(r["service"], json!("dig-node"));
    assert_eq!(r["version"], json!(dig_companion::VERSION));
    assert!(r["uptime_secs"].is_u64());
    assert!(r["cache"]["cap_bytes"].is_u64());
    assert!(r["hosted_store_count"].is_u64());
    assert!(r["pinned_store_count"].is_u64());
    assert!(r["sync"]["available"].is_boolean());
}

#[tokio::test]
async fn control_token_via_params_is_also_accepted() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    // No header — present the token in params._control_token instead.
    let resp = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "control.cache.get",
            "params": { "_control_token": token }
        }),
        None,
    )
    .await;
    assert!(resp["result"]["cap_bytes"].is_u64());
    assert!(resp["result"]["used_bytes"].is_u64());
    assert!(resp["result"]["dir"].is_string());
    assert!(resp["result"]["shared"].is_boolean());
}

#[tokio::test]
async fn read_methods_are_unaffected_by_the_control_gate() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token) = start_companion_full(&upstream).await;

    // A read method with NO token must still work (the gate is control.* only).
    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "cache.getConfig" }),
        None,
    )
    .await;
    assert!(resp["result"]["cap_bytes"].is_u64());
    assert!(resp.get("error").is_none(), "read method must not be gated");
}

#[tokio::test]
async fn control_config_get_reports_addr_upstream_and_cache() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.config.get" }),
        Some(&token),
    )
    .await;
    let r = &resp["result"];
    assert_eq!(r["upstream"], json!(upstream));
    assert!(r["addr"].is_string());
    assert!(r["cache_dir"].is_string());
    assert!(r["sync_available"].is_boolean());
}

#[tokio::test]
async fn control_pin_unpin_roundtrips_in_hosted_stores() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let store = "a1".repeat(32); // 64-hex
    let cap = format!("{store}:{}", "b2".repeat(32));

    // Pin (store-level — no fetch since no concrete root would be served by the mock).
    let pin = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "control.hostedStores.pin",
            "params": { "store": store }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(pin["result"]["pinned"], json!(true));
    assert_eq!(pin["result"]["store_id"], json!(store));

    // It shows up in the hosted-store list as pinned.
    let list = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "control.hostedStores.list" }),
        Some(&token),
    )
    .await;
    let stores = list["result"]["stores"].as_array().unwrap();
    let entry = stores
        .iter()
        .find(|s| s["store_id"] == json!(store))
        .expect("pinned store listed");
    assert_eq!(entry["pinned"], json!(true));

    // A capsule-form pin is also accepted (parses storeId:rootHash).
    let pin_cap = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "control.hostedStores.pin",
            "params": { "store": cap }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(pin_cap["result"]["pinned"], json!(true));

    // Unpin removes it.
    let unpin = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "control.hostedStores.unpin",
            "params": { "store": store }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(unpin["result"]["unpinned"], json!(true));
}

#[tokio::test]
async fn control_pin_rejects_a_malformed_store_ref() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 1, "method": "control.hostedStores.pin",
            "params": { "store": "not-a-valid-hex-store-id" }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(resp["error"]["data"]["code"], json!("INVALID_PARAMS"));
}

#[tokio::test]
async fn control_sync_status_reports_availability() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.sync.status" }),
        Some(&token),
    )
    .await;
    assert!(resp["result"]["available"].is_boolean());
    assert_eq!(
        resp["result"]["method"],
        json!("section-21-whole-store-sync")
    );
    assert!(resp["result"]["pinned_total"].is_u64());
}

#[tokio::test]
async fn control_unknown_method_is_method_not_found() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.does.not.exist" }),
        Some(&token),
    )
    .await;
    assert_eq!(resp["error"]["data"]["code"], json!("METHOD_NOT_FOUND"));
}

#[tokio::test]
async fn control_methods_are_not_passed_through_to_upstream() {
    // A control.* method without a token must be rejected by the SHELL, never
    // relayed to the upstream (it is not a read method).
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, _token) = start_companion_full(&upstream).await;

    let _ = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        None,
    )
    .await;
    let seen = calls.lock().unwrap();
    assert!(
        !seen.iter().any(|c| c["method"]
            .as_str()
            .map(|m| m.starts_with("control."))
            .unwrap_or(false)),
        "control.* must never reach the upstream"
    );
}

#[tokio::test]
async fn control_cors_preflight_allows_the_control_token_header() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token) = start_companion_full(&upstream).await;

    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("http://{addr}/"))
        .header("Origin", "chrome-extension://abcdefghijklmnop")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "x-dig-control-token")
        .send()
        .await
        .unwrap();

    let allow_headers = resp
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    assert!(
        allow_headers.contains("x-dig-control-token"),
        "preflight must allow the control-token header, got: {allow_headers}"
    );
}
