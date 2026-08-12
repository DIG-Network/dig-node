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
use dig_wallet::sage::events::SyncEvent;
use dig_wallet::sage::rpc::WalletBackend;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};

/// Serializes every test that builds a companion server. dig-node reads
/// `DIG_NODE_UPSTREAM` and the cache/config/token paths from the PROCESS-GLOBAL
/// environment — at construction AND live on each request. Tests run concurrently in
/// one process, so without serialization one test's `set_var` (+ its dir teardown) is
/// observed mid-request by another, racing the upstream wiring and the control-token
/// file (→ flaky UNAUTHORIZED / cache-dir-not-writable fallbacks). The lock is held
/// for the WHOLE test (via [`EnvHold`]), not just the build window, so those global
/// reads stay consistent for that test's lifetime.
///
/// A `tokio::sync::Mutex` (not `std::sync::Mutex`) because the guard is held across
/// `.await` points; its guard is await-safe, whereas a std guard trips
/// `clippy::await_holding_lock`. `Arc` + `lock_owned()` yields a `'static` guard the
/// helpers can return.
fn env_guard() -> Arc<tokio::sync::Mutex<()>> {
    static LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Monotonic sequence giving each `start_companion_full` call a UNIQUE cache/config
/// dir, so the per-server control-token file + pin registry (and pinned-store list a
/// test asserts on) are never shared between tests. This + the [`EnvHold`] lock
/// together remove the flaky UNAUTHORIZED: the lock makes the global-env reads
/// consistent, the unique dir keeps each server's on-disk state isolated.
static TEST_DIR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

/// A held serialization guard returned by the start helpers. The companion server
/// reads the PROCESS-GLOBAL `DIG_NODE_CACHE` (and the config/token paths derived from
/// it) LIVE on every request — so two tests running concurrently with different cache
/// dirs race (one test's `set_var` + dir teardown is observed mid-request by another,
/// surfacing as cache-dir-not-writable fallbacks or token mismatches → flaky
/// UNAUTHORIZED). Production is single-process/single-config and correct; only the
/// concurrent test harness must serialize. A test binds this guard (`_hold`) so the
/// global env stays pinned to ITS dir for the whole test, then releases it on drop.
/// (Per-test unique dirs alone are not enough precisely because the reads are live
/// and global — the lock is what makes them consistent.)
#[must_use]
struct EnvHold(
    // Held purely for its Drop (RAII release of the serialization lock). The field is
    // never read — the value's lifetime IS its purpose — so silence dead_code.
    #[allow(dead_code)] tokio::sync::OwnedMutexGuard<()>,
);

/// Start the companion app on a random loopback port pointed at the given upstream
/// and an isolated cache dir. Returns the companion's base URL and the [`EnvHold`]
/// serialization guard the caller must keep alive for the test's duration.
async fn start_companion(upstream: &str) -> (SocketAddr, EnvHold) {
    let (addr, _token, hold) = start_companion_full(upstream).await;
    (addr, hold)
}

/// Like [`start_companion`] but also returns the local control token the server
/// generated, so the control-plane tests can authorize `control.*` calls (a same-
/// host controller reads it from `<config_dir>/control-token`; here the test reads
/// the same on-disk token the server wrote, mirroring exactly that controller flow).
async fn start_companion_full(upstream: &str) -> (SocketAddr, String, EnvHold) {
    start_companion_full_inner(upstream, None).await
}

async fn start_companion_full_inner(
    upstream: &str,
    chia_peers: Option<u32>,
) -> (SocketAddr, String, EnvHold) {
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,                  // bind ephemeral
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };

    // Hold the env lock for the WHOLE test (returned as EnvHold), not just the build
    // window: build_state applies the upstream to DIG_NODE_UPSTREAM and constructs the
    // node, but the server then reads DIG_NODE_CACHE/config_path LIVE per request, so
    // the lock must outlive construction to keep those reads consistent (see EnvHold).
    let hold = env_guard().lock_owned().await;
    let (state, token) = {
        // Isolate dig-node's on-disk state PER CALL so the test never touches the
        // real cache AND no two concurrent tests share state.
        //
        // The control-token file + config.json pin registry live in the PARENT of
        // DIG_NODE_CACHE: dig-node's `config_path()` is `cache_dir().parent()/
        // config.json` and the token sits beside it. So pointing DIG_NODE_CACHE at a
        // PID-only (or even per-seq) dir directly under the system temp dir leaves the
        // PARENT shared — every test then read/wrote the SAME `<temp>/control-token`,
        // and on Windows a concurrent reader could hit that file mid-write, error,
        // and fall back to a random in-memory token → intermittent UNAUTHORIZED on a
        // token-gated control.* call (the flaky failure this guards). Give each call
        // its own PARENT dir (`<temp>/dig-node-test-<pid>-<seq>/cache`) so the
        // token + config.json are unique per server. (Set before from_env reads it.)
        let unique = TEST_DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("dig-node-test-{}-{}", std::process::id(), unique));
        let cache = base.join("cache");
        std::fs::create_dir_all(&cache).expect("create test cache dir");
        std::env::set_var("DIG_NODE_CACHE", &cache);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        // Isolate the control-token/paired-token STATE dir per test (#501): without this, on a
        // host that already has a real machine state dir (`/var/lib/dig-node`, `%PROGRAMDATA%\
        // DigNode`, …) the server + this test would resolve THAT shared dir instead of the temp
        // one, losing isolation and clobbering across concurrent tests. DIG_NODE_STATE_DIR (the
        // designed test/deploy override) pins it to this test's base dir, identity-independently.
        std::env::set_var("DIG_NODE_STATE_DIR", &base);
        let state = dig_node_service::server::build_state(&config).await;
        let state = match chia_peers {
            Some(n) => state.with_chia_peer_count_for_tests(n),
            None => state,
        };
        // The token the server wrote (read from disk, exactly as a real controller
        // would). config_path() resolves under the temp DIG_NODE_CACHE we just set.
        let token = dig_node_service::control::load_or_create_token().unwrap();
        (state, token)
    };
    // `into_make_service_with_connect_info` — not the plain `app` — is what makes
    // `ConnectInfo<SocketAddr>` extractable in the real `rpc()` handler (#1619 follow-up): a bare
    // `axum::serve(listener, router)` never populates it.
    let app =
        dig_node_service::server::router(state).into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, token, EnvHold(hold))
}

/// Like [`start_companion_full`], but with the wallet's Chia peer count pinned to `peers`. No
/// supervisor is started and nothing is dialled — see `AppState::with_chia_peer_count_for_tests`.
async fn start_companion_full_with_chia_peers(
    upstream: &str,
    peers: u32,
) -> (SocketAddr, String, EnvHold) {
    start_companion_full_inner(upstream, Some(peers)).await
}

/// Like [`start_companion`] but ALSO returns this node's loop-probe request (#1997) — the exact
/// body the bring-up probe puts on the wire. A loop-breaker test must be able to stage the probe
/// COMING BACK, and only the node knows the random id it generated.
async fn start_companion_probe(upstream: &str) -> (SocketAddr, Value, EnvHold) {
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };
    let hold = env_guard().lock_owned().await;
    let (state, probe) = {
        let unique = TEST_DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("dig-node-test-{}-{}", std::process::id(), unique));
        let cache = base.join("cache");
        std::fs::create_dir_all(&cache).expect("create test cache dir");
        std::env::set_var("DIG_NODE_CACHE", &cache);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        std::env::set_var("DIG_NODE_STATE_DIR", &base);
        let state = dig_node_service::server::build_state(&config).await;
        let probe = state.loop_probe_request();
        (state, probe)
    };
    let app =
        dig_node_service::server::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, probe, EnvHold(hold))
}

/// Like [`start_companion_probe`] but ALSO returns the built [`AppState`], so a test can observe
/// the shell's and the ENGINE's relay decisions directly instead of inferring them from a response.
async fn start_companion_probe_state(
    upstream: &str,
) -> (
    SocketAddr,
    Value,
    dig_node_service::server::AppState,
    EnvHold,
) {
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };
    let hold = env_guard().lock_owned().await;
    let (state, probe) = {
        let unique = TEST_DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("dig-node-test-{}-{}", std::process::id(), unique));
        let cache = base.join("cache");
        std::fs::create_dir_all(&cache).expect("create test cache dir");
        std::env::set_var("DIG_NODE_CACHE", &cache);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        std::env::set_var("DIG_NODE_STATE_DIR", &base);
        let state = dig_node_service::server::build_state(&config).await;
        let probe = state.loop_probe_request();
        (state, probe)
    };
    let app = dig_node_service::server::router(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, probe, state, EnvHold(hold))
}

/// Like [`start_companion_full`] but ALSO returns the served wallet backend (#368/#369) so a WS
/// push test can drive the backend's event bus directly. Same per-call on-disk isolation + env
/// lock (the wallet DB + seed live under the same per-test config dir).
async fn start_companion_wallet(
    upstream: &str,
) -> (SocketAddr, String, Arc<WalletBackend>, EnvHold) {
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };
    let hold = env_guard().lock_owned().await;
    let (state, token, backend) = {
        let unique = TEST_DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("dig-node-test-{}-{}", std::process::id(), unique));
        let cache = base.join("cache");
        std::fs::create_dir_all(&cache).expect("create test cache dir");
        std::env::set_var("DIG_NODE_CACHE", &cache);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        // Isolate the control-token/paired-token STATE dir per test (#501): without this, on a
        // host that already has a real machine state dir (`/var/lib/dig-node`, `%PROGRAMDATA%\
        // DigNode`, …) the server + this test would resolve THAT shared dir instead of the temp
        // one, losing isolation and clobbering across concurrent tests. DIG_NODE_STATE_DIR (the
        // designed test/deploy override) pins it to this test's base dir, identity-independently.
        std::env::set_var("DIG_NODE_STATE_DIR", &base);
        let state = dig_node_service::server::build_state(&config).await;
        let token = dig_node_service::control::load_or_create_token().unwrap();
        let backend = state.wallet_backend();
        (state, token, backend)
    };
    let app =
        dig_node_service::server::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, token, backend, EnvHold(hold))
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

#[tokio::test]
async fn health_reports_ok_version_mode_and_cache() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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
    assert_eq!(resp["version"], json!(dig_node_service::VERSION));
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

/// #669: a desktop-app (Tauri) cross-origin request to the loopback serve surface must be
/// reflected by CORS, and the `X-Dig-*` verification headers must be EXPOSED so the browser
/// dig-urn-resolver can read the "Verified by Chia" attestation instead of failing closed.
#[tokio::test]
async fn cors_reflects_tauri_origin_and_exposes_verification_headers() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    // A preflight from a Tauri origin is answered + reflected (not blocked as foreign).
    let preflight = client()
        .request(reqwest::Method::OPTIONS, format!("http://{addr}/health"))
        .header("Origin", "tauri://localhost")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("tauri://localhost"),
        "the Tauri desktop-app origin must be reflected by CORS"
    );

    // A real GET from that origin exposes the verification headers to the cross-origin reader.
    let resp = client()
        .get(format!("http://{addr}/health"))
        .header("Origin", "tauri://localhost")
        .send()
        .await
        .unwrap();
    let exposed = resp
        .headers()
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    for required in [
        "x-dig-verified",
        "x-dig-root",
        "x-dig-inclusion-proof",
        "x-dig-chunk-lens",
    ] {
        assert!(
            exposed.contains(required),
            "{required} must be listed in Access-Control-Expose-Headers (got {exposed:?})"
        );
    }
}

#[tokio::test]
async fn cache_get_config_reports_dir_and_shared_from_dig_node() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    // #96 additive fields on the dig-node `cache.getConfig` RPC: the effective
    // resolved cache dir + whether it is the shared canonical one. The companion
    // routes this straight to dig_node_core::handle_rpc, so this asserts the new crate
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
    let (addr, _hold) = start_companion(&upstream).await;

    let resp: Value = client()
        .get(format!("http://{addr}/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["service"], json!("dig-node"));
    assert_eq!(resp["version"], json!(dig_node_service::VERSION));
    assert!(resp["commit"].is_string());
    // #586: exactly one version field — the ambiguous `dig_node_version` alias is gone.
    assert!(resp.get("dig_node_version").is_none());
    assert_eq!(resp["protocol"], json!("21"));
}

#[tokio::test]
async fn well_known_document_is_a_discovery_surface() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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
    let (addr, _hold) = start_companion(&upstream).await;

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
    let (addr, _hold) = start_companion(&upstream).await;

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
    let (addr, _hold) = start_companion(&upstream).await;

    // Each canonical local Host (the loopback bind makes the actual socket the
    // same; we override the Host header to prove the allowlist accepts the name).
    for host in [
        "dig.local",
        "dig.local:80",
        "localhost:9778",
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
    let (addr, _hold) = start_companion(&upstream).await;

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

    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port,
        dig_local: true, // attempt the privileged 127.0.0.2:80 bind (expected to fail in CI)
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };

    // Drive serve under the env lock, held for the whole test (the server reads
    // DIG_NODE_CACHE/config live per request — see EnvHold). Bound to `_hold` so it
    // outlives the spawned server below.
    let _hold = EnvHold(env_guard().lock_owned().await);
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_for_server = stop.clone();
    let server = {
        let tmp = std::env::temp_dir().join(format!("dig-node-dual-{}", std::process::id()));
        std::env::set_var("DIG_NODE_CACHE", &tmp);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        // Isolate the #501 control-token/paired-token state dir per test (see the note above).
        std::env::set_var("DIG_NODE_STATE_DIR", &tmp);
        // This test exercises the LISTENER bind fallback, not the peer network. Opt out of the
        // §14 peer-network bring-up (#213) so `serve_with_shutdown` stays hermetic here (no gossip
        // pool / DHT / relay reach). A dedicated test covers the peer-network wiring.
        std::env::set_var("DIG_PEER_NETWORK", "off");
        tokio::spawn(async move {
            dig_node_service::server::serve_with_shutdown(config, async move {
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

/// #288: with the DEFAULT config (no `DIG_NODE_HOST` override), `serve_with_shutdown`
/// must bind BOTH loopback families on the SAME port — `127.0.0.1` AND `[::1]` —
/// so `localhost` reaches the node regardless of which address family the
/// resolver returns first (Windows resolves `localhost` to `::1` first by
/// default, which made the node appear offline to such a client before this).
#[tokio::test]
async fn dual_stack_loopback_serves_both_ipv4_and_ipv6_on_the_same_port() {
    let (upstream, _calls) = start_mock_upstream().await;

    // Grab a free loopback port, then hand it to serve_with_shutdown explicitly so
    // we know where to probe (serve_with_shutdown binds config.bind_addr directly).
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free); // release it so the server can bind the same port

    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port,
        dig_local: false,         // skip the privileged 127.0.0.2:80 bind in tests
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()  // host: None → dual-stack default
    };

    let _hold = EnvHold(env_guard().lock_owned().await);
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_for_server = stop.clone();
    let server = {
        let tmp = std::env::temp_dir().join(format!("dig-node-dualstack-{}", std::process::id()));
        std::env::set_var("DIG_NODE_CACHE", &tmp);
        std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
        // Isolate the #501 control-token/paired-token state dir per test (see the note above).
        std::env::set_var("DIG_NODE_STATE_DIR", &tmp);
        std::env::set_var("DIG_PEER_NETWORK", "off");
        tokio::spawn(async move {
            dig_node_service::server::serve_with_shutdown(config, async move {
                stop_for_server.notified().await;
            })
            .await
        })
    };

    // Poll both addresses until each answers /health (the server starts async).
    async fn poll_health(url: &str) -> bool {
        for _ in 0..50 {
            if let Ok(r) = client().get(url).send().await {
                if r.status().is_success() {
                    return true;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        }
        false
    }

    let v4_url = format!("http://127.0.0.1:{port}/health");
    let v6_url = format!("http://[::1]:{port}/health");
    let v4_served = poll_health(&v4_url).await;
    let v6_served = poll_health(&v6_url).await;

    assert!(v4_served, "127.0.0.1 must serve /health");
    assert!(
        v6_served,
        "[::1] must ALSO serve /health on the same port (#288 dual-stack default)"
    );

    // Clean shutdown.
    stop.notify_waiters();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
}

#[tokio::test]
async fn cors_reflects_chrome_extension_origin() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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

/// #285: Chrome's Private Network Access blocks an extension/page request to a private IP
/// (127.0.0.1) unless the preflight response carries `Access-Control-Allow-Private-Network:
/// true` — this was the sole reason a running node was reported OFFLINE by the extension.
/// A preflight that itself carries `Access-Control-Request-Private-Network: true` (Chrome sends
/// this whenever the calling context is public/private and the target is more-private/local)
/// MUST get the allow header back.
#[tokio::test]
async fn cors_preflight_emits_pna_header_for_a_private_network_request() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("http://{addr}/"))
        .header("Origin", "chrome-extension://abcdefghijklmnop")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .header("Access-Control-Request-Private-Network", "true")
        .send()
        .await
        .unwrap();

    let pna = resp
        .headers()
        .get("access-control-allow-private-network")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(
        pna, "true",
        "a PNA preflight must get Access-Control-Allow-Private-Network: true, or Chrome \
         blocks the extension's request and reports the node offline (#285)"
    );
}

/// The PNA header is a narrowly-scoped ADDITION: a preflight that does NOT carry
/// `Access-Control-Request-Private-Network` (ordinary same-origin-family CORS, unaffected by
/// PNA) must NOT get the allow-private-network response header — proving the fix does not
/// change CORS behavior for non-PNA requests.
#[tokio::test]
async fn cors_preflight_omits_pna_header_without_a_private_network_request() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let resp = client()
        .request(reqwest::Method::OPTIONS, format!("http://{addr}/"))
        .header("Origin", "chrome-extension://abcdefghijklmnop")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .unwrap();

    assert!(
        resp.headers()
            .get("access-control-allow-private-network")
            .is_none(),
        "no PNA request header in the preflight → no PNA response header"
    );
    // The existing origin-reflection behavior is unchanged alongside the new header.
    let allow = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(allow, "chrome-extension://abcdefghijklmnop");
}

#[tokio::test]
async fn cache_get_config_reports_cap_and_used() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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
    let (addr, _hold) = start_companion(&upstream).await;

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

/// **Proves:** with no upstream configured — the default since #1997 — an unimplemented method is
/// answered locally with `-32601` and the node contacts nobody.
/// **Catches:** a reinstated default upstream, or a relay branch that runs on an empty upstream and
/// so posts every unrecognised method (with its params) to whatever an empty URL resolves to.
#[tokio::test]
async fn with_no_upstream_an_unimplemented_method_is_answered_locally_and_relayed_nowhere() {
    let (upstream, calls) = start_mock_upstream().await;
    // The upstream exists and is reachable, but is NOT configured on this node.
    let (addr, _hold) = start_companion("").await;

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

    assert_eq!(
        resp["error"]["code"],
        json!(-32601),
        "an unimplemented method answers method-not-found locally, not an upstream error: {resp}"
    );
    assert!(resp.get("result").is_none(), "no fabricated result: {resp}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "an unconfigured upstream must receive nothing; it saw {:?}",
        calls.lock().unwrap()
    );
    let _ = upstream;
}

/// **Proves:** `dig.health` is answered by this node about itself, with no upstream configured.
/// **Catches:** the #1997 regression in full — the node behind rpc.dig.net could not state its own
/// health without asking its own public address, which is what produced the relay loop.
#[tokio::test]
async fn dig_health_is_answered_locally_with_no_upstream() {
    let (_upstream, calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion("").await;

    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 3, "method": "dig.health", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["result"]["status"], json!("ok"), "{resp}");
    assert!(resp["result"]["version"].is_string(), "{resp}");
    // The `methods` array is the dig.health contract's capability summary.
    assert!(
        resp["result"]["methods"]
            .as_array()
            .is_some_and(|m| m.iter().any(|v| v == "dig.getContent")),
        "health carries the method catalogue: {resp}"
    );
    assert!(calls.lock().unwrap().is_empty(), "health asks nobody");
}

/// **Proves:** `dig.methods` self-describes locally and agrees with the catalogue, including the
/// two methods #1997 moved onto the shell.
/// **Catches:** adding the catalogue entries without adding the handlers (or vice versa), which
/// would make the node advertise a method it answers `-32601` for.
#[tokio::test]
async fn dig_methods_lists_the_catalogue_locally() {
    let (_upstream, calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion("").await;

    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 4, "method": "dig.methods", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let names: Vec<String> = resp["result"]["methods"]
        .as_array()
        .expect("methods array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    for expected in [
        "dig.getContent",
        "dig.health",
        "dig.methods",
        "rpc.discover",
    ] {
        assert!(names.contains(&expected.to_string()), "missing {expected}");
    }
    // dig.methods is on the same public allowlist as dig.health, so it carries the same duty.
    assert!(
        !names.iter().any(|n| n.starts_with("control.")),
        "dig.methods must not enumerate the control plane to anonymous callers: {names:?}"
    );
    assert!(calls.lock().unwrap().is_empty(), "methods asks nobody");
}

/// **Proves:** the runtime loop breaker end-to-end — when this node's OWN bring-up probe arrives
/// back at its dispatcher, passthrough switches off and unimplemented methods answer `-32601`
/// locally from then on, contacting the upstream no further.
/// **Catches:** the production outage shape exactly, and the two ways the guard could be wired to
/// nothing: a dispatcher that never checks the inbound id, and a relay branch that ignores the
/// disabled flag. A static address comparison cannot see this case at all — in production the
/// upstream was `https://rpc.dig.net`, self only by DNS.
#[tokio::test]
async fn a_returning_loop_probe_disables_passthrough() {
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, probe, _hold) = start_companion_probe(&upstream).await;

    // Before: an unimplemented method relays, and the upstream answers it.
    let before: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "dig.listCapsules", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        before["result"]["capsules"],
        json!(["passthrough-ok"]),
        "a configured, non-looping upstream still relays: {before}"
    );
    let relayed_before = calls.lock().unwrap().len();
    assert!(relayed_before > 0);

    // The node's own probe comes back to it — the observable proof that the upstream leads here.
    // This is byte-for-byte what `relay::probe_upstream_for_loop` put on the wire.
    let echoed: Value = client()
        .post(format!("http://{addr}/"))
        .json(&probe)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Still answered normally: it is an ordinary dig.health call.
    assert_eq!(echoed["result"]["status"], json!("ok"), "{echoed}");

    // After: the same unimplemented method is answered locally, and the upstream sees nothing more.
    let after: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "dig.listCapsules", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after["error"]["code"],
        json!(-32601),
        "a proven loop must stop the relay: {after}"
    );
    assert_eq!(
        calls.lock().unwrap().len(),
        relayed_before,
        "no further request may reach a looping upstream"
    );
}

/// **Proves:** a proven loop latches the ENGINE's upstream, not only the shell's passthrough guard.
/// **Catches:** the exact defect the security audit found on the first cut of this fix. The latch
/// lived only in `RelayGuard`, which gates ONE of three legs that reach an upstream; the two that
/// carry content (`dig.getContent`'s miss proxy and the `/s/*` Tier 3 fetch) read
/// `Node::has_upstream()` — a separate value the guard never touched. A node that had detected,
/// latched and LOGGED a loop would still recurse on any anonymous `dig.getContent` for content it
/// does not hold: the original outage on the more expensive path, behind a log line claiming it was
/// closed.
///
/// Asserted on the engine's own state rather than by driving a content read, deliberately. A read
/// for a fabricated `(store, root)` never reaches the proxy leg — it fails earlier, at
/// chain-anchored-root resolution — so a test written that way passes whether or not the latch is
/// wired, which is how the first version of this test came to prove nothing.
#[tokio::test]
async fn a_proven_loop_latches_the_engine_not_just_the_shell() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, probe, state, _hold) = start_companion_probe_state(&upstream).await;

    assert!(
        state.would_relay(),
        "precondition: the shell relays with a configured upstream"
    );
    assert!(
        state.engine_would_use_upstream(),
        "precondition: the engine would use the configured upstream"
    );

    // The node's own probe comes back to it — the upstream demonstrably leads here.
    let _: Value = client()
        .post(format!("http://{addr}/"))
        .json(&probe)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(
        !state.would_relay(),
        "the shell's passthrough must latch off"
    );
    assert!(
        !state.engine_would_use_upstream(),
        "the ENGINE must latch off too — otherwise dig.getContent still recurses"
    );
}

/// **Proves:** another node's probe is ordinary traffic and does not switch OUR relay off.
/// **Catches:** matching the probe on its prefix rather than the full random id — which would let
/// any caller disable a node's passthrough, and would break the legitimate case of this node being
/// somebody else's upstream (they probe us; we must keep relaying).
#[tokio::test]
async fn another_nodes_loop_probe_does_not_disable_our_relay() {
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, _probe, _hold) = start_companion_probe(&upstream).await;

    let foreign = json!({
        "jsonrpc": "2.0",
        "id": "dig-node-loop-probe:00112233445566778899aabbccddeeff",
        "method": "dig.health",
        "params": {}
    });
    let _: Value = client()
        .post(format!("http://{addr}/"))
        .json(&foreign)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let after: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 5, "method": "dig.listCapsules", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        after["result"]["capsules"],
        json!(["passthrough-ok"]),
        "a foreign probe must not disable our passthrough: {after}"
    );
    assert!(!calls.lock().unwrap().is_empty());
}

/// **Proves:** every method the catalogue classifies `served: "shell"` really HAS a shell handler —
/// none of them answers `-32601`.
/// **Catches:** the hole the `openrpc_drift_guard` leaves open. That guard only cross-checks `local`
/// and `passthrough` against the core read path; a `shell` entry could be advertised in
/// `rpc.discover`, `/health.methods` and `/.well-known/dig-node.json` with nothing implementing it,
/// and stay green. The shell is the only place that can answer this, so the assertion lives here
/// where the real router is running.
#[tokio::test]
async fn every_shell_classified_method_has_a_shell_handler() {
    let (addr, _hold) = start_companion("").await;

    let shell_methods: Vec<&str> = dig_node_service::meta::methods()
        .iter()
        .filter(|m| m.served == "shell")
        .map(|m| m.name)
        .collect();
    assert!(
        shell_methods.len() >= 4,
        "expected at least rpc.discover + dig.health + dig.methods + a pairing method, got {shell_methods:?}"
    );

    for name in shell_methods {
        let resp: Value = client()
            .post(format!("http://{addr}/"))
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": name, "params": {} }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // A shell method may legitimately reject EMPTY params (-32602) — pairing.request does.
        // What it may never do is claim the method does not exist.
        assert_ne!(
            resp["error"]["code"],
            json!(-32601),
            "catalogue marks {name} served=shell, but the shell returned method-not-found: {resp}"
        );
    }
}

/// **Proves:** the public `dig.health` body carries liveness only — never the node's cache path,
/// bound address, configured upstream, or commit.
/// **Catches:** a future re-widening of this result to `status_fields()`. `dig.health` is on
/// rpc.dig.net's public-read allowlist, so anything here is readable ANONYMOUSLY from the internet;
/// the absolute cache path alone discloses the OS account name. The operational body stays on the
/// loopback-only `GET /health`.
#[tokio::test]
async fn public_dig_health_does_not_leak_operational_detail() {
    let (addr, _hold) = start_companion("").await;

    let resp: Value = client()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "dig.health", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let result = resp["result"].as_object().expect("health result object");
    assert_eq!(result["status"], json!("ok"));
    assert!(result["version"].is_string());
    assert!(result["methods"].is_array());
    // An EXACT key set, not a deny-list of today's operational fields. A deny-list silently admits
    // the NEXT field somebody adds to the public body — `state_dir`, `identity`, `peers` — which is
    // the same class of leak this test exists to stop. Adding a key here must be a deliberate act
    // asserting that it is safe to publish to anonymous internet callers.
    let mut keys: Vec<&str> = result.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["methods", "status", "version"],
        "public dig.health exposes an unexpected field: {resp}"
    );

    // The METHOD LIST is part of the disclosure, not just the field set. `rpc.discover` is kept off
    // rpc.dig.net's public allowlist precisely because it "self-describes the whole surface
    // including control"; publishing that same catalogue through an ALLOWLISTED method would
    // re-open the hole through a different door.
    let methods: Vec<&str> = result["methods"]
        .as_array()
        .expect("methods array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    assert!(
        methods.contains(&"dig.getContent"),
        "the public list must still describe what a caller CAN call: {methods:?}"
    );
    let control: Vec<&&str> = methods
        .iter()
        .filter(|m| m.starts_with("control."))
        .collect();
    assert!(
        control.is_empty(),
        "public dig.health must not enumerate the control plane to anonymous callers: {control:?}"
    );
    // The loopback-only GET /health keeps the operational detail.
    let local: Value = client()
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        local["cache"]["dir"].is_string(),
        "GET /health keeps the operational body: {local}"
    );
}

#[tokio::test]
async fn non_object_body_returns_jsonrpc_error_not_transport_error() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        None, // no token
    )
    .await;

    // Canonical control-plane UNAUTHORIZED is -32030 (dig-rpc-types §10, SPEC §10);
    // -32020 is reserved for the onion-routing contract and MUST NOT be minted here.
    assert_eq!(resp["error"]["code"], json!(-32030));
    assert_eq!(resp["error"]["data"]["code"], json!("UNAUTHORIZED"));
    assert_eq!(resp["error"]["data"]["origin"], json!("shell"));
    assert!(resp.get("result").is_none(), "no result on a rejected call");
}

/// **Proves (#1654):** `cache.fetchAndCache` over the HTTP `POST /` surface is token-gated like
/// `control.*` — an untokened call is UNAUTHORIZED (-32030) and never reaches the landing dispatch,
/// while the master control token gets PAST the gate (the response is not the unauthorized error).
/// The method makes this node a durable DHT holder of the requested capsule, so it is not a public
/// read; the in-process FFI `cache.*` path (which never reaches this handler) stays open.
#[tokio::test]
async fn cache_fetch_and_cache_over_http_requires_the_control_token() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cache.fetchAndCache",
        "params": { "store_id": "31".repeat(32) }
    });

    // Untokened → rejected at the gate before any landing work.
    let rejected = post_rpc(&addr, body.clone(), None).await;
    assert_eq!(rejected["error"]["code"], json!(-32030));
    assert_eq!(rejected["error"]["data"]["code"], json!("UNAUTHORIZED"));
    assert!(
        rejected.get("result").is_none(),
        "no result on a rejected landing call"
    );

    // With the master control token → PAST the gate (whatever the dispatch then returns, it is not
    // the landing gate's UNAUTHORIZED).
    let authorized = post_rpc(&addr, body, Some(&token)).await;
    let is_unauthorized = authorized
        .get("error")
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("code"))
        .is_some_and(|c| c == &json!("UNAUTHORIZED"));
    assert!(
        !is_unauthorized,
        "a control-token call must clear the landing gate, got {authorized:?}"
    );
}

/// **Proves (dig_ecosystem#2108):** `cache.listCached` over the HTTP `POST /` surface is
/// control-token-gated like the holder-mutating `cache.*` methods — an untokened call is
/// UNAUTHORIZED (-32030) and NEVER leaks the cached-capsule inventory (`result.cached`), while the
/// master control token gets PAST the gate and the inventory is returned.
///
/// The method enumerates the operator's full cached-capsule inventory (storeId:rootHash, sizes, LRU
/// order), which deanonymizes what content the user has consumed; over the loopback HTTP surface a
/// cross-site page (DNS-rebinding / local-service attack) could otherwise POST here and read it. The
/// in-process FFI `cache.*` path (which never reaches this handler) stays open; anonymous public
/// CONTENT reads are unaffected.
#[tokio::test]
async fn cache_list_cached_over_http_requires_the_control_token() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "cache.listCached",
    });

    // Untokened → rejected at the gate before any enumeration; no inventory leaks.
    let rejected = post_rpc(&addr, body.clone(), None).await;
    assert_eq!(rejected["error"]["code"], json!(-32030));
    assert_eq!(rejected["error"]["data"]["code"], json!("UNAUTHORIZED"));
    assert!(
        rejected.get("result").is_none(),
        "no result on a rejected enumeration"
    );
    assert!(
        rejected.pointer("/result/cached").is_none(),
        "the cached-capsule inventory must NEVER be present on a rejected call, got {rejected:?}"
    );

    // With the master control token → PAST the gate: the inventory is returned.
    let authorized = post_rpc(&addr, body, Some(&token)).await;
    let is_unauthorized = authorized
        .get("error")
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("code"))
        .is_some_and(|c| c == &json!("UNAUTHORIZED"));
    assert!(
        !is_unauthorized,
        "a control-token call must clear the gate, got {authorized:?}"
    );
    assert!(
        authorized["result"]["cached"].is_array(),
        "an authorized call returns the cached array, got {authorized:?}"
    );
}

/// **Proves (dig_ecosystem#2108, WS parity — the #2032 lesson for READS):** `cache.listCached` is
/// NOT routable over the `/ws` transport, so gating it at the HTTP transport is sufficient and there
/// is no second, ungated path that leaks the inventory. The WS `ws_dispatch` fall-through routes an
/// unrecognized method to the wallet backend (`WalletBackend::dispatch`), whose match has NO `cache.*`
/// arm — so `cache.listCached` returns the backend's "unknown method" error, never the inventory.
#[tokio::test]
async fn cache_list_cached_is_not_routable_over_ws() {
    use tokio_tungstenite::tungstenite::Message;
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _backend, _hold) = start_companion_wallet(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("connect to /ws");
    let _ = next_ws_json(&mut ws).await; // drain the initial sync_status snapshot

    // Present the control token; even so, the WS transport has no route to the cache enumerator.
    ws.send(Message::Text(
        json!({ "id": "lc1", "type": "request", "method": "cache.listCached", "token": token })
            .to_string(),
    ))
    .await
    .unwrap();
    let resp = next_ws_json(&mut ws).await;
    assert_eq!(resp["id"], json!("lc1"));
    assert_eq!(resp["type"], json!("response"));
    assert_eq!(
        resp["ok"],
        json!(false),
        "cache.listCached is not a WS method, got {resp:?}"
    );
    assert!(
        resp.pointer("/result/cached").is_none(),
        "the cached-capsule inventory must NEVER be reachable over WS, got {resp:?}"
    );
}

/// **The money push AND the arrival cursor are behind the token, over the REAL server gate**
/// (dig_ecosystem#2376, dig_ecosystem#2548).
///
/// The unit test beside `is_open_control_read` pins the predicate; this pins what a caller actually
/// experiences, through `server::rpc`'s auth gate and the control dispatcher — the two can only
/// agree by accident otherwise.
///
/// The fixture varies ONE thing across three calls: which wallet method is asked, all untokened.
/// That is what makes it able to see the specific defect this guards. The obvious way to widen the
/// open-read set for three new methods is `method.starts_with("control.wallet.")`, which compiles,
/// passes every read-focused test, and silently makes the money push reachable with no token at
/// all. A test that only checked "the reads are open" would pass on that implementation.
///
/// The reads are asserted NOT to be `UNAUTHORIZED` rather than to succeed, because a node with no
/// chain source answers `WALLET_NO_CHAIN_SOURCE` — a different, honest answer that still proves the
/// call got PAST the gate.
#[tokio::test]
async fn the_push_and_the_arrival_cursor_are_gated_while_the_chain_reads_are_open() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let call = |method: &str, params: Value| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let address = "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";

    // The push, untokened: refused BY THE GATE, before any bundle is looked at.
    let pushed = post_rpc(
        &addr,
        call(
            "control.wallet.broadcast",
            json!({ "signed_bundle_hex": "deadbeef" }),
        ),
        None,
    )
    .await;
    assert_eq!(
        pushed["error"]["data"]["code"],
        json!("UNAUTHORIZED"),
        "an untokened push must be refused: got {pushed:?}"
    );

    // The same push WITH the token gets past the gate — so the refusal above was the token, not a
    // missing method. Without this, a node that had never registered the method would pass the
    // assertion above for entirely the wrong reason.
    let tokened = post_rpc(
        &addr,
        call(
            "control.wallet.broadcast",
            json!({ "signed_bundle_hex": "deadbeef" }),
        ),
        Some(&token),
    )
    .await;
    assert_ne!(
        tokened["error"]["data"]["code"],
        json!("METHOD_NOT_FOUND"),
        "control.wallet.broadcast must be registered: got {tokened:?}"
    );
    assert_ne!(
        tokened["error"]["data"]["code"],
        json!("UNAUTHORIZED"),
        "the token must actually authorize the push: got {tokened:?}"
    );

    // The arrival cursor, untokened: refused BY THE GATE. It is a chain read, which is exactly why
    // it was briefly served open -- but the caller supplies only a cursor, so the answer names this
    // node's OWN watched puzzle hashes and the receive history behind them. The open reads below
    // are the control: they take the same untokened path and are NOT refused, so this assertion
    // pins the arrival cursor specifically and not a gate that has closed over the whole wallet.
    let arrivals = post_rpc(
        &addr,
        call("control.wallet.arrivals", json!({ "after_seq": 0 })),
        None,
    )
    .await;
    assert_eq!(
        arrivals["error"]["data"]["code"],
        json!("UNAUTHORIZED"),
        "an untokened arrivals read must be refused: got {arrivals:?}"
    );

    // ...and WITH the token it gets past the gate to its own handler. Without this, the assertion
    // above would pass just as well against a node that never registered the method at all.
    let arrivals_tokened = post_rpc(
        &addr,
        call("control.wallet.arrivals", json!({ "after_seq": 0 })),
        Some(&token),
    )
    .await;
    for wrong in ["UNAUTHORIZED", "METHOD_NOT_FOUND", "INVALID_PARAMS"] {
        assert_ne!(
            arrivals_tokened["error"]["data"]["code"],
            json!(wrong),
            "a tokened arrivals read must reach its own handler, got {wrong}: {arrivals_tokened:?}"
        );
    }

    // The chain reads, untokened: they reach their handlers. Whatever they answer, it is not the
    // gate's refusal.
    for (method, params) in [
        (
            "control.wallet.coins",
            json!({ "address": address, "asset": "xch" }),
        ),
        (
            "control.wallet.coinById",
            json!({ "coin_id": "ab".repeat(32) }),
        ),
        ("control.wallet.peak", json!({})),
    ] {
        let response = post_rpc(&addr, call(method, params), None).await;
        assert_ne!(
            response["error"]["data"]["code"],
            json!("UNAUTHORIZED"),
            "{method} is an open read and must not need a token: got {response:?}"
        );
        assert_ne!(
            response["error"]["data"]["code"],
            json!("METHOD_NOT_FOUND"),
            "{method} must be registered: got {response:?}"
        );
        // ...and reached ITS OWN handler. Registration and routing are separate: mutating the
        // dispatch arm so `control.wallet.coins` runs `wallet_broadcast` leaves the method
        // registered and the gate open, so both assertions above still pass — but these params
        // carry no `signed_bundle_hex`, so the wrong handler answers INVALID_PARAMS. Each call
        // here sends params that are VALID for its own handler, which is what makes this
        // discriminating rather than decorative.
        assert_ne!(
            response["error"]["data"]["code"],
            json!("INVALID_PARAMS"),
            "{method} was routed to a handler that wanted different params: got {response:?}"
        );
    }
}

/// **Proves (dig_ecosystem#2501):** `control.wallet.syncStatus` and `control.peerCounts` are served
/// over the real gate, share the same `chia_peer_count` shape, and keep the unknown-peak sentinel.
///
/// **Why the count is INJECTED and not left at its default.** This harness runs
/// `enable_chain_sync: false`, so with no supervisor attached both methods answer `null` — and a
/// `null == null` comparison compares two unobservables. It passed with `peer_counts`' shared
/// read replaced by a literal `None`, which is exactly the divergence it claims to catch. The
/// seam below attaches a detached handle AND a fixed chain peer tier, both reporting a
/// distinctive count (no supervisor, no dialling), so a handler serving that field from anywhere
/// else answers a DIFFERENT number and the assertion fails.
///
/// Since dig_ecosystem#2806 there are TWO counts and they are different facts: `chia_peer_count`
/// is the Chia full nodes the node HOLDS (the transport's pool, which serves its chain reads) and
/// `subscription_peer_count` is the replica's single subscription session. Both are injected,
/// because leaving either at its default would put this test back in the `null == null` blind
/// spot it exists to escape.
///
/// The phase is asserted to be one of the four declared tokens rather than a specific one: this
/// node has no chain source, so whether it ever attaches a peer is not the property under test.
/// What IS pinned is that a peak-less replica reports `null` and never `0` — a zero here reads as
/// "synced to genesis", a claim about the chain that would be false.
/// **Proves (dig_ecosystem#2609):** every phase this node can emit is a token the PUBLISHED
/// contract declares.
///
/// This is the gate the #2609 incident was missing, and it is deliberately not a server test:
/// it compares two lists of values, so it holds for phases no fixture can reach.
///
/// What happened without it: dig-node grew `no_addresses_to_watch` while
/// `WalletSyncPhase` was a closed three-variant `Deserialize` enum with no `serde(other)`. The
/// only coupling was a hand-typed token list in the test above, and the change widened that list
/// alongside the node — so CI agreed with the bug. Every consumer on the older contract failed
/// the ENTIRE `WalletSyncStatusResult` parse, not one field, and rendered nothing at all: strictly
/// worse than the wrong-but-present word it replaced. dig-node referenced `WalletSyncPhase`
/// nowhere, so nothing else could have caught it.
///
/// Subset, not equality: the contract MAY declare a token this node has no way to reach yet
/// (a consumer can be ahead of a node), but the node MUST NOT emit one the contract has never
/// heard of. That asymmetry is the contract's own wording.
#[test]
fn every_phase_the_node_can_emit_is_declared_by_the_published_contract() {
    use dig_node_control_interface::results::WalletSyncPhase;

    let declared: Vec<&str> = WalletSyncPhase::ALL.iter().map(|p| p.as_wire()).collect();
    for phase in dig_wallet::sage::sync_supervisor::SyncPhase::ALL {
        assert!(
            declared.contains(&phase.as_wire()),
            "the node can emit {:?} ({:?}), which the published WalletSyncPhase does not declare. \
             A consumer deserializing it fails the WHOLE response, not one field. Publish the \
             token in dig-node-control-interface FIRST, then emit it. Contract declares {declared:?}",
            phase,
            phase.as_wire()
        );
    }
}

#[tokio::test]
async fn the_wallet_sync_status_and_peer_counts_agree_and_need_no_token() {
    // Distinctive: not 0, not 1, and not a count this fixture could reach by accident, so an
    // agreeing pair of answers can only have come from the one accessor that was given it.
    const OBSERVED_CHIA_PEERS: u64 = 7;

    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) =
        start_companion_full_with_chia_peers(&upstream, OBSERVED_CHIA_PEERS as u32).await;

    let call = |method: &str| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} });

    let sync = post_rpc(&addr, call("control.wallet.syncStatus"), None).await;
    assert!(
        sync["error"].is_null(),
        "syncStatus is an open read and must answer: got {sync:?}"
    );
    // Derived from the CONTRACT, never retyped. A hand-written literal list here is what let
    // dig-node ship a phase token the published `WalletSyncPhase` did not contain: the diff
    // WIDENED the literal alongside the node, so the assertion agreed with the bug and stayed
    // green, while every consumer deserializing the real enum failed the whole response
    // (dig_ecosystem#2609). `ALL` is the in-crate anchor the conformance KATs pin against, so a
    // node-side token that is not in the contract now turns this red automatically.
    let phase = sync["result"]["phase"].as_str().unwrap_or_default();
    let declared: Vec<&str> = dig_node_control_interface::results::WalletSyncPhase::ALL
        .iter()
        .map(|p| p.as_wire())
        .collect();
    assert!(
        declared.contains(&phase),
        "phase must be a token the published WalletSyncPhase declares; got {phase:?}, contract \
         declares {declared:?}"
    );
    assert!(
        sync["result"]["peak_height"].is_null() || sync["result"]["peak_height"].as_u64() > Some(0),
        "an unknown peak is null, never 0: got {sync:?}"
    );

    let counts = post_rpc(&addr, call("control.peerCounts"), None).await;
    assert!(
        counts["error"].is_null(),
        "peerCounts is an open read and must answer: got {counts:?}"
    );
    assert_eq!(
        sync["result"]["chia_peer_count"].as_u64(),
        Some(OBSERVED_CHIA_PEERS),
        "syncStatus must report the observation the node actually holds, not a default"
    );
    assert_eq!(
        counts["result"]["chia_peer_count"], sync["result"]["chia_peer_count"],
        "both methods report the SAME Chia peer observation; serving them from two sources is \
         how they start to disagree"
    );
    // dig_ecosystem#2570 -- the known-peer count is PRESENT on the wire even when this node cannot
    // observe it, so a client can tell "unknown" from "the node is too old to say". Asserting the
    // KEY EXISTS rather than only that its value is null is what separates those: a handler that
    // omitted the field entirely also reads as `Value::Null` through the index operator.
    assert!(
        counts["result"]
            .as_object()
            .expect("peerCounts answers with an object")
            .contains_key("known_dig_peer_count"),
        "peerCounts must always carry the known-peer key: got {counts:?}"
    );
    // This harness runs no peer network, so the count is UNOBSERVABLE. `null` here is the honest
    // answer and a `0` would be the bug -- it would claim the node consulted an address book that
    // does not exist.
    assert!(
        counts["result"]["known_dig_peer_count"].is_null(),
        "a node with no peer network cannot have looked at an address book, so the count is          unknown, never a measured zero: got {counts:?}"
    );
}

/// **Proves (dig_ecosystem#2392):** `control.wallet.coinById` validates its `coin_id` BEFORE any
/// chain work — ahead of the chain-source liveness check, and therefore ahead of the rate limiter
/// and the network call behind it.
///
/// **Why an `INVALID_PARAMS` assertion alone would NOT prove this.** `-32602` is also exactly what
/// a handler returns when it forwards a malformed id to the oracle, gets a rejection, and maps it
/// back to a param error. The code is the same; the byte that left the host is not. Since
/// `control.wallet.coinById` is an OPEN, token-less method whose argument is forwarded to a
/// third-party oracle, "refused before the network" is a security property, not a nicety: any local
/// process could otherwise push arbitrary content at that oracle through this node.
///
/// **The observable.** `wallet_coin_by_id` calls `coin_by_id`, which checks liveness first
/// (`WALLET_NO_CHAIN_SOURCE`), then the rate limiter, then the network. This test node has NO live
/// chain source, so the ladder is stopped at its first rung and the two calls below vary in exactly
/// one way — whether the `coin_id` is well-formed:
/// * malformed → `INVALID_PARAMS`, which can only come from the validator;
/// * well-formed → something ELSE, which can only come from the chain path.
///
/// The two answers DIFFERING is the proof. **Catches** moving the validation after the chain call:
/// the malformed id would then reach the liveness check too and answer identically to the
/// well-formed one, and this test fails. (Verified by performing that reorder locally and
/// confirming the failure.) A same-answer assertion is impossible to fake by narrowing the fixture,
/// because the control call is the one that must NOT be `INVALID_PARAMS`.
#[tokio::test]
async fn a_malformed_coin_id_is_refused_before_the_chain_is_ever_consulted() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let coin_by_id = |coin_id: Value| {
        json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "control.wallet.coinById",
            "params": { "coin_id": coin_id },
        })
    };

    // Malformed: 63 hex characters, one short of the contract's 64. Untokened, as a real caller
    // of this open read would be.
    let malformed = post_rpc(&addr, coin_by_id(json!("a".repeat(63))), None).await;
    assert_eq!(
        malformed["error"]["data"]["code"],
        json!("INVALID_PARAMS"),
        "a malformed coin id must be refused by the validator: got {malformed:?}"
    );

    // Well-formed, same shape of call, same node. This one DOES reach the chain path and fails
    // there, because the test node has no chain source.
    let well_formed = post_rpc(&addr, coin_by_id(json!("ab".repeat(32))), None).await;
    assert_ne!(
        well_formed["error"]["data"]["code"],
        json!("INVALID_PARAMS"),
        "a well-formed coin id must get PAST validation into the chain path: got {well_formed:?}"
    );
    assert_ne!(
        malformed["error"]["data"]["code"], well_formed["error"]["data"]["code"],
        "the malformed id must be answered by the validator and the well-formed one by the chain \
         path; identical answers mean validation ran AFTER the chain was consulted: \
         malformed={malformed:?} well_formed={well_formed:?}"
    );
}

/// **Proves (dig_ecosystem#2572):** both new chain reads validate their caller-supplied ids BEFORE
/// any chain work — ahead of the liveness check, the rate limiter and the network call.
///
/// The same design as `a_malformed_coin_id_is_refused_before_the_chain_is_ever_consulted`, and for
/// the same reason: an `INVALID_PARAMS` assertion ALONE would not prove it, because `-32602` is also
/// what a handler returns after forwarding a bad id to the oracle and mapping the rejection back.
/// The code is identical; the byte that left the host is not. These are OPEN, token-less methods
/// forwarding a caller-supplied string to a third party, so "refused before the network" is a
/// security property.
///
/// **The observable is that a malformed and a well-formed id get DIFFERENT answers.** This node has
/// no live chain source, so a well-formed id is stopped at the first rung of the chain ladder and
/// answers something other than `INVALID_PARAMS`. Move the validation after the chain call and both
/// ids reach the same rung, both answers become identical, and this fails.
///
/// `coinsByParent` is exercised through TWO malformed shapes — a bad `parent_coin_id` and a bad
/// `after_coin_id` — because they are validated on different fields, and a node that checked only
/// the parent would silently restart a caller's walk from the beginning on a corrupt cursor.
#[tokio::test]
async fn the_chain_reads_refuse_malformed_ids_before_the_chain_is_ever_consulted() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let call_with = |method: &'static str, params: Value| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let good = "ab".repeat(32);
    // 63 hex characters, one short of the contract's 64.
    let bad = "a".repeat(63);

    for (label, method, malformed, well_formed) in [
        (
            "coinSpend",
            "control.wallet.coinSpend",
            json!({ "coin_id": bad }),
            json!({ "coin_id": good }),
        ),
        (
            "coinsByParent/parent",
            "control.wallet.coinsByParent",
            json!({ "parent_coin_id": bad }),
            json!({ "parent_coin_id": good }),
        ),
        (
            "coinsByParent/cursor",
            "control.wallet.coinsByParent",
            json!({ "parent_coin_id": good, "after_coin_id": bad }),
            json!({ "parent_coin_id": good, "after_coin_id": good }),
        ),
    ] {
        // Untokened, as a real caller of an open read would be.
        let refused = post_rpc(&addr, call_with(method, malformed), None).await;
        assert_eq!(
            refused["error"]["data"]["code"],
            json!("INVALID_PARAMS"),
            "{label}: a malformed id must be refused by the validator: got {refused:?}"
        );

        let reached = post_rpc(&addr, call_with(method, well_formed), None).await;
        assert_ne!(
            reached["error"]["data"]["code"],
            json!("INVALID_PARAMS"),
            "{label}: a well-formed id must get PAST validation into the chain path: got {reached:?}"
        );
        assert_ne!(
            refused["error"]["data"]["code"], reached["error"]["data"]["code"],
            "{label}: identical answers mean validation ran AFTER the chain was consulted: \
             refused={refused:?} reached={reached:?}"
        );
    }
}

/// **Proves (dig_ecosystem#2572):** both new chain reads are OPEN over HTTP — reachable, routed to
/// their own handlers, and never answered `UNAUTHORIZED` to a token-less caller.
///
/// Three distinct silent failures are ruled out, because each looks like the others from outside:
/// * `UNAUTHORIZED` — the method was registered but left out of `is_open_control_read`. This is the
///   one that costs the most: the published contract declares both open, so a client following it
///   sends no token, and the two refusals demand OPPOSITE remedies (get a token vs upgrade the
///   node). A caller told `UNAUTHORIZED` goes hunting for a permissions fault that does not exist.
/// * `METHOD_NOT_FOUND` — the method was never added to `OWNED_CONTROL_METHODS`, so
///   `dispatch_control` silently delegated it to the embedded node, which answers `-32601`. That
///   omission does NOT fail to compile.
/// * `INVALID_PARAMS` from a MISSING required field — reachable only from this shell's own
///   validator, which proves `dispatch_owned` routed to the right arm rather than hitting its
///   `unreachable!()` or delegating. A listed method with a typo'd match arm compiles fine.
///
/// The well-formed call at the end asserts a DISJUNCTION, deliberately. This harness wires the real
/// lazy [`ChainTransport`], so whether that call reaches a chain depends on the machine's network —
/// pinning either outcome alone would make the test assert the environment rather than the node.
/// Both honest outcomes are accepted: a catalogued `WALLET_*` error, or a result carrying the
/// contract's declared members. What is ruled out is everything else — a panic, a hang, an
/// `INTERNAL_ERROR`, or a success whose body is missing the members a client decodes.
#[tokio::test]
async fn the_chain_reads_are_open_reachable_and_degrade_honestly() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let call_with = |method: &'static str, params: Value| json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let good = "ab".repeat(32);

    for (method, missing_field, well_formed, required_members) in [
        (
            "control.wallet.coinSpend",
            json!({}),
            json!({ "coin_id": good }),
            &["spend", "source", "synced", "peak_height"][..],
        ),
        (
            "control.wallet.coinsByParent",
            json!({}),
            json!({ "parent_coin_id": good }),
            &[
                "coins",
                "complete",
                "cursor",
                "source",
                "synced",
                "peak_height",
            ][..],
        ),
    ] {
        let empty = post_rpc(&addr, call_with(method, missing_field), None).await;
        assert_ne!(
            empty["error"]["data"]["code"],
            json!("UNAUTHORIZED"),
            "{method} is published as an OPEN read and must not demand a token: got {empty:?}"
        );
        assert_ne!(
            empty["error"]["data"]["code"],
            json!("METHOD_NOT_FOUND"),
            "{method} must be registered in OWNED_CONTROL_METHODS: got {empty:?}"
        );
        assert_eq!(
            empty["error"]["data"]["code"],
            json!("INVALID_PARAMS"),
            "a missing required id must be THIS handler's own rejection, which is only reachable \
             if dispatch_owned routed here: got {empty:?}"
        );

        let answered = post_rpc(&addr, call_with(method, well_formed), None).await;
        match answered.get("result") {
            Some(result) => {
                for member in required_members {
                    assert!(
                        result.get(member).is_some(),
                        "{method} answered a result missing the required `{member}` member, which \
                         a conforming client decodes as a hard failure: got {answered:?}"
                    );
                }
            }
            None => {
                let code = answered["error"]["data"]["code"]
                    .as_str()
                    .unwrap_or_default();
                assert!(
                    code.starts_with("WALLET_"),
                    "{method} must fail as a catalogued wallet error a caller can act on, \
                     got {answered:?}"
                );
            }
        }
    }
}

/// **Proves (dig_ecosystem#1985):** `control.peers.ping` is REACHABLE over the real HTTP control
/// surface — token-gated, registered, and routed to its own handler.
///
/// **Catches** the failure this ticket's first pass actually had: the ladder engine existed and
/// nothing could call it. Each assertion below rules out a distinct way that can silently recur:
/// * untokened → `UNAUTHORIZED`, so the dialer is never reachable without the control token;
/// * tokened → NOT `METHOD_NOT_FOUND`, so the method is registered in the dispatcher (an engine
///   with no route answers -32601 and looks identical to a missing feature);
/// * a missing `peer` → `INVALID_PARAMS` from THIS handler, which is only reachable if
///   `dispatch_owned` routed here rather than hitting its `unreachable!()` arm or delegating to the
///   node. A method listed in `OWNED_CONTROL_METHODS` with a typo'd `match` arm compiles fine and
///   fails only at runtime — this is what notices;
/// * a well-formed ping on a node with NO peer network → a deterministic `CONTROL_ERROR` saying so,
///   never a hang, a panic, or an invented ladder. The FFI/test node has no NAT runtime, so this is
///   the honest-degradation path every consumer hits before bring-up completes.
#[tokio::test]
async fn control_peers_ping_is_reachable_token_gated_and_degrades_honestly() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let ping = |params: Value| {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "control.peers.ping",
            "params": params,
        })
    };

    // Untokened: the gate refuses before the dialer is reached.
    let rejected = post_rpc(&addr, ping(json!({ "peer": "[::1]:9444" })), None).await;
    assert_eq!(rejected["error"]["data"]["code"], json!("UNAUTHORIZED"));

    // Tokened: resolved by this node, never the "no such method" answer an unwired engine gives.
    let missing_peer = post_rpc(&addr, ping(json!({})), Some(&token)).await;
    assert_ne!(
        missing_peer["error"]["data"]["code"],
        json!("METHOD_NOT_FOUND"),
        "control.peers.ping must be registered, got {missing_peer:?}"
    );
    // INVALID_PARAMS can only come from this handler's own `peer` check, so reaching it proves the
    // dispatcher routed here.
    assert_eq!(
        missing_peer["error"]["data"]["code"],
        json!("INVALID_PARAMS"),
        "a missing params.peer must be this handler's own rejection, got {missing_peer:?}"
    );

    // A well-formed ping on a node with no peer network: honest, deterministic, and not a ladder.
    let no_network = post_rpc(&addr, ping(json!({ "peer": "[::1]:9444" })), Some(&token)).await;
    assert_eq!(
        no_network["error"]["data"]["code"],
        json!("CONTROL_ERROR"),
        "no peer network must be a control error, got {no_network:?}"
    );
    assert!(
        no_network["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("no peer network")),
        "the message must name the missing precondition, got {no_network:?}"
    );
    assert!(
        no_network.get("result").is_none(),
        "no ladder result is invented when nothing could be dialed"
    );
}

/// **Proves (F1, #1946):** `chat.send` and `chat.poll` over the HTTP `POST /` surface are token-gated
/// like `control.*` — an untokened call is UNAUTHORIZED (-32030) and never reaches the chat dispatch,
/// so the node NEVER seals + BLS-signs a message as its own 0x0010 identity (`chat.send`) and NEVER
/// drains the inbound inbox (`chat.poll`) for an unauthorized local caller. The master control token
/// gets PAST the gate (whatever the dispatch returns next, it is not the gate's UNAUTHORIZED).
#[tokio::test]
async fn chat_methods_over_http_require_the_control_token() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    for method in ["chat.send", "chat.poll"] {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} });

        // Untokened → rejected at the gate BEFORE any seal/send or inbox drain runs.
        let rejected = post_rpc(&addr, body.clone(), None).await;
        assert_eq!(rejected["error"]["code"], json!(-32030), "{method}: -32030");
        assert_eq!(
            rejected["error"]["data"]["code"],
            json!("UNAUTHORIZED"),
            "{method}: UNAUTHORIZED"
        );
        assert!(
            rejected.get("result").is_none(),
            "{method}: no result — no seal/send, no inbox drain on a rejected call"
        );

        // Wrong token → same rejection (the side effect still never runs).
        let wrong = post_rpc(&addr, body.clone(), Some("the-wrong-token")).await;
        assert_eq!(
            wrong["error"]["data"]["code"],
            json!("UNAUTHORIZED"),
            "{method}: wrong token rejected"
        );

        // With the master control token → PAST the gate (whatever the dispatch then returns, it is
        // not the gate's UNAUTHORIZED).
        let authorized = post_rpc(&addr, body, Some(&token)).await;
        let is_unauthorized = authorized
            .get("error")
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("code"))
            .is_some_and(|c| c == &json!("UNAUTHORIZED"));
        assert!(
            !is_unauthorized,
            "{method}: a control-token call must clear the chat gate, got {authorized:?}"
        );
    }
}

#[tokio::test]
async fn control_method_with_wrong_token_is_rejected() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        Some("the-wrong-token"),
    )
    .await;
    assert_eq!(resp["error"]["data"]["code"], json!("UNAUTHORIZED"));
}

// --- #280: control-token PAIRING — the extension bootstraps a scoped credential ----
//
// End-to-end over the real HTTP server: an unpaired caller is rejected (-32030); it
// pairs (OPEN request/poll + operator approve with the MASTER token); the scoped
// token then authorizes a control MUTATION but NOT pairing administration; and a
// revoke immediately un-authorizes it.

/// A control MUTATION probe (`control.config.setUpstream`) for the pairing test —
/// reusable across the un-paired / paired / revoked assertions.
async fn setupstream_mutation(addr: &SocketAddr, token: Option<&str>) -> Value {
    post_rpc(
        addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.config.setUpstream",
                "params": { "upstream": "https://paired.example" } }),
        token,
    )
    .await
}

/// OPEN `pairing.poll` for the given id.
async fn poll_pairing(addr: &SocketAddr, pairing_id: &str) -> Value {
    post_rpc(
        addr,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "pairing.poll",
                "params": { "pairing_id": pairing_id } }),
        None,
    )
    .await
}

#[tokio::test]
async fn pairing_flow_grants_then_revokes_a_scoped_control_token() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, master, _hold) = start_companion_full(&upstream).await;

    // A control MUTATION with no token is rejected (the extension can't read the file).
    let denied = setupstream_mutation(&addr, None).await;
    assert_eq!(denied["error"]["data"]["code"], json!("UNAUTHORIZED"));

    // 1. OPEN pairing.request → a pairing_id + a compare-codes value.
    let req = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "pairing.request",
                "params": { "client_name": "DIG Chrome Extension" } }),
        None,
    )
    .await;
    let pairing_id = req["result"]["pairing_id"].as_str().unwrap().to_string();
    assert_eq!(req["result"]["pairing_code"].as_str().unwrap().len(), 6);

    // 2. OPEN pairing.poll → pending (not yet approved).
    assert_eq!(
        poll_pairing(&addr, &pairing_id).await["result"]["status"],
        json!("pending")
    );

    // 3. The operator approves with the MASTER token (the `dig-node pair` step).
    let approve = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 4, "method": "control.pairing.approve",
                "params": { "pairing_id": pairing_id } }),
        Some(&master),
    )
    .await;
    assert_eq!(approve["result"]["approved"], json!(true));
    let token_id = approve["result"]["token_id"].as_str().unwrap().to_string();

    // 4. The extension polls again → approved + its scoped token (delivered once).
    let approved = poll_pairing(&addr, &pairing_id).await;
    assert_eq!(approved["result"]["status"], json!("approved"));
    let scoped = approved["result"]["token"].as_str().unwrap().to_string();
    assert_eq!(scoped.len(), 64);

    // 5. The scoped token AUTHORIZES a control mutation.
    let ok = setupstream_mutation(&addr, Some(&scoped)).await;
    assert_eq!(ok["result"]["upstream"], json!("https://paired.example"));

    // 6. But the scoped token CANNOT administer pairings (master-only).
    let admin = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 6, "method": "control.pairing.list" }),
        Some(&scoped),
    )
    .await;
    assert_eq!(admin["error"]["data"]["code"], json!("UNAUTHORIZED"));

    // 7. The operator revokes it (master token) → the scoped token stops working.
    let revoke = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "control.pairing.revoke",
                "params": { "token_id": token_id } }),
        Some(&master),
    )
    .await;
    assert_eq!(revoke["result"]["revoked"], json!(true));

    let after_revoke = setupstream_mutation(&addr, Some(&scoped)).await;
    assert_eq!(after_revoke["error"]["data"]["code"], json!("UNAUTHORIZED"));
}

#[tokio::test]
async fn control_status_with_token_returns_rich_status() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

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
    assert_eq!(r["version"], json!(dig_node_service::VERSION));
    assert!(r["uptime_secs"].is_u64());
    assert!(r["cache"]["cap_bytes"].is_u64());
    assert!(r["hosted_store_count"].is_u64());
    assert!(r["pinned_store_count"].is_u64());
    assert!(r["sync"]["available"].is_boolean());
}

#[tokio::test]
async fn control_token_via_params_is_also_accepted() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.sync.status" }),
        Some(&token),
    )
    .await;
    // Whole-store sync leads with the ANONYMOUS chunked capsule download, so availability no
    // longer depends on a §21 identity; the identity's presence is reported on its own field
    // (#1886). `whole_store_trigger_supported` is now true because a store id alone is enough.
    assert_eq!(resp["result"]["available"], json!(true));
    assert_eq!(
        resp["result"]["method"],
        json!("chunked-capsule-download-with-section-21-clone-fallback")
    );
    assert!(resp["result"]["identity_loaded"].is_boolean());
    assert_eq!(resp["result"]["whole_store_trigger_supported"], json!(true));
    assert!(resp["result"]["pinned_total"].is_u64());
}

// --- #515: DIG auto-update beacon proxy (`control.updater.*`) ----------------------
//
// A THIN passthrough to `dig-updater`'s own status file + CLI (`crate::updater`'s own
// unit tests cover the arg-building/output-parsing logic in isolation); these prove the
// FULL wire path — HTTP -> the control-token gate -> dispatch -> the proxy -> a real
// child-process spawn (the `fake_beacon_cli` fixture, `tests/fixtures/fake_beacon_cli.rs`)
// -> the response back over HTTP.

/// `control.updater.*` requires the SAME control token as every other `control.*` method —
/// a read (`status`) and a mutation (`checkNow`) are both rejected without one.
#[tokio::test]
async fn control_updater_methods_without_token_are_rejected() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    for method in ["control.updater.status", "control.updater.checkNow"] {
        let resp = post_rpc(
            &addr,
            json!({ "jsonrpc": "2.0", "id": 1, "method": method }),
            None,
        )
        .await;
        assert_eq!(
            resp["error"]["data"]["code"],
            json!("UNAUTHORIZED"),
            "{method} must require the control token"
        );
    }
}

/// The full status round trip (absent -> present, read directly off disk) PLUS a real
/// mutation (`setChannel`, spawned against the `fake_beacon_cli` fixture) — end to end
/// over the real HTTP server, with the control token.
#[tokio::test]
async fn control_updater_status_and_mutation_wired_over_http() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    // -- status: absent (no beacon installed on this runner) is a normal, non-error result.
    let status_dir = std::env::temp_dir().join(format!(
        "dig-node-updater-e2e-status-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&status_dir);
    std::env::set_var("DIG_UPDATER_STATUS_DIR", &status_dir);

    let absent = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.updater.status" }),
        Some(&token),
    )
    .await;
    assert_eq!(absent["result"]["installed"], json!(false));

    // -- status: present is forwarded verbatim.
    std::fs::create_dir_all(&status_dir).unwrap();
    let body = json!({ "schema": 1, "version": "0.6.0", "channel": "alpha", "paused": false });
    std::fs::write(
        status_dir.join("status.json"),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();

    let present = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "control.updater.status" }),
        Some(&token),
    )
    .await;
    assert_eq!(present["result"]["installed"], json!(true));
    assert_eq!(present["result"]["status"], body);

    // -- a real mutation, spawned against the fake CLI fixture — proves setChannel walks
    // the whole path (auth -> dispatch -> a real child process -> its JSON stdout) rather
    // than being tested only in isolation (`crate::updater`'s own unit tests).
    std::env::set_var("DIG_UPDATER_BIN", env!("CARGO_BIN_EXE_fake_beacon_cli"));
    std::env::set_var(
        "FAKE_UPDATER_STDOUT",
        r#"{"command":"channel","channel":"alpha"}"#,
    );
    std::env::set_var("FAKE_UPDATER_EXIT_CODE", "0");

    let set_channel = post_rpc(
        &addr,
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "control.updater.setChannel",
            "params": { "channel": "alpha" }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(set_channel["result"]["channel"], json!("alpha"));

    let _ = std::fs::remove_dir_all(&status_dir);
    for var in [
        "DIG_UPDATER_STATUS_DIR",
        "DIG_UPDATER_BIN",
        "FAKE_UPDATER_STDOUT",
        "FAKE_UPDATER_EXIT_CODE",
    ] {
        std::env::remove_var(var);
    }
}

#[tokio::test]
async fn control_unknown_method_is_method_not_found() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    // A control method the shell does not own is delegated to the node's own control
    // surface (control.peerStatus / control.subscribe / …); a genuinely unknown one
    // falls through the node and returns -32601 (method not found). The shell does NOT
    // relay control methods to the upstream, so this is answered locally.
    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.does.not.exist" }),
        Some(&token),
    )
    .await;
    assert_eq!(resp["error"]["code"], json!(-32601));
}

#[tokio::test]
async fn control_methods_are_not_passed_through_to_upstream() {
    // A control.* method without a token must be rejected by the SHELL, never
    // relayed to the upstream (it is not a read method).
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

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
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

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

// ===========================================================================
// #130 cross-repo node-control CONTRACT conformance.
//
// The dig-chrome-extension node-control UI is written against THIS interface
// (SYSTEM.md → "dig-node control interface" is the source of truth). These tests
// pin the exact field names the extension consumes so a one-sided dig-node change
// can never silently break the extension's node-status panel. If any assertion
// here fails, the extension's `src/lib/dig-control.ts` reader breaks in lockstep —
// change BOTH sides in one coordinated unit (cross-repo-contracts skill).
// ===========================================================================

/// The `control.status` result MUST carry the exact snake_case fields the
/// extension's `ControlStatusPayload` + `controlPanelViewModel` read
/// (`dig-chrome-extension/src/lib/dig-control.ts`): `hosted_store_count`,
/// `pinned_store_count`, `cached_capsule_count`, `cache.used_bytes`,
/// `sync.available`, `upstream`. A rename here shows the extension `'—'` for every
/// stat, so this is the contract pin.
#[tokio::test]
async fn control_status_emits_the_extension_consumed_field_names() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, token, _hold) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        Some(&token),
    )
    .await;
    let r = &resp["result"];
    // Store/capsule counters the ControlTab renders.
    assert!(
        r["hosted_store_count"].is_u64(),
        "extension reads status.hosted_store_count"
    );
    assert!(
        r["pinned_store_count"].is_u64(),
        "extension reads status.pinned_store_count (hosted-stores fallback)"
    );
    assert!(
        r["cached_capsule_count"].is_u64(),
        "extension reads status.cached_capsule_count"
    );
    // Nested cache.used_bytes (the panel's cache-usage line).
    assert!(
        r["cache"]["used_bytes"].is_u64(),
        "extension reads status.cache.used_bytes"
    );
    // Nested sync.available (the panel's sync toggle state).
    assert!(
        r["sync"]["available"].is_boolean(),
        "extension reads status.sync.available"
    );
    // Upstream line.
    assert!(r["upstream"].is_string(), "extension reads status.upstream");
}

/// A `control.*` call the extension makes WITHOUT the local token (a sandboxed MV3
/// extension cannot read `<config_dir>/control-token`) MUST be answered with the
/// canonical `UNAUTHORIZED` code `-32030` and machine `data.code` `"UNAUTHORIZED"` —
/// the exact value the extension's `isUnauthorizedControlResult` / `CONTROL_ERR`
/// branch on to fall back to the "manage in the DIG Browser" affordance.
#[tokio::test]
async fn control_unauthorized_matches_the_extension_error_contract() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _hold) = start_companion_full(&upstream).await;

    let resp = post_rpc(
        &addr,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "control.status" }),
        None,
    )
    .await;
    assert_eq!(resp["error"]["code"], json!(-32030));
    assert_eq!(resp["error"]["data"]["code"], json!("UNAUTHORIZED"));
}

/// `GET /health` is the OPEN status probe the extension's node-detection + status
/// UI relies on (no control token). It MUST carry the stable probe contract fields
/// (`status`, `version`, `mode`, `upstream`, `cache`) so a consumer can display node
/// liveness + identity without the token-gated control plane.
#[tokio::test]
async fn health_carries_the_open_status_probe_contract() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

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
    assert!(resp["version"].is_string());
    assert_eq!(resp["upstream"], json!(upstream));
    assert!(resp["cache"]["used_bytes"].is_u64());
    assert!(resp["cache"]["cap_bytes"].is_u64());
}

// -- §14 autonomous-sync bring-up (#213) -------------------------------------------
//
// The OS-service bring-up (`serve_with_shutdown`) must start the L7 peer network — the
// connected pool + DHT + the chain-watch/gap-fill loop — unless the operator opts out
// with `DIG_PEER_NETWORK=off`. Before #213 it never did (the §14 loop was dead code:
// `spawn_peer_network` had zero call sites), so these drive the real serve path and
// observe the peer network via `control.peerStatus`. Hermetic: relay OFF (no live
// network), an ephemeral peer port, no privileged `:80` bind, an isolated cache dir.

/// Drive `serve_with_shutdown` on a free loopback port with the `DIG_PEER_NETWORK` gate
/// set to `peer_network` (`"on"`/`"off"`) and a hermetic peer-network env. Returns the
/// bound port, a shutdown `Notify`, the server task handle, the control token, and the
/// held env guard (kept alive for the whole test). Polls until `/health` serves.
async fn start_serving_node(
    peer_network: &str,
) -> (
    u16,
    std::sync::Arc<tokio::sync::Notify>,
    tokio::task::JoinHandle<std::io::Result<()>>,
    String,
    EnvHold,
) {
    let (upstream, _calls) = start_mock_upstream().await;

    // Grab then release a free loopback port so serve binds a known address.
    let free = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);

    let config = dig_node_service::Config {
        upstream,
        port,
        dig_local: false,         // skip the privileged 127.0.0.2:80 bind in tests
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };

    let hold = EnvHold(env_guard().lock_owned().await);
    let unique = TEST_DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "dig-node-peernet-{}-{}",
        std::process::id(),
        unique
    ));
    let cache = base.join("cache");
    std::fs::create_dir_all(&cache).expect("create test cache dir");
    std::env::set_var("DIG_NODE_CACHE", &cache);
    std::env::set_var("DIG_NODE_CACHE_CAP", "67108864");
    // Hermetic peer network: no relay/introducer reach, ephemeral mTLS port.
    std::env::set_var("DIG_RELAY_URL", "off");
    std::env::set_var("DIG_PEER_PORT", "0");
    std::env::set_var("DIG_PEER_NETWORK", peer_network);

    // The token the bring-up writes (read from disk exactly as a same-host controller would).
    let token = dig_node_service::control::load_or_create_token().unwrap();

    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let stop_for_server = stop.clone();
    let server = tokio::spawn(async move {
        dig_node_service::server::serve_with_shutdown(config, async move {
            stop_for_server.notified().await;
        })
        .await
    });

    let url = format!("http://127.0.0.1:{port}/health");
    let mut served = false;
    for _ in 0..100 {
        if let Ok(r) = client().get(&url).send().await {
            if r.status().is_success() {
                served = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    assert!(served, "the node must serve /health after bring-up");

    (port, stop, server, token, hold)
}

/// Call `control.peerStatus` with the control token and return the JSON-RPC response.
async fn peer_status(port: u16, token: &str) -> Value {
    client()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("X-Dig-Control-Token", token)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "control.peerStatus" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Clear the peer-network env this test set (held under the env lock).
fn clear_peernet_env() {
    std::env::remove_var("DIG_PEER_NETWORK");
    std::env::remove_var("DIG_RELAY_URL");
    std::env::remove_var("DIG_PEER_PORT");
}

#[tokio::test]
async fn serve_with_gate_on_starts_the_peer_network_and_still_serves_reads() {
    // #213 (RED before the wiring): `serve_with_shutdown` built the node + control token
    // ONLY and never called `spawn_peer_network`, so `control.peerStatus.running` stayed
    // false forever — the §14 autonomous-sync loop was dead code. With the gate ON
    // (default) the service bring-up MUST start the peer network (running:true) while the
    // HTTP read path keeps serving.
    let (port, stop, server, token, _hold) = start_serving_node("on").await;

    // Poll control.peerStatus until the peer network reports running (set as soon as the
    // bring-up derives the node identity, before the pool/DHT come up).
    let mut running = false;
    for _ in 0..100 {
        if peer_status(port, &token).await["result"]["running"] == json!(true) {
            running = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    assert!(
        running,
        "gate ON → the service bring-up must start the peer network (running:true)"
    );

    // Reads still serve while the peer network runs.
    let health: Value = client()
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], json!("ok"));

    stop.notify_waiters();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    clear_peernet_env();
}

#[tokio::test]
async fn serve_with_gate_off_disables_the_peer_network_but_still_serves_reads() {
    // AC3: DIG_PEER_NETWORK=off cleanly disables the §14 peer network — the node comes up
    // serving reads and control.peerStatus reports NOT running (no pool/DHT/chain-watch).
    let (port, stop, server, token, _hold) = start_serving_node("off").await;

    let health: Value = client()
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], json!("ok"));

    // Give any (erroneously-spawned) bring-up a moment, then assert it is NOT running.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let resp = peer_status(port, &token).await;
    assert_eq!(
        resp["result"]["running"],
        json!(false),
        "gate OFF → the peer network must not run"
    );

    stop.notify_waiters();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    clear_peernet_env();
}

// --- #239: `GET /ws/status` — the WS liveness/status endpoint ----------------------
//
// The extension's SW holds this socket open as its liveness signal for the local
// dig-node; these tests exercise it end-to-end (real TCP, real WS frames) exactly
// like the HTTP tests above do for `/health` — the pattern is the SSE `GET /events`
// on dig-wallet's transport (design A.9), adapted to a real WebSocket here because
// the extension needs a socket whose OPEN/CLOSE state itself is the liveness
// signal it holds in its service worker (rather than polling an SSE reconnect).

/// **Proves:** on connect, `/ws/status` immediately sends a `status` snapshot with
/// the same unauthenticated fields `/health` exposes (service/version/mode/addr/
/// upstream/cache/sync) — issue #239's "send the current status snapshot".
#[tokio::test]
async fn ws_status_sends_snapshot_on_connect() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/status"))
        .await
        .expect("connect to /ws/status");

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for the snapshot")
        .expect("stream ended before a snapshot arrived")
        .expect("ws error");
    let text = msg.into_text().expect("snapshot is a text frame");
    let v: Value = serde_json::from_str(&text).expect("snapshot is valid JSON");

    assert_eq!(v["type"], json!("status"));
    assert_eq!(v["service"], json!("dig-node"));
    assert!(v["version"].is_string());
    assert_eq!(v["mode"], json!("local-node"));
    // `addr` is the CONFIGURED bind address string (here `127.0.0.1:0`, since the test
    // config binds an ephemeral port — the same shape `/health` already reports), not
    // necessarily the actual bound ephemeral port `addr` (the SocketAddr) resolved to.
    assert!(v["addr"].is_string());
    assert!(v["cache"]["cap_bytes"].is_number());
    assert_eq!(v["sync"]["available"], json!(true));
}

/// **Proves:** after the initial snapshot, the server pushes a periodic `heartbeat`
/// (carrying `ts` + a refreshed status) — the liveness pulse a client uses to
/// notice a stalled/half-open connection (issue #239 acceptance #2).
#[tokio::test]
async fn ws_status_sends_heartbeat_after_snapshot() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/status"))
        .await
        .expect("connect to /ws/status");

    // Drain the snapshot first.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for snapshot")
        .expect("stream ended before snapshot")
        .expect("ws error");

    // Then a heartbeat within one interval + margin.
    let msg = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
        .await
        .expect("timed out waiting for the heartbeat")
        .expect("stream ended before a heartbeat arrived")
        .expect("ws error");
    let text = msg.into_text().expect("heartbeat is a text frame");
    let v: Value = serde_json::from_str(&text).expect("heartbeat is valid JSON");
    assert_eq!(v["type"], json!("heartbeat"));
    assert!(v["ts"].as_u64().is_some());
    assert_eq!(v["service"], json!("dig-node"));
}

/// **Proves:** a client-initiated close is handled cleanly — the server's close
/// handshake (echoing `Message::Close`, see `ws_status_session`) completes
/// without the client hanging or erroring on the close itself, and a FOLLOW-UP
/// connection to the same endpoint still works — i.e. the server didn't wedge
/// its listener/router state from the prior connection's teardown.
#[tokio::test]
async fn ws_status_closes_cleanly_on_client_close() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/status"))
        .await
        .expect("connect to /ws/status");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next()).await;
    ws.close(None)
        .await
        .expect("client close must not hang/error");

    // A second, independent connection right after proves the server is still healthy
    // (didn't panic/wedge while tearing down the first).
    let (mut ws2, _resp2) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws/status"))
        .await
        .expect("connect to /ws/status after a prior client close");
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws2.next())
        .await
        .expect("timeout waiting for the second connection's snapshot")
        .expect("stream ended before a snapshot arrived")
        .expect("ws error");
    assert!(msg.into_text().unwrap().contains("\"type\":\"status\""));
}

/// **Proves:** the `Origin` header is validated with the SAME allowlist CORS
/// reflects (#91's local-origin policy) — a disallowed Origin never reaches the
/// upgrade. Unlike `fetch`, a WS handshake is not blocked by the browser based on
/// CORS response headers, so the server itself must reject it (CSWSH defense).
#[tokio::test]
async fn ws_status_rejects_a_disallowed_origin() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let mut request = format!("ws://{addr}/ws/status")
        .into_client_request()
        .expect("build client request");
    request
        .headers_mut()
        .insert("origin", "https://evil.example.com".parse().unwrap());

    let result = tokio_tungstenite::connect_async(request).await;
    match result {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 403);
        }
        other => panic!("expected an HTTP 403 rejection, got {other:?}"),
    }
}

/// **Proves:** the real caller's origin — `chrome-extension://…` — is accepted,
/// the same allowlist that already permits it for CORS (#91).
#[tokio::test]
async fn ws_status_accepts_a_chrome_extension_origin() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _hold) = start_companion(&upstream).await;

    let mut request = format!("ws://{addr}/ws/status")
        .into_client_request()
        .expect("build client request");
    request.headers_mut().insert(
        "origin",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
            .parse()
            .unwrap(),
    );

    let (mut ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("chrome-extension origin must be accepted");
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
        .await
        .expect("timeout")
        .expect("stream ended")
        .expect("ws error");
    assert!(msg.into_text().unwrap().contains("\"type\":\"status\""));
}

// --- #368: the served Sage-parity wallet RPC surface (POST /{method}) ----------------
//
// The shipped node now BUILDS + SERVES the node-custodied wallet backend on the
// extension-reachable loopback. These prove the extension's `node-wallet` target
// (`POST {base}/{method}`) is answered by the installed binary (not relayed upstream),
// and that custody/mutation methods are paired-token gated.

/// **Proves (#368):** the running node answers the core Sage reads (`get_version`,
/// `get_sync_status`, `get_coins`) over `POST /{method}` on the loopback — not a `404`
/// and not relayed to the upstream.
#[tokio::test]
async fn wallet_rpc_answers_core_reads_on_loopback() {
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, _token, _backend, _hold) = start_companion_wallet(&upstream).await;

    for (method, body) in [
        ("get_version", "{}"),
        ("get_sync_status", "{}"),
        ("get_coins", r#"{"offset":0,"limit":10}"#),
    ] {
        let resp = client()
            .post(format!("http://{addr}/{method}"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{method} must be answered by the node");
        let v: Value = resp.json().await.unwrap();
        if method == "get_version" {
            assert!(v["version"].is_string(), "get_version returns a version");
        }
    }
    // None of the wallet reads were relayed to the upstream DIG RPC.
    assert!(
        calls.lock().unwrap().is_empty(),
        "wallet reads must not relay upstream"
    );
}

/// **Proves (#368 security):** an unauthenticated wallet MUTATION (`send_xch`) over the
/// served surface is rejected `401` — a spend is never served without the paired/control
/// token, and never relayed upstream.
#[tokio::test]
async fn wallet_rpc_rejects_unauthorized_mutation() {
    let (upstream, calls) = start_mock_upstream().await;
    let (addr, _token, _backend, _hold) = start_companion_wallet(&upstream).await;

    let resp = client()
        .post(format!("http://{addr}/send_xch"))
        .header("content-type", "application/json")
        .body(r#"{"address":"xch1xxxx","amount":1,"fee":0}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "an unauthorized spend must be 401");
    assert!(
        calls.lock().unwrap().is_empty(),
        "a spend must never relay upstream"
    );
}

// --- #369: the bidirectional WS wallet+control transport (GET /ws) -------------------

/// Read the next TEXT frame as JSON within a timeout, skipping transport ping/pong/close.
async fn next_ws_json<S>(ws: &mut S) -> Value
where
    S: futures_util::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for a WS frame")
            .expect("stream ended")
            .expect("ws error");
        if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
            return serde_json::from_str(&t).expect("frame is valid JSON");
        }
        // Skip ping/pong/binary/close keepalives.
    }
}

/// **Proves (#369):** on connect `/ws` pushes the initial `sync_status`, and a correlated
/// `request` (a wallet read) gets a `response` frame echoing its `id`.
#[tokio::test]
async fn ws_wallet_pushes_status_and_correlates_a_request() {
    use tokio_tungstenite::tungstenite::Message;
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _backend, _hold) = start_companion_wallet(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("connect to /ws");

    // Initial push: a sync_status frame (fresh DB => syncing).
    let snap = next_ws_json(&mut ws).await;
    assert_eq!(snap["type"], json!("sync_status"));
    assert_eq!(snap["state"], json!("syncing"));

    // A correlated wallet read.
    ws.send(Message::Text(
        r#"{"id":"req-1","type":"request","method":"get_version","params":{}}"#.into(),
    ))
    .await
    .unwrap();
    let resp = next_ws_json(&mut ws).await;
    assert_eq!(resp["id"], json!("req-1"));
    assert_eq!(resp["type"], json!("response"));
    assert_eq!(resp["ok"], json!(true));
    assert!(resp["result"]["version"].is_string());
}

/// **Proves (#369 push):** the node forwards sync EVENTS to the subscribed socket and pushes
/// a `sync_status` transition to `disconnected` when the sync loop stops.
#[tokio::test]
async fn ws_wallet_pushes_events_and_disconnected_on_stop() {
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, backend, _hold) = start_companion_wallet(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("connect to /ws");

    // Drain the initial sync_status snapshot (subscription is now active).
    let snap = next_ws_json(&mut ws).await;
    assert_eq!(snap["type"], json!("sync_status"));

    // A coin-state change is forwarded as an event frame.
    backend.events().publish(SyncEvent::CoinState);
    let ev = next_ws_json(&mut ws).await;
    assert_eq!(ev["type"], json!("event"));
    assert_eq!(ev["event"]["type"], json!("coin_state"));

    // Stop => the event is forwarded AND a disconnected sync_status transition is pushed.
    backend.events().publish(SyncEvent::Stop);
    let ev = next_ws_json(&mut ws).await;
    assert_eq!(ev["type"], json!("event"));
    assert_eq!(ev["event"]["type"], json!("stop"));
    let status = next_ws_json(&mut ws).await;
    assert_eq!(status["type"], json!("sync_status"));
    assert_eq!(status["state"], json!("disconnected"));
}

/// **Proves (#369 authz):** an unauthorized wallet MUTATION and an unauthorized `control.*`
/// call over the WS are both rejected (`ok:false`), while a wallet READ is served.
#[tokio::test]
async fn ws_wallet_rejects_unauthorized_mutation_and_control() {
    use tokio_tungstenite::tungstenite::Message;
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _backend, _hold) = start_companion_wallet(&upstream).await;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("connect to /ws");
    let _ = next_ws_json(&mut ws).await; // drain initial sync_status

    // Unauthorized mutation (no token).
    ws.send(Message::Text(
        r#"{"id":"m1","type":"request","method":"send_xch","params":{"address":"xch1x","amount":1,"fee":0}}"#.into(),
    ))
    .await
    .unwrap();
    let resp = next_ws_json(&mut ws).await;
    assert_eq!(resp["id"], json!("m1"));
    assert_eq!(resp["ok"], json!(false), "unauthorized mutation rejected");

    // Unauthorized control.* (no token).
    ws.send(Message::Text(
        r#"{"id":"c1","type":"request","method":"control.status","params":{}}"#.into(),
    ))
    .await
    .unwrap();
    let resp = next_ws_json(&mut ws).await;
    assert_eq!(resp["id"], json!("c1"));
    assert_eq!(resp["ok"], json!(false), "unauthorized control.* rejected");
}

/// **Proves (#369 CSWSH):** `/ws` validates the `Origin` with the same local-origin allowlist —
/// a disallowed browser Origin is rejected at the handshake (`403`), never upgraded.
#[tokio::test]
async fn ws_wallet_rejects_a_disallowed_origin() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let (upstream, _calls) = start_mock_upstream().await;
    let (addr, _token, _backend, _hold) = start_companion_wallet(&upstream).await;

    let mut request = format!("ws://{addr}/ws")
        .into_client_request()
        .expect("build client request");
    request
        .headers_mut()
        .insert("origin", "https://evil.example.com".parse().unwrap());

    match tokio_tungstenite::connect_async(request).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), 403);
        }
        other => panic!("expected an HTTP 403 rejection, got {other:?}"),
    }
}
