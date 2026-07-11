//! End-to-end tests for the LOCAL plaintext content-serve surface (#289): spin up the service's
//! axum app in-process against a REAL compiled public `.dig` module seeded into the node's cache, and
//! drive `GET /s/<storeId>:<root>/<path>` over HTTP. Prove the node decrypts server-side and returns
//! the real website (not ciphertext), with the store-root `<base>`/`<meta referrer>` injected into
//! HTML, the `X-Dig-*` provenance headers set, the SPA-vs-404 miss decision applied, and a
//! root-absolute subresource rerooted via `Referer`.
//!
//! Hermetic + mainnet-safe: `DIG_NODE_PIN=off` (no coinset resolution — serve against the requested
//! root), a unique temp cache per server, and a MOCK upstream that answers every `dig.getContent`
//! with `-32004` so a genuine local miss classifies as a clean NotFound (⇒ the SPA/404 branch), never
//! a transport error. (The chain-anchored `verified=true` path is covered by dig-node-core's
//! `serve_content_plaintext_serves_local_first_decrypted`, which injects a deterministic resolver.)

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use axum::routing::post;
use axum::{Json, Router};
use digstore_core::Bytes32;
use serde_json::{json, Value};

/// Serialize every test in this file: they set PROCESS-GLOBAL `DIG_NODE_*` env the node reads live
/// per request, so concurrent tests must not race each other's cache/pin wiring (mirrors
/// `tests/server.rs`). A `tokio::sync::Mutex` because the guard is held across `.await`.
fn env_guard() -> Arc<tokio::sync::Mutex<()>> {
    static LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// RAII release of the env-serialization lock (held for the whole test).
#[must_use]
struct EnvHold(#[allow(dead_code)] tokio::sync::OwnedMutexGuard<()>);

/// Compile a REAL public `.dig` module (the SAME `digstore_stage::stage_and_compile` engine the node
/// depends on) with a `PublicManifest` section. Returns `(root, module_bytes)`.
fn compile_public_module(store_id: Bytes32, files: &[(String, Vec<u8>)]) -> (Bytes32, Vec<u8>) {
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
        include_public_manifest: true,
    };
    let compiled = digstore_stage::stage_and_compile(
        files,
        store_id,
        &digstore_core::Visibility::Public,
        digstore_core::MAX_STORE_BYTES,
        false,
        0,
        0,
        &opts,
    )
    .expect("stage + compile a fixture module");
    let bytes = std::fs::read(&compiled.module_path).expect("read compiled module");
    (compiled.root, bytes)
}

/// Seed a compiled module into the node's on-disk cache at its canonical `(store, root)` path
/// (`<cache>/modules/<store>/<root>.module`) so the local-first serve finds it.
fn seed_module(cache: &Path, store_hex: &str, root_hex: &str, bytes: &[u8]) {
    let dir = cache.join("modules").join(store_hex);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{root_hex}.module")), bytes).unwrap();
}

/// A mock upstream DIG RPC that answers every request with `-32004` (resource not available), so a
/// local miss on the node classifies as a clean NotFound → the SPA-fallback/404 branch.
async fn mock_upstream_all_miss() -> String {
    let app = Router::new().route(
        "/",
        post(|Json(req): Json<Value>| async move {
            let id = req.get("id").cloned().unwrap_or(json!(1));
            Json(json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32004,"message":"resource not available at this root"}}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Start the service app on an ephemeral loopback port with a unique temp cache, the pin OFF (so the
/// serve is hermetic — no coinset), and the given upstream. Returns the bound addr, the cache dir (to
/// seed a module into), and the env-serialization hold.
async fn start_server(upstream: &str) -> (SocketAddr, PathBuf, EnvHold) {
    let hold = env_guard().lock_owned().await;
    let unique = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "dig-node-serve-test-{}-{}",
        std::process::id(),
        unique
    ));
    let cache = base.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::env::set_var("DIG_NODE_CACHE", &cache);
    // Hermetic: disable the chain-anchored pin so the serve resolves against the requested root with
    // NO coinset call (the node-side gate only; a real deploy leaves the pin ON).
    std::env::set_var("DIG_NODE_PIN", "off");
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,
        dig_local: false,
        ..dig_node_service::Config::default()
    };
    let state = dig_node_service::server::build_state(&config);
    let app = dig_node_service::server::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, cache, EnvHold(hold))
}

fn store_and_files() -> (Bytes32, Vec<(String, Vec<u8>)>) {
    (
        Bytes32([31u8; 32]),
        vec![
            (
                "index.html".to_string(),
                b"<html><head><title>x</title></head><body>hello dig</body></html>".to_vec(),
            ),
            ("assets/app.js".to_string(), b"console.log(1)".to_vec()),
        ],
    )
}

#[tokio::test]
async fn serves_index_html_decrypted_with_headers_and_injected_base() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    let url = format!(
        "http://{addr}/s/{}:{}/index.html",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let h = resp.headers();
    assert!(h
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(h.get("x-dig-source").unwrap(), "local");
    assert_eq!(h.get("x-dig-root").unwrap(), &root.to_hex());
    // The pin is OFF in this hermetic test, so the serve is NOT chain-anchored → verified=false.
    assert_eq!(h.get("x-dig-verified").unwrap(), "false");
    assert!(
        h.get("content-security-policy").is_some(),
        "served HTML carries the store CSP"
    );

    let body = resp.text().await.unwrap();
    assert!(body.contains("hello dig"), "the HTML was decrypted: {body}");
    assert!(
        body.contains(&format!(
            "<base href=\"/s/{}:{}/\">",
            store.to_hex(),
            root.to_hex()
        )),
        "the store-root <base> is injected: {body}"
    );
    assert!(body.contains("<meta name=\"referrer\" content=\"same-origin\">"));
}

#[tokio::test]
async fn serves_js_asset_verbatim_without_html_injection() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    let url = format!(
        "http://{addr}/s/{}:{}/assets/app.js",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    let body = resp.text().await.unwrap();
    assert_eq!(body, "console.log(1)");
    assert!(!body.contains("<base"), "no HTML injection on a JS asset");
}

#[tokio::test]
async fn spa_route_falls_back_to_index_html() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    // A route-like path (no known asset extension) that is NOT in the store's manifest → SPA fallback
    // serves the store's index.html as 200 text/html so a client-side deep link boots.
    let url = format!(
        "http://{addr}/s/{}:{}/dashboard/settings",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "an SPA route must serve index.html, not 404"
    );
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("hello dig"),
        "the SPA fallback served index.html"
    );
}

#[tokio::test]
async fn missing_static_asset_is_an_honest_404() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    // A known-extension asset the store does not hold MUST 404 (never text/html — #144 MIME rule),
    // so a browser never rejects a service-worker/module fetch for a wrong MIME type.
    let url = format!(
        "http://{addr}/s/{}:{}/missing.js",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    assert!(!resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
}

#[tokio::test]
async fn root_absolute_subresource_reroots_via_referer() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    // A ROOT-ABSOLUTE request (`GET /assets/app.js`) carrying the store page's same-origin Referer is
    // rerooted back into its store and served.
    let referer = format!(
        "http://{addr}/s/{}:{}/index.html",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/assets/app.js"))
        .header(reqwest::header::REFERER, referer)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the Referer reroots the subresource into its store"
    );
    assert_eq!(resp.text().await.unwrap(), "console.log(1)");
}
