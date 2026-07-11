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

// -- Verification ledger (#307) -----------------------------------------------------------------
//
// The `/s/` serve path records each served (or fail-closed) resource's verdict + Merkle proof into
// the in-memory verification ledger; `GET /verify/<store>[:<root>]` exposes it. These prove the
// end-to-end HTTP contract the extension's "Verified by Chia" badge + proof-inspection modal consume.

/// A mock upstream that answers every `dig.getContent` with a self-consistent Merkle proof whose root
/// is the served leaf — which is NOT the requested (anchored) root — so the node's RPC tier verifies,
/// FAILS CLOSED (a decoy/tampered response), and never serves the bytes. Returns the crafted result.
async fn mock_upstream_bad_bytes() -> String {
    use base64::Engine;
    use digstore_core::codec::{Encode, Encoder};
    use digstore_core::{resource_leaf, MerkleProof};

    // Bytes that are NOT the requested resource; a self-consistent single-leaf proof rooted at the
    // leaf. `proof.root == leaf` (folds) but `leaf != requested_root`, so the anchored-root gate
    // rejects it (the decoy-for-a-missing-key shape).
    let ciphertext = b"decoy-bytes-not-the-resource".to_vec();
    let leaf = resource_leaf(&ciphertext);
    let proof = MerkleProof {
        leaf,
        path: Vec::new(),
        root: leaf,
    };
    let mut enc = Encoder::new();
    proof.encode(&mut enc);
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(enc.finish());
    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

    let app = Router::new().route(
        "/",
        post(move |Json(req): Json<Value>| {
            let ct_b64 = ct_b64.clone();
            let proof_b64 = proof_b64.clone();
            async move {
                let id = req.get("id").cloned().unwrap_or(json!(1));
                Json(json!({"jsonrpc":"2.0","id":id,"result":{
                    "ciphertext": ct_b64,
                    "inclusion_proof": proof_b64,
                    "chunk_lens": [],
                    "complete": true,
                }}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Fetch + parse the `/verify/<store>[:<root>]` JSON snapshot.
async fn get_verify(addr: &SocketAddr, store_hex: &str, root_hex: &str) -> Value {
    let url = format!("http://{addr}/verify/{store_hex}:{root_hex}");
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "/verify always returns a valid snapshot"
    );
    resp.json::<Value>().await.unwrap()
}

#[tokio::test]
async fn served_page_records_the_verification_ledger_with_proof_data() {
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);
    let upstream = mock_upstream_all_miss().await;
    let (addr, cache, _hold) = start_server(&upstream).await;
    seed_module(&cache, &store.to_hex(), &root.to_hex(), &module);

    // Serve two distinct resources of the page from the local module.
    for path in ["index.html", "assets/app.js"] {
        let url = format!(
            "http://{addr}/s/{}:{}/{}",
            store.to_hex(),
            root.to_hex(),
            path
        );
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path} served");
    }

    let v = get_verify(&addr, &store.to_hex(), &root.to_hex()).await;
    assert_eq!(v["storeId"], store.to_hex());
    assert_eq!(v["root"], root.to_hex());
    // Both resources recorded, each from the local tier, with proof data.
    let resources = v["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2, "index.html + assets/app.js recorded");
    for entry in resources {
        assert_eq!(entry["source"], "local", "served from the local .dig");
        assert!(
            entry["proof"]["leafHash"].as_str().unwrap().len() == 64,
            "leaf hash is 32-byte hex"
        );
        assert!(entry["proof"].get("siblings").is_some());
        assert!(entry["proof"].get("leafIndex").is_some());
        assert_eq!(entry["proof"]["proofRoot"], root.to_hex());
        assert_eq!(entry["root"], root.to_hex());
    }
    let counts = &v["aggregate"]["counts"];
    assert_eq!(counts["total"], 2);
    assert_eq!(counts["bySource"]["local"], 2);
    // The pin is OFF in this hermetic harness, so the serve is not chain-anchored → verified=false
    // per resource; the aggregate is therefore not "verified", and — being all local — no RPC failed.
    assert_eq!(v["aggregate"]["verified"], false);
    assert_eq!(v["aggregate"]["anyRpcFailed"], false);
}

#[tokio::test]
async fn rpc_verification_failure_is_recorded_and_fails_closed() {
    let (store, _files) = store_and_files();
    // A requested root that the decoy proof will NOT fold to — the fail-closed trigger.
    let root = digstore_core::Bytes32([0x5au8; 32]);
    let upstream = mock_upstream_bad_bytes().await;
    // Do NOT seed any local module: the serve falls through local → peer → RPC (the mock).
    let (addr, _cache, _hold) = start_server(&upstream).await;

    // The resource is NEVER served (fail-closed): a route-like miss SPA-falls-back to index.html,
    // which also fails to verify, so the response is an honest error, not decoy plaintext.
    let url = format!(
        "http://{addr}/s/{}:{}/index.html",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_ne!(
        resp.status(),
        200,
        "a decoy that fails verification is never served"
    );
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("decoy-bytes"),
        "fail-closed: no decoy plaintext crosses the wire: {body}"
    );

    // But the failed verification IS recorded, flipping the page aggregate to Unverified.
    let v = get_verify(&addr, &store.to_hex(), &root.to_hex()).await;
    assert_eq!(
        v["aggregate"]["verified"], false,
        "a failed RPC resource → not verified"
    );
    assert_eq!(
        v["aggregate"]["anyRpcFailed"], true,
        "source=rpc && !verified"
    );
    let resources = v["resources"].as_array().unwrap();
    assert!(
        !resources.is_empty(),
        "the failed resource is recorded, not silently dropped"
    );
    let failed = &resources[0];
    assert_eq!(failed["source"], "rpc");
    assert_eq!(failed["verified"], false);
    assert!(
        failed["failReason"].as_str().is_some_and(|s| !s.is_empty()),
        "the fail-closed reason is recorded: {failed}"
    );
    // Proof data for the (failed) resource is exposed for the modal.
    assert_eq!(failed["proof"]["leafHash"].as_str().unwrap().len(), 64);
    assert!(failed["proof"].get("proofRoot").is_some());
}
