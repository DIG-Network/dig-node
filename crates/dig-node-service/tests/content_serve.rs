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

/// RAII release of the env-serialization lock (held for the whole test).
#[must_use]
struct EnvHold(#[allow(dead_code)] tokio::sync::OwnedMutexGuard<()>);

/// A node's temp tree, **owned** — removed when the test's binding drops, including on panic.
///
/// # Why this is a type and not a `PathBuf` plus a cleanup line (dig-node#361)
///
/// This harness used to build its path by hand, `env::temp_dir().join(format!("dig-node-serve-\
/// test-{pid}-{n}"))`, and nothing ever removed it. Each node seeds a real compiled `.dig` module
/// and warms a cache, so a run costs ~57 MB. **1,123 of them reached 62.5 GB and took the dev
/// machine to 81 MB free on a 1.9 TB disk**, producing a machine-wide `ENOSPC` that stopped an
/// unrelated lane mid-build. It is self-concealing: it grows fastest exactly when the suite runs
/// most, so it surfaces during heavy development and reads like a build-cache problem.
///
/// **Ownership is the point, not the deletion.** A `remove_dir_all` at the end of each test would
/// be skipped by every failing assertion — the runs most worth diagnosing leak, and a panic
/// unwinding past a deferred cleanup placed after an `.await` leaks whenever anything catches it.
/// `TempDir` removes the tree in `Drop`, which unwinding runs.
struct NodeCache {
    /// The whole per-node tree (`<temp>/<prefix><random>/`): cache, state dir, everything.
    dir: tempfile::TempDir,
    /// `<dir>/cache`, the path handed to `DIG_NODE_CACHE` and to [`seed_module`].
    cache: PathBuf,
}

/// Every temp tree this harness has ever created carries this prefix — the guard's own name for
/// itself, and what [`sweep_stale_trees`] matches on.
const TREE_PREFIX: &str = "dig-node-serve-test-";

/// A tree untouched for this long cannot belong to a live run.
///
/// Only the `content_serve` binary creates these, and it finishes in ~2.5 minutes, so a tree idle
/// for fifteen has no owner. Chosen as a safety margin rather than a tuning knob: being too eager
/// deletes a concurrent lane's working directory and manufactures a flaky failure somewhere else,
/// while being too patient costs only one more run's worth of small files.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Remove trees left by EARLIER runs, once per test process.
///
/// # Why a sweep is needed at all when the guard is RAII
///
/// The per-node [`NodeCache`] drop removes the ~57 MB cache tree, which is the whole of the disk
/// cost. What it cannot always remove is the node's `wallet.sqlite` (~428 KB with its `-wal` and
/// `-shm`): the axum task serving the node is detached and still holds the handle when the test
/// body returns, and **Windows refuses to unlink an open file**. `TempDir::drop` swallows that
/// error, so the tree survives with its database in it.
///
/// Fixing that inside `Drop` is not possible honestly — cancelling the server task needs the
/// runtime to poll it, and `Drop` cannot `.await`. So the residue is **bounded** instead of
/// pretended away, which dig-node#361 names as the acceptable second option: one run's worth of
/// small files at any time, rather than unbounded growth. The 62.5 GB / `ENOSPC` failure the
/// ticket was filed for is removed by the guard; this keeps the entry COUNT flat.
fn sweep_stale_trees() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| sweep_trees_in(&std::env::temp_dir(), STALE_AFTER));
}

/// The sweep itself, over an explicit directory and threshold.
///
/// Split out from [`sweep_stale_trees`] so it is reachable from a test: the `Once` fires before
/// the first [`NodeCache`], and a `Once` cannot be made to fire twice, so a test that could only
/// call the wrapper could never observe what it did.
fn sweep_trees_in(root: &Path, stale_after: std::time::Duration) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(TREE_PREFIX) {
            continue;
        }
        // Unreadable metadata is treated as RECENT, so an entry this code cannot judge is left
        // alone. The fail-safe direction is keeping a stranger's directory, never removing it.
        let recently_touched = entry
            .metadata()
            .and_then(|m| m.modified())
            .and_then(|t| t.elapsed().map_err(std::io::Error::other))
            .map_or(true, |age| age < stale_after);
        if recently_touched {
            continue;
        }
        // Best effort by design: a tree whose database is still open elsewhere simply stays, and
        // the next run tries again.
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

impl NodeCache {
    /// A fresh, uniquely-named tree with its `cache` subdirectory created.
    fn new() -> Self {
        sweep_stale_trees();
        let dir = tempfile::Builder::new()
            .prefix(TREE_PREFIX)
            .tempdir()
            .expect("temp dir for a serve-test node");
        let cache = dir.path().join("cache");
        std::fs::create_dir_all(&cache).expect("cache dir");
        Self { dir, cache }
    }

    /// The tree root — the node's `DIG_NODE_STATE_DIR`.
    fn root(&self) -> &Path {
        self.dir.path()
    }
}

impl AsRef<Path> for NodeCache {
    fn as_ref(&self) -> &Path {
        &self.cache
    }
}

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
fn seed_module(cache: impl AsRef<Path>, store_hex: &str, root_hex: &str, bytes: &[u8]) {
    let dir = cache.as_ref().join("modules").join(store_hex);
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
async fn start_server(upstream: &str) -> (SocketAddr, NodeCache, EnvHold) {
    let hold = env_guard().lock_owned().await;
    let (addr, cache) = spawn_node(upstream).await;
    (addr, cache, EnvHold(hold))
}

/// Bring up ONE service node — the body of [`start_server`] WITHOUT taking the env-serialization
/// lock, so a single test can stand up two nodes (a reader and the gateway it falls back to) inside
/// one hold. Each node captures its own cache dir at construction, so the process-global
/// `DIG_NODE_CACHE` may be repointed between calls.
async fn spawn_node(upstream: &str) -> (SocketAddr, NodeCache) {
    let cache = NodeCache::new();
    std::env::set_var("DIG_NODE_CACHE", &cache.cache);
    // Isolate the #501 control-token/paired-token state dir per test (identity-independent), so a
    // host with a real machine state dir can't defeat the temp isolation.
    std::env::set_var("DIG_NODE_STATE_DIR", cache.root());
    // Hermetic: disable the chain-anchored pin so the serve resolves against the requested root with
    // NO coinset call (the node-side gate only; a real deploy leaves the pin ON).
    std::env::set_var("DIG_NODE_PIN", "off");
    let config = dig_node_service::Config {
        upstream: upstream.to_string(),
        port: 0,
        dig_local: false,
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };
    let state = dig_node_service::server::build_state(&config).await;
    // `into_make_service_with_connect_info` — not the plain `app` — is what makes
    // `ConnectInfo<SocketAddr>` extractable in the real `rpc()` handler (#1619 follow-up).
    let app =
        dig_node_service::server::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, cache)
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

    // Serve-metadata headers (#486).
    assert_eq!(h.get("x-dig-store-id").unwrap(), &store.to_hex());
    assert_eq!(
        h.get("x-dig-capsule").unwrap(),
        &format!("{}:{}", store.to_hex(), root.to_hex())
    );
    assert_eq!(h.get("x-dig-resource-key").unwrap(), "index.html");
    // The fixture module embeds a PublicManifest (single commit) → generation 0, a LOCAL-only lookup
    // unaffected by the pin being off.
    assert_eq!(h.get("x-dig-generation").unwrap(), "0");
    // The pin is OFF ⇒ no chain read ran ⇒ the owner is genuinely unknowable → OMITTED, never a
    // placeholder.
    assert!(
        h.get("x-dig-owner-puzzle-hash").is_none(),
        "owner is unknowable with the pin off — must be omitted, not guessed"
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
    // Serve-metadata (#486): the resource key reports the ACTUAL asset served, not a default.
    assert_eq!(
        resp.headers().get("x-dig-resource-key").unwrap(),
        "assets/app.js"
    );
    assert_eq!(
        resp.headers().get("x-dig-store-id").unwrap(),
        &store.to_hex()
    );
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
    // Serve-metadata (#486): the resource key reports what was ACTUALLY served (the SPA fallback
    // index.html), never the miss path (`dashboard/settings`) that triggered it.
    assert_eq!(
        resp.headers().get("x-dig-resource-key").unwrap(),
        "index.html"
    );
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
    // Serve-metadata (#486): NONE of the 5 headers appear on an unresolved/non-served response — no
    // empty placeholder, the headers simply do not exist.
    for name in [
        "x-dig-store-id",
        "x-dig-owner-puzzle-hash",
        "x-dig-generation",
        "x-dig-capsule",
        "x-dig-resource-key",
    ] {
        assert!(
            resp.headers().get(name).is_none(),
            "a 404 must carry no serve-metadata header, found {name}"
        );
    }
}

#[tokio::test]
async fn head_request_returns_the_same_serve_metadata_headers_with_no_body() {
    // #486: a HEAD request must carry the identical serve-metadata + provenance headers as the
    // equivalent GET, but with an empty body (axum dispatches HEAD to the registered GET route and
    // strips the body — no separate HEAD handler is needed).
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
    let resp = reqwest::Client::new().head(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let h = resp.headers();
    assert!(h
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert_eq!(h.get("x-dig-source").unwrap(), "local");
    assert_eq!(h.get("x-dig-root").unwrap(), &root.to_hex());
    assert_eq!(h.get("x-dig-store-id").unwrap(), &store.to_hex());
    assert_eq!(
        h.get("x-dig-capsule").unwrap(),
        &format!("{}:{}", store.to_hex(), root.to_hex())
    );
    assert_eq!(h.get("x-dig-resource-key").unwrap(), "index.html");
    assert_eq!(h.get("x-dig-generation").unwrap(), "0");

    let body = resp.bytes().await.unwrap();
    assert!(body.is_empty(), "a HEAD response must carry no body");
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

// -- `/s/` ReadOrigin derivation (#1576) ---------------------------------------------------------
//
// The `/s/` handlers may NOT assume their caller is local. The whole router is served on EVERY
// listener, and `Config::bind_addr()` is `host.unwrap_or(127.0.0.1)` with no loopback validation on
// the `DIG_NODE_HOST` override — so with `DIG_NODE_HOST=0.0.0.0` a stranger reaches `GET /s/…`
// unauthenticated (no §21 token, no mTLS) and, with a `Local` label, would drive this node into a
// whole-capsule pull + cache promotion + DHT holder-announce for a capsule of the STRANGER'S naming.
// The label must therefore come from the accepting connection's real remote address.
//
// A test server bound to loopback can never PRODUCE a non-loopback remote address, so these tests
// drive the REAL router through `tower::ServiceExt::oneshot` with a FORGED `ConnectInfo` — the same
// extension `into_make_service_with_connect_info` inserts in production — and observe the origin at
// the seam-5 boundary via a recording `ContentServer` double.

/// A [`ContentServer`](dig_node_core::ContentServer) that serves nothing and records the
/// [`ReadOrigin`](dig_node_core::download::ReadOrigin) of every read that reaches it.
///
/// Returning `NotFound` deliberately drives the SPA-miss leg too, so the recorded sequence covers
/// BOTH `serve_resource`'s read and the `serve_miss` `index.html` read — a hardcoded origin left
/// behind at either one shows up as a wrong label rather than passing unnoticed.
#[derive(Default)]
struct RecordingContentServer {
    origins: std::sync::Mutex<Vec<dig_node_core::download::ReadOrigin>>,
    provenances: std::sync::Mutex<Vec<dig_node_core::download::RequestProvenance>>,
}

impl RecordingContentServer {
    fn recorded(&self) -> Vec<dig_node_core::download::ReadOrigin> {
        self.origins.lock().unwrap().clone()
    }

    fn recorded_provenances(&self) -> Vec<dig_node_core::download::RequestProvenance> {
        self.provenances.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl dig_node_core::ContentServer for RecordingContentServer {
    async fn serve_content_plaintext(
        &self,
        _store_hex: &str,
        _requested_root_hex: &str,
        _resource_key: &str,
        _salt_hex: Option<&str>,
        origin: dig_node_core::download::ReadOrigin,
        provenance: dig_node_core::download::RequestProvenance,
    ) -> dig_node_core::content_serve::PlaintextOutcome {
        self.origins.lock().unwrap().push(origin);
        self.provenances.lock().unwrap().push(provenance);
        dig_node_core::content_serve::PlaintextOutcome::NotFound {
            root_hex: String::new(),
        }
    }

    async fn manifest_paths(&self, _store_hex: &str, _root_hex: &str) -> Option<Vec<String>> {
        None
    }

    async fn resource_generation(
        &self,
        _store_hex: &str,
        _root_hex: &str,
        _resource_key: &str,
    ) -> Option<u64> {
        None
    }
}

/// Drive `GET <path>` through the REAL router from `peer` (a forged connection remote address),
/// optionally carrying a `Referer` and a `Sec-Fetch-Site` header, and return the recording content
/// server (the reads it saw) plus the HTTP status. The single low-level seam behind the origin- and
/// provenance-observing helpers.
async fn drive_s_get(
    peer: &str,
    path: &str,
    referer: Option<&str>,
    sec_fetch_site: Option<&str>,
) -> (Arc<RecordingContentServer>, axum::http::StatusCode) {
    use tower::ServiceExt;

    let hold = env_guard().lock_owned().await;
    // Owned for the body of this helper, so the tree goes when it returns OR panics. The same
    // hand-rolled leak as `spawn_node` had (`dig-node-origin-test-*`), fixed the same way.
    let base = NodeCache::new();
    std::env::set_var("DIG_NODE_CACHE", &base.cache);
    std::env::set_var("DIG_NODE_STATE_DIR", base.root());
    std::env::set_var("DIG_NODE_PIN", "off");
    let config = dig_node_service::Config {
        upstream: "http://127.0.0.1:1/unreachable".to_string(),
        port: 0,
        dig_local: false,
        enable_chain_sync: false, // never dial mainnet from the harness (#2501)
        ..dig_node_service::Config::default()
    };
    let recorder = Arc::new(RecordingContentServer::default());
    let state = dig_node_service::server::build_state(&config)
        .await
        .with_content_server(recorder.clone());

    // `Host: localhost` is exactly what a remote client sends to clear the DNS-rebinding host guard:
    // the guard is not an origin check, which is why the origin must be derived from the connection.
    let mut builder = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .header(axum::http::header::HOST, "localhost");
    if let Some(referer) = referer {
        builder = builder.header(axum::http::header::REFERER, referer);
    }
    if let Some(sfs) = sec_fetch_site {
        builder = builder.header("sec-fetch-site", sfs);
    }
    let mut request = builder.body(axum::body::Body::empty()).unwrap();
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        peer.parse::<SocketAddr>()
            .expect("a valid forged peer addr"),
    ));

    let response = dig_node_service::server::router(state)
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_ne!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "a missing ConnectInfo would be an axum rejection (500), not a defaulted origin"
    );
    let status = response.status();
    drop(EnvHold(hold));
    (recorder, status)
}

/// Drive `GET <path>` through the real router from `peer` and return every `ReadOrigin` the content
/// server was asked with.
async fn origins_seen_for(
    peer: &str,
    path: &str,
    referer: Option<&str>,
) -> Vec<dig_node_core::download::ReadOrigin> {
    drive_s_get(peer, path, referer, None).await.0.recorded()
}

/// **Proves:** `GET /s/…` labels its read from the CONNECTION — a non-loopback reader is `Peer`
/// (so the miss effects nothing on the network) while the paired loopback control over the IDENTICAL
/// route is `Local` (so the operator's own read still warms + reshares).
///
/// **Catches:** `store_serve` (or `serve_resource`/`serve_miss`) hardcoding `ReadOrigin::Local`
/// rather than carrying `read_origin_for(&peer_addr)`. Because the two arms differ ONLY in the
/// connection's remote address, a relocated or reasserted label changes the observable — the
/// property cannot be satisfied by a guard placed at the wrong layer.
#[tokio::test]
async fn store_serve_labels_the_read_from_the_connection_not_the_endpoint() {
    use dig_node_core::download::ReadOrigin;
    let store = "31".repeat(32);
    let path = format!("/s/{store}/app/deep/route");

    let stranger = origins_seen_for("203.0.113.7:51234", &path, None).await;
    assert!(
        !stranger.is_empty(),
        "the read must reach the content server at all, or this test observes nothing"
    );
    assert!(
        stranger.iter().all(|o| *o == ReadOrigin::Peer),
        "a non-loopback /s/ reader must be labelled Peer at every read, got {stranger:?}"
    );

    // The control: the same route, the same store, only the connection differs.
    let operator = origins_seen_for("127.0.0.1:51234", &path, None).await;
    assert!(
        operator.iter().all(|o| *o == ReadOrigin::Local) && !operator.is_empty(),
        "the loopback control must be labelled Local, got {operator:?}"
    );
}

/// **Proves:** the ROUTER FALLBACK — the root-absolute-subresource path (`GET /foo.js` rerooted via
/// `Referer`) — derives its label the same way. It is a SECOND door into the identical serve path, so
/// gating only `/s/*path` would leave the defect reachable.
#[tokio::test]
async fn fallback_serve_labels_a_rerooted_read_from_the_connection() {
    use dig_node_core::download::ReadOrigin;
    let store = "31".repeat(32);
    // A ROOT-ABSOLUTE subresource (no `/s/` prefix) that the router sends to the fallback, carrying
    // the same-origin `Referer` a store page always sends — so the reroot succeeds and the read
    // genuinely reaches the content server through the fallback door.
    let seen = origins_seen_for(
        "203.0.113.7:51235",
        "/bundle.js",
        Some(&format!("http://localhost/s/{store}/index.html")),
    )
    .await;
    assert!(
        seen.iter().all(|o| *o == ReadOrigin::Peer) && !seen.is_empty(),
        "a non-loopback reader must be Peer on the fallback door too, got {seen:?}"
    );
}

// -- `/s/` RequestProvenance derivation (#1654) --------------------------------------------------
//
// A loopback address proves the CONNECTION is local, not that the operator authorized the request:
// a malicious page can drive a cross-site `GET dig.local/s/<capsule>`, and the durable LANDING side
// effect (cache write → DHT holder) would then be remotely triggerable. `Sec-Fetch-Site: cross-site`
// is the browser's own report that another origin drove the request; the node threads it to the
// serve seam so the LANDING legs (but never the READ) can suppress it. These prove the header is
// carried to the seam exactly; the core `landing_origin` unit test proves the collapse it drives.

/// **Proves:** a loopback `GET /s/…` carrying `Sec-Fetch-Site: cross-site` still SERVES (the read is
/// frictionless — same status as an ordinary miss) but reaches the serve seam labelled `CrossSite`,
/// so the landing legs fold to `Peer` and no durable holder side effect fires. A same-site request
/// and a header-ABSENT request (a CLI/SDK client) both reach the seam as `FirstParty`, so a
/// legitimate read still lands.
///
/// **Catches:** the `Sec-Fetch-Site` header being dropped between the transport and the serve seam,
/// or absence being mistaken for cross-site (which would silently stop every CLI/SDK read landing).
#[tokio::test]
async fn store_serve_labels_provenance_from_sec_fetch_site_without_blocking_the_read() {
    use dig_node_core::download::RequestProvenance;
    let store = "31".repeat(32);
    let path = format!("/s/{store}/app/index.html");

    // Cross-site: the browser reports another origin drove this loopback request.
    let (cross, cross_status) =
        drive_s_get("127.0.0.1:51240", &path, None, Some("cross-site")).await;
    assert!(
        cross
            .recorded_provenances()
            .iter()
            .all(|p| *p == RequestProvenance::CrossSite)
            && !cross.recorded_provenances().is_empty(),
        "a cross-site read must reach the seam as CrossSite, got {:?}",
        cross.recorded_provenances()
    );

    // Same-origin: dig-node#450. `/s/*` and `POST /` share a router, a port and therefore an
    // ORIGIN, and STORE_CSP lets a store page script a call the browser labels `same-origin`. It
    // must reach the seam as StoreServed so landing folds to `Peer` — otherwise a stranger's page
    // chooses which capsule this operator bonds $DIG against.
    let (same, same_status) =
        drive_s_get("127.0.0.1:51241", &path, None, Some("same-origin")).await;
    assert!(
        same.recorded_provenances()
            .iter()
            .all(|p| *p == RequestProvenance::StoreServed)
            && !same.recorded_provenances().is_empty(),
        "a same-origin read must reach the seam as StoreServed, got {:?}",
        same.recorded_provenances()
    );

    // The control that keeps the flywheel honest: a USER-initiated top-level navigation
    // (`Sec-Fetch-Site: none`, unforgeable by page script) is still FirstParty and still lands. If
    // this arm ever folded too, opening a store in a browser would stop landing it at all — a
    // regression a StoreServed-only assertion could not see.
    let (nav, _) = drive_s_get("127.0.0.1:51243", &path, None, Some("none")).await;
    assert!(
        nav.recorded_provenances()
            .iter()
            .all(|p| *p == RequestProvenance::FirstParty)
            && !nav.recorded_provenances().is_empty(),
        "a top-level navigation must reach the seam as FirstParty, got {:?}",
        nav.recorded_provenances()
    );

    // Header ABSENT (a CLI/SDK client sends no Sec-Fetch-*): must be FirstParty, never CrossSite.
    let (absent, absent_status) = drive_s_get("127.0.0.1:51242", &path, None, None).await;
    assert!(
        absent
            .recorded_provenances()
            .iter()
            .all(|p| *p == RequestProvenance::FirstParty)
            && !absent.recorded_provenances().is_empty(),
        "an absent Sec-Fetch-Site must reach the seam as FirstParty, got {:?}",
        absent.recorded_provenances()
    );

    // The READ is never blocked by provenance: all three miss identically (the recorder serves
    // NotFound → the SPA/404 decision), so a cross-site read is exactly as served as a same-site one.
    assert_eq!(
        cross_status, same_status,
        "a cross-site read must not be blocked — same status as a same-site read"
    );
    assert_eq!(
        same_status, absent_status,
        "a header-absent read must not be blocked either"
    );
}

/// **Regression (#1763):** during the ~30 s cold-start window BEFORE the peer network attaches, a
/// content read still succeeds — but it is served by the public gateway, having never consulted the
/// peer tier at all. Before this fix the response was indistinguishable from a post-attach gateway
/// serve, so a fresh node (or a test that started promptly) measured the gateway and recorded it as
/// a P2P result. The read MUST now say, in the response itself, that the peer tier was not attached
/// when it was routed.
///
/// **The fixture is a real cold start, not a mock of one:** `build_state` is the same constructor
/// the daemon uses and it does NOT attach the P2P content engine (only `spawn_peer_network` does),
/// so the reader node below is genuinely inside the window. Its Tier-3 fallback is a SECOND real
/// dig-node serving the capsule over the real `dig.getContent` wire — the gateway's bytes, proof and
/// chunk lengths are produced by the production serve path, not hand-built.
#[tokio::test]
async fn cold_start_gateway_serve_reports_the_peer_tier_as_unattached() {
    let _hold = EnvHold(env_guard().lock_owned().await);
    let (store, files) = store_and_files();
    let (root, module) = compile_public_module(store, &files);

    // The GATEWAY: a node that holds the capsule and answers `dig.getContent` from its own cache.
    // Its own upstream is unroutable — every byte it returns comes from the module seeded below.
    let (gw_addr, gw_cache) = spawn_node("http://127.0.0.1:1/").await;
    seed_module(&gw_cache, &store.to_hex(), &root.to_hex(), &module);

    // The READER: a freshly-started node with an EMPTY cache and no peer network attached — the
    // cold-start window. Local misses, the peer tier is not there, so the read falls to the gateway.
    let (addr, _cache) = spawn_node(&format!("http://{gw_addr}")).await;

    let url = format!(
        "http://{addr}/s/{}:{}/index.html",
        store.to_hex(),
        root.to_hex()
    );
    let resp = reqwest::Client::new().get(&url).send().await.unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the read still succeeds — availability is not traded away"
    );
    let h = resp.headers();
    assert_eq!(
        h.get("x-dig-source").unwrap(),
        "rpc",
        "the gateway served these bytes"
    );
    // #1765 (source ⊥ verified): the reader ran with `DIG_NODE_PIN=off` (the hermetic harness), so
    // the bytes were NOT bound to a chain-anchored root — the GATEWAY leg must report
    // `x-dig-verified:false`, EXACTLY as the local leg does under the same pin-off condition
    // (asserted for the local tier in `serves_index_html_decrypted_with_headers_and_injected_base`).
    // `x-dig-verified` is derived solely from the pin state (`Served.verified`), never from the
    // serve `source`, so the header is consistent across the local, peer, and gateway legs (the
    // three legs thread the SAME `verified` value — dig-node-core `content_serve.rs`, the
    // local/peer/rpc `Served { verified, .. }` constructions). No code change was needed here.
    assert_eq!(
        h.get("x-dig-verified").unwrap(),
        "false",
        "with the pin off the gateway leg must report unverified, like the local leg"
    );
    assert_eq!(
        h.get("x-dig-peer-tier")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("<header absent>"),
        "unattached",
        "the read must declare that the peer tier was never consulted"
    );
}

/// **Proves (#1763):** the peer-tier state is ALSO checkable out-of-band, on `GET /health`, so an
/// acceptance test can poll `peer_tier.attached` until the peer network is up instead of sleeping a
/// guessed 30 s and hoping. A node that answers `/health` with `status: ok` is live, but liveness has
/// never implied a usable peer tier — this is the field that separates the two.
#[tokio::test]
async fn health_reports_the_peer_tier_as_unattached_before_the_peer_network_starts() {
    let (addr, _cache, _hold) = start_server("http://127.0.0.1:1/").await;
    let body: Value = reqwest::get(format!("http://{addr}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], json!("ok"), "the node is live");
    assert_eq!(
        body["peer_tier"]["attached"],
        json!(false),
        "a live node with no peer network must say so rather than leaving it unstated"
    );
}

/// **The temp tree is removed when the guard drops — including when the drop is a PANIC unwinding
/// out of a failing test.**
///
/// This is dig-node#361's regression, and the panic half is the half that matters. The leak was
/// not "someone forgot the cleanup line"; it was that a cleanup line cannot run on the failing
/// runs, which are exactly the runs a developer repeats. 1,123 leaked trees reached 62.5 GB and
/// took the machine to 81 MB free.
///
/// **Asserted on the path, after the guard is gone.** Asserting that `Drop` was *reached* would
/// pass for a `Drop` that reached a `remove_dir_all` and ignored its error, which is precisely the
/// silent failure mode of the type being tested.
///
/// No node is started here on purpose: this pins the GUARD, and a live node's open `wallet.sqlite`
/// handle is a separate, bounded residue that [`sweep_stale_trees`] owns.
#[test]
fn the_temp_tree_is_removed_on_drop_and_on_panic() {
    let cache = NodeCache::new();
    let normal = cache.root().to_path_buf();
    std::fs::write(
        normal.join("cache").join("seeded.bin"),
        b"57 MB stands in here",
    )
    .unwrap();
    assert!(
        normal.is_dir(),
        "the fixture never existed, so nothing is proven"
    );
    drop(cache);
    assert!(
        !normal.exists(),
        "a guard dropped normally left its tree at {}",
        normal.display()
    );

    // The panic path. `catch_unwind` is what makes it observable from inside a passing test; the
    // unwind is real, and the guard is dropped by it and not by us.
    let leaked = std::sync::Arc::new(std::sync::Mutex::new(PathBuf::new()));
    let seen = std::sync::Arc::clone(&leaked);
    let outcome = std::panic::catch_unwind(move || {
        let cache = NodeCache::new();
        *seen.lock().unwrap() = cache.root().to_path_buf();
        std::fs::write(cache.as_ref().join("seeded.bin"), b"and here").unwrap();
        panic!("a failing assertion, which is when the old harness leaked");
    });

    assert!(
        outcome.is_err(),
        "the fixture did not panic, so it proves nothing"
    );
    let path = leaked.lock().unwrap().clone();
    assert!(
        !path.as_os_str().is_empty(),
        "the closure never built a tree, so the assertion below is vacuous"
    );
    assert!(
        !path.exists(),
        "a panic unwound past the guard and left its tree at {} -- this is the ENOSPC defect",
        path.display()
    );
}

/// **The sweep removes an abandoned tree and leaves a live one alone.**
///
/// Both halves are the test. A sweep that removes everything would pass a
/// "the stale one is gone" assertion while deleting a concurrent lane's working directory
/// mid-run — turning a disk-hygiene fix into a flaky-failure generator in an unrelated repo. So
/// the fresh tree is not decoration: it is the actor that distinguishes this sweep from the
/// nearest wrong one.
///
/// Run over a scratch directory rather than the real `Temp`, so it cannot delete anything real,
/// and with an explicit threshold rather than [`STALE_AFTER`], so it does not take fifteen
/// minutes to be true.
#[test]
fn the_sweep_removes_an_abandoned_tree_and_spares_a_live_one() {
    let scratch = tempfile::tempdir().unwrap();
    let threshold = std::time::Duration::from_millis(300);

    let abandoned = scratch.path().join(format!("{TREE_PREFIX}abandoned"));
    std::fs::create_dir_all(abandoned.join("cache")).unwrap();
    std::fs::write(abandoned.join("wallet.sqlite"), b"residue").unwrap();

    // An unrelated directory that merely shares the temp dir. The sweep must be selective by
    // PREFIX as well as by age -- it is pointed at a directory full of other people's files.
    let stranger = scratch.path().join("someone-elses-work");
    std::fs::create_dir_all(&stranger).unwrap();

    std::thread::sleep(threshold * 4);

    let live = scratch.path().join(format!("{TREE_PREFIX}live"));
    std::fs::create_dir_all(live.join("cache")).unwrap();

    sweep_trees_in(scratch.path(), threshold);

    assert!(
        !abandoned.exists(),
        "the abandoned tree survived, so the count grows without bound"
    );
    assert!(
        live.is_dir(),
        "the sweep deleted a tree young enough to belong to a running test -- this would break \
         a concurrent lane rather than tidy up after this one"
    );
    assert!(
        stranger.is_dir(),
        "the sweep removed a directory that is not one of ours at all"
    );
}
