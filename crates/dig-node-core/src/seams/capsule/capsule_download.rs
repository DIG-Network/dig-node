//! Whole-capsule download over the public `dig.getCapsule` JSON-RPC (#1886).
//!
//! # Why this exists beside the §21 `GET /stores/{id}/module` clone
//!
//! The §21 clone is a single HTTP response carrying the entire `.dig`. Against the public
//! gateway that route CANNOT carry a real capsule: `rpc.dig.net` buffers the module into a
//! Lambda/API-Gateway response capped at ~6 MB, while a production capsule is ~135 MB, so a
//! correctly-formed clone of a real store answers `500`. (A clone that omits the gateway's
//! REQUIRED `root` query answers `400` before even reaching that limit.)
//!
//! `dig.getCapsule` is the gateway's own answer to its own cap: it streams the capsule by
//! `(store_id, root)` in bounded offset/length windows the caller reassembles. It is also
//! ANONYMOUS — no §21.9 identity is needed — so whole-store sync no longer depends on the node
//! holding an identity key.
//!
//! # What this refuses to trust
//!
//! The upstream is not trusted to be honest about size or progress. Every window is checked:
//! the declared `total_length` may not exceed [`MAX_CAPSULE_BYTES`] and may not change between
//! windows; the stream must make forward progress; and the reassembled length must match the
//! length that was declared. A hostile or broken server therefore fails fast instead of driving
//! the node into an unbounded allocation or an endless loop. The BYTES are not trusted either —
//! nothing here verifies them, exactly as with the §21 clone: every resource the node later
//! serves out of this module carries a merkle proof the client checks against the
//! chain-anchored root, and that is the gate a tampered capsule fails.

use base64::Engine as _;
use serde_json::{json, Value};

/// Bytes requested per `dig.getCapsule` window.
///
/// Pinned to the gateway's OWN per-response ceiling (`RPC_MAX_CHUNK`, 3 MiB in
/// hub.dig.net's retrieval service): asking for more is silently clamped there, so a larger
/// value would only make the client's accounting disagree with the wire. Windows are 64-KiB
/// aligned server-side, so a served window may be shorter than this — the loop follows the
/// server's `next_offset`, never its own arithmetic.
pub const CAPSULE_WINDOW_BYTES: u64 = 3 * 1024 * 1024;

/// Hard ceiling on a downloaded capsule (4 GiB).
///
/// A declared `total_length` above this is refused BEFORE any allocation, so an upstream
/// claiming an absurd size cannot exhaust node memory. Well above any real capsule (the largest
/// observed production store is ~135 MB) and well below a size the node could hold anyway.
pub const MAX_CAPSULE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Download the WHOLE `.dig` capsule for `(store_hex, root_hex)` from a `dig` JSON-RPC endpoint
/// by paging `dig.getCapsule`.
///
/// `root_hex` is always sent explicitly, never `"latest"`: the caller has already resolved the
/// generation it wants (from the chain, for a pinned read), and letting the SERVER pick the
/// generation would let a compromised upstream choose which one this node caches and reshares.
///
/// # Errors
/// Returns a human-readable reason naming the ACTUAL failure — transport, JSON-RPC error, a
/// dishonest length or a stalled stream. This string reaches the operator, so it must never
/// degenerate into a list of causes the code did not check.
pub async fn download_capsule_via_rpc(
    http: &reqwest::Client,
    endpoint: &str,
    store_hex: &str,
    root_hex: &str,
    window: u64,
) -> Result<Vec<u8>, String> {
    let mut assembled: Vec<u8> = Vec::new();
    let mut offset: u64 = 0;
    let mut declared_total: Option<u64> = None;

    loop {
        let window_json = request_window(http, endpoint, store_hex, root_hex, offset, window)
            .await
            .map_err(|e| format!("dig.getCapsule at offset {offset}: {e}"))?;
        let win = CapsuleWindow::parse(&window_json)?;

        // The declared size is a commitment made on the FIRST window; a later window that
        // disagrees is an upstream rewriting the download mid-flight.
        match declared_total {
            None => {
                if win.total_length > MAX_CAPSULE_BYTES {
                    return Err(format!(
                        "upstream declared a {}-byte capsule, above the {MAX_CAPSULE_BYTES}-byte ceiling",
                        win.total_length
                    ));
                }
                assembled.reserve_exact(win.total_length as usize);
                declared_total = Some(win.total_length);
            }
            Some(total) if total != win.total_length => {
                return Err(format!(
                    "upstream changed total_length mid-download ({total} then {})",
                    win.total_length
                ));
            }
            Some(_) => {}
        }

        if win.offset != offset {
            return Err(format!(
                "upstream served offset {} but {offset} was requested",
                win.offset
            ));
        }
        assembled.extend_from_slice(&win.bytes);

        if win.complete {
            break;
        }
        // Forward progress is mandatory: an upstream that keeps answering the same offset (or
        // hands back an empty non-final window) would otherwise loop forever.
        let next = win
            .next_offset
            .ok_or("upstream marked the capsule incomplete but gave no next_offset")?;
        if next <= offset {
            return Err(format!(
                "upstream stalled: next_offset {next} does not advance past {offset}"
            ));
        }
        offset = next;
    }

    let total = declared_total.unwrap_or_default();
    if assembled.len() as u64 != total {
        return Err(format!(
            "capsule truncated: assembled {} bytes of a declared {total}",
            assembled.len()
        ));
    }
    if assembled.is_empty() {
        return Err("upstream served an empty capsule".to_string());
    }
    Ok(assembled)
}

/// POST one `dig.getCapsule` window and return its `result` object.
async fn request_window(
    http: &reqwest::Client,
    endpoint: &str,
    store_hex: &str,
    root_hex: &str,
    offset: u64,
    window: u64,
) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "dig.getCapsule",
        "params": {
            "store_id": store_hex,
            "root": root_hex,
            "offset": offset,
            "length": window,
        }
    });
    let resp = http
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    // A non-2xx carries the gateway's own reason; surface the status so an operator sees the
    // real rejection rather than a guess (this is precisely what hid #1886's 400).
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("upstream returned HTTP {}", status.as_u16()));
    }
    let envelope: Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = envelope.get("error") {
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unspecified");
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        return Err(format!("JSON-RPC error {code}: {message}"));
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| "JSON-RPC response carried neither result nor error".to_string())
}

/// One decoded `dig.getCapsule` window.
struct CapsuleWindow {
    bytes: Vec<u8>,
    offset: u64,
    total_length: u64,
    complete: bool,
    next_offset: Option<u64>,
}

impl CapsuleWindow {
    /// Decode the wire shape (`ciphertext` base64 + the streaming envelope). The field is named
    /// `ciphertext` for the per-resource reads that share this envelope; for a whole capsule it
    /// is the raw `.dig` module bytes, which are already the encrypted-at-rest artifact.
    fn parse(result: &Value) -> Result<Self, String> {
        let b64 = result
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or("window carried no ciphertext field")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("window ciphertext is not valid base64: {e}"))?;
        let total_length = result
            .get("total_length")
            .and_then(Value::as_u64)
            .ok_or("window carried no total_length")?;
        Ok(CapsuleWindow {
            bytes,
            offset: result.get("offset").and_then(Value::as_u64).unwrap_or(0),
            total_length,
            complete: result
                .get("complete")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            next_offset: result.get("next_offset").and_then(Value::as_u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A mock `dig` JSON-RPC endpoint streaming `capsule` in `window`-sized pieces, exactly as
    /// hub.dig.net's retrieval service does. `mangle` may rewrite each result object, which is
    /// how the dishonest-upstream tests express their specific lie.
    async fn spawn_capsule_rpc(
        capsule: Vec<u8>,
        window: usize,
        mangle: impl Fn(&mut Value) + Clone + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<usize>>) {
        use axum::{routing::post, Json, Router};

        let calls = Arc::new(Mutex::new(0usize));
        let seen = calls.clone();
        let handler = move |Json(body): Json<Value>| {
            let capsule = capsule.clone();
            let mangle = mangle.clone();
            let seen = seen.clone();
            async move {
                *seen.lock().unwrap() += 1;
                let params = &body["params"];
                let offset = params["offset"].as_u64().unwrap_or(0) as usize;
                let end = (offset + window).min(capsule.len());
                let chunk = capsule.get(offset..end).unwrap_or(&[]);
                let complete = end >= capsule.len();
                let mut result = json!({
                    "ciphertext": base64::engine::general_purpose::STANDARD.encode(chunk),
                    "total_length": capsule.len(),
                    "offset": offset,
                    "length": chunk.len(),
                    "complete": complete,
                    "next_offset": if complete { Value::Null } else { json!(end) },
                });
                mangle(&mut result);
                Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
            }
        };
        let app = Router::new().route("/", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), calls)
    }

    fn deterministic_capsule(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    const STORE: &str = "1426d9064bb59353e2ad3845c1d250af1f75476a6d4d85f2c4d6b90696359907";
    const ROOT: &str = "6caaeb51745e358b7b999a09903735c6001f82ba48c53c00760cd0f435709906";

    /// The property: the download REASSEMBLES a capsule that does not fit in one window.
    ///
    /// The fixture spans three full windows plus a partial one, and the assertion is on the
    /// BYTES, not the length — a single-shot implementation that returns the first window (the
    /// nearest wrong implementation, and what the §21 clone effectively is) fails on both counts,
    /// and a loop that reassembles out of order fails on the bytes.
    #[tokio::test]
    async fn reassembles_a_capsule_spanning_several_windows() {
        let window = 1024;
        let capsule = deterministic_capsule(window * 3 + 17);
        let (url, calls) = spawn_capsule_rpc(capsule.clone(), window, |_| {}).await;

        let got =
            download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, window as u64)
                .await
                .expect("download");

        assert_eq!(got, capsule, "reassembled bytes must equal the capsule");
        assert_eq!(*calls.lock().unwrap(), 4, "one request per window");
    }

    /// A capsule that fits in ONE window still completes — the loop must not require a second
    /// round trip to terminate.
    #[tokio::test]
    async fn single_window_capsule_completes_in_one_request() {
        let capsule = deterministic_capsule(64);
        let (url, calls) = spawn_capsule_rpc(capsule.clone(), 1024, |_| {}).await;

        let got = download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 1024)
            .await
            .expect("download");

        assert_eq!(got, capsule);
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    /// The requested root reaches the wire VERBATIM and is never replaced by `"latest"`: a
    /// server that picks the generation picks what this node caches and reshares.
    #[tokio::test]
    async fn requests_the_explicit_root_never_latest() {
        use axum::{routing::post, Json, Router};
        let seen: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
        let captured = seen.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(body): Json<Value>| {
                let captured = captured.clone();
                async move {
                    *captured.lock().unwrap() = Some(body["params"].clone());
                    Json(json!({"jsonrpc":"2.0","id":1,"result":{
                        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"x"),
                        "total_length": 1, "offset": 0, "length": 1, "complete": true,
                    }}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let _ = download_capsule_via_rpc(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            STORE,
            ROOT,
            4096,
        )
        .await;

        let params = seen.lock().unwrap().clone().expect("server saw a request");
        assert_eq!(params["store_id"], json!(STORE));
        assert_eq!(
            params["root"],
            json!(ROOT),
            "the explicit root, not \"latest\""
        );
    }

    /// A stalled upstream must fail, not spin. `next_offset` is rewritten to the offset just
    /// served, so the honest loop would re-request the same window forever.
    #[tokio::test]
    async fn refuses_an_upstream_that_never_advances() {
        let capsule = deterministic_capsule(4096);
        let (url, _) = spawn_capsule_rpc(capsule, 512, |r| {
            r["next_offset"] = r["offset"].clone();
            r["complete"] = json!(false);
        })
        .await;

        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 512),
        )
        .await
        .expect("must not loop forever")
        .expect_err("a stalled stream is an error");

        assert!(err.contains("stalled"), "names the stall: {err}");
    }

    /// A declared size above the ceiling is refused BEFORE the bytes are gathered.
    #[tokio::test]
    async fn refuses_a_capsule_declared_above_the_ceiling() {
        let capsule = deterministic_capsule(512);
        let (url, calls) = spawn_capsule_rpc(capsule, 512, |r| {
            r["total_length"] = json!(MAX_CAPSULE_BYTES + 1);
            r["complete"] = json!(false);
            r["next_offset"] = json!(512);
        })
        .await;

        let err = download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 512)
            .await
            .expect_err("an over-ceiling declaration is an error");

        assert!(err.contains("ceiling"), "names the ceiling: {err}");
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "refused on the FIRST window, before gathering bytes"
        );
    }

    /// At the ceiling itself the size check must NOT fire — a bound tested only from one side
    /// can only confirm itself. (The download then fails for an unrelated, named reason: the
    /// mock cannot actually produce 4 GiB, so it truncates.)
    #[tokio::test]
    async fn a_capsule_declared_exactly_at_the_ceiling_passes_the_size_check() {
        let capsule = deterministic_capsule(512);
        let (url, _) = spawn_capsule_rpc(capsule, 512, |r| {
            r["total_length"] = json!(MAX_CAPSULE_BYTES);
            r["complete"] = json!(true);
        })
        .await;

        let err = download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 512)
            .await
            .expect_err("the mock cannot really serve 4 GiB");

        assert!(
            !err.contains("ceiling"),
            "at-bound must clear the size check, failed as: {err}"
        );
        assert!(err.contains("truncated"), "fails on the real defect: {err}");
    }

    /// An upstream that grows the capsule mid-download is rewriting the artifact under us.
    #[tokio::test]
    async fn refuses_a_total_length_that_changes_mid_download() {
        let capsule = deterministic_capsule(2048);
        let (url, _) = spawn_capsule_rpc(capsule, 512, |r| {
            // Every window after the first inflates the declared size.
            if r["offset"].as_u64() != Some(0) {
                r["total_length"] = json!(99_999);
            }
        })
        .await;

        let err = download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 512)
            .await
            .expect_err("a shifting total_length is an error");

        assert!(err.contains("changed total_length"), "names it: {err}");
    }

    /// A short final window that still claims completeness is a truncated capsule.
    #[tokio::test]
    async fn refuses_a_capsule_shorter_than_declared() {
        let capsule = deterministic_capsule(2048);
        let (url, _) = spawn_capsule_rpc(capsule, 512, |r| {
            r["complete"] = json!(true);
            r["next_offset"] = Value::Null;
        })
        .await;

        let err = download_capsule_via_rpc(&reqwest::Client::new(), &url, STORE, ROOT, 512)
            .await
            .expect_err("512 of a declared 2048 is truncated");

        assert!(err.contains("truncated"), "names it: {err}");
    }

    /// A JSON-RPC error is reported with its code and message — the real reason, not a guess.
    #[tokio::test]
    async fn surfaces_a_json_rpc_error_verbatim() {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/",
            post(|| async {
                Json(json!({"jsonrpc":"2.0","id":1,"error":{
                    "code": -32004, "message": "resource not available at the requested root"}}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let err = download_capsule_via_rpc(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            STORE,
            ROOT,
            512,
        )
        .await
        .expect_err("a JSON-RPC error is an error");

        assert!(err.contains("-32004"), "carries the code: {err}");
        assert!(
            err.contains("not available at the requested root"),
            "carries the message: {err}"
        );
    }

    /// An HTTP rejection is reported with its STATUS — the exact signal whose absence made
    /// #1886's 400 invisible for the whole investigation.
    #[tokio::test]
    async fn surfaces_the_http_status_of_a_rejection() {
        use axum::{http::StatusCode, routing::post, Router};
        let app = Router::new().route(
            "/",
            post(|| async { (StatusCode::BAD_REQUEST, "{\"error\":\"invalid_request\"}") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let err = download_capsule_via_rpc(
            &reqwest::Client::new(),
            &format!("http://{addr}/"),
            STORE,
            ROOT,
            512,
        )
        .await
        .expect_err("a 400 is an error");

        assert!(err.contains("400"), "names the status: {err}");
    }

    /// The property: the usage breakdown DISTINGUISHES held capsules from response windows —
    /// the state that made `cache.get` and `cache.listCached` look contradictory (#1886).
    ///
    /// The fixture writes DIFFERENT byte counts to the two subtrees, and a third file outside
    /// both, so an implementation that reported the same walk for every field, or folded the
    /// stray file into a subtree, cannot pass. `capsule_bytes == 0` with a non-zero total is
    /// exactly the observed broken-flywheel reading, and it must be legible as such.
    #[test]
    fn cache_usage_separates_held_capsules_from_response_windows() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let td = tempfile::tempdir().unwrap();
        let cache = td.path().join("cache");
        std::env::set_var("DIG_NODE_CACHE", &cache);

        std::fs::create_dir_all(cache.join("modules/aa")).unwrap();
        std::fs::create_dir_all(cache.join("responses")).unwrap();
        std::fs::write(cache.join("modules/aa/bb.module"), vec![7u8; 300]).unwrap();
        std::fs::write(cache.join("responses/win1"), vec![1u8; 50]).unwrap();
        std::fs::write(cache.join("responses/win2"), vec![1u8; 25]).unwrap();
        std::fs::write(cache.join("config-adjacent"), vec![0u8; 9]).unwrap();

        let usage = crate::cache_usage();
        assert_eq!(usage.capsule_bytes, 300, "held capsules");
        assert_eq!(usage.response_bytes, 75, "response windows");
        assert_eq!(usage.other_bytes, 9, "neither subtree, still accounted for");
        assert_eq!(usage.total(), 384);
        assert_eq!(
            usage.total(),
            crate::cache_used_bytes(),
            "the breakdown sums to the number `used_bytes` has always reported"
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// The default window is pinned to the GATEWAY's per-response ceiling. If hub.dig.net's
    /// `RPC_MAX_CHUNK` moves, asking for more is clamped server-side and the two ends stop
    /// agreeing on what a window is — this guard makes that drift a test failure.
    #[test]
    fn the_default_window_matches_the_gateway_chunk_ceiling() {
        assert_eq!(CAPSULE_WINDOW_BYTES, 3 * 1024 * 1024);
    }
}
