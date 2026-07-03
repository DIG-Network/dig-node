//! dig-runtime — the DIG browser's NATIVE in-process runtime.
//!
//! The browser process **is** the DIG node. `dig_runtime.dll` (a cargo `cdylib`
//! shipped next to the browser executable like `chrome.dll`) exposes a direct
//! C-ABI entrypoint, [`dig_rpc`] (`request_json -> response_json`), that the
//! browser's dig:// handler calls IN-PROCESS — there is no loopback server, no
//! socket, and no `dig-node.exe` sidecar. It runs the exact same
//! `dig_node::handle_rpc` dispatch the standalone node uses, on a shared
//! multi-thread tokio runtime owned by this library.
//!
//! Heavy Rust deps (wasmtime, tokio, reqwest, blst via the node) build freely as
//! a cargo cdylib — the route Chromium's restricted Rust/GN build can't take —
//! and run in the browser (broker) process, which is unsandboxed (full token)
//! and not ACG/JIT-locked the way renderer processes are.

use std::ffi::{c_char, CStr, CString};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::OnceLock;

use dig_node::Node;

/// The process-wide DIG runtime: the tokio runtime + the node it drives. Built
/// once, lazily, on first use (or eagerly by `dig_runtime_start`).
struct DigRuntime {
    rt: tokio::runtime::Runtime,
    node: Arc<Node>,
}

static RUNTIME: OnceLock<DigRuntime> = OnceLock::new();

fn runtime() -> &'static DigRuntime {
    RUNTIME.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("dig-runtime: tokio runtime");
        let node = Node::from_env();
        // Bring up the built-in Chia wallet in-process too (loopback UI on 9777;
        // native BLS signing in this same process). The dig:// content path uses
        // direct FFI (dig_rpc); the wallet is an interactive web UI, so it is
        // served over loopback — still in-process, no sidecar exe.
        rt.spawn(dig_wallet::run());
        DigRuntime { rt, node }
    })
}

/// Initialize the native DIG runtime (build the node + tokio runtime, load the
/// §21 identity, prepare the cache). Idempotent and cheap to call again. Optional
/// — [`dig_rpc`] initializes lazily — but the browser calls this once at startup
/// so the identity + cache are ready before the first dig:// navigation.
///
/// # Safety
/// C-ABI export for `GetProcAddress`. Takes no arguments and never unwinds across
/// the FFI boundary (any panic during init is caught).
#[no_mangle]
pub extern "C" fn dig_runtime_start() {
    let _ = std::panic::catch_unwind(|| {
        runtime();
    });
}

/// Execute one DIG JSON-RPC request in-process and return the JSON-RPC response.
///
/// `request_json` is a NUL-terminated UTF-8 JSON string owned by the caller. The
/// return value is a NUL-terminated UTF-8 JSON string owned by this library; the
/// caller MUST return it to [`dig_free`]. Returns null only on a null/invalid
/// input pointer or an allocation failure.
///
/// Blocking: drives the request to completion on the shared runtime, so callers
/// must invoke it from a thread allowed to block (e.g. a `base::MayBlock` task),
/// never the browser UI/IO thread. Concurrent calls are safe.
///
/// # Safety
/// `request_json` must be a valid NUL-terminated C string for the duration of the
/// call. The returned pointer must be freed exactly once with [`dig_free`].
#[no_mangle]
pub unsafe extern "C" fn dig_rpc(request_json: *const c_char) -> *mut c_char {
    if request_json.is_null() {
        return std::ptr::null_mut();
    }
    let req = unsafe { CStr::from_ptr(request_json) }
        .to_string_lossy()
        .into_owned();
    let out = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let rt = runtime();
        rt.rt.block_on(dig_node::handle_rpc_json(&rt.node, &req))
    }));
    match out.ok().and_then(|s| CString::new(s).ok()) {
        Some(c) => c.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Execute one wallet request in-process and return a JSON envelope of the answer.
///
/// This is the wallet counterpart to [`dig_rpc`]: the DIG browser's broker process
/// calls it to drive the per-origin wallet surface (the CHIP-0002 / chia methods)
/// DIRECTLY, with no loopback HTTP hop. It runs the SAME dispatch the loopback
/// `/api/wc/request` handler runs (`dig_wallet::wallet_dispatch`) against the same
/// process-global wallet state, so the per-origin approval gate, the unlocked
/// session, and the wallet source are shared with the loopback wallet UI.
///
/// `origin` is the calling page's web origin (supplied first-hand by the browser, so
/// — unlike a header a page could forge — it is UNSPOOFABLE and is what the approval
/// gate keys on). `request_json` is the `{method, params}` body. Both are
/// NUL-terminated UTF-8 strings owned by the caller; a null pointer or invalid UTF-8
/// yields an error envelope rather than undefined behavior.
///
/// The return value is a newly-allocated NUL-terminated UTF-8 JSON ENVELOPE
/// `{"status":<u16>,"body":<body>}`, where `status` is the HTTP-equivalent status the
/// dispatch produced (200 ok / 202 pending / 403 not-approved / 4xx-5xx errors) and
/// `body` is the dispatch's JSON body embedded as raw JSON (the `{"data":...}` /
/// `{"error":...}` value — NOT a double-encoded string). The caller MUST return the
/// pointer to [`dig_free`] (same allocation discipline as [`dig_rpc`]).
///
/// Blocking: drives the request to completion on the shared runtime, so callers must
/// invoke it from a thread allowed to block (never the browser UI/IO thread).
/// Concurrent calls are safe.
///
/// # Safety
/// `origin` and `request_json` must each be a valid NUL-terminated C string for the
/// duration of the call (or null). The returned pointer must be freed exactly once
/// with [`dig_free`].
#[no_mangle]
pub unsafe extern "C" fn dig_wallet_rpc(
    origin: *const c_char,
    request_json: *const c_char,
) -> *mut c_char {
    // Read both C strings up front; a null pointer is treated as an empty string so a
    // missing origin/body degrades to a clean wallet error, never UB. `to_string_lossy`
    // makes invalid UTF-8 lossy rather than panicking.
    let read = |p: *const c_char| -> String {
        if p.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        }
    };
    let origin = read(origin);
    let request_json = read(request_json);

    let envelope = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let rt = runtime();
        let (status, body) = rt
            .rt
            .block_on(dig_wallet::wallet_dispatch(&origin, &request_json));
        // Embed the body as RAW JSON (not a re-encoded string). It is always a JSON
        // object from `wallet_dispatch`; if it ever weren't parseable, fall back to a
        // JSON null body so the envelope itself is always valid JSON.
        let body_value: serde_json::Value =
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        serde_json::json!({ "status": status, "body": body_value }).to_string()
    }))
    // A panic during dispatch (should not happen) becomes a 500 error envelope rather
    // than crossing the FFI boundary.
    .unwrap_or_else(|_| {
        r#"{"status":500,"body":{"error":"wallet dispatch panicked"}}"#.to_string()
    });

    match CString::new(envelope) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a string previously returned by [`dig_rpc`] or [`dig_wallet_rpc`].
///
/// # Safety
/// `ptr` must be a pointer returned by [`dig_rpc`] or [`dig_wallet_rpc`] and not yet
/// freed; passing any other value (or freeing twice) is undefined behavior. Null is
/// ignored.
#[no_mangle]
pub unsafe extern "C" fn dig_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A full FFI round-trip that needs no network: an unknown method dispatches
    // through handle_rpc to the JSON-RPC "method not found" error. Exercises
    // dig_runtime_start (lazy init), dig_rpc (parse -> dispatch -> serialize),
    // and dig_free, proving the browser-side path works with no loopback server.
    #[test]
    fn ffi_roundtrip_unknown_method() {
        // Isolate the identity + cache the node creates so the test is hermetic.
        let tmp = std::env::temp_dir().join("dig-runtime-test");
        std::env::set_var("DIG_IDENTITY_DIR", tmp.join("id"));
        std::env::set_var("DIG_NODE_CACHE", tmp.join("cache"));

        dig_runtime_start();
        let req = CString::new(r#"{"jsonrpc":"2.0","id":7,"method":"nope"}"#).unwrap();
        let resp_ptr = unsafe { dig_rpc(req.as_ptr()) };
        assert!(!resp_ptr.is_null());
        let resp = unsafe { CStr::from_ptr(resp_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dig_free(resp_ptr) };
        assert!(resp.contains("method not found"), "got: {resp}");
        assert!(resp.contains("\"id\":7"), "id should round-trip: {resp}");
    }

    // The wallet FFI counterpart, needing no network: `chip0002_chainId` is a public
    // method (no origin approval, no unlocked session) that the wallet always answers
    // `mainnet`. Proves dig_wallet_rpc returns a well-formed {status, body} envelope
    // with the body embedded as RAW JSON (not double-encoded), and that dig_free frees
    // it without UB — the browser-side wallet path with no loopback server.
    #[test]
    fn wallet_ffi_roundtrip_chain_id_envelope() {
        // Isolate the identity + cache (the runtime brings up the node + wallet).
        let tmp = std::env::temp_dir().join("dig-runtime-wallet-test");
        std::env::set_var("DIG_IDENTITY_DIR", tmp.join("id"));
        std::env::set_var("DIG_NODE_CACHE", tmp.join("cache"));

        dig_runtime_start();
        let origin = CString::new("https://anything.example").unwrap();
        let req = CString::new(r#"{"method":"chip0002_chainId"}"#).unwrap();
        let resp_ptr = unsafe { dig_wallet_rpc(origin.as_ptr(), req.as_ptr()) };
        assert!(!resp_ptr.is_null());
        let resp = unsafe { CStr::from_ptr(resp_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dig_free(resp_ptr) };

        // The envelope is valid JSON: { "status": 200, "body": { "data": "mainnet" } }.
        let env: serde_json::Value = serde_json::from_str(&resp).expect("envelope is JSON");
        assert_eq!(env["status"], 200, "chainId is a 200: {resp}");
        // body is RAW JSON (an object), not a re-encoded string.
        assert!(env["body"].is_object(), "body embedded as raw JSON: {resp}");
        assert_eq!(env["body"]["data"], "mainnet", "chainId data: {resp}");
    }

    // A null origin/request pointer must yield an error envelope, never UB. (A null
    // request is an empty body → the dispatch's malformed-JSON 400 error envelope.)
    #[test]
    fn wallet_ffi_null_pointers_yield_error_envelope_not_ub() {
        let tmp = std::env::temp_dir().join("dig-runtime-wallet-null-test");
        std::env::set_var("DIG_IDENTITY_DIR", tmp.join("id"));
        std::env::set_var("DIG_NODE_CACHE", tmp.join("cache"));

        dig_runtime_start();
        let resp_ptr = unsafe { dig_wallet_rpc(std::ptr::null(), std::ptr::null()) };
        assert!(!resp_ptr.is_null(), "null inputs still return an envelope");
        let resp = unsafe { CStr::from_ptr(resp_ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { dig_free(resp_ptr) };
        let env: serde_json::Value = serde_json::from_str(&resp).expect("envelope is JSON");
        // An empty body is malformed → the 400 error envelope.
        assert_eq!(env["status"], 400, "null/empty body is a 400: {resp}");
        assert!(env["body"]["error"].is_string(), "carries an error: {resp}");
    }
}
