//! dig-runtime — the DIG browser's NATIVE in-process runtime.
//!
//! `dig_runtime.dll` (a cargo `cdylib` shipped next to the browser executable
//! like `chrome.dll`) exposes direct C-ABI entrypoints the browser calls
//! IN-PROCESS — no loopback server, no socket, no `dig-node.exe` sidecar. It has
//! three surfaces:
//!
//! * **Wallet** ([`dig_wallet_rpc`]) — the built-in Chia wallet (CHIP-0002). This
//!   is what the browser needs; the browser starts the runtime WALLET-ONLY.
//! * **Read-crypto** ([`dig_read_verify_decrypt`]) — the digstore `.dig`
//!   fetch-verify-decrypt read-crypto, exported as C-ABI. This is the SAME Rust
//!   the webpage `dig-client-wasm` wraps: ONE Rust impl (`digstore-core`), two
//!   bindings — native FFI for the browser, wasm for webpages. The browser is
//!   native, so it links + calls the Rust DIRECTLY; wasm is for webpages only.
//!   This call needs NO runtime and NO node engine — it is pure crypto over
//!   bytes the caller already fetched from an external RPC endpoint (§5.3).
//! * **Node RPC** ([`dig_rpc`]) — the full `dig_node_core::handle_rpc` dispatch,
//!   retained for OTHER consumers. The DIG Browser does NOT use it (it is a pure
//!   RPC consumer of an EXTERNAL node, super-repo #44); when the browser starts
//!   the runtime wallet-only there is no node engine and this returns an error.
//!
//! Heavy Rust deps (tokio, blst, the digstore crypto) build freely as a cargo
//! cdylib — the route Chromium's restricted Rust/GN build can't take — and run in
//! the browser (broker) process, which is unsandboxed (full token) and not
//! ACG/JIT-locked the way renderer processes are.

use std::ffi::{c_char, CStr, CString};
use std::panic::AssertUnwindSafe;
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::OnceLock;

use base64::Engine;
use digstore_core::codec::Decode;
use digstore_core::crypto::{decrypt_chunk, derive_decryption_key};
use digstore_core::{
    resource_leaf, Bytes32, MerkleProof, SecretSalt, Urn, CHAIN, DEFAULT_RESOURCE_KEY,
};

use dig_node_core::Node;

/// The process-wide DIG runtime: the tokio runtime + (optionally) the node it
/// drives. Built once, lazily, on first use (or eagerly by a `dig_runtime_start*`
/// entrypoint). `node` is `None` in WALLET-ONLY mode — the browser's mode — so no
/// node engine (no `dig_rpc`/P2P/cache) is spun up.
struct DigRuntime {
    rt: tokio::runtime::Runtime,
    node: Option<Arc<Node>>,
}

/// Build the runtime struct: the tokio runtime, and — only when `with_node` — the
/// node engine. Pure constructor: it does NOT spawn the wallet server and does NOT
/// touch the process-global [`RUNTIME`] (see [`init_global`]), so it is unit-testable
/// in isolation. `with_node == false` is WALLET-ONLY (no node engine constructed).
fn build_runtime(with_node: bool) -> DigRuntime {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("dig-runtime: tokio runtime");
    // Only construct the node engine (identity, cache, P2P wiring) in full mode.
    // Wallet-only skips it entirely — the browser runs no in-process node (#44/#47).
    let node = if with_node {
        Some(Node::from_env())
    } else {
        None
    };
    DigRuntime { rt, node }
}

static RUNTIME: OnceLock<DigRuntime> = OnceLock::new();

/// Lazily initialize the process-global runtime in the given mode and bring up the
/// in-process Chia wallet on it. The FIRST caller's `with_node` wins (`OnceLock`),
/// so a browser that calls [`dig_runtime_start_wallet`] at startup pins WALLET-ONLY
/// and a later [`dig_rpc`] finds no node engine (returns an error) rather than
/// silently spinning one up.
fn init_global(with_node: bool) -> &'static DigRuntime {
    RUNTIME.get_or_init(|| {
        let dr = build_runtime(with_node);
        // Bring up the built-in Chia wallet in-process (loopback UI on 9777; native
        // BLS signing in this same process). Present in BOTH modes — the wallet is
        // the browser's reason to load this DLL. The dig:// content path uses direct
        // FFI; the wallet is an interactive web UI, so it is served over loopback —
        // still in-process, no sidecar exe.
        dr.rt.spawn(dig_wallet::run());
        dr
    })
}

/// The FULL runtime (node engine + wallet), initializing it lazily if no
/// `dig_runtime_start*` was called yet — preserving the historical behavior of
/// [`dig_rpc`]/[`dig_wallet_rpc`] for non-browser consumers.
fn runtime() -> &'static DigRuntime {
    init_global(true)
}

/// A JSON-RPC error returned by [`dig_rpc`] when the runtime was started
/// WALLET-ONLY (the browser's mode) and therefore has no node engine. The DIG
/// Browser never calls `dig_rpc` — it consumes an EXTERNAL node over RPC (#44) —
/// so this only guards a misuse.
const NODE_UNAVAILABLE_JSONRPC: &str = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"node engine not available: dig-runtime started wallet-only"}}"#;

/// Dispatch one node JSON-RPC request, or return [`NODE_UNAVAILABLE_JSONRPC`] when
/// there is no node engine (wallet-only mode). Factored out of [`dig_rpc`] so the
/// wallet-only guard is testable without the process-global runtime.
fn dispatch_node_rpc(node: Option<&Node>, rt: &tokio::runtime::Runtime, req: &str) -> String {
    match node {
        Some(node) => rt.block_on(dig_node_core::handle_rpc_json(node, req)),
        None => NODE_UNAVAILABLE_JSONRPC.to_string(),
    }
}

/// Initialize the native DIG runtime FULLY (node engine + wallet + tokio runtime),
/// load the §21 identity, prepare the cache. Idempotent and cheap to call again.
/// This is the entrypoint for consumers that want the in-process node; the DIG
/// Browser uses [`dig_runtime_start_wallet`] instead (#44/#47).
///
/// # Safety
/// C-ABI export for `GetProcAddress`. Takes no arguments and never unwinds across
/// the FFI boundary (any panic during init is caught).
#[no_mangle]
pub extern "C" fn dig_runtime_start() {
    let _ = std::panic::catch_unwind(|| {
        init_global(true);
    });
}

/// Initialize the native DIG runtime WALLET-ONLY: bring up the built-in Chia wallet
/// (and its tokio runtime) WITHOUT the node engine — no `dig_rpc` dispatch, no P2P,
/// no content cache. This is what the DIG Browser calls at startup: it links this
/// DLL for the wallet FFI ([`dig_wallet_rpc`]) and the read-crypto FFI
/// ([`dig_read_verify_decrypt`]), and resolves content from an EXTERNAL dig-node
/// over RPC (the §5.3 ladder) — it runs no in-process node (#44/#47).
///
/// Idempotent; the FIRST `dig_runtime_start*` call fixes the mode. If the runtime
/// was already started FULL, this is a no-op (the node stays up).
///
/// # Safety
/// C-ABI export for `GetProcAddress`. Takes no arguments and never unwinds across
/// the FFI boundary (any panic during init is caught).
#[no_mangle]
pub extern "C" fn dig_runtime_start_wallet() {
    let _ = std::panic::catch_unwind(|| {
        init_global(false);
    });
}

/// Execute one DIG JSON-RPC request in-process and return the JSON-RPC response.
///
/// `request_json` is a NUL-terminated UTF-8 JSON string owned by the caller. The
/// return value is a NUL-terminated UTF-8 JSON string owned by this library; the
/// caller MUST return it to [`dig_free`]. Returns null only on a null/invalid
/// input pointer or an allocation failure. When the runtime was started WALLET-ONLY
/// there is no node engine and this returns a JSON-RPC error response.
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
        dispatch_node_rpc(rt.node.as_deref(), &rt.rt, &req)
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
/// session, and the wallet source are shared with the loopback wallet UI. The wallet
/// is present in BOTH runtime modes, so this works after [`dig_runtime_start_wallet`].
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

// ===========================================================================
// Read-crypto FFI — the digstore `.dig` verify+decrypt, native (NOT wasm).
//
// This is the SAME Rust the webpage `dig-client-wasm` wraps (`decrypt_resource`):
// ONE crypto impl in `digstore-core`, two thin bindings. The browser is native so
// it calls the Rust DIRECTLY via this FFI; wasm is ONLY for webpages (hub /
// extension / SDK). The browser's C++ URL loader fetches ciphertext + the base64
// inclusion proof from an external node (§5.3), then calls this to verify against
// the chain-anchored root and decrypt — replacing the deleted native C++
// `net::dig` verify/decrypt (the former third read-crypto copy). No runtime and no
// node engine are needed for this call.
// ===========================================================================

/// [`dig_read_verify_decrypt`] status: success.
pub const DIG_READ_OK: i32 = 0;
/// [`dig_read_verify_decrypt`] status: a malformed argument — null required pointer,
/// non-UTF-8 string, bad hex (store id / root / salt), bad base64 or proof encoding,
/// or `chunk_lens` that do not sum to `ciphertext_len`.
pub const DIG_READ_BAD_INPUT: i32 = 1;
/// [`dig_read_verify_decrypt`] status: the served bytes' Merkle inclusion proof does
/// NOT chain to the trusted (chain-anchored) root — a tampered chunk or a decoy /
/// wrong-store response. Fail-closed.
pub const DIG_READ_VERIFY_FAILED: i32 = 2;
/// [`dig_read_verify_decrypt`] status: AES-256-GCM-SIV tag verification failed — a
/// wrong key/salt or tampered ciphertext. Fail-closed.
pub const DIG_READ_DECRYPT_FAILED: i32 = 3;
/// [`dig_read_verify_decrypt`] status: an internal error (e.g. a caught panic or an
/// allocation failure). Fail-closed.
pub const DIG_READ_INTERNAL: i32 = 4;

/// Read-crypto failure classes, mapped 1:1 onto the `DIG_READ_*` status codes.
enum ReadErr {
    BadInput,
    VerifyFailed,
    DecryptFailed,
}

impl ReadErr {
    fn code(&self) -> i32 {
        match self {
            ReadErr::BadInput => DIG_READ_BAD_INPUT,
            ReadErr::VerifyFailed => DIG_READ_VERIFY_FAILED,
            ReadErr::DecryptFailed => DIG_READ_DECRYPT_FAILED,
        }
    }
}

/// Build the canonical ROOT-INDEPENDENT resource URN — the exact form whose SHA-256
/// is the retrieval key and whose bytes seed the AES key (Digstore §6.1/§7.3/§11.1).
/// Byte-identical to `dig-client-wasm`'s `canonical_resource_urn`, so the native FFI
/// derives the SAME key the webpage wasm derives.
fn canonical_resource_urn(store_id: Bytes32, resource_key: &str) -> Urn {
    Urn {
        chain: CHAIN.to_string(),
        store_id,
        root_hash: None,
        resource_key: Some(resource_key.to_string()),
    }
}

/// Decode a base64 Merkle proof (the `X-Dig-Inclusion-Proof` header wire form) into a
/// [`MerkleProof`]; the encoding is the Chia big-endian streamable codec
/// (`MerkleProof::to_bytes`).
fn decode_proof_b64(proof_b64: &str) -> Option<MerkleProof> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(proof_b64.trim().as_bytes())
        .ok()?;
    MerkleProof::from_bytes(&raw).ok()
}

/// The verification core (mirrors `dig-client-wasm`'s `verify_inclusion_core`,
/// Digstore §9.3): the served `ciphertext` must be the proof's leaf
/// (`leaf = SHA-256(ciphertext)`), the path must fold to `proof.root`, and
/// `proof.root` MUST equal the chain-anchored `trusted_root`. A decoy's proof folds
/// to its own fabricated root and so fails the final equality.
fn verify_inclusion_core(
    ciphertext: &[u8],
    proof: &MerkleProof,
    trusted_root: &Bytes32,
) -> Result<(), ReadErr> {
    if resource_leaf(ciphertext) != proof.leaf {
        return Err(ReadErr::VerifyFailed);
    }
    if !proof.verify() {
        return Err(ReadErr::VerifyFailed);
    }
    if &proof.root != trusted_root {
        return Err(ReadErr::VerifyFailed);
    }
    Ok(())
}

/// The full read pipeline (Digstore §9.3 + §11), gate-then-decrypt — the native
/// counterpart of `dig-client-wasm`'s `decrypt_resource`, over the SAME
/// `digstore-core` crypto:
///
/// 1. **Integrity** — verify the served `ciphertext`'s Merkle inclusion against the
///    chain-anchored `trusted_root_hex`.
/// 2. **Confidentiality** — derive the URN key (mixing in the private-store `salt`
///    when present), split the plain-concatenated chunk ciphertexts by `chunk_lens`
///    (per-chunk CIPHERTEXT byte lengths in order; `None`/empty => a single chunk),
///    and AES-256-GCM-SIV-open each, concatenating plaintext in order.
///
/// `resource_key` empty resolves to the §8.5 default view `index.html`. `salt` is the
/// 32-byte private-store secret salt as hex (`None`/empty => public store).
fn read_verify_decrypt_core(
    store_id_hex: &str,
    resource_key: &str,
    ciphertext: &[u8],
    proof_b64: &str,
    trusted_root_hex: &str,
    salt_hex: Option<&str>,
    chunk_lens: Option<&[u32]>,
) -> Result<Vec<u8>, ReadErr> {
    let store_id = Bytes32::from_hex(store_id_hex.trim()).map_err(|_| ReadErr::BadInput)?;
    let trusted_root = Bytes32::from_hex(trusted_root_hex.trim()).map_err(|_| ReadErr::BadInput)?;
    let salt: Option<[u8; 32]> = match salt_hex {
        None => None,
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(
            Bytes32::from_hex(s.trim())
                .map_err(|_| ReadErr::BadInput)?
                .0,
        ),
    };
    let proof = decode_proof_b64(proof_b64).ok_or(ReadErr::BadInput)?;

    // 1) integrity: the served bytes are committed under the chain-anchored root.
    verify_inclusion_core(ciphertext, &proof, &trusted_root)?;

    // 2) confidentiality: derive the key, split the plain concat, open each chunk.
    let key = if resource_key.is_empty() {
        DEFAULT_RESOURCE_KEY
    } else {
        resource_key
    };
    let canonical = canonical_resource_urn(store_id, key).canonical();
    let aes_key = derive_decryption_key(&canonical, salt.map(SecretSalt).as_ref());

    let plan: Vec<usize> = match chunk_lens {
        Some(lens) if !lens.is_empty() => lens.iter().map(|l| *l as usize).collect(),
        _ => vec![ciphertext.len()],
    };
    let total: usize = plan.iter().sum();
    if total != ciphertext.len() {
        return Err(ReadErr::BadInput);
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut p = 0usize;
    for len in plan {
        let ct = &ciphertext[p..p + len];
        p += len;
        let pt = decrypt_chunk(&aes_key, ct).map_err(|_| ReadErr::DecryptFailed)?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

// -- FFI argument readers (unsafe C-string / buffer helpers) ----------------------

/// Read a REQUIRED C string as an owned `String`; null or non-UTF-8 is [`ReadErr::BadInput`].
///
/// # Safety
/// `p`, if non-null, must be a valid NUL-terminated C string for the duration of the call.
unsafe fn read_req_str(p: *const c_char) -> Result<String, ReadErr> {
    if p.is_null() {
        return Err(ReadErr::BadInput);
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| ReadErr::BadInput)
}

/// Read an OPTIONAL C string; null (or non-UTF-8) yields `None`.
///
/// # Safety
/// `p`, if non-null, must be a valid NUL-terminated C string for the duration of the call.
unsafe fn read_opt_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(p) }
            .to_str()
            .ok()
            .map(|s| s.to_owned())
    }
}

/// Read a byte buffer; `len == 0` is the empty slice, a null pointer with `len > 0`
/// is [`ReadErr::BadInput`]. The returned slice borrows `p` for the call's duration.
///
/// # Safety
/// When `len > 0`, `p` must point to `len` initialized bytes valid for the call.
unsafe fn read_bytes<'a>(p: *const u8, len: usize) -> Result<&'a [u8], ReadErr> {
    if len == 0 {
        Ok(&[])
    } else if p.is_null() {
        Err(ReadErr::BadInput)
    } else {
        Ok(unsafe { slice::from_raw_parts(p, len) })
    }
}

/// Read an optional `u32` array as an owned `Vec`; `len == 0` or null yields `None`.
///
/// # Safety
/// When `len > 0` and `p` is non-null, `p` must point to `len` initialized `u32`s.
unsafe fn read_lens(p: *const u32, len: usize) -> Option<Vec<u32>> {
    if len == 0 || p.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(p, len) }.to_vec())
    }
}

/// Verify + decrypt one served DIG resource, trustlessly, and return the plaintext.
///
/// This is the browser's read-crypto: after its C++ URL loader fetches `ciphertext`
/// and the base64 inclusion `proof_b64` from an external node (§5.3 ladder) and
/// resolves the chain-anchored `trusted_root_hex`, it calls this to (1) verify the
/// bytes' Merkle inclusion against that root and (2) AES-256-GCM-SIV-decrypt them —
/// fail-closed. It is the SAME `digstore-core` crypto the webpage `dig-client-wasm`
/// wraps as `decryptResource`; the browser links this Rust directly (no wasm).
///
/// Inputs (all borrowed for the call only):
/// - `store_id_hex` — 64-hex store id (required).
/// - `resource_key` — the resource path (required; empty resolves to `index.html`).
/// - `ciphertext` / `ciphertext_len` — the served ciphertext (the plain concatenation
///   of the chunk ciphertexts; `ciphertext_len == 0` allowed with a null pointer).
/// - `proof_b64` — base64 Merkle inclusion proof (required).
/// - `trusted_root_hex` — 64-hex chain-anchored root the proof MUST chain to (required).
/// - `salt_hex` — 64-hex private-store secret salt, or NULL/empty for a public store.
/// - `chunk_lens` / `chunk_lens_len` — per-chunk CIPHERTEXT byte lengths in order;
///   pass NULL/0 for the common single-chunk resource. They MUST sum to `ciphertext_len`.
///
/// Output: on success (`DIG_READ_OK`) `*out_ptr`/`*out_len` receive a heap buffer of
/// plaintext the caller MUST free with [`dig_bytes_free`]. On ANY failure a `DIG_READ_*`
/// error code is returned and `*out_ptr`/`*out_len` are set to null/0 (nothing to free).
///
/// Return: one of [`DIG_READ_OK`], [`DIG_READ_BAD_INPUT`], [`DIG_READ_VERIFY_FAILED`],
/// [`DIG_READ_DECRYPT_FAILED`], [`DIG_READ_INTERNAL`].
///
/// # Safety
/// Every non-null pointer argument must be valid for the duration of the call per its
/// documented length. `out_ptr` and `out_len` must be valid, writable pointers. The
/// buffer returned via `out_ptr` must be freed exactly once with [`dig_bytes_free`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn dig_read_verify_decrypt(
    store_id_hex: *const c_char,
    resource_key: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
    proof_b64: *const c_char,
    trusted_root_hex: *const c_char,
    salt_hex: *const c_char,
    chunk_lens: *const u32,
    chunk_lens_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // Without out-params there is no way to hand back the plaintext.
    if out_ptr.is_null() || out_len.is_null() {
        return DIG_READ_BAD_INPUT;
    }
    // Define the outputs up front so every failure path leaves nothing to free.
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<Vec<u8>, ReadErr> {
        let store_id_hex = unsafe { read_req_str(store_id_hex) }?;
        let resource_key = unsafe { read_req_str(resource_key) }?;
        let proof_b64 = unsafe { read_req_str(proof_b64) }?;
        let trusted_root_hex = unsafe { read_req_str(trusted_root_hex) }?;
        let salt = unsafe { read_opt_str(salt_hex) };
        let ct = unsafe { read_bytes(ciphertext, ciphertext_len) }?;
        let lens = unsafe { read_lens(chunk_lens, chunk_lens_len) };
        read_verify_decrypt_core(
            &store_id_hex,
            &resource_key,
            ct,
            &proof_b64,
            &trusted_root_hex,
            salt.as_deref(),
            lens.as_deref(),
        )
    }));

    match result {
        Ok(Ok(plaintext)) => {
            // Hand the plaintext to C as a boxed slice; the caller frees it with
            // dig_bytes_free (which reconstitutes the same Box<[u8]>).
            let mut boxed = plaintext.into_boxed_slice();
            let len = boxed.len();
            let raw = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            unsafe {
                *out_ptr = raw;
                *out_len = len;
            }
            DIG_READ_OK
        }
        Ok(Err(e)) => e.code(),
        Err(_) => DIG_READ_INTERNAL,
    }
}

/// Free a plaintext buffer previously returned by [`dig_read_verify_decrypt`].
///
/// # Safety
/// `ptr`/`len` must be exactly the pair a single [`dig_read_verify_decrypt`] success
/// produced, not yet freed. A null `ptr` is ignored. Passing any other pointer/length,
/// or freeing twice, is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn dig_bytes_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::codec::Encode;
    use digstore_core::crypto::encrypt_chunk;
    use digstore_core::{MerkleTree, ProofStep};

    // ---- runtime split (#47) ---------------------------------------------------

    // The browser's mode: a wallet-only runtime constructs NO node engine, yet its
    // tokio runtime is live (the wallet FFI drives it). Uses the pure `build_runtime`
    // constructor so it never touches the process-global RUNTIME the full-mode FFI
    // tests below rely on.
    #[test]
    fn build_runtime_wallet_only_has_no_node_engine() {
        let dr = build_runtime(false);
        assert!(
            dr.node.is_none(),
            "wallet-only runtime must not construct the node engine"
        );
        // The tokio runtime is usable.
        assert_eq!(dr.rt.block_on(async { 1 + 1 }), 2);
    }

    // The full runtime still constructs the node engine (other consumers keep it).
    #[test]
    fn build_runtime_full_has_node_engine() {
        let tmp = std::env::temp_dir().join("dig-runtime-buildfull");
        std::env::set_var("DIG_IDENTITY_DIR", tmp.join("id"));
        std::env::set_var("DIG_NODE_CACHE", tmp.join("cache"));
        let dr = build_runtime(true);
        assert!(
            dr.node.is_some(),
            "full runtime must construct the node engine"
        );
    }

    // dig_rpc with no node engine (wallet-only) returns a well-formed JSON-RPC error,
    // never a panic. Exercised via the same helper dig_rpc uses, without the global.
    #[test]
    fn node_rpc_without_engine_returns_jsonrpc_error() {
        let dr = build_runtime(false);
        let resp = dispatch_node_rpc(
            dr.node.as_deref(),
            &dr.rt,
            r#"{"jsonrpc":"2.0","id":1,"method":"anything"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&resp).expect("error is valid JSON");
        assert!(v["error"].is_object(), "carries a JSON-RPC error: {resp}");
        assert!(
            resp.contains("node engine not available"),
            "explains wallet-only: {resp}"
        );
    }

    // ---- read-crypto FFI (#44 item 2) -----------------------------------------

    // Build a valid served response (ciphertext, base64 proof, root hex) exactly as
    // the commit/serve path produces it — the same construction dig-client-wasm's
    // own parity test uses. A real sibling leaf makes the proof carry a fold step.
    fn make_served(
        store: Bytes32,
        resource: &str,
        chunks: &[&[u8]],
        salt: Option<[u8; 32]>,
    ) -> (Vec<u8>, Vec<u32>, String, String) {
        let canonical = Urn {
            chain: CHAIN.to_string(),
            store_id: store,
            root_hash: None,
            resource_key: Some(resource.to_string()),
        }
        .canonical();
        let key = derive_decryption_key(&canonical, salt.map(SecretSalt).as_ref());
        let mut ct = Vec::new();
        let mut lens = Vec::new();
        for chunk in chunks {
            let c = encrypt_chunk(&key, chunk);
            lens.push(c.len() as u32);
            ct.extend_from_slice(&c);
        }
        let leaf = resource_leaf(&ct);
        // Two-leaf generation so the proof carries a real sibling step (not a bare leaf).
        let sibling = Bytes32([0x99u8; 32]);
        let tree = MerkleTree::from_leaves(vec![leaf, sibling]);
        let root = tree.root();
        let proof = MerkleProof {
            leaf,
            path: vec![ProofStep {
                hash: sibling,
                is_left: false,
            }],
            root,
        };
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof.to_bytes());
        (ct, lens, proof_b64, root.to_hex())
    }

    // Drive the C-ABI end to end and collect the plaintext (or the status on failure).
    fn ffi_call(
        store_hex: &str,
        resource: &str,
        ct: &[u8],
        proof_b64: &str,
        root_hex: &str,
        salt_hex: Option<&str>,
        chunk_lens: Option<&[u32]>,
    ) -> Result<Vec<u8>, i32> {
        let store_c = CString::new(store_hex).unwrap();
        let res_c = CString::new(resource).unwrap();
        let proof_c = CString::new(proof_b64).unwrap();
        let root_c = CString::new(root_hex).unwrap();
        let salt_c = salt_hex.map(|s| CString::new(s).unwrap());
        let salt_ptr = salt_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let (lens_ptr, lens_len) = match chunk_lens {
            Some(l) => (l.as_ptr(), l.len()),
            None => (ptr::null(), 0),
        };
        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            dig_read_verify_decrypt(
                store_c.as_ptr(),
                res_c.as_ptr(),
                ct.as_ptr(),
                ct.len(),
                proof_c.as_ptr(),
                root_c.as_ptr(),
                salt_ptr,
                lens_ptr,
                lens_len,
                &mut out_ptr,
                &mut out_len,
            )
        };
        if status != DIG_READ_OK {
            assert!(out_ptr.is_null(), "failure must leave nothing to free");
            return Err(status);
        }
        let plaintext = unsafe { slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { dig_bytes_free(out_ptr, out_len) };
        Ok(plaintext)
    }

    #[test]
    fn read_verify_decrypt_public_single_chunk_round_trip() {
        let store = Bytes32([5u8; 32]);
        let plaintext = b"<!doctype html><title>dig</title>".to_vec();
        let (ct, _lens, proof_b64, root_hex) =
            make_served(store, "index.html", &[&plaintext], None);
        // Single-chunk: pass NULL chunk_lens (the whole blob is one ciphertext).
        let got = ffi_call(
            &store.to_hex(),
            "index.html",
            &ct,
            &proof_b64,
            &root_hex,
            None,
            None,
        )
        .expect("verify+decrypt succeeds");
        assert_eq!(got, plaintext);
    }

    #[test]
    fn read_verify_decrypt_empty_resource_key_defaults_index_html() {
        let store = Bytes32([6u8; 32]);
        let plaintext = b"default view".to_vec();
        // Served under index.html; the caller passes an EMPTY resource key.
        let (ct, _lens, proof_b64, root_hex) =
            make_served(store, "index.html", &[&plaintext], None);
        let got = ffi_call(&store.to_hex(), "", &ct, &proof_b64, &root_hex, None, None)
            .expect("empty key resolves to index.html");
        assert_eq!(got, plaintext);
    }

    #[test]
    fn read_verify_decrypt_private_salt_round_trip() {
        let store = Bytes32([0xABu8; 32]);
        let salt = [0x42u8; 32];
        let plaintext = b"secret page".to_vec();
        let (ct, _lens, proof_b64, root_hex) =
            make_served(store, "secret/page.html", &[&plaintext], Some(salt));
        let salt_hex = hex::encode(salt);
        let got = ffi_call(
            &store.to_hex(),
            "secret/page.html",
            &ct,
            &proof_b64,
            &root_hex,
            Some(&salt_hex),
            None,
        )
        .expect("private-store verify+decrypt succeeds");
        assert_eq!(got, plaintext);

        // The WRONG salt (public read) must fail the GCM-SIV tag — fail-closed.
        let status = ffi_call(
            &store.to_hex(),
            "secret/page.html",
            &ct,
            &proof_b64,
            &root_hex,
            None,
            None,
        )
        .expect_err("missing salt yields a wrong key");
        assert_eq!(status, DIG_READ_DECRYPT_FAILED);
    }

    #[test]
    fn read_verify_decrypt_multi_chunk_round_trip() {
        let store = Bytes32([7u8; 32]);
        let part1 = b"first-chunk-".to_vec();
        let part2 = b"second-chunk".to_vec();
        let (ct, lens, proof_b64, root_hex) =
            make_served(store, "big.bin", &[&part1, &part2], None);
        let mut expected = part1.clone();
        expected.extend_from_slice(&part2);
        let got = ffi_call(
            &store.to_hex(),
            "big.bin",
            &ct,
            &proof_b64,
            &root_hex,
            None,
            Some(&lens),
        )
        .expect("multi-chunk verify+decrypt succeeds");
        assert_eq!(got, expected);
    }

    #[test]
    fn read_verify_decrypt_tampered_ciphertext_fails_closed() {
        let store = Bytes32([8u8; 32]);
        let plaintext = b"trusted content".to_vec();
        let (mut ct, _lens, proof_b64, root_hex) =
            make_served(store, "index.html", &[&plaintext], None);
        ct[0] ^= 0xFF; // tamper: the leaf no longer matches the proof
        let status = ffi_call(
            &store.to_hex(),
            "index.html",
            &ct,
            &proof_b64,
            &root_hex,
            None,
            None,
        )
        .expect_err("tampered bytes must not decrypt");
        assert_eq!(status, DIG_READ_VERIFY_FAILED);
    }

    #[test]
    fn read_verify_decrypt_decoy_wrong_root_rejected() {
        let store = Bytes32([9u8; 32]);
        let plaintext = b"decoy".to_vec();
        let (ct, _lens, proof_b64, _root_hex) =
            make_served(store, "index.html", &[&plaintext], None);
        // The real chain-anchored root differs from the served proof's root.
        let wrong_root = Bytes32([0u8; 32]).to_hex();
        let status = ffi_call(
            &store.to_hex(),
            "index.html",
            &ct,
            &proof_b64,
            &wrong_root,
            None,
            None,
        )
        .expect_err("a proof that does not chain to the trusted root is rejected");
        assert_eq!(status, DIG_READ_VERIFY_FAILED);
    }

    #[test]
    fn read_verify_decrypt_bad_hex_is_bad_input() {
        let status = ffi_call(
            "not-hex",
            "index.html",
            b"whatever",
            "AAAA",
            &Bytes32([1u8; 32]).to_hex(),
            None,
            None,
        )
        .expect_err("a malformed store id is rejected");
        assert_eq!(status, DIG_READ_BAD_INPUT);
    }

    #[test]
    fn read_verify_decrypt_null_out_params_is_bad_input() {
        let status = unsafe {
            dig_read_verify_decrypt(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(status, DIG_READ_BAD_INPUT);
    }

    // ---- existing FFI surface (full runtime, unchanged behavior) ---------------

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
