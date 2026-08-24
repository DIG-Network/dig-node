//! dig-wallet — the DIG Browser's built-in Chia wallet surface.
//!
//! A loopback-only axum server that hosts the wallet page the browser opens at 127.0.0.1, the
//! WalletConnect responder that backs `window.chia`, the per-origin consent gate a dapp must pass,
//! and the local cache/settings surface.
//!
//! # This process holds no user key and signs nothing (§908, dig_ecosystem#1701)
//!
//! It used to. Earlier builds created and restored a 24-word wallet here, sealed the seed at rest,
//! unlocked it into memory, BLS-signed payments over `POST /api/send`, and served the whole
//! CHIP-0002 method surface from that local signer. It must not, and does not: dig-node#327 removed
//! the surface, and the user's spend key now lives in their own Sage wallet.
//!
//! What remains is a ROUTER. [`wc_dispatch`] answers the three keyless handshake methods
//! (`chip0002_chainId`, `chip0002_connect`, `chip0002_getMethods`) and forwards every other method
//! to Sage over the WalletConnect requester session, via the delegate bridge the wallet page pumps.
//! There is no local branch to fall through to and no setting that selects one, so a key/sign request
//! either reaches Sage or is refused.
//!
//! The absences are load-bearing and are meant to be noticed:
//!
//! - [`AppState`] has no unlocked-session field, so a signer would have nothing to read.
//! - [`crate::seed_store::encrypt_seed`] is `#[cfg(test)]`, so production code that sealed a user
//!   seed would not compile.
//! - The `DIG_WALLET_ALLOW_BROADCAST` dry-run gate is gone with the signer it gated. Sage's own
//!   confirmation is the gate now, which is where it belongs: with the key.
//!
//! # A seed an older build left behind
//!
//! Such a file is never read, used or deleted here. `GET /api/status` reports `"custodied"` while one
//! exists so both UI surfaces can say so, and it is recovered OFFLINE with `dign wallet export-seed`
//! ([`crate::seed_export`]) — never through a served route.
//!
//! The node's OWN operator identity ([`crate::autoseed`]) is a different thing that shares the same
//! at-rest primitive: a machine credential that never leaves the host, not custody of anyone's funds.
//! It stays.
use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

// `CapsuleStore` is seam 6's public surface (#1285 W1b-4) — brings `cache_list_cached` /
// `cache_remove_cached` / `cache_fetch_and_cache` into scope for the fully-qualified
// `dig_node_core::Node` calls below.
use dig_node_core::CapsuleStore;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};

// #205 phase-2: the Sage-parity wallet RPC — direct-peer chain sync, a local SQLite
// wallet DB, the chia-query/coinset fallback tier, and the dual-transport server that
// re-serves Sage's `endpoints.json` method surface byte-compatibly. This is an ADDITIVE
// surface (distinct from the CHIP-0002 `window.chia` dapp responder above and the
// wallet-UI host); see `SPEC.md §18` and `docs/design/dig-node-sage-parity-rpc.md`.
pub mod sage;

// #205 PR4: unified at-rest seed custody via `dig-keystore` (new writes), with
// backwards-compatible reads of the legacy `digstore_chain::seed` on-disk format (an old seed
// file keeps opening — see the module docs).
mod seed_store;

pub mod seed_export;

// #277: unattended wallet bootstrap — detect a missing seed on start and mint one, sealed
// under a machine-held device key. Every failure arm is fail-closed and writes nothing.
pub mod autoseed;

/// One wallet request awaiting Sage. When the wallet source is `Sage`, `wc_dispatch`
/// cannot reach the relay itself (the live WalletConnect requester SignClient lives
/// in the wallet UI page, the one tab that stays open), so it parks the call here and
/// `await`s `tx`. The page long-polls `/api/wc/delegate/next`, forwards `{method,
/// params}` to Sage over the session, and POSTs Sage's result/error back to
/// `/api/wc/delegate/result`, which fulfils `tx`. This keeps `window.chia` and the
/// per-origin consent gate completely unchanged — only the *signer* moves to Sage.
struct DelegateRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
    /// Fulfilled with Sage's bare result (`Ok`) or an error message (`Err`) by
    /// `/api/wc/delegate/result`.
    tx: oneshot::Sender<Result<serde_json::Value, String>>,
}

/// The requester-side delegate bridge between `wc_dispatch` and the in-page Sage
/// WalletConnect client (see [`DelegateRequest`]). `queue` holds requests the page
/// has not yet picked up; `waiters` holds the oneshot senders for requests in flight
/// at Sage, keyed by request id. Lives only while the wallet page is open (the same
/// v1 persistence caveat the responder documents); a dropped page drops the waiters,
/// surfacing as a clean "Sage did not respond" rather than a hang.
#[derive(Default)]
struct DelegateBridge {
    queue: VecDeque<DelegateRequest>,
    waiters: std::collections::HashMap<u64, oneshot::Sender<Result<serde_json::Value, String>>>,
    next_id: AtomicU64,
}

/// Everything the embedded wallet holds in memory.
///
/// There is no unlocked-session field and no wallet-source field, and their absence is the
/// point: this process cannot hold a user mnemonic, so there is no state for a signer to
/// read, and there is exactly one place a key/sign request can be answered from — Sage.
#[derive(Default)]
struct AppState {
    approvals: Mutex<Approvals>,
    /// Requester→Sage delegate bridge — the only route a key/sign method has.
    delegate: Mutex<DelegateBridge>,
}

/// Per-origin dapp connection state. `approved` is the user's allow-list (which
/// web origins may use the wallet), persisted to disk so it survives restarts.
/// `pending` holds origins that called `connect` and are awaiting the user's
/// approval in the wallet UI (in-memory — a pending request doesn't outlive the
/// session).
struct Approvals {
    approved: BTreeSet<String>,
    pending: BTreeSet<String>,
}

impl Default for Approvals {
    fn default() -> Self {
        Approvals {
            approved: load_approved(),
            pending: BTreeSet::new(),
        }
    }
}

impl Approvals {
    /// The wallet's own loopback origin is implicitly trusted (the wallet UI
    /// itself), so it never needs a connect handshake.
    fn is_approved(&self, origin: &str) -> bool {
        is_self_origin(origin) || self.approved.contains(origin)
    }
}

/// The loopback port the wallet serves on (default 9777; `DIG_WALLET_PORT`).
fn wallet_port() -> u16 {
    std::env::var("DIG_WALLET_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9777)
}

/// True only for the wallet's OWN page origin (exact host + port) — the UI is
/// trusted. Deliberately NOT all of 127.0.0.1: another local app on a different
/// port must still go through the approval gate, or any localhost process could
/// spend the wallet unprompted.
fn is_self_origin(origin: &str) -> bool {
    let port = wallet_port();
    origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
}

/// Path to the encrypted seed file (per-user, off the profile dir).
fn seed_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("DigWallet").join("seed.bin")
}

/// Path to the persisted dapp allow-list (next to the seed file).
fn connections_path() -> PathBuf {
    seed_path()
        .parent()
        .map(|p| p.join("connections.json"))
        .unwrap_or_else(|| PathBuf::from("connections.json"))
}

/// Load the approved-origins allow-list from disk (empty if absent/corrupt).
fn load_approved() -> BTreeSet<String> {
    std::fs::read(connections_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

/// Persist the approved-origins allow-list.
fn save_approved(approved: &BTreeSet<String>) {
    let path = connections_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&approved.iter().collect::<Vec<_>>()) {
        let _ = std::fs::write(path, json);
    }
}

/// Whether a wallet is on disk.
///
/// Uses [`autoseed::presence`] rather than `Path::exists()`, and answers `true` when the question
/// cannot be answered at all. `exists()` reports a metadata failure — permission denied, a locked
/// file, a transient I/O error, an unmounted volume — as a plain `false`, which here would render
/// "no wallet on this device" over a wallet that is merely unreadable this second, and invite the
/// user to create a replacement. Treating the unknown case as "a wallet exists" is the direction
/// that cannot lose anything.
fn wallet_exists() -> bool {
    !matches!(
        autoseed::presence(&seed_path()),
        Ok(autoseed::Presence::Absent)
    )
}

#[derive(Serialize)]
struct StatusResp {
    /// `"delegated"` (the normal state: Sage answers every key/sign method) or
    /// `"custodied"` (a seed from an older, custodying build is still on disk and should be
    /// exported off this node with `dign wallet export-seed`).
    state: &'static str,
    address: Option<String>,
}

/// A failure body, shaped the way every wallet endpoint reports one.
#[derive(Serialize)]
struct ErrResp {
    error: String,
}

/// What the wallet page renders on load.
///
/// `"custodied"` reports a seed still at rest from a build that custodied one — it is NOT
/// usable here and the page says so, pointing at `dign wallet export-seed`. Otherwise
/// `"delegated"`: key and signing requests go to Sage. The old `"locked"`/`"unlocked"`
/// states are gone because there is no session to be in either of them.
async fn status() -> impl IntoResponse {
    Json(StatusResp {
        state: if wallet_exists() {
            "custodied"
        } else {
            "delegated"
        },
        address: None,
    })
}

// ---- My Stores: the wallet's own DataLayer stores as capsules ----------------
//
// A user's DataLayer stores are discovered across the HD wallet and reported as
// CAPSULES — the canonical `storeId:rootHash` identity (`digstore_core::Capsule`).
// `/api/stores` lists every store's CURRENT capsule + which HD index owns it;

async fn index() -> Html<&'static str> {
    Html(UI_HTML)
}

/// The bundled WalletConnect responder (esbuild IIFE exposing `window.DigWC`).
/// Served as a static asset the wallet page loads with `<script src>`. Checked in
/// (regenerated via `wc/build.mjs`) so the crate builds offline — no npm at build
/// time. Loopback only, same as the rest of the wallet.
async fn wc_bundle_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        WC_BUNDLE_JS,
    )
}

/// The DIG protocol settings page (loopback). The browser opens it at
/// `dig://settings`, which the dig:// loader redirects here.
async fn settings_page() -> Html<&'static str> {
    Html(SETTINGS_HTML)
}

/// Current local-cache configuration: the LRU capacity ceiling and the bytes
/// currently on disk. Both come from `dig-node`, the single source of truth for
/// the native cache (so the CLI, the loader, and this UI agree).
#[derive(serde::Serialize)]
struct DigConfig {
    cache_cap_bytes: u64,
    cache_used_bytes: u64,
}

async fn dig_config_get() -> Json<DigConfig> {
    Json(DigConfig {
        cache_cap_bytes: dig_node_core::cache_cap_bytes(),
        cache_used_bytes: dig_node_core::cache_used_bytes(),
    })
}

#[derive(serde::Deserialize)]
struct SetDigConfig {
    cache_cap_bytes: u64,
}

/// Clamp a requested cache cap to a sane minimum. A fat-fingered "0" must not
/// disable caching entirely (that would defeat local-first and hammer
/// rpc.dig.net), so the cap floors at 64 MiB.
fn floored_cache_cap(requested: u64) -> u64 {
    const MIN_CAP: u64 = 64 * 1024 * 1024;
    requested.max(MIN_CAP)
}

async fn dig_config_set(Json(req): Json<SetDigConfig>) -> impl IntoResponse {
    let cap = floored_cache_cap(req.cache_cap_bytes);
    match dig_node_core::set_cache_cap_bytes(cap) {
        Ok(()) => (
            StatusCode::OK,
            Json(DigConfig {
                cache_cap_bytes: cap,
                cache_used_bytes: dig_node_core::cache_used_bytes(),
            }),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Purge the entire local DIG cache. Content stays available — it just falls
/// back to rpc.dig.net on next visit and re-warms the cache.
async fn dig_cache_clear() -> impl IntoResponse {
    dig_node_core::clear_cache();
    StatusCode::NO_CONTENT
}

// ---- Cached-store manager (#32) ---------------------------------------------
//
// The DIG settings "Cached stores" card manages the per-capsule local cache:
// every cached store generation is one CAPSULE — the canonical `storeId:rootHash`
// identity (`digstore_core::Capsule`) — keyed on disk at
// `<cache>/modules/<storeId>/<root>.module`. These endpoints back that card by
// calling the dig-node public cache fns DIRECTLY on a `Node::from_env()` (the same
// cache dir / config the loader and CLI use — no extra process / port).
//
// They are wallet-local (self-origin gated): only the DIG settings page may list /
// remove / fetch capsules, never a dapp page (the cache is the user's local store,
// not a dapp-facing surface). `is_self_origin` uses the unspoofable `Origin` header.

/// One cached capsule in the settings table: its capsule identity (`storeId:rootHash`),
/// the store id + root separately (so the UI can show/truncate each), the on-disk size,
/// and the last-used (LRU recency) timestamp. Mirrors [`dig_node_core::CachedCapsule`] one to
/// one; rendered by [`cached_capsule_json`] so the wire shape is unit-tested.
fn cached_capsule_json(c: &dig_node_core::CachedCapsule) -> serde_json::Value {
    serde_json::json!({
        // The canonical storeId:rootHash identity (== digstore_core::Capsule::canonical()).
        "capsule": format!("{}:{}", c.store_id, c.root),
        "store_id": c.store_id,
        "root": c.root,
        "size_bytes": c.size_bytes,
        "last_used_unix_ms": c.last_used_unix_ms,
    })
}

/// List every cached capsule (`storeId:rootHash`) with its size + last-used time, for the
/// DIG settings "Cached stores" table. Self-origin only (the local cache is the user's,
/// not a dapp surface). Reads via `dig_node_core::Node::cache_list_cached` on a fresh
/// `Node::from_env()` — the same cache dir the loader/CLI use.
async fn dig_cache_list(headers: HeaderMap) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node_core::Node::from_env();
    let cached = node.cache_list_cached().await;
    let list: Vec<_> = cached.iter().map(cached_capsule_json).collect();
    (StatusCode::OK, Json(serde_json::json!({ "cached": list }))).into_response()
}

#[derive(Deserialize)]
struct CacheCapsuleReq {
    /// Store id, lowercase 64-hex (the capsule's head).
    store_id: String,
    /// Generation root hash, lowercase 64-hex (the capsule's tail).
    root: String,
}

/// Remove one cached capsule (`storeId:rootHash`) from the local cache. Idempotent: a
/// capsule that isn't cached returns `removed:false`. Content stays available — it just
/// re-fetches from rpc.dig.net on next visit. Self-origin only. Delegates to
/// `dig_node_core::Node::cache_remove_cached`, which validates the hex + guards path traversal.
async fn dig_cache_remove(headers: HeaderMap, Json(req): Json<CacheCapsuleReq>) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node_core::Node::from_env();
    match node.cache_remove_cached(&req.store_id, &req.root).await {
        Ok(removed) => (
            StatusCode::OK,
            Json(serde_json::json!({ "removed": removed })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ErrResp { error: e })).into_response(),
    }
}

/// Fetch a capsule (`storeId:rootHash`) into the local cache on demand (the settings
/// "Cache a capsule" sub-card). May be slow (a network whole-store sync from the §21
/// remote), so the UI shows a spinner. Self-origin only. Delegates to
/// `dig_node_core::Node::cache_fetch_and_cache`; a failed fetch is reported in-band
/// (`status:"failed"`) so the manager shows it without treating it as a transport error.
async fn dig_cache_fetch(headers: HeaderMap, Json(req): Json<CacheCapsuleReq>) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node_core::Node::from_env();
    match node.cache_fetch_and_cache(&req.store_id, &req.root).await {
        Ok((size_bytes, served_root)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "cached",
                "size_bytes": size_bytes,
                "served_root": served_root,
            })),
        )
            .into_response(),
        // In-band failure (no §21 identity, not authorized, or the served root differs).
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "failed", "message": e })),
        )
            .into_response(),
    }
}

// ---- DIG settings: WalletConnect projectId, public key, key export ----------
//
// These endpoints back the DIG settings page (`dig://settings`). Two of them
// touch secrets and so are restricted to the wallet's OWN loopback origin
// (`is_self_origin`): the master mnemonic export and the projectId setter. They
// are deliberately NOT routed through `/api/wc/request`, so no dapp / injected
// `window.chia` / WC session can reach them — see `wc_dispatch`, whose method
// set has no export/projectId/key-material path.

/// The effective WalletConnect projectId surfaced to the settings page.
#[derive(Serialize)]
struct WcProjectIdResp {
    /// The effective projectId (persisted config > `DIG_WALLET_WC_PROJECT_ID`),
    /// or `null` when none is configured.
    project_id: Option<String>,
    /// `true` iff a projectId is configured (relay can pair); drives the
    /// "WalletConnect not configured" UI state when `false`.
    configured: bool,
}

/// Current effective WalletConnect projectId (config value, else env default).
/// Readable by the wallet UI so the in-page WC responder can boot the relay with
/// it (or show the "not configured" state).
async fn wc_project_id_get() -> Json<WcProjectIdResp> {
    let id = dig_node_core::wc_project_id();
    Json(WcProjectIdResp {
        configured: id.is_some(),
        project_id: id,
    })
}

#[derive(Deserialize)]
struct SetWcProjectId {
    project_id: String,
}

/// Persist the WalletConnect projectId (DIG settings). Restricted to the wallet's
/// own origin — only the settings UI may change it, never a dapp. A blank value
/// clears the override (falls back to the env default).
async fn wc_project_id_set(headers: HeaderMap, Json(req): Json<SetWcProjectId>) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "settings are wallet-local only").into_response();
    }
    match dig_node_core::set_wc_project_id(&req.project_id) {
        Ok(()) => {
            let id = dig_node_core::wc_project_id();
            (
                StatusCode::OK,
                Json(WcProjectIdResp {
                    configured: id.is_some(),
                    project_id: id,
                }),
            )
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---- WalletConnect / CHIP-0002 dapp signer ----------------------------------
//
// The in-page WalletConnect client (loopback UI) pairs with dapps over the WC
// relay and forwards each CHIP-0002 / chia request here. The cryptographic core
// lives in `digstore_chain::chip0002` (byte-exact to Sage); this layer is just
// routing + the unlocked-session gate.

/// A single WC request forwarded from the in-page WC client.
#[derive(Deserialize)]
struct WcRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Whether a WC method requires an unlocked wallet. The handshake + introspection
/// methods (`chainId`, `connect`, `getMethods`) are answered without one; anything
/// that reads keys or signs requires an unlocked session.
fn wc_method_needs_wallet(method: &str) -> bool {
    !matches!(
        method,
        "chip0002_chainId" | "chip0002_connect" | "chip0002_getMethods"
    )
}

/// The full catalogue of dispatchable `window.chia` / WC methods this wallet serves,
/// advertised by `chip0002_getMethods` so an agent/dapp can introspect the surface
/// without scraping prose (agent-friendly self-description). Kept in sync with the
/// `wc_dispatch` match arms; the `wc_dispatch_method_catalogue_matches_dispatch` test
/// guards against drift. Export-class methods are deliberately ABSENT — they are never
/// dispatchable (see `is_export_class_method`).
const WC_METHOD_CATALOGUE: &[&str] = &[
    // Handshake + introspection (no wallet needed).
    "chip0002_chainId",
    "chip0002_connect",
    "chip0002_getMethods",
    // CHIP-0002 keys + signing.
    "chip0002_getPublicKeys",
    "chip0002_signMessage",
    "chip0002_signCoinSpends",
    "chip0002_getAssetBalance",
    "chip0002_getAssetCoins",
    // chia_* wallet surface.
    "chia_getAddress",
    "chia_signMessageByAddress",
    "chia_send",
    "chia_getTransactions",
    "chia_getNfts",
    "chia_transferNft",
    "chia_mintNft",
    "chia_bulkMintNfts",
    "chia_getDids",
    "chia_createDidWallet",
    "chia_transferDid",
    "chia_getOfferSummary",
    "chia_createOffer",
    "chia_takeOffer",
    "chia_cancelOffer",
    // Local on-chain STORE lifecycle (#95/#96 Pass B).
    "chia_mintStore",
    "chia_advanceStore",
    "chia_meltStore",
    "chia_setStoreDelegation",
    "chia_setStoreOwnership",
    // Advanced coin types (power-user).
    "dig_clawbackSend",
    "dig_clawbackClaim",
    "dig_clawbackRecover",
    "dig_optionCreate",
    "dig_streamCreate",
    "dig_streamClaim",
    "dig_streamClawback",
    "dig_vaultCreate",
    "dig_vcVerify",
];

/// The per-origin permission decision for a WC request. A dapp's web origin
/// (from the unspoofable HTTP `Origin` header) must be explicitly approved by the
/// user before it can read keys or request signatures.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// No origin approval needed (e.g. `chainId`).
    Public,
    /// Origin is approved — proceed.
    Allowed,
    /// `connect` from an unapproved origin — record it as pending and ask the user.
    NeedsApproval,
    /// A key/sign method from an unapproved origin — refuse; it must `connect` first.
    Forbidden,
}

/// Decide what to do with `method` from an origin that is (or isn't) approved.
/// Pure so the consent policy is unit-tested independently of HTTP/state.
fn wc_gate(method: &str, origin_approved: bool) -> Gate {
    match method {
        "chip0002_chainId" | "chip0002_getMethods" => Gate::Public,
        "chip0002_connect" => {
            if origin_approved {
                Gate::Allowed
            } else {
                Gate::NeedsApproval
            }
        }
        _ => {
            if origin_approved {
                Gate::Allowed
            } else {
                Gate::Forbidden
            }
        }
    }
}

fn wc_err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, String) {
    (code, msg.into())
}

/// The most-significant method names that would, if ever dispatched, hand back key
/// material. They are NOT match arms in `wc_dispatch` (so they already fall to the
/// 501 arm), but the delegate router must ALSO never forward them to Sage — a Sage
/// that implemented such a method must not become a way to exfiltrate a seed through
/// the dapp surface. Guarded by `delegate_never_forwards_export_class_methods`.
fn is_export_class_method(method: &str) -> bool {
    matches!(
        method,
        "export"
            | "exportMnemonic"
            | "chip0002_export"
            | "chia_export"
            | "getMnemonic"
            | "getSecretKeys"
            | "getPrivateKey"
            | "getPrivateKeys"
            | "revealSeed"
    )
}

/// Answer one WalletConnect / CHIP-0002 request.
///
/// The handshake + introspection methods are answered here: they touch no keys and must
/// work before any Sage session exists. **Every other method is delegated to the user's
/// Sage wallet** over the requester session.
///
/// There is deliberately no local-signer branch to fall through to. This process holds no
/// user spend key and cannot obtain one (§908), so a method that reaches this point either
/// delegates or is refused — which is the property that makes the refusal structural rather
/// than a policy check someone can later relax.
async fn wc_dispatch(
    st: &AppState,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;

    if !wc_method_needs_wallet(method) {
        return Ok(match method {
            "chip0002_chainId" => json!("mainnet"),
            "chip0002_connect" => json!(true),
            // Agent-friendly self-description: the full dispatchable method list.
            "chip0002_getMethods" => json!(WC_METHOD_CATALOGUE),
            _ => unreachable!("non-wallet method list is exhaustive"),
        });
    }

    // Defence in depth against a FUTURE catalogue, not against today's input.
    //
    // Measured: this block is currently UNREACHABLE. Every export-class spelling is
    // already absent from `WC_METHOD_CATALOGUE`, so the check below refuses all of them
    // with the identical 501 and deleting this one changes nothing observable — a
    // mutation that removes it leaves the whole suite green. It is kept, and kept FIRST,
    // because the ordering is what survives the change that makes it matter: the day an
    // export-flavoured method is added to the catalogue, this is the check that still
    // refuses it. `export_class_methods_are_absent_from_the_catalogue` pins the
    // disjointness that makes the claim true today, and is the test that actually fails
    // if someone breaks it.
    if is_export_class_method(method) {
        return Err(unsupported(method));
    }

    // Unknown methods keep answering 501 rather than being forwarded blind, so the
    // advertised catalogue and the dispatchable set stay the same set. THIS is the check
    // that is load-bearing today.
    if !WC_METHOD_CATALOGUE.contains(&method) {
        return Err(unsupported(method));
    }

    delegate_to_sage(st, method, params).await
}

/// The 501 a method outside the advertised catalogue receives. Shared so the
/// export-class refusal and the unknown-method refusal are indistinguishable on the wire —
/// a caller must not be able to probe which export spellings exist.
fn unsupported(method: &str) -> (StatusCode, String) {
    wc_err(
        StatusCode::NOT_IMPLEMENTED,
        format!("unsupported WC method: {method}"),
    )
}

// ---- The single dispatch path: HTTP handler + native FFI share it -----------
//
// `wallet_dispatch` is the ONE place a wallet request — its calling origin + the
// `{method, params}` JSON — turns into a `(status, body)` answer. Two callers reach
// it: the loopback HTTP handler `wc_request` (which parses the origin from the
// `Origin` header and maps the result to an axum response), and the browser
// process directly via the C-ABI FFI `dig_wallet_rpc` in `dig-runtime` (which has
// no HTTP server in the path — it knows the calling page's origin first-hand and is
// thus UNSPOOFABLE). Both share ONE process-global `AppState` (`shared_state`) so
// the per-origin approval allow-list, the unlocked session, and the wallet source
// are consistent no matter which entrypoint is used.

/// The process-global wallet state, shared by the loopback HTTP server (`run`) and
/// the native FFI dispatch (`wallet_dispatch`). Built once, lazily — the wallet has
/// exactly one approval allow-list / session / source per browser process, and both
/// entrypoints must see the same one (an FFI approval must let the HTTP path through
/// and vice-versa).
fn shared_state() -> &'static Arc<AppState> {
    static STATE: OnceLock<Arc<AppState>> = OnceLock::new();
    STATE.get_or_init(|| Arc::new(AppState::default()))
}

/// Dispatch one wallet request against `st`, returning the HTTP-equivalent
/// `(status, body_json)` the loopback handler produces. This is the shared core of
/// [`wallet_dispatch`]; it takes the state explicitly so it can be unit-tested with
/// a fresh, isolated `AppState`. `origin` is the calling web origin (from the
/// unspoofable `Origin` header over HTTP, or supplied first-hand by the browser
/// process over FFI); `request_json` is the `{method, params}` body.
///
/// The status/body mirror the HTTP path exactly: 200 `{"data":...}` on success, 202
/// `{"status":"pending"}` for a `connect` from an unapproved origin (recorded
/// pending), 403 `{"error":...}` for a key/sign method from an unapproved origin,
/// 400 `{"error":...}` for a malformed request body, and the dispatcher's own
/// status (401/4xx/5xx/501) `{"error":...}` otherwise.
async fn wallet_dispatch_with(st: &AppState, origin: &str, request_json: &str) -> (u16, String) {
    let req: WcRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST.as_u16(),
                serde_json::json!({ "error": format!("bad request: {e}") }).to_string(),
            );
        }
    };

    let approved = st.approvals.lock().await.is_approved(origin);
    match wc_gate(&req.method, approved) {
        Gate::NeedsApproval => {
            if !origin.is_empty() {
                st.approvals.lock().await.pending.insert(origin.to_string());
            }
            return (
                StatusCode::ACCEPTED.as_u16(),
                serde_json::json!({ "status": "pending" }).to_string(),
            );
        }
        Gate::Forbidden => {
            return (
                StatusCode::FORBIDDEN.as_u16(),
                serde_json::json!({
                    "error": "origin not connected — call chip0002_connect and approve it in the DIG wallet"
                })
                .to_string(),
            );
        }
        Gate::Public | Gate::Allowed => {}
    }

    match wc_dispatch(st, &req.method, req.params).await {
        Ok(data) => (
            StatusCode::OK.as_u16(),
            serde_json::json!({ "data": data }).to_string(),
        ),
        Err((code, msg)) => (
            code.as_u16(),
            serde_json::json!({ "error": msg }).to_string(),
        ),
    }
}

/// Dispatch one wallet request in-process against the process-global wallet state,
/// returning the HTTP-equivalent `(status, body_json)`. The native FFI entrypoint
/// (`dig_runtime::dig_wallet_rpc`) calls this directly so the browser process can
/// drive the per-origin wallet surface with NO loopback HTTP hop — the same dispatch
/// (and the same approval gate / session / source) the loopback `wc_request` handler
/// uses. `origin` is the calling page's web origin (supplied first-hand by the
/// browser, hence unspoofable); `request_json` is the `{method, params}` body.
pub async fn wallet_dispatch(origin: &str, request_json: &str) -> (u16, String) {
    wallet_dispatch_with(shared_state(), origin, request_json).await
}

// ---- Sage delegate bridge (requester role, #34) -----------------------------
//
// When the wallet source is `Sage`, `wc_dispatch` cannot reach the relay from Rust:
// the live WalletConnect *requester* SignClient (the dual of the responder) runs in
// the wallet UI page, the one tab that stays open. So a delegated method is parked in
// `AppState::delegate` and the call `await`s a oneshot; the page long-polls for it,
// forwards it to Sage over the session, and POSTs the result back — which fulfils the
// oneshot. This keeps `window.chia` and the per-origin consent gate untouched; only
// the signer moves to Sage. The bridge lives only while the page is open (same v1
// caveat as the responder): if the page goes away the waiter drops, surfacing as a
// clean "Sage did not respond" error rather than a hang.

/// How long a parked delegate request waits for the wallet page to forward it to Sage
/// and return Sage's reply. Generous: a backgrounded mobile Sage can take a while to
/// surface the prompt and have the user approve it.
const DELEGATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Park `{method, params}` for the in-page Sage requester and await Sage's reply.
/// Returns the bare result Sage returns (already normalized by the page to the same
/// shapes the local signer returns, mirroring the hub's `sage.js`), or a wallet error
/// if Sage rejects / the page is gone / it times out.
async fn delegate_to_sage(
    st: &AppState,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let (tx, rx) = oneshot::channel();
    {
        // Park the request for the page to pick up via /api/wc/delegate/next.
        let mut bridge = st.delegate.lock().await;
        let id = bridge.next_id.fetch_add(1, Ordering::Relaxed);
        bridge.queue.push_back(DelegateRequest {
            id,
            method: method.to_string(),
            params,
            tx,
        });
    }
    match tokio::time::timeout(DELEGATE_TIMEOUT, rx).await {
        Ok(Ok(Ok(value))) => Ok(value),
        // Sage (via the page) returned an explicit error for this method.
        Ok(Ok(Err(msg))) => Err(wc_err(StatusCode::BAD_GATEWAY, msg)),
        // The page dropped the waiter (tab closed) before answering.
        Ok(Err(_)) => Err(wc_err(
            StatusCode::BAD_GATEWAY,
            "Sage wallet is not connected (open the DIG wallet and connect Sage in DIG settings)",
        )),
        Err(_) => Err(wc_err(
            StatusCode::GATEWAY_TIMEOUT,
            "Sage did not respond — open the Sage app and approve the request, then try again",
        )),
    }
}

/// Take the next parked delegate request for the in-page Sage requester, moving its
/// oneshot sender into `waiters` keyed by id. Returns `None` when the queue is empty
/// (the page long-polls, so an empty queue is the common case).
async fn delegate_take_next(st: &AppState) -> Option<(u64, String, serde_json::Value)> {
    let mut bridge = st.delegate.lock().await;
    let req = bridge.queue.pop_front()?;
    let DelegateRequest {
        id,
        method,
        params,
        tx,
    } = req;
    bridge.waiters.insert(id, tx);
    Some((id, method, params))
}

/// Fulfil the parked delegate request `id` with Sage's result (`Ok`) or error
/// message (`Err`). A no-op if the id is unknown (already fulfilled / timed out).
async fn delegate_fulfill(st: &AppState, id: u64, result: Result<serde_json::Value, String>) {
    if let Some(tx) = st.delegate.lock().await.waiters.remove(&id) {
        let _ = tx.send(result);
    }
}

/// The dapp's web origin, from the unspoofable HTTP `Origin` header (page JS
/// cannot forge it on a cross-origin fetch). Empty if absent.
fn origin_of(headers: &HeaderMap) -> String {
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Reflect the dapp's origin into a response's CORS headers so the page can read it.
/// Security is the per-origin approval gate (not CORS), so the origin is reflected
/// verbatim (an empty origin becomes `null`). Shared by every dapp-facing reply so
/// the header policy lives in one place.
fn attach_cors_origin(resp: &mut Response, origin: &str) {
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(if origin.is_empty() { "null" } else { origin }) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
}

/// CORS preflight for the dapp-facing `/api/wc/request` endpoint.
async fn wc_preflight(headers: HeaderMap) -> Response {
    let origin = origin_of(&headers);
    let mut resp = StatusCode::NO_CONTENT.into_response();
    attach_cors_origin(&mut resp, &origin);
    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    resp
}

/// The dapp-facing WalletConnect endpoint. A thin HTTP wrapper over the shared
/// [`wallet_dispatch`] core: it reads the origin from the unspoofable `Origin`
/// header + the `{method, params}` request body, runs the ONE dispatch path
/// (consent gate + signer), and maps the `(status, body_json)` it returns to a CORS
/// axum response so the dapp can read the reply. There is no behaviour difference
/// from the native FFI path — both go through `wallet_dispatch`.
async fn wc_request(State(st): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    let origin = origin_of(&headers);
    let (status, body_json) = wallet_dispatch_with(&st, &origin, &body).await;
    // Re-attach CORS (the dispatch core is transport-agnostic). The body is already
    // a JSON string from the shared core, so emit it verbatim rather than re-encoding.
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = (
        code,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body_json,
    )
        .into_response();
    attach_cors_origin(&mut resp, &origin);
    resp
}

// ---- Sage delegate pump endpoints (requester role, #34) ---------------------
//
// The in-page Sage requester (the wallet UI page, which owns the live SignClient)
// drives the delegate bridge through these two endpoints. Both are SELF-ORIGIN ONLY:
// the delegate queue carries the wallet's own dispatched requests (and would let a
// caller feed arbitrary results back into `wc_dispatch`), so only the wallet's own
// page may pump it — never a dapp. They are NOT a dapp signing surface.

/// Long-poll for the next parked delegate request to forward to Sage. Returns
/// `{ id, method, params }` when one is waiting, or `{}` when the queue is empty
/// (the page polls on a short interval). Self-origin only.
async fn wc_delegate_next(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "delegate pump is wallet-local only").into_response();
    }
    match delegate_take_next(&st).await {
        Some((id, method, params)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "id": id, "method": method, "params": params })),
        )
            .into_response(),
        None => (StatusCode::OK, Json(serde_json::json!({}))).into_response(),
    }
}

/// The page returns Sage's reply for a delegate request: `{ id, result }` on success
/// (the bare, page-normalized value `wc_dispatch` hands back to the caller) or
/// `{ id, error }` on failure (Sage rejected, the method is unsupported, etc.). This
/// fulfils the parked oneshot. Self-origin only.
#[derive(Deserialize)]
struct DelegateResult {
    id: u64,
    /// Sage's bare result (present on success). Mutually exclusive with `error`.
    #[serde(default)]
    result: Option<serde_json::Value>,
    /// Error message (present on failure).
    #[serde(default)]
    error: Option<String>,
}

async fn wc_delegate_result(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DelegateResult>,
) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "delegate pump is wallet-local only").into_response();
    }
    let outcome = match req.error {
        Some(msg) => Err(msg),
        None => Ok(req.result.unwrap_or(serde_json::Value::Null)),
    };
    delegate_fulfill(&st, req.id, outcome).await;
    StatusCode::NO_CONTENT.into_response()
}

/// The dapp connections the wallet UI shows: approved allow-list + pending requests.
#[derive(Serialize)]
struct ConnectionsResp {
    approved: Vec<String>,
    pending: Vec<String>,
}

async fn wc_connections(State(st): State<Arc<AppState>>) -> Json<ConnectionsResp> {
    let a = st.approvals.lock().await;
    Json(ConnectionsResp {
        approved: a.approved.iter().cloned().collect(),
        pending: a.pending.iter().cloned().collect(),
    })
}

#[derive(Deserialize)]
struct OriginReq {
    origin: String,
}

/// Approve a pending dapp origin (user action in the wallet) — persists it.
async fn wc_approve(
    State(st): State<Arc<AppState>>,
    Json(req): Json<OriginReq>,
) -> impl IntoResponse {
    let mut a = st.approvals.lock().await;
    a.pending.remove(&req.origin);
    a.approved.insert(req.origin.clone());
    save_approved(&a.approved);
    StatusCode::NO_CONTENT
}

/// Reject a pending dapp origin (drop it without approving).
async fn wc_reject(
    State(st): State<Arc<AppState>>,
    Json(req): Json<OriginReq>,
) -> impl IntoResponse {
    st.approvals.lock().await.pending.remove(&req.origin);
    StatusCode::NO_CONTENT
}

/// Revoke a previously-approved dapp origin — persists the removal.
async fn wc_revoke(
    State(st): State<Arc<AppState>>,
    Json(req): Json<OriginReq>,
) -> impl IntoResponse {
    let mut a = st.approvals.lock().await;
    a.approved.remove(&req.origin);
    save_approved(&a.approved);
    StatusCode::NO_CONTENT
}

/// Serve the DIG wallet (loopback only) to completion. Driven either by the
/// standalone `dig-wallet` binary OR in-process by `dig-runtime` on the browser's
/// tokio runtime (no sidecar). The wallet UI is an interactive web page, so it is
/// served over loopback HTTP (never reachable off-host); native BLS signing runs
/// in this same process.
pub async fn run() {
    // Share the ONE process-global state with the native FFI dispatch
    // (`wallet_dispatch`), so an approval granted over either entrypoint is honoured
    // by both, and the unlocked session / wallet source are consistent.
    let state = shared_state().clone();
    let app = Router::new()
        .route("/", get(index))
        .route("/wc-bundle.js", get(wc_bundle_js))
        .route("/settings", get(settings_page))
        .route("/api/status", get(status))
        .route("/api/dig-config", get(dig_config_get).post(dig_config_set))
        .route("/api/dig-cache/clear", post(dig_cache_clear))
        .route("/api/dig-cache/list", get(dig_cache_list))
        .route("/api/dig-cache/remove", post(dig_cache_remove))
        .route("/api/dig-cache/fetch", post(dig_cache_fetch))
        .route(
            "/api/wc/project-id",
            get(wc_project_id_get).post(wc_project_id_set),
        )
        .route("/api/wc/request", post(wc_request).options(wc_preflight))
        .route("/api/wc/delegate/next", get(wc_delegate_next))
        .route("/api/wc/delegate/result", post(wc_delegate_result))
        .route("/api/wc/connections", get(wc_connections))
        .route("/api/wc/approve", post(wc_approve))
        .route("/api/wc/reject", post(wc_reject))
        .route("/api/wc/revoke", post(wc_revoke))
        .with_state(state);

    // Bind loopback only — the wallet must never be reachable off-host.
    let addr = format!("127.0.0.1:{}", wallet_port());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("dig-wallet: cannot bind {addr}: {e}"));
    println!("dig-wallet listening on http://{addr}");
    axum::serve(listener, app).await.expect("dig-wallet server");
}

/// The Sage-mirroring wallet UI (single self-contained page). Dark, luxury,
/// DIG-purple / Chia-green accents.
const UI_HTML: &str = include_str!("ui.html");

/// The DIG protocol settings page (single self-contained page). Same dark luxury
/// DIG aesthetic as the wallet; first setting is the native local-cache threshold.
const SETTINGS_HTML: &str = include_str!("settings.html");

/// The bundled WalletConnect responder client (`window.DigWC`), generated by
/// `wc/build.mjs` (esbuild). Checked in so the crate builds offline; served at
/// `/wc-bundle.js`.
const WC_BUNDLE_JS: &str = include_str!("wc-bundle.js");

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that mutate the process-global `LOCALAPPDATA` env (the
    /// seed/connections/wallet-source dir). Without it, `cargo test`'s parallel runner
    /// can have one test clear the env mid-flight under another, making disk
    /// persistence assertions flaky. A tokio mutex so the guard is held safely across
    /// the `.await`s in these async tests. Held for the whole body of each such test.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    #[test]
    fn cache_cap_is_floored_so_caching_cant_be_disabled() {
        // A 0 / tiny request must not disable the cache (which would defeat
        // local-first and hammer rpc.dig.net) — it floors to the 64 MiB minimum.
        assert_eq!(floored_cache_cap(0), 64 * 1024 * 1024);
        assert_eq!(floored_cache_cap(1), 64 * 1024 * 1024);
        // A request above the floor is honoured verbatim.
        assert_eq!(
            floored_cache_cap(5 * 1024 * 1024 * 1024),
            5 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn only_the_exact_wallet_origin_is_self_trusted() {
        // The wallet's own page origin is trusted (it serves the UI)…
        assert!(is_self_origin("http://127.0.0.1:9777"));
        assert!(is_self_origin("http://localhost:9777"));
        // …but NOT some other local server on a different port (that would let any
        // localhost app spend the wallet without approval).
        assert!(!is_self_origin("http://127.0.0.1:8099"));
        assert!(!is_self_origin("http://127.0.0.1"));
        assert!(!is_self_origin("https://example.com"));
        assert!(!is_self_origin(""));
    }

    #[test]
    fn wc_origin_gate() {
        // chainId is public — no origin approval needed.
        assert_eq!(wc_gate("chip0002_chainId", false), Gate::Public);
        // connect from an unapproved origin must ask the user; from an approved
        // origin it just succeeds.
        assert_eq!(wc_gate("chip0002_connect", false), Gate::NeedsApproval);
        assert_eq!(wc_gate("chip0002_connect", true), Gate::Allowed);
        // Any key/sign method is forbidden until the origin is approved.
        assert_eq!(wc_gate("chip0002_signMessage", false), Gate::Forbidden);
        assert_eq!(wc_gate("chip0002_signCoinSpends", false), Gate::Forbidden);
        assert_eq!(wc_gate("chip0002_getPublicKeys", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_getAddress", false), Gate::Forbidden);
        // …and allowed once approved.
        assert_eq!(wc_gate("chip0002_signMessage", true), Gate::Allowed);
    }

    #[test]
    fn wc_methods_that_need_a_wallet() {
        // Public handshake methods never need an unlocked wallet…
        assert!(!wc_method_needs_wallet("chip0002_chainId"));
        assert!(!wc_method_needs_wallet("chip0002_connect"));
        // …but anything that reads keys or signs does.
        assert!(wc_method_needs_wallet("chip0002_getPublicKeys"));
        assert!(wc_method_needs_wallet("chip0002_signMessage"));
        assert!(wc_method_needs_wallet("chip0002_signCoinSpends"));
        assert!(wc_method_needs_wallet("chia_getAddress"));
        // Taking an offer builds + signs a spend, so it needs an unlocked wallet…
        assert!(wc_method_needs_wallet("chia_takeOffer"));
    }

    #[test]
    fn take_offer_is_gated_behind_the_origin_consent_and_wallet() {
        // chia_takeOffer is a spend method: forbidden until the origin is approved,
        // allowed once approved (same gate as the other signing methods). This guards
        // the badge-minting path from an unapproved dapp triggering a take.
        assert_eq!(wc_gate("chia_takeOffer", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_takeOffer", true), Gate::Allowed);
    }

    // -- Wallet source: Native local keys vs. Sage delegate (#34) --------------

    #[test]
    fn export_class_methods_are_recognised_so_delegate_never_forwards_them() {
        // The seed-revealing method names the delegate router must refuse before they
        // ever reach Sage (defence in depth — export is never a dispatchable method,
        // local OR delegated).
        for m in [
            "export",
            "exportMnemonic",
            "chip0002_export",
            "chia_export",
            "getMnemonic",
            "getSecretKeys",
            "getPrivateKey",
            "getPrivateKeys",
            "revealSeed",
        ] {
            assert!(is_export_class_method(m), "{m} must be export-class");
        }
        // Ordinary signing methods are NOT export-class (they delegate normally).
        assert!(!is_export_class_method("chip0002_signMessage"));
        assert!(!is_export_class_method("chip0002_getPublicKeys"));
    }

    /// The delegate pump endpoints are wallet-local: a dapp origin cannot pull the
    /// parked queue or feed results back into the dispatcher.
    #[tokio::test]
    async fn delegate_pump_endpoints_are_self_origin_only() {
        let st = Arc::new(AppState::default());
        let dapp = origin_headers("https://evil.example.com");
        assert_eq!(
            wc_delegate_next(State(st.clone()), dapp.clone())
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let r = wc_delegate_result(
            State(st),
            dapp,
            Json(DelegateResult {
                id: 0,
                result: Some(serde_json::json!("x")),
                error: None,
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn nft_methods_are_gated_and_need_a_wallet() {
        for m in [
            "chia_getNfts",
            "chia_transferNft",
            "chia_mintNft",
            "chia_bulkMintNfts",
        ] {
            assert_eq!(
                wc_gate(m, false),
                Gate::Forbidden,
                "{m} forbidden unapproved"
            );
            assert_eq!(wc_gate(m, true), Gate::Allowed, "{m} allowed approved");
            assert!(wc_method_needs_wallet(m), "{m} needs a wallet");
        }
    }

    #[test]
    fn transactions_method_is_gated_and_needs_a_wallet() {
        assert_eq!(wc_gate("chia_getTransactions", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_getTransactions", true), Gate::Allowed);
        assert!(wc_method_needs_wallet("chia_getTransactions"));
    }

    #[test]
    fn did_methods_are_gated_and_need_a_wallet() {
        for m in ["chia_getDids", "chia_createDidWallet", "chia_transferDid"] {
            assert_eq!(
                wc_gate(m, false),
                Gate::Forbidden,
                "{m} forbidden unapproved"
            );
            assert_eq!(wc_gate(m, true), Gate::Allowed, "{m} allowed approved");
            assert!(wc_method_needs_wallet(m), "{m} needs a wallet");
        }
    }

    #[test]
    fn offer_methods_are_gated() {
        // Summary is read-only but still requires origin approval; create/cancel are
        // state-changing and need an unlocked wallet.
        assert_eq!(wc_gate("chia_getOfferSummary", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_createOffer", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_cancelOffer", true), Gate::Allowed);
        assert!(wc_method_needs_wallet("chia_createOffer"));
        assert!(wc_method_needs_wallet("chia_cancelOffer"));
        assert!(wc_method_needs_wallet("chia_getOfferSummary"));
    }

    #[test]
    fn token_methods_are_gated_and_need_a_wallet() {
        // chia_send is a spend method: forbidden until the origin is approved, allowed
        // once approved, and always needs an unlocked wallet.
        assert_eq!(wc_gate("chia_send", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_send", true), Gate::Allowed);
        assert!(wc_method_needs_wallet("chia_send"));
        // Generic CAT balance/coins still need a wallet (they read keys + scan).
        assert!(wc_method_needs_wallet("chip0002_getAssetBalance"));
        assert!(wc_method_needs_wallet("chip0002_getAssetCoins"));
    }

    #[test]
    fn settings_page_wires_the_cache_config_api() {
        // The served settings page must talk to the same config endpoints the
        // handlers expose, or the UI silently no-ops.
        assert!(SETTINGS_HTML.contains("/api/dig-config"));
        assert!(SETTINGS_HTML.contains("/api/dig-cache/clear"));
    }

    // -- Cached-store manager (#32) --------------------------------------------

    #[test]
    fn cached_capsule_json_matches_the_capsule_identity() {
        // The wire shape carries the canonical storeId:rootHash capsule identity plus
        // the head/tail/size/last-used the settings table renders + sorts on.
        let c = dig_node_core::CachedCapsule {
            store_id: "aa".repeat(32),
            root: "bb".repeat(32),
            size_bytes: 4096,
            last_used_unix_ms: 1_700_000_000_000,
            provenance: dig_node_core::CapsuleProvenance::Held,
        };
        let j = cached_capsule_json(&c);
        assert_eq!(
            j["capsule"],
            format!("{}:{}", "aa".repeat(32), "bb".repeat(32))
        );
        assert_eq!(j["store_id"], "aa".repeat(32));
        assert_eq!(j["root"], "bb".repeat(32));
        assert_eq!(j["size_bytes"], 4096);
        assert_eq!(j["last_used_unix_ms"], 1_700_000_000_000u64);
    }

    /// All three cache-manager endpoints are wallet-local: a dapp origin is refused (403)
    /// so the user's local cache is never listable/removable/fetchable from a dapp page.
    #[tokio::test]
    async fn cache_manager_endpoints_are_self_origin_only() {
        let dapp = origin_headers("https://evil.example.com");
        assert_eq!(
            dig_cache_list(dapp.clone()).await.status(),
            StatusCode::FORBIDDEN
        );
        let req = || {
            Json(CacheCapsuleReq {
                store_id: "aa".repeat(32),
                root: "bb".repeat(32),
            })
        };
        assert_eq!(
            dig_cache_remove(dapp.clone(), req()).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            dig_cache_fetch(dapp, req()).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// The self origin can LIST the cache (an empty list when nothing is cached). Points
    /// the cache dir at a throwaway tempdir so the test is hermetic.
    ///
    /// The override MUST be `DIG_NODE_CACHE`, the only variable `canonical_cache_dir` consults
    /// before falling through to `directories::BaseDirs`. `BaseDirs` reads the OS API rather than
    /// the environment, so setting `LOCALAPPDATA` alone left this test reading the REAL machine
    /// cache and asserting it was empty — it failed on any host that had ever cached a capsule.
    #[tokio::test]
    async fn cache_list_self_origin_returns_capsule_list() {
        let _g = ENV_LOCK.lock().await;
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", td.path().join("cache"));
        std::env::set_var("LOCALAPPDATA", td.path());
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());
        let resp = dig_cache_list(origin_headers(&self_origin)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["cached"].is_array(), "list returns a cached array");
        assert_eq!(body["cached"].as_array().unwrap().len(), 0, "empty cache");
        std::env::remove_var("DIG_NODE_CACHE");
        std::env::remove_var("LOCALAPPDATA");
    }

    #[test]
    fn settings_page_wires_the_cache_manager_api() {
        // The "Cached stores" card must call the list/remove/fetch endpoints, or the
        // capsule manager silently no-ops.
        assert!(SETTINGS_HTML.contains("/api/dig-cache/list"));
        assert!(SETTINGS_HTML.contains("/api/dig-cache/remove"));
        assert!(SETTINGS_HTML.contains("/api/dig-cache/fetch"));
    }

    #[test]
    fn wallet_page_hosts_the_walletconnect_responder() {
        // The wallet page must load the bundled responder and expose the
        // "Connect a dapp" pairing surface; the bundle must be the real client
        // (exposes window.DigWC), and the page must read the effective projectId
        // from DIG settings so the relay boots with it.
        assert!(
            UI_HTML.contains("/wc-bundle.js"),
            "page loads the WC bundle"
        );
        assert!(UI_HTML.contains("DigWC"), "page uses the responder API");
        assert!(
            UI_HTML.contains("/api/wc/project-id"),
            "page reads the effective projectId"
        );
        // The bundle is the actual esbuild output, not a stub.
        assert!(
            WC_BUNDLE_JS.contains("var DigWC") && WC_BUNDLE_JS.len() > 100_000,
            "wc-bundle.js is the real bundled SignClient"
        );
    }

    #[test]
    fn wallet_page_wires_the_advanced_surfaces() {
        // The advanced wallet UI must call each new method/endpoint, or the surface
        // silently no-ops. Guard the wiring the same way the settings page is guarded.
        // Tokens (generic CAT) + send.
        assert!(UI_HTML.contains("chip0002_getAssetBalance"));
        assert!(UI_HTML.contains("chia_send"));
        // NFTs.
        assert!(UI_HTML.contains("chia_getNfts"));
        assert!(UI_HTML.contains("chia_transferNft"));
        assert!(UI_HTML.contains("chia_mintNft"));
        // Offers: inspect, make, take, and cancel (the luxury redesign wires the
        // Cancel action on "Your offers" through the real chia_cancelOffer signer).
        assert!(UI_HTML.contains("chia_getOfferSummary"));
        assert!(UI_HTML.contains("chia_createOffer"));
        assert!(UI_HTML.contains("chia_takeOffer"));
        assert!(UI_HTML.contains("chia_cancelOffer"));
        // DIDs.
        assert!(UI_HTML.contains("chia_getDids"));
        assert!(UI_HTML.contains("chia_createDidWallet"));
        assert!(UI_HTML.contains("chia_transferDid"));
        // Transactions.
        assert!(UI_HTML.contains("chia_getTransactions"));
        // My Stores was enumerated from the seed this node used to hold, so the page must
        // no longer call those routes at all. Asserting their ABSENCE is what keeps a
        // re-added listing from quietly depending on custody again.
        // Matched as a CALL, not as a bare path: the page's own header comment names the
        // removed routes, and a substring check would match that explanation instead of a
        // regression — passing today and passing after the routes came back.
        assert!(!UI_HTML.contains("api('/api/stores"));
        // Self-origin auto-approved, then forwarded to Sage.
        assert!(UI_HTML.contains("/api/wc/request"));
    }

    #[test]
    fn wallet_page_renders_the_luxury_dig_wallet_shell() {
        // The "DIG Wallet" luxury redesign: a persistent left rail with the
        // plain-language domains, the Balance Orb hero, the Notary hold-to-sign
        // sheet, and the Certificate-of-Permanence ownership framing. Guard the
        // shell so a regression can't silently strip the redesign while leaving
        // the endpoint wiring intact.
        assert!(UI_HTML.contains("class=\"rail\""), "persistent left rail");
        assert!(UI_HTML.contains("class=\"orb\""), "balance orb hero");
        assert!(UI_HTML.contains("Hold to sign"), "notary hold-to-confirm");
        assert!(
            UI_HTML.contains("Show protocol detail"),
            "progressive-disclosure of protocol detail"
        );
        // Every everyday domain is reachable from the rail.
        for go in [
            "data-go=\"home\"",
            "data-go=\"tokens\"",
            "data-go=\"nfts\"",
            "data-go=\"trades\"",
            "data-go=\"activity\"",
            "data-go=\"profiles\"",
            "data-go=\"stores\"",
            "data-go=\"connect\"",
            "data-go=\"advanced\"",
            "data-go=\"settings\"",
        ] {
            assert!(UI_HTML.contains(go), "rail wires {go}");
        }
    }

    #[test]
    fn wallet_page_wires_the_advanced_coin_types() {
        // The Advanced tab must call each supported advanced method, or the surface
        // silently no-ops. Clawback (send/claim/recover).
        assert!(UI_HTML.contains("dig_clawbackSend"));
        assert!(UI_HTML.contains("dig_clawbackClaim"));
        assert!(UI_HTML.contains("dig_clawbackRecover"));
        // Options (create).
        assert!(UI_HTML.contains("dig_optionCreate"));
        // Streaming (create/claim/clawback).
        assert!(UI_HTML.contains("dig_streamCreate"));
        assert!(UI_HTML.contains("dig_streamClaim"));
        assert!(UI_HTML.contains("dig_streamClawback"));
        // Vault (create).
        assert!(UI_HTML.contains("dig_vaultCreate"));
        // Verifiable credentials (verify).
        assert!(UI_HTML.contains("dig_vcVerify"));
        // The Advanced tab itself is present and clearly secondary.
        assert!(UI_HTML.contains("data-tab=\"advanced\""));
    }

    #[test]
    fn settings_page_offers_no_route_to_a_key_and_says_where_the_keys_are() {
        // The projectId control stays — the relay needs it to reach Sage.
        assert!(SETTINGS_HTML.contains("/api/wc/project-id"));
        // Every seed-touching control is gone. These are absence assertions on purpose:
        // the page is where a user would look for "reveal my phrase", so a re-added
        // control here is the most likely way the removed plane comes back.
        for gone in [
            "/api/export",
            "/api/import",
            "/api/wallet/pubkey",
            "/api/unlock",
            "/api/generate",
        ] {
            assert!(
                !SETTINGS_HTML.contains(gone),
                "settings must not call {gone}"
            );
        }
        // Silence would read as a missing feature rather than a deliberate boundary, so
        // the page has to SAY that the keys are Sage's and that reading needs none.
        assert!(SETTINGS_HTML.contains("This browser holds no wallet keys"));
        // …and a user whose seed is still on disk must be told how to get it out.
        assert!(SETTINGS_HTML.contains("dign wallet export-seed"));
    }

    #[test]
    fn settings_page_wires_the_sage_connection_and_offers_no_alternative_to_it() {
        // There is no signer choice any more, so there must be no control that implies
        // one. Sage is not an option among two; it is where the keys are.
        assert!(!SETTINGS_HTML.contains("/api/wallet/source"));
        assert!(
            !SETTINGS_HTML.contains("value=\"native\""),
            "no Native option"
        );
        // Connect-to-Sage flow: the bundle (the WC requester), projectId, the pairing
        // URI surface, and a Disconnect.
        assert!(
            SETTINGS_HTML.contains("/wc-bundle.js"),
            "loads the WC requester bundle"
        );
        assert!(
            SETTINGS_HTML.contains("/api/wc/project-id"),
            "needs the relay projectId"
        );
        assert!(SETTINGS_HTML.contains("DigWC"), "uses the requester API");
        assert!(
            SETTINGS_HTML.contains("connectSage"),
            "starts the Sage pairing"
        );
    }

    #[test]
    fn wallet_page_runs_the_sage_delegate_pump() {
        // The wallet page must (a) host the WC requester (DigWC.sageRequest), and (b) pump
        // the delegate bridge — pull parked requests, forward to Sage, return results — or
        // EVERY key/sign method hangs, because delegation is now the only route there is.
        // It must do so unconditionally: a pump still gated on a source setting would idle
        // forever, since nothing sets one.
        assert!(
            !UI_HTML.contains("/api/wallet/source"),
            "the pump must not wait on a source setting that no longer exists"
        );
        assert!(
            UI_HTML.contains("/api/wc/delegate/next"),
            "pulls parked requests"
        );
        assert!(
            UI_HTML.contains("/api/wc/delegate/result"),
            "returns Sage's replies"
        );
        assert!(
            UI_HTML.contains("sageRequest"),
            "forwards over the requester session"
        );
        // The bundle must expose the requester role, not just the responder.
        assert!(
            WC_BUNDLE_JS.contains("sageRequest"),
            "wc-bundle.js exposes the Sage requester role"
        );
    }

    // -- Key export is unreachable from every dapp-facing path -----------------

    // -- wallet_dispatch: the one dispatch path (HTTP handler + FFI share it) ----

    /// `wallet_dispatch_with` is the single core both the HTTP `wc_request` handler
    /// and the native FFI (`dig_wallet_rpc`) call. An UNAPPROVED origin asking a
    /// key/sign method must be gated exactly as the HTTP path is: 403 with the
    /// `{"error":...}` "origin not connected" body. The per-origin gate keys on the
    /// passed `origin` (now supplied unspoofably by the browser process), so a bogus
    /// origin never slips through.
    #[tokio::test]
    async fn wallet_dispatch_gates_unapproved_origin_for_sign_methods() {
        let st = AppState::default();
        let req =
            r#"{"method":"chip0002_signMessage","params":{"message":"hi","publicKey":"0xabc"}}"#;
        let (status, body) = wallet_dispatch_with(&st, "https://dapp.example.com", req).await;
        assert_eq!(status, 403, "unapproved sign method is forbidden");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v.get("data").is_none(),
            "a forbidden request must NOT carry data"
        );
        assert!(
            v["error"].as_str().unwrap().contains("not connected"),
            "error body matches the HTTP path's 'origin not connected' shape: {body}"
        );
    }

    // -- Ported guards -------------------------------------------------------------
    //
    // These six properties predate dig-node#327 and SURVIVE it. Their original tests
    // referenced `WalletSource` / `Session`, which the removal deleted, so a
    // compile-driven prune would have taken them out as "tests of removed code" — they
    // are not. Losing them would have left the export-class refusal, the unknown-method
    // 501, and the handshake/delegate split with no coverage at all, which is the exact
    // shape of a security guard quietly becoming untested.
    //
    // Each is re-expressed against what the code does NOW. Two get stronger in the port:
    // the routing split was a pure-function assertion over a routing table that no longer
    // exists, and is now a behavioural check that the request actually reaches the Sage
    // queue — placement, not policy.

    /// Drive `method` from `origin` and report whether it was PARKED for Sage.
    ///
    /// Returns `Ok(true)` when the request reached the delegate queue, `Ok(false)` when it
    /// was answered locally, and `Err(status)` when it was refused. The distinction is the
    /// whole point of these tests: "refused" and "answered locally" are indistinguishable
    /// from a caller that only looks at whether an error came back.
    async fn park_outcome(method: &str) -> Result<bool, StatusCode> {
        let st = Arc::new(AppState::default());
        let caller = {
            let st = st.clone();
            let method = method.to_string();
            tokio::spawn(async move { wc_dispatch(&st, &method, serde_json::json!({})).await })
        };
        // Give the dispatch a moment to either answer or park, then look at the queue.
        for _ in 0..100 {
            if let Some((id, _m, _p)) = delegate_take_next(&st).await {
                delegate_fulfill(&st, id, Ok(serde_json::json!("ok"))).await;
                let _ = caller.await;
                return Ok(true);
            }
            if caller.is_finished() {
                return match caller.await.expect("dispatch task") {
                    Ok(_) => Ok(false),
                    Err((code, _)) => Err(code),
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("{method} neither answered nor parked");
    }

    /// An export-flavoured method is refused BEFORE it can be parked for Sage.
    ///
    /// The pump is the load-bearing part. Asserting only the 501 cannot tell a refusal
    /// from a request that was forwarded to Sage and happened to come back as an error —
    /// and forwarding is the failure that matters, because it would make the delegate
    /// surface a seed-exfiltration path through any Sage that implemented such a method.
    /// The counter proves nothing was ever parked; the control below proves the pump
    /// would have caught it if something had been.
    ///
    /// **What this does NOT prove, measured rather than assumed:** it cannot tell which of
    /// `wc_dispatch`'s two refusals fired. Removing the export-class guard leaves this
    /// green, because the catalogue check refuses the same names identically. The outcome
    /// is pinned here; the ordering that will matter later is pinned by
    /// `export_class_methods_are_absent_from_the_catalogue`.
    #[tokio::test]
    async fn delegate_never_forwards_export_class_methods() {
        let st = Arc::new(AppState::default());
        let leaked = Arc::new(AtomicU64::new(0));
        let pump = {
            let st = st.clone();
            let leaked = leaked.clone();
            tokio::spawn(async move {
                for _ in 0..80 {
                    if let Some((id, _m, _p)) = delegate_take_next(&st).await {
                        leaked.fetch_add(1, Ordering::Relaxed);
                        delegate_fulfill(&st, id, Ok(serde_json::json!("LEAK"))).await;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
        };
        for method in ["export", "exportMnemonic", "getSecretKeys", "revealSeed"] {
            match wc_dispatch(&st, method, serde_json::Value::Null).await {
                Err((code, _)) => assert_eq!(
                    code,
                    StatusCode::NOT_IMPLEMENTED,
                    "{method} must be refused as unsupported, never forwarded"
                ),
                Ok(v) => panic!("{method} must not be delegatable, got {v:?}"),
            }
        }
        pump.await.unwrap();
        assert_eq!(
            leaked.load(Ordering::Relaxed),
            0,
            "no export-class method may ever be parked for Sage"
        );
        // CONTROL: an ordinary catalogue method DOES reach the queue. Without this the
        // counter above would read zero just as happily against a build where nothing is
        // ever parked — a broken pump and a working guard look identical.
        assert_eq!(
            park_outcome("chip0002_signMessage").await,
            Ok(true),
            "the pump must be able to observe a parked request"
        );
    }

    /// No export-class spelling may appear in the advertised catalogue.
    ///
    /// This is the invariant the export-class guard's redundancy rests on, and the only
    /// assertion in this file that fails if someone breaks it. Adding, say,
    /// `chip0002_export` to `WC_METHOD_CATALOGUE` would make the catalogue check wave it
    /// through to Sage; the guard ordered before it is what still refuses, and this test
    /// is what says the situation ever arose.
    ///
    /// It is written over the catalogue constant rather than over dispatch on purpose:
    /// dispatch answers 501 either way, so a behavioural check cannot see the difference.
    #[test]
    fn export_class_methods_are_absent_from_the_catalogue() {
        for m in WC_METHOD_CATALOGUE {
            assert!(
                !is_export_class_method(m),
                "{m} is advertised as dispatchable AND is export-class — the catalogue \
                 check would forward it, and only the guard ordered before it refuses"
            );
        }
    }

    /// The master mnemonic is not reachable through the dapp-facing dispatch under any
    /// spelling. There is no session gate left to stop these first, so a 501 here is the
    /// export guard or the catalogue check and nothing else.
    #[tokio::test]
    async fn export_is_not_a_dispatchable_wc_method() {
        let st = AppState::default();
        for method in [
            "export",
            "exportMnemonic",
            "chip0002_export",
            "getMnemonic",
            "getSecretKeys",
            "chia_export",
            "revealSeed",
        ] {
            match wc_dispatch(&st, method, serde_json::Value::Null).await {
                Err((code, _)) => assert_eq!(
                    code,
                    StatusCode::NOT_IMPLEMENTED,
                    "dapp-facing dispatch must reject {method} as unsupported"
                ),
                Ok(v) => panic!("{method} must not be dispatchable, got {v:?}"),
            }
        }
    }

    /// A method outside the advertised catalogue is refused, never forwarded blind.
    ///
    /// These legs used to hit explicit "not supported in this build" arms in the local
    /// signer. With the signer gone the tempting shortcut is to forward anything to Sage
    /// and let Sage decide — which would silently widen this surface to whatever the
    /// user's wallet happens to implement, and would make the advertised catalogue a lie.
    #[tokio::test]
    async fn unsupported_advanced_legs_surface_as_not_implemented() {
        for method in [
            "dig_optionExercise",
            "dig_optionClawback",
            "dig_vaultSpend",
            "dig_vcIssue",
            "dig_vcRevoke",
            "dig_vcTransfer",
        ] {
            assert_eq!(
                park_outcome(method).await,
                Err(StatusCode::NOT_IMPLEMENTED),
                "{method} is not in the catalogue and must not be forwarded to Sage"
            );
        }
    }

    /// Sage's ERRORS reach the dapp, rather than hanging or being dressed up as success.
    #[tokio::test]
    async fn dispatch_surfaces_sage_errors() {
        let st = Arc::new(AppState::default());
        let pump = {
            let st = st.clone();
            tokio::spawn(async move {
                loop {
                    if let Some((id, _m, _p)) = delegate_take_next(&st).await {
                        delegate_fulfill(&st, id, Err("User rejected".to_string())).await;
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
        };
        let err = wc_dispatch(&st, "chia_send", serde_json::json!({}))
            .await
            .expect_err("a Sage rejection must surface as an error");
        assert_eq!(err.0, StatusCode::BAD_GATEWAY);
        assert!(err.1.contains("User rejected"));
        pump.await.unwrap();
    }

    /// The handshake is answered here; everything that touches a key goes to Sage.
    ///
    /// This replaces a pure-function assertion over the old `wc_route` table. Checking a
    /// table only ever proved the table said the right thing — it could not see whether
    /// dispatch consulted it, and a table is exactly what this change deleted. Driving
    /// `wc_dispatch` and watching the queue tests the placement instead, and both halves
    /// are needed: the handshake must NOT park (it has to work before Sage exists), and
    /// every key/sign method MUST park (it cannot be answered here at all).
    #[tokio::test]
    async fn the_handshake_is_local_and_every_key_method_goes_to_sage() {
        for m in [
            "chip0002_chainId",
            "chip0002_connect",
            "chip0002_getMethods",
        ] {
            assert_eq!(
                park_outcome(m).await,
                Ok(false),
                "{m} touches no key and must be answered without Sage"
            );
        }
        for m in [
            "chip0002_getPublicKeys",
            "chip0002_signMessage",
            "chip0002_signCoinSpends",
            "chia_getAddress",
            "chia_signMessageByAddress",
            "chip0002_getAssetBalance",
            "chip0002_getAssetCoins",
            "chia_takeOffer",
            "chia_createOffer",
            "chia_getOfferSummary",
            "chia_send",
            "chia_getNfts",
            "chia_getDids",
            "chia_getTransactions",
        ] {
            assert_eq!(park_outcome(m).await, Ok(true), "{m} must be asked of Sage");
        }
    }

    /// The wallet's own UI passes the consent gate implicitly, and lands on the Sage
    /// queue like any approved origin.
    ///
    /// The original asserted a `401 locked` from the local signer to prove the request had
    /// cleared the gate rather than been forbidden by it. There is no signer and no locked
    /// state now, so the equivalent evidence is that the request reaches the delegate
    /// queue: a `403` would mean the gate rejected it, and being answered locally would
    /// mean it never reached dispatch at all.
    #[tokio::test]
    async fn wallet_dispatch_self_origin_routes_through_to_sage() {
        let st = Arc::new(AppState::default());
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());
        let caller = {
            let st = st.clone();
            tokio::spawn(async move {
                wallet_dispatch_with(
                    &st,
                    &self_origin,
                    r#"{"method":"chip0002_getPublicKeys","params":{}}"#,
                )
                .await
            })
        };
        let parked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(t) = delegate_take_next(&st).await {
                    return t;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the wallet's own origin must clear the gate and reach the Sage queue");
        delegate_fulfill(&st, parked.0, Ok(serde_json::json!(["0xpk"]))).await;
        let (status, body) = caller.await.expect("dispatch task");
        assert_eq!(status, 200, "self origin is implicitly approved: {body}");
    }

    /// An APPROVED origin's sign request is PARKED FOR SAGE — never answered here.
    ///
    /// This is the positive half of the pair whose negative half is
    /// [`wallet_dispatch_gates_unapproved_origin_for_sign_methods`], and the pair is what
    /// makes either one meaningful. Alone, the refusal test passes just as well against a
    /// build that still holds a local signer, because an unapproved origin never reaches
    /// the signer to begin with; the consent gate would be the only thing under test.
    ///
    /// dig_ecosystem#1701 is a PLACEMENT change — signing left this process — so the
    /// observable that has to move is *where the request ends up*, not merely whether a
    /// response is an error. Asserting a 501 or an empty result would be satisfied
    /// identically by a local signer that happened to be locked, which is exactly the state
    /// the old build sat in most of the time. Reaching the delegate queue cannot be.
    #[tokio::test]
    async fn an_approved_origins_sign_request_is_parked_for_sage_not_answered_locally() {
        let st = Arc::new(AppState::default());
        st.approvals
            .lock()
            .await
            .approved
            .insert("https://dapp.example.com".to_string());

        let caller = {
            let st = st.clone();
            tokio::spawn(async move {
                wallet_dispatch_with(
                    &st,
                    "https://dapp.example.com",
                    r#"{"method":"chip0002_signMessage","params":{"message":"hi","publicKey":"0xabc"}}"#,
                )
                .await
            })
        };

        // The caller is now awaiting Sage. Poll the pump the wallet page drives; the
        // request must be sitting on it, with its method and params intact.
        let parked = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(taken) = delegate_take_next(&st).await {
                    return taken;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a sign request from an approved origin must reach the Sage delegate queue");

        let (id, method, params) = parked;
        assert_eq!(
            method, "chip0002_signMessage",
            "the method must be forwarded verbatim, not rewritten"
        );
        assert_eq!(
            params["message"], "hi",
            "params must survive the hop intact"
        );

        // Answer as Sage would, and confirm the answer is what the caller receives — so
        // the delegation is a real round trip, not a request that merely leaves.
        delegate_fulfill(&st, id, Ok(serde_json::json!("0xs1gnature"))).await;
        let (status, body) = caller.await.expect("dispatch task");
        assert_eq!(status, 200, "Sage's answer is returned to the dapp: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["data"], "0xs1gnature");
    }

    /// There is no wallet-source switch left to flip back to a local signer.
    ///
    /// The removed plane was reachable through a persisted wallet-source setting, so a
    /// residual file from an older build must not be able to re-enable it. The settings and
    /// wallet pages are separate files from this one, so scanning them cannot match this
    /// test's own text — the failure mode that makes a source-scanning assertion worthless.
    #[test]
    fn no_persisted_setting_can_route_a_sign_method_back_into_this_process() {
        assert!(
            !SETTINGS_HTML.contains("/api/wallet/source"),
            "the settings page must not offer a signer choice"
        );
        assert!(
            !UI_HTML.contains("/api/wallet/source"),
            "the wallet page must not read a signer choice"
        );
    }

    /// A `chip0002_connect` from an unapproved origin parks it pending and returns the
    /// HTTP-equivalent 202 with `{"status":"pending"}` — identical to the HTTP handler.
    #[tokio::test]
    async fn wallet_dispatch_connect_from_unapproved_origin_is_pending_202() {
        let st = AppState::default();
        let (status, body) = wallet_dispatch_with(
            &st,
            "https://newdapp.example",
            r#"{"method":"chip0002_connect"}"#,
        )
        .await;
        assert_eq!(status, 202, "connect from a new origin is pending approval");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "pending");
        // …and the origin was recorded as pending so the wallet UI can approve it.
        assert!(st
            .approvals
            .lock()
            .await
            .pending
            .contains("https://newdapp.example"));
    }

    /// `chip0002_chainId` is public (no approval, no unlock) and returns the OK 200
    /// `{"data":"mainnet"}` body — the shape the HTTP path returns. Driven through the
    /// PUBLIC `wallet_dispatch` (the FFI entrypoint's exact callee) to prove the
    /// process-global state path answers it too, with no origin and no session.
    #[tokio::test]
    async fn wallet_dispatch_chain_id_is_public_and_returns_mainnet() {
        let (status, body) = wallet_dispatch("", r#"{"method":"chip0002_chainId"}"#).await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["data"], "mainnet", "chainId data is mainnet: {body}");
    }

    /// Malformed request JSON is a clean 400 `{"error":...}` (never a panic / UB),
    /// since the browser process may hand us arbitrary bytes over the FFI.
    #[tokio::test]
    async fn wallet_dispatch_rejects_malformed_request_json() {
        let st = AppState::default();
        let (status, body) = wallet_dispatch_with(&st, "", "not json at all").await;
        assert_eq!(status, 400, "bad request JSON is a 400");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.get("error").is_some(), "carries an error body: {body}");
    }

    #[test]
    fn wc_dispatch_method_set_has_no_export_path() {
        // Guard the source of truth: the dapp-facing dispatcher must never RETURN
        // the recovery phrase or reach the export/decrypt path. (`mnemonic` as a
        // local signing secret is fine; what must not appear is returning it or
        // decrypting the seed.) If someone wires export into the dapp surface,
        // this fails.
        let src = include_str!("lib.rs");
        let dispatch = src
            .split("async fn wc_dispatch")
            .nth(1)
            .expect("wc_dispatch present")
            .split("\nasync fn ")
            .next()
            .unwrap();
        for forbidden in [
            "ExportResp",
            "/api/export",
            "decrypt_seed",
            "mnemonic.to_string()",
            "fn export",
        ] {
            assert!(
                !dispatch.contains(forbidden),
                "wc_dispatch must not reference {forbidden} (would leak the recovery phrase to dapps)"
            );
        }
    }

    // -- Export endpoint: self-origin + password gates -------------------------

    /// Build a HeaderMap carrying an Origin (the unspoofable dapp/page origin).
    fn origin_headers(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        h
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    /// The projectId setter is wallet-local only: a dapp origin cannot change it.
    #[tokio::test]
    async fn wc_project_id_set_is_self_origin_only() {
        let r = wc_project_id_set(
            origin_headers("https://evil.example.com"),
            Json(SetWcProjectId {
                project_id: "hijacked".to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    // -- Advanced coin types (Part B) ------------------------------------------

    #[test]
    fn advanced_methods_are_gated_and_need_a_wallet() {
        // Every advanced coin-type method is a key/sign method: forbidden until the
        // origin is approved, allowed once approved, and needs an unlocked wallet —
        // same gate as the core spend methods.
        for m in [
            "dig_clawbackSend",
            "dig_clawbackClaim",
            "dig_clawbackRecover",
            "dig_optionCreate",
            "dig_optionExercise",
            "dig_streamCreate",
            "dig_streamClaim",
            "dig_streamClawback",
            "dig_vaultCreate",
            "dig_vaultSpend",
            "dig_vcIssue",
            "dig_vcVerify",
            "dig_vcRevoke",
        ] {
            assert_eq!(
                wc_gate(m, false),
                Gate::Forbidden,
                "{m} forbidden unapproved"
            );
            assert_eq!(wc_gate(m, true), Gate::Allowed, "{m} allowed approved");
            assert!(wc_method_needs_wallet(m), "{m} needs a wallet");
        }
    }

    // -- Local on-chain STORE lifecycle (#95/#96 Pass B) -----------------------

    #[test]
    fn store_lifecycle_methods_are_gated_and_need_a_wallet() {
        // mint/advance/melt/delegate/transfer are all key/sign methods: forbidden
        // until the origin is approved, allowed once approved, and need an unlocked
        // wallet — the same gate as every other spend method.
        for m in [
            "chia_mintStore",
            "chia_advanceStore",
            "chia_meltStore",
            "chia_setStoreDelegation",
            "chia_setStoreOwnership",
        ] {
            assert_eq!(
                wc_gate(m, false),
                Gate::Forbidden,
                "{m} forbidden unapproved"
            );
            assert_eq!(wc_gate(m, true), Gate::Allowed, "{m} allowed approved");
            assert!(wc_method_needs_wallet(m), "{m} needs a wallet");
        }
    }

    #[tokio::test]
    async fn get_methods_is_public_and_advertises_the_store_lifecycle() {
        // chip0002_getMethods is an agent-friendly self-description: PUBLIC (no
        // origin approval, no unlocked wallet), and it lists every dispatchable
        // method — including the new local on-chain store-lifecycle methods.
        assert_eq!(wc_gate("chip0002_getMethods", false), Gate::Public);
        assert!(!wc_method_needs_wallet("chip0002_getMethods"));
        let st = AppState::default(); // locked wallet — must still answer
        let v = wc_dispatch(&st, "chip0002_getMethods", serde_json::Value::Null)
            .await
            .expect("getMethods is answered without a wallet");
        let methods: Vec<String> = serde_json::from_value(v).unwrap();
        for m in [
            "chia_mintStore",
            "chia_advanceStore",
            "chia_meltStore",
            "chia_setStoreDelegation",
            "chia_setStoreOwnership",
            "chip0002_getMethods",
        ] {
            assert!(
                methods.contains(&m.to_string()),
                "catalogue must advertise {m}"
            );
        }
    }

    #[test]
    fn method_catalogue_matches_the_gate_and_never_leaks_export() {
        // Every advertised method must be reachable through the gate (Public for the
        // handshake/introspection, Allowed-when-approved for the rest) and NONE may be
        // an export-class method — the catalogue can never become a seed-exfil hint.
        for m in WC_METHOD_CATALOGUE {
            assert!(
                !is_export_class_method(m),
                "{m} must never appear in the public method catalogue"
            );
            // Approved origin → never Forbidden (Public or Allowed).
            assert_ne!(
                wc_gate(m, true),
                Gate::Forbidden,
                "{m} unreachable when approved"
            );
        }
        // The handshake/introspection trio is public; everything else needs a wallet.
        assert!(WC_METHOD_CATALOGUE.contains(&"chia_mintStore"));
        assert!(WC_METHOD_CATALOGUE.contains(&"chip0002_getMethods"));
    }
}
