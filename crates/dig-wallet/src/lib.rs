//! dig-wallet — the DIG Browser's built-in Chia wallet sidecar.
//!
//! A local axum server (loopback only) that reuses `digstore-chain` (BIP-39
//! seed, standard Chia key derivation, the Sage-style HD wallet scan, DIG-CAT
//! support, AND encrypted seed storage) over coinset.org, and serves a
//! Sage-mirroring web UI the browser opens at 127.0.0.1. Native Rust, so BLS
//! (blst) signing works — unlike a WASM wallet.
//!
//! This build: create/restore a 24-word wallet protected by a password; the
//! seed is stored **encrypted at rest** (Argon2 + AES-GCM via
//! `digstore_chain::seed`) so the wallet persists across restarts and unlocks
//! with the password. Shows the live XCH + DIG balance scanned from coinset.org.
//!
//! Send/sign (`POST /api/send`): builds + BLS-signs a standard XCH payment via
//! `digstore_chain::send` (AugScheme, §11.3) drawing coins across the HD wallet.
//! Because a broadcast spends REAL mainnet funds, it is **gated twice**: the
//! request must set `broadcast: true` AND the process must run with
//! `DIG_WALLET_ALLOW_BROADCAST=1`. Otherwise the endpoint performs a **dry run** —
//! it returns the fully signed bundle (proof the signing path works) and pushes
//! NOTHING. The default is dry-run, so the flow can be exercised unattended safely.

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use digstore_chain::coinset::{ChainReads, Coinset};
use digstore_chain::keys::{derive_wallet_keys, owner_address};
use digstore_chain::seed::{
    decrypt_seed, encrypt_seed, generate_mnemonic, validate_mnemonic, EncryptedSeed,
};
use digstore_chain::send::{build_xch_send, decode_xch_address};
use digstore_chain::wallet::scan_wallet;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use zeroize::Zeroizing;

/// In-memory unlocked wallet for the session.
struct Session {
    mnemonic: Zeroizing<String>,
    address: String,
}

/// Where the embedded wallet answers wallet requests FROM (the "wallet source",
/// #34). `Native` signs with the local encrypted seed (the default, exactly the
/// behaviour before this feature). `Sage` *delegates* the full wallet surface to
/// the user's Sage wallet over a WalletConnect session in which **this** wallet is
/// the requester/client (the dual of the existing dapp-facing responder): each
/// CHIP-0002/chia method is forwarded over the relay to Sage and Sage's response
/// is returned. In `Sage` mode there is NO local signer in play — Sage holds the
/// keys — but the consent + broadcast gates are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WalletSource {
    /// Sign locally with the encrypted seed (default — zero behaviour change).
    #[default]
    Native,
    /// Delegate to Sage over a WalletConnect requester session.
    Sage,
}

impl WalletSource {
    /// The wire token persisted/served for this source (stable across versions).
    fn as_str(self) -> &'static str {
        match self {
            WalletSource::Native => "native",
            WalletSource::Sage => "sage",
        }
    }
    /// Parse the wire token; anything unrecognised falls back to the safe default
    /// (`Native`) so a corrupt/forward-incompatible value never strands the wallet.
    fn from_str(s: &str) -> WalletSource {
        match s {
            "sage" => WalletSource::Sage,
            _ => WalletSource::Native,
        }
    }
}

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

struct AppState {
    session: Mutex<Option<Session>>,
    approvals: Mutex<Approvals>,
    /// The active wallet source (Native local keys vs. Sage delegate). Persisted to
    /// disk (next to the seed) and loaded here so the choice survives restarts.
    source: Mutex<WalletSource>,
    /// Requester→Sage delegate bridge, used only when `source == Sage`.
    delegate: Mutex<DelegateBridge>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            session: Mutex::new(None),
            approvals: Mutex::new(Approvals::default()),
            source: Mutex::new(load_wallet_source()),
            delegate: Mutex::new(DelegateBridge::default()),
        }
    }
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

/// Path to the persisted wallet-source choice (next to the seed file). A tiny
/// `{ "source": "native" | "sage" }` JSON — kept separate from the seed so it is
/// readable/writable without unlocking and never touches key material.
fn wallet_source_path() -> PathBuf {
    seed_path()
        .parent()
        .map(|p| p.join("wallet-source.json"))
        .unwrap_or_else(|| PathBuf::from("wallet-source.json"))
}

/// Load the persisted wallet source (defaults to `Native` if absent/corrupt — the
/// safe local-keys behaviour).
fn load_wallet_source() -> WalletSource {
    std::fs::read(wallet_source_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| {
            v.get("source")
                .and_then(|s| s.as_str())
                .map(WalletSource::from_str)
        })
        .unwrap_or_default()
}

/// Persist the wallet source choice so it survives restarts.
fn save_wallet_source(source: WalletSource) {
    let path = wallet_source_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = serde_json::json!({ "source": source.as_str() });
    if let Ok(json) = serde_json::to_vec_pretty(&body) {
        let _ = std::fs::write(path, json);
    }
}

fn wallet_exists() -> bool {
    seed_path().exists()
}

#[derive(Serialize)]
struct StatusResp {
    /// "none" (no wallet yet), "locked" (encrypted seed on disk, needs unlock),
    /// or "unlocked" (a session is active).
    state: &'static str,
    address: Option<String>,
}

#[derive(Serialize)]
struct GenerateResp {
    mnemonic: String,
}

#[derive(Deserialize)]
struct ImportReq {
    mnemonic: String,
    /// Password that encrypts the seed at rest (also required to unlock later).
    password: String,
}

#[derive(Deserialize)]
struct UnlockReq {
    password: String,
}

#[derive(Serialize)]
struct AddressResp {
    address: String,
}

#[derive(Serialize)]
struct BalanceResp {
    address: String,
    /// XCH balance in mojos (1 XCH = 1e12 mojos).
    xch_mojos: u64,
    /// DIG balance in base units (1 DIG = 1e3 base units).
    dig_units: u64,
}

#[derive(Serialize)]
struct ErrResp {
    error: String,
}

fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrResp>) {
    (code, Json(ErrResp { error: msg.into() }))
}

/// Derive the receive address + store an unlocked session for `mnemonic`.
async fn open_session(st: &AppState, mnemonic: Zeroizing<String>) -> Result<String, String> {
    let keys = derive_wallet_keys(&mnemonic).map_err(|e| e.to_string())?;
    let address = owner_address(&keys);
    *st.session.lock().await = Some(Session {
        mnemonic,
        address: address.clone(),
    });
    Ok(address)
}

async fn status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let s = st.session.lock().await;
    if let Some(w) = s.as_ref() {
        return Json(StatusResp {
            state: "unlocked",
            address: Some(w.address.clone()),
        });
    }
    Json(StatusResp {
        state: if wallet_exists() { "locked" } else { "none" },
        address: None,
    })
}

/// Generate a fresh 24-word mnemonic (not stored until imported with a password).
async fn generate() -> Result<Json<GenerateResp>, (StatusCode, Json<ErrResp>)> {
    let m =
        generate_mnemonic(24).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(GenerateResp {
        mnemonic: m.to_string(),
    }))
}

/// Validate a mnemonic, encrypt + persist it under `password`, and unlock.
async fn import(
    State(st): State<Arc<AppState>>,
    Json(req): Json<ImportReq>,
) -> Result<Json<AddressResp>, (StatusCode, Json<ErrResp>)> {
    if req.password.len() < 8 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "password must be at least 8 characters",
        ));
    }
    let m = validate_mnemonic(&req.mnemonic).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("invalid recovery phrase: {e}"),
        )
    })?;
    // Encrypt at rest (Argon2 + AES-GCM) and persist.
    let enc = encrypt_seed(&m, &req.password)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let path = seed_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("create dir: {e}"),
            )
        })?;
    }
    std::fs::write(&path, enc.to_bytes()).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write seed: {e}"),
        )
    })?;
    let address = open_session(&st, Zeroizing::new(m.to_string()))
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(AddressResp { address }))
}

/// Decrypt the on-disk seed with `password` and unlock the session.
async fn unlock(
    State(st): State<Arc<AppState>>,
    Json(req): Json<UnlockReq>,
) -> Result<Json<AddressResp>, (StatusCode, Json<ErrResp>)> {
    let bytes = std::fs::read(seed_path())
        .map_err(|_| err(StatusCode::NOT_FOUND, "no wallet on this device"))?;
    let enc = EncryptedSeed::from_bytes(&bytes).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("corrupt seed file: {e}"),
        )
    })?;
    let m = decrypt_seed(&enc, &req.password)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "wrong password"))?;
    let address = open_session(&st, m)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(AddressResp { address }))
}

/// Live XCH + DIG balance, scanned from coinset.org (Sage-style whole-wallet scan).
async fn balance(
    State(st): State<Arc<AppState>>,
) -> Result<Json<BalanceResp>, (StatusCode, Json<ErrResp>)> {
    let (mnemonic, address) = {
        let s = st.session.lock().await;
        match s.as_ref() {
            Some(w) => (w.mnemonic.clone(), w.address.clone()),
            None => return Err(err(StatusCode::UNAUTHORIZED, "wallet is locked")),
        }
    };
    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, &mnemonic)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    Ok(Json(BalanceResp {
        address,
        xch_mojos: scanned.xch_balance(),
        dig_units: scanned.dig_balance(),
    }))
}

/// Lock the wallet (clear the session; the encrypted seed stays on disk).
async fn lock(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    *st.session.lock().await = None;
    StatusCode::NO_CONTENT
}

#[derive(Deserialize)]
struct SendReq {
    /// Recipient mainnet address (`xch1…`).
    to: String,
    /// Amount to send, in mojos (1 XCH = 1e12 mojos).
    amount_mojos: u64,
    /// Network fee in mojos (0 = no fee).
    #[serde(default)]
    fee_mojos: u64,
    /// Request an actual on-chain broadcast. Ignored unless the process also runs
    /// with `DIG_WALLET_ALLOW_BROADCAST=1`; otherwise the send is a dry run.
    #[serde(default)]
    broadcast: bool,
}

#[derive(Serialize)]
struct SendResp {
    /// "signed" — built + signed but NOT broadcast (dry run; nothing was spent); or
    /// "broadcast" — the signed bundle was pushed to mainnet (real funds spent).
    status: &'static str,
    to: String,
    amount_mojos: u64,
    fee_mojos: u64,
    /// Change returned to the wallet, in mojos.
    change_mojos: u64,
    /// Total mojos of the selected input coins.
    inputs_mojos: u64,
    /// Number of input coin spends in the bundle.
    coin_spends: usize,
    /// Hex of the aggregated BLS signature over the spend — proof the bundle is
    /// fully signed and ready to broadcast.
    aggregated_signature: String,
}

/// What to do with a built+signed send bundle. Kept as a pure decision so the
/// safety gate (never broadcast unattended) is unit-tested independently of the
/// network path.
#[derive(Debug, PartialEq, Eq)]
enum SendAction {
    /// Built + signed, push nothing (default / `broadcast:false`).
    DryRun,
    /// Both the request and the env opted in — push to mainnet.
    Broadcast,
    /// `broadcast:true` requested but broadcasting is disabled — refuse (do not push).
    RefusedDisabled,
}

/// Broadcasting requires BOTH an explicit `broadcast:true` request AND the process
/// env opt-in (`DIG_WALLET_ALLOW_BROADCAST=1`). Anything else is a dry run; an
/// explicit request while disabled is refused (never silently downgraded).
fn send_action(req_broadcast: bool, env_enabled: bool) -> SendAction {
    match (req_broadcast, env_enabled) {
        (true, true) => SendAction::Broadcast,
        (true, false) => SendAction::RefusedDisabled,
        (false, _) => SendAction::DryRun,
    }
}

/// Build + BLS-sign a standard XCH payment. **Spends real mainnet funds only when
/// explicitly enabled.** Broadcasting requires BOTH `broadcast: true` in the request
/// AND `DIG_WALLET_ALLOW_BROADCAST=1` in the environment; otherwise the endpoint
/// returns the fully signed bundle as a dry run and pushes nothing. A `broadcast:
/// true` request while broadcasting is disabled is refused (403) — never silently
/// downgraded — so the caller knows the spend did not happen.
async fn send(
    State(st): State<Arc<AppState>>,
    Json(req): Json<SendReq>,
) -> Result<Json<SendResp>, (StatusCode, Json<ErrResp>)> {
    let recipient_ph =
        decode_xch_address(&req.to).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let mnemonic = {
        let s = st.session.lock().await;
        match s.as_ref() {
            Some(w) => w.mnemonic.clone(),
            None => return Err(err(StatusCode::UNAUTHORIZED, "wallet is locked")),
        }
    };
    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, &mnemonic)
        .await
        .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    let (bundle, plan) = build_xch_send(&scanned, recipient_ph, req.amount_mojos, req.fee_mojos)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;

    let broadcast_enabled =
        std::env::var("DIG_WALLET_ALLOW_BROADCAST").ok().as_deref() == Some("1");
    let status = match send_action(req.broadcast, broadcast_enabled) {
        SendAction::Broadcast => {
            chain
                .push(bundle.clone())
                .await
                .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("push_tx: {e}")))?;
            "broadcast"
        }
        SendAction::RefusedDisabled => {
            // Refuse rather than silently dry-run, so the caller is not misled into
            // thinking funds moved.
            return Err(err(
                StatusCode::FORBIDDEN,
                "broadcasting is disabled — set DIG_WALLET_ALLOW_BROADCAST=1 to spend real mainnet funds",
            ));
        }
        SendAction::DryRun => "signed", // signed, not pushed
    };

    Ok(Json(SendResp {
        status,
        to: req.to,
        amount_mojos: req.amount_mojos,
        fee_mojos: req.fee_mojos,
        change_mojos: plan.change,
        inputs_mojos: plan.inputs,
        coin_spends: bundle.coin_spends.len(),
        aggregated_signature: hex::encode(bundle.aggregated_signature.to_bytes()),
    }))
}

// ---- My Stores: the wallet's own DataLayer stores as capsules ----------------
//
// A user's DataLayer stores are discovered across the HD wallet and reported as
// CAPSULES — the canonical `storeId:rootHash` identity (`digstore_core::Capsule`).
// `/api/stores` lists every store's CURRENT capsule + which HD index owns it;
// `/api/stores/history` returns one store's full capsule lineage (eve → current).
// Wallet-local (needs an unlocked session); not a dapp-facing WC method.

/// One owned store in the list view: its current capsule (`storeId:rootHash`), the
/// HD index that owns it, and the current root (so the UI can show it without
/// re-parsing the capsule string).
#[derive(Serialize)]
struct StoreEntry {
    /// The store id (launcher id), `0x` hex.
    store_id: String,
    /// The canonical current capsule string: `storeId:rootHash`.
    current_capsule: String,
    /// The HD index whose address owns this store.
    hd_index: u32,
    /// The current root hash, `0x`-free lowercase hex (matches the capsule's tail).
    current_root: String,
}

#[derive(Serialize)]
struct StoresResp {
    stores: Vec<StoreEntry>,
}

/// List the wallet's own DataLayer stores, each as its CURRENT capsule
/// (`storeId:rootHash`) plus the HD index that owns it. Discovers stores across the
/// whole HD wallet ([`discover_all_user_stores`]) then syncs each to its current
/// root ([`sync_datastore_with_history`]). Wallet-local (unlocked session required).
async fn stores_list(
    State(st): State<Arc<AppState>>,
) -> Result<Json<StoresResp>, (StatusCode, Json<ErrResp>)> {
    let mnemonic = {
        let s = st.session.lock().await;
        match s.as_ref() {
            Some(w) => w.mnemonic.clone(),
            None => return Err(err(StatusCode::UNAUTHORIZED, "wallet is locked")),
        }
    };
    let chain = Coinset::mainnet();
    let discovered = digstore_chain::singleton::discover_all_user_stores(&chain, &mnemonic)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("store discovery failed: {e}"),
            )
        })?;

    let mut stores = Vec::with_capacity(discovered.len());
    for (hd_index, store_id) in discovered {
        let (_store, history) =
            digstore_chain::singleton::sync_datastore_with_history(&chain, store_id)
                .await
                .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("store sync failed: {e}")))?;
        // `Capsule::canonical()` is the ecosystem-wide storeId:rootHash identity.
        stores.push(StoreEntry {
            store_id: format!("0x{}", hex::encode(store_id)),
            current_capsule: history.current.canonical(),
            hd_index,
            current_root: history.current.root_hash.to_hex(),
        });
    }
    Ok(Json(StoresResp { stores }))
}

#[derive(Deserialize)]
struct StoreHistoryQuery {
    /// The store id (launcher id), `0x`-prefixed or bare hex.
    store_id: String,
}

#[derive(Serialize)]
struct StoreHistoryResp {
    store_id: String,
    /// The current capsule (`storeId:rootHash`) — equals the last `capsules` entry.
    current_capsule: String,
    /// Every capsule the store has ever been, oldest → newest, as canonical strings.
    capsules: Vec<String>,
}

/// One store's full capsule history (eve → current) as canonical `storeId:rootHash`
/// strings, via [`sync_datastore_with_history`]. Wallet-local (unlocked session).
async fn store_history(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<StoreHistoryQuery>,
) -> Result<Json<StoreHistoryResp>, (StatusCode, Json<ErrResp>)> {
    {
        let s = st.session.lock().await;
        if s.is_none() {
            return Err(err(StatusCode::UNAUTHORIZED, "wallet is locked"));
        }
    }
    let store_id = parse_asset_id_hex(&q.store_id).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    let chain = Coinset::mainnet();
    let (_store, history) =
        digstore_chain::singleton::sync_datastore_with_history(&chain, store_id)
            .await
            .map_err(|e| err(StatusCode::BAD_GATEWAY, format!("store sync failed: {e}")))?;
    Ok(Json(StoreHistoryResp {
        store_id: format!("0x{}", hex::encode(store_id)),
        current_capsule: history.current.canonical(),
        capsules: history.history.iter().map(|c| c.canonical()).collect(),
    }))
}

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
        cache_cap_bytes: dig_node::cache_cap_bytes(),
        cache_used_bytes: dig_node::cache_used_bytes(),
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
    match dig_node::set_cache_cap_bytes(cap) {
        Ok(()) => (
            StatusCode::OK,
            Json(DigConfig {
                cache_cap_bytes: cap,
                cache_used_bytes: dig_node::cache_used_bytes(),
            }),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Purge the entire local DIG cache. Content stays available — it just falls
/// back to rpc.dig.net on next visit and re-warms the cache.
async fn dig_cache_clear() -> impl IntoResponse {
    dig_node::clear_cache();
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
/// and the last-used (LRU recency) timestamp. Mirrors [`dig_node::CachedCapsule`] one to
/// one; rendered by [`cached_capsule_json`] so the wire shape is unit-tested.
fn cached_capsule_json(c: &dig_node::CachedCapsule) -> serde_json::Value {
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
/// not a dapp surface). Reads via `dig_node::Node::cache_list_cached` on a fresh
/// `Node::from_env()` — the same cache dir the loader/CLI use.
async fn dig_cache_list(headers: HeaderMap) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node::Node::from_env();
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
/// `dig_node::Node::cache_remove_cached`, which validates the hex + guards path traversal.
async fn dig_cache_remove(headers: HeaderMap, Json(req): Json<CacheCapsuleReq>) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node::Node::from_env();
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
/// `dig_node::Node::cache_fetch_and_cache`; a failed fetch is reported in-band
/// (`status:"failed"`) so the manager shows it without treating it as a transport error.
async fn dig_cache_fetch(headers: HeaderMap, Json(req): Json<CacheCapsuleReq>) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "cache manager is wallet-local only").into_response();
    }
    let node = dig_node::Node::from_env();
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
    let id = dig_node::wc_project_id();
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
    match dig_node::set_wc_project_id(&req.project_id) {
        Ok(()) => {
            let id = dig_node::wc_project_id();
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

// ---- DIG settings: wallet source (Native local keys vs. Sage delegate) #34 ---
//
// The "Wallet source" control. `Native` (default) signs with the local encrypted
// seed; `Sage` delegates every key/sign method to the user's Sage wallet over a
// WalletConnect requester session (see `delegate_to_sage` / the delegate bridge).
// `window.chia` and the per-origin consent gate are unchanged either way — only the
// signer moves. The setter is self-origin only (only the settings UI may flip it).

/// The active wallet source surfaced to the settings page.
#[derive(Serialize)]
struct WalletSourceResp {
    /// `"native"` or `"sage"` — the persisted, active source.
    source: &'static str,
}

/// Read the active wallet source (Native vs. Sage). Readable by the wallet UI + the
/// settings page so both can render the right state and run the delegate pump when
/// Sage is selected.
async fn wallet_source_get(State(st): State<Arc<AppState>>) -> Json<WalletSourceResp> {
    Json(WalletSourceResp {
        source: st.source.lock().await.as_str(),
    })
}

#[derive(Deserialize)]
struct SetWalletSource {
    /// `"native"` or `"sage"` (anything else is treated as `native`).
    source: String,
}

/// Set the active wallet source (DIG settings). Self-origin only — only the settings
/// UI may flip it, never a dapp. Persists the choice so it survives restarts. Note
/// this only selects WHERE requests are answered; it never touches key material, and
/// switching to Sage does NOT establish the session (the page's connect flow does).
async fn wallet_source_set(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetWalletSource>,
) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "settings are wallet-local only").into_response();
    }
    let source = WalletSource::from_str(&req.source);
    *st.source.lock().await = source;
    save_wallet_source(source);
    (
        StatusCode::OK,
        Json(WalletSourceResp {
            source: source.as_str(),
        }),
    )
        .into_response()
}

/// The wallet's public identity, safe to display in plain text.
#[derive(Serialize)]
struct PubKeyResp {
    /// The owner (first synthetic) public key, hex (no `0x`) — the same value
    /// `chip0002_getPublicKeys`/`derive_wallet_keys` exposes.
    public_key: String,
    /// The owner mainnet receive address (`xch1…`).
    address: String,
}

/// The wallet's public key + address (read-only, plain text in DIG settings).
/// Requires an unlocked session; public keys are not secret, but we still gate
/// to the wallet's own origin so it is never served to a dapp page.
async fn wallet_pubkey(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "wallet-local only").into_response();
    }
    let mnemonic = {
        let s = st.session.lock().await;
        match s.as_ref() {
            Some(w) => w.mnemonic.clone(),
            None => return (StatusCode::UNAUTHORIZED, "wallet is locked").into_response(),
        }
    };
    match derive_wallet_keys(&mnemonic) {
        Ok(keys) => (
            StatusCode::OK,
            Json(PubKeyResp {
                public_key: hex::encode(keys.synthetic_pk.to_bytes()),
                address: owner_address(&keys),
            }),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ExportReq {
    /// The wallet password — re-entered to authorize revealing the master secret.
    password: String,
}

#[derive(Serialize)]
struct ExportResp {
    /// The 24-word master mnemonic. THE master secret — anyone with it controls
    /// the funds. Served only to the wallet's own origin, only on a correct
    /// password, and never to any dapp-facing path.
    mnemonic: String,
}

/// Reveal the wallet's recovery phrase for backup. The most sensitive endpoint:
///
/// * **Self-origin only** — restricted to the wallet's own loopback origin via
///   the unspoofable `Origin` header, so a dapp page can never call it.
/// * **Password-gated** — the on-disk encrypted seed is decrypted with the
///   password supplied *in this request* (not the live session), so revealing
///   the master secret always requires re-proving the password.
/// * **Unreachable from dapps** — it is its own route, NOT a `wc_dispatch`
///   method, so no `/api/wc/request`, injected provider, or WC session can hit it.
///
/// The mnemonic is never logged. The UI reveals it transiently (reveal-then-hide).
async fn export(headers: HeaderMap, Json(req): Json<ExportReq>) -> Response {
    // Gate 1: only the wallet's own UI origin may ever ask to export.
    if !is_self_origin(&origin_of(&headers)) {
        return (StatusCode::FORBIDDEN, "export is wallet-local only").into_response();
    }
    // Gate 2: re-decrypt the on-disk seed with the supplied password. A wrong
    // password fails decryption (AEAD) — there is no other way to recover it.
    let bytes = match std::fs::read(seed_path()) {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "no wallet on this device").into_response(),
    };
    let enc = match EncryptedSeed::from_bytes(&bytes) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("corrupt seed file: {e}"),
            )
                .into_response()
        }
    };
    match decrypt_seed(&enc, &req.password) {
        Ok(m) => (
            StatusCode::OK,
            Json(ExportResp {
                mnemonic: m.to_string(),
            }),
        )
            .into_response(),
        Err(_) => (StatusCode::UNAUTHORIZED, "wrong password").into_response(),
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

/// Sage's default `getPublicKeys` window, and the most keys we will derive for
/// one request (a dapp must not be able to force unbounded derivation).
const DEFAULT_PUBKEYS: u32 = 10;
const MAX_PUBKEYS: u32 = 1000;
/// Wallet indices searched when matching a `publicKey` / covering coin spends.
const KEY_SEARCH_WINDOW: u32 = 100;

/// Resolve `{offset?, limit?}` for `chip0002_getPublicKeys`: Sage's defaults,
/// with the limit clamped so a dapp can't make us derive unboundedly.
fn pubkey_window(params: &serde_json::Value) -> (u32, u32) {
    let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let limit = params
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n.min(MAX_PUBKEYS as u64) as u32)
        .unwrap_or(DEFAULT_PUBKEYS);
    (offset, limit)
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

/// Where a dispatched WC method is answered FROM, given the active wallet source
/// (#34). Decided purely so the policy is unit-tested independently of state/HTTP.
#[derive(Debug, PartialEq, Eq)]
enum WcRoute {
    /// Answer with the local encrypted-seed signer (the only route in Native mode,
    /// and still the route for the keyless handshake methods even in Sage mode).
    Native,
    /// Forward over the WalletConnect requester session to Sage (Sage mode only,
    /// for the methods that read keys or sign).
    Delegate,
}

/// Decide whether `method` is answered locally or delegated to Sage, given the
/// active `source`. In `Native` mode everything is local (zero behaviour change).
/// In `Sage` mode the keyless handshake methods (`chainId`, `connect` — the same
/// ones [`wc_method_needs_wallet`] marks as not needing the wallet) are still
/// answered locally (they touch no keys and must work before any Sage session is
/// up); every key/sign method is delegated to Sage. Pure so the routing policy is
/// guarded by a unit test against both modes.
fn wc_route(source: WalletSource, method: &str) -> WcRoute {
    match source {
        WalletSource::Native => WcRoute::Native,
        WalletSource::Sage => {
            if wc_method_needs_wallet(method) {
                WcRoute::Delegate
            } else {
                WcRoute::Native
            }
        }
    }
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

/// Dispatch one WalletConnect / CHIP-0002 request to the native signer, returning
/// the bare result value Sage would return (the in-page WC client wraps it into
/// the WC response). Signing methods require an unlocked wallet.
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

    // Wallet-source routing (#34): in Sage delegate mode, forward every key/sign
    // method to Sage over the requester session instead of touching a local seed —
    // Sage holds the keys. Native mode falls straight through to the local signer
    // below (zero behaviour change). The handshake methods returned above are
    // answered locally in either mode (they touch no keys).
    let source = *st.source.lock().await;
    if wc_route(source, method) == WcRoute::Delegate {
        // Defence in depth: even if a Sage implemented an export-flavoured method,
        // the delegate surface must never become a seed-exfiltration path. Reject
        // before it ever reaches the relay (this matches the local 501 arm).
        if is_export_class_method(method) {
            return Err(wc_err(
                StatusCode::NOT_IMPLEMENTED,
                format!("unsupported WC method: {method}"),
            ));
        }
        return delegate_to_sage(st, method, params).await;
    }

    let mnemonic = {
        let s = st.session.lock().await;
        match s.as_ref() {
            Some(w) => w.mnemonic.clone(),
            None => return Err(wc_err(StatusCode::UNAUTHORIZED, "wallet is locked")),
        }
    };
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    match method {
        "chip0002_getPublicKeys" => {
            let (offset, limit) = pubkey_window(&params);
            let keys = digstore_chain::chip0002::wallet_public_keys(&mnemonic, offset, limit)
                .map_err(bad)?;
            Ok(json!(keys))
        }
        "chip0002_signMessage" => {
            let message = params
                .get("message")
                .and_then(|m| m.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'message'"))?;
            let public_key = params
                .get("publicKey")
                .and_then(|m| m.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'publicKey'"))?;
            let sig = digstore_chain::chip0002::sign_message_by_public_key(
                &mnemonic,
                public_key,
                message.as_bytes(),
                KEY_SEARCH_WINDOW,
            )
            .map_err(bad)?;
            Ok(json!(sig))
        }
        "chip0002_signCoinSpends" => {
            let spends_val = params
                .get("coinSpends")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let spends: Vec<digstore_chain::chip0002::WcCoinSpend> =
                serde_json::from_value(spends_val)
                    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, format!("bad coinSpends: {e}")))?;
            let sig = digstore_chain::chip0002::sign_wc_coin_spends(
                &mnemonic,
                &spends,
                KEY_SEARCH_WINDOW,
            )
            .map_err(bad)?;
            Ok(json!(sig))
        }
        "chia_getAddress" => {
            let keys = digstore_chain::keys::derive_wallet_keys(&mnemonic).map_err(bad)?;
            Ok(json!({ "address": digstore_chain::keys::owner_address(&keys) }))
        }
        "chia_signMessageByAddress" => {
            let message = params
                .get("message")
                .and_then(|m| m.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'message'"))?;
            let address = params
                .get("address")
                .and_then(|m| m.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'address'"))?;
            let signed = digstore_chain::chip0002::sign_message_by_address(
                &mnemonic,
                address,
                message.as_bytes(),
            )
            .map_err(bad)?;
            Ok(json!(signed))
        }
        "chip0002_getAssetBalance" => {
            // The hub reads `resp.confirmed`; type null => XCH, type "cat" => a CAT
            // identified by `assetId` (DIG when omitted). Generic over the TAIL, so
            // any CAT the wallet holds is reported — not just DIG. Drives the
            // account-menu XCH balance and every token balance widget.
            let is_cat = params.get("type").and_then(|t| t.as_str()) == Some("cat");
            let chain = Coinset::mainnet();
            let confirmed = if is_cat {
                let asset_id = cat_asset_id(&params)?;
                // Spendable base units of this CAT at the wallet's per-asset CAT puzzle
                // hash, summed across every scanned HD address (Sage-style).
                let owner_phs = wallet_owner_phs(&mnemonic).await?;
                let mut total = 0u64;
                for ph in owner_phs {
                    total = total.saturating_add(
                        digstore_chain::cat::cat_balance(&chain, ph, asset_id)
                            .await
                            .map_err(|e| {
                                wc_err(
                                    StatusCode::BAD_GATEWAY,
                                    format!("coinset CAT balance failed: {e}"),
                                )
                            })?,
                    );
                }
                total
            } else {
                let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                    wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
                })?;
                scanned.xch_balance()
            };
            Ok(json!({ "confirmed": confirmed, "spendable": confirmed }))
        }
        "chip0002_getAssetCoins" => {
            // The hub's spend path. Returns Sage's SpendableCoin shape: each entry is
            // { coin{parent_coin_info,puzzle_hash,amount}, locked, spent_block_index }
            // plus, for XCH, `puzzle` = the standard p2 reveal curried with that
            // coin's synthetic key (the hub uncurries it to recover the key per coin).
            // DIG CAT entries omit `puzzle` — the hub rebuilds the CAT lineage proof
            // from the parent spend. type null => XCH; type "cat" => the DIG CAT.
            let is_cat = params.get("type").and_then(|t| t.as_str()) == Some("cat");
            let offset = params.get("offset").and_then(|o| o.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|l| l.as_u64()).unwrap_or(100) as usize;
            let chain = Coinset::mainnet();
            let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
            })?;
            let mut coins = Vec::new();
            if is_cat {
                // Generic over the TAIL: the unspent CAT coins of `assetId` (DIG when
                // omitted) at each address's per-asset CAT puzzle hash. The DIG scan
                // shortcut still applies for DIG; any other CAT is read directly.
                let asset_id = cat_asset_id(&params)?;
                let is_dig = asset_id == digstore_chain::dig::DIG_ASSET_ID;
                for a in &scanned.addrs {
                    if is_dig {
                        for c in &a.dig {
                            coins.push(coin_entry_json(c, None));
                        }
                    } else {
                        let ph = digstore_chain::cat::cat_puzzle_hash(
                            a.keys.owner_puzzle_hash,
                            asset_id,
                        );
                        let cat_coins = chain.unspent_coins(ph).await.map_err(|e| {
                            wc_err(
                                StatusCode::BAD_GATEWAY,
                                format!("coinset CAT coins failed: {e}"),
                            )
                        })?;
                        for c in &cat_coins {
                            coins.push(coin_entry_json(c, None));
                        }
                    }
                }
            } else {
                for a in &scanned.addrs {
                    let puzzle =
                        digstore_chain::send::standard_puzzle_reveal_hex(&a.keys.synthetic_pk)
                            .map_err(bad)?;
                    for c in &a.xch {
                        coins.push(coin_entry_json(c, Some(&puzzle)));
                    }
                }
            }
            let page: Vec<_> = coins.into_iter().skip(offset).take(limit).collect();
            Ok(json!({ "coins": page }))
        }
        "chia_takeOffer" => {
            // The hub's badge-minting path: accept a MintGarden offer (pay the
            // requested DIG, receive the badge NFT). Build + BLS-sign the taker side
            // over the wallet's scanned DIG/XCH; the maker's half is already signed
            // inside the offer. Like /api/send, this is gated TWICE before it spends
            // real funds: it dry-runs (signs but pushes nothing) unless the env opts
            // in with DIG_WALLET_ALLOW_BROADCAST=1.
            let offer = params
                .get("offer")
                .and_then(|o| o.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'offer'"))?;
            // Fee tolerated as number or decimal string (dapps send both); default 0.
            let fee = params
                .get("fee")
                .map(|f| {
                    f.as_u64()
                        .or_else(|| f.as_str().and_then(|s| s.trim().parse().ok()))
                        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "invalid 'fee'"))
                })
                .transpose()?
                .unwrap_or(0);

            let chain = Coinset::mainnet();
            // mainnet agg_sig (for_testnet = false) — same as the canonical send path.
            let taken =
                digstore_chain::offer::build_take_offer(&chain, &mnemonic, offer, fee, false)
                    .await
                    .map_err(bad)?;

            let broadcast_enabled =
                std::env::var("DIG_WALLET_ALLOW_BROADCAST").ok().as_deref() == Some("1");
            // A dapp cannot itself force a broadcast; taking an offer is treated as a
            // broadcast-intent request, so it pushes only when the env also opts in.
            let status = match send_action(true, broadcast_enabled) {
                SendAction::Broadcast => {
                    chain
                        .push(taken.bundle.clone())
                        .await
                        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("push_tx: {e}")))?;
                    "broadcast"
                }
                // Disabled → dry run (signed, not pushed). The hub still gets a
                // success-shaped result proving the take was built + signed.
                SendAction::RefusedDisabled | SendAction::DryRun => "signed",
            };

            // Sage's chia_takeOffer returns a transaction-ish object; the hub tolerates
            // any shape, so report status + the signed bundle + what was paid.
            Ok(json!({
                "status": status,
                "success": true,
                "spendBundle": {
                    "coinSpends": taken.bundle.coin_spends.len(),
                    "aggregatedSignature": hex::encode(taken.bundle.aggregated_signature.to_bytes()),
                },
                "paid": {
                    "xch": taken.cost.xch.to_string(),
                    "cats": taken
                        .cost
                        .cats
                        .iter()
                        .map(|(id, amt)| json!({
                            "assetId": format!("0x{}", hex::encode(id)),
                            "amount": amt.to_string(),
                        }))
                        .collect::<Vec<_>>(),
                },
            }))
        }
        "chia_getTransactions" => {
            // Paginated wallet transaction history (XCH + DIG CAT), newest-first.
            let page = params.get("page").and_then(|p| p.as_u64()).unwrap_or(0) as usize;
            let chain = Coinset::mainnet();
            let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
            })?;
            let txs = digstore_chain::wallet::wallet_transactions(&chain, &scanned, page)
                .await
                .map_err(bad)?;
            Ok(json!({
                "page": page,
                "transactions": txs.iter().map(tx_json).collect::<Vec<_>>(),
            }))
        }
        "chia_getNfts" => {
            // List the wallet's owned NFTs across every HD address (off-chain media is
            // app-side; this returns the on-chain metadata/identity it has).
            let chain = Coinset::mainnet();
            let owner_phs = wallet_owner_phs(&mnemonic).await?;
            let nfts = digstore_chain::nft::list_owned_nfts(&chain, &owner_phs)
                .await
                .map_err(bad)?;
            Ok(json!({ "nfts": nfts.iter().map(owned_nft_json).collect::<Vec<_>>() }))
        }
        "chia_transferNft" => {
            // Transfer an owned NFT (identified by its current coin id or launcher id)
            // to `to`, optional `fee`. State-changing → broadcast/dry-run env gate.
            let to = params
                .get("to")
                .or_else(|| params.get("address"))
                .and_then(|a| a.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'to'"))?;
            let new_owner_ph = digstore_chain::send::decode_xch_address(to).map_err(bad)?;
            let fee = json_u64(&params, "fee").unwrap_or(0);

            let chain = Coinset::mainnet();
            let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
            })?;
            let owner_phs: Vec<_> = scanned
                .addrs
                .iter()
                .map(|a| a.keys.owner_puzzle_hash)
                .collect();
            let owned = digstore_chain::nft::list_owned_nfts(&chain, &owner_phs)
                .await
                .map_err(bad)?;
            let idx = find_owned_index(owned.iter().map(|n| (n.coin_id, n.launcher_id)), &params)?;
            let nft = &owned[idx];
            // The address that holds the NFT authorizes the spend (match by its p2 ph).
            let owner = scanned
                .addrs
                .iter()
                .find(|a| a.keys.owner_puzzle_hash == nft.p2_puzzle_hash)
                .map(|a| a.keys.clone())
                .ok_or_else(|| {
                    wc_err(StatusCode::BAD_REQUEST, "NFT is not owned by this wallet")
                })?;
            // A fee draws from an XCH coin at the owner's address.
            let fee_coin = if fee > 0 {
                scanned
                    .addrs
                    .iter()
                    .find(|a| a.keys.owner_puzzle_hash == owner.owner_puzzle_hash)
                    .and_then(|a| a.xch.first().copied())
            } else {
                None
            };
            let (spends, _child) = digstore_chain::nft::build_nft_transfer(
                &chain,
                &owner,
                nft.nft.coin,
                new_owner_ph,
                fee,
                fee_coin,
            )
            .await
            .map_err(bad)?;
            let sig = digstore_chain::nft::sign_nft_spends(
                &spends,
                std::slice::from_ref(&owner.synthetic_sk),
                false,
            )
            .map_err(bad)?;
            let bundle = chia_protocol::SpendBundle::new(spends, sig);
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            Ok(singleton_spend_json(status, n, &bundle))
        }
        "chia_mintNft" => {
            // Mint one NFT from a funding XCH coin at the wallet's primary address.
            let chain = Coinset::mainnet();
            let minter = digstore_chain::keys::derive_indexed_keys(&mnemonic, 0..1)
                .map_err(bad)?
                .into_iter()
                .next()
                .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))?;
            let funding = find_funding_coin(&chain, &mnemonic, minter.owner_puzzle_hash).await?;
            let spec = parse_mint_spec(&params, minter.owner_puzzle_hash)?;
            let (spends, nft) =
                digstore_chain::nft::build_nft_mint(&minter, funding, &spec).map_err(bad)?;
            let sig = digstore_chain::nft::sign_nft_spends(
                &spends,
                std::slice::from_ref(&minter.synthetic_sk),
                false,
            )
            .map_err(bad)?;
            let bundle = chia_protocol::SpendBundle::new(spends, sig);
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            let mut out = singleton_spend_json(status, n, &bundle);
            out["launcherId"] = json!(format!("0x{}", hex::encode(nft.info.launcher_id)));
            Ok(out)
        }
        "chia_bulkMintNfts" => {
            // Bulk-mint N NFTs from one funding XCH coin, atomically in one bundle.
            let chain = Coinset::mainnet();
            let minter = digstore_chain::keys::derive_indexed_keys(&mnemonic, 0..1)
                .map_err(bad)?
                .into_iter()
                .next()
                .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))?;
            let specs_val = params
                .get("nfts")
                .or_else(|| params.get("specs"))
                .and_then(|v| v.as_array())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'nfts' (array)"))?;
            let mut specs = Vec::with_capacity(specs_val.len());
            for s in specs_val {
                specs.push(parse_mint_spec(s, minter.owner_puzzle_hash)?);
            }
            let funding = find_funding_coin(&chain, &mnemonic, minter.owner_puzzle_hash).await?;
            let (spends, nfts) =
                digstore_chain::nft::build_bulk_mint(&minter, funding, &specs).map_err(bad)?;
            let sig = digstore_chain::nft::sign_nft_spends(
                &spends,
                std::slice::from_ref(&minter.synthetic_sk),
                false,
            )
            .map_err(bad)?;
            let bundle = chia_protocol::SpendBundle::new(spends, sig);
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            let mut out = singleton_spend_json(status, n, &bundle);
            out["launcherIds"] = json!(nfts
                .iter()
                .map(|n| format!("0x{}", hex::encode(n.info.launcher_id)))
                .collect::<Vec<_>>());
            Ok(out)
        }
        "chia_getDids" => {
            // List the wallet's owned DIDs (profiles) across every HD address.
            let chain = Coinset::mainnet();
            let owner_phs = wallet_owner_phs(&mnemonic).await?;
            let dids = digstore_chain::did::list_owned_dids(&chain, &owner_phs)
                .await
                .map_err(bad)?;
            Ok(json!({ "dids": dids.iter().map(owned_did_json).collect::<Vec<_>>() }))
        }
        "chia_createDidWallet" => {
            // Create a DID (profile) from a funding XCH coin at the primary address.
            // `create_simple_did` by default; an explicit recovery config uses
            // `create_did` (recoveryListHash? + numVerificationsRequired).
            let chain = Coinset::mainnet();
            let creator = digstore_chain::keys::derive_indexed_keys(&mnemonic, 0..1)
                .map_err(bad)?
                .into_iter()
                .next()
                .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))?;
            let funding = find_funding_coin(&chain, &mnemonic, creator.owner_puzzle_hash).await?;

            let (spends, did) = if params.get("numVerificationsRequired").is_some()
                || params.get("recoveryListHash").is_some()
            {
                let recovery = match params.get("recoveryListHash").and_then(|v| v.as_str()) {
                    Some(s) if !s.trim().is_empty() => Some(
                        parse_asset_id_hex(s).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?,
                    ),
                    _ => None,
                };
                let n = json_u64(&params, "numVerificationsRequired").unwrap_or(1);
                digstore_chain::did::create_did(&creator, funding, recovery, n).map_err(bad)?
            } else {
                digstore_chain::did::create_simple_did(&creator, funding).map_err(bad)?
            };
            let sig = digstore_chain::did::sign_did_spends(
                &spends,
                std::slice::from_ref(&creator.synthetic_sk),
                false,
            )
            .map_err(bad)?;
            let bundle = chia_protocol::SpendBundle::new(spends, sig);
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            let mut out = singleton_spend_json(status, n, &bundle);
            out["launcherId"] = json!(format!("0x{}", hex::encode(did.info.launcher_id)));
            Ok(out)
        }
        "chia_transferDid" => {
            // Transfer an owned DID (by coinId or launcherId) to `to`, optional `fee`.
            let to = params
                .get("to")
                .or_else(|| params.get("address"))
                .and_then(|a| a.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'to'"))?;
            let new_owner_ph = digstore_chain::send::decode_xch_address(to).map_err(bad)?;
            let fee = json_u64(&params, "fee").unwrap_or(0);

            let chain = Coinset::mainnet();
            let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
            })?;
            let owner_phs: Vec<_> = scanned
                .addrs
                .iter()
                .map(|a| a.keys.owner_puzzle_hash)
                .collect();
            let owned = digstore_chain::did::list_owned_dids(&chain, &owner_phs)
                .await
                .map_err(bad)?;
            let idx = find_owned_index(owned.iter().map(|d| (d.coin_id, d.launcher_id)), &params)?;
            let did = &owned[idx];
            let owner = scanned
                .addrs
                .iter()
                .find(|a| a.keys.owner_puzzle_hash == did.p2_puzzle_hash)
                .map(|a| a.keys.clone())
                .ok_or_else(|| {
                    wc_err(StatusCode::BAD_REQUEST, "DID is not owned by this wallet")
                })?;
            let fee_coin = if fee > 0 {
                scanned
                    .addrs
                    .iter()
                    .find(|a| a.keys.owner_puzzle_hash == owner.owner_puzzle_hash)
                    .and_then(|a| a.xch.first().copied())
            } else {
                None
            };
            let (spends, _child) = digstore_chain::did::build_did_transfer(
                &chain,
                &owner,
                did.did.coin,
                new_owner_ph,
                fee,
                fee_coin,
            )
            .await
            .map_err(bad)?;
            let sig = digstore_chain::did::sign_did_spends(
                &spends,
                std::slice::from_ref(&owner.synthetic_sk),
                false,
            )
            .map_err(bad)?;
            let bundle = chia_protocol::SpendBundle::new(spends, sig);
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            Ok(singleton_spend_json(status, n, &bundle))
        }
        "chia_getOfferSummary" => {
            // Inspect an offer WITHOUT taking it: offered/requested assets, the net
            // the taker must fund (arbitrage), and any NFT royalties. Read-only; needs
            // an unlocked wallet only to match the other methods' gate.
            let offer = params
                .get("offer")
                .and_then(|o| o.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'offer'"))?;
            let summary = digstore_chain::offer::decode_offer_summary(offer).map_err(bad)?;
            Ok(offer_summary_json(&summary))
        }
        "chia_createOffer" => {
            // Build + sign a make-offer: OFFER `offered` assets, REQUEST `requested`
            // assets (paid to the maker), optional `fee`. Returns the bech32 offer1…
            // string (+ a decoded summary). Building an offer SPENDS nothing on its own
            // (settlement happens when someone takes it), so it returns the string
            // regardless of the broadcast gate.
            let offered = parse_offer_legs(&params, "offered")?;
            let requested = parse_offer_legs(&params, "requested")?;
            let fee = json_u64(&params, "fee").unwrap_or(0);

            let chain = Coinset::mainnet();
            let maker = digstore_chain::keys::derive_indexed_keys(&mnemonic, 0..1)
                .map_err(bad)?
                .into_iter()
                .next()
                .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))?;
            let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
            })?;

            // XCH funding coins tagged with each address's keys.
            let mut xch: Vec<(chia_protocol::Coin, &digstore_chain::keys::IndexedKeys)> =
                Vec::new();
            for a in &scanned.addrs {
                for c in &a.xch {
                    xch.push((*c, &a.keys));
                }
            }
            // CAT funding coins (with lineage proofs) for each DISTINCT offered CAT.
            let offered_cats: BTreeSet<chia_protocol::Bytes32> = offered
                .iter()
                .filter_map(|l| match l {
                    digstore_chain::offer::OfferAsset::Cat { asset_id, .. } => Some(*asset_id),
                    _ => None,
                })
                .collect();
            let mut cats: Vec<(
                chia_wallet_sdk::driver::Cat,
                &digstore_chain::keys::IndexedKeys,
            )> = Vec::new();
            for asset_id in offered_cats {
                for a in &scanned.addrs {
                    let reconstructed = digstore_chain::cat::reconstruct_cat_coins(
                        &chain,
                        a.keys.owner_puzzle_hash,
                        asset_id,
                    )
                    .await
                    .map_err(bad)?;
                    for cat in reconstructed {
                        cats.push((cat, &a.keys));
                    }
                }
            }

            let funds = digstore_chain::offer::MakerFunds { xch, cats };
            let offer_str = digstore_chain::offer::build_make_offer(
                &maker, funds, &offered, &requested, fee, false,
            )
            .map_err(bad)?;
            let summary = digstore_chain::offer::decode_offer_summary(&offer_str).map_err(bad)?;
            Ok(json!({ "offer": offer_str, "summary": offer_summary_json(&summary) }))
        }
        "chia_cancelOffer" => {
            // Cancel an offer the wallet MADE: re-spend the offered coins back to the
            // maker, invalidating the outstanding offer1… string. State-changing, so
            // gated by the broadcast/dry-run env gate (signed-only unless opted in).
            let offer = params
                .get("offer")
                .and_then(|o| o.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'offer'"))?;
            let fee = json_u64(&params, "fee").unwrap_or(0);
            let maker = digstore_chain::keys::derive_indexed_keys(&mnemonic, 0..1)
                .map_err(bad)?
                .into_iter()
                .next()
                .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))?;
            let bundle =
                digstore_chain::offer::cancel_offer(offer, &maker, fee, false).map_err(bad)?;
            let chain = Coinset::mainnet();
            let n = bundle.coin_spends.len();
            let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
            Ok(json!({
                "status": status,
                "success": true,
                "spendBundle": {
                    "coinSpends": n,
                    "aggregatedSignature": hex::encode(bundle.aggregated_signature.to_bytes()),
                },
            }))
        }
        "chia_send" => {
            // Sage-parity send: pay XCH (type null) or a generic CAT (type "cat",
            // identified by `assetId`) to `address`, with optional `memos` and `fee`.
            // Like /api/send, this spends real funds only when the env opts in; a
            // dapp-originated send is treated as broadcast-intent and pushes only when
            // DIG_WALLET_ALLOW_BROADCAST=1 (otherwise dry-run / "signed").
            let to = params
                .get("address")
                .or_else(|| params.get("to"))
                .and_then(|a| a.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'address'"))?;
            let recipient_ph = digstore_chain::send::decode_xch_address(to).map_err(bad)?;
            let amount = json_u64(&params, "amount")
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'amount'"))?;
            let fee = json_u64(&params, "fee").unwrap_or(0);
            let is_cat = params.get("type").and_then(|t| t.as_str()) == Some("cat");
            let chain = Coinset::mainnet();

            let (signed_bundle, coin_spends, status_value) = if is_cat {
                let asset_id = cat_asset_id(&params)?;
                // Reconstruct this asset's CAT coins (with lineage proofs) across every
                // scanned address; the recipient/change use the primary owner key.
                let keys = digstore_chain::keys::derive_wallet_keys(&mnemonic).map_err(bad)?;
                let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                    wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
                })?;
                let mut cats = Vec::new();
                for a in &scanned.addrs {
                    cats.extend(
                        digstore_chain::cat::reconstruct_cat_coins(
                            &chain,
                            a.keys.owner_puzzle_hash,
                            asset_id,
                        )
                        .await
                        .map_err(bad)?,
                    );
                }
                let memos = parse_memo_hashes(&params)?;
                let (bundle, plan) = digstore_chain::cat::build_cat_send(
                    &keys,
                    &cats,
                    asset_id,
                    recipient_ph,
                    amount,
                    &memos,
                    fee,
                    false,
                )
                .map_err(bad)?;
                let n = bundle.coin_spends.len();
                (
                    bundle,
                    n,
                    json!({ "amount": plan.amount.to_string(), "change": plan.change.to_string() }),
                )
            } else {
                let scanned = scan_wallet(&chain, &mnemonic).await.map_err(|e| {
                    wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}"))
                })?;
                let (bundle, plan) =
                    digstore_chain::send::build_xch_send(&scanned, recipient_ph, amount, fee)
                        .map_err(bad)?;
                let n = bundle.coin_spends.len();
                (
                    bundle,
                    n,
                    json!({ "amount": amount.to_string(), "change": plan.change.to_string() }),
                )
            };

            let status = broadcast_or_dry_run(&chain, signed_bundle.clone()).await?;
            Ok(json!({
                "status": status,
                "success": true,
                "spendBundle": {
                    "coinSpends": coin_spends,
                    "aggregatedSignature": hex::encode(signed_bundle.aggregated_signature.to_bytes()),
                },
                "sent": status_value,
            }))
        }

        // ---- Local on-chain STORE lifecycle (#95/#96 Pass B) ----------------
        //
        // Mint / advance (deploy) / melt / delegate / transfer a CHIP-0035
        // DataLayer store locally, so the DIG Browser can publish + manage stores
        // without the hub's spend service. Every spend is BUILT via `digstore-chain`
        // (the byte-mirror of chip35 — never hand-rolled), signed with the wallet
        // seed, and broadcast-gated by `DIG_WALLET_ALLOW_BROADCAST` (dry-run
        // otherwise). Minting is FREE of $DIG (#111); only `chia_advanceStore` (a
        // commit / capsule) carries the atomic DIG-CAT payment to the treasury (the
        // DIG amount is an INPUT, consistent with the configurable dig.rs pricing —
        // the wallet never fetches a live price).
        "chia_mintStore" => mint_store(&mnemonic, &params).await,
        "chia_advanceStore" => advance_store(&mnemonic, &params).await,
        "chia_meltStore" => melt_store(&mnemonic, &params).await,
        "chia_setStoreDelegation" => set_store_delegation(&mnemonic, &params).await,
        "chia_setStoreOwnership" => set_store_ownership(&mnemonic, &params).await,

        // ---- Advanced coin types (power-user) -------------------------------
        //
        // Clawback payments, options, streaming/vesting, vaults, and verifiable
        // credentials. These wrap the digstore-chain builders behind the SAME
        // consent + broadcast gate as the core methods. Where a builder documents a
        // gap (e.g. an option exercise needs the caller to also fund the strike, a
        // vault spend needs the wallet's non-existent K1 secret keys, a VC issue/revoke
        // needs the issuer DID co-spent in the same bundle), the leg is surfaced as an
        // honest "not supported in this build" (501) rather than faked.
        "dig_clawbackSend" => clawback_send(&mnemonic, &params).await,
        "dig_clawbackClaim" => clawback_claim_or_recover(&mnemonic, &params, true).await,
        "dig_clawbackRecover" => clawback_claim_or_recover(&mnemonic, &params, false).await,

        "dig_optionCreate" => option_create(&mnemonic, &params).await,
        "dig_optionExercise" | "dig_optionClawback" => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            "exercising / clawing back an option is not supported in this build: it needs the \
             post-create option state (the option singleton + locked-underlying coin) and, for \
             exercise, a same-bundle strike payment — neither is reconstructable from a request. \
             Create options here; exercise/clawback them with a full Chia wallet."
                .to_string(),
        )),

        "dig_streamCreate" => stream_create(&mnemonic, &params).await,
        "dig_streamClaim" => stream_claim_or_clawback(&mnemonic, &params, false).await,
        "dig_streamClawback" => stream_claim_or_clawback(&mnemonic, &params, true).await,

        "dig_vaultCreate" => vault_create(&mnemonic, &params).await,
        "dig_vaultSpend" => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            "spending a vault is not supported in this build: a vault's custody is an \
             independent K1 (secp256k1) member set, NOT the wallet's BLS keys, so this wallet \
             holds no signer for it (chia-wallet-sdk 0.30 only verifies the K1 member spend). \
             Create vaults here; spend them with the K1 custody keys elsewhere."
                .to_string(),
        )),

        "dig_vcVerify" => vc_verify(&params),
        "dig_vcIssue" | "dig_vcRevoke" => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            "issuing / revoking a verifiable credential is not supported in this build: both \
             require the issuing DID to be co-spent in the SAME bundle (it holds the issuer's \
             authority), which this standalone wallet endpoint cannot orchestrate. Verify \
             credentials here (dig_vcVerify); issue/revoke them from the issuing DID's tooling."
                .to_string(),
        )),
        "dig_vcTransfer" => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            digstore_chain::vc::vc_transfer_unsupported().to_string(),
        )),

        other => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            format!("unsupported WC method: {other}"),
        )),
    }
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

// ---- Local on-chain STORE lifecycle handlers (#95/#96 Pass B) ----------------
//
// Mint / advance / melt / delegate / transfer a CHIP-0035 DataLayer store locally.
// Every spend is BUILT via `digstore-chain` (the byte-mirror of chip35 — these
// handlers NEVER hand-roll a spend bundle) and broadcast-gated by
// `DIG_WALLET_ALLOW_BROADCAST` (dry-run / "signed" otherwise), exactly like the
// other spend methods. Minting is FREE of $DIG (#111); only `advance` (a commit /
// capsule) carries the atomic DIG-CAT payment; its DIG amount is an INPUT param (the
// wallet never fetches a live price — it stays deterministic, consistent with the
// configurable `dig.rs` pricing).

/// The DIG amount (base units) for a COMMIT / root-advance (a capsule), from `digAmount`
/// (number or decimal string), defaulting to `default_units` ([`COMMIT_DIG`]) when omitted
/// — mirroring the CLI's deterministic [`resolve_dig_amount`]. The hub's dynamic,
/// USD-pegged amount is passed in here as an explicit input; the wallet never fetches a
/// live price. An explicit `0` is rejected (a capsule must pay the protocol fee). Only the
/// commit path uses this — minting a store is free of $DIG (#111).
fn store_dig_amount(
    params: &serde_json::Value,
    default_units: u64,
) -> Result<u64, (StatusCode, String)> {
    match json_u64(params, "digAmount") {
        Some(0) => Err(wc_err(
            StatusCode::BAD_REQUEST,
            "digAmount must be greater than zero (a capsule must pay the protocol DIG fee)",
        )),
        other => Ok(digstore_chain::dig::resolve_dig_amount(
            other,
            default_units,
        )),
    }
}

/// Resolve the live `DataStore` for a request's `storeId` AND the wallet [`WalletKeys`]
/// of the HD address that OWNS it. Scans the wallet, finds which scanned address's owner
/// puzzle hash matches the store's on-chain `owner_puzzle_hash`, and returns both — so
/// melt / delegation / transfer are authorized by the correct owner key (a wallet that
/// rotated addresses owns different stores under different indices). Errors clearly if
/// the wallet does not own the store.
async fn resolve_owned_store(
    chain: &Coinset,
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<
    (
        digstore_chain::singleton::DataStore,
        digstore_chain::keys::WalletKeys,
    ),
    (StatusCode, String),
> {
    let store_id = requested_store_id(params)?;
    let store = digstore_chain::singleton::sync_datastore(chain, store_id)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("store sync failed: {e}")))?;
    let owner_ph = store.info.owner_puzzle_hash;
    let scanned = scan_wallet(chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    let owner = scanned
        .addrs
        .iter()
        .find(|a| a.keys.owner_puzzle_hash == owner_ph)
        .map(|a| digstore_chain::keys::WalletKeys {
            synthetic_sk: a.keys.synthetic_sk.clone(),
            synthetic_pk: a.keys.synthetic_pk,
            owner_puzzle_hash: a.keys.owner_puzzle_hash,
        })
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "this wallet does not own that store (no HD address matches its owner)",
            )
        })?;
    Ok((store, owner))
}

/// The `storeId` (launcher id) a store-lifecycle request targets, as a 32-byte id.
/// Accepts `storeId`, `launcherId`, or `id` (any `0x`/bare hex).
fn requested_store_id(
    params: &serde_json::Value,
) -> Result<chia_protocol::Bytes32, (StatusCode, String)> {
    let raw = params
        .get("storeId")
        .or_else(|| params.get("launcherId"))
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'storeId'"))?;
    parse_asset_id_hex(raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))
}

/// Standard JSON for a store-lifecycle spend: the broadcast `status` ("broadcast" when
/// pushed, "signed" on a dry run), the coin-spend count, and the aggregated signature.
/// (Same shape as [`singleton_spend_json`], named for the store flows.)
fn store_spend_json(status: &str, bundle: &chia_protocol::SpendBundle) -> serde_json::Value {
    singleton_spend_json(status, bundle.coin_spends.len(), bundle)
}

/// `chia_mintStore` — mint a NEW empty (root = 0) CHIP-0035 store. Params: `label?`,
/// `description?`, `fee?` (mojos; 0 → auto-estimate). Returns the new
/// `storeId`/`launcherId`, the broadcast status, and `digPaid: "0"`.
///
/// **Minting is FREE of $DIG (#111):** the mint launches the singleton + the XCH
/// network fee ONLY — no DIG-CAT payment is attached. The per-capsule $DIG price is
/// paid on [`advance_store`] (`chia_advanceStore`), a capsule. Built via
/// `digstore_chain::anchor::build_mint_store_bundle` (byte-exact CHIP-0035 mint, no
/// DIG) — never hand-rolled.
async fn mint_store(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let label = params
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let description = params
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let fee = json_u64(params, "fee").unwrap_or(0);

    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    let built = digstore_chain::anchor::build_mint_store_bundle(
        &chain as &dyn ChainReads,
        &scanned,
        label,
        description,
        fee,
    )
    .await
    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?;

    let status = broadcast_or_dry_run(&chain, built.bundle.clone()).await?;
    let mut out = store_spend_json(status, &built.bundle);
    out["storeId"] = serde_json::json!(format!("0x{}", hex::encode(built.launcher_id)));
    out["launcherId"] = serde_json::json!(format!("0x{}", hex::encode(built.launcher_id)));
    out["coinId"] = serde_json::json!(format!("0x{}", hex::encode(built.coin_id)));
    // Minting is free of $DIG — report 0 paid so callers/UX show the mint cost as no DIG.
    out["digPaid"] = serde_json::json!("0");
    Ok(out)
}

/// `chia_advanceStore` — advance an existing store's root (deploy / metadata / root
/// advance) to `newRoot`, with the atomic DIG-CAT payment, in one co-signed bundle.
/// Params: `storeId` (required), `newRoot` (required, 32-byte hex), `label?`,
/// `description?` (RE-SENT — an update REPLACES metadata), `digAmount?` (default
/// [`COMMIT_DIG`]), `fee?`, and optional `writerSeed` (a 32-byte hex deploy-token seed):
/// when present, the singleton update is authorized by that WRITER DELEGATE key (the
/// store must already carry its delegated puzzle) instead of the owner seed, while the
/// wallet still funds the fee + DIG. Built via
/// `digstore_chain::anchor::build_advance_store_bundle` /
/// `build_advance_store_writer_bundle` — never hand-rolled.
async fn advance_store(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let store_id = requested_store_id(params)?;
    let new_root_raw = params
        .get("newRoot")
        .or_else(|| params.get("root"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'newRoot'"))?;
    let new_root =
        parse_asset_id_hex(new_root_raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?;
    let label = params
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let description = params
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let fee = json_u64(params, "fee").unwrap_or(0);
    let dig_amount = store_dig_amount(params, digstore_chain::dig::COMMIT_DIG)?;

    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;

    // Optional writer-delegate seed (a 32-byte hex deploy token) authorizes the
    // singleton update via the writer puzzle instead of the owner seed.
    let writer_seed = params.get("writerSeed").and_then(|v| v.as_str());
    let built = if let Some(seed_hex) = writer_seed.filter(|s| !s.trim().is_empty()) {
        let seed = parse_seed32(seed_hex)?;
        let writer = digstore_chain::keys::wallet_keys_from_seed(&seed);
        digstore_chain::anchor::build_advance_store_writer_bundle(
            &chain as &dyn ChainReads,
            store_id,
            new_root,
            label,
            description,
            &writer,
            &scanned,
            fee,
            dig_amount,
        )
        .await
    } else {
        digstore_chain::anchor::build_advance_store_bundle(
            &chain as &dyn ChainReads,
            store_id,
            new_root,
            label,
            description,
            &scanned,
            fee,
            dig_amount,
        )
        .await
    }
    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?;

    let status = broadcast_or_dry_run(&chain, built.bundle.clone()).await?;
    let mut out = store_spend_json(status, &built.bundle);
    out["storeId"] = serde_json::json!(format!("0x{}", hex::encode(store_id)));
    out["newCoinId"] = serde_json::json!(format!("0x{}", hex::encode(built.new_coin_id)));
    out["newRoot"] = serde_json::json!(format!("0x{}", hex::encode(new_root)));
    out["digPaid"] = serde_json::json!(dig_amount.to_string());
    Ok(out)
}

/// `chia_meltStore` — permanently retire a store by melting its singleton (no further
/// capsules can ever be anchored under its launcher id). Params: `storeId` (required).
/// Owner-authorized; the melt reserves the singleton's 1 mojo as fee, so no DIG payment
/// / fee coin is needed. Built via `digstore_chain::singleton::build_melt` — never
/// hand-rolled.
async fn melt_store(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let store_id = requested_store_id(params)?;
    let (store, owner) = resolve_owned_store(&chain, mnemonic, params).await?;
    let built = digstore_chain::singleton::build_melt(&owner, store)
        .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let status = broadcast_or_dry_run(&chain, built.bundle.clone()).await?;
    let mut out = store_spend_json(status, &built.bundle);
    out["storeId"] = serde_json::json!(format!("0x{}", hex::encode(store_id)));
    Ok(out)
}

/// `chia_setStoreDelegation` — set the store's delegated-puzzle set (admin / writer /
/// oracle delegates — Teams #43, deploy tokens #17), keeping the SAME owner. Params:
/// `storeId` (required), `delegates` (array of `{ role:"admin"|"writer"|"oracle",
/// publicKey? (admin/writer synthetic pk hex), oraclePuzzleHash? + oracleFee? (oracle) }`),
/// `fee?`. The delegated set REPLACES the prior set (re-send every delegate to keep; omit
/// to revoke). Built via `digstore_chain::singleton::build_update_ownership` (owner
/// unchanged) using the same admin/writer/oracle derivations the hub/chip35 use.
async fn set_store_delegation(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let store_id = requested_store_id(params)?;
    let (store, owner) = resolve_owned_store(&chain, mnemonic, params).await?;
    let delegated = parse_delegates(params)?;
    let fee = json_u64(params, "fee").unwrap_or(0);
    let fee_coins = owner_xch_coins(&chain, mnemonic, owner.owner_puzzle_hash, fee).await?;

    let built = digstore_chain::singleton::build_update_ownership(
        &owner,
        store,
        owner.owner_puzzle_hash, // ownership unchanged — delegation only
        delegated,
        &fee_coins,
        fee,
    )
    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let status = broadcast_or_dry_run(&chain, built.bundle.clone()).await?;
    let mut out = store_spend_json(status, &built.bundle);
    out["storeId"] = serde_json::json!(format!("0x{}", hex::encode(store_id)));
    out["newCoinId"] = serde_json::json!(format!("0x{}", hex::encode(built.new_coin_id)));
    Ok(out)
}

/// `chia_setStoreOwnership` — TRANSFER a store to a new owner. Params: `storeId`
/// (required), `newOwner` (an `xch1…` address OR a 32-byte owner puzzle-hash hex),
/// `delegates?` (the delegated set for the new owner — defaults to NONE, so a plain
/// transfer hands over a clean store; pass `delegates` to carry roles across), `fee?`.
/// Built via `digstore_chain::singleton::build_update_ownership` (new `owner_ph`) — the
/// same primitive as delegation, with the owner re-targeted. Never hand-rolled.
async fn set_store_ownership(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let store_id = requested_store_id(params)?;
    let (store, owner) = resolve_owned_store(&chain, mnemonic, params).await?;

    // `newOwner` accepts an xch address or a raw 32-byte puzzle hash.
    let raw = params
        .get("newOwner")
        .or_else(|| params.get("to"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'newOwner'"))?;
    let new_owner_ph = if raw.trim().starts_with("xch1") {
        digstore_chain::send::decode_xch_address(raw.trim())
            .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        parse_asset_id_hex(raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?
    };
    // A transfer defaults to NO delegates (clean handover); honour `delegates` if given.
    let delegated = if params.get("delegates").is_some() {
        parse_delegates(params)?
    } else {
        Vec::new()
    };
    let fee = json_u64(params, "fee").unwrap_or(0);
    let fee_coins = owner_xch_coins(&chain, mnemonic, owner.owner_puzzle_hash, fee).await?;

    let built = digstore_chain::singleton::build_update_ownership(
        &owner,
        store,
        new_owner_ph,
        delegated,
        &fee_coins,
        fee,
    )
    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let status = broadcast_or_dry_run(&chain, built.bundle.clone()).await?;
    let mut out = store_spend_json(status, &built.bundle);
    out["storeId"] = serde_json::json!(format!("0x{}", hex::encode(store_id)));
    out["newOwner"] = serde_json::json!(format!("0x{}", hex::encode(new_owner_ph)));
    out["newCoinId"] = serde_json::json!(format!("0x{}", hex::encode(built.new_coin_id)));
    Ok(out)
}

/// Parse a 32-byte hex seed (a writer-delegate / deploy-token seed) into `[u8; 32]`.
fn parse_seed32(s: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let hex = s.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(hex).map_err(|_| wc_err(StatusCode::BAD_REQUEST, "writerSeed must be hex"))?;
    bytes
        .try_into()
        .map_err(|_| wc_err(StatusCode::BAD_REQUEST, "writerSeed must be 32 bytes"))
}

/// The owner's spendable XCH coins to fund a `fee` (across the owning address). Returns
/// an empty vec when `fee == 0` (no fee coin needed). Scans coinset for the owner's
/// unspent XCH at `owner_ph`.
async fn owner_xch_coins(
    chain: &Coinset,
    mnemonic: &str,
    owner_ph: chia_protocol::Bytes32,
    fee: u64,
) -> Result<Vec<chia_protocol::Coin>, (StatusCode, String)> {
    if fee == 0 {
        return Ok(Vec::new());
    }
    let scanned = scan_wallet(chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    Ok(scanned
        .addrs
        .iter()
        .find(|a| a.keys.owner_puzzle_hash == owner_ph)
        .map(|a| a.xch.clone())
        .unwrap_or_default())
}

/// Parse the `delegates` array into a `Vec<DelegatedPuzzle>` using the same
/// admin/writer/oracle derivations the hub/chip35 use. Each entry is
/// `{ role:"admin"|"writer"|"oracle", publicKey? (admin/writer synthetic pk hex),
/// oraclePuzzleHash? + oracleFee? }`. Empty/absent → an empty set (revoke all).
fn parse_delegates(
    params: &serde_json::Value,
) -> Result<Vec<digstore_chain::singleton::DelegatedPuzzle>, (StatusCode, String)> {
    let Some(arr) = params.get("delegates").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for d in arr {
        let role = d
            .get("role")
            .and_then(|r| r.as_str())
            .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "each delegate needs a 'role'"))?;
        match role {
            "admin" | "writer" => {
                let pk_hex = d
                    .get("publicKey")
                    .or_else(|| d.get("syntheticPublicKey"))
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| {
                        wc_err(
                            StatusCode::BAD_REQUEST,
                            format!("{role} delegate needs a 'publicKey' (synthetic pk hex)"),
                        )
                    })?;
                let pk = parse_public_key_hex(pk_hex)?;
                out.push(if role == "admin" {
                    digstore_chain::singleton::admin_delegated_puzzle(pk)
                } else {
                    digstore_chain::singleton::writer_delegated_puzzle(pk)
                });
            }
            "oracle" => {
                let oph = d
                    .get("oraclePuzzleHash")
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| {
                        wc_err(
                            StatusCode::BAD_REQUEST,
                            "oracle delegate needs 'oraclePuzzleHash'",
                        )
                    })?;
                let oracle_ph =
                    parse_asset_id_hex(oph).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?;
                let oracle_fee = json_u64(d, "oracleFee").unwrap_or(0);
                out.push(digstore_chain::singleton::oracle_delegated_puzzle(
                    oracle_ph, oracle_fee,
                ));
            }
            other => {
                return Err(wc_err(
                    StatusCode::BAD_REQUEST,
                    format!("unknown delegate role '{other}' (admin|writer|oracle)"),
                ))
            }
        }
    }
    Ok(out)
}

/// Parse a 48-byte BLS G1 public key from hex (a synthetic pk for an admin/writer
/// delegate).
fn parse_public_key_hex(
    s: &str,
) -> Result<digstore_chain::singleton::PublicKey, (StatusCode, String)> {
    let hex = s.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(hex).map_err(|_| wc_err(StatusCode::BAD_REQUEST, "publicKey must be hex"))?;
    let arr: [u8; 48] = bytes.try_into().map_err(|_| {
        wc_err(
            StatusCode::BAD_REQUEST,
            "publicKey must be 48 bytes (BLS G1)",
        )
    })?;
    digstore_chain::singleton::PublicKey::from_bytes(&arr)
        .map_err(|e| wc_err(StatusCode::BAD_REQUEST, format!("invalid publicKey: {e}")))
}

// ---- Advanced coin-type handlers --------------------------------------------
//
// Each builds (and, where it holds all keys, signs) via the digstore-chain builders,
// then applies `broadcast_or_dry_run` — signed-but-not-pushed unless the env opts in
// (`DIG_WALLET_ALLOW_BROADCAST=1`), exactly like the core spend methods. A dapp can
// never force a broadcast; these are broadcast-INTENT, gated by the env.

/// Build + sign a clawback SEND: fund a clawback coin (claimable by `receiver` after
/// `timelock` seconds, recoverable by the wallet until then) from an XCH coin at the
/// wallet's primary address. Returns the resulting clawback coin id + terms so the
/// recipient/sender can later claim/recover it (those need the coin + terms back).
async fn clawback_send(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    let to = params
        .get("receiver")
        .or_else(|| params.get("to"))
        .or_else(|| params.get("address"))
        .and_then(|a| a.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'receiver'"))?;
    let receiver_ph = digstore_chain::send::decode_xch_address(to).map_err(bad)?;
    let amount = json_u64(params, "amount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'amount'"))?;
    let timelock = json_u64(params, "timelock")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'timelock' (seconds)"))?;

    let chain = Coinset::mainnet();
    let sender = primary_keys(mnemonic)?;
    let funding = find_funding_coin(&chain, mnemonic, sender.owner_puzzle_hash).await?;
    let (spends, clawback) = digstore_chain::clawback::build_clawback_send(
        &sender,
        funding,
        receiver_ph,
        amount,
        timelock,
    )
    .map_err(bad)?;
    let sig = digstore_chain::clawback::sign_clawback_spends(
        &spends,
        std::slice::from_ref(&sender.synthetic_sk),
        false,
    )
    .map_err(bad)?;
    let bundle = chia_protocol::SpendBundle::new(spends, sig);
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    let mut out = singleton_spend_json(status, n, &bundle);
    out["clawbackCoin"] = clawback_coin_json(&clawback);
    Ok(out)
}

/// Build + sign a clawback CLAIM (recipient path, after the timelock) or RECOVER
/// (sender path, before the recipient claims) of an existing clawback coin. The coin +
/// its terms are supplied in the request (a clawback coin is fully reconstructable from
/// `{parentCoinId, amount, timelock, senderAddress, receiverAddress}`); the wallet
/// signs with the matching (claim → receiver / recover → sender) key.
async fn clawback_claim_or_recover(
    mnemonic: &str,
    params: &serde_json::Value,
    claim: bool,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());
    let clawback = parse_clawback_coin(params)?;
    let fee = json_u64(params, "fee").unwrap_or(0);

    // The key that authorizes this path: the receiver (claim) or the sender (recover).
    let target_ph = if claim {
        clawback.terms.receiver_puzzle_hash
    } else {
        clawback.terms.sender_puzzle_hash
    };
    let keys = wallet_keys_for_ph(mnemonic, target_ph)
        .await?
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                if claim {
                    "this wallet does not hold the clawback's receiver address"
                } else {
                    "this wallet does not hold the clawback's sender address"
                },
            )
        })?;

    let bundle = if claim {
        digstore_chain::clawback::build_clawback_claim(&clawback, &keys, fee, false).map_err(bad)?
    } else {
        digstore_chain::clawback::build_clawback_recover(&clawback, &keys, fee, false)
            .map_err(bad)?
    };
    let chain = Coinset::mainnet();
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    Ok(singleton_spend_json(status, n, &bundle))
}

/// Build + sign an option CREATE: lock `underlyingAmount` XCH from the wallet's primary
/// address as the underlying, mint the option singleton to the wallet, exercisable for
/// the requested strike (`strike{type,amount,assetId?}`) until `expirySeconds`. Returns
/// the option launcher id + underlying coin id.
async fn option_create(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    let underlying_amount = json_u64(params, "underlyingAmount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'underlyingAmount'"))?;
    let expiry = json_u64(params, "expirySeconds")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'expirySeconds'"))?;
    let strike = parse_option_strike(params)?;

    let chain = Coinset::mainnet();
    let creator = primary_keys(mnemonic)?;
    let funding = find_funding_coin(&chain, mnemonic, creator.owner_puzzle_hash).await?;
    let (spends, created) = digstore_chain::option::build_option_create(
        &creator,
        funding,
        underlying_amount,
        strike,
        expiry,
    )
    .map_err(bad)?;
    let sig = digstore_chain::option::sign_option_spends(
        &spends,
        std::slice::from_ref(&creator.synthetic_sk),
        false,
    )
    .map_err(bad)?;
    let bundle = chia_protocol::SpendBundle::new(spends, sig);
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    let mut out = singleton_spend_json(status, n, &bundle);
    out["launcherId"] = json!(format!(
        "0x{}",
        hex::encode(created.option.info.launcher_id)
    ));
    out["underlyingCoinId"] = json!(format!(
        "0x{}",
        hex::encode(created.underlying_coin.coin_id())
    ));
    Ok(out)
}

/// Build + sign a streaming CREATE: lock `amount` XCH from the wallet's primary address
/// that vests linearly from `startTime` to `endTime` to `recipient`, with the unvested
/// remainder claw-back-able to the wallet. Returns the streaming coin id.
async fn stream_create(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    let to = params
        .get("recipient")
        .or_else(|| params.get("to"))
        .or_else(|| params.get("address"))
        .and_then(|a| a.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'recipient'"))?;
    let recipient_ph = digstore_chain::send::decode_xch_address(to).map_err(bad)?;
    let amount = json_u64(params, "amount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'amount'"))?;
    let start = json_u64(params, "startTime")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'startTime'"))?;
    let end = json_u64(params, "endTime")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'endTime'"))?;

    let chain = Coinset::mainnet();
    let payer = primary_keys(mnemonic)?;
    // The payer is the clawback address (it reclaims the unvested remainder).
    let clawback_ph = payer.owner_puzzle_hash;
    let funding = find_funding_coin(&chain, mnemonic, payer.owner_puzzle_hash).await?;
    let (spends, stream) = digstore_chain::streaming::build_stream_create(
        &payer,
        funding,
        recipient_ph,
        clawback_ph,
        amount,
        start,
        end,
    )
    .map_err(bad)?;
    let sig = digstore_chain::streaming::sign_stream_spends(
        &spends,
        std::slice::from_ref(&payer.synthetic_sk),
        false,
    )
    .map_err(bad)?;
    let bundle = chia_protocol::SpendBundle::new(spends, sig);
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    let mut out = singleton_spend_json(status, n, &bundle);
    out["streamCoinId"] = json!(format!("0x{}", hex::encode(stream.asset.coin.coin_id())));
    Ok(out)
}

/// Build + sign a streaming CLAIM (recipient takes the vested portion) or CLAWBACK
/// (payer reclaims the unvested remainder). The live stream is reconstructed from the
/// `parentSpend` hex (the coin spend that created/last-updated it) via
/// [`reconstruct_stream`]; the authorizing message coin is a 0-mojo coin the wallet
/// holds at the recipient/clawback address.
async fn stream_claim_or_clawback(
    mnemonic: &str,
    params: &serde_json::Value,
    clawback: bool,
) -> Result<serde_json::Value, (StatusCode, String)> {
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    let parent_spend = parse_coin_spend_hex(params, "parentSpend")?;
    let stream = digstore_chain::streaming::reconstruct_stream(&parent_spend)
        .map_err(bad)?
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "no live stream in that parent spend (it may have been fully clawed back)",
            )
        })?;
    let payment_time = json_u64(params, "paymentTime").ok_or_else(|| {
        wc_err(
            StatusCode::BAD_REQUEST,
            "missing 'paymentTime' (block timestamp)",
        )
    })?;

    // The address that authorizes this path: recipient (claim) or clawback (clawback).
    let target_ph = if clawback {
        stream.asset.info.clawback_ph.ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "this stream has no clawback path (clawback_ph is None)",
            )
        })?
    } else {
        stream.asset.info.recipient
    };
    let keys = wallet_keys_for_ph(mnemonic, target_ph)
        .await?
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                if clawback {
                    "this wallet does not hold the stream's clawback address"
                } else {
                    "this wallet does not hold the stream's recipient address"
                },
            )
        })?;
    // The stream releases funds ONLY for an authorizing message from a real coin at the
    // recipient/clawback address — and that coin is consumed with no output, so it MUST
    // be a 0-mojo coin (a value-bearing coin would burn its value). Don't fake one.
    let message_coin = find_zero_mojo_coin(&keys.owner_puzzle_hash, mnemonic).await?;

    let bundle = if clawback {
        digstore_chain::streaming::build_stream_clawback(
            &stream,
            &keys,
            message_coin,
            payment_time,
            false,
        )
        .map_err(bad)?
    } else {
        digstore_chain::streaming::build_stream_claim(
            &stream,
            &keys,
            message_coin,
            payment_time,
            false,
        )
        .map_err(bad)?
    };
    let chain = Coinset::mainnet();
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    Ok(singleton_spend_json(status, n, &bundle))
}

/// Build + sign a vault CREATE: launch a vault singleton (funded by the wallet's BLS
/// coin at its primary address) under a K1 custody set — `members` (33-byte K1 pubkeys,
/// hex) with `required` of them needed to spend. Returns the vault launcher id. (The
/// vault SPEND needs the K1 secret keys, which the wallet does not hold — see the
/// dig_vaultSpend "not supported in this build" note.)
async fn vault_create(
    mnemonic: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;
    let bad = |e: digstore_chain::error::ChainError| wc_err(StatusCode::BAD_REQUEST, e.to_string());

    let config = parse_vault_config(params)?;
    let chain = Coinset::mainnet();
    let funder = primary_keys(mnemonic)?;
    let funding = find_funding_coin(&chain, mnemonic, funder.owner_puzzle_hash).await?;
    let (spends, created) =
        digstore_chain::vault::build_vault_create(&funder, funding, config).map_err(bad)?;
    let sig = digstore_chain::vault::sign_vault_create_spends(
        &spends,
        std::slice::from_ref(&funder.synthetic_sk),
        false,
    )
    .map_err(bad)?;
    let bundle = chia_protocol::SpendBundle::new(spends, sig);
    let n = bundle.coin_spends.len();
    let status = broadcast_or_dry_run(&chain, bundle.clone()).await?;
    let mut out = singleton_spend_json(status, n, &bundle);
    out["launcherId"] = json!(format!("0x{}", hex::encode(created.vault.info.launcher_id)));
    Ok(out)
}

/// VC VERIFY (pure, no chain): compute the on-chain asserter puzzle hash for a credential
/// `(issuerDid, version, assetId, dataHash)` — the address a relying party sends a coin to
/// so spending it REQUIRES proof of that credential. The "verify a credential" primitive.
fn vc_verify(params: &serde_json::Value) -> Result<serde_json::Value, (StatusCode, String)> {
    use serde_json::json;
    let issuer_did = parse_required_hash(params, "issuerDid")?;
    let asset_id = parse_required_hash(params, "assetId")?;
    let data_hash = parse_required_hash(params, "dataHash")?;
    let version = json_u64(params, "version").unwrap_or(1) as u32;
    let ph = digstore_chain::vc::vc_asserter_puzzle_hash(issuer_did, version, asset_id, data_hash);
    Ok(json!({
        "asserterPuzzleHash": format!("0x{}", hex::encode(ph)),
        "issuerDid": format!("0x{}", hex::encode(issuer_did)),
        "version": version,
        "assetId": format!("0x{}", hex::encode(asset_id)),
        "dataHash": format!("0x{}", hex::encode(data_hash)),
    }))
}

/// One `getAssetCoins` entry in Sage's SpendableCoin shape. `amount` is a decimal
/// string (BigInt-safe); `puzzle` (the standard p2 reveal) is present for XCH coins
/// and omitted for CAT coins (whose lineage the hub rebuilds from the parent spend).
fn coin_entry_json(coin: &chia_protocol::Coin, puzzle: Option<&str>) -> serde_json::Value {
    use serde_json::json;
    let mut e = json!({
        "coin": {
            "parent_coin_info": format!("0x{}", hex::encode(coin.parent_coin_info)),
            "puzzle_hash": format!("0x{}", hex::encode(coin.puzzle_hash)),
            "amount": coin.amount.to_string(),
        },
        "locked": false,
        "spent_block_index": 0,
    });
    if let Some(p) = puzzle {
        e["puzzle"] = json!(p);
    }
    e
}

/// Parse a 32-byte CAT asset id (TAIL hash) from a hex string (`0x`-prefixed or
/// bare). Pure so the parse/validation is unit-tested independently of HTTP.
fn parse_asset_id_hex(s: &str) -> Result<chia_protocol::Bytes32, String> {
    let hex = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|_| format!("invalid asset id hex: {s}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("asset id must be 32 bytes: {s}"))?;
    Ok(chia_protocol::Bytes32::new(arr))
}

/// The CAT `assetId` for a request, defaulting to the DIG TAIL when omitted/empty
/// (so the common DIG path needs no asset id). Any 32-byte TAIL is accepted —
/// generic over the asset, no allow-list.
fn cat_asset_id(
    params: &serde_json::Value,
) -> Result<chia_protocol::Bytes32, (StatusCode, String)> {
    let raw = params
        .get("assetId")
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .trim();
    if raw.is_empty() {
        return Ok(digstore_chain::dig::DIG_ASSET_ID);
    }
    parse_asset_id_hex(raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))
}

/// A `u64` from `params[key]`, tolerating both a JSON number and a decimal string
/// (dapps send amounts/fees as either; BigInt-safe values arrive as strings).
fn json_u64(params: &serde_json::Value, key: &str) -> Option<u64> {
    let v = params.get(key)?;
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Parse optional `memos` (array of hex strings) into 32-byte memo hashes for a CAT
/// send. Memos that are not 32-byte hex are rejected (the CAT memo slot is a hash).
fn parse_memo_hashes(
    params: &serde_json::Value,
) -> Result<Vec<chia_protocol::Bytes32>, (StatusCode, String)> {
    let Some(arr) = params.get("memos").and_then(|m| m.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for m in arr {
        let s = m
            .as_str()
            .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "each memo must be a hex string"))?;
        out.push(parse_asset_id_hex(s).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?);
    }
    Ok(out)
}

/// The wallet's HD owner puzzle hashes (one per scanned address), used to find a
/// wallet's coins/NFTs/DIDs across every derived address. Scans over coinset.
async fn wallet_owner_phs(
    mnemonic: &str,
) -> Result<Vec<chia_protocol::Bytes32>, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    Ok(scanned
        .addrs
        .iter()
        .map(|a| a.keys.owner_puzzle_hash)
        .collect())
}

/// Apply the SAME broadcast gate the XCH `send`/`chia_takeOffer` paths use to a
/// built+signed bundle: push only when the env opts in (`DIG_WALLET_ALLOW_BROADCAST=1`),
/// otherwise dry-run (the bundle is signed but nothing is pushed). A dapp can never
/// itself force a broadcast — taking/sending is broadcast-INTENT, gated by the env.
/// Returns `"broadcast"` or `"signed"`.
async fn broadcast_or_dry_run(
    chain: &Coinset,
    bundle: chia_protocol::SpendBundle,
) -> Result<&'static str, (StatusCode, String)> {
    let broadcast_enabled =
        std::env::var("DIG_WALLET_ALLOW_BROADCAST").ok().as_deref() == Some("1");
    Ok(match send_action(true, broadcast_enabled) {
        SendAction::Broadcast => {
            chain
                .push(bundle)
                .await
                .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("push_tx: {e}")))?;
            "broadcast"
        }
        SendAction::RefusedDisabled | SendAction::DryRun => "signed",
    })
}

/// Parse an offer's `offered`/`requested` legs from `params[key]` — an array of
/// `{ assetId?, amount }` where a missing/empty `assetId` means XCH and any 32-byte
/// TAIL means that CAT — into `OfferAsset`s. Generic over the asset (no allow-list).
fn parse_offer_legs(
    params: &serde_json::Value,
    key: &str,
) -> Result<Vec<digstore_chain::offer::OfferAsset>, (StatusCode, String)> {
    use digstore_chain::offer::OfferAsset;
    let arr = params
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, format!("missing '{key}' (array)")))?;
    let mut out = Vec::with_capacity(arr.len());
    for leg in arr {
        let amount = json_u64(leg, "amount").ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                format!("{key} leg missing 'amount'"),
            )
        })?;
        let asset_raw = leg
            .get("assetId")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .trim();
        if asset_raw.is_empty() {
            out.push(OfferAsset::Xch(amount));
        } else {
            let asset_id =
                parse_asset_id_hex(asset_raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?;
            out.push(OfferAsset::Cat { asset_id, amount });
        }
    }
    Ok(out)
}

/// Render an [`OfferAsset`] as `{ type, assetId?, amount }` (amount as a BigInt-safe
/// decimal string). XCH carries no `assetId`.
fn offer_asset_json(a: &digstore_chain::offer::OfferAsset) -> serde_json::Value {
    use digstore_chain::offer::OfferAsset;
    match a {
        OfferAsset::Xch(amount) => {
            serde_json::json!({ "type": "xch", "amount": amount.to_string() })
        }
        OfferAsset::Cat { asset_id, amount } => serde_json::json!({
            "type": "cat",
            "assetId": format!("0x{}", hex::encode(asset_id)),
            "amount": amount.to_string(),
        }),
    }
}

/// Render an [`OfferSummary`] (offered/requested assets, the taker's funding cost,
/// and any NFT royalties) as the JSON the wallet UI / dapps consume.
fn offer_summary_json(s: &digstore_chain::offer::OfferSummary) -> serde_json::Value {
    serde_json::json!({
        "offered": s.offered.iter().map(offer_asset_json).collect::<Vec<_>>(),
        "requested": s.requested.iter().map(offer_asset_json).collect::<Vec<_>>(),
        "arbitrage": {
            "xch": s.arbitrage.xch.to_string(),
            "cats": s.arbitrage.cats.iter().map(|(id, amt)| serde_json::json!({
                "assetId": format!("0x{}", hex::encode(id)),
                "amount": amt.to_string(),
            })).collect::<Vec<_>>(),
        },
        "royalties": s.royalties.iter().map(|(launcher, bp)| serde_json::json!({
            "launcherId": format!("0x{}", hex::encode(launcher)),
            "basisPoints": bp,
        })).collect::<Vec<_>>(),
    })
}

/// Render an [`OwnedNft`] as the JSON the wallet UI consumes. Ids are `0x` hex
/// (the canonical launcher/coin identity); off-chain media is app-side, so only the
/// on-chain identity/royalty/owner is reported here.
fn owned_nft_json(n: &digstore_chain::nft::OwnedNft) -> serde_json::Value {
    serde_json::json!({
        "launcherId": format!("0x{}", hex::encode(n.launcher_id)),
        "coinId": format!("0x{}", hex::encode(n.coin_id)),
        "ownerDid": n.owner_did.map(|d| format!("0x{}", hex::encode(d))),
        "royaltyPuzzleHash": format!("0x{}", hex::encode(n.royalty_puzzle_hash)),
        "royaltyBasisPoints": n.royalty_basis_points,
        "p2PuzzleHash": format!("0x{}", hex::encode(n.p2_puzzle_hash)),
    })
}

/// Render one [`Tx`] (a wallet receipt or spend) as the JSON the history UI consumes.
/// Amounts are BigInt-safe decimal strings; the asset is `{ type, assetId?/launcherId? }`.
fn tx_json(tx: &digstore_chain::wallet::Tx) -> serde_json::Value {
    use digstore_chain::wallet::{TxAsset, TxDirection, TxStatus};
    let asset = match tx.asset {
        TxAsset::Xch => serde_json::json!({ "type": "xch" }),
        TxAsset::Cat { tail } => {
            serde_json::json!({ "type": "cat", "assetId": format!("0x{}", hex::encode(tail)) })
        }
        TxAsset::Nft { launcher_id } => serde_json::json!({
            "type": "nft", "launcherId": format!("0x{}", hex::encode(launcher_id)),
        }),
        TxAsset::Did { launcher_id } => serde_json::json!({
            "type": "did", "launcherId": format!("0x{}", hex::encode(launcher_id)),
        }),
    };
    serde_json::json!({
        "direction": match tx.direction { TxDirection::In => "in", TxDirection::Out => "out" },
        "asset": asset,
        "amount": tx.amount.to_string(),
        "fee": tx.fee.to_string(),
        "height": tx.height,
        "timestamp": tx.timestamp,
        "coinIds": tx.coin_ids.iter().map(|c| format!("0x{}", hex::encode(c))).collect::<Vec<_>>(),
        "status": match tx.status { TxStatus::Pending => "pending", TxStatus::Confirmed => "confirmed" },
    })
}

/// Render an [`OwnedDid`] as the JSON the wallet UI consumes (the DID's on-chain
/// identity + location). Ids are `0x` hex.
fn owned_did_json(d: &digstore_chain::did::OwnedDid) -> serde_json::Value {
    serde_json::json!({
        "launcherId": format!("0x{}", hex::encode(d.launcher_id)),
        "coinId": format!("0x{}", hex::encode(d.coin_id)),
        "p2PuzzleHash": format!("0x{}", hex::encode(d.p2_puzzle_hash)),
        "numVerificationsRequired": d.num_verifications_required,
    })
}

/// Standard JSON for a single state-changing singleton spend (transfer/mint):
/// the broadcast `status`, the coin-spend count, and the aggregated signature.
fn singleton_spend_json(
    status: &str,
    coin_spends: usize,
    bundle: &chia_protocol::SpendBundle,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "success": true,
        "spendBundle": {
            "coinSpends": coin_spends,
            "aggregatedSignature": hex::encode(bundle.aggregated_signature.to_bytes()),
        },
    })
}

/// Normalize a `coinId` / `launcherId` request param to a 32-byte id (either is
/// accepted; `coinId` wins). Errors if neither is present or the hex is malformed.
fn requested_singleton_id(
    params: &serde_json::Value,
) -> Result<chia_protocol::Bytes32, (StatusCode, String)> {
    let raw = params
        .get("coinId")
        .or_else(|| params.get("launcherId"))
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'coinId' or 'launcherId'"))?;
    parse_asset_id_hex(raw).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))
}

/// Find the index of the owned singleton (NFT/DID) the request targets, matching the
/// requested id against each candidate's `(coin_id, launcher_id)`. Pure over an
/// iterator of those pairs so the selection is unit-tested without chain reads.
fn find_owned_index<I>(
    candidates: I,
    params: &serde_json::Value,
) -> Result<usize, (StatusCode, String)>
where
    I: IntoIterator<Item = (chia_protocol::Bytes32, chia_protocol::Bytes32)>,
{
    let id = requested_singleton_id(params)?;
    candidates
        .into_iter()
        .position(|(coin_id, launcher_id)| coin_id == id || launcher_id == id)
        .ok_or_else(|| wc_err(StatusCode::NOT_FOUND, "no owned NFT/DID matches that id"))
}

/// Find an XCH funding coin at `owner_ph` (the wallet's primary address) to launch a
/// singleton (NFT/DID) from. Scans over coinset and returns the first spendable XCH
/// coin; errors clearly if the address has none.
async fn find_funding_coin(
    chain: &Coinset,
    mnemonic: &str,
    owner_ph: chia_protocol::Bytes32,
) -> Result<chia_protocol::Coin, (StatusCode, String)> {
    let scanned = scan_wallet(chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    scanned
        .addrs
        .iter()
        .find(|a| a.keys.owner_puzzle_hash == owner_ph)
        .and_then(|a| a.xch.first().copied())
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "no spendable XCH coin to fund the mint at the wallet's address",
            )
        })
}

// ---- Advanced coin-type helpers ---------------------------------------------

/// The wallet's primary (index 0) [`IndexedKeys`] — the address that funds new
/// singletons / clawback coins / streams / vaults, mirroring the mint/DID paths.
fn primary_keys(mnemonic: &str) -> Result<digstore_chain::keys::IndexedKeys, (StatusCode, String)> {
    digstore_chain::keys::derive_indexed_keys(mnemonic, 0..1)
        .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| wc_err(StatusCode::INTERNAL_SERVER_ERROR, "no wallet key"))
}

/// The wallet's HD [`IndexedKeys`] whose owner puzzle hash equals `ph`, if any, found by
/// scanning the wallet's derived addresses. `None` when the wallet does not hold `ph`
/// (e.g. claiming a clawback the wallet did not receive). Lets the clawback/stream legs
/// pick the exact key that authorizes the receiver / sender / clawback path.
async fn wallet_keys_for_ph(
    mnemonic: &str,
    ph: chia_protocol::Bytes32,
) -> Result<Option<digstore_chain::keys::IndexedKeys>, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let scanned = scan_wallet(&chain, mnemonic)
        .await
        .map_err(|e| wc_err(StatusCode::BAD_GATEWAY, format!("coinset scan failed: {e}")))?;
    Ok(scanned
        .addrs
        .iter()
        .find(|a| a.keys.owner_puzzle_hash == ph)
        .map(|a| a.keys.clone()))
}

/// Find a 0-mojo coin the wallet holds at `ph`, for use as a stream's authorizing
/// MESSAGE coin. The message coin is spent with only a `send_message` (no output), so it
/// MUST be a 0-mojo coin — a value-bearing coin would burn its value. Errors clearly when
/// the wallet has none at that address (we never substitute a value-bearing coin).
async fn find_zero_mojo_coin(
    ph: &chia_protocol::Bytes32,
    mnemonic: &str,
) -> Result<chia_protocol::Coin, (StatusCode, String)> {
    let chain = Coinset::mainnet();
    let coins = chain.unspent_coins(*ph).await.map_err(|e| {
        wc_err(
            StatusCode::BAD_GATEWAY,
            format!("coinset coins failed: {e}"),
        )
    })?;
    let _ = mnemonic; // address derives from the supplied ph; mnemonic kept for symmetry
    coins.into_iter().find(|c| c.amount == 0).ok_or_else(|| {
        wc_err(
            StatusCode::BAD_REQUEST,
            "no 0-mojo message coin at that address — a stream claim/clawback needs a spare \
             0-mojo coin to carry the authorizing message (we will not burn a value-bearing coin)",
        )
    })
}

/// Render a freshly-built [`ClawbackCoin`] as the JSON the UI shows after a clawback send:
/// the coin's id + amount and the terms (timelock + sender/receiver puzzle hashes) the
/// recipient/sender later supply to claim/recover it.
fn clawback_coin_json(c: &digstore_chain::clawback::ClawbackCoin) -> serde_json::Value {
    serde_json::json!({
        "coinId": format!("0x{}", hex::encode(c.coin.coin_id())),
        "parentCoinId": format!("0x{}", hex::encode(c.coin.parent_coin_info)),
        "amount": c.coin.amount.to_string(),
        "timelock": c.terms.timelock,
        "senderPuzzleHash": format!("0x{}", hex::encode(c.terms.sender_puzzle_hash)),
        "receiverPuzzleHash": format!("0x{}", hex::encode(c.terms.receiver_puzzle_hash)),
    })
}

/// Reconstruct a [`ClawbackCoin`] from a claim/recover request:
/// `{ parentCoinId, amount, timelock, senderAddress|senderPuzzleHash,
///    receiverAddress|receiverPuzzleHash }`. The coin's puzzle hash is the clawback
/// 1-of-2 merkle root derived from the terms (so the request need not carry it). Pure so
/// the parse is unit-tested without chain reads.
fn parse_clawback_coin(
    params: &serde_json::Value,
) -> Result<digstore_chain::clawback::ClawbackCoin, (StatusCode, String)> {
    use chia_wallet_sdk::driver::Clawback;
    use chia_wallet_sdk::prelude::ToTreeHash;

    let parent = parse_required_hash(params, "parentCoinId")?;
    let amount = json_u64(params, "amount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'amount'"))?;
    let timelock = json_u64(params, "timelock")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing 'timelock'"))?;
    let sender_ph = parse_ph_or_address(params, "sender")?;
    let receiver_ph = parse_ph_or_address(params, "receiver")?;

    let terms = Clawback {
        timelock,
        sender_puzzle_hash: sender_ph,
        receiver_puzzle_hash: receiver_ph,
    };
    let clawback_ph: chia_protocol::Bytes32 = terms.to_layer().tree_hash().into();
    let coin = chia_protocol::Coin::new(parent, clawback_ph, amount);
    Ok(digstore_chain::clawback::ClawbackCoin { coin, terms })
}

/// Parse an option `strike{ type, amount, assetId? }`. Only an XCH strike is fully
/// verifiable in this build; a CAT/NFT strike underlying leg is surfaced as "not
/// supported in this build" (the create can encode a CAT strike type, but the exercise it
/// implies is the unsupported leg, so we refuse it up front to avoid an unexercisable
/// option). Pure so the parse + the gap refusal are unit-tested.
fn parse_option_strike(
    params: &serde_json::Value,
) -> Result<chia_wallet_sdk::driver::OptionType, (StatusCode, String)> {
    use chia_wallet_sdk::driver::OptionType;
    let strike = params.get("strike").unwrap_or(params);
    let amount = json_u64(strike, "amount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "missing strike 'amount'"))?;
    let ty = strike.get("type").and_then(|t| t.as_str()).unwrap_or("xch");
    match ty {
        "xch" | "" => Ok(OptionType::Xch { amount }),
        "cat" | "nft" | "revocableCat" => Err(wc_err(
            StatusCode::NOT_IMPLEMENTED,
            format!(
                "a '{ty}' strike is not supported in this build — only an XCH strike is fully \
                 verifiable here (the CAT/NFT strike's exercise leg is unsupported)"
            ),
        )),
        other => Err(wc_err(
            StatusCode::BAD_REQUEST,
            format!("unknown strike type '{other}'"),
        )),
    }
}

/// Parse a vault `{ members: [K1 pubkey hex (33 bytes)], required }` into a
/// [`VaultKeyConfig`]. `required` defaults to the member count (n-of-n) when omitted.
/// Pure so the parse + threshold validation are unit-tested without chain reads.
fn parse_vault_config(
    params: &serde_json::Value,
) -> Result<digstore_chain::vault::VaultKeyConfig, (StatusCode, String)> {
    let arr = params
        .get("members")
        .and_then(|m| m.as_array())
        .ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "missing 'members' (array of K1 pubkeys)",
            )
        })?;
    if arr.is_empty() {
        return Err(wc_err(
            StatusCode::BAD_REQUEST,
            "vault needs at least one member",
        ));
    }
    let mut members = Vec::with_capacity(arr.len());
    for m in arr {
        let s = m.as_str().ok_or_else(|| {
            wc_err(
                StatusCode::BAD_REQUEST,
                "each member must be a K1 pubkey hex",
            )
        })?;
        members.push(parse_k1_pubkey(s)?);
    }
    let required = json_u64(params, "required").unwrap_or(members.len() as u64) as usize;
    digstore_chain::vault::VaultKeyConfig::m_of_n(required, members)
        .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()))
}

/// Parse a 33-byte secp256k1 (K1) public key from hex (`0x`-prefixed or bare). Pure so
/// the parse/validation is unit-tested independently of HTTP.
fn parse_k1_pubkey(s: &str) -> Result<chia::secp::K1PublicKey, (StatusCode, String)> {
    let hex = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|_| {
        wc_err(
            StatusCode::BAD_REQUEST,
            format!("invalid K1 pubkey hex: {s}"),
        )
    })?;
    let arr: [u8; 33] = bytes.try_into().map_err(|_| {
        wc_err(
            StatusCode::BAD_REQUEST,
            format!("K1 pubkey must be 33 bytes: {s}"),
        )
    })?;
    chia::secp::K1PublicKey::from_bytes(&arr)
        .map_err(|e| wc_err(StatusCode::BAD_REQUEST, format!("invalid K1 pubkey: {e}")))
}

/// A required 32-byte hash param (e.g. a DID / asset id / data hash), `0x`-prefixed or
/// bare. A clear 400 if missing or malformed.
fn parse_required_hash(
    params: &serde_json::Value,
    key: &str,
) -> Result<chia_protocol::Bytes32, (StatusCode, String)> {
    let s = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, format!("missing '{key}'")))?;
    parse_asset_id_hex(s).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))
}

/// Parse a puzzle hash for `<key>`, accepting EITHER `<key>Address` (an `xch1…` address,
/// decoded to its puzzle hash) OR `<key>PuzzleHash` (a 32-byte hash). Lets the clawback
/// claim/recover request name the sender/receiver by whichever the caller has.
fn parse_ph_or_address(
    params: &serde_json::Value,
    key: &str,
) -> Result<chia_protocol::Bytes32, (StatusCode, String)> {
    if let Some(a) = params.get(format!("{key}Address")).and_then(|v| v.as_str()) {
        return digstore_chain::send::decode_xch_address(a)
            .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e.to_string()));
    }
    if let Some(h) = params
        .get(format!("{key}PuzzleHash"))
        .and_then(|v| v.as_str())
    {
        return parse_asset_id_hex(h).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e));
    }
    Err(wc_err(
        StatusCode::BAD_REQUEST,
        format!("missing '{key}Address' or '{key}PuzzleHash'"),
    ))
}

/// Parse a [`CoinSpend`] from a request field carrying its components:
/// `<key>{ coin{parentCoinInfo,puzzleHash,amount}, puzzleReveal, solution }`, with the
/// program/hex fields `0x`-prefixed or bare. Used to reconstruct a live streaming coin
/// from the spend that created/updated it.
fn parse_coin_spend_hex(
    params: &serde_json::Value,
    key: &str,
) -> Result<chia_protocol::CoinSpend, (StatusCode, String)> {
    let cs = params.get(key).ok_or_else(|| {
        wc_err(
            StatusCode::BAD_REQUEST,
            format!("missing '{key}' (coin spend)"),
        )
    })?;
    let coin = cs
        .get("coin")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, format!("'{key}' missing 'coin'")))?;
    let parent = parse_required_hash(coin, "parentCoinInfo")?;
    let puzzle_hash = parse_required_hash(coin, "puzzleHash")?;
    let amount = json_u64(coin, "amount")
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "coin missing 'amount'"))?;
    let puzzle_reveal = parse_program_hex(cs, "puzzleReveal")?;
    let solution = parse_program_hex(cs, "solution")?;
    Ok(chia_protocol::CoinSpend::new(
        chia_protocol::Coin::new(parent, puzzle_hash, amount),
        puzzle_reveal,
        solution,
    ))
}

/// Parse a serialized CLVM program (`Program`) from a hex field (`0x`-prefixed or bare).
fn parse_program_hex(
    params: &serde_json::Value,
    key: &str,
) -> Result<chia_protocol::Program, (StatusCode, String)> {
    let s = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, format!("missing '{key}'")))?;
    let hex = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(hex)
        .map_err(|_| wc_err(StatusCode::BAD_REQUEST, format!("invalid {key} hex")))?;
    Ok(chia_protocol::Program::from(bytes))
}

/// Parse a `MintSpec` from a `{ metadata{dataUris,dataHash,metadataUris,…,edition*},
/// royaltyBasisPoints?, did? }` JSON object, serializing the on-chain NFT metadata
/// into a `Program`. `default_owner_ph` is the minter's address (the NFT is created
/// for the wallet). DID attribution is parsed but the attributing DID's own spend is
/// the caller's responsibility (out of scope for this pass).
fn parse_mint_spec(
    params: &serde_json::Value,
    default_owner_ph: chia_protocol::Bytes32,
) -> Result<digstore_chain::nft::MintSpec, (StatusCode, String)> {
    use chia::puzzles::nft::NftMetadata;
    use chia_wallet_sdk::driver::SpendContext;

    let md = params
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let str_vec = |key: &str| -> Vec<String> {
        md.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let opt_hash = |key: &str| -> Result<Option<chia_protocol::Bytes32>, (StatusCode, String)> {
        match md.get(key).and_then(|v| v.as_str()) {
            Some(s) if !s.trim().is_empty() => Ok(Some(
                parse_asset_id_hex(s).map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?,
            )),
            _ => Ok(None),
        }
    };

    let metadata = NftMetadata {
        edition_number: md
            .get("editionNumber")
            .and_then(|v| v.as_u64())
            .unwrap_or(1),
        edition_total: md.get("editionTotal").and_then(|v| v.as_u64()).unwrap_or(1),
        data_uris: str_vec("dataUris"),
        data_hash: opt_hash("dataHash")?,
        metadata_uris: str_vec("metadataUris"),
        metadata_hash: opt_hash("metadataHash")?,
        license_uris: str_vec("licenseUris"),
        license_hash: opt_hash("licenseHash")?,
    };
    let mut ctx = SpendContext::new();
    let metadata = ctx.serialize(&metadata).map_err(|e| {
        wc_err(
            StatusCode::BAD_REQUEST,
            format!("serialize nft metadata: {e}"),
        )
    })?;

    let royalty_basis_points = params
        .get("royaltyBasisPoints")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    // Optional DID attribution: { launcherId, innerPuzzleHash }.
    let did = match params.get("did") {
        Some(d) if d.is_object() => {
            let launcher = d
                .get("launcherId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "did missing 'launcherId'"))?;
            let inner = d
                .get("innerPuzzleHash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| wc_err(StatusCode::BAD_REQUEST, "did missing 'innerPuzzleHash'"))?;
            Some(digstore_chain::nft::DidAttribution {
                launcher_id: parse_asset_id_hex(launcher)
                    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?,
                inner_puzzle_hash: parse_asset_id_hex(inner)
                    .map_err(|e| wc_err(StatusCode::BAD_REQUEST, e))?,
            })
        }
        _ => None,
    };

    Ok(digstore_chain::nft::MintSpec {
        metadata,
        owner_ph: default_owner_ph,
        royalty_basis_points,
        did,
    })
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
        .route("/api/generate", post(generate))
        .route("/api/import", post(import))
        .route("/api/unlock", post(unlock))
        .route("/api/balance", get(balance))
        .route("/api/send", post(send))
        .route("/api/stores", get(stores_list))
        .route("/api/stores/history", get(store_history))
        .route("/api/lock", post(lock))
        .route("/api/dig-config", get(dig_config_get).post(dig_config_set))
        .route("/api/dig-cache/clear", post(dig_cache_clear))
        .route("/api/dig-cache/list", get(dig_cache_list))
        .route("/api/dig-cache/remove", post(dig_cache_remove))
        .route("/api/dig-cache/fetch", post(dig_cache_fetch))
        .route(
            "/api/wc/project-id",
            get(wc_project_id_get).post(wc_project_id_set),
        )
        .route(
            "/api/wallet/source",
            get(wallet_source_get).post(wallet_source_set),
        )
        .route("/api/wallet/pubkey", get(wallet_pubkey))
        .route("/api/export", post(export))
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
    fn default_send_is_a_dry_run_never_broadcasts() {
        // No broadcast requested → never push, regardless of the env opt-in. This is
        // the safe default that lets the signing path run unattended.
        assert_eq!(send_action(false, false), SendAction::DryRun);
        assert_eq!(send_action(false, true), SendAction::DryRun);
    }

    #[test]
    fn broadcast_requires_both_request_and_env_optin() {
        // Explicit request but env disabled → refused (NOT a silent dry run, NOT a push).
        assert_eq!(send_action(true, false), SendAction::RefusedDisabled);
        // Both opted in → the only path that actually broadcasts.
        assert_eq!(send_action(true, true), SendAction::Broadcast);
    }

    #[test]
    fn coin_entry_json_matches_sage_spendable_coin_shape() {
        let coin = chia_protocol::Coin::new([1u8; 32].into(), [2u8; 32].into(), 12345);
        // XCH entry carries the standard puzzle reveal the hub uncurries per coin.
        let xch = coin_entry_json(&coin, Some("0xdeadbeef"));
        assert_eq!(
            xch["coin"]["parent_coin_info"],
            format!("0x{}", "01".repeat(32))
        );
        assert_eq!(xch["coin"]["puzzle_hash"], format!("0x{}", "02".repeat(32)));
        assert_eq!(xch["coin"]["amount"], "12345"); // decimal string (BigInt-safe)
        assert_eq!(xch["puzzle"], "0xdeadbeef");
        assert_eq!(xch["locked"], false);
        assert_eq!(xch["spent_block_index"], 0);
        // CAT entry omits `puzzle` (the hub rebuilds the lineage from the parent spend).
        let cat = coin_entry_json(&coin, None);
        assert!(cat.get("puzzle").is_none());
        assert_eq!(cat["coin"]["amount"], "12345");
    }

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
    fn pubkey_window_defaults_and_clamps() {
        // No params → Sage's default first 10 keys at offset 0.
        assert_eq!(pubkey_window(&serde_json::Value::Null), (0, 10));
        // Explicit offset/limit honoured.
        assert_eq!(
            pubkey_window(&serde_json::json!({"offset": 5, "limit": 3})),
            (5, 3)
        );
        // An absurd limit is clamped so a dapp can't make us derive forever.
        let (off, lim) = pubkey_window(&serde_json::json!({"limit": 100000}));
        assert_eq!(off, 0);
        assert!(lim <= MAX_PUBKEYS, "limit clamped to {MAX_PUBKEYS}");
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
    fn wallet_source_round_trips_through_its_wire_token() {
        // The persisted/served token is stable and the parse is total (unknown → the
        // safe Native default, so a corrupt value never strands the wallet).
        assert_eq!(WalletSource::Native.as_str(), "native");
        assert_eq!(WalletSource::Sage.as_str(), "sage");
        assert_eq!(WalletSource::from_str("native"), WalletSource::Native);
        assert_eq!(WalletSource::from_str("sage"), WalletSource::Sage);
        assert_eq!(WalletSource::from_str("garbage"), WalletSource::Native);
        assert_eq!(WalletSource::from_str(""), WalletSource::Native);
        // Default is Native — the local-keys behaviour that predates this feature.
        assert_eq!(WalletSource::default(), WalletSource::Native);
    }

    #[test]
    fn native_mode_routes_every_method_to_the_local_signer() {
        // In Native mode nothing is delegated — the local signer answers everything,
        // exactly as before this feature (zero regression).
        for m in [
            "chip0002_chainId",
            "chip0002_connect",
            "chip0002_getPublicKeys",
            "chip0002_signMessage",
            "chip0002_signCoinSpends",
            "chia_getAddress",
            "chia_signMessageByAddress",
            "chia_takeOffer",
            "chia_createOffer",
            "chia_send",
        ] {
            assert_eq!(
                wc_route(WalletSource::Native, m),
                WcRoute::Native,
                "{m} must stay local in Native mode"
            );
        }
    }

    #[test]
    fn sage_mode_delegates_signing_methods_but_answers_the_handshake_locally() {
        // The keyless handshake methods are answered locally even in Sage mode (they
        // touch no keys and must work before any Sage session is up)…
        assert_eq!(
            wc_route(WalletSource::Sage, "chip0002_chainId"),
            WcRoute::Native
        );
        assert_eq!(
            wc_route(WalletSource::Sage, "chip0002_connect"),
            WcRoute::Native
        );
        // …but every method that reads keys or signs is delegated to Sage.
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
            assert_eq!(
                wc_route(WalletSource::Sage, m),
                WcRoute::Delegate,
                "{m} must delegate to Sage in Sage mode"
            );
        }
    }

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

    /// In Sage mode `wc_dispatch` must NOT touch the local seed — it parks the request
    /// on the delegate bridge and awaits Sage. Drive the dual: a background task plays
    /// the in-page Sage requester (take the parked request, return a canned result),
    /// and assert the dispatched method routes through the bridge and returns Sage's
    /// value. With NO unlocked local session, a local-signer route would 401; getting
    /// Sage's value back proves the request went to Sage, not the local keys.
    #[tokio::test]
    async fn sage_mode_dispatch_routes_through_the_delegate_bridge_not_local_keys() {
        let st = Arc::new(AppState::default());
        *st.source.lock().await = WalletSource::Sage;
        // Deliberately leave the local session locked (None): Native would 401 here.

        // The "Sage requester" pump: pick up the parked request and answer it.
        let pump = {
            let st = st.clone();
            tokio::spawn(async move {
                loop {
                    if let Some((id, method, params)) = delegate_take_next(&st).await {
                        // Echo back something Sage-shaped that proves the round-trip.
                        let result = serde_json::json!({
                            "fromSage": true,
                            "method": method,
                            "echo": params,
                        });
                        delegate_fulfill(&st, id, Ok(result)).await;
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
        };

        let out = wc_dispatch(
            &st,
            "chip0002_getPublicKeys",
            serde_json::json!({ "limit": 5 }),
        )
        .await
        .expect("delegate dispatch returns Sage's result, not a local 401");
        assert_eq!(out["fromSage"], true);
        assert_eq!(out["method"], "chip0002_getPublicKeys");
        assert_eq!(out["echo"]["limit"], 5);
        pump.await.unwrap();
    }

    /// The delegate bridge propagates Sage's ERRORS (a user rejection / unsupported
    /// method) back as a wallet error, rather than hanging or faking success.
    #[tokio::test]
    async fn sage_mode_dispatch_surfaces_sage_errors() {
        let st = Arc::new(AppState::default());
        *st.source.lock().await = WalletSource::Sage;
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

    /// Even in Sage mode, an export-flavoured method is refused (501) BEFORE it can be
    /// parked for Sage — the delegate surface is never a seed-exfiltration path. (A
    /// pump is started to prove the request never reaches it: if it did, the test
    /// would see the pumped value instead of the 501.)
    #[tokio::test]
    async fn delegate_never_forwards_export_class_methods() {
        let st = Arc::new(AppState::default());
        *st.source.lock().await = WalletSource::Sage;
        let leaked = Arc::new(AtomicU64::new(0));
        let pump = {
            let st = st.clone();
            let leaked = leaked.clone();
            tokio::spawn(async move {
                // Run briefly; if any export-class request is ever parked, flag it.
                for _ in 0..40 {
                    if let Some((id, _m, _p)) = delegate_take_next(&st).await {
                        leaked.fetch_add(1, Ordering::Relaxed);
                        delegate_fulfill(&st, id, Ok(serde_json::json!("LEAK"))).await;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
        };
        for method in ["export", "exportMnemonic", "getSecretKeys", "revealSeed"] {
            let r = wc_dispatch(&st, method, serde_json::Value::Null).await;
            match r {
                Err((code, _)) => assert_eq!(
                    code,
                    StatusCode::NOT_IMPLEMENTED,
                    "delegate mode must reject {method} as unsupported, never forward it"
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

    /// The wallet-source setter is wallet-local only (a dapp cannot flip the wallet to
    /// Sage / back), and a self-origin set persists + is reflected by the getter.
    #[tokio::test]
    async fn wallet_source_set_is_self_origin_only_and_persists() {
        let _g = ENV_LOCK.lock().await;
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("LOCALAPPDATA", td.path());
        let st = Arc::new(AppState::default());

        // A dapp origin is refused.
        let r = wallet_source_set(
            State(st.clone()),
            origin_headers("https://evil.example.com"),
            Json(SetWalletSource {
                source: "sage".to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // …and did NOT change the mode.
        assert_eq!(*st.source.lock().await, WalletSource::Native);

        // The self origin can flip to Sage; it persists to disk and the getter agrees.
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());
        let r = wallet_source_set(
            State(st.clone()),
            origin_headers(&self_origin),
            Json(SetWalletSource {
                source: "sage".to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(*st.source.lock().await, WalletSource::Sage);
        let got = wallet_source_get(State(st)).await;
        assert_eq!(got.0.source, "sage");

        // It persisted to disk: read the file directly from the tempdir (not via the
        // process-global env, which a parallel env-mutating test could have changed).
        let persisted = std::fs::read(td.path().join("DigWallet").join("wallet-source.json"))
            .expect("wallet-source.json written");
        let v: serde_json::Value = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(v["source"], "sage");

        std::env::remove_var("LOCALAPPDATA");
    }

    #[test]
    fn asset_id_parses_with_or_without_0x_and_rejects_bad_len() {
        // A 32-byte hex TAIL parses identically with or without the 0x prefix.
        let bare = "ab".repeat(32);
        let prefixed = format!("0x{bare}");
        let a = parse_asset_id_hex(&bare).unwrap();
        let b = parse_asset_id_hex(&prefixed).unwrap();
        assert_eq!(a, b);
        assert_eq!(hex::encode(a), bare);
        // Wrong length / bad hex are rejected (not panics).
        assert!(parse_asset_id_hex("dead").is_err()); // too short
        assert!(parse_asset_id_hex(&"zz".repeat(32)).is_err()); // not hex
    }

    #[test]
    fn cat_asset_id_defaults_to_dig_and_accepts_any_tail() {
        // No / empty assetId → DIG (the common token path needs no id)…
        assert_eq!(
            cat_asset_id(&serde_json::Value::Null).unwrap(),
            digstore_chain::dig::DIG_ASSET_ID
        );
        assert_eq!(
            cat_asset_id(&serde_json::json!({ "assetId": "" })).unwrap(),
            digstore_chain::dig::DIG_ASSET_ID
        );
        // …and ANY 32-byte TAIL is accepted — no allow-list, generic over the asset.
        let tail = "cd".repeat(32);
        let got = cat_asset_id(&serde_json::json!({ "assetId": format!("0x{tail}") })).unwrap();
        assert_eq!(hex::encode(got), tail);
        // A malformed assetId is a 400.
        let (code, _) = cat_asset_id(&serde_json::json!({ "assetId": "nope" })).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn json_u64_tolerates_number_and_decimal_string() {
        // Amounts/fees arrive as numbers OR decimal strings (BigInt-safe) — both work.
        assert_eq!(
            json_u64(&serde_json::json!({"amount": 42}), "amount"),
            Some(42)
        );
        assert_eq!(
            json_u64(&serde_json::json!({"amount": "1000000000000"}), "amount"),
            Some(1_000_000_000_000)
        );
        assert_eq!(json_u64(&serde_json::json!({}), "amount"), None);
    }

    #[test]
    fn memo_hashes_parse_and_reject_non_hash() {
        // No memos → empty (a memo-less send is fine).
        assert!(parse_memo_hashes(&serde_json::Value::Null)
            .unwrap()
            .is_empty());
        // 32-byte hex memos parse in order.
        let m = "11".repeat(32);
        let got = parse_memo_hashes(&serde_json::json!({ "memos": [format!("0x{m}")] })).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(hex::encode(got[0]), m);
        // A non-32-byte memo is rejected (the CAT memo slot is a hash).
        let (code, _) = parse_memo_hashes(&serde_json::json!({ "memos": ["dead"] })).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn find_owned_index_matches_coin_or_launcher_id() {
        let coin_a = chia_protocol::Bytes32::new([0xa0u8; 32]);
        let launcher_a = chia_protocol::Bytes32::new([0xa1u8; 32]);
        let coin_b = chia_protocol::Bytes32::new([0xb0u8; 32]);
        let launcher_b = chia_protocol::Bytes32::new([0xb1u8; 32]);
        let cands = vec![(coin_a, launcher_a), (coin_b, launcher_b)];
        // Match by coin id…
        let p = serde_json::json!({ "coinId": format!("0x{}", "b0".repeat(32)) });
        assert_eq!(find_owned_index(cands.clone(), &p).unwrap(), 1);
        // …or by launcher id.
        let p = serde_json::json!({ "launcherId": format!("0x{}", "a1".repeat(32)) });
        assert_eq!(find_owned_index(cands.clone(), &p).unwrap(), 0);
        // A non-matching id is a 404.
        let p = serde_json::json!({ "coinId": format!("0x{}", "cc".repeat(32)) });
        let (code, _) = find_owned_index(cands.clone(), &p).unwrap_err();
        assert_eq!(code, StatusCode::NOT_FOUND);
        // A missing id is a 400.
        let (code, _) = find_owned_index(cands, &serde_json::json!({})).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn mint_spec_parses_metadata_royalty_and_did() {
        let owner = chia_protocol::Bytes32::new([0x55u8; 32]);
        let p = serde_json::json!({
            "metadata": {
                "dataUris": ["https://example.com/a.png"],
                "dataHash": format!("0x{}", "11".repeat(32)),
                "editionNumber": 2,
                "editionTotal": 10
            },
            "royaltyBasisPoints": 300,
            "did": {
                "launcherId": format!("0x{}", "22".repeat(32)),
                "innerPuzzleHash": format!("0x{}", "33".repeat(32))
            }
        });
        let spec = parse_mint_spec(&p, owner).unwrap();
        assert_eq!(spec.owner_ph, owner);
        assert_eq!(spec.royalty_basis_points, 300);
        let did = spec.did.expect("did attribution parsed");
        assert_eq!(hex::encode(did.launcher_id), "22".repeat(32));
        assert_eq!(hex::encode(did.inner_puzzle_hash), "33".repeat(32));
        // The metadata serialized to a non-empty Program.
        assert!(!spec.metadata.is_empty());
        // A malformed did is a 400 (missing innerPuzzleHash).
        let bad_p = serde_json::json!({
            "metadata": {},
            "did": { "launcherId": format!("0x{}", "22".repeat(32)) }
        });
        let (code, _) = parse_mint_spec(&bad_p, owner).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
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
    fn tx_json_renders_direction_asset_and_amounts() {
        use digstore_chain::wallet::{Tx, TxAsset, TxDirection, TxStatus};
        let tx = Tx {
            direction: TxDirection::Out,
            asset: TxAsset::Cat {
                tail: chia_protocol::Bytes32::new([0x42u8; 32]),
            },
            amount: 1234,
            fee: 0,
            height: 100,
            timestamp: 99,
            coin_ids: vec![chia_protocol::Bytes32::new([0x01u8; 32])],
            memos: vec![],
            status: TxStatus::Confirmed,
        };
        let j = tx_json(&tx);
        assert_eq!(j["direction"], "out");
        assert_eq!(j["asset"]["type"], "cat");
        assert_eq!(j["asset"]["assetId"], format!("0x{}", "42".repeat(32)));
        assert_eq!(j["amount"], "1234"); // decimal string (BigInt-safe)
        assert_eq!(j["status"], "confirmed");
        assert_eq!(j["coinIds"][0], format!("0x{}", "01".repeat(32)));
        // XCH renders without an assetId.
        let xch = Tx {
            asset: TxAsset::Xch,
            direction: TxDirection::In,
            status: TxStatus::Pending,
            ..tx
        };
        let j = tx_json(&xch);
        assert_eq!(j["asset"]["type"], "xch");
        assert!(j["asset"].get("assetId").is_none());
        assert_eq!(j["direction"], "in");
        assert_eq!(j["status"], "pending");
    }

    #[test]
    fn transactions_method_is_gated_and_needs_a_wallet() {
        assert_eq!(wc_gate("chia_getTransactions", false), Gate::Forbidden);
        assert_eq!(wc_gate("chia_getTransactions", true), Gate::Allowed);
        assert!(wc_method_needs_wallet("chia_getTransactions"));
    }

    #[tokio::test]
    async fn store_endpoints_require_an_unlocked_wallet() {
        // Both store endpoints are wallet-local: a locked wallet is refused (401),
        // proving they never run a discovery/sync without a session.
        let st = Arc::new(AppState::default());
        let r = stores_list(State(st.clone())).await;
        assert!(matches!(r, Err((StatusCode::UNAUTHORIZED, _))));
        let r = store_history(
            State(st),
            axum::extract::Query(StoreHistoryQuery {
                store_id: format!("0x{}", "ab".repeat(32)),
            }),
        )
        .await;
        assert!(matches!(r, Err((StatusCode::UNAUTHORIZED, _))));
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
    fn offer_legs_parse_xch_and_cat() {
        use digstore_chain::offer::OfferAsset;
        // A missing/empty assetId means XCH; a 32-byte TAIL means that CAT.
        let tail = "ab".repeat(32);
        let legs = parse_offer_legs(
            &serde_json::json!({
                "offered": [
                    { "amount": 1000 },
                    { "assetId": format!("0x{tail}"), "amount": "250" }
                ]
            }),
            "offered",
        )
        .unwrap();
        assert_eq!(legs.len(), 2);
        assert_eq!(legs[0], OfferAsset::Xch(1000));
        match legs[1] {
            OfferAsset::Cat { asset_id, amount } => {
                assert_eq!(hex::encode(asset_id), tail);
                assert_eq!(amount, 250);
            }
            _ => panic!("expected a CAT leg"),
        }
        // A missing array is a 400 (so the builder never sees a half-formed offer).
        let (code, _) = parse_offer_legs(&serde_json::json!({}), "offered").unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        // A leg without an amount is a 400.
        let (code, _) =
            parse_offer_legs(&serde_json::json!({ "offered": [{}] }), "offered").unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn offer_summary_json_shape() {
        use digstore_chain::offer::{OfferAsset, OfferCost, OfferSummary};
        let tail = chia_protocol::Bytes32::new([0x42u8; 32]);
        let nft = chia_protocol::Bytes32::new([0x07u8; 32]);
        let s = OfferSummary {
            offered: vec![OfferAsset::Xch(5)],
            requested: vec![OfferAsset::Cat {
                asset_id: tail,
                amount: 9,
            }],
            arbitrage: OfferCost {
                xch: 0,
                cats: vec![(tail, 9)],
            },
            royalties: vec![(nft, 300)],
        };
        let j = offer_summary_json(&s);
        assert_eq!(j["offered"][0]["type"], "xch");
        assert_eq!(j["offered"][0]["amount"], "5"); // decimal string (BigInt-safe)
        assert_eq!(j["requested"][0]["type"], "cat");
        assert_eq!(
            j["requested"][0]["assetId"],
            format!("0x{}", "42".repeat(32))
        );
        assert_eq!(j["arbitrage"]["cats"][0]["amount"], "9");
        assert_eq!(j["royalties"][0]["basisPoints"], 300);
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
        let c = dig_node::CachedCapsule {
            store_id: "aa".repeat(32),
            root: "bb".repeat(32),
            size_bytes: 4096,
            last_used_unix_ms: 1_700_000_000_000,
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
    /// the cache dir at a throwaway tempdir via LOCALAPPDATA so the test is hermetic.
    #[tokio::test]
    async fn cache_list_self_origin_returns_capsule_list() {
        let _g = ENV_LOCK.lock().await;
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("LOCALAPPDATA", td.path());
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());
        let resp = dig_cache_list(origin_headers(&self_origin)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["cached"].is_array(), "list returns a cached array");
        assert_eq!(body["cached"].as_array().unwrap().len(), 0, "empty cache");
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
        // My Stores (the dedicated HTTP routes + the capsule history view).
        assert!(UI_HTML.contains("/api/stores"));
        assert!(UI_HTML.contains("/api/stores/history"));
        // Goes through the native signer (self-origin auto-approved).
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
            UI_HTML.contains("yours forever"),
            "ownership framing (never 'fee')"
        );
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
    fn settings_page_wires_the_new_settings_apis() {
        // The settings page must talk to the projectId, export, import, and
        // public-key endpoints, or those features silently no-op.
        assert!(SETTINGS_HTML.contains("/api/wc/project-id"));
        assert!(SETTINGS_HTML.contains("/api/export"));
        assert!(SETTINGS_HTML.contains("/api/import"));
        assert!(SETTINGS_HTML.contains("/api/wallet/pubkey"));
    }

    #[test]
    fn settings_page_wires_the_wallet_source_control() {
        // The "Wallet source" control must read/write the source endpoint and offer
        // both choices, and the Sage path must load the WC bundle (requester role) +
        // the projectId so the connect-to-Sage pairing can run, or the surface no-ops.
        assert!(
            SETTINGS_HTML.contains("/api/wallet/source"),
            "reads/sets the source"
        );
        assert!(SETTINGS_HTML.contains("value=\"native\""), "Native option");
        assert!(SETTINGS_HTML.contains("value=\"sage\""), "Sage option");
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
        // When the wallet source is Sage, the wallet page must (a) host the WC
        // requester (DigWC.sageRequest), and (b) pump the delegate bridge — pull
        // parked requests, forward to Sage, return results — or delegate dispatch
        // would hang. Guard the wiring the same way the responder is guarded.
        assert!(
            UI_HTML.contains("/api/wallet/source"),
            "reads the active source"
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

    /// The master mnemonic must NEVER be reachable through the WC / injected
    /// `window.chia` dispatch. `wc_dispatch` is the single dapp-facing signer
    /// surface; with the wallet UNLOCKED (so the locked-gate isn't what stops it),
    /// every export-flavoured method name is rejected as unsupported (501) — never
    /// served. (Locked, it 401s first; either way no key material comes back.)
    #[tokio::test]
    async fn export_is_not_a_dispatchable_wc_method() {
        const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let st = AppState::default();
        // Unlock a session so the unlocked-gate is satisfied; now an unsupported
        // method can only fall through to the explicit 501 arm.
        *st.session.lock().await = Some(Session {
            mnemonic: Zeroizing::new(ABANDON.to_string()),
            address: "xch1test".to_string(),
        });
        for method in [
            "export",
            "exportMnemonic",
            "chip0002_export",
            "getMnemonic",
            "getSecretKeys",
            "chia_export",
            "revealSeed",
        ] {
            let r = wc_dispatch(&st, method, serde_json::Value::Null).await;
            match r {
                Err((code, _)) => assert_eq!(
                    code,
                    StatusCode::NOT_IMPLEMENTED,
                    "dapp-facing dispatch must reject {method} as unsupported"
                ),
                Ok(v) => panic!("{method} must not be dispatchable, got {v:?}"),
            }
        }
    }

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

    /// The self origin (the wallet's own UI) routes straight through the gate (it is
    /// implicitly approved) — a key method reaches the signer rather than being
    /// forbidden. With the wallet locked it surfaces the signer's 401, proving it
    /// passed the consent gate and hit dispatch (a Forbidden gate would be 403).
    #[tokio::test]
    async fn wallet_dispatch_self_origin_routes_through_to_the_signer() {
        let st = AppState::default();
        // Pin Native so this test exercises the LOCAL signer's locked-gate regardless
        // of any on-disk wallet-source the dev machine has (Sage would delegate).
        *st.source.lock().await = WalletSource::Native;
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());
        let (status, body) = wallet_dispatch_with(
            &st,
            &self_origin,
            r#"{"method":"chip0002_getPublicKeys","params":{}}"#,
        )
        .await;
        // Locked session → the signer returns 401 (NOT the gate's 403).
        assert_eq!(
            status, 401,
            "self origin passes the gate; locked signer 401s"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("locked"), "{body}");
    }

    /// An APPROVED origin routes through the gate to the signer, exactly like the self
    /// origin (proving the approval allow-list — not just self-origin — opens the path).
    #[tokio::test]
    async fn wallet_dispatch_approved_origin_routes_through() {
        let st = AppState::default();
        // Pin Native (see the self-origin test) so the locked LOCAL signer answers.
        *st.source.lock().await = WalletSource::Native;
        st.approvals
            .lock()
            .await
            .approved
            .insert("https://good.example".to_string());
        let (status, _body) = wallet_dispatch_with(
            &st,
            "https://good.example",
            r#"{"method":"chip0002_getPublicKeys","params":{}}"#,
        )
        .await;
        // Passed the gate (not 403); locked signer 401s.
        assert_eq!(status, 401, "approved origin passes the gate to the signer");
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

    /// End-to-end of the export gate against a real on-disk encrypted seed:
    /// * a non-self origin is refused (403) even with the right password;
    /// * the self origin with a WRONG password is refused (401);
    /// * the self origin with the CORRECT password yields the exact mnemonic.
    ///
    /// Points the seed file at a throwaway tempdir via LOCALAPPDATA — no other
    /// dig-wallet test reads that env, so the process-global set is safe here.
    #[tokio::test]
    async fn export_requires_self_origin_and_correct_password() {
        // Public BIP-39 test vector (NOT a real wallet).
        const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        const PW: &str = "correct horse battery";

        let _g = ENV_LOCK.lock().await;
        let td = tempfile::tempdir().unwrap();
        std::env::set_var("LOCALAPPDATA", td.path());
        // Encrypt + persist the seed exactly as `import` does.
        let enc = encrypt_seed(ABANDON, PW).unwrap();
        let path = seed_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, enc.to_bytes()).unwrap();

        let dapp = "https://evil.example.com";
        let self_origin = format!("http://127.0.0.1:{}", wallet_port());

        // A dapp origin is refused even with the correct password.
        let r = export(
            origin_headers(dapp),
            Json(ExportReq {
                password: PW.to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // Self origin + wrong password → 401, no mnemonic.
        let r = export(
            origin_headers(&self_origin),
            Json(ExportReq {
                password: "wrong".to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

        // Self origin + correct password → the exact mnemonic.
        let r = export(
            origin_headers(&self_origin),
            Json(ExportReq {
                password: PW.to_string(),
            }),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = body_json(r).await;
        assert_eq!(body["mnemonic"], ABANDON);

        std::env::remove_var("LOCALAPPDATA");
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

    /// The public-key endpoint is wallet-local only and needs an unlocked wallet:
    /// a dapp origin is refused; the self origin with no session is unauthorized.
    #[tokio::test]
    async fn wallet_pubkey_is_self_origin_and_needs_unlock() {
        let st = Arc::new(AppState::default());
        // Dapp origin → forbidden.
        let r = wallet_pubkey(
            State(st.clone()),
            origin_headers("https://evil.example.com"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // Self origin but locked → unauthorized.
        let self_origin = format!("http://localhost:{}", wallet_port());
        let r = wallet_pubkey(State(st), origin_headers(&self_origin)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    // -- Advanced coin types (Part B) ------------------------------------------

    // Public BIP-39 test vector (NOT a real wallet), for the dispatch-gate tests.
    const ABANDON_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

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

    #[test]
    fn store_dig_amount_defaults_and_rejects_zero() {
        use digstore_chain::dig::COMMIT_DIG;
        // Omitted → the protocol default (deterministic; no live-price fetch). Only the
        // COMMIT path resolves a DIG amount — minting is free of $DIG (#111).
        let none = serde_json::json!({});
        assert_eq!(store_dig_amount(&none, COMMIT_DIG).unwrap(), COMMIT_DIG);
        // Explicit amount (number or decimal string) wins — the hub's USD-pegged value.
        let n = serde_json::json!({ "digAmount": 42_000 });
        assert_eq!(store_dig_amount(&n, COMMIT_DIG).unwrap(), 42_000);
        let s = serde_json::json!({ "digAmount": "37500" });
        assert_eq!(store_dig_amount(&s, COMMIT_DIG).unwrap(), 37_500);
        // Explicit 0 is rejected (a capsule must pay the protocol DIG fee).
        let z = serde_json::json!({ "digAmount": 0 });
        assert!(store_dig_amount(&z, COMMIT_DIG).is_err());
    }

    #[test]
    fn requested_store_id_accepts_storeid_launcherid_or_id() {
        let id = format!("0x{}", "ab".repeat(32));
        for key in ["storeId", "launcherId", "id"] {
            let p = serde_json::json!({ key: id });
            assert!(
                requested_store_id(&p).is_ok(),
                "{key} must resolve a store id"
            );
        }
        // Missing → a clear 400.
        let (code, _) = requested_store_id(&serde_json::json!({})).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_delegates_builds_admin_writer_oracle_and_rejects_unknown() {
        use digstore_chain::singleton::DelegatedPuzzle;
        // A 48-byte BLS pk (the abandon test wallet's synthetic pk) for admin/writer.
        let keys = digstore_chain::keys::derive_wallet_keys(ABANDON_24).unwrap();
        let pk_hex = format!("0x{}", hex::encode(keys.synthetic_pk.to_bytes()));
        let oph = format!("0x{}", "cd".repeat(32));
        let params = serde_json::json!({
            "delegates": [
                { "role": "admin", "publicKey": pk_hex },
                { "role": "writer", "publicKey": pk_hex },
                { "role": "oracle", "oraclePuzzleHash": oph, "oracleFee": 1000 },
            ]
        });
        let dps = parse_delegates(&params).unwrap();
        assert_eq!(dps.len(), 3);
        assert!(matches!(dps[0], DelegatedPuzzle::Admin(_)));
        assert!(matches!(dps[1], DelegatedPuzzle::Writer(_)));
        assert!(matches!(dps[2], DelegatedPuzzle::Oracle(_, 1000)));
        // No delegates array → an empty set (revoke-all / clean transfer).
        assert!(parse_delegates(&serde_json::json!({})).unwrap().is_empty());
        // Unknown role → a 400.
        let bad = serde_json::json!({ "delegates": [{ "role": "wizard" }] });
        assert_eq!(
            parse_delegates(&bad).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        // admin/writer missing publicKey → a 400.
        let nopk = serde_json::json!({ "delegates": [{ "role": "admin" }] });
        assert_eq!(
            parse_delegates(&nopk).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
    }

    /// The legs the digstore-chain builders cannot support standalone are surfaced as
    /// honest 501s (never faked) — with the wallet UNLOCKED so the locked-gate isn't
    /// what stops them; they reach the explicit "not supported in this build" arm.
    #[tokio::test]
    async fn unsupported_advanced_legs_surface_as_not_implemented() {
        let st = AppState::default();
        *st.session.lock().await = Some(Session {
            mnemonic: Zeroizing::new(ABANDON_24.to_string()),
            address: "xch1test".to_string(),
        });
        for method in [
            "dig_optionExercise",
            "dig_optionClawback",
            "dig_vaultSpend",
            "dig_vcIssue",
            "dig_vcRevoke",
            "dig_vcTransfer",
        ] {
            let r = wc_dispatch(&st, method, serde_json::Value::Null).await;
            match r {
                Err((code, msg)) => {
                    assert_eq!(
                        code,
                        StatusCode::NOT_IMPLEMENTED,
                        "{method} must be an honest 501, got: {msg}"
                    );
                    assert!(
                        msg.contains("not supported in this build")
                            || msg.contains("cannot be transferred"),
                        "{method} must say why it is unsupported, got: {msg}"
                    );
                }
                Ok(v) => panic!("{method} must not silently succeed, got {v:?}"),
            }
        }
    }

    #[test]
    fn clawback_coin_parses_and_renders() {
        // A clawback coin round-trips from a claim/recover request: parent + amount +
        // terms (timelock + sender/receiver puzzle hashes), with the coin's own puzzle
        // hash derived from the terms (the 1-of-2 merkle root).
        let params = serde_json::json!({
            "parentCoinId": format!("0x{}", "11".repeat(32)),
            "amount": "1000",
            "timelock": 86400,
            "senderPuzzleHash": format!("0x{}", "22".repeat(32)),
            "receiverPuzzleHash": format!("0x{}", "33".repeat(32)),
        });
        let c = parse_clawback_coin(&params).unwrap();
        assert_eq!(c.coin.amount, 1000);
        assert_eq!(c.terms.timelock, 86400);
        assert_eq!(hex::encode(c.terms.sender_puzzle_hash), "22".repeat(32));
        assert_eq!(hex::encode(c.terms.receiver_puzzle_hash), "33".repeat(32));
        assert_eq!(hex::encode(c.coin.parent_coin_info), "11".repeat(32));
        // The rendered JSON carries the coin id + terms back to the UI.
        let j = clawback_coin_json(&c);
        assert_eq!(j["amount"], "1000");
        assert_eq!(j["timelock"], 86400);
        assert_eq!(j["senderPuzzleHash"], format!("0x{}", "22".repeat(32)));
        // A missing term is a 400.
        let (code, _) = parse_clawback_coin(&serde_json::json!({})).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn option_strike_parses_xch_and_rejects_unsupported_underlyings() {
        use chia_wallet_sdk::driver::OptionType;
        // An XCH strike is supported (the fully-verifiable case).
        let xch =
            parse_option_strike(&serde_json::json!({ "strike": { "type": "xch", "amount": 250 } }))
                .unwrap();
        assert!(matches!(xch, OptionType::Xch { amount: 250 }));
        // A bare amount (no nested 'strike') defaults to XCH too.
        let bare = parse_option_strike(&serde_json::json!({ "amount": 5 })).unwrap();
        assert!(matches!(bare, OptionType::Xch { amount: 5 }));
        // A CAT / NFT strike is surfaced as an honest 501 (its exercise leg is unsupported).
        for ty in ["cat", "nft", "revocableCat"] {
            let (code, msg) =
                parse_option_strike(&serde_json::json!({ "strike": { "type": ty, "amount": 1 } }))
                    .unwrap_err();
            assert_eq!(code, StatusCode::NOT_IMPLEMENTED, "{ty} strike");
            assert!(msg.contains("not supported in this build"), "{ty}: {msg}");
        }
        // A missing amount is a 400.
        let (code, _) =
            parse_option_strike(&serde_json::json!({ "strike": { "type": "xch" } })).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn vault_config_parses_members_and_threshold() {
        // Use real K1 pubkeys from the test harness so from_bytes accepts them.
        use chia_sdk_test::K1Pair;
        let keys = K1Pair::range_vec(3);
        let hexes: Vec<String> = keys
            .iter()
            .map(|k| format!("0x{}", hex::encode(k.pk.to_bytes())))
            .collect();
        // 2-of-3.
        let cfg = parse_vault_config(&serde_json::json!({
            "members": hexes, "required": 2
        }))
        .unwrap();
        assert_eq!(cfg.members.len(), 3);
        assert_eq!(cfg.required, 2);
        // Omitted 'required' defaults to n-of-n.
        let cfg = parse_vault_config(&serde_json::json!({ "members": hexes })).unwrap();
        assert_eq!(cfg.required, 3);
        // An empty member set is a 400.
        let (code, _) = parse_vault_config(&serde_json::json!({ "members": [] })).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
        // A bad threshold (more than members) is a 400.
        let (code, _) = parse_vault_config(&serde_json::json!({
            "members": hexes, "required": 9
        }))
        .unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn k1_pubkey_parses_and_rejects_bad_len() {
        use chia_sdk_test::K1Pair;
        let pk = K1Pair::default().pk;
        let hex_pk = format!("0x{}", hex::encode(pk.to_bytes()));
        let parsed = parse_k1_pubkey(&hex_pk).unwrap();
        assert_eq!(parsed.to_bytes(), pk.to_bytes());
        // A 32-byte value (wrong length for K1's 33) is rejected, not panicked.
        let (code, _) = parse_k1_pubkey(&"ab".repeat(32)).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn ph_or_address_accepts_either_form() {
        // A raw puzzle hash.
        let ph = parse_ph_or_address(
            &serde_json::json!({ "senderPuzzleHash": format!("0x{}", "aa".repeat(32)) }),
            "sender",
        )
        .unwrap();
        assert_eq!(hex::encode(ph), "aa".repeat(32));
        // Neither form → 400.
        let (code, _) = parse_ph_or_address(&serde_json::json!({}), "sender").unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn vc_verify_is_pure_and_deterministic() {
        // The asserter puzzle hash is computed with no chain/keys, and is deterministic
        // for a given credential tuple.
        let params = serde_json::json!({
            "issuerDid": format!("0x{}", "11".repeat(32)),
            "assetId": format!("0x{}", "22".repeat(32)),
            "dataHash": format!("0x{}", "33".repeat(32)),
            "version": 1,
        });
        let a = vc_verify(&params).unwrap();
        let b = vc_verify(&params).unwrap();
        assert_eq!(a["asserterPuzzleHash"], b["asserterPuzzleHash"]);
        assert!(a["asserterPuzzleHash"].as_str().unwrap().starts_with("0x"));
        assert_eq!(a["version"], 1);
        // A missing field is a 400.
        let (code, _) = vc_verify(&serde_json::json!({})).unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn coin_spend_hex_round_trips_from_components() {
        // A coin spend reconstructs from coin{parent,puzzleHash,amount} + program hexes.
        let params = serde_json::json!({
            "parentSpend": {
                "coin": {
                    "parentCoinInfo": format!("0x{}", "01".repeat(32)),
                    "puzzleHash": format!("0x{}", "02".repeat(32)),
                    "amount": 7,
                },
                "puzzleReveal": "0xff80",
                "solution": "80",
            }
        });
        let cs = parse_coin_spend_hex(&params, "parentSpend").unwrap();
        assert_eq!(cs.coin.amount, 7);
        assert_eq!(hex::encode(cs.coin.parent_coin_info), "01".repeat(32));
        assert_eq!(hex::encode(cs.puzzle_reveal.as_ref()), "ff80");
        assert_eq!(hex::encode(cs.solution.as_ref()), "80");
        // A missing field is a 400.
        let (code, _) = parse_coin_spend_hex(&serde_json::json!({}), "parentSpend").unwrap_err();
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }
}
