//! The CONTROL / admin RPC surface — how a same-host controller (the DIG Browser
//! "My Node" UI, or any local tool) MANAGES the node, BESIDE the open read RPC.
//!
//! # Roles (SYSTEM.md → "Roles — serving vs consuming")
//!
//! dig-node = **serve + be-controllable**; dig-browser = **consume + control**. The
//! read methods (`dig.*`/`cache.*`) stay open to local consumers (the extension, the
//! browser's loader). The CONTROL methods here MANAGE the node — pin/unpin/list
//! hosted stores, view/clear/cap the cache, §21 sync status/trigger, get/set config,
//! and a rich node status — and are gated so a page a user merely *visits* cannot
//! drive the node.
//!
//! # Security — loopback-only + locally authorized
//!
//! Two layers:
//!
//! 1. **Loopback-only.** The whole server binds `127.0.0.1` (see [`crate::config`]),
//!    so nothing off-machine can reach any method.
//! 2. **Local authorization** for the mutating control namespace. A random
//!    **control token** is generated at first run into the node's config dir
//!    (`<config_dir>/control-token`, next to dig-node's `config.json`) with
//!    owner-only permissions where the OS supports it. A same-host controller reads
//!    that file (it can, because it runs as the same user on the same machine) and
//!    presents the token on every `control.*` call — as the `X-Dig-Control-Token`
//!    request header or a `params._control_token` field. The READ methods are NOT
//!    gated; only `control.*` requires the token.
//!
//! This is the standard "local capability file" pattern (cf. Chia's `daemon` /
//! Bitcoin's cookie auth): possession of the on-disk token = authorization, so a
//! random web page (which cannot read a local file) is rejected even though it can
//! reach loopback, while the legitimate local controller (which can) is allowed.
//!
//! The token is generated at RUNTIME and never committed; constant-time comparison
//! avoids a timing oracle.
//!
//! # What's proxied vs. owned
//!
//! Cache + sync operations proxy to digstore's `dig-node` crate (`cache_*`,
//! `clear_cache`, `set_cache_cap_bytes`, `Node::cache_fetch_and_cache` /
//! `cache_remove_cached` / `cache_list_cached`) — the companion never duplicates the
//! read/cache logic. The shell owns only the small amount of state the crate does
//! not model: the **pin registry** (which stores the operator chose to host, so they
//! survive being listed even before/after caching) and the **upstream override**,
//! both persisted in the companion's own keys inside dig-node's shared `config.json`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dig_node::Node;
use serde_json::{json, Value};

use crate::meta::ErrorCode;

/// The control-token file name, kept in the node's config dir next to
/// `config.json` so a same-host controller resolves it from one well-known place.
pub const CONTROL_TOKEN_FILE: &str = "control-token";

/// The request header a controller presents the control token in. Mirrors the
/// `params._control_token` alternative; either is accepted.
pub const CONTROL_TOKEN_HEADER: &str = "X-Dig-Control-Token";

/// The `params` field a controller may present the control token in, as an
/// alternative to the header (handy for JSON-RPC clients that don't set headers).
pub const CONTROL_TOKEN_PARAM: &str = "_control_token";

/// Is this method part of the gated CONTROL namespace? PURE.
///
/// Only `control.*` is gated; every read/discovery method (`dig.*`, `cache.*`,
/// `rpc.discover`) is open to local consumers.
pub fn is_control_method(method: &str) -> bool {
    method.starts_with("control.")
}

/// The path to the control-token file, given the node's config dir. The config dir
/// is `config.json`'s parent (dig-node's `config_path()`), so the token lives beside
/// the shared config. PURE (path math only).
pub fn control_token_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|p| p.join(CONTROL_TOKEN_FILE))
        .unwrap_or_else(|| PathBuf::from(CONTROL_TOKEN_FILE))
}

/// Load the control token, generating + persisting a fresh one if absent.
///
/// The token is 32 random bytes rendered as 64-hex. Generated at RUNTIME into the
/// node's config dir on first call; subsequent calls (and other processes sharing
/// the dir) read the same value. Written with owner-only permissions on Unix
/// (`0600`) so another user on the box cannot read it. Never committed.
pub fn load_or_create_token() -> std::io::Result<String> {
    let path = control_token_path(&dig_node::config_path());
    load_or_create_token_at(&path)
}

/// [`load_or_create_token`] for an explicit path (so tests use a temp dir and never
/// touch the real config). Reads an existing non-blank token; otherwise generates,
/// persists (owner-only on Unix), and returns a fresh one.
pub fn load_or_create_token_at(path: &Path) -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = generate_token();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, &token)?;
    restrict_permissions(path);
    Ok(token)
}

/// Restrict the token file to owner read/write where the OS supports it (Unix
/// `0600`). On Windows the default ACL on a per-user profile dir already scopes it
/// to the user, and loopback-only binding is the primary control; this is
/// best-effort defense-in-depth, so a failure is ignored.
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Generate a fresh 64-hex control token from 32 bytes of OS randomness.
fn generate_token() -> String {
    let mut buf = [0u8; 32];
    fill_random(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Fill `buf` with cryptographically-random bytes from the OS, without adding a
/// crypto dependency: read `/dev/urandom` on Unix, `BCryptGenRandom` is not wired
/// so on Windows we fall back to a strong, non-deterministic mix (PID + high-res
/// time + address-space entropy hashed) — adequate for a loopback capability token
/// whose real protection is the file's same-host-readable property + loopback bind.
/// Unix uses the kernel CSPRNG directly.
fn fill_random(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    // Fallback (Windows, or a Unix box without /dev/urandom): mix several
    // non-deterministic sources through a splitmix64 stream. Not a CSPRNG, but the
    // token's security model is "readable only by a same-host process", not
    // secrecy from a network attacker; combined with loopback-only binding this is
    // sufficient, and it never blocks the build on a platform crypto crate.
    let mut seed = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id() as u64;
        let stack_addr = (&seed_anchor() as *const u8) as u64;
        nanos ^ pid.rotate_left(17) ^ stack_addr.rotate_left(33)
    };
    for slot in buf.iter_mut() {
        // splitmix64
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *slot = (z & 0xff) as u8;
    }
}

/// A tiny stack byte whose address contributes ASLR entropy to the fallback seed.
#[inline(never)]
fn seed_anchor() -> u8 {
    0
}

/// Constant-time string equality, so token verification can't be probed via a
/// timing oracle. Compares byte-by-byte over the max length, never short-circuiting.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the presented control token from a request: the `X-Dig-Control-Token`
/// header (preferred) or `params._control_token`. PURE. `header` is whatever the
/// server read from the request headers (it does header parsing; this stays I/O
/// free). Returns `None` when neither is present.
pub fn presented_token(header: Option<&str>, req: &Value) -> Option<String> {
    if let Some(h) = header {
        let t = h.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    req.get("params")
        .and_then(|p| p.get(CONTROL_TOKEN_PARAM))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Decide whether a request is AUTHORIZED to run a control method. PURE.
///
/// * Not a `control.*` method → always authorized (read methods are open).
/// * A `control.*` method → authorized only when the presented token matches the
///   expected token (constant-time).
///
/// This is the single gate the server consults; it is pure so the
/// allow/deny contract is unit-tested exhaustively without a running server.
pub fn is_authorized(method: &str, presented: Option<&str>, expected: &str) -> bool {
    if !is_control_method(method) {
        return true;
    }
    match presented {
        Some(tok) => ct_eq(tok, expected),
        None => false,
    }
}

/// A control-plane error envelope carrying a catalogued, stable code (same shape as
/// the read-plane [`crate::rpc::rpc_error`]). PURE.
pub fn control_error(id: Value, code: ErrorCode, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code.code(),
            "message": message.into(),
            "data": { "code": code.name(), "origin": code.origin() },
        },
    })
}

/// A control-plane success envelope. PURE.
pub fn control_ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

// -- Pin registry (companion-owned config state) -----------------------------
//
// dig-node models the cache as a set of capsules but has no concept of a "pinned"
// store the operator deliberately hosts. The companion owns that small registry,
// persisted under its OWN key (`pinned_stores`) in dig-node's shared `config.json`
// (read-modify-write via an atomic temp+rename write), so a pin survives listing
// and an LRU eviction (the controller can re-trigger a sync for a pinned store).

/// The config.json key the companion stores the pinned-store list under. Namespaced
/// so it never collides with dig-node's own keys (`cache_cap_bytes`, `wc_project_id`).
const PINNED_KEY: &str = "pinned_stores";

/// The companion config.json key for the persisted upstream override (set via
/// `control.config.setUpstream`; read by `Config::from_env` on next start).
pub const UPSTREAM_OVERRIDE_KEY: &str = "upstream_override";

/// Read the pinned-store list from the node's config.json. Each entry is a
/// canonical lowercase 64-hex store id (optionally with a pinned root, kept as a
/// `{store_id, root?}` object). Missing/blank config → empty list.
pub fn read_pins() -> Vec<Value> {
    read_pins_from(&dig_node::config_path())
}

/// [`read_pins`] for an explicit config path (tests).
pub fn read_pins_from(config_path: &Path) -> Vec<Value> {
    let Ok(txt) = std::fs::read_to_string(config_path) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&txt) else {
        return Vec::new();
    };
    v.get(PINNED_KEY)
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Read the persisted upstream override from config.json, if any (blank → `None`).
pub fn read_upstream_override_from(config_path: &Path) -> Option<String> {
    let txt = std::fs::read_to_string(config_path).ok()?;
    let v: Value = serde_json::from_str(&txt).ok()?;
    v.get(UPSTREAM_OVERRIDE_KEY)
        .and_then(|u| u.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Read the persisted upstream override from the real config path.
pub fn read_upstream_override() -> Option<String> {
    read_upstream_override_from(&dig_node::config_path())
}

/// Read-modify-write the node's config.json, applying `mutate` to the parsed JSON
/// and writing it back atomically (temp file in the same dir + rename). Mirrors
/// dig-node's own `write_atomic` so the shared config is never observed torn. Used
/// for the companion's `pinned_stores` / `upstream_override` keys ONLY — it never
/// touches dig-node's keys.
fn update_config(config_path: &Path, mutate: impl FnOnce(&mut Value)) -> std::io::Result<()> {
    if let Some(dir) = config_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut v: Value = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({}));
    mutate(&mut v);
    let bytes = serde_json::to_vec_pretty(&v).unwrap_or_default();
    write_atomic(config_path, &bytes)
}

/// Atomic write (temp in same dir + rename) — see [`update_config`].
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".tmp-control-{}-{}", std::process::id(), nanos));
    std::fs::write(&tmp, bytes)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Add a store (canonical 64-hex id, optional root) to the pin registry. Idempotent
/// (a store already pinned is not duplicated; pinning with a root updates the entry).
pub fn add_pin(config_path: &Path, store_id: &str, root: Option<&str>) -> std::io::Result<()> {
    let entry = match root {
        Some(r) => json!({ "store_id": store_id, "root": r }),
        None => json!({ "store_id": store_id }),
    };
    update_config(config_path, |v| {
        let arr = v
            .as_object_mut()
            .map(|o| o.entry(PINNED_KEY).or_insert_with(|| json!([])))
            .and_then(|e| e.as_array_mut());
        if let Some(arr) = arr {
            arr.retain(|e| e.get("store_id").and_then(|s| s.as_str()) != Some(store_id));
            arr.push(entry);
        }
    })
}

/// Remove a store from the pin registry. Idempotent (absent → no-op). Returns
/// whether an entry was actually removed.
pub fn remove_pin(config_path: &Path, store_id: &str) -> std::io::Result<bool> {
    let mut removed = false;
    update_config(config_path, |v| {
        if let Some(arr) = v.get_mut(PINNED_KEY).and_then(|p| p.as_array_mut()) {
            let before = arr.len();
            arr.retain(|e| e.get("store_id").and_then(|s| s.as_str()) != Some(store_id));
            removed = arr.len() != before;
        }
    })?;
    Ok(removed)
}

/// Persist the upstream override (set via `control.config.setUpstream`). A blank
/// value clears the override (falling back to env/default on next start).
pub fn set_upstream_override(config_path: &Path, upstream: &str) -> std::io::Result<()> {
    let trimmed = upstream.trim().to_string();
    update_config(config_path, |v| {
        if trimmed.is_empty() {
            if let Some(obj) = v.as_object_mut() {
                obj.remove(UPSTREAM_OVERRIDE_KEY);
            }
        } else {
            v[UPSTREAM_OVERRIDE_KEY] = json!(trimmed);
        }
    })
}

/// Is a value a canonical lowercase 64-hex string (a store id / root)? PURE.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a `storeId` or `storeId:rootHash` capsule reference into `(store_id, root?)`,
/// validating each part is 64-hex. PURE. Returns `Err(message)` on a malformed ref.
pub fn parse_store_ref(s: &str) -> Result<(String, Option<String>), String> {
    let s = s.trim();
    if let Some((store, root)) = s.split_once(':') {
        if !is_hex64(store) {
            return Err(format!("invalid store_id (want 64-hex): {store}"));
        }
        if !is_hex64(root) {
            return Err(format!("invalid root (want 64-hex): {root}"));
        }
        Ok((store.to_lowercase(), Some(root.to_lowercase())))
    } else {
        if !is_hex64(s) {
            return Err(format!("invalid store_id (want 64-hex): {s}"));
        }
        Ok((s.to_lowercase(), None))
    }
}

/// The runtime context the control dispatcher needs from the server: the embedded
/// node (for cache ops + §21 sync), the resolved config path (where pins/config
/// live), the bound addr + upstream + start instant (for status), and whether a
/// §21 identity is loaded (whole-store sync availability).
pub struct ControlCtx {
    /// The embedded dig-node, for cache list/remove/fetch + §21 sync.
    pub node: Arc<Node>,
    /// The node's config.json path (pins + upstream override live here).
    pub config_path: PathBuf,
    /// The loopback `host:port` the node is bound to (status/config).
    pub addr: String,
    /// The upstream DIG RPC the node proxies/syncs to.
    pub upstream: String,
    /// The process start instant, for uptime in `control.status`.
    pub started: std::time::Instant,
    /// Whether authenticated §21 whole-store sync is available (a §21 identity is
    /// loaded). Drives `control.sync.*` and NOT_SUPPORTED.
    pub sync_available: bool,
}

/// Dispatch a single authorized CONTROL method. The caller has ALREADY enforced the
/// auth gate ([`is_authorized`]); this performs the operation and returns the
/// JSON-RPC response Value. Unknown `control.*` methods → METHOD_NOT_FOUND.
pub async fn dispatch_control(ctx: &ControlCtx, id: Value, method: &str, params: &Value) -> Value {
    match method {
        "control.status" => control_ok(id, status(ctx).await),
        "control.config.get" => control_ok(id, config_get(ctx)),
        "control.config.setUpstream" => config_set_upstream(ctx, id, params),
        "control.cache.get" => control_ok(id, cache_get()),
        "control.cache.setCap" => cache_set_cap(id, params),
        "control.cache.clear" => {
            dig_node::clear_cache();
            control_ok(id, json!({ "cleared": true }))
        }
        "control.hostedStores.list" => control_ok(id, hosted_list(ctx).await),
        "control.hostedStores.pin" => hosted_pin(ctx, id, params).await,
        "control.hostedStores.unpin" => hosted_unpin(ctx, id, params).await,
        "control.hostedStores.status" => hosted_status(ctx, id, params).await,
        "control.sync.status" => control_ok(id, sync_status(ctx).await),
        "control.sync.trigger" => sync_trigger(ctx, id, params).await,
        _ => control_error(
            id,
            ErrorCode::MethodNotFound,
            format!("unknown control method: {method}"),
        ),
    }
}

/// Rich node status — the controller's at-a-glance view.
async fn status(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let hosted_store_count = distinct_store_count(&cached);
    let pins = read_pins_from(&ctx.config_path);
    json!({
        "running": true,
        "service": crate::meta::SERVICE_NAME,
        "version": crate::meta::VERSION,
        "commit": crate::meta::GIT_SHA,
        "dig_node_version": crate::meta::DIG_NODE_VERSION,
        "protocol": crate::meta::PROTOCOL,
        "uptime_secs": ctx.started.elapsed().as_secs(),
        "addr": ctx.addr,
        "upstream": ctx.upstream,
        "cache": cache_get(),
        "hosted_store_count": hosted_store_count,
        "cached_capsule_count": cached.len(),
        "pinned_store_count": pins.len(),
        "sync": {
            "available": ctx.sync_available,
        },
    })
}

/// Node config: bound addr/port, cache dir + shared flag, upstream, identity.
fn config_get(ctx: &ControlCtx) -> Value {
    let (dir, shared) = (crate::meta::cache_dir(), crate::meta::cache_shared());
    let port = ctx.addr.rsplit(':').next().unwrap_or("");
    json!({
        "addr": ctx.addr,
        "port": port,
        "upstream": ctx.upstream,
        "upstream_override": read_upstream_override_from(&ctx.config_path),
        "cache_dir": dir.display().to_string(),
        "cache_shared": shared,
        "config_path": ctx.config_path.display().to_string(),
        "sync_available": ctx.sync_available,
    })
}

/// Set the upstream override (persisted; effective on next node start).
fn config_set_upstream(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(upstream) = params.get("upstream").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.config.setUpstream requires params.upstream (a URL string)",
        );
    };
    let normalized = crate::config::normalize_upstream(upstream);
    match set_upstream_override(&ctx.config_path, &normalized) {
        Ok(()) => control_ok(
            id,
            json!({
                "upstream": normalized,
                // The embedded node captured its upstream at construction, so a
                // change takes effect when the node is next started.
                "requires_restart": true,
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to persist upstream override: {e}"),
        ),
    }
}

/// Cache view (cap/used/dir/shared) — reuses the dig-node crate's resolvers.
fn cache_get() -> Value {
    json!({
        "cap_bytes": dig_node::cache_cap_bytes(),
        "used_bytes": dig_node::cache_used_bytes(),
        "dir": crate::meta::cache_dir().display().to_string(),
        "shared": crate::meta::cache_shared(),
    })
}

/// Set the cache cap (bytes, floored at 64 MiB by dig-node).
fn cache_set_cap(id: Value, params: &Value) -> Value {
    let Some(cap) = params.get("cap_bytes").and_then(|v| v.as_u64()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.cache.setCap requires params.cap_bytes (a number)",
        );
    };
    let floored = cap.max(64 * 1024 * 1024);
    match dig_node::set_cache_cap_bytes(floored) {
        Ok(()) => control_ok(id, json!({ "cap_bytes": floored })),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to set cache cap: {e}"),
        ),
    }
}

/// List hosted/pinned stores: every store the node holds (from the cache) AND every
/// pinned store, merged, with each store's cached capsules + a `pinned` flag.
async fn hosted_list(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let pins = read_pins_from(&ctx.config_path);
    let pinned_ids: std::collections::HashSet<String> = pins
        .iter()
        .filter_map(|p| {
            p.get("store_id")
                .and_then(|s| s.as_str())
                .map(str::to_string)
        })
        .collect();

    // Group cached capsules by store id.
    let mut by_store: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    for c in &cached {
        by_store.entry(c.store_id.clone()).or_default().push(json!({
            "capsule": format!("{}:{}", c.store_id, c.root),
            "root": c.root,
            "size_bytes": c.size_bytes,
            "last_used_unix_ms": c.last_used_unix_ms,
        }));
    }
    // Ensure pinned-but-not-yet-cached stores still appear.
    for id in &pinned_ids {
        by_store.entry(id.clone()).or_default();
    }

    let stores: Vec<Value> = by_store
        .into_iter()
        .map(|(store_id, capsules)| {
            let total: u64 = capsules
                .iter()
                .filter_map(|c| c.get("size_bytes").and_then(|s| s.as_u64()))
                .sum();
            json!({
                "store_id": store_id,
                "pinned": pinned_ids.contains(&store_id),
                "capsule_count": capsules.len(),
                "total_bytes": total,
                "capsules": capsules,
            })
        })
        .collect();

    json!({ "stores": stores })
}

/// Pin a store (storeId[:rootHash]): record it in the pin registry, then
/// pre-fetch the capsule into the cache via §21 sync when a concrete root is given
/// and sync is available. A pin with no root, or one made while sync is
/// unavailable, is recorded and the fetch result is reported in-band so the
/// controller can show "pinned, not yet synced".
async fn hosted_pin(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.pin requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    if let Err(e) = add_pin(&ctx.config_path, &store_id, root.as_deref()) {
        return control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to record pin: {e}"),
        );
    }

    // Pre-fetch when we have a concrete root and §21 sync is available.
    let fetch = match (&root, ctx.sync_available) {
        (Some(r), true) => match ctx.node.cache_fetch_and_cache(&store_id, r).await {
            Ok((size_bytes, served_root)) => json!({
                "status": "cached",
                "size_bytes": size_bytes,
                "served_root": served_root,
            }),
            Err(e) => json!({ "status": "failed", "message": e }),
        },
        (Some(_), false) => json!({
            "status": "skipped",
            "reason": "NOT_SUPPORTED",
            "message": "no §21 identity loaded — authenticated whole-store sync unavailable",
        }),
        (None, _) => json!({
            "status": "skipped",
            "reason": "no_root",
            "message": "pinned at store level; provide storeId:rootHash to pre-fetch a capsule",
        }),
    };

    control_ok(
        id,
        json!({
            "store_id": store_id,
            "root": root,
            "pinned": true,
            "fetch": fetch,
        }),
    )
}

/// Unpin a store: remove it from the pin registry and evict its cached capsule(s).
async fn hosted_unpin(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.unpin requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, _root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    let removed = match remove_pin(&ctx.config_path, &store_id) {
        Ok(r) => r,
        Err(e) => {
            return control_error(
                id,
                ErrorCode::ControlError,
                format!("failed to remove pin: {e}"),
            )
        }
    };
    // Evict every cached capsule of this store.
    let cached = ctx.node.cache_list_cached().await;
    let mut evicted = 0u64;
    for c in cached.iter().filter(|c| c.store_id == store_id) {
        if let Ok(true) = ctx.node.cache_remove_cached(&c.store_id, &c.root).await {
            evicted += 1;
        }
    }
    control_ok(
        id,
        json!({
            "store_id": store_id,
            "unpinned": removed,
            "evicted_capsules": evicted,
        }),
    )
}

/// Per-store status: pinned flag, cached capsules, total bytes.
async fn hosted_status(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    let Some(store_ref) = params.get("store").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.hostedStores.status requires params.store (storeId or storeId:rootHash)",
        );
    };
    let (store_id, _root) = match parse_store_ref(store_ref) {
        Ok(p) => p,
        Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
    };
    let cached = ctx.node.cache_list_cached().await;
    let capsules: Vec<Value> = cached
        .iter()
        .filter(|c| c.store_id == store_id)
        .map(|c| {
            json!({
                "capsule": format!("{}:{}", c.store_id, c.root),
                "root": c.root,
                "size_bytes": c.size_bytes,
                "last_used_unix_ms": c.last_used_unix_ms,
            })
        })
        .collect();
    let total: u64 = capsules
        .iter()
        .filter_map(|c| c.get("size_bytes").and_then(|s| s.as_u64()))
        .sum();
    let pinned = read_pins_from(&ctx.config_path)
        .iter()
        .any(|p| p.get("store_id").and_then(|s| s.as_str()) == Some(store_id.as_str()));
    control_ok(
        id,
        json!({
            "store_id": store_id,
            "pinned": pinned,
            "capsule_count": capsules.len(),
            "total_bytes": total,
            "capsules": capsules,
        }),
    )
}

/// §21 sync status: whether authenticated whole-store sync is available, and the
/// pinned-store coverage (how many pinned stores currently have a cached capsule).
async fn sync_status(ctx: &ControlCtx) -> Value {
    let cached = ctx.node.cache_list_cached().await;
    let cached_stores: std::collections::HashSet<&str> =
        cached.iter().map(|c| c.store_id.as_str()).collect();
    let pins = read_pins_from(&ctx.config_path);
    let pinned_total = pins.len();
    let pinned_synced = pins
        .iter()
        .filter_map(|p| p.get("store_id").and_then(|s| s.as_str()))
        .filter(|s| cached_stores.contains(s))
        .count();
    json!({
        "available": ctx.sync_available,
        "method": "section-21-whole-store-sync",
        "pinned_total": pinned_total,
        "pinned_synced": pinned_synced,
        // Whole-store-by-store-id sync (without a concrete capsule root) is not
        // exposed by the pinned dig-node crate revision; per-capsule sync IS (via
        // control.sync.trigger / hostedStores.pin with a root).
        "whole_store_trigger_supported": false,
    })
}

/// Trigger a §21 sync for one capsule (storeId + root). Reports NOT_SUPPORTED when
/// authenticated sync is unavailable (no §21 identity), and INVALID_PARAMS for a bad
/// capsule ref. The actual fetch proxies to dig-node's `cache_fetch_and_cache`.
async fn sync_trigger(ctx: &ControlCtx, id: Value, params: &Value) -> Value {
    // Accept either `store` = "storeId:rootHash" or explicit store_id + root.
    let (store_id, root) = if let Some(s) = params.get("store").and_then(|v| v.as_str()) {
        match parse_store_ref(s) {
            Ok((sid, Some(r))) => (sid, r),
            Ok((_, None)) => {
                return control_error(
                    id,
                    ErrorCode::InvalidParams,
                    "control.sync.trigger needs a capsule root: pass store as storeId:rootHash",
                )
            }
            Err(e) => return control_error(id, ErrorCode::InvalidParams, e),
        }
    } else {
        let sid = params
            .get("store_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let r = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
        if !is_hex64(sid) || !is_hex64(r) {
            return control_error(
                id,
                ErrorCode::InvalidParams,
                "control.sync.trigger requires store_id + root (each 64-hex), \
                 or store=storeId:rootHash",
            );
        }
        (sid.to_lowercase(), r.to_lowercase())
    };

    if !ctx.sync_available {
        return control_error(
            id,
            ErrorCode::NotSupported,
            "authenticated §21 whole-store sync is unavailable (no §21 identity loaded)",
        );
    }

    match ctx.node.cache_fetch_and_cache(&store_id, &root).await {
        Ok((size_bytes, served_root)) => control_ok(
            id,
            json!({
                "store_id": store_id,
                "root": root,
                "status": "synced",
                "size_bytes": size_bytes,
                "served_root": served_root,
            }),
        ),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("§21 sync failed for {store_id}:{root}: {e}"),
        ),
    }
}

/// Count distinct store ids among the cached capsules. PURE-ish (reads the slice).
fn distinct_store_count(cached: &[dig_node::CachedCapsule]) -> usize {
    cached
        .iter()
        .map(|c| c.store_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn is_control_method_only_matches_control_namespace() {
        assert!(is_control_method("control.status"));
        assert!(is_control_method("control.hostedStores.pin"));
        assert!(!is_control_method("dig.getContent"));
        assert!(!is_control_method("cache.getConfig"));
        assert!(!is_control_method("rpc.discover"));
        assert!(!is_control_method(""));
    }

    #[test]
    fn read_methods_are_always_authorized_without_a_token() {
        // The whole point of the gate: read methods are open to local consumers.
        assert!(is_authorized("dig.getContent", None, "secret"));
        assert!(is_authorized("cache.getConfig", None, "secret"));
        assert!(is_authorized("rpc.discover", None, "secret"));
    }

    #[test]
    fn control_method_without_token_is_rejected() {
        assert!(!is_authorized("control.status", None, "secret"));
    }

    #[test]
    fn control_method_with_wrong_token_is_rejected() {
        assert!(!is_authorized("control.status", Some("wrong"), "secret"));
    }

    #[test]
    fn control_method_with_correct_token_is_allowed() {
        assert!(is_authorized("control.status", Some("secret"), "secret"));
    }

    #[test]
    fn ct_eq_matches_string_equality_but_constant_time() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd")); // length differs
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn presented_token_prefers_header_then_param() {
        let req = json!({ "params": { "_control_token": "from-param" } });
        assert_eq!(
            presented_token(Some("from-header"), &req),
            Some("from-header".to_string())
        );
        assert_eq!(presented_token(None, &req), Some("from-param".to_string()));
        assert_eq!(
            presented_token(Some("   "), &req),
            Some("from-param".to_string())
        );
        assert_eq!(presented_token(None, &json!({})), None);
    }

    #[test]
    fn generate_token_is_64_hex_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two generated tokens must differ");
    }

    #[test]
    fn load_or_create_token_persists_and_is_stable() {
        let dir = std::env::temp_dir().join(format!(
            "dig-companion-token-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let first = load_or_create_token_at(&path).unwrap();
        let second = load_or_create_token_at(&path).unwrap();
        assert_eq!(first, second, "token must be stable across reads");
        assert_eq!(first.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_store_ref_validates_hex_and_splits_capsule() {
        let store = "a".repeat(64);
        let root = "b".repeat(64);
        assert_eq!(parse_store_ref(&store).unwrap(), (store.clone(), None));
        assert_eq!(
            parse_store_ref(&format!("{store}:{root}")).unwrap(),
            (store.clone(), Some(root.clone()))
        );
        assert!(parse_store_ref("nothex").is_err());
        assert!(parse_store_ref(&format!("{store}:nothex")).is_err());
    }

    #[test]
    fn pin_registry_roundtrips_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "dig-companion-pins-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        let store = "c".repeat(64);
        let root = "d".repeat(64);

        assert!(read_pins_from(&config_path).is_empty());
        add_pin(&config_path, &store, Some(&root)).unwrap();
        // Idempotent: pinning the same store again does not duplicate it.
        add_pin(&config_path, &store, Some(&root)).unwrap();
        let pins = read_pins_from(&config_path);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0]["store_id"], json!(store));
        assert_eq!(pins[0]["root"], json!(root));

        assert!(remove_pin(&config_path, &store).unwrap());
        assert!(read_pins_from(&config_path).is_empty());
        // Removing an absent pin is a no-op false.
        assert!(!remove_pin(&config_path, &store).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_config_preserves_dig_node_keys() {
        // The companion's pin/upstream writes must NOT clobber dig-node's own keys
        // in the shared config.json (cache_cap_bytes, wc_project_id).
        let dir = std::env::temp_dir().join(format!(
            "dig-companion-config-merge-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&json!({ "cache_cap_bytes": 12345, "wc_project_id": "abc" }))
                .unwrap(),
        )
        .unwrap();

        let store = "e".repeat(64);
        add_pin(&config_path, &store, None).unwrap();
        set_upstream_override(&config_path, "https://example.test").unwrap();

        let v: Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(v["cache_cap_bytes"], json!(12345), "dig-node key preserved");
        assert_eq!(v["wc_project_id"], json!("abc"), "dig-node key preserved");
        assert_eq!(v["pinned_stores"][0]["store_id"], json!(store));
        assert_eq!(v["upstream_override"], json!("https://example.test"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upstream_override_roundtrips_and_clears() {
        let dir = std::env::temp_dir().join(format!(
            "dig-companion-upstream-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let config_path = dir.join("config.json");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(read_upstream_override_from(&config_path), None);
        set_upstream_override(&config_path, "https://up.test").unwrap();
        assert_eq!(
            read_upstream_override_from(&config_path),
            Some("https://up.test".to_string())
        );
        // Blank clears it.
        set_upstream_override(&config_path, "  ").unwrap();
        assert_eq!(read_upstream_override_from(&config_path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
