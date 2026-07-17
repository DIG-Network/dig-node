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
//!    **control token** is generated at first run into the machine-wide, identity-
//!    INDEPENDENT state dir (`<state_dir>/control-token` — [`crate::state`], #501) with
//!    a restrictive ACL. A same-host controller reads that file and presents the token
//!    on every `control.*` call — as the `X-Dig-Control-Token` request header or a
//!    `params._control_token` field. The READ methods are NOT gated; only `control.*`
//!    requires the token. The token lives in [`crate::state::state_dir`] (NOT the
//!    per-user config dir) so the daemon (which may run as a service under a different
//!    OS account) and the operator CLI resolve the SAME file.
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
//! `cache_remove_cached` / `cache_list_cached`) — this service never duplicates the
//! read/cache logic. The shell owns only the small amount of state the crate does
//! not model: the **pin registry** (which stores the operator chose to host, so they
//! survive being listed even before/after caching) and the **upstream override**,
//! both persisted in this service's own keys inside the shared `config.json`.
//! `control.updater.*` (#515) proxies the DIG auto-update beacon the same way — see
//! [`crate::updater`] for what it reads directly vs. shells out to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dig_node_core::Node;
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

/// The canonical set of `control.*` methods the node's control plane RESOLVES — the
/// union of the methods this shell owns ([`dispatch_control`]) and the ones it delegates
/// to the embedded node's own control surface (`control.peerStatus` +
/// `control.subscribe`/`unsubscribe`/`listSubscriptions`). This is the SINGLE source of
/// truth for "what can be controlled", consumed by:
///
/// * the CLI-parity drift test (#426) — every method here MUST have a `dig-node` CLI verb
///   (see `crate::control_cli::cli_covered_control_methods`), so the CLI never silently
///   falls behind the WS control surface the extension drives;
/// * introspection — a stable list a machine can enumerate.
///
/// Keep it in lockstep with [`dispatch_control`]: a new `control.*` method added there MUST
/// be added here (and given a CLI verb), or the drift test fails.
pub const CONTROL_METHODS: &[&str] = &[
    // Owned by this shell (dispatch_control).
    "control.status",
    "control.config.get",
    "control.config.setUpstream",
    "control.log.setLevel",
    "control.cache.get",
    "control.cache.setCap",
    "control.cache.clear",
    "control.hostedStores.list",
    "control.hostedStores.pin",
    "control.hostedStores.unpin",
    "control.hostedStores.status",
    "control.sync.status",
    "control.sync.trigger",
    "control.updater.status",
    "control.updater.setChannel",
    "control.updater.pause",
    "control.updater.resume",
    "control.updater.checkNow",
    "control.pairing.list",
    "control.pairing.approve",
    "control.pairing.revoke",
    // Delegated to the embedded node's own control surface.
    "control.peerStatus",
    "control.subscribe",
    "control.unsubscribe",
    "control.listSubscriptions",
];

/// The control methods this shell HANDLES ITSELF, in [`dispatch_control`]'s owned arms — the
/// ROUTING source of truth: [`dispatch_control`] delegates any method NOT in this set to the
/// embedded node. Adding an owned `match` arm without listing it here leaves that arm
/// unreachable (silently delegated); the lockstep test
/// (`control_methods_partition_into_owned_and_delegated`) forces this set + [`CONTROL_METHODS`]
/// to agree, so a shell-owned method can never be dispatched without also being declared.
pub const OWNED_CONTROL_METHODS: &[&str] = &[
    "control.status",
    "control.config.get",
    "control.config.setUpstream",
    "control.log.setLevel",
    "control.cache.get",
    "control.cache.setCap",
    "control.cache.clear",
    "control.hostedStores.list",
    "control.hostedStores.pin",
    "control.hostedStores.unpin",
    "control.hostedStores.status",
    "control.sync.status",
    "control.sync.trigger",
    "control.updater.status",
    "control.updater.setChannel",
    "control.updater.pause",
    "control.updater.resume",
    "control.updater.checkNow",
    "control.pairing.list",
    "control.pairing.approve",
    "control.pairing.revoke",
];

/// The control methods [`dispatch_control`] DELEGATES to the embedded node's own control surface
/// (`dig_node_core::handle_rpc`) — the node-internal subscription set + peer-status snapshot.
/// Together with [`OWNED_CONTROL_METHODS`] this partitions [`CONTROL_METHODS`] exactly (asserted
/// by the lockstep test): the two disjoint sets union to the full control surface.
pub const DELEGATED_CONTROL_METHODS: &[&str] = &[
    "control.peerStatus",
    "control.subscribe",
    "control.unsubscribe",
    "control.listSubscriptions",
];

/// Is this a PAIRING-ADMINISTRATION control method (#280)? PURE.
///
/// These manage the pairing lifecycle — list pending requests, approve one (minting
/// a scoped controller token), revoke an issued token — and so MUST require the
/// MASTER control token (a local file read), NEVER a paired token: a paired
/// controller can drive `control.*` mutations but can neither mint more tokens nor
/// hide/revoke itself. The auth gate consults this to decide whether the paired-token
/// path is even eligible.
pub fn is_pairing_admin_method(method: &str) -> bool {
    matches!(
        method,
        "control.pairing.list" | "control.pairing.approve" | "control.pairing.revoke"
    )
}

/// The path to the control-token file: `<state_dir>/control-token`, where the state
/// dir is the machine-wide, identity-INDEPENDENT daemon state dir (#501,
/// [`crate::state::state_dir`]) — NOT the per-user config dir. Decoupling the token
/// from `config_path()` is the fix for the service-vs-user path split: the running
/// daemon and the operator CLI resolve this ONE path regardless of which OS user each
/// runs as, so the CLI reads the SAME token the service wrote.
pub fn control_token_path() -> PathBuf {
    crate::state::state_dir().join(CONTROL_TOKEN_FILE)
}

/// Load the control token, generating + persisting a fresh one if absent.
///
/// The token is 32 random bytes rendered as 64-hex. Generated at RUNTIME into the
/// machine-wide state dir ([`control_token_path`]) on first call; subsequent calls (and
/// other processes / users on the box) read the same value. The dir + file are created
/// with a RESTRICTIVE ACL (owner/SYSTEM + Administrators, the creating user; never
/// world/all-users-readable — see [`crate::state`]). Never committed.
pub fn load_or_create_token() -> std::io::Result<String> {
    load_or_create_token_at(&control_token_path())
}

/// A precise, service-aware remedy for a control-token authorization failure (#501).
///
/// The classic failure is the service-vs-user PATH/PERMISSION split: the node runs as a
/// service (Windows LocalSystem / a root daemon) and minted `control-token` in the
/// machine-wide state dir with restrictive perms, but the interactive user running
/// `dig-node pair` / a `control.*` call cannot READ it. This inspects the resolved token
/// path from the CALLER's perspective and returns the exact fix (which dir + that it
/// needs elevation or the install-user's read ACL), instead of the generic hint.
pub fn control_token_remedy() -> String {
    control_token_remedy_for(&control_token_path())
}

/// [`control_token_remedy`] for an explicit `path` (so the classification is unit-tested
/// against a temp dir without touching the real state dir / `DIG_NODE_STATE_DIR`).
///
/// Classifies by the READ RESULT, NOT by `path.exists()`: a token the SYSTEM service minted
/// under a locked-down DACL is UNreadable by the invoking (non-elevated) user, and
/// `path.exists()` then reports `false` too (the denied ACL blocks even a stat) — which used to
/// mis-render the ACL split as a bare "no control token found" (#772). The read error KIND
/// distinguishes the cases: `PermissionDenied` = present-but-locked; anything else = absent.
pub fn control_token_remedy_for(path: &Path) -> String {
    let dir = path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    match std::fs::read_to_string(path) {
        // Blank token — treat as absent (not a state-dir mismatch).
        Ok(s) if s.trim().is_empty() => format!(
            "no control token found at {}. Start the node so it mints one (`dig-node run`, or `dig-node start` for the installed service), then retry. If the service IS already running, it is likely a STALE older build — reinstall the current dig-node (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`) so the running service mints the token here.",
            path.display()
        ),
        // Readable and non-blank, yet the presented token was rejected — a state-dir mismatch, not an
        // ACL/mint problem.
        Ok(_) => format!(
            "the presented control token was not accepted. Ensure the node and this command resolve the SAME state dir ({dir}) — if you set DIG_NODE_STATE_DIR it must match on both the node and this command."
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => format!(
            "the node's control token at {} exists but is NOT readable by your account — the node runs as a service under a different account (Windows LocalSystem / a root daemon). Re-run this command elevated (Administrator on Windows, sudo on Unix), or reinstall the current dig-node so the service grants your account read access to {} (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`).",
            path.display(),
            dir
        ),
        // Absent (NotFound) — the node has not minted one here yet. Either it is not running,
        // or a STALE older build (installed before the machine-wide state dir) is running and
        // never mints the token at this path; reinstalling the current dig-node fixes the latter.
        Err(_) => format!(
            "no control token found at {}. Start the node so it mints one (`dig-node run`, or `dig-node start` for the installed service), then retry. If the service IS already running, it is likely a STALE older build — reinstall the current dig-node (`dig-node uninstall` then an elevated `dig-node install`, then `dig-node start`) so the running service mints the token here.",
            path.display()
        ),
    }
}

/// Read the master control token WITHOUT creating one — the OPERATOR-side load (`dig-node
/// pair` / any local control CLI, #501). It must NEVER mint a token: minting a fresh token
/// the running node does not trust is the exact original bug (the CLI wrote its own token to
/// a per-user path the service never read). On a missing/unreadable/blank token it returns a
/// rich [`std::io::Error`] carrying [`control_token_remedy`] — the precise service-vs-user
/// remedy — with the error KIND chosen so the CLI maps it to the right exit code
/// ([`crate::cli::ExitCode::from_io_error`]): `PermissionDenied` (the ACL split → "elevate")
/// when the file is present but unreadable, else `NotFound` ("start the node").
pub fn load_token_readonly() -> std::io::Result<String> {
    read_token_readonly_at(&control_token_path())
}

/// [`load_token_readonly`] for an explicit `path` — the service-mints ⇄ CLI-reads round-trip is
/// unit-tested against a temp dir with this (no `DIG_NODE_STATE_DIR` env mutation, so it is
/// race-free under parallel tests). Classifies the failure KIND by the READ error, not
/// `path.exists()`, so an ACL-denied token maps to `PermissionDenied` ("elevate") rather than a
/// misleading `NotFound` (#772).
pub fn read_token_readonly_at(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => Ok(s.trim().to_string()),
        // Present-but-blank counts as absent (never a real token). A read ERROR keeps its kind:
        // PermissionDenied ⇒ the ACL split ("elevate"); anything else ⇒ NotFound ("start the node").
        read => {
            let kind = match &read {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    std::io::ErrorKind::PermissionDenied
                }
                _ => std::io::ErrorKind::NotFound,
            };
            drop(read);
            Err(std::io::Error::new(kind, control_token_remedy_for(path)))
        }
    }
}

/// [`load_or_create_token`] for an explicit path (so tests use a temp dir and never
/// touch the real config). Reads an existing non-blank token ONLY when its file is owned by a
/// trusted principal ([`crate::state::token_file_is_trusted`], #501 residual); otherwise (or
/// when absent) generates, persists (owner-only on Unix), and returns a fresh one.
pub fn load_or_create_token_at(path: &Path) -> std::io::Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            // #501 residual: TRUST a pre-existing token ONLY when its file is owned by a
            // trusted principal. An attacker who can plant a KNOWN token in the machine-wide
            // state dir — a `%PROGRAMDATA%` squat, or the narrow window during a service
            // harden — would otherwise have the daemon (LocalSystem) read + trust it, learning
            // the control token → full local node control (a local privilege escalation). A
            // foreign-owned token is deleted + regenerated, so the daemon only ever trusts a
            // token it (or a trusted principal: SYSTEM/Administrators/root) owns.
            if crate::state::token_file_is_trusted(path, crate::state::running_as_service()) {
                return Ok(t);
            }
            let _ = std::fs::remove_file(path);
        }
    }
    let token = generate_token();
    if let Some(dir) = path.parent() {
        // Create the state dir with a RESTRICTIVE ACL (not the world-readable default of
        // a machine-wide `%PROGRAMDATA%`) — see [`crate::state::ensure_dir_restricted`].
        crate::state::ensure_dir_restricted(dir)?;
    }
    std::fs::write(path, &token)?;
    restrict_permissions(path);
    Ok(token)
}

/// Restrict a control/auth file so it is not readable by every local user. Delegates to
/// [`crate::state::restrict_file`]: Unix `0600`; on Windows the file inherits the tight,
/// inheritable ACL of the machine-wide state dir ([`crate::state::ensure_dir_restricted`]) —
/// critical now that the file lives under `%PROGRAMDATA%`, whose default would otherwise let
/// every local user read it (a local privilege-escalation vector, #501). Best-effort (a
/// failure is ignored — loopback bind + token possession are the primary gate).
pub(crate) fn restrict_permissions(path: &Path) {
    crate::state::restrict_file(path);
}

/// Generate a fresh 64-hex control token from 32 bytes of OS randomness.
fn generate_token() -> String {
    random_hex(32)
}

/// `n_bytes` of OS randomness rendered as lowercase hex. Used for the control token
/// (32 bytes → 64-hex) and the pairing ids/tokens (#280). Same randomness source as
/// [`generate_token`].
pub(crate) fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    fill_random(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A short numeric pairing code (6 digits, zero-padded) for the compare-codes
/// consent step (#280) — the human confirms the extension's code matches the CLI's
/// before approving. Uniformly random over `000000..=999999` from OS randomness.
pub(crate) fn random_pairing_code() -> String {
    let mut buf = [0u8; 4];
    fill_random(&mut buf);
    let n = u32::from_le_bytes(buf) % 1_000_000;
    format!("{n:06}")
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

// -- Pin registry (service-owned config state) -------------------------------
//
// The embedded dig-node read path models the cache as a set of capsules but has no
// concept of a "pinned" store the operator deliberately hosts. This service owns
// that small registry, persisted under its OWN key (`pinned_stores`) in the shared
// `config.json` (read-modify-write via an atomic temp+rename write), so a pin
// survives listing and an LRU eviction (the controller can re-trigger a sync for a
// pinned store).

/// The config.json key this service stores the pinned-store list under. Namespaced
/// so it never collides with dig-node's own keys (`cache_cap_bytes`, `wc_project_id`).
const PINNED_KEY: &str = "pinned_stores";

/// The config.json key for the persisted upstream override (set via
/// `control.config.setUpstream`; read by `Config::from_env` on next start).
pub const UPSTREAM_OVERRIDE_KEY: &str = "upstream_override";

/// Read the pinned-store list from the node's config.json. Each entry is a
/// canonical lowercase 64-hex store id (optionally with a pinned root, kept as a
/// `{store_id, root?}` object). Missing/blank config → empty list.
pub fn read_pins() -> Vec<Value> {
    read_pins_from(&dig_node_core::config_path())
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
    read_upstream_override_from(&dig_node_core::config_path())
}

/// Read-modify-write the node's config.json, applying `mutate` to the parsed JSON
/// and writing it back atomically (temp file in the same dir + rename). Mirrors
/// dig-node's own `write_atomic` so the shared config is never observed torn. Used
/// for this service's `pinned_stores` / `upstream_override` keys ONLY — it never
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

/// Atomic write (temp in same dir + rename) — see [`update_config`]. Also used by
/// the pairing module (#280) to persist the paired-token store without a torn read.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
    /// The machine-wide daemon STATE dir (#501) — where the control token +
    /// `paired-tokens.json` live (NOT the per-user config dir). The pairing-admin
    /// methods read/write the paired-token store from here.
    pub state_dir: PathBuf,
    /// The loopback `host:port` the node is bound to (status/config).
    pub addr: String,
    /// The upstream DIG RPC the node proxies/syncs to.
    pub upstream: String,
    /// The process start instant, for uptime in `control.status`.
    pub started: std::time::Instant,
    /// Whether authenticated §21 whole-store sync is available (a §21 identity is
    /// loaded). Drives `control.sync.*` and NOT_SUPPORTED.
    pub sync_available: bool,
    /// The in-memory pending-pairing set (#280), shared with the OPEN
    /// `pairing.request`/`pairing.poll` handlers so an operator-approved pairing
    /// becomes pollable by the requesting extension.
    pub pairings: Arc<std::sync::Mutex<crate::pairing::PendingPairings>>,
}

/// Dispatch a single authorized CONTROL method. The caller has ALREADY enforced the
/// auth gate ([`is_authorized`]); this performs the operation and returns the
/// JSON-RPC response Value. Unknown `control.*` methods → METHOD_NOT_FOUND.
pub async fn dispatch_control(ctx: &ControlCtx, id: Value, method: &str, params: &Value) -> Value {
    // Route by the SINGLE source of truth: methods this shell owns go to `dispatch_owned`;
    // everything else (the delegated set + any genuinely-unknown `control.*`) falls through to
    // the embedded node's own control surface, which resolves it or returns -32601.
    if OWNED_CONTROL_METHODS.contains(&method) {
        return dispatch_owned(ctx, id, method, params).await;
    }
    // Control methods the shell does not own are delegated to the NODE's own control surface
    // (`control.peerStatus` / `control.subscribe` / `control.unsubscribe` /
    // `control.listSubscriptions` — the node's persisted subscription set + peer-status
    // snapshot). The shell forwards them so the whole control surface is reachable through one
    // loopback endpoint. A genuinely unknown control method falls through the node too and
    // returns -32601.
    let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    dig_node_core::handle_rpc(&ctx.node, req).await
}

/// Handle a control method OWNED by this shell (guaranteed by [`dispatch_control`] to be a member
/// of [`OWNED_CONTROL_METHODS`]). The `_` arm is [`unreachable`] BY CONSTRUCTION: it fires only if
/// [`OWNED_CONTROL_METHODS`] lists a method with no arm here (or vice-versa), i.e. the routing
/// const and the arms drifted — the lockstep test exercises this correspondence.
async fn dispatch_owned(ctx: &ControlCtx, id: Value, method: &str, params: &Value) -> Value {
    match method {
        "control.status" => control_ok(id, status(ctx).await),
        "control.config.get" => control_ok(id, config_get(ctx)),
        "control.config.setUpstream" => config_set_upstream(ctx, id, params),
        "control.log.setLevel" => log_set_level(id, params),
        "control.cache.get" => control_ok(id, cache_get()),
        "control.cache.setCap" => cache_set_cap(id, params),
        "control.cache.clear" => {
            dig_node_core::clear_cache();
            control_ok(id, json!({ "cleared": true }))
        }
        "control.hostedStores.list" => control_ok(id, hosted_list(ctx).await),
        "control.hostedStores.pin" => hosted_pin(ctx, id, params).await,
        "control.hostedStores.unpin" => hosted_unpin(ctx, id, params).await,
        "control.hostedStores.status" => hosted_status(ctx, id, params).await,
        "control.sync.status" => control_ok(id, sync_status(ctx).await),
        "control.sync.trigger" => sync_trigger(ctx, id, params).await,
        // The DIG auto-update beacon proxy (#515) — a THIN passthrough to `dig-updater`'s
        // own status file + CLI (see `crate::updater`'s module doc for why nothing here
        // re-implements the beacon's trust/install logic).
        "control.updater.status" => crate::updater::status(id),
        "control.updater.setChannel" => crate::updater::set_channel(id, params).await,
        "control.updater.pause" => crate::updater::pause(id, params).await,
        "control.updater.resume" => crate::updater::resume(id).await,
        "control.updater.checkNow" => crate::updater::check_now(id).await,
        // Pairing administration (#280) — reached only with the MASTER token (the
        // gate blocks a paired token from these, see `is_pairing_admin_method`).
        "control.pairing.list" => crate::pairing::list(&ctx.pairings, &ctx.state_dir, id),
        "control.pairing.approve" => {
            crate::pairing::approve(&ctx.pairings, &ctx.state_dir, id, params)
        }
        "control.pairing.revoke" => crate::pairing::revoke(&ctx.state_dir, id, params),
        // Unreachable: `dispatch_control` only routes here for `OWNED_CONTROL_METHODS` members.
        // Reaching this arm means the routing const and these arms have drifted.
        _ => unreachable!(
            "dispatch_owned reached for non-owned control method {method:?}: \
             OWNED_CONTROL_METHODS and dispatch_owned's arms have drifted"
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
        "cap_bytes": dig_node_core::cache_cap_bytes(),
        "used_bytes": dig_node_core::cache_used_bytes(),
        "dir": crate::meta::cache_dir().display().to_string(),
        "shared": crate::meta::cache_shared(),
    })
}

/// Set the cache cap (bytes, floored at 64 MiB by dig-node).
/// `control.log.setLevel` (#553): live-swap the running node's `tracing` level filter via the
/// `dig-logging` reload handle (SPEC §5). The filter is a standard `EnvFilter` directive, e.g.
/// `debug` or `info,dig_node_core=debug`. This takes effect immediately WITHOUT persisting — the
/// operator persists a level across restarts with `dig-node logs level <filter>`. Fails with
/// `InvalidParams` on a missing/invalid directive and `ControlError` when logging is not installed
/// in this process (never a serving node).
fn log_set_level(id: Value, params: &Value) -> Value {
    let Some(filter) = params.get("filter").and_then(|v| v.as_str()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.log.setLevel requires params.filter (an EnvFilter directive string)",
        );
    };
    match crate::logging::set_level(filter) {
        Ok(()) => control_ok(id, json!({ "filter": filter })),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to set level: {e}"),
        ),
    }
}

fn cache_set_cap(id: Value, params: &Value) -> Value {
    let Some(cap) = params.get("cap_bytes").and_then(|v| v.as_u64()) else {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.cache.setCap requires params.cap_bytes (a number)",
        );
    };
    let floored = cap.max(64 * 1024 * 1024);
    match dig_node_core::set_cache_cap_bytes(floored) {
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
fn distinct_store_count(cached: &[dig_node_core::CachedCapsule]) -> usize {
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

    /// LOCKSTEP GATE (#711): [`dispatch_control`] resolves EXACTLY [`CONTROL_METHODS`] — the
    /// owned set it routes to `dispatch_owned` ([`OWNED_CONTROL_METHODS`]) plus the set it
    /// delegates to the node ([`DELEGATED_CONTROL_METHODS`]) — the two disjoint, and their union
    /// equal to the declared surface. This closes the shell-owned-method drift gap the CLI-parity
    /// test (`cli_covers_every_node_control_method`) leaves open: a `dispatch_owned` arm added
    /// without declaring it (in `OWNED_CONTROL_METHODS` + `CONTROL_METHODS`) fails HERE, and a
    /// declared owned method with no arm makes `dispatch_owned`'s `unreachable!` fire.
    #[test]
    fn control_methods_partition_into_owned_and_delegated() {
        use std::collections::BTreeSet;
        let listed: BTreeSet<&str> = CONTROL_METHODS.iter().copied().collect();
        let owned: BTreeSet<&str> = OWNED_CONTROL_METHODS.iter().copied().collect();
        let delegated: BTreeSet<&str> = DELEGATED_CONTROL_METHODS.iter().copied().collect();

        // Each list is duplicate-free.
        assert_eq!(
            owned.len(),
            OWNED_CONTROL_METHODS.len(),
            "OWNED has duplicates"
        );
        assert_eq!(
            delegated.len(),
            DELEGATED_CONTROL_METHODS.len(),
            "DELEGATED has duplicates"
        );
        assert_eq!(
            listed.len(),
            CONTROL_METHODS.len(),
            "CONTROL_METHODS has duplicates"
        );

        // Owned and delegated are disjoint — no method is both handled and forwarded.
        let both: Vec<&&str> = owned.intersection(&delegated).collect();
        assert!(
            both.is_empty(),
            "methods both owned AND delegated: {both:?}"
        );

        // The union is EXACTLY the declared surface — neither an undeclared handler nor a
        // declared-but-unhandled method can slip through.
        let union: BTreeSet<&str> = owned.union(&delegated).copied().collect();
        assert_eq!(
            listed, union,
            "CONTROL_METHODS drifted from dispatch_control's owned+delegated set"
        );
    }

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
    fn log_set_level_rejects_a_missing_filter_param() {
        // #553: `control.log.setLevel` needs `params.filter`; an empty body is an InvalidParams
        // error, never a silent no-op.
        let resp = log_set_level(json!(1), &json!({}));
        assert_eq!(
            resp["error"]["code"],
            json!(ErrorCode::InvalidParams.code())
        );
    }

    #[test]
    fn log_set_level_errors_when_logging_is_not_installed() {
        // #553: in a plain `cargo test` process no serve path installed the logging guard, so a
        // live level change reports a ControlError (rather than pretending it applied). A valid
        // directive still parses — the failure is specifically "logging not initialised".
        let resp = log_set_level(json!(1), &json!({ "filter": "debug" }));
        assert_eq!(resp["error"]["code"], json!(ErrorCode::ControlError.code()));
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
            "dig-node-token-test-{}-{}",
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

    /// SECURITY (#501 residual): a pre-existing control-token file that is NOT owned by a
    /// trusted principal (here forced group/other-readable, so not owner-only) MUST be DELETED
    /// and REGENERATED — never returned — so a planted/squatted token can never become the
    /// trusted one (which would hand an attacker full local node control). Unix-gated: it
    /// relies on mode bits (CI runs on Linux). Skipped when running as root, where a
    /// root-owned file is legitimately trusted regardless of mode.
    #[cfg(unix)]
    #[test]
    fn foreign_owned_token_file_is_regenerated_not_trusted() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-untrusted-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let planted = "planted0".repeat(8); // a KNOWN 64-char attacker value (non-empty)
        std::fs::write(&path, &planted).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let running_as_root = std::fs::metadata(&path)
            .map(|m| m.uid() == 0)
            .unwrap_or(false);
        let got = load_or_create_token_at(&path).unwrap();
        if !running_as_root {
            assert_ne!(
                got, planted,
                "an untrusted (group-readable) token must be regenerated, not returned"
            );
            assert_eq!(
                got.len(),
                64,
                "the regenerated token is a fresh 64-hex value"
            );
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode & 0o077,
                0,
                "the regenerated token must be owner-only 0600 (got {mode:o})"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A trusted (owner-only `0600`, current-user-owned) pre-existing token is loaded AS-IS —
    /// never regenerated — so a legit token stays stable across runs (#501 residual).
    #[cfg(unix)]
    #[test]
    fn trusted_owner_only_token_file_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-trusted-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let existing = "a".repeat(64);
        std::fs::write(&path, &existing).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let got = load_or_create_token_at(&path).unwrap();
        assert_eq!(
            got, existing,
            "a trusted owner-only token must be loaded as-is, not regenerated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECURITY (#501): the control token grants full local control, so the created
    /// file MUST NOT be readable by other local users. On Unix that is a hard `0600`
    /// assertion (no group/other bits) — the CI-gated path (CI runs on Linux). On
    /// Windows the restriction is applied via `icacls` (asserted separately in a
    /// Windows-gated test / by the orchestrator's adversarial ACL check).
    #[cfg(unix)]
    #[test]
    fn created_token_file_is_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-perms-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        load_or_create_token_at(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "token must have NO group/other permission bits (got {mode:o})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The remedy hint names the concrete token path and, when the token is absent from
    /// the caller's perspective, tells them to start the node — never the old generic
    /// "<config_dir>" wording.
    #[test]
    fn control_token_remedy_names_a_concrete_path() {
        let remedy = control_token_remedy();
        assert!(
            remedy.contains("control token") || remedy.contains("control-token"),
            "remedy should mention the control token: {remedy}"
        );
        assert!(
            remedy.contains("dig-node")
                || remedy.contains("state dir")
                || remedy.contains('/')
                || remedy.contains('\\'),
            "remedy should name a path or command: {remedy}"
        );
    }

    /// #772 symptom 2 — the SERVICE-mints ⇄ CLI-reads round-trip: a token minted by the
    /// node-side writer at a path is read back byte-identically by the operator-side reader at
    /// the SAME path. This is the coupling the bug broke (service running yet CLI cannot read
    /// the token); a fresh mint must always be readable at its own path.
    #[test]
    fn service_mint_then_cli_read_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-roundtrip-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let minted = load_or_create_token_at(&path).unwrap();
        let read_back = read_token_readonly_at(&path).unwrap();
        assert_eq!(
            minted, read_back,
            "the CLI read must return the exact token the service minted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A genuinely-absent token reads as `NotFound` with the "no control token found" remedy that
    /// now ALSO names the stale-service reinstall recovery (#772).
    #[test]
    fn read_readonly_reports_absent_token_as_not_found() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-absent-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        let err = read_token_readonly_at(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let msg = err.to_string();
        assert!(msg.contains("no control token found"), "{msg}");
        assert!(
            msg.contains("reinstall") && msg.contains("STALE"),
            "the absent-token remedy must name the stale-service reinstall recovery: {msg}"
        );
    }

    /// #772 symptom 2 (the ACL split): a token present but UNREADABLE by the invoking user must
    /// map to `PermissionDenied` ("elevate / reinstall"), NEVER the misleading `NotFound` the old
    /// `path.exists()` classification produced. Unix mode-bit gated; skipped as root (root
    /// bypasses the mode bits).
    #[cfg(unix)]
    #[test]
    fn unreadable_token_maps_to_permission_denied_not_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "dig-node-token-denied-{}-{}",
            std::process::id(),
            line!()
        ));
        let path = dir.join(CONTROL_TOKEN_FILE);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "a".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let running_as_root = std::fs::read_to_string(&path).is_ok();
        if !running_as_root {
            let err = read_token_readonly_at(&path).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "an unreadable token must be PermissionDenied, not NotFound"
            );
            assert!(
                err.to_string().contains("NOT readable"),
                "the remedy must explain the token is present but unreadable: {err}"
            );
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
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
            "dig-node-pins-test-{}-{}",
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
        // This service's pin/upstream writes must NOT clobber dig-node's own keys
        // in the shared config.json (cache_cap_bytes, wc_project_id).
        let dir = std::env::temp_dir().join(format!(
            "dig-node-config-merge-test-{}-{}",
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
            "dig-node-upstream-test-{}-{}",
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
