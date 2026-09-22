//! Control-token PAIRING (#280) — how an MV3 browser extension, which cannot read
//! the local `<config_dir>/control-token` file, obtains a SCOPED, revocable
//! credential to drive `control.*` mutations over the 9778 browser surface.
//!
//! # Why
//!
//! The static control token ([`crate::control`]) is a local capability FILE: a
//! same-host CLI / native app reads it and authorizes. A sandboxed extension cannot
//! read a file, so before this it could only call `control.status` and the read
//! plane. Pairing adds a consented handshake that yields the extension its OWN token
//! WITHOUT ever exposing the master token, gated by LOCAL operator approval.
//!
//! # Flow (compare-codes consent, à la Bluetooth pairing)
//!
//! 1. **OPEN** `pairing.request { client_name }` → the node mints a random
//!    `pairing_id` + a short numeric `pairing_code` + a `redemption_secret`, stores
//!    it PENDING (with a TTL), and returns
//!    `{ pairing_id, pairing_code, redemption_secret, expires_ms }`. The extension
//!    DISPLAYS the code and keeps the secret to itself — `pairing_id` is a HANDLE the
//!    operator may see and type in argv; `redemption_secret` is the credential that
//!    redeems the token, and it is returned only here, to the requesting client.
//! 2. The local operator runs `dig-node pair` (which reads the master token — proving
//!    local-machine control), sees the pending request with its code + `client_name`,
//!    CONFIRMS the code matches what the extension shows, and approves via
//!    `control.pairing.approve { pairing_id }` (MASTER-token only) — `pairing_id`
//!    alone is the correct handle here, because it is not the redeeming credential.
//! 3. On approve the node mints a fresh scoped token, PERSISTS it to
//!    `<config_dir>/paired-tokens.json`, and marks the pending entry approved.
//! 4. **OPEN** `pairing.poll { pairing_id, redemption_secret }` → once approved
//!    returns `{ status:"approved", token }`; the token is delivered ONCE (the
//!    pending entry is then consumed). A poll missing the secret is refused; a poll
//!    with the wrong secret reads exactly like an unknown id. The extension stores
//!    the token and presents it as `X-Dig-Control-Token` on `control.*` calls.
//!
//! # Security properties
//!
//! - **The value the operator handles never redeems a credential.** `pairing_id`
//!   appears in argv (`dig-node pair approve <pairing_id>`) and in `list()`, so it
//!   must not double as the bearer that redeems the minted token. `pairing.poll`
//!   requires a separate `redemption_secret`, returned only in the `pairing.request`
//!   result, never serialized by `list()` or `approve()`'s result, and compared
//!   constant-time; a wrong secret reads identically to an unknown id.
//! - **A pending request is never displaced.** `pairing.request` REFUSES at the
//!   pending-slot cap rather than evicting an older entry to make room — a request
//!   the node already accepted is a commitment. A pairing-specific token bucket
//!   additionally bounds a burst of requests (independent of the cap, and it never
//!   touches `pairing.poll`), so a flood cannot grow the pending set unbounded or
//!   starve a legitimate pairing already underway.
//! - **Loopback bind (enforced)** — the server binds loopback by default; a non-loopback
//!   `DIG_NODE_HOST` is refused unless `DIG_NODE_ALLOW_REMOTE=1` (#1662). Defense-in-depth
//!   beneath the token gate (same boundary as `control.*`), not the primary control.
//! - **Consent = the master token.** APPROVE requires the master token (a local FILE
//!   read), so only the machine's operator can grant a pairing; the compare-codes
//!   step defeats a concurrent rogue request (a visited page's) being approved by
//!   mistake — the operator only approves the `pairing_id` whose code matches the one
//!   the legitimate extension shows.
//! - **The token can't be stolen by a page.** The `pairing.poll` response carrying
//!   the token is readable only by an allowed CORS origin (`chrome-extension://…`); a
//!   foreign web origin's `fetch` is CORS-blocked from reading it (and blocked at
//!   preflight from even sending a `control.*` token header).
//! - **Scoped.** A paired token authorizes `control.*` MUTATIONS but NOT the MASTER
//!   tier (see [`crate::control::requires_master_token`]) — pairing administration
//!   (`list`/`approve`/`revoke`), so it can neither mint more tokens nor hide/revoke
//!   itself, and `chiaPeers.add`/`.remove`, so it cannot grant itself chain authority
//!   that SURVIVES the revocation below. The scope is per CAPABILITY, not per plane:
//!   the Sage-parity aliases of those two methods (`add_peer`/`remove_peer`) resolve the
//!   same tier through [`crate::wallet_authz`], on both HTTP and WS, because they reach
//!   the same writer.
//! - **Revocable.** `dig-node pair revoke <id>` removes it; the gate rejects it at
//!   once (the paired-token file is consulted per request).
//! - **Constant-time comparison** for every token check (no timing oracle).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::control::{control_error, control_ok, ct_eq};
use crate::meta::ErrorCode;

/// The paired-token store file, beside `control-token` in the machine-wide state dir
/// (#501, [`crate::state::state_dir`]) — NOT the per-user config dir — so the daemon
/// and the operator CLI resolve the SAME store regardless of OS user.
pub const PAIRED_TOKENS_FILE: &str = "paired-tokens.json";

/// How long a pending pairing request stays valid before it must be re-requested.
const PAIRING_TTL_MS: u64 = 5 * 60 * 1000;

/// Cap on concurrently-pending requests, so a flood of `pairing.request` calls
/// (e.g. from a rogue page) cannot grow the in-memory map without bound. At the cap
/// a request is REFUSED, never displaced (#3191/B1): a pending request the node
/// already accepted is a commitment, and quietly dropping it to serve a later
/// caller is the node partly writing someone else's outcome — the same discipline
/// [`MAX_CLIENT_NAME`] already applies to a name.
const MAX_PENDING: usize = 32;

/// Capacity of the pairing-specific request-rate bucket (#3191/B2), independent of
/// [`MAX_PENDING`]. `pairing.request` has no requestor identity to key a limiter on
/// (loopback callers are indistinguishable), so this bucket is process-wide. It
/// bounds a BURST of `pairing.request` calls, not the read plane `pairing.poll` is
/// on: each admitted request holds one of `MAX_PENDING` scarce slots for up to
/// `PAIRING_TTL_MS`, which is exactly the asymmetry the open control-read limiter
/// declines to claim for itself.
const PAIRING_BUCKET_CAPACITY: usize = 8;

/// How often the bucket in [`PendingPairings`] refills by one token.
const PAIRING_BUCKET_REFILL_MS: u64 = 10_000;

/// The longest `client_name` this node will ACCEPT, in characters.
///
/// It is a REFUSAL bound, not a clip (dig-node#346). Silently truncating an attacker-supplied
/// label is a forgery the node performs on the attacker's behalf: pad a hostile name with
/// characters that spend the budget while rendering as nothing, and the node's own clip produces
/// a short, trusted-looking name for the operator to approve. Refusing an over-long request is
/// visible to the caller and invents nothing.
///
/// The stored value stays BYTE-VERBATIM; neutralisation happens at render time
/// ([`crate::untrusted_text::render_untrusted`]), because only the display is a lie surface.
pub const MAX_CLIENT_NAME: usize = 64;

/// Current unix time in milliseconds (0 on a clock error — only affects TTL math).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A pending pairing awaiting local operator approval.
#[derive(Clone)]
struct Pending {
    /// The 6-digit compare-codes value shown to BOTH the extension and the operator.
    code: String,
    /// The requester-supplied label (e.g. "DIG Chrome Extension"), for the operator.
    client_name: String,
    created_ms: u64,
    expires_ms: u64,
    /// Set on approval: the minted scoped token, delivered ONCE via `pairing.poll`.
    approved_token: Option<String>,
    /// The sole bearer that redeems the token via `pairing.poll` (#3191/W1). Returned
    /// ONLY in the `pairing.request` result — never by `list()`, never by `approve()`'s
    /// result, never logged — so it stays known only to the client that requested it.
    /// `pairing_id` is a HANDLE the operator may type in argv; this is the credential.
    redemption_secret: String,
}

/// The in-memory set of pending pairings, keyed by `pairing_id` (a 32-hex handle
/// returned to the requester). Shared behind a `Mutex` in `AppState`.
pub struct PendingPairings {
    map: HashMap<String, Pending>,
    /// Token-bucket state for the `pairing.request` rate bound (#3191/B2).
    bucket_tokens: f64,
    /// The clock reading the bucket was last topped up at.
    bucket_refilled_ms: u64,
}

impl Default for PendingPairings {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            bucket_tokens: PAIRING_BUCKET_CAPACITY as f64,
            bucket_refilled_ms: 0,
        }
    }
}

impl PendingPairings {
    /// Drop expired entries. Called opportunistically on every operation so the map
    /// never accumulates stale requests.
    fn prune(&mut self, now: u64) {
        self.map
            .retain(|_, p| p.approved_token.is_some() || now <= p.expires_ms);
    }

    /// Admit one `pairing.request` against the bucket, refilling lazily off the
    /// caller-supplied clock first. `now` is threaded in (never `Instant::now()`
    /// internally) so a test can drive time without sleeping.
    fn take_request_token(&mut self, now: u64) -> bool {
        let elapsed_ms = now.saturating_sub(self.bucket_refilled_ms);
        if elapsed_ms > 0 {
            let refill = elapsed_ms as f64 / PAIRING_BUCKET_REFILL_MS as f64;
            self.bucket_tokens = (self.bucket_tokens + refill).min(PAIRING_BUCKET_CAPACITY as f64);
            self.bucket_refilled_ms = now;
        }
        if self.bucket_tokens >= 1.0 {
            self.bucket_tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// -- OPEN methods (no token) --------------------------------------------------

/// OPEN `pairing.request { client_name }` — create a pending pairing and return
/// `{ pairing_id, pairing_code, expires_ms }`. The extension displays the code for
/// the operator to confirm.
pub fn request(pending: &Mutex<PendingPairings>, id: Value, params: &Value) -> Value {
    let client_name: String = params
        .get("client_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown controller")
        .to_string();
    if client_name.chars().count() > MAX_CLIENT_NAME {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            format!(
                concat!(
                    "client_name must be at most {MAX_CLIENT_NAME} characters; this request is ",
                    "refused rather than shortened, because a name the node shortened is a name the ",
                    "node partly wrote"
                ),
                MAX_CLIENT_NAME = MAX_CLIENT_NAME
            ),
        );
    }

    let created = now_ms();
    let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
    g.prune(created);

    // #3191/B2: a pairing-specific burst bound, checked BEFORE the cap and BEFORE
    // minting anything. It fires well under MAX_PENDING for a tight flood, and never
    // touches `pairing.poll` (the read plane), so an ordinary interval-spaced pairing
    // sequence is unaffected.
    if !g.take_request_token(created) {
        return control_error(
            id,
            ErrorCode::PairingPendingLimited,
            "pairing requests to this node are bounded per interval, because each one holds a \
             pending slot until it is approved or expires. Back off briefly and retry.",
        );
    }

    // #3191/B1: a pending request the node already accepted is a commitment; refuse
    // rather than displace it to make room for a later one (never evict).
    if g.map.len() >= MAX_PENDING {
        return control_error(
            id,
            ErrorCode::PairingPendingLimited,
            "this node is already holding the maximum number of pending pairing requests. A \
             request that is already pending is never displaced to make room for a later one; \
             retry once one has been approved or has expired (within five minutes).",
        );
    }

    // Fail CLOSED: the pairing id + code + redemption secret gate the consent step, so
    // if the OS CSPRNG is unavailable refuse the request rather than mint guessable
    // pairing material (§7.3).
    let (pairing_id, code, redemption_secret) = match (
        crate::control::random_hex(16), // 32-hex
        crate::control::random_pairing_code(),
        crate::control::random_hex(32), // 64-hex — #3191/W1, never the operator's id
    ) {
        (Ok(pairing_id), Ok(code), Ok(redemption_secret)) => (pairing_id, code, redemption_secret),
        _ => {
            return control_error(
                id,
                ErrorCode::ControlError,
                "the OS CSPRNG is unavailable; refusing to start pairing",
            )
        }
    };
    let expires = created + PAIRING_TTL_MS;

    g.map.insert(
        pairing_id.clone(),
        Pending {
            code: code.clone(),
            client_name,
            created_ms: created,
            expires_ms: expires,
            approved_token: None,
            redemption_secret: redemption_secret.clone(),
        },
    );

    control_ok(
        id,
        json!({
            "pairing_id": pairing_id,
            "pairing_code": code,
            "redemption_secret": redemption_secret,
            "expires_ms": expires,
        }),
    )
}

/// OPEN `pairing.poll { pairing_id, redemption_secret }` — report the pairing's
/// state: `{ status: "pending" | "approved" | "expired" | "unknown", token? }`. On
/// `approved` the minted token is returned and the pending entry is consumed (the
/// token is delivered exactly once).
///
/// `redemption_secret` is REQUIRED (#3191/W1): the value the operator handles
/// (`pairing_id`) is a handle, not a credential — the token is delivered only to the
/// client `pairing.request` returned the secret to. A missing field is a SHAPE error
/// (reveals nothing about any id) and gets a named, diagnosable refusal; a WRONG
/// secret is answered identically to an unknown id (constant-time compare), so
/// `poll` cannot become an existence oracle over the id space.
pub fn poll(pending: &Mutex<PendingPairings>, id: Value, params: &Value) -> Value {
    let pairing_id = params
        .get("pairing_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let redemption_secret = params
        .get("redemption_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if redemption_secret.is_empty() {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "pairing.poll requires params.redemption_secret — the value pairing.request \
             returned to the requesting client. The paired token is delivered only to the \
             client that made the request, so the pairing_id alone does not redeem it.",
        );
    }
    let now = now_ms();

    let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
    // Resolve the REQUESTED id BEFORE pruning, so an expired-but-not-yet-swept entry
    // reports `expired` exactly once (rather than being swept to `unknown`).
    let resp = match g.map.get(&pairing_id).cloned() {
        None => control_ok(id, json!({ "status": "unknown" })),
        Some(p) if !ct_eq(redemption_secret, &p.redemption_secret) => {
            // Wrong secret reads exactly like an unknown id — never removed, never
            // distinguishable, so a guesser learns nothing about which ids exist.
            control_ok(id, json!({ "status": "unknown" }))
        }
        Some(p) => {
            if let Some(token) = p.approved_token {
                g.map.remove(&pairing_id); // deliver once
                control_ok(id, json!({ "status": "approved", "token": token }))
            } else if now > p.expires_ms {
                g.map.remove(&pairing_id);
                control_ok(id, json!({ "status": "expired" }))
            } else {
                control_ok(id, json!({ "status": "pending" }))
            }
        }
    };
    g.prune(now); // opportunistically sweep OTHER stale entries
    resp
}

// -- GATED admin methods (MASTER token only) ----------------------------------

/// GATED `control.pairing.list` — the operator's approve view: pending requests
/// (each with its `pairing_code` + `client_name`) AND the issued controller tokens
/// (id + client_name + created, NEVER the token value).
pub fn list(pending: &Mutex<PendingPairings>, state_dir: &Path, id: Value) -> Value {
    let now = now_ms();
    let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
    g.prune(now);
    let mut pending_list: Vec<Value> = g
        .map
        .iter()
        .filter(|(_, p)| p.approved_token.is_none())
        .map(|(pid, p)| {
            json!({
                "pairing_id": pid,
                "pairing_code": p.code,
                "client_name": p.client_name,
                "created_ms": p.created_ms,
                "expires_ms": p.expires_ms,
            })
        })
        .collect();
    pending_list.sort_by(|a, b| a["created_ms"].as_u64().cmp(&b["created_ms"].as_u64()));

    let tokens: Vec<Value> = load_paired_tokens(&paired_tokens_path(state_dir))
        .iter()
        .map(|t| json!({ "id": t.id, "client_name": t.client_name, "created_ms": t.created_ms }))
        .collect();

    control_ok(id, json!({ "pending": pending_list, "tokens": tokens }))
}

/// GATED `control.pairing.approve { pairing_id }` — mint + persist a scoped token,
/// mark the pending entry approved (so the requester's `pairing.poll` returns it).
pub fn approve(
    pending: &Mutex<PendingPairings>,
    state_dir: &Path,
    id: Value,
    params: &Value,
) -> Value {
    let pairing_id = params
        .get("pairing_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let now = now_ms();

    let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
    g.prune(now);
    let client_name =
        match g.map.get(&pairing_id) {
            None => return control_error(
                id,
                ErrorCode::InvalidParams,
                "no such pending pairing (it expired, was already approved, or the id is wrong)",
            ),
            Some(p) if p.approved_token.is_some() => {
                return control_error(id, ErrorCode::InvalidParams, "pairing already approved")
            }
            Some(p) => p.client_name.clone(),
        };

    // Fail CLOSED: a paired token is authorization material, so if the OS CSPRNG is
    // unavailable refuse to issue one rather than mint a guessable token (§7.3).
    let (token, record_id) = match (
        crate::control::random_hex(32),
        crate::control::random_hex(8),
    ) {
        (Ok(token), Ok(id)) => (token, id), // 64-hex token + 16-hex short id for revoke
        _ => {
            return control_error(
                id,
                ErrorCode::ControlError,
                "the OS CSPRNG is unavailable; refusing to mint a paired token",
            )
        }
    };
    let record = PairedToken {
        id: record_id,
        token: token.clone(),
        client_name: client_name.clone(),
        created_ms: now,
    };
    if let Err(e) = append_paired_token(&paired_tokens_path(state_dir), &record) {
        return control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to persist the paired token: {e}"),
        );
    }
    // Only mark approved AFTER the token is durably persisted, so a poll can never
    // return a token the gate wouldn't accept on the next process start.
    if let Some(p) = g.map.get_mut(&pairing_id) {
        p.approved_token = Some(token);
    }
    control_ok(
        id,
        json!({ "approved": true, "client_name": client_name, "token_id": record.id }),
    )
}

/// GATED `control.pairing.revoke { token_id }` — remove an issued token; the gate
/// rejects it immediately (the file is consulted per request).
pub fn revoke(state_dir: &Path, id: Value, params: &Value) -> Value {
    let token_id = params
        .get("token_id")
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if token_id.is_empty() {
        return control_error(
            id,
            ErrorCode::InvalidParams,
            "control.pairing.revoke requires params.token_id",
        );
    }
    match revoke_paired_token(&paired_tokens_path(state_dir), token_id) {
        Ok(removed) => control_ok(id, json!({ "revoked": removed, "token_id": token_id })),
        Err(e) => control_error(
            id,
            ErrorCode::ControlError,
            format!("failed to revoke: {e}"),
        ),
    }
}

// -- Paired-token store (persisted) -------------------------------------------

/// One issued controller credential. Serialized into `paired-tokens.json`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedToken {
    /// Short id for `list` / `revoke` (the token value is never listed).
    pub id: String,
    /// The 64-hex bearer token the controller presents as `X-Dig-Control-Token`.
    pub token: String,
    /// The controller label captured at pairing time.
    pub client_name: String,
    pub created_ms: u64,
}

/// Path to the paired-token store within the machine-wide state dir (#501). `state_dir`
/// is [`crate::state::state_dir`] (the same dir the control token lives in).
pub fn paired_tokens_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PAIRED_TOKENS_FILE)
}

/// Load the issued paired tokens (missing/blank/malformed file → empty).
pub fn load_paired_tokens(path: &Path) -> Vec<PairedToken> {
    let Ok(txt) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&txt) else {
        return Vec::new();
    };
    v.get("tokens")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| serde_json::from_value::<PairedToken>(e.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Persist the token list atomically + owner-only. The state dir is created with a
/// restrictive ACL (#501) — the paired tokens are as sensitive as the master token.
fn save_paired_tokens(path: &Path, tokens: &[PairedToken]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        crate::state::ensure_dir_restricted(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(&json!({ "tokens": tokens })).unwrap_or_default();
    crate::control::write_atomic(path, &bytes)?;
    crate::control::restrict_permissions(path);
    Ok(())
}

/// Append one issued token to the store.
fn append_paired_token(path: &Path, record: &PairedToken) -> std::io::Result<()> {
    let mut tokens = load_paired_tokens(path);
    tokens.push(record.clone());
    save_paired_tokens(path, &tokens)
}

/// Remove a token by id. Returns whether one was removed (idempotent).
///
/// This touches the token store and NOTHING else — deliberately. Revocation cannot undo a side
/// effect that already outlived the token, so the tier rule
/// ([`crate::control::requires_master_token`]) keeps a paired token away from the methods that
/// produce one; it does not try to chase them afterwards. Concretely: this must NOT strip
/// user-managed Chia peers. A compromised app's "cleanup" would then silently un-trust the nodes
/// an operator deliberately configured, which is a worse failure than the one it would be
/// papering over — the escalation is made unreachable at the gates instead, on every plane a PAIRED
/// TOKEN can present itself on: the `control.*` gate ([`crate::control::requires_master_token`]) and
/// the Sage-parity wallet gate ([`crate::wallet_authz`]), each over both `POST /{method}` and `/ws`.
/// The enumeration is the load-bearing part of the sentence, not decoration: this claim was once
/// made of the control plane alone while `POST /add_peer` handed a paired token the same row, and a
/// sentence that says "unreachable" without naming the routes is what stopped the next reader
/// checking the second one.
///
/// The loopback wallet mTLS listener (`dig_wallet::sage::transport`) dispatches the parity surface
/// with NO token gate; it is outside this claim because its credential is a different one (the
/// shared client cert), which a paired token cannot supply. That plane is currently unreachable by
/// anything — the cert is generated per run and never persisted — but persisting it, which its own
/// comment anticipates, would make an ungated wallet surface live.
fn revoke_paired_token(path: &Path, token_id: &str) -> std::io::Result<bool> {
    let mut tokens = load_paired_tokens(path);
    let before = tokens.len();
    tokens.retain(|t| t.id != token_id);
    let removed = tokens.len() != before;
    if removed {
        save_paired_tokens(path, &tokens)?;
    }
    Ok(removed)
}

/// Does `presented` match ANY issued paired token (constant-time)? This is the
/// gate's paired-token path (beside the master-token check). Loaded fresh per call
/// so a revoke takes effect on the very next request.
pub fn is_paired_token(path: &Path, presented: &str) -> bool {
    // Constant-time over EVERY token so the check time does not reveal which (if any)
    // token matched. `any()` would early-out; the fold never short-circuits.
    load_paired_tokens(path)
        .iter()
        .fold(false, |acc, t| ct_eq(presented, &t.token) | acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves (dig-node#346):** an over-long `client_name` is REFUSED, not shortened.
    ///
    /// The ingest used to `.take(64)`, which is an unmarked truncation on the OPEN,
    /// unauthenticated `pairing.request` — so an attacker could pad a hostile label with budget
    /// -consuming characters and have the NODE produce a short, trusted-looking name for the
    /// operator to approve. Refusing is the only answer that invents nothing.
    ///
    /// The at-bound case is asserted alongside, because a bound tested only from above cannot
    /// distinguish "refuses over-long" from "refuses everything".
    #[test]
    fn an_over_long_client_name_is_refused_rather_than_silently_shortened() {
        let pending = Mutex::new(PendingPairings::default());

        let at_bound = "n".repeat(MAX_CLIENT_NAME);
        let ok = request(&pending, json!(1), &json!({ "client_name": at_bound }));
        assert!(
            ok.get("result").is_some(),
            "a name exactly at the bound must be accepted: {ok}"
        );

        let too_long = "n".repeat(MAX_CLIENT_NAME + 1);
        let refused = request(&pending, json!(2), &json!({ "client_name": too_long }));
        assert_eq!(
            refused["error"]["data"]["code"],
            json!(ErrorCode::InvalidParams.name()),
            "an over-long name must be refused: {refused}"
        );
        let message = refused["error"]["message"].as_str().unwrap();
        assert!(
            message.contains("refused rather than shortened"),
            "the refusal must say why it is a refusal: {refused}"
        );
        // dig-node#526: this is the ONE user-visible site of the lost-continuation
        // class -- prove the fix through the JSON-RPC error path a real client
        // receives, not against the source literal, and that the join left no
        // stray multi-space run where the `\` continuation used to be.
        assert!(
            message.contains("node partly wrote"),
            "the full refusal sentence must survive the join: {refused}"
        );
        assert!(
            !message.contains("  "),
            "a run of consecutive spaces means a continuation lost its backslash: {message:?}"
        );
    }

    /// **Proves:** the accepted `client_name` is stored BYTE-VERBATIM.
    ///
    /// Neutralisation belongs at the render, never at the store: a value that is ever compared or
    /// used as an identity must not be quietly rewritten, and rewriting at ingest would also make
    /// the stored value disagree with what the requester believes it sent.
    #[test]
    fn an_accepted_client_name_is_stored_verbatim() {
        let pending = Mutex::new(PendingPairings::default());
        // Contains characters the RENDERER must neutralise; the STORE must not.
        let raw = "app\u{200b}\u{202e}name";
        let resp = request(&pending, json!(1), &json!({ "client_name": raw }));
        let pairing_id = resp["result"]["pairing_id"].as_str().unwrap().to_string();

        let g = pending.lock().unwrap();
        let stored = &g.map.get(&pairing_id).expect("pending entry").client_name;
        assert_eq!(stored, raw, "the stored label must be byte-verbatim");
    }

    /// A unique temp STATE dir (#501: the paired-token store now lives in the state
    /// dir, not beside a `config.json`). Returns `(state_dir, state_dir)` so both
    /// tuple bindings point at the dir a test seeds + cleans.
    /// The tree is OWNED by the returned guard: `TempDir`'s `Drop` removes it, including on
    /// an unwind, so a failing assertion cannot leak it (dig-node#370). `tempfile`'s random
    /// component also subsumes the hand-rolled pid + counter name, which repeated across runs.
    fn tmp_config() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("dig-node-pairing-")
            .tempdir()
            .expect("a scratch dir")
    }

    fn pending() -> Mutex<PendingPairings> {
        Mutex::new(PendingPairings::default())
    }

    #[test]
    fn request_returns_id_code_and_expiry() {
        let p = pending();
        let resp = request(
            &p,
            json!(1),
            &json!({ "client_name": "DIG Chrome Extension" }),
        );
        let r = &resp["result"];
        assert_eq!(r["pairing_id"].as_str().unwrap().len(), 32, "32-hex id");
        assert_eq!(r["pairing_code"].as_str().unwrap().len(), 6, "6-digit code");
        assert!(r["expires_ms"].as_u64().unwrap() > now_ms());
    }

    #[test]
    fn poll_unknown_then_pending_then_approved_delivers_token_once() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();

        // Unknown id → status unknown (secret present but irrelevant to a nonexistent id).
        let unknown = poll(
            &p,
            json!(1),
            &json!({ "pairing_id": "deadbeef", "redemption_secret": "x".repeat(64) }),
        );
        assert_eq!(unknown["result"]["status"], json!("unknown"));

        // Request → pending.
        let req = request(&p, json!(2), &json!({ "client_name": "ext" }));
        let pid = req["result"]["pairing_id"].as_str().unwrap().to_string();
        let secret = req["result"]["redemption_secret"].as_str().unwrap().to_string();
        let pend = poll(
            &p,
            json!(3),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );
        assert_eq!(pend["result"]["status"], json!("pending"));

        // Approve (master path) → the token is minted + persisted.
        let ap = approve(&p, config, json!(4), &json!({ "pairing_id": pid }));
        assert_eq!(ap["result"]["approved"], json!(true));
        let token_id = ap["result"]["token_id"].as_str().unwrap().to_string();

        // First poll after approve → approved + token.
        let ok = poll(
            &p,
            json!(5),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );
        assert_eq!(ok["result"]["status"], json!("approved"));
        let token = ok["result"]["token"].as_str().unwrap().to_string();
        assert_eq!(token.len(), 64, "64-hex scoped token");

        // The token is a valid paired token; a wrong one is not.
        assert!(is_paired_token(&paired_tokens_path(config), &token));
        assert!(!is_paired_token(&paired_tokens_path(config), "not-a-token"));

        // Delivered ONCE: a second poll no longer knows the id.
        let again = poll(
            &p,
            json!(6),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );
        assert_eq!(again["result"]["status"], json!("unknown"));

        // Revoke → the token stops authorizing.
        let rv = revoke(config, json!(7), &json!({ "token_id": token_id }));
        assert_eq!(rv["result"]["revoked"], json!(true));
        assert!(!is_paired_token(&paired_tokens_path(config), &token));
    }

    #[test]
    fn approve_unknown_pairing_is_invalid_params() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();
        let resp = approve(&p, config, json!(1), &json!({ "pairing_id": "nope" }));
        assert_eq!(
            resp["error"]["code"],
            json!(ErrorCode::InvalidParams.code())
        );
    }

    #[test]
    fn list_shows_pending_and_issued_tokens() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();
        let req = request(&p, json!(1), &json!({ "client_name": "ext-A" }));
        let pid = req["result"]["pairing_id"].as_str().unwrap().to_string();
        let secret = req["result"]["redemption_secret"].as_str().unwrap().to_string();

        // Before approval: one pending, no tokens.
        let l1 = list(&p, config, json!(2));
        assert_eq!(l1["result"]["pending"].as_array().unwrap().len(), 1);
        assert_eq!(l1["result"]["pending"][0]["client_name"], json!("ext-A"));
        assert_eq!(l1["result"]["tokens"].as_array().unwrap().len(), 0);

        approve(&p, config, json!(3), &json!({ "pairing_id": pid.clone() }));
        // consume the pending via poll
        poll(
            &p,
            json!(4),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );

        // After: no pending, one issued token (value never listed).
        let l2 = list(&p, config, json!(5));
        assert_eq!(l2["result"]["pending"].as_array().unwrap().len(), 0);
        let tokens = l2["result"]["tokens"].as_array().unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0]["client_name"], json!("ext-A"));
        assert!(
            tokens[0].get("token").is_none(),
            "token value is never listed"
        );
    }

    #[test]
    fn expired_pending_polls_as_expired_then_unknown() {
        let p = pending();
        // Insert a manually-expired pending entry.
        {
            let mut g = p.lock().unwrap();
            g.map.insert(
                "abc".into(),
                Pending {
                    code: "000000".into(),
                    client_name: "old".into(),
                    created_ms: 0,
                    expires_ms: 1, // long past
                    approved_token: None,
                    redemption_secret: "s".repeat(64),
                },
            );
        }
        let params = json!({ "pairing_id": "abc", "redemption_secret": "s".repeat(64) });
        let expired = poll(&p, json!(1), &params);
        assert_eq!(expired["result"]["status"], json!("expired"));
        // And it's been consumed.
        let after = poll(&p, json!(2), &params);
        assert_eq!(after["result"]["status"], json!("unknown"));
    }

    /// **Proves:** the value the operator handles (`pairing_id`) does not by itself redeem the
    /// minted token. `pairing.poll` requires the `redemption_secret` returned only to the
    /// requesting client; a poll that omits it is refused, and the entry survives so the correct
    /// poll (with the secret) still delivers the token afterwards.
    #[test]
    fn a_poll_without_the_requesters_redemption_secret_does_not_deliver_the_token() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();

        let req = request(&p, json!(1), &json!({ "client_name": "ext" }));
        let pid = req["result"]["pairing_id"].as_str().unwrap().to_string();
        let secret = req["result"]["redemption_secret"]
            .as_str()
            .expect("pairing.request must return a redemption_secret")
            .to_string();

        approve(&p, config, json!(2), &json!({ "pairing_id": pid.clone() }));

        // Poll with the operator-visible id ALONE — no secret.
        let bare = poll(&p, json!(3), &json!({ "pairing_id": pid.clone() }));
        assert_eq!(
            bare["error"]["data"]["code"],
            json!(ErrorCode::InvalidParams.name()),
            "a poll missing the redemption secret must be refused, not answered: {bare}"
        );
        assert!(
            bare.get("result").is_none(),
            "a poll missing the secret must never carry a result, let alone a token: {bare}"
        );

        // The entry must have SURVIVED the failed poll: the correct poll still delivers it.
        let ok = poll(
            &p,
            json!(4),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );
        assert_eq!(ok["result"]["status"], json!("approved"));
        assert!(ok["result"]["token"].as_str().is_some());
    }

    /// **Proves:** a WRONG redemption secret is answered identically to an unknown id — it must
    /// not become an oracle over the id space. The entry survives, and a subsequent correct poll
    /// still delivers the token.
    #[test]
    fn a_poll_with_a_wrong_redemption_secret_is_indistinguishable_from_an_unknown_id() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();

        let req = request(&p, json!(1), &json!({ "client_name": "ext" }));
        let pid = req["result"]["pairing_id"].as_str().unwrap().to_string();
        let secret = req["result"]["redemption_secret"].as_str().unwrap().to_string();
        approve(&p, config, json!(2), &json!({ "pairing_id": pid.clone() }));

        let wrong = poll(
            &p,
            json!(3),
            &json!({ "pairing_id": pid.clone(), "redemption_secret": "0".repeat(64) }),
        );
        let fabricated = poll(
            &p,
            json!(3),
            &json!({ "pairing_id": "f".repeat(32), "redemption_secret": "0".repeat(64) }),
        );
        assert_eq!(wrong, json!({ "jsonrpc": "2.0", "id": 3, "result": { "status": "unknown" } }));
        assert_eq!(
            wrong["result"], fabricated["result"],
            "a wrong secret must read exactly like an unknown id: {wrong} vs {fabricated}"
        );

        let ok = poll(
            &p,
            json!(4),
            &json!({ "pairing_id": pid, "redemption_secret": secret }),
        );
        assert_eq!(ok["result"]["status"], json!("approved"));
    }

    /// **Proves:** the redemption secret never appears anywhere it isn't strictly needed —
    /// `list()` and `approve()`'s own result must not carry it.
    #[test]
    fn the_redemption_secret_is_never_serialized_by_list_or_approve() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();
        let req = request(&p, json!(1), &json!({ "client_name": "ext" }));
        let pid = req["result"]["pairing_id"].as_str().unwrap().to_string();

        let l = list(&p, config, json!(2));
        let pending_entry = &l["result"]["pending"][0];
        assert!(
            pending_entry.get("redemption_secret").is_none(),
            "list() must never carry the redemption secret: {l}"
        );

        let ap = approve(&p, config, json!(3), &json!({ "pairing_id": pid }));
        assert!(
            ap["result"].get("redemption_secret").is_none(),
            "approve()'s result must never carry the redemption secret: {ap}"
        );
    }

    /// **Proves:** a pending request the node already accepted is never displaced to make room
    /// for a later one. Flooding `pairing.request` past the slot cap leaves the FIRST entry
    /// pending and redeemable, and the surplus requests are refused with `PAIRING_PENDING_LIMITED`.
    #[test]
    fn a_pending_request_is_never_displaced_by_a_later_request() {
        let p = pending();
        let first = request(&p, json!(0), &json!({ "client_name": "first" }));
        let first_id = first["result"]["pairing_id"].as_str().unwrap().to_string();
        let first_secret = first["result"]["redemption_secret"].as_str().unwrap().to_string();

        let mut saw_limited = false;
        for i in 1..(MAX_PENDING as i64 + 8) {
            let r = request(&p, json!(i), &json!({ "client_name": "flood" }));
            if r.get("error").is_some() {
                assert_eq!(r["error"]["data"]["code"], json!("PAIRING_PENDING_LIMITED"));
                saw_limited = true;
            }
        }
        assert!(saw_limited, "the surplus requests past the cap must be refused");

        let still_pending = poll(
            &p,
            json!(999),
            &json!({ "pairing_id": first_id, "redemption_secret": first_secret }),
        );
        assert_eq!(
            still_pending["result"]["status"],
            json!("pending"),
            "the first-accepted pending request must never be displaced: {still_pending}"
        );
    }

    /// **Proves:** the third defect — approved-but-unpolled entries never age out of `prune()`, so
    /// the cap must stop the map growing even when every held entry is already approved. Filling
    /// the map with 32 approved entries and requesting one more must refuse, not grow the map.
    #[test]
    fn a_pending_map_at_capacity_of_approved_entries_does_not_grow() {
        let scratch = tmp_config();
        let config = scratch.path();
        let p = pending();
        for i in 0..MAX_PENDING {
            let r = request(&p, json!(i as i64), &json!({ "client_name": "c" }));
            let pid = r["result"]["pairing_id"].as_str().unwrap().to_string();
            approve(&p, config, json!(1000 + i as i64), &json!({ "pairing_id": pid }));
        }
        assert_eq!(p.lock().unwrap().map.len(), MAX_PENDING);

        let refused = request(&p, json!(9999), &json!({ "client_name": "one-more" }));
        assert!(refused.get("error").is_some(), "at cap the request must be refused: {refused}");
        assert_eq!(
            p.lock().unwrap().map.len(),
            MAX_PENDING,
            "the map must not grow past MAX_PENDING even when every held entry is approved"
        );
    }

    /// **Proves:** a burst of `pairing.request` calls is bounded by the pairing-specific token
    /// bucket, independently of the pending-slot cap (this fires well before `MAX_PENDING`).
    #[test]
    fn a_burst_of_pairing_requests_is_bounded_by_the_pairing_slot_budget() {
        let p = pending();
        let mut saw_limited = false;
        for i in 0..(PAIRING_BUCKET_CAPACITY as i64 + 4) {
            let r = request(&p, json!(i), &json!({ "client_name": "burst" }));
            if r.get("error").is_some() {
                assert_eq!(r["error"]["data"]["code"], json!("PAIRING_PENDING_LIMITED"));
                saw_limited = true;
            }
        }
        assert!(saw_limited, "a tight burst must eventually be refused by the bucket");
    }

    /// **Proves:** the pairing-slot budget bounds a BURST, and the fix does not recreate the
    /// failure `control_ingress_admits` exists to avoid: an ordinary operator pairing sequence
    /// (a handful of requests, spaced by the refill interval) is never refused.
    #[test]
    fn a_normal_operator_pairing_sequence_is_never_refused() {
        let p = pending();
        for i in 0..5 {
            let r = request(&p, json!(i), &json!({ "client_name": "ext" }));
            assert!(
                r.get("result").is_some(),
                "an ordinary, interval-spaced pairing request must never be refused: {r}"
            );
            {
                let mut g = p.lock().unwrap();
                g.bucket_tokens = PAIRING_BUCKET_CAPACITY as f64;
            }
        }
    }

    #[test]
    fn load_paired_tokens_tolerates_missing_and_malformed() {
        let scratch = tmp_config();
        let config = scratch.path();
        let path = paired_tokens_path(config);
        assert!(load_paired_tokens(&path).is_empty(), "missing file → empty");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_paired_tokens(&path).is_empty(), "malformed → empty");
    }
}
