//! The MODULE-GRANULARITY relay leg (dig-node#276): serving a whole-`.dig` window to a requestor
//! that asked this node to fetch the capsule on its behalf.
//!
//! # What this is
//!
//! A requestor A wants a capsule held by C but cannot reach C's socket — C is behind a NAT A cannot
//! traverse, or A only ever learned of C through B. A asks B, with `proxy: true`. B does not hold the
//! capsule, so B pulls the WHOLE capsule from C over the ordinary chain-anchored, merkle-verified
//! whole-capsule path ([`CapsuleWarmer`](super::CapsuleWarmer)) and then answers A's module windows
//! from its own cache, byte-identically to a genuine holder. Bytes flow `A <- B <- C`, and **A never
//! learns C's address**.
//!
//! This is the whole-`.dig` twin of the resource-granularity relay that already ships on
//! `dig.fetchRange` ([`crate::download::NodeContent::miss_outcome`], leg 2). The module path had no
//! miss branch at all: it answered `RESOURCE_UNAVAILABLE` unconditionally, which is why requirement 4
//! of the recursive-download epic — content streaming back THROUGH a hop — did not exist at the
//! granularity a `.dig` download actually uses.
//!
//! # What this deliberately is NOT
//!
//! * **One hop, not a circuit.** `A -> B -> C`, and no further. B knows exactly who asked and for
//!   what. This buys the requestor HOLDER-ADDRESS privacy, not sender anonymity. Multi-hop layered
//!   circuits are `dig-onion`'s job; nothing here discharges that crate's SPEC.
//! * **Store-and-forward, not pass-through.** B completes and VERIFIES its pull before serving the
//!   first byte. That costs first-byte latency on a cold hop and buys reuse of the one whole-capsule
//!   path that is already chain-anchored and already audited.
//! * **Capsule bytes ONLY.** A `.dig` is public-by-content-address and the hop is handed
//!   `(store_id, root)` and never a retrieval key, so it relays ciphertext it cannot read — exactly
//!   what a DHT-discovered holder sees. No directed message, no chat, no mail and no
//!   recipient-specific request may ever be routed through this path; those stay end-to-end sealed to
//!   the recipient key (NC-1 / §5.4). Widening this path's payload is an NC-1 review, not an
//!   extension.
//!
//! # The three gates, each independently sufficient to refuse
//!
//! 1. **The requestor asked.** `params.proxy == true`. Automatic relaying is off; a requestor that
//!    can reach holders itself should, and does.
//! 2. **The operator opted in.** [`crate::download::ONION_RELAY_ENV`], default OFF. This leg spends a
//!    THIRD party's bandwidth, so it is not gated more loosely than the legs that spend only this
//!    node's.
//! 3. **The requestor is within its PROXY allowance** — the separate, tighter bucket
//!    (dig_ecosystem#2189), never the cheap-lookup one. Relaying a whole capsule is the costliest
//!    thing a stranger can ask this node to do.
//!
//! A refusal at any gate leaves the pre-existing `RESOURCE_UNAVAILABLE` answer exactly as it was, so
//! the requestor stays free to ask a different hop — a hop's "not found" may always be a lie (NC-12).

use serde_json::Value;

use crate::download::proxy_requested;
use crate::rate_limit::RequestorId;
use crate::Node;

/// What a relay ask can honestly be told about `(store_hex, root_hex)`.
///
/// Three outcomes, because the two that used to be one — *this node will not relay* and *this node is
/// relaying and has not finished* — carry OPPOSITE instructions to the requestor. Collapsing them into
/// a single `false` is what made a cold relayed fetch look like a settled miss while the hop was in
/// the middle of answering it (dig-node#333).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayStatus {
    /// The capsule is in this node's cache and its windows may be read now.
    Landed,
    /// A relay pull is RUNNING and has staged this many bytes so far. The requestor may wait.
    ///
    /// The byte count is this node's own measurement of its own staging file, offered as a liveness
    /// signal so a waiting requestor can tell progress from a stall. It says nothing about
    /// correctness: every one of those bytes still has to pass the requestor's merkle verification
    /// against the chain-anchored root, exactly as a direct holder's would (NC-12).
    Pending { staged_bytes: u64 },
    /// No relay: the requestor did not ask, the operator did not opt in, the requestor is outside its
    /// proxy allowance, or this build has no capsule warmer. Indistinguishable to the requestor from
    /// a plain miss, deliberately — a refusal must not narrate which gate refused.
    Refused,
}

/// How long a hop waits for its own relay pull before answering [`RelayStatus::Pending`].
///
/// Sized to be comfortably INSIDE the requestor's first descriptor rung (5 s), so a capsule that
/// lands quickly is still answered in one round trip and the pre-#333 behaviour is preserved for the
/// case that already worked. It must never grow toward the length of a bulk transfer: a hop that
/// holds a requestor's stream for minutes is the held-slot cost the descriptor ladder exists to bound,
/// and lengthening it here would simply move that cost rather than remove it.
const RELAY_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// Try to make this node able to serve `(store_hex, root_hex)` on `requestor`'s behalf.
///
/// The pull runs in the BACKGROUND and this call waits only [`RELAY_GRACE`] for it. That is the whole
/// of dig-node#333: awaiting a 135 MB third-party transfer inside the requestor's descriptor ask meant
/// the ask always expired first, so the relay completed minutes after the only caller who wanted it
/// had given up. A hop that ACKs instead of blocking lets the requestor wait on this node's PROGRESS
/// rather than on a wall clock it has no way to size.
///
/// Every refusal is silent and returns [`RelayStatus::Refused`]; the caller's own
/// `RESOURCE_UNAVAILABLE` then stands. Never a silent success, and never an unbounded fetch: the pull
/// is the ordinary [`CapsuleWarmer`](super::CapsuleWarmer) one, byte-capped and chain-anchored, and it
/// does NOT make this node a holder ([`HolderClaim::Suppress`](super::module_reshare::HolderClaim)).
pub(crate) async fn relay_capsule(
    node: &Node,
    store_hex: &str,
    root_hex: &str,
    params: &Value,
    requestor: &RequestorId,
) -> RelayStatus {
    // (1) The requestor must ASK. Checked first because it is free and because it is the only gate
    //     whose absence means "this request never wanted a relay" rather than "this node refuses".
    if !proxy_requested(params) {
        return RelayStatus::Refused;
    }
    let Some(content) = node.p2p_content() else {
        return RelayStatus::Refused;
    };
    // (2) The OPERATOR must have opted in.
    if !content.onion_relay_enabled() {
        return RelayStatus::Refused;
    }
    // (3) The requestor must be inside its PROXY-class allowance — the expensive-egress bucket.
    if !content.allow_proxy_fetch(requestor) {
        return RelayStatus::Refused;
    }
    let Some(warmer) = content.capsule_warmer().cloned() else {
        // No warmer wired (the FFI/base path): there is no whole-capsule pull to drive, so there is
        // no relay. A read behaves identically with or without the leg.
        return RelayStatus::Refused;
    };
    tracing::debug!(
        store = %super::serve_log::SafeId::new(store_hex),
        root = %super::serve_log::SafeId::new(root_hex),
        "module relay: pulling a capsule this node does not hold, on a requestor's behalf"
    );
    // Re-entrant by construction: `WarmRegistry` admits one warm per generation, so a second requestor
    // — or this same requestor polling — joins the running pull rather than starting a rival one.
    //
    // SPAWNED, not awaited, and that changes who bears the cost. An awaited pull died with the
    // request; a spawned one outlives it, so a requestor that gives up leaves this node still
    // pulling. The registry's cap is GLOBAL and SHARED with this node's own `spawn_capsule_warm`,
    // so an abandoning peer can hold a warm slot that a local read wanted. Bounded (the cap), opt-in
    // (gate 2) and allowance-limited (gate 3) — but a real cost of running the leg, recorded on
    // `CapsuleWarmer::warm_relayed` as well so it is visible from either end.
    super::module_reshare::spawn_relayed_capsule_warm(
        std::sync::Arc::clone(&warmer),
        store_hex.to_string(),
        root_hex.to_string(),
    );
    if warmer.await_landing(store_hex, root_hex, RELAY_GRACE).await {
        return RelayStatus::Landed;
    }
    RelayStatus::Pending {
        staged_bytes: warmer.staged_bytes(store_hex, root_hex),
    }
}
