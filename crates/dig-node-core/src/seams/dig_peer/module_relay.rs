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
use crate::seams::dig_peer::module_reshare::WarmOutcome;
use crate::Node;

/// Try to make this node able to serve `(store_hex, root_hex)` on `requestor`'s behalf, returning
/// whether the capsule is now in the local cache and may be read from.
///
/// Awaited, not spawned: the caller has a module window to answer RIGHT NOW, and the answer depends
/// on the pull. This is the store-and-forward cost, paid once per capsule — a second window of the
/// same capsule finds it cached and returns immediately.
///
/// Every refusal is silent and returns `false`; the caller's own `RESOURCE_UNAVAILABLE` then stands.
/// Never a silent success, and never an unbounded fetch: the pull is the ordinary
/// [`CapsuleWarmer`](super::CapsuleWarmer) one, byte-capped and chain-anchored, and it does NOT make
/// this node a holder ([`HolderClaim::Suppress`](super::module_reshare::HolderClaim)).
pub(crate) async fn relay_capsule(
    node: &Node,
    store_hex: &str,
    root_hex: &str,
    params: &Value,
    requestor: &RequestorId,
) -> bool {
    // (1) The requestor must ASK. Checked first because it is free and because it is the only gate
    //     whose absence means "this request never wanted a relay" rather than "this node refuses".
    if !proxy_requested(params) {
        return false;
    }
    let Some(content) = node.p2p_content() else {
        return false;
    };
    // (2) The OPERATOR must have opted in.
    if !content.onion_relay_enabled() {
        return false;
    }
    // (3) The requestor must be inside its PROXY-class allowance — the expensive-egress bucket.
    if !content.allow_proxy_fetch(requestor) {
        return false;
    }
    let Some(warmer) = content.capsule_warmer() else {
        // No warmer wired (the FFI/base path): there is no whole-capsule pull to drive, so there is
        // no relay. A read behaves identically with or without the leg.
        return false;
    };
    tracing::debug!(
        store = %super::serve_log::SafeId::new(store_hex),
        root = %super::serve_log::SafeId::new(root_hex),
        "module relay: pulling a capsule this node does not hold, on a requestor's behalf"
    );
    // `AlreadyHeld` is admitted alongside `Held` because a concurrent warm may have landed the
    // capsule between the caller's miss and this call — the question this function answers is "can the
    // window be read now?", not "did I personally pull it?".
    matches!(
        warmer.warm_relayed(store_hex, root_hex).await,
        WarmOutcome::Held { .. } | WarmOutcome::AlreadyHeld
    )
}
