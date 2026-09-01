//! The one place this crate mints a JSON-RPC error, so every frame it emits carries the
//! canonical `data.code` + `data.origin` discriminators by construction.
//!
//! # Why this module exists
//!
//! The error taxonomy is OWNED by `dig-rpc-protocol` and adopted, never restated (`SYSTEM.md`).
//! Its canonical envelope is `{code, message, data:{code: UPPER_SNAKE, origin}}`, and the two
//! `data` fields are the entire point: a client branches on the stable machine code instead of
//! parsing a human message that may be reworded in any release.
//!
//! This crate used to frame errors as a bare `{code, message}`. That is not a narrower envelope,
//! it is a DIFFERENT one — a consumer written against the published types finds neither
//! discriminator and is forced back to prose, which is exactly what the taxonomy exists to
//! prevent (dig-node#340).
//!
//! # Why the mapping is a lookup rather than a table
//!
//! [`taxonomy_code`] resolves a numeric code by scanning [`ErrorCode::ALL`], so the machine code
//! and the origin are DERIVED from the contract crate at every call. A local `match` from integer
//! to `"UPPER_SNAKE"` would be a second copy of the taxonomy, and a second copy is what drifts —
//! the same failure this repo has already paid for twice in code-number collisions.
//!
//! # The codes this crate emits that the taxonomy does not declare
//!
//! `-32001` (an authorization refusal on the push surface, `seams::capsule::push_capsule`) is
//! occupied here and undeclared upstream; `SYSTEM.md` records it as reserved-by-occupancy. A
//! frame carrying it therefore gets NO `data` rather than an invented machine name: a fabricated
//! `data.code` is worse than an absent one, because a client would branch on a name that no
//! contract defines and that the owning crate may later assign a different meaning. Declaring it
//! is release-first work in `dig-rpc-protocol`, not a decision this consumer may take.

use dig_rpc_protocol::{ErrorCode, RpcError};
use serde_json::{json, Value};

/// The canonical [`ErrorCode`] for a numeric wire code, or `None` when this crate emits a number
/// the taxonomy does not declare.
pub(crate) fn taxonomy_code(code: i64) -> Option<ErrorCode> {
    ErrorCode::ALL
        .iter()
        .copied()
        .find(|c| i64::from(c.code()) == code)
}

/// The `error` OBJECT of a JSON-RPC failure — `{code, message, data:{code, origin}}` for any
/// declared code, and a bare `{code, message}` for one the taxonomy does not declare.
///
/// Both `data` fields come from `dig-rpc-protocol`'s own serialization of [`RpcError`], never
/// from a literal here, so they cannot drift from the contract.
pub(crate) fn error_object(code: i64, message: &str) -> Value {
    match taxonomy_code(code) {
        Some(known) => serde_json::to_value(RpcError::of(known, message))
            .unwrap_or_else(|_| json!({"code": code, "message": message})),
        None => json!({"code": code, "message": message}),
    }
}

/// A complete JSON-RPC 2.0 error RESPONSE echoing `id`.
pub(crate) fn error_frame(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": error_object(code, message)})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** a client can tell two DIFFERENT failures apart from `data.code` ALONE, without
    /// reading the numeric code and without parsing the message.
    ///
    /// The two chosen codes are the pair a client most needs to separate: a settled
    /// `RESOURCE_UNAVAILABLE` ("it is not here") against `CONTENT_MISS_INCONCLUSIVE` ("nobody
    /// established that it is not here"). Collapsing those is what turns one slow peer into proof
    /// that content is gone.
    ///
    /// Asserting merely that `data.code` is PRESENT would pass on any constant, so the assertion
    /// that carries the weight is the inequality plus the two exact names.
    #[test]
    fn two_failures_are_distinguishable_by_machine_code_alone() {
        let id = json!(1);
        let miss = crate::rpc_err(&id, -32004, "resource not available");
        let unsettled = crate::rpc_err(&id, -32017, "a hop never answered");

        let a = miss["error"]["data"]["code"].as_str().expect("data.code");
        let b = unsettled["error"]["data"]["code"]
            .as_str()
            .expect("data.code");

        assert_eq!(a, "RESOURCE_UNAVAILABLE");
        assert_eq!(b, "CONTENT_MISS_INCONCLUSIVE");
        assert_ne!(a, b, "the two failures must not share a branch key");
    }

    /// **Proves:** `data.origin` also SEPARATES the two, so a client routing by subsystem is not
    /// reading a constant either.
    ///
    /// A settled miss is the node's own read path; an unestablished absence is a peer-layer
    /// failure. A frame builder that hard-coded one origin would satisfy a presence check and
    /// fail this.
    #[test]
    fn origin_separates_a_node_failure_from_a_peer_failure() {
        let id = json!(1);
        let node = crate::rpc_err(&id, -32004, "resource not available");
        let peer = crate::rpc_err(&id, -32017, "a hop never answered");

        assert_eq!(node["error"]["data"]["origin"], json!("node"));
        assert_eq!(peer["error"]["data"]["origin"], json!("peer"));
    }

    /// **Proves:** the NEGATIVE the ticket asks for — a frame built the old way fails the new
    /// assertion, so the assertion is load-bearing rather than trivially true.
    ///
    /// This is the exact shape `rpc_err` emitted before this change.
    #[test]
    fn a_hand_built_frame_lacks_the_discriminators() {
        let old = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32004,"message":"x"}});
        assert!(old["error"]["data"]["code"].as_str().is_none());
        assert!(old["error"]["data"]["origin"].as_str().is_none());
    }

    /// **Proves:** an UNDECLARED code yields no `data` at all rather than a fabricated machine
    /// name — the honest gap, not an invented one.
    ///
    /// `-32001` is emitted by the push surface and is not in `ErrorCode::ALL`. Inventing a name
    /// for it here would publish a branch key no contract defines.
    #[test]
    fn an_undeclared_code_gets_no_fabricated_machine_code() {
        assert!(taxonomy_code(-32001).is_none());
        let frame = crate::rpc_err(&json!(1), -32001, "unauthorized push");
        assert_eq!(frame["error"]["code"], json!(-32001));
        assert!(
            frame["error"].get("data").is_none(),
            "an undeclared code must not carry an invented data.code"
        );
    }

    /// **Proves:** the numeric code and the machine code cannot disagree, for EVERY declared
    /// code — the drift this module exists to make unrepresentable.
    #[test]
    fn every_declared_code_round_trips_to_its_own_machine_name() {
        for known in ErrorCode::ALL {
            let frame = crate::rpc_err(&json!(1), i64::from(known.code()), "m");
            assert_eq!(frame["error"]["code"], json!(known.code()));
            assert_eq!(frame["error"]["data"]["code"], json!(known.machine_code()));
        }
    }
}
