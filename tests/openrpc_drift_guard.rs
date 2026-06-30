//! DRIFT GUARD (gap #129): the dig-companion method/error catalogue
//! (`meta::methods` / `meta::openrpc_document` / `meta::ErrorCode`) must stay in
//! sync with what the EMBEDDED dig-node (`dig_node::handle_rpc`) actually resolves.
//!
//! The catalogue had drifted from the implementation: the `dig.getCapsule` alias was
//! marked `served: local` though dig-node does NOT resolve it (it returns `-32601` →
//! relayed), and the upstream `-32004` ("resource not available at the requested
//! root") was uncatalogued. This test pins the catalogue to reality by DISPATCHING
//! each catalogued read method through the real `dig_node::handle_rpc` and asserting
//! that:
//!
//!   * every `served: "local"` method is RESOLVED by dig-node (never returns
//!     `-32601 method not found` — it returns a result or a method-specific error),
//!     and
//!   * every `served: "passthrough"` read method (and the `dig.getCapsule` alias)
//!     is NOT resolved by dig-node (returns `-32601`, which is the companion shell's
//!     cue to relay it to the upstream).
//!
//! If a future dig-node rev moves a method between local and passthrough — or the
//! catalogue mislabels one — this test fails, so the published OpenRPC can never
//! again silently describe a surface the node does not serve.
//!
//! Methods dispatched with deliberately empty/invalid params return their
//! param-validation error (e.g. `-32602`) BEFORE any network/chain I/O, so the test
//! is hermetic — no upstream is contacted. `dig.getContent` is the sole exception:
//! it is the default branch (never `-32601`) and proceeds to a local-or-proxy read,
//! so it is asserted by classification only (it is unambiguously the local read).
//! `control.*` methods are the shell's own surface (dispatched by the companion, not
//! dig-node) and are covered by the unit tests in `meta.rs`.

use dig_companion::meta::{self, ErrorCode};
use dig_node::{handle_rpc, Node};
use serde_json::json;
use std::sync::Arc;

/// Build a dig-node whose cache + §21 identity live in a throwaway tempdir, so the
/// test never reads or writes the real user cache / identity key. Env is read by
/// `Node::from_env` at construction; set it immediately before building.
fn ephemeral_node() -> Arc<Node> {
    let base = std::env::temp_dir().join(format!(
        "dig-companion-drift-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::env::set_var("DIG_NODE_CACHE", base.join("cache"));
    std::env::set_var("DIG_IDENTITY_DIR", base.join("identity"));
    Node::from_env()
}

/// Dispatch one method with empty params through the real dig-node and return the
/// numeric JSON-RPC error code, or `None` when dig-node returned a `result`.
async fn dispatch_error_code(node: &Node, method: &str) -> Option<i64> {
    let req = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} });
    let resp = handle_rpc(node, req).await;
    resp.get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_i64())
}

/// The companion-shell methods that `dig_node::handle_rpc` never sees (they are
/// answered by the companion's own server/control plane, not dispatched to the
/// node). Excluded from the live-dispatch sync check; covered by `meta.rs` units.
fn is_shell_only(name: &str) -> bool {
    name == "rpc.discover" || name.starts_with("control.")
}

#[tokio::test(flavor = "multi_thread")]
async fn local_methods_are_resolved_by_dig_node() {
    const METHOD_NOT_FOUND: i64 = -32601;
    let node = ephemeral_node();

    for m in meta::methods() {
        if is_shell_only(m.name) || m.served != "local" {
            continue;
        }
        // Skip the two local methods that reach the network with empty params (so the
        // test stays hermetic — no upstream contacted): dig.getContent is the default
        // branch (never -32601) and proceeds to a local-or-proxy read, and
        // cache.fetchAndCache attempts an upstream §21 sync. Both are asserted as
        // catalogued `local` by classification only (dig.getContent has its own test).
        if m.name == "dig.getContent" || m.name == "cache.fetchAndCache" {
            continue;
        }
        let code = dispatch_error_code(&node, m.name).await;
        assert_ne!(
            code,
            Some(METHOD_NOT_FOUND),
            "catalogue marks {} served=local, but dig-node returned -32601 \
             (method not found) — it does NOT resolve it locally; the catalogue \
             is drifted from handle_rpc",
            m.name
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn passthrough_methods_are_not_resolved_by_dig_node() {
    const METHOD_NOT_FOUND: i64 = -32601;
    let node = ephemeral_node();

    for m in meta::methods() {
        if is_shell_only(m.name) || m.served != "passthrough" {
            continue;
        }
        let code = dispatch_error_code(&node, m.name).await;
        assert_eq!(
            code,
            Some(METHOD_NOT_FOUND),
            "catalogue marks {} served=passthrough, but dig-node did NOT return \
             -32601 — it resolves it locally, so it must be served=local; the \
             catalogue is drifted from handle_rpc",
            m.name
        );
    }
}

/// dig.getContent is the canonical local read (the default branch of handle_rpc):
/// confirm the catalogue agrees so the classification asserted-by-exclusion above is
/// anchored to a real expectation.
#[test]
fn get_content_is_catalogued_local() {
    let m = meta::methods()
        .iter()
        .find(|m| m.name == "dig.getContent")
        .expect("dig.getContent in catalogue");
    assert_eq!(m.served, "local");
    assert!(!m.requires_auth);
}

/// The reconciled error catalogue carries the upstream `-32004` ("resource not
/// available at the requested root") that dig-node's §21 remote client recognizes
/// and the companion relays — previously undocumented — with the right origin and a
/// stable symbolic name, and it surfaces in the machine-readable catalogue JSON.
#[test]
fn reconciled_error_codes_are_catalogued_with_correct_origin() {
    assert_eq!(ErrorCode::ResourceNotAvailableAtRoot.code(), -32004);
    assert_eq!(
        ErrorCode::ResourceNotAvailableAtRoot.name(),
        "RESOURCE_NOT_AVAILABLE_AT_ROOT"
    );
    assert_eq!(ErrorCode::ResourceNotAvailableAtRoot.origin(), "upstream");

    let catalogue = meta::error_catalogue();
    let arr = catalogue.as_array().expect("error catalogue array");
    assert!(
        arr.iter()
            .any(|e| e["name"] == json!("RESOURCE_NOT_AVAILABLE_AT_ROOT")
                && e["code"] == json!(-32004)
                && e["origin"] == json!("upstream")),
        "error catalogue missing the reconciled -32004 RESOURCE_NOT_AVAILABLE_AT_ROOT"
    );
}

/// Every method the catalogue lists as a public read (`served` in {local,
/// passthrough}) carries `requires_auth: false`, and every `control.*` method is
/// `served: control` + `requires_auth: true` — a structural sanity check that the
/// reconciliation did not mislabel a served class.
#[test]
fn served_classes_are_well_formed() {
    for m in meta::methods() {
        match m.served {
            "local" | "passthrough" | "shell" => assert!(
                !m.requires_auth,
                "{} is a read/discovery method and must not require auth",
                m.name
            ),
            "control" => {
                assert!(m.requires_auth, "{} (control) must require auth", m.name);
                assert!(m.name.starts_with("control."));
            }
            other => panic!("{} has an unknown served class {other:?}", m.name),
        }
    }
}
