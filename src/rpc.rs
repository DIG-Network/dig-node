//! The dig-node service's JSON-RPC surface — pure routing/normalisation, kept free
//! of I/O so it is unit-testable and is the single source of truth for dispatch.
//!
//! This service is a thin shell around digstore's `dig-node` read-path crate
//! (`digstore_node::handle_rpc`), which IS the rpc.dig.net-compatible local node the
//! native DIG Browser runs in-process: `dig.getContent` returns blind ciphertext +
//! a merkle inclusion proof + chunk lengths (local-first from cached `.dig` modules,
//! else proxied to the upstream), `dig.getAnchoredRoot` resolves the chain-anchored
//! tip root, and the `cache.*` methods configure the on-disk cache. The CALLER (the
//! extension / hub / browser) does the verify + decrypt locally — so this service
//! must mirror the read path's ciphertext contract exactly, NOT return plaintext.
//!
//! What this module owns is the small amount of *request shaping* the read path
//! needs: the extension always sends the canonical `{store_id, root, retrieval_key,
//! …}` params, but other callers may send a `urn` or `resource` form.
//! [`normalize_request`] maps those onto the field names the read path reads, so any
//! well-formed DIG request reaches the node, and everything else passes through
//! untouched.

use serde_json::{json, Value};

use crate::meta::ErrorCode;

/// How the dig-node service handles a given JSON-RPC method. Informational/
/// structural — dispatch itself is `digstore_node::handle_rpc`; this classification
/// drives request normalisation and keeps the routing intent documented and tested.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Route {
    /// `dig.getContent` / `dig.getCapsule` — verified content retrieval (returns
    /// ciphertext + proof + chunk_lens). The only methods whose params we shape.
    Content,
    /// `dig.getProof` — inclusion proof for a resource.
    Proof,
    /// `dig.getAnchoredRoot` — chain-anchored tip root.
    AnchoredRoot,
    /// `cache.getConfig` / `setCapBytes` / `clear` / `listCached` / `removeCached`
    /// / `fetchAndCache` — the on-disk cache config + manager surface.
    Cache,
    /// Anything else — relayed verbatim (the read path passes unknown methods
    /// through to the upstream, so this service stays a correct transparent proxy).
    Passthrough,
}

/// Classify a JSON-RPC method. PURE.
pub fn route_method(method: &str) -> Route {
    match method {
        "dig.getContent" | "dig.getCapsule" => Route::Content,
        "dig.getProof" => Route::Proof,
        "dig.getAnchoredRoot" => Route::AnchoredRoot,
        m if m.starts_with("cache.") => Route::Cache,
        _ => Route::Passthrough,
    }
}

/// A JSON-RPC error envelope carrying a CATALOGUED, stable error code. PURE.
///
/// The error object includes the numeric JSON-RPC `code` AND a `data.code` stable
/// UPPER_SNAKE symbolic name (+ `data.origin`) drawn from [`ErrorCode`], so an
/// agent branches on the symbolic name rather than scraping the human `message`.
/// This is the only way the dig-node shell mints an error — every shell error is
/// therefore catalogued and discoverable via `rpc.discover` / `/openrpc.json`.
pub fn rpc_error(id: Value, code: ErrorCode, message: impl Into<String>) -> Value {
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

/// Normalise a single JSON-RPC request object so dig-node sees the param names it
/// reads (`store_id`, `root`, `retrieval_key`). The common case — the extension's
/// `{store_id, root, retrieval_key, offset, length}` — passes through unchanged.
///
/// Adaptations, applied only for content/proof methods and only when the canonical
/// field is absent (never overwriting an explicit value):
///   * `storeId` → `store_id`
///   * `resource_key` / `resourceKey` → `retrieval_key` (a pre-hashed key)
///   * a `"latest"` (or empty) root is left as-is — the read path treats a non-64-hex
///     root as rootless and proxies, which is the correct behaviour for this service
///     (it has no chain client to resolve "latest" to a concrete root).
///
/// Returns the (possibly cloned-and-edited) request Value. PURE — no I/O.
pub fn normalize_request(mut req: Value) -> Value {
    let method = req
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    if !matches!(route_method(&method), Route::Content | Route::Proof) {
        return req;
    }
    let Some(params) = req.get_mut("params").and_then(|p| p.as_object_mut()) else {
        return req;
    };

    // storeId -> store_id (camelCase alias some callers use).
    if !params.contains_key("store_id") {
        if let Some(v) = params.get("storeId").cloned() {
            params.insert("store_id".into(), v);
        }
    }
    // resource_key / resourceKey -> retrieval_key, when no explicit retrieval_key.
    if !params.contains_key("retrieval_key") {
        if let Some(v) = params
            .get("resource_key")
            .or_else(|| params.get("resourceKey"))
            .cloned()
        {
            params.insert("retrieval_key".into(), v);
        }
    }

    req
}

/// Extract the JSON-RPC `id` (defaulting to `null`) so error envelopes echo it.
/// PURE.
pub fn request_id(req: &Value) -> Value {
    req.get("id").cloned().unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_content_methods() {
        assert_eq!(route_method("dig.getContent"), Route::Content);
        assert_eq!(route_method("dig.getCapsule"), Route::Content);
    }

    #[test]
    fn routes_proof_anchored_and_cache() {
        assert_eq!(route_method("dig.getProof"), Route::Proof);
        assert_eq!(route_method("dig.getAnchoredRoot"), Route::AnchoredRoot);
        assert_eq!(route_method("cache.getConfig"), Route::Cache);
        assert_eq!(route_method("cache.setCapBytes"), Route::Cache);
        assert_eq!(route_method("cache.clear"), Route::Cache);
        assert_eq!(route_method("cache.listCached"), Route::Cache);
    }

    #[test]
    fn routes_unknown_as_passthrough() {
        assert_eq!(route_method("dig.listCapsules"), Route::Passthrough);
        assert_eq!(route_method("dig.getManifest"), Route::Passthrough);
        assert_eq!(route_method(""), Route::Passthrough);
    }

    #[test]
    fn normalize_leaves_canonical_extension_request_untouched() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "dig.getContent",
            "params": { "store_id": "aa", "root": "bb", "retrieval_key": "cc", "offset": 0 }
        });
        assert_eq!(normalize_request(req.clone()), req);
    }

    #[test]
    fn normalize_maps_camelcase_store_id() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "dig.getContent",
            "params": { "storeId": "aa", "root": "bb", "retrieval_key": "cc" }
        });
        let out = normalize_request(req);
        assert_eq!(out["params"]["store_id"], json!("aa"));
    }

    #[test]
    fn normalize_maps_resource_key_to_retrieval_key() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "dig.getContent",
            "params": { "store_id": "aa", "root": "bb", "resource_key": "cc" }
        });
        let out = normalize_request(req);
        assert_eq!(out["params"]["retrieval_key"], json!("cc"));
    }

    #[test]
    fn normalize_never_overwrites_explicit_retrieval_key() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "dig.getContent",
            "params": { "store_id": "aa", "retrieval_key": "explicit", "resource_key": "other" }
        });
        let out = normalize_request(req);
        assert_eq!(out["params"]["retrieval_key"], json!("explicit"));
    }

    #[test]
    fn normalize_does_not_touch_non_content_methods() {
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "cache.getConfig",
            "params": { "storeId": "aa" }
        });
        let out = normalize_request(req.clone());
        // storeId is NOT promoted for a cache method.
        assert!(out["params"].get("store_id").is_none());
        assert_eq!(out, req);
    }

    #[test]
    fn request_id_defaults_to_null() {
        assert_eq!(request_id(&json!({"method": "x"})), Value::Null);
        assert_eq!(request_id(&json!({"id": 7})), json!(7));
    }

    #[test]
    fn rpc_error_carries_numeric_and_symbolic_code() {
        let env = rpc_error(json!(1), ErrorCode::InvalidRequest, "nope");
        assert_eq!(env["error"]["code"], json!(-32600));
        assert_eq!(env["error"]["data"]["code"], json!("INVALID_REQUEST"));
        assert_eq!(env["error"]["data"]["origin"], json!("shell"));
        assert_eq!(env["error"]["message"], json!("nope"));
        assert_eq!(env["id"], json!(1));
    }
}
