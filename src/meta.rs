//! Self-describing discovery surface for the dig-node service — the machine-readable
//! "what am I, what do I speak, how do I fail" contract an agent can introspect
//! WITHOUT out-of-band knowledge.
//!
//! This module is the single source of truth for:
//!
//! * [`build_info`] — service name + version + git commit + embedded dig-node
//!   read-path version (the `GET /version` body).
//! * [`methods`] — the JSON-RPC method catalogue (drives `rpc.discover`, `/health`,
//!   and `/.well-known/dig-node.json`).
//! * [`ErrorCode`] — the catalogued, stable, machine-readable error codes on the
//!   JSON-RPC/wire boundary (UPPER_SNAKE symbolic strings + the numeric JSON-RPC
//!   code), with the companion-shell vs proxied-upstream distinction.
//! * [`openrpc_document`] — the OpenRPC 3.0 spec for the node's RPC surface.
//! * [`well_known_document`] — `/.well-known/dig-node.json` (addr + cache + the
//!   method/spec/error pointers an agent discovers first).
//!
//! Everything else in the crate (the server, the CLI `--json` output) renders these
//! definitions; nothing re-declares a method name, error code, or version string.

use serde_json::{json, Value};

/// Service identity reported everywhere. `dig-node` is the canonical, user-facing
/// name for the local node (renamed from `dig-companion`, per SYSTEM.md → canonical
/// terminology). The binary/crate name stays `dig-companion` for install stability,
/// but the *service* an agent discovers identifies itself as `dig-node`.
pub const SERVICE_NAME: &str = "dig-node";

/// The companion binary version (Cargo package version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The git commit the binary was built from (captured by `build.rs`), or
/// `"unknown"` when built outside a git checkout. Lets an agent correlate a
/// running node back to an exact source revision.
pub const GIT_SHA: &str = env!("DIG_COMPANION_GIT_SHA");

/// The embedded dig-node read-path version: the digstore git ref the `dig-node`
/// crate is pinned to (the same local-first node the native DIG Browser runs
/// in-process). Currently the #95/#96 Pass A commit (shared `.dig` cache: atomic
/// content-addressed writes + cross-process lock + the additive
/// `cache.getConfig` `cache_dir`/`shared` fields) — no release tag contains it yet,
/// so this is the short `rev`. Kept in sync with the `rev`/`tag` on the `dig-node`
/// git dependency in `Cargo.toml`.
pub const DIG_NODE_VERSION: &str = "b2632c4";

/// The DIG read protocol the node speaks (the rpc.dig.net §21 JSON-RPC read
/// contract). Bumped only when the wire contract changes.
pub const PROTOCOL: &str = "21";

/// One JSON-RPC method the node exposes, with where it is served and a one-line
/// description — the unit of the discoverable method catalogue.
pub struct MethodInfo {
    /// The JSON-RPC method name (e.g. `dig.getContent`).
    pub name: &'static str,
    /// Where the method is resolved: `local` = answered by the embedded dig-node
    /// (local-first, blind-fetch+verify+decrypt+cache), `passthrough` = relayed
    /// verbatim to the upstream DIG RPC, `shell` = answered by the companion shell
    /// itself (discovery methods), `control` = the CONTROL/admin surface answered by
    /// the shell, loopback-only AND gated behind the local control token.
    pub served: &'static str,
    /// Human/agent one-liner describing what the method does.
    pub summary: &'static str,
    /// Whether the method requires the local control token (the `control.*`
    /// surface). Read/discovery methods are `false`; mutating/management control
    /// methods are `true`. Surfaced in the catalogue + OpenRPC so a controller
    /// learns the auth requirement without trial and error.
    pub requires_auth: bool,
}

/// The full JSON-RPC method catalogue. Single source of truth for `rpc.discover`,
/// the `/health` `methods` array, and `/.well-known/dig-node.json`. Ordered most-
/// to least commonly driven.
pub fn methods() -> &'static [MethodInfo] {
    &[
        MethodInfo {
            name: "dig.getContent",
            served: "local",
            summary: "Verified retrieval: blind ciphertext + Merkle inclusion proof \
                      + chunk lengths (local-first from cache, else proxied).",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.getCapsule",
            served: "local",
            summary: "Alias of dig.getContent for a capsule (storeId:rootHash).",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.getAnchoredRoot",
            served: "local",
            summary: "The store's chain-anchored tip root (DataStore singleton lineage).",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.getConfig",
            served: "local",
            summary: "On-disk cache config: { cap_bytes, used_bytes }.",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.setCapBytes",
            served: "local",
            summary: "Set the on-disk cache size cap (floored at 64 MiB).",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.clear",
            served: "local",
            summary: "Delete all locally cached DIG content.",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.listCached",
            served: "local",
            summary: "List cached capsules (storeId:rootHash).",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.removeCached",
            served: "local",
            summary: "Remove one cached capsule.",
            requires_auth: false,
        },
        MethodInfo {
            name: "cache.fetchAndCache",
            served: "local",
            summary: "Pre-fetch and cache a capsule.",
            requires_auth: false,
        },
        MethodInfo {
            name: "rpc.discover",
            served: "shell",
            summary: "Return this node's OpenRPC document (method/error discovery).",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.getProof",
            served: "passthrough",
            summary: "Inclusion proof for a resource — relayed verbatim to the upstream.",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.listCapsules",
            served: "passthrough",
            summary: "List a store's capsules — relayed verbatim to the upstream.",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.getManifest",
            served: "passthrough",
            summary: "A capsule's manifest — relayed verbatim to the upstream.",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.getCollection",
            served: "passthrough",
            summary: "Public collection facts (creator DID, item count, uniform royalty) \
                      for a set of NFT launcher ids — relayed verbatim to the upstream.",
            requires_auth: false,
        },
        MethodInfo {
            name: "dig.listCollectionItems",
            served: "passthrough",
            summary: "A paginated page of a collection's NFT items resolved to their \
                      CURRENT on-chain owner + royalty + CHIP-0007 metadata — relayed \
                      verbatim to the upstream.",
            requires_auth: false,
        },
        // -- CONTROL / admin surface (loopback-only + local-token gated) ----------
        // The DIG Browser "My Node" controller drives these to MANAGE the node.
        // Every `control.*` method requires the local control token (requires_auth).
        MethodInfo {
            name: "control.status",
            served: "control",
            summary: "Rich node status: running, version, uptime, cache, upstream, \
                      hosted-store count, §21 sync capability.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.config.get",
            served: "control",
            summary: "Node config: bound loopback addr/port, cache dir + shared flag, \
                      upstream, §21 identity present.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.config.setUpstream",
            served: "control",
            summary: "Set the upstream DIG RPC (DIG_RPC_UPSTREAM); persisted, takes \
                      effect on next node start (requires_restart).",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.cache.get",
            served: "control",
            summary: "Cache view: cap_bytes, used_bytes, dir, shared.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.cache.setCap",
            served: "control",
            summary: "Set the on-disk cache size cap in bytes (floored at 64 MiB).",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.cache.clear",
            served: "control",
            summary: "Delete all locally cached DIG content.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.hostedStores.list",
            served: "control",
            summary: "List hosted/pinned stores: each store's pinned flag + its cached \
                      capsules (storeId:rootHash), sizes, last-used.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.hostedStores.pin",
            served: "control",
            summary: "Pin a store (storeId[:rootHash]): record it in the pin registry \
                      and pre-fetch+cache the capsule via §21 sync.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.hostedStores.unpin",
            served: "control",
            summary: "Unpin a store: remove it from the pin registry and evict its \
                      cached capsule(s).",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.hostedStores.status",
            served: "control",
            summary: "Per-store status: pinned flag, cached capsules, total bytes.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.sync.status",
            served: "control",
            summary: "§21 sync status: whether authenticated whole-store sync is \
                      available (a §21 identity is loaded) + pinned-store coverage.",
            requires_auth: true,
        },
        MethodInfo {
            name: "control.sync.trigger",
            served: "control",
            summary: "Trigger a §21 sync for a capsule (storeId + root); reports \
                      NOT_SUPPORTED if no §21 identity / not eligible.",
            requires_auth: true,
        },
    ]
}

/// Just the method names, for the compact `methods` array in `/health` and the
/// well-known document.
pub fn method_names() -> Vec<&'static str> {
    methods().iter().map(|m| m.name).collect()
}

/// The catalogued, stable error codes the node emits on the JSON-RPC/wire boundary.
///
/// Each variant carries a numeric JSON-RPC `code` AND a stable UPPER_SNAKE symbolic
/// `name` — agents branch on the symbolic name (never on prose). The companion owns
/// the `-320xx` shell range (errors it mints itself); codes proxied from
/// dig-node/upstream are catalogued separately so a client can tell a local-shell
/// failure from an upstream one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// `-32700` — request body was not valid JSON.
    ParseError,
    /// `-32600` — the request was not a single JSON-RPC object (e.g. a batch
    /// array, which the node does not support). Companion-shell error.
    InvalidRequest,
    /// `-32601` — method not found (dig-node's cue to passthrough; surfaced to the
    /// client only when the upstream also rejects it). Boundary code.
    MethodNotFound,
    /// `-32602` — invalid params (e.g. missing store_id / urn). From dig-node.
    InvalidParams,
    /// `-32000` — the companion shell failed to dispatch the request to the node.
    /// Companion-shell error.
    DispatchFailed,
    /// `-32010` — the blind-passthrough relay to the upstream DIG RPC failed
    /// (unreachable / non-JSON). Companion-shell error distinguishing a local
    /// proxy failure from an upstream-returned JSON-RPC error.
    UpstreamError,
    /// `-32020` — a `control.*` (CONTROL/admin) method was called without a valid
    /// local control token. The control surface is loopback-only AND locally
    /// authorized: a same-host controller (the DIG Browser "My Node" UI) must read
    /// the node's control token from its config dir and present it. Read methods
    /// are NOT gated; only the mutating/management control namespace is. Shell error.
    Unauthorized,
    /// `-32021` — a control operation the embedded dig-node cannot perform on this
    /// build (e.g. whole-store §21 sync when no §21 identity is loaded, or a feature
    /// the pinned crate revision does not expose). Reported with this STABLE code
    /// rather than a generic failure so a controller can branch on "not supported"
    /// vs a transient error. Shell error.
    NotSupported,
    /// `-32022` — a `control.*` operation failed at runtime (e.g. could not write
    /// the pin registry / config, or the cache op errored). Distinct from
    /// `INVALID_PARAMS` (bad input) and `NOT_SUPPORTED` (capability absent). Shell.
    ControlError,
}

impl ErrorCode {
    /// The numeric JSON-RPC error code.
    pub const fn code(self) -> i64 {
        match self {
            ErrorCode::ParseError => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::DispatchFailed => -32000,
            ErrorCode::UpstreamError => -32010,
            ErrorCode::Unauthorized => -32020,
            ErrorCode::NotSupported => -32021,
            ErrorCode::ControlError => -32022,
        }
    }

    /// The stable UPPER_SNAKE symbolic name an agent branches on. Never derived
    /// from the human message.
    pub fn name(self) -> &'static str {
        match self {
            ErrorCode::ParseError => "PARSE_ERROR",
            ErrorCode::InvalidRequest => "INVALID_REQUEST",
            ErrorCode::MethodNotFound => "METHOD_NOT_FOUND",
            ErrorCode::InvalidParams => "INVALID_PARAMS",
            ErrorCode::DispatchFailed => "DISPATCH_FAILED",
            ErrorCode::UpstreamError => "UPSTREAM_ERROR",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::NotSupported => "NOT_SUPPORTED",
            ErrorCode::ControlError => "CONTROL_ERROR",
        }
    }

    /// Where the error originates: `shell` = minted by the companion shell,
    /// `boundary` = the dig-node/upstream method-not-found cue, `upstream` =
    /// proxied from the upstream DIG RPC / dig-node.
    pub fn origin(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest
            | ErrorCode::DispatchFailed
            | ErrorCode::UpstreamError
            | ErrorCode::Unauthorized
            | ErrorCode::NotSupported
            | ErrorCode::ControlError
            | ErrorCode::ParseError => "shell",
            ErrorCode::MethodNotFound => "boundary",
            ErrorCode::InvalidParams => "upstream",
        }
    }

    /// A one-line description for the catalogue.
    pub fn description(self) -> &'static str {
        match self {
            ErrorCode::ParseError => "Request body was not valid JSON.",
            ErrorCode::InvalidRequest => {
                "Request was not a single JSON-RPC object (batch arrays are not supported)."
            }
            ErrorCode::MethodNotFound => "Method is not resolved locally or by the upstream.",
            ErrorCode::InvalidParams => "Invalid or missing method parameters.",
            ErrorCode::DispatchFailed => "The node failed to dispatch the request.",
            ErrorCode::UpstreamError => {
                "The blind-passthrough relay to the upstream DIG RPC failed."
            }
            ErrorCode::Unauthorized => {
                "A control.* method was called without a valid local control token."
            }
            ErrorCode::NotSupported => {
                "The requested control operation is not supported on this node build."
            }
            ErrorCode::ControlError => "A control operation failed at runtime.",
        }
    }

    /// Every catalogued code, for the error-catalogue document.
    pub fn all() -> &'static [ErrorCode] {
        &[
            ErrorCode::ParseError,
            ErrorCode::InvalidRequest,
            ErrorCode::MethodNotFound,
            ErrorCode::InvalidParams,
            ErrorCode::DispatchFailed,
            ErrorCode::UpstreamError,
            ErrorCode::Unauthorized,
            ErrorCode::NotSupported,
            ErrorCode::ControlError,
        ]
    }
}

/// The CANONICAL cache directory dig-node uses, resolved from the SAME env
/// contract dig-node itself reads (`DIG_NODE_CACHE`, else
/// `%LOCALAPPDATA%`/`$HOME` + `DigNode/cache`). This is the *intended* shared dir —
/// the same path the DIG Browser's in-process node uses, so omitting
/// `DIG_NODE_CACHE` shares ONE cache between the standalone service and the browser
/// (see [`crate::config`] → "Shared `.dig` cache").
///
/// dig-node keeps its effective resolver private (it may fall back to a
/// process-private dir when the canonical one is unwritable — surfaced as
/// [`cache_shared`]`== false`); the companion mirrors the canonical-path logic to
/// surface it in `/health` and the well-known document for operator/agent
/// discoverability. The AUTHORITATIVE effective dir + shared flag are available on
/// the `cache.getConfig` RPC (the `cache_dir`/`shared` fields dig-node returns).
pub fn cache_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    std::env::var("DIG_NODE_CACHE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let root = std::env::var("LOCALAPPDATA")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(root).join("DigNode").join("cache")
        })
}

/// Whether dig-node's EFFECTIVE cache dir is the shared canonical one (`true`) or a
/// process-private fallback because the canonical dir was unwritable (`false`).
/// Delegates to dig-node's resolver ([`dig_node::cache_dir_is_shared`]) so the
/// value is authoritative — the companion never re-implements the writability
/// probe. Surfaced additively in `/health` + the well-known document (#96).
pub fn cache_shared() -> bool {
    dig_node::cache_dir_is_shared()
}

/// The `GET /version` body: service identity + build provenance + the embedded
/// read-path version, so an agent can fingerprint exactly what is running.
pub fn build_info() -> Value {
    json!({
        "service": SERVICE_NAME,
        "version": VERSION,
        "commit": GIT_SHA,
        "dig_node_version": DIG_NODE_VERSION,
        "protocol": PROTOCOL,
    })
}

/// The error catalogue as machine-readable JSON: every code's numeric value,
/// symbolic name, origin, and description. Embedded in the OpenRPC `errors` and
/// surfaced under `/.well-known/dig-node.json`.
pub fn error_catalogue() -> Value {
    Value::Array(
        ErrorCode::all()
            .iter()
            .map(|e| {
                json!({
                    "code": e.code(),
                    "name": e.name(),
                    "origin": e.origin(),
                    "message": e.description(),
                })
            })
            .collect(),
    )
}

/// The method catalogue as JSON, used by `rpc.discover` summaries, `/health`, and
/// the well-known document.
fn methods_json() -> Value {
    Value::Array(
        methods()
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "served": m.served,
                    "summary": m.summary,
                    "requires_auth": m.requires_auth,
                })
            })
            .collect(),
    )
}

/// `/.well-known/dig-node.json` — the first thing an agent fetches: service
/// identity, the loopback addr it serves on, the cache dir, the method catalogue,
/// the error catalogue, and pointers to the richer specs (OpenRPC, health,
/// version). `addr` and the cache stats are supplied by the caller (they depend on
/// the running config / live cache).
pub fn well_known_document(addr: &str, upstream: &str, cap_bytes: u64, used_bytes: u64) -> Value {
    json!({
        "service": SERVICE_NAME,
        "version": VERSION,
        "commit": GIT_SHA,
        "dig_node_version": DIG_NODE_VERSION,
        "protocol": PROTOCOL,
        "addr": addr,
        "upstream": upstream,
        "cache": {
            "dir": cache_dir().display().to_string(),
            "cap_bytes": cap_bytes,
            "used_bytes": used_bytes,
            "shared": cache_shared(),
        },
        "rpc": {
            "endpoint": "/",
            "discover": "rpc.discover",
            "openrpc": "/openrpc.json",
        },
        "endpoints": {
            "health": "/health",
            "version": "/version",
            "well_known": "/.well-known/dig-node.json",
            "openrpc": "/openrpc.json",
        },
        "methods": methods_json(),
        "errors": error_catalogue(),
    })
}

/// The OpenRPC 3.0 document describing the node's JSON-RPC surface. Generated from
/// the [`methods`] catalogue and [`ErrorCode`] enum so it cannot drift from what
/// the node actually serves. Served at `GET /openrpc.json` and returned by the
/// `rpc.discover` method. Schemas are intentionally permissive (the chunk/proof
/// wire shapes are owned by the digstore dig RPC, whose canonical OpenRPC lives in
/// docs.dig.net) — this document's job is method/param/error DISCOVERY.
pub fn openrpc_document() -> Value {
    let method_objs: Vec<Value> = methods()
        .iter()
        .map(|m| {
            // Control methods document the local-auth requirement in the description
            // and via the machine-readable `x-requires-auth` extension, so a
            // controller learns the gate from the spec rather than by trial.
            let auth_note = if m.requires_auth {
                " CONTROL method: requires the local control token (loopback-only + \
                  locally authorized — present it as the X-Dig-Control-Token header or \
                  params._control_token; read it from <config_dir>/control-token)."
            } else {
                ""
            };
            json!({
                "name": m.name,
                "summary": m.summary,
                "description": format!("{}{}", m.summary, auth_note),
                "tags": [{ "name": m.served }],
                "x-requires-auth": m.requires_auth,
                "params": [
                    {
                        "name": "params",
                        "description": "Method parameters (object). See docs.dig.net for the canonical dig RPC schemas.",
                        "required": false,
                        "schema": { "type": "object" }
                    }
                ],
                "result": {
                    "name": "result",
                    "schema": { "type": "object" }
                },
                "errors": openrpc_errors(),
            })
        })
        .collect();

    json!({
        "openrpc": "1.2.6",
        "info": {
            "title": "dig-node JSON-RPC",
            "version": VERSION,
            "description": "The local DIG node's JSON-RPC surface (rpc.dig.net-compatible), \
                            served at POST /. The read methods (dig.*/cache.*) are open to local \
                            consumers; the CONTROL/admin methods (control.*) MANAGE the node and \
                            are loopback-only AND locally authorized — present the local control \
                            token (the X-Dig-Control-Token header or params._control_token, read \
                            from <config_dir>/control-token). The canonical dig RPC param/result \
                            schemas are published by docs.dig.net; this document is the \
                            discoverable method + error catalogue for the local node.",
            "x-control-auth": {
                "scheme": "local-token",
                "header": "X-Dig-Control-Token",
                "param": "_control_token",
                "token_file": "<config_dir>/control-token",
                "applies_to": "control.*",
                "description": "A random token generated at first run into the node's config \
                                dir (next to config.json), readable only by same-host processes. \
                                A same-host controller reads it and presents it on control.* calls.",
            },
        },
        "servers": [
            { "name": "loopback", "url": "http://127.0.0.1:8080/" }
        ],
        "methods": method_objs,
        "components": {
            "errors": openrpc_error_components(),
        },
    })
}

/// The `errors` array attached to every OpenRPC method (references the catalogue).
fn openrpc_errors() -> Value {
    Value::Array(
        ErrorCode::all()
            .iter()
            .map(|e| {
                json!({
                    "code": e.code(),
                    "message": e.description(),
                    "data": { "name": e.name(), "origin": e.origin() },
                })
            })
            .collect(),
    )
}

/// The OpenRPC `components.errors` map keyed by symbolic name.
fn openrpc_error_components() -> Value {
    let mut map = serde_json::Map::new();
    for e in ErrorCode::all() {
        map.insert(
            e.name().to_string(),
            json!({
                "code": e.code(),
                "message": e.description(),
                "data": { "name": e.name(), "origin": e.origin() },
            }),
        );
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_carries_service_version_commit_and_dig_node_version() {
        let info = build_info();
        assert_eq!(info["service"], json!(SERVICE_NAME));
        assert_eq!(info["service"], json!("dig-node"));
        assert_eq!(info["version"], json!(VERSION));
        assert_eq!(info["commit"], json!(GIT_SHA));
        assert_eq!(info["dig_node_version"], json!(DIG_NODE_VERSION));
        assert_eq!(info["protocol"], json!(PROTOCOL));
    }

    #[test]
    fn error_codes_are_unique_and_upper_snake() {
        let mut seen_codes = std::collections::HashSet::new();
        let mut seen_names = std::collections::HashSet::new();
        for e in ErrorCode::all() {
            assert!(
                seen_codes.insert(e.code()),
                "duplicate numeric code {}",
                e.code()
            );
            assert!(seen_names.insert(e.name()), "duplicate name {}", e.name());
            // UPPER_SNAKE: only A-Z and underscore.
            assert!(
                e.name().chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "{} is not UPPER_SNAKE",
                e.name()
            );
        }
    }

    #[test]
    fn error_code_numeric_values_are_the_documented_jsonrpc_codes() {
        assert_eq!(ErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(ErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(ErrorCode::InvalidParams.code(), -32602);
        assert_eq!(ErrorCode::DispatchFailed.code(), -32000);
        assert_eq!(ErrorCode::UpstreamError.code(), -32010);
    }

    #[test]
    fn methods_catalogue_covers_the_served_surface() {
        let names = method_names();
        for required in [
            "dig.getContent",
            "dig.getAnchoredRoot",
            "cache.getConfig",
            "cache.setCapBytes",
            "cache.clear",
            "rpc.discover",
            "dig.getProof",
            "dig.listCapsules",
            // #39 public collection reads (passthrough to the upstream dig-node).
            "dig.getCollection",
            "dig.listCollectionItems",
            // CONTROL surface (#101a).
            "control.status",
            "control.config.get",
            "control.config.setUpstream",
            "control.cache.get",
            "control.cache.setCap",
            "control.cache.clear",
            "control.hostedStores.list",
            "control.hostedStores.pin",
            "control.hostedStores.unpin",
            "control.hostedStores.status",
            "control.sync.status",
            "control.sync.trigger",
        ] {
            assert!(
                names.contains(&required),
                "method catalogue missing {required}"
            );
        }
    }

    #[test]
    fn collection_read_methods_are_catalogued_passthrough_no_auth() {
        // #39: dig.getCollection / dig.listCollectionItems are public reads — served by
        // passthrough to the upstream dig-node, never auth-gated — and they appear in the
        // generated OpenRPC so rpc.discover / /openrpc.json stay correct.
        for name in ["dig.getCollection", "dig.listCollectionItems"] {
            let m = methods()
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("{name} missing from the method catalogue"));
            assert_eq!(m.served, "passthrough", "{name} must be a passthrough read");
            assert!(!m.requires_auth, "{name} is a public read (no control token)");
        }
        let doc = openrpc_document();
        let methods = doc["methods"].as_array().expect("methods array");
        for name in ["dig.getCollection", "dig.listCollectionItems"] {
            assert!(
                methods.iter().any(|m| m["name"] == json!(name)),
                "{name} missing from the OpenRPC document"
            );
        }
    }

    #[test]
    fn control_methods_require_auth_and_read_methods_do_not() {
        for m in methods() {
            if m.name.starts_with("control.") {
                assert!(
                    m.requires_auth,
                    "control method {} must require auth",
                    m.name
                );
                assert_eq!(m.served, "control", "{} must be served=control", m.name);
            } else {
                assert!(
                    !m.requires_auth,
                    "non-control method {} must NOT require auth",
                    m.name
                );
            }
        }
    }

    #[test]
    fn control_error_codes_are_catalogued() {
        // The local-auth gate + control surface mint these stable codes.
        assert_eq!(ErrorCode::Unauthorized.code(), -32020);
        assert_eq!(ErrorCode::Unauthorized.name(), "UNAUTHORIZED");
        assert_eq!(ErrorCode::NotSupported.code(), -32021);
        assert_eq!(ErrorCode::NotSupported.name(), "NOT_SUPPORTED");
        assert_eq!(ErrorCode::ControlError.code(), -32022);
        assert_eq!(ErrorCode::ControlError.name(), "CONTROL_ERROR");
        // All are shell-origin (minted by the companion control plane).
        for e in [
            ErrorCode::Unauthorized,
            ErrorCode::NotSupported,
            ErrorCode::ControlError,
        ] {
            assert_eq!(e.origin(), "shell");
        }
    }

    #[test]
    fn openrpc_marks_control_methods_with_requires_auth() {
        let doc = openrpc_document();
        let methods = doc["methods"].as_array().expect("methods array");
        let status = methods
            .iter()
            .find(|m| m["name"] == json!("control.status"))
            .expect("control.status present in OpenRPC");
        assert_eq!(status["x-requires-auth"], json!(true));
        let get_content = methods
            .iter()
            .find(|m| m["name"] == json!("dig.getContent"))
            .expect("dig.getContent present");
        assert_eq!(get_content["x-requires-auth"], json!(false));
        // The control-auth scheme is documented in info for discoverability.
        assert_eq!(
            doc["info"]["x-control-auth"]["header"],
            json!("X-Dig-Control-Token")
        );
    }

    #[test]
    fn openrpc_document_is_generated_from_the_method_catalogue() {
        let doc = openrpc_document();
        assert_eq!(doc["openrpc"], json!("1.2.6"));
        let methods = doc["methods"].as_array().expect("methods array");
        assert_eq!(methods.len(), super::methods().len());
        // rpc.discover must be present so an agent can find the spec over the wire.
        assert!(methods.iter().any(|m| m["name"] == json!("rpc.discover")));
        // Every method carries the error catalogue.
        for m in methods {
            assert!(
                m["errors"].is_array(),
                "method {} missing errors",
                m["name"]
            );
        }
    }

    #[test]
    fn well_known_document_exposes_addr_cache_methods_and_errors() {
        let doc = well_known_document("127.0.0.1:8080", "https://rpc.dig.net", 1024, 0);
        assert_eq!(doc["service"], json!("dig-node"));
        assert_eq!(doc["addr"], json!("127.0.0.1:8080"));
        assert!(doc["cache"]["dir"].is_string());
        assert_eq!(doc["cache"]["cap_bytes"], json!(1024));
        // #96: the discovery doc reports whether the cache is the shared canonical
        // dir (vs a process-private fallback), from dig-node's resolver.
        assert!(doc["cache"]["shared"].is_boolean());
        assert!(doc["methods"].is_array());
        assert!(doc["errors"].is_array());
        assert_eq!(doc["rpc"]["openrpc"], json!("/openrpc.json"));
    }
}
