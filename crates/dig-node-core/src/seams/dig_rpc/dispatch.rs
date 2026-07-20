//! Seam 4's public surface (#1285/#1303) — the node-internal JSON-RPC dispatch every transport
//! (the loopback HTTP shell, the L7 peer-RPC server, the in-process FFI) drives through the SAME
//! entry point, so the DIG Browser's dig:// handler can *be* the node with no HTTP, socket, or
//! sidecar in between.
//!
//! `RpcDispatch` is implemented by [`Node`] with the EXISTING `handle_rpc` body relocated
//! unchanged (#1285 W1b-5) — a behaviour-preserving trait extraction, not a new implementation
//! or a `dig-rpc-protocol` crate adoption (that is W3's job; this pass keeps the hand-rolled
//! `match Method::from_name(..)` dispatch byte-identical). `async_trait`-boxed (matching the
//! other seam traits) so it stays dyn-compatible for the future `Arc<dyn RpcDispatch>` handle
//! (W1c). The crate-root `handle_rpc`/`handle_rpc_json` free functions (every external caller's
//! entry point — `dig-node-service`, `dig-runtime`, the peer-RPC server) now thinly delegate to
//! [`RpcDispatch::dispatch`] — their signatures are UNCHANGED, so no caller anywhere needed to
//! change.

use serde_json::{json, Value};

use crate::Node;
// The relocated body below calls a number of crate-root private helpers (`rpc_err`,
// `parse_store_id_arg`, `pin_request_root`, …) UNQUALIFIED, exactly as it did when it lived in
// `lib.rs` itself. A glob import is the pragmatic, safe way to keep every one of those references
// resolving without hand-auditing each name — private crate-root items are visible to this
// descendant module either way (`use crate::*` vs. naming each one has no visibility effect).
#[allow(unused_imports)]
use crate::*;

/// Seam 4 (dig RPC server) — the node's core JSON-RPC dispatch.
#[async_trait::async_trait]
pub trait RpcDispatch: Send + Sync {
    /// Dispatch one JSON-RPC request `Value`, returning its response `Value`. See
    /// [`crate::handle_rpc`] (the stable free-function entry point every caller uses).
    async fn dispatch(&self, req: Value) -> Value;
}

#[async_trait::async_trait]
impl RpcDispatch for Node {
    async fn dispatch(&self, req: Value) -> Value {
        // `node` alias: the body below is relocated VERBATIM from the pre-#1285-W1b-5
        // `handle_rpc(node: &Node, req: Value)` free function — byte-identical, just bound to
        // `self` here instead of taking `node` as a parameter.
        let node = self;
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        use dig_rpc_protocol::Method;
        // Dispatch on the canonical Method enum (dig-rpc-protocol, #1075) instead of
        // string literals, so the served method names cannot drift from the shared
        // node<->node contract. A name this core engine does not serve — the shell's
        // discovery aliases (dig.getCapsule / dig.getProof / …) or an unknown method —
        // falls to the `_` arm's method-not-found; dig.getContent falls through to the
        // read block after the match.
        match Method::from_name(method) {
            // dig.getAnchoredRoot: resolve a store's chain-anchored tip root (the TRUSTED
            // root for the browser's mandatory dig:// root-pinning — see anchored_root).
            Some(Method::GetAnchoredRoot) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.anchored_root(&params, id).await;
            }
            // dig.getManifest (#176 Phase C): the normalized PublicManifest (data-section id 13)
            // embedded in a specific CAPSULE's (store_id:root) compiled `.dig` module — the store's
            // complete public file surface (latest version per path) as of that commit. PUBLIC,
            // unencrypted data, so no retrieval_key is needed. Served LOCALLY now (was a blind
            // passthrough alias before #176): see `Node::get_manifest`.
            Some(Method::GetManifest) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.get_manifest(&params, id).await;
            }
            // dig.stage (#95 Pass C): turn a local folder into a capsule (.dig module) IN
            // PROCESS — the staging/compile half of a local deploy. The DIG Browser's
            // in-process node calls this (no CLI binary) to produce the artifact, then
            // signs the on-chain root advance via the Pass B `chia_advanceStore` wallet
            // method and §21-pushes the module. ADDITIVE — no existing method is touched.
            Some(Method::Stage) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.stage(&params, id);
            }
            // dig.getCollection / dig.listCollectionItems (#39): PUBLIC, owner-independent
            // collection reads computed from DIG's own coinset data — no third-party indexer.
            // Read-only (no spend bundles). The item set is the NFT launcher ids the mint
            // produced (the authoritative, owner-independent anchor; see
            // digstore_chain::collection_index for why launcher ids, not the creator DID
            // hint, are the discovery key). Each item is resolved to its CURRENT on-chain
            // owner + royalty + CHIP-0007 metadata by walking the singleton lineage forward.
            Some(Method::GetCollection) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return Node::get_collection(&params, id).await;
            }
            Some(Method::ListCollectionItems) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return Node::list_collection_items(&params, id).await;
            }
            // -- L7 peer RPC (PHASE-2b, #162) — the node-profile peer-network methods -----------------------
            //
            // Additive JSON-RPC methods that expose the peer network over the node's RPC surface, so an agent
            // (or the peer transport's JSON-RPC stream path) drives discovery + availability + range fetch
            // without speaking the binary peer protocol. They are served here (over §21/FFI AND over an
            // inbound mTLS peer stream, which routes JSON-RPC frames through this same dispatch). See
            // docs.dig.net → L7 · DIG Node peer network + openrpc-node.json.
            Some(Method::GetNetworkInfo) => {
                // This node's own posture (identity, reachability, candidate addrs, relay reservation).
                return json!({"jsonrpc":"2.0","id":id,"result": node.network_info()});
            }
            Some(Method::GetPeers) => {
                // The peers this node currently knows (peer-exchange over RPC). The connected-pool source is
                // owned by the live GossipService in the standalone run(); the node struct here does not hold
                // the gossip handle (it stays FFI-safe), so this base dispatch returns the node's own view:
                // an empty peer list when no pool is wired. The standalone peer-network task answers inbound
                // `dig.getPeers` from the live pool via its own responder override (see peer::PoolResponder).
                return json!({"jsonrpc":"2.0","id":id,"result": {"peers": []}});
            }
            Some(Method::Announce) => {
                // Accept an announcement (peer_id + candidate addresses). The base node has no pool to fold it
                // into, so it acknowledges without growing a peer view; the live peer-network task overrides
                // this to register the announced peer with the pool/introducer. Validates the required params.
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let peer_id_ok = params
                    .get("peer_id")
                    .and_then(Value::as_str)
                    .map(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    .unwrap_or(false);
                let has_addrs = params
                    .get("addresses")
                    .map(Value::is_array)
                    .unwrap_or(false);
                if !peer_id_ok || !has_addrs {
                    return rpc_err(
                        &id,
                        -32602,
                        "dig.announce requires peer_id (64-hex) + addresses (array)",
                    );
                }
                return json!({"jsonrpc":"2.0","id":id,"result": {"accepted": true, "known_peers": 0}});
            }
            Some(Method::GetAvailability) => {
                // Batch-answer whether this node holds the queried stores/roots/capsules (from local
                // inventory), so a downloader confirms holders + plans ranges before any fetch.
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let items = match params.get("items").and_then(Value::as_array) {
                    Some(items) => items.clone(),
                    None => {
                        return rpc_err(
                            &id,
                            -32602,
                            "dig.getAvailability requires params.items (array)",
                        )
                    }
                };
                return json!({"jsonrpc":"2.0","id":id,"result": node.availability_batch(&items).await});
            }
            Some(Method::ListInventory) => {
                // Enumerate what this node serves: its stores, or the roots it holds for a given store.
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_id = params.get("store_id").and_then(Value::as_str);
                if let Some(s) = store_id {
                    if !(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
                        return rpc_err(&id, -32602, "store_id must be 64-hex");
                    }
                }
                let limit = params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize);
                let cached = node.cache_list_cached().await;
                return json!({"jsonrpc":"2.0","id":id,
            "result": peer::list_inventory(&cached, store_id, limit)});
            }
            Some(Method::FetchRange) => {
                // A single range frame of a resource this node holds (the JSON-RPC face of the streamed
                // peer-transport range fetch; the caller advances `offset` for further windows). The frame
                // carries the per-range verification metadata on the first window.
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_hex = params.get("store_id").and_then(Value::as_str).unwrap_or("");
                let root_hex = params.get("root").and_then(Value::as_str).unwrap_or("");
                let rk_hex = params
                    .get("retrieval_key")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let capsule = params
                    .get("capsule")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let length = params.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
                if store_hex.len() != 64 || length == 0 {
                    return rpc_err(
                        &id,
                        -32602,
                        "dig.fetchRange requires store_id (64-hex) + length (>0)",
                    );
                }
                if capsule {
                    // Whole-capsule streaming is a clean follow-up seam (the .dig streaming path); resource
                    // range fetch is served now. Report the catalogued unavailable code for capsule mode.
                    return rpc_err(
                    &id,
                    -32004,
                    "capsule range fetch not served by this node yet (use resource retrieval_key)",
                );
                }
                if rk_hex.len() != 64 || root_hex.len() != 64 {
                    return rpc_err(
                        &id,
                        -32602,
                        "resource fetchRange requires retrieval_key + root (64-hex each)",
                    );
                }
                return match node
                    .fetch_range_frame(store_hex, root_hex, rk_hex, offset, length)
                    .await
                {
                    Ok(frame) => {
                        // OUTGOING-BANDWIDTH THROTTLE (#30): this node HOLDS the range, but serving it now
                        // may push it over its configured cap — redirect to a known holder instead (same
                        // #165 redirect shape) with a graceful serve-anyway fallback when none is known.
                        let bytes = frame.get("length").and_then(Value::as_u64).unwrap_or(0);
                        let depth = download::redirect_depth(&params);
                        if let Some(obj) = node
                            .bandwidth_redirect_for(store_hex, root_hex, rk_hex, bytes, depth)
                            .await
                        {
                            return json!({"jsonrpc":"2.0","id":id,"error":obj});
                        }
                        node.record_outgoing_bytes(bytes);
                        json!({"jsonrpc":"2.0","id":id,"result": frame})
                    }
                    // A LOCAL MISS (-32004): try the #165 P2P miss path — redirect to a holder (default) or
                    // fetch-through via dig-download — before returning the bare not-found. An empty engine
                    // (FFI path) or no provider yields `None` and the original error stands (no silent 404
                    // when a provider exists). Other errors (e.g. -32007 bad range) pass through unchanged.
                    Err((code, message)) => {
                        if code == download::RESOURCE_UNAVAILABLE {
                            if let Some(content) =
                                download::miss_content_for(store_hex, root_hex, rk_hex)
                            {
                                let depth = download::redirect_depth(&params);
                                if let Some(envelope) = node
                                    .range_miss_envelope(&id, &content, depth, offset, length)
                                    .await
                                {
                                    // Served from another node — background-backfill the whole capsule so the
                                    // next read is local (SPEC §14.3). Deduped + detached; no delay here.
                                    node.maybe_backfill_capsule(store_hex, root_hex);
                                    return envelope;
                                }
                            }
                        }
                        rpc_err(&id, code, &message)
                    }
                };
            }
            // cache.* — the local-cache config for the chrome://settings DIG section.
            // The browser's Mojo handler reaches these via the in-process CallDigRpc FFI;
            // dig-node owns the cache, so it is the single source of truth (same fns the
            // dig-wallet /api/dig-config endpoint uses).
            Some(Method::CacheGetConfig) => {
                // ADDITIVE fields (#96): `cache_dir` = the effective resolved cache path,
                // `shared` = whether that path is the canonical dir shared with the
                // standalone dig-node / dig-companion (`false` = a process-private
                // fallback because the canonical dir was unwritable). Existing
                // `cap_bytes`/`used_bytes` are UNCHANGED — the FFI contract is
                // additive-only (see SYSTEM.md change-impact + the regression test).
                let (dir, shared) = resolve_cache_dir();
                return json!({"jsonrpc":"2.0","id":id,"result":{
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": cache_used_bytes(),
            "cache_dir": dir.display().to_string(),
            "shared": shared}});
            }
            // control.peerStatus — live, pool-oriented status of the node's L7 peer network (the connected
            // peer pool + the relay reservation for NAT reachability). Read-only; safe before/without a peer
            // network running (then `running:false`). Replaces the retired `control.relayStatus`: relay
            // reachability now lives in dig-nat/dig-gossip and is reported here as the pool's relay flag.
            Some(Method::ControlPeerStatus) => {
                let endpoint = peer::relay_url_from_env();
                let network_id = peer::network_id_from_env();
                let mut snapshot = node.peer_status.snapshot_json(&endpoint, &network_id);
                // Attach the per-peer array so the A↔B mutual-connection proof is machine-checkable (each
                // side lists the OTHER's peer_id), not just a count. Sourced from the live pool handle; empty
                // (and omitted-as-`[]`) on the FFI path / before bring-up. See `peer::connected_peers_json`.
                if let Some(handle) = node.gossip_handle() {
                    snapshot["peers"] = Value::Array(peer::connected_peers_json(handle));
                }
                return json!({"jsonrpc":"2.0","id":id, "result": snapshot});
            }
            // control.peers.connect — dial a peer by address (or resolve an already-connected peer_id) via the
            // live gossip pool, turning a relay-DISCOVERED peer into a COUNTED, RPC-reachable connected peer
            // (#929). CONTROL-plane: reachable ONLY from the loopback admin / in-process FFI dispatch, NEVER
            // over the mTLS peer surface (absent from `is_peer_reachable_method`). Deterministic success /
            // failure; a no-op "no peer network" on the FFI path (no pool handle retained).
            Some(Method::ControlPeersConnect) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let peer = params.get("peer").and_then(Value::as_str).unwrap_or("");
                let Some(handle) = node.gossip_handle() else {
                    return control_err(
                        &id,
                        CONTROL_ERROR,
                        "no peer network is running on this node",
                    );
                };
                return match peer::connect_peer(handle, peer).await {
                    Ok(peer_id) => json!({"jsonrpc":"2.0","id":id,
                "result": {"connected": true, "peer_id": peer_id}}),
                    Err(e) => control_err(&id, CONTROL_ERROR, &format!("connect failed: {e}")),
                };
            }
            // control.peers.disconnect — drop a pooled peer by peer_id, closing its mTLS link (the inverse of
            // control.peers.connect). CONTROL-plane: loopback admin / in-process FFI ONLY, NEVER over the mTLS
            // peer surface (absent from `is_peer_reachable_method`). Idempotent: disconnecting a peer that is
            // not connected succeeds as a no-op. A no-op "no peer network" on the FFI path.
            Some(Method::ControlPeersDisconnect) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let peer = params.get("peer").and_then(Value::as_str).unwrap_or("");
                let Some(handle) = node.gossip_handle() else {
                    return control_err(
                        &id,
                        CONTROL_ERROR,
                        "no peer network is running on this node",
                    );
                };
                return match peer::disconnect_peer(handle, peer).await {
                    Ok(()) => json!({"jsonrpc":"2.0","id":id,
                "result": {"disconnected": true, "peer_id": peer.trim().to_ascii_lowercase()}}),
                    Err(e) => control_err(&id, CONTROL_ERROR, &format!("disconnect failed: {e}")),
                };
            }
            // control.subscribe / control.unsubscribe / control.listSubscriptions (SPEC §6) — manage the
            // node's OWN persisted set of subscribed stores (the stores it actively watches + gap-fills). These
            // are CONTROL-plane methods: reachable ONLY from the loopback admin server / in-process FFI
            // dispatch, NEVER over the mTLS peer surface (they are absent from `is_peer_reachable_method`, so
            // the peer responder answers `-32601` before dispatch). Errors carry the canonical control-plane
            // taxonomy (`-32030`/`-32032`, `data.code`/`data.origin`; dig-rpc-types §10).
            Some(Method::ControlSubscribe) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_id = params.get("store_id").and_then(Value::as_str).unwrap_or("");
                return match subscribe_store(store_id) {
                    Ok(added) => {
                        // A newly-subscribed store is reconciled promptly (the watch loop also polls it on its
                        // interval); a refresh of the DHT inventory is not needed here (subscription != held).
                        json!({"jsonrpc":"2.0","id":id,"result":{
                    "subscribed": true,
                    "added": added,
                    // Echo the CANONICAL persisted id (trimmed + lower-cased), so the response can
                    // never disagree with control.listSubscriptions.
                    "store_id": subscription::normalize_store_id(store_id)}})
                    }
                    Err(e) => control_err(&id, CONTROL_ERROR, &format!("subscribe failed: {e}")),
                };
            }
            Some(Method::ControlUnsubscribe) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_id = params.get("store_id").and_then(Value::as_str).unwrap_or("");
                return match unsubscribe_store(store_id) {
                    Ok(removed) => json!({"jsonrpc":"2.0","id":id,"result":{
                "subscribed": false,
                "removed": removed,
                "store_id": subscription::normalize_store_id(store_id)}}),
                    Err(e) => control_err(&id, CONTROL_ERROR, &format!("unsubscribe failed: {e}")),
                };
            }
            Some(Method::ControlListSubscriptions) => {
                let set = load_subscriptions();
                return json!({"jsonrpc":"2.0","id":id,"result":{
            "subscriptions": set.stores(),
            "count": set.len()}});
            }
            Some(Method::CacheSetCapBytes) => {
                let requested = req
                    .get("params")
                    .and_then(|p| p.get("cap_bytes"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                // Floor at 64 MiB so a stray 0 can't disable caching (mirrors dig-wallet).
                let cap = requested.max(64 * 1024 * 1024);
                return match set_cache_cap_bytes(cap) {
                    Ok(()) => json!({"jsonrpc":"2.0","id":id,"result":{"cap_bytes": cap}}),
                    // A config write failure is a control-plane runtime error (canonical taxonomy §10).
                    Err(e) => control_err(&id, CONTROL_ERROR, &e.to_string()),
                };
            }
            Some(Method::CacheClear) => {
                clear_cache();
                // Also drop the in-memory decoded-content cache so a cleared capsule can't still be served
                // from RAM (audit #179).
                node.clear_content_cache();
                return json!({"jsonrpc":"2.0","id":id,"result":{}});
            }
            // cache.listCached / removeCached / fetchAndCache — the cached-store manager
            // (task #32). Each cached module is a CAPSULE (storeId:rootHash), so these are
            // keyed by capsule identity (`digstore_core::Capsule`).
            Some(Method::CacheListCached) => {
                let list = node.cache_list_cached().await;
                // #279: attach `lru_rank` to each entry so a controller can render the
                // eviction order without re-deriving it. Rank 0 = the LEAST-recently-used
                // capsule (the NEXT one the size cap would evict), increasing with recency
                // — the same oldest-mtime-first order `plan_eviction` uses. Computed here
                // (a view concept) rather than on `CachedCapsule` (kept a plain fact).
                let mut order: Vec<usize> = (0..list.len()).collect();
                order.sort_by_key(|&i| (list[i].last_used_unix_ms, i));
                let mut rank_of = vec![0u64; list.len()];
                for (rank, &i) in order.iter().enumerate() {
                    rank_of[i] = rank as u64;
                }
                let cached: Vec<Value> = list
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        json!({
                            // The canonical capsule string identity (storeId:rootHash),
                            // identical to digstore_core::Capsule::canonical().
                            "capsule": format!("{}:{}", c.store_id, c.root),
                            "store_id": c.store_id,
                            "root": c.root,
                            "size_bytes": c.size_bytes,
                            "last_used_unix_ms": c.last_used_unix_ms,
                            // #279: LRU/eviction order — 0 = next to be evicted.
                            "lru_rank": rank_of[i],
                        })
                    })
                    .collect();
                return json!({"jsonrpc":"2.0","id":id,"result":{"cached": cached}});
            }
            Some(Method::CacheStats) => {
                // #279: OPEN cache telemetry beside `cache.getConfig` — the reserved cap +
                // live usage, the cached-capsule count and their total on-disk bytes, and
                // the session eviction + decoded-content hit/miss counters. All additive.
                let list = node.cache_list_cached().await;
                let entry_count = list.len() as u64;
                let total_bytes: u64 = list.iter().map(|c| c.size_bytes).sum();
                use std::sync::atomic::Ordering::Relaxed;
                return json!({"jsonrpc":"2.0","id":id,"result":{
                "cap_bytes": cache_cap_bytes(),
                "used_bytes": cache_used_bytes(),
                "entry_count": entry_count,
                "total_bytes": total_bytes,
                "evicted_count": CACHE_EVICTED_COUNT.load(Relaxed),
                "evicted_bytes": CACHE_EVICTED_BYTES.load(Relaxed),
                "content_cache": {
                    "hits": CONTENT_CACHE_HITS.load(Relaxed),
                    "misses": CONTENT_CACHE_MISSES.load(Relaxed),
                }}});
            }
            Some(Method::CacheRemoveCached) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_hex = params
                    .get("store_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
                return match node.cache_remove_cached(store_hex, root_hex).await {
                    Ok(removed) => json!({"jsonrpc":"2.0","id":id,"result":{"removed": removed}}),
                    Err(e) => json!({"jsonrpc":"2.0","id":id,
                "error":{"code":-32602,"message": e}}),
                };
            }
            Some(Method::CacheFetchAndCache) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let store_hex = params
                    .get("store_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
                // Was it already present before this call? (so we can report
                // already_cached vs a fresh cached, per the spec's status field.)
                let already = module_path(&node.cache_dir, store_hex, root_hex).exists();
                return match node.cache_fetch_and_cache(store_hex, root_hex).await {
                    Ok((size_bytes, served_root)) => {
                        // A freshly-cached capsule entered the served set — refresh the DHT provider records so
                        // peers immediately find this node as a holder (§14.1). No-op on the FFI path / before
                        // peer-network bring-up. (Already-cached is unchanged inventory, so skip the refresh.)
                        if !already {
                            node.refresh_dht_inventory().await;
                        }
                        json!({"jsonrpc":"2.0","id":id,"result":{
                    "status": if already { "already_cached" } else { "cached" },
                    "size_bytes": size_bytes,
                    "served_root": served_root}})
                    }
                    // A failed fetch is reported in-band (status:"failed") so the settings
                    // manager can show it without treating it as a transport error.
                    Err(e) => json!({"jsonrpc":"2.0","id":id,"result":{
                "status": "failed",
                "message": e}}),
                };
            }
            // dig.getContent is the canonical local read — the default branch, handled by the
            // block below the match. Everything the crate catalogues but this core engine does
            // not serve locally (the shell's passthrough aliases: getCapsule / getModule /
            // getMetadata / getProof / getProofStatus / listCapsules / health / methods /
            // rpc.discover) AND any unknown method fall through to method-not-found — exactly
            // the pre-adoption behaviour (the shell relays those to the upstream on a -32601).
            Some(Method::GetContent) => {}
            _ => {
                return json!({"jsonrpc":"2.0","id":id,
            "error":{"code":-32601,"message":"method not found"}});
            }
        }
        let params = req.get("params").cloned().unwrap_or(json!({}));
        let store_hex = params
            .get("store_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let requested_root_hex = params.get("root").and_then(|v| v.as_str()).unwrap_or("");
        let rk_hex = params
            .get("retrieval_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        let err = |id: &Value, code: i64, msg: String| -> Value {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
        };

        // -- MANDATORY anchored-root pin (#127) ------------------------------------
        //
        // Before serving ANY content (local module, §21 sync, cached window, or an
        // upstream proxy), resolve the store's CHIP-0035 chain-anchored TIP root and
        // require the served generation to BE that root, or FAIL CLOSED. The chain —
        // not the request, the cached module, or the upstream — is the authority over
        // which generation is served. A rootless request resolves to the chain tip; an
        // explicit root must equal it. This is the same pin the CLI clone/pull enforce,
        // now uniform across the node read path (a compromised upstream can no longer
        // choose the served generation).
        let store_id_arr = match parse_store_id_arg(&params) {
            Ok(b) => b.into(),
            Err(()) => {
                return err(
                    &id,
                    -32602,
                    "params.store_id must be a 32-byte (64-hex) launcher id".into(),
                )
            }
        };
        // A concrete, valid requested root (non-empty, 64-hex). The `"latest"`
        // sentinel and any malformed value are treated as ROOTLESS (resolve the tip).
        let requested_root = Bytes32::from_hex(requested_root_hex).ok();
        let pinned_root: Option<Bytes32> = if pin_enforced() {
            let anchored = node
                .anchored_root_resolver
                .anchored_root(&store_id_arr)
                .await;
            match decide_pin(true, requested_root, anchored) {
                PinDecision::ServeAt(root) => Some(root),
                PinDecision::Reject(code, msg) => return err(&id, code, msg),
                // `decide_pin(true, ..)` never returns Unpinned.
                PinDecision::Unpinned => requested_root,
            }
        } else {
            // Pin disabled (DIG_NODE_PIN=off, offline/local dev): serve against the
            // requested root as-is; the client still verifies against its trust root.
            requested_root
        };

        // The concrete root hash everything below serves against. With the pin on this
        // is the chain-anchored tip; with it off it is the requested root (or empty).
        let root_hex = pinned_root
            .map(|r| r.to_hex())
            .unwrap_or_else(|| requested_root_hex.to_string());

        // Tag the result with where it was served from so the browser can show a
        // "local" chip: "local" = from this device's cache (a compiled module or a
        // previously-cached window), "remote" = freshly fetched from rpc.dig.net.
        let local = |id: &Value, mut result: Value| -> Value {
            if let Some(obj) = result.as_object_mut() {
                obj.insert("source".into(), json!("local"));
            }
            json!({"jsonrpc":"2.0","id":id,"result":result})
        };

        // 1. LOCAL-FIRST: serve from a cached compiled module (no network at all). The
        //    served module's own root MUST equal the pinned chain-anchored root — a
        //    cached module whose generation is not the anchored tip is rejected (it is
        //    not served as if current).
        // OUTGOING-BANDWIDTH THROTTLE (dig_ecosystem #30): before serving a LOCAL-FIRST hit, check
        // whether the window's bytes would push this node's outgoing traffic over its configured cap;
        // if so and a holder is known, redirect there instead (extends #165 redirect-on-miss from "not
        // held" to "held but saturated") — else the graceful fallback: serve anyway.
        let depth = download::redirect_depth(&params);

        if let (Ok(rk), false) = (decode_rk(rk_hex), root_hex.is_empty()) {
            if let Some(resp) = node.serve_local_cached(store_hex, &root_hex, &rk).await {
                if let Some(pin) = pinned_root {
                    if resp.roothash != pin {
                        return err(
                        &id,
                        ROOT_NOT_ANCHORED,
                        format!(
                            "served module root {} does not match the store's on-chain root {} (chain is the authority)",
                            resp.roothash.to_hex(),
                            pin.to_hex()
                        ),
                    );
                    }
                }
                let bytes = content_window_len(resp.ciphertext.len(), offset) as u64;
                if let Some(obj) = node
                    .bandwidth_redirect_for(store_hex, &root_hex, rk_hex, bytes, depth)
                    .await
                {
                    return json!({"jsonrpc":"2.0","id":id,"error":obj});
                }
                node.record_outgoing_bytes(bytes);
                return local(&id, build_result(&resp, offset));
            }
            // 1b. AUTHENTICATED WHOLE-STORE SYNC (§21.9): on a module-cache miss, pull
            //     the whole `.dig` from rpc.dig.net's auth-gated §21 endpoint, cache
            //     it, then serve locally. Best-effort — a failed/disabled sync just
            //     falls through to the per-resource proxy below. `sync_module` returns
            //     true only when the SERVED root == the requested (= pinned) root, so a
            //     synced module is keyed by the anchored root before we serve it.
            if node.sync_module(store_hex, &root_hex).await {
                // The sync just wrote/replaced the on-disk module; drop any stale decoded entry so the
                // cache reflects the newly-synced module rather than a prior decode.
                node.invalidate_content_cache(store_hex, &root_hex);
                if let Some(resp) = node.serve_local_cached(store_hex, &root_hex, &rk).await {
                    if pinned_root.map(|p| resp.roothash == p).unwrap_or(true) {
                        let bytes = content_window_len(resp.ciphertext.len(), offset) as u64;
                        if let Some(obj) = node
                            .bandwidth_redirect_for(store_hex, &root_hex, rk_hex, bytes, depth)
                            .await
                        {
                            return json!({"jsonrpc":"2.0","id":id,"error":obj});
                        }
                        node.record_outgoing_bytes(bytes);
                        return local(&id, build_result(&resp, offset));
                    }
                }
            }
        }

        // 2. RESPONSE CACHE: a window we previously proxied for this exact request.
        //    Keyed by the PINNED root, so a window cached for a stale/mismatched root
        //    is never replayed for the anchored read.
        let key = response_key(store_hex, &root_hex, rk_hex, offset);
        if let Some(result) = node.serve_cached_response(&key) {
            return local(&id, result);
        }

        // 2b. P2P REDIRECT-ON-MISS (#165): this node does NOT hold the content locally. If it runs a P2P
        //     content engine (the standalone peer network — never the in-process FFI/browser path) and the
        //     DHT locates a holder, answer with a REDIRECT to that holder (default) or FETCH-THROUGH via
        //     dig-download (`DIG_NODE_ON_MISS=fetch`) instead of dead-ending — never a silent miss while a
        //     provider exists. A bounded `redirect_depth` (echoed by the caller) prevents redirect loops.
        //     Applies only to a concrete resource (store+root+retrieval_key); an empty engine or no
        //     provider falls through to the upstream proxy below (byte-identical to before).
        if let Some(content) = download::miss_content_for(store_hex, &root_hex, rk_hex) {
            let depth = download::redirect_depth(&params);
            let pin_hex = pinned_root.map(|r| r.to_hex());
            if let Some(envelope) = node
                .content_miss_envelope(&id, &content, depth, offset, pin_hex.as_deref())
                .await
            {
                // This resource is being served FROM ANOTHER NODE (a redirect/fetch-through). In the
                // background, ALSO pull the whole `.dig` capsule for this generation so the NEXT read of
                // the store is served locally (SPEC §14.3, `DIG_NODE_BACKFILL_ON_MISS`, default on). This
                // does not delay the current response — it spawns a deduped detached pull and returns.
                node.maybe_backfill_capsule(store_hex, &root_hex);
                return envelope;
            }
        }

        // 3. MISS: proxy to rpc.dig.net, then cache the result window (LRU-capped)
        //    so the next load of this resource is served locally. (rpc.dig.net is the
        //    remote DIG network, not a local server — the in-process node IS local.)
        //
        //    The upstream request is pinned to the anchored root (rewriting/forcing
        //    `params.root`), and the upstream-returned root is re-checked against the
        //    pin — so even on the proxy path the node never serves a generation the
        //    chain did not confirm.
        let upstream_req = pinned_root
            .map(|pin| pin_request_root(&req, &pin.to_hex()))
            .unwrap_or_else(|| req.clone());
        match node.proxy(&upstream_req).await {
            Ok(mut v) => {
                // Verify the upstream served the pinned root before trusting/caching it.
                if let Some(pin) = pinned_root {
                    let served = v
                        .get("result")
                        .and_then(|r| r.get("root"))
                        .and_then(|r| r.as_str())
                        .and_then(|s| Bytes32::from_hex(s).ok());
                    if let Some(served) = served {
                        if served != pin {
                            return err(
                            &id,
                            ROOT_NOT_ANCHORED,
                            format!(
                                "upstream served root {} does not match the store's on-chain root {} (chain is the authority)",
                                served.to_hex(),
                                pin.to_hex()
                            ),
                        );
                        }
                    }
                }
                if let Some(result) = v.get("result") {
                    node.store_response(&key, result).await;
                }
                // Mark this window as freshly fetched from the network.
                if let Some(result) = v.get_mut("result").and_then(|r| r.as_object_mut()) {
                    result.insert("source".into(), json!("remote"));
                }
                v
            }
            Err(e) => json!({"jsonrpc":"2.0","id":id,
            "error":{"code":-32000,"message":format!("upstream: {e}")}}),
        }
    }
}
