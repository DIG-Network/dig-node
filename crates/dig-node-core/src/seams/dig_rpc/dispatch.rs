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
//! entry point — `dig-node-service`, `dig-runtime`, the peer-RPC server) thinly delegate to
//! [`RpcDispatch::dispatch`]. Each carries the request's `origin` (transport axis) AND its
//! `provenance` (the `Sec-Fetch-Site` landing axis, #1956) — both threaded EXPLICITLY by every
//! caller so a transport can never forget to state who is asking or whether a cross-site page drove
//! the request.

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
    ///
    /// `origin` says who is asking — this node's OWN operator or a REMOTE peer — because this ONE
    /// dispatch is shared by every transport (loopback HTTP, in-process FFI, AND the peer-RPC
    /// server, #179/#1576): it is the single place the two are told apart, so it is threaded through
    /// EXPLICITLY by each caller rather than inferred here.
    ///
    /// `provenance` is the SECOND, orthogonal axis (#1956): within a loopback HTTP request, whether
    /// the browser reports another origin's page drove it (`Sec-Fetch-Site: cross-site`). Like
    /// `origin` it is threaded EXPLICITLY (never inferred) — a required param so every transport must
    /// state it (fail-safe): a browser-facing POST classifies the header, every trusted/non-browser
    /// caller passes [`FirstParty`]. It gates ONLY the miss-path landing legs (never the served
    /// bytes) via [`landing_origin`], exactly as the `/s/` serve path does.
    ///
    /// [`FirstParty`]: crate::download::RequestProvenance::FirstParty
    /// [`landing_origin`]: crate::download::landing_origin
    async fn dispatch(
        &self,
        req: Value,
        origin: crate::download::ReadOrigin,
        provenance: crate::download::RequestProvenance,
        requestor: crate::rate_limit::RequestorId,
    ) -> Value;
}

/// Resolve the mandatory chain-anchored pin (#127) for one serve/read request, fail-closed.
///
/// This is the SINGLE source of truth for "which generation may this node serve", shared byte-for-
/// byte by the `dig.getContent` READ arm AND the `dig.fetchRange` peer-SERVE arm (#1764 — the serve
/// arm formerly bypassed the gate entirely, letting a permissionless peer fetch ranges of a
/// generation the local read path already refuses). The chain — not the request, a cached module,
/// or an upstream — is the authority over which root is served.
///
/// Returns the concrete root to serve against:
/// - `Ok(Some(root))` — the pin is enforced and resolved: the chain-anchored tip (a rootless
///   request), or the requested root proven equal to the on-chain generation.
/// - `Ok(None)` — the pin is disabled (`DIG_NODE_PIN=off`, local dev): serve against the requested
///   root as-is; the client still verifies the Merkle proof against its own trust root.
/// - `Err((code, message))` — FAIL CLOSED: a superseded/forged root (`-32005` anti-rollback, the
///   real rollback attack), a store with no confirmed generation, or an unreachable chain — the
///   catalogued rejection the caller returns verbatim.
async fn resolve_enforced_pin(
    node: &Node,
    store_id_arr: &[u8; 32],
    requested_root: Option<Bytes32>,
) -> Result<Option<Bytes32>, (i64, String)> {
    if !pin_enforced() {
        // Pin disabled: serve against the requested root as-is (the client still verifies).
        return Ok(requested_root);
    }
    let anchored = node
        .anchored_root_resolver
        .anchored_root(store_id_arr)
        .await;
    match requested_root {
        // ROOTED: the requested root must BE the current on-chain generation (#127 anti-rollback).
        // Prefer the lineage walk's tip; a walk aborted by one unparseable intermediate generation
        // (#747 "parse next store: missing child") must NOT block a valid pinned root — fall back to
        // the BOUNDED verify (one launcher-hint query, no walk). Fail-closed either way.
        Some(req) => match &anchored {
            Ok(Some(tip)) if *tip == req => Ok(Some(req)),
            Ok(Some(tip)) => Err((
                ROOT_NOT_ANCHORED,
                format!(
                    "served root {} does not match the store's on-chain root {} (chain is the authority)",
                    req.to_hex(),
                    tip.to_hex()
                ),
            )),
            Ok(None) | Err(_) => match node
                .anchored_root_resolver
                .verify_pinned_root(store_id_arr, req)
                .await
            {
                Ok(()) => Ok(Some(req)),
                Err(msg) => Err((ROOT_NOT_ANCHORED, msg)),
            },
        },
        // ROOTLESS: resolve the chain-anchored tip (the authority) via the shared `decide_pin`.
        None => match decide_pin(true, None, anchored) {
            PinDecision::ServeAt(root) => Ok(Some(root)),
            PinDecision::Reject(code, msg) => Err((code, msg)),
            // `decide_pin(true, ..)` never returns Unpinned.
            PinDecision::Unpinned => Ok(None),
        },
    }
}

#[async_trait::async_trait]
impl RpcDispatch for Node {
    async fn dispatch(
        &self,
        req: Value,
        origin: crate::download::ReadOrigin,
        provenance: crate::download::RequestProvenance,
        requestor: crate::rate_limit::RequestorId,
    ) -> Value {
        // `node` alias: the body below is relocated VERBATIM from the pre-#1285-W1b-5
        // `handle_rpc(node: &Node, req: Value)` free function — byte-identical, just bound to
        // `self` here instead of taking `node` as a parameter.
        let node = self;
        let id = req.get("id").cloned().unwrap_or(json!(1));
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        // Chat subsystem (epic #793). These methods are NOT yet in the shared `dig-rpc-protocol`
        // Method catalogue (promoting them there is a release-first follow-up), so they are dispatched
        // here BEFORE the `Method::from_name` match. They are `served: "local"` in the shell's method
        // catalogue, so the OpenRPC drift guard dispatches them through this path and never sees -32601.
        match method {
            "chat.send" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.chat_send(&params, id).await;
            }
            "chat.poll" => return node.chat_poll(id),
            // cache.pushCapsule (#1476): the publish→seed flywheel front — the store owner hands a
            // freshly-committed capsule to their own node so it becomes a discoverable holder
            // immediately. A dig-node-LOCAL mutator (not a `dig-rpc-protocol` Method): local-only by
            // default, and — when `DIG_NODE_PUSH_OPEN=true` admits it to peers — gated inside the
            // handler by a §21.9 authorized-writer signature. Threads `origin`/`provenance` so the
            // handler can tell a trusted loopback push from an opened peer push. See
            // `seams::capsule::push_capsule`.
            m if m == crate::seams::capsule::PUSH_CAPSULE_METHOD => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                // `requestor` is the non-spoofable transport identity (loopback operator / verified
                // peer_id); the handler keys its pending-reassembly DoS bound on it (#2149).
                return node
                    .push_capsule(&params, id, origin, provenance, requestor)
                    .await;
            }
            // `dig.getPublicManifest` is NOT yet a `dig_rpc_protocol::Method` variant, so — like
            // the chat methods above — it is dispatched here, before the enum match. Promoting it
            // into the shared catalogue is a release-first follow-up on that crate (#2071); until
            // then a node that did not serve it here would answer `-32601` for a method the
            // rpc.dig.net read tier already allowlists and the hub client already calls.
            //
            // SECURITY, and the reason this placement is safe: being absent from the `Method`
            // catalogue ALSO makes it un-peer-reachable, because `is_peer_reachable_method` ends in
            // `Method::from_name(m).is_some_and(..)` — an unknown name is filtered out before the
            // peer surface ever reaches this dispatch. So this arm serves the loopback / in-process
            // / gateway surface only, and a permissionless peer cannot call it. Promoting the
            // method into `dig-rpc-protocol` later MUST therefore make a deliberate decision about
            // `is_peer_reachable()` rather than inherit one: it would otherwise silently widen a
            // public read from the gateway surface to the whole peer network.
            "dig.getPublicManifest" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.get_public_manifest(&params, id).await;
            }
            _ => {}
        }

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
            // dig.getModuleInfo (#1576, the reshare leg): the transfer descriptor for a whole `.dig`
            // module this node HOLDS — total size, whole-blob content id, and the per-chunk hashes a
            // puller attributes each range against. It describes only local content, so it is a read of
            // this node's own cache, never a chain or network call.
            // dig.getProof (#2071): a read's trust half — the inclusion proof + the chain-anchored
            // root it verifies against, no ciphertext. Served by running the ORDINARY getContent
            // read and discarding the bytes, so the proof is provably the one a content read would
            // have verified against (see `Node::get_proof`). Previously a passthrough alias, which
            // meant `-32601` on any node without an upstream.
            Some(Method::GetProof) => {
                return node.get_proof(&req, id, origin, provenance).await;
            }
            // dig.getMetadata (#2071): the publisher's plaintext metadata manifest (data-section
            // id 6) for a capsule. PUBLIC, unencrypted — no retrieval_key, no decrypt.
            Some(Method::GetMetadata) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.get_metadata(&params, id).await;
            }
            // dig.getCapsule / dig.getModule (#2071): one window of a whole `.dig` module this
            // node holds, in the same streaming envelope getContent uses. This node's own capsule
            // downloader has always consumed this shape from an upstream; now it can serve it too.
            Some(Method::GetCapsule) | Some(Method::GetModule) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.get_capsule(&params, id).await;
            }
            Some(Method::GetModuleInfo) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.get_module_info(&params, id, &requestor).await;
            }
            // dig.fetchModuleRange (#1576): one window of a held `.dig` module.
            //
            // On the PEER surface this method STREAMS frames, and the stream router intercepts it
            // before this dispatch is reached (see `peer::classify_request`). Here — the loopback /
            // in-process JSON-RPC surface — it answers with a SINGLE frame in the `result`, because a
            // JSON-RPC envelope has no way to express a stream. Both forms carry the identical frame
            // shape, so an agent can read a module through the machine-friendly request/response form
            // (§6.2) without implementing the frame protocol.
            Some(Method::FetchModuleRange) => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                return node.fetch_module_range_frame(&params, id, &requestor).await;
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
                // Thread the in-scope `requestor` so the not-held → DHT enrichment on this JSON leg is
                // bounded by the SAME per-requestor miss-lookup budget as the single-item legs
                // (dig_ecosystem#2007) — a batch is the largest amplification vector on this path.
                //
                // `redirect_depth` is the hop budget the caller echoed, read with the SAME parser
                // every other redirect leg uses so one field expresses one budget across the whole
                // wire (dig_ecosystem#3128). It bounds how far the not-held enrichment may forward the
                // question across connected pool peers; absent, this is a fresh question at depth 0.
                let budget = crate::download::HopBudget::from_params(&params);
                return json!({"jsonrpc":"2.0","id":id,"result": node.availability_batch(&items, &requestor, budget).await});
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
                // WHOLE-INVENTORY enumeration (`store_id` omitted) is LOOPBACK/CONTROL-ONLY (#2022).
                // The mTLS peer surface is permissionless — the verifier accepts any self-signed leaf,
                // so an "authenticated" peer is merely "some peer_id", never an authorized admin
                // (see peer::is_peer_reachable_method). Handing an arbitrary peer "a free map of
                // everything this node holds" answers a question no honest peer needs: a downloader
                // asks `dig.getAvailability` for the SPECIFIC store/root it wants to fetch. The
                // operator's OWN node must still be able to see what it advertises (the #1934/#2006
                // consent surface precondition), so the `None` form stays reachable — but ONLY from
                // the loopback/FFI/control path (`ReadOrigin::Local`), never over the peer wire.
                if store_id.is_none() && origin == crate::download::ReadOrigin::Peer {
                    return rpc_err(
                        &id,
                        -32601,
                        "dig.listInventory whole-inventory enumeration (store_id omitted) is \
                         loopback-only; a peer must query a specific store_id",
                    );
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
                //
                // Fold the two landing axes ONCE (#1956): a cross-site-driven POST still serves the
                // range bytes, but its miss-path landing legs (the miss-envelope→reshare chain AND the
                // whole-capsule backfill) gate on `land_origin`, so a same-origin capsule page cannot
                // drive this node into becoming a holder. Reads are NEVER altered — only the side effect.
                let land_origin = crate::download::landing_origin(origin, provenance);
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
                // #1764 — the peer-SERVE arm enforces the SAME chain-anchored pin (#127) the READ
                // arms (`dig.getContent`, the local `/s` tier) enforce, via the shared
                // [`resolve_enforced_pin`]. Without it a permissionless peer could fetch ranges of a
                // forged or superseded generation that every local read path already refuses — the
                // serve side answering 200 where `/s` answers `-32005`. The chain, not the
                // client-named `root`, decides which generation is served.
                let store_id_arr: [u8; 32] = match parse_store_id_arg(&params) {
                    // `store_hex` was validated 64-hex above, so this is unreachable; still fail
                    // closed rather than serve an unpinned range.
                    Ok(b) => b.into(),
                    Err(()) => {
                        return rpc_err(
                            &id,
                            -32602,
                            "dig.fetchRange store_id must be a 64-hex launcher id",
                        )
                    }
                };
                let pinned_root = match resolve_enforced_pin(
                    node,
                    &store_id_arr,
                    Bytes32::from_hex(root_hex).ok(),
                )
                .await
                {
                    Ok(root) => root,
                    Err((code, msg)) => return rpc_err(&id, code, &msg),
                };
                // Serve against the resolved pin (the chain tip / verified root). In every ACCEPTED
                // case this equals the client-named root, so the range bytes are unchanged — the
                // gate only REFUSES an unanchored root; it never re-points an accepted read.
                let pinned_root_hex = pinned_root
                    .map(|r| r.to_hex())
                    .unwrap_or_else(|| root_hex.to_string());
                let root_hex = pinned_root_hex.as_str();
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
                                let budget = download::HopBudget::from_params(&params);
                                let proxy = download::proxy_requested(&params);
                                if let Some(envelope) = node
                                    .range_miss_envelope(
                                        &id,
                                        &content,
                                        budget,
                                        offset,
                                        length,
                                        proxy,
                                        land_origin,
                                        &requestor,
                                    )
                                    .await
                                {
                                    // Served from another node — background-backfill the whole capsule so the
                                    // next read is local (SPEC §14.3). Deduped + detached; no delay here.
                                    // `origin` is the SAME gate the reshare leg uses: a peer-origin
                                    // miss must never trigger this pull (#1619 follow-up).
                                    node.maybe_backfill_capsule(store_hex, root_hex, land_origin);
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
                // The breakdown is ADDITIVE beside `used_bytes` (#1886): it is what tells an
                // operator whether those bytes are held CAPSULES (this node is a holder) or
                // merely per-resource response windows (it is not) — the difference between a
                // turning flywheel and a stalled one.
                let usage = cache_usage();
                return json!({"jsonrpc":"2.0","id":id,"result":{
            "cap_bytes": cache_cap_bytes(),
            "used_bytes": usage.total(),
            "capsule_bytes": usage.capsule_bytes,
            "response_bytes": usage.response_bytes,
            "cache_dir": dir.display().to_string(),
            "shared": shared}});
            }
            // control.peerStatus — live, pool-oriented status of the node's L7 peer network (the connected
            // peer pool + the relay reservation for NAT reachability). Read-only; safe before/without a peer
            // network running (then `running:false`). Replaces the retired `control.relayStatus`: relay
            // reachability now lives in dig-nat/dig-gossip and is reported here as the pool's relay flag.
            Some(Method::ControlPeerStatus) => {
                let endpoint = peer::relay_url_from_env();
                let network_id = peer::effective_network_label_from_env();
                let genesis = hex::encode(peer::genesis_challenge_from_env());
                let mut snapshot = node
                    .peer_status
                    .snapshot_json(&endpoint, &network_id, &genesis);
                // Attach the per-peer array so the A↔B mutual-connection proof is machine-checkable (each
                // side lists the OTHER's peer_id), not just a count. Sourced from the live pool handle; empty
                // (and omitted-as-`[]`) on the FFI path / before bring-up. See `peer::connected_peers_json`.
                if let Some(handle) = node.gossip_handle() {
                    snapshot["peers"] = Value::Array(peer::connected_peers_json(handle));
                    // The pool's connectivity posture vs the configured target/min/max (#709/#846) —
                    // the peer-management view an operator needs beyond the per-peer array.
                    snapshot["pool"] = peer::pool_stats_json(handle);
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
                // And drain the process-lifetime decoded-MANIFEST memo (#2145): it is a RAM residency
                // with no TTL that `clear_cache`/`clear_content_cache` did not touch, so without this
                // an operator clearing the cache could not reclaim it.
                clear_manifest_memo();
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
                let usage = cache_usage();
                // #1991 (epic #1934): per-tier occupancy for the relay-globe cached-store count.
                // Tier1 is a REAL figure — the inbound-demand ledger's own bounded-LRU size (§7.10d).
                // Tier0 is now LIVE (§7.10e/f, #1934 PR-3): `wired` flips true once the eager-precache
                // loop is spawned at bring-up, and `occupancy` is that loop's land counter. Tier2
                // (bribed retention) has no live source yet, so it stays `wired: false, occupancy: 0` —
                // a controller distinguishes "empty" from "not measurable yet". The shape is fixed.
                //
                // Hand-built JSON (not the typed `dig_rpc_protocol::CacheStats`): that published crate
                // (0.6.0) predates `refetch_count`/`tiers` and gains them release-first in a follow-up
                // (dig_ecosystem#2024) — out of scope for this dig-node-only change.
                return json!({"jsonrpc":"2.0","id":id,"result":{
                "cap_bytes": cache_cap_bytes(),
                "used_bytes": usage.total(),
                "capsule_bytes": usage.capsule_bytes,
                "response_bytes": usage.response_bytes,
                "entry_count": entry_count,
                "total_bytes": total_bytes,
                "evicted_count": CACHE_EVICTED_COUNT.load(Relaxed),
                "evicted_bytes": CACHE_EVICTED_BYTES.load(Relaxed),
                "refetch_count": CACHE_REFETCH_COUNT.load(Relaxed),
                "content_cache": {
                    "hits": CONTENT_CACHE_HITS.load(Relaxed),
                    "misses": CONTENT_CACHE_MISSES.load(Relaxed),
                },
                "tiers": {
                    "tier0_precache": {
                        "occupancy": crate::tier0_live::tier0_occupancy(),
                        "wired": crate::tier0_live::tier0_wired(),
                    },
                    "tier1_demand": {"occupancy": node.inbound_demand_entry_count(), "wired": true},
                    "tier2_bribed": {"occupancy": 0, "wired": false},
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
                // `module_exists` re-validates the caller's key, so a non-canonical one reports
                // not-already-cached without a path ever being built (#1599).
                let already = crate::module_exists(&node.cache_dir, store_hex, root_hex);
                return match node.cache_fetch_and_cache(store_hex, root_hex).await {
                    Ok((size_bytes, served_root)) => {
                        // A freshly-cached capsule makes this node a discoverable DHT holder — that
                        // re-announce (§14.1) now fires once inside `cache_fetch_and_cache` on the fresh
                        // land, so every caller announces uniformly and this handler needs no explicit
                        // refresh.
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
            // block below the match. What remains unserved here (`dig.getProofStatus`, which polls
            // an execution-proof JOB this node has none of, and `dig.listCapsules`, which needs a
            // chain generation walk — both tracked on #2071), plus the shell-answered discovery
            // methods (health / methods / rpc.discover) and any unknown method, fall through to
            // method-not-found; the shell relays those to an upstream when one is configured.
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
        let store_id_arr: [u8; 32] = match parse_store_id_arg(&params) {
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
        // The mandatory chain-anchored pin (#127), resolved through the SAME shared
        // [`resolve_enforced_pin`] the `dig.fetchRange` peer-serve arm uses (#1764) — one policy,
        // no drift between the read and serve paths.
        let pinned_root: Option<Bytes32> =
            match resolve_enforced_pin(node, &store_id_arr, requested_root).await {
                Ok(root) => root,
                Err((code, msg)) => return err(&id, code, msg),
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
            //     PROVENANCE (dig-node#436): this land is remote-triggerable with no feature flag in
            //     front of it -- a stranger asking for content this node does not hold makes it pull
            //     a whole capsule -- so a non-`Local` read lands `Suppress`. It is cached and served
            //     to the requestor exactly as before; it is simply never advertised and never bonded
            //     against, because it is not this operator's content. A `Local` read keeps `Announce`,
            //     which is the reshare flywheel: the operator's own read leaves content more
            //     available than it found it.
            let claim = holder_claim_for_read(origin, provenance);
            if node
                .sync_module_and_bound(store_hex, &root_hex, claim)
                .await
            {
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
            let budget = download::HopBudget::from_params(&params);
            let proxy = download::proxy_requested(&params);
            let pin_hex = pinned_root.map(|r| r.to_hex());
            // Fold the two landing axes ONCE (#1956): a cross-site-driven `dig.getContent` POST still
            // serves the bytes, but the miss-path landing legs (the miss-envelope→`fetch_resource`→
            // reshare chain AND the whole-capsule backfill) gate on `land_origin`, so a same-origin
            // capsule page cannot drive landing. Reads are NEVER altered — only the side effect.
            let land_origin = crate::download::landing_origin(origin, provenance);
            if let Some(envelope) = node
                .content_miss_envelope(
                    &id,
                    &content,
                    budget,
                    offset,
                    pin_hex.as_deref(),
                    proxy,
                    land_origin,
                    &requestor,
                )
                .await
            {
                // This resource is being served FROM ANOTHER NODE (a redirect/fetch-through). In the
                // background, ALSO pull the whole `.dig` capsule for this generation so the NEXT read of
                // the store is served locally (SPEC §14.3, `DIG_NODE_BACKFILL_ON_MISS`, default on). This
                // does not delay the current response — it spawns a deduped detached pull and returns.
                // `origin` is the SAME gate the reshare leg uses: a peer-origin miss must never
                // trigger this pull (#1619 follow-up).
                node.maybe_backfill_capsule(store_hex, &root_hex, land_origin);
                return envelope;
            }
        }

        // 3. MISS: proxy to the CONFIGURED upstream, then cache the result window (LRU-capped)
        //    so the next load of this resource is served locally.
        //
        //    There is NO upstream by default (#1997). Without one this leg does not run at all and
        //    the miss is reported as `-32004` — the catalogued "not available at this root" answer
        //    the read path already uses for content it does not hold. Reporting a configuration
        //    error instead would blame the operator's setup for a resource that no node offered.
        //
        //    The upstream request is pinned to the anchored root (rewriting/forcing
        //    `params.root`), and the upstream-returned root is re-checked against the
        //    pin — so even on the proxy path the node never serves a generation the
        //    chain did not confirm.
        if !node.has_upstream() {
            return err(
                &id,
                RESOURCE_NOT_AVAILABLE,
                "resource not available: this node does not hold it and no peer served it"
                    .to_string(),
            );
        }
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

/// Which holder claim a `dig.getContent` miss-backfill lands under, decided from the read's origin.
///
/// This is the eleventh cache-write path (dig-node#436). `dig.getContent` for a capsule this node
/// does not hold funnels through [`Node::sync_module_and_bound`] to `write_atomic`, reaching the
/// cache WITHOUT passing `cache_fetch_and_cache` or `land_capsule_bytes`. It is remote-triggerable
/// and behind no feature flag, so a stranger requesting content this node does not hold makes it
/// pull a whole capsule — which, landed unmarked, would be `Held`: the bondable state a mirror coin
/// is minted against.
///
/// A remote read therefore lands [`HolderClaim::Suppress`]. The capsule is still cached and still
/// served to the requestor, exactly as before; it is simply never advertised and never bonded
/// against, because it is not this operator's content.
///
/// A `Local` read keeps [`HolderClaim::Announce`], and that asymmetry is the point rather than an
/// oversight: the operator's own read leaves content more available than it found it, which is the
/// reshare flywheel. Suppressing every land through the shared choke point would satisfy the remote
/// case while silently disabling that.
///
/// Extracted as a named function rather than left inline so the decision is testable on its own —
/// an end-to-end assertion on the landed marker passes for many reasons, only one of which is this
/// mapping being right.
fn holder_claim_for_read(
    origin: crate::download::ReadOrigin,
    provenance: crate::download::RequestProvenance,
) -> crate::seams::dig_peer::HolderClaim {
    // BOTH axes, folded through `landing_origin` exactly as every other landing decision in this
    // file does (`dispatch.rs:381`, `:953`, `content_serve.rs:366`, `push_capsule.rs:272`). The
    // transport axis alone is NOT sufficient, and reading it alone was a real exploit: a browser
    // page served from `dig.local` -- or any extension origin -- can POST `dig.getContent` to the
    // loopback port, which CORS admits, so the request arrives over a genuinely local socket
    // (`origin = Local`, un-spoofable and correct) while being made on a STRANGER's behalf
    // (`provenance = CrossSite`). Deciding on `origin` alone announced that stranger's chosen
    // capsule as this operator's own, and -- because `Announce` REMOVES an existing marker -- could
    // additionally un-suppress a capsule already correctly relayed.
    //
    // The fold is only ever restrictive (`CrossSite` -> `Peer`, `FirstParty` -> unchanged), so it
    // cannot cost the operator their own flywheel.
    match crate::download::landing_origin(origin, provenance) {
        crate::download::ReadOrigin::Local => crate::seams::dig_peer::HolderClaim::Announce,
        // Every non-local landing origin is someone else's request, so its backfill is someone
        // else's content. The wildcard is the safe direction: a new origin variant lands
        // SUPPRESSED, i.e. unbonded.
        _ => crate::seams::dig_peer::HolderClaim::Suppress,
    }
}

#[cfg(test)]
mod holder_claim_tests {
    use super::holder_claim_for_read;
    use crate::download::{ReadOrigin, RequestProvenance};
    use crate::seams::dig_peer::HolderClaim;

    /// **Proves (dig-node#436, the eleventh path):** a read arriving from a PEER backfills
    /// unbonded.
    ///
    /// Before the fix this path landed with no claim at all, which reads as `Held` — so a stranger
    /// could make this node stake its $DIG on content the stranger chose, in a default install.
    ///
    /// **Catches:** any relaxation of the remote arm back toward `Announce`.
    #[test]
    fn a_peer_read_backfills_suppressed() {
        assert_eq!(
            holder_claim_for_read(ReadOrigin::Peer, RequestProvenance::FirstParty),
            HolderClaim::Suppress,
            "a capsule pulled because a STRANGER asked for it is not this operator's content"
        );
    }

    /// **The control.** The operator's own read must stay bondable, or the fix has disabled the
    /// reshare flywheel for this node's own content while fixing the remote case.
    ///
    /// **Catches:** a blanket suppression of the shared choke point.
    #[test]
    fn a_local_read_backfills_announced() {
        assert_eq!(
            holder_claim_for_read(ReadOrigin::Local, RequestProvenance::FirstParty),
            HolderClaim::Announce,
            "the operator's own read leaves content more available than it found it"
        );
    }
    /// **Proves (dig-node#436, the confused deputy):** a request arriving over a genuinely LOCAL
    /// socket but made on a STRANGER's behalf backfills unbonded.
    ///
    /// This is the finding the first version of this fix missed, and the reason the decision folds
    /// both axes instead of reading `origin` alone. A page served from `dig.local` — or any
    /// extension origin — can POST `dig.getContent` to the loopback port; CORS admits it, so the
    /// transport axis says `Local` and says so *correctly*. Only `provenance` distinguishes "the
    /// operator asked for this" from "a web page asked for this using the operator's browser".
    ///
    /// Deciding on `origin` alone let an attacker-chosen capsule land bondable in a default
    /// install, and — since `Announce` REMOVES an existing marker — un-suppress a capsule already
    /// correctly relayed.
    ///
    /// **Catches:** any regression to a single-axis decision here. Both sibling tests in this
    /// module pass with that bug present, which is precisely why this one exists.
    #[test]
    fn a_cross_site_read_over_a_local_socket_backfills_suppressed() {
        assert_eq!(
            holder_claim_for_read(ReadOrigin::Local, RequestProvenance::CrossSite),
            HolderClaim::Suppress,
            "a local socket driven by a stranger's page is a confused deputy, not the operator"
        );
    }

    /// **The fold is restrictive-only.** A cross-site request that already arrived from a peer
    /// stays suppressed — the fold can never *widen* a claim, so it cannot cost the operator their
    /// own flywheel.
    #[test]
    fn a_cross_site_peer_read_stays_suppressed() {
        assert_eq!(
            holder_claim_for_read(ReadOrigin::Peer, RequestProvenance::CrossSite),
            HolderClaim::Suppress,
            "folding both axes is only ever restrictive"
        );
    }
}
