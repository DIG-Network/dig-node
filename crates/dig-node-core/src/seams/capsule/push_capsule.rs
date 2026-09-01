//! `cache.pushCapsule` — the node-side of the publish→seed flywheel front (#1476).
//!
//! # What this is
//!
//! A LOCAL JSON-RPC mutation that lets the store owner hand a freshly-committed `.dig` capsule
//! straight to their own node's cache, so the node becomes a discoverable DHT holder the instant the
//! content is published (the seed→discoverable invariant, #1429/#1423) — instead of waiting for some
//! other node to be asked for it first. It mirrors [`dig.getCapsule`](super::capsule_download) in
//! reverse: the bytes arrive in ≤3 MiB base64 windows the node reassembles by `offset` until the
//! declared `total_length` is met, then it VERIFIES and LANDS them through the ONE shared land site
//! ([`Node::land_capsule_bytes`]), which announces the holder exactly once.
//!
//! # The two trust postures (SECURITY-CRITICAL, #1476 D2/D3)
//!
//! `cache.pushCapsule` is a MUTATOR. Like every `cache.*`/`control.*` method it is **local-only by
//! default**: it is deliberately absent from the peer allowlist ([`is_peer_reachable_method`]), so the
//! mTLS `NodeResponder` answers a peer `-32601` before dispatch (audit #179). A loopback/FFI push is
//! then trusted-by-locality — the local operator owns the node, exactly as they do for `cache.clear`.
//!
//! Setting **`DIG_NODE_PUSH_OPEN=true`** admits the method to the peer surface. Locality no longer
//! implies authority there, so an OPENED push MUST additionally prove the caller is the store's
//! **§21.6/§21.9 authorized writer** for the TARGET store:
//! 1. the pushed module commits a publisher public key whose `SHA-256` DERIVES `store_id`
//!    (`store_id = sha256(publisher_pubkey)`, the DIG store-identity derivation `init_store`/`dig.stage`
//!    use) — this binds the signature below to THIS store, so a valid signature under some other key
//!    the caller merely owns cannot authorize a push here; and
//! 2. the request carries a BLS signature over `SHA-256(root || store_id)` that
//!    [`verify_push_signature`] accepts under that key.
//!
//! The merkle-integrity check ([`verify_capsule_integrity`]) proves the bytes are internally a genuine
//! `.dig` committing the requested `(store_id, root)` — that is INTEGRITY, never AUTHORITY. Without the
//! writer check an opened node would be an unauthenticated cache-poison + DHT-announce-amplification
//! surface (the #179/#1576 class), because an attacker can craft a self-consistent `.dig` declaring any
//! `(store_id, root)`. The signature is the gate that makes that impossible: forging it needs the
//! store's secret key.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use digstore_core::datasection::{DataView, SectionId};
use digstore_core::{Bytes32, Bytes48, Bytes96};
use digstore_remote::verify_push_signature;
use serde_json::{json, Value};

use crate::download::{landing_origin, ReadOrigin, RequestProvenance};
use crate::rate_limit::RequestorId;
use crate::seams::dig_peer::ChainAnchoredModuleVerifier;
use crate::{CapsuleKey, InMemoryModule, Node};

use super::MAX_CAPSULE_BYTES;

/// The catalogued JSON-RPC error a push is refused with when it would exceed ANY in-flight
/// reassembly bound — the per-requestor cap, the global cap, or the global pending-bytes budget
/// (dig_ecosystem#2149). A DEDICATED code in the bounded/resource-limit cluster, distinct from the
/// miss-lookup `-32003` and from `-32015 METADATA_TOO_LARGE` (a different bounded condition on
/// `dig.getMetadata`): the condition here is not "you are asking too fast" but "this node is holding
/// too much unfinished push state to accept another window right now". The caller SHOULD complete or
/// abandon an in-flight push, or retry after backing off; an abandoned partial frees its slot after
/// [`PENDING_PUSH_TTL`]. Catalogued symbolically as `PUSH_PENDING_LIMITED` (see
/// `dig_node_service::meta::ErrorCode`).
pub(crate) const PUSH_PENDING_LIMITED: i64 = -32016;

/// The most concurrent in-flight (incomplete) pushes ONE requestor may hold open at once
/// (dig_ecosystem#2149). A legitimate publisher seeds a handful of freshly-committed stores in
/// parallel; eight distinct simultaneous partial uploads is already well beyond an honest workload,
/// while being small enough that the per-requestor share of reassembly memory stays modest. Keyed on
/// the non-spoofable transport identity ([`RequestorId::key`]), so one opened peer flooding distinct
/// `(store_id, root)` partials exhausts only ITS OWN slots — a different peer is untouched.
const MAX_PENDING_PUSHES_PER_REQUESTOR: usize = 8;

/// The most concurrent in-flight pushes across ALL requestors (dig_ecosystem#2149). Bounds the
/// reassembly table so a caller cycling identities (fresh self-signed mTLS leaves under
/// `DIG_NODE_PUSH_OPEN`) cannot grow it without bound past the per-requestor cap. Sized as
/// `MAX_PENDING_PUSHES_PER_REQUESTOR` × 32 authorized writers' worth of parallel seeding — generous
/// for a real multi-peer seed host, yet a hard ceiling on entry proliferation. The pending-BYTES
/// budget below is the true memory bound; this caps the count/overhead.
const MAX_GLOBAL_PENDING_PUSHES: usize = 256;

/// The global ceiling on bytes buffered across ALL in-flight partial pushes (dig_ecosystem#2149).
/// This is the real memory bound: each window arrives ≤ the 64 KiB transport frame cap, but windows
/// accumulate toward the declared `total_length` (up to [`MAX_CAPSULE_BYTES`]), so without an
/// aggregate budget many never-completed partials would pin memory until restart. 512 MiB admits
/// several full-capsule reassemblies (a compiled module is ~128 MiB) in parallel on a real host while
/// capping the worst case; a window that would push the aggregate past this is refused BEFORE its
/// bytes are buffered (fail-closed).
const MAX_PENDING_PUSH_BYTES: usize = 512 * 1024 * 1024;

/// How long an in-flight partial may sit WITHOUT advancing before the reaper evicts it
/// (dig_ecosystem#2149). A genuine multi-window push advances every network round-trip, so 60 s
/// between windows is far beyond any honest gap yet promptly reclaims the slot + bytes of a partial
/// an attacker (or a crashed client) opened and abandoned. Eviction is lazy: every push call reaps
/// expired partials first, so no background task is needed.
const PENDING_PUSH_TTL: Duration = Duration::from_secs(60);

/// The dig-node-LOCAL method name. NOT a `dig-rpc-protocol` `Method` variant: that crate is a
/// crates.io pin this repo cannot extend, and — being a mutator — the method is deliberately kept OUT
/// of the shared peer allowlist anyway (see the module docs / #1476 D2). Dispatched by string in
/// [`RpcDispatch::dispatch`](crate::seams::dig_rpc) BEFORE the `Method::from_name` match, exactly like
/// `chat.send`.
pub(crate) const PUSH_CAPSULE_METHOD: &str = "cache.pushCapsule";

/// The env flag that OPENS `cache.pushCapsule` to the peer/mTLS surface (default `false` = local-only).
///
/// Kept dig-node-LOCAL — deliberately NOT in `dig-constants`: only dig-node reads it, and promoting a
/// single node's operational toggle into a foundation crate would force a needless release-first
/// cascade (the canonical anti-over-coupling rule). Read live from the environment so an operator can
/// flip it without recompiling.
pub(crate) const PUSH_OPEN_ENV: &str = "DIG_NODE_PUSH_OPEN";

/// Whether the operator has OPENED `cache.pushCapsule` to remote peers (`DIG_NODE_PUSH_OPEN=true`).
///
/// Only an explicit, case-insensitive `true`/`1` opens it; anything else — unset, empty, `false`, an
/// unknown value — keeps it local-only (fail-safe default).
pub(crate) fn push_open_enabled() -> bool {
    matches!(
        std::env::var(PUSH_OPEN_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true"
    )
}

/// One in-flight chunked push, keyed by `(cache_dir, capsule)` so two nodes sharing a process (the
/// test harness) never cross-contaminate. Bounded by `total_length ≤ MAX_CAPSULE_BYTES`, validated
/// before the first byte is buffered.
struct PendingPush {
    /// The capsule's declared total byte length, committed on the FIRST window and constant after.
    total_length: u64,
    /// The bytes assembled so far. `buf.len()` is the next expected `offset` — pushes are strictly
    /// forward with no gaps or overlaps.
    buf: Vec<u8>,
    /// The non-spoofable requestor ([`RequestorId::key`]) that opened this partial, so the
    /// per-requestor concurrent-push cap counts only a given peer's OWN in-flight entries
    /// (dig_ecosystem#2149).
    requestor: String,
    /// When this partial last advanced (opened or extended). Drives the [`PENDING_PUSH_TTL`] reaper
    /// that reclaims abandoned partials (dig_ecosystem#2149).
    last_activity: Instant,
}

/// The bounded, process-wide table of in-flight chunked pushes (dig_ecosystem#2149). Holds transient
/// per-capsule reassembly state — a completed or abandoned push is removed — under a `std::sync::Mutex`
/// (never held across an `.await`). The bounds (per-requestor / global entry caps + a global
/// pending-bytes budget + a TTL reaper) turn the previously-unbounded `cache.pushCapsule` open surface
/// into one that can pin only a fixed amount of memory. The limits are fields (not bare consts) so the
/// tests can construct a small, deterministic instance instead of allocating production-sized budgets.
struct PendingPushes {
    entries: HashMap<(PathBuf, CapsuleKey), PendingPush>,
    max_per_requestor: usize,
    max_global: usize,
    max_bytes: usize,
    ttl: Duration,
}

impl PendingPushes {
    /// A table at the production bounds ([`MAX_PENDING_PUSHES_PER_REQUESTOR`] /
    /// [`MAX_GLOBAL_PENDING_PUSHES`] / [`MAX_PENDING_PUSH_BYTES`] / [`PENDING_PUSH_TTL`]).
    fn with_defaults() -> Self {
        Self {
            entries: HashMap::new(),
            max_per_requestor: MAX_PENDING_PUSHES_PER_REQUESTOR,
            max_global: MAX_GLOBAL_PENDING_PUSHES,
            max_bytes: MAX_PENDING_PUSH_BYTES,
            ttl: PENDING_PUSH_TTL,
        }
    }

    /// Evict every partial that has not advanced within [`Self::ttl`] as of `now`. Called at the top
    /// of every window so an abandoned partial's slot + bytes are reclaimed lazily, without a
    /// background task.
    fn reap_expired(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, p| now.duration_since(p.last_activity) < ttl);
    }

    /// Bytes buffered across ALL in-flight partials right now — the quantity the global byte budget
    /// bounds. Recomputed on demand (the table is small — bounded by [`Self::max_global`]) rather than
    /// tracked incrementally, so no counter can drift out of step with the map.
    fn buffered_bytes(&self) -> usize {
        self.entries.values().map(|p| p.buf.len()).sum()
    }

    /// How many in-flight partials `requestor` currently owns — the per-requestor cap's measure.
    fn count_for(&self, requestor: &str) -> usize {
        self.entries
            .values()
            .filter(|p| p.requestor == requestor)
            .count()
    }

    /// Decide whether one incoming window may be buffered, WITHOUT mutating the entry set — the single
    /// place every DoS bound (dig_ecosystem#2149) is enforced, so the handler and the tests agree by
    /// construction. Reaps expired partials first (so a stalled attacker cannot hold slots past the
    /// TTL), then, for a NEW `(cache_dir, capsule)`, enforces the global then per-requestor entry caps,
    /// and finally the global byte budget for EVERY window. Fail-closed: a refusal happens before any
    /// bytes are buffered.
    fn admit_window(
        &mut self,
        map_key: &(PathBuf, CapsuleKey),
        requestor: &str,
        incoming_len: usize,
        now: Instant,
    ) -> Result<(), &'static str> {
        self.reap_expired(now);
        if !self.entries.contains_key(map_key) {
            if self.entries.len() >= self.max_global {
                return Err(
                    "too many concurrent pending pushes on this node; retry after in-flight pushes complete",
                );
            }
            if self.count_for(requestor) >= self.max_per_requestor {
                return Err(
                    "too many concurrent pending pushes for this requestor; complete or abandon one first",
                );
            }
        }
        if self.buffered_bytes() + incoming_len > self.max_bytes {
            return Err(
                "the pending-push memory budget is exhausted; retry after in-flight pushes complete",
            );
        }
        Ok(())
    }
}

/// The process-wide bounded pending-push table (dig_ecosystem#2149). One instance for the whole
/// process; entries are keyed by `(cache_dir, capsule)`, so two nodes sharing a process never
/// cross-contaminate.
fn pending_pushes() -> &'static Mutex<PendingPushes> {
    static PENDING: OnceLock<Mutex<PendingPushes>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(PendingPushes::with_defaults()))
}

impl Node {
    /// Handle one `cache.pushCapsule` window (#1476). See the module docs for the wire + trust model.
    ///
    /// `origin`/`provenance` are threaded from the transport (never inferred): a loopback/FFI push is
    /// [`ReadOrigin::Local`] and trusted-by-locality; a push admitted to the peer surface by
    /// `DIG_NODE_PUSH_OPEN` is [`ReadOrigin::Peer`] and must carry a §21.9 authorized-writer signature.
    /// A cross-site loopback request folds to `Peer` too ([`landing_origin`]), so a malicious web page
    /// can never drive an unauthenticated seed-push through the loopback shell.
    pub(crate) async fn push_capsule(
        &self,
        params: &Value,
        id: Value,
        origin: ReadOrigin,
        provenance: RequestProvenance,
        requestor: RequestorId,
    ) -> Value {
        let err = |code: i64, msg: &str| crate::seams::dig_rpc::errors::error_frame(&id, code, msg);

        let store_hex = params.get("store_id").and_then(Value::as_str).unwrap_or("");
        let root_hex = params.get("root").and_then(Value::as_str).unwrap_or("");
        let Some(key) = CapsuleKey::parse(store_hex, root_hex) else {
            return err(-32602, "store_id and root must each be 64-hex");
        };
        // `parse` proved both are canonical 64-hex, so these both succeed.
        let (Ok(store_id), Ok(root)) = (Bytes32::from_hex(store_hex), Bytes32::from_hex(root_hex))
        else {
            return err(-32602, "store_id and root must each be 64-hex");
        };

        // Authority axis: a request that did NOT arrive first-party over the loopback/FFI transport
        // must prove authorized-writer. Peer reachability is gated separately (open mode), but this
        // handler enforces the writer check itself so it can never be reached without one.
        let require_auth = landing_origin(origin, provenance) == ReadOrigin::Peer;

        // Decode this window's bytes.
        let data_b64 = params.get("data").and_then(Value::as_str).unwrap_or("");
        let Ok(data) = base64::engine::general_purpose::STANDARD.decode(data_b64) else {
            return err(-32602, "params.data is not valid base64");
        };
        let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
        // A single-shot push omits total_length: the one window IS the whole capsule.
        let total_length = params
            .get("total_length")
            .and_then(Value::as_u64)
            .unwrap_or(data.len() as u64);
        if total_length > MAX_CAPSULE_BYTES {
            return err(-32602, "declared total_length exceeds the capsule ceiling");
        }

        // Parse the §21.9 push signature if present (192-hex = 96 bytes). Its ABSENCE is only fatal on
        // the authority-required path — a local push needs none.
        let signature = match params.get("signature").and_then(Value::as_str) {
            Some(s) => match Bytes96::from_hex(s) {
                Ok(sig) => Some(sig),
                Err(_) => {
                    return err(
                        -32602,
                        "params.signature must be 192-hex (a 96-byte BLS signature)",
                    )
                }
            },
            None => None,
        };
        if require_auth && signature.is_none() {
            // Refuse BEFORE buffering a single byte from an unauthenticated peer.
            return err(
                -32001,
                "cache.pushCapsule over the peer surface requires a §21.9 authorized-writer signature",
            );
        }

        // Idempotent (#1476 D4/f): already a holder → report complete without re-accumulating or
        // re-announcing. Also drop any stale partial upload for this capsule.
        if crate::module_exists(&self.cache_dir, store_hex, root_hex) {
            pending_pushes()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .remove(&(self.cache_dir.clone(), key.clone()));
            let size = std::fs::metadata(key.module_path(&self.cache_dir))
                .map(|m| m.len())
                .unwrap_or(total_length);
            return json!({"jsonrpc":"2.0","id":id.clone(),"result":{
                "offset": total_length,
                "complete": true,
                "next_offset": Value::Null,
                "size_bytes": size,
                "served_root": root_hex,
                "already_cached": true,
            }});
        }

        // Reassemble this window into the in-flight buffer. On the completing window, take the whole
        // buffer OUT of the table so the verify+land below runs on owned bytes with no lock held.
        let requestor_key = requestor.key();
        let bytes = {
            let now = Instant::now();
            let mut table = pending_pushes().lock().unwrap_or_else(|p| p.into_inner());
            let map_key = (self.cache_dir.clone(), key.clone());

            // DoS bounds (dig_ecosystem#2149): refuse a push that would exceed any reassembly bound
            // BEFORE buffering its bytes (fail-closed). All bound logic + the TTL reap lives in
            // `admit_window`, the one place the caps are enforced.
            if let Err(msg) = table.admit_window(&map_key, &requestor_key, data.len(), now) {
                return err(PUSH_PENDING_LIMITED, msg);
            }

            let pending = table
                .entries
                .entry(map_key.clone())
                .or_insert_with(|| PendingPush {
                    total_length,
                    buf: Vec::new(),
                    requestor: requestor_key.clone(),
                    last_activity: now,
                });
            // total_length is a commitment made on the first window; a later disagreement is a caller
            // rewriting the push mid-flight.
            if pending.total_length != total_length {
                table.entries.remove(&map_key);
                return err(-32602, "total_length changed mid-push");
            }
            // Strict forward progress: the only accepted offset is exactly where the buffer stands, so
            // a gap can never leave a hole and an overlap can never silently rewrite earlier bytes.
            if offset != pending.buf.len() as u64 {
                return err(
                    -32602,
                    "offset does not continue the push where it left off",
                );
            }
            if offset + data.len() as u64 > pending.total_length {
                table.entries.remove(&map_key);
                return err(-32602, "chunk overflows the declared total_length");
            }
            pending.buf.extend_from_slice(&data);
            pending.last_activity = now;
            let assembled = pending.buf.len() as u64;
            if assembled < pending.total_length {
                // Ack this window and ask for the next; nothing lands until the capsule is whole.
                return json!({"jsonrpc":"2.0","id":id.clone(),"result":{
                    "offset": offset,
                    "complete": false,
                    "next_offset": assembled,
                    "size_bytes": assembled,
                }});
            }
            // Whole: remove and own the buffer.
            table
                .entries
                .remove(&map_key)
                .map(|p| p.buf)
                .unwrap_or(data)
        };

        // INTEGRITY (D1): the bytes must be a genuine `.dig` committing exactly (store_id, root).
        if let Err(reason) = verify_capsule_integrity(&bytes, store_id, root).await {
            return err(-32602, &reason);
        }

        // AUTHORITY (D3): only enforced on the opened peer surface — a loopback push is trusted by
        // locality. This is the leg that turns "internally consistent bytes" into "the store's owner
        // said so"; see the module docs for why integrity alone is not authorization.
        if require_auth {
            let sig =
                signature.expect("require_auth implies a signature was supplied (checked above)");
            if let Err(reason) = verify_push_authority(&bytes, store_id, root, &sig) {
                return err(-32001, &reason);
            }
        }

        // LAND through the ONE shared site: write + announce-once + size-cap sweep, idempotent. Held
        // under `cache_lock` so a concurrent pull-land of the same capsule cannot race the write.
        let _guard = self.cache_lock.lock().await;
        // PROVENANCE (dig-node#436). A push that arrived over the PEER surface is content a remote
        // party asked this node to keep; it is not this operator's capsule, so it is cached and served
        // but never announced and never bonded against.
        //
        // The authorized-writer signature checked above does NOT change that, and the distinction is
        // easy to collapse: provenance does not answer "is this content legitimate" — authority
        // already answered that — it answers "should THIS operator stake THEIR money on it". A third
        // party who owns the store's key is entitled to push; they are not thereby entitled to spend
        // the node operator's $DIG. Only a LOCAL push is the operator speaking for themselves.
        //
        // BOTH axes, via the shared `holder_claim_for_landing` — the same fold line 272 above
        // already applies to the AUTHORITY check in this very function. Reading `origin` alone here
        // while folding it there was a real hole: a cross-site page POSTing `cache.pushCapsule` to
        // the loopback port arrives `origin = Local` (true, and un-spoofable) with
        // `provenance = CrossSite`, so the authority check correctly demanded an authorized-writer
        // signature while the provenance check handed the capsule `Announce`. Creating a store is
        // permissionless, so "owns a store key" is not a trust boundary.
        let claim = crate::seams::dig_rpc::holder_claim_for_landing(origin, provenance);
        match self.land_capsule_bytes(&key, &bytes, claim).await {
            Ok((size, _fresh)) => json!({"jsonrpc":"2.0","id":id.clone(),"result":{
                "offset": total_length,
                "complete": true,
                "next_offset": Value::Null,
                "size_bytes": size,
                "served_root": root_hex,
            }}),
            Err(e) => err(-32603, &format!("could not land the pushed capsule: {e}")),
        }
    }
}

/// INTEGRITY gate (#1476 D1): the pushed bytes must be a genuine `.dig` module committing exactly the
/// requested `(store_id, root)`.
///
/// Reuses the SAME digstore-bound verifier every other land runs
/// ([`ChainAnchoredModuleVerifier`]): it rejects an empty/unparseable blob and checks the module's OWN
/// committed `StoreId`/`CurrentRoot` sections (decoded, byte-compared) against the requested pair. Here
/// the root is the WRITER-ATTESTED requested root, not a chain-resolved one — for a push, AUTHORITY
/// (the §21.9 writer signature, `verify_push_authority`) is the trust anchor, and this gate provides
/// only integrity: the bytes are self-consistently the capsule they claim to be.
async fn verify_capsule_integrity(
    bytes: &[u8],
    store_id: Bytes32,
    root: Bytes32,
) -> Result<(), String> {
    use dig_download::{ModuleAnchor, ModuleAnchorVerifier};
    let verifier = ChainAnchoredModuleVerifier::for_generation(store_id, root);
    let reader = InMemoryModule(bytes.to_vec());
    match verifier
        .verify_module_anchor(&reader, &store_id.to_hex(), &root.to_hex())
        .await
    {
        ModuleAnchor::Anchored => Ok(()),
        ModuleAnchor::NotAnchored => {
            Err("the pushed bytes do not commit the declared (store_id, root)".to_string())
        }
        ModuleAnchor::Unavailable(reason) => {
            Err(format!("could not verify the pushed capsule: {reason}"))
        }
    }
}

/// AUTHORITY gate (#1476 D3): the caller is the store's §21.6/§21.9 authorized writer.
///
/// Two bound checks, both required:
/// 1. the module commits a 48-byte publisher public key whose `SHA-256` equals `store_id`
///    (`store_id = sha256(publisher_pubkey)` — the DIG store-identity derivation). This BINDS the
///    signature to THIS store; without it, a valid signature under an unrelated key the caller happens
///    to hold would authorize a push to a store they do not own.
/// 2. the request signature verifies over `SHA-256(root || store_id)` under that key
///    ([`verify_push_signature`], the canonical §21.6 push message). Forging it requires the store's
///    secret key, which is what makes an opened node safe against cache-poison.
fn verify_push_authority(
    bytes: &[u8],
    store_id: Bytes32,
    root: Bytes32,
    signature: &Bytes96,
) -> Result<(), String> {
    // A pushed module is a full `.dig` container OR a bare DIGS data-section blob; accept either as a
    // real parse (never a silent fallback on garbage), exactly as the anchor verifier does.
    let blob = digstore_compiler::extract_data_section_blob(bytes)
        .ok()
        .or_else(|| DataView::parse(bytes).ok().map(|_| bytes.to_vec()))
        .ok_or("the pushed blob is neither a .dig container nor a DIGS data section")?;
    let view = DataView::parse(&blob).map_err(|_| "the module's data section does not parse")?;

    let pk_bytes = view
        .section(SectionId::PublicKey)
        .ok_or("the pushed module commits no publisher public key")?;
    if pk_bytes.len() != Bytes48::LEN {
        return Err("the committed publisher public key is not 48 bytes".to_string());
    }
    let mut pk_arr = [0u8; Bytes48::LEN];
    pk_arr.copy_from_slice(pk_bytes);
    let publisher_pk = Bytes48(pk_arr);

    // store-identity binding: store_id MUST be sha256(publisher pubkey).
    if digstore_crypto::sha256(publisher_pk.as_bytes()).0 != store_id.0 {
        return Err("the committed publisher key does not derive this store_id".to_string());
    }

    // §21.6 authorized-writer: a BLS signature over SHA-256(root || store_id) under the store key.
    if !verify_push_signature(&publisher_pk, &root, &store_id, signature) {
        return Err("the signature is not from the store's authorized writer".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use digstore_core::datasection::{
        encode_blob, encode_chunk_pool, encode_key_table, encode_merkle_nodes,
    };
    use digstore_core::merkle::{resource_leaf, MerkleTree};
    use digstore_core::serving::concat_output;
    use digstore_core::KeyTableEntry;

    use crate::seams::dig_peer::peer_network::PeerNetwork;

    /// A FAITHFUL `.dig` data-section blob committing `(store_id, root, publisher_pk)` whose `ChunkPool`
    /// content actually recomputes to the committed `root`, plus filler to reach `min_len` bytes —
    /// enough for the anchor verifier AND the authority check, and (with a large `min_len`) a
    /// multi-window fixture. Returns `(blob, root)`: the root is DERIVED from the content (a preimage
    /// of an arbitrary root cannot be chosen), so callers use the returned root as the capsule's root.
    ///
    /// Mirrors the producer recipe (`module_anchor.rs::honest_capsule_blob`): one resource with a
    /// `seed`-derived `static_key` and a single content chunk; its leaf is
    /// `resource_leaf(concat_output(cts))`, the one-leaf tree's root IS the committed root, and the
    /// `KeyTable`/`ChunkPool`/`MerkleNodes` are mutually consistent — the shape a genuine capsule has,
    /// so the admit gate's rule-5 recompute admits it. A capsule whose ChunkPool does NOT recompute is
    /// refused; `push_module_bad_merkle` builds that shape.
    fn push_module(store: [u8; 32], pk: &Bytes48, seed: u8, min_len: usize) -> (Vec<u8>, [u8; 32]) {
        let chunk = format!("faithful capsule content for seed {seed:#04x}").into_bytes();
        let leaf = resource_leaf(&concat_output(&[chunk.as_slice()]));
        let leaves = vec![leaf];
        let root = MerkleTree::from_leaves(leaves.clone()).root().0;
        let entries = vec![KeyTableEntry {
            static_key: Bytes32([seed; 32]),
            generation: Bytes32(root),
            chunk_indices: vec![0],
            total_size: chunk.len() as u64,
        }];

        let mut sections = vec![
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::PublicKey as u16, pk.0.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&entries)),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[chunk.as_slice()]),
            ),
            (SectionId::MerkleNodes as u16, encode_merkle_nodes(&leaves)),
        ];
        if min_len > 0 {
            sections.push((SectionId::Filler as u16, vec![0x5a; min_len]));
        }
        (encode_blob(&sections), root)
    }

    /// Like [`push_module`] but the `ChunkPool` content recomputes to a DIFFERENT root than the
    /// committed `CurrentRoot` — a header-matching-but-tampered capsule (#2246/#2240). The committed
    /// header commits the caller's `root` (so a byte-compare on `CurrentRoot` passes), while the served
    /// `ChunkPool`/`KeyTable` fold to the content's own root, which cannot equal an arbitrary `root`.
    /// The integrity gate's rule-5 recompute must refuse it before it lands.
    fn push_module_bad_merkle(store: [u8; 32], root: [u8; 32], pk: &Bytes48) -> Vec<u8> {
        let chunk = b"tampered capsule content".to_vec();
        let leaf = resource_leaf(&concat_output(&[chunk.as_slice()]));
        let leaves = vec![leaf];
        let entries = vec![KeyTableEntry {
            static_key: Bytes32([0xab; 32]),
            generation: Bytes32(root),
            chunk_indices: vec![0],
            total_size: chunk.len() as u64,
        }];
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            // Header commits the caller's `root`, but the ChunkPool below folds to the content's root.
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::PublicKey as u16, pk.0.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&entries)),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[chunk.as_slice()]),
            ),
            (SectionId::MerkleNodes as u16, encode_merkle_nodes(&leaves)),
        ])
    }

    /// Install an inventory-refresher spy that COUNTS announces, so a test can assert an announce fired
    /// exactly N times (§14.1: `refresh_dht_inventory` IS the announce).
    fn install_announce_counter(node: &Node, count: Arc<AtomicUsize>) {
        node.set_inventory_refresher(Box::new(move || {
            let count = count.clone();
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
            })
        }));
    }

    /// A store keypair + its DERIVED store_id (`sha256(pubkey)`), the real DIG store-identity binding.
    fn store_keypair(seed: u8) -> (digstore_crypto::bls::SecretKey, Bytes48, [u8; 32]) {
        let (sk, pk) = digstore_crypto::bls_keygen(&[seed; 32]);
        let store_id = digstore_crypto::sha256(pk.as_bytes()).0;
        (sk, pk, store_id)
    }

    /// One base64 window of `bytes[offset..offset+len]`.
    fn window_b64(bytes: &[u8], offset: usize, len: usize) -> String {
        let end = (offset + len).min(bytes.len());
        base64::engine::general_purpose::STANDARD.encode(&bytes[offset..end])
    }

    fn local() -> (ReadOrigin, RequestProvenance) {
        (ReadOrigin::Local, RequestProvenance::FirstParty)
    }
    fn peer() -> (ReadOrigin, RequestProvenance) {
        (ReadOrigin::Peer, RequestProvenance::FirstParty)
    }
    /// A request over a genuinely LOCAL socket, made on a stranger's behalf: a cross-site page in
    /// the operator's browser POSTing to the loopback port, which CORS admits.
    fn cross_site_over_local_socket() -> (ReadOrigin, RequestProvenance) {
        (ReadOrigin::Local, RequestProvenance::CrossSite)
    }

    /// Push a whole capsule single-shot (one window) as the local operator and return the response.
    async fn push_one_shot(
        node: &Node,
        store_hex: &str,
        root_hex: &str,
        module: &[u8],
        signature: Option<&str>,
        (origin, provenance): (ReadOrigin, RequestProvenance),
    ) -> Value {
        let mut params = json!({
            "store_id": store_hex,
            "root": root_hex,
            "data": base64::engine::general_purpose::STANDARD.encode(module),
        });
        if let Some(sig) = signature {
            params["signature"] = json!(sig);
        }
        node.push_capsule(&params, json!(1), origin, provenance, RequestorId::Local)
            .await
    }

    /// Open ONE incomplete partial push for `(store, root)` as `requestor`: a first window whose
    /// declared `total_length` exceeds the sent bytes, so the push stays PENDING (never lands). The
    /// bytes need not be a genuine `.dig` — the bound is enforced BEFORE integrity/authority — so a
    /// tiny window suffices. Local origin keeps the auth path out of the way; the cap keys purely on
    /// `requestor`.
    async fn open_partial(
        node: &Node,
        store_hex: &str,
        root_hex: &str,
        window: &[u8],
        requestor: RequestorId,
    ) -> Value {
        let params = json!({
            "store_id": store_hex,
            "root": root_hex,
            "data": base64::engine::general_purpose::STANDARD.encode(window),
            "offset": 0,
            "total_length": window.len() as u64 + 4096, // > sent → stays pending
        });
        node.push_capsule(
            &params,
            json!(1),
            ReadOrigin::Local,
            RequestProvenance::FirstParty,
            requestor,
        )
        .await
    }

    /// A distinct `(store_hex, root_hex)` pair seeded from one byte, for opening many independent
    /// partials in the cap tests.
    fn distinct_capsule(seed: u8) -> (String, String) {
        (hex::encode([seed; 32]), hex::encode([seed ^ 0xff; 32]))
    }

    /// (a) A loopback push lands the capsule — it appears on disk at `module_path` and in the cached
    /// inventory. (b) The push routes through the ONE announce site exactly ONCE per fresh land.
    #[test]
    fn a_local_push_lands_and_announces_exactly_once() {
        // Serialized against every test that pins the process-global cache cap: a tiny cap set
        // by a concurrent test would sweep this capsule right back off disk (#267).
        let _env = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // A blocking runtime, not `#[tokio::test]`: `ENV_GUARD` is a std `Mutex` and clippy
        // `await_holding_lock` (rightly) refuses a guard held across an `.await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_sk, pk, store) = store_keypair(0x11);
            let (module, root) = push_module(store, &pk, 0x22, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));

            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();
            let announces = Arc::new(AtomicUsize::new(0));
            install_announce_counter(node, announces.clone());

            let resp = push_one_shot(node, &store_hex, &root_hex, &module, None, local()).await;
            assert_eq!(resp["result"]["complete"], json!(true), "resp={resp}");

            assert!(
                crate::module_exists(&node.cache_dir, &store_hex, &root_hex),
                "the capsule must be on disk at its module_path after a local push"
            );
            let listed = crate::seams::capsule::CapsuleStore::cache_list_cached(node).await;
            assert!(
                listed
                    .iter()
                    .any(|c| c.store_id == store_hex && c.root == root_hex),
                "the pushed capsule must appear in cache_list_cached"
            );
            assert_eq!(
                announces.load(Ordering::SeqCst),
                1,
                "a fresh land announces the holder exactly once"
            );
        });
    }

    /// **Proves (#267, dig-sex SPEC §7.1):** a LAND that sacrifices a capsule to make room advertises
    /// AFTER the sweep, so the node stops naming itself a holder of what it just deleted.
    ///
    /// This drives the real push→land path (`land_capsule_bytes` → `announce_and_bound_after_land`),
    /// which is where the reported defect actually lived: that tail ran `refresh_dht_inventory()` and
    /// THEN `evict_modules_locked()`, so the reconcile saw a world the victim had not yet left and the
    /// retraction was never computed. The capsule stayed advertised until some unrelated inventory
    /// change happened to reconcile it, which on a quiet node is never.
    ///
    /// **Non-vacuous, and deliberately not a call counter.** `install_announce_counter` — used by the
    /// two tests either side of this one — reports exactly one round under BOTH orderings, because one
    /// round does happen either way. Only the CONTENT of that round separates them, so the spy
    /// snapshots the on-disk capsule set inside it: with the sweep second, the snapshot still lists the
    /// filler that is about to be deleted.
    /// **Catches:** restoring the advertise-then-sweep order, and dropping the land-path retraction.
    #[test]
    fn a_land_that_evicts_advertises_after_the_sweep() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let (_sk, pk, store) = store_keypair(0x9a);
        let (module, root) = push_module(store, &pk, 0x9b, 0);
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let node = node.as_ref();

        // Isolate the process-global cap config, then pin a cap the filler ALONE already exceeds, so
        // the post-land sweep must sacrifice it whatever the pushed capsule weighs.
        let cfg = tempfile::tempdir().unwrap();
        std::env::set_var("DIG_NODE_CACHE", cfg.path());
        let _ = std::fs::remove_file(crate::config_path());
        crate::set_cache_cap_bytes(1_500).unwrap();

        // A tier-0 filler: sacrificial by tier, so the freshly-landed capsule (untagged, and therefore
        // the protected Tier1Demand default) is never the victim.
        let filler_store = "ba".repeat(32);
        let filler_root = "cd".repeat(32);
        crate::tier0_live::mark_tier0_land(&filler_store);
        let filler = crate::CapsuleKey::parse(&filler_store, &filler_root)
            .expect("canonical hex")
            .module_path(&node.cache_dir);
        std::fs::create_dir_all(filler.parent().unwrap()).unwrap();
        std::fs::write(&filler, vec![0u8; 2_048]).unwrap();

        let rounds = Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::test_support::install_inventory_snapshot_spy(node, rounds.clone());

        // A plain `#[test]` driving its own runtime, not `#[tokio::test]`: `ENV_GUARD` is a std
        // `Mutex` guarding the process-global cap config and must never be held across an `.await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(push_one_shot(
            node,
            &store_hex,
            &root_hex,
            &module,
            None,
            local(),
        ));
        assert_eq!(resp["result"]["complete"], json!(true), "resp={resp}");

        assert!(!filler.exists(), "the tier-0 filler was the sacrifice");
        assert!(
            crate::module_exists(&node.cache_dir, &store_hex, &root_hex),
            "the pushed capsule landed and survived the sweep"
        );

        let rounds = rounds.lock().unwrap();
        assert_eq!(
            rounds.len(),
            1,
            "a land advertises exactly once; got {rounds:?}"
        );
        assert!(
            !rounds[0].contains(&format!("{filler_store}/{filler_root}")),
            "the advertisement must run AFTER the sweep, so the evicted filler is no longer in the \
             set it advertises; saw {:?}",
            rounds[0]
        );
        assert!(
            rounds[0].contains(&format!("{store_hex}/{root_hex}")),
            "the capsule that just landed must be advertised; saw {:?}",
            rounds[0]
        );

        std::env::remove_var("DIG_NODE_CACHE");
    }

    /// (f) Re-pushing an already-held capsule is idempotent — it reports complete and does NOT fire a
    /// second announce.
    #[test]
    fn a_repushed_capsule_does_not_announce_twice() {
        // Serialized against every test that pins the process-global cache cap: a tiny cap set
        // by a concurrent test would sweep this capsule right back off disk (#267).
        let _env = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // A blocking runtime, not `#[tokio::test]`: `ENV_GUARD` is a std `Mutex` and clippy
        // `await_holding_lock` (rightly) refuses a guard held across an `.await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_sk, pk, store) = store_keypair(0x33);
            let (module, root) = push_module(store, &pk, 0x44, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));

            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();
            let announces = Arc::new(AtomicUsize::new(0));
            install_announce_counter(node, announces.clone());

            let r1 = push_one_shot(node, &store_hex, &root_hex, &module, None, local()).await;
            assert_eq!(r1["result"]["complete"], json!(true));
            let r2 = push_one_shot(node, &store_hex, &root_hex, &module, None, local()).await;
            assert_eq!(r2["result"]["complete"], json!(true));
            assert_eq!(
                r2["result"]["already_cached"],
                json!(true),
                "second push is a no-op"
            );
            assert_eq!(
                announces.load(Ordering::SeqCst),
                1,
                "re-pushing a held capsule must not double-announce"
            );
        });
    }

    /// (e) Chunked reassembly across ≥2 windows lands the whole capsule; a root-mismatch (bytes that do
    /// not commit the requested root) is rejected BEFORE landing.
    #[test]
    fn chunked_reassembly_lands_and_root_mismatch_is_rejected() {
        // Serialized against every test that pins the process-global cache cap: a tiny cap set
        // by a concurrent test would sweep this capsule right back off disk (#267).
        let _env = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // A blocking runtime, not `#[tokio::test]`: `ENV_GUARD` is a std `Mutex` and clippy
        // `await_holding_lock` (rightly) refuses a guard held across an `.await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_sk, pk, store) = store_keypair(0x55);
            // A ~200 KiB module so a small window forces multiple chunks.
            let (module, root) = push_module(store, &pk, 0x66, 200 * 1024);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
            let total = module.len();
            let win = 64 * 1024;

            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();
            let announces = Arc::new(AtomicUsize::new(0));
            install_announce_counter(node, announces.clone());

            let mut offset = 0usize;
            let mut last = Value::Null;
            while offset < total {
                let params = json!({
                    "store_id": store_hex,
                    "root": root_hex,
                    "data": window_b64(&module, offset, win),
                    "offset": offset,
                    "total_length": total,
                });
                last = node
                    .push_capsule(
                        &params,
                        json!(1),
                        ReadOrigin::Local,
                        RequestProvenance::FirstParty,
                        RequestorId::Local,
                    )
                    .await;
                offset = last["result"]["next_offset"]
                    .as_u64()
                    .map(|n| n as usize)
                    .unwrap_or(total);
                if offset < total {
                    assert_eq!(
                        last["result"]["complete"],
                        json!(false),
                        "mid-stream not complete"
                    );
                }
            }
            assert_eq!(
                last["result"]["complete"],
                json!(true),
                "final window completes: {last}"
            );
            assert!(crate::module_exists(&node.cache_dir, &store_hex, &root_hex));
            assert!(offset >= total, "reassembly needed ≥2 windows");
            assert_eq!(announces.load(Ordering::SeqCst), 1);

            // Root-mismatch: bytes commit a DIFFERENT root than requested → rejected, nothing lands.
            let wrong_root = [0x67; 32];
            let wrong_root_hex = hex::encode(wrong_root);
            // A faithful capsule committing its OWN content-derived root, pushed under `wrong_root_hex` —
            // its committed root is neither the requested root nor the chain root, so it is rejected.
            let (mismatched, _mroot) = push_module(store, &pk, 0x99, 0);
            let resp = push_one_shot(
                node,
                &store_hex,
                &wrong_root_hex,
                &mismatched,
                None,
                local(),
            )
            .await;
            assert!(
                resp.get("error").is_some(),
                "root-mismatch must be rejected: {resp}"
            );
            assert!(!crate::module_exists(
                &node.cache_dir,
                &store_hex,
                &wrong_root_hex
            ));
        });
    }

    /// (#2246/#2240) A push whose bytes commit the requested `(store_id, root)` in their HEADER but
    /// whose `MerkleNodes` leaves recompute to a different root is refused BEFORE landing. The integrity
    /// gate reuses `ChainAnchoredModuleVerifier`, so the admit-gate recompute (rule 5) guards the push
    /// land too: a header-matching-but-tampered capsule never reaches disk or the announce.
    /// **Catches:** an integrity gate that trusts the committed `CurrentRoot` header without recomputing
    /// the merkle root from the capsule's own data.
    #[tokio::test]
    async fn a_push_whose_data_does_not_recompute_to_its_root_is_refused_before_landing() {
        let (_sk, pk, store) = store_keypair(0x5b);
        let root = [0x6c; 32];
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
        // Commits the requested root in its header (clears the byte-compare) but its leaves recompute to
        // a different root — the tampered/incomplete capsule.
        let tampered = push_module_bad_merkle(store, root, &pk);

        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let node = node.as_ref();
        let announces = Arc::new(AtomicUsize::new(0));
        install_announce_counter(node, announces.clone());

        let resp = push_one_shot(node, &store_hex, &root_hex, &tampered, None, local()).await;
        assert!(
            resp.get("error").is_some(),
            "a push whose data does not recompute to its committed root must be refused: {resp}"
        );
        assert!(
            !crate::module_exists(&node.cache_dir, &store_hex, &root_hex),
            "the tampered capsule must never reach disk"
        );
        assert_eq!(
            announces.load(Ordering::SeqCst),
            0,
            "a refused push must not announce"
        );
    }

    /// (c) With `DIG_NODE_PUSH_OPEN` unset, `cache.pushCapsule` is not peer-reachable — the peer
    /// allowlist answers `-32601` before dispatch.
    #[test]
    fn push_capsule_is_not_peer_reachable_by_default() {
        let _guard = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::remove_var(PUSH_OPEN_ENV);
        assert!(
            !crate::peer::is_peer_reachable_method(PUSH_CAPSULE_METHOD),
            "cache.pushCapsule must be peer-UNreachable when DIG_NODE_PUSH_OPEN is unset"
        );
    }

    /// (c cont.) With `DIG_NODE_PUSH_OPEN=true` the method becomes peer-reachable (the open branch).
    #[test]
    fn push_capsule_becomes_peer_reachable_when_opened() {
        let _guard = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        std::env::set_var(PUSH_OPEN_ENV, "true");
        let reachable = crate::peer::is_peer_reachable_method(PUSH_CAPSULE_METHOD);
        std::env::remove_var(PUSH_OPEN_ENV);
        assert!(
            reachable,
            "DIG_NODE_PUSH_OPEN=true must admit cache.pushCapsule to the peer surface"
        );
    }

    /// (d) On the peer/authority path a push signed by a NON-authorized writer is rejected, and one
    /// signed by the store's authorized writer succeeds. This is the load-bearing auth test: neuter
    /// `verify_push_authority` and the reject half goes green (proving it is what rejects).
    #[test]
    fn open_push_requires_the_authorized_writer_signature() {
        // Serialized against every test that pins the process-global cache cap: a tiny cap set
        // by a concurrent test would sweep this capsule right back off disk (#267).
        let _env = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // A blocking runtime, not `#[tokio::test]`: `ENV_GUARD` is a std `Mutex` and clippy
        // `await_holding_lock` (rightly) refuses a guard held across an `.await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (sk, pk, store) = store_keypair(0x77);
            let (module, root) = push_module(store, &pk, 0x88, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));

            // A DIFFERENT keypair — an attacker who owns a key, but not THIS store's key.
            let (attacker_sk, _apk, _astore) = store_keypair(0xEE);
            let bad_sig = digstore_crypto::sign_push(&attacker_sk, &Bytes32(root), &Bytes32(store));
            let good_sig = digstore_crypto::sign_push(&sk, &Bytes32(root), &Bytes32(store));

            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();

            // No signature at all on the peer surface → rejected before any buffering.
            let none = push_one_shot(node, &store_hex, &root_hex, &module, None, peer()).await;
            assert!(
                none.get("error").is_some(),
                "a peer push with no signature must be rejected: {none}"
            );

            // Wrong writer → rejected, nothing lands.
            let wrong = push_one_shot(
                node,
                &store_hex,
                &root_hex,
                &module,
                Some(&bad_sig.to_hex()),
                peer(),
            )
            .await;
            assert!(
                wrong.get("error").is_some(),
                "a non-authorized signature must be rejected: {wrong}"
            );
            assert!(!crate::module_exists(
                &node.cache_dir,
                &store_hex,
                &root_hex
            ));

            // Authorized writer → lands.
            let ok = push_one_shot(
                node,
                &store_hex,
                &root_hex,
                &module,
                Some(&good_sig.to_hex()),
                peer(),
            )
            .await;
            assert_eq!(
                ok["result"]["complete"],
                json!(true),
                "the authorized writer's push must land: {ok}"
            );
            assert!(crate::module_exists(&node.cache_dir, &store_hex, &root_hex));
        });
    }

    // ---- dig_ecosystem#2149: DoS bounds on in-flight pending-reassembly state ----
    //
    // The bounds live in one pure method, `PendingPushes::admit_window` — the SAME code the handler
    // calls. Testing it directly on local instances (rather than mutating the process-wide static that
    // the end-to-end push tests share) keeps every bound test deterministic and free of cross-test
    // interference, and lets the TTL reaper run against an INJECTED clock with no wall-clock sleep.

    /// A small bounded table for a bound test: caps + budget + TTL as given, starting empty.
    fn table(max_per_requestor: usize, max_global: usize, max_bytes: usize) -> PendingPushes {
        PendingPushes {
            entries: HashMap::new(),
            max_per_requestor,
            max_global,
            max_bytes,
            ttl: Duration::from_secs(60),
        }
    }

    /// A distinct `(cache_dir, capsule)` map key seeded from one byte, for opening independent
    /// partials.
    fn map_key(seed: u8) -> (PathBuf, CapsuleKey) {
        let capsule = CapsuleKey::parse(&hex::encode([seed; 32]), &hex::encode([seed ^ 0xff; 32]))
            .expect("valid 64-hex");
        (PathBuf::from("/cache"), capsule)
    }

    /// Admit one window into the table (mutating it as the handler does on success): reserve via
    /// `admit_window`, then insert/extend the partial. Returns the admission result so a test can
    /// assert acceptance or the refusal message.
    fn admit(
        t: &mut PendingPushes,
        key: &(PathBuf, CapsuleKey),
        requestor: &str,
        len: usize,
        now: Instant,
    ) -> Result<(), &'static str> {
        t.admit_window(key, requestor, len, now)?;
        let pending = t.entries.entry(key.clone()).or_insert_with(|| PendingPush {
            total_length: len as u64 + 4096, // > buffered → stays pending
            buf: Vec::new(),
            requestor: requestor.to_string(),
            last_activity: now,
        });
        pending.buf.resize(pending.buf.len() + len, 0u8);
        pending.last_activity = now;
        Ok(())
    }

    /// The (N+1)th concurrent partial from ONE requestor is refused, while the first N are accepted;
    /// a DIFFERENT requestor is untouched. Pins the per-requestor cap.
    #[test]
    fn per_requestor_cap_refuses_the_nth_concurrent_partial() {
        let mut t = table(3, 1000, usize::MAX);
        let now = Instant::now();

        for i in 0..3u8 {
            assert!(
                admit(&mut t, &map_key(0x10 + i), "peer:aaaa", 20, now).is_ok(),
                "partial {i} must be accepted"
            );
        }
        assert_eq!(
            admit(&mut t, &map_key(0x1f), "peer:aaaa", 20, now),
            Err("too many concurrent pending pushes for this requestor; complete or abandon one first"),
            "the 4th concurrent partial from one requestor must be refused"
        );
        // A different requestor draws from its OWN per-requestor slots.
        assert!(
            admit(&mut t, &map_key(0x2a), "peer:bbbb", 20, now).is_ok(),
            "a different requestor is unaffected by the abuser's exhausted slots"
        );
    }

    /// Once the GLOBAL concurrent-push cap is hit, a push from a SECOND requestor is refused — the
    /// bound is process-wide, not merely per-requestor.
    #[test]
    fn global_cap_refuses_a_second_requestor_once_full() {
        let mut t = table(1000, 2, usize::MAX);
        let now = Instant::now();

        assert!(admit(&mut t, &map_key(0x40), "peer:aaaa", 20, now).is_ok());
        assert!(admit(&mut t, &map_key(0x41), "peer:aaaa", 20, now).is_ok());
        assert_eq!(
            admit(&mut t, &map_key(0x4f), "peer:bbbb", 20, now),
            Err("too many concurrent pending pushes on this node; retry after in-flight pushes complete"),
            "a second requestor is refused once the global cap is full"
        );
    }

    /// A window that would push the aggregate buffered bytes past the global byte budget is refused
    /// BEFORE its bytes are buffered (fail-closed: the refused window leaves no bytes behind).
    #[test]
    fn byte_budget_refuses_before_buffering() {
        // Budget admits one 20-byte window but not two.
        let mut t = table(1000, 1000, 21);
        let now = Instant::now();

        assert!(
            admit(&mut t, &map_key(0x60), "peer:aaaa", 20, now).is_ok(),
            "first window fits"
        );
        assert_eq!(
            admit(&mut t, &map_key(0x61), "peer:aaaa", 20, now),
            Err("the pending-push memory budget is exhausted; retry after in-flight pushes complete"),
            "a window over the byte budget must be refused"
        );
        assert_eq!(
            t.buffered_bytes(),
            20,
            "only the first (admitted) window's bytes are buffered — the refusal buffered nothing"
        );
    }

    /// The catalogued reject code reaches the wire END-TO-END through the real handler: opening one
    /// more than the DEFAULT per-requestor cap of concurrent partials answers [`PUSH_PENDING_LIMITED`].
    ///
    /// Uses a UNIQUE requestor id so `count_for` is isolated from any parallel test sharing the
    /// process-wide table — no shared limit is mutated, so this cannot flake a sibling test.
    #[tokio::test]
    async fn handler_answers_the_catalogued_error_at_the_per_requestor_cap() {
        let (node, _td) = crate::test_support::test_node_for_peer_surface();
        let node = node.as_ref();
        let who = || RequestorId::Peer("peer:test-2149-per-requestor-cap".to_string());

        // The first MAX_PENDING_PUSHES_PER_REQUESTOR partials are accepted (each stays pending).
        for i in 0..MAX_PENDING_PUSHES_PER_REQUESTOR as u8 {
            let (s, r) = distinct_capsule(0xA0 + i);
            let resp = open_partial(node, &s, &r, b"partial-window", who()).await;
            assert_eq!(
                resp["result"]["complete"],
                json!(false),
                "partial {i} within the cap must be accepted and pending: {resp}"
            );
        }
        // One more distinct partial from the SAME requestor trips the cap.
        let (s, r) = distinct_capsule(0xBF);
        let refused = open_partial(node, &s, &r, b"partial-window", who()).await;
        assert_eq!(
            refused["error"]["code"],
            json!(PUSH_PENDING_LIMITED),
            "the (cap+1)th concurrent partial must answer PUSH_PENDING_LIMITED: {refused}"
        );
    }

    /// The reaper evicts a partial that has not advanced within the TTL — freeing its slot + bytes —
    /// while a fresh partial survives. Driven with an INJECTED clock (no wall-clock sleep).
    #[test]
    fn reaper_evicts_only_partials_past_the_ttl() {
        let mut t = table(1000, 1000, usize::MAX);
        let now = Instant::now();

        let stale = map_key(0x81);
        let fresh = map_key(0x83);
        t.entries.insert(
            stale.clone(),
            PendingPush {
                total_length: 4096,
                buf: vec![0u8; 100],
                requestor: "peer:aaaa".to_string(),
                last_activity: now.checked_sub(Duration::from_secs(120)).expect("clock"),
            },
        );
        t.entries.insert(
            fresh.clone(),
            PendingPush {
                total_length: 4096,
                buf: vec![0u8; 50],
                requestor: "peer:aaaa".to_string(),
                last_activity: now,
            },
        );
        assert_eq!(t.buffered_bytes(), 150);

        t.reap_expired(now);

        assert!(
            !t.entries.contains_key(&stale),
            "the stale partial is reaped"
        );
        assert!(t.entries.contains_key(&fresh), "the fresh partial survives");
        assert_eq!(
            t.buffered_bytes(),
            50,
            "the reaped partial's bytes are reclaimed"
        );
        assert_eq!(
            t.count_for("peer:aaaa"),
            1,
            "only the fresh partial remains for the requestor"
        );

        // A completing push AFTER the TTL is treated as new: the freed slot is available again.
        assert!(
            admit(&mut t, &stale, "peer:aaaa", 10, now).is_ok(),
            "the reaped capsule's slot is free for a fresh push"
        );
    }

    // ---- dig-node#436: the PROVENANCE a land path records ----
    //
    // # The property
    //
    // A capsule this node accepted BECAUSE A STRANGER ASKED must be recorded `Relayed`; a capsule the
    // operator asked for must be recorded `Held`. Only `Held` is bondable, so that distinction is the
    // only barrier between a stranger's content and this operator's $DIG. Since dig-node#424 wired a
    // real broadcaster, getting it wrong is no longer a wrong announce — it is a mainnet spend against
    // content this node is merely relaying.
    //
    // # Why the fixture varies the ORIGIN and nothing else
    //
    // Provenance is not carried in the capsule. It is derived at READ time from the `<root>.relay`
    // sidecar (`capsule_store::list_cached_capsules`), so "no marker" and "the operator's own capsule"
    // are the SAME on-disk state. A test that landed only a remote capsule and asserted `Relayed`
    // would be satisfied by an implementation that marked EVERY capsule relayed — which breaks the
    // flywheel, and is the nearest wrong implementation in the other direction.
    //
    // So both tests land the same shape of capsule through the same handler, varying only
    // `ReadOrigin`, and each asserts its own half. The truthful control (a local land stays `Held`) is
    // what makes the remote assertion load-bearing rather than a restatement of a global default.

    /// The provenance the INVENTORY reports for `(store_hex, root_hex)`, or `None` if absent.
    ///
    /// Read through `cache_list_cached` — the same scan every announce cause and every bonding
    /// decision consumes — rather than by stat-ing the sidecar. Asserting on the sidecar would pin the
    /// mechanism; asserting on the inventory pins the ANSWER, which is what a spend acts on.
    async fn listed_provenance(
        node: &Node,
        store_hex: &str,
        root_hex: &str,
    ) -> Option<crate::CapsuleProvenance> {
        crate::seams::capsule::CapsuleStore::cache_list_cached(node)
            .await
            .into_iter()
            .find(|c| c.store_id == store_hex && c.root == root_hex)
            .map(|c| c.provenance)
    }

    /// **Proves (dig-node#436):** the operator's OWN push lands bondable.
    ///
    /// This is the control for `a_peer_originated_push_must_land_relayed`, and it is the half that
    /// must keep passing after any fix: marking every land `Relayed` would satisfy the remote
    /// assertion while silently disabling the flywheel for the operator's own content.
    ///
    /// **Catches:** a fix that marks every land `Relayed` instead of only the remote-originated ones.
    #[test]
    fn a_local_push_lands_held_and_therefore_bondable() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (_sk, pk, store) = store_keypair(0x36);
            let (module, root) = push_module(store, &pk, 0x43, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();

            let resp = push_one_shot(node, &store_hex, &root_hex, &module, None, local()).await;
            assert_eq!(resp["result"]["complete"], json!(true), "resp={resp}");

            assert_eq!(
                listed_provenance(node, &store_hex, &root_hex).await,
                Some(crate::CapsuleProvenance::Held),
                "the operator's own push is this node's own capsule and must stay bondable"
            );
        });
    }

    /// **Proves (dig-node#436, defect B):** a push accepted over the PEER surface — which
    /// `DIG_NODE_PUSH_OPEN=true` admits — must land `Relayed`.
    ///
    /// Was RED when this test was written: `land_capsule_bytes` wrote the module and announced
    /// without ever writing a relay marker, so a remote authorized-writer's capsule landed
    /// indistinguishable from the operator's own — announced, and bondable. It passes because
    /// provenance is now a REQUIRED argument of landing rather than a property of the route.
    ///
    /// **Catches:** any future land route reaching `land_capsule_bytes` without recording its origin.
    #[test]
    fn a_peer_originated_push_must_land_relayed() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (sk, pk, store) = store_keypair(0x51);
            let (module, root) = push_module(store, &pk, 0x52, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
            let sig = digstore_crypto::sign_push(&sk, &Bytes32(root), &Bytes32(store));
            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();

            let resp = push_one_shot(
                node,
                &store_hex,
                &root_hex,
                &module,
                Some(&sig.to_hex()),
                peer(),
            )
            .await;
            assert_eq!(resp["result"]["complete"], json!(true), "resp={resp}");

            assert_eq!(
                listed_provenance(node, &store_hex, &root_hex).await,
                Some(crate::CapsuleProvenance::Relayed),
                "a capsule pushed by a REMOTE writer is held on that writer's behalf, never this \
                 operator's own content to bond against"
            );
        });
    }
    /// **Proves (dig-node#436, the confused deputy on the PUSH path):** a push arriving over a
    /// genuinely local socket but made on a STRANGER's behalf lands `Relayed`.
    ///
    /// This site read the raw `origin` while line 272 of the SAME function already folded both axes
    /// for its authority check — so the authority half correctly demanded an authorized-writer
    /// signature for a cross-site push, and the provenance half handed that same push `Announce`.
    /// Creating a store is permissionless, so holding a store key is not a trust boundary: a third
    /// party entitled to push is not thereby entitled to spend this operator's $DIG.
    ///
    /// **Catches:** either landing decision in this file reverting to a single axis.
    #[test]
    fn a_cross_site_push_over_a_local_socket_lands_relayed() {
        let _g = crate::test_support::ENV_GUARD
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (sk, pk, store) = store_keypair(0x63);
            let (module, root) = push_module(store, &pk, 0x64, 0);
            let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
            let sig = digstore_crypto::sign_push(&sk, &Bytes32(root), &Bytes32(store));
            let (node, _td) = crate::test_support::test_node_for_peer_surface();
            let node = node.as_ref();

            let resp = push_one_shot(
                node,
                &store_hex,
                &root_hex,
                &module,
                Some(&sig.to_hex()),
                cross_site_over_local_socket(),
            )
            .await;
            assert_eq!(resp["result"]["complete"], json!(true), "resp={resp}");

            assert_eq!(
                listed_provenance(node, &store_hex, &root_hex).await,
                Some(crate::CapsuleProvenance::Relayed),
                "a local socket driven by a stranger's page is a confused deputy, not the operator"
            );
        });
    }
}
