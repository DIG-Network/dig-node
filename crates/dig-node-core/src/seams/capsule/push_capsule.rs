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

use base64::Engine as _;
use digstore_core::datasection::{DataView, SectionId};
use digstore_core::{Bytes32, Bytes48, Bytes96};
use digstore_remote::verify_push_signature;
use serde_json::{json, Value};

use crate::download::{landing_origin, ReadOrigin, RequestProvenance};
use crate::seams::dig_peer::ChainAnchoredModuleVerifier;
use crate::{CapsuleKey, InMemoryModule, Node};

use super::MAX_CAPSULE_BYTES;

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
}

/// The process-wide table of in-flight chunked pushes. A `std::sync::Mutex` (never held across an
/// `.await`) guarding transient per-capsule reassembly state — a completed or abandoned push is
/// removed, so the table holds only genuinely in-flight uploads.
fn pending_pushes() -> &'static Mutex<HashMap<(PathBuf, CapsuleKey), PendingPush>> {
    static PENDING: OnceLock<Mutex<HashMap<(PathBuf, CapsuleKey), PendingPush>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
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
    ) -> Value {
        let err = |code: i64, msg: &str| json!({"jsonrpc":"2.0","id":id.clone(),"error":{"code":code,"message":msg}});

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
        let bytes = {
            let mut table = pending_pushes().lock().unwrap_or_else(|p| p.into_inner());
            let map_key = (self.cache_dir.clone(), key.clone());
            let pending = table.entry(map_key.clone()).or_insert_with(|| PendingPush {
                total_length,
                buf: Vec::new(),
            });
            // total_length is a commitment made on the first window; a later disagreement is a caller
            // rewriting the push mid-flight.
            if pending.total_length != total_length {
                table.remove(&map_key);
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
                table.remove(&map_key);
                return err(-32602, "chunk overflows the declared total_length");
            }
            pending.buf.extend_from_slice(&data);
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
            table.remove(&map_key).map(|p| p.buf).unwrap_or(data)
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
        match self.land_capsule_bytes(&key, &bytes).await {
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

    use digstore_core::datasection::encode_blob;

    use crate::seams::dig_peer::peer_network::PeerNetwork;

    /// A minimal but genuine `.dig` data-section blob committing `(store_id, root, publisher_pk)` plus
    /// filler to reach `min_len` bytes — enough for the anchor verifier AND the authority check, and
    /// (with a large `min_len`) a multi-window fixture.
    fn push_module(store: [u8; 32], root: [u8; 32], pk: &Bytes48, min_len: usize) -> Vec<u8> {
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::PublicKey as u16, pk.0.to_vec()),
            (SectionId::Filler as u16, vec![0x5a; min_len]),
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

    /// Push a whole capsule single-shot (one window) and return the response.
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
        node.push_capsule(&params, json!(1), origin, provenance)
            .await
    }

    /// (a) A loopback push lands the capsule — it appears on disk at `module_path` and in the cached
    /// inventory. (b) The push routes through the ONE announce site exactly ONCE per fresh land.
    #[tokio::test]
    async fn a_local_push_lands_and_announces_exactly_once() {
        let (_sk, pk, store) = store_keypair(0x11);
        let root = [0x22; 32];
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
        let module = push_module(store, root, &pk, 0);

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
    }

    /// (f) Re-pushing an already-held capsule is idempotent — it reports complete and does NOT fire a
    /// second announce.
    #[tokio::test]
    async fn a_repushed_capsule_does_not_announce_twice() {
        let (_sk, pk, store) = store_keypair(0x33);
        let root = [0x44; 32];
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
        let module = push_module(store, root, &pk, 0);

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
    }

    /// (e) Chunked reassembly across ≥2 windows lands the whole capsule; a root-mismatch (bytes that do
    /// not commit the requested root) is rejected BEFORE landing.
    #[tokio::test]
    async fn chunked_reassembly_lands_and_root_mismatch_is_rejected() {
        let (_sk, pk, store) = store_keypair(0x55);
        let root = [0x66; 32];
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
        // A ~200 KiB module so a small window forces multiple chunks.
        let module = push_module(store, root, &pk, 200 * 1024);
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
        let mismatched = push_module(store, [0x99; 32], &pk, 0); // commits neither the requested root
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
    #[tokio::test]
    async fn open_push_requires_the_authorized_writer_signature() {
        let (sk, pk, store) = store_keypair(0x77);
        let root = [0x88; 32];
        let (store_hex, root_hex) = (hex::encode(store), hex::encode(root));
        let module = push_module(store, root, &pk, 0);

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
    }
}
