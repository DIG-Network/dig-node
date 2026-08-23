//! The peer `dig.resolveCapsule` RPC — the SERVER side of the tier-0 precache key→preimage resolve
//! (epic #1934 flywheel live-wiring, child PR-1/3).
//!
//! # The problem this solves
//!
//! A sampled DHT content-key is `SHA-256(ContentId canonical bytes)` — a ONE-WAY digest. The tier-0
//! precache loop ([`crate::dht_sampling`], merged + inert) samples such keys from the neighbourhood, but
//! to actually fetch + verify a capsule it needs the `(store_id, root)` PREIMAGE the key was hashed
//! from. That preimage cannot be recovered from the key; only a node that ALREADY HOLDS the capsule can
//! supply it, because a holder knows its own `(store_id, root)` and can recompute the key to confirm the
//! match. This module answers exactly that question over the peer wire: "for content-key `H`, what
//! `(store_id, root, size)` do YOU hold that hashes to it?".
//!
//! # The two halves (this PR is the first)
//!
//! - **Server** (THIS module) — a `dig.resolveCapsule` peer RPC that answers PURELY from this node's own
//!   holdings reverse index ([`crate::CapsuleStore::cache_list_cached`]): for each held `(store, root)`
//!   recompute `ContentId::capsule(store, root).to_key()` and, if it is in the requested set, return the
//!   preimage plus the on-disk `.dig` size. A requested key this node does NOT hold is simply ABSENT
//!   from the answer — never an error, mirroring the `dig.getAvailability` "not-held ⇒ absent" idiom.
//! - **Client resolver + seam/spawn wiring** — PR-2 and PR-3, not built here.
//!
//! # Why this discloses no NEW privacy surface
//!
//! A node answers a resolve ONLY for capsules it already announces as a public provider in the DHT (the
//! same inventory `dig.getProviderSnapshot` reports the COUNTS of). The preimage `(store_id, root)` of a
//! capsule this node publicly serves is already learnable — `dig.getAvailability` / `dig.fetchRange`
//! serve its bytes to anyone. Keeping it a SEPARATE method from `getProviderSnapshot` is deliberate: the
//! snapshot stays strictly counts-only (it never names a store), while this method — asked only for keys
//! a caller already sampled — trades the preimage of THIS node's own public holdings. No provider
//! identity of any OTHER node is ever revealed, and no node state is mutated.
//!
//! # Bounds — one cheap request cannot become unbounded work
//!
//! The requested-key batch is CLAMPED to [`MAX_RESOLVE_CAPSULE_KEYS`], a frame-ceiling-derived constant:
//! the answer rides [`crate::peer::read_framed`]'s 64 KiB control-frame ceiling, and one resolved record
//! serializes to ~300 bytes, so the cap keeps a maximal answer safely under the ceiling (asserted at
//! compile time below). A malformed (non-64-hex) requested key can never be a real content-key, so it is
//! dropped rather than erroring — a lying caller wastes only its own request.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::capsule_key::is_canonical_hex_id;
use crate::seams::dig_peer::dht::hex64;
use crate::CachedCapsule;

/// The wire name of the peer capsule-resolve RPC.
///
/// Like [`GET_PROVIDER_SNAPSHOT_METHOD`](crate::seams::dig_peer::neighbourhood_probe::GET_PROVIDER_SNAPSHOT_METHOD),
/// this is a **dig-node-local** peer method: the shared `dig-rpc-protocol` allowlist is a crates.io pin
/// this crate cannot extend, so [`crate::peer::is_peer_reachable_method`] allowlists this name
/// explicitly (promoting it into the shared crate is a tracked cross-repo follow-up). Namespaced under
/// `dig.` to match every other read/discovery method on the peer surface.
pub const RESOLVE_CAPSULE_METHOD: &str = "dig.resolveCapsule";

/// The hard cap on how many content-keys one `dig.resolveCapsule` request may ask about.
///
/// WHY a cap at all: `content_keys` is an untrusted list a remote peer chose, and the resolve walks this
/// node's holdings once per request while serializing up to `content_keys.len()` matched records — an
/// unbounded list lets one small request drive an oversized response on the very connection this node
/// depends on for reachability. The clamp bounds that work regardless of what a peer asks.
///
/// WHY 128 specifically: the response rides [`crate::peer::read_framed`]'s 64 KiB control-frame ceiling.
/// One resolved record serializes as
/// `{"content_key":"<64 hex>","store_id":"<64 hex>","root":"<64 hex>","size_bytes":<u64>}` — three
/// 64-hex ids plus field names, a size, and JSON punctuation ≈ 300 bytes. 128 records ≈ 38 KB sits
/// safely under 64 KiB with room for the JSON-RPC envelope. A larger cap could produce an answer the
/// peer's own `read_framed` REFUSES as oversized — a self-inflicted denial of the very data we serve —
/// so this bound is derived from the frame ceiling, not chosen for taste (asserted in the tests).
pub const MAX_RESOLVE_CAPSULE_KEYS: usize = 128;

/// One resolved capsule: the preimage `(store_id, root)` of a requested content-key this node holds,
/// plus the on-disk size of the cached `.dig`.
///
/// Serialized as the elements of the `resolved` array. Every field is a canonical value sourced from
/// this node's own inventory — `content_key` is recomputed here (never echoed from the request), and
/// `store_id`/`root` are the lowercase 64-hex ids from [`CachedCapsule`], safe to serialize verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ResolvedCapsule {
    /// The 64-hex DHT content-key `SHA-256(ContentId::capsule(store, root) canonical bytes)`, recomputed
    /// from the holding so it is proven to match the request, not merely echoed back.
    pub content_key: String,
    /// The preimage store id (lowercase 64-hex).
    pub store_id: String,
    /// The preimage generation root hash (lowercase 64-hex).
    pub root: String,
    /// On-disk size of the cached `.dig`, in bytes — what a fetcher budgets against before pulling.
    pub size_bytes: u64,
}

/// Parse + CLAMP the requested content-keys out of an untrusted `params`.
///
/// Pure, so the clamp is unit-testable with no connection. Reads `params.content_keys` (an array of
/// strings); a missing/mistyped field yields an empty list (the method is supported, there is simply
/// nothing to resolve). At most [`MAX_RESOLVE_CAPSULE_KEYS`] keys are taken — an over-cap request is
/// truncated rather than honoured unboundedly. String SHAPE is NOT validated here; a non-64-hex key is
/// carried through and dropped by [`resolve_capsule_result`], which is where "can this be a content-key
/// at all?" is the natural question to ask.
fn requested_keys_from_params(params: &Value) -> Vec<String> {
    params
        .get("content_keys")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .take(MAX_RESOLVE_CAPSULE_KEYS)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve `requested_keys` against this node's `held` capsules — the PURE reverse-index core.
///
/// For each held `(store, root)` recompute the DHT content-key `ContentId::capsule(store, root).to_key()`
/// and, if it is in the requested set, emit its preimage + on-disk size. A requested key this node does
/// NOT hold is simply absent from the result (never an error) — the `dig.getAvailability` "not-held ⇒
/// absent" idiom. The computed key is the ONLY thing matched against the request, so a resolved record
/// is proof this node genuinely holds a capsule hashing to that key — a caller cannot make this node
/// claim a preimage it does not hold.
///
/// Both untrusted edges are handled without panicking: a malformed (non-64-hex) REQUESTED key can never
/// equal a recomputed key, so it matches nothing (dropped up front to keep the set clean); a malformed
/// on-disk inventory entry — which cannot be a valid content-key — is skipped. Pure over its inputs so
/// the whole reverse index is exercised with no socket and no disk.
pub(crate) fn resolve_capsule_result(
    held: &[CachedCapsule],
    requested_keys: &[String],
) -> Vec<ResolvedCapsule> {
    // Normalize to lowercase because `Key::to_hex` emits lowercase and a caller may send either casing;
    // dropping non-canonical keys here keeps the match set to values that COULD be a real content-key.
    let requested: HashSet<String> = requested_keys
        .iter()
        .filter(|k| is_canonical_hex_id(k))
        .map(|k| k.to_ascii_lowercase())
        .collect();
    if requested.is_empty() {
        return Vec::new();
    }

    let mut resolved = Vec::new();
    for capsule in held {
        let (Some(store), Some(root)) = (hex64(&capsule.store_id), hex64(&capsule.root)) else {
            continue; // a malformed inventory entry can never be a valid content-key
        };
        let content_key = dig_dht::ContentId::capsule(store, root).to_key().to_hex();
        if requested.contains(&content_key) {
            resolved.push(ResolvedCapsule {
                content_key,
                store_id: capsule.store_id.clone(),
                root: capsule.root.clone(),
                size_bytes: capsule.size_bytes,
            });
        }
    }
    resolved
}

/// Build the `dig.resolveCapsule` RESULT value from this node's live holdings.
///
/// The thin async shell over [`resolve_capsule_result`]: parse + clamp the request, read this node's
/// current holdings reverse index ([`crate::CapsuleStore::cache_list_cached`]), resolve, and wrap the
/// answer as `{ "resolved": [ … ] }`. Kept minimal — all policy (the clamp, the match, the not-held ⇒
/// absent rule) lives in the two pure helpers so it is unit-tested without a peer connection.
pub(crate) async fn resolve_capsule_answer(node: &Arc<crate::Node>, params: &Value) -> Value {
    use crate::CapsuleStore;
    let requested = requested_keys_from_params(params);
    let held = node.cache_list_cached().await;
    let resolved = resolve_capsule_result(&held, &requested);
    json!({ "resolved": resolved })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genuine DHT content-key for a `(store, root)` capsule — the value a holder recomputes and the
    /// sampler would have found. Built through the SAME `ContentId::capsule(..).to_key()` path the server
    /// uses, so the test pins the real key↔preimage relation, not a hand-copied digest.
    fn content_key_for(store: [u8; 32], root: [u8; 32]) -> String {
        dig_dht::ContentId::capsule(store, root).to_key().to_hex()
    }

    fn held(store: [u8; 32], root: [u8; 32], size_bytes: u64) -> CachedCapsule {
        CachedCapsule {
            store_id: hex::encode(store),
            root: hex::encode(root),
            size_bytes,
            last_used_unix_ms: 0,
            provenance: crate::CapsuleProvenance::Held,
        }
    }

    #[test]
    fn a_held_key_resolves_to_its_correct_store_root_and_size() {
        let (store, root) = ([0xab; 32], [0xcd; 32]);
        let key = content_key_for(store, root);
        let inventory = vec![held(store, root, 4_096)];

        let resolved = resolve_capsule_result(&inventory, std::slice::from_ref(&key));

        assert_eq!(
            resolved.len(),
            1,
            "the held key resolves to exactly one record"
        );
        assert_eq!(resolved[0].content_key, key);
        assert_eq!(resolved[0].store_id, hex::encode(store));
        assert_eq!(resolved[0].root, hex::encode(root));
        assert_eq!(
            resolved[0].size_bytes, 4_096,
            "the on-disk size is reported"
        );
    }

    #[test]
    fn a_non_held_key_is_absent_never_an_error() {
        // The node holds capsule A; the caller asks for capsule B's key. B must simply be absent — the
        // `getAvailability` not-held idiom, never an error record.
        let inventory = vec![held([0x01; 32], [0x02; 32], 10)];
        let unheld_key = content_key_for([0xff; 32], [0xee; 32]);

        let resolved = resolve_capsule_result(&inventory, &[unheld_key]);

        assert!(
            resolved.is_empty(),
            "a key this node does not hold is absent"
        );
    }

    #[test]
    fn only_the_genuine_holding_matches_its_computed_key() {
        // Two held capsules; asking for one key must return ONLY that capsule, proving the match is the
        // recomputed key equality and not, say, positional or first-record coincidence.
        let a = ([0x11; 32], [0x22; 32]);
        let b = ([0x33; 32], [0x44; 32]);
        let inventory = vec![held(a.0, a.1, 1), held(b.0, b.1, 2)];
        let key_b = content_key_for(b.0, b.1);

        let resolved = resolve_capsule_result(&inventory, std::slice::from_ref(&key_b));

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].content_key, key_b);
        assert_eq!(
            resolved[0].store_id,
            hex::encode(b.0),
            "the RIGHT preimage is returned"
        );
        assert_eq!(resolved[0].size_bytes, 2);
    }

    #[test]
    fn a_malformed_requested_key_is_dropped_not_fatal() {
        // A non-64-hex requested key can never equal a recomputed key; it must be dropped silently, and
        // a genuine key alongside it must still resolve — no panic, no poisoning of the batch.
        let (store, root) = ([0x55; 32], [0x66; 32]);
        let good = content_key_for(store, root);
        let inventory = vec![held(store, root, 7)];

        let requested = vec![
            "not-hex".to_string(),
            "z".repeat(64),                       // right length, wrong alphabet
            good[..63].to_string(),               // wrong length
            format!("{}\ninjected", &good[..54]), // control chars
            good.clone(),                         // the one genuine key
        ];
        let resolved = resolve_capsule_result(&inventory, &requested);

        assert_eq!(
            resolved.len(),
            1,
            "only the genuine key resolves; malformed keys are dropped"
        );
        assert_eq!(resolved[0].content_key, good);
    }

    #[test]
    fn an_uppercase_requested_key_still_matches_a_lowercase_computed_key() {
        // A caller may send the key in either casing; canonical hex is case-insensitive, so an uppercase
        // request must resolve the same holding as its lowercase computed key.
        let (store, root) = ([0x7a; 32], [0x8b; 32]);
        let key_upper = content_key_for(store, root).to_ascii_uppercase();
        let inventory = vec![held(store, root, 9)];

        let resolved = resolve_capsule_result(&inventory, &[key_upper]);

        assert_eq!(
            resolved.len(),
            1,
            "an uppercase request matches the lowercase computed key"
        );
    }

    #[test]
    fn a_malformed_inventory_entry_is_skipped() {
        // A garbage on-disk entry (non-64-hex store) cannot be a valid content-key; it must be skipped
        // rather than panicking the whole resolve. The genuine held capsule beside it still resolves.
        let (store, root) = ([0x0a; 32], [0x0b; 32]);
        let good = content_key_for(store, root);
        let inventory = vec![
            CachedCapsule {
                store_id: "not-a-real-store".to_string(),
                root: "garbage".to_string(),
                size_bytes: 1,
                last_used_unix_ms: 0,
                provenance: crate::CapsuleProvenance::Held,
            },
            held(store, root, 5),
        ];

        let resolved = resolve_capsule_result(&inventory, std::slice::from_ref(&good));

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].content_key, good);
    }

    #[test]
    fn the_request_batch_is_clamped_to_the_frame_safe_cap() {
        // An over-cap `content_keys` list must be truncated to the cap, so one small request cannot drive
        // an oversized holdings walk / response.
        let over_cap: Vec<Value> = (0..(MAX_RESOLVE_CAPSULE_KEYS + 50) as u32)
            .map(|i| json!(hex::encode(i.to_be_bytes().repeat(8))))
            .collect();
        let params = json!({ "content_keys": over_cap });

        let parsed = requested_keys_from_params(&params);

        assert_eq!(
            parsed.len(),
            MAX_RESOLVE_CAPSULE_KEYS,
            "an over-cap request is clamped to the frame-safe ceiling"
        );
    }

    #[test]
    fn an_under_cap_request_passes_through_whole_and_absent_field_is_empty() {
        let params = json!({ "content_keys": [ "aa".repeat(32), "bb".repeat(32) ] });
        assert_eq!(
            requested_keys_from_params(&params).len(),
            2,
            "under-cap is kept whole"
        );

        // A request with no `content_keys` field is supported — it simply resolves nothing.
        assert!(requested_keys_from_params(&json!({})).is_empty());
        assert!(requested_keys_from_params(&Value::Null).is_empty());
    }

    #[test]
    fn the_resolve_cap_keeps_a_full_answer_under_the_frame_ceiling() {
        // The WHY behind the value: a maximal answer must fit read_framed's 64 KiB control-frame ceiling,
        // or the peer's own reader would reject the data we serve. ~300 B/record is the measured worst
        // case (three 64-hex ids + field names + a u64 size + JSON punctuation).
        const FRAME_CEILING: usize = 64 * 1024;
        const BYTES_PER_RECORD: usize = 300;
        const {
            assert!(
                MAX_RESOLVE_CAPSULE_KEYS * BYTES_PER_RECORD < FRAME_CEILING,
                "a full resolve answer must fit under the 64 KiB control-frame ceiling"
            );
        }
    }

    #[test]
    fn no_requested_keys_resolves_nothing_even_with_holdings() {
        let inventory = vec![held([0x01; 32], [0x02; 32], 1)];
        assert!(resolve_capsule_result(&inventory, &[]).is_empty());
    }

    /// **Proves:** over a REAL loopback mTLS peer connection, `dig.resolveCapsule` resolves a sampled
    /// content-key the server GENUINELY HOLDS to its correct `(store_id, root, size)` preimage, sourced
    /// from the server's own on-disk holdings — the end-to-end tier-0 precache key→preimage resolve over
    /// the honest node-to-node wire. This is the server-side counterpart of `neighbourhood_probe`'s
    /// two-node round-trip.
    ///
    /// Binds a loopback socket, so it may not run under the sandbox's socket limit; it is structured to
    /// pass on a real CI runner (the same pattern as `neighbourhood_probe.rs`).
    #[tokio::test]
    async fn two_node_round_trip_resolves_a_held_key_to_its_preimage() {
        use std::net::SocketAddr;
        use std::time::Duration;

        use serde_json::json;

        use crate::peer::{
            install_crypto_provider, load_or_generate_node_cert, read_framed,
            serve_peer_rpc_listener, write_framed, NodeResponder, PeerRpcResponder,
        };

        fn seed(label: &str) -> [u8; 32] {
            use sha2::{Digest, Sha256};
            Sha256::digest(label.as_bytes()).into()
        }

        install_crypto_provider();

        // A real server node that GENUINELY holds a capsule: write `<cache>/modules/<store>/<root>.dig`
        // into the node's cache dir so `cache_list_cached` discovers it exactly as a landed capsule.
        let (node, cache) = crate::test_support::test_node_for_peer_surface();
        let (store, root) = ([0xab; 32], [0xcd; 32]);
        let capsule_bytes = vec![0x7u8; 512]; // the on-disk `.dig` — its length is the reported size
        let store_dir = cache.path().join("modules").join(hex::encode(store));
        std::fs::create_dir_all(&store_dir).expect("store dir");
        std::fs::write(
            store_dir.join(format!("{}.dig", hex::encode(root))),
            &capsule_bytes,
        )
        .expect("write held capsule");
        let expected_key = content_key_for(store, root);

        let server_dir = tempfile::tempdir().expect("server cert dir");
        let server_identity =
            load_or_generate_node_cert(server_dir.path(), &seed("resolve-holder"))
                .expect("holder id");
        let server_peer_id = server_identity.peer_id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().expect("addr");
        let responder: Arc<dyn PeerRpcResponder> = Arc::new(NodeResponder::without_pool(node));
        let _server = tokio::spawn(serve_peer_rpc_listener(
            listener,
            server_identity,
            responder,
        ));

        // The client dials the real server and calls dig.resolveCapsule for the sampled key over mTLS.
        let client_dir = tempfile::tempdir().expect("client cert dir");
        let client_identity =
            load_or_generate_node_cert(client_dir.path(), &seed("resolve-reader"))
                .expect("reader id");
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(10))
            .build();
        let target = dig_nat::PeerTarget::with_addrs(
            dig_dht::PeerId::from_bytes(*server_peer_id.as_bytes()),
            vec![SocketAddr::new(addr.ip(), addr.port())],
            "DIG_MAINNET".to_string(),
        );
        let mut conn = dig_nat::connect(&target, &client_identity, &config)
            .await
            .expect("dial the holder over mTLS");
        let mut stream = conn.session.open_stream().await.expect("open stream");
        write_framed(
            &mut stream,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": RESOLVE_CAPSULE_METHOD,
                "params": { "content_keys": [ expected_key.clone(), "ff".repeat(32) ] },
            }),
        )
        .await
        .expect("write request");
        let response = read_framed(&mut stream)
            .await
            .expect("read response")
            .expect("a response frame");

        let resolved = response["result"]["resolved"]
            .as_array()
            .expect("resolved is an array");
        assert_eq!(
            resolved.len(),
            1,
            "only the held key resolves; the absent key is absent"
        );
        assert_eq!(resolved[0]["content_key"], expected_key);
        assert_eq!(resolved[0]["store_id"], hex::encode(store));
        assert_eq!(resolved[0]["root"], hex::encode(root));
        assert_eq!(
            resolved[0]["size_bytes"].as_u64().expect("size"),
            capsule_bytes.len() as u64,
            "the on-disk `.dig` size round-trips"
        );
    }
}
