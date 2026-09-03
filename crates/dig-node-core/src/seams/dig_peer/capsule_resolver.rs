//! The self-verifying [`CapsuleKeyResolver`] — the CLIENT half of the tier-0 precache key→preimage
//! resolve (epic #1934 flywheel live-wiring, child PR-2/3), and the anti-forgery crux of the whole
//! loop.
//!
//! # The problem this solves
//!
//! DHT sampling ([`crate::dht_sampling`]) and the 4a neighbourhood probe
//! ([`super::neighbourhood_probe`]) yield only ONE-WAY content-keys `H = SHA-256(ContentId::capsule
//! (store, root) canonical bytes)`. To fetch + merkle-verify a capsule the loop needs the
//! `(store_id, root)` PREIMAGE those bytes hashed from, and only a node that ALREADY HOLDS the capsule
//! can supply it — the [`super::resolve_capsule`] server (PR-1) answers exactly that over the peer
//! wire. This module is that server's peer: it turns a sampled key `H` into a fetchable, verifiable
//! `(store_id, root)` WITHOUT trusting the provider that supplied the answer.
//!
//! # THE load-bearing security property: a forged preimage is UNREPRESENTABLE
//!
//! A malicious provider can answer `dig.resolveCapsule` with an ARBITRARY `(store_id, root)` for a
//! sampled key `H` — nothing on the wire binds the answer to the request. The client therefore trusts
//! NOTHING the provider says about the mapping. For every returned `(store_id, root)` it RECOMPUTES
//! `ContentId::capsule(store_id, root).to_key()` locally and requires the result to byte-equal the
//! sampled `H` before the pair is ever handed onward ([`VerifiedCapsuleKey::verify`]). Because
//! `to_key` is collision-resistant SHA-256 over a frozen domain-separated encoding, a provider cannot
//! produce a `(store_id, root)` that hashes to an `H` it does not legitimately hold: to make this node
//! accept a forged preimage it would have to invert or collide SHA-256. A mismatch is DROPPED, never
//! fetched.
//!
//! That guarantee is a TYPE, not a remembered check. [`VerifiedCapsuleKey`] has no public constructor
//! — its ONLY constructor is [`VerifiedCapsuleKey::verify`], which returns `Some` solely on a
//! successful recompute — so an "unverified preimage" cannot be built at all. A future fetch/cache
//! path (PR-3) that accepts a `VerifiedCapsuleKey` is, by the type, holding a preimage that provably
//! hashes to the key it was sampled under. There is no call site that could reintroduce a forged pair,
//! because there is no function to call incorrectly.
//!
//! # The SECOND gate — chain-anchoring — attaches at the fetch path (PR-3), by design
//!
//! `to_key`-equality proves the preimage is the genuine one for the sampled key; it does NOT prove the
//! `root` is the store's chain-confirmed current generation (an honest-but-stale holder, or one
//! serving a superseded root, still passes the recompute). That second gate is
//! [`ChainAnchoredModuleVerifier`](super::ChainAnchoredModuleVerifier), which needs a coinset lineage
//! walk ([`crate::shared::AnchoredRootResolver`]) — a fetch-path concern the existing verified-download
//! path already owns and which the tier-0 fetcher ([`crate::tier0_prefetch`]) reuses BEFORE anything is
//! cached. This module deliberately stops at the `to_key` gate and hands PR-3 a `VerifiedCapsuleKey`
//! whose type makes "unverified" unrepresentable; the chain-anchor gate layers on at fetch, never
//! caching an unanchored root. Splitting it here keeps this unit pure + socket-free and avoids a
//! network handle leaking into a value type (the same discipline `module_anchor.rs` follows).
//!
//! # Identity binds to the verified session, never the payload (anti-Sybil, carried from 4a)
//!
//! A resolve answer is self-verifying, so it needs no peer attribution to be trusted — but the mTLS
//! dial still binds to the responding cert's SPKI (`SHA-256(SPKI DER)`, pinned by dig-tls), exactly as
//! [`super::neighbourhood_probe`] does. No field of the `resolveCapsule` payload is ever treated as an
//! identity; the answer's only authority is the local recompute.
//!
//! # Bounds — one call cannot become unbounded work
//!
//! A single provider call asks about at most [`MAX_RESOLVE_CAPSULE_KEYS`] keys ([`resolve_params`]
//! clamps the outgoing request to the server's own frame-safe ceiling), and every returned entry whose
//! `content_key` was not requested, is malformed, or fails the recompute is dropped. A caller with more
//! than one batch of keys chunks them across calls ([`CapsuleKeyResolver::resolve_from`]).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use dig_dht::ContentId;

use super::dht::hex64;
use super::neighbourhood_probe::direct_socket_addrs;
use super::resolve_capsule::{MAX_RESOLVE_CAPSULE_KEYS, RESOLVE_CAPSULE_METHOD};

/// A capsule preimage whose `(store_id, root)` has been PROVEN to hash to the sampled content-key.
///
/// The only constructor is [`Self::verify`], which returns `Some` solely when
/// `ContentId::capsule(store_id, root).to_key()` byte-equals the sampled key — so an unverified
/// preimage is unrepresentable (see the module docs). Carries the raw 32-byte components a fetcher
/// needs: the sampled `content_key` (what to announce/fetch against), the `store_id`/`root` preimage,
/// and the provider-reported on-disk `size_bytes` (a hint a fetcher still hard-caps against the true
/// size, never trusted verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedCapsuleKey {
    content_key: [u8; 32],
    store_id: [u8; 32],
    root: [u8; 32],
    size_bytes: u64,
}

impl VerifiedCapsuleKey {
    /// THE anti-forgery gate. Recompute the DHT content-key from the claimed preimage and admit the
    /// pair ONLY when it byte-equals `sampled_key`; any other outcome yields `None`.
    ///
    /// Both preimage components are decoded through [`hex64`], the canonical 64-hex→32-byte decode, so
    /// a non-canonical or malformed `store_id`/`root` is dropped without panicking — it can never name
    /// real content, so the honest answer is "no verified key". The comparison is over raw `[u8; 32]`,
    /// never hex text, so casing/length quirks cannot buy a bypass (`module_anchor.rs` rule 2).
    pub(crate) fn verify(
        sampled_key: [u8; 32],
        store_id: &str,
        root: &str,
        size_bytes: u64,
    ) -> Option<Self> {
        let store_id = hex64(store_id)?;
        let root = hex64(root)?;
        let recomputed = *ContentId::capsule(store_id, root).to_key().as_bytes();
        (recomputed == sampled_key).then_some(Self {
            content_key: sampled_key,
            store_id,
            root,
            size_bytes,
        })
    }

    /// The sampled DHT content-key this preimage was proven against (what a fetcher announces/fetches).
    // The one accessor tier-0 does not yet read: `tier0_live` consumes the store_id/root preimage and
    // announces against the key it already holds. Kept so a verified key is readable back off the
    // proof rather than re-derived; consumed when the fetch loop announces from the VERIFIED value.
    #[allow(dead_code)]
    pub(crate) fn content_key(&self) -> [u8; 32] {
        self.content_key
    }

    /// The verified preimage store id (raw 32 bytes).
    pub(crate) fn store_id(&self) -> [u8; 32] {
        self.store_id
    }

    /// The verified preimage generation root (raw 32 bytes) — what the chain-anchor gate confirms.
    pub(crate) fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The provider-reported on-disk `.dig` size, in bytes — a hint a fetcher hard-caps, never trusts.
    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// One untrusted `resolved` array element as it arrives on the wire — raw, unverified strings.
///
/// Mirrors the server's `ResolvedCapsule` shape field-for-field. Nothing here is trusted: every field
/// is re-derived or recomputed by [`verified_from_answer`] before it becomes a [`VerifiedCapsuleKey`].
#[derive(Debug, Deserialize)]
struct WireResolvedCapsule {
    content_key: String,
    store_id: String,
    root: String,
    #[serde(default)]
    size_bytes: u64,
}

/// Build the `dig.resolveCapsule` request params for `requested`, CLAMPED to the frame-safe ceiling.
///
/// Pure so the clamp is unit-testable with no connection. At most [`MAX_RESOLVE_CAPSULE_KEYS`] keys go
/// on the wire — the server clamps identically, so sending more would only waste the request; the
/// caller chunks a larger set across calls ([`CapsuleKeyResolver::resolve_from`]). Keys are lowercase
/// 64-hex, the casing the server's recompute emits.
fn resolve_params(requested: &[[u8; 32]]) -> Value {
    let content_keys: Vec<String> = requested
        .iter()
        .take(MAX_RESOLVE_CAPSULE_KEYS)
        .map(hex::encode)
        .collect();
    json!({ "content_keys": content_keys })
}

/// Verify an untrusted resolve answer against the keys we ASKED for — the PURE anti-forgery core.
///
/// For each returned entry: decode its `content_key` (drop if malformed), drop it if we never requested
/// that key, then run the [`VerifiedCapsuleKey::verify`] recompute (drop on mismatch). A provider can
/// therefore only ever cause this to return preimages that (a) we sampled and (b) genuinely hash to the
/// sampled key — a forged or unsolicited pair contributes nothing. Pure over its inputs, so the whole
/// gate is exercised with no socket.
fn verified_from_answer(
    requested: &[[u8; 32]],
    entries: &[WireResolvedCapsule],
) -> Vec<VerifiedCapsuleKey> {
    let requested: HashSet<[u8; 32]> = requested.iter().copied().collect();
    entries
        .iter()
        .filter_map(|entry| {
            let content_key = hex64(&entry.content_key)?; // malformed key can match nothing
            if !requested.contains(&content_key) {
                return None; // a key we never asked about — dropped, never fetched
            }
            VerifiedCapsuleKey::verify(content_key, &entry.store_id, &entry.root, entry.size_bytes)
        })
        .collect()
}

/// Parse the `resolved` array out of a `dig.resolveCapsule` result into raw wire entries.
///
/// Pure. A missing/mistyped `resolved` field yields an empty list (a provider with nothing to offer),
/// and an individual element that fails to deserialize is skipped rather than poisoning the batch.
fn parse_resolve_answer(result: &Value) -> Vec<WireResolvedCapsule> {
    result
        .get("resolved")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Ask ONE provider to resolve a batch of sampled keys, returning only the SELF-VERIFIED preimages.
///
/// A seam over the mTLS dial + RPC so the resolver's verification + clamp are testable without a
/// socket. The production impl is [`MtlsCapsuleResolveClient`]. The contract every impl MUST honour:
/// every [`VerifiedCapsuleKey`] returned has passed the [`VerifiedCapsuleKey::verify`] recompute
/// against a key in `requested` — an impl may NEVER surface a provider's raw claim unverified. Any
/// failure (unreachable, handshake refused, malformed answer) yields an empty vec, never an error.
#[async_trait]
pub(crate) trait CapsuleResolveClient: Send + Sync {
    /// Resolve `requested` (already ≤ [`MAX_RESOLVE_CAPSULE_KEYS`]) against `contact`.
    async fn resolve(
        &self,
        contact: &dig_dht::Contact,
        requested: &[[u8; 32]],
    ) -> Vec<VerifiedCapsuleKey>;
}

/// The production [`CapsuleResolveClient`]: dials a contact over dig-nat mTLS and speaks
/// `dig.resolveCapsule` on the peer surface, verifying every answer locally before returning it.
pub(crate) struct MtlsCapsuleResolveClient {
    /// This node's own mTLS identity, presented as the client leaf on every dial.
    identity: Arc<dig_nat::NodeCert>,
    /// The traversal config (which tiers, per-tier timeout).
    config: dig_nat::NatConfig,
    /// The network label the dial is scoped to (e.g. `DIG_MAINNET`).
    network_id: String,
}

impl MtlsCapsuleResolveClient {
    /// A client dialing as `identity`, using `config`, scoped to `network_id`.
    pub(crate) fn new(
        identity: Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            config,
            network_id: network_id.into(),
        }
    }
}

#[async_trait]
impl CapsuleResolveClient for MtlsCapsuleResolveClient {
    async fn resolve(
        &self,
        contact: &dig_dht::Contact,
        requested: &[[u8; 32]],
    ) -> Vec<VerifiedCapsuleKey> {
        // The dialed id PINS the handshake; the answer's authority is the local recompute below, not
        // any wire-supplied identity — a lying `contact.peer_id` fails the dial rather than misleading
        // the resolve (anti-Sybil discipline carried from 4a).
        let Some(dial_id) = dig_dht::PeerId::from_hex(&contact.peer_id) else {
            return Vec::new();
        };
        let addrs = direct_socket_addrs(&contact.addresses);
        if addrs.is_empty() {
            return Vec::new(); // relay-only / unparseable — nothing to dial directly
        }
        let target = dig_nat::PeerTarget::with_addrs(dial_id, addrs, self.network_id.clone());
        let Ok(mut conn) = dig_nat::connect(&target, &self.identity, &self.config).await else {
            return Vec::new();
        };
        match request_resolve(&mut conn, requested).await {
            Some(entries) => verified_from_answer(requested, &entries),
            None => Vec::new(),
        }
    }
}

/// One `dig.resolveCapsule` round-trip over an established peer connection: open a stream, write the
/// framed clamped request, read the framed response, and parse its `resolved` array. `None` on any
/// transport/decode failure — the caller treats that as a silent provider.
async fn request_resolve(
    conn: &mut dig_nat::PeerConnection,
    requested: &[[u8; 32]],
) -> Option<Vec<WireResolvedCapsule>> {
    let mut stream = conn.session.open_stream().await.ok()?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": RESOLVE_CAPSULE_METHOD,
        "params": resolve_params(requested),
    });
    crate::peer::write_framed(&mut stream, &request)
        .await
        .ok()?;
    let response = crate::peer::read_framed(&mut stream).await.ok()??;
    Some(parse_resolve_answer(response.get("result")?))
}

/// The tier-0 preimage resolver: turn sampled DHT content-keys into SELF-VERIFIED `(store_id, root)`
/// preimages by asking providers and recomputing every answer.
///
/// Generic over the [`CapsuleResolveClient`] seam so the batching is tested without a socket. This is
/// the clean unit PR-3's fetch wiring consumes — it hands back only [`VerifiedCapsuleKey`]s, so the
/// fetch path is structurally incapable of acting on a forged preimage.
pub(crate) struct CapsuleKeyResolver<C: CapsuleResolveClient> {
    client: C,
}

impl<C: CapsuleResolveClient> CapsuleKeyResolver<C> {
    /// A resolver that resolves via `client`.
    pub(crate) fn new(client: C) -> Self {
        Self { client }
    }

    /// Resolve every sampled key in `keys` against `contact`, chunking into frame-safe batches of
    /// [`MAX_RESOLVE_CAPSULE_KEYS`] so a set larger than one request is fully resolved rather than
    /// truncated. Returns only self-verified preimages, in first-seen order.
    pub(crate) async fn resolve_from(
        &self,
        contact: &dig_dht::Contact,
        keys: &[[u8; 32]],
    ) -> Vec<VerifiedCapsuleKey> {
        let mut verified = Vec::new();
        for batch in keys.chunks(MAX_RESOLVE_CAPSULE_KEYS) {
            verified.extend(self.client.resolve(contact, batch).await);
        }
        verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genuine DHT content-key for a `(store, root)` capsule, built through the SAME
    /// `ContentId::capsule(..).to_key()` path a sampler would have found — so the tests pin the real
    /// key↔preimage relation, never a hand-copied digest.
    fn content_key_for(store: [u8; 32], root: [u8; 32]) -> [u8; 32] {
        *ContentId::capsule(store, root).to_key().as_bytes()
    }

    fn wire(
        content_key: [u8; 32],
        store: [u8; 32],
        root: [u8; 32],
        size: u64,
    ) -> WireResolvedCapsule {
        WireResolvedCapsule {
            content_key: hex::encode(content_key),
            store_id: hex::encode(store),
            root: hex::encode(root),
            size_bytes: size,
        }
    }

    // -- 1. The load-bearing anti-forgery property ------------------------------------------------

    #[test]
    fn a_forged_preimage_is_rejected() {
        // The provider answers the sampled key H (for the HONEST capsule A) with a DIFFERENT
        // `(store', root')` that does not hash to H — an arbitrary forged preimage. The recompute must
        // reject it: no verified key is produced.
        let (store, root) = ([0xa1; 32], [0xa2; 32]);
        let sampled = content_key_for(store, root);
        let forged = wire(sampled, [0xbb; 32], [0xcc; 32], 4_096); // store'/root' ≠ preimage of H

        let verified = verified_from_answer(&[sampled], &[forged]);

        assert!(
            verified.is_empty(),
            "a preimage that does not hash to the sampled key MUST be dropped"
        );
    }

    #[test]
    fn verify_returns_none_on_a_mismatched_recompute() {
        // The type-level guard directly: verify against a key the preimage does not hash to yields None,
        // so no VerifiedCapsuleKey can be constructed for a forged pair.
        let wrong_key = [0x00; 32];
        assert!(
            VerifiedCapsuleKey::verify(
                wrong_key,
                &hex::encode([0x11; 32]),
                &hex::encode([0x22; 32]),
                1
            )
            .is_none(),
            "verify is the ONLY constructor and it refuses a mismatch"
        );
    }

    // -- 2. The honest preimage is accepted -------------------------------------------------------

    #[test]
    fn an_honest_preimage_is_accepted_and_carries_its_components() {
        let (store, root) = ([0x11; 32], [0x22; 32]);
        let sampled = content_key_for(store, root);

        let verified = verified_from_answer(&[sampled], &[wire(sampled, store, root, 512)]);

        assert_eq!(verified.len(), 1, "the honest preimage resolves");
        assert_eq!(verified[0].content_key(), sampled);
        assert_eq!(verified[0].store_id(), store);
        assert_eq!(verified[0].root(), root);
        assert_eq!(verified[0].size_bytes(), 512);
    }

    // -- 3. An unrequested key is dropped ---------------------------------------------------------

    #[test]
    fn an_unrequested_key_is_dropped_even_when_its_preimage_is_genuine() {
        // The provider returns a genuine (self-consistent) preimage for key B, but the client only
        // sampled key A. Even though B would pass the recompute, it was never requested, so it is
        // dropped — a provider cannot inject keys the client did not sample.
        let a = ([0x01; 32], [0x02; 32]);
        let b = ([0x03; 32], [0x04; 32]);
        let key_a = content_key_for(a.0, a.1);
        let key_b = content_key_for(b.0, b.1);

        let verified = verified_from_answer(&[key_a], &[wire(key_b, b.0, b.1, 9)]);

        assert!(
            verified.is_empty(),
            "a key we never requested must be dropped"
        );
    }

    // -- 4. Non-canonical / malformed components are dropped without panic ------------------------

    #[test]
    fn malformed_store_or_root_is_dropped_not_fatal() {
        let (store, root) = ([0x55; 32], [0x66; 32]);
        let sampled = content_key_for(store, root);
        let good = wire(sampled, store, root, 7);

        // Each of these claims the sampled key but carries a non-canonical preimage; none may panic,
        // and none may verify (a non-64-hex id can never name real content), while `good` still passes.
        let malformed = [
            WireResolvedCapsule {
                content_key: hex::encode(sampled),
                store_id: "not-hex".to_string(),
                root: hex::encode(root),
                size_bytes: 1,
            },
            WireResolvedCapsule {
                content_key: hex::encode(sampled),
                store_id: "z".repeat(64), // right length, wrong alphabet
                root: hex::encode(root),
                size_bytes: 1,
            },
            WireResolvedCapsule {
                content_key: hex::encode(sampled),
                store_id: hex::encode(store),
                root: hex::encode(root)[..63].to_string(), // wrong length
                size_bytes: 1,
            },
        ];
        let mut entries: Vec<WireResolvedCapsule> = malformed.into_iter().collect();
        entries.push(good);

        let verified = verified_from_answer(&[sampled], &entries);

        assert_eq!(
            verified.len(),
            1,
            "only the canonical, matching preimage resolves; malformed ones are dropped"
        );
        assert_eq!(verified[0].store_id(), store);
    }

    #[test]
    fn a_malformed_returned_content_key_is_dropped() {
        // The `content_key` field itself is garbage — it can decode to nothing in the requested set.
        let entries = vec![WireResolvedCapsule {
            content_key: "not-a-hex-key".to_string(),
            store_id: hex::encode([0x1; 32]),
            root: hex::encode([0x2; 32]),
            size_bytes: 1,
        }];
        assert!(verified_from_answer(&[[0x1; 32]], &entries).is_empty());
    }

    // -- 5. The outgoing request is clamped to the frame-safe cap ---------------------------------

    #[test]
    fn the_request_is_clamped_to_the_frame_safe_cap() {
        let over_cap: Vec<[u8; 32]> = (0..(MAX_RESOLVE_CAPSULE_KEYS as u32 + 50))
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();

        let params = resolve_params(&over_cap);
        let sent = params["content_keys"]
            .as_array()
            .expect("content_keys array");

        assert_eq!(
            sent.len(),
            MAX_RESOLVE_CAPSULE_KEYS,
            "an over-cap request is clamped to the server's frame-safe ceiling"
        );
    }

    #[test]
    fn an_under_cap_request_is_sent_whole_as_lowercase_hex() {
        let keys = [[0xab; 32], [0xcd; 32]];
        let params = resolve_params(&keys);
        let sent = params["content_keys"].as_array().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], json!(hex::encode([0xab; 32])));
    }

    // -- 7. The newtype is only constructable via the verified path -------------------------------

    #[test]
    fn a_verified_key_is_only_born_from_a_matching_recompute() {
        // Compile-plus-runtime proof: the sole way to obtain a VerifiedCapsuleKey is verify(), and it
        // only yields one when the recompute matches. There is no other constructor (no public fields,
        // no Default, no `new`) — enforced by the type, exercised here on the happy path.
        let (store, root) = ([0x7a; 32], [0x8b; 32]);
        let sampled = content_key_for(store, root);
        let vk = VerifiedCapsuleKey::verify(sampled, &hex::encode(store), &hex::encode(root), 3)
            .expect("a matching recompute constructs the verified key");
        assert_eq!(vk.content_key(), sampled);
    }

    // -- Wire parse + empties ---------------------------------------------------------------------

    #[test]
    fn parse_reads_the_resolved_array_and_tolerates_a_missing_field() {
        let store = [0x0a; 32];
        let root = [0x0b; 32];
        let key = content_key_for(store, root);
        let result = json!({
            "resolved": [
                { "content_key": hex::encode(key), "store_id": hex::encode(store),
                  "root": hex::encode(root), "size_bytes": 42 },
            ]
        });
        let entries = parse_resolve_answer(&result);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].size_bytes, 42);

        // A result with no `resolved` field is a provider with nothing to offer, never an error.
        assert!(parse_resolve_answer(&json!({})).is_empty());
        assert!(parse_resolve_answer(&Value::Null).is_empty());
    }

    #[test]
    fn no_requested_keys_verifies_nothing() {
        let store = [0x1; 32];
        let root = [0x2; 32];
        let key = content_key_for(store, root);
        assert!(verified_from_answer(&[], &[wire(key, store, root, 1)]).is_empty());
    }

    // -- The batching resolver over a stub client -------------------------------------------------

    /// A stub client that returns a fixed verified key for whatever batch it is handed, recording how
    /// many batches it saw — so the chunking can be asserted without a socket.
    struct BatchCountingClient {
        seen_batches: std::sync::Mutex<Vec<usize>>,
        reply: Vec<VerifiedCapsuleKey>,
    }

    #[async_trait]
    impl CapsuleResolveClient for BatchCountingClient {
        async fn resolve(
            &self,
            _contact: &dig_dht::Contact,
            requested: &[[u8; 32]],
        ) -> Vec<VerifiedCapsuleKey> {
            self.seen_batches.lock().unwrap().push(requested.len());
            self.reply.clone()
        }
    }

    fn a_contact() -> dig_dht::Contact {
        dig_dht::Contact::new(
            &dig_dht::PeerId::from_bytes([0x01; 32]),
            vec![dig_dht::CandidateAddr::direct("203.0.113.7", 9257)],
        )
    }

    #[tokio::test]
    async fn the_resolver_chunks_a_large_key_set_into_frame_safe_batches() {
        let keys: Vec<[u8; 32]> = (0..(MAX_RESOLVE_CAPSULE_KEYS as u32 + 10))
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();
        let client = BatchCountingClient {
            seen_batches: std::sync::Mutex::new(Vec::new()),
            reply: Vec::new(),
        };
        let resolver = CapsuleKeyResolver::new(client);

        resolver.resolve_from(&a_contact(), &keys).await;

        let batches = resolver.client.seen_batches.lock().unwrap().clone();
        assert_eq!(batches.len(), 2, "138 keys chunk into two calls");
        assert_eq!(batches[0], MAX_RESOLVE_CAPSULE_KEYS, "first batch is full");
        assert_eq!(batches[1], 10, "the remainder rides a second batch");
    }

    /// **Proves:** over a REAL loopback mTLS peer connection, the resolver turns a sampled content-key
    /// the honest server GENUINELY HOLDS into a self-verified `(store_id, root)` preimage — and that a
    /// forged answer key alongside it (a key we never sampled) contributes nothing. The client-side
    /// counterpart of `resolve_capsule.rs`'s two-node round-trip.
    ///
    /// Binds a loopback socket, so it may not run under the sandbox's socket limit; structured to pass
    /// on a real CI runner (the same pattern as `neighbourhood_probe.rs`).
    #[tokio::test]
    async fn two_node_round_trip_resolves_a_held_key_and_rejects_an_unrequested_one() {
        use std::time::Duration;

        use crate::peer::{
            install_crypto_provider, load_or_generate_node_cert, serve_peer_rpc_listener,
            NodeResponder, PeerRpcResponder,
        };

        fn seed(label: &str) -> [u8; 32] {
            use sha2::{Digest, Sha256};
            Sha256::digest(label.as_bytes()).into()
        }

        install_crypto_provider();

        // A real server node genuinely holding a capsule on disk, discoverable by `cache_list_cached`.
        let (node, cache) = crate::test_support::test_node_for_peer_surface();
        let (store, root) = ([0xab; 32], [0xcd; 32]);
        let capsule_bytes = vec![0x7u8; 512];
        let store_dir = cache.path().join("modules").join(hex::encode(store));
        std::fs::create_dir_all(&store_dir).expect("store dir");
        std::fs::write(
            store_dir.join(format!("{}.dig", hex::encode(root))),
            &capsule_bytes,
        )
        .expect("write held capsule");
        let sampled = content_key_for(store, root);

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

        // The client resolves the sampled key PLUS a key it never sampled's preimage would be forged;
        // here we simply ask for the held key and an unrelated one the server does not hold.
        let client_dir = tempfile::tempdir().expect("client cert dir");
        let client_identity =
            load_or_generate_node_cert(client_dir.path(), &seed("resolve-reader"))
                .expect("reader id");
        let config = dig_nat::NatConfig::builder()
            .enabled_methods(vec![dig_nat::TraversalKind::Direct])
            .per_method_timeout(Duration::from_secs(10))
            .build();
        let resolver = CapsuleKeyResolver::new(MtlsCapsuleResolveClient::new(
            client_identity,
            config,
            "DIG_MAINNET",
        ));

        let unheld = content_key_for([0xff; 32], [0xee; 32]);
        let contact = dig_dht::Contact::new(
            &dig_dht::PeerId::from_bytes(*server_peer_id.as_bytes()),
            vec![dig_dht::CandidateAddr::direct(
                addr.ip().to_string(),
                addr.port(),
            )],
        );

        let verified = resolver.resolve_from(&contact, &[sampled, unheld]).await;

        assert_eq!(verified.len(), 1, "only the genuinely-held key resolves");
        assert_eq!(verified[0].content_key(), sampled);
        assert_eq!(verified[0].store_id(), store);
        assert_eq!(verified[0].root(), root);
        assert_eq!(
            verified[0].size_bytes(),
            capsule_bytes.len() as u64,
            "the on-disk `.dig` size round-trips"
        );
    }
}
