//! Local plaintext content-serve (#289/#290) — the node's SERVER-SIDE decrypt path.
//!
//! The node↔node JSON-RPC contract (`POST /`, SPEC §1.3) is and stays BLIND: it returns
//! ciphertext + Merkle proof, and the *client* verifies + decrypts. That is the only surface
//! `rpc.dig.net` and peers ever expose, so plaintext never crosses an untrusted hop.
//!
//! This module adds a DISTINCT capability the LOOPBACK-only service shell drives (`dig-node-service`'s
//! `GET /s/<storeId>[:<root>]/<path>`): resolve the store's chain-anchored root, fetch the resource's
//! ciphertext local-first (then peer, then the public RPC), VERIFY its Merkle inclusion against the
//! chain-anchored root, and DECRYPT it server-side — handing plaintext to a same-machine browser over
//! loopback. Decrypting here is safe precisely because this node is the trusted, key-holding endpoint
//! and the channel is loopback: a browser cannot present a client cert to get plaintext from the public
//! gateway, so the local node is the only place the plaintext read can legitimately happen.
//!
//! Verify-then-decrypt is FAIL-CLOSED and reuses the ONE `digstore-core` read-crypto every DIG layer
//! shares (the same primitives `dig-client-wasm::decryptResource` and `dig-runtime::dig_read_verify_decrypt`
//! wrap): `resource_leaf(ciphertext) == proof.leaf`, `proof.verify()`, `proof.root == chain_anchored_root`,
//! THEN AES-256-GCM-SIV-open each chunk under the per-URN key. A tampered chunk, a decoy/wrong-store
//! response, or a non-anchored root never decrypts. The retrieval key + AES key derive from the SAME
//! canonical ROOTLESS URN the rest of the ecosystem uses (`urn:dig:chia:<store>[/<path>]`, empty path →
//! `index.html`), so a resource served here is byte-identical to one read through any other client.

use base64::Engine;
use digstore_core::codec::{Decode, Decoder};
use digstore_core::crypto::{decrypt_chunk, derive_decryption_key};
use digstore_core::merkle::MerkleProof;
use digstore_core::wire::ContentResponse;
use digstore_core::{resource_leaf, Bytes32, SecretSalt, Urn, CHAIN, DEFAULT_RESOURCE_KEY};
use serde_json::{json, Value};

use crate::{decide_pin, pin_enforced, CapsuleStore, Node, PinDecision, ROOT_NOT_ANCHORED};

/// The upstream/peer "resource not available at this root" code — a genuine content miss (SPEC §10).
const RESOURCE_UNAVAILABLE: i64 = -32004;

/// Which tier served the MAIN resource — surfaced to the browser as `X-Dig-Source` (#292) so the
/// extension toolbar can badge "loaded from local".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeSource {
    /// From a synced+verified `.dig` module on THIS device's disk — no network.
    Local,
    /// Fetched from a peer over the P2P content engine (multi-source, dig-download).
    Peer,
    /// Fetched from a configured upstream RPC, the final fallback. OPTIONAL: no upstream is
    /// configured by default (#1997), in which case this tier does not exist for that node.
    Rpc,
}

impl ServeSource {
    /// The lowercase `X-Dig-Source` header value.
    pub fn as_str(self) -> &'static str {
        match self {
            ServeSource::Local => "local",
            ServeSource::Peer => "peer",
            ServeSource::Rpc => "rpc",
        }
    }
}

/// Whether the P2P content engine was attached when a read was routed — surfaced verbatim as
/// `X-Dig-Peer-Tier` (#1763).
///
/// The engine attaches ~30 s after the HTTP surface opens, so a node answers content reads before
/// there is any peer tier to consult. Such a read is still SERVED (refusing content for half a
/// minute is worse), but it reaches the gateway having skipped Tier 2 entirely. `X-Dig-Source`
/// alone cannot express that: a gateway serve because the peer tier was DOWN and a gateway serve
/// because no peer HELD the resource are both `rpc`. This value is the difference, so a caller —
/// or an acceptance test — can tell whether the peer path was measured or merely absent.
///
/// It reports engine ATTACHMENT and nothing else: not peer count, not reachability, not whether a
/// fetch was attempted, and emphatically not verification (see `X-Dig-Verified`, whose overloaded
/// name is #1738).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTier {
    /// The P2P content engine was attached when this read was routed, so Tier 2 was consultable.
    /// A read that nonetheless came from the gateway genuinely missed on the peer tier.
    Attached,
    /// No P2P content engine was attached, so this read SKIPPED Tier 2. Either the node is still
    /// inside its cold-start window, or it runs on the FFI/in-process path that has no peer
    /// network at all. Any peer-replication conclusion drawn from this read is unfounded.
    Unattached,
}

impl PeerTier {
    /// The lowercase `X-Dig-Peer-Tier` header value.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerTier::Attached => "attached",
            PeerTier::Unattached => "unattached",
        }
    }
}

/// The result of a local plaintext content serve. The HTTP layer (`dig-node-service`) maps each
/// variant to a response: `Served` → 200 with the plaintext + `X-Dig-*` headers; `NotFound` → the
/// SPA-fallback-vs-404 decision (a route serves the store's `index.html`, an asset misses honestly);
/// `RootError`/`Unreadable` → a 502-class error page; `InvalidParams` → 400.
#[derive(Debug)]
pub enum PlaintextOutcome {
    /// The resource was fetched, verified, and decrypted. `verified` is whether the bytes were
    /// verified against the CHAIN-ANCHORED root (`true` under the default pin; `false` only when the
    /// node-side pin is disabled via `DIG_NODE_PIN=off`, in which case the Merkle proof was still
    /// checked for internal consistency but not tied to the on-chain tip).
    Served {
        bytes: Vec<u8>,
        root_hex: String,
        verified: bool,
        source: ServeSource,
        /// Whether the P2P content engine was attached when this read was ROUTED — surfaced as
        /// `X-Dig-Peer-Tier` (#1763). Independent of `source`: a gateway serve is `Unattached`
        /// during cold start but `Attached` once the engine is up and simply missed. Captured
        /// ONCE at request entry and applied uniformly across whichever tier served the bytes
        /// (see [`with_serve_metadata`]), so it describes the routing decision this read faced
        /// rather than a later moment.
        peer_tier: PeerTier,
        /// The store's on-chain OWNER puzzle hash (64-hex) — the future tip recipient, surfaced
        /// as `X-Dig-Owner-Puzzle-Hash` (#486). `None` when the chain-anchored pin did not run
        /// (`DIG_NODE_PIN=off`) or the resolver could not supply it — the header is OMITTED
        /// rather than guessed. Resolved ONCE per request and applied uniformly across whichever
        /// tier served the bytes (see [`with_serve_metadata`]).
        owner_puzzle_hash: Option<String>,
        /// The 0-based commit ordinal that last wrote this resource, per the store's embedded
        /// `PublicManifest` (data-section id 13) — surfaced as `X-Dig-Generation` (#486). `None`
        /// when the module carries no manifest (an older `.dig`) or lists no entry for this
        /// exact key — the header is OMITTED rather than guessed. Local-only (no chain call).
        generation: Option<u64>,
    },
    /// The resource is genuinely not available at the resolved root (a real content miss). Carries the
    /// resolved root so the HTTP layer can look up the store's manifest for the SPA-fallback decision.
    NotFound { root_hex: String },
    /// The mandatory chain-anchored-root pin failed closed (#127): the requested root is not the
    /// on-chain tip, the store has no confirmed generation, or the chain was unreachable.
    RootError { code: i64, message: String },
    /// The request was malformed (store id / salt not 64-hex).
    InvalidParams { message: String },
    /// Bytes were fetched but verification or decryption failed (tamper / wrong key / decode error),
    /// or the fetch itself errored at the transport level. Fail-closed — no plaintext is returned.
    ///
    /// Carries NO numeric code: this outcome's only sink is the HTTP serve path, which answers
    /// `502 BAD_GATEWAY` from the message alone. A `-32000` field here never reached any wire and
    /// was therefore a dead producer rather than a taxonomy gap (dig-node#496).
    Unreadable { message: String, root_hex: String },
}

/// The canonical ROOTLESS resource URN whose SHA-256 is the retrieval key and whose bytes seed the AES
/// content key (`urn:dig:chia:<store>[/<resource_key>]`). Empty `resource_key` → the §8.5 default view
/// `index.html`. Byte-identical to `dig-client-wasm::canonical_resource_urn` / `dig-runtime`'s native
/// derivation, so a key derived here matches the whole ecosystem.
fn canonical_resource_urn(store_id: &Bytes32, resource_key: &str) -> Urn {
    let key = if resource_key.is_empty() {
        DEFAULT_RESOURCE_KEY
    } else {
        resource_key
    };
    Urn {
        chain: CHAIN.to_string(),
        store_id: *store_id,
        root_hash: None,
        resource_key: Some(key.to_string()),
    }
}

/// `retrieval_key = SHA-256(canonical rootless URN)` for `(store_id, resource_key)` — the content
/// address the node fetches by. Empty `resource_key` resolves to `index.html`. Pure; the single
/// derivation the serve path uses so it can never skew from the wasm/native readers.
pub fn derive_retrieval_key(store_id: &Bytes32, resource_key: &str) -> Bytes32 {
    canonical_resource_urn(store_id, resource_key).retrieval_key()
}

/// Parse the optional private-store secret salt (64-hex). `None`/blank → a public store (no salt).
fn parse_salt(salt_hex: Option<&str>) -> Result<Option<[u8; 32]>, ()> {
    match salt_hex {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => Bytes32::from_hex(s.trim())
            .map(|b| Some(b.0))
            .map_err(|_| ()),
    }
}

/// Decode a base64 Merkle inclusion proof (the `X-Dig-Inclusion-Proof` wire form / the first
/// `dig.getContent` window's `inclusion_proof`) into a [`MerkleProof`].
fn decode_proof_b64(proof_b64: &str) -> Option<MerkleProof> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(proof_b64.trim().as_bytes())
        .ok()?;
    // Decode via the `codec::Decode` trait (the inverse of the `Encode`/`to_bytes` wire form the
    // producer + `build_result` emit) — `MerkleProof` has no inherent `from_bytes` at this rev.
    let mut dec = Decoder::new(&raw);
    MerkleProof::decode(&mut dec).ok()
}

/// Verify a served resource's Merkle inclusion against `trusted_root`, then AES-256-GCM-SIV-decrypt it
/// — fail-closed, gate-then-decrypt (Digstore §9.3 + §11), the native counterpart of
/// `dig-client-wasm::decryptResource`. `resource_key` is the EFFECTIVE key (with the `index.html`
/// default already applied). `chunk_lens` are the per-chunk CIPHERTEXT byte lengths (empty ⇒ a single
/// chunk). Returns the decrypted plaintext, or an error string describing the fail-closed reason.
///
/// `trusted_root` is the root the proof must fold to — the store's chain-anchored TIP for a resource
/// last written at the tip, OR the older generation's OWN root when the resource is served from an
/// earlier capsule (#2088). An older capsule's root is NOT chain-anchored (the #127 pin would refuse
/// it from a client), so serving older-generation bytes REQUIRES the second binding:
///
/// `expected_leaf` is the tip-anchored leaf: when `Some`, the proof's leaf MUST equal the
/// `sha256_latest` the CHAIN-ANCHORED TIP manifest (§13) recorded for this path. This is what ties
/// older-generation bytes back to the tip — the older capsule's root is attacker-choosable in
/// isolation, so folding a proof to it proves nothing on its own; only `sha256_latest`, sourced from
/// the tip capsule, authenticates that the served leaf is the one the tip vouches for. `None`
/// (no tip manifest / legacy `.dig`) ⇒ no leaf binding, byte-identical to the pre-#2088 behaviour.
#[allow(clippy::too_many_arguments)]
fn verify_and_decrypt(
    store_id: &Bytes32,
    resource_key: &str,
    ciphertext: &[u8],
    proof: &MerkleProof,
    trusted_root: &Bytes32,
    expected_leaf: Option<Bytes32>,
    salt: Option<&[u8; 32]>,
    chunk_lens: &[u32],
) -> Result<Vec<u8>, String> {
    // 1) Integrity gate: the served bytes are the proof's leaf, the path folds to its root, and that
    //    root is the trusted (chain-anchored tip, or the older generation's own) root. Any failure =
    //    a tampered/decoy/wrong-store serve.
    if resource_leaf(ciphertext) != proof.leaf {
        return Err("inclusion proof leaf does not match the served ciphertext".into());
    }
    if !proof.verify() {
        return Err("inclusion proof does not fold to its root".into());
    }
    if &proof.root != trusted_root {
        return Err("served root is not the store's chain-anchored root".into());
    }
    // 1b) Tip binding (#2088): when the serve root is an OLDER generation (whose own root is not
    //     chain-anchored), the leaf MUST match the `sha256_latest` the chain-anchored TIP manifest
    //     recorded for this path. Without this an attacker who could name any older root could fold a
    //     proof to a capsule of their choosing; sha256_latest — sourced from the tip — closes that.
    if let Some(expected) = expected_leaf {
        if proof.leaf != expected {
            return Err(
                "served leaf does not match the chain-anchored tip manifest's sha256_latest".into(),
            );
        }
    }
    // 2) Confidentiality: derive the per-URN key (mixing the private-store salt when present), split
    //    the plain-concatenated chunk ciphertexts, and open each.
    let canonical = canonical_resource_urn(store_id, resource_key).canonical();
    let salt_owned = salt.map(|s| SecretSalt(*s));
    let aes_key = derive_decryption_key(&canonical, salt_owned.as_ref());

    let plan: Vec<usize> = if chunk_lens.is_empty() {
        vec![ciphertext.len()]
    } else {
        chunk_lens.iter().map(|l| *l as usize).collect()
    };
    if plan.iter().sum::<usize>() != ciphertext.len() {
        return Err("chunk lengths do not sum to the served ciphertext length".into());
    }
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut pos = 0usize;
    for len in plan {
        let ct = &ciphertext[pos..pos + len];
        pos += len;
        let pt = decrypt_chunk(&aes_key, ct)
            .map_err(|_| "AES-256-GCM-SIV tag verification failed (wrong key/salt or tampered)")?;
        plaintext.extend_from_slice(&pt);
    }
    Ok(plaintext)
}

/// A miss/error from the public-RPC (proxy) full-content fetch: a clean content miss vs a transport
/// error, so the caller distinguishes an honest 404 from a fail-closed serve error.
enum ProxyMiss {
    /// The upstream reported `-32004` — the resource is genuinely not available at this root.
    NotFound,
    /// A transport/decode failure talking to the upstream.
    Error(String),
}

/// Seam 5's public surface (#1285/#1303) — the loopback plaintext content-serve operations the
/// `dig-node-service` HTTP layer drives. Implemented by [`Node`] with the method bodies carved
/// unchanged from this module (W1b-1) — a behaviour-preserving trait extraction, not a new
/// implementation. `async_trait`-boxed (matching [`crate::shared::AnchoredRootResolver`]) so the
/// trait stays dyn-compatible for the future `Arc<dyn ContentServer>` handle (W1c).
#[async_trait::async_trait]
pub trait ContentServer: Send + Sync {
    /// Serve a store resource as DECRYPTED plaintext over the trusted loopback surface (#289).
    ///
    /// Resolution order (per `(store, resolved_root)`):
    /// 1. **Local** — a synced+verified `.dig` module on disk (no network). The DEFAULT once a store
    ///    is cached; every subsequent read is local (#290).
    /// 2. **Peer** — the P2P content engine (dig-download multi-source), when one is attached.
    /// 3. **Rpc** — a configured upstream, the final fallback. Absent by default (#1997): with no
    ///    upstream the ladder ends at Peer, and an unheld resource is a clean miss.
    ///
    /// The store's chain-anchored root is resolved FIRST and every serve is pinned to it (#127,
    /// fail-closed): a stale locally-cached generation whose root is not the on-chain tip is not served
    /// as current — the read falls through to a fresh fetch at the tip (so local-default is never
    /// local-FROZEN; a newly-anchored generation is served fresh on the next read, #290). On a miss
    /// against a concrete root the node ALSO kicks off a single-flight background whole-`.dig` sync-down
    /// (`maybe_backfill_capsule`, #290) so the NEXT read is local.
    ///
    /// `requested_root_hex` empty / `"latest"` ⇒ rootless (resolve the tip). `resource_key` empty ⇒
    /// `index.html`. `salt_hex` is the private-store secret salt (`None` ⇒ public store).
    ///
    /// `origin` is the SECURITY LABEL of the connection that asked for this read, derived by the
    /// transport from the accepting connection's real remote address — never assumed from the
    /// endpoint. Only a `Local` read may trigger the network-effecting background legs a miss
    /// reaches (the whole-capsule warm `maybe_backfill_capsule`, and the reshare
    /// `spawn_capsule_reshare` behind the peer tier's `fetch_resource`); a `Peer` read is served
    /// but effects nothing, so a stranger can never drive this node into pulling, caching, and
    /// DHT-announcing capsules of the STRANGER'S choosing (#1576).
    ///
    /// `provenance` is the SECOND landing axis (#1654): even on a `Local` (loopback) connection, a
    /// browser-reported `Sec-Fetch-Site: cross-site` marks the request as driven by another origin's
    /// page (a CSRF vector). The bytes ALWAYS serve regardless of provenance; only the landing side
    /// effects fold to `Peer` for a cross-site request, so a malicious page cannot make this node
    /// land + DHT-announce a capsule of its choosing. Non-browser clients send no header ⇒ first-party.
    async fn serve_content_plaintext(
        &self,
        store_hex: &str,
        requested_root_hex: &str,
        resource_key: &str,
        salt_hex: Option<&str>,
        origin: crate::download::ReadOrigin,
        provenance: crate::download::RequestProvenance,
    ) -> PlaintextOutcome;

    /// The store's public file PATHS at `(store, root)` from the embedded `PublicManifest` (id 13),
    /// or `None` when this node does not hold the capsule OR it carries no manifest (an older `.dig` /
    /// a private store whose paths stay opaque). The HTTP layer uses this to distinguish a KNOWN file
    /// genuinely missing at this root (an honest 404) from an SPA route (serve `index.html`).
    async fn manifest_paths(&self, store_hex: &str, root_hex: &str) -> Option<Vec<String>>;

    /// The store generation (0-based commit ordinal) that most recently wrote `resource_key`, per
    /// the store's embedded `PublicManifest` (id 13) at `(store, root)` — surfaced as
    /// `X-Dig-Generation` (#486). `None` when this node does not hold the capsule, the module
    /// carries no manifest (an older `.dig` or a private store whose paths stay opaque), or the
    /// manifest lists no entry for this exact key (a resource outside the normalized public-path
    /// surface). Local-only (mirrors [`manifest_paths`](Self::manifest_paths)) — never a chain call.
    async fn resource_generation(
        &self,
        store_hex: &str,
        root_hex: &str,
        resource_key: &str,
    ) -> Option<u64>;
}

#[async_trait::async_trait]
impl ContentServer for Node {
    async fn serve_content_plaintext(
        &self,
        store_hex: &str,
        requested_root_hex: &str,
        resource_key: &str,
        salt_hex: Option<&str>,
        origin: crate::download::ReadOrigin,
        provenance: crate::download::RequestProvenance,
    ) -> PlaintextOutcome {
        // The landing axis (#1654): a cross-site request serves the bytes but must NOT trigger the
        // network-effecting landing legs (whole-capsule backfill + reshare/DHT-announce), so a
        // malicious page can never CSRF this node into becoming a holder of a capsule it chose.
        // The READ tiers still use `origin`; only the LANDING calls below use `land_origin`.
        let land_origin = crate::download::landing_origin(origin, provenance);
        let store_id = match Bytes32::from_hex(store_hex.trim()) {
            Ok(b) => b,
            Err(_) => {
                return PlaintextOutcome::InvalidParams {
                    message: "store_id must be a 32-byte (64-hex) launcher id".into(),
                }
            }
        };
        let salt = match parse_salt(salt_hex) {
            Ok(s) => s,
            Err(()) => {
                return PlaintextOutcome::InvalidParams {
                    message: "salt must be 32 bytes (64-hex)".into(),
                }
            }
        };
        let effective_key = if resource_key.is_empty() {
            DEFAULT_RESOURCE_KEY
        } else {
            resource_key
        };

        // -- Mandatory chain-anchored-root pin (#127) --------------------------------------------
        // A concrete, valid requested root; "latest"/malformed ⇒ rootless (resolve the tip).
        let requested_root = Bytes32::from_hex(requested_root_hex).ok();
        let enforced = pin_enforced();
        // The store's current on-chain OWNER puzzle hash (#486), resolved from the SAME chain
        // read as the anchored-root pin below — no second coinset call. Stays `None` when the
        // pin is disabled (`DIG_NODE_PIN=off`) or the resolver can't supply it.
        let mut owner_puzzle_hash: Option<String> = None;
        let pinned_root: Option<Bytes32> = if enforced {
            // Resolve the store's on-chain state via the full singleton-lineage walk. For a healthy
            // store this yields both the tip root AND the owner puzzle hash (#486) in ONE chain read.
            let anchored_state = self
                .anchored_root_resolver
                .anchored_state(&store_id.0)
                .await;
            owner_puzzle_hash = match &anchored_state {
                Ok(Some(state)) => state.owner_puzzle_hash.map(|ph| ph.to_hex()),
                _ => None,
            };
            match requested_root {
                // ROOTED (`dig://<store>:<root>`): the pinned root must equal the current on-chain
                // root (#127 anti-rollback). Prefer the walk's tip (it also carried the owner above);
                // but a walk aborted by a single unparseable intermediate generation (#747 "parse
                // next store: missing child") MUST NOT block a valid pinned root — fall back to the
                // BOUNDED verify (one launcher-hint query, no walk) so the local `/s` tier (§5.3)
                // stays readable (#747/#841). Both paths are fail-closed: the pinned root is accepted
                // only when it is the live on-chain generation.
                Some(req) => match &anchored_state {
                    Ok(Some(state)) if state.root == req => Some(req),
                    Ok(Some(state)) => {
                        return PlaintextOutcome::RootError {
                            code: ROOT_NOT_ANCHORED,
                            message: format!(
                                "served root {} does not match the store's on-chain root {} (chain is the authority)",
                                req.to_hex(),
                                state.root.to_hex()
                            ),
                        }
                    }
                    // Walk broken (#747) or no confirmed generation → bounded fallback anchors the
                    // pinned root directly (owner stays `None`; the walk that carries it is broken).
                    Ok(None) | Err(_) => match self
                        .anchored_root_resolver
                        .verify_pinned_root(&store_id.0, req)
                        .await
                    {
                        Ok(()) => Some(req),
                        Err(message) => {
                            return PlaintextOutcome::RootError {
                                code: ROOT_NOT_ANCHORED,
                                message,
                            }
                        }
                    },
                },
                // ROOTLESS (`dig://<store>`): serve against the resolved chain-anchored TIP — the
                // resolved root surfaces to the client as `X-Dig-Root` + `X-Dig-Verified: true`
                // (#852, SPEC §4.6/§14.4). A rootless request has no candidate to bounded-verify, so
                // it relies on the lineage walk resolved above.
                None => {
                    let anchored: Result<Option<Bytes32>, String> =
                        anchored_state.map(|opt| opt.map(|state| state.root));
                    match decide_pin(true, None, anchored) {
                        PinDecision::ServeAt(root) => Some(root),
                        PinDecision::Reject(code, message) => {
                            return PlaintextOutcome::RootError { code, message }
                        }
                        // decide_pin(true, ..) never returns Unpinned.
                        PinDecision::Unpinned => None,
                    }
                }
            }
        } else {
            requested_root
        };
        // The concrete root everything serves against: the anchored tip under the pin, else the
        // requested root (possibly empty when the pin is off and the request was rootless).
        let root_hex = pinned_root
            .map(|r| r.to_hex())
            .unwrap_or_else(|| requested_root_hex.to_string());
        let verified = enforced;
        // Whether Tier 2 even EXISTS for this read (#1763), captured before any tier runs so the
        // answer describes the routing decision this request faced — not whether the engine
        // happened to attach while the read was in flight. A read routed with no engine skipped the
        // peer tier outright, and the response says so rather than letting a gateway serve pass for
        // a measured P2P result.
        let peer_tier = self.peer_tier();
        // -- Generation resolution (#2088 / #2211) ----------------------------------------------
        // The pin above resolved the store's chain-anchored TIP. Two facts about the tip's embedded
        // `PublicManifest` (§13) drive the serve below:
        //   1. §13 is an ADDITIVE data section — it is NOT committed into the chain-anchored
        //      `current_root`, and NOT checked by the capsule anchor gate (#2203). A malicious holder
        //      can therefore serve a GENUINE, anchor-passing tip capsule carrying a FORGED §13 whose
        //      per-path `(latest_root, sha256_latest)` redirect the read at attacker-chosen content.
        //   2. The tip's own `current_root` commits ONLY the tip generation's leaves — a resource
        //      UNCHANGED since an earlier commit is physically ABSENT from the tip capsule, so serving
        //      it at the tip folds to the constant-time decoy and reads as a miss (#2088).
        //
        // The #2211 anti-rollback rule reconciles the two: serve TIP-AUTHORITATIVE. A path whose
        // current bytes the tip's `current_root` commits is served from the TIP with NO §13 leaf
        // binding — bound purely by `proof.root == tip` (the chain-anchored tip; the pre-#2088 path) —
        // so a §13 forged to redirect that path at a genuine-but-superseded prior generation is NEVER
        // consulted for it, and the tip's current version wins (Case A). The §13 redirect + its
        // `expected_leaf` are consulted ONLY on a genuine tip MISS (Case B): a path whose latest
        // version legitimately lives in an older generation, absent from the tip, which then resolves
        // to that older capsule below. `X-Dig-Generation` (#486) reports the generation the §13 entry
        // records for the path.
        //
        // Resolve — but do NOT yet serve — the §13 redirect candidate (Case B). It is honoured only
        // after the tip serve misses, and only when `latest_root` is a GENUINE root in the store's
        // AUTHENTICATED on-chain lineage (the #184 cross-check): a fabricated/unconfirmable root is
        // dropped, so a tip miss for it falls through to a clean 404, never attacker-named bytes.
        let mut generation: Option<u64> = None;
        let mut redirect: Option<(Bytes32, String, Bytes32)> = None;
        if !root_hex.is_empty() {
            if let Some(entry) = self
                .resource_manifest_entry(store_hex, &root_hex, effective_key)
                .await
            {
                // `X-Dig-Generation` (#486) is stamped from the §13 `generation_index`, which is
                // additive/uncommitted and thus attacker-forgeable: a forged §13 can misreport the
                // generation NUMBER even for a Case-A serve whose BYTES are the correct chain-anchored
                // tip. The served bytes stay safe (bound by `proof.root == tip`); only this cosmetic
                // header can be spoofed. A committed per-path generation closes it (digstore #2203).
                generation = Some(entry.generation_index);
                // The tip (bytes) whose manifest we just read — `pinned_root` under the pin, else the
                // resolved concrete root. A redirect exists only when §13 names a DIFFERENT capsule.
                let tip = pinned_root.or_else(|| Bytes32::from_hex(&root_hex).ok());
                // #2211 (the tampered-capsule closure): a §13 redirect may move this read OFF the
                // chain-anchored tip only when the tip capsule genuinely BACKS its committed
                // `current_root` — its own data folds to the `CurrentRoot` it commits, and that root
                // IS the tip. The tip-authoritative closure above rests on "a tip MISS means the path
                // is legitimately absent from the tip generation"; that holds ONLY if the tip capsule
                // actually holds every leaf its `current_root` commits. The anchor gate compares just
                // the 32-byte `CurrentRoot` HEADER, so it admits a capsule whose header still names the
                // genuine tip while its data was tampered so a tip-committed path no longer folds to
                // it — turning a forged tip MISS into a §13 redirect (rollback). So re-derive the tip
                // capsule here and refuse the redirect if its data does not fold to its committed tip:
                // a tampered tip yields a clean miss, never a downgrade (fail closed).
                if Some(entry.latest_root) != tip
                    && self
                        .tip_capsule_backs_its_committed_root(store_hex, &root_hex, &store_id)
                        .await
                    && self
                        .anchored_root_resolver
                        .verify_lineage_root(&store_id.0, entry.latest_root)
                        .await
                        .is_ok()
                {
                    redirect = Some((
                        entry.latest_root,
                        entry.latest_root.to_hex(),
                        entry.sha256_latest,
                    ));
                }
            }
        }

        let retrieval_key = derive_retrieval_key(&store_id, effective_key).0;
        let rk_hex = hex::encode(retrieval_key);

        // -- TIP-AUTHORITATIVE serve (#2211 Case A) ----------------------------------------------
        // Serve the chain-anchored tip FIRST, with NO §13 leaf binding (`expected_leaf = None`): a
        // path the tip's own `current_root` commits is bound purely by `proof.root == tip`, so a §13
        // `PublicManifest` forged to redirect that path at a genuine-but-superseded prior generation
        // is never reached for it — the tip's current bytes win. This is the pre-#2088 tip serve path,
        // still running the full anchor-gate/uniform enforcement resolved above (#1764/#1765).
        let tip_outcome = self
            .serve_tiers_at_root(
                store_hex,
                &store_id,
                effective_key,
                pinned_root,
                &root_hex,
                None,
                salt.as_ref(),
                verified,
                &root_hex,
                land_origin,
                &retrieval_key,
                &rk_hex,
                &owner_puzzle_hash,
                generation,
                peer_tier,
            )
            .await;

        // A genuine tip SERVE wins outright (Case A): the path is committed by the chain-anchored
        // tip's own `current_root`, so no §13 redirect is consulted for it. Any other tip outcome —
        // a clean miss (`None`) or a deferred `Unreadable` — flows to the §13 redirect pass below.
        let tip_outcome = match tip_outcome {
            Some(out @ PlaintextOutcome::Served { .. }) => return out,
            other => other,
        };

        // -- §13 REDIRECT serve (#2088 Case B) ---------------------------------------------------
        // The tip did NOT serve — either a clean MISS (the path is absent from the tip generation,
        // its latest version living in an older capsule) or an upstream ERROR in the tip pass. A
        // non-Served tip outcome is NOT definitive while a §13 redirect candidate remains (#2088): an
        // upstream error on the tip pass must not pre-empt the older-generation read. So consult the
        // §13 redirect — already resolved + lineage-authenticated above (#184) — binding the older,
        // non-chain-anchored capsule via `expected_leaf` (the tip-anchored `sha256_latest`) so no
        // other content can substitute for it.
        if let Some((redirect_root, ref redirect_hex, redirect_leaf)) = redirect {
            if let Some(out) = self
                .serve_tiers_at_root(
                    store_hex,
                    &store_id,
                    effective_key,
                    Some(redirect_root),
                    redirect_hex,
                    Some(redirect_leaf),
                    salt.as_ref(),
                    verified,
                    &root_hex,
                    land_origin,
                    &retrieval_key,
                    &rk_hex,
                    &owner_puzzle_hash,
                    generation,
                    peer_tier,
                )
                .await
            {
                return out;
            }
        }

        // No §13 redirect served either. Surface the tip pass's own non-Served outcome — an
        // `Unreadable` (an upstream error, deferred until now so it could not pre-empt the redirect),
        // else a clean MISS → the `NotFound` that drives the SPA/404 decision.
        tip_outcome.unwrap_or(PlaintextOutcome::NotFound { root_hex })
    }

    async fn manifest_paths(&self, store_hex: &str, root_hex: &str) -> Option<Vec<String>> {
        let cache_dir = self.cache_dir.clone();
        let capsule = crate::CapsuleKey::parse(store_hex, root_hex)?;
        let outcome = tokio::task::spawn_blocking(move || {
            crate::read_public_manifest_json(&cache_dir, &capsule)
        })
        .await
        .ok()?;
        // The memo retains RENDERED manifest JSON (#2071), so read the paths out of that rather
        // than a decoded tree. Field names are `PublicManifest::to_json`'s, the same shape
        // `dig.getManifest` puts on the wire.
        match outcome {
            Ok(Some(Some(manifest))) => Some(
                manifest
                    .get("entries")?
                    .as_array()?
                    .iter()
                    .filter_map(|e| e.get("path")?.as_str().map(str::to_string))
                    .collect(),
            ),
            _ => None,
        }
    }

    async fn resource_generation(
        &self,
        store_hex: &str,
        root_hex: &str,
        resource_key: &str,
    ) -> Option<u64> {
        self.resource_manifest_entry(store_hex, root_hex, resource_key)
            .await
            .map(|e| e.generation_index)
    }
}

/// The chain-anchored facts a store's TIP `PublicManifest` (§13) records for ONE resource key — the
/// inputs the generation-resolution read (#2088) binds against. A projection of
/// [`digstore_core::PublicManifestEntry`] narrowed to the three fields the serve path needs.
#[derive(Debug, Clone)]
struct ManifestEntry {
    /// The root (capsule) hash of the generation that holds this path's LATEST version — where the
    /// bytes actually live, which may be an OLDER capsule than the tip.
    latest_root: Bytes32,
    /// The 0-based commit ordinal that last wrote this path (surfaced as `X-Dig-Generation`).
    generation_index: u64,
    /// SHA-256 of that latest version's ciphertext leaf — the tip-anchored value the served proof's
    /// leaf must match, the link that binds older-generation bytes back to the chain-anchored tip.
    sha256_latest: Bytes32,
}

impl Node {
    /// Resolve the TIP manifest entry for `(store, tip_root, resource_key)` — a local-only binary
    /// parse of the tip capsule's `PublicManifest` (§13), no wasmtime, no chain call (mirrors
    /// [`ContentServer::resource_generation`]). `None` when this node does not hold the tip capsule,
    /// it carries no manifest (legacy `.dig` / private store), or the manifest lists no entry for
    /// this exact key. The single manifest read behind both generation resolution and the
    /// `X-Dig-Generation` header (#2088/#486).
    async fn resource_manifest_entry(
        &self,
        store_hex: &str,
        tip_root_hex: &str,
        resource_key: &str,
    ) -> Option<ManifestEntry> {
        let cache_dir = self.cache_dir.clone();
        let capsule = crate::CapsuleKey::parse(store_hex, tip_root_hex)?;
        let key = resource_key.to_string();
        let outcome = tokio::task::spawn_blocking(move || {
            crate::read_public_manifest_json(&cache_dir, &capsule)
        })
        .await
        .ok()?;
        let manifest = match outcome {
            Ok(Some(Some(manifest))) => manifest,
            _ => return None,
        };
        let entry = manifest
            .get("entries")?
            .as_array()?
            .iter()
            .find(|e| e.get("path").and_then(Value::as_str) == Some(key.as_str()))?;
        Some(ManifestEntry {
            latest_root: Bytes32::from_hex(entry.get("latest_root")?.as_str()?).ok()?,
            generation_index: entry.get("generation_index")?.as_u64()?,
            sha256_latest: Bytes32::from_hex(entry.get("sha256_latest")?.as_str()?).ok()?,
        })
    }

    /// Whether the cached TIP capsule at `(store, tip_root_hex)` genuinely BACKS its committed
    /// `current_root`: its own data folds to the `CurrentRoot` it commits, AND that committed root is
    /// the chain-anchored tip being served.
    ///
    /// This is the premise the #2211 tip-authoritative closure depends on. A tip serve MISS is treated
    /// as "this path is legitimately absent from the tip generation" (Case B → consult the §13
    /// redirect). That inference is sound only when the tip capsule actually holds every leaf its
    /// `current_root` commits. The capsule anchor gate ([`ChainAnchoredModuleVerifier`]) compares only
    /// the 32-byte `CurrentRoot` HEADER against the chain, never re-deriving the tree from the capsule
    /// data — so it admits a capsule whose header still names the genuine tip while a tip-committed
    /// path has been tampered out of its data. For such a capsule a forged tip MISS would drive a §13
    /// redirect at a genuine-but-superseded prior generation: a rollback.
    ///
    /// So before a redirect is trusted, the tip capsule is re-derived here:
    /// [`digstore_compiler::verify_module_root`] recomputes the merkle root from the capsule's own
    /// `MerkleNodes` and requires it to equal the committed `CurrentRoot`, and that committed root must
    /// equal `tip_root_hex`. Either mismatch means the capsule does not back its committed tip, its
    /// misses are untrustworthy, and the redirect is refused (fail closed). A whole-module read + a
    /// merkle recompute is the cost, so it is run only on the redirect-candidate path (§13 names a
    /// DIFFERENT capsule), never on the common tip-hit read.
    async fn tip_capsule_backs_its_committed_root(
        &self,
        store_hex: &str,
        tip_root_hex: &str,
        store_id: &Bytes32,
    ) -> bool {
        let Some(key) = crate::CapsuleKey::parse(store_hex, tip_root_hex) else {
            return false;
        };
        let cache_dir = self.cache_dir.clone();
        let store_id = *store_id;
        let tip = tip_root_hex.to_string();
        tokio::task::spawn_blocking(move || {
            let path = key.resolve_cached_path(&cache_dir);
            let Ok(module) = std::fs::read(&path) else {
                return false;
            };
            match digstore_compiler::verify_module_root(&module, &store_id) {
                Ok(identity) => identity.root.to_hex() == tip,
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    }
}

impl Node {
    /// Verify + decrypt a locally-decoded [`ContentResponse`] into a `Served` outcome, or `None` when
    /// the local module did not genuinely hold the resource at the anchored root — a cached module
    /// whose generation is not the anchored tip (#127), or a DECOY the module returns for a key it does
    /// not hold (whose proof does not fold to the anchored root, or whose bytes do not decrypt under the
    /// resource's URN key). `None` means "fall through to the peer/RPC tier", never a served/garbage
    /// result — the fail-closed guarantee holds (nothing is served) while a genuine miss still resolves.
    #[allow(clippy::too_many_arguments)]
    fn decrypt_local(
        &self,
        store_id: &Bytes32,
        effective_key: &str,
        resp: &ContentResponse,
        serve_root: Option<Bytes32>,
        expected_leaf: Option<Bytes32>,
        salt: Option<&[u8; 32]>,
        root_hex: &str,
        verified: bool,
    ) -> Option<PlaintextOutcome> {
        // The cached module must be the capsule we resolved to serve from — the chain-anchored tip,
        // or the older generation the tip manifest says holds this file (#2088). A module whose root
        // is neither is a stale generation, not the resource at this serve root — fall through rather
        // than serve it as current (#127, extended to per-path generation resolution).
        if let Some(sr) = serve_root {
            if resp.roothash != sr {
                return None;
            }
        }
        let trusted = serve_root.unwrap_or(resp.roothash);
        verify_and_decrypt(
            store_id,
            effective_key,
            &resp.ciphertext,
            &resp.merkle_proof,
            &trusted,
            expected_leaf,
            salt,
            &resp.chunk_lens,
        )
        .ok()
        .map(|bytes| {
            // Ledger (#307): record the verified local serve + its proof. A decoy/verify failure here
            // returns `None` (fall through to peer/RPC) and is NOT recorded — only this definitive
            // local-served outcome is.
            self.record_verification(
                &store_id.to_hex(),
                root_hex,
                effective_key,
                ServeSource::Local.as_str(),
                verified,
                &resp.merkle_proof,
                None,
            );
            PlaintextOutcome::Served {
                bytes,
                root_hex: root_hex.to_string(),
                verified,
                source: ServeSource::Local,
                // Stamped by the caller (`serve_content_plaintext`) via `with_serve_metadata` —
                // every one of these is resolved ONCE per request, not per tier.
                peer_tier: PeerTier::Unattached,
                owner_puzzle_hash: None,
                generation: None,
            }
        })
    }

    /// Run the three serve tiers (local → peer → optional upstream) against ONE candidate capsule
    /// `serve_root`, returning:
    ///   - `Some(outcome)` — a DEFINITIVE result for this root: a metadata-stamped `Served`, or a
    ///     hard `Unreadable` upstream error. The caller returns it verbatim.
    ///   - `None` — nothing genuinely available at this root (every tier missed, decoyed, or the
    ///     upstream reported not-found / returned bytes that failed verification). The caller may
    ///     retry at the next candidate — the #2211 tip-first → §13-redirect fall-through — or, when
    ///     there is none, answer `NotFound`.
    ///
    /// `expected_leaf` is the tip-anchored `sha256_latest` binding for a §13 REDIRECT read (#2088);
    /// it is `None` for the TIP-AUTHORITATIVE read (#2211), where `proof.root == serve_root` (the
    /// chain-anchored tip) is the sole binding and no §13 leaf is trusted. `serve_root_hex` empty ⇒
    /// no concrete capsule to serve (rootless with the pin off) ⇒ an immediate `None`.
    #[allow(clippy::too_many_arguments)]
    async fn serve_tiers_at_root(
        &self,
        store_hex: &str,
        store_id: &Bytes32,
        effective_key: &str,
        serve_root: Option<Bytes32>,
        serve_root_hex: &str,
        expected_leaf: Option<Bytes32>,
        salt: Option<&[u8; 32]>,
        verified: bool,
        root_hex: &str,
        land_origin: crate::download::ReadOrigin,
        retrieval_key: &[u8; 32],
        rk_hex: &str,
        owner_puzzle_hash: &Option<String>,
        generation: Option<u64>,
        peer_tier: PeerTier,
    ) -> Option<PlaintextOutcome> {
        if serve_root_hex.is_empty() {
            return None;
        }

        // -- Tier 1: LOCAL-FIRST (no network) ----------------------------------------------------
        // A cached module returns a DECOY (constant-time, to hide key existence) for a key it does not
        // hold, whose proof does not fold to the anchored root. So a verify/decrypt failure here means
        // "not genuinely held at this root" — treat it as a MISS and fall through, NOT a hard error.
        if let Some(resp) = self
            .serve_local_cached(store_hex, serve_root_hex, retrieval_key)
            .await
        {
            if let Some(served) = self.decrypt_local(
                store_id,
                effective_key,
                &resp,
                serve_root,
                expected_leaf,
                salt,
                root_hex,
                verified,
            ) {
                return Some(with_serve_metadata(
                    served,
                    owner_puzzle_hash.clone(),
                    generation,
                    peer_tier,
                ));
            }
            // else: a decoy / verify or decrypt failure → fall through to peer/RPC.
        }

        // -- Tier 2: PEER (P2P content engine, when attached) ------------------------------------
        // Best-effort: any failure falls through to the public-RPC tier so a resource is never
        // dead-ended while the gateway can still serve it.
        if let Some(peer) = self
            .peer_serve_plaintext(
                store_hex,
                serve_root_hex,
                rk_hex,
                store_id,
                effective_key,
                serve_root,
                expected_leaf,
                salt,
                verified,
                land_origin,
                root_hex,
            )
            .await
        {
            // A peer served the resource; warm the capsule that holds it locally for next time (#290).
            self.maybe_backfill_capsule(store_hex, serve_root_hex, land_origin);
            return Some(with_serve_metadata(
                peer,
                owner_puzzle_hash.clone(),
                generation,
                peer_tier,
            ));
        }

        // -- Tier 3: an OPTIONAL configured upstream, the final fallback -------------------------
        //
        // Skipped entirely when no upstream is configured, which is the DEFAULT since #1997 (there is
        // no well-known fallback host any more). Skipping rather than attempting-and-failing is what
        // keeps the outcome honest: a resource no peer holds is a MISS (`None` → the caller's SPA/404
        // decision), not an `Unreadable` server error blaming this node's upstream configuration.
        if self.has_upstream() {
            match self
                .proxy_full_content(store_hex, serve_root_hex, rk_hex)
                .await
            {
                Ok((ciphertext, proof, chunk_lens)) => {
                    let trusted = serve_root.unwrap_or(proof.root);
                    // Warm the capsule that holds the bytes locally for next time (#290).
                    self.maybe_backfill_capsule(store_hex, serve_root_hex, land_origin);
                    match verify_and_decrypt(
                        store_id,
                        effective_key,
                        &ciphertext,
                        &proof,
                        &trusted,
                        expected_leaf,
                        salt,
                        &chunk_lens,
                    ) {
                        Ok(bytes) => {
                            // Ledger (#307): record the verified RPC serve + its proof.
                            self.record_verification(
                                store_hex,
                                root_hex,
                                effective_key,
                                ServeSource::Rpc.as_str(),
                                verified,
                                &proof,
                                None,
                            );
                            Some(with_serve_metadata(
                                PlaintextOutcome::Served {
                                    bytes,
                                    root_hex: root_hex.to_string(),
                                    verified,
                                    source: ServeSource::Rpc,
                                    // All three stamped just below by `with_serve_metadata`.
                                    peer_tier: PeerTier::Unattached,
                                    owner_puzzle_hash: None,
                                    generation: None,
                                },
                                owner_puzzle_hash.clone(),
                                generation,
                                peer_tier,
                            ))
                        }
                        // The gateway returned bytes that do not verify against the anchored root — a
                        // decoy for a missing key (or tampered). Either way the resource is NOT
                        // genuinely available at this root → a miss (`None`, so a tip miss can still
                        // fall through to the §13 redirect), never a served-garbage result (fail-
                        // closed: no plaintext is returned). Ledger (#307): retain the failed proof
                        // (verified=false + the reason) so the badge reads "Unverified".
                        Err(reason) => {
                            self.record_verification(
                                store_hex,
                                root_hex,
                                effective_key,
                                ServeSource::Rpc.as_str(),
                                false,
                                &proof,
                                Some(reason),
                            );
                            None
                        }
                    }
                }
                Err(ProxyMiss::NotFound) => {
                    self.maybe_backfill_capsule(store_hex, serve_root_hex, land_origin);
                    None
                }
                Err(ProxyMiss::Error(message)) => Some(PlaintextOutcome::Unreadable {
                    message,
                    root_hex: root_hex.to_string(),
                }),
            }
        } else {
            None
        }
    }

    /// Best-effort PEER serve: fetch the whole resource from the P2P content engine (dig-download
    /// multi-source), verify + decrypt it. `None` when no engine is attached, no provider holds it, or
    /// any step fails — so the caller falls through to the public-RPC tier (never a dead end).
    #[allow(clippy::too_many_arguments)]
    async fn peer_serve_plaintext(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
        store_id: &Bytes32,
        effective_key: &str,
        serve_root: Option<Bytes32>,
        expected_leaf: Option<Bytes32>,
        salt: Option<&[u8; 32]>,
        verified: bool,
        origin: crate::download::ReadOrigin,
        display_root_hex: &str,
    ) -> Option<PlaintextOutcome> {
        // Tier-2 observability (#836): this path emitted zero tracing, so a live-but-failing peer
        // fetch was indistinguishable from "engine never attached". Log each decision point.
        let Some(engine) = self.p2p_content() else {
            tracing::debug!(store = %store_hex, root = %root_hex, "peer serve: no P2P engine attached");
            return None;
        };
        let content = crate::download::miss_content_for(store_hex, root_hex, rk_hex)?;
        tracing::info!(
            store = %store_hex,
            root = %root_hex,
            rk = %rk_hex,
            "peer serve: fetching resource from the P2P content engine"
        );
        // `origin` is the CALLER'S label, derived by the transport from the accepting connection's
        // real remote address and carried down through `serve_content_plaintext` — never re-asserted
        // here. It is load-bearing: `fetch_resource` fires `spawn_capsule_reshare`, so a hardcoded
        // `Local` would let a stranger's `GET /s/…` (reachable, unauthenticated, whenever
        // `DIG_NODE_HOST` binds non-loopback) drive this node into a whole-capsule pull, cache
        // promotion, and DHT holder-announce for a capsule of the STRANGER'S naming (#1576).
        let fetched = match engine.fetch_resource(&content, origin).await {
            Ok(f) => f,
            Err(e) => {
                tracing::info!(store = %store_hex, root = %root_hex, error = %e, "peer serve: fetch missed");
                return None;
            }
        };
        tracing::info!(
            store = %store_hex,
            root = %root_hex,
            bytes = fetched.bytes.len(),
            "peer serve: fetched bytes; verifying + decrypting"
        );
        let proof = decode_proof_b64(fetched.inclusion_proof.as_deref()?)?;
        let chunk_lens: Vec<u32> = fetched.chunk_lens.iter().map(|l| *l as u32).collect();
        let trusted = serve_root.unwrap_or(proof.root);
        match verify_and_decrypt(
            store_id,
            effective_key,
            &fetched.bytes,
            &proof,
            &trusted,
            expected_leaf,
            salt,
            &chunk_lens,
        ) {
            Ok(bytes) => {
                tracing::info!(
                    store = %store_hex,
                    root = %root_hex,
                    bytes = bytes.len(),
                    "peer serve: verified + decrypted — serving from a peer"
                );
                // Ledger (#307): record the verified peer serve + its proof.
                self.record_verification(
                    store_hex,
                    root_hex,
                    effective_key,
                    ServeSource::Peer.as_str(),
                    verified,
                    &proof,
                    None,
                );
                Some(PlaintextOutcome::Served {
                    bytes,
                    // Report the store's chain-anchored TIP as `X-Dig-Root` even when the bytes came
                    // from an older capsule (#2088) — the content is anchored to the tip via the
                    // manifest's `sha256_latest`; `X-Dig-Generation` states which generation held it.
                    root_hex: display_root_hex.to_string(),
                    verified,
                    source: ServeSource::Peer,
                    // Stamped by the caller via `with_serve_metadata` (see `decrypt_local`).
                    peer_tier: PeerTier::Unattached,
                    owner_puzzle_hash: None,
                    generation: None,
                })
            }
            // A verify/decrypt failure on the peer bytes is NOT fatal to the serve — fall through to
            // the public RPC (a different holder / the gateway may serve the correct bytes).
            Err(e) => {
                tracing::info!(
                    store = %store_hex,
                    root = %root_hex,
                    error = %e,
                    "peer serve: fetched bytes failed verify/decrypt — falling through"
                );
                None
            }
        }
    }

    /// Page the public RPC's `dig.getContent` windows for `(store, root, retrieval_key)` into the WHOLE
    /// resource: the assembled ciphertext, the inclusion proof + chunk lengths (carried on the first
    /// window). Pins the request to `root_hex`; the caller re-verifies the assembled bytes against the
    /// chain-anchored root, so a compromised gateway cannot substitute a generation.
    async fn proxy_full_content(
        &self,
        store_hex: &str,
        root_hex: &str,
        rk_hex: &str,
    ) -> Result<(Vec<u8>, MerkleProof, Vec<u32>), ProxyMiss> {
        let mut ciphertext: Vec<u8> = Vec::new();
        let mut proof: Option<MerkleProof> = None;
        let mut chunk_lens: Vec<u32> = Vec::new();
        let mut offset = 0usize;
        loop {
            let req = json!({"jsonrpc":"2.0","id":1,"method":"dig.getContent","params":{
                "store_id": store_hex, "root": root_hex, "retrieval_key": rk_hex, "offset": offset }});
            let resp = self.proxy(&req).await.map_err(ProxyMiss::Error)?;
            if let Some(err) = resp.get("error") {
                let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                if code == RESOURCE_UNAVAILABLE {
                    return Err(ProxyMiss::NotFound);
                }
                let msg = err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error")
                    .to_string();
                return Err(ProxyMiss::Error(msg));
            }
            let result = resp
                .get("result")
                .ok_or_else(|| ProxyMiss::Error("upstream response missing result".into()))?;
            let window = base64::engine::general_purpose::STANDARD
                .decode(
                    result
                        .get("ciphertext")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .as_bytes(),
                )
                .map_err(|_| ProxyMiss::Error("upstream returned non-base64 ciphertext".into()))?;
            ciphertext.extend_from_slice(&window);
            if offset == 0 {
                proof = result
                    .get("inclusion_proof")
                    .and_then(Value::as_str)
                    .and_then(decode_proof_b64);
                if let Some(cl) = result.get("chunk_lens").and_then(Value::as_array) {
                    chunk_lens = cl
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u32))
                        .collect();
                }
            }
            if result
                .get("complete")
                .and_then(Value::as_bool)
                .unwrap_or(true)
            {
                break;
            }
            match result.get("next_offset").and_then(Value::as_u64) {
                Some(n) => offset = n as usize,
                None => break,
            }
        }
        let proof = proof.ok_or_else(|| {
            ProxyMiss::Error("upstream response carried no inclusion proof".into())
        })?;
        Ok((ciphertext, proof, chunk_lens))
    }
}

/// Stamp the request-scoped serve-metadata onto a `Served` outcome — the owner puzzle hash and
/// generation (#486) plus the peer-tier attachment (#1763), each resolved ONCE in
/// [`Node::serve_content_plaintext`] and applied uniformly across whichever tier (local/peer/rpc)
/// actually served the bytes. A no-op on any other variant.
fn with_serve_metadata(
    mut outcome: PlaintextOutcome,
    owner_puzzle_hash: Option<String>,
    generation: Option<u64>,
    peer_tier: PeerTier,
) -> PlaintextOutcome {
    if let PlaintextOutcome::Served {
        owner_puzzle_hash: o,
        generation: g,
        peer_tier: p,
        ..
    } = &mut outcome
    {
        *o = owner_puzzle_hash;
        *g = generation;
        *p = peer_tier;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::crypto::encrypt_chunk;

    fn test_store() -> Bytes32 {
        Bytes32([7u8; 32])
    }

    #[test]
    fn retrieval_key_matches_canonical_rootless_urn() {
        let store = test_store();
        // Explicit key.
        let expect = Urn {
            chain: CHAIN.to_string(),
            store_id: store,
            root_hash: None,
            resource_key: Some("assets/app.js".to_string()),
        }
        .retrieval_key();
        assert_eq!(derive_retrieval_key(&store, "assets/app.js"), expect);
    }

    #[test]
    fn empty_resource_key_derives_the_index_html_key() {
        let store = test_store();
        // An empty key must derive the SAME key as an explicit "index.html" (the §8.5 default view).
        assert_eq!(
            derive_retrieval_key(&store, ""),
            derive_retrieval_key(&store, DEFAULT_RESOURCE_KEY)
        );
    }

    /// Build a single-chunk public-store sealed resource for `plaintext` under `(store, resource_key)`:
    /// encrypt with the real per-URN key, commit a single-leaf proof rooted at the leaf. Returns
    /// `(ciphertext, proof, root)`.
    fn seal_public(
        store: &Bytes32,
        resource_key: &str,
        plaintext: &[u8],
    ) -> (Vec<u8>, MerkleProof, Bytes32) {
        let canonical = canonical_resource_urn(store, resource_key).canonical();
        let key = derive_decryption_key(&canonical, None);
        let ciphertext = encrypt_chunk(&key, plaintext);
        let leaf = resource_leaf(&ciphertext);
        let proof = MerkleProof {
            leaf,
            path: Vec::new(),
            root: leaf,
        };
        (ciphertext, proof, leaf)
    }

    #[test]
    fn verify_and_decrypt_round_trips_a_public_resource() {
        let store = test_store();
        let plaintext = b"<h1>hello dig</h1>";
        let (ciphertext, proof, root) = seal_public(&store, "index.html", plaintext);
        let out = verify_and_decrypt(
            &store,
            "index.html",
            &ciphertext,
            &proof,
            &root,
            None,
            None,
            &[],
        );
        assert_eq!(out.as_deref(), Ok(plaintext.as_slice()));
    }

    #[test]
    fn verify_and_decrypt_fails_closed_on_a_tampered_chunk() {
        let store = test_store();
        let (mut ciphertext, proof, root) = seal_public(&store, "index.html", b"secret");
        // Flip a byte: the proof leaf (SHA-256 of the ciphertext) no longer matches → reject BEFORE
        // any decrypt attempt.
        ciphertext[0] ^= 0xff;
        let out = verify_and_decrypt(
            &store,
            "index.html",
            &ciphertext,
            &proof,
            &root,
            None,
            None,
            &[],
        );
        assert!(out.is_err(), "a tampered chunk must fail closed");
    }

    #[test]
    fn verify_and_decrypt_rejects_a_non_anchored_root() {
        let store = test_store();
        let (ciphertext, proof, _root) = seal_public(&store, "index.html", b"data");
        // A different "trusted" root than the proof folds to → the served root is not anchored.
        let wrong_root = Bytes32([0x99; 32]);
        let out = verify_and_decrypt(
            &store,
            "index.html",
            &ciphertext,
            &proof,
            &wrong_root,
            None,
            None,
            &[],
        );
        assert!(
            out.is_err(),
            "a root that is not the anchored tip must fail closed"
        );
    }

    #[test]
    fn verify_and_decrypt_rejects_a_wrong_key_for_a_different_resource() {
        let store = test_store();
        // Seal under index.html but try to open as if it were assets/app.js — the per-URN key differs,
        // so the GCM-SIV tag check fails (the integrity gate passes because we reuse the real proof).
        let (ciphertext, proof, root) = seal_public(&store, "index.html", b"data");
        let out = verify_and_decrypt(
            &store,
            "assets/app.js",
            &ciphertext,
            &proof,
            &root,
            None,
            None,
            &[],
        );
        assert!(
            out.is_err(),
            "decrypting under the wrong URN key must fail closed"
        );
    }

    #[test]
    fn verify_and_decrypt_serves_older_gen_root_when_leaf_matches() {
        // #2088 (the enabling half): a resource served from an OLDER generation folds its proof to
        // that generation's OWN root (not the tip). With `trusted_root = the older root` AND
        // `expected_leaf = Some(the tip manifest's sha256_latest)` — which for the genuine bytes IS
        // the proof leaf — the serve succeeds. This is the path that fixes the unreadable older file.
        let store = test_store();
        let plaintext = b"console.log(1)";
        let (ciphertext, proof, older_root) = seal_public(&store, "assets/app.js", plaintext);
        // The tip manifest's sha256_latest for this path == the older generation's committed leaf.
        let tip_leaf = proof.leaf;
        let out = verify_and_decrypt(
            &store,
            "assets/app.js",
            &ciphertext,
            &proof,
            &older_root,
            Some(tip_leaf),
            None,
            &[],
        );
        assert_eq!(
            out.as_deref(),
            Ok(plaintext.as_slice()),
            "older-gen bytes whose leaf matches the tip manifest must serve"
        );
    }

    #[test]
    fn verify_and_decrypt_rejects_leaf_mismatch_against_tip_manifest() {
        // #2088 (the SECURITY half): an older capsule's root is attacker-choosable in isolation, so
        // a proof that folds to it proves nothing on its own. When the served leaf does NOT match the
        // chain-anchored tip manifest's `sha256_latest`, the serve MUST fail closed — otherwise a
        // party who could name any older root could substitute a capsule of their choosing.
        let store = test_store();
        // Genuine, internally-consistent bytes+proof (integrity gate + root check both pass)…
        let (ciphertext, proof, older_root) =
            seal_public(&store, "assets/app.js", b"attacker bytes");
        // …but the tip manifest committed a DIFFERENT leaf for this path.
        let tip_leaf = Bytes32([0xAB; 32]);
        assert_ne!(proof.leaf, tip_leaf, "the mismatch under test must be real");
        let out = verify_and_decrypt(
            &store,
            "assets/app.js",
            &ciphertext,
            &proof,
            &older_root,
            Some(tip_leaf),
            None,
            &[],
        );
        assert!(
            out.is_err(),
            "a leaf that does not match the tip manifest's sha256_latest must fail closed"
        );
    }

    // -- landing_origin: the two-axis collapse (#1654) --------------------------------------------

    use crate::download::{landing_origin, ReadOrigin, RequestProvenance};

    #[test]
    fn first_party_local_read_still_lands() {
        // A same-site / header-absent (CLI/SDK) request keeps its Local origin, so a legitimate
        // operator read still triggers the whole-capsule warm + reshare (the #290 flywheel).
        assert_eq!(
            landing_origin(ReadOrigin::Local, RequestProvenance::FirstParty),
            ReadOrigin::Local,
            "a first-party local read must keep landing"
        );
    }

    #[test]
    fn cross_site_local_read_does_not_land() {
        // The CSRF door (#1654): a loopback connection whose browser reports cross-site provenance
        // folds to Peer, so the bytes serve but no durable holder side effect fires.
        assert_eq!(
            landing_origin(ReadOrigin::Local, RequestProvenance::CrossSite),
            ReadOrigin::Peer,
            "a cross-site read must NOT land, even on a loopback connection"
        );
    }

    #[test]
    fn a_peer_read_never_lands_regardless_of_provenance() {
        // A genuine peer-wire read never lands; provenance can only ever tighten, never loosen.
        for provenance in [RequestProvenance::FirstParty, RequestProvenance::CrossSite] {
            assert_eq!(
                landing_origin(ReadOrigin::Peer, provenance),
                ReadOrigin::Peer,
                "a peer read must never land"
            );
        }
    }
}
