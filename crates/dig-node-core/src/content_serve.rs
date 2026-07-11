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

use crate::{decide_pin, pin_enforced, Node, PinDecision};

/// JSON-RPC-style code for a serve that fetched bytes but could not verify/decrypt/reach them —
/// distinct from a clean content miss (`NotFound`) and from the anchored-root pin (`RootError`).
const SERVE_UNREADABLE: i64 = -32000;
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
    /// Fetched from the public RPC gateway (rpc.dig.net), the final fallback.
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
    Unreadable {
        code: i64,
        message: String,
        root_hex: String,
    },
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
fn verify_and_decrypt(
    store_id: &Bytes32,
    resource_key: &str,
    ciphertext: &[u8],
    proof: &MerkleProof,
    trusted_root: &Bytes32,
    salt: Option<&[u8; 32]>,
    chunk_lens: &[u32],
) -> Result<Vec<u8>, String> {
    // 1) Integrity gate: the served bytes are the proof's leaf, the path folds to its root, and that
    //    root is the trusted (chain-anchored) root. Any failure = a tampered/decoy/wrong-store serve.
    if resource_leaf(ciphertext) != proof.leaf {
        return Err("inclusion proof leaf does not match the served ciphertext".into());
    }
    if !proof.verify() {
        return Err("inclusion proof does not fold to its root".into());
    }
    if &proof.root != trusted_root {
        return Err("served root is not the store's chain-anchored root".into());
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

impl Node {
    /// Serve a store resource as DECRYPTED plaintext over the trusted loopback surface (#289).
    ///
    /// Resolution order (per `(store, resolved_root)`):
    /// 1. **Local** — a synced+verified `.dig` module on disk (no network). The DEFAULT once a store
    ///    is cached; every subsequent read is local (#290).
    /// 2. **Peer** — the P2P content engine (dig-download multi-source), when one is attached.
    /// 3. **Rpc** — the public gateway (rpc.dig.net), the final fallback.
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
    pub async fn serve_content_plaintext(
        &self,
        store_hex: &str,
        requested_root_hex: &str,
        resource_key: &str,
        salt_hex: Option<&str>,
    ) -> PlaintextOutcome {
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
        let pinned_root: Option<Bytes32> = if enforced {
            let anchored = self.anchored_root_resolver.anchored_root(&store_id.0).await;
            match decide_pin(true, requested_root, anchored) {
                PinDecision::ServeAt(root) => Some(root),
                PinDecision::Reject(code, message) => {
                    return PlaintextOutcome::RootError { code, message }
                }
                // decide_pin(true, ..) never returns Unpinned.
                PinDecision::Unpinned => requested_root,
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

        let retrieval_key = derive_retrieval_key(&store_id, effective_key).0;
        let rk_hex = hex::encode(retrieval_key);

        // -- Tier 1: LOCAL-FIRST (no network) ----------------------------------------------------
        // A cached module returns a DECOY (constant-time, to hide key existence) for a key it does not
        // hold, whose proof does not fold to the anchored root. So a verify/decrypt failure here means
        // "not genuinely held locally" — treat it as a MISS and fall through, NOT a hard error.
        if !root_hex.is_empty() {
            if let Some(resp) = self
                .serve_local_cached(store_hex, &root_hex, &retrieval_key)
                .await
            {
                if let Some(served) = self.decrypt_local(
                    &store_id,
                    effective_key,
                    &resp,
                    pinned_root,
                    salt.as_ref(),
                    &root_hex,
                    verified,
                ) {
                    return served;
                }
                // else: a decoy / verify or decrypt failure → fall through to peer/RPC.
            }
        }

        // -- Tier 2: PEER (P2P content engine, when attached) ------------------------------------
        // Best-effort: any failure falls through to the public-RPC tier so a resource is never
        // dead-ended while the gateway can still serve it. Only a concrete root has a content id.
        if !root_hex.is_empty() {
            if let Some(peer) = self
                .peer_serve_plaintext(
                    store_hex,
                    &root_hex,
                    &rk_hex,
                    &store_id,
                    effective_key,
                    pinned_root,
                    salt.as_ref(),
                    verified,
                )
                .await
            {
                // A peer served the resource; warm the whole capsule locally for next time (#290).
                self.maybe_backfill_capsule(store_hex, &root_hex);
                return peer;
            }
        }

        // -- Tier 3: PUBLIC RPC (rpc.dig.net), the final fallback --------------------------------
        if !root_hex.is_empty() {
            match self.proxy_full_content(store_hex, &root_hex, &rk_hex).await {
                Ok((ciphertext, proof, chunk_lens)) => {
                    let trusted = pinned_root.unwrap_or(proof.root);
                    // Warm the whole capsule locally so the next read is local-first (#290).
                    self.maybe_backfill_capsule(store_hex, &root_hex);
                    return match verify_and_decrypt(
                        &store_id,
                        effective_key,
                        &ciphertext,
                        &proof,
                        &trusted,
                        salt.as_ref(),
                        &chunk_lens,
                    ) {
                        Ok(bytes) => PlaintextOutcome::Served {
                            bytes,
                            root_hex: root_hex.clone(),
                            verified,
                            source: ServeSource::Rpc,
                        },
                        // The gateway returned bytes that do not verify against the anchored root — a
                        // decoy for a missing key (or tampered). Either way the resource is NOT
                        // genuinely available at this root → a clean miss (drives the SPA/404 decision),
                        // never a served-garbage result (fail-closed: no plaintext is returned).
                        Err(_) => PlaintextOutcome::NotFound {
                            root_hex: root_hex.clone(),
                        },
                    };
                }
                Err(ProxyMiss::NotFound) => {
                    self.maybe_backfill_capsule(store_hex, &root_hex);
                    return PlaintextOutcome::NotFound {
                        root_hex: root_hex.clone(),
                    };
                }
                Err(ProxyMiss::Error(message)) => {
                    return PlaintextOutcome::Unreadable {
                        code: SERVE_UNREADABLE,
                        message,
                        root_hex: root_hex.clone(),
                    }
                }
            }
        }

        // Rootless with the pin off and nothing served — a miss.
        PlaintextOutcome::NotFound { root_hex }
    }

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
        pinned_root: Option<Bytes32>,
        salt: Option<&[u8; 32]>,
        root_hex: &str,
        verified: bool,
    ) -> Option<PlaintextOutcome> {
        // A cached module whose served generation is not the anchored tip is not the resource at this
        // root — fall through rather than serve a stale generation as current (#127).
        if let Some(pin) = pinned_root {
            if resp.roothash != pin {
                return None;
            }
        }
        let trusted = pinned_root.unwrap_or(resp.roothash);
        verify_and_decrypt(
            store_id,
            effective_key,
            &resp.ciphertext,
            &resp.merkle_proof,
            &trusted,
            salt,
            &resp.chunk_lens,
        )
        .ok()
        .map(|bytes| PlaintextOutcome::Served {
            bytes,
            root_hex: root_hex.to_string(),
            verified,
            source: ServeSource::Local,
        })
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
        pinned_root: Option<Bytes32>,
        salt: Option<&[u8; 32]>,
        verified: bool,
    ) -> Option<PlaintextOutcome> {
        let engine = self.p2p_content()?;
        let content = crate::download::miss_content_for(store_hex, root_hex, rk_hex)?;
        let fetched = engine.fetch_resource(&content).await.ok()?;
        let proof = decode_proof_b64(fetched.inclusion_proof.as_deref()?)?;
        let chunk_lens: Vec<u32> = fetched.chunk_lens.iter().map(|l| *l as u32).collect();
        let trusted = pinned_root.unwrap_or(proof.root);
        match verify_and_decrypt(
            store_id,
            effective_key,
            &fetched.bytes,
            &proof,
            &trusted,
            salt,
            &chunk_lens,
        ) {
            Ok(bytes) => Some(PlaintextOutcome::Served {
                bytes,
                root_hex: root_hex.to_string(),
                verified,
                source: ServeSource::Peer,
            }),
            // A verify/decrypt failure on the peer bytes is NOT fatal to the serve — fall through to
            // the public RPC (a different holder / the gateway may serve the correct bytes).
            Err(_) => None,
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

    /// The store's public file PATHS at `(store, root)` from the embedded `PublicManifest` (id 13),
    /// or `None` when this node does not hold the capsule OR it carries no manifest (an older `.dig` /
    /// a private store whose paths stay opaque). The HTTP layer uses this to distinguish a KNOWN file
    /// genuinely missing at this root (an honest 404) from an SPA route (serve `index.html`).
    pub async fn manifest_paths(&self, store_hex: &str, root_hex: &str) -> Option<Vec<String>> {
        let cache_dir = self.cache_dir.clone();
        let (store, root) = (store_hex.to_string(), root_hex.to_string());
        let outcome = tokio::task::spawn_blocking(move || {
            crate::read_public_manifest_blocking(&cache_dir, &store, &root)
        })
        .await
        .ok()?;
        match outcome {
            Ok(Some(Some(pm))) => Some(pm.entries.into_iter().map(|e| e.path).collect()),
            _ => None,
        }
    }
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
        let out = verify_and_decrypt(&store, "index.html", &ciphertext, &proof, &root, None, &[]);
        assert_eq!(out.as_deref(), Ok(plaintext.as_slice()));
    }

    #[test]
    fn verify_and_decrypt_fails_closed_on_a_tampered_chunk() {
        let store = test_store();
        let (mut ciphertext, proof, root) = seal_public(&store, "index.html", b"secret");
        // Flip a byte: the proof leaf (SHA-256 of the ciphertext) no longer matches → reject BEFORE
        // any decrypt attempt.
        ciphertext[0] ^= 0xff;
        let out = verify_and_decrypt(&store, "index.html", &ciphertext, &proof, &root, None, &[]);
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
            &[],
        );
        assert!(
            out.is_err(),
            "decrypting under the wrong URN key must fail closed"
        );
    }
}
