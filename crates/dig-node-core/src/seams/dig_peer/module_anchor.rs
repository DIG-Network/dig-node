//! [`ChainAnchoredModuleVerifier`] — the sole root of trust of the whole-`.dig`-module pull (#1576).
//!
//! # Why this file is the whole guarantee
//!
//! [`dig_download::ModuleDownloader`] deliberately delegates 100% of the reshare guarantee to this
//! verifier. Every check the engine runs BEFORE calling it — per-chunk hashes, the whole-blob
//! `module_hash` — compares attacker-chosen bytes against attacker-chosen hashes taken from the same
//! peer's descriptor. Those checks prove SELF-CONSISTENCY; they cannot prove AUTHENTICITY. A holder
//! that fabricates a module and describes it correctly passes all of them.
//!
//! What this verifier accepts, the node then CACHES, SERVES, and ANNOUNCES itself a holder of. So a
//! weak verifier does not merely admit bad bytes locally — it turns an honest node into an
//! authoritative-looking source of corrupt content for the whole network. Every rule below exists
//! because an adversarial round produced an executed proof of the attack it closes.
//!
//! # The rules
//!
//! 1. **The expected root comes from the CHAIN, never from the serving peer.** This is the entire
//!    fail-closed story. The verifier is constructed [`for_generation`](ChainAnchoredModuleVerifier::for_generation)
//!    with a root the caller ALREADY resolved through an
//!    [`AnchoredRootResolver`](crate::shared::AnchoredRootResolver) — a coinset lineage walk, not a
//!    peer answer. The verifier holds 32 bytes and cannot reach the network at all, so there is no code
//!    path by which a peer-supplied "anchored root" could reach it. If the anchor ever came from the
//!    peer that served the module, every guarantee here collapses to zero.
//! 2. **Compare DECODED bytes, never hex text.** Hex is case-insensitive and length-forgiving in a
//!    way byte equality is not; a peer that influences either side of a TEXT comparison gets a bypass
//!    for free (`"AB.."` vs `"ab.."`, a leading zero, trailing whitespace). Every comparison in this
//!    module is over `[u8; 32]`.
//! 3. **An unparseable or empty module is REJECTED explicitly.** Both of the engine's hash gates pass
//!    TRIVIALLY for the empty module — the attacker simply declares `total_size: 0` and
//!    `module_hash: sha256("")`, and `sha256(&[])` genuinely equals it. This verifier is the only
//!    thing standing between that and a node announcing itself the holder of a 0-byte capsule.
//! 4. **The module must name the store + generation it claims to be.** A genuine `.dig` commits its
//!    own `StoreId` and `CurrentRoot` in its data section. A module whose committed ids do not match
//!    the generation being pulled is a real capsule for the WRONG generation — a rollback primitive if
//!    admitted (serve yesterday's content under today's root), so it fails closed too.
//! 5. **The committed root must be the MERKLE ROOT of the SERVED CONTENT.** Rule 4 only proves the
//!    module *names* the chain-anchored root in its `CurrentRoot` section — a header a fabricator
//!    writes freely. It says nothing about whether the bytes hash to that root. So the verifier
//!    RECOMPUTES the merkle root **from the capsule's own `ChunkPool` ciphertexts** — the same
//!    content→leaf recipe the producer (`digstore-store`) commits and the browser verifier
//!    (`dig-client-wasm`) checks: for each `KeyTable` entry `leaf = resource_leaf(concat_output(its
//!    chunk ciphertexts))`, the leaves sorted ASCENDING by `static_key`, folded via
//!    [`MerkleTree::from_leaves`] — and refuses unless it reproduces the committed root.
//!
//!    The `MerkleNodes` section is **never trusted for the admit decision.** An earlier fix
//!    recomputed from `MerkleNodes` leaves instead, which was HOLLOW: rule 4 pins `committed_root ==
//!    chain_root`, a single-leaf tree has `from_leaves(vec![x]).root() == x` (no fold, no tag), and
//!    `decode_merkle_leaves` accepts arbitrary bytes — so `MerkleNodes = [chain_root]` plus an empty
//!    or garbage `ChunkPool` passed for free, admitting a contentless phantom-holder capsule. The
//!    trust anchor is therefore fold-of-CONTENT == chain_root. `MerkleNodes` is retained only as a
//!    defense-in-depth cross-check: because the served inclusion proofs are generated from it, its
//!    leaves must equal the content leaves in producer order, or the served proofs would disagree
//!    with the bytes. An absent `KeyTable`/`ChunkPool`, a chunk index the pool cannot satisfy, an
//!    undecodable section, or any mismatch fails closed. A legitimately EMPTY store (no entries)
//!    folds to `from_leaves(vec![]).root() == sha256(&[])` and is admitted, not errored.

use std::sync::{Arc, Mutex};

use digstore_core::datasection::{decode_merkle_leaves, DataView, SectionId};
use digstore_core::merkle::MerkleTree;
use digstore_core::{Bytes32, Decode, Decoder, KeyTableEntry};
use sha2::{Digest, Sha256};

use dig_download::{ModuleAnchor, ModuleAnchorVerifier, ModuleReader};

/// Why a blob was not admitted, and — crucially — WHOSE fault that is.
///
/// The distinction is the whole reason [`ModuleAnchor`] is three-valued rather than a `bool`: a
/// rejection is either EVIDENCE against the peer that supplied the descriptor, or a failure of this
/// node's own wiring that says nothing whatsoever about that peer. Collapsing the two lets a local
/// bug brand every honest holder it is tried against, and a durable demotion of honest holders
/// inverts the node's preference toward unremembered peers — which is what a sybil is.
///
/// So: **demote only on evidence about the BLOB; never on a fact about ourselves.**
enum Rejection {
    /// The blob is definitively not the chain-anchored module — established from the blob's OWN
    /// committed bytes. Real evidence against the descriptor's source, so it earns a demotion.
    NotAnchored(&'static str),
    /// This verifier could not reach a verdict because it was asked about a generation it is not
    /// bound to. The blob was never examined, so there is nothing to hold against the holder:
    /// terminal for the pull, and no verdict.
    Indeterminate(&'static str),
}

/// `SHA-256` of `bytes` as raw 32 bytes — the module pull's one content-addressing primitive.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Binds an assembled `.dig` module to ONE chain-resolved generation.
///
/// Built by [`for_generation`](Self::for_generation) from a root the caller resolved through the
/// chain (see the module docs, rule 1), then handed to
/// [`ModuleDownloader`](dig_download::ModuleDownloader) as its anchor gate. Deliberately holds no
/// network handle and no resolver: a verifier that COULD ask a peer for the anchor is one refactor away
/// from asking the wrong one.
#[derive(Debug, Clone)]
pub struct ChainAnchoredModuleVerifier {
    /// The store this verifier accepts modules for (32 raw bytes).
    store_id: [u8; 32],
    /// The generation root the CHAIN says this store is at (32 raw bytes).
    chain_root: [u8; 32],
    /// `SHA-256` of the exact blob this verifier last ADMITTED — the pre-announce re-check's reference.
    ///
    /// This verifier is the only component that ever sees the fully-assembled, gate-passed bytes, so
    /// recording their digest here is what lets the caller prove, from OUTSIDE the engine, that the
    /// artifact it is about to promote + announce is byte-identical to the artifact that was verified
    /// (see [`admitted_digest`](Self::admitted_digest)).
    admitted_digest: Arc<Mutex<Option<[u8; 32]>>>,
}

impl ChainAnchoredModuleVerifier {
    /// A verifier that accepts ONLY the `.dig` module committing `chain_root` for `store_id`.
    ///
    /// `chain_root` MUST come from an [`AnchoredRootResolver`](crate::shared::AnchoredRootResolver)
    /// (`anchored_root` / `verify_pinned_root`) — i.e. from the CHAIN. Passing a peer-supplied root
    /// here defeats the entire module pull; the pull's only caller
    /// ([`super::module_reshare`]) resolves it from the node's resolver before the pull begins, which
    /// is why this constructor takes bytes rather than a resolver it might be tempted to call later.
    pub fn for_generation(store_id: Bytes32, chain_root: Bytes32) -> Self {
        ChainAnchoredModuleVerifier {
            store_id: store_id.0,
            chain_root: chain_root.0,
            admitted_digest: Arc::new(Mutex::new(None)),
        }
    }

    /// The generation root this verifier is bound to — the chain's answer, exposed for logging.
    pub fn chain_root(&self) -> Bytes32 {
        Bytes32(self.chain_root)
    }

    /// `SHA-256` of the blob this verifier ADMITTED, or `None` if it never admitted one.
    ///
    /// The caller re-hashes the artifact it is about to promote + announce and compares it against
    /// this. Both sides of that comparison are then this node's OWN: no peer supplies either, unlike a
    /// re-hash against the descriptor's `module_hash`, which is a value the serving peer chose. It is
    /// the check that catches, from outside the engine, a promoted artifact that is not the verified one
    /// — a "verified artifact != promoted artifact" poisoning is otherwise invisible to a caller that
    /// trusts `download() == Ok`.
    pub fn admitted_digest(&self) -> Option<[u8; 32]> {
        *self
            .admitted_digest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The reason `module` is not the chain-anchored `.dig` for this generation, or `None` when it is.
    ///
    /// Split out from [`ModuleAnchorVerifier::verify_module_anchor`] so a rejection can be LOGGED with
    /// its cause: a bare `false` on the reshare path is the same ambiguity that cost the read leg six
    /// blind diagnosis rounds (#836). The reason text is derived entirely from this node's own parse —
    /// it never embeds peer-supplied text (#1603).
    ///
    /// **Every failure to establish a fact is a REJECTION, never a fall-through.** `None` means "this
    /// module IS chain-anchored", so an unparseable blob, an absent section, or a non-canonical id must
    /// each produce a `Some(reason)`. Writing this with `?` on the `Option`-returning helpers would make
    /// each of those return `None` — i.e. ACCEPT the module — which is the fail-OPEN inversion of the one
    /// guarantee this whole file exists to provide. Hence the explicit `else` on every lookup.
    fn rejection_reason(&self, module: &[u8], store_id: &str, root: &str) -> Option<Rejection> {
        // The generation being pulled must be the one this verifier was BOUND to. A verifier is built
        // per pull from a chain-resolved root, so a mismatch here means THIS NODE reused a verifier
        // across generations — it would silently check the wrong anchor. That is our own wiring fault
        // and the blob is never even examined, so it is `Indeterminate`: the pull dies, and the holder
        // earns nothing (see [`Rejection`]).
        let Some(pulled_store) = decode_id(store_id) else {
            return Some(Rejection::Indeterminate(
                "the pulled store_id is not a canonical 64-hex id",
            ));
        };
        if pulled_store != self.store_id {
            return Some(Rejection::Indeterminate(
                "the pulled store_id is not the one this verifier was bound to",
            ));
        }
        let Some(pulled_root) = decode_id(root) else {
            return Some(Rejection::Indeterminate(
                "the pulled root is not a canonical 64-hex id",
            ));
        };
        if pulled_root != self.chain_root {
            return Some(Rejection::Indeterminate(
                "the pulled root is not the chain-resolved root this verifier was bound to",
            ));
        }

        // Rule 3: an empty module is rejected BEFORE any parse. Both of the engine's hash gates accept
        // it (sha256 of no bytes is a real, declarable digest), so this is the only rejection there is.
        if module.is_empty() {
            return Some(Rejection::NotAnchored("an empty blob is not a .dig module"));
        }
        let blob = digstore_compiler::extract_data_section_blob(module)
            .ok()
            .or_else(|| {
                // A module pulled straight from a peer may be the bare data-section blob rather than a
                // wasm container. Accept either shape, but ONLY as a real parse — never as a fallback
                // that silently succeeds on garbage.
                DataView::parse(module).ok().map(|_| module.to_vec())
            });
        let Some(blob) = blob else {
            return Some(Rejection::NotAnchored(
                "the blob is neither a .dig container nor a DIGS data section",
            ));
        };
        let Ok(view) = DataView::parse(&blob) else {
            return Some(Rejection::NotAnchored(
                "the module's data section does not parse",
            ));
        };

        // Rule 4 + rule 1: the module's OWN committed ids, compared as decoded bytes (rule 2) against
        // the store being pulled and the CHAIN's root.
        let Some(committed_store) = section_id32(&view, SectionId::StoreId) else {
            return Some(Rejection::NotAnchored(
                "the module commits no 32-byte store_id",
            ));
        };
        if committed_store != self.store_id {
            return Some(Rejection::NotAnchored(
                "the module commits a different store_id than the one being pulled",
            ));
        }
        let Some(committed_root) = section_id32(&view, SectionId::CurrentRoot) else {
            return Some(Rejection::NotAnchored(
                "the module commits no 32-byte generation root",
            ));
        };
        if committed_root != self.chain_root {
            return Some(Rejection::NotAnchored(
                "the module's committed root is not the store's chain-anchored root",
            ));
        }

        // Rule 5: the committed root must be the merkle root of the SERVED CONTENT, not merely a
        // header that happens to name the chain root. Recompute from the capsule's own `ChunkPool`
        // ciphertexts (NEVER from the attacker-supplied `MerkleNodes` digests — see the module docs
        // for why trusting those was hollow) and refuse unless the content reproduces `committed_root`
        // (which rule 4 has already pinned == the chain root).
        let content_leaves = match content_leaves(&view, committed_root) {
            Ok(leaves) => leaves,
            Err(reason) => return Some(Rejection::NotAnchored(reason)),
        };
        let content_root = MerkleTree::from_leaves(content_leaves.clone()).root().0;
        if content_root != committed_root {
            return Some(Rejection::NotAnchored(
                "the module's ChunkPool content does not recompute to its committed root",
            ));
        }

        // Defense-in-depth: the served inclusion proofs are generated from `MerkleNodes`, so its
        // leaves MUST equal the content leaves in producer (static-key-ascending) order — else a
        // capsule whose content folds correctly could still ship proofs that disagree with the bytes
        // it serves. This is a consistency cross-check, NOT the trust anchor (that is the content
        // fold above); absence or an undecodable/disagreeing section fails closed.
        let Some(merkle_body) = view.section(SectionId::MerkleNodes) else {
            return Some(Rejection::NotAnchored(
                "the module commits no MerkleNodes leaves alongside its content",
            ));
        };
        let Ok(declared_leaves) = decode_merkle_leaves(merkle_body) else {
            return Some(Rejection::NotAnchored(
                "the module's MerkleNodes section does not decode into merkle leaves",
            ));
        };
        if declared_leaves != content_leaves {
            return Some(Rejection::NotAnchored(
                "the module's MerkleNodes leaves disagree with its served ChunkPool content",
            ));
        }
        None
    }
}

/// The per-resource merkle leaves recomputed from a module's SERVED CONTENT for the CURRENT
/// GENERATION, sorted into producer order — the trustworthy input to rule 5's root fold.
///
/// **Scoped to the current generation (`committed_root`).** The embedded `KeyTable` is
/// MULTI-generation: the producer pushes one entry per (generation, resource), each stamped with its
/// generation's root (`digstore-compiler` `key_table.rs`). But the committed root the producer folds
/// (`pipeline.rs` → `current_generation_leaves(generations.last())`) is over the CURRENT generation
/// ONLY — and the last generation's root IS `committed_root` (rule 4 pins it == the chain root, and
/// §9.4's `state.root == tree.root()` invariant makes the last generation's `gen.root()` equal that).
/// So this folds ONLY the entries whose `generation == committed_root`; folding every generation's
/// entries would over-count for any store published then updated even once (the normal lifecycle),
/// false-rejecting its genuine current content as `NotAnchored`.
///
/// For each such `KeyTable` (id 8) entry, this gathers the resource's chunk ciphertexts from the
/// `ChunkPool` (id 9) by their global indices and hashes their concatenation with the ONE shared
/// content→leaf recipe (`resource_leaf(concat_output(cts))`) the producer commits and the browser
/// verifier checks — never trusting the attacker-supplied `MerkleNodes` digests. The pairs are then
/// sorted ASCENDING by `static_key`, because the producer folds `resource_leaves.sort_by_key(|r| r.0)`
/// and KeyTable storage order is not guaranteed sorted, so an independent sort is what makes the root
/// reproducible.
///
/// Fail-closed on every gap: an absent `KeyTable`/`ChunkPool`, an undecodable entry, or a chunk index
/// the pool cannot satisfy is an `Err`, never a silent empty result. A genuinely empty store (no
/// current-generation entries) returns an empty leaf list, which folds to `sha256(&[])` — the
/// legitimate empty edge.
///
/// Processed resource-by-resource (each resource's leaf computed then its ciphertext borrows dropped)
/// so no second whole-module copy is held in RAM.
///
/// **Chunk lookup is O(1), so the whole recompute is O(pool_size + total_references).** The
/// `ChunkPool` framing is parsed ONCE into per-chunk byte ranges ([`index_chunk_pool`]) and each
/// `KeyTable` reference resolves by index into that table. This closes a quadratic CPU-DoS: the
/// canonical `read_chunk` is O(global_index) — it re-walks the pool from offset 0 on every call — so
/// resolving N references against an M-chunk pool was Θ(N·M). An attacker could make that ≈Θ(module²)
/// with a pool of M ZERO-LENGTH chunks + one current-generation entry referencing index `M-1` N times;
/// worse, zero-length chunks add 0 bytes, so the `MAX_STORE_BYTES` accumulator never tripped. The
/// pre-index removes the quadratic root cause; the cumulative reference-count cap
/// ([`MAX_MODULE_CHUNK_REFERENCES`]) bounds scan+hash work even independent of it.
fn content_leaves(
    view: &DataView<'_>,
    committed_root: [u8; 32],
) -> Result<Vec<Bytes32>, &'static str> {
    let Some(key_table_body) = view.section(SectionId::KeyTable) else {
        return Err("the module commits no KeyTable to recompute its content root from");
    };
    let Some(chunk_pool_body) = view.section(SectionId::ChunkPool) else {
        return Err("the module commits no ChunkPool to recompute its content root from");
    };

    // Pre-index the ChunkPool ONCE: a single linear pass building each chunk's byte range, so every
    // reference below is an O(1) index rather than a fresh O(global_index) `read_chunk` re-scan (the
    // quadratic-DoS fix). Malformed framing fails closed here, exactly as `read_chunk` would per call.
    let Some(chunk_ranges) = index_chunk_pool(chunk_pool_body) else {
        return Err("the module's ChunkPool framing does not decode");
    };

    let mut decoder = Decoder::new(key_table_body);
    let Ok(entry_count) = u32::decode(&mut decoder) else {
        return Err("the module's KeyTable count does not decode");
    };

    // Do NOT pre-size from `entry_count`: it is attacker-supplied (up to `u32::MAX`), so
    // `with_capacity(entry_count)` would OOM long before the decode of a short body failed. Grow
    // on demand instead — a lying count simply runs out of body and fails closed on the next decode.
    let mut leaves: Vec<(Bytes32, Bytes32)> = Vec::new();

    // Amplification bound (HIGH remote pre-auth OOM/CPU-DoS). `chunk_indices` is attacker-controlled
    // and — because the producer dedups chunks — legitimately permits REPEATED/non-increasing indices
    // (two identical chunks, or a chunk shared with an earlier resource). So repeats cannot be banned;
    // instead the TOTAL referenced ciphertext bytes across the whole module is capped at
    // `MAX_STORE_BYTES` (the ceiling a genuine store cannot exceed). Without this a ~1 MB module with
    // `chunk_indices = [0; K]` over one large chunk would reference K×|chunk| bytes (e.g. 100 GB),
    // aborting the allocator and crashing the node. The recompute streams each ciphertext into the
    // leaf hash (below) so memory stays O(1); this cap additionally bounds the CPU of the hashing.
    let mut total_referenced_bytes: u64 = 0;

    // Defense-in-depth CPU bound: cap the cumulative number of chunk REFERENCES across the whole
    // current generation, so scan+hash work stays bounded even for ZERO-LENGTH chunks (which add
    // nothing to `total_referenced_bytes` and so slip past the byte cap — the quadratic scan-bomb's
    // fuel). See [`MAX_MODULE_CHUNK_REFERENCES`] for the ceiling's derivation.
    let mut total_referenced_chunks: u64 = 0;

    for _ in 0..entry_count {
        let Ok(entry) = KeyTableEntry::decode(&mut decoder) else {
            return Err("the module's KeyTable does not decode into entries");
        };
        // Skip prior-generation entries: only the CURRENT generation's resources fold into the
        // committed root (see the fn docs). Every entry must still DECODE — the count/body must be
        // well-formed — but a stale-generation entry contributes no leaf.
        if entry.generation.0 != committed_root {
            continue;
        }
        // Stream the resource's ciphertexts into its leaf hash rather than materializing their
        // concatenation: `resource_leaf(concat_output(cts)) == sha256(ct0 ++ ct1 ++ …)` because
        // `resource_leaf` is plain SHA-256 and `concat_output` is plain concatenation, so hashing
        // incrementally is byte-identical AND holds no second copy of the content in RAM.
        let mut hasher = Sha256::new();
        for &global_index in &entry.chunk_indices {
            total_referenced_chunks = total_referenced_chunks.saturating_add(1);
            if total_referenced_chunks > MAX_MODULE_CHUNK_REFERENCES {
                return Err("the module's KeyTable references more chunks than a store may hold");
            }
            // O(1) lookup into the pre-indexed pool: byte-identical to `read_chunk(chunk_pool_body,
            // global_index)`, without its per-call O(global_index) re-scan. Out of range fails closed
            // exactly as `read_chunk` returning `None` does.
            let Some(range) = chunk_ranges.get(global_index as usize) else {
                return Err("a KeyTable entry references a chunk absent from the ChunkPool");
            };
            let ciphertext = &chunk_pool_body[range.clone()];
            total_referenced_bytes = total_referenced_bytes.saturating_add(ciphertext.len() as u64);
            if total_referenced_bytes > digstore_core::MAX_STORE_BYTES {
                return Err("the module's KeyTable references more content than a store may hold");
            }
            hasher.update(ciphertext);
        }
        let leaf = Bytes32(hasher.finalize().into());
        leaves.push((entry.static_key, leaf));
    }

    leaves.sort_by_key(|(static_key, _)| static_key.0);
    Ok(leaves.into_iter().map(|(_, leaf)| leaf).collect())
}

/// Ceiling on the cumulative number of `KeyTable` chunk references a module's current generation may
/// make before it fails closed.
///
/// Derived from `MAX_STORE_BYTES / MIN_CHUNK_FRAMING`: every chunk in the `ChunkPool` costs at least
/// its 4-byte length prefix (the encoding in `datasection::encode_chunk_pool`), so a store within the
/// `MAX_STORE_BYTES` budget cannot frame — and thus a genuine current generation cannot reference —
/// more than `MAX_STORE_BYTES / 4` chunks. The existing `MAX_STORE_BYTES` byte cap bounds work for
/// NON-empty chunks; this reference-count cap additionally bounds scan+hash work for ZERO-LENGTH
/// chunks, which contribute no bytes and so cannot trip the byte cap on their own.
const MAX_MODULE_CHUNK_REFERENCES: u64 = digstore_core::MAX_STORE_BYTES / 4;

/// Parse a `ChunkPool` body's length-prefixed framing ONCE into each chunk's byte range within
/// `pool_body`, or `None` if the framing is malformed (a truncated count, a length that overruns the
/// body).
///
/// This is the pre-index that makes [`content_leaves`] linear. It walks the exact same encoding
/// [`read_chunk`](digstore_core::datasection::read_chunk) parses — a `u32` BE count, then per chunk a
/// `u32` BE length prefix followed by that many bytes — but records every chunk's slice bounds in one
/// pass so a later reference is an O(1) `Vec` index, not another O(global_index) walk from offset 0.
/// `pool_body[range]` for the returned range is byte-identical to `read_chunk(pool_body, index)`.
///
/// The returned `Vec` grows on demand: the claimed count is NOT pre-allocated (it is attacker-supplied
/// up to `u32::MAX`), and a count larger than the body can satisfy simply runs the body out and fails
/// closed on the next length read.
fn index_chunk_pool(pool_body: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    if pool_body.len() < 4 {
        return None;
    }
    let count = u32::from_be_bytes([pool_body[0], pool_body[1], pool_body[2], pool_body[3]]);
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
    let mut pos = 4usize;
    for _ in 0..count {
        if pos + 4 > pool_body.len() {
            return None;
        }
        let len = u32::from_be_bytes([
            pool_body[pos],
            pool_body[pos + 1],
            pool_body[pos + 2],
            pool_body[pos + 3],
        ]) as usize;
        pos += 4;
        let end = pos.checked_add(len)?;
        if end > pool_body.len() {
            return None;
        }
        ranges.push(pos..end);
        pos = end;
    }
    Some(ranges)
}

#[async_trait::async_trait]
impl ModuleAnchorVerifier for ChainAnchoredModuleVerifier {
    /// dig-download 0.15 hands the staged module as a borrowed READER rather than a slice, so the
    /// engine no longer has to hold the whole blob in memory on the caller's behalf.
    ///
    /// This verifier still needs every byte: both `extract_data_section_blob` and `DataView::parse`
    /// parse the whole container, and the admitted digest is over the whole module. So the bytes are
    /// materialized here — the same working set the old `&[u8]` API forced on the engine, just owned
    /// on this side of the call now. Verifying from a prefix would mean teaching those parsers to
    /// stream, which is a real change to the trust core and not something to fold into a dep bump.
    async fn verify_module_anchor(
        &self,
        module: &dyn ModuleReader,
        store_id: &str,
        root: &str,
    ) -> ModuleAnchor {
        // A read failure is THIS NODE failing to read its own staging area, never evidence against
        // the holder — so `Unavailable`, never `NotAnchored`. Collapsing the two would durably demote
        // an honest peer for our local I/O error (see `ModuleAnchor`).
        let module = match module.read_at(0, module.len()).await {
            Ok(bytes) => bytes,
            Err(e) => {
                let reason = format!("could not read the staged module back: {e}");
                tracing::warn!(
                    store = %crate::seams::dig_peer::serve_log::SafeId::new(store_id),
                    root = %crate::seams::dig_peer::serve_log::SafeId::new(root),
                    %reason,
                    "module pull: cannot verify the anchor — local read failure, not holder evidence"
                );
                return ModuleAnchor::Unavailable(reason);
            }
        };
        let module = module.as_slice();

        let rejection = match self.rejection_reason(module, store_id, root) {
            None => {
                // Record the digest of exactly what was admitted, so the caller can prove the artifact
                // it promotes is this one (see `admitted_digest`). Written only on ACCEPT: a rejected
                // blob must never become a promotion reference.
                *self
                    .admitted_digest
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sha256(module));
                return ModuleAnchor::Anchored;
            }
            Some(rejection) => rejection,
        };
        let (reason, verdict) = match rejection {
            Rejection::NotAnchored(reason) => (reason, ModuleAnchor::NotAnchored),
            // Report our own wiring fault as `Unavailable`, never `NotAnchored`: the blob was not
            // examined, so there is no evidence, and `NotAnchored` would durably demote a holder for
            // something it did not do (see [`Rejection`]).
            Rejection::Indeterminate(reason) => {
                (reason, ModuleAnchor::Unavailable(reason.to_string()))
            }
        };
        tracing::warn!(
            store = %crate::seams::dig_peer::serve_log::SafeId::new(store_id),
            root = %crate::seams::dig_peer::serve_log::SafeId::new(root),
            reason,
            "module pull: refusing to admit an assembled module that is not chain-anchored"
        );
        verdict
    }
}

/// Decode a canonical 64-hex id into its 32 raw bytes, or `None` if it is not one.
///
/// The ONLY way an id enters a comparison in this module: decoding first makes hex case, padding, and
/// stray whitespace irrelevant to the outcome, where a text comparison would let a peer that
/// influences either side pick a spelling that compares unequal-but-looks-right (or equal-but-isn't).
fn decode_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *byte = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Read a data section that MUST be exactly 32 bytes, or `None` (absent, or the wrong width).
///
/// A short/long body is refused rather than padded or truncated: a 31-byte "root" silently
/// zero-extended into a 32-byte comparison is a forgery primitive.
fn section_id32(view: &DataView<'_>, id: SectionId) -> Option<[u8; 32]> {
    let body = view.section(id)?;
    <[u8; 32]>::try_from(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use digstore_core::datasection::{
        encode_blob, encode_chunk_pool, encode_key_table, encode_merkle_nodes, read_chunk,
    };
    use digstore_core::merkle::resource_leaf;
    use digstore_core::serving::concat_output;

    const STORE: [u8; 32] = [0xa1; 32];
    const CHAIN_ROOT: [u8; 32] = [0xb2; 32];
    /// A root a lying holder might serve instead — a real generation, just not the anchored one.
    const OTHER_ROOT: [u8; 32] = [0xc3; 32];

    fn hex32(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A `.dig`-shaped blob committing `store` + `root` with an EXPLICIT `MerkleNodes` set, but NO
    /// `ChunkPool`/`KeyTable` — reaches rules 1–4 exactly, and is (correctly) rejected by rule 5 if it
    /// ever gets that far. Used only by tests whose verdict is decided at rules 1–4.
    fn module_committing(store: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(root)]),
            ),
        ])
    }

    /// One resource in a synthetic capsule: its `static_key` and its ordered chunk ciphertexts.
    struct Resource {
        static_key: [u8; 32],
        chunks: Vec<Vec<u8>>,
    }

    /// Build a FAITHFUL `.dig`-shaped blob from `resources`, committing `store` + the root recomputed
    /// FROM the content, with a mutually-consistent `ChunkPool`, `KeyTable`, and `MerkleNodes` — the
    /// shape a genuine capsule has, so rule 5 admits it. Returns `(blob, root)`.
    ///
    /// Mirrors the producer recipe (`digstore-store` `store.rs`): chunks land in the pool in the order
    /// resources are given (assigning global indices), each resource's leaf is
    /// `resource_leaf(concat_output(its ciphertexts))`, and the leaves are sorted ASCENDING by
    /// `static_key` before folding — while the `KeyTable` retains the caller's (possibly unsorted)
    /// order, so a verifier that fails to sort independently computes the wrong root.
    fn honest_capsule_blob(store: [u8; 32], resources: &[Resource]) -> (Vec<u8>, [u8; 32]) {
        let mut pool: Vec<Vec<u8>> = Vec::new();
        let mut entries: Vec<KeyTableEntry> = Vec::new();
        let mut pairs: Vec<([u8; 32], Bytes32)> = Vec::new();

        for resource in resources {
            let mut chunk_indices = Vec::new();
            let mut total_size: u64 = 0;
            for chunk in &resource.chunks {
                chunk_indices.push(pool.len() as u32);
                total_size += chunk.len() as u64;
                pool.push(chunk.clone());
            }
            let slices: Vec<&[u8]> = resource.chunks.iter().map(|c| c.as_slice()).collect();
            let leaf = resource_leaf(&concat_output(&slices));
            pairs.push((resource.static_key, leaf));
            entries.push(KeyTableEntry {
                static_key: Bytes32(resource.static_key),
                generation: Bytes32([0u8; 32]),
                chunk_indices,
                total_size,
            });
        }

        pairs.sort_by_key(|(static_key, _)| *static_key);
        let leaves: Vec<Bytes32> = pairs.iter().map(|(_, leaf)| *leaf).collect();
        let root = MerkleTree::from_leaves(leaves.clone()).root().0;
        for entry in &mut entries {
            entry.generation = Bytes32(root);
        }

        let pool_slices: Vec<&[u8]> = pool.iter().map(|c| c.as_slice()).collect();
        let blob = encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&entries)),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&pool_slices)),
            (SectionId::MerkleNodes as u16, encode_merkle_nodes(&leaves)),
        ]);
        (blob, root)
    }

    /// One generation of a synthetic multi-generation capsule: the resources present in that
    /// generation. A resource re-appearing (same `static_key`) across generations models an UPDATE.
    struct Generation {
        resources: Vec<Resource>,
    }

    /// Build a FAITHFUL multi-generation `.dig`-shaped blob, mirroring the producer
    /// (`digstore-compiler`): the `KeyTable` carries one entry PER (generation, resource) — each
    /// stamped with THAT generation's root — the `ChunkPool` holds every generation's chunks in
    /// global-index order, but the committed `CurrentRoot` + `MerkleNodes` are over the CURRENT
    /// (last) generation ONLY. This is the shape any published store that has been updated at least
    /// once has, so it exercises the current-generation scoping of `content_leaves`. Returns
    /// `(blob, current_root)`.
    fn multi_generation_capsule_blob(
        store: [u8; 32],
        generations: &[Generation],
    ) -> (Vec<u8>, [u8; 32]) {
        // Per-generation leaves (ascending by static_key) → that generation's root, exactly as the
        // producer folds each generation.
        let gen_root = |resources: &[Resource]| -> [u8; 32] {
            let mut pairs: Vec<([u8; 32], Bytes32)> = resources
                .iter()
                .map(|r| {
                    let slices: Vec<&[u8]> = r.chunks.iter().map(|c| c.as_slice()).collect();
                    (r.static_key, resource_leaf(&concat_output(&slices)))
                })
                .collect();
            pairs.sort_by_key(|(static_key, _)| *static_key);
            let leaves: Vec<Bytes32> = pairs.into_iter().map(|(_, leaf)| leaf).collect();
            MerkleTree::from_leaves(leaves).root().0
        };

        let mut pool: Vec<Vec<u8>> = Vec::new();
        let mut entries: Vec<KeyTableEntry> = Vec::new();
        for generation in generations {
            let root = gen_root(&generation.resources);
            for resource in &generation.resources {
                let mut chunk_indices = Vec::new();
                let mut total_size: u64 = 0;
                for chunk in &resource.chunks {
                    chunk_indices.push(pool.len() as u32);
                    total_size += chunk.len() as u64;
                    pool.push(chunk.clone());
                }
                entries.push(KeyTableEntry {
                    static_key: Bytes32(resource.static_key),
                    generation: Bytes32(root),
                    chunk_indices,
                    total_size,
                });
            }
        }

        // The CURRENT generation drives the committed root + MerkleNodes.
        let current = &generations.last().unwrap().resources;
        let mut current_pairs: Vec<([u8; 32], Bytes32)> = current
            .iter()
            .map(|r| {
                let slices: Vec<&[u8]> = r.chunks.iter().map(|c| c.as_slice()).collect();
                (r.static_key, resource_leaf(&concat_output(&slices)))
            })
            .collect();
        current_pairs.sort_by_key(|(static_key, _)| *static_key);
        let current_leaves: Vec<Bytes32> =
            current_pairs.into_iter().map(|(_, leaf)| leaf).collect();
        let current_root = MerkleTree::from_leaves(current_leaves.clone()).root().0;

        let pool_slices: Vec<&[u8]> = pool.iter().map(|c| c.as_slice()).collect();
        let blob = encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, current_root.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&entries)),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&pool_slices)),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&current_leaves),
            ),
        ]);
        (blob, current_root)
    }

    fn verifier() -> ChainAnchoredModuleVerifier {
        ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(CHAIN_ROOT))
    }

    /// The verifier's verdict on `module` pulled as `(store, root)`.
    ///
    /// Tests assert the VARIANT, never a boolean: `NotAnchored` and `Unavailable` are both refusals
    /// but only the first is evidence against the holder, and a test that cannot tell them apart
    /// cannot notice a local fault being mislabelled as a peer's misbehaviour (see [`Rejection`]).
    fn verdict(module: &[u8], store: &str, root: &str) -> ModuleAnchor {
        let reader = SliceReader(module.to_vec());
        futures::executor::block_on(verifier().verify_module_anchor(&reader, store, root))
    }

    /// An in-memory [`ModuleReader`] over staged bytes — dig-download 0.15 hands the verifier a
    /// reader rather than a slice, so the tests supply the same shape the engine does.
    struct SliceReader(Vec<u8>);

    #[async_trait::async_trait]
    impl ModuleReader for SliceReader {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        async fn read_at(
            &self,
            offset: u64,
            len: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            let start = offset as usize;
            let end = start.saturating_add(len as usize).min(self.0.len());
            Ok(self.0[start.min(self.0.len())..end].to_vec())
        }
    }

    /// A reader whose every read FAILS — the local-fault path. A staging read error is this node
    /// failing to read its own bytes, so it must be `Unavailable` (no evidence against the holder),
    /// never `NotAnchored` (a durable demotion for something the peer did not do).
    struct FailingReader;

    #[async_trait::async_trait]
    impl ModuleReader for FailingReader {
        fn len(&self) -> u64 {
            128
        }
        async fn read_at(
            &self,
            _offset: u64,
            _len: u64,
        ) -> Result<Vec<u8>, dig_download::DownloadError> {
            Err(dig_download::DownloadError::Sink(
                "staging read failed".into(),
            ))
        }
    }

    /// **Proves:** a failure to read the staged bytes back is reported as OUR fault, not the
    /// holder's. Collapsing this into `NotAnchored` would durably demote an honest peer for a local
    /// I/O error — the distinction the whole `Rejection` split exists to preserve.
    #[test]
    fn a_staging_read_failure_is_unavailable_not_notanchored() {
        let verdict = futures::executor::block_on(verifier().verify_module_anchor(
            &FailingReader,
            &hex32(STORE),
            &hex32(CHAIN_ROOT),
        ));
        match verdict {
            ModuleAnchor::Unavailable(reason) => {
                assert!(
                    reason.contains("read"),
                    "reason should name the read: {reason}"
                );
            }
            other => panic!("a local read failure must be Unavailable, got {other:?}"),
        }
    }

    /// **Proves:** the genuine content-bearing module — the one whose ChunkPool recomputes to the
    /// chain's root — is admitted.
    #[test]
    fn admits_the_module_committing_the_chain_anchored_root() {
        let (module, root) = honest_capsule_blob(
            STORE,
            &[Resource {
                static_key: [0x01; 32],
                chunks: vec![b"the one and only resource".to_vec()],
            }],
        );
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE),
                &hex32(root)
            )),
            ModuleAnchor::Anchored
        );
    }

    /// **Proves:** a module whose committed root is a DIFFERENT real generation is refused — the
    /// rollback case (serve yesterday's capsule under today's root).
    /// **Catches:** a verifier that checked only that the module parses + commits *some* root.
    #[test]
    fn rejects_a_module_committing_a_different_generation() {
        // The blob's OWN committed root is wrong, so this is real evidence against whoever served
        // it — `NotAnchored`, the one verdict that earns a demotion.
        let module = module_committing(STORE, OTHER_ROOT);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** THE attack this whole file exists to stop — the "anchored root" offered by the
    /// SERVING PEER is never consulted. A holder that fabricates a module AND declares its root
    /// (self-consistently, so every hash gate passes) is still refused, because the only root this
    /// verifier compares against is the one the CHAIN gave the caller.
    /// **Catches:** any wiring in which the anchor is resolved from, or influenced by, the peer that
    /// served the module — the single defect that collapses the entire fail-closed story.
    ///
    /// Covers BOTH refusal arms deliberately. Asserting only the self-consistent lie stops at the
    /// generation-binding guard and never reaches rule 4, so it cannot distinguish
    /// `Indeterminate` from `NotAnchored` — a test that would stay green if the two verdicts were
    /// swapped is claiming more than it checks.
    #[test]
    fn rejects_a_module_whose_root_is_the_one_the_serving_peer_offered() {
        // The peer serves a perfectly well-formed module and *tells us* its root is OTHER_ROOT, both in
        // the module's own committed section and in the pull's `root` argument — a fully self-consistent
        // lie. A verifier that took the anchor from the peer would admit this.
        let peer_offered_root = OTHER_ROOT;
        let module = module_committing(STORE, peer_offered_root);

        assert_ne!(
            verdict(&module, &hex32(STORE), &hex32(peer_offered_root)),
            ModuleAnchor::Anchored,
            "a peer-offered root must never satisfy the anchor gate"
        );

        // And the reason names the anchor, so the rejection is diagnosable rather than a bare false.
        let reason = match verifier()
            .rejection_reason(&module, &hex32(STORE), &hex32(peer_offered_root))
            .expect("rejected")
        {
            Rejection::NotAnchored(reason) | Rejection::Indeterminate(reason) => reason,
        };
        assert!(
            reason.contains("chain-resolved root"),
            "the rejection must name the chain anchor, got: {reason}"
        );

        // The assertion above stops at the GENERATION-BINDING guard, because the pull argument names a
        // root this verifier is not bound to — so it never reaches rule 4, and it cannot tell the two
        // verdict arms apart. Drive rule 4 explicitly: the pull names the CHAIN root (clearing the
        // binding guard) while the module still commits the peer's root, which is the shape rule 4
        // exists for. It is EVIDENCE about the blob, so it must be `NotAnchored`, not `Indeterminate`.
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored,
            "a module committing the peer's root, pulled at the chain root, is evidence against the              holder — the arm matters, because only NotAnchored earns a demotion"
        );
    }

    /// **Proves:** a 0-byte blob is refused.
    /// **Catches:** relying on the engine's hash gates, both of which PASS trivially for the empty
    /// module (`sha256("")` is a perfectly declarable `module_hash`) — this verifier is the only check.
    #[test]
    fn rejects_an_empty_blob() {
        assert_eq!(
            verdict(&[], &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** bytes that are not a parseable `.dig` are refused, rather than falling through some
    /// "could not parse, assume fine" path.
    #[test]
    fn rejects_an_unparseable_blob() {
        assert_eq!(
            verdict(
                b"this is not a DIGS container",
                &hex32(STORE),
                &hex32(CHAIN_ROOT)
            ),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** the root comparison is over DECODED bytes, so hex CASE cannot change the outcome —
    /// the genuine module is still admitted when the ids arrive upper-cased.
    /// **Catches:** a `String`/`&str` comparison, where a peer-influenced spelling of the same 32 bytes
    /// silently decides the anchor gate.
    #[test]
    fn hex_case_does_not_change_the_verdict() {
        let (module, root) = honest_capsule_blob(
            STORE,
            &[Resource {
                static_key: [0x07; 32],
                chunks: vec![b"case-insensitive-id resource".to_vec()],
            }],
        );
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE).to_uppercase(),
                &hex32(root).to_uppercase()
            )),
            ModuleAnchor::Anchored
        );
    }

    /// **Proves:** a module committing the right root but a DIFFERENT store is refused — a real capsule
    /// from another store cannot be admitted under this store's identity.
    #[test]
    fn rejects_a_module_committing_a_different_store() {
        let module = module_committing([0xee; 32], CHAIN_ROOT);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** a module whose `CurrentRoot` body is the wrong WIDTH is refused, never
    /// zero-extended or truncated into a comparison it could pass.
    #[test]
    fn rejects_a_short_root_section() {
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT[..31].to_vec()),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** a module missing its `CurrentRoot` section entirely is refused (absence is not
    /// "anchored").
    #[test]
    fn rejects_a_module_with_no_committed_root() {
        let module = encode_blob(&[(SectionId::StoreId as u16, STORE.to_vec())]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** THE refuted attack — `MerkleNodes = [chain_root]` (a single-leaf tree whose root
    /// IS that leaf, so it trivially equals the committed chain root) plus an EMPTY `ChunkPool` and
    /// empty `KeyTable` is refused. The prior fix recomputed from `MerkleNodes` and ADMITTED this
    /// contentless phantom-holder capsule; binding the decision to the served content refuses it,
    /// because empty content folds to `sha256(&[])` ≠ `chain_root`.
    /// **Catches:** any rule 5 that trusts `MerkleNodes` digests instead of the `ChunkPool` bytes.
    #[test]
    fn rejects_single_leaf_merklenodes_equal_chain_root_with_empty_chunk_pool() {
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[])),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&[])),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** the same self-consistent `MerkleNodes = [chain_root]` lie, now with a GARBAGE
    /// `ChunkPool` and a `KeyTable` entry pointing at it, is still refused — the content recomputes to
    /// its own (garbage) leaf, not to the chain root.
    /// **Catches:** a rule 5 that trusts `MerkleNodes` regardless of what the pool actually holds.
    #[test]
    fn rejects_single_leaf_merklenodes_equal_chain_root_with_garbage_chunk_pool() {
        let garbage: &[u8] = b"not the resource these leaves claim";
        let entry = KeyTableEntry {
            static_key: Bytes32([0x01; 32]),
            generation: Bytes32(CHAIN_ROOT),
            chunk_indices: vec![0],
            total_size: garbage.len() as u64,
        };
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[entry])),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&[garbage])),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** THE decisive #2246/#2240 kill — a GENUINE capsule whose `ChunkPool` has had one
    /// ciphertext byte flipped, while its `MerkleNodes` (and committed root) remain the HONEST ones,
    /// is refused. The old rule read `MerkleNodes` and would ADMIT it (the honest leaves still fold to
    /// the committed root); the new rule recomputes from the tampered content and refuses.
    /// **Catches:** exactly the "trust the digests, not the bytes" defect the refutation exposed.
    #[test]
    fn rejects_content_tampered_capsule_with_honest_merklenodes() {
        // Build the honest capsule to learn its committed root + honest leaf, then re-encode with a
        // tampered pool but the ORIGINAL MerkleNodes + CurrentRoot — the header-honest, content-forged
        // shape.
        let honest_chunk = b"the honest resource ciphertext bytes".to_vec();
        let honest_leaf = resource_leaf(&concat_output(&[honest_chunk.as_slice()]));
        let root = MerkleTree::from_leaves(vec![honest_leaf]).root().0;

        let mut tampered_chunk = honest_chunk.clone();
        tampered_chunk[0] ^= 0xff;
        let entry = KeyTableEntry {
            static_key: Bytes32([0x02; 32]),
            generation: Bytes32(root),
            chunk_indices: vec![0],
            total_size: tampered_chunk.len() as u64,
        };
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[entry])),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[tampered_chunk.as_slice()]),
            ),
            // The HONEST leaves — the fabricator leaves these untouched to fool a digest-trusting gate.
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[honest_leaf]),
            ),
        ]);
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE),
                &hex32(root)
            )),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** THE remote OOM/CPU-DoS is bounded — a small module whose KeyTable entry REPEATS one
    /// chunk index a huge number of times (`chunk_indices = [0; N]`, an ~1 MB blob addressing gigabytes
    /// of referenced content) is refused fail-closed, NOT allocated/hashed into a crash. `store_id` +
    /// `chain_root` are public so rules 1–4 pass for free on the pre-auth reshare-warm path; the total
    /// referenced-bytes cap (`MAX_STORE_BYTES`) is the only thing between the crafted amplifier and an
    /// allocator abort.
    /// **Catches:** a `content_leaves` that concatenates/hashes attacker-repeated indices unbounded.
    #[test]
    fn rejects_a_chunk_index_amplification_bomb() {
        // ~256 KiB real chunk, referenced 1_000_000 times ⇒ ~256 GB of referenced content: a genuine
        // store cannot exceed MAX_STORE_BYTES (128 MB), so the recompute must refuse rather than fold.
        let big_chunk = vec![0xabu8; 256 * 1024];
        let repeats = 1_000_000u32;
        let entry = KeyTableEntry {
            static_key: Bytes32([0x01; 32]),
            generation: Bytes32(CHAIN_ROOT),
            chunk_indices: vec![0; repeats as usize],
            total_size: big_chunk.len() as u64 * repeats as u64,
        };
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[entry])),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[big_chunk.as_slice()]),
            ),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored,
            "an index-repetition amplification bomb must fail closed, not OOM the node"
        );
    }

    /// **Proves:** the quadratic scan-DoS is CLOSED — a module with M ZERO-LENGTH `ChunkPool` chunks
    /// and one current-generation entry referencing the HIGHEST index N times completes in
    /// O(pool+refs), not Θ(N·M). The canonical `read_chunk` is O(global_index) (it re-walks the pool
    /// from offset 0 per call), and zero-length chunks add 0 bytes so the `MAX_STORE_BYTES` cap never
    /// trips — so before the pre-index this input pinned a CPU core for Θ(module²) iterations per
    /// unauthenticated reshare request (M=N=100k ⇒ 10^10 scans, tens of seconds→minutes). With the
    /// one-pass pre-index each reference is O(1), so the whole recompute is ~200k ops and returns
    /// promptly, fail-closed (`NotAnchored`: empty content folds to `sha256(&[])` ≠ chain root).
    /// **Catches:** any reintroduction of a per-reference `read_chunk` re-scan.
    #[test]
    fn bounds_a_zero_length_chunk_scan_bomb() {
        use std::time::Instant;
        // M zero-length chunks in the pool; N references, all at the highest index — the worst case
        // for an O(global_index) per-call scan.
        const M: u32 = 100_000;
        const N: usize = 100_000;

        let zero_chunks: Vec<&[u8]> = vec![&[][..]; M as usize];
        let entry = KeyTableEntry {
            static_key: Bytes32([0x01; 32]),
            generation: Bytes32(CHAIN_ROOT),
            chunk_indices: vec![M - 1; N],
            total_size: 0,
        };
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[entry])),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&zero_chunks)),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);

        let start = Instant::now();
        let verdict = verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT));
        let elapsed = start.elapsed();

        assert_eq!(
            verdict,
            ModuleAnchor::NotAnchored,
            "a zero-length scan bomb must fail closed, never be admitted"
        );
        // A generous ceiling: the pre-indexed path is milliseconds; the pre-fix Θ(N·M) path would
        // take tens of seconds to minutes and blow this bound.
        assert!(
            elapsed.as_secs() < 5,
            "content_leaves must be O(pool+refs), not O(pool*refs): took {elapsed:?} for {M}×{N}"
        );
    }

    /// **Proves:** the pre-indexed lookup is byte-identical to the canonical `read_chunk` for every
    /// index of a normal (mixed-length, including zero-length) pool, and mirrors its out-of-range
    /// `None`. This is what lets [`content_leaves`] swap `read_chunk` for the O(1) pre-index without
    /// changing which bytes fold into a leaf.
    #[test]
    fn the_prebuilt_chunk_index_matches_read_chunk() {
        let chunks: Vec<Vec<u8>> = vec![
            b"first chunk".to_vec(),
            Vec::new(), // a zero-length chunk — the framing must still advance
            b"a third, longer chunk of ciphertext".to_vec(),
            b"x".to_vec(),
        ];
        let slices: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let pool = encode_chunk_pool(&slices);

        let ranges = index_chunk_pool(&pool).expect("a well-formed pool indexes");
        assert_eq!(ranges.len(), chunks.len());
        for i in 0..chunks.len() as u32 {
            let via_read = read_chunk(&pool, i).expect("read_chunk in range");
            let via_index = &pool[ranges[i as usize].clone()];
            assert_eq!(
                via_index, via_read,
                "pre-indexed range {i} must equal read_chunk's slice"
            );
        }
        // Out of range mirrors read_chunk's None.
        assert!(read_chunk(&pool, chunks.len() as u32).is_none());
        assert!(ranges.get(chunks.len()).is_none());
    }

    /// **Proves:** malformed `ChunkPool` framing fails closed — a body whose declared count exceeds
    /// the bytes present cannot be indexed, so the recompute refuses rather than reading past the end.
    #[test]
    fn a_malformed_chunk_pool_fails_the_preindex_closed() {
        // Claims one chunk of length 100 but supplies no body bytes → overruns.
        let mut malformed = 1u32.to_be_bytes().to_vec();
        malformed.extend_from_slice(&100u32.to_be_bytes());
        assert!(index_chunk_pool(&malformed).is_none());
    }

    /// **Proves:** a module missing its `ChunkPool` is refused — the content the root must bind is
    /// absent, so there is nothing to recompute from (fail-closed).
    #[test]
    fn rejects_missing_chunk_pool() {
        let entry = KeyTableEntry {
            static_key: Bytes32([0x01; 32]),
            generation: Bytes32(CHAIN_ROOT),
            chunk_indices: vec![0],
            total_size: 4,
        };
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[entry])),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** a module missing its `KeyTable` is refused — without it there is no map from
    /// resources to their chunks, so the content root cannot be reconstructed (fail-closed).
    #[test]
    fn rejects_missing_key_table() {
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, CHAIN_ROOT.to_vec()),
            (
                SectionId::ChunkPool as u16,
                encode_chunk_pool(&[b"orphan chunk"]),
            ),
            (
                SectionId::MerkleNodes as u16,
                encode_merkle_nodes(&[Bytes32(CHAIN_ROOT)]),
            ),
        ]);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
            ModuleAnchor::NotAnchored
        );
    }

    /// **Proves:** the genuine content-bearing capsule — multiple resources whose ChunkPool folds to
    /// the committed chain root — is admitted, and that the recompute SORTS by `static_key`: the
    /// resources are given in DESCENDING key order (so the KeyTable stores them unsorted) while the
    /// producer root is over the ascending fold, so a verifier that did not sort would compute a
    /// different two-leaf root and reject an honest capsule.
    #[test]
    fn admits_a_genuine_content_bearing_capsule() {
        let (module, root) = honest_capsule_blob(
            STORE,
            &[
                Resource {
                    static_key: [0x09; 32],
                    chunks: vec![b"resource nine".to_vec(), b" second chunk".to_vec()],
                },
                Resource {
                    static_key: [0x02; 32],
                    chunks: vec![b"resource two".to_vec()],
                },
            ],
        );
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE),
                &hex32(root)
            )),
            ModuleAnchor::Anchored
        );
    }

    /// **Proves:** THE #2246 current-generation-scoping fix — a genuine capsule for a store that has
    /// been UPDATED (≥2 generations) is admitted. Its embedded `KeyTable` is multi-generation
    /// (gen0 = {A_v1}; gen1/current = {A_v2, B}, each entry stamped with ITS generation's root),
    /// while the committed root + `MerkleNodes` are over the CURRENT generation only.
    /// **Catches:** a `content_leaves` that folds EVERY KeyTable entry (all 3) instead of only the
    /// current generation's (A_v2, B) — it recomputes a root over too many leaves, so it
    /// false-rejects the genuine current content of any published-then-updated store as
    /// `NotAnchored`, breaking admit/cache/announce for the normal update lifecycle.
    #[test]
    fn admits_a_genuine_multi_generation_updated_capsule() {
        let key_a = [0x0a; 32];
        let key_b = [0x0b; 32];
        let (module, current_root) = multi_generation_capsule_blob(
            STORE,
            &[
                Generation {
                    resources: vec![Resource {
                        static_key: key_a,
                        chunks: vec![b"resource A, version one".to_vec()],
                    }],
                },
                Generation {
                    resources: vec![
                        Resource {
                            static_key: key_a,
                            chunks: vec![b"resource A, version TWO".to_vec()],
                        },
                        Resource {
                            static_key: key_b,
                            chunks: vec![b"resource B, added in gen one".to_vec()],
                        },
                    ],
                },
            ],
        );
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(current_root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE),
                &hex32(current_root)
            )),
            ModuleAnchor::Anchored,
            "a genuine capsule for an updated (multi-generation) store must be admitted"
        );
    }

    /// **Proves:** the §5.1 legitimate-empty edge — a metadata-only store with an EMPTY `KeyTable` +
    /// empty `ChunkPool`, whose chain root is `sha256(&[])` (the empty-tree fold), with empty
    /// `MerkleNodes`, is ADMITTED, not errored. The recompute must reproduce `from_leaves(vec![])`,
    /// not reject on "no entries".
    #[test]
    fn admits_a_genuine_empty_metadata_only_store() {
        let empty_root = sha256(&[]);
        let module = encode_blob(&[
            (SectionId::StoreId as u16, STORE.to_vec()),
            (SectionId::CurrentRoot as u16, empty_root.to_vec()),
            (SectionId::KeyTable as u16, encode_key_table(&[])),
            (SectionId::ChunkPool as u16, encode_chunk_pool(&[])),
            (SectionId::MerkleNodes as u16, encode_merkle_nodes(&[])),
        ]);
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(empty_root));
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module),
                &hex32(STORE),
                &hex32(empty_root)
            )),
            ModuleAnchor::Anchored
        );
    }

    /// **Proves:** a non-canonical id (wrong length, non-hex) is refused rather than treated as a
    /// wildcard.
    #[test]
    fn rejects_non_canonical_ids() {
        // A malformed id is OUR caller's fault, not the holder's: the blob is never examined, so the
        // refusal must carry no verdict about whoever served it.
        let module = module_committing(STORE, CHAIN_ROOT);
        for (store, root) in [
            ("short".to_string(), hex32(CHAIN_ROOT)),
            (hex32(STORE), "zz".repeat(32)),
        ] {
            assert!(
                matches!(
                    verdict(&module, &store, &root),
                    ModuleAnchor::Unavailable(_)
                ),
                "a non-canonical id must refuse WITHOUT blaming the holder: {store}/{root}"
            );
        }
    }

    /// **Proves:** the admitted digest is the digest of exactly the bytes that passed the gate, so the
    /// caller's pre-announce re-check has a self-sourced reference (no peer supplies either side).
    #[test]
    fn the_admitted_digest_is_the_digest_of_the_admitted_bytes() {
        let (module, root) = honest_capsule_blob(
            STORE,
            &[Resource {
                static_key: [0x05; 32],
                chunks: vec![b"admitted-digest resource".to_vec()],
            }],
        );
        let v = ChainAnchoredModuleVerifier::for_generation(Bytes32(STORE), Bytes32(root));
        assert_eq!(v.admitted_digest(), None, "nothing admitted yet");
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module.clone()),
                &hex32(STORE),
                &hex32(root)
            )),
            ModuleAnchor::Anchored
        );
        assert_eq!(v.admitted_digest(), Some(sha256(&module)));
    }

    /// **Proves:** a REJECTED blob never becomes the promotion reference — otherwise a rejected module
    /// could hand the caller a digest that makes promoting that very module look self-consistent.
    /// **Catches:** recording the digest before/regardless of the verdict.
    #[test]
    fn a_rejected_blob_never_becomes_the_promotion_reference() {
        let v = verifier();
        assert_eq!(
            futures::executor::block_on(v.verify_module_anchor(
                &SliceReader(module_committing(STORE, OTHER_ROOT)),
                &hex32(STORE),
                &hex32(CHAIN_ROOT)
            )),
            ModuleAnchor::NotAnchored
        );
        assert_eq!(
            v.admitted_digest(),
            None,
            "a rejected module must leave no admitted digest"
        );
    }

    /// **Proves:** a verifier bound to generation A refuses a pull of generation B, so a verifier can
    /// never be reused across generations to check the wrong anchor.
    #[test]
    fn a_verifier_is_bound_to_one_generation() {
        let module = module_committing(STORE, OTHER_ROOT);
        // The module is genuine for OTHER_ROOT, and the pull names OTHER_ROOT — but this verifier was
        // built for CHAIN_ROOT, so it must refuse rather than validate a generation it never resolved.
        // Refused, but with NO verdict about the holder: reusing a verifier across generations is
        // THIS node's wiring fault, and `NotAnchored` here would durably demote an honest holder that
        // served a perfectly genuine capsule (see [`Rejection`]).
        assert!(matches!(
            verdict(&module, &hex32(STORE), &hex32(OTHER_ROOT)),
            ModuleAnchor::Unavailable(_)
        ));
    }
}
