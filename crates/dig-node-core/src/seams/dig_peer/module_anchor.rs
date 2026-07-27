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

use std::sync::{Arc, Mutex};

use digstore_core::datasection::{DataView, SectionId};
use digstore_core::Bytes32;
use sha2::{Digest, Sha256};

use dig_download::{ModuleAnchor, ModuleAnchorVerifier};

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
        None
    }
}

impl ModuleAnchorVerifier for ChainAnchoredModuleVerifier {
    fn verify_module_anchor(&self, module: &[u8], store_id: &str, root: &str) -> ModuleAnchor {
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
    use digstore_core::datasection::encode_blob;

    const STORE: [u8; 32] = [0xa1; 32];
    const CHAIN_ROOT: [u8; 32] = [0xb2; 32];
    /// A root a lying holder might serve instead — a real generation, just not the anchored one.
    const OTHER_ROOT: [u8; 32] = [0xc3; 32];

    fn hex32(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A `.dig`-shaped data-section blob committing `store` + `root`.
    fn module_committing(store: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        encode_blob(&[
            (SectionId::StoreId as u16, store.to_vec()),
            (SectionId::CurrentRoot as u16, root.to_vec()),
        ])
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
        verifier().verify_module_anchor(module, store, root)
    }

    /// **Proves:** the genuine module — the one whose committed root IS the chain's root — is admitted.
    #[test]
    fn admits_the_module_committing_the_chain_anchored_root() {
        let module = module_committing(STORE, CHAIN_ROOT);
        assert_eq!(
            verdict(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
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
        let module = module_committing(STORE, CHAIN_ROOT);
        assert_eq!(
            verdict(
                &module,
                &hex32(STORE).to_uppercase(),
                &hex32(CHAIN_ROOT).to_uppercase()
            ),
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
        let module = module_committing(STORE, CHAIN_ROOT);
        let v = verifier();
        assert_eq!(v.admitted_digest(), None, "nothing admitted yet");
        assert_eq!(
            v.verify_module_anchor(&module, &hex32(STORE), &hex32(CHAIN_ROOT)),
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
            v.verify_module_anchor(
                &module_committing(STORE, OTHER_ROOT),
                &hex32(STORE),
                &hex32(CHAIN_ROOT)
            ),
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
