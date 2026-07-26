//! The per-range verification contract of a `dig.fetchRange` frame (#1577 / #1437 serve leg).
//!
//! A downloading peer fetches a resource as ranges, in parallel, from whichever holders answer. For
//! that to be safe, **each range must be checkable on arrival** — otherwise a source serving a range
//! from a different (or forged) generation is only caught at the very end, after the whole resource
//! has been paid for in bandwidth. This module owns the metadata that makes a frame self-describing,
//! and is the ONE place both serve paths — a locally-held capsule
//! ([`crate::Node::fetch_range_frame`]) and a fetched-through one
//! ([`crate::download::FetchedResource::range_frame`]) — build it, so the two can never skew.
//!
//! ## What a frame commits to
//!
//! [`RangeVerification`] rides EVERY frame, not just the `offset == 0` one:
//!
//! * `total_length` + `chunk_lens` — the resource's chunk layout, so the client can plan/validate
//!   ranges and confirm the frame covers whole chunks (dig-download's `verify_range`).
//! * `root` — the chain-anchored generation root this resource is served from. A frame declaring a
//!   root the client has not committed to is rejected by `ResourceCommitment::check_consistent`
//!   *before* its bytes are trusted. Serving it only on the first frame left every subsequent range —
//!   from every other peer — declaring nothing to check.
//! * `inclusion_proof` — the whole-resource digstore merkle proof binding
//!   `resource_leaf(ciphertext)` under `root`, which the client folds once the resource is assembled.
//! * `first_chunk_index` (+ the legacy `chunk_index` alias) — the absolute index, into `chunk_lens`,
//!   of the chunk this frame starts at. Reported ONLY when the frame genuinely starts on a chunk
//!   boundary (see [`chunk_index_at`]).
//!
//! Every field is additive and optional on the wire (dig-rpc-protocol §5.1): a client that reads only
//! `offset`/`length`/`bytes`/`complete` is unaffected, and the served window is never widened to a
//! chunk boundary — the client's `verify_range` fails closed on any length but the one it planned.
//!
//! ## Why there is no per-chunk merkle proof
//!
//! The obvious reading of "per-range integrity" — one merkle inclusion proof per served chunk, folded
//! to the generation root — is **not derivable from the `.dig` format**, and this module deliberately
//! does not fabricate one. The chain-anchored generation tree commits RESOURCES, not chunks:
//! `digstore_core::merkle::resource_leaf(ciphertext)` is `SHA-256` of the resource's WHOLE ciphertext,
//! and every real tree is built by `MerkleTree::from_leaves(resource_leaves)`. So recomputing the leaf
//! for a resource requires every chunk's bytes; a single chunk has no committed digest of its own to
//! prove, and `MerkleTree::build` (the chunk-leaf constructor) has no callers in the store at all.
//!
//! A `range_proof` emitted today therefore could not be folded to the on-chain root by any verifier.
//! Serving one would be unverifiable decoration that invites a client to trust bytes it cannot check —
//! strictly worse than the honest contract above, which binds the resource to the root at completion
//! and rejects a wrong-generation range on arrival. Real per-chunk proofs need a store-format
//! prerequisite (a per-resource chunk tree whose root becomes the resource leaf, additive per §5.1, in
//! `digs`); until that exists the field stays absent rather than false.

use serde_json::{json, Value};

/// The verification metadata a served range frame carries about its resource.
///
/// Borrowed rather than owned so both serve paths can hand over whatever they already hold (a decoded
/// `ContentResponse`, a fetched-through resource) with no cloning.
pub(crate) struct RangeVerification<'a> {
    /// The full resource ciphertext length.
    pub total_length: u64,
    /// Per-chunk ciphertext lengths of the whole resource, in order. Empty for a single-chunk
    /// resource compiled by a producer that emitted no chunk table.
    pub chunk_lens: &'a [u64],
    /// The chain-anchored generation root (64-hex), when the serve path knows it.
    pub root: Option<&'a str>,
    /// The whole-resource merkle inclusion proof (base64, digstore byte format), when known.
    pub inclusion_proof: Option<&'a str>,
}

/// The absolute chunk index that byte `offset` begins, or `None` when `offset` is not on a chunk
/// boundary (or lies past the resource).
///
/// A frame starting mid-chunk is not a chunk-aligned verifiable unit, so the serve path reports no
/// index at all rather than an index the client's own alignment check would then contradict.
pub(crate) fn chunk_index_at(chunk_lens: &[u64], offset: u64) -> Option<u64> {
    let mut boundary = 0u64;
    for (index, &len) in chunk_lens.iter().enumerate() {
        if boundary == offset {
            return Some(index as u64);
        }
        boundary = boundary.saturating_add(len);
    }
    // The terminal boundary (== total length) starts no chunk. A resource with no chunk table
    // reports chunk 0 at its start, matching the single-chunk shape the wire has always served.
    (chunk_lens.is_empty() && offset == 0).then_some(0)
}

/// Attach `verification` to a range `frame` whose window starts at absolute byte `start`.
///
/// Idempotent in shape: the data fields (`offset`/`length`/`bytes`/`complete`) are never touched, and
/// a field whose value the serve path does not know is omitted rather than nulled.
pub(crate) fn attach_verification(
    frame: &mut Value,
    verification: &RangeVerification<'_>,
    start: u64,
) {
    let Some(obj) = frame.as_object_mut() else {
        return;
    };
    obj.insert("total_length".into(), json!(verification.total_length));
    obj.insert("chunk_lens".into(), json!(verification.chunk_lens));
    if let Some(root) = verification.root {
        obj.insert("root".into(), json!(root));
    }
    if let Some(proof) = verification.inclusion_proof {
        obj.insert("inclusion_proof".into(), json!(proof));
    }
    if let Some(index) = chunk_index_at(verification.chunk_lens, start) {
        obj.insert("first_chunk_index".into(), json!(index));
        // `chunk_index` is the pre-#1577 name for the same value, kept for older readers.
        obj.insert("chunk_index".into(), json!(index));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_index_at_maps_every_boundary_to_its_chunk() {
        let lens = [40, 25, 17];
        assert_eq!(chunk_index_at(&lens, 0), Some(0));
        assert_eq!(chunk_index_at(&lens, 40), Some(1));
        assert_eq!(chunk_index_at(&lens, 65), Some(2));
    }

    #[test]
    fn chunk_index_at_refuses_an_offset_inside_a_chunk() {
        let lens = [40, 25, 17];
        for offset in [1, 39, 41, 64, 66] {
            assert_eq!(chunk_index_at(&lens, offset), None, "offset {offset}");
        }
    }

    #[test]
    fn chunk_index_at_refuses_the_terminal_and_past_the_end_offsets() {
        // The end-of-resource boundary starts no chunk, so it is not a verifiable span's start.
        let lens = [40, 25, 17];
        assert_eq!(chunk_index_at(&lens, 82), None);
        assert_eq!(chunk_index_at(&lens, 9_000), None);
    }

    #[test]
    fn chunk_index_at_treats_a_resource_with_no_chunk_table_as_one_chunk() {
        assert_eq!(chunk_index_at(&[], 0), Some(0));
        assert_eq!(chunk_index_at(&[], 1), None);
    }

    #[test]
    fn attach_verification_leaves_the_data_fields_untouched() {
        let mut frame = json!({"offset": 40, "length": 25, "bytes": "AAA=", "complete": false});
        let lens = [40u64, 25, 17];
        attach_verification(
            &mut frame,
            &RangeVerification {
                total_length: 82,
                chunk_lens: &lens,
                root: Some("aa"),
                inclusion_proof: Some("cHJvb2Y="),
            },
            40,
        );
        assert_eq!(frame["offset"], json!(40));
        assert_eq!(frame["length"], json!(25));
        assert_eq!(frame["bytes"], json!("AAA="));
        assert_eq!(frame["complete"], json!(false));
        assert_eq!(frame["first_chunk_index"], json!(1));
        assert_eq!(frame["chunk_index"], json!(1));
        assert_eq!(frame["root"], json!("aa"));
        assert_eq!(frame["inclusion_proof"], json!("cHJvb2Y="));
    }

    #[test]
    fn attach_verification_omits_what_the_serve_path_does_not_know() {
        // A capsule fetch knows no per-resource root or proof: those fields are ABSENT, not null —
        // a half-specified binding (root without proof, or vice versa) fails closed client-side.
        let mut frame = json!({"offset": 3, "length": 1});
        let lens = [40u64];
        attach_verification(
            &mut frame,
            &RangeVerification {
                total_length: 40,
                chunk_lens: &lens,
                root: None,
                inclusion_proof: None,
            },
            3,
        );
        assert!(frame.get("root").is_none());
        assert!(frame.get("inclusion_proof").is_none());
        assert!(
            frame.get("first_chunk_index").is_none(),
            "offset 3 is mid-chunk"
        );
        assert_eq!(frame["total_length"], json!(40));
    }
}
