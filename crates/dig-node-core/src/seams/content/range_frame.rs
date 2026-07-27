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
//! ## One frame is not one window (#1640 / #1668)
//!
//! A frame's payload is capped at [`dig_nat::MAX_RANGE_FRAME_PAYLOAD`] (32,768 B). That is a different
//! and much smaller quantity than [`crate::peer::RANGE_WINDOW`] (3 MiB), which bounds how much ONE
//! REQUEST may ask for. Framing on the request window against the frame cap is how this node became
//! unable to serve any resource over roughly 48 KiB: `bytes` travels base64, so a larger payload
//! produces a body over [`dig_nat::MAX_FRAMED_BODY`], and every conforming receiver is REQUIRED to
//! reject it. A serving peer therefore tiles a requested window into ceiling-sized frames.
//!
//! Which metadata rides which frame follows from the same arithmetic, and the split is normative
//! (dig-nat `SPEC.md` §5.1.1):
//!
//! * the **identity set** — `root`, `total_length`, `chunk_count`, and `chunk_index` where the window
//!   is chunk-aligned — is FIXED-SIZE, so it rides EVERY frame. It is what lets a reader reject a
//!   wrong-generation or wrong-layout holder the moment a frame arrives, which a once-per-stream field
//!   can never do.
//! * the **prologue** — `chunk_lens` and `inclusion_proof` — scales with the RESOURCE, so it is sent
//!   once per stream and MUST NOT be repeated. A layout too large for one frame is PAGED, each page
//!   stamped with the `chunk_lens_offset` it begins at.
//!
//! ## Why this module builds the dig-nat type rather than a `json!`
//!
//! [`RangeStreamFramer`] returns a real [`dig_nat::RangeFrame`], and the serve paths write it with
//! [`write_range_frame`], which goes through [`dig_nat::RangeFrame::encode`] — the encoder that
//! REFUSES an over-ceiling payload. Building frames as raw JSON and writing them with an uncapped
//! `write_framed` is what made the defect possible in the first place: the sender had no way to learn
//! it had produced something the receiver must reject, so the asymmetry could only surface as a failed
//! read in production. Routing every frame through the type the receiver decodes makes the two sides
//! of one rule impossible to maintain separately.
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

use std::collections::VecDeque;

use serde_json::{json, Value};

/// The most raw ciphertext bytes ONE frame may carry — read from dig-nat, never restated here.
///
/// Restating a wire bound as a local literal is how two implementations of one rule drift apart, and
/// this particular budget was independently derived wrong four times, every error running too
/// generous. There is exactly one authority for it.
pub(crate) const FRAME_PAYLOAD: usize = dig_nat::MAX_RANGE_FRAME_PAYLOAD;

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

/// Split `chunk_lens` into the pages a paged prologue is made of: page-aligned offsets, each page
/// exactly [`dig_nat::MAX_CHUNK_LENS_PER_FRAME`] entries except a possibly-short tail.
///
/// This mirrors `dig_nat::RangeFrame::split_chunk_lens_pages`, which is the normative split and the
/// reassembler's own mirror. It is reproduced here ONLY because that helper landed in dig-nat 0.14,
/// while this node is held at 0.13 by dig-download and dig-gossip (see the dependency rationale in
/// `Cargo.toml`); the moment the tree reaches 0.14 this function should be deleted in favour of it,
/// because #1640 was precisely two sides of one rule maintained separately. The page SIZE is read from
/// dig-nat either way, so the one number that matters cannot drift.
///
/// The shape is what the reassembler requires, and each requirement excludes a whole class rather
/// than one observed misbehaviour:
///
/// * no page is EMPTY — an empty page fills nothing, so accepting one lets a sender stream frames
///   forever without ever completing the prologue;
/// * every page except the tail is exactly full — a short page anywhere but the end leaves a gap no
///   page-aligned page can ever fill, so it is refused on arrival rather than surfacing later as an
///   unexplained incompleteness;
/// * an empty ARRAY yields no pages at all, which is a complete prologue for a resource with no chunk
///   table rather than a stream that can never finish.
fn chunk_lens_pages(chunk_lens: &[u64]) -> Vec<(u64, Vec<u64>)> {
    chunk_lens
        .chunks(dig_nat::MAX_CHUNK_LENS_PER_FRAME)
        .enumerate()
        .map(|(page, entries)| {
            (
                (page * dig_nat::MAX_CHUNK_LENS_PER_FRAME) as u64,
                entries.to_vec(),
            )
        })
        .collect()
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

/// Builds the frames of ONE range stream, in order.
///
/// It is a stream-scoped object rather than a free function because "which prologue page does this
/// frame carry, and has the proof gone out yet" is a property of the STREAM, not of the frame. A
/// per-frame builder cannot know, which is why the pre-#1668 code could only ever put the whole
/// layout on the first frame — and a layout that does not fit one frame then has no representation at
/// all.
pub(crate) struct RangeStreamFramer<'a> {
    verification: RangeVerification<'a>,
    /// The prologue pages not yet sent, in order. Drained as frames go out.
    pending_pages: VecDeque<(u64, Vec<u64>)>,
    /// Whether the inclusion proof has already ridden a frame of this stream.
    proof_sent: bool,
    /// The client already holds the commitment for this root and asked us not to resend the
    /// resource-scaling set.
    skip_layout: bool,
}

impl<'a> RangeStreamFramer<'a> {
    /// A framer for a stream serving `verification`'s resource.
    ///
    /// `skip_layout` comes from the request. Honouring it omits `chunk_lens` + `inclusion_proof`
    /// entirely — and ONLY those: the identity set is never suppressed, because it is fixed-size and
    /// it is the reader's only means of detecting a wrong-generation holder as frames arrive.
    pub(crate) fn new(verification: RangeVerification<'a>, skip_layout: bool) -> Self {
        let pending_pages = if skip_layout {
            VecDeque::new()
        } else {
            chunk_lens_pages(verification.chunk_lens).into()
        };
        RangeStreamFramer {
            verification,
            pending_pages,
            proof_sent: false,
            skip_layout,
        }
    }

    /// The next frame of this stream: the window `[start, start + bytes.len())`, plus the identity set
    /// and whichever prologue page is next owed.
    ///
    /// The frame comes back with `complete` UNSET, deliberately. `complete` means "this is the final
    /// frame of the range", and whether a frame is final is not knowable until after this call has
    /// consumed its prologue page — the caller asks [`prologue_pending`](Self::prologue_pending)
    /// afterwards and applies `with_complete` itself. Setting `complete` on a frame that still owes
    /// pages would stop a conforming reader before the layout it needs to DECRYPT ever arrives.
    pub(crate) fn next_frame(&mut self, start: u64, bytes: Vec<u8>) -> dig_nat::RangeFrame {
        let mut frame = dig_nat::RangeFrame::data(start, bytes);

        // The identity set rides EVERY frame. `chunk_count` is the resource's TOTAL entry count, so a
        // reader can size the array it is paging in and tell when the prologue is done.
        let chunk_count = self.chunk_count();
        if let Some(root) = self.verification.root {
            frame = frame.with_identity(root, self.verification.total_length, chunk_count);
        } else {
            // No generation root to bind to (a capsule fetch, which is self-verifying on install).
            // `chunk_count` exists to let a reader detect a wrong-generation or wrong-LAYOUT holder,
            // and dig-nat deliberately sets it only together with the root it is a fact about, so a
            // rootless frame states the one thing that is still true of it: the declared length.
            frame = frame.with_declared_length(self.verification.total_length);
        }
        if let Some(index) = chunk_index_at(self.verification.chunk_lens, start) {
            frame = frame.with_chunk_index(index);
        }

        if self.skip_layout {
            return frame;
        }
        // The prologue: at most one page per frame, and the proof exactly once. Both are
        // resource-scaling, so repeating either would spend the frame budget on bytes the reader
        // already holds — and at its 4,096 B cap a repeated proof alone would consume it.
        if let Some((offset, page)) = self.pending_pages.pop_front() {
            frame = frame.with_chunk_lens_page(offset, page);
        }
        if !self.proof_sent {
            if let Some(proof) = self.verification.inclusion_proof {
                frame = frame.with_inclusion_proof(proof);
                self.proof_sent = true;
            }
        }
        frame
    }

    /// The resource's total `chunk_lens` entry count — `1` for a resource that published no chunk
    /// table, which the wire has always treated as a single implicit chunk.
    fn chunk_count(&self) -> u64 {
        if self.verification.chunk_lens.is_empty() {
            1
        } else {
            self.verification.chunk_lens.len() as u64
        }
    }

    /// Whether the prologue still owes pages.
    ///
    /// A stream that ends here leaves the reader with a partial `chunk_lens`, which it MUST discard
    /// entirely: the array is a DECRYPT input whose entries must sum to `total_length`, so a layout
    /// short even one entry cannot decrypt the resource. The serve loop reports this rather than
    /// letting the reader discover it as an unexplained decrypt failure.
    pub(crate) fn prologue_pending(&self) -> bool {
        !self.pending_pages.is_empty()
    }
}

/// Write one range frame through dig-nat's own encoder.
///
/// The encoder is what makes an over-ceiling frame IMPOSSIBLE to emit rather than merely unlikely: it
/// refuses a payload over [`dig_nat::MAX_RANGE_FRAME_PAYLOAD`], a proof over
/// [`dig_nat::MAX_INCLUSION_PROOF_B64`], and any body over [`dig_nat::MAX_FRAMED_BODY`]. Every serve
/// path writes frames through here, so no path can regain the ability to produce something a
/// conforming receiver is required to reject.
pub(crate) async fn write_range_frame<W>(
    w: &mut W,
    frame: &dig_nat::RangeFrame,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::AsyncWriteExt as _;
    let bytes = frame.encode()?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Attach `verification` to a range `frame` whose window starts at absolute byte `start`.
///
/// The JSON-shaped counterpart of [`RangeStreamFramer::next_frame`], for the SINGLE-frame JSON-RPC
/// `dig.fetchRange` response — a JSON-RPC result rather than a length-prefixed wire frame, so it is
/// not bound by the framing ceiling and carries the whole layout on its one frame.
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
    // The reader sizes its layout array from `chunk_count` and uses it to tell a complete prologue
    // from a partial one, so it belongs on this frame too — a resource with no chunk table is one
    // implicit chunk.
    obj.insert(
        "chunk_count".into(),
        json!(if verification.chunk_lens.is_empty() {
            1
        } else {
            verification.chunk_lens.len() as u64
        }),
    );
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
