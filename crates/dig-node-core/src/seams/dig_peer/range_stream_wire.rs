//! Wire-level proof that this node can SERVE a conforming `dig.fetchRange` stream (#1668 / #1640).
//!
//! # Why these tests exist, and why they go over a socket
//!
//! Every other range-serve test in this crate inspects the `serde_json::Value` the serve path builds,
//! or streams into a [`tokio::io::sink`]. Both bypass the only component that enforces the wire's
//! ceilings — dig-nat's [`dig_nat::RangeFrame`] codec — so a serve path could frame a 3 MiB window
//! against a 32 KiB payload cap and every one of those tests would still pass. It did, and they did:
//! that is exactly how #1640 survived the whole suite it had.
//!
//! So these tests drive the REAL thing at every layer that could hide the defect:
//!
//! * the real [`NodeResponder`] serving from the node's real content cache,
//! * over a real loopback mTLS + yamux connection established by [`dig_nat::connect`],
//! * with the client decoding through the real [`dig_nat::RangeFrame::decode`], which REFUSES a body
//!   over [`dig_nat::MAX_FRAMED_BODY`] — so an over-ceiling frame fails the test rather than being
//!   quietly accepted by a permissive assertion, and
//! * over resources sized FROM dig-nat's published bounds (see
//!   [`oversized_served_resource`](crate::test_support::oversized_served_resource)), never under them.
//!
//! The assertion of record is that the reassembled ciphertext merkle-verifies to the generation root:
//! a reader that cannot fold the resource to its chain-anchored root has not read it, whatever the
//! frames looked like.
//!
//! # Which bound each fixture exercises, and which it deliberately does not
//!
//! Stating this is part of the test, because a fixture's SIZE is the whole difference between proving
//! a bound and confirming a coincidence:
//!
//! * [`a_resource_above_the_frame_ceiling_reads_and_verifies_over_the_real_wire`] exercises the
//!   **payload/body ceilings** ([`dig_nat::MAX_RANGE_FRAME_PAYLOAD`] and
//!   [`dig_nat::MAX_FRAMED_BODY`]). Its resource is far above both, and its layout is deliberately kept
//!   to a handful of chunks — well inside ONE prologue page. It is therefore also the shape a real
//!   dig-download reader can consume today: as of dig-download 0.12.0 the reader reassembles a
//!   single-page prologue only, and refuses a paged one rather than mis-reading it. The end-to-end read
//!   is the property being proven, so the fixture stays inside the reader's real capability.
//! * [`a_layout_needing_several_pages_is_paged_and_reassembles_completely`] and
//!   [`a_prologue_longer_than_the_requested_span_is_still_delivered_whole`] exercise
//!   [`dig_nat::MAX_CHUNK_LENS_PER_FRAME`] and the **paged prologue**, which is a SERVE-side obligation.
//!   They are proven against dig-nat's own codec, and the reader here is this module's own reassembler
//!   (which implements the §5.1.1 placement rules). They are NOT claims about dig-download, which
//!   cannot yet reassemble a paged prologue — a holder must nonetheless page correctly, because a
//!   layout over the per-frame entry cap has no other conforming representation, and emitting it on one
//!   frame produces a body no receiver may accept.
//!
//! Every count asserted below is a STRUCTURAL quantity — frames, pages, page offsets, exact byte
//! equality, a merkle fold — never a byte or fetch total standing in for one. An aggregate count
//! answers "how much happened", not "did THIS happen", and a guard built on one can pass identically
//! against the code it was written to catch.

use std::sync::Arc;
use std::time::Duration;

use crate::peer::{
    install_crypto_provider, load_or_generate_node_cert, serve_peer_rpc_listener, NodeResponder,
    PeerRpcResponder,
};
use crate::test_support::{oversized_served_resource, seed_served_resource};

/// A deterministic 32-byte identity seed from a label — never an integer literal, which CodeQL
/// correctly flags as hard-coded key material in crypto tests.
fn node_seed(label: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(label.as_bytes()).into()
}

/// Everything a client needs to talk to a live loopback holder: the open connection and the
/// `(store, root, retrieval_key)` triple naming the seeded resource.
struct Holder {
    conn: dig_nat::PeerConnection,
    ids: (String, String, String),
    /// The exact ciphertext the holder was seeded with — the reader's answer must equal it.
    ciphertext: Vec<u8>,
    /// The resource's real chunk layout, so a test can assert the served layout is the true one.
    chunk_lens: Vec<u64>,
    /// The generation root the resource is committed under (64-hex).
    root: String,
    /// Kept alive for the duration of the test: the listener task and the node's temp cache dir.
    _server: tokio::task::JoinHandle<Result<(), String>>,
    _cache: tempfile::TempDir,
}

/// Stand up a real node holding `resource`, serve its real `NodeResponder` on a loopback mTLS
/// listener, and dial it as a peer would — the honest reader↔holder wire.
async fn holder_serving(
    label: &str,
    frame_payloads: usize,
    tail: usize,
    chunk_len: usize,
) -> Holder {
    install_crypto_provider();
    let (resource, chunk_lens) = oversized_served_resource(frame_payloads, tail, chunk_len);
    let ciphertext = resource.ciphertext.clone();
    let root = resource.roothash.to_hex();

    let (node, cache) = crate::test_support::test_node_for_peer_surface();
    let ids = seed_served_resource(&node, resource);

    let server_dir = tempfile::tempdir().expect("server cert dir");
    let server_identity =
        load_or_generate_node_cert(server_dir.path(), &node_seed(&format!("{label}-holder")))
            .expect("holder identity");
    let server_peer_id = server_identity.peer_id();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let addr = listener.local_addr().expect("listener addr");
    let responder: Arc<dyn PeerRpcResponder> = Arc::new(NodeResponder::without_pool(node));
    let server = tokio::spawn(serve_peer_rpc_listener(
        listener,
        server_identity,
        responder,
    ));

    let client_dir = tempfile::tempdir().expect("client cert dir");
    let client_identity =
        load_or_generate_node_cert(client_dir.path(), &node_seed(&format!("{label}-reader")))
            .expect("reader identity");
    let target = dig_nat::PeerTarget::with_addr(server_peer_id, addr, "DIG_MAINNET");
    let config = dig_nat::NatConfig::builder()
        .enabled_methods(vec![dig_nat::TraversalKind::Direct])
        .per_method_timeout(Duration::from_secs(10))
        .build();
    let conn = dig_nat::connect(&target, &client_identity, &config)
        .await
        .await_ok();

    Holder {
        conn,
        ids,
        ciphertext,
        chunk_lens,
        root,
        _server: server,
        _cache: cache,
    }
}

/// `expect` with a message naming the failure mode, so a broken handshake is not reported as a
/// framing bug.
trait AwaitOk<T> {
    fn await_ok(self) -> T;
}
impl<T, E: std::fmt::Debug> AwaitOk<T> for Result<T, E> {
    fn await_ok(self) -> T {
        self.expect("the reader must establish an mTLS peer connection to the holder")
    }
}

/// What one range stream delivered, reassembled by the reader exactly as dig-download would.
struct StreamedRead {
    /// The reassembled ciphertext, placed by each frame's `offset`.
    bytes: Vec<u8>,
    /// Every frame the holder wrote, in arrival order.
    frames: Vec<dig_nat::RangeFrame>,
}

impl StreamedRead {
    /// The `chunk_lens` array reassembled from the stream's prologue pages, or `None` if the prologue
    /// never completed.
    ///
    /// Mirrors what a reader must do and MUST refuse to do: a page is placed at its stated
    /// `chunk_lens_offset`, and a prologue that ends short of `chunk_count` yields NO array at all.
    /// `chunk_lens` is a DECRYPT input — per-chunk AES-GCM-SIV needs the whole array, summing to the
    /// ciphertext length — so a partial layout is unusable rather than partially useful.
    fn reassembled_chunk_lens(&self) -> Option<Vec<u64>> {
        let count = self.frames.first()?.chunk_count? as usize;
        let mut out = vec![None; count];
        for frame in &self.frames {
            let Some(page) = frame.chunk_lens.as_ref() else {
                continue;
            };
            let offset = frame.chunk_lens_offset.unwrap_or(0) as usize;
            for (slot, &len) in out.iter_mut().skip(offset).zip(page) {
                *slot = Some(len);
            }
        }
        out.into_iter().collect()
    }
}

/// Read `[offset, offset+length)` from `holder` the way a peer does: open a range stream, decode
/// frames through the REAL codec until `complete`, and place each frame's bytes at its own offset.
async fn read_range(
    holder: &mut Holder,
    offset: u64,
    length: u64,
    skip_layout: bool,
) -> std::io::Result<StreamedRead> {
    let (store, root, rk) = holder.ids.clone();
    let mut request = dig_nat::RangeRequest::resource(store, rk, offset, length).with_root(root);
    if skip_layout {
        request = request.with_skip_layout(true);
    }
    let mut stream = holder
        .conn
        .session
        .open_range_stream(&request)
        .await
        .expect("the holder accepts a range stream");

    let mut read = StreamedRead {
        bytes: vec![0u8; length as usize],
        frames: Vec::new(),
    };
    let mut filled = 0usize;
    // Bounded by the frames a conforming stream could possibly need, so a holder that never sets
    // `complete` fails the test instead of hanging it — silence and endlessness are the cheapest
    // adversarial claims, and a test that loops forever on them reports nothing at all.
    let max_frames = (length as usize / dig_nat::MAX_RANGE_FRAME_PAYLOAD) + 4;
    while read.frames.len() <= max_frames {
        let Some(frame) = dig_nat::RangeFrame::decode(&mut stream).await? else {
            // Clean end-of-stream. `complete` means "the RESOURCE is exhausted", so a request for a
            // sub-span legitimately ends without it — the holder simply stops once the span is served.
            // Accept that ONLY when the span is genuinely full; a stream that ends short is a failure,
            // never a short read silently treated as success.
            if filled == length as usize {
                return Ok(read);
            }
            break;
        };
        let start = (frame.offset - offset) as usize;
        let end = start + frame.bytes.len();
        assert!(
            end <= read.bytes.len(),
            "a frame must not overrun the requested span: {start}..{end} of {}",
            read.bytes.len()
        );
        read.bytes[start..end].copy_from_slice(&frame.bytes);
        filled += frame.bytes.len();
        let complete = frame.complete;
        read.frames.push(frame);
        if complete {
            read.bytes.truncate(filled.min(read.bytes.len()));
            return Ok(read);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "the holder never completed the stream ({} frames, {filled} of {length} bytes)",
            read.frames.len()
        ),
    ))
}

/// Fold `ciphertext` to `root` through the frame's own inclusion proof — the check that decides
/// whether bytes were genuinely READ, as opposed to merely received.
fn merkle_verifies(ciphertext: &[u8], proof_b64: &str, root_hex: &str) -> bool {
    use base64::Engine as _;
    use digstore_core::codec::Decode as _;
    let Ok(proof_bytes) = base64::engine::general_purpose::STANDARD.decode(proof_b64) else {
        return false;
    };
    let Ok(proof) = digstore_core::MerkleProof::from_bytes(&proof_bytes) else {
        return false;
    };
    proof.leaf.0 == digstore_core::merkle::resource_leaf(ciphertext).0
        && proof.verify()
        && proof.root.to_hex() == root_hex
}

// -- the acceptance test of #1668 step 3 ------------------------------------------------------------

/// **Proves:** a resource LARGER than the wire's frame ceiling reads end-to-end over the real
/// reader↔holder wire and merkle-verifies to its chain-anchored generation root.
///
/// **Catches:** the #1640 defect this test was written against — a serve path that frames on the
/// per-REQUEST window (`RANGE_WINDOW`, 3 MiB) instead of the per-FRAME payload cap
/// (`MAX_RANGE_FRAME_PAYLOAD`, 32 KiB). Such a holder writes one ~220 KB body, and
/// `RangeFrame::decode` refuses any body over `MAX_FRAMED_BODY`, so the read fails outright: no
/// holder in the network can satisfy a read above ~48 KiB. It is the ONLY test here that would not
/// pass against a single-frame serve, which is why it is the acceptance bar for the step.
#[tokio::test]
async fn a_resource_above_the_frame_ceiling_reads_and_verifies_over_the_real_wire() {
    // Five full payloads plus a short tail: over MAX_FRAMED_BODY, and impossible to serve as one
    // frame. The 24 KiB chunk size keeps the layout to 7 entries — far inside one prologue page — so
    // this fixture exercises the FRAME ceiling and nothing else, and stays within what a real
    // dig-download reader can consume (single-page prologue only, as of 0.12.0). The paging bound has
    // its own fixtures; see the module docs.
    let mut holder = holder_serving("above-ceiling", 5, 777, 24_576).await;
    let total = holder.ciphertext.len() as u64;

    let read = read_range(&mut holder, 0, total, false)
        .await
        .expect("a conforming holder streams a resource above the frame ceiling");

    // 1. The bytes are the holder's bytes, in the right order.
    assert_eq!(
        read.bytes, holder.ciphertext,
        "the reassembled ciphertext must be byte-identical to the served resource"
    );

    // 2. Every frame obeyed the payload ceiling — the property the old framing violated.
    for frame in &read.frames {
        assert!(
            frame.bytes.len() <= dig_nat::MAX_RANGE_FRAME_PAYLOAD,
            "a frame carried {} bytes, over MAX_RANGE_FRAME_PAYLOAD {}",
            frame.bytes.len(),
            dig_nat::MAX_RANGE_FRAME_PAYLOAD
        );
    }

    // 3. It genuinely took MORE THAN ONE frame. Without this a future regression that raised the
    //    ceiling, or a fixture that shrank under it, would keep every other assertion green.
    assert!(
        read.frames.len() > 1,
        "a resource of {total} B must be tiled into several frames, got {}",
        read.frames.len()
    );

    // 4. The fixed identity set rides EVERY frame, not just the first — that is what lets a reader
    //    reject a wrong-generation holder on arrival rather than after paying for the whole resource.
    for (index, frame) in read.frames.iter().enumerate() {
        assert_eq!(
            frame.root.as_deref(),
            Some(holder.root.as_str()),
            "frame {index} declared no/!= root"
        );
        assert_eq!(
            frame.total_length,
            Some(total),
            "frame {index} declared no/!= total_length"
        );
        assert_eq!(
            frame.chunk_count,
            Some(holder.chunk_lens.len() as u64),
            "frame {index} declared no/!= chunk_count"
        );
    }

    // 5. The resource-scaling prologue was sent ONCE, and the layout it delivered is the true one.
    let proofs = read
        .frames
        .iter()
        .filter(|f| f.inclusion_proof.is_some())
        .count();
    assert_eq!(proofs, 1, "the inclusion proof must ride exactly one frame");
    assert_eq!(
        read.reassembled_chunk_lens(),
        Some(holder.chunk_lens.clone()),
        "the stream must deliver the resource's real chunk layout, complete"
    );

    // 6. THE assertion of record: the bytes fold to the chain-anchored root.
    let proof = read
        .frames
        .iter()
        .find_map(|f| f.inclusion_proof.clone())
        .expect("the stream carries an inclusion proof");
    assert!(
        merkle_verifies(&read.bytes, &proof, &holder.root),
        "the reassembled resource must merkle-verify to its generation root"
    );
}

/// **Proves:** a layout too large to state on one frame is delivered as a PAGED prologue whose pages
/// tile the array exactly, and the reader reassembles the complete `chunk_lens`.
///
/// **Catches:** a sender that puts the whole array on the first frame (which then exceeds the body
/// ceiling and cannot be decoded at all), and — via the per-page shape assertions — a sender whose
/// pages are empty or short-in-the-middle. Those two are called out separately in dig-nat's
/// `SPEC.md` §5.1.1 because a guard aimed at a short LAST page is bypassed by a short MIDDLE one.
///
/// The chunk count is chosen to force at least THREE pages, so a genuine middle page exists: with two
/// pages every page is either the first or the tail, and "no short non-tail page" is then vacuously
/// true — a two-page fixture cannot see the defect.
#[tokio::test]
async fn a_layout_needing_several_pages_is_paged_and_reassembles_completely() {
    let mut holder = holder_serving("paged-prologue", 6, 777, 40).await;
    let chunks = holder.chunk_lens.len();
    let expected_pages = chunks.div_ceil(dig_nat::MAX_CHUNK_LENS_PER_FRAME);
    assert!(
        expected_pages >= 3,
        "the fixture must need a MIDDLE page to be able to detect a short non-tail page, \
         got {chunks} chunks in {expected_pages} page(s)"
    );

    let total = holder.ciphertext.len() as u64;
    let read = read_range(&mut holder, 0, total, false)
        .await
        .expect("a conforming holder pages a large layout across frames");

    assert_eq!(read.bytes, holder.ciphertext);

    let pages: Vec<(u64, usize)> = read
        .frames
        .iter()
        .filter_map(|f| {
            f.chunk_lens
                .as_ref()
                .map(|p| (f.chunk_lens_offset.unwrap_or(0), p.len()))
        })
        .collect();
    assert_eq!(
        pages.len(),
        expected_pages,
        "the prologue must be split into exactly the pages the array needs: {pages:?}"
    );
    for (position, &(offset, len)) in pages.iter().enumerate() {
        assert_ne!(len, 0, "page at {offset} is EMPTY");
        assert!(
            len <= dig_nat::MAX_CHUNK_LENS_PER_FRAME,
            "page at {offset} carries {len} entries, over MAX_CHUNK_LENS_PER_FRAME"
        );
        assert_eq!(
            offset as usize,
            position * dig_nat::MAX_CHUNK_LENS_PER_FRAME,
            "page {position} must begin on a page-aligned entry index"
        );
        // Every page but the tail is exactly full: a short non-tail page leaves a gap that no
        // page-aligned page can ever fill.
        if position + 1 < pages.len() {
            assert_eq!(
                len,
                dig_nat::MAX_CHUNK_LENS_PER_FRAME,
                "non-tail page {position} is short, leaving an unfillable gap"
            );
        }
    }

    assert_eq!(
        read.reassembled_chunk_lens(),
        Some(holder.chunk_lens.clone()),
        "the paged prologue must reassemble into the resource's real layout"
    );
}

/// **Proves:** a stream whose prologue needs MORE frames than its bytes do still delivers the whole
/// layout — the holder keeps emitting pages after the requested bytes are exhausted, and does not mark
/// the stream `complete` until the last page has gone out.
///
/// **Catches:** setting `complete` as soon as the BYTES are done. A conforming reader stops on
/// `complete`, so it would stop holding a partial `chunk_lens` — and `chunk_lens` is a DECRYPT input
/// whose entries must sum to `total_length`, making a layout short even one entry unusable rather than
/// partially useful. The read would fail later, at decrypt, with nothing pointing back here.
///
/// This case needs its own fixture because the other paged test CANNOT exhibit it: there, six data
/// frames carry three pages, so the prologue is long finished before the last frame and withholding
/// `complete` changes nothing observable. Only a span SMALLER than the prologue separates the two
/// behaviours — one data frame, three pages.
#[tokio::test]
async fn a_prologue_longer_than_the_requested_span_is_still_delivered_whole() {
    let mut holder = holder_serving("prologue-outlives-span", 6, 777, 40).await;
    let pages = holder
        .chunk_lens
        .len()
        .div_ceil(dig_nat::MAX_CHUNK_LENS_PER_FRAME);
    assert!(
        pages > 1,
        "the fixture must need more than one page for the span to be the shorter of the two"
    );

    // One byte: fewer data frames than the prologue has pages, by construction.
    let read = read_range(&mut holder, 0, 1, false)
        .await
        .expect("the holder finishes the prologue even after the bytes run out");

    assert_eq!(read.bytes, holder.ciphertext[..1]);
    assert!(
        read.frames.len() >= pages,
        "the stream must carry at least one frame per page, got {} frame(s) for {pages} page(s)",
        read.frames.len()
    );
    assert_eq!(
        read.reassembled_chunk_lens(),
        Some(holder.chunk_lens.clone()),
        "a one-byte request must still yield the COMPLETE layout, never a partial one"
    );
    // No frame claims the resource is exhausted: a one-byte read of a large resource is not complete,
    // and the reader stops on its own span accounting instead.
    assert!(
        read.frames.iter().all(|f| !f.complete),
        "a sub-span read must not be marked complete"
    );
}

/// **Proves:** every frame's declared `length` equals its own payload, and the identity set is present
/// on EVERY frame — including the rootless branch, where no builder can set `total_length`.
///
/// **Catches:** calling `RangeFrame::with_declared_length` in the belief that it sets `total_length`.
/// It does not; it overrides `length`, the frame's OWN payload length, and dig-nat documents that a
/// serve path has no reason to call it because a frame whose `length` disagrees with its payload is one
/// the reader distrusts. The mistake is invisible to a test that never compares the two — neither
/// `dig_nat::decode_framed_opt` nor this node's own puller validates the relation — and it is worse than
/// a wrong number: `ResourceCommitment::check_consistent` is written `if let Some(..)`, so an ABSENT
/// `total_length`/`root` SKIPS the wrong-generation check rather than failing it. Omitting the field
/// silently disables the gate.
///
/// The rootless branch is reached with a `FetchedResource` carrying no `root`, which is what the
/// fetch-through serve path hands over when the engine reported none.
#[tokio::test]
async fn every_frame_declares_its_own_payload_length_and_the_identity_set() {
    use crate::peer::stream_fetched_range;

    let (resource, chunk_lens) = oversized_served_resource(3, 511, 24_576);
    let total = resource.ciphertext.len() as u64;

    // A rootless fetched resource: `root` and `inclusion_proof` are None, so `next_frame` takes the
    // branch that cannot use `with_identity`.
    let fetched = crate::download::FetchedResource {
        bytes: resource.ciphertext.clone(),
        total_length: total,
        chunk_lens: chunk_lens.clone(),
        root: None,
        inclusion_proof: None,
    };

    let (client, server) = tokio::io::duplex(1 << 20);
    let mut out = server;
    let charged = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let sink = charged.clone();
    let streamed = stream_fetched_range(
        &mut out,
        &fetched,
        crate::peer::RangeStreamPlan {
            offset: 0,
            requested_end: total as usize,
            skip_layout: false,
            limiter: None,
            conn_key: "reader",
            egress: &move |n| sink.lock().unwrap().push(n),
        },
    )
    .await
    .expect("the rootless path streams");
    drop(out);

    let mut reader = client;
    let mut frames = Vec::new();
    while let Some(frame) = dig_nat::RangeFrame::decode(&mut reader)
        .await
        .expect("every frame decodes")
    {
        frames.push(frame);
    }
    assert!(
        frames.len() > 1,
        "a multi-frame stream, got {}",
        frames.len()
    );
    assert_eq!(frames.len() as u64, streamed.frames);

    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(
            frame.length,
            frame.bytes.len() as u64,
            "frame {index} declares length {} over a {}-byte payload",
            frame.length,
            frame.bytes.len()
        );
        assert_eq!(
            frame.total_length,
            Some(total),
            "frame {index} must state total_length even with no root — an absent field SKIPS the \
             reader's consistency check rather than failing it"
        );
        assert_eq!(
            frame.chunk_count,
            Some(chunk_lens.len() as u64),
            "frame {index} must state chunk_count"
        );
    }

    // Egress is charged per frame, on the ENCODED size, before each write.
    let charged = charged.lock().unwrap().clone();
    assert_eq!(
        charged.len(),
        frames.len(),
        "every frame must be charged exactly once"
    );
    assert!(
        charged.iter().all(|&n| n > 0),
        "no frame may be charged zero: {charged:?}"
    );
    assert_eq!(charged.iter().sum::<u64>(), streamed.encoded_bytes);
}

/// **Proves:** a prologue page riding a ZERO-payload frame is still charged its real wire cost.
///
/// **Catches:** charging the throttles the payload length. Once the requested span is served the
/// payload is empty while the frame still carries a full ~14 KB `chunk_lens` page, so a payload-based
/// debit scores it as free. A peer asks for exactly this by requesting one byte and simply NOT setting
/// `skip_layout` — it is a client-set flag — turning a ~200-byte request into a large unaccounted serve.
#[tokio::test]
async fn a_zero_payload_prologue_frame_is_still_charged_its_wire_cost() {
    use crate::peer::stream_fetched_range;

    // Many small chunks so the prologue needs several pages, and a one-byte span so all but the first
    // page rides a zero-payload frame.
    let (resource, chunk_lens) = oversized_served_resource(6, 777, 40);
    let pages = chunk_lens.len().div_ceil(dig_nat::MAX_CHUNK_LENS_PER_FRAME);
    assert!(pages >= 3, "need a middle page; got {pages}");

    let fetched = crate::download::FetchedResource {
        bytes: resource.ciphertext.clone(),
        total_length: resource.ciphertext.len() as u64,
        chunk_lens,
        root: None,
        inclusion_proof: None,
    };

    let charged = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let sink = charged.clone();
    let mut out = tokio::io::sink();
    let streamed = stream_fetched_range(
        &mut out,
        &fetched,
        crate::peer::RangeStreamPlan {
            offset: 0,
            requested_end: 1,
            skip_layout: false,
            limiter: None,
            conn_key: "reader",
            egress: &move |n| sink.lock().unwrap().push(n),
        },
    )
    .await
    .expect("streamed");

    let charged = charged.lock().unwrap().clone();
    assert_eq!(charged.len(), pages, "one frame per owed page: {charged:?}");
    // One payload byte in total, yet every frame costs real bytes on the wire.
    assert_eq!(streamed.bytes, 1);
    assert!(
        charged.iter().all(|&n| n > 1_000),
        "each page frame costs kilobytes and must be charged as such: {charged:?}"
    );
    assert!(
        streamed.encoded_bytes > 10_000,
        "a one-byte request that pulls a paged prologue is a real serve, charged {} bytes",
        streamed.encoded_bytes
    );
}

/// **Proves:** `skip_layout` suppresses the resource-scaling set (`chunk_lens` + `inclusion_proof`)
/// while the fixed identity set still rides every frame, and the bytes still read correctly.
///
/// **Catches:** a holder that ignores the flag (costing a re-sent paged prologue on every parallel
/// or resumed stream), and — more importantly — one that "honours" it by suppressing the IDENTITY
/// fields too, which would silently remove the reader's only means of detecting a wrong-generation
/// holder on arrival.
#[tokio::test]
async fn skip_layout_suppresses_only_the_resource_scaling_metadata() {
    let mut holder = holder_serving("skip-layout", 5, 777, 24_576).await;
    let total = holder.ciphertext.len() as u64;

    let read = read_range(&mut holder, 0, total, true)
        .await
        .expect("a holder honouring skip_layout still streams the bytes");

    assert_eq!(read.bytes, holder.ciphertext);
    assert!(read.frames.len() > 1, "still a multi-frame read");
    for (index, frame) in read.frames.iter().enumerate() {
        assert!(
            frame.chunk_lens.is_none(),
            "frame {index} re-sent chunk_lens despite skip_layout"
        );
        assert!(
            frame.inclusion_proof.is_none(),
            "frame {index} re-sent the inclusion proof despite skip_layout"
        );
        // The identity set is NOT suppressed: it is what detects a wrong-generation holder, and it is
        // fixed-size, so there is never a bandwidth reason to drop it.
        assert_eq!(frame.root.as_deref(), Some(holder.root.as_str()));
        assert_eq!(frame.total_length, Some(total));
        assert_eq!(frame.chunk_count, Some(holder.chunk_lens.len() as u64));
    }
}

/// **Proves:** a request for a span far smaller than the resource is answered with exactly that span,
/// still framed within the ceiling.
///
/// **Catches:** the inverse of the ceiling bug — a serve loop that, having been taught to tile,
/// streams the whole resource off a small probe (#1619). Both defects live in the same loop, so both
/// bounds are pinned here.
#[tokio::test]
async fn a_short_request_is_answered_with_exactly_that_span() {
    let mut holder = holder_serving("short-span", 5, 777, 24_576).await;
    // Deliberately just over ONE payload, so the answer must be two frames and neither the request
    // nor the resource length can be mistaken for the other.
    let span = dig_nat::MAX_RANGE_FRAME_PAYLOAD as u64 + 100;

    let read = read_range(&mut holder, 0, span, false)
        .await
        .expect("the holder answers a sub-resource span");

    assert_eq!(
        read.bytes.len() as u64,
        span,
        "the holder must serve the requested span, not the whole resource"
    );
    assert_eq!(read.bytes, holder.ciphertext[..span as usize]);
    for frame in &read.frames {
        assert!(frame.bytes.len() <= dig_nat::MAX_RANGE_FRAME_PAYLOAD);
    }
}
