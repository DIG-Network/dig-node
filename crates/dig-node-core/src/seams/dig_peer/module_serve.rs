//! The SERVE half of the whole-`.dig`-module pull (#1576): answering `dig.getModuleInfo` and
//! `dig.fetchModuleRange` from a capsule this node holds.
//!
//! A holder answers two questions. `getModuleInfo` describes the module — its size, its content id, and
//! the per-chunk hashes the puller attributes each range against. `fetchModuleRange` serves a window of
//! it. Together they let a reader pull the ENTIRE capsule and become a resharer of it, which is what
//! makes the network's copy count grow with every read.
//!
//! # Chunking is chosen so the DESCRIPTOR fits one control frame
//!
//! The descriptor is one framed JSON response, and the peer control framing caps a frame at 64 KiB. Each
//! chunk costs ~75 bytes of descriptor (a 64-hex hash plus a length), so a fixed small chunk size would
//! make a large capsule's descriptor exceed the cap and become unanswerable — the module would be
//! undiscoverable through a limit that has nothing to do with its content.
//!
//! So the chunk size SCALES with the module: at least [`MIN_CHUNK_SIZE`], and always large enough to
//! keep the chunk count at or under [`MAX_DESCRIPTOR_CHUNKS`]. The chunk count is therefore bounded by
//! construction, which bounds the descriptor — rather than by a check that would have to reject an
//! otherwise-servable capsule.
//!
//! # What a serve MUST NOT decide
//!
//! Nothing here is a trust decision. The bytes are content-addressed and the puller re-checks all of
//! them against the chain anchor, so this side's only job is to answer accurately about content it
//! actually holds — and to say so plainly when it does not.

use std::path::{Path, PathBuf};

use dig_rpc_protocol::types::ModuleInfo;
use serde_json::{json, Value};

use super::module_anchor::sha256;

/// The smallest chunk a descriptor will declare (1 MiB).
///
/// Chunks are the pull's parallelism + re-fetch granularity, so smaller is better for spreading a pull
/// across holders — but each one costs descriptor bytes. 1 MiB keeps a typical capsule's descriptor to a
/// few hundred bytes while still splitting a large module into enough pieces to fan out.
pub const MIN_CHUNK_SIZE: u64 = 1024 * 1024;

/// The most chunks a descriptor will declare, so it always fits one 64 KiB control frame.
///
/// At ~75 descriptor bytes per chunk (a 64-hex hash + a length + JSON punctuation), 512 chunks is ~38 KB
/// — comfortably inside the cap with room for the rest of the envelope.
pub const MAX_DESCRIPTOR_CHUNKS: u64 = 512;

/// The largest window one `fetchModuleRange` request will be served, so a single request cannot make
/// this node read and frame an unbounded amount of a module.
pub const MAX_MODULE_WINDOW: u64 = 4 * 1024 * 1024;

/// The chunk size a module of `total_size` bytes is described in.
///
/// Scales up so the chunk count never exceeds [`MAX_DESCRIPTOR_CHUNKS`] (see the module docs). Returns
/// at least 1 so a non-empty module always has at least one chunk.
pub fn chunk_size_for(total_size: u64) -> u64 {
    let by_cap = total_size.div_ceil(MAX_DESCRIPTOR_CHUNKS.max(1));
    MIN_CHUNK_SIZE.max(by_cap).max(1)
}

/// The `.dig` module path for `(store_hex, root_hex)` under `cache_dir` — the same layout the local
/// serve path reads, so a module this node can serve resources from is a module it can also reshare.
fn module_path(cache_dir: &Path, store_hex: &str, root_hex: &str) -> PathBuf {
    cache_dir
        .join("modules")
        .join(store_hex)
        .join(format!("{root_hex}.module"))
}

/// Build the [`ModuleInfo`] descriptor for a locally-held capsule, or `None` if this node does not hold
/// it (or the ids are not canonical).
///
/// Blocking file I/O — call from `spawn_blocking`, like the rest of the module-reading serve path.
pub fn describe_module(cache_dir: &Path, store_hex: &str, root_hex: &str) -> Option<ModuleInfo> {
    if !is_canonical(store_hex) || !is_canonical(root_hex) {
        return None;
    }
    let bytes = std::fs::read(module_path(cache_dir, store_hex, root_hex)).ok()?;
    if bytes.is_empty() {
        // A 0-byte file is not a module. Describing it would produce a descriptor whose hash gates all
        // PASS (sha256 of no bytes is a real digest), leaving the puller's anchor gate as the only thing
        // between a truncated local file and a peer caching it — so refuse at the source instead.
        return None;
    }
    let chunk = chunk_size_for(bytes.len() as u64) as usize;
    Some(ModuleInfo {
        total_size: bytes.len() as u64,
        module_hash: hex32(&sha256(&bytes)),
        chunk_hashes: bytes.chunks(chunk).map(|c| hex32(&sha256(c))).collect(),
        chunk_lens: bytes.chunks(chunk).map(|c| c.len() as u64).collect(),
    })
}

/// Read the `[offset, offset+length)` window of a locally-held module.
///
/// Returns `None` when the module is not held. An offset at or past the end yields an EMPTY window
/// rather than an error: the window is a byte range over a content-addressed blob, and the caller's own
/// chunk-hash check is what decides whether what arrived is what it asked for.
///
/// `length` is clamped to [`MAX_MODULE_WINDOW`] — a serve never lets one request size its own work.
pub fn read_module_window(
    cache_dir: &Path,
    store_hex: &str,
    root_hex: &str,
    offset: u64,
    length: u64,
) -> Option<Vec<u8>> {
    if !is_canonical(store_hex) || !is_canonical(root_hex) {
        return None;
    }
    let bytes = std::fs::read(module_path(cache_dir, store_hex, root_hex)).ok()?;
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let want = usize::try_from(length.min(MAX_MODULE_WINDOW)).unwrap_or(usize::MAX);
    let end = start.saturating_add(want).min(bytes.len());
    Some(bytes[start..end].to_vec())
}

/// One `RangeFrame`-shaped response frame for a module window, in the SAME wire shape
/// `dig.fetchRange` frames use (the puller decodes both with `dig_nat::RangeFrame`).
///
/// `total_length` is carried on the first frame only, matching the range contract. No inclusion proof is
/// attached: a whole `.dig` is self-verifying on assembly (its committed root is inside it), which is
/// why the puller's gate is the chain anchor rather than a per-frame proof.
pub fn module_frame(offset: u64, bytes: &[u8], complete: bool, total_length: Option<u64>) -> Value {
    let mut frame = json!({
        "offset": offset,
        "length": bytes.len() as u64,
        "bytes": base64_encode(bytes),
        "complete": complete,
    });
    if let Some(total) = total_length {
        frame["total_length"] = json!(total);
    }
    frame
}

/// The JSON-RPC-shaped error frame a module serve answers with when it holds nothing to serve.
///
/// Names the outcome in the node's own vocabulary; it never echoes the caller's ids back into a message
/// (the log's sentinel is where ids are rendered, #1603).
pub fn module_unavailable_frame(code: i64) -> Value {
    json!({"error": {"code": code, "message": "this node does not hold the requested .dig module"}})
}

/// Whether `id` is a canonical 64-hex content id — the only shape that can name real content.
fn is_canonical(id: &str) -> bool {
    crate::is_canonical_hex_id(id)
}

/// Lower-case hex of 32 raw bytes.
fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Standard base64 of `bytes` — the canonical `RangeFrame::bytes` wire encoding.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// -- Serve observability (#1595 vocabulary, extended to the module methods) ---------------------------

/// Record an inbound module-descriptor request and its outcome (INFO), so "was this holder asked, and
/// what did it answer?" is one grep away — the question that stayed ambiguous for many rounds of the
/// read-leg bring-up.
pub(crate) fn module_info_answered(
    peer: &str,
    store_hex: &str,
    root_hex: &str,
    info: Option<&ModuleInfo>,
) {
    match info {
        Some(info) => tracing::info!(
            peer_id = %super::serve_log::SafeId::new(peer),
            store_id = %super::serve_log::SafeId::new(store_hex),
            root = %super::serve_log::SafeId::new(root_hex),
            total_size = info.total_size,
            chunks = info.chunk_hashes.len(),
            outcome = %"described",
            "peer serve: dig.getModuleInfo answered"
        ),
        None => tracing::info!(
            peer_id = %super::serve_log::SafeId::new(peer),
            store_id = %super::serve_log::SafeId::new(store_hex),
            root = %super::serve_log::SafeId::new(root_hex),
            outcome = %"not-held",
            "peer serve: dig.getModuleInfo refused"
        ),
    }
}

/// Record an inbound module-range request as it arrives (DEBUG) — the detail behind the INFO outcome.
pub(crate) fn module_range_requested(
    peer: &str,
    store_hex: &str,
    root_hex: &str,
    offset: u64,
    length: u64,
) {
    tracing::debug!(
        peer_id = %super::serve_log::SafeId::new(peer),
        store_id = %super::serve_log::SafeId::new(store_hex),
        root = %super::serve_log::SafeId::new(root_hex),
        offset,
        length,
        "peer serve: dig.fetchModuleRange received"
    );
}

/// Record how an inbound module-range request ended (INFO). `offset` is always the offset the CALLER
/// REQUESTED, so the one outcome line per request keys to the request a harness greps for.
pub(crate) fn module_range_outcome(
    peer: &str,
    store_hex: &str,
    root_hex: &str,
    offset: u64,
    served: Option<(u64, u64)>,
) {
    match served {
        Some((bytes, frames)) => tracing::info!(
            peer_id = %super::serve_log::SafeId::new(peer),
            store_id = %super::serve_log::SafeId::new(store_hex),
            root = %super::serve_log::SafeId::new(root_hex),
            offset,
            served_bytes = bytes,
            frames,
            outcome = %"served",
            "peer serve: dig.fetchModuleRange served"
        ),
        None => tracing::info!(
            peer_id = %super::serve_log::SafeId::new(peer),
            store_id = %super::serve_log::SafeId::new(store_hex),
            root = %super::serve_log::SafeId::new(root_hex),
            offset,
            outcome = %"not-held",
            "peer serve: dig.fetchModuleRange refused"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_id(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Write `bytes` as the cached module for `(store, root)` under a fresh temp cache dir.
    fn cache_with(bytes: &[u8], store: &str, root: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-modserve-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = module_path(&dir, store, root);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        dir
    }

    /// **Proves:** the descriptor describes the held module exactly — its size, its whole-blob content
    /// id, and per-chunk hashes/lengths that cover every byte and sum to `total_size`. A puller
    /// attributes ranges against these, so a descriptor that did not cover the blob would make every
    /// pull fail its chunk check with no discoverable cause.
    #[test]
    fn describes_a_held_module_exactly() {
        let (store, root) = (hex_id(1), hex_id(2));
        let bytes: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let dir = cache_with(&bytes, &store, &root);

        let info = describe_module(&dir, &store, &root).expect("held");
        assert_eq!(info.total_size, bytes.len() as u64);
        assert_eq!(info.module_hash, hex32(&sha256(&bytes)));
        assert_eq!(info.chunk_lens.iter().sum::<u64>(), info.total_size);
        assert_eq!(info.chunk_hashes.len(), info.chunk_lens.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a module this node does not hold is reported as not-held, rather than described as
    /// empty — a described-but-absent module would advertise a capsule this node cannot serve.
    #[test]
    fn an_unheld_module_is_not_described() {
        let dir = cache_with(b"x", &hex_id(1), &hex_id(2));
        assert!(describe_module(&dir, &hex_id(9), &hex_id(9)).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a 0-byte local file is NOT described.
    /// **Catches:** describing it, which yields a descriptor whose per-chunk AND whole-blob hash gates
    /// both pass trivially (`sha256("")` is a real digest) — leaving the puller's anchor gate as the only
    /// thing between one truncated local file and peers caching it.
    #[test]
    fn an_empty_module_file_is_not_described() {
        let (store, root) = (hex_id(3), hex_id(4));
        let dir = cache_with(b"", &store, &root);
        assert!(describe_module(&dir, &store, &root).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a non-canonical id is refused rather than turned into a filesystem path — a store id
    /// that reached `Path::join` would be a path-traversal primitive.
    #[test]
    fn a_non_canonical_id_never_reaches_the_filesystem() {
        let dir = cache_with(b"x", &hex_id(1), &hex_id(2));
        assert!(describe_module(&dir, "../../etc", &hex_id(2)).is_none());
        assert!(read_module_window(&dir, "../../etc", &hex_id(2), 0, 16).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** the chunk count stays within the descriptor cap however large the module is, so the
    /// descriptor always fits one control frame — a capsule is never made unpullable by a framing limit
    /// unrelated to its content.
    #[test]
    fn the_chunk_count_is_bounded_for_any_module_size() {
        for total in [
            1u64,
            MIN_CHUNK_SIZE,
            512 * 1024 * 1024,
            8 * 1024 * 1024 * 1024,
        ] {
            let chunk = chunk_size_for(total);
            assert!(chunk >= MIN_CHUNK_SIZE, "chunk {chunk} below the floor");
            let chunks = total.div_ceil(chunk);
            assert!(
                chunks <= MAX_DESCRIPTOR_CHUNKS,
                "{total} bytes -> {chunks} chunks, above the descriptor cap"
            );
        }
    }

    /// **Proves:** a window read returns exactly the requested span of the module.
    #[test]
    fn reads_the_exact_requested_window() {
        let (store, root) = (hex_id(5), hex_id(6));
        let bytes: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let dir = cache_with(&bytes, &store, &root);
        assert_eq!(
            read_module_window(&dir, &store, &root, 100, 50).expect("held"),
            bytes[100..150]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a window is CLAMPED to the module's end and to the per-request cap, so neither an
    /// absurd offset nor an absurd length can make one request size this node's work.
    #[test]
    fn a_window_is_clamped_to_the_module_and_to_the_request_cap() {
        let (store, root) = (hex_id(7), hex_id(8));
        let bytes = vec![7u8; 100];
        let dir = cache_with(&bytes, &store, &root);

        // Past the end: an empty window, not an error and not a wrapped read.
        assert!(read_module_window(&dir, &store, &root, 1_000, 10)
            .expect("held")
            .is_empty());
        // Absurd length: clamped to what exists.
        assert_eq!(
            read_module_window(&dir, &store, &root, 0, u64::MAX)
                .expect("held")
                .len(),
            100
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a module frame carries `total_length` on the FIRST frame only, matching the range
    /// contract the puller decodes with `dig_nat::RangeFrame`.
    #[test]
    fn total_length_rides_the_first_frame_only() {
        let first = module_frame(0, b"abc", false, Some(9));
        assert_eq!(first["total_length"], 9);
        assert_eq!(first["length"], 3);
        assert_eq!(first["complete"], false);

        let later = module_frame(3, b"def", true, None);
        assert!(later.get("total_length").is_none());
        assert_eq!(later["complete"], true);
    }

    /// **Proves:** a frame's bytes are base64 — the canonical `RangeFrame::bytes` encoding — so the
    /// puller's decode agrees with this producer.
    /// **Catches:** the #836 class of encoding skew, where producer and consumer disagreed about the
    /// byte encoding and content "arrived" but never verified.
    #[test]
    fn frame_bytes_are_base64_the_puller_can_decode() {
        let frame = module_frame(0, b"hello", true, Some(5));
        let decoded: dig_nat::RangeFrame =
            serde_json::from_value(frame).expect("decodes as a RangeFrame");
        assert_eq!(decoded.bytes, b"hello");
        assert_eq!(decoded.total_length, Some(5));
    }
}
