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

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use dig_rpc_protocol::types::ModuleInfo;
use lru::LruCache;
use serde_json::{json, Value};

use crate::capsule_key::CapsuleKey;

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

/// A descriptor memoized against the file metadata it was computed from, so a later request for an
/// UNCHANGED file can be answered without re-reading or re-hashing it.
struct CachedDescriptor {
    len: u64,
    modified: Option<SystemTime>,
    info: ModuleInfo,
}

/// The descriptor memo's entry cap.
///
/// Each entry is tens of KB (up to [`MAX_DESCRIPTOR_CHUNKS`] `chunk_hashes` + `chunk_lens`), and every
/// entry is created by a peer-driven `dig.getModuleInfo` — an UNBOUNDED memo would let a long-running
/// node accumulate one entry per module it has EVER described, including modules since evicted from
/// the actual capsule cache and no longer servable at all. 512 entries bounds the memo to tens of MB
/// however many distinct capsules a peer has ever asked about.
const DESCRIPTOR_MEMO_CAP: usize = 512;

/// The process-wide descriptor memo, keyed by `(store_hex, root_hex)`, evicting least-recently-used
/// once [`DESCRIPTOR_MEMO_CAP`] is reached.
///
/// A `dig.getModuleInfo` costs a full-file read PLUS a SHA-256 of every chunk (#1615/G2) — real work a
/// ~100-byte peer request can trigger on every call. The module a descriptor describes changes only when
/// this node re-warms it (a brand-new file, written via write-then-rename — never edited in place), so
/// `(len, mtime)` is a safe fingerprint: a cache hit means the file is provably the one the memo was
/// built from, and any change invalidates it automatically.
fn descriptor_memo() -> &'static Mutex<LruCache<(String, String), CachedDescriptor>> {
    static MEMO: OnceLock<Mutex<LruCache<(String, String), CachedDescriptor>>> = OnceLock::new();
    MEMO.get_or_init(|| {
        Mutex::new(LruCache::new(
            NonZeroUsize::new(DESCRIPTOR_MEMO_CAP).expect("512 is nonzero"),
        ))
    })
}

/// Build the [`ModuleInfo`] descriptor for a locally-held capsule, or `None` if this node does not hold
/// it (or the ids are not canonical).
///
/// Blocking file I/O — call from `spawn_blocking`, like the rest of the module-reading serve path.
pub fn describe_module(cache_dir: &Path, store_hex: &str, root_hex: &str) -> Option<ModuleInfo> {
    let capsule = CapsuleKey::parse(store_hex, root_hex)?;
    // Reader-tolerance (#1896): describe the current `.dig`, or a legacy `.module` a prior binary wrote.
    let path = capsule.resolve_cached_path(cache_dir);
    let metadata = std::fs::metadata(&path).ok()?;
    let len = metadata.len();
    if len == 0 {
        // A 0-byte file is not a module. Describing it would produce a descriptor whose hash gates all
        // PASS (sha256 of no bytes is a real digest), leaving the puller's anchor gate as the only thing
        // between a truncated local file and a peer caching it — so refuse at the source instead.
        return None;
    }
    let modified = metadata.modified().ok();
    let key = (store_hex.to_string(), root_hex.to_string());

    if let Some(cached) = descriptor_memo()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
    {
        // `get` (not `peek`) bumps this entry to most-recently-used, so a capsule still being asked
        // about survives the cap even as new ones are described.
        if cached.len == len && cached.modified == modified {
            return Some(cached.info.clone());
        }
    }

    let bytes = std::fs::read(&path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let chunk = chunk_size_for(bytes.len() as u64) as usize;
    let info = ModuleInfo {
        total_size: bytes.len() as u64,
        module_hash: hex32(&sha256(&bytes)),
        chunk_hashes: bytes.chunks(chunk).map(|c| hex32(&sha256(c))).collect(),
        chunk_lens: bytes.chunks(chunk).map(|c| c.len() as u64).collect(),
    };

    descriptor_memo()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .put(
            key,
            CachedDescriptor {
                len,
                modified,
                info: info.clone(),
            },
        );

    Some(info)
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
    use std::io::{Read, Seek, SeekFrom};

    let capsule = CapsuleKey::parse(store_hex, root_hex)?;
    // Seek to the window instead of `fs::read`-ing the whole module (#1615/G1): a 512 MiB capsule
    // served in 4 MiB windows would otherwise cost a full-file read PER request — ~256 GiB of IO to
    // serve one pull, with up to 512 MiB resident per in-flight request. Only the bytes this request
    // actually asked for are ever pulled off disk.
    let mut file = std::fs::File::open(capsule.resolve_cached_path(cache_dir)).ok()?;
    let total = file.metadata().ok()?.len();
    let start = offset.min(total);
    let want = length.min(MAX_MODULE_WINDOW).min(total - start);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut window = vec![0u8; want as usize];
    file.read_exact(&mut window).ok()?;
    Some(window)
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
    use std::path::PathBuf;

    fn hex_id(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The cached-module path for a capsule named by hex ids, for fixtures that seed the cache
    /// directly. Panics on a non-canonical id: a hostile key must reach the code under test through its
    /// real entry point, never through a fixture that rebuilds the path by hand.
    fn module_path(dir: &Path, store_hex: &str, root_hex: &str) -> PathBuf {
        CapsuleKey::parse(store_hex, root_hex)
            .expect("a fixture names a capsule with canonical ids")
            .module_path(dir)
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

    /// **Proves:** a window read against a module several times larger than the per-request window still
    /// returns exactly the requested window, byte-identical — the seek-based read (#1615/G1) must behave
    /// like the old whole-file read even when the seek lands well past the start of a large file.
    /// **Catches:** an off-by-one or wrong-origin `seek`, which the small fixtures above (well under one
    /// window) could not expose.
    #[test]
    fn reads_one_window_of_a_module_larger_than_the_window_cap() {
        let (store, root) = (hex_id(13), hex_id(14));
        let total = (MAX_MODULE_WINDOW * 3) as usize;
        let bytes: Vec<u8> = (0..total).map(|i| (i % 256) as u8).collect();
        let dir = cache_with(&bytes, &store, &root);

        let offset = MAX_MODULE_WINDOW * 2 + 17;
        let want = 4096u64;
        let window = read_module_window(&dir, &store, &root, offset, want).expect("held");

        assert_eq!(window.len(), want as usize);
        assert_eq!(window, bytes[offset as usize..(offset + want) as usize]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** a second `describe_module` call for an UNCHANGED file is answered from the memo
    /// rather than recomputed — proven by seeding the memo with a distinguishable sentinel value (under
    /// the real, unchanged `(len, mtime)` fingerprint) and observing the sentinel come back. If this call
    /// had recomputed from disk it would have recovered the true hash, not the sentinel.
    /// **Catches:** re-reading and re-hashing the whole module on every `dig.getModuleInfo` (#1615/G2) —
    /// real work a ~100-byte peer request could otherwise trigger without bound.
    #[test]
    fn an_unchanged_module_descriptor_is_served_from_the_memo() {
        let (store, root) = (hex_id(15), hex_id(16));
        let bytes: Vec<u8> = (0..2000u32).map(|i| (i % 200) as u8).collect();
        let dir = cache_with(&bytes, &store, &root);

        let real = describe_module(&dir, &store, &root).expect("held");
        let metadata = std::fs::metadata(module_path(&dir, &store, &root)).unwrap();
        let sentinel = ModuleInfo {
            module_hash: "0".repeat(64),
            ..real.clone()
        };
        descriptor_memo().lock().unwrap().put(
            (store.clone(), root.clone()),
            CachedDescriptor {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                info: sentinel.clone(),
            },
        );

        let second = describe_module(&dir, &store, &root).expect("held");
        assert_eq!(
            second.module_hash, sentinel.module_hash,
            "the unchanged file's second describe_module call is answered from the memo"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Proves:** the descriptor memo is BOUNDED — describing more distinct modules than
    /// `DESCRIPTOR_MEMO_CAP` evicts the earliest entries rather than growing without limit.
    /// **Catches:** an unbounded memo (#1615/G2 follow-up), which would let a long-running node
    /// accumulate one entry per module it has EVER described, including modules long since evicted
    /// from the actual capsule cache and no longer servable at all.
    ///
    /// Asserts only the invariant that holds regardless of what OTHER tests concurrently insert into
    /// this process-global memo: describing `DESCRIPTOR_MEMO_CAP + 1` never-touched-again modules
    /// guarantees the FIRST one is evicted (nothing else in the process ever re-touches it to save
    /// it), however many extra entries other tests happen to interleave in.
    #[test]
    fn the_descriptor_memo_is_capped_and_evicts_stale_entries() {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-modserve-memocap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // DESCRIPTOR_MEMO_CAP + 1 distinct (store, root) keys, none shared with any other test in
        // this file (those use small repeated-byte ids; these are sequential integers padded to
        // 64-hex) — so this test's own fill is the only thing that can evict or preserve them.
        let keys: Vec<(String, String)> = (0..=DESCRIPTOR_MEMO_CAP)
            .map(|i| (format!("{i:064x}"), format!("{:064x}", i + 10_000_000)))
            .collect();
        for (store, root) in &keys {
            let path = module_path(&dir, store, root);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
            describe_module(&dir, store, root).expect("held");
        }

        let first = keys[0].clone();
        assert!(
            !descriptor_memo()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&first),
            "the earliest-described module's memo entry must be evicted once the cap is exceeded"
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
