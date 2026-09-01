//! Serving a capsule descriptor must not make the whole capsule resident (dig-node#302, #1615/G2).
//!
//! `dig.getModuleInfo` is a ~100-byte peer request. Answering it needs a SHA-256 of the whole capsule
//! plus a per-chunk hash list, so every byte must be read, but no implementation needs every byte to
//! be resident AT ONCE. `read_module_window` beside it already seeks rather than slurping (#1615/G1);
//! this is the sibling path, where a whole-file `fs::read` turned a ~100-byte request into a
//! ~135 MB allocation on a live node.
//!
//! # Why this test measures ALLOCATION rather than the return value
//!
//! A streaming descriptor and a slurping one return a BIT-IDENTICAL `ModuleInfo`: same total size,
//! same whole-file digest, same chunk hashes, same chunk lengths. That is the point, because
//! incremental SHA-256 is defined to agree with the one-shot call. So no assertion on the OUTPUT can
//! tell the two apart, and a test that only checked the descriptor would pass just as happily against
//! the defect. The single observable that distinguishes them is the size of the largest allocation
//! made while the call runs.
//!
//! This mirrors `holdings_decode_alloc.rs`, which instruments the allocator for the same reason.
//!
//! # The descriptor is asserted too, and that is not redundant
//!
//! Memory can always be lowered by computing a different, cheaper answer. So the peak-allocation
//! bound is paired with an independent recomputation of the whole-file digest: a change that streams
//! but hashes the wrong bytes fails here rather than shipping a descriptor no puller can match.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use dig_node_core::seams::dig_peer::module_serve::{chunk_size_for, describe_module};
use dig_node_core::seams::dig_peer::module_stream::copy_verifying;
use sha2::{Digest, Sha256};

// ============================================================================
// Allocation instrumentation
// ============================================================================

thread_local! {
    /// Whether allocations on THIS thread are being measured. Thread-local so a test running
    /// concurrently in the same binary cannot contaminate the reading.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// The largest single allocation request seen on this thread while armed.
    static PEAK_REQUEST: Cell<usize> = const { Cell::new(0) };
}

/// Record `size` as a candidate peak. Uses `try_with` and allocation-free `Cell`s because an
/// allocator hook that itself allocates, or that panics during thread-local teardown, deadlocks.
fn record(size: usize) {
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = PEAK_REQUEST.try_with(|peak| {
                if size > peak.get() {
                    peak.set(size);
                }
            });
        }
    });
}

struct PeakRecordingAllocator;

// SAFETY: every method delegates to `System` with the caller's original arguments and contracts; the
// only added behaviour is recording a size into allocation-free thread-local `Cell`s.
unsafe impl GlobalAlloc for PeakRecordingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
}

#[global_allocator]
static ALLOC: PeakRecordingAllocator = PeakRecordingAllocator;

/// Run `f` with allocation recording armed, returning `(value, peak_single_allocation_bytes)`.
fn measure_peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
    PEAK_REQUEST.with(|p| p.set(0));
    ARMED.with(|a| a.set(true));
    let out = f();
    ARMED.with(|a| a.set(false));
    (out, PEAK_REQUEST.with(Cell::get))
}

// ============================================================================
// Fixture
// ============================================================================

/// A capsule big enough that a whole-file read is unmistakable next to the bound, and small enough
/// that writing it in CI is cheap. Far larger than [`PEAK_BOUND`], as the ticket requires.
const CAPSULE_BYTES: usize = 32 * 1024 * 1024;

/// The bound the serve path must stay under.
///
/// `chunk_size_for(32 MiB)` is 1 MiB (the floor), so a streaming descriptor's largest live buffer is
/// one chunk. 8 MiB leaves generous headroom for allocator behaviour and for the descriptor vectors
/// themselves, while staying 4x below the 32 MiB a whole-file read commits, so the test cannot pass
/// by accident under the defect and cannot fail by accident under the fix.
const PEAK_BOUND: usize = 8 * 1024 * 1024;

fn hex_id(seed: u8) -> String {
    hex::encode([seed; 32])
}

/// Write a capsule fixture at the cached-module path `describe_module` resolves:
/// `<cache_dir>/modules/<store>/<root>.dig`.
///
/// The layout is spelled out rather than borrowed from `CapsuleKey`, which is crate-private. If the
/// layout ever changes, `describe_module` returns `None` here and the test fails loudly rather than
/// silently measuring nothing.
fn seed_capsule(cache_dir: &Path, store_hex: &str, root_hex: &str, len: usize) -> PathBuf {
    let dir = cache_dir.join("modules").join(store_hex);
    std::fs::create_dir_all(&dir).expect("create cache dir");
    let path = dir.join(format!("{root_hex}.dig"));

    // Written in blocks so the FIXTURE never makes the whole capsule resident, otherwise the harness
    // would out-allocate the thing it is measuring. Content varies per block so a descriptor that
    // hashed the wrong offsets could not coincidentally agree with the expected digest.
    let mut f = std::io::BufWriter::new(std::fs::File::create(&path).expect("create fixture"));
    let mut written = 0usize;
    let mut counter: u64 = 0;
    while written < len {
        let mut block = [0u8; 64 * 1024];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (counter.wrapping_mul(31).wrapping_add(i as u64) % 251) as u8;
        }
        let take = block.len().min(len - written);
        f.write_all(&block[..take]).expect("write fixture");
        written += take;
        counter = counter.wrapping_add(1);
    }
    f.flush().expect("flush fixture");
    path
}

/// The whole-file SHA-256, computed incrementally by the TEST so the descriptor's digest is checked
/// against an independent answer rather than against itself.
fn file_digest(path: &Path) -> String {
    let mut f = std::fs::File::open(path).expect("open fixture");
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).expect("read fixture");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hex::encode(hasher.finalize())
}

// ============================================================================
// The guard
// ============================================================================

#[test]
fn describing_a_capsule_never_makes_the_whole_capsule_resident() {
    let cache = tempfile::tempdir().expect("tempdir");
    let store = hex_id(0x51);
    let root = hex_id(0x52);
    let path = seed_capsule(cache.path(), &store, &root, CAPSULE_BYTES);

    let expected_digest = file_digest(&path);
    let chunk = chunk_size_for(CAPSULE_BYTES as u64) as usize;
    let expected_chunks = CAPSULE_BYTES.div_ceil(chunk);

    let (info, peak) = measure_peak(|| describe_module(cache.path(), &store, &root));

    let info = info.expect(
        "the fixture is at the cached-module path, so the capsule must describe. A None here means \
         the cache layout moved and this test measured nothing",
    );

    // The descriptor must be the SAME answer, not a cheaper one.
    assert_eq!(
        info.total_size, CAPSULE_BYTES as u64,
        "the descriptor must report the real capsule length"
    );
    assert_eq!(
        info.module_hash, expected_digest,
        "the streamed whole-file digest must equal the digest computed independently over the same \
         bytes. A descriptor that got cheaper by hashing different bytes is not a fix"
    );
    assert_eq!(
        info.chunk_hashes.len(),
        expected_chunks,
        "one hash per chunk"
    );
    assert_eq!(
        info.chunk_lens.iter().sum::<u64>(),
        CAPSULE_BYTES as u64,
        "the chunk lengths must cover the whole capsule exactly"
    );

    // ...and it must have been produced without ever holding the capsule.
    assert!(
        peak <= PEAK_BOUND,
        "describing a {CAPSULE_BYTES}-byte capsule made a single {peak}-byte allocation, over the \
         {PEAK_BOUND}-byte bound. A ~100-byte `dig.getModuleInfo` from a peer must not commit the \
         whole capsule to RAM: read it in chunks and hash incrementally (#302, #1615/G2)."
    );
}

/// Promoting a verified capsule into the cache must not make it resident either (#302).
///
/// The reshare-warm promotion previously read the whole staged artifact into a `Vec` and then wrote
/// that same `Vec` back out, so one promotion cost a whole capsule resident PLUS a full in-memory
/// copy. This bounds the primitive the promotion now streams through.
#[test]
fn copying_a_verified_capsule_never_makes_it_resident() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("staged.dig");
    let dst = dir.path().join("cached.dig.warm.tmp");

    // Reuse the block writer so the fixture itself stays bounded.
    let store = hex_id(0x61);
    let root = hex_id(0x62);
    let seeded = seed_capsule(dir.path(), &store, &root, CAPSULE_BYTES);
    std::fs::rename(&seeded, &src).expect("stage the fixture");

    let mut expected = [0u8; 32];
    expected.copy_from_slice(&hex::decode(file_digest(&src)).expect("hex"));

    let (copied, peak) = measure_peak(|| copy_verifying(&src, &dst, &expected));

    assert_eq!(
        copied.expect("the digest is the file's own, so the copy must verify"),
        CAPSULE_BYTES as u64
    );
    assert_eq!(
        file_digest(&dst),
        file_digest(&src),
        "the copy must be byte-identical, not merely the right length"
    );
    assert!(
        peak <= PEAK_BOUND,
        "promoting a {CAPSULE_BYTES}-byte capsule made a single {peak}-byte allocation, over the \
         {PEAK_BOUND}-byte bound. Copy it through a fixed buffer, hashing as it goes (#302)."
    );
}

/// The promotion path itself must not have reverted to slurping.
///
/// The peak-allocation test above bounds `copy_verifying`, which is one level BELOW the decision that
/// matters: `promote_into_cache` could pass that test while reading the artifact itself. That function
/// is crate-private, so an allocator probe cannot reach it from here, and this reads its source
/// instead.
///
/// It reads the file from `CARGO_MANIFEST_DIR` rather than `include_str!` deliberately. A guard scoped
/// by `include_str!` is invisible in its own scoping: move the function to another file and the guard
/// keeps passing while checking a file the code left. Here, a move makes `find_fn` return `None` and
/// this test FAILS, which is the outcome a guard should have when it can no longer see its subject.
#[test]
fn promotion_does_not_slurp_the_staged_artifact() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("seams")
        .join("dig_peer")
        .join("module_reshare.rs");
    let source = std::fs::read_to_string(&path).expect("module_reshare.rs is readable");

    let body = find_fn(&source, "fn promote_into_cache(").unwrap_or_else(|| {
        panic!(
            "`promote_into_cache` was not found in {}. If it moved, move this guard with it rather \
             than deleting it: the whole-capsule read it prevents is invisible to every correctness \
             test, because a slurping promotion and a streaming one produce the same cached file.",
            path.display()
        )
    });

    // The POSITIVE assertion first, because it is the one a new slurping API cannot slip past. A ban
    // list can only ever check the names on it: swap `fs::read` for a `File::open` plus some future
    // read-everything helper and an enumeration stays green while the defect returns. Requiring the
    // streaming primitive by name fails on any rewrite that stops using it, whatever it uses instead.
    assert!(
        body.contains("module_stream::copy_verifying"),
        "`promote_into_cache` no longer routes through `module_stream::copy_verifying`. Whatever \
         replaced it must hash and copy in one bounded pass, or a promotion makes the whole ~135 MB \
         capsule resident again (#302)."
    );

    // Then the ban list, for the specific slurps that were actually here.
    for banned in ["fs::read(", "fs::write(", "read_to_end(", "read_to_string("] {
        assert!(
            !body.contains(banned),
            "`promote_into_cache` contains `{banned}`, which makes the whole staged capsule resident. \
             A promotion is a hash-and-copy over opaque bytes, so it streams through \
             `module_stream::copy_verifying` (#302)."
        );
    }
}

/// The body of the first function whose signature line contains `needle`, up to the closing brace at
/// column 0. Returns `None` when the signature is absent, so a caller can fail loudly.
fn find_fn<'a>(source: &'a str, needle: &str) -> Option<&'a str> {
    let start = source.find(needle)?;
    let rest = &source[start..];
    // Functions in this crate are top-level, so the terminating brace is the first one at column 0.
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
    Some(&rest[..end])
}
