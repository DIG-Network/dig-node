//! One-pass streaming primitives for whole-capsule digests (dig-node#302).
//!
//! A capsule measures ~135 MB on a live node. Two serve-side paths needed a digest over EVERY byte of
//! one, and both got those bytes with `std::fs::read`, making the whole capsule resident to compute a
//! 32-byte answer. `read_module_window` beside them already seeks instead of slurping (#1615/G1);
//! these are the hashing siblings (#1615/G2).
//!
//! # Why these paths are streamable when the interpreting paths are not
//!
//! Three other whole-capsule reads in this crate hand the buffer to `digstore_compiler`
//! (`serve_blind`, `extract_data_section_blob`, `verify_module_root`), whose signatures take `&[u8]`
//! and whose work needs the blob in wasm linear memory or a parsed wasm binary. Those are blocked on
//! the format side (DIG-Network/digs#49) and are deliberately untouched here.
//!
//! The two paths in this module are different in kind: they do not INTERPRET the capsule at all. They
//! compute SHA-256 over opaque bytes. Incremental SHA-256 is defined to produce the identical digest
//! to the one-shot call over the same byte sequence, so streaming them changes the memory profile and
//! nothing else. No verification is weakened, relaxed, deferred, or made partial: the same bytes are
//! hashed in the same order and compared against the same expected value.
//!
//! # What this module does NOT claim
//!
//! It does not provide *prefix* verification. Nothing here can attest that a partial capsule is a
//! correct prefix of the whole, because the format commits one leaf per whole resource
//! (`digstore-core`'s `resource_leaf`) and has no per-chunk commitment to check a prefix against.
//! These primitives verify a COMPLETE artifact using bounded memory. That is a different property
//! from streaming verification, and conflating the two is what digs#49 exists to fix.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

/// The fixed read buffer every stream here uses.
///
/// Deliberately independent of both the capsule size and the descriptor's chunk size, so peak resident
/// memory is a CONSTANT rather than a fraction of the artifact. A buffer sized from the capsule (one
/// descriptor chunk, say) would still grow without bound as capsules grow, which is the property this
/// module exists to remove.
pub const STREAM_BUF: usize = 256 * 1024;

/// A capsule digested in a single pass, without the capsule ever being resident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamedDigest {
    /// Bytes actually read from the file.
    pub total: u64,
    /// SHA-256 over every byte, in order.
    pub whole: [u8; 32],
    /// SHA-256 of each fixed-size chunk, in order. The last chunk may be short.
    pub chunk_digests: Vec<[u8; 32]>,
    /// The length of each chunk, in the same order. Sums to [`total`](Self::total).
    pub chunk_lens: Vec<u64>,
}

/// Digest `path` whole AND per `chunk_size`-byte chunk, in ONE pass over a fixed buffer.
///
/// The chunk hashes are folded as the bytes stream past rather than by slicing a resident buffer, so
/// the largest live allocation is [`STREAM_BUF`] plus the two output vectors, whatever the file size.
///
/// The result is byte-for-byte what `sha256(&fs::read(path)?)` and `bytes.chunks(chunk_size)` would
/// produce. Chunk boundaries are absolute file offsets, so they do not depend on how the reads
/// happened to land.
///
/// # Errors
///
/// Any I/O error from opening or reading `path`. A `chunk_size` of 0 is rejected as
/// [`io::ErrorKind::InvalidInput`] rather than silently producing no chunks, because a zero here would
/// come from a caller's arithmetic and should surface there.
pub fn digest_with_chunks(path: &Path, chunk_size: usize) -> io::Result<StreamedDigest> {
    if chunk_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chunk_size must be non-zero",
        ));
    }

    let mut file = File::open(path)?;
    let mut buf = vec![0u8; STREAM_BUF];

    let mut whole = Sha256::new();
    let mut chunk = Sha256::new();
    let mut in_chunk: usize = 0;
    let mut total: u64 = 0;
    let mut chunk_digests = Vec::new();
    let mut chunk_lens = Vec::new();

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        whole.update(&buf[..n]);
        total += n as u64;

        // A read can straddle any number of chunk boundaries, so walk the buffer and close a chunk
        // exactly when `chunk_size` bytes have passed through it. This is what keeps the boundaries a
        // property of the FILE rather than of the read sizes the OS happened to return.
        let mut off = 0usize;
        while off < n {
            let take = (chunk_size - in_chunk).min(n - off);
            chunk.update(&buf[off..off + take]);
            in_chunk += take;
            off += take;
            if in_chunk == chunk_size {
                chunk_digests.push(chunk.finalize_reset().into());
                chunk_lens.push(chunk_size as u64);
                in_chunk = 0;
            }
        }
    }

    // The trailing partial chunk, if the file did not divide evenly.
    if in_chunk > 0 {
        chunk_digests.push(chunk.finalize_reset().into());
        chunk_lens.push(in_chunk as u64);
    }

    Ok(StreamedDigest {
        total,
        whole: whole.finalize().into(),
        chunk_digests,
        chunk_lens,
    })
}

/// Why a verified stream-copy did not complete.
///
/// Read and write failures are kept APART rather than collapsed into one `Io`, because callers map
/// them to different outcomes: a source that cannot be read says something about the ARTIFACT, while a
/// destination that cannot be written says something about this HOST. The promotion path relied on
/// exactly that distinction before this was streamed (an unreadable staged artifact was a
/// `PromotedArtifactMismatch`, a failed write was a `CacheWriteFailed`), so a single variant here would
/// have silently re-mapped one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCopyError {
    /// The source could not be opened or read. The destination has been removed.
    ReadFailed,
    /// The destination could not be created, written, or flushed. It has been removed.
    WriteFailed,
    /// The bytes copied do not hash to the expected digest. The destination has been removed.
    ///
    /// Distinct from a read failure because the two mean different things about the source: an I/O
    /// error says nothing about the artifact, while a mismatch says the artifact on disk is not the
    /// one that was admitted, and no retry of the copy will change that.
    DigestMismatch,
}

/// Copy `src` to `dst` in one pass, hashing as it goes, and keep `dst` only if the copy hashes to
/// `expected`.
///
/// Returns the number of bytes copied.
///
/// # Ordering, and why the destination is written before the digest is known
///
/// A whole-file `read` lets a caller verify BEFORE writing anything. Streaming cannot: the final
/// digest is known only after the last byte, which by then has been written. So `dst` transiently
/// holds unverified bytes, and this function's contract is that **it never leaves them there** on
/// either failure path.
///
/// That is safe for the promotion path only because `dst` is a private temporary, never the cache
/// path. A file at the cache path IS this node's holder claim, so unverified bytes appearing there
/// would be an announcement that this node serves content no gate admitted. The caller renames into
/// the cache path only after this function returns `Ok`, which preserves the invariant exactly as the
/// whole-file version did: nothing unverified is ever observable at the cache path.
///
/// # Errors
///
/// [`StreamCopyError::ReadFailed`] or [`StreamCopyError::WriteFailed`] on I/O, and
/// [`StreamCopyError::DigestMismatch`] when the copied bytes do not match `expected`. In every case
/// `dst` has been removed on a best-effort basis.
pub fn copy_verifying(src: &Path, dst: &Path, expected: &[u8; 32]) -> Result<u64, StreamCopyError> {
    let copied = copy_hashing(src, dst, expected);
    if copied.is_err() {
        // Best-effort: an unverified or partial artifact must not survive this call. If the removal
        // itself fails there is nothing further to do here, and the caller has already been told the
        // promotion failed, so the file is never treated as held either way.
        let _ = std::fs::remove_file(dst);
    }
    copied
}

/// The copy itself, split out so [`copy_verifying`] can clean up on every failure path in ONE place
/// rather than at each `?`.
fn copy_hashing(src: &Path, dst: &Path, expected: &[u8; 32]) -> Result<u64, StreamCopyError> {
    let mut input = File::open(src).map_err(|_| StreamCopyError::ReadFailed)?;
    let mut output = File::create(dst).map_err(|_| StreamCopyError::WriteFailed)?;

    let mut buf = vec![0u8; STREAM_BUF];
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;

    loop {
        let n = input
            .read(&mut buf)
            .map_err(|_| StreamCopyError::ReadFailed)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output
            .write_all(&buf[..n])
            .map_err(|_| StreamCopyError::WriteFailed)?;
        total += n as u64;
    }
    output.flush().map_err(|_| StreamCopyError::WriteFailed)?;
    drop(output);

    let actual: [u8; 32] = hasher.finalize().into();
    if &actual != expected {
        return Err(StreamCopyError::DigestMismatch);
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = File::create(&p).expect("create");
        f.write_all(bytes).expect("write");
        p
    }

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    /// The streamed digests must equal the one-shot answers over the same bytes, at a size that
    /// straddles several buffer reads AND several chunk boundaries, with a short final chunk.
    ///
    /// This is the property every caller depends on: streaming is only a memory change if the answer
    /// is identical, so a divergence here would mean the fix silently re-defined the descriptor.
    #[test]
    fn streamed_digests_equal_the_one_shot_digests() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Not a multiple of STREAM_BUF or of the chunk size, so both the read loop and the chunk loop
        // finish mid-buffer.
        let len = STREAM_BUF * 2 + 7777;
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let path = write_fixture(dir.path(), "a.dig", &bytes);

        let chunk_size = 100_000usize;
        let got = digest_with_chunks(&path, chunk_size).expect("digest");

        assert_eq!(got.total, len as u64);
        assert_eq!(got.whole, sha(&bytes), "whole-file digest must match");

        let want_chunks: Vec<[u8; 32]> = bytes.chunks(chunk_size).map(sha).collect();
        let want_lens: Vec<u64> = bytes.chunks(chunk_size).map(|c| c.len() as u64).collect();
        assert_eq!(got.chunk_digests, want_chunks, "chunk digests must match");
        assert_eq!(got.chunk_lens, want_lens, "chunk lengths must match");
        assert!(
            *got.chunk_lens.last().expect("at least one chunk") < chunk_size as u64,
            "this fixture is chosen so the final chunk is SHORT, which is the case a boundary bug hides in"
        );
    }

    /// A file shorter than one buffer read still produces exactly one chunk.
    #[test]
    fn a_file_smaller_than_the_buffer_yields_one_short_chunk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = b"short".to_vec();
        let path = write_fixture(dir.path(), "b.dig", &bytes);

        let got = digest_with_chunks(&path, 1024).expect("digest");
        assert_eq!(got.total, 5);
        assert_eq!(got.whole, sha(&bytes));
        assert_eq!(got.chunk_digests, vec![sha(&bytes)]);
        assert_eq!(got.chunk_lens, vec![5]);
    }

    /// An exact multiple must NOT emit a trailing empty chunk.
    #[test]
    fn an_exact_multiple_emits_no_trailing_empty_chunk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = vec![7u8; 4096];
        let path = write_fixture(dir.path(), "c.dig", &bytes);

        let got = digest_with_chunks(&path, 1024).expect("digest");
        assert_eq!(
            got.chunk_digests.len(),
            4,
            "4096 / 1024 is exactly four chunks"
        );
        assert_eq!(got.chunk_lens, vec![1024; 4]);
        assert_eq!(
            got.chunk_lens.iter().sum::<u64>(),
            4096,
            "an empty fifth chunk would still sum to 4096, so the COUNT above is the real assertion"
        );
    }

    /// An empty file has no chunks, and its whole digest is the digest of no bytes.
    #[test]
    fn an_empty_file_has_no_chunks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_fixture(dir.path(), "d.dig", b"");

        let got = digest_with_chunks(&path, 1024).expect("digest");
        assert_eq!(got.total, 0);
        assert!(got.chunk_digests.is_empty());
        assert!(got.chunk_lens.is_empty());
        assert_eq!(got.whole, sha(b""));
    }

    /// A zero chunk size is a caller arithmetic bug and must surface, not silently produce no chunks.
    #[test]
    fn a_zero_chunk_size_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_fixture(dir.path(), "e.dig", b"abc");
        let err = digest_with_chunks(&path, 0).expect_err("zero chunk size must be an error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_matching_copy_lands_and_reports_its_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = vec![3u8; STREAM_BUF + 11];
        let src = write_fixture(dir.path(), "src.dig", &bytes);
        let dst = dir.path().join("dst.tmp");

        let n = copy_verifying(&src, &dst, &sha(&bytes)).expect("digest matches");
        assert_eq!(n, bytes.len() as u64);
        assert_eq!(
            std::fs::read(&dst).expect("dst"),
            bytes,
            "the copy is byte-identical"
        );
    }

    /// The failure mode streaming INTRODUCES: the destination is written before the digest is known,
    /// so a mismatch must leave nothing behind.
    ///
    /// Asserted on the FILESYSTEM rather than on the return value, because a caller that only checked
    /// the `Err` would still be correct while an unverified artifact sat on disk waiting for the next
    /// promotion to rename it into the cache.
    #[test]
    fn a_mismatched_copy_leaves_no_artifact_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = vec![9u8; STREAM_BUF * 2];
        let src = write_fixture(dir.path(), "src.dig", &bytes);
        let dst = dir.path().join("dst.tmp");

        let err = copy_verifying(&src, &dst, &[0u8; 32]).expect_err("digest cannot match");
        assert_eq!(err, StreamCopyError::DigestMismatch);
        assert!(
            !dst.exists(),
            "a copy that failed verification must not survive: the caller renames this path into the \
             cache, where its mere existence is this node's holder claim"
        );
    }

    /// A missing source is an I/O failure, distinguishable from a digest mismatch.
    #[test]
    fn a_missing_source_is_an_io_failure_not_a_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dst = dir.path().join("dst.tmp");
        let err = copy_verifying(&dir.path().join("absent.dig"), &dst, &[0u8; 32])
            .expect_err("no source");
        assert_eq!(
            err,
            StreamCopyError::ReadFailed,
            "an unreadable SOURCE must stay distinguishable from a failed WRITE: the promotion path \
             maps the two to different outcomes, so collapsing them would silently re-map one"
        );
        assert!(!dst.exists());
    }
}
