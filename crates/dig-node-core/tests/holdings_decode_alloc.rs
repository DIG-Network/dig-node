//! The opcode-222 decoder must never size an allocation from a peer-declared count (#1723).
//!
//! A `holdings-announce` frame declares its per-change address count as a `u16`. Reserving on that
//! declaration lets a ~200-byte frame from an **unauthenticated** peer commit ~2 MiB, because decode
//! runs *before* `verify_holdings_announce` checks the signature. The bound is not the problem —
//! `u16` bounds it — the problem is that the number is the peer's to choose and nothing verifies it
//! against the protocol's own per-change maximum until much later.
//!
//! # Why this test measures ALLOCATION rather than the return value
//!
//! The fix is a **placement**, not an outcome: a decoder that reserves first and then fails on the
//! truncated address bytes returns exactly the same `None` as one that rejects the count up front.
//! An `assert!(decoded.is_none())` therefore passes identically against the defect and against the
//! fix — it would pin a coincidence, and a later refactor moving the guard back below the reservation
//! would keep it green. The only observable that distinguishes the two placements is the reservation
//! itself, so this test instruments the allocator and asserts the peak single request made *during*
//! the decode call.
//!
//! The frame is deliberately truncated after the declared count. That is what makes the test
//! discriminating: it means the *only* reason a large allocation could appear is the declaration
//! being trusted, since no address bytes exist to justify one.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use chia_protocol::{Bytes, Message, ProtocolMessageTypes};
use dig_gossip::holdings_announce_payload;

// ============================================================================
// Allocation instrumentation
// ============================================================================

thread_local! {
    /// Whether allocations on THIS thread are currently being measured. Thread-local so the
    /// measurement is unaffected by tests running concurrently in the same binary.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// The largest single allocation request seen on this thread while armed.
    static PEAK_REQUEST: Cell<usize> = const { Cell::new(0) };
}

/// Records `size` as a candidate peak. Uses `try_with` and allocation-free `Cell`s because a global
/// allocator hook that itself allocates — or that panics during thread-local teardown — deadlocks.
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

/// A pass-through allocator that notes the size of every request while [`ARMED`].
struct PeakRecordingAllocator;

// SAFETY: every method delegates to `System` with the caller's original arguments and contracts;
// the only added behaviour is recording a size into allocation-free thread-local `Cell`s.
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
static ALLOCATOR: PeakRecordingAllocator = PeakRecordingAllocator;

/// Runs `body` with allocation measurement armed, returning its value and the peak request seen.
fn measuring_allocations<T>(body: impl FnOnce() -> T) -> (T, usize) {
    PEAK_REQUEST.with(|peak| peak.set(0));
    ARMED.with(|armed| armed.set(true));
    let value = body();
    ARMED.with(|armed| armed.set(false));
    (value, PEAK_REQUEST.with(Cell::get))
}

// ============================================================================
// The crafted frame
// ============================================================================

/// `HoldingsDelta::Add`'s wire kind tag.
const KIND_ADD: u8 = 0x01;

/// The largest count the wire's `u16` can express — the whole point of the ticket is that a peer
/// may choose it freely.
const DECLARED_ADDRESS_COUNT: u16 = u16::MAX;

/// The ceiling the decode path must stay under for this frame.
///
/// Sized from the protocol, not from taste: the per-change maximum is 32 addresses, so an HONEST
/// worst-case reservation here is 32 × `size_of::<CandidateAddr>()` — well under a kibibyte. 64 KiB
/// leaves three orders of magnitude of headroom for the small `String`/`Vec` allocations the header
/// legitimately makes, while sitting ~32× below the ~2 MiB a trusted `u16` would commit. Any
/// allocation between those two figures is not something this decode path has an honest reason to
/// make.
const ALLOCATION_CEILING: usize = 64 * 1024;

/// Appends a `u16`-length-prefixed byte string, matching the wire's `put_bytes`.
fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// A well-formed opcode-222 header followed by one `Add` delta that declares
/// [`DECLARED_ADDRESS_COUNT`] addresses and then **stops**.
///
/// Every field up to the count is valid, so the decoder reaches the count by the ordinary path
/// rather than bailing early on a malformed header — the frame must get far enough to be able to
/// make the allocation under test.
fn frame_declaring_an_impossible_address_count() -> Vec<u8> {
    let mut buf = Vec::new();
    put_bytes(&mut buf, &[b'a'; 64]); // provider_peer_id (hex-shaped, never parsed at decode)
    put_bytes(&mut buf, &[0x30; 91]); // provider_spki (opaque to decode)
    buf.extend_from_slice(&7u64.to_be_bytes()); // seq
    buf.extend_from_slice(&1_800_000_000u64.to_be_bytes()); // announced_at
    buf.extend_from_slice(&1u16.to_be_bytes()); // change_count — one delta, within MAX_CHANGES
    buf.push(KIND_ADD);
    buf.extend_from_slice(&[0xAB; 32]); // content_key
    buf.extend_from_slice(&DECLARED_ADDRESS_COUNT.to_be_bytes());
    // Deliberately truncated: not one address byte follows the declaration.
    buf
}

/// Wraps `payload` in the opcode-222 message the inbound peer path actually receives.
fn holdings_message(payload: Vec<u8>) -> Message {
    Message {
        msg_type: ProtocolMessageTypes::HoldingsAnnounce,
        id: None,
        data: Bytes::new(payload),
    }
}

// ============================================================================
// The regression
// ============================================================================

/// Decoding a frame that DECLARES 65,535 addresses and carries none must not reserve for 65,535.
///
/// Asserted at `holdings_announce_payload` — the function `HoldingsIngress`'s inbound handler calls
/// on every opcode-222 frame — so this exercises the real entry point rather than a helper.
#[test]
fn decoding_a_declared_address_count_reserves_nothing_proportional_to_the_declaration() {
    let message = holdings_message(frame_declaring_an_impossible_address_count());

    // A first, unmeasured pass so that any one-time lazily-initialised state inside the decode path
    // is not charged to the measurement below.
    let _ = holdings_announce_payload(&message);

    let (decoded, peak_request) = measuring_allocations(|| holdings_announce_payload(&message));

    assert!(
        decoded.is_none(),
        "a frame truncated after its address-count declaration must not decode"
    );
    assert!(
        peak_request <= ALLOCATION_CEILING,
        "decoding a frame that declares {DECLARED_ADDRESS_COUNT} addresses and carries none \
         requested {peak_request} bytes in a single allocation (ceiling {ALLOCATION_CEILING}); \
         the declared count is being trusted to size a reservation before the signature is checked"
    );
}
