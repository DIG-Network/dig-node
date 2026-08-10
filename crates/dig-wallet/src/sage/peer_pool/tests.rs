//! Tests for the held peer pool (dig_ecosystem#2606, #2573).
//!
//! Every fixture here is built against the NEAREST WRONG implementation rather than against the
//! happy path, and each test names which one it is meant to catch. The two that matter most:
//!
//! * a pool that de-duplicates within one fill but not across fills — invisible to any
//!   single-fill fixture, and it re-admits the same peer on every reconnect; and
//! * a sample drawn WITH replacement — invisible under real entropy, which will not collide in a
//!   test's lifetime, so the entropy here is fixed to force the collision.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chia_protocol::Bytes32;

use super::*;
use crate::sage::quorum;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn addr(last_octet: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)), 8444)
}

const LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8444);

/// A peer that answers whatever it was built to answer.
///
/// It carries its OWN peak and its OWN header hash — two independently settable fields, not one.
/// A double that can only vary one of them cannot express the lie the quorum exists to catch (a
/// peer that agrees about the tip and disagrees about a settled block), so the honest and hostile
/// fixtures below would differ only cosmetically.
struct FakePeer {
    peak: Option<PeakClaim>,
    answer: Option<Bytes32>,
}

impl FakePeer {
    fn at(height: u32, answer_byte: u8) -> Arc<dyn PoolPeer> {
        Arc::new(Self {
            peak: Some(PeakClaim {
                height,
                header_hash: Bytes32::from([0xAB; 32]),
            }),
            answer: Some(Bytes32::from([answer_byte; 32])),
        })
    }

    /// A member that has connected but not yet announced a peak.
    fn silent() -> Arc<dyn PoolPeer> {
        Arc::new(Self {
            peak: None,
            answer: None,
        })
    }
}

#[async_trait::async_trait]
impl PoolPeer for FakePeer {
    fn peak(&self) -> Option<PeakClaim> {
        self.peak
    }
    async fn header_hash_at(&self, _height: u32) -> Option<Bytes32> {
        self.answer
    }
}

/// A book that hands back a fixed list, and counts how often it was asked.
struct FixedBook {
    list: Vec<SocketAddr>,
    resolutions: AtomicUsize,
}

impl FixedBook {
    fn new(list: Vec<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            list,
            resolutions: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl AddressBook for FixedBook {
    async fn addresses(&self) -> Vec<SocketAddr> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        self.list.clone()
    }
}

/// A dialer that always succeeds, recording every address it was ASKED to dial.
///
/// The record is the load-bearing part: asserting only on the resulting member set cannot tell a
/// pool that refused to dial a duplicate from one that dialled it and then discarded it, and the
/// second still burns a handshake per slot against a peer that wants exactly that.
struct RecordingDialer {
    dialled: Mutex<Vec<SocketAddr>>,
    /// Addresses that refuse the connection.
    refusing: Vec<SocketAddr>,
}

impl RecordingDialer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            dialled: Mutex::new(Vec::new()),
            refusing: Vec::new(),
        })
    }

    fn refusing(refusing: Vec<SocketAddr>) -> Arc<Self> {
        Arc::new(Self {
            dialled: Mutex::new(Vec::new()),
            refusing,
        })
    }

    fn dialled(&self) -> Vec<SocketAddr> {
        self.dialled.lock().expect("dial log").clone()
    }
}

#[async_trait::async_trait]
impl PeerDialer for RecordingDialer {
    async fn dial(&self, addr: SocketAddr) -> Option<Arc<dyn PoolPeer>> {
        self.dialled.lock().expect("dial log").push(addr);
        if self.refusing.contains(&addr) {
            return None;
        }
        Some(FakePeer::at(9_131_375, 7))
    }
}

/// Entropy that always yields the same bytes.
///
/// Deliberately degenerate. Real entropy makes a with-replacement sampler LOOK distinct, so a
/// test using it would pass against the wrong implementation; a constant source makes a
/// with-replacement sampler return the same index every time, which is the collision the
/// distinctness test needs to be able to see.
struct ConstantEntropy(u8);

impl quorum::EntropySource for ConstantEntropy {
    fn fill(&self, buf: &mut [u8]) {
        buf.fill(self.0);
    }
}

fn pool_of(
    book: Arc<dyn AddressBook>,
    dialer: Arc<dyn PeerDialer>,
    target: usize,
) -> PeerPool {
    PeerPool::new(book, dialer, Arc::new(ConstantEntropy(0)), target)
}

// ---------------------------------------------------------------------------
// Distinctness: one peer cannot occupy a pool
// ---------------------------------------------------------------------------

/// The #2573 property, at its sharpest: an address offered over and over — which is exactly what
/// `connect_random_peer` does with loopback — takes ONE slot, not the whole pool.
///
/// The fixture keeps two honest addresses alongside the repeated one so the pool has somewhere
/// else to go. An all-one-address fixture would read as harsher and could not distinguish
/// "admitted once" from "the pool is broken and admits nothing".
#[tokio::test]
async fn a_repeated_address_takes_one_slot_and_the_rest_go_to_other_peers() {
    let book = FixedBook::new(vec![
        LOOPBACK,
        LOOPBACK,
        addr(1),
        LOOPBACK,
        addr(2),
        LOOPBACK,
    ]);
    let dialer = RecordingDialer::new();
    let pool = pool_of(book, dialer.clone(), TARGET_PEERS);

    assert_eq!(pool.fill().await, 3, "three DISTINCT addresses were offered");

    let mut held: Vec<SocketAddr> = pool.members().await.iter().map(|m| m.addr).collect();
    held.sort();
    assert_eq!(held, vec![LOOPBACK, addr(1), addr(2)]);

    // And the duplicates were never even dialled: a repeat must cost nothing, or a peer that
    // wants to be dialled five times still gets five handshakes.
    assert_eq!(
        dialer.dialled().iter().filter(|a| **a == LOOPBACK).count(),
        1,
        "a duplicate candidate must not be dialled again"
    );
}

/// The cross-fill half, which a single-fill fixture cannot see: a refill must not re-admit an
/// address the pool is ALREADY holding.
///
/// This is the test that fails against a pool whose de-duplication is a local `HashSet` inside
/// one `fill` call — the most natural wrong implementation, and one that degrades quietly,
/// because it only misbehaves after a member has been evicted and the pool refills.
#[tokio::test]
async fn refilling_does_not_re_admit_a_peer_already_held() {
    let book = FixedBook::new(vec![addr(1), addr(2), addr(3)]);
    let dialer = RecordingDialer::new();
    let pool = pool_of(book, dialer.clone(), 3);

    assert_eq!(pool.fill().await, 3);
    pool.evict(addr(2)).await;
    assert_eq!(pool.len().await, 2);

    assert_eq!(pool.fill().await, 3, "the evicted slot refills");
    let mut held: Vec<SocketAddr> = pool.members().await.iter().map(|m| m.addr).collect();
    held.sort();
    assert_eq!(held, vec![addr(1), addr(2), addr(3)]);

    // addr(1) and addr(3) were held throughout, so the refill must not have touched them.
    assert_eq!(
        dialer.dialled().iter().filter(|a| **a == addr(1)).count(),
        1,
        "a held member must not be re-dialled by a refill"
    );
}

/// The pool stops at its target rather than draining the whole candidate list.
#[tokio::test]
async fn the_pool_stops_at_its_target() {
    let book = FixedBook::new((1..=20).map(addr).collect());
    let dialer = RecordingDialer::new();
    let pool = pool_of(book, dialer.clone(), TARGET_PEERS);

    assert_eq!(pool.fill().await, TARGET_PEERS);
    assert_eq!(
        dialer.dialled().len(),
        TARGET_PEERS,
        "no candidate beyond the target is dialled"
    );
}

/// A refusing candidate is skipped, not fatal — the pool moves down the list and still fills.
#[tokio::test]
async fn a_refusing_candidate_is_skipped_and_the_target_is_still_reached() {
    let book = FixedBook::new((1..=8).map(addr).collect());
    let dialer = RecordingDialer::refusing(vec![addr(1), addr(3)]);
    let pool = pool_of(book, dialer, TARGET_PEERS);

    assert_eq!(pool.fill().await, TARGET_PEERS);
    let held: Vec<SocketAddr> = pool.members().await.iter().map(|m| m.addr).collect();
    assert!(!held.contains(&addr(1)) && !held.contains(&addr(3)));
}

/// The candidate list is resolved ONCE and then fixed, so a resolver cannot re-bias later fills.
#[tokio::test]
async fn the_candidate_list_is_resolved_once() {
    let book = FixedBook::new(vec![addr(1), addr(2)]);
    let pool = pool_of(book.clone(), RecordingDialer::new(), TARGET_PEERS);

    pool.fill().await;
    pool.evict(addr(1)).await;
    pool.fill().await;

    assert_eq!(
        book.resolutions.load(Ordering::SeqCst),
        1,
        "re-resolving per fill would reopen the head-of-list bias #2573 closes"
    );
}

// ---------------------------------------------------------------------------
// Sampling: a quorum is drawn from DISTINCT members
// ---------------------------------------------------------------------------

/// A sample never counts one peer twice, even when the entropy is degenerate enough that a
/// with-replacement draw would pick the same index every time.
#[tokio::test]
async fn a_sample_contains_each_member_at_most_once() {
    let book = FixedBook::new((1..=TARGET_PEERS as u8).map(addr).collect());
    let pool = pool_of(book, RecordingDialer::new(), TARGET_PEERS);
    pool.fill().await;

    let sample = pool.sample(quorum::QUORUM_SAMPLE).await;
    assert_eq!(sample.len(), quorum::QUORUM_SAMPLE);

    let distinct: std::collections::HashSet<SocketAddr> =
        sample.iter().map(|m| m.addr).collect();
    assert_eq!(
        distinct.len(),
        quorum::QUORUM_SAMPLE,
        "one peer counted four times is a sample of one"
    );
}

/// The property the whole design exists for: **one peer cannot supply a quorum.**
///
/// A pool holding a single member yields a SHORT sample, which `quorum::tally` resolves to
/// [`quorum::Verdict::Insufficient`] — nothing written — no matter how confidently that one peer
/// answers. The honest control sits beside it so the test cannot pass merely because the tally
/// refuses everything.
#[tokio::test]
async fn a_single_peer_cannot_supply_a_quorum_but_four_distinct_peers_can() {
    // Hostile: the candidate list is one address, repeated — the co-resident-full-node shape.
    let hostile = pool_of(
        FixedBook::new(vec![LOOPBACK; 8]),
        RecordingDialer::new(),
        TARGET_PEERS,
    );
    hostile.fill().await;
    assert_eq!(hostile.len().await, 1);

    let sample = hostile.sample(quorum::QUORUM_SAMPLE).await;
    let responses: Vec<quorum::Response<Bytes32>> = sample
        .iter()
        .map(|m| quorum::Response {
            peer: m.addr.to_string(),
            answer: Bytes32::from([7u8; 32]),
        })
        .collect();
    assert!(
        matches!(
            quorum::tally(&responses, quorum::QUORUM_SAMPLE, quorum::QUORUM_AGREEMENT),
            quorum::Verdict::Insufficient { .. }
        ),
        "a unanimous sample of one must not be a quorum"
    );

    // Control: four DISTINCT peers giving the same answer DO reach one, so the assertion above
    // is about the sample size and not about the tally rejecting everything.
    let honest = pool_of(
        FixedBook::new((1..=TARGET_PEERS as u8).map(addr).collect()),
        RecordingDialer::new(),
        TARGET_PEERS,
    );
    honest.fill().await;
    let responses: Vec<quorum::Response<Bytes32>> = honest
        .sample(quorum::QUORUM_SAMPLE)
        .await
        .iter()
        .map(|m| quorum::Response {
            peer: m.addr.to_string(),
            answer: Bytes32::from([7u8; 32]),
        })
        .collect();
    assert!(
        quorum::tally(&responses, quorum::QUORUM_SAMPLE, quorum::QUORUM_AGREEMENT)
            .corroborated()
            .is_some(),
        "four distinct agreeing peers must reach a quorum"
    );
}

/// A member that has not announced a peak is not a candidate, so it cannot drag the settled
/// height anywhere. It is absent from the vote, which counts against the quorum.
#[tokio::test]
async fn a_member_with_no_peak_claim_is_not_a_candidate() {
    struct SilentDialer;
    #[async_trait::async_trait]
    impl PeerDialer for SilentDialer {
        async fn dial(&self, addr: SocketAddr) -> Option<Arc<dyn PoolPeer>> {
            Some(if addr == addr_one() {
                FakePeer::silent()
            } else {
                FakePeer::at(9_131_375, 7)
            })
        }
    }
    fn addr_one() -> SocketAddr {
        addr(1)
    }

    let pool = pool_of(
        FixedBook::new(vec![addr(1), addr(2)]),
        Arc::new(SilentDialer),
        TARGET_PEERS,
    );
    pool.fill().await;

    let candidates: Vec<_> = pool
        .members()
        .await
        .iter()
        .filter_map(Member::candidate)
        .collect();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, addr(2).to_string());
}

// ---------------------------------------------------------------------------
// The candidate list (#2573)
// ---------------------------------------------------------------------------

/// Loopback is NOT an unconditional member. This is the #2573 fix stated as a property.
#[test]
fn loopback_is_absent_unless_the_operator_asked_for_it() {
    let discovered = vec![addr(1), addr(2)];
    let list = assemble_addresses(&[], &discovered);
    assert!(
        !list.contains(&LOOPBACK),
        "a co-resident process must not be dialled just because it is listening"
    );
    assert_eq!(list, discovered);
}

/// ...and IS a member, first, when the operator named it. The escape hatch has to work, or an
/// operator running their own node beside the wallet loses it.
#[test]
fn loopback_is_admitted_first_when_the_operator_named_it() {
    let list = assemble_addresses(&[LOOPBACK], &[addr(1)]);
    assert_eq!(list, vec![LOOPBACK, addr(1)]);
}

/// An address named by the operator AND returned by discovery appears once, in the operator
/// position — otherwise it would occupy two pool slots and vote twice.
#[test]
fn an_address_from_both_sources_appears_once() {
    let list = assemble_addresses(&[addr(1)], &[addr(2), addr(1), addr(3)]);
    assert_eq!(list, vec![addr(1), addr(2), addr(3)]);
}
