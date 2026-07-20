//! Node-side peer address book (#381) — a durable, **IPv6-first**, provenance + staleness-TTL store
//! of learned peer candidates.
//!
//! ## What it does
//!
//! Every peer address the node learns — from PEX (dig-pex, #387), from `dig.getPeers`, from the relay
//! introducer, or from an observed pool peer — is OFFERED here instead of being dialed-and-dropped.
//! The book keeps one entry per `peer_id`, unions each peer's dialable candidate addresses ordered
//! IPv6-first (ecosystem HARD RULE §5.2), records the provenance + a freshen timestamp, and reads back
//! a **ranked, non-stale** candidate list (peers that carry a directly-dialable IPv6 address lead) that
//! seeds future dial selection. A per-peer capacity bound evicts the stalest entry so the book can
//! never grow unbounded from a chatty peer.
//!
//! ## Why this lives in the node (interim) — the missing dig-gossip crate API
//!
//! dig-gossip owns the canonical `AddressManager` (candidate store + IPv6-first ordering). The
//! intended design (issue #381) is a PUBLIC crate ingest API on `GossipHandle` — e.g.
//! `offer_addresses(candidates, provenance)` — so learned addresses upsert into that ONE store and the
//! pool's own dial loop selects from it. The pinned dig-gossip rev exposes **no such production API**
//! (only a `#[doc(hidden)]` `__seed_address_book_for_tests` hook), so the node cannot feed the crate's
//! AddressManager without a release-first crate change. Until that lands, THIS module is the node's
//! durable address book; when the crate ships the ingest API, this book becomes the bridge that flushes
//! into the crate AddressManager (a single source of truth). See the crate-API note in the P2P section
//! of `SPEC.md`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

/// How the node learned a candidate address. Provenance is retained so a later selection can trust /
/// prioritize a first-hand-observed peer over an unverified PEX hint (SPEC §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrProvenance {
    /// Discovered via peer exchange (dig-pex) — a HINT, proven only by a successful dial.
    Pex,
    /// Reported by a peer's `dig.getPeers` response.
    GetPeers,
    /// Learned from the relay introducer.
    Introducer,
    /// A directly-observed connected pool peer (first-hand).
    PoolDirect,
}

/// A learned peer candidate: its `peer_id` (64-hex), its directly-dialable candidate addresses ordered
/// **IPv6-first**, how + when it was learned, and whether it is relay-only (no dialable address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAddr {
    /// The peer identity, 64-hex.
    pub peer_id: String,
    /// Directly-dialable candidate addresses, ordered IPv6-first. Empty for a relay-only peer.
    pub addrs: Vec<SocketAddr>,
    /// How the node learned this candidate.
    pub provenance: AddrProvenance,
    /// Unix seconds when the candidate was last (re)learned — drives staleness.
    pub learned_at: u64,
}

impl CandidateAddr {
    /// Build a candidate from its parts, ordering the addresses IPv6-first + de-duplicating. A
    /// candidate with no dialable address is a relay-only hint (still worth persisting).
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        addrs: Vec<SocketAddr>,
        provenance: AddrProvenance,
        learned_at: u64,
    ) -> Self {
        let mut c = CandidateAddr {
            peer_id: peer_id.into(),
            addrs,
            provenance,
            learned_at,
        };
        c.normalize_addrs();
        c
    }

    /// Whether this candidate has NO directly-dialable address (reached only via the relay tiers).
    #[must_use]
    pub fn is_relay_only(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Whether this candidate carries at least one directly-dialable IPv6 address (leads the ordering).
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.addrs.first().is_some_and(SocketAddr::is_ipv6)
    }

    /// Sort addresses IPv6-first (ecosystem §5.2) + de-dup, preserving relative order within a family.
    fn normalize_addrs(&mut self) {
        self.addrs.sort_by_key(SocketAddr::is_ipv4); // false (IPv6) < true (IPv4) — stable
        self.addrs.dedup();
    }
}

/// The default per-peer staleness TTL (seconds): a learned candidate not refreshed within this window
/// is treated as stale and dropped from the read-back set. 1 hour — long enough that a transiently
/// unreachable peer survives to be retried, short enough that a churned-away peer ages out.
pub const DEFAULT_TTL_SECS: u64 = 3600;

/// The default capacity (number of distinct peers). Bounds the book so a chatty PEX source cannot make
/// it grow unbounded; when full, the stalest entry is evicted on insert.
pub const DEFAULT_CAPACITY: usize = 4096;

/// A durable, IPv6-first, provenance + TTL address book. Cheap to clone-share via `Arc`; all mutation
/// is behind an internal mutex (address traffic is low-rate, so contention is negligible).
pub struct AddressBook {
    ttl_secs: u64,
    capacity: usize,
    entries: Mutex<HashMap<String, CandidateAddr>>,
}

impl std::fmt::Debug for AddressBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressBook")
            .field("ttl_secs", &self.ttl_secs)
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish()
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new(DEFAULT_TTL_SECS, DEFAULT_CAPACITY)
    }
}

impl AddressBook {
    /// A book with an explicit staleness TTL + capacity.
    #[must_use]
    pub fn new(ttl_secs: u64, capacity: usize) -> Self {
        AddressBook {
            ttl_secs,
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Ingest a learned candidate (#381 ingest seam): upsert by `peer_id`, unioning its dialable
    /// addresses IPv6-first, freshening `learned_at` to the newer value, and keeping the more-trusted
    /// provenance (a first-hand `PoolDirect`/`GetPeers` observation is not downgraded by a later PEX
    /// hint). When the book is at capacity for a NEW peer, the stalest entry is evicted first.
    pub fn offer(&self, candidate: CandidateAddr) {
        let mut g = self.entries.lock().expect("address_book mutex poisoned");
        match g.get_mut(&candidate.peer_id) {
            Some(existing) => {
                // Union addresses, re-order IPv6-first, dedup.
                existing.addrs.extend(candidate.addrs);
                existing.normalize_addrs();
                // Freshen to the newer sighting.
                existing.learned_at = existing.learned_at.max(candidate.learned_at);
                // Keep the more-trusted provenance (lower rank == more trusted).
                if provenance_rank(candidate.provenance) < provenance_rank(existing.provenance) {
                    existing.provenance = candidate.provenance;
                }
            }
            None => {
                if g.len() >= self.capacity {
                    evict_stalest(&mut g);
                }
                g.insert(candidate.peer_id.clone(), candidate);
            }
        }
    }

    /// All non-stale candidates as of `now` (unix secs), ordered best-first for dial selection:
    /// candidates with a directly-dialable **IPv6** address lead, then other directly-dialable
    /// candidates, then relay-only hints; ties break by most-recently-learned. This is the read-back
    /// that seeds future candidate selection (#381) — IPv6-first per §5.2.
    #[must_use]
    pub fn candidates(&self, now: u64) -> Vec<CandidateAddr> {
        let g = self.entries.lock().expect("address_book mutex poisoned");
        let mut out: Vec<CandidateAddr> = g
            .values()
            .filter(|c| !self.is_stale(c, now))
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            dial_class(a)
                .cmp(&dial_class(b))
                .then(b.learned_at.cmp(&a.learned_at))
                .then(a.peer_id.cmp(&b.peer_id))
        });
        out
    }

    /// The non-stale candidates that carry at least one directly-dialable address (relay-only hints
    /// excluded), ordered best-first as in [`Self::candidates`]. The dial-selection source (#384).
    #[must_use]
    pub fn dialable_candidates(&self, now: u64) -> Vec<CandidateAddr> {
        self.candidates(now)
            .into_iter()
            .filter(|c| !c.is_relay_only())
            .collect()
    }

    /// Number of entries currently held (incl. stale-but-not-yet-evicted).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("address_book mutex poisoned")
            .len()
    }

    /// Whether the book holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the book knows `peer_id` (any freshness).
    #[must_use]
    pub fn contains(&self, peer_id: &str) -> bool {
        self.entries
            .lock()
            .expect("address_book mutex poisoned")
            .contains_key(peer_id)
    }

    fn is_stale(&self, c: &CandidateAddr, now: u64) -> bool {
        now.saturating_sub(c.learned_at) > self.ttl_secs
    }
}

/// Provenance trust rank — LOWER is more trusted. A first-hand pool sighting outranks a `getPeers`
/// answer, which outranks an introducer entry, which outranks an unverified PEX hint.
fn provenance_rank(p: AddrProvenance) -> u8 {
    match p {
        AddrProvenance::PoolDirect => 0,
        AddrProvenance::GetPeers => 1,
        AddrProvenance::Introducer => 2,
        AddrProvenance::Pex => 3,
    }
}

/// Dial-preference class — LOWER dials first: a directly-dialable IPv6 candidate, then another
/// directly-dialable candidate (IPv4), then a relay-only hint.
fn dial_class(c: &CandidateAddr) -> u8 {
    if c.has_ipv6() {
        0
    } else if !c.is_relay_only() {
        1
    } else {
        2
    }
}

/// Evict the single stalest (oldest `learned_at`) entry — the capacity backstop on insert.
fn evict_stalest(map: &mut HashMap<String, CandidateAddr>) {
    if let Some(key) = map
        .iter()
        .min_by_key(|(_, c)| c.learned_at)
        .map(|(k, _)| k.clone())
    {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexid(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }
    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new("2001:db8::1".parse().unwrap(), port)
    }
    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new("203.0.113.7".parse().unwrap(), port)
    }

    #[test]
    fn new_orders_addresses_ipv6_first_and_dedups() {
        let c = CandidateAddr::new(
            hexid(1),
            vec![v4(9), v6(9), v4(9)],
            AddrProvenance::Pex,
            100,
        );
        assert_eq!(c.addrs, vec![v6(9), v4(9)], "IPv6 leads, duplicate dropped");
        assert!(c.has_ipv6());
        assert!(!c.is_relay_only());
    }

    #[test]
    fn relay_only_candidate_has_no_addrs() {
        let c = CandidateAddr::new(hexid(2), vec![], AddrProvenance::Pex, 100);
        assert!(c.is_relay_only());
        assert!(!c.has_ipv6());
    }

    /// #387 regression: a relay-only PEX hint SURVIVES into the book (it is not dial-and-dropped).
    #[test]
    fn relay_only_hint_persists_in_the_book() {
        let book = AddressBook::new(DEFAULT_TTL_SECS, DEFAULT_CAPACITY);
        book.offer(CandidateAddr::new(
            hexid(3),
            vec![],
            AddrProvenance::Pex,
            100,
        ));
        assert!(book.contains(&hexid(3)), "relay-only hint must persist");
        // It appears in the full candidate list (seeding future selection) but NOT the dialable set.
        assert_eq!(book.candidates(100).len(), 1);
        assert!(book.dialable_candidates(100).is_empty());
    }

    #[test]
    fn offer_upserts_unions_addresses_and_freshens() {
        let book = AddressBook::new(DEFAULT_TTL_SECS, DEFAULT_CAPACITY);
        book.offer(CandidateAddr::new(
            hexid(4),
            vec![v4(9)],
            AddrProvenance::Pex,
            100,
        ));
        book.offer(CandidateAddr::new(
            hexid(4),
            vec![v6(9)],
            AddrProvenance::GetPeers,
            200,
        ));
        assert_eq!(book.len(), 1, "same peer upserts, not duplicates");
        let c = &book.candidates(200)[0];
        assert_eq!(
            c.addrs,
            vec![v6(9), v4(9)],
            "addresses unioned + IPv6-first"
        );
        assert_eq!(c.learned_at, 200, "freshened to newer sighting");
        assert_eq!(
            c.provenance,
            AddrProvenance::GetPeers,
            "more-trusted provenance kept"
        );
    }

    #[test]
    fn later_pex_hint_does_not_downgrade_first_hand_provenance() {
        let book = AddressBook::new(DEFAULT_TTL_SECS, DEFAULT_CAPACITY);
        book.offer(CandidateAddr::new(
            hexid(5),
            vec![v6(9)],
            AddrProvenance::PoolDirect,
            100,
        ));
        book.offer(CandidateAddr::new(
            hexid(5),
            vec![v6(9)],
            AddrProvenance::Pex,
            150,
        ));
        assert_eq!(
            book.candidates(150)[0].provenance,
            AddrProvenance::PoolDirect
        );
    }

    #[test]
    fn candidates_are_ipv6_first_then_dialable_then_relay_only() {
        let book = AddressBook::new(DEFAULT_TTL_SECS, DEFAULT_CAPACITY);
        book.offer(CandidateAddr::new(
            hexid(0x10),
            vec![],
            AddrProvenance::Pex,
            100,
        )); // relay-only
        book.offer(CandidateAddr::new(
            hexid(0x11),
            vec![v4(9)],
            AddrProvenance::Pex,
            100,
        )); // v4
        book.offer(CandidateAddr::new(
            hexid(0x12),
            vec![v6(9)],
            AddrProvenance::Pex,
            100,
        )); // v6
        let ordered: Vec<String> = book
            .candidates(100)
            .into_iter()
            .map(|c| c.peer_id)
            .collect();
        assert_eq!(ordered, vec![hexid(0x12), hexid(0x11), hexid(0x10)]);
        // dialable_candidates drops the relay-only tail, keeps IPv6-first.
        let dialable: Vec<String> = book
            .dialable_candidates(100)
            .into_iter()
            .map(|c| c.peer_id)
            .collect();
        assert_eq!(dialable, vec![hexid(0x12), hexid(0x11)]);
    }

    #[test]
    fn stale_candidates_are_dropped_from_readback() {
        let book = AddressBook::new(10, DEFAULT_CAPACITY);
        book.offer(CandidateAddr::new(
            hexid(6),
            vec![v6(9)],
            AddrProvenance::Pex,
            100,
        ));
        assert_eq!(book.candidates(105).len(), 1, "within TTL: present");
        assert!(
            book.candidates(200).is_empty(),
            "past TTL: dropped from readback"
        );
        assert!(
            book.contains(&hexid(6)),
            "still held until evicted/refreshed"
        );
    }

    #[test]
    fn capacity_evicts_the_stalest_on_new_insert() {
        let book = AddressBook::new(DEFAULT_TTL_SECS, 2);
        book.offer(CandidateAddr::new(
            hexid(7),
            vec![v6(9)],
            AddrProvenance::Pex,
            100,
        )); // stalest
        book.offer(CandidateAddr::new(
            hexid(8),
            vec![v6(9)],
            AddrProvenance::Pex,
            200,
        ));
        book.offer(CandidateAddr::new(
            hexid(9),
            vec![v6(9)],
            AddrProvenance::Pex,
            300,
        )); // evicts 7
        assert_eq!(book.len(), 2);
        assert!(!book.contains(&hexid(7)), "stalest evicted");
        assert!(book.contains(&hexid(8)) && book.contains(&hexid(9)));
    }
}
