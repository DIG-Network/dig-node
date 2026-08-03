//! Inbound-demand ledger — the live, in-memory tier-tagging of stores a PEER has asked us to serve.
//!
//! # Two distinct tier-1 caching triggers
//! Epic #1934 settles that a store earns [`Tier1Demand`](crate::relevance::CacheTier::Tier1Demand)
//! from EITHER of two independent kinds of real demand:
//!
//! 1. **Fetch-side backfill (SPEC §5.6 / §14.3).** THIS node reads a resource it does not hold, is
//!    served it from another node, and background-pulls the whole `.dig` so its NEXT read is local.
//!    This is what THIS node fetched — gated `ReadOrigin::Local` to stay amplification-safe.
//! 2. **Inbound demand (this module, #1990).** A remote PEER asks US for a resource from a store —
//!    direct evidence this node's neighbourhood WANTS that content. A peer's request is the demand
//!    signal, so the demanded store is tagged `Tier1Demand` (via
//!    [`Node::module_tier`](crate::Node)), which gives it eviction precedence over speculative
//!    `Tier0Precache` — the KEEP mechanism the modules-cache sweep consults (#2013).
//!
//! # Why this ledger exists
//! The on-disk LRU cache (see [`crate`] `DIG_NODE_CACHE_CAP`) keys entries by path and orders them by
//! file mtime alone — it carries NO per-entry acquisition tier. This ledger is the FIRST live
//! tier-tagging: a small, additive, in-memory map that records WHICH stores a peer has demanded and
//! at what tier, WITHOUT touching the `.dig` format or the on-disk cache layout. It is the source the
//! tier-based eviction precedence consults for peer-demanded stores.
//! Process-lifetime (never persisted) — like the other §7.9 runtime counters, it resets each start.
//!
//! # Bounded against remote memory-exhaustion (load-bearing)
//! Recording is ALWAYS-ON (it runs before the pull gate, in the default config) and is fed by a
//! REMOTE peer — the store id comes off the wire and `is_canonical_hex_id` checks only 64-hex FORMAT,
//! not that the store exists. Any peer that completes the mTLS handshake can therefore name arbitrary
//! distinct 64-hex points from the 2^256 keyspace, and dedup gives no protection against DISTINCT
//! ids. An unbounded map would let cheap requests mint permanent entries until the node OOMs. So the
//! ledger is a BOUNDED LRU: at most [`MAX_DEMAND_ENTRIES`], evicting the least-recently-demanded entry
//! on overflow. Memory is bounded by the cap regardless of remote request volume; a re-demanded store
//! is refreshed (survives over colder entries), so genuine demand is retained while spam churns
//! through the cap.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use crate::relevance::CacheTier;

/// The maximum number of distinct stores the inbound-demand ledger retains. On overflow the
/// least-recently-demanded entry is evicted (LRU).
///
/// Sized for real demand, not for spam: a node that legitimately serves many stores is well covered
/// at 65_536 distinct stores, while the worst-case memory stays bounded and small — each entry is a
/// 64-byte hex key + a fixed record + the recency-index key, on the order of ~200 bytes with heap
/// overhead, so a fully-saturated ledger is roughly ten-odd MiB. That ceiling holds no matter how
/// many distinct ids a remote peer names, which is the whole point (see the module's DoS note).
pub const MAX_DEMAND_ENTRIES: usize = 65_536;

/// One store's inbound-demand record: how many times a peer has requested a resource from it, and
/// the acquisition tier that demand assigns. The tier is ALWAYS
/// [`Tier1Demand`](CacheTier::Tier1Demand) — a peer's request is real demand, never a speculative
/// precache bet, so it can never be demoted to `Tier0Precache` by this path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemandRecord {
    /// Count of inbound peer requests observed for this store (saturating at `u32::MAX`).
    pub count: u32,
    /// The acquisition tier this demand assigns — always [`Tier1Demand`](CacheTier::Tier1Demand).
    pub tier: CacheTier,
}

/// A stored entry: the caller-visible [`DemandRecord`] plus the recency tick that orders LRU eviction.
#[derive(Debug, Clone, Copy)]
struct Entry {
    record: DemandRecord,
    /// The logical clock value of this entry's most recent demand; larger = more recently demanded.
    tick: u64,
}

/// The interior state, guarded by one lock: the `store_id_hex -> Entry` map plus a `tick -> key`
/// recency index that makes least-recently-demanded eviction O(log n) without scanning the map. The
/// two are kept in lockstep — every entry has exactly one recency-index slot at its current tick.
#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Entry>,
    recency: BTreeMap<u64, String>,
    clock: u64,
}

/// The node's live inbound-demand ledger: a BOUNDED LRU of `store_id_hex -> DemandRecord`.
///
/// In-memory + process-lifetime; additive over the on-disk cache (nothing here changes the `.dig`
/// format or the LRU layout). Interior-mutable behind a [`Mutex`] so a `&self` serve handler can
/// record demand without an exclusive borrow. A poisoned lock is recovered (`into_inner`) rather than
/// panicked on: a demand record is advisory cache metadata, never a correctness invariant, so losing
/// atomicity on one bump must not take the node down. Capacity is bounded by `cap` (see
/// [`MAX_DEMAND_ENTRIES`] and the module's DoS note).
#[derive(Debug)]
pub struct InboundDemand {
    inner: Mutex<Inner>,
    cap: usize,
}

impl Default for InboundDemand {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundDemand {
    /// A fresh, empty ledger bounded at [`MAX_DEMAND_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_DEMAND_ENTRIES)
    }

    /// A fresh, empty ledger bounded at `cap` entries. `cap` is clamped to at least 1 so the ledger
    /// can always hold the entry it is currently recording.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap: cap.max(1),
        }
    }

    /// Record ONE inbound peer request for `store_id_hex`: tag it
    /// [`Tier1Demand`](CacheTier::Tier1Demand), bump its saturating demand count, and mark it the
    /// most-recently-demanded entry. Returns the updated record. On overflow past the cap, the
    /// least-recently-demanded OTHER entry is evicted first, so the ledger never exceeds `cap`.
    /// The caller is responsible for only recording canonical store ids.
    pub fn record(&self, store_id_hex: &str) -> DemandRecord {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.clock += 1;
        let tick = inner.clock;

        if let Some(entry) = inner.map.get_mut(store_id_hex) {
            // Re-demand: refresh recency (move the recency-index slot to the new tick) and bump.
            let old_tick = entry.tick;
            entry.tick = tick;
            entry.record.count = entry.record.count.saturating_add(1);
            // Inbound demand always asserts Tier1 — re-affirmed on every bump so no other path can
            // leave a peer-demanded store tagged below Tier1.
            entry.record.tier = CacheTier::Tier1Demand;
            let record = entry.record;
            inner.recency.remove(&old_tick);
            inner.recency.insert(tick, store_id_hex.to_string());
            return record;
        }

        // A new store id. Evict the least-recently-demanded entry FIRST if we are at the cap, so a
        // stream of distinct ids churns through a fixed footprint instead of growing without bound.
        if inner.map.len() >= self.cap {
            if let Some((&victim_tick, _)) = inner.recency.iter().next() {
                if let Some(victim_key) = inner.recency.remove(&victim_tick) {
                    inner.map.remove(&victim_key);
                }
            }
        }
        let record = DemandRecord {
            count: 1,
            tier: CacheTier::Tier1Demand,
        };
        inner
            .map
            .insert(store_id_hex.to_string(), Entry { record, tick });
        inner.recency.insert(tick, store_id_hex.to_string());
        record
    }

    /// The demand count for `store_id_hex` (0 if absent/evicted). Feeds
    /// [`RelevanceInputs::local_read_count`](crate::relevance::RelevanceInputs::local_read_count) —
    /// inbound peer demand counts toward the same saturating local-demand term as a local read.
    #[must_use]
    pub fn count(&self, store_id_hex: &str) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map
            .get(store_id_hex)
            .map_or(0, |e| e.record.count)
    }

    /// The tier `store_id_hex` is tagged with, or `None` if it has no live inbound-demand entry.
    #[must_use]
    pub fn tier(&self, store_id_hex: &str) -> Option<CacheTier> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map
            .get(store_id_hex)
            .map(|e| e.record.tier)
    }

    /// The number of live entries — the ledger's own bounded-LRU size. Backs both the
    /// boundedness regression test AND the live `tier1_demand.occupancy` figure `cache.stats`
    /// reports (#1991, epic #1934).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// A distinct 64-hex store id for `n`, so a test can mint many keyspace points cheaply.
    fn store_n(n: u64) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn first_record_tags_tier1_and_counts_one() {
        let ledger = InboundDemand::new();
        let s = store(0xab);
        let rec = ledger.record(&s);
        assert_eq!(rec.count, 1);
        assert_eq!(rec.tier, CacheTier::Tier1Demand);
        assert_eq!(ledger.count(&s), 1);
        assert_eq!(ledger.tier(&s), Some(CacheTier::Tier1Demand));
    }

    #[test]
    fn repeated_demand_accumulates_the_count() {
        let ledger = InboundDemand::new();
        let s = store(0x11);
        for expected in 1..=5 {
            assert_eq!(ledger.record(&s).count, expected);
        }
        assert_eq!(ledger.count(&s), 5);
    }

    #[test]
    fn distinct_stores_count_independently() {
        let ledger = InboundDemand::new();
        let a = store(0x01);
        let b = store(0x02);
        ledger.record(&a);
        ledger.record(&b);
        ledger.record(&b);
        assert_eq!(ledger.count(&a), 1);
        assert_eq!(ledger.count(&b), 2);
    }

    #[test]
    fn an_undemanded_store_is_zero_and_untagged() {
        let ledger = InboundDemand::new();
        let s = store(0xff);
        assert_eq!(ledger.count(&s), 0);
        assert_eq!(ledger.tier(&s), None);
    }

    #[test]
    fn the_tier_is_always_tier1_never_below() {
        // A peer's request is real demand — the ledger must never tag it below Tier1 (which would let
        // speculative precache out-rank genuinely-demanded content in eviction).
        let ledger = InboundDemand::new();
        let s = store(0x42);
        ledger.record(&s);
        let tier = ledger.tier(&s).unwrap();
        assert!(
            tier.rank() >= CacheTier::Tier1Demand.rank(),
            "inbound demand must never tag below Tier1: got rank {}",
            tier.rank()
        );
    }

    /// **Proves (#1990 DoS fix):** the ledger is BOUNDED against distinct-id spam — a remote peer
    /// naming arbitrarily many distinct 64-hex keyspace points from the 2^256 keyspace can never grow
    /// it past the cap (the memory-exhaustion DoS the fix closes).
    /// **Catches:** a regression to the unbounded map.
    #[test]
    fn demand_ledger_is_bounded_against_distinct_id_spam() {
        let cap = 8;
        let ledger = InboundDemand::with_capacity(cap);
        // Far more DISTINCT ids than the cap — length must never exceed it, at any point.
        for n in 0..(cap as u64 * 100) {
            ledger.record(&store_n(n));
            assert!(
                ledger.entry_count() <= cap,
                "distinct-id spam grew the ledger past the cap: len={} cap={cap}",
                ledger.entry_count()
            );
        }
        assert_eq!(ledger.entry_count(), cap, "bounded exactly to the cap");
    }

    /// **Proves (#1990 DoS fix):** eviction is LRU — a re-demanded entry survives a new insertion
    /// that displaces the COLDEST (least-recently-demanded) entry instead.
    /// **Catches:** a non-LRU eviction that drops hot/re-touched entries, or an eviction that drops the
    /// entry being inserted.
    #[test]
    fn eviction_drops_the_least_recently_demanded_entry() {
        let cap = 3;
        let ledger = InboundDemand::with_capacity(cap);
        let (a, b, c, d) = (store_n(0), store_n(1), store_n(2), store_n(3));
        ledger.record(&a); // coldest so far
        ledger.record(&b);
        ledger.record(&c);
        // Re-demand `a` so `b` is now the least-recently-demanded.
        ledger.record(&a);
        // A new id at the cap evicts the coldest — which is now `b`, not the re-touched `a`.
        ledger.record(&d);

        assert_eq!(ledger.entry_count(), cap);
        assert_eq!(ledger.count(&a), 2, "the re-demanded entry survived");
        assert_eq!(
            ledger.count(&b),
            0,
            "the least-recently-demanded entry was evicted"
        );
        assert_eq!(ledger.count(&c), 1, "a warmer entry survived");
        assert_eq!(ledger.count(&d), 1, "the freshly inserted entry is present");
    }

    #[test]
    fn new_defaults_to_the_documented_cap() {
        let ledger = InboundDemand::new();
        // Recording one entry works and the ledger is usable at the default cap; the cap itself is a
        // documented const, asserted here so a silent change to it is caught.
        assert_eq!(MAX_DEMAND_ENTRIES, 65_536);
        ledger.record(&store(0x01));
        assert_eq!(ledger.entry_count(), 1);
    }
}
