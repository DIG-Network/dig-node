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
//!    signal, so the demanded store is tagged `Tier1Demand`, its demand count feeds
//!    [`relevance`](crate::relevance::relevance)'s local-demand term, and the tier gives it eviction
//!    precedence over speculative `Tier0Precache`.
//!
//! # Why this ledger exists
//! The on-disk LRU cache (see [`crate`] `DIG_NODE_CACHE_CAP`) keys entries by path and orders them by
//! file mtime alone — it carries NO per-entry acquisition tier. This ledger is the FIRST live
//! tier-tagging: a small, additive, in-memory map that records WHICH stores a peer has demanded and
//! at what tier, WITHOUT touching the `.dig` format or the on-disk cache layout. It is the source the
//! relevance demand term + the tier-based eviction precedence consult for peer-demanded stores.
//! Process-lifetime (never persisted) — like the other §7.9 runtime counters, it resets each start.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::relevance::CacheTier;

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

/// The node's live inbound-demand ledger: `store_id_hex -> DemandRecord`.
///
/// In-memory + process-lifetime; additive over the on-disk cache (nothing here changes the `.dig`
/// format or the LRU layout). Interior-mutable behind a [`Mutex`] so a `&self` serve handler can
/// record demand without an exclusive borrow. A poisoned lock is recovered (`into_inner`) rather than
/// panicked on: a demand record is advisory cache metadata, never a correctness invariant, so losing
/// atomicity on one bump must not take the node down.
#[derive(Debug, Default)]
pub struct InboundDemand {
    records: Mutex<HashMap<String, DemandRecord>>,
}

impl InboundDemand {
    /// A fresh, empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record ONE inbound peer request for `store_id_hex`: tag it
    /// [`Tier1Demand`](CacheTier::Tier1Demand) and bump its saturating demand count. Returns the
    /// updated record. The caller is responsible for only recording canonical store ids.
    pub fn record(&self, store_id_hex: &str) -> DemandRecord {
        let mut map = self.records.lock().unwrap_or_else(|p| p.into_inner());
        let rec = map.entry(store_id_hex.to_string()).or_insert(DemandRecord {
            count: 0,
            tier: CacheTier::Tier1Demand,
        });
        rec.count = rec.count.saturating_add(1);
        // Inbound demand always asserts Tier1 — re-affirmed on every bump so no other path can leave
        // a peer-demanded store tagged below Tier1.
        rec.tier = CacheTier::Tier1Demand;
        *rec
    }

    /// The demand count for `store_id_hex` (0 if never demanded). Feeds
    /// [`RelevanceInputs::local_read_count`](crate::relevance::RelevanceInputs::local_read_count) —
    /// inbound peer demand counts toward the same saturating local-demand term as a local read.
    #[must_use]
    pub fn count(&self, store_id_hex: &str) -> u32 {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(store_id_hex)
            .map_or(0, |r| r.count)
    }

    /// The tier `store_id_hex` is tagged with, or `None` if it has no recorded inbound demand.
    #[must_use]
    pub fn tier(&self, store_id_hex: &str) -> Option<CacheTier> {
        self.records
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(store_id_hex)
            .map(|r| r.tier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
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
}
