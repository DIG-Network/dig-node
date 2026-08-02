//! Cache relevance + tier model + eviction precedence — the pure "brain" the
//! on-disk LRU cache (see [`crate`] `DIG_NODE_CACHE_CAP`) will later consult to
//! decide WHAT to keep, WHAT to sacrifice first, and WHEN a new candidate is
//! worth displacing an incumbent.
//!
//! Everything here is PURE and deterministic: no clock, no network, no
//! `Instant::now`, no I/O. Time enters only as caller-supplied tick counters
//! (`reads_recency_ticks`, `last_access_ticks`). This makes the whole scoring
//! model trivially testable and reproducible — the same inputs always yield the
//! same score, so eviction decisions can be replayed and audited.

/// Placeholder — real signatures land in the TDD phase.
pub fn __scaffold() {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_fails_until_implemented() {
        // Red anchor: intentionally failing so the branch has a red test before
        // the real relevance core is written (TDD §2.1).
        assert!(false, "relevance core not yet implemented");
    }
}
