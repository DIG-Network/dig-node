//! Sync-state-gated source selection (design **B.6** routing table).
//!
//! Every wallet-data read chooses its source from two axes — whether the local DB has
//! completed its initial catch-up, and whether the read is scoped to the wallet's own
//! tracked data — reproducing the B.6 table exactly:
//!
//! | Condition                                             | Source                    |
//! |-------------------------------------------------------|---------------------------|
//! | Wallet's own data, DB synced to peak                  | [`Source::Db`]            |
//! | Wallet's own data, DB still syncing                   | [`Source::Fallback`]      |
//! | Chain data not scoped to this wallet, not in the DB   | [`Source::Fallback`]      |
//!
//! The gate is intentionally a tiny pure function so it is trivially unit-testable and
//! has a single, auditable definition; the RPC layer calls it once per wallet-data read.

/// Where a wallet-data read is served from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The local SQLite wallet DB (peer-maintained, design B.3/B.6).
    Db,
    /// The `chia-query`/coinset.org fallback tier (design B.5).
    Fallback,
}

/// Select the source for a wallet-data read given the two B.6 axes.
///
/// - `db_synced`: has the initial subscription catch-up completed
///   ([`crate::sage::db::WalletDb::is_synced`])?
/// - `scoped_to_wallet`: is the read about the wallet's own tracked data (its puzzle
///   hashes / CAT hints), as opposed to an arbitrary chain lookup?
pub fn route(db_synced: bool, scoped_to_wallet: bool) -> Source {
    match (db_synced, scoped_to_wallet) {
        // Synced + wallet-scoped → the local DB is authoritative.
        (true, true) => Source::Db,
        // Wallet-scoped but still syncing → don't make the caller wait for convergence.
        (false, true) => Source::Fallback,
        // Not scoped to this wallet (arbitrary chain read, not in the DB) → fallback,
        // regardless of sync state.
        (_, false) => Source::Fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synced_wallet_data_reads_from_db() {
        assert_eq!(route(true, true), Source::Db);
    }

    #[test]
    fn syncing_wallet_data_falls_back_so_caller_does_not_wait() {
        assert_eq!(route(false, true), Source::Fallback);
    }

    #[test]
    fn non_wallet_chain_reads_always_fall_back() {
        assert_eq!(route(true, false), Source::Fallback);
        assert_eq!(route(false, false), Source::Fallback);
    }
}
