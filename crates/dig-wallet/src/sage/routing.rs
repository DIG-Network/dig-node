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
///
/// This is also the WIRE spelling of the tier (`"db"` / `"fallback"`), reported on every
/// read result that makes a tier choice (#2233). One definition serves both the routing
/// decision and its disclosure, so the reported tier cannot drift from the tier taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// The local SQLite wallet DB (peer-maintained, design B.3/B.6).
    Db,
    /// The `chia-query`/coinset.org fallback tier (design B.5).
    Fallback,
}

impl Source {
    /// The wire/log spelling of this tier — the SAME string [`serde::Serialize`] emits.
    ///
    /// Used for the `tier` field on the routing `tracing` event, so a log line and the JSON
    /// result a caller reads always name the tier identically.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Db => "db",
            Self::Fallback => "fallback",
        }
    }
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

    /// The wire spelling and the log spelling are the SAME string, pinned literally so a
    /// rename of the Rust variant cannot silently change what a consumer parses (#2233).
    #[test]
    fn tier_serializes_and_logs_as_the_same_lowercase_wire_string() {
        for (src, wire) in [(Source::Db, "db"), (Source::Fallback, "fallback")] {
            assert_eq!(serde_json::to_value(src).unwrap(), serde_json::json!(wire));
            assert_eq!(src.as_wire(), wire);
        }
    }
}
