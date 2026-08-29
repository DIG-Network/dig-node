//! **The census runner** — the half of the collateral record store that reads the chain.
//!
//! [`crate::collateral`] owns what a node STORES and what it will serve; this module owns how a
//! record for an epoch after the first comes to exist at all. Before it, a node's store held
//! exactly one record — [`dig_mirror_collateral::EpochRecord::bootstrap`], which is derivable from
//! nothing — so `control.collateral.requirement` answered `unknown / not_censused` for the current
//! epoch correctly and permanently (dig-node#400).
//!
//! # Nothing here is arithmetic
//!
//! Every number this module writes is produced by a call: [`dig_mirror_coin::census`] counts the
//! network, and [`dig_mirror_collateral::EpochRecord::advance`] derives the record. Restating
//! either — even as an apparently harmless `equilibrium × multiplier − handicap` — drops the floor
//! clamp and yields a second price the network does not agree with. This module chooses WHICH
//! epochs to compute and WHERE to put the answers, and nothing else.
//!
//! # A census that could not be taken is never a figure
//!
//! Each reason a catch-up stops is a distinct [`CensusStop`] variant carrying what an operator
//! would need to act on it, and a stop writes NOTHING. There is no default record, no zeroed
//! census, and no reuse of a neighbouring epoch's answer: those are all ways of turning "this node
//! could not look" into a number that reads exactly like one it did look up. The store's own
//! absence then surfaces as `unknown` with its reason, which is the honest answer.
//!
//! # The walk is sequential because the model is
//!
//! Epoch *n*'s record is derived from epoch *n-1*'s, so a node cannot skip forward to the current
//! epoch: it computes each intervening epoch in order, from the newest record it holds. A node
//! that has been offline for three epochs performs three censuses, at three heights consensus
//! already agrees on, and arrives at the same records as a node that never stopped.

use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::{census, census_height, CensusOutcome, MirrorError};

use crate::collateral::{
    EpochRecordStore, PutOutcome, StoredEpoch, StoredRecord, GENESIS_EPOCH,
};

/// Why a catch-up stopped before reaching the target epoch.
///
/// Every variant is a reason to write nothing, and each names a DIFFERENT remedy — which is why
/// they are not collapsed into one string. "Wait for the chain to bury the census height" and
/// "this node cannot reach a chain at all" are the same silence to a caller who only sees
/// `unknown`, and opposite situations to an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CensusStop {
    /// A chain read could not be answered. The census is absent, not empty.
    ChainUnavailable {
        /// The epoch being computed when the read failed.
        epoch: u64,
        /// The source's own words.
        detail: String,
    },

    /// The chain has not yet reached the epoch's start instant.
    ///
    /// The ordinary state of an epoch that has begun by the clock but not yet on chain, and not an
    /// error: the remedy is to wait for a block.
    EpochNotStartedOnChain {
        /// The epoch whose start the chain has not reached.
        epoch: u64,
    },

    /// The census height is not yet buried deeply enough for its answer to be safe to act on.
    ///
    /// A census taken at the tip is reorg-sensitive and this is a money path. The remedy is only to
    /// wait — roughly ten minutes out of a seven-day epoch.
    BehindFinalityDepth {
        /// The epoch that would be censused.
        epoch: u64,
        /// The height it would be censused at.
        census_height: u32,
        /// The source's current peak.
        peak_height: u32,
    },

    /// The candidate population at the shared mirror puzzle hash exceeds what can be authenticated.
    ///
    /// `dig-mirror-coin` REFUSES rather than censusing a prefix, because a prefix of an
    /// attacker-writable set is a censorship primitive and two nodes keeping different prefixes
    /// fork. This node reports the refusal for the same reason.
    PopulationTooLarge {
        /// The epoch that would be censused.
        epoch: u64,
        /// The height it would be censused at.
        census_height: u32,
        /// How many coins pay to the shared mirror puzzle hash.
        candidates: usize,
        /// How many distinct creating spends the survivors would have needed executed.
        creating_spends: usize,
        /// The bound that was exceeded.
        limit: usize,
    },

    /// The predecessor epoch is not recorded, so there is nothing to derive this one from.
    ///
    /// Unreachable from the shipped bring-up, which writes the genesis record before this runs, and
    /// kept because a store pruned to a retention boundary can reach it.
    PriorEpochMissing {
        /// The epoch whose record is absent.
        epoch: u64,
    },

    /// The predecessor epoch's stored line could not be read.
    PriorEpochUnreadable {
        /// The epoch whose record could not be read.
        epoch: u64,
    },

    /// The predecessor record names a ruleset this build does not implement.
    ///
    /// The protocol-version ceiling, applied at the CENSUS boundary as well as at the serve and
    /// gossip boundaries. Deriving a successor from a record whose arithmetic this build does not
    /// have would compute a figure under the wrong ruleset and store it as though it were checked.
    PriorEpochUninterpretable {
        /// The epoch whose record names the unimplemented ruleset.
        epoch: u64,
        /// The version it names.
        protocol_version: u16,
    },

    /// The controller refused to derive the record.
    Arithmetic {
        /// The epoch being derived.
        epoch: u64,
        /// The controller's own words.
        detail: String,
    },

    /// This node already holds a DIFFERENT record for the epoch it just computed.
    ///
    /// History is immutable, so the held record stands and the walk stops: every later epoch would
    /// be derived from a record this node and its own store disagree about.
    Contradiction {
        /// The epoch the stored record disagrees about.
        epoch: u64,
    },

    /// The record store could not be read or written.
    Store {
        /// The underlying I/O error.
        detail: String,
    },
}

/// What one catch-up did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUp {
    /// The epochs newly recorded, in ascending order. Empty is the ordinary steady state: a node
    /// already current has nothing to compute and performs no chain read at all.
    pub recorded: Vec<u64>,
    /// Why the walk stopped short of the target, or `None` when it reached it.
    pub stopped: Option<CensusStop>,
}

/// Compute and record every epoch from the newest one `store` holds up to `target_epoch`.
///
/// Returns what it recorded and, when it stopped early, why. **A stop writes nothing**: this
/// function never invents, defaults, or carries forward a figure.
///
/// The walk performs NO chain read when the store is already current, so calling it on a timer is
/// cheap in the steady state.
///
/// # The census height is derived, never chosen
///
/// Each epoch is censused at the first transaction block at or after that epoch's start instant
/// ([`dig_mirror_coin::census_height`]). Every node therefore censuses at the same height without
/// coordinating, which is the property that makes the requirement a consensus figure rather than
/// each node's local opinion.
pub fn catch_up<S: ChainSource>(
    source: &S,
    store: &EpochRecordStore,
    target_epoch: u64,
) -> CatchUp {
    let mut recorded = Vec::new();

    let highest = match highest_recorded(store) {
        Ok(highest) => highest,
        Err(detail) => {
            return CatchUp {
                recorded,
                stopped: Some(CensusStop::Store { detail }),
            }
        }
    };

    for epoch in (highest + 1)..=target_epoch {
        match record_one(source, store, epoch) {
            Ok(()) => recorded.push(epoch),
            Err(stopped) => {
                return CatchUp {
                    recorded,
                    stopped: Some(stopped),
                }
            }
        }
    }

    CatchUp {
        recorded,
        stopped: None,
    }
}

/// The newest epoch `store` holds a record for.
///
/// Falls back to [`GENESIS_EPOCH`] when the store holds nothing, so a walk from a store the
/// bring-up has not yet seeded still starts at the only epoch that could follow one.
fn highest_recorded(store: &EpochRecordStore) -> Result<u64, String> {
    let records = store.records().map_err(|e| e.to_string())?;
    Ok(records
        .iter()
        .map(|stored| stored.record.epoch)
        .max()
        .unwrap_or(GENESIS_EPOCH))
}

/// Census `epoch` and write its record, or say why it could not be written.
fn record_one<S: ChainSource>(
    source: &S,
    store: &EpochRecordStore,
    epoch: u64,
) -> Result<(), CensusStop> {
    let prior = prior_record(store, epoch)?;

    let at = match census_height(source, epoch_start_unix_secs(epoch)) {
        Ok(Some(at)) => at,
        Ok(None) => return Err(CensusStop::EpochNotStartedOnChain { epoch }),
        Err(e) => return Err(chain_stop(epoch, e)),
    };

    let counted = match census(source, &prior, at) {
        Ok(CensusOutcome::Final(counted)) => counted,
        Ok(CensusOutcome::Pending {
            census_height,
            peak_height,
        }) => {
            return Err(CensusStop::BehindFinalityDepth {
                epoch,
                census_height,
                peak_height,
            })
        }
        Ok(CensusOutcome::Incomplete {
            census_height,
            candidates,
            creating_spends,
            limit,
        }) => {
            return Err(CensusStop::PopulationTooLarge {
                epoch,
                census_height,
                candidates,
                creating_spends,
                limit,
            })
        }
        Err(e) => return Err(chain_stop(epoch, e)),
    };

    // The whole derivation, in one call. `advance` applies this epoch's ruleset, re-checks the
    // protocol version on both sides, and produces the record — including the floor clamp that a
    // restated formula loses.
    let record = prior
        .advance(counted.census())
        .map_err(|e| CensusStop::Arithmetic {
            epoch,
            detail: e.to_string(),
        })?;

    // `censused`, with the height the census was actually taken at — the two facts that make this
    // record auditable and distinguish it from one adopted from peers.
    let stored = StoredRecord::censused(record, counted.height());
    match store.put(&stored) {
        Ok(PutOutcome::Written | PutOutcome::AlreadyPresent) => Ok(()),
        Ok(PutOutcome::Conflict { .. }) => Err(CensusStop::Contradiction { epoch }),
        Err(e) => Err(CensusStop::Store {
            detail: e.to_string(),
        }),
    }
}

/// The record `epoch` is derived from — epoch `epoch - 1` — refusing anything this build cannot
/// interpret.
fn prior_record(
    store: &EpochRecordStore,
    epoch: u64,
) -> Result<dig_mirror_collateral::EpochRecord, CensusStop> {
    let prior_epoch = epoch.saturating_sub(1);
    match store.get(prior_epoch) {
        StoredEpoch::Found(stored) if !stored.is_interpretable() => {
            Err(CensusStop::PriorEpochUninterpretable {
                epoch: prior_epoch,
                protocol_version: stored.record.protocol_version.0,
            })
        }
        StoredEpoch::Found(stored) => Ok(stored.record),
        StoredEpoch::Absent => Err(CensusStop::PriorEpochMissing { epoch: prior_epoch }),
        StoredEpoch::Unreadable => Err(CensusStop::PriorEpochUnreadable { epoch: prior_epoch }),
    }
}

/// Map a [`MirrorError`] onto the stop it describes.
///
/// Every variant lands on [`CensusStop::ChainUnavailable`] deliberately: from this walk's point of
/// view a malformed answer and an unreachable source are the same fact — the census could not be
/// taken — and neither may become a figure. The error's own words carry the difference to the log.
fn chain_stop(epoch: u64, error: MirrorError) -> CensusStop {
    CensusStop::ChainUnavailable {
        epoch,
        detail: error.to_string(),
    }
}

/// The Unix-second instant `epoch` begins at.
///
/// Delegated to `dig_constants::mirror_epoch_start_unix_ms`, never re-derived: the epoch schedule
/// is a consensus fact, and a node that placed an epoch boundary one second differently would
/// census at a different height and derive a different requirement from the same chain.
///
/// `div_euclid` rather than `/`, so an instant before the Unix epoch would floor rather than
/// truncate toward zero. No epoch in the schedule is before 1970; the operator is chosen for the
/// property rather than for the case, because a truncating divide is silently wrong only where it
/// is hard to notice.
fn epoch_start_unix_secs(epoch: u64) -> u64 {
    let start_ms = dig_constants::mirror_epoch_start_unix_ms(epoch as i64);
    start_ms.div_euclid(1_000).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_chainsource_interface::CoinRecord;
    use dig_mirror_collateral::EpochRecord;
    use std::cell::RefCell;

    /// A source that answers nothing, for the reason it was asked.
    ///
    /// It counts its reads, because "the walk stopped" and "the walk never looked" are different
    /// outcomes that produce the same empty store.
    struct UnreachableSource {
        reads: RefCell<u32>,
    }

    impl UnreachableSource {
        fn new() -> Self {
            Self {
                reads: RefCell::new(0),
            }
        }

        fn reads(&self) -> u32 {
            *self.reads.borrow()
        }

        fn refuse<T>(&self) -> Result<T, String> {
            *self.reads.borrow_mut() += 1;
            Err("no chain source reachable".to_string())
        }
    }

    impl ChainSource for UnreachableSource {
        type Error = String;

        fn coin_record(
            &self,
            _coin_id: chia_protocol::Bytes32,
        ) -> Result<Option<CoinRecord>, Self::Error> {
            self.refuse()
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: chia_protocol::Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.refuse()
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: chia_protocol::Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.refuse()
        }

        fn coin_spend(
            &self,
            _coin_id: chia_protocol::Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            self.refuse()
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: chia_protocol::Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            self.refuse()
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.refuse()
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            self.refuse()
        }
    }

    /// A store in a fresh temp dir, holding only the genesis record the bring-up writes.
    fn seeded_store(name: &str) -> (EpochRecordStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "dig-node-census-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create the scratch dir");
        let store = EpochRecordStore::at(dir.join("epochs.jsonl"));
        store
            .put(&StoredRecord::bootstrap())
            .expect("seed the genesis record");
        (store, dir)
    }

    /// **A node that cannot reach a chain records NOTHING and says why.**
    ///
    /// The defect this whole module exists to avoid re-introducing: an unreachable source must not
    /// become an empty census, which `advance` would happily turn into a real-looking requirement.
    /// The assertion is on the STORE as well as the report — a stop that still wrote a record would
    /// satisfy a report-only assertion.
    #[test]
    fn an_unreachable_chain_records_nothing_and_names_the_reason() {
        let (store, dir) = seeded_store("unreachable");
        let source = UnreachableSource::new();

        let outcome = catch_up(&source, &store, 5);

        assert!(
            outcome.recorded.is_empty(),
            "a node that could not read the chain recorded {:?}",
            outcome.recorded
        );
        assert!(
            matches!(
                outcome.stopped,
                Some(CensusStop::ChainUnavailable { epoch: 2, .. })
            ),
            "expected an unavailable-chain stop on the first uncomputed epoch, got {:?}",
            outcome.stopped
        );
        assert!(source.reads() > 0, "the walk never attempted a chain read");
        assert!(
            matches!(store.get(2), StoredEpoch::Absent),
            "epoch 2 was written despite the census failing"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **A node already current performs NO chain read.**
    ///
    /// The steady state, and the property that makes running this on a timer cheap. It is asserted
    /// against a source that fails on every read: if the walk touched the chain at all the target
    /// would be unreachable and `stopped` would be `Some`.
    #[test]
    fn a_store_already_at_the_target_reads_no_chain() {
        let (store, dir) = seeded_store("current");
        let source = UnreachableSource::new();

        let outcome = catch_up(&source, &store, GENESIS_EPOCH);

        assert_eq!(outcome.recorded, Vec::<u64>::new());
        assert_eq!(outcome.stopped, None, "a current store stopped for a reason");
        assert_eq!(
            source.reads(),
            0,
            "a current store still performed a chain read"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **The walk refuses to derive a successor from a record whose ruleset this build lacks.**
    ///
    /// The protocol-version ceiling at the census boundary. Without it, a record written under a
    /// future ruleset would be advanced under v1 arithmetic and the result stored as `censused` —
    /// a figure this node never had the rules to compute, wearing the provenance of one it did.
    ///
    /// The prior epoch is 2 rather than 1 so the refusal cannot be confused with the genesis
    /// record's own handling, and the target is 4 so a walk that ignored the ceiling would have a
    /// further epoch to attempt.
    #[test]
    fn a_prior_record_from_an_unimplemented_ruleset_is_refused() {
        let (store, dir) = seeded_store("ceiling");

        // A record for epoch 2 naming a ruleset far beyond anything implemented. Every field of it
        // parses, which is exactly why the ceiling has to be checked rather than inferred.
        let mut future = EpochRecord::bootstrap();
        future.epoch = 2;
        future.protocol_version = dig_mirror_collateral::ProtocolVersion(u16::MAX);
        store
            .put(&StoredRecord::censused(future, 1_000))
            .expect("write the future-ruleset record");

        let source = UnreachableSource::new();
        let outcome = catch_up(&source, &store, 4);

        assert!(outcome.recorded.is_empty());
        assert_eq!(
            outcome.stopped,
            Some(CensusStop::PriorEpochUninterpretable {
                epoch: 2,
                protocol_version: u16::MAX,
            }),
        );
        assert_eq!(
            source.reads(),
            0,
            "the ceiling was checked after a chain read rather than before one"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **Epoch starts come from the schedule, and consecutive epochs are one epoch length apart.**
    ///
    /// Pinned because this is the one arithmetic in the module, and a census height derived from a
    /// boundary one second out is a fork. Both sides are asserted: the absolute instant of epoch 1
    /// (so a wrong genesis is caught) and the spacing (so a wrong length is).
    #[test]
    fn epoch_starts_follow_the_published_schedule() {
        let first = epoch_start_unix_secs(1);
        let second = epoch_start_unix_secs(2);

        assert_eq!(
            first,
            (dig_constants::MIRROR_EPOCH_GENESIS_UNIX_MS.div_euclid(1_000)) as u64,
            "epoch 1 does not start at the published genesis instant"
        );
        assert_eq!(
            second - first,
            (dig_constants::MIRROR_EPOCH_LENGTH_MS.div_euclid(1_000)) as u64,
            "consecutive epoch starts are not one epoch length apart"
        );
    }
}
