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
//! # A census that counted nothing says what it examined
//!
//! A stop is not the only ambiguous outcome. A census that SUCCEEDS and counts zero stores is
//! produced identically by an empty network, by a source answering at the wrong puzzle hash, and by
//! a degraded source whose candidates' creating spends were all unavailable — three situations with
//! opposite remedies, on the path that decides how much collateral this node posts. The walk
//! therefore carries [`CensusObservation`] out for every epoch it records, so the node reports what
//! was examined and why candidates were excluded, and not only the figure it arrived at.
//!
//! # The walk is sequential because the model is
//!
//! Epoch *n*'s record is derived from epoch *n-1*'s, so a node cannot skip forward to the current
//! epoch: it computes each intervening epoch in order, from the newest record it holds. A node
//! that has been offline for three epochs performs three censuses, at three heights consensus
//! already agrees on, and arrives at the same records as a node that never stopped.

use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::{census, census_height, CensusOutcome, Exclusions, MirrorError};

use crate::collateral::{
    EpochRecordStore, PutOutcome, RecordProvenance, StoredEpoch, StoredRecord, GENESIS_EPOCH,
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

    /// The store already holds a line for the epoch being computed, and that line cannot be read.
    ///
    /// Distinct from [`Self::Store`], which is an I/O fault, and from [`Self::Contradiction`],
    /// which is a readable disagreement — this is one rotted line, and its remedy is to repair or
    /// remove that line.
    ///
    /// It is checked BEFORE any chain read, and it is the reason the walk is not silent here.
    /// [`EpochRecordStore::records`] SKIPS unparseable lines while
    /// [`EpochRecordStore::get`] reports them, so a line for epoch *n* truncated by a crash or a
    /// full disk leaves `highest_recorded` answering *n-1*. Without this check the walk would
    /// recompute *n* — a whole population read and its spend executions — and then fail at `put`,
    /// on every timer tick, forever, advancing nothing and reporting only a generic store fault.
    EpochLineUnreadable {
        /// The epoch whose stored line cannot be read.
        epoch: u64,
    },
}

/// What one epoch's census found, beyond the figures that went into its record.
///
/// # Why a count of nothing is not self-explanatory
///
/// `stores: 0` has at least three causes that call for opposite responses: the network is
/// genuinely empty; the source answered at the WRONG puzzle hash (`foreign_puzzle`); or every
/// candidate's creating spend was unavailable, so a DEGRADED source described a smaller network
/// than exists (`unreadable`). The record alone cannot tell them apart, and this is the path that
/// decides how much collateral a node posts — so the census's own account of what it examined and
/// why candidates were dropped is carried out of the walk and reported, rather than discarded at
/// the point the record is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusObservation {
    /// The epoch that was censused and recorded.
    pub epoch: u64,
    /// The height it was censused at.
    pub census_height: u32,
    /// The qualifying advertisement count the record was derived from.
    pub stores: u64,
    /// How many candidate coins at the shared mirror puzzle hash were examined to reach it.
    ///
    /// A [`CensusOutcome::Final`] examines the WHOLE population, never a prefix, so
    /// `examined == 0` is the one reading that means the network is empty.
    pub examined: usize,
    /// Why the examined candidates that did not qualify did not qualify.
    pub excluded: Exclusions,
}

/// What one catch-up did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUp {
    /// What each newly recorded epoch's census found, in ascending epoch order. Empty is the
    /// ordinary steady state: a node already current has no NEW epoch to compute, and its one
    /// census of the target epoch is reported through `superseded` only if it repaired something.
    pub recorded: Vec<CensusObservation>,
    /// The re-census of the target epoch that REPLACED a lower answer this node had already
    /// recorded for it, when one did (dig-node#405).
    ///
    /// `None` is the ordinary outcome and covers two different ordinary things: the target was
    /// recorded for the first time by this very walk, so `recorded` already describes it; or it was
    /// re-censused and the answer had not moved. Only a genuine repair appears here, because only a
    /// genuine repair is worth an operator's attention — it says this node's chain view had been
    /// showing it a smaller network than the chain holds.
    pub superseded: Option<CensusObservation>,
    /// Why the walk stopped short of the target, or `None` when it reached it.
    pub stopped: Option<CensusStop>,
}

/// Compute and record every epoch from the newest one `store` holds up to `target_epoch`.
///
/// Returns what it recorded and, when it stopped early, why. **A stop writes nothing**: this
/// function never invents, defaults, or carries forward a figure.
///
/// A walk whose store is already current still censuses the TARGET epoch once, so that a record
/// written under a briefly degraded chain view cannot stay sealed (dig-node#405, see [`refresh`]).
/// It censuses no epoch before the target, so history is computed exactly once and the cost of
/// running this on a timer is one epoch's census per pass.
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
                superseded: None,
                stopped: Some(CensusStop::Store { detail }),
            }
        }
    };

    for epoch in (highest + 1)..=target_epoch {
        match record_one(source, store, epoch) {
            Ok(observed) => recorded.push(observed),
            Err(stopped) => {
                return CatchUp {
                    recorded,
                    superseded: None,
                    stopped: Some(stopped),
                }
            }
        }
    }

    // The store was already at the target, so nothing above ran. Take the census again: this is the
    // ONE epoch whose answer is still repairable, and the pass costs one census of one epoch.
    if highest >= target_epoch {
        return match refresh(source, store, target_epoch) {
            Ok(superseded) => CatchUp {
                recorded,
                superseded,
                stopped: None,
            },
            Err(stopped) => CatchUp {
                recorded,
                superseded: None,
                stopped: Some(stopped),
            },
        };
    }

    CatchUp {
        recorded,
        superseded: None,
        stopped: None,
    }
}

/// Re-census an epoch this node has ALREADY recorded, and replace its record if the new census
/// counts more stores.
///
/// # Why the walk is no longer read-free once it is current (dig-node#405)
///
/// It used to perform no chain read at all when the store held the target, and that cheapness was
/// exactly what made a degraded read permanent: the record written by one thin ten-minute window
/// was never looked at again. So the steady state now costs one census of ONE epoch per pass, and
/// buys back the property that an under-count has to be sustained for the whole epoch rather than
/// merely be well timed.
///
/// # What is deliberately NOT re-censused
///
/// Every epoch before the target. History stays computed exactly once
/// ([`EpochRecordStore::put`] would refuse to change it anyway), so the cold-start cost of a node
/// catching up across many epochs (dig-node#404) is untouched: this adds one census, to the epoch
/// the walk was asked for, and only when that epoch was already held.
///
/// # A LOWER re-census is a stop, not a silence
///
/// [`EpochRecordStore::put`] admits only a strictly higher count, so a re-census that comes back
/// smaller lands on [`PutOutcome::Conflict`] and is reported as [`CensusStop::Contradiction`]. That
/// is the honest reading: this node's stored answer and its current chain view disagree about a
/// block that is already buried, and the held record — the higher one — stands.
fn refresh<S: ChainSource>(
    source: &S,
    store: &EpochRecordStore,
    epoch: u64,
) -> Result<Option<CensusObservation>, CensusStop> {
    let held_stores = match store.get(epoch) {
        // Only a CENSUS is worth repeating. `put` demands `Censused` on both sides of the repair,
        // so re-censusing anything else spends a whole population read to reach a refusal.
        //
        // **This is also what protects the genesis epoch**, and it is the only guard that does.
        // Epoch 1 is derived from nothing and has no predecessor, so re-entering `record_one` for
        // it stops at `PriorEpochMissing { epoch: 0 }` — an epoch that cannot exist — on every pass
        // forever. It is reached here as a BOOTSTRAP record, never a censused one: no path writes a
        // censused epoch 1 (`put` answers `AlreadyPresent` for an identical record offered with
        // weaker evidence, and `Conflict` for a differing one, since a bootstrap record is on
        // neither superseding side). An explicit `epoch <= GENESIS_EPOCH` arm was tried and removed
        // — it sat in front of this one, could never fire, and so masked the guard that does the
        // work: mutating it away left the suite green, which is the whole argument against keeping
        // a second guard that nothing can witness.
        StoredEpoch::Found(held) if !matches!(held.provenance, RecordProvenance::Censused) => {
            return Ok(None)
        }
        StoredEpoch::Found(held) => held.record.census.stores,
        // Not a state this function is reached in — `catch_up` only calls it for an epoch
        // `highest_recorded` just reported — and answered honestly rather than assumed away.
        StoredEpoch::Absent => return Ok(None),
        StoredEpoch::Unreadable => return Err(CensusStop::EpochLineUnreadable { epoch }),
    };

    let observed = record_one(source, store, epoch)?;
    Ok((observed.stores > held_stores).then_some(observed))
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
) -> Result<CensusObservation, CensusStop> {
    // Before any chain read: a rotted line for THIS epoch is invisible to `highest_recorded` and
    // would otherwise cost a full census per timer tick, forever, to reach a `put` that cannot
    // succeed. See `CensusStop::EpochLineUnreadable`.
    if matches!(store.get(epoch), StoredEpoch::Unreadable) {
        return Err(CensusStop::EpochLineUnreadable { epoch });
    }

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
    let observed = CensusObservation {
        epoch,
        census_height: counted.height(),
        stores: record.census.stores,
        examined: counted.examined(),
        excluded: counted.excluded(),
    };
    match store.put(&stored) {
        Ok(PutOutcome::Written | PutOutcome::AlreadyPresent) => Ok(observed),
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

    /// A source that answers a chain, at a peak far past finality, holding exactly the coin records
    /// it was built with.
    ///
    /// Every height carries a timestamp at or after epoch 2's start, so `census_height` settles on
    /// height 0 without the fixture having to model a block schedule — the height is not what these
    /// tests are about.
    struct PopulatedSource {
        records: Vec<CoinRecord>,
    }

    impl PopulatedSource {
        fn holding(records: Vec<CoinRecord>) -> Self {
            Self { records }
        }
    }

    impl ChainSource for PopulatedSource {
        type Error = String;

        fn coin_record(
            &self,
            _coin_id: chia_protocol::Bytes32,
        ) -> Result<Option<CoinRecord>, Self::Error> {
            Ok(None)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: chia_protocol::Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(self.records.clone())
        }

        fn coin_records_by_parent(
            &self,
            _parent_coin_id: chia_protocol::Bytes32,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            Ok(Vec::new())
        }

        fn coin_spend(
            &self,
            _coin_id: chia_protocol::Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            Ok(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: chia_protocol::Bytes32,
        ) -> Result<Option<dig_chainsource_interface::SingletonLineage>, Self::Error> {
            Ok(None)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            Ok(Some(10_000))
        }

        fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
            Ok(Some(epoch_start_unix_secs(2) + u64::from(height)))
        }
    }

    /// A coin record at `puzzle_hash`, confirmed well before any census height these tests use.
    fn record_at(puzzle_hash: chia_protocol::Bytes32) -> CoinRecord {
        CoinRecord {
            coin: chia_protocol::Coin {
                parent_coin_info: chia_protocol::Bytes32::new([7u8; 32]),
                puzzle_hash,
                amount: 1_000_000,
            },
            confirmed_height: Some(0),
            spent_height: None,
            timestamp: Some(epoch_start_unix_secs(2)),
            coinbase: false,
        }
    }

    /// A plausible consensus record for `epoch`, for seeding a store the walk must then re-census.
    fn record_for(epoch: u64) -> dig_mirror_collateral::EpochRecord {
        let mut rec = EpochRecord::bootstrap();
        rec.epoch = epoch;
        rec
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

    /// **A node already current re-censuses the TARGET epoch, and records nothing new.**
    ///
    /// The steady state after dig-node#405. It used to perform no chain read at all, and that
    /// cheapness is exactly what sealed a record written under a briefly degraded view: the walk
    /// never looked at the epoch again. So a read is now expected, and its absence would mean the
    /// repair path is unreachable.
    ///
    /// Asserted against a source that fails on every read, so the read is observable in TWO
    /// independent ways — the counter, and a stop that could only have come from attempting it.
    #[test]
    fn a_store_already_at_the_target_recensuses_it() {
        // The target is epoch 2, NOT genesis. Genesis is derived from nothing and is deliberately
        // never re-censused (see `refresh`), so a fixture aimed at it asserts the guard rather than
        // the repair and reads as "no chain read" for the wrong reason — which is exactly how this
        // test first passed against a walk that could not repair anything.
        let (store, dir) = seeded_store("current");
        store
            .put(&StoredRecord::censused(record_for(2), 1_002))
            .expect("seed epoch 2");
        let source = UnreachableSource::new();

        let outcome = catch_up(&source, &store, 2);

        assert_eq!(outcome.recorded, Vec::<CensusObservation>::new());
        assert_eq!(outcome.superseded, None, "nothing was repaired to report");
        assert!(
            source.reads() > 0,
            "the target epoch was not re-censused, so a degraded record could never be repaired"
        );
        match outcome.stopped {
            Some(CensusStop::ChainUnavailable { epoch, .. }) => assert_eq!(
                epoch, 2,
                "the re-census must be of the TARGET epoch and of no earlier one"
            ),
            other => panic!("expected the refused read to be reported, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **A record that is not a census is never re-censused — which is what protects genesis.**
    ///
    /// Epoch 1 is derived from nothing and has no predecessor, so re-entering the census for it
    /// stops at `PriorEpochMissing { epoch: 0 }` — an epoch that cannot exist — on every pass,
    /// forever, on the one node state that is unambiguously correct. It is held as a BOOTSTRAP
    /// record, so the provenance arm in `refresh` is the guard that fires.
    ///
    /// Written against the provenance arm rather than against an epoch-number arm deliberately. An
    /// explicit `epoch <= GENESIS_EPOCH` guard was tried, sat in front of this one, and could never
    /// fire; mutating it away left this test green, which is exactly what a masked guard looks like
    /// and why it was removed rather than kept for reassurance.
    #[test]
    fn a_record_that_is_not_a_census_is_never_re_censused() {
        let (store, dir) = seeded_store("genesis");
        let source = UnreachableSource::new();

        let outcome = catch_up(&source, &store, GENESIS_EPOCH);

        assert_eq!(outcome.stopped, None, "genesis reported a stop: {outcome:?}");
        assert_eq!(source.reads(), 0, "genesis was re-censused");

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **History is computed exactly once; only the target is ever re-censused.**
    ///
    /// The bound that keeps the repair from multiplying a cold-start walk (dig-node#404) by every
    /// pass. A store holding epochs 1..=3 with a target of 3 must attempt a census of 3 and of
    /// nothing else — so the stop names 3, not 2, even though 2 is equally re-computable.
    ///
    /// The fixture varies the held epoch away from genesis deliberately: with the target at
    /// genesis, "the target" and "the only epoch held" are the same number and a walk that
    /// re-censused everything would be indistinguishable from one that re-censused the target.
    #[test]
    fn no_epoch_before_the_target_is_ever_re_censused() {
        let (store, dir) = seeded_store("history-once");
        for epoch in 2..=3u64 {
            store
                .put(&StoredRecord::censused(record_for(epoch), 1_000 + epoch as u32))
                .expect("seed");
        }
        let source = UnreachableSource::new();

        let outcome = catch_up(&source, &store, 3);

        match outcome.stopped {
            Some(CensusStop::ChainUnavailable { epoch, .. }) => assert_eq!(
                epoch, 3,
                "an epoch before the target was re-censused; the walk is no longer cheap"
            ),
            other => panic!("expected the target's refused read, got {other:?}"),
        }

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

    /// **Two censuses that count nothing are told apart by what the walk reports.**
    ///
    /// This is the whole reason `CensusObservation` exists. Both halves record a `stores` of 0 and
    /// both write a record carrying the floor requirement — identical on every field that reaches
    /// the record. What separates them is `examined` and the exclusion counts:
    ///
    /// * the EMPTY chain examined nothing, so the network really is empty;
    /// * the WRONG-puzzle-hash source examined a candidate and dropped it as `foreign_puzzle`,
    ///   which is a fact about the source and says nothing about the network.
    ///
    /// The second is a broken instrument rendered as a reassuring answer, on the path that decides
    /// how much collateral this node posts. Asserting the two observations DIFFER is what fails if
    /// the fields are dropped again: an assertion on `stores` alone passes in both cases, which is
    /// exactly the state this test was written against.
    #[test]
    fn a_census_of_nothing_reports_whether_it_examined_anything() {
        let (empty_store, empty_dir) = seeded_store("examined-empty");
        let empty = catch_up(&PopulatedSource::holding(Vec::new()), &empty_store, 2);

        let (foreign_store, foreign_dir) = seeded_store("examined-foreign");
        let foreign = catch_up(
            &PopulatedSource::holding(vec![record_at(chia_protocol::Bytes32::new([9u8; 32]))]),
            &foreign_store,
            2,
        );

        let [empty] = &empty.recorded[..] else {
            panic!("the empty chain recorded {:?}", empty)
        };
        let [foreign] = &foreign.recorded[..] else {
            panic!("the foreign-puzzle chain recorded {:?}", foreign)
        };

        // The figure that reaches the record is the same in both. That is the problem.
        assert_eq!(empty.stores, 0);
        assert_eq!(foreign.stores, 0);

        assert_eq!(empty.examined, 0, "an empty chain examined a candidate");
        assert_eq!(empty.excluded, Exclusions::default());

        assert_eq!(
            foreign.examined, 1,
            "the candidate the source answered was not counted as examined"
        );
        assert_eq!(
            foreign.excluded.foreign_puzzle, 1,
            "a record at the wrong puzzle hash was not reported as such"
        );

        assert_ne!(
            (empty.examined, empty.excluded),
            (foreign.examined, foreign.excluded),
            "an empty network and a source answering at the wrong puzzle hash are indistinguishable"
        );

        let _ = std::fs::remove_dir_all(empty_dir);
        let _ = std::fs::remove_dir_all(foreign_dir);
    }

    /// **The line an operator reads carries the exclusion counts, not just the figure.**
    ///
    /// Asserted on the RENDERED event rather than on the struct, because the struct being right is
    /// not what an operator sees. The observation is a real one — produced by a census of a source
    /// answering at the wrong puzzle hash — so the line under test is the one that would be written
    /// on a node in exactly that state.
    #[test]
    fn the_recorded_epoch_is_logged_with_what_the_census_examined() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Captured(Arc<Mutex<Vec<u8>>>);

        impl Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("the capture buffer")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
            type Writer = Captured;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let (store, dir) = seeded_store("logged");
        let outcome = catch_up(
            &PopulatedSource::holding(vec![record_at(chia_protocol::Bytes32::new([9u8; 32]))]),
            &store,
            2,
        );
        let [observed] = &outcome.recorded[..] else {
            panic!("nothing was recorded to log: {outcome:?}")
        };

        let buffer = Captured(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            crate::server::log_census_observation(observed);
        });

        let line = String::from_utf8(buffer.0.lock().expect("the capture buffer").clone())
            .expect("the rendered line is utf-8");
        println!("{line}");

        for field in [
            "examined=1",
            "excluded_foreign_puzzle=1",
            "excluded_unreadable=0",
            "stores=0",
        ] {
            assert!(
                line.contains(field),
                "the logged line does not carry {field}: {line}"
            );
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// **A rotted line for the epoch being computed stops the walk BEFORE any chain read.**
    ///
    /// `records()` skips unparseable lines while `get()` reports them, so a line for epoch 2
    /// truncated by a crash or a full disk leaves `highest_recorded` answering 1 and the walk
    /// heading straight back at epoch 2. Without the pre-check that walk performs a whole
    /// population read and its spend executions, fails at `put`, and does it all again on the next
    /// timer tick — forever, advancing nothing.
    ///
    /// `reads() == 0` is the load-bearing assertion, and it is what a fix placed anywhere later
    /// than this would fail: a stop reported AFTER the census is still a correct-looking stop, and
    /// still burns the census every ten minutes.
    #[test]
    fn a_rotted_line_for_the_target_epoch_stops_the_walk_before_reading_the_chain() {
        let (store, dir) = seeded_store("rotted");

        // Valid JSON that names epoch 2 — so the store can attribute it — and is not a
        // `StoredRecord`. This is the shape a half-written append leaves behind.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join("epochs.jsonl"))
                .expect("open the store for the rotted append");
            writeln!(f, "{{\"epoch\":2}}").expect("append the rotted line");
        }
        assert!(
            matches!(store.get(2), StoredEpoch::Unreadable),
            "the fixture did not produce an unreadable line for epoch 2"
        );

        let source = UnreachableSource::new();
        let outcome = catch_up(&source, &store, 3);

        assert!(outcome.recorded.is_empty());
        assert_eq!(
            outcome.stopped,
            Some(CensusStop::EpochLineUnreadable { epoch: 2 }),
            "the rotted line was not named as the reason"
        );
        assert_eq!(
            source.reads(),
            0,
            "a full census was performed against a line that could never be written"
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
