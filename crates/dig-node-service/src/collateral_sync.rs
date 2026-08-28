//! Adopting an epoch history from peers, and serving one to them.
//!
//! # The one sentence this module exists to make true
//!
//! **A record from a peer is adopted because it is RECOMPUTABLE, never because the peer is
//! trusted.** NC-12 binds every dialled peer as untrusted, and the value being fetched here is
//! consensus-adjacent in the most direct way possible: the requirement a record names is the amount
//! of $DIG this operator posts as collateral. A peer that can move it down leaves this node's
//! stores uncollateralised and silently unpaid; a peer that can move it up locks the operator's
//! money for nothing. The user's stated threat is specifically the *down* direction — nodes
//! spamming invalid mirror coins to force the requirement down — and a sampled sync that took a
//! peer's word would be a second, cheaper path to the same end.
//!
//! # What a receiving node CAN verify, and does
//!
//! A record carries its own census inputs, so the whole derivation is reproducible. This node
//! **re-derives** the candidate from a predecessor it already holds, via
//! [`EpochRecord::advance`](dig_mirror_collateral::EpochRecord::advance), and demands that every
//! field of the result match — not just the headline requirement. Nothing here restates the
//! formula: `equilibrium x multiplier - handicap` omits the floor clamp, and a check written that
//! way would accept records the network rejects.
//!
//! That means a peer cannot lie about **any derived quantity** — the requirement, the multiplier,
//! the handicap, the base price, the band, the signals — while keeping its census inputs. It also
//! cannot lie about the **ruleset**: `advance` refuses a protocol version this build does not
//! implement, on the candidate and on the seed, so a forged record from a "newer model" is refused
//! rather than believed. And it cannot lie about the **epoch**: the recurrence is defined only for
//! consecutive epochs, so a record is only ever verified against its immediate predecessor, walking
//! forward from a bootstrap record that depends on nothing.
//!
//! # What it CANNOT verify, and what it does about that
//!
//! **It cannot check the census inputs against the chain.** A peer that reports a smaller
//! `stores` count than the chain holds has produced a record whose arithmetic is impeccable and
//! whose inputs are fiction. Re-derivation cannot see that; only a chain read can.
//!
//! So the sample is the defence against exactly that residue, and it is bounded honestly:
//!
//! * The sample is sized by [`dig_mirror_collateral::sync_sample_plan`] against a **chain-derived
//!   population**. A node that does not know the population does not get a plan — it gets
//!   [`AdoptOutcome::Advisory`], and derives from chain instead. That is not a degraded mode to be
//!   worked around; a sample drawn from an unknown population supports no confidence claim at all.
//! * Agreement is a strict two-thirds supermajority of a bounded sample, and its confidence number
//!   is conditional on at most a fifth of the population being dishonest. Below
//!   `SYNC_MIN_POPULATION` the plan says `advisory_only` and this node does not adopt.
//! * Hearing from **more distinct owners than the chain says exist** is not noise, it is a
//!   detectable lie, and it refuses the whole sample rather than the excess responses.
//! * **Disagreement never resolves to a majority of a tiny sample.** No supermajority means
//!   [`AdoptOutcome::NoAgreement`], which is an `unknown` with a reason — never a best guess, never
//!   the most popular answer, and never a neighbouring epoch's figure.
//!
//! # The honest gap, stated rather than papered over
//!
//! The plan counts distinct **collateralised owners**; this node samples distinct **peers**, and a
//! peer's claimed owner attribution is not proven on this path. One adversary holding many peer
//! identities therefore looks like many owners to the sampler, which is precisely the assumption
//! the confidence figure rests on. This is why adoption is never load-bearing: the sample buys the
//! ability to SKIP an expensive historical re-derivation, never the right to be wrong. A node that
//! can census an epoch itself must prefer its own computation, and [`crate::collateral::put`]'s
//! provenance ranking is what lets a later census supersede an adopted record without a conflict.

use std::collections::BTreeMap;

use dig_mirror_collateral::{sync_sample_plan, SyncSamplePlan};

use crate::collateral::{RecordProvenance, StoredRecord};

/// One peer's answer for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Who answered, as this node identifies them. Used only to count DISTINCT responders.
    pub responder: String,
    /// What they returned.
    pub record: StoredRecord,
}

/// Why a candidate record was not counted.
///
/// Every rejection is named. A sample that discarded responses silently would report "no
/// agreement" for a network that agreed perfectly and one liar, which sends an operator to
/// diagnose the wrong thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// The record does not describe the epoch after the one it was verified against.
    NonSequential {
        /// The epoch a record would have had to describe.
        expected: u64,
        /// The epoch it did describe.
        found: u64,
    },
    /// The record, or the predecessor it was checked against, names a ruleset this build does not
    /// implement.
    UnimplementedRuleset {
        /// The version named.
        protocol_version: u16,
    },
    /// Re-deriving the record from its own census inputs did not reproduce it.
    ///
    /// The strongest signal available on this path: the peer's arithmetic disagrees with the
    /// network's, which no honest node can do.
    ArithmeticMismatch,
    /// The census height does not advance past the predecessor's.
    ///
    /// A census for a later epoch is taken at a later block. A record claiming otherwise describes
    /// a chain that ran backwards.
    CensusHeightNotAdvancing {
        /// The predecessor's height.
        previous: u32,
        /// The height claimed.
        found: u32,
    },
    /// This responder had already answered, differently. Both answers are discarded.
    ///
    /// Discarding BOTH is deliberate. Keeping the first would let a peer that equivocates still
    /// contribute a vote, and equivocation is the clearest evidence of dishonesty this sampler can
    /// observe.
    Equivocated,
}

/// What a sampled sync concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptOutcome {
    /// The sample agreed; this record may be stored.
    Adopted {
        /// The record, with its adoption recorded in its provenance.
        record: Box<StoredRecord>,
    },
    /// The sample is advisory only: it informs, it does not decide.
    ///
    /// Either the population is unknown to this node, or it is below the threshold at which the
    /// "at most a fifth dishonest" assumption every confidence figure rests on is meaningful. The
    /// node derives the epoch from chain instead.
    Advisory {
        /// Why, in a sentence an operator can act on.
        reason: &'static str,
    },
    /// More distinct responders answered than the chain says owners exist.
    ///
    /// Not noise: a finite population is what makes the sample a sample, and exceeding it is
    /// evidence of fabricated identities. The whole sample is refused, not trimmed — a prefix of an
    /// attacker-writable set is a set the attacker chose.
    PopulationExceeded {
        /// The chain-derived population.
        population: u64,
        /// How many distinct responders answered.
        responders: u64,
    },
    /// No record reached the agreement threshold.
    ///
    /// An `unknown` with a reason, never a best guess. The most popular answer in a sample that
    /// failed to converge is exactly the answer an attacker with a minority of identities is trying
    /// to produce.
    NoAgreement {
        /// How many responses survived verification.
        verified: u64,
        /// How many agreeing responses were needed.
        needed: u64,
        /// The largest number that agreed on any one record.
        best: u64,
    },
}

/// Verify a candidate against the predecessor this node already holds.
///
/// The whole record is reproduced, not just its headline figure. Checking only
/// `required_per_store_dig_base_units` would accept a record whose multiplier and handicap are both
/// wrong in compensating directions — and the multiplier is what the buffer's escalation headroom
/// scales, so the compensation would not survive into the next epoch.
///
/// # Errors
///
/// A [`Rejection`] naming which check failed.
pub fn verify(prior: &StoredRecord, candidate: &StoredRecord) -> Result<(), Rejection> {
    if !prior.is_interpretable() {
        return Err(Rejection::UnimplementedRuleset {
            protocol_version: prior.record.protocol_version.0,
        });
    }
    if !candidate.is_interpretable() {
        return Err(Rejection::UnimplementedRuleset {
            protocol_version: candidate.record.protocol_version.0,
        });
    }

    // Re-derive. The candidate's OWN census inputs are the only thing taken from it; every derived
    // field is this node's own arithmetic, through the crate that owns it.
    let derived = prior
        .record
        .advance(candidate.record.census)
        .map_err(|e| match e {
            dig_mirror_collateral::CollateralError::NonSequentialEpoch { expected, found } => {
                Rejection::NonSequential { expected, found }
            }
            _ => Rejection::UnimplementedRuleset {
                protocol_version: candidate.record.protocol_version.0,
            },
        })?;
    if derived != candidate.record {
        return Err(Rejection::ArithmeticMismatch);
    }

    // A census for a later epoch is taken at a later block. Only checkable when both heights are
    // present; epoch 1 has none, because no census produced it.
    if let (Some(previous), Some(found)) = (prior.census_height, candidate.census_height) {
        if found <= previous {
            return Err(Rejection::CensusHeightNotAdvancing { previous, found });
        }
    }
    Ok(())
}

/// Decide whether a sample of peer answers may be adopted as the epoch after `prior`.
///
/// `population` is the count of distinct collateralised owner hashes the chain reports at the
/// census height — `None` when this node cannot read it, which is not a detail to route around:
/// see [`AdoptOutcome::Advisory`].
pub fn adopt(
    prior: &StoredRecord,
    population: Option<u64>,
    responses: &[PeerRecord],
) -> AdoptOutcome {
    let Some(population) = population else {
        return AdoptOutcome::Advisory {
            reason: "this node cannot read the chain-derived owner population, so a sample of \
                     peers supports no confidence claim; derive the epoch from chain instead",
        };
    };
    let plan: SyncSamplePlan = sync_sample_plan(population);
    if plan.advisory_only {
        return AdoptOutcome::Advisory {
            reason: "the collateralised owner population is too small for a sample to mean \
                     anything; derive the epoch from chain instead",
        };
    }

    // One vote per responder, and an equivocating responder gets none. Recorded before any
    // counting so that a peer cannot buy a second vote by answering twice.
    let mut by_responder: BTreeMap<&str, Option<&StoredRecord>> = BTreeMap::new();
    for response in responses {
        match by_responder.get(response.responder.as_str()) {
            None => {
                by_responder.insert(&response.responder, Some(&response.record));
            }
            Some(Some(first)) if **first == response.record => {}
            // Answered before, differently: both answers are discarded.
            Some(_) => {
                by_responder.insert(&response.responder, None);
            }
        }
    }

    // A finite, chain-derived population is what makes this a sample. Hearing from more distinct
    // responders than the chain says owners exist is a detectable lie about identity, and it
    // refuses the sample outright rather than trimming it to a prefix the attacker chose.
    let responders = by_responder.len() as u64;
    if responders > plan.population {
        return AdoptOutcome::PopulationExceeded {
            population: plan.population,
            responders,
        };
    }

    // Verify, then tally by the FULL record. Two records that agree on the requirement but differ
    // anywhere else are different answers, and counting them together would let a disagreement
    // about the multiplier ride in on agreement about today's price.
    let mut tally: BTreeMap<String, (u64, StoredRecord)> = BTreeMap::new();
    let mut verified = 0u64;
    for record in by_responder.values().flatten() {
        if verify(prior, record).is_err() {
            continue;
        }
        verified += 1;
        // Keyed on the canonical JSON of the CONSENSUS record only. Provenance and census height
        // are this node's bookkeeping about a peer, not part of what the network agrees on, so two
        // peers that derived the same epoch must not be split into two camps by them.
        let key = match serde_json::to_string(&record.record) {
            Ok(key) => key,
            Err(_) => continue,
        };
        let entry = tally.entry(key).or_insert((0, **record));
        entry.0 += 1;
    }

    let best = tally.values().map(|(count, _)| *count).max().unwrap_or(0);
    if best < plan.agreement_threshold {
        return AdoptOutcome::NoAgreement {
            verified,
            needed: plan.agreement_threshold,
            best,
        };
    }
    let (agreed, winner) = tally
        .into_values()
        .max_by_key(|(count, _)| *count)
        .expect("a non-zero best implies at least one tallied record");

    AdoptOutcome::Adopted {
        record: Box::new(StoredRecord {
            record: winner.record,
            census_height: winner.census_height,
            provenance: RecordProvenance::AdoptedFromPeers {
                agreed,
                sampled: responders,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_mirror_collateral::{EpochCensus, EpochRecord};

    /// The bootstrap record, which every walk forward starts from.
    fn genesis() -> StoredRecord {
        StoredRecord::bootstrap()
    }

    /// The HONEST successor of `prior` for a census of `stores` advertisements across `owners`
    /// owners, taken at `height`.
    ///
    /// Derived through `advance` rather than hand-built, so a fixture cannot accidentally encode
    /// arithmetic the crate does not actually produce — which would make every test below a test
    /// of the fixture.
    fn honest(prior: &StoredRecord, stores: u64, owners: u64, height: u32) -> StoredRecord {
        let census = EpochCensus {
            epoch: prior.record.epoch + 1,
            stores,
            owners,
            locked: stores * 20_000,
        };
        StoredRecord::censused(
            prior.record.advance(census).expect("an honest successor"),
            height,
        )
    }

    fn sample(records: &[(&str, StoredRecord)]) -> Vec<PeerRecord> {
        records
            .iter()
            .map(|(responder, record)| PeerRecord {
                responder: (*responder).to_string(),
                record: *record,
            })
            .collect()
    }

    /// A population comfortably at the sampling plateau, so the plan is a real plan (9 sampled, 7
    /// needed) rather than the degenerate advisory one. Chosen FROM `SYNC_MIN_POPULATION` rather
    /// than picked because it looked big.
    const PLATEAU_POPULATION: u64 = 40;

    #[test]
    fn an_honest_successor_verifies() {
        let prior = genesis();
        let candidate = honest(&prior, 120, 30, 5_000);
        assert_eq!(verify(&prior, &candidate), Ok(()));
    }

    #[test]
    fn a_record_whose_requirement_was_edited_down_is_refused() {
        let prior = genesis();
        let mut forged = honest(&prior, 120, 30, 5_000);
        // The down direction is the user's stated threat: a requirement talked lower leaves this
        // operator's stores uncollateralised while every surface reports success.
        forged.record.required_per_store_dig_base_units -= 1;
        assert_eq!(
            verify(&prior, &forged),
            Err(Rejection::ArithmeticMismatch),
            "a peer's arithmetic must be re-derived, never believed"
        );
    }

    #[test]
    fn a_record_whose_multiplier_was_edited_is_refused_even_though_the_requirement_is_honest() {
        let prior = genesis();
        let honest_next = honest(&prior, 120, 30, 5_000);
        let mut forged = honest_next;
        // The requirement is left EXACTLY as derived. Only the multiplier moves — the field the
        // buffer's escalation headroom scales. A check that compared only the headline figure
        // would pass this, and the lie would surface an epoch later as a wrong recommendation.
        forged.record.multiplier_micros += 1;
        assert_eq!(
            forged.record.required_per_store_dig_base_units,
            honest_next.record.required_per_store_dig_base_units,
            "the fixture must differ ONLY in the multiplier, or it proves nothing about it"
        );
        assert_eq!(verify(&prior, &forged), Err(Rejection::ArithmeticMismatch));
    }

    #[test]
    fn a_record_from_an_unimplemented_ruleset_is_refused_rather_than_interpreted() {
        let prior = genesis();
        let mut forged = honest(&prior, 120, 30, 5_000);
        forged.record.protocol_version = dig_mirror_collateral::ProtocolVersion(u16::MAX);
        assert_eq!(
            verify(&prior, &forged),
            Err(Rejection::UnimplementedRuleset {
                protocol_version: u16::MAX
            })
        );
    }

    #[test]
    fn a_record_that_skips_an_epoch_is_refused() {
        let prior = genesis();
        let next = honest(&prior, 120, 30, 5_000);
        let two_ahead = honest(&next, 130, 31, 6_000);
        assert_eq!(
            verify(&prior, &two_ahead),
            Err(Rejection::NonSequential {
                expected: 2,
                found: 3
            }),
            "the recurrence is defined only for consecutive epochs"
        );
    }

    #[test]
    fn a_census_height_that_does_not_advance_is_refused() {
        let prior = honest(&genesis(), 120, 30, 5_000);
        let mut candidate = honest(&prior, 130, 31, 9_000);
        candidate.census_height = Some(5_000);
        assert_eq!(
            verify(&prior, &candidate),
            Err(Rejection::CensusHeightNotAdvancing {
                previous: 5_000,
                found: 5_000
            }),
            "a later epoch is censused at a later block"
        );
    }

    #[test]
    fn an_unknown_population_is_advisory_and_never_adopts() {
        let prior = genesis();
        let good = honest(&prior, 120, 30, 5_000);
        // Nine honest, agreeing peers -- a sample that WOULD adopt if the population were known.
        // The control matters: without it this test would pass for a function that never adopts.
        let responses = sample(&[
            ("a", good),
            ("b", good),
            ("c", good),
            ("d", good),
            ("e", good),
            ("f", good),
            ("g", good),
            ("h", good),
            ("i", good),
        ]);
        assert!(matches!(
            adopt(&prior, Some(PLATEAU_POPULATION), &responses),
            AdoptOutcome::Adopted { .. }
        ));
        assert!(matches!(
            adopt(&prior, None, &responses),
            AdoptOutcome::Advisory { .. }
        ));
    }

    #[test]
    fn one_liar_among_honest_peers_does_not_stop_adoption_and_does_not_get_counted() {
        let prior = genesis();
        let good = honest(&prior, 120, 30, 5_000);
        let mut liar = good;
        liar.record.required_per_store_dig_base_units /= 2;
        // Seven honest peers, one liar, one equivocator. Exactly ONE actor is dishonest per role,
        // and the honest majority is a truthful control: an all-hostile fixture cannot see whether
        // an honest answer would have been counted.
        let mut responses = sample(&[
            ("a", good),
            ("b", good),
            ("c", good),
            ("d", good),
            ("e", good),
            ("f", good),
            ("g", good),
            ("liar", liar),
        ]);
        responses.push(PeerRecord {
            responder: "equivocator".to_string(),
            record: good,
        });
        responses.push(PeerRecord {
            responder: "equivocator".to_string(),
            record: liar,
        });

        match adopt(&prior, Some(PLATEAU_POPULATION), &responses) {
            AdoptOutcome::Adopted { record } => {
                assert_eq!(record.record, good.record, "the honest record was adopted");
                assert_eq!(
                    record.provenance,
                    RecordProvenance::AdoptedFromPeers {
                        agreed: 7,
                        sampled: 9
                    },
                    "the equivocator is sampled but never counted, and the liar never agrees"
                );
            }
            other => panic!("expected adoption, got {other:?}"),
        }
    }

    #[test]
    fn a_sample_that_does_not_converge_is_unknown_rather_than_a_majority() {
        let prior = genesis();
        let good = honest(&prior, 120, 30, 5_000);
        // A DIFFERENT but internally honest record: a real disagreement about the census, which is
        // the residue re-derivation cannot resolve. Both camps verify; neither reaches 7 of 9.
        let other = honest(&prior, 121, 30, 5_000);
        assert_ne!(
            good.record, other.record,
            "the two camps must really differ"
        );
        let responses = sample(&[
            ("a", good),
            ("b", good),
            ("c", good),
            ("d", good),
            ("e", good),
            ("f", other),
            ("g", other),
            ("h", other),
            ("i", other),
        ]);
        assert_eq!(
            adopt(&prior, Some(PLATEAU_POPULATION), &responses),
            AdoptOutcome::NoAgreement {
                verified: 9,
                needed: 7,
                best: 5
            },
            "a plurality is not a supermajority, and the plurality is what an attacker aims for"
        );
    }

    #[test]
    fn more_responders_than_the_chain_says_owners_exist_refuses_the_whole_sample() {
        use dig_mirror_collateral::SYNC_MIN_POPULATION;
        let prior = genesis();
        let good = honest(&prior, 120, 30, 5_000);
        // Every response is HONEST and they all agree, so this refusal is about the identity claim
        // alone; a fixture with a liar in it could not tell the two reasons apart.
        //
        // The population is taken FROM `SYNC_MIN_POPULATION` rather than picked, because below it
        // the plan is advisory and `PopulationExceeded` is unreachable — a smaller fixture reports
        // `Advisory` and would have pinned the wrong refusal. Both sides of the bound are checked:
        // one responder over must be refused, and exactly at the population must not be.
        let responders: Vec<(String, StoredRecord)> = (0..=SYNC_MIN_POPULATION)
            .map(|i| (format!("peer-{i}"), good))
            .collect();
        let over: Vec<PeerRecord> = responders
            .iter()
            .map(|(responder, record)| PeerRecord {
                responder: responder.clone(),
                record: *record,
            })
            .collect();
        assert_eq!(
            over.len() as u64,
            SYNC_MIN_POPULATION + 1,
            "the over-the-bound sample must really exceed the population"
        );
        assert_eq!(
            adopt(&prior, Some(SYNC_MIN_POPULATION), &over),
            AdoptOutcome::PopulationExceeded {
                population: SYNC_MIN_POPULATION,
                responders: SYNC_MIN_POPULATION + 1
            }
        );

        // At the bound the same honest sample is adopted. Without this the test could not tell a
        // correct guard from one that refuses every sample.
        let at_bound = &over[..SYNC_MIN_POPULATION as usize];
        assert!(
            matches!(
                adopt(&prior, Some(SYNC_MIN_POPULATION), at_bound),
                AdoptOutcome::Adopted { .. }
            ),
            "exactly at the population is not an excess"
        );
    }

    #[test]
    fn the_epoch_one_record_needs_no_census_height_and_still_seeds_a_walk() {
        let genesis = genesis();
        assert_eq!(
            genesis.census_height, None,
            "no census produced epoch 1, so there is no height to record"
        );
        assert_eq!(genesis.provenance, RecordProvenance::Bootstrap);
        assert_eq!(verify(&genesis, &honest(&genesis, 5, 2, 1_000)), Ok(()));
    }

    #[test]
    fn a_bare_epoch_record_line_reads_back_with_the_weakest_provenance() {
        // A line written before the envelope existed: no provenance, no height. Reading it as
        // `Censused` would upgrade an unaccounted-for record to "I verified this myself".
        let bare = serde_json::to_string(&EpochRecord::bootstrap()).expect("serialize");
        let parsed: StoredRecord = serde_json::from_str(&bare).expect("a bare record still parses");
        assert_eq!(parsed.record, EpochRecord::bootstrap());
        assert_eq!(parsed.census_height, None);
        assert_eq!(
            parsed.provenance,
            RecordProvenance::AdoptedFromPeers {
                agreed: 0,
                sampled: 0
            }
        );
    }
}
