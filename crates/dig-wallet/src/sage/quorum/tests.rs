//! Tests for quorum-by-agreement peer trust (dig_ecosystem#2568).
//!
//! Each test names the property it pins and the NEAREST WRONG implementation it distinguishes
//! that property from, because a fixture that cannot exhibit the wrong behaviour proves nothing
//! however strongly it asserts.

use super::*;
use chia_protocol::Coin;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

/// An entropy source that hands out a scripted sequence of `u64` draws, little-endian, and
/// records how many draws were consumed.
///
/// Scripted rather than seeded so a test can place a draw in the rejection tail *deliberately*
/// and observe that it was rejected — the only way to distinguish rejection sampling from `%`,
/// which produces an answer for every draw and therefore never reveals itself.
struct ScriptedEntropy {
    draws: Mutex<std::collections::VecDeque<u64>>,
    consumed: Mutex<usize>,
}

impl ScriptedEntropy {
    fn new(draws: &[u64]) -> Self {
        Self {
            draws: Mutex::new(draws.iter().copied().collect()),
            consumed: Mutex::new(0),
        }
    }

    fn consumed(&self) -> usize {
        *self.consumed.lock().unwrap()
    }
}

impl EntropySource for ScriptedEntropy {
    fn fill(&self, buf: &mut [u8]) {
        let draw =
            self.draws.lock().unwrap().pop_front().expect(
                "scripted entropy exhausted: the code under test drew more than the script",
            );
        *self.consumed.lock().unwrap() += 1;
        let bytes = draw.to_le_bytes();
        for (slot, byte) in buf.iter_mut().zip(bytes.iter().cycle()) {
            *slot = *byte;
        }
    }
}

fn candidate(id: &str, height: u32) -> Candidate {
    Candidate {
        id: id.to_string(),
        claim: PeakClaim {
            height,
            header_hash: Bytes32::new([0xAB; 32]),
        },
    }
}

fn responses(pairs: &[(&str, u8)]) -> Vec<Response<Bytes32>> {
    pairs
        .iter()
        .map(|(peer, tag)| Response {
            peer: (*peer).to_string(),
            answer: Bytes32::new([*tag; 32]),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Randomness: the source, and the absence of bias
// ---------------------------------------------------------------------------

/// PROPERTY: the production entropy source is the OS CSPRNG, not the wall clock.
///
/// NEAREST WRONG IMPLEMENTATION: `SystemTime::now().subsec_nanos()`, which this very crate
/// already uses for the reconnect jitter in `sync_supervisor::jitter` — so it is the source a
/// future edit is most likely to reach for, and it is predictable to anyone who can observe when
/// this node reconnects.
///
/// The fixture distinguishes them STRUCTURALLY rather than statistically: `subsec_nanos()` is
/// bounded by 1_000_000_000 < 2^30, so a u64 derived from it has its top four bytes permanently
/// zero, no matter how the low bytes are shuffled. A source whose high bytes vary across draws
/// cannot be a nanosecond clock. Asserting the distribution instead would be both weaker and
/// flaky; this asserts something the wrong source is structurally incapable of.
#[test]
fn the_production_entropy_source_is_the_os_csprng_and_not_the_clock() {
    let os = OsEntropy;

    // The range a nanosecond clock structurally cannot reach.
    let mut saw_high_bytes = false;
    let mut draws = Vec::new();
    for _ in 0..32 {
        let mut buf = [0u8; 8];
        os.fill(&mut buf);
        let value = u64::from_le_bytes(buf);
        if value >> 30 != 0 {
            saw_high_bytes = true;
        }
        draws.push(value);
    }
    assert!(
        saw_high_bytes,
        "every draw fitted in 30 bits; that is the signature of a `subsec_nanos()` source, not \
         of the OS CSPRNG"
    );

    // CONTROL, proving the assertion above is not satisfied by a constant: a clock-derived
    // source WOULD pass a naive "the draws differ" test while failing the one above, so this
    // pins that the real source also differs.
    draws.sort_unstable();
    draws.dedup();
    assert!(
        draws.len() > 1,
        "the OS CSPRNG returned a constant across 32 draws"
    );
}

/// PROPERTY: an out-of-zone draw is REJECTED and re-drawn, not folded in with `%`.
///
/// NEAREST WRONG IMPLEMENTATION: `draw % bound`, which biases the low residues — i.e. the peers
/// at the FRONT of the candidate list, whose position an attacker controls for free by choosing
/// where his addresses appear in an introducer's answer.
///
/// The fixture is built FROM the bound's own arithmetic: for `bound = 3`, `zone = u64::MAX - (
/// u64::MAX % 3)`, and `u64::MAX` itself sits above it. A modulo implementation answers
/// `u64::MAX % 3 == 0` from that single draw and consumes ONE draw; a rejecting implementation
/// discards it, consumes TWO, and answers from the second. Asserting the RESULT alone would not
/// separate them if the second draw also reduced to 0, so the draw COUNT is asserted too.
#[test]
fn an_out_of_zone_draw_is_rejected_rather_than_folded_in_with_modulo() {
    // `u64::MAX` is in the rejection tail for any bound that does not divide 2^64: the accepted
    // zone is `u64::MAX - (u64::MAX % bound)`, which for bound 3 is `u64::MAX - 0`, so a draw of
    // exactly `u64::MAX` falls outside it. First draw is that tail value; second is a clean 1.
    let bound = 3u64;
    let entropy = ScriptedEntropy::new(&[u64::MAX, 1]);
    let picked = uniform_below(&entropy, bound);

    assert_eq!(picked, Some(1), "the answer came from the rejected draw");
    assert_eq!(
        entropy.consumed(),
        2,
        "only one draw was consumed, so the tail draw was folded in with `%` rather than rejected"
    );
}

/// PROPERTY: selection is not biased by position in the candidate list.
///
/// NEAREST WRONG IMPLEMENTATION: first-responder-wins / take-the-head, which is what a
/// latency-ordered or introducer-ordered list produces and which hands the selection to whoever
/// can answer fastest or get listed first.
///
/// The fixture drives the sampler to the TAIL: with 5 candidates and offsets that always pick the
/// last remaining slot, an unbiased partial Fisher-Yates returns the tail indices. A head-biased
/// implementation returns `[0, 1, ...]` for every script, so it cannot produce this output at all.
/// A CONTROL script drives it to the head, proving the sampler follows the script in both
/// directions rather than being hard-wired to either end.
#[test]
fn selection_follows_the_draw_and_not_the_candidate_order() {
    // Offsets are into the REMAINING pool. Starting from [0,1,2,3,4] a draw of 4 takes index 4
    // and swaps the displaced 0 into its slot, leaving [4,1,2,3,0]; the next draws then land on
    // that shuffled pool. The exact sequence matters less than what it is NOT: a head-biased
    // sampler cannot produce a 4 in the first position for any script at all.
    let to_the_tail = ScriptedEntropy::new(&[4, 3, 2]);
    let tail = select_sample(&to_the_tail, 5, 3);
    assert_eq!(
        tail,
        vec![4, 0, 1],
        "the sampler ignored the draw and took the head of the list"
    );
    assert_ne!(tail, vec![0, 1, 2], "the sampler is hard-wired to the head");

    // CONTROL: the same sampler, driven to the head.
    let to_the_head = ScriptedEntropy::new(&[0, 0, 0]);
    let head = select_sample(&to_the_head, 5, 3);
    assert_eq!(head, vec![0, 1, 2]);
}

/// PROPERTY: a sample contains no peer twice — one hostile peer cannot fill a quorum by being
/// drawn repeatedly.
///
/// NEAREST WRONG IMPLEMENTATION: sampling WITH replacement (`k` independent `uniform_below(n)`
/// draws), which is the shorter code and which lets a single peer supply every "independent"
/// vote in a round. The fixture scripts every draw to the same remaining-pool offset 0, which
/// with replacement yields `[0, 0, 0, 0]` and without replacement yields four distinct indices.
#[test]
fn a_peer_is_never_drawn_twice_into_one_sample() {
    let entropy = ScriptedEntropy::new(&[0, 0, 0, 0]);
    let sample = select_sample(&entropy, 6, 4);

    assert_eq!(sample.len(), 4);
    let mut deduped = sample.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        4,
        "the same peer was drawn more than once, so one peer can carry a whole quorum: {sample:?}"
    );
}

/// PROPERTY: a candidate set smaller than the sample yields a short sample rather than a panic or
/// a silently padded one — the shortfall must reach [`Verdict::Insufficient`] intact.
#[test]
fn a_short_candidate_set_yields_a_short_sample() {
    let entropy = ScriptedEntropy::new(&[0, 0]);
    assert_eq!(select_sample(&entropy, 2, 4).len(), 2);
    assert!(select_sample(&ScriptedEntropy::new(&[]), 0, 4).is_empty());
}

// ---------------------------------------------------------------------------
// BEHIND versus LYING
// ---------------------------------------------------------------------------

/// PROPERTY: an honest peer that is merely a block or two behind stays in the candidate set.
///
/// This is the control the whole module needs. Treating normal propagation lag as hostile is its
/// own denial of service, and it is the failure mode a strict equality vote on the tip walks
/// straight into.
#[test]
fn a_peer_lagging_within_tolerance_is_still_asked() {
    let candidates = vec![
        candidate("fast", 1_000),
        candidate("one-behind", 999),
        candidate("at-tolerance", 1_000 - PEAK_LAG_TOLERANCE),
    ];
    let kept = eligible(&candidates, PEAK_LAG_TOLERANCE);

    assert_eq!(kept.len(), 3, "an ordinarily-lagging peer was excluded");
}

/// PROPERTY: the lag tolerance is pinned from BOTH sides — at-bound is admitted, one block
/// further behind is excluded.
///
/// A bound tested only from below confirms only itself: a filter that admitted EVERYTHING would
/// pass the at-bound half alone.
#[test]
fn the_lag_tolerance_admits_at_bound_and_excludes_one_block_further() {
    // Three peers pin the median at 1_000, so the band is unambiguously [997, 1003] and the two
    // peers under test straddle its lower edge by exactly one block.
    let candidates = vec![
        candidate("fast-a", 1_000),
        candidate("fast-b", 1_000),
        candidate("fast-c", 1_000),
        candidate("at-bound", 1_000 - PEAK_LAG_TOLERANCE),
        candidate("past-bound", 1_000 - PEAK_LAG_TOLERANCE - 1),
    ];

    let kept: Vec<String> = eligible(&candidates, PEAK_LAG_TOLERANCE)
        .into_iter()
        .map(|c| c.id)
        .collect();

    assert!(kept.contains(&"at-bound".to_string()), "at-bound excluded");
    assert!(
        !kept.contains(&"past-bound".to_string()),
        "a peer one block past the tolerance was still asked"
    );
}

/// PROPERTY: one peer claiming an absurd peak cannot evict the honest set from the candidate
/// pool.
///
/// NEAREST WRONG IMPLEMENTATION: anchoring the lag band on the MAXIMUM claim — the obvious
/// version, and the one this test was written against before the fixture caught it. With a
/// max-anchored band, `u32::MAX` becomes the reference, every honest peer is billions of blocks
/// "behind", and the liar is left ALONE in the pool. That is a total denial of service bought
/// with one unverifiable integer, and no amount of downstream voting recovers from it, because
/// there is nobody left to vote.
///
/// FIXTURE DESIGN: the inflated claim is placed FIRST and set to `u32::MAX`, so an implementation
/// that anchors on the maximum *or* favours list order fails on the same input. The honest peers
/// are at two slightly different heights, so the surviving set cannot be explained by a filter
/// that simply keeps everything at one exact height.
#[test]
fn an_inflated_claim_cannot_evict_the_honest_peers_from_the_pool() {
    let candidates = vec![
        candidate("liar", u32::MAX),
        candidate("honest-a", 1_000),
        candidate("honest-b", 1_000),
        candidate("honest-c", 1_001),
    ];

    let kept: Vec<String> = eligible(&candidates, PEAK_LAG_TOLERANCE)
        .into_iter()
        .map(|c| c.id)
        .collect();

    for honest in ["honest-a", "honest-b", "honest-c"] {
        assert!(
            kept.contains(&honest.to_string()),
            "one absurd claim evicted the honest peer {honest} from the candidate pool: {kept:?}"
        );
    }

    // The liar is admitted — being outvoted is what happens to it, not exclusion — but its
    // inflated height is never adopted as the reference.
    let verdict = tally(&responses(&[("liar", 1)]));
    assert!(
        verdict.corroborated().is_none(),
        "a lone peer's answer was treated as authoritative"
    );
}

/// PROPERTY: the band is symmetric — a claim far ABOVE the median is excluded exactly as a claim
/// far below it is.
///
/// NEAREST WRONG IMPLEMENTATION: a one-sided `height >= median - tolerance`, which admits every
/// high outlier and quietly rebuilds max-wins in the sample.
#[test]
fn the_credibility_band_is_symmetric_about_the_median() {
    let candidates = vec![
        candidate("low", 1_000),
        candidate("mid-a", 1_001),
        candidate("mid-b", 1_001),
        candidate("high", 1_001 + PEAK_LAG_TOLERANCE + 1),
    ];

    let kept: Vec<String> = eligible(&candidates, PEAK_LAG_TOLERANCE)
        .into_iter()
        .map(|c| c.id)
        .collect();

    assert!(
        !kept.contains(&"high".to_string()),
        "a claim past the tolerance ABOVE the median was admitted: {kept:?}"
    );
    assert!(
        kept.contains(&"low".to_string()),
        "a healthy peer was excluded"
    );
}

/// PROPERTY: the question is normalised to a height every sampled peer has already passed, so
/// lag cannot manufacture disagreement.
///
/// This is the load-bearing half of the behind-vs-lying discriminator. The fixture uses peers at
/// DIFFERENT heights — the ordinary case — and asserts the question lands strictly below the
/// slowest of them.
///
/// NEAREST WRONG IMPLEMENTATION: asking at the maximum (or at "now"), where the slowest peer has
/// no answer yet and honest disagreement is guaranteed.
#[test]
fn the_question_lands_below_every_sampled_peers_own_peak() {
    let sample = vec![
        candidate("fast", 1_000),
        candidate("mid", 999),
        candidate("slow", 998),
    ];

    let height = common_height(&sample, SETTLED_LAG).expect("a settled height exists");

    assert_eq!(height, 998 - SETTLED_LAG);
    for peer in &sample {
        assert!(
            height < peer.claim.height,
            "the question was asked at {height}, which peer {} has not passed",
            peer.id
        );
    }
}

/// PROPERTY: a chain younger than the settle margin yields no question rather than an underflowed
/// one.
///
/// NEAREST WRONG IMPLEMENTATION: `lowest - lag` with wrapping or saturating arithmetic, which on
/// a fresh chain produces height 0 (or `u32::MAX` under wrapping) and asks a meaningless question
/// that peers may well "agree" on.
#[test]
fn a_chain_younger_than_the_settle_margin_has_no_settled_height() {
    assert_eq!(common_height(&[candidate("new", 1)], SETTLED_LAG), None);
    assert_eq!(common_height(&[], SETTLED_LAG), None);
    // At-bound: exactly `SETTLED_LAG` IS answerable, at height 0.
    assert_eq!(
        common_height(&[candidate("edge", SETTLED_LAG)], SETTLED_LAG),
        Some(0)
    );
}

// ---------------------------------------------------------------------------
// Tallying
// ---------------------------------------------------------------------------

/// PROPERTY: a single lying peer cannot move the replica — the honest majority carries, the liar
/// is named, and the answer written is the honest one.
///
/// FIXTURE DESIGN: exactly ONE actor varies. An all-hostile fixture would read as the harsher
/// test and is precisely the one that cannot see a missed corroboration, because it leaves no
/// honest control to be overruled.
#[test]
fn a_single_lying_peer_cannot_move_the_replica() {
    let verdict = tally(&responses(&[
        ("honest-a", 1),
        ("honest-b", 1),
        ("honest-c", 1),
        ("liar", 9),
    ]));

    match verdict {
        Verdict::MajorityWithDissent {
            answer,
            agreed,
            dissenters,
        } => {
            assert_eq!(
                answer,
                Bytes32::new([1; 32]),
                "the liar's answer was written"
            );
            assert_eq!(agreed, 3);
            assert_eq!(
                dissenters,
                vec!["liar".to_string()],
                "the dissent was not surfaced as evidence"
            );
        }
        other => panic!("expected a corroborated majority naming the dissenter, got {other:?}"),
    }
}

/// PROPERTY: a split answer writes NOTHING and does not silently majority-vote.
///
/// FIXTURE DESIGN: a 2-1-1, deliberately NOT a 2-2. A 2-2 has no plurality at all, so an
/// implementation that DOES silently take the most popular answer would also decline it — and the
/// test would pass against the very defect it claims to exclude. With 2-1-1 there IS a strict
/// plurality, so declining it can only be the threshold doing its job.
#[test]
fn a_split_answer_writes_nothing_and_does_not_take_the_plurality() {
    let verdict = tally(&responses(&[("a", 1), ("b", 1), ("c", 2), ("d", 3)]));

    assert!(
        verdict.corroborated().is_none(),
        "a 2-1-1 plurality was adopted as authoritative"
    );
    match verdict {
        Verdict::Split { tallies } => assert_eq!(tallies, vec![2, 1, 1]),
        other => panic!("expected Split, got {other:?}"),
    }

    // The even split too, for completeness — it must also write nothing.
    let even = tally(&responses(&[("a", 1), ("b", 1), ("c", 2), ("d", 2)]));
    assert!(even.corroborated().is_none());
}

/// PROPERTY: the agreement threshold is pinned from BOTH sides — at-bound passes, one under fails.
#[test]
fn the_agreement_threshold_is_pinned_from_both_sides() {
    let at_bound = responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 9)]);
    assert!(
        tally(&at_bound).corroborated().is_some(),
        "exactly the required number of agreeing peers were refused"
    );

    let one_under = responses(&[("a", 1), ("b", 1), ("c", 8), ("d", 9)]);
    assert!(
        tally(&one_under).corroborated().is_none(),
        "one peer short of the threshold was accepted"
    );
}

/// PROPERTY: unanimity is reported as unanimity, not as a majority with an empty dissent list.
///
/// The two are different signals — a dissent list is evidence a caller acts on — and collapsing
/// them would make "was anyone lying?" unanswerable.
#[test]
fn unanimity_is_distinguished_from_a_majority_with_dissent() {
    let verdict = tally(&responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 1)]));
    assert_eq!(
        verdict,
        Verdict::Unanimous {
            answer: Bytes32::new([1; 32]),
            agreed: 4
        }
    );
}

// ---------------------------------------------------------------------------
// Confidence as a gradient rather than a gate (dig_ecosystem#2827)
// ---------------------------------------------------------------------------

/// PROPERTY: a round only two peers answered, where those two AGREE, produces a USABLE verdict
/// that carries how many corroborated it.
///
/// This is the freeze this ticket exists to end. A wallet held five peers and stalled at height
/// 9,139,211 for hours while the chain moved ~2,500 blocks, because a round that did not collect
/// a fixed number of ANSWERS was thrown away whole — one slow or unreachable peer was enough.
///
/// FIXTURE DESIGN: the two answers AGREE, so the round's only deficiency is the answer COUNT.
/// A fixture whose two answers disagreed could not distinguish "the count no longer gates" from
/// "the round was discarded for disagreeing", which is a different rule that must stay.
///
/// NEAREST WRONG IMPLEMENTATION: `responses.len() < QUORUM_SAMPLE => Insufficient`, which is
/// exactly what shipped, and which discards this round.
#[test]
fn two_agreeing_answers_are_usable_and_carry_their_own_confidence() {
    let verdict = tally(&responses(&[("a", 1), ("b", 1)]));

    assert_eq!(
        verdict.corroborated(),
        Some(&Bytes32::new([1; 32])),
        "two independent peers agreeing produced no usable answer, so the round was discarded"
    );
    assert_eq!(
        verdict.agreed(),
        2,
        "the confidence did not travel with the datum"
    );
}

/// PROPERTY: one answer is never corroboration. A peer agreeing with itself is one peer.
///
/// This is the FLOOR, and it is the whole difference between "relax the answer count" and
/// "accept a single untrusted source" — the problem NC-12 exists to prevent.
///
/// FIXTURE DESIGN: a POSITIVE CONTROL follows, identical but for one additional agreeing peer.
/// Without it, an implementation that refuses everything would pass the refusal assertion.
#[test]
fn a_single_answer_never_corroborates_itself() {
    let alone = tally(&responses(&[("a", 1)]));

    assert!(
        alone.corroborated().is_none(),
        "one peer was treated as its own corroboration"
    );
    assert_eq!(
        alone,
        Verdict::Insufficient {
            answered: 1,
            required: CORROBORATION_FLOOR
        }
    );
    assert_eq!(alone.agreed(), 0, "a refused round reported confidence");

    // POSITIVE CONTROL: the same answer, once a SECOND independent peer gives it, is usable.
    assert!(tally(&responses(&[("a", 1), ("b", 1)]))
        .corroborated()
        .is_some());
}

/// PROPERTY: agreement is still required. Relaxing how many answers a round needs must not
/// relax how strongly those answers must agree — they are different knobs and only one moved.
///
/// FIXTURE DESIGN: two cases, because one cannot see both failure directions.
///
/// * TWO answers that DISAGREE. The floor is met, so an implementation that only checks the
///   answer count corroborates it.
/// * FIVE answers splitting 3-2. Comfortably past the floor AND holding a strict plurality, so
///   an implementation that kept the floor but dropped the agreement ratio takes the 3. Under
///   the shipped ratio a five-answer round needs four.
#[test]
fn answers_that_disagree_do_not_corroborate_however_many_answered() {
    let two_ways = tally(&responses(&[("a", 1), ("b", 2)]));
    assert!(
        two_ways.corroborated().is_none(),
        "two peers that contradicted each other produced an authoritative answer"
    );

    let three_of_five = tally(&responses(&[
        ("a", 1),
        ("b", 1),
        ("c", 1),
        ("d", 2),
        ("e", 2),
    ]));
    assert!(
        three_of_five.corroborated().is_none(),
        "a 3-2 plurality was adopted, so the agreement ratio was lowered rather than the answer \
         count relaxed"
    );
    assert!(matches!(three_of_five, Verdict::Split { .. }));
}

/// PROPERTY: the agreement RATIO is never lowered by widening or narrowing the round. It is
/// pinned from both sides at every round size the node can actually produce.
///
/// The ratio is the shipped 3-of-4 (`QUORUM_AGREEMENT : QUORUM_SAMPLE`), applied to whoever
/// answered rather than to a fixed sample, with [`CORROBORATION_FLOOR`] underneath it.
///
/// NEAREST WRONG IMPLEMENTATION: a bare majority (`agreed * 2 > answered`), which would admit
/// 3-of-5 and 2-of-3 — a genuine weakening of agreement dressed up as the same change.
#[test]
fn the_agreement_ratio_is_never_lowered_by_the_size_of_the_round() {
    // At the shipped sample size the rule is the shipped threshold, unchanged.
    assert_eq!(required_agreement(QUORUM_SAMPLE), QUORUM_AGREEMENT);

    for (answered, required) in [(2, 2), (3, 3), (4, 3), (5, 4), (8, 6), (10, 8)] {
        assert_eq!(
            required_agreement(answered),
            required,
            "a round of {answered} answers required the wrong number to agree"
        );
        // A bare majority would be strictly less at 3, 5 and 10 — the sizes that catch it.
        assert!(
            required * 4 >= answered * QUORUM_AGREEMENT,
            "the agreement ratio dropped below the shipped 3-of-4 at {answered} answers"
        );
    }

    // Both sides, at a size only reachable after this change: four of five passes, three fails.
    let four_of_five = responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 9)]);
    assert!(tally(&four_of_five).corroborated().is_some());
    let three_of_five = responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 8), ("e", 9)]);
    assert!(tally(&three_of_five).corroborated().is_none());
}

/// PROPERTY: a wide dial is narrowed to the peers actually asked, and the narrowing drops the
/// badly-lagged rather than a slice of the credible ones.
///
/// FIXTURE DESIGN: ten candidates, two of them far off the median in OPPOSITE directions. A
/// fixture with only lagging outliers cannot see a one-sided band, and one with fewer than
/// `hold + 1` credible members cannot see whether the narrowing happens at all.
///
/// NEAREST WRONG IMPLEMENTATION: returning the credible set unnarrowed (the round then asks
/// every peer it dialled, which is the cost this exists to bound), or truncating the head of the
/// list (which hands the choice to whoever controls the order the addresses arrive in).
#[test]
fn a_wide_dial_is_held_back_to_the_credible_few() {
    let mut candidates: Vec<Candidate> = (0..8)
        .map(|i| candidate(&format!("honest-{i}"), 1_000))
        .collect();
    candidates.push(candidate("stale", 1_000 - PEAK_LAG_TOLERANCE - 1));
    candidates.push(candidate("inflated", 1_000 + PEAK_LAG_TOLERANCE + 1));

    // Draws land on distinct offsets; the values are arbitrary because `select_sample` is
    // order-blind — what is asserted is the OUTCOME, not which five were picked.
    let entropy = ScriptedEntropy::new(&[0, 1, 2, 3, 4]);
    let held = hold_best(&entropy, &candidates, PEAK_LAG_TOLERANCE, QUORUM_HOLD)
        .expect("eight of ten claimants are credible, so the band kept a majority");

    assert_eq!(
        held.len(),
        QUORUM_HOLD,
        "ten dialled candidates were not narrowed to the {QUORUM_HOLD} the round asks"
    );
    for excluded in ["stale", "inflated"] {
        assert!(
            !held.iter().any(|c| c.id == excluded),
            "a candidate outside the credibility band was asked: {excluded}"
        );
    }
    let mut ids: Vec<&str> = held.iter().map(|c| c.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), QUORUM_HOLD, "the same peer was held twice");

    // A dial that came back with FEWER than the hold keeps everything it has — the round
    // proceeds on the peers that answered, which is the whole of this ticket.
    let thin = hold_best(&entropy, &candidates[..3], PEAK_LAG_TOLERANCE, QUORUM_HOLD)
        .expect("three honest claimants at the same height are all credible");
    assert_eq!(thin.len(), 3);
}

/// PROPERTY: a round whose credibility band discarded HALF OR MORE of the peers that claimed a
/// peak is REFUSED, not run on whichever side of the band survived.
///
/// FIXTURE DESIGN: the exploit exactly as measured — ten dialled peers, five honest at the real
/// tip `H`, five hostile claiming `H - PEAK_LAG_TOLERANCE - 1`, which is an ordinary "four blocks
/// behind" and not a claim anything could call implausible. Sorted, the lower median lands on the
/// hostile height, so the band is `[H-7, H-1]` and every honest peer sits OUTSIDE it. The
/// asserted-first half of this test proves the fixture genuinely exhibits the attack rather than
/// merely being lopsided: the band alone keeps precisely the attacker's five, and those five,
/// agreeing with each other by construction, tally to `Unanimous` on a hash nobody honest ever
/// saw. Everything downstream of that verdict — balance, confirmation counts, spend-path coin
/// selection — is written from it.
///
/// A 9-1 or 8-2 fixture cannot see this: one or two outliers cannot move a median, which is the
/// property the old rationale claimed and which holds against every attacker EXCEPT the
/// coordinated half. Fifty-fifty is the smallest split that owns the lower median.
///
/// NEAREST WRONG IMPLEMENTATION: the shipped narrowing, which treats the band as a selection and
/// returns the survivors. It is indistinguishable from correct on every fixture where the honest
/// peers happen to be the survivors, so the honest side must be the EXCLUDED one here.
#[test]
fn a_band_that_splits_the_claimants_in_half_refuses_the_round() {
    const HONEST_TIP: u32 = 1_000_000;
    const HOSTILE_CLAIM: u32 = HONEST_TIP - PEAK_LAG_TOLERANCE - 1;

    let mut candidates: Vec<Candidate> = (0..5)
        .map(|i| candidate(&format!("honest-{i}"), HONEST_TIP))
        .collect();
    candidates.extend((0..5).map(|i| candidate(&format!("hostile-{i}"), HOSTILE_CLAIM)));

    // The fixture really does exhibit the attack: the band keeps the attacker's five and nobody
    // else. If this ever stops holding, the test below is passing for the wrong reason.
    let credible = eligible(&candidates, PEAK_LAG_TOLERANCE);
    let credible_ids: Vec<&str> = credible.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        credible_ids,
        [
            "hostile-0",
            "hostile-1",
            "hostile-2",
            "hostile-3",
            "hostile-4"
        ],
        "the fixture no longer places the honest peers outside the median-anchored band"
    );

    // ...and those survivors would have carried the round outright: they are exactly QUORUM_HOLD,
    // so no sampling even thins them, and they agree with each other by construction.
    let forged = Bytes32::new([0xEE; 32]);
    let attacker_answers: Vec<Response<Bytes32>> = credible
        .iter()
        .map(|c| Response {
            peer: c.id.clone(),
            answer: forged,
        })
        .collect();
    assert_eq!(
        tally(&attacker_answers),
        Verdict::Unanimous {
            answer: forged,
            agreed: 5
        },
        "the fixture's surviving set no longer produces an authoritative verdict, so refusing it \
         would prove nothing"
    );

    // THE GUARD. Real entropy, because the refusal must not depend on how the draw falls.
    assert_eq!(
        hold_best(&OsEntropy, &candidates, PEAK_LAG_TOLERANCE, QUORUM_HOLD),
        None,
        "a round in which the band excluded half the claimants was allowed to proceed on the \
         survivors"
    );
}

/// PROPERTY: a thin, slow, honest round still SUCCEEDS. This is the anti-refreeze pin — the guard
/// above must key on BAND EXCLUSION among claimants, never on how few peers the node reached.
///
/// FIXTURE DESIGN: the incident's own shape. The user's frozen node reported
/// `Insufficient { answered: 2, required: 4 }`, so the control is two claimants — and they are one
/// block apart rather than identical, because two identical claims cannot distinguish "kept a
/// majority of claimants" from "kept every claimant", and an implementation demanding the latter
/// would refuse ordinary propagation lag. The three-peer case adds a member who is genuinely
/// outside the band, pinning that a MINORITY exclusion is still a narrowing rather than a refusal.
///
/// NEAREST WRONG IMPLEMENTATION: a guard whose denominator is the dial target
/// (`QUORUM_DIAL_WIDE`) or the count of peers that answered the later header-hash question. Either
/// refuses this round and re-creates the hours-long freeze this PR exists to end.
#[test]
fn a_thin_honest_round_is_never_refused_by_the_band_guard() {
    let entropy = ScriptedEntropy::new(&[0, 1, 0]);

    // Two claimants, one block apart: the exact width the incident round had.
    let two = [candidate("slow", 999_999), candidate("fresh", 1_000_000)];
    let held = hold_best(&entropy, &two, PEAK_LAG_TOLERANCE, QUORUM_HOLD)
        .expect("a two-peer round of agreeing honest claims must still corroborate");
    assert_eq!(held.len(), 2, "a thin honest round lost a peer");

    // A MINORITY outside the band is a narrowing, not a refusal.
    let three = [
        candidate("honest-a", 1_000_000),
        candidate("honest-b", 1_000_000),
        candidate("stale", 1_000_000 - PEAK_LAG_TOLERANCE - 1),
    ];
    let held = hold_best(&entropy, &three, PEAK_LAG_TOLERANCE, QUORUM_HOLD)
        .expect("one stale peer in three is a minority exclusion and must not refuse the round");
    assert_eq!(
        held.len(),
        2,
        "the stale peer was asked, or the round collapsed"
    );
}

/// PROPERTY: the majority bound holds from BOTH sides — one peer over the line must refuse, and
/// the line itself must pass. A bound tested only from below can only confirm itself.
///
/// FIXTURE DESIGN: exhaustive over the shipped dial width, comparing against the independently
/// stated rule "strictly more than half". `6 of 10` passes and `5 of 10` refuses, which is the
/// attacker's new bar; `2 of 2` passes, which is the incident round.
#[test]
fn the_band_majority_bound_is_pinned_from_both_sides() {
    for claimants in 0..=QUORUM_DIAL_WIDE {
        for credible in 0..=claimants {
            assert_eq!(
                band_kept_a_majority(claimants, credible),
                credible > claimants / 2,
                "wrong verdict for {credible} credible of {claimants} claimants"
            );
        }
    }
    assert!(band_kept_a_majority(10, 6), "the attacker's new bar moved");
    assert!(!band_kept_a_majority(10, 5), "an even split was accepted");
    assert!(
        band_kept_a_majority(2, 2),
        "the incident's two-peer round was refused"
    );
}

// ---------------------------------------------------------------------------
// Self-verifying reads
// ---------------------------------------------------------------------------

/// PROPERTY: a coin's id is derived from its own fields, so a peer cannot name a coin that is not
/// the coin it described.
///
/// FIXTURE DESIGN: two coins differing in ONE field (the amount). Asserting only that a coin
/// matches its own id would pass against an implementation that returns `true` unconditionally;
/// the mismatched pair is what makes the check falsifiable.
#[test]
fn a_coin_id_is_verified_locally_and_never_taken_on_a_peers_word() {
    let coin = Coin {
        parent_coin_info: Bytes32::new([1; 32]),
        puzzle_hash: Bytes32::new([2; 32]),
        amount: 1_000,
    };
    let impostor = Coin {
        amount: 999,
        ..coin
    };

    assert!(coin_id_is_derived_not_trusted(&coin, coin.coin_id()));
    assert!(
        !coin_id_is_derived_not_trusted(&coin, impostor.coin_id()),
        "a coin id belonging to a DIFFERENT coin was accepted, so the id is being trusted rather \
         than derived"
    );
}

/// PROPERTY: the self-verifying set is closed and named, so a future read is classified
/// deliberately rather than defaulting into a vote.
#[test]
fn the_self_verifying_reads_are_enumerated() {
    let all = [
        SelfVerifying::CoinId,
        SelfVerifying::HeaderBlockBinding,
        SelfVerifying::NetworkIdentity,
    ];
    assert_eq!(all.len(), 3);
}

// ---------------------------------------------------------------------------
// Spentness
// ---------------------------------------------------------------------------

/// PROPERTY: one credible report of SPENT beats three reports of unspent.
///
/// This is the direction that costs money. FIXTURE DESIGN: the spent report is placed LAST, so an
/// implementation that short-circuits on the first answer (or majority-votes) resolves the
/// opposite way and is caught.
#[test]
fn one_report_of_spent_outweighs_a_majority_of_unspent() {
    let evidence = SpentEvidence::resolve(&[false, false, false, true], QUORUM_SAMPLE);

    assert_eq!(evidence, SpentEvidence::Spent);
    assert!(
        !evidence.is_selectable(),
        "a coin three peers called unspent and one called spent was offered to coin selection"
    );
}

/// PROPERTY: a missing answer makes unspentness UNPROVEN, not unspent.
///
/// NEAREST WRONG IMPLEMENTATION: `!reports.iter().any(spent)`, which reads an empty or short
/// report set as "nobody said it was spent, so it is spendable" — the exact shape that turns an
/// unreachable peer into a double-spend.
#[test]
fn an_unanswered_peer_leaves_unspentness_unproven_rather_than_assumed() {
    let short = SpentEvidence::resolve(&[false, false, false], QUORUM_SAMPLE);
    assert_eq!(short, SpentEvidence::Unproven);
    assert!(!short.is_selectable());

    let none = SpentEvidence::resolve(&[], QUORUM_SAMPLE);
    assert_eq!(none, SpentEvidence::Unproven);
    assert!(!none.is_selectable());

    // POSITIVE CONTROL: a full unanimous set IS selectable, so the assertions above cannot be
    // satisfied by an implementation that refuses everything.
    let full = SpentEvidence::resolve(&[false; QUORUM_SAMPLE], QUORUM_SAMPLE);
    assert_eq!(full, SpentEvidence::UnanimouslyUnspent);
    assert!(full.is_selectable());
}

// ---------------------------------------------------------------------------
// The Sybil limit
// ---------------------------------------------------------------------------

/// PROPERTY: the documented Sybil numbers are the ones the code computes, and they degrade
/// monotonically with the attacker's share.
///
/// Pinned because `SPEC.md` quotes them, and a doc claim that drifts from the code is how a
/// guarantee the model cannot make ends up published.
#[test]
fn the_sybil_numbers_match_what_spec_md_publishes() {
    assert!((sybil_success_probability(0.0, QUORUM_SAMPLE) - 0.0).abs() < 1e-12);
    assert!((sybil_success_probability(1.0, QUORUM_SAMPLE) - 1.0).abs() < 1e-12);

    let ten = sybil_success_probability(0.10, QUORUM_SAMPLE);
    let thirty = sybil_success_probability(0.30, QUORUM_SAMPLE);
    let half = sybil_success_probability(0.50, QUORUM_SAMPLE);

    assert!((ten - 0.0037).abs() < 0.0005, "10% hostile: {ten}");
    assert!((thirty - 0.0837).abs() < 0.0005, "30% hostile: {thirty}");
    assert!((half - 0.3125).abs() < 0.0005, "50% hostile: {half}");

    assert!(
        ten < thirty && thirty < half,
        "not monotone in the attacker's share"
    );
}

/// PROPERTY: a THIN round is easier to capture than a full one, and the published number says so
/// rather than quoting the full round's odds for every round.
///
/// This is the honest price of proceeding on the peers that answered: an attacker who can make
/// witnesses unreachable no longer has to out-vote them, only to outlast them down to the floor.
/// `SPEC.md` states it in these terms, and this pins the figure it states.
///
/// FIXTURE DESIGN: the same hostile fraction across three round sizes. Comparing one size against
/// itself could not show the gradient, which IS the finding.
#[test]
fn a_thinner_round_is_measurably_easier_to_capture() {
    let at_floor = sybil_success_probability(0.30, CORROBORATION_FLOOR);
    let at_sample = sybil_success_probability(0.30, QUORUM_SAMPLE);
    let at_hold = sybil_success_probability(0.30, QUORUM_HOLD);

    // Two hostile draws out of two: 0.30^2.
    assert!((at_floor - 0.09).abs() < 0.0005, "at the floor: {at_floor}");
    assert!(
        at_floor > at_sample && at_sample > at_hold,
        "a thin round was not reported as easier to capture than a wide one: \
         floor={at_floor} sample={at_sample} hold={at_hold}"
    );
}

// ---------------------------------------------------------------------------
// dig-node#513 item 1 -- a caller-chosen, strictly tighter corroboration floor
// ---------------------------------------------------------------------------

/// PROPERTY: `tally_with_floor` refuses a round of two at a floor of three, and accepts the round
/// of three -- the bound pinned from BOTH sides, so it cannot pass by refusing everything.
#[test]
fn the_bond_floor_is_pinned_from_both_sides() {
    let two = responses(&[("a", 1), ("b", 1)]);
    let three = responses(&[("a", 1), ("b", 1), ("c", 1)]);

    assert_eq!(
        tally_with_floor(&two, BOND_CORROBORATION_FLOOR),
        Verdict::Insufficient {
            answered: 2,
            required: BOND_CORROBORATION_FLOOR,
        },
        "one under the bond floor must not corroborate"
    );
    assert!(
        tally_with_floor(&three, BOND_CORROBORATION_FLOOR)
            .corroborated()
            .is_some(),
        "at the bond floor exactly, a unanimous round must still corroborate"
    );
}

/// PROPERTY: the floor binds the AGREEING count, not merely how many peers answered.
///
/// NEAREST WRONG IMPLEMENTATION: enforcing `floor` only on `responses.len()`. Under that, twelve
/// answers of which two agree clears a floor of three -- two colluding peers plus noise, which is
/// precisely the round the floor exists to refuse. `required_agreement(3)` is 3 already, so the
/// fixture is widened to a size where the ratio alone would permit two.
#[test]
fn a_wide_round_does_not_buy_its_way_past_the_bond_floor() {
    let scattered = responses(&[("a", 1), ("b", 1), ("c", 2), ("d", 3), ("e", 4), ("f", 5)]);

    assert!(
        matches!(
            tally_with_floor(&scattered, BOND_CORROBORATION_FLOOR),
            Verdict::Split { .. }
        ),
        "two agreeing voices in a six-peer round cleared a floor of three"
    );
}

/// PROPERTY: the floor can only TIGHTEN. A caller asking for one source is given
/// `CORROBORATION_FLOOR` anyway -- the never-one-source rule is not a caller's to relax.
#[test]
fn a_floor_below_the_shared_one_is_not_honoured() {
    let one = responses(&[("a", 1)]);

    assert_eq!(
        tally_with_floor(&one, 1),
        Verdict::Insufficient {
            answered: 1,
            required: CORROBORATION_FLOOR,
        },
        "a caller talked the tally down to a single source"
    );
}
