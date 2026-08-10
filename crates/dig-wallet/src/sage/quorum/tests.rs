//! Tests for quorum-by-agreement peer trust (dig_ecosystem#2568).
//!
//! Each test names the property it pins and the NEAREST WRONG implementation it distinguishes
//! that property from, because a fixture that cannot exhibit the wrong behaviour proves nothing
//! however strongly it asserts.

use super::*;
use chia::protocol::Coin;
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
        let draw = self
            .draws
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted entropy exhausted: the code under test drew more than the script");
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
    let bound = 3u64;
    let zone = u64::MAX - (u64::MAX % bound);
    assert!(
        u64::MAX >= zone,
        "fixture is not exercising the rejection tail; pick a draw at or above the zone"
    );

    // First draw is in the tail; second is a clean 1.
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
    let verdict = tally(&responses(&[("liar", 1)]), QUORUM_SAMPLE, QUORUM_AGREEMENT);
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
    assert!(kept.contains(&"low".to_string()), "a healthy peer was excluded");
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
    let verdict = tally(
        &responses(&[("honest-a", 1), ("honest-b", 1), ("honest-c", 1), ("liar", 9)]),
        QUORUM_SAMPLE,
        QUORUM_AGREEMENT,
    );

    match verdict {
        Verdict::MajorityWithDissent {
            answer,
            agreed,
            dissenters,
        } => {
            assert_eq!(answer, Bytes32::new([1; 32]), "the liar's answer was written");
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
    let verdict = tally(
        &responses(&[("a", 1), ("b", 1), ("c", 2), ("d", 3)]),
        QUORUM_SAMPLE,
        QUORUM_AGREEMENT,
    );

    assert!(
        verdict.corroborated().is_none(),
        "a 2-1-1 plurality was adopted as authoritative"
    );
    match verdict {
        Verdict::Split { tallies } => assert_eq!(tallies, vec![2, 1, 1]),
        other => panic!("expected Split, got {other:?}"),
    }

    // The even split too, for completeness — it must also write nothing.
    let even = tally(
        &responses(&[("a", 1), ("b", 1), ("c", 2), ("d", 2)]),
        QUORUM_SAMPLE,
        QUORUM_AGREEMENT,
    );
    assert!(even.corroborated().is_none());
}

/// PROPERTY: the agreement threshold is pinned from BOTH sides — at-bound passes, one under fails.
#[test]
fn the_agreement_threshold_is_pinned_from_both_sides() {
    let at_bound = responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 9)]);
    assert!(
        tally(&at_bound, QUORUM_SAMPLE, QUORUM_AGREEMENT)
            .corroborated()
            .is_some(),
        "exactly QUORUM_AGREEMENT agreeing peers were refused"
    );

    let one_under = responses(&[("a", 1), ("b", 1), ("c", 8), ("d", 9)]);
    assert!(
        tally(&one_under, QUORUM_SAMPLE, QUORUM_AGREEMENT)
            .corroborated()
            .is_none(),
        "one peer short of the threshold was accepted"
    );
}

/// PROPERTY: unanimity is reported as unanimity, not as a majority with an empty dissent list.
///
/// The two are different signals — a dissent list is evidence a caller acts on — and collapsing
/// them would make "was anyone lying?" unanswerable.
#[test]
fn unanimity_is_distinguished_from_a_majority_with_dissent() {
    let verdict = tally(
        &responses(&[("a", 1), ("b", 1), ("c", 1), ("d", 1)]),
        QUORUM_SAMPLE,
        QUORUM_AGREEMENT,
    );
    assert_eq!(verdict, Verdict::Unanimous(Bytes32::new([1; 32])));
}

/// PROPERTY: too few answers is `Insufficient`, NOT a quorum among whoever replied.
///
/// FIXTURE DESIGN: three peers UNANIMOUSLY agree — which clears `QUORUM_AGREEMENT` on its own.
/// An implementation that tallied against the responders rather than against the sample size
/// would corroborate this happily, and a fixture with disagreeing responders could not tell the
/// two apart. Reachability is not consensus: an attacker who can make one peer unreachable must
/// not thereby shrink the quorum he has to capture.
#[test]
fn too_few_answers_is_insufficient_and_not_a_quorum_among_the_responders() {
    let verdict = tally(
        &responses(&[("a", 1), ("b", 1), ("c", 1)]),
        QUORUM_SAMPLE,
        QUORUM_AGREEMENT,
    );

    assert!(
        verdict.corroborated().is_none(),
        "three unanimous responders were allowed to form a quorum of four"
    );
    assert_eq!(
        verdict,
        Verdict::Insufficient {
            answered: 3,
            required: QUORUM_SAMPLE
        }
    );
}

/// PROPERTY: the compile-time floor holds — the threshold is a strict majority, so two
/// contradictory answers can never both reach quorum in one round.
#[test]
fn the_threshold_is_a_strict_majority_of_the_sample() {
    assert!(QUORUM_AGREEMENT * 2 > QUORUM_SAMPLE);
    assert!(QUORUM_AGREEMENT <= QUORUM_SAMPLE);
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
    let impostor = Coin { amount: 999, ..coin };

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
    assert!((sybil_success_probability(0.0) - 0.0).abs() < 1e-12);
    assert!((sybil_success_probability(1.0) - 1.0).abs() < 1e-12);

    let ten = sybil_success_probability(0.10);
    let thirty = sybil_success_probability(0.30);
    let half = sybil_success_probability(0.50);

    assert!((ten - 0.0037).abs() < 0.0005, "10% hostile: {ten}");
    assert!((thirty - 0.0837).abs() < 0.0005, "30% hostile: {thirty}");
    assert!((half - 0.3125).abs() < 0.0005, "50% hostile: {half}");

    assert!(ten < thirty && thirty < half, "not monotone in the attacker's share");
}
