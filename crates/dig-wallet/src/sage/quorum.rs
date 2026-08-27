//! Quorum-by-agreement peer trust for the light client (dig_ecosystem#2568).
//!
//! dig-node is a Chia **light client**: it holds no chain of its own and learns every fact about
//! mainnet from full nodes it did not choose. Until this module, [`crate::sage::sync::PeerTrust`]
//! resolved that by refusing discovered peers any write at all, which is safe and also means a
//! DEFAULT install never syncs — `initial_sync_complete` stays false and the replica peak stays
//! NULL forever. That is not a light client; it is a light client with the light off.
//!
//! The replacement is the one the user settled: there are no operator-chosen peers to fall back
//! on, so **a discovered peer's answer becomes authoritative when enough independently and
//! randomly chosen peers agree with it, and never on its own.**
//!
//! # The problem this module actually has to solve
//!
//! Voting on "what is the chain tip" does not work, and the reason is not subtle: Chia produces a
//! block roughly every 18.75s, so at any instant honest peers hold DIFFERENT tips. A naive
//! equality vote over `(height, header_hash)` splits almost always, writes nothing almost always,
//! and turns ordinary network lag into a permanent stall — a denial of service the node inflicts
//! on itself. This is not hypothetical: twelve consecutive single-peer polls of one address
//! through `chia-query`'s router returned `2,2,2,2,2,2,0,2,2,2,2,0`, and reading those two zeroes
//! as hostile would be just as wrong as reading them as truth. They were peers that had not
//! caught up.
//!
//! So the module's central job is to tell **BEHIND** from **LYING**, which look identical in any
//! single answer. It does that in two steps, in this order:
//!
//! 1. **Exclude the badly-lagged** ([`eligible`]). A peer whose claimed peak sits more than
//!    [`PEAK_LAG_TOLERANCE`] blocks below the best claim in the candidate set is not asked. It is
//!    not accused of anything either — it is simply not a useful witness right now.
//! 2. **Normalise the question to a height every remaining peer has already reached**
//!    ([`common_height`]). Every question this module votes on is asked *as of*
//!    `min(claimed peaks) − `[`SETTLED_LAG`], never as of "now". At a settled height in the shared
//!    past, a lagging-but-honest peer and a fully-caught-up peer hold the **same** answer, so
//!    lag stops being a source of disagreement at all.
//!
//! After those two steps, a peer that still disagrees is claiming a peak it has reached and then
//! contradicting the majority about the settled past. That is a lie, a partition, or a fork —
//! never ordinary lag — and [`Verdict`] treats it as evidence rather than as a tie to break.
//!
//! # Sage as a reference, and where dig-node deliberately differs
//!
//! Sage (`xch-dev/sage`, Apache-2.0) is a production Chia light client solving the same problem.
//! Nothing here is copied from it — it is Apache-2.0 against this crate's GPL-2.0-only, and more
//! importantly a lifted block carries assumptions that do not travel. Two of its DECISIONS are
//! adopted, re-derived and re-implemented in dig-node's own terms:
//!
//! * **Do not vote on the tip; tolerate a small lag band.** Sage admits a peer to its pool only
//!   while its claimed peak is within 3 blocks of the pool's, and evicts one that falls further
//!   behind — with the reason recorded as "peer is behind", a cool-off rather than an accusation.
//!   That band is production evidence for where ordinary lag ends, and [`PEAK_LAG_TOLERANCE`]
//!   takes the same value for the same reason.
//! * **~5 concurrent peer connections is an acceptable cost for a light client.** Sage's default
//!   `target_peers` is 5. [`QUORUM_SAMPLE`] of 4 sits inside that envelope, so corroboration does
//!   not make dig-node a heavier network citizen than a shipped desktop wallet.
//!
//! Where dig-node departs: Sage syncs its wallet from **one** peer and takes the **maximum**
//! claimed peak across its pool, defending itself by banning peers that misbehave. That is a
//! reasonable trade for an attended desktop wallet whose user is looking at the balance. It is
//! the wrong trade here, and adopting it would revert a finding this crate already paid for:
//! dig-node is an **unattended OS service** whose replica feeds spend-path coin selection and
//! whose peak is divided into confirmation counts served over RPC. A maximum is the single most
//! attacker-friendly aggregate available — one inflated claim wins outright and raises apparent
//! confirmations — which is exactly the inversion recorded in [`crate::sage::sync::PeerTrust`].
//! Corroboration replaces the ban-after-the-fact posture with a refuse-before-the-write one.
//!
//! # What is voted on, and what is not
//!
//! Voting on a fact the node can check for itself is wasted round trips and, worse, invites the
//! majority to overrule arithmetic. Three classes, and only the third reaches [`tally`]:
//!
//! * **Self-verifying, checked locally, never voted** — see [`SelfVerifying`]. A coin id is the
//!   hash of the coin's own fields; a header block's hash is the hash of its own contents; the
//!   genesis challenge and network id are values this node pins and the handshake enforces. No
//!   quorum can make any of these true or false.
//! * **Monotone, resolved by fail-closed union rather than by vote** — see [`SpentEvidence`]. A
//!   coin's spentness only ever moves one way, and the expensive error is one-directional too:
//!   believing a spent coin is spendable is what produces a DOUBLE_SPEND. Omission is not
//!   evidence of absence, so a peer that has not seen a spend does not get to outvote one that
//!   has.
//! * **Genuinely contested, quorum'd** — the canonical header hash at a settled height, and the
//!   coin set for the subscribed puzzle hashes at that height. Nothing local can decide these,
//!   and an honest majority is the only handle available.
//!
//! # The Sybil limit
//!
//! Stated plainly, and stated again in `SPEC.md`: random selection raises an attacker's cost; it
//! does not eliminate the attack. See [`sybil_success_probability`].

use std::collections::HashMap;
use std::hash::Hash;

use chia_protocol::Bytes32;

// ---------------------------------------------------------------------------
// The tunable policy, and why each number is what it is
// ---------------------------------------------------------------------------

/// The sample size the agreement RATIO is expressed against (see [`required_agreement`]).
///
/// Until dig_ecosystem#2827 this was also the number of ANSWERS a round had to collect before it
/// counted for anything, and that second job is what froze a user's replica at height 9,139,211
/// for hours while five peers were held and the chain moved ~2,500 blocks: one slow or
/// unreachable member discarded the whole round, every round. A round now proceeds on the peers
/// that ANSWERED (see [`CORROBORATION_FLOOR`]) and this constant keeps only its first job —
/// naming, with [`QUORUM_AGREEMENT`], how strongly those answers must agree.
///
/// Four is the smallest sample that makes every outcome in [`Verdict`] distinguishable while
/// staying inside a light client's normal connection budget:
///
/// * Fewer than three cannot express "majority with dissent" at all — with two peers every
///   disagreement is a bare split carrying no information about which side is anomalous, so the
///   module would learn nothing from the very event it exists to notice.
/// * Three would work, but leaves no margin: one peer mid-reorg, or one that answers a settled
///   height wrongly through a bug, drops the sample to a 2-1 that only just clears
///   [`QUORUM_AGREEMENT`], and a second such peer stalls sync entirely.
/// * Four costs one more TCP+TLS handshake to a full node per corroboration round. Sage ships a
///   default `target_peers` of 5, so four concurrent peer connections is demonstrably an
///   acceptable load for a light client on a home connection.
///
/// It is deliberately NOT larger. Every additional peer widens the window in which an attacker
/// who controls a slice of the discoverable set lands two members in one sample, and buys less
/// certainty than it costs in round trips.
pub const QUORUM_SAMPLE: usize = 4;

/// How many of the [`QUORUM_SAMPLE`] must return the SAME answer for it to be written.
///
/// Three of four: a strict supermajority, tolerating exactly one dissenter.
///
/// One dissenter is the case that must not stall the node, because it happens without an attacker
/// — a peer part-way through applying a reorg, a peer with a corrupt index, a peer that answers a
/// settled height from a pruned store. Two dissenters is a different animal: at a settled height,
/// past the lag filter, two peers agreeing with each other and against the rest is a partition or
/// a coordinated lie, and neither is something to resolve by counting.
///
/// The floor is checked at compile time below: this must always exceed half of
/// [`QUORUM_SAMPLE`], or "the quorum" could be satisfied by two disjoint answers at once.
pub const QUORUM_AGREEMENT: usize = 3;

const _: () = assert!(
    QUORUM_AGREEMENT * 2 > QUORUM_SAMPLE,
    "the agreement threshold must be a strict majority of the sample, or two contradictory \
     answers could each 'reach quorum' in the same round"
);
const _: () = assert!(
    QUORUM_AGREEMENT <= QUORUM_SAMPLE,
    "the agreement threshold cannot exceed the sample size"
);

/// The fewest answers that can corroborate anything (dig_ecosystem#2827).
///
/// Two, and the reason is definitional rather than statistical: **a single source is never
/// corroboration.** One peer agreeing with itself is one peer, and admitting it would reinstate
/// the single-untrusted-source problem this whole module exists to remove — a discovered peer
/// would once again be able to move the replica on nobody's word but its own.
///
/// It is the floor UNDER the ratio, not a replacement for it: a round of two must be unanimous
/// (`required_agreement(2) == 2`), so the floor buys a thin round no leniency about agreeing.
///
/// # Why it is TWO and not three, from the measurement rather than from taste
///
/// Raising it to three is the intuitive hardening and it would re-create the incident. The round
/// that froze the user's installed node reported `Insufficient { answered: 2, required: 4 }` —
/// **two peers answered**, not four. A floor of three refuses that round for as long as the
/// network stays that thin, which is the frozen replica again, arrived at by a different route.
/// The strength a thin round lacks is bought by [`required_agreement`] (two of two must agree)
/// and by [`band_kept_a_majority`] (a round whose CLAIMS are split is refused outright), never by
/// demanding more peers answer than the network is currently offering.
///
/// This is recorded in `SPEC.md` §18.6 as an ASSUMPTION rather than a derived constant, because
/// it encodes a judgement about what the word "corroborated" is allowed to mean, and the operator
/// of this node may reasonably overturn it in either direction.
pub const CORROBORATION_FLOOR: usize = 2;

/// How many distinct peers one round DIALS before narrowing (dig_ecosystem#2827).
///
/// Over-subscribing then pulling back is what makes a round resilient to the ordinary case that
/// froze this wallet: some of the peers dialled will be slow, mid-reorg, or gone by the time the
/// question is asked, and a round that dials exactly as many as it needs has no margin for any of
/// them. Dialling ten to hold [`QUORUM_HOLD`] leaves the round whole when half the dials are
/// useless.
///
/// It is not larger because every extra dial is a TCP+TLS handshake to a full node this node does
/// not otherwise need, and because the marginal certainty falls away fast — see
/// [`sybil_success_probability`], where the gap between a five-answer round and a ten-answer one
/// is much smaller than the gap between two and five.
pub const QUORUM_DIAL_WIDE: usize = 10;

/// How many of the [`QUORUM_DIAL_WIDE`] dialled peers a round actually ASKS.
///
/// Five, which is Sage's shipped `target_peers` for the same reason it is shipped there: it is a
/// load a light client on a home connection can carry indefinitely. The round is narrowed to it by
/// [`hold_best`].
///
/// This is a QUESTION budget, never a claim about what the node holds. The peer count a user sees
/// (`chia_peer_count`) is the transport's HELD pool and is measured, not targeted — a node holding
/// three peers reports three however wide this is set.
pub const QUORUM_HOLD: usize = 5;

/// How many of `answered` peers must give the SAME answer for it to be authoritative.
///
/// The shipped ratio, [`QUORUM_AGREEMENT`] of [`QUORUM_SAMPLE`], applied to the peers that
/// actually answered, with [`CORROBORATION_FLOOR`] underneath it. `required_agreement(4)` is
/// exactly [`QUORUM_AGREEMENT`], so at the sample size this module was built around the rule is
/// unchanged.
///
/// # The knob that moved, and the one that did not
///
/// dig_ecosystem#2827 relaxed **how many answers a round needs**; it did not relax **how strongly
/// those answers must agree**. Those are different knobs and only the first was the defect.
/// Lowering agreement — to a bare majority, say — would make the wallet believe a disagreeing
/// minority, which is the opposite of the goal: rounding UP (`div_ceil`) keeps the ratio at or
/// above three-quarters at every size, so 3-of-5 and 2-of-3 stay refused.
///
/// Note the direction the requirement moves as a round widens: more answers demand more agreement,
/// so dialling wide never makes a verdict cheaper to obtain.
pub fn required_agreement(answered: usize) -> usize {
    let by_ratio = (answered * QUORUM_AGREEMENT).div_ceil(QUORUM_SAMPLE);
    by_ratio.max(CORROBORATION_FLOOR)
}

/// How far below the best claimed peak a peer may sit and still be asked (in blocks).
///
/// This is the **behind** filter, and it is a policy rather than a measurement: a light client
/// cannot verify any peer's claim, so it can only decide how much lag it considers ordinary.
///
/// Three blocks — roughly a minute of chain at Chia's ~18.75s block time — is the band Sage
/// applies in production before it stops treating a peer as a useful pool member, and its reason
/// there is the same as the reason here: a peer one or two blocks back is mid-propagation, while
/// a peer many blocks back is either broken, on another fork, or lying, and none of the three
/// makes it a witness worth consulting.
///
/// A peer excluded by this filter is **not** accused of anything and **not** banned. It is
/// dropped from this round's candidate set, and a later round with a fresher claim may include it.
pub const PEAK_LAG_TOLERANCE: u32 = 3;

/// How far below the sample's LOWEST claimed peak every quorum question is asked (in blocks).
///
/// [`common_height`] subtracts this, so the question lands at a height every sampled peer reached
/// some time ago rather than one it reached this instant. Without the margin the question sits
/// exactly on the slowest peer's tip, where that peer is most likely to be mid-apply and where a
/// one-block reorg — the common kind — still separates honest answers.
///
/// Two blocks past the slowest member, combined with [`PEAK_LAG_TOLERANCE`], puts the question at
/// least two blocks behind every sampled peer and at most five behind the fastest: settled enough
/// that honest disagreement is not expected, recent enough that the replica is not being told
/// about a materially old chain.
pub const SETTLED_LAG: u32 = 2;

/// How many consecutive [`Verdict::Split`] rounds are tolerated before the disagreement is
/// treated as a standing condition worth surfacing rather than a transient one worth retrying.
///
/// A single split is unremarkable; the node simply re-draws and asks again. A run of them means
/// the randomly-chosen samples keep failing to agree, which is what a network partition and a
/// sustained attack both look like from here — and silently retrying forever would hide both
/// behind a node that merely appears slow.
pub const PERSISTENT_DISAGREEMENT_ROUNDS: u32 = 3;

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// The source of the bytes [`select_sample`] draws with.
///
/// It is a trait for exactly one reason: a test must be able to prove the selection is unbiased
/// and order-independent by scripting the draws, which is impossible against a real CSPRNG. It is
/// **not** a configuration point — production has one implementation, [`OsEntropy`], and the
/// [`sample_peers`] entry point does not accept another.
pub trait EntropySource: Send + Sync {
    /// Fill `buf` with unpredictable bytes.
    fn fill(&self, buf: &mut [u8]);
}

/// The operating system CSPRNG, via `getrandom` (`/dev/urandom`, `getrandom(2)`,
/// `BCryptGenRandom`).
///
/// Random selection is not a load-balancing nicety here — it IS the defence. The whole model
/// assumes an attacker cannot arrange to be the peers this node happens to ask, and a source he
/// can predict or steer removes that assumption without changing a single visible behaviour
/// (dig_ecosystem#2549). Two specific wrong sources are ruled out by construction:
///
/// * **The wall clock.** [`crate::sage::sync_supervisor`]'s reconnect jitter derives from
///   `SystemTime`, which is correct there — it only needs hosts to be uncorrelated with each
///   other — and would be catastrophic here, where an attacker who can observe or influence when
///   this node reconnects would thereby influence whom it asks.
/// * **A cached fastest-peer or first-responder list.** Ordering the candidate set by anything an
///   attacker can affect (latency, response order, position in an introducer answer) hands him
///   the selection even while the draw itself is random.
///
/// A failure to obtain OS entropy PANICS rather than degrading to a weaker source. There is no
/// safe fallback: continuing with predictable selection would silently disable the corroboration
/// this module exists to provide, and a node that cannot read its own kernel's RNG has a problem
/// that quietly writing chain state will not improve.
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect(
            "dig-wallet quorum: the OS CSPRNG is unavailable; refusing to select corroboration \
             peers from a predictable source",
        );
    }
}

/// Draw a uniform random `u64` below `bound` using rejection sampling.
///
/// **Rejection, not modulo.** `draw % bound` is the obvious implementation and is biased whenever
/// `bound` does not divide `2^64`: the low residues occur once more often than the high ones, so
/// the peers at the start of the candidate list are chosen slightly more often than the peers at
/// the end. On its own that bias is tiny, but it is a bias in the one mechanism an attacker is
/// trying to influence, and it points in the direction he controls — he chooses where in an
/// introducer's answer his addresses appear. Rejecting the unusable tail costs an occasional
/// extra draw and removes the effect entirely.
///
/// Returns `None` for `bound == 0`, which has no valid answer.
fn uniform_below(entropy: &dyn EntropySource, bound: u64) -> Option<u64> {
    if bound == 0 {
        return None;
    }
    // `zone` is the largest multiple of `bound` that fits in a u64 (`u64::MAX - u64::MAX % bound`
    // is divisible by `bound` by construction). Draws at or above it are the unusable tail that
    // would otherwise skew the low residues, and are re-drawn rather than folded in.
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let mut bytes = [0u8; 8];
        entropy.fill(&mut bytes);
        let draw = u64::from_le_bytes(bytes);
        if draw < zone {
            return Some(draw % bound);
        }
    }
}

/// Choose `k` distinct indices below `n`, uniformly at random, with no dependence on order.
///
/// A partial Fisher-Yates shuffle: every position is equally likely to be drawn at every step, so
/// no index enjoys an advantage from sitting early (or late) in the candidate list. That property
/// is the point — a selection that quietly favours the head of the list is defeated by an
/// attacker who only has to get his addresses listed first, which is free.
///
/// Returns fewer than `k` indices only when `n < k`; the caller decides whether a short sample is
/// usable (it is not — see [`Verdict::Insufficient`]).
pub fn select_sample(entropy: &dyn EntropySource, n: usize, k: usize) -> Vec<usize> {
    let mut pool: Vec<usize> = (0..n).collect();
    let mut chosen = Vec::with_capacity(k.min(n));
    for taken in 0..k.min(n) {
        let remaining = (n - taken) as u64;
        let Some(offset) = uniform_below(entropy, remaining) else {
            break;
        };
        let pick = taken + offset as usize;
        pool.swap(taken, pick);
        chosen.push(pool[taken]);
    }
    chosen
}

// ---------------------------------------------------------------------------
// Candidates: separating BEHIND from LYING before anything is asked
// ---------------------------------------------------------------------------

/// What a peer claims about the chain tip, as it arrives in its handshake `new_peak_wallet`.
///
/// A claim, never a fact: a light client cannot verify either field. It is used only to decide
/// whether the peer is worth asking and at what height to ask it — never written to the replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeakClaim {
    /// The height the peer says it has reached.
    pub height: u32,
    /// The header hash the peer says sits at that height.
    pub header_hash: Bytes32,
}

/// A peer that could be sampled this round: an opaque identity plus its claim.
///
/// The identity is a string (the dialed address) because this module never dials anything — it
/// decides WHO to ask and WHETHER to believe the answers, and the caller owns the sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// How the caller names this peer, for logging and for excluding a dissenter later.
    pub id: String,
    /// The peer's claimed tip.
    pub claim: PeakClaim,
}

/// Keep the candidates whose claimed peak sits within [`PEAK_LAG_TOLERANCE`] blocks of the
/// **median** claim, in either direction.
///
/// This is the FIRST half of telling behind from lying, and it runs before any question is asked
/// so that a badly-stale peer never becomes a dissenting vote. It is deliberately a filter and
/// not a judgement: nothing here bans, penalises, or remembers a peer, because being a block or
/// two behind is the ordinary condition of a healthy full node.
///
/// # Why the MEDIAN, and not the best claim
///
/// Anchoring on the maximum is the obvious implementation and it is a denial of service. A single
/// peer claiming `u32::MAX` is then the reference point, every honest peer is billions of blocks
/// "behind" it, and the entire honest set is filtered out — leaving the liar alone in the
/// candidate pool, for free, from one unverifiable integer. A median cannot be moved by one
/// outlier: the liar is admitted, drawn no more often than anyone else, and outvoted at the
/// settled height, which is what the rest of this module is for.
///
/// **A median CAN be moved by a coordinated half**, and this filter does not pretend otherwise.
/// Half the claimants announcing a plausible lag place the median on themselves and the band off
/// the honest set entirely. Nothing here detects that — the detection is
/// [`band_kept_a_majority`], applied by [`hold_best`], which refuses a round the band split rather
/// than proceeding on whichever side survived.
///
/// The filter is symmetric for the same reason. A claim far ABOVE the median is no more credible
/// than one far below it — nothing here can verify either — and admitting the high outlier while
/// excluding the low one would rebuild max-wins by the back door.
///
/// Note what it still does NOT do: it does not PREFER the highest surviving claimant, and the
/// surviving set keeps its original order for the caller's convenience only, because
/// [`select_sample`] is order-blind. Inflating a claim buys admission and never authority.
pub fn eligible(candidates: &[Candidate], tolerance: u32) -> Vec<Candidate> {
    let mut heights: Vec<u32> = candidates.iter().map(|c| c.claim.height).collect();
    if heights.is_empty() {
        return Vec::new();
    }
    heights.sort_unstable();
    // The lower median: with an even count either middle value is equally defensible, and the
    // lower one is the more conservative reference for a lag band.
    let median = heights[(heights.len() - 1) / 2];
    let floor = median.saturating_sub(tolerance);
    let ceiling = median.saturating_add(tolerance);
    candidates
        .iter()
        .filter(|c| c.claim.height >= floor && c.claim.height <= ceiling)
        .cloned()
        .collect()
}

/// Narrow a wide dial down to the peers this round will actually ASK (dig_ecosystem#2827).
///
/// The node over-subscribes — [`QUORUM_DIAL_WIDE`] dials — and then pulls back to `hold`, so that
/// slow, stale and vanished dials are absorbed before the question is asked rather than after.
///
/// # What "best" means here, and what it deliberately does NOT mean
///
/// "Best" is **membership of the credibility band** ([`eligible`]), and nothing else. Among the
/// peers inside that band the choice is made at random, which is not indecision — it is the same
/// property [`select_sample`] exists to provide, and it is load-bearing.
///
/// The tempting alternative is to rank by RESPONSIVENESS and keep the fastest. That would reverse
/// a defence this module already paid for. [`OsEntropy`] and `ChiaQuorumCorroborator` both record
/// the reason in their own words: latency is a channel an attacker CONTROLS — a fast, always-up
/// node is cheap to run — so preferring the quickest answerers is preferring the peers an attacker
/// is best placed to supply. Ranking by claimed height is no better: it hands selection to
/// whoever claims the top of the band, and claiming is free.
///
/// So the observable this narrowing uses is the median-relative one: whether the peer's claim sits
/// within [`PEAK_LAG_TOLERANCE`] of the MEDIAN claim. That is cheap for ONE peer to lie about and
/// useless to it — a single outlier cannot move a median, so inflating or deflating a lone claim
/// buys admission and never authority. It is **not** unsteerable against a COORDINATED HALF, and
/// pretending otherwise is what made this narrowing dangerous once it became a SELECTION rather
/// than merely a filter: peers holding half the claims own the median, and can therefore place the
/// band where the honest peers are not. [`band_kept_a_majority`] is the guard that restores the
/// property, and it is enforced here rather than left to the caller.
///
/// A per-peer history of agreeing with the rest would be a genuinely better criterion and is NOT
/// implemented — this corroborator is round-scoped and keeps no state between rounds, and
/// inventing a history it does not have would be worse than admitting it has none.
///
/// A dial that came back with `hold` or fewer credible peers keeps all of them: the round proceeds
/// on the peers that answered.
///
/// Returns `None` — refuse the round, write nothing — when the band excluded half or more of the
/// peers that made a claim. See [`band_kept_a_majority`] for why that is a refusal and not a
/// narrowing.
pub fn hold_best(
    entropy: &dyn EntropySource,
    candidates: &[Candidate],
    tolerance: u32,
    hold: usize,
) -> Option<Vec<Candidate>> {
    let credible = eligible(candidates, tolerance);
    if !band_kept_a_majority(candidates.len(), credible.len()) {
        return None;
    }
    if credible.len() <= hold {
        return Some(credible);
    }
    Some(
        select_sample(entropy, credible.len(), hold)
            .into_iter()
            .map(|index| credible[index].clone())
            .collect(),
    )
}

/// Did the credibility band keep a STRICT MAJORITY of the peers that made a claim?
///
/// The guard on [`hold_best`], and the reason the median narrowing is safe to select with.
///
/// # The attack it refuses, which needs no implausible claim
///
/// A round dials [`QUORUM_DIAL_WIDE`] peers; five honest ones announce the real tip `H` and five
/// hostile ones announce `H − 4` — an ordinary "four blocks behind", one block past
/// [`PEAK_LAG_TOLERANCE`], not a number anything could call a lie. The sorted heights are
/// `[H−4 ×5, H ×5]`, so the lower median is `H − 4`, the band is `[H−7, H−1]`, and **every honest
/// peer falls outside it**. The survivors are exactly the attacker's five, they agree with each
/// other by construction, and the round returns `Unanimous` on a hash nobody honest ever saw —
/// which then feeds the balance, the confirmation counts and spend-path coin selection. Measured
/// against real [`OsEntropy`], this took forgery at f=0.3 from 8.4% to 15.0%, and at f=0.5 from
/// 31.3% to 62.3%.
///
/// Requiring the band to keep a strict majority makes the attacker buy the median outright: six of
/// the ten dialled rather than five — **60% of the round**, against the old fixed-sample bar of
/// three of four, which was **75%**. The COUNT rose and the FRACTION fell, so this guard is not
/// uniformly stricter than the design it replaces, and quoting the counts alone would flatter it.
///
/// # Whether that is stricter depends on `f`, so both numbers are published
///
/// An attacker's capability here is a fraction `f` of the reachable peer population, so the
/// fraction is what decides the comparison. Old bar: `P(X ≥ 3)`, `X ~ Binom(4, f)`. New bar:
/// `P(X ≥ 6)`, `X ~ Binom(10, f)`.
///
/// | `f` | 3-of-4 (pre-change) | 6-of-10 (this guard) |
/// |-----|--------------------:|---------------------:|
/// | 0.1 |               0.37% |                0.01% |
/// | 0.2 |               2.72% |                0.64% |
/// | 0.3 |               8.37% |                4.74% |
/// | 0.4 |              17.92% |               16.62% |
/// | 0.5 |              31.25% |               37.70% |
///
/// The guard is therefore SAFER in the healthy regime and WORSE once the attacker approaches half
/// the population, crossing over at **`f ≈ 0.42`**. That is a DIFFERENT crossover from the
/// `f ≈ 0.17` in `SPEC.md` §18.6e, which compares the pre-change design against the post-change
/// design with this guard ABSENT; the two must not be read as the same number.
///
/// Six of ten is the whole composite bar, not a lower bound on it. An attacker holding six
/// claimants sets the median, the band excludes the four honest peers, `band_kept_a_majority`
/// passes (`6 * 2 > 10`), the narrowing to [`QUORUM_HOLD`] draws five peers from a credible set
/// that is entirely his, and [`required_agreement`] is met by construction. At five he is refused
/// (`5 * 2 > 10` is false). No later stage adds a further hurdle, so nothing stricter may be
/// claimed here.
///
/// # The denominator, which is the whole risk in this guard
///
/// `claimants` is the number of dialled peers that **supplied a `new_peak_wallet` claim** — the
/// input set to [`eligible`]. It is deliberately NOT the dial target, and deliberately NOT the
/// number of peers that later answered the header-hash question. A guard keyed on either of those
/// refuses a round merely because peers were slow or unreachable, which is precisely the freeze
/// dig_ecosystem#2827 exists to end: a user's replica sat still for hours on a round that reported
/// `answered: 2`. This guard is indifferent to that round — two claimants who agree about the tip
/// keep the whole set (`2 * 2 > 2`) and the round proceeds.
///
/// So a thin honest round is never refused by this. What is refused is a round whose claims are
/// SPLIT, because a split set of claims is the one shape in which the median stops being a
/// property of the honest majority.
pub const fn band_kept_a_majority(claimants: usize, credible: usize) -> bool {
    credible * 2 > claimants
}

/// The chain height this node may report as its own, settled from several peers' claims
/// (dig_ecosystem#2790).
///
/// # What this number IS, and what it deliberately is not
///
/// It is **a height every credible peer in the sample has passed**, not the tip. The tip cannot be
/// corroborated: it moves every ~18.75s and peers learn of it at different moments, so asking for
/// it guarantees honest disagreement. Backing off by [`SETTLED_LAG`] asks a question whose answer
/// stopped changing before anybody was asked, which is what makes agreement meaningful.
///
/// # The bound it actually carries
///
/// The number is exactly `min(credible claims) - SETTLED_LAG`. So: **while at least ONE claim
/// inside the credibility band came from an honest peer, the result cannot lead the true tip** —
/// the honest claim is at or below the tip, and a minimum cannot exceed its smallest member. That
/// is the property, and it is weaker than "it never leads it", which was stated here
/// unconditionally and is false.
///
/// It is false because the band is set by the claimants themselves. [`eligible`] keeps the claims
/// within [`PEAK_LAG_TOLERANCE`] of their own MEDIAN, so claimants who form a majority of those
/// who answered own the median, evict every honest claim as an outlier, and place the result where
/// they like. Measured: two colluding claimants with the rest of the sample silent return
/// `tip + 998`; two colluders against one honest claimant return `tip + 498`.
///
/// A peak that LEADS the tip inflates every confirmation count derived from it, so a caller treats
/// an unburied coin as buried. That is the money-lie direction, and it is bounded by the honesty of
/// the claimants, not by this function.
///
/// # The sample this runs on is NOT the 10-wide dial
///
/// [`band_kept_a_majority`] publishes a `P(X >= 6), X ~ Binom(10, f)` analysis with a crossover
/// near `f ~ 0.42`. That analysis describes [`hold_best`] narrowing a [`QUORUM_DIAL_WIDE`]-wide
/// dial to [`QUORUM_HOLD`]. **This function never calls `hold_best` and never sees a 10-wide
/// dial.** It runs on whatever `DialedPeerSample::redraw` assembled, which is
/// [`QUORUM_SAMPLE`]-wide, and applies [`eligible`] and [`band_kept_a_majority`] to that directly.
///
/// So the bar here is a strict majority of the peers that answered *within a 4-peer sample* — 3
/// of 4, or 2 of 3, or 2 of 2 once silence thins the set, floored at [`CORROBORATION_FLOOR`].
/// Silence lowers the denominator for free. Read the 6-of-10 table as describing `hold_best`, not
/// this path.
///
/// # Why it refuses instead of repairing
///
/// `None` is a refusal, and every one of its causes is a case where the node genuinely does not
/// know the height:
///
/// * fewer than [`CORROBORATION_FLOOR`] peers claimed anything — one peer is not agreement, and a
///   lone claim is exactly what a node talking to a single hostile source would see;
/// * the credibility band did not keep a majority ([`band_kept_a_majority`]) — the claims are
///   SPLIT, so the median has stopped being a property of the honest set and no side of the split
///   is more believable than the other;
/// * the chain is younger than the settling margin.
///
/// There is no "take the highest", no "take the most popular" and no fallback to a third party.
/// Adopting a plurality would hide a partition behind a number that looks authoritative, and
/// falling through to a public oracle would let one HTTPS endpoint overrule the peers precisely
/// when they failed to agree — the single-source dependency NC-12 exists to remove.
pub fn settled_peak(candidates: &[Candidate]) -> Option<u32> {
    if candidates.len() < CORROBORATION_FLOOR {
        return None;
    }
    let credible = eligible(candidates, PEAK_LAG_TOLERANCE);
    if credible.len() < CORROBORATION_FLOOR
        || !band_kept_a_majority(candidates.len(), credible.len())
    {
        return None;
    }
    common_height(&credible, SETTLED_LAG)
}

/// The settled height every question in this round is asked at: the sample's LOWEST claimed peak,
/// less `lag`.
///
/// This is the SECOND half of telling behind from lying, and it is the load-bearing one. Asking
/// "what is the tip?" guarantees honest disagreement, because the tip moves every ~18.75s and
/// peers learn of it at different moments. Asking "what was true at height H?", where H is a
/// height every sampled peer passed at least `lag` blocks ago, guarantees honest AGREEMENT — the
/// answer stopped changing before any of them was asked.
///
/// Once the question is normalised this way, a disagreement can no longer be explained by lag,
/// which is what makes [`Verdict::Split`] meaningful rather than routine.
///
/// Returns `None` for an empty sample, or when the chain is younger than the margin (early testnet
/// heights), because there is no settled height to ask about.
///
/// It takes the MINIMUM, so its result is at or below every claim in `sample`. Everything the
/// caller may conclude about leading the true tip rests on that, and therefore on whether any claim
/// in `sample` is honest — see [`settled_peak`].
pub fn common_height(sample: &[Candidate], lag: u32) -> Option<u32> {
    sample
        .iter()
        .map(|c| c.claim.height)
        .min()
        .and_then(|lowest| lowest.checked_sub(lag))
}

// ---------------------------------------------------------------------------
// Tallying
// ---------------------------------------------------------------------------

/// What a round of corroboration concluded.
///
/// The variant that matters most is [`Verdict::Split`], and specifically what it is NOT: there is
/// no "take the most popular answer" arm. A split at a settled height means the truth is UNKNOWN,
/// and the honest response to not knowing is to write nothing — quietly adopting a plurality
/// would hide a partition and an attack behind a replica that looks synced.
///
/// # Corroboration is a gradient, not a gate (dig_ecosystem#2827)
///
/// Every authoritative arm carries `agreed`, the number of independent peers that gave the answer,
/// so the CONFIDENCE travels with the datum instead of being spent deciding whether to keep it.
/// Two agreeing peers and eight agreeing peers both produce a usable verdict; they do not produce
/// an equally well-attested one, and [`Verdict::agreed`] is how a caller can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<A> {
    /// Every peer that answered gave the same answer. Authoritative.
    Unanimous {
        /// The corroborated answer.
        answer: A,
        /// How many peers gave it — the round's whole answer set.
        agreed: usize,
    },
    /// At least [`QUORUM_AGREEMENT`] peers agreed and at least one did not. Authoritative — one
    /// dissenter is expected without an attacker — but the dissent is EVIDENCE and is surfaced:
    /// at a settled height, past the lag filter, a peer contradicting the supermajority is not
    /// merely slow.
    MajorityWithDissent {
        /// The corroborated answer.
        answer: A,
        /// How many peers gave it.
        agreed: usize,
        /// The peers that gave something else, by [`Candidate::id`].
        dissenters: Vec<String>,
    },
    /// No answer reached [`required_agreement`] for this round's size. **Nothing is written.**
    /// The caller re-draws a fresh sample and asks again; a run of these is surfaced (see
    /// [`PERSISTENT_DISAGREEMENT_ROUNDS`]).
    Split {
        /// The distinct answers seen, with their counts, for the diagnostic.
        tallies: Vec<usize>,
    },
    /// Fewer than [`CORROBORATION_FLOOR`] peers answered at all, so nothing could corroborate
    /// anything. **Nothing is written.** Distinguished from [`Verdict::Split`] because it is a
    /// reachability problem, not a disagreement — a node that reached one peer is not under
    /// attack, it is alone.
    Insufficient {
        /// How many peers answered.
        answered: usize,
        /// How many were required — [`CORROBORATION_FLOOR`].
        required: usize,
    },
}

impl<A> Verdict<A> {
    /// The corroborated answer, if this round produced one. `None` for every non-authoritative
    /// outcome — the single place callers should ask "may I write?".
    pub fn corroborated(&self) -> Option<&A> {
        match self {
            Verdict::Unanimous { answer, .. } | Verdict::MajorityWithDissent { answer, .. } => {
                Some(answer)
            }
            Verdict::Split { .. } | Verdict::Insufficient { .. } => None,
        }
    }

    /// How many independent peers corroborated the answer — the round's confidence.
    ///
    /// Zero for every non-authoritative outcome, so a caller cannot read a refused round's answer
    /// count as evidence for anything.
    pub fn agreed(&self) -> usize {
        match self {
            Verdict::Unanimous { agreed, .. } | Verdict::MajorityWithDissent { agreed, .. } => {
                *agreed
            }
            Verdict::Split { .. } | Verdict::Insufficient { .. } => 0,
        }
    }
}

/// One peer's response to this round's question. A peer that failed to answer is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<A> {
    /// Which peer answered, by [`Candidate::id`].
    pub peer: String,
    /// What it said.
    pub answer: A,
}

/// Count the responses and decide whether an answer is corroborated.
///
/// Generic over the answer so the same rule governs every quorum'd read — a header hash at a
/// settled height, a canonical digest of a coin set — rather than each read growing its own
/// slightly different notion of agreement.
///
/// # The round proceeds on the peers that ANSWERED (dig_ecosystem#2827)
///
/// It used to require a fixed number of answers before it would decide anything, and that is what
/// froze a user's replica for hours: the node held five peers, one of them was slow, and every
/// round was discarded whole. Waiting for a fixed count is not a security property — it is a
/// liveness cost paid in the hope of one, and the hope is unfounded, because an attacker who can
/// silence a peer can force the wait forever.
///
/// What IS a security property is [`CORROBORATION_FLOOR`] (never one source) and
/// [`required_agreement`] (the shipped agreement ratio, applied to whoever answered). Both are
/// kept. The residual cost is real and stated rather than hidden: a round with fewer answers is
/// cheaper for an attacker to capture, and [`sybil_success_probability`] will tell you by how
/// much.
pub fn tally<A: Clone + Eq + Hash>(responses: &[Response<A>]) -> Verdict<A> {
    let answered = responses.len();
    if answered < CORROBORATION_FLOOR {
        return Verdict::Insufficient {
            answered,
            required: CORROBORATION_FLOOR,
        };
    }
    let required = required_agreement(answered);

    let mut counts: HashMap<&A, usize> = HashMap::new();
    for r in responses {
        *counts.entry(&r.answer).or_insert(0) += 1;
    }

    let Some((winner, &votes)) = counts.iter().max_by_key(|(_, &n)| n).map(|(a, n)| (*a, n)) else {
        return Verdict::Split {
            tallies: Vec::new(),
        };
    };

    if votes < required {
        let mut tallies: Vec<usize> = counts.values().copied().collect();
        tallies.sort_unstable_by(|a, b| b.cmp(a));
        return Verdict::Split { tallies };
    }

    let dissenters: Vec<String> = responses
        .iter()
        .filter(|r| &r.answer != winner)
        .map(|r| r.peer.clone())
        .collect();

    if dissenters.is_empty() {
        Verdict::Unanimous {
            answer: winner.clone(),
            agreed: votes,
        }
    } else {
        Verdict::MajorityWithDissent {
            answer: winner.clone(),
            agreed: votes,
            dissenters,
        }
    }
}

// ---------------------------------------------------------------------------
// Reads that need no vote
// ---------------------------------------------------------------------------

/// The facts a light client checks for itself, listed so the distinction is a thing in the code
/// rather than a paragraph someone has to remember.
///
/// Every one of these is decidable from bytes this node already holds. Sending them to a vote
/// would spend round trips to learn something arithmetic already knows, and — the real hazard —
/// would let a majority of peers overrule a check that cannot be wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfVerifying {
    /// A coin's id is `sha256(parent_coin_info || puzzle_hash || amount)`. This node DERIVES the
    /// id from the coin's own fields rather than accepting one, so a peer cannot name a coin that
    /// is not the coin it described. See [`coin_id_is_derived_not_trusted`].
    CoinId,
    /// A header block hashes to its own header hash, so "is this the block you named?" needs no
    /// second opinion. (Which hash is CANONICAL at a height does need one — that is the quorum'd
    /// question, and the two are easy to conflate.)
    HeaderBlockBinding,
    /// The genesis challenge and network id are values this node pins locally
    /// (`MAINNET_CONSTANTS.genesis_challenge`), and the peer handshake carries the network id, so
    /// a peer on another chain cannot complete a connection. A lying peer cannot pass this and a
    /// quorum of lying peers cannot change what this node pinned.
    NetworkIdentity,
}

/// Whether a coin state's own fields hash to the coin id claimed for it.
///
/// The node never stores a peer-supplied coin id — [`crate::sage::sync::coin_state_to_row`]
/// computes `coin.coin_id()` — so this is a check the code satisfies structurally. It exists as a
/// named function so the property is pinned by a test instead of relying on nobody ever
/// introducing a `claimed_id` field.
pub fn coin_id_is_derived_not_trusted(coin: &chia_protocol::Coin, claimed: Bytes32) -> bool {
    coin.coin_id() == claimed
}

// ---------------------------------------------------------------------------
// Spentness: monotone, fail-closed, never a vote
// ---------------------------------------------------------------------------

/// How the sample answered "is this coin spent?", resolved WITHOUT a vote.
///
/// Spentness is the read that costs money when it is wrong, and it is wrong asymmetrically:
/// believing a spent coin is spendable produces a DOUBLE_SPEND, while believing a spendable coin
/// is spent produces a smaller balance and a retry. So the resolution is not majority rule, it is
/// fail-closed union:
///
/// * **Any credible report of SPENT wins**, even a lone one, because a spend is a positive fact a
///   peer must have witnessed on chain to report, and there is no incentive to invent one — an
///   attacker gains nothing by making this node under-spend its own coins.
/// * **UNSPENT requires the whole sample**, because "I have not seen a spend" is what a lagging
///   peer, a pruned peer, and a lying peer all say identically. Omission is not evidence of
///   absence.
///
/// Asking at a settled [`common_height`] is what keeps the strict rule from being a nuisance: a
/// peer that is merely behind has still passed that height, so it has seen the spend and reports
/// it, and the unanimity requirement costs nothing in the honest case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentEvidence {
    /// At least one sampled peer reported the coin spent. Treated as spent; NOT selectable.
    Spent,
    /// Every sampled peer reported the coin unspent at the settled height. Selectable.
    UnanimouslyUnspent,
    /// Not every sampled peer answered, so unspentness is unproven. NOT selectable — this is the
    /// arm that makes the rule fail-closed rather than merely strict.
    Unproven,
}

impl SpentEvidence {
    /// Resolve the sample's reports. `sample_size` is how many peers were ASKED, so a peer that
    /// did not answer counts against unspentness rather than being quietly ignored.
    pub fn resolve(reports: &[bool], sample_size: usize) -> Self {
        if reports.iter().any(|&spent| spent) {
            return SpentEvidence::Spent;
        }
        if reports.len() < sample_size {
            return SpentEvidence::Unproven;
        }
        SpentEvidence::UnanimouslyUnspent
    }

    /// Whether coin selection on the SPEND path may use this coin.
    ///
    /// The one question the spend path asks, so the fail-closed arms cannot be forgotten
    /// individually.
    pub fn is_selectable(self) -> bool {
        matches!(self, SpentEvidence::UnanimouslyUnspent)
    }
}

// ---------------------------------------------------------------------------
// The Sybil limit, stated as a number
// ---------------------------------------------------------------------------

/// The probability that an attacker controlling `hostile_fraction` of the discoverable peer set
/// carries a round in which `answered` peers replied.
///
/// Provided as a function, not a paragraph, because the honest version of this claim is a number
/// that gets worse as the attacker grows and a reader deserves to see it move. Modelled as
/// independent draws (sampling with replacement), which slightly OVERSTATES the attacker's
/// difficulty for a small candidate set — the real risk is never lower than this returns.
///
/// The shape of the answer at the shipped ratio, for a four-answer round: at a 10% hostile set an
/// attacker carries it about 0.4% of the time; at 30%, about 8%; at 50%, about 31%. Random
/// selection is a cost multiplier, not a barrier, and `SPEC.md` says so in the same words.
///
/// # Why `answered` is a parameter (dig_ecosystem#2827)
///
/// Because a round no longer has a fixed size, and pretending otherwise would publish the wide
/// round's comfortable number for a thin round's risk. A round at [`CORROBORATION_FLOOR`] needs
/// only both answerers hostile — 9% at a 30% hostile set, against 8% at four and 3% at five — so
/// an attacker who can make witnesses UNREACHABLE now has a cheaper path than out-voting them.
/// That is the price of not freezing, it is why [`QUORUM_DIAL_WIDE`] over-subscribes to keep
/// rounds wide, and it is stated in `SPEC.md` rather than left for a reader to derive.
///
/// Note the separate, cheaper attack this number does NOT describe: an attacker needs only to
/// dissent past [`required_agreement`] to force a [`Verdict::Split`] and stall the write. Denial
/// is materially easier than forgery here, and that asymmetry is deliberate — a stalled sync is a
/// visible, recoverable condition, while a forged one is neither.
pub fn sybil_success_probability(hostile_fraction: f64, answered: usize) -> f64 {
    let f = hostile_fraction.clamp(0.0, 1.0);
    let n = answered as u32;
    // P(at least `required_agreement(answered)` of n draws are hostile).
    (required_agreement(answered) as u32..=n)
        .map(|k| binomial(n, k) * f.powi(k as i32) * (1.0 - f).powi((n - k) as i32))
        .sum()
}

fn binomial(n: u32, k: u32) -> f64 {
    (0..k).fold(1.0, |acc, i| acc * f64::from(n - i) / f64::from(i + 1))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod settled_peak_tests {
    //! The peak this node reports must be a fact several peers agree on, and must REFUSE rather
    //! than repair when they do not (dig_ecosystem#2790).
    //!
    //! Every fixture varies ONE actor against a truthful control set. A fixture in which every
    //! peer lies is the harshest-looking case and the blindest: with no honest claim left there is
    //! nothing a missed corroboration could have contradicted, so it cannot tell a working quorum
    //! from one that simply believed whoever spoke.

    use super::*;

    /// A claimant at `height`. The header hash is derived from the id so two distinct peers never
    /// share one by accident — a shared hash would make separate voices indistinguishable.
    fn claimant(id: &str, height: u32) -> Candidate {
        let mut hash = [0u8; 32];
        hash[..id.len().min(32)].copy_from_slice(&id.as_bytes()[..id.len().min(32)]);
        Candidate {
            id: id.into(),
            claim: PeakClaim {
                height,
                header_hash: Bytes32::from(hash),
            },
        }
    }

    /// The control. Without it every refusal below is satisfied by a function that always refuses.
    #[test]
    fn a_truthful_sample_settles_a_height_below_the_tip() {
        let sample = [
            claimant("a", 9_000_000),
            claimant("b", 9_000_000),
            claimant("c", 9_000_001),
            claimant("d", 9_000_000),
        ];
        assert_eq!(
            settled_peak(&sample),
            Some(9_000_000 - SETTLED_LAG),
            "four peers a block apart are ordinary lag, not disagreement, and must settle"
        );
    }

    /// The bound `settled_peak`'s doc now claims, from the safe side: while an honest claim
    /// survives the credibility band, the result cannot LEAD the true tip.
    ///
    /// One liar 1,000 blocks ahead is out-voted by two honest claimants, so it is evicted and the
    /// minimum is honest. The liar's height is deliberately far outside `PEAK_LAG_TOLERANCE` — a
    /// nearby lie is indistinguishable from ordinary lag and would pin nothing.
    #[test]
    fn an_outvoted_liar_cannot_push_the_settled_height_past_the_tip() {
        let true_tip = 9_000_000;
        let sample = [
            claimant("honest-a", true_tip),
            claimant("honest-b", true_tip),
            claimant("liar", true_tip + 1_000),
        ];
        let settled = settled_peak(&sample).expect("two agreeing honest claims settle a height");
        assert!(
            settled <= true_tip,
            "the settled height {settled} LEADS the true tip {true_tip}; every confirmation count              derived from it would treat an unburied coin as buried"
        );
    }

    /// The same bound from the side that FAILS it, so the doc's qualification is pinned rather than
    /// merely worded.
    ///
    /// Two colluding claimants who are a strict majority of those who answered own the median, so
    /// `eligible` keeps them and evicts the honest claim as the outlier. The result then leads the
    /// tip by whatever they chose. This is the measured `+498` case, and it is why the doc says
    /// "while an honest claim survives the band" rather than "never".
    #[test]
    fn a_colluding_majority_of_claimants_can_make_the_settled_height_lead_the_tip() {
        let true_tip = 9_000_000;
        let lead = 500;
        let sample = [
            claimant("colluder-a", true_tip + lead),
            claimant("colluder-b", true_tip + lead),
            claimant("honest", true_tip),
        ];
        assert_eq!(
            settled_peak(&sample),
            Some(true_tip + lead - SETTLED_LAG),
            "a colluding majority of the CLAIMANTS sets the median and places the settled height              where it likes; if this ever refuses instead, the bound got stronger and              `settled_peak`'s doc must be re-read rather than this test relaxed"
        );
    }

    /// The property this whole change exists for: the answer must not survive collapsing to one
    /// voice.
    ///
    /// A single peer is what a node reading from one hostile source sees, and it is also what a
    /// node whose corroboration silently stopped working sees. Both must produce a refusal, never
    /// a number.
    #[test]
    fn one_peer_alone_settles_nothing_however_confident_it_is() {
        assert_eq!(
            settled_peak(&[claimant("lonely", 9_000_000)]),
            None,
            "one claim is not agreement: a lone peer must not be able to tell this node where the \
             chain is"
        );
    }

    /// One liar among honest peers must be OUTVOTED, not merely survived.
    ///
    /// The assertion is equality with the liar-free answer rather than "some height came back":
    /// a height that came back is produced identically by an implementation that took the maximum
    /// claim, which is the single most attacker-friendly aggregate available and is exactly what
    /// this must not be.
    #[test]
    fn a_lone_liar_cannot_move_the_settled_height() {
        let honest = [
            claimant("a", 9_000_000),
            claimant("b", 9_000_000),
            claimant("c", 9_000_000),
        ];
        let mut with_liar = honest.to_vec();
        with_liar.push(claimant("liar", u32::MAX));

        assert_eq!(
            settled_peak(&with_liar),
            settled_peak(&honest),
            "a peer claiming an absurd tip changed this node's view of the chain"
        );
        assert!(
            settled_peak(&honest).is_some(),
            "fixture: the honest set must settle, or the equality above holds because BOTH \
             refused and the liar was never actually outvoted"
        );
    }

    /// A liar in the other direction is no more credible, and must not drag the answer down.
    #[test]
    fn a_lone_liar_claiming_genesis_cannot_move_it_either() {
        let honest = [
            claimant("a", 9_000_000),
            claimant("b", 9_000_000),
            claimant("c", 9_000_000),
        ];
        let mut with_liar = honest.to_vec();
        with_liar.push(claimant("liar", 0));

        assert_eq!(settled_peak(&with_liar), settled_peak(&honest));
    }

    /// A genuinely split sample is an UNKNOWN height, and unknown is reported as unknown.
    #[test]
    fn a_split_sample_refuses_rather_than_picking_a_side() {
        let sample = [
            claimant("a", 9_000_000),
            claimant("b", 9_000_000),
            claimant("c", 8_000_000),
            claimant("d", 8_000_000),
        ];
        assert_eq!(
            settled_peak(&sample),
            None,
            "half the peers on each of two chains means this node does not know which it is on; \
             adopting either would hide a partition behind an authoritative-looking number"
        );
    }

    /// Nothing claimed, nothing settled — and specifically not height zero, which every block is
    /// trivially above.
    #[test]
    fn an_empty_sample_settles_nothing() {
        assert_eq!(settled_peak(&[]), None);
    }
}
