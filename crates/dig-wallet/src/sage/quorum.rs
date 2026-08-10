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

/// How many independently-chosen peers are asked each question.
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

/// The settled height every question in this round is asked at: the sample's LOWEST claimed peak,
/// less [`SETTLED_LAG`].
///
/// This is the SECOND half of telling behind from lying, and it is the load-bearing one. Asking
/// "what is the tip?" guarantees honest disagreement, because the tip moves every ~18.75s and
/// peers learn of it at different moments. Asking "what was true at height H?", where H is a
/// height every sampled peer passed at least [`SETTLED_LAG`] blocks ago, guarantees honest
/// AGREEMENT — the answer stopped changing before any of them was asked.
///
/// Once the question is normalised this way, a disagreement can no longer be explained by lag,
/// which is what makes [`Verdict::Split`] meaningful rather than routine.
///
/// Returns `None` for an empty sample, or when the chain is younger than the margin (early
/// testnet heights), because there is no settled height to ask about.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<A> {
    /// Every peer that answered gave the same answer. Authoritative.
    Unanimous(A),
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
    /// No answer reached [`QUORUM_AGREEMENT`]. **Nothing is written.** The caller re-draws a
    /// fresh sample and asks again; a run of these is surfaced (see
    /// [`PERSISTENT_DISAGREEMENT_ROUNDS`]).
    Split {
        /// The distinct answers seen, with their counts, for the diagnostic.
        tallies: Vec<usize>,
    },
    /// Fewer than [`QUORUM_SAMPLE`] peers answered at all, so no quorum was possible. **Nothing
    /// is written.** Distinguished from [`Verdict::Split`] because it is a reachability problem,
    /// not a disagreement — a node with three reachable peers is not under attack.
    Insufficient {
        /// How many peers answered.
        answered: usize,
        /// How many were required.
        required: usize,
    },
}

impl<A> Verdict<A> {
    /// The corroborated answer, if this round produced one. `None` for every non-authoritative
    /// outcome — the single place callers should ask "may I write?".
    pub fn corroborated(&self) -> Option<&A> {
        match self {
            Verdict::Unanimous(a) | Verdict::MajorityWithDissent { answer: a, .. } => Some(a),
            Verdict::Split { .. } | Verdict::Insufficient { .. } => None,
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
/// `required` is [`QUORUM_AGREEMENT`] in production and a parameter only so the threshold can be
/// pinned from BOTH sides in a test: one below must fail and at-bound must pass, or the bound has
/// only confirmed itself.
pub fn tally<A: Clone + Eq + Hash>(
    responses: &[Response<A>],
    sample_size: usize,
    required: usize,
) -> Verdict<A> {
    if responses.len() < sample_size {
        return Verdict::Insufficient {
            answered: responses.len(),
            required: sample_size,
        };
    }

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
        Verdict::Unanimous(winner.clone())
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
pub fn coin_id_is_derived_not_trusted(coin: &chia::protocol::Coin, claimed: Bytes32) -> bool {
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
/// lands enough members in one [`QUORUM_SAMPLE`] to carry a [`QUORUM_AGREEMENT`] vote.
///
/// Provided as a function, not a paragraph, because the honest version of this claim is a number
/// that gets worse as the attacker grows and a reader deserves to see it move. Modelled as
/// independent draws (sampling with replacement), which slightly OVERSTATES the attacker's
/// difficulty for a small candidate set — the real risk is never lower than this returns.
///
/// The shape of the answer, for the shipped 3-of-4: at a 10% hostile set an attacker carries a
/// round about 0.4% of the time; at 30%, about 8%; at 50%, about 31%. Random selection is a cost
/// multiplier, not a barrier, and `SPEC.md` says so in the same words.
///
/// Note the separate, cheaper attack this number does NOT describe: an attacker needs only TWO of
/// four to force a [`Verdict::Split`] and stall the write. Denial is materially easier than
/// forgery here, and that asymmetry is deliberate — a stalled sync is a visible, recoverable
/// condition, while a forged one is neither.
pub fn sybil_success_probability(hostile_fraction: f64) -> f64 {
    let f = hostile_fraction.clamp(0.0, 1.0);
    let n = QUORUM_SAMPLE as u32;
    // P(at least QUORUM_AGREEMENT of n draws are hostile).
    (QUORUM_AGREEMENT as u32..=n)
        .map(|k| binomial(n, k) * f.powi(k as i32) * (1.0 - f).powi((n - k) as i32))
        .sum()
}

fn binomial(n: u32, k: u32) -> f64 {
    (0..k).fold(1.0, |acc, i| acc * f64::from(n - i) / f64::from(i + 1))
}

#[cfg(test)]
mod tests;
