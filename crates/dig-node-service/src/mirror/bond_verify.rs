//! Reading a peer's claimed mirror coin against the chain (dig-node#466).
//!
//! [`dig_node_core::mirror_bond`] owns the DECISION — three verdicts, and a locator layer that ranks
//! a holder set by them. This module owns the half that needs a chain: fetching the coin a holder
//! named, re-deriving it from the spend that created it, and asking whether it bonds the content
//! that was actually requested.
//!
//! # The algorithm is `SYSTEM.md`'s, not this module's
//!
//! Four steps, in order, and none of them is optional:
//!
//! 1. the coin sits at [`mirror_coin_puzzle_hash`];
//! 2. it is $DIG, with the asset id re-derived from the creating spend;
//! 3. it carries the full collateral;
//! 4. [`MirrorCoin::advertises`] — **exact equality** on the coin's declared
//!    `(store, root, epoch)`, plus the hint recomputed with the owner taken from the coin's own
//!    lineage proof.
//!
//! Steps 1-3 establish only that *a* valid mirror coin exists somewhere. **Step 4 is what binds it
//! to the claim**, and it is why nothing here recomputes the morph by hand: `mirror_hint` sums four
//! terms, one of them a freely chosen `epoch`, so an author can solve for a value landing on any
//! other advertisement's hint. `dig-mirror-coin` asserts exactly that about itself. Both halves of
//! `advertises` are needed and neither is redundant.
//!
//! # The order of steps 3 and 4 is deliberate
//!
//! The tuple binding is checked BEFORE collateral sufficiency. A node that has not yet censused an
//! epoch cannot price a bond, and if that were checked first every verdict on such a node would be
//! `Unverified` — including a holder naming a coin that plainly bonds someone else's store. Binding
//! first means the lie is caught by any node with a chain, censused or not; an unknown requirement
//! then downgrades an otherwise-good answer to `Unverified` rather than promoting it to `Bonded`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chia_protocol::Bytes32;
use dig_chainsource_interface::ChainSource;
use dig_mirror_coin::{mirror_coin_puzzle_hash, MirrorCoin, MirrorError};
use dig_node_core::mirror_bond::{BondVerdict, ContentId, MirrorBondVerifier};
use num_bigint::BigInt;

use crate::collateral::{current_epoch_now, requirement, EpochRecordStore};
use dig_node_control_interface::results::CollateralRequirementResult;

/// How long a DEFINITE verdict stays usable before the chain is asked again.
///
/// Short relative to an epoch (seven days) so a rollover is picked up long before a stale `Bonded`
/// could outlive the coin that earned it, and long enough that a burst of reads for one capsule
/// costs one chain lookup rather than one per holder per read.
const VERDICT_TTL: Duration = Duration::from_secs(600);

/// The most cached verdicts held at once.
///
/// The key includes a coin id chosen by whoever published the provider record, so the map's growth
/// is driven by attacker-writable input and MUST be bounded. Overflow evicts ONE entry rather than
/// clearing: clearing hands a stranger a cheap way to discard every honest verdict this node has
/// earned simply by rotating coin ids, which converts a memoisation into an amplifier.
const MAX_CACHED_VERDICTS: usize = 1024;

/// The most locate-triggered verifications this PROCESS will pay for in one burst.
///
/// Each one reads through `corroborated_chain_source` (dig-node#503, dig-node#527 item 3) —
/// `api.coinset.org` first, falling back to a `BOND_CORROBORATION_FLOOR`-peer corroborated round
/// only when that read fails, never a bare uncorroborated read from a single shared client. So this
/// ceiling is not about fairness between requestors; it is about this node keeping its own chain
/// access — and its peers' attention on a fallback round — when a stranger directs traffic at it.
///
/// The inbound admission gate (`allow_miss_lookup`, burst 16 at 4/sec) is PER REQUESTOR over up to
/// 4,096 self-minted identities and has no aggregate cap, so it cannot bound this. Sixteen is
/// therefore chosen against the *outbound* cost, not the inbound one: two locates' worth of a full
/// slate, after which verification degrades to `Unverified` — which is where every record already
/// sits when no verifier is installed at all.
const VERIFICATION_BURST: u32 = 16;

/// How fast [`VERIFICATION_BURST`] refills, in verifications per second.
///
/// One per second, deliberately slower than the inbound refill it cannot control: an attacker who
/// sustains the inbound rate gets a *constant* trickle of outbound reads rather than a multiple of
/// its own request rate. An honest node's own reads — a capsule it is downloading — are answered
/// from the burst and then from the verdict cache.
const VERIFICATION_REFILL_PER_SEC: f64 = 1.0;

/// The most verifications in flight at once, so a burst cannot fan out CONCURRENTLY onto the shared
/// client even while it is within the rate ceiling.
///
/// A rate bound alone still permits sixteen simultaneous blocking reads, which is what a connection
/// pool experiences as an outage rather than as load.
const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// The most DISTINCT claimed coin ids one claiming peer may spend chain reads on, per
/// [`CLAIMANT_LEDGER_WINDOW`], without ever proving a bond.
///
/// This is the bound that answers the fabricated-coin-id case specifically. [`VerdictKey`] includes
/// the coin id — it must, or a stranger republishing a public coin id would inherit its holder's
/// verdict — so eight records carrying eight *invented* coin ids miss the cache eight times by
/// construction, and no cache design can fix that. What CAN be bounded is how many invented ids one
/// claimed identity is allowed to be wrong about before this node stops asking on its behalf.
///
/// Four, because an honest holder needs ONE: a peer publishes the coin it created. A rollover can
/// make it briefly two (the old coin and the new one). Anything beyond that is a peer that does not
/// know which coin it holds, and its records are worth no more chain reads than a stranger's.
const MAX_UNPROVEN_COINS_PER_CLAIMANT: usize = 4;

/// How long a claimant's unproven-coin ledger is remembered. Matched to [`VERDICT_TTL`] so a peer
/// that genuinely rotates coins is forgiven on the same clock a cached verdict expires on.
const CLAIMANT_LEDGER_WINDOW: Duration = VERDICT_TTL;

/// How often the SAME unproven `(claimant, coin_id)` pair may re-enter admission (dig-node#527,
/// item 1).
///
/// A coin that does not declare its claimant produces [`BondVerdict::Unverified`], and
/// [`VerdictCache::remember`] deliberately never caches `Unverified` — so without this bound, a
/// repeat of that exact pair paid only the process-wide token bucket, refilling at
/// [`VERIFICATION_REFILL_PER_SEC`]. That let one `(peer_id, coin_id)` pair a stranger controls hold
/// [`ReadAdmission::shared`]'s ENTIRE budget at zero forever, sustained at roughly one request per
/// second — silencing every other claimant's verification, not just this one's.
///
/// Matched to [`VERDICT_TTL`] rather than given its own tuning knob: an honest re-ask of a coin
/// whose cached verdict genuinely expired is indistinguishable, from this ledger's point of view,
/// from an attacker repeating a coin that will never declare them. Both are bounded to the exact
/// cadence a cache hit would have given the honest case for free, which costs the honest claimant
/// nothing it wasn't already going to wait for.
const UNPROVEN_COIN_RETRY_COOLDOWN: Duration = VERDICT_TTL;

/// The most claimants tracked in that ledger at once.
///
/// A claiming peer id is attacker-chosen and unbounded in supply, so the ledger MUST be bounded.
/// Once it is full of live entries an UNKNOWN claimant is refused rather than admitted, which is
/// the fail-closed direction: the cost of being wrong is a holder sitting at the baseline tier it
/// would occupy with no verifier at all, never a wrong promotion.
const MAX_TRACKED_CLAIMANTS: usize = 512;

/// A verdict is only ever cached for the exact question it answered.
///
/// The coin id alone is not the key: one coin bonds one `(store, root, epoch)`, so caching by coin
/// would let a genuine `Bonded` for one capsule answer for a different capsule the same coin does
/// not bond — the precise substitution `advertises` exists to refuse.
///
/// **The claiming peer is part of the key for the same reason.** [`verdict_for`] answers a
/// peer-DEPENDENT question: the chain half establishes that a coin bonds this content, and the
/// ownership half asks whether that coin declares the peer offering the record. A key without the
/// claimant would let a `Bonded` earned by the coin's real holder be served, for the whole
/// [`VERDICT_TTL`], to any stranger republishing the same public coin id — reinstating through the
/// memo layer the exact substitution the ownership half exists to refuse. It is inert only while
/// [`peer_declaration`] cannot return `DeclaresThisPeer`, and it must not depend on that.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VerdictKey {
    coin_id: [u8; 32],
    store_launcher_id: [u8; 32],
    root_hash: [u8; 32],
    epoch: u64,
    /// `SHA-256` of the claiming peer id. Hashed rather than held so the key stays `Copy` and
    /// fixed-size against an attacker-chosen string; only equality is ever needed.
    claiming_peer: [u8; 32],
}

impl VerdictKey {
    fn new(
        coin_id: [u8; 32],
        store: Bytes32,
        root: Bytes32,
        epoch: u64,
        claiming_peer_id: &str,
    ) -> Self {
        // ASCII-lowercased before hashing. A peer id is fixed-length hex, so its two spellings are
        // one identity, and `peer_declaration` already treats them as one because it compares
        // decoded bytes. Hashing the raw text would give each spelling its own cache entry, so a
        // stranger could multiply the chain reads one claim costs simply by varying case -- turning
        // a memo into an amplifier against `api.coinset.org`.
        let mut hasher = chia_sha2::Sha256::new();
        hasher.update(claiming_peer_id.to_ascii_lowercase().as_bytes());
        VerdictKey {
            coin_id,
            store_launcher_id: store.to_bytes(),
            root_hash: root.to_bytes(),
            epoch,
            claiming_peer: hasher.finalize(),
        }
    }
}

/// What a mirror coin's advertised terms say about the peer claiming it.
///
/// Two answers, not three. Until `dig-mirror-coin` 0.8.0 there was a `NotReadable` state for "this
/// node has no way to read a declaration at all"; the typed accessor removed the situation, so the
/// variant was removed with it rather than left as a case nothing constructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerDeclaration {
    /// The coin's owner declared this exact peer, in code the chain executed.
    DeclaresThisPeer,
    /// The coin declares some other peer, or none. Credit is withheld — never subtracted, because
    /// the record naming this coin may be a stranger's lie ABOUT the coin's real holder.
    Silent,
}

/// Whether `advertised_terms` — the free tail of a mirror coin's memo — declares `claiming_peer_id`.
///
/// The answer comes from `dig-mirror-coin`'s typed accessor and is NOT parsed here. A second parser
/// for this format, living in the consumer, would make a divergence between the two a silent
/// authorization difference rather than a compile error (CLAUDE.md §2.0, centralize rival
/// implementations). Everything the format means — exact prefix matching, byte-wise peer-id
/// comparison, and the rule that a coin carrying two declarations declares NOBODY — is stated once,
/// in that crate's `SPEC.md` §5.1.
///
/// **What a `DeclaresThisPeer` establishes.** Memos are written by the spend that creates the coin
/// and only the owner's key can produce that spend, so the term is an owner attestation carried by
/// executed on-chain code. It binds the coin to a `peer_id`. It does NOT bind that `peer_id` to the
/// addresses travelling beside it in the provider record — see `SPEC.md` §25.6a for why that gap is
/// closed by the transport rather than here.
pub(crate) fn peer_declaration(
    advertised_terms: &[String],
    claiming_peer_id: &str,
) -> PeerDeclaration {
    match dig_mirror_coin::declared_peer(advertised_terms) {
        Some(declared) if declared.names(claiming_peer_id) => PeerDeclaration::DeclaresThisPeer,
        _ => PeerDeclaration::Silent,
    }
}

/// Whether [`peer_declaration`] can bind a coin to a peer AT ALL — probed through the real
/// function, on the most favourable input that exists.
///
/// While the answer is `false`, [`verdict_for`] cannot return `Bonded` for any input, so every
/// chain read it would perform buys a verdict that is discarded: `Unverified` and `Unbonded` share
/// a rank in `credit_rank`, and the sort is stable, so the located slate is returned unchanged.
/// Paying four third-party HTTPS reads per holder, up to the locate budget, for a provably
/// discarded answer converts one cheap-lookup token into attacker-directed egress at
/// `api.coinset.org` — which degrades the same transport this node's wallet reads through.
///
/// **The gate is the condition itself, not a flag beside it.** The probe asks the production
/// function for the one term a coin owned by `probe_peer` would carry; a typed accessor that can
/// answer returns `DeclaresThisPeer` for it, the probe flips, and the short-circuit removes itself
/// with no second switch to remember. An accessor that needs more than the term list stays
/// unreadable here, which withholds credit rather than granting it — the fail-closed direction.
fn declaration_source_is_readable() -> bool {
    let probe_peer = "00".repeat(32);
    let terms = [format!("dig-peer:{probe_peer}")];
    peer_declaration(&terms, &probe_peer) == PeerDeclaration::DeclaresThisPeer
}

/// Whether `claimed_coin_id` genuinely bonds `store_launcher_id` at `root_hash` for `epoch`.
///
/// This is the CHAIN half only. `Bonded` here means a real coin bonds this content — it does NOT
/// mean the peer offering the record is that coin's holder. [`verdict_for`] adds that question, and
/// it is the one that decides promotion.
///
/// `required_collateral` is this node's censused per-store requirement, or `None` when it has no
/// record for the epoch. Pure over the source, so a test can drive every branch with real coins
/// built from real CAT spends.
///
/// `Err` from the source is always [`BondVerdict::Unverified`] and never `Unbonded`: a source that
/// could not answer has said nothing about the holder.
///
/// `claiming_peer_id` is the peer id off the same untrusted record as `claimed_coin_id`. A coin id
/// is a public fact, so a coin that bonds the content proves nothing about WHO is offering it; the
/// last step asks the coin whether it declares this claimant, and only that answer promotes.
pub fn chain_bond_verdict<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    chain_bond_verdict_and_coin(
        source,
        store_launcher_id,
        root_hash,
        epoch,
        required_collateral,
        claimed_coin_id,
    )
    .0
}

/// [`chain_bond_verdict`], additionally handing back the coin it read.
///
/// The ownership half needs the SAME `MirrorCoin` the chain half just re-derived. Returning it is
/// what keeps a bonded holder at two chain reads rather than four: the reads are outbound HTTPS to
/// a shared third party, so re-fetching to ask a second question about one coin doubles this
/// node's egress for no new information.
///
/// The coin is returned only alongside [`BondVerdict::Bonded`] — every other verdict is reached
/// before, or instead of, a coin that binds this claim.
fn chain_bond_verdict_and_coin<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claimed_coin_id: Bytes32,
) -> (BondVerdict, Option<MirrorCoin>) {
    let record = match source.coin_record(claimed_coin_id) {
        Ok(Some(record)) => record,
        // The chain answered and there is no such coin. The publisher named something that does not
        // exist, which is a claim disproven rather than a claim unexamined.
        Ok(None) => return (BondVerdict::Unbonded, None),
        Err(_) => return (BondVerdict::Unverified, None),
    };

    // A spent coin locks nothing. Collateral is the coin remaining unspent; a reclaimed one is a
    // bond that has already been taken back.
    if record.is_spent() {
        return (BondVerdict::Unbonded, None);
    }

    // Step 1. Every mirror coin in existence shares this puzzle hash, so failing here says the coin
    // is not collateral of any kind.
    if record.coin.puzzle_hash != mirror_coin_puzzle_hash() {
        return (BondVerdict::Unbonded, None);
    }

    // Steps 2 and 3's asset id, and the owner step 4 needs, all come from EXECUTED on-chain code:
    // the parent's puzzle is run and its `CREATE_COIN` conditions searched for this coin. Nothing
    // here is taken from a memo, which is the only part of a mirror coin its publisher writes
    // freely.
    let creating_spend = match source.coin_spend(record.coin.parent_coin_info) {
        Ok(Some(spend)) => spend,
        // The coin exists, so its parent was spent; a source that cannot produce that spend has a
        // gap rather than an answer.
        Ok(None) | Err(_) => return (BondVerdict::Unverified, None),
    };

    let mirror = match MirrorCoin::from_creating_spend(&creating_spend, claimed_coin_id) {
        Ok(Some(mirror)) => mirror,
        // Established, and the answer is no: not a $DIG-collateral coin, or one advertising nothing.
        Ok(None) => return (BondVerdict::Unbonded, None),
        Err(MirrorError::ChainUnavailable(_)) => return (BondVerdict::Unverified, None),
        // Memos that will not decode. The publisher chose this coin id and chose those memos, so
        // this is its claim failing, not this node failing to look.
        Err(_) => return (BondVerdict::Unbonded, None),
    };

    // Step 4 — the one that binds the coin to THIS claim.
    if !mirror.advertises(store_launcher_id, root_hash, epoch) {
        return (BondVerdict::Unbonded, None);
    }

    // Step 3's magnitude (see the module docs for why it is not first).
    match required_collateral {
        Some(required) if mirror.collateral() < required => return (BondVerdict::Unbonded, None),
        Some(_) => {}
        None => return (BondVerdict::Unverified, None),
    }

    // The chain half is satisfied. WHOSE bond it is is a separate question -- see `verdict_for`.
    (BondVerdict::Bonded, Some(mirror))
}

/// The full verdict: the chain half, then **whose bond it is**.
///
/// A valid, fully-collateralised coin bonding exactly this content still says nothing about the peer
/// offering the record — every field of that record, the coin id included, was chosen by whoever
/// answered the lookup. Only the coin's own owner-written declaration of a peer closes that, and
/// [`peer_declaration`] reads it, so a `Bonded` here means BOTH halves held: the coin bonds this
/// content, and the coin's owner named this claimant.
///
/// Credit is withheld, never subtracted: a record naming this coin may be a stranger's lie ABOUT the
/// coin's real holder, and demoting on it is what would make that lie pay.
///
/// **A node with no censused requirement for the epoch cannot promote anyone**, because it cannot
/// price a bond — `required_collateral` is then `None` and the verdict degrades to `Unverified`
/// rather than to `Bonded`. Detection of a false claim still works there (the binding is checked
/// first, deliberately), but certification does not.
pub fn verdict_for<S: ChainSource>(
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: Option<u64>,
    claiming_peer_id: &str,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    // Before any chain read: while nothing can bind a coin to a peer, `Bonded` is unreachable and
    // the reads below would be paid for a verdict this function is about to discard.
    if !declaration_source_is_readable() {
        return BondVerdict::Unverified;
    }
    let (chain, coin) = chain_bond_verdict_and_coin(
        source,
        store_launcher_id,
        root_hash,
        epoch,
        required_collateral,
        claimed_coin_id,
    );
    let Some(mirror) = coin else {
        // Every non-`Bonded` verdict arrives without a coin, and `Bonded` never arrives without one.
        return chain;
    };
    match peer_declaration(mirror.urls(), claiming_peer_id) {
        PeerDeclaration::DeclaresThisPeer => BondVerdict::Bonded,
        PeerDeclaration::Silent => BondVerdict::Unverified,
    }
}

/// Whether a chain read may be spent on one claim, right now.
///
/// **Why this exists.** Before promotion went live, `verdict_for` returned at
/// `declaration_source_is_readable()` and a locate cost zero chain reads. Activating it turned one
/// cheap inbound token into up to `MAX_VERIFIED_PER_LOCATE` verifications, each two outbound HTTPS
/// reads, on a client shared with the wallet — and the inbound gate that admits the locate is
/// per-requestor over self-minted identities, so it bounds nothing in aggregate. This type is the
/// aggregate bound (dig-node#501, security round 1, HIGH).
///
/// Two independent limits, because they answer two different attacks:
///
/// * a **process-wide token bucket** ([`VERIFICATION_BURST`] at [`VERIFICATION_REFILL_PER_SEC`]),
///   which bounds total outbound egress however many identities the traffic is spread across;
/// * a **per-claimant distinct-coin ledger** ([`MAX_UNPROVEN_COINS_PER_CLAIMANT`]), which bounds
///   the fabricated-coin-id case the verdict cache structurally cannot absorb.
///
/// Exhaustion of either returns [`BondVerdict::Unverified`] having read NOTHING. That is a
/// degradation and not a refusal of service: `Unverified` and `Unbonded` share a rank, the sort is
/// stable, and the located slate is returned unchanged — the exact behaviour of a node with no
/// verifier installed. **The read path is never blocked and no holder is ever ranked below where it
/// started**, so an attacker who exhausts the budget denies promotion, not content.
struct ReadAdmission {
    state: Mutex<AdmissionState>,
}

/// Per claimant: when its ledger window opened, and the distinct coin ids it has spent reads on
/// without proving a bond, each mapped to WHEN it was last admitted — so a repeat of the same coin
/// id can be throttled to [`UNPROVEN_COIN_RETRY_COOLDOWN`] independently of the process-wide
/// bucket.
type ClaimantLedger = HashMap<[u8; 32], (Instant, HashMap<[u8; 32], Instant>)>;

/// [`ReadAdmission`]'s interior, held under one lock so the two limits are decided atomically —
/// a token spent on a claim the ledger was about to refuse would be a leak.
struct AdmissionState {
    /// Whole verifications available now. Fractional so a sub-second refill is not rounded away.
    tokens: f64,
    /// When `tokens` was last brought up to date.
    refilled_at: Instant,
    burst: f64,
    refill_per_sec: f64,
    /// Keyed on the SHA-256 of the lowercased peer id, for the reason [`VerdictKey`] hashes it —
    /// the key must be fixed-size against an attacker-chosen string, and two hex spellings must be
    /// one identity.
    unproven: ClaimantLedger,
}

impl ReadAdmission {
    /// A budget of the given size. Parameterised so a test can exhaust one in a few calls rather
    /// than by replicating production's arithmetic.
    fn new(burst: u32, refill_per_sec: f64) -> Self {
        ReadAdmission {
            state: Mutex::new(AdmissionState {
                tokens: f64::from(burst),
                refilled_at: Instant::now(),
                burst: f64::from(burst),
                refill_per_sec,
                unproven: HashMap::new(),
            }),
        }
    }

    /// The one budget every locate on this node draws from.
    ///
    /// Process-wide rather than per verifier: the constraint being protected is the single shared
    /// `ChiaQuery` client, which is a property of the process, so a budget scoped to anything
    /// narrower would be several budgets against one resource.
    fn shared() -> &'static ReadAdmission {
        static SHARED: std::sync::OnceLock<ReadAdmission> = std::sync::OnceLock::new();
        SHARED.get_or_init(|| ReadAdmission::new(VERIFICATION_BURST, VERIFICATION_REFILL_PER_SEC))
    }

    /// Whether a chain read may be spent on `claimed_coin_id` for `claiming_peer_id`.
    ///
    /// Returning `false` costs the network nothing and this node nothing; returning `true` spends a
    /// token, so it is called exactly once per verification and never as a peek.
    fn admit(&self, claiming_peer_id: &str, claimed_coin_id: [u8; 32]) -> bool {
        let Ok(mut state) = self.state.lock() else {
            // A poisoned budget cannot be shown to have capacity, so it has none.
            return false;
        };

        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(state.refilled_at)
            .as_secs_f64();
        state.tokens = (state.tokens + elapsed * state.refill_per_sec).min(state.burst);
        state.refilled_at = now;

        let claimant = claimant_key(claiming_peer_id);
        state
            .unproven
            .retain(|_, (opened, _)| opened.elapsed() < CLAIMANT_LEDGER_WINDOW);
        let known = state.unproven.contains_key(&claimant);
        if !known && state.unproven.len() >= MAX_TRACKED_CLAIMANTS {
            return false;
        }
        if let Some((_, coins)) = state.unproven.get(&claimant) {
            match coins.get(&claimed_coin_id) {
                // A repeat of a coin this claimant already spent a read on. Bounded to the SAME
                // cadence a cache hit would have given an honest re-ask — never a fresh admission
                // every attempt, which is what let one unprovable pair hold the whole process-wide
                // bucket at zero (dig-node#527, item 1).
                Some(last_admitted) if last_admitted.elapsed() < UNPROVEN_COIN_RETRY_COOLDOWN => {
                    return false;
                }
                // Genuinely new to this claimant: only DISTINCT unproven ids count against the
                // ledger cap.
                None if coins.len() >= MAX_UNPROVEN_COINS_PER_CLAIMANT => {
                    return false;
                }
                _ => {}
            }
        }

        if state.tokens < 1.0 {
            return false;
        }
        state.tokens -= 1.0;
        state
            .unproven
            .entry(claimant)
            .or_insert_with(|| (now, HashMap::new()))
            .1
            .insert(claimed_coin_id, now);
        true
    }

    /// Forgive a claimant's ledger: it has proven a bond, so it is not a peer guessing at coin ids.
    ///
    /// The process-wide bucket is deliberately NOT refunded. A proven bond says the claimant is
    /// honest; it says nothing about this node's chain access, which is the thing the bucket exists
    /// to protect.
    fn record_proven(&self, claiming_peer_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.unproven.remove(&claimant_key(claiming_peer_id));
        }
    }
}

/// A claiming peer id as a fixed-size ledger key: lowercased, then hashed.
///
/// The same normalisation [`VerdictKey`] applies, for the same two reasons — the key must be
/// fixed-size against an attacker-chosen string, and a peer id's two hex spellings denote one
/// identity, so a ledger keyed on the raw text would give a stranger a fresh allowance per spelling.
fn claimant_key(claiming_peer_id: &str) -> [u8; 32] {
    let mut hasher = chia_sha2::Sha256::new();
    hasher.update(claiming_peer_id.to_ascii_lowercase().as_bytes());
    hasher.finalize()
}

/// [`verdict_for`], but only if the budget allows the reads it would perform.
///
/// **This is the composition production uses**, so a test that drives it is exercising the real
/// ordering rather than re-deriving it: the budget is consulted BEFORE the source is touched, so a
/// refused claim reads nothing, and a proven bond forgives its claimant's ledger.
///
/// **`required_collateral` is a THUNK, not a value, and that is load-bearing (dig-node#527, item
/// 2).** `current_requirement()` — the production caller — is a synchronous file read plus a JSON
/// parse; if it were an already-evaluated `Option<u64>` argument, Rust would run it while building
/// this call's argument list, which happens BEFORE `admit()` below ever runs. A claim `admit()` was
/// always going to refuse would still have paid the read. Taking a closure defers that cost to
/// exactly the branch that needs it: only a claim that survives admission ever calls it.
///
/// The parameter list is otherwise `verdict_for`'s, in `verdict_for`'s order, with the budget in
/// front. That is deliberate and is why the lint is allowed here rather than satisfied by grouping:
/// four of the arguments are opaque 32-byte values, so the one mistake this wrapper could make is
/// transposing two of them, and a signature that mirrors the wrapped function exactly makes such a
/// transposition visible at the call site below instead of hiding it inside a re-packing struct.
#[allow(clippy::too_many_arguments)]
fn admitted_verdict_for<S: ChainSource>(
    admission: &ReadAdmission,
    source: &S,
    store_launcher_id: Bytes32,
    root_hash: Bytes32,
    epoch: &BigInt,
    required_collateral: impl FnOnce() -> Option<u64>,
    claiming_peer_id: &str,
    claimed_coin_id: Bytes32,
) -> BondVerdict {
    if !admission.admit(claiming_peer_id, claimed_coin_id.to_bytes()) {
        return BondVerdict::Unverified;
    }
    let verdict = verdict_for(
        source,
        store_launcher_id,
        root_hash,
        epoch,
        required_collateral(),
        claiming_peer_id,
        claimed_coin_id,
    );
    if verdict == BondVerdict::Bonded {
        admission.record_proven(claiming_peer_id);
    }
    verdict
}

/// The memo of definite verdicts, keyed on the exact question each one answered.
///
/// Its own type, rather than two fields on the verifier, so the key/lookup/eviction rules can be
/// exercised directly — including the one that matters most and is invisible from the outside:
/// that a verdict earned by one claiming peer is never served to another.
#[derive(Default)]
struct VerdictCache {
    entries: Mutex<HashMap<VerdictKey, (Instant, BondVerdict)>>,
}

impl VerdictCache {
    /// The verdict recorded for exactly this question, if one is recorded and still fresh.
    fn get(&self, key: &VerdictKey) -> Option<BondVerdict> {
        let entries = self.entries.lock().ok()?;
        entries
            .get(key)
            .filter(|(taken, _)| taken.elapsed() < VERDICT_TTL)
            .map(|(_, verdict)| *verdict)
    }

    /// Remember a DEFINITE verdict. `Unverified` is never cached: it records this node's own
    /// momentary inability to look, and holding it would keep an outage in force after it ended.
    fn remember(&self, key: VerdictKey, verdict: BondVerdict) {
        if verdict == BondVerdict::Unverified {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= MAX_CACHED_VERDICTS {
            // Expired first. Eviction should reclaim what is already worthless before it touches
            // anything live, and a full map is the only moment worth paying the scan for.
            entries.retain(|_, (taken, _)| taken.elapsed() < VERDICT_TTL);
        }
        if entries.len() >= MAX_CACHED_VERDICTS {
            // Still full of LIVE entries, so admitting this one costs an honest verdict. Only a
            // `Bonded` is worth that trade, and only a `Bonded` is expensive to obtain: it requires
            // a coin that exists, is fully collateralised, and declares its claimant.
            //
            // **An `Unbonded` is refused admission rather than allowed to evict.** The previous
            // version evicted one arbitrary entry per insert, which read as conservative but is
            // paced by the attacker: `Unbonded` is the verdict a stranger elicits for FREE by
            // naming coin ids that do not exist, so at an attacker-chosen insert rate the map turns
            // over entirely in well under a minute and every honest `Bonded` this node earned is
            // discarded. Refusing the cheap insert instead means a flood of invented coin ids
            // cannot displace a single earned verdict — it only re-reads its own claims, which
            // `ReadAdmission` is separately bounding.
            if verdict != BondVerdict::Bonded {
                return;
            }
            if let Some(victim) = entries.keys().next().copied() {
                entries.remove(&victim);
            }
        }
        entries.insert(key, (Instant::now(), verdict));
    }
}

/// The production [`MirrorBondVerifier`]: one bounded chain read per distinct claim, memoised.
pub struct ChainBondVerifier {
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
    cache: VerdictCache,
}

impl ChainBondVerifier {
    /// Verify against the node's own chain transport.
    pub fn new(chain: Arc<dig_wallet::sage::chain::ChainTransport>) -> Arc<Self> {
        Arc::new(ChainBondVerifier {
            chain,
            cache: VerdictCache::default(),
        })
    }

    /// The chain half: one bounded read, memoised.
    ///
    /// Takes no `required_collateral` parameter, deliberately (dig-node#527, item 2): the epoch
    /// requirement is a synchronous file read, and computing it here — before `admit()` — would
    /// pay that read for a claim the budget was always going to refuse. `admitted_verdict_for`
    /// receives [`current_requirement`] itself as a thunk and calls it only past that gate.
    #[allow(clippy::too_many_arguments)]
    async fn verify_against_chain(
        &self,
        key: VerdictKey,
        store: Bytes32,
        root: Bytes32,
        epoch: u64,
        claiming_peer_id: &str,
        coin_id: [u8; 32],
    ) -> BondVerdict {
        // Corroborated, never the router (dig-node#503). `chain_source` asks `api.coinset.org`
        // first and consults this node's peers only when that read fails -- its own `ProviderInfo`
        // says `trustless: false` -- so a `Bonded` verdict taken from it rests on ONE source's
        // word. Every check below is internal consistency of a coin and its creating spend, and
        // all of them pass on a coin curried around an invented parent that was never on mainnet.
        // Only chain MEMBERSHIP disproves that, and membership is what a single endpoint cannot
        // settle.
        //
        // No fallback here, deliberately: `corroborated_chain_source` errs rather than handing
        // back the router, and this reads that as `Unverified`. Falling back would let one
        // endpoint overrule the peers exactly when they failed to agree.
        //
        // Re-read per call rather than held from bring-up, matching the mirror pass: a transport
        // built once would make a node that started offline one that never verifies again.
        //
        // At the BOND floor, not the sync one (dig-node#513). `CORROBORATION_FLOOR` is two
        // because the sync path writes the wallet's replica and a refused round stalls it; this
        // path writes nothing, so a refusal costs `Unverified` -- the tier every record occupies
        // with no verifier installed -- while believing a two-voice round sells a promotion for
        // the price of two peers.
        let Ok(source) = self
            .chain
            .corroborated_chain_source(tokio::runtime::Handle::current())
            .map(|source| {
                source.requiring_corroboration(dig_wallet::sage::quorum::BOND_CORROBORATION_FLOOR)
            })
        else {
            return BondVerdict::Unverified;
        };

        // Peer-availability pre-check (dig-node#527, item 4): a sample too small to ever meet
        // `source.required_floor()` makes `Bonded` unreachable exactly as surely as
        // `declaration_source_is_readable()` does above, so the read below is skipped rather than
        // paid for a verdict `tally_with_floor` cannot produce.
        //
        // `live_peer_hint` is a non-dialling PEEK at whatever the last draw already held, never a
        // reason to dial ourselves: forcing a fresh redraw for every claim a thin network cannot
        // satisfy would trade one honest `Unverified` for a redial storm against that same thin
        // network, which is the worse defect (§2.6 -- report the truth, do not manufacture load).
        // `None` (nothing drawn yet) fails OPEN into the real read, which is what discovers peers
        // in the first place.
        if sample_cannot_meet_floor(source.live_peer_hint(), source.required_floor()) {
            return BondVerdict::Unverified;
        }

        // The concurrency ceiling, and `try_acquire` rather than `acquire`: a queue of tasks
        // waiting for a permit is an unbounded backlog of attacker-directed work held on this
        // node's heap, and the honest answer when the budget is saturated is available immediately
        // -- `Unverified`, the tier every record occupies with no verifier installed.
        static IN_FLIGHT: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
        let Ok(_permit) = IN_FLIGHT
            .get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_VERIFICATIONS))
            .try_acquire()
        else {
            return BondVerdict::Unverified;
        };

        // `ChainSource` is blocking, so the read leaves the async worker rather than parking it.
        let epoch_big = BigInt::from(epoch);
        let verdict = tokio::task::block_in_place(|| {
            admitted_verdict_for(
                ReadAdmission::shared(),
                &source,
                store,
                root,
                &epoch_big,
                current_requirement,
                claiming_peer_id,
                Bytes32::new(coin_id),
            )
        });

        self.cache.remember(key, verdict);
        verdict
    }
}

/// Whether a chain read would be spent on a sample too small to ever produce `Bonded`
/// (dig-node#527, item 4).
///
/// A pure predicate over the two inputs [`ChainBondVerifier::verify_against_chain`] gathers, kept
/// separate from the caller so the decision is unit-testable without a real chain transport or any
/// network dial.
///
/// `live_hint` is `None` whenever nothing is known yet (no draw has happened) — that fails OPEN
/// into the real read, which is what discovers peers in the first place, never into a refusal a
/// caller could mistake for the network having none.
fn sample_cannot_meet_floor(live_hint: Option<usize>, required_floor: usize) -> bool {
    live_hint.is_some_and(|live| live < required_floor)
}

/// The `(store, root)` a bond could be checked against, or `None` for a store-granularity id.
///
/// A mirror coin bonds a `(store, root, owner, epoch)` tuple, so a claim about a whole STORE names
/// no generation and is not a thing a coin can advertise. That is a limit of the question, not a
/// failed verification.
fn bondable_tuple(content: &ContentId) -> Option<(Bytes32, Bytes32)> {
    match content {
        ContentId::Store { .. } => None,
        ContentId::Root { store_id, root } | ContentId::Resource { store_id, root, .. } => {
            Some((Bytes32::new(*store_id), Bytes32::new(*root)))
        }
    }
}

/// This node's current epoch, or `None` when it is not yet settled.
///
/// Clock arithmetic only — no file is touched, which is why the cache can be probed under the TRUE
/// current epoch rather than under a remembered hint. A hint would hit an entry stored under the
/// previous epoch for up to [`VERDICT_TTL`] after a rollover, which is a verdict taken under the
/// wrong epoch and not merely a miss.
fn settled_epoch() -> Option<u64> {
    match current_epoch_now() {
        crate::collateral::CurrentEpoch::Final(epoch) => Some(epoch),
        _ => None,
    }
}

/// This node's censused per-store requirement for the current epoch, or `None` when it has no
/// record for it.
///
/// A file read plus a line-by-line JSON parse, so it is paid only on a cache miss.
fn current_requirement() -> Option<u64> {
    let current = current_epoch_now();
    match requirement(&EpochRecordStore::in_state_dir(), current) {
        CollateralRequirementResult::Known {
            required_per_store_dig_base_units,
            ..
        } => Some(required_per_store_dig_base_units),
        _ => None,
    }
}

#[async_trait]
impl MirrorBondVerifier for ChainBondVerifier {
    async fn verify(
        &self,
        content: &ContentId,
        claiming_peer_id: &str,
        claimed_coin_id: Option<[u8; 32]>,
    ) -> BondVerdict {
        // No pointer is the ORDINARY case and costs no chain read at all: an older publisher, one
        // that has not created its coin, and one mid-rollover all legitimately omit it.
        let Some(coin_id) = claimed_coin_id else {
            return BondVerdict::Unverified;
        };
        let Some((store, root)) = bondable_tuple(content) else {
            return BondVerdict::Unverified;
        };
        // Nothing below can produce `Bonded` while the ownership half has no source, so the whole
        // leg — cache, epoch, chain — is skipped rather than paid for a discarded answer.
        if !declaration_source_is_readable() {
            return BondVerdict::Unverified;
        }
        let Some(epoch) = settled_epoch() else {
            return BondVerdict::Unverified;
        };
        // The cheap in-memory probe first: a slate of records for one capsule otherwise pays the
        // epoch-record parse per record even when every verdict is already known.
        let key = VerdictKey::new(coin_id, store, root, epoch, claiming_peer_id);
        if let Some(hit) = self.cache.get(&key) {
            return hit;
        }

        self.verify_against_chain(key, store, root, epoch, claiming_peer_id, coin_id)
            .await
    }
}

/// Install the bond verifier on the node's content engine once the peer network has brought it up.
///
/// Detached and best-effort, because the engine is created asynchronously by
/// `peer::spawn_peer_network` and this call site runs beside it. A node whose peer network never
/// comes up simply never installs a verifier, and its locator layer stays the pass-through it is
/// before installation — the shipped behaviour, not a degraded one.
pub fn spawn_bond_verifier_install(
    node: Arc<dig_node_core::Node>,
    chain: Arc<dig_wallet::sage::chain::ChainTransport>,
) {
    tokio::spawn(async move {
        for _ in 0..BOND_VERIFIER_INSTALL_ATTEMPTS {
            if let Some(content) = node.p2p_content() {
                if content.set_bond_verifier(ChainBondVerifier::new(chain)) {
                    tracing::info!(
                        "mirror-coin bond verification is live: located holders are now ranked by \
                         whether their claimed collateral actually bonds the content (#466)"
                    );
                }
                return;
            }
            tokio::time::sleep(BOND_VERIFIER_INSTALL_INTERVAL).await;
        }
        tracing::debug!(
            "no P2P content engine after peer-network bring-up; mirror-coin bond ranking stays off"
        );
    });
}

/// Long enough to outlast an ordinary peer-network bring-up, bounded so the task cannot outlive a
/// node that will never have an engine.
const BOND_VERIFIER_INSTALL_ATTEMPTS: usize = 60;
const BOND_VERIFIER_INSTALL_INTERVAL: Duration = Duration::from_secs(2);

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves (dig-node#466):** no advertised term this node can see promotes a claim today.
    ///
    /// **Catches:** the rival parser. The tail of a mirror coin's memo is arbitrary UTF-8 and
    /// `MirrorCoin::urls()` hands it straight over, so a well-meaning change could make promotion
    /// reachable immediately by parsing `dig-peer:` here — a second implementation of a
    /// security-critical format that `dig-mirror-coin` 0.8.0 is about to own, where a divergence
    /// between the two parsers is a silent authorization difference rather than a compile error.
    /// A well-formed term is included in the fixture precisely because that is the input a rival
    /// parser would accept; a fixture of only junk terms would pass against one.
    ///
    /// This test is expected to FAIL when 0.8.0's typed accessor lands. That is its second job: the
    /// authoritative-record restriction must land in the same change that makes promotion live.
    use async_trait::async_trait;
    use dig_chainsource_interface::{CoinRecord, SingletonLineage};
    use dig_node_core::mirror_bond::{
        bond_verifier_slot, BondRankingLocator, CandidateAddr, DownloadError, PeerId,
        ProviderLocator, ProviderRecord,
    };
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// A chain that counts every read reaching it and answers "no such coin".
    ///
    /// Answering nothing is deliberate. It makes the read COUNT the only variable: a claim against
    /// this source is disproven at the first step, so any count above one is a retry loop or a
    /// second question, both of which this module owes the network not to perform.
    struct CountingChain {
        reads: Arc<AtomicUsize>,
    }

    impl CountingChain {
        fn counted<T>(&self, answer: T) -> Result<T, String> {
            self.reads.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(answer)
        }
    }

    impl ChainSource for CountingChain {
        type Error = String;

        fn coin_record(&self, _coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
            self.counted(None)
        }

        fn coin_records_by_puzzle_hash(
            &self,
            _puzzle_hash: Bytes32,
            _include_spent: bool,
        ) -> Result<Vec<CoinRecord>, Self::Error> {
            self.counted(Vec::new())
        }

        fn coin_records_by_parent(&self, _parent: Bytes32) -> Result<Vec<CoinRecord>, Self::Error> {
            self.counted(Vec::new())
        }

        fn coin_spend(
            &self,
            _coin_id: Bytes32,
        ) -> Result<Option<chia_protocol::CoinSpend>, Self::Error> {
            self.counted(None)
        }

        fn resolve_singleton_lineage(
            &self,
            _launcher_id: Bytes32,
        ) -> Result<Option<SingletonLineage>, Self::Error> {
            self.counted(None)
        }

        fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
            self.counted(Some(1_000))
        }

        fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
            self.counted(Some(1_700_000_000))
        }
    }

    const STORE: [u8; 32] = [0x11; 32];
    const ROOT: [u8; 32] = [0x22; 32];

    fn capsule() -> ContentId {
        ContentId::capsule(STORE, ROOT)
    }

    fn holder_at(peer: u8, coin: Option<[u8; 32]>, host: &str) -> ProviderRecord {
        let record = ProviderRecord::new(
            &capsule().to_key(),
            &PeerId::from_bytes([peer; 32]),
            vec![CandidateAddr::direct(host, 9444)],
            u64::MAX,
        );
        match coin {
            Some(id) => record.with_unverified_mirror_coin_id(id),
            None => record,
        }
    }

    /// A slate exactly as a single lookup answer would deliver it.
    struct Slate(Vec<ProviderRecord>);

    #[async_trait]
    impl ProviderLocator for Slate {
        async fn find_providers(
            &self,
            _content: &ContentId,
        ) -> Result<Vec<ProviderRecord>, DownloadError> {
            Ok(self.0.clone())
        }
    }

    /// A chain that answers YES to everything `verdict_for` can check without this node's own
    /// judgement: the coin exists, is unspent, is a mirror coin, is fully collateralised, and
    /// advertises exactly this `(store, root, epoch)`. The ONLY step left is the real production
    /// gate — [`peer_declaration`] — so this double cannot make the layer look safer than it is.
    struct EveryChainCheckPasses;

    #[async_trait]
    impl dig_node_core::mirror_bond::MirrorBondVerifier for EveryChainCheckPasses {
        async fn verify(
            &self,
            _content: &ContentId,
            claiming_peer_id: &str,
            claimed: Option<[u8; 32]>,
        ) -> BondVerdict {
            if claimed.is_none() {
                return BondVerdict::Unverified;
            }
            // The coin's memo tail as a coin owned by this claimant would carry it.
            let terms = vec![format!("dig-peer:{claiming_peer_id}")];
            match peer_declaration(&terms, claiming_peer_id) {
                PeerDeclaration::DeclaresThisPeer => BondVerdict::Bonded,
                PeerDeclaration::Silent => BondVerdict::Unverified,
            }
        }
    }

    /// **Proves (dig-node#473):** a record carrying an honest holder's peer id and real coin id but
    /// the ATTACKER's addresses IS promoted here — and the promotion is bounded to ONE slot however
    /// many copies of it a slate contains.
    ///
    /// **This test previously asserted the opposite, and it was wrong for a measured reason.** Its
    /// premise was that "the dial does not pin the peer id (dig-gossip#85) to catch it afterwards".
    /// That is true only of `dig-gossip`'s legacy rustls outbound, which dig-node never dials on:
    /// every dial it makes passes the expected id through `dig-nat` to `dig-tls`, whose verifier
    /// fails the handshake with `peer_id mismatch`. So the attacker's addresses buy a refused
    /// connection, not a redirected reader, and the honest promotion is not a hole.
    ///
    /// **Catches:** the bound going missing. The coin binds coin -> peer id and never peer id ->
    /// address, so nothing in this layer can tell the honest holder's record from the attacker's
    /// copy of it — both name the same peer and the same real coin. What this layer CAN do is refuse
    /// to spend more than one promoted slot on one claimed peer id, which is what keeps a single
    /// stolen identity from filling the whole verified budget. The slate below carries three copies
    /// and one ordinary holder, so a missing dedup shows up as three promotions instead of one.
    #[tokio::test]
    async fn one_stolen_identity_cannot_occupy_more_than_one_promoted_slot() {
        let slate = Slate(vec![
            holder_at(0xCC, None, "honest-no-pointer.example"),
            holder_at(0xAA, Some([0x01; 32]), "attacker-1.example"),
            holder_at(0xAA, Some([0x01; 32]), "attacker-2.example"),
            holder_at(0xAA, Some([0x01; 32]), "attacker-3.example"),
        ]);
        let slot = bond_verifier_slot();
        let _ = slot.set(Arc::new(EveryChainCheckPasses));
        let locator = BondRankingLocator::new(Arc::new(slate), slot);

        let got = locator.find_providers(&capsule()).await.expect("located");
        let hosts: Vec<String> = got.iter().map(|r| r.addresses[0].host.clone()).collect();

        assert_eq!(
            hosts,
            vec![
                "attacker-1.example",
                "honest-no-pointer.example",
                "attacker-2.example",
                "attacker-3.example",
            ],
            "exactly one copy is promoted; the rest fall back to baseline in source order, never below it"
        );
    }

    /// **Proves (dig-node#466, review round 2):** a verdict earned by one claiming peer is never
    /// served from the memo to a DIFFERENT peer naming the same coin for the same content.
    ///
    /// **Catches:** the ownership check being reinstated-then-bypassed through the cache. A coin id
    /// is a public fact published in provider records by design, so a stranger can republish
    /// another peer's coin id verbatim; if the key omitted the claimant, that stranger would be
    /// served the real holder's `Bonded` for the whole TTL and `verdict_for`'s second question
    /// would never be asked of it.
    ///
    /// The two lookups differ in EXACTLY one field — the claiming peer — and the same-peer read is
    /// asserted as a control, so a key that simply never hits would not pass.
    #[test]
    fn a_verdict_earned_by_one_peer_is_not_served_to_another() {
        let store = Bytes32::new(STORE);
        let root = Bytes32::new(ROOT);
        let coin = [0x33; 32];
        let holder = "aa".repeat(32);
        let stranger = "bb".repeat(32);

        let cache = VerdictCache::default();
        cache.remember(
            VerdictKey::new(coin, store, root, 7, &holder),
            BondVerdict::Bonded,
        );

        assert_eq!(
            cache.get(&VerdictKey::new(coin, store, root, 7, &holder)),
            Some(BondVerdict::Bonded),
            "control: the peer that earned the verdict is still served it"
        );
        assert_eq!(
            cache.get(&VerdictKey::new(coin, store, root, 7, &stranger)),
            None,
            "a stranger republishing the same coin id must re-ask, not inherit the holder's verdict"
        );
    }

    /// **Proves (dig-node#473, adversarial gate):** the promotion bound is keyed on the peer's
    /// IDENTITY, not on the text a record happened to spell it with.
    ///
    /// **Catches:** the bound being defeated at zero cost. Everything that GRANTS a promotion
    /// compares bytes — the coin's declaration decodes the hex, and the TLS pin compares certificate
    /// hashes — so a peer id in upper case and the same id in lower case are one peer to every check
    /// that matters. A bound keyed on the raw string is not: a stranger returning one honest
    /// holder's peer id in eight different hex spellings, each with its own addresses, would have
    /// eight distinct keys, eight promotions, and eight chain reads, and would occupy the whole
    /// verified budget on the strength of a single bond it does not hold.
    ///
    /// The two records below differ ONLY in the case of that one field, so a set keyed on the text
    /// promotes both and a set keyed on the identity promotes one.
    #[tokio::test]
    async fn the_promotion_bound_is_not_defeated_by_respelling_one_peer_id() {
        let mut shouted = holder_at(0xAA, Some([0x01; 32]), "attacker.example");
        shouted.provider_peer_id = shouted.provider_peer_id.to_uppercase();
        assert_ne!(
            shouted.provider_peer_id,
            holder_at(0xAA, None, "x").provider_peer_id,
            "the fixture must actually differ as TEXT, or it proves nothing"
        );

        // The honest holder sits BETWEEN the two spellings, and that placement is the whole test.
        // With it last, a promoted respelling and a baseline one land in the same position under a
        // stable sort and the two behaviours are indistinguishable -- the test would pass either
        // way. Here, promoting the respelling moves it AHEAD of the honest record; bounding it
        // leaves the honest record in front.
        let slate = Slate(vec![
            holder_at(0xAA, Some([0x01; 32]), "attacker-lower.example"),
            holder_at(0xCC, None, "honest.example"),
            shouted,
        ]);
        let slot = bond_verifier_slot();
        let _ = slot.set(Arc::new(EveryChainCheckPasses));
        let locator = BondRankingLocator::new(Arc::new(slate), slot);

        let got = locator.find_providers(&capsule()).await.expect("located");
        let hosts: Vec<String> = got.iter().map(|r| r.addresses[0].host.clone()).collect();

        assert_eq!(
            hosts,
            vec![
                "attacker-lower.example",
                "honest.example",
                "attacker.example",
            ],
            "one identity earns one promoted slot however it is spelled; the respelling stays at baseline, BEHIND the honest holder it would otherwise have jumped"
        );
    }

    /// **Proves (dig-node#466 / #473):** a wrong pointer costs the verifier exactly ONE chain read,
    /// with no retry loop — the cost the ticket requires be borne by the publisher, not the reader.
    ///
    /// **Catches:** the amplifier. The production `ChainSource` reaches `api.coinset.org`, the coin
    /// id is chosen by whoever wrote the provider record, and `Unbonded` is a verdict a stranger can
    /// elicit for free. A retry, or a second question asked of a claim already disproven, multiplies
    /// attacker-directed egress by the locate budget. The count is asserted alongside the verdict so
    /// a change that stopped reading altogether would fail here rather than pass quietly.
    #[test]
    fn a_disproven_pointer_costs_exactly_one_chain_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingChain {
            reads: Arc::clone(&reads),
        };

        let verdict = verdict_for(
            &source,
            Bytes32::new(STORE),
            Bytes32::new(ROOT),
            &BigInt::from(7u64),
            Some(1),
            &"aa".repeat(32),
            Bytes32::new([0x33; 32]),
        );

        assert_eq!(
            verdict,
            BondVerdict::Unbonded,
            "the chain answered and there is no such coin, which disproves the claim"
        );
        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            1,
            "one read settles it; anything more is a retry loop paid for by the reader"
        );
    }

    /// **Proves (dig-node#501, security round 1, HIGH):** locate-triggered verification spends a
    /// PROCESS-WIDE budget of chain reads, so spreading the traffic across identities does not
    /// multiply this node's outbound egress.
    ///
    /// **Catches:** the aggregate cap going missing — the defect this PR introduced by lifting the
    /// pre-read short-circuit. The inbound gate that admits a locate is per-requestor (burst 16 at
    /// 4/sec) over up to 4,096 self-minted identities, so it bounds nothing in aggregate; every
    /// admitted locate then verified up to eight records at two HTTPS reads each, through the ONE
    /// `ChiaQuery` client the node's own wallet, census and spends read through.
    ///
    /// Each row here uses a DISTINCT claimant, so the per-claimant ledger cannot be what bites and
    /// the number asserted is the aggregate bucket's. The count is asserted from the chain double
    /// itself rather than from the admission's own bookkeeping — an admission that returned `false`
    /// while still reading would pass a test that only counted refusals.
    #[test]
    fn locate_triggered_chain_reads_are_capped_process_wide() {
        const BURST: u32 = 4;
        const CLAIMS: u32 = 20;

        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingChain {
            reads: Arc::clone(&reads),
        };
        // No refill during the test: a rate the test cannot outrun would make the cap unobservable.
        let admission = ReadAdmission::new(BURST, 0.0);

        let mut verdicts = Vec::new();
        for claim in 0..CLAIMS {
            verdicts.push(admitted_verdict_for(
                &admission,
                &source,
                Bytes32::new(STORE),
                Bytes32::new(ROOT),
                &BigInt::from(7u64),
                || Some(1),
                // A fresh claimant per row, each a well-formed 64-hex id.
                &format!("{claim:064x}"),
                Bytes32::new([0x33; 32]),
            ));
        }

        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            BURST as usize,
            "the budget is the ceiling on chain reads, whatever the claim rate"
        );
        assert_eq!(
            verdicts
                .iter()
                .filter(|v| **v == BondVerdict::Unbonded)
                .count(),
            BURST as usize,
            "control: every admitted claim was genuinely answered, so the cap is not hiding a \
             function that stopped reading altogether"
        );
        assert!(
            verdicts[BURST as usize..]
                .iter()
                .all(|v| *v == BondVerdict::Unverified),
            "past the budget a record stays at the tier it would occupy with no verifier at all -- \
             withheld credit, never a demotion, and never a blocked read"
        );
    }

    /// **Proves (dig-node#501, security round 1, HIGH):** one claimant cannot spend an unbounded
    /// number of chain reads on coin ids it invents.
    ///
    /// **Catches:** the case the verdict cache structurally cannot absorb. [`VerdictKey`] includes
    /// the coin id and MUST — without it a stranger republishing a public coin id would inherit its
    /// holder's `Bonded` — so a slate of records carrying invented coin ids misses the cache once
    /// per invented id, by construction. No cache design fixes that; only a bound on how many
    /// unproven ids one claimed identity is allowed does.
    ///
    /// The budget here is deliberately large, so the number asserted can only be the per-claimant
    /// ledger's. A single-claimant test against the aggregate bucket alone would pass with no
    /// ledger at all.
    #[test]
    fn fabricated_coin_ids_from_one_claimant_stop_costing_chain_reads() {
        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingChain {
            reads: Arc::clone(&reads),
        };
        let admission = ReadAdmission::new(1_000, 0.0);
        let claimant = "aa".repeat(32);

        for invented in 0..32u8 {
            admitted_verdict_for(
                &admission,
                &source,
                Bytes32::new(STORE),
                Bytes32::new(ROOT),
                &BigInt::from(7u64),
                || Some(1),
                &claimant,
                Bytes32::new([invented; 32]),
            );
        }

        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            MAX_UNPROVEN_COINS_PER_CLAIMANT,
            "a claimant that never proves a bond gets a fixed allowance of invented coin ids"
        );

        // The control, and the reason the bound is not simply a per-peer denial: a DIFFERENT
        // claimant is unaffected by this one's exhaustion.
        admitted_verdict_for(
            &admission,
            &source,
            Bytes32::new(STORE),
            Bytes32::new(ROOT),
            &BigInt::from(7u64),
            || Some(1),
            &"bb".repeat(32),
            Bytes32::new([0x01; 32]),
        );
        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            MAX_UNPROVEN_COINS_PER_CLAIMANT + 1,
            "the ledger is per claimant; one peer exhausting its allowance must not silence another"
        );
    }

    /// **Proves (dig-node#527, item 4, HIGH):** a sample too small for the bond floor is detected
    /// WITHOUT dialling, and a not-yet-known sample never falsely refuses.
    #[test]
    fn a_sample_below_the_required_floor_is_recognised_without_a_read() {
        assert!(
            sample_cannot_meet_floor(Some(2), 3),
            "two live peers can never satisfy a floor of three -- `tally_with_floor` would return \
             `Insufficient` every time, so the read is skippable"
        );
        assert!(
            !sample_cannot_meet_floor(Some(3), 3),
            "a sample that exactly meets the floor must still be tried"
        );
        assert!(
            !sample_cannot_meet_floor(Some(4), 3),
            "a sample above the floor must still be tried"
        );
        assert!(
            !sample_cannot_meet_floor(None, 3),
            "an unknown sample (nothing drawn yet) fails OPEN into the real read -- that is what \
             discovers peers in the first place, and a hint must never be read as a refusal"
        );
    }

    /// **Proves (dig-node#527, item 1, HIGH):** repeating the SAME unproven coin id does not buy a
    /// fresh chain read every attempt.
    ///
    /// **Catches:** the ledger bypass the distinct-coin cap left open. A coin that does not declare
    /// its claimant returns [`BondVerdict::Unverified`], which [`VerdictCache::remember`]
    /// deliberately never caches — so before this fix, re-asking about the identical
    /// `(claimant, coin_id)` pair spent only the process-wide token bucket, never the ledger. At
    /// [`VERIFICATION_REFILL_PER_SEC`] that is a sustainable ~1 request/sec that holds
    /// [`ReadAdmission::shared`]'s entire budget at zero, forever, off ONE fabricated coin.
    ///
    /// The budget here is deliberately enormous (`1_000` burst, `1_000.0`/sec refill) so the token
    /// bucket can never be what stops the 50th attempt — only the per-pair cooldown this fix adds.
    #[test]
    fn a_repeated_unproven_coin_id_stops_costing_a_fresh_read_every_attempt() {
        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingChain {
            reads: Arc::clone(&reads),
        };
        let admission = ReadAdmission::new(1_000, 1_000.0);
        let claimant = "cc".repeat(32);
        let same_coin = Bytes32::new([0x42; 32]);

        for _ in 0..50 {
            admitted_verdict_for(
                &admission,
                &source,
                Bytes32::new(STORE),
                Bytes32::new(ROOT),
                &BigInt::from(7u64),
                || Some(1),
                &claimant,
                same_coin,
            );
        }

        assert_eq!(
            reads.load(AtomicOrdering::Relaxed),
            1,
            "a claimant repeating ONE unproven coin id must be bounded to the SAME cadence a cache \
             hit would give an honest re-ask, never a fresh chain read every attempt"
        );
    }

    /// **Proves (dig-node#501, security round 1, HIGH, second half):** a flood of cheap negative
    /// verdicts cannot displace a verdict this node earned.
    ///
    /// **Catches:** attacker-paced eviction. The previous `remember` evicted one arbitrary entry per
    /// insert past [`MAX_CACHED_VERDICTS`], which reads as conservative and is not: `Unbonded` is
    /// the verdict a stranger elicits for FREE by naming coin ids that do not exist, so at an
    /// attacker-chosen insert rate the whole map turns over in under a minute and every earned
    /// `Bonded` is discarded — the "memoisation into an amplifier" the constant's own doc warns
    /// about, reached one entry at a time instead of all at once.
    ///
    /// The honest entries are counted rather than sampled, so an implementation that dropped one
    /// per cheap insert would fail here rather than pass on the entry the test happened to check.
    #[test]
    fn a_flood_of_cheap_negatives_cannot_evict_an_earned_verdict() {
        let store = Bytes32::new(STORE);
        let root = Bytes32::new(ROOT);
        let cache = VerdictCache::default();

        let earned: Vec<VerdictKey> = (0..MAX_CACHED_VERDICTS)
            .map(|n| VerdictKey::new([n as u8; 32], store, root, 7, &format!("{n:064x}")))
            .collect();
        for key in &earned {
            cache.remember(*key, BondVerdict::Bonded);
        }
        let held = earned.iter().filter(|k| cache.get(k).is_some()).count();
        assert_eq!(
            held, MAX_CACHED_VERDICTS,
            "control: the map really is full of live earned verdicts before the flood"
        );

        let liar = "ff".repeat(32);
        for invented in 0..64u8 {
            cache.remember(
                VerdictKey::new([invented; 32], store, root, 7, &liar),
                BondVerdict::Unbonded,
            );
        }

        assert_eq!(
            earned.iter().filter(|k| cache.get(k).is_some()).count(),
            MAX_CACHED_VERDICTS,
            "not one earned verdict may be traded for a negative that cost the publisher nothing"
        );
        assert_eq!(
            cache.get(&VerdictKey::new([0x07; 32], store, root, 7, &liar)),
            None,
            "the cheap negative is refused admission rather than admitted at an honest entry's cost"
        );
    }

    /// **Proves (dig-node#473):** the declaration source is LIVE, so the pre-read short-circuit no
    /// longer withholds every verdict — and the probe that lifts it is a genuine fail-closed
    /// self-test rather than a switch someone must remember to flip.
    ///
    /// **Catches:** a silent regression in the format agreement. The probe asks the production
    /// [`peer_declaration`] for the one term a coin owned by `probe_peer` would carry. If a future
    /// `dig-mirror-coin` changed the declaration format, or the accessor stopped answering, this
    /// goes false and `verdict_for` returns to withholding credit from everyone — the safe
    /// direction — instead of promoting on a check it can no longer make. Asserting it TRUE here is
    /// what makes that failure visible as a red test rather than as silently inert ranking.
    #[test]
    fn the_declaration_source_is_live_and_its_probe_is_a_fail_closed_self_test() {
        assert!(
            declaration_source_is_readable(),
            "the typed accessor must answer, or promotion is unreachable for every input"
        );

        let peer = "aa".repeat(32);
        assert_eq!(
            peer_declaration(&[format!("dig-peer:{peer}")], &peer),
            PeerDeclaration::DeclaresThisPeer,
            "control: the probe and the production path are the same function"
        );
    }

    /// **Proves (dig-node#473):** only the coin's own declaration of THIS claimant promotes it.
    ///
    /// **Catches:** the binding degrading to "some coin bonds this content", which is the weaker
    /// question a stranger republishing a public coin id passes. Every row shares one claimant and
    /// varies only what the coin says, so a check that ignored the terms would answer identically
    /// for all of them.
    #[test]
    fn only_the_coins_own_declaration_of_this_claimant_promotes_it() {
        let peer = "aa".repeat(32);
        let other = "bb".repeat(32);

        let promotes = [
            vec![format!("dig-peer:{peer}")],
            vec![
                "https://mirror.example/store".to_string(),
                format!("dig-peer:{peer}"),
            ],
            // The owner wrote the id in the other case; it denotes the same SHA-256.
            vec![format!("dig-peer:{}", peer.to_uppercase())],
        ];
        for terms in promotes {
            assert_eq!(
                peer_declaration(&terms, &peer),
                PeerDeclaration::DeclaresThisPeer,
                "terms {terms:?}"
            );
        }

        let withholds = [
            vec![],
            vec!["https://mirror.example/store".to_string()],
            // Someone else's coin, republished by this claimant.
            vec![format!("dig-peer:{other}")],
            // Two declarations name nobody -- one coin's collateral must not back two peers.
            vec![format!("dig-peer:{peer}"), format!("dig-peer:{other}")],
            // Prefix lookalikes are ordinary advertised strings.
            vec![format!("xdig-peer:{peer}")],
            vec![format!("dig-peers:{peer}")],
            // A payload that is not a peer id.
            vec!["dig-peer:nope".to_string()],
        ];
        for terms in withholds {
            assert_eq!(
                peer_declaration(&terms, &peer),
                PeerDeclaration::Silent,
                "terms {terms:?}"
            );
        }
    }
}
